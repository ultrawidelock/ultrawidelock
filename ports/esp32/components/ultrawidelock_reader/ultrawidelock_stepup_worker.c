/* SPDX-License-Identifier: ISC */

/**
 * @file ultrawidelock_stepup_worker.c
 * Step-up document verification worker for ESP32. Runs on a dedicated FreeRTOS task (6 KB stack, priority 4). Lazily creates a single-slot queue on first submission. Non-blocking submission: if a previous job is still enqueued, the new job is dropped. Verdict and connection handle are stored in shared state (spinlock-protected) and retrieved via ultrawidelock_stepup_worker_last(). Logging includes decrypted DeviceResponse hex and verdict breakdown (validity, element count, issuer found, signature OK, doctype OK, time OK, iteration OK).
 */
/*
 * ultrawidelock_stepup_worker — the ESP32 background worker for the credential step-up phase.
 * The reader collects the DeviceResponse during the pre-ranging window and hands
 * it here; this task then decrypts, parses and verifies it (spec §7.4) OFF the
 * BLE-host task, so the CPU-heavy ES256 / SHA-256 work never lands in the auth
 * segment or the ~1836 us ranging arm window. The verdict is logged and kept for
 * `ultrawidelock-stepup status`; it NEVER gates the unlock. The decrypted DeviceResponse
 * is hex-dumped so a bench-captured Apple document can be pinned as a KAT.
 *
 * ESP-only: this file is compiled solely by the ultrawidelock_reader ESP-IDF component,
 * and only when CONFIG_ULTRAWIDELOCK_CRED_STEPUP=y. The platform-neutral codec + verifier
 * live in modules/ultrawidelock_cred/src/ultrawidelock_stepup*.c.
 */
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "esp_log.h"

#include "ultrawidelock_prim.h" /* ultrawidelock_ecdsa_p256_verify (PSA ES256) */
#include "ultrawidelock_stepup.h"

#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP_BENCH)

static const char *TAG = "ultrawidelock_stepup";

static QueueHandle_t s_queue;
static portMUX_TYPE s_verdict_lock = portMUX_INITIALIZER_UNLOCKED;
static struct ultrawidelock_stepup_verdict s_last_verdict;
static uint16_t s_last_conn;
static bool s_have_last;

/**
 * Store a verdict and connection handle to shared state, protected by spinlock. Called by the worker task when verification completes.
 */
static void store_verdict(const struct ultrawidelock_stepup_verdict *v, uint16_t conn)
{
	portENTER_CRITICAL(&s_verdict_lock);
	s_last_verdict = *v;
	s_last_conn = conn;
	s_have_last = true;
	portEXIT_CRITICAL(&s_verdict_lock);
}

/**
 * Retrieve the most recent step-up verdict and connection handle from the worker. Return 1 if a verdict is available (verdict and conn populated), 0 otherwise. Thread-safe via spinlock.
 */
int ultrawidelock_stepup_worker_last(struct ultrawidelock_stepup_verdict *verdict, uint16_t *conn)
{
	int have;

	portENTER_CRITICAL(&s_verdict_lock);
	have = s_have_last ? 1 : 0;
	if (have) {
		*verdict = s_last_verdict;
		if (conn != NULL) {
			*conn = s_last_conn;
		}
	}
	portEXIT_CRITICAL(&s_verdict_lock);
	return have;
}

/**
 * Decrypt and parse a step-up job: open the secure channel with reader and device keys, decrypt SessionData to extract DeviceResponse, parse it, verify the signature and document integrity, and store the verdict. Log the DeviceResponse hex and verdict details.
 */
static void run_job(const struct ultrawidelock_stepup_job *job)
{
	static uint8_t scratch[2100]; /* only the worker task touches this */
	struct ultrawidelock_secchan sc;
	size_t dr_len;

	ultrawidelock_stepup_channel_init(&sc, job->sk_reader, job->sk_device);

	if (ultrawidelock_stepup_open_sessiondata(&sc, job->sd, job->sd_len, scratch, sizeof(scratch),
					  &dr_len) != 0) {
		ESP_LOGW(TAG, "[conn %u] SessionData decrypt failed (%u B); step-up aborted",
			 job->conn_handle, (unsigned)job->sd_len);
		return;
	}

	/* Capture: the decrypted DeviceResponse, so a real Apple document can be
	 * pinned as a KAT and its contents documented first-hand. */
	ESP_LOGI(TAG, "[conn %u] DeviceResponse (%u B):", job->conn_handle, (unsigned)dr_len);
	ESP_LOG_BUFFER_HEX(TAG, scratch, dr_len);

	struct ultrawidelock_stepup_doc doc;

	if (ultrawidelock_stepup_parse_response(scratch, dr_len, &doc) != 0) {
		ESP_LOGW(TAG, "[conn %u] DeviceResponse parse failed", job->conn_handle);
		return;
	}

	struct ultrawidelock_stepup_issuer iss;
	struct ultrawidelock_stepup_verify_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));
	if (job->have_issuer) {
		iss.kid = job->issuer_kid;
		iss.kid_len = job->issuer_kid_len;
		memcpy(iss.pub, job->issuer_pub, sizeof(iss.pub));
		ctx.issuers = &iss;
		ctx.n_issuers = 1;
	}
	ctx.time_valid = job->time_valid;
	ctx.now_epoch = job->now_epoch;
	ctx.access_iteration = 0;
	ctx.expected_doctype = ULTRAWIDELOCK_STEPUP_DOCTYPE_ACCESS;
	ctx.ecdsa_verify = ultrawidelock_ecdsa_p256_verify;

	struct ultrawidelock_stepup_verdict v;

	ultrawidelock_stepup_verify(&doc, &ctx, &v);
	store_verdict(&v, job->conn_handle);

	ESP_LOGI(TAG,
		 "[conn %u] verdict: %s (reject_step=%d) docType=%s elements=%u/%u "
		 "issuer_found=%d chain_validated=%d sig=%d digests=%d doctype=%d time=%d iter=%d",
		 job->conn_handle, v.valid ? "VALID" : "invalid", v.reject_step,
		 doc.doc_type[0] ? doc.doc_type : "?", (unsigned)v.valid_elements,
		 (unsigned)doc.n_items, v.issuer_key_found, v.issuer_chain_validated, v.sig_ok,
		 v.digests_ok, v.doctype_ok, v.time_ok, v.iteration_ok);
	ESP_LOGI(TAG,
		 "[conn %u] validity: from=%lld until=%lld timeVerificationRequired=%d "
		 "(reference verdict is logged only; the trust store gates access)",
		 job->conn_handle, (long long)doc.valid_from_epoch, (long long)doc.valid_until_epoch,
		 doc.time_verification_required);
}

/**
 * Worker task: infinite loop receiving jobs from the queue and calling run_job to process each one.
 */
static void worker_task(void *arg)
{
	(void)arg;
	static struct ultrawidelock_stepup_job job; /* ~0.8 KB: off the small task stack */

	for (;;) {
		if (xQueueReceive(s_queue, &job, portMAX_DELAY) == pdTRUE) {
			run_job(&job);
		}
	}
}

/**
 * Submit a step-up verification job to the worker queue. Create the queue and task on first use. Non-blocking: if a previous job is still queued, drop this one and return -1 (the reader must never stall). Return 0 on success, -1 on queue full or creation failure.
 */
int ultrawidelock_stepup_worker_submit(const struct ultrawidelock_stepup_job *job)
{
	/* Lazily create the queue + task on first use (from the BLE-host task). A
	 * one-shot arm never overlaps, so a depth of 1 is sufficient. */
	if (s_queue == NULL) {
		s_queue = xQueueCreate(1, sizeof(struct ultrawidelock_stepup_job));
		if (s_queue == NULL) {
			return -1;
		}
		if (xTaskCreate(worker_task, "ultrawidelock_stepup", 6144, NULL, 4, NULL) != pdPASS) {
			return -1;
		}
	}
	/* Non-blocking: if a previous job is still queued, drop this one (the reader
	 * must never stall waiting on the verifier). */
	return xQueueSend(s_queue, job, 0) == pdTRUE ? 0 : -1;
}

#endif /* CONFIG_ULTRAWIDELOCK_CRED_STEPUP_BENCH */
