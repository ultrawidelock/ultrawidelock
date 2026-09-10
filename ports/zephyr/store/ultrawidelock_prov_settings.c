/* SPDX-License-Identifier: ISC */

/*
 * ultrawidelock_prov (Zephyr backend) — the DWM3001CDK twin of the ESP32 port's
 * ultrawidelock_prov_nvs.c and the FreeRTOS port's ultrawidelock_prov_kv.c. The portable
 * serialisation, dev fallback and trust logic all live in ultrawidelock_prov.c; this file
 * only moves that one blob in and out of the store under
 * ULTRAWIDELOCK_KV_KEY_CRED_PROV.
 *
 * It reaches the store through ultrawidelock_kv.h rather than through settings
 * directly. The record used to be the string "ultrawidelock/prov" and is now
 * whatever kv_zephyr.c derives from the key, so a board provisioned by an older
 * image reads as never provisioned and comes up on the DEV identity. That is the
 * accepted cost of retiring the name table; re-provision the bench boards.
 */
#include <string.h>
#include <errno.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "ultrawidelock_kv.h"
#include "ultrawidelock_prov.h"

LOG_MODULE_REGISTER(ultrawidelock_prov, CONFIG_LOG_DEFAULT_LEVEL);

/*
 * The store has to hold the largest blob the serialiser can produce, and that
 * size moves with ULTRAWIDELOCK_TRUST_MAX. Caught here at build time rather than
 * at the first provisioning write on a customer's board. The FreeRTOS twin
 * carries the same assertion for the same reason.
 */
_Static_assert(ULTRAWIDELOCK_PROV_BLOB_MAX <= ULTRAWIDELOCK_KV_VALUE_MAX,
	       "the provisioning blob no longer fits one key-value record");

K_MUTEX_DEFINE(s_backend_lock);

/* The one serialised-blob buffer, for load and store alike; see prov_load_locked(). */
static uint8_t s_blob[ULTRAWIDELOCK_PROV_BLOB_MAX];

/*
 * Store errors, mapped onto the errno values this backend's callers already
 * handle. Only ULTRAWIDELOCK_KV_INVALID carries information they act on -- it
 * means the stored record is longer than any blob this firmware can produce, so
 * it is corruption or a future format, and neither is safe to parse.
 */
static int prov_errno(int kv_rc)
{
	switch (kv_rc) {
	case ULTRAWIDELOCK_KV_OK:
		return 0;
	case ULTRAWIDELOCK_KV_INVALID:
		return -EINVAL;
	case ULTRAWIDELOCK_KV_FULL:
		return -ENOSPC;
	default:
		return -EIO;
	}
}

/**
 * Load credential reader identity and trust anchors from the store. Returns 0 on success with
 * stored data loaded, ULTRAWIDELOCK_PROV_LOAD_EMPTY if never provisioned, and a specific
 * negative errno on store/read/malformed data. Outputs use the marked DEV identity for
 * diagnostics and recovery, but the reader keeps transport offline for every negative result.
 */
static int prov_load_locked(struct ultrawidelock_reader_identity *id,
			    struct ultrawidelock_trust_store *ts)
{
	/*
	 * STATIC, not on the stack. ULTRAWIDELOCK_PROV_BLOB_MAX scales with
	 * ULTRAWIDELOCK_TRUST_MAX, and raising that 4 -> 8 put a stack copy at 864 B on
	 * a frame that also holds a 778 B struct ultrawidelock_trust_store. The result
	 * was an MPU fault through the bottom of the 4 KB main stack about four
	 * seconds into boot -- the board advertised, froze, and the phone
	 * reported "transaction timed out" with nothing in the log after the
	 * advert line.
	 *
	 * Safe as static because s_backend_lock covers the complete read and
	 * deserialization, as well as every store and erase of the same record --
	 * which is also why load and store share the one buffer (s_blob): the
	 * blob grew past 1 KiB with the issuer keys, and the nRF52833 has no RAM
	 * for a second copy that the lock guarantees is never in use at the
	 * same time.
	 */
	uint8_t *blob = s_blob;
	size_t len = sizeof(s_blob);
	int rc = ultrawidelock_kv_init();

	if (rc != ULTRAWIDELOCK_KV_OK) {
		LOG_WRN("kv init rc=%d; using DEV identity", rc);
		ultrawidelock_prov_dev_default(id, ts);
		return prov_errno(rc);
	}

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_PROV_CLEAR_ON_BOOT)
	/* Before the load, not after: the point is that nothing ever sees the old
	 * blob, so the identity this boot reports is the DEV one. */
	rc = ultrawidelock_kv_delete(ULTRAWIDELOCK_KV_KEY_CRED_PROV);
	LOG_WRN("clear-on-boot: erased the provisioning record (rc=%d)", rc);
#endif

	rc = ultrawidelock_kv_get(ULTRAWIDELOCK_KV_KEY_CRED_PROV, blob, &len);
	if (rc == ULTRAWIDELOCK_KV_NOT_FOUND) {
		/* Never provisioned. Not an error. */
		ultrawidelock_prov_dev_default(id, ts);
		return ULTRAWIDELOCK_PROV_LOAD_EMPTY;
	}
	if (rc != ULTRAWIDELOCK_KV_OK) {
		LOG_WRN("kv get rc=%d; using DEV identity", rc);
		ultrawidelock_prov_dev_default(id, ts);
		return prov_errno(rc);
	}

	if (ultrawidelock_prov_deserialize(blob, len, id, ts) != 0) {
		LOG_WRN("stored blob malformed; using DEV identity");
		ultrawidelock_prov_dev_default(id, ts);
		return -EBADMSG;
	}
	return 0;
}

int ultrawidelock_prov_load(struct ultrawidelock_reader_identity *id,
			    struct ultrawidelock_trust_store *ts)
{
	(void)k_mutex_lock(&s_backend_lock, K_FOREVER);
	int rc = prov_load_locked(id, ts);
	(void)k_mutex_unlock(&s_backend_lock);
	return rc;
}

/**
 * Erase the stored credential provisioning blob. Returns 0 on success, negative on store error;
 * the error is logged as a warning and returned rather than suppressed, because a silent factory
 * reset that left the old anchors in place would pair but then reject the phone.
 */
static int prov_erase_locked(void)
{
	int rc = ultrawidelock_kv_init();

	if (rc != ULTRAWIDELOCK_KV_OK) {
		LOG_ERR("kv init rc=%d; nothing erased", rc);
		return prov_errno(rc);
	}
	rc = ultrawidelock_kv_delete(ULTRAWIDELOCK_KV_KEY_CRED_PROV);
	/*
	 * A record that was never stored is not a failed erase: the caller asked
	 * for the blob to be gone and it is gone. Every other rc is reported, not
	 * swallowed. A factory reset that quietly did nothing is worse than one
	 * that fails loudly: the board comes back looking reset, pairs, and then
	 * rejects the phone with the old anchors still in the store.
	 */
	if (rc == ULTRAWIDELOCK_KV_NOT_FOUND) {
		rc = ULTRAWIDELOCK_KV_OK;
	}
	LOG_WRN("factory reset: erased the provisioning record (rc=%d)", rc);
	return prov_errno(rc);
}

int ultrawidelock_prov_erase(void)
{
	(void)k_mutex_lock(&s_backend_lock, K_FOREVER);
	int rc = prov_erase_locked();
	(void)k_mutex_unlock(&s_backend_lock);
	return rc;
}

/**
 * Serialize and store credential reader identity and trust anchors. Uses a static blob buffer to
 * avoid stack overflow, for the reason set out in prov_load_locked(). A backend-local mutex
 * serializes load/store/erase, including direct shell/reset callers outside the portable reader.
 */
static int prov_store_locked(const struct ultrawidelock_reader_identity *id,
			     const struct ultrawidelock_trust_store *ts)
{
	size_t len = 0;
	int rc = ultrawidelock_kv_init();

	if (rc != ULTRAWIDELOCK_KV_OK) {
		return prov_errno(rc);
	}
	if (ultrawidelock_prov_serialize(id, ts, s_blob, sizeof(s_blob), &len) != 0) {
		return -EINVAL;
	}
	return prov_errno(ultrawidelock_kv_set(ULTRAWIDELOCK_KV_KEY_CRED_PROV, s_blob, len));
}

int ultrawidelock_prov_store(const struct ultrawidelock_reader_identity *id,
			     const struct ultrawidelock_trust_store *ts)
{
	(void)k_mutex_lock(&s_backend_lock, K_FOREVER);
	int rc = prov_store_locked(id, ts);
	(void)k_mutex_unlock(&s_backend_lock);
	return rc;
}
