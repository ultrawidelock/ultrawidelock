/*
 * Host test for the ranging-setup glue (ultrawidelock_ranging.c): the post-auth layer
 * that arms, feeds and tears down the engine's M1-M4 ranging session and
 * BleSK-seals its outbound SDUs.
 *
 * The engine (cherry context, reader adapter, session) and the BLE/facade
 * surfaces are recording doubles defined here: they capture the create/destroy
 * arguments, stash the registered transmit/event callbacks so the script can
 * invoke them as the engine would, and expose one-shot failure switches for
 * the error branches. The BleSK sealing in the transmit callback is REAL
 * crypto (ultrawidelock_crypto.c over the GCM in ultrawidelock_prim_host.c): every sealed SDU
 * the double records is opened with the mirrored device-direction GCM (as
 * test_ultrawidelock_reader.c's ph_open_ble does) to prove plaintext, AAD and the
 * per-direction counter (starting at 1) all match §11.8.2.
 *
 * Scenarios, in one linear script (the unit's state is process-global):
 *   P  start/feed/stop before init: all rejected, nothing touched
 *   I  init: cherry-create failure, adapter-create failure (cherry released),
 *      success (capabilities/reader-config/DW3000-probe captured), idempotence
 *   S  start: NULL ursk/secchan, session-create failure, set-ursk failure
 *      (session released), success (args + prewarm), single-session busy
 *   F  feed: wrong conn, undersized/oversized SDU, success, engine reject,
 *      engine DEINIT mid-handle (session cleared, feed dead afterwards)
 *   T  transmit callback: seal + send + open (counter continuity across
 *      calls), NULL message, seal failure (prim hook), BLE send failure
 *   E  events: ACTIVE, IDLE, default state, NULL status payload, ERROR,
 *      report passthrough, DEINIT for the wrong then the right conn
 *   X  stop: wrong conn no-op, teardown (tx after stop rejected, engine's
 *      DEINIT echo a no-op), stop when inactive, restart after stop
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ultrawidelock_ble.h"
#include "ultrawidelock_crypto.h"
#include "ultrawidelock_lat.h"
#include "ultrawidelock_prim.h"
#include "ultrawidelock_ranging.h"

#include "cherry/cherry.h"
#include "cherry/cherry_ccc.h"
#include "ultrawidelock_uwb_adapter/ultrawidelock_uwb_adapter.h"
#include "ultrawidelock_uwb_adapter/ultrawidelock_uwb_session.h"
#include <ultrawidelock/uwb.h>

/* Failure injection into the prim double (ultrawidelock_prim_host.c); default off,
 * self-disarming after firing. */
extern int ultrawidelock_prim_host_fail_encrypt_after;

static int fails;

static void okc(const char *name, int cond)
{
	if (!cond) {
		printf("  FAIL %s\n", name);
		fails++;
	} else {
		printf("  ok   %s\n", name);
	}
}

/* ---- cherry core double -------------------------------------------------- */

static int s_cherry_dummy;
static int s_cherry_creates, s_cherry_destroys;
static bool s_cherry_create_fail; /* one-shot */
static bool s_cherry_dev_ok;

struct cherry *cherry_create(const char *device, cherry_core_cb_t core_cb, void *user_data)
{
	(void)core_cb;
	(void)user_data;
	s_cherry_creates++;
	s_cherry_dev_ok = device != NULL && strcmp(device, "dw3000-fira") == 0;
	if (s_cherry_create_fail) {
		s_cherry_create_fail = false;
		return NULL;
	}
	return (struct cherry *)&s_cherry_dummy;
}

void cherry_destroy_sync(struct cherry *ctx)
{
	if (ctx == (struct cherry *)&s_cherry_dummy) {
		s_cherry_destroys++;
	}
}

/* ---- adapter double ------------------------------------------------------ */

static int s_adapter_dummy;
static int s_adapter_creates;
static bool s_adapter_create_fail; /* one-shot */
static struct cherry *s_adapter_cherry;
static struct cherry_ccc_capabilities s_caps; /* value copy; items copied below */
static uint16_t s_caps_proto0, s_caps_uwb0;
static uint8_t s_caps_pulse0;
static struct ultrawidelock_uwb_adapter_reader_config s_rcfg;

struct ultrawidelock_uwb_adapter *
ultrawidelock_uwb_adapter_create_reader(struct cherry *cherry_ctx,
				struct cherry_core_event_device_capabilities *caps,
				struct ultrawidelock_uwb_adapter_reader_config *config)
{
	s_adapter_creates++;
	if (s_adapter_create_fail) {
		s_adapter_create_fail = false;
		return NULL;
	}
	s_adapter_cherry = cherry_ctx;
	/* The caps arrays live in init's stack frame: copy what the asserts need
	 * during the call, exactly as a deep-copying engine would. */
	if (caps != NULL && caps->ccc_capabilities != NULL) {
		s_caps = *caps->ccc_capabilities;
		if (s_caps.protocol_versions.len == 1u) {
			s_caps_proto0 = s_caps.protocol_versions.items[0];
		}
		if (s_caps.uwb_configs.len == 1u) {
			s_caps_uwb0 = s_caps.uwb_configs.items[0];
		}
		if (s_caps.pulse_shape_combos.len == 1u) {
			s_caps_pulse0 = s_caps.pulse_shape_combos.items[0];
		}
	}
	if (config != NULL) {
		s_rcfg = *config;
	}
	return (struct ultrawidelock_uwb_adapter *)&s_adapter_dummy;
}

/* ---- session double ------------------------------------------------------ */

static int s_sess_dummy;
static int s_sess_creates, s_sess_destroys;
static bool s_sess_create_fail;    /* one-shot */
static bool s_sess_set_ursk_fail;  /* one-shot */
static struct ultrawidelock_uwb_adapter *s_sess_adapter;
static uint32_t s_sess_sid;
static ultrawidelock_uwb_session_cb_t s_ev_cb;
static ultrawidelock_uwb_adapter_transmit_message_t s_tx_cb;
static void *s_sess_user;
static uint8_t s_sess_ursk[ULTRAWIDELOCK_URSK_LEN];
static uint16_t s_sess_ver;

struct ultrawidelock_uwb_session *
ultrawidelock_uwb_session_create(struct ultrawidelock_uwb_adapter *ultrawidelock_ctx, uint32_t session_id,
				 ultrawidelock_uwb_session_cb_t callback,
				 ultrawidelock_uwb_adapter_transmit_message_t transmit,
				 void *user_data)
{
	s_sess_creates++;
	if (s_sess_create_fail) {
		s_sess_create_fail = false;
		return NULL;
	}
	s_sess_adapter = ultrawidelock_ctx;
	s_sess_sid = session_id;
	s_ev_cb = callback;
	s_tx_cb = transmit;
	s_sess_user = user_data;
	return (struct ultrawidelock_uwb_session *)&s_sess_dummy;
}

void ultrawidelock_uwb_session_destroy(struct ultrawidelock_uwb_session *session)
{
	if (session == (struct ultrawidelock_uwb_session *)&s_sess_dummy) {
		s_sess_destroys++;
	}
}

enum ultrawidelock_uwb_err
ultrawidelock_uwb_session_set_ursk(struct ultrawidelock_uwb_session *session, const uint8_t *ursk)
{
	(void)session;
	if (s_sess_set_ursk_fail) {
		s_sess_set_ursk_fail = false;
		return ULTRAWIDELOCK_UWB_ERR_INTERNAL;
	}
	memcpy(s_sess_ursk, ursk, ULTRAWIDELOCK_URSK_LEN);
	return ULTRAWIDELOCK_UWB_ERR_NONE;
}

enum ultrawidelock_uwb_err
ultrawidelock_uwb_session_set_protocol_version(struct ultrawidelock_uwb_session *session,
					       uint16_t selected_protocol_version)
{
	(void)session;
	s_sess_ver = selected_protocol_version;
	return ULTRAWIDELOCK_UWB_ERR_NONE;
}

static int s_handles;
static struct ultrawidelock_uwb_session *s_handle_sess;
static uint8_t s_handle_buf[256];
static size_t s_handle_len;
static enum ultrawidelock_uwb_err s_handle_rc;  /* one-shot, resets to NONE */
static bool s_handle_fire_deinit;       /* one-shot: emit DEINIT before returning */

static void ev_status(enum cherry_ccc_session_state st, uint16_t conn);

enum ultrawidelock_uwb_err
ultrawidelock_uwb_session_message_handle(struct ultrawidelock_uwb_session *session,
					 struct ultrawidelock_uwb_message *message)
{
	s_handles++;
	s_handle_sess = session;
	s_handle_len = message->len <= sizeof(s_handle_buf) ? message->len : 0;
	memcpy(s_handle_buf, message->data, s_handle_len);
	if (s_handle_fire_deinit) {
		/* A hard M4 failure DEINITs the session before handle returns. */
		s_handle_fire_deinit = false;
		ev_status(CHERRY_CCC_SESSION_STATE_DEINIT,
			  (uint16_t)(uintptr_t)s_sess_user);
	}
	enum ultrawidelock_uwb_err rc = s_handle_rc;

	s_handle_rc = ULTRAWIDELOCK_UWB_ERR_NONE;
	return rc;
}

static int s_msg_frees, s_msg_frees_null;

void ultrawidelock_uwb_session_message_free(struct ultrawidelock_uwb_message *message)
{
	if (message == NULL) {
		s_msg_frees_null++;
	} else {
		s_msg_frees++;
	}
}

static int s_ev_frees;

void ultrawidelock_uwb_session_event_free(struct ultrawidelock_uwb_session_event *event)
{
	(void)event;
	s_ev_frees++;
}

/* ---- ultrawidelock_uwb facade double ----------------------------------------------- */

static int s_uwb_starts, s_uwb_stops, s_uwb_prewarms;
static int s_uwb_start_rc;
static struct ultrawidelock_uwb_cred_cfg s_uwb_cfg;
static uint8_t s_uwb_ursk[ULTRAWIDELOCK_URSK_LEN];
static uint8_t s_pw_ch, s_pw_sync;

int ultrawidelock_uwb_start_cred(const struct ultrawidelock_uwb_cred_cfg *cfg)
{
	s_uwb_starts++;
	s_uwb_cfg = *cfg;
	if (cfg->ursk != NULL) {
		memcpy(s_uwb_ursk, cfg->ursk, ULTRAWIDELOCK_URSK_LEN);
	}
	return s_uwb_start_rc;
}

int ultrawidelock_uwb_prewarm(uint8_t channel, uint8_t sync_code_index)
{
	s_uwb_prewarms++;
	s_pw_ch = channel;
	s_pw_sync = sync_code_index;
	return 0;
}

void ultrawidelock_uwb_stop(void)
{
	s_uwb_stops++;
}

/* ---- ultrawidelock_ble transport double ------------------------------------------ */

#define TX_MAX 8
static struct {
	uint8_t b[512];
	size_t n;
	uint16_t conn;
} s_tx[TX_MAX];
static int s_txn;
static int s_ble_send_rc; /* one-shot: nonzero fails (and drops) the next send */
static int s_disconnects;
static uint16_t s_last_disconnected;

int ultrawidelock_ble_send(uint16_t conn_handle, const uint8_t *data, size_t len)
{
	if (s_ble_send_rc != 0) {
		int rc = s_ble_send_rc;

		s_ble_send_rc = 0;
		return rc;
	}
	if (s_txn < TX_MAX && len <= sizeof(s_tx[0].b)) {
		memcpy(s_tx[s_txn].b, data, len);
		s_tx[s_txn].n = len;
		s_tx[s_txn].conn = conn_handle;
		s_txn++;
	}
	return 0;
}

int ultrawidelock_ble_disconnect(uint16_t conn_handle)
{
	s_disconnects++;
	s_last_disconnected = conn_handle;
	return 0;
}

/* ---- device-side BleSK mirror + script helpers --------------------------- */

/* BleSKReader (the reader's seal key): the device opens with direction-0
 * nonces, mirroring ultrawidelock_msg_open — see test_ultrawidelock_reader.c's ph_open_ble. */
static uint8_t k_blesk_r[ULTRAWIDELOCK_SESSION_KEY_LEN];
static uint8_t k_blesk_d[ULTRAWIDELOCK_SESSION_KEY_LEN];
static uint32_t s_open_ctr = 1; /* §11.8: BLE-channel counters start at 1 */

static int open_ble(const uint8_t *w, size_t wl, uint8_t *plain, size_t *plen)
{
	if (wl < 4u + ULTRAWIDELOCK_GCM_TAG_LEN) {
		return -1;
	}
	size_t clen = ((size_t)w[2] << 8) | w[3];

	if (clen < ULTRAWIDELOCK_GCM_TAG_LEN || 4u + clen > wl) {
		return -1;
	}
	size_t payn = clen - ULTRAWIDELOCK_GCM_TAG_LEN;
	uint8_t aad[4] = {w[0], w[1], (uint8_t)(payn >> 8), (uint8_t)payn};
	uint8_t nonce[ULTRAWIDELOCK_GCM_NONCE_LEN];

	ultrawidelock_crypto_gcm_nonce(0, s_open_ctr, nonce);
	if (ultrawidelock_aes256_gcm_decrypt(k_blesk_r, nonce, sizeof(nonce), aad, sizeof(aad), w + 4,
				     payn, w + 4 + payn, ULTRAWIDELOCK_GCM_TAG_LEN, plain + 4) != 0) {
		return -1;
	}
	s_open_ctr++;
	memcpy(plain, aad, 4);
	*plen = 4 + payn;
	return 0;
}

/* Invoke the captured transmit callback with an engine-plaintext message
 * ([proto][id][len_be16][payload]), as the adapter would. */
static void tx_push(const uint8_t *plain, size_t n, uint16_t conn)
{
	uint8_t storage[sizeof(struct ultrawidelock_uwb_message) + 64] __attribute__((aligned(8)));
	struct ultrawidelock_uwb_message *m = (struct ultrawidelock_uwb_message *)storage;

	m->len = n;
	memcpy(m->data, plain, n);
	s_tx_cb(m, NULL, (void *)(uintptr_t)conn, false);
}

/* Invoke the captured event callback with a SESSION_STATUS event. */
static void ev_status(enum cherry_ccc_session_state st, uint16_t conn)
{
	struct cherry_ccc_session_event_session_status status = {
		.session_state = st,
		.reason_code = CHERRY_CCC_STATE_CHANGE_REASON_MGMT_CMD,
	};
	struct ultrawidelock_uwb_session_event ev = {
		.session = NULL,
		.type = ULTRAWIDELOCK_UWB_SESSION_EVENT_TYPE_SESSION_STATUS,
		.cherry_event = NULL,
	};

	ev.data.status = &status;
	s_ev_cb(&ev, (void *)(uintptr_t)conn);
}

static void ev_typed(enum ultrawidelock_uwb_session_event_type type, uint16_t conn)
{
	struct ultrawidelock_uwb_session_event ev = {
		.session = NULL,
		.type = type,
		.cherry_event = NULL,
	};

	ev.data.status = NULL;
	s_ev_cb(&ev, (void *)(uintptr_t)conn);
}

/* ---- the script ---------------------------------------------------------- */

int main(void)
{
	static const uint8_t zursk[ULTRAWIDELOCK_URSK_LEN];
	uint8_t ursk[ULTRAWIDELOCK_URSK_LEN];
	struct ultrawidelock_secchan sc;
	uint8_t irs[8] = {0x02, 0x01, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef};
	uint8_t plain[64];
	size_t pn;
	int before;

	okc("prim.init", ultrawidelock_prim_init() == 0);
	memset(ursk, 0xA7, sizeof(ursk));
	memset(k_blesk_r, 0x11, sizeof(k_blesk_r));
	memset(k_blesk_d, 0x22, sizeof(k_blesk_d));
	ultrawidelock_secchan_init(&sc, k_blesk_r, k_blesk_d);

	printf("P: API before init\n");
	okc("p.start", ultrawidelock_ranging_start(7, 1, ursk, &sc) == -1);
	okc("p.feed", ultrawidelock_ranging_feed(7, irs, sizeof(irs)) == -1);
	ultrawidelock_ranging_stop(7);
	okc("p.stop", s_sess_destroys == 0);

	printf("I: init\n");
	s_cherry_create_fail = true;
	okc("i.cherry_fail", ultrawidelock_ranging_init() == -1);
	okc("i.cherry_fail.no_adapter", s_cherry_creates == 1 && s_adapter_creates == 0);

	s_adapter_create_fail = true;
	okc("i.adapter_fail", ultrawidelock_ranging_init() == -1);
	okc("i.adapter_fail.cherry_released", s_cherry_creates == 2 && s_cherry_destroys == 1);

	okc("i.ok", ultrawidelock_ranging_init() == 0);
	okc("i.device", s_cherry_dev_ok);
	okc("i.adapter_bound", s_adapter_cherry == (struct cherry *)&s_cherry_dummy);
	okc("i.caps.bitmasks",
	    s_caps.slot_bitmask == 0xFFu && s_caps.sync_code_index_bitmask == 0x00000F00u &&
		    s_caps.hopping_config_bitmask == 0x1Au && s_caps.channel_bitmask == 0x03u);
	okc("i.caps.lists",
	    s_caps_proto0 == 0x0100u && s_caps_uwb0 == 0x0000u && s_caps_pulse0 == 0x00u &&
		    s_caps.minimum_ran_multiplier == 1u && !s_caps.qorvo_vendor_feature_1_supported);
	okc("i.reader_cfg",
	    s_rcfg.min_ran_multiplier == 1u && s_rcfg.preferred_hopping_configs.count == 2u &&
		    s_rcfg.preferred_hopping_configs.configs[0] == ULTRAWIDELOCK_HOPPING_CONFIG_DISABLED &&
		    s_rcfg.preferred_hopping_configs.configs[1] ==
			    ULTRAWIDELOCK_HOPPING_CONFIG_CONTINUOUS_DEFAULT &&
		    s_rcfg.mac_mode == 0u);
	okc("i.probe",
	    s_uwb_starts == 1 && s_uwb_cfg.session_id == 0u && s_uwb_cfg.channel == 9u &&
		    s_uwb_cfg.sync_code_index == 9u && s_uwb_cfg.slot_per_round == 1u &&
		    memcmp(s_uwb_ursk, zursk, sizeof(zursk)) == 0);
	okc("i.probe.released", s_uwb_stops == 1);

	okc("i.again", ultrawidelock_ranging_init() == 0);
	okc("i.again.noop", s_cherry_creates == 3 && s_adapter_creates == 2);

	printf("S: start\n");
	okc("s.null_ursk", ultrawidelock_ranging_start(7, 1, NULL, &sc) == -1);
	okc("s.null_sc", ultrawidelock_ranging_start(7, 1, ursk, NULL) == -1);

	s_sess_create_fail = true;
	okc("s.create_fail", ultrawidelock_ranging_start(7, 1, ursk, &sc) == -1);

	s_sess_set_ursk_fail = true;
	before = s_sess_destroys;
	okc("s.set_ursk_fail", ultrawidelock_ranging_start(7, 1, ursk, &sc) == -1);
	okc("s.set_ursk_fail.released", s_sess_destroys == before + 1);

	before = s_uwb_stops;
	okc("s.ok", ultrawidelock_ranging_start(7, 0x11223344u, ursk, &sc) == 0);
	okc("s.ok.radio_freed", s_uwb_stops == before + 1);
	okc("s.ok.prewarm", s_uwb_prewarms >= 1 && s_pw_ch == 9u && s_pw_sync == 9u);
	okc("s.ok.args",
	    s_sess_adapter == (struct ultrawidelock_uwb_adapter *)&s_adapter_dummy &&
		    s_sess_sid == 0x11223344u && s_ev_cb != NULL && s_tx_cb != NULL &&
		    s_sess_user == (void *)(uintptr_t)7);
	okc("s.ok.ursk", memcmp(s_sess_ursk, ursk, sizeof(ursk)) == 0);
	okc("s.ok.version", s_sess_ver == 0x0100u);
	/* A second peer finishing auth takes the radio: the holder's session is
	 * torn down, the newcomer's is armed. Refusing the newcomer used to turn
	 * a stale link (a Watch whose supervision timeout had not fired yet) into
	 * a GeneralError on its own reconnect. */
	before = s_sess_destroys;
	okc("s.preempt", ultrawidelock_ranging_start(8, 2, ursk, &sc) == 0);
	okc("s.preempt.holder_released", s_sess_destroys == before + 1);
	okc("s.preempt.owner", s_sess_user == (void *)(uintptr_t)8);
	okc("s.preempt.old_conn_dead", ultrawidelock_ranging_feed(7, irs, sizeof(irs)) == -1);
	/* Hand the radio back to conn 7; every feed scenario below is written to it. */
	okc("s.preempt.back", ultrawidelock_ranging_start(7, 0x11223344u, ursk, &sc) == 0);

	printf("F: feed\n");
	okc("f.wrong_conn", ultrawidelock_ranging_feed(8, irs, sizeof(irs)) == -1);
	okc("f.short", ultrawidelock_ranging_feed(7, irs, 3) == -1);
	{
		uint8_t big[257] = {0x02, 0x01, 0x00, 0xfd};

		okc("f.oversize", ultrawidelock_ranging_feed(7, big, sizeof(big)) == -1);
	}
	okc("f.ok", ultrawidelock_ranging_feed(7, irs, sizeof(irs)) == 0);
	okc("f.ok.msg",
	    s_handles == 1 && s_handle_sess == (struct ultrawidelock_uwb_session *)&s_sess_dummy &&
		    s_handle_len == sizeof(irs) && memcmp(s_handle_buf, irs, sizeof(irs)) == 0);
	/* Latency phases are stamped from each SDU's [proto][id], not from the
	 * order SDUs arrive in. The bench showed why: the phone sends a proto-2
	 * notification ahead of Initiate-Ranging-Session, and order-based
	 * labelling then shifted every device->reader stamp by one frame,
	 * putting "M2 received" on the IRS — before M1 had even been sent.
	 *
	 * ultrawidelock_lat_mark returns nonzero only when IT stamped the phase, so a
	 * nonzero here means "still unstamped", i.e. nothing mislabelled it.
	 * Each probe consumes its phase, so every scenario starts a fresh
	 * walk-up and asserts one thing. */
	printf("L: latency stamps follow message identity\n");
	{
		/* proto-3 id-0 (SUPPLEMENTARY_SERVICE): the SDU the phone
		 * actually sends ahead of the IRS, and which used to eat the
		 * IRS label. Observed on an iPhone in walkup-20260725-070057. */
		const uint8_t evt[8] = {0x03, 0x00, 0x00, 0x04, 0, 0, 0, 0};
		/* proto-1: M1/M2/M3/M4 are ids 0/1/2/3. */
		const uint8_t m2[8] = {0x01, 0x01, 0x00, 0x04, 0, 0, 0, 0};
		const uint8_t m4[8] = {0x01, 0x03, 0x00, 0x04, 0, 0, 0, 0};

		ultrawidelock_lat_begin();
		okc("l.stray_notify_keeps_irs_free",
		    ultrawidelock_ranging_feed(7, evt, sizeof(evt)) == 0 &&
			    ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_IRS_RX) != 0);

		ultrawidelock_lat_begin();
		okc("l.irs_is_not_m2", ultrawidelock_ranging_feed(7, irs, sizeof(irs)) == 0 &&
					       ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_M2_RX) != 0);

		ultrawidelock_lat_begin();
		okc("l.irs_stamps_irs", ultrawidelock_ranging_feed(7, irs, sizeof(irs)) == 0 &&
						ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_IRS_RX) == 0);

		ultrawidelock_lat_begin();
		okc("l.m2_stamps_m2", ultrawidelock_ranging_feed(7, m2, sizeof(m2)) == 0 &&
					      ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_M2_RX) == 0);

		ultrawidelock_lat_begin();
		okc("l.m4_stamps_m4", ultrawidelock_ranging_feed(7, m4, sizeof(m4)) == 0 &&
					      ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_M4_RX) == 0);
	}

	printf("F: feed (engine errors)\n");
	s_handle_rc = ULTRAWIDELOCK_UWB_ERR_MESSAGE_STATE;
	okc("f.engine_reject", ultrawidelock_ranging_feed(7, irs, sizeof(irs)) == -1);
	okc("f.engine_reject.session_kept", ultrawidelock_ranging_feed(7, irs, sizeof(irs)) == 0);

	printf("T: transmit callback\n");
	before = s_txn;
	tx_push(irs, sizeof(irs), 7);
	okc("t.sent", s_txn == before + 1 && s_tx[before].conn == 7 &&
			      s_tx[before].n == sizeof(irs) + ULTRAWIDELOCK_GCM_TAG_LEN);
	okc("t.open", open_ble(s_tx[before].b, s_tx[before].n, plain, &pn) == 0 &&
			      pn == sizeof(irs) && memcmp(plain, irs, sizeof(irs)) == 0);
	okc("t.freed", s_msg_frees == 1);
	{
		/* Second SDU: the reader-direction counter must have advanced to 2
		 * (open_ble tracks it), continuing the §11.8 sequence. */
		uint8_t m3[6] = {0x02, 0x03, 0x00, 0x02, 0x55, 0xaa};

		before = s_txn;
		tx_push(m3, sizeof(m3), 7);
		okc("t.counter", open_ble(s_tx[before].b, s_tx[before].n, plain, &pn) == 0 &&
					 pn == sizeof(m3) && memcmp(plain, m3, sizeof(m3)) == 0);
	}
	s_tx_cb(NULL, NULL, (void *)(uintptr_t)7, false);
	okc("t.null_msg", s_msg_frees_null == 1 && s_msg_frees == 2);

	before = s_txn;
	ultrawidelock_prim_host_fail_encrypt_after = 0; /* next GCM encrypt fails */
	tx_push(irs, sizeof(irs), 7);
	okc("t.seal_fail.terminates", s_txn == before && s_msg_frees == 3 &&
					 s_disconnects == 1);
	ultrawidelock_ranging_stop(7);
	ultrawidelock_secchan_init(&sc, k_blesk_r, k_blesk_d);
	okc("t.restart_after_seal_fail", ultrawidelock_ranging_start(7, 0x11223344u, ursk, &sc) == 0);

	s_ble_send_rc = -1; /* sealed fine, send fails: channel becomes terminal */
	tx_push(irs, sizeof(irs), 7);
	okc("t.send_fail.terminates", s_txn == before && s_msg_frees == 4 &&
				       s_disconnects == 2 && s_last_disconnected == 7);
	/* A later callback must neither send nor silently consume another counter.
	 * Continuing would hide counter loss until the peer rejected an unrelated
	 * frame. */
	tx_push(irs, sizeof(irs), 7);
	okc("t.send_fail.no_continuation", s_txn == before && s_msg_frees == 5 &&
					      s_disconnects == 2);

	printf("E: events\n");
	before = s_ev_frees;
	ev_status(CHERRY_CCC_SESSION_STATE_ACTIVE, 7);
	ev_status(CHERRY_CCC_SESSION_STATE_IDLE, 7);
	ev_status(CHERRY_CCC_SESSION_STATE_INIT, 7); /* default arm */
	ev_typed(ULTRAWIDELOCK_UWB_SESSION_EVENT_TYPE_SESSION_STATUS, 7); /* NULL status payload */
	ev_typed(ULTRAWIDELOCK_UWB_SESSION_EVENT_TYPE_SESSION_ERROR, 7);
	ev_typed(ULTRAWIDELOCK_UWB_SESSION_EVENT_TYPE_SESSION_CONTROLLER_REPORT, 7);
	okc("e.freed", s_ev_frees == before + 6);
	ev_status(CHERRY_CCC_SESSION_STATE_DEINIT, 8); /* wrong conn: session kept */
	okc("e.deinit_wrong_conn_still_terminal",
	     ultrawidelock_ranging_feed(7, irs, sizeof(irs)) == -1);
	ev_status(CHERRY_CCC_SESSION_STATE_DEINIT, 7); /* engine freed the session */
	okc("e.deinit", ultrawidelock_ranging_feed(7, irs, sizeof(irs)) == -1);

	okc("e.restart", ultrawidelock_ranging_start(9, 0x55667788u, ursk, &sc) == 0);
	s_handle_fire_deinit = true;
	s_handle_rc = ULTRAWIDELOCK_UWB_ERR_INTERNAL;
	okc("e.deinit_mid_handle", ultrawidelock_ranging_feed(9, irs, sizeof(irs)) == -1);
	okc("e.deinit_mid_handle.cleared", ultrawidelock_ranging_feed(9, irs, sizeof(irs)) == -1);

	printf("X: stop\n");
	okc("x.rearm", ultrawidelock_ranging_start(9, 3, ursk, &sc) == 0);
	before = s_sess_destroys;
	ultrawidelock_ranging_stop(4); /* wrong conn: no-op */
	okc("x.wrong_conn", s_sess_destroys == before && ultrawidelock_ranging_feed(9, irs, 8) == 0);
	ultrawidelock_ranging_stop(9);
	okc("x.stopped", s_sess_destroys == before + 1 && ultrawidelock_ranging_feed(9, irs, 8) == -1);
	ultrawidelock_ranging_stop(9); /* already inactive: no-op */
	okc("x.stop_idempotent", s_sess_destroys == before + 1);

	/* The secure channel was dropped at stop: a late engine TX is rejected
	 * (and still freed), and the destroy-emitted DEINIT echo is a no-op. */
	before = s_txn;
	tx_push(irs, sizeof(irs), 9);
	okc("x.tx_after_stop", s_txn == before && s_msg_frees == 6);
	ev_status(CHERRY_CCC_SESSION_STATE_DEINIT, 9);
	okc("x.deinit_echo", ultrawidelock_ranging_feed(9, irs, 8) == -1);

	okc("x.restart", ultrawidelock_ranging_start(3, 5, ursk, &sc) == 0);

	/* TX-side identity stamping, deliberately last: it pushes extra engine
	 * messages, which would shift the free/nonce counters T and X assert on.
	 * The second reader transmission of a setup is M3, and it must not be
	 * able to claim the M1 label merely by being a transmission. */
	printf("L: latency stamps follow message identity (TX)\n");
	{
		const uint8_t m1[8] = {0x01, 0x00, 0x00, 0x04, 0, 0, 0, 0};
		const uint8_t m3[8] = {0x01, 0x02, 0x00, 0x04, 0, 0, 0, 0};

		ultrawidelock_lat_begin();
		tx_push(m3, sizeof(m3), 3);
		okc("l.m3_is_not_m1", ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_M1_TX) != 0);

		ultrawidelock_lat_begin();
		tx_push(m1, sizeof(m1), 3);
		okc("l.m1_stamps_m1", ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_M1_TX) == 0);

		ultrawidelock_lat_begin();
		tx_push(m3, sizeof(m3), 3);
		okc("l.m3_stamps_m3", ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_M3_TX) == 0);
	}

	ultrawidelock_ranging_stop(3);

	printf("\nRESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
	return fails == 0 ? 0 : 1;
}
