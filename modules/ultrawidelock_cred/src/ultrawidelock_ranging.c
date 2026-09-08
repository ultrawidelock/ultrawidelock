/* SPDX-License-Identifier: ISC */

// UWB ranging bring-up and lifecycle for the credential reader: initializes the reader's UWB
// adapter and Cherry CCC context once, then arms, feeds, and tears down per-connection ranging
// sessions driven by the M1-M4 setup exchanged over the peer's L2CAP channel.
// Maintains process-wide singletons for the Cherry context and adapter (set up once via
// ultrawidelock_ranging_init) and for the single active ranging session (the DW3000 supports only
// one session at a time), tracking its owning secure channel for send/receive framing.
/*
 * ultrawidelock_ranging — see ultrawidelock_ranging.h. Drives the engine reader adapter/session
 * for the post-auth M1-M4 ranging-setup exchange. The call contract mirrors the
 * reference reader (integrations/nrfconnect-door-lock/patches/custom_impl-uwb.patch).
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ultrawidelock_log.h"

#include "ultrawidelock_ble.h"
#include "ultrawidelock_crypto.h"
#include "ultrawidelock_lab.h"
#include "ultrawidelock_lat.h"
#include <ultrawidelock/uwb.h>

#include "cherry/cherry.h"
#include "cherry/cherry_ccc.h"
#include "ultrawidelock_uwb_adapter/ultrawidelock_uwb_adapter.h"
#include "ultrawidelock_uwb_adapter/ultrawidelock_uwb_session.h"

#include "ultrawidelock_ranging.h"

LOG_MODULE_REGISTER(ultrawidelock_ranging, CONFIG_ULTRAWIDELOCK_CRED_LOG_LEVEL);

#define ULTRAWIDELOCK_VERSION         0x0100u
/* Upper bound on an inbound ranging SDU (mirrors the reference kMaxBleMessage). */
#define ULTRAWIDELOCK_RANGING_MSG_MAX 256u

/* Reader-side selection preferences. BORROWED for the adapter's lifetime (the
 * adapter stores the pointer, not a copy), so this must have static storage. */
static struct ultrawidelock_uwb_adapter_reader_config s_reader_cfg = {
	.min_ran_multiplier = 1u,
	.preferred_hopping_configs =
		{
			.configs = {ULTRAWIDELOCK_HOPPING_CONFIG_DISABLED,
				    ULTRAWIDELOCK_HOPPING_CONFIG_CONTINUOUS_DEFAULT},
			.count = 2u,
		},
	.mac_mode = 0u, /* 1 ranging round, offset 0, single antenna */
	.r1_antennas = {0u, 0u},
	.r2_antennas = {0u, 0u},
};

// Process-wide handle to the active Cherry CCC context, or NULL if ranging has not been set up.
static struct cherry *s_cherry;
// Process-wide handle to the active credential UWB adapter, or NULL if ranging has not been set up.
static struct ultrawidelock_uwb_adapter *s_adapter;

/* The single active ranging session (the DW3000 is single-session). Owned and
 * mutated only on the BLE-host task. s_sess is cleared when the engine frees the
 * session (a DEINIT status event) or when we tear it down. */
static struct ultrawidelock_uwb_session *s_sess;
static uint16_t s_sess_conn;
static bool s_sess_active;
/* Set after any ambiguous transport result. The owning reader connection is
 * disconnected and no further counters/messages may be consumed meanwhile. */
static bool s_transport_failed;

/* The connection's BleSK ranging channel (owned by the reader session), used to
 * seal the engine's outbound SDUs. Borrowed for the session's lifetime. */
static struct ultrawidelock_secchan *s_sc_ble;

/* Ranging-SDU identity, as [proto][id] on the wire. Mirrors the engine's
 * ultrawidelock_uwb_msg_spec.h, which is private to ultrawidelock_uwb; test_ultrawidelock_ranging.c
 * asserts these still agree with the frames the engine builds. */
#define RSDU_PROTO_RANGING      0x01u
#define RSDU_PROTO_NOTIFICATION 0x02u
#define RSDU_RANGING_M1         0x00u
#define RSDU_RANGING_M2         0x01u
#define RSDU_RANGING_M3         0x02u
#define RSDU_RANGING_M4         0x03u
#define RSDU_NOTIFY_RANGING     0x01u /* Initiate-Ranging-Session */

/* Stamp the latency phase this SDU actually is, by identity rather than by
 * arrival order. Order-based labelling was wrong on real hardware: the phone
 * sends a proto-3 (supplementary-service) SDU ahead of
 * Initiate-Ranging-Session, which shifted every device->reader label by one
 * frame and stamped "M2 received" on the IRS, i.e. before M1 had been sent.
 * Diagnostics only; the protocol never depended on this. */
static void lat_mark_sdu(uint8_t proto, uint8_t id)
{
	if (proto == RSDU_PROTO_NOTIFICATION && id == RSDU_NOTIFY_RANGING) {
		(void)ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_IRS_RX);
	} else if (proto == RSDU_PROTO_RANGING) {
		switch (id) {
		case RSDU_RANGING_M1:
			(void)ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_M1_TX);
			break;
		case RSDU_RANGING_M2:
			(void)ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_M2_RX);
			break;
		case RSDU_RANGING_M3:
			(void)ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_M3_TX);
			break;
		case RSDU_RANGING_M4:
			(void)ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_M4_RX);
			break;
		default:
			break;
		}
	}
}

/* ---- engine callbacks (invoked synchronously on the BLE-host task) ---- */

/* Send an adapter-built message verbatim over the peer's L2CAP channel. The
 * bytes already carry the 4-byte credential header; hand them straight to the BLE
 * send. We own the message and MUST free it (even if we don't send). */
static void uwb_tx_cb(struct ultrawidelock_uwb_message *message,
		      struct ultrawidelock_uwb_session *session, void *user_data, bool timeout)
{
	(void)session;
	(void)timeout;
	uint16_t conn = (uint16_t)(uintptr_t)user_data;

	if (message != NULL) {
		uint8_t wire[ULTRAWIDELOCK_RANGING_MSG_MAX + ULTRAWIDELOCK_GCM_TAG_LEN];
		size_t wl;

		/* The engine hands us a plaintext [proto][id][len][payload]; BleSK-seal it
		 * (§11.8.2, the 4-byte header as AAD) before it goes on the wire. */
		if (!s_transport_failed && s_sc_ble != NULL &&
		    ultrawidelock_msg_seal(s_sc_ble, message->data, message->len, wire,
					       sizeof(wire), &wl) == 0) {
			int rc = ultrawidelock_ble_send(conn, wire, wl);

			LOG_DBG("[conn %u] ranging TX proto=0x%02x id=0x%02x (%u B, rc=%d)", conn,
				message->data[0], message->data[1], (unsigned)wl, rc);
			if (rc == 0) {
				lat_mark_sdu(message->data[0], message->data[1]);
				ultrawidelock_lab_evi2("rtx", "proto", message->data[0], "id",
						 message->data[1]);
			} else {
				/* seal already consumed the counter. Transport acceptance is
				 * ambiguous, so this channel is terminal rather than rewound. */
				s_transport_failed = true;
				LOG_ERR("[conn %u] ranging transport result ambiguous; disconnecting", conn);
				(void)ultrawidelock_ble_disconnect(conn);
			}
		} else {
			if (!s_transport_failed) {
				LOG_ERR("[conn %u] ranging TX seal failed (%u B)", conn,
					(unsigned)message->len);
				s_transport_failed = true;
				(void)ultrawidelock_ble_disconnect(conn);
			}
		}
	}
	ultrawidelock_uwb_session_message_free(message);
}

/* Session notifications. On DEINIT the engine frees the session right after this
 * returns, so never touch event->session here; identify via user_data. Every
 * event must be freed. */
static void uwb_ev_cb(struct ultrawidelock_uwb_session_event *event, void *user_data)
{
	uint16_t conn = (uint16_t)(uintptr_t)user_data;

	if (event->type == ULTRAWIDELOCK_UWB_SESSION_EVENT_TYPE_SESSION_STATUS &&
	    event->data.status != NULL) {
		switch (event->data.status->session_state) {
		case CHERRY_CCC_SESSION_STATE_ACTIVE:
			ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_M4_DONE);
			LOG_INF("[conn %u] UWB ranging ACTIVE (negotiated "
				"params live)",
				conn);
			break;
		case CHERRY_CCC_SESSION_STATE_IDLE:
			LOG_INF("[conn %u] UWB session IDLE", conn);
			break;
		case CHERRY_CCC_SESSION_STATE_DEINIT:
			LOG_INF("[conn %u] UWB session DEINIT (freed)", conn);
			if (s_sess_conn == conn) {
				s_sess = NULL;
				s_sess_active = false;
			}
			break;
		default:
			break;
		}
	} else if (event->type == ULTRAWIDELOCK_UWB_SESSION_EVENT_TYPE_SESSION_ERROR) {
		LOG_WRN("[conn %u] UWB session ERROR", conn);
	}
	ultrawidelock_uwb_session_event_free(event);
}

/* ---- public API ---- */

int ultrawidelock_ranging_init(void)
{
	if (s_adapter != NULL) {
		return 0; /* already up */
	}
	s_cherry = cherry_create("dw3000-fira", NULL, NULL);
	if (s_cherry == NULL) {
		LOG_ERR("cherry_create failed");
		return -1;
	}

	/* Advertised CCC capabilities. Deep-copied by create_reader, so these
	 * locals need not outlive the call. Values match the reference reader. */
	uint16_t proto[] = {ULTRAWIDELOCK_VERSION};
	uint16_t uwb_configs[] = {0x0000u};
	uint8_t pulse_combos[] = {0x00u};
	// CCC capabilities advertised to the credential UWB adapter for this reader.
	struct cherry_ccc_capabilities ccc = {
		.slot_bitmask = 0xFFu,
		.sync_code_index_bitmask = 0x00000F00u, /* SYNC codes 9..12 */
		.hopping_config_bitmask = 0x1Au,        /* default + continuous + none */
		.channel_bitmask = 0x03u,               /* ch5 + ch9 */
		.protocol_versions = {.len = 1u, .items = proto},
		.uwb_configs = {.len = 1u, .items = uwb_configs},
		.pulse_shape_combos = {.len = 1u, .items = pulse_combos},
		.minimum_ran_multiplier = 1u,
		.qorvo_vendor_feature_1_supported = false,
	};
	// Device capabilities event reported by CCC, describing supported protocol versions, UWB
	// configurations, and pulse shape combinations.
	struct cherry_core_event_device_capabilities caps = {
		.status_err = CHERRY_ERR_NONE,
		.fira_capabilities = NULL,
		.ccc_capabilities = &ccc,
		.radar_capabilities = NULL,
	};

	s_adapter = ultrawidelock_uwb_adapter_create_reader(s_cherry, &caps, &s_reader_cfg);
	if (s_adapter == NULL) {
		LOG_ERR("ultrawidelock_uwb_adapter_create_reader failed");
		cherry_destroy_sync(s_cherry);
		s_cherry = NULL;
		return -1;
	}
	LOG_INF("UWB ranging adapter ready");

	/* Prove + initialise the DW3000 here, in the clean reader-startup task, so the
	 * heavy dwt_probe/dwt_initialise never runs from the BLE-host callback at M4.
	 * That callback path (ultrawidelock_ranging_feed -> engine ->
	 * ultrawidelock_uwb_start_cred) has a shallow stack and no prior bring-up, and
	 * dwt_probe failed there (-1). A one-shot start+stop with a throwaway URSK leaves the radio
	 * probed (uwb_min's g_radio_ready latches); the real session at M4 then re-uses it —
	 * ccc_prepoll_listen skips the probe and only re-applies the negotiated channel. Non-fatal:
	 * if the radio is absent, auth still runs and M4 will surface the failure. */
	static const uint8_t k_probe_ursk[ULTRAWIDELOCK_URSK_LEN] = {0};
	// credential UWB Kconfig-equivalent probe configuration used to bring up the
	// ultrawidelock_uwb layer on this port.
	const struct ultrawidelock_uwb_cred_cfg probe_cfg = {
		.session_id = 0u,
		.channel = 9u,
		.sync_code_index = 9u,
		.slot_per_round = 1u,
		.ursk = k_probe_ursk,
	};
	if (ultrawidelock_uwb_start_cred(&probe_cfg) == 0) {
		ultrawidelock_uwb_stop(); /* release RX; the radio stays probed */
		LOG_INF("DW3000 radio probed at init (M4 will reuse it)");
	} else {
		LOG_WRN("DW3000 probe at init failed; M4 handoff may not range");
	}
	return 0;
}

int ultrawidelock_ranging_start(uint16_t conn_handle, uint32_t session_id, const uint8_t *ursk,
			struct ultrawidelock_secchan *sc_ble)
{
	if (s_adapter == NULL || ursk == NULL || sc_ble == NULL) {
		LOG_WRN("[conn %u] ranging start: adapter/keys not ready", conn_handle);
		return -1;
	}
	if (s_sess_active) {
		/* The DW3000 is single-session and the peer that just finished
		 * authenticating is the one at the door. Refusing here used to
		 * terminate ITS session ("ranging setup unavailable", a GeneralError
		 * on the phone) in favour of whichever link got the radio first; with
		 * more than one BLE connection slot that link is often a ghost of the
		 * same Watch whose supervision timeout has not yet fired, so the fresh
		 * reconnect lost to its own corpse every 3-4 s. Newest wins: the
		 * holder's ranging is torn down and its BLE session is left to close
		 * on its own (disconnect or RSSI fade), exactly as a stale link would. */
		LOG_WRN("[conn %u] ranging active on conn %u; preempting it (DW3000 is "
			"single-session)",
			conn_handle, s_sess_conn);
		ultrawidelock_ranging_stop(s_sess_conn);
	}

	/* Release the demo responder so the radio is free for the negotiated
	 * session (the engine re-starts it with M1-M4 params at M4). */
	ultrawidelock_uwb_stop();

	/* Pre-apply the session PHY now, while the phone spends ~400 ms deciding to
	 * send Initiate-Ranging-Session: our M1 offers exactly one UWB config
	 * (channel 9, SYNC code 9 — same values as probe_cfg above), so the M4-time
	 * start hits the shim's PHY cache and skips the dwt_configure long pole,
	 * arming RX in time for the earliest phone ranging block. Best-effort: on
	 * failure M4 falls back to the full configure. */
	(void)ultrawidelock_uwb_prewarm(9u, 9u);

	struct ultrawidelock_uwb_session *sess = ultrawidelock_uwb_session_create(
		s_adapter, session_id, uwb_ev_cb, uwb_tx_cb, (void *)(uintptr_t)conn_handle);

	if (sess == NULL) {
		LOG_ERR("[conn %u] session_create failed", conn_handle);
		return -1;
	}
	if (ultrawidelock_uwb_session_set_ursk(sess, ursk) != ULTRAWIDELOCK_UWB_ERR_NONE) {
		LOG_ERR("[conn %u] set_ursk failed", conn_handle);
		ultrawidelock_uwb_session_destroy(sess);
		return -1;
	}
	ultrawidelock_uwb_session_set_protocol_version(sess, ULTRAWIDELOCK_VERSION);

	s_sc_ble = sc_ble;
	s_sess = sess;
	s_sess_conn = conn_handle;
	s_sess_active = true;
	s_transport_failed = false;

	/* No eager M1: the engine emits it (via uwb_tx_cb, BleSK-sealed) when the
	 * device sends its Initiate-Ranging-Session (proto-2 id-1). */
	LOG_INF("[conn %u] ranging armed (session id 0x%08x); awaiting "
		"Initiate-Ranging-Session",
		conn_handle, (unsigned)session_id);
	return 0;
}

int ultrawidelock_ranging_feed(uint16_t conn_handle, const uint8_t *data, size_t len)
{
	if (!s_sess_active || s_transport_failed || s_sess == NULL || s_sess_conn != conn_handle) {
		return -1;
	}
	if (len < 4u || len > ULTRAWIDELOCK_RANGING_MSG_MAX) {
		LOG_WRN("[conn %u] ranging SDU size %u out of range", conn_handle, (unsigned)len);
		return -1;
	}

	/* Device->reader setup: Initiate-Ranging-Session, M2, M4 — but not
	 * necessarily as the first three SDUs, so stamp on identity. */
	lat_mark_sdu(data[0], data[1]);

	/* Stack-framed message (the engine copies/consumes it, does not retain). */
	uint8_t storage[sizeof(struct ultrawidelock_uwb_message) + ULTRAWIDELOCK_RANGING_MSG_MAX]
		__attribute__((aligned(8)));
	struct ultrawidelock_uwb_message *msg = (struct ultrawidelock_uwb_message *)storage;

	msg->len = len;
	memcpy(msg->data, data, len);
	ultrawidelock_lab_evi2("rrx", "proto", data[0], "id", data[1]);

	/* M4 makes the engine start the responder (cherry_ccc_shim ->
	 * ultrawidelock_uwb_start_cred) with the negotiated params. A hard error may DEINIT
	 * the session, which clears s_sess via uwb_ev_cb; don't touch it after. */
	enum ultrawidelock_uwb_err e = ultrawidelock_uwb_session_message_handle(s_sess, msg);

	if (e != ULTRAWIDELOCK_UWB_ERR_NONE) {
		LOG_WRN("[conn %u] message_handle err %d", conn_handle, (int)e);
		return -1;
	}
	return 0;
}

void ultrawidelock_ranging_stop(uint16_t conn_handle)
{
	if (!s_sess_active || s_sess == NULL || s_sess_conn != conn_handle) {
		return;
	}
	struct ultrawidelock_uwb_session *sess = s_sess;

	/* Clear first so the DEINIT event this destroy emits is a no-op, and a
	 * direct free (no CCC session yet) leaves no dangling pointer. */
	s_sess = NULL;
	s_sess_active = false;
	s_transport_failed = false;
	s_sc_ble = NULL; /* borrowed from the reader session; drop before it is freed */
	LOG_INF("[conn %u] tearing down UWB ranging session", conn_handle);
	ultrawidelock_uwb_session_destroy(sess);
}
