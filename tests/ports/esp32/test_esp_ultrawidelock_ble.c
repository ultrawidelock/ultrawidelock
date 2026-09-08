/*
 * Host test for the ESP32 BLE transport (ultrawidelock_ble.c) against the sdkfake/
 * NimBLE recording doubles. "Theatre" suite: the NimBLE host, controller and
 * radio are all fakes, so passing proves the unit's wire-payload assembly and
 * branch logic (advert service data, READ payload, version WRITE validation,
 * CoC tracking, send/receive paths, retry/refresh scheduling) — not that a
 * phone can actually connect. The dynamic-tag bytes ARE cross-checked against
 * ultrawidelock_advtag_derive(), and the wall clock is overridden so both the
 * live-expiry and no-clock advert forms are pinned byte-for-byte.
 *
 * Sections (one linear script; the unit's state is process-global):
 *   A  config capture + READ payload (via the GATT access callback)
 *   B  device-version WRITE validation branches
 *   C  standalone start (ultrawidelock_ble_start) incl. NVS-erase + failure branches
 *   D  attach-mode start, advert assembly (bare UUID and full 0xFFF2 forms)
 *   E  GAP events: connect, conn-update retry ladder, disconnect, adv-complete
 *   F  L2CAP CoC: accept/connected/data/disconnected, send paths
 *   G  host-task marshaling: reader-status post, time_updated, adv refresh
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "host/ble_hs.h"
#include "host/ble_hs_id.h"
#include "host/ble_l2cap.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "nvs.h"
#include "services/gap/ble_svc_gap.h"
#include "esp_console.h" /* unused; keeps the fake include tree honest */

#include "ultrawidelock_advtag.h"
#include "ultrawidelock_ble.h"

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

/* ---- wall-clock override: ultrawidelock_ble.c calls time(NULL) ------------------- */
static time_t s_fake_now;

time_t time(time_t *out)
{
	if (out != NULL) {
		*out = s_fake_now;
	}
	return s_fake_now;
}

/* ---- app callbacks (recording) ------------------------------------------ */
static uint16_t s_conn_evts[8], s_disc_evts[8];
static int s_conn_count, s_disc_count;
static uint8_t s_rx[600];
static uint16_t s_rx_len, s_rx_conn;
static int s_rx_count;

static void on_data(uint16_t conn, const uint8_t *data, uint16_t len)
{
	s_rx_conn = conn;
	s_rx_len = len;
	if (len <= sizeof(s_rx)) {
		memcpy(s_rx, data, len);
	}
	s_rx_count++;
}

static void on_connected(uint16_t conn)
{
	if (s_conn_count < 8) {
		s_conn_evts[s_conn_count] = conn;
	}
	s_conn_count++;
}

static void on_disconnected(uint16_t conn)
{
	if (s_disc_count < 8) {
		s_disc_evts[s_disc_count] = conn;
	}
	s_disc_count++;
}

static uint16_t s_rssi_conn;
static int8_t s_rssi_val;
static int s_rssi_count;

static void on_rssi(uint16_t conn, int8_t rssi_dbm)
{
	s_rssi_conn = conn;
	s_rssi_val = rssi_dbm;
	s_rssi_count++;
}

static const uint16_t k_versions[2] = {0x0100, 0x0200};

static struct ultrawidelock_ble_config base_cfg(void)
{
	struct ultrawidelock_ble_config cfg = {
		.proto_versions = k_versions,
		.proto_versions_count = 2,
		.features = {.timesync_procedure_0 = true, .le_coded_phy = true},
		.cb = {.on_data = on_data,
		       .on_connected = on_connected,
		       .on_disconnected = on_disconnected},
	};
	return cfg;
}

/* Fetch the two access callbacks from the service definition the unit exports. */
static ble_gatt_access_fn chr_cb(int idx)
{
	const struct ble_gatt_svc_def *svc = ultrawidelock_ble_service_def();

	return svc->characteristics[idx].access_cb;
}

static void t_prepare_and_read_payload(void)
{
	printf("-- A: config capture + READ payload --\n");

	struct ultrawidelock_ble_config cfg = base_cfg();

	okc("prepare NULL cfg rejected", ultrawidelock_ble_prepare(NULL) == -1);

	struct ultrawidelock_ble_config bad = cfg;

	bad.proto_versions = NULL;
	okc("prepare NULL versions rejected", ultrawidelock_ble_prepare(&bad) == -1);
	bad = cfg;
	bad.proto_versions_count = 0;
	okc("prepare 0 versions rejected", ultrawidelock_ble_prepare(&bad) == -1);
	bad = cfg;
	bad.proto_versions_count = 9; /* > ULTRAWIDELOCK_MAX_VERSIONS */
	okc("prepare 9 versions rejected", ultrawidelock_ble_prepare(&bad) == -1);

	okc("prepare ok", ultrawidelock_ble_prepare(&cfg) == 0);
	okc("spsm getter", ultrawidelock_ble_spsm() == 0x0080u);

	/* READ: [SPSM be16][verLen][vers be16*2][featLen=1][features]. */
	struct os_mbuf om = {0};
	struct ble_gatt_access_ctxt ctxt = {.om = &om};
	static const uint8_t want[] = {0x00, 0x80, 0x04, 0x01, 0x00,
				       0x02, 0x00, 0x01, 0x05};

	okc("READ access rc", chr_cb(0)(1, 0, &ctxt, NULL) == 0);
	okc("READ payload bytes",
	    om.len == sizeof(want) && memcmp(om.data, want, sizeof(want)) == 0);

	fake_mbuf_append_rc = BLE_HS_ENOMEM;
	okc("READ append failure -> INSUFFICIENT_RES",
	    chr_cb(0)(1, 0, &ctxt, NULL) == BLE_ATT_ERR_INSUFFICIENT_RES);
	fake_mbuf_append_rc = 0;
}

static void t_device_version_write(void)
{
	printf("-- B: device-version WRITE branches --\n");

	struct os_mbuf om = {0};
	struct ble_gatt_access_ctxt ctxt = {.om = &om};

	/* Supported version 0x0200, empty feature list. */
	static const uint8_t w_ok[] = {0x02, 0x00, 0x00};

	memcpy(om.data, w_ok, sizeof(w_ok));
	om.len = sizeof(w_ok);
	okc("WRITE supported version", chr_cb(1)(1, 0, &ctxt, NULL) == 0);

	/* Unsupported version still returns 0 (logged only). */
	static const uint8_t w_unsup[] = {0x77, 0x77, 0x01, 0xAA};

	memcpy(om.data, w_unsup, sizeof(w_unsup));
	om.len = sizeof(w_unsup);
	okc("WRITE unsupported version accepted", chr_cb(1)(1, 0, &ctxt, NULL) == 0);

	om.len = 2; /* < 3 */
	okc("WRITE short rejected",
	    chr_cb(1)(1, 0, &ctxt, NULL) == BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN);

	static const uint8_t w_len[] = {0x01, 0x00, 0x05, 0xAA}; /* featLen lies */

	memcpy(om.data, w_len, sizeof(w_len));
	om.len = sizeof(w_len);
	okc("WRITE featLen mismatch rejected",
	    chr_cb(1)(1, 0, &ctxt, NULL) == BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN);

	fake_hs_mbuf_to_flat_rc = BLE_HS_ENOMEM;
	okc("WRITE flatten failure -> UNLIKELY",
	    chr_cb(1)(1, 0, &ctxt, NULL) == BLE_ATT_ERR_UNLIKELY);
	fake_hs_mbuf_to_flat_rc = 0;
}

static void t_standalone_start(void)
{
	printf("-- C: standalone start --\n");

	struct ultrawidelock_ble_config cfg = base_cfg();

	okc("start with bad cfg", ultrawidelock_ble_start(NULL) == -1);

	/* NVS wants an erase first (no-free-pages), then everything succeeds. */
	fake_nvs_reset();
	fake_nvs_init_rc_once = ESP_ERR_NVS_NO_FREE_PAGES;
	okc("start ok (with NVS erase)", ultrawidelock_ble_start(&cfg) == 0);
	okc("NVS erase ran", fake_nvs_erase_calls == 1);
	okc("device name set", strcmp(fake_svc_gap_name, "credential Reader") == 0);
	okc("L2CAP server on SPSM/MTU",
	    fake_l2cap_server_psm == 0x0080u && fake_l2cap_server_mtu == 512u);
	okc("host task handed to freertos glue", fake_nimble_host_task != NULL);

	/* Run the recorded host task: fake nimble_port_run returns immediately. */
	fake_nimble_host_task(NULL);
	okc("host task ran + deinit", fake_nimble_port_runs == 1 &&
	    fake_nimble_freertos_deinits == 1);

	/* Sync callback ensures an address and starts advertising. */
	okc("sync/reset callbacks installed",
	    ble_hs_cfg.sync_cb != NULL && ble_hs_cfg.reset_cb != NULL);

	/*
	 * Refreshes are no-ops until the advertiser is up, and "up" means either
	 * bring-up path -- this port's is the sync callback below, not
	 * start_attached(). Checked HERE because that is the last moment the
	 * unbrought-up state exists; it used to be checked after the callback had
	 * already run, which passed only because the flag was never set on this
	 * path at all. That was the bug: every later re-advertise silently did
	 * nothing, and SetAliroReaderConfig arrives after commissioning, so a
	 * provisioned reader never became approach-resolvable.
	 */
	fake_gap_adv_starts = 0;
	fake_eventq_count = 0;
	ultrawidelock_ble_readvertise();
	okc("readvertise before bring-up: no-op", fake_gap_adv_starts == 0);
	ultrawidelock_ble_time_updated();
	okc("time_updated before bring-up: no event", fake_eventq_count == 0);

	fake_gap_adv_starts = 0;
	ble_hs_cfg.sync_cb();
	okc("on_sync advertises", fake_gap_adv_starts == 1);
	ble_hs_cfg.reset_cb(7); /* logs only; must not crash */
	okc("on_reset tolerated", 1);

	/* on_sync failure branches. */
	fake_gap_adv_starts = 0;
	fake_hs_util_ensure_addr_rc = 1;
	ble_hs_cfg.sync_cb();
	okc("on_sync ensure_addr failure: no advertise", fake_gap_adv_starts == 0);
	fake_hs_util_ensure_addr_rc = 0;
	fake_hs_id_infer_rc = 1;
	ble_hs_cfg.sync_cb();
	okc("on_sync infer failure: no advertise", fake_gap_adv_starts == 0);
	fake_hs_id_infer_rc = 0;

	/* Failure injection, one call each. */
	fake_nimble_port_init_rc = ESP_FAIL;
	okc("nimble_port_init failure", ultrawidelock_ble_start(&cfg) == -1);
	fake_nimble_port_init_rc = ESP_OK;
	fake_gatts_count_rc = 1;
	okc("gatts_count failure", ultrawidelock_ble_start(&cfg) == -1);
	fake_gatts_count_rc = 0;
	fake_gatts_add_rc = 1;
	okc("gatts_add failure", ultrawidelock_ble_start(&cfg) == -1);
	fake_gatts_add_rc = 0;
	fake_svc_gap_name_set_rc = 1; /* warning only, start still succeeds */
	okc("device-name failure tolerated", ultrawidelock_ble_start(&cfg) == 0);
	fake_svc_gap_name_set_rc = 0;
}

static void t_attach_and_advert(void)
{
	printf("-- D: attach + advert assembly --\n");

	/*
	 * The host has already synced in the previous case, so the advertiser is
	 * up and a refresh must now REACH the radio. This is the property the
	 * FreeRTOS and ESP32 ports both depend on: Apple sends
	 * SetAliroReaderConfig after commissioning completes, and re-emitting is
	 * the only way a reader that advertised something else becomes
	 * approach-resolvable. The pre-bring-up no-op is checked in case C.
	 */
	fake_gap_adv_starts = 0;
	ultrawidelock_ble_readvertise();
	okc("readvertise after sync: re-emits", fake_gap_adv_starts == 1);

	fake_eventq_count = 0;
	ultrawidelock_ble_time_updated();
	okc("time_updated after sync: event queued", fake_eventq_count == 1);

	/* attach failure: infer_auto rejects. */
	fake_hs_id_infer_rc = 1;
	okc("start_attached infer failure", ultrawidelock_ble_start_attached() == -1);
	fake_hs_id_infer_rc = 0;

	/* Attach without a GRK: bare-UUID fallback advert. */
	fake_gap_adv_starts = 0;
	okc("start_attached ok", ultrawidelock_ble_start_attached() == 0);
	okc("fallback advert: bare UUID + name",
	    fake_gap_adv_starts == 1 && fake_gap_adv_fields.num_uuids16 == 1 &&
	    fake_gap_adv_fields.uuids16_is_complete == 1 &&
	    fake_gap_adv_fields.svc_data_uuid16 == NULL &&
	    strcmp((const char *)fake_gap_adv_name, "credential Reader") == 0);
	okc("advert flags GEN|BREDR_UNSUP",
	    fake_gap_adv_fields.flags == (BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP));
	okc("advert params UND/GEN",
	    fake_gap_adv_params.conn_mode == BLE_GAP_CONN_MODE_UND &&
	    fake_gap_adv_params.disc_mode == BLE_GAP_DISC_MODE_GEN);

	/* Provision adv params: full 0xFFF2 service data with a live expiry. */
	static const uint8_t group_id[8] = {0xA1, 2, 3, 4, 5, 6, 7, 8};
	static const uint8_t sub_id[2] = {0xAA, 0xBB};
	static const uint8_t grk[16] = {1, 2,  3,  4,  5,  6,  7,  8,
					9, 10, 11, 12, 13, 14, 15, 16};

	memcpy(fake_hs_id_addr, (const uint8_t[6]){0x10, 0x27, 0xC3, 0x86, 0xBB, 0xC4}, 6);
	s_fake_now = 1750000000; /* valid wall clock */
	ultrawidelock_ble_set_adv_params(group_id, sub_id, grk, -7);
	fake_gap_adv_stops = 0;
	fake_gap_adv_starts = 0;
	ultrawidelock_ble_readvertise();
	okc("readvertise stop+start", fake_gap_adv_stops == 1 && fake_gap_adv_starts == 1);
	okc("svc data length 26", fake_gap_adv_fields.svc_data_uuid16_len == 26);

	const uint8_t *sd = fake_gap_adv_svc_data;
	uint32_t expiry = ((uint32_t)sd[14] << 24) | ((uint32_t)sd[15] << 16) |
			  ((uint32_t)sd[16] << 8) | sd[17];

	okc("svc data uuid LE F2 FF", sd[0] == 0xF2 && sd[1] == 0xFF);
	okc("flags byte 0x80", sd[2] == 0x80);
	okc("tx power byte", (int8_t)sd[3] == -7);
	okc("group id bytes", memcmp(sd + 4, group_id, 8) == 0);
	okc("sub id bytes", memcmp(sd + 12, sub_id, 2) == 0);
	okc("expiry = now + 900", expiry == (uint32_t)s_fake_now + 900u);
	okc("reserved byte 0", sd[18] == 0);

	/* Cross-check the tag against the derivation (AdvA MSB-first). */
	uint8_t adva_msb[6] = {0xC4, 0xBB, 0x86, 0xC3, 0x27, 0x10};
	uint8_t want_tag[ULTRAWIDELOCK_ADVTAG_LEN];

	okc("advtag derive rc",
	    ultrawidelock_advtag_derive(grk, adva_msb, expiry, want_tag) == 0);
	okc("dynamic tag bytes", memcmp(sd + 19, want_tag, ULTRAWIDELOCK_ADVTAG_LEN) == 0);
	okc("tag refresh armed (valid clock)",
	    fake_last_callout != NULL && fake_last_callout->armed &&
	    fake_last_callout->armed_ticks == 450u * 1000u);

	/* No-clock form: epoch clock -> expiry unavailable, no refresh arm. */
	s_fake_now = 1000; /* 1970-ish: below the sanity floor */
	fake_last_callout->armed = 0;
	ultrawidelock_ble_readvertise();
	sd = fake_gap_adv_svc_data;
	okc("no-clock expiry FFFFFFFF",
	    sd[14] == 0xFF && sd[15] == 0xFF && sd[16] == 0xFF && sd[17] == 0xFF);
	okc("advtag derive (unavailable) rc",
	    ultrawidelock_advtag_derive(grk, adva_msb, ULTRAWIDELOCK_ADVTAG_EXPIRY_UNAVAILABLE,
					want_tag) == 0);
	okc("no-clock tag bytes", memcmp(sd + 19, want_tag, ULTRAWIDELOCK_ADVTAG_LEN) == 0);
	okc("no refresh armed without clock", fake_last_callout->armed == 0);

	/* Identity address unavailable -> fall back to the bare-UUID advert. */
	fake_hs_id_copy_rc = 1;
	ultrawidelock_ble_readvertise();
	okc("no-identity fallback advert", fake_gap_adv_fields.svc_data_uuid16 == NULL &&
	    fake_gap_adv_fields.num_uuids16 == 1);
	fake_hs_id_copy_rc = 0;

	/* adv_set_fields / adv_start failures are absorbed. */
	s_fake_now = 1750000000;
	fake_gap_adv_set_fields_rc = 1;
	ultrawidelock_ble_readvertise();
	okc("set_fields failure absorbed", 1);
	fake_gap_adv_set_fields_rc = 0;
	fake_gap_adv_start_rc = 1;
	ultrawidelock_ble_readvertise();
	okc("adv_start failure absorbed", 1);
	fake_gap_adv_start_rc = 0;
	ultrawidelock_ble_readvertise(); /* leave a good advert up for section E */
}

static void t_gap_events(void)
{
	printf("-- E: GAP events --\n");
	okc("gap cb captured", fake_gap_event_cb != NULL);

	struct ble_gap_event ev = {0};

	/* Failed connect -> re-advertise. */
	ev.type = BLE_GAP_EVENT_CONNECT;
	ev.connect.status = 1;
	ev.connect.conn_handle = 5;
	fake_gap_adv_starts = 0;
	okc("failed connect rc", fake_gap_event_cb(&ev, fake_gap_event_arg) == 0);
	okc("failed connect re-advertises", fake_gap_adv_starts == 1);

	/* Good connect -> fast conn-param request (15 ms floor). */
	ev.connect.status = 0;
	fake_gap_update_calls = 0;
	okc("connect rc", fake_gap_event_cb(&ev, fake_gap_event_arg) == 0);
	okc("conn update requested",
	    fake_gap_update_calls == 1 && fake_gap_update_params.itvl_min == 12 &&
	    fake_gap_update_params.itvl_max == 12 &&
	    fake_gap_update_params.supervision_timeout == 400);

	/* Rejected request logs a warning only. */
	fake_gap_update_rc = 42;
	okc("connect w/ rejected update", fake_gap_event_cb(&ev, fake_gap_event_arg) == 0);
	fake_gap_update_rc = 0;

	/* Conn update landed slow -> retry callout armed; retry re-requests. */
	ev.type = BLE_GAP_EVENT_CONN_UPDATE;
	ev.conn_update.status = 0;
	ev.conn_update.conn_handle = 5;
	fake_gap_conn_desc.conn_itvl = 24; /* 30 ms: slow */
	fake_last_callout = NULL;
	okc("slow conn-update rc", fake_gap_event_cb(&ev, fake_gap_event_arg) == 0);
	okc("retry armed at 500 ms",
	    fake_last_callout != NULL && fake_last_callout->armed &&
	    fake_last_callout->armed_ticks == 500);
	fake_gap_update_calls = 0;
	fake_last_callout->ev.fn(&fake_last_callout->ev); /* fire the retry */
	okc("retry re-requested", fake_gap_update_calls == 1);

	/* Retry fires but connection is gone / already fast. */
	fake_gap_update_calls = 0;
	fake_gap_conn_find_rc = 1;
	fake_last_callout->ev.fn(&fake_last_callout->ev);
	okc("retry: conn gone, no request", fake_gap_update_calls == 0);
	fake_gap_conn_find_rc = 0;
	fake_gap_conn_desc.conn_itvl = 12; /* fast now */
	fake_last_callout->ev.fn(&fake_last_callout->ev);
	okc("retry: already fast, no request", fake_gap_update_calls == 0);

	/* Fast-enough update: no further retry armed. */
	fake_last_callout->armed = 0;
	okc("fast conn-update rc", fake_gap_event_cb(&ev, fake_gap_event_arg) == 0);
	okc("no retry when fast", fake_last_callout->armed == 0);

	/* Exhaust the retry budget (3 tries). */
	fake_gap_conn_desc.conn_itvl = 24;
	for (int i = 0; i < 4; i++) {
		fake_gap_event_cb(&ev, fake_gap_event_arg);
		if (fake_last_callout->armed) {
			fake_last_callout->armed = 0;
			fake_last_callout->ev.fn(&fake_last_callout->ev);
		}
	}
	okc("retry budget exhausts (no re-arm)", fake_last_callout->armed == 0);

	/* Failed conn-update event + conn_find failure branch. */
	ev.conn_update.status = 3;
	okc("failed conn-update rc", fake_gap_event_cb(&ev, fake_gap_event_arg) == 0);

	/* Disconnect stops THIS link's retry and re-advertises. The retry state is
	 * per connection now: arm conn 5's retry again, then drop conn 5. */
	fake_gap_conn_desc.conn_itvl = 24;
	ev.type = BLE_GAP_EVENT_CONNECT;
	ev.connect.status = 0;
	ev.connect.conn_handle = 5;
	fake_gap_event_cb(&ev, fake_gap_event_arg); /* fresh budget for conn 5 */
	ev.type = BLE_GAP_EVENT_CONN_UPDATE;
	ev.conn_update.status = 0;
	fake_gap_event_cb(&ev, fake_gap_event_arg);
	okc("retry re-armed for conn 5", fake_last_callout != NULL && fake_last_callout->armed);
	/* Hold the retry callout: the disconnect path re-advertises, and that
	 * arms the tag-refresh callout, which moves fake_last_callout. */
	struct ble_npl_callout *retry5 = fake_last_callout;

	ev.type = BLE_GAP_EVENT_DISCONNECT;
	ev.disconnect.reason = 8;
	ev.disconnect.conn.conn_handle = 5;
	fake_gap_adv_starts = 0;
	okc("disconnect rc", fake_gap_event_cb(&ev, fake_gap_event_arg) == 0);
	okc("disconnect stops conn 5 retry", retry5->armed == 0);
	okc("disconnect re-advertises", fake_gap_adv_starts == 1);

	ev.type = BLE_GAP_EVENT_ADV_COMPLETE;
	fake_gap_adv_starts = 0;
	okc("adv-complete rc", fake_gap_event_cb(&ev, fake_gap_event_arg) == 0);
	okc("adv-complete re-advertises", fake_gap_adv_starts == 1);

	ev.type = 99;
	okc("unknown gap event ignored", fake_gap_event_cb(&ev, fake_gap_event_arg) == 0);
	fake_gap_conn_desc.conn_itvl = 12;
}

static void t_l2cap_coc(void)
{
	printf("-- F: L2CAP CoC --\n");
	okc("l2cap cb captured", fake_l2cap_event_cb != NULL);

	struct ble_l2cap_chan *chanA = (struct ble_l2cap_chan *)0x1111;
	struct ble_l2cap_event lev = {0};

	/* ACCEPT arms the first RX buffer. */
	lev.type = BLE_L2CAP_EVENT_COC_ACCEPT;
	lev.accept.chan = chanA;
	fake_l2cap_recv_ready_calls = 0;
	okc("accept arms rx", fake_l2cap_event_cb(&lev, fake_l2cap_event_arg) == 0 &&
	    fake_l2cap_recv_ready_calls == 1);

	/* ACCEPT with no buffers left. */
	fake_mbuf_alloc_fail = 1;
	okc("accept out of buffers",
	    fake_l2cap_event_cb(&lev, fake_l2cap_event_arg) == BLE_HS_ENOMEM);
	fake_mbuf_alloc_fail = 0;

	/* Failed CONNECTED: not tracked, no app callback. */
	lev.type = BLE_L2CAP_EVENT_COC_CONNECTED;
	lev.connect.status = 9;
	lev.connect.conn_handle = 7;
	lev.connect.chan = chanA;
	s_conn_count = 0;
	okc("failed coc connect", fake_l2cap_event_cb(&lev, fake_l2cap_event_arg) == 0 &&
	    s_conn_count == 0);

	/* Good CONNECTED tracks + notifies. */
	lev.connect.status = 0;
	okc("coc connected", fake_l2cap_event_cb(&lev, fake_l2cap_event_arg) == 0 &&
	    s_conn_count == 1 && s_conn_evts[0] == 7);

	/* Send happy path. */
	static const uint8_t msg[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x42};

	fake_l2cap_send_rc = 0;
	okc("send ok", ultrawidelock_ble_send(7, msg, sizeof(msg)) == 0);
	okc("send bytes on wire", fake_l2cap_sent_len == sizeof(msg) &&
	    memcmp(fake_l2cap_sent, msg, sizeof(msg)) == 0);

	/* ESTALLED counts as queued. */
	fake_l2cap_send_rc = BLE_HS_ESTALLED;
	okc("send stalled = queued", ultrawidelock_ble_send(7, msg, sizeof(msg)) == 0);

	/* Hard send failure frees the SDU. */
	fake_l2cap_send_rc = 5;
	fake_mbuf_frees = 0;
	okc("send hard failure", ultrawidelock_ble_send(7, msg, sizeof(msg)) == -1 &&
	    fake_mbuf_frees == 1);
	fake_l2cap_send_rc = 0;

	/* Argument + no-channel + alloc/append failures. */
	okc("send NULL data", ultrawidelock_ble_send(7, NULL, 5) == -1);
	okc("send zero len", ultrawidelock_ble_send(7, msg, 0) == -1);
	okc("send unknown conn", ultrawidelock_ble_send(42, msg, sizeof(msg)) == -1);
	fake_mbuf_alloc_fail = 1;
	okc("send alloc failure", ultrawidelock_ble_send(7, msg, sizeof(msg)) == -1);
	fake_mbuf_alloc_fail = 0;
	fake_mbuf_append_rc = BLE_HS_ENOMEM;
	fake_mbuf_frees = 0;
	okc("send append failure frees", ultrawidelock_ble_send(7, msg, sizeof(msg)) == -1 &&
	    fake_mbuf_frees == 1);
	fake_mbuf_append_rc = 0;

	/* CoC slot table is size 1: a second channel is silently untracked. */
	struct ble_l2cap_chan *chanB = (struct ble_l2cap_chan *)0x2222;

	lev.connect.conn_handle = 8;
	lev.connect.chan = chanB;
	okc("second coc connect (table full)",
	    fake_l2cap_event_cb(&lev, fake_l2cap_event_arg) == 0);
	okc("send to untracked conn fails", ultrawidelock_ble_send(8, msg, sizeof(msg)) == -1);

	/* DATA_RECEIVED dispatches to on_data and re-arms. */
	struct os_mbuf sdu = {0};
	static const uint8_t payload[] = {1, 2, 3, 4, 5, 6};

	memcpy(sdu.data, payload, sizeof(payload));
	sdu.len = sizeof(payload);
	lev.type = BLE_L2CAP_EVENT_COC_DATA_RECEIVED;
	lev.receive.conn_handle = 7;
	lev.receive.chan = chanA;
	lev.receive.sdu_rx = &sdu;
	s_rx_count = 0;
	fake_l2cap_recv_ready_calls = 0;
	okc("coc data rc", fake_l2cap_event_cb(&lev, fake_l2cap_event_arg) == 0);
	okc("on_data got the SDU", s_rx_count == 1 && s_rx_conn == 7 &&
	    s_rx_len == sizeof(payload) && memcmp(s_rx, payload, sizeof(payload)) == 0);
	okc("SDU freed + re-armed", sdu.freed == 1 && fake_l2cap_recv_ready_calls == 1);

	/* NULL SDU still re-arms; flatten failure drops silently. */
	lev.receive.sdu_rx = NULL;
	fake_l2cap_recv_ready_calls = 0;
	okc("coc data NULL sdu", fake_l2cap_event_cb(&lev, fake_l2cap_event_arg) == 0 &&
	    fake_l2cap_recv_ready_calls == 1);
	sdu.freed = 0;
	lev.receive.sdu_rx = &sdu;
	fake_hs_mbuf_to_flat_rc = BLE_HS_ENOMEM;
	s_rx_count = 0;
	okc("coc data flatten failure", fake_l2cap_event_cb(&lev, fake_l2cap_event_arg) == 0 &&
	    s_rx_count == 0 && sdu.freed == 1);
	fake_hs_mbuf_to_flat_rc = 0;

	/* DISCONNECTED untracks + notifies; then the channel is gone. */
	lev.type = BLE_L2CAP_EVENT_COC_DISCONNECTED;
	lev.disconnect.conn_handle = 7;
	lev.disconnect.chan = chanA;
	s_disc_count = 0;
	okc("coc disconnected", fake_l2cap_event_cb(&lev, fake_l2cap_event_arg) == 0 &&
	    s_disc_count == 1 && s_disc_evts[0] == 7);
	okc("send after disconnect fails", ultrawidelock_ble_send(7, msg, sizeof(msg)) == -1);

	/* Unknown / repeat-disconnect events are tolerated. */
	okc("repeat disconnect tolerated",
	    fake_l2cap_event_cb(&lev, fake_l2cap_event_arg) == 0);
	lev.type = 88;
	okc("unknown l2cap event ignored",
	    fake_l2cap_event_cb(&lev, fake_l2cap_event_arg) == 0);
}

static bool s_status_flag;
static int s_status_calls;
static int s_presence_reset_calls;

static void status_cb(bool unsecured)
{
	s_status_flag = unsecured;
	s_status_calls++;
}

static void presence_reset_cb(void)
{
	s_presence_reset_calls++;
}

static void t_marshaling(void)
{
	printf("-- G: host-task marshaling --\n");

	/* Reader-status post: queued, then runs on the drained \"host task\". */
	fake_eventq_count = 0;
	ultrawidelock_ble_post_reader_status(status_cb, true);
	okc("status posted not yet run", fake_eventq_count == 1 && s_status_calls == 0);
	fake_nimble_drain_eventq();
	okc("status ran unsecured=true", s_status_calls == 1 && s_status_flag == true);
	ultrawidelock_ble_post_reader_status(status_cb, false);
	fake_nimble_drain_eventq();
	okc("status ran unsecured=false", s_status_calls == 2 && s_status_flag == false);

	/* Presence reset uses its own event slot and runs on that same host task. */
	fake_eventq_count = 0;
	ultrawidelock_ble_post_presence_reset(presence_reset_cb);
	okc("presence reset posted not yet run",
	    fake_eventq_count == 1 && s_presence_reset_calls == 0);
	fake_nimble_drain_eventq();
	okc("presence reset ran", s_presence_reset_calls == 1);

	/* time_updated after attach posts the refresh event. */
	fake_eventq_count = 0;
	ultrawidelock_ble_time_updated();
	okc("time_updated posts refresh", fake_eventq_count == 1);

	/* Refresh with the advertiser up: stop + re-derive + restart. */
	s_fake_now = 1760000000;
	fake_gap_adv_active_val = 1;
	fake_gap_adv_stops = 0;
	fake_gap_adv_starts = 0;
	fake_nimble_drain_eventq();
	okc("refresh stop+restart", fake_gap_adv_stops == 1 && fake_gap_adv_starts == 1);

	const uint8_t *sd = fake_gap_adv_svc_data;
	uint32_t expiry = ((uint32_t)sd[14] << 24) | ((uint32_t)sd[15] << 16) |
			  ((uint32_t)sd[16] << 8) | sd[17];

	okc("refresh re-derived expiry", expiry == (uint32_t)s_fake_now + 900u);

	/* Refresh while the advertiser is paused: no restart. */
	ultrawidelock_ble_time_updated();
	fake_gap_adv_active_val = 0;
	fake_gap_adv_starts = 0;
	fake_nimble_drain_eventq();
	okc("refresh no-op while paused", fake_gap_adv_starts == 0);
}

static void t_leftover_branches(void)
{
	printf("-- H: leftover branches --\n");

	/* timesync_procedure_1 feature bit (bit 1) in the READ payload. */
	struct ultrawidelock_ble_config cfg = base_cfg();

	cfg.features.timesync_procedure_0 = false;
	cfg.features.timesync_procedure_1 = true;
	cfg.features.le_coded_phy = false;
	okc("re-prepare (proc-1 only)", ultrawidelock_ble_prepare(&cfg) == 0);

	struct os_mbuf om = {0};
	struct ble_gatt_access_ctxt ctxt = {.om = &om};

	okc("READ rc (proc-1)", chr_cb(0)(1, 0, &ctxt, NULL) == 0);
	okc("features byte 0x02", om.len == 9 && om.data[8] == 0x02);

	/* L2CAP server registration failure is logged + absorbed. */
	fake_l2cap_create_server_rc = 7;
	okc("l2cap server failure absorbed", ultrawidelock_ble_start_attached() == 0);
	fake_l2cap_create_server_rc = 0;

	/* CONN_UPDATE when the connection has already vanished. */
	struct ble_gap_event ev = {0};

	ev.type = BLE_GAP_EVENT_CONN_UPDATE;
	ev.conn_update.status = 0;
	ev.conn_update.conn_handle = 5;
	fake_gap_conn_find_rc = 1;
	okc("conn-update on a gone connection",
	    fake_gap_event_cb(&ev, fake_gap_event_arg) == 0);
	fake_gap_conn_find_rc = 0;
}

/* G: RSSI power gate — the connection-RSSI poll (armed only when on_rssi is set)
 * and the reader-initiated disconnect the gate uses when a peer departs. */
static void t_rssi_gate_poll(void)
{
	printf("-- G: RSSI power-gate poll --\n");

	/* on_rssi non-NULL turns the poll on; base_cfg leaves it off. */
	struct ultrawidelock_ble_config cfg = base_cfg();

	cfg.cb.on_rssi = on_rssi;
	okc("prepare with on_rssi", ultrawidelock_ble_prepare(&cfg) == 0);

	struct ble_l2cap_chan *chan = (struct ble_l2cap_chan *)0x3333;
	struct ble_l2cap_event lev = {0};

	fake_gap_rssi_rc = 0;
	fake_gap_rssi_value = -58;
	fake_last_callout = NULL;
	s_rssi_count = 0;

	/* CoC-open arms the poll and takes the first sample inline (no poll-period
	 * latency at the door). */
	lev.type = BLE_L2CAP_EVENT_COC_CONNECTED;
	lev.connect.status = 0;
	lev.connect.conn_handle = 9;
	lev.connect.chan = chan;
	okc("coc connect", fake_l2cap_event_cb(&lev, fake_l2cap_event_arg) == 0);
	okc("first RSSI sampled inline",
	    s_rssi_count == 1 && s_rssi_conn == 9 && s_rssi_val == -58);
	okc("poll callout armed at 250 ms", fake_last_callout != NULL &&
	    fake_last_callout->armed && fake_last_callout->armed_ticks == 250u);

	/* Firing the callout re-samples and re-arms. */
	fake_gap_rssi_value = -62;
	fake_last_callout->ev.fn(&fake_last_callout->ev);
	okc("poll re-samples", s_rssi_count == 2 && s_rssi_val == -62);
	okc("poll re-arms", fake_last_callout->armed == 1);

	/* A failed RSSI read is swallowed: no callback, poll keeps running. */
	fake_gap_rssi_rc = 5;
	fake_last_callout->ev.fn(&fake_last_callout->ev);
	okc("failed read skips callback", s_rssi_count == 2);
	fake_gap_rssi_rc = 0;

	/* CoC-disconnect stops the poll. */
	lev.type = BLE_L2CAP_EVENT_COC_DISCONNECTED;
	lev.disconnect.conn_handle = 9;
	lev.disconnect.chan = chan;
	okc("coc disconnect", fake_l2cap_event_cb(&lev, fake_l2cap_event_arg) == 0);
	okc("poll stopped", fake_last_callout->armed == 0);

	/* Reader-initiated disconnect (gate close on a departed peer). */
	fake_gap_terminate_calls = 0;
	fake_gap_terminate_rc = 0;
	okc("disconnect ok", ultrawidelock_ble_disconnect(9) == 0);
	okc("terminated with remote-user reason", fake_gap_terminate_calls == 1 &&
	    fake_gap_terminate_reason == BLE_ERR_REM_USER_CONN_TERM);

	/* Already-gone tolerated; a hard failure surfaces. */
	fake_gap_terminate_rc = BLE_HS_ENOTCONN;
	okc("already-gone tolerated", ultrawidelock_ble_disconnect(9) == 0);
	fake_gap_terminate_rc = 5;
	okc("hard terminate failure surfaces", ultrawidelock_ble_disconnect(9) == -1);
	fake_gap_terminate_rc = 0;
}

int main(void)
{
	fake_nimble_reset();
	fake_nvs_reset();
	s_fake_now = 1750000000;

	t_prepare_and_read_payload();
	t_device_version_write();
	t_standalone_start();
	t_attach_and_advert();
	t_gap_events();
	t_l2cap_coc();
	t_marshaling();
	t_leftover_branches();
	t_rssi_gate_poll();

	printf("\nRESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
	return fails == 0 ? 0 : 1;
}
