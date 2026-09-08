/* SPDX-License-Identifier: ISC */

// NimBLE-backed BLE transport for the credential reader: GAP advertising, the credential GATT
// service, and an L2CAP connection-oriented channel (CoC) used to carry credential protocol
// messages. Supports two bring-up modes: a standalone NimBLE host (ultrawidelock_ble_start) and
// attachment to a host already owned and synced by another stack such as esp-matter
// (ultrawidelock_ble_prepare + ultrawidelock_ble_start_attached). Tracks CoC channels per
// connection handle in a fixed-size table and exposes send/receive plus reader-status notification
// helpers to the rest of the credential reader.
/*
 * ultrawidelock_ble: NimBLE bring-up, credential GATT service (0xFFF2) with the
 * SPSM/protocol-version READ and the device-version WRITE, advertising, and the
 * L2CAP CoC server on the published SPSM that carries the credential transaction.
 * Inbound SDUs are dispatched to cb.on_data; replies go via ultrawidelock_ble_send().
 * The credential-auth and M1-M4 exchanges ride on exactly those two calls.
 *
 */
#include <string.h>
#include <time.h>

#include <ultrawidelock_log.h>

#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "host/ble_l2cap.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "host/ble_hs_id.h"

#include "ultrawidelock_advtag.h"
#include "ultrawidelock_ble.h"
#include "ultrawidelock_lat.h"

#if defined(ULTRAWIDELOCK_HAVE_MATTER) && ULTRAWIDELOCK_HAVE_MATTER
/*
 * A Matter build advertises two different things from one advertising set, and
 * this file is the only place that can choose between them. An ESP-IDF build
 * does not define ULTRAWIDELOCK_HAVE_MATTER and compiles none of it, byte for
 * byte as before.
 */
#include "matter_ble_freertos.h"
#include "matter_commission.h"
#endif

LOG_MODULE_REGISTER(ultrawidelock_ble, CONFIG_ULTRAWIDELOCK_CRED_LOG_LEVEL);

/* L2CAP SPSM published to peers. Dynamic-PSM range is 0x0080..0x00FF; the value
 * is our choice (the peer learns it from the READ char, it is not well-known). */
#define ULTRAWIDELOCK_L2CAP_SPSM 0x0080u

/* credential service, 16-bit 0xFFF2. */
static const ble_uuid16_t k_svc_uuid = BLE_UUID16_INIT(0xFFF2u);

/* Reader SPSM + BLE-UWB protocol version, D3B5A130-9E23-4B3A-8BE4-6B1EE5F980A3
 * (NimBLE stores 128-bit UUIDs little-endian, so bytes are reversed). */
static const ble_uuid128_t k_chr_reader_spsm_uuid =
	BLE_UUID128_INIT(0xa3, 0x80, 0xf9, 0xe5, 0x1e, 0x6b, 0xe4, 0x8b, 0x3a, 0x4b, 0x23, 0x9e,
			 0x30, 0xa1, 0xb5, 0xd3);

/* User-device selected BLE-UWB protocol version, BD4B9502-3F54-11EC-B919-0242AC120005. */
static const ble_uuid128_t k_chr_device_ver_uuid =
	BLE_UUID128_INIT(0x05, 0x00, 0x12, 0xac, 0x42, 0x02, 0x19, 0xb9, 0xec, 0x11, 0x54, 0x3f,
			 0x02, 0x95, 0x4b, 0xbd);

/* Advertised supported versions (host order) captured from config. */
#define ULTRAWIDELOCK_MAX_VERSIONS 8u
static uint16_t s_versions[ULTRAWIDELOCK_MAX_VERSIONS];
static size_t s_versions_count;
// Module-static table of credential BLE callbacks registered by the application, invoked by the
// GATT/GAP/L2CAP handlers as events occur.
static struct ultrawidelock_ble_callbacks s_cb;

/* Prebuilt READ payload: [SPSM be16][verLen u8][versions be16*N][featLen u8][features u8]. */
static uint8_t s_read_payload[2u + 1u + (2u * ULTRAWIDELOCK_MAX_VERSIONS) + 1u + 1u];
static uint16_t s_read_payload_len;

static uint8_t s_own_addr_type;

/*
 * The advertiser is up and its event queue exists. Guards
 * ultrawidelock_ble_readvertise() and ultrawidelock_ble_time_updated(), both of
 * which are no-ops before there is something to re-emit -- the bring-up path
 * advertises with the current params itself, so a params update that arrives
 * first needs no action.
 *
 * SET BY BOTH BRING-UP PATHS, which is the part that was missing. There are two:
 * start_attached() for a port that shares an already-running host, and
 * ultrawidelock_ble_host_sync() for a port that owns the host and advertises from
 * NimBLE's sync callback. Only the first set this, so on the FreeRTOS port the
 * flag stayed false forever and every refresh silently did nothing.
 *
 * What that cost: Apple sends SetAliroReaderConfig AFTER commissioning
 * completes, so the reader is necessarily advertising something else when the
 * GRK lands -- re-emitting is the whole mechanism by which a commissioned lock
 * becomes approach-resolvable. With the refresh disabled the board kept
 * advertising its commissionable payload, and a phone that had just been given
 * a home key had no reader to approach: no ranging, no Wallet animation, and
 * nothing in any log saying so, because refusing to re-advertise is what the
 * flag is FOR.
 */
static bool s_attached;

/* Provisioned credential advertising params (set via ultrawidelock_ble_set_adv_params). With
 * s_adv_ultrawidelock set, ultrawidelock_advertise emits the full 0xFFF2 service data + a
 * GroupResolvingKey-derived dynamic tag; else the bare service UUID (Phase-2). */
static uint8_t s_adv_group_id[8];
static uint8_t s_adv_sub_id[2];
static uint8_t s_adv_grk[16];
static int8_t s_adv_tx_power;
static bool s_adv_ultrawidelock;

/* Dynamic-tag freshness. The spec (11.3) leaves the window to the reader and
 * says only "re-derive at expiry"; 900 s matches the nRF add-on's default.
 * Re-deriving at half the window keeps the advertised expiry always >= 450 s in
 * the future while the clock is valid, so a phone never scans a boundary tag. */
#define ULTRAWIDELOCK_ADV_TAG_VALID_S	900
#define ULTRAWIDELOCK_ADV_TAG_REFRESH_S (ULTRAWIDELOCK_ADV_TAG_VALID_S / 2)

/* Wall-clock sanity floor (2000-01-01, CHIP's VALID_REAL_TIME_THRESHOLD): an
 * unset ESP32 clock sits at the 1970 epoch; any real source lands far above.
 * Below the floor the advert carries the spec's "expiry unavailable" form. */
#define ULTRAWIDELOCK_ADV_TIME_FLOOR ((time_t)946684800)

static struct ble_npl_callout s_adv_refresh;
static bool s_adv_refresh_init;

static void ultrawidelock_advertise(void);

/* ---- L2CAP CoC (Phase 2.2): the credential transaction channel on the SPSM ---- */

#ifndef CONFIG_BT_NIMBLE_L2CAP_COC_MAX_NUM
#define CONFIG_BT_NIMBLE_L2CAP_COC_MAX_NUM 1
#endif

#define ULTRAWIDELOCK_L2CAP_MTU     512u
#define ULTRAWIDELOCK_COC_BUF_COUNT (6u * CONFIG_BT_NIMBLE_L2CAP_COC_MAX_NUM)

static os_membuf_t s_coc_mem[OS_MEMPOOL_SIZE(ULTRAWIDELOCK_COC_BUF_COUNT, ULTRAWIDELOCK_L2CAP_MTU)];
// Module-static memory pool backing the CoC mbuf pool, initialized by l2cap_init.
static struct os_mempool s_coc_mempool;
// Module-static mbuf pool backing L2CAP CoC send/receive buffers, initialized by l2cap_init.
static struct os_mbuf_pool s_coc_mbuf_pool;

/* Active CoC channels (one per session, up to COC_MAX_NUM). */
static struct {
	bool active;
	uint16_t conn_handle;
	struct ble_l2cap_chan *chan;
} s_coc[CONFIG_BT_NIMBLE_L2CAP_COC_MAX_NUM];

// Record a newly established L2CAP CoC channel against its connection handle in the first free
// tracking slot. Silently does nothing if all CONFIG_BT_NIMBLE_L2CAP_COC_MAX_NUM slots are already
// active.
static void coc_track(uint16_t conn_handle, struct ble_l2cap_chan *chan)
{
	for (size_t i = 0; i < CONFIG_BT_NIMBLE_L2CAP_COC_MAX_NUM; i++) {
		if (!s_coc[i].active) {
			s_coc[i].active = true;
			s_coc[i].conn_handle = conn_handle;
			s_coc[i].chan = chan;
			return;
		}
	}
}

// Remove the tracking entry for a given L2CAP CoC channel, freeing its slot.
// No-op if chan is not found among the active tracked entries.
static void coc_untrack(const struct ble_l2cap_chan *chan)
{
	for (size_t i = 0; i < CONFIG_BT_NIMBLE_L2CAP_COC_MAX_NUM; i++) {
		if (s_coc[i].active && s_coc[i].chan == chan) {
			s_coc[i].active = false;
			return;
		}
	}
}

// Look up the tracked L2CAP CoC channel for a given connection handle.
// Returns the channel pointer if an active tracked entry matches conn_handle, otherwise NULL.
static struct ble_l2cap_chan *coc_chan_for(uint16_t conn_handle)
{
	for (size_t i = 0; i < CONFIG_BT_NIMBLE_L2CAP_COC_MAX_NUM; i++) {
		if (s_coc[i].active && s_coc[i].conn_handle == conn_handle) {
			return s_coc[i].chan;
		}
	}
	return NULL;
}

/* Give the stack a fresh receive buffer so the next SDU can be assembled. */
static int coc_arm_rx(struct ble_l2cap_chan *chan)
{
	struct os_mbuf *rx = os_mbuf_get_pkthdr(&s_coc_mbuf_pool, 0);
	if (rx == NULL) {
		LOG_ERR("coc: out of rx buffers");
		return BLE_HS_ENOMEM;
	}
	return ble_l2cap_recv_ready(chan, rx);
}

/* ---- Connection-RSSI poll (ranging power gate) ---------------------------- *
 * Armed only when the engine registered an on_rssi callback. One callout on the
 * default (host-task) event queue reads the controller RSSI every
 * CONFIG_ULTRAWIDELOCK_RSSI_GATE_POLL_MS while the credential CoC is up and feeds the sample
 * to the engine. The first read fires inline at CoC-open so the gate is primed
 * before the fast auth can complete — otherwise a walk-up that connects at the
 * door would pay up to one poll period before ranging is allowed to start. */
#ifndef CONFIG_ULTRAWIDELOCK_RSSI_GATE_POLL_MS
#define CONFIG_ULTRAWIDELOCK_RSSI_GATE_POLL_MS 250
#endif

static struct ble_npl_callout s_rssi_poll;
static bool s_rssi_poll_init;
static bool s_rssi_poll_on;
static uint16_t s_rssi_conn;

/**
 * Sample the current RSSI on the active BLE connection and invoke the registered callback if one is
 * set. A no-op if no connection is active or the callback is null.
 */
static void rssi_poll_sample(void)
{
	int8_t rssi = 0;

	if (ble_gap_conn_rssi(s_rssi_conn, &rssi) == 0 && s_cb.on_rssi != NULL) {
		s_cb.on_rssi(s_rssi_conn, rssi);
	}
}

/**
 * Poll the current RSSI on the active BLE connection and invoke the registered callback.
 * Reschedules itself if polling is enabled.
 */
static void rssi_poll_ev(struct ble_npl_event *ev)
{
	(void)ev;
	if (!s_rssi_poll_on) {
		return;
	}
	rssi_poll_sample();
	ble_npl_callout_reset(&s_rssi_poll,
			      ble_npl_time_ms_to_ticks32(CONFIG_ULTRAWIDELOCK_RSSI_GATE_POLL_MS));
}

/* Call after on_connected: the first inline sample must find the engine's
 * session already allocated. */
static void rssi_poll_start(uint16_t conn_handle)
{
	if (s_cb.on_rssi == NULL) {
		return;
	}
	if (!s_rssi_poll_init) {
		ble_npl_callout_init(&s_rssi_poll, nimble_port_get_dflt_eventq(), rssi_poll_ev,
				     NULL);
		s_rssi_poll_init = true;
	}
	s_rssi_conn = conn_handle;
	s_rssi_poll_on = true;
	rssi_poll_sample();
	ble_npl_callout_reset(&s_rssi_poll,
			      ble_npl_time_ms_to_ticks32(CONFIG_ULTRAWIDELOCK_RSSI_GATE_POLL_MS));
}

/**
 * Stop polling the RSSI on the active BLE connection.
 * A no-op if polling is not currently running.
 */
static void rssi_poll_stop(void)
{
	if (!s_rssi_poll_on) {
		return;
	}
	s_rssi_poll_on = false;
	if (s_rssi_poll_init) {
		ble_npl_callout_stop(&s_rssi_poll);
	}
}

// NimBLE L2CAP event callback that tracks connection-oriented channel (CoC) lifecycle events
// (connect, disconnect, data) for the credential L2CAP server.
static int l2cap_event_cb(struct ble_l2cap_event *event, void *arg)
{
	(void)arg;
	switch (event->type) {
	case BLE_L2CAP_EVENT_COC_ACCEPT:
		/* Incoming CoC on our SPSM: arm the first receive buffer. */
		return coc_arm_rx(event->accept.chan);

	case BLE_L2CAP_EVENT_COC_CONNECTED:
		if (event->connect.status != 0) {
			LOG_WRN("coc connect failed status=%d", event->connect.status);
			return 0;
		}
		ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_L2CAP_OPEN);
		coc_track(event->connect.conn_handle, event->connect.chan);
		LOG_INF("coc connected (conn %u)", event->connect.conn_handle);
		if (s_cb.on_connected) {
			s_cb.on_connected(event->connect.conn_handle);
		}
		rssi_poll_start(event->connect.conn_handle);
		return 0;

	case BLE_L2CAP_EVENT_COC_DISCONNECTED:
		rssi_poll_stop();
		coc_untrack(event->disconnect.chan);
		LOG_INF("coc disconnected (conn %u)", event->disconnect.conn_handle);
		if (s_cb.on_disconnected) {
			s_cb.on_disconnected(event->disconnect.conn_handle);
		}
		return 0;

	case BLE_L2CAP_EVENT_COC_DATA_RECEIVED: {
		struct os_mbuf *om = event->receive.sdu_rx;
		if (om != NULL) {
			uint8_t buf[ULTRAWIDELOCK_L2CAP_MTU];
			uint16_t len = 0;
			if (ble_hs_mbuf_to_flat(om, buf, sizeof(buf), &len) == 0) {
				LOG_INF("coc rx %u bytes (conn %u)", len,
					 event->receive.conn_handle);
				if (s_cb.on_data) {
					s_cb.on_data(event->receive.conn_handle, buf, len);
				}
			}
			os_mbuf_free_chain(om);
		}
		return coc_arm_rx(event->receive.chan); /* re-arm for the next SDU */
	}

	default:
		return 0;
	}
}

// Initialize the L2CAP connection-oriented channel (CoC) server used for the credential protocol's
// BLE transport. Sets up the CoC mbuf memory pool and registers an L2CAP server on the credential
// SPSM with the given MTU. Logs an error and returns early if the mempool init, mbuf pool init, or
// ble_l2cap_create_server call fails, leaving the CoC server unavailable. Idempotent: the
// standalone path registers the server alongside the GATT service, and start_attached() registers
// it for hosts that skipped that step. Re-running it would re-init a live mempool and fail
// ble_l2cap_create_server with EALREADY.
static bool s_l2cap_ready;

static void l2cap_init(void)
{
	if (s_l2cap_ready) {
		return;
	}

	int rc = os_mempool_init(&s_coc_mempool, ULTRAWIDELOCK_COC_BUF_COUNT,
				 ULTRAWIDELOCK_L2CAP_MTU, s_coc_mem, "ultrawidelock_coc");
	if (rc != 0) {
		LOG_ERR("coc mempool init rc=%d", rc);
		return;
	}
	rc = os_mbuf_pool_init(&s_coc_mbuf_pool, &s_coc_mempool, ULTRAWIDELOCK_L2CAP_MTU,
			       ULTRAWIDELOCK_COC_BUF_COUNT);
	if (rc != 0) {
		LOG_ERR("coc mbuf pool init rc=%d", rc);
		return;
	}
	rc = ble_l2cap_create_server(ULTRAWIDELOCK_L2CAP_SPSM, ULTRAWIDELOCK_L2CAP_MTU,
				     l2cap_event_cb, NULL);
	if (rc != 0) {
		LOG_ERR("l2cap create_server rc=%d", rc);
		return;
	}
	s_l2cap_ready = true;
	LOG_INF("L2CAP CoC server up on SPSM 0x%04x (MTU %u)", (unsigned)ULTRAWIDELOCK_L2CAP_SPSM,
		 (unsigned)ULTRAWIDELOCK_L2CAP_MTU);
}

// Pack an ultrawidelock_ble_features struct into a single bitmask byte for advertising/READ
// payloads. Bit 0 = timesync_procedure_0, bit 1 = timesync_procedure_1, bit 2 = le_coded_phy.
static uint8_t encode_features(const struct ultrawidelock_ble_features *f)
{
	uint8_t b = 0u;
	if (f->timesync_procedure_0) {
		b |= (uint8_t)(1u << 0);
	}
	if (f->timesync_procedure_1) {
		b |= (uint8_t)(1u << 1);
	}
	if (f->le_coded_phy) {
		b |= (uint8_t)(1u << 2);
	}
	return b;
}

// Build the GATT READ payload advertising the L2CAP SPSM, supported protocol versions, and
// supported features, writing it into s_read_payload and recording its length in
// s_read_payload_len.
static void build_read_payload(const struct ultrawidelock_ble_config *cfg)
{
	uint8_t *p = s_read_payload;

	*p++ = (uint8_t)(ULTRAWIDELOCK_L2CAP_SPSM >> 8);
	*p++ = (uint8_t)(ULTRAWIDELOCK_L2CAP_SPSM & 0xffu);

	*p++ = (uint8_t)(s_versions_count * 2u); /* protocol versions length */
	for (size_t i = 0; i < s_versions_count; i++) {
		*p++ = (uint8_t)(s_versions[i] >> 8);
		*p++ = (uint8_t)(s_versions[i] & 0xffu);
	}

	*p++ = 1u; /* features length: SupportedFeatures is one packed byte */
	*p++ = encode_features(&cfg->features);

	s_read_payload_len = (uint16_t)(p - s_read_payload);
}

/* READ: hand back the prebuilt SPSM/versions/features buffer. */
static int reader_spsm_access(uint16_t conn_handle, uint16_t attr_handle,
			      struct ble_gatt_access_ctxt *ctxt, void *arg)
{
	(void)conn_handle;
	(void)attr_handle;
	(void)arg;
	ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_GATT_SPSM_READ);
	int rc = os_mbuf_append(ctxt->om, s_read_payload, s_read_payload_len);
	return (rc == 0) ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}

/* WRITE: [version be16][featLen u8][features]. Validate + log the negotiated version. */
static int device_ver_access(uint16_t conn_handle, uint16_t attr_handle,
			     struct ble_gatt_access_ctxt *ctxt, void *arg)
{
	(void)attr_handle;
	(void)arg;
	uint8_t buf[32];
	uint16_t len = 0;

	ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_GATT_VER_WRITE);
	int rc = ble_hs_mbuf_to_flat(ctxt->om, buf, sizeof(buf), &len);
	if (rc != 0) {
		return BLE_ATT_ERR_UNLIKELY;
	}
	if (len < 3u) {
		return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
	}

	uint16_t version = (uint16_t)(((uint16_t)buf[0] << 8) | buf[1]);
	uint8_t feat_len = buf[2];
	if (len != (uint16_t)(3u + feat_len)) {
		return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
	}

	bool supported = false;
	for (size_t i = 0; i < s_versions_count; i++) {
		if (s_versions[i] == version) {
			supported = true;
			break;
		}
	}
	LOG_INF("conn %u selected BLE-UWB protocol version 0x%04x (%s)", conn_handle, version,
		 supported ? "supported" : "unsupported");
	return 0;
}

static const struct ble_gatt_svc_def k_gatt_svcs[] = {
	{
		.type = BLE_GATT_SVC_TYPE_PRIMARY,
		.uuid = &k_svc_uuid.u,
		.characteristics =
			// Array of GATT characteristic definitions for the credential BLE service,
			// listing each characteristic's UUID, access callback, and flags.
		(struct ble_gatt_chr_def[]){
			{
				.uuid = &k_chr_reader_spsm_uuid.u,
				.access_cb = reader_spsm_access,
				.flags = BLE_GATT_CHR_F_READ,
			},
			{
				.uuid = &k_chr_device_ver_uuid.u,
				.access_cb = device_ver_access,
				.flags = BLE_GATT_CHR_F_WRITE,
			},
			{0},
		},
	},
	{0},
};

/* Fast-interval retry: the request fired at GAP connect loses a "different
 * transaction collision" (HCI 0x2A) against the iPhone's own link setup on
 * every observed walk-up, leaving the whole GATT-discovery window (~900 ms) at
 * the peer's default interval. Re-request from the host task once the peer's
 * procedure has had time to finish; give up after a few tries so we never
 * fight a peer that insists on its own params. */
#define CONN_UPD_ITVL_MAX   12u /* accept only 15 ms (1.25 ms units); iOS idles at ~30 */
#define CONN_UPD_RETRY_MS   500u
#define CONN_UPD_MAX_TRIES  3u

/* One retry context PER CONNECTION. This was a single callout, handle and
 * try-counter shared by every link, and BLE_GAP_EVENT_CONNECT reset the counter
 * to zero. With two peers up (or one Watch reconnecting every 3-4 s beside a
 * phone) each connect re-armed the other link's budget, so the "give up after
 * three" never held and the request kept colliding (status 554 = HCI 0x2A,
 * different transaction collision) until the controller asserted. The retry
 * delay also moves out from 120 ms to 500 ms: 120 ms sat inside the peer's own
 * connect-time parameter update, which is the transaction it collided with. */
struct conn_upd_ctx {
	struct ble_npl_callout retry;
	uint16_t conn_handle;
	uint8_t tries;
	bool in_use;
	bool init;
};
/* Sized from the IDF symbol where sdkconfig.h supplies it; the host fakes and
 * the standalone FreeRTOS port build without one and get the IDF default. */
#if defined(CONFIG_BT_NIMBLE_MAX_CONNECTIONS)
#define CONN_UPD_CTX_MAX CONFIG_BT_NIMBLE_MAX_CONNECTIONS
#else
#define CONN_UPD_CTX_MAX 4
#endif
static struct conn_upd_ctx s_conn_upd[CONN_UPD_CTX_MAX];

/* Find the context owning conn_handle; with alloc, claim a free one for it. */
static struct conn_upd_ctx *conn_upd_ctx_find(uint16_t conn_handle, bool alloc)
{
	struct conn_upd_ctx *free_ctx = NULL;

	for (size_t i = 0; i < sizeof(s_conn_upd) / sizeof(s_conn_upd[0]); i++) {
		if (s_conn_upd[i].in_use && s_conn_upd[i].conn_handle == conn_handle) {
			if (alloc) {
				s_conn_upd[i].tries = 0; /* a new link on a reused handle */
			}
			return &s_conn_upd[i];
		}
		if (!s_conn_upd[i].in_use && free_ctx == NULL) {
			free_ctx = &s_conn_upd[i];
		}
	}
	if (alloc && free_ctx != NULL) {
		free_ctx->in_use = true;
		free_ctx->conn_handle = conn_handle;
		free_ctx->tries = 0;
	}
	return alloc ? free_ctx : NULL;
}

/**
 * Request the BLE connection interval be lowered to 15 ms (the Apple accessory guideline floor) to
 * minimize GATT discovery latency during credential handshake. Best-effort: a rejected request
 * keeps the current connection parameters. Updates to minimum and maximum interval 12 (1.25 ms
 * units = 15 ms), latency 0, and supervision timeout 4 s.
 */
static void request_fast_conn(uint16_t conn_handle)
{
	/* The walk-up is dozens of lock-step round trips (GATT discovery
	 * alone is ~29 events), so the connection interval is nearly linear
	 * latency. Demand exactly Apple's 15 ms floor (units: interval
	 * 1.25 ms, timeout 10 ms): the earlier [15, 30] request was
	 * satisfied by iOS's ~30 ms default, which the bench showed keeps
	 * discovery at ~900 ms. Equal min/max at a 15 ms multiple stays
	 * within the accessory guidelines. Best-effort: a rejected request
	 * keeps the old params. */
	struct ble_gap_upd_params params = {
		.itvl_min = 12, /* 15 ms */
		.itvl_max = 12, /* 15 ms */
		.latency = 0,
		.supervision_timeout = 400, /* 4 s */
	};
	int rc = ble_gap_update_params(conn_handle, &params);

	if (rc != 0) {
		LOG_WRN("conn param update request rc=%d", rc);
	}
}

/**
 * Retry callback for BLE connection interval update: increments retry counter and re-requests a
 * fast interval (15 ms) if the current interval is slower. Exits silently if the connection is gone
 * or already at target speed.
 */
static void conn_upd_retry_ev(struct ble_npl_event *ev)
{
	struct conn_upd_ctx *ctx = ble_npl_event_get_arg(ev);
	struct ble_gap_conn_desc desc;

	if (!ctx->in_use || ble_gap_conn_find(ctx->conn_handle, &desc) != 0 ||
	    desc.conn_itvl <= CONN_UPD_ITVL_MAX) {
		return; /* connection gone, or already fast enough */
	}
	ctx->tries++;
	request_fast_conn(ctx->conn_handle);
}

/* Arm one retry unless the interval is already acceptable or the budget is
 * spent. Called from GAP events only (host task). W-level logs on every exit
 * so one bench line always states the interval the transaction will run at. */
static void conn_upd_schedule_retry(uint16_t conn_handle)
{
	struct conn_upd_ctx *ctx = conn_upd_ctx_find(conn_handle, false);
	struct ble_gap_conn_desc desc;

	if (ctx == NULL || ble_gap_conn_find(conn_handle, &desc) != 0) {
		return;
	}
	if (desc.conn_itvl <= CONN_UPD_ITVL_MAX) {
		LOG_WRN("[conn %u] conn itvl %u us; fast enough, no retry", conn_handle,
			 (unsigned)desc.conn_itvl * 1250u);
		return;
	}
	if (ctx->tries >= CONN_UPD_MAX_TRIES) {
		LOG_WRN("[conn %u] conn itvl stuck at %u us after %u tries", conn_handle,
			 (unsigned)desc.conn_itvl * 1250u, (unsigned)ctx->tries);
		return;
	}
	if (!ctx->init) {
		ble_npl_callout_init(&ctx->retry, nimble_port_get_dflt_eventq(),
				     conn_upd_retry_ev, ctx);
		ctx->init = true;
	}
	ble_npl_callout_reset(&ctx->retry, ble_npl_time_ms_to_ticks32(CONN_UPD_RETRY_MS));
}

/* Release a link's retry context: stop its callout and free the slot. */
static void conn_upd_ctx_release(uint16_t conn_handle)
{
	struct conn_upd_ctx *ctx = conn_upd_ctx_find(conn_handle, false);

	if (ctx == NULL) {
		return;
	}
	if (ctx->init) {
		ble_npl_callout_stop(&ctx->retry);
	}
	ctx->in_use = false;
}

// NimBLE GAP event callback that handles connection, disconnection, and advertising-related events
// for the credential BLE service.
static int gap_event(struct ble_gap_event *event, void *arg)
{
	(void)arg;
	switch (event->type) {
	case BLE_GAP_EVENT_CONNECT:
		LOG_INF("GAP connect (conn %u) status=%d", event->connect.conn_handle,
			 event->connect.status);
		if (event->connect.status != 0) {
			ultrawidelock_advertise(); /* failed; keep advertising */
			return 0;
		}
		ultrawidelock_lat_begin(); /* walk-up t=0 */
		(void)conn_upd_ctx_find(event->connect.conn_handle, true);
		request_fast_conn(event->connect.conn_handle);
		return 0;
	case BLE_GAP_EVENT_CONN_UPDATE: {
		/* W so it lands in the default WARN console: this one line per connect
		 * is the only evidence of whether iOS honored the 15 ms interval
		 * request above (the interval bounds the lock-step transaction). */
		struct ble_gap_conn_desc desc;

		if (event->conn_update.status == 0 &&
		    ble_gap_conn_find(event->conn_update.conn_handle, &desc) == 0) {
			LOG_WRN("conn update: itvl=%u us latency=%u timeout=%u ms",
				 (unsigned)desc.conn_itvl * 1250u, desc.conn_latency,
				 (unsigned)desc.supervision_timeout * 10u);
		} else {
			LOG_WRN("conn update failed: status=%d",
				 event->conn_update.status);
		}
		/* Covers both outcomes that leave us slow: our request rejected
		 * (collision), or the peer's own update completing at its default. */
		conn_upd_schedule_retry(event->conn_update.conn_handle);
		return 0;
	}
	case BLE_GAP_EVENT_DISCONNECT:
		LOG_INF("GAP disconnect (conn %u) reason=%d", event->disconnect.conn.conn_handle,
			 event->disconnect.reason);
		conn_upd_ctx_release(event->disconnect.conn.conn_handle);
		rssi_poll_stop(); /* a GAP-level drop can race the CoC teardown */
		ultrawidelock_advertise();
		return 0;
	case BLE_GAP_EVENT_ADV_COMPLETE:
		ultrawidelock_advertise();
		return 0;
	default:
		return 0;
	}
}

/* Re-derive + re-emit the advertisement on the host task. Runs only while the
 * advertiser is actually up: if a connection paused advertising, the next
 * ultrawidelock_advertise() (GAP disconnect / adv-complete) re-derives anyway. */
static void adv_refresh_ev(struct ble_npl_event *ev)
{
	(void)ev;
	if (!s_adv_ultrawidelock || !ble_gap_adv_active()) {
		return;
	}
	(void)ble_gap_adv_stop();
	ultrawidelock_advertise();
}

/* Arm (or re-arm) the periodic dynamic-tag refresh. Host task only. The chain
 * self-sustains: every ultrawidelock_advertise() with a valid clock lands back here. */
static void adv_tag_schedule_refresh(void)
{
	if (!s_adv_refresh_init) {
		ble_npl_callout_init(&s_adv_refresh, nimble_port_get_dflt_eventq(), adv_refresh_ev,
				     NULL);
		s_adv_refresh_init = true;
	}
	ble_npl_callout_reset(&s_adv_refresh,
			      ble_npl_time_ms_to_ticks32(ULTRAWIDELOCK_ADV_TAG_REFRESH_S * 1000));
}

/* Assemble the 0xFFF2 service data (26 B = 2-byte UUID + 24-byte payload) with the
 * GroupResolvingKey dynamic tag. Payload layout (bytes 0..23):
 *   [0]      flags: bit7 = BLE+UWB supported, bits2:0 = version (0)
 *   [1]      tx power (int8)
 *   [2..9]   truncated reader group id (8)     = reader_id[0..7]
 *   [10..11] truncated reader group sub id (2) = reader_id[16..17]
 *   [12..15] dynamic-tag expiry, big-endian (0xFFFFFFFF = no clock)
 *   [16]     reserved (0)
 *   [17..23] dynamic tag (ultrawidelock_advtag.c)
 * Layout follows credential 1.0 section 11.3 (Table 11-2); NimBLE hands out AdvA
 * LSB-first, the derivation wants it MSB-first.
 * With a valid wall clock the expiry is live (now + window) and the periodic
 * re-derivation is armed; phones silently ignore an expiry in their past, so a
 * clock that cannot be trusted must advertise the "unavailable" form instead. */
static bool build_ultrawidelock_svc_data(uint8_t out[26])
{
	uint8_t id_addr_type =
		(s_own_addr_type == BLE_OWN_ADDR_PUBLIC) ? BLE_ADDR_PUBLIC : BLE_ADDR_RANDOM;
	uint8_t adva[6];

	if (ble_hs_id_copy_addr(id_addr_type, adva, NULL) != 0) {
		LOG_WRN("adv: no identity address for the dynamic tag");
		return false;
	}

	uint8_t adva_msb[6];

	for (int i = 0; i < 6; i++) {
		adva_msb[i] = adva[5 - i];
	}

	uint32_t expiry = ULTRAWIDELOCK_ADVTAG_EXPIRY_UNAVAILABLE;
	time_t now = time(NULL);
	bool have_clock = (now >= ULTRAWIDELOCK_ADV_TIME_FLOOR);

	if (have_clock) {
		expiry = (uint32_t)now + ULTRAWIDELOCK_ADV_TAG_VALID_S;
	}

	uint8_t dyn_tag[ULTRAWIDELOCK_ADVTAG_LEN];
	int rc = ultrawidelock_advtag_derive(s_adv_grk, adva_msb, expiry, dyn_tag);

	if (rc != 0) {
		LOG_ERR("adv: dynamic-tag derive rc=%d", rc);
		return false;
	}

	uint8_t *p = out;

	*p++ = 0xF2u; /* 0xFFF2 service UUID, little-endian */
	*p++ = 0xFFu;
	*p++ = 0x80u; /* flags: BLE+UWB supported, version 0, notif 0 */
	*p++ = (uint8_t)s_adv_tx_power;
	memcpy(p, s_adv_group_id, sizeof(s_adv_group_id));
	p += sizeof(s_adv_group_id);
	memcpy(p, s_adv_sub_id, sizeof(s_adv_sub_id));
	p += sizeof(s_adv_sub_id);
	*p++ = (uint8_t)(expiry >> 24); /* expiry BE32 */
	*p++ = (uint8_t)(expiry >> 16);
	*p++ = (uint8_t)(expiry >> 8);
	*p++ = (uint8_t)expiry;
	*p++ = 0x00u; /* reserved */
	memcpy(p, dyn_tag, ULTRAWIDELOCK_ADVTAG_LEN);

	if (have_clock) {
		adv_tag_schedule_refresh();
	}
	return true;
}

// Configure and start BLE advertising for credential discovery.
// Advertises full credential service data (0xFFF2, 26 bytes) built by build_ultrawidelock_svc_data
// when adv is enabled and a GRK is configured; otherwise falls back to a bare service UUID plus
// device name for the unprovisioned/no-GRK case. Logs and returns without starting advertising if
// either ble_gap_adv_set_fields or ble_gap_adv_start fails.
static void ultrawidelock_advertise(void)
{
	// Local advertising fields structure populated by ultrawidelock_advertise and passed to
	// ble_gap_adv_set_fields; zero-initialized before being filled with either full credential
	// service data or the fallback UUID/name fields.
	struct ble_hs_adv_fields fields = {0};
	uint8_t svc_data[26];

	fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;

#if defined(ULTRAWIDELOCK_HAVE_MATTER) && ULTRAWIDELOCK_HAVE_MATTER
	/*
	 * A node that holds no fabric has to be findable by a commissioner, and a
	 * provisioned reader would otherwise never be: build_ultrawidelock_svc_data()
	 * succeeds as soon as there is a GRK, so without this test the credential tag
	 * wins forever and the board is invisible in the Home app while looking
	 * perfectly healthy on the bench.
	 *
	 * An OPEN COMMISSIONING WINDOW counts as not-commissioned even though the
	 * node does hold a fabric. The Zephyr port records learning that on
	 * hardware on 2026-08-03: without it, OpenCommissioningWindow kept
	 * advertising the reader tag, so the second ecosystem the window was
	 * opened for could never find the node it had just been invited to.
	 */
	const bool commissioned =
		matter_commission_has_fabric() && !matter_commission_window_open();
#else
	const bool commissioned = true;
#endif

	if (commissioned && s_adv_ultrawidelock && build_ultrawidelock_svc_data(svc_data)) {
		/* Full credential service data — what the iPhone resolves to approach-connect. */
		fields.svc_data_uuid16 = svc_data;
		fields.svc_data_uuid16_len = sizeof(svc_data);
	} else {
		/* Fallback (unprovisioned / no GRK): bare service UUID + name (Phase-2). */
		const char *name = ble_svc_gap_device_name();

		fields.uuids16 = (ble_uuid16_t[]){BLE_UUID16_INIT(0xFFF2u)};
		fields.num_uuids16 = 1;
		fields.uuids16_is_complete = 1;
		fields.name = (uint8_t *)name;
		fields.name_len = (uint8_t)strlen(name);
		fields.name_is_complete = 1;

#if defined(ULTRAWIDELOCK_HAVE_MATTER) && ULTRAWIDELOCK_HAVE_MATTER
		/*
		 * The commissionable payload, in the same packet as the bare
		 * credential UUID. A legacy advertisement carries 31 bytes and this
		 * spends flags 3 + UUID 4 + Matter service data 12 = 19, so the
		 * scanner affordance above is kept rather than traded away --
		 * but the NAME has to go, because it would not fit and NimBLE
		 * would fail the whole set rather than drop one element.
		 *
		 * One set, not two: CONFIG_BT_EXT_ADV is what a second would
		 * cost, and this part has no flash to spend on it.
		 */
		static uint8_t matter_svc_data[MATTER_BLE_SVC_DATA_LEN];

		if (matter_ble_commissionable_svc_data(matter_svc_data,
						       sizeof(matter_svc_data)) == 0) {
			fields.name = NULL;
			fields.name_len = 0;
			fields.name_is_complete = 0;
			fields.svc_data_uuid16 = matter_svc_data;
			fields.svc_data_uuid16_len = sizeof(matter_svc_data);
		}
#endif
	}

	int rc = ble_gap_adv_set_fields(&fields);
	if (rc != 0) {
		LOG_ERR("adv_set_fields rc=%d", rc);
		return;
	}

	// Local GAP advertising parameters used to configure and start credential BLE advertising.
	// Zero-initialized then set to undirected connectable, general discoverable mode before
	// being passed to ble_gap_adv_start.
	struct ble_gap_adv_params adv_params = {0};
	adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
	adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;

	rc = ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER, &adv_params, gap_event, NULL);
	if (rc != 0) {
		LOG_ERR("adv_start rc=%d", rc);
		return;
	}
	/* Which of the two the board is offering is the first thing to check on a
	 * bench, and it is not otherwise visible without a sniffer. */
	LOG_INF("advertising: %s", fields.svc_data_uuid16_len == sizeof(svc_data)
					   ? "credential reader 0xFFF2"
					   : "unprovisioned or uncommissioned");
}

// NimBLE host sync callback: ensures a device address exists, infers the own address type,
// and starts credential advertising. Logs and returns early without advertising if either step
// fails.
//
// Ports that own the host install this as ble_hs_cfg.sync_cb, or call it from their own
// sync handler. It is exported rather than static because the bring-up sequence that
// installs it is per-OS: see ultrawidelock_ble_register_gatt().
void ultrawidelock_ble_host_sync(void)
{
	int rc = ble_hs_util_ensure_addr(0);
	if (rc != 0) {
		LOG_ERR("ensure_addr rc=%d", rc);
		return;
	}
	rc = ble_hs_id_infer_auto(0, &s_own_addr_type);
	if (rc != 0) {
		LOG_ERR("infer_auto rc=%d", rc);
		return;
	}
	LOG_INF("NimBLE synced; advertising as credential reader (SPSM 0x%04x)",
		 (unsigned)ULTRAWIDELOCK_L2CAP_SPSM);
	/* Before advertising, not after: this is what lets a later
	 * SetAliroReaderConfig re-emit the payload. See s_attached. */
	s_attached = true;
	ultrawidelock_advertise();
}

// NimBLE host reset callback; logs the reset reason.
void ultrawidelock_ble_host_reset(int reason)
{
	LOG_WRN("NimBLE reset; reason=%d", reason);
}

/* Capture the config into the module statics (versions, callbacks, READ payload).
 * Shared by the port's bring-up (owns the host) and ultrawidelock_ble_prepare (attach mode). */
static int capture_cfg(const struct ultrawidelock_ble_config *cfg)
{
	if (cfg == NULL || cfg->proto_versions == NULL || cfg->proto_versions_count == 0 ||
	    cfg->proto_versions_count > ULTRAWIDELOCK_MAX_VERSIONS) {
		return -1;
	}

	s_versions_count = cfg->proto_versions_count;
	for (size_t i = 0; i < s_versions_count; i++) {
		s_versions[i] = cfg->proto_versions[i];
	}
	s_cb = cfg->cb;
	build_read_payload(cfg);
	return 0;
}

// Register everything the credential reader needs on a NimBLE host the caller has already
// initialised: the GAP and GATT service stubs, the credential 0xFFF2 service, the device name,
// and the L2CAP CoC server on the published SPSM.
//
// This is the OS-free half of bring-up. The half that is not here -- initialising NVS or
// the port's key-value store, calling nimble_port_init(), and starting the host task --
// differs per platform and lives in each port's own bring-up file. Call this after
// nimble_port_init() and before the host task starts processing events.
//
// The config must already have been captured by ultrawidelock_ble_prepare(); this touches only
// NimBLE. Returns -1 if any registration step fails, 0 on success.
int ultrawidelock_ble_register_gatt(void)
{
	ble_svc_gap_init();
	ble_svc_gatt_init();

	int rc = ble_gatts_count_cfg(k_gatt_svcs);
	if (rc != 0) {
		LOG_ERR("gatts_count_cfg rc=%d", rc);
		return -1;
	}
	rc = ble_gatts_add_svcs(k_gatt_svcs);
	if (rc != 0) {
		LOG_ERR("gatts_add_svcs rc=%d", rc);
		return -1;
	}

	rc = ble_svc_gap_device_name_set("credential Reader");
	if (rc != 0) {
		LOG_WRN("device_name_set rc=%d", rc);
	}

	l2cap_init(); /* register the credential L2CAP CoC server on the SPSM */
	return 0;
}

/* ---- attach mode: share a host another stack (e.g. Matter) already owns ---- */

// Capture the credential BLE configuration for later use by the service.
// Returns whatever capture_cfg returns; does not itself start advertising or the GATT service.
int ultrawidelock_ble_prepare(const struct ultrawidelock_ble_config *cfg)
{
	return capture_cfg(cfg);
}

// Return the credential GATT service definition table for registration with the NimBLE host.
const struct ble_gatt_svc_def *ultrawidelock_ble_service_def(void)
{
	return &k_gatt_svcs[0];
}

// Bring up the credential BLE service on a host already initialized and synced by the owning stack
// (e.g. esp-matter), instead of starting a private NimBLE host.
// Only starts the L2CAP CoC server and advertising; the GATT service must already be
// registered through the owning stack's extra-services hook. The owner must have stopped its
// own advertiser first. Returns -1 if address inference fails, otherwise 0.
int ultrawidelock_ble_start_attached(void)
{
	/* The host is already initialised + synced by the owning stack, and our GATT
	 * service was registered through that stack's extra-services hook. Only the
	 * L2CAP CoC server + advertising remain. The owner must have released the
	 * legacy advertiser first (esp-matter stops advertising post-commissioning). */
	l2cap_init();

	int rc = ble_hs_id_infer_auto(0, &s_own_addr_type);
	if (rc != 0) {
		LOG_ERR("attached: infer_auto rc=%d", rc);
		return -1;
	}
	LOG_INF("credential reader attached to shared host; advertising (SPSM 0x%04x)",
		 (unsigned)ULTRAWIDELOCK_L2CAP_SPSM);
	s_attached = true;
	ultrawidelock_advertise();
	return 0;
}

// Re-emit the BLE advertisement with the current advertising parameters.
// Used when provisioning (the GRK) lands after the advertiser is already up: Apple sends
// SetAliroReaderConfig post-commissioning, so the reader initially advertised only the bare
// UUID. Stops any running advertisement and restarts it so the new full 0xFFF2 service data
// takes effect. No-op if the transport has not been attached yet (start_attached() will
// advertise with the current params once it runs).
void ultrawidelock_ble_readvertise(void)
{
	/* Re-emit the advertisement with the current params. Used when provisioning
	 * (the GRK) lands after the advertiser is already up: Apple sends
	 * SetAliroReaderConfig post-commissioning, so the reader initially advertised
	 * the bare UUID. Stop + restart so the new full 0xFFF2 service data takes. */
	if (!s_attached) {
		return; /* not up yet; start_attached() advertises with current params */
	}
	(void)ble_gap_adv_stop(); /* ignore rc; may already be stopped */
	ultrawidelock_advertise();
}

// Set the credential advertising identity (group ID, sub ID, GRK) and TX power, and enable full
// credential service-data advertising. Copies group_id8, sub_id2, and grk into module statics;
// after this call, ultrawidelock_advertise will build and advertise full credential service data
// instead of the fallback bare-UUID form.
void ultrawidelock_ble_set_adv_params(const uint8_t group_id8[8], const uint8_t sub_id2[2],
			      const uint8_t grk[16], int8_t tx_power)
{
	memcpy(s_adv_group_id, group_id8, sizeof(s_adv_group_id));
	memcpy(s_adv_sub_id, sub_id2, sizeof(s_adv_sub_id));
	memcpy(s_adv_grk, grk, sizeof(s_adv_grk));
	s_adv_tx_power = tx_power;
	s_adv_ultrawidelock = true;
}

// Return the L2CAP SPSM (simplified protocol/service multiplexer) value used for the credential CoC
// channel.
uint16_t ultrawidelock_ble_spsm(void)
{
	return ULTRAWIDELOCK_L2CAP_SPSM;
}

// Send data to a connected peer over its credential L2CAP CoC channel.
// Returns 0 on success (queued or sent), -1 if data is NULL, len is 0, no CoC channel exists
// for conn_handle, mbuf allocation/append fails, or ble_l2cap_send fails for any reason other
// than BLE_HS_ESTALLED (which means the SDU was queued and will flush on TX_UNSTALLED).
// On success the stack takes ownership of the sdu buffer; on failure it is freed here.
int ultrawidelock_ble_send(uint16_t conn_handle, const uint8_t *data, size_t len)
{
	if (data == NULL || len == 0) {
		return -1;
	}
	struct ble_l2cap_chan *chan = coc_chan_for(conn_handle);
	if (chan == NULL) {
		LOG_WRN("ultrawidelock_ble_send: no CoC channel for conn %u", conn_handle);
		return -1;
	}

	// Local mbuf handle allocated from the CoC mbuf pool to hold an outgoing L2CAP SDU.
	struct os_mbuf *sdu = os_mbuf_get_pkthdr(&s_coc_mbuf_pool, 0);
	if (sdu == NULL) {
		return -1;
	}
	int rc = os_mbuf_append(sdu, data, len);
	if (rc != 0) {
		os_mbuf_free_chain(sdu);
		return -1;
	}

	rc = ble_l2cap_send(chan, sdu);
	if (rc == 0 || rc == BLE_HS_ESTALLED) {
		/* Stack owns the sdu now; ESTALLED = queued, flushed on TX_UNSTALLED. */
		return 0;
	}
	os_mbuf_free_chain(sdu);
	LOG_WRN("ble_l2cap_send rc=%d", rc);
	return -1;
}

// Reader-initiated link drop (RSSI power gate close on a departed peer). Remote-user-terminated
// reason so the phone treats it as a clean end; already-gone connections count as success.
int ultrawidelock_ble_disconnect(uint16_t conn_handle)
{
	int rc = ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);

	if (rc != 0 && rc != BLE_HS_ENOTCONN) {
		LOG_WRN("gap terminate (conn %u) rc=%d", conn_handle, rc);
		return -1;
	}
	return 0;
}

/* ---- Cross-task reader->phone status send (host-task marshaling) ----------- */

static struct ble_npl_event s_reader_status_ev;
static void (*s_reader_status_cb)(bool);
static bool s_reader_status_unsecured;

// NimBLE portable event-queue event type used to defer reader-status callback execution onto the
// host task.
static void reader_status_ev_cb(struct ble_npl_event *ev)
{
	(void)ev;
	if (s_reader_status_cb != NULL) {
		s_reader_status_cb(s_reader_status_unsecured);
	}
}

// Queue a reader-status callback to run on the NimBLE host task.
// Stores cb and unsecured in module statics and posts an event to the default NimBLE event queue;
// the callback fires later from reader_status_ev_cb, not synchronously. Runs on the host task so it
// serializes with every other sc_ble seal operation and keeps the BleSK counter monotonic; callers
// must not rely on immediate execution and must not post a second call before the first has been
// drained if ordering matters.
void ultrawidelock_ble_post_reader_status(void (*cb)(bool unsecured), bool unsecured)
{
	/* Seal + send must run on the host task so they serialize with every other sc_ble
	 * seal (AP-Completed, M1-M4, notifications) and keep the BleSK counter monotonic.
	 * A grant and its relock are >200 ms apart and the host drains the queue within a
	 * few ms, so the single-slot event is race-free in practice. */
	s_reader_status_cb = cb;
	s_reader_status_unsecured = unsecured;
	ble_npl_event_init(&s_reader_status_ev, reader_status_ev_cb, NULL);
	ble_npl_eventq_put(nimble_port_get_dflt_eventq(), &s_reader_status_ev);
}

static struct ble_npl_event s_reader_tick_ev;
static void (*s_reader_tick_cb)(void);

static void reader_tick_ev_cb(struct ble_npl_event *ev)
{
	(void)ev;
	if (s_reader_tick_cb != NULL) {
		s_reader_tick_cb();
	}
}

void ultrawidelock_ble_post_reader_tick(void (*cb)(void))
{
	static bool init;

	if (!init) {
		s_reader_tick_cb = cb;
		ble_npl_event_init(&s_reader_tick_ev, reader_tick_ev_cb, NULL);
		init = true;
	} else if (cb != s_reader_tick_cb) {
		LOG_ERR("reader tick callback changed after initialization");
		return;
	}
	/* Re-posting a queued static event coalesces; reader.c atomically retains
	 * the newest monotonic timestamp. */
	ble_npl_eventq_put(nimble_port_get_dflt_eventq(), &s_reader_tick_ev);
}

static struct ble_npl_event s_presence_reset_ev;
static void (*s_presence_reset_cb)(void);

/**
 * Invoke the presence reset callback posted by ultrawidelock_ble_post_presence_reset, if one was
 * registered.
 */
static void presence_reset_ev_cb(struct ble_npl_event *ev)
{
	(void)ev;
	if (s_presence_reset_cb != NULL) {
		s_presence_reset_cb();
	}
}

/**
 * Post an event callback to be invoked asynchronously on the default NimBLE event queue when
 * presence is reset.
 */
void ultrawidelock_ble_post_presence_reset(void (*cb)(void))
{
	static bool init;

	s_presence_reset_cb = cb;
	/* Initialised once, for the reason spelled out at ultrawidelock_ble_post_revoke_sweep. */
	if (!init) {
		ble_npl_event_init(&s_presence_reset_ev, presence_reset_ev_cb, NULL);
		init = true;
	}
	ble_npl_eventq_put(nimble_port_get_dflt_eventq(), &s_presence_reset_ev);
}

static struct ble_npl_event s_revoke_sweep_ev;
static void (*s_revoke_sweep_cb)(void);

/**
 * Invoke the post-revocation link sweep posted by ultrawidelock_ble_post_revoke_sweep, if one was
 * registered.
 */
static void revoke_sweep_ev_cb(struct ble_npl_event *ev)
{
	(void)ev;
	if (s_revoke_sweep_cb != NULL) {
		s_revoke_sweep_cb();
	}
}

/**
 * Post an event callback to be invoked asynchronously on the default NimBLE event queue once a
 * credential has been revoked, so the links it may still be ranging on can be dropped.
 */
void ultrawidelock_ble_post_revoke_sweep(void (*cb)(void))
{
	static bool init;

	s_revoke_sweep_cb = cb;
	/*
	 * Initialised ONCE. There is one shared event here, and the port refuses to
	 * queue an event that is already queued -- which is exactly the coalescing a
	 * sweep wants, since one pass drops every link however many credentials went.
	 * Re-initialising clears the flag that refusal is based on, so a second
	 * revocation arriving before the host task ran would link the same static
	 * event into the queue twice.
	 */
	if (!init) {
		ble_npl_event_init(&s_revoke_sweep_ev, revoke_sweep_ev_cb, NULL);
		init = true;
	}
	ble_npl_eventq_put(nimble_port_get_dflt_eventq(), &s_revoke_sweep_ev);
}

/* ---- Wall-clock step notification (SNTP / future Matter time sync) --------- */

static struct ble_npl_event s_time_updated_ev;

// Notify the transport that the wall clock just stepped (e.g. SNTP first sync), so the
// dynamic advertisement tag is re-derived immediately instead of waiting out the refresh
// period. Safe from any task (marshaled onto the host task via the default event queue).
// No-op before ultrawidelock_ble_start_attached(): the attach path derives with the then-current
// clock, and the queue may not exist yet while the owning stack is still booting.
void ultrawidelock_ble_time_updated(void)
{
	static bool init;

	if (!s_attached) {
		return;
	}
	if (!init) {
		ble_npl_event_init(&s_time_updated_ev, adv_refresh_ev, NULL);
		init = true;
	}
	ble_npl_eventq_put(nimble_port_get_dflt_eventq(), &s_time_updated_ev);
}
