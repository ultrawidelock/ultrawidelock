/* SPDX-License-Identifier: ISC */

/*
 * dfu_ble_esp32.c - the DFU GATT service on ESP-IDF's NimBLE host.
 *
 * Lifted from ports/freertos-nrf52833/dfu/dfu_ble_freertos.c, which is the same
 * NimBLE API. Only three things changed: the logger, the way the service gets
 * registered (esp-nimble has no ultrawidelock host-hook list), and the absence
 * of the L2CAP CoC.
 *
 * NO L2CAP CoC HERE, deliberately, and it is not an omission to fix later. The
 * CoC exists on the CDK because a phone app can open one and get far better
 * throughput than GATT. The only client of this port is a web page, and Web
 * Bluetooth cannot open an L2CAP channel at all -- it is GATT or nothing. A
 * second transport nothing can reach would be code that never runs, on a part
 * whose image is already fighting for flash.
 *
 * The wire protocol is byte-identical to the other two ports, which is the
 * whole point: web/flasher/uwldfu.js and scripts/ultrawidelock_push.py drive
 * all three without knowing which one answered.
 */

#include "esp_log.h"

#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "nimble/ble.h"
#include "os/os_mbuf.h"

#include "ultrawidelock_dfu_esp32.h"
#include "ultrawidelock_dfu_rx.h"

static const char *TAG = "ultrawidelock_dfu_ble";

/*
 * One ATT write is one complete protocol frame; there is no reassembly here and
 * none is wanted. 256 is what the other two ports use, and it bounds this
 * buffer against a peer that writes something longer than the protocol can
 * produce. The host sizes its payloads to the negotiated MTU and the receiver's
 * offset echo is the flow control.
 */
#define DFU_MTU 256

/* Same vendor base as the reader's own characteristic, and the same two UUIDs
 * the Zephyr and FreeRTOS images publish. ble_uuid128_init takes them least
 * significant byte first, which is the reverse of how they are written in
 * uwldfu.js. */
static const ble_uuid128_t k_dfu_svc_uuid = BLE_UUID128_INIT(
	0xa3, 0x80, 0xf9, 0xe5, 0x1e, 0x6b, 0xe4, 0x8b,
	0x3a, 0x4b, 0x23, 0x9e, 0x40, 0xa1, 0xb5, 0xd3);
static const ble_uuid128_t k_dfu_chr_uuid = BLE_UUID128_INIT(
	0xa3, 0x80, 0xf9, 0xe5, 0x1e, 0x6b, 0xe4, 0x8b,
	0x3a, 0x4b, 0x23, 0x9e, 0x41, 0xa1, 0xb5, 0xd3);

static uint16_t s_dfu_val_handle;
static struct ble_gap_event_listener s_gap_listener;
static bool s_registered;

static int dfu_gap_event(struct ble_gap_event *event, void *arg)
{
	(void)arg;
	if (event->type == BLE_GAP_EVENT_DISCONNECT) {
		/* Owner-scoped: a disconnect on this endpoint cannot discard a
		 * transfer that some other transport owns. */
		ultrawidelock_dfu_rx_reset(ULTRAWIDELOCK_DFU_OWNER_GATT);
	}
	return 0;
}

static int dfu_gatt_access(uint16_t conn_handle, uint16_t attr_handle,
			   struct ble_gatt_access_ctxt *ctxt, void *arg)
{
	uint8_t frame[DFU_MTU];
	uint8_t rsp[ULTRAWIDELOCK_DFU_RSP_MAX];
	size_t rsp_len = 0;
	uint16_t len = 0;

	(void)attr_handle;
	(void)arg;

	if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
		return BLE_ATT_ERR_UNLIKELY;
	}
	/* The disconnect cleanup is armed HERE, on the first write, and not
	 * where the service definition is handed out. ESP-IDF's NimBLE keeps
	 * the listener list in ble_gap_vars, which ble_gap_init() allocates
	 * (BLE_STATIC_TO_DYNAMIC, default y); CHIP runs that inside
	 * esp_matter::start(), AFTER app_main has collected the service defs.
	 * Registering from service_def() therefore dereferenced NULL and the
	 * lock crashed on boot with the update service enabled. An access
	 * callback runs on the host task of a started host by construction,
	 * and a transfer cannot exist before its first frame. */
	if (!s_registered) {
		(void)ble_gap_event_listener_register(&s_gap_listener, dfu_gap_event, NULL);
		s_registered = true;
	}
	if (ble_hs_mbuf_to_flat(ctxt->om, frame, sizeof(frame), &len) != 0) {
		/* Longer than one frame can be. The protocol never produces one,
		 * so this is a peer sending something else. */
		return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
	}

	(void)ultrawidelock_dfu_rx_frame(ULTRAWIDELOCK_DFU_OWNER_GATT, frame, len, rsp, &rsp_len);

	if (rsp_len > 0u) {
		struct os_mbuf *om = ble_hs_mbuf_from_flat(rsp, (uint16_t)rsp_len);

		if (om == NULL) {
			return BLE_ATT_ERR_INSUFFICIENT_RES;
		}
		/* Takes the buffer either way, including on failure. A peer that
		 * has not subscribed simply gets nothing, which the protocol
		 * treats as a timeout -- the same as the other two ports. */
		(void)ble_gatts_notify_custom(conn_handle, s_dfu_val_handle, om);
	}
	return 0;
}

static const struct ble_gatt_svc_def k_gatt_svcs[] = {
	{
		.type = BLE_GATT_SVC_TYPE_PRIMARY,
		.uuid = &k_dfu_svc_uuid.u,
		.characteristics = (struct ble_gatt_chr_def[]){
			{
				.uuid = &k_dfu_chr_uuid.u,
				.access_cb = dfu_gatt_access,
				.val_handle = &s_dfu_val_handle,
				/* No _ENC or _AUTHEN flag: this board never
				 * pairs, so demanding link-layer security here
				 * would make the channel unreachable rather
				 * than safe. Authenticity is the P-256
				 * signature on the image header, and the
				 * window is what gates availability. */
				.flags = BLE_GATT_CHR_F_WRITE |
					 BLE_GATT_CHR_F_WRITE_NO_RSP |
					 BLE_GATT_CHR_F_NOTIFY,
			},
			{0},
		},
	},
	{0},
};

/*
 * TWO WAYS IN, because there are two kinds of NimBLE host in this tree and only
 * one of them is ours.
 *
 *   ultrawidelock_dfu_esp32_service_def()  -- for a host somebody else owns.
 *   ultrawidelock_dfu_esp32_register_gatt() -- for a host we brought up.
 *
 * The Matter lock needs the first. Its NimBLE host belongs to CHIP, which calls
 * ble_gatts_count_cfg() and ble_gatts_add_svcs() itself over one table and then
 * starts the host; a service added after ble_gatts_start() is queued into a
 * list that has already been walked and freed, so it is silently absent rather
 * than rejected. CHIP's hook for this is BLEMgrImpl().ConfigureExtraServices(),
 * which takes the definition by value and can only be called ONCE -- so every
 * extra service on that board has to arrive in the same vector, before
 * esp_matter::start().
 */

const struct ble_gatt_svc_def *ultrawidelock_dfu_esp32_service_def(void)
{
	/* Nothing touches the host here: it has not been started yet, and on
	 * ESP-IDF its GAP state does not even exist yet (see dfu_gatt_access,
	 * where the disconnect listener is armed instead). */
	/* Element [0] only. CHIP copies one struct and supplies its own
	 * terminator; handing it a table with our {0} inside would put a null
	 * entry in the middle of its list. */
	return &k_gatt_svcs[0];
}

int ultrawidelock_dfu_esp32_register_gatt(void)
{
	int rc;

	rc = ble_gatts_count_cfg(k_gatt_svcs);
	if (rc != 0) {
		ESP_LOGE(TAG, "ble_gatts_count_cfg rc=%d", rc);
		return -1;
	}
	rc = ble_gatts_add_svcs(k_gatt_svcs);
	if (rc != 0) {
		/* BLE_HS_EBUSY (2) here means the host is no longer mutable --
		 * it has connections or is advertising, i.e. this was called too
		 * late. On a CHIP-owned host, use service_def() instead. */
		ESP_LOGE(TAG, "ble_gatts_add_svcs rc=%d (too late? use service_def)", rc);
		return -1;
	}

	if (!s_registered) {
		(void)ble_gap_event_listener_register(&s_gap_listener, dfu_gap_event, NULL);
		s_registered = true;
	}
	ESP_LOGI(TAG, "DFU GATT service registered");
	return 0;
}
