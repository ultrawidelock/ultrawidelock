/*
 * Host test for the ESP32 DFU GATT service (dfu_ble_esp32.c) against the
 * sdkfake/ NimBLE doubles. Theatre suite: proves the service definition and
 * the access/disconnect wiring, not that a browser can push an image.
 *
 * The one thing it guards that a target build cannot: WHEN the GAP listener
 * is registered. ESP-IDF's NimBLE keeps the listener list in ble_gap_vars,
 * heap-allocated by ble_gap_init() (BLE_STATIC_TO_DYNAMIC, default y). The
 * Matter lock hands the service def to CHIP before esp_matter::start(), so a
 * listener registered from service_def() dereferences NULL and the board
 * never reaches app_main's next line. fake_gap_listener_early counts that.
 *
 * Sections:
 *   A  service_def before the host exists: no listener yet, def handed out
 *   B  first GATT write after the host is up: frame forwarded, listener armed
 *   C  GAP disconnect through the listener: owner-scoped receiver reset
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "host/ble_hs.h"
#include "nimble/nimble_port.h"

#include "ultrawidelock_dfu_esp32.h"
#include "ultrawidelock_dfu_rx.h"

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

/* ---- receiver doubles: record the owner and echo a fixed response ---- */
static int s_rx_frames;
static enum ultrawidelock_dfu_owner s_rx_owner;
static uint8_t s_rx_first_byte;
static int s_rx_resets;
static enum ultrawidelock_dfu_owner s_rx_reset_owner;

int ultrawidelock_dfu_rx_frame(enum ultrawidelock_dfu_owner owner, const uint8_t *frame, size_t len,
			       uint8_t *rsp, size_t *rsp_len)
{
	s_rx_frames++;
	s_rx_owner = owner;
	s_rx_first_byte = len > 0 ? frame[0] : 0xFF;
	rsp[0] = 0xA5;
	rsp[1] = 0x5A;
	*rsp_len = 2;
	return 0;
}

void ultrawidelock_dfu_rx_reset(enum ultrawidelock_dfu_owner owner)
{
	s_rx_resets++;
	s_rx_reset_owner = owner;
}

int main(void)
{
	fake_nimble_reset();

	printf("-- A: service_def before the host is up\n");
	const struct ble_gatt_svc_def *def = ultrawidelock_dfu_esp32_service_def();

	okc("A.def handed out", def != NULL);
	okc("A.def is the primary DFU service",
	    def != NULL && def->type == BLE_GATT_SVC_TYPE_PRIMARY &&
		    def->characteristics != NULL && def->characteristics[0].access_cb != NULL);
	okc("A.no listener before ble_gap_init (target: NULL ble_gap_vars)",
	    fake_gap_listener_early == 0);

	printf("-- B: first write once CHIP has started the host\n");
	(void)nimble_port_init();
	struct os_mbuf *om = os_mbuf_get_pkthdr(NULL, 0);
	static const uint8_t frame[] = {0x01, 0x02, 0x03};

	(void)os_mbuf_append(om, frame, sizeof(frame));
	struct ble_gatt_access_ctxt ctxt = {.op = BLE_GATT_ACCESS_OP_WRITE_CHR, .om = om};
	int rc = def->characteristics[0].access_cb(7, 0, &ctxt, NULL);

	okc("B.write accepted", rc == 0);
	okc("B.frame reached the receiver as the GATT owner",
	    s_rx_frames == 1 && s_rx_owner == ULTRAWIDELOCK_DFU_OWNER_GATT && s_rx_first_byte == 0x01);
	okc("B.response notified on the value handle",
	    fake_gatts_notify_calls == 1 && fake_gatts_notify_len == 2 &&
		    fake_gatts_notify_data[0] == 0xA5 &&
		    fake_gatts_notify_handle == *def->characteristics[0].val_handle);
	okc("B.listener armed now, on the host task", fake_gap_listener != NULL &&
							     fake_gap_listener->fn != NULL &&
							     fake_gap_listener_early == 0);

	ctxt.op = 0; /* a READ: this characteristic is write-only */
	okc("B.non-write refused", def->characteristics[0].access_cb(7, 0, &ctxt, NULL) ==
					   BLE_ATT_ERR_UNLIKELY);

	printf("-- C: disconnect resets only the GATT-owned transfer\n");
	struct ble_gap_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = BLE_GAP_EVENT_DISCONNECT;
	ev.disconnect.conn.conn_handle = 7;
	if (fake_gap_listener != NULL) {
		(void)fake_gap_listener->fn(&ev, fake_gap_listener->arg);
	}
	okc("C.receiver reset for the GATT owner",
	    s_rx_resets == 1 && s_rx_reset_owner == ULTRAWIDELOCK_DFU_OWNER_GATT);
	ev.type = BLE_GAP_EVENT_CONNECT;
	if (fake_gap_listener != NULL) {
		(void)fake_gap_listener->fn(&ev, fake_gap_listener->arg);
	}
	okc("C.other GAP events leave the transfer alone", s_rx_resets == 1);

	printf("RESULT %s (%d failures)\n", fails ? "FAIL" : "PASS", fails);
	return fails ? 1 : 0;
}
