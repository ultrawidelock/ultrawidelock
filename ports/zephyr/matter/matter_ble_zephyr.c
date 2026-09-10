/* SPDX-License-Identifier: ISC */

/**
 * @file matter_ble_zephyr.c — the 0xFFF6 GATT service that carries BTP.
 *
 * A thin adapter, on purpose. All the framing lives in modules/ultrawidelock_matter
 * (matter_btp.c), which has no Zephyr dependency and is tested on the host
 * under sanitizers. This file does three things and no more: hand C1 writes to
 * the reassembler, drive the fragmenter out through C2 indications, and build
 * the commissionable advertisement.
 *
 * Modelled on ultrawidelock_ble_zephyr.c -- same shape, proven against live iPhones.
 * C1 (RX, write) is 18EE2EF5-263D-4559-959F-4F9C429F9D11, C2 (TX, indicate)
 * ...D12, spelled below in the little-endian order BT_UUID_INIT_128 wants.
 *
 * NOT wired into the reader's advertising: the reader owns one advertising set
 * (credential 0xFFF2), and matter_ble_advertise_start() is never called on its own,
 * so an image with this file compiled in behaves exactly as before until
 * something asks for it.
 */
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <string.h>

#include "matter_btp.h"
#include "matter_ble_zephyr.h"

LOG_MODULE_REGISTER(matter_ble, CONFIG_ULTRAWIDELOCK_MATTER_BLE_LOG_LEVEL);

/* C1, written by the commissioner (BLEManagerImpl.cpp:78-79). */
static const struct bt_uuid_128 k_chr_c1_uuid =
	BT_UUID_INIT_128(0x11, 0x9D, 0x9F, 0x42, 0x9C, 0x4F, 0x9F, 0x95, 0x59, 0x45, 0x3D, 0x26,
			 0xF5, 0x2E, 0xEE, 0x18);
/* C2, indicated to the commissioner (BLEManagerImpl.cpp:80-81). */
static const struct bt_uuid_128 k_chr_c2_uuid =
	BT_UUID_INIT_128(0x12, 0x9D, 0x9F, 0x42, 0x9C, 0x4F, 0x9F, 0x95, 0x59, 0x45, 0x3D, 0x26,
			 0xF5, 0x2E, 0xEE, 0x18);

/* ---- connection-scoped state --------------------------------------------- */

/*
 * One commissioning connection at a time. That is not a simplification for
 * now: a second commissioner arriving mid-PASE would have to be refused
 * anyway, so the single slot IS the policy.
 */
static struct bt_conn *s_conn;
static struct matter_btp_rx s_rx;
static uint8_t s_rx_buf[CONFIG_ULTRAWIDELOCK_MATTER_BLE_RX_BUF];
static struct matter_btp_tx s_tx;
static uint8_t s_frag[MATTER_BTP_MAX_FRAGMENT];
static bool s_tx_active;
static bool s_indicate_busy;
static bool s_handshaked;

/*
 * Whether the peer enabled indications on C2 is NOT mirrored in a local flag.
 * It was, and the flag was wrong: a commissioner subscribes BEFORE its first C1
 * write, so c2_ccc_changed() set the flag and claim_conn() -> reset_link() then
 * cleared it on the very write that opened the link. The queued handshake
 * response was never sent and the phone sat on "connecting" until it gave up,
 * with nothing in the log to say why. Zephyr tracks this per connection, so ask
 * it instead of keeping a second copy that can disagree.
 */
static bool is_subscribed(void);
/** Negotiated BTP PDU size, header included. Settled by the handshake. */
static uint16_t s_fragment_size;

/*
 * The tx sequence counter lives HERE, not in struct matter_btp_tx, because BTP
 * numbers per connection rather than per message: a standalone ack consumes a
 * sequence number just as a data fragment does. The fragmenter is handed the
 * current value at init and its position is copied back after every emit.
 */
static uint8_t s_tx_seq;
/*
 * The BTP handshake response, held until the peer subscribes to C2.
 *
 * A commissioner writes the handshake request to C1 FIRST and enables
 * indications on C2 second, so at the moment the request arrives there is no
 * subscription to indicate on and bt_gatt_indicate() returns -EINVAL. CHIP does
 * the same thing for the same reason: HandleCapabilitiesRequestReceived() only
 * queues the response, and BLEEndPoint.cpp:202-231 sends it from
 * HandleSubscribeReceived(). Found against a real iPhone, which got as far as
 * "BTP up: fragment=244 window=4" and then dropped the link.
 */
static uint8_t s_hs_resp[MATTER_BTP_RESP_LEN];
static uint8_t s_hs_resp_len;

/** A received fragment we still owe an acknowledgement for. */
static bool s_ack_pending;
static uint8_t s_ack_seq;
/** Fragments received since we last acknowledged anything. */
static uint8_t s_rx_unacked;

static matter_ble_msg_cb s_msg_cb;
static matter_ble_link_cb s_link_cb;
static matter_ble_tx_cb s_tx_cb;
/** True only after matter_ble_send() accepted a caller-owned message. */
static bool s_tx_notifies;

/*
 * The node's own work queue. Stage 0 measured k_sys_work_q at 3,568 of 4,096
 * bytes during an unlock, and the reader already defers BLE work there, so
 * anything Matter submits to it overflows it. Owning a queue is the other half
 * of that constraint; thread priority alone is not enough.
 *
 * The stack size is PROVISIONAL and deliberately generous. Two stack sizes were
 * guessed low earlier in this project and both faulted on hardware, so the rule
 * now is to start roomy and trim from CONFIG_THREAD_ANALYZER_AUTO output rather
 * than from a plausible-looking round number. Nothing here is expensive yet;
 * PASE is what will actually load it, and it must be re-measured then.
 */
K_THREAD_STACK_DEFINE(matter_wq_stack, CONFIG_ULTRAWIDELOCK_MATTER_BLE_WQ_STACK);
static struct k_work_queue_config matter_wq_cfg = {.name = "matter_wq"};
static struct k_work_q matter_wq;
static struct k_work s_msg_work;
static size_t s_msg_len;
/*
 * The handshake response goes out from HERE, not from the GATT callback that
 * triggers it. CHIP's own Zephyr port does the same: the CCC write and the C1
 * write only post events (BLEManagerImpl.cpp:765,768), and the indication
 * happens later on the CHIP thread from HandleTXCharCCCDWrite().
 *
 * Indicating inline from c2_ccc_changed() means indicating before Zephyr has
 * sent the ATT write response for the subscription itself. The phone saw an
 * indication for a subscribe it had not yet been told succeeded, unsubscribed,
 * and dropped the link -- with our own log cheerfully reporting the response
 * as sent.
 */
static struct k_work s_hs_work;

static bool claim_conn(struct bt_conn *conn);

/**
 * Reset the BLE link state: clear the reassembly buffer, zero TX state, clear all flags (tx_active,
 * indicate_busy, handshaked), reset fragment size to the minimum, and reset sequence and ack
 * counters. Invoke the link state callback if registered.
 */
static void reset_link(void)
{
	/* The BTP fragmenter borrows the application's packet. Return that loan
	 * before clearing its cursor, exactly once. */
	if (s_tx_notifies) {
		s_tx_notifies = false;
		if (s_tx_cb != NULL) {
			s_tx_cb(-ECONNRESET);
		}
	}
	matter_btp_rx_init(&s_rx, s_rx_buf, sizeof(s_rx_buf), 0u);
	memset(&s_tx, 0, sizeof(s_tx));
	s_tx_active = false;
	s_indicate_busy = false;
	s_handshaked = false;
	s_fragment_size = MATTER_BTP_MIN_FRAGMENT;
	s_tx_seq = 0u;
	s_ack_pending = false;
	s_rx_unacked = 0u;
	s_hs_resp_len = 0u;

	if (s_link_cb != NULL) {
		s_link_cb();
	}
}

/* ---- outbound ------------------------------------------------------------ */

static void indicate_done(struct bt_conn *conn, struct bt_gatt_indicate_params *params,
			  uint8_t err);
static int pump_tx(void);

static struct bt_gatt_indicate_params s_ind_params;

/** Push one fragment, or a raw buffer when @p raw is set (the handshake reply). */
static int indicate_raw(const uint8_t *data, size_t len);

/**
 * Send the BTP handshake response to the peer if subscribed to C2 indications; otherwise do nothing
 * and let the subscription handler (c2_ccc_changed) resubmit this work when the subscription
 * arrives.
 */
static void hs_work_handler(struct k_work *work)
{
	uint8_t n = s_hs_resp_len;

	ARG_UNUSED(work);

	/* Not subscribed yet is not an error: c2_ccc_changed() will submit this
	 * again when the subscription arrives. */
	if (n == 0u || !is_subscribed()) {
		return;
	}
	s_hs_resp_len = 0u;
	LOG_INF("BTP handshake response out (%u B)", (unsigned int)n);
	(void)indicate_raw(s_hs_resp, n);
}

/**
 * Work queue handler for a completed BTP message reassembly. If a message callback is registered,
 * invoke it with the reassembly buffer and message length; otherwise log a warning and drop the
 * message. Then reset the reassembly state for the next message. Runs on the work queue rather than
 * in the BLE RX callback to keep the reassembly area exclusive to the handler.
 */
static void msg_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	if (s_msg_cb != NULL) {
		s_msg_cb(s_rx_buf, s_msg_len);
	} else {
		LOG_WRN("reassembled %u bytes with no handler; dropping", (unsigned int)s_msg_len);
	}
	/* The reassembly area is reused for the next message only after the
	 * handler has had it, which is why this runs on the queue and not in the
	 * BLE RX callback. */
	matter_btp_rx_reset(&s_rx);
}

/* ---- C1: the commissioner writes ----------------------------------------- */

/**
 * Handle a BLE GATT write to the Matter BTP C1 characteristic. On first write, decode and accept
 * the BTP handshake; initialize RX/TX sequence numbers and fragment size; queue the handshake
 * response for transmission on C2. On subsequent writes, decode incoming BTP fragments, reassemble
 * messages, send acknowledgments when the peer's window is half-full or a message completes, and
 * disconnect if framing desynchronizes. Return the number of bytes consumed or a GATT error code.
 */
static ssize_t c1_write(struct bt_conn *conn, const struct bt_gatt_attr *attr, const void *buf,
			uint16_t len, uint16_t offset, uint8_t flags)
{
	const uint8_t *p = buf;
	int rc;

	ARG_UNUSED(attr);
	ARG_UNUSED(flags);

	if (offset != 0) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}
	if (!claim_conn(conn)) {
		return BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES);
	}

	if (!s_handshaked) {
		struct matter_btp_handshake_req req;
		struct matter_btp_handshake_resp resp;
		uint8_t out[MATTER_BTP_RESP_LEN];
		size_t n = 0;

		LOG_HEXDUMP_DBG(p, len, "BTP handshake request");
		rc = matter_btp_req_decode(p, len, &req);
		if (rc != MATTER_OK) {
			LOG_ERR("bad BTP handshake request (%d)", rc);
			return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
		}
		rc = matter_btp_accept(&req, bt_gatt_get_mtu(conn), CONFIG_ULTRAWIDELOCK_MATTER_BLE_WINDOW,
				       &resp);
		if (rc != MATTER_OK) {
			LOG_ERR("no mutually supported BTP version");
			return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
		}
		if (matter_btp_resp_encode(&resp, out, sizeof(out), &n) != MATTER_OK) {
			return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
		}

		/*
		 * Sequence numbering after the handshake, and it is NOT symmetric.
		 *
		 * BLEEndPoint.cpp:512-514: "If end point plays peripheral role,
		 * expect ack for indication sent as last step of BTP handshake",
		 * i.e. expectInitialAck = (role == kBleRole_Peripheral). That
		 * selects BtpEngine::Init's expect_first_ack branch
		 * (BtpEngine.cpp:90-95): mTxNextSeqNum = 1, mRxNextSeqNum = 0.
		 *
		 * So the handshake indication we just queued IS sequence 0 even
		 * though it carries no sequence byte, our first framed fragment is
		 * 1, and the peer's first data fragment is 0.
		 *
		 * This was backwards until a real iPhone rejected it: the log said
		 * "BTP up" and then "BTP fragment refused (-4)" on Apple's very
		 * first data fragment. Nothing on the host could have caught it --
		 * matter_btp.c takes the first sequence as a parameter and is
		 * correct either way; the wrong number was chosen here.
		 */
		matter_btp_rx_init(&s_rx, s_rx_buf, sizeof(s_rx_buf), 0u);
		s_tx_seq = 1u;
		s_fragment_size = resp.fragment_size;
		s_handshaked = true;
		LOG_HEXDUMP_DBG(out, n, "BTP handshake response");
		LOG_INF("BTP up: fragment=%u window=%u (att mtu %u)",
			(unsigned int)resp.fragment_size, (unsigned int)resp.window_size,
			(unsigned int)bt_gatt_get_mtu(conn));

		/* The reply is NOT BTP-framed; it goes out as-is. But it cannot go
		 * out yet: the peer subscribes to C2 only after this write, so
		 * hold it and let c2_ccc_changed() send it. */
		memcpy(s_hs_resp, out, n);
		s_hs_resp_len = (uint8_t)n;
		/* Submit unconditionally. If the peer subscribed first the handler
		 * sends immediately; if not, it does nothing and c2_ccc_changed()
		 * submits again. Either order works and neither indicates from a
		 * GATT callback. */
		k_work_submit_to_queue(&matter_wq, &s_hs_work);
		return len;
	}

	LOG_HEXDUMP_DBG(p, len > 24u ? 24u : len, "C1 data fragment (first bytes)");
	rc = matter_btp_rx_fragment(&s_rx, p, len);
	LOG_DBG("C1 fragment: %u B -> rc=%d, reassembled=%u", (unsigned int)len, rc,
		(unsigned int)s_rx.len);
	if (rc == MATTER_OK || rc == MATTER_END) {
		s_ack_pending = true;
		s_ack_seq = s_rx.last_seq;
		if (s_rx_unacked < UINT8_MAX) {
			s_rx_unacked++;
		}
	}
	if (rc == MATTER_END) {
		s_msg_len = s_rx.len;
		k_work_submit_to_queue(&matter_wq, &s_msg_work);
	} else if (rc != MATTER_OK) {
		/* BTP has no gap recovery: once the framing desynchronises the only
		 * move is to drop the link. */
		LOG_ERR("BTP fragment refused (%d); dropping the connection", rc);
		(void)bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
	}

	/*
	 * Acknowledge before the peer's window fills, or it stops sending and the
	 * commissioning stalls with no error anywhere. Half the window is the
	 * trigger rather than every fragment, which would double the packet count;
	 * a completed message is always acknowledged so the peer can move on.
	 *
	 * Nothing is sent here if a transmission is already in flight: pump_tx()
	 * piggybacks the pending ack onto the next fragment for free.
	 */
	if (s_ack_pending && !s_tx_active && !s_indicate_busy &&
	    (rc == MATTER_END || s_rx_unacked >= (CONFIG_ULTRAWIDELOCK_MATTER_BLE_WINDOW / 2))) {
		uint8_t ackbuf[3];
		size_t n = 0;

		if (matter_btp_standalone_ack(s_ack_seq, s_tx_seq, ackbuf, sizeof(ackbuf), &n) ==
		    MATTER_OK) {
			s_tx_seq++;
			s_ack_pending = false;
			s_rx_unacked = 0u;
			(void)indicate_raw(ackbuf, n);
		}
	}
	return len;
}

/* ---- C2: we indicate ----------------------------------------------------- */

/**
 * BLE GATT CCC callback for the C2 indication characteristic. If indications are enabled (value ==
 * BT_GATT_CCC_INDICATE) and a handshake response is staged, submit the hs_work to the Matter work
 * queue.
 */
static void c2_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	ARG_UNUSED(attr);
	LOG_INF("C2 indications %s", value == BT_GATT_CCC_INDICATE ? "on" : "off");

	if (value == BT_GATT_CCC_INDICATE && s_hs_resp_len > 0u) {
		k_work_submit_to_queue(&matter_wq, &s_hs_work);
	}
}

/*
 * PUBLISHED ONLY WHILE COMMISSIONING IS ACTUALLY POSSIBLE. This is a dynamic
 * service, registered and withdrawn to follow the advert, for one reason:
 *
 * MACOS REFUSES THIS SERVICE TO THIRD PARTIES, AND THAT BREAKS EVERY OTHER
 * SERVICE ON THE BOARD. CoreBluetooth reserves the Matter commissioning UUIDs
 * for the system and answers a descriptor discovery on C1 with CBError 8,
 * CBErrorUUIDNotAllowed. Chromium's macOS backend logs that error and returns
 * without marking the characteristic discovered, so its GATT-discovery-complete
 * event never fires (bluetooth_low_energy_device_mac.mm; the TODO is
 * crbug.com/609844). getPrimaryService() then never settles -- Web Bluetooth
 * has no timeout of its own -- and the browser update path hangs on a board
 * that connected perfectly.
 *
 * MEASURED 2026-08-27 against this reader, one service at a time:
 *
 *     SMP              ok     h23
 *     native DFU       ok     h19
 *     credential FFF2  ok     h27 h29
 *     Matter FFF6      FAILS  CBError 8 at handle 13   <- C1
 *     SMP again        FAILS  <- the host cache is now poisoned
 *
 * The last line is why this looked intermittent for so long: one refused
 * discovery makes every later connection to the board fail, including ones that
 * would have worked, until the cache clears.
 *
 * A COMMISSIONED LOCK HAS NO USE FOR THIS SERVICE. The advert already carries
 * the credential payload rather than the commissionable one, chosen by exactly
 * the predicate that now gates registration (ultrawidelock_ble_zephyr.c's
 * advertising_payload_build). The GATT table simply did not follow the advert:
 * the board said "I am a reader, do not commission me" and published a
 * commissioning service anyway. Making the two agree is correct on its own
 * terms, and it happens to hand macOS a table it will walk.
 *
 * Order matters: attrs[4] is the C2 VALUE, which is what an indication targets.
 */
static struct bt_gatt_attr matter_attrs[] = {
	BT_GATT_PRIMARY_SERVICE(BT_UUID_DECLARE_16(0xFFF6)),
	BT_GATT_CHARACTERISTIC(&k_chr_c1_uuid.uuid,
			       BT_GATT_CHRC_WRITE | BT_GATT_CHRC_WRITE_WITHOUT_RESP,
			       BT_GATT_PERM_WRITE, NULL, c1_write, NULL),
	BT_GATT_CHARACTERISTIC(&k_chr_c2_uuid.uuid, BT_GATT_CHRC_INDICATE,
			       BT_GATT_PERM_NONE, NULL, NULL, NULL),
	BT_GATT_CCC(c2_ccc_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
};
static struct bt_gatt_service matter_svc = BT_GATT_SERVICE(matter_attrs);

/* Whether the service is in the database right now. Static zero is correct:
 * nothing is registered until the advertising worker asks for it, which it does
 * on its first pass, before anything can connect. */
static atomic_t s_svc_published;

int matter_ble_publish(bool on)
{
	int rc;

	if (on == (atomic_get(&s_svc_published) != 0)) {
		return 0;
	}
	/* Never pull the table out from under a live commissioning link. The
	 * caller runs on every advertising pass and will ask again.
	 *
	 * s_conn is written from the Bluetooth connection callback and read here
	 * on the advertising work queue, deliberately without a lock. An aligned
	 * pointer cannot tear, and both ways of losing the race are harmless: a
	 * stale non-NULL defers the withdrawal to the next pass, and a stale NULL
	 * withdraws a service a peer has only just connected to, which Zephyr
	 * permits and which the disconnect that follows would have caused anyway.
	 * A lock here would sit between the advertising path and the BLE stack for
	 * no property worth having. */
	if (!on && s_conn != NULL) {
		return -EBUSY;
	}

	rc = on ? bt_gatt_service_register(&matter_svc) : bt_gatt_service_unregister(&matter_svc);
	if (rc != 0) {
		LOG_WRN("0xFFF6 %s failed (%d)", on ? "register" : "unregister", rc);
		return rc;
	}
	atomic_set(&s_svc_published, on ? 1 : 0);
	LOG_INF("0xFFF6 service %s", on ? "published" : "withdrawn");
	return 0;
}

/**
 * Return true if a BLE connection is active and subscribed to indications on the C2 characteristic.
 */
static bool is_subscribed(void)
{
	return s_conn != NULL &&
	       bt_gatt_is_subscribed(s_conn, &matter_svc.attrs[4], BT_GATT_CCC_INDICATE);
}

/**
 * Enqueue a BLE indication (server-to-client notification) of the given data on the Matter C2
 * characteristic. Returns -EBUSY if no connection exists or an indication is already pending;
 * -EAGAIN if the peer is not subscribed to indications; 0 on success.
 */
static int indicate_raw(const uint8_t *data, size_t len)
{
	if (s_conn == NULL || s_indicate_busy) {
		return -EBUSY;
	}
	/* Indicating before the peer subscribes is refused by the stack as a bare
	 * -EINVAL, which says nothing about why. Name it here instead. */
	if (!is_subscribed()) {
		LOG_ERR("indicate before the peer subscribed to C2");
		return -EAGAIN;
	}
	memcpy(s_frag, data, len);

	memset(&s_ind_params, 0, sizeof(s_ind_params));
	s_ind_params.attr = &matter_svc.attrs[4];
	s_ind_params.func = indicate_done;
	s_ind_params.data = s_frag;
	s_ind_params.len = (uint16_t)len;

	s_indicate_busy = true;
	int rc = bt_gatt_indicate(s_conn, &s_ind_params);

	if (rc != 0) {
		s_indicate_busy = false;
		LOG_ERR("bt_gatt_indicate failed (%d)", rc);
	}
	return rc;
}

/** Emit the next BTP fragment, if a message is being sent. */
static int pump_tx(void)
{
	size_t n = 0;
	int rc;

	if (!s_tx_active || s_indicate_busy) {
		return 0;
	}
	rc = matter_btp_tx_next(&s_tx, s_ack_pending ? &s_ack_seq : NULL, s_frag, sizeof(s_frag),
				&n);
	if (rc == MATTER_END) {
		s_tx_active = false;
		if (s_tx_notifies) {
			s_tx_notifies = false;
			if (s_tx_cb != NULL) {
				s_tx_cb(0);
			}
		}
		return 0;
	}
	if (rc != MATTER_OK) {
		LOG_ERR("BTP fragmentation failed (%d)", rc);
		s_tx_active = false;
		if (s_tx_notifies) {
			s_tx_notifies = false;
			if (s_tx_cb != NULL) {
				s_tx_cb(-EIO);
			}
		}
		return -EIO;
	}
	/* s_frag is already the indication payload; indicate_raw would copy it
	 * onto itself, so the params are filled in directly here. */
	memset(&s_ind_params, 0, sizeof(s_ind_params));
	s_ind_params.attr = &matter_svc.attrs[4];
	s_ind_params.func = indicate_done;
	s_ind_params.data = s_frag;
	s_ind_params.len = (uint16_t)n;

	s_indicate_busy = true;
	rc = bt_gatt_indicate(s_conn, &s_ind_params);
	if (rc != 0) {
		s_indicate_busy = false;
		s_tx_active = false;
		LOG_ERR("bt_gatt_indicate failed (%d)", rc);
		if (s_tx_notifies) {
			s_tx_notifies = false;
			if (s_tx_cb != NULL) {
				s_tx_cb(rc);
			}
		}
	} else {
		/* Commit transport sequence and piggybacked acknowledgement only
		 * after the stack accepted this fragment. An immediate rejection put
		 * neither on air, so advancing either would desynchronise the retry. */
		s_tx_seq = s_tx.next_seq;
		if (s_ack_pending) {
			s_ack_pending = false;
			s_rx_unacked = 0u;
		}
	}
	return rc;
}

/**
 * Callback fired when a BLE indication is confirmed by the peer. Clears indicate_busy and logs the
 * confirmation error. If no error, calls pump_tx to emit the next BTP fragment; if error is
 * nonzero, sets tx_active to false and logs the error.
 */
static void indicate_done(struct bt_conn *conn, struct bt_gatt_indicate_params *params, uint8_t err)
{
	ARG_UNUSED(conn);
	ARG_UNUSED(params);

	s_indicate_busy = false;
	LOG_DBG("indication confirmed (err %u)", (unsigned int)err);
	if (err != 0u) {
		LOG_ERR("indication not confirmed (%u)", (unsigned int)err);
		s_tx_active = false;
		if (s_tx_notifies) {
			s_tx_notifies = false;
			if (s_tx_cb != NULL) {
				s_tx_cb(-EIO);
			}
		}
		return;
	}
	/* One indication may be outstanding per connection, so the next fragment
	 * only goes once the peer has confirmed this one. */
	(void)pump_tx();
}

int matter_ble_send(const uint8_t *msg, size_t len)
{
	int rc;

	if (msg == NULL || len == 0u) {
		return -EINVAL;
	}
	if (s_conn == NULL || !s_handshaked) {
		return -ENOTCONN;
	}
	if (!is_subscribed()) {
		return -EAGAIN;
	}
	if (s_tx_active) {
		return -EBUSY;
	}

	/* The fragment size is whatever the handshake settled on, not a constant:
	 * sending larger than the peer agreed to is how a commissioner silently
	 * stops reassembling. */
	rc = matter_btp_tx_init(&s_tx, msg, len, s_fragment_size, s_tx_seq);
	if (rc != MATTER_OK) {
		return -EINVAL;
	}
	s_tx_active = true;
	rc = pump_tx();
	if (rc == 0) {
		/* bt_gatt_indicate() completes asynchronously; publish the loan only
		 * after the initial submission succeeded, so an immediate rejection is
		 * returned directly and never also completes through the callback. */
		s_tx_notifies = true;
	}
	return rc;
}

/**
 * Register a callback to be invoked when the BLE link state changes (connection or disconnection).
 */
void matter_ble_set_link_handler(matter_ble_link_cb cb)
{
	s_link_cb = cb;
}

void matter_ble_set_tx_handler(matter_ble_tx_cb cb)
{
	s_tx_cb = cb;
}

void matter_ble_set_msg_handler(matter_ble_msg_cb cb)
{
	s_msg_cb = cb;
}

/* ---- connection tracking ------------------------------------------------- */

/*
 * The connection is claimed on the first C1 write, NOT on connect. The reader
 * accepts BLE connections too, and claiming every one of them would let an
 * credential peer occupy the single commissioning slot and lock out a real
 * commissioner. A peer that writes C1 has identified itself as one.
 */
static bool claim_conn(struct bt_conn *conn)
{
	if (s_conn == conn) {
		return true;
	}
	if (s_conn != NULL) {
		/*
		 * ERR, not INF: this is the only path that turns a commissioner
		 * away, and it did so silently. The peer sees a bare GATT write
		 * failure with nothing on the board to explain it, which is
		 * indistinguishable from the write never arriving -- and the two
		 * have opposite fixes. Bench builds lower the module level to see
		 * the INF lines; this one has to survive a shipping build.
		 */
		LOG_ERR("C1 write refused: commissioning link held by another peer");
		return false;
	}
	s_conn = bt_conn_ref(conn);
	reset_link();
	LOG_INF("commissioning link up");
	return true;
}

/**
 * BLE disconnection callback. Clears the connection reference, marks any active session as
 * inactive, and resets the link state (reassembly buffer, TX flags).
 */
static void on_disconnected(struct bt_conn *conn, uint8_t reason)
{
	if (conn != s_conn) {
		return;
	}
	LOG_INF("commissioning link down (0x%02x)", (unsigned int)reason);
	bt_conn_unref(s_conn);
	s_conn = NULL;
	reset_link();
}

BT_CONN_CB_DEFINE(matter_conn_cb) = {
	.disconnected = on_disconnected,
};

/* ---- advertising --------------------------------------------------------- */

/*
 * ChipBLEDeviceIdentificationInfo, 8 bytes after the 16-bit UUID
 * (CHIPBleServiceData.h:52-79):
 *   [0]    opcode, 0x00 = commissionable
 *   [1]    low 8 bits of the 12-bit discriminator
 *   [2]    high 4 bits of the discriminator in the low nibble,
 *          advertisement version in the high nibble
 *   [3..4] vendor ID, little-endian
 *   [5..6] product ID, little-endian
 *   [7]    additional-data flag
 */
/*
 * Runtime discriminator override, 0 meaning "use the built-in one".
 *
 * Set while an OpenCommissioningWindow is open, cleared when it closes. It
 * exists because CONFIG_ULTRAWIDELOCK_MATTER_DISCRIMINATOR is baked into the payload
 * at build time, and a controller opening a window picks its own.
 */
static uint16_t s_discriminator_override;

void matter_ble_set_discriminator(uint16_t discriminator)
{
	s_discriminator_override = discriminator;
}

uint16_t matter_ble_discriminator(void)
{
	return s_discriminator_override != 0u ? s_discriminator_override
					      : (uint16_t)CONFIG_ULTRAWIDELOCK_MATTER_DISCRIMINATOR;
}

int matter_ble_commissionable_svc_data(uint8_t *out, size_t cap)
{
	uint8_t *p = &out[2];

	if (out == NULL || cap < MATTER_BLE_SVC_DATA_LEN) {
		return -EINVAL;
	}

	out[0] = 0xF6u; /* 0xFFF6, little-endian inside BT_DATA_SVC_DATA16 */
	out[1] = 0xFFu;

	p[0] = 0x00u;
	/*
	 * The discriminator is normally the compile-time one, but
	 * OpenCommissioningWindow lets a controller choose its own -- and the
	 * ecosystem being invited in SCANS for that value. Advertising the
	 * factory one while a window is open makes the node undiscoverable to
	 * exactly the peer it was opened for, which is what this board did
	 * until now.
	 */
	p[1] = (uint8_t)(matter_ble_discriminator() & 0xFFu);
	/* Advertisement version 0 in the high nibble. */
	p[2] = (uint8_t)((matter_ble_discriminator() >> 8) & 0x0Fu);
	p[3] = (uint8_t)(CONFIG_ULTRAWIDELOCK_MATTER_VENDOR_ID & 0xFFu);
	p[4] = (uint8_t)(CONFIG_ULTRAWIDELOCK_MATTER_VENDOR_ID >> 8);
	p[5] = (uint8_t)(CONFIG_ULTRAWIDELOCK_MATTER_PRODUCT_ID & 0xFFu);
	p[6] = (uint8_t)(CONFIG_ULTRAWIDELOCK_MATTER_PRODUCT_ID >> 8);
	p[7] = 0x00u;

	return 0;
}

/* ---- init ---------------------------------------------------------------- */

/*
 * Started by SYS_INIT rather than by the application, because the C1 write
 * handler goes live the moment matter_ble_publish() puts the service in the
 * database, which the advertising worker does without asking the application. Leaving the queue to an explicit call meant the two lifetimes could
 * disagree, and they did -- with no caller, --gc-sections dropped this function
 * and matter_wq_stack with it, so a C1 write would have submitted to a work
 * queue that was never started. Tying the queue to the service removes the
 * question.
 */
static int matter_ble_init(void)
{
	k_work_queue_start(&matter_wq, matter_wq_stack, K_THREAD_STACK_SIZEOF(matter_wq_stack),
			   CONFIG_ULTRAWIDELOCK_MATTER_BLE_WQ_PRIO, &matter_wq_cfg);
	k_work_init(&s_msg_work, msg_work_handler);
	k_work_init(&s_hs_work, hs_work_handler);
	reset_link();
	LOG_DBG("0xFFF6 transport ready (rx buffer %u B); the service itself is published "
		"only while commissioning is possible", (unsigned int)sizeof(s_rx_buf));
	return 0;
}

SYS_INIT(matter_ble_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
