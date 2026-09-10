/* SPDX-License-Identifier: ISC */

// credential M1-M4 ranging-setup interface: negotiates UWB ranging parameters with the device and
// produces the BLE ranging-control secure channel used to carry the M1-M4 exchange.
/*
 * ultrawidelock_ranging — the post-auth credential UWB ranging-setup (M1-M4) on ESP32. Thin
 * glue that drives the engine's reader adapter/session (modules/ultrawidelock_uwb
 * ultrawidelock_uwb_ adapter + session): on a completed credential-auth it creates a session bound
 * to the derived URSK, emits M1 over the BLE L2CAP channel, feeds inbound M2/M4 back to the engine,
 * and lets the engine negotiate the ranging parameters and start the DW3000 responder itself (via
 * cherry_ccc_shim -> ultrawidelock_uwb_start_cred). This replaces the earlier canned-parameter
 * handoff.
 *
 * The DW3000 is single-session, so exactly one ranging session runs at a time.
 * The whole lifecycle stays on the BLE-host task (create/feed/teardown + the
 * engine's transmit/event callbacks are all synchronous), so no locking is needed.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** One-time bring-up of the reader UWB adapter (cherry ctx + capabilities +
 *  reader config). Idempotent. Returns 0 on success, negative on failure (the
 *  reader still runs; ranging just won't start). */
int ultrawidelock_ranging_init(void);

struct ultrawidelock_secchan; /* the BleSK ranging channel (from ultrawidelock_crypto.h) */

/** Arm the M1-M4 ranging setup for a connection: create the session with ranging
 *  session id @session_id, bound to the 32-byte @ursk and the BleSK ranging channel
 *  @sc_ble, whose reader-direction counter is used to seal the engine's outbound SDUs
 *  (continuing from the AP-Completed message). @session_id MUST match the value the
 *  device derived from the AUTH0 transaction id (big-endian txid[12..15]); it is
 *  advertised in M1 and the device indexes its URSK by it. M1 is NOT sent here — the
 *  engine emits it when the device sends its Initiate-Ranging-Session. Returns 0 on
 *  success, negative on failure or if a ranging session is already active (the DW3000
 *  is single-session). */
int ultrawidelock_ranging_start(uint16_t conn_handle, uint32_t session_id, const uint8_t *ursk,
			struct ultrawidelock_secchan *sc_ble);

/** Feed one inbound post-auth PLAINTEXT SDU (already BleSK-opened by the reader;
 *  proto/id/len header + payload) to the active ranging session. M4 makes the
 *  engine start the responder with the negotiated parameters. Returns 0 if
 *  consumed, negative if there is no active session or the engine rejected it. */
int ultrawidelock_ranging_feed(uint16_t conn_handle, const uint8_t *data, size_t len);

/** Tear down the ranging session for a connection (on disconnect). No-op if none
 *  is active for @conn_handle. */
void ultrawidelock_ranging_stop(uint16_t conn_handle);

/** Age of the newest accepted range, trusted or not. Returns false when no
 *  range has been latched since the last ultrawidelock_ranging_start(). The
 *  reader's session deadline asks this: a peer that is ranging is not idle,
 *  however long it has been connected. */
bool ultrawidelock_ranging_last_range_age_ms(int64_t *age_ms_out);

#ifdef __cplusplus
}
#endif
