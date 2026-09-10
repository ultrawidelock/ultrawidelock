/* SPDX-License-Identifier: ISC */

// Public header for UWB facade: exposes credential DS-TWR responder lifecycle and range query; the
// CCC engine is bound and unbound via internal ursk and stop calls.
/*
 * C shim bridging the add-on UWB impl to the UltraWideLock FiRa/CCC engine.
 *
 * This header is also the UWB chipset engine contract: everything above it
 * (apps, the credential adapter, session and key logic) speaks these functions and
 * never names a radio API. The DW3000 engine behind it is a closed file set
 * enforced by tests/tooling/uwb_engine_scope_check.sh; a new chipset supplies
 * its own implementation of these functions (see PORTING.md, "New UWB
 * chipset") instead of extending that set.
 */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Bind the CCC STS from the add-on-supplied plaintext URSK; returns 0 on success. */
int ultrawidelock_uwb_bind_ursk(const uint8_t *ursk, size_t ursk_len);

/**
 * @brief credential UWB ranging parameters negotiated during M1-M4 handshake.
 * @param session_id credential UWB session identifier (any non-zero value).
 * @param channel UWB operating channel (5 or 9).
 * @param sync_code_index SYNC/preamble code index (1..32).
 * @param slot_duration_rstu Slot duration in RSTU units (1200 = 1 ms).
 * @param block_duration_ms Ranging block repetition period in milliseconds.
 * @param slot_per_round Number of slots per ranging round.
 * @param sts_index0 Starting STS (Scrambled Timestamp Sequence) index.
 * @param uwb_time_us UWB_Time0 initiation reference in microseconds.
 * @param ursk 32-byte URSK (provisioned STS root key).
 * @param ranging_config Serialized RangingConfiguration (CCC SaltedHash input), or NULL to use URSK
 * fallback.
 * @param rc_len RangingConfiguration length in bytes (typically 17).
 */
struct ultrawidelock_uwb_cred_cfg {
	uint32_t session_id;         /**< credential UWB session id (any non-zero). */
	uint8_t channel;             /**< UWB channel: 5 or 9. */
	uint8_t sync_code_index;     /**< SYNC/preamble code index (1..32). */
	uint16_t slot_duration_rstu; /**< Slot duration, RSTU (1200 = 1 ms). */
	uint32_t block_duration_ms;  /**< Ranging block period, ms. */
	uint8_t slot_per_round;      /**< Slots per ranging round. */
	uint32_t sts_index0;         /**< Starting STS index. */
	uint64_t uwb_time_us;        /**< UWB_Time0 initiation reference, µs. */
	const uint8_t *ursk;         /**< 32-byte URSK (provisioned STS root). */
	/** Serialized RangingConfiguration (CCC SaltedHash input), or NULL for URSK fallback. */
	const uint8_t *ranging_config;
	size_t rc_len; /**< RangingConfiguration length, bytes (17). */
};

/** Start the CCC DS-TWR responder bound to a live credential; returns 0 on success. */
int ultrawidelock_uwb_start_cred(const struct ultrawidelock_uwb_cred_cfg *cfg);

/** Pre-apply the expected session PHY (radio configured, TRX off, RX not armed) so the
 * M4-time start skips the dwt_configure long pole when the negotiated params match. */
int ultrawidelock_uwb_prewarm(uint8_t channel, uint8_t sync_code_index);

/** Quiesce the radio and unbind the CCC STS shim. */
void ultrawidelock_uwb_stop(void);

/** Latest distance in cm; true if a valid range has been seen. */
bool ultrawidelock_uwb_last_range_cm(int32_t *cm_out);

/**
 * Latest distance in cm, gated by the range-integrity consensus (layer 4):
 * true only when a valid range has been seen AND it is trusted
 * (fira_session_range_trusted()). This is the accessor the unlock decision
 * must use so a single unverified/spoofed block cannot drive an unlock; raw
 * telemetry keeps using ultrawidelock_uwb_last_range_cm(). Without CONFIG_ULTRAWIDELOCK_CRED
 * there is no trust concept and this matches ultrawidelock_uwb_last_range_cm().
 */
bool ultrawidelock_uwb_trusted_range_cm(int32_t *cm_out);

/**
 * As ultrawidelock_uwb_trusted_range_cm(), plus how long ago that range landed. For
 * callers that must judge whether a range is still CURRENT rather than merely
 * the most recent one seen -- a distance from two minutes ago says nothing
 * about who is standing here now. Polling this beats registering a range
 * listener to timestamp latches: there is only one listener slot, and an app
 * that already owns it (the lock's approach loop) would otherwise be displaced.
 */
bool ultrawidelock_uwb_trusted_range_age_cm(int32_t *cm_out, int64_t *age_ms_out);

/**
 * As ultrawidelock_uwb_last_range_cm(), plus how long ago that range landed. The
 * store keeps the last distance until the next session clears it, so a bench
 * reading it without the age cannot tell a live range from one left behind by
 * a peer that stopped ranging a minute ago.
 */
bool ultrawidelock_uwb_last_range_age_cm(int32_t *cm_out, int64_t *age_ms_out);

/**
 * A trusted range AND the initiator's ranging block it was measured in, from
 * ONE latch.
 *
 * For pairing this node's distance against a SECOND ANCHOR's. Two anchors
 * fusing a side-of-door verdict must be describing the same instant, and the
 * block index is how that is decided: both read the same integer off the
 * initiator's own frames, so equality is exact rather than estimated. Age
 * cannot substitute -- a staleness window wide enough to be useful is many
 * blocks wide, and a phone moves a long way in that.
 *
 * Both out-params come from one call for a reason. Reading the distance and the
 * block through separate accessors lets a latch land between them, producing a
 * block that does not describe the distance it travels with -- and a label that
 * is checked but wrong is worse than no label, because the check passes and
 * nobody looks further. For the same reason the caller must fuse THIS distance,
 * not one taken from a tracker with its own update rules.
 *
 * @return false when no trusted range exists, leaving both out-params untouched.
 */
bool ultrawidelock_uwb_trusted_range_block_cm(int32_t *cm_out, uint32_t *block_out);

/**
 * The live UWB session id, or 0 when no session is up.
 *
 * Needed alongside the ranging block whenever two anchors' captures are
 * compared: the block is the INITIATOR's counter and it RESTARTS every session,
 * so block alone is not a key. Joining on it produced a confident 940 mm
 * reading out of two unrelated moments before that was noticed.
 */
uint32_t ultrawidelock_uwb_session_id(void);

/** Monotonic accepted-range epoch for post-challenge freshness checkpoints. */
uint32_t ultrawidelock_uwb_range_generation(void);

/** Counts successful ultrawidelock_uwb_start_cred() calls. A peer that suspends
 *  ranging and starts it again inside one BLE session (the Watch does, once
 *  it has walked away and come back) keeps its session id, so this is the
 *  only epoch that says "the peer began ranging again". */
uint32_t ultrawidelock_uwb_start_generation(void);

/** Trusted distance only when its accepted-range epoch is newer than @p after.
 *  This is the demand-driven presence seam: an old latch can never satisfy a
 *  challenge merely because it remains recent in wall-clock terms. */
bool ultrawidelock_uwb_trusted_range_after_cm(int32_t *cm_out, uint32_t after);

/** Layer-2 evidence for a latched range, for a consumer that must fail closed. */
struct ultrawidelock_uwb_range_integrity {
	bool sts_ok;         /**< every block in the agreeing run passed the STS floor */
	int16_t sts_quality; /**< worst STS quality index in that run */
	uint8_t trust_level; /**< how many agreeing blocks stand behind the distance */
};

/**
 * As ultrawidelock_uwb_trusted_range_after_cm(), plus the integrity evidence recorded
 * with that latch. The plain accessor answers "how far", which is all an unlock
 * decision needs; this one also answers "how well was that measured", which is
 * what a caller has to know before signing the number into a statement someone
 * else will believe. Without CONFIG_ULTRAWIDELOCK_CRED there is no evidence to report
 * and @p ig_out reads back as a failed STS.
 */
bool ultrawidelock_uwb_trusted_range_after_checked_cm(int32_t *cm_out, uint32_t after,
					    struct ultrawidelock_uwb_range_integrity *ig_out);

/**
 * Register a callback fired after each accepted range latch (NULL to clear),
 * so the unlock seam can block on an event instead of polling. The callback
 * runs on the UWB RX path; keep it to a task wake, nothing heavier. A no-op
 * without CONFIG_ULTRAWIDELOCK_CRED.
 */
void ultrawidelock_uwb_set_range_listener(void (*cb)(void));

/** Everything a second anchor needs to join the round this lock just started. */
struct ultrawidelock_uwb_handoff {
	const uint8_t *ursk; /**< 32 bytes, valid only for the duration of the call */
	size_t ursk_len;
	const uint8_t *rcfg; /**< 17 bytes, same lifetime */
	size_t rcfg_len;
	uint8_t channel;
	uint8_t sync_code_index;
};

/**
 * Register a callback fired at credential session start with the join
 * parameters (NULL to clear).
 *
 * Exists so the SEALED link can carry the handoff instead of a human relaying
 * it: CONFIG_ULTRAWIDELOCK_SATELLITE_HANDOFF_LOG prints the same payload to a
 * debug console, which needs a laptop wired to both boards and puts the URSK in
 * the clear on RTT. This module knows the parameters but nothing about
 * transports, so it hands them over and the application decides.
 *
 * The pointers are borrowed for the duration of the call only -- copy what you
 * keep. Runs on the credential thread before the radio starts, so a handoff can
 * land before UWB_Time0; treat it as latency-sensitive and do not block.
 */
void ultrawidelock_uwb_set_handoff_listener(void (*cb)(const struct ultrawidelock_uwb_handoff *h));

#ifdef __cplusplus
}
#endif
