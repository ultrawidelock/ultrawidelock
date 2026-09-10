/* SPDX-License-Identifier: ISC */

/** @file ccc_shim.h — map a per-frame STS index to the (dURSK, STS-V) pair the DW3000 STS engine
 * loads. */

#ifndef CCC_SHIM_H
#define CCC_SHIM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ccc_kdf.h"

/** Bind the shim to a ranging session's derived key material. */
int ccc_shim_bind(const uint8_t mursk[CCC_MURSK_LEN],
		  const uint8_t salted_hash[CCC_SALTED_HASH_LEN], uint32_t sts_index0,
		  uint16_t n_slot_per_round);

/** Bind the shim, deriving mURSK + SaltedHash from the URSK + RangingConfiguration. */
int ccc_shim_bind_from_ursk(const uint8_t ursk[CCC_URSK_LEN], const uint8_t *ranging_config,
			    size_t rc_len, uint32_t sts_index0, uint16_t n_slot_per_round);

/** @brief Unbind the shim; @ref ccc_shim_active returns false afterward. */
void ccc_shim_unbind(void);

/** @brief Whether the per-frame STS interception is live (bound AND not suspended). */
bool ccc_shim_active(void);

/** Suspend/resume the per-frame IV wrap without unbinding. */
void ccc_shim_suspend(bool suspend);

/** Map a per-frame STS index to its CCC dURSK (per-cycle) + STS-V (per-PPDU). */
int ccc_shim_sts_for_index(uint32_t sts_index, uint8_t dursk[CCC_DURSK_LEN],
			   uint8_t sts_v[CCC_STS_V_LEN]);

/** Derive the dUDSK (per-cycle Final_Data key) for the ranging cycle containing sts_index. */
int ccc_shim_dudsk_for_index(uint32_t sts_index, uint8_t dudsk[CCC_DUDSK_LEN]);

/** Map a ranging-slot offset (STS_Index0 + slot) to its CCC dURSK + STS-V. */
int ccc_shim_sts_for_slot(uint32_t slot, uint8_t dursk[CCC_DURSK_LEN],
			  uint8_t sts_v[CCC_STS_V_LEN]);

/** Extract the STS index the blob packed into a DW3000 STS IV (index at bytes 7..4). */
uint32_t ccc_shim_index_from_iv(const uint8_t iv16[16]);

/** Map the blob's raw provisioned STS index to a CCC-schedule STS index (origin/stride
 * auto-calibrated from the first two indices). */
uint32_t ccc_shim_blob_to_ccc_index(uint32_t blob_idx, uint32_t *block, uint32_t *sub);

/** Pin the substituted STS to one fixed CCC index (bench validation). */
void ccc_shim_pin_index(uint32_t ccc_index);

/** @brief Release the debug pin; STS resumes advancing with the blob index. */
void ccc_shim_unpin(void);

/** Reset the wrap's first-N-frame IV log budget (target only). */
void ccc_shim_wrap_log_reset(void);

/** Reset the responder-RX wrap's first-N-arm log budget (target only). */
void ccc_shim_rx_log_reset(void);

/** Feed each RX event's status word to the empirical STS-index tracker (target only). */
void ccc_shim_rx_notify_rx(uint32_t status);

/** Decode a received SP0 Pre-POLL frame to read Apple's exact POLL STS index (target only). */
void ccc_shim_rx_try_prepoll(uint16_t datalength);

/** True while an SP3 POLL RX is armed (the next RX-good event is its result). Target only. */
bool ccc_shim_rx_awaiting_poll(void);

/**
 * Per-session ranging tallies, one per step of the DS-TWR round. Reset with
 * ccc_shim_rx_log_reset() at listen start and printed, then zeroed, by
 * ccc_prepoll_stop(), so a session that accepted a Pre-POLL and never latched a
 * range says which step it died at without the per-frame trace on.
 */
struct ccc_shim_rx_stats {
	uint32_t prepoll_ok;  /* Pre-POLLs accepted (MIC + context + replay checks) */
	uint32_t poll_arm;    /* SP3 POLL windows armed off a warm STS */
	uint32_t poll_ok;     /* POLLs received with a good STS in our block */
	uint32_t poll_fail;   /* POLL windows that closed without one (CPER / timeout) */
	uint32_t resp_tx;     /* Response_0 delayed TXs armed */
	uint32_t final_data;  /* Final_Data frames decoded */
	uint32_t range;       /* ranges latched into fira_session */
	uint32_t last_poll_st; /* raw DW3000 status of the last POLL window result */
};
void ccc_shim_rx_stats_get(struct ccc_shim_rx_stats *out);

/** True while the responder still owes the current ranging block a radio event: an armed POLL RX
 * (a few slots out) or an armed Final RX (~2 ms out). Sample it AFTER chaining to the blob's RX
 * handler and it names the reception just serviced: only the Final leaves it false, with the
 * whole ~192 ms inter-block gap as slack. Diagnostics that need a long SPI burst (the
 * windowed-CIR read) must run only then — bench-proven to cost the round otherwise. Target
 * only. */
bool ccc_shim_rx_deadline_pending(void);

/** True while an SP3 Final RX is armed. Sample it BEFORE chaining to the blob's RX handler and it
 * says "the reception being serviced IS the Final" — the handler clears the flag and immediately
 * re-arms an SP0 listen. That pre-chain instant is the only point in a ranging block where the
 * radio is idle: no auto-re-enable is configured, so a completed RX leaves the DW3000 in IDLE
 * until the shim arms the next one. The accumulator can only be read there. Reading it after the
 * re-arm returns a fixed non-physical blob, byte-identical at every offset — the receiver is
 * overwriting the accumulator underneath the read (bench runs 2-4, and `cir probe` shows a clean,
 * correctly-addressed, repeatable window once the session ends). Target only. */
bool ccc_shim_rx_awaiting_final(void);

/** BENCH toggle — run the standalone SP0 Pre-POLL listener instead of the FiRa session. */
#define ULTRAWIDELOCK_CCC_PREPOLL_LISTEN 1

/** BENCH: bring up a raw continuous SP0 receiver for the CCC Pre-POLL (target only). */
int ccc_prepoll_listen(uint8_t channel, uint8_t preamble_code);

/** Pre-apply the expected session PHY (radio configured, TRX off, RX not armed) so a
 * following ccc_prepoll_listen() with the same params skips the dwt_configure long pole. */
int ccc_prepoll_prewarm(uint8_t channel, uint8_t preamble_code);

/** Stop the Pre-POLL listener: close the self-rearm listen-gate, then force the radio off (target
 * only). */
void ccc_prepoll_stop(void);

/** True while the Pre-POLL listener is up (listen-gate open). Platforms whose flash controller
 * stalls the CPU (nRF NVMC) defer flash work behind this, so a write or erase cannot land inside
 * a ranging slot's arm window (target only). */
bool ccc_prepoll_listening(void);

/** @brief The bound session's `STS_Index0` (for UAD/Pre-POLL derivation); 0 if unbound. */
uint32_t ccc_shim_sts_index0(void);

/**
 * @brief Register the credential-session handoff listener (NULL to clear).
 *
 * Backs ultrawidelock_uwb_set_handoff_listener(); see uwb.h for the contract
 * and for why the parameters leave this module at all.
 */
struct ultrawidelock_uwb_handoff;
void cherry_ccc_set_handoff_listener(void (*cb)(const struct ultrawidelock_uwb_handoff *h));

#endif /* CCC_SHIM_H */
