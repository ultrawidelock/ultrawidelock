/* SPDX-License-Identifier: ISC */

/** @file ccc_shim_rx.c — responder-RX CCC STS substitution: ultrawidelock_uwb_arm_rx() programs the
 * CCC STS on each RX-arm; target only. */

#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#include "ultrawidelock_port.h"
#include "ultrawidelock_bytes.h"

#include <deca_device_api.h>

#include "ccc_shim.h"
/* ULTRAWIDELOCK_NUM_RESPONDERS / ULTRAWIDELOCK_FINAL_SLOT_OFFSET — EXPERIMENT-2RESP */
#include "cred_round_config.h"
#include "ccc_kdf.h"            /* CCC_DURSK_LEN / CCC_STS_V_LEN + mUPSK/UAD/SP0 crypto */
#include "ccc_mac.h"            /* ccc_parse_mhr / ccc_pre_poll_parse — Pre-POLL decode */
#include "fira_session.h"       /* fira_session_current_slot / fira_session_get_ursk */
#include "uwb_min.h"            /* uwb_min_radio_init — standalone SP0 Pre-POLL listener */
#include "uwb_seam.h"           /* the decadriver seam this file implements */
#include "ultrawidelock_diag.h" /* DIAGK — verbose per-frame trace, gated off in pretty mode */
#include "uwb_rxdiag.h"         /* uwb_rxdiag_stream_get — the `ultrawidelock log` runtime toggle */
#include "flight_recorder.h"    /* fr_capture_ev — record/replay walk-up capture (gated) */

/* The host test build compiles this file without Kconfig, so the calibration
 * has to carry its own default: zero, which is the uncorrected reading. */
#ifndef CONFIG_ULTRAWIDELOCK_UWB_RANGE_BIAS_MM
#define CONFIG_ULTRAWIDELOCK_UWB_RANGE_BIAS_MM 0
#endif

#if defined(CONFIG_DW3000_SPI_METRICS)
#include "dw3000_spi.h"
#endif
#if defined(CONFIG_DW3000_STS_BULK_WRITE_EXPERIMENT)
#include "dw3000_sts_fastpath.h"
#endif

/* DIAGK runtime gate — default is per-platform; see ultrawidelock_diag.h for the rationale. */
volatile int ultrawidelock_uwb_diag_on = ULTRAWIDELOCK_UWB_DIAG_DEFAULT;

#if defined(CONFIG_ULTRAWIDELOCK_PRETTY_SHELL)
#include "ultrawidelock_log.h"
/* Pretty mode: one curated line per ranging block replaces the per-frame trace. */
LOG_MODULE_REGISTER(ultrawidelock_rng, LOG_LEVEL_INF);
#endif

/** @brief Log the first N intercepted RX-arms — confirms slot advance + register load. */
#define CCC_RX_LOG_ARMS 16

/** @brief STS_KEY/STS_IV registers (dw3000_deca_regs.h) — read back to prove the load lands. */
#define STS_KEY0_REG  0x2000CUL
#define STS_KEY1_REG  0x20010UL
#define STS_KEY2_REG  0x20014UL
#define STS_KEY3_REG  0x20018UL
#define STS_IV0_REG   0x2001CUL
#define STS_IV1_REG   0x20020UL
#define STS_IV2_REG   0x20024UL
#define STS_IV3_REG   0x20028UL
/** @brief CHAN_CTRL (dw3000_deca_regs.h): RX preamble code [12:8], SFD type [2:1]; read at the POLL
 * arm to prove the active PHY. */
#define CHAN_CTRL_REG 0x10014UL
/** @brief SYS_CFG [13:12] = CP_SPC (STS packet config / SP mode: 3 = SP3/ND). */
#define SYS_CFG_REG   0x10UL
/** @brief STS_CFG0 [7:0] = CPS_LEN (STS length code: 7 = STS64 = 4096 DRBG bits). */
#define STS_CFG0_REG  0x20000UL

/** ISOLATION PROBE (bench) — pin the RX STS index to the deterministic round-0 POLL (STS_Index0 +
 * 1) instead of the local-time slot. */
#define CCC_RX_PIN_ROUND0_POLL 1

/** ISOLATION PROBE (bench) — force SP3/ND at each RX arm so the STS engine is engaged when Apple's
 * SP3 POLL lands. */
#define CCC_RX_FORCE_SP3 1 /* 1 for the seeded Δ sweep: engage the STS engine on the SP3 POLL. */

/** EMPIRICAL STS-INDEX LOCK (bench) — track Apple's ranging clock on-air by searching the constant
 * slot offset Δ between our time0 and Apple's UWB_Time0. */
#define CCC_RX_LOCK_SWEEP                                                                          \
	0 /* 0 for the Pre-POLL listen (ULTRAWIDELOCK_CCC_PREPOLL_LISTEN): SP0 frames have no      \
	   * STS, so cper=0 would false-LOCK the sweep tracker — keep notify_rx a no-op. */

/** RESIDUE-COMPLETE alignment-offset sweep (slot = current_slot() + Δ): the STS index is linear at
 * one per slot, so sweep the constant offset Δ. */
#define CCC_RX_SLOTS_PER_BLOCK                                                                     \
	96u /**< 192 ms / 2 ms — phase-log modulus only, NOT the index stride. */
/** Sweep CENTER = Apple's UWB_Time0 / slot-duration; the offset is the constant slot gap between
 * our time0 and Apple's UWB_Time0, searched not derived. */
#define CCC_RX_DELTA_SEED 1299 /**< center: 0x0027a4d4 µs / 2 ms (heuristic; retunable). */
#define CCC_RX_DELTA_HALF                                                                          \
	768u /**< ± window around the seed: covers offsets [531,2067] (two prior estimates        \
		≈1250–1300). */
#define CCC_RX_N_CAND                                                                              \
	(2u *                                                                                      \
	 CCC_RX_DELTA_HALF) /**< 1536 one-slot Δ candidates, alternating outward from the seed. */
#define CCC_RX_DWELL                                                                               \
	1u /**< catches held per Δ candidate (1 = fast full-range sweep; bump if it cycles past). \
	    */

/** @brief Count of intercepted RX-arms; the first @ref CCC_RX_LOG_ARMS are logged. */
static uint32_t g_rx_arms;

/* --- SP3 POLL follow-on (ULTRAWIDELOCK_CCC_PREPOLL_LISTEN): after a Pre-POLL, arm the STS receiver
 * for the POLL one slot later at Apple's decrypted Poll_STS_Index. --- */
/** @brief Apple's Poll_STS_Index from the most recent decoded Pre-POLL. */
static uint32_t g_poll_sts_index;
/** @brief True once a Pre-POLL has handed us a fresh @ref g_poll_sts_index. */
static bool g_have_poll_index;
/** @brief True while the SP3 RX is armed for the POLL (next RX event = its result). */
static bool g_await_poll;
/** @brief Poll_STS_Index already armed once — a re-detected Pre-POLL (same index) must not re-arm
 * late in the block. */
static uint32_t g_armed_index;
/** @brief Pre-POLL Ipatov timestamp of the in-flight POLL arm (for the gap `d=` log). */
static uint32_t g_prepoll_ip;
/** @brief Poll_STS_Index delta between consecutive Pre-POLLs (the block stride, ~96); primes the
 * next block's dURSK. */
static uint32_t g_poll_stride;
/** @brief STS pre-derived in the idle for the predicted next POLL index, so the SP3 arm packs it
 * directly with no KDF on the 2 ms path. */
static bool g_warm_valid;
static uint32_t g_warm_index;
static uint8_t g_warm_dursk[CCC_DURSK_LEN];
static uint8_t g_warm_sts_v[CCC_STS_V_LEN];
/** @brief Verbose Pre-POLL trace budget; file-scope so a session start can reset it (below), else
 * the cap latches after the first ranging attempt and later sessions log nothing. */
static uint32_t g_pp_logged;
/* The once-per-session INF line below. Separate from g_pp_logged because that
 * budget belongs to the DIAGK trace, which pretty-shell builds compile to
 * nothing -- and it was exactly a pretty build where "did a Pre-POLL ever
 * verify" had no observable answer at all (2026-08-08, the HITL loop's
 * verdict). One INF line per session is the smallest thing a shipping image
 * can say. */
static bool g_pp_inf_said;

/** @brief Response_0 STS (Poll_STS_Index+1): same-round dURSK plus index+1 STS-V, pre-derived in
 * the idle so the TX path runs no KDF. */
static uint8_t g_warm_resp_dursk[CCC_DURSK_LEN];
static uint8_t g_warm_resp_sts_v[CCC_STS_V_LEN];
static uint8_t g_armed_resp_dursk[CCC_DURSK_LEN];
static uint8_t g_armed_resp_sts_v[CCC_STS_V_LEN];

/** @brief Final STS (Poll_STS_Index+2): the phone's Final RFRAME one slot after our Response,
 * pre-derived and snapshotted at the POLL arm so no KDF runs. */
static uint8_t g_warm_final_dursk[CCC_DURSK_LEN];
static uint8_t g_warm_final_sts_v[CCC_STS_V_LEN];
static uint8_t g_armed_final_dursk[CCC_DURSK_LEN];
static uint8_t g_armed_final_sts_v[CCC_STS_V_LEN];
/** @brief True while the SP3 RX is armed for the Final (next RX event = its result). */
static bool g_await_final;
#if defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
/** @brief Set right after a FINAL capture reverts to SP0: the NEXT callback is the
 * Final_Data's fate. Diagnostic-only; consumed and cleared by that next callback. */
static volatile bool g_postfinal_watch;
#endif
/** @brief POLL RMARKER of the in-flight round, so the TXDONE can anchor the Final window. */
static uint32_t g_poll_ip_for_final;

/** @brief The three responder DS-TWR timestamps, full 40-bit DTU: POLL RX (t2), Response TX (t3),
 * Final RX (t6). */
static uint64_t g_t_poll_rx;
static uint64_t g_t_resp_tx;
static uint64_t g_t_final_rx;

/** @brief Responder-side DS-TWR intervals (reply1 = t3-t2, round2 = t6-t3) SNAPSHOTTED at the Final
 * RX capture, when t2/t3/t6 are all from the same round. final_data_decode consumes these instead
 * of recomputing from the live globals: the Final_Data lands only after the NEXT round's POLL/
 * Response have overwritten t2/t3, so recomputing there mixes this round's t6 with the next round's
 * t3 and corrupts round2 (observed as km-scale distances). g_final_round_valid gates the compute
 * (consume-once): a Final_Data with no fresh Final capture is dropped, not turned into garbage. */
#if defined(ESP_PLATFORM) || defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
static uint32_t g_final_reply1;
static uint32_t g_final_round2;
static bool g_final_round_valid;
#endif

/* Frames we DISCARD. Deliberately not behind the bench-instrumentation ifdef:
 * either counter being non-zero means we are deleting frames the initiator did
 * send, which is a correctness signal on every build, not a diagnostic. */
static volatile uint32_t g_dbg_sp0_oversize; /* SP0 frame exceeded the stash */
static volatile uint32_t g_dbg_fd_rejected;  /* Final_Data failed the length guard */

/* Budget for the discard reports below. Loud enough that a drop can never go
 * unnoticed, bounded so a persistent mismatch cannot saturate a 115200 console
 * against the ~1.8 ms ranging-slot deadlines. */
#define CCC_DISCARD_LOG_BUDGET 8u

#if defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
/* Bench instrumentation, read over J-Link (no logging => no ISR/timing impact).
 * Diagnoses the DS-TWR capture/consume pairing on the single-core CDK. */
static volatile uint32_t g_dbg_capture_n;     /* Final RFRAME captured (snapshot set valid) */
static volatile uint32_t g_dbg_fd_calls;      /* final_data_decode entered */
static volatile uint32_t g_dbg_fd_parsed;     /* ... reached the DS-TWR compute */
static volatile uint32_t g_dbg_have_round;    /* ... with have_round == true at consume */
static volatile uint32_t g_dbg_dstwr_ok;      /* ccc_responder_ds_twr returned 0 */
static volatile int32_t g_dbg_last_dmm;       /* last computed d_mm */
static volatile uint32_t g_dbg_try_prepoll_n; /* total SP0 receptions into try_prepoll */
static volatile uint32_t g_dbg_mhr_ok;        /* SP0 frames whose MHR parsed */
static volatile uint8_t g_dbg_last_msgid;     /* last SP0 msg_id (0xFF = MHR parse fail) */
static volatile uint16_t g_dbg_last_sp0_len;  /* last SP0 datalength */
/* Post-FINAL fate: the first RX callback after a FINAL capture is the Final_Data's
 * fate (nothing else is on air between the FINAL and the next block's Pre-POLL).
 * Splits "frame arrived but our SP0 config rejected it" (=> PHY-config fix) from
 * "nothing detected, we sailed to the next Pre-POLL" (=> timing/delayed-RX fix). */
static volatile uint32_t g_dbg_pf_n;          /* post-FINAL callbacks observed */
static volatile uint32_t g_dbg_pf_err;        /* ... errored (no RXFCG): frame rejected */
static volatile uint32_t g_dbg_pf_err_hdr;    /* ... errored WITH a decoded PHR (frame on air) */
static volatile uint32_t g_dbg_pf_err_final;  /* ... errored AND header reads Final_Data (0x02) */
static volatile uint32_t g_dbg_pf_final;      /* ... a clean Final_Data (msg_id 0x02) */
static volatile uint32_t g_dbg_pf_prepoll;    /* ... a clean next-block Pre-POLL (msg_id 0x01) */
static volatile uint32_t g_dbg_pf_last_st;    /* raw status of the last post-FINAL callback */
static volatile uint8_t g_dbg_pf_last_msgid;  /* its msg_id (0xFE = no readable PHR) */
static volatile int32_t g_dbg_pf_dhi;         /* (post-FINAL frame ip) - (Final ip), hi32 ticks */
static volatile uint32_t g_dbg_fdrx_arm_ok;   /* delayed Final_Data RX armed OK */
static volatile uint32_t g_dbg_fdrx_arm_fail; /* delayed arm refused -> fell back to immediate */
static volatile int32_t g_dbg_fdrx_margin;    /* last delayed-arm margin (target - now), hi32 */
static uint32_t g_postfinal_final_ip;         /* Final ip stashed for the post-FINAL delta */
#endif

/** @brief Cache of the STS key (dURSK) currently loaded in the STS_KEY registers, so the per-arm
 * sts_key_load() skips the redundant key writes when the per-cycle-constant dURSK is
 * unchanged. Defined here (ahead of ccc_shim_rx_log_reset) so a session start can invalidate it.
 *
 * Compiled only where CCC ranging OWNS the STS_KEY registers, because the cache has no
 * invalidation hook for a foreign writer. ESP32 and the CDK
 * (CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT) qualify: their ranging path calls dwt_configurestsiv
 * directly from this file, so the IV-substitution seam is never entered. The nRF5340 DK does NOT:
 * there the Nordic MAC's dwt_configurestsiv goes through the seam into
 * ultrawidelock_uwb_set_sts_iv, and ccc_shim_wrap.c:107 overrides STS_KEY per frame with no
 * invalidation — a cache hit would then skip a write the registers actually needed, and ranging
 * would run with an STS that never correlates. */
#if defined(ESP_PLATFORM) || defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
static uint8_t g_sts_key_cache[CCC_DURSK_LEN];
static bool g_sts_key_cached;
#endif

#if defined(ESP_PLATFORM)
/** @brief ESP32: set when the POLL handler armed the Final RFRAME RX synchronously (busy-wait
 * for TXFRS), so the late-dispatching resp_tx_done skips its own (too-late) Final arm. */
static bool g_final_armed_sync;
#endif

/* Range-integrity gate (layer 2): the Final RFRAME's STS verdict, captured at
 * the Final RX event and consumed once when the matching Final_Data decodes. The
 * verdict defaults fail-closed so a block with no fresh capture cannot pass a
 * strict gate. See fira_session.h for the predicates and thresholds. */
static int32_t g_final_sts_verdict = -1;
static int16_t g_final_sts_index;
static bool g_final_evidence_valid;
static uint32_t g_final_evidence_index;
static uint32_t g_final_evidence_poll_index;

/* Authenticated SP0 anti-replay and context state. Counters are independent by
 * message class because CCC may allocate them from distinct sender streams. */
static bool g_have_prepoll_counter;
static uint32_t g_prepoll_counter;
static bool g_have_final_counter;
static uint32_t g_final_counter;
static bool g_have_session_block;
static uint16_t g_session_block;

/** @brief Per-session Pre-POLL decrypt constants (mUPSK1 + UAD-derived src/dest/keysource): depend
 * only on URSK + STS_Index0, derived once and reused. */
static bool g_uad_cached;
static uint8_t g_c_mupsk1[CCC_MUPSK1_LEN];
static uint8_t g_c_src_long[CCC_SRC_LONG_ADDR_LEN];
static uint8_t g_c_keysource[CCC_KEYSOURCE_LEN];
static uint8_t g_c_dest[CCC_DEST_SHORT_ADDR_LEN];

static bool counter_newer(uint32_t next, uint32_t previous)
{
	return (int32_t)(next - previous) > 0;
}

static bool mhr_context_ok(const struct ccc_mhr_fields *mhr)
{
	/* BOTH fields here are the byte-REVERSE of the UAD-derived arrays.
	 * ccc_uad_addresses() emits them most-significant byte first, while the
	 * frame carries them least-significant byte first (ccc_parse_mhr reads
	 * DestShort with get_le16 and copies KeySource verbatim). So DestShort is
	 * assembled MSB-first here, and KeySource is compared reversed below.
	 *
	 * Assembling DestShort little-endian instead rejected every Pre-POLL on a
	 * DWM3001CDK, and the DIAGK trace hid it by printing the two halves in
	 * different formats: "uad dest=02ff | hdr dest=02ff" is bytes 02,ff on the
	 * left against the u16 0x02ff on the right, and those bytes read
	 * little-endian are 0xff02. They were never equal.
	 */
	uint16_t dest = ((uint16_t)g_c_dest[0] << 8) | (uint16_t)g_c_dest[1];
	size_t i;

	if (mhr->dest_short_addr != dest) {
		return false;
	}
	/* KeySource is compared REVERSED, and that is not a workaround.
	 *
	 * ccc_uad_addresses() assembles g_c_keysource most-significant half first
	 * (KeySourceHigh || KeySourceLow, ccc_kdf.c), while ccc_parse_mhr() copies
	 * the Aux Security Header field in transmission order, which is LSB-first.
	 * The two are therefore byte-reverses of each other by construction.
	 *
	 * A straight memcmp here compiled fine, passed every host test, and then
	 * rejected every Pre-POLL on air -- the walk-up stopped ranging entirely,
	 * because this gate sits ahead of the whole DS-TWR chain. Observed on a
	 * DWM3001CDK: uad ks=0f3795ed against hdr ks=ed95370f.
	 * The host fakes never caught it because nothing in tests/ built an MHR the
	 * way the radio delivers one; the fixture filled both sides from the same
	 * helper, so it agreed with itself. tests/host/test_prepoll_round.c now
	 * builds the frame in transmission order and fails without this function.
	 *
	 * Reverse here rather than in ccc_uad_addresses(): g_c_keysource has no
	 * other consumer, whereas that helper's output order is asserted by the
	 * KDF tests and is the order the CCC spec defines.
	 */
	for (i = 0u; i < sizeof(g_c_keysource); i++) {
		if (mhr->key_source[i] != g_c_keysource[sizeof(g_c_keysource) - 1u - i]) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Largest SP0 frame the shim will accept, DERIVED rather than guessed.
 *
 * MHR + Final_Data header + one record per responder + MIC + the two FCS bytes
 * the driver counts in @c datalength (confirmed on air: a one-record Final_Data
 * reads 58 = 23+18+7+8+2, not 56).
 *
 * This was a bare 64. A two-record Final_Data is 65, so it was discarded one
 * byte over by the size gate below -- silently, with no counter and no log,
 * before final_data_decode ever ran. On the bench that is indistinguishable
 * from an initiator declining to send Final_Data once Response_1 goes out,
 * which is exactly the observation stage B was built on. Sizing it from the
 * constants stops the buffer falling behind CCC_MAX_RESPONDERS again.
 *
 * Then it happened once more, one layer up: that derivation covers Final_Data
 * only, but ccc_shim_rx_try_prepoll stashes EVERY SP0 frame through this
 * buffer, and a full-size 802.15.4 frame (aMaxPHYPacketSize, 127 with FCS)
 * reads 127 > 121. Seen on an ESP32-S3 walk-up as "SP0 oversize len=127
 * cap=121 DROPPED", the listener sitting in green RX and no Pre-POLL ever
 * accepted. So the floor is the PHY maximum, and the Final_Data derivation
 * only grows it past that if the responder count ever makes it larger.
 */
#define CCC_SP0_FINAL_DATA_MAX_LEN                                                                 \
	(CCC_MHR_LEN + CCC_FINAL_DATA_HDR_LEN + (CCC_MAX_RESPONDERS * CCC_RESPONDER_LEN) +          \
	 CCC_SP0_MIC_LEN + 2u)
#define CCC_SP0_PHY_MAX_LEN 127u
#define CCC_SP0_STASH_LEN                                                                          \
	((CCC_SP0_FINAL_DATA_MAX_LEN) > (CCC_SP0_PHY_MAX_LEN) ? (CCC_SP0_FINAL_DATA_MAX_LEN)        \
							      : (CCC_SP0_PHY_MAX_LEN))

/** @brief Pre-POLL frame stashed at RX for a DEFERRED decode: the ~2 ms decrypt+derive must not run
 * between the Pre-POLL and the POLL. */
static uint8_t g_pp_stash[CCC_SP0_STASH_LEN];
static uint16_t g_pp_stash_len;
static bool g_pp_pending;

/**
 * @brief Whether THIS anchor answers the block whose POLL is being handled.
 *
 * Only meaningful on the POLL path, and only there: it reads state that is
 * exactly one block behind. In steady state this block's Pre-POLL is stashed
 * but NOT yet decoded (the ~2 ms decrypt+derive is deferred past the Response
 * TX arm, see ccc_shim_rx_try_prepoll), so @c g_session_block still holds the
 * PREVIOUS block's index and this block's parity is one more than it.
 *
 * Both anchors run this identical code against the identical air input, so they
 * always reach opposite verdicts and never share a slot. The @c g_pp_pending
 * requirement is what keeps that true across the seam: on a cold bootstrap
 * block the decode runs inline instead, leaving the counter current rather than
 * one behind, and an anchor that joins mid-session would otherwise compute its
 * parity off a differently-aged counter than its partner. An anchor that cannot
 * place itself in the alternation stays silent, which costs one block; guessing
 * would risk transmitting in the same slot as its partner.
 */
static inline bool ccc_block_is_ours(void)
{
#if ULTRAWIDELOCK_BLOCK_PARITY < 0
	return true;
#else
	return g_have_session_block && g_pp_pending &&
	       (unsigned)((g_session_block + 1u) & 1u) ==
		       (unsigned)ULTRAWIDELOCK_BLOCK_PARITY;
#endif
}

#if CCC_RX_LOCK_SWEEP
/** @brief Lock/search state for the phase-locked (o,K) tracker. */
static bool g_locked;         /**< True once a candidate cleared CPER. */
static uint32_t g_lock_cand;  /**< The latched candidate index. */
static uint32_t g_sweep_cand; /**< Current candidate index in [0, N_CAND). */
static uint32_t g_dwell_cnt;  /**< Catches held at the current candidate. */
static int32_t g_cur_delta;   /**< Signed offset Δ loaded for the in-flight arm (log). */
static uint32_t g_dbg_slot;   /**< Absolute slot loaded for the in-flight arm (log). */
static uint32_t g_dbg_phase;  /**< current_slot()%96 at the in-flight arm (log). */
static uint32_t g_poll_n;     /**< Count of caught frames (for the throttled log). */

/** @brief Log the first N catches (a full cycle is 15x4=60), then only wins + banners. */
#define CCC_RX_POLL_LOG 700u /* log a full ±HALF cycle so the sweep is visible end-to-end. */

/** @brief Current candidate index: the latched lock, or the live sweep value. */
static uint32_t ccc_rx_cur_cand(void)
{
	return g_locked ? g_lock_cand : g_sweep_cand;
}
#endif /* CCC_RX_LOCK_SWEEP */

/**
 * @brief Reset all Per-POLL state: arm count, index tracking, STS warm cache, and optional
 * lock-sweep diagnostic counters; called on entry to a new Pre-POLL listen.
 */
void ccc_shim_rx_log_reset(void)
{
	g_rx_arms = 0u;
	g_have_poll_index = false;
	g_await_poll = false;
	g_armed_index = 0u;
	g_poll_sts_index = 0u;
	g_prepoll_ip = 0u;
	g_poll_stride = 0u;
	g_warm_valid = false;
	g_uad_cached = false;
	g_pp_logged = 0u; /* re-open the Pre-POLL trace for this session */
	g_pp_inf_said = false;
	g_pp_pending = false;
	g_await_final = false;
	g_poll_ip_for_final = 0u;
	g_final_sts_verdict = -1; /* fail-closed until a Final RFRAME is measured */
	g_final_sts_index = 0;
	g_final_evidence_valid = false;
	g_final_evidence_index = 0u;
	g_final_evidence_poll_index = 0u;
	g_have_prepoll_counter = false;
	g_prepoll_counter = 0u;
	g_have_final_counter = false;
	g_final_counter = 0u;
	g_have_session_block = false;
	g_session_block = 0u;
#if defined(ESP_PLATFORM) || defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
	g_final_round_valid = false;
#endif
#if defined(ESP_PLATFORM) || defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
	g_sts_key_cached =
		false; /* new session re-configures the radio -> STS_KEY regs re-cleared */
#endif
#if defined(ESP_PLATFORM)
	g_final_armed_sync = false;
#endif
#if CCC_RX_LOCK_SWEEP
	g_locked = false;
	g_sweep_cand = 0u;
	g_dwell_cnt = 0u;
	g_poll_n = 0u;
#endif
}

/**
 * @brief Returns true if the responder is awaiting the POLL frame after a successful Pre-POLL
 * decode.
 * @return true if awaiting POLL, false otherwise.
 */
bool ccc_shim_rx_awaiting_poll(void)
{
	return g_await_poll;
}

/**
 * Return true if CCC UWB reception is awaiting either POLL or FINAL frame from the responder, false
 * otherwise.
 */
bool ccc_shim_rx_deadline_pending(void)
{
	return g_await_poll || g_await_final;
}

/**
 * Return true if CCC UWB reception is awaiting a FINAL frame from the responder, false otherwise.
 */
bool ccc_shim_rx_awaiting_final(void)
{
	return g_await_final;
}

/**
 * @brief Log one RX event for the optional lock-sweep diagnostic (CONFIG_CCC_RX_LOCK_SWEEP); tracks
 * CPER (STS correlation fail flag) and dwells candidate indices until lock achieved or full cycle
 * exhausted.
 * @param status DW3000 status register value.
 */
void ccc_shim_rx_notify_rx(uint32_t status)
{
#if CCC_RX_LOCK_SWEEP
	unsigned cper;

	if (!ccc_shim_active()) {
		return;
	}
	cper = (status & 0x10000000u) ? 1u : 0u;

	/* Log the first N catches plus every win (CPER=0); ph shows the stable POLL phase. */
	if (cper == 0u || g_poll_n < CCC_RX_POLL_LOG) {
		DIAGK("cat#%u d=%d ph=%u slot=%u csn=%u cper=%u st=%08x\n", (unsigned)g_poll_n,
		      (int)g_cur_delta, (unsigned)g_dbg_phase, (unsigned)g_dbg_slot,
		      (unsigned)fira_session_current_slot(), cper, (unsigned)status);
	}
	g_poll_n++;

	if (g_locked) {
		return;
	}
	/* CPER clear => this frame's true index == the loaded candidate; latch it. Otherwise DWELL
	 * then step, announcing a full cycle with no clear. */
	if (cper == 0u) {
		g_locked = true;
		g_lock_cand = g_sweep_cand;
		DIAGK("ccc_rx LOCKED d=%d slot=%u\n", (int)g_cur_delta, (unsigned)g_dbg_slot);
		return;
	}
	if (++g_dwell_cnt >= CCC_RX_DWELL) {
		g_dwell_cnt = 0u;
		if (++g_sweep_cand >= CCC_RX_N_CAND) {
			g_sweep_cand = 0u;
			DIAGK("ccc_rx CYCLE done — all Δ dwelled, no lock\n");
		}
	}
#else
	(void)status;
#endif /* CCC_RX_LOCK_SWEEP */
}

/** BENCH: decode a live SP0 Pre-POLL (CCM*-decrypt with mUPSK1) to read Apple's exact POLL STS
 * index, learn the block stride, and warm the next block's STS. */
#define CCC_RX_PREPOLL_LOG 16u
/**
 * @brief Decode a received Pre-POLL frame: verify MHR and message ID, decrypt SP0 payload, cache
 * UAD-derived keys, extract Poll_STS_Index and stride, and pre-warm the next block's STS triplet
 * (POLL, Response_0, Final) to eliminate KDF latency from the critical path.
 * @param frame Pointer to the received frame buffer.
 * @param datalength Length of the frame in bytes.
 */
static void prepoll_decode(const uint8_t *frame, uint16_t datalength)
{
	struct ccc_mhr_fields mhr;
	// CCC pre-poll message carrying STS mode and hopping schedule start time.
	struct ccc_pre_poll pp;
	const uint8_t *ursk;
	uint8_t plain[CCC_PRE_POLL_LEN];
	int rc;
	bool lg;

	/* Only the verbose trace is budget-limited to the first @c CCC_RX_PREPOLL_LOG. */
	lg = (g_pp_logged < CCC_RX_PREPOLL_LOG);

	if (lg) {
		DIAGK("PREPOLL rx len=%u mhr=", (unsigned)datalength);
		for (unsigned i = 0u; i < CCC_MHR_LEN && (uint16_t)i < datalength; i++) {
			DIAGK("%02x", frame[i]);
		}
		DIAGK("\n");
		g_pp_logged++;
	}

	if (datalength < (uint16_t)(CCC_MHR_LEN + CCC_PRE_POLL_LEN + CCC_SP0_MIC_LEN)) {
		return; /* too short to hold a Pre-POLL */
	}
	if (ccc_parse_mhr(frame, &mhr) != 0) {
		if (lg) {
			DIAGK("PREPOLL mhr parse fail\n");
		}
		return;
	}
	if (mhr.msg_id != CCC_MSG_ID_PRE_POLL) {
		if (lg) {
			DIAGK("PREPOLL not-prepoll msg_id=%02x\n", (unsigned)mhr.msg_id);
		}
		return;
	}
	if (mhr.payload_len != CCC_PRE_POLL_LEN ||
	    (uint16_t)(CCC_MHR_LEN + mhr.payload_len + CCC_SP0_MIC_LEN) > datalength) {
		if (lg) {
			DIAGK("PREPOLL bad len pl=%u dl=%u\n", (unsigned)mhr.payload_len,
			      (unsigned)datalength);
		}
		return;
	}
	ursk = fira_session_get_ursk();
	if (ursk == NULL) {
		return;
	}
	if (!g_uad_cached) {
		uint8_t mupsk2[CCC_MUPSK2_LEN], uad[CCC_UAD_LEN];

		/* Per-session constants (URSK + STS_Index0): derive once, reuse every block so the
		 * setup KDFs stay off the decode. */
		ccc_derive_mupsk1(ursk, g_c_mupsk1);
		ccc_derive_mupsk2(ursk, mupsk2);
		ccc_derive_uad(mupsk2, ccc_shim_sts_index0(), uad);
		ccc_uad_addresses(uad, g_c_keysource, g_c_dest, g_c_src_long);
		g_uad_cached = true;
	}
	if (!mhr_context_ok(&mhr)) {
		if (lg) {
			DIAGK("PREPOLL context mismatch\n");
		}
		return;
	}
	if (lg) {
		/* Self-check: the UAD-derived DestShort + KeySource must equal the on-air header,
		 * else STS_Index0 byte order is wrong. */
		DIAGK("PREPOLL uad dest=%02x%02x ks=%02x%02x%02x%02x | hdr dest=%04x "
		      "ks=%02x%02x%02x%02x\n",
		      g_c_dest[0], g_c_dest[1], g_c_keysource[0], g_c_keysource[1],
		      g_c_keysource[2], g_c_keysource[3], (unsigned)mhr.dest_short_addr,
		      mhr.key_source[0], mhr.key_source[1], mhr.key_source[2], mhr.key_source[3]);
	}
	rc = ccc_sp0_decrypt(g_c_mupsk1, g_c_src_long, mhr.frame_counter, frame, CCC_MHR_LEN,
			     &frame[CCC_MHR_LEN], mhr.payload_len,
			     &frame[CCC_MHR_LEN + mhr.payload_len], plain);
	if (rc != 0) {
		if (lg) {
			DIAGK("PREPOLL decrypt FAIL rc=%d fc=%u\n", rc,
			      (unsigned)mhr.frame_counter);
		}
		return;
	}
	ccc_pre_poll_parse(plain, &pp);
	if (pp.uwb_session_id != fira_session_id() ||
	    (g_have_prepoll_counter && !counter_newer(mhr.frame_counter, g_prepoll_counter)) ||
	    (g_have_poll_index && !counter_newer(pp.poll_sts_index, g_poll_sts_index))) {
		if (lg) {
			DIAGK("PREPOLL replay/context reject sid=%08x fc=%u idx=%08x\n",
			      (unsigned)pp.uwb_session_id, (unsigned)mhr.frame_counter,
			      (unsigned)pp.poll_sts_index);
		}
		return;
	}
	g_prepoll_counter = mhr.frame_counter;
	g_have_prepoll_counter = true;
	g_session_block = pp.ranging_block;
	g_have_session_block = true;
	if (g_have_poll_index) {
		/* Learn the per-block Poll_STS_Index stride so the POLL-result path can pre-warm
		 * the next block's dURSK. */
		g_poll_stride = pp.poll_sts_index - g_poll_sts_index;
	}
	g_poll_sts_index = pp.poll_sts_index; /* ground truth for the next-block prediction */
	g_have_poll_index = true;
	/* Warm the NEXT block's STS now, in this ~190 ms idle, so the next Pre-POLL's SP3 arm packs
	 * it with zero KDF on the critical path. */
	if (g_poll_stride != 0u) {
		uint32_t widx = g_poll_sts_index + g_poll_stride;

		/* Warm the POLL (widx), our Response AND Final — same round, same dURSK,
		 * only STS-V advances — so no leg runs a KDF. */
		/* EXPERIMENT-2RESP: the phone's Final RFRAME sits ULTRAWIDELOCK_FINAL_SLOT_OFFSET
		 * slots past the POLL (n=1 -> widx+2, n=2 -> widx+3). Responder l's
		 * Response_l sits at widx+1+l: the lock is 0, the satellite is 1. */
		if (ccc_shim_sts_for_index(widx, g_warm_dursk, g_warm_sts_v) == 0 &&
		    ccc_shim_sts_for_index(widx + 1u + ULTRAWIDELOCK_RESPONDER_INDEX,
					   g_warm_resp_dursk, g_warm_resp_sts_v) == 0 &&
		    ccc_shim_sts_for_index(widx + ULTRAWIDELOCK_FINAL_SLOT_OFFSET, g_warm_final_dursk,
					   g_warm_final_sts_v) == 0) {
			g_warm_index = widx;
			g_warm_valid = true;
		}
	}
	if (!g_pp_inf_said) {
		g_pp_inf_said = true;
		/* The CCM* MIC above is keyed by mUPSK1 from the URSK, so this line
		 * is the on-air proof the BLE transcript cannot fake. Through the
		 * facade printer and NOT LOG_INF: this file only registers a log
		 * module under pretty shell, and not through DIAGK's gate: pretty
		 * builds compile that to nothing, which is how this event came to
		 * have no observable at all on 2026-08-08. */
		ultrawidelock_printf("I: Pre-POLL accepted: URSK proven on air (sts0 %08x)\n",
			   (unsigned)ccc_shim_sts_index0());
	}
	if (lg) {
		DIAGK("PREPOLL OK poll_sts_index=%08x cs=%u sts0=%08x\n",
		      (unsigned)pp.poll_sts_index, (unsigned)fira_session_current_slot(),
		      (unsigned)ccc_shim_sts_index0());
	}
}

/** @brief Assemble a 5-byte DW3000 (40-bit) timestamp into a uint64 (DTU ticks). */
static uint64_t ts5_to_u64(const uint8_t t[5])
{
	return (uint64_t)t[0] | ((uint64_t)t[1] << 8) | ((uint64_t)t[2] << 16) |
	       ((uint64_t)t[3] << 24) | ((uint64_t)t[4] << 32);
}

/* The negotiated slot the controller (iPhone) assumes for its single-sided ToF: M3 sends
 * 400 * chaps_per_slot RSTU (the iPhone session negotiates chaps=6 => 2400 RSTU), 1 RSTU =
 * 208 hi32 ticks, so 2400 * 208 = 499200 hi32 (127795200 DTU). A peer with no reverse
 * timestamp report assumes the responder replied exactly one such slot after the POLL. */
#define CCC_SLOT_NOMINAL_HI32 499200u
#define CCC_SLOT_NOMINAL_DTU  ((int64_t)CCC_SLOT_NOMINAL_HI32 * 256) /* 127795200 */
/* Reader reply-path excess (TX antenna + processing), hi32 ticks. Measured: reply1 came out
 * ~499263 (63 over nominal) and the controller's computed range sat a constant ~+37 m high at
 * every true distance (8 cm..3 m) = ~62 hi32 too much reply. The reader's own DS-TWR cancels
 * it; a single-sided peer does not, so pre-subtract it. Re-tune vs the phone_d diagnostic. */
#define CCC_RESP_ANT_DLY_HI32 62u
/* RESPONSE RMARKER offset from the POLL RX, hi32 = nominal slot minus the reply-path delay, so
 * the on-air RMARKER lands on the slot boundary the peer assumes. NOT the empirical
 * CCC_RX_SLOT_HI32 (that is for tolerant RX-window arming). Moving this does not change the
 * reader's own distance -- DS-TWR is invariant to the reply/round split. */
#define CCC_RESP_SLOT_HI32    (CCC_SLOT_NOMINAL_HI32 - CCC_RESP_ANT_DLY_HI32)

/**
 * @brief Decode a received Final_Data (SP0, msg_id=02): dUDSK-decrypt and parse the initiator's
 * ranging timestamps; not time-critical.
 * @param frame Pointer to the received frame buffer.
 * @param datalength Length of the frame in bytes.
 */
static void final_data_decode(const uint8_t *frame, uint16_t datalength)
{
	static uint32_t g_fd_logged;
#if defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
	g_dbg_fd_calls++;
#endif
	struct ccc_mhr_fields mhr;
	// CCC final message carrying credential authentication data (MAC, derived ranging state).
	struct ccc_final_data fd;
	uint8_t dudsk[CCC_DUDSK_LEN];
	/* Decrypted Final_Data payload: header + one record per responder. This was
	 * a bare 64, which caps at six responders (18 + 7n <= 64), the same
	 * buffer-behind-the-constant shape as the SP0 stash one layer up. Derived so
	 * neither can fall behind CCC_MAX_RESPONDERS again. */
	uint8_t plain[CCC_FINAL_DATA_HDR_LEN + (CCC_MAX_RESPONDERS * CCC_RESPONDER_LEN)];
	bool lg = (g_fd_logged < 16u);
	int rc;

	if (ccc_parse_mhr(frame, &mhr) != 0 || mhr.msg_id != CCC_MSG_ID_FINAL_DATA) {
		return;
	}
	if (!g_uad_cached || !mhr_context_ok(&mhr)) {
		return;
	}
	if (mhr.payload_len > sizeof(plain) ||
	    (uint16_t)(CCC_MHR_LEN + mhr.payload_len + CCC_SP0_MIC_LEN) > datalength) {
		/* Also a discard, so also visible. This one was a bare return too. */
		g_dbg_fd_rejected++;
		if (g_dbg_fd_rejected <= CCC_DISCARD_LOG_BUDGET) {
			ultrawidelock_printf("W: Final_Data rejected pl=%u cap=%u dl=%u (#%u)\n",
				   (unsigned)mhr.payload_len, (unsigned)sizeof(plain),
				   (unsigned)datalength, (unsigned)g_dbg_fd_rejected);
		}
		return;
	}
	/* Final_Data can be dispatched after the next block has changed the live
	 * armed index. Derive against the Final capture's snapshotted POLL index,
	 * never that mutable live value. */
	if (!g_final_evidence_valid ||
	    ccc_shim_dudsk_for_index(g_final_evidence_poll_index, dudsk) != 0) {
		return;
	}
	rc = ccc_sp0_decrypt(dudsk, g_c_src_long, mhr.frame_counter, frame, CCC_MHR_LEN,
			     &frame[CCC_MHR_LEN], mhr.payload_len,
			     &frame[CCC_MHR_LEN + mhr.payload_len], plain);
	if (rc != 0) {
		if (lg) {
			DIAGK("FINALDATA decrypt FAIL rc=%d fc=%u\n", rc,
			      (unsigned)mhr.frame_counter);
			g_fd_logged++;
		}
		return;
	}
	if (ccc_final_data_parse(plain, mhr.payload_len, &fd) != 0 || fd.num_responders == 0u) {
		if (lg) {
			DIAGK("FINALDATA parse FAIL pl=%u\n", (unsigned)mhr.payload_len);
			g_fd_logged++;
		}
		return;
	}
	/* Deliberately NOT comparing fd.ranging_block against a snapshot of the
	 * Pre-POLL's block number. That number reaches us through the DEFERRED
	 * Pre-POLL decode (g_session_block, set in prepoll_decode), while the Final
	 * evidence is snapshotted synchronously in the Final RFRAME callback, so the
	 * two are one block apart whenever the stashed Pre-POLL has not been decoded
	 * yet. On a DWM3001CDK that raced every round: "blk=2 want=1" with the
	 * session id and the STS index both matching exactly, and no range ever
	 * latched.
	 *
	 * Nothing is lost by dropping it. final_sts_index is derived from
	 * g_armed_index, increments once per block, and is checked below, so it
	 * already binds this Final_Data to one specific round -- more tightly than a
	 * 16-bit block counter does. Session binding and replay protection are the
	 * other two terms, both kept.
	 */
	if (fd.uwb_session_id != fira_session_id() ||
	    fd.final_sts_index != g_final_evidence_index ||
	    (g_have_final_counter && !counter_newer(mhr.frame_counter, g_final_counter))) {
		if (lg) {
			DIAGK("FINALDATA replay/context reject sid=%08x blk=%u idx=%08x fc=%u\n",
			      (unsigned)fd.uwb_session_id, (unsigned)fd.ranging_block,
			      (unsigned)fd.final_sts_index, (unsigned)mhr.frame_counter);
			g_fd_logged++;
		}
		return;
	}
	g_final_counter = mhr.frame_counter;
	g_have_final_counter = true;
	if (lg) {
		/* final_tx = t5-t1 (POLL->Final tx), r0_ts = t4-t1 (POLL->Response rx) — the two
		 * initiator timestamps DS-TWR needs. */
		DIAGK("FINALDATA ok blk=%u final_tx=%u nresp=%u r0_ts=%u\n",
		      (unsigned)fd.ranging_block, (unsigned)fd.ranging_ts_final_tx,
		      (unsigned)fd.num_responders, (unsigned)fd.responders[0].timestamp);
		g_fd_logged++;
	}

#if ULTRAWIDELOCK_NUM_RESPONDERS >= 2
	/* EXPERIMENT-2RESP (dual-anchor builds only; compiled out of the 1:1 baseline):
	 * the decisive outcome signal. num_responders is the count the phone actually
	 * built into the round; it rides the SP0 Final_Data on the permanent listen,
	 * independent of the SP3 Final-RFRAME arm, so it survives an arm miss. Log every
	 * record plus the Final_Data arrival slot offset (Final_Data RX - most-recent
	 * POLL RX, whole slots): 4 => the phone grew the round for 2 responders (PASS),
	 * 3 => it kept the 1-responder round (SOFT-FAIL). */
	{
		/* One ranging slot in full 40-bit DTU. Equals CCC_RX_SLOT_HI32 (499000, the
		 * hi32/bits[39:8] domain) << 8; defined locally because that macro lives
		 * further down inside the ULTRAWIDELOCK_CCC_PREPOLL_LISTEN block. Keep the two equal. */
		const uint64_t slot_dtu = (uint64_t)499000u << 8;
		uint8_t fdts[5] = {0};
		uint64_t fd_rx;
		int fd_slots;

		dwt_readrxtimestamp_ipatov(fdts);
		fd_rx = ts5_to_u64(fdts);
		fd_slots = (g_t_poll_rx != 0u) ? (int)((fd_rx - g_t_poll_rx) / slot_dtu) : -1;
		DIAGK("FINALDATA-2RESP blk=%u nresp=%u fd_slots=%d\n", (unsigned)fd.ranging_block,
		      (unsigned)fd.num_responders, fd_slots);
		for (uint8_t i = 0u; i < fd.num_responders && i < 2u; i++) {
			DIAGK("  resp[%u] idx=%u ts=%u unc=%u status=%u\n", (unsigned)i,
			      (unsigned)fd.responders[i].responder_index,
			      (unsigned)fd.responders[i].timestamp,
			      (unsigned)fd.responders[i].timestamp_uncertainty,
			      (unsigned)fd.responders[i].ranging_status);
		}
	}
#endif /* ULTRAWIDELOCK_NUM_RESPONDERS >= 2 */

	/* DS-TWR: reply1 = Response TX - POLL RX, round2 = Final RX - Response TX;
	 * ccc_responder_ds_twr pulls round1/reply2 from the Final_Data. ToF in 15.65 ps ticks. */
	{
		// CCC DS-TWR (double-sided two-way ranging) message carrying poll/response/final
		// timing and STS data.
		struct ds_twr tw;
#if defined(ESP_PLATFORM) || defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
		/* ESP32 and single-core nRF (e.g. DWM3001CDK, CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT):
		 * the Final_Data lands only after the NEXT round's POLL/Response have
		 * overwritten the live t2/t3 (slow SPI + jittery dispatch, or BLE sharing the
		 * one core), so recomputing here mixes this round's t6 with the next round's t3
		 * (km-scale garbage). Consume the same-round snapshot taken at Final capture;
		 * g_final_round_valid gates it consume-once (a Final_Data with no fresh Final is
		 * dropped). */
		uint32_t t_reply1 = g_final_reply1;
		uint32_t t_round2 = g_final_round2;
		bool have_round = g_final_round_valid;
#else
		/* Dual-core nRF (nRF5340): the Final_Data is processed before the next round
		 * overwrites the live timestamps, so recompute directly from the globals. */
		uint32_t t_reply1 = (uint32_t)(g_t_resp_tx - g_t_poll_rx);
		uint32_t t_round2 = (uint32_t)(g_t_final_rx - g_t_resp_tx);
		bool have_round = true;
#endif

#if defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
		g_dbg_fd_parsed++;
		if (have_round) {
			g_dbg_have_round++;
		}
#endif
		if (have_round && ccc_responder_ds_twr(&fd, ULTRAWIDELOCK_RESPONDER_INDEX, t_reply1, t_round2, &tw) == 0) {
			/* Signed, because near zero the numerator goes slightly negative and
			 * an unsigned divide would wrap it into a kilometre. This used to be
			 * open-coded here to dodge exactly that in ccc_ds_twr_tof(); the
			 * estimator now lives at the base tier and is signed, so the anchor
			 * link and this path share one definition. 1 tick ~ 15.65 ps,
			 * ~4.6917 mm/tick. */
			int32_t tof = ds_twr_tof_signed(&tw);
			int d_mm = (int)(((int64_t)tof * 4692) / 1000) +
				   CONFIG_ULTRAWIDELOCK_UWB_RANGE_BIAS_MM;
#if defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
			g_dbg_dstwr_ok++;
			g_dbg_last_dmm = d_mm;
#endif
			/* Range-integrity gate (layer 2): the STS-quality floor. Shadow by
			 * default (log the verdict, still latch); define
			 * CONFIG_ULTRAWIDELOCK_RANGE_GATE_STRICT to drop a failing block instead. Layers 1
			 * (plausibility) and 4 (consensus) live in fira_session below. */
			bool sts_ok =
				fira_session_sts_quality_ok(g_final_sts_verdict, g_final_sts_index);

			/* Controller-side (single-sided) range this block: the peer assumes the
			 * responder replied one nominal slot after the POLL; should read ~= d.
			 * A large fixed offset is uncompensated reply delay. */
			int64_t ph_dtu = (int64_t)tw.t_round1 - CCC_SLOT_NOMINAL_DTU;
			int ph_d_mm = (int)((ph_dtu * 4692 / 2) / 1000);
			DIAGK("DIST tof=%d d=%dmm phone_d=%dmm rep1=%u rnd2=%u rnd1=%u rep2=%u\n",
			      (int)tof, d_mm, ph_d_mm, (unsigned)t_reply1, (unsigned)t_round2,
			      (unsigned)tw.t_round1, (unsigned)tw.t_reply2);
			DIAGK("GATE sts=%d verdict=%d sts_ok=%d\n", (int)g_final_sts_index,
			      (int)g_final_sts_verdict, (int)sts_ok);
#if defined(CONFIG_ULTRAWIDELOCK_PRETTY_SHELL)
			/* Curated one-liner: the per-block distance, gated behind `ultrawidelock frames`
			 * (default off in pretty) so the console stays quiet unless asked. */
			if (uwb_rxdiag_rng_get()) {
				LOG_INF("rng  blk=%-3u d=%dmm  tof=%d", (unsigned)fd.ranging_block,
					d_mm, (int)tof);
			}
#endif
			/* Publish the layer-2 verdict with the block whatever the build does
			 * with it. The lock may choose to open on a marginal block; a signed
			 * presence assertion may not, and it can only refuse if the evidence
			 * travelled with the range instead of being dropped here. */
			fira_session_set_ccc_range_sts(g_final_sts_verdict, g_final_sts_index);


			/* Feed the range into fira_session_last_range ->
			 * UltraWideBandImpl::ReportRange -> AccessManager -> BoltLockMgr -> Matter
			 * DoorLock cluster. */
#if defined(CONFIG_ULTRAWIDELOCK_RANGE_GATE_STRICT)
			if (sts_ok)
#else
			(void)sts_ok;
#endif
				fira_session_set_ccc_range_cm(d_mm / 10, fd.ranging_block);

			/* Consume the per-block capture: the next block must re-stash a
			 * fresh verdict + interval snapshot, else the gate fails closed. */
		}
		/* One authenticated Final_Data consumes exactly one matching Final
		 * capture, even when its timestamps fail the DS-TWR estimator. */
		g_final_evidence_valid = false;
		g_final_evidence_poll_index = 0u;
		g_final_sts_verdict = -1;
		g_final_sts_index = 0;
#if defined(ESP_PLATFORM) || defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
		g_final_round_valid = false;
#endif
	}
}

/**
 * @brief Pre-POLL RX entry (from the RX-good shim): stash the frame and DEFER its ~2 ms
 * decrypt+derive off the Pre-POLL->POLL critical path.
 *
 * The decode only feeds the NEXT block's warm (the SP3 arm keys on the pre-warmed prediction,
 * not this block's fresh index), so it has the ~190 ms idle to run in.  Running it inline —
 * on the single DW3000 workqueue, ahead of the queued POLL RX-OK callback — pushed the
 * Response TX arm past its slot (dx-now < 0 => HPDWARN).  So read the bytes now (cheap SPI),
 * then:
 *   - bootstrap (no warm yet): decode inline to seed the first arm's STS — this block is not
 *     armed, so blocking its POLL is harmless;
 *   - steady state: mark pending; @ref prepoll_rx_rearm runs @ref prepoll_decode after the
 *     Response TX is armed.  A pending decode orphaned by a missed POLL is flushed on the next
 *     Pre-POLL so the warm never goes more than one block stale.
 */
void ccc_shim_rx_try_prepoll(uint16_t datalength)
{
	/* Flight recorder: record this decode call + the RX buffer it will read,
	 * in dispatch order, so a host replay drives the identical entry point. */
	fr_capture_ev((uint8_t)FR_EP_TRY_PREPOLL, 0u, datalength);

	if (!ccc_shim_active() || datalength == 0u) {
		return; /* (the POLL event is gated out by the shim's await snapshot) */
	}
	if (datalength > sizeof(g_pp_stash)) {
		/* Loud, always, and through the FACADE PRINTER rather than DIAGK: pretty
		 * builds compile DIAGK to nothing, which is precisely how this path ate
		 * every two-responder Final_Data for a whole night without leaving a
		 * mark, and how the phone got blamed for it. A discard nobody can see is
		 * how a confident wrong verdict gets built. Same reasoning as the
		 * Pre-POLL acceptance line further down. */
		g_dbg_sp0_oversize++;
		if (g_dbg_sp0_oversize <= CCC_DISCARD_LOG_BUDGET) {
			ultrawidelock_printf("W: SP0 oversize len=%u cap=%u DROPPED (#%u)\n",
				   (unsigned)datalength, (unsigned)sizeof(g_pp_stash),
				   (unsigned)g_dbg_sp0_oversize);
		}
		return;
	}
#if defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
	g_dbg_try_prepoll_n++;
	g_dbg_last_sp0_len = datalength;
#endif
	if (g_pp_pending) { /* a prior block's POLL-result never ran (missed POLL) — flush it */
		g_pp_pending = false;
		prepoll_decode(g_pp_stash, g_pp_stash_len);
	}
	dwt_readrxdata(g_pp_stash, datalength, 0u); /* stash now; decrypt/derive is deferred */
	g_pp_stash_len = datalength;
	{
		struct ccc_mhr_fields m;
		bool mhr_ok =
			datalength >= (uint16_t)CCC_MHR_LEN && ccc_parse_mhr(g_pp_stash, &m) == 0;
#if defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
		g_dbg_last_msgid = mhr_ok ? m.msg_id : 0xFFu;
		if (mhr_ok) {
			g_dbg_mhr_ok++;
		}
#endif
		/* Final_Data (SP0, msg_id=02) carries the initiator's timestamps; decode it INLINE
		 * here (never deferred, where its dUDSK decrypt would block the next POLL). */
		if (mhr_ok && m.msg_id == CCC_MSG_ID_FINAL_DATA) {
			final_data_decode(g_pp_stash, datalength);
			return;
		}
	}
	if (!g_warm_valid) {
		prepoll_decode(g_pp_stash, datalength); /* bootstrap: seed the first warm */
	} else {
		g_pp_pending = true; /* steady state: decode in the idle */
	}
}

/** @brief Pack a 16-byte `dURSK` into the DW3000 STS-key image (whole-16 reverse). */
static void pack_key(dwt_sts_cp_key_t *out, const uint8_t dursk[CCC_DURSK_LEN])
{
	uint8_t rev[CCC_DURSK_LEN];

	for (size_t i = 0; i < CCC_DURSK_LEN; i++) {
		rev[i] = dursk[CCC_DURSK_LEN - 1u - i];
	}
	out->key0 = sys_get_le32(&rev[0]);
	out->key1 = sys_get_le32(&rev[4]);
	out->key2 = sys_get_le32(&rev[8]);
	out->key3 = sys_get_le32(&rev[12]);
}

/**
 * @brief Pack a 16-byte STS-V into the DW3000 STS-IV image (whole-16 reverse then per-word LE, same
 * as pack_key).
 * @param out Pointer to the DW3000 STS-IV register image.
 * @param sts_v 16-byte STS vector to pack.
 */
static void pack_iv(dwt_sts_cp_iv_t *out, const uint8_t sts_v[CCC_STS_V_LEN])
{
	uint8_t rev[CCC_STS_V_LEN];

	for (size_t i = 0; i < CCC_STS_V_LEN; i++) {
		rev[i] = sts_v[CCC_STS_V_LEN - 1u - i];
	}
	out->iv0 = sys_get_le32(&rev[0]);
	out->iv1 = sys_get_le32(&rev[4]);
	out->iv2 = sys_get_le32(&rev[8]);
	out->iv3 = sys_get_le32(&rev[12]);
}

/* The STS key (dURSK) is per ranging CYCLE — POLL, Response, Final and every block in the cycle
 * share it — but each arm re-wrote all four STS_KEY registers: ~258 us of SPI on the critical path,
 * ~40% of the arm latency that misses the ~1836 us slot deadline (measured on ESP32 SPI; the cost
 * on nRF is unmeasured, but the writes are redundant either way). Cache the loaded
 * dURSK and skip dwt_configurestskey when unchanged; the STS_KEY registers persist across the
 * per-frame IV/loadiv/mode reprogramming within a session. ccc_shim_rx_log_reset() clears the cache
 * (a new session's dwt_configure re-clears the registers). Only the ~16-byte IV write remains per
 * arm. (g_sts_key_cache / g_sts_key_cached are declared up top so ccc_shim_rx_log_reset can clear
 * them.) */
static void sts_key_load(const uint8_t dursk[CCC_DURSK_LEN])
{
	dwt_sts_cp_key_t k;
#if defined(ESP_PLATFORM) || defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
	size_t i;

	if (g_sts_key_cached) {
		for (i = 0u; i < CCC_DURSK_LEN && dursk[i] == g_sts_key_cache[i]; i++) {
		}
		if (i == CCC_DURSK_LEN) {
			return; /* STS_KEY registers already hold this dURSK */
		}
	}
#endif
	pack_key(&k, dursk);
#if defined(CONFIG_DW3000_STS_BULK_WRITE_EXPERIMENT)
	ultrawidelock_dw3000_write_sts_key_bulk(&k.key0);
#else
	dwt_configurestskey(&k);
#endif
#if defined(ESP_PLATFORM) || defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
	for (i = 0u; i < CCC_DURSK_LEN; i++) {
		g_sts_key_cache[i] = dursk[i];
	}
	g_sts_key_cached = true;
#endif
}

/** BENCH PROBE (CCC_RX_PACK_SELFTEST) — dump the STS register lanes a known V lands in, to pin the
 * pack_iv byte order. Not shippable. */
#define CCC_RX_PACK_SELFTEST 0 /* answered 2026-07-09: pack_iv needed the reverse (applied). */
#if CCC_RX_PACK_SELFTEST
/** @brief KAT SaltedHash with the POLL index (0x075bcd16) folded BE into [8:11]. */
static const uint8_t ccc_pst_v[CCC_STS_V_LEN] = {0x79, 0xe8, 0x65, 0x18, 0x6c, 0xbd, 0x86, 0x4b,
						 0x9c, 0xb2, 0x4f, 0xdb, 0x1c, 0xdd, 0x34, 0xf8};
/** @brief FiRa default Static-STS key — `pack_key` must reproduce the QANI image. */
static const uint8_t ccc_pst_key[CCC_DURSK_LEN] = {0x14, 0x14, 0x86, 0x74, 0xd1, 0xd3, 0x36, 0xaa,
						   0xf8, 0x60, 0x50, 0xa8, 0x14, 0xeb, 0x22, 0x0f};

/** @brief Pack a 16-byte V whole-16-reversed then word-LE (the `pack_key`/blob convention). */
static void pack_iv_rev(dwt_sts_cp_iv_t *out, const uint8_t v[CCC_STS_V_LEN])
{
	uint8_t rev[CCC_STS_V_LEN];

	for (size_t i = 0; i < CCC_STS_V_LEN; i++) {
		rev[i] = v[CCC_STS_V_LEN - 1u - i];
	}
	out->iv0 = sys_get_le32(&rev[0]);
	out->iv1 = sys_get_le32(&rev[4]);
	out->iv2 = sys_get_le32(&rev[8]);
	out->iv3 = sys_get_le32(&rev[12]);
}

/** @brief One-shot: dump STS register lanes for the KAT V under three packings. */
static void ccc_pack_selftest(void)
{
	dwt_sts_cp_key_t k;
	dwt_sts_cp_iv_t v;

	/* ANCHOR: pack_key(FiRa default) must read back as the QANI key image, proving
	 * reverse+word-LE is the DW3000 KEY order. */
	pack_key(&k, ccc_pst_key);
	dwt_configurestskey(&k);
	DIAGK("PACKST key rd %08x %08x %08x %08x exp 14eb220f f86050a8 d1d336aa 14148674\n",
	      (unsigned)dwt_read_reg(STS_KEY0_REG), (unsigned)dwt_read_reg(STS_KEY1_REG),
	      (unsigned)dwt_read_reg(STS_KEY2_REG), (unsigned)dwt_read_reg(STS_KEY3_REG));
	DIAGK("PACKST V=79e865186cbd864b9cb24fdb1cdd34f8 VCounter=79e86518 idx=075bcd16\n");

	/* A: current word-LE (no reverse) — puts VCounter in iv0, index in iv2. */
	pack_iv(&v, ccc_pst_v);
	dwt_configurestsiv(&v);
	dwt_configurestsloadiv();
	DIAGK("PACKST cur rd %08x %08x %08x %08x ctr %08x\n", (unsigned)dwt_read_reg(STS_IV0_REG),
	      (unsigned)dwt_read_reg(STS_IV1_REG), (unsigned)dwt_read_reg(STS_IV2_REG),
	      (unsigned)dwt_read_reg(STS_IV3_REG), (unsigned)dwt_readctrdbg());

	/* B: whole-16 reverse — puts index in iv1 (spec) but VCounter in iv3 (off-spec). */
	pack_iv_rev(&v, ccc_pst_v);
	dwt_configurestsiv(&v);
	dwt_configurestsloadiv();
	DIAGK("PACKST rev rd %08x %08x %08x %08x ctr %08x\n", (unsigned)dwt_read_reg(STS_IV0_REG),
	      (unsigned)dwt_read_reg(STS_IV1_REG), (unsigned)dwt_read_reg(STS_IV2_REG),
	      (unsigned)dwt_read_reg(STS_IV3_REG), (unsigned)dwt_readctrdbg());

	/* C: raw distinguishable words — readctrdbg names WHICH iv lane is the counter. */
	v.iv0 = 0x00010203u;
	v.iv1 = 0x04050607u;
	v.iv2 = 0x08090a0bu;
	v.iv3 = 0x0c0d0e0fu;
	dwt_configurestsiv(&v);
	dwt_configurestsloadiv();
	DIAGK("PACKST raw wr 00010203 04050607 08090a0b 0c0d0e0f ctr %08x <= counter lane\n",
	      (unsigned)dwt_readctrdbg());
}
#endif /* CCC_RX_PACK_SELFTEST */

/** Program the CCC STS for the current ranging slot, then arm RX. */
int32_t ultrawidelock_uwb_arm_rx(int32_t mode)
{
	if (ccc_shim_active()) {
#if CCC_RX_PACK_SELFTEST
		/* One-shot STS register-lane dump on the MAC thread; the normal arm below reloads
		 * the real STS, so this is transparent. */
		static bool pst_done;

		if (!pst_done) {
			pst_done = true;
			ccc_pack_selftest();
		}
#endif
#if CCC_RX_LOCK_SWEEP
		/* Single-scalar alignment sweep (see CCC_RX_DELTA_SEED): the index is linear
		 * (STS_Index0 + elapsed_slots), so load the STS for current_slot() + Δ, swinging
		 * outward from the seed. */
		uint32_t cand = ccc_rx_cur_cand();
		uint32_t cs = fira_session_current_slot();
		int32_t mag = (int32_t)((cand + 1u) / 2u); /* 0,1,1,2,2,3,3,… */
		int32_t swing = (cand & 1u) ? mag : -mag;  /* 0,+1,−1,+2,−2,… */
		int32_t delta = CCC_RX_DELTA_SEED + swing; /* seed + outward swing */
		uint32_t slot = (uint32_t)((int32_t)cs + delta);

		g_cur_delta = delta;
		g_dbg_phase = cs % CCC_RX_SLOTS_PER_BLOCK;
		g_dbg_slot = slot;
#elif CCC_RX_PIN_ROUND0_POLL
		uint32_t slot = 1u; /* STS_Index0 + 1 = round-0 POLL */
#else
		uint32_t slot = fira_session_current_slot();
#endif
		uint8_t dursk[CCC_DURSK_LEN], sts_v[CCC_STS_V_LEN];

		if (ccc_shim_sts_for_slot(slot, dursk, sts_v) == 0) {
			dwt_sts_cp_key_t k;
			dwt_sts_cp_iv_t v;

			pack_key(&k, dursk);
			pack_iv(&v, sts_v);
			dwt_configurestskey(&k);
#if defined(ESP_PLATFORM) || defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
			/* wrote STS_KEY out-of-band; drop the arm cache */
			g_sts_key_cached = false;
#endif
			dwt_configurestsiv(&v);   /* the shim is us; load it directly */
			dwt_configurestsloadiv(); /* reset the HW STS counter to our IV */
#if CCC_RX_FORCE_SP3
			/* The blob armed SP0 (STS engine off); flip CP_SPC to SP3/ND so the STS
			 * runs on the POLL. */
			dwt_configurestsmode((uint8_t)DWT_STS_MODE_ND);
#endif

			/* Synchronous ultrawidelock_printf (survives deferred-log starvation); rd==wr proves
			 * the key reached the register, slot proves the index clock advances. */
			if (g_rx_arms < CCC_RX_LOG_ARMS) {
				DIAGK("ccc_rx arm#%u slot=%u key0 wr %08x rd %08x iv2=%08x\n",
				      (unsigned)g_rx_arms, (unsigned)slot, k.key0,
				      (unsigned)dwt_read_reg(STS_KEY0_REG), v.iv2);
			}
			g_rx_arms++;
		}
	}
	return dwt_rxenable(mode);
}

#if ULTRAWIDELOCK_CCC_PREPOLL_LISTEN
/** Re-arm the SP0 receiver after each RX event; the ultrawidelock_uwb_set_callbacks shim runs
 * ccc_shim_rx_try_prepoll first, so here we keep the plain SP0 receive listening. */
#define CCC_RX_DIAG_N                                                                              \
	110u /**< per-catch lines to emit (~1 catch/block now — spans a full sweep). */

/** Sleep between wakes, hi32 (~4 ns) units: one 192 ms block MINUS ~5 slots, waking just ahead of
 * the Pre-POLL so it is caught fresh each block. */
#define CCC_RX_SLEEP_HI32 45900000u

/** @brief One 192 ms ranging block, hi32 (~4 ns) units (measured on air, dsys ≈ 47.92 M). */
#define CCC_RX_BLOCK_HI32 47920000u
/** @brief One 2 ms slot, hi32 units (measured, dsys ≈ 499 000). */
#define CCC_RX_SLOT_HI32  499000u
/** @brief Anchored SP0 RX window length, dwt_setrxtimeout units (1.0256 µs): ~1 slot, so a miss
 * times out before the POLL slot. */
#define CCC_RX_WIN_TO     1950u
/** @brief Sweep the armed offset ±2 slots (0..4 -> -2..+2), so an off-by-one gap does not read as
 * "no Pre-POLL". */
#define CCC_RX_SWEEP_N    5u

/** @brief Open the SP3 POLL window this many hi32 units (~160 µs) BEFORE the POLL RMARKER (Pre-POLL
 * + 1 slot), leaving settle time so a too-late window doesn't preamble-miss. */
/* History: 150000 (~600 µs) gave only ~68 µs arm margin; 80000 (~320 µs) widened it to ~350 µs on
 * the low-latency nRF. On ESP32 the Pre-POLL->arm dispatch latency is ~1.5 ms (BLE/Wi-Fi/Thread/
 * Matter all live on the other core), so at 80000 the arm deadline (SLOT-LEAD = +1676 µs) sat
 * BELOW the settled dsys of 1433-1616 µs and dwt_rxenable refused the delayed RX (ARM FAIL
 * not-late). 40000 (~160 µs) pushes the deadline to +1836 µs, turning the ~60-240 µs margins into
 * ~220-400 µs, while still opening the window ~95 µs before the ~65 µs POLL preamble. Valid for nRF
 * too (its arm is never late; it just opens the window 160 µs earlier than the RMARKER instead of
 * 320 µs). */
#define CCC_RX_POLL_LEAD   40000u
/** @brief SP3 POLL RX window (dwt_setrxtimeout units, 1.0256 µs): ~1.4 ms, delayed to the POLL
 * slot, opening ~600 µs early. */
#define CCC_RX_POLL_WIN_TO 1350u

#if defined(ESP_PLATFORM)
/** @brief ESP32 only: bounded spin (dwt_readsysstatuslo polls) waiting for the Response TXFRS in
 * the POLL handler, so the Final RFRAME RX can be armed synchronously (the async TX-done callback
 * dispatches ~2-16 ms late — past the Final at POLL+2 slots). The delayed Response TX completes
 * ~0.8-1 ms after the handler starts; at task prio 23 this spin is not descheduled. The cap only
 * bounds the pathological "TXFRS never arrives" case (starttx already returned success). */
#define CCC_RESP_TXFRS_SPIN 3000u
#endif

/** @brief try_prepoll() decode duration (hi32 ~4 ns units), reported on the ARM-FAIL line to
 * attribute the pre-arm latency. */
extern uint32_t g_ccc_dbg_decode;

/** @brief Listen-gate: true only while the Pre-POLL listener is up. ccc_prepoll_stop() closes it so
 * no callback rearm can re-enable RX after a session stop; ccc_prepoll_listen() reopens it before
 * its arm. */
static volatile bool g_listen_gate;

/** @brief Gate-checked RX arm for every self-rearm site below; refuses once the listen-gate is
 * closed. Arms the radio directly: each caller has just programmed the STS for the window it is
 * opening, so re-running ultrawidelock_uwb_arm_rx would overwrite it with the current slot's. */
static int32_t gated_rxenable(int32_t mode)
{
	if (!g_listen_gate) {
		return (int32_t)DWT_ERROR;
	}
	return dwt_rxenable(mode);
}

/* ── Arm-leg latency distributions (J-Link read; nothing prints on the hot path) ──
 * One record per arm attempt, in the DW3110's hi32 time (~4 ns/tick, the same domain as dsys):
 * RMARKER of the frame that triggered the dispatch -> the arm point. min/max catch the tail that
 * the ARM FAIL log only sees once it is already fatal; the histogram (250 us buckets, the last
 * bucket saturates) shows where the steady state sits. Never reset, so a session's distribution
 * survives its stop for a post-hoc probe attach. */
#define CCC_LAT_BUCKET_HI32 62500u /* 250 us in hi32 (~4 ns) ticks */
#define CCC_LAT_HIST_N      8u     /* 0..2 ms; the whole Pre-POLL budget is 1,836 us */

struct ccc_lat_stat {
	uint32_t n;   /* samples recorded */
	uint32_t min; /* hi32 ticks; us = value / 250 */
	uint32_t max;
	uint32_t hist[CCC_LAT_HIST_N];
};

static volatile struct ccc_lat_stat g_lat_prepoll; /* Pre-POLL RMARKER -> POLL RX arm (dsys) */
static volatile struct ccc_lat_stat g_lat_resp;    /* POLL RMARKER -> Response TX arm */
static volatile struct ccc_lat_stat g_lat_final;   /* Response TX RMARKER (t3) -> Final RX arm */

#if defined(CONFIG_DW3000_SPI_METRICS)
/* Aggregate SPI work inside each deadline-critical CCC leg. Read these symbols
 * over J-Link alongside g_lat_*; the hot path performs no logging. */
struct ccc_spi_phase_stat {
	uint32_t samples;
	uint32_t transactions;
	uint32_t reads;
	uint32_t writes;
	uint32_t wire_bytes;
	uint32_t errors;
	uint32_t timeouts;
	uint32_t max_transactions;
	uint32_t max_wire_bytes;
};

static volatile struct ccc_spi_phase_stat g_spi_poll_arm;
static volatile struct ccc_spi_phase_stat g_spi_response_arm;
static volatile struct ccc_spi_phase_stat g_spi_final_arm;

static void spi_phase_record(volatile struct ccc_spi_phase_stat *phase,
			     const struct dw3000_spi_metrics *before)
{
	struct dw3000_spi_metrics after;
	uint32_t transactions;
	uint32_t wire_bytes;

	dw3000_spi_metrics_get(&after);
	transactions = after.transactions - before->transactions;
	wire_bytes = after.wire_bytes - before->wire_bytes;
	phase->samples++;
	phase->transactions += transactions;
	phase->reads += after.reads - before->reads;
	phase->writes += after.writes - before->writes;
	phase->wire_bytes += wire_bytes;
	phase->errors += after.errors - before->errors;
	phase->timeouts += after.timeouts - before->timeouts;
	if (transactions > phase->max_transactions) {
		phase->max_transactions = transactions;
	}
	if (wire_bytes > phase->max_wire_bytes) {
		phase->max_wire_bytes = wire_bytes;
	}
}
#endif

static void lat_record(volatile struct ccc_lat_stat *s, uint32_t d)
{
	uint32_t b = d / CCC_LAT_BUCKET_HI32;

	if (s->n == 0u || d < s->min) {
		s->min = d;
	}
	if (d > s->max) {
		s->max = d;
	}
	s->hist[b < CCC_LAT_HIST_N ? b : CCC_LAT_HIST_N - 1u]++;
	s->n++;
}

#if defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
/* DW3000 IRQ-path cycle stamps (the port's dw3000_hw file), read to DECOMPOSE an arm leg's
 * dispatch latency into its buckets: hop (GPIO ISR -> worker dispatch = contention), isr (worker
 * entry -> callback entry = the dwt_isr SPI frame-pull, plus the rxdiag shim's prefix), cb
 * (callback entry -> the arm point = callback processing). Whichever bucket dominates decides
 * the fix: a large hop => contention (quiet BLE / priorities); a large isr+cb => irreducible SPI
 * on the critical path (take the CPU off it via DW3000 auto-RX).
 *
 * All three stamps are from the CURRENT event. g_dw_cyc_isrdone is deliberately not consumed
 * here: the drain loop stamps it only after the callback returns, so a callback that reads it
 * gets the PREVIOUS event's value (observed as a negative isr bucket over SWD). g_dw_cyc_cbentry
 * is stamped at prepoll_rx_rearm entry instead, which is inside this event. */
extern volatile uint32_t g_dw_cyc_gpio;      /* T0: GPIO ISR entry */
extern volatile uint32_t g_dw_cyc_work;      /* T1: worker-task dispatch entry */
extern volatile uint32_t g_dw_cyc_per_us;    /* calibrated CPU cyc/us */
uint32_t dw3000_dwt_cyccnt(void);            /* free-running cycle counter, same clock */
static volatile uint32_t g_dw_cyc_cbentry;   /* T2: CCC RX-callback entry, this event */
static volatile uint32_t g_dbg_pp_hop;       /* PRE-POLL leg: T1-T0 cyc (contention) */
static volatile uint32_t g_dbg_pp_isr;       /* PRE-POLL leg: T2-T1 cyc (dwt_isr SPI) */
static volatile uint32_t g_dbg_pp_cb;        /* PRE-POLL leg: (arm point)-T2 cyc (callback) */
static volatile uint32_t g_dbg_final_hop;    /* FINAL leg: T1-T0 cyc */
static volatile uint32_t g_dbg_final_isr;    /* FINAL leg: T2-T1 cyc */
static volatile uint32_t g_dbg_final_cb;     /* FINAL leg: (arm entry)-T2 cyc */
static volatile uint32_t g_dbg_final_per_us; /* cyc/us copy for the J-Link decode */
#endif

/** Flip to SP3/ND, load the pre-warmed CCC STS (g_warm_index), and arm a delayed RX to catch the
 * POLL that follows the Pre-POLL. */
static int arm_poll_sp3(uint32_t prepoll_ip)
{
	const uint8_t *pd, *pv;
	dwt_sts_cp_iv_t v;
#if defined(CONFIG_DW3000_SPI_METRICS)
	struct dw3000_spi_metrics spi_before;
#endif

	/* The STS for the predicted index was pre-derived in the idle (g_warm_*); pack it with no
	 * KDF on the critical path. No warm yet => skip. */
	if (!g_warm_valid) {
		return -EIO;
	}
#if defined(CONFIG_DW3000_SPI_METRICS)
	dw3000_spi_metrics_get(&spi_before);
#endif
	pd = g_warm_dursk;
	pv = g_warm_sts_v;
	/* Commit the Response_0 (idx+1) AND Final (idx+2) STS NOW, before this block's decode
	 * re-warms them to the next index. */
	for (size_t i = 0; i < CCC_DURSK_LEN; i++) {
		g_armed_resp_dursk[i] = g_warm_resp_dursk[i];
		g_armed_final_dursk[i] = g_warm_final_dursk[i];
	}
	for (size_t i = 0; i < CCC_STS_V_LEN; i++) {
		g_armed_resp_sts_v[i] = g_warm_resp_sts_v[i];
		g_armed_final_sts_v[i] = g_warm_final_sts_v[i];
	}
	pack_iv(&v, pv);
	sts_key_load(pd);         /* ESP32/CDK: writes the 4 STS_KEY regs only on a dURSK change */
#if defined(CONFIG_DW3000_STS_BULK_WRITE_EXPERIMENT)
	ultrawidelock_dw3000_write_sts_iv_bulk(&v.iv0);
#else
	dwt_configurestsiv(&v);   /* the shim is us; load it directly */
#endif
	dwt_configurestsloadiv(); /* reset HW STS counter to our IV */
	dwt_configurestsmode((uint8_t)DWT_STS_MODE_ND); /* SP0 -> SP3/ND for the POLL */

	g_prepoll_ip = prepoll_ip; /* anchor for the POLL-result gap (`d=`) log */
	/* Pin the window to the POLL slot (Pre-POLL + 1 slot).  The arm is sub-µs
	 * (armlat ~20 cyc), so this delayed target is safely in the future; a "late"
	 * error just means we lost the block — revert to SP0 (IDLE_ON_DLY_ERR keeps
	 * the RX from re-enabling immediately and catching foreign traffic). */
	/* dsys = RMARKER->arm gap in hi32 (4 ns) units; the delayed target must still be
	 * in the future when rxenable latches it (dsys < SLOT - LEAD), else HPDWARN. */
	uint32_t dsys = dwt_readsystimestamphi32() - prepoll_ip;
	lat_record(&g_lat_prepoll, dsys);
#if defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
	/* Mirror of the FINAL-leg decomposition, for THIS Pre-POLL dispatch. Taken at the dsys
	 * point so the cb bucket covers the whole pre-arm work (MHR parse + STS loads above). */
	g_dbg_pp_hop = g_dw_cyc_work - g_dw_cyc_gpio;
	g_dbg_pp_isr = g_dw_cyc_cbentry - g_dw_cyc_work;
	g_dbg_pp_cb = dw3000_dwt_cyccnt() - g_dw_cyc_cbentry;
#endif
	dwt_setdelayedtrxtime(prepoll_ip + CCC_RX_SLOT_HI32 - CCC_RX_POLL_LEAD);
	dwt_setrxtimeout(CCC_RX_POLL_WIN_TO);
	if (gated_rxenable(DWT_START_RX_DELAYED | DWT_IDLE_ON_DLY_ERR) != DWT_SUCCESS) {
		/* dsys >= (SLOT - LEAD) => "late": the DELAYED RX never opened, so rxto
		 * stays 0 and the POLL is lost.  Log the first few to size the gap. */
		static uint32_t arm_fail_n;
		if (arm_fail_n < 40u) {
			DIAGK("ARM FAIL dsys=%u(%dus) dec=%dus off=%u %s idx=%08x\n",
			      (unsigned)dsys, (int)(dsys / 250u), (int)(g_ccc_dbg_decode / 250u),
			      (unsigned)(CCC_RX_SLOT_HI32 - CCC_RX_POLL_LEAD),
			      (dsys >= (CCC_RX_SLOT_HI32 - CCC_RX_POLL_LEAD)) ? "LATE" : "not-late",
			      (unsigned)g_warm_index);
			arm_fail_n++;
		}
		dwt_configurestsmode((uint8_t)DWT_STS_MODE_OFF); /* revert to SP0 */
#if defined(CONFIG_DW3000_SPI_METRICS)
		spi_phase_record(&g_spi_poll_arm, &spi_before);
#endif
		return -EIO;
	}
#if defined(CONFIG_DW3000_SPI_METRICS)
	spi_phase_record(&g_spi_poll_arm, &spi_before);
#endif
	return 0;
}

/** @brief Revert SP3/ND -> SP0 and re-arm the permanent Pre-POLL listen (no timeout). */
static void revert_to_sp0_listen(void)
{
	dwt_forcetrxoff(); /* a refused delayed TX leaves the sequencer pending — clear it first */
	dwt_configurestsmode((uint8_t)DWT_STS_MODE_OFF);
	dwt_setrxtimeout(0u);
	(void)gated_rxenable(DWT_START_RX_IMMEDIATE);
}

#if defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
/** @brief Arm a DELAYED SP0 RX aimed at the Final_Data slot (Final RX + 1 slot), instead of the
 * immediate SP0 re-arm.
 *
 * Bench finding (CDK, single-core nRF52833): after the Final RFRAME the immediate re-arm never
 * catches the Final_Data (SP0 msg_id 0x02) — the receiver is blind for ~1 slot right after the
 * Final, so 83% of the time the next clean frame it sees is the NEXT block's Pre-POLL. The
 * Final_Data is the SAME SP0 PHY we decode the Pre-POLL with cleanly, so this is a timing miss,
 * not a config reject. A delayed RX pinned to the Final_Data slot opens the window in HARDWARE at
 * exactly the right time regardless of what the CPU is doing — the same trick arm_final_sp3 uses
 * for the Final itself. On a refused arm (caller falls back to revert_to_sp0_listen) or a
 * no-frame timeout (RXFTO -> prepoll_rx_rearm else-branch re-arms immediate SP0), the next
 * Pre-POLL is never lost, so ranging can only improve. Consumed by the same-round snapshot, so no
 * live-timestamp race. */
/* The hop/isr/cb decomposition stamps this callback consumes are declared above arm_poll_sp3,
 * shared with the PRE-POLL leg's mirror. */

/* Final_Data delayed-RX net (bench-widened): open ~100 us after the Final RMARKER and hold ~8 ms
 * (~4 slots). Scheduled in HARDWARE, so the window opens at the right instant no matter how busy
 * the single core is right after the Final. Wide enough that the Final_Data cannot fall between
 * the FINAL and the CPU getting the receiver back up, wherever in the round it actually sits. */
/* ~100 us after the Final RMARKER, which skips the Final's own tail. */
#define CCC_FDRX_OPEN_HI32 25000u
/* ~8 ms window, dwt 1.0256 us units. */
#define CCC_FDRX_WIN_TO    7800u
#define CCC_FDRX_MIN_AHEAD                                                                         \
	50000u /* ~200 us: clear the forcetrxoff+cfgsts+setdelay SPI setup so                      \
		* DWT_START_RX_DELAYED isn't refused as "already past" (80 us was                  \
		* too tight -> arm_ok=0 in build12/13) */

/**
 * Arm the DW3000 radio to receive Final_Data in SP0 mode (data frame, not STS) at a delayed time
 * calculated from the Final frame's ideal arrival. Record margin metrics and adjust the open time
 * if it has already passed. Return 0 on success or -EIO if the arm fails.
 */
static int arm_final_data_sp0(uint32_t final_ip)
{
	uint32_t now;
	uint32_t dx = final_ip + CCC_FDRX_OPEN_HI32; /* ideal: just after the Final frame's tail */
	int r;

	/* Decompose THIS FINAL's dispatch latency (cyc; every stamp is from the FINAL's own IRQ —
	 * g_dw_cyc_cbentry, not g_dw_cyc_isrdone, which the drain loop has not restamped yet). */
	g_dbg_final_hop = g_dw_cyc_work - g_dw_cyc_gpio;
	g_dbg_final_isr = g_dw_cyc_cbentry - g_dw_cyc_work;
	g_dbg_final_cb = dw3000_dwt_cyccnt() - g_dw_cyc_cbentry;
	g_dbg_final_per_us = g_dw_cyc_per_us;

	dwt_forcetrxoff();
	dwt_configurestsmode((uint8_t)DWT_STS_MODE_OFF); /* SP0 — Final_Data is a data frame */
	now = dwt_readsystimestamphi32();
	/* Record how far the IDEAL open sits from now BEFORE clamping: a strongly negative margin
	 * means the callback ran so late that the ideal Final+100us window was already in the past
	 * (the Final_Data, if it lands that early, is physically unrecoverable by any re-arm). */
	g_dbg_fdrx_margin = (int32_t)(dx - now);
	if (g_dbg_fdrx_margin < (int32_t)CCC_FDRX_MIN_AHEAD) {
		dx = now +
		     CCC_FDRX_MIN_AHEAD; /* ideal open already past -> open as early as armable */
	}
	dwt_setdelayedtrxtime(dx);
	dwt_setrxtimeout(CCC_FDRX_WIN_TO);
	r = gated_rxenable(DWT_START_RX_DELAYED | DWT_IDLE_ON_DLY_ERR);
	if (r == DWT_SUCCESS) {
		g_dbg_fdrx_arm_ok++;
		return 0;
	}
	g_dbg_fdrx_arm_fail++;
	return -EIO;
}
#endif

/** @brief Dummy Response_0 body — NOT radiated (SP3/ND sends STS only), but the TX sequence writes
 * a frame body before dwt_starttx. */
static uint8_t g_resp_payload[4];

/** Delayed-TX the responder's Response_0 (SP3-ND) one slot after the POLL, at STS index
 * Poll_STS_Index + 1 (same dURSK, STS-V advances). */
static int tx_response_sp3(uint32_t poll_ip, uint32_t resp_idx)
{
	static uint32_t dbg_n;
	dwt_sts_cp_iv_t v;
	uint32_t dx, now;
	int r;
#if defined(CONFIG_DW3000_SPI_METRICS)
	struct dw3000_spi_metrics spi_before;

	dw3000_spi_metrics_get(&spi_before);
#endif

	/* NO KDF here — pack the Response STS committed at the arm (g_armed_resp_*); the derive
	 * already ran in the idle. resp_idx is only for the diagnostic print. */
	sts_key_load(g_armed_resp_dursk); /* same dURSK as the POLL round (ESP32/CDK: a no-op) */
	pack_iv(&v, g_armed_resp_sts_v);
#if defined(CONFIG_DW3000_STS_BULK_WRITE_EXPERIMENT)
	ultrawidelock_dw3000_write_sts_iv_bulk(&v.iv0);
#else
	dwt_configurestsiv(&v);   /* Response STS-V (index+1); the shim is us, load it directly */
#endif
	dwt_configurestsloadiv(); /* reset the HW STS counter to our V */
	/* STS mode stays SP3/ND (the POLL arm set it) — the Response is the same RFRAME. */
	/* RMARKER = POLL + (1 + responder index) negotiated slots, antenna-compensated. */
	dx = poll_ip + CCC_RESP_SLOT_HI32 +
	     (uint32_t)ULTRAWIDELOCK_RESPONDER_INDEX * CCC_SLOT_NOMINAL_HI32;
	dwt_setdelayedtrxtime(dx);
	dwt_writetxdata(sizeof(g_resp_payload), g_resp_payload, 0u);
	dwt_writetxfctrl(sizeof(g_resp_payload) + 2u, 0u, 1u); /* +FCS; ranging=1 (STS) */
	now = dwt_readsystimestamphi32();
	lat_record(&g_lat_resp, now - poll_ip); /* POLL RMARKER -> this TX arm */
	r = dwt_starttx(DWT_START_TX_DELAYED);
	if (dbg_n < 8u) {
		/* PROBE (removable): dx-now = margin to the programmed TX RMARKER (hi32/4 ns);
		 * negative => the target was already past (HPDWARN reject). */
		uint32_t ss = dwt_readsysstatuslo();

		DIAGK("RESPTX r=%d dx-now=%d(%dus) hpd=%u ss=%08x idx=%08x\n", r,
		      (int32_t)(dx - now), (int32_t)(dx - now) / 250,
		      (ss & DWT_INT_HPDWARN_BIT_MASK) ? 1u : 0u, (unsigned)ss, (unsigned)resp_idx);
		dbg_n++;
	}
#if defined(CONFIG_DW3000_SPI_METRICS)
	spi_phase_record(&g_spi_response_arm, &spi_before);
#endif
	return (r == DWT_SUCCESS) ? 0 : -EIO;
}

/** Arm the delayed SP3-ND RX for the phone's Final at STS index
 * Poll_STS_Index+ULTRAWIDELOCK_FINAL_SLOT_OFFSET, packing the g_armed_final_* STS (no KDF).
 *  EXPERIMENT-2RESP: the 1:1 baseline uses POLL + 2 slots / index+2; a 2-responder round puts the
 * Final at POLL + 3 (responder 1's silent slot sits at POLL + 2). */
static int arm_final_sp3(uint32_t poll_ip)
{
	static uint32_t dbg_n;
	dwt_sts_cp_iv_t v;
	uint32_t dx, now;
	int r;
#if defined(CONFIG_DW3000_SPI_METRICS)
	struct dw3000_spi_metrics spi_before;

	dw3000_spi_metrics_get(&spi_before);
#endif

	sts_key_load(g_armed_final_dursk); /* same per-cycle dURSK (ESP32/CDK: a no-op) */
	pack_iv(&v, g_armed_final_sts_v);
#if defined(CONFIG_DW3000_STS_BULK_WRITE_EXPERIMENT)
	ultrawidelock_dw3000_write_sts_iv_bulk(&v.iv0);
#else
	dwt_configurestsiv(&v);
#endif
	dwt_configurestsloadiv();
	dx = poll_ip +
	     ULTRAWIDELOCK_FINAL_SLOT_OFFSET *
		     CCC_RX_SLOT_HI32; /* EXPERIMENT-2RESP: Final RMARKER = POLL +
					  ULTRAWIDELOCK_FINAL_SLOT_OFFSET slots (n=1 -> +2, n=2 -> +3) */
	now = dwt_readsystimestamphi32();
	/* Response TX RMARKER (t3, stamped by the caller just before this arm) -> this RX arm. */
	lat_record(&g_lat_final, now - (uint32_t)(g_t_resp_tx >> 8));
	dwt_setdelayedtrxtime(dx - CCC_RX_POLL_LEAD);
	dwt_setrxtimeout(CCC_RX_POLL_WIN_TO);
	r = gated_rxenable(DWT_START_RX_DELAYED | DWT_IDLE_ON_DLY_ERR);
	if (dbg_n < 8u) {
		DIAGK("FINALARM r=%d dx-now=%d(%dus) idx=%08x\n", r,
		      (int32_t)((dx - CCC_RX_POLL_LEAD) - now),
		      (int32_t)((dx - CCC_RX_POLL_LEAD) - now) / 250,
		      (unsigned)(g_armed_index + ULTRAWIDELOCK_FINAL_SLOT_OFFSET)); /* EXPERIMENT-2RESP: n=1
									       -> +2, n=2 -> +3 */
		dbg_n++;
	}
#if defined(CONFIG_DW3000_SPI_METRICS)
	spi_phase_record(&g_spi_final_arm, &spi_before);
#endif
	return (r == DWT_SUCCESS) ? 0 : -EIO;
}

/** TX-done (TXFRS) callback: our Response_0 left the antenna, so arm the Final RX one slot later,
 * then run the block's deferred Pre-POLL decode in the idle. */
static void resp_tx_done(const dwt_cb_data_t *cb)
{
	static uint32_t g_resp_txn;

	fr_capture_ev((uint8_t)FR_EP_TX_DONE, cb != NULL ? cb->status : 0u,
		      cb != NULL ? (uint16_t)cb->datalength : 0u);

	if (g_resp_txn < 16u) {
		DIAGK("RESP txdone #%u idx=%08x\n", (unsigned)g_resp_txn,
		      (unsigned)(g_armed_index + 1u + ULTRAWIDELOCK_RESPONDER_INDEX));
		g_resp_txn++;
	}
#if defined(ESP_PLATFORM)
	/* ESP32: the POLL handler already armed the Final RFRAME RX synchronously (t3 read + arm),
	 * so this late-dispatching callback must NOT re-arm (it would tear down the pending Final
	 * RX). Just run the deferred decode below. */
	if (g_final_armed_sync) {
		g_final_armed_sync = false;
	} else
#endif
	{
		uint8_t txts[5] = {0};

		dwt_readtxtimestamp(txts); /* t3: responder Response TX (antenna plane) */
		g_t_resp_tx = ts5_to_u64(txts);
		if (arm_final_sp3(g_poll_ip_for_final) == 0) {
			g_await_final = true;
		} else {
			revert_to_sp0_listen();
		}
	}
	/* Deferred Pre-POLL decode (warms the NEXT block's STS). On ESP32/nRF5340 run it here.
	 * On the single-core CDK this KDF (3 STS derivations + a CCM decrypt, software AES) takes
	 * ~ms and this callback sits INSIDE the ~2 ms FINAL->Final_Data window, so running it here
	 * blocks the FINAL callback's re-arm on the shared workqueue and the Final_Data is missed.
	 * Moved to the FINAL callback there, AFTER the receiver is re-armed (see g_await_final). */
#if !defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
	if (g_pp_pending) {
		g_pp_pending = false;
		prepoll_decode(g_pp_stash, g_pp_stash_len);
	}
#endif
}

/**
 * @brief RX callback for Pre-POLL listen and POLL/Final results.
 *
 * Re-arms SP0 by default, or arms SP3/ND for POLL if a warmed index is ready, or fires the
 * delayed-TX Response_0 and Final RX arm on valid POLL CPER; logs free-running timing and
 * optionally defers Pre-POLL decode to warm the next block.
 */
static void prepoll_rx_rearm(const dwt_cb_data_t *cb)
{
	/* FREE-RUNNING TIMING+CONTENT DIAGNOSTIC (de-starved: re-arm first, log deferred): free-run
	 * and log each real frame's hardware Ipatov RX timestamp + delta, to validate the true
	 * slot/block timing. */
	static uint32_t prev_ip;
	static uint32_t g_cia;
	static uint32_t g_dumps;
	uint32_t st = (cb != NULL) ? cb->status : 0u;
	uint32_t ip = 0u;
	uint64_t ip40 = 0u;
	uint16_t len = 0u;
	uint8_t rng = 0u;
	bool is_pp = false;
	uint8_t b[CCC_MHR_LEN] = {0};

#if defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
	/* T2 of the hop/isr/cb decomposition: this event's own callback entry. First, so the cb
	 * bucket owns everything below, including the flight recorder. */
	g_dw_cyc_cbentry = dw3000_dwt_cyccnt();
#endif

	/* Flight recorder: record this RX-result callback + its register snapshot. */
	fr_capture_ev((uint8_t)FR_EP_RX_REARM, st, (cb != NULL) ? (uint16_t)cb->datalength : 0u);

	if ((st & DWT_INT_CIADONE_BIT_MASK) != 0u) {
		uint8_t tsb[5] = {0};

		dwt_readrxtimestamp_ipatov(tsb); /* hardware RX ts -- precise, CPU-independent */
		ip40 = ts5_to_u64(tsb);          /* full 40-bit DTU for DS-TWR */
		ip = (uint32_t)(ip40 >> 8);      /* bits[39:8] — the delayed-TRX / arm domain */
	}
	if ((st & DWT_INT_RXPHD_BIT_MASK) != 0u) {
		// CCC MAC header fields (source/dest addresses, frame control, sequence number).
		struct ccc_mhr_fields m;

		dwt_readrxdata(b, sizeof(b), 0u);
		len = dwt_getframelength(&rng);
		/* Arm only on a CLEANLY-received, GENUINE Pre-POLL: require RXFCG (good CRC) too,
		 * else a Final_Data sharing the Pre-POLL MHR framing fires a spurious arm. */
		is_pp = ((st & DWT_INT_RXFCG_BIT_MASK) != 0u && len >= (uint16_t)CCC_MHR_LEN &&
			 ccc_parse_mhr(b, &m) == 0 && m.msg_id == CCC_MSG_ID_PRE_POLL);
	}

#if defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
	/* POST-FINAL FATE: this is the first callback after a FINAL capture reverted to SP0.
	 * Nothing else is on air between the FINAL and the next block's Pre-POLL, so this event
	 * IS the Final_Data's fate. Errored (no RXFCG) => the frame arrived but our SP0 config
	 * rejected it (PHY-config fix); a clean next Pre-POLL => we never detected it (timing/
	 * delayed-RX fix). Parsing the MHR works even on a CRC-failed frame, so an errored
	 * Final_Data still reports msg_id 0x02. */
	if (g_postfinal_watch) {
		struct ccc_mhr_fields pfm;
		bool hdr = ((st & DWT_INT_RXPHD_BIT_MASK) != 0u) && len >= (uint16_t)CCC_MHR_LEN &&
			   ccc_parse_mhr(b, &pfm) == 0;

		g_postfinal_watch = false;
		g_dbg_pf_n++;
		g_dbg_pf_last_st = st;
		g_dbg_pf_last_msgid = hdr ? pfm.msg_id : 0xFEu;
		g_dbg_pf_dhi = (ip != 0u) ? (int32_t)(ip - g_postfinal_final_ip) : 0;
		if ((st & DWT_INT_RXFCG_BIT_MASK) == 0u) {
			g_dbg_pf_err++;
			if (hdr) {
				g_dbg_pf_err_hdr++;
				if (pfm.msg_id == CCC_MSG_ID_FINAL_DATA) {
					g_dbg_pf_err_final++;
				}
			}
		} else if (hdr && pfm.msg_id == CCC_MSG_ID_FINAL_DATA) {
			g_dbg_pf_final++;
		} else if (hdr && pfm.msg_id == CCC_MSG_ID_PRE_POLL) {
			g_dbg_pf_prepoll++;
		}
	}
#endif

	/* Re-arm. Default: keep listening in SP0. After a decoded Pre-POLL, arm the STS receiver
	 * (SP3/ND) for the POLL; while pending (g_await_poll) the next RX event is the POLL result.
	 */
	if (g_await_final) {
		unsigned cper = (st & 0x10000000u) ? 1u : 0u;
		int d = (ip != 0u) ? (int)(ip - g_poll_ip_for_final) : 0;
#if ULTRAWIDELOCK_NUM_RESPONDERS >= 2
		/* EXPERIMENT-2RESP: Final RFRAME arrival slot offset (Final RX - POLL RX in
		 * whole slots). Expect 3 if the phone accepted the 2-responder round, 2 if
		 * it fell back to 1 responder (in which case this arm at +3 misses it). */
		int d_slots =
			(ip != 0u) ? (int)((ip - g_poll_ip_for_final) / CCC_RX_SLOT_HI32) : -1;
#endif
		int16_t stsq = 0;
		int qret = 0;

		g_await_final = false;
		if (ip != 0u) {
			g_t_final_rx = ip40; /* t6: responder Final RX */
#if defined(ESP_PLATFORM) || defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
			/* Snapshot the responder-side DS-TWR intervals NOW, while t2/t3/t6 are all
			 * from this round; the Final_Data decode (which lands after the next round
			 * has overwritten the live timestamp globals) consumes these. On the
			 * dual-core nRF5340 the decode recomputes from the live globals directly
			 * (no snapshot needed). */
			g_final_reply1 = (uint32_t)(g_t_resp_tx - g_t_poll_rx);
			g_final_round2 = (uint32_t)(g_t_final_rx - g_t_resp_tx);
			g_final_round_valid = true;
#if defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
			g_dbg_capture_n++;
#endif
#endif
			qret = dwt_readstsquality(&stsq, 0);
			/* Range-integrity gate (layer 2): stash this Final RFRAME's STS
			 * verdict for the Final_Data decode that computes the distance. */
			g_final_sts_verdict = (cper == 0u) ? qret : -1;
			g_final_sts_index = stsq;
			g_final_evidence_index =
				g_armed_index + ULTRAWIDELOCK_FINAL_SLOT_OFFSET;
			g_final_evidence_poll_index = g_armed_index;
			g_final_evidence_valid = g_have_session_block;
		}
		/* Time-critical FIRST: revert to SP0 and re-open RX before the (blocking) UART
		 * print, so the phone's SP0 Final_Data (~1 slot behind this Final) lands in our
		 * window instead of while the log drains. Mirrors the POLL handler, which arms the
		 * Response before its printk. The print is throttled to the first
		 * CCC_RX_PREPOLL_LOG rounds so the steady-state callback is print-free: a per-round
		 * printk here blocks the ISR task ~ms, backing up dispatch (missed Final_Data) and
		 * tripping the wdt. */
#if defined(CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT)
		/* CDK: schedule a delayed SP0 RX at the Final_Data slot rather than re-arming
		 * immediately (the immediate re-arm is blind through the Final_Data — see
		 * arm_final_data_sp0). Fall back to the immediate listen if the Final ts is missing
		 * or the delayed arm is refused, so the next Pre-POLL is never lost. */
		if (ip == 0u || arm_final_data_sp0(ip) != 0) {
			revert_to_sp0_listen();
		}
		/* The next callback is the Final_Data's fate — latch it (post-FINAL diagnostic). */
		g_postfinal_final_ip = ip;
		g_postfinal_watch = true;
		/* Warm the next block's STS NOW — AFTER the SP0 receiver is re-armed above, not in
		 * resp_tx_done (which sits before the FINAL and blocked this callback's re-arm).
		 * The receiver is listening in hardware, so the Final_Data ~2 ms out is captured
		 * even while this ~ms software KDF (3 STS derivations + a CCM decrypt) runs; its
		 * decode just queues behind us. ~190 ms of slack remains before the next block
		 * needs the warm. */
		if (g_pp_pending) {
			g_pp_pending = false;
			prepoll_decode(g_pp_stash, g_pp_stash_len);
		}
#else
		revert_to_sp0_listen();
#endif
		if (g_pp_logged < CCC_RX_PREPOLL_LOG) {
#if ULTRAWIDELOCK_NUM_RESPONDERS >= 2
			/* Final result (DS-TWR leg 3): cper=0 => the idx+3 STS correlated; ip is
			 * the responder's third timestamp, d = Final - POLL. */
			DIAGK("FINAL result st=%08x cper=%u ip=%08x d=%d(%dus) slots=%d stsq=%d/%d "
			      "idx=%08x\n",
			      (unsigned)st, cper, (unsigned)ip, d, d / 250, d_slots, (int)stsq,
			      qret, (unsigned)(g_armed_index + ULTRAWIDELOCK_FINAL_SLOT_OFFSET));
#else
			/* Final result (DS-TWR leg 3): cper=0 => the idx+2 STS correlated; ip is
			 * the responder's third timestamp, d = Final - POLL ~= 2 slots. */
			DIAGK("FINAL result st=%08x cper=%u ip=%08x d=%d(%dus) stsq=%d/%d "
			      "idx=%08x\n",
			      (unsigned)st, cper, (unsigned)ip, d, d / 250, (int)stsq, qret,
			      (unsigned)(g_armed_index + ULTRAWIDELOCK_FINAL_SLOT_OFFSET));
#endif
		}
	} else if (g_await_poll) {
		unsigned cper = (st & 0x10000000u) ? 1u : 0u;
		int d = (ip != 0u) ? (int)(ip - g_prepoll_ip) : 0;
		int16_t stsq = 0;
		int qret = 0;
		int tr = -1;
		bool ours;

		g_await_poll = false;
		/* Evaluate ONCE, here: ccc_block_is_ours() reads g_pp_pending, which
		 * resp_tx_done clears as soon as the Response TX completes, so a second
		 * call further down would not agree with the one that made the decision. */
		ours = ccc_block_is_ours();
		/* Time-critical FIRST: arm Response_0's delayed TX before the stsq read and
		 * ultrawidelock_printf. cper=0 => real POLL, so delayed-TX Response_0 (index+1); else return
		 * to the SP0 listen.
		 *
		 * Under block-parity alternation the partner anchor owns the other blocks.
		 * Leaving tr = -1 on theirs falls through to exactly the path a non-POLL
		 * takes, and the whole ranging leg fails closed behind it: no Response TX
		 * means resp_tx_done never runs, so g_await_final stays false, so the Final
		 * handler never latches a capture, so Final_Data finds no fresh round and
		 * computes no distance. A silent block therefore produces no range at all
		 * rather than a stale-timestamp one, which is what keeps the layer-4 trust
		 * run intact across it. */
		if (cper == 0u && ip != 0u && ours) {
			g_poll_ip_for_final = ip; /* round anchor for the Final RX arm (TXDONE) */
			g_t_poll_rx = ip40;       /* t2: responder POLL RX */
			tr = tx_response_sp3(ip, g_armed_index + 1u + ULTRAWIDELOCK_RESPONDER_INDEX);
#if defined(ESP_PLATFORM)
			/* ESP32: the TX-done callback (resp_tx_done) dispatches too late and too
			 * jittery (~2-16 ms) to arm the Final RFRAME, which sits only ~2 ms after
			 * the Response TX. Arm it SYNCHRONOUSLY here: spin for TXFRS (the delayed
			 * Response TX completes ~0.8-1 ms out; at task prio 23 this spin isn't
			 * descheduled), read t3, then arm. The DW3000 latches the Final RX
			 * timestamp in HW, so the (late) g_await_final callback still reads a
			 * correct t6. */
			if (tr == 0) {
				uint32_t spin;

				for (spin = 0u; spin < CCC_RESP_TXFRS_SPIN; spin++) {
					if ((dwt_readsysstatuslo() & DWT_INT_TXFRS_BIT_MASK) !=
					    0u) {
						break;
					}
				}
				if ((dwt_readsysstatuslo() & DWT_INT_TXFRS_BIT_MASK) != 0u) {
					uint8_t txts[5] = {0};

					dwt_readtxtimestamp(txts); /* t3: Response TX (antenna) */
					g_t_resp_tx = ts5_to_u64(txts);
					g_final_armed_sync = true; /* resp_tx_done: skip re-arm */
					if (arm_final_sp3(g_poll_ip_for_final) == 0) {
						/* Final RX armed synchronously, right after the
						 * Response TXFRS (prompt, in-handler — this is the
						 * part that works). Hand the CAPTURE to the async
						 * g_await_final path: it reads t6 and reverts to
						 * SP0. Do NOT busy-wait for the Final here — that
						 * spin runs inside dwt_isr and races its status
						 * handling; it wedged the receiver / tripped the
						 * watchdog and never once caught the Final (the
						 * SP3-ND completion lands after this handler
						 * returns). */
						g_await_final = true;
					} else {
						revert_to_sp0_listen();
					}
				}
			}
#endif
		}
		if (tr != 0) {
			revert_to_sp0_listen();
		}
		/* else: stay SP3/ND; resp_tx_done arms the Final RX, then reverts to SP0. */

		/* Deferred diagnostics (off the TX critical path), throttled to the first
		 * CCC_RX_PREPOLL_LOG rounds so the steady-state callback stays print-free (a
		 * per-round printk blocks the ISR task ~ms, delaying dispatch). stsq splits the
		 * cper=1 cause (low = key/IV wrong, high-but-clipped = saturation). */
		if (g_pp_logged < CCC_RX_PREPOLL_LOG) {
			if (ip != 0u) {
				qret = dwt_readstsquality(&stsq, 0);
			}
			DIAGK("POLL result st=%08x cper=%u d=%d(%dus) stsq=%d/%d idx=%08x resp=%s "
			      "dec=%dus\n",
			      (unsigned)st, cper, d, d / 250, (int)stsq, qret,
			      (unsigned)g_armed_index,
			      (cper != 0u || ip == 0u) ? "-"
			      : !ours                  ? "skip" /* partner anchor's block */
			      : (tr == 0)              ? "armed"
						       : "FAIL",
			      (int)(g_ccc_dbg_decode / 250u));
		}

		/* Deferred Pre-POLL decode (warms the NEXT block's STS): on a Response-sent block
		 * resp_tx_done runs it; otherwise run it here in the idle. */
		if (tr != 0 && g_pp_pending) {
			g_pp_pending = false;
			prepoll_decode(g_pp_stash, g_pp_stash_len);
		}
	} else if (is_pp && g_warm_valid && ip != 0u && g_warm_index != g_armed_index) {
		/* Arm the POLL window on the PREDICTED next index (warmed a block ago), one arm per
		 * index; mark it before arming so a re-detected Pre-POLL can't re-arm late. */
		g_armed_index = g_warm_index;
		if (arm_poll_sp3(ip) == 0) {
			g_await_poll = true; /* SP3 armed; do not re-arm SP0 */
		} else {
			dwt_setrxtimeout(0u);
			(void)gated_rxenable(DWT_START_RX_IMMEDIATE);
		}
	} else {
		dwt_setrxtimeout(0u);
		(void)gated_rxenable(DWT_START_RX_IMMEDIATE);
	}

	if (ip != 0u && g_cia < 64u) {
		DIAGK("cia#%u ip=%08x dip=%d st=%08x len=%u%s\n", (unsigned)g_cia, (unsigned)ip,
		      (int)(ip - prev_ip), (unsigned)st, (unsigned)len,
		      is_pp ? " <<49 2b PRE-POLL>>" : "");
		g_cia++;
	}
	if (ip != 0u) {
		prev_ip = ip;
	}
	if ((st & DWT_INT_RXPHD_BIT_MASK) != 0u && g_dumps < 16u) {
		/* Cap the dump (was unbounded on every is_pp): the per-block phd flood backs up the
		 * workqueue, delaying the Pre-POLL callback. A fixed cap suffices. */
		DIAGK("  phd%s %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x "
		      "%02x%02x%02x%02x\n",
		      is_pp ? " <<49 2b>>" : "", b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		      b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
		g_dumps++;
	}
}

/** Sync (preamble) code to listen on for the SP0 Pre-POLL: 9, read from the phone's plaintext M4
 * (07 01 09 = SYNC_Code_Index=9). */
#define CCC_RX_PREPOLL_CODE 9u

/* PHY-config cache: dwt_configure is the long pole of session start, and every credential
 * session negotiates the same PHY in practice (the reader's M1 offers exactly one
 * config). Remember what was last applied, keyed to the radio-init generation so a
 * re-probe/reset invalidates it, and skip the reconfigure when identical.
 * ccc_prepoll_prewarm() lets the reader apply the expected PHY while the phone is
 * still deciding to Initiate-Ranging-Session, off the M4 critical path. */
static uint8_t g_phy_chan;
static uint8_t g_phy_code;
static uint32_t g_phy_gen;
static bool g_phy_valid;

/* Radio init + forcetrxoff + (cached) dwt_configure. Session-start context only —
 * never the RX re-arm path. */
static int prepoll_apply_phy(uint8_t channel, uint8_t preamble_code)
{
	dwt_config_t cfg = {
		.chan = channel,
		/* PHY: CCC negotiates one PHY set per session, shared by SP0 (Pre-POLL) and SP3
		   (POLL). Config 0 (cfg=0000) pins the default preamble at 64 symbols, so the set
		   is plen64 + the phone's SYNC_Code_Index (code 9). */
		.txPreambLength = DWT_PLEN_64,
		.rxPAC = DWT_PAC8,
		.txCode = CCC_RX_PREPOLL_CODE,
		.rxCode = CCC_RX_PREPOLL_CODE,
		.sfdType = DWT_SFD_IEEE_4A, /* Config 0000 SFD = ternary 8-sym (4a), not 4z; 4z
					       SFD-timed-out every phone frame */
		.dataRate = DWT_BR_6M8,     /* Pre-POLL PSDU @ 6.81 Mbps */
		.phrMode = DWT_PHRMODE_STD,
		.phrRate = DWT_PHRRATE_STD,  /* Pre-POLL PHR @ 850 kbps */
		.sfdTO = 64 + 1,             /* numeric preamble length + 1 */
		.stsMode = DWT_STS_MODE_OFF, /* SP0 — data frame, PHR+payload, no STS */
		.stsLength = DWT_STS_LEN_64,
		.pdoaMode = DWT_PDOA_M0,
	};
	int rc = uwb_min_radio_init();

	if (rc != 0) {
		DIAGK("prepoll_listen: radio init failed (%d)\n", rc);
		return rc;
	}
	dwt_forcetrxoff();
	if (g_phy_valid && g_phy_gen == uwb_min_radio_generation() && g_phy_chan == channel &&
	    g_phy_code == preamble_code) {
		DIAGK("prepoll: PHY cached (ch=%u code=%u) — dwt_configure skipped\n",
		      (unsigned)channel, (unsigned)preamble_code);
		return 0;
	}
	if (ultrawidelock_uwb_configure_phy(&cfg) != DWT_SUCCESS) {
		DIAGK("prepoll_listen: dwt_configure failed\n");
		g_phy_valid = false;
		return -EIO;
	}
	g_phy_chan = channel;
	g_phy_code = preamble_code;
	g_phy_gen = uwb_min_radio_generation();
	g_phy_valid = true;
	return 0;
}

/* Pre-apply the expected session PHY ahead of M4. Leaves the radio configured with
 * TRX off: no callbacks are (re)installed and RX is not enabled, so nothing can fire
 * until ccc_prepoll_listen() arms the listener. */
int ccc_prepoll_prewarm(uint8_t channel, uint8_t preamble_code)
{
	return prepoll_apply_phy(channel, preamble_code);
}

// Initialize the DW3000 radio for permanent SP0 Pre-POLL listen: configure PHY (6.8 Mbps, preamble
// length 64, SFD 4a, no STS), install RX callbacks that self-rearm on every frame outcome, and
// enable all RX/TX interrupts; returns 0 on success.
int ccc_prepoll_listen(uint8_t channel, uint8_t preamble_code)
{
	dwt_callbacks_s cbs = {
		.cbRxOk = prepoll_rx_rearm,
		.cbRxTo = prepoll_rx_rearm,
		.cbRxErr = prepoll_rx_rearm,
		.cbTxDone = resp_tx_done, /* Response_0 TXFRS -> revert to SP0 listen */
	};
	int rc = prepoll_apply_phy(channel, preamble_code);

	if (rc != 0) {
		return rc;
	}
	/* Permanent listen: no RX timeout; the callbacks self-re-arm so a missed/errored frame
	 * doesn't stop the search for the next Pre-POLL. */
	dwt_setrxtimeout(0u);
	/* the rxdiag shim inserts shim_rxok -> ccc_shim_rx_try_prepoll ahead of these */
	ultrawidelock_uwb_set_callbacks(&cbs);
	dwt_setinterrupt(DWT_INT_RXFCG_BIT_MASK | DWT_INT_RXFCE_BIT_MASK | DWT_INT_RXFTO_BIT_MASK |
				 DWT_INT_RXPTO_BIT_MASK | DWT_INT_RXPHE_BIT_MASK |
				 DWT_INT_RXSTO_BIT_MASK | DWT_INT_RXFSL_BIT_MASK |
				 DWT_INT_ARFE_BIT_MASK |
				 DWT_INT_TXFRS_BIT_MASK, /* Response_0 TX-done -> resp_tx_done */
			 0u, DWT_ENABLE_INT);
	ccc_shim_rx_log_reset();
	DIAGK("prepoll_listen: SP0 RX up (ch=%u code=%u plen64 sts=off; sp0code=%u) — listening "
	      "for Apple Pre-POLL\n",
	      (unsigned)channel, (unsigned)CCC_RX_PREPOLL_CODE, (unsigned)preamble_code);
	g_listen_gate = true; /* reopen the listen-gate a prior ccc_prepoll_stop() closed */
	/* Plain SP0 listen: no STS is armed for this window, so bypass the CCC arm. */
	(void)dwt_rxenable(DWT_START_RX_IMMEDIATE);
	return 0;
}

/* Stop the permanent Pre-POLL listener: close the listen-gate (every self-rearm
 * site checks it via gated_rxenable), then force the radio out of RX/TX.  The
 * DW3000 callbacks run on the dedicated coop (-11) isr workqueue with
 * busy-polled SPI and synchronous ultrawidelock_printf, so a callback never yields
 * mid-flight: one in flight when a preemptive-thread caller gets here has
 * already run to completion (its rearm landed BEFORE our forcetrxoff), and any
 * later callback sees the gate closed.  A residual rearm window exists only if
 * this is ever called from an ISR or a coop thread at prio <= -11. */
void ccc_prepoll_stop(void)
{
	/* Per-session PHY freshness: drop the cache on every stop so the next
	 * session's dwt_configure (and its RX calibration) runs exactly once, at
	 * prewarm time, never on the M4 critical path. RAM-only, so it is safe
	 * even when the early-return below skips the SPI work. */
	g_phy_valid = false;
	if (g_listen_gate) {
		g_listen_gate = false; /* order matters: close the gate, then kill RX */
		dwt_forcetrxoff();
	}
	/* Then put the part down, and do it whether or not a listener was up.
	 *
	 * The early return this replaced covered "never started or already
	 * stopped -- the driver may be unprobed, so no SPI", and that case is the
	 * one that mattered most: ultrawidelock_ranging_init() probes the radio at boot
	 * and stops without ever listening, so a board that no phone had come
	 * near still sat in IDLE_PLL at 18 mA from power-on. That was the largest
	 * single term on the board and it was being paid by every board, always.
	 *
	 * The no-SPI-when-unprobed guarantee has not been dropped, only moved:
	 * uwb_min_sleep() checks the radio is initialised before it touches the
	 * bus, which is the same test the early return was making. */
	uwb_min_sleep();
}

bool ccc_prepoll_listening(void)
{
	return g_listen_gate;
}
#endif /* ULTRAWIDELOCK_CCC_PREPOLL_LISTEN */
