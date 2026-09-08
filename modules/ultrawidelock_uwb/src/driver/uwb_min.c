/* SPDX-License-Identifier: ISC */

/** @file uwb_min.c — DW3110 bring-up driver (implementation). */

#include "uwb_min.h"

#include <errno.h>
#include <string.h>
#include "ultrawidelock_port.h"
#include "ultrawidelock_log.h"

/* dwt_uwb_driver public headers; the include is unprefixed. */
#include <deca_device_api.h>
#include <deca_probe_interface.h>
#include <dw3000_hw.h>
#include <dw3000_spi.h>

/* ultrawidelock_uwb_arm_rx / _set_sts_iv / _configure_phy — the engine's seam */
#include "uwb_seam.h"

LOG_MODULE_REGISTER(uwb_min, LOG_LEVEL_INF);

/* Idempotent-init flags: g_probed covers the chipid path, g_radio_ready the radio path.
 * g_radio_generation counts fresh radio inits so PHY-config caches upstream can tell
 * when the base dwt_configure ran again underneath them. */
static uint32_t g_radio_generation;
static bool g_probed;
static bool g_radio_ready;

/* DEEPSLEEP parameters: armed at init and re-armed before EVERY entry.
 *
 * The SDK is explicit that SLEEP_EN self-clears on wake (deca_device_api.h,
 * DWT_PRES_SLEEP), so one boot-time dwt_configuresleep() covers exactly one
 * sleep. The second dwt_entersleep() then saved the AON array with SLEEP_EN
 * clear, the part stayed in IDLE_PLL with its OTP left in low-power mode, and
 * the next "wake" toggled CS at an awake chip and spun for an IDLE_RC flag
 * that never came: "WAKEUP: chip never reached IDLE_RC" on every session after
 * the first, and no Pre-POLL ever received. DWT_PRES_SLEEP is what the SDK's
 * own sleep examples pass; re-arming is the belt to its braces. */
#define UWB_SLEEP_MODE (DWT_CONFIG | DWT_GOTOIDLE | DWT_RUNSAR)
#define UWB_SLEEP_WAKE (DWT_PRES_SLEEP | DWT_WAKE_CSN | DWT_SLP_EN)

/** @brief Bring the SDK up to "probed" state on first call; no-op afterwards.
 *
 * The whole reset -> wake -> probe sequence is retried: transient SPI/power
 * glitches (bench-seen as a burst of dwt_probe -1 during post-commissioning
 * Wi-Fi traffic, self-recovering on the caller's next attempt) clear on a
 * fresh chip reset, so retrying here turns a failed session start into a
 * slightly slower one. */
static int uwb_probe_ensure(void)
{
	if (g_probed) {
		return 0;
	}

	dw3000_hw_init();

	for (int attempt = 1; attempt <= 3; attempt++) {
		dw3000_hw_reset();
		/* Datasheet: ~2 ms wakeup latency after reset; 5 ms gives margin. */
		ultrawidelock_sleep_ms(5);

		/* Wake the DW3000 and settle it BEFORE the SDK probe. The SDK's dwt_probe reads
		 * the device id immediately after its own CS-toggle wakeup with no delay, so on a
		 * cold chip that read lands inside the ~2 ms wakeup latency and returns 0 -> the
		 * probe fails. Prime the wakeup here and poll the raw DEV_ID (register 0) until it
		 * reads valid, so the chip is definitely awake when dwt_probe runs. The logged
		 * value also diagnoses a genuine comms failure: 0x00000000 = MISO low / unpowered /
		 * held in reset (check the EVB power jumper); 0xFFFFFFFF = MISO floating / no chip;
		 * other non-DECA = wrong SPI pins/mode.
		 *
		 * One more signature, because it looks like none of the above and cost a bench
		 * session to name: a value that reconstructs to the real DEV_ID under a one-bit
		 * right shift, carrying each byte's LSB into the next byte's MSB. On nRF5340 that
		 * is 0x6fe50101, and it means SPIM4 sampled MISO a clock early because HFCLKCTRL
		 * is DIV_2. SPIM4's sample point is derived from HFCLK, so the fix is the clock
		 * divider, not the SPI config -- the pins, mode, frequency and RXDELAY all read
		 * correct while this happens. See the initiator app's hfclk_div_fixup(). */
		uint32_t raw_devid = 0u;

		for (int i = 0; i < 5; i++) {
			dw3000_spi_wakeup();
			ultrawidelock_sleep_ms(2); /* > DW3000 wakeup latency */
			uint8_t devid_hdr = 0x00;
			uint8_t devid_buf[4] = {0};

			dw3000_spi_read(1, &devid_hdr, sizeof(devid_buf), devid_buf);
			raw_devid = ((uint32_t)devid_buf[3] << 24) |
				    ((uint32_t)devid_buf[2] << 16) | ((uint32_t)devid_buf[1] << 8) |
				    (uint32_t)devid_buf[0];
			if ((raw_devid & 0xFFFFFF00u) == 0xDECA0300u) {
				break;
			}
		}
		LOG_INF("DW3000 raw DEV_ID = 0x%08x (expect 0xDECA03xx)", raw_devid);

		// Struct type passed to dwt_probe to initialize the DW3000 device; contains
		// platform-specific probe parameters.
		int err = dwt_probe((struct dwt_probe_s *)&dw3000_probe_interf);
		if (err == DWT_SUCCESS) {
			g_probed = true;
			return 0;
		}
		/* ERR so the DEV_ID diagnosis survives a WARN-level console (the INF
		 * line above does not). */
		LOG_ERR("dwt_probe failed (attempt %d/3): %d, raw DEV_ID=0x%08x", attempt, err,
			raw_devid);
		ultrawidelock_sleep_ms(10 * attempt);
	}
	return -EIO;
}

/** @brief Default radio configuration (channel 9, 6.8 Mbps). */
static const dwt_config_t g_uwb_cfg = {
	.chan = 9,
	.txPreambLength = DWT_PLEN_128,
	.rxPAC = DWT_PAC8,
	/* Preamble code 11: a compatible baseline; the responder reconfigures per the ranging
	   config. */
	.txCode = 11,
	.rxCode = 11,
	/* SP3 static STS uses the IEEE 802.15.4z 8-bit binary SFD, not the legacy Decawave pattern.
	 */
	.sfdType = DWT_SFD_IEEE_4Z,
	.dataRate = DWT_BR_6M8,
	.phrMode = DWT_PHRMODE_STD,
	.phrRate = DWT_PHRRATE_STD,
	.sfdTO = (129 + 8 - 8), /* preamble + SFD - PAC, per Qorvo formula */
	/* SP3 framing (STS-no-data) without the SDC bit. */
	.stsMode = DWT_STS_MODE_ND,
	.stsLength = DWT_STS_LEN_64,
	.pdoaMode = DWT_PDOA_M0,
};

/** @brief Default TX power / pulse-shaper config (channel 9). */
static const dwt_txconfig_t g_uwb_txcfg = {
	.PGdly = 0x34,
	.power = 0xfdfdfdfdUL,
	.PGcount = 0,
};

#if defined(CONFIG_ULTRAWIDELOCK_UWB_DEEPSLEEP)
/** @brief After a wake: prove the part answers, then restore what the AON block
 * does not. Returns 0 when the radio is usable again.
 *
 * The SDK's contract (ull_restore_common / ull_restore_txrx) is that every
 * DEEPSLEEP wake is followed by dwt_restoreconfig(): it puts the OTP back into
 * normal mode after dwt_entersleep() parked it in low-power mode, reprograms
 * the LDO and bias tune from OTP, and re-locks the PLL. None of that survives
 * in the AON array. The first wake after boot got away without it; the
 * second did not. */
static int uwb_wake_restore(void)
{
	uint32_t id = dwt_readdevid();

	if ((id & 0xFFFFFF00u) != 0xDECA0300u) {
		LOG_ERR("wake: DEV_ID 0x%08x, the part did not come back", (unsigned)id);
		return -EIO;
	}
	if (dwt_restoreconfig(DWT_RESTORE_TXRX_MODE) != DWT_SUCCESS) {
		LOG_ERR("wake: dwt_restoreconfig failed");
		return -EIO;
	}
	return 0;
}
#endif

/** @brief Bring the SDK up to "radio configured + LEDs on" state. */
static int uwb_radio_ensure_init(void)
{
	/* WAKE FIRST, BEFORE THE EARLY RETURN. A part in DEEPSLEEP has all its
	 * clocks off and answers SPI with nothing, so the wake cannot sit behind
	 * the g_radio_ready fast path -- that path is exactly the one a second
	 * session takes. Every route into the radio comes through here, which is
	 * why uwb_min_sleep() has no public counterpart: waking is not a decision
	 * a caller is trusted to remember.
	 *
	 * Free when the part is awake: dw3000_hw_wakeup() returns immediately
	 * unless dw3000_hw_mark_asleep() said otherwise, and toggling CS at an
	 * awake chip would corrupt the next transfer, which is why that guard is
	 * in the port rather than here. */
#if defined(CONFIG_ULTRAWIDELOCK_UWB_DEEPSLEEP)
	const bool was_asleep = dw3000_hw_is_asleep();
#endif
	dw3000_hw_wakeup();

#if defined(CONFIG_ULTRAWIDELOCK_UWB_DEEPSLEEP)
	if (was_asleep && g_radio_ready && uwb_wake_restore() != 0) {
		/* The part is not a configured radio any more. Rather than hand a
		 * dead receiver to the session (the phone gives up after its
		 * 30 s deadline), rebuild it from a hard reset: the same path a
		 * cold boot takes, and the one dwt_probe's own retry loop is built
		 * around. Costs a few ms, saves the walk-up. */
		LOG_WRN("wake: rebuilding the radio from reset");
		(void)uwb_min_hw_reset();
	}
#endif

	if (g_radio_ready) {
		return 0;
	}

	int err = uwb_probe_ensure();
	if (err) {
		return err;
	}

	if (dwt_initialise(DWT_DW_INIT) != DWT_SUCCESS) {
		LOG_ERR("dwt_initialise failed");
		return -EIO;
	}

	if (ultrawidelock_uwb_configure_phy((dwt_config_t *)&g_uwb_cfg) != DWT_SUCCESS) {
		LOG_ERR("PHY configure failed");
		return -EIO;
	}

	dwt_configuretxrf((dwt_txconfig_t *)&g_uwb_txcfg);

	/* Configure sleep/wake: restore config + go to IDLE_PLL on wake, wake on chip-select,
	 * re-run SAR. uwb_min_sleep() re-arms the same pair before every entry. */
	dwt_configuresleep(UWB_SLEEP_MODE, UWB_SLEEP_WAKE);

	/* INIT_BLINK | ENABLE: flash both LEDs once at setup to verify the LED lines.
	 *
	 * DISABLE costs more than it looks like it saves, which is why it is a
	 * config and not a deletion. ENABLE does not merely point GPIO2/GPIO3 at
	 * the RXLED/TXLED functions: it also sets CLK_CTRL_GPIO_DCLK_EN and
	 * CLK_CTRL_LP_CLK_EN, so the DW3110 runs a de-bounce clock and its
	 * low-power oscillator for the sole purpose of blinking. On a mains bench
	 * board that is the only outward sign the radio is alive and worth every
	 * microamp; on a battery it is two clocks and an LED bought with nothing.
	 *
	 * These are the RADIO's LEDs, not the board's four on the nRF52833 --
	 * CONFIG_ULTRAWIDELOCK_STATUS_LED governs those, on a different chip. Turning
	 * that one off and expecting this one to follow is a mistake worth
	 * spending three lines to prevent. */
#if defined(CONFIG_ULTRAWIDELOCK_UWB_LEDS)
	dwt_setleds(DWT_LEDS_ENABLE | DWT_LEDS_INIT_BLINK);
#else
	dwt_setleds(DWT_LEDS_DISABLE);
#endif

	/* Wire the chip's IRQ line into Zephyr's GPIO framework so RX/TX events reach our
	 * callbacks. */
	(void)dw3000_hw_init_interrupt();

	g_radio_ready = true;
	g_radio_generation++;
	return 0;
}

int uwb_min_radio_init(void)
{
	return uwb_radio_ensure_init();
}

/*
 * Path-A sleep entry: the half dw3000_hw.h named and nobody wrote.
 *
 * The wake half has been complete and registered the whole time --
 * dw3000_hw_wakeup() drives CS low, waits out the IDLE_RC startup and spins on
 * dwt_checkidlerc(), and deca_port.c binds it as .wakeup_device_with_io -- and
 * uwb_radio_ensure_init() above has always armed the sleep PARAMETERS with
 * dwt_configuresleep(..., DWT_WAKE_CSN | DWT_SLP_EN). Only the one call that
 * actually puts the part under was missing, so the DW3110 rested in IDLE_PLL
 * from boot for the life of every board: 18 mA against 260 nA in DEEPSLEEP
 * (DW3000 Datasheet v1.3, Figures 26 and 28, all supplies at 3.0 V), on a lock
 * whose radio is wanted for a few seconds a day.
 *
 * DWT_DW_IDLE_RC, NOT DWT_DW_IDLE, and the two halves have to agree. It clears
 * the auto-INIT2IDLE bit before sleeping so the part wakes into IDLE_RC with
 * the PLL still off; the SDK recommends it for wake speed, and more to the
 * point dw3000_hw_wakeup() already spins on dwt_checkidlerc() waiting for
 * exactly that state. Sleeping with DWT_DW_IDLE would wake into IDLE_PLL and
 * leave the wake spinning to its 5 ms timeout on every session.
 *
 * Nothing here depends on the PHY surviving the sleep: ccc_prepoll_stop()
 * drops the g_phy_valid cache on every stop, so the next prewarm re-runs
 * dwt_configure regardless of what the AON restored.
 */
void uwb_min_sleep(void)
{
#if defined(CONFIG_ULTRAWIDELOCK_UWB_DEEPSLEEP)
	/* An unprobed driver must not be touched over SPI, and a part that is
	 * already down must not be told twice. */
	if (!g_radio_ready || dw3000_hw_is_asleep()) {
		return;
	}
	/* IDLE first. Sleep entry from RX or TX is undefined, and the caller
	 * only forces TRX off when a listener was up. Idempotent on an idle part. */
	dwt_forcetrxoff();
	/* Re-arm: SLEEP_EN self-cleared on the previous wake (see UWB_SLEEP_WAKE),
	 * so without this the AON save below would not put the part down at all. */
	dwt_configuresleep(UWB_SLEEP_MODE, UWB_SLEEP_WAKE);
	dwt_entersleep(DWT_DW_IDLE_RC);
	dw3000_hw_mark_asleep();
#endif
}

uint32_t uwb_min_radio_generation(void)
{
	return g_radio_generation;
}

int uwb_min_hw_reset(void)
{
	/* Drive the SDK's reset routine (routed through the platform glue). */
	dw3000_hw_reset();
	ultrawidelock_sleep_ms(5);

	/* Force a re-probe and re-init after reset (the SDK's fn-pointer table gets cleared). */
	g_probed = false;
	g_radio_ready = false;
	return 0;
}

int uwb_min_read_chipid(uint32_t *id_out)
{
	if (id_out == NULL) {
		return -EINVAL;
	}

	int err = uwb_probe_ensure();
	if (err) {
		return err;
	}

	*id_out = dwt_readdevid();
	return 0;
}

/* Status-bit masks for clearing after each phase; kept minimal to avoid stomping unrelated bits. */
#define TX_STATUS_CLEAR_MASK                                                                       \
	(DWT_INT_TXFRS_BIT_MASK | DWT_INT_TXPHS_BIT_MASK | DWT_INT_TXPRS_BIT_MASK |                \
	 DWT_INT_TXFRB_BIT_MASK)

#define RX_STATUS_EVENT_MASK                                                                       \
	(DWT_INT_RXFCG_BIT_MASK | DWT_INT_RXFCE_BIT_MASK | DWT_INT_RXFTO_BIT_MASK |                \
	 DWT_INT_RXPTO_BIT_MASK | DWT_INT_RXPHE_BIT_MASK | DWT_INT_RXSTO_BIT_MASK |                \
	 DWT_INT_RXFSL_BIT_MASK | DWT_INT_ARFE_BIT_MASK)

int uwb_min_selftest(struct uwb_selftest_result *out)
{
	if (out == NULL) {
		return -EINVAL;
	}

	memset(out, 0, sizeof(*out));

	int err = uwb_radio_ensure_init();
	if (err) {
		return err;
	}

	/* ── TX phase ─────────────────────────────────────────────── */

	/* Short ASCII payload; the SDK appends the 16-bit FCS, so the length is data_len + 2. */
	static const uint8_t payload[] = {'Z', 'I', 'O', 'N', 'U', 'W', 'B'};
	const uint16_t frame_len = sizeof(payload) + 2; /* +FCS */

	if (dwt_writetxdata(sizeof(payload), (uint8_t *)payload, 0) != DWT_SUCCESS) {
		LOG_ERR("dwt_writetxdata failed");
		return -EIO;
	}
	/* ranging=1 tags the frame as a ranging frame; harmless for the self-test. */
	dwt_writetxfctrl(frame_len, 0, 1);

	if (dwt_starttx(DWT_START_TX_IMMEDIATE) != DWT_SUCCESS) {
		LOG_ERR("dwt_starttx failed");
		return -EIO;
	}

	/* Poll SYS_STATUS for TXFRS; 100 ms ceiling is generous. */
	uint32_t tx_status = 0;
	const int64_t tx_deadline = ultrawidelock_uptime_ms() + 100;
	while (ultrawidelock_uptime_ms() < tx_deadline) {
		tx_status = dwt_readsysstatuslo();
		if (tx_status & DWT_INT_TXFRS_BIT_MASK) {
			out->tx_done = true;
			break;
		}
	}
	out->tx_status = tx_status;

	if (!out->tx_done) {
		LOG_ERR("TX timed out: SYS_STATUS=0x%08x", tx_status);
		/* Tear-down: force radio off so the RX phase doesn't race a hung TX. */
		dwt_forcetrxoff();
		return -EIO;
	}

	/* Write-1-to-clear TX status bits so the RX phase sees a clean SYS_STATUS. */
	dwt_writesysstatuslo(TX_STATUS_CLEAR_MASK);

	/* ── RX phase ─────────────────────────────────────────────── */

	/* RX timeout register units are ~1.0256 us; ~97500 is about 100 ms. */
	dwt_setrxtimeout(97500);

	if (ultrawidelock_uwb_arm_rx(DWT_START_RX_IMMEDIATE) != DWT_SUCCESS) {
		LOG_ERR("RX arm failed");
		return -EIO;
	}
	out->rx_armed = true;

	/* Poll for any RX event; with no peer we expect RXFTO after the window. */
	uint32_t rx_status = 0;
	const int64_t rx_deadline = ultrawidelock_uptime_ms() + 200; /* 2× chip TO */
	while (ultrawidelock_uptime_ms() < rx_deadline) {
		rx_status = dwt_readsysstatuslo();
		if (rx_status & RX_STATUS_EVENT_MASK) {
			out->rx_event = true;
			break;
		}
	}
	out->rx_status = rx_status;

	/* Force the radio off at end-of-test so it isn't left in RX listen. */
	dwt_forcetrxoff();
	/* Clear the RX-event bits we just observed. */
	dwt_writesysstatuslo(rx_status & RX_STATUS_EVENT_MASK);

	return 0;
}

/** @brief Shared static STS test vector for the two-device raw loopback. */
static const uint8_t g_partner_sts_key[16] = {
	0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xF0, 0x0D,
	0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
};
static const uint8_t g_partner_sts_iv[16] = {
	0x01, 0x00, 0x00, 0x00, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
};

int uwb_min_twr_prep(void)
{
	int err = uwb_radio_ensure_init();
	if (err) {
		return err;
	}

	/* Re-apply the baseline PHY; STS is the caller's to program, so none is set here. */
	dwt_forcetrxoff();
	if (ultrawidelock_uwb_configure_phy((dwt_config_t *)&g_uwb_cfg) != DWT_SUCCESS) {
		LOG_ERR("rawtwr: PHY configure failed");
		return -EIO;
	}
	dwt_configuretxrf((dwt_txconfig_t *)&g_uwb_txcfg);

	/* RX window for the RESP; ~50 ms is a generous ceiling that only bounds the timeout case.
	 */
	dwt_setrxtimeout(50000);
	return 0;
}

void uwb_min_twr_exchange(struct uwb_twr_frame *f)
{
	static const uint8_t poll_msg[] = {'P', 'A', 'R', 'T', 'P', 'O', 'L', 'L'};
	const uint32_t rx_mask =
		RX_STATUS_EVENT_MASK | DWT_INT_CIAERR_BIT_MASK | DWT_INT_CPERR_BIT_MASK;
	const uint32_t to_mask =
		DWT_INT_RXFTO_BIT_MASK | DWT_INT_RXPTO_BIT_MASK | DWT_INT_RXSTO_BIT_MASK;

	memset(f, 0, sizeof(*f));
	dwt_forcetrxoff();

	/* STS key+IV + counter reset for TX are the caller's responsibility. */
	if (dwt_writetxdata(sizeof(poll_msg), (uint8_t *)poll_msg, 0) != DWT_SUCCESS) {
		return;
	}
	dwt_writetxfctrl(sizeof(poll_msg) + 2u, 0, 1); /* +FCS, ranging=1 */
	if (dwt_starttx(DWT_START_TX_IMMEDIATE) != DWT_SUCCESS) {
		return;
	}

	/* Wait for the POLL to leave the antenna. */
	int64_t txdl = ultrawidelock_uptime_ms() + 50;
	while (!(dwt_readsysstatuslo() & DWT_INT_TXFRS_BIT_MASK)) {
		if (ultrawidelock_uptime_ms() > txdl) {
			break;
		}
	}
	dwt_writesysstatuslo(DWT_INT_TXFRS_BIT_MASK);
	f->tx_ok = true;

	/* Arm RX for the RESP; reset the STS counter to the loaded IV so it correlates. */
	dwt_configurestsloadiv();
	ultrawidelock_uwb_arm_rx(DWT_START_RX_IMMEDIATE);

	uint32_t st = 0;
	int64_t rxdl = ultrawidelock_uptime_ms() + 80; /* > the 50 ms chip RX timeout */
	while (!((st = dwt_readsysstatuslo()) & rx_mask)) {
		if (ultrawidelock_uptime_ms() > rxdl) {
			break;
		}
	}

	const bool got_frame = (st & (DWT_INT_RXFCG_BIT_MASK | DWT_INT_RXFR_BIT_MASK)) != 0;
	f->timed_out = (st & to_mask) != 0 && !got_frame;
	if (!f->timed_out) {
		(void)dwt_readstsquality(&f->sts, 0);
	}
	f->status = st;

	dwt_forcetrxoff();
	dwt_writesysstatuslo(st & rx_mask);
}

int uwb_min_twr_poll(uint32_t n, uint32_t period_ms, struct uwb_twr_result *out)
{
	if (out == NULL) {
		return -EINVAL;
	}
	memset(out, 0, sizeof(*out));

	int err = uwb_min_twr_prep();
	if (err) {
		return err;
	}

	/* Program the fixed static STS key + IV directly (the CCC wrap passes through while
	 * unbound). */
	dwt_configurestskey((dwt_sts_cp_key_t *)g_partner_sts_key);
	ultrawidelock_uwb_set_sts_iv((dwt_sts_cp_iv_t *)g_partner_sts_iv);
	dwt_configurestsloadiv();

	for (uint32_t i = 0; i < n; i++) {
		struct uwb_twr_frame f;

		dwt_configurestsloadiv(); /* static STS: reset the counter for TX. */
		uwb_min_twr_exchange(&f);

		if (f.tx_ok) {
			out->polls_tx++;
		}
		if (!f.timed_out) {
			out->resp_rx++;
			if (f.sts > 0) {
				out->sts_ok++;
			}
		}
		out->last_sts = f.sts;
		out->last_status = f.status;
		LOG_INF("rawtwr poll=%u %s sts=%d status=%08X", i, f.timed_out ? "TO" : "RESP",
			f.sts, (unsigned int)f.status);

		if (period_ms) {
			ultrawidelock_sleep_ms(period_ms);
		}
	}
	return 0;
}
