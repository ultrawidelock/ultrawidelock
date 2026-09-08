/**
 * @file test_uwb_min.c — DW3110 bring-up driver (uwb_min.c) against the
 * drvfake recording radio. Pins the probe retry/idempotence state machine, the
 * baseline PHY/sleep/LED plumbing, and the selftest/raw-TWR status-poll
 * branches. A fake serves every register read, so nothing here proves the
 * radio works — only that the driver takes the right branch per status word.
 */
#include <string.h>

#include "drvfake.h"
#include "test.h"
#include "uwb_min.h"

/** Point the fake raw-DEV_ID SPI poll at a DW3110 answer. */
static void devid_ok(void)
{
	drvfake.spi_devid[0] = 0x02;
	drvfake.spi_devid[1] = 0x03;
	drvfake.spi_devid[2] = 0xCA;
	drvfake.spi_devid[3] = 0xDE;
	drvfake.devid = UWB_DW3110_DEV_ID;
}

/** Serve this fixed SYS_STATUS sequence (last value repeats). */
static void status_seq(const uint32_t *seq, int n)
{
	memcpy(drvfake.status_seq, seq, (size_t)n * sizeof(seq[0]));
	drvfake.status_n = n;
	drvfake.status_i = 0;
}

void test_uwb_min(void)
{
	uint32_t id;

	t_group("chip id: probe once, then cached");
	drvfake_reset();
	(void)uwb_min_hw_reset(); /* clear the module's idempotent-init latches */
	drvfake_reset();
	devid_ok();
	T_EQ("read ok", uwb_min_read_chipid(&id), 0);
	T_EQ("id", (long)id, (long)UWB_DW3110_DEV_ID);
	T_EQ("hw_init once", (long)drvfake.hw_init_calls, 1L);
	T_EQ("probe once", (long)drvfake.probe_calls, 1L);
	T_EQ("one wakeup poll round", (long)drvfake.spi_read_calls, 1L);
	T_EQ("read again (cached probe)", uwb_min_read_chipid(&id), 0);
	T_EQ("probe not repeated", (long)drvfake.probe_calls, 1L);
	T_EQ("NULL out", uwb_min_read_chipid(NULL), -22);

	t_group("probe retry: 3 attempts then -EIO");
	(void)uwb_min_hw_reset();
	drvfake_reset(); /* raw DEV_ID reads 0x00000000 (unpowered look) */
	drvfake.probe_fail_times = 5;
	T_EQ("probe exhausts -> -EIO", uwb_min_read_chipid(&id), -5);
	T_EQ("3 probe attempts", (long)drvfake.probe_calls, 3L);
	T_EQ("3 chip resets", (long)drvfake.hw_reset_calls, 3L);
	T_EQ("5 wakeups per attempt", (long)drvfake.spi_wakeup_calls, 15L);

	t_group("probe retry: transient failure clears");
	(void)uwb_min_hw_reset();
	drvfake_reset();
	devid_ok();
	drvfake.probe_fail_times = 1;
	T_EQ("2nd attempt lands", uwb_min_read_chipid(&id), 0);
	T_EQ("2 probe attempts", (long)drvfake.probe_calls, 2L);

	t_group("radio init: config + sleep + leds + irq, once");
	(void)uwb_min_hw_reset();
	drvfake_reset();
	devid_ok();
	uint32_t gen0 = uwb_min_radio_generation();

	T_EQ("init ok", uwb_min_radio_init(), 0);
	T_EQ("generation bumped", (long)uwb_min_radio_generation(), (long)(gen0 + 1u));
	T_EQ("initialise once", (long)drvfake.initialise_calls, 1L);
	T_EQ("cfg chan 9", (long)drvfake.last_cfg.chan, 9L);
	T_EQ("cfg SP3-ND", (long)drvfake.last_cfg.stsMode, (long)DWT_STS_MODE_ND);
	T_EQ("cfg sfd 4z", (long)drvfake.last_cfg.sfdType, (long)DWT_SFD_IEEE_4Z);
	T_EQ("cfg sfdTO 129", (long)drvfake.last_cfg.sfdTO, 129L);
	T_EQ("txrf applied", (long)drvfake.configuretxrf_calls, 1L);
	T_EQ("txrf PGdly", (long)drvfake.last_txcfg.PGdly, 0x34L);
	T_EQ("sleep mode", (long)drvfake.sleep_mode,
	     (long)(DWT_CONFIG | DWT_GOTOIDLE | DWT_RUNSAR));
	T_EQ("sleep wake", (long)drvfake.sleep_wake,
	     (long)(DWT_PRES_SLEEP | DWT_WAKE_CSN | DWT_SLP_EN));
	T_EQ("leds blink+enable", (long)drvfake.leds_mode,
	     (long)(DWT_LEDS_ENABLE | DWT_LEDS_INIT_BLINK));
	T_EQ("irq wired", (long)drvfake.hw_irq_calls, 1L);
	T_EQ("init again is a no-op", uwb_min_radio_init(), 0);
	T_EQ("configure not repeated", (long)drvfake.configure_calls, 1L);

	/* SLEEP_EN self-clears on wake (SDK, DWT_PRES_SLEEP), so a sleep armed once
	 * at boot covers one sleep. The bench symptom of arming it once: the first
	 * walk-up ranges, every later one logs "chip never reached IDLE_RC" and
	 * never receives a Pre-POLL. Continues from the radio-ready state above. */
	t_group("deep sleep: re-armed every entry, restored every wake");
	unsigned arm0 = drvfake.configuresleep_calls;
	unsigned trx0 = drvfake.trxoff_calls;

	uwb_min_sleep();
	T_EQ("sleep.trxoff first", (long)drvfake.trxoff_calls, (long)(trx0 + 1u));
	T_EQ("sleep.rearmed", (long)drvfake.configuresleep_calls, (long)(arm0 + 1u));
	T_EQ("sleep.rearm keeps SLEEP_EN", (long)drvfake.sleep_wake,
	     (long)(DWT_PRES_SLEEP | DWT_WAKE_CSN | DWT_SLP_EN));
	T_EQ("sleep.entered", (long)drvfake.entersleep_calls, 1L);
	T_EQ("sleep.idle_rc", (long)drvfake.last_entersleep, (long)DWT_DW_IDLE_RC);
	T_OK("sleep.marked", drvfake.asleep);
	uwb_min_sleep();
	T_EQ("sleep.twice is once", (long)drvfake.entersleep_calls, 1L);

	unsigned wake0 = drvfake.hw_wakeup_calls;
	unsigned init0 = drvfake.initialise_calls;

	T_EQ("wake.rc", uwb_min_radio_init(), 0);
	T_EQ("wake.toggled", (long)drvfake.hw_wakeup_calls, (long)(wake0 + 1u));
	T_EQ("wake.restored", (long)drvfake.restoreconfig_calls, 1L);
	T_EQ("wake.no reinit", (long)drvfake.initialise_calls, (long)init0);
	T_OK("wake.cleared", !drvfake.asleep);
	T_EQ("wake.awake init is free", uwb_min_radio_init(), 0);
	T_EQ("wake.restore once per wake", (long)drvfake.restoreconfig_calls, 1L);
	uwb_min_sleep();
	T_EQ("sleep.second entry", (long)drvfake.entersleep_calls, 2L);
	T_EQ("sleep.second rearm", (long)drvfake.configuresleep_calls, (long)(arm0 + 2u));

	t_group("deep sleep: a part that does not answer is rebuilt from reset");
	drvfake.devid = 0u; /* still marked asleep; DEV_ID now reads as unpowered */
	unsigned reset0 = drvfake.hw_reset_calls;
	uint32_t gen1 = uwb_min_radio_generation();

	init0 = drvfake.initialise_calls;
	T_EQ("dead.rc", uwb_min_radio_init(), 0);
	T_EQ("dead.no restore attempted", (long)drvfake.restoreconfig_calls, 1L);
	/* uwb_min_hw_reset's own reset, then the probe loop's per-attempt reset */
	T_EQ("dead.reset+reprobe", (long)drvfake.hw_reset_calls, (long)(reset0 + 2u));
	T_EQ("dead.reinit", (long)drvfake.initialise_calls, (long)(init0 + 1u));
	T_EQ("dead.generation bumped", (long)uwb_min_radio_generation(), (long)(gen1 + 1u));
	T_OK("dead.awake after", !drvfake.asleep);

	t_group("deep sleep: a failed restore is rebuilt from reset too");
	devid_ok();
	uwb_min_sleep();
	drvfake.restoreconfig_ret = DWT_ERROR;
	init0 = drvfake.initialise_calls;
	T_EQ("badrestore.rc", uwb_min_radio_init(), 0);
	T_EQ("badrestore.tried", (long)drvfake.restoreconfig_calls, 2L);
	T_EQ("badrestore.reinit", (long)drvfake.initialise_calls, (long)(init0 + 1u));
	drvfake.restoreconfig_ret = DWT_SUCCESS;

	t_group("radio init failures");
	(void)uwb_min_hw_reset();
	drvfake_reset();
	devid_ok();
	drvfake.initialise_ret = DWT_ERROR;
	T_EQ("dwt_initialise fail -> -EIO", uwb_min_radio_init(), -5);
	(void)uwb_min_hw_reset();
	drvfake_reset();
	devid_ok();
	drvfake.configure_ret = DWT_ERROR;
	T_EQ("dwt_configure fail -> -EIO", uwb_min_radio_init(), -5);

	t_group("selftest: happy path (TXFRS then RX timeout event)");
	(void)uwb_min_hw_reset();
	drvfake_reset();
	devid_ok();
	struct uwb_selftest_result r;
	const uint32_t happy[] = {DWT_INT_TXFRS_BIT_MASK, DWT_INT_RXFTO_BIT_MASK};

	status_seq(happy, 2);
	T_EQ("NULL out", uwb_min_selftest(NULL), -22);
	T_EQ("selftest ok", uwb_min_selftest(&r), 0);
	T_OK("tx done", r.tx_done);
	T_OK("rx armed", r.rx_armed);
	T_OK("rx event", r.rx_event);
	T_EQ("tx status latched", (long)r.tx_status, (long)DWT_INT_TXFRS_BIT_MASK);
	T_EQ("rx status latched", (long)r.rx_status, (long)DWT_INT_RXFTO_BIT_MASK);
	T_EQ("rx timeout ~100ms", (long)drvfake.last_rxtimeout, 97500L);
	T_EQ("radio left off", (long)(drvfake.trxoff_calls > 0), 1L);

	t_group("selftest: injected failures");
	drvfake.writetxdata_ret = DWT_ERROR;
	T_EQ("writetxdata fail", uwb_min_selftest(&r), -5);
	drvfake.writetxdata_ret = DWT_SUCCESS;
	drvfake.starttx_ret = DWT_ERROR;
	T_EQ("starttx fail", uwb_min_selftest(&r), -5);
	drvfake.starttx_ret = DWT_SUCCESS;
	status_seq(happy, 2);
	drvfake.rxenable_ret = DWT_ERROR;
	T_EQ("rxenable fail", uwb_min_selftest(&r), -5);
	T_OK("tx had completed", r.tx_done && !r.rx_armed);
	drvfake.rxenable_ret = DWT_SUCCESS;

	t_group("selftest: TX poll timeout (real ~100ms wait)");
	drvfake.status_n = 0; /* SYS_STATUS stays 0: no TXFRS ever */
	drvfake.status_i = 0;
	unsigned off0 = drvfake.trxoff_calls;

	T_EQ("tx timeout -> -EIO", uwb_min_selftest(&r), -5);
	T_OK("radio forced off", drvfake.trxoff_calls == off0 + 1);
	T_OK("no tx_done", !r.tx_done);

	t_group("raw twr: prep + one exchange");
	(void)uwb_min_hw_reset();
	drvfake_reset(); /* dead radio: init error propagates */
	drvfake.probe_fail_times = 3;
	T_EQ("prep on dead radio", uwb_min_twr_prep(), -5);
	struct uwb_twr_result dead;

	drvfake.probe_fail_times = 3;
	T_EQ("burst on dead radio", uwb_min_twr_poll(1, 0, &dead), -5);
	drvfake_reset();
	devid_ok();
	T_EQ("prep ok", uwb_min_twr_prep(), 0);
	T_EQ("resp window 50ms", (long)drvfake.last_rxtimeout, 50000L);
	drvfake.configure_ret = DWT_ERROR;
	T_EQ("prep configure fail", uwb_min_twr_prep(), -5);
	drvfake.configure_ret = DWT_SUCCESS;

	struct uwb_twr_frame f;
	const uint32_t resp[] = {DWT_INT_TXFRS_BIT_MASK, DWT_INT_RXFCG_BIT_MASK};

	status_seq(resp, 2);
	drvfake.stsq_val = 17;
	uwb_min_twr_exchange(&f);
	T_OK("poll left", f.tx_ok);
	T_OK("resp seen", !f.timed_out);
	T_EQ("sts read", (long)f.sts, 17L);

	const uint32_t toseq[] = {DWT_INT_TXFRS_BIT_MASK, DWT_INT_RXFTO_BIT_MASK};

	status_seq(toseq, 2);
	uwb_min_twr_exchange(&f);
	T_OK("timeout flagged", f.timed_out);

	drvfake.writetxdata_ret = DWT_ERROR;
	uwb_min_twr_exchange(&f);
	T_OK("txdata fail aborts", !f.tx_ok && !f.timed_out);
	drvfake.writetxdata_ret = DWT_SUCCESS;
	drvfake.starttx_ret = DWT_ERROR;
	uwb_min_twr_exchange(&f);
	T_OK("starttx fail aborts", !f.tx_ok);
	drvfake.starttx_ret = DWT_SUCCESS;

	/* Silent radio: both poll windows expire on their real deadlines
	 * (~50 ms + ~80 ms busy-wait; documents that tx_ok is still latched). */
	drvfake.status_n = 0;
	drvfake.status_i = 0;
	uwb_min_twr_exchange(&f);
	T_OK("deadline path: tx_ok latched anyway", f.tx_ok);
	T_OK("deadline path: no timeout bit seen", !f.timed_out);

	t_group("raw twr: initiator burst");
	struct uwb_twr_result res;
	const uint32_t both[] = {DWT_INT_TXFRS_BIT_MASK | DWT_INT_RXFCG_BIT_MASK};

	T_EQ("NULL out", uwb_min_twr_poll(1, 0, NULL), -22);
	status_seq(both, 1);
	drvfake.stsq_val = 9;
	unsigned key0 = drvfake.stskey_calls;

	T_EQ("burst ok", uwb_min_twr_poll(3, 1, &res), 0);
	T_EQ("3 polls", (long)res.polls_tx, 3L);
	T_EQ("3 resps", (long)res.resp_rx, 3L);
	T_EQ("3 sts ok", (long)res.sts_ok, 3L);
	T_EQ("last sts", (long)res.last_sts, 9L);
	T_OK("static STS key programmed", drvfake.stskey_calls == key0 + 1);
	T_OK("counter reset per poll", drvfake.loadiv_calls >= 4);
}
