/* Host recording doubles for the DRIVER-BINARY suites (uwb_min / uwb_isr /
 * uwb_rxdiag / uwb_selftest / ultrawidelock_shell). This binary compiles the real
 * modules/ultrawidelock_uwb/src/driver + shell sources, so it cannot link dw_rx_stub.c
 * (that stub defines uwb_min_radio_init etc. as fakes). drvfake.c is its
 * replacement: every dwt_* / dw3000_* / ccc_shim_* / fira_session_* symbol the
 * driver sources reach is a recording double with knobs declared here.
 *
 * Theatre disclaimer: nothing here talks to a DW3000. These doubles prove the
 * drivers' branch logic and argument plumbing, not hardware truth. */
#ifndef ULTRAWIDELOCK_HOST_SHIM_DRVFAKE_H
#define ULTRAWIDELOCK_HOST_SHIM_DRVFAKE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "deca_device_api.h"
#include <ultrawidelock/uwb.h>

#define DRVFAKE_STATUS_SEQ_MAX 8

struct drvfake_state {
	/* ── probe / init knobs + recordings ── */
	unsigned probe_calls;
	int probe_fail_times; /* first N dwt_probe calls return DWT_ERROR */
	int32_t initialise_ret;
	unsigned initialise_calls;
	int32_t configure_ret;
	unsigned configure_calls;
	dwt_config_t last_cfg;
	unsigned configuretxrf_calls;
	dwt_txconfig_t last_txcfg;
	unsigned configuresleep_calls;
	uint16_t sleep_mode;
	uint8_t sleep_wake;
	/* DEEPSLEEP entry/exit (uwb_min_sleep + the wake-restore in ensure_init) */
	unsigned entersleep_calls;
	int32_t last_entersleep; /* idle_rc argument of the last dwt_entersleep */
	unsigned restoreconfig_calls;
	int32_t restoreconfig_ret;
	bool asleep; /* dw3000_hw_mark_asleep sets, dw3000_hw_wakeup clears */
	unsigned setleds_calls;
	uint8_t leds_mode;
	uint32_t devid; /* dwt_readdevid */
	uint8_t spi_devid[4]; /* bytes served by dw3000_spi_read (raw DEV_ID poll) */
	unsigned hw_init_calls, hw_reset_calls, hw_irq_calls, hw_wakeup_calls;
	unsigned spi_wakeup_calls, spi_read_calls;

	/* ── SYS_STATUS sequencing: served in order, last value repeats ── */
	uint32_t status_seq[DRVFAKE_STATUS_SEQ_MAX];
	int status_n;
	int status_i;
	unsigned write_status_calls;
	uint32_t last_write_status;

	/* ── TX / RX knobs + recordings ── */
	int32_t writetxdata_ret, starttx_ret, rxenable_ret;
	unsigned writetxdata_calls, writetxfctrl_calls, starttx_calls;
	unsigned rxenable_calls, trxoff_calls, setrxtimeout_calls;
	uint16_t last_txfctrl_len;
	uint32_t last_rxtimeout;
	int stsq_ret;
	int16_t stsq_val;
	unsigned stskey_calls, stsiv_calls, loadiv_calls;
	uint8_t rxdata[16]; /* served by dwt_readrxdata */
	unsigned readrxdata_calls;
	uint16_t last_readrx_len;
	uint32_t read_reg_val; /* dwt_read_reg (rxdiag SYS_CFG peek) */

	/* ── CIA/CIR diagnostics (uwb_cirdiag) ── */
	uint16_t diag_fp;       /* ipatovFpIndex served by dwt_readdiagnostics (Q10.6) */
	unsigned readdiag_calls;
	unsigned configciadiag_calls;
	uint8_t last_ciadiag_mask;
	unsigned readcir_calls;
	uint16_t first_cir_base; /* sample_offs of the first dwt_readcir since reset */
	uint16_t last_cir_base; /* sample_offs of the last dwt_readcir */
	uint16_t last_cir_num;  /* num_samples of the last dwt_readcir */
	int cir_ret;            /* dwt_readcir return (0 = DWT_SUCCESS) */

	/* ── callback registration capture (dwt_setcallbacks) ── */
	dwt_callbacks_s cbs;
	unsigned setcallbacks_calls;
	unsigned setinterrupt_calls;
	uint32_t last_int_lo;

	/* ── ccc_shim / fira_session fakes (ultrawidelock_shell + uwb_rxdiag deps) ── */
	bool ccc_active;
	unsigned wrap_log_reset_calls;
	bool rx_awaiting;
	bool rx_deadline; /* ccc_shim_rx_deadline_pending — gates the Stage 1 CIR window read */
	bool rx_final; /* ccc_shim_rx_awaiting_final — sampled pre-arm; true means radio idle */
	unsigned notify_calls;
	uint32_t last_notify_status;
	unsigned try_prepoll_calls;
	uint16_t last_prepoll_len;
	bool fira_have;
	int32_t fira_cm;
	uint16_t fira_addr;
	uint8_t fira_nlos;
	uint32_t fira_block;
	int64_t fira_age_ms;
	bool fira_trusted;
	const uint8_t *fira_ursk;

	/* ── ultrawidelock_uwb_facade fake (uwb_selftest boot path) ── */
	unsigned start_ultrawidelock_calls;
	struct ultrawidelock_uwb_cred_cfg last_ultrawidelock_cfg;
	uint8_t last_ultrawidelock_ursk[32]; /* copied: cfg->ursk is a pointer */
	int start_ultrawidelock_ret;
};

extern struct drvfake_state drvfake;

/** @brief Zero all recordings and knobs (rets back to success). */
void drvfake_reset(void);

/* ── shell fake capture (zephyr/shell/shell.h) ────────────────────────────── */
struct shell {
	int unused;
};

struct shellfake_entry {
	const char *syntax;
	int (*handler)(const struct shell *sh, size_t argc, char **argv);
};

struct shellfake_root {
	const char *name;
	const struct shellfake_entry *sub; /* {NULL,NULL}-terminated */
	int (*handler)(const struct shell *sh, size_t argc, char **argv);
};

extern char shellfake_out[8192];
extern unsigned long shellfake_len;
void shellfake_reset(void);
void shellfake_print(const struct shell *sh, const char *fmt, ...);

#endif /* ULTRAWIDELOCK_HOST_SHIM_DRVFAKE_H */
