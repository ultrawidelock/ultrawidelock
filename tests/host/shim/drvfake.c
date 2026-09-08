/* Recording doubles for the driver test binary (see drvfake.h). Linked only by
 * tests/host/run.sh's host_test_drv build — never by the main host binary,
 * whose equivalents live in dw_rx_stub.c. Nothing here computes anything: the
 * doubles record arguments and serve knob values, so the suites prove the
 * driver sources' branch logic against a fake radio, not hardware truth. */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "drvfake.h"

#include "ccc_shim.h"
#include "fira_session.h"
#include <ultrawidelock/uwb.h>

#include <dw3000_hw.h>
#include <dw3000_spi.h>
#include <deca_probe_interface.h>

#include <zephyr/kernel.h>

struct drvfake_state drvfake;

void drvfake_reset(void)
{
	memset(&drvfake, 0, sizeof(drvfake));
	drvfake.stsq_val = 0;
	drvfake.start_ultrawidelock_ret = 0;
}

/* ── per-frame diag gate (defined by ccc_shim_rx.c on the main binary) ─────── */
volatile int ultrawidelock_uwb_diag_on = 1;

/* ── decadriver doubles ────────────────────────────────────────────────────── */
const struct dwt_probe_s dw3000_probe_interf = {0};

int32_t dwt_probe(struct dwt_probe_s *probe_interf)
{
	(void)probe_interf;
	drvfake.probe_calls++;
	if (drvfake.probe_fail_times > 0) {
		drvfake.probe_fail_times--;
		return DWT_ERROR;
	}
	return DWT_SUCCESS;
}

int32_t dwt_initialise(int32_t mode)
{
	(void)mode;
	drvfake.initialise_calls++;
	return drvfake.initialise_ret;
}

uint32_t dwt_readdevid(void)
{
	return drvfake.devid;
}

int32_t dwt_configure(dwt_config_t *config)
{
	drvfake.configure_calls++;
	if (config != NULL) {
		drvfake.last_cfg = *config;
	}
	return drvfake.configure_ret;
}

void dwt_configuretxrf(dwt_txconfig_t *config)
{
	drvfake.configuretxrf_calls++;
	if (config != NULL) {
		drvfake.last_txcfg = *config;
	}
}

void dwt_configuresleep(uint16_t mode, uint8_t wake)
{
	drvfake.configuresleep_calls++;
	drvfake.sleep_mode = mode;
	drvfake.sleep_wake = wake;
}

void dwt_entersleep(int32_t idle_rc)
{
	drvfake.entersleep_calls++;
	drvfake.last_entersleep = idle_rc;
}

int32_t dwt_restoreconfig(int restore_mask)
{
	(void)restore_mask;
	drvfake.restoreconfig_calls++;
	return drvfake.restoreconfig_ret;
}

void dw3000_hw_mark_asleep(void)
{
	drvfake.asleep = true;
}

bool dw3000_hw_is_asleep(void)
{
	return drvfake.asleep;
}

void dwt_setleds(uint8_t mode)
{
	drvfake.setleds_calls++;
	drvfake.leds_mode = mode;
}

uint32_t dwt_readsysstatuslo(void)
{
	if (drvfake.status_n == 0) {
		return 0u;
	}
	if (drvfake.status_i < drvfake.status_n) {
		return drvfake.status_seq[drvfake.status_i++];
	}
	return drvfake.status_seq[drvfake.status_n - 1];
}

void dwt_writesysstatuslo(uint32_t mask)
{
	drvfake.write_status_calls++;
	drvfake.last_write_status = mask;
}

int32_t dwt_writetxdata(uint16_t txDataLength, uint8_t *txDataBytes, uint16_t txBufferOffset)
{
	(void)txDataLength;
	(void)txDataBytes;
	(void)txBufferOffset;
	drvfake.writetxdata_calls++;
	return drvfake.writetxdata_ret;
}

void dwt_writetxfctrl(uint16_t txFrameLength, uint16_t txBufferOffset, uint8_t ranging)
{
	(void)txBufferOffset;
	(void)ranging;
	drvfake.writetxfctrl_calls++;
	drvfake.last_txfctrl_len = txFrameLength;
}

int32_t dwt_starttx(int32_t mode)
{
	(void)mode;
	drvfake.starttx_calls++;
	return drvfake.starttx_ret;
}

int32_t dwt_rxenable(int32_t mode)
{
	(void)mode;
	drvfake.rxenable_calls++;
	return drvfake.rxenable_ret;
}

void dwt_forcetrxoff(void)
{
	drvfake.trxoff_calls++;
}

void dwt_setrxtimeout(uint32_t time)
{
	drvfake.setrxtimeout_calls++;
	drvfake.last_rxtimeout = time;
}

void dwt_setinterrupt(uint32_t bitmask_lo, uint32_t bitmask_hi, int options)
{
	(void)bitmask_hi;
	(void)options;
	drvfake.setinterrupt_calls++;
	drvfake.last_int_lo = bitmask_lo;
}

void dwt_setcallbacks(dwt_callbacks_s *callbacks)
{
	drvfake.setcallbacks_calls++;
	if (callbacks != NULL) {
		drvfake.cbs = *callbacks;
	}
}

void dwt_configurestskey(dwt_sts_cp_key_t *key)
{
	(void)key;
	drvfake.stskey_calls++;
}

void dwt_configurestsiv(dwt_sts_cp_iv_t *iv)
{
	(void)iv;
	drvfake.stsiv_calls++;
}

void dwt_configurestsloadiv(void)
{
	drvfake.loadiv_calls++;
}

void dwt_readrxdata(uint8_t *buffer, uint16_t length, uint16_t rxBufferOffset)
{
	(void)rxBufferOffset;
	drvfake.readrxdata_calls++;
	drvfake.last_readrx_len = length;
	if (length > sizeof(drvfake.rxdata)) {
		length = sizeof(drvfake.rxdata);
	}
	memcpy(buffer, drvfake.rxdata, length);
}

int dwt_readstsquality(int16_t *rxStsQualityIndex, int stsSegment)
{
	(void)stsSegment;
	if (rxStsQualityIndex != NULL) {
		*rxStsQualityIndex = drvfake.stsq_val;
	}
	return drvfake.stsq_ret;
}

/* CIA/CIR diagnostics doubles for uwb_cirdiag.c: recording no-ops. The
 * diagnostics are zeroed except a settable ipatovFpIndex (drives the window
 * clamp), and dwt_readcir records the requested offset/width so a test can
 * assert the window geometry without any accumulator truth. */
void dwt_readdiagnostics(dwt_rxdiag_t *diagnostics)
{
	drvfake.readdiag_calls++;
	if (diagnostics != NULL) {
		memset(diagnostics, 0, sizeof(*diagnostics));
		diagnostics->ipatovFpIndex = drvfake.diag_fp;
	}
}

int dwt_readcir(uint32_t *buffer, dwt_acc_idx_e cir_idx, uint16_t sample_offs,
		uint16_t num_samples, dwt_cir_read_mode_e mode)
{
	(void)cir_idx;
	(void)mode;
	if (drvfake.readcir_calls == 0) {
		drvfake.first_cir_base = sample_offs;
	}
	drvfake.readcir_calls++;
	drvfake.last_cir_base = sample_offs;
	drvfake.last_cir_num = num_samples;
	if (buffer != NULL) {
		memset(buffer, 0, (size_t)num_samples * sizeof(uint32_t));
	}
	return drvfake.cir_ret;
}

int dwt_readstsstatus(uint16_t *stsStatus, int sts_num)
{
	(void)sts_num;
	if (stsStatus != NULL) {
		*stsStatus = 0u;
	}
	return 0;
}

void dwt_configciadiag(uint8_t enable_mask)
{
	drvfake.configciadiag_calls++;
	drvfake.last_ciadiag_mask = enable_mask;
}

uint32_t dwt_read_reg(uint32_t addr)
{
	(void)addr;
	return drvfake.read_reg_val;
}

uint32_t dwt_readsystimestamphi32(void)
{
	return 0u;
}

/* ── seam helpers this binary does not link the engine for ─────────────────── */
/* uwb_min.c and uwb_isr.c reach the radio through uwb_seam.h. uwb_rxdiag.c is in
 * this binary and supplies the callback + PHY halves itself; the CCC halves come
 * from ccc_shim_{rx,wrap}.c, which this suite deliberately excludes. Forward
 * those to the plain doubles so the calls are still counted. */
int32_t ultrawidelock_uwb_arm_rx(int32_t mode)
{
	return dwt_rxenable(mode);
}

void ultrawidelock_uwb_set_sts_iv(dwt_sts_cp_iv_t *iv)
{
	dwt_configurestsiv(iv);
}

/* ── dw3000 platform glue doubles ──────────────────────────────────────────── */
int dw3000_hw_init(void)
{
	drvfake.hw_init_calls++;
	return 0;
}

void dw3000_hw_reset(void)
{
	drvfake.hw_reset_calls++;
}

int dw3000_hw_init_interrupt(void)
{
	drvfake.hw_irq_calls++;
	return 0;
}

/* uwb_radio_ensure_init() calls this unconditionally, ahead of its own
 * g_radio_ready fast path, so that a part left in DEEPSLEEP is awake before
 * anything reaches it over SPI. On the target it is a no-op unless the part is
 * actually asleep; here it only has to link and be countable. */
void dw3000_hw_wakeup(void)
{
	drvfake.hw_wakeup_calls++;
	drvfake.asleep = false; /* the target clears its own flag the same way */
}

void dw3000_spi_wakeup(void)
{
	drvfake.spi_wakeup_calls++;
}

int32_t dw3000_spi_read(uint16_t headerLength, uint8_t *headerBuffer, uint16_t readLength,
			uint8_t *readBuffer)
{
	(void)headerLength;
	(void)headerBuffer;
	drvfake.spi_read_calls++;
	if (readLength > sizeof(drvfake.spi_devid)) {
		readLength = sizeof(drvfake.spi_devid);
	}
	memcpy(readBuffer, drvfake.spi_devid, readLength);
	return 0;
}

/* ── ccc_shim fakes (the real shim lives in the main binary's suites) ──────── */
bool ccc_shim_active(void)
{
	return drvfake.ccc_active;
}

void ccc_shim_wrap_log_reset(void)
{
	drvfake.wrap_log_reset_calls++;
}

bool ccc_shim_rx_awaiting_poll(void)
{
	return drvfake.rx_awaiting;
}

bool ccc_shim_rx_deadline_pending(void)
{
	return drvfake.rx_deadline;
}

bool ccc_shim_rx_awaiting_final(void)
{
	return drvfake.rx_final;
}

void ccc_shim_rx_notify_rx(uint32_t status)
{
	drvfake.notify_calls++;
	drvfake.last_notify_status = status;
}

void ccc_shim_rx_try_prepoll(uint16_t datalength)
{
	drvfake.try_prepoll_calls++;
	drvfake.last_prepoll_len = datalength;
}

/* ── fira_session fakes ────────────────────────────────────────────────────── */
bool fira_session_last_range(int32_t *cm_out, uint16_t *addr_out, uint8_t *nlos_out,
			     uint32_t *block_out, int64_t *age_ms_out)
{
	if (!drvfake.fira_have) {
		return false;
	}
	if (cm_out) {
		*cm_out = drvfake.fira_cm;
	}
	if (addr_out) {
		*addr_out = drvfake.fira_addr;
	}
	if (nlos_out) {
		*nlos_out = drvfake.fira_nlos;
	}
	if (block_out) {
		*block_out = drvfake.fira_block;
	}
	if (age_ms_out) {
		*age_ms_out = drvfake.fira_age_ms;
	}
	return true;
}

bool fira_session_range_trusted(void)
{
	return drvfake.fira_trusted;
}

const uint8_t *fira_session_get_ursk(void)
{
	return drvfake.fira_ursk;
}

/* ── ultrawidelock_uwb_facade fake (uwb_selftest boot path) ──────────────────────────── */
int ultrawidelock_uwb_start_cred(const struct ultrawidelock_uwb_cred_cfg *cfg)
{
	drvfake.start_ultrawidelock_calls++;
	if (cfg != NULL) {
		drvfake.last_ultrawidelock_cfg = *cfg;
		if (cfg->ursk != NULL) {
			memcpy(drvfake.last_ultrawidelock_ursk, cfg->ursk, 32);
		}
	}
	return drvfake.start_ultrawidelock_ret;
}

/* ── shell fake (zephyr/shell/shell.h capture sink) ────────────────────────── */
char shellfake_out[8192];
unsigned long shellfake_len;

void shellfake_reset(void)
{
	shellfake_len = 0;
	shellfake_out[0] = '\0';
}

void shellfake_print(const struct shell *sh, const char *fmt, ...)
{
	va_list ap;
	int n;

	(void)sh;
	if (shellfake_len >= sizeof(shellfake_out) - 2) {
		return;
	}
	va_start(ap, fmt);
	n = vsnprintf(shellfake_out + shellfake_len, sizeof(shellfake_out) - 1 - shellfake_len,
		      fmt, ap);
	va_end(ap);
	if (n > 0) {
		shellfake_len += (unsigned long)n;
		if (shellfake_len > sizeof(shellfake_out) - 2) {
			shellfake_len = sizeof(shellfake_out) - 2;
		}
	}
	shellfake_out[shellfake_len++] = '\n';
	shellfake_out[shellfake_len] = '\0';
}

/*
 * Free-running DWT cycle counter. On target this lives in
 * ports/zephyr/dw3000/dw3000_hw.c and is what uwb_cirdiag_capture() times the
 * diagnostics read with. There is no such counter on a host, and the value is
 * only ever printed as `rdcyc`, never compared against anything, so a constant
 * is a truthful stub rather than a convenient one: it makes every host-measured
 * read cost exactly zero, which is what a host read costs.
 */
uint32_t dw3000_dwt_cyccnt(void)
{
	return 0u;
}
