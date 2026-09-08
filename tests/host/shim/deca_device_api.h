/* Host shim for <deca_device_api.h> — only the STS key/IV surface ccc_sts.c
 * needs. The register writes are no-ops here, but the values are captured into
 * ultrawidelock_host_last_sts_* so a unit test can assert the derivation packed them
 * correctly (field layout matches the DW3000 driver's cp_key/cp_iv structs). */
#ifndef ULTRAWIDELOCK_HOST_SHIM_DECA_DEVICE_API_H
#define ULTRAWIDELOCK_HOST_SHIM_DECA_DEVICE_API_H

#include <stdint.h>

typedef struct {
	uint32_t key0;
	uint32_t key1;
	uint32_t key2;
	uint32_t key3;
} dwt_sts_cp_key_t;

typedef struct {
	uint32_t iv0;
	uint32_t iv1;
	uint32_t iv2;
	uint32_t iv3;
} dwt_sts_cp_iv_t;

/* Last values handed to the (no-op) register writes — for test assertions. */
extern dwt_sts_cp_key_t ultrawidelock_host_last_sts_key;
extern dwt_sts_cp_iv_t ultrawidelock_host_last_sts_iv;
extern unsigned int ultrawidelock_host_sts_loadiv_calls;

void dwt_configurestskey(dwt_sts_cp_key_t *key);
void dwt_configurestsiv(dwt_sts_cp_iv_t *iv);
void dwt_configurestsloadiv(void);

/* ── RX/radio surface for ccc_shim_rx.c (the Pre-POLL listener) ──────────────
 * Constants mirror the real deca_device_api.h values (the listener tests bit
 * positions in status words); the functions are recording doubles defined in
 * dw_rx_stub.c. */

enum { DWT_SUCCESS = 0, DWT_ERROR = -1 };

#define DWT_START_RX_IMMEDIATE 0x00
#define DWT_START_RX_DELAYED   0x01
#define DWT_IDLE_ON_DLY_ERR    0x02
#define DWT_START_TX_IMMEDIATE 0x00
#define DWT_START_TX_DELAYED   0x01

#define DWT_STS_MODE_OFF 0x0
#define DWT_STS_MODE_ND  0x3

#define DWT_PLEN_64     (64U)
#define DWT_PLEN_128    (128U)
#define DWT_PAC8        0
#define DWT_SFD_IEEE_4A 0
#define DWT_SFD_IEEE_4Z 3
#define DWT_BR_6M8      1
#define DWT_PHRMODE_STD 0x0
#define DWT_PHRRATE_STD 0x0
#define DWT_STS_LEN_64  7
#define DWT_PDOA_M0     0x0
#define DWT_ENABLE_INT  1

/* uwb_min.c surface (values mirror modules/ultrawidelock_dw3000/dwt_uwb_driver/deca_device_api.h)
 */
#define DWT_DW_INIT         0x0
#define DWT_CONFIG          0x0001
#define DWT_RUNSAR          0x0002
#define DWT_GOTOIDLE        0x0100
#define DWT_WAKE_CSN        0x8
#define DWT_SLP_EN          0x1
#define DWT_PRES_SLEEP      0x20
#define DWT_DW_IDLE_RC      0x2
#define DWT_RESTORE_TXRX_MODE 0x0C
/* Values from the vendor header (deca_device_api.h). DISABLE is 0 and is the
 * one CONFIG_ULTRAWIDELOCK_UWB_LEDS=n passes; it was missing here, so a battery
 * build compiled for the target and failed only in the host suite. */
#define DWT_LEDS_DISABLE    0x00
#define DWT_LEDS_ENABLE     0x01
#define DWT_LEDS_INIT_BLINK 0x02

#define DWT_INT_ARFE_BIT_MASK    0x20000000UL
#define DWT_INT_HPDWARN_BIT_MASK 0x8000000UL
#define DWT_INT_RXSTO_BIT_MASK   0x4000000UL
#define DWT_INT_RXPTO_BIT_MASK   0x200000UL
#define DWT_INT_RXFTO_BIT_MASK   0x20000UL
#define DWT_INT_RXFSL_BIT_MASK   0x10000UL
#define DWT_INT_RXFCE_BIT_MASK   0x8000U
#define DWT_INT_RXFCG_BIT_MASK   0x4000U
#define DWT_INT_RXPHE_BIT_MASK   0x1000U
#define DWT_INT_RXPHD_BIT_MASK   0x800U
#define DWT_INT_CIADONE_BIT_MASK 0x400U
#define DWT_INT_TXFRS_BIT_MASK   0x80U
#define DWT_INT_CPERR_BIT_MASK   0x10000000UL
#define DWT_INT_CIAERR_BIT_MASK  0x40000UL
#define DWT_INT_RXFR_BIT_MASK    0x2000U
#define DWT_INT_TXPHS_BIT_MASK   0x40U
#define DWT_INT_TXPRS_BIT_MASK   0x20U
#define DWT_INT_TXFRB_BIT_MASK   0x10U

typedef struct {
	uint8_t chan;
	uint16_t txPreambLength;
	uint8_t rxPAC;
	uint8_t txCode;
	uint8_t rxCode;
	uint8_t sfdType;
	uint8_t dataRate;
	uint8_t phrMode;
	uint8_t phrRate;
	uint16_t sfdTO;
	uint8_t stsMode;
	uint8_t stsLength;
	uint8_t pdoaMode;
} dwt_config_t;

typedef struct {
	uint32_t status;
	uint16_t status_hi;
	uint16_t datalength;
	uint8_t rx_flags;
} dwt_cb_data_t;

typedef void (*dwt_cb_t)(const dwt_cb_data_t *cb_data);

typedef struct {
	dwt_cb_t cbTxDone;
	dwt_cb_t cbRxOk;
	dwt_cb_t cbRxTo;
	dwt_cb_t cbRxErr;
	dwt_cb_t cbSPIErr;
	dwt_cb_t cbSPIRDErr;
	dwt_cb_t cbSPIRdy;
	dwt_cb_t cbDualSPIEv;
} dwt_callbacks_s;

/** @brief TX RF config (uwb_min.c); field layout mirrors the real driver. */
typedef struct {
	uint8_t PGdly;
	uint32_t power;
	uint16_t PGcount;
} dwt_txconfig_t;

/** @brief Probe interface (opaque here; uwb_min.c only passes its address). */
struct dwt_probe_s {
	void *dw;
	void *spi;
	void (*wakeup_device_with_io)(void);
};

int32_t dwt_probe(struct dwt_probe_s *probe_interf);
int32_t dwt_initialise(int32_t mode);
uint32_t dwt_readdevid(void);
void dwt_configuretxrf(dwt_txconfig_t *config);
void dwt_configuresleep(uint16_t mode, uint8_t wake);
void dwt_entersleep(int32_t idle_rc);
int32_t dwt_restoreconfig(int restore_mask);
void dwt_setleds(uint8_t mode);
void dwt_writesysstatuslo(uint32_t mask);

int32_t dwt_configure(dwt_config_t *config);
void dwt_configurestsmode(uint8_t stsMode);
void dwt_setcallbacks(dwt_callbacks_s *callbacks);
void dwt_setinterrupt(uint32_t bitmask_lo, uint32_t bitmask_hi, int options);
void dwt_setrxtimeout(uint32_t time);
void dwt_setdelayedtrxtime(uint32_t starttime);
int32_t dwt_rxenable(int32_t mode);
int32_t dwt_starttx(int32_t mode);
void dwt_forcetrxoff(void);
int32_t dwt_writetxdata(uint16_t txDataLength, uint8_t *txDataBytes, uint16_t txBufferOffset);
void dwt_writetxfctrl(uint16_t txFrameLength, uint16_t txBufferOffset, uint8_t ranging);
uint32_t dwt_read_reg(uint32_t addr);
uint32_t dwt_readctrdbg(void);
uint32_t dwt_readsystimestamphi32(void);
uint32_t dwt_readsysstatuslo(void);
void dwt_readtxtimestamp(uint8_t *timestamp);
void dwt_readrxtimestamp_ipatov(uint8_t *timestamp);
void dwt_readrxdata(uint8_t *buffer, uint16_t length, uint16_t rxBufferOffset);
uint16_t dwt_getframelength(uint8_t *rng);
int dwt_readstsquality(int16_t *rxStsQualityIndex, int stsSegment);

/* ── CIA/CIR diagnostics surface for uwb_cirdiag.c ───────────────────────────
 * Types/constants mirror modules/ultrawidelock_dw3000/dwt_uwb_driver/deca_device_api.h; the
 * doubles in drvfake.c are link-only (no theatre test arms the CIR readout). */
typedef enum {
	DWT_ACC_IDX_IP_M = 0,
	DWT_ACC_IDX_STS0_M,
	DWT_ACC_IDX_STS1_M,
} dwt_acc_idx_e;

typedef enum {
	DWT_CIR_READ_FULL = 0,
	DWT_CIR_READ_LO,
	DWT_CIR_READ_MID,
	DWT_CIR_READ_HI,
} dwt_cir_read_mode_e;

#define DWT_CIR_LEN_IP_PRF64 1016
#define DW_CIA_DIAG_LOG_ALL  0x1
#define DW_CIA_DIAG_LOG_MAX  0x8

/* Subset of the real dwt_rxdiag_t: exactly the fields uwb_cirdiag.c reads. */
typedef struct {
	uint16_t ipatovFpIndex;
	uint16_t ipatovAccumCount;
	uint32_t ipatovPeak;
	uint32_t ipatovPower;
	uint32_t ipatovF1;
	uint32_t ipatovF2;
	uint32_t ipatovF3;
	uint16_t stsFpIndex;
	uint16_t stsAccumCount;
	uint32_t stsPeak;
	uint32_t stsPower;
	uint32_t stsF1;
	uint32_t stsF2;
	uint32_t stsF3;
	int16_t xtalOffset;
	uint32_t ciaDiag1;
} dwt_rxdiag_t;

void dwt_readdiagnostics(dwt_rxdiag_t *diagnostics);
int dwt_readcir(uint32_t *buffer, dwt_acc_idx_e cir_idx, uint16_t sample_offs,
		uint16_t num_samples, dwt_cir_read_mode_e mode);
int dwt_readstsstatus(uint16_t *stsStatus, int sts_num);
void dwt_configciadiag(uint8_t enable_mask);

/* Recording state for the doubles above — reset with ultrawidelock_host_rx_reset(). */
struct ultrawidelock_host_rx_rec {
	unsigned rxenable_calls;      /* dwt_rxenable invocations */
	int32_t last_rxenable_mode;
	unsigned forcetrxoff_calls;
	unsigned sleep_calls;         /* uwb_min_sleep invocations (DW3110 DEEPSLEEP entry) */
	unsigned starttx_calls;
	unsigned seq;                 /* global call sequencer */
	unsigned last_rxenable_seq;   /* seq at the last dwt_rxenable */
	unsigned last_forcetrxoff_seq;
	dwt_callbacks_s cbs;          /* captured by dwt_setcallbacks */
	int32_t rxenable_ret;         /* returned by dwt_rxenable (default DWT_SUCCESS) */
	int32_t starttx_ret;
	/* Injectable RX/TX state, so tests can feed the listener real frames. */
	uint8_t rxdata[128];          /* served by dwt_readrxdata */
	uint16_t rxdata_len;          /* served by dwt_getframelength */
	uint64_t rx_ts40;             /* 40-bit Ipatov RX timestamp (LE 5 bytes) */
	uint64_t tx_ts40;             /* 40-bit TX timestamp */
	uint32_t systime;             /* dwt_readsystimestamphi32 */
	int stsq_ret;                 /* dwt_readstsquality return */
	int16_t stsq_val;             /* ...and its quality index out-param */
	int radio_init_ret;           /* uwb_min_radio_init return (default 0 = up) */
	int32_t configure_ret;        /* dwt_configure return (default DWT_SUCCESS) */
};
extern struct ultrawidelock_host_rx_rec ultrawidelock_host_rx;
void ultrawidelock_host_rx_reset(void);

#endif /* ULTRAWIDELOCK_HOST_SHIM_DECA_DEVICE_API_H */
