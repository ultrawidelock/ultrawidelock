#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "deca_device_api.h"
#include "dw3000_hw.h"
#include "dw3000_spi.h"

LOG_MODULE_REGISTER(dw3000, CONFIG_DW3000_LOG_LEVEL);

#define DW_INST DT_INST(0, decawave_dw3000)

static struct gpio_callback gpio_cb;
static struct k_work dw3000_isr_work;

/* Dedicated high-priority workqueue for the DW3000 IRQ -> dwt_isr path.  The default
 * k_work_submit() runs on the SHARED system workqueue (coop -1), which sits BELOW BLE's
 * cooperative threads (-8..-10) and behind any BLE work queued ahead, so dwt_isr (and the
 * MCPS worker it signals) is delayed past the ~3ms ranging slot.  Run it on a dedicated
 * cooperative thread just above BLE (-11) so the per-slot RX-arm path starts immediately,
 * like the reference which calls dwt_isr straight from the ISR. */
#define DW3000_ISR_WQ_PRIO (-11)
K_THREAD_STACK_DEFINE(dw3000_isr_wq_stack, 2048);
static struct k_work_q dw3000_isr_wq;

/* ─── Per-slot RX-arm latency localisation (DWT CYCCNT) — DIAG only ───────
 * The poll-RX is armed ~385us too late (negative `lead`, dw3000_device.c
 * DWT_SETDELAYEDTRXTIME).  To split that reaction into buckets we need a
 * ns-resolution clock, but k_cycle_get_32() here is the 32 kHz RTC
 * (CONFIG_CORTEX_M_DWT not set) = ~30.5 us/tick, far too coarse.  Drive the
 * Cortex-M33 DWT cycle counter directly (core clock, ~7.8 ns/tick @128MHz)
 * via its architecturally-fixed addresses (no CMSIS symbol dependency).
 * Three timestamps stamped along the IRQ->dwt_isr path are read back at the
 * arm to bucket the reaction:  hop = IRQ->work-handler (the k_work dispatch),
 * isr = dwt_isr frame-pull SPI, post = signal+worker fproc+arm SPI.
 * Remove this whole block once the dominant bucket is identified. */
#define ULTRAWIDELOCK_DEMCR      (*(volatile uint32_t *)0xE000EDFCu) /* DEMCR, TRCENA @ bit24 */
#define ULTRAWIDELOCK_DWT_LAR                                                                      \
	(*(volatile uint32_t *)0xE0001FB0u) /* CoreSight lock (RAZ/WI if absent) */
#define ULTRAWIDELOCK_DWT_CTRL (*(volatile uint32_t *)0xE0001000u) /* DWT_CTRL, CYCCNTENA @ bit0   \
								    */
#define ULTRAWIDELOCK_DWT_CYCCNT                                                                   \
	(*(volatile uint32_t *)0xE0001004u) /* DWT_CYCCNT free-running counter */

volatile uint32_t g_dw_cyc_gpio;    /* T0: GPIO ISR entry, pre work-submit (hop start) */
volatile uint32_t g_dw_cyc_work;    /* T1: work-handler entry, post hop */
volatile uint32_t g_dw_cyc_isrdone; /* T2: dwt_isr loop done */
volatile uint32_t g_dw_cyc_per_us = 64; /* CPU cyc/us, calibrated at init (64 = safe default) */

/** Read the DWT cycle counter — exported so dw3000_device.c can stamp the arm. */
uint32_t dw3000_dwt_cyccnt(void)
{
	return ULTRAWIDELOCK_DWT_CYCCNT;
}

/** Enable the DWT cycle counter (once, at HW init). */
static void ultrawidelock_cyccnt_enable(void)
{
	ULTRAWIDELOCK_DEMCR |= (1u << 24);   /* TRCENA — power the DWT/ITM trace unit */
	ULTRAWIDELOCK_DWT_LAR = 0xC5ACCE55u; /* unlock DWT (no-op if LAR unimplemented) */
	ULTRAWIDELOCK_DWT_CYCCNT = 0u;
	ULTRAWIDELOCK_DWT_CTRL |= 1u;        /* CYCCNTENA */

	/* Calibrate CPU cyc/us empirically: k_busy_wait(1000) is a known 1 ms wall
	 * delay, so the CYCCNT delta over it IS the core clock — removes the guess
	 * about 64 vs 128 MHz that the bucket->us conversion (dw3000_device.c)
	 * depends on, and confirms the cycle counter is actually running. */
	{
		uint32_t c0 = ULTRAWIDELOCK_DWT_CYCCNT;
		k_busy_wait(1000);
		uint32_t c1 = ULTRAWIDELOCK_DWT_CYCCNT;
		uint32_t per_us = (c1 - c0) / 1000u;

		if (per_us != 0u) {
			g_dw_cyc_per_us = per_us;
		}
		if (!IS_ENABLED(CONFIG_ULTRAWIDELOCK_PRETTY_SHELL)) {
			printk("DIAG cyccnt cal: %u cyc/ms => %u cyc/us (%u MHz)\n",
			       (unsigned)(c1 - c0), (unsigned)g_dw_cyc_per_us,
			       (unsigned)g_dw_cyc_per_us);
		}
	}
}

/* Path-A: tracks whether the MAC slept the radio (via qpwr_uwb_sleep ->
 * dwt_entersleep).  The wake path only toggles CS when actually asleep, and
 * qpwr_uwb_is_sleeping() reflects this — keeps the MAC's sleep/wake state
 * machine consistent (mirrors Qorvo qpwr.c is_sleeping). */
static bool dw3000_asleep;

void dw3000_hw_mark_asleep(void)
{
	dw3000_asleep = true;
}

bool dw3000_hw_is_asleep(void)
{
	return dw3000_asleep;
}

struct dw3000_config {
	struct gpio_dt_spec gpio_irq;
	struct gpio_dt_spec gpio_reset;
	struct gpio_dt_spec gpio_wakeup;
	struct gpio_dt_spec gpio_spi_pol;
	struct gpio_dt_spec gpio_spi_pha;
};

static const struct dw3000_config conf = {
	.gpio_irq = GPIO_DT_SPEC_GET_OR(DW_INST, irq_gpios, {0}),
	.gpio_reset = GPIO_DT_SPEC_GET_OR(DW_INST, reset_gpios, {0}),
	.gpio_wakeup = GPIO_DT_SPEC_GET_OR(DW_INST, wakeup_gpios, {0}),
	.gpio_spi_pol = GPIO_DT_SPEC_GET_OR(DW_INST, spi_pol_gpios, {0}),
	.gpio_spi_pha = GPIO_DT_SPEC_GET_OR(DW_INST, spi_pha_gpios, {0}),
};

int dw3000_hw_init(void)
{
	ultrawidelock_cyccnt_enable(); /* DIAG: arm the cycle counter before any IRQ stamps it */

	/* Reset */
	if (conf.gpio_reset.port) {
		gpio_pin_configure_dt(&conf.gpio_reset, GPIO_INPUT);
		LOG_INF("RESET on %s pin %d", conf.gpio_reset.port->name,
				conf.gpio_reset.pin);
	}

	/* Wakeup (optional) */
	if (conf.gpio_wakeup.port) {
		gpio_pin_configure_dt(&conf.gpio_wakeup, GPIO_OUTPUT_ACTIVE);
		LOG_INF("WAKEUP on %s pin %d", conf.gpio_wakeup.port->name,
				conf.gpio_wakeup.pin);
	}

	/* SPI Polarity (optional) */
	if (conf.gpio_spi_pol.port) {
		gpio_pin_configure_dt(&conf.gpio_spi_pol, GPIO_OUTPUT_INACTIVE);
		LOG_INF("SPI_POL on %s pin %d", conf.gpio_spi_pol.port->name,
				conf.gpio_spi_pol.pin);
	}

	/* SPI Phase (optional) */
	if (conf.gpio_spi_pha.port) {
		gpio_pin_configure_dt(&conf.gpio_spi_pha, GPIO_OUTPUT_INACTIVE);
		LOG_INF("SPI_PHA on %s pin %d", conf.gpio_spi_pha.port->name,
				conf.gpio_spi_pha.pin);
	}

	return dw3000_spi_init();
}

static void dw3000_hw_isr_work_handler(struct k_work* item)
{
	g_dw_cyc_work = ULTRAWIDELOCK_DWT_CYCCNT; /* T1: post-hop (work-handler entered) */
	while (gpio_pin_get_dt(&conf.gpio_irq)) {
		dwt_isr();
	}
	g_dw_cyc_isrdone = ULTRAWIDELOCK_DWT_CYCCNT; /* T2: dwt_isr loop done */
}

static void dw3000_hw_isr(const struct device* dev, struct gpio_callback* cb,
						  uint32_t pins)
{
	g_dw_cyc_gpio = ULTRAWIDELOCK_DWT_CYCCNT; /* T0: GPIO ISR entry, pre work-submit (hop start) */
	k_work_submit_to_queue(&dw3000_isr_wq, &dw3000_isr_work);
}

int dw3000_hw_init_interrupt(void)
{
	if (conf.gpio_irq.port) {
		k_work_init(&dw3000_isr_work, dw3000_hw_isr_work_handler);
		k_work_queue_init(&dw3000_isr_wq);
		k_work_queue_start(&dw3000_isr_wq, dw3000_isr_wq_stack,
				   K_THREAD_STACK_SIZEOF(dw3000_isr_wq_stack),
				   DW3000_ISR_WQ_PRIO, NULL);

		gpio_pin_configure_dt(&conf.gpio_irq, GPIO_INPUT);
		gpio_init_callback(&gpio_cb, dw3000_hw_isr, BIT(conf.gpio_irq.pin));
		gpio_add_callback(conf.gpio_irq.port, &gpio_cb);
		gpio_pin_interrupt_configure_dt(&conf.gpio_irq, GPIO_INT_EDGE_RISING);

		LOG_INF("IRQ on %s pin %d", conf.gpio_irq.port->name,
				conf.gpio_irq.pin);
		return 0;
	} else {
		LOG_ERR("IRQ pin not configured");
		return -ENOENT;
	}
}

void dw3000_hw_interrupt_enable(void)
{
	if (conf.gpio_irq.port) {
		gpio_pin_interrupt_configure_dt(&conf.gpio_irq, GPIO_INT_EDGE_RISING);
	}
}

void dw3000_hw_interrupt_disable(void)
{
	if (conf.gpio_irq.port) {
		gpio_pin_interrupt_configure_dt(&conf.gpio_irq, GPIO_INT_DISABLE);
	}
}

bool dw3000_hw_interrupt_is_enabled(void)
{
	return true; // TODO
}

void dw3000_hw_fini(void)
{
	// TODO
	if (conf.gpio_irq.port) {
		gpio_pin_interrupt_configure_dt(&conf.gpio_irq, GPIO_INT_DISABLE);
		gpio_pin_configure_dt(&conf.gpio_irq, GPIO_DISCONNECTED);
	}
	if (conf.gpio_reset.port) {
		gpio_pin_configure_dt(&conf.gpio_reset, GPIO_DISCONNECTED);
	}
	if (conf.gpio_wakeup.port) {
		gpio_pin_configure_dt(&conf.gpio_wakeup, GPIO_DISCONNECTED);
	}

	dw3000_spi_fini();
}

void dw3000_hw_reset()
{
	if (!conf.gpio_reset.port) {
		LOG_ERR("No HW reset configured");
		return;
	}

	gpio_pin_configure_dt(&conf.gpio_reset, GPIO_OUTPUT_ACTIVE);
	k_msleep(1); // 10 us?
	gpio_pin_configure_dt(&conf.gpio_reset, GPIO_INPUT);
	k_msleep(2);

	/* A HW reset leaves the DW3110 in IDLE_RC (awake); clear the sleep flag so
	 * the next wake path doesn't do a bogus CS-toggle on an already-awake chip.
	 * Matters on session restart — fira_session_stop resets the chip between
	 * ranging sessions. */
	dw3000_asleep = false;
}

/** Wake the DW3110 — the MAC's wakeup_device_with_io (see deca_port.c).
 *
 * CS-toggle wake (drive CS low, release), then WAIT until the chip confirms it
 * reached IDLE_RC — exactly as every SDK deep-sleep example does (dwt_wakeup_ic
 * -> ~2 ms -> spin dwt_checkidlerc; see the wake body below).  The reference does
 * NOT force the chip state on wake (no dwt_setdwstate); the chip auto-climbs to
 * IDLE_PLL when the next action arms.  An earlier note here claimed the llhw gates
 * the resume on a post-wake SPIRDY/RCINIT IRQ — the live trace REFUTES that
 * (setcallbacks shows SPIRdy=0, no SPIRDY callback registered), so polling
 * dwt_checkidlerc is what actually guarantees the radio is ready before the llhw
 * wake-replay reads it.
 *
 * A manual dwt_setdwstate(DWT_DW_IDLE) here (previously gated on >50 ms sleeps)
 * was both redundant (the chip auto-climbs) and harmful: per the driver's own
 * ull_restoreconfig, force-driving the state while SPIRDY is pending corrupts
 * that event, so the llhw worker parked before arming block N+1.  Removed after
 * verifying against the SDK reference (2026-06-24); see
 * notes/uwb-pathA-fira-integration.md.
 *
 * Gated on the asleep flag: a CS-toggle on an already-awake chip would corrupt
 * the next SPI xfer. */
void dw3000_hw_wakeup(void)
{
	if (!dw3000_asleep) {
		return;
	}
	LOG_INF("WAKEUP CS");
	dw3000_asleep = false; /* allow the SPI reads below; a toggle at an awake part is harmless */

	for (int attempt = 1; attempt <= 3; attempt++) {
		dw3000_spi_wakeup(); /* drive CS low ~500us, then release (Qorvo CS-toggle) */
		k_busy_wait(2000);   /* INIT_RC -> IDLE_RC startup time (SDK reference: Sleep(2)) */

		/* Spin until the chip CONFIRMS IDLE_RC, exactly as the SDK deep-sleep examples
		 * (ex_01b_tx_sleep, ex_05a_ds_twr_init).  dwt_checkidlerc() READS the RCINIT/
		 * SPIRDY status bits — safe, unlike a setdwstate WRITE.  Bounded (~5 ms) so a
		 * chip that never wakes fails loud instead of hanging the llhw worker. */
		int spins = 0;

		while (!dwt_checkidlerc() && spins < 500) {
			k_busy_wait(10);
			spins++;
		}
		if (spins < 500) {
			return;
		}

		/* RCINIT is a sticky status bit, and the SDK ISR clears every status
		 * bit it reads. After a session the interrupt mask is live and comes
		 * back from the AON array on wake, so a wake-time IRQ can consume the
		 * flag before this spin sees it. A part that answers with its DEV_ID
		 * is awake regardless of who read the flag first; one that answers
		 * with nothing is still down, and gets another toggle. */
		uint32_t id = dwt_readdevid();

		if ((id & 0xFFFFFF00u) == 0xDECA0300u) {
			LOG_WRN("WAKEUP: IDLE_RC flag not seen, DEV_ID 0x%08x answers; awake",
				(unsigned)id);
			return;
		}
		LOG_WRN("WAKEUP: attempt %d, no IDLE_RC, DEV_ID 0x%08x; toggling CS again",
			attempt, (unsigned)id);
	}
	/* Left marked awake: the caller's DEV_ID check now fails and it rebuilds
	 * the radio from a hard reset, which is the only wake that cannot miss. */
	LOG_ERR("WAKEUP: chip never reached IDLE_RC (3 CS toggles)");
}

/** set WAKEUP pin low if available */
void dw3000_hw_wakeup_pin_low(void)
{
	if (conf.gpio_wakeup.port) {
		gpio_pin_set_dt(&conf.gpio_wakeup, 0);
	}
}
