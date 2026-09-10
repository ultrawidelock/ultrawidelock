/* SPDX-License-Identifier: ISC */

/*
 * DWM3001CDK standalone credential reader.
 *
 * One board: the nRF52833 runs the BLE peripheral and the credential reader engine,
 * and the DW3110 in the same DWM3001C module does the UWB ranging. No host MCU
 * board, no seated DWM3000EVB, no NFC (the CDK has none).
 *
 * Stage 0 keeps main deliberately thin. Its job is to hold the whole call graph
 * live so the linker cannot garbage-collect the engine and hand back a size
 * number that flatters us.
 */
#include <errno.h>
#include <string.h>

#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>
#include <zephyr/usb/usb_device.h>

#include "ultrawidelock_approach.h"
#include "ultrawidelock_lat.h"
#include "ultrawidelock_prov.h" /* ultrawidelock_prov_erase, for the factory-reset button */
#include <ultrawidelock/reader.h>
#include <ultrawidelock/uwb.h>

#include "rtt_bench.h" /* `trust` / `prov` typed at the RTT terminal */
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_BLE)
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_CLIENT)
#include "matter_client.h"
#endif
#include "matter_commission.h"
#include "uwb_matter_presence.h"
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_THREAD_DATASET_DUMP)
#include <matter_thread.h> /* bench-only dataset disclosure; see the main loop */
#endif
#include "matter_fab_settings.h" /* matter_fab_erase, the Matter half of a reset */
#endif
#include "ml_feed.h" /* channel-classifier glue; plain feed when ML is off */
#include "status_led.h"
#include "uwb_cirdiag.h" /* latched Ipatov scalars, for the channel classifier */
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR)
#include "ultrawidelock_satellite.h" /* second-anchor verdict; gates PREDICT only */
#endif
/* The sensors are ANCHOR's; the event they raise is the Matter node's. An
 * anchor build with no Matter in it has nowhere to put an alarm. */
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR) && IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_BLE)
#include "door_alarm.h" /* impact latch + swing angle -> DoorLockAlarm */
#endif
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_INSIDE_LATCH)
#include "ultrawidelock_latch.h" /* persistent inside veto layered over the side gate */
#include "ultrawidelock_hash.h" /* SHA-256, for the credential's non-identifying name */
#include <zephyr/settings/settings.h>
#endif
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_SEALED_LINK)
#include "witness_link.h"
#endif
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_SIDE_GATE)
#include "ultrawidelock_side.h" /* fail-closed OUTSIDE-only passive unlock gate */
#include "ultrawidelock_side_log.h"
#include "side_feed.h"
#if defined(CONFIG_ULTRAWIDELOCK_CRED_LAB)
#include "ultrawidelock_log.h"
#include "ultrawidelock_port.h"
#endif
#endif
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR_SLAM)
#include "ultrawidelock_slam.h"
#include "ultrawidelock_slam_hw.h"
#endif

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_DFU_RECEIVER)
/* src/dfu_ble_zephyr.c. One function, so it carries no header of its own. */
int dfu_ble_start(void);
#endif

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_HEAP_PROBE)
#include <mbedtls/memory_buffer_alloc.h>
#endif

LOG_MODULE_REGISTER(main, CONFIG_LOG_DEFAULT_LEVEL);

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_HEAP_PROBE)
/* Reported at the grant, because by then the unlock has done every P-256 and
 * AES-GCM operation it is going to do. The peak is cumulative since boot, so it
 * covers BLE pairing and the credential exchange too, not only the ranging. */
static void heap_peak_log(const char *when)
{
	size_t used = 0;
	size_t blocks = 0;

	mbedtls_memory_buffer_alloc_max_get(&used, &blocks);
	LOG_INF("mbedtls heap peak @%s: %u B of %u (%u blocks)", when,
		(unsigned int)used, (unsigned int)CONFIG_MBEDTLS_HEAP_SIZE,
		(unsigned int)blocks);
}
#endif /* CONFIG_ULTRAWIDELOCK_HEAP_PROBE */

/* The per-frame UWB diagnostic trace (DIAGK) defaults ON for nRF targets but OFF
 * for the ESP32, because its printf on every ranging frame blocks the callback
 * long enough to miss the DW3110 delayed-TX slot deadline -- the ESP port disables
 * it for exactly that reason (bench-correlated late RESPONSE arms). What shell this
 * board has exists only in provisioning mode, where the radios never start, so
 * `uwbdiag off` can never be typed at a walk-up; force it off here before any
 * ranging starts. See modules/ultrawidelock_uwb/include/ultrawidelock_diag.h. */
extern volatile int ultrawidelock_uwb_diag_on;

/* Reader status housekeeping: the engine expects a periodic tick to age out a
 * stalled transaction and to drive the ranging power gate's decay. 250 ms is
 * the cadence the ESP32 port runs. */
#define ULTRAWIDELOCK_TICK_MS 250

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_SIDE_GATE)
/* Liveness watchdog on the witness feed, which is NOT the same question as
 * ultrawidelock_side_cfg::evidence_fresh_ms. That one asks "how old is the committed
 * decision at the moment a feed arrives"; this one asks "is anything still
 * feeding us at all". Sizing them the same breaks the gate: witnesses summarise
 * over WITNESS_WINDOW_MS (2000), so SF1 lands about every 2 s and a 1500 ms
 * watchdog would expire between every pair of feeds and hold the gate shut
 * forever. 5 s survives one dropped window plus margin, and still shuts the
 * gate within seconds of a witness link dying. Must stay above 2x the feed
 * period: shorten it if WITNESS_WINDOW_MS is ever cut. */
#define SIDE_FEED_WATCHDOG_MS 5000

/* A vetoed unlock is re-offered on every trusted range, so the deny line needs
 * a floor or it buries everything else on the console during a walk-up. */
#define SIDE_DENY_LOG_MS 1000
#endif

/* How long the ranging LED holds after the last range landed. Four ticks: long
 * enough that no rate iOS ranges at can make it stutter, short enough that a
 * phone put in a pocket drops the light while the person is still in the room. */
#define ULTRAWIDELOCK_LED_RANGE_HOLD_MS 1000

/* Wakes the grant loop the moment a range is latched, instead of on the next
 * 250 ms tick.
 *
 * The tick alone quantized every unlock and relock by 0-250 ms on top of the
 * structural ~1 s trust floor, and worse, 250 ms beats against the 192 ms
 * ranging block, so the delay a walk-up got was a lottery rather than a
 * constant. The tick REMAINS as the take timeout: it is still what ages out a
 * stalled transaction and decays the power gate when no range is arriving.
 *
 * Count limit 1 because the loop reads the generation counter, not a queue --
 * two latches between wakes still mean exactly one pass.
 *
 * Declared and initialised separately rather than with K_SEM_DEFINE: semgrep's
 * C parser cannot read that macro at file scope, and the security gate treats
 * an unparseable file as zero rule coverage rather than a clean result, which
 * would silently drop every rule that guards this file. */
static struct k_sem s_range_sig;

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR_LINK)
/* The fusion state lives in main()'s frame; the transport callback needs a way
 * to reach it without the transport knowing what it is. */
static struct ultrawidelock_satellite_set *s_satellite;

/**
 * A sealed, replay-checked distance from the second anchor.
 *
 * Stores only, into THAT ROLE'S slot. The pairing decision is not taken here
 * and must not be: which of OUR measurements this one belongs with is settled
 * by its ranging block when the verdict is asked for, against the ring of
 * recent samples -- so a report that took a block or two to arrive still finds
 * its partner instead of being matched against whatever we happen to hold right
 * now.
 *
 * Routing on the role is what lets two satellites report into the same block.
 * One deployed satellite is the shipping case and takes the same path it always
 * did; the roles it does not use stay absent, and absence permits.
 */
static void on_anchor_report(uint8_t role, int32_t peer_mm, uint32_t ranging_block, int64_t now_ms)
{
	if (s_satellite != NULL) {
		ultrawidelock_satellite_set_report(s_satellite, role, peer_mm, ranging_block,
						   now_ms);
	}
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR_PAIR_LOG)
	/*
	 * Runs on the OpenThread RX thread, not the ranging callback, so the
	 * synchronous-print hazard that forces the per-frame trace off does not
	 * apply here. RTT is in no-block-skip mode besides: a full buffer costs
	 * this line, never the caller's timing.
	 *
	 * Logged at the sink rather than left to the pairing code because an
	 * unpaired report and a report that never arrived are the same silence
	 * otherwise, and they have completely different causes.
	 */
	LOG_INF("anchor role=%u report blk=%u mm=%d", (unsigned)role, (unsigned)ranging_block,
		(int)peer_mm);
#endif
}
#endif

/**
 * Wake the grant loop on an accepted range latch. Runs on the UWB RX path, so it does nothing but
 * give the semaphore -- the float math in the approach controller stays on the main thread.
 */
static void on_range_latched(void)
{
	(void)ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_FIRST_RANGE);
	k_sem_give(&s_range_sig);
}

/* Provisioning mode: hold SW2 (the board's sw0 alias, P0.02) through reset.
 *
 * The reader identity is per-device data in the settings store, never a string
 * in the image, so it has to arrive at runtime. This board's only input path is
 * the USB device port wired straight to the nRF52833 -- RTT is output-only --
 * so provisioning mode brings up CDC-ACM and the `ultrawidelock` console on it.
 *
 * The radios stay down in this mode on purpose. It keeps USB's millisecond SOF
 * interrupts away from the DW3110's delayed-TX reply window (the timing that
 * commit 5b8d06b had to fight for on this single-core part), and it means the
 * console can never be reached while a walk-up is in flight. */
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_PROV_CONSOLE)
/**
 * Check GPIO SW0 (active-low, pulled up in DTS) to see if provisioning is requested at boot.
 * Returns true if SW0 is ready and held (logical 1), false otherwise.
 */
static bool provisioning_requested(void)
{
	static const struct gpio_dt_spec sw = GPIO_DT_SPEC_GET(DT_ALIAS(sw0), gpios);

	if (!gpio_is_ready_dt(&sw)) {
		return false;
	}
	if (gpio_pin_configure_dt(&sw, GPIO_INPUT) != 0) {
		return false;
	}
	/* Active low with a pull-up in the board DTS; _dt() returns logical level. */
	return gpio_pin_get_dt(&sw) == 1;
}

/* Runs the console and nothing else. Never returns: leaving this function would
 * start the radios in a mode the user did not ask for. */
static void provisioning_mode(void)
{
	int rc = usb_enable(NULL);

	/* Solid blue for as long as this mode lasts. Provisioning looks exactly
	 * like a hung boot from the outside otherwise -- the radios are down, so
	 * nothing else on the board moves. */
	status_led_signal(STATUS_LED_PROV_MODE, true);

	if (rc != 0) {
		/* Nothing to fall back to: without USB there is no input path at
		 * all on this board, so say so on RTT and stop. */
		LOG_ERR("provisioning mode: usb_enable rc=%d, no console available", rc);
	} else {
		LOG_INF("provisioning mode: USB console up, radios down");
	}

	while (1) {
		k_msleep(1000);
	}
}
#endif /* CONFIG_ULTRAWIDELOCK_PROV_CONSOLE */

/* Factory reset: hold SW2 (the sw0 alias, P0.02) through reset.
 *
 * WITHOUT THIS THE BOARD IS A BRICK AFTER A FAILED PAIRING, which is not a
 * bench annoyance but the ordinary failure. A commissioning that gets far
 * enough to install a fabric and then times out leaves the fabric stored; the
 * advert gate then offers credential 0xFFF2 instead of commissionable; the
 * controller can neither discover the node nor open a commissioning window on
 * an accessory it has already forgotten. On 2026-08-02 that state was reached
 * four times in one evening and cleared four times with a debugger. A user has
 * no debugger.
 *
 * Held through reset rather than long-pressed while running: it matches the
 * provisioning console's idiom on this same button, needs no timer, no
 * debounce and no thread on a part at 96% RAM, and cannot fire while a walk-up
 * is in flight.
 *
 * The Thread credentials are deliberately NOT erased -- see ultrawidelock_prov_erase().
 */
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_FACTORY_RESET_BUTTON)
/**
 * Check GPIO SW0 (active-low, pulled up in DTS) at boot. If SW0 is held (logical 1), blink the lock
 * LED as user feedback, erase credential provisioning and Matter fabric (if
 * CONFIG_ULTRAWIDELOCK_MATTER_BLE is on), and log that the board is now commissionable on the next
 * boot. Returns silently if GPIO is not ready or if SW0 is not held.
 */
static void factory_reset_if_requested(void)
{
	static const struct gpio_dt_spec sw = GPIO_DT_SPEC_GET(DT_ALIAS(sw0), gpios);

	if (!gpio_is_ready_dt(&sw) || gpio_pin_configure_dt(&sw, GPIO_INPUT) != 0) {
		return;
	}
	/* Active low with a pull-up in the board DTS; _dt() returns logical level. */
	if (gpio_pin_get_dt(&sw) != 1) {
		return;
	}

	LOG_WRN("SW2 held at boot: FACTORY RESET");
	/*
	 * The only feedback this board can give someone without a debugger. RTT
	 * says it too, but a user holding a button needs to see that the hold
	 * was long enough and registered. Blocking, and it goes through
	 * status_led.c because that owns the pin from SYS_INIT onwards -- driving
	 * it from here as well would put the blink and the heartbeat on the same
	 * lamp, 120 ms apart.
	 */
	status_led_boot_blink();

	(void)ultrawidelock_prov_erase();
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_BLE)
	(void)matter_fab_erase();
#endif
	LOG_WRN("factory reset done; commissionable on the next boot");
}
#endif

/**
 * Entry point for the DWM3001CDK reader application. Initializes provisioning and factory-reset
 * paths, starts the credential BLE reader and optional Matter commissioning and DFU receiver, then
 * runs the approach controller loop. Feeds the controller trusted ranges on each new latch
 * generation and observes untrusted ranges for departure detection. Grants unlock on approach
 * prediction or threshold crossing, relocks on departure or abort, and exits with an error code if
 * reader startup fails.
 */
/* How long the departure fallback holds an open bolt through the iOS
 * phase-deadline flap before treating the dead session as a walk-away. Only
 * entered when the controller was fed a range inside relock_cm moments before
 * the session died -- a phone the evidence puts AT the door (measured
 * 2026-08-21: flap at 16 cm, reconnect 4.2 s later; the immediate relock shut
 * the bolt under the owner's hand). Departures don't look like that: the far
 * tiers relock on ranges, not on the session. 10 s covers the observed
 * reconnect with margin while bounding how long a real walk-away that never
 * reconnects can leave the bolt open.
 *
 * Outside the latch guard: the departure fallback is in every image, latch or
 * not, so the constants it reads have to be too. */
#define SESSION_FLAP_HOLD_MS 10000
#define SESSION_FLAP_FEED_FRESH_MS 3000

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_INSIDE_LATCH)
/*
 * The inside veto. The side gate classifies each window; this decides what a
 * run of those classifications is allowed to authorise, and its resting state
 * is INSIDE. File scope because the settings handler has to reach it, and
 * static because that is the point -- the belief outlives the session, the
 * reboot, and the witnesses.
 */
static struct ultrawidelock_latch s_latch;
static bool s_latch_dirty;

/*
 * The latch key, per credential and non-identifying.
 *
 * ultrawidelock_assert_cred_id() is already this tree's answer to "name a
 * credential without naming a person": the first 8 bytes of SHA-256 over the
 * credential's public key, stable for the life of the credential and derivable
 * only by something that already holds the public key. The latch takes the top
 * 32 bits of that, which is a name for a record and never leaves the device.
 *
 * Zero is reserved for "no authenticated credential". It is not a record and
 * can never be granted: evidence that cannot be attributed to a credential
 * must not accumulate against one, so the session stays closed until the
 * reader can say whose it is.
 */
#define LATCH_CRED_NONE 0x00000000u

/* How long a credential-session gap still counts as the SAME approach --
 * the latch twin of SESSION_CARRY_MS in witness_link.c. iOS tears the
 * session down on its credential phase deadline and reconnects within
 * seconds, mid-walk; closing the latch session on that flap zeroes the
 * clear-run at the moment it completes (measured 2026-08-21: agree hit
 * clear_windows as the session flapped, and with the phone then at the
 * door no run could restart beyond clear_min_mm -- why=0x10 for good). */
#define LATCH_SESSION_CARRY_MS 30000

static uint32_t latch_cred_id(void)
{
	uint8_t cred_pub[65];
	uint8_t digest[ULTRAWIDELOCK_SHA256_LEN];
	uint32_t v;

	if (!ultrawidelock_reader_authenticated_credential(cred_pub)) {
		return LATCH_CRED_NONE;
	}
	/* The same construction ultrawidelock_assert_cred_id() uses -- SHA-256
	 * over the credential public key -- computed here rather than called,
	 * because ultrawidelock_assert is not linked into this image and
	 * pulling it in for four bytes of digest would cost more than it says. */
	ultrawidelock_sha256(cred_pub, sizeof(cred_pub), digest);
	v = ((uint32_t)digest[0] << 24) | ((uint32_t)digest[1] << 16) |
	    ((uint32_t)digest[2] << 8) | (uint32_t)digest[3];
	/* Two reserved values must never be minted from a real credential: zero
	 * means "nobody", and CRED_ANY addresses every record at once. A
	 * collision is a 1-in-2^31 event and costs that credential nothing but
	 * a different record number. */
	if (v == LATCH_CRED_NONE || v == ULTRAWIDELOCK_LATCH_CRED_ANY) {
		v = 1u;
	}
	return v;
}

static int latch_settings_set(const char *name, size_t len, settings_read_cb read_cb, void *cb_arg)
{
	uint8_t blob[ULTRAWIDELOCK_LATCH_BLOB_LEN];
	ssize_t got;

	if (strcmp(name, "rec") != 0 || len > sizeof(blob)) {
		return -ENOENT;
	}
	got = read_cb(cb_arg, blob, sizeof(blob));
	if (got <= 0) {
		return -EINVAL;
	}
	/* A rejected blob leaves the latch initialised-and-empty, which reads
	 * INSIDE for everyone. Corruption must not be recoverable into a
	 * permissive state.
	 *
	 * The cfg must survive the reload: deserialize re-inits, and passing
	 * NULL there re-inits to the code defaults -- which silently undid
	 * every ULTRAWIDELOCK_LATCH_* Kconfig on any boot that had records to
	 * load (measured 2026-08-21: a 5000 ms entry dwell ran as 60000).
	 * Copied out first because deserialize memsets the latch it is given. */
	struct ultrawidelock_latch_cfg cfg = s_latch.cfg;

	if (!ultrawidelock_latch_deserialize(&s_latch, &cfg, blob, (size_t)got)) {
		LOG_WRN("latch records unreadable; every credential reads INSIDE");
	}
	return 0;
}

SETTINGS_STATIC_HANDLER_DEFINE(uwl_latch, "uwl/latch", NULL, latch_settings_set, NULL, NULL);

static void latch_save(void)
{
	uint8_t blob[ULTRAWIDELOCK_LATCH_BLOB_LEN];
	size_t n;

	if (!s_latch_dirty) {
		return;
	}
	s_latch_dirty = false;
	n = ultrawidelock_latch_serialize(&s_latch, blob, sizeof(blob));
	if (n == 0u || settings_save_one("uwl/latch/rec", blob, n) != 0) {
		LOG_ERR("latch records could not be saved");
	}
}

/* Any door opening at all re-asserts INSIDE. Called from every grant path the
 * main loop can see, deliberate ones included: a phone that just walked
 * through the door is inside regardless of what opened it. */
static void latch_note_opened(uint32_t cred_id, int64_t now_ms)
{
	if (cred_id == LATCH_CRED_NONE) {
		return;
	}
	ultrawidelock_latch_note_grant(&s_latch, cred_id, now_ms);
	s_latch_dirty = true;
	latch_save();
}
#endif

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR_LINK)
/* Anchor separation set at runtime (BL over RTT down), persisted so a bench
 * rearrangement survives the reboot. 0 = never set; the Kconfig rules then. */
static int32_t s_baseline_saved;

static int anchor_settings_set(const char *name, size_t len, settings_read_cb read_cb,
			       void *cb_arg)
{
	int32_t v;

	if (strcmp(name, "bl") != 0 || len != sizeof(v)) {
		return -ENOENT;
	}
	if (read_cb(cb_arg, &v, sizeof(v)) != (ssize_t)sizeof(v)) {
		return -EINVAL;
	}
	if (v >= 300 && v <= 10000) {
		s_baseline_saved = v;
	}
	return 0;
}

SETTINGS_STATIC_HANDLER_DEFINE(uwl_anchor, "uwl/anchor", NULL, anchor_settings_set, NULL, NULL);

/* The frontier moves WITH the baseline. What the configured pair fixes is the
 * gap between the frontier and the inside anchor -- (BASELINE - BIAS) / 2 --
 * so a new baseline keeps that gap rather than the raw bias: reusing 1000
 * against a 1000 mm baseline would sit exactly on the degenerate limit the
 * Kconfig help warns about. A configured bias of 0 (bisector install) stays 0
 * at every separation. */
static int32_t baseline_bias(int32_t baseline_mm)
{
	const int32_t gap = CONFIG_ULTRAWIDELOCK_ANCHOR_BASELINE_MM -
			    CONFIG_ULTRAWIDELOCK_ANCHOR_BOUNDARY_BIAS_MM;

	if (CONFIG_ULTRAWIDELOCK_ANCHOR_BOUNDARY_BIAS_MM == 0) {
		return 0;
	}
	return baseline_mm > gap ? baseline_mm - gap : 0;
}

static void baseline_apply(struct ultrawidelock_satellite_set *set, int32_t mm, bool save)
{
	/*
	 * Role 1's slot only. The RTT calibration below measures the separation
	 * to the satellite that is answering, and role 1 is the one a
	 * one-satellite lock has -- so this stays exactly the number it was
	 * before the set existed. Roles 2 and 3 keep their configured
	 * baselines: a separation measured against one board is not the
	 * separation to another, and writing it into their slots would size
	 * their triangle test for the wrong geometry.
	 */
	struct ultrawidelock_satellite *sat = &set->peer[0];

	sat->cfg.baseline_mm = mm;
	sat->cfg.boundary_bias_mm = baseline_bias(mm);
	LOG_INF("anchor baseline %d mm (frontier bias %d)", mm,
		sat->cfg.boundary_bias_mm);
	if (save && settings_save_one("uwl/anchor/bl", &mm, sizeof(mm)) != 0) {
		LOG_ERR("baseline not saved");
	}
}
#endif

#define UWB_POLICY_BOUND_RELOCK 0x01u
#define UWB_POLICY_BOUND_UNLOCK 0x02u
#define UWB_POLICY_LOCK_RELOCK  0x04u
#define UWB_POLICY_LOCK_UNLOCK  0x08u
#define UWB_POLICY_ALL          0x0Fu

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_BLE)
static void apply_uwb_config(struct ultrawidelock_approach *approach,
			     uint8_t *policy_flags)
{
	struct matter_uwb_config config;

	if (!matter_commission_take_uwb_config(&config)) {
		return;
	}
	approach->cfg.unlock_cm = config.unlock_cm;
	approach->cfg.approach_cm = config.approach_cm;
	approach->cfg.relock_cm = config.relock_cm;
	approach->cfg.motor_ms = config.motor_ms;
	*policy_flags = config.policy_flags;
}
#endif

static bool uwb_policy_enabled(uint8_t policy_flags, uint8_t policy)
{
	return (policy_flags & policy) != 0u;
}

int main(void)
{
	/* Off before the radio comes up: keeps the ranging callbacks print-free so the
	 * delayed RESPONSE/FINAL TX can hit its microsecond turnaround. */
	ultrawidelock_uwb_diag_on = 0;

	/* ASCII only: the console is a byte stream, and a UTF-8 dash renders as
	 * mojibake in RTT Viewer. */
	LOG_INF("ultrawidelock reader: DWM3001CDK (nRF52833 + DW3110)");

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_PROV_CONSOLE)
	if (provisioning_requested()) {
		provisioning_mode(); /* never returns */
	}
#endif

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_FACTORY_RESET_BUTTON)
	factory_reset_if_requested();
#endif

	int rc = ultrawidelock_reader_start();

	if (rc != 0) {
		LOG_ERR("ultrawidelock_reader_start rc=%d", rc);
		/* main() is about to return and this board has no console, so a
		 * solid D12 is the only account anyone gets of why it does
		 * nothing. The LED tick lives on the system work queue and
		 * outlives this thread, so the light stays on. */
		status_led_signal(STATUS_LED_FAULT, true);
		return rc;
	}

#if defined(CONFIG_ULTRAWIDELOCK_ML_LOS) && defined(CONFIG_ULTRAWIDELOCK_UWB_CIRDIAG)
	/*
	 * The classifier is this image's consumer of the CIA latch, and nothing else
	 * arms it: the capture-cycle thread is CONFIG_ULTRAWIDELOCK_CIRDIAG_CAPTURE (not set
	 * here) and the console shell is a DK-only path. Safe before the radio is
	 * probed -- the chip-side CIA enable happens lazily inside the first armed
	 * reception. The first mlgate walk (2026-08-07) printed zero [ALAB] lines
	 * precisely because nothing did this.
	 */
	uwb_cirdiag_set_enabled(true);
#endif

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_BLE)
	/* After the reader, because the reader owns BLE and the advertising set;
	 * this only attaches handlers to the 0xFFF6 transport that SYS_INIT
	 * already brought up. */
	(void)matter_commission_init();
#endif

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_DFU_RECEIVER)
	/* Also after the reader, and for the same reason: registering an L2CAP
	 * PSM needs the host up, and the reader is what enables it. The channel
	 * refuses every connection until SW2 opens a window, so registering it
	 * here costs nothing an idle board can be reached through. */
	(void)dfu_ble_start();
#endif

	/* Bridge the trusted UWB range stream to the Wallet grant.
	 *
	 * ultrawidelock_reader_start brings up BLE and the CCC/FiRa ranging engine, and the engine
	 * latches a trust-gated distance (fira_session) on every good block -- but nothing
	 * consumes it on its own. The shipped Matter lock wires this in its app_main
	 * (apps/esp32-matter-lock): trusted range -> approach controller -> on UNLOCK,
	 * ultrawidelock_reader_notify_unlock(true), which sends Reader Status = Unsecured and animates
	 * the phone. The standalone reader has to do the same or a perfectly good range never
	 * becomes an unlock. There is no bolt on this board: the grant IS the product.
	 *
	 * Static: the struct carries two 5-entry sample windows plus the filter and
	 * grew past trivial; the 4 KB main stack is not the place to discover that,
	 * and in .bss the cost shows up in the measured RAM budget instead. */
	static struct ultrawidelock_approach approach;
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR)
	/*
	 * Second-anchor geometry. Nothing feeds this yet -- the satellite
	 * transport is not wired up -- and that is a working
	 * state rather than a gap: with no report the verdict is UNKNOWN, UNKNOWN
	 * permits prediction, and the door behaves exactly as it does today.
	 */
	static struct ultrawidelock_satellite_set satellite;
	/* One geometry per role: the baseline is the distance to THAT satellite,
	 * and the tolerances are properties of the ranging, so they are shared.
	 * Roles 2 and 3 default to a zero baseline, which this tree already reads
	 * as "no satellite mounted" -- so a one-satellite lock is configured
	 * exactly as it is today and behaves exactly as it does today. */
	const struct ultrawidelock_fusion_cfg fusion_cfg[ULTRAWIDELOCK_SATELLITE_MAX_ROLES] = {
		{
			.baseline_mm = CONFIG_ULTRAWIDELOCK_ANCHOR_BASELINE_MM,
			.tol_mm = CONFIG_ULTRAWIDELOCK_ANCHOR_TOL_MM,
			.deadband_mm = CONFIG_ULTRAWIDELOCK_ANCHOR_DEADBAND_MM,
			.boundary_bias_mm = CONFIG_ULTRAWIDELOCK_ANCHOR_BOUNDARY_BIAS_MM,
		},
		{
			.baseline_mm = CONFIG_ULTRAWIDELOCK_ANCHOR_BASELINE_2_MM,
			.tol_mm = CONFIG_ULTRAWIDELOCK_ANCHOR_TOL_MM,
			.deadband_mm = CONFIG_ULTRAWIDELOCK_ANCHOR_DEADBAND_MM,
			.boundary_bias_mm = CONFIG_ULTRAWIDELOCK_ANCHOR_BOUNDARY_BIAS_MM,
		},
		{
			.baseline_mm = CONFIG_ULTRAWIDELOCK_ANCHOR_BASELINE_3_MM,
			.tol_mm = CONFIG_ULTRAWIDELOCK_ANCHOR_TOL_MM,
			.deadband_mm = CONFIG_ULTRAWIDELOCK_ANCHOR_DEADBAND_MM,
			.boundary_bias_mm = CONFIG_ULTRAWIDELOCK_ANCHOR_BOUNDARY_BIAS_MM,
		},
	};

	ultrawidelock_satellite_set_init(&satellite, fusion_cfg,
					 CONFIG_ULTRAWIDELOCK_ANCHOR_STALE_MS,
					 IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR_SELF_INSIDE));
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR_LINK)
	(void)settings_load_subtree("uwl/anchor");
	if (s_baseline_saved != 0) {
		baseline_apply(&satellite, s_baseline_saved, false);
	}
	/* BL cal: median over this many paired rounds. The phone is held still,
	 * so block alignment is irrelevant; 25 rounds is a few seconds. */
	static int32_t bl_cal[25];
	static uint8_t bl_cal_n;
	static bool bl_cal_on;
#endif
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR_LINK)
	/* Before witness_link_init(), so no datagram can arrive with the sink
	 * still unset. */
	s_satellite = &satellite;
	witness_link_set_anchor_cb(on_anchor_report);
	/* The other direction: hand each session's join parameters to the second
	 * anchor over the same sealed link, so no console relay is involved. */
	ultrawidelock_uwb_set_handoff_listener(witness_link_send_handoff);
#endif
#endif
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR) && IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_BLE)
	/* Door alarms. The ajar half waits on the same missing transport as the
	 * satellite verdict above; the forced-open half is live below. */
	door_alarm_init();
#endif
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_SIDE_GATE)
	/*
	 * Fail-closed side gate. BLE witness summaries arrive as SF1 lines on
	 * RTT down (lab) via side_feed_*; without them every evaluate stays
	 * UNKNOWN / quorum-fail and passive unlock is withheld. NFC Express
	 * Mode and Home commands are not routed through this switch.
	 */
	static struct ultrawidelock_side_filter side_filt;
	static struct ultrawidelock_side_decision side_dec;
	static struct ultrawidelock_side_cfg side_cfg;
	/* When the last feed landed. side_dec is a snapshot, and the filter can
	 * only age it while it is being fed -- so a feed that stops right after
	 * committing OUTSIDE would leave the grant live forever. Observed: a lab
	 * injector was killed and the lock still opened on the next walk-up. */
	int64_t side_feed_ms = 0;
	int64_t side_deny_log_ms = 0;

	ultrawidelock_side_defaults(&side_cfg);
	side_cfg.rssi_outside_margin_db = CONFIG_ULTRAWIDELOCK_SIDE_OUTSIDE_MARGIN_DB;
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR_LINK)
	/*
	 * Quorum follows the anchors this build actually has. The default is the
	 * BLE witness pair, and with the witnesses retired that is a mask nothing
	 * can ever satisfy -- the gate then withholds every passive unlock for a
	 * reason that has nothing to do with where the phone is. Requiring the two
	 * UWB anchors instead keeps the rule identical in shape: two independent
	 * anchors, both healthy, or no decision.
	 */
	side_cfg.quorum_mask = (uint8_t)(ULTRAWIDELOCK_SIDE_ANCHOR_PRIMARY_UWB |
					 ULTRAWIDELOCK_SIDE_ANCHOR_UWB_SATELLITE);
#endif
	ultrawidelock_side_filter_init(&side_filt, &side_cfg);
	{
		/* Boot: no witnesses yet => UNKNOWN + quorum fail (fail-closed). */
		struct ultrawidelock_side_features absent;

		memset(&absent, 0, sizeof(absent));
		absent.now_ms = k_uptime_get();
		absent.uwb_range_mm = -1;
		absent.uwb_vel_mm_s = INT32_MIN;
		absent.ble_rssi_inside_dbm = INT16_MIN;
		absent.ble_rssi_outside_dbm = INT16_MIN;
		absent.ble_rssi_threshold_dbm = INT16_MIN;
		absent.uwb_peer_mm = -1;
		absent.classifier_ver = side_cfg.classifier_ver;
		absent.calibration_ver = side_cfg.calibration_ver;
		absent.flags = ULTRAWIDELOCK_SIDE_F_QUORUM_FAIL;
		side_dec = ultrawidelock_side_filter_feed(&side_filt, &absent);
	}
#endif
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_INSIDE_LATCH)
	{
		struct ultrawidelock_latch_cfg latch_cfg;

		ultrawidelock_latch_defaults(&latch_cfg);
		latch_cfg.entry_dwell_ms = CONFIG_ULTRAWIDELOCK_LATCH_ENTRY_DWELL_MS;
		latch_cfg.clear_windows = CONFIG_ULTRAWIDELOCK_LATCH_CLEAR_WINDOWS;
		latch_cfg.clear_min_mm = CONFIG_ULTRAWIDELOCK_LATCH_CLEAR_MIN_MM;
		latch_cfg.clear_valid_ms = CONFIG_ULTRAWIDELOCK_LATCH_CLEAR_VALID_MS;
		ultrawidelock_latch_init(&s_latch, &latch_cfg);
		/* Records land through the settings handler. A load that never
		 * happens leaves every credential reading INSIDE, which is the
		 * state an uncommissioned lock should be in. */
		(void)settings_load_subtree("uwl/latch");
	}
	static uint8_t latch_why;
	/* Which credential the open latch session belongs to, or CRED_NONE. */
	uint32_t latch_cred = LATCH_CRED_NONE;
	/* Nonzero while that credential's session is down but within
	 * LATCH_SESSION_CARRY_MS: the uptime when the gap began. */
	int64_t latch_gap_ms = 0;
#endif
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_SEALED_LINK)
	witness_link_init();
#endif
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR_SLAM)
	static struct ultrawidelock_slam_state slam;
	const struct ultrawidelock_slam_cfg slam_cfg = {
		.debounce_ms = ULTRAWIDELOCK_SLAM_DEBOUNCE_MS_DEFAULT,
		.tamper_window_ms = ULTRAWIDELOCK_SLAM_TAMPER_WINDOW_MS_DEFAULT,
		.tamper_count = ULTRAWIDELOCK_SLAM_TAMPER_COUNT_DEFAULT,
	};

	ultrawidelock_slam_init(&slam);
	/* A board with no accelerometer, or one that will not answer, loses the
	 * tamper signal and keeps the lock. Nothing below depends on it. */
	if (ultrawidelock_slam_hw_init() != 0) {
		LOG_WRN("no impact sensor; tamper detection is off");
	}
#endif

	/* Factory defaults: unlock 100 cm, relock 250 cm, and a trajectory gate
	 * at 180 cm -- no auto-unlock until the credential has been seen that
	 * far out in this session, so a phone that was already at the door when
	 * ranging started does not open it. See ultrawidelock_approach_cfg::approach_cm. */
	ultrawidelock_approach_init(&approach, NULL);
	approach.cfg.near_dwell = CONFIG_ULTRAWIDELOCK_APPROACH_NEAR_DWELL;
	uint8_t policy_flags = UWB_POLICY_ALL;

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_BLE)
	apply_uwb_config(&approach, &policy_flags);
	uwb_matter_presence_init();
#endif

	/* Same seam the ESP32 matter-lock uses (app_main.cpp on_uwb_range): the engine
	 * signals, this thread decides. Both lines run before the listener can fire --
	 * the semaphore has to exist before anything is allowed to give it, and the
	 * controller has to be initialised before a signal can reach it. */
	k_sem_init(&s_range_sig, 0, 1);
	ultrawidelock_uwb_set_range_listener(on_range_latched);

	uint32_t last_gen = ultrawidelock_uwb_range_generation();
	/* The last range OBSERVED for departure, trusted or not; see the loop. */
	uint32_t last_obs_gen = last_gen;
	/* Block of the trusted range below, taken from the same latch as its
	 * distance so the two always describe each other. */
	uint32_t last_obs_block = 0u;
	/* A third epoch, for the activity LED alone. The two above are consumed
	 * at different moments on purpose -- that is what keeps a late-trusted
	 * latch from being counted twice and what stops the silence clock being
	 * refreshed -- so folding a light into either would change when a relock
	 * fires. This one is read-only with respect to the unlock logic. */
	uint32_t led_gen = last_gen;
	int64_t led_range_ms = 0;
	bool present = false;
	bool granted = false;
	/* Rising-edge detector for the credential session, which is what arms the
	 * trajectory gate. See ultrawidelock_approach_session_up(). */
	bool session_was_up = false;

	while (1) {
		int64_t now = k_uptime_get();
		uint32_t gen = ultrawidelock_uwb_range_generation();
		int32_t cm = 0;
		enum ultrawidelock_approach_action act;

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_BLE)
		apply_uwb_config(&approach, &policy_flags);
#endif

		ultrawidelock_reader_status_tick(now);
		rtt_bench_poll();
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_THREAD_DATASET_DUMP)
		/*
		 * BENCH ONLY, and it prints the Thread network key. The other
		 * trigger is a commissioning window opening, which needs a
		 * controller that is talking to you -- not much use when the
		 * dataset is wanted precisely because the controller is not.
		 * Retried rather than tried once because the dataset does not
		 * exist until the node attaches, and how long that takes is
		 * not something this loop should have to know.
		 */
		static bool dataset_dumped;

		if (!dataset_dumped && matter_thread_dump_active_dataset() == 0) {
			dataset_dumped = true;
		}
#endif
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_SEALED_LINK)
		witness_link_tick(now);
#endif
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_SIDE_GATE)
		{
			struct ultrawidelock_side_features feat;

			side_feed_rtt_poll();
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR_LINK)
			{
				int32_t bl_mm;

				switch (side_feed_take_baseline(&bl_mm)) {
				case 1:
					baseline_apply(&satellite, bl_mm, true);
					break;
				case 2:
					bl_cal_n = 0;
					bl_cal_on = true;
					LOG_INF("baseline cal: hold the phone still ~1 m past the DK");
					break;
				default:
					break;
				}
			}
#endif
			if (side_feed_take(&feat)) {
				feat.now_ms = now;
				if (feat.obs_session_id == 0) {
					feat.obs_session_id = 1;
				}
				feat.classifier_ver = side_cfg.classifier_ver;
				feat.calibration_ver = side_cfg.calibration_ver;
				side_dec = ultrawidelock_side_filter_feed(&side_filt, &feat);
				side_feed_ms = now;
				LOG_INF("side feed: side=%u conf=%u flags=0x%02x oi_pkts=%u/%u rssi_io=%d/%d",
					(unsigned)side_dec.side, side_dec.confidence,
					side_dec.flags, feat.ble_pkts_inside,
					feat.ble_pkts_outside,
					(int)feat.ble_rssi_inside_dbm,
					(int)feat.ble_rssi_outside_dbm);
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_INSIDE_LATCH)
				/*
				 * Only decisions the side gate would itself
				 * release may extend a run. The two gates run in
				 * series: this counts windows that already
				 * cleared confidence, quorum, freshness and the
				 * contradiction flags, so a degraded or stale
				 * window can contradict but never accumulate.
				 */
				ultrawidelock_latch_note_window(
					&s_latch, latch_cred,
					ultrawidelock_side_may_passive_unlock(&side_dec, &side_cfg)
						? side_dec.side
						: (side_dec.side ==
							   ULTRAWIDELOCK_SIDE_LABEL_INSIDE
							   ? ULTRAWIDELOCK_SIDE_LABEL_INSIDE
							   : ULTRAWIDELOCK_SIDE_LABEL_UNKNOWN),
					feat.uwb_range_mm, now);
#endif
			}

			/* Age the snapshot on the loop clock, not on the arrival of
			 * the next feed. A witness link that dies must close the
			 * gate, not freeze it open at whatever it last said. */
			if (side_dec.side != ULTRAWIDELOCK_SIDE_LABEL_UNKNOWN &&
			    (now - side_feed_ms) > (int64_t)SIDE_FEED_WATCHDOG_MS) {
				LOG_WRN("side evidence stale (%lld ms); closing gate",
					(long long)(now - side_feed_ms));
				side_dec.side = ULTRAWIDELOCK_SIDE_LABEL_UNKNOWN;
				side_dec.confidence = 0;
				side_dec.flags |= ULTRAWIDELOCK_SIDE_F_EVIDENCE_STALE;
			}

			/*
			 * REVOKE. The gate above only guards the moment of the
			 * grant; nothing withdrew one already given. That leaves
			 * the "walk in and stay" case with no way back to Secured:
			 * iOS stops ranging once the phone is still, and the
			 * departure path deliberately refuses to relock from a
			 * last measurement INSIDE the radius (ultrawidelock_approach.c,
			 * far_silence_ms) so it cannot throw the bolt at a
			 * stationary owner. MEASURED 2026-08-11: grant, then
			 * "UWB session IDLE" at ~112 cm, then nothing -- the door
			 * stayed open with the phone demonstrably indoors.
			 *
			 * Committed INSIDE is the one signal that says the person
			 * is through the door, and it is independent of ranging.
			 * No confidence floor: revoking is the safe direction, so
			 * evidence too weak to open on is still good enough to
			 * close on. UNKNOWN deliberately does NOT revoke -- losing
			 * sight of a phone is not evidence it went inside, and
			 * relocking on it would fire while the owner stands at an
			 * open door. A peer that actually leaves relocks through
			 * the session-ended path below.
			 */
			/*
			 * INSIDE_CONTRADICT counts as well as a committed
			 * INSIDE. It is set the moment one window favours
			 * inside while OUTSIDE is committed -- which is this
			 * case, one window into the walk-in, about 6 s before
			 * INSIDE could commit. Waiting for the commit means
			 * holding the door open across the whole crossing.
			 */
			const bool went_inside =
				side_dec.side == ULTRAWIDELOCK_SIDE_LABEL_INSIDE ||
				(side_dec.flags & ULTRAWIDELOCK_SIDE_F_INSIDE_CONTRADICT) != 0;

			if (granted && went_inside) {
				LOG_INF("passive unlock revoked: side=%u flags=0x%02x conf=%u",
					(unsigned)side_dec.side, side_dec.flags,
					side_dec.confidence);
				if (uwb_policy_enabled(policy_flags, UWB_POLICY_LOCK_RELOCK)) {
					ultrawidelock_reader_notify_unlock(false);
					status_led_signal(STATUS_LED_UNLOCKED, false);
				}
				granted = false;
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_CLIENT) && IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_BLE)
				if (uwb_policy_enabled(policy_flags, UWB_POLICY_BOUND_RELOCK)) {
					matter_client_want(false);
				} else {
					matter_client_rearm_unlock();
				}
#endif
				/* Same state repair as a refusal: the controller still
				 * believes the bolt it opened is open. Without this it
				 * never offers again until a departure past relock_cm,
				 * which is the very thing that is not coming. */
				ultrawidelock_approach_veto(&approach);
			}
		}
#endif

		/*
		 * D11: what the phone is doing. The loop wakes on the latch
		 * itself, so this lights within a round rather than on the next
		 * 250 ms tick. Any range counts, trusted or not -- the light
		 * says "the radios are working on someone", which is the
		 * question being asked when you are standing in front of a
		 * board that has not opened.
		 * ULTRAWIDELOCK_LED_RANGE_HOLD_MS outlives one round at every rate iOS
		 * uses, so a walk-up shows as a steady 4 Hz rather than a
		 * stutter, and it drops back to the 1 Hz session light about a
		 * second after the phone stops ranging (which a still phone
		 * does, with the session still up).
		 */
		if (gen != led_gen) {
			led_gen = gen;
			led_range_ms = now;
		}
		/* The != 0 is not redundant: uptime is a few tens of ms when this
		 * loop first runs, so without it every board reports ranging for
		 * its first second. */
		bool ranging = led_range_ms != 0 &&
			       (now - led_range_ms) < ULTRAWIDELOCK_LED_RANGE_HOLD_MS;

		status_led_signal(STATUS_LED_RANGING, ranging);
		const bool session_now = ultrawidelock_reader_session_active();

		status_led_signal(STATUS_LED_SESSION, session_now);
		if (session_now && !session_was_up) {
			/*
			 * A session cannot come up without the phone approaching: the
			 * BLE RSSI power gate holds ranging off until the connection
			 * crosses its open threshold. So this edge is the approach
			 * evidence approach_cm wants, and it is the only form of it
			 * this architecture produces -- UWB starts when the phone is
			 * already at the door, so a 180 cm range never arrives.
			 */
			ultrawidelock_approach_session_up(&approach);
		}
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_INSIDE_LATCH)
		/*
		 * The latch session follows the CREDENTIAL, not the BLE link.
		 * A link that is up but not yet authenticated has no name to
		 * accumulate evidence against, and evidence that cannot be
		 * attributed to a credential must not be attributed to one.
		 * So the session opens when the reader can say whose it is,
		 * and any change of credential closes the old one -- a run of
		 * agreeing windows must never be inherited by another phone.
		 */
		{
			uint32_t cred_now = session_now ? latch_cred_id() : LATCH_CRED_NONE;

			if (cred_now == latch_cred) {
				if (latch_gap_ms != 0) {
					/* The same credential is back inside the
					 * carry window: same approach, and the
					 * run of agreeing windows survives. */
					latch_gap_ms = 0;
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_SEALED_LINK)
					witness_link_session(true);
#endif
				}
			} else if (cred_now == LATCH_CRED_NONE) {
				/* Hold the latch session through the flap; no
				 * evidence can accumulate meanwhile (windows on
				 * a rolled challenge arrive degraded), and no
				 * grant can be delivered to a phone that is not
				 * connected. Only a gap long enough to be a
				 * different approach closes the session. */
				if (latch_gap_ms == 0) {
					latch_gap_ms = now;
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_SEALED_LINK)
					witness_link_session(false);
#endif
				} else if ((now - latch_gap_ms) >
					   (int64_t)LATCH_SESSION_CARRY_MS) {
					ultrawidelock_latch_session_close(&s_latch);
					latch_cred = LATCH_CRED_NONE;
					latch_gap_ms = 0;
				}
			} else {
				/* A different credential: a run of agreeing
				 * windows must never be inherited by another
				 * phone, so open (which resets) even when a gap
				 * was pending. */
				if (latch_cred != LATCH_CRED_NONE) {
					ultrawidelock_latch_session_close(&s_latch);
				}
				ultrawidelock_latch_session_open(&s_latch, cred_now);
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_SEALED_LINK)
				witness_link_session(true);
#endif
				latch_cred = cred_now;
				latch_gap_ms = 0;
			}
		}
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_BLE)
		/*
		 * A Home-tile unlock is the deliberate act that creates the
		 * latch record. Without this, the only note_grant call sat on
		 * the passive-grant path, which itself requires the record --
		 * so no credential could ever earn its first one (measured
		 * 2026-08-21: why=0x12 with every other gate green).
		 */
		if (matter_commission_take_deliberate_unlock() &&
		    latch_cred != LATCH_CRED_NONE) {
			LOG_INF("inside latch: record from deliberate unlock");
			latch_note_opened(latch_cred, now);
		}
#endif
#endif
		session_was_up = session_now;
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_BLE)
		/* D12: an uncommissioned node cannot unlock anything, and it is
		 * indistinguishable from a working one until someone walks up. */
		status_led_signal(STATUS_LED_UNCOMMISSIONED, !matter_commission_has_fabric());
#endif

		/* Feed exactly one sample per NEWLY accepted trusted range (the generation epoch
		 * advances only on an accepted latch), mirroring the ESP lock's per-wake feed. A
		 * stale latch -- iOS stops ranging once the phone holds still -- keeps the old
		 * generation, so it drives a tick, not a fresh approach sample. */
		if (gen != last_gen && ultrawidelock_uwb_trusted_range_block_cm(&cm, &last_obs_block)) {
			last_gen = gen;
			last_obs_gen = gen;
			present = true;
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR_PAIR_LOG)
			/* On the MAIN THREAD, not the ranging callback: the per-frame
			 * trace is forced off above precisely because synchronous
			 * printing there pushes the delayed Response TX past its slot.
			 * Here the round is long finished. */
			LOG_INF("pair sid=%08x blk=%u mm=%d",
				(unsigned)ultrawidelock_uwb_session_id(),
				(unsigned)last_obs_block, (int)(cm * 10));
#endif
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR)
			/* Remember our half of the pair, keyed by the block it was
			 * measured in, so a peer report that took a block or two to
			 * arrive still finds something to match. Deliberately NOT
			 * approach.last_cm: the tracker has a second writer -- the
			 * departure path feeds it UNVOUCHED ranges -- so its value can be
			 * blocks newer than the label beside it. */
			ultrawidelock_satellite_set_observe(&satellite, cm * 10, last_obs_block, now);
#endif
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR_LINK) && IS_ENABLED(CONFIG_ULTRAWIDELOCK_SIDE_GATE)
			/*
			 * Drive the side gate from the two UWB anchors.
			 *
			 * Here rather than beside the RTT feed below because a
			 * window must be one PAIR of same-round distances, and this
			 * is the only place a fresh trusted range and the block it
			 * belongs to are both in hand. Fed once per accepted latch,
			 * so agree_windows counts real rounds: three of them span
			 * ~576 ms at a 192 ms block, the same span the range trust
			 * layer already uses.
			 *
			 * Everything that could withhold stays withheld. The
			 * verdict is UNKNOWN unless a peer report for THIS block
			 * arrived and cleared the triangle gate, and an UNKNOWN
			 * with no peer distance leaves the satellite bit out of
			 * anchor_health_mask, which fails quorum on its own.
			 */
			{
				struct ultrawidelock_fusion_verdict fv =
					ultrawidelock_satellite_set_verdict(&satellite, now);
				struct ultrawidelock_side_features sf;
				static uint32_t side_seq;

				memset(&sf, 0, sizeof(sf));
				sf.now_ms = now;
				sf.obs_session_id = ultrawidelock_uwb_session_id();
				if (sf.obs_session_id == 0u) {
					sf.obs_session_id = 1u;
				}
				sf.seq = ++side_seq;
				sf.uwb_range_mm = cm * 10;
				sf.uwb_vel_mm_s = INT32_MIN;
				sf.uwb_range_var_mm = -1;
				sf.ble_rssi_inside_dbm = INT16_MIN;
				sf.ble_rssi_outside_dbm = INT16_MIN;
				sf.ble_rssi_threshold_dbm = INT16_MIN;
				sf.uwb_peer_mm = ultrawidelock_satellite_set_peer_mm(&satellite, now);
				/* The filter checks quorum against THIS mask, not
				 * against the evidence fields themselves; leaving it
				 * zero fails quorum on every sample regardless of what
				 * was measured. */
				if (sf.uwb_range_mm >= 0) {
					sf.anchor_health_mask |=
						ULTRAWIDELOCK_SIDE_ANCHOR_PRIMARY_UWB;
				}
				if (sf.uwb_peer_mm >= 0) {
					sf.anchor_health_mask |=
						ULTRAWIDELOCK_SIDE_ANCHOR_UWB_SATELLITE;
				}
				sf.fusion_side = fv.geometry_ok ? (uint8_t)fv.side
								: ULTRAWIDELOCK_SIDE_LABEL_UNKNOWN;
				/* Flat, not a function of delta_mm: the dead band and
				 * the triangle gate have already decided this pair is
				 * good enough, and inventing a confidence curve here
				 * would be a second opinion with no measurement behind
				 * it. */
				sf.fusion_conf = (sf.fusion_side == ULTRAWIDELOCK_SIDE_LABEL_UNKNOWN)
							 ? 0u
							 : 70u;
				sf.classifier_ver = side_cfg.classifier_ver;
				sf.calibration_ver = side_cfg.calibration_ver;
				side_dec = ultrawidelock_side_filter_feed(&side_filt, &sf);
				side_feed_ms = now;
				LOG_INF("side uwb: side=%u conf=%u flags=0x%02x self=%d peer=%d d=%d",
					(unsigned)side_dec.side, side_dec.confidence, side_dec.flags,
					(int)sf.uwb_range_mm, (int)sf.uwb_peer_mm,
					(int)fv.delta_mm);
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_INSIDE_LATCH)
				/*
				 * Same accounting the BLE feed does, because the
				 * latch counts WINDOWS and does not care which
				 * evidence produced one. Without this an image
				 * with no BLE witnesses never advances the run at
				 * all, and the latch refuses for ever on
				 * ULTRAWIDELOCK_LATCH_R_WINDOWS however long the
				 * phone stands outside.
				 */
				ultrawidelock_latch_note_window(
					&s_latch, latch_cred,
					ultrawidelock_side_may_passive_unlock(&side_dec, &side_cfg)
						? side_dec.side
						: (side_dec.side ==
							   ULTRAWIDELOCK_SIDE_LABEL_INSIDE
							   ? ULTRAWIDELOCK_SIDE_LABEL_INSIDE
							   : ULTRAWIDELOCK_SIDE_LABEL_UNKNOWN),
					sf.uwb_range_mm, now);
#endif
				if (bl_cal_on && sf.uwb_range_mm >= 0 &&
				    sf.uwb_peer_mm >= 0) {
					bl_cal[bl_cal_n++] = sf.uwb_range_mm - sf.uwb_peer_mm;
					if (bl_cal_n == ARRAY_SIZE(bl_cal)) {
						int32_t m;

						/* Insertion sort; the median
						 * shrugs off the NLOS tail. */
						for (size_t i = 1; i < ARRAY_SIZE(bl_cal); i++) {
							int32_t k = bl_cal[i];
							size_t j = i;

							for (; j > 0 && bl_cal[j - 1] > k; j--) {
								bl_cal[j] = bl_cal[j - 1];
							}
							bl_cal[j] = k;
						}
						m = bl_cal[ARRAY_SIZE(bl_cal) / 2];
						m = m < 0 ? -m : m;
						bl_cal_on = false;
						if (m >= 300 && m <= 10000) {
							baseline_apply(&satellite, m, true);
						} else {
							LOG_WRN("baseline cal failed (median %d): not past an anchor?",
								m);
						}
					}
				}
			}
#endif
			(void)ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_TRUSTED_RANGE);
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_WITNESS_LINK_OT)
			/* Only ranges the integrity consensus vouches for are
			 * published. The picker correlates advertiser RSSI
			 * against this, so feeding it an unvouched range would
			 * let a spoofed distance choose which advertiser the
			 * lock believes is the phone. */
			witness_link_set_range_mm(cm * 10);
#endif
			act = ml_feed_range(&approach, now, cm);
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_BLE)
			uwb_matter_presence_update(&approach, cm, now);
#endif
		} else {
			/*
			 * A fresh range the integrity consensus will not vouch
			 * for still says something -- about DEPARTURE only. Far
			 * ranges are the ones it declines, so without this the
			 * walk-away relock can never fire; see
			 * ultrawidelock_approach_observe_departure() for why reading an
			 * unvouched range is safe in that one direction.
			 *
			 * last_gen is deliberately NOT consumed here. Trust can
			 * arrive late for a latch already taken (the good-run
			 * counter builds across blocks), and the retry above is
			 * what catches it. A separate epoch keeps this from
			 * observing the same range twice, which would refresh
			 * the silence clock and stop it ever expiring.
			 */
			if (gen != last_obs_gen) {
				int32_t raw = 0;

				last_obs_gen = gen;
				if (ultrawidelock_uwb_last_range_cm(&raw)) {
					ultrawidelock_approach_observe_departure(&approach, now, raw);
				}
			}
			act = ultrawidelock_approach_tick(&approach, now);
		}

		ml_feed_vote_trace(&approach, now);
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_BENCH_TOGGLE_UNLOCK)
		/*
		 * Bench-only: a NEW ranging session opens a short window in which
		 * a clean committed OUTSIDE unlocks with no approach at all. The
		 * Wallet UWB toggle (and the first session after a flash) is what
		 * creates a new session, so on the bench this is "toggle asks the
		 * geometry": outside unlocks, inside or unknown refuses. Kept off
		 * a mounted door because iOS ALSO recreates sessions on its own,
		 * and an owner resting outside must not have the bolt follow
		 * every session churn.
		 */
		{
			static uint32_t tg_sid;
			static int64_t tg_until;
			uint32_t sid = ultrawidelock_uwb_session_id();

			if (sid != 0u && sid != tg_sid) {
				tg_sid = sid;
				/* 20 s: the second anchor takes ~3-4 s to join the
				 * new session before geometry exists at all, and a
				 * measured 00:24 window expired at 8 s with the
				 * commit still forming. The length costs nothing --
				 * INSIDE refuses by verdict, never by timeout. */
				tg_until = now + 20000;
				LOG_INF("toggle window open");
			}
			/* A committed INSIDE also refreshes the window: stepping
			 * back out is the third stationary case the bench needs
			 * decided, and without this it had no unlock path at
			 * all until iOS recycled the session (~30 s). While
			 * INSIDE holds, the gate below refuses anyway; the
			 * refresh only matters once the verdict flips. */
			if (side_dec.side == ULTRAWIDELOCK_SIDE_LABEL_INSIDE) {
				tg_until = now + 20000;
			}
			if (!granted && tg_until != 0 && now < tg_until && session_now &&
			    latch_cred != LATCH_CRED_NONE &&
			    uwb_policy_enabled(policy_flags, UWB_POLICY_LOCK_UNLOCK) &&
			    ultrawidelock_side_may_passive_unlock(&side_dec, &side_cfg)) {
				tg_until = 0;
				LOG_INF("toggle unlock (conf=%u)", side_dec.confidence);
				ultrawidelock_reader_notify_unlock(true);
				status_led_signal(STATUS_LED_UNLOCKED, true);
				granted = true;
				/* Hand the open bolt to the controller so its range
				 * departure and silence tiers relock it, same as any
				 * other grant. */
				approach.locked = false;
				latch_note_opened(latch_cred, now);
			}
		}
#endif
		if (act == ULTRAWIDELOCK_APPROACH_UNLOCK_PREDICT ||
		    act == ULTRAWIDELOCK_APPROACH_UNLOCK_THRESHOLD) {
			(void)ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_NEAR_DWELL);
		}

		switch (act) {
		case ULTRAWIDELOCK_APPROACH_UNLOCK_PREDICT:
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR) && !IS_ENABLED(CONFIG_ULTRAWIDELOCK_SIDE_GATE)
			/*
			 * Legacy two-anchor helper: gates PREDICTION only and
			 * fail-opens on UNKNOWN. Retained when ULTRAWIDELOCK_SIDE_GATE is
			 * off so existing ANCHOR=1 behaviour stays unchanged.
			 */
			if (!ultrawidelock_satellite_set_may_predict(&satellite, now)) {
				LOG_INF("predict withheld: second anchor puts the phone outside");
				break;
			}
#endif
			/* fall through */
		case ULTRAWIDELOCK_APPROACH_UNLOCK_THRESHOLD:
			if (!uwb_policy_enabled(policy_flags, UWB_POLICY_LOCK_UNLOCK) &&
			    !uwb_policy_enabled(policy_flags, UWB_POLICY_BOUND_UNLOCK)) {
				ultrawidelock_approach_veto(&approach);
				break;
			}
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_SIDE_GATE)
			/*
			 * Safety gate for ALL passive approach unlocks. Requires
			 * confident OUTSIDE. UNKNOWN/INSIDE/THRESHOLD/stale/
			 * quorum-fail suppress the grant. Intentional paths
			 * (NFC Express, Home, mechanical) do not enter here.
			 */
			if (!ultrawidelock_side_may_passive_unlock(&side_dec, &side_cfg)) {
				/*
				 * Hand the unlock back. Both approach unlock paths
				 * clear their own `locked` before returning, so
				 * without this the controller thinks the bolt is
				 * open and never offers again -- one refusal, made
				 * before the witnesses had time to commit a side,
				 * killed auto-unlock for the whole approach.
				 */
				ultrawidelock_approach_veto(&approach);
				/* Retried on every trusted range now, so rate-limit
				 * the line or it buries the RTT console. */
				if ((now - side_deny_log_ms) >= SIDE_DENY_LOG_MS) {
					side_deny_log_ms = now;
					LOG_INF("passive unlock withheld: side=%u conf=%u flags=0x%02x",
						(unsigned)side_dec.side, side_dec.confidence,
						side_dec.flags);
				}
#if defined(CONFIG_ULTRAWIDELOCK_CRED_LAB)
				ultrawidelock_printf("[ALAB] t=%lld ev=side.deny side=%u conf=%u flags=%u\n",
					   ultrawidelock_uptime_us(), (unsigned)side_dec.side,
					   side_dec.confidence, side_dec.flags);
#endif
				break;
			}
#endif
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_INSIDE_LATCH)
			/*
			 * The inside veto, last and unconditional. Reached only
			 * for passive approach unlocks: NFC Express Mode, Apple
			 * Home commands and mechanical operation do not enter
			 * this switch and must never be gated here.
			 *
			 * Refusing hands the unlock back the same way the side
			 * gate does, so the approach controller keeps offering
			 * for the rest of the walk-up rather than being killed
			 * by one early refusal.
			 */
			if (!ultrawidelock_latch_may_passive_unlock(&s_latch, latch_cred, now,
								   &latch_why)) {
				ultrawidelock_approach_veto(&approach);
				if ((now - side_deny_log_ms) >= SIDE_DENY_LOG_MS) {
					side_deny_log_ms = now;
					LOG_INF("passive unlock withheld: inside latch (why=0x%02x)",
						latch_why);
				}
				break;
			}
#endif
			if (uwb_policy_enabled(policy_flags, UWB_POLICY_LOCK_UNLOCK)) {
				ultrawidelock_reader_notify_unlock(true); /* Reader Status -> Unsecured */
				status_led_signal(STATUS_LED_UNLOCKED, true);
			}
			granted = true;
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_CLIENT) && IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_BLE)
			/*
			 * And the lock this one is bound to, if there is one.
			 * Both symbols, matching the CMakeLists: the client's
			 * routing hooks live in matter_commission.c, which is
			 * the file CONFIG_ULTRAWIDELOCK_MATTER_BLE compiles.
			 * AFTER the two lines above, which are this board's
			 * entire idea of a bolt: whatever happens on the mesh
			 * must not delay them, and matter_client_want() returns
			 * without waiting for anything at all.
			 */
			if (uwb_policy_enabled(policy_flags, UWB_POLICY_BOUND_UNLOCK)) {
				matter_client_want(true);
			}
#endif
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_INSIDE_LATCH)
			/* The door is open, so assume the phone goes in. This
			 * is the pessimism the whole module rests on. */
			latch_note_opened(latch_cred, now);
#endif
			if (ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_BOLT_DRIVEN)) {
				/* This CDK has no motor. BOLT_DRIVEN means the software grant
				 * and its visible output have both been committed. */
				ultrawidelock_lat_report();
			}
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_HEAP_PROBE)
			heap_peak_log("unlock");
#endif
			break;
		case ULTRAWIDELOCK_APPROACH_RELOCK_DEPART:
		case ULTRAWIDELOCK_APPROACH_RELOCK_ABORT:
			if (uwb_policy_enabled(policy_flags, UWB_POLICY_LOCK_RELOCK)) {
				ultrawidelock_reader_notify_unlock(false); /* Reader Status -> Secured */
				status_led_signal(STATUS_LED_UNLOCKED, false);
			}
			granted = false;
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_CLIENT) && IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_BLE)
			/* And close the lock this one opened. Same shape as the
			 * grant above: after this board's own bolt, never
			 * before it. */
			if (uwb_policy_enabled(policy_flags, UWB_POLICY_BOUND_RELOCK)) {
				matter_client_want(false);
			} else {
				matter_client_rearm_unlock();
			}
#endif
			break;
		default:
			break;
		}

		/* Departure: the peer's credential session ended (walked away / phone pocketed). iOS
		 * ranging silence alone does NOT mean departed (a still phone stops ranging too),
		 * so gate on the session, not on range age. Tell Wallet Secured once and reset. */
		/* One hold per flap, judged on the evidence at the moment the
		 * session died: feeds stop with the session, so the freshness
		 * test would fail on every later tick of the same flap if it
		 * were re-judged. A session that comes back clears the hold. */
		static int64_t flap_hold_ms;
		bool sess_gone = present && !ultrawidelock_reader_session_active();

		if (!sess_gone) {
			flap_hold_ms = 0;
		} else if (flap_hold_ms == 0 && granted && approach.last_feed_ms != 0 &&
			   /* Only the mid-phase flap earns a hold. A close from
			    * ESTABLISHED is the peer done on purpose -- Wallet's
			    * UWB toggled off -- and the old immediate relock is
			    * exactly right there (measured 2026-08-22 01:15: the
			    * hold bridged a toggle-off into the reconnect and
			    * the bolt never relocked). */
			   !ultrawidelock_reader_last_close_established() &&
			   approach.last_cm < approach.cfg.relock_cm &&
			   (now - approach.last_feed_ms) <= SESSION_FLAP_FEED_FRESH_MS) {
			flap_hold_ms = now;
			LOG_WRN("session died with the phone fed at %d cm; holding the bolt %d ms",
				approach.last_cm, SESSION_FLAP_HOLD_MS);
		}
		if (sess_gone && (flap_hold_ms == 0 || (now - flap_hold_ms) > SESSION_FLAP_HOLD_MS)) {
			flap_hold_ms = 0;
			/*
			 * Reaching here with the bolt still open means the silence
			 * relock in ultrawidelock_approach_tick() did NOT fire, and this is
			 * the only moment that proves it: the Secured is about to go
			 * out with no session left to carry it.
			 *
			 * last_cm is what the controller was actually FED, which is
			 * not what the status line prints. main.c feeds only a range
			 * ultrawidelock_uwb_trusted_range_cm() vouches for; the trace prints
			 * the raw latch either way, so a walk-away can show 390 cm
			 * on screen while the controller last saw 199 cm. Printing
			 * both the value and its age says which of the two gates
			 * held. MUST run before ultrawidelock_approach_gone(), which
			 * re-inits the struct and erases the evidence.
			 */
			if (granted) {
				LOG_WRN("departure fallback: last FED %d cm, %u ms ago "
					"(gate: >= %d cm held for %d ms)",
					approach.last_cm,
					approach.last_feed_ms != 0
						? (unsigned int)(now - approach.last_feed_ms)
						: 0u,
					approach.cfg.relock_cm, approach.cfg.far_silence_ms);
			}
			(void)ultrawidelock_approach_gone(&approach);
			if (granted) {
				if (uwb_policy_enabled(policy_flags, UWB_POLICY_LOCK_RELOCK)) {
					ultrawidelock_reader_notify_unlock(false);
					status_led_signal(STATUS_LED_UNLOCKED, false);
				}
				granted = false;
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_CLIENT) && IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_BLE)
				if (uwb_policy_enabled(policy_flags, UWB_POLICY_BOUND_RELOCK)) {
					matter_client_want(false);
				} else {
					matter_client_rearm_unlock();
				}
#endif
			}
			present = false;
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_BLE)
			uwb_matter_presence_clear();
#endif
		}

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR_SLAM)
		/*
		 * The accelerometer's whole cost at runtime: one atomic read per
		 * tick. The GPIO callback that sets it does nothing but set it,
		 * so nothing here runs in interrupt context and nothing competes
		 * with the ranging arm deadline.
		 *
		 * Deliberately after the approach switch: a strike is a report
		 * about the DOOR, and must not be able to influence whether this
		 * tick unlocked. Tamper is a signal to surface, not an input to
		 * the grant.
		 */
		switch (ultrawidelock_slam_poll(&slam_cfg, &slam, ultrawidelock_slam_hw_take(), now)) {
		case ULTRAWIDELOCK_SLAM_TAMPER:
			LOG_WRN("tamper: repeated impacts on the door");
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_BLE)
			/* A struck door while the bolt is thrown is what
			 * DoorForcedOpen means. The bolt test is applied by the
			 * Matter half, which owns that state. */
			door_alarm_tamper();
#endif
			break;
		case ULTRAWIDELOCK_SLAM_IMPACT:
			LOG_INF("impact");
			break;
		default:
			break;
		}
#endif

		/* Wake on the next latch, or on the housekeeping tick if none comes.
		 * A latch that lands while this pass is still running leaves the
		 * semaphore given, so the take returns at once and no range waits.
		 *
		 * The impact poll above deliberately sits BEFORE this: it now runs on
		 * every wake rather than on a fixed 250 ms cadence, so a busy walk-up
		 * polls it more often, never less. Its debounce is a time comparison,
		 * not a count of ticks, so a faster poll rate cannot make a single
		 * strike read as several. */
		(void)k_sem_take(&s_range_sig, K_MSEC(ULTRAWIDELOCK_TICK_MS));
	}
	return 0;
}
