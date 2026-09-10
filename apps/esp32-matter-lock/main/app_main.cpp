// Matter application main: door lock endpoint setup, Matter lifecycle event handling, and (when
// CONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB is set) startup/coexistence wiring for the credential BLE+UWB
// reader alongside the Matter BLE commissioning transport. Owns the credential reader background
// task (started once on commissioning-complete or at boot if already commissioned) and the Matter
// attribute/identify/device-event callbacks required by esp-matter's node/cluster framework.
/*
   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <esp_err.h>
#include <esp_log.h>
#include <esp_timer.h>
#include <nvs_flash.h>
#ifdef CONFIG_ULTRAWIDELOCK_PIV_CCID
#include <piv_ccid_usb.h>
#endif
#if CONFIG_PM_ENABLE
#include <esp_pm.h>
#endif

#include <esp_matter.h>
#include <esp_matter_ota.h>

#include <common_macros.h>
#include <app_priv.h>
#include "app_shell.h"

#ifdef CONFIG_ULTRAWIDELOCK_DFU_ESP32
#include "ultrawidelock_dfu_esp32.h"
#ifndef CONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB
/* The reader's own include block further down pulls these in when it is
 * enabled, and it usually is. The extra-service registration in app_main needs
 * them whenever EITHER feature is on, so an image with updates but no credential
 * reader still compiles. */
#include <vector>
#include "host/ble_gatt.h"                 // struct ble_gatt_svc_def (NimBLE)
#include <platform/ESP32/BLEManagerImpl.h> // BLEMgrImpl().ConfigureExtraServices()
#endif
#endif
#if CHIP_DEVICE_CONFIG_ENABLE_THREAD
#include <platform/ESP32/OpenthreadLauncher.h>
#endif

#include <app/server/CommissioningWindowManager.h>
#include <app/server/Server.h>
// ScheduleWork — also pulled in below, but not unconditionally
#include <platform/PlatformManager.h>
#include <setup_payload/OnboardingCodesUtil.h>
#include <setup_payload/QRCodeSetupPayloadGenerator.h> // kMaxQRCodeBase38RepresentationLength
#include <iot_button.h> // BUTTON_LONG_PRESS_START — the commissioning-window recovery press
#ifdef CONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB
#include <ultrawidelock_reader_delegate.h>
#include <ultrawidelock/reader.h>
#include <ultrawidelock_approach.h>
#include <ultrawidelock_ble.h> // ultrawidelock_ble_time_updated()
#include <ultrawidelock_lab.h>
#include <ultrawidelock_lat.h>
#include <esp_netif_sntp.h>
#include <ultrawidelock/uwb.h>
#include "sat_fusion.h" // the two-anchor inside/outside gate
#ifdef CONFIG_ULTRAWIDELOCK_PRESENCE
#include <presence_link.h>
#endif
#include "door_lock_manager.h"
#include <platform/PlatformManager.h>
#include <vector>
#include "host/ble_gatt.h"                 // struct ble_gatt_svc_def (NimBLE)
#include "host/ble_gap.h"                  // ble_gap_adv_active()
#include "host/ble_hs.h"                   // ble_hs_synced()
#include <platform/ESP32/BLEManagerImpl.h> // BLEMgrImpl().ConfigureExtraServices()
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#endif
#ifdef CONFIG_ENABLE_HA_MQTT
#include "ha_mqtt.h"
#endif

static const char *TAG = "app_main";
uint16_t door_lock_endpoint_id = 0;
#ifdef CONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB
/* Kept so `status` can report the reader task's stack high-water mark. */
TaskHandle_t ultrawidelock_reader_task_handle = nullptr;

#define APPROACH_DIRECTION_CLUSTER 1

#if APPROACH_DIRECTION_CLUSTER
/* Apple's manufacturer-specific Approach Direction cluster: MEI vendor 0x1349 (Apple),
 * cluster 0xFC03, sitting on the door lock endpoint alongside DoorLock itself.
 *
 * The cluster is a server with three attributes totalling 7 bytes:
 *
 *   0x0000  size 1  type 0x18 (bitmap8)  mask 0x03 (writable|nonvolatile)  default 7
 *   0xFFFC  size 4  type 0x1B (bitmap32) FeatureMap                        default 0
 *   0xFFFD  size 2  type 0x21 (int16u)   ClusterRevision                   default 1
 *
 * The direction attribute is a bitmap, not an integer, and 7 means all three
 * directions permitted, matching Home's "unlock when you approach from any
 * direction". Which single bit is Left versus Right is still unknown; nothing here
 * depends on it.
 *
 * An earlier attempt typed the attribute as uint8 and declared neither global
 * attribute. Home commissioned the device fully and then sent RemoveFabric, which is
 * what a cluster that cannot answer ClusterRevision deserves.
 *
 * Nothing gates unlock on this: a single-antenna DW3110 cannot measure the angle, so
 * the value is stored and reported but never enforced.
 */
constexpr uint32_t kApproachDirectionClusterId = 0x1349FC03;
constexpr uint32_t kApproachDirectionAttributeId = 0x0000;
constexpr uint8_t kApproachDirectionAll = 0x07;
constexpr uint32_t kApproachDirectionFeatureMap = 0;
constexpr uint16_t kApproachDirectionClusterRevision = 1;
#endif
#endif

using namespace esp_matter;
using namespace esp_matter::attribute;
using namespace esp_matter::endpoint;
using namespace chip::app::Clusters;
using namespace chip;

constexpr auto k_timeout_seconds = 300;

#if CONFIG_ENABLE_ENCRYPTED_OTA
extern const char decryption_key_start[] asm("_binary_esp_image_encryption_key_pem_start");
extern const char decryption_key_end[] asm("_binary_esp_image_encryption_key_pem_end");

static const char *s_decryption_key = decryption_key_start;
static const uint16_t s_decryption_key_len = decryption_key_end - decryption_key_start;
#endif // CONFIG_ENABLE_ENCRYPTED_OTA

#ifdef CONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB
// BLE coexistence (nRF-style local UWB unlock): the credential reader shares Matter's
// NimBLE host — Matter keeps BLE up (CONFIG_USE_BLE_ONLY_FOR_COMMISSIONING=n), its
// GATT service is registered via BLEMgrImpl().ConfigureExtraServices() before
// esp_matter::start (see app_main), and the reader's advertiser + L2CAP CoC come
// up once the device is operational (Matter has released the single legacy
// advertiser: after commissioning, or immediately when already paired). A trusted
// UWB range then drives the Matter lock to Unlocked. This replaces the old handoff,
// which crashed because NimBLE can't be re-inited after Matter reclaims BLE.
#define ULTRAWIDELOCK_UNLOCK_RANGE_CM 100  // approach threshold: unlock at/under this (median cm)
#define ULTRAWIDELOCK_RELOCK_RANGE_CM                                                              \
	250 // depart threshold: relock past this — wide band vs UWB range noise
#define ULTRAWIDELOCK_NEAR_DWELL      2     // consecutive median <= UNLOCK before the bolt opens
#define ULTRAWIDELOCK_FAR_DWELL       3     // consecutive median >= RELOCK before the bolt closes
// Departure is the credential session ending, not a ranging timeout, so there is no
// silence threshold to tune here. Every value tried relocked the bolt under a phone
// that had simply stopped moving: iOS pauses ranging when the user stands still,
// measured at 1.6 s, 2.4 s and 3.07 s in successive bench runs, the last one with
// the phone 26 cm from the reader and the link still up.
// Negative latency: the controller predicts the time of arrival at the unlock
// radius and starts retraction motor+margin early, so the bolt is open when the
// hand lands. MOTOR_MS is this lock model's retraction time — tune it from the
// ALAB near->bolt phase gap plus the motor spec (`lab on`, walk up, read the
// budget line). The margin stays >= one 192 ms ranging block so the discrete
// sample grid cannot step over the firing window.
#define ULTRAWIDELOCK_MOTOR_MS          500 // bolt retraction time for this lock model
#define ULTRAWIDELOCK_PREDICT_MARGIN_MS 250 // scheduling slack on top of the motor
#define ULTRAWIDELOCK_PREDICT_VMIN_CM_S 30  // min closing speed before predictions arm

// Resolve the Matter user that owns the credential the reader authenticated, so the LockOperation
// event names who operated the lock. Without it the event is anonymous and Apple Home, unable to
// tell which member unlocked, notifies every device in the home including the one that just did it.
// Call from the Matter task (it reads the door lock's user and credential tables).
// Returns a null user index if no credential has authenticated since boot or no stored user owns
// it.
static app::DataModel::Nullable<uint16_t> ultrawidelock_operating_user(void)
{
	uint8_t cred[65];

	if (!ultrawidelock_reader_authenticated_credential(cred)) {
		ESP_LOGW(TAG, "no authenticated credential; LockOperation stays unattributed");
		return app::DataModel::NullNullable;
	}

	uint16_t user_index = BoltLockMgr().UserIndexForAliroCredential(ByteSpan(cred, sizeof(cred)));

	if (user_index == 0) {
		ESP_LOGW(TAG, "credential matches no stored user; LockOperation stays "
			      "unattributed (did Apple send SetUser, not just SetCredential?)");
		return app::DataModel::NullNullable;
	}
	ESP_LOGI(TAG, "credential operation attributed to user index %u", user_index);
	return app::DataModel::MakeNullable(user_index);
}

// Drive the bolt from the approach controller. Both hop to the Matter task (the only thread allowed
// to touch the DoorLock cluster). Unlock also stamps the walk-up latency mark on its first
// execution.
static void schedule_bolt_unlock(void)
{
	// Threshold decision made on the reader task; bolt-near = the Matter-task
	// hop + Unlock() itself.
	ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_NEAR_DWELL);
	chip::DeviceLayer::PlatformMgr().ScheduleWork([](intptr_t) {
		BoltLockMgr().Unlock(door_lock_endpoint_id,
				     chip::app::Clusters::DoorLock::OperationSourceEnum::kAliro,
				     ultrawidelock_operating_user());
		// Stamped after Unlock() runs on the Matter task, so the trace measures
		// execution; report only when newly stamped so a re-unlock does not reprint.
		if (ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_BOLT_DRIVEN)) {
			ultrawidelock_lat_report();
		}
	});
}

/**
 * Schedule the door bolt to lock on the credential endpoint, attributing the operation to the
 * credential owner resolved from the current reader authentication context. Defers the lock call to
 * the Matter device layer work queue.
 */
static void schedule_bolt_lock(void)
{
	chip::DeviceLayer::PlatformMgr().ScheduleWork([](intptr_t) {
		BoltLockMgr().Lock(door_lock_endpoint_id,
				   chip::app::Clusters::DoorLock::OperationSourceEnum::kAliro,
				   ultrawidelock_operating_user());
	});
}

// A key the reader learned from a device's Access Document -- an Apple Watch on the
// owner's Apple ID, in every field log so far -- rather than from a Matter
// SetCredential. Runs on the BLE-host task inside the transaction: one log line, so
// the monitor says why an approach that used to end in "credential key NOT trusted"
// now unlocks. First 4 bytes of the point only.
static void on_credential_learned(uint8_t cred_type, uint16_t cred_index, uint16_t user_index,
				  const uint8_t cred_pub[65])
{
	ESP_LOGI(TAG,
		 "credential LEARNED from its Access Document: type %u cred idx %u user idx %u, "
		 "key %02x%02x%02x%02x...",
		 static_cast<unsigned>(cred_type), static_cast<unsigned>(cred_index),
		 static_cast<unsigned>(user_index), cred_pub[0], cred_pub[1], cred_pub[2], cred_pub[3]);
}

// Range-latch listener: runs on the UWB RX path, so it only stamps the latency
// trace and wakes the reader task; the unlock decision itself stays on the task.
static void on_uwb_range(void)
{
	ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_FIRST_RANGE);

	int32_t cm;
	if (ultrawidelock_uwb_trusted_range_cm(&cm)) {
		ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_TRUSTED_RANGE);
	}
	if (ultrawidelock_reader_task_handle == nullptr) {
		return;
	}
	if (xPortInIsrContext()) {
		BaseType_t woken = pdFALSE;
		vTaskNotifyGiveFromISR(ultrawidelock_reader_task_handle, &woken);
		portYIELD_FROM_ISR(woken);
	} else {
		xTaskNotifyGive(ultrawidelock_reader_task_handle);
	}
}

// Background task that starts the credential reader and drives approach-based lock/unlock from UWB
// range. Waits for the shared NimBLE host to be usable (host synced, Matter's advertiser released)
// before calling ultrawidelock_reader_start_attached(), instead of sleeping a flat second. Then
// runs forever as the sole auto-lock driver (the fixed Matter auto-relock is disabled). See the
// controller comment inside for how the noisy per-block UWB distance is conditioned into stable
// grant / unlock / relock events.
static void ultrawidelock_reader_task(void *arg)
{
	// The reader can only take the (single, shared) legacy advertiser once the
	// host is synced and Matter has released it — Matter stops advertising on
	// commissioning-complete and never starts when already commissioned. Wait on
	// that condition, capped so a stuck advertiser still lets the start attempt
	// run (and log its failure) rather than hanging the reader forever.
	for (int waited_ms = 0; waited_ms < 5000; waited_ms += 50) {
		if (ble_hs_synced() && ble_gap_adv_active() == 0) {
			break;
		}
		vTaskDelay(pdMS_TO_TICKS(50));
	}

	ultrawidelock_uwb_set_range_listener(on_uwb_range);
	ultrawidelock_reader_set_credential_learned_listener(on_credential_learned);
#ifdef CONFIG_ENABLE_HA_MQTT
	/* Access verdicts reach Home Assistant straight from the trust gate, which
	 * runs on the BLE-host task; the listener only queues, never publishes. */
	ultrawidelock_reader_set_access_listener(ha_mqtt_publish_access);
#endif

#ifdef CONFIG_ULTRAWIDELOCK_PRESENCE
	/* false: this app already grants and relocks the phone from its own approach
	 * loop below, so presence must not also drive the Wallet notification. */
	presence_link_init(false);
#endif

	/* The two-anchor gate. Before the reader starts advertising, so a
	 * satellite report cannot arrive with the fusion state uninitialised.
	 * With no link key stored this brings up nothing and the door keeps its
	 * single-anchor behaviour. */
	sat_fusion_init();

	int rc = ultrawidelock_reader_start_attached();
	ESP_LOGI(TAG, "ultrawidelock_reader_start_attached() = %d (%s)", rc,
		 rc == 0 ? "reader advertising on shared host" : "reader start FAILED");

	// Approach controller (modules/ultrawidelock_cred/src/ultrawidelock_approach.c, shared with
	// the host suite's walk-up profile replays). The per-block UWB distance is
	// very noisy — single blocks swing by metres (bench: 70 mm -> 1604 mm ->
	// 112 mm between consecutive blocks) — and the security trust gate
	// stabilises *when* a range is surfaced, not its value, so thresholding a
	// raw sample oscillates the bolt. The controller conditions the signal
	// (median + dwell across a wide hysteresis band) and, on top, runs a
	// constant-velocity Kalman filter to predict the time of arrival at the
	// unlock radius: retraction starts ULTRAWIDELOCK_MOTOR_MS early so the bolt is
	// open when the hand lands ("negative latency"), and a predictive open
	// that stops closing or misses its arrival window relocks before anyone
	// is in reach. Presence behaviour is unchanged — slow approaches and
	// stand-at-door still unlock via the median path. This task additionally:
	//   - ties the Wallet grant (credential step 23, Unsecured) to the bolt itself,
	//     never to the bare trust bit: trust lands at whatever range the first
	//     block resolves at (bench: 300 cm), so granting there tells the phone
	//     "unlocked" while the door is still locked, for the whole walk-in. Both
	//     unlock paths grant, including the predictive one, which is honest: the
	//     bolt really is being driven;
	//   - sends Secured on the depart and abort transitions, while the link is
	//     still up — the peer-gone path below normally runs after the phone has
	//     already dropped BLE, and the notify is then discarded;
	//   - treats the peer as gone (relock + Secured) when its credential SESSION ends,
	//     never on ranging silence: iOS stops ranging when the phone stops moving,
	//     measured at 3.07 s with the phone 26 cm from the reader, which relocked
	//     the bolt under someone standing at the door and re-unlocked when ranging
	//     resumed. A link that is still up is a peer that is still there; walking
	//     away ends it via the RSSI gate's close path.
	// Only fresh notifies feed the controller; a bare 200 ms timeout only
	// supervises the arrival deadline, never re-decides on a stale latched value.
	// `granted` mirrors the Wallet state, `present` marks an approach in progress.
	struct ultrawidelock_approach approach;
	struct ultrawidelock_approach_cfg acfg;

	ultrawidelock_approach_defaults(&acfg);
	acfg.unlock_cm = ULTRAWIDELOCK_UNLOCK_RANGE_CM;
	acfg.relock_cm = ULTRAWIDELOCK_RELOCK_RANGE_CM;
	acfg.near_dwell = ULTRAWIDELOCK_NEAR_DWELL;
	acfg.far_dwell = ULTRAWIDELOCK_FAR_DWELL;
	acfg.motor_ms = ULTRAWIDELOCK_MOTOR_MS;
	acfg.margin_ms = ULTRAWIDELOCK_PREDICT_MARGIN_MS;
	acfg.vmin_cm_s = ULTRAWIDELOCK_PREDICT_VMIN_CM_S;
	// Mutually exclusive with the RSSI power gate by Kconfig dependency: the
	// gate holds ranging until the phone is already inside unlock_cm, so an
	// ETA could never arm anyway. Being explicit here keeps the trace honest
	// rather than leaving a predictor that silently never fires.
#if defined(CONFIG_ULTRAWIDELOCK_APPROACH_PREDICT)
	acfg.predict_en = true;
#else
	acfg.predict_en = false;
#endif
	ultrawidelock_approach_init(&approach, &acfg);

	bool present = false;
	bool granted = false;

	while (true) {
		// >0 = at least one range block latched since the last wake (peer is
		// ranging); 0 = a bare 200 ms timeout, which is also how often the
		// session-gone check below runs when nothing is ranging.
		uint32_t woke = ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(200));
		int64_t now = esp_timer_get_time() / 1000; // ms

		// Release a held stale-Wallet Secured if this approach produced no grant to
		// supersede it. Free on every other pass: nothing is armed unless a relock
		// went undelivered, which needs the peer to have vanished mid-notification.
		ultrawidelock_reader_status_tick(now);

		int32_t cm = 0;
		bool active = (woke > 0);
		bool trusted = active && ultrawidelock_uwb_trusted_range_cm(&cm);

		enum ultrawidelock_approach_action act;

		if (trusted) {
			// Task context (not the UWB RX path): one trace line per trusted
			// range block gives the approach curve in the Aliro Lab report.
			ultrawidelock_lab_evi("range", "cm", cm);
			present = true;
			{
				// Our half of the two-anchor pair, keyed by the block it
				// was measured in so a satellite report delayed by a block
				// or two still finds its partner. Both distances MUST come
				// from the same round: mispairing produces triangle
				// rejections that read as a hardware fault.
				int32_t bcm = 0;
				uint32_t blk = 0;

				if (ultrawidelock_uwb_trusted_range_block_cm(&bcm, &blk)) {
					sat_fusion_observe(bcm * 10, blk, now);
				}
			}
			act = ultrawidelock_approach_feed(&approach, now, cm);
#ifdef CONFIG_ENABLE_HA_MQTT
			/* The conditioned estimate the thresholds above act on, not
			 * the raw block `range` prints: a single block swings by
			 * metres, and a sensor showing that is not a distance. */
			ha_mqtt_publish_distance_cm(ultrawidelock_approach_est_cm(&approach));
#endif
			if (ultrawidelock_approach_eta_ms(&approach) >= 0) {
				// Estimator overlay for the walk-up report: closing speed
				// and predicted time of arrival at the unlock radius.
				ultrawidelock_lab_evi("vel", "cms", ultrawidelock_approach_vel_cm_s(&approach));
				ultrawidelock_lab_evi("eta", "ms", ultrawidelock_approach_eta_ms(&approach));
			}
		} else {
			act = ultrawidelock_approach_tick(&approach, now);
		}

		// THE TWO-ANCHOR GATE, on the passive paths only.
		//
		// PREDICT and THRESHOLD open a door nobody touched, on the strength of
		// a distance; those are the two the geometry may veto. Everything else
		// in this switch either closes the bolt or follows a credential the
		// user physically presented, and neither is a passive unlock.
		//
		// Fails PERMISSIVE, which is the counter-intuitive part: with no
		// satellite, no report, or a stale one, the verdict is UNKNOWN and
		// UNKNOWN permits. Absence is not evidence that the phone is outside,
		// and treating it as such would lock people out the first time an
		// anchor lost power. What is withheld is the case where the geometry
		// positively says INSIDE.
		if ((act == ULTRAWIDELOCK_APPROACH_UNLOCK_PREDICT ||
		     act == ULTRAWIDELOCK_APPROACH_UNLOCK_THRESHOLD) &&
		    !sat_fusion_may_passive_unlock(now)) {
			ESP_LOGI(TAG, "passive unlock withheld: second anchor says inside");
			ultrawidelock_lab_evi("side.veto", "cm",
					      ultrawidelock_approach_est_cm(&approach));
			// Hand the unlock back. Both unlock paths clear `locked`
			// BEFORE returning the action, so by the time we refuse it
			// the controller already believes the bolt is open -- and
			// its own guard is `if (ap->locked && ...)`. Dropping the
			// action without this would mean one veto, taken before
			// the satellite had a settled verdict, silently ends
			// auto-unlock for the whole walk-up. veto() restores
			// `locked` while deliberately keeping near_dwell and
			// approach_armed, so the retry does not pay the dwell
			// again. Same reason apps/dwm3001cdk-lock/src/main.c calls
			// it on every refusing path.
			ultrawidelock_approach_veto(&approach);
			act = ULTRAWIDELOCK_APPROACH_HOLD;
		}

		switch (act) {
		case ULTRAWIDELOCK_APPROACH_UNLOCK_PREDICT:
			// ETA inside the retraction window: start now, open at arrival.
			ESP_LOGI(TAG, "credential arrival in %d ms (%d cm/s closing): unlocking early",
				 (int)ultrawidelock_approach_eta_ms(&approach),
				 (int)ultrawidelock_approach_vel_cm_s(&approach));
			ultrawidelock_lab_evi("predict.fire", "eta_ms",
				      ultrawidelock_approach_eta_ms(&approach));
			schedule_bolt_unlock();
			// Reader Status Changed -> Unsecured. Honest on the predictive
			// path too: the bolt is being driven, just early.
			ultrawidelock_reader_notify_unlock(true);
			granted = true;
			break;
		case ULTRAWIDELOCK_APPROACH_UNLOCK_THRESHOLD:
			ESP_LOGI(TAG, "credential approach %d cm (est): unlocking",
				 (int)ultrawidelock_approach_est_cm(&approach));
			schedule_bolt_unlock();
			ultrawidelock_reader_notify_unlock(true);
			granted = true;
			break;
		case ULTRAWIDELOCK_APPROACH_RELOCK_DEPART:
			ESP_LOGI(TAG, "credential departed %d cm (est): relocking",
				 (int)ultrawidelock_approach_est_cm(&approach));
			schedule_bolt_lock();
			// Still connected here, so this one actually reaches the phone
			// (the peer-gone path below often cannot).
			ultrawidelock_reader_notify_unlock(false);
			granted = false;
			break;
		case ULTRAWIDELOCK_APPROACH_RELOCK_ABORT:
			// Opened on a prediction, but the approach stopped/turned or
			// arrival is overdue: put the bolt back.
			ESP_LOGI(TAG, "credential approach aborted (%d cm/s closing): relocking",
				 (int)ultrawidelock_approach_vel_cm_s(&approach));
			ultrawidelock_lab_ev("predict.abort");
			schedule_bolt_lock();
			ultrawidelock_reader_notify_unlock(false);
			granted = false;
			break;
		default:
			break;
		}

		// Departure: the peer's credential session is gone. Not ranging silence — iOS
		// stops ranging when the phone stops moving, so silence means "standing
		// still", which is the opposite of departed. The link is the presence
		// signal; walking away ends it via the RSSI gate's close path, and a
		// phone that pockets or sleeps ends it too. Relock if still open, tell
		// Wallet Secured, reset for the next approach.
		if (present && !ultrawidelock_reader_session_active()) {
			bool relocked = ultrawidelock_approach_gone(&approach) ==
					ULTRAWIDELOCK_APPROACH_RELOCK_DEPART;

			ESP_LOGI(TAG, "credential peer gone (session ended)%s%s",
				 relocked ? ": relock" : "", granted ? " + secured" : "");
			if (relocked) {
				schedule_bolt_lock();
			}
			if (granted) {
				ultrawidelock_reader_notify_unlock(false); /* -> Secured */
				granted = false;
			}
			present = false;
		}
	}
}

// Start the credential reader task exactly once, idempotent across repeated calls (e.g. from
// multiple event callbacks). Spawns ultrawidelock_reader_task on its own FreeRTOS task; logs the
// outcome.
static void start_ultrawidelock_reader_once(void)
{
	static bool started = false;
	if (started) {
		return;
	}
	started = true;
	/* 12 KiB, not the previous 8: ultrawidelock_reader_start_attached() runs a deep chain
	 * (NimBLE GATT/L2CAP registration, NVS reads, P-256 setup) before the poll loop
	 * begins. `status` reports the high-water mark so the real headroom is measurable
	 * rather than assumed. */
	xTaskCreate(ultrawidelock_reader_task, "ultrawidelock_reader", 12288, nullptr, 5,
		    &ultrawidelock_reader_task_handle);
	ESP_LOGI(TAG, "credential reader (attach mode) task started");
}

/* SNTP feeds ONLY the credential advertisement's dynamic-tag expiry (ultrawidelock_ble.c);
 * nothing credential- or Matter-facing consumes it here, so a spoofed server
 * can at worst break approach-unlock. Fail-open: until the first sync the advert carries the
 * spec's "expiry unavailable" form, which phones still resolve. */
static void sntp_synced_cb(struct timeval *tv)
{
	(void)tv;
	ultrawidelock_ble_time_updated(); /* re-derive the advertised tag right away */
}

// Start SNTP once the interface has an address; every (re)sync steps the wall
// clock and pokes the credential advertiser through sntp_synced_cb.
static void start_sntp_once(void)
{
	static bool started = false;
	if (started) {
		return;
	}
	started = true;
	esp_sntp_config_t cfg = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
	cfg.sync_cb = sntp_synced_cb;
	esp_err_t err = esp_netif_sntp_init(&cfg);
	ESP_LOGI(TAG, "SNTP started for the credential dynamic tag (%s)", esp_err_to_name(err));
}
#endif // CONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB

// Matter device-event callback: logs commissioning/fabric/BLE lifecycle events and, when credential
// BLE+UWB support is enabled, starts the credential reader once commissioning completes (Matter
// releases the BLE advertiser at that point). On the last fabric being removed, reopens a
// DNS-SD-only commissioning window if one is not already open.
static void app_event_cb(const ChipDeviceEvent *event, intptr_t arg)
{
	switch (event->Type) {
	case chip::DeviceLayer::DeviceEventType::kInterfaceIpAddressChanged:
		ESP_LOGI(TAG, "Interface IP Address changed");
#ifdef CONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB
		start_sntp_once(); /* wall time -> live dynamic-tag expiry */
#endif
#ifdef CONFIG_ENABLE_HA_MQTT
		/* Matter owns the station and the netif; this only attaches once
		 * that interface has an address. Idempotent, and it does no more
		 * than spawn the publisher task, so the Matter event loop is not
		 * held while a TLS session comes up. */
		ha_mqtt_start_once();
#endif
		break;

	case chip::DeviceLayer::DeviceEventType::kCommissioningComplete:
		ESP_LOGI(TAG, "Commissioning complete");
#ifdef CONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB
		// Matter stops advertising when commissioning completes; the reader can
		// now take the advertiser and run the local BLE+UWB credential transaction.
		start_ultrawidelock_reader_once();
#endif
		break;

	case chip::DeviceLayer::DeviceEventType::kFailSafeTimerExpired:
		ESP_LOGI(TAG, "Commissioning failed, fail safe timer expired");
		break;

	case chip::DeviceLayer::DeviceEventType::kCommissioningSessionStarted:
		ESP_LOGI(TAG, "Commissioning session started");
		break;

	case chip::DeviceLayer::DeviceEventType::kCommissioningSessionStopped:
		ESP_LOGI(TAG, "Commissioning session stopped");
		break;

	case chip::DeviceLayer::DeviceEventType::kCommissioningWindowOpened:
		ESP_LOGI(TAG, "Commissioning window opened");
		break;

	case chip::DeviceLayer::DeviceEventType::kCommissioningWindowClosed:
		ESP_LOGI(TAG, "Commissioning window closed");
		break;

	case chip::DeviceLayer::DeviceEventType::kFabricRemoved: {
		ESP_LOGI(TAG, "Fabric removed successfully");
		if (chip::Server::GetInstance().GetFabricTable().FabricCount() == 0) {
#ifdef CONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB
			/* The last home just removed this lock: drop its credential reader
			 * config (delegate RAM) and revert the reader identity + trust
			 * store to the dev defaults (RAM + NVS). Otherwise the old
			 * home's phones could still authenticate, and the stale
			 * verification key makes the next home's SetAliroReaderConfig
			 * fail InvalidInState. Runs on the Matter task, as required. */
			UltraWideLockReaderDelegate::Instance().ClearAliroReaderConfig();
#endif
			chip::CommissioningWindowManager &commissionMgr =
				chip::Server::GetInstance().GetCommissioningWindowManager();
			constexpr auto kTimeoutSeconds =
				chip::System::Clock::Seconds16(k_timeout_seconds);
			if (!commissionMgr.IsCommissioningWindowOpen()) {
				/* After removing last fabric, this example does not remove the
				 * Wi-Fi credentials and still has IP connectivity so, only
				 * advertising on DNS-SD.
				 */
				CHIP_ERROR err = commissionMgr.OpenBasicCommissioningWindow(
					kTimeoutSeconds,
					chip::CommissioningWindowAdvertisement::kDnssdOnly);
				if (err != CHIP_NO_ERROR) {
					ESP_LOGE(TAG,
						 "Failed to open commissioning window, "
						 "err:%" CHIP_ERROR_FORMAT,
						 err.Format());
				}
			}
		}
		break;
	}

	case chip::DeviceLayer::DeviceEventType::kFabricWillBeRemoved:
		ESP_LOGI(TAG, "Fabric will be removed");
		break;

	case chip::DeviceLayer::DeviceEventType::kFabricUpdated:
		ESP_LOGI(TAG, "Fabric is updated");
		break;

	case chip::DeviceLayer::DeviceEventType::kFabricCommitted:
		ESP_LOGI(TAG, "Fabric is committed");
		break;

	case chip::DeviceLayer::DeviceEventType::kBLEDeinitialized:
		ESP_LOGI(TAG, "BLE deinitialized and memory reclaimed");
		break;

	default:
		break;
	}
}

// This callback is invoked when clients interact with the Identify Cluster.
// In the callback implementation, an endpoint can identify itself. (e.g., by flashing an LED or
// light).
static esp_err_t app_identification_cb(identification::callback_type_t type, uint16_t endpoint_id,
				       uint8_t effect_id, uint8_t effect_variant, void *priv_data)
{
	ESP_LOGI(TAG, "Identification callback: type: %u, effect: %u, variant: %u", type, effect_id,
		 effect_variant);
	return ESP_OK;
}

// This callback is called for every attribute update. The callback implementation shall
// handle the desired attributes and return an appropriate error code. If the attribute
// is not of your interest, please do not return an error code and strictly return ESP_OK.
static esp_err_t app_attribute_update_cb(attribute::callback_type_t type, uint16_t endpoint_id,
					 uint32_t cluster_id, uint32_t attribute_id,
					 esp_matter_attr_val_t *val, void *priv_data)
{
	esp_err_t err = ESP_OK;

	if (type == PRE_UPDATE) {
		/* Driver update */
		app_driver_handle_t driver_handle = (app_driver_handle_t)priv_data;
		err = app_driver_attribute_update(driver_handle, endpoint_id, cluster_id,
						  attribute_id, val);
	}

	return err;
}

// Application entry point: initializes NVS, the lock LED, power management, and the Matter node
// with a door lock endpoint (adding credential provisioning/BLE-UWB clusters and delegate when
// enabled). See app_priv.h. Schedules the open onto the Matter task, which is the only thread
// allowed to drive the server, and logs the outcome at WARN so it lands in the boot log at the
// default level rather than needing `log` turned up.
void app_commissioning_window_open()
{
	/* Not discarded: a schedule that fails means the window never opens, and
	 * both callers would otherwise report success and leave you waiting for an
	 * advertisement that is not coming. */
	CHIP_ERROR sched = chip::DeviceLayer::PlatformMgr().ScheduleWork([](intptr_t) {
		CHIP_ERROR e = chip::Server::GetInstance()
				       .GetCommissioningWindowManager()
				       .OpenBasicCommissioningWindow();

		if (e == CHIP_NO_ERROR) {
			ESP_LOGW(TAG, "commissioning window open; pair with the printed codes");
		} else {
			ESP_LOGE(TAG, "commissioning window failed: %" CHIP_ERROR_FORMAT,
				 e.Format());
		}
	});

	if (sched != CHIP_NO_ERROR) {
		ESP_LOGE(TAG, "commissioning window not scheduled: %" CHIP_ERROR_FORMAT,
			 sched.Format());
	}
}

// See app_priv.h.
void app_print_onboarding_codes()
{
	char code[chip::QRCodeBasicSetupPayloadGenerator::kMaxQRCodeBase38RepresentationLength + 1];
	const chip::RendezvousInformationFlags rendezvous(chip::RendezvousInformationFlag::kBLE);

	chip::DeviceLayer::PlatformMgr().LockChipStack();
	chip::MutableCharSpan qr(code);
	if (GetQRCode(qr, rendezvous) == CHIP_NO_ERROR) {
		char url[512];

		printf("SetupQRCode: [%s]\n", qr.data());
		if (GetQRCodeUrl(url, sizeof(url), qr) == CHIP_NO_ERROR) {
			printf("QR code URL: %s\n", url);
		}
	} else {
		printf("SetupQRCode: unavailable\n");
	}
	chip::MutableCharSpan manual(code);
	if (GetManualPairingCode(manual, rendezvous) == CHIP_NO_ERROR) {
		printf("Manual pairing code: [%s]\n", manual.data());
	} else {
		printf("Manual pairing code: unavailable\n");
	}
	chip::DeviceLayer::PlatformMgr().UnlockChipStack();
}

/* Long press opens a commissioning window rather than the factory reset the
 * esp-matter examples map here. On a lock a mispress should cost a 3 minute
 * advertisement, not every fabric and the credential trust store. */
static void on_button_long_press(void *button_handle, void *usr_data)
{
	(void)button_handle;
	(void)usr_data;
	app_commissioning_window_open();
}

#ifdef CONFIG_ULTRAWIDELOCK_DFU_ESP32
/* Double-click opens the update window.
 *
 * A SEPARATE GESTURE FROM THE LONG PRESS, on the same and only button. The long
 * press already means "let a new fabric in" and is the one people are told
 * about; overloading it would mean anyone opening a commissioning window also
 * spent five minutes accepting firmware from whoever was in radio range.
 *
 * That window is the whole authorisation model for updates. The image is signed
 * and the bootloader re-validates it, so no peer can install code regardless --
 * what the window prevents is an unauthenticated peer erasing a 3 MB slot and
 * forcing reboots, which on a door lock is a real availability attack.
 */
static void on_button_double_click(void *button_handle, void *usr_data)
{
	(void)button_handle;
	(void)usr_data;
	ultrawidelock_dfu_esp32_open_window(CONFIG_ULTRAWIDELOCK_DFU_WINDOW_MS);
	ESP_LOGI(TAG, "update window open for %d ms", CONFIG_ULTRAWIDELOCK_DFU_WINDOW_MS);
}
#endif

// Registers the credential reader's GATT service with the BLE host before esp_matter::start so it
// coexists with CHIPoBLE. Starts Matter, prints onboarding codes, and if already commissioned (e.g.
// after a reboot) starts the credential reader immediately; otherwise the reader starts on the
// kCommissioningComplete event. Finally launches the interactive console (app_shell_start), which
// must not run alongside esp_matter::console::init since both read the same console UART.
extern "C" void app_main()
{
	esp_err_t err = ESP_OK;

	/* Initialize the ESP NVS layer */
	nvs_flash_init();

#ifdef CONFIG_ULTRAWIDELOCK_PIV_CCID
	/*
	 * Native USB is deliberately independent of the external USB-UART used
	 * for flashing and recovery. This option is off in normal firmware.
	 */
	err = piv_ccid_usb_start();
	ABORT_APP_ON_FAILURE(err == ESP_OK,
			     ESP_LOGE(TAG, "Failed to start PIV CCID USB, err:%d", err));
#endif

	/* Bolt-state indicator. Before Matter start, so the first LockState update
	 * that lands already has somewhere to go. */
	app_driver_led_init();

#if CONFIG_PM_ENABLE
	esp_pm_config_t pm_config = {.max_freq_mhz = CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ,
				     .min_freq_mhz = CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ,
#if CONFIG_FREERTOS_USE_TICKLESS_IDLE
				     .light_sleep_enable = true
#endif
	};
	err = esp_pm_configure(&pm_config);
#endif

	/* Create a Matter node and add the mandatory Root Node device type on endpoint 0 */
	node::config_t node_config;

	// node handle can be used to add/modify other endpoints.
	node_t *node = node::create(&node_config, app_attribute_update_cb, app_identification_cb);
	ABORT_APP_ON_FAILURE(node != nullptr, ESP_LOGE(TAG, "Failed to create Matter node"));

	door_lock::config_t door_lock_config;
#ifdef CONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB
	UltraWideLockReaderDelegate::Instance().Init();
	door_lock_config.door_lock.delegate = &UltraWideLockReaderDelegate::Instance();
#endif
	door_lock_config.door_lock.lock_state = chip::to_underlying(DoorLock::DlLockState::kLocked);
	cluster::door_lock::feature::credential_over_the_air_access::config_t cota_config;
	cluster::door_lock::feature::pin_credential::config_t pin_credential_config;
	cluster::door_lock::feature::user::config_t user_config;
	// endpoint handles can be used to add/modify clusters.
	endpoint_t *endpoint = door_lock::create(node, &door_lock_config, ENDPOINT_FLAG_NONE, NULL);
	ABORT_APP_ON_FAILURE(endpoint != nullptr,
			     ESP_LOGE(TAG, "Failed to create door lock endpoint"));
	cluster_t *door_lock_cluster = cluster::get(endpoint, DoorLock::Id);
	cluster::door_lock::feature::credential_over_the_air_access::add(door_lock_cluster,
									 &cota_config);
	cluster::door_lock::feature::pin_credential::add(door_lock_cluster, &pin_credential_config);
	cluster::door_lock::feature::user::add(door_lock_cluster, &user_config);
#ifdef CONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB
	cluster::door_lock::feature::aliro_provisioning::add(door_lock_cluster);
	cluster::door_lock::feature::aliro_bleuwb::add(door_lock_cluster);

#if APPROACH_DIRECTION_CLUSTER
	/* See the constants above for the descriptor this mirrors. FeatureMap and
	 * ClusterRevision are mandatory on every cluster, and cluster::create() does not
	 * emit them, so they are added explicitly. */
	cluster_t *approach_dir_cluster =
		cluster::create(endpoint, kApproachDirectionClusterId, CLUSTER_FLAG_SERVER);
	if (approach_dir_cluster != nullptr) {
		attribute::create(approach_dir_cluster, kApproachDirectionAttributeId,
				  ATTRIBUTE_FLAG_WRITABLE | ATTRIBUTE_FLAG_NONVOLATILE,
				  esp_matter_bitmap8(kApproachDirectionAll));
		cluster::global::attribute::create_feature_map(approach_dir_cluster,
							      kApproachDirectionFeatureMap);
		cluster::global::attribute::create_cluster_revision(
			approach_dir_cluster, kApproachDirectionClusterRevision);
		ESP_LOGI(TAG, "Approach Direction cluster 0x%08X created",
			 (unsigned)kApproachDirectionClusterId);
	} else {
		ESP_LOGE(TAG, "Failed to create Approach Direction cluster");
	}
#endif /* APPROACH_DIRECTION_CLUSTER */
#endif
	// 0 disables CHIP's fixed auto-relock timer (DoorLockServer skips scheduling when
	// AutoRelockTime == 0). Relock is driven by proximity instead: the reader task
	// relocks when the credential peer leaves range (see ultrawidelock_reader_task).
	cluster::door_lock::attribute::create_auto_relock_time(door_lock_cluster, 0);

	door_lock_endpoint_id = endpoint::get_id(endpoint);
	ESP_LOGI(TAG, "Door lock created with endpoint_id %d", door_lock_endpoint_id);

#if CHIP_DEVICE_CONFIG_ENABLE_THREAD
	/* Set OpenThread platform config */
	esp_openthread_platform_config_t config = {
		.radio_config = ESP_OPENTHREAD_DEFAULT_RADIO_CONFIG(),
		.host_config = ESP_OPENTHREAD_DEFAULT_HOST_CONFIG(),
		.port_config = ESP_OPENTHREAD_DEFAULT_PORT_CONFIG(),
	};
	set_openthread_platform_config(&config);
#endif

#if defined(CONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB) || defined(CONFIG_ULTRAWIDELOCK_DFU_ESP32)
	/* Register our GATT services on Matter's NimBLE host BEFORE the Matter server
	 * builds its GATT table, so they coexist with CHIPoBLE. Must be called before
	 * esp_matter::start (which runs InitServer).
	 *
	 * ONE VECTOR, ONE CALL, and that is not a style choice. NimBLE builds its
	 * attribute table exactly once, at ble_gatts_start(), and
	 * ConfigureExtraServices refuses a second call with CHIP_ERROR_INCORRECT_STATE
	 * once mGattSvcs is non-empty. So every extra service this image publishes has
	 * to arrive here together; a service registered later is not rejected, it is
	 * simply absent, which is a far worse way to find out. */
	{
		// The BLE host's combined extra-service table. Each entry is copied by
		// value, and CHIP appends CHIPoBLE and its own terminator.
		std::vector<struct ble_gatt_svc_def> svcs;

#ifdef CONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB
		const struct ble_gatt_svc_def *ultrawidelock_svc =
			static_cast<const struct ble_gatt_svc_def *>(ultrawidelock_reader_ble_prepare());
		if (ultrawidelock_svc != nullptr) {
			svcs.push_back(*ultrawidelock_svc);
		} else {
			ESP_LOGE(TAG,
				 "ultrawidelock_reader_ble_prepare failed; reader GATT not registered");
		}
#endif

#ifdef CONFIG_ULTRAWIDELOCK_DFU_ESP32
		/* Before the service goes in, so no frame can ever reach a receiver
		 * whose commit hook is not installed. Without the hook an update is
		 * received, verified, written -- and then ignored at the next boot,
		 * because nothing pointed the bootloader at the new slot. */
		ultrawidelock_dfu_esp32_init();

		const struct ble_gatt_svc_def *dfu_svc = ultrawidelock_dfu_esp32_service_def();
		if (dfu_svc != nullptr) {
			svcs.push_back(*dfu_svc);
		} else {
			ESP_LOGE(TAG, "DFU GATT not registered; no over-the-air updates");
		}
#endif

		if (!svcs.empty()) {
			CHIP_ERROR e =
				chip::DeviceLayer::Internal::BLEMgrImpl().ConfigureExtraServices(
					svcs, true);
			ESP_LOGI(TAG, "%u extra GATT service(s) registered: %" CHIP_ERROR_FORMAT,
				 static_cast<unsigned>(svcs.size()), e.Format());
		}
	}
#endif

	/* Matter start */
	err = esp_matter::start(app_event_cb);
	ABORT_APP_ON_FAILURE(err == ESP_OK, ESP_LOGE(TAG, "Failed to start Matter, err:%d", err));

	/* CONFIG_LOG_DEFAULT_LEVEL WARN compiles CHIP Progress logging out of the
	 * whole CHIP library (CHIP_LOG_DEFAULT_LEVEL is Kconfig-range-capped to
	 * LOG_DEFAULT_LEVEL and gates chip_progress_logging in the GN build), so
	 * PrintOnboardingCodes emits nothing and no runtime log level can bring
	 * it back. Print the commissioning codes directly so they are always in
	 * the boot log (Apple Home / chip-tool). BLE is the initial transport. */
	app_print_onboarding_codes();

	/* The button handle was being created and immediately dropped. Wire the
	 * long press (CONFIG_BUTTON_LONG_PRESS_TIME_MS, 5 s) to the commissioning
	 * window, so a board that lost its Wi-Fi credentials can be recovered with
	 * no console attached at all. After esp_matter::start, because the callback
	 * schedules work onto a server that has to exist. */
	{
		app_driver_handle_t btn = app_driver_button_init();

		if (btn != nullptr) {
			esp_err_t berr = iot_button_register_cb((button_handle_t)btn,
								BUTTON_LONG_PRESS_START, NULL,
								on_button_long_press, NULL);

			if (berr != ESP_OK) {
				ESP_LOGW(TAG, "button long-press hook failed: %d", (int)berr);
			}

#ifdef CONFIG_ULTRAWIDELOCK_DFU_ESP32
			berr = iot_button_register_cb((button_handle_t)btn,
						      BUTTON_DOUBLE_CLICK, NULL,
						      on_button_double_click, NULL);

			if (berr != ESP_OK) {
				ESP_LOGW(TAG, "button double-click hook failed: %d", (int)berr);
			}
#endif
		}
	}

	/* do nothing now */
	door_lock_init();

#ifdef CONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB
	/* Already commissioned (e.g. a reboot): Matter is not advertising over BLE, so
	 * bring the reader up now. A fresh commission starts it on kCommissioningComplete. */
	if (chip::Server::GetInstance().GetFabricTable().FabricCount() > 0) {
		ESP_LOGI(TAG, "Already commissioned; starting credential reader on shared host");
		start_ultrawidelock_reader_once();
	}
#endif

#if CONFIG_ENABLE_ENCRYPTED_OTA
	err = esp_matter_ota_requestor_encrypted_init(s_decryption_key, s_decryption_key_len);
	ABORT_APP_ON_FAILURE(
		err == ESP_OK,
		ESP_LOGE(TAG, "Failed to initialized the encrypted OTA, err: %d", err));
#endif // CONFIG_ENABLE_ENCRYPTED_OTA

#ifdef CONFIG_ULTRAWIDELOCK_DFU_ESP32
	/* Cancel the pending rollback, if this boot is the first after an update.
	 *
	 * HERE, AT THE END, and not one line earlier. With
	 * CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE the bootloader reverts to the
	 * previous slot unless the new image says it is healthy, and "healthy" has
	 * to mean something: reaching the top of app_main proves only that the
	 * image links. By this point Matter has started, the lock endpoint exists
	 * and the credential reader is either running or waiting on commissioning,
	 * which is as much as can be checked without someone walking up to the
	 * door. An update that panics before this line gets one more reboot on the
	 * old firmware rather than a lock that no longer answers. */
	(void)ultrawidelock_dfu_esp32_confirm();
#endif

	/* Interactive console. This replaces esp_matter::console::init(), whose CHIP
	 * shell has no line editing and loses your input whenever a log line lands.
	 * Only one of the two may run: both read the same console UART. */
	app_shell_start();
}
