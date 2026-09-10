/*
 * Host test for the ESP32 matter-lock app glue (app_driver / app_main /
 * app_shell / door_lock_manager / door_lock_callbacks / ultrawidelock_reader_delegate)
 * against the matterfake/ CHIP + esp-matter recording doubles. "Theatre"
 * suite: the Matter stack, NimBLE host, console, LED driver and credential reader
 * are all fakes, so passing proves the units' branch logic and argument
 * plumbing (state machines, index bounds, persistence calls, event dispatch)
 * — never CHIP-stack, radio, hardware, or crypto truth.
 *
 * Sections (one linear script; the production singletons are process-global):
 *   A  app_driver: LED init failure/success, lock-state colors, button init
 *   B  ultrawidelock_reader_delegate: getters, config set/clear, size validation
 *   C  door_lock_manager: init bounds, NVM blobs, users/credentials/schedules
 *   D  door_lock_callbacks: every plugin hook incl. the credential trust mirror
 *   E  app_main boot: endpoint/cluster assembly, GATT pre-registration
 *   F  Matter device events: SNTP, reader start, fabric-removal recovery
 *   G  attribute / identification callbacks
 *   H  ultrawidelock_reader_task approach controller (median, dwell, peer-gone)
 *   I  UWB range listener (task wake, ISR vs task context)
 *   J  console commands (status/range/ultrawidelock/uwbdiag/lock/unlock/codes/
 *      log/lab/factoryreset/clear)
 *   K  app_main reboot path (already commissioned, degraded branches)
 */
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "matterfake.h"

#include "esp_console.h"
#include "esp_matter.h"
#include "iot_button.h" // BUTTON_LONG_PRESS_START — the commissioning-window press
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* Include-order sentinel. This binary puts BOTH fake trees on the include path
 * (-I matterfake -I sdkfake in run.sh) and four header paths exist in both;
 * matterfake wins by order and must, because its copies carry what the
 * matter-lock app needs and sdkfake's do not (esp_console's .hint member, task
 * notifications, the ESP-IDF portYIELD_FROM_ISR spelling, the C++-guarded
 * NimBLE service type). Each shadowing copy defines its marker; if the order
 * ever flips, this fails here instead of as unrelated errors inside the app
 * sources. ble_hs.h is included only for that coverage — app_main.cpp is the
 * file that actually needs it. */
#include "host/ble_hs.h"
#if !defined(MATTERFAKE_SHADOWS_ESP_CONSOLE) || !defined(MATTERFAKE_SHADOWS_FREERTOS) || \
	!defined(MATTERFAKE_SHADOWS_FREERTOS_TASK) || !defined(MATTERFAKE_SHADOWS_BLE_HS)
#error "sdkfake shadowed matterfake; check the -I order in tests/ports/esp32/run.sh"
#endif

#include "esp_log.h"
#include "ultrawidelock_lat.h"
#include "ultrawidelock_diag.h"
#include "uwb_cirdiag.h"

#include "app_priv.h"
#include "app_shell.h"
#include "door_lock_manager.h"
#include "ultrawidelock_reader_delegate.h"
#include "lock_led.h"

extern uint16_t door_lock_endpoint_id;
extern TaskHandle_t ultrawidelock_reader_task_handle;
extern "C" void app_main();

static int fails;

static void okc(const char *name, int cond)
{
	if (!cond) {
		printf("  FAIL %s\n", name);
		fails++;
	} else {
		printf("  ok   %s\n", name);
	}
}

/* ---- helpers -------------------------------------------------------------- */
/* A wake with the credential session up (the usual case: ranging implies a session). */
static void wake_push(uint32_t wake, int trusted, int32_t cm, int64_t advance_ms,
		      int session = 1, int start_bump = 0)
{
	if (mfk_wake_len < MFK_WAKE_MAX) {
		mfk_wake_script[mfk_wake_len].wake = wake;
		mfk_wake_script[mfk_wake_len].trusted = trusted;
		mfk_wake_script[mfk_wake_len].cm = cm;
		mfk_wake_script[mfk_wake_len].advance_ms = advance_ms;
		mfk_wake_script[mfk_wake_len].session = session;
		mfk_wake_script[mfk_wake_len].start_bump = start_bump;
		mfk_wake_len++;
	}
}

/* The peer's session ended: the departure signal the approach controller acts on. */
static void wake_push_session_gone(void)
{
	wake_push(0, 0, 0, 200, 0);
}

static int run_cmd(const char *name, int argc, const char *a1 = nullptr,
		   const char *a2 = nullptr)
{
	static char b0[24], b1[24], b2[24];
	char *argv[3] = {b0, b1, b2};
	snprintf(b0, sizeof(b0), "%s", name);
	if (a1 != nullptr) {
		snprintf(b1, sizeof(b1), "%s", a1);
	}
	if (a2 != nullptr) {
		snprintf(b2, sizeof(b2), "%s", a2);
	}
	int (*fn)(int, char **) = mfk_cmd_lookup(name);
	if (fn == nullptr) {
		return -999;
	}
	return fn(argc, argv);
}

static const chip::app::DataModel::Nullable<uint16_t> kNullUser;

/* ---- A: app_driver --------------------------------------------------------- */
static void section_app_driver(void)
{
	printf("-- app_driver\n");
	mfk_reset();

	mfk_led_new_rc = ESP_FAIL;
	okc("led init failure propagates rc", app_driver_led_init() == ESP_FAIL);
	app_driver_led_lock_state(true, false);
	okc("led writes silently dropped after failed init", mfk_led_set_calls == 0);

	mfk_led_new_rc = ESP_OK;
	okc("led init ok", app_driver_led_init() == ESP_OK);
	okc("C6 onboard LED is GPIO8", mfk_led_gpio == 8);
	okc("led cleared on init", mfk_led_clears == 1);

	struct lock_led_rgb c = lock_led_color(true, false);
	app_driver_led_lock_state(true, false);
	okc("locked color pushed to pixel 0",
	    mfk_led_set_calls == 1 && mfk_led_last_index == 0 && mfk_led_r == c.r &&
		    mfk_led_g == c.g && mfk_led_b == c.b);
	okc("led refreshed", mfk_led_refreshes == 1);

	c = lock_led_color(false, true);
	app_driver_led_lock_state(false, true);
	okc("ultrawidelock-unlock color pushed",
	    mfk_led_r == c.r && mfk_led_g == c.g && mfk_led_b == c.b);

	c = lock_led_color(false, false);
	app_driver_led_lock_state(false, false);
	okc("manual-unlock color pushed",
	    mfk_led_r == c.r && mfk_led_g == c.g && mfk_led_b == c.b);

	okc("attribute update stub returns ESP_OK",
	    app_driver_attribute_update(nullptr, 1, 2, 3, nullptr) == ESP_OK);

	okc("button init returns bsp handle", app_driver_button_init() != nullptr);
	okc("bsp button driver initialized once", mfk_bsp_button_calls == 1);
}

/* ---- B: ultrawidelock_reader_delegate ---------------------------------------------- */
static void section_delegate(void)
{
	printf("-- ultrawidelock_reader_delegate\n");
	mfk_reset();
	UltraWideLockReaderDelegate &d = UltraWideLockReaderDelegate::Instance();

	/* RNG failure first: the error branch zeroes the sub-id and latches, so
	 * this is the only shot at it (singleton, no reset). */
	mfk_drbg_fail = 1;
	d.Init();
	okc("sub-id RNG consulted once", mfk_drbg_calls == 1);

	uint8_t buf65[65], buf16[16], buf2[2];
	chip::MutableByteSpan vk(buf65);
	okc("verification key empty when unconfigured",
	    d.GetAliroReaderVerificationKey(vk) == CHIP_NO_ERROR && vk.size() == 0);

	chip::MutableByteSpan gid(buf16);
	okc("group id empty when unconfigured",
	    d.GetAliroReaderGroupIdentifier(gid) == CHIP_NO_ERROR && gid.size() == 0);

	chip::MutableByteSpan grk(buf16);
	okc("group resolving key empty when unconfigured",
	    d.GetAliroGroupResolvingKey(grk) == CHIP_NO_ERROR && grk.size() == 0);

	uint8_t zeros16[16] = {0};
	chip::MutableByteSpan sub(buf16);
	okc("sub-id returned (zeroed by failed RNG), no RNG retry",
	    d.GetAliroReaderGroupSubIdentifier(sub) == CHIP_NO_ERROR && sub.size() == 16 &&
		    memcmp(buf16, zeros16, 16) == 0 && mfk_drbg_calls == 1);

	chip::MutableByteSpan pv(buf2);
	okc("expedited protocol version index 0 is BE 0x0100",
	    d.GetAliroExpeditedTransactionSupportedProtocolVersionAtIndex(0, pv) ==
			    CHIP_NO_ERROR &&
		    pv.size() == 2 && buf2[0] == 0x01 && buf2[1] == 0x00);
	chip::MutableByteSpan pv1(buf2);
	okc("expedited protocol version index 1 exhausts the list",
	    d.GetAliroExpeditedTransactionSupportedProtocolVersionAtIndex(1, pv1) ==
		    CHIP_ERROR_PROVIDER_LIST_EXHAUSTED);
	memset(buf2, 0, sizeof(buf2));
	chip::MutableByteSpan pvb(buf2);
	okc("ble-uwb protocol version index 0 is BE 0x0100",
	    d.GetAliroSupportedBLEUWBProtocolVersionAtIndex(0, pvb) == CHIP_NO_ERROR &&
		    buf2[0] == 0x01 && buf2[1] == 0x00);
	chip::MutableByteSpan pvb1(buf2);
	okc("ble-uwb protocol version index 1 exhausts the list",
	    d.GetAliroSupportedBLEUWBProtocolVersionAtIndex(1, pvb1) ==
		    CHIP_ERROR_PROVIDER_LIST_EXHAUSTED);
	chip::MutableByteSpan tiny(buf65, 1);
	okc("short span rejected for protocol version",
	    d.GetAliroExpeditedTransactionSupportedProtocolVersionAtIndex(0, tiny) ==
		    CHIP_ERROR_INVALID_ARGUMENT);

	okc("advertising version is 0", d.GetAliroBLEAdvertisingVersion() == 0);
	okc("issuer keys supported", d.GetNumberOfAliroCredentialIssuerKeysSupported() == 10);
	okc("endpoint keys supported", d.GetNumberOfAliroEndpointKeysSupported() == 10);

	uint8_t sk[32], vkey[65], gidv[16], grkv[16];
	memset(sk, 0x11, sizeof(sk));
	memset(vkey, 0x22, sizeof(vkey));
	memset(gidv, 0x33, sizeof(gidv));
	memset(grkv, 0x44, sizeof(grkv));

	okc("bad signing key size rejected",
	    d.SetAliroReaderConfig(chip::ByteSpan(sk, 31), chip::ByteSpan(vkey),
				   chip::ByteSpan(gidv), chip::Optional<chip::ByteSpan>()) ==
		    CHIP_ERROR_INVALID_ARGUMENT);
	okc("bad verification key size rejected",
	    d.SetAliroReaderConfig(chip::ByteSpan(sk), chip::ByteSpan(vkey, 64),
				   chip::ByteSpan(gidv), chip::Optional<chip::ByteSpan>()) ==
		    CHIP_ERROR_INVALID_ARGUMENT);
	okc("bad group id size rejected",
	    d.SetAliroReaderConfig(chip::ByteSpan(sk), chip::ByteSpan(vkey),
				   chip::ByteSpan(gidv, 15), chip::Optional<chip::ByteSpan>()) ==
		    CHIP_ERROR_INVALID_ARGUMENT);
	okc("bad group resolving key size rejected",
	    d.SetAliroReaderConfig(chip::ByteSpan(sk), chip::ByteSpan(vkey),
				   chip::ByteSpan(gidv),
				   chip::Optional<chip::ByteSpan>(chip::ByteSpan(grkv, 15))) ==
		    CHIP_ERROR_INVALID_ARGUMENT);
	okc("no identity persisted while rejected", mfk_prov_identity_calls == 0);

	okc("config without grk accepted",
	    d.SetAliroReaderConfig(chip::ByteSpan(sk), chip::ByteSpan(vkey),
				   chip::ByteSpan(gidv), chip::Optional<chip::ByteSpan>()) ==
		    CHIP_NO_ERROR);
	uint8_t zeros[16] = {0};
	okc("identity persisted: reader id = group id || sub id",
	    mfk_prov_identity_calls == 1 && memcmp(mfk_prov_reader_id, gidv, 16) == 0 &&
		    memcmp(mfk_prov_reader_id + 16, zeros, 16) == 0);
	okc("identity persisted: signing key + zero grk",
	    memcmp(mfk_prov_sign, sk, 32) == 0 && memcmp(mfk_prov_grk, zeros, 16) == 0);
	okc("advert refreshed after config", mfk_refresh_adv_calls == 1);

	chip::MutableByteSpan vk2(buf65);
	okc("verification key round-trips once configured",
	    d.GetAliroReaderVerificationKey(vk2) == CHIP_NO_ERROR && vk2.size() == 65 &&
		    memcmp(buf65, vkey, 65) == 0);
	chip::MutableByteSpan gid2(buf16);
	okc("group id round-trips once configured",
	    d.GetAliroReaderGroupIdentifier(gid2) == CHIP_NO_ERROR &&
		    memcmp(buf16, gidv, 16) == 0);

	okc("config with grk accepted",
	    d.SetAliroReaderConfig(chip::ByteSpan(sk), chip::ByteSpan(vkey),
				   chip::ByteSpan(gidv),
				   chip::Optional<chip::ByteSpan>(chip::ByteSpan(grkv))) ==
		    CHIP_NO_ERROR);
	okc("grk persisted", memcmp(mfk_prov_grk, grkv, 16) == 0);
	chip::MutableByteSpan grk2(buf16);
	okc("grk round-trips once configured",
	    d.GetAliroGroupResolvingKey(grk2) == CHIP_NO_ERROR && memcmp(buf16, grkv, 16) == 0);

	okc("clear reverts to unconfigured",
	    d.ClearAliroReaderConfig() == CHIP_NO_ERROR && mfk_prov_clear_calls == 1);
	chip::MutableByteSpan vk3(buf65);
	d.GetAliroReaderVerificationKey(vk3);
	okc("verification key empty again after clear", vk3.size() == 0);
}

/* ---- C: door_lock_manager --------------------------------------------------- */
static void section_manager(void)
{
	printf("-- door_lock_manager\n");
	mfk_reset();
	mfk_cfg_reset();
	BoltLockManager &mgr = BoltLockMgr();
	using ESP32DoorLock::LockInitParams::ParamBuilder;
	chip::app::DataModel::Nullable<DlLockState> nulls;

	okc("init rejects too many users",
	    mgr.Init(nulls, ParamBuilder().SetNumberOfUsers(11).GetLockParam()) ==
		    CHIP_ERROR_NO_MEMORY);
	okc("init rejects too many credentials per user",
	    mgr.Init(nulls, ParamBuilder()
				    .SetNumberOfUsers(10)
				    .SetNumberOfCredentialsPerUser(11)
				    .GetLockParam()) == CHIP_ERROR_NO_MEMORY);
	okc("init rejects too many weekday schedules",
	    mgr.Init(nulls, ParamBuilder()
				    .SetNumberOfWeekdaySchedulesPerUser(11)
				    .GetLockParam()) == CHIP_ERROR_NO_MEMORY);
	okc("init rejects too many yearday schedules",
	    mgr.Init(nulls, ParamBuilder()
				    .SetNumberOfYeardaySchedulesPerUser(11)
				    .GetLockParam()) == CHIP_ERROR_NO_MEMORY);
	okc("init rejects too many holiday schedules",
	    mgr.Init(nulls, ParamBuilder().SetNumberOfHolidaySchedules(11).GetLockParam()) ==
		    CHIP_ERROR_NO_MEMORY);
	okc("init accepts the platform limits",
	    mgr.Init(nulls, ParamBuilder()
				    .SetNumberOfUsers(10)
				    .SetNumberOfCredentialsPerUser(10)
				    .SetNumberOfWeekdaySchedulesPerUser(10)
				    .SetNumberOfYeardaySchedulesPerUser(10)
				    .SetNumberOfHolidaySchedules(10)
				    .GetLockParam()) == CHIP_NO_ERROR);

	okc("user index bounds", mgr.IsValidUserIndex(0) && mgr.IsValidUserIndex(9) &&
					 !mgr.IsValidUserIndex(10));
	okc("programming pin only valid at index 0",
	    mgr.IsValidCredentialIndex(0, CredentialTypeEnum::kProgrammingPIN) &&
		    !mgr.IsValidCredentialIndex(1, CredentialTypeEnum::kProgrammingPIN));
	okc("pin credential index bounds",
	    mgr.IsValidCredentialIndex(9, CredentialTypeEnum::kPin) &&
		    !mgr.IsValidCredentialIndex(10, CredentialTypeEnum::kPin));
	okc("credential storage index packs type * 10 + index",
	    mgr.CredentialStorageIndex(3, CredentialTypeEnum::kPin) == 13 &&
		    mgr.CredentialStorageIndex(0, CredentialTypeEnum::kAliroEvictableEndpointKey) ==
			    70);
	okc("schedule index bounds",
	    mgr.IsValidWeekdayScheduleIndex(9) && !mgr.IsValidWeekdayScheduleIndex(10) &&
		    mgr.IsValidYeardayScheduleIndex(9) && !mgr.IsValidYeardayScheduleIndex(10) &&
		    mgr.IsValidHolidayScheduleIndex(9) && !mgr.IsValidHolidayScheduleIndex(10));

	okc("lock state names",
	    strcmp(mgr.lockStateToString(DlLockState::kNotFullyLocked), "Not Fully Locked") == 0 &&
		    strcmp(mgr.lockStateToString(DlLockState::kLocked), "Locked") == 0 &&
		    strcmp(mgr.lockStateToString(DlLockState::kUnlocked), "Unlocked") == 0 &&
		    strcmp(mgr.lockStateToString(DlLockState::kUnlatched), "Unlatched") == 0 &&
		    strcmp(mgr.lockStateToString(DlLockState::kUnknownEnumValue), "Unknown") == 0);

	/* persistence: empty store -> clean read, nothing rewritten */
	okc("read with empty store succeeds", mgr.ReadConfigValues());
	okc("empty store triggers no rewrite", mfk_cfg_write_calls == 0);

	/* a stale-sized blob forces a full clear + rewrite of all 8 tables */
	uint8_t junk[4] = {1, 2, 3, 4};
	mfk_cfg_put("lock-user", junk, sizeof(junk));
	okc("stale-size blob read still succeeds", mgr.ReadConfigValues());
	okc("stale store rewritten in full (8 blobs)", mfk_cfg_write_calls == 8);
	okc("rewritten user blob has this build's size",
	    mfk_cfg_len("lock-user") == (long)(sizeof(EmberAfPluginDoorLockUserInfo) * 10));

	/* a mixed-type legacy layout (occupied non-programming-PIN in slot 0) */
	static EmberAfPluginDoorLockCredentialInfo legacy[100];
	legacy[0].status = DlCredentialStatus::kOccupied;
	legacy[0].credentialType = CredentialTypeEnum::kPin;
	mfk_cfg_put("credential", legacy, sizeof(legacy));
	mfk_cfg_write_calls = 0;
	okc("legacy slot-0 layout detected + cleared",
	    mgr.ReadConfigValues() && mfk_cfg_write_calls == 8);

	/* injected read + rewrite failures */
	mfk_cfg_fail_read = "credential";
	okc("blob read error fails ReadConfigValues", !mgr.ReadConfigValues());
	mfk_cfg_fail_read = nullptr;
	mfk_cfg_put("lock-user", junk, sizeof(junk)); /* stale again */
	mfk_cfg_fail_write = "lock-user";
	okc("rewrite failure surfaces", !mgr.ReadConfigValues());
	mfk_cfg_fail_write = nullptr;
	okc("store recovers after failure knobs clear", mgr.ReadConfigValues());

	/* users */
	EmberAfPluginDoorLockUserInfo user;
	okc("get user rejects index 0", !mgr.GetUser(1, 0, user));
	okc("get user rejects index 11", !mgr.GetUser(1, 11, user));
	okc("get user index 10 (last slot) valid", mgr.GetUser(1, 10, user));
	okc("unoccupied slot reports available",
	    mgr.GetUser(1, 1, user) && user.userStatus == UserStatusEnum::kAvailable);

	CredentialStruct ultrawidelockLink;
	ultrawidelockLink.credentialType = CredentialTypeEnum::kAliroEvictableEndpointKey;
	ultrawidelockLink.credentialIndex = 1;
	okc("set user rejects index 0",
	    !mgr.SetUser(1, 0, 1, 1, chip::CharSpan("A", 1), 7, UserStatusEnum::kOccupiedEnabled,
			 UserTypeEnum::kUnrestrictedUser, CredentialRuleEnum::kSingle, &ultrawidelockLink,
			 1));
	okc("set user rejects index 11",
	    !mgr.SetUser(1, 11, 1, 1, chip::CharSpan("A", 1), 7, UserStatusEnum::kOccupiedEnabled,
			 UserTypeEnum::kUnrestrictedUser, CredentialRuleEnum::kSingle, &ultrawidelockLink,
			 1));
	okc("set user rejects an oversized name",
	    !mgr.SetUser(1, 1, 1, 1, chip::CharSpan("ABCDEFGHIJK", 11), 7,
			 UserStatusEnum::kOccupiedEnabled, UserTypeEnum::kUnrestrictedUser,
			 CredentialRuleEnum::kSingle, &ultrawidelockLink, 1));
	okc("set user rejects too many credentials",
	    !mgr.SetUser(1, 1, 1, 1, chip::CharSpan("A", 1), 7, UserStatusEnum::kOccupiedEnabled,
			 UserTypeEnum::kUnrestrictedUser, CredentialRuleEnum::kSingle, &ultrawidelockLink,
			 11));
	mfk_cfg_fail_write = "lock-user";
	okc("set user surfaces NVM write failure",
	    !mgr.SetUser(1, 1, 1, 1, chip::CharSpan("A", 1), 7, UserStatusEnum::kOccupiedEnabled,
			 UserTypeEnum::kUnrestrictedUser, CredentialRuleEnum::kSingle, &ultrawidelockLink,
			 1));
	mfk_cfg_fail_write = nullptr;
	okc("set user 1 (alice, ultrawidelock link)",
	    mgr.SetUser(1, 1, 2, 3, chip::CharSpan("alice", 5), 42,
			UserStatusEnum::kOccupiedEnabled, UserTypeEnum::kUnrestrictedUser,
			CredentialRuleEnum::kSingle, &ultrawidelockLink, 1));
	okc("get user 1 round-trips",
	    mgr.GetUser(1, 1, user) && user.userStatus == UserStatusEnum::kOccupiedEnabled &&
		    user.userName.size() == 5 && memcmp(user.userName.data(), "alice", 5) == 0 &&
		    user.userUniqueId == 42 && user.credentials.size() == 1 &&
		    user.credentials.data()[0].credentialIndex == 1 && user.createdBy == 2 &&
		    user.lastModifiedBy == 3);

	/* credentials */
	EmberAfPluginDoorLockCredentialInfo cred;
	okc("get credential: programming pin index 1 invalid",
	    !mgr.GetCredential(1, 1, CredentialTypeEnum::kProgrammingPIN, cred));
	okc("get credential: pin index 0 invalid (one-indexed)",
	    !mgr.GetCredential(1, 0, CredentialTypeEnum::kPin, cred));
	okc("get credential: programming pin slot 0 unoccupied",
	    mgr.GetCredential(1, 0, CredentialTypeEnum::kProgrammingPIN, cred) &&
		    cred.status == DlCredentialStatus::kAvailable);

	uint8_t pin[4] = {0x31, 0x32, 0x33, 0x34};
	uint8_t big[66] = {0};
	okc("set credential: pin index 0 invalid",
	    !mgr.SetCredential(1, 0, 1, 1, DlCredentialStatus::kOccupied,
			       CredentialTypeEnum::kPin, chip::ByteSpan(pin)));
	okc("set credential: oversized data rejected",
	    !mgr.SetCredential(1, 1, 1, 1, DlCredentialStatus::kOccupied,
			       CredentialTypeEnum::kPin, chip::ByteSpan(big)));
	mfk_cfg_fail_write = "credential";
	okc("set credential surfaces NVM write failure",
	    !mgr.SetCredential(1, 1, 1, 1, DlCredentialStatus::kOccupied,
			       CredentialTypeEnum::kPin, chip::ByteSpan(pin)));
	mfk_cfg_fail_write = nullptr;
	okc("set pin credential index 1",
	    mgr.SetCredential(1, 1, 4, 5, DlCredentialStatus::kOccupied,
			      CredentialTypeEnum::kPin, chip::ByteSpan(pin)));
	okc("get pin credential round-trips",
	    mgr.GetCredential(1, 1, CredentialTypeEnum::kPin, cred) &&
		    cred.status == DlCredentialStatus::kOccupied &&
		    cred.credentialType == CredentialTypeEnum::kPin &&
		    cred.credentialData.size() == 4 &&
		    memcmp(cred.credentialData.data(), pin, 4) == 0 && cred.createdBy == 4 &&
		    cred.lastModifiedBy == 5);

	/* ultrawidelock endpoint key attribution */
	static uint8_t alice_key[65];
	memset(alice_key, 0x5A, sizeof(alice_key));
	okc("set ultrawidelock endpoint key (user 1's credential 1)",
	    mgr.SetCredential(1, 1, 1, 1, DlCredentialStatus::kOccupied,
			      CredentialTypeEnum::kAliroEvictableEndpointKey,
			      chip::ByteSpan(alice_key)));

	/* user 2: link list exercising every skip branch of the scan */
	CredentialStruct skips[3];
	skips[0].credentialType = CredentialTypeEnum::kPin; /* non-ultrawidelock type */
	skips[0].credentialIndex = 1;
	skips[1].credentialType = CredentialTypeEnum::kAliroEvictableEndpointKey;
	skips[1].credentialIndex = 0; /* invalid one-indexed 0 */
	skips[2].credentialType = CredentialTypeEnum::kAliroNonEvictableEndpointKey;
	skips[2].credentialIndex = 3; /* valid index, unoccupied storage */
	okc("set user 2 (skip-branch links)",
	    mgr.SetUser(1, 2, 1, 1, chip::CharSpan("bob", 3), 43,
			UserStatusEnum::kOccupiedEnabled, UserTypeEnum::kUnrestrictedUser,
			CredentialRuleEnum::kSingle, skips, 3));

	okc("ultrawidelock credential attributes to user 1 (one-indexed)",
	    mgr.UserIndexForAliroCredential(chip::ByteSpan(alice_key)) == 1);
	uint8_t stranger[65];
	memset(stranger, 0xEE, sizeof(stranger));
	okc("unknown ultrawidelock credential attributes to nobody",
	    mgr.UserIndexForAliroCredential(chip::ByteSpan(stranger)) == 0);

	/* ValidatePIN */
	OperationErrorEnum oerr = OperationErrorEnum::kUnspecified;
	mfk_attr_requirepin_ok = 0; /* attribute read fails -> PIN not required */
	okc("no pin + attribute read failure passes",
	    mgr.ValidatePIN(1, Optional<chip::ByteSpan>(), oerr));
	mfk_attr_requirepin_ok = 1;
	mfk_attr_requirepin_val = 1;
	okc("no pin but pin required fails",
	    !mgr.ValidatePIN(1, Optional<chip::ByteSpan>(), oerr));
	okc("matching pin passes",
	    mgr.ValidatePIN(1, Optional<chip::ByteSpan>(chip::ByteSpan(pin)), oerr));
	uint8_t wrong[4] = {9, 9, 9, 9};
	oerr = OperationErrorEnum::kUnspecified;
	okc("wrong pin fails with invalid-credential",
	    !mgr.ValidatePIN(1, Optional<chip::ByteSpan>(chip::ByteSpan(wrong)), oerr) &&
		    oerr == OperationErrorEnum::kInvalidCredential);
	mfk_attr_requirepin_val = 0;

	/* lock / unlock actuation */
	mfk_led_set_calls = 0;
	mgr.Lock(1, OperationSourceEnum::kRemote, kNullUser);
	okc("lock drives cluster state + LED",
	    mfk_dls_last_state == (int)DlLockState::kLocked &&
		    mfk_dls_last_source == (int)OperationSourceEnum::kRemote &&
		    mfk_dls_last_user_null == 1 && mfk_led_set_calls == 1);
	mgr.Unlock(1, OperationSourceEnum::kAliro, chip::app::DataModel::MakeNullable<uint16_t>(2));
	struct lock_led_rgb ac = lock_led_color(false, true);
	okc("ultrawidelock unlock drives cluster state + ultrawidelock LED + user attribution",
	    mfk_dls_last_state == (int)DlLockState::kUnlocked &&
		    mfk_dls_last_source == (int)OperationSourceEnum::kAliro &&
		    mfk_dls_last_user_null == 0 && mfk_dls_last_user == 2 &&
		    mfk_led_r == ac.r && mfk_led_g == ac.g && mfk_led_b == ac.b);

	/* weekday schedules */
	EmberAfPluginDoorLockWeekDaySchedule wd;
	okc("weekday get rejects index 0", mgr.GetWeekdaySchedule(1, 0, 1, wd) == DlStatus::kFailure);
	okc("weekday get rejects user 0", mgr.GetWeekdaySchedule(1, 1, 0, wd) == DlStatus::kFailure);
	okc("weekday get rejects index 11",
	    mgr.GetWeekdaySchedule(1, 11, 1, wd) == DlStatus::kFailure);
	okc("weekday get rejects user 11",
	    mgr.GetWeekdaySchedule(1, 1, 11, wd) == DlStatus::kFailure);
	okc("weekday get on empty slot -> not found",
	    mgr.GetWeekdaySchedule(1, 1, 1, wd) == DlStatus::kNotFound);
	okc("weekday set rejects index 0",
	    mgr.SetWeekdaySchedule(1, 0, 1, DlScheduleStatus::kOccupied, DaysMaskMap::kMonday, 8,
				   0, 17, 30) == DlStatus::kFailure);
	okc("weekday set rejects user 0",
	    mgr.SetWeekdaySchedule(1, 1, 0, DlScheduleStatus::kOccupied, DaysMaskMap::kMonday, 8,
				   0, 17, 30) == DlStatus::kFailure);
	okc("weekday set rejects index 11",
	    mgr.SetWeekdaySchedule(1, 11, 1, DlScheduleStatus::kOccupied, DaysMaskMap::kMonday, 8,
				   0, 17, 30) == DlStatus::kFailure);
	okc("weekday set rejects user 11",
	    mgr.SetWeekdaySchedule(1, 1, 11, DlScheduleStatus::kOccupied, DaysMaskMap::kMonday, 8,
				   0, 17, 30) == DlStatus::kFailure);
	mfk_cfg_fail_write = "week-day-schedules";
	okc("weekday set surfaces NVM write failure",
	    mgr.SetWeekdaySchedule(1, 1, 1, DlScheduleStatus::kOccupied, DaysMaskMap::kMonday, 8,
				   0, 17, 30) == DlStatus::kFailure);
	mfk_cfg_fail_write = nullptr;
	okc("weekday set persists",
	    mgr.SetWeekdaySchedule(1, 1, 1, DlScheduleStatus::kOccupied, DaysMaskMap::kMonday, 8,
				   0, 17, 30) == DlStatus::kSuccess);
	okc("weekday get round-trips",
	    mgr.GetWeekdaySchedule(1, 1, 1, wd) == DlStatus::kSuccess &&
		    wd.daysMask == DaysMaskMap::kMonday && wd.startHour == 8 &&
		    wd.startMinute == 0 && wd.endHour == 17 && wd.endMinute == 30);

	/* yearday schedules */
	EmberAfPluginDoorLockYearDaySchedule yd;
	okc("yearday get bounds",
	    mgr.GetYeardaySchedule(1, 0, 1, yd) == DlStatus::kFailure &&
		    mgr.GetYeardaySchedule(1, 1, 0, yd) == DlStatus::kFailure &&
		    mgr.GetYeardaySchedule(1, 11, 1, yd) == DlStatus::kFailure &&
		    mgr.GetYeardaySchedule(1, 1, 11, yd) == DlStatus::kFailure);
	okc("yearday get on empty slot -> not found",
	    mgr.GetYeardaySchedule(1, 1, 1, yd) == DlStatus::kNotFound);
	okc("yearday set bounds",
	    mgr.SetYeardaySchedule(1, 0, 1, DlScheduleStatus::kOccupied, 100, 200) ==
			    DlStatus::kFailure &&
		    mgr.SetYeardaySchedule(1, 1, 0, DlScheduleStatus::kOccupied, 100, 200) ==
			    DlStatus::kFailure &&
		    mgr.SetYeardaySchedule(1, 11, 1, DlScheduleStatus::kOccupied, 100, 200) ==
			    DlStatus::kFailure &&
		    mgr.SetYeardaySchedule(1, 1, 11, DlScheduleStatus::kOccupied, 100, 200) ==
			    DlStatus::kFailure);
	mfk_cfg_fail_write = "year-day-schedules";
	okc("yearday set surfaces NVM write failure",
	    mgr.SetYeardaySchedule(1, 1, 1, DlScheduleStatus::kOccupied, 100, 200) ==
		    DlStatus::kFailure);
	mfk_cfg_fail_write = nullptr;
	okc("yearday set + get round-trip",
	    mgr.SetYeardaySchedule(1, 1, 1, DlScheduleStatus::kOccupied, 100, 200) ==
			    DlStatus::kSuccess &&
		    mgr.GetYeardaySchedule(1, 1, 1, yd) == DlStatus::kSuccess &&
		    yd.localStartTime == 100 && yd.localEndTime == 200);

	/* holiday schedules */
	EmberAfPluginDoorLockHolidaySchedule hd;
	okc("holiday get bounds",
	    mgr.GetHolidaySchedule(1, 0, hd) == DlStatus::kFailure &&
		    mgr.GetHolidaySchedule(1, 11, hd) == DlStatus::kFailure);
	okc("holiday get on empty slot -> not found",
	    mgr.GetHolidaySchedule(1, 1, hd) == DlStatus::kNotFound);
	okc("holiday set bounds",
	    mgr.SetHolidaySchedule(1, 0, DlScheduleStatus::kOccupied, 1, 2,
				   OperatingModeEnum::kVacation) == DlStatus::kFailure &&
		    mgr.SetHolidaySchedule(1, 11, DlScheduleStatus::kOccupied, 1, 2,
					   OperatingModeEnum::kVacation) == DlStatus::kFailure);
	mfk_cfg_fail_write = "holiday-schedules";
	okc("holiday set surfaces NVM write failure",
	    mgr.SetHolidaySchedule(1, 1, DlScheduleStatus::kOccupied, 1, 2,
				   OperatingModeEnum::kVacation) == DlStatus::kFailure);
	mfk_cfg_fail_write = nullptr;
	okc("holiday set + get round-trip",
	    mgr.SetHolidaySchedule(1, 1, DlScheduleStatus::kOccupied, 1, 2,
				   OperatingModeEnum::kVacation) == DlStatus::kSuccess &&
		    mgr.GetHolidaySchedule(1, 1, hd) == DlStatus::kSuccess &&
		    hd.localStartTime == 1 && hd.localEndTime == 2 &&
		    hd.operatingMode == OperatingModeEnum::kVacation);

	/* InitLockState */
	mfk_dls_creds_val = 200; /* Init() rejects > platform max */
	okc("init-lock-state surfaces Init failure",
	    mgr.InitLockState() == CHIP_ERROR_NO_MEMORY);
	mfk_dls_creds_val = 10;
	mfk_dls_creds_ok = 0; /* both attribute reads fail -> defaults 5 + 10 */
	mfk_dls_users_ok = 0;
	okc("init-lock-state falls back to defaults when attributes unreadable",
	    mgr.InitLockState() == CHIP_NO_ERROR);
	mfk_dls_creds_ok = 1;
	mfk_dls_users_ok = 1;
	mfk_cfg_fail_read = "credential";
	okc("init-lock-state surfaces persistence failure",
	    mgr.InitLockState() == CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);
	mfk_cfg_fail_read = nullptr;
	okc("init-lock-state succeeds", mgr.InitLockState() == CHIP_NO_ERROR);
}

/* ---- D: door_lock_callbacks -------------------------------------------------- */
static void section_callbacks(void)
{
	printf("-- door_lock_callbacks\n");
	mfk_reset();
	door_lock_init();

	mfk_dls_init_server_calls = 0;
	mfk_dls_set_lock_calls = 0;
	emberAfDoorLockClusterInitCallback(1);
	okc("cluster init: server init + forced Locked",
	    mfk_dls_init_server_calls == 1 && mfk_dls_init_server_ep == 1 &&
		    mfk_dls_set_lock_calls >= 1 &&
		    mfk_dls_last_state == (int)DlLockState::kLocked &&
		    mfk_dls_last_source == -1);
	mfk_dls_creds_val = 200; /* drive the InitLockState-failed log branch */
	emberAfDoorLockClusterInitCallback(1);
	okc("cluster init: InitLockState failure tolerated",
	    mfk_dls_init_server_calls == 2);
	mfk_dls_creds_val = 10;
	BoltLockMgr().InitLockState(); /* restore sane LockParams */

	OperationErrorEnum oerr = OperationErrorEnum::kUnspecified;
	chip::Nullable<chip::FabricIndex> nofab;
	chip::Nullable<chip::NodeId> nonode;
	uint8_t pin[4] = {0x31, 0x32, 0x33, 0x34};

	mfk_attr_requirepin_val = 1;
	mfk_dls_set_lock_calls = 0;
	okc("lock command without required pin refused",
	    !emberAfPluginDoorLockOnDoorLockCommand(1, nofab, nonode,
						    Optional<chip::ByteSpan>(), oerr) &&
		    mfk_dls_set_lock_calls == 0);
	okc("lock command with pin locks remotely",
	    emberAfPluginDoorLockOnDoorLockCommand(
		    1, nofab, nonode, Optional<chip::ByteSpan>(chip::ByteSpan(pin)), oerr) &&
		    mfk_dls_last_state == (int)DlLockState::kLocked &&
		    mfk_dls_last_source == (int)OperationSourceEnum::kRemote);
	okc("unlock command without required pin refused",
	    !emberAfPluginDoorLockOnDoorUnlockCommand(1, nofab, nonode,
						      Optional<chip::ByteSpan>(), oerr));
	okc("unlock command with pin unlocks remotely",
	    emberAfPluginDoorLockOnDoorUnlockCommand(
		    1, nofab, nonode, Optional<chip::ByteSpan>(chip::ByteSpan(pin)), oerr) &&
		    mfk_dls_last_state == (int)DlLockState::kUnlocked &&
		    mfk_dls_last_source == (int)OperationSourceEnum::kRemote);
	mfk_attr_requirepin_val = 0;

	EmberAfPluginDoorLockCredentialInfo cred;
	okc("get-credential hook delegates",
	    emberAfPluginDoorLockGetCredential(1, 1, CredentialTypeEnum::kPin, cred) &&
		    cred.status == DlCredentialStatus::kOccupied);
	okc("get-credential hook propagates invalid index",
	    !emberAfPluginDoorLockGetCredential(1, 0, CredentialTypeEnum::kPin, cred));

	/* ultrawidelock endpoint key mirror into the reader trust store */
	static uint8_t key65[65];
	memset(key65, 0xC3, sizeof(key65));
	okc("set-credential mirrors an occupied 65-byte ultrawidelock key",
	    emberAfPluginDoorLockSetCredential(1, 2, 1, 1, DlCredentialStatus::kOccupied,
					       CredentialTypeEnum::kAliroNonEvictableEndpointKey,
					       chip::ByteSpan(key65)) &&
		    mfk_add_trust_calls == 1 && memcmp(mfk_add_trust_key, key65, 65) == 0);
	/* The index goes with it: ClearCredential names the key by index and never
	 * by its bytes, so an anchor stored without one can never be revoked. */
	okc("set-credential binds the credential type and index",
	    mfk_add_trust_index == 2 &&
		    mfk_add_trust_type ==
			    static_cast<uint8_t>(CredentialTypeEnum::kAliroNonEvictableEndpointKey));
	okc("set-credential does not mirror a pin",
	    emberAfPluginDoorLockSetCredential(1, 3, 1, 1, DlCredentialStatus::kOccupied,
					       CredentialTypeEnum::kPin,
					       chip::ByteSpan(key65, 4)) &&
		    mfk_add_trust_calls == 1);
	/*
	 * A cleared slot is how ClearCredential reaches this hook: the server
	 * erases the slot by writing an Available status with empty data. It must
	 * REVOKE rather than add, and it is the only signal the reader gets that a
	 * home key was removed in the controller's UI.
	 */
	okc("set-credential revokes a cleared ultrawidelock slot",
	    emberAfPluginDoorLockSetCredential(1, 4, 1, 1, DlCredentialStatus::kAvailable,
					       CredentialTypeEnum::kAliroEvictableEndpointKey,
					       chip::ByteSpan()) &&
		    mfk_add_trust_calls == 1 && mfk_remove_trust_calls == 1 &&
		    mfk_remove_trust_index == 4 &&
		    mfk_remove_trust_type ==
			    static_cast<uint8_t>(CredentialTypeEnum::kAliroEvictableEndpointKey));
	okc("set-credential does not revoke a cleared pin slot",
	    emberAfPluginDoorLockSetCredential(1, 5, 1, 1, DlCredentialStatus::kAvailable,
					       CredentialTypeEnum::kPin, chip::ByteSpan()) &&
		    mfk_remove_trust_calls == 1);
	/*
	 * A removal the reader could not persist is live in RAM and gone at the
	 * next boot. Reporting success there tells the admin a key is revoked when
	 * a power cycle brings it back, so the hook has to fail.
	 */
	mfk_remove_trust_rc = -ENOSPC;
	okc("set-credential fails when the revocation was not persisted",
	    !emberAfPluginDoorLockSetCredential(1, 6, 1, 1, DlCredentialStatus::kAvailable,
						CredentialTypeEnum::kAliroEvictableEndpointKey,
						chip::ByteSpan()) &&
		    mfk_remove_trust_calls == 2);
	mfk_remove_trust_rc = 1; /* "no such anchor": already revoked, still success */
	okc("set-credential accepts an already-revoked slot",
	    emberAfPluginDoorLockSetCredential(1, 7, 1, 1, DlCredentialStatus::kAvailable,
					       CredentialTypeEnum::kAliroEvictableEndpointKey,
					       chip::ByteSpan()) &&
		    mfk_remove_trust_calls == 3);
	mfk_remove_trust_rc = 0;
	/* Same on the way in: a key the reader is not holding must not be reported
	 * as installed, or the controller shows an enrolled phone that never opens. */
	mfk_add_trust_rc = -ENOSPC;
	okc("set-credential fails when the trust store refused the key",
	    !emberAfPluginDoorLockSetCredential(1, 8, 1, 1, DlCredentialStatus::kOccupied,
						CredentialTypeEnum::kAliroEvictableEndpointKey,
						chip::ByteSpan(key65)) &&
		    mfk_add_trust_calls == 2);
	mfk_add_trust_rc = 1; /* already trusted: nothing written, still success */
	okc("set-credential accepts an already-trusted key",
	    emberAfPluginDoorLockSetCredential(1, 9, 1, 1, DlCredentialStatus::kOccupied,
					       CredentialTypeEnum::kAliroEvictableEndpointKey,
					       chip::ByteSpan(key65)) &&
		    mfk_add_trust_calls == 3);
	mfk_add_trust_rc = 0;
	/* Index 0 is invalid for a PIN, so the lock's own store refuses before the
	 * ultrawidelock mirror is ever reached: the call count must not move. */
	okc("set-credential propagates a failed store",
	    !emberAfPluginDoorLockSetCredential(1, 0, 1, 1, DlCredentialStatus::kOccupied,
						CredentialTypeEnum::kPin,
						chip::ByteSpan(key65, 4)) &&
		    mfk_add_trust_calls == 3);

	EmberAfPluginDoorLockUserInfo user;
	okc("get-user hook delegates",
	    emberAfPluginDoorLockGetUser(1, 1, user) &&
		    user.userStatus == UserStatusEnum::kOccupiedEnabled);
	CredentialStruct link;
	link.credentialType = CredentialTypeEnum::kPin;
	link.credentialIndex = 1;
	okc("set-user hook delegates",
	    emberAfPluginDoorLockSetUser(1, 3, 1, 1, chip::CharSpan("carol", 5), 44,
					 UserStatusEnum::kOccupiedEnabled,
					 UserTypeEnum::kUnrestrictedUser,
					 CredentialRuleEnum::kSingle, &link, 1));

	EmberAfPluginDoorLockWeekDaySchedule wd;
	EmberAfPluginDoorLockYearDaySchedule yd;
	EmberAfPluginDoorLockHolidaySchedule hd;
	okc("weekday get/set hooks delegate",
	    emberAfPluginDoorLockSetSchedule(1, 2, 1, DlScheduleStatus::kOccupied,
					     DaysMaskMap::kFriday, 9, 0, 10, 0) ==
			    DlStatus::kSuccess &&
		    emberAfPluginDoorLockGetSchedule(1, (uint8_t)2, (uint16_t)1, wd) ==
			    DlStatus::kSuccess &&
		    wd.daysMask == DaysMaskMap::kFriday);
	okc("yearday get/set hooks delegate",
	    emberAfPluginDoorLockSetSchedule(1, 2, 1, DlScheduleStatus::kOccupied,
					     (uint32_t)111, (uint32_t)222) == DlStatus::kSuccess &&
		    emberAfPluginDoorLockGetSchedule(1, (uint8_t)2, (uint16_t)1, yd) ==
			    DlStatus::kSuccess &&
		    yd.localStartTime == 111);
	okc("holiday get/set hooks delegate",
	    emberAfPluginDoorLockSetSchedule(1, 2, DlScheduleStatus::kOccupied, (uint32_t)5,
					     (uint32_t)6, OperatingModeEnum::kPrivacy) ==
			    DlStatus::kSuccess &&
		    emberAfPluginDoorLockGetSchedule(1, (uint8_t)2, hd) == DlStatus::kSuccess &&
		    hd.operatingMode == OperatingModeEnum::kPrivacy);
	emberAfPluginDoorLockOnAutoRelock(1);
	okc("auto-relock hook is log-only", mfk_dls_set_lock_calls >= 1);
}

/* ---- E: app_main boot --------------------------------------------------------- */
static void section_app_main(void)
{
	printf("-- app_main boot\n");
	mfk_reset();
	mfk_fabric_count = 0;

	app_main();

	okc("matter node created with app callbacks",
	    mfk_em_node_creates >= 1 && mfk_em_attribute_cb != nullptr &&
		    mfk_em_identify_cb != nullptr);
	okc("door lock endpoint carries the ultrawidelock delegate",
	    mfk_em_delegate == (void *)&UltraWideLockReaderDelegate::Instance());
	okc("initial lock state configured Locked",
	    mfk_em_lock_state_init == chip::to_underlying(DlLockState::kLocked));
	okc("COTA + pin + user features added", mfk_em_feature_adds == 3);
	okc("ultrawidelock provisioning + ble-uwb features added",
	    mfk_em_ultrawidelock_prov_adds == 1 && mfk_em_ultrawidelock_bleuwb_adds == 1);
	okc("approach direction cluster 0x1349FC03 created",
	    mfk_em_cluster_create_id == 0x1349FC03u);
	okc("approach direction attribute: writable+nonvolatile bitmap8 = 7",
	    mfk_em_attr_creates == 1 && mfk_em_attr_last_id == 0 &&
		    mfk_em_attr_last_flags ==
			    (ATTRIBUTE_FLAG_WRITABLE | ATTRIBUTE_FLAG_NONVOLATILE) &&
		    mfk_em_attr_last_val == 7);
	okc("approach direction globals: feature map 0, revision 1",
	    mfk_em_fm_creates == 1 && mfk_em_fm_val == 0 && mfk_em_cr_creates == 1 &&
		    mfk_em_cr_val == 1);
	okc("auto-relock timer disabled (0)",
	    mfk_em_autorelock_creates == 1 && mfk_em_autorelock_val == 0);
	okc("door lock endpoint id latched", door_lock_endpoint_id == 1);
	okc("ultrawidelock GATT service pre-registered on the shared host",
	    mfk_blemgr_calls == 1 && mfk_blemgr_nsvcs == 1);
	okc("matter started with the app event callback",
	    mfk_em_start_calls == 1 && mfk_em_event_cb != nullptr);
	okc("uncommissioned boot starts no reader task", mfk_task_count == 0);
	okc("console repl started with the command set",
	    mfk_repl_started == 1 && mfk_cmd_count == 12 && mfk_help_registered == 1);
	/* The button handle used to be created and dropped. A long press is the
	 * recovery path for a board with no console attached. */
	okc("boot hangs the commissioning window off a long press",
	    mfk_btn_register_calls == 1 && mfk_btn_last_event == (int)BUTTON_LONG_PRESS_START);
	{
		/* Save and restore every counter the press moves: the fabric-removal
		 * block later in this file reads them absolutely, not as deltas. */
		int open_before = mfk_cw_open_calls;
		int sched_before = mfk_sched_calls;
		int adv_before = mfk_cw_last_adv;
		int was_open = mfk_cw_is_open;

		mfk_cw_is_open = 0;
		mfk_btn_fire_long_press();
		okc("long press opens a window advertising over BLE",
		    mfk_cw_open_calls == open_before + 1 &&
			    mfk_cw_last_adv ==
				    (int)chip::CommissioningWindowAdvertisement::kAllSupported);

		mfk_cw_open_calls = open_before;
		mfk_sched_calls = sched_before;
		mfk_cw_last_adv = adv_before;
		mfk_cw_is_open = was_open;
	}
	okc("console echoes single chars only (multiline off)",
	    mfk_linenoise_multiline == 0);
}

/* ---- F: device events ----------------------------------------------------------- */
static void section_events(void)
{
	printf("-- device events\n");
	void (*cb)(const ChipDeviceEvent *, intptr_t) = mfk_em_event_cb;
	ChipDeviceEvent ev;

	ev.Type = chip::DeviceLayer::DeviceEventType::kInterfaceIpAddressChanged;
	cb(&ev, 0);
	okc("first IP event starts SNTP", mfk_sntp_inits == 1 && mfk_sntp_cb != nullptr);
	cb(&ev, 0);
	okc("second IP event does not restart SNTP", mfk_sntp_inits == 1);
	mfk_sntp_cb(nullptr);
	okc("SNTP sync pokes the ultrawidelock advertiser", mfk_ble_time_updated_calls == 1);

	ev.Type = chip::DeviceLayer::DeviceEventType::kCommissioningComplete;
	cb(&ev, 0);
	okc("commissioning-complete starts the reader task once",
	    mfk_task_count == 1 && strcmp(mfk_tasks[0].name, "ultrawidelock_reader") == 0 &&
		    mfk_tasks[0].stack == 12288 && mfk_tasks[0].prio == 5 &&
		    ultrawidelock_reader_task_handle != nullptr);
	cb(&ev, 0);
	okc("reader task start is idempotent", mfk_task_count == 1);

	/* the informational events must all dispatch without effect */
	static const uint16_t quiet[] = {
		chip::DeviceLayer::DeviceEventType::kFailSafeTimerExpired,
		chip::DeviceLayer::DeviceEventType::kCommissioningSessionStarted,
		chip::DeviceLayer::DeviceEventType::kCommissioningSessionStopped,
		chip::DeviceLayer::DeviceEventType::kCommissioningWindowOpened,
		chip::DeviceLayer::DeviceEventType::kCommissioningWindowClosed,
		chip::DeviceLayer::DeviceEventType::kFabricWillBeRemoved,
		chip::DeviceLayer::DeviceEventType::kFabricUpdated,
		chip::DeviceLayer::DeviceEventType::kFabricCommitted,
		chip::DeviceLayer::DeviceEventType::kBLEDeinitialized,
		chip::DeviceLayer::DeviceEventType::kUnknownFakeEvent,
	};
	int before = mfk_cw_open_calls + mfk_prov_clear_calls + mfk_task_count;
	for (size_t i = 0; i < sizeof(quiet) / sizeof(quiet[0]); i++) {
		ev.Type = quiet[i];
		cb(&ev, 0);
	}
	okc("informational events are log-only",
	    before == mfk_cw_open_calls + mfk_prov_clear_calls + mfk_task_count);

	ev.Type = chip::DeviceLayer::DeviceEventType::kFabricRemoved;
	mfk_fabric_count = 1;
	mfk_prov_clear_calls = 0;
	cb(&ev, 0);
	okc("fabric removal with fabrics left changes nothing",
	    mfk_prov_clear_calls == 0 && mfk_cw_open_calls == 0);

	mfk_fabric_count = 0;
	mfk_cw_is_open = 1;
	cb(&ev, 0);
	okc("last-fabric removal drops the reader config",
	    mfk_prov_clear_calls == 1);
	okc("window already open -> not reopened", mfk_cw_open_calls == 0);

	mfk_cw_is_open = 0;
	cb(&ev, 0);
	okc("last-fabric removal reopens a dnssd-only window",
	    mfk_cw_open_calls == 1 && mfk_cw_last_timeout == 300 &&
		    mfk_cw_last_adv == (int)chip::CommissioningWindowAdvertisement::kDnssdOnly);

	mfk_cw_open_rc = 0xff; /* window-open failure branch */
	cb(&ev, 0);
	okc("window-open failure tolerated", mfk_cw_open_calls == 2);
	mfk_cw_open_rc = 0;
}

/* ---- G: attribute / identification callbacks ------------------------------------- */
static void section_matter_callbacks(void)
{
	printf("-- matter callbacks\n");
	using AttrCb = esp_matter::attribute::callback_t;
	using IdCb = esp_matter::identification::callback_t;
	AttrCb acb = (AttrCb)mfk_em_attribute_cb;
	IdCb icb = (IdCb)mfk_em_identify_cb;
	esp_matter_attr_val_t val = esp_matter_bitmap8(1);

	okc("attribute pre-update dispatches to the driver",
	    acb(esp_matter::attribute::PRE_UPDATE, 1, 2, 3, &val, nullptr) == ESP_OK);
	okc("attribute post-update is a pass-through",
	    acb(esp_matter::attribute::POST_UPDATE, 1, 2, 3, &val, nullptr) == ESP_OK);
	okc("identification callback returns ok",
	    icb(esp_matter::identification::START, 1, 0, 0, nullptr) == ESP_OK);
}

/* ---- H: reader task approach controller ------------------------------------------- */
static void section_reader_task(void)
{
	printf("-- ultrawidelock reader task\n");
	void (*task)(void *) = mfk_tasks[0].fn;

	/* run 1: no authenticated credential; full approach + depart + silence */
	mfk_reader_start_calls = 0;
	mfk_reader_start_rc = 0;
	mfk_status_tick_calls = 0;
	mfk_auth_cred_have = 0;
	mfk_notify_unlock_calls = 0;
	mfk_dls_set_lock_calls = 0;
	mfk_ble_synced = 0;
	mfk_adv_active = 1;
	static int delays;
	delays = 0;
	mfk_delay_hook = []() {
		if (++delays >= 3) {
			mfk_ble_synced = 1;
			mfk_adv_active = 0;
		}
	};
	mfk_wake_len = 0;
	mfk_wake_idx = 0;
	wake_push(1, 0, 0, 10);    /* active but untrusted: activity only */
	/* Arms the trajectory gate (ultrawidelock_approach_cfg::approach_cm, 180 cm by
	 * default). Without a sample this far out the controller refuses to
	 * unlock, which is the point of it: a credential that appears already
	 * at the door never approached. (The session's rising edge arms it too
	 * now; run 8 pins that on its own.) 200 cm also sits in the dead
	 * band, so it moves no dwell counter and the sequence below is otherwise
	 * the walk-up it always was. */
	wake_push(1, 1, 200, 10);  /* approach starts beyond the door zone */
	wake_push(1, 1, 50, 10);   /* first trusted range: grant */
	wake_push(1, 1, 60, 10);   /* near dwell 2 -> unlock */
	wake_push(1, 1, 40, 10);   /* still near, already unlocked */
	wake_push(1, 1, 300, 10);  /* median still near */
	wake_push(1, 1, 500, 10);  /* far dwell 1 */
	wake_push(1, 1, 600, 10);  /* far dwell 2 */
	wake_push(1, 1, 650, 10);  /* far dwell 3 -> relock */
	wake_push(1, 1, 200, 10);  /* far branch while already locked */
	wake_push(1, 1, 200, 10);
	wake_push(1, 1, 200, 10);  /* median decays into the dead band */
	wake_push(0, 0, 0, 200);   /* ranging silence alone must NOT relock */
	wake_push_session_gone();  /* session end -> peer gone (already locked) */
	mfk_task_run(task, nullptr);

	okc("wait loop released by host sync + free advertiser", delays >= 3);
	okc("reader started once on the shared host", mfk_reader_start_calls == 1);
	/* Every pass, not once at startup: a held Wallet status is released by this
	 * tick, so an approach that produces no grant would never deliver one. */
	okc("status tick runs on every approach pass", mfk_status_tick_calls >= mfk_wake_len);
	okc("range listener installed", mfk_range_listener != nullptr);
	okc("wallet notified exactly twice: grant with the bolt, secured on depart",
	    mfk_notify_unlock_calls == 2);
	okc("near dwell unlocked via the matter hop",
	    mfk_lat_marks[ULTRAWIDELOCK_LAT_NEAR_DWELL] >= 1 &&
		    mfk_lat_marks[ULTRAWIDELOCK_LAT_BOLT_DRIVEN] >= 1 && mfk_lat_reports == 1);
	okc("unlock was ultrawidelock-sourced and unattributed (no credential)",
	    mfk_dls_last_source == (int)OperationSourceEnum::kAliro);
	okc("far dwell + session end relocked and secured",
	    mfk_dls_last_state == (int)DlLockState::kLocked && mfk_notify_unlock_last == 0 &&
		    mfk_notify_unlock_calls == 2);
	okc("trusted ranges traced for the lab", mfk_lab_evi_calls >= 10);

	/* run 2: credential matches user 1; depart via pure silence while open */
	mfk_delay_hook = nullptr;
	mfk_auth_cred_have = 1;
	memset(mfk_auth_cred, 0x5A, sizeof(mfk_auth_cred)); /* alice_key */
	mfk_reader_start_rc = -1; /* failure log branch; controller still runs */
	mfk_notify_unlock_calls = 0;
	mfk_dls_unlock_user_null = -1;
	mfk_wake_len = 0;
	mfk_wake_idx = 0;
	wake_push(1, 1, 200, 10); /* arms the trajectory gate; see run 1 */
	wake_push(1, 1, 50, 10);
	wake_push(1, 1, 60, 10);  /* unlock, attributed to user 1 */
	wake_push(1, 1, 40, 10);  /* median settles near: near_dwell 2 -> unlock */
	wake_push(0, 0, 0, 200);  /* standing still while unlocked: no relock */
	wake_push_session_gone(); /* session end -> relock + secured */
	mfk_task_run(task, nullptr);
	okc("unlock attributed to the credential's user",
	    mfk_dls_unlock_user_null == 0 && mfk_dls_unlock_user == 1);
	okc("peer-gone while unlocked relocks the bolt",
	    mfk_dls_last_state == (int)DlLockState::kLocked);
	okc("wallet told secured on departure",
	    mfk_notify_unlock_last == 0 && mfk_notify_unlock_calls == 2);

	/* run 3: credential matches no stored user */
	memset(mfk_auth_cred, 0xEE, sizeof(mfk_auth_cred));
	mfk_dls_unlock_user_null = -1;
	mfk_wake_len = 0;
	mfk_wake_idx = 0;
	wake_push(1, 1, 200, 10); /* arms the trajectory gate; see run 1 */
	wake_push(1, 1, 50, 5);
	wake_push(1, 1, 60, 5); /* unlock, unattributed */
	wake_push(1, 1, 40, 5);  /* median settles near: near_dwell 2 -> unlock */
	mfk_task_run(task, nullptr);
	okc("unknown credential leaves the operation unattributed",
	    mfk_dls_last_state == (int)DlLockState::kUnlocked &&
		    mfk_dls_unlock_user_null == 1);

	/* run 4: trusted the whole time but never inside the unlock threshold. The bolt
	 * must not move and — the regression this guards — the phone must never be told
	 * "unsecured", which is what a grant tied to the trust bit did at 2-3 m. */
	mfk_notify_unlock_calls = 0;
	mfk_dls_set_lock_calls = 0;
	mfk_dls_last_state = (int)DlLockState::kLocked;
	mfk_wake_len = 0;
	mfk_wake_idx = 0;
	wake_push(1, 1, 300, 10);
	wake_push(1, 1, 280, 10);
	wake_push(1, 1, 260, 10);
	wake_push(1, 1, 310, 10);
	wake_push(1, 1, 290, 10);
	wake_push_session_gone(); /* session end -> peer gone, still locked */
	mfk_task_run(task, nullptr);
	okc("trusted but never near: wallet never told unsecured",
	    mfk_notify_unlock_calls == 0);
	okc("trusted but never near: bolt stayed locked",
	    mfk_dls_last_state == (int)DlLockState::kLocked);

	/* run 5: unlock, then stand still. iOS stops ranging when the phone stops
	 * moving (bench: 3.07 s of silence with the phone 26 cm from the reader and
	 * the link still up), which under a ranging-silence timeout relocked the bolt
	 * and then re-unlocked it. Silence with the session up must change nothing. */
	mfk_notify_unlock_calls = 0;
	mfk_dls_set_lock_calls = 0;
	mfk_wake_len = 0;
	mfk_wake_idx = 0;
	wake_push(1, 1, 200, 10); /* arms the trajectory gate; see run 1 */
	wake_push(1, 1, 50, 10);
	wake_push(1, 1, 60, 10); /* unlock + grant */
	wake_push(1, 1, 40, 10);  /* median settles near: near_dwell 2 -> unlock */
	for (int i = 0; i < 30; i++) {
		wake_push(0, 0, 0, 200); /* 6 s of ranging silence, session still up */
	}
	mfk_task_run(task, nullptr);
	okc("standing still does not relock the bolt",
	    mfk_dls_last_state == (int)DlLockState::kUnlocked);
	okc("standing still sends no secured", mfk_notify_unlock_last == 1);
	/* One bolt drive for the whole run: the unlock, and nothing after it. Run 2
	 * covers the other half, that a session end in the same position does relock. */
	okc("standing still drove the bolt once", mfk_dls_set_lock_calls == 1);

	/* run 6: the two-anchor gate refuses the first offer, then relents.
	 *
	 * Both unlock paths clear the controller's `locked` BEFORE returning the
	 * action, so a refusal that does not hand the unlock back leaves it
	 * believing the bolt is open -- and its own guard is `if (ap->locked &&
	 * ...)`, which can then never fire again. One veto taken before the
	 * satellite had settled a verdict would end auto-unlock for the whole
	 * walk-up, and the settling window is exactly when a veto is most likely.
	 *
	 * So this pins the RECOVERY, not the refusal: the gate says no once, then
	 * yes, and the bolt must still open. Fails if ultrawidelock_approach_veto()
	 * is dropped from the refusing path. */
	mfk_notify_unlock_calls = 0;
	mfk_dls_set_lock_calls = 0;
	mfk_may_predict = 0;
	mfk_sat_predict_asks = 0;
	/* Relent the moment the gate has refused once. Hooked on the ASK, not on
	 * vTaskDelay: the wake loop blocks in ulTaskNotifyTake, so a delay hook
	 * would never fire here and the gate would simply refuse forever. */
	mfk_predict_hook = []() { mfk_may_predict = 1; };
	mfk_wake_len = 0;
	mfk_wake_idx = 0;
	wake_push(1, 1, 200, 10); /* arms the trajectory gate; see run 1 */
	wake_push(1, 1, 50, 10);
	wake_push(1, 1, 60, 10);  /* first offer -- the gate vetoes it */
	wake_push(1, 1, 40, 10);  /* gate has relented: must be offered again */
	wake_push(1, 1, 45, 10);
	wake_push(1, 1, 42, 10);
	mfk_task_run(task, nullptr);
	okc("the two-anchor gate was consulted", mfk_sat_predict_asks >= 1);
	okc("a veto that later relents still opens the bolt",
	    mfk_dls_set_lock_calls >= 1 && mfk_dls_last_state == (int)DlLockState::kUnlocked);
	mfk_predict_hook = nullptr;
	mfk_may_predict = 1;

	/* run 7: the Watch's second approach. The Watch keeps its BLE session
	 * across a walk-away: it suspends ranging once far and starts it again
	 * (new STS, same session id) once its wearer is back -- already inside
	 * approach_cm (61 cm and 130 cm measured on the CDK, 2026-09-10). The
	 * departure relock disarmed the trajectory gate, and no range at or past
	 * approach_cm ever arrives to re-arm it: the far half of that approach
	 * happened while the Watch was not ranging. A ranging RESTART
	 * (ultrawidelock_uwb_start_generation() moved) is the approach evidence.
	 * The 3 s silent wake ages the departure samples out of the median
	 * window, as the suspended ranging does on the wrist. */
	auto watch_return = [&](int restart) {
		mfk_notify_unlock_calls = 0;
		mfk_dls_set_lock_calls = 0;
		mfk_dls_last_state = (int)DlLockState::kLocked;
		mfk_uwb_start_generation = 7;
		mfk_wake_len = 0;
		mfk_wake_idx = 0;
		wake_push(1, 1, 200, 10); /* arms the trajectory gate; see run 1 */
		wake_push(1, 1, 50, 10);
		wake_push(1, 1, 60, 10);  /* first unlock */
		wake_push(1, 1, 40, 10);
		wake_push(1, 1, 300, 10);
		wake_push(1, 1, 500, 10);
		wake_push(1, 1, 600, 10);
		wake_push(1, 1, 650, 10);
		wake_push(1, 1, 700, 10); /* far dwell 3 -> relock, gate disarmed; last range before the silence */
		wake_push(0, 0, 0, 3000); /* the Watch suspended ranging while far */
		wake_push(1, 1, 130, 10, 1, restart); /* back, already inside approach_cm */
		wake_push(1, 1, 61, 10);
		wake_push(1, 1, 50, 10);
		wake_push(1, 1, 40, 10);  /* near dwell -> second unlock, if armed */
		mfk_task_run(task, nullptr);
	};
	watch_return(1);
	okc("watch: relock, ranging restart inside approach_cm, second unlock",
	    mfk_dls_last_state == (int)DlLockState::kUnlocked && mfk_notify_unlock_calls == 3 &&
		    mfk_notify_unlock_last == 1);
	watch_return(0);
	okc("watch: the same return with no restart stays locked (gate still disarmed)",
	    mfk_dls_last_state == (int)DlLockState::kLocked && mfk_notify_unlock_calls == 2);

	/* run 8: a session that comes up already at the door, no far range ever.
	 * With the RSSI power gate that is every session (ranging starts inside
	 * unlock_cm), and the gate's rising edge is the only approach evidence
	 * the architecture produces -- the CDK arms on it; so does this loop. */
	mfk_notify_unlock_calls = 0;
	mfk_dls_set_lock_calls = 0;
	mfk_dls_last_state = (int)DlLockState::kLocked;
	mfk_wake_len = 0;
	mfk_wake_idx = 0;
	wake_push(1, 1, 60, 10); /* session rises with the first range: inside approach_cm */
	wake_push(1, 1, 50, 10);
	wake_push(1, 1, 40, 10); /* near dwell -> unlock */
	mfk_task_run(task, nullptr);
	okc("session rising edge arms the gate: unlock with no far range",
	    mfk_dls_last_state == (int)DlLockState::kUnlocked && mfk_notify_unlock_calls == 1);
}

/* ---- I: UWB range listener ---------------------------------------------------------- */
static void section_range_listener(void)
{
	printf("-- uwb range listener\n");
	void (*cb)(void) = mfk_range_listener;
	TaskHandle_t saved = ultrawidelock_reader_task_handle;

	memset(mfk_lat_marks, 0, sizeof(mfk_lat_marks));
	ultrawidelock_reader_task_handle = nullptr;
	mfk_notify_gives = 0;
	mfk_isr_gives = 0;
	mfk_trusted_have = 1;
	mfk_trusted_cm = 80;
	cb();
	okc("listener without a task only stamps the trace",
	    mfk_lat_marks[ULTRAWIDELOCK_LAT_FIRST_RANGE] == 1 &&
		    mfk_lat_marks[ULTRAWIDELOCK_LAT_TRUSTED_RANGE] == 1 && mfk_notify_gives == 0 &&
		    mfk_isr_gives == 0);

	ultrawidelock_reader_task_handle = saved;
	mfk_in_isr = 0;
	cb();
	okc("task-context wake notifies directly", mfk_notify_gives == 1 && mfk_isr_gives == 0);
	mfk_in_isr = 1;
	mfk_yield_calls = 0;
	cb();
	okc("isr-context wake notifies from ISR + yields",
	    mfk_isr_gives == 1 && mfk_yield_calls == 1);
	mfk_in_isr = 0;

	mfk_trusted_have = 0;
	int first = mfk_lat_marks[ULTRAWIDELOCK_LAT_TRUSTED_RANGE];
	cb();
	okc("untrusted range skips the trusted mark",
	    mfk_lat_marks[ULTRAWIDELOCK_LAT_TRUSTED_RANGE] == first);
}

/* ---- J: console commands -------------------------------------------------------------- */
static void section_shell(void)
{
	printf("-- console commands\n");

	okc("all 11 commands registered", mfk_cmd_lookup("status") && mfk_cmd_lookup("lock") &&
						 mfk_cmd_lookup("unlock") &&
						 mfk_cmd_lookup("codes") &&
						 mfk_cmd_lookup("range") &&
						 mfk_cmd_lookup("ultrawidelock") &&
						 mfk_cmd_lookup("uwbdiag") &&
						 mfk_cmd_lookup("lab") && mfk_cmd_lookup("log") &&
						 mfk_cmd_lookup("factoryreset") &&
						 mfk_cmd_lookup("clear"));

	/* status: locked, ranges absent, reader stack low-water branch */
	mfk_attr_lockstate_null = 0;
	mfk_attr_lockstate_val = (int)DlLockState::kLocked;
	mfk_attr_featuremap = 0x6000;
	mfk_fabric_count = 2;
	mfk_last_have = 0;
	mfk_trusted_have = 0;
	mfk_stack_hwm = 4096;
	mfk_lockstack_calls = 0;
	mfk_unlockstack_calls = 0;
	okc("status runs (locked, no ranges)", run_cmd("status", 1) == 0);
	okc("status reads under the chip stack lock",
	    mfk_lockstack_calls == 1 && mfk_unlockstack_calls == 1);

	/* status: unlocked + ranges + low reader stack */
	mfk_attr_lockstate_val = (int)DlLockState::kUnlocked;
	mfk_last_have = 1;
	mfk_last_cm = 123;
	mfk_trusted_have = 1;
	mfk_trusted_cm = 77;
	mfk_stack_hwm = 100;
	okc("status runs (unlocked, ranges, low stack)", run_cmd("status", 1) == 0);

	/* status: null lock state + no reader task */
	TaskHandle_t saved = ultrawidelock_reader_task_handle;
	ultrawidelock_reader_task_handle = nullptr;
	mfk_attr_lockstate_null = 1;
	okc("status runs (unknown state, no reader task)", run_cmd("status", 1) == 0);
	ultrawidelock_reader_task_handle = saved;
	mfk_attr_lockstate_null = 0;

	mfk_last_age_ms = 42000;
	okc("range with a latched distance and its age", run_cmd("range", 1) == 0);
	mfk_last_have = 0;
	okc("range before any distance", run_cmd("range", 1) == 0);

	mfk_prov_print_calls = 0;
	okc("ultrawidelock prov prints the identity",
	    run_cmd("ultrawidelock", 2, "prov") == 0 && mfk_prov_print_calls == 1);
	mfk_trust_last_rc = 0;
	okc("ultrawidelock trust: added", run_cmd("ultrawidelock", 2, "trust") == 0);
	mfk_trust_last_rc = 1;
	okc("ultrawidelock trust: nothing to add", run_cmd("ultrawidelock", 2, "trust") == 0);
	mfk_trust_last_rc = -1;
	okc("ultrawidelock trust: store failure", run_cmd("ultrawidelock", 2, "trust") == 0);
	mfk_trust_clear_rc = 0;
	okc("ultrawidelock clear: emptied", run_cmd("ultrawidelock", 2, "clear") == 0);
	mfk_trust_clear_rc = 1;
	okc("ultrawidelock clear: already empty", run_cmd("ultrawidelock", 2, "clear") == 0);
	mfk_trust_clear_rc = -1;
	okc("ultrawidelock clear: NVS failure", run_cmd("ultrawidelock", 2, "clear") == 0);
	okc("ultrawidelock usage on missing arg", run_cmd("ultrawidelock", 1) == 0);
	okc("ultrawidelock usage on unknown arg", run_cmd("ultrawidelock", 2, "bogus") == 0);

	okc("uwbdiag on", run_cmd("uwbdiag", 2, "on") == 0 && ultrawidelock_uwb_diag_on == 1);
	okc("uwbdiag off", run_cmd("uwbdiag", 2, "off") == 0 && ultrawidelock_uwb_diag_on == 0);
	okc("uwbdiag bare prints state", run_cmd("uwbdiag", 1) == 0);
	okc("uwbdiag usage on bad arg", run_cmd("uwbdiag", 2, "maybe") == 0);

	mfk_dls_set_lock_calls = 0;
	mfk_sched_calls = 0;
	okc("lock command drives the bolt via the matter hop",
	    run_cmd("lock", 1) == 0 && mfk_sched_calls == 1 &&
		    mfk_dls_last_state == (int)DlLockState::kLocked &&
		    mfk_dls_last_source == (int)OperationSourceEnum::kManual);
	okc("unlock command drives the bolt via the matter hop",
	    run_cmd("unlock", 1) == 0 && mfk_sched_calls == 2 &&
		    mfk_dls_last_state == (int)DlLockState::kUnlocked &&
		    mfk_dls_last_source == (int)OperationSourceEnum::kManual);

	/* Deliberately NOT PrintOnboardingCodes(): it logs at CHIP Progress level,
	 * which the default WARN build compiles out of the CHIP library, so `codes`
	 * printed nothing at all until it was moved onto the Get* pair. */
	mfk_print_codes_calls = 0;
	mfk_qr_calls = 0;
	mfk_manual_calls = 0;
	mfk_lockstack_calls = 0;
	okc("codes reprints onboarding codes under the stack lock",
	    run_cmd("codes", 1) == 0 && mfk_qr_calls == 1 && mfk_manual_calls == 1 &&
		    mfk_print_codes_calls == 0 && mfk_lockstack_calls == 1);

	/* commission: the recovery path for a board that is commissioned but has no
	 * network, so nothing can reach it to open a window the normal way. */
	mfk_cw_open_calls = 0;
	mfk_cw_close_calls = 0;
	mfk_cw_is_open = 0;
	okc("commission opens a window advertising over BLE",
	    run_cmd("commission", 1) == 0 && mfk_cw_open_calls == 1 &&
		    mfk_cw_last_adv == (int)chip::CommissioningWindowAdvertisement::kAllSupported);
	okc("commission prints the codes a controller needs",
	    mfk_qr_calls == 2 && mfk_manual_calls == 2);

	mfk_cw_open_calls = 0;
	mfk_cw_is_open = 1;
	okc("commission on an open window does not reopen it",
	    run_cmd("commission", 1) == 0 && mfk_cw_open_calls == 0);

	okc("commission close shuts an open window",
	    run_cmd("commission", 2, "close") == 0 && mfk_cw_close_calls == 1);
	okc("commission close on a shut window is a no-op",
	    run_cmd("commission", 2, "close") == 0 && mfk_cw_close_calls == 1);

	mfk_cw_open_calls = 0;
	mfk_cw_close_calls = 0;
	okc("commission rejects a bad argument",
	    run_cmd("commission", 2, "bogus") == 0 && mfk_cw_open_calls == 0 &&
		    mfk_cw_close_calls == 0);

	mfk_log_set_calls = 0;
	okc("log sets a runtime level",
	    run_cmd("log", 3, "*", "debug") == 0 && mfk_log_set_calls == 1 &&
		    mfk_log_last_level == (int)ESP_LOG_DEBUG);
	okc("log usage on unknown level",
	    run_cmd("log", 3, "*", "shouty") == 0 && mfk_log_set_calls == 1);
	okc("log usage on missing args", run_cmd("log", 1) == 0 && mfk_log_set_calls == 1);

	okc("lab on", run_cmd("lab", 2, "on") == 0 && mfk_lab_on == 1);
	okc("lab off", run_cmd("lab", 2, "off") == 0 && mfk_lab_on == 0);
	okc("lab bare prints state", run_cmd("lab", 1) == 0);
	okc("lab usage on bad arg", run_cmd("lab", 2, "maybe") == 0);
	okc("lab cir on arms the dump",
	    run_cmd("lab", 3, "cir", "on") == 0 && uwb_cirdiag_dump_enabled());
	okc("lab cir off disarms it",
	    run_cmd("lab", 3, "cir", "off") == 0 && !uwb_cirdiag_dump_enabled());
	mfk_cir_probes = 0;
	okc("lab cir probe runs the accumulator diagnostic",
	    run_cmd("lab", 3, "cir", "probe") == 0 && mfk_cir_probes == 1);
	okc("lab cir usage on bad arg", run_cmd("lab", 3, "cir", "maybe") == 0);

	mfk_prov_clear_calls = 0;
	mfk_em_factory_resets = 0;
	okc("factoryreset clears the ultrawidelock store then resets matter",
	    run_cmd("factoryreset", 1) == 0 && mfk_prov_clear_calls == 1 &&
		    mfk_em_factory_resets == 1);

	mfk_linenoise_clears = 0;
	okc("clear wipes the terminal",
	    run_cmd("clear", 1) == 0 && mfk_linenoise_clears == 1);
}

/* ---- K: app_main reboot path ------------------------------------------------------------ */
static void section_app_main_reboot(void)
{
	printf("-- app_main reboot path\n");
	int tasks_before = mfk_task_count;
	mfk_fabric_count = 1;         /* already commissioned */
	mfk_em_cluster_create_null = 1; /* approach cluster creation failure */
	mfk_ble_prepare_null = 1;     /* GATT prepare failure */
	mfk_qr_fail = 1;              /* onboarding codes unavailable */
	mfk_manual_fail = 1;
	int blemgr_before = mfk_blemgr_calls;
	int attr_before = mfk_em_attr_creates;

	app_main();

	okc("commissioned reboot skips a second reader task (once-guard)",
	    mfk_task_count == tasks_before);
	okc("approach cluster failure adds no attributes",
	    mfk_em_attr_creates == attr_before);
	okc("GATT prepare failure skips extra-service registration",
	    mfk_blemgr_calls == blemgr_before);
	okc("matter restarted with the event callback",
	    mfk_em_start_calls == 2 && mfk_em_event_cb != nullptr);
	mfk_em_cluster_create_null = 0;
	mfk_ble_prepare_null = 0;
	mfk_qr_fail = 0;
	mfk_manual_fail = 0;
}

int main(void)
{
	printf("test_esp_matter_lock: matter-lock app glue vs matterfake doubles\n"
	       "  (fakes prove branch logic + argument plumbing only — never\n"
	       "   CHIP-stack, NimBLE, hardware, or crypto truth)\n");

	section_app_driver();
	section_delegate();
	section_manager();
	section_callbacks();
	section_app_main();
	section_events();
	section_matter_callbacks();
	section_reader_task();
	section_range_listener();
	section_shell();
	section_app_main_reboot();

	printf("\nRESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
	return fails == 0 ? 0 : 1;
}
