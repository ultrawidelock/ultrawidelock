/*
 * matterfake — host-side fakes of the CHIP / esp-matter surface the
 * matter-lock app glue compiles against, so those production sources build
 * unmodified with plain c++ and their branch logic can be unit-tested.
 * Every entry point is a recording double whose state lives in mfk_* globals
 * (matterfake.cc) that the test binary scripts and inspects. Nothing here
 * talks to a radio, a Matter fabric, or real crypto: a passing suite proves
 * wiring and branch logic against the fakes, NOT CHIP-stack or hardware truth.
 *
 * The named CHIP / esp-matter headers under this directory are one-line shims
 * onto this file, mirroring only the slice of the real API the app uses.
 */
#ifndef MATTERFAKE_H
#define MATTERFAKE_H

#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <type_traits>
#include <vector>

struct ble_gatt_svc_def; /* completed by the host/ble_hs.h fake */

/* ---- CHIP error type ---------------------------------------------------- */
namespace chip {

class ChipError {
public:
	constexpr ChipError() : mCode(0) {}
	constexpr explicit ChipError(uint32_t c) : mCode(c) {}
	constexpr bool operator==(const ChipError &o) const { return mCode == o.mCode; }
	constexpr bool operator!=(const ChipError &o) const { return mCode != o.mCode; }
	unsigned Format() const { return (unsigned)mCode; }
	const char *AsString() const { return mCode == 0 ? "CHIP_NO_ERROR" : "CHIP_ERROR"; }
	uint32_t code() const { return mCode; }

private:
	uint32_t mCode;
};

} // namespace chip

using CHIP_ERROR = chip::ChipError;

#define CHIP_NO_ERROR chip::ChipError(0)
#define CHIP_ERROR_INVALID_ARGUMENT chip::ChipError(0x2f)
#define CHIP_ERROR_NO_MEMORY chip::ChipError(0x0b)
#define CHIP_ERROR_INTERNAL chip::ChipError(0xac)
#define CHIP_ERROR_BUFFER_TOO_SMALL chip::ChipError(0x19)
#define CHIP_ERROR_PROVIDER_LIST_EXHAUSTED chip::ChipError(0xc7)
#define CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND chip::ChipError(0xa0)
#define CHIP_DEVICE_ERROR_CONFIG_NOT_FOUND chip::ChipError(0xb001)
#define CHIP_ERROR_FORMAT "x"

/* ---- logging (compiled, format-checked, silent) -------------------------- */
#define ChipLogProgress(MOD, ...)                                              \
	do {                                                                   \
		if (0) {                                                       \
			printf(__VA_ARGS__);                                   \
		}                                                              \
	} while (0)
#define ChipLogError(MOD, ...)                                                 \
	do {                                                                   \
		if (0) {                                                       \
			printf(__VA_ARGS__);                                   \
		}                                                              \
	} while (0)

/* ---- assertion helpers --------------------------------------------------- */
#define VerifyOrReturnError(expr, code)                                        \
	do {                                                                   \
		if (!(expr)) {                                                 \
			return (code);                                         \
		}                                                              \
	} while (0)
#define VerifyOrReturnValue(expr, value)                                       \
	do {                                                                   \
		if (!(expr)) {                                                 \
			return (value);                                        \
		}                                                              \
	} while (0)

#define MATTER_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* ---- core scalar types --------------------------------------------------- */
namespace chip {

using EndpointId = uint16_t;
using ClusterId = uint32_t;
using AttributeId = uint32_t;
using FabricIndex = uint8_t;
using NodeId = uint64_t;

template <typename E> constexpr auto to_underlying(E e)
{
	return static_cast<std::underlying_type_t<E>>(e);
}

/* ---- Span --------------------------------------------------------------- */
template <class T> class Span {
public:
	constexpr Span() : mData(nullptr), mSize(0) {}
	constexpr Span(T *data, size_t size) : mData(data), mSize(size) {}
	template <size_t N> constexpr Span(T (&arr)[N]) : mData(arr), mSize(N) {}
	/* qualification conversion (e.g. Span<uint8_t> -> Span<const uint8_t>) */
	template <class U,
		  class = std::enable_if_t<std::is_convertible<U (*)[], T (*)[]>::value>>
	constexpr Span(const Span<U> &o) : mData(o.data()), mSize(o.size()) {}

	constexpr T *data() const { return mData; }
	constexpr size_t size() const { return mSize; }
	constexpr bool empty() const { return mSize == 0; }
	void reduce_size(size_t n)
	{
		if (n <= mSize) {
			mSize = n;
		}
	}
	template <class U> bool data_equal(const Span<U> &o) const
	{
		return mSize == o.size() &&
		       (mSize == 0 || memcmp(mData, o.data(), mSize * sizeof(T)) == 0);
	}

private:
	T *mData;
	size_t mSize;
};

using ByteSpan = Span<const uint8_t>;
using MutableByteSpan = Span<uint8_t>;
using CharSpan = Span<const char>;
using MutableCharSpan = Span<char>;

inline CHIP_ERROR CopySpanToMutableSpan(ByteSpan in, MutableByteSpan &out)
{
	if (out.size() < in.size()) {
		return CHIP_ERROR_BUFFER_TOO_SMALL;
	}
	if (in.size() > 0) {
		memcpy(out.data(), in.data(), in.size());
	}
	out.reduce_size(in.size());
	return CHIP_NO_ERROR;
}

/* ---- Optional / Nullable ------------------------------------------------- */
template <class T> class Optional {
public:
	Optional() : mHas(false), mVal() {}
	explicit Optional(const T &v) : mHas(true), mVal(v) {}
	bool HasValue() const { return mHas; }
	const T &Value() const { return mVal; }

private:
	bool mHas;
	T mVal;
};

namespace app {
namespace DataModel {

struct NullNullableType {};
inline constexpr NullNullableType NullNullable{};

template <class T> class Nullable {
public:
	Nullable() : mNull(true), mVal() {}
	Nullable(NullNullableType) : mNull(true), mVal() {}
	Nullable(const T &v) : mNull(false), mVal(v) {}
	bool IsNull() const { return mNull; }
	const T &Value() const { return mVal; }
	void SetNonNull(const T &v)
	{
		mNull = false;
		mVal = v;
	}
	void SetNull() { mNull = true; }

private:
	bool mNull;
	T mVal;
};

template <class T> Nullable<T> MakeNullable(const T &v)
{
	return Nullable<T>(v);
}

} // namespace DataModel
} // namespace app

using app::DataModel::Nullable; /* CHIP exposes the unqualified spelling too */

/* ---- misc support -------------------------------------------------------- */
namespace Platform {
template <size_t N> void CopyString(char (&dest)[N], CharSpan src)
{
	size_t n = src.size() < N - 1 ? src.size() : N - 1;
	if (n > 0) {
		memcpy(dest, src.data(), n);
	}
	dest[n] = '\0';
}
} // namespace Platform

namespace Encoding {
namespace BigEndian {
inline void Put16(uint8_t *buf, uint16_t v)
{
	buf[0] = (uint8_t)(v >> 8);
	buf[1] = (uint8_t)(v & 0xff);
}
} // namespace BigEndian
} // namespace Encoding

namespace Crypto {
CHIP_ERROR DRBG_get_bytes(uint8_t *buf, size_t len); /* recording double */
} // namespace Crypto

namespace Protocols {
namespace InteractionModel {
enum class Status : uint8_t { Success = 0, Failure = 1 };
} // namespace InteractionModel
} // namespace Protocols

namespace System {
namespace Clock {
struct Seconds16 {
	uint16_t value;
	constexpr explicit Seconds16(unsigned v) : value((uint16_t)v) {}
};
struct Milliseconds32 {
	uint32_t value;
	constexpr explicit Milliseconds32(unsigned v) : value((uint32_t)v) {}
};
} // namespace Clock

/* One timer slot. app_main arms a single timer (the reader's wait for the
 * commissioner to go quiet); starting it again replaces the pending one, as
 * the real layer does for the same callback. mfk_timer_fire() is the tick. */
class Layer;
typedef void (*TimerCompleteCallback)(Layer *layer, void *appState);
class Layer {
public:
	CHIP_ERROR StartTimer(Clock::Milliseconds32 delay, TimerCompleteCallback cb, void *appState);
	void CancelTimer(TimerCompleteCallback cb, void *appState);
};
} // namespace System

enum class CommissioningWindowAdvertisement { kAllSupported = 0, kDnssdOnly = 1 };

enum class RendezvousInformationFlag : uint8_t {
	kNone = 0,
	kSoftAP = 1,
	kBLE = 2,
	kOnNetwork = 4,
};

class RendezvousInformationFlags {
public:
	constexpr RendezvousInformationFlags(RendezvousInformationFlag f)
		: mRaw((uint8_t)f)
	{
	}
	uint8_t Raw() const { return mRaw; }

private:
	uint8_t mRaw;
};

class QRCodeBasicSetupPayloadGenerator {
public:
	static constexpr size_t kMaxQRCodeBase38RepresentationLength = 38;
};

/* ---- door lock cluster data model ---------------------------------------- */
namespace app {
namespace Clusters {
namespace DoorLock {

inline constexpr uint32_t Id = 0x00000101;

enum class DlLockState : uint8_t {
	kNotFullyLocked = 0,
	kLocked = 1,
	kUnlocked = 2,
	kUnlatched = 3,
	kUnknownEnumValue = 4,
};

enum class CredentialTypeEnum : uint8_t {
	kProgrammingPIN = 0,
	kPin = 1,
	kRfid = 2,
	kFingerprint = 3,
	kFingerVein = 4,
	kFace = 5,
	kAliroCredentialIssuerKey = 6,
	kAliroEvictableEndpointKey = 7,
	kAliroNonEvictableEndpointKey = 8,
};

enum class DlCredentialStatus : uint8_t { kAvailable = 0, kOccupied = 1 };
enum class DlScheduleStatus : uint8_t { kAvailable = 0, kOccupied = 1 };
enum class DlStatus : uint8_t {
	kSuccess = 0,
	kFailure = 1,
	kDuplicate = 2,
	kOccupied = 3,
	kInvalidField = 0x85,
	kResourceExhausted = 0x89,
	kNotFound = 0x8b,
};

enum class UserStatusEnum : uint8_t {
	kAvailable = 0,
	kOccupiedEnabled = 1,
	kOccupiedDisabled = 3,
};

enum class UserTypeEnum : uint8_t {
	kUnrestrictedUser = 0,
	kYearDayScheduleUser = 1,
	kWeekDayScheduleUser = 2,
	kProgrammingUser = 3,
	kNonAccessUser = 4,
	kForcedUser = 5,
	kDisposableUser = 6,
	kExpiringUser = 7,
	kScheduleRestrictedUser = 8,
	kRemoteOnlyUser = 9,
};

enum class CredentialRuleEnum : uint8_t { kSingle = 0, kDual = 1, kTri = 2 };

enum class OperationSourceEnum : uint8_t {
	kUnspecified = 0,
	kManual = 1,
	kProprietaryRemote = 2,
	kKeypad = 3,
	kAuto = 4,
	kButton = 5,
	kSchedule = 6,
	kRemote = 7,
	kRfid = 8,
	kBiometric = 9,
	kAliro = 10,
};

enum class OperationErrorEnum : uint8_t {
	kUnspecified = 0,
	kInvalidCredential = 1,
	kDisabledUserDenied = 2,
	kRestricted = 3,
	kInsufficientBattery = 4,
};

enum class OperatingModeEnum : uint8_t {
	kNormal = 0,
	kVacation = 1,
	kPrivacy = 2,
	kNoRemoteLockUnlock = 3,
	kPassage = 4,
};

enum class DaysMaskMap : uint8_t {
	kSunday = 0x01,
	kMonday = 0x02,
	kTuesday = 0x04,
	kWednesday = 0x08,
	kThursday = 0x10,
	kFriday = 0x20,
	kSaturday = 0x40,
};

enum class DlAssetSource : uint8_t { kUnspecified = 0, kMatterIM = 1 };

/* credential reader-provisioning sizes (Matter door lock cluster spec). */
inline constexpr size_t kAliroReaderVerificationKeySize = 65;
inline constexpr size_t kAliroReaderGroupIdentifierSize = 16;
inline constexpr size_t kAliroReaderGroupSubIdentifierSize = 16;
inline constexpr size_t kAliroGroupResolvingKeySize = 16;
inline constexpr size_t kAliroSigningKeySize = 32;
inline constexpr size_t kAliroProtocolVersionSize = 2;

/* ---- attribute accessors (scripted recording doubles) -------------------- */
namespace Attributes {
namespace LockState {
Protocols::InteractionModel::Status Get(EndpointId ep,
					DataModel::Nullable<DlLockState> &out);
} // namespace LockState
namespace FeatureMap {
Protocols::InteractionModel::Status Get(EndpointId ep, uint32_t *out);
} // namespace FeatureMap
namespace RequirePINforRemoteOperation {
Protocols::InteractionModel::Status Get(EndpointId ep, bool *out);
} // namespace RequirePINforRemoteOperation
} // namespace Attributes

} // namespace DoorLock
} // namespace Clusters
} // namespace app
} // namespace chip

/* The real door-lock-server.h leaks these into the global namespace; the
 * production sources rely on that. */
using namespace chip::app::Clusters::DoorLock;
using chip::Optional;

#define DOOR_LOCK_MAX_USER_NAME_SIZE 10

/* ---- ember plugin structs ------------------------------------------------- */
struct CredentialStruct {
	CredentialTypeEnum credentialType = CredentialTypeEnum::kProgrammingPIN;
	uint16_t credentialIndex = 0;
};

struct EmberAfPluginDoorLockUserInfo {
	chip::CharSpan userName;
	chip::Span<const CredentialStruct> credentials;
	uint32_t userUniqueId = 0;
	UserStatusEnum userStatus = UserStatusEnum::kAvailable;
	UserTypeEnum userType = UserTypeEnum::kUnrestrictedUser;
	CredentialRuleEnum credentialRule = CredentialRuleEnum::kSingle;
	DlAssetSource creationSource = DlAssetSource::kMatterIM;
	chip::FabricIndex createdBy = 0;
	DlAssetSource modificationSource = DlAssetSource::kMatterIM;
	chip::FabricIndex lastModifiedBy = 0;
};

struct EmberAfPluginDoorLockCredentialInfo {
	DlCredentialStatus status = DlCredentialStatus::kAvailable;
	CredentialTypeEnum credentialType = CredentialTypeEnum::kProgrammingPIN;
	chip::ByteSpan credentialData;
	DlAssetSource creationSource = DlAssetSource::kMatterIM;
	chip::FabricIndex createdBy = 0;
	DlAssetSource modificationSource = DlAssetSource::kMatterIM;
	chip::FabricIndex lastModifiedBy = 0;
};

struct EmberAfPluginDoorLockWeekDaySchedule {
	DaysMaskMap daysMask = (DaysMaskMap)0;
	uint8_t startHour = 0;
	uint8_t startMinute = 0;
	uint8_t endHour = 0;
	uint8_t endMinute = 0;
};

struct EmberAfPluginDoorLockYearDaySchedule {
	uint32_t localStartTime = 0;
	uint32_t localEndTime = 0;
};

struct EmberAfPluginDoorLockHolidaySchedule {
	uint32_t localStartTime = 0;
	uint32_t localEndTime = 0;
	OperatingModeEnum operatingMode = OperatingModeEnum::kNormal;
};

/* ---- DoorLockServer (recording double) ------------------------------------ */
class DoorLockServer {
public:
	static DoorLockServer &Instance();
	void InitServer(chip::EndpointId ep);
	void SetLockState(chip::EndpointId ep, DlLockState state);
	void SetLockState(chip::EndpointId ep, DlLockState state, OperationSourceEnum source,
			  const chip::app::DataModel::Nullable<uint16_t> &userIndex);
	bool GetNumberOfCredentialsSupportedPerUser(chip::EndpointId ep, uint8_t &out);
	bool GetNumberOfUserSupported(chip::EndpointId ep, uint16_t &out);
};

/* ---- door lock delegate base ---------------------------------------------- */
namespace chip {
namespace app {
namespace Clusters {
namespace DoorLock {

class Delegate {
public:
	virtual ~Delegate() = default;
	virtual CHIP_ERROR GetAliroReaderVerificationKey(MutableByteSpan &out) = 0;
	virtual CHIP_ERROR GetAliroReaderGroupIdentifier(MutableByteSpan &out) = 0;
	virtual CHIP_ERROR GetAliroReaderGroupSubIdentifier(MutableByteSpan &out) = 0;
	virtual CHIP_ERROR GetAliroExpeditedTransactionSupportedProtocolVersionAtIndex(
		size_t index, MutableByteSpan &out) = 0;
	virtual CHIP_ERROR GetAliroGroupResolvingKey(MutableByteSpan &out) = 0;
	virtual CHIP_ERROR
	GetAliroSupportedBLEUWBProtocolVersionAtIndex(size_t index, MutableByteSpan &out) = 0;
	virtual uint8_t GetAliroBLEAdvertisingVersion() = 0;
	virtual uint16_t GetNumberOfAliroCredentialIssuerKeysSupported() = 0;
	virtual uint16_t GetNumberOfAliroEndpointKeysSupported() = 0;
	virtual CHIP_ERROR SetAliroReaderConfig(const ByteSpan &signingKey,
						const ByteSpan &verificationKey,
						const ByteSpan &groupIdentifier,
						const Optional<ByteSpan> &groupResolvingKey) = 0;
	virtual CHIP_ERROR ClearAliroReaderConfig() = 0;
};

} // namespace DoorLock
} // namespace Clusters
} // namespace app

/* ---- device layer --------------------------------------------------------- */
namespace DeviceLayer {

namespace DeviceEventType {
enum PublicEventTypes : uint16_t {
	kInterfaceIpAddressChanged = 1,
	kCommissioningComplete,
	kFailSafeTimerExpired,
	kCommissioningSessionStarted,
	kCommissioningSessionStopped,
	kCommissioningWindowOpened,
	kCommissioningWindowClosed,
	kFabricRemoved,
	kFabricWillBeRemoved,
	kFabricUpdated,
	kFabricCommitted,
	kBLEDeinitialized,
	kUnknownFakeEvent = 0x7fff,
};
} // namespace DeviceEventType

struct ChipDeviceEvent {
	uint16_t Type;
};

class PlatformManager {
public:
	/* Executes the work immediately (recording); the production sources hop
	 * to "the Matter task" — here that hop is synchronous by design. Returns
	 * CHIP_ERROR like the real one, so callers that check whether the hop was
	 * even accepted compile here too; mfk_sched_rc forces the failure branch. */
	CHIP_ERROR ScheduleWork(void (*fn)(intptr_t), intptr_t arg = 0);
	void LockChipStack();
	void UnlockChipStack();
};

PlatformManager &PlatformMgr();
System::Layer &SystemLayer();

namespace Internal {

class BLEManagerImpl {
public:
	CHIP_ERROR ConfigureExtraServices(std::vector<::ble_gatt_svc_def> &svcs, bool append);
};

BLEManagerImpl &BLEMgrImpl();

/* ---- ESP32Config (in-RAM blob store) ---- */
class ESP32Config {
public:
	struct Key {
		const char *Name;
	};
	static constexpr Key kConfigKey_LockUser{"lock-user"};
	static constexpr Key kConfigKey_Credential{"credential"};
	static constexpr Key kConfigKey_LockUserName{"lock-user-name"};
	static constexpr Key kConfigKey_CredentialData{"credential-data"};
	static constexpr Key kConfigKey_UserCredentials{"user-credentials"};
	static constexpr Key kConfigKey_WeekDaySchedules{"week-day-schedules"};
	static constexpr Key kConfigKey_YearDaySchedules{"year-day-schedules"};
	static constexpr Key kConfigKey_HolidaySchedules{"holiday-schedules"};

	static CHIP_ERROR ReadConfigValueBin(Key key, uint8_t *buf, size_t bufSize,
					     size_t &outLen);
	static CHIP_ERROR WriteConfigValueBin(Key key, const uint8_t *data, size_t dataLen);
};

} // namespace Internal
} // namespace DeviceLayer

/* ---- Server / fabric / commissioning window -------------------------------- */
class FabricTable {
public:
	uint8_t FabricCount() const;
};

class CommissioningWindowManager {
public:
	bool IsCommissioningWindowOpen() const;
	/* Defaulted like the real signature, so the recovery path in app_main can
	 * call it bare and still get kAllSupported (BLE included), which is the
	 * whole point of that path over the dnssd-only one on fabric removal. */
	CHIP_ERROR OpenBasicCommissioningWindow(
		System::Clock::Seconds16 timeout = System::Clock::Seconds16(900),
		CommissioningWindowAdvertisement adv = CommissioningWindowAdvertisement::kAllSupported);
	void CloseCommissioningWindow();
};

namespace app {
class FailSafeContext {
public:
	bool IsFailSafeArmed() const;
};
} // namespace app

class Server {
public:
	static Server &GetInstance();
	FabricTable &GetFabricTable();
	CommissioningWindowManager &GetCommissioningWindowManager();
	app::FailSafeContext &GetFailSafeContext();
};

} // namespace chip

using chip::DeviceLayer::ChipDeviceEvent;

/* ---- onboarding codes (setup_payload fakes) -------------------------------- */
void PrintOnboardingCodes(chip::RendezvousInformationFlags flags);
CHIP_ERROR GetQRCode(chip::MutableCharSpan &out, chip::RendezvousInformationFlags flags);
CHIP_ERROR GetQRCodeUrl(char *url, size_t cap, chip::CharSpan qr);
CHIP_ERROR GetManualPairingCode(chip::MutableCharSpan &out,
				chip::RendezvousInformationFlags flags);

/* ---- DoorLock plugin callback declarations (real door-lock-server.h has
 * these; door_lock_callbacks.cpp defines them, the test invokes them). ------ */
void door_lock_init();
void emberAfDoorLockClusterInitCallback(chip::EndpointId endpoint);
bool emberAfPluginDoorLockOnDoorLockCommand(
	chip::EndpointId endpointId, const chip::Nullable<chip::FabricIndex> &fabricIdx,
	const chip::Nullable<chip::NodeId> &nodeId, const chip::Optional<chip::ByteSpan> &pinCode,
	OperationErrorEnum &err);
bool emberAfPluginDoorLockOnDoorUnlockCommand(
	chip::EndpointId endpointId, const chip::Nullable<chip::FabricIndex> &fabricIdx,
	const chip::Nullable<chip::NodeId> &nodeId, const chip::Optional<chip::ByteSpan> &pinCode,
	OperationErrorEnum &err);
bool emberAfPluginDoorLockGetCredential(chip::EndpointId endpointId, uint16_t credentialIndex,
					CredentialTypeEnum credentialType,
					EmberAfPluginDoorLockCredentialInfo &credential);
bool emberAfPluginDoorLockSetCredential(chip::EndpointId endpointId, uint16_t credentialIndex,
					chip::FabricIndex creator, chip::FabricIndex modifier,
					DlCredentialStatus credentialStatus,
					CredentialTypeEnum credentialType,
					const chip::ByteSpan &credentialData);
bool emberAfPluginDoorLockGetUser(chip::EndpointId endpointId, uint16_t userIndex,
				  EmberAfPluginDoorLockUserInfo &user);
bool emberAfPluginDoorLockSetUser(chip::EndpointId endpointId, uint16_t userIndex,
				  chip::FabricIndex creator, chip::FabricIndex modifier,
				  const chip::CharSpan &userName, uint32_t uniqueId,
				  UserStatusEnum userStatus, UserTypeEnum usertype,
				  CredentialRuleEnum credentialRule,
				  const CredentialStruct *credentials, size_t totalCredentials);
DlStatus emberAfPluginDoorLockGetSchedule(chip::EndpointId endpointId, uint8_t weekdayIndex,
					  uint16_t userIndex,
					  EmberAfPluginDoorLockWeekDaySchedule &schedule);
DlStatus emberAfPluginDoorLockGetSchedule(chip::EndpointId endpointId, uint8_t yearDayIndex,
					  uint16_t userIndex,
					  EmberAfPluginDoorLockYearDaySchedule &schedule);
DlStatus emberAfPluginDoorLockGetSchedule(chip::EndpointId endpointId, uint8_t holidayIndex,
					  EmberAfPluginDoorLockHolidaySchedule &holidaySchedule);
DlStatus emberAfPluginDoorLockSetSchedule(chip::EndpointId endpointId, uint8_t weekdayIndex,
					  uint16_t userIndex, DlScheduleStatus status,
					  DaysMaskMap daysMask, uint8_t startHour,
					  uint8_t startMinute, uint8_t endHour, uint8_t endMinute);
DlStatus emberAfPluginDoorLockSetSchedule(chip::EndpointId endpointId, uint8_t yearDayIndex,
					  uint16_t userIndex, DlScheduleStatus status,
					  uint32_t localStartTime, uint32_t localEndTime);
DlStatus emberAfPluginDoorLockSetSchedule(chip::EndpointId endpointId, uint8_t holidayIndex,
					  DlScheduleStatus status, uint32_t localStartTime,
					  uint32_t localEndTime, OperatingModeEnum operatingMode);
void emberAfPluginDoorLockOnAutoRelock(chip::EndpointId endpointId);

/* ===========================================================================
 * Recording / scripting surface (defined in matterfake.cc).
 * =========================================================================== */

/* DoorLockServer */
extern int mfk_dls_init_server_calls;
extern uint16_t mfk_dls_init_server_ep;
extern int mfk_dls_set_lock_calls;
extern uint16_t mfk_dls_last_ep;
extern int mfk_dls_last_state;  /* DlLockState as int */
extern int mfk_dls_last_source; /* OperationSourceEnum as int; -1 for 2-arg form */
extern int mfk_dls_last_user_null;
extern uint16_t mfk_dls_last_user;
/* per-direction history (the last-call record above gets overwritten when an
 * unlock is immediately followed by a relock) */
extern int mfk_dls_unlock_user_null;
extern uint16_t mfk_dls_unlock_user;
extern int mfk_dls_lock_user_null;
extern uint16_t mfk_dls_lock_user;
extern int mfk_dls_creds_ok; /* GetNumberOfCredentialsSupportedPerUser succeeds */
extern uint8_t mfk_dls_creds_val;
extern int mfk_dls_users_ok;
extern uint16_t mfk_dls_users_val;

/* attribute accessors */
extern int mfk_attr_lockstate_null;
extern int mfk_attr_lockstate_val; /* DlLockState as int */
extern uint32_t mfk_attr_featuremap;
extern int mfk_attr_requirepin_ok; /* Status Success when nonzero */
extern int mfk_attr_requirepin_val;

/* Server / fabric / commissioning window */
extern uint8_t mfk_fabric_count;
extern int mfk_cw_is_open;
extern int mfk_cw_open_calls;
extern uint32_t mfk_cw_open_rc; /* raw CHIP error code returned */
extern uint16_t mfk_cw_last_timeout;
extern int mfk_cw_last_adv;
extern int mfk_cw_close_calls;
extern int mfk_failsafe_armed;

/* System layer timer (one slot). */
extern int mfk_timer_pending;
extern int mfk_timer_starts;
extern uint32_t mfk_timer_last_ms;
extern uint32_t mfk_timer_start_rc; /* raw CHIP error code: non-zero refuses StartTimer */
void mfk_timer_fire(void);

/* Button recorder. mfk_btn_fire_long_press() invokes whatever app_main hung on
 * BUTTON_LONG_PRESS_START, which is how a test presses the board's button. */
extern int mfk_btn_register_calls;
extern int mfk_btn_last_event;
extern int mfk_btn_register_rc; /* esp_err_t, as int: this header predates esp_err.h */
void mfk_btn_fire_long_press(void);

/* PlatformMgr / BLEMgr */
extern int mfk_sched_calls;
extern uint32_t mfk_sched_rc; /* non-zero: ScheduleWork refuses and runs nothing */
extern int mfk_lockstack_calls;
extern int mfk_unlockstack_calls;
extern int mfk_blemgr_calls;
extern size_t mfk_blemgr_nsvcs;
extern uint32_t mfk_blemgr_rc;

/* crypto */
extern int mfk_drbg_calls;
extern int mfk_drbg_fail; /* nonzero -> DRBG_get_bytes returns INTERNAL */
extern uint8_t mfk_drbg_fill;

/* ESP32Config blob store */
void mfk_cfg_reset(void);
int mfk_cfg_put(const char *name, const void *data, size_t len); /* 0 ok */
long mfk_cfg_len(const char *name);                              /* -1 absent */
int mfk_cfg_get(const char *name, void *buf, size_t cap);        /* copied n or -1 */
extern const char *mfk_cfg_fail_read;  /* blob name -> read errors */
extern const char *mfk_cfg_fail_write; /* blob name -> write errors */
extern int mfk_cfg_write_calls;

/* esp_matter recording */
extern int mfk_em_node_creates;
extern void *mfk_em_delegate;
extern uint8_t mfk_em_lock_state_init;
extern int mfk_em_feature_adds;
extern int mfk_em_ultrawidelock_prov_adds;
extern int mfk_em_ultrawidelock_bleuwb_adds;
extern int mfk_em_cluster_create_null; /* nonzero -> cluster::create returns NULL */
extern uint32_t mfk_em_cluster_create_id;
extern uint8_t mfk_em_cluster_create_flags;
extern int mfk_em_attr_creates;
extern uint32_t mfk_em_attr_last_id;
extern uint8_t mfk_em_attr_last_flags;
extern uint8_t mfk_em_attr_last_val;
extern int mfk_em_fm_creates;
extern uint32_t mfk_em_fm_val;
extern int mfk_em_cr_creates;
extern uint16_t mfk_em_cr_val;
extern int mfk_em_autorelock_creates;
extern uint32_t mfk_em_autorelock_val;
extern uint16_t mfk_em_endpoint_id; /* endpoint::get_id return */
extern int mfk_em_start_calls;
extern void (*mfk_em_event_cb)(const ChipDeviceEvent *, intptr_t);
extern int mfk_em_factory_resets;
/* callbacks recorded by node::create (invocable from the test) */
extern void *mfk_em_attribute_cb; /* esp_matter::attribute::callback_t */
extern void *mfk_em_identify_cb;  /* esp_matter::identification::callback_t */

/* onboarding codes */
extern int mfk_qr_fail;
extern int mfk_qr_url_fail;
extern int mfk_manual_fail;
extern int mfk_print_codes_calls;
/* app_print_onboarding_codes() uses these, not PrintOnboardingCodes(), because the
 * default WARN build compiles CHIP Progress logging out and that prints nothing. */
extern int mfk_qr_calls;
extern int mfk_manual_calls;

/* console + linenoise + log */
struct mfk_console_cmd {
	const char *command;
	const char *help;
	const char *hint;
	int (*func)(int argc, char **argv);
};
#define MFK_CMD_MAX 64
extern struct mfk_console_cmd mfk_cmds[MFK_CMD_MAX];
extern int mfk_cmd_count;
extern int mfk_help_registered;
extern int mfk_repl_started;
int (*mfk_cmd_lookup(const char *name))(int, char **);
extern int mfk_linenoise_dumb;
extern int mfk_linenoise_clears;
extern int mfk_linenoise_multiline;
extern const char *mfk_log_last_tag;
extern int mfk_log_last_level;
extern int mfk_log_set_calls;

/* freertos */
struct mfk_task {
	void (*fn)(void *);
	void *arg;
	char name[24];
	uint32_t stack;
	unsigned prio;
};
#define MFK_TASK_MAX 8
extern struct mfk_task mfk_tasks[MFK_TASK_MAX];
extern int mfk_task_count;
extern int mfk_delay_calls;
extern void (*mfk_delay_hook)(void);
extern int mfk_notify_gives;
extern int mfk_isr_gives;
extern int mfk_in_isr;
extern int mfk_yield_calls;
extern unsigned mfk_stack_hwm; /* words free reported by uxTaskGetStackHighWaterMark */

/* reader-task wake script: each ulTaskNotifyTake pops one step, applies its
 * trusted-range value + clock advance, and returns `wake`. Exhausting the
 * script longjmps back into the test (the production task loops forever). */
struct mfk_wake_step {
	uint32_t wake;      /* ulTaskNotifyTake return */
	int trusted;        /* ultrawidelock_uwb_trusted_range_cm returns this */
	int32_t cm;         /* ... with this distance */
	int64_t advance_ms; /* esp_timer clock advance applied at the wake */
	int session;        /* ultrawidelock_reader_session_active() from this wake on */
	int start_bump;     /* mfk_uwb_start_generation += this at the wake (a ranging restart) */
};
#define MFK_WAKE_MAX 64
extern struct mfk_wake_step mfk_wake_script[MFK_WAKE_MAX];
extern int mfk_wake_len;
extern int mfk_wake_idx;
void mfk_task_run(void (*fn)(void *), void *arg); /* setjmp wrapper */

/* NimBLE / time / sntp */
extern int mfk_ble_synced;
extern int mfk_adv_active;
extern int64_t mfk_now_us;
extern void (*mfk_sntp_cb)(struct timeval *);
extern int mfk_sntp_inits;

/* LED / BSP */
extern int mfk_led_new_rc;
extern int mfk_led_clears;
extern int mfk_led_refreshes;
extern int mfk_led_set_calls;
extern int mfk_led_gpio;
extern uint32_t mfk_led_last_index, mfk_led_r, mfk_led_g, mfk_led_b;
extern int mfk_bsp_button_calls;

/* ultrawidelock reader / ble / lab / lat / uwb stubs */
extern int mfk_reader_start_calls;
extern int mfk_status_tick_calls;
extern int64_t mfk_status_tick_last_ms;
extern int mfk_reader_start_rc;
extern int mfk_ble_prepare_null; /* nonzero -> ultrawidelock_reader_ble_prepare NULL */
extern int mfk_notify_unlock_calls;
/* ultrawidelock_reader_session_active(): the approach controller's presence signal. */
extern int mfk_session_active;
/* ultrawidelock_uwb_start_generation(): counts ranging (re)starts; settable. */
extern uint32_t mfk_uwb_start_generation;
extern int mfk_notify_unlock_last;
extern int mfk_auth_cred_have;
extern uint8_t mfk_auth_cred[65];
extern int mfk_prov_print_calls;
extern int mfk_trust_last_rc;
extern int mfk_trust_clear_rc;
extern int mfk_prov_identity_calls;
extern uint8_t mfk_prov_reader_id[32];
extern uint8_t mfk_prov_sign[32];
extern uint8_t mfk_prov_grk[16];
extern int mfk_prov_identity_rc;
extern int mfk_add_trust_calls;
extern uint8_t mfk_add_trust_key[65];
extern int mfk_add_trust_rc;
/* The Matter indices an add was bound to, and what a revocation named. */
extern uint8_t mfk_add_trust_type;
extern uint16_t mfk_add_trust_index;
extern uint16_t mfk_add_trust_user;
extern int mfk_remove_trust_calls;
extern uint8_t mfk_remove_trust_type;
extern uint16_t mfk_remove_trust_index;
extern int mfk_remove_trust_rc;
extern int mfk_remove_user_calls;
extern uint16_t mfk_remove_user_index;
extern int mfk_remove_user_rc;
/* The issuer-key mirror (SetCredential type 6) and the learned-key listener. */
extern int mfk_add_issuer_calls;
extern uint8_t mfk_add_issuer_key[65];
extern uint16_t mfk_add_issuer_index;
extern uint16_t mfk_add_issuer_user;
extern int mfk_add_issuer_rc;
extern int mfk_remove_issuer_calls;
extern uint16_t mfk_remove_issuer_index;
extern int mfk_remove_issuer_rc;
extern void (*mfk_learned_listener)(uint8_t, uint16_t, uint16_t, const uint8_t *);
extern int mfk_prov_clear_calls;
extern int mfk_refresh_adv_calls;
extern int mfk_ble_time_updated_calls;
extern int mfk_lab_on;
extern unsigned mfk_cir_probes;
extern int mfk_lab_evi_calls;
extern long mfk_lab_evi_last;
extern int mfk_lat_marks[32];
extern int mfk_lat_reports;
extern int mfk_last_have;
extern int32_t mfk_last_cm;
extern int64_t mfk_last_age_ms; /* ultrawidelock_uwb_last_range_age_cm hands this back */
extern int mfk_trusted_have;
extern int32_t mfk_trusted_cm;
/* The ranging block a trusted range came from. The two-anchor gate pairs on it,
 * so a test that drives the gate must be able to say which round it means. */
extern uint32_t mfk_trusted_block;
extern void (*mfk_range_listener)(void);

/* The two-anchor gate (sat_fusion.h), stubbed. mfk_may_predict is the knob:
 * TRUE is the real gate's fail-open answer, so tests that do not care about
 * the second anchor see today's single-anchor behaviour unchanged. */
extern int mfk_may_predict;
extern unsigned mfk_sat_init_calls;
extern unsigned mfk_sat_observe_calls;
extern unsigned mfk_sat_predict_asks;
/* Called after each gate answer, to change the NEXT one. */
extern void (*mfk_predict_hook)(void);
extern int32_t mfk_sat_last_mm;
extern uint32_t mfk_sat_last_block;

/* reset every scriptable knob + counter to boot defaults (the ESP32Config
 * store and the production singletons are NOT touched). */
void mfk_reset(void);

#endif /* MATTERFAKE_H */
