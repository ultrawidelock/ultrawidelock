// Matter DoorLock cluster plugin callbacks: wires the ESP32 port's BoltLockManager into the
// Matter DoorLock cluster's lock/unlock commands, user and credential storage, schedule
// storage, cluster init, and auto-relock notification hooks.
/*
   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <esp_log.h>
#include "door_lock_manager.h"
#include <lib/core/DataModelTypes.h>
#ifdef CONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB
// ULTRAWIDELOCK_CRED_INDEX_NONE, for the index this hook is not given
#include <ultrawidelock_prov.h>
#include <ultrawidelock/reader.h> // reader-side provisioning trust store (ultrawidelock_prov)
#endif

static const char *TAG = "doorlock_callback";

// Log that the door lock example has initialized. Performs no other setup.
void door_lock_init()
{
	ESP_LOGI(TAG, "doorlock example init");
}

// Matter DoorLock cluster init callback: initializes the cluster server for the
// endpoint, forces its LockState attribute to Locked, and syncs the bolt
// manager's lock state from BoltLockMgr().InitLockState(), logging an error if
// that sync fails.
void emberAfDoorLockClusterInitCallback(EndpointId endpoint)
{
	DoorLockServer::Instance().InitServer(endpoint);
	DoorLockServer::Instance().SetLockState(
		endpoint, chip::app::Clusters::DoorLock::DlLockState::kLocked);
	if (BoltLockMgr().InitLockState() != CHIP_NO_ERROR) {
		ESP_LOGE(TAG, "BoltLockMgr().InitLockState failed");
	}
}

// Matter DoorLock plugin hook for a remote Lock command.
// Validates the supplied PIN via BoltLockMgr().ValidatePIN, writing any failure
// reason to err. On success, locks the bolt with OperationSourceEnum::kRemote.
// Returns the validation result; on false, err holds the failure reason and the
// lock is left untouched.
bool emberAfPluginDoorLockOnDoorLockCommand(chip::EndpointId endpointId,
					    const Nullable<chip::FabricIndex> &fabricIdx,
					    const Nullable<chip::NodeId> &nodeId,
					    const Optional<ByteSpan> &pinCode,
					    OperationErrorEnum &err)
{
	ESP_LOGI(TAG, "Door Lock App: Lock Command endpoint=%d", endpointId);
	bool status = BoltLockMgr().ValidatePIN(endpointId, pinCode, err);
	if (status) {
		BoltLockMgr().Lock(endpointId,
				   app::Clusters::DoorLock::OperationSourceEnum::kRemote);
	}
	return status;
}

// Matter DoorLock plugin hook for a remote Unlock command.
// Validates the supplied PIN via BoltLockMgr().ValidatePIN, writing any failure
// reason to err. On success, unlocks the bolt with
// OperationSourceEnum::kRemote. Returns the validation result; on false, err
// holds the failure reason and the lock is left untouched.
bool emberAfPluginDoorLockOnDoorUnlockCommand(chip::EndpointId endpointId,
					      const Nullable<chip::FabricIndex> &fabricIdx,
					      const Nullable<chip::NodeId> &nodeId,
					      const Optional<ByteSpan> &pinCode,
					      OperationErrorEnum &err)
{
	ESP_LOGI(TAG, "Door Lock App: Unlock Command endpoint=%d", endpointId);
	bool status = BoltLockMgr().ValidatePIN(endpointId, pinCode, err);
	if (status) {
		BoltLockMgr().Unlock(endpointId,
				     app::Clusters::DoorLock::OperationSourceEnum::kRemote);
	}
	return status;
}

// Matter DoorLock plugin hook: fetch a stored credential by index and type for
// an endpoint. Delegates to BoltLockMgr().GetCredential; returns true if found.
bool emberAfPluginDoorLockGetCredential(chip::EndpointId endpointId, uint16_t credentialIndex,
					CredentialTypeEnum credentialType,
					EmberAfPluginDoorLockCredentialInfo &credential)
{
	return BoltLockMgr().GetCredential(endpointId, credentialIndex, credentialType, credential);
}

// Matter DoorLock plugin hook: store a credential for an endpoint via
// BoltLockMgr().SetCredential.
// When CONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB is enabled and the write succeeds with an
// Occupied status, a 65-byte credential endpoint key (evictable or non-evictable),
// the raw key is additionally mirrored into the credential reader's trust store via
// ultrawidelock_reader_provision_add_trust, so the reader accepts ranging auth from the
// Wallet credential Apple just installed. An Available status on the same types
// is the erase half of ClearCredential and revokes the anchor by its index.
// Returns the underlying SetCredential result regardless of whether either
// mirror step ran.
bool emberAfPluginDoorLockSetCredential(chip::EndpointId endpointId, uint16_t credentialIndex,
					chip::FabricIndex creator, chip::FabricIndex modifier,
					DlCredentialStatus credentialStatus,
					CredentialTypeEnum credentialType,
					const chip::ByteSpan &credentialData)
{
	bool ok = BoltLockMgr().SetCredential(endpointId, credentialIndex, creator, modifier,
					      credentialStatus, credentialType, credentialData);
#ifdef CONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB
	// Mirror an occupied credential endpoint key (the per-device key the phone signs
	// with during the ranging auth) into the reader's raw-key trust store, so the
	// handoff-started reader accepts the Wallet credential Apple just installed.
	if (ok && credentialStatus == DlCredentialStatus::kOccupied &&
	    credentialData.size() == 65 &&
	    (credentialType == CredentialTypeEnum::kAliroEvictableEndpointKey ||
	     credentialType == CredentialTypeEnum::kAliroNonEvictableEndpointKey)) {
		// The credential index is what a later removal will name this key by:
		// ClearCredential carries (type, index) and never the key bytes. This
		// hook is not given a user index, and does not need one -- the server
		// clears a user by clearing each of its credentials through here.
		int rc = ultrawidelock_reader_provision_add_trust(
			credentialData.data(), static_cast<uint8_t>(credentialType), credentialIndex,
			ULTRAWIDELOCK_CRED_INDEX_NONE);
		ESP_LOGI(TAG, "credential endpoint key -> reader trust store (type=%u rc=%d)",
			 static_cast<unsigned>(credentialType), rc);
		// rc == 1 is "already trusted", which is success. A negative rc means the
		// reader is NOT holding this key, so reporting success would leave the
		// controller showing an enrolled phone that can never open the door.
		if (rc < 0) {
			ok = false;
		}
	}
	// The issuer key (type 6) is not an anchor -- no phone presents it -- but it
	// is the key the step-up Access Document is signed under, and the only way a
	// device the hub never sends a SetCredential for (an Apple Watch on the
	// owner's Apple ID, in every field log so far) is admitted: the reader asks
	// such a device for its document and learns the key this issuer signed.
	if (ok && credentialStatus == DlCredentialStatus::kOccupied &&
	    credentialData.size() == 65 &&
	    credentialType == CredentialTypeEnum::kAliroCredentialIssuerKey) {
		int rc = ultrawidelock_reader_provision_add_issuer(credentialData.data(),
								   credentialIndex,
								   ULTRAWIDELOCK_CRED_INDEX_NONE);
		ESP_LOGI(TAG, "credential issuer key -> reader issuer store (index=%u rc=%d)",
			 static_cast<unsigned>(credentialIndex), rc);
		// rc == 1 is "already held". A negative rc means the reader cannot
		// verify documents under this issuer, so reporting success would leave
		// the controller believing the home's devices can all get in.
		if (rc < 0) {
			ok = false;
		}
	}
	// A ClearCredential arrives here as an Available status with empty data
	// (door-lock-server.cpp calls this hook to erase the slot), so this is the
	// only place the reader learns that a credential was revoked. Without it a
	// key removed in the controller's UI kept opening the door.
	if (ok && credentialStatus == DlCredentialStatus::kAvailable &&
	    credentialType == CredentialTypeEnum::kAliroCredentialIssuerKey) {
		int rc = ultrawidelock_reader_provision_remove_issuer(credentialIndex);
		ESP_LOGW(TAG, "credential issuer key REVOKED with its learned keys (index=%u rc=%d)",
			 static_cast<unsigned>(credentialIndex), rc);
		if (rc < 0) {
			ok = false;
		}
	}
	if (ok && credentialStatus == DlCredentialStatus::kAvailable &&
	    (credentialType == CredentialTypeEnum::kAliroEvictableEndpointKey ||
	     credentialType == CredentialTypeEnum::kAliroNonEvictableEndpointKey)) {
		int rc = ultrawidelock_reader_provision_remove_trust(
			static_cast<uint8_t>(credentialType), credentialIndex);
		ESP_LOGW(TAG, "credential endpoint key REVOKED (type=%u index=%u rc=%d)",
			 static_cast<unsigned>(credentialType),
			 static_cast<unsigned>(credentialIndex), rc);
		// rc == 1 is "no such anchor", which is the right answer to a removal
		// that already happened: still success. A negative rc means the anchor
		// left RAM but the store was not written, so the removal does not
		// survive a reboot and the admin has to be told.
		if (rc < 0) {
			ok = false;
		}
	}
#endif
	return ok;
}

// Matter DoorLock plugin hook: fetch a stored user by index for an endpoint.
// Delegates to BoltLockMgr().GetUser; returns true if found.
bool emberAfPluginDoorLockGetUser(chip::EndpointId endpointId, uint16_t userIndex,
				  EmberAfPluginDoorLockUserInfo &user)
{
	return BoltLockMgr().GetUser(endpointId, userIndex, user);
}

// Matter DoorLock plugin hook: store a user record for an endpoint, including
// name, unique ID, status, type, credential rule, and its list of credentials.
// Delegates to BoltLockMgr().SetUser.
bool emberAfPluginDoorLockSetUser(chip::EndpointId endpointId, uint16_t userIndex,
				  chip::FabricIndex creator, chip::FabricIndex modifier,
				  const chip::CharSpan &userName, uint32_t uniqueId,
				  UserStatusEnum userStatus, UserTypeEnum usertype,
				  CredentialRuleEnum credentialRule,
				  const CredentialStruct *credentials, size_t totalCredentials)
{

	return BoltLockMgr().SetUser(endpointId, userIndex, creator, modifier, userName, uniqueId,
				     userStatus, usertype, credentialRule, credentials,
				     totalCredentials);
}

DlStatus emberAfPluginDoorLockGetSchedule(chip::EndpointId endpointId, uint8_t weekdayIndex,
					  uint16_t userIndex,
					  EmberAfPluginDoorLockWeekDaySchedule &schedule)
{
	return BoltLockMgr().GetWeekdaySchedule(endpointId, weekdayIndex, userIndex, schedule);
}

DlStatus emberAfPluginDoorLockGetSchedule(chip::EndpointId endpointId, uint8_t yearDayIndex,
					  uint16_t userIndex,
					  EmberAfPluginDoorLockYearDaySchedule &schedule)
{
	return BoltLockMgr().GetYeardaySchedule(endpointId, yearDayIndex, userIndex, schedule);
}

// Matter DoorLock plugin hook: fetch a holiday schedule entry by index for an
// endpoint. Delegates to BoltLockMgr().GetHolidaySchedule.
DlStatus emberAfPluginDoorLockGetSchedule(chip::EndpointId endpointId, uint8_t holidayIndex,
					  EmberAfPluginDoorLockHolidaySchedule &holidaySchedule)
{
	return BoltLockMgr().GetHolidaySchedule(endpointId, holidayIndex, holidaySchedule);
}

DlStatus emberAfPluginDoorLockSetSchedule(chip::EndpointId endpointId, uint8_t weekdayIndex,
					  uint16_t userIndex, DlScheduleStatus status,
					  DaysMaskMap daysMask, uint8_t startHour,
					  uint8_t startMinute, uint8_t endHour, uint8_t endMinute)
{
	return BoltLockMgr().SetWeekdaySchedule(endpointId, weekdayIndex, userIndex, status,
						daysMask, startHour, startMinute, endHour,
						endMinute);
}

DlStatus emberAfPluginDoorLockSetSchedule(chip::EndpointId endpointId, uint8_t yearDayIndex,
					  uint16_t userIndex, DlScheduleStatus status,
					  uint32_t localStartTime, uint32_t localEndTime)
{
	return BoltLockMgr().SetYeardaySchedule(endpointId, yearDayIndex, userIndex, status,
						localStartTime, localEndTime);
}

// Matter DoorLock plugin hook: store a holiday schedule entry for an endpoint.
// Delegates to BoltLockMgr().SetHolidaySchedule.
DlStatus emberAfPluginDoorLockSetSchedule(chip::EndpointId endpointId, uint8_t holidayIndex,
					  DlScheduleStatus status, uint32_t localStartTime,
					  uint32_t localEndTime, OperatingModeEnum operatingMode)
{
	return BoltLockMgr().SetHolidaySchedule(endpointId, holidayIndex, status, localStartTime,
						localEndTime, operatingMode);
}

// Matter DoorLock plugin hook invoked on auto-relock; logs the event only, no
// lock-state change is performed here.
void emberAfPluginDoorLockOnAutoRelock(chip::EndpointId endpointId)
{
	ESP_LOGI(TAG, "Door auto relock");
}
