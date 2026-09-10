/*
 * matterfake.cc — recording-double implementations behind matterfake.h.
 * Everything is synchronous and in-RAM; see the header's honesty note.
 */
#include "matterfake.h"

#include <setjmp.h>

#include "bsp/esp-bsp.h"
#include "esp_app_desc.h"
#include "esp_console.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_matter.h"
#include "esp_netif_sntp.h"
#include "esp_timer.h"
#include "iot_button.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "led_strip.h"
#include "led_strip_rmt.h"
#include "linenoise/linenoise.h"
#include "nvs_flash.h"

#include "ultrawidelock_ble.h"
#include "ultrawidelock_lab.h"
#include "uwb_cirdiag.h"
#include "ultrawidelock_lat.h"
#include <ultrawidelock/reader.h>
#include "ultrawidelock_diag.h"
#include <ultrawidelock/uwb.h>

/* ---- DoorLockServer ------------------------------------------------------- */
int mfk_dls_init_server_calls;
uint16_t mfk_dls_init_server_ep;
int mfk_dls_set_lock_calls;
uint16_t mfk_dls_last_ep;
int mfk_dls_last_state = -1;
int mfk_dls_last_source = -1;
int mfk_dls_last_user_null = 1;
uint16_t mfk_dls_last_user;
int mfk_dls_unlock_user_null = -1;
uint16_t mfk_dls_unlock_user;
int mfk_dls_lock_user_null = -1;
uint16_t mfk_dls_lock_user;
int mfk_dls_creds_ok = 1;
uint8_t mfk_dls_creds_val = 10;
int mfk_dls_users_ok = 1;
uint16_t mfk_dls_users_val = 10;

DoorLockServer &DoorLockServer::Instance()
{
	static DoorLockServer inst;
	return inst;
}

void DoorLockServer::InitServer(chip::EndpointId ep)
{
	mfk_dls_init_server_calls++;
	mfk_dls_init_server_ep = ep;
}

void DoorLockServer::SetLockState(chip::EndpointId ep, DlLockState state)
{
	mfk_dls_set_lock_calls++;
	mfk_dls_last_ep = ep;
	mfk_dls_last_state = (int)state;
	mfk_dls_last_source = -1;
	mfk_dls_last_user_null = 1;
}

void DoorLockServer::SetLockState(chip::EndpointId ep, DlLockState state,
				  OperationSourceEnum source,
				  const chip::app::DataModel::Nullable<uint16_t> &userIndex)
{
	mfk_dls_set_lock_calls++;
	mfk_dls_last_ep = ep;
	mfk_dls_last_state = (int)state;
	mfk_dls_last_source = (int)source;
	mfk_dls_last_user_null = userIndex.IsNull() ? 1 : 0;
	mfk_dls_last_user = userIndex.IsNull() ? 0 : userIndex.Value();
	if (state == DlLockState::kUnlocked) {
		mfk_dls_unlock_user_null = mfk_dls_last_user_null;
		mfk_dls_unlock_user = mfk_dls_last_user;
	} else if (state == DlLockState::kLocked) {
		mfk_dls_lock_user_null = mfk_dls_last_user_null;
		mfk_dls_lock_user = mfk_dls_last_user;
	}
}

bool DoorLockServer::GetNumberOfCredentialsSupportedPerUser(chip::EndpointId ep, uint8_t &out)
{
	(void)ep;
	out = mfk_dls_creds_val;
	return mfk_dls_creds_ok != 0;
}

bool DoorLockServer::GetNumberOfUserSupported(chip::EndpointId ep, uint16_t &out)
{
	(void)ep;
	out = mfk_dls_users_val;
	return mfk_dls_users_ok != 0;
}

/* ---- attribute accessors -------------------------------------------------- */
int mfk_attr_lockstate_null;
int mfk_attr_lockstate_val = (int)DlLockState::kLocked;
uint32_t mfk_attr_featuremap;
int mfk_attr_requirepin_ok = 1;
int mfk_attr_requirepin_val;

namespace chip {
namespace app {
namespace Clusters {
namespace DoorLock {
namespace Attributes {

namespace LockState {
Protocols::InteractionModel::Status Get(EndpointId ep, DataModel::Nullable<DlLockState> &out)
{
	(void)ep;
	if (mfk_attr_lockstate_null) {
		out.SetNull();
	} else {
		out.SetNonNull((DlLockState)mfk_attr_lockstate_val);
	}
	return Protocols::InteractionModel::Status::Success;
}
} // namespace LockState

namespace FeatureMap {
Protocols::InteractionModel::Status Get(EndpointId ep, uint32_t *out)
{
	(void)ep;
	*out = mfk_attr_featuremap;
	return Protocols::InteractionModel::Status::Success;
}
} // namespace FeatureMap

namespace RequirePINforRemoteOperation {
Protocols::InteractionModel::Status Get(EndpointId ep, bool *out)
{
	(void)ep;
	*out = mfk_attr_requirepin_val != 0;
	return mfk_attr_requirepin_ok ? Protocols::InteractionModel::Status::Success
				      : Protocols::InteractionModel::Status::Failure;
}
} // namespace RequirePINforRemoteOperation

} // namespace Attributes
} // namespace DoorLock
} // namespace Clusters
} // namespace app
} // namespace chip

/* ---- Server / fabric / commissioning window ------------------------------- */
uint8_t mfk_fabric_count;
int mfk_cw_is_open;
int mfk_cw_open_calls;
int mfk_cw_close_calls;
uint32_t mfk_cw_open_rc;
uint16_t mfk_cw_last_timeout;
int mfk_cw_last_adv = -1;

namespace chip {

uint8_t FabricTable::FabricCount() const
{
	return mfk_fabric_count;
}

bool CommissioningWindowManager::IsCommissioningWindowOpen() const
{
	return mfk_cw_is_open != 0;
}

CHIP_ERROR CommissioningWindowManager::OpenBasicCommissioningWindow(
	System::Clock::Seconds16 timeout, CommissioningWindowAdvertisement adv)
{
	mfk_cw_open_calls++;
	mfk_cw_last_timeout = timeout.value;
	mfk_cw_last_adv = (int)adv;
	return ChipError(mfk_cw_open_rc);
}

void CommissioningWindowManager::CloseCommissioningWindow()
{
	mfk_cw_close_calls++;
	mfk_cw_is_open = 0;
}

Server &Server::GetInstance()
{
	static Server inst;
	return inst;
}

FabricTable &Server::GetFabricTable()
{
	static FabricTable table;
	return table;
}

CommissioningWindowManager &Server::GetCommissioningWindowManager()
{
	static CommissioningWindowManager mgr;
	return mgr;
}

/* ---- device layer --------------------------------------------------------- */
namespace DeviceLayer {

int _mfk_pm_dummy;

PlatformManager &PlatformMgr()
{
	static PlatformManager inst;
	return inst;
}

} // namespace DeviceLayer
} // namespace chip

int mfk_sched_calls;
uint32_t mfk_sched_rc;
int mfk_lockstack_calls;
int mfk_unlockstack_calls;

CHIP_ERROR chip::DeviceLayer::PlatformManager::ScheduleWork(void (*fn)(intptr_t), intptr_t arg)
{
	mfk_sched_calls++;
	if (mfk_sched_rc != 0) {
		return ChipError(mfk_sched_rc); /* refused: the work never runs */
	}
	fn(arg); /* synchronous: the fake "Matter task" is the caller */
	return CHIP_NO_ERROR;
}

void chip::DeviceLayer::PlatformManager::LockChipStack()
{
	mfk_lockstack_calls++;
}

void chip::DeviceLayer::PlatformManager::UnlockChipStack()
{
	mfk_unlockstack_calls++;
}

int mfk_blemgr_calls;
size_t mfk_blemgr_nsvcs;
uint32_t mfk_blemgr_rc;

namespace chip {
namespace DeviceLayer {
namespace Internal {

BLEManagerImpl &BLEMgrImpl()
{
	static BLEManagerImpl inst;
	return inst;
}

CHIP_ERROR BLEManagerImpl::ConfigureExtraServices(std::vector<::ble_gatt_svc_def> &svcs,
						  bool append)
{
	(void)append;
	mfk_blemgr_calls++;
	mfk_blemgr_nsvcs = svcs.size();
	return ChipError(mfk_blemgr_rc);
}

} // namespace Internal
} // namespace DeviceLayer
} // namespace chip

/* ---- crypto ---------------------------------------------------------------- */
int mfk_drbg_calls;
int mfk_drbg_fail;
uint8_t mfk_drbg_fill = 0xA5;

CHIP_ERROR chip::Crypto::DRBG_get_bytes(uint8_t *buf, size_t len)
{
	mfk_drbg_calls++;
	if (mfk_drbg_fail) {
		return CHIP_ERROR_INTERNAL;
	}
	memset(buf, mfk_drbg_fill, len);
	return CHIP_NO_ERROR;
}

/* ---- ESP32Config blob store ------------------------------------------------ */
#define MFK_CFG_SLOTS 8
#define MFK_CFG_CAP 16384
struct mfk_cfg_slot {
	char name[32];
	uint8_t data[MFK_CFG_CAP];
	size_t len;
	int present;
};
static struct mfk_cfg_slot mfk_cfg[MFK_CFG_SLOTS];
const char *mfk_cfg_fail_read;
const char *mfk_cfg_fail_write;
int mfk_cfg_write_calls;

static struct mfk_cfg_slot *mfk_cfg_find(const char *name, int create)
{
	for (int i = 0; i < MFK_CFG_SLOTS; i++) {
		if (mfk_cfg[i].present && strcmp(mfk_cfg[i].name, name) == 0) {
			return &mfk_cfg[i];
		}
	}
	if (!create) {
		return NULL;
	}
	for (int i = 0; i < MFK_CFG_SLOTS; i++) {
		if (!mfk_cfg[i].present) {
			snprintf(mfk_cfg[i].name, sizeof(mfk_cfg[i].name), "%s", name);
			mfk_cfg[i].present = 1;
			mfk_cfg[i].len = 0;
			return &mfk_cfg[i];
		}
	}
	return NULL;
}

void mfk_cfg_reset(void)
{
	memset(mfk_cfg, 0, sizeof(mfk_cfg));
	mfk_cfg_fail_read = NULL;
	mfk_cfg_fail_write = NULL;
	mfk_cfg_write_calls = 0;
}

int mfk_cfg_put(const char *name, const void *data, size_t len)
{
	struct mfk_cfg_slot *s = mfk_cfg_find(name, 1);
	if (s == NULL || len > MFK_CFG_CAP) {
		return -1;
	}
	memcpy(s->data, data, len);
	s->len = len;
	return 0;
}

long mfk_cfg_len(const char *name)
{
	struct mfk_cfg_slot *s = mfk_cfg_find(name, 0);
	return s == NULL ? -1 : (long)s->len;
}

int mfk_cfg_get(const char *name, void *buf, size_t cap)
{
	struct mfk_cfg_slot *s = mfk_cfg_find(name, 0);
	if (s == NULL) {
		return -1;
	}
	size_t n = s->len < cap ? s->len : cap;
	memcpy(buf, s->data, n);
	return (int)n;
}

CHIP_ERROR chip::DeviceLayer::Internal::ESP32Config::ReadConfigValueBin(Key key, uint8_t *buf,
									size_t bufSize,
									size_t &outLen)
{
	if (mfk_cfg_fail_read != NULL && strcmp(key.Name, mfk_cfg_fail_read) == 0) {
		return CHIP_ERROR_INTERNAL;
	}
	struct mfk_cfg_slot *s = mfk_cfg_find(key.Name, 0);
	if (s == NULL) {
		return CHIP_DEVICE_ERROR_CONFIG_NOT_FOUND;
	}
	size_t n = s->len < bufSize ? s->len : bufSize;
	memcpy(buf, s->data, n);
	outLen = s->len;
	return CHIP_NO_ERROR;
}

CHIP_ERROR chip::DeviceLayer::Internal::ESP32Config::WriteConfigValueBin(Key key,
									 const uint8_t *data,
									 size_t dataLen)
{
	mfk_cfg_write_calls++;
	if (mfk_cfg_fail_write != NULL && strcmp(key.Name, mfk_cfg_fail_write) == 0) {
		return CHIP_ERROR_INTERNAL;
	}
	if (mfk_cfg_put(key.Name, data, dataLen) != 0) {
		return CHIP_ERROR_NO_MEMORY;
	}
	return CHIP_NO_ERROR;
}

/* ---- esp_matter ------------------------------------------------------------- */
int mfk_em_node_creates;
void *mfk_em_delegate;
uint8_t mfk_em_lock_state_init;
int mfk_em_feature_adds;
int mfk_em_ultrawidelock_prov_adds;
int mfk_em_ultrawidelock_bleuwb_adds;
int mfk_em_cluster_create_null;
uint32_t mfk_em_cluster_create_id;
uint8_t mfk_em_cluster_create_flags;
int mfk_em_attr_creates;
uint32_t mfk_em_attr_last_id;
uint8_t mfk_em_attr_last_flags;
uint8_t mfk_em_attr_last_val;
int mfk_em_fm_creates;
uint32_t mfk_em_fm_val;
int mfk_em_cr_creates;
uint16_t mfk_em_cr_val;
int mfk_em_autorelock_creates;
uint32_t mfk_em_autorelock_val;
uint16_t mfk_em_endpoint_id = 1;
int mfk_em_start_calls;
void (*mfk_em_event_cb)(const ChipDeviceEvent *, intptr_t);
int mfk_em_factory_resets;
void *mfk_em_attribute_cb;
void *mfk_em_identify_cb;

static esp_matter::node_t *mfk_node_obj = (esp_matter::node_t *)&mfk_em_node_creates;
static esp_matter::endpoint_t *mfk_ep_obj = (esp_matter::endpoint_t *)&mfk_em_endpoint_id;
static esp_matter::cluster_t *mfk_cluster_obj = (esp_matter::cluster_t *)&mfk_em_feature_adds;
static esp_matter::attribute_t *mfk_attr_obj = (esp_matter::attribute_t *)&mfk_em_attr_creates;

namespace esp_matter {

node_t *node::create(config_t *config, attribute::callback_t attribute_cb,
		     identification::callback_t identification_cb, void *priv_data)
{
	(void)config;
	(void)priv_data;
	mfk_em_node_creates++;
	mfk_em_attribute_cb = (void *)attribute_cb;
	mfk_em_identify_cb = (void *)identification_cb;
	return mfk_node_obj;
}

attribute_t *attribute::create(cluster_t *cluster, uint32_t attribute_id, uint8_t flags,
			       esp_matter_attr_val_t val)
{
	(void)cluster;
	mfk_em_attr_creates++;
	mfk_em_attr_last_id = attribute_id;
	mfk_em_attr_last_flags = flags;
	mfk_em_attr_last_val = val.b8;
	return mfk_attr_obj;
}

namespace cluster {

cluster_t *create(endpoint_t *endpoint, uint32_t cluster_id, uint8_t flags)
{
	(void)endpoint;
	mfk_em_cluster_create_id = cluster_id;
	mfk_em_cluster_create_flags = flags;
	return mfk_em_cluster_create_null ? nullptr : mfk_cluster_obj;
}

cluster_t *get(endpoint_t *endpoint, uint32_t cluster_id)
{
	(void)endpoint;
	(void)cluster_id;
	return mfk_cluster_obj;
}

namespace global {
namespace attribute {
esp_matter::attribute_t *create_feature_map(cluster_t *cluster, uint32_t value)
{
	(void)cluster;
	mfk_em_fm_creates++;
	mfk_em_fm_val = value;
	return mfk_attr_obj;
}
esp_matter::attribute_t *create_cluster_revision(cluster_t *cluster, uint16_t value)
{
	(void)cluster;
	mfk_em_cr_creates++;
	mfk_em_cr_val = value;
	return mfk_attr_obj;
}
} // namespace attribute
} // namespace global

namespace door_lock {
namespace feature {
namespace credential_over_the_air_access {
esp_err_t add(cluster_t *cluster, config_t *config)
{
	(void)cluster;
	(void)config;
	mfk_em_feature_adds++;
	return ESP_OK;
}
} // namespace credential_over_the_air_access
namespace pin_credential {
esp_err_t add(cluster_t *cluster, config_t *config)
{
	(void)cluster;
	(void)config;
	mfk_em_feature_adds++;
	return ESP_OK;
}
} // namespace pin_credential
namespace user {
esp_err_t add(cluster_t *cluster, config_t *config)
{
	(void)cluster;
	(void)config;
	mfk_em_feature_adds++;
	return ESP_OK;
}
} // namespace user
namespace aliro_provisioning {
esp_err_t add(cluster_t *cluster)
{
	(void)cluster;
	mfk_em_ultrawidelock_prov_adds++;
	return ESP_OK;
}
} // namespace aliro_provisioning
namespace aliro_bleuwb {
esp_err_t add(cluster_t *cluster)
{
	(void)cluster;
	mfk_em_ultrawidelock_bleuwb_adds++;
	return ESP_OK;
}
} // namespace aliro_bleuwb
} // namespace feature
namespace attribute {
esp_matter::attribute_t *create_auto_relock_time(cluster_t *cluster, uint32_t value)
{
	(void)cluster;
	mfk_em_autorelock_creates++;
	mfk_em_autorelock_val = value;
	return mfk_attr_obj;
}
} // namespace attribute
} // namespace door_lock

} // namespace cluster

namespace endpoint {
namespace door_lock {
endpoint_t *create(node_t *node, config_t *config, uint8_t flags, void *priv_data)
{
	(void)node;
	(void)flags;
	(void)priv_data;
	mfk_em_delegate = config->door_lock.delegate;
	mfk_em_lock_state_init = config->door_lock.lock_state;
	return mfk_ep_obj;
}
} // namespace door_lock
uint16_t get_id(endpoint_t *endpoint)
{
	(void)endpoint;
	return mfk_em_endpoint_id;
}
} // namespace endpoint

esp_err_t start(event_callback_t callback)
{
	mfk_em_start_calls++;
	mfk_em_event_cb = callback;
	return ESP_OK;
}

void factory_reset()
{
	mfk_em_factory_resets++;
}

} // namespace esp_matter

/* ---- onboarding codes -------------------------------------------------------- */
int mfk_qr_fail;
int mfk_qr_url_fail;
int mfk_manual_fail;
int mfk_print_codes_calls;
int mfk_qr_calls;
int mfk_manual_calls;

void PrintOnboardingCodes(chip::RendezvousInformationFlags flags)
{
	(void)flags;
	mfk_print_codes_calls++;
}

CHIP_ERROR GetQRCode(chip::MutableCharSpan &out, chip::RendezvousInformationFlags flags)
{
	(void)flags;
	mfk_qr_calls++;
	if (mfk_qr_fail) {
		return CHIP_ERROR_INTERNAL;
	}
	const char *qr = "MT:FAKEQR";
	size_t n = strlen(qr);
	if (out.size() < n + 1) {
		return CHIP_ERROR_BUFFER_TOO_SMALL;
	}
	memcpy(out.data(), qr, n + 1);
	out.reduce_size(n);
	return CHIP_NO_ERROR;
}

CHIP_ERROR GetQRCodeUrl(char *url, size_t cap, chip::CharSpan qr)
{
	if (mfk_qr_url_fail) {
		return CHIP_ERROR_INTERNAL;
	}
	snprintf(url, cap, "https://fake/qr#%.*s", (int)qr.size(), qr.data());
	return CHIP_NO_ERROR;
}

CHIP_ERROR GetManualPairingCode(chip::MutableCharSpan &out,
				chip::RendezvousInformationFlags flags)
{
	(void)flags;
	mfk_manual_calls++;
	if (mfk_manual_fail) {
		return CHIP_ERROR_INTERNAL;
	}
	const char *code = "34970112332";
	size_t n = strlen(code);
	if (out.size() < n + 1) {
		return CHIP_ERROR_BUFFER_TOO_SMALL;
	}
	memcpy(out.data(), code, n + 1);
	out.reduce_size(n);
	return CHIP_NO_ERROR;
}

/* ---- console / linenoise / log / app desc ------------------------------------ */
struct mfk_console_cmd mfk_cmds[MFK_CMD_MAX];
int mfk_cmd_count;
int mfk_help_registered;
int mfk_repl_started;
struct esp_console_repl {
	int dummy;
};
static struct esp_console_repl mfk_repl_obj;

esp_err_t esp_console_new_repl_uart(const esp_console_dev_uart_config_t *dev,
				    const esp_console_repl_config_t *cfg,
				    esp_console_repl_t **out)
{
	(void)dev;
	(void)cfg;
	*out = &mfk_repl_obj;
	return ESP_OK;
}

esp_err_t esp_console_cmd_register(const esp_console_cmd_t *cmd)
{
	if (mfk_cmd_count < MFK_CMD_MAX) {
		mfk_cmds[mfk_cmd_count].command = cmd->command;
		mfk_cmds[mfk_cmd_count].help = cmd->help;
		mfk_cmds[mfk_cmd_count].hint = cmd->hint;
		mfk_cmds[mfk_cmd_count].func = cmd->func;
		mfk_cmd_count++;
	}
	return ESP_OK;
}

esp_err_t esp_console_register_help_command(void)
{
	mfk_help_registered++;
	return ESP_OK;
}

esp_err_t esp_console_start_repl(esp_console_repl_t *repl)
{
	(void)repl;
	mfk_repl_started++;
	return ESP_OK;
}

int (*mfk_cmd_lookup(const char *name))(int, char **)
{
	/* newest registration wins, like re-running app_shell_start would */
	for (int i = mfk_cmd_count - 1; i >= 0; i--) {
		if (strcmp(mfk_cmds[i].command, name) == 0) {
			return mfk_cmds[i].func;
		}
	}
	return NULL;
}

int mfk_linenoise_dumb;
int mfk_linenoise_clears;
int mfk_linenoise_multiline = -1;

int linenoiseIsDumbMode(void)
{
	return mfk_linenoise_dumb;
}

void linenoiseClearScreen(void)
{
	mfk_linenoise_clears++;
}

void linenoiseSetMultiLine(int ml)
{
	mfk_linenoise_multiline = ml;
}

void linenoiseSetHintsCallback(linenoiseHintsCallback *fn)
{
	(void)fn;
}

const char *mfk_log_last_tag;
int mfk_log_last_level = -1;
int mfk_log_set_calls;

void esp_log_level_set(const char *tag, esp_log_level_t level)
{
	mfk_log_set_calls++;
	mfk_log_last_tag = tag;
	mfk_log_last_level = (int)level;
}

static esp_app_desc_t mfk_app_desc = {"matter-lock", "v-test"};

const esp_app_desc_t *esp_app_get_description(void)
{
	return &mfk_app_desc;
}

const char *esp_get_idf_version(void)
{
	return "v0.0-fake";
}

esp_err_t nvs_flash_init(void)
{
	return ESP_OK;
}

esp_err_t nvs_flash_erase(void)
{
	return ESP_OK;
}

/* ---- freertos ------------------------------------------------------------------ */
struct mfk_task mfk_tasks[MFK_TASK_MAX];
int mfk_task_count;
int mfk_delay_calls;
void (*mfk_delay_hook)(void);
int mfk_notify_gives;
int mfk_isr_gives;
int mfk_in_isr;
int mfk_yield_calls;
unsigned mfk_stack_hwm = 4096;

struct mfk_wake_step mfk_wake_script[MFK_WAKE_MAX];
int mfk_wake_len;
int mfk_wake_idx;
static jmp_buf mfk_task_jmp;

int mfk_trusted_have;
int32_t mfk_trusted_cm;
uint32_t mfk_trusted_block;
/* Fail-open by default, matching the real gate: UNKNOWN permits. */
int mfk_may_predict = 1;
unsigned mfk_sat_init_calls;
unsigned mfk_sat_observe_calls;
unsigned mfk_sat_predict_asks;
void (*mfk_predict_hook)(void);
int32_t mfk_sat_last_mm;
uint32_t mfk_sat_last_block;
int64_t mfk_now_us;

BaseType_t xTaskCreate(void (*fn)(void *), const char *name, uint32_t stack, void *arg,
		       UBaseType_t prio, TaskHandle_t *out)
{
	if (mfk_task_count < MFK_TASK_MAX) {
		mfk_tasks[mfk_task_count].fn = fn;
		mfk_tasks[mfk_task_count].arg = arg;
		snprintf(mfk_tasks[mfk_task_count].name, sizeof(mfk_tasks[0].name), "%s", name);
		mfk_tasks[mfk_task_count].stack = stack;
		mfk_tasks[mfk_task_count].prio = prio;
		mfk_task_count++;
	}
	if (out != NULL) {
		*out = (TaskHandle_t)&mfk_task_count;
	}
	return pdPASS;
}

void vTaskDelay(TickType_t ticks)
{
	(void)ticks;
	mfk_delay_calls++;
	if (mfk_delay_hook != NULL) {
		mfk_delay_hook();
	}
}

uint32_t ulTaskNotifyTake(BaseType_t clear, TickType_t ticks)
{
	(void)clear;
	(void)ticks;
	if (mfk_wake_idx >= mfk_wake_len) {
		longjmp(mfk_task_jmp, 1); /* production task loops forever */
	}
	const struct mfk_wake_step *s = &mfk_wake_script[mfk_wake_idx++];
	mfk_trusted_have = s->trusted;
	mfk_trusted_cm = s->cm;
	mfk_now_us += s->advance_ms * 1000;
	mfk_session_active = s->session;
	return s->wake;
}

void mfk_task_run(void (*fn)(void *), void *arg)
{
	if (setjmp(mfk_task_jmp) == 0) {
		fn(arg);
	}
}

BaseType_t xTaskNotifyGive(TaskHandle_t task)
{
	(void)task;
	mfk_notify_gives++;
	return pdPASS;
}

void vTaskNotifyGiveFromISR(TaskHandle_t task, BaseType_t *woken)
{
	(void)task;
	mfk_isr_gives++;
	if (woken != NULL) {
		*woken = pdTRUE;
	}
}

UBaseType_t uxTaskGetStackHighWaterMark(TaskHandle_t task)
{
	(void)task;
	return mfk_stack_hwm;
}

int mfk_port_in_isr(void)
{
	return mfk_in_isr;
}

void mfk_port_yield_from_isr(BaseType_t woken)
{
	(void)woken;
	mfk_yield_calls++;
}

/* ---- NimBLE / time / sntp -------------------------------------------------------- */
int mfk_ble_synced;
int mfk_adv_active;

extern "C" int ble_hs_synced(void)
{
	return mfk_ble_synced;
}

extern "C" int ble_gap_adv_active(void)
{
	return mfk_adv_active;
}

extern "C" int64_t esp_timer_get_time(void)
{
	return mfk_now_us;
}

void (*mfk_sntp_cb)(struct timeval *);
int mfk_sntp_inits;

esp_err_t esp_netif_sntp_init(const esp_sntp_config_t *cfg)
{
	mfk_sntp_inits++;
	mfk_sntp_cb = cfg->sync_cb;
	return ESP_OK;
}

const char *esp_err_to_name(esp_err_t err)
{
	return err == ESP_OK ? "ESP_OK" : "ESP_ERR";
}

/* ---- LED / BSP -------------------------------------------------------------------- */
int mfk_led_new_rc;
int mfk_led_clears;
int mfk_led_refreshes;
int mfk_led_set_calls;
int mfk_led_gpio;
uint32_t mfk_led_last_index, mfk_led_r, mfk_led_g, mfk_led_b;
int mfk_bsp_button_calls;
static struct led_strip_t *mfk_led_obj = (struct led_strip_t *)&mfk_led_new_rc;

esp_err_t led_strip_new_rmt_device(const led_strip_config_t *led_config,
				   const led_strip_rmt_config_t *rmt_config,
				   led_strip_handle_t *ret_strip)
{
	mfk_led_gpio = led_config->strip_gpio_num;
	(void)rmt_config;
	if (mfk_led_new_rc != ESP_OK) {
		return mfk_led_new_rc;
	}
	*ret_strip = mfk_led_obj;
	return ESP_OK;
}

esp_err_t led_strip_clear(led_strip_handle_t strip)
{
	(void)strip;
	mfk_led_clears++;
	return ESP_OK;
}

esp_err_t led_strip_set_pixel(led_strip_handle_t strip, uint32_t index, uint32_t red,
			      uint32_t green, uint32_t blue)
{
	(void)strip;
	mfk_led_set_calls++;
	mfk_led_last_index = index;
	mfk_led_r = red;
	mfk_led_g = green;
	mfk_led_b = blue;
	return ESP_OK;
}

esp_err_t led_strip_refresh(led_strip_handle_t strip)
{
	(void)strip;
	mfk_led_refreshes++;
	return ESP_OK;
}

int mfk_btn_register_calls;
int mfk_btn_last_event = -1;
int mfk_btn_register_rc;
static button_cb_t mfk_btn_long_press_cb;
static void *mfk_btn_long_press_arg;

esp_err_t iot_button_register_cb(button_handle_t btn_handle, button_event_t event,
				 button_event_args_t *event_args, button_cb_t cb, void *usr_data)
{
	(void)event_args;
	mfk_btn_register_calls++;
	mfk_btn_last_event = (int)event;
	if (mfk_btn_register_rc != ESP_OK) {
		return mfk_btn_register_rc; /* nothing gets hung on the button */
	}
	if (event == BUTTON_LONG_PRESS_START) {
		mfk_btn_long_press_cb = cb;
		mfk_btn_long_press_arg = usr_data;
	}
	(void)btn_handle;
	return ESP_OK;
}

// Press and hold the board's button, from a test.
void mfk_btn_fire_long_press(void)
{
	if (mfk_btn_long_press_cb != nullptr) {
		mfk_btn_long_press_cb(nullptr, mfk_btn_long_press_arg);
	}
}

esp_err_t bsp_iot_button_create(button_handle_t btn_array[], int *btn_cnt, int btn_array_size)
{
	(void)btn_cnt;
	mfk_bsp_button_calls++;
	for (int i = 0; i < btn_array_size; i++) {
		btn_array[i] = (button_handle_t)&mfk_bsp_button_calls;
	}
	return ESP_OK;
}

/* ---- ultrawidelock reader / ble / lab / lat / uwb stubs ------------------------------------ */
int mfk_reader_start_calls;
int mfk_status_tick_calls;
int64_t mfk_status_tick_last_ms;
int mfk_reader_start_rc;
int mfk_ble_prepare_null;
int mfk_notify_unlock_calls;
int mfk_notify_unlock_last = -1;
int mfk_session_active;
int mfk_auth_cred_have;
uint8_t mfk_auth_cred[65];
int mfk_prov_print_calls;
int mfk_trust_last_rc;
int mfk_trust_clear_rc;
int mfk_prov_identity_calls;
uint8_t mfk_prov_reader_id[32];
uint8_t mfk_prov_sign[32];
uint8_t mfk_prov_grk[16];
int mfk_prov_identity_rc;
int mfk_add_trust_calls;
uint8_t mfk_add_trust_key[65];
int mfk_add_trust_rc;
uint8_t mfk_add_trust_type;
uint16_t mfk_add_trust_index;
uint16_t mfk_add_trust_user;
int mfk_remove_trust_calls;
uint8_t mfk_remove_trust_type;
uint16_t mfk_remove_trust_index;
int mfk_remove_trust_rc;
int mfk_add_issuer_calls;
uint8_t mfk_add_issuer_key[65];
uint16_t mfk_add_issuer_index;
uint16_t mfk_add_issuer_user;
int mfk_add_issuer_rc;
int mfk_remove_issuer_calls;
uint16_t mfk_remove_issuer_index;
int mfk_remove_issuer_rc;
void (*mfk_learned_listener)(uint8_t, uint16_t, uint16_t, const uint8_t *);
int mfk_remove_user_calls;
uint16_t mfk_remove_user_index;
int mfk_remove_user_rc;
int mfk_prov_clear_calls;
int mfk_refresh_adv_calls;
int mfk_ble_time_updated_calls;
int mfk_lab_on;
unsigned mfk_cir_probes;
int mfk_lab_evi_calls;
long mfk_lab_evi_last;
int mfk_lat_marks[32];
int mfk_lat_reports;
int mfk_last_have;
int32_t mfk_last_cm;
int64_t mfk_last_age_ms;
void (*mfk_range_listener)(void);

static struct ble_gatt_svc_def mfk_ultrawidelock_svc = {1};

extern "C" {

int ultrawidelock_reader_start_attached(void)
{
	mfk_reader_start_calls++;
	return mfk_reader_start_rc;
}

/* Released by the approach loop, not at startup: a held Wallet status only goes
 * out because this is called every pass, so the count is recorded rather than
 * swallowed and the wiring test can assert the loop really drives it. */
void ultrawidelock_reader_status_tick(int64_t now_ms)
{
	mfk_status_tick_calls++;
	mfk_status_tick_last_ms = now_ms;
}

const void *ultrawidelock_reader_ble_prepare(void)
{
	return mfk_ble_prepare_null ? NULL : (const void *)&mfk_ultrawidelock_svc;
}

void ultrawidelock_reader_refresh_adv(void)
{
	mfk_refresh_adv_calls++;
}

void ultrawidelock_reader_notify_unlock(bool unsecured)
{
	mfk_notify_unlock_calls++;
	mfk_notify_unlock_last = unsecured ? 1 : 0;
}

bool ultrawidelock_reader_session_active(void)
{
	return mfk_session_active != 0;
}

bool ultrawidelock_reader_authenticated_credential(uint8_t cred_pub[65])
{
	if (!mfk_auth_cred_have) {
		return false;
	}
	memcpy(cred_pub, mfk_auth_cred, 65);
	return true;
}

void ultrawidelock_reader_prov_print(void)
{
	mfk_prov_print_calls++;
}

int ultrawidelock_reader_trust_last(void)
{
	return mfk_trust_last_rc;
}

int ultrawidelock_reader_trust_clear(void)
{
	return mfk_trust_clear_rc;
}

int ultrawidelock_reader_provision_identity(const uint8_t reader_id[32], const uint8_t sign_priv[32],
				    const uint8_t group_resolving_key[16])
{
	mfk_prov_identity_calls++;
	memcpy(mfk_prov_reader_id, reader_id, 32);
	memcpy(mfk_prov_sign, sign_priv, 32);
	memcpy(mfk_prov_grk, group_resolving_key, 16);
	return mfk_prov_identity_rc;
}

int ultrawidelock_reader_provision_add_trust(const uint8_t cred_pub[65], uint8_t cred_type,
				     uint16_t cred_index, uint16_t user_index)
{
	mfk_add_trust_calls++;
	mfk_add_trust_type = cred_type;
	mfk_add_trust_index = cred_index;
	mfk_add_trust_user = user_index;
	memcpy(mfk_add_trust_key, cred_pub, 65);
	return mfk_add_trust_rc;
}

int ultrawidelock_reader_provision_remove_trust(uint8_t cred_type, uint16_t cred_index)
{
	mfk_remove_trust_calls++;
	mfk_remove_trust_type = cred_type;
	mfk_remove_trust_index = cred_index;
	return mfk_remove_trust_rc;
}

int ultrawidelock_reader_provision_remove_user(uint16_t user_index)
{
	mfk_remove_user_calls++;
	mfk_remove_user_index = user_index;
	return mfk_remove_user_rc;
}

int ultrawidelock_reader_provision_add_issuer(const uint8_t pub[65], uint16_t cred_index,
					      uint16_t user_index)
{
	mfk_add_issuer_calls++;
	mfk_add_issuer_index = cred_index;
	mfk_add_issuer_user = user_index;
	memcpy(mfk_add_issuer_key, pub, 65);
	return mfk_add_issuer_rc;
}

int ultrawidelock_reader_provision_remove_issuer(uint16_t cred_index)
{
	mfk_remove_issuer_calls++;
	mfk_remove_issuer_index = cred_index;
	return mfk_remove_issuer_rc;
}

void ultrawidelock_reader_set_credential_learned_listener(
	void (*cb)(uint8_t cred_type, uint16_t cred_index, uint16_t user_index,
		   const uint8_t cred_pub[65]))
{
	mfk_learned_listener = cb;
}

int ultrawidelock_reader_provision_clear(void)
{
	mfk_prov_clear_calls++;
	return 0;
}

void ultrawidelock_ble_time_updated(void)
{
	mfk_ble_time_updated_calls++;
}

void ultrawidelock_lab_set_enabled(bool on)
{
	mfk_lab_on = on ? 1 : 0;
}

bool ultrawidelock_lab_enabled(void)
{
	return mfk_lab_on != 0;
}

/* uwb_cirdiag doubles: app_shell's `lab`/`lab cir` command drives these; the
 * real latch/stream lives in the ultrawidelock_uwb driver, out of the matter-lock suite. */
static int mfk_cir_on;
static int mfk_cir_dump_on;

void uwb_cirdiag_set_enabled(bool on)
{
	mfk_cir_on = on ? 1 : 0;
}

bool uwb_cirdiag_enabled(void)
{
	return mfk_cir_on != 0;
}

void uwb_cirdiag_dump_set_enabled(bool on)
{
	if (on) {
		mfk_cir_on = 1;
	}
	mfk_cir_dump_on = on ? 1 : 0;
}

bool uwb_cirdiag_dump_enabled(void)
{
	return mfk_cir_dump_on != 0;
}

void uwb_cirdiag_probe(void)
{
	mfk_cir_probes++;
}

void ultrawidelock_lab_ev(const char *ev)
{
	(void)ev;
}

void ultrawidelock_lab_evi(const char *ev, const char *key, long val)
{
	(void)ev;
	(void)key;
	mfk_lab_evi_calls++;
	mfk_lab_evi_last = val;
}

void ultrawidelock_lab_dump(void)
{
}

int ultrawidelock_lat_mark(enum ultrawidelock_lat_phase phase)
{
	int first = mfk_lat_marks[(int)phase] == 0;
	mfk_lat_marks[(int)phase]++;
	return first;
}

void ultrawidelock_lat_begin(void)
{
}

void ultrawidelock_lat_report(void)
{
	mfk_lat_reports++;
}

bool ultrawidelock_uwb_last_range_cm(int32_t *cm_out)
{
	if (!mfk_last_have) {
		return false;
	}
	*cm_out = mfk_last_cm;
	return true;
}

bool ultrawidelock_uwb_last_range_age_cm(int32_t *cm_out, int64_t *age_ms_out)
{
	if (!ultrawidelock_uwb_last_range_cm(cm_out)) {
		return false;
	}
	if (age_ms_out != nullptr) {
		*age_ms_out = mfk_last_age_ms;
	}
	return true;
}

bool ultrawidelock_uwb_trusted_range_cm(int32_t *cm_out)
{
	if (!mfk_trusted_have) {
		return false;
	}
	*cm_out = mfk_trusted_cm;
	return true;
}

void ultrawidelock_uwb_set_range_listener(void (*cb)(void))
{
	mfk_range_listener = cb;
}

/*
 * The block a trusted range was measured in. Serves the same value as
 * ultrawidelock_uwb_trusted_range_cm plus a block number, because the
 * two-anchor gate cannot pair a distance whose round it does not know.
 */
bool ultrawidelock_uwb_trusted_range_block_cm(int32_t *cm_out, uint32_t *block_out)
{
	if (!mfk_trusted_have) {
		return false;
	}
	*cm_out = mfk_trusted_cm;
	*block_out = mfk_trusted_block;
	return true;
}

/* ---- the two-anchor gate (apps/esp32-matter-lock/main/sat_fusion.c) --------
 *
 * Stubbed rather than compiled: sat_fusion.c reaches for esp_console, NVS and
 * the ESP-NOW carrier, none of which exist here, and this suite exists to prove
 * app_main's BRANCH LOGIC. What matters to that is the one question app_main
 * asks -- may a passive unlock proceed -- so that answer is a knob and the rest
 * are recorders.
 *
 * mfk_may_predict defaults TRUE, which is the real gate's fail-open behaviour:
 * with no satellite, no report or a stale one the verdict is UNKNOWN and
 * UNKNOWN permits. A test that wants the veto sets it false.
 */
void sat_fusion_init(void)
{
	mfk_sat_init_calls++;
}

void sat_fusion_observe(int32_t self_mm, uint32_t self_block, int64_t now_ms)
{
	(void)now_ms;
	mfk_sat_observe_calls++;
	mfk_sat_last_mm = self_mm;
	mfk_sat_last_block = self_block;
}

bool sat_fusion_may_passive_unlock(int64_t now_ms)
{
	bool answer;

	(void)now_ms;
	mfk_sat_predict_asks++;
	answer = mfk_may_predict;
	/* Fires AFTER the answer is taken, so a hook that flips mfk_may_predict
	 * changes the NEXT ask and not this one -- which is what lets a test say
	 * "refuse once, then relent". The reader task's wake loop blocks in
	 * ulTaskNotifyTake, not vTaskDelay, so mfk_delay_hook cannot do this. */
	if (mfk_predict_hook != NULL) {
		mfk_predict_hook();
	}
	return answer;
}

volatile int ultrawidelock_uwb_diag_on = ULTRAWIDELOCK_UWB_DIAG_DEFAULT;

} /* extern "C" */

/* ---- reset -------------------------------------------------------------------- */
void mfk_reset(void)
{
	mfk_dls_init_server_calls = 0;
	mfk_dls_set_lock_calls = 0;
	mfk_dls_last_ep = 0;
	mfk_dls_last_state = -1;
	mfk_dls_last_source = -1;
	mfk_dls_last_user_null = 1;
	mfk_dls_last_user = 0;
	mfk_dls_unlock_user_null = -1;
	mfk_dls_unlock_user = 0;
	mfk_dls_lock_user_null = -1;
	mfk_dls_lock_user = 0;
	mfk_dls_creds_ok = 1;
	mfk_dls_creds_val = 10;
	mfk_dls_users_ok = 1;
	mfk_dls_users_val = 10;
	mfk_attr_lockstate_null = 0;
	mfk_attr_lockstate_val = (int)DlLockState::kLocked;
	mfk_attr_featuremap = 0;
	mfk_attr_requirepin_ok = 1;
	mfk_attr_requirepin_val = 0;
	mfk_fabric_count = 0;
	mfk_cw_is_open = 0;
	mfk_cw_open_calls = 0;
	mfk_cw_open_rc = 0;
	mfk_cw_last_timeout = 0;
	mfk_cw_last_adv = -1;
	mfk_cw_close_calls = 0;
	mfk_btn_register_calls = 0;
	mfk_btn_last_event = -1;
	mfk_btn_register_rc = ESP_OK;
	mfk_sched_calls = 0;
	mfk_sched_rc = 0;
	mfk_lockstack_calls = 0;
	mfk_unlockstack_calls = 0;
	mfk_blemgr_calls = 0;
	mfk_blemgr_nsvcs = 0;
	mfk_blemgr_rc = 0;
	mfk_drbg_calls = 0;
	mfk_drbg_fail = 0;
	mfk_em_node_creates = 0;
	mfk_em_delegate = NULL;
	mfk_em_lock_state_init = 0;
	mfk_em_feature_adds = 0;
	mfk_em_ultrawidelock_prov_adds = 0;
	mfk_em_ultrawidelock_bleuwb_adds = 0;
	mfk_em_cluster_create_null = 0;
	mfk_em_cluster_create_id = 0;
	mfk_em_attr_creates = 0;
	mfk_em_fm_creates = 0;
	mfk_em_cr_creates = 0;
	mfk_em_autorelock_creates = 0;
	mfk_em_start_calls = 0;
	mfk_em_factory_resets = 0;
	mfk_cmd_count = 0;
	mfk_help_registered = 0;
	mfk_repl_started = 0;
	mfk_linenoise_dumb = 0;
	mfk_linenoise_clears = 0;
	mfk_linenoise_multiline = -1;
	mfk_log_last_tag = NULL;
	mfk_log_last_level = -1;
	mfk_log_set_calls = 0;
	mfk_stack_hwm = 4096;
	mfk_qr_fail = 0;
	mfk_qr_url_fail = 0;
	mfk_manual_fail = 0;
	mfk_print_codes_calls = 0;
	mfk_qr_calls = 0;
	mfk_manual_calls = 0;
	mfk_task_count = 0;
	mfk_delay_calls = 0;
	mfk_delay_hook = NULL;
	mfk_notify_gives = 0;
	mfk_isr_gives = 0;
	mfk_in_isr = 0;
	mfk_yield_calls = 0;
	mfk_wake_len = 0;
	mfk_wake_idx = 0;
	mfk_ble_synced = 0;
	mfk_adv_active = 0;
	mfk_sntp_inits = 0;
	mfk_led_new_rc = 0;
	mfk_led_clears = 0;
	mfk_led_refreshes = 0;
	mfk_led_set_calls = 0;
	mfk_led_gpio = -1;
	mfk_bsp_button_calls = 0;
	mfk_reader_start_calls = 0;
	mfk_reader_start_rc = 0;
	mfk_status_tick_calls = 0;
	mfk_status_tick_last_ms = 0;
	mfk_ble_prepare_null = 0;
	mfk_notify_unlock_calls = 0;
	mfk_notify_unlock_last = -1;
	mfk_auth_cred_have = 0;
	mfk_prov_print_calls = 0;
	mfk_trust_last_rc = 0;
	mfk_trust_clear_rc = 0;
	mfk_prov_identity_calls = 0;
	mfk_prov_identity_rc = 0;
	mfk_add_trust_calls = 0;
	mfk_add_trust_rc = 0;
	mfk_add_trust_type = 0;
	mfk_add_trust_index = 0;
	mfk_add_trust_user = 0;
	memset(mfk_add_trust_key, 0, sizeof(mfk_add_trust_key));
	/* The revocation half, so a section that forced a failing removal cannot
	 * leave the next one refusing for a reason it never set. */
	mfk_remove_trust_calls = 0;
	mfk_add_issuer_calls = 0;
	mfk_add_issuer_rc = 0;
	mfk_remove_issuer_calls = 0;
	mfk_remove_issuer_rc = 0;
	mfk_learned_listener = NULL;
	mfk_remove_trust_type = 0;
	mfk_remove_trust_index = 0;
	mfk_remove_trust_rc = 0;
	mfk_remove_user_calls = 0;
	mfk_remove_user_index = 0;
	mfk_remove_user_rc = 0;
	mfk_prov_clear_calls = 0;
	mfk_refresh_adv_calls = 0;
	mfk_ble_time_updated_calls = 0;
	mfk_lab_evi_calls = 0;
	memset(mfk_lat_marks, 0, sizeof(mfk_lat_marks));
	mfk_lat_reports = 0;
	mfk_last_have = 0;
	mfk_last_age_ms = 0;
	mfk_trusted_have = 0;
	mfk_trusted_block = 0;
	/* Back to permitting: a test that vetoed must not leave the next one
	 * silently unable to unlock. */
	mfk_may_predict = 1;
	mfk_sat_init_calls = 0;
	mfk_sat_observe_calls = 0;
	mfk_sat_predict_asks = 0;
	mfk_predict_hook = NULL;
	mfk_sat_last_mm = 0;
	mfk_sat_last_block = 0;
}
