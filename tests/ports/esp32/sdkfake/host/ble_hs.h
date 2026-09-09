/* sdkfake host/ble_hs.h — the slice of the NimBLE host API ultrawidelock_ble.c uses,
 * as recording doubles (fake_nimble.c). Types carry only the fields touched. */
#ifndef SDKFAKE_HOST_BLE_HS_H
#define SDKFAKE_HOST_BLE_HS_H

#include "../sdkfake.h"

/* ---- errors / constants ---- */
#define BLE_HS_ENOMEM   6
#define BLE_HS_ENOTCONN 7
#define BLE_HS_ESTALLED 25
/* HCI reason code the RSSI power gate passes to ble_gap_terminate on a departed peer. */
#define BLE_ERR_REM_USER_CONN_TERM 0x13
#define BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN 0x0D
#define BLE_ATT_ERR_UNLIKELY               0x0E
#define BLE_ATT_ERR_INSUFFICIENT_RES       0x11
#define BLE_HS_FOREVER 0x7fffffff

#define BLE_OWN_ADDR_PUBLIC 0
#define BLE_OWN_ADDR_RANDOM 1
#define BLE_ADDR_PUBLIC 0
#define BLE_ADDR_RANDOM 1

/* ---- UUIDs ---- */
typedef struct {
	uint8_t type;
} ble_uuid_t;

typedef struct {
	ble_uuid_t u;
	uint16_t value;
} ble_uuid16_t;
#define BLE_UUID16_INIT(v) {.u = {16}, .value = (v)}

typedef struct {
	ble_uuid_t u;
	uint8_t value[16];
} ble_uuid128_t;
#define BLE_UUID128_INIT(...) {.u = {128}, .value = {__VA_ARGS__}}

/* ---- mbufs / mempools ---- */
typedef uint32_t os_membuf_t;
#define OS_MEMPOOL_SIZE(n, sz) (((n) * (sz) + 3) / 4)

struct os_mempool {
	int inited;
};
struct os_mbuf_pool {
	int inited;
};
struct os_mbuf {
	uint8_t data[600];
	uint16_t len;
	int freed;
};

int os_mempool_init(struct os_mempool *mp, uint16_t n, uint32_t sz, void *mem, const char *name);
int os_mbuf_pool_init(struct os_mbuf_pool *pool, struct os_mempool *mp, uint16_t sz, uint16_t n);
struct os_mbuf *os_mbuf_get_pkthdr(struct os_mbuf_pool *pool, uint16_t hdr);
int os_mbuf_append(struct os_mbuf *om, const void *data, uint16_t len);
int os_mbuf_free_chain(struct os_mbuf *om);
int ble_hs_mbuf_to_flat(const struct os_mbuf *om, void *buf, uint16_t cap, uint16_t *out_len);

/* ---- GATT ---- */
struct ble_gatt_access_ctxt {
	uint8_t op;
	struct os_mbuf *om;
};
#define BLE_GATT_ACCESS_OP_WRITE_CHR 1
typedef int (*ble_gatt_access_fn)(uint16_t conn_handle, uint16_t attr_handle,
				  struct ble_gatt_access_ctxt *ctxt, void *arg);

#define BLE_GATT_SVC_TYPE_PRIMARY 1
#define BLE_GATT_CHR_F_READ  0x0002
#define BLE_GATT_CHR_F_WRITE 0x0008
#define BLE_GATT_CHR_F_WRITE_NO_RSP 0x0004
#define BLE_GATT_CHR_F_NOTIFY 0x0010

struct ble_gatt_chr_def {
	const ble_uuid_t *uuid;
	ble_gatt_access_fn access_cb;
	uint16_t flags;
	uint16_t *val_handle;
};
struct ble_gatt_svc_def {
	uint8_t type;
	const ble_uuid_t *uuid;
	const struct ble_gatt_chr_def *characteristics;
};

int ble_gatts_count_cfg(const struct ble_gatt_svc_def *svcs);
int ble_gatts_add_svcs(const struct ble_gatt_svc_def *svcs);
int ble_gatts_notify_custom(uint16_t conn_handle, uint16_t chr_val_handle, struct os_mbuf *om);
struct os_mbuf *ble_hs_mbuf_from_flat(const void *buf, uint16_t len);

/* ---- GAP ---- */
#define BLE_GAP_EVENT_CONNECT      0
#define BLE_GAP_EVENT_DISCONNECT   1
#define BLE_GAP_EVENT_CONN_UPDATE  3
#define BLE_GAP_EVENT_ADV_COMPLETE 9

struct ble_gap_event {
	uint8_t type;
	union {
		struct {
			int status;
			uint16_t conn_handle;
		} connect;
		struct {
			int reason;
			/* NimBLE carries the full ble_gap_conn_desc here; the transport
			 * reads only the handle. */
			struct {
				uint16_t conn_handle;
			} conn;
		} disconnect;
		struct {
			int status;
			uint16_t conn_handle;
		} conn_update;
	};
};

struct ble_gap_conn_desc {
	uint16_t conn_itvl;
	uint16_t conn_latency;
	uint16_t supervision_timeout;
};

struct ble_gap_upd_params {
	uint16_t itvl_min;
	uint16_t itvl_max;
	uint16_t latency;
	uint16_t supervision_timeout;
};

struct ble_hs_adv_fields {
	uint8_t flags;
	const uint8_t *svc_data_uuid16;
	uint8_t svc_data_uuid16_len;
	const ble_uuid16_t *uuids16;
	uint8_t num_uuids16;
	unsigned uuids16_is_complete : 1;
	const uint8_t *name;
	uint8_t name_len;
	unsigned name_is_complete : 1;
};
#define BLE_HS_ADV_F_DISC_GEN    0x02
#define BLE_HS_ADV_F_BREDR_UNSUP 0x04

struct ble_gap_adv_params {
	uint8_t conn_mode;
	uint8_t disc_mode;
};
#define BLE_GAP_CONN_MODE_UND 2
#define BLE_GAP_DISC_MODE_GEN 2

typedef int (*ble_gap_event_fn)(struct ble_gap_event *event, void *arg);

int ble_gap_adv_set_fields(const struct ble_hs_adv_fields *fields);
int ble_gap_adv_start(uint8_t own_addr_type, const void *peer, int32_t duration_ms,
		      const struct ble_gap_adv_params *params, ble_gap_event_fn cb, void *arg);
int ble_gap_adv_stop(void);
int ble_gap_adv_active(void);
int ble_gap_update_params(uint16_t conn_handle, const struct ble_gap_upd_params *params);
int ble_gap_conn_find(uint16_t conn_handle, struct ble_gap_conn_desc *out);
int ble_gap_conn_rssi(uint16_t conn_handle, int8_t *out_rssi);
int ble_gap_terminate(uint16_t conn_handle, uint8_t reason);

/* GAP listeners live in ble_gap_vars, which ESP-IDF's NimBLE (BLE_STATIC_TO_DYNAMIC,
 * default y) allocates in ble_gap_init(): registering one before the host is up
 * is a NULL dereference on the target. The fake counts those instead of crashing. */
struct ble_gap_event_listener {
	ble_gap_event_fn fn;
	void *arg;
};
int ble_gap_event_listener_register(struct ble_gap_event_listener *listener,
				    ble_gap_event_fn fn, void *arg);

/* ---- host config / npl ---- */
struct ble_hs_cfg_s {
	void (*sync_cb)(void);
	void (*reset_cb)(int reason);
};
extern struct ble_hs_cfg_s ble_hs_cfg;

struct ble_npl_event {
	void (*fn)(struct ble_npl_event *ev);
	void *arg;
};
struct ble_npl_eventq {
	int dummy;
};
struct ble_npl_callout {
	struct ble_npl_event ev;
	uint32_t armed_ticks;
	int armed;
};

void ble_npl_event_init(struct ble_npl_event *ev, void (*fn)(struct ble_npl_event *), void *arg);
void *ble_npl_event_get_arg(struct ble_npl_event *ev);
void ble_npl_eventq_put(struct ble_npl_eventq *q, struct ble_npl_event *ev);
void ble_npl_callout_init(struct ble_npl_callout *co, struct ble_npl_eventq *q,
			  void (*fn)(struct ble_npl_event *), void *arg);
void ble_npl_callout_reset(struct ble_npl_callout *co, uint32_t ticks);
void ble_npl_callout_stop(struct ble_npl_callout *co);
uint32_t ble_npl_time_ms_to_ticks32(uint32_t ms);

/* ---- fake_nimble.c control surface ---- */
extern int fake_hs_mbuf_to_flat_rc;   /* forced rc (0 = normal copy) */
extern int fake_mbuf_append_rc;       /* forced rc for os_mbuf_append */
extern int fake_mbuf_alloc_fail;      /* os_mbuf_get_pkthdr returns NULL */
extern int fake_mbuf_frees;           /* os_mbuf_free_chain count */
extern int fake_gatts_count_rc, fake_gatts_add_rc;
extern int fake_gap_adv_set_fields_rc, fake_gap_adv_start_rc;
extern int fake_gap_adv_active_val;
extern int fake_gap_adv_stops, fake_gap_adv_starts;
extern struct ble_hs_adv_fields fake_gap_adv_fields; /* last set_fields copy */
extern uint8_t fake_gap_adv_svc_data[64];            /* deep copy of svc data  */
extern uint8_t fake_gap_adv_name[32];
extern struct ble_gap_adv_params fake_gap_adv_params;
extern ble_gap_event_fn fake_gap_event_cb;
extern void *fake_gap_event_arg;
extern int fake_gap_update_rc;
extern int fake_gap_update_calls;
extern struct ble_gap_upd_params fake_gap_update_params;
extern int fake_gap_conn_find_rc;
extern struct ble_gap_conn_desc fake_gap_conn_desc; /* what conn_find returns */
extern int fake_gap_rssi_rc;                        /* ble_gap_conn_rssi return */
extern int8_t fake_gap_rssi_value;                  /* dBm it hands back */
extern int fake_gap_terminate_rc;                   /* ble_gap_terminate return */
extern int fake_gap_terminate_calls;
extern uint16_t fake_gap_terminate_conn;
extern uint8_t fake_gap_terminate_reason;
extern struct ble_npl_event *fake_eventq[16];       /* posted events, FIFO */
extern int fake_eventq_count;
extern struct ble_npl_callout *fake_last_callout;   /* last init'd/reset */
extern int fake_host_inited;                        /* nimble_port_init() ran */
extern int fake_gap_listener_early;                 /* registered before it: target NULL deref */
extern struct ble_gap_event_listener *fake_gap_listener; /* last registered, or NULL */
extern int fake_gatts_notify_calls;
extern uint16_t fake_gatts_notify_handle;
extern uint8_t fake_gatts_notify_data[64];
extern uint16_t fake_gatts_notify_len;
void fake_nimble_drain_eventq(void);                /* run + clear posted events */
void fake_nimble_reset(void);

#endif
