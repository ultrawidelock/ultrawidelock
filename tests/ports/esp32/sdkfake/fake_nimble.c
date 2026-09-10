/*
 * fake_nimble — recording doubles of the NimBLE host slice ultrawidelock_ble.c uses.
 * Every entry point records its arguments (advert fields get a deep copy) and
 * returns a test-settable rc. Callouts and posted events are captured so the
 * test can run them synchronously ("host task" pump). No radio, no timing:
 * this proves ultrawidelock_ble.c's branch logic and wiring only.
 */
#include <string.h>

#include "host/ble_hs.h"
#include "host/ble_hs_id.h"
#include "host/ble_l2cap.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

struct ble_hs_cfg_s ble_hs_cfg;

int fake_hs_mbuf_to_flat_rc;
int fake_mbuf_append_rc;
int fake_mbuf_alloc_fail;
int fake_mbuf_frees;
int fake_gatts_count_rc, fake_gatts_add_rc;
int fake_gap_adv_set_fields_rc, fake_gap_adv_start_rc;
int fake_gap_adv_active_val;
int fake_gap_adv_stops, fake_gap_adv_starts;
struct ble_hs_adv_fields fake_gap_adv_fields;
uint8_t fake_gap_adv_svc_data[64];
uint8_t fake_gap_adv_name[32];
struct ble_gap_adv_params fake_gap_adv_params;
ble_gap_event_fn fake_gap_event_cb;
void *fake_gap_event_arg;
int fake_gap_update_rc;
int fake_gap_update_calls;
struct ble_gap_upd_params fake_gap_update_params;
int fake_gap_conn_find_rc;
struct ble_gap_conn_desc fake_gap_conn_desc;
int fake_gap_rssi_rc;
int8_t fake_gap_rssi_value;
int fake_gap_terminate_rc;
int fake_gap_terminate_calls;
uint16_t fake_gap_terminate_conn;
uint8_t fake_gap_terminate_reason;
struct ble_npl_event *fake_eventq[16];
int fake_eventq_count;
struct ble_npl_callout *fake_last_callout;
int fake_host_inited;
int fake_gap_listener_early;
struct ble_gap_event_listener *fake_gap_listener;
int fake_gatts_notify_calls;
uint16_t fake_gatts_notify_handle;
uint8_t fake_gatts_notify_data[64];
uint16_t fake_gatts_notify_len;

int fake_l2cap_create_server_rc;
uint16_t fake_l2cap_server_psm, fake_l2cap_server_mtu;
ble_l2cap_event_fn fake_l2cap_event_cb;
void *fake_l2cap_event_arg;
int fake_l2cap_recv_ready_calls;
struct os_mbuf *fake_l2cap_last_rx_sdu;
int fake_l2cap_send_rc;
uint8_t fake_l2cap_sent[600];
size_t fake_l2cap_sent_len;
int fake_l2cap_send_calls;

int fake_hs_id_infer_rc;
uint8_t fake_hs_id_own_addr_type;
int fake_hs_id_copy_rc;
uint8_t fake_hs_id_addr[6];
int fake_hs_util_ensure_addr_rc;

esp_err_t fake_nimble_port_init_rc;
int fake_nimble_port_runs;
void (*fake_nimble_host_task)(void *);
int fake_nimble_freertos_deinits;

int fake_svc_gap_name_set_rc;
char fake_svc_gap_name[32] = "fake";

static struct os_mbuf s_mbufs[16];
static int s_mbuf_next;
static struct ble_npl_eventq s_dflt_eventq;

void fake_nimble_reset(void)
{
	fake_hs_mbuf_to_flat_rc = 0;
	fake_mbuf_append_rc = 0;
	fake_mbuf_alloc_fail = 0;
	fake_mbuf_frees = 0;
	fake_gatts_count_rc = 0;
	fake_gatts_add_rc = 0;
	fake_gap_adv_set_fields_rc = 0;
	fake_gap_adv_start_rc = 0;
	fake_gap_adv_active_val = 0;
	fake_gap_adv_stops = 0;
	fake_gap_adv_starts = 0;
	memset(&fake_gap_adv_fields, 0, sizeof(fake_gap_adv_fields));
	memset(fake_gap_adv_svc_data, 0, sizeof(fake_gap_adv_svc_data));
	memset(fake_gap_adv_name, 0, sizeof(fake_gap_adv_name));
	memset(&fake_gap_adv_params, 0, sizeof(fake_gap_adv_params));
	fake_gap_event_cb = NULL;
	fake_gap_event_arg = NULL;
	fake_gap_update_rc = 0;
	fake_gap_update_calls = 0;
	memset(&fake_gap_update_params, 0, sizeof(fake_gap_update_params));
	fake_gap_conn_find_rc = 0;
	memset(&fake_gap_conn_desc, 0, sizeof(fake_gap_conn_desc));
	fake_gap_rssi_rc = 0;
	fake_gap_rssi_value = -60;
	fake_gap_terminate_rc = 0;
	fake_gap_terminate_calls = 0;
	fake_gap_terminate_conn = 0;
	fake_gap_terminate_reason = 0;
	memset(fake_eventq, 0, sizeof(fake_eventq));
	fake_eventq_count = 0;
	fake_last_callout = NULL;
	fake_host_inited = 0;
	fake_gap_listener_early = 0;
	fake_gap_listener = NULL;
	fake_gatts_notify_calls = 0;
	fake_gatts_notify_handle = 0;
	memset(fake_gatts_notify_data, 0, sizeof(fake_gatts_notify_data));
	fake_gatts_notify_len = 0;
	fake_l2cap_create_server_rc = 0;
	fake_l2cap_server_psm = 0;
	fake_l2cap_server_mtu = 0;
	fake_l2cap_event_cb = NULL;
	fake_l2cap_event_arg = NULL;
	fake_l2cap_recv_ready_calls = 0;
	fake_l2cap_last_rx_sdu = NULL;
	fake_l2cap_send_rc = 0;
	memset(fake_l2cap_sent, 0, sizeof(fake_l2cap_sent));
	fake_l2cap_sent_len = 0;
	fake_l2cap_send_calls = 0;
	fake_hs_id_infer_rc = 0;
	fake_hs_id_own_addr_type = BLE_OWN_ADDR_PUBLIC;
	fake_hs_id_copy_rc = 0;
	fake_hs_util_ensure_addr_rc = 0;
	fake_nimble_port_init_rc = ESP_OK;
	fake_nimble_port_runs = 0;
	fake_nimble_host_task = NULL;
	fake_nimble_freertos_deinits = 0;
	fake_svc_gap_name_set_rc = 0;
	memset(s_mbufs, 0, sizeof(s_mbufs));
	s_mbuf_next = 0;
}

/* ---- mbufs ---- */

int os_mempool_init(struct os_mempool *mp, uint16_t n, uint32_t sz, void *mem, const char *name)
{
	(void)n;
	(void)sz;
	(void)mem;
	(void)name;
	mp->inited = 1;
	return 0;
}

int os_mbuf_pool_init(struct os_mbuf_pool *pool, struct os_mempool *mp, uint16_t sz, uint16_t n)
{
	(void)mp;
	(void)sz;
	(void)n;
	pool->inited = 1;
	return 0;
}

struct os_mbuf *os_mbuf_get_pkthdr(struct os_mbuf_pool *pool, uint16_t hdr)
{
	(void)pool;
	(void)hdr;
	if (fake_mbuf_alloc_fail) {
		return NULL;
	}

	struct os_mbuf *om = &s_mbufs[s_mbuf_next];

	s_mbuf_next = (s_mbuf_next + 1) % (int)(sizeof(s_mbufs) / sizeof(s_mbufs[0]));
	memset(om, 0, sizeof(*om));
	return om;
}

int os_mbuf_append(struct os_mbuf *om, const void *data, uint16_t len)
{
	if (fake_mbuf_append_rc != 0) {
		return fake_mbuf_append_rc;
	}
	if ((size_t)om->len + len > sizeof(om->data)) {
		return BLE_HS_ENOMEM;
	}
	memcpy(om->data + om->len, data, len);
	om->len = (uint16_t)(om->len + len);
	return 0;
}

int os_mbuf_free_chain(struct os_mbuf *om)
{
	om->freed = 1;
	fake_mbuf_frees++;
	return 0;
}

int ble_hs_mbuf_to_flat(const struct os_mbuf *om, void *buf, uint16_t cap, uint16_t *out_len)
{
	if (fake_hs_mbuf_to_flat_rc != 0) {
		return fake_hs_mbuf_to_flat_rc;
	}
	if (om->len > cap) {
		return BLE_HS_ENOMEM;
	}
	memcpy(buf, om->data, om->len);
	*out_len = om->len;
	return 0;
}

/* ---- GATT ---- */

int ble_gatts_count_cfg(const struct ble_gatt_svc_def *svcs)
{
	(void)svcs;
	return fake_gatts_count_rc;
}

int ble_gatts_add_svcs(const struct ble_gatt_svc_def *svcs)
{
	(void)svcs;
	return fake_gatts_add_rc;
}

/* ---- GAP ---- */

int ble_gatts_notify_custom(uint16_t conn_handle, uint16_t chr_val_handle, struct os_mbuf *om)
{
	(void)conn_handle;
	fake_gatts_notify_calls++;
	fake_gatts_notify_handle = chr_val_handle;
	fake_gatts_notify_len = om->len < sizeof(fake_gatts_notify_data) ? om->len
								       : sizeof(fake_gatts_notify_data);
	memcpy(fake_gatts_notify_data, om->data, fake_gatts_notify_len);
	om->freed = 1; /* NimBLE consumes the mbuf either way */
	return 0;
}

struct os_mbuf *ble_hs_mbuf_from_flat(const void *buf, uint16_t len)
{
	struct os_mbuf *om = os_mbuf_get_pkthdr(NULL, 0);

	if (om == NULL || os_mbuf_append(om, buf, len) != 0) {
		return NULL;
	}
	return om;
}

int ble_gap_event_listener_register(struct ble_gap_event_listener *listener,
				    ble_gap_event_fn fn, void *arg)
{
	if (!fake_host_inited) {
		fake_gap_listener_early++;
	}
	listener->fn = fn;
	listener->arg = arg;
	fake_gap_listener = listener;
	return 0;
}

int ble_gap_adv_set_fields(const struct ble_hs_adv_fields *fields)
{
	fake_gap_adv_fields = *fields;
	if (fields->svc_data_uuid16 != NULL &&
	    fields->svc_data_uuid16_len <= sizeof(fake_gap_adv_svc_data)) {
		memcpy(fake_gap_adv_svc_data, fields->svc_data_uuid16, fields->svc_data_uuid16_len);
	}
	if (fields->name != NULL && fields->name_len < sizeof(fake_gap_adv_name)) {
		memcpy(fake_gap_adv_name, fields->name, fields->name_len);
		fake_gap_adv_name[fields->name_len] = 0;
	}
	return fake_gap_adv_set_fields_rc;
}

int ble_gap_adv_start(uint8_t own_addr_type, const void *peer, int32_t duration_ms,
		      const struct ble_gap_adv_params *params, ble_gap_event_fn cb, void *arg)
{
	(void)own_addr_type;
	(void)peer;
	(void)duration_ms;
	fake_gap_adv_params = *params;
	fake_gap_event_cb = cb;
	fake_gap_event_arg = arg;
	fake_gap_adv_starts++;
	if (fake_gap_adv_start_rc == 0) {
		fake_gap_adv_active_val = 1;
	}
	return fake_gap_adv_start_rc;
}

int ble_gap_adv_stop(void)
{
	fake_gap_adv_stops++;
	fake_gap_adv_active_val = 0;
	return 0;
}

int ble_gap_adv_active(void)
{
	return fake_gap_adv_active_val;
}

int ble_gap_update_params(uint16_t conn_handle, const struct ble_gap_upd_params *params)
{
	(void)conn_handle;
	fake_gap_update_calls++;
	fake_gap_update_params = *params;
	return fake_gap_update_rc;
}

int ble_gap_conn_find(uint16_t conn_handle, struct ble_gap_conn_desc *out)
{
	(void)conn_handle;
	if (fake_gap_conn_find_rc != 0) {
		return fake_gap_conn_find_rc;
	}
	*out = fake_gap_conn_desc;
	return 0;
}

int ble_gap_conn_rssi(uint16_t conn_handle, int8_t *out_rssi)
{
	(void)conn_handle;
	if (fake_gap_rssi_rc != 0) {
		return fake_gap_rssi_rc;
	}
	*out_rssi = fake_gap_rssi_value;
	return 0;
}

int ble_gap_terminate(uint16_t conn_handle, uint8_t reason)
{
	fake_gap_terminate_calls++;
	fake_gap_terminate_conn = conn_handle;
	fake_gap_terminate_reason = reason;
	return fake_gap_terminate_rc;
}

/* ---- npl events / callouts ---- */

void ble_npl_event_init(struct ble_npl_event *ev, void (*fn)(struct ble_npl_event *), void *arg)
{
	ev->fn = fn;
	ev->arg = arg;
}

void ble_npl_eventq_put(struct ble_npl_eventq *q, struct ble_npl_event *ev)
{
	(void)q;
	if (fake_eventq_count < (int)(sizeof(fake_eventq) / sizeof(fake_eventq[0]))) {
		fake_eventq[fake_eventq_count++] = ev;
	}
}

void fake_nimble_drain_eventq(void)
{
	int n = fake_eventq_count;

	fake_eventq_count = 0;
	for (int i = 0; i < n; i++) {
		fake_eventq[i]->fn(fake_eventq[i]);
	}
}

void ble_npl_callout_init(struct ble_npl_callout *co, struct ble_npl_eventq *q,
			  void (*fn)(struct ble_npl_event *), void *arg)
{
	(void)q;
	co->ev.fn = fn;
	co->ev.arg = arg;
	co->armed = 0;
	fake_last_callout = co;
}

void *ble_npl_event_get_arg(struct ble_npl_event *ev)
{
	return ev->arg;
}

void ble_npl_callout_reset(struct ble_npl_callout *co, uint32_t ticks)
{
	co->armed = 1;
	co->armed_ticks = ticks;
	fake_last_callout = co;
}

void ble_npl_callout_stop(struct ble_npl_callout *co)
{
	co->armed = 0;
}

uint32_t ble_npl_time_ms_to_ticks32(uint32_t ms)
{
	return ms;
}

/* ---- L2CAP ---- */

int ble_l2cap_create_server(uint16_t psm, uint16_t mtu, ble_l2cap_event_fn cb, void *arg)
{
	fake_l2cap_server_psm = psm;
	fake_l2cap_server_mtu = mtu;
	fake_l2cap_event_cb = cb;
	fake_l2cap_event_arg = arg;
	return fake_l2cap_create_server_rc;
}

int ble_l2cap_recv_ready(struct ble_l2cap_chan *chan, struct os_mbuf *sdu_rx)
{
	(void)chan;
	fake_l2cap_recv_ready_calls++;
	fake_l2cap_last_rx_sdu = sdu_rx;
	return 0;
}

int ble_l2cap_send(struct ble_l2cap_chan *chan, struct os_mbuf *sdu_tx)
{
	(void)chan;
	fake_l2cap_send_calls++;
	if (sdu_tx->len <= sizeof(fake_l2cap_sent)) {
		memcpy(fake_l2cap_sent, sdu_tx->data, sdu_tx->len);
		fake_l2cap_sent_len = sdu_tx->len;
	}
	return fake_l2cap_send_rc;
}

/* ---- id / util / services / port ---- */

int ble_hs_id_infer_auto(int privacy, uint8_t *own_addr_type)
{
	(void)privacy;
	if (fake_hs_id_infer_rc == 0) {
		*own_addr_type = fake_hs_id_own_addr_type;
	}
	return fake_hs_id_infer_rc;
}

int ble_hs_id_copy_addr(uint8_t addr_type, uint8_t *out, int *num)
{
	(void)addr_type;
	(void)num;
	if (fake_hs_id_copy_rc == 0) {
		memcpy(out, fake_hs_id_addr, 6);
	}
	return fake_hs_id_copy_rc;
}

int ble_hs_util_ensure_addr(int prefer_random)
{
	(void)prefer_random;
	return fake_hs_util_ensure_addr_rc;
}

void ble_svc_gap_init(void)
{
}

void ble_svc_gatt_init(void)
{
}

int ble_svc_gap_device_name_set(const char *name)
{
	snprintf(fake_svc_gap_name, sizeof(fake_svc_gap_name), "%s", name);
	return fake_svc_gap_name_set_rc;
}

const char *ble_svc_gap_device_name(void)
{
	return fake_svc_gap_name;
}

esp_err_t nimble_port_init(void)
{
	if (fake_nimble_port_init_rc == ESP_OK) {
		fake_host_inited = 1;
	}
	return fake_nimble_port_init_rc;
}

void nimble_port_run(void)
{
	fake_nimble_port_runs++;
}

struct ble_npl_eventq *nimble_port_get_dflt_eventq(void)
{
	return &s_dflt_eventq;
}

void nimble_port_freertos_init(void (*host_task_fn)(void *param))
{
	fake_nimble_host_task = host_task_fn;
}

void nimble_port_freertos_deinit(void)
{
	fake_nimble_freertos_deinits++;
}
