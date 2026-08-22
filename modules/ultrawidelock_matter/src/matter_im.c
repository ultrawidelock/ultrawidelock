/* SPDX-License-Identifier: ISC */

/*
 * See matter_im.h. Tag numbers are transcribed from
 * workspace/modules/lib/matter/src/app/MessageDef/, cited at each use, because
 * they are the one thing here that cannot be derived or sanity-checked at
 * runtime: a wrong tag encodes cleanly and is refused by the peer in silence.
 */
#include "matter_im.h"

#include <string.h>

int matter_im_read_pool_init(struct matter_im_read_pool *pool,
			     struct matter_im_read_state *slots, size_t n_slots)
{
	if (pool == NULL || slots == NULL || n_slots == 0u) {
		return MATTER_E_INVAL;
	}
	memset(slots, 0, n_slots * sizeof(*slots));
	pool->slots = slots;
	pool->n_slots = n_slots;
	return MATTER_OK;
}

struct matter_im_read_state *matter_im_read_pool_find(struct matter_im_read_pool *pool,
						       uint16_t session_id,
						       uint16_t exchange_id,
						       bool over_thread)
{
	if (pool == NULL || pool->slots == NULL) {
		return NULL;
	}
	for (size_t i = 0u; i < pool->n_slots; i++) {
		struct matter_im_read_state *slot = &pool->slots[i];

		if (slot->in_use && slot->session_id == session_id &&
		    slot->exchange_id == exchange_id && slot->over_thread == over_thread) {
			return slot;
		}
	}
	return NULL;
}

int matter_im_read_pool_acquire(struct matter_im_read_pool *pool, uint16_t session_id,
				uint16_t exchange_id, bool over_thread,
				struct matter_im_read_state **out)
{
	struct matter_im_read_state *slot;

	if (pool == NULL || pool->slots == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}
	*out = NULL;
	slot = matter_im_read_pool_find(pool, session_id, exchange_id, over_thread);
	if (slot != NULL) {
		*out = slot;
		return MATTER_E_DUP;
	}
	for (size_t i = 0u; i < pool->n_slots; i++) {
		if (pool->slots[i].in_use) {
			continue;
		}
		slot = &pool->slots[i];
		memset(slot, 0, sizeof(*slot));
		slot->session_id = session_id;
		slot->exchange_id = exchange_id;
		slot->over_thread = over_thread;
		slot->in_use = true;
		*out = slot;
		return MATTER_OK;
	}
	return MATTER_E_NOSPACE;
}

int matter_im_read_pool_finish(struct matter_im_read_pool *pool, uint16_t session_id,
			       uint16_t exchange_id, bool over_thread, uint16_t emitted,
			       bool more, int status)
{
	struct matter_im_read_state *slot =
		matter_im_read_pool_find(pool, session_id, exchange_id, over_thread);

	if (slot == NULL) {
		return MATTER_E_STATE;
	}
	if (status != MATTER_OK) {
		slot->in_use = false;
		return MATTER_OK;
	}
	if (emitted == 0u && more) {
		slot->in_use = false;
		return MATTER_E_INVAL;
	}
	slot->sent = (uint16_t)(slot->sent + emitted);
	slot->more = more;
	if (!more) {
		slot->in_use = false;
	}
	return MATTER_OK;
}

void matter_im_read_pool_drop_session(struct matter_im_read_pool *pool, uint16_t session_id,
				      bool over_thread)
{
	if (pool == NULL || pool->slots == NULL) {
		return;
	}
	for (size_t i = 0u; i < pool->n_slots; i++) {
		if (pool->slots[i].in_use && pool->slots[i].session_id == session_id &&
		    pool->slots[i].over_thread == over_thread) {
			pool->slots[i].in_use = false;
		}
	}
}

/* ReadRequestMessage.h:41-47 */
#define TAG_READ_ATTRIBUTE_PATHS 0u
#define TAG_READ_EVENT_PATHS     1u
#define TAG_READ_EVENT_FILTERS   2u
#define TAG_READ_FABRIC_FILTERED 3u

/*
 * EventPathIB.h:38-44. A LIST, like AttributePathIB -- but the tag numbers are
 * NOT the same as that one's, and reusing them encodes an endpoint as a cluster
 * with no error anywhere.
 */
#define TAG_EPATH_NODE      0u
#define TAG_EPATH_ENDPOINT  1u
#define TAG_EPATH_CLUSTER   2u
#define TAG_EPATH_EVENT     3u
#define TAG_EPATH_IS_URGENT 4u

/* EventFilterIB.h:38-41 */
#define TAG_EFILTER_NODE      0u
#define TAG_EFILTER_EVENT_MIN 1u

/* EventReportIB.h:37-38 */
#define TAG_EREPORT_STATUS 0u
#define TAG_EREPORT_DATA   1u

/* EventDataIB.h:38-45 */
#define TAG_EDATA_PATH             0u
#define TAG_EDATA_EVENT_NUMBER     1u
#define TAG_EDATA_PRIORITY         2u
#define TAG_EDATA_EPOCH_TIMESTAMP  3u
#define TAG_EDATA_SYSTEM_TIMESTAMP 4u
#define TAG_EDATA_DATA             7u

/* AttributePathIB.h:40-45. The IB itself is a LIST, not a structure. */
#define TAG_PATH_ENDPOINT  2u
#define TAG_PATH_CLUSTER   3u
#define TAG_PATH_ATTRIBUTE 4u
#define TAG_PATH_LIST_INDEX 5u
#define MATTER_TLV_NULL_TYPE 0x14u

/* ReportDataMessage.h:43-47 */
#define TAG_REPORT_SUBSCRIPTION_ID   0u
#define TAG_REPORT_ATTRIBUTE_REPORTS 1u
#define TAG_REPORT_EVENT_REPORTS     2u
#define TAG_REPORT_MORE_CHUNKS       3u
#define TAG_REPORT_SUPPRESS_RESPONSE 4u

/* AttributeReportIB.h:37-38 */
#define TAG_AREPORT_STATUS 0u
#define TAG_AREPORT_DATA   1u

/* AttributeDataIB.h:37-39 */
#define TAG_ADATA_VERSION 0u
#define TAG_ADATA_PATH    1u
#define TAG_ADATA_DATA    2u

/* AttributeStatusIB.h:37-38 */
#define TAG_ASTATUS_PATH   0u
#define TAG_ASTATUS_STATUS 1u

/* StatusIB.h:67 */
#define TAG_STATUS_STATUS 0u

/* SpecificationDefinedRevisions.h:35 */
#define TAG_IM_REVISION 0xFFu

/* InvokeRequestMessage.h:41-43 */
#define TAG_INVOKE_SUPPRESS_RESPONSE 0u
#define TAG_INVOKE_TIMED_REQUEST     1u
#define TAG_INVOKE_REQUESTS          2u

/* InvokeResponseMessage.h:41-43 */
#define TAG_IRESP_SUPPRESS_RESPONSE 0u
#define TAG_IRESP_RESPONSES         1u
#define TAG_IRESP_MORE_CHUNKS       2u

/* CommandDataIB.h:37-39 */
#define TAG_CMDDATA_PATH   0u
#define TAG_CMDDATA_FIELDS 1u
#define TAG_CMDDATA_REF    2u

/* CommandPathIB.h:40-42. A LIST, like AttributePathIB. */
#define TAG_CMDPATH_ENDPOINT 0u
#define TAG_CMDPATH_CLUSTER  1u
#define TAG_CMDPATH_COMMAND  2u

/* InvokeResponseIB.h:37-38 */
#define TAG_IRESPIB_COMMAND 0u
#define TAG_IRESPIB_STATUS  1u

/* CommandStatusIB.h:37-39 */
#define TAG_CMDSTATUS_PATH   0u
#define TAG_CMDSTATUS_STATUS 1u
#define TAG_CMDSTATUS_REF    2u

/**
 * Data version reported for every attribute.
 *
 * Real devices bump this when a cluster's data changes so a commissioner can
 * skip re-reading it. Nothing on this node changes yet, so a constant is honest
 * rather than lazy; it becomes a per-cluster counter when something can write.
 */
#define DATA_VERSION 1u

/** Decode one AttributePathIB. The reader is positioned ON the list element. */
static int decode_path(struct matter_tlv_reader *r, struct matter_im_path *p)
{
	int rc;

	memset(p, 0, sizeof(*p));

	rc = matter_tlv_enter(r);
	if (rc != MATTER_OK) {
		return rc;
	}

	for (;;) {
		uint64_t v;

		rc = matter_tlv_next(r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}

		/*
		 * Unknown tags are SKIPPED, not refused. A newer commissioner may
		 * send fields this node has never heard of -- Node and
		 * EnableTagCompression already exist -- and refusing the whole
		 * read over one would break against every future revision.
		 */
		if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_PATH_ENDPOINT)) {
			rc = matter_tlv_get_u64(r, &v);
			if (rc != MATTER_OK || v > UINT16_MAX) {
				return MATTER_E_INVAL;
			}
			p->endpoint = (uint16_t)v;
			p->have_endpoint = true;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_PATH_CLUSTER)) {
			rc = matter_tlv_get_u64(r, &v);
			if (rc != MATTER_OK || v > UINT32_MAX) {
				return MATTER_E_INVAL;
			}
			p->cluster = (uint32_t)v;
			p->have_cluster = true;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_PATH_ATTRIBUTE)) {
			rc = matter_tlv_get_u64(r, &v);
			if (rc != MATTER_OK || v > UINT32_MAX) {
				return MATTER_E_INVAL;
			}
			p->attribute = (uint32_t)v;
			p->have_attribute = true;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_PATH_LIST_INDEX)) {
			p->have_list_index = true;
			if (matter_tlv_element_type(r) == MATTER_TLV_NULL_TYPE) {
				p->list_index_null = true;
			} else {
				rc = matter_tlv_get_u64(r, &v);
				if (rc != MATTER_OK || v > UINT16_MAX) {
					return MATTER_E_INVAL;
				}
				p->list_index = (uint16_t)v;
			}
		}
	}

	return matter_tlv_exit(r);
}

/** Decode one EventPathIB. The reader is positioned ON the list element. */
static int decode_event_path(struct matter_tlv_reader *r, struct matter_im_event_path *p)
{
	int rc;

	memset(p, 0, sizeof(*p));

	rc = matter_tlv_enter(r);
	if (rc != MATTER_OK) {
		return rc;
	}

	for (;;) {
		uint64_t v;

		rc = matter_tlv_next(r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}

		/* Node and IsUrgent are skipped for the reason unknown tags are:
		 * see decode_path(). IsUrgent asks for a report sooner than the
		 * minimum interval, and this node reports on the change itself,
		 * so honouring it would change nothing. */
		if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_EPATH_ENDPOINT)) {
			rc = matter_tlv_get_u64(r, &v);
			if (rc != MATTER_OK || v > UINT16_MAX) {
				return MATTER_E_INVAL;
			}
			p->endpoint = (uint16_t)v;
			p->have_endpoint = true;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_EPATH_CLUSTER)) {
			rc = matter_tlv_get_u64(r, &v);
			if (rc != MATTER_OK || v > UINT32_MAX) {
				return MATTER_E_INVAL;
			}
			p->cluster = (uint32_t)v;
			p->have_cluster = true;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_EPATH_EVENT)) {
			rc = matter_tlv_get_u64(r, &v);
			if (rc != MATTER_OK || v > UINT32_MAX) {
				return MATTER_E_INVAL;
			}
			p->event = (uint32_t)v;
			p->have_event = true;
		}
	}

	return matter_tlv_exit(r);
}

/**
 * Decode an EventRequests array into @p out.
 *
 * Paths past MATTER_IM_MAX_EVENT_PATHS are REFUSED rather than dropped, which is
 * what the attribute side does and for the same reason: answering some of what
 * was asked, silently, reads as a node that has nothing more to say.
 */
static int decode_event_paths(struct matter_tlv_reader *r, struct matter_im_read *out)
{
	int rc;

	if (matter_tlv_element_type(r) != MATTER_TLV_ARRAY) {
		return MATTER_E_TYPE;
	}
	rc = matter_tlv_enter(r);
	if (rc != MATTER_OK) {
		return rc;
	}
	for (;;) {
		rc = matter_tlv_next(r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}
		if (matter_tlv_element_type(r) != MATTER_TLV_LIST) {
			return MATTER_E_TYPE;
		}
		if (out->n_event_paths >= MATTER_IM_MAX_EVENT_PATHS) {
			return MATTER_E_NOSPACE;
		}
		rc = decode_event_path(r, &out->event_paths[out->n_event_paths]);
		if (rc != MATTER_OK) {
			return rc;
		}
		out->n_event_paths++;
	}
	return matter_tlv_exit(r);
}

/**
 * Decode an EventFilters array, keeping the LARGEST EventMin it carries.
 *
 * One filter per node id, and this node answers one peer per exchange, so the
 * highest watermark is the honest reading of "what this subscriber has already
 * seen". Taking the lowest would re-report events the peer acknowledged.
 */
static int decode_event_filters(struct matter_tlv_reader *r, struct matter_im_read *out)
{
	int rc;

	if (matter_tlv_element_type(r) != MATTER_TLV_ARRAY) {
		return MATTER_E_TYPE;
	}
	rc = matter_tlv_enter(r);
	if (rc != MATTER_OK) {
		return rc;
	}
	for (;;) {
		rc = matter_tlv_next(r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}
		if (matter_tlv_element_type(r) != MATTER_TLV_STRUCTURE) {
			return MATTER_E_TYPE;
		}
		rc = matter_tlv_enter(r);
		if (rc != MATTER_OK) {
			return rc;
		}
		for (;;) {
			uint64_t v;

			rc = matter_tlv_next(r);
			if (rc == MATTER_END) {
				break;
			}
			if (rc != MATTER_OK) {
				return rc;
			}
			if (matter_tlv_tag(r) != MATTER_TLV_CTX(TAG_EFILTER_EVENT_MIN)) {
				continue;
			}
			rc = matter_tlv_get_u64(r, &v);
			if (rc != MATTER_OK) {
				return MATTER_E_INVAL;
			}
			if (v > out->event_min) {
				out->event_min = v;
			}
		}
		rc = matter_tlv_exit(r);
		if (rc != MATTER_OK) {
			return rc;
		}
	}
	return matter_tlv_exit(r);
}

/**
 * Decode a Matter read request message from TLV to extract attribute paths and filter settings.
 * Parses ReadRequestMessage structure to collect attribute paths and fabric_filtered flag.
 * Returns MATTER_E_INVAL if tlv or out is NULL; returns MATTER_E_TYPE if element types are wrong;
 * returns MATTER_E_NOSPACE if path count exceeds MATTER_IM_MAX_PATHS.
 */
int matter_im_read_request_decode(const uint8_t *tlv, size_t len, struct matter_im_read *out)
{
	struct matter_tlv_reader r;
	int rc;

	if (tlv == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}

	memset(out, 0, sizeof(*out));
	matter_tlv_reader_init(&r, tlv, len);

	/* The message is one anonymous structure. */
	rc = matter_tlv_next(&r);
	if (rc != MATTER_OK) {
		return (rc == MATTER_END) ? MATTER_E_INVAL : rc;
	}
	if (matter_tlv_element_type(&r) != MATTER_TLV_STRUCTURE) {
		return MATTER_E_TYPE;
	}
	rc = matter_tlv_enter(&r);
	if (rc != MATTER_OK) {
		return rc;
	}

	for (;;) {
		rc = matter_tlv_next(&r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}

		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_READ_ATTRIBUTE_PATHS)) {
			if (matter_tlv_element_type(&r) != MATTER_TLV_ARRAY) {
				return MATTER_E_TYPE;
			}
			rc = matter_tlv_enter(&r);
			if (rc != MATTER_OK) {
				return rc;
			}
			for (;;) {
				rc = matter_tlv_next(&r);
				if (rc == MATTER_END) {
					break;
				}
				if (rc != MATTER_OK) {
					return rc;
				}
				if (matter_tlv_element_type(&r) != MATTER_TLV_LIST) {
					return MATTER_E_TYPE;
				}
				if (out->n_paths >= MATTER_IM_MAX_PATHS) {
					return MATTER_E_NOSPACE;
				}
				rc = decode_path(&r, &out->paths[out->n_paths]);
				if (rc != MATTER_OK) {
					return rc;
				}
				out->n_paths++;
			}
			rc = matter_tlv_exit(&r);
			if (rc != MATTER_OK) {
				return rc;
			}
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_READ_EVENT_PATHS)) {
			rc = decode_event_paths(&r, out);
			if (rc != MATTER_OK) {
				return rc;
			}
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_READ_EVENT_FILTERS)) {
			rc = decode_event_filters(&r, out);
			if (rc != MATTER_OK) {
				return rc;
			}
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_READ_FABRIC_FILTERED)) {
			rc = matter_tlv_get_bool(&r, &out->fabric_filtered);
			if (rc != MATTER_OK) {
				return rc;
			}
		}
		/* Data-version filters and the revision are read past deliberately:
		 * this node reports every value every time, and the revision is the
		 * peer's claim about itself, not a demand on the answer. */
	}

	return matter_tlv_exit(&r);
}

/** Write one AttributePathIB. Concrete by construction: only reported paths. */
static void put_path(struct matter_tlv_writer *w, matter_tlv_tag_t tag,
		     const struct matter_im_path *p)
{
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_LIST);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_PATH_ENDPOINT), p->endpoint);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_PATH_CLUSTER), p->cluster);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_PATH_ATTRIBUTE), p->attribute);
	if (p->have_list_index) {
		if (p->list_index_null) {
			(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_PATH_LIST_INDEX));
		} else {
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_PATH_LIST_INDEX),
						 p->list_index);
		}
	}
	(void)matter_tlv_end_container(w);
}

/**
 * Append one AttributeReportIB carrying a status rather than a value.
 *
 * Errors are not checked here because the writer latches the first one and
 * makes every later call a no-op; matter_tlv_writer_finish() reports it once.
 */
static void put_status_report(struct matter_tlv_writer *w, const struct matter_im_path *p,
			      uint8_t status)
{
	(void)matter_tlv_start_container(w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_start_container(w, MATTER_TLV_CTX(TAG_AREPORT_STATUS),
					 MATTER_TLV_STRUCTURE);
	put_path(w, MATTER_TLV_CTX(TAG_ASTATUS_PATH), p);
	(void)matter_tlv_start_container(w, MATTER_TLV_CTX(TAG_ASTATUS_STATUS),
					 MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_STATUS_STATUS), status);
	(void)matter_tlv_end_container(w);
	(void)matter_tlv_end_container(w);
	(void)matter_tlv_end_container(w);
}

/**
 * Append one AttributeReportIB for a CONCRETE path: the value, or the status
 * saying why not.
 *
 * The status is settled before a byte is committed. Deciding afterwards would
 * mean unwinding a half-written information block, and the writer latches its
 * first error and turns later calls into no-ops -- so an unwind would have to
 * reason about container depth that was never incremented.
 */
static void put_report(struct matter_tlv_writer *w, const struct matter_im_server *srv,
		       const struct matter_im_path *p, bool fabric_filtered)
{
	uint8_t status = srv->status(srv->ctx, p->endpoint, p->cluster, p->attribute);

	if (status != MATTER_IM_STATUS_SUCCESS) {
		put_status_report(w, p, status);
		return;
	}

	(void)matter_tlv_start_container(w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_start_container(w, MATTER_TLV_CTX(TAG_AREPORT_DATA), MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_ADATA_VERSION), DATA_VERSION);
	put_path(w, MATTER_TLV_CTX(TAG_ADATA_PATH), p);
	srv->value(srv->ctx, p->endpoint, p->cluster, p->attribute, fabric_filtered, w,
		   MATTER_TLV_CTX(TAG_ADATA_DATA));
	(void)matter_tlv_end_container(w);
	(void)matter_tlv_end_container(w);
}

/**
 * Report a wildcard path whose endpoint is now settled.
 *
 * Everything here stays SILENT on a miss. The path the commissioner sent was a
 * wildcard, and that does not stop being true once this has picked an endpoint
 * to look on -- an AttributeStatusIB would report "endpoint 0 has no such
 * attribute" as though the commissioner had asked about endpoint 0, which it
 * did not (AttributePathExpandIterator.cpp:239-255).
 */
/**
 * How far through a chunked report we are.
 *
 * Threaded through the expansion instead of returned from it, because the
 * expansion is four nested loops and the alternative is a cursor into all four.
 */
struct chunk_ctx {
	uint16_t skip;    /**< reports earlier chunks already carried */
	uint16_t seen;    /**< candidates walked in this pass */
	uint16_t emitted; /**< reports written into this chunk */
	bool full;        /**< the next report did not fit; stop */
	size_t reserve;   /**< bytes to keep free for the message's tail */
};

static int report_encode(const struct matter_im_server *srv, const struct matter_im_read *req,
			 uint8_t *out, size_t cap, size_t *out_len,
			 struct matter_im_report_stats *stats, struct chunk_ctx *cc);

/**
 * Append one report unless this chunk is full or an earlier one carried it.
 *
 * The write is attempted and ROLLED BACK when it does not fit, rather than
 * predicted: the size of a report depends on the value, and a prediction that
 * is wrong by one byte truncates a message that the peer cannot tell from a
 * complete one.
 */
static void emit(struct matter_tlv_writer *w, const struct matter_im_server *srv,
		 const struct matter_im_path *p, bool fabric_filtered, struct chunk_ctx *cc)
{
	size_t save_len;
	int save_rc;
	uint8_t save_depth;

	if (cc == NULL) {
		put_report(w, srv, p, fabric_filtered);
		return;
	}
	if (cc->full) {
		return;
	}
	if (cc->seen++ < cc->skip) {
		return;
	}

	save_len = w->len;
	save_rc = w->rc;
	/*
	 * Depth too. put_report() opens three containers before it writes
	 * anything that can overflow, so a rollback that restores only the
	 * length leaves the writer nested inside structures that were never
	 * closed -- and every later end_container() then unbalances the message
	 * instead of finishing it.
	 */
	save_depth = w->depth;
	put_report(w, srv, p, fabric_filtered);
	/* Out of room, or into the tail reserve, which amounts to the same
	 * thing: MoreChunkedMessages and the revision still have to fit. */
	if (w->rc != MATTER_TLV_OK || w->len + cc->reserve > w->cap) {
		w->len = save_len;
		w->rc = save_rc;
		w->depth = save_depth;
		cc->full = true;
		return;
	}
	cc->emitted++;
}

/**
 * Expand a wildcard attribute path by enumerating all attributes in the cluster if present.
 * If path specifies a single attribute, emit it; if attribute is unspecified, list all available
 * attributes and emit each.
 * Increments stats counters for unexpanded and skipped wildcard paths when attributes cannot be
 * listed or cluster is unavailable.
 */
static void expand_on_endpoint(struct matter_tlv_writer *w, const struct matter_im_server *srv,
			       const struct matter_im_path *p, struct matter_im_report_stats *stats,
			       bool fabric_filtered, struct chunk_ctx *cc)
{
	const uint32_t *attrs = NULL;
	size_t n_attrs = 0u;
	size_t k;

	if (!srv->has_cluster(srv->ctx, p->endpoint, p->cluster)) {
		if (stats != NULL) {
			stats->skipped_wildcard++;
		}
		return;
	}

	if (p->have_attribute) {
		if (srv->status(srv->ctx, p->endpoint, p->cluster, p->attribute) !=
		    MATTER_IM_STATUS_SUCCESS) {
			if (stats != NULL) {
				stats->skipped_wildcard++;
			}
			return;
		}
		emit(w, srv, p, fabric_filtered, cc);
		return;
	}

	if (srv->list_attrs != NULL) {
		n_attrs = srv->list_attrs(srv->ctx, p->endpoint, p->cluster, &attrs);
	}
	if (n_attrs == 0u || attrs == NULL) {
		if (stats != NULL) {
			stats->unexpanded_wildcard++;
		}
		return;
	}
	for (k = 0; k < n_attrs; k++) {
		struct matter_im_path one = *p;

		one.attribute = attrs[k];
		one.have_attribute = true;
		emit(w, srv, &one, fabric_filtered, cc);
	}
}

/** Does @p ev fall under any of the request's event paths? */
static bool event_wanted(const struct matter_im_read *req, const struct matter_im_event *ev)
{
	uint8_t i;

	for (i = 0; i < req->n_event_paths; i++) {
		const struct matter_im_event_path *p = &req->event_paths[i];

		/* An absent component is a wildcard, exactly as it is for an
		 * attribute path -- a controller subscribing to "all events"
		 * sends one path with nothing in it. */
		if (p->have_endpoint && p->endpoint != ev->endpoint) {
			continue;
		}
		if (p->have_cluster && p->cluster != ev->cluster) {
			continue;
		}
		if (p->have_event && p->event != ev->event) {
			continue;
		}
		return true;
	}
	return false;
}

/**
 * Append one EventReportIB carrying an EventDataIB.
 *
 * SYSTEM timestamp, not epoch: this node has no trusted wall clock, and an
 * epoch timestamp it invented would be a claim about when an unlock happened
 * that a controller is entitled to believe. Milliseconds since boot is true and
 * says so (EventDataIB.h:42, and the spec allows exactly one of the two).
 */
static void put_event_report(struct matter_tlv_writer *w, const struct matter_im_server *srv,
			     const struct matter_im_event *ev, size_t index)
{
	(void)matter_tlv_start_container(w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_start_container(w, MATTER_TLV_CTX(TAG_EREPORT_DATA), MATTER_TLV_STRUCTURE);

	(void)matter_tlv_start_container(w, MATTER_TLV_CTX(TAG_EDATA_PATH), MATTER_TLV_LIST);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_EPATH_ENDPOINT), ev->endpoint);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_EPATH_CLUSTER), ev->cluster);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_EPATH_EVENT), ev->event);
	(void)matter_tlv_end_container(w);

	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_EDATA_EVENT_NUMBER), ev->number);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_EDATA_PRIORITY), ev->priority);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_EDATA_SYSTEM_TIMESTAMP), ev->timestamp_ms);
	srv->event_data(srv->ctx, index, w, MATTER_TLV_CTX(TAG_EDATA_DATA));

	(void)matter_tlv_end_container(w);
	(void)matter_tlv_end_container(w);
}

/**
 * Write the EventReports array, oldest event first.
 *
 * Written only when the request ASKED for events. The field is optional, and an
 * absent array says the same thing as an empty one -- so a read that named no
 * event path produces exactly the bytes it did before this existed, which is
 * what keeps every commissioning report unchanged.
 *
 * Chunking walks the same cursor the attribute reports use, so events resume
 * where a previous chunk stopped. What that cannot survive is the ring EVICTING
 * between two chunks of one report: indices shift, and an event can be missed.
 * It stays missed rather than being reported twice, and the next report carries
 * whatever the ring still holds.
 */
static void put_event_reports(struct matter_tlv_writer *w, const struct matter_im_server *srv,
			      const struct matter_im_read *req, struct chunk_ctx *cc)
{
	size_t n;
	size_t i;

	if (req->n_event_paths == 0u || srv->event_count == NULL || srv->event_at == NULL ||
	    srv->event_data == NULL) {
		return;
	}

	(void)matter_tlv_start_container(w, MATTER_TLV_CTX(TAG_REPORT_EVENT_REPORTS),
					 MATTER_TLV_ARRAY);
	n = srv->event_count(srv->ctx);
	for (i = 0; i < n; i++) {
		struct matter_im_event ev;
		size_t save_len;
		int save_rc;
		uint8_t save_depth;

		if (!srv->event_at(srv->ctx, i, &ev)) {
			break;
		}
		if (ev.number < req->event_min || !event_wanted(req, &ev)) {
			continue;
		}
		if (cc == NULL) {
			put_event_report(w, srv, &ev, i);
			continue;
		}
		if (cc->full) {
			break;
		}
		if (cc->seen++ < cc->skip) {
			continue;
		}
		/* Attempted and rolled back, never predicted -- the same
		 * discipline emit() uses, and for the same reason. */
		save_len = w->len;
		save_rc = w->rc;
		save_depth = w->depth;
		put_event_report(w, srv, &ev, i);
		if (w->rc != MATTER_TLV_OK || w->len + cc->reserve > w->cap) {
			w->len = save_len;
			w->rc = save_rc;
			w->depth = save_depth;
			cc->full = true;
			break;
		}
		cc->emitted++;
	}
	(void)matter_tlv_end_container(w);
}

int matter_im_report_data_chunk(const struct matter_im_server *srv,
				const struct matter_im_read *req, uint16_t sent, uint8_t *out,
				size_t cap, size_t *out_len, bool *more, uint16_t *emitted,
				struct matter_im_report_stats *stats)
{
	/*
	 * MoreChunkedMessages, SuppressResponse, the revision, a subscription id
	 * and the closing byte, none of which may be squeezed out by one more
	 * report -- a chunk that cannot say "more follows" is a truncated
	 * report, and the peer has no way to tell the two apart.
	 */
	struct chunk_ctx cc = {.skip = sent, .reserve = 24u};
	int rc;

	if (more == NULL || emitted == NULL) {
		return MATTER_E_INVAL;
	}
	rc = report_encode(srv, req, out, cap, out_len, stats, &cc);
	*more = cc.full;
	*emitted = cc.emitted;
	return rc;
}

int matter_im_report_data_encode(const struct matter_im_server *srv,
				 const struct matter_im_read *req, uint8_t *out, size_t cap,
				 size_t *out_len, struct matter_im_report_stats *stats)
{
	/* Unchunked: every report or an error, which is what a caller with one
	 * concrete path wants and what the host suite asserts. */
	return report_encode(srv, req, out, cap, out_len, stats, NULL);
}

/**
 * Encode a Matter IM report containing attribute values for the requested read paths, expanding
 * wildcards by enumerating endpoints and clusters as needed. Track statistics on unexpanded
 * wildcards and set the more-chunks flag if the report was truncated. Return an error code.
 */
static int report_encode(const struct matter_im_server *srv, const struct matter_im_read *req,
			 uint8_t *out, size_t cap, size_t *out_len,
			 struct matter_im_report_stats *stats, struct chunk_ctx *cc)
{
	struct matter_tlv_writer w;
	uint8_t i;

	if (srv == NULL || srv->status == NULL || srv->value == NULL || srv->has_cluster == NULL ||
	    req == NULL || out == NULL || out_len == NULL) {
		return MATTER_E_INVAL;
	}
	if (stats != NULL) {
		memset(stats, 0, sizeof(*stats));
	}

	matter_tlv_writer_init(&w, out, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	if (req->subscription_id != 0u) {
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_REPORT_SUBSCRIPTION_ID),
					 req->subscription_id);
	}
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(TAG_REPORT_ATTRIBUTE_REPORTS),
					 MATTER_TLV_ARRAY);

	for (i = 0; i < req->n_paths; i++) {
		const struct matter_im_path *p = &req->paths[i];
		const uint16_t *eps = NULL;
		uint16_t one_ep;
		size_t n_eps = 0u;
		size_t e;

		if (!matter_im_path_is_wildcard(p)) {
			emit(&w, srv, p, req->fabric_filtered, cc);
			continue;
		}

		if (p->have_endpoint) {
			one_ep = p->endpoint;
			eps = &one_ep;
			n_eps = 1u;
		} else if (srv->list_endpoints != NULL) {
			n_eps = srv->list_endpoints(srv->ctx, &eps);
		}
		if (n_eps == 0u || eps == NULL) {
			if (stats != NULL) {
				stats->unexpanded_wildcard++;
			}
			continue;
		}

		for (e = 0; e < n_eps; e++) {
			struct matter_im_path at = *p;

			at.endpoint = eps[e];
			at.have_endpoint = true;

			/*
			 * A path naming no cluster means every cluster on the
			 * endpoint -- which is what a controller subscribes to
			 * the moment it owns the node. Enumerating them here
			 * rather than counting the path as unexpanded is the
			 * difference between a subscription that reports the
			 * device and one that reports nothing.
			 */
			if (!p->have_cluster) {
				const uint32_t *cls = NULL;
				size_t n_cls = 0u;
				size_t c;

				if (srv->list_clusters != NULL) {
					n_cls = srv->list_clusters(srv->ctx, eps[e], &cls);
				}
				if (n_cls == 0u || cls == NULL) {
					if (stats != NULL) {
						stats->unexpanded_wildcard++;
					}
					continue;
				}
				for (c = 0; c < n_cls; c++) {
					at.cluster = cls[c];
					at.have_cluster = true;
					expand_on_endpoint(&w, srv, &at, stats, req->fabric_filtered,
							   cc);
				}
				continue;
			}

			at.have_endpoint = true;
			expand_on_endpoint(&w, srv, &at, stats, req->fabric_filtered, cc);
		}
	}

	(void)matter_tlv_end_container(&w);
	put_event_reports(&w, srv, req, cc);
	/*
	 * More follows. The peer answers a chunk with a StatusResponse and waits
	 * for the rest; omitting this on a report that WAS cut short is how a
	 * partial data model gets presented as a complete one.
	 */
	if (cc != NULL && cc->full) {
		(void)matter_tlv_put_bool(&w, MATTER_TLV_CTX(TAG_REPORT_MORE_CHUNKS), true);
	}
	/*
	 * A read suppresses the response (reporting/Engine.cpp:834-836) and a
	 * priming report must NOT: the StatusResponse it draws is what the
	 * SubscribeResponse is sent in answer to. A chunk must not either --
	 * that StatusResponse is what asks for the next one.
	 */
	(void)matter_tlv_put_bool(&w, MATTER_TLV_CTX(TAG_REPORT_SUPPRESS_RESPONSE),
				  req->subscription_id == 0u && (cc == NULL || !cc->full));
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_IM_REVISION), MATTER_IM_REVISION);
	(void)matter_tlv_end_container(&w);

	return matter_tlv_writer_finish(&w, out_len);
}

/* ------------------------------------------------------------- invoke --- */

/** Decode one CommandPathIB. The reader is positioned ON the list element. */
static int decode_command_path(struct matter_tlv_reader *r, struct matter_im_invoke *inv)
{
	bool have_endpoint = false;
	bool have_cluster = false;
	bool have_command = false;
	int rc;

	rc = matter_tlv_enter(r);
	if (rc != MATTER_OK) {
		return rc;
	}

	for (;;) {
		uint64_t v;

		rc = matter_tlv_next(r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}
		if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_CMDPATH_ENDPOINT)) {
			rc = matter_tlv_get_u64(r, &v);
			if (rc != MATTER_OK || v > UINT16_MAX) {
				return MATTER_E_INVAL;
			}
			inv->endpoint = (uint16_t)v;
			have_endpoint = true;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_CMDPATH_CLUSTER)) {
			rc = matter_tlv_get_u64(r, &v);
			if (rc != MATTER_OK || v > UINT32_MAX) {
				return MATTER_E_INVAL;
			}
			inv->cluster = (uint32_t)v;
			have_cluster = true;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_CMDPATH_COMMAND)) {
			rc = matter_tlv_get_u64(r, &v);
			if (rc != MATTER_OK || v > UINT32_MAX) {
				return MATTER_E_INVAL;
			}
			inv->command = (uint32_t)v;
			have_command = true;
		}
	}

	/*
	 * A command path has no wildcards. Unlike a read, which may legitimately
	 * ask about a whole cluster, invoking "some command somewhere" is not a
	 * thing the spec defines, so a missing field is a malformed message
	 * rather than a broad request.
	 */
	if (!have_endpoint || !have_cluster || !have_command) {
		return MATTER_E_INVAL;
	}
	return matter_tlv_exit(r);
}

/** Decode one CommandDataIB. The reader is positioned ON the structure. */
static int decode_command_data(struct matter_tlv_reader *r, struct matter_im_invoke *inv)
{
	bool have_path = false;
	int rc;

	rc = matter_tlv_enter(r);
	if (rc != MATTER_OK) {
		return rc;
	}

	for (;;) {
		/*
		 * Where the element about to be read STARTS. next_off is what the
		 * next scan begins at, so recording it before next() is the only
		 * way to bound a whole element: end_off stops at a container's
		 * head and says nothing about its body (matter_tlv.h:184-185).
		 */
		size_t elem_start = r->next_off;

		rc = matter_tlv_next(r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}

		if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_CMDDATA_PATH)) {
			if (matter_tlv_element_type(r) != MATTER_TLV_LIST) {
				return MATTER_E_TYPE;
			}
			rc = decode_command_path(r, inv);
			if (rc != MATTER_OK) {
				return rc;
			}
			have_path = true;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_CMDDATA_FIELDS)) {
			/*
			 * Borrowed, not copied, and deliberately left undecoded:
			 * what the fields MEAN depends on which command this is,
			 * which is the cluster's business rather than the message
			 * layer's. Handed over as the COMPLETE element -- tag,
			 * body and end marker -- so a reader can be pointed at it
			 * directly.
			 *
			 * Valid only as long as the caller's buffer is.
			 */
			if (!matter_tlv_is_container(r)) {
				return MATTER_E_TYPE;
			}
			rc = matter_tlv_enter(r);
			if (rc != MATTER_OK) {
				return rc;
			}
			rc = matter_tlv_exit(r);
			if (rc != MATTER_OK) {
				return rc;
			}
			inv->fields = r->buf + elem_start;
			inv->fields_len = (size_t)(r->next_off - elem_start);
			inv->has_fields = true;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_CMDDATA_REF)) {
			uint64_t v;

			if (matter_tlv_get_u64(r, &v) != MATTER_OK) {
				return MATTER_E_INVAL;
			}
			inv->command_ref = v;
			inv->has_command_ref = true;
		}
	}

	if (!have_path) {
		return MATTER_E_INVAL;
	}
	return matter_tlv_exit(r);
}

/**
 * Decode a Matter invoke request message from TLV to extract command path, arguments, and flags.
 * Parses InvokeRequestMessage structure: SuppressResponse, TimedRequest booleans and exactly one
 * CommandDataIB from the Requests array.
 * Returns MATTER_E_INVAL if tlv or out is NULL, if structure is missing, or if request count is not
 * exactly one; returns MATTER_E_NOSPACE if more than one command in array; returns MATTER_E_TYPE if
 * element types are wrong.
 */
int matter_im_invoke_request_decode(const uint8_t *tlv, size_t len, struct matter_im_invoke *out)
{
	struct matter_tlv_reader r;
	unsigned int seen = 0u;
	int rc;

	if (tlv == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}

	memset(out, 0, sizeof(*out));
	matter_tlv_reader_init(&r, tlv, len);

	rc = matter_tlv_next(&r);
	if (rc != MATTER_OK) {
		return (rc == MATTER_END) ? MATTER_E_INVAL : rc;
	}
	if (matter_tlv_element_type(&r) != MATTER_TLV_STRUCTURE) {
		return MATTER_E_TYPE;
	}
	rc = matter_tlv_enter(&r);
	if (rc != MATTER_OK) {
		return rc;
	}

	for (;;) {
		rc = matter_tlv_next(&r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}

		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_INVOKE_SUPPRESS_RESPONSE)) {
			if (matter_tlv_get_bool(&r, &out->suppress_response) != MATTER_OK) {
				return MATTER_E_INVAL;
			}
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_INVOKE_TIMED_REQUEST)) {
			if (matter_tlv_get_bool(&r, &out->timed_request) != MATTER_OK) {
				return MATTER_E_INVAL;
			}
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_INVOKE_REQUESTS)) {
			if (matter_tlv_element_type(&r) != MATTER_TLV_ARRAY) {
				return MATTER_E_TYPE;
			}
			rc = matter_tlv_enter(&r);
			if (rc != MATTER_OK) {
				return rc;
			}
			for (;;) {
				rc = matter_tlv_next(&r);
				if (rc == MATTER_END) {
					break;
				}
				if (rc != MATTER_OK) {
					return rc;
				}
				if (matter_tlv_element_type(&r) != MATTER_TLV_STRUCTURE) {
					return MATTER_E_TYPE;
				}
				seen++;
				if (seen > 1u) {
					return MATTER_E_NOSPACE;
				}
				rc = decode_command_data(&r, out);
				if (rc != MATTER_OK) {
					return rc;
				}
			}
			rc = matter_tlv_exit(&r);
			if (rc != MATTER_OK) {
				return rc;
			}
		}
	}

	if (seen != 1u) {
		return MATTER_E_INVAL;
	}
	return matter_tlv_exit(&r);
}

/** Write one CommandPathIB naming @p command on the invoked path. */
static void put_command_path(struct matter_tlv_writer *w, matter_tlv_tag_t tag,
			     const struct matter_im_invoke *inv, uint32_t command)
{
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_LIST);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_CMDPATH_ENDPOINT), inv->endpoint);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_CMDPATH_CLUSTER), inv->cluster);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_CMDPATH_COMMAND), command);
	(void)matter_tlv_end_container(w);
}

/**
 * Encode a Matter invoke response message from command execution result and request parameters.
 * Runs the command immediately regardless of SuppressResponse flag; if suppress flag is set,
 * returns empty response.
 * Returns the command response on success, or status code on failure or unsupported attribute.
 * Returns MATTER_E_INVAL if srv, inv, or out is NULL; returns encoder error codes if TLV encoding
 * fails.
 */
int matter_im_invoke_response_encode(const struct matter_im_server *srv,
				     const struct matter_im_invoke *inv, uint8_t *out, size_t cap,
				     size_t *out_len)
{
	struct matter_tlv_writer w;
	uint32_t response_command = MATTER_IM_NO_RESPONSE;
	uint8_t status;

	if (srv == NULL || srv->command == NULL || srv->command_fields == NULL || inv == NULL ||
	    out == NULL || out_len == NULL) {
		return MATTER_E_INVAL;
	}

	/*
	 * Run it FIRST, and run it whatever the peer said about responses: the
	 * commissioner asked for the effect, and SuppressResponse only says it
	 * does not want to be told about it.
	 */
	status = srv->command(srv->ctx, inv, &response_command);

	if (inv->suppress_response) {
		*out_len = 0u;
		return MATTER_OK;
	}

	matter_tlv_writer_init(&w, out, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bool(&w, MATTER_TLV_CTX(TAG_IRESP_SUPPRESS_RESPONSE), false);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(TAG_IRESP_RESPONSES), MATTER_TLV_ARRAY);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);

	if (status == MATTER_IM_STATUS_SUCCESS && response_command != MATTER_IM_NO_RESPONSE) {
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(TAG_IRESPIB_COMMAND),
						 MATTER_TLV_STRUCTURE);
		put_command_path(&w, MATTER_TLV_CTX(TAG_CMDDATA_PATH), inv, response_command);
		srv->command_fields(srv->ctx, inv->endpoint, inv->cluster, response_command, &w,
				    MATTER_TLV_CTX(TAG_CMDDATA_FIELDS));
		if (inv->has_command_ref) {
			(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_CMDDATA_REF),
						 inv->command_ref);
		}
		(void)matter_tlv_end_container(&w);
	} else {
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(TAG_IRESPIB_STATUS),
						 MATTER_TLV_STRUCTURE);
		/* The path echoes the command that was ASKED for. There is no
		 * response command to name here, whether because nothing ran or
		 * because what ran had nothing to report. */
		put_command_path(&w, MATTER_TLV_CTX(TAG_CMDSTATUS_PATH), inv, inv->command);
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(TAG_CMDSTATUS_STATUS),
						 MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_STATUS_STATUS), status);
		(void)matter_tlv_end_container(&w);
		if (inv->has_command_ref) {
			(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_CMDSTATUS_REF),
						 inv->command_ref);
		}
		(void)matter_tlv_end_container(&w);
	}

	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_IM_REVISION), MATTER_IM_REVISION);
	(void)matter_tlv_end_container(&w);

	return matter_tlv_writer_finish(&w, out_len);
}

/**
 * Encode a Matter status response message with generic status code and revision.
 * Wraps status code in TLV structure suitable for error replies to read, write, or invoke requests.
 * Returns MATTER_E_INVAL if out or out_len is NULL; returns encoder error if TLV encoding fails.
 */
int matter_im_status_response_encode(uint8_t status, uint8_t *out, size_t cap, size_t *out_len)
{
	struct matter_tlv_writer w;

	if (out == NULL || out_len == NULL) {
		return MATTER_E_INVAL;
	}
	matter_tlv_writer_init(&w, out, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_STATUS_STATUS), status);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_IM_REVISION), MATTER_IM_REVISION);
	(void)matter_tlv_end_container(&w);

	return matter_tlv_writer_finish(&w, out_len);
}

int matter_im_status_response_decode(const uint8_t *buf, size_t len, uint8_t *status)
{
	struct matter_tlv_reader r;
	bool found = false;
	int rc;

	if (buf == NULL || status == NULL || len == 0u) {
		return MATTER_E_INVAL;
	}
	matter_tlv_reader_init(&r, buf, len);
	rc = matter_tlv_next(&r);
	if (rc != MATTER_OK) {
		return rc;
	}
	rc = matter_tlv_enter(&r);
	if (rc != MATTER_OK) {
		return rc;
	}
	for (;;) {
		uint64_t v;

		rc = matter_tlv_next(&r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_STATUS_STATUS)) {
			rc = matter_tlv_get_u64(&r, &v);
			if (rc != MATTER_OK || v > UINT8_MAX) {
				return MATTER_E_INVAL;
			}
			*status = (uint8_t)v;
			found = true;
		}
	}
	rc = matter_tlv_exit(&r);
	return rc == MATTER_OK && found ? MATTER_OK : (rc != MATTER_OK ? rc : MATTER_E_INVAL);
}

/* TimedRequestMessage.h: one field, the timeout in milliseconds. */
#define TAG_TIMED_TIMEOUT_MS 0u

/**
 * Decode a Matter timed request message to extract timeout value in milliseconds.
 * Parses TimedRequestMessage structure for TimeoutMs field, clamped to uint16_t range.
 * Returns MATTER_E_INVAL if buf, timeout_ms is NULL, or len is zero; returns parser errors on
 * malformed TLV.
 */
int matter_im_timed_request_decode(const uint8_t *buf, size_t len, uint16_t *timeout_ms)
{
	struct matter_tlv_reader r;
	uint64_t v = 0u;
	int rc;

	if (buf == NULL || timeout_ms == NULL || len == 0u) {
		return MATTER_E_INVAL;
	}
	*timeout_ms = 0u;
	matter_tlv_reader_init(&r, buf, len);
	rc = matter_tlv_next(&r);
	if (rc != MATTER_OK) {
		return rc;
	}
	rc = matter_tlv_enter(&r);
	if (rc != MATTER_OK) {
		return rc;
	}
	for (;;) {
		rc = matter_tlv_next(&r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_TIMED_TIMEOUT_MS) &&
		    matter_tlv_get_u64(&r, &v) == MATTER_OK) {
			*timeout_ms = (uint16_t)v;
		}
	}
	return MATTER_OK;
}

/* WriteRequestMessage.h:39-44 */
#define TAG_WRITE_SUPPRESS_RESPONSE 0u
#define TAG_WRITE_TIMED_REQUEST     1u
#define TAG_WRITE_REQUESTS          2u

/* WriteResponseMessage.h:39-42 */
#define TAG_WRESP_RESPONSES 0u

/**
 * Decode a Matter write request message from TLV to extract attribute path, value, and flags.
 * Parses WriteRequestMessage: exactly one AttributeDataIB containing path and data value,
 * SuppressResponse and TimedRequest booleans.
 * Caps at one attribute per write; sets truncated flag if peer sends more, allowing response to
 * report RESOURCE_EXHAUSTED.
 * Returns MATTER_E_INVAL if tlv or out is NULL, if structure is missing, or if no attributes
 * present; returns MATTER_E_NOSPACE when path is incomplete; returns parser errors on malformed
 * TLV.
 */
int matter_im_write_request_decode(const uint8_t *tlv, size_t len, struct matter_im_write *out)
{
	struct matter_tlv_reader r;
	unsigned int seen = 0u;
	int rc;

	if (tlv == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}
	memset(out, 0, sizeof(*out));

	matter_tlv_reader_init(&r, tlv, len);
	if (matter_tlv_next(&r) != MATTER_OK ||
	    matter_tlv_element_type(&r) != MATTER_TLV_STRUCTURE) {
		return MATTER_E_TYPE;
	}
	rc = matter_tlv_enter(&r);
	if (rc != MATTER_OK) {
		return rc;
	}

	for (;;) {
		rc = matter_tlv_next(&r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}

		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_WRITE_SUPPRESS_RESPONSE)) {
			(void)matter_tlv_get_bool(&r, &out->suppress_response);
			continue;
		}
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_WRITE_TIMED_REQUEST)) {
			(void)matter_tlv_get_bool(&r, &out->timed_request);
			continue;
		}
		if (matter_tlv_tag(&r) != MATTER_TLV_CTX(TAG_WRITE_REQUESTS)) {
			continue;
		}

		/* The array of AttributeDataIB. */
		rc = matter_tlv_enter(&r);
		if (rc != MATTER_OK) {
			return rc;
		}
		for (;;) {
			rc = matter_tlv_next(&r);
			if (rc == MATTER_END) {
				break;
			}
			if (rc != MATTER_OK) {
				return rc;
			}
			seen++;
			if (seen > MATTER_IM_MAX_WRITES) {
				out->truncated = true;
				return MATTER_OK;
			}
			out->n_items = (uint8_t)seen;
			struct matter_im_write_item *item = &out->items[seen - 1u];

			rc = matter_tlv_enter(&r); /* into the AttributeDataIB */
			if (rc != MATTER_OK) {
				return rc;
			}
			for (;;) {
				size_t start;

				/* Where this element begins, captured BEFORE it
				 * is loaded: the reader reports where a value
				 * sits, not where its header does, and a
				 * container's body is not part of either. */
				start = r.next_off;

				rc = matter_tlv_next(&r);
				if (rc == MATTER_END) {
					break;
				}
				if (rc != MATTER_OK) {
					return rc;
				}

				if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_ADATA_PATH)) {
					rc = decode_path(&r, &item->path);
					if (rc != MATTER_OK) {
						return rc;
					}
				} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_ADATA_DATA)) {
					/* Walk it to find where it ends. A value
					 * of any type is legal here, so its
					 * extent cannot be assumed from the
					 * header alone. */
					if (matter_tlv_is_container(&r)) {
						rc = matter_tlv_enter(&r);
						if (rc == MATTER_OK) {
							rc = matter_tlv_exit(&r);
						}
						if (rc != MATTER_OK) {
							return rc;
						}
					}
					item->data = tlv + start;
					item->data_len = r.next_off - start;
				}
			}
			rc = matter_tlv_exit(&r);
			if (rc != MATTER_OK) {
				return rc;
			}
		}
		rc = matter_tlv_exit(&r);
		if (rc != MATTER_OK) {
			return rc;
		}
	}

	if (seen == 0u) {
		return MATTER_E_INVAL;
	}
	/*
	 * A write needs somewhere concrete to land. Refused rather than
	 * expanded: a read that guesses too narrowly returns less than was
	 * asked for, but a write that guesses wrongly overwrites something the
	 * commissioner never named.
	 */
	for (uint8_t i = 0u; i < out->n_items; i++) {
		const struct matter_im_path *p = &out->items[i].path;

		if (!p->have_endpoint || !p->have_cluster || !p->have_attribute) {
			return MATTER_E_INVAL;
		}
		if (i > 0u) {
			const struct matter_im_path *first = &out->items[0].path;

			/* The only supported batch is one list transaction: ReplaceAll,
			 * followed by AppendItem operations on that same attribute. */
			if (first->have_list_index || !p->have_list_index || !p->list_index_null ||
			    p->endpoint != first->endpoint || p->cluster != first->cluster ||
			    p->attribute != first->attribute) {
				out->truncated = true;
			}
		}
	}
	return MATTER_OK;
}

/**
 * Encode a Matter write response message from write operation result.
 * Runs write immediately regardless of SuppressResponse flag; if suppress flag is set, returns
 * empty response.
 * Returns attribute status (success or error) for the written path.
 * Returns MATTER_E_INVAL if srv, wr, or out is NULL; returns encoder error codes if TLV encoding
 * fails.
 */
int matter_im_write_response_encode(const struct matter_im_server *srv,
				    const struct matter_im_write *wr, uint8_t *out, size_t cap,
				    size_t *out_len)
{
	struct matter_tlv_writer w;
	uint8_t status[MATTER_IM_MAX_WRITES];

	if (srv == NULL || wr == NULL || out == NULL || out_len == NULL) {
		return MATTER_E_INVAL;
	}
	*out_len = 0u;

	/* Run it first. A suppressed response suppresses the REPLY, not the
	 * write -- returning early here would silently drop it. */
	if (wr->truncated) {
		/* Nothing runs; see matter_im_write::truncated. */
		status[0] = MATTER_IM_STATUS_RESOURCE_EXHAUSTED;
	} else if (srv->write == NULL) {
		status[0] = MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE;
	} else {
		for (uint8_t i = 0u; i < wr->n_items; i++) {
			status[i] = srv->write(srv->ctx, &wr->items[i].path, wr->items[i].data,
					       wr->items[i].data_len);
			if (status[i] != MATTER_IM_STATUS_SUCCESS) {
				break;
			}
		}
	}

	if (wr->suppress_response) {
		return MATTER_OK;
	}

	matter_tlv_writer_init(&w, out, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(TAG_WRESP_RESPONSES), MATTER_TLV_ARRAY);
	for (uint8_t i = 0u; i < (wr->truncated ? 1u : wr->n_items); i++) {
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		put_path(&w, MATTER_TLV_CTX(TAG_ASTATUS_PATH), &wr->items[i].path);
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(TAG_ASTATUS_STATUS),
						 MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_STATUS_STATUS), status[i]);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
	}
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_IM_REVISION), MATTER_IM_REVISION);
	(void)matter_tlv_end_container(&w);

	return matter_tlv_writer_finish(&w, out_len);
}

/* SubscribeRequestMessage.h:39-48 */
#define TAG_SUB_KEEP_SUBSCRIPTIONS 0u
#define TAG_SUB_MIN_INTERVAL       1u
#define TAG_SUB_MAX_INTERVAL       2u
#define TAG_SUB_ATTRIBUTE_REQUESTS 3u
#define TAG_SUB_EVENT_REQUESTS     4u
#define TAG_SUB_EVENT_FILTERS      5u
#define TAG_SUB_FABRIC_FILTERED    7u

/* SubscribeResponseMessage.h:39-42 */
#define TAG_SUBRESP_SUBSCRIPTION_ID 0u
#define TAG_SUBRESP_MAX_INTERVAL    2u

/**
 * Decode a Matter subscription request message from TLV to extract attribute paths and timing
 * parameters.
 * Parses SubscribeRequestMessage: attribute paths, min/max interval timers (in seconds),
 * keep_subscriptions and fabric_filtered flags.
 * Returns MATTER_E_INVAL if tlv or out is NULL; returns MATTER_E_TYPE if element types are wrong;
 * returns MATTER_E_NOSPACE if path count exceeds MATTER_IM_MAX_PATHS.
 */
int matter_im_subscribe_request_decode(const uint8_t *tlv, size_t len,
				       struct matter_im_subscribe *out)
{
	struct matter_tlv_reader r;
	int rc;

	if (tlv == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}
	memset(out, 0, sizeof(*out));

	matter_tlv_reader_init(&r, tlv, len);
	if (matter_tlv_next(&r) != MATTER_OK ||
	    matter_tlv_element_type(&r) != MATTER_TLV_STRUCTURE) {
		return MATTER_E_TYPE;
	}
	rc = matter_tlv_enter(&r);
	if (rc != MATTER_OK) {
		return rc;
	}

	for (;;) {
		uint64_t v = 0u;

		rc = matter_tlv_next(&r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}

		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_SUB_ATTRIBUTE_REQUESTS)) {
			if (matter_tlv_element_type(&r) != MATTER_TLV_ARRAY) {
				return MATTER_E_TYPE;
			}
			rc = matter_tlv_enter(&r);
			if (rc != MATTER_OK) {
				return rc;
			}
			for (;;) {
				rc = matter_tlv_next(&r);
				if (rc == MATTER_END) {
					break;
				}
				if (rc != MATTER_OK) {
					return rc;
				}
				if (matter_tlv_element_type(&r) != MATTER_TLV_LIST) {
					return MATTER_E_TYPE;
				}
				if (out->read.n_paths >= MATTER_IM_MAX_PATHS) {
					return MATTER_E_NOSPACE;
				}
				rc = decode_path(&r, &out->read.paths[out->read.n_paths]);
				if (rc != MATTER_OK) {
					return rc;
				}
				out->read.n_paths++;
			}
			rc = matter_tlv_exit(&r);
			if (rc != MATTER_OK) {
				return rc;
			}
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_SUB_EVENT_REQUESTS)) {
			rc = decode_event_paths(&r, &out->read);
			if (rc != MATTER_OK) {
				return rc;
			}
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_SUB_EVENT_FILTERS)) {
			rc = decode_event_filters(&r, &out->read);
			if (rc != MATTER_OK) {
				return rc;
			}
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_SUB_MIN_INTERVAL)) {
			if (matter_tlv_get_u64(&r, &v) == MATTER_OK && v <= UINT16_MAX) {
				out->min_interval_s = (uint16_t)v;
			}
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_SUB_MAX_INTERVAL)) {
			if (matter_tlv_get_u64(&r, &v) == MATTER_OK && v <= UINT16_MAX) {
				out->max_interval_s = (uint16_t)v;
			}
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_SUB_KEEP_SUBSCRIPTIONS)) {
			(void)matter_tlv_get_bool(&r, &out->keep_subscriptions);
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_SUB_FABRIC_FILTERED)) {
			(void)matter_tlv_get_bool(&r, &out->read.fabric_filtered);
		}
		/* Data-version filters are read past: this node reports every
		 * value every time. */
	}

	return matter_tlv_exit(&r);
}

/**
 * Encode a Matter subscription response message with subscription ID and maximum reporting
 * interval.
 * Wraps subscription details in TLV structure as initial reply to successful SubscribeRequest.
 * Returns MATTER_E_INVAL if out or out_len is NULL; returns encoder error if TLV encoding fails.
 */
int matter_im_subscribe_response_encode(uint32_t subscription_id, uint16_t max_interval_s,
					uint8_t *out, size_t cap, size_t *out_len)
{
	struct matter_tlv_writer w;

	if (out == NULL || out_len == NULL) {
		return MATTER_E_INVAL;
	}

	matter_tlv_writer_init(&w, out, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SUBRESP_SUBSCRIPTION_ID), subscription_id);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SUBRESP_MAX_INTERVAL), max_interval_s);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_IM_REVISION), MATTER_IM_REVISION);
	(void)matter_tlv_end_container(&w);

	return matter_tlv_writer_finish(&w, out_len);
}
