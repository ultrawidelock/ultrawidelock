/* SPDX-License-Identifier: ISC */

/**
 * @file matter_im.h — the Interaction Model, as far as a commissioner needs it.
 *
 * Once PASE is done the commissioner stops speaking Secure Channel and starts
 * asking questions. The first one is a ReadRequest, and until something answers
 * it the phone waits, gives up, and shows "pairing failed" with no further clue.
 *
 *   in    ReadRequest   (protocol 0x0001, opcode 0x02)
 *   out   ReportData    (protocol 0x0001, opcode 0x05)
 *
 * This is the read half only. Write, Invoke and Subscribe are separate messages
 * and land when something needs them; commissioning cannot start without Read.
 *
 * It holds no device data. Which endpoints exist and what their attributes say
 * is matter_clusters.h's, reached through @ref matter_im_server, so the wire
 * format can be tested without a device and the device without a wire.
 * Not guessable and not symmetric: AttributePathIB is a LIST (0x17 on the
 * wire), every other information block here is a STRUCTURE.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "matter_status.h"
#include "matter_tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol 0x0001 message types (protocols/interaction_model/Constants.h:59-70). */
#define MATTER_IM_OP_STATUS_RESPONSE         0x01u
#define MATTER_IM_OP_READ_REQUEST            0x02u
#define MATTER_IM_OP_REPORT_DATA             0x05u
#define MATTER_IM_OP_SUBSCRIBE_REQUEST       0x03u
#define MATTER_IM_OP_SUBSCRIBE_RESPONSE      0x04u
#define MATTER_IM_OP_WRITE_REQUEST           0x06u
#define MATTER_IM_OP_WRITE_RESPONSE          0x07u
#define MATTER_IM_OP_INVOKE_COMMAND_REQUEST  0x08u
#define MATTER_IM_OP_INVOKE_COMMAND_RESPONSE 0x09u
/**
 * TimedRequest, which precedes any command that must not be replayed.
 *
 * The peer sends this FIRST, waits for a StatusResponse, and only then sends
 * the invoke it actually wanted. Ignoring it is not an error anywhere: the
 * peer simply waits out its own timeout and reports the transaction as timed
 * out, which is what a real controller did to this node for ten seconds
 * before abandoning a pairing.
 */
#define MATTER_IM_OP_TIMED_REQUEST           0x0Au

/**
 * Interaction Model revision this node claims
 * (app/SpecificationDefinedRevisions.h:34). Sent under tag 0xFF (line 35),
 * which is why it is a define rather than an argument: a peer that disagrees
 * about the revision disagrees about the whole message.
 */
#define MATTER_IM_REVISION 12u

/*
 * Status codes, from protocols/interaction_model/StatusCodeList.h. Only the
 * ones a read can produce; the list is long and unused entries are noise.
 */
#define MATTER_IM_STATUS_SUCCESS               0x00u /* line 31 */
#define MATTER_IM_STATUS_FAILURE               0x01u /* line 32 */
/**
 * The peer knows the command and will not let this node run it (line 34).
 *
 * Both directions need it. As a server this node answers it when the
 * accessing fabric's access control list grants too little for the request.
 * As a client it is what a bound lock answers when ITS list has no entry for
 * this node, and it is the single most likely way a binding fails once
 * everything else is right. Reported as itself rather than as a generic
 * failure, because the fix is specific and the log line is the only place it
 * can be named.
 */
#define MATTER_IM_STATUS_UNSUPPORTED_ACCESS    0x7Eu
#define MATTER_IM_STATUS_UNSUPPORTED_ENDPOINT  0x7Fu /* line 35 */
#define MATTER_IM_STATUS_UNSUPPORTED_COMMAND   0x81u /* line 37 */
#define MATTER_IM_STATUS_INVALID_COMMAND       0x85u /* line 41 */
/** A field was well-formed but the wrong size or out of range (line 55). */
#define MATTER_IM_STATUS_CONSTRAINT_ERROR      0x87u
#define MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE 0x86u /* line 42 */
#define MATTER_IM_STATUS_UNSUPPORTED_WRITE     0x88u /* line 44 */
#define MATTER_IM_STATUS_RESOURCE_EXHAUSTED    0x89u /* line 45 */
#define MATTER_IM_STATUS_UNSUPPORTED_CLUSTER   0xC3u /* line 68 */
#define MATTER_IM_STATUS_FAILSAFE_REQUIRED     0xCAu /* line 75 */

/**
 * "This command succeeded and has no response payload."
 *
 * Most commands answer with a response command; some -- AddTrustedRootCertificate
 * among them -- answer with a bare SUCCESS status and nothing else. A handler
 * says so by leaving *response_command at this value, which is also what
 * matter_im_invoke_response_encode() initialises it to, so forgetting to set a
 * response command produces a legal empty reply rather than one claiming to be
 * command 0. kInvalidCommandId (lib/core/DataModelTypes.h:86).
 */
#define MATTER_IM_NO_RESPONSE 0xFFFFFFFFu

/**
 * How many attribute paths one ReadRequest may carry before this refuses it.
 *
 * A real iPhone's commissioning read asked for NINE. The bound exists so a peer
 * cannot choose how much stack this uses, and it is a refusal rather than a
 * truncation: answering some of what was asked, silently, would look to the
 * commissioner like the device genuinely has nothing more.
 */
#define MATTER_IM_MAX_PATHS 16

/**
 * One requested path. An absent field is a WILDCARD, and that distinction
 * decides how a path that matches nothing is answered -- see
 * matter_im_report_data_encode().
 */
struct matter_im_path {
	uint16_t endpoint;
	uint32_t cluster;
	uint32_t attribute;
	bool have_endpoint;
	bool have_cluster;
	bool have_attribute;
	uint16_t list_index;
	bool have_list_index;
	bool list_index_null;
};

/** True when any component is wildcarded (app/AttributePathParams.h:57-59). */
static inline bool matter_im_path_is_wildcard(const struct matter_im_path *p)
{
	return !p->have_endpoint || !p->have_cluster || !p->have_attribute;
}

/**
 * How many event paths one request may carry.
 *
 * Smaller than MATTER_IM_MAX_PATHS on purpose: a controller subscribes to every
 * attribute it can name, but the event set is one wildcard in practice, and each
 * path costs stack in a structure that is already static for that reason.
 */
#define MATTER_IM_MAX_EVENT_PATHS 4

/**
 * One requested EventPathIB.
 *
 * NOT the same shape as an attribute path, and not the same tag numbers either
 * (EventPathIB.h:38-44 puts Endpoint at 1 where AttributePathIB.h puts it at 2),
 * so it is a separate structure rather than a reused one. An absent field is a
 * wildcard, as it is for attributes.
 */
struct matter_im_event_path {
	uint16_t endpoint;
	uint32_t cluster;
	uint32_t event;
	bool have_endpoint;
	bool have_cluster;
	bool have_event;
};

/** A decoded ReadRequest. */
struct matter_im_read {
	struct matter_im_path paths[MATTER_IM_MAX_PATHS];
	uint8_t n_paths;
	/**
	 * The events asked for, if any. A request carrying none gets an empty
	 * EventReports array -- not every event this node happens to hold.
	 */
	struct matter_im_event_path event_paths[MATTER_IM_MAX_EVENT_PATHS];
	uint8_t n_event_paths;
	/**
	 * The lowest EventNumber the peer still wants, from EventFilterIB
	 * (EventFilterIB.h:38-41). A subscriber that has already seen event 7
	 * sends 8 here, and re-reporting 7 would have it show the same unlock
	 * twice. Zero asks for everything held.
	 */
	uint64_t event_min;
	/** As sent; recorded rather than acted on, since nothing here is fabric-scoped yet. */
	bool fabric_filtered;
	/**
	 * Non-zero turns a report into a subscription's PRIMING report: the
	 * SubscriptionId is written and SuppressResponse becomes false, because
	 * the peer's StatusResponse to that report is what the SubscribeResponse
	 * answers (ReadHandler.cpp:240-250). A plain read leaves this at zero
	 * and suppresses the response, which is what Engine.cpp:834-836 does.
	 */
	uint32_t subscription_id;
};

/** One bounded app-owned cursor for a chunked Read interaction. */
struct matter_im_read_state {
	struct matter_im_read read;
	uint16_t session_id;
	uint16_t exchange_id;
	uint16_t sent;
	bool more;
	bool in_use;
	bool over_thread;
};

/** Caller-backed set of simultaneous chunked Read interactions. */
struct matter_im_read_pool {
	struct matter_im_read_state *slots;
	size_t n_slots;
};

/** Attach and clear @p n_slots Read cursors. */
int matter_im_read_pool_init(struct matter_im_read_pool *pool,
			     struct matter_im_read_state *slots, size_t n_slots);

/** Find a cursor only when session, exchange, and transport all match. */
struct matter_im_read_state *matter_im_read_pool_find(struct matter_im_read_pool *pool,
						       uint16_t session_id,
						       uint16_t exchange_id,
						       bool over_thread);

/**
 * Reserve a cursor for a new Read.
 *
 * MATTER_E_DUP returns the existing cursor without resetting it. MATTER_E_NOSPACE
 * means every bounded cursor is live. On MATTER_OK the returned cursor is fresh.
 */
int matter_im_read_pool_acquire(struct matter_im_read_pool *pool, uint16_t session_id,
				uint16_t exchange_id, bool over_thread,
				struct matter_im_read_state **out);

/**
 * Commit or reject transport completion for one Read chunk.
 *
 * A non-OK @p status drops the cursor. Successful final chunks also release it.
 */
int matter_im_read_pool_finish(struct matter_im_read_pool *pool, uint16_t session_id,
			       uint16_t exchange_id, bool over_thread, uint16_t emitted,
			       bool more, int status);

/** Drop every cursor for one secure session on one transport. */
void matter_im_read_pool_drop_session(struct matter_im_read_pool *pool, uint16_t session_id,
				      bool over_thread);

/** A SubscribeRequest: the same paths a read asks for, plus how often. */
struct matter_im_subscribe {
	struct matter_im_read read;
	uint16_t min_interval_s;
	uint16_t max_interval_s;
	bool keep_subscriptions;
};

/**
 * Decode a SubscribeRequestMessage (app/MessageDef/SubscribeRequestMessage.h).
 *
 * The paths live at tag 3 here and at tag 0 in a ReadRequest, which is the only
 * reason this is not the read decoder.
 *
 * @return MATTER_OK; MATTER_E_NOSPACE past MATTER_IM_MAX_PATHS;
 *         MATTER_E_INVAL for a malformed message.
 */
int matter_im_subscribe_request_decode(const uint8_t *tlv, size_t len,
				       struct matter_im_subscribe *out);

/**
 * Encode a SubscribeResponseMessage (SubscribeResponseMessage.h:39-42).
 *
 * Sent LAST, after the priming report has been answered with a StatusResponse
 * -- not in reply to the SubscribeRequest itself. Sending it first leaves the
 * subscriber holding an id for a subscription whose initial values it never
 * received.
 *
 * @param max_interval_s what this node COMMITS to, which must be no larger than
 *        the ceiling the subscriber asked for: it is the deadline by which the
 *        next report has to arrive or the subscription is considered dead.
 */
int matter_im_subscribe_response_encode(uint32_t subscription_id, uint16_t max_interval_s,
					uint8_t *out, size_t cap, size_t *out_len);

/**
 * Encode a bare StatusResponseMessage (app/MessageDef/StatusResponseMessage.h).
 *
 * This is the whole answer to a TimedRequest, and it is also what a subscriber
 * sends back after a priming report -- the same message in both directions.
 */
int matter_im_status_response_encode(uint8_t status, uint8_t *out, size_t cap, size_t *out_len);

/**
 * Decode a bare StatusResponseMessage.
 *
 * @return MATTER_OK with @p status set, or a parse error when the structure is
 *         malformed or omits its mandatory Status field.
 */
int matter_im_status_response_decode(const uint8_t *buf, size_t len, uint8_t *status);

/**
 * Decode a TimedRequestMessage, whose only field is the timeout.
 *
 * The timeout is the peer's own deadline for sending the invoke that follows,
 * measured from when it receives the StatusResponse. Nothing here has to
 * enforce it to interoperate; a node that does enforce it must answer a late
 * invoke with TIMEOUT rather than running it.
 *
 * @return MATTER_OK, or MATTER_E_INVAL / MATTER_E_TRUNC on a malformed message.
 */
int matter_im_timed_request_decode(const uint8_t *buf, size_t len, uint16_t *timeout_ms);

/**
 * Decode a ReadRequestMessage (app/MessageDef/ReadRequestMessage.h).
 *
 * @return MATTER_OK; MATTER_E_NOSPACE when the peer asked for more than
 *         MATTER_IM_MAX_PATHS paths; MATTER_E_INVAL for a malformed message; or
 *         whatever the TLV decoder returned.
 */
int matter_im_read_request_decode(const uint8_t *tlv, size_t len, struct matter_im_read *out);

/**
 * What answering this path will produce, WITHOUT writing anything.
 *
 * Split from writing the value on purpose. An information block is built
 * outside-in -- container, data version, path, then the value -- so by the time
 * a writing callback could report a failure, three fields are already committed
 * and TLV offers no way to take them back. Asking first means the encoder never
 * has to unwind, which matters because the writer latches its first error and
 * turns later calls into no-ops: an unwind would have to reason about container
 * depth that was never incremented.
 *
 * @return MATTER_IM_STATUS_SUCCESS, or the status explaining why not --
 *         UNSUPPORTED_ATTRIBUTE when the cluster exists but the attribute does
 *         not, UNSUPPORTED_CLUSTER when the endpoint exists but the cluster
 *         does not, UNSUPPORTED_ENDPOINT when it does not
 *         (app/data-model-provider/MetadataLookup.cpp:68-88 chooses in that
 *         order).
 */
typedef uint8_t (*matter_im_status_fn)(void *ctx, uint16_t endpoint, uint32_t cluster,
				       uint32_t attribute);

/**
 * Write one attribute's value. Called only after @ref matter_im_status_fn
 * returned SUCCESS for the same path, so it has nothing to refuse.
 *
 * @param w write EXACTLY ONE element, tagged @p tag. A structure is one
 *          element; two siblings are not. Errors need no checking -- the writer
 *          latches them and the encoder reports them once at the end.
 */
typedef void (*matter_im_value_fn)(void *ctx, uint16_t endpoint, uint32_t cluster,
				   uint32_t attribute, bool fabric_filtered,
				   struct matter_tlv_writer *w,
				   matter_tlv_tag_t tag);

/**
 * Does @p endpoint carry @p cluster?
 *
 * Only consulted for wildcard paths, where a miss must be silent rather than an
 * error, so this decides between answering and saying nothing at all.
 */
typedef bool (*matter_im_has_cluster_fn)(void *ctx, uint16_t endpoint, uint32_t cluster);

/** One command a commissioner asked this node to run. */
struct matter_im_invoke {
	uint16_t endpoint;
	uint32_t cluster;
	uint32_t command;
	/** The command's arguments, as TLV. Points into the caller's buffer. */
	const uint8_t *fields;
	size_t fields_len;
	bool has_fields;
	/**
	 * The commissioner's own handle for this command, echoed in the response
	 * when it sent one. Batched invokes need it to match responses to
	 * requests; a single invoke does not, and Apple's ArmFailSafe omits it.
	 */
	uint64_t command_ref;
	bool has_command_ref;
	bool suppress_response;
	bool timed_request;
};

/**
 * Run one command.
 *
 * Called EXACTLY ONCE per request, which is why it is separate from writing the
 * reply: this is where side effects belong. Anything the response needs must be
 * recorded in the device's own state here, because
 * @ref matter_im_command_fields_fn runs afterwards and must be pure.
 *
 * @param response_command receives the command id to answer with. Ignored
 *        unless SUCCESS is returned.
 * @return MATTER_IM_STATUS_SUCCESS to send a command response, or the status to
 *         send instead -- UNSUPPORTED_COMMAND when the cluster exists but the
 *         command does not, INVALID_COMMAND when its arguments do not parse.
 */
typedef uint8_t (*matter_im_command_fn)(void *ctx, const struct matter_im_invoke *inv,
					uint32_t *response_command);

/**
 * Write the fields of the response @ref matter_im_command_fn chose.
 *
 * Pure: it serialises what the command already computed. Write exactly one
 * element, tagged @p tag, as with @ref matter_im_value_fn.
 */
typedef void (*matter_im_command_fields_fn)(void *ctx, uint16_t endpoint, uint32_t cluster,
					    uint32_t response_command, struct matter_tlv_writer *w,
					    matter_tlv_tag_t tag);

/**
 * List the attributes of one cluster, for expanding a wildcard read.
 *
 * @param out receives a pointer to a static array of attribute ids.
 * @return how many, or 0 when the cluster is not on that endpoint.
 */
typedef size_t (*matter_im_list_attrs_fn)(void *ctx, uint16_t endpoint, uint32_t cluster,
					  const uint32_t **out);

/**
 * Every cluster on one endpoint, for expanding a path that names none.
 *
 * A commissioner that has just adopted a node subscribes to ALL of it -- no
 * endpoint, no cluster, no attribute -- and that is not an edge case, it is
 * what Apple does immediately after writing its ACL. Returning 0 makes such a
 * subscription report nothing at all, which the subscriber cannot distinguish
 * from a node that has stopped talking.
 *
 * @param out receives a pointer to a static array of cluster ids.
 * @return how many, or 0 when the endpoint does not exist.
 */
typedef size_t (*matter_im_list_clusters_fn)(void *ctx, uint16_t endpoint, const uint32_t **out);

/**
 * Every endpoint this node has, for expanding a path that names none.
 *
 * A commissioner asks about a cluster without saying where it lives -- Apple
 * reads NetworkCommissioning exactly that way -- and the only honest answer is
 * to look on each endpoint. Returning 0 makes such a path unanswerable, which
 * reads to the commissioner as a node that has no such cluster anywhere.
 *
 * @param out receives a borrowed array. @return how many.
 */
typedef size_t (*matter_im_list_endpoints_fn)(void *ctx, const uint16_t **out);

/**
 * Apply one attribute write. Supplied by the cluster layer.
 *
 * @param data the encoded value, exactly as it arrived.
 * @return an IM status: MATTER_IM_STATUS_SUCCESS, or
 *         MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE / _CLUSTER / _ENDPOINT for a
 *         path this node does not have, which is what tells a commissioner the
 *         difference between "refused" and "does not exist".
 */
typedef uint8_t (*matter_im_write_fn)(void *ctx, const struct matter_im_path *path,
				      const uint8_t *data, size_t data_len);

/**
 * One event this node is holding, as a report needs to describe it.
 *
 * The DATA is not here: it is written straight into the report by
 * @ref matter_im_event_data_fn, because an event's fields are cluster-specific
 * and copying them through a union would make this structure grow with every
 * event the node learns to emit.
 */
struct matter_im_event {
	uint16_t endpoint;
	uint32_t cluster;
	uint32_t event;
	/**
	 * Monotonic within a boot and never reused. A subscriber uses it to ask
	 * for what it has not seen (EventFilterIB), so an id that repeats after a
	 * reboot has the subscriber silently skip a real unlock.
	 */
	uint64_t number;
	/** Milliseconds since boot. Not a wall clock; see the encoder's note. */
	uint64_t timestamp_ms;
	/** MATTER_EVENT_PRIORITY_*, from EventLoggingTypes.h:51-36. */
	uint8_t priority;
};

/**
 * How many events this node currently holds.
 *
 * The set is walked by INDEX, oldest first, and an index is only valid until the
 * ring evicts. Nothing here caches one across a call.
 */
typedef size_t (*matter_im_event_count_fn)(void *ctx);

/**
 * Describe event @p index. @return false when the index is out of range, which
 * is how a walk stops if the ring changed under it.
 */
typedef bool (*matter_im_event_at_fn)(void *ctx, size_t index, struct matter_im_event *out);

/**
 * Write event @p index's fields as EXACTLY ONE element, tagged @p tag -- the
 * same contract as @ref matter_im_value_fn, and a structure counts as one.
 */
typedef void (*matter_im_event_data_fn)(void *ctx, size_t index, struct matter_tlv_writer *w,
					matter_tlv_tag_t tag);

/**
 * Callback table for the Matter interaction model server, defining functions to query attribute
 * status, read values, list endpoints and clusters, and handle write and command operations.
 */
struct matter_im_server {
	matter_im_status_fn status;
	matter_im_value_fn value;
	matter_im_has_cluster_fn has_cluster;
	matter_im_list_attrs_fn list_attrs;
	matter_im_list_endpoints_fn list_endpoints;
	matter_im_list_clusters_fn list_clusters;
	matter_im_command_fn command;
	matter_im_command_fields_fn command_fields;
	/** NULL means this node accepts no writes at all. */
	matter_im_write_fn write;
	/** All three NULL together means this node reports no events. */
	matter_im_event_count_fn event_count;
	matter_im_event_at_fn event_at;
	matter_im_event_data_fn event_data;
	void *ctx;
};

/**
 * Decode an InvokeRequestMessage (app/MessageDef/InvokeRequestMessage.h).
 *
 * Exactly one command per message. Matter allows a batch, and this refuses one
 * with MATTER_E_NOSPACE rather than silently running the first: a commissioner
 * that batched two commands and saw one response would be entitled to assume
 * both ran.
 *
 * @return MATTER_OK, MATTER_E_NOSPACE for a batch, MATTER_E_INVAL for a
 *         malformed message, or whatever the TLV decoder returned.
 */
/**
 * One attribute write.
 *
 * Exactly one per message, the same restriction matter_im_invoke has and for
 * the same reason: a commissioner that sent two and saw one status would be
 * entitled to assume both applied.
 */
/** A bounded list transaction: ReplaceAll plus at most four appended entries. */
#define MATTER_IM_MAX_WRITES 5u

struct matter_im_write_item {
	struct matter_im_path path;
	/**
	 * The value, still encoded. Points into the caller's buffer.
	 *
	 * Left as TLV rather than decoded because an attribute's type is the
	 * cluster's business, not the Interaction Model's -- an ACL is a list of
	 * structures and there is nothing useful this layer could turn it into.
	 */
	const uint8_t *data;
	size_t data_len;
};

struct matter_im_write {
	struct matter_im_write_item items[MATTER_IM_MAX_WRITES];
	uint8_t n_items;
	bool suppress_response;
	bool timed_request;
	/**
	 * The request named more attributes than this node can carry (one), so
	 * @ref path holds the FIRST and the rest were dropped unparsed.
	 *
	 * Matter has no MaxAttributesPerWrite for a device to advertise the way
	 * MaxPathsPerInvoke declares the invoke cap, so a peer cannot know the
	 * limit before it writes. The encoder answers such a request with
	 * RESOURCE_EXHAUSTED and runs NOTHING: the peer asked for a set, and
	 * applying an arbitrary member of it is a worse answer than refusing --
	 * and either way it gets an answer, where it used to get silence.
	 */
	bool truncated;
};

/**
 * Decode a WriteRequestMessage (app/MessageDef/WriteRequestMessage.h:39-44).
 *
 * @return MATTER_OK, MATTER_E_NOSPACE for a batch, MATTER_E_INVAL for a
 *         malformed message or a path that is not concrete -- a wildcard write
 *         is refused rather than expanded, because guessing which attributes a
 *         commissioner meant to overwrite is not a recoverable mistake.
 */
int matter_im_write_request_decode(const uint8_t *tlv, size_t len, struct matter_im_write *out);

/**
 * Run the write and encode its WriteResponseMessage.
 *
 * @param out_len set to 0 when the request suppressed the response, which is
 *        not an error: the write still ran.
 */
int matter_im_write_response_encode(const struct matter_im_server *srv,
				    const struct matter_im_write *wr, uint8_t *out, size_t cap,
				    size_t *out_len);

int matter_im_invoke_request_decode(const uint8_t *tlv, size_t len, struct matter_im_invoke *out);

/**
 * Run @p inv and encode the InvokeResponseMessage answering it.
 *
 * The command runs even when the peer set SuppressResponse -- it asked for the
 * effect, not for silence about it -- but then @p out_len is set to 0 and there
 * is nothing to send.
 *
 * @return MATTER_OK, MATTER_E_NOSPACE, or MATTER_E_INVAL.
 */
int matter_im_invoke_response_encode(const struct matter_im_server *srv,
				     const struct matter_im_invoke *inv, uint8_t *out, size_t cap,
				     size_t *out_len);

/** What encoding a report had to leave out. Worth logging; none of it is fatal. */
struct matter_im_report_stats {
	/** Wildcard paths skipped because the cluster is not on that endpoint. Correct. */
	uint8_t skipped_wildcard;
	/**
	 * Wildcard paths over a cluster this node DOES have.
	 *
	 * Answering one means enumerating a cluster's attributes, which nothing
	 * has asked for yet and which this does not do. The path is skipped and
	 * counted, so an under-reported read shows up in a log line instead of
	 * looking to the commissioner like an empty cluster.
	 */
	uint8_t unexpanded_wildcard;
};

/**
 * Encode the ReportData answering @p req.
 *
 * The rule that is easy to get backwards, and is not symmetric:
 *
 *   - A CONCRETE path naming something unsupported gets an AttributeStatusIB.
 *     Reporting nothing would tell the commissioner the attribute is absent
 *     from a device that never said so (reporting/Engine.cpp:92-106, 495).
 *   - A WILDCARD path matching nothing gets SILENCE. An error would claim the
 *     whole expansion failed (AttributePathExpandIterator.cpp:239-255).
 *
 * SuppressResponse is set, because this answers a Read rather than a Subscribe
 * and CHIP sets it for exactly that case (reporting/Engine.cpp:834-836). The
 * commissioner therefore sends no StatusResponse and the exchange simply ends.
 *
 * Chunking is not implemented: an answer too large for @p cap fails rather than
 * setting MoreChunkedMessages. A truncated report is indistinguishable from a
 * complete one to the peer, so it must not be possible to send one by accident.
 *
 * @param stats optional; may be NULL.
 * @return MATTER_OK, MATTER_E_NOSPACE if the report does not fit, or
 *         MATTER_E_INVAL.
 */
int matter_im_report_data_encode(const struct matter_im_server *srv,
				 const struct matter_im_read *req, uint8_t *out, size_t cap,
				 size_t *out_len, struct matter_im_report_stats *stats);

/**
 * The most a Matter message may be, per spec.
 *
 * The guaranteed IPv6 MTU is 1280 bytes and Matter does not exceed it
 * (CHIPConfig.h:320-324); over Thread there is nothing to fragment for. A
 * report larger than this is not slow, it is UNDELIVERABLE -- the subscriber
 * simply never sees it and re-subscribes forever, which is exactly what a
 * 1513-byte report produced.
 */
#define MATTER_MAX_MESSAGE_LEN 1232u

/**
 * Encode ONE CHUNK of a report, continuing where the last one stopped.
 *
 * A controller subscribes to the whole data model, and this node's answer to
 * that does not fit one message. The spec's answer is MoreChunkedMessages: send
 * what fits, let the peer acknowledge it with a StatusResponse, send the rest.
 *
 * @param sent how many attribute reports previous chunks already carried. Zero
 *        starts a fresh report. Expansion is deterministic, so re-walking and
 *        skipping is equivalent to resuming -- and far harder to get wrong than
 *        a cursor into four nested loops.
 * @param more set true when reports remain; the caller adds @p emitted to
 *        @p sent and calls again once the peer has acknowledged this chunk.
 * @param emitted how many this chunk carried. Zero with @p more true means not
 *        even one report fits in @p cap, which is a caller bug, not a chunk.
 */
int matter_im_report_data_chunk(const struct matter_im_server *srv,
				const struct matter_im_read *req, uint16_t sent, uint8_t *out,
				size_t cap, size_t *out_len, bool *more, uint16_t *emitted,
				struct matter_im_report_stats *stats);

#ifdef __cplusplus
}
#endif
