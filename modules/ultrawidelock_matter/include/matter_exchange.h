/* SPDX-License-Identifier: ISC */

/**
 * @file matter_exchange.h — the unsecured exchange PASE runs on.
 *
 * Between BTP (a byte pipe) and PASE (five messages) sits the part that makes a
 * Matter message a message: which session it belongs to, which exchange, whether
 * it is a duplicate, and whether the peer is owed an acknowledgement.
 *
 *   in    message header | protocol header | payload
 *   out   message header | protocol header | payload
 *
 * This handles exactly one exchange on the UNSECURED session, which is all
 * commissioning needs before PASE finishes: session id 0, no encryption, the
 * peer as initiator and this node as responder. Secure sessions are a different
 * object -- they carry keys and a different counter -- and arrive with CASE.
 *
 * It deliberately does not know what PASE is: it reports the opcode and hands
 * back the payload. No timers -- retransmission is matter_mrp.h's, driven by
 * whoever owns a clock. Easy to get backwards: the responder echoes the
 * initiator's exchange id unchanged and clears I, never allocating its own.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "matter_crypto.h"
#include "matter_mrp.h"
#include "matter_msg.h"
#include "matter_status.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Protocol 0x0000, vendor 0x0000. The only protocol this layer accepts. */
#define MATTER_PROTOCOL_SECURE_CHANNEL 0x0000u

/** Session id 0 is the unsecured session, by definition rather than by policy. */
#define MATTER_SESSION_ID_UNSECURED 0x0000u

/**
 * Worst-case bytes this prepends to a payload.
 *
 * Both headers at their largest. Real unsecured commissioning messages are far
 * smaller -- 8 + 6 with an ack, no node ids -- but a caller sizing a buffer
 * should not have to know that.
 */
#define MATTER_EXCHANGE_HEADER_MAX (MATTER_MSG_HEADER_MAX + MATTER_PROTO_HEADER_MAX)

/*
 * Exact-response replay for small, state-changing commissioning commands.
 * CommissioningComplete, AddNOC and RemoveFabric responses fit below this
 * bound. Large reports use their normal subscription/MRP path and fall back to
 * a standalone acknowledgement when no bounded replay is available.
 */
#define MATTER_EXCHANGE_REPLAY_MAX 192u

/**
 * Protocol 0x0001. Everything after commissioning's Secure Channel phase.
 */
#define MATTER_PROTOCOL_INTERACTION_MODEL 0x0001u

/**
 * Matter exchange state including secure session keys, local and peer session IDs, MRP settings,
 * exchange ID tracking, message counters, and acknowledgement tracking for a single commissioner
 * session.
 */
struct matter_exchange {
	/**
	 * The secure session, once PASE has built one.
	 *
	 * This object deliberately carries the session as well as the exchange,
	 * which Matter separates. That is sound HERE and nowhere wider: this node
	 * accepts one commissioner at a time (CONFIG_BT_MAX_CONN=1, and
	 * claim_conn() refuses a second), so there is never more than one session
	 * or more than one live exchange to track. A node that had to serve two
	 * exchanges at once would have to split them.
	 *
	 * `secure` false means the unsecured session, id 0, no keys.
	 */
	bool secure;
	/** The id the peer must address us with. Announced in PBKDFParamResponse. */
	uint16_t local_session_id;
	/** The id we address the peer with (SessionManager.cpp:264). */
	uint16_t peer_session_id;
	/**
	 * Keys are role-relative. As the responder we DECRYPT with i2r and
	 * ENCRYPT with r2i -- CryptoContext.cpp:77-78,102-103 selects them by
	 * role, and getting them the wrong way round produces a tag failure with
	 * no hint as to why.
	 */
	struct matter_session_keys keys;
	/**
	 * Whether MRP runs on this exchange at all.
	 *
	 * It does NOT over BLE. Matter gates reliable messaging on the transport:
	 * SecureSession.h:161 and UnauthenticatedSessionTable.h:87 both define
	 * AllowsMRP() as "the peer address is UDP", and ExchangeContext.cpp:109-112
	 * only sets the R flag when the session allows MRP. BTP already guarantees
	 * delivery and ordering, so acknowledging on top of it is duplicated work
	 * the peer does not expect.
	 *
	 * Getting this wrong is not cosmetic. A real iPhone sent
	 * PBKDFParamRequest with exchange flags 0x01 -- I only, no R -- and
	 * dropped the link on a reply that came back with R set and no ack.
	 */
	bool mrp;
	/**
	 * The initiator's ephemeral node id, and whether it sent one.
	 *
	 * On an unsecured session the initiator picks an ephemeral node id and
	 * puts it in the source field; the RESPONDER must send it back as the
	 * DESTINATION, which is how the peer matches a reply to its session.
	 * SessionManager.cpp:296-303 makes the asymmetry explicit: initiator sets
	 * source, responder sets destination.
	 *
	 * Omitting it does not produce an error anywhere. A real iPhone simply
	 * ignored our PBKDFParamResponse and sat on "connecting" until it gave up.
	 */
	uint64_t peer_node_id;
	bool have_peer_node_id;
	/**
	 * The two OPERATIONAL node ids, which are what the AEAD nonce is built
	 * from once a CASE session is running.
	 *
	 * Not the same thing as @ref peer_node_id above: that one is the
	 * initiator's ephemeral id and exists to address unsecured replies.
	 * These are the fabric identities, they never appear in a header, and
	 * both sides are simply expected to know them.
	 *
	 * Zero for PASE, which is correct rather than a placeholder -- a PASE
	 * session has no operational identity and CHIP uses kUndefinedNodeId for
	 * it explicitly (SessionManager.cpp:949-950).
	 */
	uint64_t local_op_node_id;
	uint64_t peer_op_node_id;
	/** The initiator's exchange id, echoed on every reply. */
	uint16_t exchange_id;
	/**
	 * True once a message has fixed @ref exchange_id.
	 *
	 * One exchange at a time, which is all a single commissioner needs. On a
	 * SECURE session an authenticated peer may replace it by initiating a new
	 * one -- Matter gives every interaction its own exchange -- so this node
	 * follows the peer from one to the next rather than holding the first
	 * forever. On the unsecured session it does not: see matter_exchange_recv().
	 */
	bool open;
	/**
	 * Exchange ids this node OPENED, newest last, wrapping.
	 *
	 * @ref exchange_id follows the PEER. It says nothing about the exchanges
	 * this node initiates -- subscription reports, which go out with their own
	 * ids through matter_exchange_send_initiator(). The peer acknowledges each
	 * one, and that acknowledgement arrives with I CLEAR and an exchange id
	 * that is not the peer's current one, which is indistinguishable from a
	 * reply to a conversation this node never started unless the ids it did
	 * start are remembered. They were not, so every report was refused its
	 * ack and retransmitted for the whole MRP schedule -- measured on
	 * hardware as bursts of "CASE message refused (-4)" after each report.
	 *
	 * Four, because a report goes to every subscription (two fabrics today)
	 * and the next event can be reported before the acks for the last one
	 * arrive. Older ids fall off, which costs a refusal for an ack that late
	 * and nothing else.
	 */
	uint16_t init_exchange[4];
	uint8_t init_exchange_n;
	/** Counters this node stamps on what it sends. */
	struct matter_counter counter;
	/** Counters seen from the peer, for duplicate suppression. */
	struct matter_mrp_window window;
	/**
	 * The peer counter this node still owes an acknowledgement for, and
	 * whether it owes one at all. Matter piggybacks the ack on the reply
	 * when there is one, which is the normal case here: every PASE message
	 * except the last is answered immediately.
	 */
	uint32_t ack_counter;
	bool ack_pending;
	/** Exact last bounded response, keyed by the peer counter it acknowledged. */
	uint8_t replay[MATTER_EXCHANGE_REPLAY_MAX];
	uint16_t replay_len;
	uint32_t replay_peer_counter;
	uint32_t replay_out_counter;
};

/**
 * PASE sessions have no operational identity, so the AEAD nonce carries node id
 * zero in both directions (SecureSession.h:337, kUndefinedNodeId). CASE brings
 * real node ids and will need them here.
 */
#define MATTER_PASE_NODE_ID 0ULL

/**
 * What a received message turned out to be.
 *
 * @ref opcode, @ref protocol_id, @ref exchange_id and @ref initiator are set
 * even when matter_exchange_recv() goes on to REFUSE the message, so a caller
 * can log what it turned away. The rest is meaningful only on MATTER_OK.
 */
struct matter_exchange_in {
	uint8_t opcode;
	/** Secure Channel, or the Interaction Model once the session is secure. */
	uint16_t protocol_id;
	/** The exchange the peer sent this on. */
	uint16_t exchange_id;
	/** True when the peer set I, claiming to have opened this exchange. */
	bool initiator;
	/** Points into the caller's buffer; not copied. */
	const uint8_t *payload;
	size_t payload_len;
	/** True when the peer set R and expects an acknowledgement. */
	bool ack_requested;
	/** True when the peer acknowledged something of ours. */
	bool carries_ack;
	uint32_t acked_counter;
};

/** Lifecycle of one caller-owned outbound packet slot. */
enum matter_tx_slot_state {
	MATTER_TX_SLOT_FREE = 0,
	MATTER_TX_SLOT_BUILDING,
	MATTER_TX_SLOT_READY,
	MATTER_TX_SLOT_IN_FLIGHT,
};

/**
 * Metadata for one bounded outbound packet.
 *
 * The bytes remain caller-owned. The pool owns only their lifecycle, which is
 * the important distinction from a transport borrowing an unrelated scratch
 * buffer: a READY or IN_FLIGHT slot cannot be acquired or overwritten until
 * the transport explicitly completes or rejects its token.
 */
struct matter_tx_slot {
	uint8_t *data;
	size_t capacity;
	size_t len;
	uint32_t token;
	uint32_t order;
	/** Absolute modular-ms deadline for a retained transport retry. */
	uint32_t retry_deadline_ms;
	uint8_t transport;
	bool retry_deadline_set;
	enum matter_tx_slot_state state;
};

/** A fixed caller-supplied set of outbound packet slots. */
struct matter_tx_pool {
	struct matter_tx_slot *slots;
	size_t n_slots;
	uint32_t next_token;
	uint32_t next_order;
};

/** Attach @p n_slots equally sized buffers to a fresh outbound pool. */
int matter_tx_pool_init(struct matter_tx_pool *pool, struct matter_tx_slot *slots, uint8_t *backing,
			size_t n_slots, size_t slot_capacity);

/** Reserve a free slot for one transport. NULL means the bounded pool is full. */
struct matter_tx_slot *matter_tx_pool_acquire(struct matter_tx_pool *pool, uint8_t transport);

/** Publish the bytes built in a BUILDING slot. */
int matter_tx_slot_commit(struct matter_tx_slot *slot, size_t len);

/** Oldest READY slot for @p transport, or NULL. */
struct matter_tx_slot *matter_tx_pool_ready(struct matter_tx_pool *pool, uint8_t transport);

/** The transport accepted the slot and now borrows its bytes asynchronously. */
int matter_tx_slot_in_flight(struct matter_tx_slot *slot);

/** Find a live slot by the opaque token assigned at acquire time. */
struct matter_tx_slot *matter_tx_pool_find(struct matter_tx_pool *pool, uint32_t token);

/**
 * Return an accepted packet to READY after this send attempt was rejected.
 * Its bytes and token remain owned for an exact reliable-transport retry.
 */
int matter_tx_pool_retry(struct matter_tx_pool *pool, uint32_t token, uint32_t now_ms,
			 uint32_t retain_ms);

/** First READY retry whose modular deadline has passed, or NULL. */
struct matter_tx_slot *matter_tx_pool_expired(struct matter_tx_pool *pool, uint8_t transport,
					      uint32_t now_ms);

/** Release a BUILDING token when encoding or framing failed before publication. */
int matter_tx_pool_cancel(struct matter_tx_pool *pool, uint32_t token);

/** Release an IN_FLIGHT token after successful transport completion. */
int matter_tx_pool_complete(struct matter_tx_pool *pool, uint32_t token);

/** Release a READY/IN_FLIGHT token after transport rejection or failure. */
int matter_tx_pool_reject(struct matter_tx_pool *pool, uint32_t token);

/**
 * @param entropy a random word seeding the outbound counter; see
 *        matter_counter_init(). Unsecured counters wrap, so this is about not
 *        advertising uptime, not about safety.
 * @param mrp false for BLE, true for UDP. See struct matter_exchange::mrp --
 *        this is a property of the transport, not a preference.
 */
void matter_exchange_init(struct matter_exchange *x, uint32_t entropy, bool mrp);

/**
 * Decode one received message.
 *
 * Everything here arrives from an unauthenticated peer -- the unsecured session
 * is where a commissioner is still a stranger -- so the checks are exhaustive
 * rather than trusting: version, DSIZ, session id, session type, protocol id,
 * and the vendor flag are all refused rather than ignored when wrong.
 *
 * @param pt scratch for the plaintext of an encrypted message; @p in points into
 *        it. Needs @p len bytes. Unused, and may be NULL, while unsecured.
 * @return MATTER_OK; MATTER_E_DUP when the counter has been seen, in which case
 *         the peer must still be acknowledged but @p in must NOT be acted on;
 *         MATTER_E_STATE for a message on another exchange that this node will
 *         not follow -- a second exchange on the UNSECURED session, which means
 *         a second commissioner, or one that arrives with I clear and so is a
 *         reply to nothing; MATTER_E_INVAL for a message this layer will not
 *         carry; or whatever the header decoders returned.
 */
int matter_exchange_recv(struct matter_exchange *x, const uint8_t *msg, size_t len,
			 struct matter_exchange_in *in, uint8_t *pt, size_t pt_cap);

/**
 * Decode a private mutable receive buffer without a second plaintext scratch.
 *
 * Secure ciphertext after the message header is replaced by plaintext only
 * after AEAD processing. @p in points into @p msg until the caller reuses it.
 * Authentication failure zeroes the unauthenticated body. Unsecured messages
 * are parsed in place without modification.
 */
int matter_exchange_recv_in_place(struct matter_exchange *x, uint8_t *msg, size_t len,
				  struct matter_exchange_in *in);

/**
 * Adopt the secure session PASE just established.
 *
 * After this, messages addressed to @p local_id are decrypted and anything on
 * the unsecured session is refused: a peer that has keys has no business
 * talking in the clear.
 *
 * The exchange id is deliberately released here. The commissioner opens a NEW
 * exchange on the secure session -- PASE's exchange is finished -- so holding
 * the old id would refuse the first real message.
 *
 * @param entropy seeds a FRESH counter. Secure sessions must not reuse the
 *        unsecured session's counter space: a repeated counter under the same
 *        key repeats an AEAD nonce.
 */
int matter_exchange_promote(struct matter_exchange *x, uint16_t local_id, uint16_t peer_id,
			    const struct matter_session_keys *keys, uint32_t entropy);

/**
 * Name the operational identities a CASE session's nonces are built from.
 *
 * Call after matter_exchange_promote() for a CASE session; PASE must not call
 * it at all. The node ids travel in no header, so a wrong pair here produces
 * messages that are byte-perfect and simply will not authenticate -- and the
 * peer has nothing to report but silence.
 *
 * @param local this node's operational node id, used when sealing.
 * @param peer the far side's, used when opening.
 */
void matter_exchange_set_op_node_ids(struct matter_exchange *x, uint64_t local, uint64_t peer);

/**
 * Frame a reply on this exchange.
 *
 * With MRP on, carries any outstanding acknowledgement and sets R so the peer
 * acknowledges this in turn. With MRP off -- which is what BLE uses -- neither
 * flag is ever set, because BTP is already reliable.
 *
 * @param out needs MATTER_EXCHANGE_HEADER_MAX + @p payload_len bytes.
 * @return MATTER_OK, MATTER_E_NOSPACE, MATTER_E_STATE if no message has been
 *         received yet, or MATTER_E_INVAL.
 */
int matter_exchange_reply(struct matter_exchange *x, uint8_t opcode, const uint8_t *payload,
			  size_t payload_len, uint8_t *out, size_t cap, size_t *out_len);

/**
 * Frame a reply on a protocol other than Secure Channel.
 *
 * Same framing as matter_exchange_reply(); the protocol id is the only
 * difference, and it exists because everything after commissioning's Secure
 * Channel phase is protocol 0x0001.
 *
 * On a secure session the proto header and payload are sealed together and
 * @p out receives the encrypted message, which is @ref MATTER_TAG_LEN bytes
 * longer than the cleartext equivalent.
 *
 * @param out needs MATTER_EXCHANGE_HEADER_MAX + @p payload_len + MATTER_TAG_LEN
 *        bytes on a secure session.
 */
/**
 * Send as the INITIATOR of a new exchange, on a session this node responds on.
 *
 * Everything this node sent until now answered something. A subscription does
 * not work that way: after the priming report the SERVER is the one that has to
 * speak, and a controller that gets no report shows the accessory as not
 * responding however healthy the session is. That is the whole of why the Home
 * tile spins on "Unlocking" while the invoke it sent was answered SUCCESS.
 *
 * The SESSION role is unchanged and that is what makes this cheap: keys stay
 * role-relative to CASE (this node still encrypts with r2i), and the message
 * counter is per-session, not per-exchange, so @p x's counter is still the
 * right one. Only the EXCHANGE role differs.
 *
 * @param exchange_id chosen by this node, and its alone. NOT written back into
 *        @p x -- the peer-initiated exchange that @p x describes is still live
 *        and still owns x->exchange_id.
 *
 * No acknowledgement is ever piggybacked here. An ack names a counter WITHIN an
 * exchange, so carrying the peer's pending ack out on a different exchange
 * acknowledges a message that exchange never saw.
 *
 * @return MATTER_OK, or MATTER_E_STATE on a closed exchange, or
 *         MATTER_E_NOSPACE if @p cap cannot hold the framed result.
 */
int matter_exchange_send_initiator(struct matter_exchange *x, uint16_t exchange_id,
				   uint16_t protocol_id, uint8_t opcode, const uint8_t *payload,
				   size_t payload_len, uint8_t *out, size_t cap, size_t *out_len);

/** Continue an exchange this node initiated and piggyback the pending MRP ack. */
int matter_exchange_continue_initiator(struct matter_exchange *x, uint16_t exchange_id,
				       uint16_t protocol_id, uint8_t opcode, const uint8_t *payload,
				       size_t payload_len, uint8_t *out, size_t cap,
				       size_t *out_len);

int matter_exchange_send(struct matter_exchange *x, uint16_t protocol_id, uint8_t opcode,
			 const uint8_t *payload, size_t payload_len, uint8_t *out, size_t cap,
			 size_t *out_len);

/**
 * Frame a bare acknowledgement, for when there is nothing to say yet.
 *
 * Matter's standalone ack: Secure Channel opcode 0x10, empty payload. Needed
 * when a reply cannot be produced inside the peer's retransmission timer, and
 * after the final message of an exchange.
 *
 * @return MATTER_OK; MATTER_E_STATE when nothing is pending, or whenever MRP is
 *         off, since then there is no such thing as an outstanding ack.
 */
int matter_exchange_standalone_ack(struct matter_exchange *x, uint8_t *out, size_t cap,
				   size_t *out_len);

/**
 * Replay the exact response cached for the duplicate request currently owed an
 * acknowledgement. Reusing the original ciphertext and message counter is
 * required; framing a new response would be a new MRP message, not a retry.
 */
int matter_exchange_replay(struct matter_exchange *x, uint8_t *out, size_t cap, size_t *out_len);

/** Secure Channel MsgType 0x10 (Constants.h). Not a PASE opcode. */
#define MATTER_SC_OP_ACK 0x10u

/*
 * ---------------------------------------------- this node as the INITIATOR ---
 *
 * Everything above assumes the session was opened by somebody else. The two
 * functions below are for the one case where it was not: a CASE session this
 * node started, so it could send a command to another node.
 *
 * Compiled only into a client build (see matter_clusters.h on
 * MATTER_FEATURE_CLIENT), so an image without the client preprocesses this
 * file to exactly what it was before. That is why they are here rather than in
 * a file of their own: they need frame()'s neighbours -- the header encoders
 * and the seal -- and everything in this file is already about that.
 */
/*
 * Defaulted here as well as in matter_clusters.h, rather than included from
 * there: the real definition comes from the compiler command line, and a
 * header whose declarations depend on which OTHER header was included first is
 * a link error waiting for an unlucky include order.
 */
#ifndef MATTER_FEATURE_CLIENT
#define MATTER_FEATURE_CLIENT 0
#endif

#if MATTER_FEATURE_CLIENT

/**
 * Adopt a secure session this node INITIATED.
 *
 * matter_exchange_promote() is the responder's version and deliberately leaves
 * the exchange CLOSED: a commissioner opens a new exchange on the secure
 * session and the first message arrives from the peer. An initiator has the
 * opposite problem -- the first message on the session is one it SENDS, and
 * frame() refuses to build a message on a closed exchange -- so this opens the
 * exchange with an id of this node's own choosing.
 *
 * MRP is on, because this session only exists over UDP; see struct
 * matter_exchange::mrp for why that is a property of the transport.
 *
 * @param exchange_id chosen by this node. Also recorded as the exchange this
 *        node will acknowledge on, which is what makes
 *        matter_exchange_ack_initiator() below able to name it.
 * @param entropy seeds a fresh session counter, as promote does.
 * @return MATTER_OK, or MATTER_E_INVAL.
 */
int matter_exchange_open_initiator(struct matter_exchange *x, uint16_t local_id, uint16_t peer_id,
				   uint16_t exchange_id, const struct matter_session_keys *keys,
				   uint32_t entropy);

/**
 * Frame a standalone acknowledgement on an exchange this node OPENED.
 *
 * matter_exchange_standalone_ack() cannot do this and must not be taught to:
 * it frames with I clear, which is right for every exchange the peer opened
 * and wrong for one this node did. CHIP matches an incoming message to an
 * exchange by id AND by the initiator flag being the opposite of its own
 * (ExchangeContext::MatchExchange), so an acknowledgement sent with I clear on
 * this node's own exchange matches nothing at the peer and is dropped as
 * unsolicited -- and the peer goes on retransmitting the message it is meant to
 * be acknowledging.
 *
 * @return MATTER_OK; MATTER_E_STATE when nothing is pending or the session is
 *         not secure; MATTER_E_NOSPACE; or MATTER_E_INVAL.
 */
int matter_exchange_ack_initiator(struct matter_exchange *x, uint16_t exchange_id, uint8_t *out,
				  size_t cap, size_t *out_len);

#endif /* MATTER_FEATURE_CLIENT */

#ifdef __cplusplus
}
#endif
