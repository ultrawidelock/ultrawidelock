/* SPDX-License-Identifier: ISC */

/**
 * @file matter_exchange.c — the unsecured exchange. See matter_exchange.h.
 */
#include "matter_exchange.h"

#include <string.h>

int matter_tx_pool_init(struct matter_tx_pool *pool, struct matter_tx_slot *slots, uint8_t *backing,
			size_t n_slots, size_t slot_capacity)
{
	if (pool == NULL || slots == NULL || backing == NULL || n_slots == 0u ||
	    slot_capacity == 0u) {
		return MATTER_E_INVAL;
	}
	memset(slots, 0, n_slots * sizeof(*slots));
	for (size_t i = 0u; i < n_slots; i++) {
		slots[i].data = backing + i * slot_capacity;
		slots[i].capacity = slot_capacity;
	}
	pool->slots = slots;
	pool->n_slots = n_slots;
	pool->next_token = 0u;
	pool->next_order = 0u;
	return MATTER_OK;
}

struct matter_tx_slot *matter_tx_pool_acquire(struct matter_tx_pool *pool, uint8_t transport)
{
	if (pool == NULL || pool->slots == NULL) {
		return NULL;
	}
	for (size_t i = 0u; i < pool->n_slots; i++) {
		struct matter_tx_slot *slot = &pool->slots[i];

		if (slot->state != MATTER_TX_SLOT_FREE) {
			continue;
		}
		do {
			pool->next_token++;
		} while (pool->next_token == 0u);
		pool->next_order++;
		slot->token = pool->next_token;
		slot->order = pool->next_order;
		slot->retry_deadline_ms = 0u;
		slot->retry_deadline_set = false;
		slot->transport = transport;
		slot->len = 0u;
		slot->state = MATTER_TX_SLOT_BUILDING;
		return slot;
	}
	return NULL;
}

int matter_tx_slot_commit(struct matter_tx_slot *slot, size_t len)
{
	if (slot == NULL || slot->state != MATTER_TX_SLOT_BUILDING || len == 0u ||
	    len > slot->capacity) {
		return MATTER_E_INVAL;
	}
	slot->len = len;
	slot->state = MATTER_TX_SLOT_READY;
	return MATTER_OK;
}

struct matter_tx_slot *matter_tx_pool_ready(struct matter_tx_pool *pool, uint8_t transport)
{
	struct matter_tx_slot *oldest = NULL;

	if (pool == NULL || pool->slots == NULL) {
		return NULL;
	}
	for (size_t i = 0u; i < pool->n_slots; i++) {
		struct matter_tx_slot *slot = &pool->slots[i];

		if (slot->state != MATTER_TX_SLOT_READY || slot->transport != transport) {
			continue;
		}
		if (oldest == NULL || (int32_t)(slot->order - oldest->order) < 0) {
			oldest = slot;
		}
	}
	return oldest;
}

int matter_tx_slot_in_flight(struct matter_tx_slot *slot)
{
	if (slot == NULL || slot->state != MATTER_TX_SLOT_READY) {
		return MATTER_E_STATE;
	}
	slot->state = MATTER_TX_SLOT_IN_FLIGHT;
	return MATTER_OK;
}

struct matter_tx_slot *matter_tx_pool_find(struct matter_tx_pool *pool, uint32_t token)
{
	if (pool == NULL || pool->slots == NULL || token == 0u) {
		return NULL;
	}
	for (size_t i = 0u; i < pool->n_slots; i++) {
		if (pool->slots[i].state != MATTER_TX_SLOT_FREE && pool->slots[i].token == token) {
			return &pool->slots[i];
		}
	}
	return NULL;
}

int matter_tx_pool_retry(struct matter_tx_pool *pool, uint32_t token, uint32_t now_ms,
			 uint32_t retain_ms)
{
	struct matter_tx_slot *slot = matter_tx_pool_find(pool, token);

	if (slot == NULL || slot->state != MATTER_TX_SLOT_IN_FLIGHT) {
		return MATTER_E_STATE;
	}
	/* A peer repeating a request must not extend an abandoned packet forever.
	 * Only the first failed attempt fixes the absolute reap deadline. */
	if (!slot->retry_deadline_set) {
		slot->retry_deadline_ms = now_ms + retain_ms;
		slot->retry_deadline_set = true;
	}
	slot->state = MATTER_TX_SLOT_READY;
	return MATTER_OK;
}

struct matter_tx_slot *matter_tx_pool_expired(struct matter_tx_pool *pool, uint8_t transport,
					      uint32_t now_ms)
{
	if (pool == NULL || pool->slots == NULL) {
		return NULL;
	}
	for (size_t i = 0u; i < pool->n_slots; i++) {
		struct matter_tx_slot *slot = &pool->slots[i];

		if (slot->state == MATTER_TX_SLOT_READY && slot->transport == transport &&
		    slot->retry_deadline_set && (int32_t)(now_ms - slot->retry_deadline_ms) >= 0) {
			return slot;
		}
	}
	return NULL;
}

static int matter_tx_pool_release(struct matter_tx_pool *pool, uint32_t token, bool allow_ready)
{
	struct matter_tx_slot *slot = matter_tx_pool_find(pool, token);

	if (slot == NULL || (slot->state != MATTER_TX_SLOT_IN_FLIGHT &&
			     !(allow_ready && slot->state == MATTER_TX_SLOT_READY))) {
		return MATTER_E_STATE;
	}
	slot->state = MATTER_TX_SLOT_FREE;
	slot->len = 0u;
	slot->retry_deadline_ms = 0u;
	slot->retry_deadline_set = false;
	slot->transport = 0u;
	return MATTER_OK;
}

int matter_tx_pool_cancel(struct matter_tx_pool *pool, uint32_t token)
{
	struct matter_tx_slot *slot = matter_tx_pool_find(pool, token);

	if (slot == NULL || slot->state != MATTER_TX_SLOT_BUILDING) {
		return MATTER_E_STATE;
	}
	slot->state = MATTER_TX_SLOT_FREE;
	slot->len = 0u;
	slot->retry_deadline_ms = 0u;
	slot->retry_deadline_set = false;
	slot->transport = 0u;
	return MATTER_OK;
}

int matter_tx_pool_complete(struct matter_tx_pool *pool, uint32_t token)
{
	return matter_tx_pool_release(pool, token, false);
}

int matter_tx_pool_reject(struct matter_tx_pool *pool, uint32_t token)
{
	return matter_tx_pool_release(pool, token, true);
}

/**
 * Initialize a Matter exchange: clear state, set MRP mode, init the message counter with the given
 * entropy, and init the MRP window.
 */
void matter_exchange_init(struct matter_exchange *x, uint32_t entropy, bool mrp)
{
	memset(x, 0, sizeof(*x));
	x->mrp = mrp;
	matter_counter_init(&x->counter, entropy, MATTER_COUNTER_UNSECURED);
	matter_mrp_window_init(&x->window);
}

/**
 * Everything about a message header that disqualifies it from this layer.
 *
 * Split out because it is a list of refusals rather than a computation, and
 * because every item is a thing an unauthenticated peer chose.
 */
static int check_msg_header(const struct matter_exchange *x, const struct matter_msg_header *h)
{
	if (x->secure) {
		/* Once keys exist, the clear channel is closed. A peer that holds
		 * keys and talks in the clear is either confused or probing. */
		if (h->session_id != x->local_session_id) {
			return MATTER_E_INVAL;
		}
	} else if (h->session_id != MATTER_SESSION_ID_UNSECURED) {
		/* A non-zero session id before PASE means the peer believes it
		 * holds keys with us; it does not, and answering as though it
		 * might is how a downgrade starts. */
		return MATTER_E_INVAL;
	}
	if ((h->security_flags & MATTER_SEC_SESSION_TYPE_MASK) != MATTER_SESSION_TYPE_UNICAST) {
		return MATTER_E_INVAL;
	}
	/* Privacy and message extensions both describe transformations this node
	 * does not implement. Ignoring either would mean parsing the rest wrong
	 * rather than parsing it strictly. */
	if ((h->security_flags & (MATTER_SEC_FLAG_P | MATTER_SEC_FLAG_MX)) != 0u) {
		return MATTER_E_INVAL;
	}
	return MATTER_OK;
}

/** Did this node open @p id? See @ref matter_exchange::init_exchange. */
static bool exchange_is_ours(const struct matter_exchange *x, uint16_t id)
{
	for (uint8_t i = 0u; i < x->init_exchange_n; i++) {
		if (x->init_exchange[i] == id) {
			return true;
		}
	}
	return false;
}

/** Remember it, dropping the oldest. Duplicates are not re-recorded. */
static void exchange_remember(struct matter_exchange *x, uint16_t id)
{
	const uint8_t cap = (uint8_t)(sizeof(x->init_exchange) / sizeof(x->init_exchange[0]));

	if (exchange_is_ours(x, id)) {
		return;
	}
	if (x->init_exchange_n < cap) {
		x->init_exchange[x->init_exchange_n++] = id;
		return;
	}
	memmove(&x->init_exchange[0], &x->init_exchange[1], (size_t)(cap - 1) * sizeof(uint16_t));
	x->init_exchange[cap - 1] = id;
}

/**
 * Receive and decode a message on this exchange: decode and validate the message header, decrypt if
 * secure, decode the protocol header, validate exchange ID and state, check replay window, and
 * return the parsed message. On secure sessions, the protocol header is decrypted; the plaintext
 * buffer must be provided and must be large enough. Return MATTER_OK on success; MATTER_E_INVAL if
 * pointers are null or structure is invalid; MATTER_E_STATE if the exchange ID does not match and
 * the message is not a valid acknowledgement.
 */
static int matter_exchange_recv_impl(struct matter_exchange *x, const uint8_t *msg,
				     uint8_t *mutable_msg, size_t len,
				     struct matter_exchange_in *in, uint8_t *pt, size_t pt_cap)
{
	struct matter_msg_header mh;
	struct matter_proto_header ph;
	const uint8_t *body;
	size_t body_len;
	size_t mh_len = 0u;
	size_t ph_len = 0u;
	size_t pt_len = 0u;
	int rc;

	if (x == NULL || msg == NULL || in == NULL) {
		return MATTER_E_INVAL;
	}
	memset(in, 0, sizeof(*in));

	rc = matter_msg_header_decode(msg, len, &mh, &mh_len);
	if (rc != MATTER_OK) {
		return rc;
	}
	rc = check_msg_header(x, &mh);
	if (rc != MATTER_OK) {
		return rc;
	}

	if (x->secure) {
		if (pt == NULL) {
			if (mutable_msg == NULL) {
				return MATTER_E_INVAL;
			}
			/* ccm_ctr consumes and produces each byte once, so exact aliasing
			 * is safe. The tag follows this range and remains intact while it
			 * is verified. */
			pt = mutable_msg + mh_len;
			pt_cap = len - mh_len;
		}
		/*
		 * Decrypt before anything else is believed. The protocol header
		 * lives INSIDE the ciphertext on a secure session, so until the
		 * tag verifies there is no exchange id, no opcode and no payload
		 * -- only bytes an attacker chose.
		 *
		 * i2r decrypts: we are the responder (CryptoContext.cpp:77-78).
		 * The nonce carries the SENDER's node id -- the PEER's, on the
		 * way in. Zero for PASE, which has no operational identity, and
		 * the far side's real node id once CASE has named one
		 * (SessionManager.cpp:949-950 branches on exactly this).
		 */
		rc = matter_crypto_open(msg, len, x->keys.i2r, x->peer_op_node_id, &mh, pt, pt_cap,
					&pt_len);
		if (rc != MATTER_OK) {
			return rc;
		}
		body = pt;
		body_len = pt_len;
	} else {
		body = msg + mh_len;
		body_len = len - mh_len;
	}

	rc = matter_proto_header_decode(body, body_len, &ph, &ph_len);
	if (rc != MATTER_OK) {
		return rc;
	}
	/* Secure Channel is all commissioning speaks until PASE finishes; the
	 * Interaction Model only becomes reachable once there are keys. */
	if (ph.protocol_id != MATTER_PROTOCOL_SECURE_CHANNEL &&
	    !(x->secure && ph.protocol_id == MATTER_PROTOCOL_INTERACTION_MODEL)) {
		return MATTER_E_INVAL;
	}
	/* A vendor-scoped protocol id is a different namespace entirely, so the
	 * protocol_id check above would have compared the wrong thing. */
	if ((ph.exchange_flags & MATTER_EX_FLAG_V) != 0u) {
		return MATTER_E_INVAL;
	}

	/* Filled before the exchange is checked so a caller can say what it just
	 * refused. A refusal that cannot name the message is a refusal nobody can
	 * debug -- which cost one hardware round already. */
	in->opcode = ph.opcode;
	in->protocol_id = ph.protocol_id;
	in->exchange_id = ph.exchange_id;
	in->initiator = (ph.exchange_flags & MATTER_EX_FLAG_I) != 0u;

	/*
	 * The peer opens the exchange and this node answers on it.
	 *
	 * On the UNSECURED session there is exactly one: PASE, start to finish.
	 * A second exchange id there is a second commissioner, and this node has
	 * room for neither.
	 *
	 * On a SECURE session the opposite holds, and this is not a relaxation of
	 * the rule but a different situation. The peer has authenticated by
	 * completing PASE, and Matter gives an initiator a NEW exchange for every
	 * interaction -- the read that follows PASE closes its own exchange, and
	 * the next request arrives on another. Refusing that is refusing the
	 * whole of commissioning after the first question. A real iPhone did
	 * exactly this: it took the ReportData, then sent 137 bytes on a new
	 * exchange, and hung up when nothing answered.
	 *
	 * It must still be claiming to INITIATE. A message on an unknown exchange
	 * with I clear is a reply to something this node never sent, and adopting
	 * it would mean answering a conversation that does not exist.
	 */
	if (!x->open) {
		x->exchange_id = ph.exchange_id;
		x->open = true;
	} else if (ph.exchange_id != x->exchange_id) {
		if (!in->initiator && exchange_is_ours(x, ph.exchange_id)) {
			/*
			 * An acknowledgement for an exchange this node opened,
			 * which is the one case where I clear on an unfamiliar
			 * id is exactly right. Consumed WITHOUT adopting the id:
			 * the peer's own exchange is still live and moving
			 * @ref exchange_id here would misaddress its next reply.
			 */
		} else if (!x->secure || !in->initiator) {
			return MATTER_E_STATE;
		} else {
			x->exchange_id = ph.exchange_id;
			/* Whatever was owed belonged to the exchange that just
			 * ended, and would now be framed with the wrong id. */
			x->ack_pending = false;
		}
	}

	/* Keep the initiator's ephemeral node id: every reply has to be addressed
	 * back to it (SessionManager.cpp:301-303). */
	if ((mh.flags & MATTER_MSG_FLAG_S) != 0u) {
		x->peer_node_id = mh.source_node_id;
		x->have_peer_node_id = true;
	}

	in->payload = body + ph_len;
	in->payload_len = body_len - ph_len;
	in->ack_requested = (ph.exchange_flags & MATTER_EX_FLAG_R) != 0u;
	in->carries_ack = (ph.exchange_flags & MATTER_EX_FLAG_A) != 0u;
	in->acked_counter = ph.ack_counter;
	if (in->carries_ack && x->replay_len != 0u && in->acked_counter == x->replay_out_counter) {
		x->replay_len = 0u;
	}

	/*
	 * A duplicate still has to be acknowledged -- the peer is retransmitting
	 * precisely because it thinks the last ack was lost -- but its payload
	 * must not be acted on twice. Hence the ack is recorded before the
	 * return, and the caller is told not to use `in`.
	 */
	if (x->mrp && in->ack_requested) {
		x->ack_counter = mh.message_counter;
		x->ack_pending = true;
	}

	rc = matter_mrp_window_check(&x->window, mh.message_counter);
	if (rc != MATTER_OK) {
		return rc;
	}
	/* Unsecured, so there is nothing to authenticate before committing; on a
	 * secure session this would wait until the tag verified. */
	matter_mrp_window_commit(&x->window, mh.message_counter);

	return MATTER_OK;
}

int matter_exchange_recv(struct matter_exchange *x, const uint8_t *msg, size_t len,
			 struct matter_exchange_in *in, uint8_t *pt, size_t pt_cap)
{
	return matter_exchange_recv_impl(x, msg, NULL, len, in, pt, pt_cap);
}

int matter_exchange_recv_in_place(struct matter_exchange *x, uint8_t *msg, size_t len,
				  struct matter_exchange_in *in)
{
	return matter_exchange_recv_impl(x, msg, msg, len, in, NULL, 0u);
}

/**
 * Promote an unsecured exchange to a secure session exchange: set secure flag, IDs, and keys;
 * reinit counter and MRP window with new entropy; initialize operational node IDs to PASE defaults;
 * clear open and ack_pending flags. Return MATTER_E_INVAL if pointers are null or local_id is
 * unsecured, MATTER_OK on success.
 */
int matter_exchange_promote(struct matter_exchange *x, uint16_t local_id, uint16_t peer_id,
			    const struct matter_session_keys *keys, uint32_t entropy)
{
	if (x == NULL || keys == NULL || local_id == MATTER_SESSION_ID_UNSECURED) {
		return MATTER_E_INVAL;
	}

	x->secure = true;
	x->local_session_id = local_id;
	x->peer_session_id = peer_id;
	x->keys = *keys;

	/* A fresh counter and a fresh replay window. Carrying the unsecured
	 * session's counter forward would risk repeating one under a key, and a
	 * repeated counter is a repeated AEAD nonce. */
	matter_counter_init(&x->counter, entropy, MATTER_COUNTER_SESSION);
	matter_mrp_window_init(&x->window);

	/* Undefined until told otherwise, which is what PASE needs and what a
	 * caller forgetting matter_exchange_set_op_node_ids() gets. */
	x->local_op_node_id = MATTER_PASE_NODE_ID;
	x->peer_op_node_id = MATTER_PASE_NODE_ID;

	/* PASE's exchange is over. The commissioner opens a new one on the
	 * secure session, so holding the old id would refuse its first message. */
	x->open = false;
	x->ack_pending = false;
	x->replay_len = 0u;

	return MATTER_OK;
}

/**
 * Frame one outbound message on this exchange.
 *
 * @param reliable sets R. Everything in commissioning is reliable except a
 *        standalone ack, which would otherwise ask to be acknowledged and never
 *        terminate.
 * @param as_initiator sets I and uses @p init_exchange_id instead of the
 *        peer's. Only a server-initiated exchange -- a subscription report --
 *        does this; see matter_exchange_send_initiator().
 */
static int frame(struct matter_exchange *x, uint16_t protocol_id, uint8_t opcode, bool reliable,
		 bool as_initiator, bool carry_initiator_ack, uint16_t init_exchange_id,
		 const uint8_t *payload, size_t payload_len, uint8_t *out, size_t cap,
		 size_t *out_len)
{
	struct matter_msg_header mh;
	struct matter_proto_header ph;
	size_t mh_len = 0u;
	size_t ph_len = 0u;
	uint32_t counter;
	uint32_t reply_to_counter = 0u;
	bool cache_reply;
	int rc;

	if (x == NULL || out == NULL || out_len == NULL) {
		return MATTER_E_INVAL;
	}
	if (payload_len > 0u && payload == NULL) {
		return MATTER_E_INVAL;
	}
	if (!x->open) {
		return MATTER_E_STATE;
	}
	cache_reply = reliable && !as_initiator && x->mrp && x->ack_pending;
	if (cache_reply) {
		reply_to_counter = x->ack_counter;
	}

	rc = matter_counter_next(&x->counter, &counter);
	if (rc != MATTER_OK) {
		return rc;
	}

	memset(&mh, 0, sizeof(mh));
	mh.security_flags = MATTER_SESSION_TYPE_UNICAST;
	mh.message_counter = counter;
	if (x->secure) {
		/*
		 * Addressed by session id alone. SessionManager.cpp:262-265 sets
		 * the counter, the PEER's session id and the session type, and
		 * nothing else -- a secure message carries no node ids, not even
		 * the ephemeral one the unsecured exchange needed.
		 */
		mh.session_id = x->peer_session_id;
		mh.flags = MATTER_MSG_DSIZ_NONE;
	} else {
		mh.session_id = MATTER_SESSION_ID_UNSECURED;
		/*
		 * No SOURCE node id -- this node has no operational identity yet
		 * -- but the DESTINATION is the initiator's ephemeral node id,
		 * which is what the peer matches the reply against. A responder
		 * that leaves this out is talking to nobody in particular and
		 * gets ignored.
		 */
		if (x->have_peer_node_id) {
			mh.flags = MATTER_MSG_DSIZ_NODE;
			mh.dest_node_id = x->peer_node_id;
		} else {
			mh.flags = MATTER_MSG_DSIZ_NONE;
		}
	}

	memset(&ph, 0, sizeof(ph));
	/* On a peer-initiated exchange I stays clear: the peer initiated it and
	 * keeps that role for its lifetime, however many messages each side
	 * sends. It is set only when this node opens an exchange of its own. */
	ph.exchange_flags = as_initiator ? MATTER_EX_FLAG_I : 0u;
	/* Both flags are MRP's, and MRP does not run over a transport that is
	 * already reliable (see struct matter_exchange::mrp). */
	if (reliable && x->mrp) {
		ph.exchange_flags |= MATTER_EX_FLAG_R;
	}
	/*
	 * Never acknowledge on an exchange this node has just opened. An ack
	 * names a counter WITHIN an exchange, so carrying the peer's pending ack
	 * out here would acknowledge, on a brand new exchange, a message that
	 * exchange never carried. The pending ack stays pending and leaves on
	 * the exchange that owes it.
	 */
	if ((!as_initiator || carry_initiator_ack) && x->mrp && x->ack_pending) {
		ph.exchange_flags |= MATTER_EX_FLAG_A;
		ph.ack_counter = x->ack_counter;
	}
	ph.opcode = opcode;
	ph.exchange_id = as_initiator ? init_exchange_id : x->exchange_id;
	if (as_initiator) {
		/* So the peer's acknowledgement is recognised when it comes back
		 * with I clear on an id the peer never opened. */
		exchange_remember(x, init_exchange_id);
	}
	ph.protocol_id = protocol_id;

	rc = matter_msg_header_encode(&mh, out, cap, &mh_len);
	if (rc != MATTER_OK) {
		return rc;
	}
	rc = matter_proto_header_encode(&ph, out + mh_len, cap - mh_len, &ph_len);
	if (rc != MATTER_OK) {
		return rc;
	}
	if (cap - mh_len - ph_len < payload_len) {
		return MATTER_E_NOSPACE;
	}
	if (payload_len > 0u) {
		/* The caller may build the payload in reserved headroom inside out.
		 * memmove makes that owned-packet path explicit and remains identical
		 * to memcpy for the traditional disjoint buffers. */
		memmove(out + mh_len + ph_len, payload, payload_len);
	}

	if (x->secure) {
		/*
		 * The proto header and payload are ONE plaintext; the message
		 * header is the AAD. Both are already laid out contiguously at
		 * out + mh_len, so the seal encrypts them where they lie rather
		 * than through a scratch buffer this layer would have to own.
		 *
		 * Sealing in place is safe here for two reasons, and neither is
		 * incidental: matter_crypto.c runs ccm_mac() over the whole
		 * plaintext BEFORE ccm_ctr() writes a byte, and ccm_ctr() is
		 * index-aligned (matter_crypto.c:186-188), so no output byte is
		 * written before the input byte at that index is consumed. A
		 * one-shot AEAD that made no such promise would need a copy.
		 *
		 * Keys are role-relative: this node is the RESPONDER, so it
		 * encrypts with r2i (CryptoContext.cpp:102-103). The nonce takes
		 * the SENDER's node id -- this node's, on the way out. Zero for
		 * PASE, which has no operational identity
		 * (SessionManager.cpp:279-280).
		 */
		rc = matter_crypto_seal(&mh, x->keys.r2i, x->local_op_node_id, out + mh_len,
					ph_len + payload_len, out, cap, out_len);
		if (rc != MATTER_OK) {
			return rc;
		}
	} else {
		*out_len = mh_len + ph_len + payload_len;
	}
	if (cache_reply) {
		if (*out_len <= sizeof(x->replay)) {
			memcpy(x->replay, out, *out_len);
			x->replay_len = (uint16_t)*out_len;
			x->replay_peer_counter = reply_to_counter;
			x->replay_out_counter = counter;
		} else {
			x->replay_len = 0u;
		}
	}

	/*
	 * Only now: an ack that was never encoded is an ack still owed.
	 *
	 * And not at all on an exchange this node initiated, which never
	 * carried the ack in the first place -- clearing it there drops an
	 * acknowledgement the peer is waiting for, so the peer retransmits a
	 * message this node has already handled and the exchange that owes the
	 * ack stalls. The report going out is not the reply that was owed.
	 */
	if (!as_initiator || carry_initiator_ack) {
		x->ack_pending = false;
	}

	return MATTER_OK;
}

/**
 * Frame and send a reply on this exchange in the Secure Channel protocol, setting the initiator
 * flag to false and clearing the R and A exchange flags. Calls frame() with the given opcode and
 * payload.
 */
int matter_exchange_reply(struct matter_exchange *x, uint8_t opcode, const uint8_t *payload,
			  size_t payload_len, uint8_t *out, size_t cap, size_t *out_len)
{
	return frame(x, MATTER_PROTOCOL_SECURE_CHANNEL, opcode, true, false, false, 0u, payload,
		     payload_len, out, cap, out_len);
}

/**
 * Frame one outbound message on this exchange with the given protocol ID and opcode.
 */
int matter_exchange_send(struct matter_exchange *x, uint16_t protocol_id, uint8_t opcode,
			 const uint8_t *payload, size_t payload_len, uint8_t *out, size_t cap,
			 size_t *out_len)
{
	return frame(x, protocol_id, opcode, true, false, false, 0u, payload, payload_len, out, cap,
		     out_len);
}

/**
 * Frame one outbound message on this exchange as the initiator, setting the exchange ID in the
 * message header.
 */
int matter_exchange_send_initiator(struct matter_exchange *x, uint16_t exchange_id,
				   uint16_t protocol_id, uint8_t opcode, const uint8_t *payload,
				   size_t payload_len, uint8_t *out, size_t cap, size_t *out_len)
{
	return frame(x, protocol_id, opcode, true, true, false, exchange_id, payload, payload_len,
		     out, cap, out_len);
}

int matter_exchange_continue_initiator(struct matter_exchange *x, uint16_t exchange_id,
				       uint16_t protocol_id, uint8_t opcode, const uint8_t *payload,
				       size_t payload_len, uint8_t *out, size_t cap,
				       size_t *out_len)
{
	if (x == NULL || !x->open || x->exchange_id != exchange_id || !x->ack_pending) {
		return MATTER_E_STATE;
	}
	return frame(x, protocol_id, opcode, true, true, true, exchange_id, payload, payload_len,
		     out, cap, out_len);
}

/**
 * Send a standalone MRP acknowledgment on this exchange if one is pending and MRP is enabled;
 * returns MATTER_E_STATE if no ack is pending or MRP is not active.
 */
int matter_exchange_standalone_ack(struct matter_exchange *x, uint8_t *out, size_t cap,
				   size_t *out_len)
{
	if (x == NULL) {
		return MATTER_E_INVAL;
	}
	if (!x->mrp || !x->ack_pending) {
		return MATTER_E_STATE;
	}
	return frame(x, MATTER_PROTOCOL_SECURE_CHANNEL, MATTER_SC_OP_ACK, false, false, false, 0u,
		     NULL, 0u, out, cap, out_len);
}

int matter_exchange_replay(struct matter_exchange *x, uint8_t *out, size_t cap, size_t *out_len)
{
	if (x == NULL || out == NULL || out_len == NULL) {
		return MATTER_E_INVAL;
	}
	if (!x->mrp || !x->ack_pending || x->replay_len == 0u ||
	    x->replay_peer_counter != x->ack_counter) {
		return MATTER_E_STATE;
	}
	if (cap < x->replay_len) {
		return MATTER_E_NOSPACE;
	}
	memcpy(out, x->replay, x->replay_len);
	*out_len = x->replay_len;
	x->ack_pending = false;
	return MATTER_OK;
}

#if MATTER_FEATURE_CLIENT

int matter_exchange_open_initiator(struct matter_exchange *x, uint16_t local_id, uint16_t peer_id,
				   uint16_t exchange_id, const struct matter_session_keys *keys,
				   uint32_t entropy)
{
	int rc;

	if (x == NULL) {
		return MATTER_E_INVAL;
	}
	/* MRP true: this session only ever runs over UDP. */
	matter_exchange_init(x, entropy, true);
	rc = matter_exchange_promote(x, local_id, peer_id, keys, entropy);
	if (rc != MATTER_OK) {
		return rc;
	}
	/*
	 * What promote() deliberately withholds. The exchange id is set as well
	 * as the flag, because the peer's answers arrive with I CLEAR on this
	 * id: recv_impl() consumes those through exchange_is_ours() without
	 * adopting the id, so nothing else would ever put it here, and
	 * matter_exchange_ack_initiator() needs to know which exchange the
	 * pending acknowledgement belongs to.
	 */
	x->open = true;
	x->exchange_id = exchange_id;
	return MATTER_OK;
}

int matter_exchange_ack_initiator(struct matter_exchange *x, uint16_t exchange_id, uint8_t *out,
				  size_t cap, size_t *out_len)
{
	struct matter_msg_header mh;
	struct matter_proto_header ph;
	size_t mh_len = 0u;
	size_t ph_len = 0u;
	uint32_t counter;
	int rc;

	if (x == NULL || out == NULL || out_len == NULL) {
		return MATTER_E_INVAL;
	}
	if (!x->secure || !x->mrp || !x->ack_pending) {
		return MATTER_E_STATE;
	}

	rc = matter_counter_next(&x->counter, &counter);
	if (rc != MATTER_OK) {
		return rc;
	}

	/* Addressed by session id alone, exactly as frame() does on a secure
	 * session: no node ids travel in a secure message header. */
	memset(&mh, 0, sizeof(mh));
	mh.security_flags = MATTER_SESSION_TYPE_UNICAST;
	mh.message_counter = counter;
	mh.session_id = x->peer_session_id;
	mh.flags = MATTER_MSG_DSIZ_NONE;

	memset(&ph, 0, sizeof(ph));
	/* I, because this node opened the exchange; A, because that is the
	 * whole message; and NOT R -- an acknowledgement that asks to be
	 * acknowledged is an exchange that never ends. */
	ph.exchange_flags = MATTER_EX_FLAG_I | MATTER_EX_FLAG_A;
	ph.ack_counter = x->ack_counter;
	ph.opcode = MATTER_SC_OP_ACK;
	ph.exchange_id = exchange_id;
	ph.protocol_id = MATTER_PROTOCOL_SECURE_CHANNEL;

	rc = matter_msg_header_encode(&mh, out, cap, &mh_len);
	if (rc != MATTER_OK) {
		return rc;
	}
	rc = matter_proto_header_encode(&ph, out + mh_len, cap - mh_len, &ph_len);
	if (rc != MATTER_OK) {
		return rc;
	}
	/* The proto header IS the plaintext; the message header is the AAD.
	 * Sealed in place for the reason frame() sets out at length. */
	rc = matter_crypto_seal(&mh, x->keys.r2i, x->local_op_node_id, out + mh_len, ph_len, out,
				cap, out_len);
	if (rc != MATTER_OK) {
		return rc;
	}

	/* Only now: an ack that was never encoded is an ack still owed. */
	x->ack_pending = false;
	return MATTER_OK;
}

#endif /* MATTER_FEATURE_CLIENT */

/**
 * Set the operational node IDs for this exchange; used to populate node ID fields in secure channel
 * messages.
 */
void matter_exchange_set_op_node_ids(struct matter_exchange *x, uint64_t local, uint64_t peer)
{
	if (x == NULL) {
		return;
	}
	x->local_op_node_id = local;
	x->peer_op_node_id = peer;
}
