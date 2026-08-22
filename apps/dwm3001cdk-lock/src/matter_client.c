/* SPDX-License-Identifier: ISC */

/*
 * matter_client — see matter_client.h for what this is and what it refuses to
 * do. What follows is how.
 *
 * ONE binding target at a time, one session, one exchange. The table can hold
 * four (MATTER_BINDING_MAX) and this walks it from the top on each attempt, so
 * a person with two locks bound gets the first one that resolves. Serving both
 * at once would need two sessions, two key schedules and two schedules, on a
 * part with 16 KB of RAM free; serving them in turn would make the second lock
 * open a handshake later than the first, which is not what "both doors open"
 * means to anybody standing in front of them. Stated here because it is a real
 * limit and there is no way to see it from the outside.
 *
 * THE FRAMING IS DONE BY HAND, and that is not preference. matter_exchange.c's
 * frame() sends no SOURCE node id on an unsecured session -- correct for a
 * responder, which addresses its reply by the initiator's ephemeral id -- but a
 * CASE INITIATOR must send one, and this node's own responder refuses a Sigma1
 * without it (matter_thread_on_datagram_owned, "cannot address a reply"). So
 * the handshake messages are built here out of matter_msg_header_encode() and
 * matter_proto_header_encode(), and the exchange layer takes over only once the
 * session exists and its rules start being the right ones.
 *
 * LOCKING. Three contexts touch this: the walk-up path (matter_client_want),
 * the system work queue (the poll), and OpenThread's own thread (the inbound
 * hooks and the resolve callback). The poll holds s_lock and then calls into
 * OpenThread to send; the hooks arrive from OpenThread and want s_lock. That is
 * a cycle, so the hooks TRY the lock and give up rather than wait -- the same
 * shape, and the same reasoning, as matter_thread_on_datagram()'s try-lock on
 * the commissioning owner. A lost inbound message costs one step timeout.
 */
#include <stdio.h> /* snprintf, for the operational instance name */
#include <string.h>

#include <zephyr/logging/log.h>

#include "matter_client.h"

#include "matter_binding.h"
#include "matter_case.h"
#include "matter_case_client.h"
#include "matter_client_sm.h"
#include "matter_crypto.h"
#include "matter_exchange.h"
#include "matter_fabric.h"
#include "matter_im.h"
#include "matter_im_client.h"
#include "matter_mrp.h"
#include "matter_pase_sm.h"
#include "matter_thread.h"
#include "matter_tlv.h"

#include "ultrawidelock_hash.h"
#include "ultrawidelock_osal.h"
#include "ultrawidelock_port.h"
#include "ultrawidelock_prim.h"

/* The client shares a 433,664-byte slot with the complete lock. Keep normal
 * images to actionable failures; overlay-client-debug.conf restores DBG for
 * bench diagnosis. */
#if defined(CONFIG_ULTRAWIDELOCK_MATTER_CLIENT_LOG_LEVEL_DBG)
LOG_MODULE_REGISTER(matter_client, LOG_LEVEL_DBG);
#else
LOG_MODULE_REGISTER(matter_client, LOG_LEVEL_WRN);
#endif

/**
 * Enough for the two messages this node ORIGINATES rather than replies with.
 *
 * A Sigma1 (MATTER_CASE_SIGMA1_MAX) plus both headers is the larger of them; a
 * TimedRequest is under seventy bytes sealed. Everything else this client sends
 * is a reply, and a reply is built in the buffer the datagram handler already
 * owns -- which is why this is the only outbound buffer in the file.
 */
#define CLIENT_TX_MAX (MATTER_CASE_SIGMA1_MAX + MATTER_EXCHANGE_HEADER_MAX + MATTER_TAG_LEN)

/**
 * How long the peer should hold its timed-invoke window open.
 *
 * A statement about this node's latency and not a preference: the
 * InvokeRequest has to arrive inside it, and it leaves as the reply to the
 * StatusResponse that closes the TimedRequest -- one round trip on a Thread
 * mesh. Two seconds is generous for that and short enough that a window this
 * node abandons does not sit open at the far lock.
 */
#define CLIENT_TIMED_MS 2000u

/**
 * How long the handshake's exchange stays answerable after it has succeeded.
 *
 * The peer sets R on the StatusReport that ends CASE, so it retransmits until
 * acknowledged. This node sends that acknowledgement once and does not repeat
 * it. Letting the exchange go the instant the report is handled means the
 * retransmission -- a Secure Channel message that is neither Sigma1 nor Sigma3
 * -- routes to nobody and is dropped, and the peer spends its whole MRP
 * schedule talking to a node that has stopped listening while this one is
 * already sending on the session.
 *
 * So the exchange lingers, long enough to cover a peer's retransmits, and
 * answers a repeat with another acknowledgement and no change of state.
 */
#define CLIENT_HS_LINGER_MS 3000u

/** Where the two-message invoke has got to. The state machine has no opinion
 * on this: DO_INVOKE is one action, and this is what it costs to perform. */
enum invoke_step {
	INVOKE_IDLE = 0,
	/** TimedRequest out; waiting for the peer's StatusResponse. */
	INVOKE_TIMED,
	/** InvokeRequest out; waiting for the InvokeResponse. */
	INVOKE_SENT,
};

static struct matter_device_info *s_info;
static struct matter_client_sm s_sm;
static ultrawidelock_mutex_t s_lock;

/** The one client session, once the handshake has built one. */
static struct matter_exchange s_x;
static bool s_session;

/** Who this attempt is for, chosen from the binding table when it starts. */
static const struct matter_fabric *s_fabric;
/** The fabric id s_fabric carried when this attempt chose it; see
 * fabric_still_held(), which cannot tell a reused slot from its address. */
static uint64_t s_fabric_id;
static uint64_t s_peer_node;
static uint16_t s_peer_endpoint;
static struct matter_thread_peer s_peer;
/**
 * This node's own operational public key, read out of the NOC it will ship.
 *
 * Only so the Sigma3 signature can be checked against the certificate that
 * travels with it, before a peer gets the chance to reject it without saying
 * why. Parsed in choose_target() -- once per attempt, not once per Sigma3, and
 * not on OpenThread's stack.
 *
 * False leaves the check off rather than failing the attempt: an unparsable NOC
 * is a problem the handshake itself will report, and refusing here would turn a
 * diagnostic into an outage.
 */
static uint8_t s_noc_pub[MATTER_CASE_PUBKEY_LEN];
static bool s_have_noc_pub;

/*
 * The handshake's working set. Live only between a Sigma1 leaving and the
 * session existing, and wiped when it does: an ephemeral private key kept past
 * the handshake it belongs to is a key with no reason to still be in RAM.
 */
static uint8_t s_eph_priv[32];
static uint8_t s_eph_pub[MATTER_CASE_PUBKEY_LEN];
static uint8_t s_ipk[MATTER_CASE_IPK_LEN];
static uint8_t s_shared[MATTER_CASE_SECRET_LEN];
static struct ultrawidelock_sha256 s_transcript;
static uint16_t s_local_session;
static uint16_t s_peer_session;
/**
 * The exchange the HANDSHAKE runs on, and the one the interaction runs on.
 *
 * Two, because they overlap. The peer's StatusReport -- its verdict on the
 * Sigma3, and the last unsecured message either side sends -- arrives on the
 * handshake's exchange AFTER this node has already installed the session and
 * chosen an exchange for what comes next. One variable would have been
 * overwritten by then, and the StatusReport would be routed to nobody.
 */
static uint16_t s_hs_exchange;
static uint16_t s_exchange_id;
/** True from a Sigma1 leaving until the handshake ends, either way. */
static bool s_handshake;
/** Deadline until which a SUCCEEDED handshake still answers on its exchange;
 * 0 when there is nothing to answer for. See CLIENT_HS_LINGER_MS. */
static uint32_t s_hs_linger_until;
/** The unsecured message counter, randomised once; see send_sigma2()'s note. */
static uint32_t s_counter;

static uint8_t s_invoke_step;
static uint32_t s_invoke_ms;
static uint8_t s_tx[CLIENT_TX_MAX];

/*
 * Retransmission, for the half of this exchange the node ORIGINATES.
 *
 * matter_mrp.h explains why the responder side arms no timer, and names the
 * condition that would change it: something which must arrive PROMPTLY and is
 * not a reply. A Sigma1 sent because a person is standing at the door is
 * exactly that. Without it a single dropped datagram costs the whole
 * MATTER_CLIENT_STEP_MS -- five seconds out of a want worth eight -- so one
 * loss very nearly spends the budget and two certainly do.
 *
 * The UNSECURED handshake only. Past the session the interaction is sealed by
 * matter_exchange, whose message counters this file does not own; a loss there
 * falls in a much shorter window, and the peer retransmits its own half of it
 * regardless.
 */
static struct matter_mrp s_mrp;
static uint8_t s_rtx[CLIENT_TX_MAX];
static size_t s_rtx_len;

/*
 * The resolve answer, handed over WITHOUT the lock.
 *
 * matter_thread_resolve()'s callback runs on OpenThread's thread with its API
 * mutex held, which is exactly the context that must never wait for s_lock. So
 * the callback only stores and posts; the work applies it.
 */
static struct matter_thread_peer s_resolved;
static ultrawidelock_atomic_t s_resolve_state;
#define RESOLVE_NONE 0
#define RESOLVE_OK   1
#define RESOLVE_FAIL 2

static void poll_work_fn(struct ultrawidelock_dwork *w);
static struct ultrawidelock_dwork s_poll_work;

/*
 * The work queue's clock, not the system's -- they are the same thing on
 * target and deliberately are not on a host, where the suite steps the clock
 * to walk this machine through its timeouts. Reading anything else here would
 * measure elapsed time against deadlines set on a different clock.
 */
static uint32_t now_ms(void)
{
	return (uint32_t)ultrawidelock_osal_now_ms();
}

/** Ask for a poll in @p delay_ms. UINT32_MAX means "there is nothing to wait
 * for", which is the normal state of a lock nobody is standing in front of. */
static void poll_at(uint32_t delay_ms)
{
	if (delay_ms == UINT32_MAX) {
		return;
	}
	(void)ultrawidelock_dwork_reschedule(&s_poll_work, (int32_t)delay_ms);
}

/**
 * How long until this file next needs the CPU.
 *
 * The schedule's own deadline, or the handshake's next retransmission,
 * whichever comes first. EVERY place that re-arms the poll has to use this:
 * arming from the schedule alone silently drops a pending resend, and the
 * places that re-arm are the inbound paths -- which is exactly where a message
 * that did NOT acknowledge the outstanding one arrives.
 */
static uint32_t next_wake_ms(uint32_t now)
{
	uint32_t next = matter_client_sm_next_ms(&s_sm, now);
	uint32_t due;

	if (s_handshake && matter_mrp_next_deadline(&s_mrp, &due)) {
		uint32_t in_ms = (int32_t)(due - now) > 0 ? (uint32_t)(due - now) : 0u;

		if (in_ms < next) {
			next = in_ms;
		}
	}
	return next;
}

/* ---- the peer this attempt is for ------------------------------------------ */

/** The fabric @p index names, or NULL. */
static const struct matter_fabric *fabric_of(uint8_t index)
{
	if (s_info == NULL || index == 0u) {
		return NULL;
	}
	for (size_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if (s_info->fabrics[i].index == index) {
			return &s_info->fabrics[i];
		}
	}
	return NULL;
}

/**
 * Pick the target this attempt is for, and derive the fabric key material.
 *
 * The FIRST unicast Door Lock target whose fabric this node still holds. A
 * binding whose administrator has been removed is skipped rather than refused:
 * the table is walked again on the next attempt, and by then the removal may be
 * the only thing that changed.
 *
 * @return true when s_fabric, s_peer_node, s_peer_endpoint and s_ipk are set.
 */
static bool choose_target(void)
{
	uint8_t idx = 0u;
	const struct matter_binding_target *t;

	if (s_info == NULL) {
		return false;
	}
	while ((t = matter_binding_next(&s_info->binding, MATTER_CLUSTER_DOOR_LOCK, &idx)) !=
	       NULL) {
		const struct matter_fabric *f = fabric_of(t->fabric_index);
		uint8_t cfid[MATTER_COMPRESSED_FABRIC_LEN];

		if (f == NULL || f->noc_len == 0u) {
			continue;
		}
		if (matter_fabric_compressed_id(f->root_public_key, f->fabric_id, cfid) !=
			    MATTER_OK ||
		    matter_case_operational_ipk(f->ipk, cfid, s_ipk) != MATTER_OK) {
			LOG_ERR("fabric %u key derivation failed", f->index);
			continue;
		}
		{
			struct matter_cert_info ci;

			s_have_noc_pub = matter_cert_parse(f->noc, f->noc_len, &ci) == MATTER_OK &&
					 ci.have_public_key;
			if (s_have_noc_pub) {
				memcpy(s_noc_pub, ci.public_key, sizeof(s_noc_pub));
			} else {
				LOG_DBG("fabric %u NOC has no public key", f->index);
			}
		}
		s_fabric = f;
		s_fabric_id = f->fabric_id;
		s_peer_node = t->node_id;
		s_peer_endpoint = t->has_endpoint ? t->endpoint : 1u;
		return true;
	}
	return false;
}

/**
 * Is the fabric this attempt was chosen for still one this node holds?
 *
 * s_fabric points INTO s_info->fabrics[], so a RemoveFabric that zeroes the
 * slot leaves it pointing at valid memory describing nothing. Looking the index
 * up again catches that: a cleared slot has index 0 and matches nothing.
 *
 * The fabric id is checked as well, and the address is NOT enough on its own.
 * A slot is an array position, so an administrator removed and another one
 * commissioned into the same position gives back the very same pointer, with
 * the same index, describing somebody else entirely. Address alone would call
 * that "still held" and go on to unlock a door on behalf of an administrator
 * this node was told to forget.
 */
static bool fabric_still_held(void)
{
	return s_fabric != NULL && fabric_of(s_fabric->index) == s_fabric &&
	       s_fabric->noc_len != 0u && s_fabric->fabric_id == s_fabric_id;
}

/**
 * Keep @p msg as the message awaiting an acknowledgement, and time its resend.
 *
 * Called after EVERY transmission including the first, which is what grows the
 * backoff -- see matter_mrp_arm().
 */
static void arm_retransmit(const uint8_t *msg, size_t len, uint32_t counter, uint32_t now)
{
	uint8_t jitter = 0u;

	if (len == 0u || len > sizeof(s_rtx)) {
		/* Nothing that will not fit is worth half-keeping: the step
		 * deadline still covers the message, one whole attempt at a
		 * time, which is what happened before any of this existed. */
		s_rtx_len = 0u;
		return;
	}
	if (msg != s_rtx) {
		memcpy(s_rtx, msg, len);
	}
	s_rtx_len = len;
	(void)ultrawidelock_random(&jitter, sizeof(jitter));
	(void)matter_mrp_arm(&s_mrp, counter, now, jitter);
}

/** Forget the session and the handshake's secrets, in that order. */
static void drop_session(void)
{
	s_session = false;
	s_handshake = false;
	s_hs_linger_until = 0u;
	s_invoke_step = (uint8_t)INVOKE_IDLE;
	memset(&s_x, 0, sizeof(s_x));
	memset(s_eph_priv, 0, sizeof(s_eph_priv));
	memset(s_shared, 0, sizeof(s_shared));
	matter_mrp_init(&s_mrp, MATTER_MRP_IDLE_INTERVAL_MS);
	s_rtx_len = 0u;
	matter_client_sm_session_lost(&s_sm);
}

/* ---- framing --------------------------------------------------------------- */

/**
 * Both headers for one message this node sends on the UNSECURED session.
 *
 * The SOURCE node id is this node's operational id on the target's fabric, not
 * a random ephemeral one. It is a truthful answer to the field's question, it
 * is what the peer echoes back as the destination, and it makes a capture
 * readable -- against an ephemeral id, whose only advantage is that it says
 * less to an observer who can already see the Sigma1's destination identifier.
 *
 * @return the header length, or 0 if it would not fit.
 */
static size_t frame_headers(uint8_t opcode, bool reliable, bool ack, uint32_t ack_counter,
			    uint8_t *out, size_t cap)
{
	struct matter_msg_header mh;
	struct matter_proto_header ph;
	size_t mh_len = 0u;
	size_t ph_len = 0u;

	if (s_counter == 0u) {
		if (ultrawidelock_random((uint8_t *)&s_counter, sizeof(s_counter)) != 0) {
			LOG_ERR("no entropy for the message counter");
			return 0u;
		}
		s_counter &= MATTER_COUNTER_INIT_MASK; /* leave room to increment */
	}

	memset(&mh, 0, sizeof(mh));
	mh.flags = MATTER_MSG_FLAG_S | MATTER_MSG_DSIZ_NONE;
	mh.session_id = MATTER_SESSION_ID_UNSECURED;
	mh.security_flags = MATTER_SESSION_TYPE_UNICAST;
	mh.message_counter = ++s_counter;
	mh.source_node_id = s_fabric != NULL ? s_fabric->node_id : 0u;
	if (matter_msg_header_encode(&mh, out, cap, &mh_len) != MATTER_OK) {
		return 0u;
	}

	memset(&ph, 0, sizeof(ph));
	/* I, because this node opened the exchange and keeps that role for its
	 * whole life. R on every handshake message, which all want an answer,
	 * and never on a bare acknowledgement -- an ack that asks to be
	 * acknowledged is an exchange that never ends. */
	ph.exchange_flags = MATTER_EX_FLAG_I;
	if (reliable) {
		ph.exchange_flags |= MATTER_EX_FLAG_R;
	}
	if (ack) {
		ph.exchange_flags |= MATTER_EX_FLAG_A;
		ph.ack_counter = ack_counter;
	}
	ph.opcode = opcode;
	ph.exchange_id = s_hs_exchange;
	ph.protocol_id = MATTER_PROTOCOL_SECURE_CHANNEL;
	if (matter_proto_header_encode(&ph, out + mh_len, cap - mh_len, &ph_len) != MATTER_OK) {
		return 0u;
	}
	return mh_len + ph_len;
}

/* ---- the handshake --------------------------------------------------------- */

/** Build and send a Sigma1. Everything it needs is already chosen. */
static bool send_sigma1(void)
{
	struct matter_case_client_sigma1_in in;
	uint8_t random[MATTER_CASE_RANDOM_LEN];
	size_t hdr;
	size_t payload = 0u;
	int rc;

	if (!s_peer.valid || s_fabric == NULL) {
		return false;
	}
	/* A new handshake owns the exchange from here; whatever the last one was
	 * still answering for is finished. */
	s_hs_linger_until = 0u;
	matter_mrp_init(&s_mrp, MATTER_MRP_IDLE_INTERVAL_MS);
	s_rtx_len = 0u;
	if (ultrawidelock_ec_p256_keygen(s_eph_priv, s_eph_pub) != 0 ||
	    ultrawidelock_random(random, sizeof(random)) != 0 ||
	    ultrawidelock_random((uint8_t *)&s_local_session, sizeof(s_local_session)) != 0 ||
	    ultrawidelock_random((uint8_t *)&s_hs_exchange, sizeof(s_hs_exchange)) != 0) {
		LOG_ERR("no entropy for a Sigma1");
		return false;
	}
	/*
	 * Session id 0 is the unsecured session by definition, so it can never
	 * be this node's. A COLLISION with a session this node is already
	 * answering on is possible and is not checked: those live in
	 * matter_commission.c's table, the routing there tries that table first,
	 * and the cost of the one-in-65535 case is a client handshake that times
	 * out and retries with a fresh id.
	 */
	if (s_local_session == 0u) {
		s_local_session = 1u;
	}

	hdr = frame_headers(MATTER_OP_CASE_SIGMA1, true, false, 0u, s_tx, sizeof(s_tx));
	if (hdr == 0u) {
		return false;
	}

	memset(&in, 0, sizeof(in));
	in.ipk = s_ipk;
	in.root_pub = s_fabric->root_public_key;
	in.fabric_id = s_fabric->fabric_id;
	in.peer_node_id = s_peer_node;
	in.initiator_random = random;
	in.initiator_eph_pub = s_eph_pub;
	in.initiator_session_id = s_local_session;
	rc = matter_case_client_sigma1_encode(&in, s_tx + hdr, sizeof(s_tx) - hdr, &payload);
	memset(random, 0, sizeof(random));
	if (rc != MATTER_OK) {
		LOG_ERR("cannot build a Sigma1 (%d)", rc);
		return false;
	}

	/* The transcript covers PAYLOADS, never headers. */
	ultrawidelock_sha256_init(&s_transcript);
	ultrawidelock_sha256_update(&s_transcript, s_tx + hdr, payload);

	rc = matter_thread_send_to(&s_peer, s_tx, hdr + payload);
	if (rc != MATTER_OK) {
		LOG_WRN("Sigma1 not sent (%d)", rc);
		return false;
	}
	s_handshake = true;
	arm_retransmit(s_tx, hdr + payload, s_counter, now_ms());
	LOG_DBG("Sigma1 out to node 0x%08x%08x, session 0x%04x", (unsigned int)(s_peer_node >> 32),
		(unsigned int)s_peer_node, (unsigned int)s_local_session);
	return true;
}

/**
 * Open a Sigma2 and answer it with a Sigma3, framed into @p reply.
 *
 * The session is installed HERE rather than when the peer's StatusReport
 * arrives, because the Sigma3 is the last thing this node can say in the clear:
 * from the peer's point of view the session exists the moment it accepts one.
 *
 * @return the reply length, or 0 when the Sigma2 was not acceptable.
 */
static size_t handle_sigma2(const uint8_t *payload, size_t payload_len,
			    const struct matter_msg_header *mh, uint8_t *reply, size_t cap)
{
	struct matter_case_client_sigma2 s2;
	struct matter_case_client_sigma2_in open;
	struct matter_case_client_sigma2_out peer;
	struct matter_case_client_sigma3_in s3;
	struct matter_session_keys keys;
	struct ultrawidelock_sha256 snapshot;
	uint8_t digest[ULTRAWIDELOCK_SHA256_LEN];
	uint8_t responder_eph[MATTER_CASE_PUBKEY_LEN];
	uint32_t seed = 0u;
	size_t hdr;
	size_t s3_len = 0u;
	int rc;

	rc = matter_case_client_sigma2_decode(payload, payload_len, &s2);
	if (rc != MATTER_OK) {
		LOG_ERR("Sigma2 unreadable (%d)", rc);
		return 0u;
	}
	/* Copied out before the transcript moves on: `s2` borrows the datagram,
	 * and the Sigma3 built below still needs the responder's key. */
	memcpy(responder_eph, s2.responder_eph_pub, sizeof(responder_eph));
	s_peer_session = s2.responder_session_id;

	snapshot = s_transcript;
	ultrawidelock_sha256_final(&snapshot, digest);

	memset(&open, 0, sizeof(open));
	open.s2 = &s2;
	open.ipk = s_ipk;
	open.transcript_hash = digest;
	open.initiator_eph_priv = s_eph_priv;
	open.initiator_eph_pub = s_eph_pub;
	open.root_pub = s_fabric->root_public_key;
	open.fabric_id = s_fabric->fabric_id;
	open.peer_node_id = s_peer_node;
	rc = matter_case_client_sigma2_open(&open, &peer);
	if (rc != MATTER_OK) {
		/*
		 * Each failure is reported separately by the opener, and which
		 * one it was is the whole diagnosis: MATTER_E_TYPE means the
		 * peer does not hold this fabric's keys, MATTER_E_ACCESS means
		 * it holds them and is not who this node asked for.
		 */
		LOG_ERR("Sigma2 REJECTED (%d)%s", rc,
			rc == MATTER_E_ACCESS ? " -- chain or identity" : "");
		return 0u;
	}

	/* Sigma1 || Sigma2, which is what S3K is salted with. */
	ultrawidelock_sha256_update(&s_transcript, payload, payload_len);
	snapshot = s_transcript;
	ultrawidelock_sha256_final(&snapshot, digest);

	hdr = frame_headers(MATTER_OP_CASE_SIGMA3, true, true, mh->message_counter, reply, cap);
	if (hdr == 0u) {
		return 0u;
	}

	memset(&s3, 0, sizeof(s3));
	s3.shared = peer.shared;
	s3.ipk = s_ipk;
	s3.transcript_hash = digest;
	s3.initiator_eph_pub = s_eph_pub;
	s3.responder_eph_pub = responder_eph;
	s3.noc = s_fabric->noc;
	s3.noc_len = s_fabric->noc_len;
	s3.icac = (s_info->icac.owner_index == s_fabric->index && s_info->icac.len > 0u)
			  ? s_info->icac.buf
			  : NULL;
	s3.icac_len = s3.icac != NULL ? s_info->icac.len : 0u;
	s3.op_priv = s_fabric->op_priv;
	/*
	 * Never NULL on hardware: a peer that rejects a signature says nothing
	 * about why, and this is the only place the mistake is still visible.
	 *
	 * It was NULL here until this line was written, which meant the check
	 * this comment describes was not being made at all -- the server half
	 * passes it (matter_commission.c) and the host tests pass it, so the one
	 * configuration that skipped it was the firmware. The key comes from
	 * choose_target(), which parses it out of the NOC once per attempt
	 * rather than once per Sigma3.
	 */
	s3.verify_pub = s_have_noc_pub ? s_noc_pub : NULL;
	rc = matter_case_client_sigma3_encode(&s3, reply + hdr, cap - hdr, &s3_len);
	if (rc != MATTER_OK) {
		LOG_ERR("cannot build a Sigma3 (%d)", rc);
		return 0u;
	}

	/* Sigma1 || Sigma2 || Sigma3: the session keys' salt. */
	ultrawidelock_sha256_update(&s_transcript, reply + hdr, s3_len);
	snapshot = s_transcript;
	ultrawidelock_sha256_final(&snapshot, digest);

	memcpy(s_shared, peer.shared, sizeof(s_shared));
	rc = matter_case_client_keys(s_shared, s_ipk, digest, &keys);
	if (rc != MATTER_OK) {
		LOG_ERR("no session keys (%d)", rc);
		return 0u;
	}
	if (ultrawidelock_random((uint8_t *)&seed, sizeof(seed)) != 0) {
		memset(&keys, 0, sizeof(keys));
		LOG_ERR("no entropy for the session counter");
		return 0u;
	}
	/*
	 * The interaction gets its own exchange, chosen now: the handshake's id
	 * belongs to an exchange the peer considers finished the moment it
	 * accepts this Sigma3, and re-using it invites the peer's duplicate
	 * suppression to answer a TimedRequest with the StatusReport it already
	 * sent.
	 */
	s_exchange_id = (uint16_t)(s_hs_exchange + 1u);
	rc = matter_exchange_open_initiator(&s_x, s_local_session, s_peer_session, s_exchange_id,
					    &keys, seed);
	memset(&keys, 0, sizeof(keys));
	if (rc != MATTER_OK) {
		LOG_ERR("CASE session NOT installed (%d)", rc);
		return 0u;
	}
	/* Nonces are built from the two OPERATIONAL node ids, which travel in no
	 * header. As the INITIATOR this node seals with its own. */
	matter_exchange_set_op_node_ids(&s_x, s_fabric->node_id, peer.node_id);
	s_session = true;

	/* The handshake is over; nothing below needs its private half. */
	memset(s_eph_priv, 0, sizeof(s_eph_priv));

	LOG_DBG("Sigma3 out: session 0x%04x local, 0x%04x peer", (unsigned int)s_local_session,
		(unsigned int)s_peer_session);
	return hdr + s3_len;
}

/* ---- the invoke ------------------------------------------------------------ */

/** Frame one message on the client's secure session, as the exchange's initiator. */
static size_t send_secure(uint8_t opcode, const uint8_t *body, size_t body_len, uint8_t *out,
			  size_t cap)
{
	size_t len = 0u;
	int rc;

	rc = matter_exchange_send_initiator(&s_x, s_exchange_id, MATTER_PROTOCOL_INTERACTION_MODEL,
					    opcode, body, body_len, out, cap, &len);
	if (rc != MATTER_OK) {
		LOG_DBG("cannot frame opcode 0x%02x (%d)", opcode, rc);
		return 0u;
	}
	return len;
}

/**
 * Start the invoke: a TimedRequest, because UnlockDoor is a timed command.
 *
 * Sent rather than replied, because the session may have been warm since a
 * walk-up minutes ago and there is nothing to reply to.
 */
static bool send_timed_request(void)
{
	uint8_t body[MATTER_IM_CLIENT_TIMED_MAX];
	size_t body_len = 0u;
	size_t len;

	if (matter_im_client_timed_request_encode(CLIENT_TIMED_MS, body, sizeof(body), &body_len) !=
	    MATTER_OK) {
		return false;
	}
	len = send_secure(MATTER_IM_OP_TIMED_REQUEST, body, body_len, s_tx, sizeof(s_tx));
	if (len == 0u) {
		return false;
	}
	if (matter_thread_send_to(&s_peer, s_tx, len) != MATTER_OK) {
		return false;
	}
	s_invoke_step = (uint8_t)INVOKE_TIMED;
	s_invoke_ms = now_ms();
	return true;
}

/** The UnlockDoor itself, as the reply to the peer's StatusResponse. */
static size_t send_invoke(uint8_t *reply, size_t cap)
{
	struct matter_im_client_invoke inv;
	struct matter_im_client_pin pin;
	uint8_t body[MATTER_IM_CLIENT_INVOKE_MAX];
	size_t body_len = 0u;
	size_t len;

	pin.pin = s_info->binding.pin_len > 0u ? s_info->binding.pin : NULL;
	pin.pin_len = s_info->binding.pin_len;

	memset(&inv, 0, sizeof(inv));
	inv.endpoint = s_peer_endpoint;
	inv.cluster = MATTER_CLUSTER_DOOR_LOCK;
	inv.command = MATTER_CMD_DL_UNLOCK_DOOR;
	inv.fields = matter_im_client_unlock_fields;
	inv.fields_ctx = &pin;
	inv.timed_request = true;
	if (matter_im_client_invoke_encode(&inv, body, sizeof(body), &body_len) != MATTER_OK) {
		return 0u;
	}

	len = 0u;
	if (matter_exchange_continue_initiator(&s_x, s_exchange_id,
					       MATTER_PROTOCOL_INTERACTION_MODEL,
					       MATTER_IM_OP_INVOKE_COMMAND_REQUEST, body, body_len,
					       reply, cap, &len) != MATTER_OK) {
		len = 0u;
	}
	if (len == 0u) {
		return 0u;
	}
	s_invoke_step = (uint8_t)INVOKE_SENT;
	s_invoke_ms = now_ms();
	LOG_DBG("UnlockDoor out: endpoint %u%s", s_peer_endpoint,
		pin.pin_len > 0u ? ", with a PIN" : "");
	return len;
}

/* ---- the poll -------------------------------------------------------------- */

static void on_resolved(void *ctx, const struct matter_thread_peer *peer)
{
	(void)ctx;

	if (peer != NULL && peer->valid) {
		s_resolved = *peer;
		(void)ultrawidelock_atomic_xchg(&s_resolve_state, RESOLVE_OK);
	} else {
		(void)ultrawidelock_atomic_xchg(&s_resolve_state, RESOLVE_FAIL);
	}
	(void)ultrawidelock_dwork_reschedule(&s_poll_work, 0);
}

/** Ask DNS-SD where the chosen target is. */
static bool start_resolve(void)
{
	char instance[MATTER_INSTANCE_NAME_LEN];
	uint8_t cfid[MATTER_COMPRESSED_FABRIC_LEN];
	uint64_t compressed = 0u;
	int n;

	if (s_fabric == NULL ||
	    matter_fabric_compressed_id(s_fabric->root_public_key, s_fabric->fabric_id, cfid) !=
		    MATTER_OK) {
		return false;
	}
	for (size_t i = 0u; i < sizeof(cfid); i++) {
		compressed = (compressed << 8) | cfid[i];
	}
	/*
	 * The peer's node id under THIS node's compressed fabric id, which is
	 * why matter_fabric_instance_name() cannot be used: it names the fabric
	 * member this node IS, and the one being looked up is somebody else.
	 * Two %08X halves for the reason that function gives.
	 */
	n = snprintf(instance, sizeof(instance), "%08X%08X-%08X%08X",
		     (unsigned int)(compressed >> 32), (unsigned int)compressed,
		     (unsigned int)(s_peer_node >> 32), (unsigned int)s_peer_node);
	if (n < 0 || (size_t)n >= sizeof(instance)) {
		return false;
	}
	(void)ultrawidelock_atomic_xchg(&s_resolve_state, RESOLVE_NONE);
	if (matter_thread_resolve(instance, on_resolved, NULL) != MATTER_OK) {
		return false;
	}
	LOG_DBG("resolving %s", instance);
	return true;
}

static void poll_work_fn(struct ultrawidelock_dwork *w)
{
	uint32_t t;
	uint32_t next;
	int resolved;

	(void)w;

	ultrawidelock_mutex_lock(&s_lock);
	t = now_ms();

	resolved = (int)ultrawidelock_atomic_xchg(&s_resolve_state, RESOLVE_NONE);
	/*
	 * Only while this is still the answer being waited for. A query whose
	 * step deadline already expired can still call back, and reporting that
	 * late answer would move a client out of its backoff -- or, worse, out
	 * of a session it has since established -- on the strength of a lookup
	 * nobody is waiting for any more.
	 */
	if (s_sm.state != (uint8_t)MATTER_CLIENT_RESOLVING) {
		resolved = RESOLVE_NONE;
	}
	if (resolved == RESOLVE_OK) {
		s_peer = s_resolved;
		matter_client_sm_resolved(&s_sm, true, t);
	} else if (resolved == RESOLVE_FAIL) {
		s_peer.valid = false;
		LOG_DBG("the bound lock did not resolve");
		matter_client_sm_resolved(&s_sm, false, t);
	}

	/*
	 * The administrator this attempt belongs to may have been removed since
	 * it started. Everything below would otherwise carry on with a zeroed
	 * key: a Sigma1 signed with nothing, or worse, an unlock sent on behalf
	 * of somebody this node was told to forget.
	 */
	if (s_fabric != NULL && !fabric_still_held()) {
		LOG_DBG("bound administrator removed");
		s_fabric = NULL;
		if (s_session || s_handshake) {
			drop_session();
		}
	}

	/*
	 * An interaction in flight is not something to poll around. The state
	 * machine still says DO_INVOKE -- the want is not cleared until the peer
	 * answers -- so acting on it here would send a second TimedRequest into
	 * a window that is already open.
	 */
	if (s_invoke_step != (uint8_t)INVOKE_IDLE) {
		if ((int32_t)(t - (s_invoke_ms + MATTER_CLIENT_STEP_MS)) >= 0) {
			LOG_DBG("bound lock stopped answering");
			drop_session();
			matter_client_sm_failed(&s_sm, t);
		} else {
			ultrawidelock_mutex_unlock(&s_lock);
			poll_at(MATTER_CLIENT_STEP_MS);
			return;
		}
	}

	switch (matter_client_sm_poll(&s_sm, t)) {
	case MATTER_CLIENT_DO_RESOLVE:
		/* A target is chosen HERE and not before: the binding table may
		 * have been written since the last attempt, and an attempt aimed
		 * at a target that has been unbound is one nobody asked for. */
		if (!choose_target() || !start_resolve()) {
			matter_client_sm_resolved(&s_sm, false, t);
		}
		break;

	case MATTER_CLIENT_DO_SIGMA1:
		/* Liveness rather than NULL: a pointer into a slot that has been
		 * cleared is not null and is not usable either. */
		if (!fabric_still_held() && !choose_target()) {
			matter_client_sm_failed(&s_sm, t);
			break;
		}
		if (send_sigma1()) {
			matter_client_sm_sent(&s_sm, t);
		} else {
			matter_client_sm_failed(&s_sm, t);
		}
		break;

	case MATTER_CLIENT_DO_INVOKE:
		if (!s_session) {
			/* The session went while the want was waiting for it. */
			matter_client_sm_session_lost(&s_sm);
			break;
		}
		if (!send_timed_request()) {
			drop_session();
			matter_client_sm_failed(&s_sm, t);
		}
		break;

	case MATTER_CLIENT_DO_SIGMA3:
	case MATTER_CLIENT_DO_NOTHING:
	default:
		break;
	}

	/*
	 * A handshake the schedule has given up on is one this file must give up
	 * on too, and nothing else says so: matter_client_sm_poll() leaves SIGMA1
	 * on its own deadline, silently, because it has no clock and no opinion
	 * about what its caller is still holding.
	 *
	 * Left set, s_handshake keeps an abandoned attempt's working set alive:
	 * the ephemeral private key and the transcript stay in RAM past the
	 * attempt they belong to, the exchange id stays claimed against every
	 * inbound unsecured message, and a Sigma2 arriving long after the attempt
	 * was written off is opened as though somebody were still waiting for it.
	 * That last one is the expensive case -- it would install a session for
	 * an unlock nobody asked for any more.
	 */
	/*
	 * The handshake's retransmit. Only while one is outstanding: past the
	 * session the interaction is matter_exchange's, and a timer still armed
	 * from the handshake would resend a Sigma3 into an established session.
	 */
	if (s_handshake) {
		uint32_t counter = 0u;

		switch (matter_mrp_poll(&s_mrp, t, &counter)) {
		case MATTER_MRP_RETRANSMIT:
			if (s_rtx_len != 0u &&
			    matter_thread_send_to(&s_peer, s_rtx, s_rtx_len) == MATTER_OK) {
				LOG_DBG("handshake message resent");
				arm_retransmit(s_rtx, s_rtx_len, counter, t);
			}
			break;

		case MATTER_MRP_GIVE_UP:
			LOG_DBG("handshake not acknowledged");
			drop_session();
			matter_client_sm_failed(&s_sm, t);
			break;

		case MATTER_MRP_SEND_ACK:
		case MATTER_MRP_IDLE:
		default:
			break;
		}
	}

	if (s_handshake && s_sm.state != (uint8_t)MATTER_CLIENT_SIGMA1 &&
	    s_sm.state != (uint8_t)MATTER_CLIENT_SIGMA3) {
		LOG_DBG("handshake unanswered");
		drop_session();
	}

	next = next_wake_ms(now_ms());
	ultrawidelock_mutex_unlock(&s_lock);
	poll_at(next);
}

/* ---- the seams matter_commission.c and main.c use -------------------------- */

void matter_client_init(struct matter_device_info *info)
{
	ultrawidelock_mutex_init(&s_lock);
	ultrawidelock_dwork_init(&s_poll_work, poll_work_fn);
	/*
	 * Everything this file remembers, not just the pointers. On target this
	 * runs once and there is nothing to forget; the reset is here because
	 * "initialised" has to mean the same thing the second time, and a state
	 * machine whose starting point depends on what ran before it is one no
	 * test can pin down and no field reinitialisation can trust.
	 */
	drop_session();
	s_fabric = NULL;
	s_fabric_id = 0u;
	s_have_noc_pub = false;
	s_peer_node = 0u;
	s_peer_endpoint = 0u;
	s_peer.valid = false;
	s_resolved.valid = false;
	(void)ultrawidelock_atomic_xchg(&s_resolve_state, RESOLVE_NONE);
	s_counter = 0u;
	s_hs_exchange = 0u;
	s_exchange_id = 0u;
	s_local_session = 0u;
	s_peer_session = 0u;
	s_invoke_ms = 0u;
	s_info = info;
	matter_client_sm_init(&s_sm);
}

void matter_client_want(void)
{
	if (s_info == NULL) {
		return;
	}
	/*
	 * No lock and no work of its own: this is the walk-up path, and the
	 * whole contract of this file is that it costs the person at the door
	 * nothing. matter_client_sm_want() writes two fields, and the worst a
	 * race with the poll can do is act on the want one cycle later.
	 */
	matter_client_sm_want(&s_sm, now_ms());
	(void)ultrawidelock_dwork_reschedule(&s_poll_work, 0);
}

bool matter_client_owns_session(uint16_t session_id)
{
	return s_session && s_x.secure && s_x.local_session_id == session_id;
}

bool matter_client_owns_exchange(uint16_t exchange_id)
{
	/* Only while a handshake is outstanding, or briefly after one succeeded
	 * so the peer's retransmitted StatusReport still has somewhere to go. An
	 * exchange id this node used minutes ago is not its business any more,
	 * and claiming it would swallow a message meant for the responder. */
	if (exchange_id != s_hs_exchange) {
		return false;
	}
	if (s_handshake) {
		return true;
	}
	return s_hs_linger_until != 0u && (int32_t)(now_ms() - s_hs_linger_until) < 0;
}

size_t matter_client_on_unsecured(const uint8_t *payload, size_t payload_len,
				  const struct matter_msg_header *mh,
				  const struct matter_proto_header *ph, uint8_t *reply, size_t cap)
{
	size_t out = 0u;
	uint32_t next;
	uint32_t t;

	if (ultrawidelock_mutex_trylock(&s_lock) != 0) {
		/* See the file comment. One step timeout, no state touched. */
		return 0u;
	}
	t = now_ms();

	/*
	 * The administrator this handshake belongs to may have been removed
	 * since the Sigma1 left. This path runs from the receive callback, which
	 * is AHEAD of the poll that would otherwise notice, so without this a
	 * Sigma2 is verified against a fabric slot that has already been zeroed
	 * -- s_fabric still points at it, and it still describes nobody.
	 */
	if (s_fabric != NULL && !fabric_still_held()) {
		s_fabric = NULL;
		drop_session();
		ultrawidelock_mutex_unlock(&s_lock);
		return 0u;
	}

	/*
	 * Every answer the peer sends acknowledges what it is answering, so this
	 * is where a retransmit timer is nearly always cancelled -- a standalone
	 * ack is the rare case, not the normal one.
	 */
	if ((ph->exchange_flags & MATTER_EX_FLAG_A) != 0u) {
		(void)matter_mrp_on_ack(&s_mrp, ph->ack_counter);
	}

	if (ph->opcode == MATTER_OP_CASE_SIGMA2) {
		matter_client_sm_sigma2(&s_sm, t);
		out = handle_sigma2(payload, payload_len, mh, reply, cap);
		if (out > 0u) {
			/* The Sigma3 is handed back for the transport to send,
			 * so this is the only place that can time it. */
			arm_retransmit(reply, out, s_counter, t);
			matter_client_sm_sent(&s_sm, t);
		} else {
			drop_session();
			matter_client_sm_failed(&s_sm, t);
		}
	} else if (ph->opcode == MATTER_SC_OP_STATUS_REPORT) {
		/*
		 * The peer's verdict on the Sigma3, and the last unsecured
		 * message of the handshake. matter_sc_status_report()'s own
		 * format: general code first, little-endian, and 0 is success.
		 */
		bool ok;

		if (!s_handshake) {
			/*
			 * A retransmission of the report that already ended this
			 * handshake: the peer never got the acknowledgement.
			 * Acknowledge it again and change NOTHING -- the session
			 * is up, the interaction may already be in flight, and
			 * running establishment twice would restart it.
			 */
			out = frame_headers(MATTER_SC_OP_ACK, false, true, mh->message_counter,
					    reply, cap);
			ultrawidelock_mutex_unlock(&s_lock);
			return out;
		}

		ok = s_session && payload_len >= 2u && payload[0] == 0u && payload[1] == 0u;

		if (ok) {
			LOG_DBG("CASE ESTABLISHED as initiator: session 0x%04x",
				(unsigned int)s_local_session);
			/*
			 * Say so when the session is up and nobody is waiting for
			 * it any more. The handshake is deliberately allowed to
			 * outlive its want -- the warm session is what makes the
			 * next walk-up instant -- but the visible result is an
			 * ESTABLISHED line with no UnlockDoor after it, which
			 * reads exactly like the invoke having silently failed.
			 * This is the difference between "too slow" and "broken",
			 * and it is not recoverable from the log without it.
			 */
			if (!matter_client_sm_wants(&s_sm, t)) {
				LOG_DBG("walk-up expired before UnlockDoor");
			}
			matter_client_sm_established(&s_sm);
			/*
			 * Acknowledged before the handshake exchange is let go.
			 * The peer set R on this and has nothing else coming to
			 * carry the ack, so without it the last message of the
			 * handshake is retransmitted for the peer's whole MRP
			 * schedule against a node that has stopped listening on
			 * that exchange.
			 */
			out = frame_headers(MATTER_SC_OP_ACK, false, true, mh->message_counter,
					    reply, cap);
			s_handshake = false;
			s_hs_linger_until = t + CLIENT_HS_LINGER_MS;
			if (s_hs_linger_until == 0u) {
				/* 0 is the "nothing to answer for" value, so the
				 * one tick in 2^32 that lands on it borrows the
				 * next. */
				s_hs_linger_until = 1u;
			}
		} else {
			LOG_DBG("handshake refused");
			drop_session();
			matter_client_sm_failed(&s_sm, t);
		}
	}

	next = next_wake_ms(now_ms());
	ultrawidelock_mutex_unlock(&s_lock);
	poll_at(next);
	return out;
}

size_t matter_client_on_secure(uint8_t *msg, size_t len, uint8_t *reply, size_t cap)
{
	struct matter_exchange_in in;
	size_t out = 0u;
	uint32_t next;
	uint32_t t;
	int rc;

	if (ultrawidelock_mutex_trylock(&s_lock) != 0) {
		return 0u;
	}
	t = now_ms();

	rc = matter_exchange_recv_in_place(&s_x, msg, len, &in);
	if (rc == MATTER_E_DUP) {
		/*
		 * The peer is retransmitting because it believes its last
		 * acknowledgement was lost, and here it very likely was: the
		 * reply slot for its first copy carried the InvokeRequest, and
		 * one datagram cannot be both. Acknowledge the retransmission
		 * and do NOT act on the payload a second time.
		 */
		size_t ack_len = 0u;

		if (matter_exchange_ack_initiator(&s_x, s_exchange_id, reply, cap, &ack_len) ==
		    MATTER_OK) {
			out = ack_len;
		}
		ultrawidelock_mutex_unlock(&s_lock);
		return out;
	}
	if (rc != MATTER_OK) {
		LOG_DBG("client session message refused (%d)", rc);
		ultrawidelock_mutex_unlock(&s_lock);
		return 0u;
	}

	if (in.protocol_id == MATTER_PROTOCOL_INTERACTION_MODEL &&
	    in.opcode == MATTER_IM_OP_STATUS_RESPONSE && s_invoke_step == (uint8_t)INVOKE_TIMED) {
		uint8_t status = MATTER_IM_STATUS_FAILURE;

		/*
		 * The peer's answer to the TimedRequest, and it is checked
		 * rather than assumed: a peer that refused the window answers
		 * the invoke with NEEDS_TIMED_INTERACTION, which reads in a log
		 * exactly like the firmware having forgotten to send one.
		 */
		if (matter_im_status_response_decode(in.payload, in.payload_len, &status) !=
			    MATTER_OK ||
		    status != MATTER_IM_STATUS_SUCCESS) {
			LOG_DBG("timed window refused (0x%02x)", status);
			s_invoke_step = (uint8_t)INVOKE_IDLE;
			matter_client_sm_invoked(&s_sm, false);
		} else {
			/*
			 * The invoke has to arrive inside the window, so it goes
			 * out as the REPLY to this datagram rather than through
			 * a work item that would have to be scheduled first.
			 */
			out = send_invoke(reply, cap);
			if (out == 0u) {
				drop_session();
				matter_client_sm_failed(&s_sm, t);
			}
		}
	} else if (in.protocol_id == MATTER_PROTOCOL_INTERACTION_MODEL &&
		   in.opcode == MATTER_IM_OP_INVOKE_COMMAND_RESPONSE) {
		struct matter_im_client_response resp;
		bool ok;

		rc = matter_im_client_response_decode(in.payload, in.payload_len, &resp);
		ok = rc == MATTER_OK && resp.status == MATTER_IM_STATUS_SUCCESS;
		if (ok) {
			LOG_DBG("the bound lock UNLOCKED");
		} else {
			LOG_DBG("UnlockDoor refused (0x%02x, decode %d)",
				rc == MATTER_OK ? resp.status : 0u, rc);
		}
		s_invoke_step = (uint8_t)INVOKE_IDLE;
		matter_client_sm_invoked(&s_sm, ok);
		/* The peer asked to be acknowledged and this is the end of the
		 * interaction, so there is nothing else to carry the ack. */
		if (in.ack_requested) {
			size_t ack_len = 0u;

			if (matter_exchange_ack_initiator(&s_x, s_exchange_id, reply, cap,
							  &ack_len) == MATTER_OK) {
				out = ack_len;
			}
		}
	}

	next = next_wake_ms(now_ms());
	ultrawidelock_mutex_unlock(&s_lock);
	poll_at(next);
	return out;
}
