/* SPDX-License-Identifier: ISC */

// credential reader engine: drives the Access Protocol (AUTH0/AUTH1/EXCHANGE) handshake over BLE,
// manages reader identity and credential trust provisioning in NVS, and arms UWB ranging once
// a session is authenticated. Maintains a fixed-size table of per-connection sessions tracking
// transaction phase and secure-channel state, and exposes start/attach entry points for both
// standalone and Matter-attached BLE transports, plus provisioning and diagnostic APIs used by
// Matter commissioning and the bench console.
/*
 * ultrawidelock_reader — the credential reader credential-auth transaction (Phase 3.2/3.3) on
 * top of the ultrawidelock_ble L2CAP transport. Drives AUTH0 -> AUTH1 -> EXCHANGE, runs
 * the ECDH + key schedule (ultrawidelock_crypto) to derive the URSK, then hands the URSK
 * to ultrawidelock_ranging, which negotiates the ranging parameters with the peer
 * (M1-M4) and starts the UWB responder. Wire codec = ultrawidelock_apdu; crypto =
 * ultrawidelock_crypto; ranging setup = ultrawidelock_ranging.
 *
 * Heavy diagnostic logging by design: this path can only complete end-to-end
 * once the reader is provisioned and a real credential is present. The reader
 * identity + credential trust store come from the provisioning seam (ultrawidelock_prov,
 * Phase 3.4): NVS if present, else a clearly-marked dev identity so the
 * transaction is drivable at bench before Phase-4 Matter provisioning lands.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ultrawidelock_port.h"
#include "ultrawidelock_osal.h"
#include "ultrawidelock_log.h"

#include "ultrawidelock_ble.h"
#include "ultrawidelock_apdu.h"
#include "ultrawidelock_crypto.h"
#include "ultrawidelock_lab.h"
#include "ultrawidelock_lat.h"
#include "ultrawidelock_prim.h"
#include "ultrawidelock_prov.h"
#include "ultrawidelock_ranging.h"
#include <ultrawidelock/reader.h>
#include "ultrawidelock_rssi_gate.h"
#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP)
#include "ultrawidelock_stepup.h"
#endif

LOG_MODULE_REGISTER(ultrawidelock_reader, CONFIG_ULTRAWIDELOCK_CRED_LOG_LEVEL);

/* PROVISIONAL advertised BLE-UWB protocol version. Real value is the provisioned
 * Matter attribute (Phase 4); 0x0100 is the baseline the arbiter treats specially. */
static const uint16_t k_proto_versions[] = {0x0100u};
#define ULTRAWIDELOCK_VERSION 0x0100u

/* Reader identity + credential trust store, loaded once at start from the
 * provisioning seam (NVS, else the clearly-marked dev identity). */
static struct ultrawidelock_reader_identity s_id;
static struct ultrawidelock_trust_store s_trust;
static bool s_loaded;

enum provisioning_state {
	PROVISIONING_UNAVAILABLE = 0,
	PROVISIONING_EMPTY,
	PROVISIONING_READY,
};
static enum provisioning_state s_provisioning_state;

#ifndef CONFIG_ULTRAWIDELOCK_CRED_DEV_TRUST
#define CONFIG_ULTRAWIDELOCK_CRED_DEV_TRUST 0
#endif

/* Most-recently-presented credential public key (the one the device signature
 * verified against). Captured for the `ultrawidelock-trust` bench command. */
static uint8_t s_last_cred_pub[ULTRAWIDELOCK_CRED_PUB_LEN];
static bool s_have_last_cred;

/* The credential key of the most recent session that passed the trust check, as
 * opposed to s_last_cred_pub which is every key presented. Attribution only: the
 * Matter LockOperation event names the user this key belongs to. */
static uint8_t s_auth_cred_pub[ULTRAWIDELOCK_CRED_PUB_LEN];
static bool s_have_auth_cred;

#if defined(CONFIG_ULTRAWIDELOCK_CRED_ACCESS_LISTENER)
/* Optional observer of the access verdict (see ultrawidelock_reader.h). NULL unless a port
 * registers one, and the notify below is then a single predicted branch on the
 * transaction path. Written once at startup, read from the BLE-host task. */
static void (*s_access_listener)(bool granted);

// Tell the registered observer, if any, how this transaction's credential check came out.
static void notify_access(bool granted)
{
	void (*cb)(bool) = s_access_listener;

	if (cb != NULL) {
		cb(granted);
	}
}
#else
/* Unselected, the whole hook compiles away, so an image that does not want it is
 * byte-for-byte what it was. */
#define notify_access(granted) ((void)0)
#endif

/* Reader group key X = the X coordinate of pub(sign_priv). This is salt field 1
 * (reader_group_identifier_key.x) in the §8.3.1.13 key schedule; both sides must
 * agree on it, so it is derived from the provisioned signingKey (its public
 * counterpart = the verificationKey the credential was provisioned with).
 * Recomputed whenever s_id changes. */
static uint8_t s_reader_group_x[ULTRAWIDELOCK_EC_PUBX_LEN];
static bool s_have_group_x;

/* Fallback SELECT-response 0xA5 proprietary-info TLV for a CSA-app, protocol
 * v1.0-only device (Table 10-2): a5 08 [80 02 0000] [5c 02 0100]. Used only when
 * the phone's op-0x05 message carried no 0xA5 TLV (a live device sends its own). */
static const uint8_t k_a5_csa_v1[] = {
	0xa5, 0x08, 0x80, 0x02, 0x00, 0x00, 0x5c, 0x02, 0x01, 0x00,
};

/* Recover the reader group key X from the provisioned signingKey. Call after any
 * mutation of s_id. Leaves s_have_group_x=false (and logs) on failure. */
static void compute_reader_group_x(void)
{
	uint8_t pub[ULTRAWIDELOCK_P256_POINT];

	if (ultrawidelock_ec_p256_pub_from_priv(s_id.sign_priv, pub) == 0) {
		memcpy(s_reader_group_x, pub + 1, ULTRAWIDELOCK_EC_PUBX_LEN);
		s_have_group_x = true;
	} else {
		s_have_group_x = false;
		LOG_ERR("reader group key derivation failed; salt field 1 unavailable");
	}
}

/* Serializes the persistent provisioning backend. This lock is always acquired
 * before s_prov_lock: settings/NVS writes may run both from the low-priority
 * housekeeping thread and from Matter/admin tasks, and the Zephyr backend uses
 * one static serialization buffer. Holding it from candidate snapshot through
 * store and commit also prevents an older housekeeping snapshot overwriting a
 * newer admin mutation. */
static ultrawidelock_mutex_t s_store_lock;

#if defined(ULTRAWIDELOCK_PORT_HOST)
static unsigned int s_store_lock_depth;

bool ultrawidelock_reader_store_locked_for_test(void)
{
	return s_store_lock_depth != 0u;
}
#endif

static void store_lock(void)
{
	ultrawidelock_mutex_lock(&s_store_lock);
#if defined(ULTRAWIDELOCK_PORT_HOST)
	s_store_lock_depth++;
#endif
}

static void store_unlock(void)
{
#if defined(ULTRAWIDELOCK_PORT_HOST)
	s_store_lock_depth--;
#endif
	ultrawidelock_mutex_unlock(&s_store_lock);
}

/* Guards s_trust + s_last_cred_pub/s_have_last_cred + s_auth_cred_pub/
 * s_have_auth_cred, which the BLE-host task (on_auth1_response), the REPL task
 * (the ultrawidelock-prov/ultrawidelock-trust commands) and the reader task (the attribution
 * lookup) all touch. s_id/s_loaded are set once at boot before the REPL starts,
 * so they need no lock. Created in load_provisioning() (single-threaded boot). */
static ultrawidelock_mutex_t s_prov_lock;
static bool s_prov_lock_ready;

/* Monotonic epoch for successful trusted authentications. Presence snapshots it
 * only after every pre-challenge link has disconnected, then requires it to
 * advance before accepting any range. Guarded by s_prov_lock with the key. */
static uint32_t s_auth_generation;
/* RAM-only fast-path hint. It is deliberately not persisted: trust-store
 * order remains the durable source of truth, and a stale hint cannot grant
 * access. Guarded by s_prov_lock. */
static int8_t s_fast_mru = -1;
#if defined(ULTRAWIDELOCK_PORT_HOST)
static uint8_t s_fast_trial_order[ULTRAWIDELOCK_TRUST_MAX];
static uint8_t s_fast_trial_count;

uint8_t ultrawidelock_reader_fast_trial_order_for_test(uint8_t *out, uint8_t cap)
{
	uint8_t n = s_fast_trial_count < cap ? s_fast_trial_count : cap;

	if (out != NULL && n != 0u) {
		memcpy(out, s_fast_trial_order, n);
	}
	return s_fast_trial_count;
}
#endif

/* Cross-task fresh-proof reset handshake. The console allocates a request,
 * the BLE host task terminates every old session, and only the final disconnect
 * publishes a checkpoint. Guarded by s_prov_lock except session-table scans,
 * which run only on the BLE host task. */
static uint32_t s_presence_request;
static uint32_t s_presence_ready_request;
static uint32_t s_presence_ready_auth_generation;
static bool s_presence_wait_disconnect;

/* Set when a standard phase minted a fresh Kpersistent (s_trust updated in RAM,
 * guarded by s_prov_lock); persisted to NVS on disconnect so the flash write
 * stays off the walk-up critical path. */
static bool s_kp_dirty;

/* A Secured (relock) Reader-Status-Changed that could not be delivered because the
 * peer had already disconnected. The phone is left showing this door unlocked, so
 * the next established session replays it. Host-task only, like every other touch
 * point on the session table.
 *
 * TRUE AT BOOT, deliberately. This flag is the only thing that can correct a
 * stranded Wallet, and it used to live in RAM alone -- so a reboot between the
 * undeliverable Secured and the next session destroyed the correction and left
 * the phone permanently showing this door open. That is not recoverable from the
 * lock side: iOS will not run an approach unlock on a door it believes is already
 * unlocked, so it stops opening credential sessions, so the replay can never fire.
 * MEASURED: a grant whose relock could not be delivered, followed by a firmware
 * flash, and no phone opened a session against this reader again.
 *
 * A reboot always comes up Secured and cannot know what the Wallet believes, so
 * assuming "possibly stale" is both the safe default and free: the replay is
 * Secured-only, armed rather than sent, and any grant inside the hold window
 * cancels it (reader_status_send). A normal walk-up never sees it. */
static bool s_secured_undelivered = true;
/* How long the stale-Wallet Secured waits for a grant to supersede it. Sized off
 * the slowest walk-up on record (bolt+3566 ms with AP-Completed near 1250 ms, so
 * ~2.3 s of headroom needed) rather than the fast path's 1206 ms. Overshooting is
 * nearly free: the phone has already been showing the stale unlocked state for the
 * whole disconnect, so a few more seconds costs nothing, while undershooting puts
 * the flicker straight back. */
#define ULTRAWIDELOCK_SECURED_REPLAY_HOLD_MS 3000

/* Monotonic ms at which that replay may go out, or 0 for "nothing armed". The
 * replay is held rather than sent the moment the session establishes, because the
 * common reason a phone reconnects is that it woke up on the doorstep and is about
 * to be granted again: bench 2026-07-25 measured the grant landing 1206 ms after
 * AP-Completed, so an immediate replay shows the Wallet a lock it must undo one
 * second later. Any send at all cancels the hold (see reader_status_send), so a
 * grant inside the window silently supersedes it -- which is the whole point.
 *
 * 32-bit and volatile, unlike the ms clock it comes from: this is the one piece of
 * reader state the BLE host task writes and the caller's own task reads, and the
 * two run on different cores. A single aligned word cannot tear the way an int64
 * read can, so the worst a race costs is which side of one 200 ms tick the release
 * lands on. Wraps every 49 days, which the subtraction below is written to survive;
 * the arm skips a deadline of exactly 0 so the sentinel stays unambiguous. */
static volatile uint32_t s_secured_replay_at;
/* The state the peer was last told (false = Secured, which is where the bolt boots).
 * Suppresses duplicate Reader-Status-Changed sends and, with them, the spurious
 * replays a duplicate would otherwise queue up. */
static bool s_last_unsecured;
/* Set alongside an armed replay: this peer reconnected while still owed a Secured,
 * so s_last_unsecured no longer describes what its Wallet shows -- it may well have
 * dropped its own view when the link went. Forces the first send of the new session
 * past the duplicate filter, whichever it turns out to be. Without it, deferring the
 * replay silently swallows the grant too (the peer was last told Unsecured), and the
 * walk-up loses its unlock animation entirely. */
static bool s_peer_state_unknown;

#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP)
/* One-shot step-up arm (bench `ultrawidelock-stepup arm`): forces the next transaction
 * into the expedited-standard phase and requests an Access Document after
 * EXCHANGE. Set by the REPL task, consumed by the BLE-host task in start_auth.
 * Guarded by s_prov_lock. The verdict lives in the worker (ultrawidelock-stepup status). */
#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP_BENCH)
static bool s_stepup_armed;
#endif

/* One DeviceResponse collection buffer for the whole reader rather than one per
 * session: step-up runs in at most one transaction at a time in practice (the
 * collision is a second phone walking up while a Watch is being learned, and
 * that transaction is simply told no), and the nRF52833 cannot spare a second
 * copy. Owned by a connection handle while it collects; STEPUP_SD_FREE when
 * idle. The bench worker's job copy (2 KiB) is sized to take it whole. */
#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP_SD_MAX)
#define STEPUP_SD_MAX  ((unsigned)CONFIG_ULTRAWIDELOCK_CRED_STEPUP_SD_MAX)
#else
#define STEPUP_SD_MAX  1536u
#endif
#define STEPUP_SD_FREE 0xFFFFu
static uint8_t s_stepup_sd[STEPUP_SD_MAX];
static size_t s_stepup_sd_len;
static uint16_t s_stepup_sd_owner = STEPUP_SD_FREE;

/* The learn path verifies on the BLE-host task, inside the transaction: the
 * phone is waiting for AP-Completed and nothing else can proceed, so one parsed
 * document at a time is the whole demand. Static rather than on that task's
 * stack, which the Zephyr port sizes at 4 KiB. The DeviceResponse it points
 * into is decrypted in place, over the SessionData in s_stepup_sd: a second
 * 1.5 KiB buffer for the plaintext is what the anchorlink and release client
 * images could not spare. */
static struct ultrawidelock_stepup_doc s_learn_doc;

/* Give the collection buffer back if conn holds it; a no-op otherwise. */
static void stepup_sd_release(uint16_t conn)
{
	if (s_stepup_sd_owner == conn) {
		s_stepup_sd_owner = STEPUP_SD_FREE;
		s_stepup_sd_len = 0;
	}
}

/* Whether this step-up decides the transaction (the learn path) or only logs a
 * verdict (the bench one-shot). Without the bench option the learn path is the
 * only way a step-up starts, and the compiler folds the bench branches away --
 * which is the point on a part with no console and no flash to spare. */
static bool stepup_is_learn(bool learn_pending)
{
#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP_BENCH)
	return learn_pending;
#else
	(void)learn_pending;
	return true;
#endif
}
#endif

/* Told each time an endpoint key is learned from an Access Document (see
 * ultrawidelock/reader.h). Written once at startup, read from the BLE-host task.
 * Registered by the apps whether or not the step-up phase is built, so it lives
 * outside that option; without it nothing is ever learned and it stays unread. */
static void (*s_learned_listener)(uint8_t cred_type, uint16_t cred_index, uint16_t user_index,
				  const uint8_t cred_pub[ULTRAWIDELOCK_CRED_PUB_LEN]);

/* Where the credential-auth transaction has got to on this connection. Advances
 * strictly forward from PH_IDLE as each command's response arrives; PH_FAILED is
 * terminal until the peer reconnects. */
enum txn_phase {
	PH_IDLE = 0,      /* connected; awaiting the peer's first message */
	PH_SENT_AUTH0,    /* AUTH0 sent; awaiting AUTH0Response */
	PH_SENT_AUTH1,    /* AUTH1 sent; awaiting AUTH1Response */
	PH_SENT_EXCHANGE, /* EXCHANGE sent; awaiting its response, then AP-Completed */
#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP)
	PH_SENT_STEPUP, /* ENVELOPE sent; collecting the DeviceResponse before AP-Completed */
#endif
#if defined(CONFIG_ULTRAWIDELOCK_RSSI_GATE)
	PH_GATE_HOLD, /* auth done; AP-Completed deferred until the RSSI power gate opens */
#endif
	PH_ESTABLISHED, /* AP-Completed sent; ranging setup (M1-M4) driven by ultrawidelock_ranging */
	PH_FAILED,
};

// Returns a human-readable name for a transaction phase enum value, or "?" for an unrecognized
// value.
static const char *phase_str(enum txn_phase p)
{
	switch (p) {
	case PH_IDLE:
		return "IDLE";
	case PH_SENT_AUTH0:
		return "SENT_AUTH0";
	case PH_SENT_AUTH1:
		return "SENT_AUTH1";
	case PH_SENT_EXCHANGE:
		return "SENT_EXCHANGE";
#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP)
	case PH_SENT_STEPUP:
		return "SENT_STEPUP";
#endif
#if defined(CONFIG_ULTRAWIDELOCK_RSSI_GATE)
	case PH_GATE_HOLD:
		return "GATE_HOLD";
#endif
	case PH_ESTABLISHED:
		return "ESTABLISHED";
	case PH_FAILED:
		return "FAILED";
	default:
		return "?";
	}
}

#define ULTRAWIDELOCK_MAX_SESSIONS 2

/* One credential-auth transaction, keyed by BLE connection handle. Holds the
 * reader's ephemeral keypair and the transcript inputs (txid, device pubkey, Z)
 * that derive the two secure channels and the URSK, so everything a transaction
 * needs between AUTH0 and ranging setup lives here. Cleared on disconnect;
 * ULTRAWIDELOCK_MAX_SESSIONS of them are statically allocated. */
static struct ultrawidelock_session {
	bool active;
	bool disconnect_requested;
	uint16_t conn_handle;
	enum txn_phase phase;
	bool phase_deadline_armed;
	uint32_t phase_deadline_ms;
	bool overall_deadline_armed;
	uint32_t overall_deadline_ms;
	uint32_t msgs_rx;

	uint8_t reader_eph_priv[ULTRAWIDELOCK_P256_SCALAR];
	uint8_t reader_eph_pub[ULTRAWIDELOCK_P256_POINT];
	uint8_t txid[ULTRAWIDELOCK_TXID_LEN];
	/* AUTH0 command_parameters as transmitted: 0x01 = fast requested. Feeds
	 * every salt build as the flag field (§8.3.1.12/.13), also on fallback. */
	uint8_t exp_phase_sent;
	uint8_t device_eph_pub[ULTRAWIDELOCK_P256_POINT];
	uint8_t z[32];
	struct ultrawidelock_secchan sc;     /* AP secure channel (ExpeditedSK) */
	struct ultrawidelock_secchan sc_ble; /* ranging channel (BleSKReader/Device), §11.8 */
	uint8_t ursk[ULTRAWIDELOCK_URSK_LEN];

	/* The phone's 0xA5 proprietary-info TLV (tag+len+value), captured from its
	 * op-0x05 Initiate-Access-Protocol message; the trailing field of the
	 * session-key salt. a5_len==0 means none seen (use the CSA v1.0 default). */
	uint8_t a5_tlv[64];
	size_t a5_len;

#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP)
	/* Step-up (Access Document) state for an armed transaction. The SessionData
	 * channel is keyed by StepUpSK (block[64..95], §8.4.3); the DeviceResponse is
	 * collected across ENVELOPE / GET RESPONSE before being handed to the worker. */
	bool stepup_active;
	struct ultrawidelock_secchan stepup_sc;
	uint8_t stepup_skr[ULTRAWIDELOCK_SESSION_KEY_LEN];
	uint8_t stepup_skd[ULTRAWIDELOCK_SESSION_KEY_LEN];
	/* The collected DeviceResponse lives in s_stepup_sd, one buffer for the
	 * whole reader, owned by conn_handle while this session collects. */
	/* The learn path: AUTH1 presented a key no anchor matches while an issuer
	 * key is held, so the document is being fetched to decide the transaction
	 * rather than to be logged. learn_pub is the key it must vouch for. */
	bool learn_pending;
	uint8_t learn_pub[ULTRAWIDELOCK_CRED_PUB_LEN];
#endif

#if defined(CONFIG_ULTRAWIDELOCK_RSSI_GATE)
	/* BLE-RSSI ranging power gate: fed by the transport's poll, holds
	 * AP-Completed (PH_GATE_HOLD) until the phone is near enough that the UWB
	 * radio's RX power is worth spending. Zeroed slot == closed + unprimed. */
	struct ultrawidelock_rssi_gate rgate;
#endif
} s_sessions[ULTRAWIDELOCK_MAX_SESSIONS];

/* The BLE host exclusively owns s_sessions. Other tasks only need the derived
 * established/not-established signal, so publish that as an atomic snapshot
 * instead of making them race a table scan against phase changes/teardown. */
static _Atomic unsigned int s_established_sessions;

/* Link-overridable monotonic clock seam. Target builds use the port clock;
 * host tests provide exact boundary and uint32 wrap values. */
__attribute__((weak)) int64_t ultrawidelock_reader_monotonic_ms(void)
{
	return ultrawidelock_uptime_ms();
}

static bool phase_awaits_peer(enum txn_phase phase)
{
	switch (phase) {
	case PH_IDLE:
	case PH_SENT_AUTH0:
	case PH_SENT_AUTH1:
	case PH_SENT_EXCHANGE:
#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP)
	case PH_SENT_STEPUP:
#endif
#if defined(CONFIG_ULTRAWIDELOCK_RSSI_GATE)
	case PH_GATE_HOLD:
#endif
		return true;
	default:
		return false;
	}
}

static void session_enter_phase(struct ultrawidelock_session *s, enum txn_phase phase)
{
	if (s->phase != phase) {
		if (s->phase == PH_ESTABLISHED) {
			(void)atomic_fetch_sub_explicit(&s_established_sessions, 1u,
						memory_order_relaxed);
		} else if (phase == PH_ESTABLISHED) {
			(void)atomic_fetch_add_explicit(&s_established_sessions, 1u,
						memory_order_relaxed);
		}
	}
	s->phase = phase;
	s->phase_deadline_armed = phase_awaits_peer(phase);
	if (s->phase_deadline_armed) {
		s->phase_deadline_ms = (uint32_t)ultrawidelock_reader_monotonic_ms() +
				       ULTRAWIDELOCK_READER_PHASE_TIMEOUT_MS;
	}
}

/* A nonzero send result is ambiguous: the peer may already have accepted the
 * frame while our local completion failed. Never roll a secure counter back and
 * never continue the same session. */
static void session_terminate(struct ultrawidelock_session *s, const char *reason)
{
	(void)reason; /* host log stub compiles the formatted argument away */
	if (s == NULL || !s->active || s->disconnect_requested) {
		return;
	}
	uint16_t conn = s->conn_handle;

	session_enter_phase(s, PH_FAILED);
	s->phase_deadline_armed = false;
	s->overall_deadline_armed = false;
	s->disconnect_requested = true;
	LOG_WRN("[conn %u] terminating credential session: %s", conn, reason);
	(void)ultrawidelock_ble_disconnect(conn);
}

/* Defined with the other Reader-Status-Changed plumbing; declared here so the
 * stale-Wallet resync in complete_ap_and_range can reach it. */
static void reader_status_send(struct ultrawidelock_session *s, bool unsecured);

// Finds the active session matching the given BLE connection handle.
// Returns a pointer to the matching session, or NULL if no active session has that conn_handle.
static struct ultrawidelock_session *session_find(uint16_t conn_handle)
{
	for (int i = 0; i < ULTRAWIDELOCK_MAX_SESSIONS; i++) {
		if (s_sessions[i].active && s_sessions[i].conn_handle == conn_handle) {
			return &s_sessions[i];
		}
	}
	return NULL;
}

// Allocates and returns the first inactive slot in the fixed-size session table for a new
// connection, initializing it to phase PH_IDLE. Returns NULL if all ULTRAWIDELOCK_MAX_SESSIONS
// slots are already active.
static struct ultrawidelock_session *session_alloc(uint16_t conn_handle)
{
	for (int i = 0; i < ULTRAWIDELOCK_MAX_SESSIONS; i++) {
		if (!s_sessions[i].active) {
			memset(&s_sessions[i], 0, sizeof(s_sessions[i]));
			s_sessions[i].active = true;
			s_sessions[i].conn_handle = conn_handle;
			s_sessions[i].overall_deadline_armed = true;
			s_sessions[i].overall_deadline_ms =
				(uint32_t)ultrawidelock_reader_monotonic_ms() +
				ULTRAWIDELOCK_READER_SESSION_TIMEOUT_MS;
			session_enter_phase(&s_sessions[i], PH_IDLE);
			return &s_sessions[i];
		}
	}
	return NULL;
}

// Loads the reader's provisioning state (identity, trust anchors) from NVS into the module-level
// s_id/s_trust, lazily creating the provisioning mutex on first call. Idempotent: does nothing on
// subsequent calls once s_loaded is set. Logs whether a dev-default or real identity was loaded and
// its source (NVS vs. dev default), then recomputes the reader group X coordinate.
static int load_provisioning(void)
{
	if (!s_prov_lock_ready) {
		ultrawidelock_mutex_init(&s_store_lock);
		ultrawidelock_mutex_init(&s_prov_lock);
		s_prov_lock_ready = true;
	}
	if (s_loaded && s_provisioning_state != PROVISIONING_UNAVAILABLE) {
		return s_provisioning_state == PROVISIONING_READY ? 0 :
		       (s_provisioning_state == PROVISIONING_EMPTY ? ULTRAWIDELOCK_PROV_LOAD_EMPTY :
							      -EIO);
	}
	int rc = ultrawidelock_prov_load(&s_id, &s_trust);

	if (rc == 0) {
		/* A persisted factory-clear/dev blob is still an empty development
		 * reader. It does not become production-safe merely because it came
		 * from NVS rather than the absence path. */
		s_provisioning_state = (s_id.is_dev && s_trust.count == 0u) ?
					       PROVISIONING_EMPTY : PROVISIONING_READY;
	} else if (rc == ULTRAWIDELOCK_PROV_LOAD_EMPTY) {
		s_provisioning_state = PROVISIONING_EMPTY;
	} else {
		s_provisioning_state = PROVISIONING_UNAVAILABLE;
	}

	if (s_id.is_dev) {
		LOG_WRN("using DEV reader identity (Phase 4 supplies the real "
			"one); %u trust anchor(s)",
			s_trust.count);
	} else {
		LOG_INF("provisioned reader identity loaded; %u trust anchor(s)", s_trust.count);
	}
	LOG_INF("prov source: %s", rc == 0 ? "NVS" :
		(rc == ULTRAWIDELOCK_PROV_LOAD_EMPTY ? "empty" : "UNAVAILABLE"));
	compute_reader_group_x();
	s_loaded = true;
	return rc;
}

/* Frame + send an Access-Protocol command: wrap the command TLV in an ISO7816
 * APDU (ins selects AUTH0/AUTH1/EXCHANGE), then a BLE Access frame
 * (type=ACCESS, opcode=AP_OP_COMMAND). The command byte lives in the APDU INS,
 * NOT the BLE opcode — the phone rejects a raw TLV under opcode=INS. */
static int send_ap_command(uint16_t conn, uint8_t ins, const uint8_t *tlv, size_t len)
{
	/* One buffer [type][op][len_be16][APDU]. This runs on the small nimble_host
	 * callback stack, so build the APDU past a 4-byte header and fill the header in
	 * place rather than staging a second frame buffer. AUTH0/AUTH1/EXCHANGE APDUs
	 * are all well under 256 B. */
	uint8_t frame[ULTRAWIDELOCK_ENVELOPE_HDR + 256];
	size_t alen;

	if (ultrawidelock_apdu_wrap(ins, tlv, len, frame + ULTRAWIDELOCK_ENVELOPE_HDR,
			    sizeof(frame) - ULTRAWIDELOCK_ENVELOPE_HDR, &alen) != 0) {
		LOG_ERR("[conn %u] APDU wrap failed (ins 0x%02x len %u)", conn, ins, (unsigned)len);
		return -1;
	}
	frame[0] = ULTRAWIDELOCK_PROTO_ACCESS;
	frame[1] = ULTRAWIDELOCK_AP_OP_COMMAND;
	frame[2] = (uint8_t)(alen >> 8);
	frame[3] = (uint8_t)(alen & 0xffu);

	int rc = ultrawidelock_ble_send(conn, frame, ULTRAWIDELOCK_ENVELOPE_HDR + alen);

	LOG_INF("[conn %u] TX ins 0x%02x, %u APDU bytes (send rc=%d)", conn, ins, (unsigned)alen,
		rc);
	return rc;
}

#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP)
/* Frame + send a fully-formed ISO7816 APDU (ENVELOPE / GET RESPONSE already carry
 * their own CLA/INS, so they must NOT go through ultrawidelock_apdu_wrap). Same BLE Access
 * frame as send_ap_command: [type=ACCESS][op=COMMAND][len_be16][apdu]. */
static int send_ap_raw(uint16_t conn, const uint8_t *apdu, size_t len)
{
	uint8_t frame[ULTRAWIDELOCK_ENVELOPE_HDR + 320];

	if (len > sizeof(frame) - ULTRAWIDELOCK_ENVELOPE_HDR) {
		return -1;
	}
	frame[0] = ULTRAWIDELOCK_PROTO_ACCESS;
	frame[1] = ULTRAWIDELOCK_AP_OP_COMMAND;
	frame[2] = (uint8_t)(len >> 8);
	frame[3] = (uint8_t)(len & 0xffu);
	memcpy(frame + ULTRAWIDELOCK_ENVELOPE_HDR, apdu, len);
	return ultrawidelock_ble_send(conn, frame, ULTRAWIDELOCK_ENVELOPE_HDR + len);
}
#endif

/* Spare ephemeral keypair + txid, generated off the walk-up's critical path.
 * They depend on nothing from the peer, yet the software P-256 keygen used to
 * run inside the first-message callback; consuming a precomputed pair there
 * removes about a quarter of the per-session scalar mults. Refilled at reader
 * start and by low-priority housekeeping after disconnect. The provisioning
 * mutex protects producer/consumer handoff across that worker and BLE host. */
struct spare_ephemeral {
	bool valid;
	uint8_t priv[ULTRAWIDELOCK_P256_SCALAR];
	uint8_t pub[ULTRAWIDELOCK_P256_POINT];
	uint8_t txid[ULTRAWIDELOCK_TXID_LEN];
};
static struct spare_ephemeral s_spare_eph;

/**
 * Generate and cache a fresh ephemeral P-256 keypair and random transaction ID in the global spare
 * (for immediate reuse on the next connection). Sets spare_eph.valid to 0 if either generation
 * fails.
 */
static bool spare_eph_refill(void)
{
	struct spare_ephemeral next = {0};

	ultrawidelock_mutex_lock(&s_prov_lock);
	if (s_spare_eph.valid) {
		ultrawidelock_mutex_unlock(&s_prov_lock);
		return true;
	}
	ultrawidelock_mutex_unlock(&s_prov_lock);
	next.valid = ultrawidelock_ec_p256_keygen(next.priv, next.pub) == 0 &&
		     ultrawidelock_random(next.txid, sizeof(next.txid)) == 0;
	ultrawidelock_mutex_lock(&s_prov_lock);
	if (!s_spare_eph.valid && next.valid) {
		s_spare_eph = next;
	}
	bool valid = s_spare_eph.valid;
	ultrawidelock_mutex_unlock(&s_prov_lock);
	memset(&next, 0, sizeof(next));
	return valid;
}

/* Kick the reader-driven access protocol: ephemeral keys + txid -> AUTH0. */
static void start_auth(struct ultrawidelock_session *s)
{
	if (s_provisioning_state != PROVISIONING_READY &&
	    !(CONFIG_ULTRAWIDELOCK_CRED_DEV_TRUST &&
	      s_provisioning_state == PROVISIONING_EMPTY)) {
		LOG_ERR("[conn %u] credential authentication unavailable: provisioning is not usable",
			s->conn_handle);
		session_terminate(s, "provisioning unavailable");
		return;
	}

	ultrawidelock_mutex_lock(&s_prov_lock);
	if (s_spare_eph.valid) {
		memcpy(s->reader_eph_priv, s_spare_eph.priv, sizeof(s->reader_eph_priv));
		memcpy(s->reader_eph_pub, s_spare_eph.pub, sizeof(s->reader_eph_pub));
		memcpy(s->txid, s_spare_eph.txid, sizeof(s->txid));
		s_spare_eph.valid = false;
		memset(s_spare_eph.priv, 0, sizeof(s_spare_eph.priv));
		memset(s_spare_eph.txid, 0, sizeof(s_spare_eph.txid));
		ultrawidelock_mutex_unlock(&s_prov_lock);
	} else {
		ultrawidelock_mutex_unlock(&s_prov_lock);
		if (ultrawidelock_ec_p256_keygen(s->reader_eph_priv, s->reader_eph_pub) != 0 ||
		   ultrawidelock_random(s->txid, sizeof(s->txid)) != 0) {
			LOG_ERR("[conn %u] ephemeral keygen/txid failed", s->conn_handle);
			session_terminate(s, "ephemeral generation failed");
			return;
		}
	}

	uint8_t apdu[160];
	size_t n;

	/* ExpeditedPhaseType: request the fast phase (bit 0, §8.1.1.2) when any
	 * trusted credential holds a Kpersistent from an earlier standard phase; a
	 * phone that kept the matching key answers with a cryptogram (tag 0x9D),
	 * anything else continues into the standard phase. The byte lives in the
	 * session because it feeds every salt as the flag field, which per
	 * §8.3.1.12/.13 is command_parameters AS TRANSMITTED — also on fallback.
	 * UserAuthenticationPolicy stays 0x01 (reference AUTH0Command::Serialize). */
	ultrawidelock_mutex_lock(&s_prov_lock);
	s->exp_phase_sent = (s_trust.kp_valid != 0u) ? 0x01u : 0x00u;
#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP_BENCH)
	if (s_stepup_armed) {
		s_stepup_armed = false; /* one-shot: consumed by this transaction */
		s->stepup_active = true;
		s->exp_phase_sent = 0x00u; /* step-up is standard-phase only (§8.1.2) */
		LOG_INF("[conn %u] step-up armed: forcing the standard phase", s->conn_handle);
	}
#endif
	ultrawidelock_mutex_unlock(&s_prov_lock);
	if (ultrawidelock_apdu_build_auth0(s->exp_phase_sent, 0x01u, ULTRAWIDELOCK_VERSION,
					   s->reader_eph_pub, s->txid, s_id.reader_id, apdu,
					   sizeof(apdu), &n) != 0) {
		LOG_ERR("[conn %u] AUTH0 build failed", s->conn_handle);
		session_terminate(s, "AUTH0 build failed");
		return;
	}
	if (send_ap_command(s->conn_handle, ULTRAWIDELOCK_INS_AUTH0, apdu, n) != 0) {
		session_terminate(s, "AUTH0 transport result ambiguous");
		return;
	}
	ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_AUTH0_TX);
	session_enter_phase(s, PH_SENT_AUTH0);
}

/* Derive + init the BleSK ranging channel (§11.8.1) off a 160-byte key block;
 * BleSK sits at offset 96 in both the standard and the fast block. Salt =
 * reader_supported_versions || user_device_selected_version — we advertise and
 * select v1.0 only, so salt = 01 00 01 00. Its own counters (fresh from 1) live
 * in s->sc_ble and carry across AP-Completed + M1..M4. Returns 0 on success. */
static int init_ble_channel(struct ultrawidelock_session *s,
			    const uint8_t block[ULTRAWIDELOCK_KEY_BLOCK_LEN])
{
	uint8_t ble_r[ULTRAWIDELOCK_SESSION_KEY_LEN], ble_d[ULTRAWIDELOCK_SESSION_KEY_LEN];
	uint8_t ble_salt[sizeof(k_proto_versions) + 2];
	size_t bsl = 0;

	for (size_t i = 0; i < sizeof(k_proto_versions) / sizeof(k_proto_versions[0]); i++) {
		ble_salt[bsl++] = (uint8_t)(k_proto_versions[i] >> 8);
		ble_salt[bsl++] = (uint8_t)(k_proto_versions[i] & 0xffu);
	}
	ble_salt[bsl++] = (uint8_t)(ULTRAWIDELOCK_VERSION >> 8); /* selected = only version */
	ble_salt[bsl++] = (uint8_t)(ULTRAWIDELOCK_VERSION & 0xffu);
	if (ultrawidelock_crypto_derive_ble_keys(block, ble_salt, bsl, ble_r, ble_d) != 0) {
		LOG_ERR("[conn %u] BleSK derivation failed", s->conn_handle);
		return -1;
	}
	ultrawidelock_secchan_init(&s->sc_ble, ble_r, ble_d);
	return 0;
}

/* Seal + send the EXCHANGE URSK-ready trigger; both auth paths land here once
 * the secure channels + URSK are up. The AP then waits for the EXCHANGE
 * response: §11.1.1 requires Reader-Status-AP-Completed (BleSK-sealed) after
 * EXCHANGE succeeds, otherwise the device stalls and drops (URSK_Unavailable);
 * on_exchange_response drives that + ranging. */
static bool send_exchange(struct ultrawidelock_session *s)
{
	uint8_t ex[16], ct[16], tag[ULTRAWIDELOCK_GCM_TAG_LEN], payload[32];
	size_t exn;

	if (ultrawidelock_apdu_build_exchange(0, 0, 1, ex, sizeof(ex), &exn) != 0 ||
	    ultrawidelock_secchan_seal(&s->sc, NULL, 0, ex, exn, ct, tag) != 0) {
		LOG_ERR("[conn %u] EXCHANGE seal failed", s->conn_handle);
		session_terminate(s, "EXCHANGE seal failed");
		return false;
	}
	memcpy(payload, ct, exn);
	memcpy(payload + exn, tag, ULTRAWIDELOCK_GCM_TAG_LEN);
	if (send_ap_command(s->conn_handle, ULTRAWIDELOCK_INS_EXCHANGE, payload,
			    exn + ULTRAWIDELOCK_GCM_TAG_LEN) != 0) {
		session_terminate(s, "EXCHANGE transport result ambiguous");
		return false;
	}

	session_enter_phase(s, PH_SENT_EXCHANGE);
	/* end of the auth segment on both paths (the fast path has no AUTH1) */
	ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_AUTH1_DONE);
	LOG_INF("[conn %u] URSK derived; EXCHANGE sent, awaiting response", s->conn_handle);
	LOG_HEXDUMP_DBG(s->ursk, ULTRAWIDELOCK_URSK_LEN, "");
	return true;
}

/* Expedited-fast trial (§8.3.1.10-.12): the cryptogram proves the phone holds a
 * Kpersistent agreed in an earlier standard phase with one of our trusted
 * credentials. Trial-derive the fast block under each stored Kpersistent and
 * try the AES-GCM open; a match authenticates the session with no ECDH, no
 * signatures and no AUTH1 round-trip, and identifies the credential for the
 * unlock attribution. Returns 0 when the session was consumed (EXCHANGE sent,
 * or a hard failure); -1 when nothing matched and the caller should continue
 * with the standard phase. */
static int try_fast_auth(struct ultrawidelock_session *s,
			 const struct ultrawidelock_auth0_response *r)
{
	uint8_t salt[ULTRAWIDELOCK_SALT_MAX], block[ULTRAWIDELOCK_KEY_BLOCK_LEN];
	uint8_t plain[ULTRAWIDELOCK_CRYPTOGRAM_LEN];
	uint8_t matched_pub[ULTRAWIDELOCK_CRED_PUB_LEN];
	size_t slen;
	const uint8_t *a5 = s->a5_len ? s->a5_tlv : k_a5_csa_v1;
	size_t a5n = s->a5_len ? s->a5_len : sizeof(k_a5_csa_v1);
	int match = -1;

#if defined(ULTRAWIDELOCK_PORT_HOST)
	s_fast_trial_count = 0;
#endif

	if (!s_have_group_x) {
		return -1;
	}
	ultrawidelock_mutex_lock(&s_prov_lock);
	uint8_t order[ULTRAWIDELOCK_TRUST_MAX];
	uint8_t order_count = 0;
	if (s_fast_mru >= 0 && s_fast_mru < s_trust.count) {
		order[order_count++] = (uint8_t)s_fast_mru;
	}
	for (uint8_t i = 0; i < s_trust.count && i < ULTRAWIDELOCK_TRUST_MAX; i++) {
		if (i != (uint8_t)s_fast_mru) {
			order[order_count++] = i;
		}
	}
	for (uint8_t oi = 0; oi < order_count; oi++) {
		uint8_t i = order[oi];
		if ((s_trust.kp_valid & (1u << i)) == 0u) {
			continue;
		}
#if defined(ULTRAWIDELOCK_PORT_HOST)
		if (s_fast_trial_count < ULTRAWIDELOCK_TRUST_MAX) {
			s_fast_trial_order[s_fast_trial_count++] = i;
		}
#endif
		if (ultrawidelock_salt_build(ULTRAWIDELOCK_SALT_CRYPTOGRAM, s->txid, s_reader_group_x,
				     s->reader_eph_pub + 1, s_id.reader_id, ULTRAWIDELOCK_IFACE_BLE,
				     ULTRAWIDELOCK_VERSION, s->exp_phase_sent, 0x01u,
				     s_trust.cred_pub[i] + 1, a5, a5n, salt, &slen) != 0 ||
		    ultrawidelock_crypto_derive_block(s_trust.kpersistent[i], salt, slen,
					      s->device_eph_pub + 1, block) != 0) {
			continue;
		}
		if (ultrawidelock_crypto_verify_cryptogram(block + ULTRAWIDELOCK_CRYPTOGRAM_SK_OFFSET,
						   r->cryptogram, ULTRAWIDELOCK_CRYPTOGRAM_LEN,
						   plain) == 0) {
			match = i;
			break;
		}
	}
	if (match >= 0) {
		/* the match identifies the credential: record it for the bench
		 * command and the Matter LockOperation attribution */
		memcpy(s_last_cred_pub, s_trust.cred_pub[match], ULTRAWIDELOCK_CRED_PUB_LEN);
		s_have_last_cred = true;
		memcpy(matched_pub, s_trust.cred_pub[match], sizeof(matched_pub));
	}
	ultrawidelock_mutex_unlock(&s_prov_lock);
	if (match < 0) {
		return -1;
	}

	/* Fast block layout: split(.,0) = ExpeditedSKReader/Device (offsets 32/64);
	 * BleSK@96 and URSK@128 sit at the standard offsets (§8.3.1.12). */
	uint8_t enc[ULTRAWIDELOCK_SESSION_KEY_LEN], dec[ULTRAWIDELOCK_SESSION_KEY_LEN];

	ultrawidelock_crypto_split(block, 0, enc, dec, s->ursk);
	ultrawidelock_secchan_init(&s->sc, enc, dec);
	if (init_ble_channel(s, block) != 0) {
		session_terminate(s, "fast-path BLE channel initialization failed");
		return 0;
	}
	LOG_INF("[conn %u] expedited-FAST cryptogram match (cred %d): AUTH1 skipped",
		s->conn_handle, match);
	ultrawidelock_lab_evi("flow.fast", "cred", match);
	/* The cryptogram only opens under a Kpersistent minted for a trusted
	 * credential, so a match is the trust gate for this path. */
	if (send_exchange(s)) {
		ultrawidelock_mutex_lock(&s_prov_lock);
		memcpy(s_auth_cred_pub, matched_pub, ULTRAWIDELOCK_CRED_PUB_LEN);
		s_have_auth_cred = true;
		s_auth_generation++;
		s_fast_mru = (int8_t)ultrawidelock_prov_trust_find(&s_trust, matched_pub);
		ultrawidelock_mutex_unlock(&s_prov_lock);
		notify_access(true);
	}
	return 0;
}

// Handles an inbound AUTH0Response: strips the APDU status word, parses the device's ephemeral
// public key, performs ECDH with the reader's ephemeral private key, derives the KDF intermediate
// z, signs the reader-usage transcript, and sends AUTH1. On any failure (short/malformed APDU,
// parse failure, ECDH failure, signing failure) sets s->phase to PH_FAILED and returns without
// sending. On success sets s->phase to PH_SENT_AUTH1 after sending the AUTH1 command. Logs (does
// not fail on) an unexpected status word other than 0x9000.
static void on_auth0_response(struct ultrawidelock_session *s, const uint8_t *pl, size_t len)
{
	// Holds the fields parsed from an AUTH0Response APDU while it is being processed by the
	// reader's response handler.
	struct ultrawidelock_auth0_response r;
	uint16_t sw;

	ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_AUTH0_RSP);

	/* APDU response = <response TLV> SW1 SW2; drop the status word before parsing. */
	if (ultrawidelock_apdu_strip_sw(pl, &len, &sw) != 0) {
		LOG_ERR("[conn %u] AUTH0Response too short (%u B)", s->conn_handle, (unsigned)len);
		session_terminate(s, "short AUTH0 response");
		return;
	}
	if (sw != 0x9000u) {
		LOG_WRN("[conn %u] AUTH0Response SW=0x%04x (expected 0x9000)", s->conn_handle, sw);
		session_terminate(s, "AUTH0 status rejected");
		return;
	}
	if (ultrawidelock_apdu_parse_auth0_response(pl, len, &r) != 0) {
		LOG_ERR("[conn %u] AUTH0Response parse failed", s->conn_handle);
		session_terminate(s, "malformed AUTH0 response");
		return;
	}
	memcpy(s->device_eph_pub, r.device_eph_pub, ULTRAWIDELOCK_P256_POINT);

	/* Fast-phase trial: only when we asked (command_parameters bit 0) and the
	 * phone answered with a cryptogram. A failed trial is not fatal — §8.2
	 * allows continuing with the standard phase. */
	if (s->exp_phase_sent == 0x01u && r.have_cryptogram) {
		if (try_fast_auth(s, &r) == 0) {
			return;
		}
		LOG_WRN("[conn %u] fast cryptogram matched no stored Kpersistent; "
			"continuing with the standard phase",
			s->conn_handle);
	}

	uint8_t shared[ULTRAWIDELOCK_SHARED_SECRET_LEN];

	if (ultrawidelock_ecdh_p256(s->reader_eph_priv, s->device_eph_pub, shared) != 0) {
		LOG_ERR("[conn %u] ECDH failed", s->conn_handle);
		session_terminate(s, "AUTH0 ECDH failed");
		return;
	}
	ultrawidelock_crypto_derive_z(shared, s->txid, s->z);

	/* Sign the reader-usage transcript (device pubX, reader-eph pubX). */
	uint8_t td[160], sig[ULTRAWIDELOCK_P256_SIG], apdu[128];
	size_t tn, n;

	if (ultrawidelock_apdu_build_authdata(ULTRAWIDELOCK_AUTH_READER, s_id.reader_id,
					      s->device_eph_pub + 1, s->reader_eph_pub + 1, s->txid,
					      td, sizeof(td), &tn) != 0 ||
	    ultrawidelock_ecdsa_p256_sign(s_id.sign_priv, td, tn, sig) != 0) {
		LOG_ERR("[conn %u] reader signature failed", s->conn_handle);
		session_terminate(s, "reader signature failed");
		return;
	}
	if (ultrawidelock_apdu_build_auth1(0x01u, sig, apdu, sizeof(apdu), &n) != 0) {
		session_terminate(s, "AUTH1 build failed");
		return;
	}
	if (send_ap_command(s->conn_handle, ULTRAWIDELOCK_INS_AUTH1, apdu, n) != 0) {
		session_terminate(s, "AUTH1 transport result ambiguous");
		return;
	}
	ultrawidelock_lab_ev("flow.standard");
	session_enter_phase(s, PH_SENT_AUTH1);
}

// Handles an inbound AUTH1Response: derives the AP and BLE-ranging secure channel keys and URSK
// from the ECDH intermediate, decrypts and parses the response, verifies the device's signature,
// checks trust, and sends EXCHANGE. Requires the reader group X coordinate to already be available
// (s_have_group_x); fails otherwise. Derives the session salt and 160-byte key block, splits it
// into the AP channel keys and URSK, and separately derives the BLE ranging-channel keys from the
// block's BleSK segment using a versions-based salt; both secure channels are initialized with
// counters starting at 1. Decrypts the AUTH1Response body via AES-GCM and fails on tag mismatch
// (indicating a key/counter/framing error), oversized ciphertext, or parse failure. Verifies the
// device's signature over the device-usage transcript using the presented device public key if
// available, else the device's ephemeral public key; a bad signature fails the session. Records the
// presented credential key under s_prov_lock and checks it against the trust store: an untrusted
// key fails the session unless the reader identity is the dev default (which accepts and warns). On
// success, seals and sends the EXCHANGE command, sets s->phase to PH_SENT_EXCHANGE, and logs the
// derived URSK; on any failure path sets s->phase to PH_FAILED and returns without sending
// EXCHANGE.
static void on_auth1_response(struct ultrawidelock_session *s, const uint8_t *pl, size_t len)
{
	// Holds the fields parsed from an AUTH1Response APDU while it is being processed by the
	// reader's response handler.
	struct ultrawidelock_auth1_response r;
	uint16_t sw;

	/* APDU response = <response TLV> SW1 SW2; drop the status word before parsing. */
	if (ultrawidelock_apdu_strip_sw(pl, &len, &sw) != 0) {
		LOG_ERR("[conn %u] AUTH1Response too short (%u B)", s->conn_handle, (unsigned)len);
		session_terminate(s, "short AUTH1 response");
		return;
	}
	if (sw != 0x9000u) {
		LOG_WRN("[conn %u] AUTH1Response SW=0x%04x (expected 0x9000)", s->conn_handle, sw);
		session_terminate(s, "AUTH1 status rejected");
		return;
	}
	/* Establish the secure channel BEFORE reading the body: the AUTH1Response is
	 * AES-256-GCM-encrypted under it (Aliro §8.3.1.6/.7). salt_volatile (§8.3.1.13)
	 * = reader_group_key.x || "Volatile****" || reader_id || interface_byte(BLE) ||
	 * 0x5C 0x02 || version || reader_eph.x || txid || flag || phone 0xA5 TLV; info =
	 * the device (Access Credential) ephemeral pub X; ikm = Kdh (s->z). The URSK and
	 * the ExpeditedSKReader/Device channel keys fall out of the same 160-byte block. */
	uint8_t salt[ULTRAWIDELOCK_SALT_MAX], block[ULTRAWIDELOCK_KEY_BLOCK_LEN];
	uint8_t enc[ULTRAWIDELOCK_SESSION_KEY_LEN], dec[ULTRAWIDELOCK_SESSION_KEY_LEN];
	size_t slen;
	const uint8_t *a5 = s->a5_len ? s->a5_tlv : k_a5_csa_v1;
	size_t a5n = s->a5_len ? s->a5_len : sizeof(k_a5_csa_v1);

	if (!s_have_group_x) {
		LOG_ERR("[conn %u] no reader group key; cannot build session salt", s->conn_handle);
		session_terminate(s, "reader group key unavailable");
		return;
	}
	if (ultrawidelock_salt_build(ULTRAWIDELOCK_SALT_SESSION, s->txid, s_reader_group_x,
				     s->reader_eph_pub + 1, s_id.reader_id, ULTRAWIDELOCK_IFACE_BLE,
				     ULTRAWIDELOCK_VERSION, s->exp_phase_sent, 0x01u, NULL, a5, a5n,
				     salt, &slen) != 0 ||
	    ultrawidelock_crypto_derive_block(s->z, salt, slen, s->device_eph_pub + 1, block) !=
		    0) {
		LOG_ERR("[conn %u] key-block derivation failed", s->conn_handle);
		session_terminate(s, "session key derivation failed");
		return;
	}
	ultrawidelock_crypto_split(block, 1, enc, dec, s->ursk);
	ultrawidelock_secchan_init(&s->sc, enc, dec);

#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP)
	/* Step-up SessionData keys off StepUpSK (block[64..95], §8.4.3), while the
	 * standard block is still in scope. Only for an armed transaction, which
	 * forced the standard phase, so the block layout is guaranteed. */
	if (s->stepup_active &&
	    ultrawidelock_stepup_derive_keys(block, s->stepup_skr, s->stepup_skd) == 0) {
		ultrawidelock_stepup_channel_init(&s->stepup_sc, s->stepup_skr, s->stepup_skd);
	}
#endif

	/* Ranging channel keys (§11.8.1) off the block's BleSK segment. */
	if (init_ble_channel(s, block) != 0) {
		session_terminate(s, "BLE channel initialization failed");
		return;
	}

	/* Decrypt the body: <ciphertext || 16-byte GCM tag>, the first inbound message
	 * (dec counter 1 per §8.3.1.13 init). A tag mismatch means the session key,
	 * counter, or ct/tag framing is off — the on-hardware test of the key schedule. */
	if (len < ULTRAWIDELOCK_GCM_TAG_LEN) {
		LOG_ERR("[conn %u] AUTH1Response too short for a GCM tag (%u B)", s->conn_handle,
			(unsigned)len);
		session_terminate(s, "short encrypted AUTH1 response");
		return;
	}
	size_t ctlen = len - ULTRAWIDELOCK_GCM_TAG_LEN;
	uint8_t ptbuf[256];

	if (ctlen > sizeof(ptbuf)) {
		LOG_ERR("[conn %u] AUTH1Response too large (%u B)", s->conn_handle,
			(unsigned)ctlen);
		session_terminate(s, "oversized AUTH1 response");
		return;
	}
	if (ultrawidelock_secchan_open(&s->sc, NULL, 0, pl, ctlen, pl + ctlen, ptbuf) != 0) {
		LOG_ERR("[conn %u] AUTH1Response GCM auth FAILED (%u ct B): session key / "
			"counter / ct-tag framing mismatch",
			s->conn_handle, (unsigned)ctlen);
		session_terminate(s, "AUTH1 authentication failed");
		return;
	}
	LOG_DBG("[conn %u] AUTH1Response DECRYPTED (%u B plaintext):", s->conn_handle,
		(unsigned)ctlen);
	LOG_HEXDUMP_DBG(ptbuf, ctlen, "");

	if (ultrawidelock_apdu_parse_auth1_response(ptbuf, ctlen, &r) != 0) {
		LOG_ERR("[conn %u] AUTH1Response (decrypted) parse failed", s->conn_handle);
		session_terminate(s, "malformed AUTH1 response");
		return;
	}

	/* Verify the device signature over the device-usage transcript. This proves
	 * possession of the presented key; whether that key is *trusted* is the
	 * separate trust-store check below. */
	const uint8_t *cred_pub = r.have_device_pub ? r.device_pub : s->device_eph_pub;
	uint8_t td[160];
	size_t tn;

	if (ultrawidelock_apdu_build_authdata(ULTRAWIDELOCK_AUTH_DEVICE, s_id.reader_id,
					      s->device_eph_pub + 1, s->reader_eph_pub + 1, s->txid,
					      td, sizeof(td), &tn) != 0) {
		session_terminate(s, "device transcript build failed");
		return;
	}
	if (ultrawidelock_ecdsa_p256_verify(cred_pub, td, tn, r.device_sig) != 0) {
		LOG_WRN("[conn %u] device signature INVALID (may need key lookup by "
			"identifier; the decrypt itself succeeded)",
			s->conn_handle);
		session_terminate(s, "device signature invalid");
		return;
	}
	LOG_INF("[conn %u] device signature OK", s->conn_handle);

	/* Remember the presented credential key for the `ultrawidelock-trust` bench command,
	 * and take the trust decision, under the lock the REPL commands share. The
	 * raw-key allowlist is the interim seam; real issuer-chain validation plugs
	 * in here (Phase 4). */
	ultrawidelock_mutex_lock(&s_prov_lock);
	memcpy(s_last_cred_pub, cred_pub, ULTRAWIDELOCK_CRED_PUB_LEN);
	s_have_last_cred = true;
	int tv = ultrawidelock_prov_trust_check(&s_trust, cred_pub);
	ultrawidelock_mutex_unlock(&s_prov_lock);

	if (tv == 0) {
		LOG_INF("[conn %u] credential key TRUSTED", s->conn_handle);
	} else if (tv == 1 && s_id.is_dev && CONFIG_ULTRAWIDELOCK_CRED_DEV_TRUST &&
		   s_provisioning_state == PROVISIONING_EMPTY) {
		LOG_WRN("[conn %u] no trust anchors (DEV identity): accepting the "
			"presented credential; run `ultrawidelock-trust` to enforce",
			s->conn_handle);
	} else {
#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP)
		/*
		 * Not an anchor -- but the store may hold the issuer that vouches
		 * for it. Apple Home installs the home's issuer key and one endpoint
		 * key per phone, and never one for a Watch on the same Apple ID; the
		 * Nordic reference lock admits such a device by asking for its
		 * Access Document (step-up, §8.4) and learning the key the issuer
		 * signed. So: derive the StepUpSK channel off the block while it is
		 * in scope, and let EXCHANGE go out. The grant waits on the verdict;
		 * a device that presented no long-term key has nothing to learn.
		 */
		uint8_t issuers;

		ultrawidelock_mutex_lock(&s_prov_lock);
		issuers = s_trust.issuer_count;
		ultrawidelock_mutex_unlock(&s_prov_lock);
		if (issuers > 0u && r.have_device_pub &&
		    ultrawidelock_stepup_derive_keys(block, s->stepup_skr, s->stepup_skd) == 0) {
			ultrawidelock_stepup_channel_init(&s->stepup_sc, s->stepup_skr, s->stepup_skd);
			s->stepup_active = true;
			s->learn_pending = true;
			memcpy(s->learn_pub, cred_pub, ULTRAWIDELOCK_CRED_PUB_LEN);
			LOG_INF("[conn %u] key not in trust store; %u issuer(s): asking for its "
				"Access Document",
				s->conn_handle, (unsigned)issuers);
		} else {
#endif
		LOG_WRN("[conn %u] credential key NOT trusted (%s); rejecting", s->conn_handle,
			tv == 1 ? "no anchors provisioned" : "not in trust store");
		/*
		 * "not in trust store" says the comparison failed but not what
		 * was compared, and the candidate explanations -- a credential
		 * that was never delivered, versus anchors from an old pairing
		 * holding every slot -- are told apart only by the bytes. This
		 * cost a whole evening of guessing when the line was absent, so
		 * it stays. First 8 of each point; the full key is never logged,
		 * and this only runs on a rejection.
		 */
		LOG_WRN("  presented: %02x %02x %02x %02x %02x %02x %02x %02x", cred_pub[0],
			cred_pub[1], cred_pub[2], cred_pub[3], cred_pub[4], cred_pub[5],
			cred_pub[6], cred_pub[7]);
		for (uint8_t ti = 0u; ti < s_trust.count && ti < ULTRAWIDELOCK_TRUST_MAX; ti++) {
			LOG_WRN("  anchor[%u]: %02x %02x %02x %02x %02x %02x %02x %02x%s", ti,
				s_trust.cred_pub[ti][0], s_trust.cred_pub[ti][1],
				s_trust.cred_pub[ti][2], s_trust.cred_pub[ti][3],
				s_trust.cred_pub[ti][4], s_trust.cred_pub[ti][5],
				s_trust.cred_pub[ti][6], s_trust.cred_pub[ti][7],
				(s_trust.kp_valid & (1u << ti)) ? " (has Kpersistent)" : "");
		}
		notify_access(false);
		session_terminate(s, "credential is not trusted");
		return;
#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP)
		}
#endif
	}
	/* Stage this credential's Kpersistent (§8.3.1.13): keyed off this
	 * session's Kdh, so every standard phase re-agrees it with the phone and the
	 * next walk-up can take the expedited-fast path. It is not committed to RAM
	 * until EXCHANGE transport acceptance below: an ambiguous send may have left
	 * the peer on either side of that boundary, so persisting its speculative key
	 * would make the next fast cryptogram fail. Dev-accepted credentials have no
	 * store slot to bind to. */
	uint8_t pending_kp[ULTRAWIDELOCK_KPERSISTENT_LEN] = {0};
	int pending_ki = -1;
	if (tv == 0) {
		if (ultrawidelock_salt_build(ULTRAWIDELOCK_SALT_KPERSISTENT, s->txid, s_reader_group_x,
				     s->reader_eph_pub + 1, s_id.reader_id, ULTRAWIDELOCK_IFACE_BLE,
				     ULTRAWIDELOCK_VERSION, s->exp_phase_sent, 0x01u, cred_pub + 1, a5, a5n,
				     salt, &slen) == 0 &&
		    ultrawidelock_crypto_derive_key32(s->z, salt, slen, s->device_eph_pub + 1,
					       pending_kp) == 0) {
			ultrawidelock_mutex_lock(&s_prov_lock);
			pending_ki = ultrawidelock_prov_trust_find(&s_trust, cred_pub);
			ultrawidelock_mutex_unlock(&s_prov_lock);
		}
	}

	/* EXCHANGE: seal + send the URSK-ready trigger (send_exchange also drives
	 * the §11.1.1 AP-Completed sequencing via on_exchange_response). */
	if (!send_exchange(s)) {
		memset(pending_kp, 0, sizeof(pending_kp));
		return;
	}
	if (pending_ki >= 0) {
		bool kp_committed = false;

		ultrawidelock_mutex_lock(&s_prov_lock);
		/* An admin may have reordered the trust store while EXCHANGE was in
		 * flight. Re-find rather than ever writing the staged key to a new
		 * credential that inherited the old slot. */
		if (pending_ki >= s_trust.count ||
		    memcmp(s_trust.cred_pub[pending_ki], cred_pub, ULTRAWIDELOCK_CRED_PUB_LEN) != 0) {
			pending_ki = ultrawidelock_prov_trust_find(&s_trust, cred_pub);
		}
		if (pending_ki >= 0 &&
		    ultrawidelock_prov_kpersistent_set(&s_trust, pending_ki, pending_kp) == 0) {
			s_kp_dirty = true;
			kp_committed = true;
		}
		ultrawidelock_mutex_unlock(&s_prov_lock);
		if (kp_committed) {
			LOG_INF("[conn %u] Kpersistent agreed (cred %d): next unlock can go fast",
				s->conn_handle, pending_ki);
			ultrawidelock_lab_evi("kp.minted", "cred", pending_ki);
		}
	}
	memset(pending_kp, 0, sizeof(pending_kp));
#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP)
	/* Nothing to publish yet: the key is trusted only if its document says
	 * so, and learn_decide() publishes the grant then. */
	if (s->learn_pending) {
		return;
	}
#endif
	/* Commit the externally visible authentication only after the outbound
	 * transition was accepted. A failed/ambiguous send terminates without
	 * publishing a fresh presence proof or MRU success. */
	ultrawidelock_mutex_lock(&s_prov_lock);
	memcpy(s_auth_cred_pub, cred_pub, ULTRAWIDELOCK_CRED_PUB_LEN);
	s_have_auth_cred = true;
	s_auth_generation++;
	if (tv == 0) {
		s_fast_mru = (int8_t)ultrawidelock_prov_trust_find(&s_trust, cred_pub);
	}
	ultrawidelock_mutex_unlock(&s_prov_lock);
	notify_access(true);
}

/* Reader-Status-Access-Protocol-Completed (§11.1.1 / §11.7.3.4.1): a proto-2
 * Notification, message-id 0x03, carrying one Reader Information Attribute
 * (id 0x00, len 2, value = unsolicited-status-reporting mode in bits 15:13). The
 * device will not initiate ranging until it receives this. Plaintext message the
 * BleSK channel then seals: [02][03][00 04][00 02 20 00]. */
static const uint8_t k_ap_completed_plain[] = {
	0x02, 0x03, 0x00, 0x04, 0x00, 0x02, 0x20, 0x00,
};

/* Send Reader-Status-AP-Completed (BleSK-sealed) and arm the ranging engine; the
 * transaction ends in PH_ESTABLISHED. Shared by the normal EXCHANGE path and the
 * step-up path (which runs it only after the DeviceResponse is collected). */
static void complete_ap_and_range(struct ultrawidelock_session *s)
{
	uint8_t wire[64];
	size_t wl;

	if (ultrawidelock_msg_seal(&s->sc_ble, k_ap_completed_plain, sizeof(k_ap_completed_plain), wire,
			   sizeof(wire), &wl) != 0) {
		LOG_ERR("[conn %u] AP-Completed seal failed", s->conn_handle);
		session_terminate(s, "AP-Completed seal failed");
		return;
	}
	int rc = ultrawidelock_ble_send(s->conn_handle, wire, wl);

	LOG_INF("[conn %u] Reader-Status-AP-Completed sent (%u B, rc=%d)", s->conn_handle,
		(unsigned)wl, rc);
	if (rc != 0) {
		session_terminate(s, "AP-Completed transport result ambiguous");
		return;
	}
	ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_AP_COMPLETED);

	/* Arm the ranging engine with the URSK + the BleSK channel; M1 is emitted by the
	 * engine when the device sends its Initiate-Ranging-Session (proto-2 id-1). The
	 * ranging session id is NOT reader's free choice: the device derives it as the
	 * big-endian last 4 bytes of the 16-byte AUTH0 transaction id (libaliro
	 * AccessProtocolCrypto::GetSessionId = rev(txid[12..15])) and indexes its URSK by
	 * it. A mismatch makes M1 land on a device with no URSK for that session
	 * (GeneralError URSK_Unavailable). */
	uint32_t ranging_sid = ((uint32_t)s->txid[12] << 24) | ((uint32_t)s->txid[13] << 16) |
			       ((uint32_t)s->txid[14] << 8) | (uint32_t)s->txid[15];

	if (ultrawidelock_ranging_start(s->conn_handle, ranging_sid, s->ursk, &s->sc_ble) != 0) {
		LOG_WRN("[conn %u] ranging setup did not arm", s->conn_handle);
		session_terminate(s, "ranging setup unavailable");
		return;
	}
	session_enter_phase(s, PH_ESTABLISHED);

	/* Stale-Wallet resync. If a relock notification was lost because the peer had
	 * already dropped BLE, the phone is still showing this door unlocked; a channel
	 * exists again now, so replay it once. Deliberately Secured-only: an unsolicited
	 * Unsecured would fire the Wallet unlock animation for a door the arriving phone
	 * did not open. Armed rather than sent here: the phone that just reconnected is
	 * usually one that woke on the doorstep and is about to be granted, and a Secured
	 * the grant overwrites a second later reads as the Wallet flickering locked then
	 * unlocked. ultrawidelock_reader_status_tick releases it if no grant intervenes. Costs
	 * nothing on a normal walk-up — the flag is only ever set by an undeliverable
	 * relock — so the ranging path stays off the critical latency path it just
	 * armed. */
	if (s_secured_undelivered) {
		LOG_INF("[conn %u] stale Wallet state: Secured replay armed (%d ms)",
			s->conn_handle, ULTRAWIDELOCK_SECURED_REPLAY_HOLD_MS);
		uint32_t at = (uint32_t)ultrawidelock_reader_monotonic_ms() +
			      ULTRAWIDELOCK_SECURED_REPLAY_HOLD_MS;

		s_secured_replay_at = (at == 0) ? 1u : at;
		s_peer_state_unknown = true;
	}
}

#if defined(CONFIG_ULTRAWIDELOCK_RSSI_GATE)
static const struct ultrawidelock_rssi_gate_cfg k_rgate_cfg = ULTRAWIDELOCK_RSSI_GATE_CFG_DEFAULT;
#endif

/* Run complete_ap_and_range only once the RSSI power gate allows the UWB radio:
 * the device does not initiate ranging until it receives AP-Completed (the
 * comment above k_ap_completed_plain), so holding that one message here keeps
 * the DW3000 dark while the phone is still tens of metres out. The gate opening
 * (ultrawidelock_reader_rssi_sample) completes the AP; a phone that gives up meanwhile
 * simply reconnects on approach and re-runs the fast auth. Direct call when the
 * gate is compiled out. */
static void gated_complete_ap(struct ultrawidelock_session *s)
{
#if defined(CONFIG_ULTRAWIDELOCK_RSSI_GATE)
	if (!s->rgate.primed) {
		/* No RSSI sample ever arrived (controller read failing?): fail OPEN.
		 * Deferring on missing data would trade a broken unlock for a power
		 * win; the wrong direction for a lock. The poll's inline first read
		 * at CoC-open makes this path unreachable when RSSI works. */
		LOG_WRN("[conn %u] RSSI gate has no samples; failing open (no power gating)",
			s->conn_handle);
	} else if (!ultrawidelock_rssi_gate_is_open(&s->rgate)) {
		session_enter_phase(s, PH_GATE_HOLD);
		ultrawidelock_rssi_gate_hold_begin(&s->rgate, (uint32_t)(ultrawidelock_uptime_us() / 1000));
		LOG_INF("[conn %u] RSSI gate closed (%d dBm): AP-Completed held, UWB stays dark",
			s->conn_handle, (int)ultrawidelock_rssi_gate_level_dbm(&s->rgate));
		ultrawidelock_lab_evi("gate.hold", "dbm", ultrawidelock_rssi_gate_level_dbm(&s->rgate));
		return;
	}
#endif
	complete_ap_and_range(s);
}

#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP)
/* End a learn-path transaction without the grant. The presented key stays
 * untrusted; the phone reconnects and, with a document that verifies, gets in. */
static void learn_reject(struct ultrawidelock_session *s, const char *why)
{
	(void)why; /* host log stub compiles the formatted argument away */
	LOG_WRN("[conn %u] credential key NOT trusted (%s); rejecting", s->conn_handle, why);
	LOG_WRN("  presented: %02x %02x %02x %02x %02x %02x %02x %02x", s->learn_pub[0],
		s->learn_pub[1], s->learn_pub[2], s->learn_pub[3], s->learn_pub[4], s->learn_pub[5],
		s->learn_pub[6], s->learn_pub[7]);
	s->stepup_active = false;
	s->learn_pending = false;
	stepup_sd_release(s->conn_handle);
	notify_access(false);
	session_terminate(s, "credential is not trusted");
}

/* The element the Nordic reference lock asks an Aliro device for, with the
 * intent to store it (access_manager_impl.cpp kAccessDocumentRequestParams). */
static const uint8_t k_learn_element[] = {'m', 'a', 't', 't', 'e', 'r', '1'};

/* Build the Access-Document DeviceRequest, seal it into a SessionData message on
 * the StepUpSK channel, and send it in an ENVELOPE APDU (§8.4). On any build/seal
 * failure the bench-armed path falls back to completing the AP so the unlock is
 * never blocked; the learn path has no unlock to protect and rejects. */
static void stepup_send_request(struct ultrawidelock_session *s)
{
	uint8_t devreq[128], sd[256], apdu[300];
	size_t drn, sdn, an;

	if (s_stepup_sd_owner != STEPUP_SD_FREE && s_stepup_sd_owner != s->conn_handle) {
		if (stepup_is_learn(s->learn_pending)) {
			learn_reject(s, "document buffer busy");
			return;
		}
		LOG_WRN("[conn %u] step-up: collection buffer held by conn %u; completing AP normally",
			s->conn_handle, s_stepup_sd_owner);
		s->stepup_active = false;
		gated_complete_ap(s);
		return;
	}
	s_stepup_sd_owner = s->conn_handle;
	s_stepup_sd_len = 0;

	int built;

#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP_BENCH)
	if (!s->learn_pending) {
		/* The bench one-shot asks for the §14.6 example elements. */
		built = ultrawidelock_stepup_build_device_request(NULL, 0, devreq, sizeof(devreq), &drn);
	} else
#endif
	{
		built = ultrawidelock_stepup_build_device_request_ex(k_learn_element,
								      sizeof(k_learn_element), true,
								      devreq, sizeof(devreq), &drn) ==
					ULTRAWIDELOCK_STEPUP_OK
				? 0
				: -1;
	}

	if (built != 0 ||
	    ultrawidelock_stepup_seal_sessiondata(&s->stepup_sc, devreq, drn, sd, sizeof(sd), &sdn) != 0 ||
	    ultrawidelock_stepup_build_envelope(sd, sdn, 0, apdu, sizeof(apdu), &an) != 0) {
		if (stepup_is_learn(s->learn_pending)) {
			learn_reject(s, "document request not built");
			return;
		}
		LOG_WRN("[conn %u] step-up: request build failed; completing AP normally",
			s->conn_handle);
		s->stepup_active = false;
		stepup_sd_release(s->conn_handle);
		gated_complete_ap(s);
		return;
	}
	if (send_ap_raw(s->conn_handle, apdu, an) != 0) {
		session_terminate(s, "step-up request transport result ambiguous");
		return;
	}
	session_enter_phase(s, PH_SENT_STEPUP);
	LOG_INF("[conn %u] step-up: ENVELOPE(DeviceRequest) sent (%u APDU B)", s->conn_handle,
		(unsigned)an);
}

#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP_BENCH)
/* Hand the collected SessionData response + StepUpSK keys to the background worker
 * so the parse/verify runs off the BLE-host task (never in the ranging arm window).
 * The bench-armed path (an already-trusted phone asked for its document): no issuer
 * is handed over, so the verifier selects by x5chain if present and otherwise
 * records "issuer key not found"; the verdict is logged only. The learn path never
 * comes here -- it verifies inline against the stored issuers (learn_verify) because
 * its verdict IS the access decision. A trusted wall clock is not wired
 * (time_valid = 0), so a TimeVerificationRequired document is recorded as
 * time-unverified. */
static void stepup_submit_job(struct ultrawidelock_session *s)
{
	struct ultrawidelock_stepup_job job;

	memset(&job, 0, sizeof(job));
	memcpy(job.sk_reader, s->stepup_skr, ULTRAWIDELOCK_SESSION_KEY_LEN);
	memcpy(job.sk_device, s->stepup_skd, ULTRAWIDELOCK_SESSION_KEY_LEN);
	job.have_issuer = 0;
	job.time_valid = 0;
	job.now_epoch = 0;
	job.conn_handle = s->conn_handle;
	_Static_assert(STEPUP_SD_MAX <= sizeof(((struct ultrawidelock_stepup_job *)0)->sd),
		       "the worker's job copy must take the collection buffer whole");
	memcpy(job.sd, s_stepup_sd, s_stepup_sd_len);
	job.sd_len = s_stepup_sd_len;
	if (ultrawidelock_stepup_worker_submit(&job) != 0) {
		LOG_WRN("[conn %u] step-up: worker submit failed (verdict skipped)",
			s->conn_handle);
	}
	s->stepup_active = false;
	stepup_sd_release(s->conn_handle);
}
#endif /* CONFIG_ULTRAWIDELOCK_CRED_STEPUP_BENCH */

/* Verify the collected DeviceResponse as the Access Document for s->learn_pub:
 * decrypt, parse, §7.4 against the PROVISIONED issuers only, then the binding
 * that makes it an Access Document for THIS key -- the MSO deviceKey must be the
 * key the device signed AUTH1 with. Returns the slot of the issuer that signed
 * it and copies its key to issuer_pub, or -1 with *why set. *v carries the last
 * §7.4 verdict for the log. */
static int learn_verify(struct ultrawidelock_session *s,
			uint8_t issuer_pub[ULTRAWIDELOCK_CRED_PUB_LEN], const char **why,
			struct ultrawidelock_stepup_verdict *v)
{
	struct ultrawidelock_stepup_issuer issuers[ULTRAWIDELOCK_ISSUER_MAX];
	struct ultrawidelock_stepup_verify_ctx ctx;
	size_t dr_len;
	uint8_t n;
	int picked = -1;

	memset(v, 0, sizeof(*v));
	/* Snapshot: the verify runs unlocked, and the Matter task may be
	 * installing or clearing an issuer meanwhile. */
	ultrawidelock_mutex_lock(&s_prov_lock);
	n = s_trust.issuer_count;
	for (uint8_t i = 0; i < n && i < ULTRAWIDELOCK_ISSUER_MAX; i++) {
		memcpy(issuers[i].pub, s_trust.issuer_pub[i], ULTRAWIDELOCK_CRED_PUB_LEN);
	}
	ultrawidelock_mutex_unlock(&s_prov_lock);
	if (n == 0u || n > ULTRAWIDELOCK_ISSUER_MAX) {
		*why = "no issuer key held";
		return -1;
	}
	if (s_stepup_sd_owner != s->conn_handle ||
	    ultrawidelock_stepup_open_sessiondata(&s->stepup_sc, s_stepup_sd, s_stepup_sd_len,
						  s_stepup_sd, sizeof(s_stepup_sd), &dr_len) != 0) {
		*why = "document did not authenticate";
		return -1;
	}
	if (ultrawidelock_stepup_parse_response(s_stepup_sd, dr_len, &s_learn_doc) != 0) {
		*why = "document malformed";
		return -1;
	}
	/*
	 * Only a provisioned issuer may vouch. With an x5chain present the
	 * verifier takes the signing key from the certificate the document
	 * brought along, which proves the document is self-consistent and
	 * nothing about whom the admin trusts. Drop it so selection falls to
	 * the store.
	 */
	s_learn_doc.x5chain = NULL;
	s_learn_doc.x5chain_len = 0;
	s_learn_doc.x5_cert = NULL;
	s_learn_doc.x5_cert_len = 0;

	memset(&ctx, 0, sizeof(ctx));
	/* No trusted wall clock on either board: §7.2.4 then fails a document
	 * that requires time verification, and passes one that does not. No
	 * access-iteration history is kept yet, so step 6 always passes. */
	ctx.time_valid = 0;
	ctx.access_iteration = 0;
	ctx.expected_doctype = ULTRAWIDELOCK_STEPUP_DOCTYPE_ACCESS;
	ctx.ecdsa_verify = ultrawidelock_ecdsa_p256_verify;

	/* Each provisioned issuer in turn, the document's own kid handed to the
	 * selector so the signature is the check. The kid (Aliro §7.2.1, a
	 * SHA-256 of the key) is not consulted: a home holds a handful of
	 * issuers, and an ECDSA verify per issuer is cheaper than the code that
	 * would derive and match kids, on a part with no flash to spare. */
	for (uint8_t i = 0; picked < 0 && i < n; i++) {
		issuers[i].kid = s_learn_doc.kid;
		issuers[i].kid_len = s_learn_doc.kid_len;
		ctx.issuers = &issuers[i];
		ctx.n_issuers = 1;
		if (ultrawidelock_stepup_verify(&s_learn_doc, &ctx, v) == 0) {
			picked = i;
		}
	}
	if (picked < 0) {
		*why = "no provisioned issuer signed it";
		return -1;
	}
	if (!s_learn_doc.have_device_key ||
	    memcmp(s_learn_doc.device_key, s->learn_pub, ULTRAWIDELOCK_CRED_PUB_LEN) != 0) {
		*why = "document vouches for another key";
		return -1;
	}
	memcpy(issuer_pub, issuers[picked].pub, ULTRAWIDELOCK_CRED_PUB_LEN);
	return picked;
}

/* Admit s->learn_pub as an evictable endpoint anchor vouched for by issuer_pub,
 * filed under the issuer's user and the lowest free credential index of its
 * type, mint its Kpersistent, persist -- and only then publish the grant. Same
 * rule as the Matter add: a key that cannot be persisted is not trusted.
 * Returns 0, or -1 when the key is NOT trusted. */
static int learn_commit(struct ultrawidelock_session *s,
			const uint8_t issuer_pub[ULTRAWIDELOCK_CRED_PUB_LEN])
{
	struct ultrawidelock_reader_identity id;
	struct ultrawidelock_trust_store cand;
	uint8_t kp[ULTRAWIDELOCK_KPERSISTENT_LEN], salt[ULTRAWIDELOCK_SALT_MAX];
	size_t slen;
	const uint8_t *a5 = s->a5_len ? s->a5_tlv : k_a5_csa_v1;
	size_t a5n = s->a5_len ? s->a5_len : sizeof(k_a5_csa_v1);
	uint16_t index = ULTRAWIDELOCK_CRED_INDEX_NONE, user = ULTRAWIDELOCK_CRED_INDEX_NONE;
	int slot = -1, add = -1, iss, rc = -1;

	/* The Kpersistent this standard phase agreed (§8.3.1.13), as
	 * on_auth1_response stages it for a key that was already trusted. */
	bool have_kp = ultrawidelock_salt_build(ULTRAWIDELOCK_SALT_KPERSISTENT, s->txid,
						s_reader_group_x, s->reader_eph_pub + 1,
						s_id.reader_id, ULTRAWIDELOCK_IFACE_BLE,
						ULTRAWIDELOCK_VERSION, s->exp_phase_sent, 0x01u,
						s->learn_pub + 1, a5, a5n, salt, &slen) == 0 &&
			ultrawidelock_crypto_derive_key32(s->z, salt, slen, s->device_eph_pub + 1,
							  kp) == 0;

	store_lock();
	ultrawidelock_mutex_lock(&s_prov_lock);
	id = s_id;
	cand = s_trust;
	/* Re-find rather than trust the slot the verify used: an admin may have
	 * cleared the issuer while the document was in flight. */
	iss = ultrawidelock_prov_issuer_find(&cand, issuer_pub);
	if (iss >= 0) {
		add = ultrawidelock_prov_trust_add(&cand, s->learn_pub);
		slot = add >= 0 ? ultrawidelock_prov_trust_find(&cand, s->learn_pub) : -1;
	}
	if (slot >= 0) {
		if (add == 1) {
			/* Installed by a SetCredential that landed meanwhile: keep the
			 * admin's filing, it is what ClearCredential will name. */
			index = cand.cred_index[slot];
			user = cand.user_index[slot];
		} else {
			index = ultrawidelock_prov_free_cred_index(&cand,
								   ULTRAWIDELOCK_CRED_TYPE_ALIRO_EVICTABLE);
			user = cand.issuer_user_index[iss];
			(void)ultrawidelock_prov_cred_bind_set(&cand, slot,
							       ULTRAWIDELOCK_CRED_TYPE_ALIRO_EVICTABLE,
							       index, user);
			(void)ultrawidelock_prov_anchor_issuer_set(&cand, slot, iss);
		}
		if (have_kp) {
			(void)ultrawidelock_prov_kpersistent_set(&cand, slot, kp);
		}
		rc = ultrawidelock_prov_store(&id, &cand);
	}
	if (rc == 0) {
		s_trust = cand;
		s_fast_mru = (int8_t)slot;
		memcpy(s_auth_cred_pub, s->learn_pub, ULTRAWIDELOCK_CRED_PUB_LEN);
		s_have_auth_cred = true;
		s_auth_generation++;
	}
	ultrawidelock_mutex_unlock(&s_prov_lock);
	store_unlock();
	memset(kp, 0, sizeof(kp));

	if (rc != 0) {
		LOG_ERR("[conn %u] learned key NOT stored (issuer %s, rc=%d)", s->conn_handle,
			iss < 0 ? "gone" : "held", rc);
		return -1;
	}
	LOG_INF("[conn %u] key LEARNED from its Access Document (issuer %d): type 7 idx %u user %u, "
		"%u anchor(s)%s",
		s->conn_handle, iss, (unsigned)index, (unsigned)user, cand.count,
		have_kp ? ", Kpersistent" : "");
	if (add == 2) {
		LOG_WRN("trust store was FULL; dropped an anchor to make room. "
			"ULTRAWIDELOCK_TRUST_MAX is %u -- raise it if this repeats",
			ULTRAWIDELOCK_TRUST_MAX);
	}
	ultrawidelock_lab_evi("cred.learned", "index", index);
	if (s_learned_listener != NULL) {
		s_learned_listener(ULTRAWIDELOCK_CRED_TYPE_ALIRO_EVICTABLE, index, user, s->learn_pub);
	}
	return 0;
}

/* The learn-path verdict, once the DeviceResponse is collected: verify, learn,
 * then complete the AP -- or reject with the operands in the log. */
static void learn_decide(struct ultrawidelock_session *s)
{
	uint8_t issuer_pub[ULTRAWIDELOCK_CRED_PUB_LEN];
	struct ultrawidelock_stepup_verdict v;
	const char *why = NULL;
	int iss = learn_verify(s, issuer_pub, &why, &v);

	/* The document, decrypted in place over what was collected, and the
	 * pointers into it are done with. */
	memset(&s_learn_doc, 0, sizeof(s_learn_doc));
	memset(s_stepup_sd, 0, sizeof(s_stepup_sd));
	stepup_sd_release(s->conn_handle);

	if (iss < 0) {
		LOG_WRN("[conn %u] Access Document verdict: step=%d issuer=%d sig=%d dig=%d type=%d "
			"time=%d iter=%d el=%u drop=%u/%u tr=%x",
			s->conn_handle, v.reject_step, v.issuer_key_found, v.sig_ok, v.digests_ok,
			v.doctype_ok, v.time_ok, v.iteration_ok, (unsigned)v.valid_elements,
			(unsigned)v.n_digests_dropped, (unsigned)v.n_items_dropped, v.truncated);
		learn_reject(s, why);
		return;
	}
	if (learn_commit(s, issuer_pub) != 0) {
		learn_reject(s, "learned key not persisted");
		return;
	}
	s->stepup_active = false;
	s->learn_pending = false;
	notify_access(true);
	gated_complete_ap(s);
}

/* Collect the DeviceResponse across ENVELOPE / GET RESPONSE (ISO7816 61XX
 * chaining) before completing the AP. The worker verifies it afterwards. */
static void on_stepup_response(struct ultrawidelock_session *s, const uint8_t *pl, size_t len)
{
	uint16_t sw;

	if (ultrawidelock_apdu_strip_sw(pl, &len, &sw) != 0) {
		if (stepup_is_learn(s->learn_pending)) {
			learn_reject(s, "short ENVELOPE response");
			return;
		}
		LOG_WRN("[conn %u] step-up: short ENVELOPE response; completing AP",
			s->conn_handle);
		s->stepup_active = false;
		stepup_sd_release(s->conn_handle);
		gated_complete_ap(s);
		return;
	}
	if (len > 0 && s_stepup_sd_owner == s->conn_handle &&
	    s_stepup_sd_len + len <= sizeof(s_stepup_sd)) {
		memcpy(s_stepup_sd + s_stepup_sd_len, pl, len);
		s_stepup_sd_len += len;
	} else if (len > 0) {
		if (stepup_is_learn(s->learn_pending)) {
			learn_reject(s, "document too large");
			return;
		}
		/* Bench: the first overflow ends the collection and gives the buffer
		 * back; the rest of the 61XX chain is drained without collecting, so
		 * a gapped document is never submitted. Logged once, while still owner. */
		if (s_stepup_sd_owner == s->conn_handle) {
			LOG_WRN("[conn %u] step-up: DeviceResponse over %u B; dropped",
				s->conn_handle, (unsigned)sizeof(s_stepup_sd));
			stepup_sd_release(s->conn_handle);
		}
	}

	if ((sw & 0xff00u) == 0x6100u) {
		/* more data available: GET RESPONSE for the remaining bytes */
		uint8_t apdu[8];
		size_t an;

		if (ultrawidelock_stepup_build_get_response((uint8_t)(sw & 0xffu), apdu, sizeof(apdu),
						    &an) == 0) {
				if (send_ap_raw(s->conn_handle, apdu, an) != 0) {
					session_terminate(s, "step-up continuation transport result ambiguous");
				}
		}
		return; /* stay in PH_SENT_STEPUP */
	}
	if (sw != 0x9000u) {
		LOG_WRN("[conn %u] step-up: ENVELOPE SW=0x%04x (device may have declined the "
			"DeviceRequest)",
			s->conn_handle, sw);
	}
	if (stepup_is_learn(s->learn_pending)) {
		if (sw != 0x9000u || s_stepup_sd_len == 0u) {
			learn_reject(s, "no document presented");
			return;
		}
		learn_decide(s);
		return;
	}
#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP_BENCH)
	LOG_INF("[conn %u] step-up: DeviceResponse collected (%u B); completing AP + verifying",
		s->conn_handle, (unsigned)s_stepup_sd_len);

	/* Complete the AP + arm ranging FIRST so the verify never delays the unlock,
	 * then hand the document to the worker. */
	gated_complete_ap(s);
	if (s_stepup_sd_owner == s->conn_handle && s_stepup_sd_len > 0) {
		stepup_submit_job(s);
	} else {
		s->stepup_active = false;
		stepup_sd_release(s->conn_handle);
	}
#endif
}
#endif /* CONFIG_ULTRAWIDELOCK_CRED_STEPUP */

/* Handle the EXCHANGE response, then complete the AP and arm ranging. The body is
 * an AP (proto-0) response on the ExpeditedSK channel: <ct || 16B tag> SW1SW2. */
static void on_exchange_response(struct ultrawidelock_session *s, const uint8_t *pl, size_t len)
{
	uint16_t sw;

	if (ultrawidelock_apdu_strip_sw(pl, &len, &sw) != 0) {
		LOG_ERR("[conn %u] EXCHANGE response too short", s->conn_handle);
		session_terminate(s, "short EXCHANGE response");
		return;
	}
	if (sw != 0x9000u) {
		session_terminate(s, "EXCHANGE status rejected");
		return;
	}
	uint8_t body[16];
	size_t bodylen = (len >= ULTRAWIDELOCK_GCM_TAG_LEN) ? len - ULTRAWIDELOCK_GCM_TAG_LEN : 0;

	if (bodylen == 0 || bodylen > sizeof(body) ||
	    ultrawidelock_secchan_open(&s->sc, NULL, 0, pl, bodylen, pl + bodylen, body) != 0) {
		LOG_ERR("[conn %u] EXCHANGE response decrypt failed", s->conn_handle);
		session_terminate(s, "EXCHANGE authentication failed");
		return;
	}
	/* Success body = 00 02 00 00 (len 0x0002, error 0x0000). Non-zero error bytes
	 * (body[2..4]) mean the device rejected a request. */
	bool ok = bodylen >= 4u && body[2] == 0x00u && body[3] == 0x00u;

	LOG_INF("[conn %u] EXCHANGE response: %s", s->conn_handle,
		ok ? "success (URSK armed)" : "ERROR");
	LOG_HEXDUMP_DBG(body, bodylen, "");
	if (!ok) {
		session_terminate(s, "EXCHANGE rejected");
		return;
	}
	ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_EXCHANGE_DONE);

#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP)
	/* Armed step-up: request the Access Document (ENVELOPE) before completing the
	 * AP, per the §8.2 flow (EXCHANGE response -> ENVELOPE -> ... -> AP-Completed).
	 * complete_ap_and_range runs once the DeviceResponse is fully collected. */
	if (s->stepup_active) {
		stepup_send_request(s);
		return;
	}
#endif
	gated_complete_ap(s);
}

/* Told when the reader announces a new lock state; see ultrawidelock_reader.h. */
static void (*s_lock_state_listener)(bool unlocked);

/**
 * Register a callback to be invoked when the lock state changes (unlocked or locked).
 */
void ultrawidelock_reader_set_lock_state_listener(void (*cb)(bool unlocked))
{
	s_lock_state_listener = cb;
}

/* Reader Status Changed (credential transaction step 23): the reader->phone grant/relock
 * confirmation that fires the iPhone Wallet unlock animation. proto-2 (Notification)
 * message-id 0x02, one State Attribute (id 0x00, len 2) = [OperationSource,
 * ReaderStateByte]. OperationSource 0x04 = this user device in the BLE+UWB credential flow;
 * ReaderStateByte Unsecured 0x01 = granted (animate), Secured 0x00 = relocked. The
 * 65-byte access-credential public key is NOT serialized (the reference uses it only
 * to select which connection to notify). Plaintext the BleSK channel then seals:
 * [02][02][00 04][00 02 04 <state>]. Runs on the BLE-host task (posted via
 * ultrawidelock_ble_post_reader_status) so it serializes with the other sc_ble seals. */
static void reader_status_send(struct ultrawidelock_session *s, bool unsecured)
{
	const uint8_t plain[8] = {
		0x02u, 0x02u, 0x00u, 0x04u,
		0x00u, 0x02u, 0x04u, (uint8_t)(unsecured ? 0x01u : 0x00u),
	};
	uint8_t wire[64];
	size_t wl;

	if (ultrawidelock_msg_seal(&s->sc_ble, plain, sizeof(plain), wire, sizeof(wire), &wl) != 0) {
		LOG_ERR("[conn %u] reader-status-changed seal failed", s->conn_handle);
		session_terminate(s, "Reader-Status seal failed");
		return;
	}
	int rc = ultrawidelock_ble_send(s->conn_handle, wire, wl);

	LOG_INF("[conn %u] Reader-Status-Changed %s sent (%u B, rc=%d)", s->conn_handle,
		unsecured ? "Unsecured/grant" : "Secured/relock", (unsigned)wl, rc);
	if (rc != 0) {
		if (!unsecured) {
			s_secured_undelivered = true;
		}
		session_terminate(s, "Reader-Status transport result ambiguous");
		return;
	}
	/*
	 * The lock-state listener used to fire here, gated on rc == 0 --
	 * "only once it is actually on the wire". That gate conflated two
	 * audiences. The phone needs DELIVERY; a Matter tile needs the TRUTH,
	 * and the truth does not depend on whether the phone was still around
	 * to hear it. The common relock is triggered BY the peer leaving, so
	 * hanging Matter's report off a successful send to that very peer
	 * guaranteed the Home tile stayed "unlocked" after every walk-away.
	 * The listener now fires in ultrawidelock_reader_notify_unlock(), on the state
	 * change itself.
	 */
	ultrawidelock_lab_ev(unsecured ? "grant.sent" : "relock.sent");
	s_secured_undelivered = false;
	/* Whatever just went out is newer than any held replay, including the replay
	 * itself firing. A grant landing inside the hold window therefore cancels it. */
	s_secured_replay_at = 0;
	s_peer_state_unknown = false;
	s_last_unsecured = unsecured;
}

/**
 * Send Reader-Status-Changed (credential step 23) on an established session: locked (Secured grant
 * to unlock) or unlocked (Unsecured). Deduplicates consecutive identical messages. Logs Secured
 * delivery failure and flags for replay on the next session if the peer disconnected before we
 * could send.
 */
static void reader_status_send_on_host(bool unsecured)
{
	struct ultrawidelock_session *s = NULL;

	if (unsecured == s_last_unsecured && !s_peer_state_unknown) {
		/* The peer already believes this. The gate-close path sends Secured
		 * itself before dropping the link, so the approach controller's own
		 * relock (which fires off that very disconnect) arrives here as a
		 * duplicate. Treating it as already-delivered is what stops it being
		 * flagged undeliverable and replayed on the next approach, which the
		 * user sees as the Wallet flashing locked then unlocked on arrival. */
		return;
	}

	for (int i = 0; i < ULTRAWIDELOCK_MAX_SESSIONS; i++) {
		if (s_sessions[i].active && s_sessions[i].phase == PH_ESTABLISHED) {
			s = &s_sessions[i];
			break;
		}
	}
	if (s == NULL) {
		/* The peer went away before we could tell it. A lost Unsecured costs
		 * nothing (the phone learns the door is open on its next approach), but
		 * a lost Secured strands the Wallet showing this door unlocked with
		 * nothing left to correct it: the relock is normally triggered BY the
		 * peer leaving, so this is the common case, not the rare one. Flag it
		 * and replay on the next session. */
		if (!unsecured) {
			s_secured_undelivered = true;
		}
		LOG_WRN("reader-status-changed: no established session to notify");
		return;
	}
	reader_status_send(s, unsecured);
}

// Sends a Reader-Status BLE notification reporting the lock's unsecured/secured state to the
// connected device. unsecured is true if the reader/lock is currently unsecured (unlocked), false
// if secured.
void ultrawidelock_reader_notify_unlock(bool unsecured)
{
	/*
	 * Tell the listener first, unconditionally. This is the grant machine's
	 * authoritative statement that the lock moved; whether the phone can be
	 * reached to hear about it is the delivery problem below, and the two
	 * must not share a fate. (The RSSI-gate farewell in rssi_changed() still
	 * sends Secured directly without passing here, but the approach
	 * controller's own relock follows it within a poll period and lands
	 * here; the listener's state-compare absorbs the near-duplicate.)
	 */
	if (s_lock_state_listener != NULL) {
		s_lock_state_listener(unsecured);
	}
	ultrawidelock_ble_post_reader_status(reader_status_send_on_host, unsecured);
}

// Releases a held stale-Wallet Secured once its window expires with no grant to supersede it.
// now_ms is the caller's monotonic clock (the same one ultrawidelock_uptime_ms reads); taking it as
// an argument keeps the deadline testable without a fake clock. No-op unless a replay is armed.
static _Atomic uint32_t s_reader_tick_now;

/*
 * The connected cap, once ESTABLISHED, measures idleness, not age.
 *
 * MEASURED 2026-09-10, DWM3001CDK + Apple Watch: unlock at +3 s, walk away,
 * relock at +10 s, the Watch suspends ranging at +16 s and restarts it at
 * +21 s on the same BLE link, ranges at 0 cm from +24 s -- and at +30 s the
 * reader disconnected it for "session deadline expired", mid-approach. The
 * Watch was back within a second, which is the other half of the point: the
 * cap never freed the controller, it only cost a walk-up. A peer that is
 * ranging is using the link; only one that has gone quiet on BOTH radios for
 * the whole window is holding it. BLE messages refresh the deadline in
 * on_data; this refreshes it for the UWB side, from the age of the newest
 * accepted range.
 */
static void session_idle_extend(struct ultrawidelock_session *s, uint32_t now_ms)
{
	int64_t age_ms;

	if (s->phase != PH_ESTABLISHED || !s->overall_deadline_armed ||
	    !ultrawidelock_ranging_last_range_age_ms(&age_ms) || age_ms < 0 ||
	    age_ms >= (int64_t)ULTRAWIDELOCK_READER_SESSION_TIMEOUT_MS) {
		return;
	}
	uint32_t until = now_ms + (ULTRAWIDELOCK_READER_SESSION_TIMEOUT_MS - (uint32_t)age_ms);

	if ((int32_t)(until - s->overall_deadline_ms) > 0) {
		s->overall_deadline_ms = until;
	}
}

static void reader_tick_on_host(void)
{
	uint32_t now_ms = atomic_load_explicit(&s_reader_tick_now, memory_order_relaxed);

	/* Credential handshake deadlines share this already-periodic monotonic tick.
	 * Exact equality expires; signed subtraction makes uint32 wrap safe. */
	for (int i = 0; i < ULTRAWIDELOCK_MAX_SESSIONS; i++) {
		struct ultrawidelock_session *s = &s_sessions[i];

		if (!s->active) {
			continue;
		}
		session_idle_extend(s, now_ms);
		if (s->phase_deadline_armed && (int32_t)(now_ms - s->phase_deadline_ms) >= 0) {
			session_terminate(s, "credential phase deadline expired");
		} else if (s->overall_deadline_armed &&
			   (int32_t)(now_ms - s->overall_deadline_ms) >= 0) {
			/* The two deadlines read the same in a field log unless the
			 * phase is named: a Watch that got its Pre-POLL accepted and
			 * then never ranged sits in PH_ESTABLISHED for the whole
			 * 30 s, which is not a credential-phase failure at all. */
			LOG_WRN("[conn %u] session deadline expired in phase %d", s->conn_handle,
				(int)s->phase);
			session_terminate(s, "session deadline expired");
		}
	}

	uint32_t at = s_secured_replay_at;

	/* Wrap-safe "now is at or past the deadline": the signed difference stays
	 * correct across the 49-day rollover, where a plain `now < at` would not. */
	if (at == 0 || (int32_t)(now_ms - at) < 0) {
		return;
	}
	s_secured_replay_at = 0;
	/* The peer may have left during the hold. Re-arming is the next session's job
	 * (the flag survives), so drop out quietly rather than posting a send that can
	 * only log "no established session to notify". */
	if (!s_secured_undelivered || !ultrawidelock_reader_session_active()) {
		return;
	}
	LOG_INF("replaying the undelivered Secured (stale Wallet state)");
	ultrawidelock_ble_post_reader_status(reader_status_send_on_host, false);
}

void ultrawidelock_reader_status_tick(int64_t now_ms)
{
	/* The caller is not the BLE-host owner. Retain only the newest time and
	 * coalesce a dedicated host event; the callback alone reads/mutates the
	 * session table. */
	atomic_store_explicit(&s_reader_tick_now, (uint32_t)now_ms, memory_order_relaxed);
	ultrawidelock_ble_post_reader_tick(reader_tick_on_host);
}

// Reports whether any peer currently holds an established credential session.
// Returns true if at least one session slot is active and in the established phase.
bool ultrawidelock_reader_session_active(void)
{
	return atomic_load_explicit(&s_established_sessions, memory_order_relaxed) != 0u;
}

#if defined(CONFIG_ULTRAWIDELOCK_CRED_ACCESS_LISTENER)
// Registers (or with NULL clears) the observer of the per-transaction access verdict.
// See ultrawidelock_reader.h for what the listener may do; call it before the reader starts.
void ultrawidelock_reader_set_access_listener(void (*cb)(bool granted))
{
	s_access_listener = cb;
}
#endif

// Copies the credential public key that most recently passed the trust check into out.
// Returns true if a credential has authenticated since boot (out written), false otherwise
// (out untouched). Safe to call from any task.
bool ultrawidelock_reader_authenticated_credential(uint8_t out[ULTRAWIDELOCK_CRED_PUB_LEN])
{
	bool have;

	load_provisioning(); /* the Matter task can reach here before the reader started */

	ultrawidelock_mutex_lock(&s_prov_lock);
	have = s_have_auth_cred;
	if (have) {
		memcpy(out, s_auth_cred_pub, ULTRAWIDELOCK_CRED_PUB_LEN);
	}
	ultrawidelock_mutex_unlock(&s_prov_lock);

	return have;
}

/**
 * Return true and copy the reader's single expected credential public key to out if exactly one
 * trust anchor is configured; used to validate single-device scenarios.
 */
bool ultrawidelock_reader_presence_expected_credential(uint8_t out[ULTRAWIDELOCK_CRED_PUB_LEN])
{
	bool have;

	load_provisioning();
	ultrawidelock_mutex_lock(&s_prov_lock);
	have = s_trust.count == 1u;
	if (have) {
		memcpy(out, s_trust.cred_pub[0], ULTRAWIDELOCK_CRED_PUB_LEN);
	}
	ultrawidelock_mutex_unlock(&s_prov_lock);
	return have;
}

/**
 * Return true and copy the provisioned reader's public key to out if a fresh authentication has
 * occurred since the checkpoint generation number; caller must hold the provisioning lock scope.
 */
bool ultrawidelock_reader_presence_authenticated_after(uint32_t checkpoint,
						       uint8_t out[ULTRAWIDELOCK_CRED_PUB_LEN])
{
	bool fresh;

	load_provisioning();
	ultrawidelock_mutex_lock(&s_prov_lock);
	fresh = s_have_auth_cred && (int32_t)(s_auth_generation - checkpoint) > 0;
	if (fresh) {
		memcpy(out, s_auth_cred_pub, ULTRAWIDELOCK_CRED_PUB_LEN);
	}
	ultrawidelock_mutex_unlock(&s_prov_lock);
	return fresh;
}

/**
 * Return true if any session is marked active on this connection.
 */
static bool any_session_active_on_host(void)
{
	for (int i = 0; i < ULTRAWIDELOCK_MAX_SESSIONS; i++) {
		if (s_sessions[i].active) {
			return true;
		}
	}
	return false;
}

/**
 * Mark the current presence request as ready and capture the current auth generation. Clear the
 * disconnect-wait flag.
 */
static void presence_checkpoint_ready_on_host(void)
{
	ultrawidelock_mutex_lock(&s_prov_lock);
	s_presence_ready_request = s_presence_request;
	s_presence_ready_auth_generation = s_auth_generation;
	s_presence_wait_disconnect = false;
	ultrawidelock_mutex_unlock(&s_prov_lock);
}

/**
 * Arm a waiter for disconnect, then ask the BLE transport to close all active sessions. If no
 * sessions are open, immediately publish a checkpoint; otherwise let the final disconnect event
 * trigger it.
 */
static void presence_reset_on_host(void)
{
	bool disconnecting = false;

	/* Set the waiter before asking the transport to disconnect. A host double
	 * can deliver on_disconnect inline, and a real stack may enqueue it before
	 * this callback returns. In either case the final disconnect must see the
	 * waiter armed so it can publish the post-reset checkpoint. */
	ultrawidelock_mutex_lock(&s_prov_lock);
	s_presence_wait_disconnect = true;
	ultrawidelock_mutex_unlock(&s_prov_lock);
	for (int i = 0; i < ULTRAWIDELOCK_MAX_SESSIONS; i++) {
		if (s_sessions[i].active) {
			disconnecting = true;
			(void)ultrawidelock_ble_disconnect(s_sessions[i].conn_handle);
		}
	}
	if (!disconnecting) {
		presence_checkpoint_ready_on_host();
		return;
	}
}

/**
 * Increment the presence request counter (skip zero), clear the ready request, and notify the host
 * that presence detection has restarted. Return the new request ID.
 */
uint32_t ultrawidelock_reader_presence_restart(void)
{
	uint32_t request;

	load_provisioning();
	ultrawidelock_mutex_lock(&s_prov_lock);
	request = ++s_presence_request;
	if (request == 0u) {
		request = ++s_presence_request;
	}
	s_presence_ready_request = 0u;
	ultrawidelock_mutex_unlock(&s_prov_lock);
	ultrawidelock_ble_post_presence_reset(presence_reset_on_host);
	return request;
}

/**
 * Return true if the request ID matches the stored ready-to-present checkpoint and optionally copy
 * the corresponding authentication generation; used to confirm a presence session has completed.
 */
bool ultrawidelock_reader_presence_checkpoint(uint32_t request, uint32_t *auth_generation)
{
	bool ready;

	load_provisioning();
	ultrawidelock_mutex_lock(&s_prov_lock);
	ready = request != 0u && s_presence_ready_request == request;
	if (ready && auth_generation != NULL) {
		*auth_generation = s_presence_ready_auth_generation;
	}
	ultrawidelock_mutex_unlock(&s_prov_lock);
	return ready;
}

/* Scan an op-0x05 Initiate-Access-Protocol payload for the phone's 0xA5
 * proprietary-information TLV (short-form BER length; the A5 value is small) and
 * copy the whole TLV (tag+len+value) into out. Returns the stored length, 0 if
 * no 0xA5 TLV is present, or -1 if one is present but unusable (long-form
 * length, or larger than cap) with *seen set to its length byte. The scan stops
 * at the first candidate that spans the payload: a 0xA5 inside its value is not
 * another TLV. */
static int capture_a5_tlv(const uint8_t *pl, size_t pl_len, uint8_t *out, size_t cap,
			  unsigned *seen)
{
	for (size_t i = 0; i + 2u <= pl_len; i++) {
		if (pl[i] != 0xA5u) {
			continue;
		}
		size_t vlen = pl[i + 1]; /* short-form length only */
		size_t tlv = 2u + vlen;

		*seen = (unsigned)vlen;
		if (vlen >= 0x80u) {
			return -1;
		}
		if (i + tlv > pl_len) {
			continue;
		}
		if (tlv > cap) {
			return -1;
		}
		memcpy(out, pl + i, tlv);
		return (int)tlv;
	}
	return 0;
}

/* Consume one inbound credential transaction SDU. */
static void transaction_feed(struct ultrawidelock_session *s, const uint8_t *data, uint16_t len)
{
	s->msgs_rx++;

	uint8_t type, opcode;
	const uint8_t *pl;
	size_t pl_len;

	if (ultrawidelock_ble_unframe(data, len, &type, &opcode, &pl, &pl_len) != 0) {
		LOG_WRN("[conn %u] msg #%u (%u B): not a valid envelope", s->conn_handle,
			(unsigned)s->msgs_rx, (unsigned)len);
		LOG_HEXDUMP_DBG(data, len, "");
		pl = data;
		pl_len = len;
		type = 0xff;
		opcode = 0xff;
	}
	LOG_INF("[conn %u] msg #%u: type=0x%02x op=0x%02x, %u payload B, phase=%s", s->conn_handle,
		(unsigned)s->msgs_rx, type, opcode, (unsigned)pl_len, phase_str(s->phase));

	/* A Notification Event mid-auth is the device rejecting us: GeneralError is
	 * encoded [01 01 <code>]. Surface <code> — it is the exact reason the phone
	 * bailed, far more legible than a downstream parse failure. Only pre-ranging:
	 * once ESTABLISHED, proto-2 events ride the BleSK channel encrypted, so pl[] is
	 * ciphertext here — the real event must be opened below, not read raw. */
	if (s->phase != PH_ESTABLISHED && type == ULTRAWIDELOCK_PROTO_NOTIFICATION &&
	    opcode == ULTRAWIDELOCK_NOTIF_EVENT) {
		/*
		 * Only the documented shape kills the transaction. A pre-ranging
		 * event that is NOT [01 01 <code>] is an event this reader does
		 * not understand, and "did not understand" is not "fatal".
		 *
		 * Measured 2026-08-02: a phone answered AUTH0 with a 2-byte
		 * event -- too short to be a GeneralError at all, so the code
		 * logged was this function's own 0xff placeholder -- the session
		 * latched FAILED, and the REAL 135-byte AUTH0 response arriving
		 * 2.3 s later was dropped with "message in phase FAILED
		 * ignored". That cost a whole walk-up; the phone had recovered
		 * and this end had not.
		 */
		if (pl_len >= 3u && pl[0] == 0x01u && pl[1] == 0x01u) {
			LOG_WRN("[conn %u] device GeneralError 0x%02x in phase %s", s->conn_handle,
				pl[2], phase_str(s->phase));
				session_terminate(s, "peer reported GeneralError");
			return;
		}
		LOG_WRN("[conn %u] unrecognised pre-ranging event, %u B, phase %s; not fatal",
			s->conn_handle, (unsigned)pl_len, phase_str(s->phase));
		return;
	}

	switch (s->phase) {
	case PH_IDLE:
		ultrawidelock_lat_mark(ULTRAWIDELOCK_LAT_OP05_RX);
		/* First peer message = op-0x05 Initiate Access Protocol, carrying the
		 * phone's 0xA5 proprietary-info TLV. Capture that TLV for the session-key
		 * salt (§8.3.1.13 trailing field) before driving AUTH0; fall back to the
		 * CSA v1.0 default if the phone sent none. Version negotiation rides the
		 * GATT characteristic. */
		unsigned a5_seen = 0;
		int a5 = capture_a5_tlv(pl, pl_len, s->a5_tlv, sizeof(s->a5_tlv), &a5_seen);

		if (a5 < 0) {
			/* Present but unusable: salting with the default would be a wrong
			 * key schedule, and AUTH1 would fail with a GCM error far from the
			 * cause. End it here with the reason. */
			LOG_WRN("[conn %u] 0xA5 TLV len byte 0x%02x unusable", s->conn_handle,
				a5_seen);
			session_terminate(s, "0xA5 TLV unusable");
			break;
		}
		s->a5_len = (size_t)a5;
		if (s->a5_len == 0) {
			LOG_WRN("[conn %u] no 0xA5 TLV in op-0x05; salt will use CSA v1.0 default",
				s->conn_handle);
		} else {
			LOG_INF("[conn %u] captured phone 0xA5 TLV (%u B) for session salt",
				s->conn_handle, (unsigned)s->a5_len);
		}
		LOG_INF("[conn %u] peer opened; starting access protocol", s->conn_handle);
		start_auth(s);
		break;
	case PH_SENT_AUTH0:
		on_auth0_response(s, pl, pl_len);
		break;
	case PH_SENT_AUTH1:
		on_auth1_response(s, pl, pl_len);
		break;
	case PH_SENT_EXCHANGE:
		on_exchange_response(s, pl, pl_len);
		break;
#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP)
	case PH_SENT_STEPUP:
		on_stepup_response(s, pl, pl_len);
		break;
#endif
	case PH_ESTABLISHED: {
		/* Ranging SDUs (proto 1/2/3) ride the BleSK channel: open the whole SDU
		 * (<hdr><ct||16B tag>), dump the plaintext, and hand it to the engine, which
		 * emits M1 on the Initiate-Ranging-Session and M3 on M2. The engine's replies
		 * are BleSK-sealed by ultrawidelock_ranging's tx callback. */
		uint8_t plain[256];
		size_t plen;

			if (ultrawidelock_msg_open(&s->sc_ble, data, len, plain, sizeof(plain), &plen) != 0) {
			LOG_WRN("[conn %u] ranging SDU open FAILED (proto=0x%02x id=0x%02x, %u B); "
				"raw:",
				s->conn_handle, type, opcode, (unsigned)pl_len);
			LOG_HEXDUMP_DBG(pl, pl_len, "");
				session_terminate(s, "ranging SDU authentication failed");
				break;
		}
		LOG_DBG("[conn %u] ranging SDU (proto=0x%02x id=0x%02x, %u B plaintext):",
			s->conn_handle, plain[0], plain[1], (unsigned)plen);
		LOG_HEXDUMP_DBG(plain, plen, "");
			if (ultrawidelock_ranging_feed(s->conn_handle, plain, plen) != 0) {
				session_terminate(s, "ranging engine rejected SDU");
			}
		break;
	}
	default:
		LOG_WRN("[conn %u] message in phase %s ignored", s->conn_handle,
			phase_str(s->phase));
		break;
	}
}

#if defined(CONFIG_ULTRAWIDELOCK_RSSI_GATE)
// Feeds one connection-RSSI sample into the session's ranging power gate and acts on the
// resulting transition: gate opening completes a held AP (starts ranging); gate closing on an
// established session tears ranging down and drops the link (the phone re-runs the fast auth
// on its next approach). Runs on the BLE-host task, same as every other session touch point.
void ultrawidelock_reader_rssi_sample(uint16_t conn_handle, int8_t rssi_dbm)
{
	struct ultrawidelock_session *s = session_find(conn_handle);

	if (s == NULL) {
		return;
	}
	uint32_t now_ms = (uint32_t)(ultrawidelock_uptime_us() / 1000);
	bool was_open = ultrawidelock_rssi_gate_is_open(&s->rgate);
	bool open = ultrawidelock_rssi_gate_feed(&s->rgate, &k_rgate_cfg, rssi_dbm, now_ms);

	ultrawidelock_lab_evi("rssi", "dbm", rssi_dbm);
	if (open && s->phase == PH_GATE_HOLD) {
		/* Two ways out of the hold: the level qualified, or the hold cap ran out
		 * and the gate opened anyway so the phone's own patience never does. The
		 * study needs them apart, so they get separate trace events. */
		bool capped = ultrawidelock_rssi_gate_was_capped(&s->rgate);

		LOG_INF("[conn %u] RSSI gate open%s (%d dBm): completing AP, ranging may start",
			conn_handle, capped ? " on the hold cap" : "",
			(int)ultrawidelock_rssi_gate_level_dbm(&s->rgate));
		ultrawidelock_lab_evi(capped ? "gate.holdcap" : "gate.open", "dbm",
			      ultrawidelock_rssi_gate_level_dbm(&s->rgate));
		complete_ap_and_range(s);
		return;
	}
	if (was_open && !open && s->phase == PH_ESTABLISHED) {
		/* Sustained fade below the close threshold: the peer has left the
		 * last few metres. Stop the responder (powers the DW3000 down) and
		 * drop the link rather than keep answering ever-farther polls. */
		LOG_INF("[conn %u] RSSI gate closed (%d dBm): stopping ranging, disconnecting",
			conn_handle, (int)ultrawidelock_rssi_gate_level_dbm(&s->rgate));
		ultrawidelock_lab_evi("gate.close", "dbm", ultrawidelock_rssi_gate_level_dbm(&s->rgate));
		ultrawidelock_ranging_stop(conn_handle);
		/* Say goodbye before hanging up. The approach controller relocks off the
		 * session ending, and the session ends because of the disconnect two
		 * lines down, so its own Secured would arrive with no channel left to
		 * carry it and the phone would keep showing the door unlocked until its
		 * next approach. Sending here costs one sealed 8-byte SDU on a link that
		 * is about to close anyway. The bolt follows within a poll period, so
		 * the phone reads Secured a moment early rather than minutes late. */
		if (s_last_unsecured) {
			reader_status_send(s, false);
		}
		(void)ultrawidelock_ble_disconnect(conn_handle);
	}
}
#endif /* CONFIG_ULTRAWIDELOCK_RSSI_GATE */

/**
 * Write the trust store if something left it dirty: a Kpersistent minted in RAM, or a removal that
 * was applied but could not be persisted. Returns 0 when there was nothing pending or the write
 * landed, and the store's negative errno when a pending write failed again.
 *
 * The dirty flag is cleared BEFORE the write and re-set on failure, not cleared after a success:
 * a Kpersistent minted between the housekeeping snapshot and reconciliation then leaves the flag
 * armed for the next write. s_store_lock serializes the entire operation against Matter/admin
 * stores, so none can land a newer image that this snapshot later overwrites.
 */
/* s_store_lock must be held. */
static int flush_pending_store_locked(void)
{
	struct ultrawidelock_reader_identity id;
	struct ultrawidelock_trust_store ts;
	bool dirty;

	ultrawidelock_mutex_lock(&s_prov_lock);
	dirty = s_kp_dirty;
	if (dirty) {
		id = s_id;
		ts = s_trust;
		s_kp_dirty = false;
	}
	ultrawidelock_mutex_unlock(&s_prov_lock);
	if (!dirty) {
		return 0;
	}

	int rc = ultrawidelock_prov_store(&id, &ts);

	if (rc != 0) {
		ultrawidelock_mutex_lock(&s_prov_lock);
		s_kp_dirty = true;
		ultrawidelock_mutex_unlock(&s_prov_lock);
		LOG_WRN("trust store persist failed (%d); will retry", rc);
		return rc;
	}
	LOG_INF("trust store persisted");
	return 0;
}

static int flush_pending_store(void)
{
	store_lock();
	int rc = flush_pending_store_locked();
	store_unlock();
	return rc;
}

/* Disconnect callbacks must stay bounded: P-256 key generation and settings
 * writes run on this dedicated low-priority thread. A binary semaphore
 * coalesces bursts; each wake makes at most three attempts and then leaves the
 * reason pending for the next external wake instead of spinning forever. */
#define HOUSEKEEPING_REFILL 0x01u
#define HOUSEKEEPING_STORE  0x02u
#define HOUSEKEEPING_MAX_ATTEMPTS 3u
#define HOUSEKEEPING_RETRY_MS 100u
#ifndef CONFIG_ULTRAWIDELOCK_CRED_HOUSEKEEPING_STACK_SIZE
#define CONFIG_ULTRAWIDELOCK_CRED_HOUSEKEEPING_STACK_SIZE 3072
#endif

static ultrawidelock_sem_t s_housekeeping_sem;
static ultrawidelock_thread_t s_housekeeping_thread;
ULTRAWIDELOCK_THREAD_STACK_DEFINE(s_housekeeping_stack,
				  CONFIG_ULTRAWIDELOCK_CRED_HOUSEKEEPING_STACK_SIZE);
static bool s_housekeeping_ready;
static uint8_t s_housekeeping_reasons;

static void housekeeping_schedule(uint8_t reasons)
{
	ultrawidelock_mutex_lock(&s_prov_lock);
	s_housekeeping_reasons |= reasons;
	ultrawidelock_mutex_unlock(&s_prov_lock);
	if (s_housekeeping_ready) {
		ultrawidelock_sem_give(&s_housekeeping_sem);
	}
}

/* One bounded batch. Failed operations are put back without signaling; the
 * owning thread performs its bounded retries, and a later disconnect wakes any
 * residual work. */
static uint8_t housekeeping_run_once(void)
{
	uint8_t reasons;
	uint8_t retry = 0;

	ultrawidelock_mutex_lock(&s_prov_lock);
	reasons = s_housekeeping_reasons;
	s_housekeeping_reasons = 0;
	ultrawidelock_mutex_unlock(&s_prov_lock);
	if ((reasons & HOUSEKEEPING_REFILL) != 0u && !spare_eph_refill()) {
		retry |= HOUSEKEEPING_REFILL;
	}
	if ((reasons & HOUSEKEEPING_STORE) != 0u && flush_pending_store() != 0) {
		retry |= HOUSEKEEPING_STORE;
	}
	if (retry != 0u) {
		ultrawidelock_mutex_lock(&s_prov_lock);
		s_housekeeping_reasons |= retry;
		ultrawidelock_mutex_unlock(&s_prov_lock);
	}
	return retry;
}

static void housekeeping_thread_entry(void *arg)
{
	(void)arg;
	for (;;) {
		(void)ultrawidelock_sem_take(&s_housekeeping_sem, ULTRAWIDELOCK_WAIT_FOREVER);
		for (unsigned attempt = 0; attempt < HOUSEKEEPING_MAX_ATTEMPTS; attempt++) {
			if (housekeeping_run_once() == 0u) {
				break;
			}
			if (attempt + 1u < HOUSEKEEPING_MAX_ATTEMPTS) {
				ultrawidelock_sleep_ms(HOUSEKEEPING_RETRY_MS);
			}
		}
	}
}

static int housekeeping_init(void)
{
	if (s_housekeeping_ready) {
		return 0;
	}
	ultrawidelock_sem_init(&s_housekeeping_sem, 0u, 1u);
	if (ultrawidelock_thread_create(&s_housekeeping_thread, s_housekeeping_stack,
					ULTRAWIDELOCK_THREAD_STACK_SIZEOF(s_housekeeping_stack),
					housekeeping_thread_entry, NULL,
					ULTRAWIDELOCK_THREAD_PRIO_LOW, "cred_housekeeping") != 0) {
		return -1;
	}
	s_housekeeping_ready = true;
	return 0;
}

#if defined(ULTRAWIDELOCK_PORT_HOST)
/* Host threads are recording fakes. Tests drive exactly one batch to prove
 * callback deferral, coalescing, and retry without an unbounded thread loop. */
uint8_t ultrawidelock_reader_housekeeping_run_once_for_test(void)
{
	return housekeeping_run_once();
}
#endif

/* ---- ultrawidelock_ble transport callbacks ---- */

// BLE connection-established callback: allocates a session slot for the new connection.
// Logs an error and returns without effect if no free session slot is available.
static void on_connected(uint16_t conn_handle)
{
	struct ultrawidelock_session *s = session_alloc(conn_handle);

	if (s == NULL) {
		LOG_ERR("[conn %u] no free session slot", conn_handle);
		return;
	}
	LOG_INF("[conn %u] credential session created", conn_handle);
	ultrawidelock_lab_ev("session.start");
}

/* How the most recent teardown left: from ESTABLISHED (deliberate close or
 * walked out of range) or mid-phase (the reconnect-in-seconds flap). Plain
 * boolean, same locking argument as ultrawidelock_reader_session_active(). */
static bool s_last_close_established;

bool ultrawidelock_reader_last_close_established(void)
{
	return s_last_close_established;
}

// BLE disconnection callback: marks the connection's session inactive (if one exists) and
// stops any UWB ranging associated with the connection.
// Logs the session's message count and final transaction phase before deactivating it.
static void on_disconnected(uint16_t conn_handle)
{
	struct ultrawidelock_session *s = session_find(conn_handle);

	if (s != NULL) {
		LOG_INF("[conn %u] credential session destroyed (%u msgs, phase=%s)", conn_handle,
			(unsigned)s->msgs_rx, phase_str(s->phase));
		s_last_close_established = (s->phase == PH_ESTABLISHED);
		/* Centralize the ESTABLISHED exit before clearing the host-owned slot,
		 * so the cross-task atomic snapshot cannot remain stale. */
		session_enter_phase(s, PH_FAILED);
		s->active = false;
		/* Aborted walk-ups never reach the bolt-time report: flush the stamped
		 * phases here (no-op if the bolt path already dumped them). */
		ultrawidelock_lab_dump();
		ultrawidelock_lab_ev("session.end");
	}
	ultrawidelock_ranging_stop(conn_handle);
	if (s != NULL) {
		/* Drop every volatile session key/counter immediately after the ranging
		 * owner releases its borrowed channel pointer. */
		memset(s, 0, sizeof(*s));
	}
#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP)
	/* A document half-collected by the departed peer must not block the next. */
	stepup_sd_release(conn_handle);
#endif
	ultrawidelock_mutex_lock(&s_prov_lock);
	bool presence_wait = s_presence_wait_disconnect;
	ultrawidelock_mutex_unlock(&s_prov_lock);
	if (presence_wait && !any_session_active_on_host()) {
		presence_checkpoint_ready_on_host();
	}
	/* Defer both expensive operations. The semaphore is binary, so simultaneous
	 * disconnects coalesce into one bounded low-priority batch. */
	housekeeping_schedule(HOUSEKEEPING_REFILL | HOUSEKEEPING_STORE);
}

// BLE data-received callback: looks up the session for conn_handle and feeds each credential
// envelope in the received buffer into its transaction state machine. Logs a warning and drops the
// data if no active session exists for conn_handle.
static void on_data(uint16_t conn_handle, const uint8_t *data, uint16_t len)
{
	struct ultrawidelock_session *s = session_find(conn_handle);

	if (s == NULL) {
		LOG_WRN("[conn %u] data for unknown session (%u bytes)", conn_handle,
			(unsigned)len);
		return;
	}
	uint32_t now_ms = (uint32_t)ultrawidelock_reader_monotonic_ms();
	if (s->phase == PH_ESTABLISHED) {
		/* Established, the cap is an IDLE cap: a peer that is still talking
		 * (ranging control, time sync, a restart) is not monopolizing the
		 * link, it is using it. See session_idle_extend(). */
		if (s->overall_deadline_armed) {
			s->overall_deadline_ms = now_ms + ULTRAWIDELOCK_READER_SESSION_TIMEOUT_MS;
		}
	} else if ((s->phase_deadline_armed && (int32_t)(now_ms - s->phase_deadline_ms) >= 0) ||
		   (s->overall_deadline_armed && (int32_t)(now_ms - s->overall_deadline_ms) >= 0)) {
		session_terminate(s, "credential phase deadline expired before receive");
		return;
	}
	/* One transport receive can carry more than one envelope back to back: the phone packs
	 * the Initiate-Ranging-Session SDU together with the proto-2 event that follows it, and
	 * the L2CAP CoC layer hands both up in a single callback. Split on the envelope's own
	 * length field rather than assuming one receive is one message. Two things went wrong
	 * when it did: the whole buffer was passed to ultrawidelock_msg_open, so the AEAD ran over 22
	 * bytes of the NEXT message and the tag check failed (the phone then hung up and the
	 * walk-up restarted ~3.5 s later), and the trailing envelope was dropped outright.
	 * A buffer that does not unframe is passed on whole, preserving the single-shot
	 * behaviour transaction_feed already has for a malformed envelope. */
	for (uint16_t off = 0; off < len;) {
		uint8_t type, opcode;
		const uint8_t *pl;
		size_t pl_len;
		uint16_t sdu = (uint16_t)(len - off);

		if (ultrawidelock_ble_unframe(data + off, sdu, &type, &opcode, &pl, &pl_len) == 0) {
			sdu = (uint16_t)(ULTRAWIDELOCK_ENVELOPE_HDR + pl_len);
		}
		transaction_feed(s, data + off, sdu);
		if (!s->active || s->disconnect_requested) {
			return;
		}
		off = (uint16_t)(off + sdu);
	}
}

/* The reader's BLE transport config: advertised versions/features + the
 * transaction transport callbacks. Shared by the standalone + attached starts. */
static struct ultrawidelock_ble_config make_ble_cfg(void)
{
	const struct ultrawidelock_ble_config cfg = {
		.proto_versions = k_proto_versions,
		.proto_versions_count = sizeof(k_proto_versions) / sizeof(k_proto_versions[0]),
		.features =
			{
				.timesync_procedure_0 = true,
				.timesync_procedure_1 = false,
				.le_coded_phy = false,
			},
		.cb =
			{
				.on_data = on_data,
				.on_connected = on_connected,
				.on_disconnected = on_disconnected,
#if defined(CONFIG_ULTRAWIDELOCK_RSSI_GATE)
				/* non-NULL turns the transport's RSSI poll on */
				.on_rssi = ultrawidelock_reader_rssi_sample,
#endif
			},
	};
	return cfg;
}

/* crypto + provisioning load + UWB ranging setup, shared by both start paths. */
static int reader_engine_init(void)
{
	if (ultrawidelock_crypto_init() != 0) {
		LOG_ERR("crypto init failed");
		return -1;
	}
	int prov_rc = load_provisioning();
	if (prov_rc < 0) {
		LOG_ERR("provisioning storage unavailable (%d); reader remains offline", prov_rc);
		return prov_rc;
	}
	if (housekeeping_init() != 0) {
		LOG_ERR("credential housekeeping thread unavailable");
		return -1;
	}
	if (ultrawidelock_ranging_init() != 0) {
		LOG_WRN("UWB ranging adapter unavailable; auth will run but "
			"ranging setup won't start");
	}
	(void)spare_eph_refill(); /* first walk-up's ephemeral pair, off the callback path */
	return 0;
}

/* Applies the provisioned resolvable advertising parameters when a real GRK is
 * present. The phone resolves "its" reader by re-deriving the dynamic tag from the
 * GroupResolvingKey, so without this the advertisement carries only the bare 0xFFF2
 * UUID and a provisioned Wallet key never approaches. groupId = reader_id[0..7],
 * subId = reader_id[16..17] (the identity is groupIdentifier(16) ||
 * groupSubIdentifier(16)). Returns false on the all-zero dev-default GRK. */
static bool apply_provisioned_adv_params(void)
{
	for (size_t i = 0; i < ULTRAWIDELOCK_GRK_LEN; i++) {
		if (s_id.grk[i] != 0u) {
			const uint8_t sub2[2] = {s_id.reader_id[16], s_id.reader_id[17]};

			ultrawidelock_ble_set_adv_params(&s_id.reader_id[0], sub2, s_id.grk,
						 0 /* tx power */);
			return true;
		}
	}
	return false;
}

// Starts the credential reader: initializes the engine (crypto, provisioning, UWB ranging), applies
// the provisioned advertising parameters when the loaded identity carries a GRK, and brings up the
// BLE transport. Returns 0 on success; returns -1 if engine initialization fails, or the underlying
// ultrawidelock_ble_start result otherwise.
int ultrawidelock_reader_start(void)
{
	int init_rc = reader_engine_init();
	if (init_rc != 0) {
		return init_rc;
	}
	/* A standalone reader loads its provisioned identity from storage during
	 * reader_engine_init, so the GRK is already in s_id by here. Without this the
	 * board advertises unresolvably and a provisioned Wallet key never approaches
	 * it -- the attached (Matter) path applied these params and this one did not. */
	apply_provisioned_adv_params();

	struct ultrawidelock_ble_config cfg = make_ble_cfg();
	int rc = ultrawidelock_ble_start(&cfg);

	LOG_INF("ultrawidelock_reader_start: transport %s (SPSM 0x%04x)", rc == 0 ? "up" : "FAILED",
		ultrawidelock_ble_spsm());
	return rc;
}

/* ---- attach mode: share a host another stack (e.g. Matter) owns ---------- */

// Prepares the BLE transport and returns the credential GATT service definition for external
// registration, without starting the transport. Returns NULL if ultrawidelock_ble_prepare fails; on
// success returns the pointer from ultrawidelock_ble_service_def(), owned by the BLE layer.
const void *ultrawidelock_reader_ble_prepare(void)
{
	struct ultrawidelock_ble_config cfg = make_ble_cfg();

	if (ultrawidelock_ble_prepare(&cfg) != 0) {
		LOG_ERR("ultrawidelock_ble_prepare failed");
		return NULL;
	}
	return ultrawidelock_ble_service_def();
}

// Starts the credential reader in "attached" transport mode: initializes the engine, applies
// provisioned resolvable advertising parameters if a real GRK is present, then starts the attached
// BLE transport. Unlike ultrawidelock_reader_start, this applies GRK-based advertising params
// (group/subgroup ID from reader_id, GRK) before starting, when the reader has already been
// provisioned; falls back to unresolvable advertising if no GRK is set yet. Returns 0 on success;
// returns -1 if engine initialization fails, or the underlying ultrawidelock_ble_start_attached
// result otherwise.
int ultrawidelock_reader_start_attached(void)
{
	int init_rc = reader_engine_init();
	if (init_rc != 0) {
		return init_rc;
	}

	/* Provisioned credential advertising params (BLE-UWB approach discovery): only
	 * advertise the resolvable service data when a real GRK is present
	 * (Matter-provisioned); the dev default leaves the bare 0xFFF2 UUID. */
	apply_provisioned_adv_params();

	int rc = ultrawidelock_ble_start_attached();

	LOG_INF("ultrawidelock_reader_start_attached: %s (SPSM 0x%04x)", rc == 0 ? "up" : "FAILED",
		ultrawidelock_ble_spsm());
	return rc;
}

// Refreshes the BLE advertisement to include the resolvable service data once a real
// GroupResolvingKey (GRK) is available. Handles the case where Matter provisioning
// (SetAliroReaderConfig) lands after advertising has already started with only the bare 0xFFF2 UUID
// (dev default, all-zero GRK), which the phone cannot resolve. No-ops if the GRK in s_id is still
// all-zero. On a nonzero GRK, derives the two-byte subgroup ID from reader_id[16..17] and calls
// ultrawidelock_ble_set_adv_params + ultrawidelock_ble_readvertise to make the reader
// approach-resolvable.
void ultrawidelock_reader_refresh_adv(void)
{
	/* Matter provisioning (SetAliroReaderConfig) can land after the reader has
	 * already started advertising: Apple sends it as post-commissioning operational
	 * commands, whereas the reader starts on kCommissioningComplete. At start the
	 * identity was still the dev default (no GRK), so the reader advertised only the
	 * bare 0xFFF2 UUID and the phone cannot resolve it. Once the real GRK is in
	 * s_id (provision_identity ran just before), pull it into the advertisement. */
	if (!apply_provisioned_adv_params()) {
		/*
		 * Was a bare `return`. An all-zero GRK is the one state in which
		 * the reader keeps advertising a payload no phone can resolve,
		 * and saying nothing about it is why that went unnoticed through
		 * a whole pairing: the board looked healthy in every other
		 * respect and simply never saw an approach.
		 */
		LOG_WRN("advertisement NOT refreshed: GRK is still all-zero, so this reader "
			"cannot be approach-resolved");
		return;
	}
	ultrawidelock_ble_readvertise();
	LOG_INF("advertisement refreshed with provisioned GRK (approach-resolvable)");
}

/* ---- bench provisioning helpers (ultrawidelock-prov / ultrawidelock-trust) ------------- */

// Print the reader's provisioning state (identity, trust anchors, last presented credential)
// to the console for diagnostics.
// Loads provisioning first, then snapshots the shared state under s_prov_lock before printing
// so UART I/O does not hold the lock during the BLE task's trust check.
void ultrawidelock_reader_prov_print(void)
{
	load_provisioning();

	/* Snapshot the shared state under the lock, then print off the copy so the
	 * UART I/O never holds up the BLE task's trust check. */
	struct ultrawidelock_trust_store ts;
	uint8_t last[ULTRAWIDELOCK_CRED_PUB_LEN];
	bool have;

	ultrawidelock_mutex_lock(&s_prov_lock);
	ts = s_trust;
	have = s_have_last_cred;
	memcpy(last, s_last_cred_pub, ULTRAWIDELOCK_CRED_PUB_LEN);
	ultrawidelock_mutex_unlock(&s_prov_lock);

	printf("identity  : %s\n", s_id.is_dev ? "DEV (bench)" : "provisioned");
	printf("reader_id : ");
	for (unsigned i = 0; i < ULTRAWIDELOCK_READER_ID_LEN; i++) {
		printf("%02x", s_id.reader_id[i]);
	}
	printf("\ntrust     : %u/%u anchor(s)\n", ts.count, ULTRAWIDELOCK_TRUST_MAX);
	for (unsigned i = 0; i < ts.count; i++) {
		printf("  [%u] ", i);
		for (unsigned j = 0; j < ULTRAWIDELOCK_CRED_PUB_LEN; j++) {
			printf("%02x", ts.cred_pub[i][j]);
		}
		/* type+cred is the pair a Matter ClearCredential names this anchor
		 * by -- both halves, because an index is scoped to its type -- and
		 * user is what ClearUser names it by. A 0 in either means nothing
		 * can name it. issuer is set only for a key learned from an Access
		 * Document, and names the issuer slot that vouched for it. */
		printf(" kpersistent=%s type=%u cred=%u user=%u issuer=%d\n",
		       ((ts.kp_valid >> i) & 1u) ? "yes" : "no", (unsigned)ts.cred_type[i],
		       (unsigned)ts.cred_index[i], (unsigned)ts.user_index[i],
		       ultrawidelock_prov_anchor_issuer(&ts, (int)i));
	}
	printf("issuers   : %u/%u key(s)\n", ts.issuer_count, ULTRAWIDELOCK_ISSUER_MAX);
	for (unsigned i = 0; i < ts.issuer_count && i < ULTRAWIDELOCK_ISSUER_MAX; i++) {
		printf("  [%u] ", i);
		for (unsigned j = 0; j < ULTRAWIDELOCK_CRED_PUB_LEN; j++) {
			printf("%02x", ts.issuer_pub[i][j]);
		}
		printf(" cred=%u user=%u\n", (unsigned)ts.issuer_cred_index[i],
		       (unsigned)ts.issuer_user_index[i]);
	}
	printf("last cred : ");
	if (have) {
		for (unsigned i = 0; i < ULTRAWIDELOCK_CRED_PUB_LEN; i++) {
			printf("%02x", last[i]);
		}
		printf("\n");
	} else {
		printf("(none presented yet)\n");
	}
}

/* ---- revocation aftermath ------------------------------------------------ *
 * Dropping an anchor is not the whole job. An established session keeps ranging
 * under a URSK derived long before the removal and never revisits the trust
 * store, so the door keeps opening until its link ends; and two module latches
 * still name the key that just lost its trust. */

/**
 * Terminate every live credential link. Runs on the BLE-host task, which owns the session table.
 */
static void revoke_sweep_on_host(void)
{
	for (int i = 0; i < ULTRAWIDELOCK_MAX_SESSIONS; i++) {
		if (s_sessions[i].active) {
			LOG_WRN("[conn %u] link dropped: a credential was revoked",
				s_sessions[i].conn_handle);
			(void)ultrawidelock_ble_disconnect(s_sessions[i].conn_handle);
		}
	}
}

/**
 * Forget a revoked credential everywhere outside the trust store: the attribution latch that names
 * who unlocked, the bench re-add latch that would put it straight back, and any link still ranging
 * on it. Pass NULL when more than one key went, which clears both latches unconditionally.
 * Call without s_prov_lock held.
 */
static void revoke_aftermath(const uint8_t *removed_pub)
{
	ultrawidelock_mutex_lock(&s_prov_lock);
	if (s_have_auth_cred && (removed_pub == NULL ||
				 memcmp(s_auth_cred_pub, removed_pub, ULTRAWIDELOCK_CRED_PUB_LEN) == 0)) {
		memset(s_auth_cred_pub, 0, ULTRAWIDELOCK_CRED_PUB_LEN);
		s_have_auth_cred = false;
	}
	if (s_have_last_cred && (removed_pub == NULL ||
				 memcmp(s_last_cred_pub, removed_pub, ULTRAWIDELOCK_CRED_PUB_LEN) == 0)) {
		memset(s_last_cred_pub, 0, ULTRAWIDELOCK_CRED_PUB_LEN);
		s_have_last_cred = false;
	}
	ultrawidelock_mutex_unlock(&s_prov_lock);
	ultrawidelock_ble_post_revoke_sweep(revoke_sweep_on_host);
}

/**
 * Persist a store a removal has ALREADY applied in RAM.
 *
 * The opposite order to the add path, deliberately. An add that cannot be persisted must not be
 * trusted, so it writes first and commits second. A removal that cannot be persisted must still
 * stop opening the door, so it commits first and reports the failure afterwards; the store is left
 * dirty for flush_pending_store() to retry.
 *
 * That retry needs a caller. A disconnect is one, but a revocation with no link up has no
 * disconnect coming, so the removal entry points retry a pending write themselves -- an admin
 * repeating the command is then what drives it, and until one of the two runs the removal is live
 * in RAM and a reboot would bring the anchor back.
 *
 * Returns 0 when the removal is live and persisted, or the store's negative errno when it is live
 * but unpersisted -- never 0 for an unpersisted removal, because a Matter admin is told what this
 * returns.
 */
/* Both s_store_lock and s_prov_lock must be held, in that order. */
static int persist_removal_locked(const struct ultrawidelock_reader_identity *id,
				  const struct ultrawidelock_trust_store *ts)
{
	int rc = ultrawidelock_prov_store(id, ts);

	if (rc == 0) {
		return 0;
	}
	s_kp_dirty = true;
	LOG_ERR("revocation applied in RAM but NOT persisted (%d); retrying on the next "
		"disconnect or revocation",
		rc);
	return rc;
}

// Add the most recently presented credential's public key to the trust store and persist it.
// Returns 1 if no credential has been presented yet or it is already trusted (nothing
// persisted), -1 if the key is not an uncompressed point, the store's negative errno if the
// NVS write fails (in-memory trust store left unchanged on failure), 0 if newly added and
// committed. A full store evicts rather than refusing.
int ultrawidelock_reader_trust_last(void)
{
	load_provisioning();

	/* Serialize snapshot, write, and commit against both housekeeping and other
	 * admin tasks. A failed write still changes nothing. */
	struct ultrawidelock_trust_store cand;
	uint8_t last[ULTRAWIDELOCK_CRED_PUB_LEN];
	bool have;

	store_lock();
	ultrawidelock_mutex_lock(&s_prov_lock);
	cand = s_trust;
	have = s_have_last_cred;
	memcpy(last, s_last_cred_pub, ULTRAWIDELOCK_CRED_PUB_LEN);

	if (!have) {
		ultrawidelock_mutex_unlock(&s_prov_lock);
		store_unlock();
		return 1; /* nothing presented yet */
	}
	int add = ultrawidelock_prov_trust_add(&cand, last);

	if (add == 1) {
		ultrawidelock_mutex_unlock(&s_prov_lock);
		store_unlock();
		return 1; /* already trusted; nothing to persist */
	}
	if (add < 0) {
		/* Not a P-256 point. A FULL store is no longer a refusal -- it
		 * evicts and returns 2 -- so this branch no longer means what
		 * its old comment said it did. */
		ultrawidelock_mutex_unlock(&s_prov_lock);
		store_unlock();
		return -1;
	}
	int store_rc = ultrawidelock_prov_store(&s_id, &cand);

	if (store_rc != 0) {
		ultrawidelock_mutex_unlock(&s_prov_lock);
		store_unlock();
		return store_rc; /* not committed; s_trust unchanged */
	}
	s_trust = cand;
	s_fast_mru = -1;
	ultrawidelock_mutex_unlock(&s_prov_lock);
	store_unlock();
	return 0;
}

// Empty the trust store and persist the empty store, keeping the reader identity.
// Returns 1 if the store was already empty (nothing persisted), 0 if cleared and persisted,
// or the store's negative errno if the NVS write failed -- in which case the store is still
// empty in RAM, because a revocation that cannot be written must not keep opening the door
// in the meantime.
//
// Every re-pair mints a fresh credential and nothing evicts the old ones, so the store
// reaches ULTRAWIDELOCK_TRUST_MAX and refuses the key currently being presented. A Matter factory
// reset does not touch this namespace, so without this the only way out is erasing NVS.
int ultrawidelock_reader_trust_clear(void)
{
	load_provisioning();

	struct ultrawidelock_reader_identity id;
	struct ultrawidelock_trust_store cand;

	/* Emptied under the lock rather than off a snapshot: a snapshot-then-
	 * commit would silently undo a SetCredential that landed in between, and
	 * on this path that would put a just-revoked anchor back. */
	store_lock();
	ultrawidelock_mutex_lock(&s_prov_lock);
	if (s_trust.count == 0u) {
		ultrawidelock_mutex_unlock(&s_prov_lock);
		store_unlock();
		return 1;
	}
	memset(&s_trust, 0, sizeof(s_trust));
	s_fast_mru = -1;
	id = s_id;
	cand = s_trust;
	int rc = persist_removal_locked(&id, &cand);
	ultrawidelock_mutex_unlock(&s_prov_lock);
	store_unlock();

	revoke_aftermath(NULL);
	return rc;
}

/* ---- Step-up (Access Document) bench control --------------------------- */

_Static_assert(ULTRAWIDELOCK_READER_ISSUER_KEYS_MAX == ULTRAWIDELOCK_ISSUER_MAX,
	       "the issuer cap the public header spells out must be the store's");

// Register the learned-credential listener (see ultrawidelock/reader.h).
void ultrawidelock_reader_set_credential_learned_listener(
	void (*cb)(uint8_t cred_type, uint16_t cred_index, uint16_t user_index,
		   const uint8_t cred_pub[ULTRAWIDELOCK_CRED_PUB_LEN]))
{
	s_learned_listener = cb;
}

// Arm a one-shot Access-Document request (see ultrawidelock_reader.h). No-op with a note
// when the reader was built without CONFIG_ULTRAWIDELOCK_CRED_STEPUP_BENCH.
void ultrawidelock_reader_stepup_arm(void)
{
#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP_BENCH)
	load_provisioning(); /* ensures s_prov_lock exists */
	ultrawidelock_mutex_lock(&s_prov_lock);
	s_stepup_armed = true;
	ultrawidelock_mutex_unlock(&s_prov_lock);
	LOG_INF("step-up armed: the next transaction will request an Access Document");
#else
	LOG_WRN("bench step-up not built (CONFIG_ULTRAWIDELOCK_CRED_STEPUP_BENCH=n)");
#endif
}

// Print the armed state and the most recent verification verdict (see ultrawidelock_reader.h).
void ultrawidelock_reader_stepup_status(void)
{
#if defined(CONFIG_ULTRAWIDELOCK_CRED_STEPUP_BENCH)
	bool armed;

	load_provisioning();
	ultrawidelock_mutex_lock(&s_prov_lock);
	armed = s_stepup_armed;
	ultrawidelock_mutex_unlock(&s_prov_lock);
	printf("step-up   : built, %s\n", armed ? "ARMED (one-shot)" : "idle");

	struct ultrawidelock_stepup_verdict v;
	uint16_t conn;

	if (ultrawidelock_stepup_worker_last(&v, &conn) == 1) {
		printf("last verdict (conn %u): %s (reject_step=%d)\n", conn,
		       v.valid ? "VALID" : "invalid", v.reject_step);
		printf("  issuer_key_found=%d chain_validated=%d sig_ok=%d digests_ok=%d\n",
		       v.issuer_key_found, v.issuer_chain_validated, v.sig_ok, v.digests_ok);
		printf("  doctype_ok=%d time_ok=%d iteration_ok=%d valid_elements=%u\n",
		       v.doctype_ok, v.time_ok, v.iteration_ok, (unsigned)v.valid_elements);
	} else {
		printf("last verdict: (none yet)\n");
	}
#else
	printf("step-up   : bench one-shot not built (CONFIG_ULTRAWIDELOCK_CRED_STEPUP_BENCH=n)\n");
#endif
}

/* ---- Matter provisioning bridge (Phase 4) ------------------------------ *
 * These run on the Matter task during commissioning, before the reader is
 * started (the reader starts only after the BLE handoff). They mutate the same
 * s_id/s_trust the reader loads, and persist through ultrawidelock_prov, so a snapshot-
 * then-store keeps NVS and the in-memory copy consistent under s_prov_lock. */

// Store a Matter-provisioned reader identity (reader ID, signing private key, GRK), keeping
// any trust anchors already present, and persist it to NVS.
// Returns the store's negative errno if the NVS write fails, in which case in-memory identity
// (s_id) is unchanged; returns 0 on success, after which the reader group key salt is recomputed
// via compute_reader_group_x since the signing key changed.
int ultrawidelock_reader_provision_identity(const uint8_t reader_id[ULTRAWIDELOCK_READER_ID_LEN],
				    const uint8_t sign_priv[ULTRAWIDELOCK_READER_PRIV_LEN],
				    const uint8_t grk[ULTRAWIDELOCK_GRK_LEN])
{
	load_provisioning();

	struct ultrawidelock_reader_identity id;
	struct ultrawidelock_trust_store ts;

	memcpy(id.reader_id, reader_id, ULTRAWIDELOCK_READER_ID_LEN);
	memcpy(id.sign_priv, sign_priv, ULTRAWIDELOCK_READER_PRIV_LEN);
	memcpy(id.grk, grk, ULTRAWIDELOCK_GRK_LEN);
	id.is_dev = false;

	store_lock();
	ultrawidelock_mutex_lock(&s_prov_lock);
	ts = s_trust; /* keep any anchors already added */

	int store_rc = ultrawidelock_prov_store(&id, &ts);

	if (store_rc != 0) {
		ultrawidelock_mutex_unlock(&s_prov_lock);
		store_unlock();
		return store_rc; /* not committed; s_id unchanged */
	}
	s_id = id;
	s_provisioning_state = PROVISIONING_READY;
	ultrawidelock_mutex_unlock(&s_prov_lock);
	store_unlock();
	compute_reader_group_x(); /* signingKey changed -> refresh salt field 1 */
	/*
	 * And the ADVERTISEMENT, which this path used to leave stale.
	 *
	 * The reader starts advertising long before SetAliroReaderConfig
	 * arrives -- Apple sends it as a post-commissioning operational command
	 * -- so at start the identity was the dev default with an all-zero GRK
	 * and the board could only advertise the bare 0xFFF2 UUID. The dynamic
	 * tag a phone resolves to approach the reader is derived from the GRK,
	 * so until this runs the reader is provisioned, trusted, reachable over
	 * Matter, and still invisible to a walk-up.
	 *
	 * The clone-import path has always done this and its comment claims
	 * "the Matter provisioning path calls this" -- it did not. Observed on
	 * hardware: a pairing that installed the identity and both credentials,
	 * a tile that worked, and zero credential sessions afterwards because every
	 * advert stayed on the commissionable branch. A REBOOT hid it, because
	 * the boot path applies the stored GRK before it ever advertises, which
	 * is why this survived every test that power-cycled after pairing.
	 */
	ultrawidelock_reader_refresh_adv();
	LOG_INF("Matter-provisioned reader identity stored");
	return 0;
}

// Read back the public half of the stored identity. See ultrawidelock_reader.h for why this exists
// and why verif_pub is derived rather than stored. No lock: s_id is written at boot and by the
// provisioning paths, which are the same single caller this shares a thread with, and s_trust --
// the thing s_prov_lock guards -- is not touched here.
int ultrawidelock_reader_identity_public(uint8_t reader_id[ULTRAWIDELOCK_READER_ID_LEN],
				 uint8_t verif_pub[ULTRAWIDELOCK_P256_POINT], uint8_t grk[ULTRAWIDELOCK_GRK_LEN])
{
	load_provisioning();

	/* The dev identity is a build-time placeholder every unit shares.
	 * Reporting it as this reader's configuration would tell a controller a
	 * provisioning had happened, and the null it replaces is true. */
	if (s_id.is_dev) {
		return -ENOENT;
	}
	if (ultrawidelock_ec_p256_pub_from_priv(s_id.sign_priv, verif_pub) != 0) {
		LOG_ERR("cannot derive the verification key from the stored signing key");
		return -EIO;
	}
	memcpy(reader_id, s_id.reader_id, ULTRAWIDELOCK_READER_ID_LEN);
	memcpy(grk, s_id.grk, ULTRAWIDELOCK_GRK_LEN);
	return 0;
}

// Add a Matter-provisioned credential public key to the reader's trust store, bind the Matter
// credential/user indices it was installed under, and persist it.
// Returns 0 if newly added and stored, 1 if the credential was already trusted (persisted only
// when its indices changed), -1 if cred_pub is not an uncompressed point, or the store's
// negative errno if the NVS write fails. A FULL store is not a failure: the oldest anchor
// that never completed a standard phase is evicted to make room, which is logged.
// On failure the in-memory trust store (s_trust) is left unchanged.
// The indices are what ClearCredential and ClearUser later name the anchor by; pass
// ULTRAWIDELOCK_CRED_INDEX_NONE for either one the caller does not have.
int ultrawidelock_reader_provision_add_trust(const uint8_t cred_pub[ULTRAWIDELOCK_CRED_PUB_LEN],
					     uint8_t cred_type, uint16_t cred_index,
					     uint16_t user_index)
{
	load_provisioning();

	struct ultrawidelock_reader_identity id;
	struct ultrawidelock_trust_store cand;

	store_lock();
	ultrawidelock_mutex_lock(&s_prov_lock);
	id = s_id;
	cand = s_trust;

	int add = ultrawidelock_prov_trust_add(&cand, cred_pub);

	if (add < 0) {
		ultrawidelock_mutex_unlock(&s_prov_lock);
		store_unlock();
		return -1; /* not an uncompressed point, or a corrupt count */
	}

	int slot = ultrawidelock_prov_trust_find(&cand, cred_pub);
	bool rebind = slot >= 0 &&
		      (cand.cred_type[slot] != cred_type || cand.cred_index[slot] != cred_index ||
		       cand.user_index[slot] != user_index);

	(void)ultrawidelock_prov_cred_bind_set(&cand, slot, cred_type, cred_index, user_index);
	if (add == 1 && !rebind) {
		ultrawidelock_mutex_unlock(&s_prov_lock);
		store_unlock();
		return 1; /* already trusted under this index; nothing to persist */
	}
	if (add == 1) {
		/* The key is old, its address is not. Apple re-installs a key it
		 * already sent under a fresh credential index when a user is
		 * re-added, and an anchor still carrying the previous index is
		 * one ClearCredential can no longer find. */
		int rebind_rc = ultrawidelock_prov_store(&id, &cand);

		if (rebind_rc != 0) {
			ultrawidelock_mutex_unlock(&s_prov_lock);
			store_unlock();
			return rebind_rc;
		}
		s_trust = cand;
		s_fast_mru = -1;
		ultrawidelock_mutex_unlock(&s_prov_lock);
		store_unlock();
		return 1;
	}
	int store_rc = ultrawidelock_prov_store(&id, &cand);

	if (store_rc != 0) {
		ultrawidelock_mutex_unlock(&s_prov_lock);
		store_unlock();
		return store_rc; /* not committed; s_trust unchanged */
	}
	s_trust = cand;
	s_fast_mru = -1;
	ultrawidelock_mutex_unlock(&s_prov_lock);
	store_unlock();
	if (add == 2) {
		LOG_WRN("trust store was FULL; dropped an anchor to make room. "
			"ULTRAWIDELOCK_TRUST_MAX is %u -- raise it if this repeats",
			ULTRAWIDELOCK_TRUST_MAX);
	}
	LOG_INF("Matter-provisioned trust anchor stored (%u total)", cand.count);
	return 0;
}

// Add a Matter-provisioned credential issuer public key (SetCredential type 6) and persist it;
// see ultrawidelock/reader.h. Same commit order as add_trust: written first, adopted second, so a
// key the store could not keep is not one the reader verifies documents against.
int ultrawidelock_reader_provision_add_issuer(const uint8_t pub[ULTRAWIDELOCK_CRED_PUB_LEN],
					      uint16_t cred_index, uint16_t user_index)
{
	load_provisioning();

	struct ultrawidelock_reader_identity id;
	struct ultrawidelock_trust_store cand;

	store_lock();
	ultrawidelock_mutex_lock(&s_prov_lock);
	id = s_id;
	cand = s_trust;

	int add = ultrawidelock_prov_issuer_add(&cand, pub, cred_index, user_index);

	if (add < 0) {
		ultrawidelock_mutex_unlock(&s_prov_lock);
		store_unlock();
		LOG_ERR("issuer key REFUSED: %s", pub[0] != 0x04u ? "bad point" : "store full");
		return -1;
	}
	if (add == 1 && memcmp(&cand, &s_trust, sizeof(cand)) == 0) {
		ultrawidelock_mutex_unlock(&s_prov_lock);
		store_unlock();
		return 1; /* already held under these indices; nothing to persist */
	}

	int store_rc = ultrawidelock_prov_store(&id, &cand);

	if (store_rc != 0) {
		ultrawidelock_mutex_unlock(&s_prov_lock);
		store_unlock();
		return store_rc; /* not committed; s_trust unchanged */
	}
	s_trust = cand;
	ultrawidelock_mutex_unlock(&s_prov_lock);
	store_unlock();
	LOG_INF("Matter-provisioned issuer key %s (%u total)", add == 1 ? "re-indexed" : "stored",
		cand.issuer_count);
	return add;
}

// Revoke the issuer a Matter admin installed as type-6 credential cred_index, together with
// every anchor the reader learned from a document it signed. Same fail-closed order as
// remove_trust: applied in RAM first, persisted second, the write retried later if it fails.
int ultrawidelock_reader_provision_remove_issuer(uint16_t cred_index)
{
	load_provisioning();

	struct ultrawidelock_reader_identity id;
	struct ultrawidelock_trust_store cand;
	int idx, dropped = 0;

	store_lock();
	ultrawidelock_mutex_lock(&s_prov_lock);
	idx = ultrawidelock_prov_issuer_find_index(&s_trust, cred_index);
	if (idx >= 0) {
		dropped = ultrawidelock_prov_issuer_remove_at(&s_trust, idx);
		id = s_id;
		cand = s_trust;
		s_fast_mru = -1;
	}
	if (idx < 0) {
		ultrawidelock_mutex_unlock(&s_prov_lock);
		int pending = flush_pending_store_locked();
		store_unlock();

		return pending != 0 ? pending : 1;
	}

	int rc = persist_removal_locked(&id, &cand);
	ultrawidelock_mutex_unlock(&s_prov_lock);
	store_unlock();

	/* NULL: the learned anchors went with it, so both latches go regardless. */
	revoke_aftermath(NULL);
	(void)dropped; /* host log stub compiles the formatted argument away */
	LOG_INF("issuer index %u REVOKED, %d learned anchor(s) with it (%u issuers, %u anchors left)",
		(unsigned int)cred_index, dropped, cand.issuer_count, cand.count);
	return rc;
}

// Revoke the trust anchor a Matter admin installed as (cred_type, cred_index). Both halves
// are matched, because a Matter credential index is scoped to its type.
// Returns 1 when no anchor carries that pair (a removal that already happened, or a
// pre-v4 anchor that never had one -- both are answered as success, since the credential
// the admin named is not trusted either way), 0 when the anchor is gone and the store is
// persisted, or the store's negative errno when it is gone from RAM but the write failed --
// including a write an EARLIER removal left pending, which this retries.
int ultrawidelock_reader_provision_remove_trust(uint8_t cred_type, uint16_t cred_index)
{
	load_provisioning();

	struct ultrawidelock_reader_identity id;
	struct ultrawidelock_trust_store cand;
	uint8_t removed[ULTRAWIDELOCK_CRED_PUB_LEN];
	int idx;

	/* Found, removed and snapshotted in one critical section. The add path
	 * mutates a snapshot and commits it later, which on a removal would let
	 * a SetCredential that landed in between put the revoked anchor back. */
	store_lock();
	ultrawidelock_mutex_lock(&s_prov_lock);
	idx = ultrawidelock_prov_find_cred_index(&s_trust, cred_type, cred_index);
	if (idx >= 0) {
		memcpy(removed, s_trust.cred_pub[idx], ULTRAWIDELOCK_CRED_PUB_LEN);
		(void)ultrawidelock_prov_trust_remove_at(&s_trust, idx);
		id = s_id;
		cand = s_trust;
		s_fast_mru = -1;
	}
	if (idx < 0) {
		/* Nothing to take out now, but an earlier removal may still be
		 * unwritten. This is the caller most likely to exist when there is
		 * no session to end: an admin repeating a command that reported a
		 * failure. Report the retry's failure rather than the emptiness. */
		ultrawidelock_mutex_unlock(&s_prov_lock);
		int pending = flush_pending_store_locked();
		store_unlock();

		return pending != 0 ? pending : 1;
	}

	int rc = persist_removal_locked(&id, &cand);
	ultrawidelock_mutex_unlock(&s_prov_lock);
	store_unlock();

	revoke_aftermath(removed);
	LOG_INF("credential type %u index %u REVOKED (%u anchor(s) left)", (unsigned int)cred_type,
		(unsigned int)cred_index, cand.count);
	return rc;
}

// Revoke every trust anchor of one Matter credential type, or every anchor there is when
// cred_type is 0. Backs ClearCredential's two wildcards: an index of 0xFFFE (all of that
// type) and an absent Credential field (all types, including anchors a bench command added
// -- those are not Matter credentials, but leaving them would leave the door open).
// Returns the number of anchors removed (0 is success: there were none), or the store's
// negative errno when they are gone from RAM but the write failed -- including a write an
// EARLIER removal left pending, which this retries.
int ultrawidelock_reader_provision_remove_type(uint8_t cred_type)
{
	load_provisioning();

	struct ultrawidelock_reader_identity id;
	struct ultrawidelock_trust_store cand;
	int removed = 0;

	store_lock();
	ultrawidelock_mutex_lock(&s_prov_lock);
	/* Issuers first: each takes the anchors it vouched for with it, which are
	 * counted as revoked too. Downwards, because removing slot i shifts every
	 * later slot into it. */
	if (cred_type == 0u || cred_type == ULTRAWIDELOCK_CRED_TYPE_ALIRO_ISSUER) {
		for (int i = (int)s_trust.issuer_count - 1; i >= 0; i--) {
			int dropped = ultrawidelock_prov_issuer_remove_at(&s_trust, i);

			removed += dropped > 0 ? dropped + 1 : 1;
		}
	}
	for (int i = (int)s_trust.count - 1; i >= 0; i--) {
		if (cred_type == 0u || s_trust.cred_type[i] == cred_type) {
			(void)ultrawidelock_prov_trust_remove_at(&s_trust, i);
			removed++;
		}
	}
	id = s_id;
	cand = s_trust;
	if (removed > 0) {
		s_fast_mru = -1;
	}
	if (removed == 0) {
		/* Same retry the single-anchor path takes: an admin repeating a
		 * wildcard clear is a chance to land a write left pending. */
		ultrawidelock_mutex_unlock(&s_prov_lock);
		int pending = flush_pending_store_locked();
		store_unlock();
		return pending;
	}

	int rc = persist_removal_locked(&id, &cand);
	ultrawidelock_mutex_unlock(&s_prov_lock);
	store_unlock();

	revoke_aftermath(NULL);
	LOG_INF("credential type %u REVOKED %d anchor(s) (%u left)", (unsigned int)cred_type,
		removed, cand.count);
	return rc == 0 ? removed : rc;
}

// Revoke every trust anchor a Matter admin bound to user index user_index, or all of them
// when user_index is ULTRAWIDELOCK_USER_INDEX_ALL.
// Returns the number of anchors removed (0 when the user held none, which is still success),
// or the store's negative errno when they are gone from RAM but the write failed -- including
// a write an EARLIER removal left pending, which this retries.
int ultrawidelock_reader_provision_remove_user(uint16_t user_index)
{
	load_provisioning();

	struct ultrawidelock_reader_identity id;
	struct ultrawidelock_trust_store cand;
	int removed = 0;

	store_lock();
	ultrawidelock_mutex_lock(&s_prov_lock);
	/* The user's issuer keys go first, each taking the anchors learned under
	 * it; then whatever the user held directly. Downwards, because removing
	 * slot i shifts every later slot into it. */
	for (int i = (int)s_trust.issuer_count - 1; i >= 0; i--) {
		if (user_index == ULTRAWIDELOCK_USER_INDEX_ALL ||
		    s_trust.issuer_user_index[i] == user_index) {
			int dropped = ultrawidelock_prov_issuer_remove_at(&s_trust, i);

			removed += dropped > 0 ? dropped + 1 : 1;
		}
	}
	for (int i = (int)s_trust.count - 1; i >= 0; i--) {
		if (user_index == ULTRAWIDELOCK_USER_INDEX_ALL || s_trust.user_index[i] == user_index) {
			(void)ultrawidelock_prov_trust_remove_at(&s_trust, i);
			removed++;
		}
	}
	id = s_id;
	cand = s_trust;
	if (removed > 0) {
		s_fast_mru = -1;
	}
	if (removed == 0) {
		/* The user held no anchor, so there is nothing new to write -- but
		 * an earlier removal may still owe one. */
		ultrawidelock_mutex_unlock(&s_prov_lock);
		int pending = flush_pending_store_locked();
		store_unlock();
		return pending;
	}

	int rc = persist_removal_locked(&id, &cand);
	ultrawidelock_mutex_unlock(&s_prov_lock);
	store_unlock();

	/* NULL: more than one key may have gone, so both latches go regardless. */
	revoke_aftermath(NULL);
	LOG_INF("user index %u REVOKED %d anchor(s) (%u left)", (unsigned int)user_index, removed,
		cand.count);
	return rc == 0 ? removed : rc;
}

// Revert the reader's provisioning to the default dev identity and empty trust store, and
// persist that state to NVS.
// Returns the store's negative errno if the NVS write fails, in which case in-memory state is
// unchanged; returns 0 on success, after which the reader group key salt is recomputed via
// compute_reader_group_x.
int ultrawidelock_reader_provision_clear(void)
{
	load_provisioning();

	struct ultrawidelock_reader_identity id;
	struct ultrawidelock_trust_store ts;

	ultrawidelock_prov_dev_default(&id, &ts);

	store_lock();
	ultrawidelock_mutex_lock(&s_prov_lock);
	int store_rc = ultrawidelock_prov_store(&id, &ts);

	if (store_rc != 0) {
		ultrawidelock_mutex_unlock(&s_prov_lock);
		store_unlock();
		return store_rc;
	}
	s_id = id;
	s_trust = ts;
	s_provisioning_state = PROVISIONING_EMPTY;
	s_fast_mru = -1;
	ultrawidelock_mutex_unlock(&s_prov_lock);
	store_unlock();
	compute_reader_group_x(); /* signingKey changed -> refresh salt field 1 */
	/* The store just lost every anchor, so the same latches and links a
	 * per-credential revocation drops have to go here too. */
	revoke_aftermath(NULL);
	LOG_INF("reader provisioning cleared (reverted to dev identity)");
	return 0;
}

/* ---- Identity clone (bench: replicate a reader onto a second board) ------ *
 * Serialise/adopt the full identity + trust store so a phone's existing Wallet
 * credential transacts with a second device carrying the same reader identity.
 *
 * export_blob emits sign_priv. These functions are NOT compile-gated; only the
 * console commands that reach them are, under CONFIG_ULTRAWIDELOCK_CRED_CLONE (off by
 * default). With that option off nothing in the tree calls them, so whether the
 * code reaches the image is left to --gc-sections rather than guaranteed. Treat
 * the option, not this file, as the control: a board built with it on will hand
 * the reader private key to anyone holding the USB cable. */

// Serialise the reader's current identity + trust store into a self-describing blob
// (ultrawidelock_prov_serialize format) so it can be loaded onto a second board. Snapshots
// the shared state under s_prov_lock, then serialises off the copy. Returns 0 and
// sets *out_len on success; -1 if the buffer is too small.
int ultrawidelock_reader_export_blob(uint8_t *out, size_t cap, size_t *out_len)
{
	load_provisioning();

	struct ultrawidelock_reader_identity id;
	struct ultrawidelock_trust_store ts;

	ultrawidelock_mutex_lock(&s_prov_lock);
	id = s_id;
	ts = s_trust;
	ultrawidelock_mutex_unlock(&s_prov_lock);

	return ultrawidelock_prov_serialize(&id, &ts, out, cap, out_len);
}

// Adopt an identity + trust store from a blob written by ultrawidelock_reader_export_blob
// (or ultrawidelock_prov_serialize): parse, persist to NVS, then commit in memory so the
// running reader uses it immediately. Persist happens before the in-memory commit,
// so a failed NVS write leaves the live identity unchanged. Returns 0 on success,
// -1 if the blob is malformed, -2 if the NVS write fails.
int ultrawidelock_reader_import_blob(const uint8_t *buf, size_t len)
{
	load_provisioning();

	struct ultrawidelock_reader_identity id;
	struct ultrawidelock_trust_store ts;

	if (ultrawidelock_prov_deserialize(buf, len, &id, &ts) != 0) {
		return -1;
	}
	store_lock();
	ultrawidelock_mutex_lock(&s_prov_lock);
	if (ultrawidelock_prov_store(&id, &ts) != 0) {
		ultrawidelock_mutex_unlock(&s_prov_lock);
		store_unlock();
		return -2; /* not committed; s_id/s_trust unchanged */
	}
	s_id = id;
	s_trust = ts;
	s_provisioning_state = id.is_dev ? PROVISIONING_EMPTY : PROVISIONING_READY;
	s_fast_mru = -1;
	ultrawidelock_mutex_unlock(&s_prov_lock);
	store_unlock();
	compute_reader_group_x(); /* signingKey/grk changed -> refresh salt field 1 */
	/* Same reason the Matter provisioning path calls this: a new GRK means the
	 * advertised dynamic tag is stale, and the phone resolves the reader by that
	 * tag. Without it an imported identity transacts but is never approached. */
	ultrawidelock_reader_refresh_adv();
	LOG_INF("reader identity imported from clone blob (%s, %u trust anchor(s))",
		id.is_dev ? "DEV" : "provisioned", ts.count);
	return 0;
}
