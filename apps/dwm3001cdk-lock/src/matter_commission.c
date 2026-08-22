/* SPDX-License-Identifier: ISC */

/**
 * @file matter_commission.c — joins BTP, the exchange and PASE.
 *
 * Three finished pieces and no protocol of its own:
 *
 *   matter_ble_zephyr.c   bytes in and out over the 0xFFF6 service
 *   matter_exchange.c     which session, which exchange, duplicate, ack
 *   matter_pase_sm.c      the five commissioning messages
 *
 * What is left for this file is the wiring nobody else can do: pulling the
 * SPAKE2+ verifier out of configuration, drawing real randomness, and deciding
 * what happens when a commissioner disappears halfway through.
 *
 * The Kconfig default verifier is CHIP's PUBLISHED test verifier for passcode
 * 20202021. A real deployment runs scripts/spake2p_verifier.py with its own
 * passcode.
 */
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/atomic.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* Unconditional: srp_sign_self_test() runs in every build of this file. */
#include <psa/crypto.h>

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_HEAP_PROBE)
#include <mbedtls/memory_buffer_alloc.h>
#endif

#include "ultrawidelock_hash.h" /* ultrawidelock_sha256, for the CASE transcript */
#include "ultrawidelock_ble.h" /* ultrawidelock_ble_readvertise, when a fabric arrives */
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_DFU_RECEIVER)
#include "ultrawidelock_dfu_rx.h" /* the same gesture opens the update window */
#endif
/* ULTRAWIDELOCK_TRUST_MAX, to hold the reported cap to the real one */
#include "ultrawidelock_prov.h"
/* ultrawidelock_reader_provision_identity, for SetAliroReaderConfig */
#include <ultrawidelock/reader.h>
#include "ultrawidelock_prim.h" /* ultrawidelock_random, the CSPRNG the reader already uses */
#include "ultrawidelock_port.h" /* ultrawidelock_uptime_ms, an event's SystemTimestamp */
#include <ultrawidelock_osal.h>
#include "matter_ble_zephyr.h"
#include "matter_attest.h"
#include "matter_case.h"
#include "matter_clusters.h"
/* AFTER matter_clusters.h, which is where MATTER_FEATURE_CLIENT is defaulted. */
#if MATTER_FEATURE_CLIENT
#include "matter_client.h"
#endif
#include "matter_commission.h"
#include "matter_exchange.h"
#include "matter_fab_settings.h" /* the fabric table, across a reboot */
#include "matter_im.h"
#include "matter_msg.h"
#include "matter_pase_sm.h"
#include "matter_thread.h"
#include "status_led.h" /* the lock LED; a tile tap has to move it too */

LOG_MODULE_DECLARE(matter_ble, CONFIG_ULTRAWIDELOCK_MATTER_BLE_LOG_LEVEL);

static struct matter_exchange s_exchange;
static struct matter_pase_responder s_pase;
static struct matter_pase_verifier s_verifier;
static bool s_verifier_ok;

/**
 * Set when the link dropped, cleared when the next message re-seeds.
 *
 * The reset is deferred rather than done in the Bluetooth callback because it
 * needs fresh randomness, and drawing entropy from a connection callback to
 * serve a session that may never arrive is work for nothing.
 */
static bool s_stale = true;

/**
 * What this node says it is, and the data model built over it.
 *
 * Sized in seconds and enum values rather than Kconfig strings because these
 * are what the commissioner reads back; see matter_clusters.h for each.
 */
static struct matter_device_info s_info = {
	.vendor_id = CONFIG_ULTRAWIDELOCK_MATTER_VENDOR_ID,
	.product_id = CONFIG_ULTRAWIDELOCK_MATTER_PRODUCT_ID,
	.breadcrumb = 0u,
	.regulatory_config = MATTER_REGULATORY_INDOOR,
	.location_capability = MATTER_REGULATORY_INDOOR,
	/* The fail-safe window a commissioner may arm, and the ceiling it may
	 * extend to. CHIP's own defaults; nothing here is slow enough to need
	 * more. */
	.failsafe_expiry_s = 60u,
	.failsafe_max_s = 900u,
	/*
	 * True keeps BLE up across the whole of commissioning. False would tell
	 * the commissioner to expect this node to leave BLE and reappear on its
	 * operational network -- which it cannot do, having no Thread or Wi-Fi
	 * yet, so false would promise a return that never happens.
	 */
	.supports_concurrent_connection = true,
	/* All three directions permitted, the default the CHIP builds declare;
	 * zero is a writable value so it cannot mean "never set". */
	.approach_direction = MATTER_APPROACH_DIRECTION_ALL,
};

/* Advertising and the main loop read these outside the Matter owner. Publish
 * only the two scalar predicates they need instead of exposing s_info or the
 * administrative state to a second lock owner. Static zero is the correct
 * pre-init state: no restored fabric yet and no open window. */
static atomic_t s_has_fabric_snapshot;
static atomic_t s_window_open_snapshot;

static void fabric_snapshot_refresh_owned(void)
{
	bool present = false;

	for (size_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if (s_info.fabrics[i].index != 0u) {
			present = true;
			break;
		}
	}
	atomic_set(&s_has_fabric_snapshot, present ? 1 : 0);
}
static struct matter_im_server s_im;

/**
 * Framed reply: both headers, the largest message, and the AEAD tag.
 *
 * Sized by the Interaction Model rather than PASE now, and by attestation
 * rather than by a read: an AttestationResponse carries a 539-byte
 * certification declaration plus a signature, where the largest PASE message is
 * 128 bytes. Encryption adds MATTER_TAG_LEN on top of the cleartext.
 */
/*
 * The largest IM payload that still fits one Thread datagram.
 *
 * MATTER_MAX_MESSAGE_LEN is the ceiling for the WHOLE message -- the 1280 byte
 * IPv6 MTU less the IPv6 and UDP headers -- so the exchange headers and the MIC
 * come out of it rather than being added to it. Spending it all on the payload
 * builds a datagram up to 52 bytes over the MTU, and an oversized datagram is
 * not slow, it is never delivered. Nothing is logged either, because the
 * framing itself succeeded, so the subscriber just re-subscribes forever.
 *
 * BLE hides the mistake: BTP re-fragments, so the same report crosses a
 * commissioning session intact and the subscription only dies once the node
 * moves to Thread -- which reads as "worked while pairing, then went away".
 */
#define MATTER_IM_PAYLOAD_MAX                                                                      \
	(MATTER_MAX_MESSAGE_LEN - MATTER_EXCHANGE_HEADER_MAX - MATTER_TAG_LEN)

/* Two packets, not a scratch output plus a scratch payload. Encoding starts at
 * MATTER_EXCHANGE_HEADER_MAX inside a reserved slot, then framing memmoves the
 * payload behind the actual headers and seals it in place. One BLE packet may
 * be in flight while one response is queued; a third is refused explicitly. */
#define MATTER_TX_SLOTS 2u
static uint8_t s_tx_backing[MATTER_TX_SLOTS][MATTER_MAX_MESSAGE_LEN];
static struct matter_tx_slot s_tx_slots[MATTER_TX_SLOTS];
static struct matter_tx_pool s_tx_pool;

enum tx_transport {
	TX_TRANSPORT_BLE = 1,
	TX_TRANSPORT_THREAD = 2,
};

enum tx_effect_kind {
	TX_EFFECT_NONE = 0,
	TX_EFFECT_READ,
	TX_EFFECT_SUB_PRIME,
	TX_EFFECT_SUB_RESPONSE,
};

struct tx_effect {
	enum tx_effect_kind kind;
	uint16_t session_id;
	uint16_t exchange_id;
	uint16_t emitted;
	uint32_t subscription_id;
	bool more;
	bool over_thread;
};

struct tx_thread_owner {
	uint16_t session_id;
	uint16_t exchange_id;
	uint32_t request_counter;
	bool retryable;
};

static struct tx_effect s_tx_effects[MATTER_TX_SLOTS];
static struct tx_thread_owner s_tx_thread_owner[MATTER_TX_SLOTS];
static uint32_t s_ble_tx_token;
static uint32_t s_thread_tx_token;
static ultrawidelock_mutex_t s_owner_lock;

static void tx_effect_finish(struct matter_tx_slot *slot, int status);
static int tx_ble_pump(void);
static uint16_t current_session_id(void);
static void tx_thread_reap_expired(uint32_t now_ms);
static void tx_thread_reap_schedule_owned(uint32_t now_ms);
static void tx_thread_reap_work_fn(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(s_thread_reap_work, tx_thread_reap_work_fn);

/*
 * The Thread transport's reply buffer is exactly this ceiling, and it is sized
 * in a header that cannot see the three terms above. Assert the identity here,
 * where all four are in scope: raising MATTER_MAX_MESSAGE_LEN or either header
 * without moving the buffer would silently reintroduce the framing that
 * send_framed() cannot copy out.
 */
BUILD_ASSERT(MATTER_THREAD_REPLY_MAX ==
		     MATTER_EXCHANGE_HEADER_MAX + MATTER_IM_PAYLOAD_MAX + MATTER_TAG_LEN,
	     "the Thread reply buffer must hold exactly one full-size Matter message");

/*
 * The two seams matter_attest.h declares. Kept here rather than in the module
 * so ultrawidelock_matter stays free of any particular crypto backend; on this board both
 * are the reader's existing PSA-backed primitives.
 */
int matter_attest_ecdsa_sign(const uint8_t priv[32], const uint8_t *msg, size_t msg_len,
			     uint8_t sig[MATTER_ATTEST_SIG_LEN])
{
	return ultrawidelock_ecdsa_p256_sign(priv, msg, msg_len, sig);
}

/**
 * Generate a P-256 keypair for Matter attestation. Fills priv with the 32-byte private key and pub
 * with the 65-byte uncompressed public key. Returns 0 on success.
 */
int matter_attest_ec_keygen(uint8_t priv[32], uint8_t pub[65])
{
	return ultrawidelock_ec_p256_keygen(priv, pub);
}

/*
 * The two matter_case.h declares. ECDH yields the X coordinate only, which is
 * what the spec means by the shared secret -- the Y coordinate carries no
 * additional entropy and including it would give a secret neither peer agrees
 * on.
 */
int matter_case_ecdh(const uint8_t priv[32], const uint8_t peer_pub[MATTER_CASE_PUBKEY_LEN],
		     uint8_t secret_out[MATTER_CASE_SECRET_LEN])
{
	return ultrawidelock_ecdh_p256(priv, peer_pub, secret_out);
}

/**
 * Sign a message with a P-256 private key. Fills sig with the MATTER_CASE_SIG_LEN-byte signature.
 * Returns 0 on success.
 */
int matter_case_sign(const uint8_t priv[32], const uint8_t *msg, size_t msg_len,
		     uint8_t sig[MATTER_CASE_SIG_LEN])
{
	return ultrawidelock_ecdsa_p256_sign(priv, msg, msg_len, sig);
}

/**
 * Verify a message signature with a P-256 public key. The public key is MATTER_CASE_PUBKEY_LEN
 * bytes, the signature is MATTER_CASE_SIG_LEN bytes. Returns 0 if the signature is valid.
 */
int matter_case_verify(const uint8_t pub[MATTER_CASE_PUBKEY_LEN], const uint8_t *msg,
		       size_t msg_len, const uint8_t sig[MATTER_CASE_SIG_LEN])
{
	return ultrawidelock_ecdsa_p256_verify(pub, msg, msg_len, sig);
}

/*
 * NIST CAVP SP 800-56A ECC CDH P-256, COUNT 0.
 *
 * VERIFIED BEFORE USE, not trusted: both points were checked to satisfy
 * y^2 = x^3 - 3x + b, the private key to produce its own published public key
 * under scalar multiplication, and d*Q to reproduce Z. That check exists
 * because two vectors offered for this job turned out to have public keys that
 * were not on the curve at all -- and ultrawidelock_ecdh_p256() would have correctly
 * rejected them, which reads exactly like the bug being hunted.
 */
static const uint8_t k_kat_priv[] = {
	0x7D, 0x7D, 0xC5, 0xF7, 0x1E, 0xB2, 0x9D, 0xDA, 0xF8, 0x0D, 0x62,
	0x14, 0x63, 0x2E, 0xEA, 0xE0, 0x3D, 0x90, 0x58, 0xAF, 0x1F, 0xB6,
	0xD2, 0x2E, 0xD8, 0x0B, 0xAD, 0xB6, 0x2B, 0xC1, 0xA5, 0x34,
};
static const uint8_t k_kat_peer[] = {
	0x04, 0x70, 0x0C, 0x48, 0xF7, 0x7F, 0x56, 0x58, 0x4C, 0x5C, 0xC6, 0x32, 0xCA,
	0x65, 0x64, 0x0D, 0xB9, 0x1B, 0x6B, 0xAC, 0xCE, 0x3A, 0x4D, 0xF6, 0xB4, 0x2C,
	0xE7, 0xCC, 0x83, 0x88, 0x33, 0xD2, 0x87, 0xDB, 0x71, 0xE5, 0x09, 0xE3, 0xFD,
	0x9B, 0x06, 0x0D, 0xDB, 0x20, 0xBA, 0x5C, 0x51, 0xDC, 0xC5, 0x94, 0x8D, 0x46,
	0xFB, 0xF6, 0x40, 0xDF, 0xE0, 0x44, 0x17, 0x82, 0xCA, 0xB8, 0x5F, 0xA4, 0xAC,
};
static const uint8_t k_kat_z[] = {
	0x46, 0xFC, 0x62, 0x10, 0x64, 0x20, 0xFF, 0x01, 0x2E, 0x54, 0xA4,
	0x34, 0xFB, 0xDD, 0x2D, 0x25, 0xCC, 0xC5, 0x85, 0x20, 0x60, 0x56,
	0x1E, 0x68, 0x04, 0x0D, 0xD7, 0x77, 0x89, 0x97, 0xBD, 0x7B,
};
/**
 * Prove the ECDH primitive against a published answer, once, at boot.
 *
 * The shared secret is the only input to CASE that neither peer can check
 * alone: get it wrong and the other side simply cannot decrypt, with nothing
 * on the wire to say so. This is the one place it can be pinned to something
 * external.
 */
static void ecdh_known_answer_test(void)
{
	uint8_t z[32];

	if (ultrawidelock_ecdh_p256(k_kat_priv, k_kat_peer, z) != 0) {
		LOG_ERR("ECDH self-test: primitive REFUSED the NIST vector");
		return;
	}
	if (memcmp(z, k_kat_z, sizeof(z)) == 0) {
		LOG_INF("ECDH self-test: PASS (NIST CAVP P-256 CDH count 0)");
		return;
	}
	/* Byte-reversal is the classic failure of a hardware accelerator fed
	 * the wrong way round, and worth naming rather than leaving as "wrong". */
	{
		uint8_t rev[32];
		size_t i;

		for (i = 0u; i < sizeof(rev); i++) {
			rev[i] = z[sizeof(rev) - 1u - i];
		}
		LOG_ERR("ECDH self-test: FAIL%s", memcmp(rev, k_kat_z, sizeof(rev)) == 0
							  ? " -- output is BYTE-REVERSED"
							  : "");
	}
	LOG_HEXDUMP_ERR(z, sizeof(z), "got");
}

/**
 * The PSA sequence OpenThread runs to sign an SRP update, with the status kept.
 *
 * WHY THIS EXISTS. An SRP registration that fails before the message reaches
 * the wire reports exactly one thing: "Failed to send update: Failed". That is
 * kErrorFailed, and zephyr/modules/openthread/platform/crypto_psa.c:22-34 maps
 * EVERY psa_status_t onto it except INVALID_ARGUMENT and BUFFER_TOO_SMALL -- so
 * INSUFFICIENT_MEMORY, NOT_SUPPORTED, STORAGE_FAILURE and DOES_NOT_EXIST are
 * one indistinguishable value by the time any log sees them. The number the
 * mapping throws away is the whole diagnosis, and this is the only way to read
 * it without editing fetched upstream.
 *
 * DETERMINISTIC ECDSA, not randomized, because that is what
 * otPlatCryptoEcdsaGenerateKey and otPlatCryptoEcdsaSign both ask for
 * (crypto_psa.c:432 and :465). It is also the one algorithm in this image that
 * nothing else exercises: PASE and CASE both sign with PSA_ALG_ECDSA, which is
 * why a board can finish a full commissioning handshake and still be unable to
 * sign an SRP update.
 *
 * The key is generated and thrown away. Nothing here touches the node's own
 * SRP key, so running it costs one keypair and changes no stored state.
 */
static void srp_sign_self_test(void)
{
	const psa_algorithm_t alg = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256);
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key = 0;
	psa_status_t st;
	/* PSA exports an ECC key pair as the raw scalar, 32 B for P-256.
	 * Oversized on purpose: a driver that returns DER instead must fail as
	 * BUFFER_TOO_SMALL rather than silently truncating into the stack. */
	uint8_t priv[96];
	size_t priv_len = 0u;
	uint8_t hash[32] = { 0 };
	uint8_t sig[64];
	size_t sig_len = 0u;

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&attr, alg);
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);

	st = psa_generate_key(&attr, &key);
	if (st != PSA_SUCCESS) {
		LOG_ERR("SRP sign self-test: generate FAILED, psa_status=%d", (int)st);
		return;
	}
	st = psa_export_key(key, priv, sizeof(priv), &priv_len);
	(void)psa_destroy_key(key);
	if (st != PSA_SUCCESS) {
		LOG_ERR("SRP sign self-test: export FAILED, psa_status=%d", (int)st);
		return;
	}

	/* Re-imported rather than signed with the handle above, because that is
	 * what OpenThread does: it keeps the exported bytes and imports them
	 * again on every single update (crypto_psa.c:469). */
	psa_reset_key_attributes(&attr);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_algorithm(&attr, alg);
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);

	key = 0;
	st = psa_import_key(&attr, priv, priv_len, &key);
	if (st != PSA_SUCCESS) {
		LOG_ERR("SRP sign self-test: import FAILED, psa_status=%d (exported %u B)",
			(int)st, (unsigned int)priv_len);
		return;
	}
	st = psa_sign_hash(key, alg, hash, sizeof(hash), sig, sizeof(sig), &sig_len);
	(void)psa_destroy_key(key);
	if (st != PSA_SUCCESS) {
		LOG_ERR("SRP sign self-test: sign FAILED, psa_status=%d", (int)st);
		return;
	}
	LOG_INF("SRP sign self-test: volatile PASS (exported %u B, signature %u B)",
		(unsigned int)priv_len, (unsigned int)sig_len);

	/*
	 * The half that matters, and the reason the volatile half above is not
	 * enough. This build has OPENTHREAD_CONFIG_PLATFORM_KEY_REFERENCES_ENABLE=1
	 * (read out of build/<dir>/dwm3001cdk-lock/build.ninja, not assumed), so
	 * Client::ReadOrGenerateKey takes the key-reference branch at
	 * srp_client.cpp:1144 and Generate() lands on
	 * otPlatCryptoEcdsaGenerateAndImportKey, which sets
	 * PSA_KEY_LIFETIME_PERSISTENT (crypto_psa.c:591).
	 *
	 * A persistent key is a completely different set of moving parts: the
	 * material goes through TRUSTED_STORAGE, is sealed with
	 * ChaCha20-Poly1305, and lands in NVS in the 16 KB settings partition.
	 * None of that is touched by a volatile key, so a volatile-only test
	 * passes while the real path fails -- which is worse than no test,
	 * because it reads like an all-clear.
	 *
	 * 0x2F000 is clear of OpenThread's own refs: those are
	 * OPENTHREAD_CONFIG_PSA_ITS_NVM_OFFSET (0x20000) + 1..7
	 * (crypto/storage.hpp:102-108, srp_client.hpp:813).
	 *
	 * Destroyed at both ends. Destroying first stops a slot surviving from
	 * an earlier boot and returning ALREADY_EXISTS, which would report a
	 * storage fault that is really just this test's own litter; destroying
	 * after is what keeps it from leaking an ITS entry per boot into a
	 * partition this small.
	 */
	{
		const psa_key_id_t probe_id = 0x2F000;
		psa_key_id_t pkey = 0;
		uint8_t pub[65];
		size_t pub_len = 0u;

		(void)psa_destroy_key(probe_id);

		psa_reset_key_attributes(&attr);
		psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_PERSISTENT);
		psa_set_key_id(&attr, probe_id);
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT);
		psa_set_key_algorithm(&attr, alg);
		psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(&attr, 256);

		st = psa_generate_key(&attr, &pkey);
		if (st != PSA_SUCCESS) {
			LOG_ERR("SRP sign self-test: PERSISTENT generate FAILED, psa_status=%d",
				(int)st);
			return;
		}
		/* srp_client.cpp:1176 calls this on the stored key, and it fails
		 * into the same one error value as everything else here. */
		st = psa_export_public_key(pkey, pub, sizeof(pub), &pub_len);
		if (st != PSA_SUCCESS) {
			LOG_ERR("SRP sign self-test: PERSISTENT pubkey FAILED, psa_status=%d",
				(int)st);
			(void)psa_destroy_key(pkey);
			return;
		}
		st = psa_sign_hash(pkey, alg, hash, sizeof(hash), sig, sizeof(sig), &sig_len);
		if (st != PSA_SUCCESS) {
			LOG_ERR("SRP sign self-test: PERSISTENT sign FAILED, psa_status=%d",
				(int)st);
			(void)psa_destroy_key(pkey);
			return;
		}
		st = psa_destroy_key(pkey);
		LOG_INF("SRP sign self-test: PERSISTENT PASS (pubkey %u B, signature %u B, "
			"destroy psa_status=%d)",
			(unsigned int)pub_len, (unsigned int)sig_len, (int)st);
	}
}

/** @return 0 and the byte count, or -EINVAL on any non-hex or odd-length input. */
static int unhex(const char *s, uint8_t *out, size_t cap, size_t *len)
{
	size_t n = strlen(s);
	size_t i;

	if ((n % 2u) != 0u || (n / 2u) > cap) {
		return -EINVAL;
	}
	for (i = 0; i < n; i += 2u) {
		unsigned int hi, lo;

		if (!isxdigit((int)s[i]) || !isxdigit((int)s[i + 1u])) {
			return -EINVAL;
		}
		hi = (unsigned int)((s[i] > '9') ? ((s[i] | 0x20) - 'a' + 10) : (s[i] - '0'));
		lo = (unsigned int)((s[i + 1u] > '9') ? ((s[i + 1u] | 0x20) - 'a' + 10)
						      : (s[i + 1u] - '0'));
		out[i / 2u] = (uint8_t)((hi << 4) | lo);
	}
	*len = n / 2u;
	return 0;
}

/**
 * Read the verifier out of Kconfig.
 *
 * A verifier and the parameters that produced it have to agree, and nothing on
 * this device can check that they do -- a mismatched pair fails at Pake3 with
 * cA wrong and no way to tell that apart from a wrong passcode. So this checks
 * the shapes it can and says so loudly when they are wrong, which is the only
 * warning anyone gets.
 */
static int load_verifier(void)
{
	uint8_t blob[MATTER_SPAKE_SCALAR_LEN + MATTER_SPAKE_POINT_LEN];
	size_t blob_len = 0u;
	size_t salt_len = 0u;

	if (unhex(CONFIG_ULTRAWIDELOCK_MATTER_SPAKE2P_VERIFIER, blob, sizeof(blob), &blob_len) != 0) {
		LOG_ERR("SPAKE2P verifier is not %u bytes of hex", (unsigned int)sizeof(blob));
		return -EINVAL;
	}
	if (blob_len != sizeof(blob)) {
		LOG_ERR("SPAKE2P verifier is %u bytes, expected %u", (unsigned int)blob_len,
			(unsigned int)sizeof(blob));
		return -EINVAL;
	}
	/* L must be an uncompressed point. Cheap, and it catches a verifier
	 * pasted in the wrong order -- w0 and L swapped would otherwise only
	 * show up as an unexplainable commissioning failure. */
	if (blob[MATTER_SPAKE_SCALAR_LEN] != 0x04u) {
		LOG_ERR("SPAKE2P verifier: L does not start 0x04; w0 and L swapped?");
		return -EINVAL;
	}

	if (unhex(CONFIG_ULTRAWIDELOCK_MATTER_SPAKE2P_SALT, s_verifier.salt, sizeof(s_verifier.salt),
		  &salt_len) != 0) {
		LOG_ERR("SPAKE2P salt is not valid hex, or longer than %u bytes",
			(unsigned int)sizeof(s_verifier.salt));
		return -EINVAL;
	}

	memcpy(s_verifier.w0, blob, MATTER_SPAKE_SCALAR_LEN);
	memcpy(s_verifier.l, blob + MATTER_SPAKE_SCALAR_LEN, MATTER_SPAKE_POINT_LEN);
	s_verifier.salt_len = (uint8_t)salt_len;
	s_verifier.iterations = CONFIG_ULTRAWIDELOCK_MATTER_SPAKE2P_ITERATIONS;

	return 0;
}

/* ---- AdministratorCommissioning (0x003C) ---------------------------------- */
/*
 * What Apple Home's "Turn On Pairing Mode" reaches. The cluster decodes; this
 * is everything with a side effect, because modules/ultrawidelock_matter is compiled by
 * the host suite without Zephyr and must not learn about Bluetooth.
 *
 * The commissioner supplies its OWN verifier, so the ecosystem being invited in
 * never learns this board's factory setup code. That is the whole point of the
 * enhanced form, and it is why the factory verifier is SAVED and restored: lose
 * it and the printed setup code stops working permanently.
 */
static struct matter_pase_verifier s_factory_verifier;
static uint8_t s_admin_window = MATTER_ADMIN_WINDOW_NOT_OPEN;
static uint8_t s_admin_fabric;
static uint16_t s_admin_vendor;

/**
 * Close the Matter commissioning window if open. Reset the verifier to the factory default, clear
 * the window state, fabric index, and vendor code, set the BLE discriminator to 0, re-advertise,
 * and log the closure. If the window is not open, return silently.
 */
static void admin_close(void)
{
	if (s_admin_window == MATTER_ADMIN_WINDOW_NOT_OPEN) {
		return;
	}
	s_verifier = s_factory_verifier;
	s_admin_window = MATTER_ADMIN_WINDOW_NOT_OPEN;
	atomic_set(&s_window_open_snapshot, 0);
	s_admin_fabric = 0u;
	s_admin_vendor = 0u;
	matter_ble_set_discriminator(0u);
	ultrawidelock_ble_readvertise();
	/* Withdraw the DNS-SD invitation with the same gesture that stops the BLE
	 * one. Left up, it advertises a window this node will now refuse. */
	(void)matter_thread_unadvertise_commissionable();
	LOG_INF("commissioning window closed; factory setup code back in force");
}

/**
 * Work callback that closes the Matter commissioning window when the timeout expires.
 */
static void admin_expire(struct k_work *work)
{
	ARG_UNUSED(work);
	ultrawidelock_mutex_lock(&s_owner_lock);
	admin_close();
	ultrawidelock_mutex_unlock(&s_owner_lock);
}
static K_WORK_DELAYABLE_DEFINE(s_admin_timer, admin_expire);

/**
 * Open the Matter commissioning window for the specified kind (basic or enhanced) and timeout in
 * seconds. Set the administrative window state, reschedule the admin timer, re-advertise on BLE,
 * and if CONFIG_ULTRAWIDELOCK_DFU_RECEIVER is enabled, open the DFU update window for the same
 * timeout (converted to milliseconds). Log the window opening.
 */
static void admin_arm(uint16_t timeout_s, uint8_t kind)
{
	s_admin_window = kind;
	atomic_set(&s_window_open_snapshot, 1);
	(void)k_work_reschedule(&s_admin_timer, K_SECONDS(timeout_s));
	ultrawidelock_ble_readvertise();
	/*
	 * The BLE advert above is what Apple Home looks for. Every other
	 * controller browses DNS-SD for "_matterc._udp,_S<short-discriminator>"
	 * and gives up when nothing answers -- which is why a second
	 * administrator could not be added from anything but an Apple device
	 * until this line existed. Same discriminator as the BLE advert, because
	 * a controller that finds one and falls back to the other matches on it.
	 */
	uint16_t discriminator = matter_ble_discriminator();

	(void)matter_thread_advertise_commissionable(discriminator, MATTER_OPERATIONAL_PORT);
	/* Bench builds only, and deliberately here: the dataset is wanted exactly
	 * when a window is open, and tying the disclosure to that keeps it to a
	 * gesture the owner just made rather than every boot. */
	matter_thread_dump_active_dataset();
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_DFU_RECEIVER)
	/* The same gesture opens the update window. This is what the SW2 press
	 * stands in for: an owner who can re-pair the lock is the owner who may
	 * re-flash it, and both are deliberate acts with a visible prompt. */
	ultrawidelock_dfu_window_open((uint32_t)timeout_s * 1000u);
#endif
	LOG_INF("commissioning window open for %u s (kind %u)", (unsigned)timeout_s,
		(unsigned)kind);
}

/**
 * Open the Matter commissioning window with an enhanced PAKE verifier, new discriminator, and the
 * specified timeout in seconds. Validates verifier length, point format (0x04 prefix), salt length,
 * and iterations; returns MATTER_ADMIN_STATUS_PAKE_PARAM_ERROR if any are invalid. Returns
 * MATTER_ADMIN_STATUS_BUSY if a window is already open, otherwise returns 0u.
 */
static uint8_t admin_open_enhanced(uint16_t timeout_s, const uint8_t *verifier,
				   uint32_t verifier_len, uint16_t discriminator,
				   uint32_t iterations, const uint8_t *salt, uint32_t salt_len)
{
	if (s_admin_window != MATTER_ADMIN_WINDOW_NOT_OPEN) {
		return MATTER_ADMIN_STATUS_BUSY;
	}
	if (verifier == NULL || salt == NULL || iterations == 0u ||
	    verifier_len != MATTER_SPAKE_SCALAR_LEN + MATTER_SPAKE_POINT_LEN ||
	    salt_len == 0u || salt_len > sizeof(s_verifier.salt) ||
	    verifier[MATTER_SPAKE_SCALAR_LEN] != 0x04u) {
		LOG_WRN("OpenCommissioningWindow: bad PAKE parameters");
		return MATTER_ADMIN_STATUS_PAKE_PARAM_ERROR;
	}

	s_factory_verifier = s_verifier;
	memcpy(s_verifier.w0, verifier, MATTER_SPAKE_SCALAR_LEN);
	memcpy(s_verifier.l, verifier + MATTER_SPAKE_SCALAR_LEN, MATTER_SPAKE_POINT_LEN);
	memcpy(s_verifier.salt, salt, salt_len);
	s_verifier.salt_len = (uint8_t)salt_len;
	s_verifier.iterations = iterations;

	/* The ecosystem being invited in SCANS for the discriminator its
	 * controller chose, so advertising the factory one would hide this node
	 * from exactly the peer the window was opened for. */
	matter_ble_set_discriminator(discriminator);

	admin_arm(timeout_s, MATTER_ADMIN_WINDOW_ENHANCED);
	return 0u;
}

/**
 * Open the Matter commissioning window with the factory PAKE verifier and the specified timeout in
 * seconds. Returns MATTER_ADMIN_STATUS_BUSY if a window is already open, otherwise returns 0u.
 */
static uint8_t admin_open_basic(uint16_t timeout_s)
{
	if (s_admin_window != MATTER_ADMIN_WINDOW_NOT_OPEN) {
		return MATTER_ADMIN_STATUS_BUSY;
	}
	/* Basic reuses the factory verifier, so nothing is swapped and nothing
	 * has to be restored. */
	s_factory_verifier = s_verifier;
	admin_arm(timeout_s, MATTER_ADMIN_WINDOW_BASIC);
	return 0u;
}

/**
 * Close the Matter commissioning window if one is open. Returns MATTER_ADMIN_STATUS_WINDOW_NOT_OPEN
 * if already closed, otherwise returns 0u.
 */
static uint8_t admin_revoke(void)
{
	if (s_admin_window == MATTER_ADMIN_WINDOW_NOT_OPEN) {
		return MATTER_ADMIN_STATUS_WINDOW_NOT_OPEN;
	}
	(void)k_work_cancel_delayable(&s_admin_timer);
	admin_close();
	return 0u;
}

/**
 * Return the administrative window state: one of the MATTER_ADMIN_WINDOW_* constants.
 */
static uint8_t admin_status(void)
{
	return s_admin_window;
}

bool matter_commission_window_open(void)
{
	return atomic_get(&s_window_open_snapshot) != 0;
}

/**
 * Return the fabric index of the peer commissioning the lock, or 0 if no commissioning is in
 * progress.
 */
static uint8_t admin_fabric(void)
{
	return s_admin_fabric;
}

/**
 * Return the vendor code offered by the peer during commissioning, or 0 if no commissioning is in
 * progress.
 */
static uint16_t admin_vendor(void)
{
	return s_admin_vendor;
}

static const struct matter_admin_hooks k_admin_hooks = {
	.open_enhanced = admin_open_enhanced,
	.open_basic = admin_open_basic,
	.revoke = admin_revoke,
	.status = admin_status,
	.admin_fabric = admin_fabric,
	.admin_vendor = admin_vendor,
};

/**
 * True while a message that arrived over Thread is being answered on the PASE
 * exchange rather than a CASE one.
 *
 * Declared up here, away from the s_thread_reply block it belongs with, because
 * begin_session() below needs it to choose MRP and C requires the declaration
 * first. See send_framed() for what it selects and why s_thread_reply alone
 * could not answer both questions.
 */
static bool s_thread_pase;

/** Fresh randomness for one commissioning attempt. */
static int begin_session(void)
{
	uint8_t responder_random[MATTER_PASE_RANDOM_LEN];
	uint8_t y_entropy[MATTER_PASE_Y_ENTROPY_LEN];
	uint8_t seed[sizeof(uint32_t) + sizeof(uint16_t)];
	uint32_t counter_seed;
	uint16_t session_id;
	int rc;

	/*
	 * A new commissioner supersedes an unfinished fail-safe transaction.
	 * Withdraw only the SRP names created by that transaction, then let the
	 * cluster layer wipe only those fabric slots. Existing completed fabrics
	 * remain registered and usable while a newcomer retries.
	 *
	 * Removal is asynchronous. matter_thread_unadvertise() keeps each service
	 * object retired until OpenThread returns it through the callback, and a
	 * replacement name uses another free slot or waits in the desired table.
	 */
	if (s_info.attempt.active) {
		LOG_INF("new commissioner; rolling back the abandoned attempt");
	}
	fabric_snapshot_refresh_owned();

	if (ultrawidelock_random(responder_random, sizeof(responder_random)) != 0 ||
	    ultrawidelock_random(y_entropy, sizeof(y_entropy)) != 0 ||
	    ultrawidelock_random(seed, sizeof(seed)) != 0) {
		LOG_ERR("CSPRNG failed; refusing to start PASE");
		return -EIO;
	}
	memcpy(&counter_seed, seed, sizeof(counter_seed));
	memcpy(&session_id, seed + sizeof(counter_seed), sizeof(session_id));
	/* Session id 0 is the unsecured session by definition, so it can never
	 * name the secure one PASE is about to create. */
	if (session_id == 0u) {
		session_id = 1u;
	}

	/*
	 * MRP is a property of the transport, not a preference
	 * (matter_exchange.h:233). Off for BTP, which is already reliable;
	 * REQUIRED over UDP, which is not. This read false unconditionally while
	 * PASE only ever ran over BLE, and hardcoding it would now be a silent
	 * half-fix: the handshake would answer once, never acknowledge anything,
	 * and a commissioner retransmitting on its 382 ms timer would get a
	 * duplicate reply per retry until it gave up.
	 *
	 * s_thread_pase is set by the only caller before it reaches on_message(),
	 * so it names the transport this session is being built for.
	 */
	matter_exchange_init(&s_exchange, counter_seed, s_thread_pase);
	rc = matter_pase_responder_init(&s_pase, &s_verifier, session_id, responder_random,
					y_entropy);
	if (rc != MATTER_OK) {
		LOG_ERR("PASE responder init rc=%d (verifier parameters out of range?)", rc);
		return -EINVAL;
	}

	s_stale = false;
	return 0;
}

/**
 * The operational session, once CASE has established one.
 *
 * Separate from s_exchange, which belongs to BLE: the two have different keys
 * and different counter spaces, and Apple keeps BLE open across the handover --
 * so both can be live at once and neither may borrow the other's counter.
 */
/**
 * How many CASE sessions this node holds at once.
 *
 * Was three, the CapabilityMinima floor matter_clusters.h reports. Holding ONE
 * while claiming three is what made a real pairing fail: Apple opens a session
 * for the phone on fabric 1 and a second for the home hub on fabric 2, and the
 * second overwrote the first. Every fabric-1 message after that was refused as
 * "not ours", taking the subscription with it, and the accessory hung on
 * "Adding to Home" until it was removed.
 *
 * Three was still too few. A home with an iPhone, a HomePod and an Apple TV
 * puts every one of them on both fabrics, so on 2026-08-02 the eviction warning
 * preceded EVERY establishment and the node opened nine sessions in five
 * minutes -- each eviction silencing a controller that reconnected at once.
 * The floor is what a node must support, not what a home will ask for.
 */
#define MATTER_CASE_SESSIONS 6u

static struct matter_exchange s_case_x[MATTER_CASE_SESSIONS];
static bool s_case_ready[MATTER_CASE_SESSIONS];
/**
 * The fabric each live session belongs to.
 *
 * Kept per SLOT rather than read from s_case, which holds the last
 * HANDSHAKE and says nothing about a session established before it. This is
 * what CurrentFabricIndex is answered from, and answering it for the wrong
 * fabric tells a controller it is not on the fabric it just joined.
 */
static uint8_t s_case_fabric[MATTER_CASE_SESSIONS];
static uint32_t s_case_cats[MATTER_CASE_SESSIONS][MATTER_CASE_CAT_MAX];
static size_t s_case_cat_count[MATTER_CASE_SESSIONS];
/**
 * The slot serving the datagram in flight. Valid only while s_thread_reply is
 * set, which is the whole time a reply can be built.
 *
 * A reply has to be sealed with the keys of the session its request arrived on.
 * Picking the wrong slot produces a byte-perfect message the peer cannot open
 * and cannot report -- the same shape as every other bug in this file.
 */
static uint8_t s_case_cur;
/** Round-robin victim, used only when every slot is live. */
static uint8_t s_case_next_victim;

/**
 * Release the subscription a dying session held. Defined with the subscription
 * table below; declared here because eviction is what makes it necessary.
 */
static void sub_drop_session(uint16_t session_id);
static void read_drop_session(uint16_t session_id, bool over_thread);

/** The slot holding @p session_id, or MATTER_CASE_SESSIONS if none does. */
static uint8_t case_slot_of(uint16_t session_id)
{
	uint8_t i;

	for (i = 0u; i < MATTER_CASE_SESSIONS; i++) {
		if (s_case_ready[i] && s_case_x[i].local_session_id == session_id) {
			return i;
		}
	}
	return MATTER_CASE_SESSIONS;
}

/**
 * A slot for a newly established session: a free one, else the round-robin
 * victim.
 *
 * Evicting is a real loss -- whoever held that session goes silent with no way
 * to be told -- so it happens only once there are more administrators than
 * slots, and it is logged.
 */
static uint8_t case_alloc_slot(void)
{
	uint8_t i;

	for (i = 0u; i < MATTER_CASE_SESSIONS; i++) {
		if (!s_case_ready[i]) {
			return i;
		}
	}
	i = s_case_next_victim;
	s_case_next_victim = (uint8_t)((s_case_next_victim + 1u) % MATTER_CASE_SESSIONS);
	LOG_WRN("  all %u CASE slots live; evicting session 0x%04x", MATTER_CASE_SESSIONS,
		(unsigned int)s_case_x[i].local_session_id);
	/* Whatever that session was subscribed to dies with it. Leaving the
	 * subscription behind would hold a slot for a peer that can no longer be
	 * reached, and answer its StatusResponses to a session that is gone. */
	sub_drop_session(s_case_x[i].local_session_id);
	read_drop_session(s_case_x[i].local_session_id, true);
	return i;
}

/**
 * Where a reply goes when the request arrived over Thread rather than BLE.
 *
 * The two transports answer in opposite directions: matter_ble_send() pushes,
 * while the Thread port sends whatever matter_thread_on_datagram() RETURNS. So
 * a CASE reply has to travel back up the call stack instead of out, and the
 * handlers in between -- on_read_request, on_invoke_request -- have no business
 * knowing which of the two they are serving. Non-NULL means "stage it here".
 */
static uint8_t *s_thread_reply;
static size_t s_thread_reply_cap;
static size_t s_thread_reply_len;

/*
 * s_thread_pase (declared above begin_session, which needs it too) is the
 * second half of this seam. s_thread_reply alone used to answer two questions
 * at once -- where the bytes go, and which exchange frames them -- because the
 * two always agreed: Thread meant CASE, BLE meant PASE. PASE over IP breaks
 * that pairing. Without the flag, a PASE reply would be framed on a CASE
 * exchange that has no session, and the commissioner would get a correctly
 * staged datagram it cannot parse.
 */

/* Defined below; the Thread datagram path hands PASE to the same owned handler
 * BLE uses, rather than growing a second copy of the state machine. */
static void on_message_owned(uint8_t *msg, size_t len);
static void on_message(uint8_t *msg, size_t len);

static size_t tx_slot_index(const struct matter_tx_slot *slot)
{
	return (size_t)(slot - s_tx_slots);
}

static uint32_t tx_now_ms(void)
{
	int64_t now = ultrawidelock_uptime_ms();

	return now > 0 ? (uint32_t)now : 0u;
}

static struct matter_tx_slot *tx_acquire(void)
{
	uint8_t transport = s_thread_reply != NULL ? TX_TRANSPORT_THREAD : TX_TRANSPORT_BLE;
	struct matter_tx_slot *slot;

	/* Reaping is demand-driven: expired slots consume no resource until the
	 * next packet needs one, and this makes that acquisition recover them
	 * without another timer or work item. */
	tx_thread_reap_expired(tx_now_ms());
	slot = matter_tx_pool_acquire(&s_tx_pool, transport);

	if (slot != NULL) {
		memset(&s_tx_effects[tx_slot_index(slot)], 0, sizeof(s_tx_effects[0]));
		memset(&s_tx_thread_owner[tx_slot_index(slot)], 0,
		       sizeof(s_tx_thread_owner[0]));
	}
	return slot;
}

static uint8_t *tx_payload(struct matter_tx_slot *slot, size_t *cap)
{
	if (slot == NULL || slot->capacity < MATTER_EXCHANGE_HEADER_MAX + MATTER_TAG_LEN) {
		return NULL;
	}
	if (cap != NULL) {
		*cap = slot->capacity - MATTER_EXCHANGE_HEADER_MAX - MATTER_TAG_LEN;
	}
	return slot->data + MATTER_EXCHANGE_HEADER_MAX;
}

static void tx_abort_build(struct matter_tx_slot *slot)
{
	if (slot == NULL) {
		return;
	}
	if (slot->state == MATTER_TX_SLOT_BUILDING) {
		(void)matter_tx_pool_cancel(&s_tx_pool, slot->token);
		return;
	}
	(void)matter_tx_pool_reject(&s_tx_pool, slot->token);
}

static int tx_publish(struct matter_tx_slot *slot, size_t framed)
{
	int rc;

	if (matter_tx_slot_commit(slot, framed) != MATTER_OK) {
		tx_abort_build(slot);
		return MATTER_E_INVAL;
	}
	if (slot->transport == TX_TRANSPORT_THREAD) {
		if (s_thread_reply == NULL || framed > s_thread_reply_cap ||
		    s_thread_tx_token != 0u) {
			tx_effect_finish(slot, MATTER_E_NOSPACE);
			(void)matter_tx_pool_reject(&s_tx_pool, slot->token);
			return MATTER_E_NOSPACE;
		}
		memcpy(s_thread_reply, slot->data, framed);
		s_thread_reply_len = framed;
		/* Copying into port scratch is not transport completion. Keep the
		 * owned slot and its deferred effect until otUdpSend accepts it. */
		if (matter_tx_slot_in_flight(slot) != MATTER_OK) {
			tx_effect_finish(slot, MATTER_E_STATE);
			(void)matter_tx_pool_reject(&s_tx_pool, slot->token);
			return MATTER_E_STATE;
		}
		s_thread_tx_token = slot->token;
		return MATTER_OK;
	}
	if (s_ble_tx_token != 0u) {
		/* Kept READY until the accepted indication completes. */
		return MATTER_OK;
	}
	rc = tx_ble_pump();
	return rc;
}

static int tx_frame(struct matter_tx_slot *slot, struct matter_exchange *x, uint16_t protocol,
		    uint8_t opcode, const uint8_t *payload, size_t payload_len, bool initiator,
		    uint16_t exchange_id)
{
	uint8_t *owned_payload;
	size_t payload_cap;
	size_t framed = 0u;
	int rc;

	owned_payload = tx_payload(slot, &payload_cap);
	if (owned_payload == NULL || payload_len > payload_cap) {
		tx_abort_build(slot);
		return MATTER_E_NOSPACE;
	}
	if (payload != owned_payload && payload_len > 0u) {
		memmove(owned_payload, payload, payload_len);
	}
	if (slot->transport == TX_TRANSPORT_THREAD) {
		struct tx_thread_owner *owner = &s_tx_thread_owner[tx_slot_index(slot)];

		owner->session_id = x->secure ? x->local_session_id : 0u;
		owner->exchange_id = x->exchange_id;
		owner->request_counter = x->ack_counter;
		owner->retryable = x->mrp && x->ack_pending;
	}
	if (initiator) {
		rc = matter_exchange_send_initiator(x, exchange_id, protocol, opcode, owned_payload,
						    payload_len, slot->data, slot->capacity, &framed);
	} else if (protocol == MATTER_PROTOCOL_SECURE_CHANNEL) {
		rc = matter_exchange_reply(x, opcode, owned_payload, payload_len, slot->data,
					   slot->capacity, &framed);
	} else {
		rc = matter_exchange_send(x, protocol, opcode, owned_payload, payload_len, slot->data,
					  slot->capacity, &framed);
	}
	if (rc != MATTER_OK) {
		tx_abort_build(slot);
		return rc;
	}
	return tx_publish(slot, framed);
}

static int tx_ble_pump(void)
{
	struct matter_tx_slot *slot;
	int rc;

	if (s_ble_tx_token != 0u) {
		return MATTER_OK;
	}
	slot = matter_tx_pool_ready(&s_tx_pool, TX_TRANSPORT_BLE);
	if (slot == NULL) {
		return MATTER_OK;
	}
	/* Publish the loan token before entering the transport. Both current
	 * backends complete asynchronously, but ordering the state this way also
	 * makes a future synchronous backend unable to complete an unowned token. */
	if (matter_tx_slot_in_flight(slot) != MATTER_OK) {
		return MATTER_E_STATE;
	}
	s_ble_tx_token = slot->token;
	rc = matter_ble_send(slot->data, slot->len);
	if (rc == 0) {
		return MATTER_OK;
	}
	s_ble_tx_token = 0u;
	tx_effect_finish(slot, rc);
	(void)matter_tx_pool_reject(&s_tx_pool, slot->token);
	return rc;
}

/**
 * Frame and send a Matter message with the specified opcode and payload. Over BLE, send via
 * matter_ble_send; over Thread, stage the framed bytes in s_thread_reply. Log errors if framing
 * fails or the buffer is too small.
 */
static void send_framed(uint8_t opcode, const uint8_t *payload, size_t len)
{
	struct matter_exchange *x =
		(s_thread_reply != NULL && !s_thread_pase) ? &s_case_x[s_case_cur] : &s_exchange;
	struct matter_tx_slot *slot = tx_acquire();
	int rc;

	if (slot == NULL) {
		LOG_ERR("no owned packet slot for opcode 0x%02x", opcode);
		return;
	}
	rc = tx_frame(slot, x, MATTER_PROTOCOL_SECURE_CHANNEL, opcode, payload, len, false, 0u);
	LOG_DBG("sent opcode 0x%02x, %u B payload, rc=%d", opcode, (unsigned int)len, rc);
}

/**
 * Send an Interaction Model message on whichever transport asked for it.
 *
 * The same split send_framed() makes, and for the same reason. Both IM paths
 * used to frame on the BLE exchange unconditionally, which over a CASE session
 * produced a perfectly correct response sealed with the wrong session's keys
 * and pushed at a link the commissioner had already closed -- no error
 * anywhere, and a commissioner left waiting for an answer that went out a
 * different door.
 */
/* Defined with the subscription table it walks; see notify_lock_state(). */
static void notify_lock_state_changed(void);
/* Re-arms the periodic report; defined with the table it walks. */
static void subscription_heartbeat_arm(void);

/* Storage runs on the system work queue, not OpenThread's small callback
 * stack. The caller waits for durability before the cluster emits success. */
#define FAB_STORE_ATTEMPTS 3u
#define FAB_STORE_TIMEOUT_MS 10000

struct fab_store_request {
	enum matter_fabric_store_operation operation;
	uint8_t slot;
	uint8_t value[MATTER_ACL_MAX];
	size_t value_len;
	int result;
	bool busy;
	bool clear_reader;
};

static struct fab_store_request s_fab_request;
static ultrawidelock_sem_t s_fab_done;

static void fab_store_work_fn(struct k_work *w)
{
	ARG_UNUSED(w);
	/* The caller owns s_owner_lock while it waits. That ownership also
	 * freezes s_info and s_fab_request for this worker; taking the same lock
	 * here would deadlock until the durability boundary timed out. */
	s_fab_request.result = -EIO;
	for (uint8_t attempt = 0u; attempt < FAB_STORE_ATTEMPTS; attempt++) {
		if (s_fab_request.clear_reader) {
			s_fab_request.result = ultrawidelock_reader_provision_clear();
		} else {
			s_fab_request.result = 0;
		}
		if (s_fab_request.result == 0) {
			s_fab_request.result = matter_fab_commit(
				&s_info, s_fab_request.operation, s_fab_request.slot,
				s_fab_request.value_len != 0u ? s_fab_request.value : NULL,
				s_fab_request.value_len);
		}
		if (s_fab_request.result == 0) {
			break;
		}
	}
	ultrawidelock_sem_give(&s_fab_done);
}
static K_WORK_DEFINE(s_fab_store_work, fab_store_work_fn);

static int commissioning_fabric_store(void *ctx, const struct matter_device_info *info,
			      enum matter_fabric_store_operation operation, uint8_t slot,
			      const uint8_t *value, size_t value_len)
{
	ARG_UNUSED(ctx);
	if (s_fab_request.busy || value_len > sizeof(s_fab_request.value)) {
		return MATTER_E_STATE;
	}
	s_fab_request.busy = true;
	s_fab_request.operation = operation;
	s_fab_request.slot = slot;
	s_fab_request.value_len = value_len;
	s_fab_request.clear_reader =
		operation == MATTER_FABRIC_STORE_REMOVE &&
		info->committed_slots == MATTER_FABRIC_SLOT_BIT(slot);
	if (value_len != 0u) {
		memcpy(s_fab_request.value, value, value_len);
	}
	ultrawidelock_sem_reset(&s_fab_done);
	if (k_work_submit(&s_fab_store_work) < 0) {
		LOG_ERR("Matter identity durability work was not queued");
		s_fab_request.busy = false;
		return MATTER_E_STATE;
	}
	if (ultrawidelock_sem_take(&s_fab_done, FAB_STORE_TIMEOUT_MS) != 0) {
		LOG_ERR("Matter identity durability boundary timed out");
		/* Fail closed. The worker may still own the static request after a
		 * wait timeout, so reusing it could commit a mixed operation. A reboot
		 * is the safe recovery if the system work queue is stuck this long. */
		return MATTER_E_STATE;
	}
	s_fab_request.busy = false;
	if (s_fab_request.result != 0) {
		LOG_ERR("Matter identity mutation not persisted (%d)", s_fab_request.result);
		return MATTER_E_STATE;
	}
	return MATTER_OK;
}

static void failsafe_work_fn(struct k_work *w)
{
	ARG_UNUSED(w);
	matter_clusters_failsafe_expire(&s_info);
}
static K_WORK_DELAYABLE_DEFINE(s_failsafe_work, failsafe_work_fn);

static int commissioning_failsafe_arm(void *ctx, uint16_t expiry_s)
{
	ARG_UNUSED(ctx);
	return k_work_reschedule(&s_failsafe_work, K_SECONDS(expiry_s)) < 0 ? MATTER_E_STATE
									 : MATTER_OK;
}

static void commissioning_failsafe_cancel(void *ctx)
{
	ARG_UNUSED(ctx);
	(void)k_work_cancel_delayable(&s_failsafe_work);
}

static const struct matter_commissioning_hooks k_commissioning_hooks = {
	.failsafe_arm = commissioning_failsafe_arm,
	.failsafe_cancel = commissioning_failsafe_cancel,
	.fabric_store = commissioning_fabric_store,
};

/* Defined with the CASE and subscription tables it invalidates. */
static void case_drop_fabric(uint8_t fabric_index);

static int send_standalone_ack(struct matter_exchange *x)
{
	struct matter_tx_slot *slot = tx_acquire();
	size_t framed = 0u;
	int rc;

	if (slot == NULL) {
		return MATTER_E_NOSPACE;
	}
	if (slot->transport == TX_TRANSPORT_THREAD) {
		struct tx_thread_owner *owner = &s_tx_thread_owner[tx_slot_index(slot)];

		owner->session_id = x->secure ? x->local_session_id : 0u;
		owner->exchange_id = x->exchange_id;
		owner->request_counter = x->ack_counter;
		owner->retryable = x->mrp && x->ack_pending;
	}
	rc = matter_exchange_standalone_ack(x, slot->data, slot->capacity, &framed);
	if (rc != MATTER_OK) {
		tx_abort_build(slot);
		return rc;
	}
	return tx_publish(slot, framed);
}

/**
 * A plain Read that spans multiple ReportData messages.
 *
 * Slots are keyed by secure session and exchange. Two simultaneous chunked
 * reads are bounded explicitly; a third receives RESOURCE_EXHAUSTED instead
 * of choosing the amount of static RAM this lock spends.
 */
#define MATTER_READ_SLOTS 2u
static struct matter_im_read_state s_reads[MATTER_READ_SLOTS];
static struct matter_im_read_pool s_read_pool;

static struct matter_im_read_state *read_state_find(uint16_t session_id, uint16_t exchange_id,
						     bool over_thread)
{
	return matter_im_read_pool_find(&s_read_pool, session_id, exchange_id, over_thread);
}

static void read_drop_session(uint16_t session_id, bool over_thread)
{
	matter_im_read_pool_drop_session(&s_read_pool, session_id, over_thread);
}

/** Send the next bounded ReportData message for a plain Read. */
static void send_read_chunk(struct matter_im_read_state *s)
{
	struct matter_im_report_stats stats;
	struct matter_tx_slot *slot = tx_acquire();
	uint8_t *payload;
	size_t payload_cap;
	size_t report_len = 0u;
	uint16_t emitted = 0u;
	bool more = false;
	int rc;

	if (slot == NULL) {
		LOG_ERR("no owned packet slot for Read ReportData");
		s->in_use = false;
		return;
	}
	payload = tx_payload(slot, &payload_cap);
	rc = matter_im_report_data_chunk(&s_im, &s->read, s->sent, payload,
					 payload_cap, &report_len, &more, &emitted,
					 &stats);
	if (rc != MATTER_OK) {
		LOG_ERR("cannot build Read ReportData chunk (%d)", rc);
		tx_abort_build(slot);
		s->in_use = false;
		return;
	}
	if (emitted == 0u && more) {
		LOG_ERR("a single Read attribute does not fit one Matter message");
		tx_abort_build(slot);
		s->in_use = false;
		return;
	}
	if (stats.unexpanded_wildcard > 0u) {
		LOG_WRN("%u wildcard path(s) not expanded; Read report is incomplete",
			stats.unexpanded_wildcard);
	}
	LOG_INF("  Read chunk %u B, %u report(s), %u total, %s",
		(unsigned int)report_len, emitted, (unsigned int)(s->sent + emitted),
		more ? "MORE" : "last");
	s_tx_effects[tx_slot_index(slot)] = (struct tx_effect){
		.kind = TX_EFFECT_READ,
		.session_id = s->session_id,
		.exchange_id = s->exchange_id,
		.emitted = emitted,
		.more = more,
		.over_thread = s->over_thread,
	};
	if (tx_frame(slot,
		     (s_thread_reply != NULL && !s_thread_pase) ? &s_case_x[s_case_cur] : &s_exchange,
		     MATTER_PROTOCOL_INTERACTION_MODEL, MATTER_IM_OP_REPORT_DATA, payload, report_len,
		     false, 0u) != MATTER_OK) {
		LOG_ERR("Read ReportData was not accepted by its transport");
		s->in_use = false;
	}
}

/**
 * Handle an incoming Matter ReadRequest. Decodes the paths being read, logs them per session type
 * (loud over CASE only), and builds a ReportData response. Warns if any wildcard paths could not be
 * expanded.
 */
static void on_read_request(const struct matter_exchange_in *in)
{
	struct matter_im_read_state *s;
	uint16_t session_id;
	bool over_thread = s_thread_reply != NULL;
	size_t status_len = 0u;
	int rc;

	session_id = current_session_id();
	rc = matter_im_read_pool_acquire(&s_read_pool, session_id, in->exchange_id, over_thread, &s);
	if (rc == MATTER_E_DUP) {
		/* Exchange replay filtering normally consumes this earlier. Keep the
		 * cursor intact if a duplicate ever reaches this boundary. */
		LOG_WRN("duplicate ReadRequest reached the cursor owner");
		return;
	}
	if (rc != MATTER_OK) {
		struct matter_tx_slot *slot = tx_acquire();
		uint8_t *payload;
		size_t payload_cap;

		LOG_WRN("two chunked Reads are already live; refusing another");
		payload = tx_payload(slot, &payload_cap);
		if (slot != NULL &&
		    matter_im_status_response_encode(MATTER_IM_STATUS_RESOURCE_EXHAUSTED,
						     payload, payload_cap, &status_len) ==
		    MATTER_OK) {
			(void)tx_frame(slot,
				       (s_thread_reply != NULL && !s_thread_pase) ? &s_case_x[s_case_cur]
										 : &s_exchange,
				       MATTER_PROTOCOL_INTERACTION_MODEL, MATTER_IM_OP_STATUS_RESPONSE,
				       payload, status_len, false, 0u);
		} else if (slot != NULL) {
			tx_abort_build(slot);
		}
		return;
	}
	rc = matter_im_read_request_decode(in->payload, in->payload_len, &s->read);
	if (rc != MATTER_OK) {
		LOG_WRN("unreadable ReadRequest (%d), %u B", rc, (unsigned int)in->payload_len);
		s->in_use = false;
		return;
	}

	/* What was asked, not just how much. Which paths a commissioner reads is
	 * the specification for what to implement next, and reading it out of a
	 * hexdump by hand has already cost more than this line does. */
	for (uint8_t i = 0; i < s->read.n_paths; i++) {
		const struct matter_im_path *p = &s->read.paths[i];

		/*
		 * Loud only over CASE. The BLE phase is settled and its three
		 * reads carry nine paths each -- 27 lines that filled the trace
		 * ring before the interesting half of the session began.
		 */
		if (s_thread_reply == NULL) {
			LOG_DBG("  read[%u] endpoint %d cluster 0x%04x attribute 0x%04x", i,
				p->have_endpoint ? (int)p->endpoint : -1,
				p->have_cluster ? (unsigned int)p->cluster : 0xFFFFu,
				p->have_attribute ? (unsigned int)p->attribute : 0xFFFFu);
			continue;
		}
		LOG_INF("  read[%u] endpoint %d cluster 0x%04x attribute 0x%04x", i,
			p->have_endpoint ? (int)p->endpoint : -1,
			p->have_cluster ? (unsigned int)p->cluster : 0xFFFFu,
			p->have_attribute ? (unsigned int)p->attribute : 0xFFFFu);
	}

	send_read_chunk(s);
}

/**
 * Handle an incoming Matter InvokeRequest. Decodes the request, builds an InvokeResponse, and on
 * successful Door Lock or Network Commissioning commands, submits a notification to trigger
 * subscription reports before sending. Stores fabrics and credentials to NVS only on
 * CommissioningComplete to avoid pairing delays and stack overflow on the receive path.
 */
static void on_invoke_request(const struct matter_exchange_in *in)
{
	static struct matter_im_invoke inv;
	bool removed = false;
	struct matter_tx_slot *slot;
	uint8_t *payload;
	size_t payload_cap;
	size_t resp_len = 0u;
	int rc;

	rc = matter_im_invoke_request_decode(in->payload, in->payload_len, &inv);
	if (rc != MATTER_OK) {
		LOG_WRN("unreadable InvokeRequest (%d), %u B", rc, (unsigned int)in->payload_len);
		return;
	}
	if (s_thread_reply != NULL) {
		LOG_INF("  invoke: endpoint %u cluster 0x%04x command 0x%04x, %u B fields",
			inv.endpoint, (unsigned int)inv.cluster, (unsigned int)inv.command,
			(unsigned int)inv.fields_len);
	} else {
		LOG_DBG("  invoke: endpoint %u cluster 0x%04x command 0x%04x, %u B fields",
			inv.endpoint, (unsigned int)inv.cluster, (unsigned int)inv.command,
			(unsigned int)inv.fields_len);
	}
	if (inv.cluster == MATTER_CLUSTER_OPERATIONAL_CREDENTIALS &&
	    inv.command == MATTER_CMD_OC_REMOVE_FABRIC) {
		/* Prevent a rejected request from observing a previous success. */
		s_info.last_noc_status = MATTER_NOC_STATUS_INVALID_FABRIC_INDEX;
		s_info.last_noc_index = 0u;
	}

	slot = tx_acquire();
	if (slot == NULL) {
		LOG_ERR("no owned packet slot for InvokeResponse");
		return;
	}
	payload = tx_payload(slot, &payload_cap);
	rc = matter_im_invoke_response_encode(&s_im, &inv, payload, payload_cap, &resp_len);
	/* AddNOC/RemoveFabric and fail-safe commands mutate the table while
	 * encoding their response. Publish their result before any readvertise
	 * request can rebuild the payload on another context. */
	fabric_snapshot_refresh_owned();
	if (rc != MATTER_OK) {
		LOG_ERR("cannot build InvokeResponse (%d)", rc);
		tx_abort_build(slot);
		return;
	}
	/*
	 * The tile reads LockState, not the InvokeResponse. A controller takes
	 * the SUCCESS and then waits for the attribute to be reported on its
	 * subscription before it moves -- so answering the command and stopping
	 * there is a lock that opens and a UI that spins forever. Submitted
	 * rather than sent: the response's owned packet has not completed yet,
	 * and this runs on OpenThread's thread.
	 */
	if (inv.cluster == MATTER_CLUSTER_DOOR_LOCK &&
	    (inv.command == MATTER_CMD_DL_LOCK_DOOR || inv.command == MATTER_CMD_DL_UNLOCK_DOOR)) {
		notify_lock_state_changed();
	}
	if (inv.cluster == MATTER_CLUSTER_NETWORK_COMMISSIONING &&
	    inv.command == MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK) {
		/*
		 * Length and shape only. The full dataset was dumped while
		 * there was no Thread stack to hand it to and the trace was the
		 * only way to see what arrived; now OpenThread consumes it, and
		 * a hexdump of the network key would be 700 bytes of an 8 KB
		 * trace buffer spent on printing a secret.
		 */
		LOG_INF("  Thread dataset: %u B, extended PAN id %s",
			(unsigned int)s_info.thread_dataset_len,
			s_info.have_thread_xpanid ? "found" : "MISSING");
	}
	if (inv.cluster == MATTER_CLUSTER_OPERATIONAL_CREDENTIALS &&
	    inv.command == MATTER_CMD_OC_ADD_NOC) {
		/*
		 * The verdict is inside the response payload, so without this
		 * an AddNOC this node REFUSED looks identical in the log to one
		 * it accepted. Split into halves because the log backend
		 * formats 32 bits at a time. Neither id is a secret: both are
		 * published in the clear once this node advertises operationally.
		 */
		/*
		 * The slot AddNOC actually filled, not slot 0. matter_clusters.c
		 * assigns the first FREE slot, so the second fabric's line
		 * reprinted the FIRST one's ids -- two AddNOCs, two indices, the
		 * same node and fabric id under both, which reads as a node that
		 * joined the same fabric twice.
		 */
		const struct matter_fabric *added = NULL;

		for (size_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
			if (s_info.fabrics[i].index == s_info.last_noc_index) {
				added = &s_info.fabrics[i];
				break;
			}
		}
		LOG_INF("  AddNOC -> status %u, fabric index %u, node %08x%08x on fabric %08x%08x",
			s_info.last_noc_status, s_info.last_noc_index,
			added ? (unsigned int)(added->node_id >> 32) : 0u,
			added ? (unsigned int)added->node_id : 0u,
			added ? (unsigned int)(added->fabric_id >> 32) : 0u,
			added ? (unsigned int)added->fabric_id : 0u);
	}
	removed = inv.cluster == MATTER_CLUSTER_OPERATIONAL_CREDENTIALS &&
		  inv.command == MATTER_CMD_OC_REMOVE_FABRIC &&
		  s_info.last_noc_status == MATTER_NOC_STATUS_OK && s_info.last_noc_index != 0u;
	/*
	 * ONLY at CommissioningComplete, never at AddNOC.
	 *
	 * Storing at AddNOC cost a pairing. This writes ~1.7 KB across several
	 * settings keys and an NVS sector erase on this part runs to tens of
	 * milliseconds; doing that inline left the commissioner waiting, it
	 * retransmitted Sigma1, and the second fabric's CASE then failed --
	 * "Sigma3 REJECTED (-6)" five times and a RemoveFabric. A fabric is of
	 * no use before commissioning completes anyway, so there is nothing to
	 * protect in that window: if the commissioner gives up half way, the
	 * fail-safe is supposed to discard the fabric, not persist it.
	 *
	 * Apple runs commissioning TWICE, once per administrator, so both
	 * fabrics are still captured -- each round ends here.
	 */
	if (resp_len == 0u) {
		/* The command ran; the peer asked not to be told. */
		LOG_INF("invoke done, response suppressed");
		tx_abort_build(slot);
		if (removed) {
			case_drop_fabric(s_info.last_noc_index);
		}
		return;
	}

	rc = tx_frame(slot,
		      (s_thread_reply != NULL && !s_thread_pase) ? &s_case_x[s_case_cur] : &s_exchange,
		      MATTER_PROTOCOL_INTERACTION_MODEL, MATTER_IM_OP_INVOKE_COMMAND_RESPONSE, payload,
		      resp_len, false, 0u);
	if (rc != MATTER_OK) {
		LOG_ERR("cannot frame InvokeResponse (%d)", rc);
	}
	/* The response is framed before its own session can be destroyed. */
	if (removed) {
		case_drop_fabric(s_info.last_noc_index);
	}
	LOG_DBG("InvokeResponse: %u B", (unsigned int)resp_len);
}

/**
 * Apply a WriteRequest.
 *
 * The commissioner's last act, and the one this node used to answer with
 * silence: an ACL entry granting itself Administer over CASE. A home app that
 * has finished commissioning and cannot record that it owns the node sits on
 * "Adding to home" until it gives up.
 */
static void on_write_request(const struct matter_exchange_in *in)
{
	static struct matter_im_write wr;
	struct matter_tx_slot *slot;
	uint8_t *payload;
	size_t payload_cap;
	uint32_t prev_relock_s;
	uint8_t prev_approach;
	size_t resp_len = 0u;
	int rc;

	rc = matter_im_write_request_decode(in->payload, in->payload_len, &wr);
	if (rc != MATTER_OK) {
		LOG_WRN("unreadable WriteRequest (%d), %u B", rc, (unsigned int)in->payload_len);
		return;
	}
	LOG_INF("  write: endpoint %u cluster 0x%04x attribute 0x%04x, %u item(s)",
		wr.items[0].path.endpoint, (unsigned int)wr.items[0].path.cluster,
		(unsigned int)wr.items[0].path.attribute, (unsigned int)wr.n_items);
	/*
	 * Persisted by VALUE CHANGE rather than by write status: the encoder
	 * only mutates s_info on a write it accepted, so a changed field is
	 * exactly a write that ran. Re-writing an unchanged value costs no
	 * flash, which matters because the store shares its pages with the
	 * fabric table.
	 */
	prev_relock_s = s_info.auto_relock_time_s;
	prev_approach = s_info.approach_direction;
	slot = tx_acquire();
	if (slot == NULL) {
		LOG_ERR("no owned packet slot for WriteResponse");
		return;
	}
	payload = tx_payload(slot, &payload_cap);
	rc = matter_im_write_response_encode(&s_im, &wr, payload, payload_cap, &resp_len);
	if (rc != MATTER_OK) {
		LOG_ERR("cannot build WriteResponse (%d)", rc);
		tx_abort_build(slot);
		return;
	}
	(void)matter_dl_attr_store(&s_info, prev_relock_s, prev_approach);
#if MATTER_FEATURE_CLIENT
	/*
	 * Keyed on the CLUSTER rather than on the write status: the encoder
	 * above only mutates s_info for a write it accepted, and re-storing an
	 * unchanged table costs one flash record against a binding that is
	 * silently gone after the next reboot. The slot argument is unused --
	 * the table is node-wide and carries its own fabric scoping.
	 */
	if (wr.items[0].path.cluster == MATTER_CLUSTER_BINDING) {
		(void)matter_fab_commit(&s_info, MATTER_FABRIC_STORE_BINDING, 0u, NULL, 0u);
	}
#endif
	if (resp_len == 0u) {
		/* The write ran; the peer asked not to be told. */
		LOG_INF("  write done, response suppressed");
		tx_abort_build(slot);
		return;
	}
	(void)tx_frame(slot,
		       (s_thread_reply != NULL && !s_thread_pase) ? &s_case_x[s_case_cur] : &s_exchange,
		       MATTER_PROTOCOL_INTERACTION_MODEL, MATTER_IM_OP_WRITE_RESPONSE, payload, resp_len,
		       false, 0u);
}

/**
 * The subscriptions this node is serving.
 *
 * One slot per session, because that is the natural bound: a controller
 * subscribes on the session it holds. This was a SINGLE subscription, on the
 * argument that Apple opens exactly one during commissioning and a table would
 * be RAM spent on a case that had not arrived. The case had arrived. Every
 * SubscribeRequest overwrote the last, so the displaced controller saw its
 * subscription stop, re-subscribed at once, and displaced the next one -- with
 * nothing in the log to say so, because each round looks like a healthy
 * subscribe. Measured on 2026-08-02: nine of these in five minutes and a tile
 * that never left "No Response".
 */
struct sub_state {
	struct matter_im_read read;
	uint32_t id;
	uint16_t max_interval_s;
	/**
	 * The CASE session this subscriber holds, or 0 when the request arrived
	 * over BLE. A local session id is never 0 -- see the Sigma2 path -- so
	 * the two can never collide.
	 */
	uint16_t session_id;
	/** Reports already delivered by earlier chunks of the priming report. */
	uint16_t sent;
	/**
	 * The lowest EventNumber this subscriber has NOT been sent.
	 *
	 * Held per subscription rather than per node: two controllers advance
	 * independently, and a shared watermark would have the second one never
	 * hear about an unlock the first already collected. Zero until the
	 * subscription asks for events.
	 */
	uint64_t event_min;
	/** More chunks remain; the next StatusResponse asks for one. */
	bool more;
	/* Between the priming report and the StatusResponse that confirms it. */
	bool priming;
	bool active;
	bool in_use;
	/**
	 * Where to send a report this node originates.
	 *
	 * Taken when the SubscribeRequest arrives, because that is the last
	 * moment the transport knows who asked: a subscription outlives its
	 * request by up to max_interval_s, and by then there is no datagram in
	 * flight to reply to.
	 */
	struct matter_thread_peer peer;
};

static struct sub_state s_subs[MATTER_CASE_SESSIONS];
/** Round-robin victim, used only when every subscription slot is live. */
static uint8_t s_sub_next_victim;

/*
 * Subscriptions that outlive a reboot.
 *
 * They live in RAM, so a reset destroys every one of them while the controller
 * still believes in all of them -- and it does not re-subscribe until its own
 * liveness timer expires, which is the granted max interval. Measured
 * 2026-08-02: the Home tile sent UnlockDoor, this node answered SUCCESS, no
 * report went anywhere because no subscription existed to report to, and the
 * tile sat on "Unlocking" for minutes. After every flash.
 *
 * CHIP's answer is subscription resumption: persist, then re-establish CASE
 * outbound and resume. This node has no CASE initiator -- but it does not need
 * one, because the controller comes back ON ITS OWN about 25 s after boot to
 * re-establish CASE (16:37:26 -> 16:37:51, 16:18:10 -> 16:18:35, the same
 * figure twice). It just never re-subscribes. So the record is stored here and
 * REBOUND to that new session when it arrives, which costs no handshake, no
 * outbound MRP and nothing on the OpenThread stack.
 *
 * What is NOT stored is the read path set. A revived subscription only ever
 * carries this node's own LockState reports, which notify_lock_state() builds
 * from a fixed path; the stored paths exist to build the PRIMING report, and a
 * resumed subscription does not prime.
 *
 * UNPROVEN against a real controller: Apple may refuse a ReportData whose
 * subscription id it considers bound to the session that died. Its
 * StatusResponse says so either way, and the log lines below name which
 * happened -- that is the whole experiment.
 */
#define SUB_TREE     "msub"
#define SUB_KEY_FMT  SUB_TREE "/%u"
#define SUB_KEY_MAX  16u

/**
 * Persisted subscription state: peer node ID, subscription ID, maximum heartbeat interval in
 * seconds, fabric index, and a used flag.
 */
struct sub_persist {
	uint64_t peer_node;
	uint64_t fabric_id;
	uint32_t id;
	uint16_t max_interval_s;
	uint8_t fabric_index;
	uint8_t used;
};

static struct sub_persist s_dormant[MATTER_CASE_SESSIONS];

/*
 * Subscription ids, and why this is not a local static.
 *
 * It restarted at 0 on every boot, so the FIRST subscription after a reboot was
 * always 0x00000001 -- the same id a resumed record is very likely to carry,
 * because it was also the first one before the reboot. Observed 2026-08-02
 * 17:40: a resumed subscription and the controller's fresh one both answering
 * to 0x00000001. It was benign only because the new request reused the same
 * slot. Seeded past every stored id at load, the two can no longer collide.
 */
static uint32_t s_sub_next_id;

/**
 * Persist one subscription's state to settings storage with the key SUB_KEY_FMT[slot]. Skip
 * persisting if peer_node or fabric_index is zero (no match key available). Log a warning if save
 * fails; the subscription will not survive reboot.
 */
static void sub_persist_save(uint8_t slot, const struct sub_state *s, uint64_t peer_node,
			     uint8_t fabric_index)
{
	struct sub_persist p = {
		.peer_node = peer_node,
		.id = s->id,
		.max_interval_s = s->max_interval_s,
		.fabric_index = fabric_index,
		.used = 1u,
	};
	char key[SUB_KEY_MAX];

	for (size_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if (s_info.fabrics[i].index == fabric_index &&
		    (s_info.committed_slots & MATTER_FABRIC_SLOT_BIT(i)) != 0u) {
			p.fabric_id = s_info.fabrics[i].fabric_id;
			break;
		}
	}

	if (peer_node == 0u || fabric_index == 0u || p.fabric_id == 0u) {
		/* Nothing to match on later, so storing it would only produce a
		 * record no CASE session can ever claim. */
		return;
	}
	(void)snprintf(key, sizeof(key), SUB_KEY_FMT, (unsigned int)slot);
	if (settings_save_one(key, &p, sizeof(p)) != 0) {
		LOG_WRN("  subscription 0x%08x not persisted; it will not survive a reboot",
			(unsigned int)s->id);
		return;
	}
	s_dormant[slot] = p;
}

/**
 * Settings callback to load one persisted subscription from the settings key-value store. Reads up
 * to len bytes into *out if len matches the struct size. Returns 0.
 */
static int sub_persist_read(const char *key, size_t len, settings_read_cb read_cb, void *cb_arg,
			    void *param)
{
	struct sub_persist *out = param;

	ARG_UNUSED(key);

	if (len == sizeof(*out)) {
		(void)read_cb(cb_arg, out, sizeof(*out));
	}
	return 0;
}

/** Load the stored records, dormant until a matching CASE session turns up. */
static void sub_persist_load(void)
{
	unsigned int n = 0u;

	for (uint8_t i = 0u; i < MATTER_CASE_SESSIONS; i++) {
		char key[SUB_KEY_MAX];

		(void)snprintf(key, sizeof(key), SUB_KEY_FMT, (unsigned int)i);
		(void)settings_load_subtree_direct(key, sub_persist_read, &s_dormant[i]);
		if (s_dormant[i].used) {
			n++;
			if (s_dormant[i].id > s_sub_next_id) {
				s_sub_next_id = s_dormant[i].id;
			}
		}
	}
	if (n > 0u) {
		LOG_INF("  %u subscription(s) held over the reboot, waiting for their controller",
			n);
	}
}

/**
 * A CASE session just came up. If a stored subscription belongs to this peer on
 * this fabric, put it back to work on the new session.
 */
static void sub_resume_for(uint8_t case_slot, uint64_t peer_node, uint8_t fabric_index,
			   uint16_t session_id)
{
	uint64_t fabric_id = 0u;
	struct matter_thread_peer peer;

	ARG_UNUSED(case_slot);

	if (peer_node == 0u || fabric_index == 0u) {
		return;
	}
	for (size_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if (s_info.fabrics[i].index == fabric_index &&
		    (s_info.committed_slots & MATTER_FABRIC_SLOT_BIT(i)) != 0u) {
			fabric_id = s_info.fabrics[i].fabric_id;
			break;
		}
	}
	if (fabric_id == 0u) {
		return;
	}
	matter_thread_peer_current(&peer);
	for (uint8_t i = 0u; i < MATTER_CASE_SESSIONS; i++) {
		struct sub_state *s = &s_subs[i];

		if (!s_dormant[i].used || s_dormant[i].peer_node != peer_node ||
		    s_dormant[i].fabric_index != fabric_index ||
		    s_dormant[i].fabric_id != fabric_id) {
			continue;
		}
		if (s->in_use && s->active && s->id == s_dormant[i].id) {
			/* Already live -- the controller re-subscribed before we
			 * got here, which is the outcome that needs no help. */
			s_dormant[i].used = 0u;
			continue;
		}
		memset(s, 0, sizeof(*s));
		s->id = s_dormant[i].id;
		s->max_interval_s = s_dormant[i].max_interval_s;
		s->session_id = session_id;
		s->in_use = true;
		s->active = true;
		s->priming = false;
		s->peer = peer;
		s_dormant[i].used = 0u;

		LOG_INF("  subscription 0x%08x RESUMED on session 0x%04x after the reboot",
			(unsigned int)s->id, (unsigned int)session_id);
		subscription_heartbeat_arm();
	}
}

/*
 * There is deliberately no erase for these. A record is only LOADED when a
 * fabric loads, and can only be CLAIMED by a CASE session whose peer node and
 * fabric index both match -- a factory reset destroys both, so whatever is left
 * in NVS is unreachable rather than dangerous, and the next commissioning
 * overwrites the slots it needs. Three records of 24 bytes is the whole cost of
 * not adding a second thing that must be kept in step with the fabric erase.
 */

/*
 * Tell every subscriber that LockState moved.
 *
 * DEFERRED, for two reasons that both cost a night already. It runs on the
 * system work queue rather than ot_work_q, whose stack the Interaction Model
 * has already overflowed once; and it runs AFTER the InvokeResponse has left.
 *
 * It uses the same owned packet pool as direct responses. The synchronous
 * Thread send copies into an otMessage before the slot is released.
 */
/** Exchange ids this node originates. Any non-zero value the peer is not using. */
static uint16_t s_next_init_exchange = 0xE000u;

/**
 * Send a Matter lock state subscription report to one CASE session. Builds a TLV-encoded data
 * report for the DoorLock cluster LockState attribute and sends it as an initiator exchange. Logs
 * the subscription ID and byte counts. Returns silently if the session is not in use, active, and
 * valid.
 */
static void notify_lock_state(struct sub_state *s)
{
	/*
	 * On the stack, not static: struct matter_im_read carries
	 * MATTER_IM_MAX_PATHS of them and this report uses ONE, so keeping it in
	 * BSS spends ~264 B permanently to describe a single attribute. This
	 * runs on the system work queue, which has 2,272 B of measured headroom
	 * over its 3,872 B peak, and this path is shallow.
	 */
	struct matter_im_read one;
	struct matter_tx_slot *packet;
	uint8_t *payload;
	size_t payload_cap;
	size_t tlv_len = 0u;
	size_t framed = 0u;
	uint8_t slot;
	uint16_t session_id;
	uint32_t subscription_id;
	int rc;

	if (!s->in_use || !s->active || s->session_id == 0u || !s->peer.valid) {
		return;
	}
	slot = case_slot_of(s->session_id);
	if (slot >= MATTER_CASE_SESSIONS) {
		return;
	}
	packet = matter_tx_pool_acquire(&s_tx_pool, TX_TRANSPORT_THREAD);
	if (packet == NULL) {
		LOG_ERR("  no owned packet slot for LockState report");
		return;
	}
	memset(&s_tx_effects[tx_slot_index(packet)], 0, sizeof(s_tx_effects[0]));
	payload = tx_payload(packet, &payload_cap);

	memset(&one, 0, sizeof(one));
	one.n_paths = 1u;
	one.paths[0].endpoint = MATTER_ENDPOINT_LOCK;
	one.paths[0].have_endpoint = true;
	one.paths[0].cluster = MATTER_CLUSTER_DOOR_LOCK;
	one.paths[0].have_cluster = true;
	one.paths[0].attribute = MATTER_ATTR_DL_LOCK_STATE;
	one.paths[0].have_attribute = true;
	/* Non-zero is what makes this a subscription report rather than the
	 * answer to a read the peer never sent. */
	one.subscription_id = s->id;

	/*
	 * The events this subscriber has not been sent, carried by the same
	 * report as the attribute. A subscriber that asked for no events gets
	 * none: n_event_paths stays zero and the encoder writes no array at all,
	 * so a controller that never mentioned events sees exactly the report it
	 * always did.
	 */
	if (s->read.n_event_paths > 0u) {
		one.n_event_paths = s->read.n_event_paths;
		memcpy(one.event_paths, s->read.event_paths, sizeof(one.event_paths));
		one.event_min = s->event_min;
	}

	rc = matter_im_report_data_encode(&s_im, &one, payload, payload_cap, &tlv_len,
					  NULL);
	if (rc != MATTER_OK) {
		LOG_ERR("  cannot build the LockState report (%d)", rc);
		tx_abort_build(packet);
		return;
	}

	rc = matter_exchange_send_initiator(&s_case_x[slot], s_next_init_exchange++,
					    MATTER_PROTOCOL_INTERACTION_MODEL,
					    MATTER_IM_OP_REPORT_DATA, payload, tlv_len, packet->data,
					    packet->capacity, &framed);
	if (rc != MATTER_OK) {
		LOG_ERR("  cannot frame the LockState report (%d)", rc);
		tx_abort_build(packet);
		return;
	}
	if (matter_tx_slot_commit(packet, framed) != MATTER_OK ||
	    matter_tx_slot_in_flight(packet) != MATTER_OK) {
		tx_abort_build(packet);
		return;
	}
	session_id = s->session_id;
	subscription_id = s->id;
	/* The IN_FLIGHT slot keeps packet and peer bytes stable through the
	 * synchronous copy into an otMessage. UDP receive never waits on this owner
	 * (matter_thread_on_datagram below), so this owner-to-OT call has no reverse
	 * blocking edge. */
	struct matter_thread_peer peer = s->peer;

	rc = matter_thread_send_to(&peer, packet->data, framed);
	LOG_INF("  LockState report to subscription 0x%08x, %u B, rc=%d", (unsigned int)s->id,
		(unsigned int)framed, rc);
	if (rc == MATTER_OK) {
		(void)matter_tx_pool_complete(&s_tx_pool, packet->token);
	} else {
		(void)matter_tx_pool_reject(&s_tx_pool, packet->token);
	}
	/*
	 * Advance the watermark only on a report that went out. Moving it before
	 * the send would drop an unlock on a failed transmit, and the subscriber
	 * has no way to ask for an event it was never told existed.
	 */
	if (rc == MATTER_OK && s->in_use && s->session_id == session_id &&
	    s->id == subscription_id && s->read.n_event_paths > 0u) {
		s->event_min = s_info.next_event_number + 1u;
	}
}

/**
 * Work callback that sends lock state subscription reports to all CASE sessions.
 */
static void notify_work_fn(struct k_work *w)
{
	ARG_UNUSED(w);
	ultrawidelock_mutex_lock(&s_owner_lock);

	for (uint8_t i = 0u; i < MATTER_CASE_SESSIONS; i++) {
		notify_lock_state(&s_subs[i]);
	}
	ultrawidelock_mutex_unlock(&s_owner_lock);
}

static K_WORK_DEFINE(s_notify_work, notify_work_fn);
static void heartbeat_work_fn(struct k_work *w);
static K_WORK_DELAYABLE_DEFINE(s_heartbeat_work, heartbeat_work_fn);

/**
 * Submit lock state change notification to the work queue, and move the lock LED.
 *
 * The LED is driven from here rather than from on_ultrawidelock_lock_state() because
 * this is the one point BOTH movers reach: a walk-up arrives through the credential
 * listener, and a Home tile tap arrives through the Door Lock cluster, which
 * writes s_info.lock_state itself and never touches that listener. Hanging the
 * light off the listener alone gave a board whose LED ignored the app.
 */
static void notify_lock_state_changed(void)
{
	status_led_signal(STATUS_LED_UNLOCKED, s_info.lock_state == MATTER_DL_LOCK_STATE_UNLOCKED);
	k_work_submit(&s_notify_work);
}

/*
 * The periodic half of a subscription.
 *
 * A subscriber is promised a report at least every max_interval_s -- 600 s is
 * what Apple asks for here -- whether or not anything changed. Miss it and the
 * subscription lapses, which presents as an accessory that has gone away rather
 * than as a missing message.
 *
 * One timer for every subscription rather than one each: they all carry the
 * same attribute and the period is a floor, not a schedule, so reporting early
 * is free and reporting per-subscription would cost six timers on a part with
 * under 5 KB of RAM. The period is deliberately well under the ceiling -- a
 * report costs ~67 bytes on a sleepy link whose round trip has been measured at
 * 1.4 s, and being early is cheap while being late is the whole failure.
 */
#define SUBSCRIPTION_HEARTBEAT_S 120u

/*
 * The largest max interval this node will GRANT, whatever the subscriber asks
 * for. See where it is applied, in the subscribe handler.
 *
 * The two numbers are a pair and must stay one: the heartbeat is what keeps a
 * subscription alive, so granting an interval at or below it promises a report
 * this node will not send in time. Anyone lowering this must lower the
 * heartbeat first.
 */
#define SUBSCRIPTION_MAX_INTERVAL_S 180u
BUILD_ASSERT(SUBSCRIPTION_MAX_INTERVAL_S > SUBSCRIPTION_HEARTBEAT_S,
	     "a granted interval at or below the heartbeat lapses every subscription");

/*
 * Never slower than what a subscriber was actually GRANTED.
 *
 * The ceiling above bounds what this node hands out, which is what makes the
 * assert meaningful, but it cannot bound what a subscriber ASKS for: a request
 * below the ceiling is granted as-is, and a fixed 120 s heartbeat then breaks
 * it. A controller asking for 60 s was told 60 s and reported to every 120 s --
 * precisely the lapsed subscription ("Matter Accessory / No Response") the
 * heartbeat exists to prevent, reintroduced for everyone who is not Apple, and
 * silent: from this side the report went out fine, and only the peer's own timer
 * notices. So the constant pair is checked at build time and the runtime period
 * follows whatever was actually granted.
 *
 * Nothing changes for Apple. It asks 600 s, is granted 180 s by the ceiling, and
 * three quarters of that is 135 s -- above the 120 s heartbeat, so 120 s stands.
 *
 * Three quarters rather than the interval itself: a report landing exactly on
 * the ceiling races the subscriber's timer on a link whose round trip has been
 * measured at 1.4 s. Being early is cheap; being late is the whole failure.
 *
 * Floored, because that granted value is the subscriber's number and a small one
 * would otherwise wake a sleepy-end-device radio continuously. Below about 7 s
 * of granted ceiling the floor WINS and the promise is not kept -- 4 s granted
 * reports every 5 s. That is deliberate and not free: the honest alternatives
 * are refusing the subscription or letting a controller drive this radio, and
 * the ceiling cannot be raised to fix it because the response has to sit inside
 * the range that was requested. No controller observed here comes near it;
 * Apple's floor is measured in minutes.
 */
#define SUBSCRIPTION_HEARTBEAT_MIN_S 5u

/**
 * Compute the heartbeat period in seconds for all active subscriptions. Returns the minimum of (3/4
 * * max_interval_s) across all subscriptions, or SUBSCRIPTION_HEARTBEAT_S if none are active,
 * floored to SUBSCRIPTION_HEARTBEAT_MIN_S.
 */
static uint32_t subscription_heartbeat_period_s(void)
{
	uint32_t period = SUBSCRIPTION_HEARTBEAT_S;

	for (uint8_t i = 0u; i < MATTER_CASE_SESSIONS; i++) {
		uint32_t promised;

		if (!s_subs[i].in_use || !s_subs[i].active || s_subs[i].max_interval_s == 0u) {
			continue;
		}
		promised = ((uint32_t)s_subs[i].max_interval_s * 3u) / 4u;
		if (promised < period) {
			period = promised;
		}
	}
	if (period < SUBSCRIPTION_HEARTBEAT_MIN_S) {
		period = SUBSCRIPTION_HEARTBEAT_MIN_S;
	}
	return period;
}

/**
 * Work callback that sends lock state subscription reports to all active CASE sessions and
 * reschedules itself only if at least one subscription remains active.
 */
static void heartbeat_work_fn(struct k_work *w)
{
	bool any = false;

	ARG_UNUSED(w);
	ultrawidelock_mutex_lock(&s_owner_lock);

	for (uint8_t i = 0u; i < MATTER_CASE_SESSIONS; i++) {
		if (s_subs[i].in_use && s_subs[i].active) {
			notify_lock_state(&s_subs[i]);
			any = true;
		}
	}
	/* Stops re-arming itself once nothing is subscribed, so a node nobody
	 * is watching is not waking its radio every two minutes. */
	if (any) {
		(void)k_work_schedule(&s_heartbeat_work,
				      K_SECONDS(subscription_heartbeat_period_s()));
	}
	ultrawidelock_mutex_unlock(&s_owner_lock);
}

/**
 * Schedule the subscription heartbeat work with the minimum period across all active subscriptions.
 */
static void subscription_heartbeat_arm(void)
{
	(void)k_work_schedule(&s_heartbeat_work, K_SECONDS(subscription_heartbeat_period_s()));
}

/*
 * The credential side of this lock moved, so Matter has to be told.
 *
 * A walk-up unlock and its walk-away relock never went through the Door Lock
 * cluster at all -- they are the reader's own transaction -- so LockState kept
 * whatever the last tile tap set it to. The Wallet animated "unlocked" while
 * the Home tile said locked, and the app was not wrong so much as uninformed:
 * nothing had reported the change.
 *
 * Runs on the BLE-host task, so it does the cheapest possible thing: set a byte
 * and submit. The report itself is built on the system work queue.
 */
/** The clock an event's SystemTimestamp is taken from. */
static uint64_t matter_event_uptime_ms(void)
{
	int64_t ms = ultrawidelock_uptime_ms();

	return ms > 0 ? (uint64_t)ms : 0u;
}

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_ANCHOR)
void matter_commission_record_alarm(uint8_t alarm_code)
{
	ultrawidelock_mutex_lock(&s_owner_lock);
	/*
	 * Locked or nothing. The sensors report about the DOOR; only this file
	 * knows what the bolt is supposed to be doing, and an alarm about a door
	 * the owner deliberately left open is the kind of event that teaches a
	 * controller's owner to mute the accessory.
	 */
	if (s_info.lock_state == MATTER_DL_LOCK_STATE_LOCKED) {
		matter_clusters_record_alarm(&s_info, alarm_code);
		LOG_WRN("door alarm %u recorded", (unsigned int)alarm_code);
		/*
		 * Nothing about the bolt changed -- this only asks for the
		 * report that will carry the event, and re-drives the lock LED
		 * to the value it already has.
		 */
		notify_lock_state_changed();
	}
	ultrawidelock_mutex_unlock(&s_owner_lock);
}
#endif

static void on_ultrawidelock_lock_state(bool unlocked)
{
	uint8_t want = unlocked ? MATTER_DL_LOCK_STATE_UNLOCKED : MATTER_DL_LOCK_STATE_LOCKED;

	ultrawidelock_mutex_lock(&s_owner_lock);
	if (s_info.lock_state == want) {
		goto out;
	}
	s_info.lock_state = want;
	/*
	 * A walk-up belongs to no fabric and to no node: the credential exchange
	 * is the reader's own and no controller asked for it. The credential
	 * source is exactly what the spec's enum has that value for.
	 */
	matter_clusters_record_lock_operation(&s_info,
					      unlocked ? MATTER_DL_LOCK_OP_UNLOCK
						       : MATTER_DL_LOCK_OP_LOCK,
					      MATTER_DL_OP_SOURCE_ALIRO, 0u, 0u);
	LOG_INF("Credential %s the lock; telling Matter", unlocked ? "opened" : "relocked");
	notify_lock_state_changed();
out:
	ultrawidelock_mutex_unlock(&s_owner_lock);
}

/** The session serving the datagram in flight; 0 when it arrived over BLE. */
static uint16_t current_session_id(void)
{
	if (s_thread_reply != NULL && s_case_cur < MATTER_CASE_SESSIONS &&
	    s_case_ready[s_case_cur]) {
		return s_case_x[s_case_cur].local_session_id;
	}
	return 0u;
}

/** The subscription @p session_id holds, or NULL. */
static struct sub_state *sub_of_session(uint16_t session_id)
{
	for (uint8_t i = 0u; i < MATTER_CASE_SESSIONS; i++) {
		if (s_subs[i].in_use && s_subs[i].session_id == session_id) {
			return &s_subs[i];
		}
	}
	return NULL;
}

static void tx_effect_finish(struct matter_tx_slot *slot, int status)
{
	struct tx_effect effect;

	if (slot == NULL || tx_slot_index(slot) >= MATTER_TX_SLOTS) {
		return;
	}
	effect = s_tx_effects[tx_slot_index(slot)];
	memset(&s_tx_effects[tx_slot_index(slot)], 0, sizeof(s_tx_effects[0]));
	if (effect.kind == TX_EFFECT_READ) {
		(void)matter_im_read_pool_finish(&s_read_pool, effect.session_id,
						 effect.exchange_id, effect.over_thread,
						 effect.emitted, effect.more, status);
		return;
	}
	if (effect.kind == TX_EFFECT_SUB_PRIME) {
		struct sub_state *sub = sub_of_session(effect.session_id);

		if (sub == NULL || sub->id != effect.subscription_id) {
			return;
		}
		if (status != MATTER_OK) {
			sub->in_use = false;
			return;
		}
		sub->sent = (uint16_t)(sub->sent + effect.emitted);
		sub->more = effect.more;
		return;
	}
	if (effect.kind == TX_EFFECT_SUB_RESPONSE) {
		struct sub_state *sub = sub_of_session(effect.session_id);
		uint8_t cslot;

		if (sub == NULL || sub->id != effect.subscription_id) {
			return;
		}
		if (status != MATTER_OK) {
			sub->in_use = false;
			return;
		}
		sub->priming = false;
		sub->active = true;
		cslot = case_slot_of(sub->session_id);
		if (cslot < MATTER_CASE_SESSIONS) {
			sub_persist_save((uint8_t)(sub - s_subs), sub,
					 s_case_x[cslot].peer_op_node_id, s_case_fabric[cslot]);
		}
		subscription_heartbeat_arm();
	}
}

static void tx_thread_finish(int status)
{
	uint32_t token = s_thread_tx_token;
	struct matter_tx_slot *slot;
	struct tx_thread_owner *owner;

	s_thread_tx_token = 0u;
	slot = matter_tx_pool_find(&s_tx_pool, token);
	if (slot == NULL || slot->transport != TX_TRANSPORT_THREAD ||
	    slot->state != MATTER_TX_SLOT_IN_FLIGHT) {
		return;
	}
	owner = &s_tx_thread_owner[tx_slot_index(slot)];
	if (status == MATTER_OK) {
		tx_effect_finish(slot, MATTER_OK);
		memset(owner, 0, sizeof(*owner));
		(void)matter_tx_pool_complete(&s_tx_pool, token);
	} else if (owner->retryable) {
		/* MRP will repeat the request. Keep the exact sealed packet and its
		 * deferred cursor/subscription effect until that retry is accepted.
		 * The longest current idle schedule, at maximum jitter, bounds the
		 * retention; later failures cannot extend its first deadline. */
		(void)matter_tx_pool_retry(
			&s_tx_pool, token, tx_now_ms(),
			matter_mrp_retry_horizon_ms(MATTER_MRP_IDLE_INTERVAL_MS));
		/* One wake at the earliest absolute deadline makes the bound real
		 * even when no later packet arrives to drive demand reaping. */
		tx_thread_reap_schedule_owned(tx_now_ms());
	} else {
		tx_effect_finish(slot, MATTER_E_STATE);
		memset(owner, 0, sizeof(*owner));
		(void)matter_tx_pool_reject(&s_tx_pool, token);
	}
}

static void tx_thread_reap_schedule_owned(uint32_t now_ms)
{
	uint32_t next_deadline = 0u;
	bool have_next = false;

	for (size_t i = 0u; i < MATTER_TX_SLOTS; i++) {
		const struct matter_tx_slot *slot = &s_tx_slots[i];

		if (slot->transport != TX_TRANSPORT_THREAD ||
		    slot->state != MATTER_TX_SLOT_READY || !slot->retry_deadline_set) {
			continue;
		}
		if (!have_next || (int32_t)(slot->retry_deadline_ms - next_deadline) < 0) {
			next_deadline = slot->retry_deadline_ms;
			have_next = true;
		}
	}
	if (have_next) {
		int32_t delay_ms = (int32_t)(next_deadline - now_ms);

		(void)k_work_reschedule(&s_thread_reap_work,
						delay_ms <= 0 ? K_NO_WAIT : K_MSEC(delay_ms));
	}
}

static void tx_thread_reap_work_fn(struct k_work *work)
{
	uint32_t now_ms;

	ARG_UNUSED(work);
	ultrawidelock_mutex_lock(&s_owner_lock);
	now_ms = tx_now_ms();
	tx_thread_reap_expired(now_ms);
	tx_thread_reap_schedule_owned(now_ms);
	ultrawidelock_mutex_unlock(&s_owner_lock);
}

static void tx_thread_reap_expired(uint32_t now_ms)
{
	struct matter_tx_slot *slot;

	while ((slot = matter_tx_pool_expired(&s_tx_pool, TX_TRANSPORT_THREAD, now_ms)) != NULL) {
		struct tx_thread_owner *owner = &s_tx_thread_owner[tx_slot_index(slot)];

		LOG_WRN("reaping abandoned Thread reply token %u", (unsigned int)slot->token);
		tx_effect_finish(slot, MATTER_E_STATE);
		memset(owner, 0, sizeof(*owner));
		(void)matter_tx_pool_reject(&s_tx_pool, slot->token);
	}
}

static bool tx_thread_retry(struct matter_exchange *x)
{
	uint16_t session_id = x->secure ? x->local_session_id : 0u;

	tx_thread_reap_expired(tx_now_ms());

	for (size_t i = 0u; i < MATTER_TX_SLOTS; i++) {
		struct matter_tx_slot *slot = &s_tx_slots[i];
		const struct tx_thread_owner *owner = &s_tx_thread_owner[i];

		if (slot->transport != TX_TRANSPORT_THREAD ||
		    slot->state != MATTER_TX_SLOT_READY || !owner->retryable ||
		    owner->session_id != session_id || owner->exchange_id != x->exchange_id ||
		    owner->request_counter != x->ack_counter || slot->len > s_thread_reply_cap) {
			continue;
		}
		memcpy(s_thread_reply, slot->data, slot->len);
		s_thread_reply_len = slot->len;
		if (matter_tx_slot_in_flight(slot) != MATTER_OK) {
			s_thread_reply_len = 0u;
			return false;
		}
		s_thread_tx_token = slot->token;
		return true;
	}
	return false;
}

void matter_commission_ble_tx_complete(int status)
{
	struct matter_tx_slot *slot;
	uint32_t token;

	ultrawidelock_mutex_lock(&s_owner_lock);
	token = s_ble_tx_token;
	s_ble_tx_token = 0u;
	slot = matter_tx_pool_find(&s_tx_pool, token);
	if (slot != NULL) {
		tx_effect_finish(slot, status == 0 ? MATTER_OK : MATTER_E_STATE);
		if (status == 0) {
			(void)matter_tx_pool_complete(&s_tx_pool, token);
			(void)tx_ble_pump();
		} else {
			(void)matter_tx_pool_reject(&s_tx_pool, token);
			/* A failed indication/reset invalidates the link state. Reject
			 * queued packets rather than leaking their slots or sending stale
			 * exchange responses after a reconnect. */
			for (;;) {
				slot = matter_tx_pool_ready(&s_tx_pool, TX_TRANSPORT_BLE);
				if (slot == NULL) {
					break;
				}
				tx_effect_finish(slot, MATTER_E_STATE);
				(void)matter_tx_pool_reject(&s_tx_pool, slot->token);
			}
		}
	}
	ultrawidelock_mutex_unlock(&s_owner_lock);
}

/**
 * Mark the subscription holding session_id as no longer in use, or return silently if no
 * subscription holds that session ID.
 */
static void sub_drop_session(uint16_t session_id)
{
	struct sub_state *s = sub_of_session(session_id);

	if (s != NULL) {
		s->in_use = false;
	}
}

static void reader_readback_clear(void)
{
	memset(s_info.users, 0, sizeof(s_info.users));
	memset(s_info.ultrawidelock_verification_key, 0,
	       sizeof(s_info.ultrawidelock_verification_key));
	memset(s_info.ultrawidelock_group_id, 0, sizeof(s_info.ultrawidelock_group_id));
	memset(s_info.ultrawidelock_group_resolving_key, 0,
	       sizeof(s_info.ultrawidelock_group_resolving_key));
	s_info.have_ultrawidelock_group_resolving_key = false;
	s_info.have_ultrawidelock_reader_config = false;
}

/** Revoke every live and persisted session resource owned by one removed fabric. */
static void case_drop_fabric(uint8_t fabric_index)
{
	struct sub_persist tombstone = {0};

	for (uint8_t i = 0u; i < MATTER_CASE_SESSIONS; i++) {
		char key[SUB_KEY_MAX];

		if (s_case_ready[i] && s_case_fabric[i] == fabric_index) {
			uint16_t session_id = s_case_x[i].local_session_id;

			sub_drop_session(session_id);
			memset(&s_case_x[i], 0, sizeof(s_case_x[i]));
			s_case_ready[i] = false;
			s_case_fabric[i] = 0u;
			memset(s_case_cats[i], 0, sizeof(s_case_cats[i]));
			s_case_cat_count[i] = 0u;
		}
		if (!s_dormant[i].used || s_dormant[i].fabric_index != fabric_index) {
			continue;
		}
		memset(&s_dormant[i], 0, sizeof(s_dormant[i]));
		(void)snprintf(key, sizeof(key), SUB_KEY_FMT, (unsigned int)i);
		if (settings_save_one(key, &tombstone, sizeof(tombstone)) != 0) {
			LOG_WRN("  removed fabric %u subscription tombstone not persisted",
				(unsigned int)fabric_index);
		}
	}
	if (!matter_commission_has_fabric()) {
		/* The storage worker already reverted the reader core before it
		 * made the last-fabric tombstone authoritative. Clear the cluster's
		 * readback copy too, so the next home cannot observe the old one. */
		reader_readback_clear();
	}
	ultrawidelock_ble_readvertise();
}

/**
 * The slot for a new subscription from @p session_id.
 *
 * Re-subscribing on a session REPLACES what that session already had, rather
 * than taking a second slot: a controller that asks again has abandoned the
 * first, and letting one peer hold several is how a table of six starves at
 * two controllers -- the same failure this table exists to end.
 */
static struct sub_state *sub_alloc(uint16_t session_id)
{
	struct sub_state *s = sub_of_session(session_id);
	uint8_t i;

	if (s != NULL) {
		return s;
	}
	for (i = 0u; i < MATTER_CASE_SESSIONS; i++) {
		if (!s_subs[i].in_use) {
			return &s_subs[i];
		}
	}
	i = s_sub_next_victim;
	s_sub_next_victim = (uint8_t)((s_sub_next_victim + 1u) % MATTER_CASE_SESSIONS);
	LOG_WRN("  all %u subscription slots live; dropping 0x%08x", MATTER_CASE_SESSIONS,
		(unsigned int)s_subs[i].id);
	return &s_subs[i];
}

/**
 * Send one chunk of the priming report.
 *
 * The whole data model does not fit one Matter message -- the spec caps a
 * message at the IPv6 MTU and this node's answer measured 1479 bytes of payload
 * against a ~1232 byte ceiling. An oversized datagram is not slow, it is never
 * delivered, and the subscriber re-subscribes forever with nothing to say why.
 */
static void send_report_chunk(struct sub_state *s)
{
	struct matter_im_report_stats stats;
	struct matter_tx_slot *slot = tx_acquire();
	uint8_t *payload;
	size_t payload_cap;
	size_t report_len = 0u;
	bool more = false;
	uint16_t emitted = 0u;
	int rc;

	if (slot == NULL) {
		LOG_ERR("no owned packet slot for subscription ReportData");
		s->in_use = false;
		return;
	}
	payload = tx_payload(slot, &payload_cap);
	rc = matter_im_report_data_chunk(&s_im, &s->read, s->sent, payload,
					 payload_cap, &report_len, &more, &emitted,
					 &stats);
	if (rc != MATTER_OK) {
		LOG_ERR("cannot build the report chunk (%d)", rc);
		tx_abort_build(slot);
		return;
	}
	if (emitted == 0u && more) {
		/* Not a chunk boundary -- one report is larger than a whole
		 * message, and no number of chunks will help. */
		LOG_ERR("a single attribute does not fit a message; giving up");
		tx_abort_build(slot);
		s->more = false;
		return;
	}
	/*
	 * INF, not DBG: an undersized chunk count is the only visible symptom of
	 * a report that frames cleanly and is then dropped by the network, and
	 * debug level is off in every image that gets flashed.
	 */
	LOG_INF("  chunk %u B, %u report(s), %u total, %s", (unsigned int)report_len, emitted,
		(unsigned int)(s->sent + emitted), more ? "MORE" : "last");
	s_tx_effects[tx_slot_index(slot)] = (struct tx_effect){
		.kind = TX_EFFECT_SUB_PRIME,
		.session_id = s->session_id,
		.emitted = emitted,
		.subscription_id = s->id,
		.more = more,
	};
	if (tx_frame(slot,
		     (s_thread_reply != NULL && !s_thread_pase) ? &s_case_x[s_case_cur] : &s_exchange,
		     MATTER_PROTOCOL_INTERACTION_MODEL, MATTER_IM_OP_REPORT_DATA, payload, report_len,
		     false, 0u) != MATTER_OK) {
		s->in_use = false;
	}
}

/**
 * Begin a subscription.
 *
 * The order is not the obvious one. A SubscribeRequest is answered with the
 * REPORT, not with the SubscribeResponse: the subscriber acknowledges that
 * report with a StatusResponse, and only then is the SubscribeResponse sent
 * (ReadHandler.cpp:240-250). Answering the request directly leaves the
 * subscriber holding an id for a subscription whose initial values never
 * arrived, which is indistinguishable from a node that stopped reporting.
 */
static void on_subscribe_request(const struct matter_exchange_in *in)
{
	static struct matter_im_subscribe sub;
	struct matter_thread_peer peer;
	int rc;

	rc = matter_im_subscribe_request_decode(in->payload, in->payload_len, &sub);
	if (rc != MATTER_OK) {
		LOG_WRN("unreadable SubscribeRequest (%d), %u B", rc, (unsigned int)in->payload_len);
		return;
	}
	matter_thread_peer_current(&peer);

	struct sub_state *s = sub_alloc(current_session_id());

	s->session_id = current_session_id();
	s->in_use = true;
	s->peer = peer;
	s->read = sub.read;
	/*
	 * Any non-zero id will do -- it is this node's handle and the subscriber
	 * only ever echoes it back. Counted rather than random so two
	 * subscriptions in one boot cannot collide, and never zero because zero
	 * is how a plain read is told apart from a priming report.
	 */
	s->id = ++s_sub_next_id;
	/*
	 * The ceiling is the subscriber's limit, not a request: reporting later
	 * than this is what makes a subscription dead. Committing to it exactly
	 * is honest only if this node then reports on time -- see the note in
	 * on_status_response().
	 *
	 * It is a CEILING, so granting less is legal, and less is worth having.
	 * The granted interval is also the subscriber's liveness timer, and this
	 * node's subscriptions live in RAM: a reset destroys all of them while
	 * the controller still believes in every one. Until then it will not
	 * re-subscribe, and a Home tile that sends UnlockDoor gets acceptance
	 * and never a LockState report -- measured 2026-08-02 as a tile stuck on
	 * "Unlocking" for the ten minutes Apple's requested 600 s bought, after
	 * every single flash.
	 *
	 * 180 s costs NOTHING to keep: the heartbeat below already reports every
	 * SUBSCRIPTION_HEARTBEAT_S, well inside it. Going lower would mean
	 * lowering the heartbeat too, and that is a real trade on a sleepy end
	 * device -- four times the report traffic to save two more minutes.
	 *
	 * The proper fix is persisting subscriptions and resuming them, which
	 * needs a CASE initiator this node does not have. This is the cheap
	 * third of it.
	 */
	s->max_interval_s = sub.max_interval_s;
	if (s->max_interval_s > SUBSCRIPTION_MAX_INTERVAL_S &&
	    sub.min_interval_s <= SUBSCRIPTION_MAX_INTERVAL_S) {
		s->max_interval_s = SUBSCRIPTION_MAX_INTERVAL_S;
	}
	s->read.subscription_id = s->id;
	s->priming = true;
	s->active = false;

	LOG_INF("  subscribe: %u path(s), %u..%u s, id 0x%08x, session 0x%04x", s->read.n_paths,
		sub.min_interval_s, sub.max_interval_s, (unsigned int)s->id,
		(unsigned int)s->session_id);
	/*
	 * WHICH path, not just how many. A subscription to something this node
	 * answers with silence produces a priming report that is structurally
	 * perfect and empty, and a subscriber waiting on a value that will never
	 * come looks exactly like a subscriber that never got the report.
	 */
	for (uint8_t i = 0; i < s->read.n_paths; i++) {
		const struct matter_im_path *p = &s->read.paths[i];

		LOG_INF("  sub[%u] endpoint %d cluster 0x%04x attribute 0x%04x", i,
			p->have_endpoint ? (int)p->endpoint : -1,
			p->have_cluster ? (unsigned int)p->cluster : 0xFFFFu,
			p->have_attribute ? (unsigned int)p->attribute : 0xFFFFu);
	}

	s->sent = 0u;
	s->more = false;
	send_report_chunk(s);
}

/**
 * The subscriber acknowledged the priming report, so the subscription exists.
 *
 * The StatusResponse is not inspected beyond its arrival: a subscriber that
 * rejected the report would say so by not sending one.
 */
/**
 * A TimedRequest, which is a handshake and not a request for anything.
 *
 * The peer sends it, waits for a StatusResponse, and only then sends the invoke
 * it actually wanted -- so a node that ignores it is not refusing the command,
 * it is never being asked. That is what a real controller saw: it sat for its
 * full 9,999 ms and reported the transaction as timed out, twice, with this
 * node logging the message as "unhandled" and nothing as an error.
 *
 * SUCCESS is the whole answer. Matter uses this to stop a command that must not
 * be replayed from being replayed, and the deadline it announces belongs to the
 * peer: it is measured from when this reply arrives. Nothing here enforces it.
 * Enforcing it would mean answering a late invoke with TIMEOUT rather than
 * running it, which is a promise worth making only once there is a clock to
 * make it with.
 */
/**
 * Where the reader identity Apple delivered actually lands.
 *
 * This is the end of the road the whole Matter node was built for: until now
 * the reader's private key was CONFIG_ULTRAWIDELOCK_PROV_SEED_HEX, a build-time string,
 * so every image carried one identity and unlocked only for the phones enrolled
 * in whoever built it. After this call the device has its own, in NVS, and a
 * Wallet key survives a power cycle.
 *
 * reader_id is groupIdentifier || groupSubIdentifier, which is the layout
 * ultrawidelock_reader_provision_identity documents (ultrawidelock_reader.h:152-156). The
 * sub-identifier is this node's own and is the same one the credential attributes
 * report, so the pair a controller reads back is the pair that was stored.
 *
 * The verification key is not passed on: it is the public half of the signing
 * key and the reader derives it. It is kept only so the attribute can be read
 * back.
 *
 * NOTHING IS LOGGED but the outcome. Every argument is key material.
 */
/**
 * A credential public key, handed to the reader's trust store -- but only
 * if it is a key a phone will ever present.
 *
 * The trust check is a raw-key allowlist (ultrawidelock_reader.c), so an anchor is a
 * claim that some device will present exactly these 65 bytes. An ISSUER key
 * never will: it identifies the home that certifies credentials, not a device.
 * Storing it produced a reader that reported "1 trust anchor(s)", looked
 * provisioned, and rejected every phone one step after "device signature OK" --
 * measured across three pairings on 2026-08-02, where the stored anchor was
 * byte-identical every time and the presented key was different every time.
 *
 * The ESP32 lock, which is the working reference in this repo, has always gated
 * this on the two endpoint types (door_lock_callbacks.cpp:112-114). This is that
 * rule, arrived at the long way round.
 *
 * The issuer key is still ACCEPTED: refusing it would tell the controller this
 * node cannot hold one, which is a different and equally untrue claim. It is
 * simply not an anchor. An empty store is the honest report of a reader no
 * phone can open yet, and it is what makes the next endpoint key visible.
 */
/*
 * The cluster reports NumberOfAliroEndpointKeysSupported from its own constant,
 * because ultrawidelock_matter must not include the reader's headers. This is where the
 * two meet: a controller told it may install more endpoint keys than the trust
 * store holds will have the surplus silently evicted, which is the failure that
 * once locked a re-paired reader out for good.
 */
BUILD_ASSERT(MATTER_ALIRO_ENDPOINT_KEYS_SUPPORTED == ULTRAWIDELOCK_TRUST_MAX,
	     "reported endpoint-key cap must equal the trust store it describes");

static int on_ultrawidelock_credential(uint8_t credential_type, const uint8_t public_key[65],
			       uint16_t credential_index, uint16_t user_index)
{
	if (credential_type == MATTER_DL_CRED_ALIRO_ISSUER_KEY) {
		LOG_INF("  CREDENTIAL issuer key accepted, NOT an anchor (type %u)",
			(unsigned int)credential_type);
		return 0;
	}

	int rc = ultrawidelock_reader_provision_add_trust(public_key, credential_type, credential_index,
						  user_index);

	if (rc < 0) {
		LOG_ERR("  credential type %u REFUSED (%d)", (unsigned int)credential_type, rc);
		return rc;
	}
	LOG_INF("  CREDENTIAL %s (type %u, cred idx %u, user idx %u)",
		rc == 1 ? "already present" : "ADDED", (unsigned int)credential_type,
		(unsigned int)credential_index, (unsigned int)user_index);
	return 0;
}

/**
 * Matter ClearCredential: stop honouring one credential, or every one of them.
 *
 * An issuer key was never an anchor, so clearing one is already true and says so without touching
 * the store. Everything else resolves through the credential index the SetCredential recorded.
 * Returns 0 only when the removal is persisted, because the cluster turns anything else into a
 * FAILURE the admin can act on.
 */
static int on_ultrawidelock_credential_clear(uint8_t credential_type, uint16_t credential_index)
{
	if (credential_type == MATTER_DL_CRED_ALIRO_ISSUER_KEY) {
		LOG_INF("  CREDENTIAL CLEAR issuer key: never an anchor, nothing to revoke");
		return 0;
	}
	if (credential_index == MATTER_DL_INDEX_ALL) {
		/* remove_type clears BY TYPE: with a real type only anchors
		 * carrying it go, so clearing every evictable key leaves the
		 * non-evictable ones. Type 0 is the cluster's "every type" and is
		 * wider than that -- it takes every anchor in the store, including
		 * the ones no Matter index ever named, such as a bench add. */
		int rc = ultrawidelock_reader_provision_remove_type(credential_type);

		if (rc < 0) {
			LOG_ERR("  CREDENTIAL CLEAR type %u NOT PERSISTED",
				(unsigned int)credential_type);
			return -1;
		}
		LOG_WRN("  CREDENTIAL CLEAR type %u revoked %d anchor(s)", (unsigned int)credential_type,
			rc);
		return 0;
	}

	int rc = ultrawidelock_reader_provision_remove_trust(credential_type, credential_index);

	LOG_WRN("  CREDENTIAL CLEAR credential type %u index %u -> %s", (unsigned int)credential_type,
		(unsigned int)credential_index,
		rc < 0 ? "NOT PERSISTED" : (rc == 1 ? "no such anchor" : "REVOKED"));
	return rc < 0 ? -1 : 0;
}

/**
 * Matter ClearUser: drop every credential bound to a user, or to all users.
 *
 * The user row itself is the cluster's to forget; this is only the trust store half. Returns 0 only
 * when the removal is persisted.
 */
static int on_ultrawidelock_user_clear(uint16_t user_index)
{
	int rc = ultrawidelock_reader_provision_remove_user(user_index);

	if (rc < 0) {
		LOG_ERR("  CREDENTIAL CLEAR user index %u NOT PERSISTED", (unsigned int)user_index);
		return -1;
	}
	LOG_WRN("  CREDENTIAL CLEAR user index %u revoked %d anchor(s)", (unsigned int)user_index, rc);
	return 0;
}

/**
 * Complete credential reader provisioning from a Matter commissioning exchange. Store the reader
 * identity (derived from the group ID and group sub-ID) and the signing key into the credential
 * reader engine, retire the device key, and log success or error.
 */
static int on_ultrawidelock_reader_config(const uint8_t signing_key[32],
				  const uint8_t verification_key[65], const uint8_t group_id[16],
				  const uint8_t *group_resolving_key)
{
	uint8_t reader_id[32];
	int rc;

	ARG_UNUSED(verification_key);

	memcpy(reader_id, group_id, 16u);
	memcpy(reader_id + 16, s_info.ultrawidelock_group_sub_id, 16u);

	rc = ultrawidelock_reader_provision_identity(reader_id, signing_key, group_resolving_key);
	memset(reader_id, 0, sizeof(reader_id));
	if (rc != 0) {
		LOG_ERR("  reader identity NOT stored (%d)", rc);
		return rc;
	}
	LOG_INF("  CREDENTIAL READER PROVISIONED: identity stored, dev key retired");
	return 0;
}

/**
 * Handle an incoming Matter TimedRequest. Decodes the timeout and answers with a StatusResponse of
 * SUCCESS.
 */
static void on_timed_request(const struct matter_exchange_in *in)
{
	struct matter_tx_slot *slot;
	uint8_t *payload;
	size_t payload_cap;
	uint16_t timeout_ms = 0u;
	size_t resp_len = 0u;

	if (matter_im_timed_request_decode(in->payload, in->payload_len, &timeout_ms) != MATTER_OK) {
		LOG_WRN("  malformed TimedRequest");
		return;
	}
	LOG_INF("  timed request: %u ms, answering SUCCESS", (unsigned int)timeout_ms);

	slot = tx_acquire();
	if (slot == NULL) {
		LOG_ERR("  no owned packet slot for StatusResponse");
		return;
	}
	payload = tx_payload(slot, &payload_cap);
	if (matter_im_status_response_encode(MATTER_IM_STATUS_SUCCESS, payload, payload_cap,
					     &resp_len) != MATTER_OK) {
		LOG_ERR("  cannot encode the StatusResponse");
		tx_abort_build(slot);
		return;
	}
	(void)tx_frame(slot,
		       (s_thread_reply != NULL && !s_thread_pase) ? &s_case_x[s_case_cur] : &s_exchange,
		       MATTER_PROTOCOL_INTERACTION_MODEL, MATTER_IM_OP_STATUS_RESPONSE, payload, resp_len,
		       false, 0u);
}

/**
 * Handle a StatusResponse in a subscription priming sequence: send the next report chunk if more
 * remain, or finalize the subscription, persist it to settings storage, and arm periodic
 * heartbeats.
 */
static void on_status_response(const struct matter_exchange_in *in)
{
	size_t resp_len = 0u;
	uint8_t status = MATTER_IM_STATUS_FAILURE;
	uint16_t session_id = current_session_id();
	struct matter_im_read_state *read =
		read_state_find(session_id, in->exchange_id, s_thread_reply != NULL);
	/*
	 * WHOSE StatusResponse. With one subscription this was implicit, and it
	 * was wrong the moment a second controller arrived: the acknowledgement
	 * belongs to the session it came in on, and answering it out of another
	 * subscriber's state chunks the wrong report to the wrong peer.
	 */
	struct sub_state *s = sub_of_session(session_id);

	if (matter_im_status_response_decode(in->payload, in->payload_len, &status) != MATTER_OK ||
	    status != MATTER_IM_STATUS_SUCCESS) {
		LOG_WRN("invalid or unsuccessful StatusResponse");
		if (read != NULL) {
			read->in_use = false;
		}
		return;
	}

	/* Intermediate plain-Read chunks ask for a StatusResponse. Match both
	 * session and exchange before advancing, so an unrelated interaction
	 * cannot consume this cursor. */
	if (read != NULL && read->more) {
		send_read_chunk(read);
		return;
	}

	if (s == NULL) {
		return;
	}
	/*
	 * Between chunks this is the peer asking for the next one, not the
	 * acknowledgement that ends the priming report. Only the LAST chunk's
	 * StatusResponse establishes the subscription.
	 */
	if (s->more) {
		send_report_chunk(s);
		return;
	}
	if (!s->priming) {
		return;
	}
	struct matter_tx_slot *slot = tx_acquire();
	uint8_t *payload;
	size_t payload_cap;

	if (slot == NULL) {
		LOG_ERR("no owned packet slot for SubscribeResponse");
		s->in_use = false;
		return;
	}
	payload = tx_payload(slot, &payload_cap);
	if (matter_im_subscribe_response_encode(s->id, s->max_interval_s, payload,
						payload_cap, &resp_len) != MATTER_OK) {
		LOG_ERR("cannot build the SubscribeResponse");
		tx_abort_build(slot);
		s->in_use = false;
		return;
	}
	LOG_INF("  subscription 0x%08x ESTABLISHED on session 0x%04x, max interval %u s",
		(unsigned int)s->id, (unsigned int)s->session_id, s->max_interval_s);
	s_tx_effects[tx_slot_index(slot)] = (struct tx_effect){
		.kind = TX_EFFECT_SUB_RESPONSE,
		.session_id = s->session_id,
		.subscription_id = s->id,
	};
	if (tx_frame(slot,
		     (s_thread_reply != NULL && !s_thread_pase) ? &s_case_x[s_case_cur] : &s_exchange,
		     MATTER_PROTOCOL_INTERACTION_MODEL, MATTER_IM_OP_SUBSCRIBE_RESPONSE, payload, resp_len,
		     false, 0u) != MATTER_OK) {
		s->in_use = false;
	}
}

static void on_secure(const struct matter_exchange_in *in)
{
	/*
	 * A bare acknowledgement asks nothing. Named here rather than left to
	 * the unhandled case at the bottom, which spent three log lines per ack
	 * -- and there is one after every message -- reporting that nothing
	 * needed doing. That is what kept filling the trace ring.
	 */
	if (in->protocol_id == MATTER_PROTOCOL_SECURE_CHANNEL &&
	    in->opcode == MATTER_SC_OP_ACK) {
		return;
	}

	if (in->protocol_id == MATTER_PROTOCOL_INTERACTION_MODEL &&
	    in->opcode == MATTER_IM_OP_READ_REQUEST) {
		on_read_request(in);
		return;
	}
	if (in->protocol_id == MATTER_PROTOCOL_INTERACTION_MODEL &&
	    in->opcode == MATTER_IM_OP_INVOKE_COMMAND_REQUEST) {
		on_invoke_request(in);
		return;
	}
	if (in->protocol_id == MATTER_PROTOCOL_INTERACTION_MODEL &&
	    in->opcode == MATTER_IM_OP_WRITE_REQUEST) {
		on_write_request(in);
		return;
	}
	if (in->protocol_id == MATTER_PROTOCOL_INTERACTION_MODEL &&
	    in->opcode == MATTER_IM_OP_SUBSCRIBE_REQUEST) {
		on_subscribe_request(in);
		return;
	}
	if (in->protocol_id == MATTER_PROTOCOL_INTERACTION_MODEL &&
	    in->opcode == MATTER_IM_OP_STATUS_RESPONSE) {
		on_status_response(in);
		return;
	}
	if (in->protocol_id == MATTER_PROTOCOL_INTERACTION_MODEL &&
	    in->opcode == MATTER_IM_OP_TIMED_REQUEST) {
		on_timed_request(in);
		return;
	}

	/*
	 * Anything else is the next piece of work, and the log line names it so
	 * that piece is aimed rather than guessed -- which is how the read above
	 * came to be written. The payload is dumped for the same reason: its
	 * length is never the useful part.
	 *
	 * Safe to log. These are commissioning messages over a session whose
	 * keys are gone by the time anyone reads the trace, and no PASE secret
	 * is reachable from here.
	 */
	LOG_INF("secure message: protocol 0x%04x opcode 0x%02x, %u B payload (unhandled)",
		(unsigned int)in->protocol_id, in->opcode, (unsigned int)in->payload_len);
	LOG_HEXDUMP_INF(in->payload, in->payload_len, "payload");
}

/**
 * State this node keeps between Sigma1 and Sigma3.
 *
 * One CASE handshake at a time, because there is one commissioner and one
 * fabric. A second Sigma1 arriving mid-handshake overwrites this, which is the
 * correct thing rather than a limitation: a commissioner that resent Sigma1 has
 * abandoned the earlier attempt, and its ephemeral key with it.
 */
static struct {
	uint8_t shared[MATTER_CASE_SECRET_LEN];
	uint8_t eph_priv[32];
	uint8_t eph_pub[MATTER_CASE_PUBKEY_LEN];
	uint8_t responder_random[MATTER_CASE_RANDOM_LEN];
	uint8_t resumption_id[16];
	uint8_t noc_pub[MATTER_CASE_PUBKEY_LEN];
	bool have_noc_pub;
	/*
	 * The initiator's ephemeral key, kept because TBSData3 has to be rebuilt
	 * from it and the Sigma1 that carried it is long gone by then.
	 */
	uint8_t init_eph_pub[MATTER_CASE_PUBKEY_LEN];
	/**
	 * Which fabric this handshake is for, chosen by whichever one's
	 * destination identifier the Sigma1 matched. With two administrators
	 * there are two, and every later step -- the NOC to send, the key to
	 * sign with, the node id in the nonce -- belongs to that one.
	 */
	const struct matter_fabric *fabric;
	/*
	 * The transcript, as a running hash rather than the messages themselves.
	 * Sigma2's salt needs SHA-256(Sigma1), Sigma3's needs
	 * SHA-256(Sigma1 || Sigma2) and the session keys need all three -- and
	 * keeping the ~1.2 KB of messages to re-hash is not affordable here.
	 * Copy the context and finalise the copy to read an intermediate digest;
	 * finalising this one would end the transcript a message early.
	 */
	struct ultrawidelock_sha256 transcript;
	uint16_t peer_session_id;
	uint16_t local_session_id;
	bool active;
	/**
	 * Who this handshake is with, and the exact Sigma2 they were sent.
	 *
	 * A peer that resends Sigma1 must get back the SAME Sigma2: the
	 * transcript its Sigma3 is computed over covers those bytes, and the
	 * signature inside them is randomised, so re-encoding produces a
	 * different message even from identical inputs. Answering a repeat with
	 * a fresh handshake made every following Sigma3 fail the AEAD tag, with
	 * nothing to say why -- observed on hardware as five rejections in a row
	 * and a pairing that hung.
	 */
	uint8_t init_random[MATTER_CASE_RANDOM_LEN];
	uint8_t sigma2[MATTER_CASE_SIGMA2_MAX];
	size_t sigma2_len;
} s_case;


/** The unencrypted Matter message counter for the operational exchange. */
static uint32_t s_case_counter;

/**
 * Build and frame the Sigma2 answering @p s1.
 *
 * @param sigma1 the Sigma1 payload EXACTLY as it arrived -- the transcript hash
 *        is over those bytes, and rebuilding them would be rebuilding something
 *        the peer hashed and this node did not.
 */
static size_t send_sigma2(const struct matter_case_sigma1 *s1, const uint8_t *ipk,
			  const uint8_t *sigma1, size_t sigma1_len,
			  const struct matter_proto_header *req,
			  const struct matter_msg_header *req_mh, uint8_t *reply, size_t cap)
{
	/* The fabric the Sigma1's destination identifier chose. */
	const struct matter_fabric *f = s_case.fabric;
	struct matter_case_sigma2_in in;
	struct matter_msg_header mh;
	struct matter_proto_header ph;
	uint8_t transcript[32];
	size_t s2_len = 0u;
	size_t mh_len = 0u;
	size_t ph_len = 0u;
	bool repeat;
	int rc;

	if (f->icac_len > 0u &&
	    (s_info.icac.owner_index != f->index || s_info.icac.len != f->icac_len)) {
		LOG_ERR("  fabric %u references an unavailable ICAC", (unsigned int)f->index);
		return 0u;
	}

	/*
	 * A repeat of the Sigma1 already answered, recognised by the initiator's
	 * session id AND its random -- the session id alone is 16 bits chosen by
	 * the peer and a fresh handshake may reuse it. Everything below is
	 * skipped: no new ephemeral key, no new randoms, no new session id, and
	 * above all no second ultrawidelock_sha256_update() on the transcript.
	 */
	repeat = s_case.active && s_case.sigma2_len > 0u &&
		 s_case.peer_session_id == s1->initiator_session_id &&
		 memcmp(s_case.init_random, s1->initiator_random, MATTER_CASE_RANDOM_LEN) == 0;

	if (!repeat) {
		/* A new handshake invalidates the stored answer immediately, not
		 * at the end: if the encode below fails, peer_session_id has
		 * already moved on and a stale payload must not look replayable.
		 */
		s_case.sigma2_len = 0u;
	}

	if (!repeat && (ultrawidelock_ec_p256_keygen(s_case.eph_priv, s_case.eph_pub) != 0 ||
	    ultrawidelock_random(s_case.responder_random, sizeof(s_case.responder_random)) != 0 ||
	    ultrawidelock_random(s_case.resumption_id, sizeof(s_case.resumption_id)) != 0 ||
	    ultrawidelock_random((uint8_t *)&s_case.local_session_id, sizeof(s_case.local_session_id)) !=
		    0)) {
		LOG_ERR("  no entropy for Sigma2");
		return 0u;
	}
	/* Session id 0 means "unsecured" on the wire, so it can never be ours. */
	if (s_case.local_session_id == 0u) {
		s_case.local_session_id = 1u;
	}
	s_case.peer_session_id = s1->initiator_session_id;
	/*
	 * Deliberately does NOT tear down established sessions any more. A new
	 * Sigma1 supersedes the previous HANDSHAKE, which is what s_case holds,
	 * but it says nothing about sessions already running: Apple opens the
	 * hub's session while the phone's is still carrying a subscription.
	 * Clearing them here is what made the second administrator silence the
	 * first.
	 */

	/* Start the transcript, and read SHA-256(Sigma1) off a COPY so the
	 * running context stays open for Sigma2 and Sigma3.
	 *
	 * NOT on a repeat, and this guard is the fix the repeat comment above
	 * always demanded: re-initialising here resets the running hash to
	 * Sigma1 alone, the resend branch never re-adds Sigma2, and the peer's
	 * Sigma3 -- computed over Sigma1||Sigma2 -- then fails S3K derivation
	 * with -6. Invisible while the advertised SII was 3000 ms (Apple almost
	 * never retransmitted Sigma1 mid-handshake); routine at SII=500.
	 * Measured on hardware 2026-08-06: three Sigma1s inside 500 ms, the
	 * SAME Sigma2 correctly resent twice, then "Sigma3 REJECTED (-6)" and
	 * the pairing died. */
	if (!repeat) {
		ultrawidelock_sha256_init(&s_case.transcript);
		ultrawidelock_sha256_update(&s_case.transcript, sigma1, sigma1_len);
		{
			struct ultrawidelock_sha256 snapshot = s_case.transcript;

			ultrawidelock_sha256_final(&snapshot, transcript);
		}
		memcpy(s_case.init_eph_pub, s1->initiator_pubkey, sizeof(s_case.init_eph_pub));
	}

	/*
	 * The one assumption nothing has ever checked: that the key this signs
	 * with is the key the NOC certifies. Sigma2 is signed with op_priv and
	 * carries the NOC; if they disagree the peer verifies a signature
	 * against the wrong public key, fails, and says nothing -- which is
	 * indistinguishable from every other way this can go wrong.
	 */
	{
		struct matter_cert_info ci;
		uint8_t derived[MATTER_CASE_PUBKEY_LEN];

		if (ultrawidelock_ec_p256_pub_from_priv(f->op_priv, derived) == 0 &&
		    matter_cert_parse(f->noc, f->noc_len, &ci) == MATTER_OK &&
		    ci.have_public_key) {
			LOG_INF("  signing key %s the NOC; noc %u B, icac %u B",
				memcmp(derived, ci.public_key, sizeof(derived)) == 0
					? "MATCHES"
					: "does NOT match",
				(unsigned int)f->noc_len, (unsigned int)f->icac_len);
			/* Kept so the Sigma2 signature can be verified against
			 * the certificate it ships with. */
			memcpy(s_case.noc_pub, ci.public_key, sizeof(s_case.noc_pub));
			s_case.have_noc_pub = true;
		} else {
			s_case.have_noc_pub = false;
			LOG_WRN("  could not check the signing key against the NOC");
		}
	}

	memset(&in, 0, sizeof(in));
	in.initiator_pubkey = s1->initiator_pubkey;
	in.transcript_hash = transcript;
	in.ipk = ipk;
	in.noc = f->noc;
	in.noc_len = f->noc_len;
	in.icac = f->icac_len > 0u ? s_info.icac.buf : NULL;
	in.icac_len = f->icac_len;
	in.op_priv = f->op_priv;
	in.responder_random = s_case.responder_random;
	in.responder_eph_priv = s_case.eph_priv;
	in.responder_eph_pub = s_case.eph_pub;
	in.resumption_id = s_case.resumption_id;
	in.responder_session_id = s_case.local_session_id;
	in.verify_pub = s_case.have_noc_pub ? s_case.noc_pub : NULL;

	/* Framed after both headers, so the payload lands where it will be sent
	 * from rather than being copied into place afterwards. */
	/*
	 * A DESTINATION node id, and no source. Not symmetry with the Sigma1:
	 * the ephemeral node id belongs to the INITIATOR, and the two directions
	 * carry it in different fields. SessionManager.cpp:296-302 sets the
	 * source on an initiator's message and the destination on a responder's,
	 * both to the same value; the receive side at :763 rejects outright any
	 * unsecured message carrying both or neither.
	 *
	 * Answering with a source node id is what a fresh initiator looks like,
	 * so the peer allocates a NEW unauthenticated session for it
	 * (:772-776 "Assume peer is the initiator, we are the responder") rather
	 * than matching the CASE session waiting on this exchange. The Sigma2 is
	 * then an unsolicited message with no handler, which ExchangeMgr.cpp:411
	 * acknowledges and drops. That is the whole observed symptom: a
	 * StandaloneAck, no StatusReport, and a fresh Sigma1 once the peer's
	 * session times out. None of the payload is ever looked at, which is why
	 * every byte inside it verified and none of it helped.
	 */
	mh.flags = MATTER_MSG_DSIZ_NODE;
	mh.session_id = 0u;
	mh.security_flags = 0u;
	/*
	 * Randomised once, not started at zero. The spec requires the global
	 * unencrypted counter to begin at a random value; Apple's is around
	 * 118 million, and a peer that saw this node restart at 1 would have
	 * every reason to treat the message as a replay of an old one.
	 */
	if (s_case_counter == 0u) {
		if (ultrawidelock_random((uint8_t *)&s_case_counter, sizeof(s_case_counter)) != 0) {
			LOG_ERR("  no entropy for the message counter");
			return 0u;
		}
		s_case_counter &= 0x0FFFFFFFu; /* leave room to increment */
	}
	mh.message_counter = ++s_case_counter;
	mh.source_node_id = 0u;
	/*
	 * The initiator's EPHEMERAL id, echoed from the Sigma1's source field --
	 * not this node's operational node id. It is what keys the peer's
	 * unauthenticated session table, and it is random per handshake, so
	 * there is nothing to derive it from except the message that carried it.
	 */
	mh.dest_node_id = req_mh->source_node_id;
	mh.dest_group_id = 0u;
	rc = matter_msg_header_encode(&mh, reply, cap, &mh_len);
	if (rc != MATTER_OK) {
		LOG_ERR("  cannot frame Sigma2 (%d)", rc);
		return 0u;
	}

	/*
	 * The responder is NOT the exchange initiator, so the I flag stays
	 * clear; it acknowledges the Sigma1 it is answering, and asks to be
	 * acknowledged in turn.
	 */
	ph.exchange_flags = MATTER_EX_FLAG_A | MATTER_EX_FLAG_R;
	ph.opcode = MATTER_OP_CASE_SIGMA2;
	ph.exchange_id = req->exchange_id;
	ph.vendor_id = 0u;
	ph.protocol_id = MATTER_PROTOCOL_SECURE_CHANNEL;
	/* Acknowledging the Sigma1's counter, not a fresh one -- an ack that
	 * names the wrong message is a retransmission trigger, not an ack. */
	ph.ack_counter = req_mh->message_counter;
	rc = matter_proto_header_encode(&ph, reply + mh_len, cap - mh_len, &ph_len);
	if (rc != MATTER_OK) {
		LOG_ERR("  cannot frame Sigma2 protocol header (%d)", rc);
		return 0u;
	}

	if (repeat) {
		/*
		 * The bytes already sent, re-framed. Headers may differ -- this
		 * carries a new message counter and acknowledges the repeated
		 * Sigma1 -- but the PAYLOAD must be identical, because that is
		 * what the peer's transcript already covers.
		 */
		if (s_case.sigma2_len > cap - mh_len - ph_len) {
			LOG_ERR("  no room to resend Sigma2");
			return 0u;
		}
		memcpy(reply + mh_len + ph_len, s_case.sigma2, s_case.sigma2_len);
		memset(transcript, 0, sizeof(transcript));
		LOG_INF("  Sigma1 again -- resending the SAME Sigma2 (%u B, session 0x%04x)",
			(unsigned int)s_case.sigma2_len, (unsigned int)s_case.local_session_id);
		return mh_len + ph_len + s_case.sigma2_len;
	}

	rc = matter_case_sigma2_encode(&in, reply + mh_len + ph_len, cap - mh_len - ph_len, &s2_len,
				       s_case.shared);
	memset(transcript, 0, sizeof(transcript));
	if (rc != MATTER_OK) {
		/* MATTER_E_STATE here now means the signature did not verify
		 * against the NOC's own public key, which is a far more specific
		 * thing than "could not be built". */
		LOG_ERR("  Sigma2 NOT built (%d)%s", rc,
			rc == MATTER_E_STATE ? " -- crypto step failed (sign/verify/ECDH)" : "");
		return 0u;
	}

	s_case.active = true;
	/* Remembered so a resent Sigma1 can be answered with these exact bytes
	 * rather than a fresh handshake the peer's Sigma3 cannot verify. */
	if (s2_len <= sizeof(s_case.sigma2)) {
		memcpy(s_case.sigma2, reply + mh_len + ph_len, s2_len);
		s_case.sigma2_len = s2_len;
		memcpy(s_case.init_random, s1->initiator_random, MATTER_CASE_RANDOM_LEN);
	} else {
		/* Cannot be replayed, so do not pretend it can. */
		s_case.sigma2_len = 0u;
	}
	/* The transcript covers payloads, never headers -- the same rule the
	 * Sigma1 length check above exists to prove. */
	ultrawidelock_sha256_update(&s_case.transcript, reply + mh_len + ph_len, s2_len);
	/*
	 * The first 48 bytes are the whole TLV skeleton: outer structure, the
	 * random, the session id, and the start of the ephemeral key. Enough to
	 * decode offline and settle whether the SHAPE is right, which is the
	 * question no amount of staring at the encoder answers -- and far
	 * cheaper than another pairing attempt.
	 */
	LOG_HEXDUMP_DBG(reply + mh_len + ph_len, s2_len < 48u ? s2_len : 48u, "sigma2 head");
	LOG_INF("  Sigma2 out: %u B payload, %u B total, session 0x%04x", (unsigned int)s2_len,
		(unsigned int)(mh_len + ph_len + s2_len), (unsigned int)s_case.local_session_id);
	return mh_len + ph_len + s2_len;
}

static size_t case_status_report(const struct matter_proto_header *req,
				 const struct matter_msg_header *req_mh, uint8_t *reply,
				 size_t cap);

/**
 * Answer a Sigma3, which ends the handshake.
 *
 * Sigma2 asked the initiator to believe this node; Sigma3 is the initiator
 * proving the same thing back, and it is the last message either side sends in
 * the clear. What follows it is encrypted under keys neither side transmitted,
 * so a mistake here surfaces as silence on the NEXT message rather than as a
 * failure on this one -- which is the reason for the checks logged below.
 */
static size_t handle_sigma3(const uint8_t *sigma3, size_t sigma3_len, const uint8_t *ipk,
			    const struct matter_proto_header *req,
			    const struct matter_msg_header *req_mh, uint8_t *reply, size_t cap)
{
	struct matter_case_sigma3_in in;
	struct matter_case_sigma3_out peer;
	struct matter_session_keys keys;
	uint8_t salt[MATTER_CASE_IPK_LEN + 32u];
	uint8_t digest[32];
	uint8_t slot;
	int rc;

	if (!s_case.active) {
		LOG_WRN("  Sigma3 with no handshake in progress");
		return 0u;
	}
	/*
	 * A retransmitted Sigma3. Re-verifying is impossible as well as
	 * pointless: the transcript that verified the first one was finalised to
	 * derive the session keys, and SHA-256 cannot be finalised twice. The
	 * peer resent because it never saw the StatusReport, so send that again
	 * and touch nothing else.
	 */
	/* Asked of THIS handshake's session id rather than of the node: another
	 * administrator's session being live says nothing about whether this
	 * Sigma3 has already been answered. */
	if (case_slot_of(s_case.local_session_id) < MATTER_CASE_SESSIONS) {
		LOG_DBG("  Sigma3 again -- resending the StatusReport");
		return case_status_report(req, req_mh, reply, cap);
	}

	/* SHA-256(Sigma1 || Sigma2), taken off a COPY so the running context can
	 * go on to absorb this Sigma3 for the session keys below. */
	{
		struct ultrawidelock_sha256 snapshot = s_case.transcript;

		ultrawidelock_sha256_final(&snapshot, digest);
	}

	memset(&in, 0, sizeof(in));
	in.shared = s_case.shared;
	in.ipk = ipk;
	in.transcript_hash = digest;
	in.initiator_eph_pub = s_case.init_eph_pub;
	in.responder_eph_pub = s_case.eph_pub;

	rc = matter_case_sigma3_open(&in, sigma3, sigma3_len, &peer);
	if (rc != MATTER_OK) {
		/* Worth separating: a failed AEAD tag means the key schedule
		 * diverged, a failed signature means it did NOT and the identity
		 * is the problem. Both return MATTER_E_TYPE, so this only
		 * narrows it -- but it narrows it to two. */
		LOG_ERR("  Sigma3 REJECTED (%d)%s", rc,
			rc == MATTER_E_TYPE ? " -- AEAD tag or signature failed" : "");
		return 0u;
	}
	LOG_INF("  Sigma3 VERIFIED: peer node 0x%08x%08x", (unsigned int)(peer.node_id >> 32),
		(unsigned int)peer.node_id);

	/*
	 * The signature proved the sender holds the key its NOC names. This is
	 * what ties that NOC to THIS fabric rather than to another fabric the
	 * same phone also belongs to.
	 */
	if (s_case.fabric == NULL || peer.fabric_id != s_case.fabric->fabric_id) {
		LOG_ERR("  Sigma3 names a different fabric -- refusing");
		return 0u;
	}

	/* Only now can the transcript close, over all three messages. */
	ultrawidelock_sha256_update(&s_case.transcript, sigma3, sigma3_len);
	ultrawidelock_sha256_final(&s_case.transcript, digest);
	memcpy(salt, ipk, MATTER_CASE_IPK_LEN);
	memcpy(&salt[MATTER_CASE_IPK_LEN], digest, sizeof(digest));
	rc = matter_derive_session_keys(s_case.shared, MATTER_CASE_SECRET_LEN, salt, sizeof(salt),
					false, &keys);
	memset(salt, 0, sizeof(salt));
	memset(digest, 0, sizeof(digest));
	if (rc != MATTER_OK) {
		LOG_ERR("  session keys NOT derived (%d)", rc);
		return 0u;
	}

	/*
	 * A fresh exchange object, not the BLE one: this session has its own
	 * counter space, and a counter reused under a new key repeats an AEAD
	 * nonce. The exchange id is released with it, because the commissioner
	 * opens a new exchange for what comes next.
	 */
	{
		uint32_t seed = 0u;

		/* Drawn, not carried over from s_case_counter: that one is the
		 * UNSECURED counter and is on the wire in clear text, so seeding
		 * from it would let a listener predict this session's. */
		if (ultrawidelock_random((uint8_t *)&seed, sizeof(seed)) != 0) {
			LOG_ERR("  no entropy for the session counter");
			memset(&keys, 0, sizeof(keys));
			return 0u;
		}
		/*
		 * A slot, not THE slot. Sessions established earlier stay
		 * live: this node serves a phone and a home hub at once.
		 */
		slot = case_alloc_slot();
		s_case_ready[slot] = false;
		matter_exchange_init(&s_case_x[slot], seed, true);
		rc = matter_exchange_promote(&s_case_x[slot], s_case.local_session_id,
					     s_case.peer_session_id, &keys, seed);
		/*
		 * The nonces. Unlike PASE, a CASE session builds them from the
		 * two OPERATIONAL node ids -- ours when sealing, the peer's when
		 * opening -- and neither appears in any header. Getting this
		 * wrong produces messages that decrypt to nothing with no error
		 * anyone can report.
		 */
		matter_exchange_set_op_node_ids(&s_case_x[slot], s_case.fabric->node_id,
						peer.node_id);
	}
	memset(&keys, 0, sizeof(keys));
	if (rc != MATTER_OK) {
		LOG_ERR("  CASE session NOT installed (%d)", rc);
		return 0u;
	}
	s_case_ready[slot] = true;
	s_case_fabric[slot] = s_case.fabric->index;
	memcpy(s_case_cats[slot], peer.cats, sizeof(s_case_cats[slot]));
	s_case_cat_count[slot] = peer.cat_count;
	/* Replies to THIS Sigma3 are sealed on the unsecured exchange, but the
	 * StatusReport that follows is the last thing that session sends before
	 * the peer starts using the new one, so point the current slot at it. */
	s_case_cur = slot;
	/*
	 * Now that a fabric exists, the advert can stop being the Matter
	 * commissionable payload and become the credential reader tag. Nothing else
	 * re-runs it: ultrawidelock_advertise() is called at boot and on BLE
	 * disconnect, so without this the board stayed commissionable forever
	 * and a phone could never approach-resolve the reader it had just
	 * provisioned -- the Wallet key screen came up blank and nothing
	 * installed.
	 */
	ultrawidelock_ble_readvertise();

	LOG_INF("  CASE ESTABLISHED: local session 0x%04x, peer 0x%04x",
		(unsigned int)s_case.local_session_id, (unsigned int)s_case.peer_session_id);

	/*
	 * The controller is back. If it was subscribed before the reboot, this
	 * is the session that subscription belongs on now -- it will not ask
	 * again until its own liveness timer expires. Runs while the Sigma3
	 * datagram is still current, which is what makes the reply address
	 * available (matter_thread_peer_current).
	 */
	sub_resume_for(slot, s_case_x[slot].peer_op_node_id, s_case_fabric[slot],
		       s_case.local_session_id);
#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_HEAP_PROBE)
	/* The third report point. main.c reads the peak at an unlock grant and
	 * prov_shell.c at an import, and both predate this node: Sigma3 is now
	 * the heaviest crypto this image does, running an ECDH, a signature
	 * verify and three HKDF expansions before the session keys exist. The
	 * peak is cumulative since boot, so reading it HERE covers PASE and both
	 * earlier Sigma stages too. Sizing MBEDTLS_HEAP_SIZE off the unlock
	 * figure alone would miss all of it. */
	{
		size_t used = 0;
		size_t blocks = 0;

		mbedtls_memory_buffer_alloc_max_get(&used, &blocks);
		LOG_INF("  mbedtls heap peak @case: %u B of %u (%u blocks)", (unsigned int)used,
			(unsigned int)CONFIG_MBEDTLS_HEAP_SIZE, (unsigned int)blocks);
	}
#endif

	return case_status_report(req, req_mh, reply, cap);
}

/**
 * The StatusReport that ends CASE.
 *
 * Still unsecured and still addressed to the initiator's ephemeral id: this is
 * the last message before the keys take effect, not the first one after.
 */
static size_t case_status_report(const struct matter_proto_header *req,
				 const struct matter_msg_header *req_mh, uint8_t *reply, size_t cap)
{
	struct matter_msg_header mh;
	struct matter_proto_header ph;
	size_t mh_len = 0u;
	size_t ph_len = 0u;
	size_t sr_len = 0u;

	mh.flags = MATTER_MSG_DSIZ_NODE;
	mh.session_id = 0u;
	mh.security_flags = 0u;
	mh.message_counter = ++s_case_counter;
	mh.source_node_id = 0u;
	mh.dest_node_id = req_mh->source_node_id;
	mh.dest_group_id = 0u;
	if (matter_msg_header_encode(&mh, reply, cap, &mh_len) != MATTER_OK) {
		return 0u;
	}

	ph.exchange_flags = MATTER_EX_FLAG_A | MATTER_EX_FLAG_R;
	ph.opcode = MATTER_SC_OP_STATUS_REPORT;
	ph.exchange_id = req->exchange_id;
	ph.vendor_id = 0u;
	ph.protocol_id = MATTER_PROTOCOL_SECURE_CHANNEL;
	ph.ack_counter = req_mh->message_counter;
	if (matter_proto_header_encode(&ph, reply + mh_len, cap - mh_len, &ph_len) != MATTER_OK) {
		return 0u;
	}
	if (matter_sc_status_report(MATTER_SC_CODE_SUCCESS, reply + mh_len + ph_len,
				    cap - mh_len - ph_len, &sr_len) != MATTER_OK) {
		return 0u;
	}
	LOG_DBG("  StatusReport success out: %u B total", (unsigned int)(mh_len + ph_len + sr_len));
	return mh_len + ph_len + sr_len;
}

/**
 * A datagram on the operational port. Sigma1, so far, and only Sigma1.
 *
 * There is no responder yet, so this answers nothing. What it does establish is
 * the thing that cannot be checked any other way: whether the identity the
 * initiator is asking for is THIS node's. The destination identifier is an HMAC
 * under the fabric's operational IPK, so recomputing it and finding a match
 * proves the whole chain -- AddNOC's IPK, the compressed fabric id derived from
 * the root key, the fabric and node ids out of the NOC -- all agree with what a
 * real commissioner computed independently.
 */
static size_t matter_thread_on_datagram_owned(uint8_t *msg, size_t len, uint8_t *reply,
					       size_t cap)
{
	struct matter_msg_header mh;
	struct matter_proto_header ph;
	struct matter_case_sigma1 s1;
	uint8_t cfid[MATTER_COMPRESSED_FABRIC_LEN];
	uint8_t ipk[MATTER_CASE_IPK_LEN];
	uint8_t want[MATTER_CASE_DEST_ID_LEN];
	size_t mh_len = 0u;
	size_t ph_len = 0u;
	int rc;

	rc = matter_msg_header_decode(msg, len, &mh, &mh_len);
	if (rc != MATTER_OK) {
		LOG_WRN("  not a Matter message (%d)", rc);
		return 0u;
	}

	/*
	 * A non-zero session id means the rest is encrypted, INCLUDING the
	 * protocol header -- so this has to branch before anything tries to read
	 * an opcode out of it. Decoding first is how "protocol 0xe65a opcode
	 * 0xc1" ends up in a log: those are ciphertext bytes being read as a
	 * header.
	 */
	if (mh.session_id != 0u) {
		struct matter_exchange_in in;
		uint8_t slot = case_slot_of(mh.session_id);

		/*
		 * Routed by session id across every live session, not compared
		 * against one. Matching a single session is what made the home
		 * hub's handshake silence the phone: both are legitimate peers
		 * and both keep talking.
		 */
		if (slot >= MATTER_CASE_SESSIONS) {
			/*
			 * The session PASE just built is not in that table -- it
			 * lives on s_exchange, because PASE and CASE promote
			 * different exchanges. Everything a commissioner does
			 * after PASE (AddNOC, the fail-safe, CommissioningComplete)
			 * arrives encrypted under it, so leaving this out would
			 * make PASE over IP succeed and then strand the
			 * commissioner one message later with "not ours".
			 */
			if (s_exchange.secure && s_exchange.local_session_id == mh.session_id) {
				s_thread_reply = reply;
				s_thread_reply_cap = cap;
				s_thread_reply_len = 0u;
				s_thread_pase = true;

				on_message_owned(msg, len);

				s_thread_pase = false;
				s_thread_reply = NULL;
				return s_thread_reply_len;
			}
#if MATTER_FEATURE_CLIENT
			/*
			 * A session this node INITIATED is in none of the tables
			 * above: those hold the sessions it answered. Without
			 * this the bound lock's InvokeResponse is reported as
			 * somebody else's and dropped, and the unlock that was
			 * sent looks from here exactly like one that was ignored.
			 */
			if (matter_client_owns_session(mh.session_id)) {
				return matter_client_on_secure(msg, len, reply, cap);
			}
#endif
			LOG_WRN("  encrypted for session 0x%04x, which is not ours",
				(unsigned int)mh.session_id);
			return 0u;
		}
		s_case_cur = slot;
		/* Whose fabric is asking, for the fabric-scoped attributes. */
		s_info.accessing_fabric_index = s_case_fabric[slot];
		s_info.accessing_node_id = s_case_x[slot].peer_op_node_id;
		memcpy(s_info.accessing_cats, s_case_cats[slot], sizeof(s_info.accessing_cats));
		s_info.accessing_cat_count = s_case_cat_count[slot];
		s_thread_reply = reply;
		s_thread_reply_cap = cap;
		s_thread_reply_len = 0u;

		rc = matter_exchange_recv_in_place(&s_case_x[slot], msg, len, &in);
		if (rc == MATTER_E_DUP) {
			if (!tx_thread_retry(&s_case_x[slot])) {
				(void)send_standalone_ack(&s_case_x[slot]);
			}
		} else if (rc != MATTER_OK) {
			LOG_WRN("  CASE message refused (%d)", rc);
			s_thread_reply_len = 0u;
		} else {
			LOG_DBG("  CASE in: protocol 0x%04x opcode 0x%02x, %u B",
				(unsigned int)in.protocol_id, in.opcode,
				(unsigned int)in.payload_len);
			on_secure(&in);
		}

		s_thread_reply = NULL;
		return s_thread_reply_len;
	}

	rc = matter_proto_header_decode(msg + mh_len, len - mh_len, &ph, &ph_len);
	if (rc != MATTER_OK) {
		LOG_WRN("  no protocol header (%d)", rc);
		return 0u;
	}
	/*
	 * The inbound header, so the reply can be compared against it. A Sigma2
	 * that is rejected without a word back looks identical whether the TLV
	 * is wrong or the framing is, and only one of those is visible here.
	 */
	LOG_DBG("  protocol 0x%04x opcode 0x%02x exchange 0x%04x", (unsigned int)ph.protocol_id,
		ph.opcode, (unsigned int)ph.exchange_id);
	/* Demoted now that the addressing is proven: three lines per datagram
	 * fills the 4 KB trace ring inside one handshake, and a full ring looks
	 * exactly like a board that logged nothing. */
	LOG_DBG("  in hdr: flags 0x%02x sec 0x%02x ctr %u exflags 0x%02x", mh.flags,
		mh.security_flags, (unsigned int)mh.message_counter, ph.exchange_flags);
	LOG_DBG("  in hdr: source node 0x%08x%08x", (unsigned int)(mh.source_node_id >> 32),
		(unsigned int)mh.source_node_id);

	/*
	 * PASE over IP. Every one of these used to fall through to the drop
	 * below, which is why a controller could resolve this node over DNS-SD,
	 * match the discriminator, open the exchange -- and then time out
	 * "waiting for message type 33", the PBKDFParamResponse this node had
	 * decided not to send. Commissioning ran over BLE or not at all.
	 *
	 * Only the three the responder can receive. The even opcodes above them
	 * (0x21, 0x23) are its OWN replies, and accepting one would mean taking
	 * dictation from a peer about a message this node is supposed to author.
	 *
	 * The handler is the one BLE already uses, unchanged: matter_pase_*() and
	 * the exchange layer never knew which transport they were on, and the
	 * only thing that did -- where the reply goes -- is what s_thread_pase
	 * carries. A second copy of the state machine here would be a second
	 * place for the promote-to-secure step to drift.
	 */
	if (ph.protocol_id == MATTER_PROTOCOL_SECURE_CHANNEL &&
	    (ph.opcode == MATTER_PASE_OP_PBKDF_REQ || ph.opcode == MATTER_PASE_OP_PAKE1 ||
	     ph.opcode == MATTER_PASE_OP_PAKE3)) {
		/*
		 * PBKDFParamRequest is by definition the first message of a new
		 * PASE, so whatever the last commissioner left on s_exchange is
		 * finished with. Over BLE the disconnect says this; over IP
		 * there is no disconnect to say it, and without the flag the
		 * second commissioning attempt would be answered on a promoted
		 * exchange that rejects an unsecured message.
		 */
		if (ph.opcode == MATTER_PASE_OP_PBKDF_REQ) {
			s_stale = true;
		}
		s_thread_reply = reply;
		s_thread_reply_cap = cap;
		s_thread_reply_len = 0u;
		s_thread_pase = true;

		on_message_owned(msg, len);

		s_thread_pase = false;
		s_thread_reply = NULL;
		return s_thread_reply_len;
	}

#if MATTER_FEATURE_CLIENT
	/*
	 * The other half of a handshake THIS node started. Routed by exchange
	 * id, because the unsecured session is session 0 for everybody and the
	 * exchange is the only thing separating an answer to this node's Sigma1
	 * from a Sigma1 somebody is sending it. Without this both the Sigma2 and
	 * the StatusReport that ends CASE fall into the drop below, which is
	 * where a client handshake dies with its evidence logged as a curiosity.
	 */
	if (ph.protocol_id == MATTER_PROTOCOL_SECURE_CHANNEL &&
	    (ph.opcode == MATTER_OP_CASE_SIGMA2 || ph.opcode == MATTER_SC_OP_STATUS_REPORT) &&
	    matter_client_owns_exchange(ph.exchange_id)) {
		return matter_client_on_unsecured(msg + mh_len + ph_len, len - mh_len - ph_len, &mh,
						  &ph, reply, cap);
	}
#endif

	if (ph.protocol_id != MATTER_PROTOCOL_SECURE_CHANNEL ||
	    (ph.opcode != MATTER_OP_CASE_SIGMA1 && ph.opcode != MATTER_OP_CASE_SIGMA3)) {
		/*
		 * Not silent any more: what lands here mid-handshake is the
		 * peer's whole verdict on it. Opcode 0x10 is a standalone ack
		 * (the peer HAS the message it acknowledges and owes the next
		 * one); 0x40 is a StatusReport whose payload names the
		 * rejection. Measured 2026-08-06: Sigma2 out, no Sigma3, and
		 * nothing logged in 15 s -- this branch was eating the
		 * evidence either way.
		 */
		LOG_INF("  unsecured drop: protocol 0x%04x opcode 0x%02x exchange 0x%04x ack%s",
			(unsigned int)ph.protocol_id, ph.opcode, (unsigned int)ph.exchange_id,
			(ph.exchange_flags & MATTER_EX_FLAG_A) ? "+" : "-");
		if (len > mh_len + ph_len) {
			LOG_HEXDUMP_INF(msg + mh_len + ph_len,
					MIN(len - mh_len - ph_len, 16u), "  payload");
		}
		return 0u;
	}

	if (!matter_commission_has_fabric()) {
		LOG_WRN("  no fabric to match it against");
		return 0u;
	}
	/*
	 * Sigma3 continues the handshake Sigma1 chose a fabric for. Deriving the
	 * key from a different one would decrypt to nothing, so the choice is
	 * made once, in the Sigma1 branch, and reused here.
	 */
	if (ph.opcode == MATTER_OP_CASE_SIGMA3) {
		if (s_case.fabric == NULL) {
			LOG_WRN("  Sigma3 with no fabric chosen");
			return 0u;
		}
		if (matter_fabric_compressed_id(s_case.fabric->root_public_key,
						s_case.fabric->fabric_id, cfid) != MATTER_OK ||
		    matter_case_operational_ipk(s_case.fabric->ipk, cfid, ipk) != MATTER_OK) {
			LOG_ERR("  could not derive the operational key");
			return 0u;
		}
	}
	/*
	 * The reply is addressed to the id in this field, so its absence is not
	 * a detail to skip past: there would be nothing to address the answer to
	 * and the peer would drop it exactly as it dropped the ones before this.
	 */
	if ((mh.flags & MATTER_MSG_FLAG_S) == 0u) {
		LOG_WRN("  no source node id -- cannot address a reply");
		return 0u;
	}

	if (ph.opcode == MATTER_OP_CASE_SIGMA3) {
		LOG_DBG("  lengths: msg %u = hdr %u + proto %u + payload %u", (unsigned int)len,
			(unsigned int)mh_len, (unsigned int)ph_len,
			(unsigned int)(len - mh_len - ph_len));
		return handle_sigma3(msg + mh_len + ph_len, len - mh_len - ph_len, ipk, &ph, &mh,
				     reply, cap);
	}

	rc = matter_case_sigma1_decode(msg + mh_len + ph_len, len - mh_len - ph_len, &s1);
	if (rc != MATTER_OK) {
		LOG_WRN("  Sigma1 unreadable (%d)", rc);
		return 0u;
	}
	LOG_INF("  Sigma1: initiator session 0x%04x, resumption %s",
		(unsigned int)s1.initiator_session_id, s1.has_resumption ? "offered" : "none");
	/*
	 * The transcript hash is over the Sigma1 payload and nothing else, so
	 * these three have to sum to the datagram. A payload length that is one
	 * byte long or short still decodes -- the TLV ends where it ends -- and
	 * still yields the right destination identifier, but hashes to something
	 * the peer never computed. That failure is completely silent, and this
	 * is the only place it is visible.
	 */
	LOG_DBG("  lengths: msg %u = hdr %u + proto %u + payload %u", (unsigned int)len,
		(unsigned int)mh_len, (unsigned int)ph_len, (unsigned int)(len - mh_len - ph_len));

	/*
	 * WHICH fabric, by trying each. The destination identifier is an HMAC
	 * under a fabric's operational key over the identity being asked for, so
	 * the only way to learn which fabric an initiator means is to recompute
	 * it for each one and look for a match. That is also what stops an
	 * unsolicited Sigma1 enumerating this node's fabrics: get the key wrong
	 * and you learn nothing.
	 */
	s_case.fabric = NULL;
	for (size_t fi = 0u; fi < MATTER_SUPPORTED_FABRICS; fi++) {
		const struct matter_fabric *f = &s_info.fabrics[fi];

		if (f->index == 0u) {
			continue;
		}
		if (matter_fabric_compressed_id(f->root_public_key, f->fabric_id, cfid) !=
			    MATTER_OK ||
		    matter_case_operational_ipk(f->ipk, cfid, ipk) != MATTER_OK ||
		    matter_case_destination_id(ipk, s1.initiator_random, f->root_public_key,
					       f->fabric_id, f->node_id, want) != MATTER_OK) {
			LOG_ERR("  could not recompute the destination identifier");
			return 0u;
		}
		if (memcmp(want, s1.destination_id, sizeof(want)) == 0) {
			s_case.fabric = f;
			break;
		}
	}
	if (s_case.fabric == NULL) {
		LOG_WRN("  destination matches NO fabric this node holds");
		return 0u;
	}
	LOG_INF("  destination MATCHES fabric %u -- answering", s_case.fabric->index);

	return send_sigma2(&s1, ipk, msg + mh_len + ph_len, len - mh_len - ph_len, &ph, &mh, reply,
			   cap);
}

size_t matter_thread_on_datagram(uint8_t *msg, size_t len, uint8_t *reply, size_t cap,
				 matter_thread_reply_send_fn send, void *send_ctx)
{
	size_t reply_len;
	int send_status;

	/* OpenThread invokes this callback with its API mutex held. Never wait for
	 * the Matter owner from that state: owner work legitimately calls back
	 * into OpenThread, and blocking here would make OT -> owner / owner -> OT
	 * a deadlock. Reliable Matter messages are retransmitted, so a busy owner
	 * is safely represented by no reply to this attempt. The try-lock precedes
	 * matter_thread_on_datagram_owned(), so this loss path has not parsed or
	 * mutated an exchange, cursor, session, subscription, or fabric. */
	if (k_mutex_lock(&s_owner_lock, K_NO_WAIT) != 0) {
		LOG_DBG("  Matter owner busy; leaving UDP datagram for MRP retry");
		return 0u;
	}
	s_thread_tx_token = 0u;
	reply_len = matter_thread_on_datagram_owned(msg, len, reply, cap);
	if (reply_len > 0u) {
		send_status = send != NULL ? send(send_ctx, reply, reply_len) : MATTER_E_STATE;
		tx_thread_finish(send_status);
		if (send_status != MATTER_OK) {
			reply_len = 0u;
		}
	} else if (s_thread_tx_token != 0u) {
		/* A handler must not strand a loan if a later error suppressed the
		 * staged length. This packet was never presented to the transport. */
		tx_thread_finish(MATTER_E_STATE);
	}
	ultrawidelock_mutex_unlock(&s_owner_lock);
	return reply_len;
}

static void on_message_owned(uint8_t *msg, size_t len)
{
	struct matter_exchange_in in;
	uint8_t pase_out[MATTER_PASE_REPLY_MAX];
	size_t pase_len = 0u;
	uint8_t pase_op = 0u;
	int rc;

	/* PASE and unsecured traffic cannot inherit authority from the last CASE
	 * datagram handled on the shared data model. */
	s_info.accessing_fabric_index = 0u;
	s_info.accessing_node_id = 0u;
	memset(s_info.accessing_cats, 0, sizeof(s_info.accessing_cats));
	s_info.accessing_cat_count = 0u;

	if (!s_verifier_ok) {
		LOG_ERR("no usable SPAKE2P verifier; dropping %u bytes", (unsigned int)len);
		return;
	}
	if (s_stale && begin_session() != 0) {
		return;
	}

	LOG_DBG("on_message: %u B", (unsigned int)len);
	rc = matter_exchange_recv_in_place(&s_exchange, msg, len, &in);
	LOG_DBG("exchange_recv rc=%d opcode=0x%02x payload=%u", rc, in.opcode,
		(unsigned int)in.payload_len);
	if (rc == MATTER_E_DUP) {
		/* The peer thinks its last message was lost. Acknowledge it
		 * again, but do NOT run the payload through PASE twice. */
		if (s_thread_reply == NULL || !tx_thread_retry(&s_exchange)) {
			(void)send_standalone_ack(&s_exchange);
		}
		return;
	}
	if (rc != MATTER_OK) {
		/* Name what was turned away. "refused 137 bytes (-4)" cost a whole
		 * hardware round to interpret; the exchange id and the I flag are
		 * what actually said which rule fired. */
		LOG_WRN("refused %u B (%d): protocol 0x%04x opcode 0x%02x exchange 0x%04x %s",
			(unsigned int)len, rc, (unsigned int)in.protocol_id, in.opcode,
			in.exchange_id, in.initiator ? "I" : "-");
		return;
	}

	if (s_exchange.secure) {
		on_secure(&in);
		return;
	}

	/* A bare acknowledgement closes out our last send and asks nothing. */
	if (in.opcode == MATTER_SC_OP_ACK) {
		return;
	}

	rc = matter_pase_responder_recv(&s_pase, in.opcode, in.payload, in.payload_len, pase_out,
					sizeof(pase_out), &pase_len, &pase_op);
	/* Send whatever came back BEFORE acting on rc: on a failure that reply is
	 * the StatusReport telling the peer why, and it is the only thing
	 * standing between a rejected commissioner and a silent timeout. */
	if (pase_len > 0u) {
		send_framed(pase_op, pase_out, pase_len);
	}

	if (rc != MATTER_OK) {
		LOG_WRN("PASE refused opcode 0x%02x (%d)", in.opcode, rc);
		/* Terminal for this attempt; the next connection re-seeds. */
		s_stale = true;
		return;
	}

	LOG_INF("PASE rc=%d, reply opcode 0x%02x (%u B), state=%d", rc, pase_op,
		(unsigned int)pase_len, (int)matter_pase_responder_state(&s_pase));

	if (matter_pase_responder_state(&s_pase) == MATTER_PASE_ST_DONE && !s_exchange.secure) {
		uint32_t seed = 0u;

		if (ultrawidelock_random((uint8_t *)&seed, sizeof(seed)) != 0) {
			LOG_ERR("CSPRNG failed; cannot open the secure session");
			s_stale = true;
			return;
		}
		/* The StatusReport went out on the unsecured session above; only
		 * now does the clear channel close. */
		rc = matter_exchange_promote(&s_exchange, s_pase.local_session_id,
					     s_pase.peer_session_id, &s_pase.keys, seed);
		if (rc != MATTER_OK) {
			LOG_ERR("promote to secure session rc=%d", rc);
			s_stale = true;
			return;
		}
		/* Every attestation signature covers this. Copied now because
		 * the PASE responder is wiped when the next session starts. */
		memcpy(s_info.attestation_challenge, s_pase.keys.attestation_challenge,
		       sizeof(s_info.attestation_challenge));
		s_info.have_challenge = true;

		LOG_INF("PASE complete: secure session up (local 0x%04x, peer 0x%04x)",
			(unsigned int)s_pase.local_session_id,
			(unsigned int)s_pase.peer_session_id);
	}
}

static void on_message(uint8_t *msg, size_t len)
{
	ultrawidelock_mutex_lock(&s_owner_lock);
	on_message_owned(msg, len);
	ultrawidelock_mutex_unlock(&s_owner_lock);
}

/** The link dropped. Cheap here; begin_session() does the real work later. */
static void on_link_reset_owned(void)
{
	s_stale = true;
	read_drop_session(0u, false);

	/*
	 * NOT the place to roll the fail-safe back, which is what this used to
	 * do. A commissioner with concurrent connection closes BLE ON PURPOSE
	 * once ConnectNetwork succeeds and finishes over Thread -- so the link
	 * dropping is the normal path, and discarding the fabric here destroyed
	 * the identity CASE was about to use. Observed exactly that: two Sigma1s
	 * matched, then "no fabric to match it against" for every one after.
	 *
	 * The rollback belongs at the start of the NEXT commissioning attempt
	 * instead; see begin_session().
	 */
}

static void on_link_reset(void)
{
	ultrawidelock_mutex_lock(&s_owner_lock);
	on_link_reset_owned();
	ultrawidelock_mutex_unlock(&s_owner_lock);
}

bool matter_commission_has_fabric(void)
{
	return atomic_get(&s_has_fabric_snapshot) != 0;
}

int matter_commission_init(void)
{
	ultrawidelock_sem_init(&s_fab_done, 0u, 1u);
	s_info.commissioning_hooks = &k_commissioning_hooks;
	ultrawidelock_mutex_init(&s_owner_lock);
	if (matter_tx_pool_init(&s_tx_pool, s_tx_slots, &s_tx_backing[0][0], MATTER_TX_SLOTS,
				sizeof(s_tx_backing[0])) != MATTER_OK) {
		LOG_ERR("cannot initialize owned Matter packet slots");
		return -ENOMEM;
	}
	if (matter_im_read_pool_init(&s_read_pool, s_reads, MATTER_READ_SLOTS) != MATTER_OK) {
		LOG_ERR("cannot initialize Matter Read cursors");
		return -ENOMEM;
	}
	ecdh_known_answer_test();
	srp_sign_self_test();

	if (load_verifier() != 0) {
		/* Deliberately still registers the handler. A device that cannot
		 * commission should say so on every attempt rather than look
		 * like a dead radio. */
		s_verifier_ok = false;
	} else {
		s_verifier_ok = true;
		LOG_INF("commissioning ready: discriminator 0x%03x, %u PBKDF iterations",
			(unsigned int)CONFIG_ULTRAWIDELOCK_MATTER_DISCRIMINATOR,
			(unsigned int)CONFIG_ULTRAWIDELOCK_MATTER_SPAKE2P_ITERATIONS);
	}

	/*
	 * The credential reader group sub-identifier. Derived from the factory
	 * EUI-64 rather than drawn from the RNG, because nothing on the Matter
	 * side of this node is persisted yet (there is no settings handler in
	 * ultrawidelock_matter at all) and a value regenerated at every boot would make
	 * this look like a different reader group after each power cycle.
	 * Hashing keeps the EUI-64 itself off the wire.
	 *
	 * The ESP32 lock uses DRBG and caches (ultrawidelock_reader_delegate.cpp:51),
	 * which is the better answer once Matter state persists. Revisit then.
	 */
	{
		uint32_t id[2] = { NRF_FICR->DEVICEID[0], NRF_FICR->DEVICEID[1] };
		struct ultrawidelock_sha256 h;
		uint8_t digest[ULTRAWIDELOCK_SHA256_LEN];

		ultrawidelock_sha256_init(&h);
		ultrawidelock_sha256_update(&h, (const uint8_t *)"ultrawidelock-group-sub-id", 18u);
		ultrawidelock_sha256_update(&h, (const uint8_t *)id, sizeof(id));
		ultrawidelock_sha256_final(&h, digest);
		memcpy(s_info.ultrawidelock_group_sub_id, digest, MATTER_ALIRO_GROUP_ID_LEN);
	}

	/*
	 * Recover what SetAliroReaderConfig put here, from the store it also
	 * wrote to.
	 *
	 * These three fields live only in RAM: the command fills them and the
	 * reader's own NVS keeps the identity, so after a reboot the credential layer
	 * reported "provisioned reader identity loaded" while every Matter read
	 * of AliroReaderVerificationKey answered null. A controller cannot tell
	 * that apart from a reader nobody has provisioned, and the null is what
	 * an ecosystem uses to decide whether to provision one -- so the answer
	 * was not merely unhelpful, it was wrong.
	 *
	 * Recovered rather than persisted a second time. Two copies of an
	 * identity are two things that can disagree, and the one the reader
	 * actually authenticates with has to win.
	 *
	 * group_sub_id above is deliberately NOT overwritten: it is derived from
	 * FICR DEVICEID, is the same value that went into the stored reader_id,
	 * and is available whether or not anything was ever provisioned.
	 */
	{
		uint8_t reader_id[32];
		uint8_t verif_pub[65];
		uint8_t grk[MATTER_ALIRO_GROUP_ID_LEN];
		int rc = ultrawidelock_reader_identity_public(reader_id, verif_pub, grk);

		if (rc == 0) {
			memcpy(s_info.ultrawidelock_verification_key, verif_pub, sizeof(verif_pub));
			memcpy(s_info.ultrawidelock_group_id, reader_id, MATTER_ALIRO_GROUP_ID_LEN);
			memcpy(s_info.ultrawidelock_group_resolving_key, grk, sizeof(grk));
			s_info.have_ultrawidelock_group_resolving_key = true;
			s_info.have_ultrawidelock_reader_config = true;
			LOG_INF("credential reader configuration restored; attributes readable");
		} else if (rc != -ENOENT) {
			/* -ENOENT is the dev identity and is not news. Anything
			 * else means a stored identity exists and could not be
			 * read back, which leaves the attributes lying. */
			LOG_ERR("stored credential identity unreadable (%d); attributes stay null", rc);
		}
		memset(reader_id, 0, sizeof(reader_id));
		memset(grk, 0, sizeof(grk));
	}

	s_info.ultrawidelock_reader_config_cb = on_ultrawidelock_reader_config;
	s_info.ultrawidelock_credential_cb = on_ultrawidelock_credential;
	s_info.ultrawidelock_credential_clear_cb = on_ultrawidelock_credential_clear;
	s_info.ultrawidelock_user_clear_cb = on_ultrawidelock_user_clear;

	matter_clusters_init(&s_im, &s_info);
	fabric_snapshot_refresh_owned();
	/* Without this the cluster still APPEARS in ServerList -- which is the
	 * point, a node that hides it can never be shared with a second
	 * ecosystem -- but every command answers FAILURE. */
	matter_clusters_set_admin_hooks(&k_admin_hooks);
	/* An event's SystemTimestamp. Milliseconds since boot, which is what the
	 * node can honestly claim -- it has no trusted wall clock. */
	s_info.uptime_ms_cb = matter_event_uptime_ms;
	/*
	 * Unconditional, unlike the subscriptions below: these are attribute
	 * values, and a stored value is right even on a node whose fabric did
	 * not survive -- the next commissioner reads what the last one set.
	 */
	(void)matter_dl_attr_load(&s_info);
#if MATTER_FEATURE_CLIENT
	/*
	 * AFTER matter_clusters_init, which zeroes the binding table this
	 * borrows, and BEFORE matter_fab_load below, which fills it in.
	 */
	matter_client_init(&s_info);
#endif
	matter_ble_set_link_handler(on_link_reset);
	matter_ble_set_tx_handler(matter_commission_ble_tx_complete);
	matter_ble_set_msg_handler(on_message);
	ultrawidelock_reader_set_lock_state_listener(on_ultrawidelock_lock_state);

	/*
	 * After the data model has been wired to s_info.
	 *
	 * A restored identity is not enough on its own: nothing has handed the
	 * Thread dataset to the stack and no SRP instance exists, so the node
	 * would be commissioned and unreachable, which the Home app reports the
	 * same way as an accessory that was never added. matter_clusters_resume
	 * does the pair that commissioning would have done.
	 */
	{
		int rc;

#if IS_ENABLED(CONFIG_ULTRAWIDELOCK_MATTER_CLEAR_ON_BOOT)
		/* Before the load, so nothing this boot ever sees the old
		 * fabrics -- the same shape as ULTRAWIDELOCK_PROV_CLEAR_ON_BOOT. */
		(void)matter_fab_erase();
#endif
		rc = matter_fab_load(&s_info);
		fabric_snapshot_refresh_owned();

		if (rc == 0) {
			/* Only with a fabric: a record whose fabric did not
			 * survive can never be claimed, and loading it would
			 * hold a slot against nothing. */
			sub_persist_load();
			rc = matter_clusters_resume(&s_info);
			if (rc != MATTER_OK) {
				LOG_ERR("restored a fabric but could not rejoin Thread (%d); "
					"the accessory will read as unresponsive",
					rc);
			}
			/*
			 * The advert was chosen at BLE start, BEFORE this load, so
			 * it says commissionable and a restored reader would never
			 * offer 0xFFF2 again -- a node that unlocks until its first
			 * reboot and silently stops after it. The gate reads the
			 * fabric table, which only now has anything in it.
			 */
			ultrawidelock_ble_readvertise();
		} else if (rc > 0) {
			/* The custom Matter schema is a clean break. Do not leave a
			 * credential identity with no administering fabric: old Home Keys
			 * would still authenticate and the next home would inherit them. */
			if (s_info.have_ultrawidelock_reader_config) {
				int clear_rc = ultrawidelock_reader_provision_clear();

				if (clear_rc == 0) {
					reader_readback_clear();
				} else {
					LOG_ERR("no Matter administrator, but Home Key identity clear failed (%d)",
						clear_rc);
				}
			}
			LOG_INF("no stored fabric; commissionable");
		}
	}
	return 0;
}
