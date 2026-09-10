/* SPDX-License-Identifier: ISC */

// credential step-up (Access Document) phase: builds the mdoc DeviceRequest, unwraps and decrypts
// the SessionData DeviceResponse, decodes the CBOR document per spec 7.2/8.4.2, and runs the
// six-step Access Document verification of spec 7.4. Reference-completeness codec + verifier; the
// verdict is logged and stored, never gates the unlock (the provisioned trust store remains the
// sole gate).
/*
 * ultrawidelock_stepup — the Aliro §8.4 step-up phase: the ISO 18013-5 (mdoc) document
 * exchange the Reader MAY run in the standard phase to obtain an Access or
 * Revocation Document. Split across three translation units so the wire-facing
 * decoder and codecs carry no crypto dependency:
 *
 *   ultrawidelock_stepup_parse.c  pure CBOR decode + DeviceResponse structural parse
 *                         (Table 7-1/7-2/8-22). No crypto, no allocation; every
 *                         field is a bounds-checked slice of the caller's buffer.
 *   ultrawidelock_stepup_wire.c   the DeviceRequest builders, the raw (unencrypted)
 *                         SessionData wrap/unwrap, the DO'53 wrapper, the
 *                         fragmenting ENVELOPE / GET RESPONSE APDU builders and
 *                         the 61xx response reassembly. No crypto; transports
 *                         that encrypt through their own backend link only this
 *                         and the parser.
 *   ultrawidelock_stepup.c        the SessionData seal/open (reusing the ultrawidelock_secchan
 *                         AES-256-GCM channel under StepUpSK, factored over the
 *                         raw wrap/unwrap), the simple ENVELOPE / GET RESPONSE
 *                         codec, and the §7.4 verifier (digest recompute +
 *                         validity + the issuer-signature check via an injected
 *                         ES256 verify).
 *
 * The ES256 primitive is passed in (ultrawidelock_stepup_verify_ctx.ecdsa_verify) so this
 * module carries no elliptic-curve dependency: the target wires the PSA-backed
 * ultrawidelock_ecdsa_p256_verify, the host injects its own.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ultrawidelock_crypto.h" /* struct ultrawidelock_secchan */

#if defined(ESP_PLATFORM)
#include "sdkconfig.h" /* CONFIG_ULTRAWIDELOCK_STEPUP_MAX_* (Zephyr injects autoconf.h itself) */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ---- document types (§7.7) ---- */
#define ULTRAWIDELOCK_STEPUP_DOCTYPE_ACCESS     "aliro-a"
#define ULTRAWIDELOCK_STEPUP_DOCTYPE_REVOCATION "aliro-r"

/* Result codes of the ultrawidelock_stepup_wire.c codecs (the seal/open/verify entry
 * points below keep their historic 0/-1 contract). */
enum ultrawidelock_stepup_result {
	ULTRAWIDELOCK_STEPUP_OK = 0,
	ULTRAWIDELOCK_STEPUP_MORE_RESPONSE = 1,
	ULTRAWIDELOCK_STEPUP_INVALID_ARGUMENT = -1,
	ULTRAWIDELOCK_STEPUP_BUFFER_TOO_SMALL = -2,
	ULTRAWIDELOCK_STEPUP_INVALID_DATA = -3,
	ULTRAWIDELOCK_STEPUP_STATUS_ERROR = -4,
};

/* ---- StepUpSK-derived session keys (§8.4.3): HKDF-SHA256(empty salt, IKM =
 * StepUpSK, info = "SKReader"/"SKDevice", L = 32). StepUpSK is block[64..95]. */
#define ULTRAWIDELOCK_STEPUP_SK_OFFSET 64u
int ultrawidelock_stepup_derive_keys(const uint8_t block[ULTRAWIDELOCK_KEY_BLOCK_LEN],
			     uint8_t sk_reader[ULTRAWIDELOCK_SESSION_KEY_LEN],
			     uint8_t sk_device[ULTRAWIDELOCK_SESSION_KEY_LEN]);

/* Initialise a SessionData secure channel: enc = SKReader (reader->device),
 * dec = SKDevice (device->reader). Counters start at 1 (ultrawidelock_secchan_init). */
void ultrawidelock_stepup_channel_init(struct ultrawidelock_secchan *sc,
			       const uint8_t sk_reader[ULTRAWIDELOCK_SESSION_KEY_LEN],
			       const uint8_t sk_device[ULTRAWIDELOCK_SESSION_KEY_LEN]);

/* ---- requester (§8.4.2) ----
 * Build the fixed Access-Document DeviceRequest CBOR (Table 8-21): docType
 * "aliro-a", namespace "aliro-a", requesting the given element identifiers
 * (intent-to-retain true). With elems=NULL/n_elems=0, requests element2+element4
 * (the §14.6 example request). Returns 0 and sets *out_len, or -1 on overflow. */
int ultrawidelock_stepup_build_device_request(const char *const *elems, size_t n_elems,
					      uint8_t *out, size_t cap, size_t *out_len);

/* Single-element DeviceRequest with the element identifier as a raw text slice
 * and the caller's intent-to-retain flag (same wire shape as above). Returns an
 * ultrawidelock_stepup_result. */
int ultrawidelock_stepup_build_device_request_ex(const uint8_t *element_identifier,
					 size_t element_identifier_length, bool intent_to_store,
					 uint8_t *output, size_t output_capacity,
					 size_t *output_length);

/* ---- raw SessionData / DO'53 / chaining codecs (ultrawidelock_stepup_wire.c) ----
 * The {"data": bstr} envelope WITHOUT the AES-256-GCM channel, for stacks that
 * encrypt through their own backend. The seal/open pair below factor over
 * these. All return ultrawidelock_stepup_result; unwrapped pointers are slices into
 * the caller's buffer. */
int ultrawidelock_stepup_wrap_sessiondata_raw(const uint8_t *ciphertext, size_t ciphertext_length,
				      uint8_t *output, size_t output_capacity,
				      size_t *output_length);
int ultrawidelock_stepup_unwrap_sessiondata_raw(const uint8_t *session_data,
						size_t session_data_length,
						const uint8_t **ciphertext,
						size_t *ciphertext_length);

/* Encode/decode the NFC Device Engagement DO'53 wrapper. */
int ultrawidelock_stepup_wrap_do53(const uint8_t *message, size_t message_length, uint8_t *output,
			   size_t output_capacity, size_t *output_length);
int ultrawidelock_stepup_unwrap_do53(const uint8_t *encoded, size_t encoded_length,
				     const uint8_t **message, size_t *message_length);

/* Build one ENVELOPE command fragment (short or extended APDU); offset is
 * advanced by the emitted fragment, *last_fragment set on the final one. */
int ultrawidelock_stepup_build_envelope_ex(const uint8_t *encoded_do53, size_t encoded_length,
				   size_t *offset, size_t max_command_data,
				   size_t max_response_data, bool extended_supported,
				   uint8_t *output, size_t output_capacity, size_t *output_length,
				   bool *last_fragment);

/* GET RESPONSE for 1..65536 expected bytes (extended APDU above 256). */
int ultrawidelock_stepup_build_get_response_ex(size_t expected_length, uint8_t *output,
				       size_t output_capacity, size_t *output_length);

/* Append response data and interpret 9000 / 61xx. sw2==0 means 256 bytes. */
int ultrawidelock_stepup_collect_response(const uint8_t *response, size_t response_length,
				  uint8_t *collected, size_t collected_capacity,
				  size_t *collected_length, size_t *next_length);

/* Seal a DeviceRequest into a SessionData message {"data": bstr(ct||tag)} and
 * advance the channel. Returns 0 and sets *out_len, or -1. */
int ultrawidelock_stepup_seal_sessiondata(struct ultrawidelock_secchan *sc, const uint8_t *plain,
					  size_t plain_len, uint8_t *out, size_t cap,
					  size_t *out_len);

/* Open a SessionData message: unwrap {"data": bstr}, AES-256-GCM-open under the
 * channel, and write the plaintext DeviceResponse. out may be sd itself (the
 * plaintext lands below the ciphertext it replaces). Returns 0 and sets
 * *out_len; <0 on a malformed wrapper or a GCM tag mismatch. */
int ultrawidelock_stepup_open_sessiondata(struct ultrawidelock_secchan *sc, const uint8_t *sd,
					  size_t sd_len, uint8_t *out, size_t cap, size_t *out_len);

/* ---- ENVELOPE / GET RESPONSE APDUs (§8.4.4) ----
 * ENVELOPE carries the SessionData in the command data field. chaining=1 sets
 * CLA 0x10 (more blocks follow). Result = "CLA C3 00 00 Lc <data> 00". */
#define ULTRAWIDELOCK_INS_ENVELOPE     0xC3u
#define ULTRAWIDELOCK_INS_GET_RESPONSE 0xC0u
int ultrawidelock_stepup_build_envelope(const uint8_t *data, size_t data_len, int chaining,
					uint8_t *out, size_t cap, size_t *out_len);
/* GET RESPONSE for `le` bytes (from the 61XX status word): "00 C0 00 00 <le>". */
int ultrawidelock_stepup_build_get_response(uint8_t le, uint8_t *out, size_t cap, size_t *out_len);

/* ---- parsed DeviceResponse (slices into the caller's buffer) ---- */
/* Parser capacity. Set per build through Kconfig (CONFIG_ULTRAWIDELOCK_STEPUP_MAX_*)
 * because struct ultrawidelock_stepup_doc is sized by them and lives in static RAM
 * on the reader: the DWM3001CDK trims both to fit an nRF52833. Every consumer of
 * a build must see one value; host builds get the defaults. */
#ifndef ULTRAWIDELOCK_STEPUP_MAX_DIGESTS
#if defined(CONFIG_ULTRAWIDELOCK_STEPUP_MAX_DIGESTS)
#define ULTRAWIDELOCK_STEPUP_MAX_DIGESTS ((unsigned)CONFIG_ULTRAWIDELOCK_STEPUP_MAX_DIGESTS)
#else
#define ULTRAWIDELOCK_STEPUP_MAX_DIGESTS 24u
#endif
#endif
#ifndef ULTRAWIDELOCK_STEPUP_MAX_ITEMS
#if defined(CONFIG_ULTRAWIDELOCK_STEPUP_MAX_ITEMS)
#define ULTRAWIDELOCK_STEPUP_MAX_ITEMS   ((unsigned)CONFIG_ULTRAWIDELOCK_STEPUP_MAX_ITEMS)
#else
#define ULTRAWIDELOCK_STEPUP_MAX_ITEMS   16u
#endif
#endif
#define ULTRAWIDELOCK_STEPUP_ID_MAX      32u
/* struct ultrawidelock_stepup_doc.truncated: which text fields were cut to fit. */
#define ULTRAWIDELOCK_STEPUP_TRUNC_DOC_TYPE     0x01u
#define ULTRAWIDELOCK_STEPUP_TRUNC_MSO_DOC_TYPE 0x02u
#define ULTRAWIDELOCK_STEPUP_TRUNC_NAME_SPACE   0x04u
#define ULTRAWIDELOCK_STEPUP_TRUNC_DIGEST_ALG   0x08u
#define ULTRAWIDELOCK_STEPUP_TRUNC_VERSION      0x10u

/**
 * Step-up credential element digest: SHA-256 hash of a disclosed IssuerSignedItem, with its
 * digest_id for verification.
 */
struct ultrawidelock_stepup_digest {
	uint64_t id;
	uint8_t hash[32];
};

/**
 * Single disclosed IssuerSignedItem from a Step-up document: digest_id (which digest to check
 * against), tagged (24(bstr(IssuerSignedItem)) bytes for hashing), elem_id (element name),
 * value (raw encoded elementValue "4" CBOR item, or NULL when absent).
 */
struct ultrawidelock_stepup_item {
	uint64_t digest_id;
	const uint8_t
		*tagged; /* the 24(bstr(IssuerSignedItem)) bytes, hashed for the digest check */
	size_t tagged_len;
	char elem_id[ULTRAWIDELOCK_STEPUP_ID_MAX];
	const uint8_t *value; /* raw encoded elementValue item, or NULL */
	size_t value_len;
};

/**
 * Parsed Step-up access document (ISO/IEC 18013-5 mDoc): have_document (0 if device declined),
 * status (DeviceResponse "3" code), doc_type and name_space (issuer namespace), IssuerAuth
 * COSE_Sign1 components (protected header, kid, x5chain, payload=24(bstr(MSO)), signature r||s),
 * MobileSecurityObject (digest algorithm, doc type, disclosed digests), validity dates
 * (signed/valid_from/valid_until as epoch seconds, with flags), and disclosed IssuerSignedItems
 * (elem_id, tagged bytes, digest_id for matching against MSO).
 */
struct ultrawidelock_stepup_doc {
	int have_document; /* 0 = DeviceResponse carried no documents (device declined) */
	int status;        /* DeviceResponse "3" */

	char version[ULTRAWIDELOCK_STEPUP_ID_MAX];    /* DeviceResponse "1" ("1.0"), "" if not text */
	char doc_type[ULTRAWIDELOCK_STEPUP_ID_MAX];   /* Documents[].docType ("5") */
	char name_space[ULTRAWIDELOCK_STEPUP_ID_MAX]; /* the single issuerSigned namespace */

	/* IssuerAuth COSE_Sign1 [protected, unprotected, payload, signature]. */
	const uint8_t *protected_hdr; /* content of the protected bstr */
	size_t protected_len;
	int have_cose_alg;  /* protected header decoded as {1: alg} */
	int64_t cose_alg;   /* COSE alg label 1 (-7 = ES256) */
	const uint8_t *kid; /* unprotected label 4, or NULL */
	size_t kid_len;
	const uint8_t *x5chain; /* unprotected label 33, or NULL (raw item bytes) */
	size_t x5chain_len;
	const uint8_t *x5_cert; /* first certificate bstr payload of x5chain, or NULL */
	size_t x5_cert_len;
	const uint8_t *payload; /* content of the payload bstr = 24(bstr(MSO)) */
	size_t payload_len;
	const uint8_t *signature; /* 64-byte r||s */

	/* MobileSecurityObject (Table 7-1). */
	char digest_alg[ULTRAWIDELOCK_STEPUP_ID_MAX]; /* "SHA-256" */
	char mso_doc_type[ULTRAWIDELOCK_STEPUP_ID_MAX];
	struct ultrawidelock_stepup_digest digests[ULTRAWIDELOCK_STEPUP_MAX_DIGESTS];
	size_t n_digests;
	size_t n_digests_dropped; /* past the cap: counted, not an error */

	/* deviceKeyInfo ("4") deviceKey as an uncompressed P-256 point, when the
	 * COSE_Key is EC2/P-256 with 32-byte x and y (compact key "1", with the
	 * older published fixture alias "4" also accepted). */
	int have_device_key;
	uint8_t device_key[65]; /* 0x04 || X || Y */

	/* validityInfo tdates as parsed epoch seconds (UTC), plus the raw 20-char
	 * "YYYY-MM-DDTHH:MM:SSZ" slices (NULL unless the tdate text is 20 chars). */
	int have_signed, have_valid_from, have_valid_until;
	int64_t signed_epoch, valid_from_epoch, valid_until_epoch;
	const uint8_t *signed_raw, *valid_from_raw, *valid_until_raw;
	int have_iteration;
	uint64_t iteration;
	int have_time_verification_required; /* MSO "7" present */
	int time_verification_required;

	/* disclosed IssuerSignedItems. */
	struct ultrawidelock_stepup_item items[ULTRAWIDELOCK_STEPUP_MAX_ITEMS];
	size_t n_items;
	size_t n_items_dropped; /* past the cap: counted, not an error */
	uint8_t truncated;      /* ULTRAWIDELOCK_STEPUP_TRUNC_* text fields cut to fit */
};

/* Structural decode of a plaintext DeviceResponse (Table 8-22). CRYPTO-FREE and
 * bounds-checked. Returns 0 on a well-formed document
 * (which may still be have_document=0), <0 on malformed CBOR / limits exceeded. */
int ultrawidelock_stepup_parse_response(const uint8_t *buf, size_t len,
					struct ultrawidelock_stepup_doc *doc);

/* ---- verifier (§7.4) ---- */
struct ultrawidelock_stepup_issuer {
	const uint8_t *kid; /* matched against IssuerAuth kid */
	size_t kid_len;
	uint8_t pub[65]; /* P-256 uncompressed issuer public key */
};

/**
 * Context for Step-up document verification: issuers (trust store), time_valid/now_epoch (clock
 * state), access_iteration (stored iteration for replay check), expected_doctype, ecdsa_verify
 * callback (ES256 over message, takes 65-byte pub, message, 64-byte r||s sig, returns 0 on valid).
 */
struct ultrawidelock_stepup_verify_ctx {
	const struct ultrawidelock_stepup_issuer *issuers;
	size_t n_issuers;
	int time_valid;            /* reader holds a trusted clock (timesync) */
	int64_t now_epoch;         /* current UTC seconds; used only when time_valid */
	uint64_t access_iteration; /* stored AccessIteration for this issuer (default 0) */
	const char *expected_doctype;
	/* ES256 over msg (hashing internal), pub = 65-byte point, sig = 64-byte r||s.
	 * Returns 0 on a valid signature. Target: ultrawidelock_ecdsa_p256_verify. */
	int (*ecdsa_verify)(const uint8_t pub[65], const uint8_t *msg, size_t msg_len,
			    const uint8_t sig[64]);
};

/**
 * Verdict of Step-up document verification (ISO/IEC 18013-5 §7.4): valid (all passed steps + >=1
 * valid element), reject_step (0=accepted, else step 1-6 that failed),
 * issuer_key_found/issuer_chain_validated/sig_ok/digests_ok/doctype_ok/time_ok/iteration_ok
 * (per-step flags), valid_elements (count of disclosed items with verified digest).
 */
struct ultrawidelock_stepup_verdict {
	int valid;       /* all applicable steps passed AND >=1 valid element */
	int reject_step; /* 0 = accepted; else the first §7.4 step that failed (1..6) */

	int issuer_key_found;       /* step 1 */
	int issuer_chain_validated; /* 0 for x5chain: EE key used, chain NOT validated (ref limit)
				     */
	int sig_ok;                 /* step 2 */
	int digests_ok;             /* step 3: every disclosed item matched its valueDigest */
	int doctype_ok;             /* step 4 */
	int time_ok;                /* step 5 */
	int iteration_ok;           /* step 6 */
	size_t valid_elements;      /* disclosed items whose digest verified */
	size_t n_digests_dropped;   /* from the parsed doc: past the caps */
	size_t n_items_dropped;
	uint8_t truncated;          /* from the parsed doc: ULTRAWIDELOCK_STEPUP_TRUNC_* */
};

/* Run §7.4 over a parsed document. Never gates access; fills *verdict for the
 * caller to log/store. Returns 0 if verdict->valid, <0 otherwise (same info as
 * verdict->reject_step; the return is a convenience, not an access decision). */
int ultrawidelock_stepup_verify(const struct ultrawidelock_stepup_doc *doc,
			const struct ultrawidelock_stepup_verify_ctx *ctx,
			struct ultrawidelock_stepup_verdict *verdict);

/* Convenience: open the SessionData response, parse, and verify in one call.
 * Fills *verdict; returns 0 on verdict->valid, <0 on any decrypt/parse/verify
 * failure (the worker logs the verdict regardless of the return). scratch must
 * hold the decrypted DeviceResponse (>= sd_len). */
int ultrawidelock_stepup_run(struct ultrawidelock_secchan *sc, const uint8_t *sd_resp,
			     size_t sd_len, const struct ultrawidelock_stepup_verify_ctx *ctx,
			     uint8_t *scratch, size_t scratch_cap,
			     struct ultrawidelock_stepup_doc *doc,
			     struct ultrawidelock_stepup_verdict *verdict);

/* ---- ESP worker seam (implemented per-platform; see ultrawidelock_stepup_worker.c) ----
 * Copies the collected SessionData response + keys + verify inputs and runs
 * ultrawidelock_stepup_run() off the BLE-host task, so parse/verify never touches the
 * auth segment or the ranging arm window. Returns 0 if queued. */
struct ultrawidelock_stepup_job {
	uint8_t sk_reader[ULTRAWIDELOCK_SESSION_KEY_LEN];
	uint8_t sk_device[ULTRAWIDELOCK_SESSION_KEY_LEN];
	uint8_t issuer_pub[65];
	uint8_t issuer_kid[16];
	size_t issuer_kid_len;
	int have_issuer;
	int time_valid;
	int64_t now_epoch;
	uint16_t conn_handle;
	size_t sd_len;
	uint8_t sd[2048]; /* SessionData response (x5chain-cert headroom) */
};
int ultrawidelock_stepup_worker_submit(const struct ultrawidelock_stepup_job *job);

/* Copy out the most recent verdict the worker produced (for `ultrawidelock-stepup
 * status`). Returns 1 and fills *verdict (+ *conn if non-NULL) when one exists,
 * 0 otherwise. Implemented in the per-platform worker. */
int ultrawidelock_stepup_worker_last(struct ultrawidelock_stepup_verdict *verdict, uint16_t *conn);

#ifdef __cplusplus
}
#endif
