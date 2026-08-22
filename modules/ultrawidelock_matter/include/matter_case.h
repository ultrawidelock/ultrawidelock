/* SPDX-License-Identifier: ISC */

/**
 * @file matter_case.h — proving an operational identity, both ways.
 *
 * PASE let a commissioner in because it knew a printed code. CASE is what
 * happens afterwards, every time: two nodes that already hold certificates from
 * the same fabric prove it to each other and agree on session keys. It is the
 * only session type the spec will accept CommissioningComplete over, and the
 * only way a phone talks to this node once BLE is gone.
 *
 *   Sigma1  initiator -> responder   who I want, and my ephemeral key
 *   Sigma2  responder -> initiator   my certificate chain, signed, encrypted
 *   Sigma3  initiator -> responder   the same, in the other direction
 *
 * This file is the responder's half, built in that order.
 *
 * The subtle piece is Sigma1's destinationId. It is not an address: it is an
 * HMAC that only somebody holding the fabric's identity protection key could
 * have produced, over the identity they are asking for. A responder does not
 * read a node id out of it -- it recomputes the HMAC for each fabric it holds
 * and looks for a match. That is what makes an unsolicited Sigma1 unable to
 * enumerate a node's fabrics: get the key wrong and you learn nothing.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "matter_fabric.h"
#include "matter_status.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Secure Channel opcodes for CASE (protocols/secure_channel/Constants.h:68-71).
 */
#define MATTER_OP_CASE_SIGMA1 0x30u
#define MATTER_OP_CASE_SIGMA2 0x31u
#define MATTER_OP_CASE_SIGMA3 0x32u

/** Both random values, and the destination identifier, are SHA-256 sized. */
#define MATTER_CASE_RANDOM_LEN  32u
#define MATTER_CASE_DEST_ID_LEN 32u

/** An operational group key, and the epoch key it comes from. */
#define MATTER_CASE_IPK_LEN 16u

/** Uncompressed P-256 point. */
#define MATTER_CASE_PUBKEY_LEN 65u

/**
 * Derive the operational identity protection key from the epoch key.
 *
 *   HKDF-SHA256(ikm  = the IPK AddNOC delivered,
 *               salt = the compressed fabric id,
 *               info = "GroupKey v1.0",
 *               len  = 16)
 *
 * AddNOC hands over an EPOCH key, and every use of "the IPK" in CASE means the
 * operational key derived from it -- CHIP's own GetIpkKeySet() returns
 * operational_keys[].encryption_key, not the epoch key it was given
 * (credentials/GroupDataProviderImpl.cpp). Skipping this step produces a
 * destination identifier that never matches, with nothing to say why.
 */
int matter_case_operational_ipk(const uint8_t epoch_key[MATTER_CASE_IPK_LEN],
				const uint8_t compressed_fabric_id[8],
				uint8_t out[MATTER_CASE_IPK_LEN]);

/**
 * Recompute the destination identifier an initiator claims.
 *
 *   HMAC-SHA256(key = operational IPK,
 *               msg = initiatorRandom || rootPublicKey || fabricId || nodeId)
 *
 * fabricId and nodeId are LITTLE-endian here, which is worth stating because
 * the compressed fabric identifier salts with the fabric id BIG-endian. Two
 * derivations, one field, opposite orders; both encode cleanly and only one
 * matches a real phone.
 *
 * @param root_pub uncompressed, 65 bytes, INCLUDING its 0x04 -- unlike the
 *        compressed fabric id, which drops it.
 */
int matter_case_destination_id(const uint8_t ipk[MATTER_CASE_IPK_LEN],
			       const uint8_t initiator_random[MATTER_CASE_RANDOM_LEN],
			       const uint8_t root_pub[MATTER_CASE_PUBKEY_LEN], uint64_t fabric_id,
			       uint64_t node_id, uint8_t out[MATTER_CASE_DEST_ID_LEN]);

/** What Sigma1 carries. Pointers borrow the caller's buffer; nothing is copied. */
struct matter_case_sigma1 {
	const uint8_t *initiator_random; /**< 32 bytes. */
	const uint8_t *destination_id;   /**< 32 bytes. */
	const uint8_t *initiator_pubkey; /**< 65 bytes. */
	uint16_t initiator_session_id;
	/** Present when the initiator is offering to resume an earlier session. */
	const uint8_t *resumption_id;
	size_t resumption_id_len;
	bool has_resumption;
};

/**
 * Decode a Sigma1 (CASESession.cpp:74-83).
 *
 * The three fixed-length fields are checked against their lengths rather than
 * merely read: a Sigma1 whose ephemeral key is not a P-256 point cannot lead
 * anywhere, and refusing it here is cheaper than discovering it inside ECDH.
 *
 * @return MATTER_OK, MATTER_E_INVAL if a mandatory field is missing or
 *         mis-sized, or whatever the TLV decoder returned.
 */
int matter_case_sigma1_decode(const uint8_t *tlv, size_t len, struct matter_case_sigma1 *out);

/** Raw ECDSA P-256 signature, and a shared secret. */
#define MATTER_CASE_SIG_LEN    64u
#define MATTER_CASE_SECRET_LEN 32u

/** Enough for a Sigma2: two certificates, a signature and the framing. */
#define MATTER_CASE_SIGMA2_MAX 1024u

/**
 * What building a Sigma2 needs, and nothing it can derive for itself.
 *
 * Gathered into one struct because the alternative is an eleven-argument
 * function whose adjacent 32-byte buffers can be swapped without the compiler
 * noticing -- and two of them, the random and the transcript hash, are both
 * 32 bytes and both feed the same salt.
 */
struct matter_case_sigma2_in {
	/** From the Sigma1 this answers. */
	const uint8_t *initiator_pubkey; /**< 65 bytes. */
	/** SHA-256 of the Sigma1 payload exactly as it arrived. */
	const uint8_t *transcript_hash; /**< 32 bytes. */
	/** The fabric's OPERATIONAL IPK -- see matter_case_operational_ipk(). */
	const uint8_t *ipk; /**< 16 bytes. */

	/** This node's operational certificate chain and key. */
	const uint8_t *noc;
	size_t noc_len;
	const uint8_t *icac; /**< NULL when the NOC was signed by the root. */
	size_t icac_len;
	const uint8_t *op_priv; /**< 32 bytes, the key the NOC certifies. */
	/**
	 * The NOC's own public key, to verify the signature just made. Optional;
	 * NULL skips the check. Never NULL on hardware -- the certificate is
	 * right there and the check costs one verification.
	 */
	const uint8_t *verify_pub;

	/** Freshly drawn by the caller: this module has no entropy source. */
	const uint8_t *responder_random;   /**< 32 bytes. */
	const uint8_t *responder_eph_priv; /**< 32 bytes. */
	const uint8_t *responder_eph_pub;  /**< 65 bytes. */
	const uint8_t *resumption_id;      /**< 16 bytes. */
	uint16_t responder_session_id;
};

/**
 * Build the Sigma2 answering a Sigma1.
 *
 *   shared   = ECDH(responderEphPriv, initiatorEphPub)
 *   S2K      = HKDF(shared, salt = IPK || responderRandom ||
 *                                 responderEphPubKey || transcriptHash,
 *                   info = "Sigma2", 16)
 *   TBSData2 = { NOC, ICAC?, responderEphPubKey, initiatorEphPubKey }
 *   TBEData2 = { NOC, ICAC?, Sign(opPriv, TBSData2), resumptionID }
 *   Sigma2   = { responderRandom, responderSessionId, responderEphPubKey,
 *                AES-CCM(TBEData2, S2K, "NCASE_Sigma2N") }
 *
 * The signature covers the EPHEMERAL keys of both sides, which is what stops a
 * recorded Sigma2 being replayed into another handshake: the certificate chain
 * inside it is public, and only the binding to this exchange's keys is not.
 *
 * @param shared_out receives the ECDH secret, which Sigma3 and the session keys
 *        both still need. Wiped by the caller, not here.
 * @return MATTER_OK, MATTER_E_NOSPACE, MATTER_E_INVAL, or MATTER_E_STATE when a
 *         crypto primitive failed.
 */
int matter_case_sigma2_encode(const struct matter_case_sigma2_in *in, uint8_t *out, size_t cap,
			      size_t *out_len, uint8_t shared_out[MATTER_CASE_SECRET_LEN]);

/** Enough for a Sigma3: a certificate chain, a signature and the framing. */
#define MATTER_CASE_SIGMA3_MAX 1024u

/** Who the Sigma3 proved its sender to be. */
struct matter_case_sigma3_out {
	uint64_t node_id;
	uint64_t fabric_id;
	uint32_t cats[MATTER_CASE_CAT_MAX];
	size_t cat_count;
	/** The initiator's operational public key, out of the NOC it sent. */
	uint8_t public_key[MATTER_CASE_PUBKEY_LEN];
};

/** What opening a Sigma3 needs, all of it already in hand by then. */
struct matter_case_sigma3_in {
	const uint8_t *shared;          /**< 32, the ECDH secret kept from Sigma2. */
	const uint8_t *ipk;             /**< 16, operational. */
	const uint8_t *transcript_hash; /**< 32, SHA-256 over Sigma1 || Sigma2. */
	/** Both ephemeral keys, in the roles TBSData3 names them. */
	const uint8_t *initiator_eph_pub; /**< 65, from the Sigma1. */
	const uint8_t *responder_eph_pub; /**< 65, the one Sigma2 carried. */
};

/** Convert a Matter certificate to the canonical X.509 DER TBSCertificate it signs. */
int matter_case_cert_tbs(const uint8_t *cert, size_t len, uint8_t *out, size_t cap, size_t *out_len,
			 const uint8_t **signature);

/** Verify a Matter certificate under its issuer's public key. */
int matter_case_cert_verify(const uint8_t *cert, size_t len,
			    const uint8_t issuer_pub[MATTER_CASE_PUBKEY_LEN], uint8_t *scratch,
			    size_t scratch_cap);

/**
 * Open and check a Sigma3, the initiator's half of the same proof.
 *
 *   S3K      = HKDF(shared, salt = IPK || TranscriptHash(Sigma1 || Sigma2),
 *                   info = "Sigma3", 16)
 *   TBEData3 = AES-CCM-open(encrypted3, S3K, "NCASE_Sigma3N")
 *            = { initiatorNOC, initiatorICAC?, signature }
 *   TBSData3 = { initiatorNOC, initiatorICAC?, initiatorEphPubKey,
 *                responderEphPubKey }
 *
 * and the signature over TBSData3 must verify under the public key inside the
 * NOC. Note the tag order: TBSData3 names the SENDER's key first, so Sigma3
 * puts the initiator's ephemeral key where Sigma2 put the responder's. Getting
 * that backwards still encodes, still decodes, and never verifies.
 *
 * The signature authenticates the NOC contents, including any CATs returned
 * to the caller. Certificate-chain conversion and validation is outside this
 * compact CASE implementation.
 *
 * @return MATTER_OK, MATTER_E_INVAL for a malformed message, MATTER_E_TYPE if
 *         the AEAD tag or the signature failed, MATTER_E_NOSPACE if the
 *         message is larger than this node can hold.
 */
int matter_case_sigma3_open(const struct matter_case_sigma3_in *in, const uint8_t *tlv, size_t len,
			    struct matter_case_sigma3_out *out);

/**
 * ECDSA-P256-SHA256 verification, provided by the platform.
 *
 * Used to check this node's OWN Sigma2 signature against the certificate it is
 * about to send with it. A peer that rejects a signature says nothing about
 * why, so the only way to tell "signed wrongly" from "derived a different key"
 * is to verify it here, where both halves are in hand.
 *
 * @return 0 when the signature verifies.
 */
int matter_case_verify(const uint8_t pub[MATTER_CASE_PUBKEY_LEN], const uint8_t *msg,
		       size_t msg_len, const uint8_t sig[MATTER_CASE_SIG_LEN]);

/**
 * ECDH P-256, provided by the platform.
 *
 * Declared rather than included so this module stays free of any particular
 * crypto backend, the same seam matter_attest.h uses for signing. @return 0 on
 * success.
 */
int matter_case_ecdh(const uint8_t priv[32], const uint8_t peer_pub[MATTER_CASE_PUBKEY_LEN],
		     uint8_t secret_out[MATTER_CASE_SECRET_LEN]);

/** ECDSA-P256-SHA256 over a raw message. Same seam. @return 0 on success. */
int matter_case_sign(const uint8_t priv[32], const uint8_t *msg, size_t msg_len,
		     uint8_t sig[MATTER_CASE_SIG_LEN]);

#ifdef __cplusplus
}
#endif
