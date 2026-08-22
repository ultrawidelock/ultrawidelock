/* SPDX-License-Identifier: ISC */

/*
 * See matter_case_client.h.
 */
#include "matter_case_client.h"

#include <string.h>

#include "ultrawidelock_hash.h"
#include "matter_crypto.h"
#include "matter_fabric.h"
#include "matter_tlv.h"

/*
 * The same tag numbers matter_case.c defines, from the same source, spelled out
 * again rather than shared through a header.
 *
 * WHY NOT JUST export them: they would then be part of this module's public
 * surface, and they are not -- they are the wire format of one protocol, read
 * by exactly two files. Two short lists that cite the same line of CHIP are
 * cheaper to keep honest than one header that invites a third reader.
 */

/* Sigma1 field tags (CASESession.cpp:74-83). */
#define TAG_S1_INITIATOR_RANDOM  1u
#define TAG_S1_INITIATOR_SESSION 2u
#define TAG_S1_DESTINATION_ID    3u
#define TAG_S1_INITIATOR_PUBKEY  4u

/* Sigma2 field tags (CASESession.cpp:85-92). */
#define TAG_S2_RESPONDER_RANDOM  1u
#define TAG_S2_RESPONDER_SESSION 2u
#define TAG_S2_RESPONDER_PUBKEY  3u
#define TAG_S2_ENCRYPTED         4u

/* The only field a Sigma3 has (CASESession.cpp:101-104, Sigma3Tags). */
#define TAG_S3_ENCRYPTED 1u

/* TBSData and TBEData tags, shared by Sigma2 and Sigma3 (CASESession.cpp:56-72). */
#define TAG_TBS_NOC           1u
#define TAG_TBS_ICAC          2u
#define TAG_TBS_SENDER_PUBKEY 3u
#define TAG_TBS_RECV_PUBKEY   4u

#define TAG_TBE_NOC           1u
#define TAG_TBE_ICAC          2u
#define TAG_TBE_SIGNATURE     3u
#define TAG_TBE_RESUMPTION_ID 4u

/** Length of the S2K salt: IPK, random, ephemeral key, transcript hash. */
#define S2K_SALT_LEN (MATTER_CASE_IPK_LEN + MATTER_CASE_RANDOM_LEN + MATTER_CASE_PUBKEY_LEN + 32u)

/** Length of the S3K salt: the IPK and the transcript hash, and nothing else. */
#define S3K_SALT_LEN (MATTER_CASE_IPK_LEN + 32u)

/**
 * Two scratch buffers, and why they are this size rather than a kilobyte each.
 *
 * The responder half gets away with one buffer because Sigma2 is finished with
 * before its Sigma3 arrives. Opening a Sigma2 cannot: the certificates the
 * signature covers are still sitting in the decrypted TBEData2 while TBSData2
 * is rebuilt over them, so both ARE live at once -- the same reason
 * matter_case_sigma3_open() keeps a second one.
 *
 * 768 bytes each, not MATTER_CASE_SIGMA2_MAX. A TBEData2 is a NOC (253 bytes
 * from Apple, 320 the most this node will store), a 64-byte signature, a
 * 16-byte resumption id and their framing: about 350. The kilobyte only
 * becomes necessary when the peer's chain also carries an INTERMEDIATE
 * certificate, and 1.5 KB of RAM on a part with 16 KB left over is not worth
 * spending on a case no lock this feature targets produces -- chip-tool and
 * Apple Home both issue a NOC straight off the root.
 *
 * The cost is a real limit, stated here rather than discovered: a peer whose
 * Sigma2 does not fit is REFUSED with MATTER_E_NOSPACE, loudly, and the
 * binding to it will never come up. That is a diagnosable failure with one
 * fix; a truncated certificate would be a signature that fails for no visible
 * reason.
 */
#define CLIENT_SCRATCH 768u
static uint8_t s_plain[CLIENT_SCRATCH];
static uint8_t s_rebuild[CLIENT_SCRATCH];

/* --------------------------------------------------------- Sigma1 --- */

/**
 * Encode a Sigma1 by deriving the destination identifier for the named peer and wrapping it, the
 * initiator random, session id and ephemeral public key in TLV; returns MATTER_OK on success.
 */
int matter_case_client_sigma1_encode(const struct matter_case_client_sigma1_in *in, uint8_t *out,
				     size_t cap, size_t *out_len)
{
	uint8_t dest[MATTER_CASE_DEST_ID_LEN];
	struct matter_tlv_writer w;
	int rc;

	if (in == NULL || out == NULL || out_len == NULL) {
		return MATTER_E_INVAL;
	}
	if (in->ipk == NULL || in->root_pub == NULL || in->initiator_random == NULL ||
	    in->initiator_eph_pub == NULL) {
		return MATTER_E_INVAL;
	}

	rc = matter_case_destination_id(in->ipk, in->initiator_random, in->root_pub, in->fabric_id,
					in->peer_node_id, dest);
	if (rc != MATTER_OK) {
		return rc;
	}

	matter_tlv_writer_init(&w, out, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_S1_INITIATOR_RANDOM), in->initiator_random,
				   MATTER_CASE_RANDOM_LEN);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_S1_INITIATOR_SESSION),
				 in->initiator_session_id);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_S1_DESTINATION_ID), dest, sizeof(dest));
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_S1_INITIATOR_PUBKEY),
				   in->initiator_eph_pub, MATTER_CASE_PUBKEY_LEN);
	(void)matter_tlv_end_container(&w);

	rc = matter_tlv_writer_finish(&w, out_len);
	memset(dest, 0, sizeof(dest));
	return rc;
}

/* --------------------------------------------------------- Sigma2 --- */

/** Borrow one octet string of an expected length out of the loaded element. */
static int take_bytes(const struct matter_tlv_reader *r, const uint8_t **out, size_t want)
{
	const uint8_t *p = NULL;
	size_t len = 0u;

	if (matter_tlv_get_bytes(r, &p, &len) != MATTER_OK) {
		return MATTER_E_TYPE;
	}
	if (len != want) {
		return MATTER_E_INVAL;
	}
	*out = p;
	return MATTER_OK;
}

/**
 * Decode a Sigma2 message from TLV, extracting the responder random, session id, ephemeral public
 * key and the still-sealed TBEData2; skips unknown fields and returns MATTER_E_INVAL if a mandatory
 * one is missing.
 */
int matter_case_client_sigma2_decode(const uint8_t *tlv, size_t len,
				     struct matter_case_client_sigma2 *out)
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

		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_S2_RESPONDER_RANDOM)) {
			rc = take_bytes(&r, &out->responder_random, MATTER_CASE_RANDOM_LEN);
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_S2_RESPONDER_PUBKEY)) {
			rc = take_bytes(&r, &out->responder_eph_pub, MATTER_CASE_PUBKEY_LEN);
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_S2_RESPONDER_SESSION)) {
			if (matter_tlv_get_u64(&r, &v) != MATTER_OK || v > 0xFFFFu) {
				return MATTER_E_INVAL;
			}
			out->responder_session_id = (uint16_t)v;
			rc = MATTER_OK;
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_S2_ENCRYPTED)) {
			if (matter_tlv_get_bytes(&r, &out->encrypted, &out->encrypted_len) !=
			    MATTER_OK) {
				return MATTER_E_TYPE;
			}
			rc = MATTER_OK;
		} else {
			/* SessionParameters, and anything a later revision adds. */
			rc = MATTER_OK;
		}
		if (rc != MATTER_OK) {
			return rc;
		}
	}

	/*
	 * Shorter than its own authentication tag means there is no ciphertext
	 * at all, and the subtraction in the open path below would wrap.
	 */
	if (out->responder_random == NULL || out->responder_eph_pub == NULL ||
	    out->encrypted == NULL || out->encrypted_len <= MATTER_TAG_LEN) {
		return MATTER_E_INVAL;
	}
	return MATTER_OK;
}

/**
 * Open a Sigma2: derive the ECDH secret and S2K, decrypt TBEData2, rebuild and check the signature
 * over TBSData2, walk the peer's chain up to the fabric root, and require the NOC to name the node
 * that was asked for; returns MATTER_OK on success.
 */
int matter_case_client_sigma2_open(const struct matter_case_client_sigma2_in *in,
				   struct matter_case_client_sigma2_out *out)
{
	/* "Sigma2" and "NCASE_Sigma2N" (CASESession.cpp:128,138). */
	static const uint8_t k_info[] = {0x53, 0x69, 0x67, 0x6D, 0x61, 0x32};
	static const uint8_t k_nonce[MATTER_NONCE_LEN] = {0x4E, 0x43, 0x41, 0x53, 0x45, 0x5F, 0x53,
							  0x69, 0x67, 0x6D, 0x61, 0x32, 0x4E};
	uint8_t salt[S2K_SALT_LEN];
	uint8_t s2k[MATTER_KEY_LEN];
	struct matter_cert_info cert;
	struct matter_tlv_reader r;
	struct matter_tlv_writer w;
	const uint8_t *noc = NULL;
	const uint8_t *icac = NULL;
	const uint8_t *sig = NULL;
	size_t noc_len = 0u;
	size_t icac_len = 0u;
	size_t sig_len = 0u;
	size_t off = 0u;
	size_t n;
	int rc;

	if (in == NULL || out == NULL || in->s2 == NULL) {
		return MATTER_E_INVAL;
	}
	if (in->ipk == NULL || in->transcript_hash == NULL || in->initiator_eph_priv == NULL ||
	    in->initiator_eph_pub == NULL || in->root_pub == NULL) {
		return MATTER_E_INVAL;
	}
	/*
	 * Re-checked rather than trusted to the decoder, which is where a
	 * Sigma2 normally comes from. A struct filled in by hand with a
	 * ciphertext no longer than its own tag would wrap the subtraction
	 * below into a length of nearly SIZE_MAX.
	 */
	if (in->s2->responder_random == NULL || in->s2->responder_eph_pub == NULL ||
	    in->s2->encrypted == NULL || in->s2->encrypted_len <= MATTER_TAG_LEN) {
		return MATTER_E_INVAL;
	}
	memset(out, 0, sizeof(*out));

	n = in->s2->encrypted_len - MATTER_TAG_LEN;
	if (n > sizeof(s_plain)) {
		return MATTER_E_NOSPACE;
	}

	if (matter_case_ecdh(in->initiator_eph_priv, in->s2->responder_eph_pub, out->shared) != 0) {
		return MATTER_E_STATE;
	}

	memcpy(&salt[off], in->ipk, MATTER_CASE_IPK_LEN);
	off += MATTER_CASE_IPK_LEN;
	memcpy(&salt[off], in->s2->responder_random, MATTER_CASE_RANDOM_LEN);
	off += MATTER_CASE_RANDOM_LEN;
	memcpy(&salt[off], in->s2->responder_eph_pub, MATTER_CASE_PUBKEY_LEN);
	off += MATTER_CASE_PUBKEY_LEN;
	memcpy(&salt[off], in->transcript_hash, 32u);
	off += 32u;

	rc = ultrawidelock_hkdf(salt, off, out->shared, MATTER_CASE_SECRET_LEN, k_info,
				sizeof(k_info), s2k, sizeof(s2k));
	memset(salt, 0, sizeof(salt));
	if (rc != 0) {
		return MATTER_E_STATE;
	}

	/* The tag is the last MATTER_TAG_LEN bytes; no AAD, Sigma2 has none. */
	rc = matter_aead_decrypt(s2k, k_nonce, NULL, 0u, in->s2->encrypted, n,
				 in->s2->encrypted + n, s_plain);
	memset(s2k, 0, sizeof(s2k));
	if (rc != MATTER_OK) {
		return rc;
	}

	/* TBEData2: the peer's chain, its signature over TBSData2, and the
	 * resumption id it would accept on a later handshake. */
	matter_tlv_reader_init(&r, s_plain, n);
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
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_TBE_NOC)) {
			rc = matter_tlv_get_bytes(&r, &noc, &noc_len);
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_TBE_ICAC)) {
			rc = matter_tlv_get_bytes(&r, &icac, &icac_len);
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_TBE_SIGNATURE)) {
			rc = matter_tlv_get_bytes(&r, &sig, &sig_len);
		} else {
			/* TAG_TBE_RESUMPTION_ID lands here and is deliberately
			 * dropped: it is an offer to skip a later handshake, and
			 * this node caches the SESSION instead -- see
			 * matter_case_client_sigma1_encode(). */
			rc = MATTER_OK;
		}
		if (rc != MATTER_OK) {
			return MATTER_E_TYPE;
		}
	}
	if (noc == NULL || sig == NULL || sig_len != MATTER_CASE_SIG_LEN) {
		return MATTER_E_INVAL;
	}

	/*
	 * TBSData2. The SENDER here is the PEER, so its ephemeral key goes in
	 * tag 3 and this node's in tag 4 -- the mirror of the swap
	 * matter_case_sigma3_open() warns about, and just as silent when wrong.
	 */
	matter_tlv_writer_init(&w, s_rebuild, sizeof(s_rebuild));
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_NOC), noc, noc_len);
	if (icac != NULL && icac_len > 0u) {
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_ICAC), icac, icac_len);
	}
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_SENDER_PUBKEY),
				   in->s2->responder_eph_pub, MATTER_CASE_PUBKEY_LEN);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_RECV_PUBKEY), in->initiator_eph_pub,
				   MATTER_CASE_PUBKEY_LEN);
	(void)matter_tlv_end_container(&w);
	rc = matter_tlv_writer_finish(&w, &off);
	if (rc != MATTER_OK) {
		return rc;
	}

	if (matter_cert_parse(noc, noc_len, &cert) != MATTER_OK || !cert.have_public_key) {
		return MATTER_E_INVAL;
	}
	if (matter_case_verify(cert.public_key, s_rebuild, off, sig) != 0) {
		return MATTER_E_TYPE;
	}

	/*
	 * The signature proved the peer holds the key its NOC names. Nothing so
	 * far proves that NOC came from THIS fabric's root, and unlike the
	 * responder -- which only ever answers a peer that already demonstrated
	 * the IPK -- a client chose who to talk to and has to be told it
	 * reached them. s_rebuild is free again by now: the signature it held
	 * has been checked.
	 */
	if (icac != NULL && icac_len > 0u) {
		struct matter_cert_info issuer;

		rc = matter_case_cert_verify(icac, icac_len, in->root_pub, s_rebuild,
					     sizeof(s_rebuild));
		if (rc != MATTER_OK) {
			return rc;
		}
		if (matter_cert_parse(icac, icac_len, &issuer) != MATTER_OK ||
		    !issuer.have_public_key) {
			return MATTER_E_INVAL;
		}
		rc = matter_case_cert_verify(noc, noc_len, issuer.public_key, s_rebuild,
					     sizeof(s_rebuild));
	} else {
		rc = matter_case_cert_verify(noc, noc_len, in->root_pub, s_rebuild,
					     sizeof(s_rebuild));
	}
	if (rc != MATTER_OK) {
		return rc;
	}

	/*
	 * And that it is the node that was asked for. A chain check alone would
	 * accept ANY member of the fabric answering for the bound peer, which is
	 * the whole difference between "somebody on my fabric" and "my lock".
	 */
	if (!cert.have_node_id || !cert.have_fabric_id || cert.fabric_id != in->fabric_id ||
	    cert.node_id != in->peer_node_id) {
		return MATTER_E_ACCESS;
	}

	out->node_id = cert.node_id;
	out->fabric_id = cert.fabric_id;
	memcpy(out->public_key, cert.public_key, MATTER_CASE_PUBKEY_LEN);
	return MATTER_OK;
}

/* --------------------------------------------------------- Sigma3 --- */

/**
 * Encode a Sigma3 by deriving S3K from the transcript, signing TBSData3 with this fabric's
 * operational key, and sealing TBEData3 under it; returns MATTER_OK on success.
 */
int matter_case_client_sigma3_encode(const struct matter_case_client_sigma3_in *in, uint8_t *out,
				     size_t cap, size_t *out_len)
{
	/* "Sigma3" and "NCASE_Sigma3N" (CASESession.cpp:129,140). */
	static const uint8_t k_info[] = {0x53, 0x69, 0x67, 0x6D, 0x61, 0x33};
	static const uint8_t k_nonce[MATTER_NONCE_LEN] = {0x4E, 0x43, 0x41, 0x53, 0x45, 0x5F, 0x53,
							  0x69, 0x67, 0x6D, 0x61, 0x33, 0x4E};
	uint8_t salt[S3K_SALT_LEN];
	uint8_t s3k[MATTER_KEY_LEN];
	uint8_t sig[MATTER_CASE_SIG_LEN];
	struct matter_tlv_writer w;
	size_t n = 0u;
	int rc;

	if (in == NULL || out == NULL || out_len == NULL) {
		return MATTER_E_INVAL;
	}
	if (in->shared == NULL || in->ipk == NULL || in->transcript_hash == NULL ||
	    in->initiator_eph_pub == NULL || in->responder_eph_pub == NULL || in->noc == NULL ||
	    in->op_priv == NULL) {
		return MATTER_E_INVAL;
	}

	/*
	 * TBSData3. Signed, never transmitted: the peer rebuilds it from what it
	 * already has. The SENDER is this node now, so its ephemeral key is in
	 * tag 3 -- the opposite of the Sigma2 opened a moment ago.
	 */
	matter_tlv_writer_init(&w, s_plain, sizeof(s_plain));
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_NOC), in->noc, in->noc_len);
	if (in->icac != NULL && in->icac_len > 0u) {
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_ICAC), in->icac, in->icac_len);
	}
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_SENDER_PUBKEY), in->initiator_eph_pub,
				   MATTER_CASE_PUBKEY_LEN);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_RECV_PUBKEY), in->responder_eph_pub,
				   MATTER_CASE_PUBKEY_LEN);
	(void)matter_tlv_end_container(&w);
	rc = matter_tlv_writer_finish(&w, &n);
	if (rc != MATTER_OK) {
		return rc;
	}

	if (matter_case_sign(in->op_priv, s_plain, n, sig) != 0) {
		return MATTER_E_STATE;
	}
	/* Verified here against the NOC that goes out beside it, for the reason
	 * matter_case_sigma2_encode() gives: a peer that rejects a signature
	 * says nothing about why. */
	if (in->verify_pub != NULL && matter_case_verify(in->verify_pub, s_plain, n, sig) != 0) {
		return MATTER_E_STATE;
	}

	memcpy(salt, in->ipk, MATTER_CASE_IPK_LEN);
	memcpy(&salt[MATTER_CASE_IPK_LEN], in->transcript_hash, 32u);
	rc = ultrawidelock_hkdf(salt, sizeof(salt), in->shared, MATTER_CASE_SECRET_LEN, k_info,
				sizeof(k_info), s3k, sizeof(s3k));
	memset(salt, 0, sizeof(salt));
	if (rc != 0) {
		return MATTER_E_STATE;
	}

	/* TBEData3, over the same buffer now that the signature exists. */
	matter_tlv_writer_init(&w, s_plain, sizeof(s_plain) - MATTER_TAG_LEN);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBE_NOC), in->noc, in->noc_len);
	if (in->icac != NULL && in->icac_len > 0u) {
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBE_ICAC), in->icac, in->icac_len);
	}
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBE_SIGNATURE), sig, sizeof(sig));
	(void)matter_tlv_end_container(&w);
	rc = matter_tlv_writer_finish(&w, &n);
	if (rc != MATTER_OK) {
		memset(s3k, 0, sizeof(s3k));
		return rc;
	}

	/* Encrypted in place, tag appended. No AAD, the same as Sigma2. */
	rc = matter_aead_encrypt(s3k, k_nonce, NULL, 0u, s_plain, n, s_plain, s_plain + n);
	memset(s3k, 0, sizeof(s3k));
	if (rc != MATTER_OK) {
		return rc;
	}
	n += MATTER_TAG_LEN;

	matter_tlv_writer_init(&w, out, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_S3_ENCRYPTED), s_plain, n);
	(void)matter_tlv_end_container(&w);
	return matter_tlv_writer_finish(&w, out_len);
}

/**
 * Derive the session keys for a handshake this node started and swap i2r with r2i, so the one
 * direction rule matter_exchange.c already implements is true for the initiator too; returns
 * MATTER_OK on success.
 */
int matter_case_client_keys(const uint8_t shared[MATTER_CASE_SECRET_LEN],
			    const uint8_t ipk[MATTER_CASE_IPK_LEN],
			    const uint8_t transcript_hash[32], struct matter_session_keys *out)
{
	uint8_t salt[S3K_SALT_LEN];
	uint8_t swap[MATTER_KEY_LEN];
	int rc;

	if (shared == NULL || ipk == NULL || transcript_hash == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}

	memcpy(salt, ipk, MATTER_CASE_IPK_LEN);
	memcpy(&salt[MATTER_CASE_IPK_LEN], transcript_hash, 32u);
	rc = matter_derive_session_keys(shared, MATTER_CASE_SECRET_LEN, salt, sizeof(salt), false,
					out);
	memset(salt, 0, sizeof(salt));
	if (rc != MATTER_OK) {
		return rc;
	}

	memcpy(swap, out->i2r, sizeof(swap));
	memcpy(out->i2r, out->r2i, sizeof(swap));
	memcpy(out->r2i, swap, sizeof(swap));
	memset(swap, 0, sizeof(swap));
	return MATTER_OK;
}
