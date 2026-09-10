/* SPDX-License-Identifier: ISC */

// credential crypto primitive backend implemented on Arm PSA Crypto: random generation, AES-256-GCM
// encrypt/decrypt, and NIST P-256 key generation, ECDH, and ECDSA sign/verify.
// Provides the ultrawidelock_prim_* / ultrawidelock_* primitive functions consumed by the
// higher-level credential KDF and secure-channel code in ultrawidelock_crypto.c; callers must call
// ultrawidelock_prim_init before using any other function in this file.
/*
 * ultrawidelock_prim backend for the ESP32 target: AES-256-GCM, P-256 ECDH/ECDSA, and
 * the CSPRNG, all on mbedTLS-PSA. Compiled only in the ESP-IDF build; the host
 * test build supplies its own double. See ultrawidelock_prim.h.
 */
#include "ultrawidelock_prim.h"

#include <string.h>

#include "psa/crypto.h"

#define ULTRAWIDELOCK_AES_BLOCK 16u

// Initialize the PSA Crypto backend.
// Must be called before any other ultrawidelock_prim_psa function. Returns 0 on success, -1 on
// failure.
int ultrawidelock_prim_init(void)
{
	return psa_crypto_init() == PSA_SUCCESS ? 0 : -1;
}

// Fill out with len bytes of cryptographically secure random data via PSA Crypto.
// Returns 0 on success, -1 on failure.
int ultrawidelock_random(uint8_t *out, size_t len)
{
	return psa_generate_random(out, len) == PSA_SUCCESS ? 0 : -1;
}

// Encrypt and authenticate plaintext with AES-256-GCM via PSA Crypto.
// Writes pt_len bytes of ciphertext to ct and tag_len bytes of authentication tag to tag. Returns 0
// on success, -1 if tag_len exceeds ULTRAWIDELOCK_GCM_TAG, key import fails, or encryption fails.
int ultrawidelock_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t *nonce, size_t nonce_len,
			     const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len,
			     uint8_t *ct, uint8_t *tag, size_t tag_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
	psa_key_id_t k = 0;
	psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, tag_len);
	/* PSA permits a block backend to delay up to one block, so every update
	 * must be offered input_length + one block of output room -- not
	 * input_length, which a strictly conforming backend refuses with
	 * BUFFER_TOO_SMALL. ct holds exactly pt_len bytes, so the direct prefix
	 * stops one block short of the end and that block is the headroom; the
	 * remainder (under two blocks) goes through scratch. Still no
	 * message-sized buffer: the former one-shot path kept 1040 bytes. */
	uint8_t pending[3u * ULTRAWIDELOCK_AES_BLOCK];
	uint8_t final[2u * ULTRAWIDELOCK_AES_BLOCK];
	size_t bulk_len = (pt_len >= ULTRAWIDELOCK_AES_BLOCK)
				  ? ((pt_len - ULTRAWIDELOCK_AES_BLOCK) &
				     ~(size_t)(ULTRAWIDELOCK_AES_BLOCK - 1u))
				  : 0u;
	size_t tail_len = pt_len - bulk_len;
	size_t bulk_out = 0;
	size_t pending_len = 0;
	size_t finish_len = 0;
	size_t actual_tag_len = 0;
	int rc = -1;

	if (tag_len > ULTRAWIDELOCK_GCM_TAG) {
		return -1;
	}
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&attr, alg);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 256);
	if (psa_import_key(&attr, key, 32, &k) != PSA_SUCCESS) {
		return -1;
	}
	if (psa_aead_encrypt_setup(&op, k, alg) == PSA_SUCCESS &&
	    psa_aead_set_lengths(&op, aad_len, pt_len) == PSA_SUCCESS &&
	    psa_aead_set_nonce(&op, nonce, nonce_len) == PSA_SUCCESS &&
	    psa_aead_update_ad(&op, aad, aad_len) == PSA_SUCCESS &&
	    (bulk_len == 0u ||
	     psa_aead_update(&op, pt, bulk_len, ct, pt_len, &bulk_out) == PSA_SUCCESS) &&
	    bulk_out <= pt_len &&
	    (tail_len == 0u ||
	     psa_aead_update(&op, pt + bulk_len, tail_len, pending, sizeof(pending),
			     &pending_len) == PSA_SUCCESS) &&
	    pending_len <= sizeof(pending) &&
	    psa_aead_finish(&op, final, sizeof(final), &finish_len, tag, tag_len,
			    &actual_tag_len) == PSA_SUCCESS &&
	    finish_len <= sizeof(final) && bulk_out <= pt_len &&
	    pending_len <= pt_len - bulk_out && finish_len == pt_len - bulk_out - pending_len &&
	    actual_tag_len == tag_len) {
		memcpy(ct + bulk_out, pending, pending_len);
		memcpy(ct + bulk_out + pending_len, final, finish_len);
		rc = 0;
	}
	(void)psa_aead_abort(&op);
	psa_destroy_key(k);
	return rc;
}

// Decrypt the block-aligned prefix through a small window and copy each piece out, rather than
// straight into pt. A GCM backend never emits more than it has read, so every piece lands behind
// input already consumed and pt may start at or below ct in the same buffer -- the step-up learn
// path opens a SessionData in the buffer it arrived in. No update is handed overlapping buffers,
// which PSA leaves undefined; one that would write past the input it has read fails closed. The
// window keeps the portable contract: input plus one block of output room.
static int gcm_decrypt_bulk(psa_aead_operation_t *op, const uint8_t *ct, size_t len, uint8_t *pt,
			    uint8_t *win, size_t win_len, size_t *out_len)
{
	size_t step = win_len - ULTRAWIDELOCK_AES_BLOCK;
	size_t done = 0;

	*out_len = 0;
	while (done < len) {
		size_t n = (len - done < step) ? len - done : step;
		size_t got = 0;

		if (psa_aead_update(op, ct + done, n, win, win_len, &got) != PSA_SUCCESS ||
		    got > win_len || *out_len + got > done + n) {
			return -1;
		}
		memcpy(pt + *out_len, win, got);
		*out_len += got;
		done += n;
	}
	return 0;
}

// Decrypt and authenticate an AES-256-GCM ciphertext via PSA Crypto.
// Writes ct_len bytes of plaintext to pt, which may alias ct from below (see gcm_decrypt_bulk).
// Returns 0 on success (tag verified), -1 if tag_len exceeds ULTRAWIDELOCK_GCM_TAG, key import
// fails, or authentication/decryption fails.
int ultrawidelock_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t *nonce, size_t nonce_len,
			     const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len,
			     const uint8_t *tag, size_t tag_len, uint8_t *pt)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
	psa_key_id_t k = 0;
	psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, tag_len);
	/* See encrypt: the prefix stops one block short of the end so every
	 * update has input_length + one block of output room, which is what PSA's
	 * portable contract requires -- and still no message-sized scratch. The
	 * prefix goes through pending as its window before the tail uses it. */
	uint8_t pending[3u * ULTRAWIDELOCK_AES_BLOCK];
	uint8_t final[2u * ULTRAWIDELOCK_AES_BLOCK];
	size_t bulk_len = (ct_len >= ULTRAWIDELOCK_AES_BLOCK)
				  ? ((ct_len - ULTRAWIDELOCK_AES_BLOCK) &
				     ~(size_t)(ULTRAWIDELOCK_AES_BLOCK - 1u))
				  : 0u;
	size_t tail_len = ct_len - bulk_len;
	size_t bulk_out = 0;
	size_t pending_len = 0;
	size_t verify_len = 0;
	int rc = -1;

	if (tag_len > ULTRAWIDELOCK_GCM_TAG) {
		return -1;
	}
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attr, alg);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 256);
	if (psa_import_key(&attr, key, 32, &k) != PSA_SUCCESS) {
		return -1;
	}
	if (psa_aead_decrypt_setup(&op, k, alg) == PSA_SUCCESS &&
	    psa_aead_set_lengths(&op, aad_len, ct_len) == PSA_SUCCESS &&
	    psa_aead_set_nonce(&op, nonce, nonce_len) == PSA_SUCCESS &&
	    psa_aead_update_ad(&op, aad, aad_len) == PSA_SUCCESS &&
	    gcm_decrypt_bulk(&op, ct, bulk_len, pt, pending, sizeof(pending), &bulk_out) == 0 &&
	    bulk_out <= ct_len &&
	    (tail_len == 0u ||
	     psa_aead_update(&op, ct + bulk_len, tail_len, pending, sizeof(pending),
			     &pending_len) == PSA_SUCCESS) &&
	    pending_len <= sizeof(pending) &&
	    psa_aead_verify(&op, final, sizeof(final), &verify_len, tag, tag_len) == PSA_SUCCESS &&
	    verify_len <= sizeof(final) && bulk_out <= ct_len &&
	    pending_len <= ct_len - bulk_out && verify_len == ct_len - bulk_out - pending_len) {
		memcpy(pt + bulk_out, pending, pending_len);
		memcpy(pt + bulk_out + pending_len, final, verify_len);
		rc = 0;
	}
	(void)psa_aead_abort(&op);
	psa_destroy_key(k);
	/* Multipart PSA decrypt may emit tentative plaintext before tag
	 * verification. Never return attacker-controlled unauthenticated bytes to
	 * a caller on any failure path. */
	if (rc != 0 && ct_len > 0u) {
		memset(pt, 0, ct_len);
	}
	return rc;
}

// Encrypt one AES-128/256-ECB block via PSA Crypto. Returns 0 on success, -1
// for an invalid argument, unsupported key size, or backend failure.
int ultrawidelock_aes_ecb_encrypt(const uint8_t *key, size_t key_bits,
				  const uint8_t in[16], uint8_t out[16])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = 0;
	size_t olen = 0;
	int rc = -1;

	if (key == NULL || in == NULL || out == NULL ||
	    (key_bits != 128u && key_bits != 256u)) {
		return -1;
	}
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&attr, PSA_ALG_ECB_NO_PADDING);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, key_bits);
	if (psa_import_key(&attr, key, key_bits / 8u, &k) != PSA_SUCCESS) {
		return -1;
	}
	/* ECB has no IV, so the one-shot output is exactly the 16-byte block. */
	if (psa_cipher_encrypt(k, PSA_ALG_ECB_NO_PADDING, in, 16, out, 16, &olen) == PSA_SUCCESS &&
	    olen == 16) {
		rc = 0;
	}
	psa_destroy_key(k);
	return rc;
}

int ultrawidelock_aes128_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
	return ultrawidelock_aes_ecb_encrypt(key, 128u, in, out);
}

// Encrypt and authenticate plaintext with AES-128-CCM via PSA Crypto.
// Writes ciphertext ‖ tag to out and its length to *out_len. Returns 0 on success, -1 if tag_len
// exceeds ULTRAWIDELOCK_CCM_TAG, key import fails, or encryption fails.
int ultrawidelock_aes128_ccm_encrypt(const uint8_t key[16], const uint8_t *nonce, size_t nonce_len,
				     const uint8_t *pt, size_t pt_len, size_t tag_len, uint8_t *out,
				     size_t out_cap, size_t *out_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = 0;
	psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, tag_len);
	int rc = -1;

	if (tag_len > ULTRAWIDELOCK_CCM_TAG) {
		return -1;
	}
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&attr, alg);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 128);
	if (psa_import_key(&attr, key, 16, &k) != PSA_SUCCESS) {
		return -1;
	}
	/* One shot: CCM needs the whole message length up front anyway, and the
	 * sealed link's payloads are tens of bytes. No streaming path exists. */
	if (psa_aead_encrypt(k, alg, nonce, nonce_len, NULL, 0, pt, pt_len, out, out_cap,
			     out_len) == PSA_SUCCESS) {
		rc = 0;
	}
	psa_destroy_key(k);
	return rc;
}

// Verify and decrypt an AES-128-CCM ciphertext ‖ tag via PSA Crypto.
// Writes the plaintext to out and its length to *out_len. Returns 0 on success, -1 if tag_len
// exceeds ULTRAWIDELOCK_CCM_TAG, key import fails, or the tag does not verify.
int ultrawidelock_aes128_ccm_decrypt(const uint8_t key[16], const uint8_t *nonce, size_t nonce_len,
				     const uint8_t *in, size_t in_len, size_t tag_len, uint8_t *out,
				     size_t out_cap, size_t *out_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = 0;
	psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, tag_len);
	int rc = -1;

	if (tag_len > ULTRAWIDELOCK_CCM_TAG) {
		return -1;
	}
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attr, alg);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 128);
	if (psa_import_key(&attr, key, 16, &k) != PSA_SUCCESS) {
		return -1;
	}
	if (psa_aead_decrypt(k, alg, nonce, nonce_len, NULL, 0, in, in_len, out, out_cap,
			     out_len) == PSA_SUCCESS) {
		rc = 0;
	}
	psa_destroy_key(k);
	return rc;
}

// Generate a new NIST P-256 key pair via PSA Crypto.
// Writes the private scalar to priv and the uncompressed public point to pub. Returns 0 on success,
// -1 if key generation or export fails.
int ultrawidelock_ec_p256_keygen(uint8_t priv[ULTRAWIDELOCK_P256_SCALAR],
				 uint8_t pub[ULTRAWIDELOCK_P256_POINT])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = 0;
	size_t plen = 0, publen = 0;
	int rc = -1;

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	if (psa_generate_key(&attr, &k) != PSA_SUCCESS) {
		return -1;
	}
	if (psa_export_key(k, priv, ULTRAWIDELOCK_P256_SCALAR, &plen) == PSA_SUCCESS &&
	    plen == ULTRAWIDELOCK_P256_SCALAR &&
	    psa_export_public_key(k, pub, ULTRAWIDELOCK_P256_POINT, &publen) == PSA_SUCCESS &&
	    publen == ULTRAWIDELOCK_P256_POINT) {
		rc = 0;
	}
	psa_destroy_key(k);
	return rc;
}

// Derive the uncompressed P-256 public point from an existing private scalar via PSA Crypto.
// Writes the public point to pub. Returns 0 on success, -1 if the private key import or public-key
// export fails.
int ultrawidelock_ec_p256_pub_from_priv(const uint8_t priv[ULTRAWIDELOCK_P256_SCALAR],
				uint8_t pub[ULTRAWIDELOCK_P256_POINT])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = 0;
	size_t publen = 0;
	int rc = -1;

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	if (psa_import_key(&attr, priv, ULTRAWIDELOCK_P256_SCALAR, &k) != PSA_SUCCESS) {
		return -1;
	}
	if (psa_export_public_key(k, pub, ULTRAWIDELOCK_P256_POINT, &publen) == PSA_SUCCESS &&
	    publen == ULTRAWIDELOCK_P256_POINT) {
		rc = 0;
	}
	psa_destroy_key(k);
	return rc;
}

// Compute the P-256 ECDH shared secret x-coordinate for priv and a peer's public point via PSA
// Crypto. Writes the shared x-coordinate to shared_x. Returns 0 on success, -1 if key import or key
// agreement fails.
int ultrawidelock_ecdh_p256(const uint8_t priv[ULTRAWIDELOCK_P256_SCALAR],
			    const uint8_t peer_pub[ULTRAWIDELOCK_P256_POINT],
			    uint8_t shared_x[ULTRAWIDELOCK_P256_SCALAR])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = 0;
	size_t olen = 0;
	int rc = -1;

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	if (psa_import_key(&attr, priv, ULTRAWIDELOCK_P256_SCALAR, &k) != PSA_SUCCESS) {
		return -1;
	}
	if (psa_raw_key_agreement(PSA_ALG_ECDH, k, peer_pub, ULTRAWIDELOCK_P256_POINT, shared_x,
				  ULTRAWIDELOCK_P256_SCALAR, &olen) == PSA_SUCCESS &&
	    olen == ULTRAWIDELOCK_P256_SCALAR) {
		rc = 0;
	}
	psa_destroy_key(k);
	return rc;
}

// Sign a message with ECDSA over P-256 using SHA-256, via PSA Crypto.
// Writes the signature to sig. Returns 0 on success, -1 if private key import or signing fails.
int ultrawidelock_ecdsa_p256_sign(const uint8_t priv[ULTRAWIDELOCK_P256_SCALAR], const uint8_t *msg,
				  size_t msg_len, uint8_t sig[ULTRAWIDELOCK_P256_SIG])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = 0;
	size_t slen = 0;
	int rc = -1;

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	if (psa_import_key(&attr, priv, ULTRAWIDELOCK_P256_SCALAR, &k) != PSA_SUCCESS) {
		return -1;
	}
	if (psa_sign_message(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256), msg, msg_len, sig, ULTRAWIDELOCK_P256_SIG,
			     &slen) == PSA_SUCCESS &&
	    slen == ULTRAWIDELOCK_P256_SIG) {
		rc = 0;
	}
	psa_destroy_key(k);
	return rc;
}

/**
 * Sign a 32-byte SHA-256 hash using a P-256 private key via PSA Crypto; return 0 on success, -1 if
 * key import, signing, or output length validation fails.
 */
int ultrawidelock_ecdsa_p256_sign_hash(const uint8_t priv[ULTRAWIDELOCK_P256_SCALAR],
				       const uint8_t hash[32], uint8_t sig[ULTRAWIDELOCK_P256_SIG])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = 0;
	size_t slen = 0;
	int rc = -1;

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	if (psa_import_key(&attr, priv, ULTRAWIDELOCK_P256_SCALAR, &k) != PSA_SUCCESS) {
		return -1;
	}
	if (psa_sign_hash(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, 32u, sig, ULTRAWIDELOCK_P256_SIG,
			  &slen) == PSA_SUCCESS &&
	    slen == ULTRAWIDELOCK_P256_SIG) {
		rc = 0;
	}
	psa_destroy_key(k);
	return rc;
}

// Verify an ECDSA-P256/SHA-256 signature against a message and public key, via PSA Crypto.
// Returns 0 if the signature verifies, -1 if public key import fails or verification fails.
int ultrawidelock_ecdsa_p256_verify(const uint8_t pub[ULTRAWIDELOCK_P256_POINT], const uint8_t *msg,
				    size_t msg_len, const uint8_t sig[ULTRAWIDELOCK_P256_SIG])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = 0;
	int rc = -1;

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	if (psa_import_key(&attr, pub, ULTRAWIDELOCK_P256_POINT, &k) != PSA_SUCCESS) {
		return -1;
	}
	if (psa_verify_message(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256), msg, msg_len, sig,
			       ULTRAWIDELOCK_P256_SIG) == PSA_SUCCESS) {
		rc = 0;
	}
	psa_destroy_key(k);
	return rc;
}
