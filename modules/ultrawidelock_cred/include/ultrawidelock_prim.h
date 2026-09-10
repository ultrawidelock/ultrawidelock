/* SPDX-License-Identifier: ISC */

/*
 * ultrawidelock_prim — the symmetric-crypto + elliptic-curve + RNG primitive
 * interface used by the portable modules. Target builds use
 * ultrawidelock_prim_psa.c over their platform's PSA provider; host tests use a
 * recording or reference double.
 *
 * Hashing/KDF is NOT here; that is the portable ultrawidelock_hash.c, shared by both.
 * All returns: 0 on success, negative on failure (AEAD decrypt returns <0 on a
 * tag mismatch and must be treated as a hard auth failure).
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ULTRAWIDELOCK_P256_SCALAR 32u /* private scalar / coordinate */
#define ULTRAWIDELOCK_P256_POINT  65u /* uncompressed point: 0x04 | X32 | Y32 */
#define ULTRAWIDELOCK_P256_SIG    64u /* raw ECDSA r|s */
#define ULTRAWIDELOCK_GCM_TAG     16u
#define ULTRAWIDELOCK_CCM_TAG     16u /* maximum; the sealed link uses 8 */

/* Initialise the backend (idempotent). Call once before any other call. */
int ultrawidelock_prim_init(void);

/* CSPRNG. */
int ultrawidelock_random(uint8_t *out, size_t len);

/* AES-256-GCM. tag_len must be <= 16. Decrypt verifies the tag, and may decrypt
 * in place: pt may start at or below ct in the same buffer (never above it). */
int ultrawidelock_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t *nonce, size_t nonce_len,
			     const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len,
			     uint8_t *ct, uint8_t *tag, size_t tag_len);
int ultrawidelock_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t *nonce, size_t nonce_len,
			     const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len,
			     const uint8_t *tag, size_t tag_len, uint8_t *pt);

/*
 * AES-ECB, one block. key_bits must be 128 or 256. This is the primitive
 * beneath the CCC key ladder, Matter CCM, and the advertisement Dynamic Tag.
 */
int ultrawidelock_aes_ecb_encrypt(const uint8_t *key, size_t key_bits,
				  const uint8_t in[16], uint8_t out[16]);

/* Stable AES-128 convenience ABI used by the advertisement Dynamic Tag. */
int ultrawidelock_aes128_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

/*
 * AES-128-CCM, one shot, no AAD (the sealed link between the lock and its
 * satellites and witnesses). Output is ciphertext ‖ tag, which is what goes on
 * the wire; the GCM pair above hands the tag back separately because it streams
 * a message that does not fit in RAM, and these messages are tens of bytes.
 *
 * No AAD parameter because nothing has one: everything the seal authenticates
 * is inside the plaintext, and the nonce carries the sender and counter. Add it
 * when a caller needs it, not before.
 *
 * tag_len must be <= ULTRAWIDELOCK_CCM_TAG. *out_len is what the backend wrote.
 * Decrypt verifies the tag and returns <0 on a mismatch: a hard auth failure,
 * never a retry.
 */
int ultrawidelock_aes128_ccm_encrypt(const uint8_t key[16], const uint8_t *nonce, size_t nonce_len,
				     const uint8_t *pt, size_t pt_len, size_t tag_len, uint8_t *out,
				     size_t out_cap, size_t *out_len);
int ultrawidelock_aes128_ccm_decrypt(const uint8_t key[16], const uint8_t *nonce, size_t nonce_len,
				     const uint8_t *in, size_t in_len, size_t tag_len, uint8_t *out,
				     size_t out_cap, size_t *out_len);

/* P-256 ephemeral key pair: priv = 32-byte scalar, pub = 65-byte point. */
int ultrawidelock_ec_p256_keygen(uint8_t priv[ULTRAWIDELOCK_P256_SCALAR],
				 uint8_t pub[ULTRAWIDELOCK_P256_POINT]);

/* Derive the 65-byte uncompressed public key from a 32-byte P-256 private
 * scalar (used to recover the reader group key X from the provisioned
 * signingKey; verificationKey = pub(signingKey)). */
int ultrawidelock_ec_p256_pub_from_priv(const uint8_t priv[ULTRAWIDELOCK_P256_SCALAR],
				uint8_t pub[ULTRAWIDELOCK_P256_POINT]);

/* ECDH: shared_x = X coordinate (32 bytes) of priv * peer_pub. */
int ultrawidelock_ecdh_p256(const uint8_t priv[ULTRAWIDELOCK_P256_SCALAR],
			    const uint8_t peer_pub[ULTRAWIDELOCK_P256_POINT],
			    uint8_t shared_x[ULTRAWIDELOCK_P256_SCALAR]);

/* ECDSA-P256-SHA256 over the raw message (hashing is internal). sig = r|s. */
int ultrawidelock_ecdsa_p256_sign(const uint8_t priv[ULTRAWIDELOCK_P256_SCALAR], const uint8_t *msg,
				  size_t msg_len, uint8_t sig[ULTRAWIDELOCK_P256_SIG]);
/* ECDSA-P256 over an already computed SHA-256 digest. sig = r|s. */
int ultrawidelock_ecdsa_p256_sign_hash(const uint8_t priv[ULTRAWIDELOCK_P256_SCALAR],
				       const uint8_t hash[32], uint8_t sig[ULTRAWIDELOCK_P256_SIG]);
int ultrawidelock_ecdsa_p256_verify(const uint8_t pub[ULTRAWIDELOCK_P256_POINT], const uint8_t *msg,
				    size_t msg_len, const uint8_t sig[ULTRAWIDELOCK_P256_SIG]);

#ifdef __cplusplus
}
#endif
