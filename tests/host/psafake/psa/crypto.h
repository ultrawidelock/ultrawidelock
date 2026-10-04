/* psafake: minimal <psa/crypto.h> recording double (see ../psafake.h — the
 * fake does NO crypto; statuses are knobs, outputs are deterministic filler).
 * Macro values are arbitrary-but-distinct; the suites assert the code under
 * test hands exactly these spellings through, nothing more. */
#ifndef PSAFAKE_PSA_CRYPTO_H
#define PSAFAKE_PSA_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "psafake.h"

typedef int32_t psa_status_t;
typedef uint32_t psa_key_id_t;
typedef uint32_t psa_algorithm_t;
typedef uint32_t psa_key_type_t;
typedef uint32_t psa_key_usage_t;

#define PSA_SUCCESS       ((psa_status_t)0)
#define PSA_ERROR_GENERIC ((psa_status_t)-132)
#define PSA_ERROR_BUFFER_TOO_SMALL ((psa_status_t)-138)
#define PSA_KEY_ID_NULL   ((psa_key_id_t)0)

#define PSA_KEY_USAGE_ENCRYPT        ((psa_key_usage_t)0x00000100u)
#define PSA_KEY_USAGE_DECRYPT        ((psa_key_usage_t)0x00000200u)
#define PSA_KEY_USAGE_SIGN_MESSAGE   ((psa_key_usage_t)0x00000400u)
#define PSA_KEY_USAGE_VERIFY_MESSAGE ((psa_key_usage_t)0x00000800u)
#define PSA_KEY_USAGE_SIGN_HASH      ((psa_key_usage_t)0x00001000u)
#define PSA_KEY_USAGE_VERIFY_HASH    ((psa_key_usage_t)0x00002000u)
#define PSA_KEY_USAGE_DERIVE         ((psa_key_usage_t)0x00004000u)
#define PSA_KEY_USAGE_EXPORT         ((psa_key_usage_t)0x00000001u)

#define PSA_KEY_TYPE_AES                  ((psa_key_type_t)0x2400u)
#define PSA_ECC_FAMILY_SECP_R1            0x12u
#define PSA_KEY_TYPE_ECC_KEY_PAIR(f)      ((psa_key_type_t)(0x7100u | (f)))
#define PSA_KEY_TYPE_ECC_PUBLIC_KEY(f)    ((psa_key_type_t)(0x4100u | (f)))

#define PSA_ALG_ECB_NO_PADDING ((psa_algorithm_t)0x04404400u)
#define PSA_ALG_GCM            ((psa_algorithm_t)0x05500200u)
/* The sealed peer link's AEAD (modules/ultrawidelock_anchor/src/ultrawidelock_seal.c).
 * Real PSA value, and distinct from GCM above in the low byte, so a suite that
 * asserts the spelling would catch the two being swapped. */
#define PSA_ALG_CCM            ((psa_algorithm_t)0x05500100u)
/* Real PSA CLEARS the tag-length field before writing the new one. The fake
 * used to only OR, which left the base algorithm's own tag length mixed in:
 * CCM (0x05500100, tag field 0x10 = 16) shortened to 8 came out as 24, and any
 * fake that derived a tag length from the algorithm got a number no real
 * backend would produce. Masking first makes the spelling faithful, which is
 * the only thing these suites can check about it. */
#define PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg, tag_len)                                              \
	((psa_algorithm_t)(((alg) & ~(psa_algorithm_t)0x003f0000u) |                                \
			   (((psa_algorithm_t)(tag_len) & 0x3fu) << 16)))

/** Tag length an AEAD algorithm encodes, in bytes. Real PSA's own layout. */
#define PSAFAKE_TAG_LEN(alg) ((size_t)(((alg) >> 16) & 0x3fu))
#define PSA_ALG_ECDH           ((psa_algorithm_t)0x09020000u)
#define PSA_ALG_SHA_256        ((psa_algorithm_t)0x02000009u)
#define PSA_ALG_ECDSA(hash)    ((psa_algorithm_t)(0x06000600u | ((hash) & 0xffu)))

typedef struct {
	psa_key_usage_t usage;
	psa_algorithm_t alg;
	psa_key_type_t type;
	size_t bits;
} psa_key_attributes_t;

#define PSA_KEY_ATTRIBUTES_INIT {0u, 0u, 0u, 0u}

typedef struct {
	psa_key_id_t key;
	psa_algorithm_t alg;
	size_t aad_length;
	size_t plaintext_length;
	unsigned direction;
} psa_aead_operation_t;

#define PSA_AEAD_OPERATION_INIT {0u, 0u, 0u, 0u, 0u}

static inline void psa_set_key_usage_flags(psa_key_attributes_t *a, psa_key_usage_t usage)
{
	a->usage = usage;
}
static inline void psa_set_key_algorithm(psa_key_attributes_t *a, psa_algorithm_t alg)
{
	a->alg = alg;
}
static inline void psa_set_key_type(psa_key_attributes_t *a, psa_key_type_t type)
{
	a->type = type;
}
static inline void psa_set_key_bits(psa_key_attributes_t *a, size_t bits)
{
	a->bits = bits;
}

psa_status_t psa_crypto_init(void);
psa_status_t psa_generate_random(uint8_t *output, size_t output_size);
psa_status_t psa_import_key(const psa_key_attributes_t *attributes, const uint8_t *data,
			    size_t data_length, psa_key_id_t *key);
psa_status_t psa_destroy_key(psa_key_id_t key);
psa_status_t psa_cipher_encrypt(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *input,
				size_t input_length, uint8_t *output, size_t output_size,
				size_t *output_length);
psa_status_t psa_aead_encrypt(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *nonce,
			      size_t nonce_length, const uint8_t *additional_data,
			      size_t additional_data_length, const uint8_t *plaintext,
			      size_t plaintext_length, uint8_t *ciphertext,
			      size_t ciphertext_size, size_t *ciphertext_length);
psa_status_t psa_aead_decrypt(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *nonce,
			      size_t nonce_length, const uint8_t *additional_data,
			      size_t additional_data_length, const uint8_t *ciphertext,
			      size_t ciphertext_length, uint8_t *plaintext,
			      size_t plaintext_size, size_t *plaintext_length);
psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t *operation, psa_key_id_t key,
				    psa_algorithm_t alg);
psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t *operation, psa_key_id_t key,
				    psa_algorithm_t alg);
psa_status_t psa_aead_set_lengths(psa_aead_operation_t *operation, size_t ad_length,
				  size_t plaintext_length);
psa_status_t psa_aead_set_nonce(psa_aead_operation_t *operation, const uint8_t *nonce,
				size_t nonce_length);
psa_status_t psa_aead_update_ad(psa_aead_operation_t *operation, const uint8_t *input,
				size_t input_length);
psa_status_t psa_aead_update(psa_aead_operation_t *operation, const uint8_t *input,
			     size_t input_length, uint8_t *output, size_t output_size,
			     size_t *output_length);
psa_status_t psa_aead_finish(psa_aead_operation_t *operation, uint8_t *ciphertext,
			     size_t ciphertext_size, size_t *ciphertext_length, uint8_t *tag,
			     size_t tag_size, size_t *tag_length);
psa_status_t psa_aead_verify(psa_aead_operation_t *operation, uint8_t *plaintext,
			     size_t plaintext_size, size_t *plaintext_length, const uint8_t *tag,
			     size_t tag_length);
psa_status_t psa_aead_abort(psa_aead_operation_t *operation);
psa_status_t psa_generate_key(const psa_key_attributes_t *attributes, psa_key_id_t *key);
psa_status_t psa_export_key(psa_key_id_t key, uint8_t *data, size_t data_size,
			    size_t *data_length);
psa_status_t psa_export_public_key(psa_key_id_t key, uint8_t *data, size_t data_size,
				   size_t *data_length);
psa_status_t psa_raw_key_agreement(psa_algorithm_t alg, psa_key_id_t private_key,
				   const uint8_t *peer_key, size_t peer_key_length,
				   uint8_t *output, size_t output_size, size_t *output_length);
psa_status_t psa_sign_message(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *input,
			      size_t input_length, uint8_t *signature, size_t signature_size,
			      size_t *signature_length);
psa_status_t psa_sign_hash(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *hash,
			   size_t hash_length, uint8_t *signature, size_t signature_size,
			   size_t *signature_length);
psa_status_t psa_verify_message(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *input,
				size_t input_length, const uint8_t *signature,
				size_t signature_length);
psa_status_t psa_verify_hash(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *hash,
			     size_t hash_length, const uint8_t *signature,
			     size_t signature_length);

#endif /* PSAFAKE_PSA_CRYPTO_H */
