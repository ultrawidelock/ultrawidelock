/* psafake implementations — recording doubles only (see psafake.h: the fake
 * does NO crypto). Outputs are deterministic filler so callers' length checks
 * and memcpy plumbing are observable; every status/olen is a knob. */
#include <string.h>

#include "psafake.h"
#include <mbedtls/aes.h>
#include <psa/crypto.h>

struct psafake_state psafake;

void psafake_reset(void)
{
	memset(&psafake, 0, sizeof(psafake));
	psafake.cipher_olen = -1;
	psafake.aead_enc_olen = -1;
	psafake.aead_dec_olen = -1;
	psafake.aead_update_olen = -1;
	psafake.aead_finish_olen = -1;
	psafake.aead_tag_olen = -1;
	psafake.aead_verify_olen = -1;
	psafake.export_olen = -1;
	psafake.export_pub_olen = -1;
	psafake.raw_ka_olen = -1;
	psafake.sign_olen = -1;
}

/** Fill n bytes with a recognisable ramp starting at seed. */
static void fill(uint8_t *dst, size_t n, uint8_t seed)
{
	for (size_t i = 0; i < n; i++) {
		dst[i] = (uint8_t)(seed + i);
	}
}

psa_status_t psa_crypto_init(void)
{
	psafake.init_calls++;
	return psafake.init_ret;
}

psa_status_t psa_generate_random(uint8_t *output, size_t output_size)
{
	psafake.random_calls++;
	psafake.last_random_len = output_size;
	fill(output, output_size, 0x40);
	return psafake.random_ret;
}

psa_status_t psa_import_key(const psa_key_attributes_t *attributes, const uint8_t *data,
			    size_t data_length, psa_key_id_t *key)
{
	psafake.import_calls++;
	psafake.attr_usage = attributes->usage;
	psafake.attr_alg = attributes->alg;
	psafake.attr_type = attributes->type;
	psafake.attr_bits = attributes->bits;
	psafake.key_len = data_length <= PSAFAKE_MAX_KEY ? data_length : PSAFAKE_MAX_KEY;
	memcpy(psafake.key, data, psafake.key_len);
	if (psafake.import_ret != PSA_SUCCESS) {
		return psafake.import_ret;
	}
	*key = (psa_key_id_t)(0x1000u + psafake.import_calls);
	return PSA_SUCCESS;
}

psa_status_t psa_destroy_key(psa_key_id_t key)
{
	psafake.destroy_calls++;
	psafake.last_destroyed = key;
	return PSA_SUCCESS;
}

/** Serve *olen: natural value unless the knob overrides it. */
static size_t olen_of(long knob, size_t natural)
{
	return knob >= 0 ? (size_t)knob : natural;
}

psa_status_t psa_cipher_encrypt(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *input,
				size_t input_length, uint8_t *output, size_t output_size,
				size_t *output_length)
{
	(void)key;
	psafake.cipher_calls++;
	psafake.last_alg = alg;
	psafake.last_in_len = input_length;
	if (input_length <= output_size) {
		memcpy(output, input, input_length); /* filler, not encryption */
	}
	*output_length = olen_of(psafake.cipher_olen, input_length);
	return psafake.cipher_ret;
}

psa_status_t psa_aead_encrypt(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *nonce,
			      size_t nonce_length, const uint8_t *additional_data,
			      size_t additional_data_length, const uint8_t *plaintext,
			      size_t plaintext_length, uint8_t *ciphertext,
			      size_t ciphertext_size, size_t *ciphertext_length)
{
	size_t tag;

	(void)key;
	(void)nonce;
	(void)additional_data;
	psafake.aead_enc_calls++;
	psafake.last_alg = alg;
	psafake.last_nonce_len = nonce_length;
	psafake.last_aad_len = additional_data_length;
	psafake.last_in_len = plaintext_length;
	/* Tag width from the algorithm, as a real backend does it. A fake that
	 * always appended 16 made every shortened-tag caller's frames the wrong
	 * length, and a caller that demultiplexes messages BY length then
	 * matched none of its own. */
	tag = PSAFAKE_TAG_LEN(alg);
	if (plaintext_length + tag <= ciphertext_size) {
		memcpy(ciphertext, plaintext, plaintext_length); /* filler "ct" */
		fill(ciphertext + plaintext_length, tag, 0xc0); /* filler "tag" */
	}
	*ciphertext_length = olen_of(psafake.aead_enc_olen, plaintext_length + tag);
	return psafake.aead_enc_ret;
}

psa_status_t psa_aead_decrypt(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *nonce,
			      size_t nonce_length, const uint8_t *additional_data,
			      size_t additional_data_length, const uint8_t *ciphertext,
			      size_t ciphertext_length, uint8_t *plaintext,
			      size_t plaintext_size, size_t *plaintext_length)
{
	(void)key;
	(void)nonce;
	(void)additional_data;
	size_t tag = PSAFAKE_TAG_LEN(alg);
	size_t pt = ciphertext_length >= tag ? ciphertext_length - tag : 0u;

	psafake.aead_dec_calls++;
	psafake.last_alg = alg;
	psafake.last_nonce_len = nonce_length;
	psafake.last_aad_len = additional_data_length;
	psafake.last_in_len = ciphertext_length;
	if (pt <= plaintext_size) {
		memcpy(plaintext, ciphertext, pt); /* filler "pt" */
	}
	*plaintext_length = olen_of(psafake.aead_dec_olen, pt);
	return psafake.aead_dec_ret;
}

static psa_status_t aead_setup(psa_aead_operation_t *operation, psa_key_id_t key,
			       psa_algorithm_t alg, unsigned direction)
{
	if (direction == 1u) {
		psafake.aead_enc_calls++;
	} else {
		psafake.aead_dec_calls++;
	}
	psafake.last_alg = alg;
	if (psafake.aead_setup_ret != PSA_SUCCESS) {
		return psafake.aead_setup_ret;
	}
	operation->key = key;
	operation->alg = alg;
	operation->direction = direction;
	return PSA_SUCCESS;
}

psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t *operation, psa_key_id_t key,
				    psa_algorithm_t alg)
{
	return aead_setup(operation, key, alg, 1u);
}

psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t *operation, psa_key_id_t key,
				    psa_algorithm_t alg)
{
	return aead_setup(operation, key, alg, 2u);
}

psa_status_t psa_aead_set_lengths(psa_aead_operation_t *operation, size_t ad_length,
				  size_t plaintext_length)
{
	psafake.aead_lengths_calls++;
	operation->aad_length = ad_length;
	operation->plaintext_length = plaintext_length;
	return psafake.aead_lengths_ret;
}

psa_status_t psa_aead_set_nonce(psa_aead_operation_t *operation, const uint8_t *nonce,
				size_t nonce_length)
{
	(void)operation;
	(void)nonce;
	psafake.aead_nonce_calls++;
	psafake.last_nonce_len = nonce_length;
	return psafake.aead_nonce_ret;
}

psa_status_t psa_aead_update_ad(psa_aead_operation_t *operation, const uint8_t *input,
				size_t input_length)
{
	(void)operation;
	(void)input;
	psafake.aead_ad_calls++;
	psafake.last_aad_len = input_length;
	return psafake.aead_ad_ret;
}

psa_status_t psa_aead_update(psa_aead_operation_t *operation, const uint8_t *input,
			     size_t input_length, uint8_t *output, size_t output_size,
			     size_t *output_length)
{
	(void)operation;
	psafake.aead_update_calls++;
	psafake.last_in_len = input_length;
	if (output < input + input_length && input < output + output_size) {
		psafake.aead_update_overlaps++;
	}
	if (psafake.block_hold != 0u && output_size < input_length + psafake.block_hold) {
		*output_length = 0u;
		return PSA_ERROR_BUFFER_TOO_SMALL;
	}
	if (input_length <= output_size) {
		memmove(output, input, input_length);
	}
	*output_length = olen_of(psafake.aead_update_olen, input_length);
	return psafake.aead_update_ret;
}

psa_status_t psa_aead_finish(psa_aead_operation_t *operation, uint8_t *ciphertext,
			     size_t ciphertext_size, size_t *ciphertext_length, uint8_t *tag,
			     size_t tag_size, size_t *tag_length)
{
	(void)operation;
	psafake.aead_finish_calls++;
	fill(ciphertext, ciphertext_size, 0xb0);
	fill(tag, tag_size, 0xc0);
	*ciphertext_length = olen_of(psafake.aead_finish_olen, 0u);
	*tag_length = olen_of(psafake.aead_tag_olen, tag_size);
	return psafake.aead_enc_ret;
}

psa_status_t psa_aead_verify(psa_aead_operation_t *operation, uint8_t *plaintext,
			     size_t plaintext_size, size_t *plaintext_length, const uint8_t *tag,
			     size_t tag_length)
{
	(void)operation;
	(void)tag;
	(void)tag_length;
	psafake.aead_verify_calls++;
	fill(plaintext, plaintext_size, 0xd0);
	*plaintext_length = olen_of(psafake.aead_verify_olen, 0u);
	return psafake.aead_dec_ret;
}

psa_status_t psa_aead_abort(psa_aead_operation_t *operation)
{
	psafake.aead_abort_calls++;
	memset(operation, 0, sizeof(*operation));
	return PSA_SUCCESS;
}

psa_status_t psa_generate_key(const psa_key_attributes_t *attributes, psa_key_id_t *key)
{
	psafake.generate_calls++;
	psafake.attr_usage = attributes->usage;
	psafake.attr_alg = attributes->alg;
	psafake.attr_type = attributes->type;
	psafake.attr_bits = attributes->bits;
	if (psafake.generate_key_ret != PSA_SUCCESS) {
		return psafake.generate_key_ret;
	}
	*key = 0x2000u;
	return PSA_SUCCESS;
}

psa_status_t psa_export_key(psa_key_id_t key, uint8_t *data, size_t data_size,
			    size_t *data_length)
{
	(void)key;
	psafake.export_calls++;
	fill(data, data_size, 0x50);
	*data_length = olen_of(psafake.export_olen, 32u);
	return psafake.export_key_ret;
}

psa_status_t psa_export_public_key(psa_key_id_t key, uint8_t *data, size_t data_size,
				   size_t *data_length)
{
	(void)key;
	psafake.export_pub_calls++;
	fill(data, data_size, 0x60);
	if (data_size > 0u) {
		data[0] = 0x04; /* uncompressed-point marker, cosmetic only */
	}
	*data_length = olen_of(psafake.export_pub_olen, 65u);
	return psafake.export_pub_ret;
}

psa_status_t psa_raw_key_agreement(psa_algorithm_t alg, psa_key_id_t private_key,
				   const uint8_t *peer_key, size_t peer_key_length,
				   uint8_t *output, size_t output_size, size_t *output_length)
{
	(void)private_key;
	(void)peer_key;
	psafake.raw_ka_calls++;
	psafake.last_alg = alg;
	psafake.last_in_len = peer_key_length;
	fill(output, output_size, 0x70);
	*output_length = olen_of(psafake.raw_ka_olen, 32u);
	return psafake.raw_ka_ret;
}

psa_status_t psa_sign_message(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *input,
			      size_t input_length, uint8_t *signature, size_t signature_size,
			      size_t *signature_length)
{
	(void)key;
	(void)input;
	psafake.sign_calls++;
	psafake.last_alg = alg;
	psafake.last_msg_len = input_length;
	fill(signature, signature_size, 0x80);
	*signature_length = olen_of(psafake.sign_olen, 64u);
	return psafake.sign_ret;
}

psa_status_t psa_sign_hash(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *hash,
			   size_t hash_length, uint8_t *signature, size_t signature_size,
			   size_t *signature_length)
{
	(void)key;
	(void)hash;
	psafake.sign_calls++;
	psafake.last_alg = alg;
	psafake.last_msg_len = hash_length;
	fill(signature, signature_size, 0x80);
	*signature_length = olen_of(psafake.sign_olen, 64u);
	return psafake.sign_ret;
}

psa_status_t psa_verify_message(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *input,
				size_t input_length, const uint8_t *signature,
				size_t signature_length)
{
	(void)key;
	psafake.verify_calls++;
	psafake.last_alg = alg;
	psafake.last_msg_len = input_length;
	psafake.last_sig_len = signature_length;
	if (psafake.verify_replay) {
		/* Exactly the recorded pair, or nothing. See psafake.h. */
		if (input_length != psafake.replay_msg_len || signature_length != 64u ||
		    memcmp(input, psafake.replay_msg, input_length) != 0 ||
		    memcmp(signature, psafake.replay_sig, 64) != 0) {
			psafake.verify_rejects++;
			return PSA_ERROR_GENERIC;
		}
		return PSA_SUCCESS;
	}
	return psafake.verify_ret;
}

/* ── mbedTLS AES double ────────────────────────────────────────────────────── */
void mbedtls_aes_init(mbedtls_aes_context *ctx)
{
	psafake.mtls_init_calls++;
	ctx->inited = 1;
}

void mbedtls_aes_free(mbedtls_aes_context *ctx)
{
	psafake.mtls_free_calls++;
	ctx->inited = 0;
}

int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key,
			   unsigned int keybits)
{
	(void)ctx;
	psafake.mtls_setkey_calls++;
	psafake.mtls_keybits = keybits;
	psafake.key_len = keybits / 8u <= PSAFAKE_MAX_KEY ? keybits / 8u : PSAFAKE_MAX_KEY;
	memcpy(psafake.key, key, psafake.key_len);
	return (int)psafake.mtls_setkey_ret;
}

int mbedtls_aes_crypt_ecb(mbedtls_aes_context *ctx, int mode, const unsigned char input[16],
			  unsigned char output[16])
{
	(void)ctx;
	psafake.mtls_crypt_calls++;
	psafake.mtls_mode = mode;
	memcpy(output, input, 16); /* filler, not encryption */
	return (int)psafake.mtls_crypt_ret;
}
