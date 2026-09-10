/* psafake — test-side control/inspection API for the fake PSA Crypto and
 * mbedTLS-AES surfaces under tests/host/psafake/{psa,mbedtls}/.
 *
 * THE FAKE DOES NO CRYPTO. Every psa_* / mbedtls_* entry point records its
 * arguments (key bits, algorithm, usage, lengths) and serves deterministic
 * filler bytes; every return status is a knob. The suites built on it prove
 * only that the code under test plumbs the right parameters into the API and
 * takes the right branch on each failure — never that any ciphertext is
 * correct. */
#ifndef ULTRAWIDELOCK_PSAFAKE_H
#define ULTRAWIDELOCK_PSAFAKE_H

#include <stddef.h>
#include <stdint.h>

#define PSAFAKE_MAX_KEY 65u

struct psafake_state {
	/* knobs: injected return statuses (0 = PSA_SUCCESS / mbedTLS 0) */
	int32_t init_ret;
	int32_t random_ret;
	int32_t import_ret;
	int32_t cipher_ret;
	int32_t aead_enc_ret;
	int32_t aead_dec_ret;
	int32_t aead_setup_ret;
	int32_t aead_lengths_ret;
	int32_t aead_nonce_ret;
	int32_t aead_ad_ret;
	int32_t aead_update_ret;
	int32_t generate_key_ret;
	int32_t export_key_ret;
	int32_t export_pub_ret;
	int32_t raw_ka_ret;
	int32_t sign_ret;
	int32_t verify_ret;
	/* knobs: output-length overrides (-1 = natural length) */
	long cipher_olen;
	long aead_enc_olen;
	long aead_dec_olen;
	long aead_update_olen;
	long aead_finish_olen;
	long aead_tag_olen;
	long aead_verify_olen;
	long export_olen;
	long export_pub_olen;
	long raw_ka_olen;
	long sign_olen;

	/* recorded: last key attributes at import/generate */
	uint32_t attr_usage;
	uint32_t attr_alg;
	uint32_t attr_type;
	size_t attr_bits;
	/* recorded: imported key material + call tallies */
	uint8_t key[PSAFAKE_MAX_KEY];
	size_t key_len;
	unsigned init_calls, random_calls, import_calls, cipher_calls;
	unsigned aead_enc_calls, aead_dec_calls, generate_calls;
	unsigned aead_lengths_calls, aead_nonce_calls, aead_ad_calls, aead_update_calls;
	unsigned aead_finish_calls, aead_verify_calls, aead_abort_calls;
	unsigned export_calls, export_pub_calls, raw_ka_calls;
	unsigned sign_calls, verify_calls, destroy_calls;
	/* psa_aead_update() calls whose output buffer overlapped their input.
	 * PSA leaves that undefined, so a caller decrypting in place must never
	 * hand it over, however the fake's copy happens to cope. */
	unsigned aead_update_overlaps;
	/* ---- replayed ECDSA verification -------------------------------------
	 *
	 * There is no P-256 in this host build, so a signature check can only
	 * be made to mean something by replaying one a real curve produced --
	 * the arrangement spakefake.c already uses for SPAKE2+, with the vector
	 * generated offline by tests/host/gen_dfu_vector.py.
	 *
	 * When verify_replay is set, psa_verify_message() accepts ONLY the
	 * recorded (message, signature) pair and refuses anything else. That
	 * refusal is the check: it proves the caller handed PSA exactly the
	 * bytes a real ECDSA-P256 signed, so a tampered header is rejected for
	 * a real reason rather than because a knob said so. */
	int verify_replay;
	uint8_t replay_msg[64];
	size_t replay_msg_len;
	uint8_t replay_sig[64];
	unsigned verify_rejects;

	/* ---- portable output-size contract -----------------------------------
	 *
	 * The default fake copies input to output verbatim, so it accepts an
	 * output buffer sized exactly to the input -- which a real backend need
	 * not. PSA sizes psa_aead_update() output as
	 * PSA_AEAD_UPDATE_OUTPUT_SIZE(), and for a block-buffering backend that
	 * is input_length rounded up PLUS a block, because up to one block held
	 * from an earlier call can flush on this one.
	 *
	 * With block_hold set, the fake demands that headroom and returns
	 * BUFFER_TOO_SMALL without it, standing in for the conforming backend
	 * this host build does not have. Only this knob catches a caller that
	 * passes output_size == input_length. */
	size_t block_hold;

	uint32_t last_destroyed; /* key id handed to psa_destroy_key */
	uint32_t last_alg;       /* alg argument of the last operation call */
	size_t last_nonce_len, last_aad_len, last_in_len, last_random_len;
	size_t last_msg_len, last_sig_len;

	/* mbedTLS side */
	int32_t mtls_setkey_ret;
	int32_t mtls_crypt_ret;
	unsigned mtls_init_calls, mtls_free_calls, mtls_setkey_calls, mtls_crypt_calls;
	unsigned mtls_keybits;
	int mtls_mode;
};

extern struct psafake_state psafake;

/** @brief Zero all recordings, restore every knob to success/natural length. */
void psafake_reset(void);

#endif /* ULTRAWIDELOCK_PSAFAKE_H */
