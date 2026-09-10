/**
 * @file test_psa_backends.c — the PSA primitive provider and its portable CCC
 * adapter on host, over recording fakes (tests/host/psafake/).
 *
 * THEATRE, STATED PLAINLY: the fakes do no crypto. These checks pin argument
 * plumbing (key bits, algorithm spellings, lengths) and every error branch by
 * failure injection — they cannot detect a wrong ciphertext, and the target's
 * real PSA behaviour is out of scope.
 *
 * Files under test:
 *   modules/ultrawidelock_uwb/src/ccc/ccc_crypto_prim.c
 *   modules/ultrawidelock_cred/src/ultrawidelock_prim_psa.c
 *   modules/ultrawidelock_anchor/src/ultrawidelock_seal.c   (test_ultrawidelock_seal.c)
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "ultrawidelock_prim.h"
#include "ccc_kdf.h"
#include "psafake.h"
#include <psa/crypto.h>

#include "test.h"

static const uint8_t K16[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
static const uint8_t K32[32] = {9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
				8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8};
static const uint8_t BLK[16] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
				0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};

void test_ccc_crypto_backends(void)
{
	uint8_t out[16];

	t_group("ccc primitive adapter: argument plumbing");
	psafake_reset();
	T_EQ("128-bit ok", crypto_aes_ecb_encrypt(K16, 128, BLK, out), 0);
	T_EQ("usage ENCRYPT", (long)psafake.attr_usage, (long)PSA_KEY_USAGE_ENCRYPT);
	T_EQ("alg ECB", (long)psafake.attr_alg, (long)PSA_ALG_ECB_NO_PADDING);
	T_EQ("type AES", (long)psafake.attr_type, (long)PSA_KEY_TYPE_AES);
	T_EQ("bits 128", (long)psafake.attr_bits, 128L);
	T_EQ("key bytes = bits/8", (long)psafake.key_len, 16L);
	T_OK("key material forwarded", memcmp(psafake.key, K16, 16) == 0);
	T_EQ("op alg ECB", (long)psafake.last_alg, (long)PSA_ALG_ECB_NO_PADDING);
	T_EQ("one 16B block in", (long)psafake.last_in_len, 16L);
	T_OK("out = fake passthrough", memcmp(out, BLK, 16) == 0);
	T_EQ("key destroyed", (long)psafake.destroy_calls, 1L);

	T_EQ("256-bit ok", crypto_aes_ecb_encrypt(K32, 256, BLK, out), 0);
	T_EQ("bits 256", (long)psafake.attr_bits, 256L);
	T_EQ("key bytes 32", (long)psafake.key_len, 32L);

	t_group("ccc primitive adapter: guards + provider failures");
	T_EQ("NULL key", crypto_aes_ecb_encrypt(NULL, 128, BLK, out), -EINVAL);
	T_EQ("NULL in", crypto_aes_ecb_encrypt(K16, 128, NULL, out), -EINVAL);
	T_EQ("NULL out", crypto_aes_ecb_encrypt(K16, 128, BLK, NULL), -EINVAL);
	T_EQ("192-bit rejected", crypto_aes_ecb_encrypt(K16, 192, BLK, out), -EINVAL);
	psafake_reset();
	psafake.import_ret = PSA_ERROR_GENERIC;
	T_EQ("import fail -> -EIO", crypto_aes_ecb_encrypt(K16, 128, BLK, out), -EIO);
	T_EQ("no destroy after failed import... but PSA_KEY_ID_NULL passed",
	     (long)psafake.destroy_calls, 0L);
	psafake_reset();
	psafake.cipher_ret = PSA_ERROR_GENERIC;
	T_EQ("cipher fail -> -EIO", crypto_aes_ecb_encrypt(K16, 128, BLK, out), -EIO);
	T_EQ("destroy still runs", (long)psafake.destroy_calls, 1L);
	psafake_reset();
	psafake.cipher_olen = 15;
	T_EQ("short olen -> -EIO", crypto_aes_ecb_encrypt(K16, 128, BLK, out), -EIO);
}

void test_ultrawidelock_prim_psa(void)
{
	uint8_t ct[64], tag[16], pt[64], out16[16];
	uint8_t large[1025] = {0}, large_out[1025];
	uint8_t priv[ULTRAWIDELOCK_P256_SCALAR], pub[ULTRAWIDELOCK_P256_POINT];
	uint8_t shared[ULTRAWIDELOCK_P256_SCALAR], sig[ULTRAWIDELOCK_P256_SIG];
	static const uint8_t NONCE[12] = {0};
	/* The sealed link's nonce: role ‖ boot_id ‖ ctr ‖ zeros, 13 bytes. */
	static const uint8_t CCM_NONCE[13] = {1};
	size_t olen = 0;
	static const uint8_t AAD[5] = {1, 2, 3, 4, 5};
	static const uint8_t MSG[20] = {7};
	static const uint8_t HASH[32] = {8};

	t_group("init + random");
	psafake_reset();
	T_EQ("init ok", ultrawidelock_prim_init(), 0);
	T_EQ("init hits psa_crypto_init", (long)psafake.init_calls, 1L);
	psafake.init_ret = PSA_ERROR_GENERIC;
	T_EQ("init fail -> -1", ultrawidelock_prim_init(), -1);
	T_EQ("random ok", ultrawidelock_random(pt, 20), 0);
	T_EQ("random len plumbed", (long)psafake.last_random_len, 20L);
	psafake.random_ret = PSA_ERROR_GENERIC;
	T_EQ("random fail -> -1", ultrawidelock_random(pt, 4), -1);

	t_group("aes256-gcm encrypt");
	psafake_reset();
	T_EQ("encrypt ok (tag16)",
	     ultrawidelock_aes256_gcm_encrypt(K32, NONCE, sizeof(NONCE), AAD, sizeof(AAD), BLK, 16, ct,
				      tag, 16),
	     0);
	T_EQ("bits 256", (long)psafake.attr_bits, 256L);
	T_EQ("usage ENCRYPT", (long)psafake.attr_usage, (long)PSA_KEY_USAGE_ENCRYPT);
	T_EQ("alg GCM tag16", (long)psafake.last_alg,
	     (long)PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 16));
	T_EQ("nonce len", (long)psafake.last_nonce_len, 12L);
	T_EQ("aad len", (long)psafake.last_aad_len, 5L);
	T_EQ("multipart setup", (long)psafake.aead_enc_calls, 1L);
	T_EQ("multipart lengths", (long)psafake.aead_lengths_calls, 1L);
	T_EQ("multipart update", (long)psafake.aead_update_calls, 1L);
	T_EQ("multipart finish", (long)psafake.aead_finish_calls, 1L);
	T_EQ("multipart abort", (long)psafake.aead_abort_calls, 1L);
	T_OK("ct split out", memcmp(ct, BLK, 16) == 0);
	T_OK("tag split out", tag[0] == 0xc0 && tag[15] == 0xcf);
	T_EQ("key destroyed", (long)psafake.destroy_calls, 1L);
	T_EQ("encrypt ok (tag8)",
	     ultrawidelock_aes256_gcm_encrypt(K32, NONCE, sizeof(NONCE), NULL, 0, BLK, 16, ct, tag, 8),
	     0);
	T_EQ("alg encodes tag8", (long)psafake.last_alg,
	     (long)PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 8));
	T_EQ("tag too long -> -1",
	     ultrawidelock_aes256_gcm_encrypt(K32, NONCE, 12, NULL, 0, BLK, 16, ct, tag, 17), -1);
	T_EQ("payload beyond old 1024-byte scratch succeeds",
	     ultrawidelock_aes256_gcm_encrypt(K32, NONCE, 12, NULL, 0, large, sizeof(large),
				       large_out, tag, 16),
	     0);
	psafake_reset();
	psafake.import_ret = PSA_ERROR_GENERIC;
	T_EQ("import fail -> -1",
	     ultrawidelock_aes256_gcm_encrypt(K32, NONCE, 12, NULL, 0, BLK, 16, ct, tag, 16), -1);
	psafake_reset();
	psafake.aead_setup_ret = PSA_ERROR_GENERIC;
	T_EQ("setup fail -> -1",
	     ultrawidelock_aes256_gcm_encrypt(K32, NONCE, 12, NULL, 0, BLK, 16, ct, tag, 16), -1);
	T_EQ("abort after setup fail", (long)psafake.aead_abort_calls, 1L);
	T_EQ("destroy after setup fail", (long)psafake.destroy_calls, 1L);
	psafake_reset();
	psafake.aead_lengths_ret = PSA_ERROR_GENERIC;
	T_EQ("set-lengths fail -> -1",
	     ultrawidelock_aes256_gcm_encrypt(K32, NONCE, 12, NULL, 0, BLK, 16, ct, tag, 16), -1);
	psafake_reset();
	psafake.aead_nonce_ret = PSA_ERROR_GENERIC;
	T_EQ("set-nonce fail -> -1",
	     ultrawidelock_aes256_gcm_encrypt(K32, NONCE, 12, NULL, 0, BLK, 16, ct, tag, 16), -1);
	psafake_reset();
	psafake.aead_ad_ret = PSA_ERROR_GENERIC;
	T_EQ("AAD fail -> -1",
	     ultrawidelock_aes256_gcm_encrypt(K32, NONCE, 12, AAD, sizeof(AAD), BLK, 16, ct, tag, 16),
	     -1);
	psafake_reset();
	psafake.aead_update_ret = PSA_ERROR_GENERIC;
	T_EQ("update fail -> -1",
	     ultrawidelock_aes256_gcm_encrypt(K32, NONCE, 12, NULL, 0, BLK, 16, ct, tag, 16), -1);
	psafake_reset();
	psafake.aead_enc_ret = PSA_ERROR_GENERIC;
	T_EQ("finish fail -> -1",
	     ultrawidelock_aes256_gcm_encrypt(K32, NONCE, 12, NULL, 0, BLK, 16, ct, tag, 16), -1);
	T_EQ("destroy after finish fail", (long)psafake.destroy_calls, 1L);
	psafake_reset();
	psafake.aead_finish_olen = 1;
	T_EQ("olen mismatch -> -1",
	     ultrawidelock_aes256_gcm_encrypt(K32, NONCE, 12, NULL, 0, BLK, 16, ct, tag, 16), -1);
	psafake_reset();
	psafake.aead_tag_olen = 15;
	T_EQ("tag olen mismatch -> -1",
	     ultrawidelock_aes256_gcm_encrypt(K32, NONCE, 12, NULL, 0, BLK, 16, ct, tag, 16), -1);

	t_group("aes256-gcm decrypt");
	psafake_reset();
	T_EQ("decrypt ok",
	     ultrawidelock_aes256_gcm_decrypt(K32, NONCE, 12, AAD, 5, ct, 16, tag, 16, pt), 0);
	T_EQ("usage DECRYPT", (long)psafake.attr_usage, (long)PSA_KEY_USAGE_DECRYPT);
	T_EQ("ciphertext length in", (long)psafake.last_in_len, 16L);
	T_EQ("multipart verify", (long)psafake.aead_verify_calls, 1L);
	T_OK("pt out", memcmp(pt, ct, 16) == 0);
	T_EQ("tag too long -> -1",
	     ultrawidelock_aes256_gcm_decrypt(K32, NONCE, 12, NULL, 0, ct, 16, tag, 17, pt), -1);
	T_EQ("ciphertext beyond old 1024-byte scratch succeeds",
	     ultrawidelock_aes256_gcm_decrypt(K32, NONCE, 12, NULL, 0, large, sizeof(large), tag, 16,
				       large_out),
	     0);
	psafake_reset();
	psafake.import_ret = PSA_ERROR_GENERIC;
	T_EQ("import fail -> -1",
	     ultrawidelock_aes256_gcm_decrypt(K32, NONCE, 12, NULL, 0, ct, 16, tag, 16, pt), -1);
	psafake_reset();
	psafake.aead_dec_ret = PSA_ERROR_GENERIC;
	memset(pt, 0xa5, sizeof(pt));
	T_EQ("tag-mismatch fail -> -1",
	     ultrawidelock_aes256_gcm_decrypt(K32, NONCE, 12, NULL, 0, ct, 16, tag, 16, pt), -1);
	T_EQ("destroy after verify failure", (long)psafake.destroy_calls, 1L);
	T_EQ("abort after verify failure", (long)psafake.aead_abort_calls, 1L);
	T_OK("tentative plaintext wiped after verify failure", memcmp(pt, (uint8_t[16]){0}, 16) == 0);
	psafake_reset();
	psafake.aead_verify_olen = 3;
	T_EQ("olen mismatch -> -1",
	     ultrawidelock_aes256_gcm_decrypt(K32, NONCE, 12, NULL, 0, ct, 16, tag, 16, pt), -1);

	t_group("aes-ecb primitive + stable AES-128 wrapper");
	psafake_reset();
	T_EQ("generic 128 ok", ultrawidelock_aes_ecb_encrypt(K16, 128, BLK, out16), 0);
	T_EQ("bits 128", (long)psafake.attr_bits, 128L);
	T_EQ("alg ECB", (long)psafake.last_alg, (long)PSA_ALG_ECB_NO_PADDING);
	T_OK("block out", memcmp(out16, BLK, 16) == 0);
	T_EQ("generic 256 ok", ultrawidelock_aes_ecb_encrypt(K32, 256, BLK, out16), 0);
	T_EQ("bits 256", (long)psafake.attr_bits, 256L);
	T_EQ("key bytes 32", (long)psafake.key_len, 32L);
	T_EQ("NULL key -> -1", ultrawidelock_aes_ecb_encrypt(NULL, 128, BLK, out16), -1);
	T_EQ("NULL input -> -1", ultrawidelock_aes_ecb_encrypt(K16, 128, NULL, out16), -1);
	T_EQ("NULL output -> -1", ultrawidelock_aes_ecb_encrypt(K16, 128, BLK, NULL), -1);
	T_EQ("192-bit -> -1", ultrawidelock_aes_ecb_encrypt(K16, 192, BLK, out16), -1);
	psafake_reset();
	T_EQ("AES-128 wrapper ok", ultrawidelock_aes128_ecb_encrypt(K16, BLK, out16), 0);
	psafake.import_ret = PSA_ERROR_GENERIC;
	T_EQ("import fail -> -1", ultrawidelock_aes_ecb_encrypt(K16, 128, BLK, out16), -1);
	psafake_reset();
	psafake.cipher_olen = 15;
	T_EQ("olen mismatch -> -1", ultrawidelock_aes_ecb_encrypt(K16, 128, BLK, out16), -1);
	psafake_reset();
	psafake.cipher_ret = PSA_ERROR_GENERIC;
	T_EQ("cipher fail -> -1", ultrawidelock_aes_ecb_encrypt(K16, 128, BLK, out16), -1);

	/*
	 * The sealed link's shape: 13-byte nonce, 8-byte tag, no AAD. psafake is
	 * a recorder, not AES, so what is provable here is the contract -- the
	 * algorithm identifier carries the shortened tag, the nonce length
	 * reaches the backend intact, no AAD is offered, the key is destroyed,
	 * and every failure the backend can report becomes -1.
	 */
	t_group("aes128-ccm (sealed link)");
	psafake_reset();
	T_EQ("encrypt ok", ultrawidelock_aes128_ccm_encrypt(K16, CCM_NONCE, sizeof(CCM_NONCE), BLK,
							    16, 8, ct, sizeof(ct), &olen),
	     0);
	T_EQ("bits 128", (long)psafake.attr_bits, 128L);
	T_EQ("usage ENCRYPT", (long)psafake.attr_usage, (long)PSA_KEY_USAGE_ENCRYPT);
	T_EQ("alg CCM tag8", (long)psafake.last_alg,
	     (long)PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 8));
	T_EQ("nonce len 13", (long)psafake.last_nonce_len, 13L);
	T_EQ("no aad", (long)psafake.last_aad_len, 0L);
	T_EQ("one shot, not multipart", (long)psafake.aead_enc_calls, 1L);
	T_EQ("no multipart setup", (long)psafake.aead_update_calls, 0L);
	T_EQ("key destroyed", (long)psafake.destroy_calls, 1L);
	T_EQ("tag too long -> -1",
	     ultrawidelock_aes128_ccm_encrypt(K16, CCM_NONCE, 13, BLK, 16, 17, ct, sizeof(ct),
					      &olen),
	     -1);
	psafake_reset();
	psafake.import_ret = PSA_ERROR_GENERIC;
	T_EQ("import fail -> -1",
	     ultrawidelock_aes128_ccm_encrypt(K16, CCM_NONCE, 13, BLK, 16, 8, ct, sizeof(ct), &olen),
	     -1);
	psafake_reset();
	psafake.aead_enc_ret = PSA_ERROR_GENERIC;
	T_EQ("encrypt fail -> -1",
	     ultrawidelock_aes128_ccm_encrypt(K16, CCM_NONCE, 13, BLK, 16, 8, ct, sizeof(ct), &olen),
	     -1);
	T_EQ("key destroyed after failure", (long)psafake.destroy_calls, 1L);

	psafake_reset();
	T_EQ("decrypt ok",
	     ultrawidelock_aes128_ccm_decrypt(K16, CCM_NONCE, sizeof(CCM_NONCE), ct, 24, 8, pt,
					      sizeof(pt), &olen),
	     0);
	T_EQ("usage DECRYPT", (long)psafake.attr_usage, (long)PSA_KEY_USAGE_DECRYPT);
	T_EQ("alg CCM tag8 on decrypt", (long)psafake.last_alg,
	     (long)PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 8));
	T_EQ("no aad on decrypt", (long)psafake.last_aad_len, 0L);
	T_EQ("one shot decrypt", (long)psafake.aead_dec_calls, 1L);
	T_EQ("tag too long -> -1",
	     ultrawidelock_aes128_ccm_decrypt(K16, CCM_NONCE, 13, ct, 24, 17, pt, sizeof(pt), &olen),
	     -1);
	psafake_reset();
	psafake.import_ret = PSA_ERROR_GENERIC;
	T_EQ("import fail -> -1",
	     ultrawidelock_aes128_ccm_decrypt(K16, CCM_NONCE, 13, ct, 24, 8, pt, sizeof(pt), &olen),
	     -1);
	psafake_reset();
	psafake.aead_dec_ret = PSA_ERROR_GENERIC;
	T_EQ("tag mismatch -> -1",
	     ultrawidelock_aes128_ccm_decrypt(K16, CCM_NONCE, 13, ct, 24, 8, pt, sizeof(pt), &olen),
	     -1);
	T_EQ("key destroyed after mismatch", (long)psafake.destroy_calls, 1L);

	t_group("p256 keygen");
	psafake_reset();
	T_EQ("keygen ok", ultrawidelock_ec_p256_keygen(priv, pub), 0);
	T_EQ("usage EXPORT", (long)psafake.attr_usage, (long)PSA_KEY_USAGE_EXPORT);
	T_EQ("alg ECDH", (long)psafake.attr_alg, (long)PSA_ALG_ECDH);
	T_EQ("type keypair secp256r1", (long)psafake.attr_type,
	     (long)PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	T_EQ("bits 256", (long)psafake.attr_bits, 256L);
	T_EQ("destroyed", (long)psafake.destroy_calls, 1L);
	psafake_reset();
	psafake.generate_key_ret = PSA_ERROR_GENERIC;
	T_EQ("generate fail -> -1", ultrawidelock_ec_p256_keygen(priv, pub), -1);
	psafake_reset();
	psafake.export_key_ret = PSA_ERROR_GENERIC;
	T_EQ("export-priv fail -> -1", ultrawidelock_ec_p256_keygen(priv, pub), -1);
	psafake_reset();
	psafake.export_olen = 31;
	T_EQ("priv olen mismatch -> -1", ultrawidelock_ec_p256_keygen(priv, pub), -1);
	psafake_reset();
	psafake.export_pub_ret = PSA_ERROR_GENERIC;
	T_EQ("export-pub fail -> -1", ultrawidelock_ec_p256_keygen(priv, pub), -1);
	psafake_reset();
	psafake.export_pub_olen = 64;
	T_EQ("pub olen mismatch -> -1", ultrawidelock_ec_p256_keygen(priv, pub), -1);

	t_group("p256 pub-from-priv");
	psafake_reset();
	T_EQ("derive ok", ultrawidelock_ec_p256_pub_from_priv(priv, pub), 0);
	T_EQ("scalar imported", (long)psafake.key_len, 32L);
	psafake.import_ret = PSA_ERROR_GENERIC;
	T_EQ("import fail -> -1", ultrawidelock_ec_p256_pub_from_priv(priv, pub), -1);
	psafake_reset();
	psafake.export_pub_olen = 10;
	T_EQ("olen mismatch -> -1", ultrawidelock_ec_p256_pub_from_priv(priv, pub), -1);

	t_group("p256 ecdh");
	psafake_reset();
	T_EQ("ecdh ok", ultrawidelock_ecdh_p256(priv, pub, shared), 0);
	T_EQ("usage DERIVE", (long)psafake.attr_usage, (long)PSA_KEY_USAGE_DERIVE);
	T_EQ("op alg ECDH", (long)psafake.last_alg, (long)PSA_ALG_ECDH);
	T_EQ("peer point 65B", (long)psafake.last_in_len, 65L);
	psafake.import_ret = PSA_ERROR_GENERIC;
	T_EQ("import fail -> -1", ultrawidelock_ecdh_p256(priv, pub, shared), -1);
	psafake_reset();
	psafake.raw_ka_ret = PSA_ERROR_GENERIC;
	T_EQ("agreement fail -> -1", ultrawidelock_ecdh_p256(priv, pub, shared), -1);
	psafake_reset();
	psafake.raw_ka_olen = 31;
	T_EQ("olen mismatch -> -1", ultrawidelock_ecdh_p256(priv, pub, shared), -1);

	t_group("p256 ecdsa sign/verify");
	psafake_reset();
	T_EQ("sign ok", ultrawidelock_ecdsa_p256_sign(priv, MSG, sizeof(MSG), sig), 0);
	T_EQ("usage SIGN", (long)psafake.attr_usage, (long)PSA_KEY_USAGE_SIGN_MESSAGE);
	T_EQ("alg ECDSA(SHA256)", (long)psafake.last_alg,
	     (long)PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	T_EQ("msg len plumbed", (long)psafake.last_msg_len, 20L);
	psafake.import_ret = PSA_ERROR_GENERIC;
	T_EQ("sign import fail -> -1", ultrawidelock_ecdsa_p256_sign(priv, MSG, 20, sig), -1);
	psafake_reset();
	psafake.sign_ret = PSA_ERROR_GENERIC;
	T_EQ("sign fail -> -1", ultrawidelock_ecdsa_p256_sign(priv, MSG, 20, sig), -1);
	psafake_reset();
	psafake.sign_olen = 63;
	T_EQ("sig olen mismatch -> -1", ultrawidelock_ecdsa_p256_sign(priv, MSG, 20, sig), -1);
	psafake_reset();
	T_EQ("sign hash ok", ultrawidelock_ecdsa_p256_sign_hash(priv, HASH, sig), 0);
	T_EQ("usage SIGN_HASH", (long)psafake.attr_usage, (long)PSA_KEY_USAGE_SIGN_HASH);
	T_EQ("hash len plumbed", (long)psafake.last_msg_len, 32L);
	psafake.import_ret = PSA_ERROR_GENERIC;
	T_EQ("sign hash import fail -> -1", ultrawidelock_ecdsa_p256_sign_hash(priv, HASH, sig), -1);
	psafake_reset();
	psafake.sign_ret = PSA_ERROR_GENERIC;
	T_EQ("sign hash fail -> -1", ultrawidelock_ecdsa_p256_sign_hash(priv, HASH, sig), -1);
	psafake_reset();
	psafake.sign_olen = 63;
	T_EQ("sign hash olen mismatch -> -1",
	     ultrawidelock_ecdsa_p256_sign_hash(priv, HASH, sig), -1);
	psafake_reset();
	T_EQ("verify ok", ultrawidelock_ecdsa_p256_verify(pub, MSG, sizeof(MSG), sig), 0);
	T_EQ("usage VERIFY", (long)psafake.attr_usage, (long)PSA_KEY_USAGE_VERIFY_MESSAGE);
	T_EQ("type public key", (long)psafake.attr_type,
	     (long)PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	T_EQ("sig len 64", (long)psafake.last_sig_len, 64L);
	psafake.import_ret = PSA_ERROR_GENERIC;
	T_EQ("verify import fail -> -1", ultrawidelock_ecdsa_p256_verify(pub, MSG, 20, sig), -1);
	psafake_reset();
	psafake.verify_ret = PSA_ERROR_GENERIC;
	T_EQ("bad signature -> -1", ultrawidelock_ecdsa_p256_verify(pub, MSG, 20, sig), -1);
	T_EQ("destroy after verify fail", (long)psafake.destroy_calls, 1L);

	/* Against a backend that holds a block back, every psa_aead_update() must
	 * be offered input_length + one block. Sizing the bulk output to the input
	 * -- the obvious way to write this -- fails here at every length past one
	 * block, which is why the direct prefix stops a block short of the end.
	 * Lengths straddle each block boundary in both directions. */
	{
		static const size_t LENS[] = { 0u,	1u,   15u,  16u,   17u,	  31u,
					       32u,	33u,  47u,  48u,   63u,	  64u,
					       255u,	256u, 257u, 1023u, 1024u, 1025u };
		uint8_t big[1025 + 16], big_ct[1025 + 16], big_pt[1025 + 16];

		memset(big, 0xa5, sizeof(big));
		for (size_t i = 0; i < sizeof(LENS) / sizeof(LENS[0]); i++) {
			psafake_reset();
			psafake.block_hold = 16u;
			T_EQ("block-holding backend: encrypt",
			     ultrawidelock_aes256_gcm_encrypt(K32, NONCE, 12, AAD, sizeof(AAD), big,
						      LENS[i], big_ct, tag, 16),
			     0);
			psafake_reset();
			psafake.block_hold = 16u;
			T_EQ("block-holding backend: decrypt",
			     ultrawidelock_aes256_gcm_decrypt(K32, NONCE, 12, AAD, sizeof(AAD),
						      big_ct, LENS[i], tag, 16, big_pt),
			     0);
		}
		/* In place, the way the step-up learn path opens a SessionData: the
		 * plaintext starts at or below the ciphertext in one buffer. Every
		 * length again, since the bulk/tail split moves with it. */
		for (size_t shift = 0; shift <= 9u; shift += 9u) {
			for (size_t i = 0; i < sizeof(LENS) / sizeof(LENS[0]); i++) {
				for (size_t j = 0; j < LENS[i]; j++) {
					big[j] = (uint8_t)(j * 7u + 1u);
				}
				memcpy(big_ct + shift, big, LENS[i]);
				psafake_reset();
				psafake.block_hold = 16u;
				T_EQ(shift ? "in place, pt below ct: decrypt" : "in place, pt == ct: decrypt",
				     ultrawidelock_aes256_gcm_decrypt(K32, NONCE, 12, AAD, sizeof(AAD),
								      big_ct + shift, LENS[i], tag, 16,
								      big_ct),
				     0);
				T_OK("in place: plaintext intact", memcmp(big_ct, big, LENS[i]) == 0);
				T_EQ("in place: PSA never handed overlapping buffers",
				     (long)psafake.aead_update_overlaps, 0L);
			}
		}
		psafake_reset();
	}
}

int main(void)
{
	test_ccc_crypto_backends();
	test_ultrawidelock_prim_psa();
	test_ultrawidelock_seal();
	test_ultrawidelock_link();
	if (t_fail > 0) {
		printf("  psa-backends: FAIL (%d of %d)\n", t_fail, t_fail + t_pass);
		return 1;
	}
	printf("  psa-backends: PASS (%d checks — recording fakes, no real crypto)\n", t_pass);
	return 0;
}
