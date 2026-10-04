/*
 * Host double for the ultrawidelock_prim backend so the key-schedule and secure-channel
 * code can be tested off-target. Provides a compact reference AES-256-GCM (the
 * real target backend is ultrawidelock_prim_psa.c / mbedTLS-PSA). The GCM here is
 * KAT-checked against the GCM spec vectors in test_ultrawidelock_crypto.c.
 *
 * The EC block at the bottom is NOT P-256 — it is a deterministic, commutative,
 * trivially forgeable stand-in (see its banner) so the reader transaction state
 * machine (test_ultrawidelock_reader.c) can run both sides of the handshake on host.
 * Real curve math runs only in ultrawidelock_prim_psa.c on target.
 */
#include "ultrawidelock_prim.h"
#include "ultrawidelock_hash.h"

#include <string.h>

/* ---- failure injection (reader error-path tests) --------------------------
 *
 * All hooks default OFF and disarm themselves after firing, so suites that do
 * not touch them (crypto, stepup) see the plain double. Two shapes:
 *   fail_<op>        > 0: fail the next N calls of <op>, decrementing each time
 *   fail_<op>_after >= 0: succeed that many calls, then fail ONE and reset to -1
 * The _after shape exists because some ops are nested (keygen draws from
 * ultrawidelock_random; the phone helpers seal with the same GCM the reader uses), so
 * the test must be able to fail the Nth call, not the first. */
int ultrawidelock_prim_host_fail_init;
int ultrawidelock_prim_host_fail_keygen;
int ultrawidelock_prim_host_fail_sign;
int ultrawidelock_prim_host_fail_pub_from_priv;
int ultrawidelock_prim_host_fail_random_after = -1;
int ultrawidelock_prim_host_fail_encrypt_after = -1;

/* Consume one call against an _after counter; returns 1 when this call must fail. */
static int fail_after_fires(int *after)
{
	if (*after < 0) {
		return 0;
	}
	if (*after == 0) {
		*after = -1;
		return 1;
	}
	(*after)--;
	return 0;
}

int ultrawidelock_prim_init(void)
{
	if (ultrawidelock_prim_host_fail_init > 0) {
		ultrawidelock_prim_host_fail_init--;
		return -1;
	}
	return 0;
}

int ultrawidelock_random(uint8_t *out, size_t len)
{
	if (fail_after_fires(&ultrawidelock_prim_host_fail_random_after)) {
		return -1;
	}
	/* Deterministic host filler; the host suite does not need CSPRNG quality. */
	for (size_t i = 0; i < len; i++) {
		out[i] = (uint8_t)(0x5a + i);
	}
	return 0;
}

/* ---- AES-256 (FIPS-197) ---- */

static const uint8_t sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
	0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
	0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
	0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
	0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
	0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
	0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
	0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
	0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
	0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
	0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
	0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
	0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
	0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
	0xb0, 0x54, 0xbb, 0x16,
};

static uint8_t xtime(uint8_t x)
{
	return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b));
}

/* AES-256: 14 rounds, 60-word (240-byte) key schedule. */
static void aes256_expand(const uint8_t key[32], uint8_t rk[240])
{
	static const uint8_t rcon[8] = { 0x01, 0x02, 0x04, 0x08,
					 0x10, 0x20, 0x40, 0x80 };
	memcpy(rk, key, 32);
	int rc = 0;
	for (int i = 32; i < 240; i += 4) {
		uint8_t t[4];

		memcpy(t, rk + i - 4, 4);
		if (i % 32 == 0) {
			uint8_t tmp = t[0];

			t[0] = (uint8_t)(sbox[t[1]] ^ rcon[rc++]);
			t[1] = sbox[t[2]];
			t[2] = sbox[t[3]];
			t[3] = sbox[tmp];
		} else if (i % 32 == 16) {
			for (int j = 0; j < 4; j++) {
				t[j] = sbox[t[j]];
			}
		}
		for (int j = 0; j < 4; j++) {
			rk[i + j] = (uint8_t)(rk[i - 32 + j] ^ t[j]);
		}
	}
}

static void aes256_encrypt(const uint8_t rk[240], const uint8_t in[16],
			   uint8_t out[16])
{
	uint8_t s[16];

	for (int i = 0; i < 16; i++) {
		s[i] = (uint8_t)(in[i] ^ rk[i]);
	}
	for (int round = 1; round <= 14; round++) {
		uint8_t t[16];

		for (int i = 0; i < 16; i++) {
			t[i] = sbox[s[i]];
		}
		/* ShiftRows (state is column-major: byte = col*4 + row). */
		uint8_t r[16];
		static const int shift[16] = { 0, 5, 10, 15, 4, 9, 14, 3,
					       8, 13, 2, 7, 12, 1, 6, 11 };
		for (int i = 0; i < 16; i++) {
			r[i] = t[shift[i]];
		}
		if (round < 14) {
			for (int c = 0; c < 4; c++) {
				uint8_t *col = r + c * 4;
				uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
				uint8_t x = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);

				col[0] ^= (uint8_t)(x ^ xtime((uint8_t)(a0 ^ a1)));
				col[1] ^= (uint8_t)(x ^ xtime((uint8_t)(a1 ^ a2)));
				col[2] ^= (uint8_t)(x ^ xtime((uint8_t)(a2 ^ a3)));
				col[3] ^= (uint8_t)(x ^ xtime((uint8_t)(a3 ^ a0)));
			}
		}
		for (int i = 0; i < 16; i++) {
			s[i] = (uint8_t)(r[i] ^ rk[round * 16 + i]);
		}
	}
	memcpy(out, s, 16);
}

/* ---- AES-128 (FIPS-197): 10 rounds, 44-word (176-byte) key schedule ---- */

static void aes128_expand(const uint8_t key[16], uint8_t rk[176])
{
	static const uint8_t rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10,
					  0x20, 0x40, 0x80, 0x1b, 0x36 };
	memcpy(rk, key, 16);
	int rc = 0;
	for (int i = 16; i < 176; i += 4) {
		uint8_t t[4];

		memcpy(t, rk + i - 4, 4);
		if (i % 16 == 0) {
			uint8_t tmp = t[0];

			t[0] = (uint8_t)(sbox[t[1]] ^ rcon[rc++]);
			t[1] = sbox[t[2]];
			t[2] = sbox[t[3]];
			t[3] = sbox[tmp];
		}
		for (int j = 0; j < 4; j++) {
			rk[i + j] = (uint8_t)(rk[i - 16 + j] ^ t[j]);
		}
	}
}

static void aes128_encrypt(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16])
{
	uint8_t s[16];

	for (int i = 0; i < 16; i++) {
		s[i] = (uint8_t)(in[i] ^ rk[i]);
	}
	for (int round = 1; round <= 10; round++) {
		uint8_t t[16];

		for (int i = 0; i < 16; i++) {
			t[i] = sbox[s[i]];
		}
		/* ShiftRows (state is column-major: byte = col*4 + row). */
		uint8_t r[16];
		static const int shift[16] = { 0, 5, 10, 15, 4, 9, 14, 3,
					       8, 13, 2, 7, 12, 1, 6, 11 };
		for (int i = 0; i < 16; i++) {
			r[i] = t[shift[i]];
		}
		if (round < 10) {
			for (int c = 0; c < 4; c++) {
				uint8_t *col = r + c * 4;
				uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
				uint8_t x = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);

				col[0] ^= (uint8_t)(x ^ xtime((uint8_t)(a0 ^ a1)));
				col[1] ^= (uint8_t)(x ^ xtime((uint8_t)(a1 ^ a2)));
				col[2] ^= (uint8_t)(x ^ xtime((uint8_t)(a2 ^ a3)));
				col[3] ^= (uint8_t)(x ^ xtime((uint8_t)(a3 ^ a0)));
			}
		}
		for (int i = 0; i < 16; i++) {
			s[i] = (uint8_t)(r[i] ^ rk[round * 16 + i]);
		}
	}
	memcpy(out, s, 16);
}

int ultrawidelock_aes_ecb_encrypt(const uint8_t *key, size_t key_bits,
				  const uint8_t in[16], uint8_t out[16])
{
	if (key == NULL || in == NULL || out == NULL) {
		return -1;
	}
	if (key_bits == 128u) {
		uint8_t rk[176];

		aes128_expand(key, rk);
		aes128_encrypt(rk, in, out);
		return 0;
	}
	if (key_bits == 256u) {
		uint8_t rk[240];

		aes256_expand(key, rk);
		aes256_encrypt(rk, in, out);
		return 0;
	}
	return -1;
}

int ultrawidelock_aes128_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
	return ultrawidelock_aes_ecb_encrypt(key, 128u, in, out);
}

/* ---- GHASH (GF(2^128)) ---- */

static void ghash_mul(uint8_t x[16], const uint8_t h[16])
{
	uint8_t z[16] = { 0 };
	uint8_t v[16];

	memcpy(v, h, 16);
	for (int i = 0; i < 128; i++) {
		if ((x[i / 8] >> (7 - (i % 8))) & 1) {
			for (int j = 0; j < 16; j++) {
				z[j] ^= v[j];
			}
		}
		int lsb = v[15] & 1;

		for (int j = 15; j > 0; j--) {
			v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
		}
		v[0] >>= 1;
		if (lsb) {
			v[0] ^= 0xe1;
		}
	}
	memcpy(x, z, 16);
}

static void ghash_update(uint8_t y[16], const uint8_t h[16], const uint8_t *data,
			 size_t len)
{
	uint8_t blk[16];

	while (len > 0) {
		size_t n = len < 16 ? len : 16;

		memset(blk, 0, 16);
		memcpy(blk, data, n);
		for (int j = 0; j < 16; j++) {
			y[j] ^= blk[j];
		}
		ghash_mul(y, h);
		data += n;
		len -= n;
	}
}

static void gctr(const uint8_t rk[240], const uint8_t icb[16], const uint8_t *in,
		 size_t len, uint8_t *out)
{
	uint8_t cb[16], ks[16];

	memcpy(cb, icb, 16);
	while (len > 0) {
		size_t n = len < 16 ? len : 16;

		aes256_encrypt(rk, cb, ks);
		for (size_t j = 0; j < n; j++) {
			out[j] = (uint8_t)(in[j] ^ ks[j]);
		}
		/* inc32 on the low 32 bits. */
		for (int j = 15; j >= 12; j--) {
			if (++cb[j]) {
				break;
			}
		}
		in += n;
		out += n;
		len -= n;
	}
}

static void gcm_core(const uint8_t key[32], const uint8_t *nonce, size_t nonce_len,
		     const uint8_t *aad, size_t aad_len, const uint8_t *in,
		     size_t len, uint8_t *out, uint8_t tag[16], int encrypting)
{
	uint8_t rk[240], h[16] = { 0 }, j0[16] = { 0 }, s[16] = { 0 }, lenblk[16] = { 0 };

	aes256_expand(key, rk);
	aes256_encrypt(rk, h, h); /* H = E(K, 0^128) */

	/* 96-bit nonce -> J0 = nonce | 0^31 | 1 (the only case credential uses). */
	memcpy(j0, nonce, nonce_len < 12 ? nonce_len : 12);
	j0[15] = 1;

	uint8_t icb[16];

	memcpy(icb, j0, 16);
	for (int j = 15; j >= 12; j--) {
		if (++icb[j]) {
			break;
		}
	}
	gctr(rk, icb, in, len, out);

	ghash_update(s, h, aad, aad_len);
	/* GHASH is always over the ciphertext: out on encrypt, in on decrypt. */
	ghash_update(s, h, encrypting ? out : in, len);
	uint64_t abits = (uint64_t)aad_len * 8, cbits = (uint64_t)len * 8;

	for (int j = 0; j < 8; j++) {
		lenblk[j] = (uint8_t)(abits >> (56 - j * 8));
		lenblk[8 + j] = (uint8_t)(cbits >> (56 - j * 8));
	}
	for (int j = 0; j < 16; j++) {
		s[j] ^= lenblk[j];
	}
	ghash_mul(s, h);
	gctr(rk, j0, s, 16, tag); /* T = GCTR(J0, S) */
}

int ultrawidelock_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t *nonce,
			     size_t nonce_len, const uint8_t *aad, size_t aad_len,
			     const uint8_t *pt, size_t pt_len, uint8_t *ct,
			     uint8_t *tag, size_t tag_len)
{
	uint8_t full[16];

	if (fail_after_fires(&ultrawidelock_prim_host_fail_encrypt_after)) {
		return -1;
	}
	if (tag_len > 16) {
		return -1;
	}
	gcm_core(key, nonce, nonce_len, aad, aad_len, pt, pt_len, ct, full, 1);
	memcpy(tag, full, tag_len);
	return 0;
}

int ultrawidelock_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t *nonce,
			     size_t nonce_len, const uint8_t *aad, size_t aad_len,
			     const uint8_t *ct, size_t ct_len, const uint8_t *tag,
			     size_t tag_len, uint8_t *pt)
{
	uint8_t full[16], want[16];
	uint8_t diff = 0;

	if (tag_len > 16) {
		return -1;
	}
	/* recompute tag over ciphertext, then constant-time compare */
	uint8_t tmp[1024];

	if (ct_len > sizeof(tmp)) {
		return -1;
	}
	gcm_core(key, nonce, nonce_len, aad, aad_len, ct, ct_len, tmp, full, 0);
	memcpy(want, full, 16);
	for (size_t i = 0; i < tag_len; i++) {
		diff |= (uint8_t)(want[i] ^ tag[i]);
	}
	if (diff != 0) {
		return -1;
	}
	memcpy(pt, tmp, ct_len);
	return 0;
}

/* ---- P-256 stand-in (NOT a curve — host tests only) -----------------------
 *
 * The reader engine treats the EC provider as opaque: it needs keygen, a
 * commutative shared secret, and a sign/verify pair that only the key holder
 * can produce *within the test process*. That contract is satisfied without
 * curve math:
 *
 *   pub(priv)         = 0x04 || priv || SHA-256("ultrawidelock-fake-y" || priv)
 *   ecdh(a, B)        = SHA-256("ultrawidelock-fake-ecdh" || sort(a, B.x))   (commutes
 *                       because B.x == b, so both sides hash the same pair)
 *   sign(priv, m)     = SHA-256("ultrawidelock-fake-r" || priv || H(m)) ||
 *                       SHA-256("ultrawidelock-fake-s" || priv || H(m))
 *   verify(P, m, sig) recomputes both halves from P.x (== priv).
 *
 * Anyone holding a public key can forge signatures — which is exactly why this
 * stays in the host double: it exercises the state machine, key schedule and
 * secure channels, never the curve. KATs for real EC belong on target. */

static void fake_point(const uint8_t priv[ULTRAWIDELOCK_P256_SCALAR],
		       uint8_t pub[ULTRAWIDELOCK_P256_POINT])
{
	struct ultrawidelock_sha256 s;

	pub[0] = 0x04;
	memcpy(pub + 1, priv, 32);
	ultrawidelock_sha256_init(&s);
	ultrawidelock_sha256_update(&s, "ultrawidelock-fake-y", 10);
	ultrawidelock_sha256_update(&s, priv, 32);
	ultrawidelock_sha256_final(&s, pub + 33);
}

int ultrawidelock_ec_p256_keygen(uint8_t priv[ULTRAWIDELOCK_P256_SCALAR],
				 uint8_t pub[ULTRAWIDELOCK_P256_POINT])
{
	if (ultrawidelock_prim_host_fail_keygen > 0) {
		ultrawidelock_prim_host_fail_keygen--;
		return -1;
	}
	if (ultrawidelock_random(priv, ULTRAWIDELOCK_P256_SCALAR) != 0) {
		return -1;
	}
	fake_point(priv, pub);
	return 0;
}

int ultrawidelock_ec_p256_pub_from_priv(const uint8_t priv[ULTRAWIDELOCK_P256_SCALAR],
				uint8_t pub[ULTRAWIDELOCK_P256_POINT])
{
	if (ultrawidelock_prim_host_fail_pub_from_priv > 0) {
		ultrawidelock_prim_host_fail_pub_from_priv--;
		return -1;
	}
	fake_point(priv, pub);
	return 0;
}

int ultrawidelock_ecdh_p256(const uint8_t priv[ULTRAWIDELOCK_P256_SCALAR],
			    const uint8_t peer_pub[ULTRAWIDELOCK_P256_POINT],
			    uint8_t shared_x[ULTRAWIDELOCK_P256_SCALAR])
{
	const uint8_t *a = priv, *b = peer_pub + 1;
	struct ultrawidelock_sha256 s;

	if (peer_pub[0] != 0x04) {
		return -1;
	}
	if (memcmp(a, b, 32) > 0) {
		const uint8_t *t = a;

		a = b;
		b = t;
	}
	ultrawidelock_sha256_init(&s);
	ultrawidelock_sha256_update(&s, "ultrawidelock-fake-ecdh", 13);
	ultrawidelock_sha256_update(&s, a, 32);
	ultrawidelock_sha256_update(&s, b, 32);
	ultrawidelock_sha256_final(&s, shared_x);
	return 0;
}

/* sig = two SHA-256 halves bound to the signer's X coordinate and h = H(msg). */
static void fake_sig_hash(const uint8_t x[32], const uint8_t h[ULTRAWIDELOCK_SHA256_LEN],
			  uint8_t sig[ULTRAWIDELOCK_P256_SIG])
{
	struct ultrawidelock_sha256 s;

	ultrawidelock_sha256_init(&s);
	ultrawidelock_sha256_update(&s, "ultrawidelock-fake-r", 10);
	ultrawidelock_sha256_update(&s, x, 32);
	ultrawidelock_sha256_update(&s, h, ULTRAWIDELOCK_SHA256_LEN);
	ultrawidelock_sha256_final(&s, sig);
	ultrawidelock_sha256_init(&s);
	ultrawidelock_sha256_update(&s, "ultrawidelock-fake-s", 10);
	ultrawidelock_sha256_update(&s, x, 32);
	ultrawidelock_sha256_update(&s, h, ULTRAWIDELOCK_SHA256_LEN);
	ultrawidelock_sha256_final(&s, sig + 32);
}

static void fake_sig(const uint8_t x[32], const uint8_t *msg, size_t msg_len,
		     uint8_t sig[ULTRAWIDELOCK_P256_SIG])
{
	uint8_t h[ULTRAWIDELOCK_SHA256_LEN];

	ultrawidelock_sha256(msg, msg_len, h);
	fake_sig_hash(x, h, sig);
}

int ultrawidelock_ecdsa_p256_sign(const uint8_t priv[ULTRAWIDELOCK_P256_SCALAR], const uint8_t *msg,
				  size_t msg_len, uint8_t sig[ULTRAWIDELOCK_P256_SIG])
{
	if (ultrawidelock_prim_host_fail_sign > 0) {
		ultrawidelock_prim_host_fail_sign--;
		return -1;
	}
	fake_sig(priv, msg, msg_len, sig); /* priv == pub.x by construction */
	return 0;
}

int ultrawidelock_ecdsa_p256_verify(const uint8_t pub[ULTRAWIDELOCK_P256_POINT], const uint8_t *msg,
				    size_t msg_len, const uint8_t sig[ULTRAWIDELOCK_P256_SIG])
{
	uint8_t want[ULTRAWIDELOCK_P256_SIG];

	if (pub[0] != 0x04) {
		return -1;
	}
	fake_sig(pub + 1, msg, msg_len, want);
	return memcmp(want, sig, ULTRAWIDELOCK_P256_SIG) == 0 ? 0 : -1;
}

int ultrawidelock_ecdsa_p256_verify_hash(const uint8_t pub[ULTRAWIDELOCK_P256_POINT],
					 const uint8_t hash[32],
					 const uint8_t sig[ULTRAWIDELOCK_P256_SIG])
{
	uint8_t want[ULTRAWIDELOCK_P256_SIG];

	if (pub[0] != 0x04) {
		return -1;
	}
	fake_sig_hash(pub + 1, hash, want);
	return memcmp(want, sig, ULTRAWIDELOCK_P256_SIG) == 0 ? 0 : -1;
}
