/**
 * @file aes_ref.c — Host AES-128/256 ECB primitive provider.
 *
 * On target ultrawidelock_prim_psa.c implements the same contract. On the host
 * this self-contained FIPS-197 reference lets the thin CCC adapter and key
 * schedule run without a platform crypto backend. Correctness is pinned by
 * the FIPS-197 known-answer vectors checked in test_ccc_kdf.c.
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ultrawidelock_prim.h"

/** @brief FIPS-197 S-box. */
static const uint8_t SBOX[256] = {
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

/** @brief Round constants rc[j] (rc[0] unused). */
static const uint8_t RCON[11] = {
	0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

/** @brief GF(2^8) xtime (multiply by 2 modulo the AES polynomial). */
static uint8_t xtime(uint8_t x)
{
	return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1bu));
}

/** @brief Expand the cipher key into (Nr+1) round keys (16 bytes each). */
static void key_expand(const uint8_t *key, int nk, int nr, uint8_t *rk)
{
	const int total_words = 4 * (nr + 1);

	memcpy(rk, key, (size_t)nk * 4);
	for (int i = nk; i < total_words; i++) {
		uint8_t t[4];

		memcpy(t, &rk[(i - 1) * 4], 4);
		if (i % nk == 0) {
			uint8_t tmp = t[0]; /* RotWord. */

			t[0] = t[1];
			t[1] = t[2];
			t[2] = t[3];
			t[3] = tmp;
			t[0] = SBOX[t[0]]; /* SubWord. */
			t[1] = SBOX[t[1]];
			t[2] = SBOX[t[2]];
			t[3] = SBOX[t[3]];
			t[0] ^= RCON[i / nk];
		} else if (nk > 6 && i % nk == 4) {
			t[0] = SBOX[t[0]];
			t[1] = SBOX[t[1]];
			t[2] = SBOX[t[2]];
			t[3] = SBOX[t[3]];
		}
		for (int b = 0; b < 4; b++) {
			rk[i * 4 + b] = rk[(i - nk) * 4 + b] ^ t[b];
		}
	}
}

/** @brief SubBytes + ShiftRows + (optional) MixColumns + AddRoundKey on a 16-byte column-major state. */
static void sub_shift_mix_add(uint8_t s[16], const uint8_t *rk, int mix)
{
	uint8_t t[16];

	/* SubBytes then ShiftRows, written straight into column-major t. */
	t[0]  = SBOX[s[0]];  t[4]  = SBOX[s[4]];  t[8]  = SBOX[s[8]];  t[12] = SBOX[s[12]];
	t[1]  = SBOX[s[5]];  t[5]  = SBOX[s[9]];  t[9]  = SBOX[s[13]]; t[13] = SBOX[s[1]];
	t[2]  = SBOX[s[10]]; t[6]  = SBOX[s[14]]; t[10] = SBOX[s[2]];  t[14] = SBOX[s[6]];
	t[3]  = SBOX[s[15]]; t[7]  = SBOX[s[3]];  t[11] = SBOX[s[7]];  t[15] = SBOX[s[11]];

	if (mix) {
		for (int c = 0; c < 4; c++) {
			uint8_t *a = &t[c * 4];
			uint8_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3];

			a[0] = (uint8_t)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
			a[1] = (uint8_t)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
			a[2] = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
			a[3] = (uint8_t)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
		}
	}
	for (int i = 0; i < 16; i++) {
		s[i] = t[i] ^ rk[i];
	}
}

/* Nonzero fails every call with a key of this many bits, as the ESP32's
 * mbedTLS-PSA provider does when its per-block key import or DMA descriptor
 * allocation finds no heap. Keyed by size so a test can fail the 256-bit
 * STS key schedule (dURSK off mURSK) while the 128-bit Pre-POLL CCM works. */
int aes_ref_fail_bits;

int ultrawidelock_aes_ecb_encrypt(const uint8_t *key, size_t key_bits,
				  const uint8_t in[16], uint8_t out[16])
{
	uint8_t rk[240]; /* 4*(14+1)*4 = 240 bytes, the AES-256 worst case. */
	uint8_t s[16];
	int nk, nr;

	if (aes_ref_fail_bits != 0 && key_bits == (size_t)aes_ref_fail_bits) {
		return -EIO;
	}
	if (key == NULL || in == NULL || out == NULL) {
		return -EINVAL;
	}
	if (key_bits == 128u) {
		nk = 4;
		nr = 10;
	} else if (key_bits == 256u) {
		nk = 8;
		nr = 14;
	} else {
		return -EINVAL;
	}

	key_expand(key, nk, nr, rk);
	memcpy(s, in, 16);
	for (int i = 0; i < 16; i++) {
		s[i] ^= rk[i]; /* Initial AddRoundKey. */
	}
	for (int round = 1; round < nr; round++) {
		sub_shift_mix_add(s, &rk[round * 16], 1);
	}
	sub_shift_mix_add(s, &rk[nr * 16], 0); /* Final round: no MixColumns. */
	memcpy(out, s, 16);
	return 0;
}

int ultrawidelock_aes128_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
	return ultrawidelock_aes_ecb_encrypt(key, 128u, in, out);
}
