/* SPDX-License-Identifier: ISC */

/*
 * See matter_case.h.
 */
#include "matter_case.h"

#include <string.h>

#include "ultrawidelock_hash.h"
#include "matter_crypto.h"
#include "matter_fabric.h"
#include "matter_im.h"
#include "matter_tlv.h"

/* Certificate tags (credentials/CHIPCert.h:68-96). */
#define CERT_TAG_SERIAL     1u
#define CERT_TAG_SIG_ALGO   2u
#define CERT_TAG_ISSUER     3u
#define CERT_TAG_NOT_BEFORE 4u
#define CERT_TAG_NOT_AFTER  5u
#define CERT_TAG_SUBJECT    6u
#define CERT_TAG_PUB_ALGO   7u
#define CERT_TAG_CURVE      8u
#define CERT_TAG_PUBLIC_KEY 9u
#define CERT_TAG_EXTENSIONS 10u
#define CERT_TAG_SIGNATURE  11u

struct der_writer {
	uint8_t *buf;
	size_t cap;
	size_t len;
	size_t marks[8];
	uint8_t depth;
	int rc;
};

static bool der_room(struct der_writer *w, size_t n)
{
	if (w->rc != MATTER_OK || n > w->cap - w->len) {
		w->rc = w->rc == MATTER_OK ? MATTER_E_NOSPACE : w->rc;
		return false;
	}
	return true;
}

static void der_raw(struct der_writer *w, const void *p, size_t n)
{
	if (der_room(w, n)) {
		memcpy(&w->buf[w->len], p, n);
		w->len += n;
	}
}

static void der_open(struct der_writer *w, uint8_t tag)
{
	if (w->depth >= sizeof(w->marks) / sizeof(w->marks[0]) || !der_room(w, 4u)) {
		w->rc = w->rc == MATTER_OK ? MATTER_E_DEPTH : w->rc;
		return;
	}
	w->buf[w->len++] = tag;
	w->marks[w->depth++] = w->len;
	w->buf[w->len++] = 0x82u;
	w->buf[w->len++] = 0u;
	w->buf[w->len++] = 0u;
}

static void der_close(struct der_writer *w)
{
	size_t mark;
	size_t body;
	size_t n;

	if (w->rc != MATTER_OK) {
		return;
	}
	if (w->depth == 0u) {
		w->rc = MATTER_E_STATE;
		return;
	}
	mark = w->marks[--w->depth];
	body = w->len - mark - 3u;
	n = body < 128u ? 1u : (body < 256u ? 2u : 3u);
	if (n != 3u) {
		memmove(&w->buf[mark + n], &w->buf[mark + 3u], body);
		w->len -= 3u - n;
	}
	if (n == 1u) {
		w->buf[mark] = (uint8_t)body;
	} else if (n == 2u) {
		w->buf[mark] = 0x81u;
		w->buf[mark + 1u] = (uint8_t)body;
	} else {
		w->buf[mark] = 0x82u;
		w->buf[mark + 1u] = (uint8_t)(body >> 8);
		w->buf[mark + 2u] = (uint8_t)body;
	}
}

static void der_value(struct der_writer *w, uint8_t tag, const void *p, size_t n)
{
	der_open(w, tag);
	der_raw(w, p, n);
	der_close(w);
}

static void der_oid(struct der_writer *w, const uint8_t *oid, size_t n)
{
	der_value(w, 0x06u, oid, n);
}

static int read_u64(struct matter_tlv_reader *r, uint64_t *v)
{
	return matter_tlv_get_u64(r, v) == MATTER_OK ? MATTER_OK : MATTER_E_TYPE;
}

static int next_tag(struct matter_tlv_reader *r, uint8_t tag)
{
	int rc = matter_tlv_next(r);
	return rc == MATTER_OK && matter_tlv_tag(r) == MATTER_TLV_CTX(tag) ? MATTER_OK
									   : MATTER_E_TYPE;
}

static const uint8_t k_oid_ecdsa_sha256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
static const uint8_t k_oid_ec_public[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
static const uint8_t k_oid_p256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

static void der_algorithm(struct der_writer *w)
{
	der_open(w, 0x30u);
	der_oid(w, k_oid_ecdsa_sha256, sizeof(k_oid_ecdsa_sha256));
	der_close(w);
}

static int der_dn_oid(struct der_writer *w, uint8_t id)
{
	static const uint8_t matter_prefix[] = {0x2b, 0x06, 0x01, 0x04, 0x01,
						0x82, 0xa2, 0x7c, 0x01};
	uint8_t oid[10];

	/* Operational RCAC/ICAC/NOC DNs use Matter-defined identifiers only. */
	if (id < 17u || id > 23u) {
		return MATTER_E_TYPE;
	}
	memcpy(oid, matter_prefix, sizeof(matter_prefix));
	oid[sizeof(matter_prefix)] = (uint8_t)(id - 16u);
	der_oid(w, oid, sizeof(oid));
	return MATTER_OK;
}

static void hex_fixed(char *out, uint64_t v, size_t n)
{
	static const char hex[] = "0123456789ABCDEF";
	while (n-- != 0u) {
		out[n] = hex[v & 0x0fu];
		v >>= 4;
	}
}

static int convert_dn(struct matter_tlv_reader *r, struct der_writer *w)
{
	int rc;

	if (!matter_tlv_is_container(r) || matter_tlv_enter(r) != MATTER_OK) {
		return MATTER_E_TYPE;
	}
	der_open(w, 0x30u);
	while ((rc = matter_tlv_next(r)) == MATTER_OK) {
		uint8_t raw = (uint8_t)matter_tlv_tag(r);
		uint8_t id = raw & 0x7fu;
		char hex[16];
		size_t n;
		uint64_t v;

		der_open(w, 0x31u);
		der_open(w, 0x30u);
		if (der_dn_oid(w, id) != MATTER_OK) {
			return MATTER_E_TYPE;
		}
		if (read_u64(r, &v) != MATTER_OK) {
			return MATTER_E_TYPE;
		}
		n = id == 22u ? 8u : 16u;
		hex_fixed(hex, v, n);
		der_value(w, 0x0cu, hex, n);
		der_close(w);
		der_close(w);
	}
	der_close(w);
	return rc == MATTER_END && matter_tlv_exit(r) == MATTER_OK ? w->rc : MATTER_E_TYPE;
}

static void cert_time(uint32_t seconds, char out[15], size_t *n)
{
	static const char digits[] = "0123456789";
	int64_t z, era;
	unsigned doe, yoe, y, doy, mp, month, day, year;
	uint32_t sod;
	char *p = out;

	if (seconds == 0u) {
		memcpy(out, "99991231235959Z", 15u);
		*n = 15u;
		return;
	}
	z = (int64_t)(seconds / 86400u) + 10957 + 719468;
	sod = seconds % 86400u;
	era = (z >= 0 ? z : z - 146096) / 146097;
	doe = (unsigned)(z - era * 146097);
	yoe = (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u;
	y = yoe + (unsigned)era * 400u;
	doy = doe - (365u * yoe + yoe / 4u - yoe / 100u);
	mp = (5u * doy + 2u) / 153u;
	day = doy - (153u * mp + 2u) / 5u + 1u;
	month = mp < 10u ? mp + 3u : mp - 9u;
	year = y + (month <= 2u);
#define TWO(v)                                                                                     \
	do {                                                                                       \
		*p++ = digits[((v) / 10u) % 10u];                                                  \
		*p++ = digits[(v) % 10u];                                                          \
	} while (0)
	if (year < 2050u) {
		TWO(year);
		*n = 13u;
	} else {
		TWO(year / 100u);
		TWO(year);
		*n = 15u;
	}
	TWO(month);
	TWO(day);
	TWO(sod / 3600u);
	TWO((sod / 60u) % 60u);
	TWO(sod % 60u);
	*p = 'Z';
#undef TWO
}

static void der_bit_flags(struct der_writer *w, uint64_t flags)
{
	uint8_t b[3];
	size_t bytes = flags >= 256u ? 2u : 1u;
	uint8_t highest = 0u;
	uint64_t x = flags;

	while (x > 1u) {
		x >>= 1;
		highest++;
	}
	b[0] = flags == 0u ? 0u : (uint8_t)(7u - (highest & 7u));
	for (size_t i = 0u; i < bytes; i++) {
		uint8_t v = (uint8_t)(flags >> (8u * i));
		v = (uint8_t)(((v & 0x55u) << 1) | ((v >> 1) & 0x55u));
		v = (uint8_t)(((v & 0x33u) << 2) | ((v >> 2) & 0x33u));
		b[i + 1u] = (uint8_t)((v << 4) | (v >> 4));
	}
	der_value(w, 0x03u, b, bytes + 1u);
}

static int convert_extensions(struct matter_tlv_reader *r, struct der_writer *w)
{
	static const uint8_t ext_oid[][3] = {{0},
					     {0x55, 0x1d, 0x13},
					     {0x55, 0x1d, 0x0f},
					     {0x55, 0x1d, 0x25},
					     {0x55, 0x1d, 0x0e},
					     {0x55, 0x1d, 0x23}};
	static const uint8_t purpose_prefix[] = {0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03};
	int rc;

	if (!matter_tlv_is_container(r) || matter_tlv_enter(r) != MATTER_OK) {
		return MATTER_E_TYPE;
	}
	der_open(w, 0xa3u);
	der_open(w, 0x30u);
	while ((rc = matter_tlv_next(r)) == MATTER_OK) {
		uint8_t id = (uint8_t)matter_tlv_tag(r);
		const uint8_t *b;
		size_t n;
		uint64_t v;

		if (id < 1u || id > 5u) {
			return MATTER_E_TYPE;
		}
		der_open(w, 0x30u);
		der_oid(w, ext_oid[id], 3u);
		if (id <= 3u) {
			uint8_t yes = 0xffu;
			der_value(w, 0x01u, &yes, 1u);
		}
		der_open(w, 0x04u);
		if (id == 1u) {
			bool ca;
			if (!matter_tlv_is_container(r) || matter_tlv_enter(r) != MATTER_OK ||
			    matter_tlv_next(r) != MATTER_OK ||
			    matter_tlv_get_bool(r, &ca) != MATTER_OK) {
				return MATTER_E_TYPE;
			}
			der_open(w, 0x30u);
			if (ca) {
				uint8_t yes = 0xffu;
				der_value(w, 0x01u, &yes, 1u);
			}
			if (matter_tlv_next(r) == MATTER_OK) {
				uint8_t x;
				if (read_u64(r, &v) != MATTER_OK || v > 127u) {
					return MATTER_E_TYPE;
				}
				x = (uint8_t)v;
				der_value(w, 0x02u, &x, 1u);
			}
			der_close(w);
			if (matter_tlv_exit(r) != MATTER_OK) {
				return MATTER_E_TYPE;
			}
		} else if (id == 2u) {
			if (read_u64(r, &v) != MATTER_OK) {
				return MATTER_E_TYPE;
			}
			der_bit_flags(w, v);
		} else if (id == 3u) {
			if (!matter_tlv_is_container(r) || matter_tlv_enter(r) != MATTER_OK) {
				return MATTER_E_TYPE;
			}
			der_open(w, 0x30u);
			while (matter_tlv_next(r) == MATTER_OK) {
				uint8_t oid[8];
				if (read_u64(r, &v) != MATTER_OK || v < 1u || v > 6u) {
					return MATTER_E_TYPE;
				}
				memcpy(oid, purpose_prefix, sizeof(purpose_prefix));
				oid[7] = (uint8_t)v;
				der_oid(w, oid, sizeof(oid));
			}
			der_close(w);
			if (matter_tlv_exit(r) != MATTER_OK) {
				return MATTER_E_TYPE;
			}
		} else {
			if (matter_tlv_get_bytes(r, &b, &n) != MATTER_OK) {
				return MATTER_E_TYPE;
			}
			if (id == 4u) {
				der_value(w, 0x04u, b, n);
			} else {
				der_open(w, 0x30u);
				der_value(w, 0x80u, b, n);
				der_close(w);
			}
		}
		der_close(w);
		der_close(w);
	}
	der_close(w);
	der_close(w);
	return rc == MATTER_END && matter_tlv_exit(r) == MATTER_OK ? w->rc : MATTER_E_TYPE;
}

int matter_case_cert_tbs(const uint8_t *cert, size_t len, uint8_t *out, size_t cap, size_t *out_len,
			 const uint8_t **signature)
{
	struct matter_tlv_reader r;
	struct der_writer w = {.buf = out, .cap = cap};
	const uint8_t *b;
	size_t n;
	uint64_t v;
	char time[15];
	int rc;

	if (cert == NULL || out == NULL || out_len == NULL || signature == NULL) {
		return MATTER_E_INVAL;
	}
	matter_tlv_reader_init(&r, cert, len);
	if (matter_tlv_next(&r) != MATTER_OK || !matter_tlv_is_container(&r) ||
	    matter_tlv_enter(&r) != MATTER_OK) {
		return MATTER_E_TYPE;
	}
	der_open(&w, 0x30u);
	der_open(&w, 0xa0u);
	{
		uint8_t x = 2u;
		der_value(&w, 0x02u, &x, 1u);
	}
	der_close(&w);
	if (next_tag(&r, CERT_TAG_SERIAL) != MATTER_OK ||
	    matter_tlv_get_bytes(&r, &b, &n) != MATTER_OK) {
		return MATTER_E_TYPE;
	}
	der_value(&w, 0x02u, b, n);
	if (next_tag(&r, CERT_TAG_SIG_ALGO) != MATTER_OK || read_u64(&r, &v) != MATTER_OK ||
	    v != 1u) {
		return MATTER_E_TYPE;
	}
	der_algorithm(&w);
	if (next_tag(&r, CERT_TAG_ISSUER) != MATTER_OK || convert_dn(&r, &w) != MATTER_OK) {
		return MATTER_E_TYPE;
	}
	der_open(&w, 0x30u);
	if (next_tag(&r, CERT_TAG_NOT_BEFORE) != MATTER_OK || read_u64(&r, &v) != MATTER_OK ||
	    v > UINT32_MAX) {
		return MATTER_E_TYPE;
	}
	cert_time((uint32_t)v, time, &n);
	der_value(&w, n == 13u ? 0x17u : 0x18u, time, n);
	if (next_tag(&r, CERT_TAG_NOT_AFTER) != MATTER_OK || read_u64(&r, &v) != MATTER_OK ||
	    v > UINT32_MAX) {
		return MATTER_E_TYPE;
	}
	cert_time((uint32_t)v, time, &n);
	der_value(&w, n == 13u ? 0x17u : 0x18u, time, n);
	der_close(&w);
	if (next_tag(&r, CERT_TAG_SUBJECT) != MATTER_OK || convert_dn(&r, &w) != MATTER_OK) {
		return MATTER_E_TYPE;
	}
	if (next_tag(&r, CERT_TAG_PUB_ALGO) != MATTER_OK || read_u64(&r, &v) != MATTER_OK ||
	    v != 1u || next_tag(&r, CERT_TAG_CURVE) != MATTER_OK || read_u64(&r, &v) != MATTER_OK ||
	    v != 1u || next_tag(&r, CERT_TAG_PUBLIC_KEY) != MATTER_OK ||
	    matter_tlv_get_bytes(&r, &b, &n) != MATTER_OK || n != MATTER_CASE_PUBKEY_LEN) {
		return MATTER_E_TYPE;
	}
	der_open(&w, 0x30u);
	der_open(&w, 0x30u);
	der_oid(&w, k_oid_ec_public, sizeof(k_oid_ec_public));
	der_oid(&w, k_oid_p256, sizeof(k_oid_p256));
	der_close(&w);
	der_open(&w, 0x03u);
	{
		uint8_t zero = 0u;
		der_raw(&w, &zero, 1u);
		der_raw(&w, b, n);
	}
	der_close(&w);
	der_close(&w);
	if (next_tag(&r, CERT_TAG_EXTENSIONS) != MATTER_OK ||
	    convert_extensions(&r, &w) != MATTER_OK) {
		return MATTER_E_TYPE;
	}
	der_close(&w);
	if (next_tag(&r, CERT_TAG_SIGNATURE) != MATTER_OK ||
	    matter_tlv_get_bytes(&r, signature, &n) != MATTER_OK || n != MATTER_CASE_SIG_LEN) {
		return MATTER_E_TYPE;
	}
	rc = matter_tlv_next(&r);
	if (rc != MATTER_END || matter_tlv_exit(&r) != MATTER_OK || w.depth != 0u ||
	    w.rc != MATTER_OK) {
		return w.rc != MATTER_OK ? w.rc : MATTER_E_TYPE;
	}
	*out_len = w.len;
	return MATTER_OK;
}

int matter_case_cert_verify(const uint8_t *cert, size_t len,
			    const uint8_t issuer_pub[MATTER_CASE_PUBKEY_LEN], uint8_t *scratch,
			    size_t scratch_cap)
{
	const uint8_t *sig;
	size_t tbs_len;
	int rc;

	if (cert == NULL || issuer_pub == NULL || scratch == NULL || len == 0u) {
		return MATTER_E_INVAL;
	}
	rc = matter_case_cert_tbs(cert, len, scratch, scratch_cap, &tbs_len, &sig);
	if (rc != MATTER_OK) {
		return rc;
	}
	return matter_case_verify(issuer_pub, scratch, tbs_len, sig) == 0 ? MATTER_OK
									  : MATTER_E_ACCESS;
}

/* Sigma1 field tags (CASESession.cpp:74-83). */
#define TAG_S1_INITIATOR_RANDOM  1u
#define TAG_S1_INITIATOR_SESSION 2u
#define TAG_S1_DESTINATION_ID    3u
#define TAG_S1_INITIATOR_PUBKEY  4u
#define TAG_S1_RESUMPTION_ID     6u

/**
 * Derive the CASE operational IPK from an epoch key and compressed fabric ID using HKDF with the
 * "GroupKey v1.0" info string; returns MATTER_OK on success.
 */
int matter_case_operational_ipk(const uint8_t epoch_key[MATTER_CASE_IPK_LEN],
				const uint8_t compressed_fabric_id[8],
				uint8_t out[MATTER_CASE_IPK_LEN])
{
	/* "GroupKey v1.0" (crypto/CHIPCryptoPAL.cpp:848). Spelled out so no NUL
	 * can creep into the length -- it is 13 bytes, not 14. */
	static const uint8_t k_info[] = {0x47, 0x72, 0x6F, 0x75, 0x70, 0x4B, 0x65,
					 0x79, 0x20, 0x76, 0x31, 0x2E, 0x30};

	if (epoch_key == NULL || compressed_fabric_id == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}
	if (ultrawidelock_hkdf(compressed_fabric_id, 8u, epoch_key, MATTER_CASE_IPK_LEN, k_info,
			       sizeof(k_info), out, MATTER_CASE_IPK_LEN) != 0) {
		return MATTER_E_INVAL;
	}
	return MATTER_OK;
}

/**
 * Compute a CASE destination ID by hashing the initiator random, root public key, fabric ID, and
 * node ID with the IPK as the HMAC key; returns MATTER_OK on success.
 */
int matter_case_destination_id(const uint8_t ipk[MATTER_CASE_IPK_LEN],
			       const uint8_t initiator_random[MATTER_CASE_RANDOM_LEN],
			       const uint8_t root_pub[MATTER_CASE_PUBKEY_LEN], uint64_t fabric_id,
			       uint64_t node_id, uint8_t out[MATTER_CASE_DEST_ID_LEN])
{
	uint8_t msg[MATTER_CASE_RANDOM_LEN + MATTER_CASE_PUBKEY_LEN + 8u + 8u];
	size_t n = 0u;
	size_t i;

	if (ipk == NULL || initiator_random == NULL || root_pub == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}

	memcpy(&msg[n], initiator_random, MATTER_CASE_RANDOM_LEN);
	n += MATTER_CASE_RANDOM_LEN;
	memcpy(&msg[n], root_pub, MATTER_CASE_PUBKEY_LEN);
	n += MATTER_CASE_PUBKEY_LEN;
	/* LITTLE-endian, both of them. */
	for (i = 0u; i < 8u; i++) {
		msg[n + i] = (uint8_t)(fabric_id >> (8u * i));
	}
	n += 8u;
	for (i = 0u; i < 8u; i++) {
		msg[n + i] = (uint8_t)(node_id >> (8u * i));
	}
	n += 8u;

	ultrawidelock_hmac_sha256(ipk, MATTER_CASE_IPK_LEN, msg, n, out);
	return MATTER_OK;
}

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
 * Decode a Sigma1 message from TLV, extracting initiator random, destination ID, initiator public
 * key, session ID, and optional resumption ID; skips unknown fields and returns MATTER_E_INVAL if
 * mandatory fields are missing.
 */
int matter_case_sigma1_decode(const uint8_t *tlv, size_t len, struct matter_case_sigma1 *out)
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

		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_S1_INITIATOR_RANDOM)) {
			rc = take_bytes(&r, &out->initiator_random, MATTER_CASE_RANDOM_LEN);
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_S1_DESTINATION_ID)) {
			rc = take_bytes(&r, &out->destination_id, MATTER_CASE_DEST_ID_LEN);
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_S1_INITIATOR_PUBKEY)) {
			rc = take_bytes(&r, &out->initiator_pubkey, MATTER_CASE_PUBKEY_LEN);
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_S1_INITIATOR_SESSION)) {
			if (matter_tlv_get_u64(&r, &v) != MATTER_OK || v > UINT16_MAX) {
				return MATTER_E_INVAL;
			}
			out->initiator_session_id = (uint16_t)v;
			rc = MATTER_OK;
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_S1_RESUMPTION_ID)) {
			if (matter_tlv_get_bytes(&r, &out->resumption_id,
						 &out->resumption_id_len) != MATTER_OK) {
				return MATTER_E_TYPE;
			}
			out->has_resumption = true;
			rc = MATTER_OK;
		} else {
			/* Session parameters and the resumption MIC are skipped
			 * rather than refused: a newer initiator may send fields
			 * this node has never heard of, and none of them changes
			 * whether the identity below is the right one. */
			rc = MATTER_OK;
		}

		if (rc != MATTER_OK) {
			return rc;
		}
	}

	/* All three are mandatory, and each has exactly one legal length. A
	 * Sigma1 missing any of them cannot be answered. */
	if (out->initiator_random == NULL || out->destination_id == NULL ||
	    out->initiator_pubkey == NULL) {
		return MATTER_E_INVAL;
	}
	return MATTER_OK;
}

/* --------------------------------------------------------- Sigma2 --- */

/* Sigma2 field tags (CASESession.cpp:85-92). */
#define TAG_S2_RESPONDER_RANDOM  1u
#define TAG_S2_RESPONDER_SESSION 2u
#define TAG_S2_RESPONDER_PUBKEY  3u
#define TAG_S2_ENCRYPTED         4u
#define TAG_S2_SESSION_PARAMS    5u

/* SessionParameters (PairingSession.cpp:120-144, SessionParameters::Tag). */
#define TAG_SP_IDLE_INTERVAL         1u
#define TAG_SP_ACTIVE_INTERVAL       2u
#define TAG_SP_ACTIVE_THRESHOLD      3u
#define TAG_SP_INTERACTION_MODEL_REV 5u
#define TAG_SP_MAX_PATHS_PER_INVOKE  7u

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

/** Resumption identifiers are 16 bytes (CASESession.cpp, kCASEResumptionIDSize). */
#define RESUMPTION_ID_LEN 16u

/*
 * Certificates, signatures and the TLV around them, for whichever of Sigma2 and
 * Sigma3 is in hand. One buffer serves both: Sigma2 is built, sent and finished
 * with before its Sigma3 can arrive, and both run on the OpenThread thread, so
 * the two are never live at once. A second kilobyte of scratch is a real cost
 * on a node with 128 KB of RAM; this is the reason it is not spent.
 *
 * Sigma2 uses it twice in turn -- TBSData2 is signed and then no longer needed,
 * so TBEData2 is built over it.
 */
static uint8_t s_scratch[MATTER_CASE_SIGMA2_MAX];

/**
 * Encode a Sigma2 message by computing ECDH, deriving S2K from a salt, signing TBSData2, encrypting
 * TBEData2, and wrapping both in TLV with session parameters; returns MATTER_OK on success.
 */
int matter_case_sigma2_encode(const struct matter_case_sigma2_in *in, uint8_t *out, size_t cap,
			      size_t *out_len, uint8_t shared_out[MATTER_CASE_SECRET_LEN])
{
	/* "Sigma2" and "NCASE_Sigma2N" (CASESession.cpp:128,138). */
	static const uint8_t k_info[] = {0x53, 0x69, 0x67, 0x6D, 0x61, 0x32};
	static const uint8_t k_nonce[MATTER_NONCE_LEN] = {0x4E, 0x43, 0x41, 0x53, 0x45, 0x5F, 0x53,
							  0x69, 0x67, 0x6D, 0x61, 0x32, 0x4E};
	uint8_t salt[S2K_SALT_LEN];
	uint8_t s2k[MATTER_KEY_LEN];
	uint8_t sig[MATTER_CASE_SIG_LEN];
	struct matter_tlv_writer w;
	size_t n = 0u;
	size_t off = 0u;
	int rc;

	if (in == NULL || out == NULL || out_len == NULL || shared_out == NULL) {
		return MATTER_E_INVAL;
	}
	if (in->initiator_pubkey == NULL || in->transcript_hash == NULL || in->ipk == NULL ||
	    in->noc == NULL || in->op_priv == NULL || in->responder_random == NULL ||
	    in->responder_eph_priv == NULL || in->responder_eph_pub == NULL ||
	    in->resumption_id == NULL) {
		return MATTER_E_INVAL;
	}

	if (matter_case_ecdh(in->responder_eph_priv, in->initiator_pubkey, shared_out) != 0) {
		return MATTER_E_STATE;
	}

	memcpy(&salt[off], in->ipk, MATTER_CASE_IPK_LEN);
	off += MATTER_CASE_IPK_LEN;
	memcpy(&salt[off], in->responder_random, MATTER_CASE_RANDOM_LEN);
	off += MATTER_CASE_RANDOM_LEN;
	memcpy(&salt[off], in->responder_eph_pub, MATTER_CASE_PUBKEY_LEN);
	off += MATTER_CASE_PUBKEY_LEN;
	memcpy(&salt[off], in->transcript_hash, 32u);
	off += 32u;

	rc = ultrawidelock_hkdf(salt, off, shared_out, MATTER_CASE_SECRET_LEN, k_info,
				sizeof(k_info), s2k, sizeof(s2k));
	memset(salt, 0, sizeof(salt));
	if (rc != 0) {
		return MATTER_E_STATE;
	}

	/*
	 * TBSData2. Signed, never transmitted: the peer rebuilds it from what it
	 * already has, which is what makes the signature bind this exchange's
	 * ephemeral keys rather than merely the certificate chain.
	 */
	matter_tlv_writer_init(&w, s_scratch, sizeof(s_scratch));
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_NOC), in->noc, in->noc_len);
	if (in->icac != NULL && in->icac_len > 0u) {
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_ICAC), in->icac,
					   in->icac_len);
	}
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_SENDER_PUBKEY), in->responder_eph_pub,
				   MATTER_CASE_PUBKEY_LEN);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_RECV_PUBKEY), in->initiator_pubkey,
				   MATTER_CASE_PUBKEY_LEN);
	(void)matter_tlv_end_container(&w);
	rc = matter_tlv_writer_finish(&w, &n);
	if (rc != MATTER_OK) {
		memset(s2k, 0, sizeof(s2k));
		return rc;
	}

	if (matter_case_sign(in->op_priv, s_scratch, n, sig) != 0) {
		memset(s2k, 0, sizeof(s2k));
		return MATTER_E_STATE;
	}
	/*
	 * Verify it here, against the public key out of the very NOC that is
	 * about to be sent alongside it. A peer that rejects a signature says
	 * nothing about why, so this is the only place "signed wrongly" and
	 * "derived a different key" can be told apart.
	 */
	if (in->verify_pub != NULL && matter_case_verify(in->verify_pub, s_scratch, n, sig) != 0) {
		memset(s2k, 0, sizeof(s2k));
		return MATTER_E_STATE;
	}

	/* TBEData2, over the same s_scratch now that the signature exists. */
	matter_tlv_writer_init(&w, s_scratch, sizeof(s_scratch) - MATTER_TAG_LEN);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBE_NOC), in->noc, in->noc_len);
	if (in->icac != NULL && in->icac_len > 0u) {
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBE_ICAC), in->icac,
					   in->icac_len);
	}
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBE_SIGNATURE), sig, sizeof(sig));
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBE_RESUMPTION_ID), in->resumption_id,
				   RESUMPTION_ID_LEN);
	(void)matter_tlv_end_container(&w);
	rc = matter_tlv_writer_finish(&w, &n);
	if (rc != MATTER_OK) {
		memset(s2k, 0, sizeof(s2k));
		return rc;
	}

	/* Encrypted in place, tag appended. No AAD: Sigma2 has none. */
	rc = matter_aead_encrypt(s2k, k_nonce, NULL, 0u, s_scratch, n, s_scratch, s_scratch + n);
	memset(s2k, 0, sizeof(s2k));
	if (rc != MATTER_OK) {
		return rc;
	}
	n += MATTER_TAG_LEN;

	matter_tlv_writer_init(&w, out, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_S2_RESPONDER_RANDOM),
				   in->responder_random, MATTER_CASE_RANDOM_LEN);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_S2_RESPONDER_SESSION),
				 in->responder_session_id);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_S2_RESPONDER_PUBKEY),
				   in->responder_eph_pub, MATTER_CASE_PUBKEY_LEN);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_S2_ENCRYPTED), s_scratch, n);

	/*
	 * Session parameters. Optional in the spec and ALWAYS sent by CHIP
	 * (PairingSession.cpp:120-144), which is reason enough on its own -- but
	 * two of these are load-bearing for this node in particular.
	 *
	 * The idle interval matches the radio. This node is an rx-on MED
	 * (apps/dwm3001cdk-lock/overlay-thread.conf), so the spec-default 500 ms is
	 * honest; it was 3000 while the node was a sleepy end device, and the
	 * value must follow the link mode. The SRP TXT record in
	 * ports/zephyr/matter/matter_thread_port.c advertises the same pair.
	 *
	 * MaxPathsPerInvoke is 1 because matter_im_invoke_request_decode()
	 * genuinely refuses a batch. Saying nothing lets a commissioner batch
	 * two commands and be refused for a reason it was never told.
	 */
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(TAG_S2_SESSION_PARAMS),
					 MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SP_IDLE_INTERVAL), 500u);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SP_ACTIVE_INTERVAL), 300u);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SP_ACTIVE_THRESHOLD), 4000u);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SP_INTERACTION_MODEL_REV),
				 MATTER_IM_REVISION);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SP_MAX_PATHS_PER_INVOKE), 1u);
	(void)matter_tlv_end_container(&w);

	(void)matter_tlv_end_container(&w);

	return matter_tlv_writer_finish(&w, out_len);
}

/* --------------------------------------------------------- Sigma3 --- */

/* The only field a Sigma3 has (CASESession.cpp:101-104, Sigma3Tags). */
#define TAG_S3_ENCRYPTED 1u

/** Length of the S3K salt: the IPK and the transcript hash, and nothing else. */
#define S3K_SALT_LEN (MATTER_CASE_IPK_LEN + 32u)

/**
 * Open and validate a Sigma3 message by decrypting TBEData3, verifying the signature over TBSData3
 * against the initiator's NOC, and extracting the node ID, fabric ID, and public key; returns
 * MATTER_OK on success.
 */
int matter_case_sigma3_open(const struct matter_case_sigma3_in *in, const uint8_t *tlv, size_t len,
			    struct matter_case_sigma3_out *out)
{
	/* "Sigma3" and "NCASE_Sigma3N" (CASESession.cpp:129,140). */
	static const uint8_t k_info[] = {0x53, 0x69, 0x67, 0x6D, 0x61, 0x33};
	static const uint8_t k_nonce[MATTER_NONCE_LEN] = {0x4E, 0x43, 0x41, 0x53, 0x45, 0x5F, 0x53,
							  0x69, 0x67, 0x6D, 0x61, 0x33, 0x4E};
	/*
	 * TBSData3 is rebuilt here rather than received, so it needs a buffer of
	 * its own: the certificates it copies are still sitting in the decrypted
	 * TBEData3, so unlike Sigma2's two structures these two ARE live at the
	 * same moment and cannot share.
	 */
	static uint8_t tbs[MATTER_CASE_SIGMA3_MAX];
	uint8_t salt[S3K_SALT_LEN];
	uint8_t s3k[MATTER_KEY_LEN];
	struct matter_cert_info cert;
	struct matter_tlv_reader r;
	struct matter_tlv_writer w;
	const uint8_t *enc = NULL;
	const uint8_t *noc = NULL;
	const uint8_t *icac = NULL;
	const uint8_t *sig = NULL;
	size_t enc_len = 0u;
	size_t noc_len = 0u;
	size_t icac_len = 0u;
	size_t sig_len = 0u;
	size_t n = 0u;
	int rc;

	if (in == NULL || tlv == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}
	if (in->shared == NULL || in->ipk == NULL || in->transcript_hash == NULL ||
	    in->initiator_eph_pub == NULL || in->responder_eph_pub == NULL) {
		return MATTER_E_INVAL;
	}
	memset(out, 0, sizeof(*out));

	/* The outer message: one octet string, everything else is inside it. */
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
		rc = matter_tlv_next(&r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_S3_ENCRYPTED) &&
		    matter_tlv_get_bytes(&r, &enc, &enc_len) != MATTER_OK) {
			return MATTER_E_TYPE;
		}
	}
	/* Shorter than its own authentication tag means there is no ciphertext
	 * at all, and the subtraction below would wrap. */
	if (enc == NULL || enc_len <= MATTER_TAG_LEN) {
		return MATTER_E_INVAL;
	}
	if ((enc_len - MATTER_TAG_LEN) > sizeof(s_scratch)) {
		return MATTER_E_NOSPACE;
	}

	memcpy(salt, in->ipk, MATTER_CASE_IPK_LEN);
	memcpy(&salt[MATTER_CASE_IPK_LEN], in->transcript_hash, 32u);
	rc = ultrawidelock_hkdf(salt, sizeof(salt), in->shared, MATTER_CASE_SECRET_LEN, k_info,
				sizeof(k_info), s3k, sizeof(s3k));
	memset(salt, 0, sizeof(salt));
	if (rc != 0) {
		return MATTER_E_STATE;
	}

	/* The tag is the last 16 bytes; no AAD, the same as Sigma2. */
	n = enc_len - MATTER_TAG_LEN;
	rc = matter_aead_decrypt(s3k, k_nonce, NULL, 0u, enc, n, enc + n, s_scratch);
	memset(s3k, 0, sizeof(s3k));
	if (rc != MATTER_OK) {
		return rc;
	}

	/* TBEData3: the initiator's chain and its signature over TBSData3. */
	matter_tlv_reader_init(&r, s_scratch, n);
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
	 * TBSData3. Same tag numbers as TBSData2 but the roles are swapped: the
	 * SENDER is now the initiator, so its ephemeral key goes in tag 3 and
	 * this node's in tag 4. Encoding them the other way round produces a
	 * structure that is well formed, decodes cleanly, and never verifies.
	 */
	matter_tlv_writer_init(&w, tbs, sizeof(tbs));
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_NOC), noc, noc_len);
	if (icac != NULL && icac_len > 0u) {
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_ICAC), icac, icac_len);
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

	/* The key to check it with comes from the NOC that was sent alongside
	 * it, which is only worth anything because the chain is bound to the
	 * fabric -- see the caller's fabric id check. */
	if (matter_cert_parse(noc, noc_len, &cert) != MATTER_OK || !cert.have_public_key) {
		return MATTER_E_INVAL;
	}
	if (matter_case_verify(cert.public_key, tbs, n, sig) != 0) {
		return MATTER_E_TYPE;
	}

	out->node_id = cert.node_id;
	out->fabric_id = cert.fabric_id;
	memcpy(out->cats, cert.cats, sizeof(out->cats));
	out->cat_count = cert.cat_count;
	memcpy(out->public_key, cert.public_key, MATTER_CASE_PUBKEY_LEN);
	return MATTER_OK;
}
