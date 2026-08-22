/* SPDX-License-Identifier: ISC */

/*
 * See matter_fabric.h.
 */
#include "matter_fabric.h"

#include <stdio.h>
#include <string.h>

#include "ultrawidelock_hash.h"
#include "matter_tlv.h"

/* Certificate element tags (credentials/CHIPCert.h:68-78). */
#define CERT_TAG_SUBJECT    6u
#define CERT_TAG_PUBLIC_KEY 9u

/*
 * Distinguished-name attribute tags.
 *
 * The context tag number IS the attribute's OID enum -- 17 for matter-node-id,
 * 21 for matter-fabric-id (lib/asn1/gen_asn1oid.py:137,145) -- with bit 0x80
 * set when the value is a printable string instead of an integer
 * (credentials/CHIPCert.cpp:755-758). Both of these are integers, so the flag
 * is never set on them and a tag carrying it is a different attribute, not
 * these ones spelled differently.
 */
#define DN_TAG_MATTER_NODE_ID   17u
#define DN_TAG_MATTER_FABRIC_ID 21u
#define DN_TAG_MATTER_CASE_AUTH_TAG 22u

/** Pull the node and fabric ids out of a subject DN the reader is sitting on. */
static int parse_subject(struct matter_tlv_reader *r, struct matter_cert_info *out)
{
	int rc = matter_tlv_enter(r);

	if (rc != MATTER_OK) {
		return rc;
	}

	for (;;) {
		uint64_t v = 0u;

		rc = matter_tlv_next(r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}

		if (matter_tlv_tag(r) == MATTER_TLV_CTX(DN_TAG_MATTER_NODE_ID)) {
			if (matter_tlv_get_u64(r, &v) != MATTER_OK) {
				return MATTER_E_TYPE;
			}
			out->node_id = v;
			out->have_node_id = true;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(DN_TAG_MATTER_FABRIC_ID)) {
			if (matter_tlv_get_u64(r, &v) != MATTER_OK) {
				return MATTER_E_TYPE;
			}
			out->fabric_id = v;
			out->have_fabric_id = true;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(DN_TAG_MATTER_CASE_AUTH_TAG)) {
			if (matter_tlv_get_u64(r, &v) != MATTER_OK || v > UINT32_MAX) {
				return MATTER_E_TYPE;
			}
			if (out->cat_count >= MATTER_CASE_CAT_MAX) {
				return MATTER_E_NOSPACE;
			}
			out->cats[out->cat_count++] = (uint32_t)v;
		}
		/* Every other attribute, such as a common name, is skipped. */
	}

	return matter_tlv_exit(r);
}

/**
 * Parse a Matter certificate TLV structure to extract public key and subject DN fields.
 * Reads certificate from TLV container format, validates P-256 public key length (64 bytes),
 * extracts node and fabric IDs from subject.
 * Returns MATTER_E_INVAL if cert or out is NULL; returns MATTER_E_TYPE if root element is not a
 * container or key length is wrong; returns MATTER_E_INVAL if certificate format is invalid.
 */
int matter_cert_parse(const uint8_t *cert, size_t len, struct matter_cert_info *out)
{
	struct matter_tlv_reader r;
	int rc;

	if (cert == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}
	memset(out, 0, sizeof(*out));

	matter_tlv_reader_init(&r, cert, len);
	if (matter_tlv_next(&r) != MATTER_OK || !matter_tlv_is_container(&r)) {
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

		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(CERT_TAG_PUBLIC_KEY)) {
			const uint8_t *key = NULL;
			size_t key_len = 0u;

			if (matter_tlv_get_bytes(&r, &key, &key_len) != MATTER_OK) {
				return MATTER_E_TYPE;
			}
			/* A P-256 certificate whose key is not a P-256 point is
			 * malformed, not merely uninteresting. */
			if (key_len != sizeof(out->public_key)) {
				return MATTER_E_INVAL;
			}
			memcpy(out->public_key, key, key_len);
			out->have_public_key = true;
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(CERT_TAG_SUBJECT) &&
			   matter_tlv_is_container(&r)) {
			rc = parse_subject(&r, out);
			if (rc != MATTER_OK) {
				return rc;
			}
		}
	}

	return MATTER_OK;
}

/* ------------------------------------------- operational identity --- */

/**
 * Compute the compressed fabric identifier from the root CA public key and fabric ID using HKDF.
 * Derives a 8-byte compressed ID used to identify the fabric in Matter fabric tables and
 * certificates.
 * Returns MATTER_E_INVAL if root_pub or out is NULL, if root_pub is not an uncompressed point
 * (first byte != 0x04), or if HKDF derivation fails.
 */
int matter_fabric_compressed_id(const uint8_t root_pub[MATTER_FABRIC_PUBKEY_LEN],
				uint64_t fabric_id, uint8_t out[MATTER_COMPRESSED_FABRIC_LEN])
{
	/* "CompressedFabric", spelled out rather than written as a string
	 * literal so no NUL can creep into the length. */
	static const uint8_t k_info[] = {0x43, 0x6F, 0x6D, 0x70, 0x72, 0x65, 0x73, 0x73,
					 0x65, 0x64, 0x46, 0x61, 0x62, 0x72, 0x69, 0x63};
	uint8_t salt[MATTER_COMPRESSED_FABRIC_LEN];
	size_t i;

	if (root_pub == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}
	/* An uncompressed point, or this is not the key the derivation was
	 * specified over. */
	if (root_pub[0] != 0x04u) {
		return MATTER_E_INVAL;
	}

	/* Big-endian, "as it appears in certificates". */
	for (i = 0u; i < sizeof(salt); i++) {
		salt[i] = (uint8_t)(fabric_id >> (56u - 8u * i));
	}

	if (ultrawidelock_hkdf(salt, sizeof(salt), root_pub + 1, MATTER_FABRIC_PUBKEY_LEN - 1u, k_info,
		       sizeof(k_info), out, MATTER_COMPRESSED_FABRIC_LEN) != 0) {
		return MATTER_E_INVAL;
	}
	return MATTER_OK;
}

/**
 * Format the fabric's ID and this node's ID into a hyphenated 16-digit hex instance name suitable
 * for Home Assistant.
 */
int matter_fabric_instance_name(const struct matter_fabric *fabric, char *out, size_t cap)
{
	uint8_t cid[MATTER_COMPRESSED_FABRIC_LEN];
	uint64_t compressed = 0u;
	size_t i;
	int rc;
	int n;

	if (fabric == NULL || out == NULL || cap < MATTER_INSTANCE_NAME_LEN) {
		return MATTER_E_INVAL;
	}

	rc = matter_fabric_compressed_id(fabric->root_public_key, fabric->fabric_id, cid);
	if (rc != MATTER_OK) {
		return rc;
	}
	for (i = 0u; i < sizeof(cid); i++) {
		compressed = (compressed << 8) | cid[i];
	}

	/*
	 * Two %08X halves rather than one %016llX: the format has to be exactly
	 * 16 uppercase digits with no width surprises, and a 64-bit conversion
	 * specifier is the one thing a freestanding printf may not carry.
	 */
	n = snprintf(out, cap, "%08X%08X-%08X%08X", (unsigned int)(compressed >> 32),
		     (unsigned int)compressed, (unsigned int)(fabric->node_id >> 32),
		     (unsigned int)fabric->node_id);
	if (n < 0 || (size_t)n >= cap) {
		return MATTER_E_NOSPACE;
	}
	return MATTER_OK;
}
