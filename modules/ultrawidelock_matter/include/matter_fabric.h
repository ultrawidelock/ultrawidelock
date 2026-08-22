/* SPDX-License-Identifier: ISC */

/**
 * @file matter_fabric.h — the operational identity a commissioner installs.
 *
 * Attestation ends with the commissioner holding a public key this node proved
 * it owns. What follows is the commissioner handing back an identity built on
 * that key:
 *
 *   AddTrustedRootCertificate  trust this root
 *   AddNOC                     and here is who you are underneath it
 *
 * Both certificates arrive as MATTER TLV, not X.509. The spec defines a
 * compressed form precisely so a constrained node can read one without an
 * ASN.1 decoder, and this file is that reader.
 *
 * It reads three things and ignores the rest: the subject's node id, its fabric
 * id, and the public key. Validity dates, key usage and the signature are what
 * a node checks when VERIFYING a certificate somebody else presents, which is
 * CASE's job. A commissioner has no reason to lie to itself about a NOC it just
 * minted, and this node cannot check the signature anyway without the issuer's
 * key -- which, for the NOC, is the root it was told to trust one command
 * earlier and has no independent reason to believe.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "matter_status.h"

/** kMaxCHIPCertLength (credentials/CHIPCert.h:54). */
#define MATTER_CERT_MAX 400u

/**
 * The largest OPERATIONAL certificate this node stores per fabric.
 *
 * Smaller than MATTER_CERT_MAX because a NOC is not a root: it carries one
 * subject, one issuer and one key, where a root may carry extensions this node
 * never parses. Apple's is 253 bytes; this leaves room for a longer one without
 * reserving 400 bytes per fabric on a part with 128 KB of RAM in total.
 *
 * An oversized NOC is REFUSED by AddNOC, never truncated -- a certificate
 * missing its last bytes fails signature verification with nothing to say why.
 */
#define MATTER_NOC_MAX 320u

/** The identity protection key: one AES-128 key, shared by a whole fabric. */
#define MATTER_IPK_LEN 16u

/** Uncompressed P-256 point, 0x04 || X || Y. */
#define MATTER_FABRIC_PUBKEY_LEN 65u

/** Compressed fabric identifier: 64 bits (crypto/CHIPCryptoPAL.cpp:796-833). */
#define MATTER_COMPRESSED_FABRIC_LEN 8u

/**
 * The operational instance name, "%08X%08X-%08X%08X" plus its NUL --
 * compressed fabric id, hyphen, node id, 32 uppercase hex digits in total
 * (lib/dnssd/ServiceNaming.cpp, MakeInstanceName).
 */
#define MATTER_INSTANCE_NAME_LEN 34u

/** Matter limits an operational certificate to three CASE Authenticated Tags. */
#define MATTER_CASE_CAT_MAX 3u

/** What matter_cert_parse() found. Absent fields leave their have_* flag false. */
struct matter_cert_info {
	uint64_t node_id;
	uint64_t fabric_id;
	uint32_t cats[MATTER_CASE_CAT_MAX];
	size_t cat_count;
	uint8_t public_key[MATTER_FABRIC_PUBKEY_LEN];
	bool have_node_id;
	bool have_fabric_id;
	bool have_public_key;
};

/**
 * Read the interesting fields out of a Matter operational certificate.
 *
 * @return MATTER_OK if the TLV parsed, whatever the certificate turned out to
 *         contain -- the caller decides which fields it needed. An error means
 *         the bytes were not a well-formed certificate at all.
 */
int matter_cert_parse(const uint8_t *cert, size_t len, struct matter_cert_info *out);

/**
 * One fabric's worth of operational identity.
 *
 * Held in RAM and nothing more. A fabric is supposed to survive a reboot, and
 * this one does not; there is no settings backend on this port yet, and the
 * fail-safe would roll an incomplete commissioning back regardless. What it
 * does have to survive is the gap between AddNOC and CASE, which is the same
 * boot.
 *
 * The trusted root is kept as a public key rather than as the certificate it
 * arrived in: verifying a peer's NOC chain needs the key, and nothing this node
 * does needs the other 300-odd bytes. The ICAC is kept whole because CASE has
 * to send it back out.
 */
struct matter_fabric {
	/** 0 when empty. Fabric indices start at 1. */
	uint8_t index;
	/** True once AddTrustedRootCertificate has been accepted. */
	bool have_root;
	uint64_t fabric_id;
	uint64_t node_id;
	/** The subject the commissioner wants granted administer privilege. */
	uint64_t case_admin_subject;
	uint16_t admin_vendor_id;
	uint8_t root_public_key[MATTER_FABRIC_PUBKEY_LEN];
	uint8_t ipk[MATTER_IPK_LEN];
	uint8_t noc[MATTER_NOC_MAX];
	size_t noc_len;
	/**
	 * The private half of the key this fabric's NOC certifies.
	 *
	 * Per fabric, not per node: each commissioner issues its own CSRRequest
	 * and certifies a DIFFERENT key, so a node that kept one operational key
	 * would sign the second fabric's Sigma2 with the first fabric's key --
	 * verifying against the wrong certificate, failing, and saying nothing.
	 */
	uint8_t op_priv[32];
	/**
	 * How much of the SHARED intermediate-certificate area this fabric owns.
	 *
	 * Zero for a NOC the root signed directly, which is what Apple sends and
	 * what every fabric on this node has carried so far. The certificate
	 * itself lives in one buffer for the whole node rather than one per
	 * fabric: at 400 bytes each it was the largest thing in this struct and
	 * the least used, and a device with 3 KB of RAM to spare cannot afford
	 * to reserve it per fabric against a case that has never occurred.
	 *
	 * The cost is a real limit, stated here rather than discovered: only ONE
	 * fabric may hold an intermediate certificate. A second one is REFUSED,
	 * loudly, not stored partially.
	 */
	size_t icac_len;
};

/**
 * The one intermediate certificate this node can hold, and whose it is.
 *
 * @param owner_index the fabric index holding it, or 0 when free.
 */
struct matter_icac_slot {
	uint8_t buf[MATTER_CERT_MAX];
	size_t len;
	uint8_t owner_index;
};

/**
 * Derive the compressed fabric identifier (crypto/CHIPCryptoPAL.cpp:796-833).
 *
 *   HKDF-SHA256(ikm  = root public key WITHOUT its 0x04 prefix,
 *               salt = fabric id, 8 bytes big-endian,
 *               info = "CompressedFabric",
 *               len  = 8)
 *
 * Two fabrics can share a fabric id -- it is chosen by whoever built them --
 * so this mixes in the root public key to get something that identifies a
 * fabric on the wire without being guessable from its number alone.
 *
 * The 0x04 is dropped because it says only that the point is uncompressed; it
 * is the same byte for every key and carries nothing to derive from.
 *
 * @param root_pub uncompressed, and refused if it does not start with 0x04.
 * @return MATTER_OK, or MATTER_E_INVAL.
 */
int matter_fabric_compressed_id(const uint8_t root_pub[MATTER_FABRIC_PUBKEY_LEN],
				uint64_t fabric_id, uint8_t out[MATTER_COMPRESSED_FABRIC_LEN]);

/**
 * Write the DNS-SD instance name a commissioner looks this node up by.
 *
 * "<compressed-fabric-id>-<node-id>", 16 uppercase hex digits each, which is
 * the instance part of <name>._matter._tcp.local.
 *
 * @param out at least MATTER_INSTANCE_NAME_LEN bytes; NUL-terminated.
 * @return MATTER_OK, or MATTER_E_INVAL.
 */
int matter_fabric_instance_name(const struct matter_fabric *fabric, char *out, size_t cap);
