/**
 * @file test_matter_fabric.c — reading real certificates, and installing one.
 *
 * The certificates here are not hand-built. They are CHIP's own test vectors,
 * sTestCert_Root01_Chip and sTestCert_Node01_01_Chip out of
 * credentials/tests/CHIPCert_test_vectors.cpp, produced by chip-cert and used
 * by the SDK's own certificate suite. The node and fabric ids asserted below
 * are the constants that file declares alongside them
 * (CHIPCert_test_vectors.h:143-144), so a parser that agrees with itself but
 * not with the format still fails here.
 *
 * The two certificates differ in a way that matters: the node certificate's
 * subject carries matter-node-id (17) and matter-fabric-id (21), while the
 * root's carries matter-rcac-id (20) and neither of the other two. A parser
 * that read distinguished-name attributes without checking which one it was
 * looking at would report a node id for the root, and this catches that.
 */
#include <string.h>

#include "ultrawidelock_hash.h"
#include "matter_case.h"
#include "matter_clusters.h"
#include "matter_fabric.h"
#include "matter_im.h"
#include "matter_tlv.h"

#include "test.h"
#include "test_matter_thread_stub.h"

static const uint8_t k_root01[] = {
	0x15, 0x30, 0x01, 0x08, 0x53, 0x4C, 0x45, 0x82, 0x73, 0x62, 0x35, 0x14, 0x24, 0x02, 0x01,
	0x37, 0x03, 0x27, 0x14, 0x01, 0x00, 0x00, 0x00, 0xCA, 0xCA, 0xCA, 0xCA, 0x18, 0x26, 0x04,
	0xEF, 0x17, 0x1B, 0x27, 0x26, 0x05, 0x6E, 0xB5, 0xB9, 0x4C, 0x37, 0x06, 0x27, 0x14, 0x01,
	0x00, 0x00, 0x00, 0xCA, 0xCA, 0xCA, 0xCA, 0x18, 0x24, 0x07, 0x01, 0x24, 0x08, 0x01, 0x30,
	0x09, 0x41, 0x04, 0x3B, 0x88, 0x46, 0x0E, 0xC9, 0x68, 0x7A, 0x5D, 0x0F, 0x3B, 0x4B, 0x3B,
	0x13, 0xFC, 0xD2, 0x99, 0xC2, 0xF6, 0xD5, 0x05, 0x1D, 0x00, 0x3E, 0xE4, 0x9C, 0x99, 0x24,
	0xCF, 0x98, 0xF4, 0xF7, 0x80, 0xEB, 0x20, 0xFD, 0x37, 0xC8, 0xD3, 0x58, 0x34, 0x7F, 0x5F,
	0x87, 0xD0, 0x8C, 0x32, 0x13, 0xE5, 0x40, 0xAF, 0x11, 0xBA, 0xB9, 0x13, 0x7E, 0x49, 0x35,
	0x4F, 0x0C, 0x5B, 0x63, 0x43, 0xDE, 0x63, 0x37, 0x0A, 0x35, 0x01, 0x29, 0x01, 0x18, 0x24,
	0x02, 0x60, 0x30, 0x04, 0x14, 0xCC, 0x13, 0x08, 0xAF, 0x82, 0xCF, 0xEE, 0x50, 0x5E, 0xB2,
	0x3B, 0x57, 0xBF, 0xE8, 0x6A, 0x31, 0x16, 0x65, 0x53, 0x5F, 0x30, 0x05, 0x14, 0xCC, 0x13,
	0x08, 0xAF, 0x82, 0xCF, 0xEE, 0x50, 0x5E, 0xB2, 0x3B, 0x57, 0xBF, 0xE8, 0x6A, 0x31, 0x16,
	0x65, 0x53, 0x5F, 0x18, 0x30, 0x0B, 0x40, 0xF7, 0xF0, 0x09, 0x26, 0x90, 0x49, 0x4E, 0x46,
	0xC8, 0xB1, 0xC5, 0xCB, 0xD1, 0xA5, 0x08, 0x5E, 0x1E, 0x65, 0xD4, 0x36, 0x0F, 0x98, 0xE9,
	0x6C, 0x4E, 0x8E, 0x49, 0x5D, 0xC5, 0xE2, 0x16, 0xD0, 0xBF, 0xA2, 0x3D, 0x8F, 0x57, 0x47,
	0x0D, 0x89, 0xFD, 0xDA, 0xF0, 0x3F, 0x04, 0x64, 0xB0, 0xAE, 0x8E, 0x1F, 0x95, 0x6D, 0x6F,
	0x67, 0xA3, 0x11, 0x24, 0x38, 0x58, 0x24, 0x68, 0x97, 0x80, 0xA9, 0x18,
};

static const uint8_t k_node01[] = {
	0x15, 0x30, 0x01, 0x08, 0x18, 0xE9, 0x69, 0xBA, 0x0E, 0x08, 0x9E, 0x23, 0x24, 0x02, 0x01,
	0x37, 0x03, 0x27, 0x13, 0x03, 0x00, 0x00, 0x00, 0xCA, 0xCA, 0xCA, 0xCA, 0x18, 0x26, 0x04,
	0xEF, 0x17, 0x1B, 0x27, 0x26, 0x05, 0x6E, 0xB5, 0xB9, 0x4C, 0x37, 0x06, 0x27, 0x11, 0x01,
	0x00, 0x01, 0x00, 0xDE, 0xDE, 0xDE, 0xDE, 0x27, 0x15, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xB0, 0xFA, 0x18, 0x24, 0x07, 0x01, 0x24, 0x08, 0x01, 0x30, 0x09, 0x41, 0x04, 0xBC, 0xF6,
	0x58, 0x0D, 0x2D, 0x71, 0xE1, 0x44, 0x16, 0x65, 0x1F, 0x7C, 0x31, 0x1B, 0x5E, 0xFC, 0xF9,
	0xAE, 0xC0, 0xA8, 0xC1, 0x0A, 0xF8, 0x09, 0x27, 0x84, 0x4C, 0x24, 0x0F, 0x51, 0xA8, 0xEB,
	0x23, 0xFA, 0x07, 0x44, 0x13, 0x88, 0x87, 0xAC, 0x1E, 0x73, 0xCB, 0x72, 0xA0, 0x54, 0xB6,
	0xA0, 0xDB, 0x06, 0x22, 0xAA, 0x80, 0x70, 0x71, 0x01, 0x63, 0x13, 0xB1, 0x59, 0x6C, 0x85,
	0x52, 0xCF, 0x37, 0x0A, 0x35, 0x01, 0x28, 0x01, 0x18, 0x24, 0x02, 0x01, 0x36, 0x03, 0x04,
	0x02, 0x04, 0x01, 0x18, 0x30, 0x04, 0x14, 0x69, 0x67, 0xC9, 0x12, 0xF8, 0xA3, 0xE6, 0x89,
	0x55, 0x6F, 0x89, 0x9B, 0x65, 0xD7, 0x6F, 0x53, 0xFA, 0x65, 0xC7, 0xB6, 0x30, 0x05, 0x14,
	0x44, 0x0C, 0xC6, 0x92, 0x31, 0xC4, 0xCB, 0x5B, 0x37, 0x94, 0x24, 0x26, 0xF8, 0x1B, 0xBE,
	0x24, 0xB7, 0xEF, 0x34, 0x5C, 0x18, 0x30, 0x0B, 0x40, 0xCE, 0x6E, 0xF3, 0x93, 0xCB, 0xBC,
	0x94, 0xF8, 0x0E, 0xE2, 0x90, 0xCB, 0x3C, 0x3D, 0x37, 0x33, 0x35, 0xBA, 0xB9, 0x59, 0x07,
	0x73, 0x4D, 0x99, 0xD3, 0x84, 0xA6, 0x2A, 0x37, 0x3B, 0x84, 0x84, 0xE1, 0xD4, 0x1A, 0x04,
	0xC3, 0x14, 0x0F, 0xAA, 0x19, 0xE8, 0xA2, 0xB9, 0x9B, 0x0C, 0x61, 0xE3, 0x3C, 0x27, 0xEA,
	0x91, 0x39, 0x73, 0xE4, 0x5B, 0x5B, 0xC6, 0xE3, 0x9C, 0x27, 0x0D, 0xAC, 0x53, 0x18,
};

static const uint8_t k_node01_pubkey[] = {
	0x04, 0xBC, 0xF6, 0x58, 0x0D, 0x2D, 0x71, 0xE1, 0x44, 0x16, 0x65, 0x1F, 0x7C,
	0x31, 0x1B, 0x5E, 0xFC, 0xF9, 0xAE, 0xC0, 0xA8, 0xC1, 0x0A, 0xF8, 0x09, 0x27,
	0x84, 0x4C, 0x24, 0x0F, 0x51, 0xA8, 0xEB, 0x23, 0xFA, 0x07, 0x44, 0x13, 0x88,
	0x87, 0xAC, 0x1E, 0x73, 0xCB, 0x72, 0xA0, 0x54, 0xB6, 0xA0, 0xDB, 0x06, 0x22,
	0xAA, 0x80, 0x70, 0x71, 0x01, 0x63, 0x13, 0xB1, 0x59, 0x6C, 0x85, 0x52, 0xCF,
};

static const uint8_t k_spec_root_pub[] = {
	0x04, 0x4A, 0x9F, 0x42, 0xB1, 0xCA, 0x48, 0x40, 0xD3, 0x72, 0x92, 0xBB, 0xC7,
	0xF6, 0xA7, 0xE1, 0x1E, 0x22, 0x20, 0x0C, 0x97, 0x6F, 0xC9, 0x00, 0xDB, 0xC9,
	0x8A, 0x7A, 0x38, 0x3A, 0x64, 0x1C, 0xB8, 0x25, 0x4A, 0x2E, 0x56, 0xD4, 0xE2,
	0x95, 0xA8, 0x47, 0x94, 0x3B, 0x4E, 0x38, 0x97, 0xC4, 0xA7, 0x73, 0xE9, 0x30,
	0x27, 0x7B, 0x4D, 0x9F, 0xBE, 0xDE, 0x8A, 0x05, 0x26, 0x86, 0xBF, 0xAC, 0xFA,
};

#define SPEC_FABRIC_ID  UINT64_C(0x2906C908D115D362)
#define SPEC_COMPRESSED UINT64_C(0x87e1b004e235a130)

void test_matter_fabric(void)
{
	struct matter_cert_info info;
	uint8_t junk[8];

	t_group("a node certificate");

	T_EQ("node01 parses", matter_cert_parse(k_node01, sizeof(k_node01), &info), MATTER_OK);
	T_OK("subject carries a node id", info.have_node_id);
	T_OK("node id is the vector's", info.node_id == UINT64_C(0xDEDEDEDE00010001));
	T_OK("subject carries a fabric id", info.have_fabric_id);
	T_OK("fabric id is the vector's", info.fabric_id == UINT64_C(0xFAB000000000001D));
	T_OK("public key found", info.have_public_key);
	T_OK("public key is uncompressed", info.public_key[0] == 0x04u);
	T_OK("public key is the certificate's",
	     memcmp(info.public_key, k_node01_pubkey, sizeof(k_node01_pubkey)) == 0);
	{
		static const uint8_t chip_tbs_sha256[32] = {
			0xad, 0xe1, 0xa1, 0x06, 0x1a, 0xd6, 0xfe, 0x55, 0xac, 0x5d, 0x8a,
			0xdb, 0x56, 0x22, 0x7a, 0x8c, 0x26, 0x65, 0x33, 0x3c, 0x40, 0xdc,
			0x59, 0x9e, 0x86, 0x11, 0x7c, 0x1f, 0x9e, 0xc2, 0xe6, 0x99,
		};
		uint8_t tbs[512];
		uint8_t digest[32];
		const uint8_t *signature;
		size_t tbs_len = 0u;
		struct ultrawidelock_sha256 hash;

		T_EQ("certificate converts to canonical X.509 TBS",
		     matter_case_cert_tbs(k_node01, sizeof(k_node01), tbs, sizeof(tbs), &tbs_len,
					  &signature),
		     MATTER_OK);
		T_EQ("canonical TBS has CHIP's length", (long)tbs_len, 394L);
		ultrawidelock_sha256_init(&hash);
		ultrawidelock_sha256_update(&hash, tbs, tbs_len);
		ultrawidelock_sha256_final(&hash, digest);
		T_OK("canonical TBS is byte-identical to CHIP",
		     memcmp(digest, chip_tbs_sha256, sizeof(digest)) == 0);
		T_OK("signature is borrowed from the certificate",
		     signature >= k_node01 &&
			     signature + MATTER_CASE_SIG_LEN <= k_node01 + sizeof(k_node01));
	}

	t_group("CASE authenticated tags");
	{
		uint8_t cert[160];
		struct matter_tlv_writer w;
		size_t cert_len = 0u;

		matter_tlv_writer_init(&w, cert, sizeof(cert));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(6u), MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(17u), UINT64_C(0x1234));
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(21u), UINT64_C(0x5678));
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(22u), UINT64_C(0x27730001));
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(22u), UINT64_C(0xABCD0002));
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(9u), k_node01_pubkey,
					   sizeof(k_node01_pubkey));
		(void)matter_tlv_end_container(&w);
		T_EQ("certificate builds", matter_tlv_writer_finish(&w, &cert_len), MATTER_OK);
		T_EQ("certificate parses", matter_cert_parse(cert, cert_len, &info), MATTER_OK);
		T_EQ("both CATs retained", (long)info.cat_count, 2L);
		T_OK("first CAT is exact", info.cats[0] == UINT32_C(0x27730001));
		T_OK("second CAT is exact", info.cats[1] == UINT32_C(0xABCD0002));
	}

	t_group("a root certificate");

	T_EQ("root01 parses", matter_cert_parse(k_root01, sizeof(k_root01), &info), MATTER_OK);
	T_OK("public key found", info.have_public_key);
	/*
	 * The root's subject is matter-rcac-id, tag 20. Reporting a node id
	 * here would mean the parser is matching on "some DN attribute" rather
	 * than on which one.
	 */
	T_OK("no node id claimed", !info.have_node_id);
	T_OK("no fabric id claimed", !info.have_fabric_id);
	T_OK("node id left zero", info.node_id == 0u);

	t_group("what is not a certificate");

	T_EQ("NULL certificate refused", matter_cert_parse(NULL, 10u, &info), MATTER_E_INVAL);
	T_EQ("NULL output refused", matter_cert_parse(k_root01, sizeof(k_root01), NULL),
	     MATTER_E_INVAL);
	T_EQ("empty refused", matter_cert_parse(k_root01, 0u, &info), MATTER_E_TYPE);
	/* An integer where a structure belongs: 0x04 is an anonymous uint8. */
	junk[0] = 0x04u;
	junk[1] = 0x2Au;
	T_EQ("a bare integer refused", matter_cert_parse(junk, 2u, &info), MATTER_E_TYPE);

	t_group("every truncation of a certificate");
	{
		int accepted = 0;
		int complete = 0;

		for (size_t n = 1u; n < sizeof(k_node01); n++) {
			if (matter_cert_parse(k_node01, n, &info) == MATTER_OK) {
				accepted++;
				if (info.have_node_id && info.have_fabric_id &&
				    info.have_public_key) {
					complete++;
				}
			}
		}
		/* A truncated certificate is a truncated certificate. Accepting
		 * one that happens to hold all three fields would mean a peer
		 * could cut the signature off and still be believed. */
		T_EQ("none accepted", accepted, 0);
		T_EQ("none looked complete", complete, 0);
	}

	t_group("the compressed fabric id");
	{
		/*
		 * The Matter spec's own Operational Discovery vector, lifted
		 * from CHIP's TestChipCryptoPAL.cpp:2155-2174 rather than
		 * retyped. This is the assertion that would catch a derivation
		 * that is wrong but self-consistent -- the wrong salt endianness
		 * or the 0x04 prefix left on -- and neither would show up in a
		 * round trip.
		 */
		uint8_t cid[MATTER_COMPRESSED_FABRIC_LEN];
		uint64_t v = 0u;
		size_t i;

		T_EQ("derives", matter_fabric_compressed_id(k_spec_root_pub, SPEC_FABRIC_ID, cid),
		     MATTER_OK);
		for (i = 0u; i < sizeof(cid); i++) {
			v = (v << 8) | cid[i];
		}
		T_OK("matches the spec vector", v == SPEC_COMPRESSED);

		/* A compressed point is not what the derivation is defined over,
		 * and silently hashing 64 of its bytes would give a plausible
		 * wrong answer. */
		{
			uint8_t bad[MATTER_FABRIC_PUBKEY_LEN];

			memcpy(bad, k_spec_root_pub, sizeof(bad));
			bad[0] = 0x02u;
			T_EQ("a compressed point is refused",
			     matter_fabric_compressed_id(bad, SPEC_FABRIC_ID, cid), MATTER_E_INVAL);
		}
		T_EQ("NULL key refused", matter_fabric_compressed_id(NULL, SPEC_FABRIC_ID, cid),
		     MATTER_E_INVAL);

		/* A different fabric id over the same root must not collide. */
		T_EQ("derives again",
		     matter_fabric_compressed_id(k_spec_root_pub, SPEC_FABRIC_ID + 1u, cid),
		     MATTER_OK);
		v ^= 0u;
		{
			uint64_t w = 0u;

			for (i = 0u; i < sizeof(cid); i++) {
				w = (w << 8) | cid[i];
			}
			T_OK("and differs", w != SPEC_COMPRESSED);
		}
	}

	t_group("the instance name a commissioner looks up");
	{
		struct matter_fabric fab;
		char name[MATTER_INSTANCE_NAME_LEN];

		memset(&fab, 0, sizeof(fab));
		memcpy(fab.root_public_key, k_spec_root_pub, sizeof(fab.root_public_key));
		fab.fabric_id = SPEC_FABRIC_ID;
		fab.node_id = UINT64_C(0xDEDEDEDE00010001);

		T_EQ("builds", matter_fabric_instance_name(&fab, name, sizeof(name)), MATTER_OK);
		/* Uppercase hex, 16 digits each side, one hyphen -- the format
		 * MakeInstanceName() produces and a resolver matches on. */
		T_EQ("is 33 characters", (long)strlen(name), 33);
		T_OK("names the compressed fabric then the node",
		     strcmp(name, "87E1B004E235A130-DEDEDEDE00010001") == 0);

		T_EQ("a short buffer is refused",
		     matter_fabric_instance_name(&fab, name, sizeof(name) - 1u), MATTER_E_INVAL);
	}
}

/* ------------------------------------------------------------ AddNOC --- */

/** Wrap a command's arguments the way an InvokeRequest carries them. */
static size_t fields_bytes(uint8_t *buf, size_t cap, uint8_t tag, const uint8_t *v, size_t len)
{
	struct matter_tlv_writer w;
	size_t n = 0u;

	matter_tlv_writer_init(&w, buf, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(1u), MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(tag), v, len);
	(void)matter_tlv_end_container(&w);
	T_EQ("fields encoded", matter_tlv_writer_finish(&w, &n), MATTER_OK);
	return n;
}

/** AddNOC's five arguments, with the ICAC omitted the way Apple omits it. */
static size_t fields_addnoc(uint8_t *buf, size_t cap, const uint8_t *noc, size_t noc_len,
			    const uint8_t *ipk, size_t ipk_len)
{
	struct matter_tlv_writer w;
	size_t n = 0u;

	matter_tlv_writer_init(&w, buf, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(1u), MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(0u), noc, noc_len);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(2u), ipk, ipk_len);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(3u), UINT64_C(0x1122334455667788));
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(4u), 0x1349u);
	(void)matter_tlv_end_container(&w);
	T_EQ("fields encoded", matter_tlv_writer_finish(&w, &n), MATTER_OK);
	return n;
}

static void invoke_init(struct matter_im_invoke *inv, uint32_t command, const uint8_t *fields,
			size_t len)
{
	memset(inv, 0, sizeof(*inv));
	inv->endpoint = MATTER_ENDPOINT_ROOT;
	inv->cluster = MATTER_CLUSTER_OPERATIONAL_CREDENTIALS;
	inv->command = command;
	inv->fields = fields;
	inv->fields_len = len;
	inv->has_fields = true;
}

static int s_store_calls;
static int s_store_fail;
static enum matter_fabric_store_operation s_store_operation;
static uint8_t s_store_slot;

static int fabric_store_cb(void *ctx, const struct matter_device_info *info,
			   enum matter_fabric_store_operation operation, uint8_t slot,
			   const uint8_t *value, size_t value_len)
{
	(void)ctx;
	(void)info;
	(void)value;
	(void)value_len;
	s_store_calls++;
	s_store_operation = operation;
	s_store_slot = slot;
	return s_store_fail ? MATTER_E_STATE : MATTER_OK;
}

static const struct matter_commissioning_hooks k_test_hooks = {
	.fabric_store = fabric_store_cb,
};

void test_matter_addnoc(void)
{
	struct matter_device_info dev;
	struct matter_device_info saved_dev;
	struct matter_im_server srv;
	struct matter_im_invoke inv;
	uint8_t fields[512];
	uint8_t ipk[MATTER_IPK_LEN];
	uint32_t response = 0u;
	size_t len;

	for (size_t i = 0; i < sizeof(ipk); i++) {
		ipk[i] = (uint8_t)(0x30u + i);
	}

	memset(&dev, 0, sizeof(dev));
	test_matter_thread_stub_reset();
	matter_clusters_init(&srv, &dev);

	t_group("a root outside a fail-safe");

	len = fields_bytes(fields, sizeof(fields), 0u, k_root01, sizeof(k_root01));
	invoke_init(&inv, MATTER_CMD_OC_ADD_TRUSTED_ROOT_CERTIFICATE, fields, len);
	response = 0u;
	T_EQ("refused", srv.command(srv.ctx, &inv, &response), MATTER_IM_STATUS_FAILSAFE_REQUIRED);
	T_OK("no root installed", !dev.fabrics[0].have_root);

	t_group("a root inside one");

	dev.attempt.active = true;
	response = 0u;
	T_EQ("accepted", srv.command(srv.ctx, &inv, &response), MATTER_IM_STATUS_SUCCESS);
	/* AddTrustedRootCertificate has no response command; the reply is a bare
	 * SUCCESS status. */
	T_OK("no response command", response == MATTER_IM_NO_RESPONSE);
	T_OK("root installed", dev.fabrics[0].have_root);
	T_OK("root key is the certificate's", dev.fabrics[0].root_public_key[0] == 0x04u);

	t_group("a root that is not a certificate");
	{
		uint8_t bad[16];
		uint8_t before[MATTER_FABRIC_PUBKEY_LEN];

		memcpy(before, dev.fabrics[0].root_public_key, sizeof(before));
		memset(bad, 0xAA, sizeof(bad));
		len = fields_bytes(fields, sizeof(fields), 0u, bad, sizeof(bad));
		invoke_init(&inv, MATTER_CMD_OC_ADD_TRUSTED_ROOT_CERTIFICATE, fields, len);
		T_EQ("refused", srv.command(srv.ctx, &inv, &response),
		     MATTER_IM_STATUS_INVALID_COMMAND);
		T_OK("the installed root is untouched",
		     memcmp(before, dev.fabrics[0].root_public_key, sizeof(before)) == 0);
		T_OK("and still installed", dev.fabrics[0].have_root);
	}

	t_group("a NOC with no CSR behind it");

	len = fields_addnoc(fields, sizeof(fields), k_node01, sizeof(k_node01), ipk, sizeof(ipk));
	invoke_init(&inv, MATTER_CMD_OC_ADD_NOC, fields, len);
	T_EQ("the command itself succeeds", srv.command(srv.ctx, &inv, &response),
	     MATTER_IM_STATUS_SUCCESS);
	T_OK("answered by NOCResponse", response == MATTER_CMD_OC_NOC_RESPONSE);
	T_EQ("verdict is MissingCsr", dev.last_noc_status, MATTER_NOC_STATUS_MISSING_CSR);
	T_EQ("no fabric created", dev.fabrics[0].index, 0);

	t_group("a NOC certifying somebody else's key");

	dev.have_op_key = true;
	memset(dev.op_pub, 0x04, sizeof(dev.op_pub));
	T_EQ("the command itself succeeds", srv.command(srv.ctx, &inv, &response),
	     MATTER_IM_STATUS_SUCCESS);
	T_EQ("verdict is InvalidPublicKey", dev.last_noc_status,
	     MATTER_NOC_STATUS_INVALID_PUBLIC_KEY);
	T_EQ("no fabric created", dev.fabrics[0].index, 0);

	t_group("a NOC with a short IPK");

	memcpy(dev.op_pub, k_node01_pubkey, sizeof(k_node01_pubkey));
	len = fields_addnoc(fields, sizeof(fields), k_node01, sizeof(k_node01), ipk,
			    sizeof(ipk) - 1u);
	invoke_init(&inv, MATTER_CMD_OC_ADD_NOC, fields, len);
	T_EQ("the command itself succeeds", srv.command(srv.ctx, &inv, &response),
	     MATTER_IM_STATUS_SUCCESS);
	T_EQ("verdict is InvalidNOC", dev.last_noc_status, MATTER_NOC_STATUS_INVALID_NOC);
	T_EQ("no fabric created", dev.fabrics[0].index, 0);

	t_group("the NOC this node asked for");

	len = fields_addnoc(fields, sizeof(fields), k_node01, sizeof(k_node01), ipk, sizeof(ipk));
	invoke_init(&inv, MATTER_CMD_OC_ADD_NOC, fields, len);
	T_EQ("the command itself succeeds", srv.command(srv.ctx, &inv, &response),
	     MATTER_IM_STATUS_SUCCESS);
	T_EQ("verdict is Ok", dev.last_noc_status, MATTER_NOC_STATUS_OK);
	T_EQ("fabric index is 1", dev.fabrics[0].index, 1);
	T_OK("node id taken from the NOC", dev.fabrics[0].node_id == UINT64_C(0xDEDEDEDE00010001));
	T_OK("fabric id taken from the NOC",
	     dev.fabrics[0].fabric_id == UINT64_C(0xFAB000000000001D));
	T_EQ("the NOC is kept whole", dev.fabrics[0].noc_len, sizeof(k_node01));
	T_OK("and kept verbatim", memcmp(dev.fabrics[0].noc, k_node01, sizeof(k_node01)) == 0);
	T_EQ("no ICAC, as Apple sends none", dev.fabrics[0].icac_len, 0);
	T_OK("the IPK is kept", memcmp(dev.fabrics[0].ipk, ipk, sizeof(ipk)) == 0);
	T_OK("the admin subject is kept",
	     dev.fabrics[0].case_admin_subject == UINT64_C(0x1122334455667788));
	T_EQ("the admin vendor is kept", dev.fabrics[0].admin_vendor_id, 0x1349);

	t_group("a second NOC without its own root");

	/*
	 * A second administrator gets a slot, but a slot is not a fabric: it
	 * needs its OWN AddTrustedRootCertificate first. Refusing with
	 * InvalidNOC rather than TableFull is the difference between "this node
	 * is full" and "you skipped a step", and only one of those tells the
	 * commissioner to try again.
	 */
	T_EQ("the command itself succeeds", srv.command(srv.ctx, &inv, &response),
	     MATTER_IM_STATUS_SUCCESS);
	T_EQ("verdict is InvalidNOC", dev.last_noc_status, MATTER_NOC_STATUS_INVALID_NOC);
	T_EQ("the first fabric survives", dev.fabrics[0].index, 1);
	T_EQ("and no second one was created", dev.fabrics[1].index, 0);

	t_group("a second NOC with one");

	/*
	 * What Apple actually does: the phone and the home hub each commission
	 * this node onto their own fabric. While only one slot existed the
	 * second AddNOC answered TableFull and the pairing never completed.
	 */
	dev.fabrics[1].have_root = true;
	dev.attempt.owned_slots |= MATTER_FABRIC_SLOT_BIT(1u);
	memcpy(dev.fabrics[1].root_public_key, dev.fabrics[0].root_public_key,
	       sizeof(dev.fabrics[1].root_public_key));
	T_EQ("the command itself succeeds", srv.command(srv.ctx, &inv, &response),
	     MATTER_IM_STATUS_SUCCESS);
	T_EQ("verdict is Ok", dev.last_noc_status, MATTER_NOC_STATUS_OK);
	T_EQ("it took the next index", dev.fabrics[1].index, 2);
	T_EQ("and the reply named that index", dev.last_noc_index, 2);
	T_OK("the first fabric is untouched", dev.fabrics[0].index == 1);

	t_group("a commissioner that gives up half way");
	{
		struct matter_device_info before = dev;

		/* The bug this exists for: without a rollback the fabric
		 * survives the dropped link, and the NEXT attempt is refused
		 * TableFull for a reason unrelated to what went wrong. */
		T_EQ("a fabric is installed", dev.fabrics[0].index, 1);
		matter_clusters_failsafe_expire(&dev);
		T_EQ("the fabric is gone", dev.fabrics[0].index, 0);
		T_OK("and so is the operational key", !dev.have_op_key);
		{
			uint8_t zero[32] = {0};

			T_OK("wiped, not merely forgotten",
			     memcmp(dev.op_priv, zero, sizeof(zero)) == 0);
		}
		T_OK("the fail-safe is disarmed", !dev.attempt.active);

		/* Retry: the same AddNOC that was refused now succeeds. */
		dev.attempt.active = true;
		dev.have_op_key = true;
		memcpy(dev.op_pub, k_node01_pubkey, sizeof(k_node01_pubkey));
		memcpy(dev.fabrics[0].root_public_key, before.fabrics[0].root_public_key,
		       sizeof(dev.fabrics[0].root_public_key));
		dev.fabrics[0].have_root = true;
		dev.attempt.owned_slots = MATTER_FABRIC_SLOT_BIT(0u);
		len = fields_addnoc(fields, sizeof(fields), k_node01, sizeof(k_node01), ipk,
				    sizeof(ipk));
		invoke_init(&inv, MATTER_CMD_OC_ADD_NOC, fields, len);
		T_EQ("the retry runs", srv.command(srv.ctx, &inv, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("and is accepted", dev.last_noc_status, MATTER_NOC_STATUS_OK);
		T_EQ("on fabric index 1 again", dev.fabrics[0].index, 1);

		/* A FINISHED commissioning is not the fail-safe's to remove. */
		dev.committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
		memset(&dev.attempt, 0, sizeof(dev.attempt));
		matter_clusters_failsafe_expire(&dev);
		T_EQ("a completed fabric survives", dev.fabrics[0].index, 1);

		/* A later administrator starts with fabric 1 committed, adds fabric
		 * 2, then disappears. The transaction owns only the newcomer's slot,
		 * so the committed slot survives the rollback. */
		memset(&dev.attempt, 0, sizeof(dev.attempt));
		dev.attempt.active = true;
		dev.committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
		dev.have_op_key = true;
		memcpy(dev.op_pub, k_node01_pubkey, sizeof(k_node01_pubkey));
		dev.fabrics[1].have_root = true;
		memcpy(dev.fabrics[1].root_public_key, dev.fabrics[0].root_public_key,
		       sizeof(dev.fabrics[1].root_public_key));
		/* The root reached slot 2 inside this transaction, which is what
		 * makes it the pending slot AddNOC fills. */
		dev.attempt.owned_slots = MATTER_FABRIC_SLOT_BIT(1u);
		T_EQ("the later AddNOC runs", srv.command(srv.ctx, &inv, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("the later fabric is accepted", dev.last_noc_status, MATTER_NOC_STATUS_OK);
		T_EQ("in slot 2", dev.fabrics[1].index, 2);
		matter_clusters_failsafe_expire(&dev);
		T_EQ("the completed fabric still survives", dev.fabrics[0].index, 1);
		T_EQ("the provisional fabric is removed", dev.fabrics[1].index, 0);
		T_OK("the later fail-safe is disarmed", !dev.attempt.active);
		/* Keep this scenario independent of the wire-format fixtures below,
		 * which exercise AddNOC with an armed fail-safe and a pending key. */
		dev.attempt.active = true;
		dev.have_op_key = true;
		memcpy(dev.op_pub, k_node01_pubkey, sizeof(k_node01_pubkey));
	}

	saved_dev = dev;
	t_group("a failed Home Assistant attempt cannot consume or erase Apple's fabric");
	{
		memset(&dev, 0, sizeof(dev));
		test_matter_thread_stub_reset();
		dev.fabrics[0].index = 1u;
		dev.fabrics[0].fabric_id = 0x1111u;
		memcpy(dev.fabrics[0].root_public_key, k_spec_root_pub,
		       sizeof(dev.fabrics[0].root_public_key));
		dev.fabric_acls[0].len = 1u;
		dev.fabric_acls[0].data[0] = 0xa1u;
		dev.committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
		dev.fabrics[1].index = 2u;
		dev.fabrics[1].fabric_id = 0x2222u;
		dev.fabric_acls[1].len = 1u;
		dev.fabric_acls[1].data[0] = 0xb2u;
		dev.attempt.active = true;
		dev.attempt.owned_slots = MATTER_FABRIC_SLOT_BIT(1u);
		dev.attempt.thread_applied = true;
		dev.thread_dataset_len = 4u;
		memcpy(dev.thread_dataset, "home", 4u);
		dev.icac.owner_index = 2u;
		dev.icac.len = 8u;

		matter_clusters_failsafe_expire(&dev);
		T_EQ("Apple fabric survives", dev.fabrics[0].index, 1u);
		T_EQ("Apple ACL survives", dev.fabric_acls[0].data[0], 0xa1u);
		T_EQ("only the provisional HA fabric is cleared", dev.fabrics[1].index, 0u);
		T_EQ("its ACL is cleared", dev.fabric_acls[1].len, 0u);
		T_EQ("its shared ICAC ownership is cleared", dev.icac.owner_index, 0u);
		T_EQ("the committed Apple Thread dataset is restored", g_thread_start_calls, 1u);
		T_EQ("and Apple's operational service is republished", g_thread_advertise_calls,
		     1u);
		T_OK("the attempt is disarmed", !dev.attempt.active);
	}

	t_group("CommissioningComplete is a durability boundary");
	{
		memset(&dev, 0, sizeof(dev));
		dev.commissioning_hooks = &k_test_hooks;
		dev.fabrics[0].index = 1u;
		dev.committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
		dev.fabrics[1].index = 2u;
		dev.fabrics[1].case_admin_subject = 0x55u;
		dev.attempt.active = true;
		dev.attempt.owned_slots = MATTER_FABRIC_SLOT_BIT(1u);
		dev.accessing_fabric_index = 2u;
		dev.accessing_node_id = 0x55u;
		invoke_init(&inv, MATTER_CMD_GC_COMMISSIONING_COMPLETE, NULL, 0u);
		inv.cluster = MATTER_CLUSTER_GENERAL_COMMISSIONING;
		inv.has_fields = false;
		s_store_calls = 0;
		s_store_fail = 1;
		T_EQ("the command is answered", srv.command(srv.ctx, &inv, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("storage was attempted once", s_store_calls, 1u);
		T_EQ("the provisional slot was named", s_store_slot, 1u);
		T_EQ("the operation was a commit", s_store_operation,
		     MATTER_FABRIC_STORE_COMMIT_ATTEMPT);
		T_OK("a failed store leaves the attempt rollbackable", dev.attempt.active);
		T_EQ("and does not promote its slot", dev.committed_slots,
		     MATTER_FABRIC_SLOT_BIT(0u));

		s_store_fail = 0;
		T_EQ("retry is answered", srv.command(srv.ctx, &inv, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_OK("successful durability disarms the attempt", !dev.attempt.active);
		T_EQ("both fabrics are now committed", dev.committed_slots,
		     MATTER_FABRIC_SLOT_BIT(0u) | MATTER_FABRIC_SLOT_BIT(1u));
	}
	dev = saved_dev;

	t_group("what a commissioner can read back");
	{
		struct matter_tlv_writer w;
		uint8_t buf[16];
		size_t n = 0u;

		T_EQ("SupportedFabrics is answered",
		     srv.status(srv.ctx, MATTER_ENDPOINT_ROOT,
				MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
				MATTER_ATTR_OC_SUPPORTED_FABRICS),
		     MATTER_IM_STATUS_SUCCESS);
		/* Fabrics is what a commissioner reads over CASE to confirm the
		 * fabric it just created is the one this node joined. While it
		 * answered UNSUPPORTED, a real iPhone sat on "Adding to home". */
		T_EQ("Fabrics is answered",
		     srv.status(srv.ctx, MATTER_ENDPOINT_ROOT,
				MATTER_CLUSTER_OPERATIONAL_CREDENTIALS, MATTER_ATTR_OC_FABRICS),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("NOCs is answered",
		     srv.status(srv.ctx, MATTER_ENDPOINT_ROOT,
				MATTER_CLUSTER_OPERATIONAL_CREDENTIALS, MATTER_ATTR_OC_NOCS),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("a genuinely absent attribute still is not",
		     srv.status(srv.ctx, MATTER_ENDPOINT_ROOT,
				MATTER_CLUSTER_OPERATIONAL_CREDENTIALS, 0x00FFu),
		     MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE);

		matter_tlv_writer_init(&w, buf, sizeof(buf));
		srv.value(srv.ctx, MATTER_ENDPOINT_ROOT, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
			  MATTER_ATTR_OC_COMMISSIONED_FABRICS, false, &w, MATTER_TLV_CTX(1u));
		T_EQ("CommissionedFabrics encodes", matter_tlv_writer_finish(&w, &n), MATTER_OK);
		/* context tag 1, uint8, value 1 */
		T_EQ("as one fabric", n, 3u);
		T_EQ("and it is one", buf[2], 1u);
	}

	t_group("the NOCResponse on the wire");
	{
		uint8_t out[128];
		size_t n = 0u;

		/*
		 * The encoder RUNS the command before serialising its reply, so
		 * emptying the table here is what makes this AddNOC succeed --
		 * setting last_noc_status would be overwritten a moment later.
		 */
		dev.fabrics[0].index = 0u;
		dev.committed_slots = 0u;
		dev.attempt.active = true;
		dev.attempt.owned_slots = MATTER_FABRIC_SLOT_BIT(0u);
		len = fields_addnoc(fields, sizeof(fields), k_node01, sizeof(k_node01), ipk,
				    sizeof(ipk));
		invoke_init(&inv, MATTER_CMD_OC_ADD_NOC, fields, len);
		T_EQ("encodes", matter_im_invoke_response_encode(&srv, &inv, out, sizeof(out), &n),
		     MATTER_OK);
		T_EQ("and it succeeded", dev.last_noc_status, MATTER_NOC_STATUS_OK);
		/* CommandDataIB [0], path command 0x08, fields {status 0,
		 * fabricIndex 1}. */
		t_vec("NOCResponse, accepted", out, n,
		      "1528003601153500370024000024013e24020818350124000024010118181818"
		      "24ff0c18");

		/*
		 * Again with every slot taken: the same response command,
		 * carrying a different verdict and NO fabric index -- an index
		 * for a fabric that was not created is a number a commissioner
		 * could act on.
		 */
		struct matter_fabric saved[MATTER_SUPPORTED_FABRICS];
		size_t fi;

		memcpy(saved, dev.fabrics, sizeof(saved));
		for (fi = 0u; fi < MATTER_SUPPORTED_FABRICS; fi++) {
			dev.fabrics[fi].index = (uint8_t)(fi + 1u);
			dev.fabrics[fi].have_root = true;
		}
		dev.committed_slots = (uint8_t)((1u << MATTER_SUPPORTED_FABRICS) - 1u);
		T_EQ("encodes", matter_im_invoke_response_encode(&srv, &inv, out, sizeof(out), &n),
		     MATTER_OK);
		T_EQ("and it was refused", dev.last_noc_status, MATTER_NOC_STATUS_TABLE_FULL);
		t_vec("NOCResponse, refused", out, n,
		      "1528003601153500370024000024013e2402081835012400051818181824ff0c18");
		/* Put the table back: a full one is this block's fixture, not
		 * the state every later test expects to start from. */
		memcpy(dev.fabrics, saved, sizeof(saved));
		dev.committed_slots = 0u;
	}

	t_group("the AddTrustedRootCertificate reply on the wire");
	{
		uint8_t out[128];
		size_t n = 0u;

		len = fields_bytes(fields, sizeof(fields), 0u, k_root01, sizeof(k_root01));
		invoke_init(&inv, MATTER_CMD_OC_ADD_TRUSTED_ROOT_CERTIFICATE, fields, len);
		dev.attempt.active = true;
		T_EQ("encodes", matter_im_invoke_response_encode(&srv, &inv, out, sizeof(out), &n),
		     MATTER_OK);
		/* A CommandStatusIB, not a CommandDataIB: nothing to report but
		 * that it worked. */
		t_vec("status-only reply", out, n,
		      "1528003601153501370024000024013e24020b1835012400001818181824ff0c18");
	}
}

/* --------------------------------------------------- the network --- */

/*
 * A Thread operational dataset, shaped like a real one: meshcop type/length/
 * value, in the order a border router emits them. The Extended PAN ID is
 * deliberately NOT first, so finding it exercises the walk rather than an
 * index. Every key here is obviously fake.
 */
static const uint8_t k_dataset[] =
	{
		0x0E, 0x08, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, /* active timestamp */
		0x00, 0x03, 0x00, 0x00, 0x0F,                               /* channel 15 */
		0x35, 0x06, 0x00, 0x04, 0x00, 0x1F, 0xFF, 0xE0,             /* channel mask */
		0x02, 0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, /* extended PAN id */
		0x05, 0x10, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, /* network key */
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x03, 0x08,
		'o',  'p',  'e',  'n',  'a',  'l',  'i',  'r',              /* network name */
		0x01, 0x02, 0x12, 0x34,                                     /* PAN id */
		0x07, 0x08, 0xFD, 0x00, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, /* mesh-local prefix */
		0x04, 0x10, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, /* PSKc */
		0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0x0C, 0x04,
		0x02, 0xA0, 0xFF, 0xF8, /* security policy */
};

static const uint8_t k_xpanid[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33};

static size_t read_attr(const struct matter_im_server *srv, uint32_t cluster, uint32_t attribute,
			uint8_t *buf, size_t cap)
{
	struct matter_tlv_writer w;
	size_t n = 0u;

	matter_tlv_writer_init(&w, buf, cap);
	srv->value(srv->ctx, MATTER_ENDPOINT_ROOT, cluster, attribute, false, &w,
		   MATTER_TLV_CTX(1u));
	T_EQ("attribute encodes", matter_tlv_writer_finish(&w, &n), MATTER_OK);
	return n;
}

void test_matter_network(void)
{
	struct matter_device_info dev;
	struct matter_im_server srv;
	struct matter_im_invoke inv;
	uint8_t fields[512];
	uint8_t buf[64];
	uint32_t response = 0u;
	size_t len;
	size_t n;

	memset(&dev, 0, sizeof(dev));
	test_matter_thread_stub_reset();
	matter_clusters_init(&srv, &dev);

	t_group("what the commissioner asks first");

	T_EQ("the cluster exists",
	     srv.has_cluster(srv.ctx, MATTER_ENDPOINT_ROOT, MATTER_CLUSTER_NETWORK_COMMISSIONING),
	     1);
	n = read_attr(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING, MATTER_ATTR_FEATURE_MAP, buf,
		      sizeof(buf));
	/* context tag 1, uint8, value 2 = ThreadNetworkInterface */
	T_EQ("FeatureMap is three bytes", n, 3u);
	T_EQ("and says Thread", buf[2], MATTER_NC_FEATURE_THREAD);

	n = read_attr(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING, MATTER_ATTR_NC_NETWORKS, buf,
		      sizeof(buf));
	/* An empty array: control byte, tag octet, end-of-container marker. */
	T_EQ("Networks is empty", n, 3u);
	T_EQ("and is an array", buf[0], 0x36u);

	t_group("a dataset outside a fail-safe");

	len = fields_bytes(fields, sizeof(fields), 0u, k_dataset, sizeof(k_dataset));
	invoke_init(&inv, MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK, fields, len);
	inv.cluster = MATTER_CLUSTER_NETWORK_COMMISSIONING;
	T_EQ("refused", srv.command(srv.ctx, &inv, &response), MATTER_IM_STATUS_FAILSAFE_REQUIRED);
	T_EQ("nothing stored", dev.thread_dataset_len, 0);

	t_group("the dataset");

	dev.attempt.active = true;
	T_EQ("accepted", srv.command(srv.ctx, &inv, &response), MATTER_IM_STATUS_SUCCESS);
	T_OK("answered by NetworkConfigResponse",
	     response == MATTER_CMD_NC_NETWORK_CONFIG_RESPONSE);
	T_EQ("status is Success", dev.last_network_status, MATTER_NC_STATUS_SUCCESS);
	T_EQ("staged whole", dev.attempt.thread_dataset_len, sizeof(k_dataset));
	T_OK("staged verbatim",
	     memcmp(dev.attempt.thread_dataset, k_dataset, sizeof(k_dataset)) == 0);
	T_OK("extended PAN id found", dev.attempt.have_thread_candidate);
	T_OK("and it is the right one",
	     memcmp(dev.attempt.thread_xpanid, k_xpanid, sizeof(k_xpanid)) == 0);

	n = read_attr(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING, MATTER_ATTR_NC_NETWORKS, buf,
		      sizeof(buf));
	T_OK("Networks now lists one", n > 2u);

	t_group("datasets that are not one");
	{
		/* A TLV whose length runs off the end. Nothing may be read past
		 * the buffer, and no extended PAN id may be claimed. */
		static const uint8_t runaway[] = {0x0E, 0x08, 0x00, 0x02, 0x40};
		static const uint8_t incomplete[] = {
			0x00, 0x03, 0x00, 0x00, 0x0F, 0x01, 0x02, 0x12, 0x34, 0x02,
			0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x05,
			0x10, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
			0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		};
		uint8_t empty[1] = {0};

		len = fields_bytes(fields, sizeof(fields), 0u, runaway, sizeof(runaway));
		invoke_init(&inv, MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK, fields, len);
		inv.cluster = MATTER_CLUSTER_NETWORK_COMMISSIONING;
		T_EQ("malformed dataset is answered", srv.command(srv.ctx, &inv, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("status is OutOfRange", dev.last_network_status,
		     MATTER_NC_STATUS_OUT_OF_RANGE);
		T_OK("the valid candidate remains staged", dev.attempt.have_thread_candidate);

		len = fields_bytes(fields, sizeof(fields), 0u, incomplete, sizeof(incomplete));
		invoke_init(&inv, MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK, fields, len);
		inv.cluster = MATTER_CLUSTER_NETWORK_COMMISSIONING;
		T_EQ("an incomplete dataset is answered", srv.command(srv.ctx, &inv, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("and rejected before OpenThread", dev.last_network_status,
		     MATTER_NC_STATUS_OUT_OF_RANGE);

		len = fields_bytes(fields, sizeof(fields), 0u, empty, 0u);
		invoke_init(&inv, MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK, fields, len);
		inv.cluster = MATTER_CLUSTER_NETWORK_COMMISSIONING;
		T_EQ("empty dataset runs", srv.command(srv.ctx, &inv, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("and is refused", dev.last_network_status, MATTER_NC_STATUS_OUT_OF_RANGE);
	}

	t_group("being asked to connect, having attached");
	{
		uint8_t out[128];

		/* Put a good dataset back and let the stack report success. */
		test_matter_thread_stub_reset();
		g_thread_attached = 1;
		/*
		 * A commissioned node, because that is the only kind that has a
		 * name to publish: the instance name is derived from the fabric
		 * AddNOC installed. Set directly here rather than by replaying
		 * AddNOC, so this group tests the network half alone.
		 */
		dev.fabrics[0].index = 1u;
		dev.fabrics[0].fabric_id = SPEC_FABRIC_ID;
		dev.fabrics[0].node_id = UINT64_C(0xDEDEDEDE00010001);
		memcpy(dev.fabrics[0].root_public_key, k_spec_root_pub,
		       sizeof(dev.fabrics[0].root_public_key));
		len = fields_bytes(fields, sizeof(fields), 0u, k_dataset, sizeof(k_dataset));
		invoke_init(&inv, MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK, fields, len);
		inv.cluster = MATTER_CLUSTER_NETWORK_COMMISSIONING;
		T_EQ("the dataset is accepted", srv.command(srv.ctx, &inv, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("and remains staged until ConnectNetwork", g_thread_start_calls, 0);
		T_EQ("nothing waited on yet", g_thread_wait_calls, 0);

		len = fields_bytes(fields, sizeof(fields), 0u, k_xpanid, sizeof(k_xpanid));
		invoke_init(&inv, MATTER_CMD_NC_CONNECT_NETWORK, fields, len);
		inv.cluster = MATTER_CLUSTER_NETWORK_COMMISSIONING;
		T_EQ("the command runs", srv.command(srv.ctx, &inv, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_OK("answered by ConnectNetworkResponse",
		     response == MATTER_CMD_NC_CONNECT_NETWORK_RESPONSE);
		T_EQ("it waited", g_thread_wait_calls, 1);
		T_EQ("ConnectNetwork applied the candidate", g_thread_start_calls, 1);
		T_OK("verbatim",
		     g_thread_last_len == sizeof(k_dataset) &&
			     memcmp(g_thread_last_dataset, k_dataset, sizeof(k_dataset)) == 0);
		T_OK("within the advertised ConnectMaxTimeSeconds",
		     g_thread_last_timeout_ms < 60000u);
		T_EQ("and reports Success", dev.last_network_status, MATTER_NC_STATUS_SUCCESS);

		/*
		 * Being ON the network is not being findable on it. The
		 * commissioner closes BLE the moment this succeeds, so the SRP
		 * registration has to have happened by now, not after.
		 */
		T_EQ("and registered over SRP", g_thread_advertise_calls, 1);
		T_EQ("on the Matter operational port", g_thread_last_port, 5540);
		/* The compressed fabric id derived from this fabric's own root
		 * key, then the node id -- the exact string a commissioner
		 * resolves, not merely something of the right shape. */
		T_OK("under the name a commissioner resolves",
		     strcmp(g_thread_last_instance, "87E1B004E235A130-DEDEDEDE00010001") == 0);

		n = 0u;
		T_EQ("encodes", matter_im_invoke_response_encode(&srv, &inv, out, sizeof(out), &n),
		     MATTER_OK);
		/* path command 0x07, fields {status 0, errorValue null}. */
		t_vec("ConnectNetworkResponse, attached", out, n,
		      "1528003601153500370024000024013124020718350124000034021818181824ff0c18");
	}

	t_group("being asked to connect, having not");
	{
		uint8_t out[128];

		/*
		 * The case hardware makes expensive: the stack took the dataset
		 * and then never attached. Success here would send the
		 * commissioner hunting for a node that is not on the network.
		 */
		g_thread_attached = 0;
		g_thread_advertise_calls = 0;
		T_EQ("the command runs", srv.command(srv.ctx, &inv, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("and reports a real failure", dev.last_network_status,
		     MATTER_NC_STATUS_OTHER_CONNECTION_FAILUR);
		/* Publishing a node that is not reachable would give the
		 * commissioner an address to fail against instead of an
		 * answer. */
		T_EQ("and publishes nothing", g_thread_advertise_calls, 0);

		n = 0u;
		T_EQ("encodes", matter_im_invoke_response_encode(&srv, &inv, out, sizeof(out), &n),
		     MATTER_OK);
		/* path command 0x07, fields {status 9, errorValue null}. */
		t_vec("ConnectNetworkResponse, refused", out, n,
		      "1528003601153500370024000024013124020718350124000934021818181824ff0c18");
	}

	t_group("a stack that would not take the dataset");
	{
		test_matter_thread_stub_reset();
		g_thread_start_fail = 1;
		len = fields_bytes(fields, sizeof(fields), 0u, k_dataset, sizeof(k_dataset));
		invoke_init(&inv, MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK, fields, len);
		inv.cluster = MATTER_CLUSTER_NETWORK_COMMISSIONING;
		T_EQ("storing it still succeeds", srv.command(srv.ctx, &inv, &response),
		     MATTER_IM_STATUS_SUCCESS);
		/* The commissioner asked this node to REMEMBER a network, and it
		 * has. Whether it can join is ConnectNetwork's question. */
		T_EQ("as the commissioner asked", dev.last_network_status,
		     MATTER_NC_STATUS_SUCCESS);

		len = fields_bytes(fields, sizeof(fields), 0u, k_xpanid, sizeof(k_xpanid));
		invoke_init(&inv, MATTER_CMD_NC_CONNECT_NETWORK, fields, len);
		inv.cluster = MATTER_CLUSTER_NETWORK_COMMISSIONING;
		g_thread_attached = 1; /* would attach, if anything were attaching */
		T_EQ("connecting runs", srv.command(srv.ctx, &inv, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("and fails", dev.last_network_status,
		     MATTER_NC_STATUS_OTHER_CONNECTION_FAILUR);
		/* Nothing is attaching, so there is nothing to wait for -- and
		 * waiting 20 s to say so would block the commissioner for
		 * nothing. */
		T_EQ("without waiting at all", g_thread_wait_calls, 0);
		T_OK("the possibly partial apply is rollback-owned", dev.attempt.thread_applied);
		matter_clusters_failsafe_expire(&dev);
		T_EQ("and fail-safe expiry clears it", g_thread_clear_calls, 1);
	}
}
