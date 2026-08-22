/**
 * @file test_matter_case_client.c — the initiator, judged by this node's responder.
 *
 * Every other Matter suite here checks one direction against a fixture. This
 * one cannot: a CASE initiator is only correct with respect to a responder, and
 * the responder it has to satisfy is a commercial lock nobody can put in a host
 * test. So the two halves are run against each other IN PROCESS --
 * matter_case_client.c's Sigma1 into matter_case.c's decoder, matter_case.c's
 * Sigma2 into matter_case_client.c's opener, and back again -- and each half is
 * the other's judge.
 *
 * What that proves: the tag numbers, the role swaps TBSData2 and TBSData3 turn
 * on, the transcript at each step, the key schedule, and that the initiator's
 * i2r is the responder's r2i. Every one of those is a mistake that encodes
 * cleanly, decodes cleanly and simply never verifies, which is exactly the
 * class a round trip catches and a fixture does not.
 *
 * What it does NOT prove: anything about P-256, because the host has none (see
 * test_matter_case_stub.c, paired mode), and anything about agreeing with
 * CHIP's encoding rather than merely with ourselves. A real lock is still the
 * judge of that.
 */
#include <stdbool.h>
#include <string.h>

#include "ultrawidelock_hash.h"
#include "matter_case.h"
#include "matter_case_client.h"
#include "matter_crypto.h"
#include "matter_fabric.h"
#include "matter_tlv.h"

#include "test.h"
#include "test_matter_case_stub.h"

/* Certificate element tags (credentials/CHIPCert.h:68-78), as matter_fabric.c
 * reads them and as matter_case_client.c reconstructs the signed span. */
#define CERT_TAG_SUBJECT    6u
#define CERT_TAG_PUBLIC_KEY 9u
#define CERT_TAG_SIGNATURE  11u
#define DN_TAG_NODE_ID      17u
#define DN_TAG_FABRIC_ID    21u

/** One identity in this fabric: a key, and the certificate that names it. */
struct ident {
	uint8_t priv[32];
	uint8_t pub[MATTER_CASE_PUBKEY_LEN];
	uint8_t cert[512];
	size_t cert_len;
	uint64_t node_id;
};

/** Fill @p priv with something distinct and non-zero, keyed off @p seed. */
static void make_priv(uint8_t priv[32], uint8_t seed)
{
	for (size_t i = 0; i < 32u; i++) {
		priv[i] = (uint8_t)(seed + i * 7u + 1u);
	}
}

/**
 * Build a Matter operational certificate the way a commissioner does, signed by
 * @p issuer_priv.
 *
 * Matter carries the certificate as TLV, but its signature covers the canonical
 * X.509 DER TBSCertificate. A zero signature first makes the TLV structurally
 * complete; matter_case_cert_tbs() then supplies the independent signed form
 * and the placeholder is replaced with the toy signature.
 */
static size_t build_cert(uint8_t *buf, size_t cap, uint64_t node_id, uint64_t fabric_id,
			 const uint8_t *subject_pub, const uint8_t *issuer_priv)
{
	uint8_t sig[MATTER_CASE_SIG_LEN] = {0};
	uint8_t der[512];
	const uint8_t *sig_at;
	struct matter_tlv_writer w;
	size_t der_len = 0u;
	size_t n = 0u;
	static const uint8_t serial[] = {1u};
	static const uint8_t key_id[20] = {1u};

	matter_tlv_writer_init(&w, buf, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(1u), serial, sizeof(serial));
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(2u), 1u);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(3u), MATTER_TLV_LIST);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(20u), 1u);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(4u), 1u);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(5u), 0u);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(CERT_TAG_SUBJECT), MATTER_TLV_LIST);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(DN_TAG_NODE_ID), node_id);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(DN_TAG_FABRIC_ID), fabric_id);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(7u), 1u);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(8u), 1u);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(CERT_TAG_PUBLIC_KEY), subject_pub,
				   MATTER_CASE_PUBKEY_LEN);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(10u), MATTER_TLV_LIST);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(1u), MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bool(&w, MATTER_TLV_CTX(1u), false);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(2u), 1u);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(4u), key_id, sizeof(key_id));
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(5u), key_id, sizeof(key_id));
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(CERT_TAG_SIGNATURE), sig, sizeof(sig));
	(void)matter_tlv_end_container(&w);
	T_EQ("certificate encodes", matter_tlv_writer_finish(&w, &n), MATTER_OK);
	T_EQ("certificate converts to X.509 TBS",
	     matter_case_cert_tbs(buf, n, der, sizeof(der), &der_len, &sig_at), MATTER_OK);
	T_EQ("issuer signs DER TBS", matter_case_sign(issuer_priv, der, der_len, sig), 0);
	memcpy((uint8_t *)sig_at, sig, sizeof(sig));
	return n;
}

/** Make one identity and certify it under @p issuer_priv. */
static void make_ident(struct ident *id, uint8_t seed, uint64_t node_id, uint64_t fabric_id,
		       const uint8_t *issuer_priv)
{
	memset(id, 0, sizeof(*id));
	id->node_id = node_id;
	make_priv(id->priv, seed);
	test_matter_case_stub_pubkey(id->priv, id->pub);
	id->cert_len =
		build_cert(id->cert, sizeof(id->cert), node_id, fabric_id, id->pub, issuer_priv);
}

/** SHA-256 over up to three concatenated messages, the CASE transcript shape. */
static void transcript(uint8_t out[32], const uint8_t *a, size_t a_len, const uint8_t *b,
		       size_t b_len, const uint8_t *c, size_t c_len)
{
	struct ultrawidelock_sha256 h;

	ultrawidelock_sha256_init(&h);
	ultrawidelock_sha256_update(&h, a, a_len);
	if (b != NULL) {
		ultrawidelock_sha256_update(&h, b, b_len);
	}
	if (c != NULL) {
		ultrawidelock_sha256_update(&h, c, c_len);
	}
	ultrawidelock_sha256_final(&h, out);
}

/* One fabric, and the four things every case below shares. */
static const uint64_t k_fabric_id = 0x2906C908D115D362ULL;
static const uint64_t k_peer_node = 0x00000000CAFE1234ULL;
static const uint64_t k_self_node = 0x000000000000BEEFULL;

static uint8_t s_ipk[MATTER_CASE_IPK_LEN];
static uint8_t s_root_priv[32];
static uint8_t s_root_pub[MATTER_CASE_PUBKEY_LEN];
static struct ident s_peer; /* the lock being unlocked: our responder half */
static struct ident s_self; /* this node: our initiator half */

/* The ephemerals, one pair per side. */
static uint8_t s_init_priv[32];
static uint8_t s_init_pub[MATTER_CASE_PUBKEY_LEN];
static uint8_t s_resp_priv[32];
static uint8_t s_resp_pub[MATTER_CASE_PUBKEY_LEN];
static uint8_t s_init_random[MATTER_CASE_RANDOM_LEN];
static uint8_t s_resp_random[MATTER_CASE_RANDOM_LEN];
static uint8_t s_resumption[16];

/** Everything a handshake needs, from one place, so no case forgets a field. */
static void fabric_setup(void)
{
	test_matter_case_stub_reset();
	g_case_stub_paired = 1;

	for (size_t i = 0; i < sizeof(s_ipk); i++) {
		s_ipk[i] = (uint8_t)(0x40u + i);
	}
	for (size_t i = 0; i < sizeof(s_init_random); i++) {
		s_init_random[i] = (uint8_t)(0x10u + i);
		s_resp_random[i] = (uint8_t)(0x90u + i);
	}
	for (size_t i = 0; i < sizeof(s_resumption); i++) {
		s_resumption[i] = (uint8_t)(0xE0u + i);
	}

	make_priv(s_root_priv, 0x01u);
	test_matter_case_stub_pubkey(s_root_priv, s_root_pub);
	make_ident(&s_peer, 0x30u, k_peer_node, k_fabric_id, s_root_priv);
	make_ident(&s_self, 0x60u, k_self_node, k_fabric_id, s_root_priv);

	make_priv(s_init_priv, 0xA0u);
	test_matter_case_stub_pubkey(s_init_priv, s_init_pub);
	make_priv(s_resp_priv, 0xD0u);
	test_matter_case_stub_pubkey(s_resp_priv, s_resp_pub);
}

/** The Sigma1 this node's initiator sends, and its length. */
static size_t client_sigma1(uint8_t *buf, size_t cap, uint64_t peer_node)
{
	struct matter_case_client_sigma1_in in;
	size_t n = 0u;

	memset(&in, 0, sizeof(in));
	in.ipk = s_ipk;
	in.root_pub = s_root_pub;
	in.fabric_id = k_fabric_id;
	in.peer_node_id = peer_node;
	in.initiator_random = s_init_random;
	in.initiator_eph_pub = s_init_pub;
	in.initiator_session_id = 0x1234u;

	T_EQ("sigma1 encodes", matter_case_client_sigma1_encode(&in, buf, cap, &n), MATTER_OK);
	return n;
}

/** The Sigma2 the responder half answers @p s1 with. */
static size_t server_sigma2(const struct matter_case_sigma1 *s1, const uint8_t *t1, uint8_t *buf,
			    size_t cap, uint8_t shared_out[MATTER_CASE_SECRET_LEN])
{
	struct matter_case_sigma2_in in;
	size_t n = 0u;

	memset(&in, 0, sizeof(in));
	in.initiator_pubkey = s1->initiator_pubkey;
	in.transcript_hash = t1;
	in.ipk = s_ipk;
	in.noc = s_peer.cert;
	in.noc_len = s_peer.cert_len;
	in.op_priv = s_peer.priv;
	in.verify_pub = s_peer.pub;
	in.responder_random = s_resp_random;
	in.responder_eph_priv = s_resp_priv;
	in.responder_eph_pub = s_resp_pub;
	in.resumption_id = s_resumption;
	in.responder_session_id = 0x4321u;

	T_EQ("sigma2 encodes", matter_case_sigma2_encode(&in, buf, cap, &n, shared_out), MATTER_OK);
	return n;
}

void test_matter_case_client(void)
{
	uint8_t s1[MATTER_CASE_SIGMA1_MAX];
	uint8_t s2[MATTER_CASE_SIGMA2_MAX];
	uint8_t s3[MATTER_CASE_SIGMA3_MAX];
	uint8_t t1[32];
	uint8_t t2[32];
	uint8_t t3[32];
	uint8_t dest[MATTER_CASE_DEST_ID_LEN];
	uint8_t srv_shared[MATTER_CASE_SECRET_LEN];
	struct matter_case_sigma1 got1;
	struct matter_case_client_sigma2 got2;
	struct matter_case_client_sigma2_in open_in;
	struct matter_case_client_sigma2_out open_out;
	struct matter_case_client_sigma3_in s3_in;
	struct matter_case_sigma3_in srv_s3;
	struct matter_case_sigma3_out srv_peer;
	struct matter_session_keys ck;
	struct matter_session_keys sk;
	uint8_t salt[MATTER_CASE_IPK_LEN + 32u];
	size_t n1;
	size_t n2;
	size_t n3;

	t_group("Sigma1: the responder half reads what the initiator half wrote");

	fabric_setup();
	n1 = client_sigma1(s1, sizeof(s1), k_peer_node);

	T_EQ("it decodes", matter_case_sigma1_decode(s1, n1, &got1), MATTER_OK);
	T_OK("the random survives",
	     memcmp(got1.initiator_random, s_init_random, sizeof(s_init_random)) == 0);
	T_OK("so does the ephemeral key",
	     memcmp(got1.initiator_pubkey, s_init_pub, sizeof(s_init_pub)) == 0);
	T_EQ("and the session id", (int)got1.initiator_session_id, 0x1234);
	T_OK("resumption is not offered", !got1.has_resumption);

	/*
	 * The destination identifier is the one field the responder does not
	 * read but RECOMPUTES, per fabric, looking for a match. If the initiator
	 * built it over a different field order the responder finds no fabric at
	 * all and answers nothing -- with no way to tell that from "wrong node".
	 */
	T_EQ("the responder recomputes the destination id",
	     matter_case_destination_id(s_ipk, s_init_random, s_root_pub, k_fabric_id, k_peer_node,
					dest),
	     MATTER_OK);
	T_OK("and it matches the one sent", memcmp(got1.destination_id, dest, sizeof(dest)) == 0);

	t_group("Sigma2: the initiator half opens what the responder half sealed");

	transcript(t1, s1, n1, NULL, 0u, NULL, 0u);
	n2 = server_sigma2(&got1, t1, s2, sizeof(s2), srv_shared);

	T_EQ("it decodes", matter_case_client_sigma2_decode(s2, n2, &got2), MATTER_OK);
	T_OK("the responder random survives",
	     memcmp(got2.responder_random, s_resp_random, sizeof(s_resp_random)) == 0);
	T_OK("so does its ephemeral key",
	     memcmp(got2.responder_eph_pub, s_resp_pub, sizeof(s_resp_pub)) == 0);
	T_EQ("and the session id", (int)got2.responder_session_id, 0x4321);

	memset(&open_in, 0, sizeof(open_in));
	open_in.s2 = &got2;
	open_in.ipk = s_ipk;
	open_in.transcript_hash = t1;
	open_in.initiator_eph_priv = s_init_priv;
	open_in.initiator_eph_pub = s_init_pub;
	open_in.root_pub = s_root_pub;
	open_in.fabric_id = k_fabric_id;
	open_in.peer_node_id = k_peer_node;

	T_EQ("it opens", matter_case_client_sigma2_open(&open_in, &open_out), MATTER_OK);
	/*
	 * Both sides ran ECDH over the same pair from opposite ends. A mismatch
	 * here is not a test artefact: it is the S2K salt, the S3K salt and
	 * every session key diverging at once.
	 */
	T_OK("both sides derived the same secret",
	     memcmp(open_out.shared, srv_shared, sizeof(srv_shared)) == 0);
	T_EQ("and the peer is who was asked for", (int)(open_out.node_id & 0xFFFFFFFFu),
	     (int)(k_peer_node & 0xFFFFFFFFu));

	t_group("Sigma3: the responder half verifies what the initiator half signed");

	transcript(t2, s1, n1, s2, n2, NULL, 0u);

	memset(&s3_in, 0, sizeof(s3_in));
	s3_in.shared = open_out.shared;
	s3_in.ipk = s_ipk;
	s3_in.transcript_hash = t2;
	s3_in.initiator_eph_pub = s_init_pub;
	s3_in.responder_eph_pub = s_resp_pub;
	s3_in.noc = s_self.cert;
	s3_in.noc_len = s_self.cert_len;
	s3_in.op_priv = s_self.priv;
	s3_in.verify_pub = s_self.pub;

	T_EQ("sigma3 encodes", matter_case_client_sigma3_encode(&s3_in, s3, sizeof(s3), &n3),
	     MATTER_OK);

	memset(&srv_s3, 0, sizeof(srv_s3));
	srv_s3.shared = srv_shared;
	srv_s3.ipk = s_ipk;
	srv_s3.transcript_hash = t2;
	srv_s3.initiator_eph_pub = s_init_pub;
	srv_s3.responder_eph_pub = s_resp_pub;

	T_EQ("and the responder opens it", matter_case_sigma3_open(&srv_s3, s3, n3, &srv_peer),
	     MATTER_OK);
	T_EQ("naming this node", (int)(srv_peer.node_id & 0xFFFFFFFFu),
	     (int)(k_self_node & 0xFFFFFFFFu));
	T_OK("on this fabric", srv_peer.fabric_id == k_fabric_id);

	t_group("the session keys, which are the same two keys read opposite ways");

	transcript(t3, s1, n1, s2, n2, s3, n3);
	memcpy(salt, s_ipk, sizeof(s_ipk));
	memcpy(&salt[sizeof(s_ipk)], t3, sizeof(t3));

	T_EQ("the initiator derives its schedule",
	     matter_case_client_keys(open_out.shared, s_ipk, t3, &ck), MATTER_OK);
	T_EQ("the responder derives its own",
	     matter_derive_session_keys(srv_shared, sizeof(srv_shared), salt, sizeof(salt), false,
					&sk),
	     MATTER_OK);
	/*
	 * matter_exchange.c seals with r2i and opens with i2r whatever role the
	 * session has, so the initiator's schedule is handed back swapped. What
	 * that has to mean, and all it has to mean, is this: the key one side
	 * seals with is the key the other opens with.
	 */
	T_OK("what the initiator seals with, the responder opens with",
	     memcmp(ck.r2i, sk.i2r, MATTER_KEY_LEN) == 0);
	T_OK("and the other way round", memcmp(ck.i2r, sk.r2i, MATTER_KEY_LEN) == 0);
	T_OK("the attestation challenge is not a direction",
	     memcmp(ck.attestation_challenge, sk.attestation_challenge, MATTER_KEY_LEN) == 0);

	t_group("a Sigma2 this node must refuse");

	/*
	 * Every one of these is a peer that got far enough to produce something
	 * openable. Refusing them is the whole difference between "somebody on
	 * my fabric answered" and "my lock answered".
	 */
	fabric_setup();
	n1 = client_sigma1(s1, sizeof(s1), k_peer_node);
	T_EQ("sigma1 decodes", matter_case_sigma1_decode(s1, n1, &got1), MATTER_OK);
	transcript(t1, s1, n1, NULL, 0u, NULL, 0u);
	n2 = server_sigma2(&got1, t1, s2, sizeof(s2), srv_shared);
	T_EQ("sigma2 decodes", matter_case_client_sigma2_decode(s2, n2, &got2), MATTER_OK);

	memset(&open_in, 0, sizeof(open_in));
	open_in.s2 = &got2;
	open_in.ipk = s_ipk;
	open_in.transcript_hash = t1;
	open_in.initiator_eph_priv = s_init_priv;
	open_in.initiator_eph_pub = s_init_pub;
	open_in.root_pub = s_root_pub;
	open_in.fabric_id = k_fabric_id;

	open_in.peer_node_id = k_peer_node + 1u;
	T_EQ("a different node on the same fabric",
	     matter_case_client_sigma2_open(&open_in, &open_out), MATTER_E_ACCESS);

	open_in.peer_node_id = k_peer_node;
	open_in.fabric_id = k_fabric_id + 1u;
	T_EQ("the right node on a different fabric",
	     matter_case_client_sigma2_open(&open_in, &open_out), MATTER_E_ACCESS);

	/*
	 * A certificate signed by somebody else's root. The AEAD tag and the
	 * TBSData2 signature both still check out -- this peer really does hold
	 * the IPK and the key its NOC names -- and the chain is the only thing
	 * that says the NOC is not one it minted for itself.
	 */
	open_in.fabric_id = k_fabric_id;
	{
		uint8_t other_root[32];

		make_priv(other_root, 0x77u);
		s_peer.cert_len = build_cert(s_peer.cert, sizeof(s_peer.cert), k_peer_node,
					     k_fabric_id, s_peer.pub, other_root);
		n2 = server_sigma2(&got1, t1, s2, sizeof(s2), srv_shared);
		T_EQ("sigma2 decodes", matter_case_client_sigma2_decode(s2, n2, &got2), MATTER_OK);
		T_EQ("a NOC this fabric's root never signed",
		     matter_case_client_sigma2_open(&open_in, &open_out), MATTER_E_ACCESS);
	}

	t_group("malformed input, refused rather than half-read");

	fabric_setup();
	n1 = client_sigma1(s1, sizeof(s1), k_peer_node);
	T_EQ("sigma1 decodes", matter_case_sigma1_decode(s1, n1, &got1), MATTER_OK);
	transcript(t1, s1, n1, NULL, 0u, NULL, 0u);
	n2 = server_sigma2(&got1, t1, s2, sizeof(s2), srv_shared);
	T_EQ("sigma2 decodes", matter_case_client_sigma2_decode(s2, n2, &got2), MATTER_OK);

	memset(&open_in, 0, sizeof(open_in));
	open_in.s2 = &got2;
	open_in.ipk = s_ipk;
	open_in.transcript_hash = t1;
	open_in.initiator_eph_priv = s_init_priv;
	open_in.initiator_eph_pub = s_init_pub;
	open_in.root_pub = s_root_pub;
	open_in.fabric_id = k_fabric_id;
	open_in.peer_node_id = k_peer_node;

	T_EQ("sigma1 into a buffer too small",
	     matter_case_client_sigma1_encode(
		     &(struct matter_case_client_sigma1_in){
			     .ipk = s_ipk,
			     .root_pub = s_root_pub,
			     .initiator_random = s_init_random,
			     .initiator_eph_pub = s_init_pub,
		     },
		     s1, 16u, &n3),
	     MATTER_E_NOSPACE);
	T_EQ("sigma1 with no IPK",
	     matter_case_client_sigma1_encode(
		     &(struct matter_case_client_sigma1_in){
			     .root_pub = s_root_pub,
			     .initiator_random = s_init_random,
			     .initiator_eph_pub = s_init_pub,
		     },
		     s1, sizeof(s1), &n3),
	     MATTER_E_INVAL);

	T_EQ("a Sigma2 that is not TLV at all",
	     matter_case_client_sigma2_decode((const uint8_t *)"\x01\x02", 2u, &got2),
	     MATTER_E_TYPE);
	T_EQ("a Sigma2 truncated mid-message", matter_case_client_sigma2_decode(s2, n2 / 2u, &got2),
	     MATTER_E_TRUNC);

	/* A ciphertext no longer than its own authentication tag. Caught in the
	 * decoder, because the open path would subtract past zero. */
	{
		uint8_t tiny[64];
		struct matter_tlv_writer w;
		size_t n = 0u;

		matter_tlv_writer_init(&w, tiny, sizeof(tiny));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(1u), s_resp_random,
					   MATTER_CASE_RANDOM_LEN);
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(4u), s_resumption, MATTER_TAG_LEN);
		(void)matter_tlv_end_container(&w);
		T_EQ("encodes", matter_tlv_writer_finish(&w, &n), MATTER_OK);
		T_EQ("a Sigma2 with no room for a ciphertext",
		     matter_case_client_sigma2_decode(tiny, n, &got2), MATTER_E_INVAL);
	}

	/*
	 * Not reachable through the decoder, which refuses this first -- but
	 * the open path subtracts the tag length from it, and a struct filled
	 * in by hand is the one caller the decoder does not stand in front of.
	 */
	{
		struct matter_case_client_sigma2 handmade = got2;

		handmade.encrypted_len = MATTER_TAG_LEN;
		open_in.s2 = &handmade;
		T_EQ("a hand-built Sigma2 whose ciphertext is only its own tag",
		     matter_case_client_sigma2_open(&open_in, &open_out), MATTER_E_INVAL);
		open_in.s2 = &got2;
	}

	T_EQ("a Sigma3 with no NOC to send",
	     matter_case_client_sigma3_encode(
		     &(struct matter_case_client_sigma3_in){
			     .shared = srv_shared,
			     .ipk = s_ipk,
			     .transcript_hash = t1,
			     .initiator_eph_pub = s_init_pub,
			     .responder_eph_pub = s_resp_pub,
			     .op_priv = s_self.priv,
		     },
		     s3, sizeof(s3), &n3),
	     MATTER_E_INVAL);
	T_EQ("session keys with nowhere to put them",
	     matter_case_client_keys(srv_shared, s_ipk, t1, NULL), MATTER_E_INVAL);

	test_matter_case_stub_reset();
}
