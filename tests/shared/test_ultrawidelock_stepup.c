/*
 * Host known-answer test for the credential step-up (Access Document) codec + §7.4
 * verifier. Pure host build (no ESP-IDF, no hardware), compiled from the same
 * ultrawidelock_stepup/ultrawidelock_stepup_parse/ultrawidelock_crypto/ultrawidelock_hash sources
 * as the target, with ultrawidelock_prim_host.c as the AES-GCM double.
 *
 * Two anchor sets:
 *   §14.6  the spec worked example — StepUpSK -> SKReader/SKDevice, the
 *          SessionData request/response decrypt, the DeviceRequest bytes, the
 *          DeviceResponse parse, and the step-3 digest recompute. Byte-exact.
 *   synthetic  a deterministic self-minted issuer (stepup_vectors.h) whose ES256
 *          signatures really verify (checked at generation with the cryptography
 *          library). Drives the full verifier + every reject branch. The ES256
 *          primitive is a stub that, in GOLDEN mode, asserts the module handed it
 *          exactly the Sig_structure/signature/pubkey the real signer used.
 */
#include <stdio.h>
#include <string.h>

#include "ultrawidelock_crypto.h"
#include "ultrawidelock_hash.h"
#include "ultrawidelock_prim.h"
#include "ultrawidelock_stepup.h"

#include "stepup_vectors.h"

static int fails;

static size_t uh(uint8_t *d, const char *h)
{
	size_t n = strlen(h) / 2;

	for (size_t i = 0; i < n; i++) {
		unsigned v;

		sscanf(h + 2 * i, "%2x", &v);
		d[i] = (uint8_t)v;
	}
	return n;
}

static void chk_hex(const char *name, const uint8_t *got, size_t n, const char *want)
{
	char g[1200];

	for (size_t i = 0; i < n; i++) {
		sprintf(g + 2 * i, "%02x", got[i]);
	}
	if (strcmp(g, want) != 0) {
		printf("  FAIL %-28s\n    got  %s\n    want %s\n", name, g, want);
		fails++;
	} else {
		printf("  ok   %-28s\n", name);
	}
}

static void chk(const char *name, int cond)
{
	if (!cond) {
		printf("  FAIL %-28s\n", name);
		fails++;
	} else {
		printf("  ok   %-28s\n", name);
	}
}

static void chk_eq(const char *name, long got, long want)
{
	if (got != want) {
		printf("  FAIL %-28s got %ld want %ld\n", name, got, want);
		fails++;
	} else {
		printf("  ok   %-28s\n", name);
	}
}

/* ---- §14.6 spec vectors -------------------------------------------------- */

static const char *K_STEPUP_SK =
	"616f6575616f6575616f6575616f6575616f6575616f6575616f6575616f6575";
static const char *K_SKREADER =
	"d8dcf4959bf4ae5f05318bbd47d793f00bcb1dfaa82efbb32e10933c86148478";
static const char *K_SKDEVICE =
	"6a57227cc56f84760f03cd6c55c4da55d4a85cdc4ef39bb69a4fdf466606b270";
static const char *K_DEVREQ =
	"a2613163312e30613281a16131d818582ba26131a167616c69726f2d61a268656c656d656e7432f568656c65"
	"6d656e7434f5613567616c69726f2d61";
static const char *K_SD_REQ =
	"a16464617461584c8c8fba6253f17dd60f3f30fcf035195ecca10e706320c72ed41920e59ad72d0002305f08d"
	"fd03f785d91eb22cfe475760b72cba8c427a15c4520de417fc1a8b13c80f4a66ddc19df0e5b5d17";
static const char *K_SD_RESP =
	"a164646174615901fc8068130e2312181a60e00fbb74c6f71431b8dd77ec38d0e622568ec417f74575e2dcce0"
	"623bcff99c3fc3bf8a90bfdad1f1263ff016dc43f44c518c472de38ba2f05c2dff4493dd713d0babde2c009c58"
	"42d5cb7d348f1d93c1ca3224581a0ffc320631a86e93be1b2d572846ceb46746e2438fd21179c1587d9f48e94"
	"1b569682649ceac641c9a7a4dcdcd4f17de66b5c7660341e47d41785d578244f80d1ce00edf7a9b4b2ef2b2a58"
	"50c5f365f6a85d9ebf1fd0a8b9523d2d467ed1fd4dba8a95ebd8e46c1969085150738603bcb645dde6f5ebced5"
	"59d87582601c2b7db09d7a056059796084843b928559f81af2761d7c32dc101723f15f50c543212631590cc371"
	"e0010eb48011e370de65e7330b6ea4eb0bbe666e63f01451681b8e1261c12bca61524ad2daf081c9d21d06f302"
	"31eb926dce6e1c52f92c1068cea7a6ca8fe11b5dfd1d6fe48e8c336c2ef11f863f98dc877625ba8710cb7c860e"
	"e7f7202662409254e9c2da0cc2bf00ad585189e301a013342123782cdacec9eb1b17ddbc99eff438c501ddfb60"
	"58ef36db28a44b32b64470f49dbade000fe91d5925a129f89af53a61527702bc60c4667bc6bcbd9294b6bcaed1"
	"91dd76bf2873260dbe6da3d29fbeb883335bf7a1892421207968e1b87987b8419ffa629b8669582ff1cca8f211"
	"078f9b87db132ffdacc6068335d72546a679816d49d8a4";
static const char *K_DEVRESP =
	"a3613163312e30613281a26131a26131a167616c69726f2d6181d8185838a4613101613258200aa260c85ca2f"
	"6eca90016720a1d7c7c160baf9cfa1a5aa4156331b71863b426613368656c656d656e74326134a10001613284"
	"43a10126a104478ea23b8fe54e51590133d81859012ea7613163312e306132675348412d3235366133a167616"
	"c69726f2d61a3005820b193e9b1fd40d43aee51f794fb2754f537a12104b743f53ede26d4a74ef60466015820"
	"2f6f396adb893a91242c60f3b3a32237c90f543cbbed2bf10398ac228955b7e902582095feb0333d71a311b949"
	"21230db1bcd094629c01d0fe5e1f2ab6d888b8997ca36134a16134a40102200121582096313d6c63e24e337274"
	"2bfdb1a33ba2c897dcd68ab8c753e4fbd48dca6b7f9a2258201fb3269edd418857de1b39a4e4a44b92fa484caa"
	"722c228288f01d0c03a2c3d6613567616c69726f2d616136a36131c074323032342d30362d30315431333a3330"
	"3a30325a6132c074323032342d30362d30315431333a33303a30325a6133c074323032352d30362d3031543133"
	"3a33303a30325a6137f5584007df311fce5e28c83b5b88e6402fae24250c778eec0c58e06283a7d6ab7037e791"
	"307aadb8571b1229e18c49932de464a4dc4f639ad186eb8742099b56a15d17613567616c69726f2d61613300";
static const char *K_VDIGEST1 =
	"2f6f396adb893a91242c60f3b3a32237c90f543cbbed2bf10398ac228955b7e9";

/* ---- injected ES256 (see file header) ------------------------------------ */

enum { MODE_GOLDEN, MODE_ACCEPT, MODE_REJECT };
static int g_mode;
static int g_golden_ss_ok;
static int g_calls;

static int stub_verify(const uint8_t pub[65], const uint8_t *msg, size_t len, const uint8_t sig[64])
{
	g_calls++;
	if (g_mode == MODE_REJECT) {
		return -1;
	}
	if (g_mode == MODE_GOLDEN) {
		g_golden_ss_ok = len == SV_GOLDEN_SIGSTRUCT_len &&
				 memcmp(msg, SV_GOLDEN_SIGSTRUCT, len) == 0 &&
				 memcmp(sig, SV_GOLDEN_SIG, 64) == 0 &&
				 memcmp(pub, SV_ISSUER_PUB, 65) == 0;
		return g_golden_ss_ok ? 0 : -1;
	}
	return 0; /* MODE_ACCEPT */
}

static struct ultrawidelock_stepup_verify_ctx base_ctx(const uint8_t *kid, size_t kid_len,
					       const uint8_t *pub)
{
	static struct ultrawidelock_stepup_issuer iss;

	iss.kid = kid;
	iss.kid_len = kid_len;
	if (pub) {
		memcpy(iss.pub, pub, 65);
	}
	struct ultrawidelock_stepup_verify_ctx ctx = {0};

	ctx.issuers = &iss;
	ctx.n_issuers = 1;
	ctx.time_valid = 1;
	ctx.now_epoch = SV_EPOCH_NOW;
	ctx.access_iteration = 0;
	ctx.expected_doctype = ULTRAWIDELOCK_STEPUP_DOCTYPE_ACCESS;
	ctx.ecdsa_verify = stub_verify;
	return ctx;
}

/* ---- suites -------------------------------------------------------------- */

static void t_spec_keys_and_codec(void)
{
	printf("-- §14.6 keys + SessionData codec --\n");
	uint8_t block[ULTRAWIDELOCK_KEY_BLOCK_LEN] = {0};
	uint8_t stepup[32];

	uh(stepup, K_STEPUP_SK);
	memcpy(block + ULTRAWIDELOCK_STEPUP_SK_OFFSET, stepup, 32);

	uint8_t skr[32], skd[32];

	chk("derive_keys rc", ultrawidelock_stepup_derive_keys(block, skr, skd) == 0);
	chk_hex("SKReader", skr, 32, K_SKREADER);
	chk_hex("SKDevice", skd, 32, K_SKDEVICE);

	/* DeviceRequest bytes (Table 8-21). */
	uint8_t dr[128];
	size_t drn;

	chk("build_device_request rc", ultrawidelock_stepup_build_device_request(NULL, 0, dr, sizeof(dr),
									 &drn) == 0);
	chk_hex("DeviceRequest", dr, drn, K_DEVREQ);

	/* Seal the DeviceRequest -> §14.6 SessionData request (SKReader, ctr 1). */
	struct ultrawidelock_secchan sc;

	ultrawidelock_stepup_channel_init(&sc, skr, skd);

	uint8_t sd[256];
	size_t sdn;

	chk("seal_sessiondata rc",
	    ultrawidelock_stepup_seal_sessiondata(&sc, dr, drn, sd, sizeof(sd), &sdn) == 0);
	chk_hex("SessionData request", sd, sdn, K_SD_REQ);

	/* Open the §14.6 SessionData response -> DeviceResponse (SKDevice, ctr 1). */
	uint8_t sdresp[600];
	size_t sdrespn = uh(sdresp, K_SD_RESP);
	uint8_t devresp[600];
	size_t devn;

	chk("open_sessiondata rc", ultrawidelock_stepup_open_sessiondata(&sc, sdresp, sdrespn, devresp,
								 sizeof(devresp), &devn) == 0);
	chk_hex("DeviceResponse (decrypted)", devresp, devn, K_DEVRESP);

	/* In place, the way the reader's learn path opens it: the plaintext goes
	 * back into the SessionData buffer it arrived in. */
	struct ultrawidelock_secchan sc2;

	ultrawidelock_stepup_channel_init(&sc2, skr, skd);
	chk("open_sessiondata in place rc",
	    ultrawidelock_stepup_open_sessiondata(&sc2, sdresp, sdrespn, sdresp, sizeof(sdresp),
						  &devn) == 0);
	chk_hex("DeviceResponse (decrypted in place)", sdresp, devn, K_DEVRESP);
}

static void t_spec_parse_and_digest(void)
{
	printf("-- §14.6 DeviceResponse parse + digest recompute --\n");
	uint8_t buf[600];
	size_t n = uh(buf, K_DEVRESP);
	struct ultrawidelock_stepup_doc doc;

	chk("parse rc", ultrawidelock_stepup_parse_response(buf, n, &doc) == 0);
	chk("have_document", doc.have_document == 1);
	chk("status 0", doc.status == 0);
	chk("doc_type aliro-a", strcmp(doc.doc_type, "aliro-a") == 0);
	chk("mso_doc_type aliro-a", strcmp(doc.mso_doc_type, "aliro-a") == 0);
	chk("digest_alg SHA-256", strcmp(doc.digest_alg, "SHA-256") == 0);
	chk_eq("n_digests", (long)doc.n_digests, 3);
	chk_eq("n_items", (long)doc.n_items, 1);
	chk("item digest_id 1", doc.items[0].digest_id == 1);
	chk("item elem element2", strcmp(doc.items[0].elem_id, "element2") == 0);
	chk("timeVerificationRequired", doc.time_verification_required == 1);
	chk("have validFrom/Until", doc.have_valid_from && doc.have_valid_until);
	chk_eq("validFrom epoch", (long)doc.valid_from_epoch, SV_EPOCH_VALID_FROM);
	chk_eq("validUntil epoch", (long)doc.valid_until_epoch, SV_EPOCH_VALID_UNTIL);

	/* Step-3 digest recompute against valueDigests[id=1]. */
	uint8_t want[32];

	uh(want, K_VDIGEST1);
	uint8_t got[32];

	ultrawidelock_sha256(doc.items[0].tagged, doc.items[0].tagged_len, got);
	chk("SHA-256(item)==valueDigests[1]", memcmp(got, want, 32) == 0);

	/* Full verify with the digest/validity/doctype/iteration logic exercised on
	 * the real spec document; ES256 is ACCEPTED (no issuer key is in §14.6). */
	uint8_t kid[8];
	size_t kidn = uh(kid, "8ea23b8fe54e51");
	struct ultrawidelock_stepup_verify_ctx ctx = base_ctx(kid, kidn, NULL);
	struct ultrawidelock_stepup_verdict v;

	g_mode = MODE_ACCEPT;
	ctx.now_epoch = SV_EPOCH_VALID_FROM; /* inside the window */
	int rc = ultrawidelock_stepup_verify(&doc, &ctx, &v);

	chk("§14.6 verify valid", rc == 0 && v.valid);
	chk("§14.6 valid_elements 1", v.valid_elements == 1);
	chk("§14.6 digests_ok", v.digests_ok);
	chk("§14.6 doctype_ok", v.doctype_ok);
	chk("§14.6 time_ok", v.time_ok);
}

static int verify_bytes(const uint8_t *buf, size_t n, struct ultrawidelock_stepup_verify_ctx *ctx,
			struct ultrawidelock_stepup_verdict *v)
{
	struct ultrawidelock_stepup_doc doc;

	if (ultrawidelock_stepup_parse_response(buf, n, &doc) != 0) {
		return -2;
	}
	return ultrawidelock_stepup_verify(&doc, ctx, v);
}

static void t_synth_good_and_rejects(void)
{
	printf("-- synthetic verifier (real ES256 vectors) --\n");
	struct ultrawidelock_stepup_verify_ctx ctx = base_ctx(SV_KID, SV_KID_len, SV_ISSUER_PUB);
	struct ultrawidelock_stepup_verdict v;

	/* Good: GOLDEN mode also asserts the exact Sig_structure/sig/pubkey. */
	g_mode = MODE_GOLDEN;
	g_golden_ss_ok = 0;
	int rc = verify_bytes(SV_GOOD, SV_GOOD_len, &ctx, &v);

	chk("good valid", rc == 0 && v.valid);
	chk("good Sig_structure==golden", g_golden_ss_ok == 1);
	chk("good sig_ok", v.sig_ok);
	chk("good chain_validated (kid)", v.issuer_chain_validated == 1);
	chk("good valid_elements 1", v.valid_elements == 1);

	/* Bad signature -> reject at step 2. */
	g_mode = MODE_REJECT;
	verify_bytes(SV_GOOD, SV_GOOD_len, &ctx, &v);
	chk("bad-sig reject step 2", v.reject_step == 2 && !v.valid);

	/* From here ES256 is ACCEPTED so later steps are the ones under test. */
	g_mode = MODE_ACCEPT;

	/* Tampered item -> digest mismatch -> step 3. */
	verify_bytes(SV_TAMPERED, SV_TAMPERED_len, &ctx, &v);
	chk("tampered reject step 3", v.reject_step == 3 && v.valid_elements == 0);

	/* DocType mismatch (MSO aliro-r vs doc aliro-a) -> step 4. */
	verify_bytes(SV_DOCTYPE_MISMATCH, SV_DOCTYPE_MISMATCH_len, &ctx, &v);
	chk("doctype reject step 4", v.reject_step == 4 && !v.doctype_ok);

	/* Time window: now after validUntil -> step 5. */
	ctx.now_epoch = SV_EPOCH_VALID_UNTIL + 1;
	verify_bytes(SV_GOOD, SV_GOOD_len, &ctx, &v);
	chk("expired reject step 5", v.reject_step == 5);

	/* now before validFrom -> step 5. */
	ctx.now_epoch = SV_EPOCH_VALID_FROM - 1;
	verify_bytes(SV_GOOD, SV_GOOD_len, &ctx, &v);
	chk("not-yet-valid reject step 5", v.reject_step == 5);

	/* No trusted clock + TimeVerificationRequired=true -> step 5. */
	ctx.now_epoch = SV_EPOCH_NOW;
	ctx.time_valid = 0;
	verify_bytes(SV_GOOD, SV_GOOD_len, &ctx, &v);
	chk("no-clock+required reject step 5", v.reject_step == 5 && !v.time_ok);

	/* No trusted clock + TimeVerificationRequired=false -> accepted (MAY). */
	verify_bytes(SV_TIMEVER_FALSE, SV_TIMEVER_FALSE_len, &ctx, &v);
	chk("no-clock+not-required valid", v.valid && v.time_ok);
	ctx.time_valid = 1;

	/* ValidityIteration: VI=1 < AccessIteration=20, diff 19>=8 -> step 6. */
	ctx.access_iteration = 20;
	verify_bytes(SV_WITH_VI, SV_WITH_VI_len, &ctx, &v);
	chk("VI reject step 6", v.reject_step == 6 && !v.iteration_ok);

	/* VI=1 < AccessIteration=5, diff 4<8 -> valid. */
	ctx.access_iteration = 5;
	verify_bytes(SV_WITH_VI, SV_WITH_VI_len, &ctx, &v);
	chk("VI small-diff valid", v.valid);
	ctx.access_iteration = 0;

	/* Wrong kid -> issuer not found -> step 1. */
	uint8_t wrong_kid[4] = {0xaa, 0xbb, 0xcc, 0xdd};
	struct ultrawidelock_stepup_verify_ctx wctx = base_ctx(wrong_kid, 4, SV_ISSUER_PUB);

	verify_bytes(SV_GOOD, SV_GOOD_len, &wctx, &v);
	chk("wrong-kid reject step 1", v.reject_step == 1 && !v.issuer_key_found);

	/* x5chain: EE key extracted, chain NOT validated, otherwise valid. */
	g_mode = MODE_GOLDEN;
	g_golden_ss_ok = 0;
	struct ultrawidelock_stepup_verify_ctx xctx = base_ctx(NULL, 0, NULL);

	xctx.n_issuers = 0; /* force x5chain path */
	rc = verify_bytes(SV_X5CHAIN, SV_X5CHAIN_len, &xctx, &v);
	chk("x5chain valid", rc == 0 && v.valid);
	chk("x5chain key found", v.issuer_key_found);
	chk("x5chain chain NOT validated", v.issuer_chain_validated == 0);
	chk("x5chain Sig_structure==golden", g_golden_ss_ok == 1);
	g_mode = MODE_ACCEPT;

	/* No documents returned -> reject (no data elements). */
	rc = verify_bytes(SV_NO_DOC, SV_NO_DOC_len, &ctx, &v);
	chk("no-document reject", rc < 0 && !v.valid);
}

static void t_run_convenience(void)
{
	printf("-- ultrawidelock_stepup_run (§14.6 SessionData response) --\n");
	uint8_t block[ULTRAWIDELOCK_KEY_BLOCK_LEN] = {0}, stepup[32], skr[32], skd[32];

	uh(stepup, K_STEPUP_SK);
	memcpy(block + ULTRAWIDELOCK_STEPUP_SK_OFFSET, stepup, 32);
	ultrawidelock_stepup_derive_keys(block, skr, skd);

	struct ultrawidelock_secchan sc;

	ultrawidelock_stepup_channel_init(&sc, skr, skd);

	uint8_t sdresp[600];
	size_t sdn = uh(sdresp, K_SD_RESP);
	uint8_t scratch[700];
	uint8_t kid[8];
	size_t kidn = uh(kid, "8ea23b8fe54e51");
	struct ultrawidelock_stepup_verify_ctx ctx = base_ctx(kid, kidn, NULL);

	ctx.now_epoch = SV_EPOCH_VALID_FROM;
	g_mode = MODE_ACCEPT;

	struct ultrawidelock_stepup_doc doc;
	struct ultrawidelock_stepup_verdict v;
	int rc = ultrawidelock_stepup_run(&sc, sdresp, sdn, &ctx, scratch, sizeof(scratch), &doc, &v);

	chk("run valid", rc == 0 && v.valid);
	chk("run doc_type aliro-a", strcmp(doc.doc_type, "aliro-a") == 0);
	chk("run valid_elements 1", v.valid_elements == 1);
}

/* ---- malformed-input rejection ------------------------------------------- */

/* SV_GOOD single-byte offset map (byte-walked from stepup_vectors.h):
 *    0 top map        1 top key       9 documents arr  10 document map
 *   11 doc key       13 issSig map   14 issSig key     16 nameSpaces map
 *   17 ns key        25 items arr    26 item tag       27 tag arg
 *   30 item map      31 item key     33 digest_id      36 random hdr
 *   72 elem_id hdr   86 IssuerAuth   87 protected      91 unprot map
 *   92 label         93 kid          98 payload hdr   101 payload tag arg
 *  102 mso bstr     104 MSO map     105 MSO key       107 version value
 *  113 digestAlg    123 valueDigests 124 vd ns key    132 vd inner map
 *  133 vd id        134 vd hash     170 mso docType   180 validity map
 *  181 validity key 182 vkey char   183 tag(0)        184 date hdr
 *  185 date[0]      189 date[4]     255 timeVerReq    257 sig len
 *  324 doc docType  334 status                                            */

static size_t find_pat(const uint8_t *hay, size_t hn, const uint8_t *pat, size_t pn)
{
	for (size_t i = 0; i + pn <= hn; i++) {
		if (memcmp(hay + i, pat, pn) == 0) {
			return i;
		}
	}
	return (size_t)-1;
}

static int parse_mut2(size_t o1, uint8_t v1, size_t o2, uint8_t v2,
		      struct ultrawidelock_stepup_doc *doc)
{
	static uint8_t b[400]; /* static: the doc keeps slices into this buffer */
	struct ultrawidelock_stepup_doc local;

	memcpy(b, SV_GOOD, SV_GOOD_len);
	b[o1] = v1;
	b[o2] = v2;
	return ultrawidelock_stepup_parse_response(b, SV_GOOD_len, doc ? doc : &local);
}

/* Minimal DeviceResponse {"9": <value>} exercising the unknown-key skipper. */
static int parse_skipv(const uint8_t *val, size_t vn)
{
	uint8_t b[64] = {0xa1, 0x61, 0x39};
	struct ultrawidelock_stepup_doc doc;

	memcpy(b + 3, val, vn);
	return ultrawidelock_stepup_parse_response(b, 3 + vn, &doc);
}

/* SV_GOOD with the status value (offset 334) replaced by an arbitrary tail. */
static int parse_status_tail(const uint8_t *tail, size_t tn, struct ultrawidelock_stepup_doc *doc)
{
	uint8_t b[400];
	struct ultrawidelock_stepup_doc local;

	memcpy(b, SV_GOOD, 334);
	memcpy(b + 334, tail, tn);
	return ultrawidelock_stepup_parse_response(b, 334 + tn, doc ? doc : &local);
}

static void t_parse_malformed(void)
{
	printf("-- malformed DeviceResponse rejection --\n");

	static const struct {
		const char *name;
		size_t off;
		uint8_t val;
		size_t off2;
		uint8_t val2;
		int want;
	} m[] = {
		{"top not map", 0, 0x83, 0, 0x83, -1},
		{"top key not tstr", 1, 0x01, 1, 0x01, -1},
		{"documents not arr", 9, 0xa1, 9, 0xa1, -1},
		{"document not map", 10, 0x81, 10, 0x81, -1},
		{"doc key not tstr", 11, 0x01, 11, 0x01, -1},
		{"doc unknown-key skip fail", 12, 0x39, 13, 0xff, -1},
		{"doc docType not tstr", 324, 0x47, 324, 0x47, -1},
		{"issuerSigned not map", 13, 0x81, 13, 0x81, -1},
		{"issSig key not tstr", 14, 0x01, 14, 0x01, -1},
		{"issSig unknown skip fail", 15, 0x39, 16, 0xff, -1},
		{"issSig unknown skip ok", 15, 0x39, 15, 0x39, 0},
		{"nameSpaces not map", 16, 0x81, 16, 0x81, -1},
		{"ns key not tstr", 17, 0x01, 17, 0x01, -1},
		{"ns items not arr", 25, 0xa1, 25, 0xa1, -1},
		{"item not tag24", 27, 0x19, 27, 0x19, -1},
		{"item not a tag", 26, 0x00, 26, 0x00, -1},
		{"item inner not map", 30, 0x84, 30, 0x84, -1},
		{"item key not tstr", 31, 0x01, 31, 0x01, -1},
		{"item digestID not uint", 33, 0x20, 33, 0x20, -1},
		{"item elemID not tstr", 72, 0x48, 72, 0x48, -1},
		{"item skip fail", 36, 0x5f, 36, 0x5f, -1},
		{"IssuerAuth not arr", 86, 0xa4, 86, 0xa4, -1},
		{"IssuerAuth arr not 4", 86, 0x83, 86, 0x83, -1},
		{"protected not bstr", 87, 0x63, 87, 0x63, -1},
		{"unprotected not map", 91, 0x81, 91, 0x81, -1},
		{"COSE label not int", 92, 0x61, 92, 0x61, -1},
		{"COSE nint label skipped", 92, 0x20, 92, 0x20, 0},
		{"COSE label skip fail", 92, 0x07, 93, 0x5f, -1},
		{"kid not bstr", 93, 0x24, 93, 0x24, -1},
		{"payload not bstr", 98, 0x78, 98, 0x78, -1},
		{"payload tag not 24", 101, 0x19, 101, 0x19, -1},
		{"payload inner not bstr", 102, 0x78, 102, 0x78, -1},
		{"signature not 64B", 257, 0x3f, 257, 0x3f, -1},
		{"MSO not map", 104, 0x84, 104, 0x84, -1},
		{"MSO key not tstr", 105, 0x01, 105, 0x01, -1},
		{"MSO skip fail", 107, 0x7f, 107, 0x7f, -1},
		{"digestAlg not tstr", 113, 0x41, 113, 0x41, -1},
		{"MSO docType not tstr", 170, 0x41, 170, 0x41, -1},
		{"valueDigests not map", 123, 0x81, 123, 0x81, -1},
		{"vd ns key not tstr", 124, 0x01, 124, 0x01, -1},
		{"vd inner not map", 132, 0x81, 132, 0x81, -1},
		{"vd id not uint", 133, 0x20, 133, 0x20, -1},
		{"vd hash not bstr", 134, 0x61, 134, 0x61, -1},
		{"validity not map", 180, 0x83, 180, 0x83, -1},
		{"validity key not tstr", 181, 0x01, 181, 0x01, -1},
		{"date tag missing", 183, 0x00, 183, 0x00, -1},
		{"date tag not 0", 183, 0xc1, 183, 0xc1, -1},
		{"date not tstr", 184, 0x54, 184, 0x54, -1},
		{"validity skip fail", 182, 0x34, 183, 0xff, -1},
		{"timeVerReq not bool", 255, 0xf6, 255, 0xf6, -1},
	};

	for (size_t i = 0; i < sizeof(m) / sizeof(m[0]); i++) {
		chk(m[i].name,
		    parse_mut2(m[i].off, m[i].val, m[i].off2, m[i].val2, NULL) == m[i].want);
	}

	/* NULL / empty / truncated inputs. */
	struct ultrawidelock_stepup_doc doc;
	uint8_t one = 0xa0;

	chk("NULL buf", ultrawidelock_stepup_parse_response(NULL, 4, &doc) == -1);
	chk("NULL doc", ultrawidelock_stepup_parse_response(&one, 1, NULL) == -1);
	chk("empty input", ultrawidelock_stepup_parse_response(&one, 0, &doc) == -1);
	chk("truncated at payload", ultrawidelock_stepup_parse_response(SV_GOOD, 150, &doc) == -1);
	chk("truncated at COSE label", ultrawidelock_stepup_parse_response(SV_GOOD, 92, &doc) == -1);

	/* Unknown validity key "4" whose tagged value is skipped (rc 0, no signed). */
	chk("validity unknown key skip ok",
	    parse_mut2(182, 0x34, 182, 0x34, &doc) == 0 && doc.have_signed == 0);

	/* Broken tdates are tolerated: the field is just not marked present. */
	chk("date bad punctuation", parse_mut2(189, 'x', 189, 'x', &doc) == 0 && !doc.have_signed);
	chk("date bad digit", parse_mut2(185, 'A', 185, 'A', &doc) == 0 && !doc.have_signed);
	chk("date month 13", parse_mut2(190, '1', 191, '3', &doc) == 0 && !doc.have_signed);

	/* Year 0000 exercises the negative-era arm of days_from_civil. */
	{
		uint8_t b[400];

		memcpy(b, SV_GOOD, SV_GOOD_len);
		memcpy(b + 185, "0000", 4); /* year */
		memcpy(b + 190, "01", 2);   /* month <= 2 */
		chk("date year 0000",
		    ultrawidelock_stepup_parse_response(b, SV_GOOD_len, &doc) == 0 && doc.have_signed &&
			    doc.signed_epoch < 0);
	}

	/* validityIteration not a uint (mutated SV_WITH_VI). */
	{
		static const uint8_t pat[] = {0x61, 0x35, 0x01, 0x61, 0x37};
		size_t q = find_pat(SV_WITH_VI, SV_WITH_VI_len, pat, sizeof(pat));
		uint8_t b[400];

		chk("VI pattern found", q != (size_t)-1);
		memcpy(b, SV_WITH_VI, SV_WITH_VI_len);
		b[q + 2] = 0x20;
		chk("VI not uint", ultrawidelock_stepup_parse_response(b, SV_WITH_VI_len, &doc) == -1);
	}

	/* x5chain value that cannot be skipped (mutated SV_X5CHAIN). */
	{
		static const uint8_t pat[] = {0x18, 0x21, 0x58, 0x64};
		size_t q = find_pat(SV_X5CHAIN, SV_X5CHAIN_len, pat, sizeof(pat));
		uint8_t b[512];

		chk("x5chain pattern found", q != (size_t)-1);
		memcpy(b, SV_X5CHAIN, SV_X5CHAIN_len);
		b[q + 2] = 0x7f;
		chk("x5chain skip fail", ultrawidelock_stepup_parse_response(b, SV_X5CHAIN_len, &doc) == -1);
	}

	/* CBOR head argument widths on the status value. */
	{
		static const uint8_t t16[] = {0x19, 0x01, 0x00};
		static const uint8_t t32[] = {0x1a, 0x00, 0x01, 0x00, 0x00};
		static const uint8_t t64[] = {0x1b, 0, 0, 0, 0, 0, 0, 0, 0x07};
		static const uint8_t tbad[] = {0x1c};
		static const uint8_t ttrunc[] = {0x19, 0x01};

		chk("status uint16", parse_status_tail(t16, 3, &doc) == 0 && doc.status == 256);
		chk("status uint32", parse_status_tail(t32, 5, &doc) == 0 && doc.status == 65536);
		chk("status uint64", parse_status_tail(t64, 9, &doc) == 0 && doc.status == 7);
		chk("status ai 28 invalid", parse_status_tail(tbad, 1, NULL) == -1);
		chk("status arg truncated", parse_status_tail(ttrunc, 2, NULL) == -1);
		chk("top-key skip fail", parse_mut2(333, 0x39, 334, 0xff, NULL) == -1);
	}
	{
		uint8_t b = 0xbf; /* indefinite map */

		chk("indefinite map", ultrawidelock_stepup_parse_response(&b, 1, &doc) == -1);
	}

	/* Generic skipper: array / map / tag / simple / depth / truncation. */
	{
		static const uint8_t v_arr[] = {0x82, 0x00, 0x01};
		static const uint8_t v_arr_bad[] = {0x82, 0x00};
		static const uint8_t v_map_bad[] = {0xa1, 0x00};
		static const uint8_t v_tag[] = {0xc0, 0x00};
		static const uint8_t v_null[] = {0xf6};
		static const uint8_t v_bstr_bad[] = {0x45, 0x01, 0x02};
		static const uint8_t v_nolen[] = {0x58};
		uint8_t deep[24];

		chk("skip array", parse_skipv(v_arr, 3) == 0);
		chk("skip array truncated", parse_skipv(v_arr_bad, 2) == -1);
		chk("skip map truncated", parse_skipv(v_map_bad, 2) == -1);
		chk("skip tag", parse_skipv(v_tag, 2) == 0);
		chk("skip simple null", parse_skipv(v_null, 1) == 0);
		chk("skip bstr overlong", parse_skipv(v_bstr_bad, 3) == -1);
		chk("skip missing len byte", parse_skipv(v_nolen, 1) == -1);
		memset(deep, 0xc0, 22); /* 22 nested tags > CB_MAX_DEPTH */
		deep[22] = 0x00;
		chk("skip depth limit", parse_skipv(deep, 23) == -1);
	}

	/* documents array with a second (skipped) document; then a bad second. */
	{
		uint8_t b[400];

		memcpy(b, SV_GOOD, 332); /* top hdr + document (ends at 331) */
		b[9] = 0x82;             /* two documents */
		b[332] = 0x00;           /* second document: skippable uint */
		b[333] = 0x61;
		b[334] = 0x33;
		b[335] = 0x00; /* "3": 0 */
		chk("second document skipped",
		    ultrawidelock_stepup_parse_response(b, 336, &doc) == 0 && doc.have_document &&
			    doc.n_items == 1);
		b[332] = 0xff;
		chk("second document skip fail", ultrawidelock_stepup_parse_response(b, 336, &doc) == -1);
	}

	/* ULTRAWIDELOCK_STEPUP_MAX_ITEMS parsed, the 17th falls to the skipper. */
	{
		static const uint8_t hdr[] = {0xa1, 0x61, 0x32, 0x81, 0xa1, 0x61, 0x31,
					      0xa1, 0x61, 0x31, 0xa1, 0x61, 0x6e, 0x91};
		static const uint8_t item[] = {0xd8, 0x18, 0x44, 0xa1, 0x61, 0x31, 0x00};
		uint8_t b[200];
		size_t n = sizeof(hdr);

		memcpy(b, hdr, n);
		for (int i = 0; i < 16; i++) {
			memcpy(b + n, item, sizeof(item));
			n += sizeof(item);
		}
		b[n] = 0x00; /* 17th item: skipped */
		chk("17th item skipped", ultrawidelock_stepup_parse_response(b, n + 1, &doc) == 0 &&
						 doc.n_items == ULTRAWIDELOCK_STEPUP_MAX_ITEMS);
		chk_eq("17th item counted dropped", (long)doc.n_items_dropped, 1);
		b[n] = 0xff;
		chk("17th item skip fail", ultrawidelock_stepup_parse_response(b, n + 1, &doc) == -1);
	}

	/* ULTRAWIDELOCK_STEPUP_MAX_DIGESTS kept; one more valueDigest is counted, not
	 * an error: a real MSO lists more digests than the disclosed items. */
	{
		static const uint8_t hdr[] = {0xa1, 0x61, 0x32, 0x81, 0xa1, 0x61, 0x31,
					      0xa1, 0x61, 0x32, 0x84, 0x40, 0xa0};
		static const uint8_t mso_hdr[] = {0xa1, 0x61, 0x33, 0xa1, 0x61, 0x6e};
		uint8_t b[1200], mso[1100];
		size_t n = sizeof(hdr), m = sizeof(mso_hdr);
		unsigned nd = ULTRAWIDELOCK_STEPUP_MAX_DIGESTS + 1u;

		/* MSO {"3": {"n": {id: h32, ... nd of them}}} */
		memcpy(mso, mso_hdr, m);
		if (nd < 24u) {
			mso[m++] = (uint8_t)(0xa0u | nd);
		} else {
			mso[m++] = 0xb8;
			mso[m++] = (uint8_t)nd;
		}
		for (unsigned i = 0; i < nd; i++) {
			if (i >= 24u) {
				mso[m++] = 0x18;
			}
			mso[m++] = (uint8_t)i;
			mso[m++] = 0x58;
			mso[m++] = 0x20;
			memset(mso + m, (int)i, 32);
			m += 32;
		}
		memcpy(b, hdr, n);
		b[n++] = 0x59; /* payload bstr: 24(bstr(MSO)) */
		b[n++] = (uint8_t)((m + 5) >> 8);
		b[n++] = (uint8_t)(m + 5);
		b[n++] = 0xd8;
		b[n++] = 0x18;
		b[n++] = 0x59;
		b[n++] = (uint8_t)(m >> 8);
		b[n++] = (uint8_t)m;
		memcpy(b + n, mso, m);
		n += m;
		b[n++] = 0x58; /* signature: 64 B */
		b[n++] = 0x40;
		memset(b + n, 0x51, 64);
		n += 64;
		chk("digests over cap parse ok", ultrawidelock_stepup_parse_response(b, n, &doc) == 0);
		chk_eq("digests kept", (long)doc.n_digests, (long)ULTRAWIDELOCK_STEPUP_MAX_DIGESTS);
		chk_eq("digests dropped", (long)doc.n_digests_dropped, 1);
	}

	/* A docType longer than the field is truncated, and the doc says so: the
	 * step-4 compare then fails for a named reason, not as a wrong type. */
	{
		static uint8_t b[400]; /* static: the doc keeps slices into this buffer */
		size_t n = 324;
		struct ultrawidelock_stepup_verdict v;
		struct ultrawidelock_stepup_verify_ctx ctx = base_ctx(SV_KID, SV_KID_len, SV_ISSUER_PUB);

		memcpy(b, SV_GOOD, 324); /* up to the document's docType ("5") value */
		b[n++] = 0x78;
		b[n++] = 33;
		memset(b + n, 'x', 33);
		n += 33;
		memcpy(b + n, SV_GOOD + 332, SV_GOOD_len - 332);
		n += SV_GOOD_len - 332;
		chk("33-char docType parses", ultrawidelock_stepup_parse_response(b, n, &doc) == 0);
		chk_eq("33-char docType kept 31", (long)strlen(doc.doc_type), 31);
		chk("33-char docType flagged",
		    (doc.truncated & ULTRAWIDELOCK_STEPUP_TRUNC_DOC_TYPE) != 0);
		g_mode = MODE_ACCEPT;
		chk("33-char docType reject step 4",
		    ultrawidelock_stepup_verify(&doc, &ctx, &v) < 0 && v.reject_step == 4 &&
			    (v.truncated & ULTRAWIDELOCK_STEPUP_TRUNC_DOC_TYPE) != 0);
	}
}

/* ---- writer/APDU/SessionData edges + verifier seams ----------------------- */

/* SV_X5CHAIN with the 102-byte x5chain value spliced out for an alternative. */
static int x5_splice(const uint8_t *val, size_t vn, struct ultrawidelock_stepup_doc *doc)
{
	static const uint8_t pat[] = {0x18, 0x21, 0x58, 0x64};
	size_t q = find_pat(SV_X5CHAIN, SV_X5CHAIN_len, pat, sizeof(pat));
	static uint8_t b[600]; /* static: the doc keeps slices into this buffer */
	size_t n;

	if (q == (size_t)-1) {
		return -3;
	}
	memcpy(b, SV_X5CHAIN, q + 2);
	n = q + 2;
	memcpy(b + n, val, vn);
	n += vn;
	memcpy(b + n, SV_X5CHAIN + q + 2 + 102, SV_X5CHAIN_len - (q + 2 + 102));
	n += SV_X5CHAIN_len - (q + 2 + 102);
	return ultrawidelock_stepup_parse_response(b, n, doc);
}

static void t_stepup_edges(void)
{
	printf("-- builder/SessionData edges + verifier seams --\n");
	uint8_t out[64];
	size_t n;

	/* DeviceRequest writer overflow: element too long, then cap too small. */
	{
		char big[200];
		const char *elems[1];

		memset(big, 'e', sizeof(big) - 1);
		big[sizeof(big) - 1] = '\0';
		elems[0] = big;
		uint8_t dr[256];

		chk("devreq long elem",
		    ultrawidelock_stepup_build_device_request(elems, 1, dr, sizeof(dr), &n) == -1);
		chk("devreq tiny cap",
		    ultrawidelock_stepup_build_device_request(NULL, 0, dr, 4, &n) == -1);
	}

	/* Seal/open edges over a real channel. */
	uint8_t block[ULTRAWIDELOCK_KEY_BLOCK_LEN] = {0}, stepup[32], skr[32], skd[32];

	uh(stepup, K_STEPUP_SK);
	memcpy(block + ULTRAWIDELOCK_STEPUP_SK_OFFSET, stepup, 32);
	ultrawidelock_stepup_derive_keys(block, skr, skd);

	struct ultrawidelock_secchan sc;

	ultrawidelock_stepup_channel_init(&sc, skr, skd);
	{
		uint8_t plain[500] = {0};
		uint8_t sd[600];

		chk("seal plaintext too big",
		    ultrawidelock_stepup_seal_sessiondata(&sc, plain, 500, sd, sizeof(sd), &n) == -1);
		chk("seal out cap too small",
		    ultrawidelock_stepup_seal_sessiondata(&sc, plain, 4, sd, 6, &n) == -1);

		struct ultrawidelock_secchan dead = sc;

		dead.enc_ctr = 0xffffffffu;
		chk("seal counter exhausted",
		    ultrawidelock_stepup_seal_sessiondata(&dead, plain, 4, sd, sizeof(sd), &n) == -1);
	}
	{
		static const uint8_t bad_prefix[8] = {0};
		static const uint8_t short_form[] = {0xa1, 0x64, 0x64, 0x61, 0x74, 0x61, 0x50,
						     0,	   0,	 0,    0,    0,	   0,	 0,
						     0,	   0,	 0,    0,    0,	   0,	 0,
						     0,	   0,	 0};
		static const uint8_t trunc59[] = {0xa1, 0x64, 0x64, 0x61, 0x74, 0x61, 0x59, 0x00};
		static const uint8_t bad_ib[] = {0xa1, 0x64, 0x64, 0x61, 0x74, 0x61, 0x5a, 0x00};
		static const uint8_t tiny_blob[] = {0xa1, 0x64, 0x64, 0x61, 0x74, 0x61, 0x4f, 0, 0,
						    0,	  0,	0,    0,    0,	  0,	0,    0, 0,
						    0,	  0,	0,    0};
		uint8_t pt[64];

		chk("open bad prefix",
		    ultrawidelock_stepup_open_sessiondata(&sc, bad_prefix, 8, pt, sizeof(pt), &n) == -1);
		chk("open short-form GCM fail",
		    ultrawidelock_stepup_open_sessiondata(&sc, short_form, sizeof(short_form), pt,
						  sizeof(pt), &n) == -1);

		uint8_t byte_form[7 + 1 + 32] = {0xa1, 0x64, 0x64, 0x61,
						 0x74, 0x61, 0x58, 0x20}; /* bstr(32), 1-byte len */

		chk("open 0x58-form GCM fail",
		    ultrawidelock_stepup_open_sessiondata(&sc, byte_form, sizeof(byte_form), pt, sizeof(pt),
						  &n) == -1);
		chk("open 0x59 truncated",
		    ultrawidelock_stepup_open_sessiondata(&sc, trunc59, sizeof(trunc59), pt, sizeof(pt),
						  &n) == -1);
		chk("open bad length byte",
		    ultrawidelock_stepup_open_sessiondata(&sc, bad_ib, sizeof(bad_ib), pt, sizeof(pt),
						  &n) == -1);
		chk("open blob under tag len",
		    ultrawidelock_stepup_open_sessiondata(&sc, tiny_blob, sizeof(tiny_blob), pt, sizeof(pt),
						  &n) == -1);

		uint8_t sdresp[600];
		size_t sdn = uh(sdresp, K_SD_RESP);

		chk("open out cap too small",
		    ultrawidelock_stepup_open_sessiondata(&sc, sdresp, sdn, pt, 4, &n) == -1);
	}

	/* APDU builder bounds. */
	chk("envelope zero len",
	    ultrawidelock_stepup_build_envelope(out, 0, 0, out, sizeof(out), &n) == -1);
	chk("envelope cap too small", ultrawidelock_stepup_build_envelope(out, 32, 0, out, 8, &n) == -1);
	chk("get_response cap too small", ultrawidelock_stepup_build_get_response(0, out, 4, &n) == -1);

	/* Oversized protected header: Sig_structure build fails -> reject step 2. */
	struct ultrawidelock_stepup_verify_ctx ctx = base_ctx(SV_KID, SV_KID_len, SV_ISSUER_PUB);
	struct ultrawidelock_stepup_verdict v;
	struct ultrawidelock_stepup_doc doc;

	g_mode = MODE_ACCEPT;
	{
		static uint8_t b[1024];
		size_t bn = 0;

		memcpy(b, SV_GOOD, 87);
		bn = 87;
		b[bn++] = 0x59; /* protected: bstr(600) of zeros */
		b[bn++] = 0x02;
		b[bn++] = 0x58;
		memset(b + bn, 0, 600);
		bn += 600;
		memcpy(b + bn, SV_GOOD + 91, SV_GOOD_len - 91);
		bn += SV_GOOD_len - 91;
		chk("big-protected parse", ultrawidelock_stepup_parse_response(b, bn, &doc) == 0);
		chk("big-protected reject step 2",
		    ultrawidelock_stepup_verify(&doc, &ctx, &v) == -1 && v.reject_step == 2 && !v.sig_ok);
	}

	/* >=64 KiB payload: CBOR writer takes the 4-byte-length arm, then errors. */
	{
		static uint8_t b[70500];
		size_t bn = 0;

		memcpy(b, SV_GOOD, 98);
		bn = 98;
		b[bn++] = 0x5a; /* payload: bstr(70007) */
		b[bn++] = 0x00;
		b[bn++] = 0x01;
		b[bn++] = 0x11;
		b[bn++] = 0x77;
		b[bn++] = 0xd8; /* 24(bstr(70000)) */
		b[bn++] = 0x18;
		b[bn++] = 0x5a;
		b[bn++] = 0x00;
		b[bn++] = 0x01;
		b[bn++] = 0x11;
		b[bn++] = 0x70;
		memcpy(b + bn, SV_GOOD + 104, 152); /* the real MSO map */
		bn += 152;
		memset(b + bn, 0, 70000 - 152); /* MSO trailing padding */
		bn += 70000 - 152;
		memcpy(b + bn, SV_GOOD + 256, SV_GOOD_len - 256); /* sig + docType + status */
		bn += SV_GOOD_len - 256;
		chk("huge-payload parse", ultrawidelock_stepup_parse_response(b, bn, &doc) == 0);
		chk("huge-payload reject step 2",
		    ultrawidelock_stepup_verify(&doc, &ctx, &v) == -1 && v.reject_step == 2 && !v.sig_ok);
	}

	/* x5chain too short / without an SPKI marker -> issuer key not found. */
	{
		static const uint8_t tiny[] = {0x41, 0x00};
		uint8_t nomark[72] = {0x58, 0x46, 0}; /* bstr(70) of zeros */

		chk("x5chain tiny parse", x5_splice(tiny, sizeof(tiny), &doc) == 0);
		ultrawidelock_stepup_verify(&doc, &ctx, &v);
		chk("x5chain tiny reject step 1", v.reject_step == 1 && !v.issuer_key_found);
		chk("x5chain no-marker parse", x5_splice(nomark, sizeof(nomark), &doc) == 0);
		ultrawidelock_stepup_verify(&doc, &ctx, &v);
		chk("x5chain no-marker reject step 1", v.reject_step == 1 && !v.issuer_key_found);
	}

	/* No kid + no x5chain: a single provisioned issuer is used implicitly. */
	{
		chk("no-kid parse", parse_mut2(92, 0x05, 92, 0x05, &doc) == 0 && doc.kid == NULL);
		g_mode = MODE_GOLDEN;
		g_golden_ss_ok = 0;
		chk("no-kid single-issuer valid",
		    ultrawidelock_stepup_verify(&doc, &ctx, &v) == 0 && v.valid && g_golden_ss_ok);
		g_mode = MODE_ACCEPT;

		struct ultrawidelock_stepup_verify_ctx zctx = ctx;

		zctx.n_issuers = 0;
		ultrawidelock_stepup_verify(&doc, &zctx, &v);
		chk("no-kid zero-issuer reject step 1", v.reject_step == 1);
	}

	/* Disclosed item whose digestID has no valueDigests entry -> step 3. */
	{
		chk("unknown digestID parse", parse_mut2(33, 0x08, 33, 0x08, &doc) == 0);
		ultrawidelock_stepup_verify(&doc, &ctx, &v);
		chk("unknown digestID reject step 3",
		    v.reject_step == 3 && v.valid_elements == 0);
	}

	/* ultrawidelock_stepup_run early-outs: SessionData open fails, then parse fails. */
	{
		static const uint8_t junk[8] = {0};
		uint8_t scratch[64];

		chk("run open fail", ultrawidelock_stepup_run(&sc, junk, sizeof(junk), &ctx, scratch,
						      sizeof(scratch), &doc, &v) == -1);

		/* Seal invalid CBOR in the device direction so open succeeds. */
		struct ultrawidelock_secchan sc2;

		ultrawidelock_stepup_channel_init(&sc2, skr, skd);

		uint8_t nonce[ULTRAWIDELOCK_GCM_NONCE_LEN];
		uint8_t pt[2] = {0xff, 0xff};
		uint8_t sd[7 + 18] = {0xa1, 0x64, 0x64, 0x61, 0x74, 0x61, 0x52};

		ultrawidelock_crypto_gcm_nonce(1, 1, nonce);
		chk("device-direction seal",
		    ultrawidelock_aes256_gcm_encrypt(skd, nonce, sizeof(nonce), NULL, 0, pt, 2, sd + 7,
					     sd + 9, ULTRAWIDELOCK_GCM_TAG_LEN) == 0);
		chk("run parse fail", ultrawidelock_stepup_run(&sc2, sd, sizeof(sd), &ctx, scratch,
						       sizeof(scratch), &doc, &v) == -1);
	}
}

static void t_apdu_builders(void)
{
	printf("-- ENVELOPE / GET RESPONSE APDUs --\n");
	uint8_t data[4] = {0xa1, 0x64, 0x64, 0x61};
	uint8_t out[32];
	size_t n;

	chk("envelope rc", ultrawidelock_stepup_build_envelope(data, 4, 0, out, sizeof(out), &n) == 0);
	chk_hex("envelope", out, n, "00c3000004a164646100");
	chk("envelope chaining CLA 0x10",
	    ultrawidelock_stepup_build_envelope(data, 4, 1, out, sizeof(out), &n) == 0 && out[0] == 0x10);
	chk("get_response rc", ultrawidelock_stepup_build_get_response(0x20, out, sizeof(out), &n) == 0);
	chk_hex("get_response", out, n, "00c0000020");
}

int main(void)
{
	ultrawidelock_prim_init();
	ultrawidelock_crypto_init();

	t_spec_keys_and_codec();
	t_spec_parse_and_digest();
	t_synth_good_and_rejects();
	t_run_convenience();
	t_apdu_builders();
	t_parse_malformed();
	t_stepup_edges();

	printf("\n%s (%d failure%s)\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
	return fails ? 1 : 0;
}
