/**
 * @file test_matter_clusters.c — the two credential commands, the ACL write, and resume.
 *
 * These four entry points are what a commissioner uses to turn a blank node into a
 * working reader, and none of them were reachable from the other suites: the credential
 * pair are static command handlers behind matter_im_server::command, the ACL write is
 * behind ::write, and matter_clusters_resume() only runs on a reboot with a stored
 * dataset. All four are driven here through the server vtable that
 * matter_clusters_init() fills in, which is the same seam the IM layer calls in
 * production -- no test-only entry point exists or is added.
 *
 * What the assertions are worth: every status code is checked against the branch that
 * produces it, and the failure cases matter more than the success ones. A length-
 * tolerant SetAliroReaderConfig would store a 64-byte "P-256 public key" and the
 * reader would fail later, somewhere else, for a reason nobody would connect back to
 * commissioning. So each length is wrong by exactly one byte in its own case.
 */

#include "test.h"
#include "test_matter_thread_stub.h"

#include "matter_clusters.h"
#include "matter_im.h"
#include "matter_tlv.h"

#include <string.h>

/* ---- callback doubles ---------------------------------------------------- */

static int s_cfg_calls;
static int s_cfg_result;
static uint8_t s_cfg_signing[MATTER_ALIRO_SIGNING_KEY_LEN];
static uint8_t s_cfg_verification[MATTER_ALIRO_VERIFICATION_KEY_LEN];
static uint8_t s_cfg_group_id[MATTER_ALIRO_GROUP_ID_LEN];
static uint8_t s_cfg_grk[MATTER_ALIRO_GROUP_ID_LEN];

static int cfg_cb(const uint8_t signing[MATTER_ALIRO_SIGNING_KEY_LEN],
		  const uint8_t verification[MATTER_ALIRO_VERIFICATION_KEY_LEN],
		  const uint8_t group_id[MATTER_ALIRO_GROUP_ID_LEN],
		  const uint8_t grk[MATTER_ALIRO_GROUP_ID_LEN])
{
	s_cfg_calls++;
	memcpy(s_cfg_signing, signing, sizeof(s_cfg_signing));
	memcpy(s_cfg_verification, verification, sizeof(s_cfg_verification));
	memcpy(s_cfg_group_id, group_id, sizeof(s_cfg_group_id));
	memcpy(s_cfg_grk, grk, sizeof(s_cfg_grk));
	return s_cfg_result;
}

static int s_cred_calls;
static int s_cred_result;
static uint8_t s_cred_type;
static uint8_t s_cred_key[MATTER_ALIRO_VERIFICATION_KEY_LEN];

static uint16_t s_cred_index;
static uint16_t s_cred_user;

static int cred_cb(uint8_t credential_type,
		   const uint8_t public_key[MATTER_ALIRO_VERIFICATION_KEY_LEN],
		   uint16_t credential_index, uint16_t user_index)
{
	s_cred_calls++;
	s_cred_type = credential_type;
	s_cred_index = credential_index;
	s_cred_user = user_index;
	memcpy(s_cred_key, public_key, sizeof(s_cred_key));
	return s_cred_result;
}

static int s_clear_cred_calls;
static int s_clear_cred_result;
static uint8_t s_clear_cred_type;
static uint16_t s_clear_cred_index;

static int clear_cred_cb(uint8_t credential_type, uint16_t credential_index)
{
	s_clear_cred_calls++;
	s_clear_cred_type = credential_type;
	s_clear_cred_index = credential_index;
	return s_clear_cred_result;
}

static int s_clear_user_calls;
static int s_clear_user_result;
static uint16_t s_clear_user_index;

static int clear_user_cb(uint16_t user_index)
{
	s_clear_user_calls++;
	s_clear_user_index = user_index;
	return s_clear_user_result;
}

/* ---- fixtures ------------------------------------------------------------ */

static void reset_doubles(void)
{
	s_cfg_calls = 0;
	s_cfg_result = 0;
	s_cred_calls = 0;
	s_cred_result = 0;
	s_cred_type = 0xFFu;
	s_cred_index = 0xFFFFu;
	s_cred_user = 0xFFFFu;
	s_clear_cred_calls = 0;
	s_clear_cred_result = 0;
	s_clear_cred_type = 0xFFu;
	s_clear_cred_index = 0xFFFFu;
	s_clear_user_calls = 0;
	s_clear_user_result = 0;
	s_clear_user_index = 0xFFFFu;
	memset(s_cfg_signing, 0, sizeof(s_cfg_signing));
	memset(s_cfg_verification, 0, sizeof(s_cfg_verification));
	memset(s_cfg_group_id, 0, sizeof(s_cfg_group_id));
	memset(s_cfg_grk, 0, sizeof(s_cfg_grk));
	memset(s_cred_key, 0, sizeof(s_cred_key));
}

static void fill_info(struct matter_device_info *info)
{
	memset(info, 0, sizeof(*info));
	info->vendor_id = 0xFFF1u;
	info->product_id = 0x8001u;
	info->regulatory_config = MATTER_REGULATORY_INDOOR;
	info->location_capability = MATTER_REGULATORY_INDOOR;
	info->failsafe_expiry_s = 60u;
	info->failsafe_max_s = 900u;
	info->supports_concurrent_connection = true;
	info->ultrawidelock_reader_config_cb = cfg_cb;
	info->ultrawidelock_credential_cb = cred_cb;
	info->ultrawidelock_credential_clear_cb = clear_cred_cb;
	info->ultrawidelock_user_clear_cb = clear_user_cb;
	/* Most cluster tests exercise an operational administrator. Tests of
	 * commissioning replace this state explicitly in test_matter_fabric. */
	info->fabrics[0].index = 1u;
	info->fabrics[0].fabric_id = 1u;
	info->fabrics[0].node_id = 1u;
	info->fabrics[0].case_admin_subject = 1u;
	info->committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
	info->accessing_fabric_index = 1u;
	info->accessing_node_id = 1u;
}

/* A byte pattern that differs per field, so a handler that mixes two of them up
 * fails rather than passing on two buffers that happen to match. */
static void pattern(uint8_t *dst, size_t len, uint8_t seed)
{
	size_t i;

	for (i = 0u; i < len; i++) {
		dst[i] = (uint8_t)(seed + (uint8_t)i);
	}
}

/**
 * SetAliroReaderConfig arguments. Any length may be passed, including a wrong
 * one -- that is the point of most of the cases below. @p grk_len of SIZE_MAX
 * omits the GroupResolvingKey field entirely.
 */
static size_t build_cfg_fields(uint8_t *buf, size_t cap, const uint8_t *signing, size_t signing_len,
			       const uint8_t *verification, size_t verification_len,
			       const uint8_t *group_id, size_t group_id_len, const uint8_t *grk,
			       size_t grk_len)
{
	struct matter_tlv_writer w;
	size_t len = 0u;

	matter_tlv_writer_init(&w, buf, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	if (signing != NULL) {
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_ALIRO_CFG_SIGNING_KEY), signing,
					   signing_len);
	}
	if (verification != NULL) {
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_ALIRO_CFG_VERIFICATION_KEY),
					   verification, verification_len);
	}
	if (group_id != NULL) {
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_ALIRO_CFG_GROUP_ID), group_id,
					   group_id_len);
	}
	if (grk != NULL) {
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_ALIRO_CFG_GROUP_RESOLVING_KEY),
					   grk, grk_len);
	}
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_writer_finish(&w, &len);
	return len;
}

/** SetCredential arguments. @p have_user_index omits field 3 when false.
 *  @p cred_index is the CredentialIndex inside the nested CredentialStruct --
 *  the handle a later ClearCredential names this key by. */
static size_t build_cred_fields(uint8_t *buf, size_t cap, uint64_t cred_index, uint64_t cred_type,
				bool have_cred_struct, const uint8_t *data, size_t data_len,
				bool have_user_index, uint64_t user_index)
{
	struct matter_tlv_writer w;
	size_t len = 0u;

	matter_tlv_writer_init(&w, buf, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	if (have_cred_struct) {
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(TAG_SETCRED_CREDENTIAL),
						 MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_CREDSTRUCT_TYPE), cred_type);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_CREDSTRUCT_INDEX), cred_index);
		(void)matter_tlv_end_container(&w);
	}
	if (data != NULL) {
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_SETCRED_DATA), data, data_len);
	}
	if (have_user_index) {
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SETCRED_USER_INDEX), user_index);
	}
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_writer_finish(&w, &len);
	return len;
}

/**
 * ClearCredential arguments.
 *
 * @p have_cred_struct false omits the Credential field entirely, which is how a controller says
 * "every credential of every type"; @p have_index false omits CredentialIndex inside the struct,
 * which is malformed rather than a wildcard (the wildcard is index 0xFFFE).
 */
static size_t build_clear_cred_fields(uint8_t *buf, size_t cap, bool have_cred_struct,
				      uint64_t cred_type, bool have_index, uint64_t cred_index)
{
	struct matter_tlv_writer w;
	size_t len = 0u;

	matter_tlv_writer_init(&w, buf, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	if (have_cred_struct) {
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(TAG_CLEARCRED_CREDENTIAL),
						 MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_CREDSTRUCT_TYPE), cred_type);
		if (have_index) {
			(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_CREDSTRUCT_INDEX),
						 cred_index);
		}
		(void)matter_tlv_end_container(&w);
	}
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_writer_finish(&w, &len);
	return len;
}

/** ClearUser arguments. @p have_index false omits the only field there is. */
static size_t build_clear_user_fields(uint8_t *buf, size_t cap, bool have_index, uint64_t user_index)
{
	struct matter_tlv_writer w;
	size_t len = 0u;

	matter_tlv_writer_init(&w, buf, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	if (have_index) {
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_CLEARUSER_INDEX), user_index);
	}
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_writer_finish(&w, &len);
	return len;
}

static size_t build_acl(uint8_t *buf, size_t cap, uint8_t privilege, uint64_t subject,
			bool scoped, uint16_t endpoint, uint32_t cluster)
{
	struct matter_tlv_writer w;
	size_t len = 0u;

	matter_tlv_writer_init(&w, buf, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(2u), MATTER_TLV_ARRAY);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0u), privilege);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1u), 2u); /* CASE */
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(2u), MATTER_TLV_ARRAY);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_ANON, subject);
	(void)matter_tlv_end_container(&w);
	if (scoped) {
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(3u), MATTER_TLV_ARRAY);
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0u), cluster);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1u), endpoint);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
	} else {
		(void)matter_tlv_put_null(&w, MATTER_TLV_CTX(3u));
	}
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_writer_finish(&w, &len);
	return len;
}

static uint8_t run_command(struct matter_im_server *srv, uint32_t cluster, uint32_t cmd,
			   const uint8_t *fields, size_t fields_len, uint32_t *response_command)
{
	struct matter_im_invoke inv;
	uint32_t rc = 0u;

	memset(&inv, 0, sizeof(inv));
	inv.endpoint = MATTER_ENDPOINT_LOCK;
	inv.cluster = cluster;
	inv.command = cmd;
	inv.fields = fields;
	inv.fields_len = fields_len;
	inv.has_fields = fields != NULL;
	return srv->command(srv->ctx, &inv, response_command != NULL ? response_command : &rc);
}

/* Same, on the root endpoint. NetworkCommissioning lives there, not on the lock,
 * and a mismatch answers UNSUPPORTED_CLUSTER rather than anything about fields. */
static uint8_t run_root_command(struct matter_im_server *srv, uint32_t cluster, uint32_t cmd,
				const uint8_t *fields, size_t fields_len,
				uint32_t *response_command)
{
	struct matter_im_invoke inv;
	uint32_t rc = 0u;

	memset(&inv, 0, sizeof(inv));
	inv.endpoint = MATTER_ENDPOINT_ROOT;
	inv.cluster = cluster;
	inv.command = cmd;
	inv.fields = fields;
	inv.fields_len = fields_len;
	inv.has_fields = fields != NULL;
	return srv->command(srv->ctx, &inv, response_command != NULL ? response_command : &rc);
}

/* ---- suite --------------------------------------------------------------- */

void test_matter_clusters(void)
{
	struct matter_device_info info;
	struct matter_im_server srv;
	uint8_t signing[MATTER_ALIRO_SIGNING_KEY_LEN];
	uint8_t verification[MATTER_ALIRO_VERIFICATION_KEY_LEN];
	uint8_t group_id[MATTER_ALIRO_GROUP_ID_LEN];
	uint8_t grk[MATTER_ALIRO_GROUP_ID_LEN];
	uint8_t fields[256];
	size_t flen;

	pattern(signing, sizeof(signing), 0x10u);
	pattern(verification, sizeof(verification), 0x40u);
	pattern(group_id, sizeof(group_id), 0x80u);
	pattern(grk, sizeof(grk), 0xC0u);

	t_group("SetAliroReaderConfig accepts a well-formed identity");
	{
		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);

		flen = build_cfg_fields(fields, sizeof(fields), signing, sizeof(signing),
					verification, sizeof(verification), group_id,
					sizeof(group_id), grk, sizeof(grk));
		T_OK("fields encode", flen > 0u);
		T_EQ("accepted",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK,
				 MATTER_CMD_DL_SET_ALIRO_READER_CONFIG, fields, flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("store written once", s_cfg_calls, 1);
		T_OK("signing key forwarded verbatim",
		     memcmp(s_cfg_signing, signing, sizeof(signing)) == 0);
		T_OK("verification key forwarded verbatim",
		     memcmp(s_cfg_verification, verification, sizeof(verification)) == 0);
		T_OK("group id forwarded verbatim",
		     memcmp(s_cfg_group_id, group_id, sizeof(group_id)) == 0);
		T_OK("resolving key forwarded verbatim", memcmp(s_cfg_grk, grk, sizeof(grk)) == 0);

		/* The signing key is the one field NOT mirrored into device state:
		 * it goes to the store and nowhere else. */
		T_OK("config marked present", info.have_ultrawidelock_reader_config);
		T_OK("resolving key marked present", info.have_ultrawidelock_group_resolving_key);
		T_OK("verification key mirrored",
		     memcmp(info.ultrawidelock_verification_key, verification, sizeof(verification)) == 0);
		T_OK("group id mirrored",
		     memcmp(info.ultrawidelock_group_id, group_id, sizeof(group_id)) == 0);
		T_OK("resolving key mirrored",
		     memcmp(info.ultrawidelock_group_resolving_key, grk, sizeof(grk)) == 0);
	}

	t_group("SetAliroReaderConfig refuses a malformed identity");
	{
		/* Each length wrong by exactly one byte, one field at a time. */
		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);

		flen = build_cfg_fields(fields, sizeof(fields), NULL, 0u, verification,
					sizeof(verification), group_id, sizeof(group_id), grk,
					sizeof(grk));
		T_EQ("no signing key is an invalid command",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK,
				 MATTER_CMD_DL_SET_ALIRO_READER_CONFIG, fields, flen, NULL),
		     MATTER_IM_STATUS_INVALID_COMMAND);

		flen = build_cfg_fields(fields, sizeof(fields), signing, sizeof(signing), NULL, 0u,
					group_id, sizeof(group_id), grk, sizeof(grk));
		T_EQ("no verification key is an invalid command",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK,
				 MATTER_CMD_DL_SET_ALIRO_READER_CONFIG, fields, flen, NULL),
		     MATTER_IM_STATUS_INVALID_COMMAND);

		flen = build_cfg_fields(fields, sizeof(fields), signing, sizeof(signing),
					verification, sizeof(verification), NULL, 0u, grk,
					sizeof(grk));
		T_EQ("no group id is an invalid command",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK,
				 MATTER_CMD_DL_SET_ALIRO_READER_CONFIG, fields, flen, NULL),
		     MATTER_IM_STATUS_INVALID_COMMAND);

		flen = build_cfg_fields(fields, sizeof(fields), signing, sizeof(signing) - 1u,
					verification, sizeof(verification), group_id,
					sizeof(group_id), grk, sizeof(grk));
		T_EQ("a 31-byte signing key is refused",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK,
				 MATTER_CMD_DL_SET_ALIRO_READER_CONFIG, fields, flen, NULL),
		     MATTER_IM_STATUS_CONSTRAINT_ERROR);

		flen = build_cfg_fields(fields, sizeof(fields), signing, sizeof(signing),
					verification, sizeof(verification) - 1u, group_id,
					sizeof(group_id), grk, sizeof(grk));
		T_EQ("a 64-byte verification key is refused",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK,
				 MATTER_CMD_DL_SET_ALIRO_READER_CONFIG, fields, flen, NULL),
		     MATTER_IM_STATUS_CONSTRAINT_ERROR);

		flen = build_cfg_fields(fields, sizeof(fields), signing, sizeof(signing),
					verification, sizeof(verification), group_id,
					sizeof(group_id) - 1u, grk, sizeof(grk));
		T_EQ("a 15-byte group id is refused",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK,
				 MATTER_CMD_DL_SET_ALIRO_READER_CONFIG, fields, flen, NULL),
		     MATTER_IM_STATUS_CONSTRAINT_ERROR);

		flen = build_cfg_fields(fields, sizeof(fields), signing, sizeof(signing),
					verification, sizeof(verification), group_id,
					sizeof(group_id), NULL, 0u);
		T_EQ("a missing resolving key is refused",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK,
				 MATTER_CMD_DL_SET_ALIRO_READER_CONFIG, fields, flen, NULL),
		     MATTER_IM_STATUS_CONSTRAINT_ERROR);

		flen = build_cfg_fields(fields, sizeof(fields), signing, sizeof(signing),
					verification, sizeof(verification), group_id,
					sizeof(group_id), grk, sizeof(grk) - 1u);
		T_EQ("a 15-byte resolving key is refused",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK,
				 MATTER_CMD_DL_SET_ALIRO_READER_CONFIG, fields, flen, NULL),
		     MATTER_IM_STATUS_CONSTRAINT_ERROR);

		T_EQ("nothing reached the store", s_cfg_calls, 0);
		T_OK("and no config was recorded", !info.have_ultrawidelock_reader_config);
	}

	t_group("SetAliroReaderConfig fails loudly when the store cannot keep it");
	{
		reset_doubles();
		fill_info(&info);
		info.ultrawidelock_reader_config_cb = NULL;
		matter_clusters_init(&srv, &info);

		flen = build_cfg_fields(fields, sizeof(fields), signing, sizeof(signing),
					verification, sizeof(verification), group_id,
					sizeof(group_id), grk, sizeof(grk));
		/* Success here would claim an identity survives a reboot that will be
		 * gone at the next boot. */
		T_EQ("no store is a failure, not a success",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK,
				 MATTER_CMD_DL_SET_ALIRO_READER_CONFIG, fields, flen, NULL),
		     MATTER_IM_STATUS_FAILURE);
		T_OK("and no config was recorded", !info.have_ultrawidelock_reader_config);

		reset_doubles();
		fill_info(&info);
		s_cfg_result = -1;
		matter_clusters_init(&srv, &info);
		T_EQ("a refusing store is a failure",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK,
				 MATTER_CMD_DL_SET_ALIRO_READER_CONFIG, fields, flen, NULL),
		     MATTER_IM_STATUS_FAILURE);
		T_EQ("the store was asked", s_cfg_calls, 1);
		T_OK("and nothing was mirrored", !info.have_ultrawidelock_reader_config);
	}

	t_group("SetCredential installs the three credential types");
	{
		const uint8_t types[3] = {MATTER_DL_CRED_ALIRO_ISSUER_KEY,
					  MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT,
					  MATTER_DL_CRED_ALIRO_ENDPOINT_KEY};
		size_t i;

		for (i = 0u; i < 3u; i++) {
			uint32_t resp = 0u;

			reset_doubles();
			fill_info(&info);
			matter_clusters_init(&srv, &info);

			flen = build_cred_fields(fields, sizeof(fields), 4u, types[i], true,
						 verification, sizeof(verification), true, 7u);
			T_EQ("command succeeds",
			     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK,
					 MATTER_CMD_DL_SET_CREDENTIAL, fields, flen, &resp),
			     MATTER_IM_STATUS_SUCCESS);
			T_EQ("answered with SetCredentialResponse", (long)resp,
			     (long)MATTER_CMD_DL_SET_CREDENTIAL_RESPONSE);
			T_EQ("credential status SUCCESS", info.last_credential_status,
			     MATTER_IM_STATUS_SUCCESS);
			T_EQ("type forwarded", s_cred_type, types[i]);
			T_EQ("installed once", s_cred_calls, 1);
			T_OK("key forwarded verbatim",
			     memcmp(s_cred_key, verification, sizeof(verification)) == 0);
			T_EQ("user index recorded", info.last_user_index, 7u);
			/*
			 * Both indices reach the store, which is the only reason
			 * a later ClearCredential can find this key again: the
			 * clear commands carry indices and never key bytes.
			 */
			T_EQ("credential index forwarded", s_cred_index, 4u);
			T_EQ("user index forwarded", s_cred_user, 7u);
		}
	}

	t_group("SetCredential refuses what the reader cannot use");
	{
		uint32_t resp = 0u;

		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);

		/* PIN: a surface this node does not claim. */
		flen = build_cred_fields(fields, sizeof(fields), 1u, 1u, true, verification,
					 sizeof(verification), true, 1u);
		T_EQ("command still succeeds",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_SET_CREDENTIAL,
				 fields, flen, &resp),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("but the credential is unsupported", info.last_credential_status,
		     MATTER_IM_STATUS_UNSUPPORTED_COMMAND);
		T_EQ("and nothing was installed", s_cred_calls, 0);

		flen = build_cred_fields(fields, sizeof(fields), 1u, MATTER_DL_CRED_ALIRO_ISSUER_KEY,
					 true, verification, sizeof(verification) - 1u, true, 1u);
		T_EQ("command still succeeds",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_SET_CREDENTIAL,
				 fields, flen, &resp),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("a 64-byte key is a constraint error", info.last_credential_status,
		     MATTER_IM_STATUS_CONSTRAINT_ERROR);
		T_EQ("and nothing was installed", s_cred_calls, 0);

		flen = build_cred_fields(fields, sizeof(fields), 1u, 0u, false, verification,
					 sizeof(verification), true, 1u);
		T_EQ("command still succeeds",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_SET_CREDENTIAL,
				 fields, flen, &resp),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("no CredentialStruct is an invalid command", info.last_credential_status,
		     MATTER_IM_STATUS_INVALID_COMMAND);

		flen = build_cred_fields(fields, sizeof(fields), 1u, MATTER_DL_CRED_ALIRO_ISSUER_KEY,
					 true, NULL, 0u, true, 1u);
		T_EQ("command still succeeds",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_SET_CREDENTIAL,
				 fields, flen, &resp),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("no CredentialData is an invalid command", info.last_credential_status,
		     MATTER_IM_STATUS_INVALID_COMMAND);
		T_EQ("and nothing was installed", s_cred_calls, 0);

		/*
		 * TLV carries both indices as unsigned integers of any width and the
		 * store's are 16 bits. Truncating 0x10001 to 1 would bind this key to
		 * an index the admin never sent, and the ClearCredential(1) that
		 * follows would revoke somebody else's key instead.
		 */
		flen = build_cred_fields(fields, sizeof(fields), 0x10001u,
					 MATTER_DL_CRED_ALIRO_ENDPOINT_KEY, true, verification,
					 sizeof(verification), true, 1u);
		T_EQ("command still succeeds",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_SET_CREDENTIAL,
				 fields, flen, &resp),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("a credential index past 16 bits is an invalid command",
		     info.last_credential_status, MATTER_IM_STATUS_INVALID_COMMAND);
		T_EQ("and nothing was installed", s_cred_calls, 0);

		flen = build_cred_fields(fields, sizeof(fields), 1u,
					 MATTER_DL_CRED_ALIRO_ENDPOINT_KEY, true, verification,
					 sizeof(verification), true, 0x10001u);
		T_EQ("command still succeeds",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_SET_CREDENTIAL,
				 fields, flen, &resp),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("a user index past 16 bits is an invalid command",
		     info.last_credential_status, MATTER_IM_STATUS_INVALID_COMMAND);
		T_EQ("and nothing was installed", s_cred_calls, 0);
		T_EQ("and no user index is claimed", info.last_user_index, 0u);
	}

	t_group("SetCredential reports a store that refused");
	{
		reset_doubles();
		fill_info(&info);
		info.ultrawidelock_credential_cb = NULL;
		matter_clusters_init(&srv, &info);

		flen = build_cred_fields(fields, sizeof(fields), 1u, MATTER_DL_CRED_ALIRO_ISSUER_KEY,
					 true, verification, sizeof(verification), true, 3u);
		T_EQ("command still succeeds",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_SET_CREDENTIAL,
				 fields, flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("no store leaves the status at FAILURE", info.last_credential_status,
		     MATTER_IM_STATUS_FAILURE);
		T_EQ("and no user index is claimed", info.last_user_index, 0u);

		reset_doubles();
		fill_info(&info);
		s_cred_result = -1;
		matter_clusters_init(&srv, &info);
		T_EQ("command still succeeds",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_SET_CREDENTIAL,
				 fields, flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("a refusing store leaves FAILURE", info.last_credential_status,
		     MATTER_IM_STATUS_FAILURE);
		T_EQ("the store was asked", s_cred_calls, 1);

		/* UserIndex is optional: omitting it must not fail the install. */
		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);
		flen = build_cred_fields(fields, sizeof(fields), 1u, MATTER_DL_CRED_ALIRO_ISSUER_KEY,
					 true, verification, sizeof(verification), false, 0u);
		T_EQ("command succeeds",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_SET_CREDENTIAL,
				 fields, flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("installed without a user index", info.last_credential_status,
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("index stays zero", info.last_user_index, 0u);
	}

	t_group("the ACL is one of two writable attributes");
	{
		struct matter_im_path path;
		uint8_t acl[64];
		uint8_t oversized[MATTER_ACL_MAX + 1u];

		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);
		pattern(acl, sizeof(acl), 0x20u);
		memset(oversized, 0xAAu, sizeof(oversized));

		memset(&path, 0, sizeof(path));
		path.endpoint = MATTER_ENDPOINT_ROOT;
		path.cluster = MATTER_CLUSTER_ACCESS_CONTROL;
		path.attribute = MATTER_ATTR_AC_ACL;
		info.fabrics[0].index = 1u;
		info.fabrics[0].case_admin_subject = 1u;
		info.committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
		info.accessing_fabric_index = 1u;
		info.accessing_node_id = 1u;
		T_EQ("ACL write accepted", srv.write(srv.ctx, &path, acl, sizeof(acl)),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("length recorded", info.fabric_acls[0].len, sizeof(acl));
		T_OK("bytes stored verbatim",
		     memcmp(info.fabric_acls[0].data, acl, sizeof(acl)) == 0);

		/* Truncating would read back as a shorter list than was written, which
		 * looks like the node silently dropped entries it was asked to grant. */
		T_EQ("an oversized ACL is refused, not truncated",
		     srv.write(srv.ctx, &path, oversized, sizeof(oversized)),
		     MATTER_IM_STATUS_RESOURCE_EXHAUSTED);
		T_EQ("and the stored one is untouched", info.fabric_acls[0].len, sizeof(acl));

		T_EQ("an empty write is an invalid command", srv.write(srv.ctx, &path, acl, 0u),
		     MATTER_IM_STATUS_INVALID_COMMAND);
		T_EQ("a null write is an invalid command",
		     srv.write(srv.ctx, &path, NULL, sizeof(acl)),
		     MATTER_IM_STATUS_INVALID_COMMAND);

		path.attribute = MATTER_ATTR_AC_ACL + 1u;
		T_EQ("another Access Control attribute is not writable",
		     srv.write(srv.ctx, &path, acl, sizeof(acl)),
		     MATTER_IM_STATUS_UNSUPPORTED_WRITE);

		/* A cluster this node really has, and a cluster it does not: the two
		 * answers must differ, or a commissioner cannot tell a typo from a
		 * read-only attribute. */
		path.cluster = MATTER_CLUSTER_DESCRIPTOR;
		path.attribute = 0u;
		T_EQ("a real read-only cluster says UNSUPPORTED_WRITE",
		     srv.write(srv.ctx, &path, acl, sizeof(acl)),
		     MATTER_IM_STATUS_UNSUPPORTED_WRITE);

		path.cluster = 0x1234u;
		T_EQ("a cluster this node lacks says UNSUPPORTED_CLUSTER",
		     srv.write(srv.ctx, &path, acl, sizeof(acl)),
		     MATTER_IM_STATUS_UNSUPPORTED_CLUSTER);

		path.endpoint = 9u;
		path.cluster = MATTER_CLUSTER_ACCESS_CONTROL;
		path.attribute = MATTER_ATTR_AC_ACL;
		T_EQ("an endpoint this node lacks says UNSUPPORTED_ENDPOINT",
		     srv.write(srv.ctx, &path, acl, sizeof(acl)),
		     MATTER_IM_STATUS_UNSUPPORTED_ENDPOINT);

		path.endpoint = MATTER_ENDPOINT_ROOT;
		T_EQ("a null device refuses every write", srv.write(NULL, &path, acl, sizeof(acl)),
		     MATTER_IM_STATUS_UNSUPPORTED_ENDPOINT);
	}

	t_group("fabric ACLs delegate access without authorizing PASE");
	{
		struct matter_im_path path = {
			.endpoint = MATTER_ENDPOINT_ROOT,
			.cluster = MATTER_CLUSTER_ACCESS_CONTROL,
			.attribute = MATTER_ATTR_AC_ACL,
		};
		struct matter_tlv_writer w;
		uint8_t acl[128];
		uint8_t args[64];
		size_t acl_len;
		size_t args_len = 0u;
		uint32_t response = 0u;

		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);

		acl_len = build_acl(acl, sizeof(acl), 5u, 0x77u, false, 0u, 0u);
		T_OK("administrator ACL builds", acl_len > 0u);
		T_EQ("bootstrap administrator stores it",
		     srv.write(srv.ctx, &path, acl, acl_len), MATTER_IM_STATUS_SUCCESS);

		info.accessing_node_id = 0x77u;
		matter_tlv_writer_init(&w, args, sizeof(args));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SETUSER_INDEX), 1u);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &args_len);
		T_EQ("delegated administrator can manage Door Lock",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_SET_USER, args,
				 args_len, NULL),
		     MATTER_IM_STATUS_SUCCESS);

		matter_tlv_writer_init(&w, args, sizeof(args));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0u), MATTER_SUPPORTED_FABRICS);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &args_len);
		T_EQ("delegated administrator reaches RemoveFabric",
		     run_root_command(&srv, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
				      MATTER_CMD_OC_REMOVE_FABRIC, args, args_len, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("invalid target still answers with NOCResponse", response,
		     MATTER_CMD_OC_NOC_RESPONSE);

		/* Replace it with an Operate grant scoped to Door Lock. The delegated
		 * administrator above is allowed to make this ACL change. */
		acl_len = build_acl(acl, sizeof(acl), 3u, 0x88u, true, MATTER_ENDPOINT_LOCK,
				    MATTER_CLUSTER_DOOR_LOCK);
		T_EQ("delegated administrator can replace the ACL",
		     srv.write(srv.ctx, &path, acl, acl_len), MATTER_IM_STATUS_SUCCESS);
		info.accessing_node_id = 0x88u;
		T_EQ("scoped operator can unlock",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_UNLOCK_DOOR,
				 NULL, 0u, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("but cannot manage users",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_SET_USER, args,
				 args_len, NULL),
		     MATTER_IM_STATUS_UNSUPPORTED_ACCESS);
		T_EQ("and cannot remove a fabric",
		     run_root_command(&srv, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
				      MATTER_CMD_OC_REMOVE_FABRIC, args, args_len, NULL),
		     MATTER_IM_STATUS_UNSUPPORTED_ACCESS);

		info.accessing_fabric_index = 0u;
		info.accessing_node_id = 0u;
		T_EQ("PASE cannot operate the lock",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_UNLOCK_DOOR,
				 NULL, 0u, NULL),
		     MATTER_IM_STATUS_UNSUPPORTED_ACCESS);
	}

	t_group("AutoRelockTime is the lock endpoint's writable attribute");
	{
		struct matter_im_path path;
		struct matter_tlv_writer w;
		uint8_t tlv[16];
		uint8_t out[64];
		size_t n;

		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);

		memset(&path, 0, sizeof(path));
		path.endpoint = MATTER_ENDPOINT_LOCK;
		path.cluster = MATTER_CLUSTER_DOOR_LOCK;
		path.attribute = MATTER_ATTR_DL_AUTO_RELOCK_TIME;

		T_EQ("readable before any write",
		     srv.status(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_DOOR_LOCK,
				MATTER_ATTR_DL_AUTO_RELOCK_TIME),
		     MATTER_IM_STATUS_SUCCESS);

		matter_tlv_writer_init(&w, tlv, sizeof(tlv));
		(void)matter_tlv_put_u64(&w, MATTER_TLV_ANON, 120u);
		T_EQ("a u32 write is accepted",
		     srv.write(srv.ctx, &path, tlv, w.len),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("the seconds are stored", info.auto_relock_time_s, 120u);

		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.value(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_DOOR_LOCK,
			  MATTER_ATTR_DL_AUTO_RELOCK_TIME, false, &w, MATTER_TLV_ANON);
		n = w.len;
		T_OK("the read emits a value", n > 0u);
		{
			struct matter_tlv_reader r;
			uint64_t v = 0u;

			matter_tlv_reader_init(&r, out, n);
			T_OK("read decodes", matter_tlv_next(&r) == 0 &&
					     matter_tlv_get_u64(&r, &v) == 0);
			T_EQ("read value matches", (uint32_t)v, 120u);
		}

		matter_tlv_writer_init(&w, tlv, sizeof(tlv));
		(void)matter_tlv_put_u64(&w, MATTER_TLV_ANON, 0x100000000ull);
		T_EQ("a value wider than u32 is a constraint error",
		     srv.write(srv.ctx, &path, tlv, w.len),
		     MATTER_IM_STATUS_CONSTRAINT_ERROR);
		T_EQ("and the stored value is untouched", info.auto_relock_time_s, 120u);

		T_EQ("an empty write is an invalid command",
		     srv.write(srv.ctx, &path, tlv, 0u), MATTER_IM_STATUS_INVALID_COMMAND);

		path.attribute = MATTER_ATTR_DL_LOCK_STATE;
		T_EQ("LockState itself is not writable",
		     srv.write(srv.ctx, &path, tlv, 4u), MATTER_IM_STATUS_UNSUPPORTED_WRITE);

		path.cluster = MATTER_CLUSTER_DESCRIPTOR;
		T_EQ("the lock's Descriptor is read-only",
		     srv.write(srv.ctx, &path, tlv, 4u), MATTER_IM_STATUS_UNSUPPORTED_WRITE);

		path.cluster = 0x1234u;
		T_EQ("a cluster the lock endpoint lacks says UNSUPPORTED_CLUSTER",
		     srv.write(srv.ctx, &path, tlv, 4u), MATTER_IM_STATUS_UNSUPPORTED_CLUSTER);
	}

	t_group("the lock serves the globals Apple builds its settings UI from");
	{
		struct matter_tlv_writer w;
		struct matter_tlv_reader r;
		uint8_t out[256];
		uint64_t v;
		bool saw_auto_relock = false;
		bool saw_cred_config_cmd = false;

		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);

		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.value(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_DOOR_LOCK,
			  MATTER_ATTR_CLUSTER_REVISION, false, &w, MATTER_TLV_ANON);
		matter_tlv_reader_init(&r, out, w.len);
		v = 0u;
		T_OK("ClusterRevision decodes",
		     matter_tlv_next(&r) == 0 && matter_tlv_get_u64(&r, &v) == 0);
		T_EQ("and is 8, the Nordic reference build's value", (unsigned)v,
		     MATTER_DL_CLUSTER_REVISION);

		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.value(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_DOOR_LOCK,
			  MATTER_ATTR_ATTRIBUTE_LIST, false, &w, MATTER_TLV_ANON);
		matter_tlv_reader_init(&r, out, w.len);
		T_OK("AttributeList is a container",
		     matter_tlv_next(&r) == 0 && matter_tlv_is_container(&r));
		T_OK("and can be entered", matter_tlv_enter(&r) == 0);
		while (matter_tlv_next(&r) == 0) {
			if (matter_tlv_get_u64(&r, &v) == 0 &&
			    v == MATTER_ATTR_DL_AUTO_RELOCK_TIME) {
				saw_auto_relock = true;
			}
		}
		T_OK("and it names AutoRelockTime, the optional control", saw_auto_relock);

		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.value(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_DOOR_LOCK,
			  MATTER_ATTR_ACCEPTED_CMD_LIST, false, &w, MATTER_TLV_ANON);
		matter_tlv_reader_init(&r, out, w.len);
		T_OK("AcceptedCommandList decodes",
		     matter_tlv_next(&r) == 0 && matter_tlv_enter(&r) == 0);
		while (matter_tlv_next(&r) == 0) {
			if (matter_tlv_get_u64(&r, &v) == 0 &&
			    v == MATTER_CMD_DL_SET_ALIRO_READER_CONFIG) {
				saw_cred_config_cmd = true;
			}
		}
		T_OK("and it names SetAliroReaderConfig", saw_cred_config_cmd);
	}

	t_group("Approach Direction is the lock endpoint's other writable cluster");
	{
		struct matter_im_path path;
		struct matter_tlv_writer w;
		struct matter_tlv_reader r;
		uint8_t tlv[16];
		uint8_t out[64];
		uint64_t v;
		const uint32_t *ids = NULL;
		size_t n;
		size_t i;
		bool listed = false;

		reset_doubles();
		fill_info(&info);
		info.approach_direction = MATTER_APPROACH_DIRECTION_ALL;
		matter_clusters_init(&srv, &info);

		/* The cluster has to be discoverable before its attribute
		 * matters: Home walks ServerList, not vendor documentation. */
		n = srv.list_clusters(srv.ctx, MATTER_ENDPOINT_LOCK, &ids);
		for (i = 0u; i < n; i++) {
			if (ids[i] == MATTER_CLUSTER_APPROACH_DIRECTION) {
				listed = true;
			}
		}
		T_OK("the lock endpoint lists the cluster", listed);
		T_EQ("and answers for its attribute",
		     srv.status(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_APPROACH_DIRECTION,
				MATTER_ATTR_APPROACH_DIRECTION),
		     MATTER_IM_STATUS_SUCCESS);

		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.value(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_APPROACH_DIRECTION,
			  MATTER_ATTR_APPROACH_DIRECTION, false, &w, MATTER_TLV_ANON);
		matter_tlv_reader_init(&r, out, w.len);
		v = 0u;
		T_OK("the direction decodes",
		     matter_tlv_next(&r) == 0 && matter_tlv_get_u64(&r, &v) == 0);
		T_EQ("and defaults to all three directions", (unsigned)v,
		     MATTER_APPROACH_DIRECTION_ALL);

		memset(&path, 0, sizeof(path));
		path.endpoint = MATTER_ENDPOINT_LOCK;
		path.cluster = MATTER_CLUSTER_APPROACH_DIRECTION;
		path.attribute = MATTER_ATTR_APPROACH_DIRECTION;

		matter_tlv_writer_init(&w, tlv, sizeof(tlv));
		(void)matter_tlv_put_u64(&w, MATTER_TLV_ANON, 0x01u);
		T_EQ("a bitmap8 write is accepted", srv.write(srv.ctx, &path, tlv, w.len),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("and stored", info.approach_direction, 0x01u);

		matter_tlv_writer_init(&w, tlv, sizeof(tlv));
		(void)matter_tlv_put_u64(&w, MATTER_TLV_ANON, 0x100u);
		T_EQ("a value wider than bitmap8 is a constraint error",
		     srv.write(srv.ctx, &path, tlv, w.len), MATTER_IM_STATUS_CONSTRAINT_ERROR);
		T_EQ("and the stored value is untouched", info.approach_direction, 0x01u);

		path.attribute = MATTER_ATTR_CLUSTER_REVISION;
		T_EQ("the cluster's globals are read-only",
		     srv.write(srv.ctx, &path, tlv, 4u), MATTER_IM_STATUS_UNSUPPORTED_WRITE);
	}

	t_group("the lock endpoint answers its own commands");
	{
		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);

		/* The tile's two buttons, answered with a bare status: DoorLock
		 * defines no LockDoorResponse, and inventing one leaves the
		 * controller waiting. */
		T_EQ("UnlockDoor accepted",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_UNLOCK_DOOR, NULL,
				 0u, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("and the lock reports unlocked", info.lock_state,
		     MATTER_DL_LOCK_STATE_UNLOCKED);
		T_EQ("LockDoor accepted",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_LOCK_DOOR, NULL, 0u,
				 NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("and the lock reports locked", info.lock_state, MATTER_DL_LOCK_STATE_LOCKED);

		/* A cluster the lock endpoint does not have. Answering
		 * UNSUPPORTED_ENDPOINT here would contradict every attribute read
		 * that says endpoint 1 exists. */
		T_EQ("a cluster this endpoint lacks says UNSUPPORTED_CLUSTER",
		     run_command(&srv, MATTER_CLUSTER_DESCRIPTOR, MATTER_CMD_DL_LOCK_DOOR, NULL, 0u,
				 NULL),
		     MATTER_IM_STATUS_UNSUPPORTED_CLUSTER);

		/* A Door Lock command this node has not implemented: the endpoint and
		 * the cluster are both real, the command is not. */
		T_EQ("an unimplemented command says UNSUPPORTED_COMMAND",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, 0x00FFu, NULL, 0u, NULL),
		     MATTER_IM_STATUS_UNSUPPORTED_COMMAND);
	}

	t_group("SetUser stores what GetUser will be asked for");
	{
		struct matter_tlv_writer w;

		reset_doubles();
		fill_info(&info);
		info.fabrics[1].index = 2u;
		info.fabrics[1].fabric_id = 2u;
		info.fabrics[1].node_id = 2u;
		info.fabrics[1].case_admin_subject = 2u;
		info.committed_slots |= MATTER_FABRIC_SLOT_BIT(1u);
		info.accessing_fabric_index = 2u;
		info.accessing_node_id = 2u;
		matter_clusters_init(&srv, &info);

		matter_tlv_writer_init(&w, fields, sizeof(fields));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SETUSER_INDEX), 1u);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SETUSER_UNIQUE_ID), 0xABCDu);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SETUSER_STATUS), 1u);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SETUSER_TYPE), 0u);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SETUSER_CREDENTIAL_RULE), 0u);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &flen);

		T_EQ("accepted",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_SET_USER, fields,
				 flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		/* Stored, not merely accepted: Apple reads the user straight back, and
		 * a node that says SUCCESS then reports an empty slot has told the
		 * controller two different things about the same user. */
		T_OK("slot 1 is in use", info.users[0].in_use);
		T_EQ("unique id kept", (long)info.users[0].unique_id, 0xABCDL);
		T_EQ("creator fabric recorded", info.users[0].creator_fabric, 2u);

		/* Index 0 and one past the table are both out of range. */
		matter_tlv_writer_init(&w, fields, sizeof(fields));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SETUSER_INDEX), 0u);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &flen);
		T_EQ("index 0 is refused",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_SET_USER, fields,
				 flen, NULL),
		     MATTER_IM_STATUS_INVALID_COMMAND);

		matter_tlv_writer_init(&w, fields, sizeof(fields));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SETUSER_INDEX),
					 MATTER_DL_USERS_MAX + 1u);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &flen);
		T_EQ("one past the table is refused",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_SET_USER, fields,
				 flen, NULL),
		     MATTER_IM_STATUS_INVALID_COMMAND);

		T_EQ("no index at all is refused",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_SET_USER, NULL, 0u,
				 NULL),
		     MATTER_IM_STATUS_INVALID_COMMAND);
	}

	/*
	 * ---- revocation ----------------------------------------------------
	 *
	 * ClearCredential and ClearUser are the only way the Door Lock cluster
	 * says "this key must stop working", and both are mandatory for the USR
	 * feature this node claims. While they answered UNSUPPORTED_COMMAND, a
	 * home key removed in the controller's UI went on opening the door.
	 */
	t_group("ClearCredential revokes the credential it names");
	{
		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);

		flen = build_clear_cred_fields(fields, sizeof(fields), true,
					       MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT, true, 4u);
		T_EQ("accepted",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_CREDENTIAL,
				 fields, flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("port told once", s_clear_cred_calls, 1);
		T_EQ("type forwarded", s_clear_cred_type, MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT);
		T_EQ("index forwarded", s_clear_cred_index, 4u);

		/* 0xFFFE: every credential of that type. */
		reset_doubles();
		flen = build_clear_cred_fields(fields, sizeof(fields), true,
					       MATTER_DL_CRED_ALIRO_ENDPOINT_KEY, true,
					       MATTER_DL_INDEX_ALL);
		T_EQ("wildcard index accepted",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_CREDENTIAL,
				 fields, flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("wildcard forwarded", s_clear_cred_index, MATTER_DL_INDEX_ALL);

		/* No Credential field at all: every credential of every type, which
		 * the port is told as type 0 -- not a credential type, so it cannot
		 * be confused with one. */
		reset_doubles();
		flen = build_clear_cred_fields(fields, sizeof(fields), false, 0u, false, 0u);
		T_EQ("absent credential clears everything",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_CREDENTIAL,
				 fields, flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("all types", s_clear_cred_type, 0u);
		T_EQ("all indices", s_clear_cred_index, MATTER_DL_INDEX_ALL);

		/* And with no fields whatsoever, which is the same statement. */
		reset_doubles();
		T_EQ("no fields clears everything",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_CREDENTIAL,
				 NULL, 0u, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("all types", s_clear_cred_type, 0u);
	}

	t_group("ClearCredential refuses what it cannot act on");
	{
		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);

		/* A credential class this node never claimed cannot be holding one. */
		flen = build_clear_cred_fields(fields, sizeof(fields), true, 1u /* PIN */, true, 1u);
		T_EQ("a PIN credential is not ours",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_CREDENTIAL,
				 fields, flen, NULL),
		     MATTER_IM_STATUS_INVALID_COMMAND);
		T_EQ("port not told", s_clear_cred_calls, 0);

		/* Indices are 1-based, so 0 is not a slot this lock could hold. */
		flen = build_clear_cred_fields(fields, sizeof(fields), true,
					       MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT, true, 0u);
		T_EQ("index 0 is refused",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_CREDENTIAL,
				 fields, flen, NULL),
		     MATTER_IM_STATUS_INVALID_COMMAND);

		/* A CredentialStruct with a type and no index names nothing. */
		flen = build_clear_cred_fields(fields, sizeof(fields), true,
					       MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT, false, 0u);
		T_EQ("a missing index is refused",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_CREDENTIAL,
				 fields, flen, NULL),
		     MATTER_IM_STATUS_INVALID_COMMAND);
		T_EQ("port still not told", s_clear_cred_calls, 0);
	}

	t_group("a revocation the store could not keep reports FAILURE");
	{
		/*
		 * The single most important status in this file. An admin told a key
		 * was removed stops looking; a removal that would come back on the
		 * next boot must therefore never be answered SUCCESS.
		 */
		reset_doubles();
		fill_info(&info);
		s_clear_cred_result = -1;
		s_clear_user_result = -1;
		matter_clusters_init(&srv, &info);

		flen = build_clear_cred_fields(fields, sizeof(fields), true,
					       MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT, true, 4u);
		T_EQ("ClearCredential reports the failure",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_CREDENTIAL,
				 fields, flen, NULL),
		     MATTER_IM_STATUS_FAILURE);

		flen = build_clear_user_fields(fields, sizeof(fields), true, 1u);
		T_EQ("ClearUser reports the failure",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_USER, fields,
				 flen, NULL),
		     MATTER_IM_STATUS_FAILURE);

		/* A port that registered no hook at all is the same answer: this node
		 * cannot revoke, and must not pretend it did. */
		reset_doubles();
		fill_info(&info);
		info.ultrawidelock_credential_clear_cb = NULL;
		info.ultrawidelock_user_clear_cb = NULL;
		matter_clusters_init(&srv, &info);
		info.users[0].in_use = true;

		flen = build_clear_cred_fields(fields, sizeof(fields), true,
					       MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT, true, 4u);
		T_EQ("no ClearCredential hook is a FAILURE",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_CREDENTIAL,
				 fields, flen, NULL),
		     MATTER_IM_STATUS_FAILURE);
		flen = build_clear_user_fields(fields, sizeof(fields), true, 1u);
		T_EQ("no ClearUser hook is a FAILURE",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_USER, fields,
				 flen, NULL),
		     MATTER_IM_STATUS_FAILURE);
		/* And the row survives it. A refusal that still emptied the slot
		 * would show the controller an empty user whose credential is
		 * untouched and still opening the door. */
		T_OK("refused ClearUser left the row alone", info.users[0].in_use);
	}

	t_group("ClearUser empties the slot and the credentials in it");
	{
		struct matter_tlv_writer w;

		reset_doubles();
		fill_info(&info);
		info.fabrics[1].index = 2u;
		info.fabrics[1].fabric_id = 2u;
		info.fabrics[1].node_id = 2u;
		info.fabrics[1].case_admin_subject = 2u;
		info.committed_slots |= MATTER_FABRIC_SLOT_BIT(1u);
		info.accessing_fabric_index = 2u;
		info.accessing_node_id = 2u;
		matter_clusters_init(&srv, &info);

		/* Fill slot 1 the way a controller does, then take it away. */
		matter_tlv_writer_init(&w, fields, sizeof(fields));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SETUSER_INDEX), 1u);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SETUSER_UNIQUE_ID), 0xABCDu);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &flen);
		T_EQ("user added",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_SET_USER, fields,
				 flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_OK("slot 1 in use", info.users[0].in_use);

		flen = build_clear_user_fields(fields, sizeof(fields), true, 1u);
		T_EQ("cleared",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_USER, fields,
				 flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		/* Both halves, because either one alone is a lie: an empty slot whose
		 * credential still opens the door, or a credential gone from a user
		 * the controller can still read back. */
		T_OK("slot 1 emptied", !info.users[0].in_use);
		T_EQ("unique id forgotten", (long)info.users[0].unique_id, 0L);
		T_EQ("port told once", s_clear_user_calls, 1);
		T_EQ("user index forwarded", s_clear_user_index, 1u);

		/* 0xFFFE: every user, and every credential under them. */
		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);
		info.users[0].in_use = true;
		info.users[MATTER_DL_USERS_MAX - 1u].in_use = true;
		flen = build_clear_user_fields(fields, sizeof(fields), true, MATTER_DL_INDEX_ALL);
		T_EQ("all users cleared",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_USER, fields,
				 flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_OK("first slot emptied", !info.users[0].in_use);
		T_OK("last slot emptied", !info.users[MATTER_DL_USERS_MAX - 1u].in_use);
		T_EQ("wildcard forwarded", s_clear_user_index, MATTER_DL_INDEX_ALL);

		/* Out of range on both ends, exactly as SetUser refuses them. */
		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);
		flen = build_clear_user_fields(fields, sizeof(fields), true, 0u);
		T_EQ("index 0 is refused",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_USER, fields,
				 flen, NULL),
		     MATTER_IM_STATUS_INVALID_COMMAND);
		flen = build_clear_user_fields(fields, sizeof(fields), true,
					       MATTER_DL_USERS_MAX + 1u);
		T_EQ("one past the table is refused",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_USER, fields,
				 flen, NULL),
		     MATTER_IM_STATUS_INVALID_COMMAND);
		T_EQ("no index at all is refused",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_USER, NULL, 0u,
				 NULL),
		     MATTER_IM_STATUS_INVALID_COMMAND);
		T_EQ("port never told", s_clear_user_calls, 0);
	}

	t_group("a real controller's bytes decode to the same three calls");
	{
		/*
		 * Captured from the Matter SDK itself (python home-assistant-chip-clusters
		 * 2025.7.0, DoorLock.Commands.*.ToTLV()), not written by hand here, because
		 * every other case in this file encodes the arguments with the same
		 * TAG_ constants the decoder reads them back with -- so a tag numbered
		 * wrong would agree with itself and pass. These are the field bytes a
		 * commissioner actually puts on the wire.
		 */
		static const uint8_t sdk_set_cred[] = {
			0x15, 0x24, 0x00, 0x00, 0x35, 0x01, 0x24, 0x00, 0x07, 0x24, 0x01, 0x09,
			0x18, 0x30, 0x02, 0x41, 0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42,
			0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d,
			0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
			0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
			0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
			0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5, 0x24, 0x03, 0x05,
			0x24, 0x04, 0x01, 0x24, 0x05, 0x00, 0x18,
		};
		static const uint8_t sdk_clear_cred[] = {
			0x15, 0x35, 0x00, 0x24, 0x00, 0x07, 0x24, 0x01, 0x09, 0x18, 0x18,
		};
		static const uint8_t sdk_clear_user[] = { 0x15, 0x24, 0x00, 0x05, 0x18 };

		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);

		T_EQ("SetCredential accepted",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_SET_CREDENTIAL,
				 sdk_set_cred, sizeof(sdk_set_cred), NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("stored once", s_cred_calls, 1);
		T_EQ("as an evictable endpoint key", s_cred_type,
		     MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT);
		T_EQ("under the index the controller named", s_cred_index, 9);
		T_EQ("bound to the user it named", s_cred_user, 5);
		T_EQ("key kept whole", (long)s_cred_key[0], 0x04L);
		T_EQ("to its last byte", (long)s_cred_key[MATTER_ALIRO_VERIFICATION_KEY_LEN - 1u],
		     0xF5L);

		T_EQ("ClearCredential accepted",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_CREDENTIAL,
				 sdk_clear_cred, sizeof(sdk_clear_cred), NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("removal asked for once", s_clear_cred_calls, 1);
		T_EQ("of the same type", s_clear_cred_type,
		     MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT);
		T_EQ("and the same index", s_clear_cred_index, 9);

		T_EQ("ClearUser accepted",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_CLEAR_USER,
				 sdk_clear_user, sizeof(sdk_clear_user), NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("forwarded once", s_clear_user_calls, 1);
		T_EQ("naming the same user", s_clear_user_index, 5);
	}

	t_group("resume brings Thread back without a commissioner");
	{
		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);

		T_EQ("a null device cannot resume", matter_clusters_resume(NULL), MATTER_E_STATE);
		T_EQ("no stored dataset means nothing to resume", matter_clusters_resume(&info),
		     MATTER_E_STATE);
		T_OK("and Thread was never started", !info.thread_started);

		/* A dataset that the stack accepts. */
		test_matter_thread_stub_reset();
		info.thread_dataset_len = 16u;
		memset(info.thread_dataset, 0x5Au, info.thread_dataset_len);
		T_EQ("resume starts Thread", matter_clusters_resume(&info), MATTER_OK);
		T_OK("and records that it did", info.thread_started);
		T_EQ("the stack was started once", g_thread_start_calls, 1);
		T_EQ("with the stored dataset", (long)g_thread_last_len, 16L);
		T_OK("verbatim", memcmp(g_thread_last_dataset, info.thread_dataset, 16u) == 0);

		/* A stack that refuses the dataset must not leave the node believing
		 * it is on the network. */
		test_matter_thread_stub_reset();
		info.thread_started = false;
		g_thread_start_fail = 1;
		T_EQ("a refused dataset fails the resume", matter_clusters_resume(&info),
		     MATTER_E_STATE);
		T_OK("and Thread is not claimed to be up", !info.thread_started);
		g_thread_start_fail = 0;
	}

	t_group("a second admin does not knock this node off Thread");
	{
		/*
		 * The failure this pins, measured on hardware 2026-08-07: a
		 * second administrator sends AddOrUpdateThreadNetwork carrying
		 * the dataset of the network the node is ALREADY on. Restarting
		 * the stack detached it for 20+ s, the BLE commissioning link
		 * timed out during the silence, and commissioning died after
		 * AddNOC had already succeeded.
		 */
		static const uint8_t k_xpanid[MATTER_THREAD_XPANID_LEN] = {
			0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
		};
		uint8_t ds[] = {
			0x0e, 0x08, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x03, 0x00, 0x00, 0x19,
			0x35, 0x06, 0x00, 0x04, 0x00, 0x1f, 0xff, 0xe0,
			0x02, 0x08, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
			0x05, 0x10, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0x03, 0x04, 'h',  'o',  'm',  'e',
			0x01, 0x02, 0x12, 0x34,
			0x07, 0x08, 0xfd, 0x00, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x04, 0x10, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
			0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
			0x0c, 0x04, 0x02, 0xa0, 0xff, 0xf8,
		};
		uint8_t candidate[sizeof(ds)];
		uint8_t fields[256];
		size_t flen = 0u;
		struct matter_tlv_writer w;

		matter_tlv_writer_init(&w, fields, sizeof(fields));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(0u), ds, sizeof(ds));
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &flen);

		/* Already attached to exactly this network: no restart. */
		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);
		info.attempt.active = true;
		info.fabrics[0].index = 1u;
		info.committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
		memcpy(info.thread_dataset, ds, sizeof(ds));
		info.thread_dataset_len = sizeof(ds);
		memcpy(info.thread_xpanid, k_xpanid, sizeof(k_xpanid));
		info.have_thread_xpanid = true;
		test_matter_thread_stub_reset();
		g_thread_attached_to = 1;
		T_EQ("the dataset is accepted",
		     run_root_command(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
				      MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK, fields, flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("the stack is NOT restarted", g_thread_start_calls, 0);
		T_OK("the dataset is staged", info.attempt.have_thread_candidate);
		T_EQ("attachment is not touched before ConnectNetwork",
		     g_thread_attached_to_calls, 0);

		/* A second controller may carry a newer timestamp or even stale
		 * credentials for the same Extended PAN ID. Accept the network
		 * identity but retain the dataset that already keeps the lock
		 * reachable. */
		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);
		info.attempt.active = true;
		info.fabrics[0].index = 1u;
		info.committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
		memcpy(info.thread_dataset, ds, sizeof(ds));
		info.thread_dataset_len = sizeof(ds);
		memcpy(info.thread_xpanid, k_xpanid, sizeof(k_xpanid));
		info.have_thread_xpanid = true;
		test_matter_thread_stub_reset();
		memcpy(candidate, ds, sizeof(candidate));
		for (size_t i = 0u; i + 2u <= sizeof(candidate);) {
			size_t len = candidate[i + 1u];

			if (candidate[i] == 0x05u) {
				candidate[i + 2u] ^= 1u;
				break;
			}
			i += 2u + len;
		}
		matter_tlv_writer_init(&w, fields, sizeof(fields));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(0u), candidate,
					   sizeof(candidate));
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &flen);
		T_EQ("same-network credentials are answered",
		     run_root_command(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
				      MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK, fields, flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("and accepted", info.last_network_status, MATTER_NC_STATUS_SUCCESS);
		T_OK("while the committed dataset wins",
		     info.attempt.thread_dataset_len == sizeof(ds) &&
			     memcmp(info.attempt.thread_dataset, ds, sizeof(ds)) == 0);
		T_EQ("the stack is untouched", g_thread_start_calls, 0);

		/* A genuinely different Extended PAN ID is a migration request.
		 * Multi-admin commissioning must reject it without moving the lock. */
		memcpy(candidate, ds, sizeof(candidate));
		for (size_t i = 0u; i + 2u <= sizeof(candidate);) {
			size_t len = candidate[i + 1u];

			if (candidate[i] == 0x02u) {
				candidate[i + 2u] ^= 1u;
				break;
			}
			i += 2u + len;
		}
		matter_tlv_writer_init(&w, fields, sizeof(fields));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(0u), candidate,
					   sizeof(candidate));
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &flen);
		T_EQ("a different network is answered",
		     run_root_command(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
				      MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK, fields, flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("and rejected without moving the lock", info.last_network_status,
		     MATTER_NC_STATUS_BOUNDS_EXCEEDED);
		T_EQ("the stack is still untouched", g_thread_start_calls, 0);

		/*
		 * A dataset with no Extended PAN ID cannot be compared against
		 * anything, so the guard must not fire on it: unknown falls back
		 * to the restart, which is always correct if slower.
		 */
		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);
		info.attempt.active = true;
		test_matter_thread_stub_reset();
		g_thread_attached_to = 1; /* would skip, if it were ever asked */
		matter_tlv_writer_init(&w, fields, sizeof(fields));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(0u), ds, 5u); /* timestamp fragment */
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &flen);
		T_EQ("a dataset without an ext PAN id is answered",
		     run_root_command(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
				      MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK, fields, flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("as malformed", info.last_network_status, MATTER_NC_STATUS_OUT_OF_RANGE);
		T_EQ("and the stack remains untouched", g_thread_start_calls, 0);
	}

	t_group("RemoveFabric frees the slot it names and only that slot");
	{
		/*
		 * The failure this pins, measured on hardware 2026-08-07: two
		 * commissioning attempts died mid-flight and left their fabrics
		 * behind, the table filled, and the next AddTrustedRootCertificate
		 * answered RESOURCE_EXHAUSTED with no way to make room short of a
		 * factory wipe. RemoveFabric is that way.
		 */
		uint8_t fields[16];
		size_t flen = 0u;
		uint32_t resp = 0u;
		struct matter_tlv_writer w;
		char expect_name[MATTER_INSTANCE_NAME_LEN];
		size_t i;

		reset_doubles();
		fill_info(&info);
		matter_clusters_init(&srv, &info);
		test_matter_thread_stub_reset();
		for (i = 0u; i < 3u; i++) {
			info.fabrics[i].index = (uint8_t)(i + 1u);
			info.fabrics[i].have_root = true;
			info.fabrics[i].fabric_id = 0x1000u + i;
			info.fabrics[i].node_id = 0x2000u + i;
			info.fabrics[i].noc_len = 1u;
			/* An uncompressed-point root, or the compressed-fabric
			 * derivation behind the instance name refuses it. */
			pattern(info.fabrics[i].root_public_key,
				sizeof(info.fabrics[i].root_public_key), (uint8_t)(0x40u + i));
			info.fabrics[i].root_public_key[0] = 0x04u;
		}
		info.committed_slots = MATTER_FABRIC_SLOT_BIT(0u) |
				       MATTER_FABRIC_SLOT_BIT(1u) |
				       MATTER_FABRIC_SLOT_BIT(2u);
		info.fabrics[0].case_admin_subject = UINT64_C(0xFFFFFFFD27730001);
		info.accessing_fabric_index = 1u;
		info.accessing_node_id = UINT64_C(0x804B5E16);
		info.accessing_cats[0] = UINT32_C(0x27730002);
		info.accessing_cat_count = 1u;
		/* Slot 2 owns the shared intermediate-certificate area. */
		info.icac.owner_index = 2u;
		info.icac.len = 100u;
		/* Computed BEFORE the removal wipes the inputs it derives from. */
		T_EQ("instance name derivable",
		     matter_fabric_instance_name(&info.fabrics[1], expect_name,
						 sizeof(expect_name)),
		     MATTER_OK);

		matter_tlv_writer_init(&w, fields, sizeof(fields));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0u), 2u);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &flen);

		info.accessing_cats[0] = UINT32_C(0x27720002);
		T_EQ("a different CAT identifier is refused",
		     run_root_command(&srv, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
				      MATTER_CMD_OC_REMOVE_FABRIC, fields, flen, &resp),
		     MATTER_IM_STATUS_UNSUPPORTED_ACCESS);
		T_EQ("the target survives the wrong CAT", info.fabrics[1].index, 2u);
		info.accessing_cats[0] = UINT32_C(0x27730000);
		T_EQ("an older CAT version is refused",
		     run_root_command(&srv, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
				      MATTER_CMD_OC_REMOVE_FABRIC, fields, flen, &resp),
		     MATTER_IM_STATUS_UNSUPPORTED_ACCESS);
		T_EQ("the target survives the old CAT", info.fabrics[1].index, 2u);
		info.accessing_cats[0] = UINT32_C(0x27730002);

		/* No fail-safe armed on purpose: removal is administration, not
		 * commissioning, and chip-tool's remove-fabric arms none. */
		T_EQ("the command runs without a fail-safe",
		     run_root_command(&srv, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
				      MATTER_CMD_OC_REMOVE_FABRIC, fields, flen, &resp),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("answered with NOCResponse", (long)resp, (long)MATTER_CMD_OC_NOC_RESPONSE);
		T_EQ("status OK", info.last_noc_status, MATTER_NOC_STATUS_OK);
		T_EQ("naming the removed index", info.last_noc_index, 2u);
		T_EQ("the slot is empty", info.fabrics[1].index, 0u);
		T_OK("and holds nothing else", !info.fabrics[1].have_root &&
		     info.fabrics[1].noc_len == 0u);
		T_EQ("its neighbours are untouched", info.fabrics[0].index, 1u);
		T_EQ("both of them", info.fabrics[2].index, 3u);
		T_EQ("the ICAC area it owned is freed", (long)info.icac.len, 0L);
		T_EQ("and disowned", info.icac.owner_index, 0u);
		T_EQ("its SRP record is withdrawn", g_thread_unadvertise_calls, 1);
		T_OK("by the removed fabric's own instance name",
		     strcmp(g_thread_last_unadvertised, expect_name) == 0);

		/* The index just removed no longer exists: the verdict arrives
		 * in the NOCResponse, not as a bare IM status. */
		resp = 0u;
		T_EQ("removing it again still answers",
		     run_root_command(&srv, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
				      MATTER_CMD_OC_REMOVE_FABRIC, fields, flen, &resp),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("with NOCResponse", (long)resp, (long)MATTER_CMD_OC_NOC_RESPONSE);
		T_EQ("saying the index is invalid", info.last_noc_status,
		     MATTER_NOC_STATUS_INVALID_FABRIC_INDEX);
		T_EQ("and the survivors still stand", info.fabrics[0].index, 1u);

		/* Index 0 is what EMPTY slots hold; asking to remove it must not
		 * match one of them. */
		matter_tlv_writer_init(&w, fields, sizeof(fields));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0u), 0u);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &flen);
		T_EQ("index 0 answers",
		     run_root_command(&srv, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
				      MATTER_CMD_OC_REMOVE_FABRIC, fields, flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("as invalid, not as a match on an empty slot", info.last_noc_status,
		     MATTER_NOC_STATUS_INVALID_FABRIC_INDEX);
		T_EQ("and no removal ever withdrew a record it did not remove",
		     g_thread_unadvertise_calls, 1);

		/* A command with no FabricIndex at all is malformed. */
		T_EQ("a missing index is INVALID_COMMAND",
		     run_root_command(&srv, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
				      MATTER_CMD_OC_REMOVE_FABRIC, NULL, 0u, NULL),
		     MATTER_IM_STATUS_INVALID_COMMAND);
	}
}
