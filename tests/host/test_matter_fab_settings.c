/*
 * Host test for ports/zephyr/store/matter_fab_settings.c — the FIRST host
 * coverage any file under firmware has had.
 *
 * That gap is why this exists. Every defect this port has hit on hardware lived
 * in the Zephyr glue, never in the ultrawidelock_matter protocol modules (which are 14/14
 * covered), and the glue was never compiled by anything but a developer's local
 * `make cdk-*`. This compiles the REAL source unmodified against the Zephyr KV
 * backend over a fake settings store, so what passes is the code that ships.
 *
 * What it can and cannot prove: the fake is an in-RAM key/value store, so
 * nothing here says anything about NVS durability, wear or garbage collection.
 * What it does prove is the branch logic around failure — and one failure in
 * particular, the TORN WRITE, which is otherwise only reachable by cutting power
 * to a real board between two of seven persistent writes.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/settings/settings.h>

#include "matter_fab_settings.h"
#include "settingsfake.h"
#include "test.h"
#include "ultrawidelock_kv.h"
#include "ultrawidelock_prov.h"

#define K_META ULTRAWIDELOCK_KV_KEY_MATTER_MF2_META
#define K_FAB0 (ULTRAWIDELOCK_KV_KEY_MATTER_MF2_FAB0 + 0u)
#define K_FAB1 (ULTRAWIDELOCK_KV_KEY_MATTER_MF2_FAB0 + 1u)
#define K_ACL0 (ULTRAWIDELOCK_KV_KEY_MATTER_MF2_ACL0 + 0u)
#define K_ACL1 (ULTRAWIDELOCK_KV_KEY_MATTER_MF2_ACL0 + 1u)
#define K_NET  ULTRAWIDELOCK_KV_KEY_MATTER_MF2_NET
#define K_ICAC ULTRAWIDELOCK_KV_KEY_MATTER_MF2_ICAC
#if MATTER_FEATURE_CLIENT
#define K_BIND ULTRAWIDELOCK_KV_KEY_MATTER_MF2_BINDING
#endif
#define K_USERS ULTRAWIDELOCK_KV_KEY_MATTER_MF2_USERS

static bool kv_has(uint16_t key)
{
	size_t len = 0u;

	return ultrawidelock_kv_get(key, NULL, &len) == ULTRAWIDELOCK_KV_OK;
}

/* Corruption is deliberately injected below the seam. name_of() is already
 * pinned exhaustively by test_kv_zephyr.c; this helper only reaches the fake's
 * stored bytes after addressing the record by its public numeric key. */
static bool kv_corrupt(uint16_t key)
{
	char name[9];

	(void)snprintf(name, sizeof(name), "uwl/%04x", (unsigned int)key);
	return settingsfake_corrupt(name);
}

static void fill_identity(struct matter_device_info *info)
{
	memset(info, 0, sizeof(*info));

	info->fabrics[0].index = 1u;
	info->fabrics[0].have_root = true;
	info->fabrics[0].fabric_id = 0x1122334455667788ULL;
	info->fabrics[0].node_id = 0x99AABBCCDDEEFF00ULL;

	info->fabrics[1].index = 2u;
	info->fabrics[1].have_root = true;
	info->fabrics[1].fabric_id = 0xAAAABBBBCCCCDDDDULL;
	info->fabrics[1].node_id = 0x0011223344556677ULL;
	info->fabric_acls[0].len = 3u;
	memcpy(info->fabric_acls[0].data, "one", 3u);
	info->fabric_acls[1].len = 3u;
	memcpy(info->fabric_acls[1].data, "two", 3u);

	info->thread_dataset_len = 32u;
	for (size_t i = 0; i < info->thread_dataset_len; i++) {
		info->thread_dataset[i] = (uint8_t)(0x40u + i);
	}
	info->have_thread_xpanid = true;
	memcpy(info->thread_xpanid, "\xde\xad\x00\xbe\xef\x00\xca\xfe", 8);
}

static int store_identity(struct matter_device_info *info)
{
	struct matter_device_info empty;
	int rc;

	memset(&empty, 0, sizeof(empty));
	(void)matter_fab_load(&empty);
	info->attempt.have_thread_candidate = true;
	info->attempt.thread_dataset_len = info->thread_dataset_len;
	memcpy(info->attempt.thread_dataset, info->thread_dataset, info->thread_dataset_len);
	memcpy(info->attempt.thread_xpanid, info->thread_xpanid, MATTER_THREAD_XPANID_LEN);
	info->committed_slots = 0u;
	rc = matter_fab_commit(info, MATTER_FABRIC_STORE_COMMIT_ATTEMPT, 0u, NULL, 0u);
	if (rc != 0) {
		return rc;
	}
	info->committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
	info->attempt.have_thread_candidate = false;
	rc = matter_fab_commit(info, MATTER_FABRIC_STORE_COMMIT_ATTEMPT, 1u, NULL, 0u);
	info->committed_slots |= MATTER_FABRIC_SLOT_BIT(1u);
	return rc;
}

void test_matter_fab_settings(void)
{
	struct matter_device_info stored;
	struct matter_device_info loaded;
	int rc;

	t_group("matter_fab_settings: round trip");
	settingsfake_reset();
	fill_identity(&stored);

	rc = store_identity(&stored);
	T_EQ("store succeeds", rc, 0);
#if MATTER_FEATURE_CLIENT
	stored.binding.count = 1u;
	stored.binding.e[0].fabric_index = 1u;
	stored.binding.e[0].node_id = 0x0123456789abcdefULL;
	stored.binding.e[0].has_node = true;
	T_EQ("binding table store succeeds",
	     matter_fab_commit(&stored, MATTER_FABRIC_STORE_BINDING, 0u, NULL, 0u), 0);
	T_OK("binding table has its own key", kv_has(K_BIND));
#endif
	T_OK("epoch key written", kv_has(K_META));
	T_OK("fabric 0 written", kv_has(K_FAB0));
	T_OK("fabric 1 written", kv_has(K_FAB1));
	T_OK("dataset written before the first fabric", kv_has(K_NET));
	T_OK("ACLs are scoped per fabric", kv_has(K_ACL0) && kv_has(K_ACL1));

	memset(&loaded, 0, sizeof(loaded));
	rc = matter_fab_load(&loaded);
	T_EQ("load reports a restored record", rc, 0);
	T_EQ("fabric 0 index survives", loaded.fabrics[0].index, 1);
	T_EQ("fabric 1 index survives", loaded.fabrics[1].index, 2);
	T_EQ("dataset length survives", loaded.thread_dataset_len, 32);
	T_OK("dataset bytes survive",
	     memcmp(loaded.thread_dataset, stored.thread_dataset, 32) == 0);
	T_OK("xpanid survives", loaded.have_thread_xpanid &&
				       memcmp(loaded.thread_xpanid, stored.thread_xpanid, 8) == 0);
	T_OK("a restored record marks its fabrics committed", loaded.committed_slots != 0u);
	T_OK("fabric ACLs survive independently",
	     loaded.fabric_acls[0].len == 3u && loaded.fabric_acls[1].len == 3u &&
		     memcmp(loaded.fabric_acls[0].data, "one", 3u) == 0 &&
		     memcmp(loaded.fabric_acls[1].data, "two", 3u) == 0);
#if MATTER_FEATURE_CLIENT
	T_OK("binding table survives on its fabric",
	     loaded.binding.count == 1u && loaded.binding.e[0].fabric_index == 1u &&
		     loaded.binding.e[0].node_id == 0x0123456789abcdefULL &&
		     loaded.binding.e[0].has_node);
#endif

	/*
	 * Found on hardware: the table was RAM only. A controller that wrote a
	 * user, then read an empty slot after the node reset, sent RemoveFabric.
	 */
	t_group("matter_fab_settings: the user table survives a reset");
	settingsfake_reset();
	fill_identity(&stored);
	T_EQ("identity stored for the user table", store_identity(&stored), 0);
	stored.users[0].in_use = true;
	stored.users[0].unique_id = 0xA1B2C3D4u;
	stored.users[0].status = 1u;
	stored.users[0].type = 2u;
	stored.users[0].credential_rule = 1u;
	stored.users[0].creator_fabric = 1u;
	stored.users[0].modifier_fabric = 2u;
	stored.users[MATTER_DL_USERS_MAX - 1u].in_use = true;
	stored.users[MATTER_DL_USERS_MAX - 1u].unique_id = 7u;
	T_EQ("user table store succeeds",
	     matter_fab_commit(&stored, MATTER_FABRIC_STORE_USERS, 0u, NULL, 0u), 0);
	T_OK("user table has its own key", kv_has(K_USERS));
	memset(&loaded, 0, sizeof(loaded));
	T_EQ("identity reloads with it", matter_fab_load(&loaded), 0);
	T_OK("the first row survives field for field",
	     loaded.users[0].in_use && loaded.users[0].unique_id == 0xA1B2C3D4u &&
		     loaded.users[0].status == 1u && loaded.users[0].type == 2u &&
		     loaded.users[0].credential_rule == 1u &&
		     loaded.users[0].creator_fabric == 1u &&
		     loaded.users[0].modifier_fabric == 2u);
	T_OK("the last row survives",
	     loaded.users[MATTER_DL_USERS_MAX - 1u].in_use &&
		     loaded.users[MATTER_DL_USERS_MAX - 1u].unique_id == 7u);
	T_OK("a row nobody wrote stays empty", !loaded.users[1].in_use);

	/* An emptied table is a state, not an absence: the old rows must not
	 * come back because nothing newer was written over them. */
	memset(stored.users, 0, sizeof(stored.users));
	T_EQ("emptied user table store succeeds",
	     matter_fab_commit(&stored, MATTER_FABRIC_STORE_USERS, 0u, NULL, 0u), 0);
	memset(&loaded, 0, sizeof(loaded));
	T_EQ("identity reloads after the clear", matter_fab_load(&loaded), 0);
	T_OK("a cleared user stays cleared", !loaded.users[0].in_use &&
						     !loaded.users[MATTER_DL_USERS_MAX - 1u].in_use);

	t_group("matter_fab_settings: a damaged user table costs the users, not the fabrics");
	stored.users[0].in_use = true;
	T_EQ("user table stored for corruption",
	     matter_fab_commit(&stored, MATTER_FABRIC_STORE_USERS, 0u, NULL, 0u), 0);
	T_OK("user table corrupted", kv_corrupt(K_USERS));
	memset(&loaded, 0, sizeof(loaded));
	T_EQ("the identity still loads", matter_fab_load(&loaded), 0);
	T_EQ("both fabrics survive", loaded.fabrics[0].index + loaded.fabrics[1].index, 3);
	T_OK("and no damaged row is presented", !loaded.users[0].in_use);

	/*
	 * The record outlives the fabrics in flash: removing the last
	 * administrator tombstones the fabric, not the table. Nothing may read
	 * it back, and the next home's first commit has to replace it.
	 */
	t_group("matter_fab_settings: a new home does not inherit the last one's users");
	settingsfake_reset();
	fill_identity(&stored);
	T_EQ("first home stored", store_identity(&stored), 0);
	stored.users[4].in_use = true;
	stored.users[4].unique_id = 0x0DDBA11u;
	T_EQ("first home's user stored",
	     matter_fab_commit(&stored, MATTER_FABRIC_STORE_USERS, 0u, NULL, 0u), 0);
	T_EQ("one administrator removed",
	     matter_fab_commit(&stored, MATTER_FABRIC_STORE_REMOVE, 1u, NULL, 0u), 0);
	memset(&loaded, 0, sizeof(loaded));
	T_EQ("the survivor loads", matter_fab_load(&loaded), 0);
	T_OK("and still has the user", loaded.users[4].in_use);
	T_EQ("last administrator removed",
	     matter_fab_commit(&stored, MATTER_FABRIC_STORE_REMOVE, 0u, NULL, 0u), 0);
	memset(&loaded, 0, sizeof(loaded));
	loaded.users[4].in_use = true;
	T_EQ("nothing is left to load", matter_fab_load(&loaded), 1);
	T_OK("and no user is presented without a fabric", !loaded.users[4].in_use);
	fill_identity(&stored);
	T_EQ("second home stored", store_identity(&stored), 0);
	memset(&loaded, 0, sizeof(loaded));
	T_EQ("second home loads", matter_fab_load(&loaded), 0);
	T_OK("without the first home's user", !loaded.users[4].in_use);

	t_group("matter_fab_settings: nothing stored");
	settingsfake_reset();
	memset(&loaded, 0, sizeof(loaded));
	rc = matter_fab_load(&loaded);
	T_EQ("load reports an empty store", rc, 1);
	T_OK("and claims no commissioning", loaded.committed_slots == 0u);

	/*
	 * THE ONE THAT MATTERS.
	 *
	 * Network and ACL prerequisites may land first, but the per-slot fabric
	 * record is the authority commit. Losing power before it cannot create a
	 * half identity.
	 */
	t_group("matter_fab_settings: torn write");
	settingsfake_reset();
	fill_identity(&stored);
	memset(&loaded, 0, sizeof(loaded));
	(void)matter_fab_load(&loaded);
	settingsfake_fail_saves_after(3); /* meta + network + user table land */

	stored.attempt.have_thread_candidate = true;
	stored.attempt.thread_dataset_len = stored.thread_dataset_len;
	memcpy(stored.attempt.thread_dataset, stored.thread_dataset, stored.thread_dataset_len);
	memcpy(stored.attempt.thread_xpanid, stored.thread_xpanid, MATTER_THREAD_XPANID_LEN);
	stored.committed_slots = 0u;
	rc = matter_fab_commit(&stored, MATTER_FABRIC_STORE_COMMIT_ATTEMPT, 0u, NULL, 0u);
	T_OK("a torn store reports failure", rc != 0);
	T_EQ("and stopped before the authority record", settingsfake_save_count(), 3);

	settingsfake_fail_saves_after(-1);
	memset(&loaded, 0, sizeof(loaded));
	rc = matter_fab_load(&loaded);
	T_OK("a torn record does NOT restore as commissioned", loaded.committed_slots == 0u);
	T_OK("and no fabric is presented", loaded.fabrics[0].index == 0u &&
						  loaded.fabrics[1].index == 0u);

	t_group("matter_fab_settings: corruption is isolated to one fabric");
	settingsfake_reset();
	fill_identity(&stored);
	T_EQ("two fabrics stored for corruption", store_identity(&stored), 0);
	T_OK("second authority record corrupted", kv_corrupt(K_FAB1));
	memset(&loaded, 0, sizeof(loaded));
	T_EQ("the intact neighbour still loads", matter_fab_load(&loaded), 0);
	T_EQ("first fabric survives isolated corruption", loaded.fabrics[0].index, 1u);
	T_EQ("corrupt second fabric is discarded", loaded.fabrics[1].index, 0u);
	T_EQ("its ACL is not exposed without its identity", loaded.fabric_acls[1].len, 0u);

	t_group("matter_fab_settings: corrupt shared ICAC only discards its owner");
	settingsfake_reset();
	fill_identity(&stored);
	stored.fabrics[1].icac_len = 8u;
	stored.icac.owner_index = 2u;
	stored.icac.len = 8u;
	memcpy(stored.icac.buf, "testicac", 8u);
	T_EQ("two fabrics and an ICAC stored", store_identity(&stored), 0);
	T_OK("shared ICAC record corrupted", kv_corrupt(K_ICAC));
	memset(&loaded, 0, sizeof(loaded));
	T_EQ("the independent neighbour still loads", matter_fab_load(&loaded), 0);
	T_EQ("fabric without an ICAC survives", loaded.fabrics[0].index, 1u);
	T_EQ("fabric whose ICAC is corrupt is discarded", loaded.fabrics[1].index, 0u);
	T_EQ("corrupt ICAC bytes are not exposed", loaded.icac.len, 0u);
	T_EQ("the discarded fabric's ACL is also cleared", loaded.fabric_acls[1].len, 0u);

	t_group("matter_fab_settings: targeted tombstone preserves neighbours");
	settingsfake_reset();
	fill_identity(&stored);
	T_EQ("two fabrics stored", store_identity(&stored), 0);
	T_EQ("targeted remove is durable",
	     matter_fab_commit(&stored, MATTER_FABRIC_STORE_REMOVE, 1u, NULL, 0u), 0);
	memset(&loaded, 0, sizeof(loaded));
	T_EQ("survivor loads", matter_fab_load(&loaded), 0);
	T_EQ("first fabric survives", loaded.fabrics[0].index, 1u);
	T_EQ("removed fabric stays absent", loaded.fabrics[1].index, 0u);
	T_EQ("removed ACL cannot leak into the empty slot", loaded.fabric_acls[1].len, 0u);

	t_group("matter_fab_settings: erase");
	settingsfake_reset();
	fill_identity(&stored);
	T_EQ("store for erase", store_identity(&stored), 0);
	T_OK("keys exist before erase", settingsfake_key_count() > 0);
	settingsfake_fail_saves_after(0);
	T_OK("a torn erase reports failure", matter_fab_erase() != 0);
	settingsfake_fail_saves_after(-1);
	memset(&loaded, 0, sizeof(loaded));
	T_EQ("a torn erase leaves the old epoch authoritative", matter_fab_load(&loaded), 0);
	T_EQ("and the old fabric remains intact", loaded.fabrics[0].index, 1u);
	T_EQ("erase succeeds", matter_fab_erase(), 0);
	T_OK("the epoch tombstone remains", kv_has(K_META));

	memset(&loaded, 0, sizeof(loaded));
	T_EQ("load after erase reports an empty store", matter_fab_load(&loaded), 1);

	t_group("matter_fab_settings: v0.3 Matter identity is a clean break");
	settingsfake_reset();
	T_EQ("legacy numeric record injected",
	     ultrawidelock_kv_set(ULTRAWIDELOCK_KV_KEY_MATTER_FAB_SLOT0,
				  &stored.fabrics[0], sizeof(stored.fabrics[0])),
	     (long)ULTRAWIDELOCK_KV_OK);
	T_EQ("unowned legacy Zephyr record injected",
	     settings_save_one("mfab/f0", &stored.fabrics[0], sizeof(stored.fabrics[0])), 0);
	memset(&loaded, 0, sizeof(loaded));
	T_EQ("legacy identity is not loaded", matter_fab_load(&loaded), 1);
	T_EQ("no legacy fabric reaches RAM", loaded.fabrics[0].index, 0u);
	T_OK("owned legacy numeric key is reclaimed",
	     !kv_has(ULTRAWIDELOCK_KV_KEY_MATTER_FAB_SLOT0));
	T_OK("non-owned settings record is left alone", settingsfake_has("mfab/f0"));

	/*
	 * The two attributes a controller WRITES, which lived only in RAM until
	 * now: every reset silently undid whatever auto-lock timing and approach
	 * direction the home app had configured, and the app has no way to tell
	 * that apart from a lock that ignored the setting.
	 */
	t_group("matter_dl_attr: a write survives a reboot");
	settingsfake_reset();
	memset(&stored, 0, sizeof(stored));
	stored.auto_relock_time_s = 120u;
	stored.approach_direction = 0x05u;
	T_EQ("both changed values are stored", matter_dl_attr_store(&stored, 0u, 0x07u), 0);
	T_EQ("and each got its own key", settingsfake_key_count(), 2);
	T_OK("under keys of their own, not the identity's",
	     kv_has(ULTRAWIDELOCK_KV_KEY_MATTER_DL_AUTO_RELOCK) &&
		     kv_has(ULTRAWIDELOCK_KV_KEY_MATTER_DL_APPROACH));

	memset(&loaded, 0, sizeof(loaded));
	loaded.auto_relock_time_s = 999u;
	loaded.approach_direction = 0x07u;
	T_EQ("the load succeeds", matter_dl_attr_load(&loaded), 0);
	T_EQ("AutoRelockTime comes back", loaded.auto_relock_time_s, 120u);
	T_EQ("the approach direction comes back", loaded.approach_direction, 0x05u);

	t_group("matter_dl_attr: only what changed is written");
	settingsfake_reset();
	memset(&stored, 0, sizeof(stored));
	stored.auto_relock_time_s = 60u;
	stored.approach_direction = 0x07u;
	T_EQ("a store of two changes", matter_dl_attr_store(&stored, 0u, 0x00u), 0);
	T_EQ("costs two saves", settingsfake_save_count(), 2);
	T_EQ("re-writing the same values succeeds",
	     matter_dl_attr_store(&stored, 60u, 0x07u), 0);
	T_EQ("and costs no flash at all", settingsfake_save_count(), 2);

	stored.auto_relock_time_s = 0u;
	T_EQ("zero is a value, not an absence", matter_dl_attr_store(&stored, 60u, 0x07u), 0);
	T_EQ("so it is written", settingsfake_save_count(), 3);
	memset(&loaded, 0, sizeof(loaded));
	loaded.auto_relock_time_s = 999u;
	(void)matter_dl_attr_load(&loaded);
	T_EQ("and read back as zero", loaded.auto_relock_time_s, 0u);

	t_group("matter_dl_attr: nothing stored leaves the boot defaults alone");
	settingsfake_reset();
	memset(&loaded, 0, sizeof(loaded));
	loaded.auto_relock_time_s = 42u;
	loaded.approach_direction = 0x07u;
	T_EQ("an empty store still succeeds", matter_dl_attr_load(&loaded), 0);
	T_EQ("AutoRelockTime keeps the port's default", loaded.auto_relock_time_s, 42u);
	T_EQ("so does the approach direction", loaded.approach_direction, 0x07u);

	/*
	 * A store that refuses the write. The RAM value stands for this boot --
	 * the controller's write took effect and only its durability was lost --
	 * so the failure is reported and nothing is rolled back.
	 */
	t_group("matter_dl_attr: a full store is reported, not hidden");
	settingsfake_reset();
	memset(&stored, 0, sizeof(stored));
	stored.auto_relock_time_s = 30u;
	settingsfake_fail_saves_after(0);
	T_OK("a failed save is reported", matter_dl_attr_store(&stored, 0u, 0u) != 0);
	settingsfake_fail_saves_after(-1);
	T_EQ("and nothing was stored", settingsfake_key_count(), 0);

	t_group("matter_dl_attr: erase");
	settingsfake_reset();
	memset(&stored, 0, sizeof(stored));
	stored.auto_relock_time_s = 90u;
	stored.approach_direction = 0x01u;
	T_EQ("store for erase", matter_dl_attr_store(&stored, 0u, 0u), 0);
	T_EQ("erase succeeds", matter_dl_attr_erase(), 0);
	T_EQ("both keys are gone", settingsfake_key_count(), 0);

	t_group("matter_uwb_config: one durable record");
	settingsfake_reset();
	{
		const struct matter_uwb_config defaults = {
			.version = MATTER_UWB_CONFIG_VERSION,
			.policy_flags = MATTER_UWB_POLICY_ALL,
			.unlock_cm = 100u,
			.approach_cm = 180u,
			.relock_cm = 250u,
			.motor_ms = 500u,
		};
		struct matter_uwb_config changed = defaults;
		struct matter_uwb_config readback = { 0 };

		changed.unlock_cm = 90u;
		changed.motor_ms = 650u;
		T_EQ("changed settings store together",
		     matter_uwb_config_store(&changed, &defaults), 0);
		T_EQ("that costs one save", settingsfake_save_count(), 1);
		T_EQ("the settings load", matter_uwb_config_load(&readback), 0);
		T_OK("and all fields survive", memcmp(&readback, &changed, sizeof(readback)) == 0);
		T_EQ("re-storing the same block succeeds",
		     matter_uwb_config_store(&changed, &changed), 0);
		T_EQ("without another flash write", settingsfake_save_count(), 1);
	}

	settingsfake_reset();
	{
		const struct matter_uwb_config defaults = {
			.version = MATTER_UWB_CONFIG_VERSION,
			.policy_flags = MATTER_UWB_POLICY_ALL,
			.unlock_cm = 100u,
			.approach_cm = 180u,
			.relock_cm = 250u,
			.motor_ms = 500u,
		};
		struct matter_uwb_config legacy = defaults;
		struct matter_uwb_config readback = defaults;

		legacy.version = 1u;
		legacy.policy_flags = 0u;
		T_EQ("legacy UWB settings store", matter_uwb_config_store(&legacy, &defaults), 0);
		T_EQ("legacy UWB settings load", matter_uwb_config_load(&readback), 0);
		T_EQ("the old disabled departure relock stays disabled",
		     readback.policy_flags & MATTER_UWB_POLICY_BOUND_RELOCK, 0u);
		T_EQ("new policy actions default enabled",
		     readback.policy_flags,
		     MATTER_UWB_POLICY_ALL & (uint8_t)~MATTER_UWB_POLICY_BOUND_RELOCK);
	}

	/*
	 * And the two trees stay separate. A factory reset un-commissions the
	 * node; forgetting the owner's auto-lock timing is not part of that.
	 */
	t_group("matter_dl_attr: the identity erase leaves them alone");
	settingsfake_reset();
	fill_identity(&stored);
	stored.auto_relock_time_s = 75u;
	stored.approach_direction = 0x02u;
	T_EQ("identity stored", store_identity(&stored), 0);
	T_EQ("attributes stored", matter_dl_attr_store(&stored, 0u, 0u), 0);
	T_EQ("erasing the identity succeeds", matter_fab_erase(), 0);
	T_OK("and the attributes are still there",
	     kv_has(ULTRAWIDELOCK_KV_KEY_MATTER_DL_AUTO_RELOCK) &&
		     kv_has(ULTRAWIDELOCK_KV_KEY_MATTER_DL_APPROACH));

	memset(&loaded, 0, sizeof(loaded));
	(void)matter_dl_attr_load(&loaded);
	T_EQ("they still read back", loaded.auto_relock_time_s, 75u);
	T_EQ("both of them", loaded.approach_direction, 0x02u);
}

static void fill_provisioning(struct ultrawidelock_reader_identity *id,
			      struct ultrawidelock_trust_store *ts)
{
	memset(id, 0, sizeof(*id));
	memset(ts, 0, sizeof(*ts));
	for (size_t i = 0; i < sizeof(id->reader_id); i++) {
		id->reader_id[i] = (uint8_t)(0x10u + i);
		id->sign_priv[i] = (uint8_t)(0x80u + i);
	}
	memset(id->grk, 0x5a, sizeof(id->grk));
	id->is_dev = false;
	ts->count = 1u;
	ts->cred_pub[0][0] = 0x04u;
	memset(&ts->cred_pub[0][1], 0xa5, ULTRAWIDELOCK_CRED_PUB_LEN - 1u);
	ts->kp_valid = 1u;
	memset(ts->kpersistent[0], 0x3c, ULTRAWIDELOCK_KPERSISTENT_LEN);
	ts->cred_type[0] = 5u;
	ts->cred_index[0] = 0x1234u;
	ts->user_index[0] = 0x5678u;
}

static void test_ultrawidelock_prov_settings(void)
{
	struct ultrawidelock_reader_identity stored_id;
	struct ultrawidelock_reader_identity loaded_id;
	struct ultrawidelock_trust_store stored_ts;
	struct ultrawidelock_trust_store loaded_ts;
	uint8_t malformed[] = {'b', 'a', 'd'};
	uint8_t oversized[ULTRAWIDELOCK_PROV_BLOB_MAX + 1u] = {0};

	t_group("ultrawidelock_prov_settings: empty and sibling records");
	settingsfake_reset();
	memset(&loaded_id, 0, sizeof(loaded_id));
	memset(&loaded_ts, 0xff, sizeof(loaded_ts));
	T_EQ("empty store is distinct from storage failure",
	     ultrawidelock_prov_load(&loaded_id, &loaded_ts), ULTRAWIDELOCK_PROV_LOAD_EMPTY);
	T_OK("empty store exposes only marked recovery identity", loaded_id.is_dev);
	T_EQ("empty store exposes no trust anchors", loaded_ts.count, 0);
	/* The record is addressed by key now, so a foreign name cannot be mistaken
	 * for it the way a sibling under the old "ultrawidelock" subtree could. Kept
	 * as an assertion because the erase path still has to leave it alone. */
	T_EQ("an unrelated record can be stored",
	     settings_save_one("ultrawidelock/other", malformed, sizeof(malformed)), 0);
	T_EQ("an unrelated record is not treated as provisioning",
	     ultrawidelock_prov_load(&loaded_id, &loaded_ts), ULTRAWIDELOCK_PROV_LOAD_EMPTY);

	t_group("ultrawidelock_prov_settings: valid round trip");
	settingsfake_reset();
	fill_provisioning(&stored_id, &stored_ts);
	T_EQ("provisioning store succeeds", ultrawidelock_prov_store(&stored_id, &stored_ts), 0);
	memset(&loaded_id, 0, sizeof(loaded_id));
	memset(&loaded_ts, 0, sizeof(loaded_ts));
	T_EQ("stored provisioning loads", ultrawidelock_prov_load(&loaded_id, &loaded_ts), 0);
	T_OK("reader identity survives",
	     memcmp(loaded_id.reader_id, stored_id.reader_id, sizeof(stored_id.reader_id)) == 0 &&
		     memcmp(loaded_id.sign_priv, stored_id.sign_priv,
			    sizeof(stored_id.sign_priv)) == 0 &&
		     memcmp(loaded_id.grk, stored_id.grk, sizeof(stored_id.grk)) == 0 &&
		     !loaded_id.is_dev);
	T_OK("anchor and expedited key survive",
	     loaded_ts.count == 1u && loaded_ts.kp_valid == 1u &&
		     memcmp(loaded_ts.cred_pub[0], stored_ts.cred_pub[0],
			    ULTRAWIDELOCK_CRED_PUB_LEN) == 0 &&
		     memcmp(loaded_ts.kpersistent[0], stored_ts.kpersistent[0],
			    ULTRAWIDELOCK_KPERSISTENT_LEN) == 0);
	T_OK("Matter indices survive", loaded_ts.cred_type[0] == 5u &&
					 loaded_ts.cred_index[0] == 0x1234u &&
					 loaded_ts.user_index[0] == 0x5678u);

	t_group("ultrawidelock_prov_settings: corrupt storage fails closed");
	settingsfake_reset();
	/* Injected through the seam, not by spelling the derived name: the name
	 * kv_zephyr.c builds is pinned in test_kv_zephyr.c, and pinning it twice
	 * would make this suite fail for a reason that is not about provisioning. */
	T_EQ("malformed record can be injected",
	     ultrawidelock_kv_set(ULTRAWIDELOCK_KV_KEY_CRED_PROV, malformed, sizeof(malformed)),
	     (long)ULTRAWIDELOCK_KV_OK);
	memset(&loaded_id, 0, sizeof(loaded_id));
	memset(&loaded_ts, 0xff, sizeof(loaded_ts));
	T_EQ("malformed record is an explicit error",
	     ultrawidelock_prov_load(&loaded_id, &loaded_ts), -EBADMSG);
	T_OK("malformed record cannot expose production identity", loaded_id.is_dev);
	T_EQ("malformed record cannot expose trust anchors", loaded_ts.count, 0);
	settingsfake_reset();
	T_EQ("oversized record can be injected",
	     ultrawidelock_kv_set(ULTRAWIDELOCK_KV_KEY_CRED_PROV, oversized, sizeof(oversized)),
	     (long)ULTRAWIDELOCK_KV_OK);
	T_EQ("oversized record preserves handler errno",
	     ultrawidelock_prov_load(&loaded_id, &loaded_ts), -EINVAL);
	T_OK("oversized record remains fail-closed", loaded_id.is_dev && loaded_ts.count == 0u);

	t_group("ultrawidelock_prov_settings: write and erase failures surface");
	settingsfake_reset();
	settingsfake_fail_saves_after(0);
	T_EQ("full settings store is reported", ultrawidelock_prov_store(&stored_id, &stored_ts),
	     -ENOSPC);
	settingsfake_fail_saves_after(-1);
	T_EQ("erase succeeds", ultrawidelock_prov_erase(), 0);
	T_EQ("erase removes exact provisioning key", settingsfake_key_count(), 0);
}

void test_kv_zephyr(void); /* test_kv_zephyr.c, same stage, same fake */

int main(void)
{
	test_matter_fab_settings();
	test_ultrawidelock_prov_settings();
	test_kv_zephyr();

	if (t_fail > 0) {
		printf("  cdk-fab-settings: FAIL (%d of %d)\n", t_fail, t_fail + t_pass);
		return 1;
	}
	printf("  cdk-settings: PASS (%d checks — fake settings store, no NVS durability)\n",
	       t_pass);
	return 0;
}
