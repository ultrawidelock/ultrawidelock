/** @file test_ultrawidelock_prov.c — reader identity + trust store (de)serialisation KAT.
 *
 * Backs the `ultrawidelock-export` / `ultrawidelock-import` clone path: a blob written on one
 * board must round-trip byte-for-byte into the same identity + trust store on a
 * second board, and a malformed or wrong-version blob must be rejected, never
 * half-applied. Also locks the wire header so the format cannot drift silently.
 */
#include <string.h>

#include "ultrawidelock_prov.h"
#include "test.h"

/* A deterministic, fully-known non-dev identity + trust store to serialise. */
static void make_identity(struct ultrawidelock_reader_identity *id,
			  struct ultrawidelock_trust_store *ts)
{
	memset(id, 0, sizeof(*id));
	for (unsigned i = 0; i < ULTRAWIDELOCK_READER_ID_LEN; i++) {
		id->reader_id[i] = (uint8_t)i;
	}
	for (unsigned i = 0; i < ULTRAWIDELOCK_READER_PRIV_LEN; i++) {
		id->sign_priv[i] = (uint8_t)(0x20u + i);
	}
	for (unsigned i = 0; i < ULTRAWIDELOCK_GRK_LEN; i++) {
		id->grk[i] = (uint8_t)(0x40u + i);
	}
	id->is_dev = false;

	memset(ts, 0, sizeof(*ts));
	/* Two credentials; only the first carries a Kpersistent. */
	uint8_t a[ULTRAWIDELOCK_CRED_PUB_LEN];
	uint8_t b[ULTRAWIDELOCK_CRED_PUB_LEN];
	a[0] = 0x04u;
	b[0] = 0x04u;
	for (unsigned i = 1; i < ULTRAWIDELOCK_CRED_PUB_LEN; i++) {
		a[i] = (uint8_t)(0x50u + i);
		b[i] = (uint8_t)(0x90u + i);
	}
	T_EQ("add.a", ultrawidelock_prov_trust_add(ts, a), 0);
	T_EQ("add.b", ultrawidelock_prov_trust_add(ts, b), 0);
	uint8_t kp[ULTRAWIDELOCK_KPERSISTENT_LEN];
	memset(kp, 0xAB, sizeof(kp));
	T_EQ("kp.set",
	     ultrawidelock_prov_kpersistent_set(ts, ultrawidelock_prov_trust_find(ts, a), kp), 0);
	/* Both carry the Matter indices a SetCredential would have bound. */
	T_EQ("bind.a", ultrawidelock_prov_cred_bind_set(ts, 0, 7u, 11u, 3u), 0);
	T_EQ("bind.b", ultrawidelock_prov_cred_bind_set(ts, 1, 7u, 12u, 3u), 0);
}

/* A distinct, valid uncompressed point per seed. */
static void make_key(uint8_t out[ULTRAWIDELOCK_CRED_PUB_LEN], uint8_t seed)
{
	memset(out, 0, ULTRAWIDELOCK_CRED_PUB_LEN);
	out[0] = 0x04u;
	out[1] = seed;
}

void test_ultrawidelock_prov(void)
{
	t_group("dev default");
	struct ultrawidelock_reader_identity dev_id;
	struct ultrawidelock_trust_store dev_ts;
	ultrawidelock_prov_dev_default(&dev_id, &dev_ts);
	T_OK("dev.is_dev", dev_id.is_dev);
	T_EQ("dev.trust_empty", dev_ts.count, 0);
	/* dev identity round-trips (empty trust). */
	uint8_t db[ULTRAWIDELOCK_PROV_BLOB_MAX];
	size_t dn = 0;
	T_EQ("dev.serialize", ultrawidelock_prov_serialize(&dev_id, &dev_ts, db, sizeof(db), &dn), 0);
	struct ultrawidelock_reader_identity dev_id2;
	struct ultrawidelock_trust_store dev_ts2;
	T_EQ("dev.deserialize", ultrawidelock_prov_deserialize(db, dn, &dev_id2, &dev_ts2), 0);
	T_OK("dev.id_match", memcmp(&dev_id, &dev_id2, sizeof(dev_id)) == 0);
	T_OK("dev.ts_match", memcmp(&dev_ts, &dev_ts2, sizeof(dev_ts)) == 0);

	t_group("provisioned round-trip");
	struct ultrawidelock_reader_identity id;
	struct ultrawidelock_trust_store ts;
	make_identity(&id, &ts);
	uint8_t blob[ULTRAWIDELOCK_PROV_BLOB_MAX];
	size_t n = 0;
	T_EQ("serialize", ultrawidelock_prov_serialize(&id, &ts, blob, sizeof(blob), &n), 0);

	/* Wire header is locked: magic "APRV", version 5, flags 0 (not dev). */
	T_OK("hdr.magic", n >= 6 && memcmp(blob, "APRV", 4) == 0);
	T_EQ("hdr.version", blob[4], 5);
	T_EQ("hdr.flags_notdev", blob[5], 0);
	/* Exact length for 2 anchors, both with a kpersistent row, a 5-byte
	 * (type, credential index, user index) binding and a 1-byte issuer
	 * binding, then the issuer count (0: no issuer installed here). */
	size_t want = 6u + ULTRAWIDELOCK_READER_ID_LEN + ULTRAWIDELOCK_READER_PRIV_LEN +
		      ULTRAWIDELOCK_GRK_LEN + 1u + 2u * ULTRAWIDELOCK_CRED_PUB_LEN + 1u +
		      2u * ULTRAWIDELOCK_KPERSISTENT_LEN + 2u * 5u + 2u * 1u + 1u;
	T_EQ("hdr.length", n, want);

	struct ultrawidelock_reader_identity id2;
	struct ultrawidelock_trust_store ts2;
	T_EQ("deserialize", ultrawidelock_prov_deserialize(blob, n, &id2, &ts2), 0);
	T_OK("id_match", memcmp(&id, &id2, sizeof(id)) == 0);
	T_OK("ts_match", memcmp(&ts, &ts2, sizeof(ts)) == 0);
	T_EQ("kp_valid", ts2.kp_valid, 0x01); /* only anchor 0 has a Kpersistent */

	t_group("serialize overflow");
	uint8_t small[8];
	T_EQ("too_small", ultrawidelock_prov_serialize(&id, &ts, small, sizeof(small), &n), -1);

	t_group("deserialize rejects");
	T_EQ("null", ultrawidelock_prov_deserialize(NULL, 10, &id2, &ts2), -1);
	T_EQ("short", ultrawidelock_prov_deserialize(blob, 4, &id2, &ts2), -1);
	uint8_t bad[ULTRAWIDELOCK_PROV_BLOB_MAX];
	memcpy(bad, blob, want);
	bad[0] = 'X'; /* corrupt magic */
	T_EQ("bad_magic", ultrawidelock_prov_deserialize(bad, want, &id2, &ts2), -1);
	memcpy(bad, blob, want);
	bad[4] = 0x09; /* unknown version */
	T_EQ("bad_version", ultrawidelock_prov_deserialize(bad, want, &id2, &ts2), -1);
	memcpy(bad, blob, want);
	T_EQ("trailing_byte", ultrawidelock_prov_deserialize(bad, want - 1u, &id2, &ts2), -1);
	/* count byte past ULTRAWIDELOCK_TRUST_MAX. Its offset = 6 + id + priv + grk. */
	memcpy(bad, blob, want);
	bad[6u + ULTRAWIDELOCK_READER_ID_LEN + ULTRAWIDELOCK_READER_PRIV_LEN +
	    ULTRAWIDELOCK_GRK_LEN] = 0xFF;
	T_EQ("count_overflow", ultrawidelock_prov_deserialize(bad, want, &id2, &ts2), -1);

	t_group("version back-compat");
	/* Hand-build a v1 blob (no grk, no kp tail), count=0. */
	uint8_t v1[6u + ULTRAWIDELOCK_READER_ID_LEN + ULTRAWIDELOCK_READER_PRIV_LEN + 1u];
	memcpy(v1, "APRV", 4);
	v1[4] = 0x01;
	v1[5] = 0x00;
	for (unsigned i = 0; i < ULTRAWIDELOCK_READER_ID_LEN; i++) {
		v1[6u + i] = (uint8_t)(0xA0u + i);
	}
	for (unsigned i = 0; i < ULTRAWIDELOCK_READER_PRIV_LEN; i++) {
		v1[6u + ULTRAWIDELOCK_READER_ID_LEN + i] = (uint8_t)(0xB0u + i);
	}
	v1[sizeof(v1) - 1u] = 0x00; /* count */
	T_EQ("v1.parse", ultrawidelock_prov_deserialize(v1, sizeof(v1), &id2, &ts2), 0);
	uint8_t zero_grk[ULTRAWIDELOCK_GRK_LEN] = { 0 };
	T_OK("v1.grk_zeroed", memcmp(id2.grk, zero_grk, ULTRAWIDELOCK_GRK_LEN) == 0);
	T_EQ("v1.no_trust", ts2.count, 0);

	/* v2 blob (grk, no kp tail), count=0. */
	uint8_t v2[6u + ULTRAWIDELOCK_READER_ID_LEN + ULTRAWIDELOCK_READER_PRIV_LEN +
		   ULTRAWIDELOCK_GRK_LEN + 1u];
	memcpy(v2, "APRV", 4);
	v2[4] = 0x02;
	v2[5] = 0x00;
	memset(v2 + 6, 0x11,
	       ULTRAWIDELOCK_READER_ID_LEN + ULTRAWIDELOCK_READER_PRIV_LEN + ULTRAWIDELOCK_GRK_LEN);
	v2[sizeof(v2) - 1u] = 0x00; /* count */
	T_EQ("v2.parse", ultrawidelock_prov_deserialize(v2, sizeof(v2), &id2, &ts2), 0);
	T_EQ("v2.no_trust", ts2.count, 0);

	/*
	 * A v3 blob with one anchor: the format every board provisioned before
	 * revocation existed is carrying. It must still parse, and its anchor
	 * must come back with no Matter index -- claiming one it never had is
	 * how a ClearCredential would revoke the wrong key.
	 */
	uint8_t v3[6u + ULTRAWIDELOCK_READER_ID_LEN + ULTRAWIDELOCK_READER_PRIV_LEN +
		   ULTRAWIDELOCK_GRK_LEN + 1u + ULTRAWIDELOCK_CRED_PUB_LEN + 1u +
		   ULTRAWIDELOCK_KPERSISTENT_LEN];
	size_t v3_count_off = 6u + ULTRAWIDELOCK_READER_ID_LEN + ULTRAWIDELOCK_READER_PRIV_LEN +
			      ULTRAWIDELOCK_GRK_LEN;

	memset(v3, 0x22, sizeof(v3));
	memcpy(v3, "APRV", 4);
	v3[4] = 0x03;
	v3[5] = 0x00;
	v3[v3_count_off] = 0x01;               /* count */
	v3[v3_count_off + 1u] = 0x04u;         /* cred_pub[0][0]: uncompressed point */
	v3[v3_count_off + 1u + ULTRAWIDELOCK_CRED_PUB_LEN] = 0x01u; /* kp_valid */
	T_EQ("v3.parse", ultrawidelock_prov_deserialize(v3, sizeof(v3), &id2, &ts2), 0);
	T_EQ("v3.one_anchor", ts2.count, 1);
	T_EQ("v3.kp_kept", ts2.kp_valid, 0x01);
	T_EQ("v3.no_cred_index", ts2.cred_index[0], ULTRAWIDELOCK_CRED_INDEX_NONE);
	T_EQ("v3.no_user_index", ts2.user_index[0], ULTRAWIDELOCK_CRED_INDEX_NONE);
	/* And an anchor with no index is not addressable by one. Asked with a real
	 * (type, index) pair, so the lookup runs the comparison against the parsed
	 * anchor instead of stopping at the "caller named no index" guard -- that
	 * guard would answer -1 for an addressable anchor too, and prove nothing. */
	T_EQ("v3.unaddressable", ultrawidelock_prov_find_cred_index(&ts2, 7u, 1u), -1);

	t_group("trust store logic");
	struct ultrawidelock_trust_store t3;
	memset(&t3, 0, sizeof(t3));
	uint8_t key[ULTRAWIDELOCK_CRED_PUB_LEN];
	memset(key, 0, sizeof(key));
	key[0] = 0x04u;
	key[1] = 0x77u;
	T_EQ("check.no_anchors", ultrawidelock_prov_trust_check(&t3, key), 1);
	T_EQ("add", ultrawidelock_prov_trust_add(&t3, key), 0);
	T_EQ("check.trusted", ultrawidelock_prov_trust_check(&t3, key), 0);
	T_EQ("add.dedup", ultrawidelock_prov_trust_add(&t3, key), 1);
	uint8_t other[ULTRAWIDELOCK_CRED_PUB_LEN];
	memset(other, 0, sizeof(other));
	other[0] = 0x04u;
	other[1] = 0x99u;
	T_EQ("check.rejected", ultrawidelock_prov_trust_check(&t3, other), -1);
	uint8_t notpoint[ULTRAWIDELOCK_CRED_PUB_LEN];
	memset(notpoint, 0x04, sizeof(notpoint));
	notpoint[0] = 0x02u; /* not an uncompressed point */
	T_EQ("add.not_point", ultrawidelock_prov_trust_add(&t3, notpoint), -1);

	/* Fill to ULTRAWIDELOCK_TRUST_MAX, then the next add reports full. */
	struct ultrawidelock_trust_store full;
	memset(&full, 0, sizeof(full));
	for (unsigned i = 0; i < ULTRAWIDELOCK_TRUST_MAX; i++) {
		uint8_t k[ULTRAWIDELOCK_CRED_PUB_LEN];
		memset(k, 0, sizeof(k));
		k[0] = 0x04u;
		k[1] = (uint8_t)(0x10u + i);
		T_EQ("fill.add", ultrawidelock_prov_trust_add(&full, k), 0);
	}
	uint8_t overflow[ULTRAWIDELOCK_CRED_PUB_LEN];
	memset(overflow, 0, sizeof(overflow));
	overflow[0] = 0x04u;
	overflow[1] = 0xEEu;
	/*
	 * A FULL STORE EVICTS, it does not refuse. Refusing locked a re-paired
	 * reader out permanently: stale anchors held every slot, the key the
	 * phone presented could never be added, and the unlock failed one step
	 * after the signature verified. 2 = added, something was dropped.
	 */
	T_EQ("fill.evicts", ultrawidelock_prov_trust_add(&full, overflow), 2);
	T_EQ("fill.count_held", (int)full.count, (int)ULTRAWIDELOCK_TRUST_MAX);
	T_EQ("fill.newest_present", ultrawidelock_prov_trust_check(&full, overflow), 0);

	/*
	 * A count past the array is the one case where eviction cannot free a
	 * slot, and cred_pub[count] would then be written off the end of the
	 * store. Nothing reachable produces it -- deserialize rejects it and add
	 * is the only thing that increments -- so this is the guard's only proof.
	 */
	struct ultrawidelock_trust_store corrupt;

	memset(&corrupt, 0, sizeof(corrupt));
	corrupt.count = (uint8_t)(ULTRAWIDELOCK_TRUST_MAX + 1u);
	T_EQ("add.corrupt_count", ultrawidelock_prov_trust_add(&corrupt, overflow), -1);
	T_EQ("add.corrupt_untouched", (int)corrupt.count, (int)ULTRAWIDELOCK_TRUST_MAX + 1);

	/* The victim is the OLDEST when nothing has a Kpersistent. */
	uint8_t oldest[ULTRAWIDELOCK_CRED_PUB_LEN];
	memset(oldest, 0, sizeof(oldest));
	oldest[0] = 0x04u;
	oldest[1] = 0x10u;
	T_EQ("fill.oldest_gone", ultrawidelock_prov_trust_check(&full, oldest), -1);

	/*
	 * A slot that has completed a standard phase outranks one that never
	 * has: Kpersistent only exists where a phone actually authenticated, so
	 * an unused slot is the cheaper thing to lose.
	 */
	struct ultrawidelock_trust_store used;
	memset(&used, 0, sizeof(used));
	for (unsigned i = 0; i < ULTRAWIDELOCK_TRUST_MAX; i++) {
		uint8_t k[ULTRAWIDELOCK_CRED_PUB_LEN];
		memset(k, 0, sizeof(k));
		k[0] = 0x04u;
		k[1] = (uint8_t)(0x40u + i);
		T_EQ("used.add", ultrawidelock_prov_trust_add(&used, k), 0);
	}
	/* Slot 0 has been used; slot 1 never has. */
	T_EQ("used.kp_set", ultrawidelock_prov_kpersistent_set(&used, 0, key), 0);
	uint8_t newcomer[ULTRAWIDELOCK_CRED_PUB_LEN];
	memset(newcomer, 0, sizeof(newcomer));
	newcomer[0] = 0x04u;
	newcomer[1] = 0xABu;
	T_EQ("used.evicts", ultrawidelock_prov_trust_add(&used, newcomer), 2);

	uint8_t kept[ULTRAWIDELOCK_CRED_PUB_LEN];
	memset(kept, 0, sizeof(kept));
	kept[0] = 0x04u;
	kept[1] = 0x40u; /* the one carrying a Kpersistent */
	T_EQ("used.kept_the_used_one", ultrawidelock_prov_trust_check(&used, kept), 0);

	uint8_t dropped[ULTRAWIDELOCK_CRED_PUB_LEN];
	memset(dropped, 0, sizeof(dropped));
	dropped[0] = 0x04u;
	dropped[1] = 0x41u; /* never used, so this is the victim */
	T_EQ("used.dropped_the_unused", ultrawidelock_prov_trust_check(&used, dropped), -1);

	T_EQ("kp.bad_idx", ultrawidelock_prov_kpersistent_set(&full, -1, key), -1);

	/*
	 * ---- revocation ---------------------------------------------------
	 *
	 * The lock could be told to add a credential and never to remove one, so
	 * a home key removed in the controller's UI kept opening the door. These
	 * cover the four things a removal has to be: effective, idempotent,
	 * slot-freeing, and taking its Kpersistent with it.
	 */
	t_group("revocation");
	struct ultrawidelock_trust_store rv;
	uint8_t k0[ULTRAWIDELOCK_CRED_PUB_LEN];
	uint8_t k1[ULTRAWIDELOCK_CRED_PUB_LEN];
	uint8_t k2[ULTRAWIDELOCK_CRED_PUB_LEN];
	uint8_t kp0[ULTRAWIDELOCK_KPERSISTENT_LEN];
	uint8_t kp2[ULTRAWIDELOCK_KPERSISTENT_LEN];

	memset(&rv, 0, sizeof(rv));
	make_key(k0, 0xA0u);
	make_key(k1, 0xA1u);
	make_key(k2, 0xA2u);
	memset(kp0, 0x70, sizeof(kp0));
	memset(kp2, 0x72, sizeof(kp2));
	T_EQ("rv.add0", ultrawidelock_prov_trust_add(&rv, k0), 0);
	T_EQ("rv.add1", ultrawidelock_prov_trust_add(&rv, k1), 0);
	T_EQ("rv.add2", ultrawidelock_prov_trust_add(&rv, k2), 0);
	T_EQ("rv.bind0", ultrawidelock_prov_cred_bind_set(&rv, 0, 7u, 21u, 5u), 0);
	T_EQ("rv.bind1", ultrawidelock_prov_cred_bind_set(&rv, 1, 7u, 22u, 5u), 0);
	T_EQ("rv.bind2", ultrawidelock_prov_cred_bind_set(&rv, 2, 8u, 23u, 6u), 0);
	T_EQ("rv.kp0", ultrawidelock_prov_kpersistent_set(&rv, 0, kp0), 0);
	T_EQ("rv.kp2", ultrawidelock_prov_kpersistent_set(&rv, 2, kp2), 0);
	T_EQ("rv.kp_valid_before", rv.kp_valid, 0x05); /* slots 0 and 2 */

	/* An admin names a credential by index; nothing else identifies it. */
	T_EQ("rv.find_index", ultrawidelock_prov_find_cred_index(&rv, 7u, 21u), 0);
	T_EQ("rv.find_index_miss", ultrawidelock_prov_find_cred_index(&rv, 7u, 99u), -1);

	/*
	 * Remove the FIRST slot, which is also the one holding a Kpersistent.
	 * The shift is where this gets dangerous: try_fast_auth() pairs
	 * kpersistent[i] with cred_pub[i] and never re-checks the trust store,
	 * so a valid bit left behind on a moved row would authenticate the wrong
	 * phone with no signature at all.
	 */
	T_EQ("rv.remove_at0", ultrawidelock_prov_trust_remove_at(&rv, 0), 0);
	T_EQ("rv.count", (int)rv.count, 2);
	T_EQ("rv.gone", ultrawidelock_prov_trust_check(&rv, k0), -1);
	T_EQ("rv.k1_kept", ultrawidelock_prov_trust_check(&rv, k1), 0);
	T_EQ("rv.k2_kept", ultrawidelock_prov_trust_check(&rv, k2), 0);
	/* k1 had no Kpersistent and k2 did, so after the shift only slot 1 does. */
	T_EQ("rv.kp_valid_after", rv.kp_valid, 0x02);
	T_OK("rv.kp_followed_its_key",
	     memcmp(rv.kpersistent[1], kp2, ULTRAWIDELOCK_KPERSISTENT_LEN) == 0);
	/* The revoked credential's Kpersistent is not anywhere in the store. */
	T_OK("rv.kp_of_revoked_gone",
	     memcmp(rv.kpersistent[0], kp0, ULTRAWIDELOCK_KPERSISTENT_LEN) != 0 &&
		     memcmp(rv.kpersistent[1], kp0, ULTRAWIDELOCK_KPERSISTENT_LEN) != 0);
	/* And the vacated slot holds no key material at all. */
	uint8_t zero_kp[ULTRAWIDELOCK_KPERSISTENT_LEN] = { 0 };
	uint8_t zero_pub[ULTRAWIDELOCK_CRED_PUB_LEN] = { 0 };
	T_OK("rv.tail_wiped",
	     memcmp(rv.kpersistent[2], zero_kp, ULTRAWIDELOCK_KPERSISTENT_LEN) == 0 &&
		     memcmp(rv.cred_pub[2], zero_pub, ULTRAWIDELOCK_CRED_PUB_LEN) == 0);
	/* The indices moved with their keys, so the survivors stay addressable. */
	T_EQ("rv.index_followed", ultrawidelock_prov_find_cred_index(&rv, 7u, 22u), 0);
	T_EQ("rv.index_followed2", ultrawidelock_prov_find_cred_index(&rv, 8u, 23u), 1);
	T_EQ("rv.revoked_index_unknown", ultrawidelock_prov_find_cred_index(&rv, 7u, 21u), -1);
	/*
	 * The type is half the name. Slot 1 is (type 8, index 23); asking for
	 * (type 7, index 23) must miss, or a controller clearing an evictable
	 * endpoint key would revoke the non-evictable one that happens to share
	 * its index and leave the intended credential opening the door.
	 */
	T_EQ("rv.type_is_part_of_the_name", ultrawidelock_prov_find_cred_index(&rv, 7u, 23u), -1);
	T_EQ("rv.tail_index_cleared", rv.cred_index[2], ULTRAWIDELOCK_CRED_INDEX_NONE);

	/* Idempotent: removing what is already gone is a fact, not a failure. */
	T_EQ("rv.remove_absent", ultrawidelock_prov_trust_remove(&rv, k0), 1);
	T_EQ("rv.remove_absent_no_change", (int)rv.count, 2);
	T_EQ("rv.remove_at_oob", ultrawidelock_prov_trust_remove_at(&rv, 2), -1);
	T_EQ("rv.remove_at_neg", ultrawidelock_prov_trust_remove_at(&rv, -1), -1);
	T_EQ("rv.remove_null", ultrawidelock_prov_trust_remove(NULL, k0), -1);

	/* The freed slot is reusable, and comes back with no inherited state. */
	uint8_t k3[ULTRAWIDELOCK_CRED_PUB_LEN];

	make_key(k3, 0xA3u);
	T_EQ("rv.reuse_slot", ultrawidelock_prov_trust_add(&rv, k3), 0);
	T_EQ("rv.reuse_count", (int)rv.count, 3);
	T_EQ("rv.reuse_trusted", ultrawidelock_prov_trust_check(&rv, k3), 0);
	T_EQ("rv.reuse_no_kp", rv.kp_valid & 0x04u, 0);
	T_EQ("rv.reuse_no_index", rv.cred_index[2], ULTRAWIDELOCK_CRED_INDEX_NONE);
	T_EQ("rv.reuse_no_type", rv.cred_type[2], 0);

	/* By key rather than by index, which is what the bench path removes with. */
	T_EQ("rv.remove_by_key", ultrawidelock_prov_trust_remove(&rv, k1), 0);
	T_EQ("rv.remove_by_key_gone", ultrawidelock_prov_trust_check(&rv, k1), -1);

	/*
	 * Removing the LAST anchor leaves an empty store, which reports
	 * "no anchors" rather than "rejected". That is not an open door: it
	 * hands the decision to the reader's dev-identity policy, and a
	 * Matter-provisioned reader is not a dev identity.
	 */
	struct ultrawidelock_trust_store solo;

	memset(&solo, 0, sizeof(solo));
	T_EQ("rv.solo_add", ultrawidelock_prov_trust_add(&solo, k0), 0);
	T_EQ("rv.solo_remove", ultrawidelock_prov_trust_remove(&solo, k0), 0);
	T_EQ("rv.solo_empty", (int)solo.count, 0);
	T_EQ("rv.solo_no_anchors", ultrawidelock_prov_trust_check(&solo, k0), 1);

	/*
	 * A removal that cannot be persisted.
	 *
	 * The blob is the store of record across a reboot, so a write that fails
	 * leaves the OLD store on flash -- unchanged, credential still trusted
	 * there. That is exactly why the reader applies the removal to its live
	 * store first and reports the write failure second: the door stops
	 * opening now, and the admin is told the removal did not stick.
	 */
	t_group("revocation persistence");
	struct ultrawidelock_reader_identity pid;
	struct ultrawidelock_trust_store pts;

	make_identity(&pid, &pts);
	uint8_t onflash[ULTRAWIDELOCK_PROV_BLOB_MAX];
	size_t onflash_len = 0;

	T_EQ("pers.write",
	     ultrawidelock_prov_serialize(&pid, &pts, onflash, sizeof(onflash), &onflash_len), 0);

	uint8_t victim[ULTRAWIDELOCK_CRED_PUB_LEN];

	memcpy(victim, pts.cred_pub[0], ULTRAWIDELOCK_CRED_PUB_LEN);

	struct ultrawidelock_trust_store live = pts;

	T_EQ("pers.remove_live", ultrawidelock_prov_trust_remove(&live, victim), 0);
	T_EQ("pers.live_rejects", ultrawidelock_prov_trust_check(&live, victim), -1);

	/* The write never happened, so the blob still holds what it held. */
	struct ultrawidelock_reader_identity rid;
	struct ultrawidelock_trust_store rts;

	T_EQ("pers.reload", ultrawidelock_prov_deserialize(onflash, onflash_len, &rid, &rts), 0);
	T_EQ("pers.flash_unchanged", ultrawidelock_prov_trust_check(&rts, victim), 0);
	T_OK("pers.flash_bytes_unchanged", memcmp(&rts, &pts, sizeof(rts)) == 0);

	/* Persisted, it survives the reboot as removed -- indices and all. */
	size_t after_len = 0;

	T_EQ("pers.rewrite",
	     ultrawidelock_prov_serialize(&pid, &live, onflash, sizeof(onflash), &after_len), 0);
	T_EQ("pers.reload2", ultrawidelock_prov_deserialize(onflash, after_len, &rid, &rts), 0);
	T_EQ("pers.still_removed", ultrawidelock_prov_trust_check(&rts, victim), -1);
	T_OK("pers.roundtrip", memcmp(&rts, &live, sizeof(rts)) == 0);
}
