/* SPDX-License-Identifier: ISC */

// credential reader provisioning state: default dev identity, and serialization/deserialization of
// the reader identity plus trusted-credential store to/from a self-describing binary blob. Also
// implements the trust-store membership check and add-with-dedup operations used to decide whether
// a presented credential public key is trusted.
/*
 * ultrawidelock_prov (portable core) — dev identity, blob (de)serialisation, and the
 * trust-store logic. No ESP-IDF or crypto dependency, so it compiles identically
 * on host and target. The NVS-backed load/store lives in ultrawidelock_prov_nvs.c
 * (target only).
 */
#include <string.h>

#include "ultrawidelock_prov.h"

/*
 * Built-in DEV reader identity — a fixed, non-secret P-256 bench keypair so the
 * reader identity is stable across reboots (a phone provisioned against it stays
 * valid). NOT for deployment: Phase-4 Matter provisioning overwrites this in NVS.
 * reader_id = the signing public key's X coordinate (the dev convention the
 * earlier scaffold used); sign_priv = the matching private scalar.
 */
static const uint8_t k_dev_reader_id[ULTRAWIDELOCK_READER_ID_LEN] = {
	0x11, 0x3b, 0x1a, 0x9e, 0xf2, 0x95, 0x67, 0x60, 0x8b, 0x75, 0x00,
	0xfb, 0xac, 0xa6, 0x09, 0xe9, 0xc0, 0x7b, 0x87, 0x4e, 0x18, 0x2a,
	0xe5, 0x65, 0x02, 0x4b, 0x54, 0x3e, 0x3b, 0x40, 0x93, 0x5f,
};
static const uint8_t k_dev_sign_priv[ULTRAWIDELOCK_READER_PRIV_LEN] = {
	0x4d, 0x33, 0x21, 0x69, 0xf4, 0x33, 0x9e, 0xef, 0x54, 0x9e, 0xf2,
	0xa6, 0xa9, 0x4b, 0x61, 0x95, 0xa4, 0x2f, 0xc2, 0xaf, 0x8c, 0xcf,
	0xdf, 0xce, 0x35, 0xbd, 0xf9, 0xbe, 0xd8, 0xf3, 0x83, 0xa3,
};

static const uint8_t k_magic[4] = {'A', 'P', 'R', 'V'};
#define ULTRAWIDELOCK_PROV_VERSION   0x05u /* current: adds issuer keys + anchor->issuer bindings */
#define ULTRAWIDELOCK_PROV_VERSION_4 0x04u /* legacy: Matter credential/user indices, no issuers */
#define ULTRAWIDELOCK_PROV_VERSION_3 0x03u /* legacy: kp_valid + kpersistent, no indices */
#define ULTRAWIDELOCK_PROV_VERSION_2 0x02u /* legacy: grk but no kpersistent (still parsed) */
#define ULTRAWIDELOCK_PROV_VERSION_1 0x01u /* legacy: no grk (still parsed) */
#define ULTRAWIDELOCK_PROV_FLAG_DEV  0x01u

/**
 * Load the built-in development reader identity and empty trust store (zeroed issuer credentials
 * and kpersistent keys).
 */
void ultrawidelock_prov_dev_default(struct ultrawidelock_reader_identity *id,
				    struct ultrawidelock_trust_store *ts)
{
	if (id != NULL) {
		memset(id, 0, sizeof(*id)); /* zeroes grk (dev has none) + padding */
		memcpy(id->reader_id, k_dev_reader_id, ULTRAWIDELOCK_READER_ID_LEN);
		memcpy(id->sign_priv, k_dev_sign_priv, ULTRAWIDELOCK_READER_PRIV_LEN);
		id->is_dev = true;
	}
	if (ts != NULL) {
		memset(ts, 0, sizeof(*ts));
	}
}

/**
 * Serialize reader identity and trust store into a provisioning blob (v5 format with grk,
 * kpersistent, the Matter credential/user indices, the anchor->issuer bindings and the issuer
 * keys). Returns 0 on success, -1 if a count exceeds its capacity or the buffer is too small.
 * Outputs blob and sets out_len.
 */
int ultrawidelock_prov_serialize(const struct ultrawidelock_reader_identity *id,
				 const struct ultrawidelock_trust_store *ts, uint8_t *out,
				 size_t cap, size_t *out_len)
{
	uint8_t count = (ts != NULL) ? ts->count : 0u;
	uint8_t issuers = (ts != NULL) ? ts->issuer_count : 0u;

	if (count > ULTRAWIDELOCK_TRUST_MAX || issuers > ULTRAWIDELOCK_ISSUER_MAX) {
		return -1;
	}

	size_t need = ULTRAWIDELOCK_PROV_BLOB_HDR + ULTRAWIDELOCK_READER_ID_LEN +
		      ULTRAWIDELOCK_READER_PRIV_LEN + ULTRAWIDELOCK_GRK_LEN + 1u +
		      (size_t)count * ULTRAWIDELOCK_CRED_PUB_LEN + 1u +
		      (size_t)count * ULTRAWIDELOCK_KPERSISTENT_LEN + (size_t)count * 6u + 1u +
		      (size_t)issuers * (ULTRAWIDELOCK_CRED_PUB_LEN + 4u);

	if (out == NULL || cap < need) {
		return -1;
	}

	uint8_t *p = out;

	memcpy(p, k_magic, sizeof(k_magic));
	p += sizeof(k_magic);
	*p++ = ULTRAWIDELOCK_PROV_VERSION;
	*p++ = id->is_dev ? ULTRAWIDELOCK_PROV_FLAG_DEV : 0u;
	memcpy(p, id->reader_id, ULTRAWIDELOCK_READER_ID_LEN);
	p += ULTRAWIDELOCK_READER_ID_LEN;
	memcpy(p, id->sign_priv, ULTRAWIDELOCK_READER_PRIV_LEN);
	p += ULTRAWIDELOCK_READER_PRIV_LEN;
	memcpy(p, id->grk, ULTRAWIDELOCK_GRK_LEN);
	p += ULTRAWIDELOCK_GRK_LEN;
	*p++ = count;
	for (uint8_t i = 0; i < count; i++) {
		memcpy(p, ts->cred_pub[i], ULTRAWIDELOCK_CRED_PUB_LEN);
		p += ULTRAWIDELOCK_CRED_PUB_LEN;
	}

	uint8_t mask = (ts != NULL) ? (uint8_t)(ts->kp_valid & ((1u << count) - 1u)) : 0u;

	*p++ = mask;
	for (uint8_t i = 0; i < count; i++) {
		if (mask & (1u << i)) {
			memcpy(p, ts->kpersistent[i], ULTRAWIDELOCK_KPERSISTENT_LEN);
		} else {
			memset(p, 0, ULTRAWIDELOCK_KPERSISTENT_LEN); /* never stale key bytes */
		}
		p += ULTRAWIDELOCK_KPERSISTENT_LEN;
	}
	/* Big-endian so the blob reads the same on a board and in a hexdump, and
	 * so a clone blob moved between architectures cannot re-point an index. */
	for (uint8_t i = 0; i < count; i++) {
		*p++ = ts->cred_type[i];
		*p++ = (uint8_t)(ts->cred_index[i] >> 8);
		*p++ = (uint8_t)(ts->cred_index[i] & 0xFFu);
		*p++ = (uint8_t)(ts->user_index[i] >> 8);
		*p++ = (uint8_t)(ts->user_index[i] & 0xFFu);
	}
	/* v5 tail: which issuer vouched for each anchor, then the issuers. */
	for (uint8_t i = 0; i < count; i++) {
		*p++ = ts->anchor_issuer[i];
	}
	*p++ = issuers;
	for (uint8_t i = 0; i < issuers; i++) {
		memcpy(p, ts->issuer_pub[i], ULTRAWIDELOCK_CRED_PUB_LEN);
		p += ULTRAWIDELOCK_CRED_PUB_LEN;
		*p++ = (uint8_t)(ts->issuer_cred_index[i] >> 8);
		*p++ = (uint8_t)(ts->issuer_cred_index[i] & 0xFFu);
		*p++ = (uint8_t)(ts->issuer_user_index[i] >> 8);
		*p++ = (uint8_t)(ts->issuer_user_index[i] & 0xFFu);
	}

	if (out_len != NULL) {
		*out_len = (size_t)(p - out);
	}
	return 0;
}

/**
 * Deserialize a provisioning blob (magic + version + flags + reader_id + sign_priv + grk +
 * credential count + cred_pub list + kpersistent bitmask + kpersistent list + Matter index pairs).
 * Supports v1 (no grk), v2 (grk, no kpersistent), v3 (no indices), v4 (no issuers), v5 (all).
 * Returns 0 on success, -1 on invalid magic/version/length/count.
 */
int ultrawidelock_prov_deserialize(const uint8_t *buf, size_t len,
				   struct ultrawidelock_reader_identity *id,
				   struct ultrawidelock_trust_store *ts)
{
	if (buf == NULL || len < ULTRAWIDELOCK_PROV_BLOB_HDR ||
	    memcmp(buf, k_magic, sizeof(k_magic)) != 0) {
		return -1;
	}

	/* grk was added in v2, the kpersistent tail in v3, the Matter indices in
	 * v4, the issuers in v5; older blobs are still parsed for back-compat
	 * (their credentials simply lack whatever came later). */
	size_t grk_len;
	int has_kp = 0;
	int has_idx = 0;
	int has_issuers = 0;
	if (buf[4] == ULTRAWIDELOCK_PROV_VERSION) {
		grk_len = ULTRAWIDELOCK_GRK_LEN;
		has_kp = 1;
		has_idx = 1;
		has_issuers = 1;
	} else if (buf[4] == ULTRAWIDELOCK_PROV_VERSION_4) {
		grk_len = ULTRAWIDELOCK_GRK_LEN;
		has_kp = 1;
		has_idx = 1;
	} else if (buf[4] == ULTRAWIDELOCK_PROV_VERSION_3) {
		grk_len = ULTRAWIDELOCK_GRK_LEN;
		has_kp = 1;
	} else if (buf[4] == ULTRAWIDELOCK_PROV_VERSION_2) {
		grk_len = ULTRAWIDELOCK_GRK_LEN;
	} else if (buf[4] == ULTRAWIDELOCK_PROV_VERSION_1) {
		grk_len = 0u;
	} else {
		return -1;
	}

	const size_t fixed = ULTRAWIDELOCK_PROV_BLOB_HDR + ULTRAWIDELOCK_READER_ID_LEN +
			     ULTRAWIDELOCK_READER_PRIV_LEN + grk_len + 1u;

	if (len < fixed) {
		return -1;
	}

	uint8_t count = buf[fixed - 1u];
	size_t want = fixed + (size_t)count * ULTRAWIDELOCK_CRED_PUB_LEN;

	if (has_kp) {
		want += 1u + (size_t)count * ULTRAWIDELOCK_KPERSISTENT_LEN;
	}
	if (has_idx) {
		want += (size_t)count * 5u;
	}
	uint8_t issuers = 0u;

	if (has_issuers) {
		/* The issuer count sits after the per-anchor bindings; it has to be
		 * read before the total length can be checked. */
		want += (size_t)count + 1u;
		if (len < want || count > ULTRAWIDELOCK_TRUST_MAX) {
			return -1;
		}
		issuers = buf[want - 1u];
		want += (size_t)issuers * (ULTRAWIDELOCK_CRED_PUB_LEN + 4u);
	}
	if (count > ULTRAWIDELOCK_TRUST_MAX || issuers > ULTRAWIDELOCK_ISSUER_MAX || len != want) {
		return -1;
	}

	const uint8_t *p = buf + ULTRAWIDELOCK_PROV_BLOB_HDR;

	if (id != NULL) {
		id->is_dev = (buf[5] & ULTRAWIDELOCK_PROV_FLAG_DEV) != 0u;
		memcpy(id->reader_id, p, ULTRAWIDELOCK_READER_ID_LEN);
		memcpy(id->sign_priv, p + ULTRAWIDELOCK_READER_ID_LEN, ULTRAWIDELOCK_READER_PRIV_LEN);
		if (grk_len == ULTRAWIDELOCK_GRK_LEN) {
			memcpy(id->grk, p + ULTRAWIDELOCK_READER_ID_LEN + ULTRAWIDELOCK_READER_PRIV_LEN,
			       ULTRAWIDELOCK_GRK_LEN);
		} else {
			memset(id->grk, 0, ULTRAWIDELOCK_GRK_LEN);
		}
	}
	if (ts != NULL) {
		memset(ts, 0, sizeof(*ts));
		ts->count = count;
		const uint8_t *k = buf + fixed;

		for (uint8_t i = 0; i < count; i++) {
			memcpy(ts->cred_pub[i], k, ULTRAWIDELOCK_CRED_PUB_LEN);
			k += ULTRAWIDELOCK_CRED_PUB_LEN;
		}
		if (has_kp) {
			ts->kp_valid = (uint8_t)(*k++ & ((1u << count) - 1u));
			for (uint8_t i = 0; i < count; i++) {
				memcpy(ts->kpersistent[i], k, ULTRAWIDELOCK_KPERSISTENT_LEN);
				k += ULTRAWIDELOCK_KPERSISTENT_LEN;
			}
		}
		/* memset above already left every index at ULTRAWIDELOCK_CRED_INDEX_NONE,
		 * which is what a pre-v4 blob's anchors truthfully have. */
		if (has_idx) {
			for (uint8_t i = 0; i < count; i++) {
				ts->cred_type[i] = k[0];
				ts->cred_index[i] = (uint16_t)(((uint16_t)k[1] << 8) | k[2]);
				ts->user_index[i] = (uint16_t)(((uint16_t)k[3] << 8) | k[4]);
				k += 5u;
			}
		}
		/* memset also left anchor_issuer at ULTRAWIDELOCK_ANCHOR_ISSUER_NONE and
		 * issuer_count at 0, which is what a pre-v5 blob truthfully has. */
		if (has_issuers) {
			for (uint8_t i = 0; i < count; i++) {
				ts->anchor_issuer[i] = *k++;
			}
			ts->issuer_count = *k++;
			for (uint8_t i = 0; i < issuers; i++) {
				memcpy(ts->issuer_pub[i], k, ULTRAWIDELOCK_CRED_PUB_LEN);
				k += ULTRAWIDELOCK_CRED_PUB_LEN;
				ts->issuer_cred_index[i] = (uint16_t)(((uint16_t)k[0] << 8) | k[1]);
				ts->issuer_user_index[i] = (uint16_t)(((uint16_t)k[2] << 8) | k[3]);
				k += 4u;
			}
		}
	}
	return 0;
}

/**
 * Check if a credential public key is in the trust store: returns 0 (trusted), -1 (known set, not a
 * member), 1 (no anchors provisioned). The return order (0, -1, 1) matches the credential state
 * (accepted, rejected, uncertain).
 */
int ultrawidelock_prov_trust_check(const struct ultrawidelock_trust_store *ts,
			   const uint8_t cred_pub[ULTRAWIDELOCK_CRED_PUB_LEN])
{
	if (ts == NULL || ts->count == 0u) {
		return 1; /* no anchors provisioned */
	}
	for (uint8_t i = 0; i < ts->count && i < ULTRAWIDELOCK_TRUST_MAX; i++) {
		if (memcmp(ts->cred_pub[i], cred_pub, ULTRAWIDELOCK_CRED_PUB_LEN) == 0) {
			return 0; /* trusted */
		}
	}
	return -1; /* known set, not a member */
}

/**
 * Add a credential public key to the trust store if not already present. Returns 0 on success, 1 if
 * already present, 2 when the store was full and an anchor was evicted to make room, -1 on error
 * (null pointer, invalid key format, or a count already past ULTRAWIDELOCK_TRUST_MAX). A full store
 * is not an error: it evicts. The key must start with 0x04 (uncompressed point). Clears the
 * Kpersistent bit for the new slot and zeroes its entry.
 */
int ultrawidelock_prov_trust_add(struct ultrawidelock_trust_store *ts,
				 const uint8_t cred_pub[ULTRAWIDELOCK_CRED_PUB_LEN])
{
	if (ts == NULL || cred_pub[0] != 0x04u) {
		return -1;
	}
	if (ultrawidelock_prov_trust_check(ts, cred_pub) == 0) {
		return 1; /* already present */
	}
	int evicted = 0;

	if (ts->count >= ULTRAWIDELOCK_TRUST_MAX) {
		/*
		 * EVICT rather than refuse. Anchors accumulate across pairings
		 * and nothing ever removed them, so a store that filled stayed
		 * full for good: the reader kept rejecting the credential the
		 * phone actually presents, one step after "device signature OK",
		 * and no amount of re-pairing could recover it. Observed on
		 * hardware with 4 anchors held and a 5th key being presented.
		 *
		 * Evict a slot that has NEVER completed a standard phase first
		 * -- no Kpersistent means no phone has ever authenticated with
		 * it, so it is the cheapest thing in the store to lose. Only if
		 * every slot has been used does the oldest go.
		 */
		uint8_t victim = 0u;

		for (uint8_t i = 0u; i < ULTRAWIDELOCK_TRUST_MAX; i++) {
			if ((ts->kp_valid & (uint8_t)(1u << i)) == 0u) {
				victim = i;
				break;
			}
		}
		/* Same shift a revocation does, so there is one place where a
		 * slot's key, Kpersistent, valid bit and Matter indices move
		 * together and one place to get that wrong. */
		if (ultrawidelock_prov_trust_remove_at(ts, (int)victim) != 0) {
			/* Only a count already past ULTRAWIDELOCK_TRUST_MAX gets here, and
			 * then ts->count is not a slot index: writing the new key
			 * at it would run off the end of the array. Refuse. */
			return -1;
		}
		evicted = 1;
	}
	memcpy(ts->cred_pub[ts->count], cred_pub, ULTRAWIDELOCK_CRED_PUB_LEN);
	/* the new slot has no Kpersistent yet (a stale bit would alias an old key)
	 * and no Matter index until a SetCredential binds one */
	ts->kp_valid &= (uint8_t)~(1u << ts->count);
	memset(ts->kpersistent[ts->count], 0, ULTRAWIDELOCK_KPERSISTENT_LEN);
	ts->cred_type[ts->count] = 0u;
	ts->cred_index[ts->count] = ULTRAWIDELOCK_CRED_INDEX_NONE;
	ts->user_index[ts->count] = ULTRAWIDELOCK_CRED_INDEX_NONE;
	ts->anchor_issuer[ts->count] = ULTRAWIDELOCK_ANCHOR_ISSUER_NONE;
	ts->count++;
	/* 2 tells the caller an anchor was dropped to make room, which is worth
	 * a log line -- it is the only visible sign the store is undersized. */
	return evicted ? 2 : 0;
}

/**
 * Find the index of a credential public key in the trust store. Returns the index (0..count-1) on
 * match, -1 if not found or ts is NULL.
 */
int ultrawidelock_prov_trust_find(const struct ultrawidelock_trust_store *ts,
			  const uint8_t cred_pub[ULTRAWIDELOCK_CRED_PUB_LEN])
{
	if (ts == NULL) {
		return -1;
	}
	for (uint8_t i = 0; i < ts->count && i < ULTRAWIDELOCK_TRUST_MAX; i++) {
		if (memcmp(ts->cred_pub[i], cred_pub, ULTRAWIDELOCK_CRED_PUB_LEN) == 0) {
			return i;
		}
	}
	return -1;
}

/**
 * Remove the anchor at idx, shifting every later slot down one and zeroing the slot that falls off
 * the top. Returns 0 on success, -1 if ts is NULL or idx is not an occupied slot.
 */
int ultrawidelock_prov_trust_remove_at(struct ultrawidelock_trust_store *ts, int idx)
{
	if (ts == NULL || idx < 0 || (unsigned)idx >= ts->count || ts->count > ULTRAWIDELOCK_TRUST_MAX) {
		return -1;
	}
	for (uint8_t i = (uint8_t)idx; i + 1u < ts->count; i++) {
		memcpy(ts->cred_pub[i], ts->cred_pub[i + 1u], ULTRAWIDELOCK_CRED_PUB_LEN);
		memcpy(ts->kpersistent[i], ts->kpersistent[i + 1u], ULTRAWIDELOCK_KPERSISTENT_LEN);
		ts->cred_type[i] = ts->cred_type[i + 1u];
		ts->cred_index[i] = ts->cred_index[i + 1u];
		ts->user_index[i] = ts->user_index[i + 1u];
		ts->anchor_issuer[i] = ts->anchor_issuer[i + 1u];
		/*
		 * The bit must follow its key. try_fast_auth() pairs
		 * kpersistent[i] with cred_pub[i] and never consults the trust
		 * check, so a bit left behind on a shifted row would open the
		 * door for a revoked phone with no signature verified.
		 */
		if (ts->kp_valid & (uint8_t)(1u << (i + 1u))) {
			ts->kp_valid |= (uint8_t)(1u << i);
		} else {
			ts->kp_valid &= (uint8_t)~(1u << i);
		}
	}
	ts->count--;
	/* Wipe the vacated top slot rather than leaving it to be overwritten: a
	 * Kpersistent is key material, and the next add must not inherit one. */
	memset(ts->cred_pub[ts->count], 0, ULTRAWIDELOCK_CRED_PUB_LEN);
	memset(ts->kpersistent[ts->count], 0, ULTRAWIDELOCK_KPERSISTENT_LEN);
	ts->kp_valid &= (uint8_t)~(1u << ts->count);
	ts->cred_type[ts->count] = 0u;
	ts->cred_index[ts->count] = ULTRAWIDELOCK_CRED_INDEX_NONE;
	ts->user_index[ts->count] = ULTRAWIDELOCK_CRED_INDEX_NONE;
	ts->anchor_issuer[ts->count] = ULTRAWIDELOCK_ANCHOR_ISSUER_NONE;
	return 0;
}

/**
 * Remove a credential public key from the trust store. Returns 0 if it was removed, 1 if it was not
 * there (an already-applied removal is not a failure), -1 if ts is NULL.
 */
int ultrawidelock_prov_trust_remove(struct ultrawidelock_trust_store *ts,
			    const uint8_t cred_pub[ULTRAWIDELOCK_CRED_PUB_LEN])
{
	if (ts == NULL) {
		return -1;
	}
	int idx = ultrawidelock_prov_trust_find(ts, cred_pub);

	if (idx < 0) {
		return 1; /* already gone; saying so is not an error */
	}
	return ultrawidelock_prov_trust_remove_at(ts, idx);
}

/**
 * Record the Matter credential and user indices the anchor at idx was installed under. Returns 0 on
 * success, -1 if idx is not a stored credential.
 */
int ultrawidelock_prov_cred_bind_set(struct ultrawidelock_trust_store *ts, int idx,
				     uint8_t cred_type, uint16_t cred_index, uint16_t user_index)
{
	if (ts == NULL || idx < 0 || (unsigned)idx >= ts->count) {
		return -1;
	}
	ts->cred_type[idx] = cred_type;
	ts->cred_index[idx] = cred_index;
	ts->user_index[idx] = user_index;
	return 0;
}

/**
 * Find the slot bound to a Matter (credential type, credential index). Returns the slot, or -1 if
 * no anchor carries that pair. Type 0 and ULTRAWIDELOCK_CRED_INDEX_NONE never match, so an unbound
 * anchor cannot be removed by index.
 */
int ultrawidelock_prov_find_cred_index(const struct ultrawidelock_trust_store *ts,
				       uint8_t cred_type, uint16_t cred_index)
{
	if (ts == NULL || cred_type == 0u || cred_index == ULTRAWIDELOCK_CRED_INDEX_NONE) {
		return -1;
	}
	for (uint8_t i = 0; i < ts->count && i < ULTRAWIDELOCK_TRUST_MAX; i++) {
		/*
		 * Both halves, because a Matter credential index is scoped to
		 * its type: an evictable and a non-evictable endpoint key can
		 * both be index 1, and matching on the index alone would revoke
		 * whichever came first and leave the other one opening the door.
		 */
		if (ts->cred_type[i] == cred_type && ts->cred_index[i] == cred_index) {
			return i;
		}
	}
	return -1;
}

/* ---- credential issuer keys ---------------------------------------------- */

/**
 * Slot of an issuer public key, or -1 if it is not stored (or ts is NULL).
 */
int ultrawidelock_prov_issuer_find(const struct ultrawidelock_trust_store *ts,
				   const uint8_t pub[ULTRAWIDELOCK_CRED_PUB_LEN])
{
	if (ts == NULL) {
		return -1;
	}
	for (uint8_t i = 0; i < ts->issuer_count && i < ULTRAWIDELOCK_ISSUER_MAX; i++) {
		if (memcmp(ts->issuer_pub[i], pub, ULTRAWIDELOCK_CRED_PUB_LEN) == 0) {
			return i;
		}
	}
	return -1;
}

/**
 * Slot of the issuer a Matter admin installed as credential index cred_index (type 6), or -1.
 * ULTRAWIDELOCK_CRED_INDEX_NONE never matches: an issuer no admin named is not addressable.
 */
int ultrawidelock_prov_issuer_find_index(const struct ultrawidelock_trust_store *ts,
					 uint16_t cred_index)
{
	if (ts == NULL || cred_index == ULTRAWIDELOCK_CRED_INDEX_NONE) {
		return -1;
	}
	for (uint8_t i = 0; i < ts->issuer_count && i < ULTRAWIDELOCK_ISSUER_MAX; i++) {
		if (ts->issuer_cred_index[i] == cred_index) {
			return i;
		}
	}
	return -1;
}

/**
 * Add an issuer public key, or rebind the indices of one already stored. Returns 0 added, 1 already
 * present (indices rebound), -1 if the key is not an uncompressed point or the store is full. Full
 * REFUSES: an issuer is a trust root the admin placed, the cluster reports exactly this many slots,
 * and evicting one silently would revoke every key it vouched for.
 */
int ultrawidelock_prov_issuer_add(struct ultrawidelock_trust_store *ts,
				  const uint8_t pub[ULTRAWIDELOCK_CRED_PUB_LEN], uint16_t cred_index,
				  uint16_t user_index)
{
	if (ts == NULL || pub[0] != 0x04u) {
		return -1;
	}
	int slot = ultrawidelock_prov_issuer_find(ts, pub);

	if (slot >= 0) {
		ts->issuer_cred_index[slot] = cred_index;
		ts->issuer_user_index[slot] = user_index;
		return 1;
	}
	if (ts->issuer_count >= ULTRAWIDELOCK_ISSUER_MAX) {
		return -1;
	}
	memcpy(ts->issuer_pub[ts->issuer_count], pub, ULTRAWIDELOCK_CRED_PUB_LEN);
	ts->issuer_cred_index[ts->issuer_count] = cred_index;
	ts->issuer_user_index[ts->issuer_count] = user_index;
	ts->issuer_count++;
	return 0;
}

/**
 * Drop the issuer at idx together with every anchor it vouched for, closing both gaps. Anchors
 * bound to a later issuer follow it down one slot. Returns the number of anchors dropped, or -1
 * if idx is not an occupied issuer slot.
 */
int ultrawidelock_prov_issuer_remove_at(struct ultrawidelock_trust_store *ts, int idx)
{
	if (ts == NULL || idx < 0 || (unsigned)idx >= ts->issuer_count ||
	    ts->issuer_count > ULTRAWIDELOCK_ISSUER_MAX) {
		return -1;
	}
	uint8_t bound = (uint8_t)(idx + 1); /* anchor_issuer is 1 + slot */
	int dropped = 0;

	/* Downwards, because removing anchor i shifts every later anchor into it. */
	for (int i = (int)ts->count - 1; i >= 0; i--) {
		if (ts->anchor_issuer[i] == bound) {
			(void)ultrawidelock_prov_trust_remove_at(ts, i);
			dropped++;
		} else if (ts->anchor_issuer[i] > bound) {
			ts->anchor_issuer[i]--;
		}
	}
	for (uint8_t i = (uint8_t)idx; i + 1u < ts->issuer_count; i++) {
		memcpy(ts->issuer_pub[i], ts->issuer_pub[i + 1u], ULTRAWIDELOCK_CRED_PUB_LEN);
		ts->issuer_cred_index[i] = ts->issuer_cred_index[i + 1u];
		ts->issuer_user_index[i] = ts->issuer_user_index[i + 1u];
	}
	ts->issuer_count--;
	memset(ts->issuer_pub[ts->issuer_count], 0, ULTRAWIDELOCK_CRED_PUB_LEN);
	ts->issuer_cred_index[ts->issuer_count] = ULTRAWIDELOCK_CRED_INDEX_NONE;
	ts->issuer_user_index[ts->issuer_count] = ULTRAWIDELOCK_CRED_INDEX_NONE;
	return dropped;
}

/**
 * Bind the anchor at idx to the issuer at issuer_slot. Returns 0, or -1 if either is not an
 * occupied slot.
 */
int ultrawidelock_prov_anchor_issuer_set(struct ultrawidelock_trust_store *ts, int idx,
					 int issuer_slot)
{
	if (ts == NULL || idx < 0 || (unsigned)idx >= ts->count || issuer_slot < 0 ||
	    (unsigned)issuer_slot >= ts->issuer_count) {
		return -1;
	}
	ts->anchor_issuer[idx] = (uint8_t)(issuer_slot + 1);
	return 0;
}

/**
 * Issuer slot the anchor at idx was learned under, or -1 when none vouched for it.
 */
int ultrawidelock_prov_anchor_issuer(const struct ultrawidelock_trust_store *ts, int idx)
{
	if (ts == NULL || idx < 0 || (unsigned)idx >= ts->count ||
	    ts->anchor_issuer[idx] == ULTRAWIDELOCK_ANCHOR_ISSUER_NONE) {
		return -1;
	}
	return (int)ts->anchor_issuer[idx] - 1;
}

/**
 * Lowest Matter credential index in 1..ULTRAWIDELOCK_TRUST_MAX no anchor of cred_type carries, or
 * 0 when they are all taken. Indices are scoped to their type, so only same-type anchors count.
 */
uint16_t ultrawidelock_prov_free_cred_index(const struct ultrawidelock_trust_store *ts,
					    uint8_t cred_type)
{
	if (ts == NULL) {
		return 0u;
	}
	for (uint16_t index = 1u; index <= ULTRAWIDELOCK_TRUST_MAX; index++) {
		if (ultrawidelock_prov_find_cred_index(ts, cred_type, index) < 0) {
			return index;
		}
	}
	return 0u;
}

/**
 * Set the Kpersistent key for a credential at index idx; marks it valid in the bitmask. Returns 0
 * on success, -1 if idx out of range.
 */
int ultrawidelock_prov_kpersistent_set(struct ultrawidelock_trust_store *ts, int idx,
			       const uint8_t kp[ULTRAWIDELOCK_KPERSISTENT_LEN])
{
	if (ts == NULL || kp == NULL || idx < 0 || (unsigned)idx >= ts->count) {
		return -1;
	}
	memcpy(ts->kpersistent[idx], kp, ULTRAWIDELOCK_KPERSISTENT_LEN);
	ts->kp_valid |= (uint8_t)(1u << idx);
	return 0;
}
