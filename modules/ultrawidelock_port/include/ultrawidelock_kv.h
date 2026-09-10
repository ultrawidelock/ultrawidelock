/* SPDX-License-Identifier: ISC */

/*
 * ultrawidelock_kv.h - small persistent values, addressed by number.
 *
 * WHAT THIS REPLACES, AND WHY THE KEY IS AN INTEGER. Each framework caps record
 * names differently -- ESP-IDF's NVS at 15 characters, Zephyr's settings at 64 --
 * and ESP-IDF's read side reports a too-long name as "never stored" rather than
 * as an error, which is how an 18-character namespace survived a rename, a test
 * suite and a release (docs/esp32-gotchas.md 8.4). Every port re-solved that
 * trap by hand, and PORTING.md carried a table of every spelled-out name to
 * police it.
 *
 * A uint16_t key cannot be too long. Backends derive their own storage name
 * from the number -- "uwl/%04x" under Zephyr settings, namespace "uwl" with key
 * "%04x" under NVS -- so both are bounded by construction, four hex digits, and
 * the cap can no longer be exceeded by anyone. The FreeRTOS port reached this
 * shape first (ports/freertos-nrf52833, where records were always numeric); this
 * header is that design promoted to the contract every port implements.
 *
 * Keys are grouped into windows by consumer, because a range is cheaper to
 * reason about than a registry and two consumers must never collide. Take an id
 * from the right window; do not invent a window without a consumer.
 *
 * Backends: FreeRTOS flash pages (ports/freertos-nrf52833), Zephyr settings,
 * ESP-IDF NVS, and host RAM (tests/host/port/kv_host.c), which doubles as the
 * test fake.
 *
 * NOT a filesystem and not a database. Small values that must survive a reset
 * and a firmware update -- keys, a provisioning blob, a handful of flags.
 */
#ifndef ULTRAWIDELOCK_KV_H
#define ULTRAWIDELOCK_KV_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Key windows. A consumer owns a range; ids inside it are assigned by the
 * consumer's own header or, where there is only ever one, here.
 */
#define ULTRAWIDELOCK_KV_KEY_CRED_PROV 0x0001u

/* OpenThread's own settings keys are 0x0000..0x00ff, offset into this window so
 * they cannot land on a credential key. */
#define ULTRAWIDELOCK_KV_KEY_OPENTHREAD_BASE  0x1000u
#define ULTRAWIDELOCK_KV_KEY_OPENTHREAD_LIMIT 0x1100u

/* Matter: the fabric table, subscription slots, and the door-lock attributes
 * that persist. These ids are shared by every backend because the portable
 * Matter store now calls this seam directly. */
#define ULTRAWIDELOCK_KV_KEY_MATTER_BASE  0x2000u
#define ULTRAWIDELOCK_KV_KEY_MATTER_LIMIT 0x2100u

#define ULTRAWIDELOCK_KV_KEY_MATTER_SRP_HOST_ID 0x2000u
/* Retired v0.3 fabric schema. Kept assigned so a clean-break loader can erase
 * it without ever mistaking it for current identity. */
#define ULTRAWIDELOCK_KV_KEY_MATTER_FAB_VER   0x2010u
#define ULTRAWIDELOCK_KV_KEY_MATTER_FAB_OK    0x2011u
#define ULTRAWIDELOCK_KV_KEY_MATTER_FAB_TD    0x2012u
#define ULTRAWIDELOCK_KV_KEY_MATTER_FAB_XP    0x2013u
#define ULTRAWIDELOCK_KV_KEY_MATTER_FAB_ICLEN 0x2014u
#define ULTRAWIDELOCK_KV_KEY_MATTER_FAB_ICAC  0x2015u
#define ULTRAWIDELOCK_KV_KEY_MATTER_FAB_SLOT0      0x2020u
#define ULTRAWIDELOCK_KV_KEY_MATTER_FAB_SLOT_LIMIT 0x2030u

#define ULTRAWIDELOCK_KV_KEY_MATTER_SUB_SLOT0      0x2040u
#define ULTRAWIDELOCK_KV_KEY_MATTER_SUB_SLOT_LIMIT 0x2050u
#define ULTRAWIDELOCK_KV_KEY_MATTER_DL_AUTO_RELOCK 0x2060u
#define ULTRAWIDELOCK_KV_KEY_MATTER_DL_APPROACH    0x2061u
#define ULTRAWIDELOCK_KV_KEY_MATTER_UWB_CONFIG     0x2062u

/* Current clean-break, per-record Matter identity schema. */
#define ULTRAWIDELOCK_KV_KEY_MATTER_MF2_META    0x2070u
#define ULTRAWIDELOCK_KV_KEY_MATTER_MF2_NET     0x2071u
#define ULTRAWIDELOCK_KV_KEY_MATTER_MF2_ICAC    0x2072u
#define ULTRAWIDELOCK_KV_KEY_MATTER_MF2_BINDING 0x2073u
#define ULTRAWIDELOCK_KV_KEY_MATTER_MF2_FAB0      0x2080u
#define ULTRAWIDELOCK_KV_KEY_MATTER_MF2_FAB_LIMIT 0x2085u
#define ULTRAWIDELOCK_KV_KEY_MATTER_MF2_ACL0      0x2090u
#define ULTRAWIDELOCK_KV_KEY_MATTER_MF2_ACL_LIMIT 0x2095u

/* PSA internal trusted storage, when a port has no ITS of its own. */
#define ULTRAWIDELOCK_KV_KEY_PSA_ITS_BASE  0x3000u
#define ULTRAWIDELOCK_KV_KEY_PSA_ITS_LIMIT 0x3100u

/* The sealed link's keys: per-witness, the anchor's, the satellite's own. One
 * window because they are one subsystem with one lifetime -- a factory reset
 * takes all of them or none. */
#define ULTRAWIDELOCK_KV_KEY_LINK_BASE  0x4000u
#define ULTRAWIDELOCK_KV_KEY_LINK_LIMIT 0x4100u

/* The lock indexes witness keys by enum ultrawidelock_witness_role. Role zero
 * is UNKNOWN and intentionally has no provisionable record. */
#define ULTRAWIDELOCK_KV_KEY_LINK_WITNESS_KEY_BASE  0x4000u
#define ULTRAWIDELOCK_KV_KEY_LINK_WITNESS_KEY_LIMIT 0x4004u
#define ULTRAWIDELOCK_KV_KEY_LINK_ANCHOR_KEY         0x4010u
#define ULTRAWIDELOCK_KV_KEY_LINK_SATELLITE_KEY      0x4011u

/* A BLE witness's own provisioning record. This is separate from the lock's
 * role-indexed copy of the link key above: the two live on different boards. */
#define ULTRAWIDELOCK_KV_KEY_LINK_BLE_WITNESS_ROLE      0x4020u
#define ULTRAWIDELOCK_KV_KEY_LINK_BLE_WITNESS_LINK_KEY  0x4021u
#define ULTRAWIDELOCK_KV_KEY_LINK_BLE_WITNESS_GROUP_KEY 0x4022u
#define ULTRAWIDELOCK_KV_KEY_LINK_BLE_WITNESS_DATASET   0x4023u

#if ULTRAWIDELOCK_KV_KEY_MATTER_SRP_HOST_ID < ULTRAWIDELOCK_KV_KEY_MATTER_BASE || \
	ULTRAWIDELOCK_KV_KEY_MATTER_MF2_ACL_LIMIT > ULTRAWIDELOCK_KV_KEY_MATTER_LIMIT || \
	ULTRAWIDELOCK_KV_KEY_MATTER_MF2_BINDING == ULTRAWIDELOCK_KV_KEY_MATTER_MF2_META || \
	ULTRAWIDELOCK_KV_KEY_MATTER_MF2_BINDING == ULTRAWIDELOCK_KV_KEY_MATTER_MF2_NET || \
	ULTRAWIDELOCK_KV_KEY_MATTER_MF2_BINDING == ULTRAWIDELOCK_KV_KEY_MATTER_MF2_ICAC || \
	ULTRAWIDELOCK_KV_KEY_MATTER_MF2_BINDING >= ULTRAWIDELOCK_KV_KEY_MATTER_MF2_FAB0
#error "Matter key assignments collide or escape their reserved window"
#endif

#if ULTRAWIDELOCK_KV_KEY_LINK_WITNESS_KEY_BASE < ULTRAWIDELOCK_KV_KEY_LINK_BASE || \
	ULTRAWIDELOCK_KV_KEY_LINK_WITNESS_KEY_BASE + 3u >= \
		ULTRAWIDELOCK_KV_KEY_LINK_WITNESS_KEY_LIMIT || \
	ULTRAWIDELOCK_KV_KEY_LINK_WITNESS_KEY_LIMIT > ULTRAWIDELOCK_KV_KEY_LINK_ANCHOR_KEY || \
	ULTRAWIDELOCK_KV_KEY_LINK_ANCHOR_KEY == ULTRAWIDELOCK_KV_KEY_LINK_SATELLITE_KEY || \
	ULTRAWIDELOCK_KV_KEY_LINK_SATELLITE_KEY >= ULTRAWIDELOCK_KV_KEY_LINK_BLE_WITNESS_ROLE || \
	ULTRAWIDELOCK_KV_KEY_LINK_BLE_WITNESS_DATASET >= ULTRAWIDELOCK_KV_KEY_LINK_LIMIT
#error "sealed-link key assignments collide or escape their reserved window"
#endif

/* Whatever a single board persists for itself and no other port shares. */
#define ULTRAWIDELOCK_KV_KEY_APP_BASE  0x5000u
#define ULTRAWIDELOCK_KV_KEY_APP_LIMIT 0x5100u

/* A key no record can carry: erased flash reads as all ones. */
#define ULTRAWIDELOCK_KV_KEY_NONE 0xffffu

/* The largest single value. Sized by the credential provisioning blob, the
 * biggest thing any consumer stores (ULTRAWIDELOCK_PROV_BLOB_MAX, 1052 bytes
 * since the blob gained the issuer keys). */
#define ULTRAWIDELOCK_KV_VALUE_MAX 1088u

enum ultrawidelock_kv_result {
	ULTRAWIDELOCK_KV_OK = 0,
	/* No record for that key. Not an error; the caller decides. */
	ULTRAWIDELOCK_KV_NOT_FOUND = -1,
	/* The key or length is outside what this store accepts. */
	ULTRAWIDELOCK_KV_INVALID = -2,
	/* The live set no longer fits, even after whatever compaction exists. */
	ULTRAWIDELOCK_KV_FULL = -3,
	/* The underlying store refused a read, write, or erase. */
	ULTRAWIDELOCK_KV_IO = -4,
	/* The store is unreadable or unformatted and could not be recovered. */
	ULTRAWIDELOCK_KV_CORRUPT = -5,
};

/**
 * Mount the store, formatting it if there is nothing valid to mount.
 *
 * Safe to call more than once; later calls are no-ops. Returns
 * ULTRAWIDELOCK_KV_OK or a negative ultrawidelock_kv_result.
 */
int ultrawidelock_kv_init(void);

/**
 * Read a value. On ULTRAWIDELOCK_KV_OK, *@p length carries the stored length; on
 * entry it carries the capacity of @p value. A value larger than the buffer is
 * refused with ULTRAWIDELOCK_KV_INVALID and *@p length set to the stored length,
 * so a caller can size a second attempt.
 *
 * @p value may be NULL with *@p length zero to ask only for the stored length.
 */
int ultrawidelock_kv_get(uint16_t key, void *value, size_t *length);

/** Write a value, replacing any earlier one for that key. */
int ultrawidelock_kv_set(uint16_t key, const void *value, size_t length);

/** Forget one key. ULTRAWIDELOCK_KV_NOT_FOUND if it was not stored. */
int ultrawidelock_kv_delete(uint16_t key);

/**
 * Forget everything, leaving a formatted store.
 *
 * A factory reset of what this store owns. NOT an erase of the underlying
 * region: a caller that wants only its own keys gone must delete them.
 */
int ultrawidelock_kv_erase_all(void);

#ifdef __cplusplus
}
#endif

#endif /* ULTRAWIDELOCK_KV_H */
