/* SPDX-License-Identifier: ISC */

/*
 * OpenThread's settings platform over the port's key-value store.
 *
 * The store holds one value per key; otPlatSettings is multi-valued — Add
 * appends another value under the same key, Get and Delete address one value by
 * index, and Delete with index -1 removes them all. The reconciliation is a
 * record format: every OpenThread key owns one key-value record that packs its
 * values back to back as length-prefixed entries, and every mutation rewrites
 * that record whole. That costs a full record write per mutation, which is
 * acceptable because the only multi-valued key a Thread device writes is
 * CHILD_INFO, and an MTD (which this product configures) writes none — but the
 * full contract is implemented anyway, because a backend that silently breaks
 * the day CONFIG_OPENTHREAD_MTD changes is worse than a few bytes of code.
 *
 * Key mapping: OpenThread's native keys are 0x0000..0x00ff and are offset into
 * the reserved ULTRAWIDELOCK_KV_KEY_OPENTHREAD_BASE window, which holds exactly 0x100
 * keys. OpenThread also reserves 0x8000..0xffff for vendor use; that range
 * cannot fit the window, and masking it in would silently alias distinct
 * vendor keys onto each other and onto the native ones. This firmware keeps
 * its own persistent data (the credential provisioning blob) under its own store
 * key rather than behind otPlatSettings, so no vendor key exists here, and any
 * key outside the native range is refused with OT_ERROR_NOT_IMPLEMENTED and a
 * warning. If a vendor key is ever wanted, the window must be widened in
 * ultrawidelock_freertos_kv.h deliberately, not aliased into quietly.
 */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <ultrawidelock_freertos_kv.h>
#include <ultrawidelock_freertos_platform.h>

#include <openthread/dataset.h>
#include <openthread/platform/settings.h>

#define OT_SETTINGS_TAG "ot_settings"

/* Each packed value is preceded by its length, two bytes little-endian. */
#define ENTRY_HEADER 2u

/*
 * The window has to hold every key OpenThread can natively use, and the store
 * has to hold the largest single value the stack can hand us — the Operational
 * Dataset — as one entry of one record. Catch a change to either limit at
 * build time rather than at the first join on a customer's board.
 */
_Static_assert(ULTRAWIDELOCK_KV_KEY_OPENTHREAD_LIMIT - ULTRAWIDELOCK_KV_KEY_OPENTHREAD_BASE >=
		       0x100u,
	       "the reserved key window no longer holds every native OpenThread key");
_Static_assert(ENTRY_HEADER + OT_OPERATIONAL_DATASET_MAX_LENGTH <= ULTRAWIDELOCK_KV_VALUE_MAX,
	       "the largest OpenThread value no longer fits one key-value record");

/*
 * STATIC, not on the stack, for the same reason ultrawidelock_prov_kv.c's buffer is: a
 * record is up to ULTRAWIDELOCK_KV_VALUE_MAX bytes, and that does not fit the
 * port's 4096-byte task stacks alongside the stack's own frames. One buffer is
 * enough because every caller is the serialized OpenThread runtime
 * (openthread_freertos.c), which never runs two settings calls at once.
 */
static uint8_t s_record[ULTRAWIDELOCK_KV_VALUE_MAX];

/* True if the key is native and maps into the reserved window. */
static bool key_maps(uint16_t key, uint16_t *kv_key)
{
	if (key > 0x00ffu) {
		ultrawidelock_freertos_log(ULTRAWIDELOCK_FREERTOS_LOG_WARNING, OT_SETTINGS_TAG,
				 "key 0x%04x is outside the native range; refused",
				 (unsigned)key);
		return false;
	}
	*kv_key = (uint16_t)(ULTRAWIDELOCK_KV_KEY_OPENTHREAD_BASE + key);
	return true;
}

static uint16_t entry_length_at(const uint8_t *header)
{
	return (uint16_t)(header[0] | ((uint16_t)header[1] << 8));
}

static void entry_length_write(uint8_t *header, uint16_t length)
{
	header[0] = (uint8_t)(length & 0xffu);
	header[1] = (uint8_t)(length >> 8);
}

/*
 * Length of the well-formed prefix of a record: whole entries whose declared
 * length fits what was stored. A truncated tail — a header past the end, or an
 * entry running past it — is corruption; the entries in front of it are still
 * good, so they are kept and the tail is dropped, loudly.
 */
static size_t record_well_formed(const uint8_t *record, size_t length)
{
	size_t offset = 0;

	while (length - offset >= ENTRY_HEADER) {
		size_t entry = ENTRY_HEADER + (size_t)entry_length_at(record + offset);

		if (entry > length - offset) {
			break;
		}
		offset += entry;
	}
	return offset;
}

/*
 * Read one key's record into s_record. ULTRAWIDELOCK_KV_OK with *used the well-formed
 * length, ULTRAWIDELOCK_KV_NOT_FOUND, or a negative store error. The buffer is sized to
 * ULTRAWIDELOCK_KV_VALUE_MAX, so no stored record can be too long for it.
 */
static int record_load(uint16_t kv_key, size_t *used)
{
	size_t length = sizeof(s_record);
	int rc = ultrawidelock_kv_init();

	if (rc != ULTRAWIDELOCK_KV_OK) {
		return rc;
	}
	rc = ultrawidelock_kv_get(kv_key, s_record, &length);
	if (rc != ULTRAWIDELOCK_KV_OK) {
		return rc;
	}
	*used = record_well_formed(s_record, length);
	if (*used != length) {
		ultrawidelock_freertos_log(ULTRAWIDELOCK_FREERTOS_LOG_WARNING, OT_SETTINGS_TAG,
				 "record 0x%04x has a malformed tail (%u of %u B); dropped",
				 (unsigned)kv_key, (unsigned)(length - *used), (unsigned)length);
	}
	return ULTRAWIDELOCK_KV_OK;
}

/*
 * Offset of the index-th entry within the well-formed prefix, or false. A
 * negative index never matches the counting cursor, so callers need no guard
 * of their own against one.
 */
static bool record_find(const uint8_t *record, size_t used, int index, size_t *offset)
{
	size_t at = 0;
	int i = 0;

	while (at < used) {
		if (i == index) {
			*offset = at;
			return true;
		}
		at += ENTRY_HEADER + (size_t)entry_length_at(record + at);
		i++;
	}
	return false;
}

static otError store_result(int rc)
{
	if (rc == ULTRAWIDELOCK_KV_OK) {
		return OT_ERROR_NONE;
	}
	if (rc == ULTRAWIDELOCK_KV_FULL) {
		return OT_ERROR_NO_BUFS;
	}
	ultrawidelock_freertos_log(ULTRAWIDELOCK_FREERTOS_LOG_WARNING, OT_SETTINGS_TAG,
				   "kv write rc=%d", rc);
	return OT_ERROR_FAILED;
}

/*
 * The sensitive-key list asks for a secure area this part does not have: every
 * record lands in the same settings region of internal flash, readable by anything
 * that can read flash. Nothing can be done with the list here, so it is
 * ignored; keeping key material out of an attacker's reach is APPROTECT's job.
 */
void otPlatSettingsInit(otInstance *instance, const uint16_t *sensitive_keys,
			uint16_t sensitive_keys_length)
{
	int rc;

	(void)instance;
	(void)sensitive_keys;
	(void)sensitive_keys_length;

	rc = ultrawidelock_kv_init();
	if (rc != ULTRAWIDELOCK_KV_OK) {
		/*
		 * Init returns void, so the failure cannot be reported here; it
		 * is logged, and every later operation fails loudly on its own
		 * mount attempt rather than pretending the store is up.
		 */
		ultrawidelock_freertos_log(ULTRAWIDELOCK_FREERTOS_LOG_ERROR, OT_SETTINGS_TAG,
					   "kv init rc=%d", rc);
	}
}

void otPlatSettingsDeinit(otInstance *instance)
{
	/* The store stays mounted: the credential provisioning backend shares it. */
	(void)instance;
}

otError otPlatSettingsGet(otInstance *instance, uint16_t key, int index, uint8_t *value,
			  uint16_t *value_length)
{
	uint16_t kv_key;
	size_t used = 0;
	size_t offset = 0;
	uint16_t entry_length;
	int rc;

	(void)instance;

	if (!key_maps(key, &kv_key)) {
		return OT_ERROR_NOT_IMPLEMENTED;
	}
	rc = record_load(kv_key, &used);
	if (rc == ULTRAWIDELOCK_KV_NOT_FOUND) {
		return OT_ERROR_NOT_FOUND;
	}
	if (rc != ULTRAWIDELOCK_KV_OK) {
		/*
		 * A store that cannot be read serves nothing. NOT_FOUND is the
		 * one degraded answer the contract offers, and it makes the
		 * stack rebuild the state rather than trust garbage.
		 */
		ultrawidelock_freertos_log(ULTRAWIDELOCK_FREERTOS_LOG_WARNING, OT_SETTINGS_TAG,
					   "kv read rc=%d", rc);
		return OT_ERROR_NOT_FOUND;
	}
	if (!record_find(s_record, used, index, &offset)) {
		return OT_ERROR_NOT_FOUND;
	}
	entry_length = entry_length_at(s_record + offset);
	if (value_length != NULL) {
		if (value != NULL) {
			uint16_t copy = entry_length < *value_length ? entry_length
								     : *value_length;

			memcpy(value, s_record + offset + ENTRY_HEADER, copy);
		}
		/* Always the stored length, so a short read is visible. */
		*value_length = entry_length;
	}
	return OT_ERROR_NONE;
}

otError otPlatSettingsSet(otInstance *instance, uint16_t key, const uint8_t *value,
			  uint16_t value_length)
{
	uint16_t kv_key;

	(void)instance;

	if (!key_maps(key, &kv_key)) {
		return OT_ERROR_NOT_IMPLEMENTED;
	}
	if (value == NULL && value_length != 0u) {
		return OT_ERROR_INVALID_ARGS;
	}
	if (ENTRY_HEADER + (size_t)value_length > sizeof(s_record)) {
		return OT_ERROR_NO_BUFS;
	}

	/* Set replaces every value: the record becomes this one entry. */
	entry_length_write(s_record, value_length);
	if (value_length != 0u) {
		memcpy(s_record + ENTRY_HEADER, value, value_length);
	}
	return store_result(
		ultrawidelock_kv_set(kv_key, s_record, ENTRY_HEADER + (size_t)value_length));
}

otError otPlatSettingsAdd(otInstance *instance, uint16_t key, const uint8_t *value,
			  uint16_t value_length)
{
	uint16_t kv_key;
	size_t used = 0;
	int rc;

	(void)instance;

	if (!key_maps(key, &kv_key)) {
		return OT_ERROR_NOT_IMPLEMENTED;
	}
	if (value == NULL && value_length != 0u) {
		return OT_ERROR_INVALID_ARGS;
	}

	rc = record_load(kv_key, &used);
	if (rc == ULTRAWIDELOCK_KV_NOT_FOUND) {
		/* Absent is the ordinary first Add. */
		used = 0;
	} else if (rc != ULTRAWIDELOCK_KV_OK) {
		ultrawidelock_freertos_log(ULTRAWIDELOCK_FREERTOS_LOG_WARNING, OT_SETTINGS_TAG,
					   "kv read rc=%d", rc);
		return OT_ERROR_FAILED;
	}

	if (used + ENTRY_HEADER + (size_t)value_length > sizeof(s_record)) {
		return OT_ERROR_NO_BUFS;
	}
	entry_length_write(s_record + used, value_length);
	if (value_length != 0u) {
		memcpy(s_record + used + ENTRY_HEADER, value, value_length);
	}
	return store_result(
		ultrawidelock_kv_set(kv_key, s_record, used + ENTRY_HEADER + (size_t)value_length));
}

otError otPlatSettingsDelete(otInstance *instance, uint16_t key, int index)
{
	uint16_t kv_key;
	size_t used = 0;
	size_t offset = 0;
	size_t entry;
	int rc;

	(void)instance;

	if (!key_maps(key, &kv_key)) {
		return OT_ERROR_NOT_IMPLEMENTED;
	}

	if (index == -1) {
		rc = ultrawidelock_kv_init();
		if (rc != ULTRAWIDELOCK_KV_OK) {
			return OT_ERROR_FAILED;
		}
		rc = ultrawidelock_kv_delete(kv_key);
		if (rc == ULTRAWIDELOCK_KV_NOT_FOUND) {
			return OT_ERROR_NOT_FOUND;
		}
		return store_result(rc);
	}

	rc = record_load(kv_key, &used);
	if (rc == ULTRAWIDELOCK_KV_NOT_FOUND) {
		return OT_ERROR_NOT_FOUND;
	}
	if (rc != ULTRAWIDELOCK_KV_OK) {
		ultrawidelock_freertos_log(ULTRAWIDELOCK_FREERTOS_LOG_WARNING, OT_SETTINGS_TAG,
					   "kv read rc=%d", rc);
		return OT_ERROR_FAILED;
	}
	if (!record_find(s_record, used, index, &offset)) {
		return OT_ERROR_NOT_FOUND;
	}

	entry = ENTRY_HEADER + (size_t)entry_length_at(s_record + offset);
	memmove(s_record + offset, s_record + offset + entry, used - offset - entry);
	used -= entry;

	if (used == 0u) {
		/*
		 * The last value is gone: delete the record rather than store
		 * it empty, so the key reads as fully deleted — the state the
		 * stack's Set-after-Delete guarantee is worded around.
		 */
		return store_result(ultrawidelock_kv_delete(kv_key));
	}
	return store_result(ultrawidelock_kv_set(kv_key, s_record, used));
}

/*
 * Factory-reset OpenThread and nothing else. This walks the reserved window
 * and deletes key by key; it must never call ultrawidelock_kv_erase_all(),
 * because the credential provisioning blob lives in the same region and erasing
 * it would take the reader's provisioned identity and trust anchors with it —
 * the mirror of the argument in ultrawidelock_prov_erase(), which spares these keys so
 * a credential factory reset cannot cost the SRP client key and the up-to-14-day
 * lease wait that follows.
 */
void otPlatSettingsWipe(otInstance *instance)
{
	uint16_t kv_key;
	int rc;

	(void)instance;

	rc = ultrawidelock_kv_init();
	if (rc != ULTRAWIDELOCK_KV_OK) {
		ultrawidelock_freertos_log(ULTRAWIDELOCK_FREERTOS_LOG_ERROR, OT_SETTINGS_TAG,
				 "kv init rc=%d; nothing wiped", rc);
		return;
	}
	for (kv_key = ULTRAWIDELOCK_KV_KEY_OPENTHREAD_BASE;
	     kv_key < ULTRAWIDELOCK_KV_KEY_OPENTHREAD_LIMIT; kv_key++) {
		rc = ultrawidelock_kv_delete(kv_key);
		if (rc != ULTRAWIDELOCK_KV_OK && rc != ULTRAWIDELOCK_KV_NOT_FOUND) {
			ultrawidelock_freertos_log(ULTRAWIDELOCK_FREERTOS_LOG_WARNING, OT_SETTINGS_TAG,
					 "wipe: delete 0x%04x rc=%d", (unsigned)kv_key, rc);
		}
	}
	ultrawidelock_freertos_log(ULTRAWIDELOCK_FREERTOS_LOG_WARNING, OT_SETTINGS_TAG,
			 "factory reset: OpenThread settings wiped");
}
