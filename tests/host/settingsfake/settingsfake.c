/*
 * In-RAM stand-in for Zephyr's settings subsystem.
 *
 * Deliberately NOT a simulation of NVS. It reproduces the two behaviours the
 * port's persistence code actually depends on -- a key/value store that
 * survives within a run, and a save that can fail part way through a sequence
 * of them -- and nothing else. Wear levelling, sector garbage collection and
 * the name-id table are the backend's problem, and faking them would only test
 * the fake.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/settings/settings.h>

#include "settingsfake.h"

/* Above kv_zephyr.c's ERASE_BATCH, so a store that needs more than one sweep
 * pass to empty can be built here. At 16 the multi-pass path was unreachable
 * and a single-pass erase would have looked correct. */
#define FAKE_MAX_KEYS 64
#define FAKE_MAX_NAME 64
#define FAKE_MAX_VAL  1088 /* >= ULTRAWIDELOCK_KV_VALUE_MAX: the real NVS backend has no cap this low */

struct fake_entry {
	char name[FAKE_MAX_NAME];
	unsigned char val[FAKE_MAX_VAL];
	size_t len;
	bool used;
};

static struct fake_entry s_store[FAKE_MAX_KEYS];
static const struct settings_handler_static *s_handlers[4];
static int s_n_handlers;
static int s_fail_after = -1;
static int s_fail_reads_after = -1;
static int s_saves;
static int s_deletes;

void settingsfake_register(const struct settings_handler_static *h)
{
	if (s_n_handlers < (int)(sizeof(s_handlers) / sizeof(s_handlers[0]))) {
		s_handlers[s_n_handlers++] = h;
	}
}

void settingsfake_reset(void)
{
	memset(s_store, 0, sizeof(s_store));
	s_fail_after = -1;
	s_fail_reads_after = -1;
	s_saves = 0;
	s_deletes = 0;
	/* Handlers are registered by constructors and outlive a reset, which is
	 * also true of the real static handlers. */
}

void settingsfake_fail_saves_after(int n)
{
	s_fail_after = n;
}

void settingsfake_fail_reads_after(int n)
{
	s_fail_reads_after = n;
}

int settingsfake_save_count(void)
{
	return s_saves;
}

int settingsfake_delete_count(void)
{
	return s_deletes;
}

int settingsfake_key_count(void)
{
	int n = 0;

	for (int i = 0; i < FAKE_MAX_KEYS; i++) {
		if (s_store[i].used) {
			n++;
		}
	}
	return n;
}

static struct fake_entry *find(const char *name)
{
	for (int i = 0; i < FAKE_MAX_KEYS; i++) {
		if (s_store[i].used && strcmp(s_store[i].name, name) == 0) {
			return &s_store[i];
		}
	}
	return NULL;
}

bool settingsfake_has(const char *name)
{
	return find(name) != NULL;
}

bool settingsfake_corrupt(const char *name)
{
	struct fake_entry *e = find(name);

	if (e == NULL || e->len == 0u) {
		return false;
	}
	e->val[e->len - 1u] ^= 0x80u;
	return true;
}

int settings_subsys_init(void)
{
	return 0;
}

int settings_save_one(const char *name, const void *value, size_t val_len)
{
	struct fake_entry *e;

	if (name == NULL || val_len > FAKE_MAX_VAL || strlen(name) >= FAKE_MAX_NAME) {
		return -EINVAL;
	}
	if (s_fail_after >= 0) {
		if (s_fail_after == 0) {
			/* Out of space is the realistic failure on a two-sector
			 * partition, and it is the one the caller must survive. */
			return -ENOSPC;
		}
		s_fail_after--;
	}

	e = find(name);
	if (e == NULL) {
		for (int i = 0; i < FAKE_MAX_KEYS; i++) {
			if (!s_store[i].used) {
				e = &s_store[i];
				break;
			}
		}
	}
	if (e == NULL) {
		return -ENOSPC;
	}

	e->used = true;
	snprintf(e->name, sizeof(e->name), "%s", name);
	memcpy(e->val, value, val_len);
	e->len = val_len;
	s_saves++;
	return 0;
}

int settings_delete(const char *name)
{
	struct fake_entry *e = find(name);

	s_deletes++;
	if (e != NULL) {
		memset(e, 0, sizeof(*e));
	}
	/* Zephyr returns 0 for a name that was never stored, and the port's
	 * erase path depends on that: it deletes every key unconditionally. */
	return 0;
}

/* What the handler is handed to pull its value out. */
struct read_ctx {
	const struct fake_entry *e;
};

static ssize_t fake_read(void *cb_arg, void *data, size_t len)
{
	const struct read_ctx *ctx = cb_arg;
	size_t n = ctx->e->len < len ? ctx->e->len : len;

	if (s_fail_reads_after >= 0) {
		if (s_fail_reads_after == 0) {
			return -EIO;
		}
		s_fail_reads_after--;
	}

	memcpy(data, ctx->e->val, n);
	return (ssize_t)n;
}

int settings_load_subtree(const char *subtree)
{
	size_t tlen;

	if (subtree == NULL) {
		return -EINVAL;
	}
	tlen = strlen(subtree);

	for (int h = 0; h < s_n_handlers; h++) {
		if (strcmp(s_handlers[h]->name, subtree) != 0) {
			continue;
		}
		for (int i = 0; i < FAKE_MAX_KEYS; i++) {
			struct read_ctx ctx;
			const char *leaf;
			int rc;

			if (!s_store[i].used) {
				continue;
			}
			if (strncmp(s_store[i].name, subtree, tlen) != 0 ||
			    s_store[i].name[tlen] != '/') {
				continue;
			}
			leaf = s_store[i].name + tlen + 1;
			ctx.e = &s_store[i];
			rc = s_handlers[h]->h_set(leaf, s_store[i].len, fake_read, &ctx);
			if (rc != 0) {
				/* Zephyr propagates a handler's rejection, and
				 * matter_fab_load() relies on seeing it. */
				return rc;
			}
		}
	}
	return 0;
}

/*
 * Zephyr calls the callback once per record AT OR BELOW the subtree, and a
 * subtree that names a leaf outright is the normal way a caller asks for one
 * value. That case hands the callback an empty key, which is what the port's
 * loaders match on -- so it is reproduced rather than approximated.
 */
int settings_load_subtree_direct(const char *subtree, settings_load_direct_cb cb, void *param)
{
	size_t tlen;

	if (subtree == NULL || cb == NULL) {
		return -EINVAL;
	}
	tlen = strlen(subtree);

	for (int i = 0; i < FAKE_MAX_KEYS; i++) {
		struct read_ctx ctx;
		const char *leaf;
		int rc;

		if (!s_store[i].used || strncmp(s_store[i].name, subtree, tlen) != 0) {
			continue;
		}
		if (s_store[i].name[tlen] == '\0') {
			leaf = "";
		} else if (s_store[i].name[tlen] == '/') {
			leaf = s_store[i].name + tlen + 1;
		} else {
			continue;
		}
		ctx.e = &s_store[i];
		rc = cb(leaf, s_store[i].len, fake_read, &ctx, param);
		if (rc != 0) {
			return rc;
		}
	}
	return 0;
}

int settings_name_steq(const char *name, const char *key, const char **next)
{
	size_t klen = strlen(key);

	if (next != NULL) {
		*next = NULL;
	}
	if (strncmp(name, key, klen) != 0) {
		return 0;
	}
	if (name[klen] == '\0') {
		return 1;
	}
	if (name[klen] == '/') {
		if (next != NULL) {
			*next = name + klen + 1;
		}
		return 1;
	}
	return 0;
}
