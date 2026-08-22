/* SPDX-License-Identifier: ISC */

/*
 * See matter_binding.h.
 */
#include "matter_binding.h"

#include <string.h>

/* TargetStruct fields (Binding cluster spec, 9.6.5.1). */
#define TAG_TARGET_NODE     1u
#define TAG_TARGET_GROUP    2u
#define TAG_TARGET_ENDPOINT 3u
#define TAG_TARGET_CLUSTER  4u

/** The fabric index every fabric-scoped struct carries (core spec, 7.13.2). */
#define TAG_FABRIC_INDEX 254u

/** Decode one TargetStruct the reader is sitting on. */
static int take_target(struct matter_tlv_reader *r, struct matter_binding_target *out)
{
	int rc = matter_tlv_enter(r);

	if (rc != MATTER_OK) {
		return rc;
	}
	for (;;) {
		uint64_t v = 0u;

		rc = matter_tlv_next(r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}
		/*
		 * The FabricIndex a peer encoded is READ PAST, not stored. It is
		 * this node's answer when it reports the list, never the peer's
		 * to assert -- see matter_binding_write().
		 */
		if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_FABRIC_INDEX)) {
			continue;
		}
		if (matter_tlv_get_u64(r, &v) != MATTER_OK) {
			return MATTER_E_TYPE;
		}
		if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_TARGET_NODE)) {
			out->node_id = v;
			out->has_node = true;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_TARGET_GROUP)) {
			out->group_id = (uint16_t)v;
			out->has_group = true;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_TARGET_ENDPOINT)) {
			out->endpoint = (uint16_t)v;
			out->has_endpoint = true;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_TARGET_CLUSTER)) {
			out->cluster = (uint32_t)v;
			out->has_cluster = true;
		}
	}
	rc = matter_tlv_exit(r);
	if (rc != MATTER_OK) {
		return rc;
	}

	/*
	 * "Either Node+Endpoint or Group, and not both" is the constraint the
	 * cluster states, and an entry that satisfies neither addresses nothing
	 * at all. Refusing it here is what stops a typo becoming a binding that
	 * exists, reads back, and never fires.
	 */
	if (out->has_group == out->has_node) {
		return MATTER_E_INVAL;
	}
	if (out->has_node && !out->has_endpoint) {
		return MATTER_E_INVAL;
	}
	return MATTER_OK;
}

int matter_binding_write(struct matter_binding_table *t, uint8_t fabric_index, const uint8_t *tlv,
			 size_t len)
{
	/*
	 * Built beside the live table and swapped in at the end, because the
	 * write is all-or-nothing: an entry that fails halfway through must not
	 * leave this node holding half of one administrator's list and half of
	 * the one before it.
	 */
	struct matter_binding_table next;
	struct matter_tlv_reader r;
	int rc;

	if (t == NULL || tlv == NULL || fabric_index == 0u) {
		return MATTER_E_INVAL;
	}

	/* Every OTHER fabric's entries survive untouched. This is the whole of
	 * fabric scoping, and getting it wrong silently unbinds an
	 * administrator the moment a second one writes. */
	memset(&next, 0, sizeof(next));
	memcpy(next.pin, t->pin, sizeof(next.pin));
	next.pin_len = t->pin_len;
	for (uint8_t i = 0u; i < t->count; i++) {
		if (t->e[i].fabric_index != fabric_index) {
			next.e[next.count] = t->e[i];
			next.count++;
		}
	}

	matter_tlv_reader_init(&r, tlv, len);
	rc = matter_tlv_next(&r);
	if (rc != MATTER_OK) {
		return (rc == MATTER_END) ? MATTER_E_INVAL : rc;
	}
	if (matter_tlv_element_type(&r) != MATTER_TLV_ARRAY) {
		return MATTER_E_TYPE;
	}
	rc = matter_tlv_enter(&r);
	if (rc != MATTER_OK) {
		return rc;
	}
	for (;;) {
		struct matter_binding_target one;

		rc = matter_tlv_next(&r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}
		if (matter_tlv_element_type(&r) != MATTER_TLV_STRUCTURE) {
			return MATTER_E_TYPE;
		}
		if (next.count >= MATTER_BINDING_MAX) {
			return MATTER_E_NOSPACE;
		}

		memset(&one, 0, sizeof(one));
		rc = take_target(&r, &one);
		if (rc != MATTER_OK) {
			return rc;
		}
		one.fabric_index = fabric_index;
		next.e[next.count] = one;
		next.count++;
	}
	rc = matter_tlv_exit(&r);
	if (rc != MATTER_OK) {
		return rc;
	}

	*t = next;
	return MATTER_OK;
}

int matter_binding_append(struct matter_binding_table *t, uint8_t fabric_index,
			  const uint8_t *tlv, size_t len)
{
	struct matter_tlv_reader r;
	struct matter_binding_target one;
	int rc;

	if (t == NULL || tlv == NULL || fabric_index == 0u) {
		return MATTER_E_INVAL;
	}
	if (t->count >= MATTER_BINDING_MAX) {
		return MATTER_E_NOSPACE;
	}
	matter_tlv_reader_init(&r, tlv, len);
	if (matter_tlv_next(&r) != MATTER_OK ||
	    matter_tlv_element_type(&r) != MATTER_TLV_STRUCTURE) {
		return MATTER_E_TYPE;
	}
	memset(&one, 0, sizeof(one));
	rc = take_target(&r, &one);
	if (rc != MATTER_OK) {
		return rc;
	}
	one.fabric_index = fabric_index;
	t->e[t->count++] = one;
	return MATTER_OK;
}

void matter_binding_read(const struct matter_binding_table *t, uint8_t fabric_index,
			 struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	if (w == NULL) {
		return;
	}
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
	if (t != NULL) {
		for (uint8_t i = 0u; i < t->count; i++) {
			const struct matter_binding_target *e = &t->e[i];

			/*
			 * Zero enumerates every fabric, which is what an
			 * unfiltered read asks for. Not a magic number that
			 * could one day collide: matter_binding_write() refuses
			 * a zero fabric index, so no stored entry can carry one.
			 */
			if (fabric_index != 0u && e->fabric_index != fabric_index) {
				continue;
			}
			(void)matter_tlv_start_container(w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
			if (e->has_node) {
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_TARGET_NODE),
							 e->node_id);
			}
			if (e->has_group) {
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_TARGET_GROUP),
							 e->group_id);
			}
			if (e->has_endpoint) {
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_TARGET_ENDPOINT),
							 e->endpoint);
			}
			if (e->has_cluster) {
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_TARGET_CLUSTER),
							 e->cluster);
			}
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_FABRIC_INDEX),
						 e->fabric_index);
			(void)matter_tlv_end_container(w);
		}
	}
	(void)matter_tlv_end_container(w);
}

void matter_binding_forget_fabric(struct matter_binding_table *t, uint8_t fabric_index)
{
	uint8_t kept = 0u;

	if (t == NULL) {
		return;
	}
	for (uint8_t i = 0u; i < t->count; i++) {
		if (t->e[i].fabric_index != fabric_index) {
			t->e[kept] = t->e[i];
			kept++;
		}
	}
	/* The tail is cleared rather than merely unreachable: these entries name
	 * a node this administrator is no longer entitled to reach, and leaving
	 * them readable in RAM serves nothing. */
	for (uint8_t i = kept; i < t->count; i++) {
		memset(&t->e[i], 0, sizeof(t->e[i]));
	}
	t->count = kept;

	/* The PIN goes with the last binding. It is the credential of a lock
	 * this node has just been told it may no longer open. */
	if (kept == 0u) {
		memset(t->pin, 0, sizeof(t->pin));
		t->pin_len = 0u;
	}
}

const struct matter_binding_target *matter_binding_next(const struct matter_binding_table *t,
							uint32_t cluster, uint8_t *idx)
{
	if (t == NULL || idx == NULL) {
		return NULL;
	}
	while (*idx < t->count) {
		const struct matter_binding_target *e = &t->e[*idx];

		(*idx)++;
		if (!e->has_node || !e->has_endpoint) {
			continue;
		}
		/*
		 * An entry naming NO cluster binds every cluster on that
		 * endpoint, which includes this one. Skipping it would ignore
		 * the most natural thing an administrator can write.
		 */
		if (e->has_cluster && e->cluster != cluster) {
			continue;
		}
		return e;
	}
	return NULL;
}

int matter_binding_write_pin(struct matter_binding_table *t, const uint8_t *pin, size_t len)
{
	if (t == NULL) {
		return MATTER_E_INVAL;
	}
	if (len > MATTER_BINDING_PIN_MAX || (pin == NULL && len > 0u)) {
		return MATTER_E_INVAL;
	}
	memset(t->pin, 0, sizeof(t->pin));
	if (len > 0u) {
		memcpy(t->pin, pin, len);
	}
	t->pin_len = (uint8_t)len;
	return MATTER_OK;
}

void matter_binding_read_pin(const struct matter_binding_table *t, struct matter_tlv_writer *w,
			     matter_tlv_tag_t tag)
{
	(void)t;
	if (w == NULL) {
		return;
	}
	/* Empty, always. See the header: nothing needs to read this back, and a
	 * credential that reads back is one every administrator can harvest. */
	(void)matter_tlv_put_bytes(w, tag, (const uint8_t *)"", 0u);
}
