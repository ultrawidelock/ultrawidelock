/* SPDX-License-Identifier: ISC */

/**
 * @file matter_binding.h — who this lock should tell, and how it was told to.
 *
 * The Binding cluster (0x001E) is how a Matter client is CONFIGURED rather than
 * programmed: an administrator writes a list of targets onto this node, and the
 * node sends its commands to whatever is in that list. Nothing here is
 * hard-coded to a particular lock, and no automation in a hub is involved --
 * the binding is the whole configuration.
 *
 *   Binding, attribute 0x0000: list[TargetStruct], fabric-scoped, writable
 *
 * TargetStruct is either a unicast target (Node + Endpoint, optionally
 * narrowed to one Cluster) or a Group. This node acts on unicast DoorLock
 * targets and stores the rest without acting on them, because a list is written
 * whole: refusing an entry this node has no use for would fail the entire
 * write, including the entry it does want.
 *
 * FABRIC SCOPING is the part that is easy to get wrong and impossible to see
 * afterwards. The list is per fabric: a write from one administrator replaces
 * that administrator's entries and must leave every other fabric's alone. Get
 * it wrong and adding a second administrator silently unbinds the first.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "matter_status.h"
#include "matter_tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Binding cluster (Binding cluster spec, 9.6). */
#define MATTER_CLUSTER_BINDING 0x001Eu

/** The Binding attribute itself. */
#define MATTER_ATTR_BINDING_LIST 0x0000u

/**
 * How many targets this node stores, across all fabrics.
 *
 * Four rather than one because the list is fabric-scoped, so more than one
 * administrator (MATTER_SUPPORTED_FABRICS) may want an entry, and because a
 * person with a front and a back door has two locks. It is deliberately not
 * derived from MATTER_SUPPORTED_FABRICS: the number that matters is doors this
 * lock opens, and raising the fabric count does not add a door. Beyond that, a
 * write is refused with RESOURCE_EXHAUSTED rather than truncated: a binding
 * list that is silently shorter than what was written is a lock that does not
 * open with no way to see why.
 */
#define MATTER_BINDING_MAX 4u

/**
 * The longest unlock PIN this node will carry for a target.
 *
 * DoorLock's PIN codes are 4 to 8 characters by default and this reserves the
 * maximum. Longer is refused rather than truncated, for the reason a truncated
 * PIN deserves: it fails at the far lock as a wrong credential, which looks
 * like the wrong PIN rather than like a length limit here.
 */
#define MATTER_BINDING_PIN_MAX 8u

/** One entry of the Binding list. */
struct matter_binding_target {
	/** Unicast target. Meaningful only with @ref has_node. */
	uint64_t node_id;
	/** Group target. Stored, never acted on; see the file comment. */
	uint16_t group_id;
	uint16_t endpoint;
	uint32_t cluster;
	bool has_node;
	bool has_group;
	bool has_endpoint;
	bool has_cluster;
	/** Which administrator wrote it. Never read off the wire; see below. */
	uint8_t fabric_index;
};

/** Every target this node holds, for every fabric. */
struct matter_binding_table {
	struct matter_binding_target e[MATTER_BINDING_MAX];
	uint8_t count;
	/**
	 * The unlock PIN, for targets whose RequirePINforRemoteOperation is set.
	 *
	 * ONE PIN FOR THE NODE, not one per target, and that is a real
	 * limitation rather than an oversight. TargetStruct has no field for a
	 * credential -- the spec's binding says WHO to talk to and never HOW to
	 * authenticate -- so this lives in a manufacturer-specific attribute
	 * beside the list instead, and a manufacturer attribute that shadowed
	 * the standard list entry by entry would be a second list to keep in
	 * step with the first. Somebody binding two locks that both demand
	 * different PINs is not served by this; somebody binding one lock is,
	 * and that is the case this exists for.
	 *
	 * THE TRADEOFF, stated plainly: a remote unlock PIN is a shared secret
	 * and this stores it. Anyone who can read this node's flash can read the
	 * PIN of the lock it is bound to. That is why the attribute never reads
	 * back (see matter_binding_read_pin) and why binding a lock that needs
	 * no PIN is the better configuration whenever it is available.
	 */
	uint8_t pin[MATTER_BINDING_PIN_MAX];
	uint8_t pin_len;
};

/**
 * Replace one fabric's entries with the list in @p tlv.
 *
 * The fabric index comes from the SESSION, never from the encoded
 * FabricIndex field: that field is what the node reports when it sends the
 * list back, and a peer that writes one is either confused or claiming to be
 * another administrator. CHIP ignores it on write for exactly this reason.
 *
 * All-or-nothing. A list that does not fit, or an entry that is neither
 * unicast nor group, leaves the table as it was -- a partially applied binding
 * list is a configuration nobody wrote.
 *
 * @param tlv the ARRAY element of the write, already positioned by the caller.
 * @return MATTER_OK; MATTER_E_NOSPACE when the result would exceed
 *         MATTER_BINDING_MAX; MATTER_E_INVAL for a malformed or impossible
 *         entry, or a zero fabric index.
 */
int matter_binding_write(struct matter_binding_table *t, uint8_t fabric_index, const uint8_t *tlv,
			 size_t len);

/** Append one encoded TargetStruct as a Matter list AppendItem operation. */
int matter_binding_append(struct matter_binding_table *t, uint8_t fabric_index,
			  const uint8_t *tlv, size_t len);

/**
 * Encode one fabric's entries as the Binding attribute's value.
 *
 * Only @p fabric_index's own entries, or EVERY fabric's when it is zero, which
 * is what a read with FabricFiltered false asks for. Every entry carries its
 * own FabricIndex either way, so an unfiltered reader can still tell them
 * apart -- that field is why the spec expects cross-fabric reads to work
 * rather than treating them as a disclosure.
 *
 * Writes exactly one element, an ARRAY, tagged @p tag -- an empty one when
 * there is nothing to report, which is a legal and common answer.
 */
void matter_binding_read(const struct matter_binding_table *t, uint8_t fabric_index,
			 struct matter_tlv_writer *w, matter_tlv_tag_t tag);

/**
 * Forget every entry belonging to @p fabric_index.
 *
 * Called when a fabric is removed. A binding that outlives the administrator
 * that wrote it is a lock that keeps unlocking another lock on behalf of
 * somebody who has been removed from the system.
 */
void matter_binding_forget_fabric(struct matter_binding_table *t, uint8_t fabric_index);

/**
 * The next unicast target for @p cluster, at or after index @p *idx.
 *
 * Iteration rather than a single lookup because a person may bind two locks,
 * and both should open. Group entries and entries naming a different cluster
 * are skipped.
 *
 * @param idx in/out cursor; set to 0 to start. Advanced past the entry
 *        returned, so the same call in a loop walks the whole table.
 * @return the entry, or NULL when there are no more.
 */
const struct matter_binding_target *matter_binding_next(const struct matter_binding_table *t,
							uint32_t cluster, uint8_t *idx);

/**
 * The manufacturer-specific attribute carrying the unlock PIN.
 *
 * Manufacturer extensions are identified by the vendor's MEI prefix in the
 * upper 16 bits, which is what keeps this from colliding with a future
 * standard attribute of the Binding cluster (Matter core spec, 7.18.2.25).
 */
#define MATTER_ATTR_BINDING_PIN(vendor_id) ((((uint32_t)(vendor_id)) << 16) | 0x0000u)

/**
 * Store the PIN a bound lock will demand. @p len 0 clears it.
 *
 * @return MATTER_OK, or MATTER_E_INVAL for a PIN longer than
 *         MATTER_BINDING_PIN_MAX -- refused rather than truncated, because a
 *         truncated PIN fails at the far lock as a wrong credential.
 */
int matter_binding_write_pin(struct matter_binding_table *t, const uint8_t *pin, size_t len);

/**
 * Report the PIN attribute, which always reads back as EMPTY.
 *
 * A credential that can be read back is a credential every administrator on the
 * fabric can harvest, and nothing needs to read it: the node uses it, nobody
 * asks it what it is. Writing it and reading nothing back is the same shape
 * DoorLock uses for its own credentials, so a controller is not surprised.
 */
void matter_binding_read_pin(const struct matter_binding_table *t, struct matter_tlv_writer *w,
			     matter_tlv_tag_t tag);

#ifdef __cplusplus
}
#endif
