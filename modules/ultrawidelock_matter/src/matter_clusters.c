/* SPDX-License-Identifier: ISC */

/*
 * See matter_clusters.h.
 *
 * status() and value() dispatch over the same paths and are kept as two
 * switches rather than one table of function pointers. A table would cost a
 * relocation and an indirect call per attribute on a part where flash is the
 * binding constraint, and the duplication is a case label -- the compiler
 * checks neither way, but a missing case here reads as a missing case.
 */
#include "matter_clusters.h"

#include <stddef.h>
#include <string.h>

/* GeneralCommissioning/Structs.h:41-44 */
#define TAG_BCI_FAILSAFE_EXPIRY 0u
#define TAG_BCI_FAILSAFE_MAX    1u

/* OperationalCredentials Structs.h:43-49, FabricDescriptorStruct. */
#define TAG_FABRIC_ROOT_KEY  1u
#define TAG_FABRIC_VENDOR_ID 2u
#define TAG_FABRIC_FABRIC_ID 3u
#define TAG_FABRIC_NODE_ID   4u
#define TAG_FABRIC_LABEL     5u
/** Every fabric-scoped struct carries this, always at 254. */
#define TAG_FABRIC_INDEX     254u

/* Same header, NOCStruct at :84-87. */
#define TAG_NOC_NOC  1u
#define TAG_NOC_ICAC 2u

/* BasicInformation/Structs.h:43-44, CapabilityMinimaStruct. */
#define TAG_CAPMIN_CASE_SESSIONS 0u
#define TAG_CAPMIN_SUBSCRIPTIONS 1u

/*
 * Strings this node reports about itself. Build-time, not per-device: this port
 * has no factory data partition and no per-board serial to read out of one.
 */
#define MATTER_VENDOR_NAME   "ultrawidelock"
#define MATTER_PRODUCT_NAME  "DWM3001CDK credential Reader"
#define MATTER_SERIAL_NUMBER "DWM3001CDK-0001"

/* Descriptor/Structs.h:43-44, DeviceTypeStruct. */
#define TAG_DEVTYPE_TYPE     0u
#define TAG_DEVTYPE_REVISION 1u

/**
 * Every cluster the root endpoint serves, for Descriptor's ServerList.
 *
 * Descriptor is in it: a controller that reads ServerList and does not find the
 * cluster it just read is entitled to conclude the answer is stale.
 */
/*
 * Installed by the port. Declared up here rather than beside the command
 * handler because the WindowStatus ATTRIBUTE is read far earlier in this file
 * than the commands are dispatched, and a controller reads that attribute to
 * decide whether its own OpenCommissioningWindow worked.
 */
static const struct matter_admin_hooks *s_admin_hooks;

static const uint32_t k_root_servers[] = {
	MATTER_CLUSTER_DESCRIPTOR,
	MATTER_CLUSTER_ACCESS_CONTROL,
	MATTER_CLUSTER_BASIC_INFORMATION,
	MATTER_CLUSTER_GENERAL_COMMISSIONING,
	MATTER_CLUSTER_NETWORK_COMMISSIONING,
	MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
	MATTER_CLUSTER_ADMIN_COMMISSIONING,
};

/**
 * Every cluster the lock endpoint serves.
 *
 * Descriptor again, because every endpoint has one: it is how a controller
 * learns what the endpoint IS without being told where to look.
 */
static const uint32_t k_lock_servers[] = {
	MATTER_CLUSTER_DESCRIPTOR,
	MATTER_CLUSTER_DOOR_LOCK,
	MATTER_CLUSTER_APPROACH_DIRECTION,
#if MATTER_FEATURE_CLIENT
	/*
	 * Advertised as a SERVER even though the point of it is to make this
	 * node a client. Not a contradiction: the Binding cluster's server is
	 * the thing an administrator writes the target list into, and a
	 * controller that cannot find it here has no way to configure the
	 * client at all.
	 */
	MATTER_CLUSTER_BINDING,
#endif
};

/* NetworkInfoStruct (python clusters/Objects.py, NetworkInfoStruct). */
#define TAG_NETINFO_ID        0u
#define TAG_NETINFO_CONNECTED 1u

/**
 * The slot currently being provisioned, allocating one if needed.
 *
 * A commissioner builds a fabric across several commands -- the root arrives
 * before the NOC -- so the half-built slot must survive between them. A slot
 * with a root but no index yet is that one. NULL when every slot is taken,
 * which is what AddNOC reports as TABLE_FULL.
 */
static size_t fabric_pending_slot(struct matter_device_info *info)
{
	size_t i;

	for (i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if ((info->attempt.owned_slots & MATTER_FABRIC_SLOT_BIT(i)) != 0u &&
		    info->fabrics[i].have_root && info->fabrics[i].index == 0u) {
			return i;
		}
	}
	for (i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if ((info->committed_slots & MATTER_FABRIC_SLOT_BIT(i)) == 0u &&
		    (info->attempt.owned_slots & MATTER_FABRIC_SLOT_BIT(i)) == 0u &&
		    !info->fabrics[i].have_root && info->fabrics[i].index == 0u) {
			return i;
		}
	}
	return MATTER_SUPPORTED_FABRICS;
}

static struct matter_fabric *fabric_pending(struct matter_device_info *info, size_t *slot)
{
	size_t i = fabric_pending_slot(info);

	if (i >= MATTER_SUPPORTED_FABRICS) {
		return NULL;
	}
	if (slot != NULL) {
		*slot = i;
	}
	return &info->fabrics[i];
}

static size_t fabric_slot_for_index(const struct matter_device_info *info, uint8_t index)
{
	size_t i;

	for (i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if (info->fabrics[i].index == index &&
		    (info->committed_slots & MATTER_FABRIC_SLOT_BIT(i)) != 0u) {
			return i;
		}
	}
	return MATTER_SUPPORTED_FABRICS;
}

static size_t fabric_slot_for_request(const struct matter_device_info *info, uint8_t index)
{
	size_t i;
	uint8_t visible = info->committed_slots | info->attempt.owned_slots;

	for (i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if ((visible & MATTER_FABRIC_SLOT_BIT(i)) != 0u &&
		    info->fabrics[i].index == index) {
			return i;
		}
	}
	return MATTER_SUPPORTED_FABRICS;
}

#define MATTER_AC_PRIVILEGE_OPERATE     3u
#define MATTER_AC_PRIVILEGE_ADMINISTER  5u
#define MATTER_AC_AUTH_MODE_CASE        2u
#define MATTER_AC_ENTRY_PRIVILEGE_TAG   0u
#define MATTER_AC_ENTRY_AUTH_MODE_TAG   1u
#define MATTER_AC_ENTRY_SUBJECTS_TAG    2u
#define MATTER_AC_ENTRY_TARGETS_TAG     3u
#define MATTER_AC_TARGET_CLUSTER_TAG    0u
#define MATTER_AC_TARGET_ENDPOINT_TAG   1u
#define MATTER_AC_TARGET_DEVICE_TAG     2u
#define MATTER_TLV_NULL_TYPE            0x14u
#define MATTER_DEVICE_TYPE_ROOT_NODE    0x0016u
#define MATTER_DEVICE_TYPE_DOOR_LOCK    0x000Au
#define MATTER_CASE_AUTH_TAG_MASK       UINT64_C(0xFFFFFFFF00000000)
#define MATTER_CASE_AUTH_TAG_PREFIX     UINT64_C(0xFFFFFFFD00000000)

/* A CASE Authenticated Tag subject is 0xFFFFFFFD || identifier || version.
 * The peer's CATs below came from the NOC whose Sigma3 signature was verified. */
static bool acl_subject_matches(uint64_t subject, uint64_t node_id, const uint32_t *cats,
				size_t cat_count)
{
	uint32_t requested;

	if (subject == node_id) {
		return true;
	}
	if ((subject & MATTER_CASE_AUTH_TAG_MASK) != MATTER_CASE_AUTH_TAG_PREFIX) {
		return false;
	}
	requested = (uint32_t)subject;
	for (size_t i = 0u; i < cat_count; i++) {
		/* The high half names the CAT; a newer version satisfies an ACL
		 * written for an older version of the same CAT. */
		if ((cats[i] >> 16) == (requested >> 16) &&
		    (uint16_t)cats[i] >= (uint16_t)requested) {
			return true;
		}
	}
	return false;
}

static bool acl_subjects_match(struct matter_tlv_reader *r, uint64_t node_id,
			       const uint32_t *cats, size_t cat_count)
{
	bool match = false;

	if (matter_tlv_element_type(r) == MATTER_TLV_NULL_TYPE) {
		return true;
	}
	if (!matter_tlv_is_container(r) || matter_tlv_enter(r) != MATTER_OK) {
		return false;
	}
	for (;;) {
		uint64_t subject;
		int rc = matter_tlv_next(r);

		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return false;
		}
		if (matter_tlv_get_u64(r, &subject) == MATTER_OK &&
		    acl_subject_matches(subject, node_id, cats, cat_count)) {
			match = true;
		}
	}
	return matter_tlv_exit(r) == MATTER_OK && match;
}

static uint32_t endpoint_device_type(uint16_t endpoint)
{
	if (endpoint == MATTER_ENDPOINT_ROOT) {
		return MATTER_DEVICE_TYPE_ROOT_NODE;
	}
	if (endpoint == MATTER_ENDPOINT_LOCK) {
		return MATTER_DEVICE_TYPE_DOOR_LOCK;
	}
	return 0u;
}

static bool acl_target_match(struct matter_tlv_reader *r, uint16_t endpoint, uint32_t cluster)
{
	bool match = true;

	if (!matter_tlv_is_container(r) || matter_tlv_enter(r) != MATTER_OK) {
		return false;
	}
	for (;;) {
		uint64_t value;
		matter_tlv_tag_t tag;
		int rc = matter_tlv_next(r);

		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return false;
		}
		tag = matter_tlv_tag(r);
		if (tag != MATTER_TLV_CTX(MATTER_AC_TARGET_CLUSTER_TAG) &&
		    tag != MATTER_TLV_CTX(MATTER_AC_TARGET_ENDPOINT_TAG) &&
		    tag != MATTER_TLV_CTX(MATTER_AC_TARGET_DEVICE_TAG)) {
			continue;
		}
		/* Null means this dimension is unrestricted. */
		if (matter_tlv_element_type(r) == MATTER_TLV_NULL_TYPE) {
			continue;
		}
		if (matter_tlv_get_u64(r, &value) != MATTER_OK) {
			match = false;
			continue;
		}
		if (tag == MATTER_TLV_CTX(MATTER_AC_TARGET_CLUSTER_TAG)) {
			match = match && value == cluster;
		} else if (tag == MATTER_TLV_CTX(MATTER_AC_TARGET_ENDPOINT_TAG)) {
			match = match && value == endpoint;
		} else {
			match = match && endpoint_device_type(endpoint) != 0u &&
				value == endpoint_device_type(endpoint);
		}
	}
	return matter_tlv_exit(r) == MATTER_OK && match;
}

static bool acl_targets_match(struct matter_tlv_reader *r, uint16_t endpoint, uint32_t cluster)
{
	bool match = false;

	if (matter_tlv_element_type(r) == MATTER_TLV_NULL_TYPE) {
		return true;
	}
	if (!matter_tlv_is_container(r) || matter_tlv_enter(r) != MATTER_OK) {
		return false;
	}
	for (;;) {
		int rc = matter_tlv_next(r);

		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return false;
		}
		if (acl_target_match(r, endpoint, cluster)) {
			match = true;
		}
	}
	return matter_tlv_exit(r) == MATTER_OK && match;
}

static bool acl_entry_grants(struct matter_tlv_reader *r, uint64_t node_id,
			     const uint32_t *cats, size_t cat_count,
			     uint8_t required_privilege, uint16_t endpoint, uint32_t cluster)
{
	uint64_t privilege = 0u;
	uint64_t auth_mode = 0u;
	bool have_privilege = false;
	bool have_auth_mode = false;
	bool subjects_match = false;
	bool targets_match = false;

	if (!matter_tlv_is_container(r) || matter_tlv_enter(r) != MATTER_OK) {
		return false;
	}
	for (;;) {
		matter_tlv_tag_t tag;
		int rc = matter_tlv_next(r);

		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return false;
		}
		tag = matter_tlv_tag(r);
		if (tag == MATTER_TLV_CTX(MATTER_AC_ENTRY_PRIVILEGE_TAG)) {
			have_privilege = matter_tlv_get_u64(r, &privilege) == MATTER_OK;
		} else if (tag == MATTER_TLV_CTX(MATTER_AC_ENTRY_AUTH_MODE_TAG)) {
			have_auth_mode = matter_tlv_get_u64(r, &auth_mode) == MATTER_OK;
		} else if (tag == MATTER_TLV_CTX(MATTER_AC_ENTRY_SUBJECTS_TAG)) {
			subjects_match = acl_subjects_match(r, node_id, cats, cat_count);
		} else if (tag == MATTER_TLV_CTX(MATTER_AC_ENTRY_TARGETS_TAG)) {
			targets_match = acl_targets_match(r, endpoint, cluster);
		}
	}
	if (matter_tlv_exit(r) != MATTER_OK) {
		return false;
	}
	return have_privilege && privilege >= required_privilege && have_auth_mode &&
	       auth_mode == MATTER_AC_AUTH_MODE_CASE && subjects_match && targets_match;
}

static bool fabric_slot_has_privilege(const struct matter_device_info *info, size_t slot,
			      uint8_t required_privilege, uint16_t endpoint,
			      uint32_t cluster)
{
	struct matter_tlv_reader r;

	if (slot >= MATTER_SUPPORTED_FABRICS || info->accessing_node_id == 0u) {
		return false;
	}
	/* Bootstrap authority from AddNOC. It remains a recovery administrator
	 * even if a later malformed ACL would otherwise lock every controller out. */
	if (info->fabrics[slot].case_admin_subject != 0u &&
	    acl_subject_matches(info->fabrics[slot].case_admin_subject,
				info->accessing_node_id, info->accessing_cats,
				info->accessing_cat_count)) {
		return true;
	}
	if (info->fabric_acls[slot].len == 0u) {
		return false;
	}
	matter_tlv_reader_init(&r, info->fabric_acls[slot].data,
			       info->fabric_acls[slot].len);
	if (matter_tlv_next(&r) != MATTER_OK || !matter_tlv_is_container(&r) ||
	    matter_tlv_enter(&r) != MATTER_OK) {
		return false;
	}
	for (;;) {
		int rc = matter_tlv_next(&r);

		if (rc == MATTER_END) {
			(void)matter_tlv_exit(&r);
			return false;
		}
		if (rc != MATTER_OK) {
			return false;
		}
		if (acl_entry_grants(&r, info->accessing_node_id, info->accessing_cats,
				     info->accessing_cat_count, required_privilege,
				     endpoint, cluster)) {
			return true;
		}
	}
}

/** How many fabrics hold a complete identity. */
static uint8_t fabric_count(const struct matter_device_info *info)
{
	uint8_t n = 0u;
	size_t i;

	for (i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if ((info->committed_slots & MATTER_FABRIC_SLOT_BIT(i)) != 0u &&
		    info->fabrics[i].index != 0u) {
			n++;
		}
	}
	return n;
}

static int fabric_store(struct matter_device_info *info,
			enum matter_fabric_store_operation operation, size_t slot,
			const uint8_t *value, size_t value_len)
{
	if (info->commissioning_hooks == NULL ||
	    info->commissioning_hooks->fabric_store == NULL) {
		return MATTER_OK;
	}
	return info->commissioning_hooks->fabric_store(
		info->commissioning_hooks->ctx, info, operation, (uint8_t)slot, value,
		value_len);
}

static void fabric_slot_clear(struct matter_device_info *info, size_t slot)
{
	struct matter_fabric *f;

	if (slot >= MATTER_SUPPORTED_FABRICS) {
		return;
	}
	f = &info->fabrics[slot];
	if (f->index != 0u) {
		char iname[MATTER_INSTANCE_NAME_LEN];

		if (matter_fabric_instance_name(f, iname, sizeof(iname)) == MATTER_OK) {
			(void)matter_thread_unadvertise(iname);
		}
	}
	if (info->icac.owner_index == f->index) {
		memset(&info->icac, 0, sizeof(info->icac));
	}
	memset(&info->fabric_acls[slot], 0, sizeof(info->fabric_acls[slot]));
#if MATTER_FEATURE_CLIENT
	/*
	 * And the bindings this administrator wrote. A binding that outlives
	 * the fabric it belongs to is this lock still unlocking another lock on
	 * behalf of somebody who has been removed from the system -- and there
	 * is nothing left in the table to say who asked for it. Here rather
	 * than at RemoveFabric because a rolled-back attempt wipes a slot too,
	 * and a provisional administrator can write a binding before it fails.
	 */
	matter_binding_forget_fabric(&info->binding, f->index);
#endif
	memset(f, 0, sizeof(*f));
	info->attempt.owned_slots &= (uint8_t)~MATTER_FABRIC_SLOT_BIT(slot);
	info->committed_slots &= (uint8_t)~MATTER_FABRIC_SLOT_BIT(slot);
}

/**
 * The lowest index not already taken. Indices are 1-based on the wire.
 *
 * Kept in one place because an off-by-one here reports one fabric's
 * certificate under another's index, which no peer can detect.
 */
static uint8_t fabric_next_index(const struct matter_device_info *info)
{
	uint8_t want;

	for (want = 1u; want <= MATTER_SUPPORTED_FABRICS; want++) {
		bool taken = false;
		size_t i;

		for (i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
			if (info->fabrics[i].index == want) {
				taken = true;
			}
		}
		if (!taken) {
			return want;
		}
	}
	return 0u;
}

/**
 * Check whether a given cluster is present on a given endpoint. Returns true if the cluster is
 * supported on that endpoint, false otherwise.
 */
static bool has_cluster(void *ctx, uint16_t endpoint, uint32_t cluster)
{
	(void)ctx;

	if (endpoint == MATTER_ENDPOINT_LOCK) {
		return cluster == MATTER_CLUSTER_DESCRIPTOR ||
		       cluster == MATTER_CLUSTER_DOOR_LOCK ||
#if MATTER_FEATURE_CLIENT
		       cluster == MATTER_CLUSTER_BINDING ||
#endif
		       cluster == MATTER_CLUSTER_APPROACH_DIRECTION;
	}
	if (endpoint != MATTER_ENDPOINT_ROOT) {
		return false;
	}
	return cluster == MATTER_CLUSTER_BASIC_INFORMATION ||
	       cluster == MATTER_CLUSTER_GENERAL_COMMISSIONING ||
	       cluster == MATTER_CLUSTER_NETWORK_COMMISSIONING ||
	       cluster == MATTER_CLUSTER_DESCRIPTOR || cluster == MATTER_CLUSTER_ACCESS_CONTROL ||
	       cluster == MATTER_CLUSTER_OPERATIONAL_CREDENTIALS ||
	       cluster == MATTER_CLUSTER_ADMIN_COMMISSIONING;
}

/*
 * Every endpoint.
 *
 * This exists because Apple reads NetworkCommissioning with the endpoint
 * WILDCARDED, so a node that cannot expand an endpoint wildcard looks like a
 * node with no network interface anywhere -- which is where commissioning
 * stopped before this. Endpoint 1 is the Door Lock, and it must appear here as
 * well as in the root's PartsList: a wildcard read walks THIS list, so an
 * endpoint missing from it is invisible no matter what PartsList claims.
 */
static const uint16_t k_endpoints[] = {
	MATTER_ENDPOINT_ROOT,
	MATTER_ENDPOINT_LOCK,
};

/**
 * Return the list of endpoint IDs this device exposes.
 */
static size_t list_endpoints(void *ctx, const uint16_t **out)
{
	(void)ctx;

	*out = k_endpoints;
	return sizeof(k_endpoints) / sizeof(k_endpoints[0]);
}

/**
 * Query whether an attribute on a given endpoint and cluster is supported. Returns
 * MATTER_IM_STATUS_SUCCESS if supported, MATTER_IM_STATUS_UNSUPPORTED_ENDPOINT if the endpoint does
 * not exist, MATTER_IM_STATUS_UNSUPPORTED_CLUSTER if the cluster does not exist on that endpoint,
 * or MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE if the attribute does not exist on that cluster.
 */
static uint8_t attr_status(void *ctx, uint16_t endpoint, uint32_t cluster, uint32_t attribute)
{
	(void)ctx;

	/*
	 * Endpoint, then cluster, then attribute. The ORDER is the answer:
	 * MetadataLookup.cpp:68-88 reports the outermost thing that is missing,
	 * so a bad endpoint must not be reported as a bad attribute.
	 */
	if (endpoint == MATTER_ENDPOINT_LOCK) {
		if (cluster == MATTER_CLUSTER_DESCRIPTOR) {
			switch (attribute) {
			case MATTER_ATTR_DESC_DEVICE_TYPE_LIST:
			case MATTER_ATTR_DESC_SERVER_LIST:
			case MATTER_ATTR_DESC_CLIENT_LIST:
			case MATTER_ATTR_DESC_PARTS_LIST:
				return MATTER_IM_STATUS_SUCCESS;
			default:
				return MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE;
			}
		}
#if MATTER_FEATURE_CLIENT
		if (cluster == MATTER_CLUSTER_BINDING) {
			const struct matter_device_info *info =
				(const struct matter_device_info *)ctx;

			/*
			 * The one place in this function that reads ctx, and it
			 * has to: the PIN attribute's id is built from this
			 * node's vendor id (MATTER_ATTR_BINDING_PIN), so there
			 * is no constant to put in a case label. A node with no
			 * vendor id has no such attribute rather than one at
			 * 0x0000, which is the standard list.
			 */
			if (info != NULL && info->vendor_id != 0u &&
			    attribute == MATTER_ATTR_BINDING_PIN(info->vendor_id)) {
				return MATTER_IM_STATUS_SUCCESS;
			}
			switch (attribute) {
			case MATTER_ATTR_BINDING_LIST:
			case MATTER_ATTR_FEATURE_MAP:
			case MATTER_ATTR_CLUSTER_REVISION:
			case MATTER_ATTR_ATTRIBUTE_LIST:
			case MATTER_ATTR_ACCEPTED_CMD_LIST:
			case MATTER_ATTR_GENERATED_CMD_LIST:
				return MATTER_IM_STATUS_SUCCESS;
			default:
				return MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE;
			}
		}
#endif
		if (cluster == MATTER_CLUSTER_APPROACH_DIRECTION) {
			switch (attribute) {
			case MATTER_ATTR_APPROACH_DIRECTION:
			case MATTER_ATTR_FEATURE_MAP:
			case MATTER_ATTR_CLUSTER_REVISION:
			case MATTER_ATTR_ATTRIBUTE_LIST:
			case MATTER_ATTR_ACCEPTED_CMD_LIST:
			case MATTER_ATTR_GENERATED_CMD_LIST:
				return MATTER_IM_STATUS_SUCCESS;
			default:
				return MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE;
			}
		}
		if (cluster != MATTER_CLUSTER_DOOR_LOCK) {
			return MATTER_IM_STATUS_UNSUPPORTED_CLUSTER;
		}
		switch (attribute) {
		case MATTER_ATTR_DL_LOCK_STATE:
		case MATTER_ATTR_DL_LOCK_TYPE:
		case MATTER_ATTR_DL_ACTUATOR_ENABLED:
		case MATTER_ATTR_DL_AUTO_RELOCK_TIME:
		case MATTER_ATTR_DL_OPERATING_MODE:
		case MATTER_ATTR_DL_SUPPORTED_OPERATING_MODES:
		case MATTER_ATTR_DL_ALIRO_VERIFICATION_KEY:
		case MATTER_ATTR_DL_ALIRO_GROUP_ID:
		case MATTER_ATTR_DL_ALIRO_GROUP_SUB_ID:
		case MATTER_ATTR_DL_ALIRO_EXPEDITED_VERSIONS:
		case MATTER_ATTR_DL_ALIRO_GROUP_RESOLVING_KEY:
		case MATTER_ATTR_DL_ALIRO_BLE_UWB_VERSIONS:
		case MATTER_ATTR_DL_ALIRO_BLE_ADV_VERSION:
		case MATTER_ATTR_DL_ALIRO_ISSUER_KEYS_MAX:
		case MATTER_ATTR_DL_ALIRO_ENDPOINT_KEYS_MAX:
		case MATTER_ATTR_DL_USERS_MAX:
		case MATTER_ATTR_DL_CREDS_PER_USER_MAX:
		case MATTER_ATTR_DL_CREDENTIAL_RULES:
		/*
		 * FeatureMap is answered here for the same reason it is on
		 * NetworkCommissioning: it is what a controller reads to decide
		 * whether this lock is a credential reader, and without it the
		 * credential attributes below look like a lock that answers
		 * questions nobody asked.
		 */
		case MATTER_ATTR_FEATURE_MAP:
		/*
		 * The remaining globals, on this cluster only: the CHIP builds
		 * answer them everywhere, and Apple Home's optional lock
		 * controls (auto-lock timing, access management) appear on
		 * those builds and not on this one. See the note in
		 * matter_clusters.h at MATTER_ATTR_CLUSTER_REVISION.
		 */
		case MATTER_ATTR_CLUSTER_REVISION:
		case MATTER_ATTR_ATTRIBUTE_LIST:
		case MATTER_ATTR_ACCEPTED_CMD_LIST:
		case MATTER_ATTR_GENERATED_CMD_LIST:
			return MATTER_IM_STATUS_SUCCESS;
		default:
			return MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE;
		}
	}
	if (endpoint != MATTER_ENDPOINT_ROOT) {
		return MATTER_IM_STATUS_UNSUPPORTED_ENDPOINT;
	}

	switch (cluster) {
	case MATTER_CLUSTER_BASIC_INFORMATION:
		switch (attribute) {
		case MATTER_ATTR_BASIC_DATA_MODEL_REVISION:
		case MATTER_ATTR_BASIC_VENDOR_NAME:
		case MATTER_ATTR_BASIC_VENDOR_ID:
		case MATTER_ATTR_BASIC_PRODUCT_NAME:
		case MATTER_ATTR_BASIC_PRODUCT_ID:
		case MATTER_ATTR_BASIC_NODE_LABEL:
		case MATTER_ATTR_BASIC_LOCATION:
		case MATTER_ATTR_BASIC_HARDWARE_VERSION:
		case MATTER_ATTR_BASIC_HARDWARE_VERSION_STR:
		case MATTER_ATTR_BASIC_SOFTWARE_VERSION:
		case MATTER_ATTR_BASIC_SOFTWARE_VERSION_STR:
		case MATTER_ATTR_BASIC_SERIAL_NUMBER:
		case MATTER_ATTR_BASIC_UNIQUE_ID:
		case MATTER_ATTR_BASIC_CAPABILITY_MINIMA:
		case MATTER_ATTR_BASIC_SPECIFICATION_VERSION:
		case MATTER_ATTR_BASIC_MAX_PATHS_PER_INVOKE:
			return MATTER_IM_STATUS_SUCCESS;
		default:
			return MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE;
		}
	case MATTER_CLUSTER_NETWORK_COMMISSIONING:
		switch (attribute) {
		case MATTER_ATTR_NC_MAX_NETWORKS:
		case MATTER_ATTR_NC_NETWORKS:
		case MATTER_ATTR_NC_SCAN_MAX_TIME_S:
		case MATTER_ATTR_NC_CONNECT_MAX_TIME_S:
		case MATTER_ATTR_NC_INTERFACE_ENABLED:
		case MATTER_ATTR_NC_LAST_NETWORKING_STATUS:
		case MATTER_ATTR_FEATURE_MAP:
			return MATTER_IM_STATUS_SUCCESS;
		default:
			return MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE;
		}
	case MATTER_CLUSTER_DESCRIPTOR:
		switch (attribute) {
		case MATTER_ATTR_DESC_DEVICE_TYPE_LIST:
		case MATTER_ATTR_DESC_SERVER_LIST:
		case MATTER_ATTR_DESC_CLIENT_LIST:
		case MATTER_ATTR_DESC_PARTS_LIST:
			return MATTER_IM_STATUS_SUCCESS;
		default:
			return MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE;
		}
	case MATTER_CLUSTER_ACCESS_CONTROL:
		switch (attribute) {
		case MATTER_ATTR_AC_ACL:
		case MATTER_ATTR_AC_SUBJECTS_PER_ENTRY:
		case MATTER_ATTR_AC_TARGETS_PER_ENTRY:
		case MATTER_ATTR_AC_ENTRIES_PER_FABRIC:
			return MATTER_IM_STATUS_SUCCESS;
		default:
			return MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE;
		}
	case MATTER_CLUSTER_ADMIN_COMMISSIONING:
		switch (attribute) {
		case MATTER_ATTR_ADMIN_WINDOW_STATUS:
		case MATTER_ATTR_ADMIN_FABRIC_INDEX:
		case MATTER_ATTR_ADMIN_VENDOR_ID:
			return MATTER_IM_STATUS_SUCCESS;
		default:
			return MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE;
		}
	case MATTER_CLUSTER_OPERATIONAL_CREDENTIALS:
		switch (attribute) {
		case MATTER_ATTR_OC_NOCS:
		case MATTER_ATTR_OC_FABRICS:
		case MATTER_ATTR_OC_SUPPORTED_FABRICS:
		case MATTER_ATTR_OC_COMMISSIONED_FABRICS:
		case MATTER_ATTR_OC_TRUSTED_ROOTS:
		case MATTER_ATTR_OC_CURRENT_FABRIC_INDEX:
			return MATTER_IM_STATUS_SUCCESS;
		default:
			return MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE;
		}
	case MATTER_CLUSTER_GENERAL_COMMISSIONING:
		switch (attribute) {
		case MATTER_ATTR_GC_BREADCRUMB:
		case MATTER_ATTR_GC_BASIC_COMMISSIONING_INFO:
		case MATTER_ATTR_GC_REGULATORY_CONFIG:
		case MATTER_ATTR_GC_LOCATION_CAPABILITY:
		case MATTER_ATTR_GC_SUPPORTS_CONCURRENT_CONNECTION:
			return MATTER_IM_STATUS_SUCCESS;
		default:
			/*
			 * IsCommissioningWithoutPower (0x000C) lands here, and a
			 * real iPhone does ask for it. Saying UNSUPPORTED
			 * ATTRIBUTE is the correct answer for a node that does
			 * not implement it, and the commissioner carries on.
			 */
			return MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE;
		}
	default:
		return MATTER_IM_STATUS_UNSUPPORTED_CLUSTER;
	}
}

/**
 * One credential protocol version, as the two big-endian bytes the spec asks for.
 *
 * Both version lists carry the same single entry, so they share this. The
 * ESP32 lock encodes it the same way (ultrawidelock_reader_delegate.cpp:106-115) and
 * that is the port Apple Home has actually provisioned.
 */
static void put_protocol_version_list(struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	const uint8_t version[2] = {
		(uint8_t)(MATTER_ALIRO_PROTOCOL_VERSION >> 8),
		(uint8_t)(MATTER_ALIRO_PROTOCOL_VERSION & 0xFFu),
	};

	(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
	(void)matter_tlv_put_bytes(w, MATTER_TLV_ANON, version, sizeof(version));
	(void)matter_tlv_end_container(w);
}

/*
 * FeatureMap leads, because it is the attribute that decides what the rest
 * mean: without the two credential bits a controller reads 0x0080..0x0088 as
 * attributes a lock has no business answering. The four other globals close
 * the list, and the list includes them because it IS AttributeList: the same
 * array expands a wildcard and answers 0xFFFB, so the two cannot disagree
 * about what this cluster carries.
 */
static const uint32_t k_lock_attrs[] = {
	MATTER_ATTR_FEATURE_MAP,
	MATTER_ATTR_DL_LOCK_STATE,
	MATTER_ATTR_DL_LOCK_TYPE,
	MATTER_ATTR_DL_ACTUATOR_ENABLED,
	MATTER_ATTR_DL_AUTO_RELOCK_TIME,
	MATTER_ATTR_DL_OPERATING_MODE,
	MATTER_ATTR_DL_SUPPORTED_OPERATING_MODES,
	MATTER_ATTR_DL_ALIRO_VERIFICATION_KEY,
	MATTER_ATTR_DL_ALIRO_GROUP_ID,
	MATTER_ATTR_DL_ALIRO_GROUP_SUB_ID,
	MATTER_ATTR_DL_ALIRO_EXPEDITED_VERSIONS,
	MATTER_ATTR_DL_ALIRO_GROUP_RESOLVING_KEY,
	MATTER_ATTR_DL_ALIRO_BLE_UWB_VERSIONS,
	MATTER_ATTR_DL_ALIRO_BLE_ADV_VERSION,
	MATTER_ATTR_DL_ALIRO_ISSUER_KEYS_MAX,
	MATTER_ATTR_DL_ALIRO_ENDPOINT_KEYS_MAX,
	MATTER_ATTR_DL_USERS_MAX,
	MATTER_ATTR_DL_CREDS_PER_USER_MAX,
	MATTER_ATTR_DL_CREDENTIAL_RULES,
	MATTER_ATTR_CLUSTER_REVISION,
	MATTER_ATTR_ATTRIBUTE_LIST,
	MATTER_ATTR_ACCEPTED_CMD_LIST,
	MATTER_ATTR_GENERATED_CMD_LIST,
};

/*
 * AcceptedCommandList / GeneratedCommandList: exactly what command() below
 * dispatches and what it answers with. An id here that command() refuses
 * invites an invoke that earns UNSUPPORTED_COMMAND, so the three must agree.
 */
static const uint32_t k_lock_accepted_cmds[] = {
	MATTER_CMD_DL_LOCK_DOOR,
	MATTER_CMD_DL_UNLOCK_DOOR,
	MATTER_CMD_DL_SET_USER,
	MATTER_CMD_DL_GET_USER,
	MATTER_CMD_DL_CLEAR_USER,
	MATTER_CMD_DL_SET_CREDENTIAL,
	MATTER_CMD_DL_GET_CREDENTIAL_STATUS,
	MATTER_CMD_DL_CLEAR_CREDENTIAL,
	MATTER_CMD_DL_SET_ALIRO_READER_CONFIG,
};

static const uint32_t k_lock_generated_cmds[] = {
	MATTER_CMD_DL_GET_USER_RESPONSE,
	MATTER_CMD_DL_SET_CREDENTIAL_RESPONSE,
	MATTER_CMD_DL_GET_CREDENTIAL_STATUS_RESPONSE,
};

static const uint32_t k_approach_attrs[] = {
	MATTER_ATTR_APPROACH_DIRECTION,
	MATTER_ATTR_FEATURE_MAP,
	MATTER_ATTR_CLUSTER_REVISION,
	MATTER_ATTR_ATTRIBUTE_LIST,
	MATTER_ATTR_ACCEPTED_CMD_LIST,
	MATTER_ATTR_GENERATED_CMD_LIST,
};

#if MATTER_FEATURE_CLIENT
/*
 * The manufacturer-specific PIN attribute is deliberately NOT in this list.
 *
 * Its id depends on info->vendor_id and so could not sit in a static array
 * anyway, but the reason to leave it out is the better one: it never reads back
 * (see matter_binding_read_pin), and an AttributeList naming an attribute whose
 * every read is empty invites a controller to keep asking a question this node
 * has already decided not to answer.
 */
static const uint32_t k_binding_attrs[] = {
	MATTER_ATTR_BINDING_LIST,
	MATTER_ATTR_FEATURE_MAP,
	MATTER_ATTR_CLUSTER_REVISION,
	MATTER_ATTR_ATTRIBUTE_LIST,
	MATTER_ATTR_ACCEPTED_CMD_LIST,
	MATTER_ATTR_GENERATED_CMD_LIST,
};
#endif

/** An array attribute whose members are bare unsigned ids; NULL/0 is legal
 * and encodes the empty list, which is how a cluster says "no commands". */
static void put_id_list(struct matter_tlv_writer *w, matter_tlv_tag_t tag, const uint32_t *ids,
			size_t count)
{
	size_t i;

	(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
	for (i = 0u; i < count; i++) {
		(void)matter_tlv_put_u64(w, MATTER_TLV_ANON, ids[i]);
	}
	(void)matter_tlv_end_container(w);
}

/**
 * Endpoint 1: the Door Lock and its own Descriptor.
 *
 * Split out rather than folded into attr_value() because the two endpoints
 * share cluster IDs -- Descriptor is on both -- and a single flat switch on
 * cluster would answer the root's Descriptor for the lock.
 */
static void lock_attr_value(const struct matter_device_info *info, uint32_t cluster,
			    uint32_t attribute, bool fabric_filtered,
			    struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	size_t i;

	if (cluster == MATTER_CLUSTER_DESCRIPTOR) {
		switch (attribute) {
		case MATTER_ATTR_DESC_DEVICE_TYPE_LIST:
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			(void)matter_tlv_start_container(w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_DEVTYPE_TYPE),
						 MATTER_DEVICE_TYPE_DOOR_LOCK);
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_DEVTYPE_REVISION),
						 MATTER_DEVICE_TYPE_LOCK_REV);
			(void)matter_tlv_end_container(w);
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_DESC_SERVER_LIST:
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			for (i = 0u; i < sizeof(k_lock_servers) / sizeof(k_lock_servers[0]); i++) {
				(void)matter_tlv_put_u64(w, MATTER_TLV_ANON, k_lock_servers[i]);
			}
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_DESC_CLIENT_LIST:
		case MATTER_ATTR_DESC_PARTS_LIST:
			/* A leaf endpoint: nothing hangs off it and it binds
			 * nothing as a client. */
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			(void)matter_tlv_end_container(w);
			return;
		default:
			return;
		}
	}

#if MATTER_FEATURE_CLIENT
	if (cluster == MATTER_CLUSTER_BINDING) {
		/*
		 * The list first, so a node whose vendor id is still 0 cannot
		 * have MATTER_ATTR_BINDING_PIN(0) -- which is 0x0000 -- shadow
		 * the standard attribute that shares that number.
		 */
		if (attribute == MATTER_ATTR_BINDING_LIST) {
			/*
			 * Zero means every fabric. A controller building its
			 * device model reads wildcards unfiltered, and a
			 * fabric-scoped list that answered those with one
			 * fabric's entries would describe this cluster as empty
			 * to everybody who did not already know what to ask
			 * for. Nothing is protected by refusing: the privilege
			 * gate above already required Administer, and a peer
			 * holding that can write this list and unlock the door.
			 */
			matter_binding_read(&info->binding,
					    fabric_filtered ? info->accessing_fabric_index : 0u,
					    w, tag);
			return;
		}
		if (info->vendor_id != 0u &&
		    attribute == MATTER_ATTR_BINDING_PIN(info->vendor_id)) {
			matter_binding_read_pin(&info->binding, w, tag);
			return;
		}
		switch (attribute) {
		case MATTER_ATTR_FEATURE_MAP:
			/* The cluster defines no features. */
			(void)matter_tlv_put_u64(w, tag, 0u);
			return;
		case MATTER_ATTR_CLUSTER_REVISION:
			(void)matter_tlv_put_u64(w, tag, MATTER_BINDING_CLUSTER_REV);
			return;
		case MATTER_ATTR_ATTRIBUTE_LIST:
			put_id_list(w, tag, k_binding_attrs,
				    sizeof(k_binding_attrs) / sizeof(k_binding_attrs[0]));
			return;
		case MATTER_ATTR_ACCEPTED_CMD_LIST:
		case MATTER_ATTR_GENERATED_CMD_LIST:
			/* A list and nothing else: the cluster has no commands. */
			put_id_list(w, tag, NULL, 0u);
			return;
		default:
			return;
		}
	}
#endif

	if (cluster == MATTER_CLUSTER_APPROACH_DIRECTION) {
		switch (attribute) {
		case MATTER_ATTR_APPROACH_DIRECTION:
			(void)matter_tlv_put_u64(w, tag, info->approach_direction);
			return;
		case MATTER_ATTR_FEATURE_MAP:
			(void)matter_tlv_put_u64(w, tag, 0u);
			return;
		case MATTER_ATTR_CLUSTER_REVISION:
			(void)matter_tlv_put_u64(w, tag, MATTER_APPROACH_DIRECTION_CLUSTER_REV);
			return;
		case MATTER_ATTR_ATTRIBUTE_LIST:
			put_id_list(w, tag, k_approach_attrs,
				    sizeof(k_approach_attrs) / sizeof(k_approach_attrs[0]));
			return;
		case MATTER_ATTR_ACCEPTED_CMD_LIST:
		case MATTER_ATTR_GENERATED_CMD_LIST:
			/* Three attributes and nothing else: no commands. */
			put_id_list(w, tag, NULL, 0u);
			return;
		default:
			return;
		}
	}

	if (cluster != MATTER_CLUSTER_DOOR_LOCK) {
		return;
	}

	switch (attribute) {
	case MATTER_ATTR_FEATURE_MAP:
		(void)matter_tlv_put_u64(w, tag,
					 MATTER_DL_FEATURE_ALIRO_PROVISIONING |
						 MATTER_DL_FEATURE_ALIRO_BLE_UWB |
						 MATTER_DL_FEATURE_USER);
		return;
	case MATTER_ATTR_CLUSTER_REVISION:
		(void)matter_tlv_put_u64(w, tag, MATTER_DL_CLUSTER_REVISION);
		return;
	case MATTER_ATTR_ATTRIBUTE_LIST:
		put_id_list(w, tag, k_lock_attrs, sizeof(k_lock_attrs) / sizeof(k_lock_attrs[0]));
		return;
	case MATTER_ATTR_ACCEPTED_CMD_LIST:
		put_id_list(w, tag, k_lock_accepted_cmds,
			    sizeof(k_lock_accepted_cmds) / sizeof(k_lock_accepted_cmds[0]));
		return;
	case MATTER_ATTR_GENERATED_CMD_LIST:
		put_id_list(w, tag, k_lock_generated_cmds,
			    sizeof(k_lock_generated_cmds) / sizeof(k_lock_generated_cmds[0]));
		return;
	case MATTER_ATTR_DL_USERS_MAX:
		(void)matter_tlv_put_u64(w, tag, MATTER_DL_USERS_MAX);
		return;
	case MATTER_ATTR_DL_CREDS_PER_USER_MAX:
		(void)matter_tlv_put_u64(w, tag, MATTER_DL_CREDS_PER_USER_MAX);
		return;
	case MATTER_ATTR_DL_CREDENTIAL_RULES:
		(void)matter_tlv_put_u64(w, tag, MATTER_DL_CREDENTIAL_RULES);
		return;
	case MATTER_ATTR_DL_LOCK_STATE:
		/*
		 * Still no actuator: nothing reported here moves a bolt. What it
		 * does report is what LockDoor/UnlockDoor last set, because a
		 * controller that sends UnlockDoor and then reads Locked has been
		 * told its command did nothing.
		 */
		(void)matter_tlv_put_u64(w, tag,
					 info->lock_state == MATTER_DL_LOCK_STATE_UNLOCKED
						 ? MATTER_DL_LOCK_STATE_UNLOCKED
						 : MATTER_DL_LOCK_STATE_LOCKED);
		return;
	case MATTER_ATTR_DL_LOCK_TYPE:
		/* 0x00 is DeadBolt (DoorLock/Enums.h, DlLockType). */
		(void)matter_tlv_put_u64(w, tag, 0u);
		return;
	case MATTER_ATTR_DL_ACTUATOR_ENABLED:
		/*
		 * False. There IS no actuator on this board, and claiming one
		 * would invite a Lock/Unlock command this endpoint cannot
		 * honour. The credential half is what this device is for.
		 */
		(void)matter_tlv_put_bool(w, tag, false);
		return;
	case MATTER_ATTR_DL_AUTO_RELOCK_TIME:
		/* Whatever the controller last wrote; 0 (never set) = no
		 * automatic relock. Reported so the controller shows its
		 * timing UI instead of improvising a relock of its own. */
		(void)matter_tlv_put_u64(w, tag, info->auto_relock_time_s);
		return;
	case MATTER_ATTR_DL_OPERATING_MODE:
		(void)matter_tlv_put_u64(w, tag, MATTER_DL_OPERATING_MODE_NORMAL);
		return;
	case MATTER_ATTR_DL_SUPPORTED_OPERATING_MODES:
		(void)matter_tlv_put_u64(w, tag, MATTER_DL_SUPPORTED_OPERATING_MODES);
		return;

	/*
	 * ---- the credential reader configuration -------------------------------
	 *
	 * NULL until SetAliroReaderConfig arrives, which is exactly what tells
	 * a controller this reader is unprovisioned and needs an identity.
	 * Reporting zeros instead would claim a key that cannot verify.
	 */
	case MATTER_ATTR_DL_ALIRO_VERIFICATION_KEY:
		if (info->have_ultrawidelock_reader_config) {
			(void)matter_tlv_put_bytes(w, tag, info->ultrawidelock_verification_key,
						   MATTER_ALIRO_VERIFICATION_KEY_LEN);
		} else {
			(void)matter_tlv_put_null(w, tag);
		}
		return;
	case MATTER_ATTR_DL_ALIRO_GROUP_ID:
		if (info->have_ultrawidelock_reader_config) {
			(void)matter_tlv_put_bytes(w, tag, info->ultrawidelock_group_id,
						   MATTER_ALIRO_GROUP_ID_LEN);
		} else {
			(void)matter_tlv_put_null(w, tag);
		}
		return;
	case MATTER_ATTR_DL_ALIRO_GROUP_RESOLVING_KEY:
		if (info->have_ultrawidelock_group_resolving_key) {
			(void)matter_tlv_put_bytes(w, tag, info->ultrawidelock_group_resolving_key,
						   MATTER_ALIRO_GROUP_ID_LEN);
		} else {
			(void)matter_tlv_put_null(w, tag);
		}
		return;
	case MATTER_ATTR_DL_ALIRO_GROUP_SUB_ID:
		/* Not nullable and not provisioned: it identifies the reader
		 * GROUP this device belongs to, which it has before any
		 * controller talks to it. The port supplies it. */
		(void)matter_tlv_put_bytes(w, tag, info->ultrawidelock_group_sub_id,
					   MATTER_ALIRO_GROUP_ID_LEN);
		return;
	case MATTER_ATTR_DL_ALIRO_EXPEDITED_VERSIONS:
	case MATTER_ATTR_DL_ALIRO_BLE_UWB_VERSIONS:
		put_protocol_version_list(w, tag);
		return;
	case MATTER_ATTR_DL_ALIRO_BLE_ADV_VERSION:
		(void)matter_tlv_put_u64(w, tag, MATTER_ALIRO_BLE_ADV_VERSION);
		return;
	case MATTER_ATTR_DL_ALIRO_ISSUER_KEYS_MAX:
		(void)matter_tlv_put_u64(w, tag, MATTER_ALIRO_ISSUER_KEYS_SUPPORTED);
		return;
	case MATTER_ATTR_DL_ALIRO_ENDPOINT_KEYS_MAX:
		(void)matter_tlv_put_u64(w, tag, MATTER_ALIRO_ENDPOINT_KEYS_SUPPORTED);
		return;
	default:
		return;
	}
}

/**
 * Retrieve the value of an attribute on a given endpoint and cluster. Encodes the value into the
 * TLV writer using the supplied tag. Handles root and lock endpoints, multiple cluster types
 * including Door Lock, Descriptor, Basic Information, Network Commissioning, Access Control,
 * Operational Credentials, Admin Commissioning, and General Commissioning.
 */
static void attr_value(void *ctx, uint16_t endpoint, uint32_t cluster, uint32_t attribute,
		       bool fabric_filtered, struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	const struct matter_device_info *info = (const struct matter_device_info *)ctx;

	/*
	 * The lock endpoint is answered first and returns, so everything below
	 * it can still assume the root. attr_status() has already refused any
	 * endpoint that is neither.
	 */
	if (endpoint == MATTER_ENDPOINT_LOCK) {
		lock_attr_value(info, cluster, attribute, fabric_filtered, w, tag);
		return;
	}

	if (cluster == MATTER_CLUSTER_ADMIN_COMMISSIONING) {
		/* No hooks installed means no window can ever be open, and saying
		 * so truthfully is better than refusing the read: a controller
		 * that cannot read WindowStatus cannot tell why its own
		 * OpenCommissioningWindow appeared to fail. */
		bool live = s_admin_hooks != NULL;

		switch (attribute) {
		case MATTER_ATTR_ADMIN_WINDOW_STATUS:
			(void)matter_tlv_put_u64(w, tag,
						 (live && s_admin_hooks->status != NULL)
							 ? s_admin_hooks->status()
							 : MATTER_ADMIN_WINDOW_NOT_OPEN);
			return;
		case MATTER_ATTR_ADMIN_FABRIC_INDEX: {
			uint8_t fabric = (live && s_admin_hooks->admin_fabric != NULL)
						 ? s_admin_hooks->admin_fabric()
						 : 0u;
			/* Nullable, and null is the correct answer while shut --
			 * zero is a fabric index nobody has. */
			if (fabric == 0u) {
				(void)matter_tlv_put_null(w, tag);
			} else {
				(void)matter_tlv_put_u64(w, tag, fabric);
			}
			return;
		}
		case MATTER_ATTR_ADMIN_VENDOR_ID: {
			uint16_t vendor = (live && s_admin_hooks->admin_vendor != NULL)
						  ? s_admin_hooks->admin_vendor()
						  : 0u;
			if (vendor == 0u) {
				(void)matter_tlv_put_null(w, tag);
			} else {
				(void)matter_tlv_put_u64(w, tag, vendor);
			}
			return;
		}
		default:
			return;
		}
	}

	if (cluster == MATTER_CLUSTER_BASIC_INFORMATION) {
		switch (attribute) {
		case MATTER_ATTR_BASIC_DATA_MODEL_REVISION:
			(void)matter_tlv_put_u64(w, tag, MATTER_DATA_MODEL_REVISION);
			return;
		case MATTER_ATTR_BASIC_VENDOR_NAME:
			(void)matter_tlv_put_utf8(w, tag, MATTER_VENDOR_NAME,
						  strlen(MATTER_VENDOR_NAME));
			return;
		case MATTER_ATTR_BASIC_VENDOR_ID:
			(void)matter_tlv_put_u64(w, tag, info->vendor_id);
			return;
		case MATTER_ATTR_BASIC_PRODUCT_NAME:
			(void)matter_tlv_put_utf8(w, tag, MATTER_PRODUCT_NAME,
						  strlen(MATTER_PRODUCT_NAME));
			return;
		case MATTER_ATTR_BASIC_PRODUCT_ID:
			(void)matter_tlv_put_u64(w, tag, info->product_id);
			return;
		case MATTER_ATTR_BASIC_NODE_LABEL:
			/* Writable, and empty until somebody writes one. A
			 * controller supplies its own name for the accessory. */
			(void)matter_tlv_put_utf8(w, tag, "", 0u);
			return;
		case MATTER_ATTR_BASIC_LOCATION:
			/* "XX" is the spec's value for "not configured", and it
			 * has to be exactly two characters. */
			(void)matter_tlv_put_utf8(w, tag, "XX", 2u);
			return;
		case MATTER_ATTR_BASIC_HARDWARE_VERSION:
		case MATTER_ATTR_BASIC_SOFTWARE_VERSION:
			(void)matter_tlv_put_u64(w, tag, 1u);
			return;
		case MATTER_ATTR_BASIC_HARDWARE_VERSION_STR:
		case MATTER_ATTR_BASIC_SOFTWARE_VERSION_STR:
			(void)matter_tlv_put_utf8(w, tag, "1", 1u);
			return;
		case MATTER_ATTR_BASIC_SERIAL_NUMBER:
		case MATTER_ATTR_BASIC_UNIQUE_ID:
			/*
			 * The same string for both, and it is a BUILD-TIME
			 * constant: this port has no per-device serial to read.
			 * Two boards running this image are indistinguishable
			 * here, which matters the moment a home holds both.
			 */
			(void)matter_tlv_put_utf8(w, tag, MATTER_SERIAL_NUMBER,
						  strlen(MATTER_SERIAL_NUMBER));
			return;
		case MATTER_ATTR_BASIC_CAPABILITY_MINIMA:
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_CAPMIN_CASE_SESSIONS),
						 MATTER_CASE_SESSIONS_PER_FABRIC);
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_CAPMIN_SUBSCRIPTIONS),
						 MATTER_SUBSCRIPTIONS_PER_FABRIC);
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_BASIC_SPECIFICATION_VERSION:
			(void)matter_tlv_put_u64(w, tag, MATTER_SPECIFICATION_VERSION);
			return;
		case MATTER_ATTR_BASIC_MAX_PATHS_PER_INVOKE:
			(void)matter_tlv_put_u64(w, tag, MATTER_MAX_PATHS_PER_INVOKE);
			return;
		default:
			return;
		}
	}

	if (cluster == MATTER_CLUSTER_NETWORK_COMMISSIONING) {
		switch (attribute) {
		case MATTER_ATTR_NC_MAX_NETWORKS:
			(void)matter_tlv_put_u64(w, tag, 1u);
			return;
		case MATTER_ATTR_NC_NETWORKS:
			/*
			 * A list of NetworkInfoStruct. Empty until a dataset
			 * arrives, and then exactly one entry whose networkID is
			 * the Extended PAN ID -- which is the id ConnectNetwork
			 * names the network by. `connected` is false and stays
			 * false: nothing here has joined anything.
			 */
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			if (info->attempt.have_thread_candidate || info->have_thread_xpanid) {
				const uint8_t *xpanid = info->attempt.have_thread_candidate
							? info->attempt.thread_xpanid
							: info->thread_xpanid;
				(void)matter_tlv_start_container(w, MATTER_TLV_ANON,
								 MATTER_TLV_STRUCTURE);
				(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(TAG_NETINFO_ID),
							   xpanid, MATTER_THREAD_XPANID_LEN);
				(void)matter_tlv_put_bool(w, MATTER_TLV_CTX(TAG_NETINFO_CONNECTED),
							  matter_thread_attached_to(xpanid));
				(void)matter_tlv_end_container(w);
			}
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_NC_SCAN_MAX_TIME_S:
			/* Never scanned; the value still has to be inside the
			 * spec's 1..255 range to be a legal answer. */
			(void)matter_tlv_put_u64(w, tag, 30u);
			return;
		case MATTER_ATTR_NC_CONNECT_MAX_TIME_S:
			(void)matter_tlv_put_u64(w, tag, 60u);
			return;
		case MATTER_ATTR_NC_INTERFACE_ENABLED:
			(void)matter_tlv_put_bool(w, tag, true);
			return;
		case MATTER_ATTR_NC_LAST_NETWORKING_STATUS:
			(void)matter_tlv_put_u64(w, tag, info->last_network_status);
			return;
		case MATTER_ATTR_FEATURE_MAP:
			/*
			 * Thread, and only Thread. This is the answer Apple was
			 * asking for when it read this cluster with the endpoint
			 * wildcarded and got silence.
			 */
			(void)matter_tlv_put_u64(w, tag, MATTER_NC_FEATURE_THREAD);
			return;
		default:
			return;
		}
	}

	if (cluster == MATTER_CLUSTER_DESCRIPTOR) {
		size_t i;

		switch (attribute) {
		case MATTER_ATTR_DESC_DEVICE_TYPE_LIST:
			/*
			 * What this endpoint IS, which is the question a
			 * controller asks once it owns the node. Endpoint 0 is
			 * the Root Node and nothing else.
			 */
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			(void)matter_tlv_start_container(w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_DEVTYPE_TYPE),
						 MATTER_DEVICE_TYPE_ROOT_NODE);
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_DEVTYPE_REVISION),
						 MATTER_DEVICE_TYPE_ROOT_REV);
			(void)matter_tlv_end_container(w);
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_DESC_SERVER_LIST:
			/* Built from the same list has_cluster() answers from,
			 * so the two cannot drift into disagreeing about what
			 * this endpoint carries. */
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			for (i = 0u; i < sizeof(k_root_servers) / sizeof(k_root_servers[0]); i++) {
				(void)matter_tlv_put_u64(w, MATTER_TLV_ANON, k_root_servers[i]);
			}
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_DESC_CLIENT_LIST:
			/* Empty, and empty is an answer: this node binds nothing
			 * as a client. */
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_DESC_PARTS_LIST:
			/*
			 * The Door Lock. This is the attribute that turns an
			 * empty tile into a lock: a controller reads the root's
			 * PartsList to find the endpoints that carry function,
			 * and a Root Node on its own carries none.
			 */
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			(void)matter_tlv_put_u64(w, MATTER_TLV_ANON, MATTER_ENDPOINT_LOCK);
			(void)matter_tlv_end_container(w);
			return;
		default:
			return;
		}
	}

	if (cluster == MATTER_CLUSTER_ACCESS_CONTROL) {
		size_t slot = fabric_slot_for_request(info, info->accessing_fabric_index);

		switch (attribute) {
		case MATTER_ATTR_AC_ACL:
			/*
			 * Handed straight back as it arrived. Authorization decodes
			 * the stored form in place, but preserving the exact element
			 * avoids rebuilding fields this implementation does not alter.
			 */
			if (slot < MATTER_SUPPORTED_FABRICS &&
			    info->fabric_acls[slot].len > 0u) {
				(void)matter_tlv_put_encoded(w, tag, info->fabric_acls[slot].data,
							     info->fabric_acls[slot].len);
			} else {
				(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
				(void)matter_tlv_end_container(w);
			}
			return;
		case MATTER_ATTR_AC_SUBJECTS_PER_ENTRY:
		case MATTER_ATTR_AC_ENTRIES_PER_FABRIC:
			/* The spec's floor for both, and what one fabric needs. */
			(void)matter_tlv_put_u64(w, tag, 4u);
			return;
		case MATTER_ATTR_AC_TARGETS_PER_ENTRY:
			(void)matter_tlv_put_u64(w, tag, 3u);
			return;
		default:
			return;
		}
	}

	if (cluster == MATTER_CLUSTER_OPERATIONAL_CREDENTIALS) {
		size_t fi;

		switch (attribute) {
		case MATTER_ATTR_OC_FABRICS:
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			for (fi = 0u; fi < MATTER_SUPPORTED_FABRICS; fi++) {
				const struct matter_fabric *f = &info->fabrics[fi];

				if (f->index == 0u ||
				    (fabric_filtered && f->index != info->accessing_fabric_index)) {
					continue;
				}
				(void)matter_tlv_start_container(w, MATTER_TLV_ANON,
								 MATTER_TLV_STRUCTURE);
				(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(TAG_FABRIC_ROOT_KEY),
							   f->root_public_key,
							   MATTER_FABRIC_PUBKEY_LEN);
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_FABRIC_VENDOR_ID),
							 f->admin_vendor_id);
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_FABRIC_FABRIC_ID),
							 f->fabric_id);
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_FABRIC_NODE_ID),
							 f->node_id);
				/* Empty until a commissioner writes one. */
				(void)matter_tlv_put_utf8(w, MATTER_TLV_CTX(TAG_FABRIC_LABEL), "",
							  0u);
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_FABRIC_INDEX),
							 f->index);
				(void)matter_tlv_end_container(w);
			}
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_OC_NOCS:
			/* The certificates themselves. FabricFiltered limits the
			 * list to the CASE session's fabric. */
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			for (fi = 0u; fi < MATTER_SUPPORTED_FABRICS; fi++) {
				const struct matter_fabric *f = &info->fabrics[fi];

				if (f->index == 0u ||
				    (fabric_filtered && f->index != info->accessing_fabric_index)) {
					continue;
				}
				(void)matter_tlv_start_container(w, MATTER_TLV_ANON,
								 MATTER_TLV_STRUCTURE);
				(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(TAG_NOC_NOC), f->noc,
							   f->noc_len);
				if (f->icac_len > 0u && info->icac.owner_index == f->index &&
				    info->icac.len == f->icac_len) {
					(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(TAG_NOC_ICAC),
								   info->icac.buf, f->icac_len);
				} else {
					/* Nullable, and null is the answer when
					 * the root signed the NOC directly. */
					(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_NOC_ICAC));
				}
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_FABRIC_INDEX),
							 f->index);
				(void)matter_tlv_end_container(w);
			}
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_OC_TRUSTED_ROOTS:
			/*
			 * A list of the root CERTIFICATES, which this node does
			 * not keep -- matter_fabric holds the root public key
			 * and discards the ~300 bytes around it. An empty list
			 * is the honest consequence of that choice.
			 */
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_OC_CURRENT_FABRIC_INDEX:
			/*
			 * The fabric of whoever is ASKING, which the port
			 * records from the session the request arrived on.
			 * Answering with the first live fabric was right while
			 * there was one and a guess once there were two -- and
			 * the guess is what made the home hub remove itself.
			 */
			(void)matter_tlv_put_u64(w, tag, info->accessing_fabric_index);
			return;
		case MATTER_ATTR_OC_SUPPORTED_FABRICS:
			(void)matter_tlv_put_u64(w, tag, MATTER_SUPPORTED_FABRICS);
			return;
		case MATTER_ATTR_OC_COMMISSIONED_FABRICS:
			(void)matter_tlv_put_u64(w, tag, fabric_count(info));
			return;
		default:
			return;
		}
	}

	switch (attribute) {
	case MATTER_ATTR_GC_BREADCRUMB:
		(void)matter_tlv_put_u64(w, tag, info->breadcrumb);
		return;
	case MATTER_ATTR_GC_BASIC_COMMISSIONING_INFO:
		(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_BCI_FAILSAFE_EXPIRY),
					 info->failsafe_expiry_s);
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_BCI_FAILSAFE_MAX),
					 info->failsafe_max_s);
		(void)matter_tlv_end_container(w);
		return;
	case MATTER_ATTR_GC_REGULATORY_CONFIG:
		(void)matter_tlv_put_u64(w, tag, info->regulatory_config);
		return;
	case MATTER_ATTR_GC_LOCATION_CAPABILITY:
		(void)matter_tlv_put_u64(w, tag, info->location_capability);
		return;
	case MATTER_ATTR_GC_SUPPORTS_CONCURRENT_CONNECTION:
		(void)matter_tlv_put_bool(w, tag, info->supports_concurrent_connection);
		return;
	default:
		return;
	}
}

/*
 * Attribute lists for expanding a wildcard read. These are exactly the
 * attributes attr_status() answers SUCCESS for, and the two must agree: an id
 * here that attr_status() refuses turns a wildcard into a report full of
 * UNSUPPORTED_ATTRIBUTE, which is worse than the silence it replaced.
 *
 * The global attributes (FeatureMap 0xFFFC, ClusterRevision 0xFFFD and the
 * rest) are deliberately absent. Nothing has asked for them, and a wildcard
 * that names them commits this node to answering them individually too.
 */
static const uint32_t k_gc_attrs[] = {
	MATTER_ATTR_GC_BREADCRUMB,
	MATTER_ATTR_GC_BASIC_COMMISSIONING_INFO,
	MATTER_ATTR_GC_REGULATORY_CONFIG,
	MATTER_ATTR_GC_LOCATION_CAPABILITY,
	MATTER_ATTR_GC_SUPPORTS_CONCURRENT_CONNECTION,
};

static const uint32_t k_basic_attrs[] = {
	MATTER_ATTR_BASIC_DATA_MODEL_REVISION,
	MATTER_ATTR_BASIC_VENDOR_NAME,
	MATTER_ATTR_BASIC_VENDOR_ID,
	MATTER_ATTR_BASIC_PRODUCT_NAME,
	MATTER_ATTR_BASIC_PRODUCT_ID,
	MATTER_ATTR_BASIC_NODE_LABEL,
	MATTER_ATTR_BASIC_LOCATION,
	MATTER_ATTR_BASIC_HARDWARE_VERSION,
	MATTER_ATTR_BASIC_HARDWARE_VERSION_STR,
	MATTER_ATTR_BASIC_SOFTWARE_VERSION,
	MATTER_ATTR_BASIC_SOFTWARE_VERSION_STR,
	MATTER_ATTR_BASIC_SERIAL_NUMBER,
	MATTER_ATTR_BASIC_UNIQUE_ID,
	MATTER_ATTR_BASIC_CAPABILITY_MINIMA,
	MATTER_ATTR_BASIC_SPECIFICATION_VERSION,
	MATTER_ATTR_BASIC_MAX_PATHS_PER_INVOKE,
};

static const uint32_t k_desc_attrs[] = {
	MATTER_ATTR_DESC_DEVICE_TYPE_LIST,
	MATTER_ATTR_DESC_SERVER_LIST,
	MATTER_ATTR_DESC_CLIENT_LIST,
	MATTER_ATTR_DESC_PARTS_LIST,
};

/* k_lock_attrs and k_approach_attrs live above lock_attr_value(), which
 * serves them as AttributeList; they belong to this section all the same. */

static const uint32_t k_ac_attrs[] = {
	MATTER_ATTR_AC_ACL,
	MATTER_ATTR_AC_SUBJECTS_PER_ENTRY,
	MATTER_ATTR_AC_TARGETS_PER_ENTRY,
	MATTER_ATTR_AC_ENTRIES_PER_FABRIC,
};

/**
 * AdministratorCommissioning's three attributes.
 *
 * A controller reads WindowStatus to decide whether its own
 * OpenCommissioningWindow succeeded, and reads the other two to show WHO opened
 * it. Both of those are nullable and are null whenever the window is shut.
 */
static const uint32_t k_admin_attrs[] = {
	MATTER_ATTR_ADMIN_WINDOW_STATUS,
	MATTER_ATTR_ADMIN_FABRIC_INDEX,
	MATTER_ATTR_ADMIN_VENDOR_ID,
};

static const uint32_t k_oc_attrs[] = {
	MATTER_ATTR_OC_NOCS,
	MATTER_ATTR_OC_FABRICS,
	MATTER_ATTR_OC_SUPPORTED_FABRICS,
	MATTER_ATTR_OC_COMMISSIONED_FABRICS,
	MATTER_ATTR_OC_TRUSTED_ROOTS,
	MATTER_ATTR_OC_CURRENT_FABRIC_INDEX,
};

/*
 * FeatureMap is in this list where it is in no other, because it is the one
 * global attribute a commissioner cannot proceed without: it says which network
 * technologies exist. Listing it here commits this node to answering it for
 * THIS cluster only, which attr_status() above does.
 */
static const uint32_t k_nc_attrs[] = {
	MATTER_ATTR_NC_MAX_NETWORKS,      MATTER_ATTR_NC_NETWORKS,
	MATTER_ATTR_NC_SCAN_MAX_TIME_S,   MATTER_ATTR_NC_CONNECT_MAX_TIME_S,
	MATTER_ATTR_NC_INTERFACE_ENABLED, MATTER_ATTR_NC_LAST_NETWORKING_STATUS,
	MATTER_ATTR_FEATURE_MAP,
};

/**
 * Every cluster on @p endpoint, which is the same list has_cluster() answers
 * from and the same one Descriptor's ServerList reports. One array, so the
 * three cannot drift into disagreeing about what this endpoint carries.
 */
static size_t list_clusters(void *ctx, uint16_t endpoint, const uint32_t **out)
{
	(void)ctx;

	if (endpoint == MATTER_ENDPOINT_LOCK) {
		*out = k_lock_servers;
		return sizeof(k_lock_servers) / sizeof(k_lock_servers[0]);
	}
	if (endpoint != MATTER_ENDPOINT_ROOT) {
		return 0u;
	}
	*out = k_root_servers;
	return sizeof(k_root_servers) / sizeof(k_root_servers[0]);
}

/**
 * Return the attribute IDs for a given endpoint and cluster, or 0 if the endpoint or cluster is not
 * supported.
 */
static size_t list_attrs(void *ctx, uint16_t endpoint, uint32_t cluster, const uint32_t **out)
{
	(void)ctx;

	if (endpoint == MATTER_ENDPOINT_LOCK) {
		if (cluster == MATTER_CLUSTER_DESCRIPTOR) {
			*out = k_desc_attrs;
			return sizeof(k_desc_attrs) / sizeof(k_desc_attrs[0]);
		}
		if (cluster == MATTER_CLUSTER_DOOR_LOCK) {
			*out = k_lock_attrs;
			return sizeof(k_lock_attrs) / sizeof(k_lock_attrs[0]);
		}
		if (cluster == MATTER_CLUSTER_APPROACH_DIRECTION) {
			*out = k_approach_attrs;
			return sizeof(k_approach_attrs) / sizeof(k_approach_attrs[0]);
		}
#if MATTER_FEATURE_CLIENT
		if (cluster == MATTER_CLUSTER_BINDING) {
			*out = k_binding_attrs;
			return sizeof(k_binding_attrs) / sizeof(k_binding_attrs[0]);
		}
#endif
		return 0u;
	}
	if (endpoint != MATTER_ENDPOINT_ROOT) {
		return 0u;
	}
	if (cluster == MATTER_CLUSTER_BASIC_INFORMATION) {
		*out = k_basic_attrs;
		return sizeof(k_basic_attrs) / sizeof(k_basic_attrs[0]);
	}
	if (cluster == MATTER_CLUSTER_ADMIN_COMMISSIONING) {
		*out = k_admin_attrs;
		return sizeof(k_admin_attrs) / sizeof(k_admin_attrs[0]);
	}
	if (cluster == MATTER_CLUSTER_GENERAL_COMMISSIONING) {
		*out = k_gc_attrs;
		return sizeof(k_gc_attrs) / sizeof(k_gc_attrs[0]);
	}
	if (cluster == MATTER_CLUSTER_DESCRIPTOR) {
		*out = k_desc_attrs;
		return sizeof(k_desc_attrs) / sizeof(k_desc_attrs[0]);
	}
	if (cluster == MATTER_CLUSTER_ACCESS_CONTROL) {
		*out = k_ac_attrs;
		return sizeof(k_ac_attrs) / sizeof(k_ac_attrs[0]);
	}
	if (cluster == MATTER_CLUSTER_OPERATIONAL_CREDENTIALS) {
		*out = k_oc_attrs;
		return sizeof(k_oc_attrs) / sizeof(k_oc_attrs[0]);
	}
	if (cluster == MATTER_CLUSTER_NETWORK_COMMISSIONING) {
		*out = k_nc_attrs;
		return sizeof(k_nc_attrs) / sizeof(k_nc_attrs[0]);
	}
	return 0u;
}

/** Read one unsigned field out of a command's TLV arguments. */
static bool field_u64(const struct matter_im_invoke *inv, uint8_t tag, uint64_t *out)
{
	struct matter_tlv_reader r;

	if (!inv->has_fields || inv->fields == NULL) {
		return false;
	}
	matter_tlv_reader_init(&r, inv->fields, inv->fields_len);
	if (matter_tlv_next(&r) != MATTER_OK || !matter_tlv_is_container(&r)) {
		return false;
	}
	if (matter_tlv_enter(&r) != MATTER_OK) {
		return false;
	}
	for (;;) {
		int rc = matter_tlv_next(&r);

		if (rc != MATTER_OK) {
			return false;
		}
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(tag)) {
			return matter_tlv_get_u64(&r, out) == MATTER_OK;
		}
	}
}

/* -------------------------------------- OperationalCredentials --- */

/*
 * Command field tags. Matter numbers a command's arguments from 0 in
 * declaration order, so these are the positions in
 * controller/python/matter/clusters/Objects.py, which spells the tag out
 * rather than leaving it to be counted.
 */
#define TAG_ATTEST_NONCE 0u
#define TAG_CERT_TYPE    0u
#define TAG_CSR_NONCE    0u

#define TAG_ADDNOC_NOC                0u
#define TAG_ADDNOC_ICAC               1u
#define TAG_ADDNOC_IPK                2u
#define TAG_ADDNOC_CASE_ADMIN_SUBJECT 3u
#define TAG_ADDNOC_ADMIN_VENDOR_ID    4u

#define TAG_ADDROOT_CERT 0u

#define TAG_REMOVE_FABRIC_INDEX 0u

/* Response field tags, same source. */
#define TAG_RESP_ELEMENTS  0u
#define TAG_RESP_SIGNATURE 1u
#define TAG_RESP_CERT      0u

#define TAG_NOCRESP_STATUS       0u
#define TAG_NOCRESP_FABRIC_INDEX 1u

/** Borrow one octet-string field out of a command's arguments. */
/**
 * Read an unsigned field from INSIDE a nested structure field.
 *
 * SetCredential carries the credential type one level down, in a
 * CredentialStruct under field 1. Reading tag 0 at the top level instead finds
 * OperationType, which is also a small unsigned and decodes perfectly -- so
 * getting this wrong installs a credential key as whatever operation type happened
 * to be sent, with nothing to report.
 */
static bool field_struct_u64(const struct matter_im_invoke *inv, uint8_t outer, uint8_t inner,
			     uint64_t *out)
{
	struct matter_tlv_reader r;

	if (!inv->has_fields || inv->fields == NULL) {
		return false;
	}
	matter_tlv_reader_init(&r, inv->fields, inv->fields_len);
	if (matter_tlv_next(&r) != MATTER_OK || matter_tlv_enter(&r) != MATTER_OK) {
		return false;
	}
	for (;;) {
		int rc = matter_tlv_next(&r);

		if (rc != MATTER_OK) {
			return false;
		}
		if (matter_tlv_tag(&r) != MATTER_TLV_CTX(outer)) {
			continue;
		}
		if (!matter_tlv_is_container(&r) || matter_tlv_enter(&r) != MATTER_OK) {
			return false;
		}
		for (;;) {
			rc = matter_tlv_next(&r);
			if (rc != MATTER_OK) {
				return false;
			}
			if (matter_tlv_tag(&r) == MATTER_TLV_CTX(inner)) {
				return matter_tlv_get_u64(&r, out) == MATTER_OK;
			}
		}
	}
}

/**
 * Extract a bytes field from the TLV-encoded command fields by tag. Searches the structure for the
 * first matching tag and decodes it. Returns true and fills out and len on success, false if the
 * fields are missing, malformed, or the tag is not found.
 */
static bool field_bytes(const struct matter_im_invoke *inv, uint8_t tag, const uint8_t **out,
			size_t *len)
{
	struct matter_tlv_reader r;

	if (!inv->has_fields || inv->fields == NULL) {
		return false;
	}
	matter_tlv_reader_init(&r, inv->fields, inv->fields_len);
	if (matter_tlv_next(&r) != MATTER_OK || !matter_tlv_is_container(&r)) {
		return false;
	}
	if (matter_tlv_enter(&r) != MATTER_OK) {
		return false;
	}
	for (;;) {
		if (matter_tlv_next(&r) != MATTER_OK) {
			return false;
		}
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(tag)) {
			return matter_tlv_get_bytes(&r, out, len) == MATTER_OK;
		}
	}
}

/* --------------------------------------- NetworkCommissioning --- */

/* AddOrUpdateThreadNetwork / ConnectNetwork field tags, and the two responses. */
#define TAG_ADDTHREAD_DATASET  0u
#define TAG_CONNECT_NETWORK_ID 0u
#define TAG_NCRESP_STATUS      0u
#define TAG_NCRESP_INDEX       2u
#define TAG_CONNRESP_STATUS    0u
#define TAG_CONNRESP_ERROR     2u

/**
 * Thread meshcop TLV type for the Extended PAN ID (Thread 1.3 spec, 8.10.1.5).
 *
 * The operational dataset is a sequence of one-byte type, one-byte length,
 * value -- a different encoding from everything else here, and unrelated to
 * Matter TLV.
 */
#define MESHCOP_TLV_CHANNEL           0x00u
#define MESHCOP_TLV_PANID             0x01u
#define MESHCOP_TLV_EXTENDED_PANID    0x02u
#define MESHCOP_TLV_NETWORK_NAME      0x03u
#define MESHCOP_TLV_PSKC              0x04u
#define MESHCOP_TLV_NETWORK_KEY       0x05u
#define MESHCOP_TLV_MESH_LOCAL_PREFIX 0x07u
#define MESHCOP_TLV_SECURITY_POLICY   0x0cu
#define MESHCOP_TLV_ACTIVE_TIMESTAMP  0x0eu
#define MESHCOP_TLV_CHANNEL_MASK      0x35u

static bool dataset_channel_mask_valid(const uint8_t *value, size_t len)
{
	size_t i = 0u;

	while (i + 2u <= len) {
		size_t mask_len = value[i + 1u];

		if (mask_len == 0u || i + 2u + mask_len > len) {
			return false;
		}
		i += 2u + mask_len;
	}
	return i == len && i != 0u;
}

/**
 * Find the Extended PAN ID in a Thread operational dataset.
 *
 * Walked rather than indexed: the dataset's TLVs may arrive in any order, and a
 * length that runs past the end is a malformed dataset rather than a reason to
 * read past the buffer.
 */
static bool dataset_validate(const uint8_t *ds, size_t len,
			     uint8_t out[MATTER_THREAD_XPANID_LEN])
{
	size_t i = 0u;
	uint8_t seen[32] = { 0 };
	uint16_t required = 0u;
	enum {
		HAVE_ACTIVE_TIMESTAMP = 1u << 0,
		HAVE_CHANNEL = 1u << 1,
		HAVE_CHANNEL_MASK = 1u << 2,
		HAVE_XPANID = 1u << 3,
		HAVE_MESH_LOCAL_PREFIX = 1u << 4,
		HAVE_NETWORK_KEY = 1u << 5,
		HAVE_NETWORK_NAME = 1u << 6,
		HAVE_PANID = 1u << 7,
		HAVE_PSKC = 1u << 8,
		HAVE_SECURITY_POLICY = 1u << 9,
		HAVE_ALL = (1u << 10) - 1u,
	};

	if (ds == NULL || len == 0u || len > MATTER_THREAD_DATASET_MAX) {
		return false;
	}
	while (i + 2u <= len) {
		uint8_t type = ds[i];
		size_t vlen = ds[i + 1u];

		if (vlen == 0u || i + 2u + vlen > len ||
		    (seen[type / 8u] & (uint8_t)(1u << (type % 8u))) != 0u) {
			return false;
		}
		seen[type / 8u] |= (uint8_t)(1u << (type % 8u));
		switch (type) {
		case MESHCOP_TLV_ACTIVE_TIMESTAMP:
			if (vlen != 8u) {
				return false;
			}
			required |= HAVE_ACTIVE_TIMESTAMP;
			break;
		case MESHCOP_TLV_CHANNEL:
			if (vlen != 3u || ds[i + 2u] != 0u ||
			    (((uint16_t)ds[i + 3u] << 8) | ds[i + 4u]) < 11u ||
			    (((uint16_t)ds[i + 3u] << 8) | ds[i + 4u]) > 26u) {
				return false;
			}
			required |= HAVE_CHANNEL;
			break;
		case MESHCOP_TLV_PANID:
			if (vlen != 2u) {
				return false;
			}
			required |= HAVE_PANID;
			break;
		case MESHCOP_TLV_EXTENDED_PANID:
			if (vlen != MATTER_THREAD_XPANID_LEN) {
				return false;
			}
			memcpy(out, &ds[i + 2u], MATTER_THREAD_XPANID_LEN);
			required |= HAVE_XPANID;
			break;
		case MESHCOP_TLV_NETWORK_NAME:
			if (vlen == 0u || vlen > 16u) {
				return false;
			}
			required |= HAVE_NETWORK_NAME;
			break;
		case MESHCOP_TLV_PSKC:
			if (vlen != 16u) {
				return false;
			}
			required |= HAVE_PSKC;
			break;
		case MESHCOP_TLV_NETWORK_KEY:
			if (vlen != 16u) {
				return false;
			}
			required |= HAVE_NETWORK_KEY;
			break;
		case MESHCOP_TLV_MESH_LOCAL_PREFIX:
			if (vlen != 8u) {
				return false;
			}
			required |= HAVE_MESH_LOCAL_PREFIX;
			break;
		case MESHCOP_TLV_SECURITY_POLICY:
			if (vlen != 3u && vlen != 4u) {
				return false;
			}
			required |= HAVE_SECURITY_POLICY;
			break;
		case MESHCOP_TLV_CHANNEL_MASK:
			if (!dataset_channel_mask_valid(&ds[i + 2u], vlen)) {
				return false;
			}
			required |= HAVE_CHANNEL_MASK;
			break;
		default:
			break;
		}
		i += 2u + vlen;
	}
	return i == len && required == HAVE_ALL;
}

/**
 * Publish "<compressed-fabric-id>-<node-id>._matter._tcp" over SRP.
 *
 * Silent when there is no fabric yet: a node with a network but no identity has
 * no name to register under, and that is a legal intermediate state rather than
 * a failure. Failures ARE logged by the port, which is where the SRP server's
 * answer eventually lands.
 */
static void advertise_one(const struct matter_fabric *fabric);

/**
 * Advertise one Thread mDNS instance per provisioned fabric, deriving each instance name from the
 * compressed fabric ID and node ID. Do nothing if no fabrics are provisioned.
 */
static void advertise_operational(const struct matter_device_info *info)
{
	size_t fi;

	/*
	 * One instance PER FABRIC. The name is derived from the compressed
	 * fabric id and this node's id on that fabric, so a second
	 * administrator resolving the first fabric's name finds an address it
	 * cannot open a session to.
	 */
	for (fi = 0u; fi < MATTER_SUPPORTED_FABRICS; fi++) {
		if (info->fabrics[fi].index != 0u) {
			advertise_one(&info->fabrics[fi]);
		}
	}
}

/**
 * Advertise this fabric's instance name over Thread on the operational port if the name can be
 * derived.
 */
static void advertise_one(const struct matter_fabric *fabric)
{
	char name[MATTER_INSTANCE_NAME_LEN];

	if (matter_fabric_instance_name(fabric, name, sizeof(name)) != MATTER_OK) {
		return;
	}
	(void)matter_thread_advertise(name, MATTER_OPERATIONAL_PORT);
}

/**
 * Run one NetworkCommissioning command.
 *
 * @return the IM status. The networking verdict goes in last_network_status and
 *         travels in the response payload, the same split AddNOC uses.
 */
/* ---- AdministratorCommissioning (0x003C) ---------------------------------- */
/*
 * The cluster behind Apple Home's "Turn On Pairing Mode", and behind
 * multi-admin sharing generally. Without it a node is commissioned once, by
 * whoever got there first, and can never be handed to a second ecosystem --
 * which is what this board did until now: the button existed in the app and
 * the node answered UNSUPPORTED_CLUSTER.
 *
 * Everything with a side effect is behind hooks the port installs. This file
 * decodes and validates; opening a window means swapping the SPAKE2+ verifier
 * the PASE responder uses and putting the commissionable payload back on the
 * air, and neither belongs in a module that tests/host compiles without Zephyr.
 */
void matter_clusters_set_admin_hooks(const struct matter_admin_hooks *hooks)
{
	s_admin_hooks = hooks;
}

/**
 * Map a hook's cluster-specific status onto an IM status.
 *
 * Lossy, and knowingly so: Matter can carry a ClusterStatus alongside FAILURE
 * so a controller can tell "already open" from "that verifier is malformed",
 * and this IM does not encode one yet. A controller therefore sees a generic
 * failure. Worth fixing when something depends on the distinction; nothing
 * here does, because the only caller that matters retries either way.
 */
static uint8_t admin_status(uint8_t cluster_status)
{
	return cluster_status == 0u ? MATTER_IM_STATUS_SUCCESS : MATTER_IM_STATUS_FAILURE;
}

/**
 * Decode and dispatch an admin cluster command: open-enhanced-window, open-basic-window, or revoke.
 * Extract TLV-encoded parameters by tag, validate lengths exactly, delegate to the registered
 * hooks, and return a status code. None of the three commands carry a response payload.
 */
static uint8_t admin_command(const struct matter_im_invoke *inv, uint32_t *response_command)
{
	const uint8_t *verifier = NULL;
	const uint8_t *salt = NULL;
	size_t verifier_len = 0;
	size_t salt_len = 0;
	uint64_t timeout = 0;
	uint64_t discriminator = 0;
	uint64_t iterations = 0;

	/* None of the three carries a response payload; the status IS the reply. */
	*response_command = MATTER_IM_NO_RESPONSE;

	if (s_admin_hooks == NULL) {
		return MATTER_IM_STATUS_FAILURE;
	}

	switch (inv->command) {
	case MATTER_CMD_ADMIN_OPEN_WINDOW:
		/*
		 * The commissioner supplies the verifier, so the setup code for
		 * this window is one IT chose and the factory code is never
		 * disclosed to the ecosystem being invited in. Field tags are
		 * positional per the spec: timeout, verifier, discriminator,
		 * iterations, salt.
		 */
		if (!field_u64(inv, 0u, &timeout) ||
		    !field_bytes(inv, 1u, &verifier, &verifier_len) ||
		    !field_u64(inv, 2u, &discriminator) || !field_u64(inv, 3u, &iterations) ||
		    !field_bytes(inv, 4u, &salt, &salt_len)) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		if (s_admin_hooks->open_enhanced == NULL) {
			return MATTER_IM_STATUS_FAILURE;
		}
		return admin_status(s_admin_hooks->open_enhanced(
			(uint16_t)timeout, verifier, (uint32_t)verifier_len,
			(uint16_t)discriminator, (uint32_t)iterations, salt, (uint32_t)salt_len));

	case MATTER_CMD_ADMIN_OPEN_BASIC_WINDOW:
		if (!field_u64(inv, 0u, &timeout)) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		if (s_admin_hooks->open_basic == NULL) {
			return MATTER_IM_STATUS_FAILURE;
		}
		return admin_status(s_admin_hooks->open_basic((uint16_t)timeout));

	case MATTER_CMD_ADMIN_REVOKE:
		if (s_admin_hooks->revoke == NULL) {
			return MATTER_IM_STATUS_FAILURE;
		}
		return admin_status(s_admin_hooks->revoke());

	default:
		return MATTER_IM_STATUS_UNSUPPORTED_COMMAND;
	}
}

static uint8_t network_command(struct matter_device_info *info, const struct matter_im_invoke *inv,
			       uint32_t *response_command)
{
	const uint8_t *v = NULL;
	size_t v_len = 0u;
	uint8_t xpanid[MATTER_THREAD_XPANID_LEN];

	if (!info->attempt.active) {
		return MATTER_IM_STATUS_FAILSAFE_REQUIRED;
	}

	switch (inv->command) {
	case MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK:
		*response_command = MATTER_CMD_NC_NETWORK_CONFIG_RESPONSE;
		if (!field_bytes(inv, TAG_ADDTHREAD_DATASET, &v, &v_len) ||
		    !dataset_validate(v, v_len, xpanid)) {
			info->last_network_status = MATTER_NC_STATUS_OUT_OF_RANGE;
			return MATTER_IM_STATUS_SUCCESS;
		}
		/* A second administrator may adopt the existing network, never
		 * silently move a working lock away from its current controllers.
		 * The Extended PAN ID is the network identity. Once it matches,
		 * retain the already-committed credentials instead of accepting a
		 * controller's differing timestamp, policy, or key material. */
		if (info->committed_slots != 0u) {
			if (!info->have_thread_xpanid ||
			    memcmp(xpanid, info->thread_xpanid, MATTER_THREAD_XPANID_LEN) != 0) {
				info->last_network_status = MATTER_NC_STATUS_BOUNDS_EXCEEDED;
				return MATTER_IM_STATUS_SUCCESS;
			}
			memcpy(info->attempt.thread_dataset, info->thread_dataset,
			       info->thread_dataset_len);
			info->attempt.thread_dataset_len = info->thread_dataset_len;
			memcpy(info->attempt.thread_xpanid, info->thread_xpanid,
			       MATTER_THREAD_XPANID_LEN);
		} else {
			memcpy(info->attempt.thread_dataset, v, v_len);
			info->attempt.thread_dataset_len = v_len;
			memcpy(info->attempt.thread_xpanid, xpanid, sizeof(xpanid));
		}
		info->attempt.have_thread_candidate = true;
		info->last_network_status = MATTER_NC_STATUS_SUCCESS;
		return MATTER_IM_STATUS_SUCCESS;

	case MATTER_CMD_NC_CONNECT_NETWORK:
		*response_command = MATTER_CMD_NC_CONNECT_NETWORK_RESPONSE;
		if (!field_bytes(inv, TAG_CONNECT_NETWORK_ID, &v, &v_len) ||
		    v_len != MATTER_THREAD_XPANID_LEN || !info->attempt.have_thread_candidate ||
		    memcmp(v, info->attempt.thread_xpanid, MATTER_THREAD_XPANID_LEN) != 0) {
			info->last_network_status = MATTER_NC_STATUS_NETWORK_ID_NOT_FOUND;
			return MATTER_IM_STATUS_SUCCESS;
		}
		if (matter_thread_attached_to(info->attempt.thread_xpanid)) {
			info->thread_started = true;
		} else {
			/* start() may install the dataset before a later stack step
			 * fails. Mark it applied before the call so fail-safe rollback
			 * restores the committed network on every failure path. */
			info->attempt.thread_applied = true;
			info->thread_started =
				matter_thread_start(info->attempt.thread_dataset,
						    info->attempt.thread_dataset_len) == MATTER_OK;
		}
		if (!info->thread_started) {
			info->last_network_status = MATTER_NC_STATUS_OTHER_CONNECTION_FAILUR;
			return MATTER_IM_STATUS_SUCCESS;
		}
		/*
		 * Blocks. The commissioner is waiting on this reply and allows
		 * up to the ConnectMaxTimeSeconds this node advertises, so the
		 * bound below has to stay comfortably under it. Reporting
		 * Success before the node is actually on the network would send
		 * the commissioner hunting for it and cost far more than a wait.
		 */
		if (matter_thread_wait_attached(MATTER_THREAD_ATTACH_TIMEOUT_MS) != MATTER_OK) {
			info->last_network_status = MATTER_NC_STATUS_OTHER_CONNECTION_FAILUR;
			return MATTER_IM_STATUS_SUCCESS;
		}
		/*
		 * On the network, and now findable ON it. The commissioner
		 * closes BLE the moment this reply says Success and looks the
		 * node up in DNS-SD; registering after that would be a race
		 * against a search already under way.
		 */
		advertise_operational(info);
		info->last_network_status = MATTER_NC_STATUS_SUCCESS;
		return MATTER_IM_STATUS_SUCCESS;

	case MATTER_CMD_NC_REMOVE_NETWORK:
		*response_command = MATTER_CMD_NC_NETWORK_CONFIG_RESPONSE;
		if (!field_bytes(inv, TAG_CONNECT_NETWORK_ID, &v, &v_len) ||
		    v_len != MATTER_THREAD_XPANID_LEN || !info->attempt.have_thread_candidate ||
		    memcmp(v, info->attempt.thread_xpanid, MATTER_THREAD_XPANID_LEN) != 0) {
			info->last_network_status = MATTER_NC_STATUS_NETWORK_ID_NOT_FOUND;
			return MATTER_IM_STATUS_SUCCESS;
		}
		/* Removing an established network is a migration operation, not
		 * part of adding an administrator. Keep it out of this path. */
		if (info->committed_slots != 0u) {
			info->last_network_status = MATTER_NC_STATUS_BOUNDS_EXCEEDED;
			return MATTER_IM_STATUS_SUCCESS;
		}
		if (info->attempt.thread_applied) {
			(void)matter_thread_clear();
		}
		info->attempt.have_thread_candidate = false;
		info->attempt.thread_applied = false;
		info->attempt.thread_dataset_len = 0u;
		info->last_network_status = MATTER_NC_STATUS_SUCCESS;
		return MATTER_IM_STATUS_SUCCESS;

	default:
		return MATTER_IM_STATUS_UNSUPPORTED_COMMAND;
	}
}

/** Serialise what network_command() decided. */
static void network_fields(const struct matter_device_info *info, uint32_t response_command,
			   struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);

	if (response_command == MATTER_CMD_NC_CONNECT_NETWORK_RESPONSE) {
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_CONNRESP_STATUS),
					 info->last_network_status);
		/* ErrorValue is nullable and mandatory: null is what a device
		 * sends when the failure has no driver-specific code behind it. */
		(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_CONNRESP_ERROR));
	} else {
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_NCRESP_STATUS),
					 info->last_network_status);
		if (info->last_network_status == MATTER_NC_STATUS_SUCCESS) {
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_NCRESP_INDEX), 0u);
		}
	}

	(void)matter_tlv_end_container(w);
}

/**
 * Install the root the commissioner wants this node to trust.
 *
 * Only the public key is kept -- see matter_fabric.h. Nothing is verified: this
 * node has no prior opinion about which roots are legitimate, which is exactly
 * what makes it commissionable.
 */
static uint8_t add_trusted_root(struct matter_device_info *info, const struct matter_im_invoke *inv)
{
	const uint8_t *cert = NULL;
	size_t cert_len = 0u;
	struct matter_cert_info ci;

	if (!field_bytes(inv, TAG_ADDROOT_CERT, &cert, &cert_len) || cert_len > MATTER_CERT_MAX) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	if (matter_cert_parse(cert, cert_len, &ci) != MATTER_OK || !ci.have_public_key) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}

	{
		size_t slot = MATTER_SUPPORTED_FABRICS;
		struct matter_fabric *f = fabric_pending(info, &slot);

		/* Every slot already holds a complete fabric. Refused here
		 * rather than at AddNOC, so the commissioner learns before it
		 * mints an operational certificate this node cannot accept. */
		if (f == NULL) {
			return MATTER_IM_STATUS_RESOURCE_EXHAUSTED;
		}
		memcpy(f->root_public_key, ci.public_key, sizeof(ci.public_key));
		f->have_root = true;
		info->attempt.owned_slots |= MATTER_FABRIC_SLOT_BIT(slot);
	}
	return MATTER_IM_STATUS_SUCCESS;
}

/**
 * Accept the operational identity the commissioner minted for this node.
 *
 * @return the NodeOperationalCertStatusEnum for the reply. Every refusal is one
 *         of these rather than an IM status, because each names WHICH input was
 *         wrong and a commissioner can act on that.
 */
static uint8_t add_noc(struct matter_device_info *info, const struct matter_im_invoke *inv)
{
	const uint8_t *noc = NULL;
	const uint8_t *icac = NULL;
	const uint8_t *ipk = NULL;
	size_t noc_len = 0u;
	size_t icac_len = 0u;
	size_t ipk_len = 0u;
	struct matter_cert_info ci;
	struct matter_fabric *fab;
	size_t slot = MATTER_SUPPORTED_FABRICS;
	uint8_t new_index;
	uint64_t admin_subject = 0u;
	uint64_t admin_vendor = 0u;

	if (!info->have_op_key) {
		/* No CSR, so there is no private key behind whatever public key
		 * this NOC certifies. */
		return MATTER_NOC_STATUS_MISSING_CSR;
	}
	fab = fabric_pending(info, &slot);
	if (fab == NULL) {
		/* Every slot holds a complete fabric already. This is what a
		 * second administrator sees on a node built for one, and it is
		 * where Apple stopped: the phone and the home hub each want
		 * their own. */
		return MATTER_NOC_STATUS_TABLE_FULL;
	}
	if (!fab->have_root) {
		return MATTER_NOC_STATUS_INVALID_NOC;
	}

	if (!field_bytes(inv, TAG_ADDNOC_NOC, &noc, &noc_len) || noc_len > MATTER_NOC_MAX ||
	    !field_bytes(inv, TAG_ADDNOC_IPK, &ipk, &ipk_len) || ipk_len != MATTER_IPK_LEN ||
	    !field_u64(inv, TAG_ADDNOC_CASE_ADMIN_SUBJECT, &admin_subject) || admin_subject == 0u ||
	    !field_u64(inv, TAG_ADDNOC_ADMIN_VENDOR_ID, &admin_vendor) ||
	    admin_vendor > UINT16_MAX) {
		return MATTER_NOC_STATUS_INVALID_NOC;
	}
	if (matter_cert_parse(noc, noc_len, &ci) != MATTER_OK || !ci.have_node_id ||
	    !ci.have_fabric_id || !ci.have_public_key) {
		return MATTER_NOC_STATUS_INVALID_NOC;
	}
	/*
	 * The certified key must be the one this node minted for the CSR.
	 * Installing an identity whose private half this node does not hold
	 * would look like success here and surface much later as a CASE that
	 * never completes, with nothing to point at.
	 */
	if (memcmp(ci.public_key, info->op_pub, sizeof(info->op_pub)) != 0) {
		return MATTER_NOC_STATUS_INVALID_PUBLIC_KEY;
	}
	/* Optional: absent when the commissioner signed the NOC with its root
	 * directly, which is what Apple does. */
	(void)field_bytes(inv, TAG_ADDNOC_ICAC, &icac, &icac_len);
	if (icac_len > MATTER_CERT_MAX) {
		return MATTER_NOC_STATUS_INVALID_NOC;
	}
	new_index = fabric_next_index(info);
	if (new_index == 0u) {
		return MATTER_NOC_STATUS_TABLE_FULL;
	}
	/* The constrained target has one ICAC buffer. Refuse a second owner
	 * before mutating either fabric so no certificate is silently replaced. */
	if (icac_len != 0u && info->icac.owner_index != 0u &&
	    info->icac.owner_index != new_index) {
		return MATTER_NOC_STATUS_TABLE_FULL;
	}

	memcpy(fab->noc, noc, noc_len);
	fab->noc_len = noc_len;
	if (icac_len != 0u) {
		memcpy(info->icac.buf, icac, icac_len);
		info->icac.len = icac_len;
		info->icac.owner_index = new_index;
	}
	fab->icac_len = icac_len;
	memcpy(fab->ipk, ipk, ipk_len);
	/*
	 * The key this fabric's NOC certifies, taken from the CSR that preceded
	 * it. Copied INTO the fabric rather than left in info->op_priv: the next
	 * administrator issues its own CSRRequest and overwrites that, and a
	 * node that signed Sigma2 with the wrong fabric's key would verify
	 * against the wrong certificate and be refused with nothing said.
	 */
	memcpy(fab->op_priv, info->op_priv, sizeof(fab->op_priv));
	fab->node_id = ci.node_id;
	fab->fabric_id = ci.fabric_id;
	fab->case_admin_subject = admin_subject;
	fab->admin_vendor_id = (uint16_t)admin_vendor;
	fab->index = new_index;
	/*
	 * Findable on the new fabric, immediately. A second administrator adds
	 * its fabric over an EXISTING CASE session and then has to open a new
	 * one to the identity it has just issued -- which means resolving a
	 * DNS-SD name that only exists once this runs. Registration at
	 * ConnectNetwork covers the first fabric only; that is where the second
	 * administrator stopped, with the fabric accepted and nothing to reach.
	 */
	advertise_one(fab);
	/* Held for the response, which is serialised after this has run. */
	info->last_noc_index = fab->index;
	return MATTER_NOC_STATUS_OK;
}

/**
 * Run one OperationalCredentials command.
 *
 * Everything expensive happens here -- the signature, and for a CSR a fresh
 * P-256 key pair -- because this runs exactly once per request while
 * opcred_fields() may not.
 */
static uint8_t opcred_command(struct matter_device_info *info, const struct matter_im_invoke *inv,
			      uint32_t *response_command)
{
	const uint8_t *nonce = NULL;
	size_t nonce_len = 0u;
	uint64_t v = 0u;
	int rc;

	switch (inv->command) {
	case MATTER_CMD_OC_CERTIFICATE_CHAIN_REQUEST: {
		const uint8_t *cert = NULL;
		size_t cert_len = 0u;

		if (!field_u64(inv, TAG_CERT_TYPE, &v) || v > UINT8_MAX) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		/* Checked here rather than when writing the reply, because a
		 * reply has no way to say "no such certificate". */
		if (matter_attest_cert((uint8_t)v, &cert, &cert_len) != MATTER_OK) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		info->cert_type = (uint8_t)v;
		*response_command = MATTER_CMD_OC_CERTIFICATE_CHAIN_RESPONSE;
		return MATTER_IM_STATUS_SUCCESS;
	}

	case MATTER_CMD_OC_ATTESTATION_REQUEST:
		if (!info->have_challenge) {
			/* Nothing to bind the signature to. Refusing beats
			 * signing something a recorded session could reuse. */
			return MATTER_IM_STATUS_FAILURE;
		}
		if (!field_bytes(inv, TAG_ATTEST_NONCE, &nonce, &nonce_len) ||
		    nonce_len != MATTER_ATTEST_NONCE_LEN) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		/* No clock on this node, and 0 is what a device without one
		 * sends -- not a placeholder for something better. */
		rc = matter_attest_elements_encode(nonce, nonce_len, 0u, info->attest_buf,
						   MATTER_ATTEST_ELEMENTS_MAX, &info->attest_len);
		if (rc != MATTER_OK) {
			return MATTER_IM_STATUS_FAILURE;
		}
		rc = matter_attest_sign_with_challenge(
			info->attest_buf, info->attest_len, sizeof(info->attest_buf),
			info->attestation_challenge, sizeof(info->attestation_challenge),
			info->attest_sig);
		if (rc != MATTER_OK) {
			return MATTER_IM_STATUS_FAILURE;
		}
		*response_command = MATTER_CMD_OC_ATTESTATION_RESPONSE;
		return MATTER_IM_STATUS_SUCCESS;

	case MATTER_CMD_OC_CSR_REQUEST: {
		uint8_t csr[MATTER_CSR_MAX];
		size_t csr_len = 0u;

		if (!info->have_challenge) {
			return MATTER_IM_STATUS_FAILURE;
		}
		if (!field_bytes(inv, TAG_CSR_NONCE, &nonce, &nonce_len) ||
		    nonce_len != MATTER_ATTEST_NONCE_LEN) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		/*
		 * A FRESH key every time. Reusing one across commissioning
		 * attempts would let a fabric that saw an earlier CSR recognise
		 * the node on another.
		 */
		if (matter_attest_ec_keygen(info->op_priv, info->op_pub) != 0) {
			return MATTER_IM_STATUS_FAILURE;
		}
		info->have_op_key = true;
		if (matter_attest_csr(info->op_priv, info->op_pub, csr, sizeof(csr), &csr_len) !=
		    MATTER_OK) {
			return MATTER_IM_STATUS_FAILURE;
		}
		rc = matter_attest_nocsr_encode(csr, csr_len, nonce, nonce_len, info->attest_buf,
						MATTER_ATTEST_ELEMENTS_MAX, &info->attest_len);
		if (rc != MATTER_OK) {
			return MATTER_IM_STATUS_FAILURE;
		}
		rc = matter_attest_sign_with_challenge(
			info->attest_buf, info->attest_len, sizeof(info->attest_buf),
			info->attestation_challenge, sizeof(info->attestation_challenge),
			info->attest_sig);
		if (rc != MATTER_OK) {
			return MATTER_IM_STATUS_FAILURE;
		}
		*response_command = MATTER_CMD_OC_CSR_RESPONSE;
		return MATTER_IM_STATUS_SUCCESS;
	}

	case MATTER_CMD_OC_ADD_TRUSTED_ROOT_CERTIFICATE:
		/*
		 * Both of the commands below change what this node believes
		 * about who owns it, which is precisely what a fail-safe exists
		 * to be able to undo. Doing either outside one would leave a
		 * half-installed identity with nothing scheduled to remove it.
		 */
		if (!info->attempt.active) {
			return MATTER_IM_STATUS_FAILSAFE_REQUIRED;
		}
		/* No response command: the reply is a bare SUCCESS status. */
		*response_command = MATTER_IM_NO_RESPONSE;
		return add_trusted_root(info, inv);

	case MATTER_CMD_OC_ADD_NOC:
		if (!info->attempt.active) {
			return MATTER_IM_STATUS_FAILSAFE_REQUIRED;
		}
		info->last_noc_status = add_noc(info, inv);
		*response_command = MATTER_CMD_OC_NOC_RESPONSE;
		/* SUCCESS means "a NOCResponse follows", not "the NOC was
		 * accepted"; last_noc_status carries the verdict. */
		return MATTER_IM_STATUS_SUCCESS;

	case MATTER_CMD_OC_REMOVE_FABRIC: {
		size_t i;
		size_t accessing_slot;

		/* Reset the response latch before any validation. A rejected request
		 * must never leave a prior successful removal visible to its caller. */
		info->last_noc_status = MATTER_NOC_STATUS_INVALID_FABRIC_INDEX;
		info->last_noc_index = 0u;

		/*
		 * NOT gated on the fail-safe, unlike the additions above: a
		 * removal is administration, not commissioning, and the
		 * controllers that send it -- chip-tool's remove-fabric, a hub
		 * cleaning up after itself -- arm no fail-safe first. A full
		 * table whose orphaned owners can never be removed leaves a
		 * factory wipe as the only way to commission again.
		 *
		 * Portable removal does not guess which credential anchor belongs to
		 * this fabric. Anchors are named by credential index and do not record
		 * their installing fabric. The owning port may still clear the whole
		 * Home Key trust store when this is the last fabric, as the DWM app
		 * does inside its durable-store hook.
		 */
		if (!field_u64(inv, TAG_REMOVE_FABRIC_INDEX, &v)) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		accessing_slot = fabric_slot_for_index(info, info->accessing_fabric_index);
		if (!fabric_slot_has_privilege(info, accessing_slot,
					 MATTER_AC_PRIVILEGE_ADMINISTER, MATTER_ENDPOINT_ROOT,
					 MATTER_CLUSTER_OPERATIONAL_CREDENTIALS)) {
			return MATTER_IM_STATUS_UNSUPPORTED_ACCESS;
		}
		/* An index this table cannot hold and an index it merely does
		 * not hold answer the same way: through the NOCResponse, which
		 * is where a commissioner looks for the verdict. */
		for (i = 0u;
		     v >= 1u && v <= MATTER_SUPPORTED_FABRICS && i < MATTER_SUPPORTED_FABRICS;
		     i++) {
			struct matter_fabric *f = &info->fabrics[i];

			if (f->index != (uint8_t)v) {
				continue;
			}
			/* A successful response must survive reset. Write the targeted
			 * tombstone before dropping keys or withdrawing discovery. */
			if (fabric_store(info, MATTER_FABRIC_STORE_REMOVE, i, NULL, 0u) !=
			    MATTER_OK) {
				*response_command = MATTER_IM_NO_RESPONSE;
				return MATTER_IM_STATUS_FAILURE;
			}
			fabric_slot_clear(info, i);
			info->last_noc_status = MATTER_NOC_STATUS_OK;
			info->last_noc_index = (uint8_t)v;
			break;
		}
		*response_command = MATTER_CMD_OC_NOC_RESPONSE;
		return MATTER_IM_STATUS_SUCCESS;
	}

	default:
		return MATTER_IM_STATUS_UNSUPPORTED_COMMAND;
	}
}

/** Serialise what opcred_command() already computed. */
static void opcred_fields(const struct matter_device_info *info, uint32_t response_command,
			  struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);

	if (response_command == MATTER_CMD_OC_CERTIFICATE_CHAIN_RESPONSE) {
		const uint8_t *cert = NULL;
		size_t cert_len = 0u;

		if (matter_attest_cert(info->cert_type, &cert, &cert_len) == MATTER_OK) {
			(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(TAG_RESP_CERT), cert,
						   cert_len);
		}
	} else if (response_command == MATTER_CMD_OC_NOC_RESPONSE) {
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_NOCRESP_STATUS),
					 info->last_noc_status);
		/*
		 * FabricIndex only on success, and DebugText not at all. Both
		 * are optional and CHIP's own device omits them the same way
		 * (operational-credentials-cluster.cpp, SendNOCResponse) -- an
		 * index for a fabric that was not created would be a number the
		 * commissioner could act on.
		 */
		if (info->last_noc_status == MATTER_NOC_STATUS_OK) {
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_NOCRESP_FABRIC_INDEX),
						 info->last_noc_index);
		}
	} else {
		/* AttestationResponse and CSRResponse are the same shape: the
		 * elements, then the signature over them. */
		(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(TAG_RESP_ELEMENTS), info->attest_buf,
					   info->attest_len);
		(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(TAG_RESP_SIGNATURE), info->attest_sig,
					   sizeof(info->attest_sig));
	}

	(void)matter_tlv_end_container(w);
}

/**
 * SetAliroReaderConfig: the reader identity, delivered by Apple Home.
 *
 * This is the point of the whole Matter node. Until now the reader's private
 * key was a build-time Kconfig string, so every image carried one identity and
 * only unlocked for the phones in whoever built it. This command is how a
 * device gets its own.
 *
 * NOTHING HERE IS LOGGED. Every field is key material, and the signing key is
 * not even kept in this struct: it goes straight to the port's callback, which
 * persists it, and is wiped from the stack on the way out.
 *
 * The group resolving key is optional in the schema but not here: this node
 * claims the BLE-UWB feature, and that is exactly the bit that makes it
 * mandatory. Accepting a config without it would leave the reader unable to
 * resolve the group it was just told it belongs to.
 */
/**
 * SetCredential: the credential trust anchor.
 *
 * The reader identity says who this device IS; this says whose key it will
 * open for. Without it a provisioned reader still holds 0 trust anchors and
 * no phone can unlock it, which is the last functional gap before a walk-up.
 *
 * The key is handed to the port unchanged and NOT stored here: the reader's
 * own trust store owns it, decides whether it is a valid P-256 point, and
 * persists it. Duplicating it in this struct would be a second copy of a
 * secret with no reader to use it.
 *
 * The response is REQUIRED even for a refusal -- SetCredential is answered
 * with SetCredentialResponse carrying a status, not with a bare command
 * status, and a controller that gets the wrong shape treats it as no answer.
 */
static uint8_t set_credential(struct matter_device_info *info, const struct matter_im_invoke *inv,
			      uint32_t *response_command)
{
	const uint8_t *data = NULL;
	size_t data_len = 0u;
	uint64_t user_index = 0u;
	uint64_t cred_type = 0u;

	*response_command = MATTER_CMD_DL_SET_CREDENTIAL_RESPONSE;
	info->last_credential_status = MATTER_IM_STATUS_FAILURE;
	info->last_user_index = 0u;

	/* The type lives inside the nested CredentialStruct, not beside it. */
	if (!field_struct_u64(inv, TAG_SETCRED_CREDENTIAL, TAG_CREDSTRUCT_TYPE, &cred_type) ||
	    !field_bytes(inv, TAG_SETCRED_DATA, &data, &data_len)) {
		info->last_credential_status = MATTER_IM_STATUS_INVALID_COMMAND;
		return MATTER_IM_STATUS_SUCCESS;
	}
	if (cred_type != MATTER_DL_CRED_ALIRO_ISSUER_KEY &&
	    cred_type != MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT &&
	    cred_type != MATTER_DL_CRED_ALIRO_ENDPOINT_KEY) {
		/* PIN, RFID, fingerprint, face: surfaces this node does not
		 * claim, so refusing is the truthful answer rather than storing
		 * something the reader can never use. */
		info->last_credential_status = MATTER_IM_STATUS_UNSUPPORTED_COMMAND;
		return MATTER_IM_STATUS_SUCCESS;
	}
	if (data_len != MATTER_ALIRO_VERIFICATION_KEY_LEN) {
		info->last_credential_status = MATTER_IM_STATUS_CONSTRAINT_ERROR;
		return MATTER_IM_STATUS_SUCCESS;
	}
	/*
	 * Both indices are read BEFORE the store is told, because they are the
	 * only handle a later ClearCredential or ClearUser has on this key --
	 * neither command carries key bytes. An absent field stays 0, which the
	 * store reads as "no Matter index" and refuses to match.
	 */
	uint64_t cred_index = 0u;
	bool have_user_index;

	(void)field_struct_u64(inv, TAG_SETCRED_CREDENTIAL, TAG_CREDSTRUCT_INDEX, &cred_index);
	have_user_index = field_u64(inv, TAG_SETCRED_USER_INDEX, &user_index);
	if (cred_index > 0xFFFFu || user_index > 0xFFFFu) {
		/* TLV carries these as unsigned integers of any width, and the
		 * store's are 16-bit. Truncating would bind the anchor to an index
		 * the admin never sent -- 0x10001 becomes 1 -- and a later
		 * ClearCredential(1) would then revoke somebody else's key.
		 * ClearCredential refuses an out-of-range index the same way. */
		info->last_credential_status = MATTER_IM_STATUS_INVALID_COMMAND;
		return MATTER_IM_STATUS_SUCCESS;
	}
	if (have_user_index) {
		info->last_user_index = (uint16_t)user_index;
	}
	if (info->ultrawidelock_credential_cb == NULL ||
	    info->ultrawidelock_credential_cb((uint8_t)cred_type, data, (uint16_t)cred_index,
				      (uint16_t)user_index) < 0) {
		info->last_user_index = 0u;      /* nothing was stored to attribute */
		return MATTER_IM_STATUS_SUCCESS; /* status stays FAILURE */
	}
	info->last_credential_status = MATTER_IM_STATUS_SUCCESS;
	return MATTER_IM_STATUS_SUCCESS;
}

/**
 * Decode and store credential reader configuration: signing key, verification key (P-256 public),
 * group ID, and group-resolving key. Validate all field lengths exactly, call the registered config
 * hook to persist them, and store copies in the device info structure. Return a status code.
 */
static uint8_t set_ultrawidelock_reader_config(struct matter_device_info *info,
				       const struct matter_im_invoke *inv)
{
	const uint8_t *signing = NULL;
	const uint8_t *verification = NULL;
	const uint8_t *group_id = NULL;
	const uint8_t *grk = NULL;
	size_t signing_len = 0u;
	size_t verification_len = 0u;
	size_t group_id_len = 0u;
	size_t grk_len = 0u;

	if (!field_bytes(inv, TAG_ALIRO_CFG_SIGNING_KEY, &signing, &signing_len) ||
	    !field_bytes(inv, TAG_ALIRO_CFG_VERIFICATION_KEY, &verification, &verification_len) ||
	    !field_bytes(inv, TAG_ALIRO_CFG_GROUP_ID, &group_id, &group_id_len)) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	/*
	 * Lengths are checked before anything is copied, and checked exactly:
	 * a 64-byte "P-256 public key" is a different thing from a 65-byte one
	 * and would be stored happily by a length-tolerant reader.
	 */
	if (signing_len != MATTER_ALIRO_SIGNING_KEY_LEN ||
	    verification_len != MATTER_ALIRO_VERIFICATION_KEY_LEN ||
	    group_id_len != MATTER_ALIRO_GROUP_ID_LEN) {
		return MATTER_IM_STATUS_CONSTRAINT_ERROR;
	}
	if (!field_bytes(inv, TAG_ALIRO_CFG_GROUP_RESOLVING_KEY, &grk, &grk_len) ||
	    grk_len != MATTER_ALIRO_GROUP_ID_LEN) {
		return MATTER_IM_STATUS_CONSTRAINT_ERROR;
	}

	if (info->ultrawidelock_reader_config_cb == NULL) {
		/* No store to write to. Reporting success would claim an
		 * identity was kept that will be gone at the next boot. */
		return MATTER_IM_STATUS_FAILURE;
	}
	if (info->ultrawidelock_reader_config_cb(signing, verification, group_id, grk) != 0) {
		return MATTER_IM_STATUS_FAILURE;
	}

	memcpy(info->ultrawidelock_verification_key, verification, MATTER_ALIRO_VERIFICATION_KEY_LEN);
	memcpy(info->ultrawidelock_group_id, group_id, MATTER_ALIRO_GROUP_ID_LEN);
	memcpy(info->ultrawidelock_group_resolving_key, grk, MATTER_ALIRO_GROUP_ID_LEN);
	info->have_ultrawidelock_group_resolving_key = true;
	info->have_ultrawidelock_reader_config = true;
	return MATTER_IM_STATUS_SUCCESS;
}

/**
 * ClearCredential (0x0026): stop honouring one credential, every credential of one type, or
 * every credential there is.
 *
 * The command names its target by (type, index) and never by key, so this is only answerable
 * because SetCredential recorded the index the key was installed under. An absent or null
 * Credential field means all types (door-lock-server.cpp:1021-1025); index 0xFFFE means all of the
 * named type (:1040-1044).
 *
 * FAILURE rather than SUCCESS whenever the port could not make the removal stick. An admin who is
 * told a key was removed stops looking, so a removal that would come back on the next boot must not
 * be reported as done. "Nothing carried that index" is NOT such a case: the named credential is not
 * trusted either way, and the reference server answers a clear of an unoccupied slot with success
 * too (:3025-3029).
 */
static uint8_t clear_credential(struct matter_device_info *info, const struct matter_im_invoke *inv)
{
	uint64_t cred_type = 0u;
	uint64_t cred_index = 0u;

	if (info->ultrawidelock_credential_clear_cb == NULL) {
		return MATTER_IM_STATUS_FAILURE;
	}
	if (!field_struct_u64(inv, TAG_CLEARCRED_CREDENTIAL, TAG_CREDSTRUCT_TYPE, &cred_type)) {
		/* Null or absent: every credential of every type. Type 0 is not a
		 * credential type, which is what makes it usable as that flag. */
		return info->ultrawidelock_credential_clear_cb(0u, MATTER_DL_INDEX_ALL) == 0
			       ? MATTER_IM_STATUS_SUCCESS
			       : MATTER_IM_STATUS_FAILURE;
	}
	if (cred_type != MATTER_DL_CRED_ALIRO_ISSUER_KEY &&
	    cred_type != MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT &&
	    cred_type != MATTER_DL_CRED_ALIRO_ENDPOINT_KEY) {
		/* Same answer SetCredential gives for a type this node never
		 * claimed: it cannot be holding one to clear. */
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	if (!field_struct_u64(inv, TAG_CLEARCRED_CREDENTIAL, TAG_CREDSTRUCT_INDEX, &cred_index) ||
	    cred_index == 0u || cred_index > 0xFFFFu) {
		/* Indices are 1-based, so 0 is not a slot this lock could hold. */
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	return info->ultrawidelock_credential_clear_cb((uint8_t)cred_type, (uint16_t)cred_index) == 0
		       ? MATTER_IM_STATUS_SUCCESS
		       : MATTER_IM_STATUS_FAILURE;
}

/**
 * ClearUser (0x001D): forget a user slot and every credential bound to it.
 *
 * Answered because a controller may remove a person without ever naming their credentials -- the
 * reference server clears a user's credentials as part of clearing the user
 * (door-lock-server.cpp:2109-2135). A node that dropped the user row and kept the credential would
 * report an empty slot while still opening for the phone in it.
 *
 * The row is cleared before the port is called and stays cleared even when the port reports a
 * failure, because the failure means "not persisted", not "still trusted": the credential is
 * already untrusted in RAM by then, and a user row that outlived it would be the lie.
 *
 * A port that registered no hook is the other way round, which is why the check comes first: no
 * removal was attempted, the credential is still trusted, and emptying the row would leave the
 * controller reading an empty slot whose key still opens the door. ClearCredential refuses the
 * same way.
 */
static uint8_t clear_user(struct matter_device_info *info, const struct matter_im_invoke *inv)
{
	uint64_t idx = 0u;

	if (!field_u64(inv, TAG_CLEARUSER_INDEX, &idx) || idx == 0u ||
	    (idx > MATTER_DL_USERS_MAX && idx != MATTER_DL_INDEX_ALL)) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	if (info->ultrawidelock_user_clear_cb == NULL) {
		return MATTER_IM_STATUS_FAILURE;
	}
	if (idx == MATTER_DL_INDEX_ALL) {
		memset(info->users, 0, sizeof(info->users));
	} else {
		memset(&info->users[idx - 1u], 0, sizeof(info->users[0]));
	}
	return info->ultrawidelock_user_clear_cb((uint16_t)idx) == 0 ? MATTER_IM_STATUS_SUCCESS
							     : MATTER_IM_STATUS_FAILURE;
}

static uint8_t command(void *ctx, const struct matter_im_invoke *inv, uint32_t *response_command)
{
	struct matter_device_info *info = (struct matter_device_info *)ctx;
	uint64_t v = 0u;

	/*
	 * The lock endpoint answers commands too. Refusing every command here
	 * with UNSUPPORTED_ENDPOINT while Descriptor, PartsList and every
	 * attribute read say endpoint 1 exists is a direct self-contradiction,
	 * and it is what a real controller reported back as "the endpoint
	 * indicated is unsupported on the node" before abandoning the pairing.
	 *
	 * UNSUPPORTED_COMMAND is the honest answer for the Door Lock commands
	 * this node has not implemented: the endpoint and the cluster are both
	 * real, the command is not. A controller can act on that; it cannot act
	 * on an endpoint that claims to exist and not exist at once.
	 */
	if (inv->endpoint == MATTER_ENDPOINT_LOCK) {
		size_t accessing_slot =
			fabric_slot_for_index(info, info->accessing_fabric_index);

		if (inv->cluster != MATTER_CLUSTER_DOOR_LOCK) {
			return MATTER_IM_STATUS_UNSUPPORTED_CLUSTER;
		}
		/* PASE, a removed fabric, and a provisional identity cannot operate
		 * the lock or mutate its credential database. */
		if (accessing_slot >= MATTER_SUPPORTED_FABRICS || info->accessing_node_id == 0u) {
			return MATTER_IM_STATUS_UNSUPPORTED_ACCESS;
		}
		if (inv->command == MATTER_CMD_DL_LOCK_DOOR ||
		    inv->command == MATTER_CMD_DL_UNLOCK_DOOR) {
			if (!fabric_slot_has_privilege(info, accessing_slot,
						 MATTER_AC_PRIVILEGE_OPERATE, MATTER_ENDPOINT_LOCK,
						 MATTER_CLUSTER_DOOR_LOCK)) {
				return MATTER_IM_STATUS_UNSUPPORTED_ACCESS;
			}
			/*
			 * The tile's two buttons. Answered with a bare status,
			 * which is what DoorLock defines for both -- there is no
			 * LockDoorResponse, and inventing one leaves the
			 * controller waiting.
			 *
			 * The optional PINCode field is ignored rather than
			 * rejected: this node advertises no PIN_CREDENTIAL
			 * feature, so a controller sends none, and refusing a
			 * command over a field nobody sends would fail every
			 * press.
			 */
			info->lock_state = (inv->command == MATTER_CMD_DL_UNLOCK_DOOR)
						   ? MATTER_DL_LOCK_STATE_UNLOCKED
						   : MATTER_DL_LOCK_STATE_LOCKED;
			/*
			 * Recorded here rather than by the caller, because this is
			 * the only place that knows the command ran AND which
			 * fabric asked. SourceNode is left unknown: the peer's node
			 * id belongs to the CASE session, which this layer never
			 * sees, and the fabric's own node id is THIS node's -- it
			 * would name the lock as the thing that unlocked the lock.
			 */
			matter_clusters_record_lock_operation(
				info,
				(inv->command == MATTER_CMD_DL_UNLOCK_DOOR)
					? MATTER_DL_LOCK_OP_UNLOCK
					: MATTER_DL_LOCK_OP_LOCK,
				MATTER_DL_OP_SOURCE_REMOTE, info->accessing_fabric_index, 0u);
			return MATTER_IM_STATUS_SUCCESS;
		}
		if (!fabric_slot_has_privilege(info, accessing_slot,
					 MATTER_AC_PRIVILEGE_ADMINISTER, MATTER_ENDPOINT_LOCK,
					 MATTER_CLUSTER_DOOR_LOCK)) {
			return MATTER_IM_STATUS_UNSUPPORTED_ACCESS;
		}
		if (inv->command == MATTER_CMD_DL_SET_ALIRO_READER_CONFIG) {
			return set_ultrawidelock_reader_config(info, inv);
		}
		if (inv->command == MATTER_CMD_DL_SET_CREDENTIAL) {
			return set_credential(info, inv, response_command);
		}
		if (inv->command == MATTER_CMD_DL_CLEAR_CREDENTIAL) {
			return clear_credential(info, inv);
		}
		if (inv->command == MATTER_CMD_DL_CLEAR_USER) {
			return clear_user(info, inv);
		}
		if (inv->command == MATTER_CMD_DL_SET_USER) {
			/*
			 * Stored, not merely accepted. Apple writes a user here
			 * and reads it straight back with GetUser, so a node
			 * that says SUCCESS and then reports an empty slot has
			 * told the controller two different things about the
			 * same user.
			 *
			 * OperationType is read but not distinguished: Add and
			 * Modify differ only in whether the slot was already
			 * occupied, and overwriting is the right answer to both
			 * for a table that holds no credentials of its own yet.
			 */
			struct matter_user *u;
			uint64_t idx = 0u;

			if (!field_u64(inv, TAG_SETUSER_INDEX, &idx) || idx == 0u ||
			    idx > MATTER_DL_USERS_MAX) {
				return MATTER_IM_STATUS_INVALID_COMMAND;
			}
			u = &info->users[idx - 1u];
			u->in_use = true;
			u->creator_fabric = info->accessing_fabric_index;
			u->modifier_fabric = info->accessing_fabric_index;
			u->unique_id = field_u64(inv, TAG_SETUSER_UNIQUE_ID, &v) ? (uint32_t)v : 0u;
			u->status = field_u64(inv, TAG_SETUSER_STATUS, &v) ? (uint8_t)v : 1u;
			u->type = field_u64(inv, TAG_SETUSER_TYPE, &v) ? (uint8_t)v : 0u;
			u->credential_rule =
				field_u64(inv, TAG_SETUSER_CREDENTIAL_RULE, &v) ? (uint8_t)v : 0u;
			/* No response command: SetUser is answered with a bare
			 * status, which the IM layer sends for SUCCESS. */
			return MATTER_IM_STATUS_SUCCESS;
		}
		if (inv->command == MATTER_CMD_DL_GET_CREDENTIAL_STATUS) {
			/*
			 * Asked right after the reader identity lands, to find
			 * out whether the credential about to be installed is
			 * already here. It is not: this node holds no
			 * credential database, so the honest answer is that it
			 * does not exist. Refusing the command instead ends the
			 * pairing, exactly as refusing GetUser did.
			 */
			*response_command = MATTER_CMD_DL_GET_CREDENTIAL_STATUS_RESPONSE;
			return MATTER_IM_STATUS_SUCCESS;
		}
		if (inv->command == MATTER_CMD_DL_GET_USER) {
			/*
			 * Answered because a real controller invokes it during
			 * commissioning and gives up when it is refused -- it
			 * reported "the specified action or command indicated
			 * is not supported" and sent RemoveFabric.
			 *
			 * The answer is an EMPTY slot, which is the truth:
			 * there is no user database here yet. UserIndex is
			 * echoed and every other field is null, which is how
			 * the spec says an unoccupied slot reads.
			 */
			if (!field_u64(inv, TAG_GETUSER_INDEX, &v) || v == 0u ||
			    v > MATTER_DL_USERS_MAX) {
				return MATTER_IM_STATUS_INVALID_COMMAND;
			}
			info->last_user_index = (uint16_t)v;
			*response_command = MATTER_CMD_DL_GET_USER_RESPONSE;
			return MATTER_IM_STATUS_SUCCESS;
		}
		return MATTER_IM_STATUS_UNSUPPORTED_COMMAND;
	}
	if (inv->endpoint != MATTER_ENDPOINT_ROOT) {
		return MATTER_IM_STATUS_UNSUPPORTED_ENDPOINT;
	}
	if (inv->cluster == MATTER_CLUSTER_ADMIN_COMMISSIONING) {
		size_t accessing_slot =
			fabric_slot_for_index(info, info->accessing_fabric_index);

		if (!fabric_slot_has_privilege(info, accessing_slot,
					 MATTER_AC_PRIVILEGE_ADMINISTER, MATTER_ENDPOINT_ROOT,
					 MATTER_CLUSTER_ADMIN_COMMISSIONING)) {
			return MATTER_IM_STATUS_UNSUPPORTED_ACCESS;
		}
		return admin_command(inv, response_command);
	}
	if (inv->cluster == MATTER_CLUSTER_OPERATIONAL_CREDENTIALS) {
		return opcred_command(info, inv, response_command);
	}
	if (inv->cluster == MATTER_CLUSTER_NETWORK_COMMISSIONING) {
		return network_command(info, inv, response_command);
	}
	if (inv->cluster != MATTER_CLUSTER_GENERAL_COMMISSIONING) {
		return MATTER_IM_STATUS_UNSUPPORTED_CLUSTER;
	}

	switch (inv->command) {
	case MATTER_CMD_GC_ARM_FAIL_SAFE:
		/*
		 * The breadcrumb is the commissioner's own progress marker: it
		 * sets it here and reads it back if it has to resume, so losing
		 * it makes a retry restart from nothing.
		 */
		{
			uint64_t expiry = 0u;
			bool new_attempt = !info->attempt.active;

			if (!field_u64(inv, 0u, &expiry) || expiry > info->failsafe_max_s) {
				info->last_commissioning_error =
					MATTER_COMMISSIONING_VALUE_OUTSIDE_RANGE;
				*response_command = MATTER_CMD_GC_ARM_FAIL_SAFE_RESPONSE;
				return MATTER_IM_STATUS_SUCCESS;
			}
			if (field_u64(inv, 1u, &v)) {
				info->breadcrumb = v;
			}
			if (expiry == 0u) {
				matter_clusters_failsafe_expire(info);
				info->last_commissioning_error = MATTER_COMMISSIONING_OK;
				*response_command = MATTER_CMD_GC_ARM_FAIL_SAFE_RESPONSE;
				return MATTER_IM_STATUS_SUCCESS;
			}
			if (!info->attempt.active) {
				memset(&info->attempt, 0, sizeof(info->attempt));
				info->attempt.active = true;
			}
			if (info->commissioning_hooks != NULL &&
			    info->commissioning_hooks->failsafe_arm != NULL &&
			    info->commissioning_hooks->failsafe_arm(
				    info->commissioning_hooks->ctx, (uint16_t)expiry) != MATTER_OK) {
				if (new_attempt) {
					memset(&info->attempt, 0, sizeof(info->attempt));
				}
				info->last_commissioning_error =
					MATTER_COMMISSIONING_BUSY_WITH_OTHER;
				*response_command = MATTER_CMD_GC_ARM_FAIL_SAFE_RESPONSE;
				return MATTER_IM_STATUS_SUCCESS;
			}
		}
		info->last_commissioning_error = MATTER_COMMISSIONING_OK;
		*response_command = MATTER_CMD_GC_ARM_FAIL_SAFE_RESPONSE;
		return MATTER_IM_STATUS_SUCCESS;

	case MATTER_CMD_GC_SET_REGULATORY_CONFIG:
		if (field_u64(inv, 0u, &v)) {
			/* Accept only what LocationCapability claims to support.
			 * Saying yes to a location this node cannot honour is a
			 * lie the commissioner has no way to detect. */
			if (v != info->location_capability &&
			    info->location_capability != MATTER_REGULATORY_INDOOR_OUTDOOR) {
				info->last_commissioning_error =
					MATTER_COMMISSIONING_VALUE_OUTSIDE_RANGE;
				*response_command = MATTER_CMD_GC_SET_REGULATORY_CONFIG_RESPONSE;
				return MATTER_IM_STATUS_SUCCESS;
			}
			info->regulatory_config = (uint8_t)v;
		}
		if (field_u64(inv, 2u, &v)) {
			info->breadcrumb = v;
		}
		info->last_commissioning_error = MATTER_COMMISSIONING_OK;
		*response_command = MATTER_CMD_GC_SET_REGULATORY_CONFIG_RESPONSE;
		return MATTER_IM_STATUS_SUCCESS;

	case MATTER_CMD_GC_COMMISSIONING_COMPLETE:
	{
		size_t slot;

		*response_command = MATTER_CMD_GC_COMMISSIONING_COMPLETE_RESPONSE;
		/*
		 * Refused over anything but CASE, and NO_FAIL_SAFE rather than
		 * OK because OK would be a lie: the command asserts that the
		 * commissioner has reached this node operationally, and until a
		 * CASE session exists it has not. Telling the truth makes the
		 * commissioner fail cleanly instead of believing it owns a node
		 * it cannot reach.
		 */
		if (!info->attempt.active || info->accessing_fabric_index == 0u ||
		    info->accessing_node_id == 0u) {
			info->last_commissioning_error = MATTER_COMMISSIONING_NO_FAIL_SAFE;
			return MATTER_IM_STATUS_SUCCESS;
		}
		for (slot = 0u; slot < MATTER_SUPPORTED_FABRICS; slot++) {
			const struct matter_fabric *f = &info->fabrics[slot];

			if ((info->attempt.owned_slots & MATTER_FABRIC_SLOT_BIT(slot)) != 0u &&
			    f->index == info->accessing_fabric_index &&
			    acl_subject_matches(f->case_admin_subject, info->accessing_node_id,
					info->accessing_cats, info->accessing_cat_count)) {
				break;
			}
		}
		if (slot >= MATTER_SUPPORTED_FABRICS ||
		    (info->committed_slots == 0u && !info->attempt.have_thread_candidate)) {
			info->last_commissioning_error = MATTER_COMMISSIONING_INVALID_AUTH;
			return MATTER_IM_STATUS_SUCCESS;
		}
		if (fabric_store(info, MATTER_FABRIC_STORE_COMMIT_ATTEMPT, slot, NULL, 0u) !=
		    MATTER_OK) {
			info->last_commissioning_error = MATTER_COMMISSIONING_BUSY_WITH_OTHER;
			return MATTER_IM_STATUS_SUCCESS;
		}
		/*
		 * Commit. Disarming the fail-safe is the substance of the
		 * command, not bookkeeping: until this point every fabric,
		 * every key and the whole operational identity are provisional
		 * and matter_clusters_failsafe_expire() will erase them.
		 */
		if (info->attempt.have_thread_candidate) {
			memcpy(info->thread_dataset, info->attempt.thread_dataset,
			       info->attempt.thread_dataset_len);
			info->thread_dataset_len = info->attempt.thread_dataset_len;
			memcpy(info->thread_xpanid, info->attempt.thread_xpanid,
			       MATTER_THREAD_XPANID_LEN);
			info->have_thread_xpanid = true;
		}
		info->committed_slots |= info->attempt.owned_slots;
		memset(&info->attempt, 0, sizeof(info->attempt));
		if (info->commissioning_hooks != NULL &&
		    info->commissioning_hooks->failsafe_cancel != NULL) {
			info->commissioning_hooks->failsafe_cancel(info->commissioning_hooks->ctx);
		}
		info->last_commissioning_error = MATTER_COMMISSIONING_OK;
		return MATTER_IM_STATUS_SUCCESS;
	}

	default:
		return MATTER_IM_STATUS_UNSUPPORTED_COMMAND;
	}
}

/**
 * Encode the fields of a command response based on endpoint, cluster, and response command type.
 * Handles Door Lock SetCredentialResponse and GetCredentialStatusResponse on the lock endpoint, and
 * OperationalCredentials, NetworkCommissioning, and GeneralCommissioning responses on the root
 * endpoint.
 */
static void command_fields(void *ctx, uint16_t endpoint, uint32_t cluster,
			   uint32_t response_command, struct matter_tlv_writer *w,
			   matter_tlv_tag_t tag)
{
	const struct matter_device_info *info = (const struct matter_device_info *)ctx;

	if (endpoint == MATTER_ENDPOINT_LOCK) {
		if (cluster == MATTER_CLUSTER_DOOR_LOCK &&
		    response_command == MATTER_CMD_DL_SET_CREDENTIAL_RESPONSE) {
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_SETCREDRESP_STATUS),
						 info->last_credential_status);
			if (info->last_user_index != 0u) {
				(void)matter_tlv_put_u64(w,
							 MATTER_TLV_CTX(TAG_SETCREDRESP_USER_INDEX),
							 info->last_user_index);
			} else {
				(void)matter_tlv_put_null(
					w, MATTER_TLV_CTX(TAG_SETCREDRESP_USER_INDEX));
			}
			/* No next index: this node keeps no credential list to
			 * walk, and a number here would invite a read of a slot
			 * that does not exist. */
			(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_SETCREDRESP_NEXT_INDEX));
			(void)matter_tlv_end_container(w);
			return;
		}
		if (cluster == MATTER_CLUSTER_DOOR_LOCK &&
		    response_command == MATTER_CMD_DL_GET_CREDENTIAL_STATUS_RESPONSE) {
			/* Does not exist, and nothing describes a credential
			 * that is not there. CredentialData is omitted rather
			 * than null: it is only ever present for a credential
			 * that exists, and only to an administrator. */
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
			(void)matter_tlv_put_bool(w, MATTER_TLV_CTX(TAG_CREDSTATUS_EXISTS), false);
			(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_CREDSTATUS_USER_INDEX));
			(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_CREDSTATUS_CREATOR_FABRIC));
			(void)matter_tlv_put_null(w,
						  MATTER_TLV_CTX(TAG_CREDSTATUS_MODIFIER_FABRIC));
			(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_CREDSTATUS_NEXT_INDEX));
			(void)matter_tlv_end_container(w);
			return;
		}
		if (cluster == MATTER_CLUSTER_DOOR_LOCK &&
		    response_command == MATTER_CMD_DL_GET_USER_RESPONSE) {
			/*
			 * An unoccupied slot: the index that was asked for, and
			 * null for everything that describes a user who is not
			 * there. NextUserIndex is null too -- there is no next
			 * occupied slot to walk to.
			 *
			 * The CommandFields STRUCTURE is opened here, by the
			 * callee, exactly as opcred_fields and network_fields
			 * do. Writing the fields bare puts them in the
			 * CommandDataIB beside the path instead of inside it,
			 * and the result is a response that encodes without
			 * error, decodes as garbage, and is simply dropped.
			 */
			{
				const struct matter_user *u =
					&info->users[info->last_user_index - 1u];

				(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_GETUSER_INDEX),
							 info->last_user_index);
				/* The name is never stored, so it is always null
				 * -- which is a legal answer and not a claim
				 * that the slot is empty. */
				(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_GETUSER_NAME));
				if (!u->in_use) {
					(void)matter_tlv_put_null(
						w, MATTER_TLV_CTX(TAG_GETUSER_UNIQUE_ID));
					(void)matter_tlv_put_null(
						w, MATTER_TLV_CTX(TAG_GETUSER_STATUS));
					(void)matter_tlv_put_null(w,
								  MATTER_TLV_CTX(TAG_GETUSER_TYPE));
					(void)matter_tlv_put_null(
						w, MATTER_TLV_CTX(TAG_GETUSER_CREDENTIAL_RULE));
					(void)matter_tlv_put_null(
						w, MATTER_TLV_CTX(TAG_GETUSER_CREATOR_FABRIC));
					(void)matter_tlv_put_null(
						w, MATTER_TLV_CTX(TAG_GETUSER_MODIFIER_FABRIC));
				} else {
					(void)matter_tlv_put_u64(
						w, MATTER_TLV_CTX(TAG_GETUSER_UNIQUE_ID),
						u->unique_id);
					(void)matter_tlv_put_u64(
						w, MATTER_TLV_CTX(TAG_GETUSER_STATUS), u->status);
					(void)matter_tlv_put_u64(
						w, MATTER_TLV_CTX(TAG_GETUSER_TYPE), u->type);
					(void)matter_tlv_put_u64(
						w, MATTER_TLV_CTX(TAG_GETUSER_CREDENTIAL_RULE),
						u->credential_rule);
					(void)matter_tlv_put_u64(
						w, MATTER_TLV_CTX(TAG_GETUSER_CREATOR_FABRIC),
						u->creator_fabric);
					(void)matter_tlv_put_u64(
						w, MATTER_TLV_CTX(TAG_GETUSER_MODIFIER_FABRIC),
						u->modifier_fabric);
				}
				/* Credentials is a LIST, and an empty list is
				 * not the same answer as null: null says the
				 * slot is empty, empty says the user exists and
				 * holds none. */
				if (u->in_use) {
					(void)matter_tlv_start_container(
						w, MATTER_TLV_CTX(TAG_GETUSER_CREDENTIALS),
						MATTER_TLV_ARRAY);
					(void)matter_tlv_end_container(w);
				} else {
					(void)matter_tlv_put_null(
						w, MATTER_TLV_CTX(TAG_GETUSER_CREDENTIALS));
				}
				(void)matter_tlv_put_null(w,
							  MATTER_TLV_CTX(TAG_GETUSER_NEXT_INDEX));
				(void)matter_tlv_end_container(w);
			}
		}
		return;
	}
	(void)endpoint;

	if (cluster == MATTER_CLUSTER_OPERATIONAL_CREDENTIALS) {
		opcred_fields(info, response_command, w, tag);
		return;
	}
	if (cluster == MATTER_CLUSTER_NETWORK_COMMISSIONING) {
		network_fields(info, response_command, w, tag);
		return;
	}
	(void)response_command;

	/*
	 * All three GeneralCommissioning responses carry the same two fields:
	 * ErrorCode then DebugText (Commands.h:133-134, 209-210). DebugText is
	 * mandatory and empty, not omitted -- a missing mandatory field is a
	 * decode failure at the commissioner, which presents as a hang.
	 */
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(0u), info->last_commissioning_error);
	(void)matter_tlv_put_utf8(w, MATTER_TLV_CTX(1u), "", 0u);
	(void)matter_tlv_end_container(w);
}

int matter_clusters_resume(struct matter_device_info *info)
{
	if (info == NULL || info->thread_dataset_len == 0u) {
		return MATTER_E_STATE;
	}

	info->thread_started =
		matter_thread_start(info->thread_dataset, info->thread_dataset_len) == MATTER_OK;
	if (!info->thread_started) {
		return MATTER_E_STATE;
	}

	/*
	 * Advertise every restored fabric, not just the first. The same rule as
	 * AddNOC: an administrator resolving a name this node never registered
	 * finds nothing and gives up, and on a reboot there is no commissioner
	 * coming along afterwards to fix it.
	 */
	advertise_operational(info);
	return MATTER_OK;
}

/**
 * Roll back fabric state created after the fail-safe was armed, wiping every
 * provisional fabric's private key and intermediate certificate.
 */
void matter_clusters_failsafe_expire(struct matter_device_info *info)
{
	size_t slot;

	if (info == NULL || !info->attempt.active) {
		return;
	}

	/*
	 * Only fabric slots created inside this fail-safe. Slots captured when it
	 * was armed belong to completed commissioning transactions and must
	 * survive a later administrator abandoning its own AddNOC. Wipe each new
	 * slot in full because it holds the private key its NOC certifies.
	 */
	for (slot = 0u; slot < MATTER_SUPPORTED_FABRICS; slot++) {
		if ((info->attempt.owned_slots & MATTER_FABRIC_SLOT_BIT(slot)) != 0u) {
			fabric_slot_clear(info, slot);
		}
	}
	if (info->attempt.thread_applied) {
		if (info->committed_slots != 0u && info->thread_dataset_len != 0u) {
			info->thread_started =
				matter_thread_start(info->thread_dataset, info->thread_dataset_len) ==
				MATTER_OK;
			if (info->thread_started) {
				advertise_operational(info);
			}
		} else {
			(void)matter_thread_clear();
			info->thread_started = false;
		}
	}
	memset(info->op_priv, 0, sizeof(info->op_priv));
	memset(info->op_pub, 0, sizeof(info->op_pub));
	info->have_op_key = false;
	info->last_noc_status = MATTER_NOC_STATUS_OK;

	memset(&info->attempt, 0, sizeof(info->attempt));
	info->breadcrumb = 0u;
	info->last_commissioning_error = MATTER_COMMISSIONING_OK;
}

/**
 * Apply an attribute write.
 *
 * One attribute is writable on this node: the ACL. A commissioner's last act is
 * writing itself an entry granting Administer over CASE, and refusing it leaves
 * a home app that finished commissioning and then cannot record that it owns
 * the node -- which is what "Adding to home" is waiting on.
 *
 * The value is stored byte-for-byte so it can be reported back. The bounded
 * access checker above decodes only the fields needed for CASE authorization.
 */
static uint8_t attr_write(void *ctx, const struct matter_im_path *path, const uint8_t *data,
			  size_t data_len)
{
	struct matter_device_info *info = (struct matter_device_info *)ctx;
	size_t slot;

	if (info == NULL) {
		return MATTER_IM_STATUS_UNSUPPORTED_ENDPOINT;
	}
	if (path->endpoint == MATTER_ENDPOINT_LOCK) {
		size_t accessing_slot =
			fabric_slot_for_index(info, info->accessing_fabric_index);

		if (!fabric_slot_has_privilege(info, accessing_slot,
					 MATTER_AC_PRIVILEGE_ADMINISTER, path->endpoint,
					 path->cluster)) {
			return MATTER_IM_STATUS_UNSUPPORTED_ACCESS;
		}
		if (path->cluster == MATTER_CLUSTER_APPROACH_DIRECTION) {
			struct matter_tlv_reader r;
			uint64_t v = 0u;

			if (path->attribute != MATTER_ATTR_APPROACH_DIRECTION) {
				return MATTER_IM_STATUS_UNSUPPORTED_WRITE;
			}
			if (data == NULL || data_len == 0u) {
				return MATTER_IM_STATUS_INVALID_COMMAND;
			}
			matter_tlv_reader_init(&r, data, data_len);
			if (matter_tlv_next(&r) != 0 || matter_tlv_get_u64(&r, &v) != 0) {
				return MATTER_IM_STATUS_INVALID_COMMAND;
			}
			/* bitmap8; a wider value is the controller's error. */
			if (v > 0xFFu) {
				return MATTER_IM_STATUS_CONSTRAINT_ERROR;
			}
			info->approach_direction = (uint8_t)v;
			return MATTER_IM_STATUS_SUCCESS;
		}
#if MATTER_FEATURE_CLIENT
		if (path->cluster == MATTER_CLUSTER_BINDING) {
			int rc;

			if (data == NULL || data_len == 0u) {
				return MATTER_IM_STATUS_INVALID_COMMAND;
			}
			/*
			 * The PIN before the list, and only for a node that has
			 * a vendor id: MATTER_ATTR_BINDING_PIN(0) is 0x0000,
			 * which is the standard list attribute, and answering a
			 * list write by storing its bytes as a PIN is the kind
			 * of mistake nothing downstream can detect.
			 */
			if (info->vendor_id != 0u &&
			    path->attribute == MATTER_ATTR_BINDING_PIN(info->vendor_id)) {
				struct matter_tlv_reader r;
				const uint8_t *pin = NULL;
				size_t pin_len = 0u;

				matter_tlv_reader_init(&r, data, data_len);
				if (matter_tlv_next(&r) != MATTER_OK ||
				    matter_tlv_get_bytes(&r, &pin, &pin_len) != MATTER_OK) {
					return MATTER_IM_STATUS_INVALID_COMMAND;
				}
				if (matter_binding_write_pin(&info->binding, pin, pin_len) !=
				    MATTER_OK) {
					return MATTER_IM_STATUS_CONSTRAINT_ERROR;
				}
				return MATTER_IM_STATUS_SUCCESS;
			}
			if (path->attribute != MATTER_ATTR_BINDING_LIST) {
				return MATTER_IM_STATUS_UNSUPPORTED_WRITE;
			}
			/*
			 * The fabric index comes from the SESSION, which the
			 * port put here before dispatching. Zero means no
			 * session chose one, and a fabric-scoped write with no
			 * fabric behind it has no list to replace.
			 */
			if (info->accessing_fabric_index == 0u) {
				return MATTER_IM_STATUS_UNSUPPORTED_ACCESS;
			}
			if (path->have_list_index) {
				if (!path->list_index_null) {
					return MATTER_IM_STATUS_CONSTRAINT_ERROR;
				}
				rc = matter_binding_append(&info->binding,
							   info->accessing_fabric_index, data, data_len);
			} else {
				rc = matter_binding_write(&info->binding,
							  info->accessing_fabric_index, data, data_len);
			}
			if (rc == MATTER_E_NOSPACE) {
				return MATTER_IM_STATUS_RESOURCE_EXHAUSTED;
			}
			if (rc != MATTER_OK) {
				return MATTER_IM_STATUS_CONSTRAINT_ERROR;
			}
			return MATTER_IM_STATUS_SUCCESS;
		}
#endif
		if (path->cluster != MATTER_CLUSTER_DOOR_LOCK) {
			return has_cluster(ctx, path->endpoint, path->cluster)
				       ? MATTER_IM_STATUS_UNSUPPORTED_WRITE
				       : MATTER_IM_STATUS_UNSUPPORTED_CLUSTER;
		}
		if (path->attribute != MATTER_ATTR_DL_AUTO_RELOCK_TIME) {
			return MATTER_IM_STATUS_UNSUPPORTED_WRITE;
		}
		{
			struct matter_tlv_reader r;
			uint64_t v = 0u;

			if (data == NULL || data_len == 0u) {
				return MATTER_IM_STATUS_INVALID_COMMAND;
			}
			matter_tlv_reader_init(&r, data, data_len);
			if (matter_tlv_next(&r) != 0 || matter_tlv_get_u64(&r, &v) != 0) {
				return MATTER_IM_STATUS_INVALID_COMMAND;
			}
			/* uint32 per the cluster spec; a wider value is the
			 * controller's error, not something to truncate. */
			if (v > 0xFFFFFFFFu) {
				return MATTER_IM_STATUS_CONSTRAINT_ERROR;
			}
			info->auto_relock_time_s = (uint32_t)v;
			return MATTER_IM_STATUS_SUCCESS;
		}
	}
	if (path->endpoint != MATTER_ENDPOINT_ROOT) {
		return MATTER_IM_STATUS_UNSUPPORTED_ENDPOINT;
	}
	if (path->cluster != MATTER_CLUSTER_ACCESS_CONTROL) {
		/* Every other cluster this node has is read-only, so the honest
		 * answer distinguishes "no such cluster" from "not writable". */
		return has_cluster(ctx, path->endpoint, path->cluster)
			       ? MATTER_IM_STATUS_UNSUPPORTED_WRITE
			       : MATTER_IM_STATUS_UNSUPPORTED_CLUSTER;
	}
	if (path->attribute != MATTER_ATTR_AC_ACL) {
		return MATTER_IM_STATUS_UNSUPPORTED_WRITE;
	}
	if (data == NULL || data_len == 0u) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	slot = fabric_slot_for_request(info, info->accessing_fabric_index);
	if (!fabric_slot_has_privilege(info, slot, MATTER_AC_PRIVILEGE_ADMINISTER,
				       path->endpoint, path->cluster)) {
		return MATTER_IM_STATUS_UNSUPPORTED_ACCESS;
	}
	/*
	 * Refused rather than truncated. A half-stored ACL would be read back as
	 * a shorter list than the commissioner wrote, and it would look like the
	 * node had silently dropped entries it was asked to grant.
	 */
	if (data_len > sizeof(info->fabric_acls[slot].data)) {
		return MATTER_IM_STATUS_RESOURCE_EXHAUSTED;
	}
	if ((info->committed_slots & MATTER_FABRIC_SLOT_BIT(slot)) != 0u &&
	    fabric_store(info, MATTER_FABRIC_STORE_ACL, slot, data, data_len) != MATTER_OK) {
		return MATTER_IM_STATUS_FAILURE;
	}
	memcpy(info->fabric_acls[slot].data, data, data_len);
	info->fabric_acls[slot].len = data_len;
	return MATTER_IM_STATUS_SUCCESS;
}

/* ---- events ---------------------------------------------------------------- */

void matter_clusters_record_lock_operation(struct matter_device_info *info, uint8_t operation,
					   uint8_t source, uint8_t fabric_index,
					   uint64_t source_node)
{
	struct matter_lock_event *ev;

	if (info == NULL) {
		return;
	}
	/*
	 * A full ring drops its OLDEST, not the new one. The newest event is the
	 * one describing the state a controller can still see on the tile, so
	 * refusing it to keep history would leave the report agreeing with the
	 * past and disagreeing with the bolt.
	 */
	if (info->event_count == MATTER_EVENTS_MAX) {
		memmove(&info->events[0], &info->events[1],
			sizeof(info->events[0]) * (MATTER_EVENTS_MAX - 1u));
		info->event_count--;
	}
	ev = &info->events[info->event_count];
	memset(ev, 0, sizeof(*ev));
	/* Pre-increment: the first event is number 1, so a filter of 0 can mean
	 * "everything" without also meaning "one I have already seen". */
	ev->number = ++info->next_event_number;
	ev->timestamp_ms = info->uptime_ms_cb != NULL ? info->uptime_ms_cb() : 0u;
#if MATTER_FEATURE_DL_ALARMS
	ev->event_id = MATTER_EVENT_DL_LOCK_OPERATION;
#endif
	ev->operation = operation;
	ev->source = source;
	ev->fabric_index = fabric_index;
	/* Zero is not a legal operational node id, so it doubles as "unknown"
	 * and is reported as null. A walk-up has no node behind it at all. */
	ev->source_node = fabric_index != 0u ? source_node : 0u;
	info->event_count++;
}

#if MATTER_FEATURE_DL_ALARMS
/*
 * The eviction rule and the numbering appear a second time here rather than in
 * a helper both recorders call. That is deliberate and it is a trade: factoring
 * them out was measured to move 259 KB of the DEFAULT image -- every address
 * downstream of matter_clusters.o shifts -- for a build that has no alarms in
 * it at all. Keeping the operation recorder above textually what it was is what
 * makes a non-anchor image byte-identical to the one before this event existed.
 *
 * The two copies MUST stay in step: same eviction (drop the oldest), same
 * pre-increment (the first event is number 1), same clock. They are the only
 * two places an event enters this ring, and a divergence between them shows up
 * as a repeated EventNumber, which a subscriber's filter reads as "already
 * seen" and silently drops.
 */
void matter_clusters_record_alarm(struct matter_device_info *info, uint8_t alarm_code)
{
	struct matter_lock_event *ev;

	if (info == NULL) {
		return;
	}
	if (info->event_count == MATTER_EVENTS_MAX) {
		memmove(&info->events[0], &info->events[1],
			sizeof(info->events[0]) * (MATTER_EVENTS_MAX - 1u));
		info->event_count--;
	}
	ev = &info->events[info->event_count];
	memset(ev, 0, sizeof(*ev));
	ev->number = ++info->next_event_number;
	ev->timestamp_ms = info->uptime_ms_cb != NULL ? info->uptime_ms_cb() : 0u;
	ev->event_id = MATTER_EVENT_DL_ALARM;
	ev->alarm_code = alarm_code;
	info->event_count++;
}
#endif

size_t matter_clusters_event_count(const struct matter_device_info *info)
{
	return info != NULL ? info->event_count : 0u;
}

static size_t event_count(void *ctx)
{
	return matter_clusters_event_count((const struct matter_device_info *)ctx);
}

static bool event_at(void *ctx, size_t index, struct matter_im_event *out)
{
	const struct matter_device_info *info = (const struct matter_device_info *)ctx;

	if (info == NULL || out == NULL || index >= info->event_count) {
		return false;
	}
	out->endpoint = MATTER_ENDPOINT_LOCK;
	out->cluster = MATTER_CLUSTER_DOOR_LOCK;
#if MATTER_FEATURE_DL_ALARMS
	out->event = info->events[index].event_id;
#else
	out->event = MATTER_EVENT_DL_LOCK_OPERATION;
#endif
	out->number = info->events[index].number;
	out->timestamp_ms = info->events[index].timestamp_ms;
	out->priority = MATTER_EVENT_PRIORITY_CRITICAL;
	return true;
}

/**
 * The event's fields: a DoorLockAlarm's single AlarmCode, or the LockOperation
 * fields below.
 *
 * UserIndex is always null: this node's users are a table a controller writes,
 * and nothing correlates an unlock back to one of them. A null nullable says
 * "not known", which is true; a zero would name user slot 0, which is not.
 */
static void event_data(void *ctx, size_t index, struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	const struct matter_device_info *info = (const struct matter_device_info *)ctx;
	const struct matter_lock_event *ev;

	if (info == NULL || index >= info->event_count) {
		(void)matter_tlv_put_null(w, tag);
		return;
	}
	ev = &info->events[index];

#if MATTER_FEATURE_DL_ALARMS
	/*
	 * A DoorLockAlarm is one field and stops there. Padding it out with the
	 * LockOperation fields would describe an operation that never happened.
	 */
	if (ev->event_id == MATTER_EVENT_DL_ALARM) {
		(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(MATTER_DL_ALARM_FIELD_CODE),
					 ev->alarm_code);
		(void)matter_tlv_end_container(w);
		return;
	}
#endif

	(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(MATTER_DL_LOCK_OP_FIELD_TYPE), ev->operation);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(MATTER_DL_LOCK_OP_FIELD_SOURCE), ev->source);
	(void)matter_tlv_put_null(w, MATTER_TLV_CTX(MATTER_DL_LOCK_OP_FIELD_USER_INDEX));
	/*
	 * Each nullable stands on its own. A controller command has a fabric and
	 * an unknown node; a walk-up has neither. Naming a node that did not ask
	 * would tell a controller that IT unlocked the door.
	 */
	if (ev->fabric_index != 0u) {
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(MATTER_DL_LOCK_OP_FIELD_FABRIC_INDEX),
					 ev->fabric_index);
	} else {
		(void)matter_tlv_put_null(w, MATTER_TLV_CTX(MATTER_DL_LOCK_OP_FIELD_FABRIC_INDEX));
	}
	if (ev->source_node != 0u) {
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(MATTER_DL_LOCK_OP_FIELD_SOURCE_NODE),
					 ev->source_node);
	} else {
		(void)matter_tlv_put_null(w, MATTER_TLV_CTX(MATTER_DL_LOCK_OP_FIELD_SOURCE_NODE));
	}
	(void)matter_tlv_end_container(w);
}

/**
 * Register this device's attribute, cluster, and command handlers with a Matter IM server.
 */
void matter_clusters_init(struct matter_im_server *srv, struct matter_device_info *info)
{
	if (srv == NULL) {
		return;
	}
	srv->status = attr_status;
	srv->value = attr_value;
	srv->has_cluster = has_cluster;
	srv->list_attrs = list_attrs;
	srv->list_endpoints = list_endpoints;
	srv->list_clusters = list_clusters;
	srv->command = command;
	srv->command_fields = command_fields;
	srv->write = attr_write;
	srv->event_count = event_count;
	srv->event_at = event_at;
	srv->event_data = event_data;
	srv->ctx = info;
}
