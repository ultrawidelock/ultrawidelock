/**
 * @file test_matter_im.c — the read a commissioner actually sends.
 *
 * The request replayed here is not constructed and not invented. It is the 106
 * bytes a real iPhone sent this node immediately after PASE completed, lifted
 * from the device log. Encoding a request by hand would only prove this code
 * agrees with itself about the format; these bytes prove it agrees with Apple.
 *
 * Safe to keep in the tree: an attribute path list names cluster and attribute
 * numbers and nothing else. No node ids, no addresses, no key material -- the
 * message header that carried them was stripped before logging.
 *
 * Responses are checked by DECODING them again rather than by comparing against
 * a golden blob. A golden blob locks in whatever this code happened to emit the
 * day it was written, including its mistakes; decoding asserts the properties
 * that actually matter, and says which one broke.
 */
#include <stdio.h>
#include <string.h>

#include "matter_clusters.h"
#include "matter_im.h"

#include "test.h"

/*
 * ReadRequestMessage, protocol 0x0001 opcode 0x02, as received.
 *
 *   endpoint 0  cluster 0x0030  attributes 0x04 0x00 0x01 0x02 0x03 0x0C
 *   endpoint 0  cluster 0x0028  attributes 0x02 0x04
 *   endpoint 0  cluster 0x0038  ALL attributes (wildcard)
 *   FabricFiltered false, InteractionModelRevision 12
 */
static const uint8_t apple_read[] = {
	0x15, 0x36, 0x00, 0x17, 0x24, 0x02, 0x00, 0x24, 0x03, 0x30, 0x24, 0x04, 0x04, 0x18,
	0x17, 0x24, 0x02, 0x00, 0x24, 0x03, 0x30, 0x24, 0x04, 0x00, 0x18, 0x17, 0x24, 0x02,
	0x00, 0x24, 0x03, 0x30, 0x24, 0x04, 0x01, 0x18, 0x17, 0x24, 0x02, 0x00, 0x24, 0x03,
	0x30, 0x24, 0x04, 0x02, 0x18, 0x17, 0x24, 0x02, 0x00, 0x24, 0x03, 0x30, 0x24, 0x04,
	0x03, 0x18, 0x17, 0x24, 0x02, 0x00, 0x24, 0x03, 0x30, 0x24, 0x04, 0x0c, 0x18, 0x17,
	0x24, 0x02, 0x00, 0x24, 0x03, 0x28, 0x24, 0x04, 0x02, 0x18, 0x17, 0x24, 0x02, 0x00,
	0x24, 0x03, 0x28, 0x24, 0x04, 0x04, 0x18, 0x17, 0x24, 0x02, 0x00, 0x24, 0x03, 0x38,
	0x18, 0x18, 0x28, 0x03, 0x24, 0xff, 0x0c, 0x18,
};

/** One decoded AttributeReportIB, flattened for assertion. */
struct rep {
	uint16_t endpoint;
	uint32_t cluster;
	uint32_t attribute;
	bool is_status;
	uint8_t status;
	uint8_t vtype; /* wire element type of the value */
	uint64_t vu;
	bool vb;
	/* BasicCommissioningInfo's two fields, when the value is a structure. */
	uint64_t s0;
	uint64_t s1;
	/* Borrowed from the report buffer, when the value is a string. */
	const char *vs;
	size_t vs_len;
};

/**
 * What apps/dwm3001cdk-lock/src/matter_commission.c gives one report chunk.
 *
 * Duplicated rather than shared because the module must not depend on a port.
 * If the two drift apart the assertion below stops meaning anything, so they
 * are named the same thing on purpose.
 */
#define PORT_REPORT_MAX 1180u

/* Room for every attribute of the widest cluster this node has, plus slack.
 * BasicInformation alone reports 16, which is exactly where this used to sit --
 * and an overflow here reads as a malformed report rather than a full one. */
#define MAX_REPS 96

/** Read an AttributePathIB into @p r. Reader is positioned on the list. */
static int walk_path(struct matter_tlv_reader *rd, struct rep *r)
{
	int rc = matter_tlv_enter(rd);

	if (rc != MATTER_OK) {
		return rc;
	}
	for (;;) {
		uint64_t v;

		rc = matter_tlv_next(rd);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}
		if (matter_tlv_get_u64(rd, &v) != MATTER_OK) {
			continue;
		}
		if (matter_tlv_tag(rd) == MATTER_TLV_CTX(2)) {
			r->endpoint = (uint16_t)v;
		} else if (matter_tlv_tag(rd) == MATTER_TLV_CTX(3)) {
			r->cluster = (uint32_t)v;
		} else if (matter_tlv_tag(rd) == MATTER_TLV_CTX(4)) {
			r->attribute = (uint32_t)v;
		}
	}
	return matter_tlv_exit(rd);
}

/** Decode a whole ReportData into @p reps. @return count, or -1. */
static int walk_report(const uint8_t *buf, size_t len, struct rep *reps, bool *suppress,
		       uint64_t *revision)
{
	struct matter_tlv_reader rd;
	int n = 0;

	*suppress = false;
	*revision = 0u;
	matter_tlv_reader_init(&rd, buf, len);

	if (matter_tlv_next(&rd) != MATTER_OK || matter_tlv_enter(&rd) != MATTER_OK) {
		return -1;
	}

	for (;;) {
		int rc = matter_tlv_next(&rd);

		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return -1;
		}

		if (matter_tlv_tag(&rd) == MATTER_TLV_CTX(4)) {
			if (matter_tlv_get_bool(&rd, suppress) != MATTER_OK) {
				return -1;
			}
			continue;
		}
		if (matter_tlv_tag(&rd) == MATTER_TLV_CTX(0xFF)) {
			if (matter_tlv_get_u64(&rd, revision) != MATTER_OK) {
				return -1;
			}
			continue;
		}
		if (matter_tlv_tag(&rd) != MATTER_TLV_CTX(1)) {
			continue;
		}

		/* The AttributeReportIBs array. */
		if (matter_tlv_enter(&rd) != MATTER_OK) {
			return -1;
		}
		for (;;) {
			struct rep *r;

			rc = matter_tlv_next(&rd);
			if (rc == MATTER_END) {
				break;
			}
			if (rc != MATTER_OK || n >= MAX_REPS) {
				return -1;
			}
			r = &reps[n];
			memset(r, 0, sizeof(*r));

			/* AttributeReportIB: one anonymous structure. */
			if (matter_tlv_enter(&rd) != MATTER_OK) {
				return -1;
			}
			if (matter_tlv_next(&rd) != MATTER_OK) {
				return -1;
			}
			r->is_status = (matter_tlv_tag(&rd) == MATTER_TLV_CTX(0));

			/* AttributeStatusIB or AttributeDataIB. */
			if (matter_tlv_enter(&rd) != MATTER_OK) {
				return -1;
			}
			for (;;) {
				rc = matter_tlv_next(&rd);
				if (rc == MATTER_END) {
					break;
				}
				if (rc != MATTER_OK) {
					return -1;
				}

				if (r->is_status) {
					if (matter_tlv_tag(&rd) == MATTER_TLV_CTX(0)) {
						if (walk_path(&rd, r) != MATTER_OK) {
							return -1;
						}
					} else if (matter_tlv_tag(&rd) == MATTER_TLV_CTX(1)) {
						/* StatusIB */
						uint64_t s = 0u;

						if (matter_tlv_enter(&rd) != MATTER_OK ||
						    matter_tlv_next(&rd) != MATTER_OK ||
						    matter_tlv_get_u64(&rd, &s) != MATTER_OK) {
							return -1;
						}
						r->status = (uint8_t)s;
						if (matter_tlv_exit(&rd) != MATTER_OK) {
							return -1;
						}
					}
					continue;
				}

				if (matter_tlv_tag(&rd) == MATTER_TLV_CTX(1)) {
					if (walk_path(&rd, r) != MATTER_OK) {
						return -1;
					}
				} else if (matter_tlv_tag(&rd) == MATTER_TLV_CTX(2)) {
					r->vtype = matter_tlv_element_type(&rd);
					if (r->vtype == MATTER_TLV_STRUCTURE ||
					    r->vtype == MATTER_TLV_ARRAY ||
					    r->vtype == MATTER_TLV_LIST) {
						/*
						 * Walked generically, capturing
						 * the first two integers for the
						 * cases that care. Demanding
						 * exactly two made every list
						 * attribute -- the ACL, Fabrics,
						 * NOCs -- read as a malformed
						 * report.
						 */
						int nint = 0;

						if (matter_tlv_enter(&rd) != MATTER_OK) {
							return -1;
						}
						for (;;) {
							uint64_t v = 0u;
							int crc = matter_tlv_next(&rd);

							if (crc == MATTER_END) {
								break;
							}
							if (crc != MATTER_OK) {
								return -1;
							}
							if (matter_tlv_is_container(&rd)) {
								if (matter_tlv_enter(&rd) != MATTER_OK ||
								    matter_tlv_exit(&rd) != MATTER_OK) {
									return -1;
								}
								continue;
							}
							if (matter_tlv_get_u64(&rd, &v) == MATTER_OK) {
								if (nint == 0) {
									r->s0 = v;
								} else if (nint == 1) {
									r->s1 = v;
								}
								nint++;
							}
						}
						if (matter_tlv_exit(&rd) != MATTER_OK) {
							return -1;
						}
					} else if (r->vtype == 0x14u) {
						/*
						 * TLV null (0x14), which has no
						 * accessor because it carries no
						 * value. It arrived with the
						 * credential reader attributes, where
						 * null is the meaningful answer:
						 * an unprovisioned reader. Not
						 * handling it made every report
						 * containing one -- including
						 * the whole data model -- read
						 * as a malformed message.
						 */
						r->vu = 0u;
					} else if (matter_tlv_get_utf8(&rd, &r->vs, &r->vs_len) ==
						   MATTER_OK) {
						/* Tried BEFORE the integer
						 * accessors, not after: falling
						 * through to get_u64() is how a
						 * report full of names came back
						 * as a malformed message. */
						r->vs = r->vs;
					} else if (matter_tlv_get_bool(&rd, &r->vb) == MATTER_OK) {
						r->vb = r->vb;
					} else if (matter_tlv_get_u64(&rd, &r->vu) == MATTER_OK) {
						r->vu = r->vu;
					} else {
						const uint8_t *b = NULL;
						size_t bl = 0u;

						/* Octet strings: certificates and
						 * public keys, which arrived with
						 * the OperationalCredentials
						 * attributes. */
						if (matter_tlv_get_bytes(&rd, &b, &bl) != MATTER_OK) {
							return -1;
						}
					}
				}
			}
			if (matter_tlv_exit(&rd) != MATTER_OK) {
				return -1;
			}
			if (matter_tlv_exit(&rd) != MATTER_OK) {
				return -1;
			}
			n++;
		}
		if (matter_tlv_exit(&rd) != MATTER_OK) {
			return -1;
		}
	}
	return n;
}

/** Find the report for one path; NULL when it was omitted entirely. */
static const struct rep *find(const struct rep *reps, int n, uint32_t cluster, uint32_t attribute)
{
	for (int i = 0; i < n; i++) {
		if (reps[i].cluster == cluster && reps[i].attribute == attribute) {
			return &reps[i];
		}
	}
	return NULL;
}

static void fill_info(struct matter_device_info *info)
{
	memset(info, 0, sizeof(*info));
	info->vendor_id = 0xFFF1u;
	info->product_id = 0x8001u;
	info->breadcrumb = 0u;
	info->regulatory_config = MATTER_REGULATORY_INDOOR;
	info->location_capability = MATTER_REGULATORY_INDOOR;
	info->failsafe_expiry_s = 60u;
	info->failsafe_max_s = 900u;
	info->supports_concurrent_connection = true;
}

static void authorize_admin(struct matter_device_info *info)
{
	info->fabrics[0].index = 1u;
	info->fabrics[0].fabric_id = 1u;
	info->fabrics[0].node_id = 1u;
	info->fabrics[0].case_admin_subject = 1u;
	info->committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
	info->accessing_fabric_index = 1u;
	info->accessing_node_id = 1u;
}

static void test_read_cursor_owner(void)
{
	struct matter_im_read_state slots[2];
	struct matter_im_read_pool pool;
	struct matter_im_read_state *a = NULL;
	struct matter_im_read_state *b = NULL;
	struct matter_im_read_state *again = NULL;

	t_group("bounded chunked-Read cursor owner");
	T_EQ("cursor pool initializes", matter_im_read_pool_init(&pool, slots, 2u), MATTER_OK);
	T_EQ("first Read acquires",
	     matter_im_read_pool_acquire(&pool, 0x1001u, 0x2001u, true, &a), MATTER_OK);
	T_EQ("second Read acquires",
	     matter_im_read_pool_acquire(&pool, 0x1002u, 0x2002u, true, &b), MATTER_OK);
	T_OK("two Reads own distinct cursors", a != NULL && b != NULL && a != b);
	a->sent = 7u;
	T_EQ("retransmit is identified",
	     matter_im_read_pool_acquire(&pool, 0x1001u, 0x2001u, true, &again), MATTER_E_DUP);
	T_OK("retransmit keeps the same cursor", again == a && again->sent == 7u);
	T_EQ("third live Read is bounded",
	     matter_im_read_pool_acquire(&pool, 0x1003u, 0x2003u, true, &again),
	     MATTER_E_NOSPACE);

	T_EQ("wrong session cannot advance",
	     matter_im_read_pool_finish(&pool, 0x9999u, 0x2001u, true, 3u, true, MATTER_OK),
	     MATTER_E_STATE);
	T_EQ("wrong exchange cannot advance",
	     matter_im_read_pool_finish(&pool, 0x1001u, 0x9999u, true, 3u, true, MATTER_OK),
	     MATTER_E_STATE);
	T_EQ("wrong transport cannot advance",
	     matter_im_read_pool_finish(&pool, 0x1001u, 0x2001u, false, 3u, true, MATTER_OK),
	     MATTER_E_STATE);
	T_EQ("wrong completions leave cursor untouched", a->sent, 7u);
	T_EQ("accepted intermediate chunk advances once",
	     matter_im_read_pool_finish(&pool, 0x1001u, 0x2001u, true, 3u, true, MATTER_OK),
	     MATTER_OK);
	T_OK("intermediate cursor stays live", a->in_use && a->more && a->sent == 10u);
	T_EQ("accepted final chunk releases",
	     matter_im_read_pool_finish(&pool, 0x1001u, 0x2001u, true, 2u, false, MATTER_OK),
	     MATTER_OK);
	T_OK("final cursor is free", !a->in_use);
	T_EQ("duplicate completion cannot advance a freed cursor",
	     matter_im_read_pool_finish(&pool, 0x1001u, 0x2001u, true, 2u, false, MATTER_OK),
	     MATTER_E_STATE);

	T_EQ("released cursor can be reused",
	     matter_im_read_pool_acquire(&pool, 0x1004u, 0x2004u, false, &a), MATTER_OK);
	T_EQ("transport rejection releases its cursor",
	     matter_im_read_pool_finish(&pool, 0x1004u, 0x2004u, false, 0u, false,
					MATTER_E_STATE),
	     MATTER_OK);
	T_OK("rejected cursor is gone",
	     matter_im_read_pool_find(&pool, 0x1004u, 0x2004u, false) == NULL);
	matter_im_read_pool_drop_session(&pool, 0x1002u, false);
	T_OK("wrong-transport cleanup preserves cursor", b->in_use);
	matter_im_read_pool_drop_session(&pool, 0x1002u, true);
	T_OK("matching session cleanup releases cursor", !b->in_use);
}

void test_matter_im(void)
{
	struct matter_im_read req;
	struct matter_device_info info;
	struct matter_im_server srv;
	struct matter_im_report_stats stats;
	struct rep reps[MAX_REPS];
	uint8_t out[512];
	size_t len = 0u;
	bool suppress = false;
	uint64_t revision = 0u;
	const struct rep *r;
	int n;

	test_read_cursor_owner();

	/* ------------------------------------------------ decoding the read --- */

	T_EQ("apple read decodes",
	     matter_im_read_request_decode(apple_read, sizeof(apple_read), &req), MATTER_OK);
	T_EQ("nine paths", req.n_paths, 9);
	T_OK("not fabric filtered", !req.fabric_filtered);

	/* First path: GeneralCommissioning SupportsConcurrentConnection. */
	T_EQ("path0 endpoint", req.paths[0].endpoint, 0);
	T_EQ("path0 cluster", req.paths[0].cluster, 0x0030);
	T_EQ("path0 attribute", req.paths[0].attribute, 0x0004);
	T_OK("path0 concrete", !matter_im_path_is_wildcard(&req.paths[0]));

	/* Sixth: the attribute this node does not implement. */
	T_EQ("path5 attribute", req.paths[5].attribute, 0x000C);

	/* Seventh and eighth: BasicInformation. */
	T_EQ("path6 cluster", req.paths[6].cluster, 0x0028);
	T_EQ("path6 attribute", req.paths[6].attribute, 0x0002);
	T_EQ("path7 attribute", req.paths[7].attribute, 0x0004);

	/* Ninth: cluster given, attribute wildcarded. */
	T_EQ("path8 cluster", req.paths[8].cluster, 0x0038);
	T_OK("path8 has endpoint", req.paths[8].have_endpoint);
	T_OK("path8 has cluster", req.paths[8].have_cluster);
	T_OK("path8 attribute wildcarded", !req.paths[8].have_attribute);
	T_OK("path8 is a wildcard path", matter_im_path_is_wildcard(&req.paths[8]));

	/* ------------------------------------------------ answering the read --- */

	fill_info(&info);
	matter_clusters_init(&srv, &info);

	T_EQ("report encodes",
	     matter_im_report_data_encode(&srv, &req, out, sizeof(out), &len, &stats), MATTER_OK);
	T_OK("report is not empty", len > 0u);
	/* The TimeSynchronization wildcard: skipped because the cluster is absent,
	 * which is the CORRECT answer and must not be an error. */
	T_EQ("one wildcard skipped", stats.skipped_wildcard, 1);
	T_EQ("nothing left unexpanded", stats.unexpanded_wildcard, 0);

	n = walk_report(out, len, reps, &suppress, &revision);
	/* Eight concrete paths answered; the wildcard contributes nothing. */
	T_EQ("eight reports", n, 8);
	T_OK("suppress response set", suppress);
	T_EQ("interaction model revision", (long)revision, MATTER_IM_REVISION);

	r = find(reps, n, 0x0028, 0x0002);
	T_OK("vendor id reported", r != NULL && !r->is_status);
	T_EQ("vendor id value", r ? (long)r->vu : -1, 0xFFF1);
	T_EQ("vendor id endpoint", r ? r->endpoint : 0xFFFF, 0);

	r = find(reps, n, 0x0028, 0x0004);
	T_OK("product id reported", r != NULL && !r->is_status);
	T_EQ("product id value", r ? (long)r->vu : -1, 0x8001);

	r = find(reps, n, 0x0030, 0x0000);
	T_OK("breadcrumb reported", r != NULL && !r->is_status);
	T_EQ("breadcrumb value", r ? (long)r->vu : -1, 0);

	r = find(reps, n, 0x0030, 0x0001);
	T_OK("basic commissioning info reported", r != NULL && !r->is_status);
	T_EQ("bci is a structure", r ? r->vtype : 0, MATTER_TLV_STRUCTURE);
	T_EQ("bci failsafe expiry", r ? (long)r->s0 : -1, 60);
	T_EQ("bci failsafe max", r ? (long)r->s1 : -1, 900);

	r = find(reps, n, 0x0030, 0x0002);
	T_OK("regulatory config reported", r != NULL && !r->is_status);
	T_EQ("regulatory config value", r ? (long)r->vu : -1, MATTER_REGULATORY_INDOOR);

	r = find(reps, n, 0x0030, 0x0003);
	T_OK("location capability reported", r != NULL && !r->is_status);

	r = find(reps, n, 0x0030, 0x0004);
	T_OK("concurrent connection reported", r != NULL && !r->is_status);
	T_OK("concurrent connection true", r != NULL && r->vb);

	/* The asymmetry, stated as a test: a CONCRETE path naming an attribute
	 * this node lacks gets a status, where the wildcard above got silence. */
	r = find(reps, n, 0x0030, 0x000C);
	T_OK("unimplemented attribute answered", r != NULL);
	T_OK("answered with a status", r != NULL && r->is_status);
	T_EQ("status is unsupported attribute", r ? r->status : 0,
	     MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE);

	/* And the wildcard genuinely produced nothing at all. */
	T_OK("wildcard cluster absent from report", find(reps, n, 0x0038, 0) == NULL);

	t_group("FabricFiltered is carried into fabric-scoped values");
	{
		struct matter_device_info fabric_info;
		struct matter_im_server fabric_srv;
		struct matter_im_read fabric_read;
		uint8_t all[512];
		uint8_t own[512];
		size_t all_len = 0u;
		size_t own_len = 0u;

		fill_info(&fabric_info);
		fabric_info.fabrics[0].index = 1u;
		fabric_info.fabrics[0].fabric_id = 0x1111u;
		fabric_info.fabrics[0].node_id = 0xaaaa;
		fabric_info.fabrics[1].index = 2u;
		fabric_info.fabrics[1].fabric_id = 0x2222u;
		fabric_info.fabrics[1].node_id = 0xbbbb;
		fabric_info.committed_slots = MATTER_FABRIC_SLOT_BIT(0u) |
					      MATTER_FABRIC_SLOT_BIT(1u);
		fabric_info.accessing_fabric_index = 1u;
		matter_clusters_init(&fabric_srv, &fabric_info);

		memset(&fabric_read, 0, sizeof(fabric_read));
		fabric_read.n_paths = 1u;
		fabric_read.paths[0].endpoint = MATTER_ENDPOINT_ROOT;
		fabric_read.paths[0].cluster = MATTER_CLUSTER_OPERATIONAL_CREDENTIALS;
		fabric_read.paths[0].attribute = MATTER_ATTR_OC_FABRICS;
		fabric_read.paths[0].have_endpoint = true;
		fabric_read.paths[0].have_cluster = true;
		fabric_read.paths[0].have_attribute = true;
		T_EQ("unfiltered fabric list encodes",
		     matter_im_report_data_encode(&fabric_srv, &fabric_read, all, sizeof(all),
					  &all_len, NULL),
		     MATTER_OK);
		fabric_read.fabric_filtered = true;
		T_EQ("filtered fabric list encodes",
		     matter_im_report_data_encode(&fabric_srv, &fabric_read, own, sizeof(own),
					  &own_len, NULL),
		     MATTER_OK);
		T_OK("the filtered read contains only the accessing fabric", own_len < all_len);
	}

	/* ---------------------------------------------------- status choices --- */
	{
		struct matter_im_read one;
		struct rep sreps[MAX_REPS];
		int m;

		/* Unknown cluster on a known endpoint: UNSUPPORTED_CLUSTER, not
		 * UNSUPPORTED_ATTRIBUTE. MetadataLookup.cpp:68-88 reports the
		 * outermost missing thing, and a device that says "attribute" of
		 * a cluster it does not have is lying about having the cluster. */
		memset(&one, 0, sizeof(one));
		one.n_paths = 1;
		one.paths[0].endpoint = 0;
		one.paths[0].cluster = 0x0101; /* DoorLock, not implemented yet */
		one.paths[0].attribute = 0x0000;
		one.paths[0].have_endpoint = true;
		one.paths[0].have_cluster = true;
		one.paths[0].have_attribute = true;
		T_EQ("unknown cluster encodes",
		     matter_im_report_data_encode(&srv, &one, out, sizeof(out), &len, &stats),
		     MATTER_OK);
		m = walk_report(out, len, sreps, &suppress, &revision);
		T_EQ("one report", m, 1);
		T_OK("is a status", sreps[0].is_status);
		T_EQ("unsupported cluster", sreps[0].status, MATTER_IM_STATUS_UNSUPPORTED_CLUSTER);

		/* Unknown endpoint outranks both. Endpoint 2, not 1: 1 is the
		 * Door Lock and exists, so asking it for BasicInformation is
		 * an unsupported CLUSTER and would not test the ordering. */
		one.paths[0].endpoint = 2;
		one.paths[0].cluster = 0x0028;
		T_EQ("unknown endpoint encodes",
		     matter_im_report_data_encode(&srv, &one, out, sizeof(out), &len, &stats),
		     MATTER_OK);
		m = walk_report(out, len, sreps, &suppress, &revision);
		T_EQ("one report for bad endpoint", m, 1);
		T_EQ("unsupported endpoint", sreps[0].status,
		     MATTER_IM_STATUS_UNSUPPORTED_ENDPOINT);

		/* A wildcard over a cluster this node HAS expands to every
		 * attribute of it. It used to be skipped and counted, which was
		 * honest but incomplete -- two of Apple's three commissioning
		 * reads carry one, and both came back short. */
		one.paths[0].endpoint = 0;
		one.paths[0].cluster = 0x0028;
		one.paths[0].have_attribute = false;
		T_EQ("known-cluster wildcard encodes",
		     matter_im_report_data_encode(&srv, &one, out, sizeof(out), &len, &stats),
		     MATTER_OK);
		T_EQ("nothing left unexpanded", stats.unexpanded_wildcard, 0);
		T_EQ("nothing counted as absent", stats.skipped_wildcard, 0);
		m = walk_report(out, len, sreps, &suppress, &revision);
		T_EQ("every BasicInformation attribute reported", m, 16);

		/* An ENDPOINT wildcard expands over every endpoint this node
		 * has. Apple reads NetworkCommissioning exactly this way, and
		 * while it went unexpanded the phone concluded there was no
		 * network interface anywhere and stopped commissioning. */
		one.paths[0].have_endpoint = false;
		one.paths[0].have_attribute = true;
		one.paths[0].attribute = MATTER_ATTR_BASIC_VENDOR_ID;
		T_EQ("endpoint wildcard encodes",
		     matter_im_report_data_encode(&srv, &one, out, sizeof(out), &len, &stats),
		     MATTER_OK);
		T_EQ("nothing left unexpanded", stats.unexpanded_wildcard, 0);
		m = walk_report(out, len, sreps, &suppress, &revision);
		T_EQ("reported on the one endpoint", m, 1);
		T_EQ("and it is the root", sreps[0].endpoint, 0);

		/*
		 * The same wildcard naming an attribute this node does NOT have
		 * is silence, not a status. The commissioner asked "wherever
		 * this lives", so answering "endpoint 0 has no such attribute"
		 * would report on an endpoint it never named.
		 */
		one.paths[0].attribute = 0x4242u;
		T_EQ("encodes",
		     matter_im_report_data_encode(&srv, &one, out, sizeof(out), &len, &stats),
		     MATTER_OK);
		/* Once per endpoint, and there are two: the root and the lock.
		 * Counting one would mean an endpoint was never walked. */
		T_EQ("counted as absent on both endpoints", stats.skipped_wildcard, 2);
		m = walk_report(out, len, sreps, &suppress, &revision);
		T_EQ("and said nothing", m, 0);

		/*
		 * ---- endpoint 1, the Door Lock ----------------------------
		 *
		 * The reason this node exists. A controller finds this endpoint
		 * in the root's PartsList, reads its DeviceTypeList to learn it
		 * is a lock, and reads the Door Lock FeatureMap to decide
		 * whether it may send SetAliroReaderConfig. A wrong answer to
		 * any one of those is not an error anywhere -- it is an
		 * accessory tile with no controls, which is the exact symptom
		 * this endpoint was added to fix, so each is asserted.
		 */
		one.paths[0].have_endpoint = true;
		one.paths[0].endpoint = MATTER_ENDPOINT_LOCK;
		one.paths[0].have_cluster = true;
		one.paths[0].cluster = MATTER_CLUSTER_DOOR_LOCK;
		one.paths[0].have_attribute = true;
		one.paths[0].attribute = MATTER_ATTR_FEATURE_MAP;
		T_EQ("lock FeatureMap encodes",
		     matter_im_report_data_encode(&srv, &one, out, sizeof(out), &len, &stats),
		     MATTER_OK);
		m = walk_report(out, len, sreps, &suppress, &revision);
		T_EQ("one report", m, 1);
		T_OK("not a status", !sreps[0].is_status);
		T_EQ("on the lock endpoint", sreps[0].endpoint, MATTER_ENDPOINT_LOCK);
		/*
		 * The two credential bits and User, and nothing else. User is not
		 * aspiration: a real controller invokes GetUser during
		 * commissioning and abandons the pairing when it is refused.
		 * PIN, RFID, schedules and logging stay out -- claiming those
		 * would commit this node to surfaces it has none of.
		 */
		T_EQ("the three feature bits and only those", sreps[0].vu,
		     MATTER_DL_FEATURE_ALIRO_PROVISIONING | MATTER_DL_FEATURE_ALIRO_BLE_UWB |
			     MATTER_DL_FEATURE_USER);

		/*
		 * The verification key is NULL until SetAliroReaderConfig
		 * arrives, and that null IS the answer: it is how a controller
		 * knows this reader still needs an identity. Reporting zeros
		 * would claim a key that cannot verify. 0x14 is the TLV null
		 * element type; matter_tlv.h names the containers but not this.
		 */
		one.paths[0].attribute = MATTER_ATTR_DL_ALIRO_VERIFICATION_KEY;
		T_EQ("verification key encodes",
		     matter_im_report_data_encode(&srv, &one, out, sizeof(out), &len, &stats),
		     MATTER_OK);
		m = walk_report(out, len, sreps, &suppress, &revision);
		T_EQ("one report", m, 1);
		T_OK("not a status", !sreps[0].is_status);
		T_EQ("unprovisioned reads as null", sreps[0].vtype, 0x14u);

		/* The sub-identifier is NOT nullable: it names the reader group
		 * this device belongs to, which it has before any controller
		 * speaks to it. A null here would be a different bug. */
		one.paths[0].attribute = MATTER_ATTR_DL_ALIRO_GROUP_SUB_ID;
		T_EQ("sub-identifier encodes",
		     matter_im_report_data_encode(&srv, &one, out, sizeof(out), &len, &stats),
		     MATTER_OK);
		m = walk_report(out, len, sreps, &suppress, &revision);
		T_EQ("one report", m, 1);
		T_OK("and it is not null", sreps[0].vtype != 0x14u);

		/* A cluster wildcard on the lock expands to the same two
		 * clusters has_cluster() answers for, no more. */
		one.paths[0].have_cluster = false;
		one.paths[0].have_attribute = true;
		one.paths[0].attribute = MATTER_ATTR_FEATURE_MAP;
		T_EQ("lock cluster wildcard encodes",
		     matter_im_report_data_encode(&srv, &one, out, sizeof(out), &len, &stats),
		     MATTER_OK);
		T_EQ("nothing left unexpanded", stats.unexpanded_wildcard, 0);
		one.paths[0].have_cluster = true;
		/* Back to the root, so the cases below read the endpoint they
		 * were written for rather than whichever one ran last. */
		one.paths[0].endpoint = MATTER_ENDPOINT_ROOT;

		/*
		 * A CLUSTER wildcard expands over every cluster on the endpoint.
		 * A controller subscribes to exactly this -- no endpoint, no
		 * cluster, no attribute -- the moment it has adopted the node,
		 * and while it went unexpanded the subscription was established
		 * and then reported nothing at all, forever.
		 */
		one.paths[0].have_endpoint = true;
		/* Named, not inherited. This case is about the ROOT's whole
		 * model, and it was reading whichever endpoint the previous
		 * case happened to leave behind -- which stopped being endpoint
		 * 0 the moment a second endpoint existed. */
		one.paths[0].endpoint = MATTER_ENDPOINT_ROOT;
		one.paths[0].have_cluster = false;
		/* And no attribute either -- the previous case left a
		 * deliberately absent one here, which would make every cluster
		 * correctly report nothing and hide whether expansion ran. */
		one.paths[0].have_attribute = false;
		{
			static uint8_t big[4096];

			T_EQ("cluster wildcard encodes",
			     matter_im_report_data_encode(&srv, &one, big, sizeof(big), &len,
							  &stats),
			     MATTER_OK);
			T_EQ("nothing left unexpanded", stats.unexpanded_wildcard, 0);
			m = walk_report(big, len, sreps, &suppress, &revision);
			T_OK("and reported the endpoint's attributes", m > 0);
			/*
			 * The whole data model in one message, which is what a
			 * controller subscribes to. It has to fit the report
			 * buffer the port hands this encoder
			 * (MATTER_REPORT_MAX in matter_commission.c) or the
			 * node answers NOSPACE and sends nothing -- so this
			 * fails HERE, on the host, rather than as a
			 * subscription that silently never reports.
			 */
			T_OK("fits the port's report buffer", len <= PORT_REPORT_MAX);

			/*
			 * And now the report a controller ACTUALLY subscribes
			 * to: no endpoint either, so it spans every endpoint
			 * this node has. The case above names endpoint 0 and so
			 * measured only part of the answer, which was the whole
			 * truth while there was one endpoint and stopped being
			 * it the moment the Door Lock existed.
			 *
			 * This is the number the unchunked read path lives or
			 * dies by (matter_commission.c on_read_request), so it
			 * is asserted separately rather than inferred.
			 */
			one.paths[0].have_endpoint = false;
			T_EQ("full wildcard encodes",
			     matter_im_report_data_encode(&srv, &one, big, sizeof(big), &len,
							  &stats),
			     MATTER_OK);
			T_EQ("nothing left unexpanded", stats.unexpanded_wildcard, 0);
			T_OK("full wildcard needs the chunked Read path", len > PORT_REPORT_MAX);
			{
				uint16_t sent = 0u;
				uint16_t emitted = 0u;
				bool more = true;
				int chunks = 0;
				int total = 0;
				int full = walk_report(big, len, sreps, &suppress, &revision);

				while (more && chunks < 24) {
					T_EQ("real-cap chunk encodes",
					     matter_im_report_data_chunk(&srv, &one, sent, big,
									 PORT_REPORT_MAX, &len, &more,
									 &emitted, &stats),
					     MATTER_OK);
					T_OK("real-cap chunk stayed within Thread payload",
					     len <= PORT_REPORT_MAX);
					T_OK("real-cap chunk carried something", emitted > 0);
					total += walk_report(big, len, sreps, &suppress, &revision);
					T_OK("only the final Read chunk suppresses StatusResponse",
					     suppress == !more);
					sent = (uint16_t)(sent + emitted);
					chunks++;
				}
				T_OK("real Thread cap split the full wildcard", chunks > 1);
				T_OK("real-cap chunking stopped", !more);
				T_EQ("real-cap chunks delivered every report once", total, full);
			}
			one.paths[0].have_endpoint = true;
			one.paths[0].endpoint = MATTER_ENDPOINT_ROOT;

			/*
			 * And the same report CHUNKED, which is what actually
			 * goes on the wire: one message may not exceed the IPv6
			 * MTU, and 1079 bytes of reports plus framing does. An
			 * oversized datagram is not slow, it is never delivered.
			 */
			{
				/*
				 * Deliberately far below the real ceiling. What
				 * is under test is the chunk boundary, and this
				 * fixture holds no fabric -- so its report is
				 * 1079 B where a commissioned node's is nearly
				 * 1500, and the real MTU would not split it here
				 * even though it splits it on hardware.
				 */
				/*
				 * Swept, not a single size. WHERE a chunk
				 * boundary falls decides whether the rollback
				 * happens between containers or inside one, and
				 * only the second case catches a rollback that
				 * forgets the writer's nesting depth -- which
				 * one cap missed and hardware did not.
				 */
				size_t small;

				for (small = 200u; small <= 700u; small += 37u) {
				uint16_t sent = 0u;
				uint16_t emitted = 0u;
				bool more = true;
				int chunks = 0;
				int total = 0;

				while (more && chunks < 24) {
					T_EQ("chunk encodes",
					     matter_im_report_data_chunk(&srv, &one, sent, big,
									 small, &len, &more,
									 &emitted, &stats),
					     MATTER_OK);
					T_OK("chunk stayed within the cap", len <= small);
					T_OK("chunk carried something", emitted > 0);
					total += walk_report(big, len, sreps, &suppress,
							     &revision);
					T_OK("only final swept chunk suppresses StatusResponse",
					     suppress == !more);
					sent = (uint16_t)(sent + emitted);
					chunks++;
				}
				T_OK("took more than one chunk", chunks > 1);
				T_OK("and stopped", !more);
				/* Every report, once: no gap at a boundary and
				 * no report sent twice. */
				T_EQ("delivered every report exactly once", total, m);
				}
			}
		}
		one.paths[0].have_cluster = true;
	}

	/*
	 * TimedRequest, as a real iPhone sent it.
	 *
	 * These nine bytes are from the device log, taken while a pairing hung:
	 * the phone sent this, waited its full 9,999 ms for a StatusResponse
	 * that never came, and reported the transaction as timed out. The node
	 * logged it as "unhandled" and nothing as an error.
	 *
	 * Kept verbatim for the reason at the top of this file -- constructing
	 * it by hand would only prove this decoder agrees with this encoder.
	 * It carries a timeout and nothing else: no ids, no key material.
	 */
	t_group("TimedRequest, as a real iPhone sent it");
	{
		static const uint8_t apple_timed[] = {
			0x15, 0x25, 0x00, 0x0f, 0x27, 0x24, 0xff, 0x0c, 0x18,
		};
		uint16_t timeout_ms = 0u;
		uint8_t sr[32];
		size_t sr_len = 0u;
		uint8_t decoded_status = 0xffu;
		struct matter_tlv_reader rd;
		uint64_t v = 0u;

		T_EQ("decodes",
		     matter_im_timed_request_decode(apple_timed, sizeof(apple_timed), &timeout_ms),
		     MATTER_OK);
		T_EQ("carries the peer's deadline", (long)timeout_ms, 9999L);

		/* Truncation must not read as a shorter, valid request. */
		for (size_t cut = 1u; cut < sizeof(apple_timed); cut++) {
			uint16_t partial = 0u;

			T_OK("a prefix never decodes as complete",
			     matter_im_timed_request_decode(apple_timed, cut, &partial) !=
					     MATTER_OK ||
				     partial != 9999u);
		}

		/* The answer is a bare StatusResponse. Decoded rather than
		 * compared: what matters is that the status is SUCCESS and the
		 * revision is present, not the byte order they came out in. */
		T_EQ("status response encodes",
		     matter_im_status_response_encode(MATTER_IM_STATUS_SUCCESS, sr, sizeof(sr),
						      &sr_len),
		     MATTER_OK);
		T_OK("and is not empty", sr_len > 0u);
		matter_tlv_reader_init(&rd, sr, sr_len);
		T_EQ("opens", matter_tlv_next(&rd), MATTER_OK);
		T_EQ("a structure", matter_tlv_enter(&rd), MATTER_OK);
		T_EQ("first field", matter_tlv_next(&rd), MATTER_OK);
		T_EQ("is the status", (long)matter_tlv_tag(&rd), (long)MATTER_TLV_CTX(0));
		T_EQ("reads", matter_tlv_get_u64(&rd, &v), MATTER_OK);
		T_EQ("SUCCESS", (long)v, (long)MATTER_IM_STATUS_SUCCESS);
		T_EQ("status response decodes",
		     matter_im_status_response_decode(sr, sr_len, &decoded_status), MATTER_OK);
		T_EQ("decoded SUCCESS", decoded_status, MATTER_IM_STATUS_SUCCESS);
		T_OK("truncated status response is refused",
		     matter_im_status_response_decode(sr, sr_len - 1u, &decoded_status) != MATTER_OK);
		T_EQ("null status buffer refused",
		     matter_im_status_response_decode(NULL, sr_len, &decoded_status), MATTER_E_INVAL);
		T_EQ("null status output refused",
		     matter_im_status_response_decode(sr, sr_len, NULL), MATTER_E_INVAL);
		{
			static const uint8_t missing_status[] = {
				0x15, 0x24, 0xff, MATTER_IM_REVISION, 0x18,
			};
			uint8_t empty = 0u;

			T_EQ("missing mandatory status refused",
			     matter_im_status_response_decode(missing_status,
						      sizeof(missing_status), &decoded_status),
			     MATTER_E_INVAL);
			T_EQ("empty status response refused",
			     matter_im_status_response_decode(&empty, 0u, &decoded_status),
			     MATTER_E_INVAL);
		}
	}

	/* --------------------------------------------------------- refusals --- */

	T_EQ("null request refused", matter_im_read_request_decode(NULL, 4, &req), MATTER_E_INVAL);
	T_EQ("null out refused",
	     matter_im_read_request_decode(apple_read, sizeof(apple_read), NULL), MATTER_E_INVAL);
	T_EQ("empty refused", matter_im_read_request_decode(apple_read, 0u, &req), MATTER_E_INVAL);

	/* Truncation must not be mistaken for a shorter request. Every prefix of
	 * a real message is malformed, and none may decode as if complete. */
	for (size_t cut = 1u; cut < sizeof(apple_read); cut++) {
		struct matter_im_read partial;

		if (matter_im_read_request_decode(apple_read, cut, &partial) == MATTER_OK) {
			T_OK("truncated request must not decode", false);
			break;
		}
	}
	T_OK("every truncation refused", true);

	/* A payload that is not a structure at all. */
	{
		static const uint8_t not_a_struct[] = {0x24, 0x00, 0x01};

		T_EQ("non-structure refused",
		     matter_im_read_request_decode(not_a_struct, sizeof(not_a_struct), &req),
		     MATTER_E_TYPE);
	}

	/* More paths than the bound: refused outright rather than truncated,
	 * because a silently shortened answer looks complete to the peer. */
	{
		uint8_t big[512];
		struct matter_tlv_writer w;
		size_t blen = 0u;

		matter_tlv_writer_init(&w, big, sizeof(big));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(0), MATTER_TLV_ARRAY);
		for (int i = 0; i < MATTER_IM_MAX_PATHS + 1; i++) {
			(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_LIST);
			(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(2), 0u);
			(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(3), 0x0028u);
			(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(4), (uint64_t)i);
			(void)matter_tlv_end_container(&w);
		}
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
		T_EQ("oversized request builds", matter_tlv_writer_finish(&w, &blen), MATTER_OK);
		T_EQ("too many paths refused", matter_im_read_request_decode(big, blen, &req),
		     MATTER_E_NOSPACE);
	}

	/* No room for the answer must fail rather than truncate: a short report
	 * is indistinguishable from a complete one once it reaches the peer. */
	T_EQ("cramped buffer refused",
	     matter_im_report_data_encode(&srv, &req, out, 8u, &len, &stats), MATTER_E_NOSPACE);
	T_EQ("null server refused",
	     matter_im_report_data_encode(NULL, &req, out, sizeof(out), &len, &stats),
	     MATTER_E_INVAL);
	{
		struct matter_im_server broken = srv;

		broken.value = NULL;
		T_EQ("incomplete server refused",
		     matter_im_report_data_encode(&broken, &req, out, sizeof(out), &len, &stats),
		     MATTER_E_INVAL);
	}

	/* stats is optional. */
	fill_info(&info);
	T_EQ("null stats accepted",
	     matter_im_report_data_encode(&srv, &req, out, sizeof(out), &len, NULL), MATTER_OK);

	/* ------------------------------------------------ wildcard expansion --- */
	{
		struct matter_im_read one;
		struct rep wreps[MAX_REPS];
		int m;

		/* A wildcard over a cluster this node HAS must now report every
		 * attribute of it, not skip the path. Apple sends these: two of
		 * its three commissioning reads carried them. */
		memset(&one, 0, sizeof(one));
		one.n_paths = 1;
		one.paths[0].endpoint = 0;
		one.paths[0].cluster = MATTER_CLUSTER_GENERAL_COMMISSIONING;
		one.paths[0].have_endpoint = true;
		one.paths[0].have_cluster = true;
		one.paths[0].have_attribute = false;

		fill_info(&info);
		T_EQ("wildcard encodes",
		     matter_im_report_data_encode(&srv, &one, out, sizeof(out), &len, &stats),
		     MATTER_OK);
		T_EQ("nothing left unexpanded", stats.unexpanded_wildcard, 0);
		T_EQ("nothing skipped", stats.skipped_wildcard, 0);
		m = walk_report(out, len, wreps, &suppress, &revision);
		T_EQ("all five attributes reported", m, 5);
		T_OK("breadcrumb among them", find(wreps, m, MATTER_CLUSTER_GENERAL_COMMISSIONING,
						   MATTER_ATTR_GC_BREADCRUMB) != NULL);
		T_OK("concurrent connection among them",
		     find(wreps, m, MATTER_CLUSTER_GENERAL_COMMISSIONING,
			  MATTER_ATTR_GC_SUPPORTS_CONCURRENT_CONNECTION) != NULL);
		/* Every expanded path must carry a VALUE. An expansion that
		 * yields UNSUPPORTED_ATTRIBUTE means the attribute list and the
		 * status function disagree, which is worse than not expanding. */
		for (int i = 0; i < m; i++) {
			T_OK("expansion yields values, not statuses", !wreps[i].is_status);
		}

		/* An absent cluster still expands to silence, not to an error. */
		one.paths[0].cluster = 0x0038u;
		T_EQ("absent wildcard encodes",
		     matter_im_report_data_encode(&srv, &one, out, sizeof(out), &len, &stats),
		     MATTER_OK);
		T_EQ("skipped", stats.skipped_wildcard, 1);
		T_EQ("not unexpanded", stats.unexpanded_wildcard, 0);
		m = walk_report(out, len, wreps, &suppress, &revision);
		T_EQ("no reports", m, 0);
	}
}

/*
 * InvokeRequestMessage carrying ArmFailSafe, exactly as a real iPhone sent it
 * once the three commissioning reads were answered.
 *
 *   SuppressResponse false, TimedRequest false
 *   endpoint 0, cluster 0x0030 GeneralCommissioning, command 0x00 ArmFailSafe
 *   ExpiryLengthSeconds 60, Breadcrumb 3
 */
static const uint8_t apple_armfailsafe[] = {
	0x15, 0x28, 0x00, 0x28, 0x01, 0x36, 0x02, 0x15, 0x37, 0x00, 0x24, 0x00,
	0x00, 0x24, 0x01, 0x30, 0x24, 0x02, 0x00, 0x18, 0x35, 0x01, 0x24, 0x00,
	0x3c, 0x24, 0x01, 0x03, 0x18, 0x18, 0x18, 0x24, 0xff, 0x0c, 0x18,
};

/** One decoded InvokeResponseIB. */
struct iresp {
	bool is_status;
	uint8_t status;
	uint16_t endpoint;
	uint32_t cluster;
	uint32_t command;
	uint64_t error_code;
	bool have_debug_text;
};

/** Decode an InvokeResponseMessage. @return true on success. */
static bool walk_invoke_response(const uint8_t *buf, size_t len, struct iresp *ir)
{
	struct matter_tlv_reader rd;

	memset(ir, 0, sizeof(*ir));
	matter_tlv_reader_init(&rd, buf, len);
	if (matter_tlv_next(&rd) != MATTER_OK || matter_tlv_enter(&rd) != MATTER_OK) {
		return false;
	}
	for (;;) {
		int rc = matter_tlv_next(&rd);

		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return false;
		}
		if (matter_tlv_tag(&rd) != MATTER_TLV_CTX(1)) {
			continue;
		}
		/* InvokeResponses array. */
		if (matter_tlv_enter(&rd) != MATTER_OK) {
			return false;
		}
		if (matter_tlv_next(&rd) != MATTER_OK) {
			return false;
		}
		/* One InvokeResponseIB. */
		if (matter_tlv_enter(&rd) != MATTER_OK || matter_tlv_next(&rd) != MATTER_OK) {
			return false;
		}
		ir->is_status = (matter_tlv_tag(&rd) == MATTER_TLV_CTX(1));
		if (matter_tlv_enter(&rd) != MATTER_OK) {
			return false;
		}
		for (;;) {
			rc = matter_tlv_next(&rd);
			if (rc == MATTER_END) {
				break;
			}
			if (rc != MATTER_OK) {
				return false;
			}
			if (matter_tlv_tag(&rd) == MATTER_TLV_CTX(0)) {
				/* CommandPathIB, a list. */
				uint64_t v;

				if (matter_tlv_enter(&rd) != MATTER_OK) {
					return false;
				}
				for (;;) {
					rc = matter_tlv_next(&rd);
					if (rc == MATTER_END) {
						break;
					}
					if (rc != MATTER_OK ||
					    matter_tlv_get_u64(&rd, &v) != MATTER_OK) {
						return false;
					}
					if (matter_tlv_tag(&rd) == MATTER_TLV_CTX(0)) {
						ir->endpoint = (uint16_t)v;
					} else if (matter_tlv_tag(&rd) == MATTER_TLV_CTX(1)) {
						ir->cluster = (uint32_t)v;
					} else if (matter_tlv_tag(&rd) == MATTER_TLV_CTX(2)) {
						ir->command = (uint32_t)v;
					}
				}
				if (matter_tlv_exit(&rd) != MATTER_OK) {
					return false;
				}
			} else if (matter_tlv_tag(&rd) == MATTER_TLV_CTX(1)) {
				/* Fields struct, or StatusIB. */
				if (matter_tlv_enter(&rd) != MATTER_OK) {
					return false;
				}
				for (;;) {
					rc = matter_tlv_next(&rd);
					if (rc == MATTER_END) {
						break;
					}
					if (rc != MATTER_OK) {
						return false;
					}
					if (matter_tlv_tag(&rd) == MATTER_TLV_CTX(0)) {
						uint64_t v = 0u;

						if (matter_tlv_get_u64(&rd, &v) != MATTER_OK) {
							return false;
						}
						ir->error_code = v;
						if (ir->is_status) {
							ir->status = (uint8_t)v;
						}
					} else if (matter_tlv_tag(&rd) == MATTER_TLV_CTX(1)) {
						const char *sp = NULL;
						size_t sl = 0u;

						if (matter_tlv_get_utf8(&rd, &sp, &sl) ==
						    MATTER_OK) {
							ir->have_debug_text = true;
						}
					}
				}
				if (matter_tlv_exit(&rd) != MATTER_OK) {
					return false;
				}
			}
		}
		return true;
	}
	return false;
}

void test_matter_im_invoke(void)
{
	struct matter_im_invoke inv;
	struct matter_device_info info;
	struct matter_im_server srv;
	struct iresp ir;
	uint8_t out[256];
	size_t len = 0u;

	fill_info(&info);
	authorize_admin(&info);
	matter_clusters_init(&srv, &info);

	t_group("ArmFailSafe, as a real iPhone sent it");
	{
		T_EQ("decodes",
		     matter_im_invoke_request_decode(apple_armfailsafe, sizeof(apple_armfailsafe),
						     &inv),
		     MATTER_OK);
		T_EQ("endpoint", inv.endpoint, 0);
		T_EQ("GeneralCommissioning", (long)inv.cluster, 0x0030L);
		T_EQ("ArmFailSafe", (long)inv.command, 0x0000L);
		T_OK("carries fields", inv.has_fields);
		T_OK("response wanted", !inv.suppress_response);
		T_OK("not timed", !inv.timed_request);
		T_OK("no command ref", !inv.has_command_ref);

		T_OK("fail-safe not armed yet", !info.attempt.active);
		/* Existing administrators must not be owned by the new transaction.
		 * Use nonadjacent slots so this proves a mask rather than a count. */
		info.fabrics[0].index = 1u;
		info.fabrics[2].index = 3u;
		T_EQ("encodes a response",
		     matter_im_invoke_response_encode(&srv, &inv, out, sizeof(out), &len),
		     MATTER_OK);
		T_OK("response is not empty", len > 0u);
		/* The command RAN: the effect is the point, and the breadcrumb is
		 * how the commissioner resumes a half-finished attempt. */
		T_OK("fail-safe armed", info.attempt.active);
		T_EQ("existing fabrics are not the transaction's to roll back",
		     info.attempt.owned_slots, 0u);
		T_EQ("breadcrumb taken from the request", (long)info.breadcrumb, 3L);
		info.fabrics[2].index = 0u;
		/* Restore the single authorized administrator the rest of this
		 * function invokes against. */
		authorize_admin(&info);

		T_OK("response decodes", walk_invoke_response(out, len, &ir));
		T_OK("carries a command, not a status", !ir.is_status);
		T_EQ("same endpoint", ir.endpoint, 0);
		T_EQ("same cluster", (long)ir.cluster, 0x0030L);
		/* The path names the RESPONSE command, not the one invoked. */
		T_EQ("ArmFailSafeResponse", (long)ir.command,
		     (long)MATTER_CMD_GC_ARM_FAIL_SAFE_RESPONSE);
		T_EQ("ErrorCode OK", (long)ir.error_code, (long)MATTER_COMMISSIONING_OK);
		/* DebugText is mandatory; omitting it fails the decode at the
		 * commissioner, which shows up as a hang rather than an error. */
		T_OK("DebugText present", ir.have_debug_text);
	}

	t_group("SetRegulatoryConfig");
	{
		uint8_t buf[64];
		struct matter_tlv_writer w;
		size_t blen = 0u;

		/* NewRegulatoryConfig indoor, CountryCode XX, Breadcrumb 5. */
		matter_tlv_writer_init(&w, buf, sizeof(buf));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_bool(&w, MATTER_TLV_CTX(0), false);
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(2), MATTER_TLV_ARRAY);
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(0), MATTER_TLV_LIST);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0), 0u);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1),
					 MATTER_CLUSTER_GENERAL_COMMISSIONING);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(2),
					 MATTER_CMD_GC_SET_REGULATORY_CONFIG);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(1), MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0), MATTER_REGULATORY_INDOOR);
		(void)matter_tlv_put_utf8(&w, MATTER_TLV_CTX(1), "XX", 2u);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(2), 5u);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
		T_EQ("request builds", matter_tlv_writer_finish(&w, &blen), MATTER_OK);

		T_EQ("decodes", matter_im_invoke_request_decode(buf, blen, &inv), MATTER_OK);
		T_EQ("SetRegulatoryConfig", (long)inv.command,
		     (long)MATTER_CMD_GC_SET_REGULATORY_CONFIG);
		T_EQ("encodes",
		     matter_im_invoke_response_encode(&srv, &inv, out, sizeof(out), &len),
		     MATTER_OK);
		T_OK("decodes", walk_invoke_response(out, len, &ir));
		T_EQ("SetRegulatoryConfigResponse", (long)ir.command,
		     (long)MATTER_CMD_GC_SET_REGULATORY_CONFIG_RESPONSE);
		T_EQ("accepted", (long)ir.error_code, (long)MATTER_COMMISSIONING_OK);
		T_EQ("breadcrumb advanced", (long)info.breadcrumb, 5L);

		/* A location this node never claimed is refused with a
		 * CommissioningError, not accepted silently. */
		buf[0] = buf[0]; /* rebuild with outdoor */
		matter_tlv_writer_init(&w, buf, sizeof(buf));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(2), MATTER_TLV_ARRAY);
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(0), MATTER_TLV_LIST);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0), 0u);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1),
					 MATTER_CLUSTER_GENERAL_COMMISSIONING);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(2),
					 MATTER_CMD_GC_SET_REGULATORY_CONFIG);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(1), MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0), MATTER_REGULATORY_OUTDOOR);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &blen);
		T_EQ("decodes", matter_im_invoke_request_decode(buf, blen, &inv), MATTER_OK);
		T_EQ("encodes",
		     matter_im_invoke_response_encode(&srv, &inv, out, sizeof(out), &len),
		     MATTER_OK);
		T_OK("decodes", walk_invoke_response(out, len, &ir));
		T_EQ("refused as outside range", (long)ir.error_code,
		     (long)MATTER_COMMISSIONING_VALUE_OUTSIDE_RANGE);
		T_EQ("and the config is unchanged", info.regulatory_config,
		     MATTER_REGULATORY_INDOOR);
	}

	/*
	 * GetUser on the lock endpoint, which is where a real pairing stops.
	 * Apple invokes it during commissioning and sends RemoveFabric if it
	 * does not get an answer it can use, so what matters is not that the
	 * command is accepted but that the RESPONSE decodes and names the right
	 * path -- a response built for the wrong endpoint or under the invoked
	 * command's id looks like silence to the controller.
	 */
	t_group("GetUser answers with an empty slot");
	{
		uint8_t fields[16];
		struct matter_tlv_writer fw;
		size_t flen = 0u;

		matter_tlv_writer_init(&fw, fields, sizeof(fields));
		(void)matter_tlv_start_container(&fw, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&fw, MATTER_TLV_CTX(0), 1u); /* UserIndex */
		(void)matter_tlv_end_container(&fw);
		T_EQ("fields encode", matter_tlv_writer_finish(&fw, &flen), MATTER_OK);

		memset(&inv, 0, sizeof(inv));
		inv.endpoint = MATTER_ENDPOINT_LOCK;
		inv.cluster = MATTER_CLUSTER_DOOR_LOCK;
		inv.command = MATTER_CMD_DL_GET_USER;
		inv.fields = fields;
		inv.fields_len = flen;
		inv.has_fields = true;

		T_EQ("encodes a response",
		     matter_im_invoke_response_encode(&srv, &inv, out, sizeof(out), &len),
		     MATTER_OK);
		T_OK("response is not empty", len > 0u);
		T_OK("response decodes", walk_invoke_response(out, len, &ir));
		T_OK("carries a command, not a status", !ir.is_status);
		T_EQ("on the lock endpoint", ir.endpoint, (long)MATTER_ENDPOINT_LOCK);
		T_EQ("Door Lock", (long)ir.cluster, (long)MATTER_CLUSTER_DOOR_LOCK);
		/* The path names GetUserResponse, not the GetUser that was
		 * invoked. A controller matches on this. */
		T_EQ("GetUserResponse", (long)ir.command, (long)MATTER_CMD_DL_GET_USER_RESPONSE);

		/* An index outside the table is refused rather than answered
		 * with an empty slot that implies the slot exists. */
		matter_tlv_writer_init(&fw, fields, sizeof(fields));
		(void)matter_tlv_start_container(&fw, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&fw, MATTER_TLV_CTX(0), MATTER_DL_USERS_MAX + 1u);
		(void)matter_tlv_end_container(&fw);
		T_EQ("fields encode", matter_tlv_writer_finish(&fw, &flen), MATTER_OK);
		inv.fields_len = flen;
		T_EQ("out-of-range encodes",
		     matter_im_invoke_response_encode(&srv, &inv, out, sizeof(out), &len),
		     MATTER_OK);
		T_OK("response decodes", walk_invoke_response(out, len, &ir));
		T_OK("and it is a status", ir.is_status);
		T_EQ("invalid command", ir.status, (long)MATTER_IM_STATUS_INVALID_COMMAND);
	}

	t_group("commands this node does not have");
	{
		uint8_t buf[64];
		struct matter_tlv_writer w;
		size_t blen = 0u;

		matter_tlv_writer_init(&w, buf, sizeof(buf));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(2), MATTER_TLV_ARRAY);
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(0), MATTER_TLV_LIST);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0), 0u);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1),
					 MATTER_CLUSTER_GENERAL_COMMISSIONING);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(2), 0x00FFu); /* no such command */
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &blen);

		T_EQ("decodes", matter_im_invoke_request_decode(buf, blen, &inv), MATTER_OK);
		T_EQ("encodes",
		     matter_im_invoke_response_encode(&srv, &inv, out, sizeof(out), &len),
		     MATTER_OK);
		T_OK("decodes", walk_invoke_response(out, len, &ir));
		T_OK("answered with a status", ir.is_status);
		T_EQ("unsupported command", ir.status, MATTER_IM_STATUS_UNSUPPORTED_COMMAND);
		/* The status path echoes the command ASKED for: there is no
		 * response command when nothing ran. */
		T_EQ("path names the invoked command", (long)ir.command, 0x00FFL);
	}

	t_group("the tile's two buttons");
	{
		struct matter_im_invoke inv2;
		struct iresp ir2;
		size_t len2 = 0u;

		/* Never asked: zero is not a legal LockState, and a reader that
		 * has been asked nothing is Locked rather than unlocked. */
		info.lock_state = 0u;

		memset(&inv2, 0, sizeof(inv2));
		inv2.endpoint = MATTER_ENDPOINT_LOCK;
		inv2.cluster = MATTER_CLUSTER_DOOR_LOCK;
		inv2.command = MATTER_CMD_DL_UNLOCK_DOOR;

		T_EQ("UnlockDoor encodes",
		     matter_im_invoke_response_encode(&srv, &inv2, out, sizeof(out), &len2),
		     MATTER_OK);
		T_OK("UnlockDoor decodes", walk_invoke_response(out, len2, &ir2));
		/* A bare status, not a response command: DoorLock defines no
		 * LockDoorResponse, and inventing one leaves a controller
		 * waiting for a message that never comes. */
		T_OK("answered with a status", ir2.is_status);
		T_EQ("UnlockDoor SUCCESS", ir2.status, (long)MATTER_IM_STATUS_SUCCESS);
		T_EQ("state is Unlocked", (long)info.lock_state,
		     (long)MATTER_DL_LOCK_STATE_UNLOCKED);

		inv2.command = MATTER_CMD_DL_LOCK_DOOR;
		T_EQ("LockDoor encodes",
		     matter_im_invoke_response_encode(&srv, &inv2, out, sizeof(out), &len2),
		     MATTER_OK);
		T_OK("LockDoor decodes", walk_invoke_response(out, len2, &ir2));
		T_EQ("LockDoor SUCCESS", ir2.status, (long)MATTER_IM_STATUS_SUCCESS);
		T_EQ("state is Locked", (long)info.lock_state,
		     (long)MATTER_DL_LOCK_STATE_LOCKED);
	}

	t_group("what invoke refuses");
	{
		T_EQ("null refused", matter_im_invoke_request_decode(NULL, 4u, &inv),
		     MATTER_E_INVAL);
		T_EQ("empty refused", matter_im_invoke_request_decode(apple_armfailsafe, 0u, &inv),
		     MATTER_E_INVAL);

		/* Every truncation of a real request must be refused. */
		for (size_t cut = 1u; cut < sizeof(apple_armfailsafe); cut++) {
			if (matter_im_invoke_request_decode(apple_armfailsafe, cut, &inv) ==
			    MATTER_OK) {
				T_OK("truncated invoke must not decode", false);
				break;
			}
		}
		T_OK("every truncation refused", true);

		/* A batch is refused rather than half-run: a commissioner that
		 * batched two commands and got one response would be entitled to
		 * assume both happened. */
		{
			uint8_t buf[128];
			struct matter_tlv_writer w;
			size_t blen = 0u;

			matter_tlv_writer_init(&w, buf, sizeof(buf));
			(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
			(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(2), MATTER_TLV_ARRAY);
			for (int i = 0; i < 2; i++) {
				(void)matter_tlv_start_container(&w, MATTER_TLV_ANON,
								 MATTER_TLV_STRUCTURE);
				(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(0),
								 MATTER_TLV_LIST);
				(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0), 0u);
				(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1), 0x0030u);
				(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(2), 0u);
				(void)matter_tlv_end_container(&w);
				(void)matter_tlv_end_container(&w);
			}
			(void)matter_tlv_end_container(&w);
			(void)matter_tlv_end_container(&w);
			(void)matter_tlv_writer_finish(&w, &blen);
			T_EQ("a batch is refused", matter_im_invoke_request_decode(buf, blen, &inv),
			     MATTER_E_NOSPACE);
		}

		/* No command at all. */
		{
			static const uint8_t empty_invoke[] = {0x15, 0x36, 0x02, 0x18, 0x18};

			T_EQ("no command refused",
			     matter_im_invoke_request_decode(empty_invoke, sizeof(empty_invoke),
							     &inv),
			     MATTER_E_INVAL);
		}
	}

	t_group("SuppressResponse runs the command and says nothing");
	{
		fill_info(&info);
		T_EQ("decodes",
		     matter_im_invoke_request_decode(apple_armfailsafe, sizeof(apple_armfailsafe),
						     &inv),
		     MATTER_OK);
		inv.suppress_response = true;
		len = 1u;
		T_EQ("encodes",
		     matter_im_invoke_response_encode(&srv, &inv, out, sizeof(out), &len),
		     MATTER_OK);
		T_EQ("nothing to send", (long)len, 0L);
		T_OK("but the command still ran", info.attempt.active);
	}
}

/* ---- WriteRequest and SubscribeRequest ----------------------------------- */

/** One AttributePathIB, as a LIST, inside whatever container is open. */
static void put_path(struct matter_tlv_writer *w, matter_tlv_tag_t tag, bool have_ep,
		     uint16_t endpoint, bool have_cl, uint32_t cluster, bool have_at,
		     uint32_t attribute)
{
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_LIST);
	if (have_ep) {
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(2), endpoint);
	}
	if (have_cl) {
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(3), cluster);
	}
	if (have_at) {
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(4), attribute);
	}
	(void)matter_tlv_end_container(w);
}

/**
 * A WriteRequestMessage carrying @p n_requests AttributeDataIBs. Two is not a
 * batch this node supports, and building one is the only way to prove it says so
 * rather than silently writing the first.
 */
static size_t build_write(uint8_t *buf, size_t cap, unsigned int n_requests, bool have_attribute,
			  bool suppress, bool timed)
{
	struct matter_tlv_writer w;
	unsigned int i;
	size_t len = 0u;

	matter_tlv_writer_init(&w, buf, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bool(&w, MATTER_TLV_CTX(0), suppress);
	(void)matter_tlv_put_bool(&w, MATTER_TLV_CTX(1), timed);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(2), MATTER_TLV_ARRAY);
	for (i = 0u; i < n_requests; i++) {
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0), 0u); /* DataVersion */
		put_path(&w, MATTER_TLV_CTX(1), true, MATTER_ENDPOINT_ROOT, true,
			 MATTER_CLUSTER_ACCESS_CONTROL, have_attribute, MATTER_ATTR_AC_ACL);
		/* An ACL is a list of structures; an empty one is still a value. */
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(2), MATTER_TLV_ARRAY);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
	}
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_writer_finish(&w, &len);
	return len;
}

/** Home Assistant's canonical list update: ReplaceAll([]), then AppendItem. */
static size_t build_binding_list_write(uint8_t *buf, size_t cap)
{
	struct matter_tlv_writer w;
	size_t len = 0u;

	matter_tlv_writer_init(&w, buf, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bool(&w, MATTER_TLV_CTX(0), false);
	(void)matter_tlv_put_bool(&w, MATTER_TLV_CTX(1), false);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(2), MATTER_TLV_ARRAY);
	for (uint8_t append = 0u; append < 2u; append++) {
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0), 0u);
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(1), MATTER_TLV_LIST);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(2), MATTER_ENDPOINT_LOCK);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(3), MATTER_CLUSTER_BINDING);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(4), MATTER_ATTR_BINDING_LIST);
		if (append != 0u) {
			(void)matter_tlv_put_null(&w, MATTER_TLV_CTX(5));
		}
		(void)matter_tlv_end_container(&w);
		if (append == 0u) {
			(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(2), MATTER_TLV_ARRAY);
		} else {
			(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(2),
						 MATTER_TLV_STRUCTURE);
			(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1), 43u);
			(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(3), 1u);
			(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(4),
						 MATTER_CLUSTER_DOOR_LOCK);
		}
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
	}
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_writer_finish(&w, &len);
	return len;
}

static size_t build_subscribe(uint8_t *buf, size_t cap, unsigned int n_paths, uint16_t min_s,
			      uint16_t max_s, bool keep, bool paths_as_array)
{
	struct matter_tlv_writer w;
	unsigned int i;
	size_t len = 0u;

	matter_tlv_writer_init(&w, buf, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bool(&w, MATTER_TLV_CTX(0), keep);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1), min_s);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(2), max_s);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(3),
					 paths_as_array ? MATTER_TLV_ARRAY : MATTER_TLV_STRUCTURE);
	for (i = 0u; i < n_paths; i++) {
		put_path(&w, MATTER_TLV_ANON, true, MATTER_ENDPOINT_LOCK, true,
			 MATTER_CLUSTER_DOOR_LOCK, true, (uint32_t)i);
	}
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_put_bool(&w, MATTER_TLV_CTX(7), true);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_writer_finish(&w, &len);
	return len;
}

/**
 * The two message types a controller uses after commissioning: the ACL write
 * that grants it access, and the subscription that keeps a Home tile live. Both
 * decoders were reachable only from a real controller before this.
 */
void test_matter_im_write(void)
{
	struct matter_device_info info;
	struct matter_im_server srv;
	uint8_t buf[1024];
	uint8_t out[512];
	size_t blen;
	size_t len = 0u;

	fill_info(&info);
	matter_clusters_init(&srv, &info);

	t_group("WriteRequest");
	{
		struct matter_im_write wr;

		blen = build_write(buf, sizeof(buf), 1u, true, false, false);
		T_OK("request builds", blen > 0u);
		T_EQ("decodes", matter_im_write_request_decode(buf, blen, &wr), MATTER_OK);
		T_EQ("endpoint", (long)wr.items[0].path.endpoint, (long)MATTER_ENDPOINT_ROOT);
		T_EQ("cluster", (long)wr.items[0].path.cluster, (long)MATTER_CLUSTER_ACCESS_CONTROL);
		T_EQ("attribute", (long)wr.items[0].path.attribute, (long)MATTER_ATTR_AC_ACL);
		T_OK("value present", wr.items[0].data != NULL && wr.items[0].data_len > 0u);
		T_OK("response not suppressed", !wr.suppress_response);
		T_OK("not a timed request", !wr.timed_request);

		T_EQ("null tlv refused", matter_im_write_request_decode(NULL, blen, &wr),
		     MATTER_E_INVAL);
		T_EQ("null out refused", matter_im_write_request_decode(buf, blen, NULL),
		     MATTER_E_INVAL);

		/* A wildcard write is refused rather than expanded: guessing which
		 * attributes a commissioner meant to overwrite is not recoverable. */
		blen = build_write(buf, sizeof(buf), 1u, false, false, false);
		T_OK("a wildcard write is refused",
		     matter_im_write_request_decode(buf, blen, &wr) != MATTER_OK);

		/*
		 * A batch is CAPPED, not refused outright. Returning an error
		 * left the caller with nothing to answer, and a commissioner
		 * that gets no WriteResponse hangs on "Adding to home" -- so
		 * the decode succeeds with the first path and says so, and the
		 * encoder below turns that into RESOURCE_EXHAUSTED.
		 */
		blen = build_write(buf, sizeof(buf), 2u, true, false, false);
		T_EQ("a batch decodes", matter_im_write_request_decode(buf, blen, &wr), MATTER_OK);
		T_OK("and is flagged truncated", wr.truncated);

		blen = build_write(buf, sizeof(buf), 1u, true, true, true);
		T_EQ("decodes", matter_im_write_request_decode(buf, blen, &wr), MATTER_OK);
		T_OK("suppression carried", wr.suppress_response);
		T_OK("timed flag carried", wr.timed_request);
	}

	t_group("WriteResponse");
	{
		struct matter_im_write wr;

		blen = build_write(buf, sizeof(buf), 1u, true, false, false);
		info.fabrics[0].index = 1u;
		info.fabrics[0].case_admin_subject = 1u;
		info.committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
		info.accessing_fabric_index = 1u;
		info.accessing_node_id = 1u;
		T_EQ("decodes", matter_im_write_request_decode(buf, blen, &wr), MATTER_OK);
		T_EQ("response encodes",
		     matter_im_write_response_encode(&srv, &wr, out, sizeof(out), &len), MATTER_OK);
		T_OK("and has content", len > 0u);
		T_EQ("the ACL reached the device", info.fabric_acls[0].len,
		     wr.items[0].data_len);

		/* Suppressed: nothing to send, but the write still ran. */
		info.fabric_acls[0].len = 0u;
		wr.suppress_response = true;
		len = 1u;
		T_EQ("suppressed response encodes",
		     matter_im_write_response_encode(&srv, &wr, out, sizeof(out), &len), MATTER_OK);
		T_EQ("nothing to send", (long)len, 0L);
		T_EQ("but the write still ran", info.fabric_acls[0].len,
		     wr.items[0].data_len);

		/*
		 * A batch gets an ANSWER, and nothing runs. The peer asked for
		 * a set of writes; applying an arbitrary member of it and
		 * reporting success would be a worse answer than refusing, and
		 * silence -- what this used to do -- is the worst of the three.
		 */
		info.fabric_acls[0].len = 0u;
		blen = build_write(buf, sizeof(buf), 2u, true, false, false);
		T_EQ("batch decodes", matter_im_write_request_decode(buf, blen, &wr), MATTER_OK);
		len = 0u;
		T_EQ("a truncated batch still encodes a response",
		     matter_im_write_response_encode(&srv, &wr, out, sizeof(out), &len), MATTER_OK);
		T_OK("with something to send", len > 0u);
		T_EQ("and nothing was written", (long)info.fabric_acls[0].len, 0L);
		T_OK("status is RESOURCE_EXHAUSTED",
		     memchr(out, MATTER_IM_STATUS_RESOURCE_EXHAUSTED, len) != NULL);

		/* A list transaction is not an arbitrary batch: both IBs name the
		 * same attribute and the second explicitly carries AppendItem. */
		memset(&info.binding, 0, sizeof(info.binding));
		blen = build_binding_list_write(buf, sizeof(buf));
		T_EQ("binding list transaction decodes",
		     matter_im_write_request_decode(buf, blen, &wr), MATTER_OK);
		T_OK("binding list transaction is accepted", !wr.truncated);
		T_EQ("it has replace and append", (long)wr.n_items, 2L);
		len = 0u;
		T_EQ("binding list response encodes",
		     matter_im_write_response_encode(&srv, &wr, out, sizeof(out), &len),
		     MATTER_OK);
		T_EQ("one binding lands", (long)info.binding.count, 1L);
		T_EQ("and names the target", (long)info.binding.e[0].node_id, 43L);
	}

	t_group("SubscribeRequest");
	{
		struct matter_im_subscribe sub;

		blen = build_subscribe(buf, sizeof(buf), 3u, 1u, 60u, true, true);
		T_OK("request builds", blen > 0u);
		T_EQ("decodes", matter_im_subscribe_request_decode(buf, blen, &sub), MATTER_OK);
		T_EQ("three paths", (long)sub.read.n_paths, 3L);
		T_EQ("min interval", (long)sub.min_interval_s, 1L);
		T_EQ("max interval", (long)sub.max_interval_s, 60L);
		T_OK("keeps existing subscriptions", sub.keep_subscriptions);
		T_OK("fabric filter carried", sub.read.fabric_filtered);
		T_EQ("first path cluster", (long)sub.read.paths[0].cluster,
		     (long)MATTER_CLUSTER_DOOR_LOCK);

		T_EQ("null tlv refused", matter_im_subscribe_request_decode(NULL, blen, &sub),
		     MATTER_E_INVAL);
		T_EQ("null out refused", matter_im_subscribe_request_decode(buf, blen, NULL),
		     MATTER_E_INVAL);

		/* AttributeRequests is an array; a structure there is a malformed
		 * message, not a zero-path subscription. */
		blen = build_subscribe(buf, sizeof(buf), 1u, 1u, 60u, false, false);
		T_EQ("a non-array path list is refused",
		     matter_im_subscribe_request_decode(buf, blen, &sub), MATTER_E_TYPE);

		blen = build_subscribe(buf, sizeof(buf), MATTER_IM_MAX_PATHS + 1u, 1u, 60u, false,
				       true);
		T_EQ("more paths than the node can hold is refused",
		     matter_im_subscribe_request_decode(buf, blen, &sub), MATTER_E_NOSPACE);

		blen = build_subscribe(buf, sizeof(buf), MATTER_IM_MAX_PATHS, 0u, 0u, false, true);
		T_EQ("exactly the maximum is accepted",
		     matter_im_subscribe_request_decode(buf, blen, &sub), MATTER_OK);
		T_EQ("all of them", (long)sub.read.n_paths, (long)MATTER_IM_MAX_PATHS);
	}
}

/* ---- events ------------------------------------------------------------- */

/*
 * A LockOperation event, from the command that causes it to the report that
 * carries it.
 *
 * This exists because the node served NO events at all, which is the working
 * hypothesis for why Apple Home shows the lock none of its access controls: the
 * CHIP builds serve LockOperation and the Nordic reference needed a zap patch to
 * add exactly that one.
 */

/** Run one argument-less Door Lock command straight through the server. */
static uint8_t run_lock_command(struct matter_im_server *srv, uint32_t command)
{
	struct matter_im_invoke inv;
	uint32_t response = MATTER_IM_NO_RESPONSE;

	memset(&inv, 0, sizeof(inv));
	inv.endpoint = MATTER_ENDPOINT_LOCK;
	inv.cluster = MATTER_CLUSTER_DOOR_LOCK;
	inv.command = command;
	return srv->command(srv->ctx, &inv, &response);
}

/** Write an EventPathIB, with each component present only if asked for. */
static void put_event_path(struct matter_tlv_writer *w, bool have_ep, uint16_t ep, bool have_cl,
			   uint32_t cl, bool have_ev, uint32_t ev)
{
	(void)matter_tlv_start_container(w, MATTER_TLV_ANON, MATTER_TLV_LIST);
	if (have_ep) {
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(1), ep); /* EventPathIB.h:40 */
	}
	if (have_cl) {
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(2), cl);
	}
	if (have_ev) {
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(3), ev);
	}
	(void)matter_tlv_end_container(w);
}

/** A SubscribeRequest carrying event requests, and optionally an event filter. */
static size_t build_event_subscribe(uint8_t *buf, size_t cap, unsigned int n_event_paths,
				    bool with_filter, uint64_t event_min)
{
	struct matter_tlv_writer w;
	unsigned int i;
	size_t len = 0u;

	matter_tlv_writer_init(&w, buf, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1), 1u);   /* min interval */
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(2), 60u);  /* max interval */
	/* EventRequests, tag 4 in a subscribe (SubscribeRequestMessage.h:44). */
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(4), MATTER_TLV_ARRAY);
	for (i = 0u; i < n_event_paths; i++) {
		put_event_path(&w, true, MATTER_ENDPOINT_LOCK, true, MATTER_CLUSTER_DOOR_LOCK, true,
			       MATTER_EVENT_DL_LOCK_OPERATION);
	}
	(void)matter_tlv_end_container(&w);
	if (with_filter) {
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(5), MATTER_TLV_ARRAY);
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1), event_min); /* EventMin */
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
	}
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_writer_finish(&w, &len);
	return len;
}

/** A read whose ONE event path names everything. */
static void one_event_path(struct matter_im_read *req)
{
	memset(req, 0, sizeof(*req));
	req->n_event_paths = 1u;
	req->event_paths[0].endpoint = MATTER_ENDPOINT_LOCK;
	req->event_paths[0].have_endpoint = true;
	req->event_paths[0].cluster = MATTER_CLUSTER_DOOR_LOCK;
	req->event_paths[0].have_cluster = true;
	req->event_paths[0].event = MATTER_EVENT_DL_LOCK_OPERATION;
	req->event_paths[0].have_event = true;
}

/**
 * Walk a ReportData and count the EventReportIBs in it, returning the first
 * event's number and the operation type it carries.
 */
static int count_event_reports(const uint8_t *tlv, size_t len, uint64_t *first_number,
			       uint64_t *first_op)
{
	struct matter_tlv_reader r;
	int n = 0;

	if (first_number != NULL) {
		*first_number = 0u;
	}
	if (first_op != NULL) {
		*first_op = 0xFFu;
	}

	matter_tlv_reader_init(&r, tlv, len);
	if (matter_tlv_next(&r) != 0 || matter_tlv_enter(&r) != 0) {
		return -1;
	}
	while (matter_tlv_next(&r) == 0) {
		if (matter_tlv_tag(&r) != MATTER_TLV_CTX(2)) { /* EventReports */
			continue;
		}
		if (matter_tlv_enter(&r) != 0) {
			return -1;
		}
		while (matter_tlv_next(&r) == 0) { /* one EventReportIB */
			if (matter_tlv_enter(&r) != 0) {
				return -1;
			}
			while (matter_tlv_next(&r) == 0) { /* EventData at tag 1 */
				if (matter_tlv_tag(&r) != MATTER_TLV_CTX(1)) {
					continue;
				}
				if (matter_tlv_enter(&r) != 0) {
					return -1;
				}
				while (matter_tlv_next(&r) == 0) {
					uint64_t v = 0u;

					if (matter_tlv_tag(&r) == MATTER_TLV_CTX(1) && n == 0 &&
					    first_number != NULL &&
					    matter_tlv_get_u64(&r, &v) == 0) {
						*first_number = v;
					} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(7) &&
						   n == 0 && first_op != NULL) {
						/* The fields structure: its
						 * first member is the type. */
						if (matter_tlv_enter(&r) == 0) {
							if (matter_tlv_next(&r) == 0) {
								(void)matter_tlv_get_u64(&r,
											 first_op);
							}
							(void)matter_tlv_exit(&r);
						}
					}
				}
				(void)matter_tlv_exit(&r);
			}
			(void)matter_tlv_exit(&r);
			n++;
		}
		(void)matter_tlv_exit(&r);
	}
	return n;
}

void test_matter_im_events(void)
{
	struct matter_device_info info;
	struct matter_im_server srv;
	struct matter_im_read req;
	uint8_t buf[1024];
	uint8_t out[512];
	size_t blen;
	size_t len = 0u;
	uint64_t number = 0u;
	uint64_t op = 0u;

	t_group("a LockOperation event is recorded when the tile unlocks");
	{
		fill_info(&info);
		authorize_admin(&info);
		matter_clusters_init(&srv, &info);

		T_EQ("a fresh node holds no events", (long)matter_clusters_event_count(&info), 0L);

		T_EQ("UnlockDoor accepted", run_lock_command(&srv, MATTER_CMD_DL_UNLOCK_DOOR),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("and it left an event", (long)matter_clusters_event_count(&info), 1L);
		T_EQ("numbered from one", (long)info.events[0].number, 1L);
		T_EQ("the operation is Unlock", (long)info.events[0].operation,
		     (long)MATTER_DL_LOCK_OP_UNLOCK);
		T_EQ("the source is Remote -- a controller asked", (long)info.events[0].source,
		     (long)MATTER_DL_OP_SOURCE_REMOTE);
		T_EQ("on the fabric that asked", (long)info.events[0].fabric_index, 1L);

		T_EQ("LockDoor accepted", run_lock_command(&srv, MATTER_CMD_DL_LOCK_DOOR),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("two events now", (long)matter_clusters_event_count(&info), 2L);
		T_OK("and the numbers never repeat", info.events[1].number > info.events[0].number);
	}

	t_group("a walk-up is credential-sourced and belongs to no fabric");
	{
		fill_info(&info);
		matter_clusters_init(&srv, &info);

		matter_clusters_record_lock_operation(&info, MATTER_DL_LOCK_OP_UNLOCK,
						      MATTER_DL_OP_SOURCE_ALIRO, 0u, 0u);
		T_EQ("recorded", (long)matter_clusters_event_count(&info), 1L);
		T_EQ("the credential source", (long)info.events[0].source,
		     (long)MATTER_DL_OP_SOURCE_ALIRO);
		T_EQ("no fabric", (long)info.events[0].fabric_index, 0L);

		/* A node id offered without a fabric is dropped rather than
		 * reported: it would name a controller that did not ask. */
		matter_clusters_record_lock_operation(&info, MATTER_DL_LOCK_OP_LOCK,
						      MATTER_DL_OP_SOURCE_ALIRO, 0u,
						      0x1122334455667788ULL);
		T_EQ("a node id without a fabric is not kept", (long)info.events[1].source_node,
		     0L);
	}

	t_group("the ring keeps the newest, not the oldest");
	{
		unsigned int i;

		fill_info(&info);
		matter_clusters_init(&srv, &info);

		for (i = 0u; i < MATTER_EVENTS_MAX + 2u; i++) {
			matter_clusters_record_lock_operation(&info, MATTER_DL_LOCK_OP_UNLOCK,
							      MATTER_DL_OP_SOURCE_ALIRO, 0u, 0u);
		}
		T_EQ("it never grows past its bound", (long)matter_clusters_event_count(&info),
		     (long)MATTER_EVENTS_MAX);
		T_EQ("the oldest held is the third recorded", (long)info.events[0].number, 3L);
		T_EQ("and the newest is the last", (long)info.events[MATTER_EVENTS_MAX - 1u].number,
		     (long)(MATTER_EVENTS_MAX + 2u));
	}

	t_group("a report carries the events a request asked for");
	{
		fill_info(&info);
		matter_clusters_init(&srv, &info);
		matter_clusters_record_lock_operation(&info, MATTER_DL_LOCK_OP_UNLOCK,
						      MATTER_DL_OP_SOURCE_ALIRO, 0u, 0u);

		/* A request naming NO event path gets no EventReports array at
		 * all -- which is what keeps every commissioning read byte-for-
		 * byte what it was before events existed. */
		memset(&req, 0, sizeof(req));
		req.n_paths = 1u;
		req.paths[0].endpoint = MATTER_ENDPOINT_LOCK;
		req.paths[0].have_endpoint = true;
		req.paths[0].cluster = MATTER_CLUSTER_DOOR_LOCK;
		req.paths[0].have_cluster = true;
		req.paths[0].attribute = MATTER_ATTR_DL_LOCK_STATE;
		req.paths[0].have_attribute = true;
		T_EQ("an attribute-only read encodes",
		     matter_im_report_data_encode(&srv, &req, out, sizeof(out), &len, NULL),
		     MATTER_OK);
		T_EQ("and carries no event reports", count_event_reports(out, len, NULL, NULL), 0);

		one_event_path(&req);
		T_EQ("an event read encodes",
		     matter_im_report_data_encode(&srv, &req, out, sizeof(out), &len, NULL),
		     MATTER_OK);
		T_EQ("and carries the one event", count_event_reports(out, len, &number, &op), 1);
		T_EQ("with its event number", (long)number, 1L);
		T_EQ("and the operation it recorded", (long)op, (long)MATTER_DL_LOCK_OP_UNLOCK);
	}

#if MATTER_FEATURE_DL_ALARMS
	t_group("a forced door is recorded as an alarm, in the same ring");
	{
		fill_info(&info);
		matter_clusters_init(&srv, &info);

		matter_clusters_record_alarm(&info, MATTER_DL_ALARM_DOOR_FORCED_OPEN);
		T_EQ("recorded", (long)matter_clusters_event_count(&info), 1L);
		T_EQ("as the alarm event", (long)info.events[0].event_id,
		     (long)MATTER_EVENT_DL_ALARM);
		T_EQ("carrying DoorForcedOpen", (long)info.events[0].alarm_code,
		     (long)MATTER_DL_ALARM_DOOR_FORCED_OPEN);

		/* One ring for both events, because EventNumbers are ONE
		 * ascending sequence for the node: a second ring would have to
		 * invent an ordering between them that the numbers already
		 * answer, and a subscriber's EventMin filter reads that
		 * ordering as "already seen". */
		matter_clusters_record_lock_operation(&info, MATTER_DL_LOCK_OP_LOCK,
						      MATTER_DL_OP_SOURCE_ALIRO, 0u, 0u);
		T_EQ("a lock operation shares the ring", (long)matter_clusters_event_count(&info),
		     2L);
		T_OK("and the numbers stay one ascending sequence",
		     info.events[1].number > info.events[0].number);
		T_EQ("each entry says which event it is", (long)info.events[1].event_id,
		     (long)MATTER_EVENT_DL_LOCK_OPERATION);
	}

	t_group("a report carries the alarm, its code, and no operation fields");
	{
		fill_info(&info);
		matter_clusters_init(&srv, &info);
		matter_clusters_record_alarm(&info, MATTER_DL_ALARM_DOOR_AJAR);

		one_event_path(&req);
		req.event_paths[0].event = MATTER_EVENT_DL_ALARM;
		T_EQ("an alarm read encodes",
		     matter_im_report_data_encode(&srv, &req, out, sizeof(out), &len, NULL),
		     MATTER_OK);
		T_EQ("and carries the one event", count_event_reports(out, len, &number, &op), 1);
		T_EQ("with its event number", (long)number, 1L);
		/* Field 0 of a DoorLockAlarm is the AlarmCode; field 0 of a
		 * LockOperation is the operation type. Reading the first field
		 * is therefore also the check that the right ENCODER ran. */
		T_EQ("and its first field is the AlarmCode", (long)op,
		     (long)MATTER_DL_ALARM_DOOR_AJAR);

		/* Same endpoint, same cluster, different event: a subscriber
		 * watching LockOperation must not be handed an alarm, which is
		 * what the per-entry event id is FOR. */
		one_event_path(&req);
		T_EQ("a LockOperation read encodes",
		     matter_im_report_data_encode(&srv, &req, out, sizeof(out), &len, NULL),
		     MATTER_OK);
		T_EQ("and the alarm is not in it", count_event_reports(out, len, NULL, NULL), 0);
	}
#endif /* MATTER_FEATURE_DL_ALARMS */

	t_group("an event filter is what stops a subscriber seeing an unlock twice");
	{
		fill_info(&info);
		matter_clusters_init(&srv, &info);
		matter_clusters_record_lock_operation(&info, MATTER_DL_LOCK_OP_UNLOCK,
						      MATTER_DL_OP_SOURCE_ALIRO, 0u, 0u);
		matter_clusters_record_lock_operation(&info, MATTER_DL_LOCK_OP_LOCK,
						      MATTER_DL_OP_SOURCE_ALIRO, 0u, 0u);

		one_event_path(&req);
		T_EQ("unfiltered encodes",
		     matter_im_report_data_encode(&srv, &req, out, sizeof(out), &len, NULL),
		     MATTER_OK);
		T_EQ("and carries both", count_event_reports(out, len, NULL, NULL), 2);

		req.event_min = 2u;
		T_EQ("filtered encodes",
		     matter_im_report_data_encode(&srv, &req, out, sizeof(out), &len, NULL),
		     MATTER_OK);
		T_EQ("and carries only what the peer has not seen",
		     count_event_reports(out, len, &number, NULL), 1);
		T_EQ("which is the second one", (long)number, 2L);

		req.event_min = 99u;
		T_EQ("a filter past everything encodes",
		     matter_im_report_data_encode(&srv, &req, out, sizeof(out), &len, NULL),
		     MATTER_OK);
		T_EQ("and carries nothing", count_event_reports(out, len, NULL, NULL), 0);
	}

	t_group("an event path that names something else matches nothing");
	{
		fill_info(&info);
		matter_clusters_init(&srv, &info);
		matter_clusters_record_lock_operation(&info, MATTER_DL_LOCK_OP_UNLOCK,
						      MATTER_DL_OP_SOURCE_ALIRO, 0u, 0u);

		one_event_path(&req);
		req.event_paths[0].event = 0x00FFu;
		T_EQ("a read for another event encodes",
		     matter_im_report_data_encode(&srv, &req, out, sizeof(out), &len, NULL),
		     MATTER_OK);
		T_EQ("and reports none of ours", count_event_reports(out, len, NULL, NULL), 0);

		/* Wildcards work the same way they do for attributes: a
		 * controller subscribing to "all events" names nothing at all. */
		memset(&req, 0, sizeof(req));
		req.n_event_paths = 1u;
		T_EQ("a wildcard event path encodes",
		     matter_im_report_data_encode(&srv, &req, out, sizeof(out), &len, NULL),
		     MATTER_OK);
		T_EQ("and matches the event", count_event_reports(out, len, NULL, NULL), 1);
	}

	t_group("SubscribeRequest carries event paths and filters");
	{
		struct matter_im_subscribe sub;

		blen = build_event_subscribe(buf, sizeof(buf), 1u, false, 0u);
		T_OK("request builds", blen > 0u);
		T_EQ("decodes", matter_im_subscribe_request_decode(buf, blen, &sub), MATTER_OK);
		T_EQ("one event path", (long)sub.read.n_event_paths, 1L);
		T_EQ("on the lock endpoint", (long)sub.read.event_paths[0].endpoint,
		     (long)MATTER_ENDPOINT_LOCK);
		T_EQ("the Door Lock cluster", (long)sub.read.event_paths[0].cluster,
		     (long)MATTER_CLUSTER_DOOR_LOCK);
		T_EQ("and the LockOperation event", (long)sub.read.event_paths[0].event,
		     (long)MATTER_EVENT_DL_LOCK_OPERATION);
		T_EQ("no filter means everything held", (long)sub.read.event_min, 0L);

		blen = build_event_subscribe(buf, sizeof(buf), 1u, true, 7u);
		T_EQ("with a filter it decodes",
		     matter_im_subscribe_request_decode(buf, blen, &sub), MATTER_OK);
		T_EQ("and the EventMin is carried", (long)sub.read.event_min, 7L);

		blen = build_event_subscribe(buf, sizeof(buf), MATTER_IM_MAX_EVENT_PATHS + 1u, false,
					     0u);
		T_EQ("more event paths than the node holds is refused",
		     matter_im_subscribe_request_decode(buf, blen, &sub), MATTER_E_NOSPACE);
	}

	/* Keep the complete event ring compact even though the application now
	 * encodes directly into an owned full-size packet. */
	t_group("a full event ring remains compact");
	{
		uint8_t notify[256];
		unsigned int i;

		fill_info(&info);
		matter_clusters_init(&srv, &info);
		for (i = 0u; i < MATTER_EVENTS_MAX; i++) {
			matter_clusters_record_lock_operation(&info, MATTER_DL_LOCK_OP_UNLOCK,
							      MATTER_DL_OP_SOURCE_REMOTE, 1u,
							      0x1122334455667788ULL);
		}
		one_event_path(&req);
		req.n_paths = 1u;
		req.paths[0].endpoint = MATTER_ENDPOINT_LOCK;
		req.paths[0].have_endpoint = true;
		req.paths[0].cluster = MATTER_CLUSTER_DOOR_LOCK;
		req.paths[0].have_cluster = true;
		req.paths[0].attribute = MATTER_ATTR_DL_LOCK_STATE;
		req.paths[0].have_attribute = true;
		req.subscription_id = 0x11223344u;

		T_EQ("the report fits the notify buffer",
		     matter_im_report_data_encode(&srv, &req, notify, sizeof(notify), &len, NULL),
		     MATTER_OK);
		/* 247 B when this was written. The check is that it fits, not
		 * that it is exactly that -- a field added to the event should
		 * fail on the bound, not on a number nobody can update. */
		T_OK("with room to spare", len <= sizeof(notify));
		T_EQ("and carries every event", count_event_reports(notify, len, NULL, NULL),
		     (int)MATTER_EVENTS_MAX);
	}
}
