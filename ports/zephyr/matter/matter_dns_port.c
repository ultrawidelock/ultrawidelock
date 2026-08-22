/* SPDX-License-Identifier: ISC */

/*
 * matter_dns_port — finding the lock this one was bound to.
 *
 * The SRP client in matter_thread_port.c is this node PUBLISHING itself so a
 * controller can find it. This is the other half, and it exists only in a
 * client build: looking somebody else up.
 *
 * A Matter node on a Thread network registers with the network's SRP server,
 * which serves the registrations back over DNS-SD. So resolving a bound peer is
 * one service query against a name this node can DERIVE rather than discover --
 * matter_fabric_instance_name() builds it from the compressed fabric id and the
 * node id, both of which are already in hand. Nothing browses, and a browse
 * would be the wrong shape anyway: the answer is a specific node, not a list.
 *
 * ONE QUERY AT A TIME. otDnsClient carries its own per-query state and this
 * node has exactly one binding it acts on at a time, so a second concurrent
 * resolve would be a second thing to cancel, time out and reconcile for no gain
 * at all. A resolve that is already outstanding is reported as such and the
 * caller's state machine backs off.
 */
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/openthread.h>

#include <openthread/dns_client.h>
#include <openthread/thread.h>

#include "matter_status.h"
#include "matter_thread.h"

LOG_MODULE_DECLARE(matter_thread, CONFIG_LOG_DEFAULT_LEVEL);

/*
 * The Matter operational service, and the domain an SRP server serves its
 * registrations under (Matter core spec, 4.3: "_matter._tcp"; the domain is
 * OpenThread's default, matching what otSrpClient registered into).
 */
#define MATTER_SERVICE_NAME "_matter._tcp.default.service.arpa."

/**
 * How long a query may hold the slot before it is treated as never coming back.
 *
 * A BACKSTOP FOR A CALLBACK THAT NEVER ARRIVES, not a tuning knob. otDnsClient
 * has its own timeout and retry schedule and normally answers -- with a failure
 * if nothing else -- well inside this. But `busy` used to be cleared ONLY by
 * that callback, so a query that never completed left the slot held for the
 * rest of the boot: every later resolve returned MATTER_E_STATE, every walk-up
 * failed instantly with nothing on the radio, and only a reboot fixed it. A
 * wedged slot is worth more than the answer it is still waiting for.
 */
#define QUERY_MAX_MS 15000u

/** The one outstanding query, and who asked for it. */
static struct {
	matter_thread_resolve_fn cb;
	void *ctx;
	bool busy;
	uint32_t started_ms;
	/**
	 * Which query the callback is allowed to answer.
	 *
	 * Reclaiming the slot on QUERY_MAX_MS is not enough on its own: the
	 * abandoned query may still be alive inside otDnsClient, and its answer
	 * would otherwise be handed to whoever asked NEXT -- a resolve for one
	 * peer completing with another peer's address. The generation goes out
	 * as the query's context and comes back with the answer, so a late one
	 * is recognised and dropped instead.
	 */
	uint32_t generation;
} s_query;

/**
 * Hand the answer back exactly once, and free the slot BEFORE doing it.
 *
 * The callback is entitled to start another resolve -- a failure is the most
 * likely moment for the caller to want one -- and it would find the slot still
 * marked busy if this were the other way round.
 */
static void finish(const struct matter_thread_peer *peer)
{
	matter_thread_resolve_fn cb = s_query.cb;
	void *ctx = s_query.ctx;

	s_query.cb = NULL;
	s_query.ctx = NULL;
	s_query.busy = false;

	if (cb != NULL) {
		cb(ctx, peer);
	}
}

/** otDnsClient's answer, on OpenThread's thread. */
static void resolve_cb(otError err, const otDnsServiceResponse *response, void *ctx)
{
	struct matter_thread_peer peer;
	otDnsServiceInfo info;

	if ((uint32_t)(uintptr_t)ctx != s_query.generation) {
		LOG_WRN("a resolve that had already been given up on answered; ignoring it");
		return;
	}
	char host[OT_DNS_MAX_NAME_SIZE];

	(void)ctx;

	if (err != OT_ERROR_NONE || response == NULL) {
		/* OT_ERROR_NOT_FOUND is the ordinary one: nothing on this
		 * network has registered that name. Logged at the same level as
		 * the rest because from here they are the same outcome. */
		LOG_WRN("bound peer not resolved (ot %d)", err);
		finish(NULL);
		return;
	}

	memset(&info, 0, sizeof(info));
	/*
	 * Every buffer in otDnsServiceInfo is the CALLER's, and OpenThread
	 * fills whichever are non-NULL. The TXT record is deliberately not
	 * asked for: its contents tune retransmission timings this node does
	 * not negotiate (see matter_case.c on session parameters), and asking
	 * for it would mean carrying a second buffer for a value nothing reads.
	 */
	info.mHostNameBuffer = host;
	info.mHostNameBufferSize = sizeof(host);

	if (otDnsServiceResponseGetServiceInfo(response, &info) != OT_ERROR_NONE) {
		LOG_WRN("bound peer resolved to a record without a service");
		finish(NULL);
		return;
	}

	/*
	 * A SRV record with no AAAA behind it. This happens when the peer's
	 * host registration expired while its service registration had not, and
	 * it is worth telling apart from "not found": the name exists, so the
	 * binding is right and the peer is the problem.
	 */
	if (info.mHostAddress.mFields.m32[0] == 0u && info.mHostAddress.mFields.m32[1] == 0u &&
	    info.mHostAddress.mFields.m32[2] == 0u && info.mHostAddress.mFields.m32[3] == 0u) {
		LOG_WRN("bound peer has a service but no address yet");
		finish(NULL);
		return;
	}

	memset(&peer, 0, sizeof(peer));
	memcpy(peer.addr, info.mHostAddress.mFields.m8, sizeof(peer.addr));
	peer.port = info.mPort;
	peer.valid = true;

	LOG_INF("bound peer resolved: port %u", (unsigned int)peer.port);
	finish(&peer);
}

int matter_thread_resolve(const char *instance_name, matter_thread_resolve_fn cb, void *ctx)
{
	otInstance *ot = openthread_get_default_instance();
	otError err;

	if (instance_name == NULL || cb == NULL) {
		return MATTER_E_INVAL;
	}
	if (ot == NULL) {
		return MATTER_E_STATE;
	}
	if (s_query.busy) {
		if ((int32_t)(k_uptime_get_32() - s_query.started_ms) < (int32_t)QUERY_MAX_MS) {
			return MATTER_E_STATE;
		}
		/*
		 * Past the backstop. The slot is freed here and the generation
		 * is bumped by the start below, which is what orphans the old
		 * query: a late answer carries the old generation and is
		 * dropped rather than handed to whoever asked next.
		 */
		LOG_WRN("the previous resolve never answered; taking the slot back");
		s_query.cb = NULL;
		s_query.ctx = NULL;
		s_query.busy = false;
	}
	/*
	 * Detached, there is no SRP server to ask and the query would fail
	 * after a timeout rather than immediately. Failing now is the same
	 * answer sooner, and it keeps the caller's step deadline meaningful.
	 */
	if (otThreadGetDeviceRole(ot) <= OT_DEVICE_ROLE_DETACHED) {
		return MATTER_E_STATE;
	}

	s_query.cb = cb;
	s_query.ctx = ctx;
	s_query.busy = true;
	s_query.started_ms = k_uptime_get_32();
	s_query.generation++;

	LOG_INF("resolving bound peer %s", instance_name);

	openthread_mutex_lock();
	/* NULL config: use whatever server the network told OpenThread about,
	 * which is the same one the SRP client registered this node with. Resolve
	 * the host address too: an SRV response is not required to carry its AAAA
	 * record in the Additional Data section. The context is the generation, so
	 * a late answer can be told apart from the answer to the query now in the
	 * slot. */
	err = otDnsClientResolveServiceAndHostAddress(
		ot, instance_name, MATTER_SERVICE_NAME, resolve_cb,
		(void *)(uintptr_t)s_query.generation, NULL);
	openthread_mutex_unlock();

	if (err != OT_ERROR_NONE) {
		LOG_WRN("resolve not sent (ot %d)", err);
		s_query.cb = NULL;
		s_query.ctx = NULL;
		s_query.busy = false;
		return MATTER_E_STATE;
	}
	return MATTER_OK;
}
