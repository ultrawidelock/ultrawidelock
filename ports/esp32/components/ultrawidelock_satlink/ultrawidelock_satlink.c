/* SPDX-License-Identifier: ISC */

/**
 * @file ultrawidelock_satlink.c — the sealed anchor link's ESP-NOW carrier.
 *
 * Bytes, key storage and channel discovery. Every decision about a DATAGRAM is
 * ultrawidelock_link.c's, shared with the Thread port, so the two carriers
 * cannot come to different conclusions about the same bytes; what is this
 * carrier's own is finding the one Wi-Fi channel ESP-NOW crosses on (the
 * CHANNEL DISCOVERY comment below), a problem the Thread mesh does not have.
 *
 * BROADCAST, NOT A UNICAST PEER. Both directions go to the ESP-NOW broadcast
 * address, matching the Thread port's mesh-local all-nodes for the same reason:
 * neither board is ever told the other's address, so replacing one, or reusing
 * these boards on a different door, costs no re-provisioning. Only a holder of
 * the link key can produce or read anything, so the broadcast costs a frame and
 * reveals a distance to nobody who could not already measure one.
 *
 * WHAT A LISTENER LEARNS ANYWAY. ESP-NOW frames carry a source MAC in the
 * clear, and the sealed payload's length says which of the two messages it is.
 * So an observer learns that two boards are exchanging something and how often.
 * That is the same exposure the Thread port has and is not what the seal is
 * for; the seal keeps the distance, the URSK and the schedule.
 */

#include "ultrawidelock_satlink.h"

#include <string.h>

#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_now.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "satlink";

/*
 * THE FRAME MUST FIT THE CARRIER, checked here where the carrier is chosen.
 * The largest thing this link sends is the WV4 handoff at
 * ULTRAWIDELOCK_LINK_MAX_FRAME bytes. If that ever outgrew ESP-NOW's payload,
 * the symptom would be a session handoff that silently never arrives -- a
 * satellite that ranges perfectly and joins nothing -- so it fails the build
 * instead.
 */
_Static_assert(ULTRAWIDELOCK_LINK_MAX_FRAME <= ESP_NOW_MAX_DATA_LEN,
	       "sealed frame is larger than one ESP-NOW payload");

/* NVS names. All are capped at 15 characters by ESP-IDF and all are declared
 * in PORTING.md's storage table; the asserts below fail the build rather than
 * let a too-long name become a silent "never stored" at run time. */
#define SATLINK_NS   "satlink"
#define SATLINK_KEY  "lk"
#define SATLINK_CHAN "ch"
_Static_assert(sizeof(SATLINK_NS) - 1 <= NVS_NS_NAME_MAX_SIZE - 1,
	       "NVS namespace name is longer than NVS allows (NVS_NS_NAME_MAX_SIZE - 1)");
_Static_assert(sizeof(SATLINK_KEY) - 1 <= NVS_KEY_NAME_MAX_SIZE - 1,
	       "NVS key name is longer than NVS allows (NVS_KEY_NAME_MAX_SIZE - 1)");
_Static_assert(sizeof(SATLINK_CHAN) - 1 <= NVS_KEY_NAME_MAX_SIZE - 1,
	       "NVS key name is longer than NVS allows (NVS_KEY_NAME_MAX_SIZE - 1)");

/*
 * CHANNEL DISCOVERY. ESP-NOW only crosses between boards on the same Wi-Fi
 * channel, and the two ends do not get to pick one number: the lock is a
 * station on whatever channel its AP chose, and the satellite associates with
 * nothing. So the satellite hunts: it sends the link's unsealed challenge
 * beacon on each channel in turn and parks on the one where the lock answers.
 *
 * The probe is the existing 9-byte challenge frame -- no new wire format going
 * out, and ultrawidelock_link_consume() reads it before the key is consulted,
 * so a factory-fresh satellite can find the lock before anyone types a key in.
 * The ANSWER is this carrier's own: the same 9 bytes with the version byte's
 * top bit set, echoing the probe's nonce. It must not be a challenge frame
 * itself -- two locks in radio range would then answer each other's answers
 * forever -- and the shared parser ignoring it guarantees only real probes
 * draw replies. The nonce echo is what stops a satellite mistaking another
 * satellite's probe, or a stale answer, for its own.
 *
 * Once found, the channel is persisted and re-verified by a heartbeat probe;
 * enough consecutive silent heartbeats restart the hunt (the AP may have
 * rebooted onto a new channel). A satellite mid-rescan can miss a session
 * handoff, and a spoofed reply can park it on a dead channel -- both cost
 * reports, and absent reports leave the verdict UNKNOWN, which PERMITS. An
 * attacker with that much radio presence could simply jam 2.4 GHz; the
 * fail-open direction is the design's answer, not this file's.
 */
#define SCAN_TICK_US       (150 * 1000)	/* one channel dwell per tick */
#define SCAN_CHAN_MIN      1u
#define SCAN_CHAN_MAX      13u		/* 12/13 may refuse TX by region; skipped via error */
#define HEARTBEAT_TICKS    100u		/* probe the lock every 15 s once found */
#define HEARTBEAT_MISS_MAX 3u		/* rescan after 45 s of silence */

/* Carrier-only first bytes. A reply proves which channel heard a probe. A
 * freshness beacon carries a lock-owned nonce but must not look like a probe,
 * or nearby locks would answer one another's beacons indefinitely. */
#define SCAN_REPLY_MARK ((uint8_t)(ULTRAWIDELOCK_WITNESS_MSG_VER | 0x80u))
#define FRESHNESS_MARK  ((uint8_t)(ULTRAWIDELOCK_WITNESS_MSG_VER | 0x40u))

/* Floor between epoch rolls. Well under the fusion's staleness window, so a
 * genuinely rebooted satellite is believed again within one report or two,
 * and far above the rate a probe flood could force. */
#define FRESHNESS_MIN_MS 2000

static const uint8_t BCAST[ESP_NOW_ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static struct ultrawidelock_link s_link;
static SemaphoreHandle_t s_link_mutex;
/* When the freshness epoch last rolled. See freshness_challenge_send(). */
static int64_t s_fresh_ms;
static bool s_up;
static ultrawidelock_satlink_report_cb s_report_cb;
static ultrawidelock_satlink_join_cb s_join_cb;

/* Which end of the link this image is; set once at init. The lock answers
 * probes and never changes channel (its AP owns that); the satellite hunts. */
static uint8_t s_role;
/* True only when this file brought Wi-Fi up itself. Riding someone else's
 * radio -- Matter's on the lock -- forbids touching their channel. */
static bool s_wifi_ours;

/* Scan state. s_probe_nonce is written on the esp_timer task and read on the
 * Wi-Fi task, s_probe_hit the other way around; both are single flags whose
 * torn-read worst case is one missed probe, answered by the next one. */
static volatile uint64_t s_probe_nonce;
static volatile bool s_probe_hit;
static bool s_scanning;
static bool s_chan_found;
static uint8_t s_chan;
static uint32_t s_ticks;
static uint32_t s_misses;
static esp_timer_handle_t s_scan_timer;

static bool link_take(TickType_t wait)
{
	return s_link_mutex != NULL && xSemaphoreTake(s_link_mutex, wait) == pdTRUE;
}

static void link_give(void)
{
	xSemaphoreGive(s_link_mutex);
}

void ultrawidelock_satlink_set_report_cb(ultrawidelock_satlink_report_cb cb)
{
	s_report_cb = cb;
}

void ultrawidelock_satlink_set_join_cb(ultrawidelock_satlink_join_cb cb)
{
	s_join_cb = cb;
}

bool ultrawidelock_satlink_ready(void)
{
	bool ready = false;

	if (s_up && link_take(0u)) {
		ready = ultrawidelock_link_ready(&s_link);
		link_give();
	}
	return ready;
}

/** Load the stored link key, if there is one. Absence is not an error. */
static void key_load(void)
{
	uint8_t key[ULTRAWIDELOCK_SEAL_KEY_LEN];
	size_t len = sizeof(key);
	nvs_handle_t h;

	if (nvs_open(SATLINK_NS, NVS_READONLY, &h) != ESP_OK) {
		return;
	}
	if (nvs_get_blob(h, SATLINK_KEY, key, &len) == ESP_OK) {
		if (link_take(portMAX_DELAY)) {
			(void)ultrawidelock_link_set_key(&s_link, key, len);
			link_give();
		}
	}
	nvs_close(h);
	memset(key, 0, sizeof(key));
}

int ultrawidelock_satlink_set_key(const uint8_t *key, size_t len)
{
	nvs_handle_t h;
	esp_err_t e;
	int rc;

	/* Install first: a key the link refuses must never reach flash, or the
	 * next boot loads something that cannot seal and says nothing about it. */
	if (!link_take(portMAX_DELAY)) {
		return -1;
	}
	rc = ultrawidelock_link_set_key(&s_link, key, len);
	link_give();
	if (rc != 0) {
		ESP_LOGE(TAG, "link key must be %u bytes", (unsigned)ULTRAWIDELOCK_SEAL_KEY_LEN);
		return -1;
	}
	if (nvs_open(SATLINK_NS, NVS_READWRITE, &h) != ESP_OK) {
		return -1;
	}
	e = nvs_set_blob(h, SATLINK_KEY, key, len);
	if (e == ESP_OK) {
		e = nvs_commit(h);
	}
	nvs_close(h);
	if (e != ESP_OK) {
		/* The key is live in RAM but will not survive a reboot. Say so:
		 * a link that works until the next power cut is worse to debug
		 * than one that never worked. */
		ESP_LOGE(TAG, "link key not persisted (%s); it will be lost on reboot",
			 esp_err_to_name(e));
		return -1;
	}
	return 0;
}

/** Hand one sealed frame to the carrier. */
static void tx(const uint8_t *buf, size_t len)
{
	esp_err_t e = esp_now_send(BCAST, buf, len);

	if (e != ESP_OK) {
		ESP_LOGW(TAG, "send failed (%s)", esp_err_to_name(e));
	}
}

/**
 * Broadcast the lock's freshness challenge, rolling it at most every
 * FRESHNESS_MIN_MS.
 *
 * Every probe gets an answer, because a satellite that missed the last beacon
 * has no other way to learn the current epoch. But a probe does not get to
 * ROLL the epoch: a roll retires every report already in flight, so an
 * attacker broadcasting probes at line rate would otherwise keep the lock
 * permanently between epochs and starve the geometry it is supposed to
 * protect. Answering with the standing nonce costs the attacker the effect and
 * costs an honest satellite nothing.
 */
static void freshness_challenge_send(void)
{
	uint8_t frame[ULTRAWIDELOCK_LINK_CHALLENGE_LEN];
	int64_t now = esp_timer_get_time() / 1000;
	uint64_t nonce;
	size_t len;

	/* Expected state is local, never learned from an unauthenticated
	 * incoming probe. Replaying an old probe therefore cannot make an old
	 * report fresh. */
	if (!link_take(0u)) {
		return;
	}
	nonce = s_link.expected_echo_nonce;
	if (nonce == 0u || (now - s_fresh_ms) >= FRESHNESS_MIN_MS) {
		/* Never zero: the link core reads zero as UNARMED, so a draw that
		 * happened to be zero would retire the freshness rule rather than
		 * roll it. */
		do {
			nonce = ((uint64_t)esp_random() << 32) | esp_random();
		} while (nonce == 0u);
		ultrawidelock_link_expect_echo(&s_link, nonce);
		s_fresh_ms = now;
	}
	link_give();

	len = ultrawidelock_link_build_challenge(nonce, frame, sizeof(frame));
	if (len == 0u) {
		return;
	}
	frame[0] = FRESHNESS_MARK;
	tx(frame, len);
}

/** The last channel the lock was heard on; SCAN_CHAN_MIN when never found. */
static uint8_t chan_load(void)
{
	nvs_handle_t h;
	uint8_t ch = SCAN_CHAN_MIN;

	if (nvs_open(SATLINK_NS, NVS_READONLY, &h) != ESP_OK) {
		return ch;
	}
	if (nvs_get_u8(h, SATLINK_CHAN, &ch) != ESP_OK ||
	    ch < SCAN_CHAN_MIN || ch > SCAN_CHAN_MAX) {
		ch = SCAN_CHAN_MIN;
	}
	nvs_close(h);
	return ch;
}

static void chan_save(uint8_t ch)
{
	nvs_handle_t h;

	if (nvs_open(SATLINK_NS, NVS_READWRITE, &h) != ESP_OK) {
		return;
	}
	if (nvs_set_u8(h, SATLINK_CHAN, ch) == ESP_OK) {
		(void)nvs_commit(h);
	}
	nvs_close(h);
}

/** One probe on the current channel, under a fresh nonce. */
static void probe_send(void)
{
	uint8_t frame[ULTRAWIDELOCK_LINK_CHALLENGE_LEN];
	uint64_t n = ((uint64_t)esp_random() << 32) | esp_random();
	size_t len;

	s_probe_hit = false;
	s_probe_nonce = n;
	len = ultrawidelock_link_build_challenge(n, frame, sizeof(frame));
	if (len != 0u) {
		tx(frame, len);
	}
}

/**
 * The satellite's channel hunt, one step per tick (esp_timer task).
 *
 * SCANNING dwells one tick per channel: probe, listen, move on. A reply
 * (checked at the top, so the dwell covers the probe that earned it) parks the
 * hunt. Parked, a heartbeat probe goes out every HEARTBEAT_TICKS; the reply
 * resets the miss count, and HEARTBEAT_MISS_MAX silent ones in a row mean the
 * lock's AP has likely moved -- hunt again, starting from the stored channel.
 */
static void scan_tick(void *arg)
{
	(void)arg;

	if (s_scanning) {
		if (s_probe_hit) {
			s_scanning = false;
			s_chan_found = true;
			s_ticks = 0u;
			s_misses = 0u;
			ESP_LOGI(TAG, "lock found on Wi-Fi channel %u", (unsigned)s_chan);
			if (chan_load() != s_chan) {
				chan_save(s_chan);
			}
			return;
		}
		s_chan = (s_chan >= SCAN_CHAN_MAX) ? SCAN_CHAN_MIN : (uint8_t)(s_chan + 1u);
		if (esp_wifi_set_channel(s_chan, WIFI_SECOND_CHAN_NONE) != ESP_OK) {
			/* Region-forbidden channel; the advance above skips it. */
			return;
		}
		probe_send();
		return;
	}

	s_ticks++;
	if (s_ticks % HEARTBEAT_TICKS != 0u) {
		return;
	}
	if (s_probe_hit) {
		s_misses = 0u;
	} else if (++s_misses >= HEARTBEAT_MISS_MAX) {
		s_scanning = true;
		s_chan_found = false;
		s_chan = chan_load();
		ESP_LOGW(TAG, "lock silent for %u heartbeats; hunting for its channel",
			 (unsigned)HEARTBEAT_MISS_MAX);
		if (esp_wifi_set_channel(s_chan, WIFI_SECOND_CHAN_NONE) == ESP_OK) {
			probe_send();
		}
		return;
	}
	probe_send();
}

/**
 * ESP-NOW receive. Runs on the Wi-Fi task, so it does the least it can: decide
 * and dispatch. The Thread port's equivalent runs on the OpenThread RX thread
 * and is arranged the same way.
 */
static void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len)
{
	struct ultrawidelock_anchor_msg am;
	struct ultrawidelock_join_msg jm;
	enum ultrawidelock_link_rx rx;
	uint8_t shared_challenge[ULTRAWIDELOCK_LINK_CHALLENGE_LEN];
	uint64_t received_challenge = 0u;

	(void)info;
	if (data == NULL || len <= 0) {
		return;
	}

	/* The carrier's own probe answer, read before the shared parser (which
	 * rightly does not know it). Only the satellite hunts, and only the
	 * echo of the nonce it just sent means "the lock heard THIS probe on
	 * THIS channel". */
	if (len == ULTRAWIDELOCK_LINK_CHALLENGE_LEN && data[0] == SCAN_REPLY_MARK &&
	    s_role != ULTRAWIDELOCK_LINK_HANDOFF_ROLE) {
		uint64_t n = 0u;

		for (int i = 0; i < 8; i++) {
			n = (n << 8) | (uint64_t)data[1 + i];
		}
		if (n == s_probe_nonce) {
			s_probe_hit = true;
		}
		return;
	}
	/* A lock-owned freshness beacon is carrier-marked so another lock never
	 * mistakes it for a channel probe. Restore the shared challenge marker
	 * only on a satellite, immediately before the shared parser consumes it. */
	if (len == ULTRAWIDELOCK_LINK_CHALLENGE_LEN && data[0] == FRESHNESS_MARK) {
		if (s_role == ULTRAWIDELOCK_LINK_HANDOFF_ROLE) {
			return;
		}
		memcpy(shared_challenge, data, sizeof(shared_challenge));
		shared_challenge[0] = ULTRAWIDELOCK_WITNESS_MSG_VER;
		data = shared_challenge;
	}

	memset(&am, 0, sizeof(am));
	memset(&jm, 0, sizeof(jm));
	/* Never wait on the high-priority Wi-Fi task. A concurrent key update or
	 * send costs this datagram; absence is the link's fail-permissive state. */
	if (!link_take(0u)) {
		return;
	}
	rx = ultrawidelock_link_consume(&s_link, data, (size_t)len,
					s_report_cb != NULL ? &am : NULL,
					s_join_cb != NULL ? &jm : NULL);
	received_challenge = s_link.tx_echo_nonce;
	link_give();

	switch (rx) {
	case ULTRAWIDELOCK_LINK_RX_REPORT:
		if (s_report_cb != NULL) {
			s_report_cb(am.role, am.peer_mm, am.ranging_block);
		}
		break;
	case ULTRAWIDELOCK_LINK_RX_JOIN:
		if (s_join_cb != NULL) {
			s_join_cb(jm.ursk, jm.rcfg, jm.channel, jm.sync_code_index);
		}
		break;
	case ULTRAWIDELOCK_LINK_RX_REPLAYED:
		/* Logged, because it is the one rejection that means something is
		 * being recorded and re-sent rather than merely misconfigured. */
		ESP_LOGW(TAG, "peer datagram replayed or stale; ignored");
		break;
	case ULTRAWIDELOCK_LINK_RX_UNSEALED:
		ESP_LOGW(TAG, "peer datagram failed the seal; ignored");
		break;
	case ULTRAWIDELOCK_LINK_RX_MALFORMED:
		/* Sealed under our key but the codec refused it: the two ends
		 * disagree about the format, which is a version skew, not an
		 * attack. Worth saying out loud -- both boards need reflashing. */
		ESP_LOGE(TAG, "peer datagram sealed but malformed: wire format skew");
		break;
	case ULTRAWIDELOCK_LINK_RX_CHALLENGE:
		/* A satellite is hunting for our channel; consume() stored its
		 * probe's nonce in s_link.tx_echo_nonce. Answer with the carrier's
		 * reply frame echoing it. Only the lock answers -- a satellite
		 * answering would let two satellites find each other -- and the
		 * answer is deliberately not a challenge frame, or two locks in
		 * radio range would answer each other's answers forever. */
		if (s_role == ULTRAWIDELOCK_LINK_HANDOFF_ROLE) {
			uint8_t reply[ULTRAWIDELOCK_LINK_CHALLENGE_LEN];
			uint64_t n = received_challenge;

			reply[0] = SCAN_REPLY_MARK;
			for (int i = 0; i < 8; i++) {
				reply[1 + i] = (uint8_t)(n >> (56 - 8 * i));
			}
			tx(reply, sizeof(reply));
			/* The echoed probe only proves the channel. This second,
			 * lock-owned nonce is what the next sealed report must echo;
			 * an attacker cannot reset it by replaying an old probe. */
			freshness_challenge_send();
		}
		break;
	case ULTRAWIDELOCK_LINK_RX_IGNORED:
	default:
		break;
	}

	/* jm carried a URSK if anything did. It does not outlive this frame. */
	memset(&jm, 0, sizeof(jm));
	memset(&am, 0, sizeof(am));
}

int ultrawidelock_satlink_init(uint8_t role)
{
	esp_now_peer_info_t peer;
	esp_err_t e;

	if (s_link_mutex == NULL) {
		s_link_mutex = xSemaphoreCreateMutex();
		if (s_link_mutex == NULL) {
			return ESP_ERR_NO_MEM;
		}
	}
	if (!link_take(portMAX_DELAY)) {
		return ESP_ERR_TIMEOUT;
	}
	ultrawidelock_link_init(&s_link, role, esp_random());
	link_give();
	s_role = role;
	key_load();

	e = esp_netif_init();
	if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) {
		return e;
	}
	e = esp_event_loop_create_default();
	if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) {
		return e;
	}
	/*
	 * WHOEVER OWNS THE RADIO KEEPS IT. On the satellite this is the only
	 * user of Wi-Fi and the block below brings it up. On the Matter lock,
	 * Matter has already initialised, configured and started it -- and
	 * forcing STA mode, RAM storage or a restart there would disconnect a
	 * commissioned node to deliver a distance report. ESP-NOW rides whatever
	 * interface is already up, so the right move is to touch nothing.
	 *
	 * esp_wifi_init() cannot say who got here first: ESP-IDF 5.x answers
	 * ESP_OK on a radio someone else already initialised (wifi_init.c,
	 * s_wifi_inited), so this used to take the lock's radio for its own and
	 * moved Matter's Wi-Fi config store into RAM. Ask before initialising
	 * instead: esp_wifi_get_mode() says ESP_ERR_WIFI_NOT_INIT only while
	 * nobody has.
	 */
	wifi_mode_t mode;

	if (esp_wifi_get_mode(&mode) != ESP_ERR_WIFI_NOT_INIT) {
		ESP_LOGI(TAG, "Wi-Fi already up; riding it rather than reconfiguring");
	} else {
		wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

		e = esp_wifi_init(&cfg);
		if (e != ESP_OK) {
			return e;
		}
		/* Ours to configure. Storage in RAM so this leaves no Wi-Fi
		 * credentials in NVS beside the link key, and STA mode without
		 * ever associating: ESP-NOW needs the radio initialised, not a
		 * network. */
		(void)esp_wifi_set_storage(WIFI_STORAGE_RAM);
		(void)esp_wifi_set_mode(WIFI_MODE_STA);
		e = esp_wifi_start();
		if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) {
			return e;
		}
		s_wifi_ours = true;
	}

	e = esp_now_init();
	if (e != ESP_OK) {
		return e;
	}
	e = esp_now_register_recv_cb(on_recv);
	if (e != ESP_OK) {
		return e;
	}

	memset(&peer, 0, sizeof(peer));
	memcpy(peer.peer_addr, BCAST, ESP_NOW_ETH_ALEN);
	peer.channel = 0;  /* whatever channel the interface is on */
	peer.encrypt = false; /* our seal, not ESP-NOW's -- see the file header */
	e = esp_now_add_peer(&peer);
	if (e != ESP_OK && e != ESP_ERR_ESPNOW_EXIST) {
		return e;
	}

	s_up = true;
	if (!ultrawidelock_satlink_ready()) {
		/* Loud on purpose. An anchor that ranges perfectly and reports
		 * nothing is indistinguishable from one that never booted. */
		ESP_LOGW(TAG, "no link key stored: ranging will work, reporting will not");
	} else {
		ESP_LOGI(TAG, "up, role %u", (unsigned)role);
	}

	/*
	 * The channel hunt: satellite only, and only on a radio this file
	 * brought up itself. The lock's channel belongs to its AP, and a radio
	 * someone else owns (Matter's, on the lock) is not ours to retune. The
	 * stored channel is probed first, before the timer's first tick can
	 * advance past it, so a satellite rebooting next to a healthy lock
	 * parks in one dwell instead of a full sweep. Failure to start the
	 * hunt leaves the link on the radio's current channel -- exactly the
	 * pre-hunt behaviour -- and is said aloud rather than returned, because
	 * the sealed link itself is up.
	 */
	if (s_role != ULTRAWIDELOCK_LINK_HANDOFF_ROLE && s_wifi_ours) {
		const esp_timer_create_args_t targs = {
			.callback = scan_tick,
			.name = "satlink_scan",
		};

		s_scanning = true;
		s_chan = chan_load();
		if (esp_wifi_set_channel(s_chan, WIFI_SECOND_CHAN_NONE) == ESP_OK) {
			probe_send();
		}
		if (esp_timer_create(&targs, &s_scan_timer) != ESP_OK ||
		    esp_timer_start_periodic(s_scan_timer, SCAN_TICK_US) != ESP_OK) {
			ESP_LOGW(TAG, "channel hunt not running; staying on channel %u",
				 (unsigned)s_chan);
		}
	}
	return 0;
}

void ultrawidelock_satlink_report(int32_t peer_mm, uint32_t ranging_block)
{
	uint8_t frame[ULTRAWIDELOCK_LINK_MAX_FRAME];
	size_t n;

	if (!s_up || !link_take(pdMS_TO_TICKS(10))) {
		return;
	}
	n = ultrawidelock_link_build_report(&s_link, peer_mm, ranging_block, frame, sizeof(frame));
	link_give();
	if (n != 0u) {
		tx(frame, n);
	}
}

void ultrawidelock_satlink_send_handoff(const uint8_t *ursk, const uint8_t *rcfg, uint8_t channel,
					uint8_t sync_code_index)
{
	uint8_t frame[ULTRAWIDELOCK_LINK_MAX_FRAME];
	size_t n;

	if (!s_up || !link_take(pdMS_TO_TICKS(10))) {
		return;
	}
	n = ultrawidelock_link_build_join(&s_link, ursk, rcfg, channel, sync_code_index, frame,
					  sizeof(frame));
	link_give();
	if (n != 0u) {
		tx(frame, n);
	}
	/* The sealed handoff carries a URSK. Do not leave it on the stack. */
	memset(frame, 0, sizeof(frame));
}

int ultrawidelock_satlink_channel(void)
{
	if (!s_up || s_role == ULTRAWIDELOCK_LINK_HANDOFF_ROLE || !s_wifi_ours) {
		return -1;
	}
	return s_chan_found ? (int)s_chan : 0;
}

void ultrawidelock_satlink_challenge(uint64_t nonce)
{
	uint8_t frame[ULTRAWIDELOCK_LINK_CHALLENGE_LEN];
	size_t n;

	/* Zero is the link core's UNARMED value. Broadcasting it would retire the
	 * freshness rule for every reporter, which is never what a caller asking
	 * to challenge means. */
	if (!s_up || nonce == 0u || !link_take(pdMS_TO_TICKS(10))) {
		return;
	}
	n = ultrawidelock_link_build_challenge(nonce, frame, sizeof(frame));
	if (n != 0u) {
		ultrawidelock_link_expect_echo(&s_link, nonce);
		s_fresh_ms = esp_timer_get_time() / 1000;
		frame[0] = FRESHNESS_MARK;
	}
	link_give();
	if (n != 0u) {
		tx(frame, n);
	}
}
