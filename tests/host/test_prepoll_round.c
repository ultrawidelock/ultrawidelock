/** @file test_prepoll_round.c — one full DS-TWR round through the real
 * listener: genuinely CCM*-encrypted Pre-POLLs are decoded (bootstrap + stride
 * learning + STS warm), the SP3 POLL window is armed off the warm, the POLL
 * result fires the Response TX, TXFRS arms the Final, and the Final_Data
 * decrypt latches a range into fira_session. Frames are built with the same
 * public codec + KDF the initiator side would use, so the decrypt is real. */
#include <string.h>

#include <deca_device_api.h>

#include "cred_kdf.h" /* ULTRAWIDELOCK_URSK_LEN */
#include "ccc_kdf.h"
#include "ccc_mac.h"
#include "ccc_shim.h"
#include "fira_session.h"
#include <ultrawidelock/uwb.h>
#include "test.h"

/* The CCC STS substitution seam entry point (uwb_seam.h). */
extern int32_t ultrawidelock_uwb_arm_rx(int32_t mode);

#define RND_SID  0x11223344u
#define RND_STS0 0x00400000u
#define RND_IDX1 5000u   /* first Pre-POLL's Poll_STS_Index */
#define RND_STRIDE 96u   /* per-block index stride the decode must learn */
#define RND_BLOCK 7u

/* Session crypto constants, derived in setup exactly as prepoll_decode does. */
static uint8_t g_ursk[ULTRAWIDELOCK_URSK_LEN];
static uint8_t g_mupsk1[CCC_MUPSK1_LEN];
static uint8_t g_ks[CCC_KEYSOURCE_LEN];

/* The Aux Security Header carries KeySource in transmission order, which is the
 * byte-reverse of the KeySourceHigh||KeySourceLow layout ccc_uad_addresses()
 * returns (ccc_kdf.c). Copying g_ks in verbatim made both sides of the receiver's
 * context check come from the same helper, so the fixture agreed with itself
 * while a real DWM3001CDK rejected every Pre-POLL and never ranged: observed
 * uad ks=0f3795ed against on-air ks=ed95370f, dest matching. Build the frame the
 * way the radio actually delivers it. */
static void mhr_set_keysource(uint8_t dst[CCC_KEYSOURCE_LEN])
{
	size_t i;

	for (i = 0u; i < CCC_KEYSOURCE_LEN; i++) {
		dst[i] = g_ks[CCC_KEYSOURCE_LEN - 1u - i];
	}
}
static uint8_t g_dest[CCC_DEST_SHORT_ADDR_LEN];
static uint8_t g_src_long[CCC_SRC_LONG_ADDR_LEN];

/** Build an encrypted Pre-POLL frame; returns its on-air length. */
static uint16_t mk_prepoll_for(uint8_t *out, uint32_t fc, uint32_t poll_idx,
			       uint16_t ranging_block)
{
	struct ccc_mhr_fields f;
	struct ccc_pre_poll pp;
	uint8_t plain[CCC_PRE_POLL_LEN];

	memset(&pp, 0, sizeof(pp));
	pp.uwb_session_id = RND_SID;
	pp.poll_sts_index = poll_idx;
	pp.ranging_block = ranging_block;
	ccc_pre_poll_pack(&pp, plain);

	memset(&f, 0, sizeof(f));
	f.dest_short_addr = (uint16_t)(((uint16_t)g_dest[0] << 8) | g_dest[1]);
	f.frame_counter = fc;
	mhr_set_keysource(f.key_source);
	f.msg_id = CCC_MSG_ID_PRE_POLL;
	f.payload_len = CCC_PRE_POLL_LEN;
	T_EQ("mk_pp.mhr", ccc_build_mhr(&f, out), 0);
	T_EQ("mk_pp.enc",
	     ccc_sp0_encrypt(g_mupsk1, g_src_long, fc, out, CCC_MHR_LEN, plain,
			     CCC_PRE_POLL_LEN, &out[CCC_MHR_LEN],
			     &out[CCC_MHR_LEN + CCC_PRE_POLL_LEN]),
	     0);
	return CCC_MHR_LEN + CCC_PRE_POLL_LEN + CCC_SP0_MIC_LEN;
}

static uint16_t mk_prepoll(uint8_t *out, uint32_t fc, uint32_t poll_idx)
{
	return mk_prepoll_for(out, fc, poll_idx, RND_BLOCK);
}

/** One responder record, tag and timestamp given explicitly. */
struct fd_rec {
	uint8_t idx;
	uint32_t ts;
};

/**
 * Build an encrypted Final_Data carrying @p n records, keyed on the armed POLL
 * index, and return the length the DRIVER would report.
 *
 * That return value includes the two FCS bytes. It used to omit them, so every
 * fixture frame was 2 bytes shorter than the hardware reports -- which, with the
 * responder count hardcoded to 1, is why the suite could never reach the
 * 64-byte SP0 stash gate that a 65-byte two-record frame trips. Both halves of
 * that blind spot are closed here.
 */
static uint16_t mk_final_data_n(uint8_t *out, uint32_t fc, uint32_t armed_idx,
				const struct fd_rec *recs, uint8_t n, uint32_t final_tx,
				uint32_t session_id, uint16_t ranging_block,
				uint32_t final_sts_index)
{
	struct ccc_mhr_fields f;
	struct ccc_final_data fd;
	uint8_t plain[CCC_FINAL_DATA_HDR_LEN + (CCC_MAX_RESPONDERS * CCC_RESPONDER_LEN)];
	uint8_t dudsk[CCC_DUDSK_LEN];
	size_t pl = 0;
	uint8_t i;

	memset(&fd, 0, sizeof(fd));
	fd.uwb_session_id = session_id;
	fd.ranging_block = ranging_block;
	fd.final_sts_index = final_sts_index;
	fd.ranging_ts_final_tx = final_tx; /* t5-t1 */
	fd.num_responders = n;
	for (i = 0u; i < n; i++) {
		fd.responders[i].responder_index = recs[i].idx;
		fd.responders[i].timestamp = recs[i].ts; /* t4-t1 */
	}
	T_EQ("mk_fd.pack", ccc_final_data_pack(&fd, plain, sizeof(plain), &pl), 0);

	memset(&f, 0, sizeof(f));
	f.dest_short_addr = (uint16_t)(((uint16_t)g_dest[0] << 8) | g_dest[1]);
	f.frame_counter = fc;
	mhr_set_keysource(f.key_source);
	f.msg_id = CCC_MSG_ID_FINAL_DATA;
	f.payload_len = (uint8_t)pl;
	T_EQ("mk_fd.mhr", ccc_build_mhr(&f, out), 0);
	T_EQ("mk_fd.key", ccc_shim_dudsk_for_index(armed_idx, dudsk), 0);
	T_EQ("mk_fd.enc",
	     ccc_sp0_encrypt(dudsk, g_src_long, fc, out, CCC_MHR_LEN, plain, pl,
			     &out[CCC_MHR_LEN], &out[CCC_MHR_LEN + pl]),
	     0);
	/* Write the FCS the radio appends, so the bytes the stub hands back are
	 * initialised rather than merely counted. */
	out[CCC_MHR_LEN + pl + CCC_SP0_MIC_LEN] = 0xAAu;
	out[CCC_MHR_LEN + pl + CCC_SP0_MIC_LEN + 1u] = 0x55u;
	return (uint16_t)(CCC_MHR_LEN + pl + CCC_SP0_MIC_LEN + 2u);
}

/** Build an encrypted Final_Data (1 responder, tagged 0) keyed on the armed POLL index. */
static uint16_t mk_final_data_for(uint8_t *out, uint32_t fc, uint32_t armed_idx,
				  uint32_t t_round1, uint32_t t_reply2, uint32_t session_id,
				  uint16_t ranging_block, uint32_t final_sts_index)
{
	const struct fd_rec rec = {.idx = 0u, .ts = t_round1};

	return mk_final_data_n(out, fc, armed_idx, &rec, 1u, t_round1 + t_reply2, session_id,
			       ranging_block, final_sts_index);
}

static uint16_t mk_final_data(uint8_t *out, uint32_t fc, uint32_t armed_idx,
			      uint32_t t_round1, uint32_t t_reply2)
{
	return mk_final_data_for(out, fc, armed_idx, t_round1, t_reply2, RND_SID, RND_BLOCK,
				 armed_idx + 2u);
}

/** Load a frame + Ipatov timestamp into the stub, then feed it to try_prepoll. */
static void stash_frame(const uint8_t *frame, uint16_t len, uint64_t ip40)
{
	memcpy(ultrawidelock_host_rx.rxdata, frame, len);
	ultrawidelock_host_rx.rxdata_len = len;
	ultrawidelock_host_rx.rx_ts40 = ip40;
}

/** Fire a captured RX callback the way dwt_isr would. */
static void rx_event(dwt_cb_t cb, uint32_t status)
{
	dwt_cb_data_t d;

	memset(&d, 0, sizeof(d));
	d.status = status;
	d.datalength = ultrawidelock_host_rx.rxdata_len;
	cb(&d);
}

/* Good-frame status: CIA done (timestamp valid) + PHR + CRC good. */
#define ST_GOOD (DWT_INT_CIADONE_BIT_MASK | DWT_INT_RXPHD_BIT_MASK | \
		 DWT_INT_RXFCG_BIT_MASK)
#define ST_CPER 0x10000000u /* STS correlation error (matches the in-tree literal) */

void test_prepoll_round(void)
{
	uint8_t frame[128];
	uint16_t len;
	uint8_t rc[17];
	struct ultrawidelock_uwb_cred_cfg c;
	uint8_t mupsk2[CCC_MUPSK2_LEN], uad[CCC_UAD_LEN];
	const uint32_t widx = RND_IDX1 + 2u * RND_STRIDE; /* warmed POLL index */
	uint32_t fc = 100u;
	int32_t cm = -1;

	t_group("session setup mirrors the initiator's derivations");
	for (size_t i = 0; i < sizeof(g_ursk); i++) {
		g_ursk[i] = (uint8_t)(0xA0u + i);
	}
	for (size_t i = 0; i < sizeof(rc); i++) {
		rc[i] = (uint8_t)i;
	}
	T_EQ("kdf.mupsk1", ccc_derive_mupsk1(g_ursk, g_mupsk1), 0);
	T_EQ("kdf.mupsk2", ccc_derive_mupsk2(g_ursk, mupsk2), 0);
	T_EQ("kdf.uad", ccc_derive_uad(mupsk2, RND_STS0, uad), 0);
	T_EQ("kdf.addr", ccc_uad_addresses(uad, g_ks, g_dest, g_src_long), 0);

	memset(&c, 0, sizeof(c));
	c.session_id = RND_SID;
	c.channel = 9u;
	c.sync_code_index = 9u;
	c.slot_per_round = 12u;
	c.sts_index0 = RND_STS0;
	c.ursk = g_ursk;
	c.ranging_config = rc;
	c.rc_len = sizeof(rc);
	ultrawidelock_host_rx_reset();
	T_EQ("start", ultrawidelock_uwb_start_cred(&c), 0);
	T_EQ("start.armed", ultrawidelock_host_rx.rxenable_calls, 1);

	t_group("STS substitution wrap programs a key while bound");
	T_EQ("wrap.rxenable", ultrawidelock_uwb_arm_rx(DWT_START_RX_IMMEDIATE),
	     DWT_SUCCESS);

	t_group("bootstrap: two Pre-POLL decodes learn index + stride");
	len = mk_prepoll(frame, fc++, RND_IDX1);
	stash_frame(frame, len, 0x1000000ull);
	ccc_shim_rx_try_prepoll(len); /* inline decode #1 — index, no stride */
	len = mk_prepoll(frame, fc++, RND_IDX1 + RND_STRIDE);
	stash_frame(frame, len, 0x2000000ull);
	ccc_shim_rx_try_prepoll(len); /* inline decode #2 — stride, warms widx */

	t_group("Pre-POLL event arms the SP3 POLL window off the warm");
	T_OK("prearm.not_awaiting", !ccc_shim_rx_awaiting_poll());
	stash_frame(frame, len, 0x3000000ull); /* MHR re-read by the callback */
	rx_event(ultrawidelock_host_rx.cbs.cbRxOk, ST_GOOD);
	T_OK("arm.awaiting_poll", ccc_shim_rx_awaiting_poll());
	T_EQ("arm.delayed", ultrawidelock_host_rx.last_rxenable_mode,
	     DWT_START_RX_DELAYED | DWT_IDLE_ON_DLY_ERR);
	/* Next block's Pre-POLL arrives while armed: stash + defer its decode. */
	len = mk_prepoll(frame, fc++, RND_IDX1 + 2u * RND_STRIDE);
	stash_frame(frame, len, 0x3100000ull);
	ccc_shim_rx_try_prepoll(len);

	t_group("POLL result (cper=0) fires the delayed Response TX");
	ultrawidelock_host_rx.rx_ts40 = 0x40000000ull;            /* t2: POLL RX */
	rx_event(ultrawidelock_host_rx.cbs.cbRxOk, DWT_INT_CIADONE_BIT_MASK);
	T_EQ("poll.resp_tx", ultrawidelock_host_rx.starttx_calls, 1);
	T_OK("poll.await_cleared", !ccc_shim_rx_awaiting_poll());

	t_group("TXFRS arms the Final window and flushes the deferred decode");
	ultrawidelock_host_rx.tx_ts40 = 0x40000000ull + 100000u;  /* t3 = t2 + 100k DTU */
	rx_event(ultrawidelock_host_rx.cbs.cbTxDone, DWT_INT_TXFRS_BIT_MASK);
	T_EQ("final.armed", ultrawidelock_host_rx.last_rxenable_mode,
	     DWT_START_RX_DELAYED | DWT_IDLE_ON_DLY_ERR);

	t_group("Final result stashes the STS verdict, reverts to SP0");
	ultrawidelock_host_rx.rx_ts40 = 0x40000000ull + 300000u;  /* t6 = t3 + 200k DTU */
	ultrawidelock_host_rx.stsq_ret = 0;
	ultrawidelock_host_rx.stsq_val = 100;
	rx_event(ultrawidelock_host_rx.cbs.cbRxOk, DWT_INT_CIADONE_BIT_MASK);
	T_EQ("final.sp0", ultrawidelock_host_rx.last_rxenable_mode, DWT_START_RX_IMMEDIATE);

	/* Advance the live Pre-POLL context before Final_Data is dispatched. The
	 * accepted Final must remain bound to its capture-time block rather than
	 * mutable globals from later blocks. The second call flushes the first;
	 * the pending second one is flushed when Final_Data enters. */
	len = mk_prepoll_for(frame, fc++, RND_IDX1 + 3u * RND_STRIDE, RND_BLOCK + 1u);
	stash_frame(frame, len, 0x3110000ull);
	ccc_shim_rx_try_prepoll(len);
	len = mk_prepoll_for(frame, fc++, RND_IDX1 + 4u * RND_STRIDE, RND_BLOCK + 2u);
	stash_frame(frame, len, 0x3120000ull);
	ccc_shim_rx_try_prepoll(len);

	t_group("Final_Data decrypt latches the DS-TWR range");
	/* reply1=100k, round2=200k (injected above); round1=101k, reply2=199k
	 * => tof = (101k*200k - 100k*199k) / 600k = 500 ticks = 234 cm. */
	len = mk_final_data_for(frame, fc++, widx, 101000u, 199000u, RND_SID ^ 1u,
				RND_BLOCK, widx + 2u);
	stash_frame(frame, len, 0x3180000ull);
	ccc_shim_rx_try_prepoll(len);
	T_OK("wrong-session Final_Data rejected", !fira_session_last_range(&cm, NULL, NULL, NULL, NULL));

	len = mk_final_data(frame, fc++, widx, 101000u, 199000u);
	stash_frame(frame, len, 0x3200000ull);
	ccc_shim_rx_try_prepoll(len); /* Final_Data decodes inline */
	T_OK("range.latched", fira_session_last_range(&cm, NULL, NULL, NULL, NULL));
	T_EQ("range.cm", cm, 234);
	{
		/* The post-mortem tallies: every step of this round happened once,
		 * off the five Pre-POLLs this fixture accepted on the way to its
		 * arm (bootstrap, stride, and the warm-index walk above), and the
		 * wrong-session Final_Data still counted as a decode attempt. */
		struct ccc_shim_rx_stats st;

		ccc_shim_rx_stats_get(&st);
		T_EQ("stats.prepoll_ok", st.prepoll_ok, 5);
		T_EQ("stats.poll_arm", st.poll_arm, 1);
		T_EQ("stats.poll_ok", st.poll_ok, 1);
		T_EQ("stats.poll_fail", st.poll_fail, 0);
		T_EQ("stats.resp_tx", st.resp_tx, 1);
		T_EQ("stats.final_data", st.final_data, 2);
		T_EQ("stats.range", st.range, 1);
	}
	{
		uint32_t generation = fira_session_range_generation();

		stash_frame(frame, len, 0x3210000ull);
		ccc_shim_rx_try_prepoll(len);
		T_EQ("replayed Final_Data cannot relatch", (long)fira_session_range_generation(),
		     (long)generation);
	}

	t_group("two-record Final_Data survives the SP0 gate and selects by tag");
	/*
	 * The whole path in one frame: try_prepoll -> the stash size gate ->
	 * final_data_decode -> record select -> the DS-TWR latch. Two things are
	 * being defended at once, both of which shipped broken:
	 *
	 *   size  a two-record frame is 65 bytes on air against a stash that was
	 *         64, so it was discarded before the decode ran and the initiator
	 *         got blamed for not sending it;
	 *   order the records are laid out tagged {1, 0}, so ARRAY POSITION and
	 *         TAG disagree. This build is responder 0, so a correct lookup
	 *         reads the tag-0 record (101000) and lands on the same 234 cm as
	 *         the single-record case above; position indexing would read
	 *         150000 and be off by kilometres.
	 */
	{
		const struct fd_rec recs[2] = {
			{.idx = 1u, .ts = 150000u}, /* the satellite's, first in the array */
			{.idx = 0u, .ts = 101000u}, /* ours, second */
		};

		len = mk_final_data_n(frame, fc++, widx, recs, 2u, 300000u, RND_SID, RND_BLOCK,
				      widx + 2u);
		T_EQ("two-record frame is 65 bytes on air", (long)len, 65L);

		stash_frame(frame, len, 0x3220000ull);
		ccc_shim_rx_try_prepoll(len);
		T_OK("two-record range latched", fira_session_last_range(&cm, NULL, NULL, NULL, NULL));
		T_EQ("two-record range picks the tag-0 record", cm, 234);
	}

	t_group("round 2: POLL result with STS error reverts and reflushes");
	stash_frame(frame, len, 0x4000000ull);
	len = mk_prepoll(frame, fc++, RND_IDX1 + 5u * RND_STRIDE);
	stash_frame(frame, len, 0x4000000ull);
	rx_event(ultrawidelock_host_rx.cbs.cbRxOk, ST_GOOD);    /* re-arm off decode #3's warm */
	T_OK("arm2.awaiting", ccc_shim_rx_awaiting_poll());
	len = mk_prepoll(frame, fc++, RND_IDX1 + 6u * RND_STRIDE);
	stash_frame(frame, len, 0x4100000ull);
	ccc_shim_rx_try_prepoll(len);                 /* pending decode #4 */
	rx_event(ultrawidelock_host_rx.cbs.cbRxOk, DWT_INT_CIADONE_BIT_MASK | ST_CPER);
	T_OK("poll2.no_tx", ultrawidelock_host_rx.starttx_calls == 1); /* no new Response */
	T_EQ("poll2.sp0", ultrawidelock_host_rx.last_rxenable_mode, DWT_START_RX_IMMEDIATE);

	t_group("a refused delayed arm falls back to the SP0 listen");
	stash_frame(frame, len, 0x5000000ull);
	ultrawidelock_host_rx.rxenable_ret = DWT_ERROR;
	rx_event(ultrawidelock_host_rx.cbs.cbRxOk, ST_GOOD);    /* arm fails -> ARM FAIL path */
	T_OK("armfail.not_awaiting", !ccc_shim_rx_awaiting_poll());
	ultrawidelock_host_rx.rxenable_ret = DWT_SUCCESS;

	t_group("notify_rx is a quiet no-op without the lock-sweep diagnostic");
	ccc_shim_rx_notify_rx(0x10000000u);
	T_OK("notify_rx.survived", 1);

	t_group("restart: a Pre-POLL event with no warm cannot arm SP3");
	ultrawidelock_uwb_stop();
	T_EQ("restart", ultrawidelock_uwb_start_cred(&c), 0); /* log_reset clears the warm */
	len = mk_prepoll(frame, fc++, RND_IDX1);
	stash_frame(frame, len, 0x6000000ull);
	rx_event(ultrawidelock_host_rx.cbs.cbRxOk, ST_GOOD);    /* arm_poll_sp3 -> no warm */
	T_OK("nowarm.not_awaiting", !ccc_shim_rx_awaiting_poll());

	t_group("prepoll decode rejects every malformed frame class");
	/* Too short to hold a Pre-POLL (routing header parses, decode bails). */
	len = mk_prepoll(frame, fc++, RND_IDX1);
	stash_frame(frame, len, 0x6100000ull);
	ccc_shim_rx_try_prepoll((uint16_t)(CCC_MHR_LEN + 2u));
	/* Corrupted frame control: the MHR parse fails. */
	len = mk_prepoll(frame, fc++, RND_IDX1);
	frame[0] ^= 0xFFu;
	stash_frame(frame, len, 0x6200000ull);
	ccc_shim_rx_try_prepoll(len);
	/* Valid MHR carrying a message id that is neither Pre-POLL nor Final. */
	{
		struct ccc_mhr_fields f;

		memset(&f, 0, sizeof(f));
		f.dest_short_addr = (uint16_t)(((uint16_t)g_dest[0] << 8) | g_dest[1]);
		f.frame_counter = fc++;
		mhr_set_keysource(f.key_source);
		f.msg_id = 0x07u;
		f.payload_len = CCC_PRE_POLL_LEN;
		memset(frame, 0, sizeof(frame));
		T_EQ("mk_odd.mhr", ccc_build_mhr(&f, frame), 0);
		len = CCC_MHR_LEN + CCC_PRE_POLL_LEN + CCC_SP0_MIC_LEN;
		stash_frame(frame, len, 0x6300000ull);
		ccc_shim_rx_try_prepoll(len);
		/* Pre-POLL id with a wrong payload length in the MHR. */
		f.msg_id = CCC_MSG_ID_PRE_POLL;
		f.payload_len = CCC_PRE_POLL_LEN - 1u;
		T_EQ("mk_badlen.mhr", ccc_build_mhr(&f, frame), 0);
		stash_frame(frame, len, 0x6400000ull);
		ccc_shim_rx_try_prepoll(len);
	}
	/* No URSK provisioned: the decode stops before any derivation. */
	fira_session_set_provisioned_ursk(NULL);
	len = mk_prepoll(frame, fc++, RND_IDX1);
	stash_frame(frame, len, 0x6500000ull);
	ccc_shim_rx_try_prepoll(len);
	fira_session_set_provisioned_ursk(g_ursk);
	/* Genuine Pre-POLL with a flipped MIC byte: the CCM* decrypt fails. */
	len = mk_prepoll(frame, fc++, RND_IDX1);
	frame[len - 1u] ^= 0x01u;
	stash_frame(frame, len, 0x6600000ull);
	ccc_shim_rx_try_prepoll(len);
	T_OK("badframes.no_warm", !ccc_shim_rx_awaiting_poll());

	t_group("Final_Data decode rejects malformed frames");
	/* Payload length beyond the decode's plaintext scratch. */
	{
		struct ccc_mhr_fields f;

		memset(&f, 0, sizeof(f));
		f.dest_short_addr = (uint16_t)(((uint16_t)g_dest[0] << 8) | g_dest[1]);
		f.frame_counter = fc++;
		mhr_set_keysource(f.key_source);
		f.msg_id = CCC_MSG_ID_FINAL_DATA;
		f.payload_len = 100u;
		memset(frame, 0, sizeof(frame));
		T_EQ("mk_fdbig.mhr", ccc_build_mhr(&f, frame), 0);
		stash_frame(frame, 40u, 0x6700000ull);
		ccc_shim_rx_try_prepoll(40u);
	}
	/* Flipped MIC byte: the dUDSK decrypt fails. */
	len = mk_final_data(frame, fc++, 0u, 101000u, 199000u);
	frame[len - 1u] ^= 0x01u;
	stash_frame(frame, len, 0x6800000ull);
	ccc_shim_rx_try_prepoll(len);
	/* Valid decrypt of an 18-byte all-zero header: zero responders reported. */
	{
		struct ccc_mhr_fields f;
		uint8_t plain[18];
		uint8_t dudsk[CCC_DUDSK_LEN];

		memset(plain, 0, sizeof(plain));
		memset(&f, 0, sizeof(f));
		f.dest_short_addr = (uint16_t)(((uint16_t)g_dest[0] << 8) | g_dest[1]);
		f.frame_counter = fc;
		mhr_set_keysource(f.key_source);
		f.msg_id = CCC_MSG_ID_FINAL_DATA;
		f.payload_len = sizeof(plain);
		T_EQ("mk_fd0.mhr", ccc_build_mhr(&f, frame), 0);
		T_EQ("mk_fd0.key", ccc_shim_dudsk_for_index(0u, dudsk), 0);
		T_EQ("mk_fd0.enc",
		     ccc_sp0_encrypt(dudsk, g_src_long, fc, frame, CCC_MHR_LEN, plain,
				     sizeof(plain), &frame[CCC_MHR_LEN],
				     &frame[CCC_MHR_LEN + sizeof(plain)]),
		     0);
		fc++;
		len = CCC_MHR_LEN + sizeof(plain) + CCC_SP0_MIC_LEN;
		stash_frame(frame, len, 0x6900000ull);
		ccc_shim_rx_try_prepoll(len);
	}
	T_OK("badfinal.survived", 1);

	t_group("an orphaned pending decode is flushed by the next Pre-POLL");
	len = mk_prepoll(frame, fc++, RND_IDX1);
	stash_frame(frame, len, 0x7000000ull);
	ccc_shim_rx_try_prepoll(len); /* bootstrap decode #1 — index only */
	len = mk_prepoll(frame, fc++, RND_IDX1 + RND_STRIDE);
	stash_frame(frame, len, 0x7100000ull);
	ccc_shim_rx_try_prepoll(len); /* decode #2 — stride learned, warm valid */
	len = mk_prepoll(frame, fc++, RND_IDX1 + 2u * RND_STRIDE);
	stash_frame(frame, len, 0x7200000ull);
	ccc_shim_rx_try_prepoll(len); /* steady state: deferred (pending) */
	len = mk_prepoll(frame, fc++, RND_IDX1 + 3u * RND_STRIDE);
	stash_frame(frame, len, 0x7300000ull);
	ccc_shim_rx_try_prepoll(len); /* missed POLL: flushes the orphan first */
	T_OK("flush.survived", 1);

	t_group("try_prepoll is gated once the listener is stopped");
	ultrawidelock_uwb_stop();
	ccc_shim_rx_try_prepoll(len);
	T_OK("stopped.not_awaiting", !ccc_shim_rx_awaiting_poll());
	{
		/* The stop printed the session's post-mortem and zeroed it, so the
		 * stop-before-start of the next session has nothing to report. */
		struct ccc_shim_rx_stats st;

		ccc_shim_rx_stats_get(&st);
		T_EQ("stats.zeroed_by_stop", st.prepoll_ok + st.poll_arm + st.range, 0);
	}
}
