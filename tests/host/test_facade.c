/** @file test_facade.c — ultrawidelock_uwb_facade: bind/start/stop + range readback. */
#include <errno.h>
#include <string.h>

#include "cred_kdf.h" /* ULTRAWIDELOCK_URSK_LEN */
#include "ccc_shim.h"
#include "fira_session.h"
#include <ultrawidelock/uwb.h>
#include "test.h"

static int s_facade_listener_hits;

static void facade_range_listener(void)
{
	s_facade_listener_hits++;
}

void test_facade(void)
{
	uint8_t ursk[ULTRAWIDELOCK_URSK_LEN];
	uint8_t rc[17];
	struct ultrawidelock_uwb_cred_cfg c;
	int32_t cm = -1;

	for (size_t i = 0; i < sizeof(ursk); i++) {
		ursk[i] = (uint8_t)(i + 1u);
	}
	for (size_t i = 0; i < sizeof(rc); i++) {
		rc[i] = (uint8_t)i;
	}

	t_group("prewarm applies the session PHY with the radio left off");
	T_EQ("prewarm.ok", ultrawidelock_uwb_prewarm(9u, 9u), 0);

	t_group("range-listener seam registers and clears");
	s_facade_listener_hits = 0;
	ultrawidelock_uwb_set_range_listener(facade_range_listener);
	fira_session_set_ccc_range_cm(140, 1u); /* accepted latch -> callback */
	T_EQ("listener.fired", s_facade_listener_hits, 1);
	ultrawidelock_uwb_set_range_listener(NULL);
	fira_session_set_ccc_range_cm(141, 2u);
	T_EQ("listener.cleared", s_facade_listener_hits, 1);

	t_group("bind_ursk binds the CCC shim");
	T_OK("shim.unbound.before", !ccc_shim_active());
	T_EQ("bind.ok", ultrawidelock_uwb_bind_ursk(ursk, sizeof(ursk)), 0);
	T_OK("shim.bound.after", ccc_shim_active());

	t_group("start_ultrawidelock rejects null cfg / null ursk");
	T_EQ("start.null", ultrawidelock_uwb_start_cred(NULL), -EINVAL);
	memset(&c, 0, sizeof(c));
	c.ursk = NULL;
	T_EQ("start.null.ursk", ultrawidelock_uwb_start_cred(&c), -EINVAL);

	t_group("start_ultrawidelock with a serialized RangingConfiguration");
	memset(&c, 0, sizeof(c));
	c.session_id = 0x11223344u;
	c.channel = 5u;
	c.sync_code_index = 9u;
	c.slot_duration_rstu = 1200u;
	c.block_duration_ms = 768u;
	c.slot_per_round = 6u;
	c.sts_index0 = 0x1000u;
	c.uwb_time_us = 0u;
	c.ursk = ursk;
	c.ranging_config = rc;
	c.rc_len = sizeof(rc);
	uint32_t start_gen = ultrawidelock_uwb_start_generation();

	T_EQ("start.rc", ultrawidelock_uwb_start_cred(&c), 0);
	T_OK("shim.active.rc", ccc_shim_active());
	T_EQ("start.generation.advanced", ultrawidelock_uwb_start_generation(), start_gen + 1u);

	t_group("start_ultrawidelock URSK fallback (no ranging_config, slot_per_round 0)");
	c.ranging_config = NULL;
	c.rc_len = 0u;
	c.slot_per_round = 0u;
	T_EQ("start.fallback", ultrawidelock_uwb_start_cred(&c), 0);

	t_group("stop unbinds the shim");
	ultrawidelock_uwb_stop();
	T_OK("shim.unbound", !ccc_shim_active());

	t_group("last_range_cm reflects the fira range store");
	fira_session_set_ccc_range_cm(150, 3u);
	T_OK("range.present", ultrawidelock_uwb_last_range_cm(&cm));
	T_EQ("range.cm", cm, 150);

	t_group("trusted_range_cm gates the unlock seam on layer-4 consensus");
	/* Four agreeing blocks saturate trust at K regardless of prior state. */
	fira_session_set_ccc_range_cm(150, 4u);
	fira_session_set_ccc_range_cm(150, 5u);
	fira_session_set_ccc_range_cm(150, 6u);
	fira_session_set_ccc_range_cm(150, 7u);
	cm = -1;
	T_OK("trusted.present", ultrawidelock_uwb_trusted_range_cm(&cm));
	T_EQ("trusted.cm", cm, 150);
	uint32_t range_checkpoint = ultrawidelock_uwb_range_generation();
	T_OK("trusted.old_generation_refused",
	     !ultrawidelock_uwb_trusted_range_after_cm(&cm, range_checkpoint));
	fira_session_set_ccc_range_cm(150, 8u);
	T_OK("trusted.new_generation_accepted",
	     ultrawidelock_uwb_trusted_range_after_cm(&cm, range_checkpoint));
	/* A spoofed (implausible) block clears trust and does not latch: the raw
	 * accessor still returns the last good range, but the trusted accessor
	 * (what the unlock seam uses) refuses it. */
	fira_session_set_ccc_range_cm(-400, 9u);
	cm = -1;
	T_OK("spoof.raw.kept", ultrawidelock_uwb_last_range_cm(&cm));
	T_EQ("spoof.raw.cm", cm, 150);
	T_OK("spoof.trusted.refused", !ultrawidelock_uwb_trusted_range_cm(&cm));

	t_group("trusted_range_age_cm carries the age, and gates the same way");
	/* Presence needs to know a range is CURRENT, not merely the most recent one
	 * ever seen: a distance from two minutes ago says nothing about who is here
	 * now. Polling this is what lets presence skip the single range-listener
	 * slot, which the lock's approach loop already owns. */
	int64_t age_ms = -1;

	fira_session_set_ccc_range_cm(150, 10u);
	fira_session_set_ccc_range_cm(150, 11u);
	fira_session_set_ccc_range_cm(150, 12u);
	fira_session_set_ccc_range_cm(150, 13u);
	cm = -1;
	T_OK("age.present", ultrawidelock_uwb_trusted_range_age_cm(&cm, &age_ms));
	T_EQ("age.cm", cm, 150);
	T_OK("age.nonneg", age_ms >= 0);
	/* A NULL age must behave exactly as the older accessor, since that one is
	 * now implemented by delegating here. */
	cm = -1;
	T_OK("age.null.ok", ultrawidelock_uwb_trusted_range_age_cm(&cm, NULL));
	T_EQ("age.null.cm", cm, 150);
	/* The trust gate applies identically: an untrusted range must not surface a
	 * distance just because the caller also asked for its age. */
	fira_session_set_ccc_range_cm(-400, 14u);
	T_OK("age.spoof.refused", !ultrawidelock_uwb_trusted_range_age_cm(&cm, &age_ms));

	t_group("last_range_age_cm carries the age without the trust gate");
	/* The bench "range" command reads the raw store, which keeps the last
	 * distance until the next session clears it: the age is what separates a
	 * live reading from one a departed peer left behind. */
	fira_session_set_ccc_range_cm(150, 15u);
	cm = -1;
	age_ms = -1;
	T_OK("rawage.present", ultrawidelock_uwb_last_range_age_cm(&cm, &age_ms));
	T_EQ("rawage.cm", cm, 150);
	T_OK("rawage.nonneg", age_ms >= 0);
	cm = -1;
	T_OK("rawage.null.ok", ultrawidelock_uwb_last_range_age_cm(&cm, NULL));
	T_EQ("rawage.null.cm", cm, 150);
	/* Raw, not trusted: after an implausible block the last good range is
	 * still handed out here, exactly as ultrawidelock_uwb_last_range_cm() does,
	 * while the trusted accessor refuses it. */
	fira_session_set_ccc_range_cm(-400, 16u);
	T_OK("rawage.spoof.kept", ultrawidelock_uwb_last_range_age_cm(&cm, &age_ms));
	T_EQ("rawage.spoof.cm", cm, 150);
	T_OK("rawage.spoof.untrusted", !ultrawidelock_uwb_trusted_range_age_cm(&cm, &age_ms));

	/* Leave the fira store cleared for any later reader. */
	fira_session_set_provisioned_ursk(NULL);
}
