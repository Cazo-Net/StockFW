#!/bin/bash
# P4 -- Detection validation: a repeatable adversarial suite run against
# the engine.  Named attack and benign corpora replayed through
# fs_copilot_feed_event_full() with exact clocks: port scans, suspicious
# outbound patterns, benign developer tools, the 2026-10-10 false-positive
# replay, and rule rollback under a failed apply.
#
#   ./tests/test-adversarial.sh
#
# Pure core (fs-copilot, fs-apply), so it runs without a display.

set -e

if [ -d /ucrt64/bin ]; then
  export PATH="/ucrt64/bin:$PATH"
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"

cd "$PORT"

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

cat > "$BUILD_DIR/test-adversarial.c" <<'EOF'
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include "core/fs-rules.h"
#include "core/fs-copilot.h"
#include "core/fs-apply.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	if (!(cond)) {                                             \
		printf ("FAIL: ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
		failures++;                                         \
	} else {                                                  \
		printf ("ok:   ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
	}                                                         \
} while (0)

/* =====================================================================
 * Harness: exact clocks.  Monotonic base and unix base are fixed, and
 * A_T0_UNIX sits mid-hour on an exact-hour offset so no scenario can
 * trip the novel-hour signal by accident of wall-clock placement.
 * ===================================================================== */

#define A_T0_US    ((gint64) 600000 * G_USEC_PER_SEC)
#define A_T0_UNIX  ((gint64) 1760000000)   /* 53:20 into its local hour */

static void
feed (FsCopilot *c, FsHit *hit, gint64 sec)
{
	fs_copilot_feed_event_full (c, hit,
	                            A_T0_US + sec * G_USEC_PER_SEC,
	                            A_T0_UNIX + sec);
}

static guint
count_insights (FsCopilot *copilot, FsInsightType type)
{
	GList *insights = fs_copilot_get_insights (copilot);
	GList *l;
	guint n = 0;

	for (l = insights; l != NULL; l = l->next) {
		FsInsight *ins = l->data;

		if (ins->type == type)
			n++;
	}

	g_list_free (insights);
	return n;
}

static const FsInsight *
find_insight (FsCopilot *copilot, FsInsightType type)
{
	GList *insights = fs_copilot_get_insights (copilot);
	GList *l;
	const FsInsight *hit_insight = NULL;

	for (l = insights; l != NULL; l = l->next) {
		FsInsight *ins = l->data;

		if (ins->type == type) {
			hit_insight = ins;
			break;
		}
	}

	g_list_free (insights);
	return hit_insight;
}

/* The auto-pass's own gate order (ui/fs-copilot.c): auto_applicable
 * first, then the is_auto_safe choke point.  "Would stage" is exactly
 * what the UI is allowed to put on the wire without a human. */
static guint
would_stage (FsCopilot *copilot)
{
	GList *insights = fs_copilot_get_insights (copilot);
	GList *l;
	guint n = 0;

	for (l = insights; l != NULL; l = l->next) {
		FsInsight *ins = l->data;

		if (ins->auto_applicable && fs_insight_is_auto_safe (ins))
			n++;
	}

	g_list_free (insights);
	return n;
}

static FsHit *
base_hit (const gchar *service)
{
	FsHit *hit = g_new0 (FsHit, 1);

	hit->direction = (gchar *) "Out";
	hit->source    = (gchar *) "192.168.1.7";
	hit->protocol  = (gchar *) "TCP";
	hit->service   = (gchar *) service;

	return hit;
}

/* =====================================================================
 * 1. Port scan by a rogue agent: refused connections fanning out to
 *    many distinct hosts.  Blocked fan-out is the strongest scan
 *    signal, and it must stay report-only -- a scan report carries no
 *    rule, because "block the scanner" is what the firewall already
 *    did.
 * ===================================================================== */

static void
test_scan_blocked_fanout (void)
{
	FsCopilot *c = fs_copilot_new ();
	FsHit *hit = base_hit ("scanner [BLOCKED]");
	const FsInsight *ins;
	gchar dest[32];
	gint i;

	for (i = 0; i < 12; i++) {
		g_snprintf (dest, sizeof dest, "198.51.100.%d", i + 1);
		hit->destination = dest;
		hit->port = (i % 2) ? "22" : "445";
		feed (c, hit, 5 * i);
	}

	CHECK (count_insights (c, FS_INSIGHT_FANOUT) == 1,
	       "scan: 12 refused hosts inside the window report one fan-out");
	ins = find_insight (c, FS_INSIGHT_FANOUT);
	CHECK (ins != NULL && ins->severity == FS_COPILOT_CRITICAL,
	       "scan: the fan-out report is CRITICAL");
	CHECK (ins != NULL && ins->rule_csv == NULL &&
	       !ins->auto_applicable,
	       "scan: fan-out carries no rule -- nothing to auto-stage from it");

	/* More of the same INSIDE the window must not double-report --
	 * the threshold is met again, and the episode flag says no. */
	for (i = 12; i < 18; i++) {
		g_snprintf (dest, sizeof dest, "198.51.100.%d", i + 1);
		hit->destination = dest;
		feed (c, hit, 4 * i);
	}
	CHECK (count_insights (c, FS_INSIGHT_FANOUT) == 1,
	       "scan: one report per window, not one per host");
	CHECK (would_stage (c) == 0,
	       "scan: a fan-out episode stages nothing");

	fs_copilot_free (c);
	g_free (hit);

	/* The same scan arriving FROM outside: egress is Sentinel's job,
	 * inbound events are not scored. */
	c = fs_copilot_new ();
	hit = base_hit ("unknown [BLOCKED]");
	hit->direction = (gchar *) "In";
	for (i = 0; i < 12; i++) {
		g_snprintf (dest, sizeof dest, "198.51.100.%d", i + 1);
		hit->destination = dest;
		feed (c, hit, 5 * i);
	}
	CHECK (count_insights (c, FS_INSIGHT_FANOUT) == 0,
	       "scan: the same pattern inbound raises nothing (egress only)");

	fs_copilot_free (c);
	g_free (hit);
}

/* =====================================================================
 * 2. Single-host port sweep: one host, many ports.  Fan-out counts
 *    distinct hosts by design, so the sweep surfaces where it honestly
 *    belongs -- the behavior layer's first-use-of-port findings, whose
 *    suggestion is an allow, and an allow is never auto-safe.
 * ===================================================================== */

static void
test_port_sweep_single_host (void)
{
	FsCopilot *c = fs_copilot_new ();
	FsHit *hit = base_hit ("sweeper.exe");
	const FsInsight *ins;
	static const gint learn_gaps[] =
		{ 13, 7, 19, 4, 11, 25, 6, 14, 9, 22, 8 };
	gchar port[16];
	gint64 t = 0;
	gint i;

	hit->destination = (gchar *) "203.0.113.50";

	/* Baseline: twelve connections on the usual port, at human-ish
	 * cadence -- an exact-interval "baseline" would itself be a
	 * beacon, and the engine correctly says so. */
	hit->port = (gchar *) "443";
	for (i = 0; i < 12; i++) {
		feed (c, hit, t);
		t += learn_gaps[i % G_N_ELEMENTS (learn_gaps)];
	}

	/* The sweep: forty never-before-seen ports of the SAME host. */
	for (i = 0; i < 40; i++) {
		g_snprintf (port, sizeof port, "%d", 1024 + i);
		hit->port = port;
		feed (c, hit, 200 + i);
	}

	CHECK (count_insights (c, FS_INSIGHT_UNUSUAL_PORT) >= 1,
	       "sweep: novel ports surface as first-use-of-port findings");
	CHECK (count_insights (c, FS_INSIGHT_FANOUT) == 0,
	       "sweep: one host is not a fan-out (fan-out counts hosts)");

	ins = find_insight (c, FS_INSIGHT_UNUSUAL_PORT);
	CHECK (ins != NULL && ins->suggested_rule != NULL &&
	       strstr (ins->suggested_rule, "Allow") != NULL,
	       "sweep: the finding suggests an allow, honestly -- no deny is invented");
	CHECK (ins != NULL && !fs_insight_is_auto_safe (ins),
	       "sweep: an allow-shaped suggestion is never auto-safe");
	CHECK (would_stage (c) == 0,
	       "sweep: nothing a port sweep produces would stage itself");

	fs_copilot_free (c);
	g_free (hit);
}

/* =====================================================================
 * 3. The case that MUST fire: a metronomic C2 beacon to a public
 *    stranger with no recorded history.  The P6 gates must not blind
 *    Sentinel to the real thing.
 * ===================================================================== */

static void
test_beacon_c2_fires (void)
{
	FsCopilot *c = fs_copilot_new ();
	FsHit *hit = base_hit ("update-checker.exe");
	const FsInsight *ins;
	FsPolicy *policy;
	FsRule *probe;
	gint i;

	hit->destination = (gchar *) "198.51.100.9";
	hit->port = (gchar *) "8443";

	for (i = 0; i < 6; i++)
		feed (c, hit, (gint64) i * 60);

	CHECK (count_insights (c, FS_INSIGHT_BEACON) == 1,
	       "beacon: the real C2 check-in loop is caught");
	ins = find_insight (c, FS_INSIGHT_BEACON);
	CHECK (ins != NULL && ins->severity == FS_COPILOT_CRITICAL,
	       "beacon: the C2 report is CRITICAL");
	CHECK (ins != NULL && ins->auto_applicable &&
	       fs_insight_is_auto_safe (ins),
	       "beacon: a public stranger with no baseline stays stageable");
	CHECK (would_stage (c) == 1,
	       "beacon: exactly one insight would stage");

	/* And it stages a real deny, not a suggestion-shaped word. */
	policy = fs_policy_new ();
	CHECK (ins != NULL && fs_insight_apply (ins, policy),
	       "beacon: the deny rule applies into the policy");
	probe = ins != NULL ? fs_insight_to_rule (ins) : NULL;
	CHECK (probe != NULL && fs_policy_contains (policy, probe),
	       "beacon: the staged rule is the deny the detector built");
	fs_rule_free (probe);
	fs_policy_free (policy);

	fs_copilot_free (c);
	g_free (hit);
}

/* =====================================================================
 * 4. The 2026-10-10 incident replay: the exact false-positive corpus,
 *    metronomic, as it arrived those two days.  The timing detector may
 *    fire -- timing is timing -- but nothing from this corpus may ever
 *    reach the wire without a human.
 * ===================================================================== */

static void
test_incident_replay_no_outage (void)
{
	static const struct {
		const gchar *dest;
		const gchar *port;
		const gchar *service;
	} corpus[] = {
		{ "224.0.0.252",     "5355", "LLMNR"    },
		{ "239.255.255.250", "1900", "SSDP"     },
		{ "192.168.1.21",    "445",  "SMB"      },
		{ "192.168.50.2",    "80",   "nas.local"},
		{ "127.0.0.1",       "9050", "loopback" },
	};
	guint i;

	for (i = 0; i < G_N_ELEMENTS (corpus); i++) {
		FsCopilot *c = fs_copilot_new ();
		FsHit *hit = base_hit (corpus[i].service);
		gint k;

		hit->destination = (gchar *) corpus[i].dest;
		hit->port = (gchar *) corpus[i].port;

		for (k = 0; k < 6; k++)
			feed (c, hit, (gint64) k * 60);

		/* The timing detector fires -- and that is correct: it is a
		 * report, not a block.  What matters is the verdict. */
		CHECK (count_insights (c, FS_INSIGHT_BEACON) == 1,
		       "replay: the metronomic %s contact is still reported",
		       corpus[i].dest);
		CHECK (would_stage (c) == 0,
		       "replay: %s never reaches the wire unattended",
		       corpus[i].dest);

		fs_copilot_free (c);
		g_free (hit);
	}

	/* The shared CDN: an established destination stays report-only
	 * even when a fresh port starts ticking metronomically. */
	{
		FsCopilot *c = fs_copilot_new ();
		FsHit *hit = base_hit ("browser.exe");
		const FsInsight *ins;
		static const gint gaps[] =
			{ 7, 3, 15, 5, 23, 9, 4, 31, 6, 12 };
		gint64 t = 0;
		gint k;

		hit->destination = (gchar *) "3.173.21.63";
		hit->port = (gchar *) "443";
		for (k = 0; k < 27; k++) {          /* jittered history */
			feed (c, hit, t);
			t += gaps[k % G_N_ELEMENTS (gaps)];
		}
		CHECK (fs_copilot_baseline_dest_established
		       (c, "browser.exe", "3.173.21.63"),
		       "replay: twenty-seven recorded connections establish the CDN");

		hit->port = (gchar *) "8443";       /* a fresh ticking port */
		for (k = 0; k < 6; k++)
			feed (c, hit, 400 + (gint64) k * 60);

		CHECK (count_insights (c, FS_INSIGHT_BEACON) == 1,
		       "replay: the established CDN's metronome is still reported");
		ins = find_insight (c, FS_INSIGHT_BEACON);
		CHECK (ins != NULL && !ins->auto_applicable,
		       "replay: an established destination is vetoed at creation");
		CHECK (would_stage (c) == 0,
		       "replay: the browser's own CDN stages nothing");

		fs_copilot_free (c);
		g_free (hit);
	}
}

/* =====================================================================
 * 5. Benign developer tools: the traffic a working machine makes all
 *    day.  Jittered human cadence is not a beacon; a CDN fan-in just
 *    under the line is not a scan; and when the line IS crossed, the
 *    report still carries no rule.
 * ===================================================================== */

static void
test_benign_devtools (void)
{
	/* git: jittered cadence, one host. */
	{
		FsCopilot *c = fs_copilot_new ();
		FsHit *hit = base_hit ("git.exe");
		static const gint gaps[] =
			{ 5, 11, 3, 27, 9, 4, 40, 13, 6, 22, 7, 31 };
		gint64 t = 0;
		gint k;

		hit->destination = (gchar *) "140.82.112.4";
		hit->port = (gchar *) "443";
		for (k = 0; k < 12; k++) {
			feed (c, hit, t);
			t += gaps[k % G_N_ELEMENTS (gaps)];
		}

		CHECK (count_insights (c, FS_INSIGHT_BEACON) == 0,
		       "benign: git's jittered cadence is not a beacon");
		CHECK (would_stage (c) == 0,
		       "benign: a clone stages nothing");

		fs_copilot_free (c);
		g_free (hit);
	}

	/* npm: a CDN fan-in.  59 distinct hosts pass; the 60th reports --
	 * a line, not a judgment -- and even then the report carries no
	 * rule, so the worst it can do is ask for a look. */
	{
		FsCopilot *c = fs_copilot_new ();
		FsHit *hit = base_hit ("npm.exe");
		const FsInsight *ins;
		gchar dest[32];
		gint i;

		hit->port = (gchar *) "443";
		for (i = 0; i < 59; i++) {
			g_snprintf (dest, sizeof dest, "198.51.100.%d",
			            i + 1);
			hit->destination = dest;
			feed (c, hit, i);            /* 0..58 s */
		}
		CHECK (count_insights (c, FS_INSIGHT_FANOUT) == 0,
		       "benign: 59 distinct hosts in a window report nothing");

		g_snprintf (dest, sizeof dest, "198.51.100.60");
		hit->destination = dest;
		feed (c, hit, 59);               /* still the same window */
		CHECK (count_insights (c, FS_INSIGHT_FANOUT) == 1,
		       "benign: the 60th distinct host crosses the line");

		ins = find_insight (c, FS_INSIGHT_FANOUT);
		CHECK (ins != NULL && ins->rule_csv == NULL,
		       "benign: even the crossed line stages nothing by itself");
		CHECK (would_stage (c) == 0,
		       "benign: sixty CDN first-contacts stage nothing at all");

		fs_copilot_free (c);
		g_free (hit);
	}
}

/* =====================================================================
 * 6. Outbound exfiltration pattern: a quiet, established rate that
 *    suddenly sixty-bursts.  The volume finding must fire -- and must
 *    carry no rule, because "this is loud" is evidence, not a verdict.
 * ===================================================================== */

static void
test_exfil_volume_burst (void)
{
	FsCopilot *c = fs_copilot_new ();
	FsHit *hit = base_hit ("syncer.exe");
	const FsInsight *ins;
	static const gint learn_offsets[] = { 3, 17, 45, 52, 78, 97 };
	gint b, k;

	hit->destination = (gchar *) "198.51.100.77";
	hit->port = (gchar *) "443";

	/* Nine learned 10-minute buckets, six connections each, at a
	 * jittered cadence (exact 20-second spacing would itself be a
	 * beacon -- the engine is right to object to that too). */
	for (b = 0; b < 9; b++)
		for (k = 0; k < 6; k++)
			feed (c, hit, (gint64) b * 600 + learn_offsets[k]);

	/* The burst: sixty connections inside the tenth bucket. */
	for (k = 0; k < 60; k++)
		feed (c, hit, (gint64) 9 * 600 + k);

	CHECK (count_insights (c, FS_INSIGHT_UNUSUAL_VOLUME) >= 1,
	       "exfil: sixty connections against a usual six is a finding");
	ins = find_insight (c, FS_INSIGHT_UNUSUAL_VOLUME);
	CHECK (ins != NULL && ins->rule_csv == NULL,
	       "exfil: the volume finding carries no rule");
	CHECK (would_stage (c) == 0,
	       "exfil: a loud burst stages nothing by itself");

	fs_copilot_free (c);
	g_free (hit);
}

/* =====================================================================
 * 7. Rule rollback: the detection stages its deny, the apply fails
 *    halfway, and the firewall must stay at the last verified policy --
 *    the detection rule neither half-applied nor journaled as live.
 * ===================================================================== */

/* --- scripted backend (the apply-gate test's fake, in miniature) ----- */

#define FAKE_MAX_QUEUE 8

static FsApplyResult fake_queue[FAKE_MAX_QUEUE];
static gint fake_queue_len, fake_queue_pos;
static gint fake_full_calls, fake_delta_calls;
static FsPolicy *fake_seen[FAKE_MAX_QUEUE];
static gint fake_seen_len;

static void
fake_reset (void)
{
	for (gint i = 0; i < fake_seen_len; i++)
		fs_policy_free (fake_seen[i]);

	fake_seen_len = 0;
	fake_queue_len = fake_queue_pos = 0;
	fake_full_calls = fake_delta_calls = 0;
}

static void
fake_enqueue (FsApplyResult result)
{
	fake_queue[fake_queue_len++] = result;
}

static FsApplyResult
fake_next (GError **error)
{
	FsApplyResult result = FS_APPLY_OK;

	if (fake_queue_pos < fake_queue_len)
		result = fake_queue[fake_queue_pos++];

	if (result != FS_APPLY_OK)
		g_set_error_literal (error,
		                     g_quark_from_static_string ("fake-backend"),
		                     (int) result,
		                     "scripted backend failure");

	return result;
}

static gboolean
fake_available (void)
{
	return TRUE;
}

/* Deep copy: the fake records what the wire was TOLD, and the gate
 * keeps mutating its policy after the call -- a stored pointer would
 * both drift with it and be freed out from under the test. */
static FsPolicy *
fake_policy_copy (const FsPolicy *src)
{
	FsPolicy *dst = fs_policy_new ();

	for (gint kind = 0; kind < FS_RULE_N_KINDS; kind++)
		for (guint i = 0; i < src->kinds[kind]->len; i++)
			fs_policy_add (dst, g_ptr_array_index (src->kinds[kind], i));

	return dst;
}

static FsApplyResult
fake_apply_rules (const FsPolicy *policy, GError **error)
{
	fake_full_calls++;

	if (fake_seen_len < FAKE_MAX_QUEUE)
		fake_seen[fake_seen_len++] = fake_policy_copy (policy);

	return fake_next (error);
}

static FsApplyResult
fake_apply_delta (const GList *remove, const GList *add,
                  const GList *repair, GError **error)
{
	(void) remove; (void) add; (void) repair;
	fake_delta_calls++;
	return fake_next (error);
}

static const FsBackend fake_backend = {
	.name = "fake",
	.display_name = "scripted fake backend",
	.available = fake_available,
	.apply_rules = fake_apply_rules,
	.apply_delta = fake_apply_delta,
};

static guint
policy_total (const FsPolicy *policy)
{
	guint total = 0;

	for (gint kind = 0; kind < FS_RULE_N_KINDS; kind++)
		total += policy->kinds[kind]->len;

	return total;
}

static gchar *
audit_read (void)
{
	gchar *contents = NULL;
	const gchar *path = g_getenv ("STOCKFW_AUDIT_FILE");

	if (path != NULL)
		g_file_get_contents (path, &contents, NULL, NULL);

	return contents;
}

static void
test_detection_rule_rollback (void)
{
	gchar *dir = g_build_filename (g_get_tmp_dir (),
	                               "stockfw-p4-rollback", NULL);
	gchar *file = g_build_filename (dir, "applied.csv", NULL);
	gchar *audit_file = g_build_filename (dir, "audit.log", NULL);
	FsCopilot *c;
	FsHit *hit;
	const FsInsight *beacon;
	FsPolicy *policy;
	FsPolicy *loaded;
	FsApplyOutcome *outcome;
	FsRule *rule;
	GError *error = NULL;
	gchar *contents;
	guint rows;
	gint i;

	g_mkdir_with_parents (dir, 0700);
	remove (file);
	remove (audit_file);
	g_setenv ("STOCKFW_APPLIED_FILE", file, TRUE);
	g_setenv ("STOCKFW_AUDIT_FILE", audit_file, TRUE);

	/* A baseline policy the user already has on the wire. */
	policy = fs_policy_new ();
	rule = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);
	rule->service = g_strdup ("SSH");
	rule->port    = g_strdup ("22");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);
	rule = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_TO);
	rule->target = g_strdup ("203.0.113.9");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);
	rows = policy_total (policy);

	fake_reset ();
	outcome = fs_policy_apply_safe (&fake_backend, policy, "p4 test",
	                                NULL, &error);
	CHECK (outcome->result == FS_APPLY_OK && outcome->applied,
	       "rollback: the baseline applies first");
	g_clear_error (&error);
	fs_apply_outcome_free (outcome);

	/* The detection stages its deny. */
	c = fs_copilot_new ();
	hit = base_hit ("beacon-host");
	hit->destination = (gchar *) "198.51.100.200";
	hit->port = (gchar *) "8443";
	for (i = 0; i < 6; i++)
		feed (c, hit, (gint64) i * 60);
	beacon = find_insight (c, FS_INSIGHT_BEACON);
	CHECK (beacon != NULL && fs_insight_apply (beacon, policy),
	       "rollback: the detection's deny stages into the policy");
	CHECK (policy_total (policy) == rows + 1,
	       "rollback: the policy now holds baseline plus the deny");

	/* The apply fails halfway; the rollback restores the wire.
	 * Sequence: narrow apply fails (delta), rollback re-applies the
	 * JOURNALED baseline whole-set -- one of each call, and the wire
	 * ends at the baseline, deny never live. */
	fake_reset ();
	fake_enqueue (FS_APPLY_PARTIAL);   /* the narrow apply            */
	fake_enqueue (FS_APPLY_OK);        /* the rollback                */
	outcome = fs_policy_apply_safe (&fake_backend, policy, "p4 test",
	                                NULL, &error);
	CHECK (outcome->result == FS_APPLY_PARTIAL && !outcome->applied,
	       "rollback: the failed apply is never reported as applied");
	CHECK (outcome->rollback_attempted && outcome->rollback_verified,
	       "rollback: the rollback runs and its verdict is verified");
	CHECK (fake_delta_calls == 1 && fake_full_calls == 1,
	       "rollback: one failed narrow apply, one whole-set restore");
	CHECK (fake_seen_len == 1 &&
	       policy_total (fake_seen[0]) == rows,
	       "rollback: the wire ends at the baseline, deny never live");
	g_clear_error (&error);
	fs_apply_outcome_free (outcome);

	loaded = fs_policy_new ();
	CHECK (fs_apply_journal_load (loaded, &error) &&
	       policy_total (loaded) == rows,
	       "rollback: the journal still holds only the verified baseline");
	g_clear_error (&error);
	fs_policy_free (loaded);

	contents = audit_read ();
	CHECK (contents != NULL &&
	       strstr (contents, "| policy apply failed |") != NULL &&
	       strstr (contents, "rollback verified:") != NULL,
	       "rollback: failure and verified rollback are one audit trail");
	g_free (contents);

	fs_policy_free (policy);
	fs_copilot_free (c);
	g_free (hit);
	g_free (file);
	g_free (audit_file);
	g_free (dir);
}

int
main (void)
{
	test_scan_blocked_fanout ();
	test_port_sweep_single_host ();
	test_beacon_c2_fires ();
	test_incident_replay_no_outage ();
	test_benign_devtools ();
	test_exfil_volume_burst ();
	test_detection_rule_rollback ();

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);

	return failures ? 1 : 0;
}
EOF

EXTRA_LIBS=""
if [ "${OS:-}" = "Windows_NT" ] || [ -d /ucrt64 ]; then
  EXTRA_LIBS="-lws2_32"
fi

cc "$BUILD_DIR/test-adversarial.c" \
   -I src \
   $(pkg-config --cflags glib-2.0) \
   -o "$BUILD_DIR/test-adversarial" \
   src/core/*.c \
   $(pkg-config --libs glib-2.0 gio-2.0 liblzma libcrypto) $EXTRA_LIBS

# Keep rule/journal/audit files out of the real directories.
export STOCKFW_RULES_DIR="$BUILD_DIR/rules"
rm -rf "$STOCKFW_RULES_DIR"

"$BUILD_DIR/test-adversarial"
