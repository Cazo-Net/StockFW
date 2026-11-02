/*---[ ui-copilot-smoke.c ]------------------------------------------------
 *
 * UI smoke test for Sentinel's P6 auto-block state machine.
 *
 * The 2026-10-10 incident was three silent loops in this exact code:
 * an expiry that re-staged forever, staging records that died with the
 * process while their policy rows survived, and a user Allow that a
 * block rule outranked.  None of that is visible to fs-core: it lives
 * in the Copilot page's statics.  So this smoke drives the REAL page
 * and the exported functions end to end against scratch files:
 *
 *   1. boot restore  -- a stale row comes out of the policy, a fresh
 *      row is re-armed with its ORIGINAL clock, the state file is
 *      rewritten to match, and the episode is audited;
 *   2. cooldown      -- a restored (retired) rule is refused even
 *      when a live beacon insight asks for it again;
 *   3. staging       -- a metronomic stranger to a public host
 *      stages, persists to the state file, and pushes (held=staged
 *      without elevation, which is the honest verdict, not a lie);
 *   4. dest lift     -- the user's Allow takes down Sentinel's rows
 *      for that destination (staged or persisted) and NEVER the
 *      user's own rules, and the cooldown blocks the re-stage;
 *   5. lift all      -- one call retires every staged block;
 *   6. detect mode   -- with the pref switched, auto_pass stages
 *      nothing at all.
 *
 * Everything runs against a mkdtemp scratch tree (rules dir, audit,
 * journal, autoblocks, APPDATA) set before the first path is
 * resolved, so the user's real policy is never in scope.  The push
 * attempts reach the real backend but run unelevated: no rule can
 * reach the firewall from a test, which is exactly the "staged, not
 * live" path being asserted.
 *
 * Deliberately NOT part of StockFW.exe -- the CMake target is
 * EXCLUDE_FROM_ALL -- so no test hook is ever shipped to a user.
 *
 *----------------------------------------------------------------------*/
#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "core/fs-copilot.h"
#include "core/fs-rules.h"
#include "core/fs-prefs.h"
#include "core/fs-audit.h"
#include "core/fs-util.h"
#include "ui/fs-copilot.h"

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

/* ---- scratch isolation ---------------------------------------------- */

static gchar *scratch = NULL;

static gchar *
scratch_path (const gchar *name)
{
	return g_build_filename (scratch, name, NULL);
}

static void
isolate (void)
{
	gchar *rules;
	gchar *audit;
	gchar *journal;
	gchar *blocks;
	gchar *behavior;

	scratch = g_dir_make_tmp ("stockfw-copilot-smoke-XXXXXX", NULL);
	if (scratch == NULL) {
		fprintf (stderr, "cannot create scratch dir\n");
		exit (1);
	}

	rules    = scratch_path ("rules");
	audit    = scratch_path ("audit.log");
	journal  = scratch_path ("applied.csv");
	blocks   = scratch_path ("autoblocks");
	behavior = scratch_path ("behavior.csv");

	g_mkdir_with_parents (rules, 0700);

	g_setenv ("STOCKFW_RULES_DIR", rules, TRUE);
	g_setenv ("STOCKFW_AUDIT_FILE", audit, TRUE);
	g_setenv ("STOCKFW_APPLIED_FILE", journal, TRUE);
	g_setenv ("STOCKFW_AUTOBLOCK_FILE", blocks, TRUE);
	g_setenv ("STOCKFW_BEHAVIOR_FILE", behavior, TRUE);
	/* Prefs follow APPDATA on Windows (and XDG_CONFIG_HOME on
	 * Linux): the Sentinel mode switch below writes there. */
	g_setenv ("APPDATA", scratch, TRUE);
	g_setenv ("XDG_CONFIG_HOME", scratch, TRUE);

	g_free (rules);
	g_free (audit);
	g_free (journal);
	g_free (blocks);
	g_free (behavior);
}

/* ---- small helpers --------------------------------------------------- */

static gboolean
policy_has (FsPolicy *policy, FsRuleKind kind, const gchar *csv)
{
	FsRule *rule = fs_rule_from_csv (kind, csv);
	gboolean in = rule != NULL && fs_policy_contains (policy, rule);

	fs_rule_free (rule);
	return in;
}

static void
policy_add (FsPolicy *policy, FsRuleKind kind, const gchar *csv)
{
	FsRule *rule = fs_rule_from_csv (kind, csv);

	if (rule == NULL) {
		printf ("FAIL: test setup cannot parse \"%s\"\n", csv);
		failures++;
		return;
	}

	fs_policy_add (policy, rule);
	fs_rule_free (rule);
}

static gchar *
file_contents (const gchar *path)
{
	gchar *text = NULL;

	if (!g_file_get_contents (path, &text, NULL, NULL))
		return g_strdup ("");

	return text;
}

/* How many staged rows ("S,...") the state file holds right now. */
static guint
state_row_count (void)
{
	gchar *path = scratch_path ("autoblocks");
	gchar *text = file_contents (path);
	gchar **lines = g_strsplit (text, "\n", -1);
	guint n = 0;
	guint i;

	for (i = 0; lines[i] != NULL; i++)
		if (g_str_has_prefix (lines[i], "S,"))
			n++;

	g_strfreev (lines);
	g_free (text);
	g_free (path);
	return n;
}

static gboolean
state_mentions (const gchar *needle)
{
	gchar *path = scratch_path ("autoblocks");
	gchar *text = file_contents (path);
	gboolean hit = strstr (text, needle) != NULL;

	g_free (text);
	g_free (path);
	return hit;
}

static gboolean
audit_mentions (const gchar *needle)
{
	gchar *path = scratch_path ("audit.log");
	gchar *text = file_contents (path);
	gboolean hit = strstr (text, needle) != NULL;

	g_free (text);
	g_free (path);
	return hit;
}

/* Six metronomic contacts: enough for the beacon detector, at dst:port
 * with exact 60 s intervals. */
static void
feed_beacon (FsCopilot *copilot, const gchar *dest, gint64 t0)
{
	FsHit hit;
	gint i;

	memset (&hit, 0, sizeof hit);
	hit.direction   = "Out";
	hit.source      = "192.168.1.7";
	hit.destination = (gchar *) dest;
	hit.port        = "443";
	hit.protocol    = "TCP";
	hit.service     = "smoke.exe";

	for (i = 0; i < 6; i++)
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * 60 * G_USEC_PER_SEC);
}

static const FsInsight *
find_beacon (FsCopilot *copilot)
{
	GList *insights = fs_copilot_get_insights (copilot);
	GList *l;
	const FsInsight *found = NULL;

	for (l = insights; l != NULL; l = l->next) {
		FsInsight *ins = l->data;

		if (ins->type == FS_INSIGHT_BEACON) {
			found = ins;
			break;
		}
	}

	g_list_free (insights);
	return found;
}

/* ---- the smoke ------------------------------------------------------- */

int
main (int argc, char **argv)
{
	/* Scratch FIRST: every path below is resolved lazily on first
	 * use, and none of them may ever point at the real user data. */
	isolate ();

	gtk_init (&argc, &argv);

	FsPolicy *policy = fs_policy_new ();
	FsCopilot *copilot = fs_copilot_new ();
	gint malformed = 0;
	GtkWidget *page;
	const gint64 now_epoch = g_get_real_time () / G_USEC_PER_SEC;
	const gint64 t0 = (gint64) 800000 * G_USEC_PER_SEC;

	/* A virgin scratch dir holds no rule files: load's FALSE here is
	 * "nothing saved yet", not a failure -- and the empty store it
	 * leaves behind is exactly the blank slate the restore needs. */
	fs_policy_load (policy, &malformed);

	/* The real page: it owns the statics (global copilot, shared
	 * policy, cached Sentinel mode) the whole state machine runs
	 * through, exactly as fs-app.c builds it. */
	page = fs_copilot_page (copilot, policy);
	CHECK (page != NULL, "the Copilot page builds");

	/* ---- 1. boot restore ------------------------------------------ */

	policy_add (policy, FS_RULE_OUTBOUND_DENY_TO,
	            "3.3.3.3, Sentinel: periodic beacon");   /* fresh */
	policy_add (policy, FS_RULE_OUTBOUND_DENY_TO,
	            "1.2.3.4, Sentinel: periodic beacon");   /* stale */
	CHECK (fs_policy_save (policy), "the seeded policy saves");

	{
		gchar *path = scratch_path ("autoblocks");
		GString *out = g_string_new (NULL);

		g_string_append_printf (out,
			"S,%" G_GINT64_FORMAT ",6,"
			"3.3.3.3, Sentinel: periodic beacon\n",
			now_epoch - 60);                    /* inside TTL  */
		g_string_append_printf (out,
			"S,%" G_GINT64_FORMAT ",6,"
			"1.2.3.4, Sentinel: periodic beacon\n",
			now_epoch - 3600);                  /* past TTL    */
		g_string_append (out, "S,0,6,broken epoch row\n");
		g_string_append (out, "not a row at all\n");
		CHECK (g_file_set_contents (path, out->str, -1, NULL),
		       "the previous session's staged list is written");
		g_string_free (out, TRUE);
		g_free (path);
	}

	fs_copilot_autoblocks_restore (policy, NULL);

	CHECK (!policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                    "1.2.3.4, Sentinel: periodic beacon"),
	       "restore takes the stale block out of the policy");
	CHECK (policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                   "3.3.3.3, Sentinel: periodic beacon"),
	       "restore keeps the fresh block in the policy");
	CHECK (state_row_count () == 1 && state_mentions ("3.3.3.3"),
	       "the state file now holds exactly the fresh row");
	CHECK (audit_mentions ("expired while StockFW was not running"),
	       "the stale expiry is audited");
	CHECK (audit_mentions ("sentinel auto-blocks restored"),
	       "the restore episode is audited");

	/* ---- 2. cooldown: the stale rule is refused again ------------- */

	feed_beacon (copilot, "1.2.3.4", t0);
	{
		const FsInsight *b = find_beacon (copilot);

		CHECK (b != NULL && b->auto_applicable,
		       "the 1.2.3.4 beacon still asks to be auto-blocked");
	}
	CHECK (!fs_copilot_sentinel_auto_pass (),
	       "the auto pass stages nothing: the stale rule is cooled");
	CHECK (!policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                    "1.2.3.4, Sentinel: periodic beacon"),
	       "the cooled rule is not re-staged into the policy");

	/* ---- 3. staging: a metronomic stranger to a public host -------- */

	feed_beacon (copilot, "5.6.7.8", t0 + (gint64) 1000 * G_USEC_PER_SEC);
	CHECK (fs_copilot_sentinel_auto_pass (),
	       "the auto pass stages the stranger's beacon");
	CHECK (policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                   "5.6.7.8, Sentinel: periodic beacon"),
	       "the staged block is in the policy");
	CHECK (state_row_count () == 2 && state_mentions ("5.6.7.8"),
	       "the staged block is persisted with its fresh row");
	CHECK (audit_mentions ("sentinel auto-block staged, not live") ||
	       audit_mentions ("sentinel auto-block is live"),
	       "the push reports its real verdict");

	/* ---- 4. dest lift: the user's Allow is the last word ----------- */

	policy_add (policy, FS_RULE_OUTBOUND_DENY_TO,
	            "9.9.9.9, Sentinel: periodic beacon");  /* persisted sentinel */
	policy_add (policy, FS_RULE_OUTBOUND_DENY_TO,
	            "8.8.8.8, user manual rule");           /* the user's own    */
	CHECK (fs_policy_save (policy),
	       "the earlier-session sentinel row and the user rule save");

	CHECK (fs_copilot_lift_auto_blocks_for_dest ("9.9.9.9"),
	       "lifting a persisted sentinel row reports a change");
	CHECK (!policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                    "9.9.9.9, Sentinel: periodic beacon"),
	       "the persisted sentinel row is gone");
	CHECK (policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                   "8.8.8.8, user manual rule"),
	       "the user's own rule is untouched");

	CHECK (fs_copilot_lift_auto_blocks_for_dest ("5.6.7.8"),
	       "lifting a staged block reports a change");
	CHECK (!policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                    "5.6.7.8, Sentinel: periodic beacon"),
	       "the staged block is out of the policy");
	CHECK (state_row_count () == 1 && !state_mentions ("5.6.7.8"),
	       "the staged block is out of the state file");

	CHECK (!fs_copilot_lift_auto_blocks_for_dest ("203.0.113.1"),
	       "lifting a destination nothing blocks reports no change");

	CHECK (!fs_copilot_sentinel_auto_pass (),
	       "the lifted rule cannot be staged straight back (cooldown)");
	CHECK (!policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                    "5.6.7.8, Sentinel: periodic beacon"),
	       "the policy stays free of the lifted block");

	/* ---- 5. lift all: one call retires every staged block ---------- */

	feed_beacon (copilot, "6.6.6.6", t0 + (gint64) 2000 * G_USEC_PER_SEC);
	CHECK (fs_copilot_sentinel_auto_pass (),
	       "a second stranger stages");
	CHECK (policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                   "6.6.6.6, Sentinel: periodic beacon"),
	       "the second stranger is in the policy");

	CHECK (fs_copilot_lift_all_auto_blocks ("smoke test"),
	       "lift-all retires every staged block");
	CHECK (!policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                    "6.6.6.6, Sentinel: periodic beacon"),
	       "nothing staged remains in the policy");
	CHECK (state_row_count () == 0,
	       "nothing staged remains in the state file");
	CHECK (!fs_copilot_sentinel_auto_pass (),
	       "after lift-all the cooldown keeps everything down");

	/* ---- 6. detect mode: auto_pass stages nothing ------------------ */

	fs_prefs_set_string ("/apps/stockfw/client/sentinel/mode", "detect");
	page = fs_copilot_page (copilot, policy);   /* re-caches the mode */
	CHECK (page != NULL, "the Copilot page rebuilds in detect mode");

	feed_beacon (copilot, "7.7.7.7", t0 + (gint64) 3000 * G_USEC_PER_SEC);
	CHECK (!fs_copilot_sentinel_auto_pass (),
	       "detect mode refuses to stage anything");
	CHECK (!policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                    "7.7.7.7, Sentinel: periodic beacon"),
	       "detect mode leaves the policy free of the block");

	printf ("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
