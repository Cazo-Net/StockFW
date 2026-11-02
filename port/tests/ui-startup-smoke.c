/*---[ ui-startup-smoke.c ]----------------------------------------------
 * What the firewall is handed when StockFW starts it at launch.
 *
 * Up to 1.0.7, fs_app_activate() ran "Start the firewall on program
 * startup" BEFORE the Policy page had loaded the policy from disk, so
 * on Linux -- where starting is a whole-set apply -- the backend
 * installed an EMPTY policy, and the Sentinel restore that came later
 * took expired blocks out of the policy file without ever pushing
 * that to the firewall.  This smoke supplies fs_backend() itself with
 * a Linux-shaped fake that RECORDS the policy it is handed at start
 * (and at any apply), runs the real fs_app_activate() on a scratch
 * profile, and checks:
 *
 *   start      the backend started once, with every rule from the
 *              policy files -- never an empty policy -- and WITHOUT the
 *              Sentinel block whose ten minutes ran out while StockFW
 *              was closed; the start is on the audit record and the
 *              journal says what is live;
 *   held       audit-only mode on: start() itself is never called (it
 *              would install the file with its held changes); the
 *              journal -- the last policy really applied -- goes in
 *              instead;
 *   heldnone   audit-only mode on and nothing ever applied: the
 *              firewall is left alone entirely;
 *   push       no start at launch, firewall running: the expired
 *              Sentinel block is pushed OFF the firewall through the
 *              apply gate (it used to stay live until some later
 *              apply);
 *   stopped    no start at launch, firewall stopped: nothing is
 *              applied (on Linux an apply IS a start, and a firewall
 *              the user left stopped must not start behind them).
 *
 * Each scenario runs in its own process (fs-app.c keeps its state in
 * statics); run with no arguments, the binary runs them all.
 *
 * Teeth: move the START_ON_GUI block in fs-app.c back above the Policy
 * page, and "start" fails on the rule count; drop the push in
 * start_at_launch() and "push" fails.  See tests/README.md.
 *--------------------------------------------------------------------*/

#include <gtk/gtk.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-apply.h"
#include "core/fs-backend.h"
#include "core/fs-prefs.h"
#include "core/fs-rules.h"
#include "ui/fs-app.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	printf ((cond) ? "ok:   " : "FAIL: ");                  \
	printf (__VA_ARGS__);                                   \
	printf ("\n");                                          \
	if (!(cond))                                            \
		failures++;                                     \
} while (0)

/* The user's own rules, and the one Sentinel staged an hour ago. */
#define USER_BLOCK   "198.51.100.7, my own block"
#define USER_ALLOW   "192.0.2.10, office"
#define SENTINEL_CSV "203.0.113.9, Sentinel: beacon to 203.0.113.9"

/* ------------------------------------------------------- fake backend */

static FsPolicy        *ctx_policy = NULL;
static FsFirewallState  fake_state = FS_FW_STOPPED;
static guint            starts = 0, applies = 0, stops = 0;
static GPtrArray       *seen_at_start = NULL;   /* "kind|csv" */
static GPtrArray       *seen_at_apply = NULL;   /* last apply */

static GPtrArray *
snapshot (const FsPolicy *policy)
{
	GPtrArray *rows = g_ptr_array_new_with_free_func (g_free);

	if (policy == NULL)
		return rows;

	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		for (guint i = 0; i < policy->kinds[k]->len; i++) {
			gchar *csv = fs_rule_to_csv (
				g_ptr_array_index (policy->kinds[k], i));

			g_ptr_array_add (rows, g_strdup_printf ("%d|%s", k,
			                                        csv));
			g_free (csv);
		}
	return rows;
}

static gboolean
seen (GPtrArray *rows, FsRuleKind kind, const gchar *csv)
{
	FsRule *rule = fs_rule_from_csv (kind, csv);
	gchar *norm = rule != NULL ? fs_rule_to_csv (rule) : g_strdup (csv);
	gchar *key = g_strdup_printf ("%d|%s", (int) kind, norm);
	gboolean hit = FALSE;

	for (guint i = 0; rows != NULL && i < rows->len && !hit; i++)
		hit = g_strcmp0 (g_ptr_array_index (rows, i), key) == 0;

	fs_rule_free (rule);
	g_free (norm);
	g_free (key);
	return hit;
}

static gboolean fake_available (void) { return TRUE; }
static FsFirewallState fake_get_state (void) { return fake_state; }

static gboolean
fake_start (GError **error)
{
	(void) error;
	starts++;
	if (seen_at_start != NULL)
		g_ptr_array_unref (seen_at_start);
	seen_at_start = snapshot (ctx_policy);
	fake_state = FS_FW_RUNNING;
	return TRUE;
}

static gboolean
fake_stop (GError **error)
{
	(void) error;
	stops++;
	fake_state = FS_FW_STOPPED;
	return TRUE;
}

static FsApplyResult
fake_apply_rules (const FsPolicy *policy, GError **error)
{
	(void) error;
	applies++;
	if (seen_at_apply != NULL)
		g_ptr_array_unref (seen_at_apply);
	seen_at_apply = snapshot (policy);
	fake_state = FS_FW_RUNNING;
	return FS_APPLY_OK;
}

static GList *fake_none (void) { return NULL; }

static gboolean
fake_log_start (FsLogFunc cb, gpointer user, GError **error)
{
	(void) cb; (void) user; (void) error;
	return TRUE;
}
static void     fake_log_stop (void) { }
static gboolean fake_log_active (void) { return TRUE; }
static const gchar *fake_log_text (void) { return NULL; }

static gboolean
fake_get_profile (gint profile, gboolean *on)
{
	(void) profile; (void) on;
	return FALSE;
}

static FsIpv6State
fake_ipv6 (gchar **detail)
{
	if (detail != NULL)
		*detail = NULL;
	return FS_IPV6_FILTERED;
}

static const FsBackend fake_backend = {
	.name                 = "fake-linux",
	.display_name         = "Fake (records starts)",
	.start_applies_policy = TRUE,
	.available            = fake_available,
	.get_state            = fake_get_state,
	.start                = fake_start,
	.stop                 = fake_stop,
	.apply_rules          = fake_apply_rules,
	.list_interfaces      = fake_none,
	.list_interface_stats = fake_none,
	.list_connections     = fake_none,
	.list_processes       = fake_none,
	.log_start            = fake_log_start,
	.log_stop             = fake_log_stop,
	.log_active           = fake_log_active,
	.log_source           = fake_log_text,
	.log_problem          = fake_log_text,
	.get_profile_enabled  = fake_get_profile,
	.ipv6_state           = fake_ipv6,
};

const FsBackend *
fs_backend (void)
{
	return &fake_backend;
}

const gchar *
fs_error_domain (void)
{
	return "fake-linux";
}

void
fs_backend_set_context (FsPolicy *policy, FsSettings *settings)
{
	(void) settings;
	ctx_policy = policy;
}

/* ------------------------------------------------------------ helpers */

static gchar *scratch = NULL;
static const gchar *scenario = NULL;

static void
put_rule (FsPolicy *policy, FsRuleKind kind, const gchar *csv)
{
	FsRule *rule = fs_rule_from_csv (kind, csv);

	if (rule != NULL)
		fs_policy_add (policy, rule);
}

static gboolean
audit_has (const gchar *needle)
{
	gchar *path = g_build_filename (scratch, "audit.log", NULL);
	gchar *text = NULL;
	gboolean hit;

	g_file_get_contents (path, &text, NULL, NULL);
	hit = text != NULL && strstr (text, needle) != NULL;
	g_free (text);
	g_free (path);
	return hit;
}

/* Everything the app reads or writes lives under the scratch dir, set
 * before anything can cache a path. */
static void
prepare (void)
{
	FsPolicy *policy;
	gchar *path, *rows;
	gint64 now = g_get_real_time () / G_USEC_PER_SEC;
	gboolean start_on_gui = g_strcmp0 (scenario, "push") != 0 &&
	                        g_strcmp0 (scenario, "stopped") != 0;
	gboolean audit_only = g_str_has_prefix (scenario, "held");

	scratch = g_dir_make_tmp ("stockfw-startup-XXXXXX", NULL);
	g_setenv ("XDG_CONFIG_HOME", scratch, TRUE);
	g_setenv ("APPDATA", scratch, TRUE);
	path = g_build_filename (scratch, "rules", NULL);
	g_setenv ("STOCKFW_RULES_DIR", path, TRUE);
	g_free (path);
#define SCRATCH_ENV(var, name) do {                               \
		gchar *p_ = g_build_filename (scratch, name, NULL);   \
		g_setenv (var, p_, TRUE);                             \
		g_free (p_);                                          \
	} while (0)
	SCRATCH_ENV ("STOCKFW_AUDIT_FILE", "audit.log");
	SCRATCH_ENV ("STOCKFW_APPLIED_FILE", "applied.csv");
	SCRATCH_ENV ("STOCKFW_AUTOBLOCK_FILE", "autoblocks");
	SCRATCH_ENV ("STOCKFW_BEHAVIOR_FILE", "behavior.csv");
	SCRATCH_ENV ("STOCKFW_TRUST_FILE", "trust.csv");

	/* The policy on disk: two user rules and Sentinel's block. */
	policy = fs_policy_new ();
	put_rule (policy, FS_RULE_OUTBOUND_DENY_TO, USER_BLOCK);
	put_rule (policy, FS_RULE_INBOUND_ALLOW_FROM, USER_ALLOW);
	put_rule (policy, FS_RULE_OUTBOUND_DENY_TO, SENTINEL_CSV);
	fs_policy_save (policy);

	/* What is live, for the held scenario: the user's block only --
	 * the allow was added later, while changes were held. */
	if (g_strcmp0 (scenario, "held") == 0) {
		FsPolicy *live = fs_policy_new ();

		put_rule (live, FS_RULE_OUTBOUND_DENY_TO, USER_BLOCK);
		fs_apply_journal_save (live, NULL);
		fs_policy_free (live);
	}
	fs_policy_free (policy);

	/* Sentinel staged its block an hour ago: long expired. */
	rows = g_strdup_printf ("S,%" G_GINT64_FORMAT ",%d,%s\n", now - 3600,
	                        (int) FS_RULE_OUTBOUND_DENY_TO, SENTINEL_CSV);
	path = g_build_filename (scratch, "autoblocks", NULL);
	g_file_set_contents (path, rows, -1, NULL);
	g_free (path);
	g_free (rows);

	fs_prefs_init ();
	fs_prefs_load ();
	fs_prefs_set_defaults ();
	fs_prefs_set_bool (FS_PREFS_START_ON_GUI, start_on_gui);
	fs_prefs_set_bool (FS_PREFS_AUDIT_ONLY, audit_only);
	/* No tray in this smoke: the window must simply open. */
	fs_prefs_set_bool (FS_PREFS_ENABLE_TRAY_ICON, FALSE);
	fs_prefs_save ();

	fake_state = g_strcmp0 (scenario, "push") == 0 ? FS_FW_RUNNING
	                                                : FS_FW_STOPPED;
}

static void
check_scenario (void)
{
	if (g_strcmp0 (scenario, "start") == 0) {
		CHECK (starts == 1, "start: the backend was started once "
		       "(got %u)", starts);
		CHECK (seen_at_start != NULL && seen_at_start->len == 2,
		       "start: the backend was handed the loaded policy, not "
		       "an empty one (%u rules at start, want 2)",
		       seen_at_start != NULL ? seen_at_start->len : 0);
		CHECK (seen (seen_at_start, FS_RULE_OUTBOUND_DENY_TO,
		             USER_BLOCK) &&
		       seen (seen_at_start, FS_RULE_INBOUND_ALLOW_FROM,
		             USER_ALLOW),
		       "start: both of the user's rules were in force");
		CHECK (!seen (seen_at_start, FS_RULE_OUTBOUND_DENY_TO,
		              SENTINEL_CSV),
		       "start: the expired Sentinel block was taken out "
		       "BEFORE the start, so it is not installed again");
		CHECK (audit_has ("firewall started"),
		       "start: the start is on the audit record");
		{
			FsPolicy *live = fs_policy_new ();

			CHECK (fs_apply_journal_load (live, NULL) &&
			       fs_policy_count (live,
			                        FS_RULE_OUTBOUND_DENY_TO) == 1,
			       "start: the journal records the started policy "
			       "as live");
			fs_policy_free (live);
		}
	} else if (g_strcmp0 (scenario, "held") == 0) {
		CHECK (starts == 0,
		       "held: start() was NOT called -- it would install "
		       "the policy file with its held changes (got %u)",
		       starts);
		CHECK (applies == 1 && seen_at_apply != NULL &&
		       seen_at_apply->len == 1 &&
		       seen (seen_at_apply, FS_RULE_OUTBOUND_DENY_TO,
		             USER_BLOCK),
		       "held: the last applied policy (the journal) was "
		       "started instead (%u applies, %u rules)", applies,
		       seen_at_apply != NULL ? seen_at_apply->len : 0);
		CHECK (audit_has ("started with the last applied policy"),
		       "held: the audit line says the changes stay held");
	} else if (g_strcmp0 (scenario, "heldnone") == 0) {
		CHECK (starts == 0 && applies == 0,
		       "heldnone: held and nothing ever applied -- the "
		       "firewall is not touched (%u starts, %u applies)",
		       starts, applies);
		CHECK (audit_has ("firewall start held"),
		       "heldnone: the held start is on the audit record");
	} else if (g_strcmp0 (scenario, "push") == 0) {
		CHECK (starts == 0, "push: start at launch is off, so no "
		       "start (got %u)", starts);
		CHECK (applies == 1 && seen_at_apply != NULL &&
		       !seen (seen_at_apply, FS_RULE_OUTBOUND_DENY_TO,
		              SENTINEL_CSV) &&
		       seen (seen_at_apply, FS_RULE_OUTBOUND_DENY_TO,
		             USER_BLOCK),
		       "push: the expired Sentinel block was pushed off the "
		       "running firewall, the user's block kept (%u applies)",
		       applies);
	} else if (g_strcmp0 (scenario, "stopped") == 0) {
		CHECK (starts == 0 && applies == 0,
		       "stopped: a stopped firewall is not started behind "
		       "the user's back by the Sentinel clean-up (%u starts, "
		       "%u applies)", starts, applies);
	} else {
		CHECK (FALSE, "unknown scenario %s", scenario);
	}

	{
		/* Whatever happened at the firewall, the policy file lost
		 * the expired block in every scenario. */
		FsPolicy *disk = fs_policy_new ();
		FsRule *probe = fs_rule_from_csv (FS_RULE_OUTBOUND_DENY_TO,
		                                  SENTINEL_CSV);

		fs_policy_load (disk, NULL);
		CHECK (probe != NULL && !fs_policy_contains (disk, probe),
		       "%s: the expired Sentinel row is gone from the policy "
		       "file", scenario);
		fs_rule_free (probe);
		fs_policy_free (disk);
	}
}

static void
on_activate (GtkApplication *app, gpointer data)
{
	(void) data;

	fs_app_activate (app);

	/* Let the pages' idle work run once. */
	for (gint i = 0; i < 50 && gtk_events_pending (); i++)
		gtk_main_iteration ();

	check_scenario ();
	fs_app_quit ();
}

static void
rm_rf (const gchar *path)
{
	GDir *dir = g_dir_open (path, 0, NULL);

	if (dir != NULL) {
		const gchar *name;

		while ((name = g_dir_read_name (dir)) != NULL) {
			gchar *child = g_build_filename (path, name, NULL);

			if (g_file_test (child, G_FILE_TEST_IS_DIR))
				rm_rf (child);
			else
				g_unlink (child);
			g_free (child);
		}
		g_dir_close (dir);
	}
	g_rmdir (path);
}

static int
run_all (const gchar *self)
{
	static const gchar *const all[] = {
		"start", "held", "heldnone", "push", "stopped"
	};
	int bad = 0;

	for (guint i = 0; i < G_N_ELEMENTS (all); i++) {
		gchar *argv[] = { (gchar *) self, (gchar *) all[i], NULL };
		gchar *out = NULL;
		gint status = 0;
		GError *error = NULL;

		if (!g_spawn_sync (NULL, argv, NULL, G_SPAWN_STDERR_TO_DEV_NULL,
		                   NULL, NULL, &out, NULL, &status, &error)) {
			printf ("FAIL: could not run scenario %s: %s\n", all[i],
			        error->message);
			g_clear_error (&error);
			bad++;
			continue;
		}
		fputs (out != NULL ? out : "", stdout);
		if (!g_spawn_check_wait_status (status, NULL)) {
			bad++;
			if (out == NULL || strstr (out, "FAIL") == NULL)
				printf ("FAIL: scenario %s exited badly\n",
				        all[i]);
		}
		g_free (out);
	}

	printf ("\nui-startup-smoke: %s: %d scenario(s) failed\n",
	        bad ? "FAILED" : "PASSED", bad);
	return bad ? 1 : 0;
}

int
main (int argc, char **argv)
{
	GtkApplication *app;

	if (argc < 2)
		return run_all (argv[0]);

	scenario = argv[1];
	prepare ();

	app = gtk_application_new ("org.stockfw.StartupSmoke",
	                           G_APPLICATION_NON_UNIQUE);
	g_signal_connect (app, "activate", G_CALLBACK (on_activate), NULL);
	{
		gchar *args[] = { argv[0], NULL };

		g_application_run (G_APPLICATION (app), 1, args);
	}
	g_object_unref (app);

	rm_rf (scratch);
	g_free (scratch);
	return failures ? 1 : 0;
}
