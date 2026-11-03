/*---[ ui-whatif-start-smoke.c ]-----------------------------------------
 * The What-If "Start the firewall" button goes through the start gate
 * (H12).
 *
 * It used to call fs_backend()->start() directly, so audit-only mode
 * did not hold it, nothing was audited, and on Linux the saved policy
 * (edits never applied) went live.  Now it goes through
 * fs_statusview_firewall_start() -> fs_firewall_start_safe(), like the
 * Overview's Start button and the tray's Resume.
 *
 * Runs the real fs_app_activate() against a fake backend that reads
 * "stopped" and counts starts and applies.  On the Copilot page it asks
 * the What-If card a question that the stopped firewall answers
 * ALLOWED, opens Details, presses "Start the firewall" and says Yes.
 * One process per scenario:
 *
 *   held     audit-only on, a backend whose start installs a policy
 *            (Linux), nothing applied before: held, the backend is not
 *            started, the user is told, an audit line is written;
 *   journal  the same, but a policy was applied before (the journal):
 *            the start installs the journal, not the saved file (the
 *            allow saved but never applied stays off), the backend's
 *            own start is never called, and the audit line says held;
 *   windows  audit-only on, a backend whose start only switches
 *            enforcement on (Windows): it starts, and the audit line
 *            names the hold;
 *   unheld   audit-only off (Linux model, nothing applied before): it
 *            starts once and is audited;
 *   winfail  audit-only on, Windows model, and the backend's start
 *            fails: the What-If window says it did not start, not that
 *            it was held (a hold never stops a Windows start);
 *   badjournal  audit-only on, Linux model, a journal that cannot be
 *            read: the start is refused, and the window says it did
 *            not start, not that it was held.
 *
 * Every scenario also checks the question asked before the start: on
 * Linux it says the last applied policy goes live (not "the saved
 * policy"), on Windows that the firewall is switched on.
 *
 * Needs a display (xvfb-run).  On Linux it needs root: the What-If
 * trusts a "stopped" reading only from root (fs-copilot.c,
 * whatif_state_reliable), and offers no Start button otherwise; it
 * prints SKIP then.  Everything goes to a scratch directory; the
 * backend is fake, so no firewall is touched.  Supplies fs_backend()
 * itself.  See tests/README.md.
 *--------------------------------------------------------------------*/

#include <gtk/gtk.h>
#include <glib/gstdio.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#ifndef G_OS_WIN32
#include <unistd.h>
#endif

#include "core/fs-apply.h"
#include "core/fs-backend.h"
#include "core/fs-netplace.h"
#include "core/fs-prefs.h"
#include "core/fs-rules.h"
#include "ui/fs-app.h"
#include "ui/fs-simviz.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	printf ((cond) ? "ok:   " : "FAIL: ");                  \
	printf (__VA_ARGS__);                                   \
	printf ("\n");                                          \
	fflush (stdout);                                        \
	if (!(cond))                                            \
		failures++;                                     \
} while (0)

/* The user's block (applied before, in the journal for "journal") and
 * an allow saved later and never applied. */
#define USER_BLOCK "198.51.100.7, my own block"
#define USER_ALLOW "192.0.2.10, office"

/* A question the stopped firewall answers ALLOWED and the rules, once
 * it runs, answer BLOCKED (inbound is blocked by default): the engine
 * offers "Start the firewall" for it. */
#define QUESTION "inbound tcp 8443 from 203.0.113.20"

/* ------------------------------------------------------- fake backend */

static FsFirewallState fake_state = FS_FW_STOPPED;
static guint           starts = 0, applies = 0;
static gboolean        start_fails = FALSE;
static GPtrArray      *seen_at_apply = NULL;   /* "kind|csv" */

static GPtrArray *
snapshot (const FsPolicy *policy)
{
	GPtrArray *rows = g_ptr_array_new_with_free_func (g_free);

	for (gint k = 0; policy != NULL && k < FS_RULE_N_KINDS; k++)
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
	starts++;
	if (start_fails) {
		g_set_error_literal (error, g_quark_from_static_string (
		                             "fake"), 1,
		                     "fake start failed");
		return FALSE;
	}
	fake_state = FS_FW_RUNNING;
	return TRUE;
}

static gboolean
fake_stop (GError **error)
{
	(void) error;
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

static FsNetworkPlace *
fake_place (void)
{
	FsNetworkPlace *place = fs_network_place_new ();

	fs_network_place_add (place, "HomeNet", FS_PROFILE_PRIVATE, "Wi-Fi",
	                      TRUE);
	place->in_use = FS_PROFILE_BIT (FS_PROFILE_PRIVATE);
	return place;
}

/* start_applies_policy is set per scenario in prepare(). */
static FsBackend fake_backend = {
	.name                 = "fake",
	.display_name         = "Fake (What-If start)",
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
	.network_place        = fake_place,
};

const FsBackend *
fs_backend (void)
{
	return &fake_backend;
}

const gchar *
fs_error_domain (void)
{
	return "fake";
}

void
fs_backend_set_context (FsPolicy *policy, FsSettings *settings)
{
	(void) policy;
	(void) settings;
}

/* ------------------------------------------------------------ dialogs */

/* Every message dialog is answered from a timer inside its own
 * gtk_dialog_run, the way a user would: Yes to a question, OK to the
 * rest.  Their text is kept. */
static GString *dialogs_seen = NULL;

static gboolean
answer_dialogs (gpointer data)
{
	GList *tops = gtk_window_list_toplevels ();

	(void) data;
	for (GList *l = tops; l != NULL; l = l->next) {
		GtkWidget *w = l->data;
		gchar *text = NULL, *secondary = NULL;
		GtkMessageType type = GTK_MESSAGE_OTHER;

		if (!GTK_IS_MESSAGE_DIALOG (w) || !gtk_widget_get_visible (w))
			continue;
		g_object_get (w, "text", &text, "secondary-text", &secondary,
		              "message-type", &type, NULL);
		g_string_append_printf (dialogs_seen, "[%s|%s]",
		                        text != NULL ? text : "",
		                        secondary != NULL ? secondary : "");
		g_free (text);
		g_free (secondary);
		gtk_dialog_response (GTK_DIALOG (w),
		                     type == GTK_MESSAGE_QUESTION
		                     ? GTK_RESPONSE_YES : GTK_RESPONSE_OK);
		break;
	}
	g_list_free (tops);
	return G_SOURCE_CONTINUE;
}

/* ------------------------------------------------------------- helpers */

static gchar *scratch = NULL;
static const gchar *scenario = NULL;

static void
pump (guint ms)
{
	gint64 until = g_get_monotonic_time () + (gint64) ms * 1000;

	do {
		while (gtk_events_pending ())
			gtk_main_iteration_do (FALSE);
		g_usleep (2000);
	} while (g_get_monotonic_time () < until);
}

static void
put_rule (FsPolicy *policy, FsRuleKind kind, const gchar *csv)
{
	FsRule *rule = fs_rule_from_csv (kind, csv);

	if (rule != NULL)
		fs_policy_add (policy, rule);
}

static gchar *
audit_text (void)
{
	gchar *path = g_build_filename (scratch, "audit.log", NULL);
	gchar *text = NULL;

	if (!g_file_get_contents (path, &text, NULL, NULL))
		text = g_strdup ("");
	g_free (path);
	return text;
}

/* One audit line that holds every one of the NULL-ended needles. */
static gboolean
audit_line (const gchar *first, ...)
{
	gchar *text = audit_text ();
	gchar **lines = g_strsplit (text, "\n", -1);
	gboolean hit = FALSE;

	for (guint i = 0; lines[i] != NULL && !hit; i++) {
		const gchar *needle = first;
		va_list ap;

		hit = TRUE;
		va_start (ap, first);
		for (; needle != NULL; needle = va_arg (ap, const gchar *))
			if (strstr (lines[i], needle) == NULL)
				hit = FALSE;
		va_end (ap);
	}
	g_strfreev (lines);
	g_free (text);
	return hit;
}

static GtkWidget *
main_window (void)
{
	GList *tops = gtk_window_list_toplevels ();
	GtkWidget *found = NULL;

	for (GList *l = tops; l != NULL && found == NULL; l = l->next)
		if (GTK_IS_APPLICATION_WINDOW (l->data))
			found = l->data;
	g_list_free (tops);
	return found;
}

/* The open What-If window, if any. */
static GtkWidget *
whatif_window_open (void)
{
	GList *tops = gtk_window_list_toplevels ();
	GtkWidget *hit = NULL;

	for (GList *l = tops; l != NULL && hit == NULL; l = l->next)
		if (gtk_widget_get_visible (l->data) &&
		    gtk_style_context_has_class (
			    gtk_widget_get_style_context (l->data), "fs-wi-dialog"))
			hit = l->data;
	g_list_free (tops);
	return hit;
}

/* The status line of the What-If window (what the action did). */
static gchar *
window_status (GtkWidget *win)
{
	GtkWidget *status = fs_simviz_find_named (win, "whatif-status");
	GString *all = g_string_new (NULL);
	GList *stack = NULL;

	/* Every label under the status row, joined. */
	if (status != NULL)
		stack = g_list_prepend (stack, status);
	while (stack != NULL) {
		GtkWidget *w = stack->data;

		stack = g_list_delete_link (stack, stack);
		if (GTK_IS_LABEL (w))
			g_string_append_printf (all, "%s ",
			                        gtk_label_get_text (GTK_LABEL (w)));
		if (GTK_IS_CONTAINER (w)) {
			GList *kids = gtk_container_get_children (
				GTK_CONTAINER (w));

			for (GList *k = kids; k != NULL; k = k->next)
				stack = g_list_append (stack, k->data);
			g_list_free (kids);
		}
	}
	return g_string_free (all, FALSE);
}

static void
prepare (void)
{
	gboolean held = g_strcmp0 (scenario, "unheld") != 0;
	FsPolicy *policy;
	gchar *path;

	scratch = g_dir_make_tmp ("stockfw-wistart-XXXXXX", NULL);
	g_setenv ("XDG_CONFIG_HOME", scratch, TRUE);
	g_setenv ("APPDATA", scratch, TRUE);
	g_setenv ("HOME", scratch, TRUE);
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
	SCRATCH_ENV ("STOCKFW_AUTOSTART_DIR", "autostart");
	/* This computer's addresses, fixed: none. */
	g_setenv ("STOCKFW_LOCAL_ADDRESSES", "", TRUE);

	/* The policy on disk: the user's block and an allow. */
	policy = fs_policy_new ();
	put_rule (policy, FS_RULE_OUTBOUND_DENY_TO, USER_BLOCK);
	put_rule (policy, FS_RULE_INBOUND_ALLOW_FROM, USER_ALLOW);
	fs_policy_save (policy);
	fs_policy_free (policy);

	/* journal: the block went live before; the allow never did. */
	if (g_strcmp0 (scenario, "journal") == 0) {
		FsPolicy *live = fs_policy_new ();

		put_rule (live, FS_RULE_OUTBOUND_DENY_TO, USER_BLOCK);
		fs_apply_journal_save (live, NULL);
		fs_policy_free (live);
	}

	/* badjournal: a journal is there but its row cannot be read. */
	if (g_strcmp0 (scenario, "badjournal") == 0) {
		gchar *journal = fs_apply_journal_path ();

		g_file_set_contents (journal, "not a journal row\n", -1,
		                     NULL);
		g_free (journal);
	}

	fake_backend.start_applies_policy =
		g_strcmp0 (scenario, "windows") != 0 &&
		g_strcmp0 (scenario, "winfail") != 0;
	start_fails = g_strcmp0 (scenario, "winfail") == 0;

	fs_prefs_init ();
	fs_prefs_load ();
	fs_prefs_set_defaults ();
	fs_prefs_set_bool (FS_PREFS_START_ON_GUI, FALSE);
	fs_prefs_set_bool (FS_PREFS_AUDIT_ONLY, held);
	fs_prefs_set_bool (FS_PREFS_ENABLE_TRAY_ICON, FALSE);
	fs_prefs_save ();
	dialogs_seen = g_string_new (NULL);
}

/* --------------------------------------------------------- the checks */

static void
press_start (void)
{
	GtkWidget *win = main_window ();
	GtkWidget *card, *entry, *btn, *wi;
	gchar *status;

	fs_app_show_page (FS_PAGE_COPILOT);
	pump (100);
	card = fs_simviz_find_named (win, "whatif-card");
	entry = fs_simviz_find_named (card, "whatif-entry");
	CHECK (card != NULL && entry != NULL,
	       "%s: the What-If card is on the Copilot page", scenario);
	if (entry == NULL)
		return;

	gtk_entry_set_text (GTK_ENTRY (entry), QUESTION);
	gtk_button_clicked (GTK_BUTTON (fs_simviz_find_named (
		card, "whatif-simulate")));
	pump (60);
	gtk_button_clicked (GTK_BUTTON (fs_simviz_find_named (
		card, "whatif-details")));
	pump (150);
	wi = whatif_window_open ();
	btn = wi != NULL ? fs_simviz_find_button (wi, "Start the firewall")
	                 : NULL;
	CHECK (btn != NULL && gtk_widget_is_sensitive (btn),
	       "%s: the stopped firewall gets a \"Start the firewall\" "
	       "button", scenario);
	if (btn == NULL)
		return;

	starts = applies = 0;
	gtk_button_clicked (GTK_BUTTON (btn));
	pump (200);

	CHECK (strstr (dialogs_seen->str, "Start the firewall now?") != NULL,
	       "%s: the start is asked first", scenario);
	CHECK (strstr (dialogs_seen->str, "loads the saved policy") == NULL,
	       "%s: the question does not promise the saved policy",
	       scenario);
	if (fake_backend.start_applies_policy)
		CHECK (strstr (dialogs_seen->str,
		               "filtering with the last policy") != NULL,
		       "%s: the question says the last applied policy goes "
		       "live", scenario);
	else
		CHECK (strstr (dialogs_seen->str,
		               "switches Windows Firewall on") != NULL,
		       "%s: the question says the firewall is switched on",
		       scenario);

	status = window_status (wi);
	if (g_strcmp0 (scenario, "held") == 0) {
		CHECK (starts == 0 && applies == 0 &&
		       fake_state == FS_FW_STOPPED,
		       "held: audit-only holds the start: the firewall was "
		       "not started (%u starts, %u applies)", starts, applies);
		CHECK (audit_line ("firewall start held", "what-if | held",
		                   "audit-only testing mode", NULL),
		       "held: an audit line says the What-If start was held");
		CHECK (strstr (dialogs_seen->str,
		               "The firewall was not started") != NULL,
		       "held: the user is told, as from the Start button");
		CHECK (strstr (status, "not started") != NULL &&
		       strstr (status, "audit-only") != NULL,
		       "held: the What-If window says it was not started and "
		       "why (\"%s\")", status);
	} else if (g_strcmp0 (scenario, "journal") == 0) {
		CHECK (starts == 0,
		       "journal: the backend's own start (the saved file) was "
		       "not used (%u starts)", starts);
		CHECK (applies == 1 &&
		       seen (seen_at_apply, FS_RULE_OUTBOUND_DENY_TO,
		             USER_BLOCK) &&
		       !seen (seen_at_apply, FS_RULE_INBOUND_ALLOW_FROM,
		              USER_ALLOW),
		       "journal: the last applied policy went in, the allow "
		       "never applied stayed off (%u applies)", applies);
		CHECK (audit_line ("firewall started", "what-if | held",
		                   "audit-only testing mode", NULL),
		       "journal: an audit line says it started held");
		CHECK (strstr (status, "last applied policy") != NULL,
		       "journal: the What-If window says the last applied "
		       "policy runs (\"%s\")", status);
	} else if (g_strcmp0 (scenario, "windows") == 0) {
		CHECK (starts == 1 && applies == 0,
		       "windows: enforcement switched on, rules unchanged "
		       "(%u starts, %u applies)", starts, applies);
		CHECK (audit_line ("firewall started", "what-if | start",
		                   "audit-only testing mode", NULL),
		       "windows: an audit line says it started, and names the "
		       "hold");
		CHECK (strstr (status, "was started") != NULL &&
		       strstr (status, "last applied") == NULL,
		       "windows: the What-If window says it was started "
		       "(\"%s\")", status);
	} else if (g_strcmp0 (scenario, "winfail") == 0) {
		CHECK (starts == 1 && fake_state == FS_FW_STOPPED,
		       "winfail: the start was tried and failed (%u starts)",
		       starts);
		CHECK (audit_line ("firewall start failed", "what-if", NULL),
		       "winfail: an audit line says the start failed");
		CHECK (strstr (dialogs_seen->str,
		               "Failed to start the firewall") != NULL,
		       "winfail: the error dialog says it failed");
		CHECK (strstr (status, "did not start") != NULL &&
		       strstr (status, "held") == NULL,
		       "winfail: the What-If window says it did not start, "
		       "not that it was held (\"%s\")", status);
	} else if (g_strcmp0 (scenario, "badjournal") == 0) {
		CHECK (starts == 0 && applies == 0 &&
		       fake_state == FS_FW_STOPPED,
		       "badjournal: the firewall was not touched (%u starts, "
		       "%u applies)", starts, applies);
		CHECK (audit_line ("firewall start refused", "what-if", NULL),
		       "badjournal: an audit line says the start was refused");
		CHECK (strstr (dialogs_seen->str,
		               "Failed to start the firewall") != NULL,
		       "badjournal: the error dialog says it failed");
		CHECK (strstr (status, "did not start") != NULL &&
		       strstr (status, "held") == NULL,
		       "badjournal: the What-If window says it did not start, "
		       "not that it was held (\"%s\")", status);
	} else if (g_strcmp0 (scenario, "unheld") == 0) {
		CHECK (starts == 1,
		       "unheld: the firewall was started once (%u starts)",
		       starts);
		CHECK (audit_line ("firewall started", "what-if | start",
		                   NULL),
		       "unheld: the start is audited");
		CHECK (strstr (status, "was started") != NULL,
		       "unheld: the What-If window says it was started "
		       "(\"%s\")", status);
	} else {
		CHECK (FALSE, "unknown scenario %s", scenario);
	}
	g_free (status);
}

static gboolean
run_checks (gpointer data)
{
	(void) data;
	press_start ();
	if (failures > 0) {
		gchar *text = audit_text ();

		printf ("  dialogs: %s\n  audit:\n%s\n", dialogs_seen->str,
		        text);
		g_free (text);
	}
	fs_app_quit ();
	return G_SOURCE_REMOVE;
}

static void
on_activate (GtkApplication *app, gpointer data)
{
	(void) data;

	fs_app_activate (app);
	pump (50);
	g_timeout_add (40, answer_dialogs, NULL);
	g_timeout_add (200, run_checks, NULL);
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
		"held", "journal", "windows", "unheld", "winfail",
		"badjournal"
	};
	int bad = 0;

#ifndef G_OS_WIN32
	if (geteuid () != 0) {
		printf ("SKIP: needs root on Linux (the What-If trusts a "
		        "\"stopped\" reading only from root)\n");
		return 0;
	}
#endif

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

	printf ("\nui-whatif-start-smoke: %s: %d scenario(s) failed\n",
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

	app = gtk_application_new ("org.stockfw.WhatIfStartSmoke",
	                           G_APPLICATION_NON_UNIQUE);
	g_signal_connect (app, "activate", G_CALLBACK (on_activate), NULL);
	{
		gchar *args[] = { argv[0], NULL };

		g_application_run (G_APPLICATION (app), 1, args);
	}
	g_object_unref (app);

	rm_rf (scratch);
	g_free (scratch);
	g_string_free (dialogs_seen, TRUE);
	return failures ? 1 : 0;
}
