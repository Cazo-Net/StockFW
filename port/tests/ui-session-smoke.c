/*---[ ui-session-smoke.c ]----------------------------------------------
 * Session safety (src/ui/fs-app.c, 1.0.7), driven against the REAL app.
 *
 * A copy that lives in the notification area is mostly ended by a
 * sign-out, a shutdown or a signal, not by its Quit item.  This runs
 * the real fs_app_activate() against a fake backend (it supplies
 * fs_backend() itself, and hands the app's own event callback back so
 * an event can be fed through the Events page into the Copilot) and
 * proves, each scenario in its own process:
 *
 *   autosave  (STOCKFW_AUTOSAVE_S=1 in place of five minutes)
 *     - with nothing changed, nothing is written;
 *     - a changed setting is written without quitting;
 *     - what the Copilot learned from an event is written;
 *     - a Sentinel staged-list write that failed is audited once, and
 *       retried until it goes through (audited again when it does);
 *   queryend
 *     - the session manager's query-end writes settings and baseline
 *       at once, does not inhibit the logout, and does not quit;
 *     - a session manager's Stop (g_application_quit straight away)
 *       still writes what changed after query-end;
 *   dialog
 *     - a quit that arrives while a dialog runs its own loop (a signal,
 *       --quit) writes everything and takes the icon down at once,
 *       frees nothing under the dialog, closes the dialog as its close
 *       button would, and finishes once the dialog has returned;
 *   prefs
 *     - the same with the Preferences window open, which is no
 *       GtkDialog and runs a loop of its own: the quit closes it as its
 *       Cancel would (a change made in it is not saved) and finishes;
 *   background (the window hidden, as "Minimize to the tray" leaves it)
 *     - a Sentinel block whose ten minutes run out while the window is
 *       hidden is lifted from the policy on time;
 *     - an event still reaches the Copilot: the contact that completes
 *       a timed series is staged as a Sentinel block, through the
 *       Events page's own callback;
 *     - what the Copilot learned is written by the periodic save;
 *     - the tray's Pause Sentinel item stays offered, pauses, and a
 *       paused Sentinel stages nothing;
 *     - nothing opens a window or a dialog meanwhile.
 *
 * Needs a display (xvfb-run).  Everything the app writes goes to a
 * scratch directory.
 *--------------------------------------------------------------------*/

#include <gtk/gtk.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-backend.h"
#include "core/fs-copilot.h"
#include "core/fs-netplace.h"
#include "core/fs-prefs.h"
#include "core/fs-rules.h"
#include "ui/fs-app.h"
#include "ui/fs-copilot.h"
#include "ui/fs-dialogs.h"
#include "ui/fs-statusview.h"
#include "ui/fs-tray.h"

/* fs-app.c's own instance: NULL once a quit has finished. */
extern FsCopilot *copilot;

static int failures = 0;

/* `cond' is evaluated once: some of them act. */
#define CHECK(cond, ...) do {                                   \
	gboolean ok_ = (cond) ? TRUE : FALSE;                   \
	printf (ok_ ? "ok:   " : "FAIL: ");                     \
	printf (__VA_ARGS__);                                   \
	printf ("\n");                                          \
	fflush (stdout);                                        \
	if (!ok_)                                               \
		failures++;                                     \
} while (0)

#define SENTINEL_CSV "203.0.113.9, Sentinel: beacon to 203.0.113.9"
/* The background scenario's timed contacts. */
#define BEACON_DEST  "203.0.113.77"
#define BEACON_DEST2 "203.0.113.78"
#define BEACON_APP   "beaconprobe"
#define PROBE_KEY    "/apps/stockfw/client/session_probe"

/* ------------------------------------------------------- fake backend */

static FsFirewallState fake_state = FS_FW_RUNNING;
static guint           stops = 0;
static FsLogFunc       log_cb = NULL;
static gpointer        log_user = NULL;

static gboolean fake_available (void) { return TRUE; }
static FsFirewallState fake_get_state (void) { return fake_state; }

static gboolean
fake_start (GError **error)
{
	(void) error;
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
	(void) policy;
	(void) error;
	fake_state = FS_FW_RUNNING;
	return FS_APPLY_OK;
}

static GList *fake_none (void) { return NULL; }

static gboolean
fake_log_start (FsLogFunc cb, gpointer user, GError **error)
{
	(void) error;
	log_cb = cb;
	log_user = user;
	return TRUE;
}
static void     fake_log_stop (void) { log_cb = NULL; }
static gboolean fake_log_active (void) { return log_cb != NULL; }
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
	.name                 = "fake",
	.display_name         = "Fake (session)",
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
	return "fake";
}

void
fs_backend_set_context (FsPolicy *policy, FsSettings *settings)
{
	(void) policy;
	(void) settings;
}

/* ------------------------------------------------------------- helpers */

static gchar *scratch = NULL;
static const gchar *scenario = NULL;
static GtkApplication *the_app = NULL;

static gchar *
in_scratch (const gchar *name)
{
	return g_build_filename (scratch, name, NULL);
}

/* Run the loop for `seconds' (timers included), from inside a
 * callback. */
static void
wait_s (gdouble seconds)
{
	gint64 until = g_get_monotonic_time () +
	               (gint64) (seconds * G_USEC_PER_SEC);

	while (g_get_monotonic_time () < until) {
		while (gtk_events_pending ())
			gtk_main_iteration_do (FALSE);
		g_usleep (10000);
	}
}

static gboolean
file_has (const gchar *path, const gchar *needle)
{
	gchar *text = NULL;
	gboolean hit;

	if (!g_file_get_contents (path, &text, NULL, NULL))
		return FALSE;
	hit = needle == NULL || strstr (text, needle) != NULL;
	g_free (text);
	return hit;
}

static guint
audit_count (const gchar *needle)
{
	gchar *path = in_scratch ("audit.log");
	gchar *text = NULL;
	guint n = 0;

	if (g_file_get_contents (path, &text, NULL, NULL)) {
		for (const gchar *p = strstr (text, needle); p != NULL;
		     p = strstr (p + 1, needle))
			n++;
	}
	g_free (text);
	g_free (path);
	return n;
}

static gchar *prefs_file = NULL;
static gchar *baseline_file = NULL;

static void
feed_event (void)
{
	FsHit *hit = fs_hit_new ();

	hit->time = g_strdup ("2026-11-02 10:42:01");
	hit->direction = g_strdup ("Out");
	hit->protocol = g_strdup ("TCP");
	hit->port = g_strdup ("8443");
	hit->source = g_strdup ("192.0.2.20");
	hit->destination = g_strdup ("198.51.100.7");
	hit->service = g_strdup ("sessionprobe");
	if (log_cb != NULL)
		log_cb (hit, log_user);
	fs_hit_free (hit);
}

static void
put_rule (FsPolicy *policy, FsRuleKind kind, const gchar *csv)
{
	FsRule *rule = fs_rule_from_csv (kind, csv);

	if (rule != NULL)
		fs_policy_add (policy, rule);
}

static void
prepare (void)
{
	FsPolicy *policy;
	gchar *path, *rows;
	gint64 now = g_get_real_time () / G_USEC_PER_SEC;

	scratch = g_dir_make_tmp ("stockfw-session-XXXXXX", NULL);
	g_setenv ("XDG_CONFIG_HOME", scratch, TRUE);
	g_setenv ("APPDATA", scratch, TRUE);
	g_setenv ("HOME", scratch, TRUE);
	path = in_scratch ("rules");
	g_setenv ("STOCKFW_RULES_DIR", path, TRUE);
	g_free (path);
#define SCRATCH_ENV(var, name) do {                               \
		gchar *p_ = in_scratch (name);                        \
		g_setenv (var, p_, TRUE);                             \
		g_free (p_);                                          \
	} while (0)
	SCRATCH_ENV ("STOCKFW_AUDIT_FILE", "audit.log");
	SCRATCH_ENV ("STOCKFW_APPLIED_FILE", "applied.csv");
	SCRATCH_ENV ("STOCKFW_AUTOBLOCK_FILE", "autoblocks");
	SCRATCH_ENV ("STOCKFW_BEHAVIOR_FILE", "behavior.csv");
	SCRATCH_ENV ("STOCKFW_TRUST_FILE", "trust.csv");
	SCRATCH_ENV ("STOCKFW_AUTOSTART_DIR", "autostart");
	if (g_strcmp0 (scenario, "autosave") == 0 ||
	    g_strcmp0 (scenario, "background") == 0)
		g_setenv ("STOCKFW_AUTOSAVE_S", "1", TRUE);
	else
		g_unsetenv ("STOCKFW_AUTOSAVE_S");

	baseline_file = in_scratch ("behavior.csv");

	/* The DNS servers and gateway the Copilot exempts, fixed, so the
	 * documentation addresses below are ordinary public hosts. */
	path = in_scratch ("resolv.conf");
	g_file_set_contents (path, "nameserver 192.0.2.53\n", -1, NULL);
	g_setenv ("STOCKFW_RESOLV_CONF", path, TRUE);
	g_free (path);
	path = in_scratch ("route");
	g_file_set_contents (path,
		"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\t"
		"Mask\t\tMTU\tWindow\tIRTT\n"
		"eth0\t00000000\t0102000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
		-1, NULL);
	g_setenv ("STOCKFW_ROUTE_FILE", path, TRUE);
	g_free (path);
	g_unsetenv ("STOCKFW_RESOLVED_CONF");

	/* Sentinel staged a block a minute ago (nine minutes left), so
	 * the restore re-arms it and there is a staged list to write.  In
	 * the background scenario it was staged nine minutes and 57
	 * seconds ago: its ten minutes run out while the window is
	 * hidden. */
	policy = fs_policy_new ();
	put_rule (policy, FS_RULE_OUTBOUND_DENY_TO, SENTINEL_CSV);
	fs_policy_save (policy);
	fs_policy_free (policy);
	rows = g_strdup_printf ("S,%" G_GINT64_FORMAT ",%d,%s\n",
	                        g_strcmp0 (scenario, "background") == 0
	                        ? now - 597 : now - 60,
	                        (int) FS_RULE_OUTBOUND_DENY_TO, SENTINEL_CSV);
	path = in_scratch ("autoblocks");
	g_file_set_contents (path, rows, -1, NULL);
	g_free (path);
	g_free (rows);

	fs_prefs_init ();
	fs_prefs_load ();
	fs_prefs_set_defaults ();
	fs_prefs_set_bool (FS_PREFS_START_ON_GUI, FALSE);
	fs_prefs_set_bool (FS_PREFS_ENABLE_TRAY_ICON, TRUE);
	fs_prefs_set_bool (FS_PREFS_SKIP_NOT_FOR_FIREWALL, FALSE);
	fs_prefs_set_string ("/apps/stockfw/client/sentinel/mode", "auto");
	fs_prefs_save ();
	prefs_file = g_strdup (fs_prefs_path ());
}

/* --------------------------------------------------------- the checks */

static void
check_autosave (void)
{
	gchar *good = in_scratch ("autoblocks");
	gchar *blocker = in_scratch ("not-a-dir");
	gchar *bad = g_build_filename (blocker, "autoblocks", NULL);

	/* Whatever starting up changed has had its round. */
	wait_s (1.5);

	/* 1. Nothing changed: nothing written. */
	g_unlink (prefs_file);
	g_unlink (baseline_file);
	wait_s (2.2);
	CHECK (!g_file_test (prefs_file, G_FILE_TEST_EXISTS) &&
	       !g_file_test (baseline_file, G_FILE_TEST_EXISTS),
	       "nothing changed: the periodic save writes nothing");

	/* 2. A changed setting is written while running. */
	fs_prefs_set_string (PROBE_KEY, "autosave");
	wait_s (2.2);
	CHECK (file_has (prefs_file, "session_probe=autosave"),
	       "a changed setting is written within the period, without "
	       "quitting");

	/* 3. What the Copilot learned is written. */
	feed_event ();
	wait_s (2.2);
	CHECK (file_has (baseline_file, "sessionprobe"),
	       "what the Copilot learned from an event is written within "
	       "the period");

	/* 4. A failed staged-list write is retried. */
	CHECK (file_has (good, "Sentinel: beacon to 203.0.113.9"),
	       "the restore re-armed the staged block (the list to write)");
	g_file_set_contents (blocker, "a file, not a directory", -1, NULL);
	g_setenv ("STOCKFW_AUTOBLOCK_FILE", bad, TRUE);
	CHECK (fs_copilot_lift_all_auto_blocks ("session smoke"),
	       "lifting the staged block rewrites the list");
	CHECK (audit_count ("auto-block state save failed") == 1,
	       "the failed write is audited (%u time(s))",
	       audit_count ("auto-block state save failed"));
	wait_s (2.2);
	CHECK (audit_count ("auto-block state save failed") == 1,
	       "retries against the same failure do not repeat the audit "
	       "line (%u)", audit_count ("auto-block state save failed"));
	CHECK (file_has (good, "Sentinel: beacon to 203.0.113.9"),
	       "(the old file still lists the lifted block)");
	g_setenv ("STOCKFW_AUTOBLOCK_FILE", good, TRUE);
	wait_s (2.2);
	CHECK (g_file_test (good, G_FILE_TEST_EXISTS) &&
	       !file_has (good, "Sentinel: beacon"),
	       "once the file can be written again, the periodic save "
	       "brings it up to date");
	CHECK (audit_count ("auto-block state saved after a failed write")
	       == 1, "...and audits that it did");
	CHECK (fs_copilot_autoblocks_flush (),
	       "the list is reported in step with its file");

	g_free (good);
	g_free (blocker);
	g_free (bad);
}

/* --- background: the window hidden behind the tray icon ----------- */

/* The policy as saved in the rules directory: what Sentinel staged or
 * lifted, read back from disk. */
static gboolean
policy_has (const gchar *target)
{
	FsPolicy *policy = fs_policy_new ();
	GPtrArray *rows;
	gboolean found = FALSE;

	fs_policy_load (policy, NULL);
	rows = policy->kinds[FS_RULE_OUTBOUND_DENY_TO];
	for (guint i = 0; rows != NULL && i < rows->len; i++) {
		FsRule *rule = g_ptr_array_index (rows, i);

		if (g_strcmp0 (rule->target, target) == 0)
			found = TRUE;
	}
	fs_policy_free (policy);
	return found;
}

static GtkWidget *
menu_item_prefixed (GtkWidget *menu, const gchar *prefix)
{
	GList *items = gtk_container_get_children (GTK_CONTAINER (menu));
	GtkWidget *found = NULL;

	for (GList *l = items; l != NULL && found == NULL; l = l->next)
		if (GTK_IS_MENU_ITEM (l->data) &&
		    !GTK_IS_SEPARATOR_MENU_ITEM (l->data) &&
		    g_str_has_prefix (gtk_menu_item_get_label (l->data),
		                      prefix))
			found = l->data;
	g_list_free (items);
	return found;
}

/* Visible top-level windows other than the tray icon itself. */
static guint
visible_windows (void)
{
	GList *tops = gtk_window_list_toplevels ();
	guint n = 0;

	for (GList *l = tops; l != NULL; l = l->next)
		if (gtk_widget_get_visible (l->data) &&
		    gtk_window_get_window_type (l->data) ==
		    GTK_WINDOW_TOPLEVEL &&
		    /* the icon's own plug, which is what stays up */
		    g_strcmp0 (G_OBJECT_TYPE_NAME (l->data),
		               "GtkTrayIcon") != 0)
			n++;
	g_list_free (tops);
	return n;
}

/* Seven contacts 30 s apart, the last 30 s ago, straight into the
 * app's Copilot (a test cannot wait three minutes); the eighth, which
 * completes the series, then comes now through the Events page's own
 * log callback, as the backend delivers it. */
static void
beacon_series (const gchar *dest)
{
	gint64 now_us = g_get_monotonic_time ();
	gint64 now_unix = g_get_real_time () / G_USEC_PER_SEC;
	FsHit *hit = fs_hit_new ();

	hit->time = g_strdup ("2026-11-02 10:42:01");
	hit->direction = g_strdup ("Out");
	hit->protocol = g_strdup ("TCP");
	hit->port = g_strdup ("4444");
	hit->source = g_strdup ("192.0.2.20");
	hit->destination = g_strdup (dest);
	hit->service = g_strdup (BEACON_APP);
	for (gint k = 7; k >= 1; k--)
		fs_copilot_feed_event_full (copilot, hit,
		                            now_us - (gint64) k * 30 *
		                            G_USEC_PER_SEC,
		                            now_unix - k * 30);
	if (log_cb != NULL)
		log_cb (hit, log_user);
	fs_hit_free (hit);
}

static void
check_background (void)
{
	GtkWindow *win = gtk_application_get_active_window (the_app);
	GtkWidget *item;
	gchar *list = in_scratch ("autoblocks");

	if (win == NULL) {
		GList *wins = gtk_application_get_windows (the_app);

		win = wins != NULL ? wins->data : NULL;
	}

	/* What the window's close does with the tray icon up and "Minimize
	 * to the tray" on (fs-app.c): it is hidden, nothing else.  The
	 * icon cannot embed without a notification area (xvfb), so the
	 * hide is done here directly. */
	CHECK (win != NULL && gtk_widget_get_visible (GTK_WIDGET (win)),
	       "(the window is up before it is hidden)");
	if (win == NULL)
		return;
	gtk_widget_hide (GTK_WIDGET (win));
	wait_s (0.3);
	CHECK (!gtk_widget_get_visible (GTK_WIDGET (win)) &&
	       visible_windows () == 0,
	       "(the window is hidden; nothing of StockFW is on screen)");
	CHECK (policy_has ("203.0.113.9") &&
	       file_has (list, "203.0.113.9"),
	       "(the restored Sentinel block is in the policy, about 3 s "
	       "left)");
	CHECK (log_cb != NULL,
	       "the Events page keeps monitoring with the window hidden");

	/* 1. Expiry runs while hidden. */
	wait_s (4.5);
	CHECK (!policy_has ("203.0.113.9") && !file_has (list, "203.0.113.9"),
	       "a Sentinel block whose ten minutes ran out while the window "
	       "was hidden is lifted from the policy and the staged list");
	CHECK (audit_count ("expired after 10 minutes") == 1,
	       "...and audited (%u)", audit_count ("expired after 10 minutes"));

	/* 2. Events reach the Copilot; Sentinel stages the block. */
	g_unlink (baseline_file);
	beacon_series (BEACON_DEST);
	CHECK (fs_copilot_events_seen (copilot) >= 8,
	       "an event delivered while hidden reaches the Copilot (%"
	       G_GUINT64_FORMAT " seen)", fs_copilot_events_seen (copilot));
	CHECK (policy_has (BEACON_DEST) && file_has (list, BEACON_DEST),
	       "the contact that completes a timed series is staged as a "
	       "Sentinel block while the window is hidden");
	CHECK (audit_count ("sentinel auto-block is live") >= 1,
	       "...and pushed through the apply gate");

	/* 3. The periodic save writes what was learned. */
	wait_s (2.2);
	CHECK (file_has (baseline_file, BEACON_APP),
	       "what the Copilot learned while hidden is written by the "
	       "periodic save");

	/* 4. The tray's Sentinel item works with the window hidden. */
	item = menu_item_prefixed (fs_tray_menu (),
	                           "Pause Sentinel auto-block for 1 hour");
	CHECK (item != NULL && gtk_widget_get_sensitive (item),
	       "the tray offers Pause Sentinel auto-block while hidden");
	if (item != NULL)
		gtk_menu_item_activate (GTK_MENU_ITEM (item));
	CHECK (fs_copilot_sentinel_paused (NULL) &&
	       menu_item_prefixed (fs_tray_menu (),
	                           "Resume Sentinel auto-block (paused, ")
	       != NULL,
	       "...it pauses Sentinel, and the menu says so");
	beacon_series (BEACON_DEST2);
	CHECK (!policy_has (BEACON_DEST2),
	       "a paused Sentinel stages nothing, window hidden or not");
	fs_copilot_sentinel_pause (0);

	/* 5. Nothing came up meanwhile. */
	wait_s (0.3);
	CHECK (!gtk_widget_get_visible (GTK_WIDGET (win)) &&
	       visible_windows () == 0,
	       "nothing opened a window or a dialog while hidden");

	g_free (list);
}

static void
check_queryend (void)
{
	g_unlink (prefs_file);
	g_unlink (baseline_file);
	fs_prefs_set_string (PROBE_KEY, "queryend");
	feed_event ();
	wait_s (0.5);
	CHECK (!g_file_test (prefs_file, G_FILE_TEST_EXISTS) &&
	       !g_file_test (baseline_file, G_FILE_TEST_EXISTS),
	       "(control: nothing is written before the five minutes)");

	g_signal_emit_by_name (the_app, "query-end");
	CHECK (file_has (prefs_file, "session_probe=queryend"),
	       "query-end writes the settings at once");
	CHECK (file_has (baseline_file, "sessionprobe"),
	       "query-end writes the Copilot baseline at once");
	CHECK (!gtk_application_is_inhibited (the_app,
	                                      GTK_APPLICATION_INHIBIT_LOGOUT),
	       "query-end does not hold up the logout");
	wait_s (0.3);
	CHECK (fs_tray_icon () != NULL && copilot != NULL,
	       "query-end does not quit: the session manager decides");
	CHECK (stops == 0 && fake_state == FS_FW_RUNNING,
	       "the firewall is left on");

	/* The session manager's Stop: GtkApplication quits by itself,
	 * without fs_app_quit().  Checked in main() once the run ends. */
	fs_prefs_set_string (PROBE_KEY, "stopped");
	g_application_quit (G_APPLICATION (the_app));
}

/* When the dialog or Preferences scenario made its quit.  "Promptly"
 * is measured from here: what came before it (building the window, and
 * on Windows asking the Task Scheduler for the sign-in switch) is not
 * the quit's time. */
static gint64 quit_at = 0;

static gint dialog_response = 0;

static gboolean
dialog_fallback (gpointer data)
{
	/* Without the fix nothing closes the dialog: do it here, with an
	 * answer the checks can tell apart. */
	gtk_dialog_response (GTK_DIALOG (data), GTK_RESPONSE_REJECT);
	return G_SOURCE_REMOVE;
}

static gboolean
quit_from_nested (gpointer data)
{
	(void) data;

	CHECK (g_main_depth () > 1,
	       "(the quit is dispatched inside the dialog's own loop)");
	g_unlink (prefs_file);
	g_unlink (baseline_file);
	fs_prefs_set_string (PROBE_KEY, "dialog");

	quit_at = g_get_monotonic_time ();
	fs_app_quit ();     /* what SIGTERM and --quit do */

	CHECK (file_has (prefs_file, "session_probe=dialog") &&
	       g_file_test (baseline_file, G_FILE_TEST_EXISTS),
	       "settings and baseline are written at once, dialog or not");
	CHECK (fs_tray_icon () == NULL, "the icon is taken down at once");
	CHECK (copilot != NULL,
	       "nothing is freed while the dialog's caller still runs");
	return G_SOURCE_REMOVE;
}

static gboolean
run_dialog (gpointer data)
{
	GtkWidget *dialog;
	guint fallback;

	(void) data;

	dialog = gtk_message_dialog_new (NULL, GTK_DIALOG_MODAL,
	                                 GTK_MESSAGE_QUESTION,
	                                 GTK_BUTTONS_OK_CANCEL,
	                                 "A dialog open at the quit");
	fallback = g_timeout_add (4000, dialog_fallback, dialog);
	g_timeout_add (300, quit_from_nested, NULL);

	dialog_response = gtk_dialog_run (GTK_DIALOG (dialog));

	CHECK (dialog_response == GTK_RESPONSE_DELETE_EVENT,
	       "the dialog is closed as its close button would (response "
	       "%d)", dialog_response);
	CHECK (copilot != NULL,
	       "its caller still finds everything in place when it returns");
	if (dialog_response != GTK_RESPONSE_REJECT)
		g_source_remove (fallback);
	gtk_widget_destroy (dialog);
	return G_SOURCE_REMOVE;
}

/* --- prefs: a quit while the Preferences window is open ---------------
 * That window is no GtkDialog: it runs a loop of its own, so closing
 * GtkDialogs alone left the quit waiting for whoever sat at the
 * computer to close it. */

static gboolean prefs_fallback_fired = FALSE;
static gboolean prefs_redundant_before = FALSE;

static GtkWidget *
find_named (GtkWidget *root, const gchar *name)
{
	GtkWidget *found = NULL;

	if (root == NULL)
		return NULL;
	if (g_strcmp0 (gtk_widget_get_name (root), name) == 0)
		return root;
	if (GTK_IS_CONTAINER (root)) {
		GList *kids = gtk_container_get_children (GTK_CONTAINER (root));

		for (GList *l = kids; l != NULL && found == NULL; l = l->next)
			found = find_named (l->data, name);
		g_list_free (kids);
	}
	return found;
}

static GtkWidget *
prefs_window (void)
{
	GList *tops = gtk_window_list_toplevels ();
	GtkWidget *found = NULL;

	for (GList *l = tops; l != NULL && found == NULL; l = l->next)
		if (g_strcmp0 (gtk_widget_get_name (l->data),
		               "fs-preferences") == 0 &&
		    gtk_widget_get_visible (l->data))
			found = l->data;
	g_list_free (tops);
	return found;
}

static gboolean
prefs_fallback (gpointer data)
{
	GtkWidget *win = prefs_window ();

	(void) data;
	/* Without the fix nothing closes the window: do it here, so the
	 * checks can tell. */
	prefs_fallback_fired = TRUE;
	if (win != NULL)
		gtk_button_clicked (GTK_BUTTON (find_named (win,
		                                            "prefs-cancel")));
	return G_SOURCE_REMOVE;
}

static gboolean
quit_from_prefs (gpointer data)
{
	GtkWidget *win = prefs_window ();
	GtkWidget *sw = find_named (win, FS_PREFS_SKIP_REDUNDANT);

	(void) data;
	CHECK (win != NULL && sw != NULL && g_main_depth () > 1,
	       "(Preferences is open, its own loop running the quit)");
	/* An unsaved change in it. */
	if (sw != NULL)
		gtk_switch_set_active (GTK_SWITCH (sw), !prefs_redundant_before);

	quit_at = g_get_monotonic_time ();
	fs_app_quit ();     /* what SIGTERM and --quit do */

	CHECK (fs_tray_icon () == NULL, "the icon is taken down at once");
	CHECK (copilot != NULL,
	       "nothing is freed while Preferences' caller still runs");
	return G_SOURCE_REMOVE;
}

static gboolean
run_prefs (gpointer data)
{
	guint fallback;

	(void) data;

	prefs_redundant_before = fs_prefs_bool (FS_PREFS_SKIP_REDUNDANT);
	fallback = g_timeout_add (4000, prefs_fallback, NULL);
	g_timeout_add (300, quit_from_prefs, NULL);

	fs_dialogs_preferences (GTK_WIDGET (
		gtk_application_get_active_window (the_app)));

	CHECK (!prefs_fallback_fired,
	       "the quit closes the Preferences window");
	CHECK (prefs_window () == NULL, "...and it is gone");
	CHECK (fs_prefs_bool (FS_PREFS_SKIP_REDUNDANT) ==
	       prefs_redundant_before &&
	       !file_has (prefs_file, prefs_redundant_before
	                              ? "redundant=false" : "redundant=true"),
	       "...as Cancel: the change made in it is not saved");
	CHECK (copilot != NULL,
	       "its caller still finds everything in place when it returns");
	if (!prefs_fallback_fired)
		g_source_remove (fallback);
	return G_SOURCE_REMOVE;
}

/* The quit and a timer that reads the shared policy come due in the
 * same loop pass (a loop that was late, as a stopped or busy process
 * is): GLib dispatches both, the reader after the quit.  It used to
 * find the policy freed under it -- the Overview's 2 s refresh did,
 * after a SIGTERM. */
static gboolean same_tick_ran = FALSE;

static gboolean
same_tick_quit (gpointer data)
{
	(void) data;

	fs_app_quit ();
	return G_SOURCE_REMOVE;
}

static gboolean
same_tick_reader (gpointer data)
{
	(void) data;

	same_tick_ran = TRUE;
	CHECK (copilot != NULL,
	       "a timer due in the same loop pass as the quit still finds "
	       "everything in place");
	/* What the Overview's refresh does with the shared policy. */
	fs_statusview_set_state (FS_FW_RUNNING);
	return G_SOURCE_REMOVE;
}

static gboolean
arm_same_tick (gpointer data)
{
	(void) data;

	g_timeout_add (20, same_tick_quit, NULL);
	g_timeout_add (20, same_tick_reader, NULL);
	/* Late: both are overdue by the next pass. */
	g_usleep (150 * 1000);
	return G_SOURCE_REMOVE;
}

static gboolean
run_checks (gpointer data)
{
	(void) data;

	if (g_strcmp0 (scenario, "autosave") == 0) {
		check_autosave ();
		fs_app_quit ();
	} else if (g_strcmp0 (scenario, "queryend") == 0) {
		check_queryend ();
	} else if (g_strcmp0 (scenario, "background") == 0) {
		check_background ();
		fs_app_quit ();
	}
	return G_SOURCE_REMOVE;
}

static void
on_activate (GtkApplication *app, gpointer data)
{
	(void) data;

	the_app = app;
	fs_app_activate (app);
	while (gtk_events_pending ())
		gtk_main_iteration ();

	if (g_strcmp0 (scenario, "dialog") == 0)
		g_timeout_add (200, run_dialog, NULL);
	else if (g_strcmp0 (scenario, "prefs") == 0)
		g_timeout_add (200, run_prefs, NULL);
	else if (g_strcmp0 (scenario, "sametick") == 0)
		g_timeout_add (200, arm_same_tick, NULL);
	else
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
	static const gchar *const all[] = { "autosave", "queryend", "dialog",
	                                    "prefs", "sametick",
	                                    "background" };
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

	printf ("\nui-session-smoke: %s: %d scenario(s) failed\n",
	        bad ? "FAILED" : "PASSED", bad);
	return bad ? 1 : 0;
}

int
main (int argc, char **argv)
{
	GtkApplication *app;
	gint64 started;

	if (argc < 2)
		return run_all (argv[0]);

	scenario = argv[1];
	prepare ();

	app = gtk_application_new ("org.stockfw.SessionSmoke",
	                           G_APPLICATION_NON_UNIQUE);
	g_signal_connect (app, "activate", G_CALLBACK (on_activate), NULL);
	started = g_get_monotonic_time ();
	{
		gchar *args[] = { argv[0], NULL };

		g_application_run (G_APPLICATION (app), 1, args);
	}

	if (g_strcmp0 (scenario, "queryend") == 0)
		CHECK (file_has (prefs_file, "session_probe=stopped"),
		       "a Stop without fs_app_quit() still writes what "
		       "changed after query-end");
	if (g_strcmp0 (scenario, "sametick") == 0) {
		CHECK (same_tick_ran,
		       "(the reader ran in the quit's loop pass)");
		CHECK (copilot == NULL,
		       "everything is freed once the loop has ended");
	}
	if (g_strcmp0 (scenario, "dialog") == 0 ||
	    g_strcmp0 (scenario, "prefs") == 0) {
		gint64 now = g_get_monotonic_time ();

		CHECK (copilot == NULL,
		       "the quit finished once the %s had returned",
		       g_strcmp0 (scenario, "prefs") == 0
		       ? "Preferences window" : "dialog");
		/* Left to its 4 s fallback, the window would close >= 3.7 s
		 * after the quit. */
		CHECK (quit_at != 0 && now - quit_at < 2 * G_USEC_PER_SEC,
		       "...promptly (%.2f s after the quit, %.2f s after "
		       "the start)",
		       quit_at != 0 ? (now - quit_at) / (gdouble) G_USEC_PER_SEC
		                    : -1.0,
		       (now - started) / (gdouble) G_USEC_PER_SEC);
	}
	CHECK (stops == 0, "%s: no path here stopped the firewall",
	       scenario);
	g_object_unref (app);

	rm_rf (scratch);
	g_free (scratch);
	g_free (prefs_file);
	g_free (baseline_file);
	return failures ? 1 : 0;
}
