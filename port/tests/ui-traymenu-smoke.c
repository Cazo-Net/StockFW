/*---[ ui-traymenu-smoke.c ]---------------------------------------------
 * The tray menu (src/ui/fs-tray.c), driven against the REAL app.
 *
 * Runs the real fs_app_activate() against a fake backend (it supplies
 * fs_backend() itself) that records starts and stops, reports a
 * Private network, and hands the app's own event callback back to the
 * test so a blocked event can be fed through the whole pipeline: event
 * monitor -> Events page -> Overview -> the tray's tally.  Then it
 * works every row of the menu the way a click would (the "activate"
 * signal), answering the dialogs that come up:
 *
 *   - "Firewall: On - Private network" and "Blocked today: N" are
 *     greyed information rows and follow the state and the events;
 *   - Recent blocks lists the block as "TCP 445 to 203.0.113.5 (hh:mm)"
 *     and a click on it brings the window up on the Events page;
 *   - Go to opens each of the six pages;
 *   - Pause protection asks first (Cancel leaves the firewall alone),
 *     stops it only on "Pause protection", and then reads Resume
 *     protection, which starts it again; greyed with a reason when the
 *     backend is not available;
 *   - a firewall stopped or started OUTSIDE StockFW shows as such when
 *     the menu opens, and on the slow timer with no menu open;
 *   - Pause Sentinel auto-block pauses and resumes, both audited; it is
 *     greyed with a reason when Sentinel is in detect mode (scenario
 *     "detect", its own process) and in a copy that cannot change the
 *     firewall;
 *   - Start at sign-in writes and removes the autostart entry, and a
 *     failure shows an error and leaves the tick showing the truth;
 *   - Preferences and About open their dialogs; Help opens the Help
 *     window at "Running in the background" with the main window left
 *     hidden;
 *   - Quit (firewall stays on) quits without stopping the firewall.
 *
 * Needs a display (xvfb-run).  Everything the app writes goes to a
 * scratch directory.  STOCKFW_TRAYMENU_SHOT=<file.png> with the "main"
 * scenario: instead of the checks, feed two blocks, pop the menu up
 * with Recent blocks open, and save a screenshot of the screen.
 *--------------------------------------------------------------------*/

#include <gtk/gtk.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-backend.h"
#include "core/fs-netplace.h"
#include "core/fs-prefs.h"
#include "core/fs-rules.h"
#include "ui/fs-app.h"
#include "ui/fs-copilot.h"
#include "ui/fs-helpwindow.h"
#include "ui/fs-tray.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	printf ((cond) ? "ok:   " : "FAIL: ");                  \
	printf (__VA_ARGS__);                                   \
	printf ("\n");                                          \
	fflush (stdout);                                        \
	if (!(cond))                                            \
		failures++;                                     \
} while (0)

/* ------------------------------------------------------- fake backend */

static FsFirewallState fake_state = FS_FW_RUNNING;
static gboolean        fake_avail = TRUE;
static guint           starts = 0, stops = 0;
static FsLogFunc       log_cb = NULL;
static gpointer        log_user = NULL;

static gboolean fake_available (void) { return fake_avail; }
static FsFirewallState fake_get_state (void) { return fake_state; }

static gboolean
fake_start (GError **error)
{
	(void) error;
	starts++;
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

static FsNetworkPlace *
fake_place (void)
{
	FsNetworkPlace *place = fs_network_place_new ();

	fs_network_place_add (place, "HomeNet", FS_PROFILE_PRIVATE, "Wi-Fi",
	                      TRUE);
	place->in_use = FS_PROFILE_BIT (FS_PROFILE_PRIVATE);
	return place;
}

static const FsBackend fake_backend = {
	.name                 = "fake",
	.display_name         = "Fake (tray menu)",
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

/* Every dialog that comes up is answered by this timer with
 * `answer', and its title recorded: the menu's dialogs run nested
 * main loops (gtk_dialog_run), so the test cannot answer them inline. */
static gint     answer = GTK_RESPONSE_CANCEL;
static GString *dialogs_seen = NULL;
static gboolean saw_cancel_default = FALSE;

/* The widget called `name' inside `root', or NULL. */
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

/* Section 8: when the Preferences window opened from the tray comes up,
 * prefs_with (if set) is run on it instead of closing it with Cancel. */
static void (*prefs_with) (GtkWidget *prefs) = NULL;

static gboolean
answer_dialogs (gpointer data)
{
	GList *tops = gtk_window_list_toplevels ();

	(void) data;

	for (GList *l = tops; l != NULL; l = l->next) {
		GtkWidget *w = l->data;
		const gchar *title;

		/* The Preferences window (fs-prefsdialog.c) is a window with
		 * its own loop, not a GtkDialog: closed with its Cancel. */
		if (g_strcmp0 (gtk_widget_get_name (w), "fs-preferences") == 0 &&
		    gtk_widget_get_visible (w)) {
			GtkWidget *cancel = find_named (w, "prefs-cancel");

			title = gtk_window_get_title (GTK_WINDOW (w));
			g_string_append_printf (dialogs_seen, "[%s]",
			                        title != NULL ? title : "");
			if (prefs_with != NULL) {
				void (*with) (GtkWidget *) = prefs_with;

				prefs_with = NULL;
				with (w);
			} else if (cancel != NULL) {
				gtk_button_clicked (GTK_BUTTON (cancel));
			}
			continue;
		}
		if (!GTK_IS_DIALOG (w) || !gtk_widget_get_visible (w))
			continue;
		title = gtk_window_get_title (GTK_WINDOW (w));
		g_string_append_printf (dialogs_seen, "[%s]",
		                        title != NULL ? title : "");
		if (g_strcmp0 (title, "Pause protection") == 0) {
			GtkWidget *def = gtk_dialog_get_widget_for_response (
				GTK_DIALOG (w), GTK_RESPONSE_CANCEL);

			saw_cancel_default = def != NULL &&
			                     gtk_widget_has_default (def);
		}
		if (GTK_IS_ABOUT_DIALOG (w))
			gtk_dialog_response (GTK_DIALOG (w),
			                     GTK_RESPONSE_DELETE_EVENT);
		else
			gtk_dialog_response (GTK_DIALOG (w), answer);
	}
	g_list_free (tops);
	return G_SOURCE_CONTINUE;
}

/* ------------------------------------------------------------- helpers */

static gchar *scratch = NULL;
static const gchar *scenario = NULL;

static void
pump (void)
{
	for (gint i = 0; i < 200 && gtk_events_pending (); i++)
		gtk_main_iteration ();
}

static GtkWidget *
item_at (GtkWidget *menu, guint index)
{
	GList *items = gtk_container_get_children (GTK_CONTAINER (menu));
	GtkWidget *w = g_list_nth_data (items, index);

	g_list_free (items);
	return w;
}

static GtkWidget *
item_labelled (GtkWidget *menu, const gchar *label)
{
	GList *items = gtk_container_get_children (GTK_CONTAINER (menu));
	GtkWidget *found = NULL;

	for (GList *l = items; l != NULL && found == NULL; l = l->next)
		if (GTK_IS_MENU_ITEM (l->data) &&
		    !GTK_IS_SEPARATOR_MENU_ITEM (l->data) &&
		    g_strcmp0 (gtk_menu_item_get_label (l->data), label) == 0)
			found = l->data;
	g_list_free (items);
	return found;
}

static GtkWidget *
item_prefixed (GtkWidget *menu, const gchar *prefix)
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

static const gchar *
label_of (GtkWidget *item)
{
	return item != NULL ? gtk_menu_item_get_label (GTK_MENU_ITEM (item))
	                    : "(missing)";
}

static void
click (GtkWidget *item)
{
	if (item != NULL)
		gtk_menu_item_activate (GTK_MENU_ITEM (item));
	pump ();
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

static GtkWindow *
main_window (void)
{
	GList *tops = gtk_window_list_toplevels ();
	GtkWindow *found = NULL;

	for (GList *l = tops; l != NULL && found == NULL; l = l->next)
		if (GTK_IS_APPLICATION_WINDOW (l->data))
			found = l->data;
	g_list_free (tops);
	return found;
}

static guint
prefs_count (void)
{
	GList *tops = gtk_window_list_toplevels ();
	guint n = 0;

	for (GList *l = tops; l != NULL; l = l->next)
		if (g_strcmp0 (gtk_widget_get_name (l->data),
		               "fs-preferences") == 0 &&
		    gtk_widget_get_visible (l->data))
			n++;
	g_list_free (tops);
	return n;
}

static gboolean prefs_opened = FALSE;
static gboolean prefs_nested = FALSE;

/* A second Preferences window opened inside the first would run its own
 * loop under this check, where answer_dialogs (being dispatched) cannot
 * close it: this closes it instead, and says it was there. */
static gboolean
close_nested_prefs (gpointer data)
{
	GList *tops = gtk_window_list_toplevels ();

	for (GList *l = tops; l != NULL; l = l->next)
		if (l->data != data &&
		    g_strcmp0 (gtk_widget_get_name (l->data),
		               "fs-preferences") == 0 &&
		    gtk_widget_get_visible (l->data)) {
			GtkWidget *cancel = find_named (l->data, "prefs-cancel");

			prefs_nested = TRUE;
			if (cancel != NULL)
				gtk_button_clicked (GTK_BUTTON (cancel));
		}
	g_list_free (tops);
	return G_SOURCE_CONTINUE;
}

/* The tray's Start at sign-in item, as it was while Preferences was
 * open: read afterwards WITHOUT opening the menu again (which re-reads
 * the setting anyway), so the check sees what Preferences told it. */
static GtkWidget *signin_item = NULL;

/* Section 8: the Preferences window the tray opened, while it is open
 * (its own loop is running under this). */
static void
with_prefs (GtkWidget *prefs)
{
	GtkWindow *main = main_window ();

	prefs_opened = TRUE;
	CHECK (main != NULL && gtk_widget_get_visible (GTK_WIDGET (main)) &&
	       gtk_window_get_transient_for (GTK_WINDOW (prefs)) == main,
	       "from the tray, the hidden window comes up first and "
	       "Preferences opens over it");

	/* One at a time: asked for again from the tray, no second one. */
	{
		guint closer = g_timeout_add (1000, close_nested_prefs, prefs);

		gtk_menu_item_activate (GTK_MENU_ITEM (
			item_labelled (fs_tray_menu (), "Pr_eferences...")));
		g_source_remove (closer);
	}
	CHECK (!prefs_nested && prefs_count () == 1,
	       "Preferences... while it is open: still one window (%u%s)",
	       prefs_count (), prefs_nested ? ", a second one opened inside "
	                                      "it" : "");

#ifdef G_OS_WIN32
	/* Start at sign-in would register a real Task Scheduler task. */
	gtk_button_clicked (GTK_BUTTON (find_named (prefs, "prefs-cancel")));
#else
	{
		gchar *entry_path = g_build_filename (scratch, "autostart",
		                                      "stockfw.desktop", NULL);
		GtkWidget *sw = find_named (prefs, "prefs-signin");
		GtkWidget *status = find_named (prefs, "prefs-status");
		GtkWidget *item = item_labelled (fs_tray_menu (),
		                                 "_Start at sign-in");

		signin_item = item;
		CHECK (sw != NULL && item != NULL &&
		       !gtk_switch_get_active (GTK_SWITCH (sw)) &&
		       !gtk_check_menu_item_get_active (
		           GTK_CHECK_MENU_ITEM (item)) &&
		       !g_file_test (entry_path, G_FILE_TEST_EXISTS),
		       "Preferences shows Start at sign-in as the tray does "
		       "(off)");

		/* The tray changes it while Preferences is open. */
		gtk_menu_item_activate (GTK_MENU_ITEM (item));
		CHECK (g_file_test (entry_path, G_FILE_TEST_EXISTS) &&
		       gtk_check_menu_item_get_active (
		           GTK_CHECK_MENU_ITEM (item)) &&
		       sw != NULL && gtk_switch_get_active (GTK_SWITCH (sw)) &&
		       g_strcmp0 (gtk_label_get_text (GTK_LABEL (status)),
		                  "No changes") == 0,
		       "ticked in the tray, the open Preferences switch "
		       "follows, with nothing to save");

		/* Preferences changes it back: only on Save. */
		if (sw != NULL)
			gtk_switch_set_active (GTK_SWITCH (sw), FALSE);
		CHECK (g_file_test (entry_path, G_FILE_TEST_EXISTS) &&
		       gtk_check_menu_item_get_active (
		           GTK_CHECK_MENU_ITEM (item)),
		       "moving the Preferences switch changes nothing before "
		       "Save");
		g_free (entry_path);
		gtk_button_clicked (GTK_BUTTON (find_named (prefs,
		                                            "prefs-save")));
	}
#endif
}

static void
prepare (void)
{
	gchar *path;

	scratch = g_dir_make_tmp ("stockfw-traymenu-XXXXXX", NULL);
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
	/* The tray's slow refresh, every second instead of every minute. */
	g_setenv ("STOCKFW_TRAY_REFRESH_S", "1", TRUE);

	fs_prefs_init ();
	fs_prefs_load ();
	fs_prefs_set_defaults ();
	fs_prefs_set_bool (FS_PREFS_START_ON_GUI, FALSE);
	fs_prefs_set_bool (FS_PREFS_ENABLE_TRAY_ICON, TRUE);
	/* Count an inbound block even though it is not addressed to one
	 * of this machine's (fake, empty) interfaces. */
	fs_prefs_set_bool (FS_PREFS_SKIP_NOT_FOR_FIREWALL, FALSE);
	fs_prefs_set_string ("/apps/stockfw/client/sentinel/mode",
	                     g_strcmp0 (scenario, "detect") == 0 ? "detect"
	                                                         : "auto");
	fs_prefs_save ();
	dialogs_seen = g_string_new (NULL);
}

static FsHit *
blocked_hit (void)
{
	FsHit *hit = fs_hit_new ();

	hit->time = g_strdup ("2026-11-02 10:42:01");
	hit->direction = g_strdup ("Out");
	hit->protocol = g_strdup ("TCP");
	hit->port = g_strdup ("445");
	hit->source = g_strdup ("192.0.2.20");
	hit->destination = g_strdup ("203.0.113.5");
	hit->service = g_strdup ("microsoft-ds [BLOCKED]");
	return hit;
}

/* --------------------------------------------------------- the checks */

static void
check_detect (void)
{
	GtkWidget *menu = fs_tray_menu ();
	GtkWidget *item = item_labelled (menu, "Pause Sentinel auto-block "
	                                       "for 1 hour");

	CHECK (item != NULL && !gtk_widget_get_sensitive (item) &&
	       gtk_widget_get_tooltip_text (item) != NULL,
	       "detect mode: Pause Sentinel is greyed, with the reason as "
	       "its tooltip");
}

static void
check_main (void)
{
	GtkWidget *menu = fs_tray_menu ();
	GtkWidget *recent_item, *recent_sub, *item, *go_sub;
	GtkWindow *window = main_window ();
	gchar *expect, *hhmm, *entry;
	GDateTime *now;
	static const struct { const gchar *label; FsAppPage page; } pages[] = {
		{ "Overview", FS_PAGE_OVERVIEW }, { "Events", FS_PAGE_EVENTS },
		{ "Activity", FS_PAGE_ACTIVITY }, { "Policy", FS_PAGE_POLICY },
		{ "Copilot", FS_PAGE_COPILOT },   { "Trust", FS_PAGE_TRUST },
	};

	/* 1. The information rows. */
	CHECK (g_strcmp0 (label_of (item_at (menu, 0)),
	                  "Firewall: On - Private network") == 0,
	       "row 1 reads \"Firewall: On - Private network\" (got \"%s\")",
	       label_of (item_at (menu, 0)));
	CHECK (g_strcmp0 (label_of (item_at (menu, 1)),
	                  "Blocked today: 0") == 0,
	       "row 2 reads \"Blocked today: 0\" (got \"%s\")",
	       label_of (item_at (menu, 1)));
	CHECK (!gtk_widget_get_sensitive (item_at (menu, 0)) &&
	       !gtk_widget_get_sensitive (item_at (menu, 1)),
	       "both are greyed information rows");

	recent_item = item_labelled (menu, "_Recent blocks");
	recent_sub = recent_item != NULL
	           ? gtk_menu_item_get_submenu (GTK_MENU_ITEM (recent_item))
	           : NULL;
	CHECK (recent_sub != NULL &&
	       g_strcmp0 (label_of (item_at (recent_sub, 0)),
	                  "Nothing blocked since StockFW started") == 0 &&
	       !gtk_widget_get_sensitive (item_at (recent_sub, 0)),
	       "Recent blocks, with nothing blocked yet, says so in a "
	       "greyed row");

	/* 2. A blocked event, through the app's own monitor callback. */
	CHECK (log_cb != NULL, "the app started its event monitor");
	if (log_cb != NULL) {
		FsHit *hit = blocked_hit ();

		now = g_date_time_new_now_local ();
		log_cb (hit, log_user);
		hhmm = g_date_time_format (now, "%H:%M");
		g_date_time_unref (now);
		fs_hit_free (hit);
		pump ();
	} else {
		hhmm = g_strdup ("");
	}
	menu = fs_tray_menu ();
	CHECK (g_strcmp0 (label_of (item_at (menu, 1)),
	                  "Blocked today: 1") == 0,
	       "a blocked event counts: \"Blocked today: 1\" (got \"%s\")",
	       label_of (item_at (menu, 1)));
	expect = g_strdup_printf ("TCP 445 to 203.0.113.5 (%s)", hhmm);
	entry = g_strdup (label_of (item_at (recent_sub, 0)));
	CHECK (g_strcmp0 (entry, expect) == 0 &&
	       gtk_widget_get_sensitive (item_at (recent_sub, 0)),
	       "Recent blocks lists \"%s\" (got \"%s\")", expect, entry);
	g_free (expect);
	g_free (entry);
	g_free (hhmm);
	{
		GtkStatusIcon *icon = fs_tray_icon ();
		gchar *tip = NULL;

		G_GNUC_BEGIN_IGNORE_DEPRECATIONS
		if (icon != NULL)
			tip = gtk_status_icon_get_tooltip_text (icon);
		G_GNUC_END_IGNORE_DEPRECATIONS
		CHECK (g_strcmp0 (tip, "StockFW - Firewall on, 1 blocked "
		                       "today") == 0,
		       "the tooltip reads \"StockFW - Firewall on, 1 blocked "
		       "today\" (got \"%s\")", tip != NULL ? tip : "(none)");
		g_free (tip);
	}

	/* 3. A recent block opens the Events page, window and all. */
	if (window != NULL)
		gtk_widget_hide (GTK_WIDGET (window));
	/* Let the unmap land first, as it has long before anyone clicks
	 * the tray: with no window manager X reports the unmapped window
	 * as iconified, and with an icon up "Minimize to the tray" would
	 * act on that stale event after the click. */
	for (gint i = 0; i < 5; i++) {
		g_usleep (60 * 1000);
		pump ();
	}
	fs_app_show_page (FS_PAGE_OVERVIEW);
	click (item_at (recent_sub, 0));
	CHECK (fs_app_current_page () == FS_PAGE_EVENTS &&
	       window != NULL && gtk_widget_get_visible (GTK_WIDGET (window)),
	       "clicking a recent block brings the window up on Events "
	       "(page %d, window %s)", (int) fs_app_current_page (),
	       window == NULL ? "missing"
	       : gtk_widget_get_visible (GTK_WIDGET (window)) ? "shown"
	                                                      : "hidden");

	/* 4. Go to: every page. */
	item = item_labelled (menu, "_Go to");
	go_sub = item != NULL ? gtk_menu_item_get_submenu (GTK_MENU_ITEM (item))
	                      : NULL;
	CHECK (go_sub != NULL, "Go to has a submenu");
	for (guint i = 0; go_sub != NULL && i < G_N_ELEMENTS (pages); i++) {
		click (item_labelled (go_sub, pages[i].label));
		CHECK (fs_app_current_page () == pages[i].page,
		       "Go to > %s opens the %s page", pages[i].label,
		       pages[i].label);
	}

	/* 5. Pause protection: confirmed first, Cancel is the default and
	 * leaves the firewall alone. */
	item = item_labelled (menu, "_Pause protection...");
	CHECK (item != NULL && gtk_widget_get_sensitive (item),
	       "Pause protection... is offered while the firewall runs");
	answer = GTK_RESPONSE_CANCEL;
	g_string_truncate (dialogs_seen, 0);
	click (item);
	CHECK (strstr (dialogs_seen->str, "[Pause protection]") != NULL &&
	       saw_cancel_default,
	       "it asks first, with Cancel as the default (dialogs: %s)",
	       dialogs_seen->str);
	CHECK (stops == 0 && fake_state == FS_FW_RUNNING,
	       "Cancel leaves the firewall running (%u stops)", stops);

	answer = GTK_RESPONSE_ACCEPT;
	click (item_labelled (fs_tray_menu (), "_Pause protection..."));
	menu = fs_tray_menu ();
	CHECK (stops == 1 && fake_state == FS_FW_STOPPED,
	       "\"Pause protection\" in the dialog stops it (%u stops)",
	       stops);
	CHECK (audit_has ("firewall stopped") && audit_has ("tray"),
	       "the stop is on the audit record, from the tray");
	CHECK (g_strcmp0 (label_of (item_at (menu, 0)), "Firewall: Off") == 0,
	       "row 1 now reads \"Firewall: Off\" (got \"%s\")",
	       label_of (item_at (menu, 0)));
	item = item_labelled (menu, "_Resume protection");
	CHECK (item != NULL && gtk_widget_get_sensitive (item),
	       "the row now offers Resume protection");
	answer = GTK_RESPONSE_CANCEL;
	click (item);
	menu = fs_tray_menu ();
	CHECK (starts == 1 && fake_state == FS_FW_RUNNING &&
	       g_strcmp0 (label_of (item_at (menu, 0)),
	                  "Firewall: On - Private network") == 0,
	       "Resume protection starts it again through the start gate "
	       "(%u starts)", starts);

	/* 5b. Stopped behind the app's back (`stockfw stop' in a
	 * terminal): the menu asks again when it opens, and the slow
	 * timer does with no menu open. */
	fake_state = FS_FW_STOPPED;
	menu = fs_tray_menu ();
	CHECK (g_strcmp0 (label_of (item_at (menu, 0)), "Firewall: Off") == 0,
	       "a firewall stopped outside StockFW reads \"Firewall: Off\" "
	       "as soon as the menu opens (got \"%s\")",
	       label_of (item_at (menu, 0)));
	CHECK (item_labelled (menu, "_Resume protection") != NULL,
	       "...and the menu offers Resume, not Pause");
	fake_state = FS_FW_RUNNING;
	menu = fs_tray_menu ();
	CHECK (g_strcmp0 (label_of (item_at (menu, 0)),
	                  "Firewall: On - Private network") == 0,
	       "started again outside StockFW: \"On\" again (got \"%s\")",
	       label_of (item_at (menu, 0)));
	fake_state = FS_FW_STOPPED;
	{
		GtkStatusIcon *icon = fs_tray_icon ();
		gchar *tip = NULL;

		/* STOCKFW_TRAY_REFRESH_S=1 (prepare): two periods. */
		for (gint i = 0; i < 25; i++) {
			g_usleep (100 * 1000);
			pump ();
		}
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS
		if (icon != NULL)
			tip = gtk_status_icon_get_tooltip_text (icon);
		G_GNUC_END_IGNORE_DEPRECATIONS
		CHECK (tip != NULL &&
		       g_str_has_prefix (tip, "StockFW - Firewall OFF"),
		       "with no menu open, the slow timer catches it too: "
		       "\"%s\"", tip != NULL ? tip : "(none)");
		g_free (tip);
	}
	fake_state = FS_FW_RUNNING;
	menu = fs_tray_menu ();

	fake_avail = FALSE;
	menu = fs_tray_menu ();
	item = item_labelled (menu, "_Pause protection...");
	CHECK (item != NULL && !gtk_widget_get_sensitive (item) &&
	       gtk_widget_get_tooltip_text (item) != NULL,
	       "without the rights to change the firewall, Pause is greyed "
	       "with the reason as its tooltip");
	item = item_labelled (menu, "Pause Sentinel auto-block for 1 hour");
	CHECK (item != NULL && !gtk_widget_get_sensitive (item) &&
	       gtk_widget_get_tooltip_text (item) != NULL,
	       "...and so is Pause Sentinel: it could not block anything "
	       "from here");
	fake_avail = TRUE;
	menu = fs_tray_menu ();

	/* 6. Sentinel. */
	item = item_labelled (menu, "Pause Sentinel auto-block for 1 hour");
	CHECK (item != NULL && gtk_widget_get_sensitive (item),
	       "Pause Sentinel auto-block for 1 hour is offered in auto mode");
	click (item);
	menu = fs_tray_menu ();
	item = item_prefixed (menu, "Resume Sentinel auto-block (paused, ");
	CHECK (fs_copilot_sentinel_paused (NULL) && item != NULL &&
	       g_str_has_suffix (label_of (item), "60 min left)"),
	       "it pauses for an hour and the row says so (\"%s\")",
	       label_of (item));
	CHECK (audit_has ("sentinel auto-block paused"),
	       "the pause is on the audit record");
	click (item);
	CHECK (!fs_copilot_sentinel_paused (NULL) &&
	       audit_has ("sentinel auto-block resumed"),
	       "clicking it again resumes auto-block, audited");

	/* 7. Start at sign-in.  Linux only: on Windows the same click
	 * would register a real Task Scheduler task. */
#ifdef G_OS_WIN32
	printf ("SKIP: Start at sign-in (would register a real task)\n");
#else
	menu = fs_tray_menu ();
	item = item_labelled (menu, "_Start at sign-in");
	CHECK (item != NULL && GTK_IS_CHECK_MENU_ITEM (item) &&
	       gtk_widget_get_sensitive (item) &&
	       !gtk_check_menu_item_get_active (GTK_CHECK_MENU_ITEM (item)),
	       "Start at sign-in is a check item, offered, not ticked");
	{
		gchar *entry_path = g_build_filename (scratch, "autostart",
		                                      "stockfw.desktop", NULL);
		gchar *blocker = g_build_filename (scratch, "not-a-dir", NULL);
		gchar *bad = g_build_filename (blocker, "autostart", NULL);
		gchar *good = g_build_filename (scratch, "autostart", NULL);

		click (item);
		CHECK (g_file_test (entry_path, G_FILE_TEST_EXISTS) &&
		       gtk_check_menu_item_get_active (
		           GTK_CHECK_MENU_ITEM (item)),
		       "ticking it writes the sign-in entry");
		click (item);
		CHECK (!g_file_test (entry_path, G_FILE_TEST_EXISTS) &&
		       !gtk_check_menu_item_get_active (
		           GTK_CHECK_MENU_ITEM (item)),
		       "unticking it removes the entry");

		/* A place that cannot be written: an error, and the tick
		 * shows what is true (off), not what was asked. */
		g_file_set_contents (blocker, "", -1, NULL);
		g_setenv ("STOCKFW_AUTOSTART_DIR", bad, TRUE);
		answer = GTK_RESPONSE_OK;
		g_string_truncate (dialogs_seen, 0);
		click (item);
		CHECK (dialogs_seen->len > 0 &&
		       !gtk_check_menu_item_get_active (
		           GTK_CHECK_MENU_ITEM (item)),
		       "a failure is reported (%s) and the tick stays off",
		       dialogs_seen->str);
		g_setenv ("STOCKFW_AUTOSTART_DIR", good, TRUE);
		g_free (entry_path);
		g_free (blocker);
		g_free (bad);
		g_free (good);
	}
#endif

	/* 8. Preferences and About.  Preferences is opened from the tray
	 * with the window hidden, as it is in background mode. */
	answer = GTK_RESPONSE_CANCEL;
	g_string_truncate (dialogs_seen, 0);
	gtk_widget_hide (GTK_WIDGET (main_window ()));
	prefs_opened = FALSE;
	prefs_with = with_prefs;
	click (item_labelled (fs_tray_menu (), "Pr_eferences..."));
	CHECK (strstr (dialogs_seen->str, "[Preferences]") != NULL &&
	       prefs_opened,
	       "Preferences... opens the Preferences window (%s)",
	       dialogs_seen->str);
#ifndef G_OS_WIN32
	{
		gchar *entry_path = g_build_filename (scratch, "autostart",
		                                      "stockfw.desktop", NULL);

		CHECK (!g_file_test (entry_path, G_FILE_TEST_EXISTS) &&
		       signin_item != NULL &&
		       !gtk_check_menu_item_get_active (
		           GTK_CHECK_MENU_ITEM (signin_item)),
		       "Save in Preferences removed the entry, and the tray's "
		       "tick follows at once (off)");
		g_free (entry_path);
	}
#endif
	/* About (1.0.7) is not modal: click returns with it open, and the
	 * dialog answerer sees it on its next tick.  Wait for that, up to
	 * two seconds. */
	g_string_truncate (dialogs_seen, 0);
	click (item_labelled (fs_tray_menu (), "_About StockFW"));
	{
		gint64 until = g_get_monotonic_time () + 2 * G_USEC_PER_SEC;

		while (strstr (dialogs_seen->str, "[About StockFW]") == NULL &&
		       g_get_monotonic_time () < until)
			g_main_context_iteration (NULL, TRUE);
	}
	CHECK (strstr (dialogs_seen->str, "[About StockFW]") != NULL,
	       "About StockFW opens About (%s)", dialogs_seen->str);

	/* Help (1.0.7): the Help window, at the topic about this menu,
	 * placed between Preferences and About; in background mode it
	 * opens on its own and does not bring the main window back. */
	{
		GtkWidget *help = item_labelled (fs_tray_menu (), "_Help");
		GList *items = gtk_container_get_children (
			GTK_CONTAINER (fs_tray_menu ()));
		gint at_help = g_list_index (items, help);
		gint at_prefs = g_list_index (items,
			item_labelled (fs_tray_menu (), "Pr_eferences..."));
		gint at_about = g_list_index (items,
			item_labelled (fs_tray_menu (), "_About StockFW"));

		g_list_free (items);
		CHECK (help != NULL && gtk_widget_get_sensitive (help) &&
		       at_help == at_prefs + 1 && at_about == at_help + 1,
		       "the menu has Help, between Preferences and About "
		       "(%d %d %d)", at_prefs, at_help, at_about);
		gtk_widget_hide (GTK_WIDGET (main_window ()));
		click (help);
		CHECK (fs_help_window () != NULL &&
		       gtk_widget_get_visible (fs_help_window ()) &&
		       g_strcmp0 (fs_help_current_topic (), "background") == 0,
		       "Help opens the Help window at \"Running in the "
		       "background\" (topic %s)",
		       fs_help_current_topic () != NULL
		       ? fs_help_current_topic () : "(none)");
		CHECK (!gtk_widget_get_visible (GTK_WIDGET (main_window ())),
		       "Help from the tray leaves the main window hidden");
		if (fs_help_window () != NULL)
			gtk_widget_destroy (fs_help_window ());
		pump ();
	}
}

static gboolean
run_checks (gpointer data)
{
	(void) data;

	if (g_strcmp0 (scenario, "detect") == 0) {
		check_detect ();
		fs_app_quit ();
		return G_SOURCE_REMOVE;
	}

	check_main ();

	/* 9. Quit: the program goes, the firewall stays on. */
	{
		guint stops_before = stops;

		click (item_labelled (fs_tray_menu (),
		                      "_Quit (firewall stays on)"));
		CHECK (stops == stops_before && fake_state == FS_FW_RUNNING,
		       "Quit (firewall stays on) does not stop the firewall");
	}
	return G_SOURCE_REMOVE;
}

/* STOCKFW_TRAYMENU_SHOT: pop the menu up where a tray menu appears
 * and save the screen, then carry on with the checks. */
static gboolean
shot_take (gpointer data)
{
	const gchar *out = data;
	GdkWindow *root = gdk_get_default_root_window ();
	GdkPixbuf *pix = gdk_pixbuf_get_from_window (
		root, 0, 0, gdk_window_get_width (root),
		gdk_window_get_height (root));

	if (pix != NULL) {
		gdk_pixbuf_save (pix, out, "png", NULL, NULL);
		g_object_unref (pix);
	}
	gtk_menu_popdown (GTK_MENU (fs_tray_menu ()));
	/* A picture, not a test run: the extra events would throw the
	 * counts off. */
	fs_app_quit ();
	return G_SOURCE_REMOVE;
}

static gboolean
shot_open_submenu (gpointer data)
{
	GtkWidget *menu = fs_tray_menu ();
	GtkWidget *recent = item_labelled (menu, "_Recent blocks");

	(void) data;
	if (recent != NULL)
		gtk_menu_shell_select_item (GTK_MENU_SHELL (menu), recent);
	return G_SOURCE_REMOVE;
}

static gboolean
shot_popup (gpointer data)
{
	GtkWidget *menu = fs_tray_menu ();
	GdkWindow *root = gdk_get_default_root_window ();
	GdkRectangle at = { gdk_window_get_width (root) - 40, 2, 1, 1 };

	gtk_menu_popup_at_rect (GTK_MENU (menu), root, &at,
	                        GDK_GRAVITY_SOUTH_WEST,
	                        GDK_GRAVITY_NORTH_EAST, NULL);
	g_timeout_add (500, shot_open_submenu, NULL);
	g_timeout_add (1500, shot_take, data);
	return G_SOURCE_REMOVE;
}

static void
on_activate (GtkApplication *app, gpointer data)
{
	const gchar *shot = g_getenv ("STOCKFW_TRAYMENU_SHOT");

	(void) data;

	fs_app_activate (app);
	pump ();
	g_timeout_add (100, answer_dialogs, NULL);

	if (shot != NULL && *shot != '\0' &&
	    g_strcmp0 (scenario, "main") == 0) {
		/* Something to show in Recent blocks. */
		if (log_cb != NULL) {
			FsHit *hit = blocked_hit ();

			log_cb (hit, log_user);
			fs_hit_free (hit);

			hit = blocked_hit ();
			g_free (hit->direction);
			hit->direction = g_strdup ("In");
			g_free (hit->protocol);
			hit->protocol = g_strdup ("UDP");
			g_free (hit->port);
			hit->port = g_strdup ("5353");
			g_free (hit->source);
			hit->source = g_strdup ("198.51.100.23");
			log_cb (hit, log_user);
			fs_hit_free (hit);
		}
		g_timeout_add (800, shot_popup, (gpointer) shot);
		return;
	}
	g_timeout_add (300, run_checks, NULL);
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
	static const gchar *const all[] = { "main", "detect" };
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

	printf ("\nui-traymenu-smoke: %s: %d scenario(s) failed\n",
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

	app = gtk_application_new ("org.stockfw.TrayMenuSmoke",
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
