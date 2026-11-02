/*---[ ui-prefs-smoke.c ]--------------------------------------------------
 *
 * UI smoke test for the Preferences window (1.0.7).
 *
 * Built twice:
 *
 *   fs-ui-smoke           against this platform's real backend.  Opens
 *                         the real window, checks its pages against the
 *                         backend's capability bits (and pins those bits
 *                         to the backend's identity), walks every page
 *                         from the navigation, checks nothing dead is on
 *                         offer, and saves without a change: nothing
 *                         may be written.  Also checks the About credits
 *                         and the compiled-in stylesheet, as before.
 *
 *   fs-prefs-fake-smoke   (FS_PREFS_FAKE_BACKEND) supplies fs_backend()
 *                         itself and answers once as the Linux backend
 *                         and once as the Windows one, so both platforms'
 *                         windows are exercised on any machine:
 *                           - the page set per FS_FWSEC_* / FS_FWHON_*;
 *                           - honest hiding (no Reject/Drop, outbound
 *                             mode or devices on Windows), honest
 *                             notes (ICMP on Windows is IPv4 allow rules);
 *                           - D1: the Internet device combo shows the
 *                             stored device, not "the first one";
 *                           - D2: the local device combo is filled and
 *                             keeps a stored device that is not present;
 *                           - D3: an unset "apply immediately" reads off,
 *                             as the Policy page treats it;
 *                           - D4: Linux blocks that need an Internet
 *                             device are disabled, with the reason, until
 *                             one is chosen;
 *                           - D8: Save writes only what changed, never a
 *                             setting the window does not offer, and
 *                             never drops a change to a row that is
 *                             disabled now (sharing turned off with a
 *                             device missing);
 *                           - the Protection and sharing rows are live
 *                             exactly when the generator emits them;
 *                           - D5: a firewall change asks before applying
 *                             (with the firewall running, or off where
 *                             Start does not re-apply), applies under
 *                             the policy that is live -- never unapplied
 *                             Policy-page edits, never an empty policy --
 *                             and after "Later" the next policy apply
 *                             brings the settings in; Cancel writes
 *                             nothing.
 *                         With STOCKFW_PREFS_SHOTS=<dir> it also saves a
 *                         PNG of every page (and a narrow window).
 *
 * Deliberately NOT part of StockFW.exe -- the CMake targets are
 * EXCLUDE_FROM_ALL -- so no test hook is ever shipped to a user.  The
 * preference file is pointed at a scratch directory first thing, so
 * nothing touches the user's real settings.
 *----------------------------------------------------------------------*/
#include <gtk/gtk.h>
#include <glib/gstdio.h>
#include <string.h>

#include "core/fs-prefs.h"
#include "core/fs-backend.h"
#include "core/fs-i18n.h"
#include "core/fs-rules.h"
#include "core/fs-script.h"
#include "core/fs-apply.h"
#include "ui/fs-app.h"
#include "ui/fs-dialogs.h"
#include "fs-theme-css.h"   /* generated from src/ui/fs-theme.css */

#define SMOKE_STEP_MS  100
#define SMOKE_MAX_RUNS 600

static int failures = 0;
static guint warnings = 0;

#define CHECK(cond, ...) do {                                   \
	g_print ((cond) ? "ok:   " : "FAIL: ");                 \
	g_print (__VA_ARGS__);                                  \
	g_print ("\n");                                         \
	if (!(cond))                                            \
		failures++;                                     \
} while (0)

static GLogWriterOutput
count_warnings (GLogLevelFlags level, const GLogField *fields,
                gsize n_fields, gpointer data)
{
	(void) data;
	if (level & (G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL))
		warnings++;
	return g_log_writer_default (level, fields, n_fields, NULL);
}

/* The capability sets the shipped backends declare.  fs-ui-smoke pins
 * the real backend to its row, so the fake below cannot drift from
 * what users run. */
#define LINUX_SECTIONS (FS_FWSEC_NETWORK | FS_FWSEC_ICMP | FS_FWSEC_ADVANCED)
#define LINUX_HONORS   (FS_FWHON_REJECT_METHOD | FS_FWHON_RATE_LIMIT | \
                        FS_FWHON_LOG_ALLOWED | FS_FWHON_HOST_NAMES |   \
                        FS_FWHON_OUTBOUND_MODE | FS_FWHON_ICMP_EXACT | \
                        FS_FWHON_START_APPLIES)
#define WINDOWS_SECTIONS (FS_FWSEC_ICMP | FS_FWSEC_ADVANCED)
#define WINDOWS_HONORS   0u

/* ===================================================== fake backend */
#ifdef FS_PREFS_FAKE_BACKEND

static FsFirewallState fake_state = FS_FW_RUNNING;
static guint fake_apply_calls = 0;
static guint fake_last_rows = 0;         /* policy rows of the last apply */
static gboolean fake_last_has_deny = FALSE;
static guint fake_list_calls = 0;

static gboolean fake_available (void) { return TRUE; }
static FsFirewallState fake_get_state (void) { return fake_state; }

static FsApplyResult
fake_apply_rules (const FsPolicy *policy, GError **error)
{
	(void) error;
	fake_apply_calls++;
	fake_last_rows = 0;
	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		fake_last_rows += policy->kinds[k]->len;
	fake_last_has_deny = policy->kinds[FS_RULE_OUTBOUND_DENY_TO]->len > 0;
	return FS_APPLY_OK;
}

static FsInterface *
iface (const gchar *name, const gchar *ip)
{
	FsInterface *i = g_new0 (FsInterface, 1);

	i->name = g_strdup (name);
	i->ip = g_strdup (ip);
	return i;
}

/* eth0 first, so "the first device" is never the stored one, and eth1
 * twice, as getifaddrs() reports a device with two addresses. */
static GList *
fake_list_interfaces (void)
{
	GList *l = NULL;

	fake_list_calls++;
	l = g_list_append (l, iface ("eth0", "10.0.0.2"));
	l = g_list_append (l, iface ("eth1", "192.168.1.2"));
	l = g_list_append (l, iface ("eth1", "192.168.1.3"));
	l = g_list_append (l, iface ("wlan0", "192.168.50.7"));
	return l;
}

static FsIpv6State
fake_ipv6_state (gchar **detail)
{
	if (detail != NULL)
		*detail = NULL;
	return FS_IPV6_FILTERED;
}

static FsBackend fake_backend = {
	.name            = "fake",
	.display_name    = "Fake backend",
	.available       = fake_available,
	.get_state       = fake_get_state,
	.apply_rules     = fake_apply_rules,
	.list_interfaces = fake_list_interfaces,
};

static void
fake_as_linux (void)
{
	fake_backend.name = "fake-linux";
	fake_backend.display_name = "Linux (iptables)";
	fake_backend.fw_sections = LINUX_SECTIONS;
	fake_backend.fw_honors = LINUX_HONORS;
	fake_backend.ipv6_state = fake_ipv6_state;
	fake_backend.list_interfaces = fake_list_interfaces;
}

static void
fake_as_windows (void)
{
	fake_backend.name = "fake-windows";
	fake_backend.display_name = "Windows Defender Firewall";
	fake_backend.fw_sections = WINDOWS_SECTIONS;
	fake_backend.fw_honors = WINDOWS_HONORS;
	fake_backend.ipv6_state = NULL;
	fake_backend.list_interfaces = fake_list_interfaces;
}

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

#endif /* FS_PREFS_FAKE_BACKEND */

/* ========================================================== helpers */

static GtkWidget *
find_named (GtkWidget *root, const gchar *name)
{
	GtkWidget *found = NULL;
	GList *children;

	if (root == NULL)
		return NULL;
	if (g_strcmp0 (gtk_widget_get_name (root), name) == 0)
		return root;
	if (!GTK_IS_CONTAINER (root))
		return NULL;

	children = gtk_container_get_children (GTK_CONTAINER (root));
	for (GList *l = children; l != NULL && found == NULL; l = l->next)
		found = find_named (l->data, name);
	g_list_free (children);

	return found;
}

/* Every label's text under root, joined. */
static void
gather_text (GtkWidget *root, GString *out)
{
	GList *children;

	if (GTK_IS_LABEL (root)) {
		g_string_append (out, gtk_label_get_text (GTK_LABEL (root)));
		g_string_append_c (out, '\n');
	}
	if (GTK_IS_BUTTON (root) && gtk_button_get_label (GTK_BUTTON (root))) {
		g_string_append (out, gtk_button_get_label (GTK_BUTTON (root)));
		g_string_append_c (out, '\n');
	}
	if (!GTK_IS_CONTAINER (root))
		return;
	children = gtk_container_get_children (GTK_CONTAINER (root));
	for (GList *l = children; l != NULL; l = l->next)
		gather_text (l->data, out);
	g_list_free (children);
}

G_GNUC_UNUSED static gboolean
mentions (GtkWidget *root, const gchar *needle)
{
	GString *text = g_string_new (NULL);
	gboolean found;

	gather_text (root, text);
	found = strstr (text->str, needle) != NULL;
	g_string_free (text, TRUE);
	return found;
}

static GtkWidget *
find_prefs (void)
{
	GList *windows = gtk_window_list_toplevels ();
	GtkWidget *found = NULL;

	for (GList *l = windows; l != NULL; l = l->next)
		if (g_strcmp0 (gtk_widget_get_name (l->data),
		               "fs-preferences") == 0 &&
		    gtk_widget_get_mapped (l->data))
			found = l->data;
	g_list_free (windows);
	return found;
}

/* The first mapped message dialog, or NULL. */
static GtkWidget *
find_message (void)
{
	GList *windows = gtk_window_list_toplevels ();
	GtkWidget *found = NULL;

	for (GList *l = windows; l != NULL; l = l->next)
		if (GTK_IS_MESSAGE_DIALOG (l->data) &&
		    gtk_widget_get_mapped (l->data))
			found = l->data;
	g_list_free (windows);
	return found;
}

static void
pump (void)
{
	for (gint i = 0; i < 6; i++) {
		while (gtk_events_pending ())
			gtk_main_iteration ();
		g_usleep (20000);
	}
}

/* The page ids in navigation order, "general,events,...". */
static gchar *
nav_order (GtkWidget *win)
{
	GtkWidget *stack = find_named (win, "prefs-pages");
	GString *out = g_string_new (NULL);
	GList *pages;

	if (stack == NULL)
		return g_string_free (out, FALSE);

	pages = gtk_container_get_children (GTK_CONTAINER (stack));
	for (GList *l = pages; l != NULL; l = l->next) {
		gchar *id = NULL;

		gtk_container_child_get (GTK_CONTAINER (stack), l->data,
		                         "name", &id, NULL);
		if (out->len > 0)
			g_string_append_c (out, ',');
		g_string_append (out, id != NULL ? id : "?");
		g_free (id);
	}
	g_list_free (pages);
	return g_string_free (out, FALSE);
}

static gchar *
expected_pages (guint32 sections, guint32 honors)
{
	GString *out = g_string_new ("general,events,policy");

	if (honors & (FS_FWHON_REJECT_METHOD | FS_FWHON_OUTBOUND_MODE |
	              FS_FWHON_LOG_ALLOWED))
		g_string_append (out, ",firewall");
	if (sections & FS_FWSEC_NETWORK)
		g_string_append (out, ",network");
	if (sections & FS_FWSEC_ICMP)
		g_string_append (out, ",icmp");
	if (sections & FS_FWSEC_ADVANCED)
		g_string_append (out, ",protection");
	return g_string_free (out, FALSE);
}

/* Clicks each navigation item; each must show its own page. */
static void
check_navigation (GtkWidget *win, const gchar *pages, const gchar *shots,
                  const gchar *tag)
{
	GtkWidget *stack = find_named (win, "prefs-pages");
	gchar **ids = g_strsplit (pages, ",", -1);
	guint ok = 0, n = 0;

	for (guint i = 0; ids[i] != NULL; i++) {
		gchar *nav_name = g_strconcat ("nav:", ids[i], NULL);
		GtkWidget *item = find_named (win, nav_name);
		const gchar *now;

		n++;
		if (item == NULL) {
			CHECK (FALSE, "[%s] navigation item for \"%s\"", tag, ids[i]);
			g_free (nav_name);
			continue;
		}
		gtk_button_clicked (GTK_BUTTON (item));
		pump ();
		now = gtk_stack_get_visible_child_name (GTK_STACK (stack));
		if (g_strcmp0 (now, ids[i]) == 0 &&
		    gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (item)))
			ok++;
		else
			CHECK (FALSE, "[%s] \"%s\" shows page %s", tag, ids[i], now);

		if (shots != NULL) {
			GdkWindow *gw = gtk_widget_get_window (win);
			GdkPixbuf *pix = gdk_pixbuf_get_from_window (
				gw, 0, 0, gdk_window_get_width (gw),
				gdk_window_get_height (gw));
			gchar *file = g_strdup_printf ("%s/%s-%02u-%s.png", shots,
			                               tag, i, ids[i]);

			if (pix != NULL) {
				gdk_pixbuf_save (pix, file, "png", NULL, NULL);
				g_object_unref (pix);
				g_print ("shot: %s\n", file);
			}
			g_free (file);

			/* A page taller than the window: its end too. */
			{
				GtkWidget *scroll = gtk_stack_get_visible_child (
					GTK_STACK (stack));
				GtkAdjustment *adj = GTK_IS_SCROLLED_WINDOW (scroll)
					? gtk_scrolled_window_get_vadjustment (
						GTK_SCROLLED_WINDOW (scroll))
					: NULL;

				if (adj != NULL &&
				    gtk_adjustment_get_upper (adj) >
				    gtk_adjustment_get_page_size (adj) + 1) {
					gtk_adjustment_set_value (adj,
						gtk_adjustment_get_upper (adj));
					pump ();
					file = g_strdup_printf ("%s/%s-%02u-%s-end.png",
					                        shots, tag, i, ids[i]);
					pix = gdk_pixbuf_get_from_window (
						gw, 0, 0, gdk_window_get_width (gw),
						gdk_window_get_height (gw));
					if (pix != NULL) {
						gdk_pixbuf_save (pix, file, "png",
						                 NULL, NULL);
						g_object_unref (pix);
						g_print ("shot: %s\n", file);
					}
					g_free (file);
					gtk_adjustment_set_value (adj, 0);
				}
			}
		}
		g_free (nav_name);
	}
	CHECK (ok == n && n > 0,
	       "[%s] every navigation item shows its own page (%u/%u)",
	       tag, ok, n);
	g_strfreev (ids);
}

/* Nothing the port does not do may be on offer anywhere.  "_Help" is
 * the legacy dialog's Help button, which did nothing; the footer's Help
 * (1.0.7) opens the Help window and is checked in check_pages. */
static void
check_no_dead_controls (GtkWidget *win, const gchar *tag)
{
	static const gchar *dead[] = {
		"ToS", "Type of Service", "DHCP lease", "DHCP for",
		"DHCP server", "dial-out", "Dial-out",
		"not implemented", "Ignored hosts", "Ignored ports", "_Help"
	};
	GString *text = g_string_new (NULL);
	guint hits = 0;

	gather_text (win, text);
	for (guint i = 0; i < G_N_ELEMENTS (dead); i++)
		if (strstr (text->str, dead[i]) != NULL) {
			g_print ("       dead text found: %s\n", dead[i]);
			hits++;
		}
	CHECK (hits == 0, "[%s] no dead control (nor the old dead Help) on "
	       "any page",
	       tag);
	g_string_free (text, TRUE);
}

/* Keys the settings file holds, from the file on disk. */
static gboolean
disk_has (const gchar *key, gchar **value)
{
	GKeyFile *kf = g_key_file_new ();
	gboolean has = FALSE;

	if (value != NULL)
		*value = NULL;

	if (g_key_file_load_from_file (kf, fs_prefs_path (), 0, NULL)) {
		const gchar *rest = key + strlen ("/apps/stockfw/");
		const gchar *slash = strchr (rest, '/');
		gchar *group = g_strndup (rest, (gsize) (slash - rest));

		has = g_key_file_has_key (kf, group, slash + 1, NULL);
		if (has && value != NULL)
			*value = g_key_file_get_value (kf, group, slash + 1, NULL);
		g_free (group);
	}
	g_key_file_free (kf);
	return has;
}

/* Table keys on disk, as "key=value" lines sorted by table order. */
static gchar *
disk_table_keys (void)
{
	guint n = 0;
	const FsPrefSpec *specs = fs_prefs_specs (&n);
	GString *out = g_string_new (NULL);

	for (guint i = 0; i < n; i++) {
		gchar *value = NULL;

		if (disk_has (specs[i].key, &value))
			g_string_append_printf (out, "%s=%s;",
			                        specs[i].key + strlen ("/apps/stockfw/"),
			                        value);
		g_free (value);
	}
	return g_string_free (out, FALSE);
}

G_GNUC_UNUSED static gboolean
sensitive (GtkWidget *win, const gchar *key)
{
	GtkWidget *w = find_named (win, key);

	return w != NULL && gtk_widget_get_sensitive (w);
}

G_GNUC_UNUSED static gboolean
reason_shown (GtkWidget *win, const gchar *key)
{
	gchar *name = g_strconcat ("reason:", key, NULL);
	GtkWidget *w = find_named (win, name);

	g_free (name);
	return w != NULL && gtk_widget_get_visible (w);
}

G_GNUC_UNUSED static void
set_switch (GtkWidget *win, const gchar *key, gboolean on)
{
	GtkWidget *w = find_named (win, key);

	if (w != NULL && GTK_IS_SWITCH (w))
		gtk_switch_set_active (GTK_SWITCH (w), on);
	else
		CHECK (FALSE, "switch for %s exists", key);
}

G_GNUC_UNUSED static void
set_combo (GtkWidget *win, const gchar *key, const gchar *id)
{
	GtkWidget *w = find_named (win, key);

	if (w != NULL && GTK_IS_COMBO_BOX (w))
		gtk_combo_box_set_active_id (GTK_COMBO_BOX (w), id);
	else
		CHECK (FALSE, "choice for %s exists", key);
}

G_GNUC_UNUSED static const gchar *
combo_id (GtkWidget *win, const gchar *key)
{
	GtkWidget *w = find_named (win, key);

	return (w != NULL && GTK_IS_COMBO_BOX (w))
	       ? gtk_combo_box_get_active_id (GTK_COMBO_BOX (w)) : NULL;
}

G_GNUC_UNUSED static gchar *
combo_text (GtkWidget *win, const gchar *key)
{
	GtkWidget *w = find_named (win, key);

	return (w != NULL && GTK_IS_COMBO_BOX_TEXT (w))
	       ? gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (w))
	       : NULL;
}

/* Every id a combo offers, "a,b,c". */
G_GNUC_UNUSED static gchar *
combo_ids (GtkWidget *win, const gchar *key)
{
	GtkWidget *w = find_named (win, key);
	GString *out = g_string_new (NULL);
	GtkTreeModel *model;
	GtkTreeIter iter;
	gint col;

	if (w == NULL || !GTK_IS_COMBO_BOX (w))
		return g_string_free (out, FALSE);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (w));
	col = gtk_combo_box_get_id_column (GTK_COMBO_BOX (w));
	if (gtk_tree_model_get_iter_first (model, &iter)) {
		guint n = 0;

		do {
			gchar *id = NULL;

			gtk_tree_model_get (model, &iter, col, &id, -1);
			if (n++ > 0)
				g_string_append_c (out, ',');
			g_string_append (out, id != NULL ? id : "");
			g_free (id);
		} while (gtk_tree_model_iter_next (model, &iter));
	}
	return g_string_free (out, FALSE);
}

/* With STOCKFW_PREFS_SHOTS set: the window as it is now, as <name>.png. */
G_GNUC_UNUSED static void
snap (GtkWidget *win, const gchar *page, const gchar *name)
{
	const gchar *dir = g_getenv ("STOCKFW_PREFS_SHOTS");
	gchar *nav, *file;
	GdkWindow *gw;
	GdkPixbuf *pix;

	if (dir == NULL)
		return;

	nav = g_strconcat ("nav:", page, NULL);
	gtk_button_clicked (GTK_BUTTON (find_named (win, nav)));
	g_free (nav);
	pump ();

	gw = gtk_widget_get_window (win);
	pix = gdk_pixbuf_get_from_window (gw, 0, 0, gdk_window_get_width (gw),
	                                  gdk_window_get_height (gw));
	file = g_strdup_printf ("%s/%s.png", dir, name);
	if (pix != NULL) {
		gdk_pixbuf_save (pix, file, "png", NULL, NULL);
		g_object_unref (pix);
		g_print ("shot: %s\n", file);
	}
	g_free (file);
}

static void
click (GtkWidget *win, const gchar *name)
{
	GtkWidget *w = find_named (win, name);

	if (w != NULL)
		gtk_button_clicked (GTK_BUTTON (w));
	else
		CHECK (FALSE, "button %s exists", name);
}

/* ========================================================= scenarios */

typedef enum
{
	ANSWER_NONE,        /* no question may appear              */
	ANSWER_LATER,
	ANSWER_APPLY_NOW
} Answer;

typedef struct
{
	const gchar *tag;
	void       (*drive) (GtkWidget *win);
	Answer       answer;
	/* set by the driver */
	gboolean     drove;
	gboolean     asked;
	gboolean     reported;
	gchar       *report_text;
} Scenario;

static Scenario *current = NULL;
static gchar *last_question = NULL;   /* the apply question's text */
static guint runs = 0;
static gboolean scenario_done = FALSE;

/* [ tick ]
 * Drives one scenario: the window first, then any question or report
 * that follows its Save. */
static gboolean
tick (gpointer data)
{
	GtkWidget *win, *msg;

	(void) data;

	if (++runs > SMOKE_MAX_RUNS) {
		CHECK (FALSE, "[%s] the window completed in time",
		       current->tag);
		scenario_done = TRUE;
		return G_SOURCE_REMOVE;
	}

	msg = find_message ();
	if (msg != NULL) {
		const gchar *name = gtk_widget_get_name (msg);

		if (g_strcmp0 (name, "prefs-apply-question") == 0) {
			GString *text = g_string_new (NULL);

			gather_text (msg, text);
			g_free (last_question);
			last_question = g_string_free (text, FALSE);
			g_print ("       question: %s\n", last_question);
			current->asked = TRUE;
			gtk_dialog_response (GTK_DIALOG (msg),
			                     current->answer == ANSWER_APPLY_NOW
			                     ? GTK_RESPONSE_OK
			                     : GTK_RESPONSE_CANCEL);
		} else {
			GString *text = g_string_new (NULL);

			gather_text (msg, text);
			current->reported = TRUE;
			g_free (current->report_text);
			current->report_text = g_string_free (text, FALSE);
			g_print ("       report: %s\n", current->report_text);
			gtk_dialog_response (GTK_DIALOG (msg), GTK_RESPONSE_OK);
		}
		return G_SOURCE_CONTINUE;
	}

	if (!current->drove) {
		win = find_prefs ();
		if (win == NULL)
			return G_SOURCE_CONTINUE;
		pump ();
		current->drove = TRUE;
		current->drive (win);
	}

	return scenario_done ? G_SOURCE_REMOVE : G_SOURCE_CONTINUE;
}

static void
run_scenario (Scenario *scenario)
{
	guint source;

	current = scenario;
	runs = 0;
	scenario_done = FALSE;
	g_print ("---- %s\n", scenario->tag);

	source = g_timeout_add (SMOKE_STEP_MS, tick, NULL);
	fs_dialogs_preferences (NULL);
	scenario_done = TRUE;
	/* Let a pending tick see the flag and go. */
	if (g_main_context_find_source_by_id (NULL, source) != NULL)
		g_source_remove (source);

	CHECK (scenario->drove, "[%s] the window opened and was driven",
	       scenario->tag);
	if (scenario->answer == ANSWER_NONE)
		CHECK (!scenario->asked,
		       "[%s] no apply question (nothing to apply to)",
		       scenario->tag);
	else
		CHECK (scenario->asked,
		       "[%s] the firewall change asks \"Apply the new firewall "
		       "settings now?\"", scenario->tag);
}

/* Writes the start state straight into a fresh settings file. */
static void
seed (const gchar *contents)
{
	g_file_set_contents (fs_prefs_path (), contents, -1, NULL);
	CHECK (fs_prefs_load (), "seeded settings load");
}

static void
check_pages (GtkWidget *win, const gchar *tag)
{
	gchar *want = expected_pages (fs_backend ()->fw_sections,
	                              fs_backend ()->fw_honors);
	gchar *have = nav_order (win);

	CHECK (g_strcmp0 (want, have) == 0,
	       "[%s] pages follow the capability bits: %s (want %s)",
	       tag, have, want);
	check_navigation (win, have, g_getenv ("STOCKFW_PREFS_SHOTS"), tag);
	check_no_dead_controls (win, tag);

	{
		GtkWidget *bg = find_named (win, "prefs-background");

		CHECK (bg != NULL && !gtk_widget_get_visible (bg),
		       "[%s] the Background card is in place and hidden until "
		       "it has a setting", tag);
	}
	{
		/* 1.0.7: the footer has a Help button (it opens the topic
		 * for the page shown; fs-help-smoke follows it there). */
		GtkWidget *help = find_named (win, "prefs-help");

		CHECK (help != NULL && GTK_IS_BUTTON (help)
		       && gtk_widget_get_visible (help)
		       && gtk_widget_is_sensitive (help),
		       "[%s] the footer has a Help button", tag);
	}
	g_free (want);
	g_free (have);
}

/* ---------------------------------------------------- real backend */
#ifndef FS_PREFS_FAKE_BACKEND

static void
drive_real (GtkWidget *win)
{
	const FsBackend *b = fs_backend ();

	if (g_strcmp0 (b->name, "linux") == 0)
		CHECK (b->fw_sections == LINUX_SECTIONS &&
		       b->fw_honors == LINUX_HONORS,
		       "the Linux capability set is the one the fake smoke "
		       "tests (sections 0x%x honors 0x%x)",
		       b->fw_sections, b->fw_honors);
	else if (g_strcmp0 (b->name, "windows") == 0)
		CHECK (b->fw_sections == WINDOWS_SECTIONS &&
		       b->fw_honors == WINDOWS_HONORS,
		       "the Windows capability set is the one the fake smoke "
		       "tests (sections 0x%x honors 0x%x)",
		       b->fw_sections, b->fw_honors);

	check_pages (win, b->name);

	/* Open and Save without touching anything: nothing is written. */
	click (win, "prefs-save");
}

#else
/* ---------------------------------------------------- fake backend */

static void
drive_linux (GtkWidget *win)
{
	gchar *text, *ids, *keys;

	check_pages (win, "linux");

	/* D1: the stored Internet device, not row 1 (eth0). */
	CHECK (g_strcmp0 (combo_id (win, FS_PREFS_FW_EXT_IF), "eth1") == 0,
	       "D1: the Internet device combo shows the stored eth1 (got %s)",
	       combo_id (win, FS_PREFS_FW_EXT_IF));

	/* D2: the local device combo lists the devices too, and keeps a
	 * stored device that is not attached, marked as such. */
	ids = combo_ids (win, FS_PREFS_FW_INT_IF);
	CHECK (g_strcmp0 (ids, ",eth0,eth1,wlan0,eth9") == 0,
	       "D2: the local device combo lists every device once plus the "
	       "absent stored one (%s)", ids);
	g_free (ids);
	ids = combo_ids (win, FS_PREFS_FW_EXT_IF);
	CHECK (g_strcmp0 (ids, ",eth0,eth1,wlan0") == 0,
	       "both combos are filled from list_interfaces, eth1 once (%s)",
	       ids);
	g_free (ids);
	text = combo_text (win, FS_PREFS_FW_INT_IF);
	CHECK (g_strcmp0 (combo_id (win, FS_PREFS_FW_INT_IF), "eth9") == 0 &&
	       text != NULL && strstr (text, "not present") != NULL,
	       "D2: the stored local device eth9 stays chosen as \"%s\"",
	       text != NULL ? text : "(none)");
	g_free (text);
	{
		GtkWidget *note = find_named (win, "prefs-absent-note");

		CHECK (note != NULL && gtk_widget_get_visible (note),
		       "the \"not present\" note is shown");
	}

	/* D3: unset reads as off, as the Policy page treats it. */
	{
		GtkWidget *w = find_named (win, FS_PREFS_APPLY_POLICY_INSTANTLY);

		CHECK (w != NULL && !gtk_switch_get_active (GTK_SWITCH (w)),
		       "D3: \"Apply policy changes immediately\" is off when "
		       "the key is unset");
	}

	/* Firewall page rows, Linux only. */
	CHECK (g_strcmp0 (combo_id (win, FS_PREFS_FW_DENY_PACKETS), "drop") == 0,
	       "blocked connections: Drop by default");
	CHECK (g_strcmp0 (combo_id (win, FS_PREFS_FW_RESTRICTIVE_OUTBOUND),
	                  "allow") == 0,
	       "outbound: Allow all by default");
	{
		GtkWidget *warn = find_named (win, "prefs-outbound-warning");

		CHECK (warn != NULL && !gtk_widget_get_visible (warn),
		       "no restrictive-mode warning while outbound is allowed");
		set_combo (win, FS_PREFS_FW_RESTRICTIVE_OUTBOUND, "block");
		CHECK (warn != NULL && gtk_widget_get_visible (warn) &&
		       mentions (warn, "updates"),
		       "choosing \"Block outgoing\" shows the warning, updates "
		       "named");
		snap (win, "firewall", "linux-firewall-block-outgoing");
		set_combo (win, FS_PREFS_FW_RESTRICTIVE_OUTBOUND, "allow");
	}
	CHECK (find_named (win, FS_PREFS_FW_LOG_ALLOWED) != NULL,
	       "\"Log allowed connections\" is offered on Linux");

	/* D4: Linux blocks need the Internet device. */
	CHECK (sensitive (win, FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST) &&
	       sensitive (win, FS_PREFS_FW_BLOCK_NON_ROUTABLES) &&
	       !reason_shown (win, FS_PREFS_FW_BLOCK_NON_ROUTABLES),
	       "D4: with an Internet device the device blocks are live");
	CHECK (!sensitive (win, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST) &&
	       reason_shown (win, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST),
	       "D4: the local-network block is disabled, with the reason, "
	       "while sharing is off");
	set_combo (win, FS_PREFS_FW_EXT_IF, "");
	CHECK (!sensitive (win, FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST) &&
	       !sensitive (win, FS_PREFS_FW_BLOCK_NON_ROUTABLES) &&
	       reason_shown (win, FS_PREFS_FW_BLOCK_NON_ROUTABLES) &&
	       reason_shown (win, FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST),
	       "D4: with no Internet device those blocks are disabled and "
	       "say why");
	CHECK (!sensitive (win, FS_PREFS_FW_NAT) &&
	       reason_shown (win, FS_PREFS_FW_NAT),
	       "connection sharing needs both devices, and says so");
	{
		GtkWidget *w = find_named (win, FS_PREFS_FW_BLOCK_NON_ROUTABLES);
		const gchar *desc = w != NULL
			? atk_object_get_description (gtk_widget_get_accessible (w))
			: NULL;

		CHECK (desc != NULL &&
		       g_str_has_prefix (desc, "Has no effect until you choose "
		                               "an Internet device") &&
		       strstr (desc, "Drops packets") != NULL,
		       "a disabled row tells a screen reader why, then what it "
		       "does (%s)", desc != NULL ? desc : "(none)");
	}
	snap (win, "protection", "linux-protection-no-device");
	snap (win, "network", "linux-network-no-device");
	set_combo (win, FS_PREFS_FW_EXT_IF, "eth1");
	CHECK (sensitive (win, FS_PREFS_FW_NAT) &&
	       !reason_shown (win, FS_PREFS_FW_NAT),
	       "with both devices chosen, sharing can be turned on");
	set_switch (win, FS_PREFS_FW_NAT, TRUE);
	CHECK (sensitive (win, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST),
	       "sharing on: the local-network block becomes live");
	set_switch (win, FS_PREFS_FW_NAT, FALSE);

	/* ICMP: types follow the master switch; the notes fit Linux. */
	set_switch (win, FS_PREFS_FW_FILTER_ICMP, FALSE);
	CHECK (!sensitive (win, FS_PREFS_FW_ICMP_ECHO_REQUEST),
	       "ICMP types are disabled while filtering is off");
	set_switch (win, FS_PREFS_FW_FILTER_ICMP, TRUE);
	CHECK (sensitive (win, FS_PREFS_FW_ICMP_ECHO_REQUEST),
	       "ICMP types come back with filtering");
	{
		GtkWidget *icmp = find_named (win, "prefs-pages");

		CHECK (mentions (icmp, "IPv6 uses the same choices") &&
		       !mentions (icmp, "Windows' own rules") &&
		       !mentions (icmp, "rate-limit"),
		       "Linux ICMP notes: IPv6 yes, Windows caveats no");
		CHECK (mentions (icmp, "Replies to your own pings get through "
		                       "either way") &&
		       mentions (icmp, "Reports about your own connections get "
		                       "through either way") &&
		       mentions (icmp, "tracert do not need it"),
		       "Linux ICMP rows say what the switches add: the "
		       "connection-state accept lets this computer's own "
		       "replies and errors in whatever they say");
	}

	/* Screen readers get the line on what a setting does, and the
	 * reason first while the row cannot act. */
	{
		GtkWidget *w = find_named (win, FS_PREFS_SKIP_REDUNDANT);
		const gchar *desc = w != NULL
			? atk_object_get_description (gtk_widget_get_accessible (w))
			: NULL;

		CHECK (desc != NULL &&
		       g_str_has_prefix (desc, "Leaves out a hit that repeats"),
		       "a switch's accessible description is its line (%s)",
		       desc != NULL ? desc : "(none)");
	}

	/* The policy link works only with nothing pending. */
	CHECK (sensitive (win, "prefs-open-policy"),
	       "\"Change on the Policy page\" is live with no changes");

	/* D8: change exactly two settings, one of them a firewall one. */
	set_switch (win, FS_PREFS_FW_ICMP_ECHO_REQUEST, FALSE);
	set_switch (win, FS_PREFS_SKIP_REDUNDANT, TRUE);
	CHECK (!sensitive (win, "prefs-open-policy"),
	       "the Policy link waits while changes are pending");
	{
		GtkWidget *status = find_named (win, "prefs-status");

		CHECK (status != NULL &&
		       g_strcmp0 (gtk_label_get_text (GTK_LABEL (status)),
		                  "2 unsaved changes") == 0,
		       "the footer counts the changes (\"%s\")",
		       status ? gtk_label_get_text (GTK_LABEL (status)) : "");
	}

	keys = disk_table_keys ();
	g_print ("       before save: %s\n", keys);
	g_free (keys);

	if (g_getenv ("STOCKFW_PREFS_SHOTS") != NULL) {
		/* A narrow window must still read: wrapping, scrolling. */
		gchar *file = g_build_filename (g_getenv ("STOCKFW_PREFS_SHOTS"),
		                                "linux-narrow-protection.png",
		                                NULL);
		GdkPixbuf *pix;
		GdkWindow *gw;

		gtk_window_resize (GTK_WINDOW (win), 560, 460);
		click (win, "nav:protection");
		pump ();
		pump ();
		gw = gtk_widget_get_window (win);
		pix = gdk_pixbuf_get_from_window (gw, 0, 0,
		                                  gdk_window_get_width (gw),
		                                  gdk_window_get_height (gw));
		if (pix != NULL) {
			gdk_pixbuf_save (pix, file, "png", NULL, NULL);
			g_object_unref (pix);
			g_print ("shot: %s\n", file);
		}
		g_free (file);
		click (win, "nav:firewall");
		set_combo (win, FS_PREFS_FW_RESTRICTIVE_OUTBOUND, "block");
		pump ();
		file = g_build_filename (g_getenv ("STOCKFW_PREFS_SHOTS"),
		                         "linux-narrow-firewall-block.png", NULL);
		pix = gdk_pixbuf_get_from_window (gw, 0, 0,
		                                  gdk_window_get_width (gw),
		                                  gdk_window_get_height (gw));
		if (pix != NULL) {
			gdk_pixbuf_save (pix, file, "png", NULL, NULL);
			g_object_unref (pix);
			g_print ("shot: %s\n", file);
		}
		g_free (file);
		set_combo (win, FS_PREFS_FW_RESTRICTIVE_OUTBOUND, "allow");
	}

	click (win, "prefs-save");
}

static void
drive_windows (GtkWidget *win)
{
	check_pages (win, "windows");

	CHECK (find_named (win, FS_PREFS_FW_DENY_PACKETS) == NULL &&
	       find_named (win, FS_PREFS_FW_RESTRICTIVE_OUTBOUND) == NULL &&
	       find_named (win, FS_PREFS_FW_LOG_ALLOWED) == NULL,
	       "Windows: no Reject/Drop, outbound mode or allowed logging");
	CHECK (find_named (win, FS_PREFS_FW_EXT_IF) == NULL &&
	       find_named (win, FS_PREFS_FW_INT_IF) == NULL &&
	       find_named (win, FS_PREFS_FW_NAT) == NULL,
	       "Windows: no device choosers and no connection sharing");
	{
		GtkWidget *pages = find_named (win, "prefs-pages");

		CHECK (mentions (pages, "IPv4 only") &&
		       mentions (pages, "Windows' own rules") &&
		       mentions (pages, "does not rate-limit these messages") &&
		       !mentions (pages, "Linux") &&
		       !mentions (pages, "IPv6 uses the same choices"),
		       "Windows ICMP notes: IPv4 allow rules beside Windows' "
		       "own, no rate limits, said without naming Linux");
		CHECK (!mentions (pages, "either way") &&
		       mentions (pages, "from anywhere, asked for or not"),
		       "Windows ICMP rows claim no more than the allow rules "
		       "they are");
		CHECK (mentions (pages, "Windows treats as public"),
		       "Windows protection rows describe the profile scoping");
	}
	CHECK (sensitive (win, FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST) &&
	       sensitive (win, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST) &&
	       sensitive (win, FS_PREFS_FW_BLOCK_NON_ROUTABLES),
	       "Windows protection switches are live (no device needed)");

	set_switch (win, FS_PREFS_FW_FILTER_ICMP, FALSE);
	click (win, "prefs-save");
}

static void
drive_cancel (GtkWidget *win)
{
	set_switch (win, FS_PREFS_SKIP_REDUNDANT, TRUE);
	set_switch (win, FS_PREFS_FW_ICMP_TIMESTAMPING, TRUE);
	click (win, "prefs-cancel");
}

static void
drive_no_change (GtkWidget *win)
{
	/* Toggle and toggle back: no change, nothing written, no question. */
	set_switch (win, FS_PREFS_FW_ICMP_TIMESTAMPING, TRUE);
	set_switch (win, FS_PREFS_FW_ICMP_TIMESTAMPING, FALSE);
	click (win, "prefs-save");
}

static const gchar *
footer (GtkWidget *win)
{
	GtkWidget *status = find_named (win, "prefs-status");

	return status != NULL ? gtk_label_get_text (GTK_LABEL (status)) : "";
}

/* Sharing stored on with only the Internet device: the switch must
 * stay movable both ways, and turning it off must be saved. */
static void
drive_nat_off_one_device (GtkWidget *win)
{
	CHECK (sensitive (win, FS_PREFS_FW_NAT) &&
	       reason_shown (win, FS_PREFS_FW_NAT),
	       "sharing stored on with one device: the switch can be moved, "
	       "and says it needs both devices");
	set_switch (win, FS_PREFS_FW_NAT, FALSE);
	CHECK (sensitive (win, FS_PREFS_FW_NAT) &&
	       g_strcmp0 (footer (win), "1 unsaved change") == 0,
	       "turned off, it stays movable and is counted (\"%s\")",
	       footer (win));
	set_switch (win, FS_PREFS_FW_NAT, TRUE);
	CHECK (g_strcmp0 (footer (win), "No changes") == 0,
	       "...and can be turned back on before saving (\"%s\")",
	       footer (win));
	set_switch (win, FS_PREFS_FW_NAT, FALSE);
	click (win, "prefs-save");
}

/* Both devices and sharing stored.  The local-broadcast block is
 * turned on while it can act, then the local device is cleared (which
 * disables that row) and sharing turned off: all three are saved. */
static void
drive_clear_int_and_nat_off (GtkWidget *win)
{
	CHECK (sensitive (win, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST),
	       "with both devices and sharing, the local-broadcast block is "
	       "live");
	set_switch (win, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST, TRUE);
	set_combo (win, FS_PREFS_FW_INT_IF, "");
	set_switch (win, FS_PREFS_FW_NAT, FALSE);
	CHECK (!sensitive (win, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST) &&
	       reason_shown (win, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST) &&
	       g_strcmp0 (footer (win), "3 unsaved changes") == 0,
	       "the block is disabled now, with its reason, and its change "
	       "still counts: three changes (\"%s\")", footer (win));
	click (win, "prefs-save");
}

/* What the generator emits with settings s: the Linux rules a
 * Protection or sharing row stands for. */
typedef struct
{
	gboolean ext_bcast, int_bcast, reserved, sharing;
} Emitted;

static gboolean
inbound_has (FsSettings *s, const gchar *needle)
{
	FsPolicy *p = fs_policy_new ();
	gchar *in = fs_script_generate_inbound (p, s);
	gboolean has = strstr (in, needle) != NULL;

	g_free (in);
	fs_policy_free (p);
	return has;
}

static Emitted
emitted (const gchar *ext, const gchar *intf, gboolean nat)
{
	FsSettings *s = fs_settings_new ();
	FsPolicy *p = fs_policy_new ();
	Emitted e;
	gchar *out, *in;

	s->ext_device = *ext != '\0' ? g_strdup (ext) : NULL;
	s->int_device = *intf != '\0' ? g_strdup (intf) : NULL;
	s->block_external_broadcast = FALSE;
	s->block_internal_broadcast = FALSE;
	s->block_non_routables = FALSE;

	/* One block at a time, so each line is told apart. */
	s->nat = nat;
	s->block_external_broadcast = TRUE;
	e.ext_bcast = inbound_has (s, "-d 255.255.255.255");
	s->block_external_broadcast = FALSE;
	s->block_internal_broadcast = TRUE;
	e.int_bcast = inbound_has (s, "-d 255.255.255.255");
	s->block_internal_broadcast = FALSE;
	s->block_non_routables = TRUE;
	e.reserved = inbound_has (s, "-s 10.0.0.0/8");
	s->block_non_routables = FALSE;

	/* Sharing as the switch would make it: on.  Router mode accepts
	 * what arrives on the local device and what leaves on the
	 * Internet one; either line means sharing acts. */
	s->nat = TRUE;
	in = fs_script_generate_inbound (p, s);
	out = fs_script_generate_outbound (p, s);
	{
		gchar *in_line = g_strdup_printf ("-A INBOUND -i %s -j ACCEPT",
		                                  intf);
		gchar *out_line = g_strdup_printf ("-A OUTBOUND -o %s -j ACCEPT",
		                                   ext);

		e.sharing = (*intf != '\0' && strstr (in, in_line) != NULL) ||
		            (*ext != '\0' && strstr (out, out_line) != NULL);
		g_free (in_line);
		g_free (out_line);
	}
	g_free (in);
	g_free (out);

	fs_policy_free (p);
	fs_settings_free (s);
	return e;
}

/* Every device and sharing combination: a row is live exactly when the
 * generator emits its rule, and disabled (with its reason) exactly when
 * it does not. */
static void
drive_dependencies (GtkWidget *win)
{
	static const gchar *exts[] = { "", "eth1" };
	static const gchar *ints[] = { "", "eth0" };
	guint agree = 0, n = 0;

	for (guint e = 0; e < G_N_ELEMENTS (exts); e++)
	for (guint i = 0; i < G_N_ELEMENTS (ints); i++)
	for (guint nat = 0; nat < 2; nat++) {
		Emitted gen = emitted (exts[e], ints[i], nat);
		gboolean ok;

		set_combo (win, FS_PREFS_FW_EXT_IF, exts[e]);
		set_combo (win, FS_PREFS_FW_INT_IF, ints[i]);
		set_switch (win, FS_PREFS_FW_NAT, nat);

		ok = sensitive (win, FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST) ==
		     gen.ext_bcast &&
		     reason_shown (win, FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST) ==
		     !gen.ext_bcast &&
		     sensitive (win, FS_PREFS_FW_BLOCK_NON_ROUTABLES) ==
		     gen.reserved &&
		     reason_shown (win, FS_PREFS_FW_BLOCK_NON_ROUTABLES) ==
		     !gen.reserved &&
		     sensitive (win, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST) ==
		     gen.int_bcast &&
		     reason_shown (win, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST) ==
		     !gen.int_bcast &&
		     reason_shown (win, FS_PREFS_FW_NAT) == !gen.sharing;
		n++;
		if (ok)
			agree++;
		else
			g_print ("       ext=%s int=%s nat=%u: generator "
			         "ext-bcast %d int-bcast %d reserved %d "
			         "sharing %d; window live %d %d %d, sharing "
			         "reason %d\n",
			         exts[e], ints[i], nat, gen.ext_bcast,
			         gen.int_bcast, gen.reserved, gen.sharing,
			         sensitive (win,
			                    FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST),
			         sensitive (win,
			                    FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST),
			         sensitive (win, FS_PREFS_FW_BLOCK_NON_ROUTABLES),
			         reason_shown (win, FS_PREFS_FW_NAT));
	}
	CHECK (agree == n && n == 8,
	       "every Protection and sharing row is live exactly when the "
	       "rule generator emits its rule (%u/%u combinations)", agree, n);
	click (win, "prefs-cancel");
}

/* One firewall setting flipped and saved. */
static void
drive_flip_echo (GtkWidget *win)
{
	GtkWidget *w = find_named (win, FS_PREFS_FW_ICMP_ECHO_REQUEST);

	set_switch (win, FS_PREFS_FW_ICMP_ECHO_REQUEST,
	            w != NULL && !gtk_switch_get_active (GTK_SWITCH (w)));
	click (win, "prefs-save");
}

static void
drive_flip_timestamps (GtkWidget *win)
{
	GtkWidget *w = find_named (win, FS_PREFS_FW_ICMP_TIMESTAMPING);

	set_switch (win, FS_PREFS_FW_ICMP_TIMESTAMPING,
	            w != NULL && !gtk_switch_get_active (GTK_SWITCH (w)));
	click (win, "prefs-save");
}

static FsPolicy *
policy_with_deny (void)
{
	FsPolicy *p = fs_policy_new ();
	FsRule *rule = fs_rule_new (FS_RULE_OUTBOUND_DENY_TO);

	rule->target = g_strdup ("192.0.2.66");
	fs_policy_add (p, rule);
	fs_rule_free (rule);
	return p;
}

static FsPolicy *
policy_with_allow (void)
{
	FsPolicy *p = fs_policy_new ();
	FsRule *rule = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);

	rule->service = g_strdup ("HTTP");
	rule->port = g_strdup ("80");
	rule->target = g_strdup ("Anyone");
	fs_policy_add (p, rule);
	fs_rule_free (rule);
	return p;
}

static gchar *
journal_setting (const gchar *key)
{
	GHashTable *recorded = fs_apply_journal_settings ();
	gchar *value = recorded != NULL
		? g_strdup (g_hash_table_lookup (recorded, key)) : NULL;

	if (recorded != NULL)
		g_hash_table_unref (recorded);
	return value;
}

static gboolean
file_mentions (const gchar *path, const gchar *needle)
{
	gchar *text = NULL;
	gboolean found = g_file_get_contents (path, &text, NULL, NULL) &&
	                 strstr (text, needle) != NULL;

	g_free (text);
	return found;
}

#endif

/* ============================================================== main */

/* sRGB to linear light, WCAG's formula, without libm: the 2.4 power
 * is a square times the square of a fifth root (Newton, from 1.0). */
static gdouble
linear (gdouble v)
{
	gdouble a, y = 1.0;

	if (v <= 0.03928)
		return v / 12.92;
	a = (v + 0.055) / 1.055;
	for (guint i = 0; i < 60; i++)
		y -= (y * y * y * y * y - a) / (5 * y * y * y * y);
	return a * a * y * y;
}

static gdouble
luminance (const GdkRGBA *c)
{
	return 0.2126 * linear (c->red) + 0.7152 * linear (c->green) +
	       0.0722 * linear (c->blue);
}

/* The keyboard focus ring on a switch, as the theme computes it: the
 * ring is drawn on the slider, so it must be solid, at least 2px, and
 * stand out from the slider by 3:1 (WCAG non-text contrast).  GTK's
 * own default is a 1px dash in a faded grey.  The slider is a CSS
 * node, not a widget, so it is reached through a widget path:
 * window > switch:focus > slider. */
static void
check_switch_focus_ring (void)
{
	GtkWidgetPath *path = gtk_widget_path_new ();
	GtkStyleContext *ctx = gtk_style_context_new ();
	GdkRGBA *ring = NULL, *slider = NULL;
	GtkBorderStyle style = GTK_BORDER_STYLE_NONE;
	gint width = 0;
	gdouble l1, l2, ratio = 0;

	gtk_widget_path_append_type (path, GTK_TYPE_WINDOW);
	gtk_widget_path_iter_set_object_name (path, -1, "window");
	gtk_widget_path_append_type (path, GTK_TYPE_SWITCH);
	gtk_widget_path_iter_set_object_name (path, -1, "switch");
	gtk_widget_path_iter_set_state (path, -1, GTK_STATE_FLAG_FOCUSED);
	gtk_widget_path_append_type (path, GTK_TYPE_WIDGET);
	gtk_widget_path_iter_set_object_name (path, -1, "slider");
	gtk_style_context_set_path (ctx, path);
	gtk_style_context_set_screen (ctx, gdk_screen_get_default ());

	gtk_style_context_get (ctx, gtk_style_context_get_state (ctx),
	                       "outline-color", &ring,
	                       "outline-style", &style,
	                       "outline-width", &width,
	                       "background-color", &slider, NULL);

	if (ring != NULL && slider != NULL) {
		l1 = luminance (ring);
		l2 = luminance (slider);
		ratio = (MAX (l1, l2) + 0.05) / (MIN (l1, l2) + 0.05);
	}
	CHECK (style == GTK_BORDER_STYLE_SOLID && width >= 2 && ratio >= 3.0 &&
	       ring != NULL && ring->alpha == 1.0,
	       "a focused switch is ringed solid, %dpx, %.2f:1 against its "
	       "slider", width, ratio);

	if (ring != NULL)
		gdk_rgba_free (ring);
	if (slider != NULL)
		gdk_rgba_free (slider);
	g_object_unref (ctx);
	gtk_widget_path_unref (path);
}

static void
check_about_and_theme (void)
{
	const gchar * const *credits = fs_dialogs_about_credits ();
	static const gchar *const tokens[] = {
		"#f4f5f7", "#14161b", "#16181d", "#2a2f39", "#eaf0fb",
		"#ffebee", "#b71c1c", "#f9f9f9",
	};
	static const gchar *const forbidden[] = { ":focused", ":insensitive" };
	GtkCssProvider *provider = gtk_css_provider_new ();
	GError *error = NULL;

	/* The About credits are plain text now (the window sets them on
	 * labels, not as GtkAboutDialog markup): the creator line reads
	 * exactly as written, and no line carries an e-mail address.  The
	 * About window itself is covered by fs-help-smoke. */
	CHECK (credits != NULL && credits[0] != NULL, "About has credits");
	CHECK (credits != NULL && g_strcmp0 (credits[0],
	       "Stock Team & Qusai - Creator & Original Developer") == 0,
	       "the creator line reads as written");
	for (guint i = 0; credits != NULL && credits[i] != NULL; i++)
		CHECK (strchr (credits[i], '@') == NULL,
		       "about credit %u carries no e-mail address", i);

	CHECK (gtk_css_provider_load_from_data (provider, fs_theme_css, -1,
	                                        &error) && error == NULL,
	       "theme loads clean%s%s", error ? ": " : "",
	       error ? error->message : "");
	g_clear_error (&error);
	for (guint i = 0; i < G_N_ELEMENTS (tokens); i++)
		CHECK (strstr (fs_theme_css, tokens[i]) != NULL,
		       "theme keeps palette token %s", tokens[i]);
	for (guint i = 0; i < G_N_ELEMENTS (forbidden); i++)
		CHECK (strstr (fs_theme_css, forbidden[i]) == NULL,
		       "theme avoids deprecated %s", forbidden[i]);

	/* The theme drives the window: install it as the app does. */
	gtk_style_context_add_provider_for_screen (
		gdk_screen_get_default (), GTK_STYLE_PROVIDER (provider),
		GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	g_object_unref (provider);

	check_switch_focus_ring ();
}

int
main (int argc, char **argv)
{
	gchar *dir;

	/* Isolate the settings file before anything computes its path. */
	dir = g_dir_make_tmp ("stockfw-prefs-smoke-XXXXXX", NULL);
#ifdef G_OS_WIN32
	g_setenv ("APPDATA", dir, TRUE);
#else
	g_setenv ("XDG_CONFIG_HOME", dir, TRUE);
#endif
	g_log_set_writer_func (count_warnings, NULL, NULL);

	gtk_init (&argc, &argv);
	g_mkdir_with_parents (g_path_get_dirname (fs_prefs_path ()), 0700);

	check_about_and_theme ();

#ifndef FS_PREFS_FAKE_BACKEND
	{
		static Scenario real = { "real", drive_real, ANSWER_NONE,
		                         FALSE, FALSE, FALSE, NULL };
		gchar *keys;

		seed ("[client]\nenable_tray_icon=true\n");
		run_scenario (&real);
		keys = disk_table_keys ();
		CHECK (g_strcmp0 (keys, "client/enable_tray_icon=true;") == 0,
		       "Save without a change writes nothing (%s)", keys);
		g_free (keys);
	}
#else
	{
		static Scenario linux_run = { "linux", drive_linux, ANSWER_LATER,
		                              FALSE, FALSE, FALSE, NULL };
		static Scenario windows_run = { "windows", drive_windows,
		                                ANSWER_NONE,
		                                FALSE, FALSE, FALSE, NULL };
		static Scenario cancel_run = { "cancel", drive_cancel,
		                               ANSWER_NONE,
		                               FALSE, FALSE, FALSE, NULL };
		static Scenario same_run = { "no-change", drive_no_change,
		                             ANSWER_NONE,
		                             FALSE, FALSE, FALSE, NULL };
		static Scenario nat_off_run = { "nat-off-one-device",
		                                drive_nat_off_one_device,
		                                ANSWER_NONE,
		                                FALSE, FALSE, FALSE, NULL };
		static Scenario clear_int_run = { "clear-local-device-and-nat",
		                                  drive_clear_int_and_nat_off,
		                                  ANSWER_NONE,
		                                  FALSE, FALSE, FALSE, NULL };
		static Scenario deps_run = { "dependencies", drive_dependencies,
		                             ANSWER_NONE,
		                             FALSE, FALSE, FALSE, NULL };
		static Scenario live_run = { "apply-under-live-policy",
		                             drive_flip_echo, ANSWER_APPLY_NOW,
		                             FALSE, FALSE, FALSE, NULL };
		static Scenario later_run = { "later-then-policy-apply",
		                              drive_flip_timestamps, ANSWER_LATER,
		                              FALSE, FALSE, FALSE, NULL };
		static Scenario fresh_run = { "windows-off-no-journal",
		                              drive_flip_echo, ANSWER_APPLY_NOW,
		                              FALSE, FALSE, FALSE, NULL };
		gchar *keys, *value = NULL;
		gchar *journal = g_build_filename (dir, "applied.csv", NULL);
		gchar *audit = g_build_filename (dir, "audit.log", NULL);
		FsPolicy *loaded, *live;
		FsSettings *loaded_settings;
		FsApplyOutcome *outcome;
		guint calls;

		/* The apply gate's journal and audit log, in the scratch
		 * directory too. */
		g_setenv ("STOCKFW_APPLIED_FILE", journal, TRUE);
		g_setenv ("STOCKFW_AUDIT_FILE", audit, TRUE);

		/* ---- Windows, before any policy is loaded ---- */
		fake_as_windows ();
		fake_state = FS_FW_RUNNING;
		seed ("[firewall]\ndeny_packets=false\n"
		      "restrictive_outbound=true\next_if=eth1\n");
		run_scenario (&windows_run);
		keys = disk_table_keys ();
		CHECK (g_strcmp0 (keys,
		                  "firewall/ext_if=eth1;"
		                  "firewall/icmp/enable=false;"
		                  "firewall/deny_packets=false;"
		                  "firewall/restrictive_outbound=true;") == 0,
		       "D8: on Windows only the ICMP switch was written; the "
		       "settings Windows does not offer kept their values (%s)",
		       keys);
		g_free (keys);
		CHECK (windows_run.reported && windows_run.report_text != NULL &&
		       strstr (windows_run.report_text, "no policy loaded") != NULL,
		       "with no policy loaded the window says so instead of "
		       "asking to apply");
		CHECK (fake_apply_calls == 0,
		       "an empty policy is never applied in place of the real "
		       "one");

		/* From here on the app has a loaded policy, as it does once
		 * the main window is built: one inbound allow. */
		loaded = policy_with_allow ();
		loaded_settings = fs_settings_new ();
		fs_app_test_set_context (loaded, loaded_settings);

		/* ---- Linux ---- */
		fake_as_linux ();
		fake_state = FS_FW_RUNNING;
		seed ("[firewall]\next_if=eth1\nint_if=eth9\n");
		run_scenario (&linux_run);
		keys = disk_table_keys ();
		CHECK (g_strcmp0 (keys,
		                  "client/filter/redundant=true;"
		                  "firewall/ext_if=eth1;firewall/int_if=eth9;"
		                  "firewall/icmp/echo_request=false;") == 0,
		       "D8: Save wrote exactly the two changed settings and "
		       "kept both devices (%s)", keys);
		g_free (keys);
		CHECK (!disk_has (FS_PREFS_APPLY_POLICY_INSTANTLY, NULL) &&
		       !fs_prefs_bool (FS_PREFS_APPLY_POLICY_INSTANTLY),
		       "D3: Save did not turn \"apply immediately\" on");
		CHECK (fake_apply_calls == 0,
		       "\"Later\" left the firewall alone");
		CHECK (last_question != NULL &&
		       strstr (last_question, "No applied policy is on record")
		       != NULL &&
		       strstr (last_question, "+1 added") != NULL &&
		       strstr (last_question, "or the firewall is started") != NULL,
		       "with nothing applied yet, the question says the policy "
		       "goes out too and what it changes; Linux's Start brings "
		       "the settings in");

		/* ---- Cancel writes nothing ---- */
		keys = disk_table_keys ();
		run_scenario (&cancel_run);
		{
			gchar *after = disk_table_keys ();

			CHECK (g_strcmp0 (keys, after) == 0,
			       "Cancel wrote nothing");
			g_free (after);
		}

		/* ---- Changed and changed back: nothing ---- */
		run_scenario (&same_run);
		{
			gchar *after = disk_table_keys ();

			CHECK (g_strcmp0 (keys, after) == 0,
			       "a setting changed and changed back is not "
			       "written, and asks nothing");
			g_free (after);
		}
		g_free (keys);

		/* ---- Sharing turned off with a device missing ---- */
		fake_state = FS_FW_STOPPED;
		seed ("[firewall]\next_if=eth1\nnat=true\n");
		run_scenario (&nat_off_run);
		CHECK (disk_has (FS_PREFS_FW_NAT, &value) &&
		       g_strcmp0 (value, "false") == 0,
		       "sharing turned off with only the Internet device is "
		       "saved (nat=%s)", value != NULL ? value : "(unset)");
		g_clear_pointer (&value, g_free);
		CHECK (!nat_off_run.asked && fake_apply_calls == 0,
		       "Linux with the firewall off: nothing asked, nothing "
		       "applied (Start applies the saved settings)");

		seed ("[firewall]\next_if=eth1\nint_if=eth0\nnat=true\n");
		run_scenario (&clear_int_run);
		keys = disk_table_keys ();
		CHECK (g_strcmp0 (keys, "firewall/ext_if=eth1;firewall/int_if=;"
		                        "firewall/nat=false;"
		                        "firewall/block_internal_broadcast=true;")
		       == 0,
		       "the change to a row disabled before Save is saved with "
		       "the rest, as the footer counted (%s)", keys);
		g_free (keys);

		/* ---- The window's dependencies are the generator's ---- */
		seed ("");
		run_scenario (&deps_run);

		/* ---- Apply now: under the policy that is live ----
		 * The journal says one outbound block is live; the loaded
		 * policy (the Policy page's) has it removed and an allow
		 * added, never applied.  Applying a settings change must
		 * push the live policy, not those edits. */
		fake_as_linux ();
		fake_state = FS_FW_RUNNING;
		seed ("");
		live = policy_with_deny ();
		CHECK (fs_apply_journal_save (live, NULL) &&
		       !fs_apply_settings_pending (),
		       "the live policy is on record with the saved settings");
		calls = fake_apply_calls;
		run_scenario (&live_run);
		CHECK (fake_apply_calls == calls + 1 && fake_last_has_deny &&
		       fake_last_rows == 1,
		       "\"Apply now\" reached the apply gate once, with the "
		       "live policy (the block kept, the unapplied allow left "
		       "out: %u row(s))", fake_last_rows);
		CHECK (last_question != NULL &&
		       strstr (last_question, "stay pending") != NULL &&
		       strstr (last_question, "-1 removed (0 allow, 1 block)")
		       != NULL,
		       "the question says the Policy page's unapplied changes "
		       "stay pending, and what they are");
		CHECK (live_run.reported && live_run.report_text != NULL &&
		       strstr (live_run.report_text, "new settings") != NULL &&
		       strstr (live_run.report_text, "left out") != NULL,
		       "the report says the settings are live and the policy "
		       "changes were left out");
		{
			FsPolicy *after = fs_policy_new ();
			gchar *echo = journal_setting (FS_PREFS_FW_ICMP_ECHO_REQUEST);

			CHECK (fs_apply_journal_load (after, NULL) &&
			       after->kinds[FS_RULE_OUTBOUND_DENY_TO]->len == 1 &&
			       after->kinds[FS_RULE_INBOUND_ALLOW_SERVICE]->len == 0 &&
			       g_strcmp0 (echo, "false") == 0 &&
			       !fs_apply_settings_pending (),
			       "the journal still holds the live policy and now "
			       "records the new settings (echo_request=%s)",
			       echo != NULL ? echo : "(none)");
			g_free (echo);
			fs_policy_free (after);
		}
		CHECK (file_mentions (audit, "| firewall settings applied |"),
		       "the apply is audited as a settings apply");

		/* ---- Later, then the next policy apply brings them in ----
		 * Even with the policy unchanged, which the gate otherwise
		 * calls "no change" and leaves alone. */
		run_scenario (&later_run);
		CHECK (fs_apply_settings_pending (),
		       "after \"Later\" the saved settings are pending");
		calls = fake_apply_calls;
		outcome = fs_policy_apply_safe (fs_backend (), live, "smoke",
		                                NULL, NULL);
		CHECK (outcome != NULL && outcome->applied && outcome->settings &&
		       !outcome->narrow && fake_apply_calls == calls + 1 &&
		       !fs_apply_settings_pending (),
		       "the next apply of the unchanged policy is a whole one "
		       "and brings the pending settings in");
		fs_apply_outcome_free (outcome);
		calls = fake_apply_calls;
		outcome = fs_policy_apply_safe (fs_backend (), live, "smoke",
		                                NULL, NULL);
		CHECK (outcome != NULL && outcome->narrow && !outcome->settings &&
		       fake_apply_calls == calls,
		       "...and the one after it is \"no change\" again");
		fs_apply_outcome_free (outcome);

		/* ---- Windows, firewall off, nothing on record ----
		 * Start only turns the profiles on there, so a change is
		 * offered even with the firewall off; with no journal it can
		 * only go out with the loaded policy, and the question says
		 * so. */
		fake_as_windows ();
		fake_state = FS_FW_STOPPED;
		g_remove (journal);
		calls = fake_apply_calls;
		run_scenario (&fresh_run);
		CHECK (last_question != NULL &&
		       strstr (last_question, "The firewall is off") != NULL &&
		       strstr (last_question, "No applied policy is on record")
		       != NULL &&
		       strstr (last_question, "or the firewall is started") == NULL,
		       "Windows, firewall off: asked anyway, the policy named, "
		       "and no promise that Start applies the settings");
		CHECK (fake_apply_calls == calls + 1 && !fake_last_has_deny &&
		       fake_last_rows == 1 && fresh_run.report_text != NULL &&
		       strstr (fresh_run.report_text,
		               "Your policy was applied with them") != NULL,
		       "with nothing on record, the loaded policy went out with "
		       "the settings, as the question said");
		CHECK (fresh_run.report_text != NULL &&
		       strstr (fresh_run.report_text, "still off") != NULL &&
		       strstr (fresh_run.report_text, "now uses") == NULL,
		       "firewall off: the report says the settings wait for it "
		       "to be turned on, not that it uses them now");

		fs_app_test_set_context (NULL, NULL);
		fs_policy_free (loaded);
		fs_policy_free (live);
		fs_settings_free (loaded_settings);
		g_free (journal);
		g_free (audit);
		(void) value;
		CHECK (fake_list_calls > 0, "Linux asked for its devices");
	}
#endif

	CHECK (warnings == 0, "no GLib/GTK warnings (%u)", warnings);

	g_print ("\nui-prefs-smoke: %s, %d failure(s)\n",
	         failures ? "FAILED" : "PASSED", failures);
	return failures ? 1 : 0;
}
