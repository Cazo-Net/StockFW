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
 *                             setting the window does not offer;
 *                           - D5: a firewall change with the firewall
 *                             running asks before applying, never applies
 *                             an empty policy, and Cancel writes nothing.
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
                        FS_FWHON_OUTBOUND_MODE | FS_FWHON_ICMP_EXACT)
#define WINDOWS_SECTIONS (FS_FWSEC_ICMP | FS_FWSEC_ADVANCED)
#define WINDOWS_HONORS   0u

/* ===================================================== fake backend */
#ifdef FS_PREFS_FAKE_BACKEND

static FsFirewallState fake_state = FS_FW_RUNNING;
static guint fake_apply_calls = 0;
static guint fake_list_calls = 0;

static gboolean fake_available (void) { return TRUE; }
static FsFirewallState fake_get_state (void) { return fake_state; }

static FsApplyResult
fake_apply_rules (const FsPolicy *policy, GError **error)
{
	(void) policy;
	(void) error;
	fake_apply_calls++;
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

/* Nothing the port does not do may be on offer anywhere. */
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
	CHECK (hits == 0, "[%s] no dead control or Help button on any page",
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
		       "[%s] a firewall change with the firewall running asks "
		       "\"Apply the new firewall settings now?\"", scenario->tag);
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
		       !mentions (icmp, "rate limits"),
		       "Linux ICMP notes: IPv6 yes, Windows caveats no");
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
		       mentions (pages, "rate limits") &&
		       !mentions (pages, "IPv6 uses the same choices"),
		       "Windows ICMP notes: IPv4 allow rules beside Windows' "
		       "own, no rate limits");
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

#endif

/* ============================================================== main */

static void
check_about_and_theme (void)
{
	const gchar **authors = fs_dialogs_about_authors ();
	static const gchar *const tokens[] = {
		"#f4f5f7", "#14161b", "#16181d", "#2a2f39", "#eaf0fb",
		"#ffebee", "#b71c1c", "#f9f9f9",
	};
	static const gchar *const forbidden[] = { ":focused", ":insensitive" };
	GtkCssProvider *provider = gtk_css_provider_new ();
	GError *error = NULL;

	/* GtkAboutDialog parses authors as markup without escaping them,
	 * so each must parse -- and the creator line must read as written. */
	CHECK (authors != NULL && authors[0] != NULL, "About has authors");
	for (guint i = 0; authors != NULL && authors[i] != NULL; i++) {
		gchar *plain = NULL;
		gboolean ok = pango_parse_markup (authors[i], -1, '\0', NULL,
		                                  &plain, NULL, NULL);

		CHECK (ok, "about author %u is valid markup", i);
		if (i == 0)
			CHECK (g_strcmp0 (plain,
			                  "Qusai Fethalrahman (Qusaifox2@gmail.com)"
			                  " - Creator & Original Developer") == 0,
			       "the creator line renders as written");
		g_free (plain);
	}

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
		                                ANSWER_APPLY_NOW,
		                                FALSE, FALSE, FALSE, NULL };
		static Scenario cancel_run = { "cancel", drive_cancel,
		                               ANSWER_NONE,
		                               FALSE, FALSE, FALSE, NULL };
		static Scenario same_run = { "no-change", drive_no_change,
		                             ANSWER_NONE,
		                             FALSE, FALSE, FALSE, NULL };
		gchar *keys, *value = NULL;

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

		/* ---- Windows ---- */
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
		       "\"Apply now\" with no policy loaded says so instead of "
		       "applying");
		CHECK (fake_apply_calls == 0,
		       "an empty policy is never applied in place of the real "
		       "one");
		(void) value;
		CHECK (fake_list_calls > 0, "Linux asked for its devices");
	}
#endif

	CHECK (warnings == 0, "no GLib/GTK warnings (%u)", warnings);

	g_print ("\nui-prefs-smoke: %s, %d failure(s)\n",
	         failures ? "FAILED" : "PASSED", failures);
	return failures ? 1 : 0;
}
