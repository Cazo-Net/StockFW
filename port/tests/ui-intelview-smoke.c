/* The Threat Intel page (1.0.7, design 8) and the Events page's list
 * attribution, against a fake backend and a fake downloader.
 *
 * The page is built in an offscreen window and driven the way a user
 * drives it: switches are flipped, buttons clicked, text typed, and an
 * auto-responder stands in for the user at every dialog.  What is read
 * back is what the user reads: the state card's title, each feed's
 * status and facts, the buttons that appear, the lookup's answer.
 *
 *   - opening the page with no store reads "Off" and creates nothing;
 *   - turning a feed on asks for consent first; Cancel downloads
 *     nothing, Accept downloads it, puts it in force: "Protected";
 *   - the work runs in a worker: the main loop keeps running while a
 *     slow download is in progress, and the progress line names it;
 *   - blocked counters per feed, "Not loaded" with Apply, "Paused",
 *     "Changed outside StockFW", "Unknown", "Not supported";
 *   - a refused update offers "Accept smaller list", which lets it in;
 *     a failed one says so and keeps the copy;
 *   - a firewall that is stopped: saved, not applied; a hold (the
 *     Lock): saved, not applied, and the reason;
 *   - the allow list, your blocklist, an imported list, removal;
 *   - the lookup box;
 *   - Events: a list's block shows the list's name, is found by the
 *     filter, carries the rule in the selection, and "Add exception"
 *     puts the address on the allow list;
 *   - countries and networks (design 13.11), with tests/geodb's small
 *     database: the consent dialog's text, Cancel and Accept, the
 *     database's date and state, the picker's model (every country,
 *     the networks searched as you type), adding by picking and by
 *     typing a code, the anycast warning and its tooltip, the lookup's
 *     "Registered in" and licence line, Remove, Update database, off,
 *     and the sentence (no control) where the platform has none.
 *
 * With INTEL_SMOKE_SHOTS=<dir>, a PNG of the page in each state.
 * Teeth: tests/README.md, "The Threat Intel page".
 */

#include <gtk/gtk.h>
#include <glib/gstdio.h>
#include <lzma.h>
#include <stdio.h>
#include <string.h>
#ifdef G_OS_WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#endif
#ifndef G_OS_WIN32
#include <unistd.h>
#endif

#include "core/fs-backend.h"
#include "core/fs-feed.h"
#include "core/fs-geodb.h"
#include "core/fs-intel.h"
#include "core/fs-winstore.h"
#include "core/fs-intelset.h"
#include "core/fs-netparse.h"
#include "core/fs-prefs.h"
#include "ui/fs-hitview.h"
#include "ui/fs-intelview.h"
#include "ui/fs-tray.h"
#include "fs-theme-css.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	printf ((cond) ? "ok:   " : "FAIL: ");                  \
	printf (__VA_ARGS__);                                   \
	printf ("\n");                                          \
	fflush (stdout);                                        \
	if (!(cond))                                            \
		failures++;                                     \
} while (0)

/* ------------------------------------------------------- fake kernel */

static struct
{
	FsIntelLive     live;
	gchar          *digest;
	GHashTable     *counters;     /* id -> FsIntelCounter*           */
	gboolean        unknown;
	FsFirewallState fw;
	guint           apply_calls;
	guint           clear_calls;
	gchar          *last_sets;    /* "id id ..." of the last apply   */
	gboolean        apply_inactive; /* rules written, not enforced
	                              * (Windows: off for the profile)   */
} kern;

static void
counter_set (GHashTable *t, const gchar *id, guint64 p)
{
	FsIntelCounter *c = g_new0 (FsIntelCounter, 1);

	c->packets = p;
	c->bytes = p * 60;
	g_hash_table_replace (t, g_strdup (id), c);
}

static gboolean
fake_apply (const FsIntelRuleset *rs, GError **error)
{
	GString *ids = g_string_new (NULL);

	(void) error;
	kern.apply_calls++;
	g_free (kern.digest);
	kern.digest = rs->sets->len ? fs_intel_ruleset_digest (rs) : NULL;
	kern.live = !rs->sets->len ? FS_INTEL_LIVE_ABSENT
	            : kern.apply_inactive ? FS_INTEL_LIVE_INACTIVE
	            : FS_INTEL_LIVE_PRESENT;
	g_hash_table_remove_all (kern.counters);
	for (guint i = 0; i < rs->sets->len; i++) {
		const FsIntelSet *s = g_ptr_array_index (rs->sets, i);

		g_string_append_printf (ids, "%s%s", i ? " " : "", s->id);
		if (!fs_range_set_is_empty (s->ranges))
			counter_set (kern.counters, s->id, 0);
	}
	g_free (kern.last_sets);
	kern.last_sets = g_string_free (ids, FALSE);
	return TRUE;
}

static gboolean
fake_clear (GError **error)
{
	(void) error;
	kern.clear_calls++;
	kern.live = FS_INTEL_LIVE_ABSENT;
	g_clear_pointer (&kern.digest, g_free);
	g_hash_table_remove_all (kern.counters);
	return TRUE;
}

static GHashTable *
fake_counters (void)
{
	GHashTable *t;
	GHashTableIter it;
	gpointer k, v;

	if (kern.unknown || kern.live != FS_INTEL_LIVE_PRESENT)
		return NULL;
	t = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	g_hash_table_iter_init (&it, kern.counters);
	while (g_hash_table_iter_next (&it, &k, &v))
		counter_set (t, k, ((FsIntelCounter *) v)->packets);
	return t;
}

static FsIntelLive
fake_live (gchar **digest)
{
	if (digest != NULL)
		*digest = NULL;
	if (kern.unknown)
		return FS_INTEL_LIVE_UNKNOWN;
	if (digest != NULL && (kern.live == FS_INTEL_LIVE_PRESENT ||
	                       kern.live == FS_INTEL_LIVE_INACTIVE))
		*digest = g_strdup (kern.digest);
	return kern.live;
}

/* The Windows backend's sentence when the rules are there and not
 * enforced (fs-intelwin.c words it per profile). */
#define WIN_NOT_IN_FORCE "Windows Firewall is off for the Public profile, " \
                         "which the network in use has."

static gchar *
fake_not_in_force (void)
{
	return kern.live == FS_INTEL_LIVE_INACTIVE
	       ? g_strdup (WIN_NOT_IN_FORCE) : NULL;
}

static FsFirewallState
fake_get_state (void)
{
	return kern.fw;
}

static FsBackend fake_backend;
static FsBackend bare_backend;     /* no intel slots: another platform */
static FsBackend win_backend;      /* like Windows: no counters slot,
                                    * a not-in-force sentence          */

/* --------------------------------------------------------- fake net */

static GHashTable *bodies;          /* url -> body                    */
static GHashTable *errors;          /* url -> message                 */
static guint       fetches;
static gulong      fetch_delay_us;

static GBytes *
fake_fetch (const gchar *url, const gchar *proxy, gpointer data,
            GError **error)
{
	const gchar *b;

	(void) proxy;
	(void) data;
	g_atomic_int_inc (&fetches);
	if (fetch_delay_us > 0)
		g_usleep (fetch_delay_us);
	if (g_hash_table_lookup (errors, url) != NULL) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "%s",
		             (const gchar *) g_hash_table_lookup (errors, url));
		return NULL;
	}
	b = g_hash_table_lookup (bodies, url);
	if (b == NULL) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
		             "HTTP 404 for %s", url);
		return NULL;
	}
	return g_bytes_new (b, strlen (b));
}

static void
serve (const gchar *id, const gchar *body)
{
	const gchar *url = fs_feed_catalog_find (id)->url;

	g_hash_table_remove (errors, url);
	g_hash_table_replace (bodies, g_strdup (url), g_strdup (body));
}

static void
serve_error (const gchar *id, const gchar *message)
{
	const gchar *url = fs_feed_catalog_find (id)->url;

	g_hash_table_replace (errors, g_strdup (url), g_strdup (message));
}

static gchar *
plain_body (guint n, guint first_octet)
{
	GString *out = g_string_new ("# Last updated: test\n");

	for (guint i = 0; i < n; i++)
		g_string_append_printf (out, "%u.%u.%u.1\n", first_octet,
		                        i / 250, i % 250 + 1);
	return g_string_free (out, FALSE);
}

static gchar *
drop_body (const gchar *cidrs)
{
	GString *out = g_string_new (NULL);
	gchar **v = g_strsplit (cidrs, " ", -1);
	guint n = 0;

	for (guint i = 0; v[i] != NULL; i++, n++)
		g_string_append_printf (out, "{\"cidr\":\"%s\",\"sblid\":"
		                        "\"SBL%u\",\"rir\":\"arin\"}\n", v[i], i);
	g_string_append_printf (out, "{\"type\":\"metadata\",\"timestamp\":%"
	                        G_GINT64_FORMAT ",\"size\":1,\"records\":%u}\n",
	                        g_get_real_time () / G_USEC_PER_SEC - 3600, n);
	g_strfreev (v);
	return g_string_free (out, FALSE);
}

/* ---------------------------------------------------- the responder */

static gint   next_response = GTK_RESPONSE_ACCEPT;
static gchar *last_dialog = NULL;     /* widget name of the last one   */
static gchar *last_dialog_text = NULL;
static guint  dialogs = 0;

static gint
respond (GtkDialog *dialog, gpointer data)
{
	gchar *primary = NULL, *secondary = NULL;

	(void) data;
	dialogs++;
	g_free (last_dialog);
	last_dialog = g_strdup (gtk_widget_get_name (GTK_WIDGET (dialog)));
	if (GTK_IS_MESSAGE_DIALOG (dialog))
		g_object_get (dialog, "text", &primary, "secondary-text",
		              &secondary, NULL);
	g_free (last_dialog_text);
	last_dialog_text = g_strdup_printf ("%s\n%s", primary ? primary : "",
	                                    secondary ? secondary : "");
	g_free (primary);
	g_free (secondary);
	return next_response;
}

/* ------------------------------------------------------ widget walk */

static GtkWidget *
find (GtkWidget *w, const gchar *name)
{
	if (g_strcmp0 (gtk_widget_get_name (w), name) == 0)
		return w;
	if (GTK_IS_CONTAINER (w)) {
		GList *kids = gtk_container_get_children (GTK_CONTAINER (w));
		GtkWidget *hit = NULL;

		for (GList *l = kids; l != NULL && hit == NULL; l = l->next)
			hit = find (GTK_WIDGET (l->data), name);
		g_list_free (kids);
		return hit;
	}
	return NULL;
}

static GtkWidget *page;
static GtkWidget *window;

static const gchar *
text_of (const gchar *name)
{
	GtkWidget *w = find (page, name);

	return w != NULL && GTK_IS_LABEL (w) ? gtk_label_get_text (GTK_LABEL (w))
	                                     : "";
}

static gboolean
visible (const gchar *name)
{
	GtkWidget *w = find (page, name);

	return w != NULL && gtk_widget_get_visible (w);
}

/* ------------------------------------------------------- main loop */

/* While waiting: how often a 10 ms timer fired on the main loop, and
 * every progress line the page showed. */
static guint   ticks;
static GString *seen_progress;

static gboolean
tick (gpointer data)
{
	(void) data;
	ticks++;
	return G_SOURCE_CONTINUE;
}

static void
wait_idle (void)
{
	gint64 until = g_get_monotonic_time () + 20 * G_USEC_PER_SEC;
	guint id = g_timeout_add (10, tick, NULL);

	do {
		while (gtk_events_pending ())
			gtk_main_iteration ();
		if (visible ("intel-progress")) {
			const gchar *t = text_of ("intel-progress-label");

			if (t != NULL && *t != '\0' &&
			    strstr (seen_progress->str, t) == NULL)
				g_string_append_printf (seen_progress, "%s|", t);
		}
		g_usleep (2000);
	} while (fs_intelview_busy () && g_get_monotonic_time () < until);
	while (gtk_events_pending ())
		gtk_main_iteration ();
	g_source_remove (id);
}

static void
refresh (void)
{
	fs_intelview_refresh ();
	wait_idle ();
}

static void
flip (const gchar *id, gboolean on)
{
	gchar *name = g_strdup_printf ("feed-switch-%s", id);
	GtkWidget *sw = find (page, name);

	CHECK (sw != NULL && gtk_widget_is_sensitive (sw),
	       "the switch for %s is there and can be used", id);
	g_free (name);
	if (sw != NULL)
		gtk_switch_set_active (GTK_SWITCH (sw), on);
	wait_idle ();
}

static void
click (const gchar *name)
{
	GtkWidget *b = find (page, name);

	CHECK (b != NULL && gtk_widget_is_sensitive (b) &&
	       gtk_widget_get_visible (b), "%s can be clicked", name);
	if (b != NULL)
		gtk_button_clicked (GTK_BUTTON (b));
	wait_idle ();
}

/* Every label under a widget, its markup joined by newlines. */
static gchar *
row_labels (GtkWidget *row)
{
	GString *all = g_string_new (NULL);
	GQueue q = G_QUEUE_INIT;

	if (row != NULL)
		g_queue_push_tail (&q, row);
	while (!g_queue_is_empty (&q)) {
		GtkWidget *w = g_queue_pop_head (&q);

		if (GTK_IS_LABEL (w)) {
			g_string_append (all, gtk_label_get_label (GTK_LABEL (w)));
			g_string_append_c (all, '\n');
		}
		if (GTK_IS_CONTAINER (w)) {
			GList *kids = gtk_container_get_children (GTK_CONTAINER (w));

			for (GList *l = kids; l != NULL; l = l->next)
				g_queue_push_tail (&q, l->data);
			g_list_free (kids);
		}
	}
	return g_string_free (all, FALSE);
}

static gchar *
feed_text (const gchar *what, const gchar *id)
{
	gchar *name = g_strdup_printf ("feed-%s-%s", what, id);
	gchar *t = g_strdup (text_of (name));

	g_free (name);
	return t;
}

static void
set_editor (const gchar *name, const gchar *text)
{
	GtkWidget *v = find (page, name);
	GtkTextBuffer *b = gtk_text_view_get_buffer (GTK_TEXT_VIEW (v));

	gtk_text_buffer_set_text (b, text, -1);
	gtk_text_buffer_set_modified (b, TRUE);
}

static void
lookup (const gchar *addr)
{
	gtk_entry_set_text (GTK_ENTRY (find (page, "intel-lookup-entry")), addr);
	click ("intel-lookup-button");
}

static const gchar *shots = NULL;

static void
shot (const gchar *file)
{
	cairo_surface_t *surface;
	gint64 until = g_get_monotonic_time () + G_USEC_PER_SEC / 4;
	gchar *path;

	if (shots == NULL)
		return;
	/* The whole page, not one screenful: the window as tall as the
	 * page wants to be at this width. */
	{
		GtkWidget *inner = gtk_bin_get_child (GTK_BIN (page));
		gint min = 0, nat = 0;

		gtk_widget_get_preferred_height_for_width (inner, 1000, &min,
		                                           &nat);
		gtk_widget_set_size_request (window, 1000, MAX (nat, 400));
	}
	gtk_widget_queue_resize (window);
	gtk_widget_queue_draw (window);
	while (g_get_monotonic_time () < until) {
		while (gtk_events_pending ())
			gtk_main_iteration ();
		g_usleep (10000);
	}
	surface = gtk_offscreen_window_get_surface (GTK_OFFSCREEN_WINDOW (window));
	path = g_build_filename (shots, file, NULL);
	if (surface != NULL)
		cairo_surface_write_to_png (surface, path);
	g_free (path);
}

/* --------------------------------------------------------------- setup */

static gchar *base;

static void
rm_rf (const gchar *path)
{
	GDir *d = g_dir_open (path, 0, NULL);
	const gchar *n;

	if (d != NULL) {
		while ((n = g_dir_read_name (d)) != NULL) {
			gchar *p = g_build_filename (path, n, NULL);

			if (g_file_test (p, G_FILE_TEST_IS_DIR) &&
			    !g_file_test (p, G_FILE_TEST_IS_SYMLINK))
				rm_rf (p);
			else
				g_unlink (p);
			g_free (p);
		}
		g_dir_close (d);
	}
	g_rmdir (path);
}

#ifdef G_OS_WIN32
/* Gives `dir' a protected access list: SYSTEM, Administrators and this
 * account, nobody else.  A new folder inherits its parent's list, and
 * on the CI runner (D:\a, under a drive root that lets Users create
 * folders and files) that lets Users change it, which the engine
 * rightly refuses as a store parent (design 11.5). */
static gboolean
protect_dir (const gchar *dir)
{
	HANDLE token = NULL;
	DWORD len = 0;
	TOKEN_USER *tu = NULL;
	LPSTR me = NULL;
	gchar *sddl = NULL;
	gunichar2 *w = NULL;
	PSECURITY_DESCRIPTOR sd = NULL;
	PACL dacl = NULL;
	BOOL present = FALSE, defaulted = FALSE;
	gboolean ok = FALSE;

	if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
		return FALSE;
	GetTokenInformation (token, TokenUser, NULL, 0, &len);
	tu = g_malloc0 (len ? len : 1);
	if (len != 0 &&
	    GetTokenInformation (token, TokenUser, tu, len, &len) &&
	    ConvertSidToStringSidA (tu->User.Sid, &me)) {
		sddl = g_strdup_printf ("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
		                        "(A;OICI;FA;;;%s)", me);
		w = g_utf8_to_utf16 (dir, -1, NULL, NULL, NULL);
		if (w != NULL &&
		    ConvertStringSecurityDescriptorToSecurityDescriptorA (
			    sddl, SDDL_REVISION_1, &sd, NULL) &&
		    GetSecurityDescriptorDacl (sd, &present, &dacl,
		                               &defaulted) && present &&
		    SetNamedSecurityInfoW ((LPWSTR) w, SE_FILE_OBJECT,
		                           DACL_SECURITY_INFORMATION |
		                           PROTECTED_DACL_SECURITY_INFORMATION,
		                           NULL, NULL, dacl, NULL)
		    == ERROR_SUCCESS)
			ok = TRUE;
	}
	if (sd != NULL)
		LocalFree (sd);
	if (me != NULL)
		LocalFree (me);
	g_free (w);
	g_free (sddl);
	g_free (tu);
	CloseHandle (token);
	return ok;
}
#endif

/* A scratch directory the engine accepts as a store parent (StrictModes:
 * no parent writable by others, so not under /tmp; on Windows, one with
 * its own protected access list). */
static gboolean
make_base (const gchar *argv0)
{
	const gchar *cands[3] = { g_getenv ("STOCKFW_TEST_SAFE_DIR"),
	                          g_get_home_dir (), NULL };
	gchar *exe = g_path_get_dirname (argv0);
	gchar *cwd = g_get_current_dir ();

	cands[2] = g_path_is_absolute (exe) ? exe
	           : g_build_filename (cwd, exe, NULL);
	for (guint i = 0; i < 3 && base == NULL; i++) {
		gchar *tmpl, *dir, *probe, *got;

		if (cands[i] == NULL)
			continue;
		tmpl = g_build_filename (cands[i], "sfw-intelui-XXXXXX", NULL);
		/* g_mkdtemp_full() fills in and returns tmpl itself. */
		dir = g_mkdtemp_full (tmpl, 0700);
		if (dir == NULL) {
			g_free (tmpl);
			continue;
		}
#ifdef G_OS_WIN32
		if (!protect_dir (dir)) {
			rm_rf (dir);
			g_free (dir);
			continue;
		}
#endif
		probe = g_build_filename (dir, "probe", NULL);
		g_setenv ("STOCKFW_INTEL_DIR", probe, TRUE);
		got = fs_intel_dir (NULL);
		if (got != NULL)
			base = g_strdup (dir);
		else
			rm_rf (dir);
		g_free (got);
		g_free (probe);
		g_free (dir);
	}
	if (cands[2] != exe)
		g_free ((gchar *) cands[2]);
	g_free (exe);
	g_free (cwd);
	return base != NULL;
}

static void
install_theme (void)
{
	GtkCssProvider *p = gtk_css_provider_new ();

	gtk_css_provider_load_from_data (p, fs_theme_css, -1, NULL);
	gtk_style_context_add_provider_for_screen (gdk_screen_get_default (),
		GTK_STYLE_PROVIDER (p), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	g_object_unref (p);
}

static const gchar *test_hold = NULL;

static const gchar *
hold (void)
{
	return test_hold;
}

/* ------------------------------------------------------------- Events */

/* The Service cell of visible row n as the user reads it: the column's
 * cell-data function run on that row. */
static gchar *
service_cell (GtkWidget *tree, guint n)
{
	GtkTreeModel *model = gtk_tree_view_get_model (GTK_TREE_VIEW (tree));
	GList *cols = gtk_tree_view_get_columns (GTK_TREE_VIEW (tree));
	GtkTreeViewColumn *col = NULL;
	GtkTreeIter iter;
	gchar *path = g_strdup_printf ("%u", n), *text = NULL;

	for (GList *l = cols; l != NULL; l = l->next)
		if (g_strcmp0 (gtk_tree_view_column_get_title (l->data),
		               "Service") == 0)
			col = l->data;
	g_list_free (cols);
	if (col != NULL &&
	    gtk_tree_model_get_iter_from_string (model, &iter, path)) {
		GList *cells = gtk_cell_layout_get_cells (GTK_CELL_LAYOUT (col));

		gtk_tree_view_column_cell_set_cell_data (col, model, &iter,
		                                         FALSE, FALSE);
		g_object_get (cells->data, "text", &text, NULL);
		g_list_free (cells);
	}
	g_free (path);
	return text;
}

static GtkWidget *
find_tree (GtkWidget *w)
{
	if (GTK_IS_TREE_VIEW (w))
		return w;
	if (GTK_IS_CONTAINER (w)) {
		GList *kids = gtk_container_get_children (GTK_CONTAINER (w));
		GtkWidget *hit = NULL;

		for (GList *l = kids; l != NULL && hit == NULL; l = l->next)
			hit = find_tree (GTK_WIDGET (l->data));
		g_list_free (kids);
		return hit;
	}
	return NULL;
}

static GtkWidget *
find_entry (GtkWidget *w)
{
	if (GTK_IS_SEARCH_ENTRY (w))
		return w;
	if (GTK_IS_CONTAINER (w)) {
		GList *kids = gtk_container_get_children (GTK_CONTAINER (w));
		GtkWidget *hit = NULL;

		for (GList *l = kids; l != NULL && hit == NULL; l = l->next)
			hit = find_entry (GTK_WIDGET (l->data));
		g_list_free (kids);
		return hit;
	}
	return NULL;
}

static void
check_events (void)
{
	GtkWidget *ewin = gtk_offscreen_window_new ();
	GtkWidget *epage = fs_hitview_page ();
	GtkWidget *tree, *entry;
	FsHit hit = { 0 };
	const FsHit *sel;
	gchar *cell, *rule;
	FsIntelConfig *c;

	gtk_window_set_default_size (GTK_WINDOW (ewin), 1100, 360);
	gtk_container_add (GTK_CONTAINER (ewin), epage);
	gtk_widget_show_all (ewin);
	fs_hitview_stop ();
	fs_hitview_clear ();
	tree = find_tree (epage);

	/* A policy block and a list's block, as the backend delivers
	 * them (the list's from fs_netparse_intel_line). */
	hit.time = (gchar *) "2026-11-02T10:00:00Z";
	hit.direction = (gchar *) "in";
	hit.source = (gchar *) "192.0.2.10";
	hit.destination = (gchar *) "198.51.100.1";
	hit.port = (gchar *) "443";
	hit.protocol = (gchar *) "TCP";
	hit.service = (gchar *) "HTTPS" FS_HIT_BLOCKED_MARKER;
	fs_hitview_append (&hit);
	{
		FsHit ti = { 0 };
		gchar *id = NULL;

		CHECK (fs_netparse_intel_line (
			"2026-11-02T10:00:05Z STOCKFW-TI spamhaus-drop IN=eth0 "
			"OUT= SRC=45.1.0.77 DST=198.51.100.1 PROTO=TCP SPT=5 DPT=22",
			&ti, NULL, &id), "events: the list's log line parses");
		fs_netparse_name_blocked (&ti);
		rule = g_strdup_printf ("Threat intel: %s",
		                        fs_feed_catalog_find (id)->name);
		ti.rule = g_strdup (rule);
		fs_hitview_append (&ti);
		fs_netparse_clear_hit (&ti);
		g_free (id);
	}

	cell = service_cell (tree, 0);
	CHECK (cell != NULL && strstr (cell, "SSH") &&
	       strstr (cell, "Threat intel: Spamhaus DROP (IPv4)"),
	       "events: the list's block names the list in the Service "
	       "column (\"%s\")", cell ? cell : "(null)");
	g_free (cell);
	cell = service_cell (tree, 1);
	CHECK (cell != NULL && strcmp (cell, "HTTPS" FS_HIT_BLOCKED_MARKER) == 0,
	       "events: a policy block is shown as before (\"%s\")",
	       cell ? cell : "(null)");
	g_free (cell);

	gtk_tree_view_set_cursor (GTK_TREE_VIEW (tree),
	                          gtk_tree_path_new_from_string ("0"), NULL,
	                          FALSE);
	sel = fs_hitview_selected ();
	CHECK (sel != NULL && g_strcmp0 (sel->rule, rule) == 0 &&
	       fs_hit_is_blocked (sel) &&
	       g_strcmp0 (sel->service, "SSH" FS_HIT_BLOCKED_MARKER) == 0,
	       "events: the selected row carries the rule, and its service "
	       "is untouched");
	CHECK (fs_intelview_rule_is_intel (sel != NULL ? sel->rule : NULL) &&
	       !fs_intelview_rule_is_intel ("Policy") &&
	       !fs_intelview_rule_is_intel (NULL),
	       "events: the rule is recognised as a blocklist's, nothing "
	       "else is");
	gtk_tree_view_set_cursor (GTK_TREE_VIEW (tree),
	                          gtk_tree_path_new_from_string ("1"), NULL,
	                          FALSE);
	sel = fs_hitview_selected ();
	CHECK (sel != NULL && sel->rule == NULL,
	       "events: a policy block carries no rule");

	entry = find_entry (epage);
	gtk_entry_set_text (GTK_ENTRY (entry), "Spamhaus");
	{
		/* GtkSearchEntry reports a change after a short delay. */
		gint64 until = g_get_monotonic_time () + G_USEC_PER_SEC / 2;

		while (g_get_monotonic_time () < until) {
			while (gtk_events_pending ())
				gtk_main_iteration ();
			g_usleep (10000);
		}
	}
	CHECK (fs_hitview_visible_count () == 1,
	       "events: the filter finds the list's block by the list's "
	       "name (%u visible)", fs_hitview_visible_count ());
	if (shots != NULL) {
		gchar *path = g_build_filename (shots, "08-events.png", NULL);
		gint64 until = g_get_monotonic_time () + G_USEC_PER_SEC / 4;

		gtk_entry_set_text (GTK_ENTRY (entry), "");
		gtk_widget_queue_draw (ewin);
		while (g_get_monotonic_time () < until) {
			while (gtk_events_pending ())
				gtk_main_iteration ();
			g_usleep (10000);
		}
		cairo_surface_write_to_png (gtk_offscreen_window_get_surface (
			GTK_OFFSCREEN_WINDOW (ewin)), path);
		g_free (path);
	}
	gtk_entry_set_text (GTK_ENTRY (entry), "");

	/* "Add exception": the address goes on the allow list. */
	next_response = GTK_RESPONSE_CANCEL;
	fs_intelview_add_exception (NULL, "45.1.0.77", rule);
	wait_idle ();
	c = fs_intel_config_load (NULL);
	CHECK (c != NULL && !fs_range_set_contains_text (c->exceptions,
	                                                 "45.1.0.77") &&
	       g_strcmp0 (last_dialog, "intel-exception-dialog") == 0 &&
	       strstr (last_dialog_text, "Spamhaus"),
	       "events: Add exception asks first, naming the list; Cancel "
	       "changes nothing");
	fs_intel_config_free (c);
	next_response = GTK_RESPONSE_ACCEPT;
	fs_intelview_add_exception (NULL, "45.1.0.77", rule);
	wait_idle ();
	c = fs_intel_config_load (NULL);
	CHECK (c != NULL && fs_range_set_contains_text (c->exceptions,
	                                                "45.1.0.77"),
	       "events: Add exception puts the address on the allow list");
	fs_intel_config_free (c);
	g_free (rule);
	gtk_widget_destroy (ewin);
}

/* ------------------------------------------ countries and networks */

/* The location database the fake downloader serves: tests/geodb's
 * small.db (written by libloc's writer, signed with k1's key), xz'd
 * here.  Its networks: DE, US (anycast, private space), FR, NL (one
 * public anycast /20, 2c0f:f000::/20), GB, IT, JP; ASes "Example One"
 * (64500), "Example Two GmbH" (64501) and more. */
static GBytes *geo_xz = NULL;
static guint   geo_fetches = 0;

static GBytes *
geo_fetch (const gchar *url, const gchar *proxy, gpointer data,
           GError **error)
{
	(void) proxy;
	(void) data;
	(void) error;
	g_atomic_int_inc (&geo_fetches);
	CHECK (g_strcmp0 (url, FS_GEODB_URL) == 0,
	       "geo: the database is fetched from %s", url);
	return g_bytes_ref (geo_xz);
}

static gboolean
geo_setup (void)
{
	gchar *pem = NULL, *db = NULL;
	gsize len = 0;
	guint8 *out;
	size_t out_pos = 0, cap;
	gboolean ok;

	ok = g_file_get_contents (FS_TEST_GEODB_DIR "/k1.pub", &pem, NULL,
	                          NULL) &&
	     g_file_get_contents (FS_TEST_GEODB_DIR "/small.db", &db, &len,
	                          NULL);
	if (!ok) {
		g_free (pem);
		g_free (db);
		return FALSE;
	}
	fs_geodb_testing_set_key (pem);
	cap = lzma_stream_buffer_bound (len);
	out = g_malloc (cap);
	ok = lzma_easy_buffer_encode (6, LZMA_CHECK_CRC64, NULL,
	                              (const guint8 *) db, len, out, &out_pos,
	                              cap) == LZMA_OK;
	if (ok)
		geo_xz = g_bytes_new_take (out, out_pos);
	else
		g_free (out);
	g_free (pem);
	g_free (db);
	fs_geodb_set_fetcher (geo_fetch, NULL);
	return ok;
}

/* Let a timer of the page fire (the picker's search waits 250 ms after
 * the last key), then wait for the work it started. */
static void
pump_ms (guint ms)
{
	gint64 until = g_get_monotonic_time () + (gint64) ms * 1000;

	while (g_get_monotonic_time () < until) {
		while (gtk_events_pending ())
			gtk_main_iteration ();
		g_usleep (5000);
	}
	wait_idle ();
}

/* The picker's row whose text is `text'; FALSE when there is none. */
static gboolean
geo_row (GtkTreeModel *model, const gchar *text, GtkTreeIter *out,
         gint *kind)
{
	gboolean valid = gtk_tree_model_get_iter_first (model, out);

	while (valid) {
		gchar *t = NULL;
		gint k = 0;
		gboolean hit;

		gtk_tree_model_get (model, out, 0, &t, 1, &k, -1);
		hit = g_strcmp0 (t, text) == 0;
		g_free (t);
		if (hit) {
			if (kind != NULL)
				*kind = k;
			return TRUE;
		}
		valid = gtk_tree_model_iter_next (model, out);
	}
	return FALSE;
}

static guint
geo_rows_of_kind (GtkTreeModel *model, gint kind)
{
	GtkTreeIter it;
	gboolean valid = gtk_tree_model_get_iter_first (model, &it);
	guint n = 0;

	while (valid) {
		gint k = 0;

		gtk_tree_model_get (model, &it, 1, &k, -1);
		n += k == kind;
		valid = gtk_tree_model_iter_next (model, &it);
	}
	return n;
}

/* The completion's own filtered model: the tree view in its popup,
 * whose model filters the picker's store (GTK keeps it private). */
static GtkTreeModel *
geo_filtered_in (GtkWidget *w, GtkTreeModel *store)
{
	if (GTK_IS_TREE_VIEW (w)) {
		GtkTreeModel *m = gtk_tree_view_get_model (GTK_TREE_VIEW (w));

		if (GTK_IS_TREE_MODEL_FILTER (m) &&
		    gtk_tree_model_filter_get_model (GTK_TREE_MODEL_FILTER (m))
		    == store)
			return m;
	}
	if (GTK_IS_CONTAINER (w)) {
		GList *kids = gtk_container_get_children (GTK_CONTAINER (w));
		GtkTreeModel *hit = NULL;

		for (GList *k = kids; k != NULL && hit == NULL; k = k->next)
			hit = geo_filtered_in (k->data, store);
		g_list_free (kids);
		return hit;
	}
	return NULL;
}

/* The rows the completion offers for `typed', as GTK filters them
 * (its key normalized and casefolded, then the page's match
 * function); *has is set when one of them reads `want'.  The entry's
 * text is set and the completion run at once, before the search's
 * timer can change the networks. */
static guint
geo_offered (const gchar *typed, const gchar *want, gboolean *has)
{
	GtkWidget *entry = find (page, "intel-geo-entry");
	GtkEntryCompletion *c = gtk_entry_get_completion (GTK_ENTRY (entry));
	GtkTreeModel *store = gtk_entry_completion_get_model (c);
	GtkTreeModel *filtered = NULL;
	GList *tops;
	GtkTreeIter it;
	gboolean valid;
	guint n = 0;

	*has = FALSE;
	gtk_entry_set_text (GTK_ENTRY (entry), typed);
	gtk_entry_completion_complete (c);
	tops = gtk_window_list_toplevels ();
	for (GList *t = tops; t != NULL && filtered == NULL; t = t->next)
		filtered = geo_filtered_in (t->data, store);
	g_list_free (tops);
	if (filtered == NULL)
		return 0;
	valid = gtk_tree_model_get_iter_first (filtered, &it);
	while (valid) {
		gchar *text = NULL;

		gtk_tree_model_get (filtered, &it, 0, &text, -1);
		*has = *has || g_strcmp0 (text, want) == 0;
		g_free (text);
		n++;
		valid = gtk_tree_model_iter_next (filtered, &it);
	}
	return n;
}

/* The id of the saved rule that blocks `asn'; NULL when none does. */
static gchar *
geo_rule_of_asn (guint32 asn)
{
	FsIntelConfig *c = fs_intel_config_load (NULL);
	gchar *id = NULL;

	for (guint i = 0; c != NULL && i < c->locations->len && id == NULL;
	     i++) {
		FsIntelLocationConf *l = g_ptr_array_index (c->locations, i);

		for (guint j = 0; l->asns != NULL && j < l->asns->len; j++)
			if (g_array_index (l->asns, guint32, j) == asn)
				id = g_strdup (l->id);
	}
	if (c != NULL)
		fs_intel_config_free (c);
	return id;
}

/* Pick `text' in the completion, as a click on its row does. */
static void
geo_pick (const gchar *text)
{
	GtkWidget *entry = find (page, "intel-geo-entry");
	GtkEntryCompletion *c = gtk_entry_get_completion (GTK_ENTRY (entry));
	GtkTreeModel *model = gtk_entry_completion_get_model (c);
	GtkTreeIter it;
	gboolean handled = FALSE;
	gboolean found = geo_row (model, text, &it, NULL);

	CHECK (found, "geo: \"%s\" is in the picker's list", text);
	/* A row that is not there is a failure above, never a click on
	 * an iterator that points nowhere. */
	if (found)
		g_signal_emit_by_name (c, "match-selected", model, &it,
		                       &handled);
}

static gboolean
geo_conf (gboolean *enabled, guint *rules)
{
	FsIntelConfig *c = fs_intel_config_load (NULL);

	if (c == NULL)
		return FALSE;
	*enabled = c->geo_enabled;
	*rules = c->locations->len;
	fs_intel_config_free (c);
	return TRUE;
}

static void
check_geo (void)
{
	GtkWidget *sw = find (page, "intel-geo-switch");
	GtkWidget *entry = find (page, "intel-geo-entry");
	GtkTreeModel *model = gtk_entry_completion_get_model (
		gtk_entry_get_completion (GTK_ENTRY (entry)));
	GtkTreeIter it;
	GtkWidget *w;
	gchar *attribution = fs_intel_geo_attribution ();
	gboolean on = FALSE;
	guint rules = 0;
	gint kind = 0;
	const gchar *tip;
	gchar *t;

	if (!gtk_switch_get_active (GTK_SWITCH (find (page, "intel-master"))))
		gtk_switch_set_active (GTK_SWITCH (find (page, "intel-master")),
		                       TRUE);
	wait_idle ();
	CHECK (visible ("intel-geo") && visible ("intel-geo-controls") &&
	       !visible ("intel-geo-unsupported"),
	       "geo: on Linux the countries and networks card has its "
	       "controls, not the unsupported sentence");
	CHECK (!visible ("intel-geo-picker"),
	       "geo: no picker before the database's terms are accepted");
	CHECK (strcmp (text_of ("intel-geo-attribution"), attribution) == 0,
	       "geo: the card carries the licence line (\"%s\")",
	       text_of ("intel-geo-attribution"));

	/* Consent: Cancel changes nothing and downloads nothing. */
	next_response = GTK_RESPONSE_CANCEL;
	gtk_switch_set_active (GTK_SWITCH (sw), TRUE);
	wait_idle ();
	CHECK (g_strcmp0 (last_dialog, "intel-geo-consent-dialog") == 0 &&
	       strstr (last_dialog_text, "location.ipfire.org") != NULL &&
	       strstr (last_dialog_text, "once a day") != NULL &&
	       strstr (last_dialog_text, "public IP address") != NULL &&
	       strstr (last_dialog_text, "CC BY-SA 4.0") != NULL &&
	       strstr (last_dialog_text, "has not confirmed") != NULL &&
	       strstr (last_dialog_text, "where an address range is "
	                                 "registered, not where a computer "
	                                 "is") != NULL &&
	       strstr (last_dialog_text, "anycast") != NULL,
	       "geo: turning it on asks first: the host, how often, what it "
	       "learns, the licence as the file declares it (unconfirmed), "
	       "\"registered in\", anycast");
	CHECK (geo_fetches == 0 && geo_conf (&on, &rules) && !on &&
	       !gtk_switch_get_active (GTK_SWITCH (sw)),
	       "geo: Cancel at the consent dialog: still off, nothing "
	       "downloaded");

	/* Accept: on, and downloaded at once. */
	next_response = GTK_RESPONSE_ACCEPT;
	gtk_switch_set_active (GTK_SWITCH (sw), TRUE);
	wait_idle ();
	CHECK (geo_fetches == 1 && geo_conf (&on, &rules) && on,
	       "geo: Accept turns it on and downloads it once (%u)",
	       geo_fetches);
	CHECK (strstr (text_of ("intel-geo-state"), "Database of") != NULL &&
	       strstr (text_of ("intel-geo-state"), "more than 30 days old") !=
	       NULL,
	       "geo: its date and state are shown (\"%s\")",
	       text_of ("intel-geo-state"));
	CHECK (visible ("intel-geo-picker") &&
	       gtk_widget_is_sensitive (entry),
	       "geo: the picker is there once a copy is");

	/* The picker's model: every country of the copy in use... */
	CHECK (geo_rows_of_kind (model, FS_INTEL_LOCATION_COUNTRY) == 7 &&
	       geo_row (model, "Netherlands (NL)", &it, &kind) &&
	       kind == FS_INTEL_LOCATION_COUNTRY &&
	       geo_row (model, "Germany (DE)", &it, NULL),
	       "geo: the picker lists the database's 7 countries, code and "
	       "name");
	/* ... and its networks, searched as you type. */
	gtk_entry_set_text (GTK_ENTRY (entry), "Example");
	pump_ms (400);
	CHECK (geo_row (model, "AS64500 Example One", &it, &kind) &&
	       kind == FS_INTEL_LOCATION_ASN &&
	       geo_row (model, "AS64501 Example Two GmbH", &it, NULL) &&
	       geo_rows_of_kind (model, FS_INTEL_LOCATION_ASN) == 2,
	       "geo: typing \"Example\" searches the networks: AS64500 and "
	       "AS64501 (%u network rows)",
	       geo_rows_of_kind (model, FS_INTEL_LOCATION_ASN));
	/* The completion offers rows by code, by name, by AS number, in
	 * any case and with accents composed or not (GTK hands the match
	 * function its key decomposed and casefolded). */
	{
		gboolean has_nl, has_name, has_as, has_acc, has_up;
		guint by_code = geo_offered ("nl", "Netherlands (NL)", &has_nl);
		guint by_name = geo_offered ("Nether", "Netherlands (NL)",
		                             &has_name);
		guint by_as = geo_offered ("64500", "AS64500 Example One",
		                           &has_as);

		CHECK (by_code >= 1 && has_nl && by_name == 1 && has_name &&
		       by_as == 1 && has_as,
		       "geo: the completion offers the Netherlands for \"nl\" "
		       "(%u rows) and \"Nether\" (%u), AS64500 for \"64500\" "
		       "(%u)", by_code, by_name, by_as);
		gtk_entry_set_text (GTK_ENTRY (entry), "T\xc3\xa9st");
		pump_ms (400);
		geo_offered ("t\xc3\xa9st \xc3\xbcn", "AS64502 T\xc3\xa9st "
		             "\xc3\x9cn\xc3\xaf" "code", &has_acc);
		geo_offered ("T\xc3\x89ST", "AS64502 T\xc3\xa9st "
		             "\xc3\x9cn\xc3\xaf" "code", &has_up);
		CHECK (has_acc && has_up,
		       "geo: an accented name completes typed in either case "
		       "(\"t\xc3\xa9st \xc3\xbcn\" %d, \"T\xc3\x89ST\" %d)",
		       has_acc, has_up);
		/* Typed in full in another case, and Block: that row, not
		 * "pick a country or network". */
		gtk_entry_set_text (GTK_ENTRY (entry), "as64502 t\xc3\xa9st "
		                    "\xc3\xbcn\xc3\xaf" "code");
		click ("intel-geo-add");
		gchar *x = geo_rule_of_asn (64502);
		CHECK (x != NULL,
		       "geo: a name typed in full in another case finds its "
		       "row and blocks AS64502 (\"%s\")",
		       text_of ("intel-message"));
		/* Taken away again: the counts below start from none. */
		if (x != NULL) {
			gchar *button = g_strdup_printf ("geo-remove-%s", x);

			next_response = GTK_RESPONSE_ACCEPT;
			click (button);
			g_free (button);
			g_free (x);
		}
		CHECK (geo_conf (&on, &rules) && rules == 0,
		       "geo: ... and removed again (%u rules)", rules);
	}
	/* The page fits a 640 px window: the picker wraps under its
	 * entry. */
	{
		gint min = 0;

		gtk_widget_get_preferred_width (find (page, "intel-geo-picker"),
		                                &min, NULL);
		CHECK (min <= 640 - 64 - 40,
		       "geo: the picker needs %d px, within a 640 px window's "
		       "card", min);
	}
	/* Enter in the entry while Block is greyed out adds nothing. */
	{
		GtkWidget *add = find (page, "intel-geo-add");
		guint before = 0;

		geo_conf (&on, &before);
		gtk_widget_set_sensitive (add, FALSE);
		gtk_entry_set_text (GTK_ENTRY (entry), "fr");
		g_signal_emit_by_name (entry, "activate");
		wait_idle ();
		CHECK (geo_conf (&on, &rules) && rules == before &&
		       find (page, "geo-row-country-france") == NULL,
		       "geo: Enter while Block is greyed out adds nothing (%u "
		       "rules, %u before)", rules, before);
		gtk_widget_set_sensitive (add, TRUE);
	}
	/* Add: Netherlands, inbound, picked from the list. */
	gtk_entry_set_text (GTK_ENTRY (entry), "Nether");
	geo_pick ("Netherlands (NL)");
	CHECK (strcmp (gtk_entry_get_text (GTK_ENTRY (entry)),
	               "Netherlands (NL)") == 0,
	       "geo: picking a row puts it in the entry");
	gtk_combo_box_set_active_id (GTK_COMBO_BOX (find (page,
	                                                  "intel-geo-dir")),
	                             "in");
	kern.apply_calls = 0;
	click ("intel-geo-add");
	CHECK (find (page, "geo-row-country-netherlands") != NULL &&
	       kern.last_sets != NULL &&
	       strstr (kern.last_sets, "country-netherlands") != NULL &&
	       kern.apply_calls > 0,
	       "geo: Block adds the rule and puts it in force (%s)",
	       kern.last_sets ? kern.last_sets : "nothing applied");
	t = g_strdup (text_of ("geo-facts-country-netherlands"));
	CHECK (strstr (t, "Registered in Netherlands (NL)") != NULL &&
	       strstr (t, "Stops them connecting to you.") != NULL,
	       "geo: its row says where the country's ranges are registered "
	       "and the direction (\"%s\")", t != NULL ? t : "(null)");
	CHECK (strstr (t, "1 anycast network, which may block services "
	                  "elsewhere") != NULL,
	       "geo: the row says how many anycast networks in words, for "
	       "the keyboard and screen readers (\"%s\")", t != NULL ? t : "(null)");
	g_free (t);
	{
		AtkObject *a = gtk_widget_get_accessible (
			find (page, "geo-remove-country-netherlands"));
		const gchar *an = a != NULL ? atk_object_get_name (a) : NULL;

		CHECK (g_strcmp0 (an, "Remove Netherlands") == 0,
		       "geo: its Remove button's accessible name names the "
		       "rule (\"%s\")", an != NULL ? an : "none");
	}
	CHECK (strcmp (text_of ("geo-status-country-netherlands"),
	               "In force.") == 0,
	       "geo: and says it is in force (\"%s\")",
	       text_of ("geo-status-country-netherlands"));
	w = find (page, "geo-anycast-country-netherlands");
	tip = w != NULL ? gtk_widget_get_tooltip_text (w) : NULL;
	CHECK (w != NULL && gtk_widget_get_visible (w) && tip != NULL &&
	       strstr (tip, "Includes 1 anycast network (IPv6)") != NULL &&
	       strstr (tip, "may also block services outside what you "
	                    "chose") != NULL,
	       "geo: a rule whose set holds an anycast network carries the "
	       "warning, with the count on hover (\"%s\")",
	       tip != NULL ? tip : "no warning");

	/* Add: DE typed as a code, not picked; its anycast network (US,
	 * private space) is not DE's, so no warning. */
	gtk_entry_set_text (GTK_ENTRY (entry), "de");
	gtk_combo_box_set_active_id (GTK_COMBO_BOX (find (page,
	                                                  "intel-geo-dir")),
	                             "both");
	click ("intel-geo-add");
	CHECK (find (page, "geo-row-country-germany") != NULL &&
	       find (page, "geo-anycast-country-germany") == NULL,
	       "geo: a country code typed in full adds that country by its "
	       "name, and a rule without anycast networks has no warning");

	/* Add: a network, picked from the search. */
	gtk_entry_set_text (GTK_ENTRY (entry), "Example One");
	pump_ms (400);
	geo_pick ("AS64500 Example One");
	click ("intel-geo-add");
	CHECK (find (page, "geo-row-asn-as64500-example-one") != NULL &&
	       strstr (kern.last_sets, "asn-as64500-example-one") != NULL,
	       "geo: a network picked from the search is blocked by its AS "
	       "number (%s)", kern.last_sets);
	CHECK (geo_conf (&on, &rules) && rules == 3,
	       "geo: three rules saved (%u)", rules);

	/* Something that is neither. */
	gtk_entry_set_text (GTK_ENTRY (entry), "nowhere land");
	click ("intel-geo-add");
	CHECK (geo_conf (&on, &rules) && rules == 3 &&
	       strstr (text_of ("intel-message"), "Pick a country or network")
	       != NULL,
	       "geo: text that names no country or network adds nothing and "
	       "says why (\"%s\")", text_of ("intel-message"));

	/* Lookup: where an address is registered, with the licence line. */
	lookup ("2c0f:f000::1");
	t = g_strdup (text_of ("intel-lookup-result"));
	CHECK (strstr (t, "the country rule Netherlands") != NULL &&
	       strstr (t, "Registered in Netherlands (NL).") != NULL &&
	       strstr (t, "anycast") != NULL &&
	       strstr (t, attribution) != NULL,
	       "geo: the lookup names the rule, \"Registered in\", anycast "
	       "and the licence line (\"%s\")", t != NULL ? t : "(null)");
	g_free (t);
	shot ("11-countries.png");

	/* Remove: asked first; the set leaves the kernel. */
	next_response = GTK_RESPONSE_ACCEPT;
	click ("geo-remove-country-germany");
	CHECK (g_strcmp0 (last_dialog, "intel-remove-dialog") == 0 &&
	       strstr (last_dialog_text, "stored copy") == NULL &&
	       find (page, "geo-row-country-germany") == NULL &&
	       strstr (kern.last_sets, "country-germany") == NULL &&
	       geo_conf (&on, &rules) && rules == 2,
	       "geo: Remove asks, then the rule is gone from the page, the "
	       "config and the kernel");

	/* Update database: downloaded again. */
	click ("intel-geo-update");
	CHECK (geo_fetches == 2 &&
	       strstr (text_of ("intel-message"), "Location database:") != NULL,
	       "geo: Update database downloads it again (\"%s\")",
	       text_of ("intel-message"));

	/* Off: the rules stay and block nothing. */
	gtk_switch_set_active (GTK_SWITCH (sw), FALSE);
	wait_idle ();
	CHECK (geo_conf (&on, &rules) && !on && rules == 2 &&
	       strstr (text_of ("intel-geo-state"), "more than 30 days old")
	       != NULL &&
	       strstr (text_of ("intel-geo-state"), "still used") == NULL &&
	       strstr (text_of ("geo-status-country-netherlands"),
	               "location database is off") != NULL &&
	       strstr (kern.last_sets, "country-netherlands") == NULL,
	       "geo: turned off, the rules are kept, say they block nothing, "
	       "and their sets leave the kernel (\"%s\")",
	       text_of ("geo-status-country-netherlands"));
	next_response = GTK_RESPONSE_CANCEL;
	gtk_switch_set_active (GTK_SWITCH (sw), TRUE);
	wait_idle ();
	CHECK (geo_conf (&on, &rules) && on &&
	       g_strcmp0 (last_dialog, "intel-geo-consent-dialog") != 0,
	       "geo: on again: its terms were accepted once, no second "
	       "dialog");
	next_response = GTK_RESPONSE_ACCEPT;

	/* Where it does not exist (Windows in 1.0.7): the sentence, and no
	 * control that acts. */
	fs_intelview_set_geo_supported (0);
	fs_intelview_set_backend (&win_backend);
	refresh ();
	CHECK (visible ("intel-geo") && visible ("intel-geo-unsupported") &&
	       strcmp (text_of ("intel-geo-unsupported"),
	               fs_intel_geo_unsupported_text ()) == 0 &&
	       !visible ("intel-geo-controls") &&
	       !gtk_widget_is_visible (find (page, "intel-geo-switch")) &&
	       !gtk_widget_is_visible (find (page, "intel-geo-add")),
	       "geo: a platform without it shows its sentence (\"%s\") and "
	       "no control", text_of ("intel-geo-unsupported"));
	shot ("12-countries-unsupported.png");
	fs_intelview_set_geo_supported (-1);
	fs_intelview_set_backend (&fake_backend);
	refresh ();
	g_free (attribution);
}

/* An entry with a completion asks GDK for its monitor at every
 * allocation; in an offscreen window there is none, and GDK says so
 * with this critical (a plain GtkWindow does not: checked by hand).
 * Only that message is dropped; every other one is printed and
 * counted. */
static guint other_criticals = 0;

static void
gdk_log (const gchar *domain, GLogLevelFlags level, const gchar *message,
         gpointer data)
{
	(void) data;
	if (message != NULL &&
	    strstr (message, "gdk_window_get_origin: assertion "
	                     "'GDK_IS_WINDOW (window)' failed") != NULL)
		return;
	other_criticals++;
	g_log_default_handler (domain, level, message, NULL);
}

/* ---------------------------------------------------------------- main */

int
main (int argc, char **argv)
{
	gchar *t, *b10, *b1;
	guint calls;

	if (!make_base (argv[0])) {
		printf ("FAIL: no directory the engine accepts as a store\n");
		return 1;
	}
	{
		gchar *home = g_build_filename (base, "home", NULL);
		gchar *store = g_build_filename (base, "intel", NULL);
		gchar *audit = g_build_filename (base, "audit.log", NULL);

		g_mkdir (home, 0700);
		g_setenv ("HOME", home, TRUE);
		g_setenv ("XDG_CONFIG_HOME", home, TRUE);
		g_setenv ("STOCKFW_INTEL_DIR", store, TRUE);
		g_setenv ("STOCKFW_AUDIT_FILE", audit, TRUE);
		g_free (home);
		g_free (store);
		g_free (audit);
	}
	shots = g_getenv ("INTEL_SMOKE_SHOTS");
	gtk_init (&argc, &argv);
	g_log_set_handler ("Gdk", G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING,
	                   gdk_log, NULL);
	install_theme ();
	seen_progress = g_string_new (NULL);

	kern.counters = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
	                                       g_free);
	kern.live = FS_INTEL_LIVE_ABSENT;
	kern.fw = FS_FW_RUNNING;
	fake_backend.name = "fake";
	fake_backend.get_state = fake_get_state;
	fake_backend.intel_apply = fake_apply;
	fake_backend.intel_clear = fake_clear;
	fake_backend.intel_counters = fake_counters;
	fake_backend.intel_live = fake_live;
	bare_backend.name = "bare";
	bare_backend.get_state = fake_get_state;
	win_backend = fake_backend;
	win_backend.name = "win";
	win_backend.intel_counters = NULL;
	win_backend.intel_not_in_force = fake_not_in_force;
	bodies = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	errors = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	fs_intel_set_fetcher (fake_fetch, NULL);
	if (!geo_setup ()) {
		printf ("FAIL: the test location database (%s) could not be "
		        "read\n", FS_TEST_GEODB_DIR);
		return 1;
	}
	fs_intelview_set_backend (&fake_backend);
	fs_intelview_set_responder (respond, NULL);
	fs_intelview_set_hold_func (hold);

	window = gtk_offscreen_window_new ();
	gtk_window_set_default_size (GTK_WINDOW (window), 1000, 600);
	page = fs_intelview_page ();
	gtk_scrolled_window_set_propagate_natural_height (
		GTK_SCROLLED_WINDOW (page), TRUE);
	gtk_container_add (GTK_CONTAINER (window), page);
	gtk_widget_show_all (window);
	wait_idle ();

	/* ---- no store: Off, nothing created ---- */
	CHECK (strcmp (text_of ("intel-state-title"), "Off") == 0,
	       "no list ever turned on: \"Off\" (got \"%s\")",
	       text_of ("intel-state-title"));
	CHECK (!fs_intel_store_exists (),
	       "opening the page creates no store (Stop and Start stay no-ops)");
	t = feed_text ("status", "spamhaus-drop");
	CHECK (strcmp (t, "Off.") == 0, "a feed that is off says so (\"%s\")", t != NULL ? t : "(null)");
	g_free (t);
	{
		GtkWidget *row = find (page, "feed-row-firehol-level1");
		gchar *labels = row_labels (row);

		CHECK (row != NULL &&
		       strstr (labels, "Non-commercial use only") != NULL &&
		       strstr (labels, "href=\"https://iplists.firehol.org/")
		       != NULL,
		       "FireHOL level 1: \"Non-commercial use only\" and a "
		       "credit link to its publisher");
		g_free (labels);
		/* The credit is the catalog's line, the one the CLI and the
		 * dashboard print: Spamhaus asks to be named. */
		row = find (page, "feed-row-spamhaus-drop");
		labels = row_labels (row);
		CHECK (row != NULL &&
		       strstr (labels, fs_feed_catalog_find ("spamhaus-drop")
		                       ->credit) != NULL &&
		       strstr (labels, "The Spamhaus Project") != NULL,
		       "Spamhaus DROP: the credit names The Spamhaus Project");
		g_free (labels);
	}
	shot ("01-off.png");

	/* ---- consent ---- */
	b10 = drop_body ("45.1.0.0/24 45.2.0.0/24 45.3.0.0/24 45.4.0.0/24 "
	                 "45.5.0.0/24 45.6.0.0/24 45.7.0.0/24 45.8.0.0/24 "
	                 "45.9.0.0/24 45.10.0.0/24");
	serve ("spamhaus-drop", b10);
	next_response = GTK_RESPONSE_CANCEL;
	flip ("spamhaus-drop", TRUE);
	CHECK (g_strcmp0 (last_dialog, "intel-consent-dialog") == 0 &&
	       strstr (last_dialog_text, "www.spamhaus.org") != NULL,
	       "turning a feed on asks first, naming the host contacted");
	CHECK (last_dialog_text != NULL &&
	       strstr (last_dialog_text, "allow list on the Threat Intel "
	                                 "page") != NULL,
	       "the consent text sends mistakes to this page's allow list");
	CHECK (fetches == 0 && kern.apply_calls == 0 && !fs_intel_store_exists (),
	       "Cancel at the consent dialog: nothing downloaded, nothing "
	       "applied, no store");
	t = feed_text ("status", "spamhaus-drop");
	CHECK (strcmp (t, "Off.") == 0, "and the feed is still off (\"%s\")", t != NULL ? t : "(null)");
	g_free (t);

	next_response = GTK_RESPONSE_ACCEPT;
	fetch_delay_us = 400000;
	ticks = 0;
	g_string_truncate (seen_progress, 0);
	flip ("spamhaus-drop", TRUE);
	fetch_delay_us = 0;
	CHECK (fetches == 1 && kern.apply_calls == 1,
	       "Accept: downloaded once and applied once (%u, %u)", fetches,
	       kern.apply_calls);
	CHECK (ticks >= 10,
	       "the window kept running during a 0.4 s download (%u timer "
	       "ticks on the main loop)", ticks);
	CHECK (strstr (seen_progress->str, "Downloading Spamhaus DROP (IPv4)")
	       != NULL,
	       "the progress line named the download (%s)", seen_progress->str);
	CHECK (strcmp (text_of ("intel-state-title"), "Protected") == 0,
	       "in force: \"Protected\" (got \"%s\")",
	       text_of ("intel-state-title"));
	t = feed_text ("status", "spamhaus-drop");
	CHECK (strcmp (t, "Up to date and in force.") == 0,
	       "the feed: \"Up to date and in force.\" (\"%s\")", t != NULL ? t : "(null)");
	g_free (t);
	t = feed_text ("facts", "spamhaus-drop");
	CHECK (strstr (t, "10 entries") && strstr (t, "updated just now") &&
	       strstr (t, "next update in 24 h") &&
	       strstr (t, "Nothing blocked yet"),
	       "its facts: entries, last and next update, nothing blocked "
	       "(\"%s\")", t != NULL ? t : "(null)");
	g_free (t);
	CHECK (!visible ("intel-progress"), "the progress line goes when done");

	/* ---- counters ---- */
	counter_set (kern.counters, "spamhaus-drop", 1234);
	refresh ();
	t = feed_text ("facts", "spamhaus-drop");
	CHECK (strstr (t, "Blocked 1,234 packets since") != NULL,
	       "blocked counter per feed (\"%s\")", t != NULL ? t : "(null)");
	g_free (t);
	CHECK (strcmp (text_of ("intel-tile-2"), "1,234") == 0 &&
	       strcmp (text_of ("intel-tile-0"), "1") == 0,
	       "the card's tiles: 1 list on, 1,234 blocked");
	shot ("02-protected.png");

	/* ---- progress, mid-job (for the screenshot and the bar) ---- */
	fetch_delay_us = 1500000;
	gtk_button_clicked (GTK_BUTTON (find (page, "intel-update")));
	{
		gint64 until = g_get_monotonic_time () + G_USEC_PER_SEC / 2;

		while (g_get_monotonic_time () < until) {
			while (gtk_events_pending ())
				gtk_main_iteration ();
			g_usleep (5000);
		}
	}
	CHECK (fs_intelview_busy () && visible ("intel-progress") &&
	       strstr (text_of ("intel-progress-label"), "Downloading") &&
	       !gtk_widget_is_sensitive (find (page, "intel-update")) &&
	       !gtk_widget_is_sensitive (find (page,
	                                       "feed-switch-spamhaus-drop")),
	       "mid-update: the progress line shows (\"%s\"), and the "
	       "controls wait for it", text_of ("intel-progress-label"));
	shot ("02b-updating.png");
	wait_idle ();
	fetch_delay_us = 0;

	/* ---- refused, Accept smaller list ---- */
	b1 = drop_body ("45.1.0.0/24");
	serve ("spamhaus-drop", b1);
	calls = kern.apply_calls;
	click ("intel-update");
	t = feed_text ("status", "spamhaus-drop");
	CHECK (strstr (t, "The last update was refused") != NULL,
	       "a list that shrank to 1 of 10 is refused (\"%s\")", t != NULL ? t : "(null)");
	g_free (t);
	CHECK (visible ("feed-accept-spamhaus-drop") &&
	       strcmp (gtk_button_get_label (GTK_BUTTON (
	               find (page, "feed-accept-spamhaus-drop"))),
	               "Accept smaller list") == 0,
	       "and \"Accept smaller list\" is offered");
	CHECK (strstr (text_of ("intel-message"), "Refused") != NULL,
	       "the page says what happened (\"%s\")",
	       text_of ("intel-message"));
	shot ("03-refused.png");
	click ("feed-accept-spamhaus-drop");
	t = feed_text ("facts", "spamhaus-drop");
	CHECK (strstr (t, "1 entry") != NULL &&
	       find (page, "feed-accept-spamhaus-drop") == NULL,
	       "Accept smaller list lets the copy in, and the button goes "
	       "(\"%s\")", t != NULL ? t : "(null)");
	g_free (t);
	CHECK (kern.apply_calls > calls, "and the smaller list is applied");

	/* ---- failed download ---- */
	serve_error ("spamhaus-drop", "Could not resolve host");
	click ("intel-update");
	t = feed_text ("status", "spamhaus-drop");
	CHECK (strstr (t, "failed") && strstr (t, "Could not resolve host") &&
	       strstr (t, "is kept and in force") && !strstr (t, "still used"),
	       "a failed download says so and keeps the copy, in force while "
	       "it is (\"%s\")", t != NULL ? t : "(null)");
	g_free (t);
	serve ("spamhaus-drop", b10);

	/* ---- not loaded, Apply ---- */
	fake_clear (NULL);
	refresh ();
	CHECK (strcmp (text_of ("intel-state-title"), "Not loaded") == 0 &&
	       visible ("intel-apply"),
	       "table gone behind StockFW's back: \"Not loaded\", with Apply "
	       "(got \"%s\")", text_of ("intel-state-title"));
	shot ("04-not-loaded.png");
	click ("intel-apply");
	CHECK (strcmp (text_of ("intel-state-title"), "Protected") == 0,
	       "Apply puts it back: \"Protected\"");

	/* ---- differs ---- */
	g_free (kern.digest);
	kern.digest = g_strdup ("0123456789abcdef0123456789abcdef");
	refresh ();
	CHECK (strcmp (text_of ("intel-state-title"),
	               "Changed outside StockFW") == 0 && visible ("intel-apply"),
	       "another table: \"Changed outside StockFW\" (got \"%s\")",
	       text_of ("intel-state-title"));
	shot ("05-differs.png");
	click ("intel-apply");

	/* ---- suspended (the user's Stop) ---- */
	kern.fw = FS_FW_STOPPED;
	CHECK (fs_intel_suspend (&fake_backend, "smoke", NULL), "suspend");
	refresh ();
	CHECK (strcmp (text_of ("intel-state-title"), "Paused") == 0,
	       "firewall stopped by the user: \"Paused\" (got \"%s\")",
	       text_of ("intel-state-title"));
	shot ("06-paused.png");

	/* Paused: the lookup must not say "is blocked" (the kernel holds
	 * nothing), and the failed update's copy is "kept", not "in force"
	 * or "still used". */
	t = feed_text ("status", "spamhaus-drop");
	CHECK (strstr (t, "is kept.") && !strstr (t, "in force") &&
	       !strstr (t, "still used"),
	       "paused: the failed update's copy is kept, not said to be used "
	       "(\"%s\")", t != NULL ? t : "(null)");
	g_free (t);
	lookup ("45.1.0.9");
	CHECK (strstr (text_of ("intel-lookup-result"), "Spamhaus DROP (IPv4)") &&
	       strstr (text_of ("intel-lookup-result"), "not blocked now") &&
	       !strstr (text_of ("intel-lookup-result"), "and is blocked") &&
	       !gtk_style_context_has_class (gtk_widget_get_style_context (
	               find (page, "intel-lookup-result")), "intel-hit"),
	       "paused: lookup says the list holds it but nothing blocks it now "
	       "(\"%s\")", text_of ("intel-lookup-result"));
	CHECK (find (page, "intel-lists-empty") != NULL &&
	       gtk_style_context_has_class (gtk_widget_get_style_context (
	               find (page, "intel-lists-empty")), "intel-pad"),
	       "\"No list file imported.\" is padded like the rows");

	/* ---- stopped: a change is saved, not applied ---- */
	calls = kern.apply_calls;
	serve ("feodo", t = plain_body (12, 77));
	g_free (t);
	flip ("feodo", TRUE);
	CHECK (kern.apply_calls == calls &&
	       strstr (text_of ("intel-message"),
	               "put in force when the firewall starts") != NULL,
	       "firewall stopped: turning a feed on saves it, applies "
	       "nothing, and says when it will be (\"%s\")",
	       text_of ("intel-message"));
	kern.fw = FS_FW_RUNNING;
	{
		FsIntelOutcome *o = fs_intel_resume (&fake_backend, "smoke", NULL,
		                                     NULL);

		fs_intel_outcome_free (o);
	}
	refresh ();
	CHECK (strcmp (text_of ("intel-state-title"), "Protected") == 0 &&
	       strstr (kern.last_sets, "feodo") != NULL,
	       "Start: both lists in force (%s)", kern.last_sets);
	CHECK (!visible ("intel-lookup-result"),
	       "the paused lookup's answer is gone once the state changed");

	/* ---- a hold (the Lock) ---- */
	test_hold = "the policy is locked on the Overview";
	calls = kern.apply_calls;
	flip ("feodo", FALSE);
	CHECK (kern.apply_calls == calls &&
	       strstr (text_of ("intel-message"), "not put in force") &&
	       strstr (text_of ("intel-message"), "locked"),
	       "under a hold: saved, not applied, and why (\"%s\")",
	       text_of ("intel-message"));
	test_hold = NULL;
	click ("intel-apply");   /* the config now differs from the kernel */
	CHECK (strstr (kern.last_sets, "feodo") == NULL,
	       "released: Apply takes feodo out (%s)", kern.last_sets);

	/* A feed turned on under the Lock blocks nothing: once the 30 s
	 * refresh took the message line away, its row must still say so,
	 * while the hero stays Protected for the other list. */
	test_hold = "the policy is locked on the Overview";
	CHECK (g_strcmp0 (fs_intelview_hold_reason (), test_hold) == 0,
	       "fs_intelview_hold_reason: the Lock's sentence (what the Status "
	       "page's Start is held by)");
	flip ("feodo", TRUE);
	refresh ();
	t = feed_text ("status", "feodo");
	CHECK (strcmp (text_of ("intel-state-title"), "Protected") == 0 &&
	       !visible ("intel-message") && strstr (kern.last_sets, "feodo") == NULL &&
	       strstr (t, "not in force") && strstr (t, "locked"),
	       "held under the Lock: after a refresh the feodo row says it is "
	       "not in force, and why (\"%s\")", t != NULL ? t : "(null)");
	g_free (t);
	shot ("06c-held-feodo-on.png");
	{
		/* Review T3: the Overview and the tray do not claim every
		 * list is in force while feodo is on and blocks nothing. */
		gchar *sum = fs_intelview_summary ();

		CHECK (sum != NULL && strstr (sum, "except 1 list") != NULL &&
		       strstr (sum, "not applied yet") != NULL,
		       "held under the Lock: the summary names the list that is "
		       "on but not in force (\"%s\")", sum != NULL ? sum : "(null)");
		g_free (sum);
	}
	{
		/* Review T4: the master switch turned off here, under the
		 * Lock, leaves the rules blocking.  That is the user's own
		 * change, not one made outside StockFW, and the rules still
		 * block. */
		GtkWidget *master = find (page, "intel-master");
		gchar *sum;

		CHECK (master != NULL, "the master switch is there");
		if (master != NULL)
			gtk_switch_set_active (GTK_SWITCH (master), FALSE);
		wait_idle ();
		refresh ();
		sum = fs_intelview_summary ();
		CHECK (strcmp (text_of ("intel-state-title"),
		               "Off, but rules still in place") == 0 &&
		       sum != NULL && strstr (sum, "outside StockFW") == NULL &&
		       strstr (sum, "still holds blocklist rules") != NULL,
		       "master switch off under the Lock: \"%s\", and the summary "
		       "says the rules still block, never \"changed outside "
		       "StockFW\" (\"%s\")", text_of ("intel-state-title"), sum);
		g_free (sum);
		if (master != NULL)
			gtk_switch_set_active (GTK_SWITCH (master), TRUE);
		wait_idle ();
		refresh ();
	}
	test_hold = NULL;
	CHECK (fs_intelview_hold_reason () == NULL,
	       "fs_intelview_hold_reason: NULL without a hold");
	refresh ();
	t = feed_text ("status", "feodo");
	CHECK (strstr (t, "press Apply") != NULL,
	       "released, not applied yet: \"press Apply\" (\"%s\")", t != NULL ? t : "(null)");
	g_free (t);
	click ("intel-apply");
	t = feed_text ("status", "feodo");
	CHECK (strstr (kern.last_sets, "feodo") != NULL &&
	       strstr (t, "in force") && !strstr (t, "not in force"),
	       "applied: the row says in force (\"%s\")", t != NULL ? t : "(null)");
	g_free (t);
	flip ("feodo", FALSE);
	CHECK (strstr (kern.last_sets, "feodo") == NULL,
	       "(feodo off again: %s)", kern.last_sets);

	/* ---- lookup ---- */
	lookup ("45.1.0.9");
	CHECK (strstr (text_of ("intel-lookup-result"), "Spamhaus DROP (IPv4)") &&
	       strstr (text_of ("intel-lookup-result"), "is blocked"),
	       "lookup: a listed address is blocked, naming the list (\"%s\")",
	       text_of ("intel-lookup-result"));
	lookup ("8.8.8.8");
	CHECK (strstr (text_of ("intel-lookup-result"), "on none") != NULL,
	       "lookup: an address on no list (\"%s\")",
	       text_of ("intel-lookup-result"));
	lookup ("not-an-address");
	CHECK (strstr (text_of ("intel-lookup-result"), "not one address"),
	       "lookup: text that is not an address (\"%s\")",
	       text_of ("intel-lookup-result"));

	/* ---- allow list ---- */
	set_editor ("intel-allow-text", "45.1.0.9 # a partner\n# another\n");
	click ("intel-allow-save");
	lookup ("45.1.0.9");
	CHECK (strstr (text_of ("intel-lookup-result"), "allow list") != NULL,
	       "allow list: saved, the address is never blocked (\"%s\")",
	       text_of ("intel-lookup-result"));
	set_editor ("intel-allow-text", "45.1.0.9\nnonsense\n");
	click ("intel-allow-save");
	CHECK (gtk_style_context_has_class (gtk_widget_get_style_context (
	               find (page, "intel-message")), "intel-error"),
	       "allow list: a line that is not an address is refused, shown "
	       "as an error (\"%s\")", text_of ("intel-message"));

	/* ---- your blocklist ---- */
	set_editor ("intel-deny-text", "203.0.113.0/24\n");
	click ("intel-deny-save");
	lookup ("203.0.113.7");
	CHECK (strstr (text_of ("intel-lookup-result"), "My blocklist") &&
	       strstr (text_of ("intel-lookup-result"), "is blocked") &&
	       strstr (kern.last_sets, "local-my-blocklist") != NULL,
	       "your blocklist: saved, applied, blocks (\"%s\")",
	       text_of ("intel-lookup-result"));

	/* ---- import, remove ---- */
	{
		gchar *file = g_build_filename (base, "Office VPN.txt", NULL);

		g_file_set_contents (file, "198.51.100.0/24\n198.51.101.5\n"
		                     "10.1.2.3\nnot an address\n", -1, NULL);
		fs_intelview_set_import_path (file);
		click ("intel-import");
		CHECK (find (page, "list-row-local-office-vpn") != NULL &&
		       strstr (kern.last_sets, "local-office-vpn") != NULL,
		       "import: the file becomes a list, applied (%s)",
		       kern.last_sets);
		CHECK (strstr (text_of ("intel-message"), "did not parse (the first "
		                        "is line 4)") &&
		       strstr (text_of ("intel-message"), "never blocked") &&
		       gtk_style_context_has_class (gtk_widget_get_style_context (
		               find (page, "intel-message")), "intel-warn"),
		       "import: the bad line and the private entry are named, as a "
		       "warning (\"%s\")", text_of ("intel-message"));
		fs_intelview_set_import_path (NULL);
		g_free (file);
	}
	counter_set (kern.counters, "spamhaus-drop", 5678);
	refresh ();
	shot ("07-your-lists.png");
	next_response = GTK_RESPONSE_ACCEPT;
	click ("list-remove-local-office-vpn");
	CHECK (find (page, "list-row-local-office-vpn") == NULL &&
	       strstr (kern.last_sets, "local-office-vpn") == NULL &&
	       g_strcmp0 (last_dialog, "intel-remove-dialog") == 0,
	       "remove: asked first, then gone from the page and the kernel");

	/* ---- unknown ---- */
	kern.unknown = TRUE;
	refresh ();
	/* Root sees "Unknown"; without rights the same unreadable kernel
	 * is "Needs administrator rights" (fs_intel_state), which is what
	 * the CI's non-root smoke run sees. */
	{
#ifdef G_OS_WIN32
		gboolean admin = fs_winstore_is_admin ();
#else
		gboolean admin = geteuid () == 0;
#endif
		const gchar *want = admin ? "Unknown"
		                          : "Needs administrator rights";

		CHECK (strcmp (text_of ("intel-state-title"), want) == 0,
		       "the kernel cannot be read: \"%s\" (got \"%s\")",
		       want, text_of ("intel-state-title"));
	}
	shot ("09-unknown.png");
	kern.unknown = FALSE;

	/* ---- Windows: rules there but not enforced, nothing counted ---- */
	fs_intelview_set_backend (&win_backend);
	kern.live = FS_INTEL_LIVE_INACTIVE;
	refresh ();
	CHECK (strcmp (text_of ("intel-state-title"), "Not in force") == 0 &&
	       strstr (text_of ("intel-state-body"), WIN_NOT_IN_FORCE) != NULL,
	       "windows: rules the firewall does not enforce: \"Not in "
	       "force\" with the platform's reason (\"%s\": \"%s\")",
	       text_of ("intel-state-title"), text_of ("intel-state-body"));
	{
		gchar *sum = fs_intelview_summary ();

		CHECK (sum != NULL && strstr (sum, "not in force") != NULL &&
		       strstr (sum, WIN_NOT_IN_FORCE) != NULL,
		       "windows: the Overview and tray summary says not in "
		       "force, with the reason (\"%s\")", sum != NULL ? sum : "(null)");
		g_free (sum);
	}
	t = feed_text ("facts", "spamhaus-drop");
	CHECK (strstr (t, fs_intel_counts_unavailable (&win_backend)) != NULL &&
	       strstr (t, "Nothing blocked") == NULL &&
	       strstr (t, "Blocked ") == NULL,
	       "windows: no count per feed, the reason instead (\"%s\")", t != NULL ? t : "(null)");
	g_free (t);
	CHECK (strcmp (text_of ("intel-tile-2"), "n/a") == 0,
	       "windows: the Blocked tile says n/a, never 0 (\"%s\")",
	       text_of ("intel-tile-2"));
	shot ("09b-not-in-force.png");
	/* Review T2: Apply while the firewall does not enforce the rules
	 * (Windows Firewall off for the profile in use) must not say they
	 * are in force. */
	kern.apply_inactive = TRUE;
	click ("intel-apply");
	CHECK (strstr (text_of ("intel-message"), "The lists are in force") ==
	       NULL &&
	       strstr (text_of ("intel-message"), "not in force") != NULL &&
	       strstr (text_of ("intel-message"), WIN_NOT_IN_FORCE) != NULL &&
	       gtk_style_context_has_class (gtk_widget_get_style_context (
	               find (page, "intel-message")), "intel-warn") &&
	       strcmp (text_of ("intel-state-title"), "Not in force") == 0,
	       "windows: Apply with the firewall off for the profile says the "
	       "rules are in place but not in force, as a warning (\"%s\")",
	       text_of ("intel-message"));
	kern.apply_inactive = FALSE;
	kern.live = FS_INTEL_LIVE_INACTIVE;
	kern.live = FS_INTEL_LIVE_PARTIAL;
	refresh ();
	CHECK (strcmp (text_of ("intel-state-title"),
	               "Changed outside StockFW") == 0,
	       "windows: rules not whole read \"Changed outside StockFW\" "
	       "(got \"%s\")", text_of ("intel-state-title"));
	{
		gchar *sum = fs_intelview_summary ();

		CHECK (sum != NULL && strstr (sum, "changed outside") != NULL,
		       "windows: ... and the summary says so (\"%s\")", sum != NULL ? sum : "(null)");
		g_free (sum);
	}
	kern.live = FS_INTEL_LIVE_PRESENT;
	refresh ();
	CHECK (strcmp (text_of ("intel-state-title"), "Protected") == 0,
	       "windows: whole and enforced again: \"Protected\" (got "
	       "\"%s\")", text_of ("intel-state-title"));
	{
		gchar *sum = fs_intelview_summary ();

		CHECK (sum != NULL && strstr (sum, "are in force") != NULL,
		       "windows: ... summary: in force (\"%s\")", sum != NULL ? sum : "(null)");
		g_free (sum);
	}
	{
		/* Review T1: after Stop the tray says the firewall is off and
		 * claims no blocklist in force, even before the page reads
		 * the state again. */
		GtkStatusIcon *icon;
		const gchar *tip = NULL;
		gchar *sum;

		fs_prefs_set_bool (FS_PREFS_ENABLE_TRAY_ICON, TRUE);
		fs_tray_set_window (GTK_WINDOW (window));
		fs_tray_sync ();
		fs_tray_set_firewall (FS_FW_RUNNING, NULL);
		icon = fs_tray_icon ();
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS
		tip = icon != NULL ? gtk_status_icon_get_tooltip_text (icon) : NULL;
		G_GNUC_END_IGNORE_DEPRECATIONS
		CHECK (tip != NULL && strstr (tip, "are in force") != NULL,
		       "tray: running, the tooltip carries the summary (\"%s\")",
		       tip ? tip : "(no icon)");
		CHECK (fs_intel_suspend (&win_backend, "smoke", NULL), "(Stop)");
		kern.fw = FS_FW_STOPPED;
		fs_tray_set_firewall (FS_FW_STOPPED, NULL);
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS
		tip = icon != NULL ? gtk_status_icon_get_tooltip_text (icon) : NULL;
		G_GNUC_END_IGNORE_DEPRECATIONS
		CHECK (tip != NULL && strstr (tip, "Firewall OFF") != NULL &&
		       strstr (tip, "in force") == NULL,
		       "tray: after Stop, before the next read, the tooltip "
		       "claims no blocklist in force (\"%s\")",
		       tip ? tip : "(no icon)");
		refresh ();
		sum = fs_intelview_summary ();
		CHECK (sum == NULL, "after Stop, once read: no summary (\"%s\")",
		       sum ? sum : "none");
		g_free (sum);
		kern.fw = FS_FW_RUNNING;
		fs_intel_outcome_free (fs_intel_resume (&win_backend, "smoke",
		                                        NULL, NULL));
		fs_tray_set_firewall (FS_FW_RUNNING, NULL);
		fs_tray_uninstall ();
		refresh ();
	}
	fs_intelview_set_backend (&fake_backend);
	refresh ();

	/* ---- countries and networks ---- */
	check_geo ();

	/* ---- unsupported (no intel slots) ---- */
	fs_intelview_set_backend (&bare_backend);
	refresh ();
	CHECK (g_str_has_prefix (text_of ("intel-state-title"), "Not supported"),
	       "no intel slots: \"%s\"", text_of ("intel-state-title"));
	CHECK (!gtk_widget_is_sensitive (find (page, "feed-switch-feodo")) &&
	       !gtk_widget_is_sensitive (find (page, "intel-update")) &&
	       !visible ("intel-yours"),
	       "and nothing can be turned on there");
	shot ("10-unsupported.png");
	fs_intelview_set_backend (&fake_backend);
	refresh ();

	/* ---- Events ---- */
	check_events ();

	g_free (b10);
	g_free (b1);
	g_string_free (seen_progress, TRUE);
	gtk_widget_destroy (window);
	CHECK (other_criticals == 0, "no other GDK critical or warning (%u)",
	       other_criticals);
	if (g_getenv ("INTEL_SMOKE_KEEP") == NULL)
		rm_rf (base);
	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);
	return failures ? 1 : 0;
}
