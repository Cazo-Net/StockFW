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
 *     puts the address on the allow list.
 *
 * With INTEL_SMOKE_SHOTS=<dir>, a PNG of the page in each state.
 * Teeth: tests/README.md, "The Threat Intel page".
 */

#include <gtk/gtk.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-backend.h"
#include "core/fs-feed.h"
#include "core/fs-intel.h"
#include "core/fs-intelset.h"
#include "core/fs-netparse.h"
#include "ui/fs-hitview.h"
#include "ui/fs-intelview.h"
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
	kern.live = rs->sets->len ? FS_INTEL_LIVE_PRESENT : FS_INTEL_LIVE_ABSENT;
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
	if (digest != NULL && kern.live == FS_INTEL_LIVE_PRESENT)
		*digest = g_strdup (kern.digest);
	return kern.live;
}

static FsFirewallState
fake_get_state (void)
{
	return kern.fw;
}

static FsBackend fake_backend;
static FsBackend bare_backend;     /* no intel slots: Windows today   */

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

/* A scratch directory the engine accepts as a store parent (StrictModes:
 * no parent writable by others, so not under /tmp). */
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
	bodies = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	errors = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	fs_intel_set_fetcher (fake_fetch, NULL);
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
	CHECK (strcmp (t, "Off.") == 0, "a feed that is off says so (\"%s\")", t);
	g_free (t);
	{
		GtkWidget *row = find (page, "feed-row-firehol-level1");
		GList *kids = NULL;
		gboolean nc = FALSE, credit = FALSE;
		GQueue q = G_QUEUE_INIT;

		/* The row's labels, for the licence and credit. */
		g_queue_push_tail (&q, row);
		while (!g_queue_is_empty (&q)) {
			GtkWidget *w = g_queue_pop_head (&q);

			if (GTK_IS_LABEL (w)) {
				const gchar *l = gtk_label_get_label (GTK_LABEL (w));

				nc |= strstr (l, "Non-commercial use only") != NULL;
				credit |= strstr (l, "href=\"https://iplists.firehol.org/")
				          != NULL;
			}
			if (GTK_IS_CONTAINER (w)) {
				kids = gtk_container_get_children (GTK_CONTAINER (w));
				for (GList *l = kids; l != NULL; l = l->next)
					g_queue_push_tail (&q, l->data);
				g_list_free (kids);
			}
		}
		CHECK (row != NULL && nc && credit,
		       "FireHOL level 1: \"Non-commercial use only\" and a "
		       "credit link to its publisher");
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
	CHECK (fetches == 0 && kern.apply_calls == 0 && !fs_intel_store_exists (),
	       "Cancel at the consent dialog: nothing downloaded, nothing "
	       "applied, no store");
	t = feed_text ("status", "spamhaus-drop");
	CHECK (strcmp (t, "Off.") == 0, "and the feed is still off (\"%s\")", t);
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
	       "the feed: \"Up to date and in force.\" (\"%s\")", t);
	g_free (t);
	t = feed_text ("facts", "spamhaus-drop");
	CHECK (strstr (t, "10 entries") && strstr (t, "updated just now") &&
	       strstr (t, "next update in 24 h") &&
	       strstr (t, "Nothing blocked yet"),
	       "its facts: entries, last and next update, nothing blocked "
	       "(\"%s\")", t);
	g_free (t);
	CHECK (!visible ("intel-progress"), "the progress line goes when done");

	/* ---- counters ---- */
	counter_set (kern.counters, "spamhaus-drop", 1234);
	refresh ();
	t = feed_text ("facts", "spamhaus-drop");
	CHECK (strstr (t, "Blocked 1,234 packets since") != NULL,
	       "blocked counter per feed (\"%s\")", t);
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
	       "a list that shrank to 1 of 10 is refused (\"%s\")", t);
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
	       "(\"%s\")", t);
	g_free (t);
	CHECK (kern.apply_calls > calls, "and the smaller list is applied");

	/* ---- failed download ---- */
	serve_error ("spamhaus-drop", "Could not resolve host");
	click ("intel-update");
	t = feed_text ("status", "spamhaus-drop");
	CHECK (strstr (t, "failed") && strstr (t, "Could not resolve host") &&
	       strstr (t, "is still used"),
	       "a failed download says so and keeps the copy (\"%s\")", t);
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
	set_editor ("intel-allow-text", "45.1.0.9\n# a partner\n");
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

		g_file_set_contents (file, "198.51.100.0/24\n198.51.101.5\n", -1,
		                     NULL);
		fs_intelview_set_import_path (file);
		click ("intel-import");
		CHECK (find (page, "list-row-local-office-vpn") != NULL &&
		       strstr (kern.last_sets, "local-office-vpn") != NULL,
		       "import: the file becomes a list, applied (%s)",
		       kern.last_sets);
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
	CHECK (strcmp (text_of ("intel-state-title"), "Unknown") == 0,
	       "the kernel cannot be read: \"Unknown\" (got \"%s\")",
	       text_of ("intel-state-title"));
	shot ("09-unknown.png");
	kern.unknown = FALSE;

	/* ---- unsupported (Windows today) ---- */
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
	if (g_getenv ("INTEL_SMOKE_KEEP") == NULL)
		rm_rf (base);
	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);
	return failures ? 1 : 0;
}
