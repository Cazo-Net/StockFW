/* The Overview on a Windows-shaped backend (1.0.7), on any platform.
 *
 * The real Windows backend reads the profile in force from
 * INetFwPolicy2::CurrentProfileTypes and the connected networks from
 * INetworkListManager; neither exists off Windows.  This test supplies
 * fs_backend() itself with a fake that answers the way that backend
 * does, builds the real Overview page, and checks what a user would
 * read on it:
 *
 *   - the subtitle names the network, the medium and its kind;
 *   - the profiles card marks the profile in force "In use", and only
 *     that one, through the page-wide show_all() fs-app.c does;
 *   - the verdict names the profile doing the protecting;
 *   - the profile in use switched off turns the verdict red ("This
 *     network is not protected") while the service still runs, and a
 *     secondary network's profile off turns it amber, not red;
 *   - switching the profile back on from the card clears it at once;
 *   - moving networks (home Private -> cafe Public) is picked up.
 *
 * That backend has no adapter counters and cannot list connections, so
 * the same page then shows the status board's live cards (2.0.0) with
 * nothing to show: the Traffic card must say the counters are missing,
 * Busiest programs must be left out.  The page is destroyed and a
 * second one built on a backend whose counters, connection list and
 * clock the test sets, and checked for:
 *
 *   - the Traffic graph's two series: bytes per second over the real
 *     adapters only, one point a refresh, sixty at most, a reading in
 *     between adding no point and losing no byte;
 *   - its scale: the round step that holds the peak (1, 2, 5, 10...
 *     KiB/s), never under 1 KiB/s;
 *   - Busiest programs: ranked by open connections to other computers,
 *     unnamed owners as one "Unknown program";
 *   - a connection row opening the detail drawer.
 *
 * Teeth: make update_overview ignore `unguarded' (or refresh_place not
 * show the marks) and the corresponding checks fail; count the bridge
 * in refresh_network, or sort update_busiest the other way, and the
 * live-card checks fail; see tests/README.
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-backend.h"
#include "core/fs-netplace.h"
#include "ui/fs-drawer.h"
#include "ui/fs-statusview.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	printf ((cond) ? "ok:   " : "FAIL: ");                  \
	printf (__VA_ARGS__);                                   \
	printf ("\n");                                          \
	if (!(cond))                                            \
		failures++;                                     \
} while (0)

/* ------------------------------------------------------- fake backend */

static gboolean    fake_on[FS_PROFILE_COUNT] = { TRUE, TRUE, TRUE };
static const char *fake_network = "HomeNet";
static gint        fake_category = FS_PROFILE_PRIVATE;
static gboolean    fake_hyperv = FALSE;   /* + an Unidentified network */
static guint       fake_set_calls = 0;

static gboolean
fake_available (void)
{
	return TRUE;
}

static gboolean
fake_get_profile_enabled (gint profile, gboolean *enabled)
{
	if (profile < 0 || profile >= FS_PROFILE_COUNT)
		return FALSE;
	if (enabled != NULL)
		*enabled = fake_on[profile];
	return TRUE;
}

static gboolean
fake_set_profile_enabled (gint profile, gboolean enabled, GError **error)
{
	(void) error;
	fake_on[profile] = enabled;
	fake_set_calls++;
	return TRUE;
}

/* What fs-backend-windows.c builds: the networks in NLM's order (the
 * virtual switch first, as Windows often lists it) and in_use from
 * CurrentProfileTypes. */
static FsNetworkPlace *
fake_network_place (void)
{
	FsNetworkPlace *place = fs_network_place_new ();

	if (fake_hyperv) {
		fs_network_place_add (place, "Unidentified network",
		                      FS_PROFILE_PUBLIC, "Virtual", FALSE);
		place->in_use |= FS_PROFILE_BIT (FS_PROFILE_PUBLIC);
	}
	fs_network_place_add (place, fake_network, fake_category, "Wi-Fi",
	                      TRUE);
	place->in_use |= FS_PROFILE_BIT (fake_category);
	return place;
}

static const FsBackend fake_backend = {
	.name                = "fake-windows",
	.display_name        = "Windows Defender Firewall",
	.available           = fake_available,
	.get_profile_enabled = fake_get_profile_enabled,
	.set_profile_enabled = fake_set_profile_enabled,
	.network_place       = fake_network_place,
};

/* ---- the same, with adapter counters and a connection list (2.0.0) ---
 * What the status board's live cards read.  The counters and the list
 * are the test's to set, so every number the page shows is known. */

static guint64  fake_rx = 1000000, fake_tx = 500000;   /* eth0, bytes  */
static guint64  fake_bridge = 0;                       /* docker0      */
static gboolean fake_no_counters = FALSE;
static gboolean fake_no_conns = FALSE;
static gint64   fake_time = 5 * G_USEC_PER_SEC;

static gint64
fake_clock (void)
{
	return fake_time;
}

static FsIfaceStat *
fake_stat (const gchar *device, const gchar *kind, const gchar *ip,
           guint64 received, guint64 sent)
{
	FsIfaceStat *stat = g_new0 (FsIfaceStat, 1);

	stat->device = g_strdup (device);
	stat->kind = g_strdup (kind);
	stat->ip = g_strdup (ip);
	stat->received = received;
	stat->sent = sent;
	stat->up = TRUE;
	return stat;
}

static GList *
fake_list_interface_stats (void)
{
	GList *stats = NULL;

	if (fake_no_counters)
		return NULL;
	stats = g_list_append (stats, fake_stat ("eth0", "Ethernet",
	                                         "192.168.1.20", fake_rx,
	                                         fake_tx));
	/* A bridge: its traffic also crosses eth0, so the graph must not
	 * count it. */
	stats = g_list_append (stats, fake_stat ("docker0", "Virtual",
	                                         "172.17.0.1", fake_bridge,
	                                         fake_bridge));
	return stats;
}

static FsConnection *
fake_conn (const gchar *program, const gchar *remote, const gchar *port,
           gboolean inbound, guint local_port)
{
	FsConnection *c = g_new0 (FsConnection, 1);
	const gchar *here = g_str_has_prefix (remote, "127.") ? "127.0.0.1"
	                                                      : "192.168.1.20";

	c->source = g_strdup (inbound ? remote : here);
	c->destination = g_strdup (inbound ? here : remote);
	c->port = g_strdup (port);
	c->protocol = g_strdup ("TCP");
	c->service = g_strdup (strcmp (port, "443") == 0 ? "HTTPS" : "");
	c->program = g_strdup (program);
	c->direction = g_strdup (inbound ? "Inbound" : "Outbound");
	c->local_port = local_port;
	c->state = g_strdup ("ESTABLISHED");
	return c;
}

/* firefox 5, unnamed 4 ("?" three times and no name once), ssh 2, then
 * curl, nginx and python with 1 each; postgres has six, all between
 * programs on this computer. */
static GList *
fake_list_connections (void)
{
	GList *conns = NULL;
	gint i;

	if (fake_no_conns)
		return NULL;

	conns = g_list_append (conns, fake_conn ("firefox", "93.184.216.34",
	                                         "443", FALSE, 50001));
	conns = g_list_append (conns, fake_conn ("?", "203.0.113.9", "8443",
	                                         FALSE, 50002));
	conns = g_list_append (conns, fake_conn ("python", "198.51.100.3",
	                                         "8000", FALSE, 50003));
	for (i = 0; i < 6; i++)
		conns = g_list_append (conns, fake_conn ("postgres", "127.0.0.1",
		                                         "5432", FALSE, 0));
	for (i = 0; i < 4; i++)
		conns = g_list_append (conns, fake_conn ("firefox",
		                                         "93.184.216.35", "443",
		                                         FALSE, 0));
	conns = g_list_append (conns, fake_conn ("ssh", "198.51.100.7", "22",
	                                         FALSE, 0));
	conns = g_list_append (conns, fake_conn ("ssh", "198.51.100.8", "22",
	                                         FALSE, 0));
	conns = g_list_append (conns, fake_conn ("?", "203.0.113.10", "8443",
	                                         FALSE, 0));
	conns = g_list_append (conns, fake_conn ("?", "203.0.113.11", "8443",
	                                         FALSE, 0));
	conns = g_list_append (conns, fake_conn (NULL, "203.0.113.12", "8443",
	                                         FALSE, 0));
	conns = g_list_append (conns, fake_conn ("nginx", "198.51.100.200",
	                                         "443", TRUE, 0));
	conns = g_list_append (conns, fake_conn ("curl", "198.51.100.4", "443",
	                                         FALSE, 0));
	return conns;
}

static const FsBackend fake_live = {
	.name                 = "fake-live",
	.display_name         = "test firewall",
	.available            = fake_available,
	.get_profile_enabled  = fake_get_profile_enabled,
	.set_profile_enabled  = fake_set_profile_enabled,
	.network_place        = fake_network_place,
	.list_interface_stats = fake_list_interface_stats,
	.list_connections     = fake_list_connections,
};

static const FsBackend *current = &fake_backend;

const FsBackend *
fs_backend (void)
{
	return current;
}

const gchar *
fs_error_domain (void)
{
	return "fake-windows";
}

void
fs_backend_set_context (FsPolicy *policy, FsSettings *settings)
{
	(void) policy;
	(void) settings;
}

/* ------------------------------------------------------------ helpers */

static GtkWidget *
find_by_class (GtkWidget *widget, const gchar *klass)
{
	if (gtk_style_context_has_class (gtk_widget_get_style_context (widget),
	                                 klass))
		return widget;
	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));
		GtkWidget *found = NULL;

		for (GList *l = children; l != NULL && found == NULL; l = l->next)
			found = find_by_class (GTK_WIDGET (l->data), klass);
		g_list_free (children);
		return found;
	}
	return NULL;
}

/* Every widget carrying klass, in tree order. */
static void
collect_by_class (GtkWidget *widget, const gchar *klass, GPtrArray *out)
{
	if (gtk_style_context_has_class (gtk_widget_get_style_context (widget),
	                                 klass))
		g_ptr_array_add (out, widget);
	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));

		for (GList *l = children; l != NULL; l = l->next)
			collect_by_class (GTK_WIDGET (l->data), klass, out);
		g_list_free (children);
	}
}

static const gchar *
text_of (GtkWidget *page, const gchar *klass)
{
	GtkWidget *w = find_by_class (page, klass);

	return w != NULL && GTK_IS_LABEL (w) ? gtk_label_get_text (GTK_LABEL (w))
	                                     : "(none)";
}

/* Visible here and all the way up to the page. */
static gboolean
shown (GtkWidget *widget, GtkWidget *top)
{
	for (GtkWidget *w = widget; w != NULL; w = gtk_widget_get_parent (w)) {
		if (!gtk_widget_get_visible (w))
			return FALSE;
		if (w == top)
			return TRUE;
	}
	return TRUE;
}

/* Which rows' "In use" marks show, as a string: "-P-" = Private only. */
static gchar *
marks (GtkWidget *page)
{
	GPtrArray *pills = g_ptr_array_new ();
	GString *out = g_string_new (NULL);

	collect_by_class (page, "in-use", pills);
	for (guint i = 0; i < pills->len; i++)
		g_string_append_c (out, shown (pills->pdata[i], page)
		                        ? "DPU"[i % 3] : '-');
	g_ptr_array_unref (pills);
	return g_string_free (out, FALSE);
}

/* The 5 s timer, without waiting five seconds. */
static void
poll (void)
{
	fs_statusview_set_state (fs_statusview_get_state ());
	fs_statusview_refresh ();
}

static GtkWidget *
switch_for (GtkWidget *page, gint profile)
{
	GPtrArray *rows = g_ptr_array_new ();
	GtkWidget *sw = NULL;

	collect_by_class (page, "profile-row", rows);
	if ((guint) profile < rows->len) {
		GList *kids = gtk_container_get_children (
			GTK_CONTAINER (rows->pdata[profile]));

		for (GList *l = kids; l != NULL; l = l->next)
			if (GTK_IS_SWITCH (l->data))
				sw = l->data;
		g_list_free (kids);
	}
	g_ptr_array_unref (rows);
	return sw;
}

/* --------------------------------------- the status board's live cards */

static guint warnings = 0;

static GLogWriterOutput
count_warnings (GLogLevelFlags level, const GLogField *fields,
                gsize n_fields, gpointer data)
{
	(void) data;
	if (level & (G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL))
		warnings++;
	return g_log_writer_default (level, fields, n_fields, NULL);
}

/* Every widget of `type' under widget carrying klass (NULL: any), in
 * tree order. */
static void
collect (GtkWidget *widget, GType type, const gchar *klass, GPtrArray *out)
{
	if (G_TYPE_CHECK_INSTANCE_TYPE (widget, type) &&
	    (klass == NULL ||
	     gtk_style_context_has_class (gtk_widget_get_style_context (widget),
	                                  klass)))
		g_ptr_array_add (out, widget);
	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));

		for (GList *l = children; l != NULL; l = l->next)
			collect (GTK_WIDGET (l->data), type, klass, out);
		g_list_free (children);
	}
}

/* The first label under widget whose text contains `needle' (or, with
 * `whole', is exactly it). */
static GtkWidget *
find_label (GtkWidget *widget, const gchar *needle, gboolean whole)
{
	GPtrArray *labels = g_ptr_array_new ();
	GtkWidget *found = NULL;

	if (widget != NULL)
		collect (widget, GTK_TYPE_LABEL, NULL, labels);
	for (guint i = 0; i < labels->len && found == NULL; i++) {
		const gchar *text = gtk_label_get_text (labels->pdata[i]);

		if (whole ? strcmp (text, needle) == 0
		          : strstr (text, needle) != NULL)
			found = labels->pdata[i];
	}
	g_ptr_array_unref (labels);
	return found;
}

static GtkWidget *
find_named (GtkWidget *widget, const gchar *name)
{
	GtkWidget *found = NULL;

	if (g_strcmp0 (gtk_widget_get_name (widget), name) == 0)
		return widget;
	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));

		for (GList *l = children; l != NULL && found == NULL; l = l->next)
			found = find_named (GTK_WIDGET (l->data), name);
		g_list_free (children);
	}
	return found;
}

static const gchar *
named_text (const gchar *name)
{
	GtkWidget *w = find_named (fs_drawer_widget (), name);

	return w != NULL && GTK_IS_LABEL (w) ? gtk_label_get_text (GTK_LABEL (w))
	                                     : "(none)";
}

/* Lay the page out and paint it into an offscreen window, so the draw
 * handlers (the graph, the bars, the sparklines) really run. */
static GtkWidget *
offscreen_with (GtkWidget *page)
{
	GtkWidget *window = gtk_offscreen_window_new ();

	gtk_window_set_default_size (GTK_WINDOW (window), 1024, 900);
	gtk_container_add (GTK_CONTAINER (window), page);
	gtk_widget_show_all (window);   /* as fs-app.c does */
	return window;
}

static gboolean
draw_offscreen (GtkWidget *window)
{
	gint64 until = g_get_monotonic_time () + G_USEC_PER_SEC / 4;

	gtk_widget_queue_draw (window);
	while (g_get_monotonic_time () < until) {
		while (gtk_events_pending ())
			gtk_main_iteration ();
		g_usleep (10000);
	}
	if (g_getenv ("OVERVIEW_SMOKE_PNG") != NULL)
		cairo_surface_write_to_png (
			gtk_offscreen_window_get_surface (
				GTK_OFFSCREEN_WINDOW (window)),
			g_getenv ("OVERVIEW_SMOKE_PNG"));
	return gtk_offscreen_window_get_surface (
		GTK_OFFSCREEN_WINDOW (window)) != NULL;
}

/* One reading of the counters, `seconds' after the last: eth0 received
 * and sent this much more. */
static void
reading (gdouble seconds, guint64 received, guint64 sent)
{
	fake_time += (gint64) (seconds * G_USEC_PER_SEC);
	fake_rx += received;
	fake_tx += sent;
	/* The bridge is always busy; none of it may reach the graph. */
	fake_bridge += 1 << 30;
	fs_statusview_refresh ();
}

/* The newest point of the graph. */
static gboolean
newest_is (guint count, guint64 received, guint64 sent)
{
	guint64 *rx = NULL, *tx = NULL;
	guint n = fs_statusview_traffic_points (&rx, &tx);
	gboolean ok = n == count && n > 0 && rx[n - 1] == received &&
	              tx[n - 1] == sent;

	if (!ok)
		printf ("      (%u points, newest %" G_GUINT64_FORMAT " / %"
		        G_GUINT64_FORMAT ")\n", n, n > 0 ? rx[n - 1] : 0,
		        n > 0 ? tx[n - 1] : 0);
	g_free (rx);
	g_free (tx);
	return ok;
}

/* 7. The page of the checks above, whose backend has no adapter
 *    counters and cannot list connections: no card may invent data. */
static void
check_no_live_data (GtkWidget *page)
{
	GtkWidget *window = offscreen_with (page);
	GtkWidget *label;
	gchar **busy;

	label = find_label (page, "This computer's adapter counters are not "
	                    "available.", TRUE);
	CHECK (label != NULL && shown (label, page),
	       "no adapter counters: the Traffic card says so in a sentence");
	CHECK (fs_statusview_traffic_points (NULL, NULL) == 0,
	       "and its graph has no point");
	label = find_label (page, "Received", TRUE);
	CHECK (label != NULL && !shown (label, page),
	       "and its legend, which would show two rates, is not shown");

	label = find_label (page, "Busiest programs", TRUE);
	CHECK (label != NULL && !shown (label, page),
	       "no connection list: the Busiest programs card is left out, "
	       "even after show_all");
	busy = fs_statusview_busiest_programs ();
	CHECK (g_strv_length (busy) == 0, "and nothing is ranked");
	g_strfreev (busy);

	label = find_label (page, "Latest blocks", TRUE);
	CHECK (label != NULL && shown (label, page) &&
	       find_label (page, "Nothing has been blocked since StockFW "
	                   "opened.", TRUE) != NULL,
	       "Latest blocks stays, with its empty sentence");

	CHECK (draw_offscreen (window),
	       "the page draws with every live slot missing");

	/* The page goes, and with it its timers and its pointers. */
	gtk_widget_destroy (window);
	fs_statusview_set_state (FS_FW_RUNNING);
	fs_statusview_refresh ();
	CHECK (TRUE, "a state change and a refresh after the page is "
	       "destroyed touch nothing");
}

/* 8. A second page, on a backend with counters and a connection list
 *    that the test sets, and a clock the test moves. */
static void
check_live_cards (void)
{
	static const gchar *const ranked[] = {
		"firefox\t5", "Unknown program\t4", "ssh\t2", "curl\t1",
		"nginx\t1"
	};
	GtkWidget *window, *page, *label, *view = NULL, *body, *button = NULL;
	GPtrArray *found = g_ptr_array_new ();
	const gchar *on_row[5] = { "(none)", "(none)", "(none)", "(none)",
	                           "(none)" };
	GtkTreePath *path;
	guint64 *rx = NULL, *tx = NULL;
	gchar **busy;
	gboolean same, quiet = TRUE;
	guint n, shown_names = 0;

	current = &fake_live;
	fs_statusview_set_clock (fake_clock);

	page = fs_statusview_page ();
	window = offscreen_with (page);
	fs_statusview_set_state (FS_FW_RUNNING);

	/* --- Traffic --- */
	CHECK (fs_statusview_traffic_points (NULL, NULL) == 0,
	       "the first reading gives no point: nothing to measure from yet");
	label = find_label (page, "Received", TRUE);
	CHECK (label != NULL && shown (label, page),
	       "with counters, the legend shows");

	reading (2.0, 4096, 1024);
	CHECK (newest_is (1, 2048, 512),
	       "4096 and 1024 bytes over two seconds are 2048 and 512 B/s, "
	       "and the virtual bridge's traffic is not in them");
	CHECK (find_label (page, "2.0 KiB/s", TRUE) != NULL &&
	       find_label (page, "512 B/s", TRUE) != NULL,
	       "the legend says the two rates in numbers");
	CHECK (find_label (page, "whether or not the firewall filtered it",
	                   FALSE) != NULL,
	       "the card says it is all adapter traffic, not only the "
	       "firewall's");
	CHECK (fs_statusview_traffic_scale () == 2 * 1024,
	       "a peak of 2048 B/s fits a 2 KiB/s scale exactly (got %"
	       G_GUINT64_FORMAT ")", fs_statusview_traffic_scale ());

	reading (2.0, 2 * 3000, 0);
	CHECK (fs_statusview_traffic_scale () == 5 * 1024,
	       "3000 B/s: the next round step up, 5 KiB/s (got %"
	       G_GUINT64_FORMAT ")", fs_statusview_traffic_scale ());
	reading (2.0, 2 * 300 * 1024, 0);
	CHECK (fs_statusview_traffic_scale () == 500 * 1024,
	       "300 KiB/s: 500 KiB/s (got %" G_GUINT64_FORMAT ")",
	       fs_statusview_traffic_scale ());
	reading (2.0, 0, 2 * 600 * 1024);
	CHECK (newest_is (4, 0, 600 * 1024) &&
	       fs_statusview_traffic_scale () == 1024 * 1024,
	       "600 KiB/s sent: the scale follows the higher of the two "
	       "series, 1 MiB/s (got %" G_GUINT64_FORMAT ")",
	       fs_statusview_traffic_scale ());

	/* A reading between two refreshes (the adapters card's "Show them"
	 * asks for one). */
	reading (0.5, 1000, 0);
	CHECK (fs_statusview_traffic_points (NULL, NULL) == 4,
	       "a reading half a second after the last adds no point");
	reading (1.5, 1048, 0);
	CHECK (newest_is (5, 1024, 0),
	       "and its bytes are in the next one: 2048 bytes over the two "
	       "seconds, 1024 B/s");

	/* A counter that goes backwards is an adapter reset, not traffic. */
	fake_rx = 10;
	reading (2.0, 0, 0);
	CHECK (newest_is (6, 0, 0), "a counter that went backwards counts as "
	       "no traffic, not as a huge rate");

	for (gint i = 0; i < 70; i++)
		reading (2.0, 0, 0);
	n = fs_statusview_traffic_points (&rx, &tx);
	for (guint i = 0; i < n; i++)
		quiet = quiet && rx[i] == 0 && tx[i] == 0;
	CHECK (n == 60 && quiet,
	       "the graph keeps two minutes (60 points) and the older ones "
	       "leave it (got %u)", n);
	CHECK (fs_statusview_traffic_scale () == 1024,
	       "an idle graph keeps a 1 KiB/s scale, not a zero one");
	g_free (rx);
	g_free (tx);
	CHECK (draw_offscreen (window), "the full graph draws");

	fake_no_counters = TRUE;
	fs_statusview_refresh ();
	CHECK (fs_statusview_traffic_points (NULL, NULL) == 0 &&
	       find_label (page, "This computer's adapter counters are not "
	                   "available.", TRUE) != NULL,
	       "counters that go away empty the graph and say so; the old "
	       "line is not left standing");
	fake_no_counters = FALSE;
	fs_statusview_refresh ();
	reading (2.0, 2048, 2048);
	CHECK (newest_is (1, 1024, 1024), "and it starts again when they "
	       "come back");

	/* --- Busiest programs --- */
	busy = fs_statusview_busiest_programs ();
	same = g_strv_length (busy) == G_N_ELEMENTS (ranked);
	for (guint i = 0; same && i < G_N_ELEMENTS (ranked); i++)
		same = strcmp (busy[i], ranked[i]) == 0;
	{
		gchar *got = g_strjoinv (", ", busy);

		g_strdelimit (got, "\t", ' ');
		CHECK (same,
		       "the five busiest, by open connections; \"?\" and no "
		       "name are one Unknown program; a tie goes by name (got "
		       "%s)", got);
		g_free (got);
	}
	for (guint i = 0; busy[i] != NULL; i++)
		CHECK (!g_str_has_prefix (busy[i], "postgres"),
		       "row %u: connections between two local programs are not "
		       "counted", i);
	g_strfreev (busy);

	/* The card's rows, top to bottom. */
	collect (page, GTK_TYPE_LABEL, "busy-name", found);
	for (guint i = 0; i < found->len; i++) {
		GtkWidget *name = found->pdata[i];

		if (shown (name, page))
			shown_names++;
		if (i < 5)
			on_row[i] = gtk_label_get_text (GTK_LABEL (name));
	}
	CHECK (found->len == 5 && shown_names == 5 &&
	       g_strcmp0 (on_row[0], "firefox") == 0 &&
	       g_strcmp0 (on_row[1], "Unknown program") == 0 &&
	       g_strcmp0 (on_row[4], "nginx") == 0,
	       "the card shows the five, busiest on the top row (%u shown; "
	       "\"%s\", \"%s\" ... \"%s\")", shown_names, on_row[0],
	       on_row[1], on_row[4]);
	CHECK (find_label (page, "not by data volume", FALSE) != NULL,
	       "and says it counts connections, not data");

	/* --- A connection's details --- */
	g_ptr_array_set_size (found, 0);
	collect (page, GTK_TYPE_TREE_VIEW, NULL, found);
	view = found->len > 0 ? found->pdata[0] : NULL;
	CHECK (view != NULL, "the page has the connections list");
	fs_drawer_close ();
	if (view != NULL) {
		path = gtk_tree_path_new_from_string ("0");
		gtk_tree_view_row_activated (GTK_TREE_VIEW (view), path,
			gtk_tree_view_get_column (GTK_TREE_VIEW (view), 1));
		gtk_tree_path_free (path);
	}
	body = find_named (fs_drawer_widget (), "fs-drawer-body");
	CHECK (fs_drawer_is_open (),
	       "activating a connection (Enter, double click) opens the "
	       "drawer");
	CHECK (strcmp (named_text ("fs-drawer-title"), "firefox") == 0 &&
	       strcmp (named_text ("fs-drawer-subtitle"),
	               "93.184.216.34, port 443") == 0,
	       "titled with the program, then the remote end (got \"%s\" / "
	       "\"%s\")", named_text ("fs-drawer-title"),
	       named_text ("fs-drawer-subtitle"));
	CHECK (find_label (body, "192.168.1.20, port 50001", TRUE) != NULL &&
	       find_label (body, "ESTABLISHED", TRUE) != NULL &&
	       find_label (body, "HTTPS", TRUE) != NULL &&
	       find_label (body, "Outbound", TRUE) != NULL,
	       "with this computer's end, the state, the service and the "
	       "direction");
	CHECK (find_label (body, "Open connections of this program", TRUE)
	       != NULL &&
	       find_label (body, "5 to other computers", TRUE) != NULL,
	       "and how many connections the program holds (5)");

	if (view != NULL) {
		path = gtk_tree_path_new_from_string ("1");
		gtk_tree_view_row_activated (GTK_TREE_VIEW (view), path,
			gtk_tree_view_get_column (GTK_TREE_VIEW (view), 1));
		gtk_tree_path_free (path);
	}
	body = find_named (fs_drawer_widget (), "fs-drawer-body");
	CHECK (fs_drawer_is_open () &&
	       strcmp (named_text ("fs-drawer-title"), "Unknown program") == 0 &&
	       find_label (body, "4 to other computers", TRUE) != NULL,
	       "a connection with no known owner: Unknown program, counted "
	       "with the other unnamed ones (4)");

	/* With the local connections on show ("Show them"), one of them:
	 * the fourth row is postgres, which has no other kind. */
	g_ptr_array_set_size (found, 0);
	/* The list's own card (the adapters card has a "Show them" too):
	 * the view sits in a scrolled window, and that in the card. */
	collect (view != NULL
	         ? gtk_widget_get_parent (gtk_widget_get_parent (view)) : page,
	         GTK_TYPE_BUTTON, "fs-link", found);
	for (guint i = 0; i < found->len; i++)
		if (g_strcmp0 (gtk_button_get_label (found->pdata[i]),
		               "Show them") == 0 && shown (found->pdata[i], page))
			button = found->pdata[i];
	CHECK (button != NULL, "the list offers to show the local connections");
	if (button != NULL && view != NULL) {
		gtk_button_clicked (GTK_BUTTON (button));
		path = gtk_tree_path_new_from_string ("3");
		gtk_tree_view_row_activated (GTK_TREE_VIEW (view), path,
			gtk_tree_view_get_column (GTK_TREE_VIEW (view), 1));
		gtk_tree_path_free (path);
		gtk_button_clicked (GTK_BUTTON (button));
	}
	body = find_named (fs_drawer_widget (), "fs-drawer-body");
	CHECK (strcmp (named_text ("fs-drawer-title"), "postgres") == 0 &&
	       find_label (body, "0 to other computers, and 6 between "
	                   "programs on this computer", TRUE) != NULL,
	       "a local connection: its program's count says which are local "
	       "(got \"%s\")", named_text ("fs-drawer-title"));
	button = NULL;

	g_ptr_array_set_size (found, 0);
	collect (fs_drawer_widget (), GTK_TYPE_BUTTON, NULL, found);
	for (guint i = 0; i < found->len; i++)
		if (g_strcmp0 (gtk_button_get_label (found->pdata[i]),
		               "Show in Events") == 0)
			button = found->pdata[i];
	CHECK (button != NULL, "the drawer offers Show in Events");
	if (button != NULL)
		gtk_button_clicked (GTK_BUTTON (button));
	fs_drawer_close ();

	/* --- Nothing open --- */
	fake_no_conns = TRUE;
	fs_statusview_refresh ();
	busy = fs_statusview_busiest_programs ();
	label = find_label (page, "No open connections right now.", TRUE);
	CHECK (g_strv_length (busy) == 0 && label != NULL &&
	       shown (label, page) &&
	       shown (find_label (page, "Busiest programs", TRUE), page),
	       "no open connection: the card stays and says so");
	g_strfreev (busy);
	fake_no_conns = FALSE;
	fs_statusview_refresh ();

	CHECK (draw_offscreen (window), "the page draws with its live cards");

	g_ptr_array_unref (found);
	gtk_widget_destroy (window);
	fs_statusview_set_clock (NULL);
}

int
main (int argc, char **argv)
{
	GtkWidget *page;
	GtkWidget *hero;
	FsVerdict level;
	gchar *m;

	gtk_init (&argc, &argv);
	g_log_set_writer_func (count_warnings, NULL, NULL);

	page = fs_statusview_page ();
	gtk_widget_show_all (page);   /* as fs-app.c does */
	fs_statusview_set_state (FS_FW_RUNNING);
	fs_statusview_refresh ();
	hero = find_by_class (page, "hero");

	/* 1. Home, Private, everything on. */
	CHECK (strcmp (text_of (page, "page-subtitle"),
	               "This computer \xc2\xb7 HomeNet (Wi-Fi) \xc2\xb7 "
	               "Private network") == 0,
	       "subtitle names the network, the medium and its kind (got \"%s\")",
	       text_of (page, "page-subtitle"));
	m = marks (page);
	CHECK (strcmp (m, "-P-") == 0,
	       "only Private is marked In use, after show_all (got %s)", m);
	g_free (m);
	fs_statusview_verdict (&level);
	CHECK (level == FS_VERDICT_OK, "all on: the verdict is OK");
	CHECK (strstr (text_of (page, "hero-body"), "Windows Defender Firewall "
	               "is applying the Private profile.") != NULL,
	       "the verdict names the profile doing the protecting (got \"%s\")",
	       text_of (page, "hero-body"));

	/* 2. Private switched off behind the app's back (Windows Security,
	 *    Group Policy): the service still runs, this network has no
	 *    firewall. */
	fake_on[FS_PROFILE_PRIVATE] = FALSE;
	poll ();
	fs_statusview_verdict (&level);
	CHECK (level == FS_VERDICT_BAD &&
	       gtk_style_context_has_class (gtk_widget_get_style_context (hero),
	                                    "level-bad"),
	       "the profile in use off: the verdict is red");
	CHECK (strcmp (text_of (page, "hero-title"),
	               "This network is not protected") == 0,
	       "and says so (got \"%s\")", text_of (page, "hero-title"));
	CHECK (strstr (text_of (page, "hero-body"), "The Private profile of "
	               "Windows Defender Firewall is off, so traffic on HomeNet "
	               "(Wi-Fi) is not filtered.") != NULL,
	       "and why, naming the network (got \"%s\")",
	       text_of (page, "hero-body"));
	CHECK (strcmp (fs_statusview_verdict (NULL), "Not protected") == 0,
	       "the sidebar's word follows (got %s)", fs_statusview_verdict (NULL));

	/* 3. The fix is the switch on the card. */
	{
		GtkWidget *sw = switch_for (page, FS_PROFILE_PRIVATE);

		CHECK (sw != NULL && !gtk_switch_get_active (GTK_SWITCH (sw)),
		       "the Private switch shows off");
		if (sw != NULL)
			gtk_switch_set_active (GTK_SWITCH (sw), TRUE);
		fs_statusview_verdict (&level);
		CHECK (fake_set_calls == 1 && fake_on[FS_PROFILE_PRIVATE] &&
		       level == FS_VERDICT_OK,
		       "switching it on asks the backend once and the verdict "
		       "is OK at once, no poll needed (calls %u)", fake_set_calls);
	}

	/* 4. Public off, but only a virtual switch is on Public: amber. */
	fake_hyperv = TRUE;
	fake_on[FS_PROFILE_PUBLIC] = FALSE;
	poll ();
	fs_statusview_verdict (&level);
	m = marks (page);
	CHECK (strcmp (m, "-PU") == 0, "Private and Public both In use (got %s)",
	       m);
	g_free (m);
	CHECK (level == FS_VERDICT_WARN &&
	       strcmp (text_of (page, "hero-title"),
	               "Some networks are not protected") == 0,
	       "a secondary network's profile off is amber, not red (got \"%s\")",
	       text_of (page, "hero-title"));
	CHECK (strstr (text_of (page, "hero-body"), "Unidentified network "
	               "(Virtual)") != NULL &&
	       strstr (text_of (page, "hero-body"), "HomeNet") == NULL,
	       "and names the virtual switch, not the Wi-Fi (got \"%s\")",
	       text_of (page, "hero-body"));
	CHECK (strstr (text_of (page, "page-subtitle"), "HomeNet (Wi-Fi)") != NULL,
	       "the subtitle still names the internet-facing network");

	/* 5. To the cafe: Public network, Public profile off.  Red. */
	fake_hyperv = FALSE;
	fake_network = "CafeNet";
	fake_category = FS_PROFILE_PUBLIC;
	poll ();
	fs_statusview_verdict (&level);
	CHECK (strstr (text_of (page, "page-subtitle"), "CafeNet (Wi-Fi) \xc2\xb7 "
	               "Public network") != NULL,
	       "moving networks is picked up (got \"%s\")",
	       text_of (page, "page-subtitle"));
	m = marks (page);
	CHECK (strcmp (m, "--U") == 0, "now only Public is In use (got %s)", m);
	g_free (m);
	CHECK (level == FS_VERDICT_BAD, "on the cafe network with Public off: red");

	/* 6. A stopped firewall is judged on its own terms. */
	fs_statusview_set_state (FS_FW_STOPPED);
	CHECK (strcmp (text_of (page, "hero-title"),
	               "This computer is not protected") == 0,
	       "stopped: the stopped verdict, not the profile one");
	CHECK (strcmp (text_of (page, "state-word"), "Not protected") == 0,
	       "and the board's large word follows (got \"%s\")",
	       text_of (page, "state-word"));

	/* 7, 8. The status board's live cards (2.0.0). */
	check_no_live_data (page);
	check_live_cards ();

	CHECK (warnings == 0,
	       "no GTK warning or critical in all of the above (%u)", warnings);

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED", failures);
	return failures ? 1 : 0;
}
