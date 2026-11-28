/* The Topology page: this computer's open connections and the addresses
 * the firewall blocked in the last ten minutes, drawn as a diagram
 * whose lines move.
 *
 * The page reads the backend's list_connections and is told of every
 * event by the Events page.  This test supplies fs_backend() itself
 * with a fake whose list it controls, builds the real page in an
 * offscreen window, and checks what a user would see:
 *
 *   - programs are ranked by their open connections; five get a node
 *     each and the rest are merged into "Other programs" (a single
 *     leftover keeps its own name); a "?" owner reads "Unknown
 *     program"; connections between two loopback ends are not drawn;
 *   - remote addresses are sorted into "Local network" and "Internet";
 *   - a blocked event adds a blocked node and a blocked line, a repeat
 *     raises its count instead of adding a node, an allowed event adds
 *     nothing, the diagram draws the newest four, and a block is
 *     forgotten ten minutes after the last one from its address;
 *   - a backend that cannot list connections gives the empty state, and
 *     so does an empty list, with a different sentence;
 *   - the nodes never overlap and stay inside the diagram, at the
 *     smallest page and at a large one;
 *   - the lines are moved by a frame-clock callback only while the
 *     diagram is on screen and GTK animations are on, and the backend
 *     is polled only while the page is on screen;
 *   - a click or Enter on a node opens its details in the drawer, and
 *     the arrow keys move between nodes;
 *   - destroying the page while it animates leaves nothing running, and
 *     nothing above raises a GTK warning.
 *
 * Teeth: make anim_sync ignore area_mapped (or the animation setting)
 * and the "no tick" checks fail; make expire_blocks keep everything and
 * the expiry checks fail.
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-backend.h"
#include "core/fs-netparse.h"
#include "core/fs-types.h"
#include "ui/fs-drawer.h"
#include "ui/fs-topology.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	printf ((cond) ? "ok:   " : "FAIL: ");                  \
	printf (__VA_ARGS__);                                   \
	printf ("\n");                                          \
	if (!(cond))                                            \
		failures++;                                     \
} while (0)

#define MINUTE ((gint64) 60 * G_USEC_PER_SEC)

/* ------------------------------------------------------- fake backend */

typedef struct
{
	const gchar *program;
	const gchar *local;
	const gchar *remote;
	const gchar *port;
	const gchar *service;
	const gchar *direction;
} FakeConn;

/* Eight programs, sixteen connections that leave this computer (three
 * to the local network) and one that does not. */
static const FakeConn busy[] = {
	{ "firefox", "192.168.1.50", "93.184.216.34",  "443", "HTTPS",   "Outbound" },
	{ "firefox", "192.168.1.50", "151.101.1.69",   "443", "HTTPS",   "Outbound" },
	{ "firefox", "192.168.1.50", "2606:4700::6810:85e5", "443", "HTTPS", "Outbound" },
	{ "firefox", "192.168.1.50", "142.250.74.14",  "443", "HTTPS",   "Outbound" },
	{ "code",    "192.168.1.50", "13.107.42.18",   "443", "HTTPS",   "Outbound" },
	{ "code",    "192.168.1.50", "140.82.112.21",  "443", "HTTPS",   "Outbound" },
	{ "code",    "192.168.1.50", "20.42.65.92",    "443", "HTTPS",   "Outbound" },
	{ "?",       "192.168.1.50", "34.107.243.93",  "443", "HTTPS",   "Outbound" },
	{ "?",       "192.168.1.50", "52.84.12.7",     "8443", "Unknown", "Outbound" },
	{ "dnsmasq", "192.168.1.50", "192.168.1.1",    "53",  "DNS",     "Outbound" },
	{ "dnsmasq", "192.168.1.50", "192.168.1.1",    "53",  "DNS",     "Outbound" },
	{ "slack",   "192.168.1.50", "3.120.31.4",     "443", "HTTPS",   "Outbound" },
	{ "slack",   "192.168.1.50", "3.120.31.5",     "443", "HTTPS",   "Outbound" },
	{ "curl",    "192.168.1.50", "185.199.108.153", "443", "HTTPS",  "Outbound" },
	{ "sshd",    "192.168.1.50", "192.168.1.20",   "22",  "SSH",     "Inbound"  },
	{ "zoom",    "192.168.1.50", "170.114.52.2",   "443", "HTTPS",   "Outbound" },
	{ "postgres", "127.0.0.1",   "127.0.0.1",      "5432", "PostgreSQL", "Inbound" },
};

/* Six programs: the sixth is named, not merged. */
static const FakeConn six[] = {
	{ "a", "10.0.0.5", "8.8.8.8", "443", "HTTPS", "Outbound" },
	{ "a", "10.0.0.5", "8.8.4.4", "443", "HTTPS", "Outbound" },
	{ "b", "10.0.0.5", "1.1.1.1", "443", "HTTPS", "Outbound" },
	{ "c", "10.0.0.5", "1.0.0.1", "443", "HTTPS", "Outbound" },
	{ "d", "10.0.0.5", "9.9.9.9", "443", "HTTPS", "Outbound" },
	{ "e", "10.0.0.5", "9.9.9.10", "443", "HTTPS", "Outbound" },
	{ "C:\\Program Files\\Tool\\tool.exe", "10.0.0.5", "4.4.4.4", "443",
	  "HTTPS", "Outbound" },
};

/* One program holding more connections than the drawer lists. */
#define MANY 25

static const FakeConn *fake_table = busy;
static guint           fake_rows = G_N_ELEMENTS (busy);
static gboolean        fake_many = FALSE;
static guint           fake_calls = 0;

static FsConnection *
make_conn (const FakeConn *f)
{
	FsConnection *c = g_new0 (FsConnection, 1);

	c->program = g_strdup (f->program);
	c->source = g_strdup (f->local);
	c->destination = g_strdup (f->remote);
	c->port = g_strdup (f->port);
	c->protocol = g_strdup ("TCP");
	c->service = g_strdup (f->service);
	c->direction = g_strdup (f->direction);
	return c;
}

static GList *
fake_list (void)
{
	GList *list = NULL;

	fake_calls++;
	if (fake_many) {
		for (guint i = 0; i < MANY; i++) {
			FakeConn f = { "rsync", "10.0.0.5", NULL, "873", "rsync",
			               "Outbound" };
			gchar *remote = g_strdup_printf ("10.0.1.%u", i + 1);

			f.remote = remote;
			list = g_list_prepend (list, make_conn (&f));
			g_free (remote);
		}
		return g_list_reverse (list);
	}

	for (guint i = 0; i < fake_rows; i++)
		list = g_list_prepend (list, make_conn (&fake_table[i]));
	return g_list_reverse (list);
}

static gboolean
fake_available (void)
{
	return TRUE;
}

static FsBackend fake_backend = {
	.name             = "fake",
	.display_name     = "Fake firewall",
	.available        = fake_available,
	.list_connections = fake_list,
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

/* ------------------------------------------------------------ helpers */

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

static void
spin (guint ms)
{
	gint64 until = g_get_monotonic_time () + (gint64) ms * 1000;

	while (g_get_monotonic_time () < until) {
		while (gtk_events_pending ())
			gtk_main_iteration ();
		g_usleep (5000);
	}
}

/* Lets the offscreen window lay out and paint, then takes its surface:
 * the page's own draw handlers have run by then, as on screen.
 * TOPOLOGY_SMOKE_PNG=<prefix> keeps each picture as <prefix>-<tag>.png. */
static gboolean
draw_offscreen (GtkWidget *window, const gchar *tag)
{
	cairo_surface_t *surface;

	gtk_widget_queue_draw (window);
	spin (250);

	surface = gtk_offscreen_window_get_surface (GTK_OFFSCREEN_WINDOW (window));
	if (surface == NULL)
		return FALSE;

	if (g_getenv ("TOPOLOGY_SMOKE_PNG") != NULL) {
		gchar *path = g_strdup_printf ("%s-%s.png",
		                               g_getenv ("TOPOLOGY_SMOKE_PNG"), tag);

		cairo_surface_write_to_png (surface, path);
		g_free (path);
	}
	return TRUE;
}

static GtkWidget *
find_by_name (GtkWidget *widget, const gchar *name)
{
	if (g_strcmp0 (gtk_widget_get_name (widget), name) == 0)
		return widget;
	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));
		GtkWidget *found = NULL;

		for (GList *l = children; l != NULL && found == NULL; l = l->next)
			found = find_by_name (GTK_WIDGET (l->data), name);
		g_list_free (children);
		return found;
	}
	return NULL;
}

/* TRUE when some label under `widget' reads exactly `text'. */
static gboolean
has_label (GtkWidget *widget, const gchar *text)
{
	gboolean found = FALSE;

	if (GTK_IS_LABEL (widget))
		return g_strcmp0 (gtk_label_get_text (GTK_LABEL (widget)), text) == 0;
	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));

		for (GList *l = children; l != NULL && !found; l = l->next)
			found = has_label (GTK_WIDGET (l->data), text);
		g_list_free (children);
	}
	return found;
}

static const gchar *
drawer_title (void)
{
	GtkWidget *label = find_by_name (fs_drawer_widget (), "fs-drawer-title");

	return label != NULL ? gtk_label_get_text (GTK_LABEL (label)) : "(none)";
}

static void
set_animations (gboolean on)
{
	g_object_set (gtk_settings_get_default (), "gtk-enable-animations", on,
	              NULL);
}

static void
block (const gchar *remote, gboolean inbound, const gchar *port,
       const gchar *service, gint64 at)
{
	FsHit hit = { 0 };
	gchar *marked = g_strconcat (service, FS_HIT_BLOCKED_MARKER, NULL);

	hit.direction = (gchar *) (inbound ? "In" : "Out");
	hit.source = (gchar *) (inbound ? remote : "192.168.1.50");
	hit.destination = (gchar *) (inbound ? "192.168.1.50" : remote);
	hit.port = (gchar *) port;
	hit.protocol = (gchar *) "TCP";
	hit.service = marked;
	fs_topology_note_hit_at (&hit, at);
	g_free (marked);
}

/* No two nodes overlap and every node lies inside the diagram. */
static gboolean
nodes_apart (GtkWidget *area)
{
	guint n = fs_topology_node_count ();
	gint w = gtk_widget_get_allocated_width (area);
	gint h = gtk_widget_get_allocated_height (area);

	for (guint i = 0; i < n; i++) {
		GdkRectangle a;

		fs_topology_node_rect (i, &a);
		if (a.x < 0 || a.y < 0 || a.x + a.width > w || a.y + a.height > h)
			return FALSE;
		for (guint k = i + 1; k < n; k++) {
			GdkRectangle b;

			fs_topology_node_rect (k, &b);
			if (gdk_rectangle_intersect (&a, &b, NULL))
				return FALSE;
		}
	}
	return TRUE;
}

static void
press_key (GtkWidget *area, guint keyval)
{
	GdkEvent *event = gdk_event_new (GDK_KEY_PRESS);

	event->key.window = g_object_ref (gtk_widget_get_window (area));
	event->key.keyval = keyval;
	event->key.send_event = TRUE;
	gtk_widget_event (area, event);
	gdk_event_free (event);
}

static void
click (GtkWidget *area, gint x, gint y)
{
	GdkEvent *event = gdk_event_new (GDK_BUTTON_PRESS);
	GdkDevice *pointer = gdk_seat_get_pointer (
		gdk_display_get_default_seat (gdk_display_get_default ()));

	event->button.window = g_object_ref (gtk_widget_get_window (area));
	event->button.button = 1;
	event->button.x = x;
	event->button.y = y;
	event->button.send_event = TRUE;
	if (pointer != NULL)
		gdk_event_set_device (event, pointer);
	gtk_widget_event (area, event);
	gdk_event_free (event);
}

static GtkWidget *
build (gint width, gint height)
{
	GtkWidget *window = gtk_offscreen_window_new ();

	gtk_window_set_default_size (GTK_WINDOW (window), width, height);
	gtk_container_add (GTK_CONTAINER (window), fs_topology_page ());
	gtk_widget_show_all (window);   /* as fs-app.c does */
	spin (100);
	return window;
}

int
main (int argc, char **argv)
{
	static const struct { const gchar *address; gboolean local; } where[] = {
		{ "10.1.2.3",            TRUE  },   /* RFC 1918             */
		{ "172.16.0.9",          TRUE  },
		{ "172.31.255.254",      TRUE  },
		{ "192.168.1.1",         TRUE  },
		{ "127.0.0.1",           TRUE  },   /* loopback             */
		{ "169.254.10.20",       TRUE  },   /* link-local           */
		{ "100.64.0.1",          TRUE  },   /* CGNAT                */
		{ "100.127.255.254",     TRUE  },
		{ "::1",                 TRUE  },
		{ "fe80::1",             TRUE  },   /* link-local           */
		{ "fe80::1%eth0",        TRUE  },   /* with its zone        */
		{ "[fe80::1]",           TRUE  },
		{ "fd12:3456:789a::1",   TRUE  },   /* unique-local         */
		{ "::ffff:192.168.1.5",  TRUE  },   /* IPv4-mapped          */
		{ "8.8.8.8",             FALSE },
		{ "172.32.0.1",          FALSE },   /* just past 172.16/12  */
		{ "100.128.0.1",         FALSE },   /* just past CGNAT      */
		{ "192.169.0.1",         FALSE },
		{ "2606:4700:4700::1111", FALSE },
		{ "::ffff:8.8.8.8",      FALSE },
		{ "example.org",         FALSE },   /* not an address       */
		{ "",                    FALSE },
	};
	GtkWidget *window, *page, *area, *caption;
	GdkRectangle rect;
	gint64 t0;
	gint other, unknown, lan, net, blocked;
	guint calls;

	gtk_init (&argc, &argv);
	g_log_set_writer_func (count_warnings, NULL, NULL);
	set_animations (TRUE);

	/* ---- local network or internet ---- */
	for (guint i = 0; i < G_N_ELEMENTS (where); i++)
		CHECK (fs_topology_address_is_local (where[i].address) ==
		       where[i].local,
		       "\"%s\" is %s", where[i].address,
		       where[i].local ? "on the local side" : "not local");
	CHECK (!fs_topology_address_is_local (NULL), "NULL is not local");

	/* ---- the smallest page, a busy computer ---- */
	window = build (900, 500);
	page = gtk_bin_get_child (GTK_BIN (window));
	area = find_by_name (page, "topology-diagram");
	caption = find_by_name (page, "topology-caption");
	CHECK (area != NULL && caption != NULL,
	       "the page carries a diagram and a caption");
	CHECK (fake_calls >= 1 && fs_topology_polling (),
	       "showing the page asks the backend at once and starts polling");

	CHECK (g_strcmp0 (fs_topology_node_title (0), "This computer") == 0 &&
	       fs_topology_node_connections (0) == 16,
	       "node 0 is This computer with the 16 connections that leave it "
	       "(got \"%s\", %u)", fs_topology_node_title (0),
	       fs_topology_node_connections (0));
	CHECK (g_strcmp0 (fs_topology_node_detail (0), g_get_host_name ()) == 0,
	       "and it carries this computer's name");
	CHECK (g_strcmp0 (fs_topology_node_title (1), "firefox") == 0 &&
	       fs_topology_node_connections (1) == 4 &&
	       g_strcmp0 (fs_topology_node_title (2), "code") == 0 &&
	       fs_topology_node_connections (2) == 3,
	       "programs are ranked by open connections (firefox 4, code 3)");
	unknown = fs_topology_find_node ("Unknown program");
	CHECK (unknown == 3 && fs_topology_node_connections (3) == 2 &&
	       fs_topology_find_node ("?") < 0,
	       "the \"?\" owner reads Unknown program, with its two connections");
	other = fs_topology_find_node ("Other programs");
	CHECK (other == 6 && fs_topology_node_connections (6) == 3 &&
	       g_strcmp0 (fs_topology_node_detail (6),
	                  "3 connections from 3 programs") == 0,
	       "past five, the rest are merged into Other programs (got node "
	       "%d, \"%s\")", other,
	       other >= 0 ? fs_topology_node_detail ((guint) other) : "");
	CHECK (fs_topology_find_node ("curl") < 0 &&
	       fs_topology_find_node ("sshd") < 0 &&
	       fs_topology_find_node ("zoom") < 0,
	       "and have no node of their own");
	CHECK (fs_topology_find_node ("postgres") < 0,
	       "a connection between two loopback ends is not drawn");
	lan = fs_topology_find_node ("Local network");
	net = fs_topology_find_node ("Internet");
	CHECK (lan == 7 && fs_topology_node_connections (7) == 3 &&
	       net == 8 && fs_topology_node_connections (8) == 13,
	       "3 connections go to the local network and 13 to the internet "
	       "(got %u and %u)",
	       lan >= 0 ? fs_topology_node_connections ((guint) lan) : 0,
	       net >= 0 ? fs_topology_node_connections ((guint) net) : 0);
	CHECK (fs_topology_node_count () == 9 && fs_topology_link_count () == 8 &&
	       fs_topology_blocked_link_count () == 0,
	       "9 nodes, 8 lines, none of them blocked (got %u, %u, %u)",
	       fs_topology_node_count (), fs_topology_link_count (),
	       fs_topology_blocked_link_count ());
	CHECK (fs_topology_empty_text () == NULL, "no empty state with connections");
	CHECK (strstr (gtk_label_get_text (GTK_LABEL (caption)),
	               "16 open connections from 8 programs.") != NULL &&
	       strstr (gtk_label_get_text (GTK_LABEL (caption)),
	               "1 more stays inside this computer") != NULL &&
	       strstr (gtk_label_get_text (GTK_LABEL (caption)),
	               "since StockFW opened") != NULL,
	       "the caption counts them, names the one not drawn, and says "
	       "blocks are counted since StockFW opened (got \"%s\")",
	       gtk_label_get_text (GTK_LABEL (caption)));
	CHECK (has_label (page, "Open connections") &&
	       has_label (page, "Blocked at the firewall"),
	       "the legend names the open and the blocked line");
	CHECK (find_by_name (page, "topology-sample-notice") == NULL,
	       "the preview notice is gone");

	/* ---- blocked events ---- */
	t0 = g_get_monotonic_time ();
	block ("203.0.113.7", TRUE, "22", "SSH", t0);
	blocked = fs_topology_find_node ("203.0.113.7");
	CHECK (blocked == 9 && fs_topology_blocked_link_count () == 1 &&
	       fs_topology_link_count () == 9,
	       "a blocked event adds a blocked node and a blocked line");
	CHECK (blocked >= 0 &&
	       g_strcmp0 (fs_topology_node_detail ((guint) blocked),
	                  "SSH \xc2\xb7 blocked 1 time") == 0,
	       "which says what was blocked and how often (got \"%s\")",
	       blocked >= 0 ? fs_topology_node_detail ((guint) blocked) : "");
	block ("203.0.113.7", TRUE, "22", "SSH", t0 + 1);
	block ("203.0.113.7", TRUE, "22", "SSH", t0 + 2);
	blocked = fs_topology_find_node ("203.0.113.7");
	CHECK (fs_topology_blocked_link_count () == 1 &&
	       fs_topology_blocked_count () == 1 && blocked >= 0 &&
	       fs_topology_node_connections ((guint) blocked) == 3 &&
	       g_strcmp0 (fs_topology_node_detail ((guint) blocked),
	                  "SSH \xc2\xb7 blocked 3 times") == 0,
	       "repeats raise its count and add no node (got \"%s\")",
	       blocked >= 0 ? fs_topology_node_detail ((guint) blocked) : "");
	{
		FsHit allowed = { 0 };

		allowed.direction = (gchar *) "Out";
		allowed.source = (gchar *) "192.168.1.50";
		allowed.destination = (gchar *) "198.51.100.77";
		allowed.port = (gchar *) "443";
		allowed.service = (gchar *) "HTTPS";
		fs_topology_note_hit_at (&allowed, t0);
		fs_topology_note_hit_at (NULL, t0);
		CHECK (fs_topology_blocked_count () == 1 &&
		       fs_topology_find_node ("198.51.100.77") < 0,
		       "an allowed event adds nothing");
	}
	block ("198.51.100.9", FALSE, "4444", "", t0 + 5 * MINUTE);
	blocked = fs_topology_find_node ("198.51.100.9");
	CHECK (blocked == 9 && fs_topology_blocked_link_count () == 2 &&
	       g_strcmp0 (fs_topology_node_detail (9),
	                  "port 4444 \xc2\xb7 blocked 1 time") == 0,
	       "an outbound block is filed under the address it was heading "
	       "for, newest first (got node %d)", blocked);
	CHECK (draw_offscreen (window, "900-blocked"),
	       "the page draws at 900x500 with blocked lines");
	CHECK (strstr (gtk_label_get_text (GTK_LABEL (caption)),
	               "2 addresses were blocked in the last 10 minutes") != NULL,
	       "and the caption counts them (got \"%s\")",
	       gtk_label_get_text (GTK_LABEL (caption)));
	CHECK (nodes_apart (area),
	       "at 900x500 no two of the %u nodes overlap and none leaves the "
	       "diagram", fs_topology_node_count ());
	CHECK (gtk_widget_get_allocated_width (window) <= 900,
	       "the page fits the smallest content width (%d px)",
	       gtk_widget_get_allocated_width (window));

	/* ---- the lines move only when they should ---- */
	CHECK (fs_topology_animating (),
	       "on screen with animations on, a frame-clock callback runs");
	set_animations (FALSE);
	CHECK (!fs_topology_animating (),
	       "with GTK animations off there is no callback");
	fs_topology_set_phase (1.5);
	CHECK (fs_topology_get_phase () == 1.5 &&
	       draw_offscreen (window, "900-static"),
	       "the still picture (arrowheads) draws at a given phase");
	CHECK (fs_topology_get_phase () == 1.5,
	       "and nothing moved the lines meanwhile");
	set_animations (TRUE);
	CHECK (fs_topology_animating (), "animations back on: it runs again");
	fs_topology_set_table (TRUE);
	spin (50);
	CHECK (!fs_topology_animating (),
	       "the table view unmaps the diagram: no callback");
	CHECK (fs_topology_table_rows () == 18,
	       "the table lists 16 open connections and 2 blocked addresses "
	       "(got %u rows)", fs_topology_table_rows ());
	CHECK (draw_offscreen (window, "900-table"), "the page draws as a table");
	fs_topology_set_table (FALSE);
	spin (50);
	CHECK (fs_topology_animating (), "back to the diagram: it runs again");
	gtk_widget_hide (window);
	spin (50);
	calls = fake_calls;
	CHECK (!fs_topology_animating () && !fs_topology_polling (),
	       "a page that is not on screen neither animates nor polls");
	block ("192.0.2.200", TRUE, "23", "Telnet", t0 + 5 * MINUTE);
	spin (300);
	CHECK (fake_calls == calls && fs_topology_blocked_count () == 3,
	       "a block noted meanwhile is remembered without asking the "
	       "backend");
	gtk_widget_show (window);
	spin (100);
	CHECK (fs_topology_animating () && fs_topology_polling () &&
	       fake_calls > calls,
	       "shown again: it asks the backend at once and both resume");

	/* ---- details: click, Enter, arrow keys ---- */
	CHECK (!fs_drawer_is_open (), "the drawer starts closed");
	blocked = fs_topology_find_node ("203.0.113.7");
	fs_topology_node_rect ((guint) blocked, &rect);
	click (area, rect.x + rect.width / 2, rect.y + rect.height / 2);
	CHECK (fs_drawer_is_open () && fs_drawer_owner () != NULL &&
	       g_strcmp0 (drawer_title (), "203.0.113.7") == 0,
	       "a click on a blocked node opens its details (title \"%s\")",
	       drawer_title ());
	CHECK (has_label (fs_drawer_widget (), "Show in Events") &&
	       has_label (fs_drawer_widget (), "Blocked inbound SSH") &&
	       has_label (fs_drawer_widget (), "Internet"),
	       "with what was blocked, where it is, and Show in Events");
	fs_drawer_close ();
	click (area, 3, 3);
	CHECK (!fs_drawer_is_open (), "a click on no node opens nothing");
	/* The keyboard starts from the node last clicked, on the right. */
	press_key (area, GDK_KEY_Left);
	press_key (area, GDK_KEY_Return);
	CHECK (fs_drawer_is_open () &&
	       g_strcmp0 (drawer_title (), "This computer") == 0,
	       "Left moves to This computer and Enter opens it (title \"%s\")",
	       drawer_title ());
	press_key (area, GDK_KEY_Left);
	for (guint i = 0; i < 8; i++)
		press_key (area, GDK_KEY_Up);
	press_key (area, GDK_KEY_Return);
	CHECK (g_strcmp0 (drawer_title (), "firefox") == 0 &&
	       has_label (fs_drawer_widget (), "4 open connections"),
	       "Left again, Up and Enter open the busiest program (title "
	       "\"%s\")", drawer_title ());
	CHECK (has_label (fs_drawer_widget (), "93.184.216.34") &&
	       has_label (fs_drawer_widget (), "HTTPS, port 443 \xc2\xb7 Outbound"),
	       "listing its connections: remote, service, port and direction");
	press_key (area, GDK_KEY_Right);
	press_key (area, GDK_KEY_Right);
	for (guint i = 0; i < 8; i++)
		press_key (area, GDK_KEY_Up);
	press_key (area, GDK_KEY_Return);
	CHECK (g_strcmp0 (drawer_title (), "Local network") == 0 &&
	       has_label (fs_drawer_widget (), "dnsmasq") &&
	       has_label (fs_drawer_widget (), "sshd") &&
	       !has_label (fs_drawer_widget (), "firefox"),
	       "Right twice and Enter open Local network with the programs "
	       "talking to it (title \"%s\")", drawer_title ());
	CHECK (fs_topology_activate_node ((guint) other) &&
	       g_strcmp0 (drawer_title (), "Other programs") == 0 &&
	       has_label (fs_drawer_widget (), "185.199.108.153"),
	       "Other programs lists the merged programs' connections");
	CHECK (fs_topology_activate_node (0) &&
	       g_strcmp0 (drawer_title (), "This computer") == 0,
	       "This computer has details too");
	CHECK (!fs_topology_activate_node (99), "a node that does not exist has none");

	/* ---- more blocks than the diagram draws, then expiry ---- */
	block ("192.0.2.201", TRUE, "445", "SMB", t0 + 5 * MINUTE);
	block ("192.0.2.202", TRUE, "3389", "RDP", t0 + 5 * MINUTE);
	block ("192.168.1.99", TRUE, "5900", "VNC", t0 + 6 * MINUTE);
	CHECK (fs_topology_blocked_count () == 6 &&
	       fs_topology_blocked_link_count () == 4 &&
	       fs_topology_node_count () == 13,
	       "six blocked addresses are remembered and the newest four drawn "
	       "(%u remembered, %u lines)", fs_topology_blocked_count (),
	       fs_topology_blocked_link_count ());
	CHECK (fs_topology_find_node ("192.168.1.99") == 9 &&
	       fs_topology_find_node ("203.0.113.7") < 0,
	       "newest first: the oldest is not drawn");
	CHECK (fs_topology_table_rows () == 22,
	       "but the table lists all six (got %u rows)",
	       fs_topology_table_rows ());
	CHECK (draw_offscreen (window, "900-full"),
	       "the page draws with every kind of node");
	CHECK (nodes_apart (area),
	       "at 900x500 with 13 nodes none overlap and none leaves the "
	       "diagram");

	fs_topology_expire (t0 + 10 * MINUTE - G_USEC_PER_SEC);
	CHECK (fs_topology_blocked_count () == 6,
	       "just under ten minutes after its last block an address stays");
	fs_topology_expire (t0 + 10 * MINUTE + G_USEC_PER_SEC);
	CHECK (fs_topology_blocked_count () == 5 &&
	       fs_topology_blocked_link_count () == 4,
	       "ten minutes after its last block it is forgotten; the others, "
	       "blocked later, stay (%u left)", fs_topology_blocked_count ());
	fs_topology_expire (t0 + 15 * MINUTE + G_USEC_PER_SEC);
	CHECK (fs_topology_blocked_count () == 1 &&
	       fs_topology_find_node ("192.168.1.99") == 9,
	       "each address expires by its own last block");
	fs_topology_expire (t0 + 17 * MINUTE);
	CHECK (fs_topology_blocked_count () == 0 &&
	       fs_topology_blocked_link_count () == 0 &&
	       fs_topology_node_count () == 9,
	       "and then the diagram shows no blocked node");

	/* ---- six programs, a path for a name, a long list ---- */
	fake_table = six;
	fake_rows = G_N_ELEMENTS (six);
	fs_topology_refresh ();
	CHECK (fs_topology_find_node ("Other programs") < 0 &&
	       fs_topology_find_node ("tool.exe") == 2 &&
	       fs_topology_find_node ("Local network") < 0 &&
	       fs_topology_node_count () == 8,
	       "a single program past five keeps its own name, shown as its "
	       "file name, and only Internet is drawn");
	fake_many = TRUE;
	fs_topology_refresh ();
	CHECK (fs_topology_node_count () == 3 &&
	       fs_topology_node_connections (1) == MANY &&
	       fs_topology_activate_node (1) &&
	       has_label (fs_drawer_widget (), "10.0.1.20") &&
	       !has_label (fs_drawer_widget (), "10.0.1.21") &&
	       has_label (fs_drawer_widget (), "and 5 more"),
	       "a program's details list 20 of its 25 connections and say "
	       "\"and 5 more\"");
	fake_many = FALSE;

	/* ---- nothing to list ---- */
	fake_table = NULL;
	fake_rows = 0;
	fs_topology_refresh ();
	CHECK (g_strcmp0 (fs_topology_empty_text (),
	                  "No open connections right now.") == 0 &&
	       fs_topology_node_count () == 1 && fs_topology_link_count () == 0,
	       "no connections: the empty state says so (got \"%s\")",
	       fs_topology_empty_text ());
	CHECK (!fs_topology_animating (), "with no line to move, nothing animates");
	CHECK (draw_offscreen (window, "900-none"), "the empty diagram draws");

	fake_backend.list_connections = NULL;
	fs_topology_refresh ();
	CHECK (g_strcmp0 (fs_topology_empty_text (),
	                  "This computer's open connections cannot be listed "
	                  "here.") == 0 &&
	       fs_topology_node_count () == 1,
	       "a backend that cannot list them: a different sentence (got "
	       "\"%s\")", fs_topology_empty_text ());
	CHECK (strstr (gtk_label_get_text (GTK_LABEL (caption)),
	               "cannot be listed here") != NULL,
	       "the caption carries it too");
	block ("203.0.113.7", TRUE, "22", "SSH", g_get_monotonic_time ());
	CHECK (fs_topology_blocked_link_count () == 1 && fs_topology_animating (),
	       "blocked events are still drawn, and move, without the list");
	CHECK (draw_offscreen (window, "900-nolist"),
	       "the page draws without a connection list");
	CHECK (warnings == 0, "no GTK warning or critical so far (%u)", warnings);

	/* ---- destroyed and built again, larger ---- */
	fs_topology_activate_node (0);
	gtk_widget_destroy (window);
	spin (50);
	CHECK (!fs_drawer_is_open (),
	       "destroying the page closes the details it had opened");

	fake_backend.list_connections = fake_list;
	fake_table = busy;
	fake_rows = G_N_ELEMENTS (busy);
	t0 = g_get_monotonic_time ();
	block ("198.51.100.9", FALSE, "4444", "", t0);
	block ("192.0.2.201", TRUE, "445", "SMB", t0);
	block ("2001:db8:85a3::8a2e:370:7334", TRUE, "3389", "RDP", t0);

	window = build (1400, 800);
	page = gtk_bin_get_child (GTK_BIN (window));
	area = find_by_name (page, "topology-diagram");
	CHECK (fs_topology_node_count () == 13 &&
	       fs_topology_blocked_link_count () == 4,
	       "built again: the connections and the remembered blocks are "
	       "back (%u nodes)", fs_topology_node_count ());
	CHECK (draw_offscreen (window, "1400-full"), "the page draws at 1400x800");
	CHECK (gtk_widget_get_allocated_width (area) > 1000 && nodes_apart (area),
	       "at 1400x800 no two of the 13 nodes overlap and none leaves the "
	       "diagram (%d px wide)", gtk_widget_get_allocated_width (area));

	CHECK (fs_topology_animating () && fs_topology_polling (),
	       "it animates and polls");
	gtk_widget_destroy (window);
	CHECK (!fs_topology_animating () && !fs_topology_polling (),
	       "destroying the page while it animates removes the callback "
	       "and the timer");
	set_animations (FALSE);
	set_animations (TRUE);
	block ("192.0.2.77", TRUE, "22", "SSH", g_get_monotonic_time ());
	spin (400);
	CHECK (!fs_topology_animating () && !fs_topology_polling () &&
	       fs_topology_find_node ("192.0.2.77") >= 0,
	       "nothing restarts once the page is gone, and events are still "
	       "taken");

	/* ---- fed without a backend ---- */
	{
		GList *list = NULL;

		for (guint i = 0; i < G_N_ELEMENTS (six); i++)
			list = g_list_prepend (list, make_conn (&six[i]));
		fs_topology_set_connections (list);
		g_list_free_full (list, (GDestroyNotify) fs_connection_free);
		CHECK (fs_topology_find_node ("tool.exe") >= 0 &&
		       fs_topology_node_connections (0) == 7,
		       "a list handed over directly builds the same model");
	}

	CHECK (warnings == 0,
	       "no GTK warning or critical while building, feeding, drawing "
	       "and destroying (%u)", warnings);

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED", failures);
	return failures ? 1 : 0;
}
