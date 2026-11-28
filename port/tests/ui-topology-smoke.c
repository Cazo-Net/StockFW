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
 *   - a click or Enter between a block and the repaint that follows it
 *     opens the node that is on screen, or nothing when it has gone;
 *   - a line whose connections were opened both ways is neither
 *     outbound nor inbound: it does not move, it has an arrowhead at
 *     each end, and the tooltip and the details count the two kinds;
 *   - past the 32 addresses it remembers, the page says "more than 32"
 *     and does not claim that the table lists them all;
 *   - open details follow the diagram: left alone when nothing changed,
 *     filled again when something did, closed when their node goes;
 *   - in a window that hosts the drawer, the page is laid out in the
 *     width the open drawer leaves, the hit test agrees with the
 *     picture, and the arrow keys take the details with them;
 *   - destroying the page while it animates leaves nothing running, and
 *     nothing above raises a GTK warning.
 *
 * Teeth: make anim_sync ignore area_mapped (or the animation setting)
 * and the "no tick" checks fail; make expire_blocks keep everything and
 * the expiry checks fail; make diagram_width return the width it is
 * given and the "legend that cannot give way" checks fail.
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

/* A server: nginx answers three clients and has opened one connection
 * itself, sshd has one client on the local network, curl is on its way
 * out.  The first four rows alone leave no line that runs one way. */
static const FakeConn mixed[] = {
	{ "nginx", "192.168.1.50", "203.0.113.1",   "443", "HTTPS", "Inbound"  },
	{ "nginx", "192.168.1.50", "203.0.113.2",   "443", "HTTPS", "Inbound"  },
	{ "nginx", "192.168.1.50", "203.0.113.3",   "443", "HTTPS", "Inbound"  },
	{ "nginx", "192.168.1.50", "198.51.100.5",  "443", "HTTPS", "Outbound" },
	{ "sshd",  "192.168.1.50", "192.168.1.20",  "22",  "SSH",   "Inbound"  },
	{ "curl",  "192.168.1.50", "93.184.216.34", "443", "HTTPS", "Outbound" },
};

/* One program holding more connections than the drawer lists. */
#define MANY 25

static const FakeConn *fake_table = busy;
static guint           fake_rows = G_N_ELEMENTS (busy);
static gboolean        fake_many = FALSE;
static guint           fake_many_rows = MANY;
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
		for (guint i = 0; i < fake_many_rows; i++) {
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

/* TRUE when some label under `widget' contains `text'. */
static gboolean
has_label_with (GtkWidget *widget, const gchar *text)
{
	gboolean found = FALSE;

	if (GTK_IS_LABEL (widget))
		return strstr (gtk_label_get_text (GTK_LABEL (widget)), text) != NULL;
	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));

		for (GList *l = children; l != NULL && !found; l = l->next)
			found = has_label_with (GTK_WIDGET (l->data), text);
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

/* What the drawer was last filled with: the one child of its body. */
static GtkWidget *
drawer_body (void)
{
	GtkWidget *slot = find_by_name (fs_drawer_widget (), "fs-drawer-body");
	GList *children = slot != NULL
		? gtk_container_get_children (GTK_CONTAINER (slot)) : NULL;
	GtkWidget *body = children != NULL ? children->data : NULL;

	g_list_free (children);
	return body;
}

/* The colour of one pixel of the diagram as the window last painted it
 * (0xRRGGBB); x and y are the diagram's own. */
static guint32
pixel_at (GtkWidget *window, GtkWidget *area, gint x, gint y)
{
	cairo_surface_t *surface = gtk_offscreen_window_get_surface (
		GTK_OFFSCREEN_WINDOW (window));
	cairo_surface_t *one = cairo_image_surface_create (CAIRO_FORMAT_RGB24,
	                                                   1, 1);
	cairo_t *cr = cairo_create (one);
	gint wx = 0, wy = 0;
	guint32 pixel = 0;

	gtk_widget_translate_coordinates (area, window, x, y, &wx, &wy);
	cairo_set_source_surface (cr, surface, -wx, -wy);
	cairo_paint (cr);
	cairo_destroy (cr);
	cairo_surface_flush (one);
	memcpy (&pixel, cairo_image_surface_get_data (one), sizeof pixel);
	cairo_surface_destroy (one);
	return pixel & 0xffffff;
}

/* Is an arrowhead painted where the line of node `index' leaves it?
 * `right' is the side of the node the line is on.  Six pixels along
 * the line an arrowhead is some three pixels tall on each side of it;
 * the line itself is at most two.  Compared with the card's ground,
 * taken well above the line. */
static gboolean
arrowhead_at_node (GtkWidget *window, GtkWidget *area, guint index,
                   gboolean right)
{
	GdkRectangle r;
	gint x;

	fs_topology_node_rect (index, &r);
	x = right ? r.x + r.width + 6 : r.x - 7;
	return pixel_at (window, area, x, r.y + r.height / 2 - 3) !=
	       pixel_at (window, area, x, r.y + 2);
}

/* Where the drawer's panel begins, in the diagram's coordinates. */
static gint
drawer_left (GtkWidget *area)
{
	gint x = -1;

	if (!gtk_widget_translate_coordinates (fs_drawer_widget (), area, 0, 0,
	                                       &x, NULL))
		return -1;
	return x;
}

/* The right edge of `widget', in the diagram's coordinates. */
static gint
right_edge (GtkWidget *widget, GtkWidget *area)
{
	gint x = -1;

	gtk_widget_translate_coordinates (widget, area,
		gtk_widget_get_allocated_width (widget), 0, &x, NULL);
	return x;
}

/* Every node ends at or before `x'. */
static gboolean
nodes_left_of (gint x)
{
	for (guint i = 0; i < fs_topology_node_count (); i++) {
		GdkRectangle r;

		fs_topology_node_rect (i, &r);
		if (r.x + r.width > x)
			return FALSE;
	}
	return TRUE;
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

/* The page under the drawer, as the main window hosts them: the drawer
 * is an overlay at the right edge of the pages.  Destroying the window
 * destroys the drawer with it; the next use makes a new one. */
static GtkWidget *
build_hosted (gint width, gint height)
{
	GtkWidget *window = gtk_offscreen_window_new ();
	GtkWidget *overlay = gtk_overlay_new ();

	gtk_window_set_default_size (GTK_WINDOW (window), width, height);
	gtk_container_add (GTK_CONTAINER (overlay), fs_topology_page ());
	gtk_overlay_add_overlay (GTK_OVERLAY (overlay), fs_drawer_widget ());
	gtk_container_add (GTK_CONTAINER (window), overlay);
	gtk_widget_show_all (window);
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

	/* ---- a click or Enter between a block and its repaint ----
	 * A new block moves every blocked node down by one, and the
	 * diagram is repainted a tenth of a second later.  Until then the
	 * picture on screen is the old one, and it is the old picture the
	 * user clicks on. */
	fs_drawer_close ();
	t0 = g_get_monotonic_time ();
	block ("203.0.113.10", TRUE, "22", "SSH", t0);
	block ("203.0.113.20", TRUE, "22", "SSH", t0 + 1);
	blocked = fs_topology_find_node ("203.0.113.10");
	fs_topology_node_rect ((guint) blocked, &rect);
	CHECK (draw_offscreen (window, "900-two") && blocked == 10,
	       "two blocked addresses are painted, 203.0.113.10 second");
	block ("203.0.113.30", TRUE, "22", "SSH", t0 + 2);
	click (area, rect.x + rect.width / 2, rect.y + rect.height / 2);
	CHECK (fs_drawer_is_open () &&
	       g_strcmp0 (drawer_title (), "203.0.113.10") == 0,
	       "a click just after another block opens the node that was "
	       "clicked, not the one that took its place (title \"%s\")",
	       drawer_title ());
	fs_drawer_close ();
	block ("203.0.113.40", TRUE, "22", "SSH", t0 + 3);
	press_key (area, GDK_KEY_Return);
	CHECK (fs_drawer_is_open () &&
	       g_strcmp0 (drawer_title (), "203.0.113.10") == 0,
	       "Enter just after another block opens the node under the "
	       "ring (title \"%s\")", drawer_title ());
	fs_drawer_close ();
	blocked = fs_topology_find_node ("203.0.113.10");
	fs_topology_node_rect ((guint) blocked, &rect);
	block ("203.0.113.50", TRUE, "22", "SSH", t0 + 4);
	click (area, rect.x + rect.width / 2, rect.y + rect.height / 2);
	CHECK (blocked == 12 && !fs_drawer_is_open () &&
	       fs_topology_find_node ("203.0.113.10") < 0,
	       "a click on a node that the new block pushed off the diagram "
	       "opens nothing (open: %d, title \"%s\")",
	       fs_drawer_is_open (), drawer_title ());

	/* ---- more addresses than are remembered ---- */
	fs_topology_expire (t0 + 11 * MINUTE);
	t0 = g_get_monotonic_time ();
	block ("198.18.0.1", TRUE, "23", "Telnet", t0);
	for (guint i = 2; i <= 33; i++) {
		gchar *remote = g_strdup_printf ("198.18.0.%u", i);

		block (remote, TRUE, "23", "Telnet", t0 + MINUTE);
		g_free (remote);
	}
	CHECK (fs_topology_blocked_count () == 32 &&
	       fs_topology_find_node ("198.18.0.33") == 9 &&
	       fs_topology_table_rows () == 16 + 32,
	       "33 addresses blocked: the newest 32 are remembered and "
	       "listed (%u, %u rows)", fs_topology_blocked_count (),
	       fs_topology_table_rows ());
	CHECK (strstr (gtk_label_get_text (GTK_LABEL (caption)),
	               "More than 32 addresses were blocked in the last "
	               "10 minutes") != NULL &&
	       strstr (gtk_label_get_text (GTK_LABEL (caption)),
	               "the table lists the newest 32.") != NULL &&
	       strstr (gtk_label_get_text (GTK_LABEL (caption)),
	               "them all") == NULL,
	       "the caption says more than 32, and that the table lists the "
	       "newest 32, not all (got \"%s\")",
	       gtk_label_get_text (GTK_LABEL (caption)));
	CHECK (fs_topology_activate_node (0) &&
	       has_label (fs_drawer_widget (), "More than 32"),
	       "and so do the details of This computer");
	fs_topology_expire (t0 + 10 * MINUTE + G_USEC_PER_SEC);
	CHECK (fs_topology_blocked_count () == 32 &&
	       fs_topology_node_count () == 13 &&
	       strstr (gtk_label_get_text (GTK_LABEL (caption)),
	               "32 addresses were blocked in the last 10 minutes") != NULL &&
	       strstr (gtk_label_get_text (GTK_LABEL (caption)),
	               "More than") == NULL &&
	       strstr (gtk_label_get_text (GTK_LABEL (caption)),
	               "the table lists them all.") != NULL,
	       "ten minutes after the block that was pushed out, 32 is the "
	       "whole count again (got \"%s\")",
	       gtk_label_get_text (GTK_LABEL (caption)));
	CHECK (fs_drawer_is_open () && has_label (fs_drawer_widget (), "32") &&
	       !has_label (fs_drawer_widget (), "More than 32"),
	       "and the open details of This computer were brought up to "
	       "date");
	fs_topology_expire (t0 + 12 * MINUTE);
	CHECK (fs_topology_blocked_count () == 0 &&
	       fs_topology_node_count () == 9 &&
	       strstr (gtk_label_get_text (GTK_LABEL (caption)),
	               "Nothing was blocked") != NULL,
	       "and then nothing is left");

	/* ---- open details follow the diagram ---- */
	{
		GtkWidget *body;

		CHECK (fs_topology_activate_node (1) &&
		       g_strcmp0 (drawer_title (), "firefox") == 0 &&
		       has_label (fs_drawer_widget (), "4 open connections"),
		       "firefox is open in the drawer with its 4 connections");
		body = drawer_body ();
		g_object_add_weak_pointer (G_OBJECT (body), (gpointer *) &body);
		fs_topology_refresh ();
		spin (50);
		CHECK (body != NULL && drawer_body () == body,
		       "a sample that changes nothing leaves the drawer's content "
		       "alone");
		fake_rows = 3;                 /* firefox closed one */
		fs_topology_refresh ();
		spin (50);
		CHECK (fs_drawer_is_open () &&
		       g_strcmp0 (drawer_title (), "firefox") == 0 &&
		       has_label (fs_drawer_widget (), "3 open connections") &&
		       !has_label (fs_drawer_widget (), "4 open connections") &&
		       !has_label (fs_drawer_widget (), "142.250.74.14") &&
		       body == NULL,
		       "a sample with one connection fewer fills it again: 3 open "
		       "connections");
		fake_rows = G_N_ELEMENTS (busy);
		fs_topology_refresh ();

		t0 = g_get_monotonic_time ();
		block ("203.0.113.7", TRUE, "22", "SSH", t0);
		blocked = fs_topology_find_node ("203.0.113.7");
		CHECK (blocked >= 0 && fs_topology_activate_node ((guint) blocked) &&
		       has_label_with (fs_drawer_widget (), "1 time, since "),
		       "a blocked address is open in the drawer: blocked 1 time");
		block ("203.0.113.7", TRUE, "22", "SSH", t0 + 1);
		block ("203.0.113.7", TRUE, "22", "SSH", t0 + 2);
		CHECK (fs_topology_node_count () == 10 &&
		       g_strcmp0 (drawer_title (), "203.0.113.7") == 0 &&
		       has_label_with (fs_drawer_widget (), "3 times, since ") &&
		       !has_label_with (fs_drawer_widget (), "1 time, since "),
		       "two more blocks from it and the drawer says 3 times");
		fs_topology_expire (t0 + 11 * MINUTE);
		CHECK (fs_topology_find_node ("203.0.113.7") < 0 &&
		       !fs_drawer_is_open (),
		       "when the address leaves the diagram its details close");

		CHECK (fs_topology_activate_node (1) &&
		       g_strcmp0 (drawer_title (), "firefox") == 0,
		       "firefox is open again");
		fake_table = six;
		fake_rows = G_N_ELEMENTS (six);
		fs_topology_refresh ();
		CHECK (fs_topology_find_node ("firefox") < 0 && !fs_drawer_is_open (),
		       "and when firefox has no connection left its details close");
		fake_table = busy;
		fake_rows = G_N_ELEMENTS (busy);
		fs_topology_refresh ();
	}

	/* ---- connections opened both ways ---- */
	{
		gint nginx, curl, sshd;
		gchar *tip;

		fake_table = mixed;
		fake_rows = G_N_ELEMENTS (mixed);
		fs_topology_refresh ();
		nginx = fs_topology_find_node ("nginx");
		curl = fs_topology_find_node ("curl");
		sshd = fs_topology_find_node ("sshd");
		lan = fs_topology_find_node ("Local network");
		net = fs_topology_find_node ("Internet");
		CHECK (nginx == 1 && curl == 2 && sshd == 3 && lan == 4 && net == 5,
		       "a server: nginx, curl, sshd, Local network and Internet");
		CHECK (fs_topology_node_flow ((guint) curl) ==
		       FS_TOPOLOGY_FLOW_OUTBOUND,
		       "curl's one connection was opened here: its line is "
		       "outbound");
		CHECK (fs_topology_node_flow ((guint) sshd) ==
		       FS_TOPOLOGY_FLOW_INBOUND &&
		       fs_topology_node_flow ((guint) lan) ==
		       FS_TOPOLOGY_FLOW_INBOUND,
		       "sshd's one connection was opened from the local network: "
		       "both lines are inbound");
		CHECK (fs_topology_node_flow ((guint) nginx) ==
		       FS_TOPOLOGY_FLOW_MIXED &&
		       fs_topology_node_flow ((guint) net) == FS_TOPOLOGY_FLOW_MIXED,
		       "nginx (3 in, 1 out) and Internet (3 in, 2 out) are mixed, "
		       "not outbound (%d, %d)",
		       fs_topology_node_flow ((guint) nginx),
		       fs_topology_node_flow ((guint) net));
		CHECK (fs_topology_node_flow (0) == FS_TOPOLOGY_FLOW_NONE &&
		       fs_topology_node_flow (99) == FS_TOPOLOGY_FLOW_NONE,
		       "This computer and a node that does not exist have no line");

		tip = fs_topology_node_tooltip ((guint) nginx);
		CHECK (tip != NULL && strstr (tip, "4 open connections") != NULL &&
		       strstr (tip, "1 opened here, 3 opened from outside") != NULL,
		       "nginx's tooltip gives the split");
		g_free (tip);
		tip = fs_topology_node_tooltip ((guint) net);
		CHECK (tip != NULL &&
		       strstr (tip, "2 opened here, 3 opened from outside") != NULL,
		       "and so does Internet's");
		g_free (tip);
		tip = fs_topology_node_tooltip ((guint) curl);
		CHECK (tip != NULL && strstr (tip, "opened") == NULL,
		       "curl's has none to give");
		g_free (tip);
		CHECK (fs_topology_node_tooltip (99) == NULL,
		       "a node that does not exist has no tooltip");

		CHECK (fs_topology_activate_node ((guint) nginx) &&
		       has_label (fs_drawer_widget (),
		                  "1 opened here, 3 opened from outside"),
		       "nginx's details give the split");
		CHECK (fs_topology_activate_node ((guint) net) &&
		       has_label (fs_drawer_widget (),
		                  "2 opened here, 3 opened from outside"),
		       "Internet's details give it");
		CHECK (fs_topology_activate_node (0) &&
		       has_label (fs_drawer_widget (),
		                  "2 opened here, 4 opened from outside"),
		       "and This computer's details give it for all six");
		CHECK (fs_topology_activate_node ((guint) curl) &&
		       !has_label_with (fs_drawer_widget (), "opened here"),
		       "curl's details have no split");
		fs_drawer_close ();
		CHECK (has_label (page, "Opened both ways"),
		       "the legend has a sample of a line opened both ways");

		/* The picture.  Moving: a mixed line has an arrowhead where it
		 * leaves its program and where it reaches Internet; an
		 * outbound one is dashes only. */
		CHECK (fs_topology_animating () &&
		       draw_offscreen (window, "900-mixed"),
		       "the server draws, and curl's and sshd's lines move");
		CHECK (arrowhead_at_node (window, area, (guint) nginx, TRUE) &&
		       arrowhead_at_node (window, area, (guint) net, FALSE),
		       "moving: the mixed lines carry an arrowhead at nginx and at "
		       "Internet");
		CHECK (!arrowhead_at_node (window, area, (guint) curl, TRUE),
		       "moving: curl's outbound line carries none where it "
		       "starts");
		set_animations (FALSE);
		CHECK (draw_offscreen (window, "900-mixed-static") &&
		       arrowhead_at_node (window, area, (guint) nginx, TRUE) &&
		       arrowhead_at_node (window, area, (guint) net, FALSE),
		       "still: the mixed lines carry them too");
		CHECK (!arrowhead_at_node (window, area, (guint) curl, TRUE) &&
		       arrowhead_at_node (window, area, (guint) sshd, TRUE) &&
		       !arrowhead_at_node (window, area, (guint) lan, FALSE),
		       "still: an outbound line has its arrowhead at the far end "
		       "only, an inbound one at the program");
		set_animations (TRUE);

		fake_rows = 4;                 /* nginx alone */
		fs_topology_refresh ();
		CHECK (fs_topology_link_count () == 2 &&
		       fs_topology_node_flow (1) == FS_TOPOLOGY_FLOW_MIXED &&
		       fs_topology_node_flow (2) == FS_TOPOLOGY_FLOW_MIXED &&
		       !fs_topology_animating (),
		       "with mixed lines only, nothing is animated: a mixed line "
		       "has no moving dashes");
		CHECK (draw_offscreen (window, "900-mixed-only"),
		       "and the page draws");

		fake_table = busy;
		fake_rows = G_N_ELEMENTS (busy);
		fs_topology_refresh ();
		CHECK (fs_topology_animating () &&
		       fs_topology_node_flow (1) == FS_TOPOLOGY_FLOW_OUTBOUND,
		       "back to the busy computer: firefox is outbound and the "
		       "lines move again");
	}

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

	/* ---- beside the drawer, as the main window hosts it ----
	 * The drawer is 380 pixels at the right edge of the pages, over
	 * the diagram's right column.  With GTK animations off it is there
	 * at once, and nothing but the page's own handlers repaints the
	 * diagram. */
	{
		GtkWidget *toggle, *card, *legend, *scroller;
		GtkAdjustment *adj;
		GtkWidget *body;
		gint area_w, edge;

		set_animations (FALSE);
		window = build_hosted (1400, 800);
		page = gtk_bin_get_child (GTK_BIN (gtk_bin_get_child (GTK_BIN (window))));
		area = find_by_name (page, "topology-diagram");
		caption = find_by_name (page, "topology-caption");
		toggle = find_by_name (page, "topology-table-toggle");
		legend = find_by_name (page, "topology-legend");
		card = gtk_widget_get_parent (legend);
		lan = fs_topology_find_node ("Local network");
		net = fs_topology_find_node ("Internet");
		area_w = gtk_widget_get_allocated_width (area);
		fs_topology_node_rect ((guint) net, &rect);
		CHECK (!fs_drawer_is_open () && toggle != NULL && lan > 0 && net > 0 &&
		       fs_topology_node_count () == 13 &&
		       rect.x + rect.width > area_w - 380 &&
		       right_edge (toggle, area) > area_w - 380,
		       "hosted, drawer closed: Internet and Show as table stand "
		       "where the drawer will lie (node ends at %d of %d)",
		       rect.x + rect.width, area_w);

		gtk_widget_grab_focus (area);
		click (area, rect.x + rect.width / 2, rect.y + rect.height / 2);
		spin (200);
		edge = drawer_left (area);
		CHECK (fs_drawer_is_open () &&
		       g_strcmp0 (drawer_title (), "Internet") == 0 &&
		       gtk_widget_get_mapped (fs_drawer_widget ()) &&
		       edge > 640 && edge < area_w,
		       "a click on Internet opens the drawer over the page (its "
		       "edge at %d of %d)", edge, area_w);
		CHECK (right_edge (card, area) <= edge &&
		       right_edge (toggle, area) <= edge &&
		       right_edge (caption, area) <= edge &&
		       right_edge (legend, area) <= edge,
		       "the card, the caption, the legend and Show as table end "
		       "where the drawer begins (%d, %d, %d, %d; drawer at %d)",
		       right_edge (card, area), right_edge (caption, area),
		       right_edge (legend, area), right_edge (toggle, area), edge);
		CHECK (nodes_left_of (edge) && nodes_apart (area),
		       "every node is beside the drawer, none under it, and none "
		       "overlap");
		CHECK (fs_topology_diagram_width () > 0 &&
		       fs_topology_diagram_width () <= edge,
		       "and that is the width the diagram was painted in, with "
		       "nothing asked of it (%d)", fs_topology_diagram_width ());
		fs_topology_node_rect ((guint) lan, &rect);
		click (area, rect.x + rect.width / 2, rect.y + rect.height / 2);
		CHECK (g_strcmp0 (drawer_title (), "Local network") == 0,
		       "a click where Local network now stands opens it: the hit "
		       "test agrees with the picture (title \"%s\")",
		       drawer_title ());

		/* The arrow keys take the details with them. */
		press_key (area, GDK_KEY_Down);
		CHECK (g_strcmp0 (drawer_title (), "Internet") == 0,
		       "Down moves the ring to Internet and the drawer follows "
		       "without Enter (title \"%s\")", drawer_title ());
		press_key (area, GDK_KEY_Left);
		CHECK (g_strcmp0 (drawer_title (), "This computer") == 0,
		       "Left: This computer (title \"%s\")", drawer_title ());
		press_key (area, GDK_KEY_Left);
		for (guint i = 0; i < 8; i++)
			press_key (area, GDK_KEY_Up);
		CHECK (g_strcmp0 (drawer_title (), "firefox") == 0 &&
		       gtk_window_get_focus (GTK_WINDOW (window)) == area,
		       "Left and Up: firefox, and the keyboard is still on the "
		       "diagram (title \"%s\")", drawer_title ());
		fs_drawer_close ();
		press_key (area, GDK_KEY_Down);
		CHECK (!fs_drawer_is_open (),
		       "with the drawer closed the arrow keys open nothing");

		/* Closed: the page has its width back, by itself. */
		spin (200);
		fs_topology_node_rect ((guint) net, &rect);
		CHECK (gtk_widget_get_allocated_width (area) == area_w &&
		       fs_topology_diagram_width () == area_w &&
		       rect.x + rect.width > area_w - 380 &&
		       right_edge (toggle, area) > area_w - 380,
		       "closing the drawer gives the page its width back (%d "
		       "painted of %d)", fs_topology_diagram_width (), area_w);

		/* A long list in the drawer: reading it is not disturbed. */
		fake_many = TRUE;
		fs_topology_refresh ();
		CHECK (fs_topology_activate_node (1) &&
		       g_strcmp0 (drawer_title (), "rsync") == 0,
		       "rsync and its 25 connections are open in the drawer");
		spin (200);
		body = drawer_body ();
		g_object_add_weak_pointer (G_OBJECT (body), (gpointer *) &body);
		scroller = gtk_widget_get_ancestor (body, GTK_TYPE_SCROLLED_WINDOW);
		adj = gtk_scrolled_window_get_vadjustment (
			GTK_SCROLLED_WINDOW (scroller));
		gtk_adjustment_set_value (adj, 120.0);
		gtk_widget_grab_focus (area);
		fs_topology_refresh ();
		spin (100);
		CHECK (gtk_adjustment_get_value (adj) == 120.0 && body != NULL &&
		       drawer_body () == body &&
		       gtk_window_get_focus (GTK_WINDOW (window)) == area,
		       "the list is longer than the drawer and scrolled; a sample "
		       "that changes nothing leaves it where it was (at %.0f)",
		       gtk_adjustment_get_value (adj));
		fake_many_rows = MANY - 1;
		fs_topology_refresh ();
		spin (100);
		CHECK (fs_drawer_is_open () &&
		       has_label (fs_drawer_widget (), "24 open connections") &&
		       has_label (fs_drawer_widget (), "and 4 more") &&
		       gtk_window_get_focus (GTK_WINDOW (window)) == area,
		       "one connection fewer: the drawer says 24, and the keyboard "
		       "stays on the diagram (scrolled to %.0f)",
		       gtk_adjustment_get_value (adj));
		if (body != NULL)
			g_object_remove_weak_pointer (G_OBJECT (body),
			                              (gpointer *) &body);
		fake_many_rows = MANY;
		fake_many = FALSE;
		fs_drawer_close ();
		fs_topology_refresh ();
		spin (200);

		/* A legend that cannot give way (a long translation): the card
		 * stays wider than what the drawer leaves, and the diagram
		 * keeps to that by itself. */
		gtk_widget_set_size_request (legend, 1150, -1);
		spin (100);
		net = fs_topology_find_node ("Internet");
		fs_topology_node_rect ((guint) net, &rect);
		click (area, rect.x + rect.width / 2, rect.y + rect.height / 2);
		spin (200);
		edge = drawer_left (area);
		CHECK (g_strcmp0 (drawer_title (), "Internet") == 0 &&
		       gtk_widget_get_allocated_width (area) > edge,
		       "with a legend 1150 pixels wide the diagram's area runs on "
		       "under the drawer (%d wide, drawer at %d)",
		       gtk_widget_get_allocated_width (area), edge);
		CHECK (fs_topology_diagram_width () == edge &&
		       nodes_left_of (edge) && nodes_apart (area),
		       "but the diagram is painted in what the drawer leaves, "
		       "every node beside it (%d)", fs_topology_diagram_width ());
		lan = fs_topology_find_node ("Local network");
		fs_topology_node_rect ((guint) lan, &rect);
		click (area, rect.x + rect.width / 2, rect.y + rect.height / 2);
		CHECK (g_strcmp0 (drawer_title (), "Local network") == 0,
		       "and a click where Local network is painted opens it "
		       "(title \"%s\")", drawer_title ());
		CHECK (draw_offscreen (window, "1400-drawer"),
		       "the page draws beside the open drawer");
		CHECK (warnings == 0, "no GTK warning or critical hosted (%u)",
		       warnings);
		gtk_widget_destroy (window);
		spin (50);
		CHECK (!fs_drawer_is_open (),
		       "destroying the window closes the drawer with it");

		/* A window too narrow for both: the diagram keeps its smallest
		 * width and its right column goes under the drawer. */
		window = build_hosted (900, 500);
		page = gtk_bin_get_child (GTK_BIN (gtk_bin_get_child (GTK_BIN (window))));
		area = find_by_name (page, "topology-diagram");
		CHECK (fs_topology_activate_node (0), "hosted at 900x500, drawer open");
		spin (200);
		edge = drawer_left (area);
		CHECK (edge > 0 && edge < 640 &&
		       fs_topology_diagram_width () == 640 && nodes_apart (area),
		       "at 900x500 the diagram is not squeezed below its smallest "
		       "width (painted in %d, drawer at %d)",
		       fs_topology_diagram_width (), edge);
		gtk_widget_destroy (window);
		spin (50);
		set_animations (TRUE);
	}

	CHECK (warnings == 0,
	       "no GTK warning or critical while building, feeding, drawing "
	       "and destroying (%u)", warnings);

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED", failures);
	return failures ? 1 : 0;
}
