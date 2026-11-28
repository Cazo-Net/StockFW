/*---[ fs-topology.c ]--------------------------------------------------
 * The Topology page: what this computer is connected to right now, and
 * what the firewall turned away in the last ten minutes, as a diagram
 * or a table.
 *
 * Everything on it is read from this computer.  The open connections
 * are the backend's list_connections (the list the Overview shows),
 * asked for every three seconds while the page is on show.  The blocked
 * addresses come from the events as they arrive (fs_topology_note_hit,
 * which the Events page calls for every event it lists), so they are
 * counted from the moment StockFW opened and the page says so.
 *
 * The lines move.  1.0.9 took the motion out because the page then drew
 * made-up computers, and dots travelling over made-up data read as
 * traffic being shown as it happened.  Now a line stands for
 * connections that are open, and its dashes run the way those
 * connections were opened, every line at the same speed: the page
 * measures no rates and its legend says that.  With GTK animations
 * switched off nothing moves, and arrowheads carry the direction.  A
 * line whose connections were opened both ways never moves: it has an
 * arrowhead at each end, and the node's tooltip and details count the
 * two kinds.
 *
 * A click on a node opens its details in the window's drawer.  While
 * they are open the diagram is laid out in the width the drawer leaves,
 * and the details are kept up to date with the diagram.
 *--------------------------------------------------------------------*/

#include "ui/fs-topology.h"
#include "ui/fs-app.h"
#include "ui/fs-drawer.h"
#include "ui/fs-hitview.h"
#include "ui/fs-statusview.h"
#include "ui/fs-themecolor.h"
#include "core/fs-backend.h"
#include "core/fs-copilot.h"
#include "core/fs-iprange.h"
#include "core/fs-netparse.h"
#include "core/fs-util.h"
#include "core/fs-i18n.h"

#include <string.h>
#include <math.h>

#define DOT " \xc2\xb7 "                /* " . " middle dot */

#define POLL_MS            3000
#define REBUILD_MS         120
#define BLOCK_WINDOW_US    ((gint64) 10 * 60 * G_USEC_PER_SEC)
#define MAX_PROGRAMS       5         /* named; the rest are merged      */
#define MAX_BLOCKED_DRAWN  4
#define MAX_BLOCKED_KEPT   32
#define DRAWER_ROWS        20
#define DRAWER_GAP         12        /* between the page and the open drawer */

/* Every line's dashes travel at this speed, whatever it carries. */
#define FLOW_SPEED         26.0      /* pixels a second                 */
#define FRAME_US           33000     /* redraw at most 30 times a second */

/* The diagram's measures, in pixels. */
#define MIN_W              640
#define MIN_H              320
#define PAD_X              18.0
#define PAD_TOP            36.0      /* room for the column captions    */
#define PAD_BOTTOM         18.0
#define NODE_H             50.0
#define NODE_GAP           10.0      /* at least; more when there is room */
#define NODE_GAP_MAX       20.0
#define NODE_R             8.0
#define NODE_PAD           12.0
#define SECTION_H          26.0      /* "Blocked in the last 10 minutes" */
#define WALL_GAP           26.0      /* This computer to the firewall bar */
#define WALL_W             6.0
#define WALL_OVER          10.0
#define WALL_LABEL_H       22.0
#define PORT_GAP           18.0
#define MARK_R             6.0

/* ---- the data ------------------------------------------------------ */

/* One open connection of the last sample. */
typedef struct
{
	gchar   *program;     /* as the backend names it; never NULL      */
	gchar   *remote;
	gchar   *port;
	gchar   *service;
	gboolean inbound;
	gboolean local;       /* the remote end is on the local network   */
} TopoConn;

/* One remote address the firewall blocked. */
typedef struct
{
	gchar   *remote;
	gchar   *port;
	gchar   *service;     /* without the "[BLOCKED]" marker           */
	gchar   *protocol;
	gboolean inbound;     /* of the newest block                      */
	gboolean local;
	guint    count;       /* blocks since first_us                    */
	gint64   first_us;    /* monotonic                                */
	gint64   last_us;
	gint64   first_wall;  /* the same two moments on the wall clock,  */
	gint64   last_wall;   /* in seconds, for the details              */
} TopoBlock;

/* A program and the connections it holds, for ranking. */
typedef struct
{
	const gchar *name;    /* borrowed from a TopoConn                 */
	guint        count;
	guint        inbound;
} Tally;

typedef enum
{
	NODE_SELF,
	NODE_PROGRAM,
	NODE_OTHER,           /* "Other programs"                         */
	NODE_LAN,
	NODE_NET,
	NODE_BLOCKED
} NodeKind;

typedef struct
{
	NodeKind kind;
	gchar   *title;
	gchar   *detail;
	gchar   *key;         /* program name or blocked address, or NULL */
	guint    count;       /* open connections; blocks for NODE_BLOCKED */
	guint    inbound;     /* of the open connections: opened from
	                       * outside                                   */
	guint    programs;    /* behind NODE_OTHER, NODE_LAN and NODE_NET  */
	gdouble  x, y, w, h;  /* set by layout ()                          */
} TopoNode;

/* A line between "This computer" (node 0) and one other node. */
typedef struct
{
	guint    node;        /* the other end                             */
	gboolean left;        /* it is a program, left of This computer    */
	guint    count;
	FsTopologyFlow flow;  /* which way its open connections were
	                       * opened; NONE for a blocked line           */
	gboolean blocked;
	gboolean inbound;     /* blocked: it was on its way in             */
	gdouble  port_y;      /* where it meets This computer              */
} TopoLink;

static GPtrArray *conns = NULL;         /* TopoConn*                   */
static gboolean   conns_known = TRUE;   /* FALSE: the backend cannot   */
static guint      conns_inside = 0;     /* loopback to loopback        */
static GPtrArray *blocks = NULL;        /* TopoBlock*, newest first    */
static gint64     blocks_dropped_us = 0; /* the last block of the newest
                                         * address the cap pushed out;
                                         * 0 when none is inside the
                                         * window                      */
static GArray    *tallies = NULL;       /* Tally, busiest first        */
static guint      n_named = 0;          /* tallies with a node each    */

static GPtrArray *nodes = NULL;
static GPtrArray *links = NULL;
static gboolean   model_dirty = TRUE;
static gdouble    wall_x = 0.0;         /* the firewall bar, by layout */
static gdouble    flow_x0 = 0.0;        /* the strip the lines cross,  */
static gdouble    flow_x1 = 0.0;        /* between the side columns    */

/* ---- the page ------------------------------------------------------ */

static GtkWidget    *page = NULL;
static GtkWidget    *top_bar = NULL;       /* the switch and the caption */
static GtkWidget    *diagram_card = NULL;  /* diagram or table, and legend */
static GtkWidget    *drawing_area = NULL;
static GtkWidget    *stack = NULL;
static GtkWidget    *table_toggle = NULL;
static GtkWidget    *caption_label = NULL;
static GtkWidget    *legend = NULL;
static GtkWidget    *legend_note = NULL;
static GtkListStore *list_store = NULL;
static gboolean      table_shown = FALSE;
static gboolean      syncing = FALSE;

static gboolean   page_mapped = FALSE;
static gboolean   area_mapped = FALSE;
static guint      poll_id = 0;
static guint      rebuild_id = 0;
static guint      tick_id = 0;
static gint64     tick_origin_us = 0;
static gint64     tick_drawn_us = 0;
static gdouble    phase_s = 0.0;
static GtkSettings *anim_settings = NULL;
static gulong     anim_handler = 0;

static gint       hover_node = -1;
static gint       focus_node = -1;
static gboolean   pointer_inside = FALSE;
static gdouble    pointer_x = 0.0, pointer_y = 0.0;

/* Who filled the drawer, and with which node, so that node can be
 * marked while its details are on show. */
static gint       drawer_owner = 0;
static NodeKind   drawer_kind = NODE_SELF;
static gchar     *drawer_key = NULL;
static gchar     *drawer_text = NULL;      /* what the drawer says */
static gboolean   drawer_marked = FALSE;   /* as last painted */
static gdouble    drawn_width = 0.0;       /* laid out in, as last painted */

enum
{
	COL_PROGRAM,
	COL_REMOTE,
	COL_PORT,
	COL_SERVICE,
	COL_DIRECTION,
	COL_STATUS,
	N_COLS
};

static void sync_widgets (void);
static void anim_sync (void);
static void refresh_drawer (void);

/* ------------------------------------------------------------ helpers */

static void
add_class (GtkWidget *w, const gchar *cls)
{
	gtk_style_context_add_class (gtk_widget_get_style_context (w), cls);
}

static gboolean
animations_enabled (void)
{
	GtkSettings *settings = gtk_settings_get_default ();
	gboolean on = TRUE;

	if (settings != NULL)
		g_object_get (settings, "gtk-enable-animations", &on, NULL);
	return on;
}

static gboolean
firewall_running (void)
{
	FsFirewallState state = fs_statusview_get_state ();

	return state == FS_FW_RUNNING || state == FS_FW_LOCKED ||
	       state == FS_FW_HIT;
}

static gboolean
is_blank (const gchar *s)
{
	return s == NULL || *s == '\0';
}

static gchar *
connections_text (guint n)
{
	return g_strdup_printf (g_dngettext (NULL, "%u connection",
	                                     "%u connections", n), n);
}

static gchar *
open_connections_text (guint n)
{
	return g_strdup_printf (g_dngettext (NULL, "%u open connection",
	                                     "%u open connections", n), n);
}

static gchar *
programs_text (guint n)
{
	return g_strdup_printf (g_dngettext (NULL, "%u program",
	                                     "%u programs", n), n);
}

static gchar *
times_text (guint n)
{
	return g_strdup_printf (g_dngettext (NULL, "blocked %u time",
	                                     "blocked %u times", n), n);
}

static gchar *
clock_text (gint64 wall_s)
{
	GDateTime *when = g_date_time_new_from_unix_local (wall_s);
	gchar *text;

	if (when == NULL)
		return g_strdup ("");
	text = g_date_time_format (when, "%H:%M:%S");
	g_date_time_unref (when);
	return text != NULL ? text : g_strdup ("");
}

/* The file name of a program given by its path, for a node's title;
 * the tooltip and the details keep the whole name. */
static gchar *
short_name (const gchar *program)
{
	const gchar *base = program;
	const gchar *p;

	for (p = program; *p != '\0'; p++)
		if ((*p == '/' || *p == '\\') && p[1] != '\0')
			base = p + 1;
	return g_strdup (base);
}

/* A service worth showing by name: the backends write "Unknown" for a
 * port they have no name for. */
static gboolean
service_named (const gchar *service)
{
	return !is_blank (service) &&
	       g_ascii_strcasecmp (service, "Unknown") != 0;
}

/* "SSH", "port 4444", "UDP": what a block was about, in a few words. */
static gchar *
block_what (const TopoBlock *b)
{
	if (service_named (b->service))
		return g_strdup (b->service);
	if (!is_blank (b->port))
		return g_strdup_printf (_("port %s"), b->port);
	if (!is_blank (b->protocol))
		return g_strdup (b->protocol);
	return g_strdup (_("traffic"));
}

/* ----------------------------------------------- local or the internet */

gboolean
fs_topology_address_is_local (const gchar *address)
{
	gchar *copy, *zone;
	gboolean local = FALSE;

	if (is_blank (address))
		return FALSE;

	copy = g_strdup (address);
	if (copy[0] == '[') {
		gchar *end = strchr (copy, ']');

		if (end != NULL)
			*end = '\0';
		memmove (copy, copy + 1, strlen (copy + 1) + 1);
	}
	zone = strchr (copy, '%');
	if (zone != NULL)
		*zone = '\0';

	/* Sentinel's rule for "never block this by itself" is the list of
	 * address classes that do not leave the local side, which is the
	 * question here too.  It answers TRUE for text that is not an
	 * address at all; a remote end that cannot be read is not known to
	 * be local, so that case is settled first. */
	if (fs_addr_parse (copy, NULL, NULL) != FS_AF_NONE)
		local = fs_sentinel_dest_never_auto_block (copy);

	g_free (copy);
	return local;
}

/* ------------------------------------------------------- connections */

static void
conn_free (gpointer data)
{
	TopoConn *c = data;

	if (c == NULL)
		return;
	g_free (c->program);
	g_free (c->remote);
	g_free (c->port);
	g_free (c->service);
	g_free (c);
}

static void
block_free (gpointer data)
{
	TopoBlock *b = data;

	if (b == NULL)
		return;
	g_free (b->remote);
	g_free (b->port);
	g_free (b->service);
	g_free (b->protocol);
	g_free (b);
}

static void
node_free (gpointer data)
{
	TopoNode *n = data;

	if (n == NULL)
		return;
	g_free (n->title);
	g_free (n->detail);
	g_free (n->key);
	g_free (n);
}

static void
ensure_data (void)
{
	if (conns == NULL)
		conns = g_ptr_array_new_with_free_func (conn_free);
	if (blocks == NULL)
		blocks = g_ptr_array_new_with_free_func (block_free);
}

/* Copies the backend's list.  Both backends put this computer's end in
 * `source' and the other end in `destination', whichever way the
 * connection was opened. */
static void
take_connections (const GList *list)
{
	const GList *l;

	ensure_data ();
	/* The tallies borrow their names from the list that goes now. */
	if (tallies != NULL)
		g_array_set_size (tallies, 0);
	n_named = 0;
	g_ptr_array_set_size (conns, 0);
	conns_inside = 0;

	for (l = list; l != NULL; l = l->next) {
		const FsConnection *c = l->data;
		TopoConn *t;

		if (c == NULL)
			continue;

		/* Two programs on this computer talking to each other: no
		 * firewall rule sees it and it goes nowhere on this diagram.
		 * Counted, and said in the caption (the Overview hides the
		 * same ones). */
		if (fs_util_is_loopback_address (c->source) &&
		    fs_util_is_loopback_address (c->destination)) {
			conns_inside++;
			continue;
		}

		t = g_new0 (TopoConn, 1);
		t->program = g_strdup (is_blank (c->program) ||
		                       strcmp (c->program, "?") == 0
		                       ? _("Unknown program") : c->program);
		t->remote = g_strdup (is_blank (c->destination)
		                      ? _("Unknown address") : c->destination);
		t->port = g_strdup (c->port != NULL ? c->port : "");
		t->service = g_strdup (c->service != NULL ? c->service : "");
		t->inbound = g_strcmp0 (c->direction, "Inbound") == 0;
		t->local = fs_topology_address_is_local (c->destination);
		g_ptr_array_add (conns, t);
	}
}

static gint
tally_compare (gconstpointer a, gconstpointer b)
{
	const Tally *x = a, *y = b;

	if (x->count != y->count)
		return x->count > y->count ? -1 : 1;
	return strcmp (x->name, y->name);
}

/* Counts the connections of each program, busiest first.  `zone' picks
 * the ones to the local network (1), to the internet (2) or all (0). */
static GArray *
tally_programs (gint zone)
{
	GArray *out = g_array_new (FALSE, TRUE, sizeof (Tally));
	GHashTable *seen = g_hash_table_new (g_str_hash, g_str_equal);
	guint i;

	for (i = 0; conns != NULL && i < conns->len; i++) {
		const TopoConn *c = g_ptr_array_index (conns, i);
		gpointer at;
		Tally *t;

		if ((zone == 1 && !c->local) || (zone == 2 && c->local))
			continue;

		if (g_hash_table_lookup_extended (seen, c->program, NULL, &at)) {
			t = &g_array_index (out, Tally, GPOINTER_TO_UINT (at));
		} else {
			Tally fresh = { c->program, 0, 0 };

			g_hash_table_insert (seen, c->program,
			                     GUINT_TO_POINTER (out->len));
			g_array_append_val (out, fresh);
			t = &g_array_index (out, Tally, out->len - 1);
		}
		t->count++;
		if (c->inbound)
			t->inbound++;
	}

	g_hash_table_destroy (seen);
	g_array_sort (out, tally_compare);
	return out;
}

/* ------------------------------------------------------------- blocks */

static gboolean
hit_inbound (const FsHit *hit)
{
	return hit->direction != NULL &&
	       (g_ascii_strcasecmp (hit->direction, "In") == 0 ||
	        g_ascii_strcasecmp (hit->direction, "Inbound") == 0);
}

/* TRUE while the cap has pushed out an address whose last block is
 * still inside the window: more addresses were blocked in it than are
 * remembered, and what counts them must say "more than". */
static gboolean
blocks_capped (void)
{
	return blocks_dropped_us != 0;
}

/* Drops the blocks older than the window.  TRUE when any went, or when
 * the count stopped being short of the truth. */
static gboolean
expire_blocks (gint64 now_us)
{
	gboolean changed = FALSE;
	guint i;

	if (blocks == NULL)
		return FALSE;

	for (i = blocks->len; i-- > 0;) {
		const TopoBlock *b = g_ptr_array_index (blocks, i);

		if (now_us - b->last_us > BLOCK_WINDOW_US) {
			g_ptr_array_remove_index (blocks, i);
			changed = TRUE;
		}
	}

	/* The address the cap pushed out was blocked before every one that
	 * was kept, so it leaves the window no later than they do. */
	if (blocks_dropped_us != 0 &&
	    (now_us - blocks_dropped_us > BLOCK_WINDOW_US ||
	     blocks->len < MAX_BLOCKED_KEPT)) {
		blocks_dropped_us = 0;
		changed = TRUE;
	}
	return changed;
}

static gboolean
on_rebuild_timeout (gpointer data)
{
	(void) data;
	rebuild_id = 0;
	(void) fs_topology_node_count ();   /* rebuilds when out of date */
	return G_SOURCE_REMOVE;
}

/* The blocks changed.  A burst of blocked events (a port scan) is one
 * redraw a little later, not one for each event; with the page out of
 * sight nothing is rebuilt until something asks. */
static void
model_touch (void)
{
	model_dirty = TRUE;
	if (page_mapped && rebuild_id == 0)
		rebuild_id = g_timeout_add (REBUILD_MS, on_rebuild_timeout, NULL);
}

void
fs_topology_note_hit_at (const FsHit *hit, gint64 now_us)
{
	const gchar *remote;
	TopoBlock *b = NULL;
	gboolean inbound;
	guint i;

	if (hit == NULL || !fs_hit_is_blocked (hit))
		return;

	ensure_data ();
	inbound = hit_inbound (hit);
	remote = inbound ? hit->source : hit->destination;
	if (is_blank (remote))
		remote = _("Unknown address");

	/* Newest first: a known address moves to the front, a new one is
	 * put there, and past the cap the one blocked longest ago goes. */
	for (i = 0; i < blocks->len; i++) {
		TopoBlock *have = g_ptr_array_index (blocks, i);

		if (strcmp (have->remote, remote) == 0) {
			b = have;
			memmove (&blocks->pdata[1], &blocks->pdata[0],
			         i * sizeof (gpointer));
			blocks->pdata[0] = b;
			break;
		}
	}

	if (b == NULL) {
		b = g_new0 (TopoBlock, 1);
		b->remote = g_strdup (remote);
		b->local = fs_topology_address_is_local (remote);
		b->first_us = now_us;
		b->first_wall = g_get_real_time () / G_USEC_PER_SEC;
		g_ptr_array_insert (blocks, 0, b);
		/* The cap is on memory, not on the truth: what it pushes out
		 * was blocked inside the window all the same, and the counts
		 * say "more than" until that block is ten minutes old. */
		for (i = MAX_BLOCKED_KEPT; i < blocks->len; i++) {
			const TopoBlock *gone = g_ptr_array_index (blocks, i);

			blocks_dropped_us = MAX (blocks_dropped_us, gone->last_us);
		}
		if (blocks->len > MAX_BLOCKED_KEPT)
			g_ptr_array_set_size (blocks, MAX_BLOCKED_KEPT);
	}

	g_free (b->port);
	g_free (b->service);
	g_free (b->protocol);
	b->port = g_strdup (hit->port != NULL ? hit->port : "");
	b->service = fs_hit_service_name (hit);
	b->protocol = g_strdup (hit->protocol != NULL ? hit->protocol : "");
	b->inbound = inbound;
	b->count++;
	b->last_us = now_us;
	b->last_wall = g_get_real_time () / G_USEC_PER_SEC;

	expire_blocks (now_us);
	model_touch ();
}

void
fs_topology_note_hit (const FsHit *hit)
{
	fs_topology_note_hit_at (hit, g_get_monotonic_time ());
}

void
fs_topology_expire (gint64 now_us)
{
	if (expire_blocks (now_us))
		model_touch ();
}

/* -------------------------------------------------------------- model */

static TopoNode *
node_add (NodeKind kind, const gchar *title, gchar *detail,
          const gchar *key, guint count, guint inbound)
{
	TopoNode *n = g_new0 (TopoNode, 1);

	n->kind = kind;
	n->title = g_strdup (title);
	n->detail = detail;               /* taken */
	n->key = g_strdup (key);
	n->count = count;
	n->inbound = inbound;
	g_ptr_array_add (nodes, n);
	return n;
}

/* Which way `count' open connections were opened when `inbound' of them
 * came from outside.  One connection the other way is enough to make a
 * line mixed: a line drawn as outbound must carry nothing inbound. */
static FsTopologyFlow
flow_of (guint count, guint inbound)
{
	if (inbound == 0)
		return FS_TOPOLOGY_FLOW_OUTBOUND;
	return inbound >= count ? FS_TOPOLOGY_FLOW_INBOUND
	                        : FS_TOPOLOGY_FLOW_MIXED;
}

/* The line of the node added last: open connections, `inbound' of them
 * opened from outside. */
static void
link_add_open (gboolean left, guint count, guint inbound)
{
	TopoLink *l = g_new0 (TopoLink, 1);

	l->node = nodes->len - 1;
	l->left = left;
	l->count = count;
	l->flow = flow_of (count, inbound);
	g_ptr_array_add (links, l);
}

/* The line of the node added last: a blocked address. */
static void
link_add_blocked (guint count, gboolean inbound)
{
	TopoLink *l = g_new0 (TopoLink, 1);

	l->node = nodes->len - 1;
	l->count = count;
	l->flow = FS_TOPOLOGY_FLOW_NONE;
	l->blocked = TRUE;
	l->inbound = inbound;
	g_ptr_array_add (links, l);
}

static gint
find_node (NodeKind kind, const gchar *key)
{
	guint i;

	for (i = 0; nodes != NULL && i < nodes->len; i++) {
		const TopoNode *n = g_ptr_array_index (nodes, i);

		if (n->kind == kind && g_strcmp0 (n->key, key) == 0)
			return (gint) i;
	}
	return -1;
}

/* Builds the nodes and links from the last sample and the remembered
 * blocks.  The node under the keyboard keeps the focus when it is still
 * there. */
static void
rebuild_model (void)
{
	gboolean had_focus = focus_node >= 0;
	NodeKind focus_kind = NODE_SELF;
	gchar *focus_key = NULL;
	guint zone_count[2] = { 0, 0 }, zone_in[2] = { 0, 0 };
	TopoNode *self;
	guint i;

	ensure_data ();

	if (had_focus && nodes != NULL && (guint) focus_node < nodes->len) {
		const TopoNode *n = g_ptr_array_index (nodes, focus_node);

		focus_kind = n->kind;
		focus_key = g_strdup (n->key);
	}

	if (nodes != NULL)
		g_ptr_array_unref (nodes);
	if (links != NULL)
		g_ptr_array_unref (links);
	if (tallies != NULL)
		g_array_unref (tallies);
	nodes = g_ptr_array_new_with_free_func (node_free);
	links = g_ptr_array_new_with_free_func (g_free);

	self = node_add (NODE_SELF, _("This computer"),
	                 g_strdup (g_get_host_name ()), NULL, conns->len, 0);

	/* Programs, busiest first.  Five get a node each and the rest are
	 * merged, unless the rest is one program: then its own name says
	 * more than "Other programs" would. */
	tallies = tally_programs (0);
	n_named = tallies->len <= MAX_PROGRAMS + 1 ? tallies->len : MAX_PROGRAMS;

	for (i = 0; i < n_named; i++) {
		const Tally *t = &g_array_index (tallies, Tally, i);
		gchar *title = short_name (t->name);

		node_add (NODE_PROGRAM, title, connections_text (t->count),
		          t->name, t->count, t->inbound);
		link_add_open (TRUE, t->count, t->inbound);
		g_free (title);
	}

	if (tallies->len > n_named) {
		guint count = 0, inbound = 0, n_rest = tallies->len - n_named;
		gchar *a, *b;
		TopoNode *n;

		for (i = n_named; i < tallies->len; i++) {
			const Tally *t = &g_array_index (tallies, Tally, i);

			count += t->count;
			inbound += t->inbound;
		}
		a = connections_text (count);
		b = programs_text (n_rest);
		n = node_add (NODE_OTHER, _("Other programs"),
		              g_strdup_printf (_("%s from %s"), a, b), NULL, count,
		              inbound);
		n->programs = n_rest;
		link_add_open (TRUE, count, inbound);
		g_free (a);
		g_free (b);
	}

	/* Where they connect to. */
	for (i = 0; i < conns->len; i++) {
		const TopoConn *c = g_ptr_array_index (conns, i);
		guint z = c->local ? 0 : 1;

		zone_count[z]++;
		if (c->inbound)
			zone_in[z]++;
	}
	self->inbound = zone_in[0] + zone_in[1];
	for (i = 0; i < 2; i++) {
		GArray *who;
		TopoNode *n;

		if (zone_count[i] == 0)
			continue;
		who = tally_programs ((gint) i + 1);
		n = node_add (i == 0 ? NODE_LAN : NODE_NET,
		              i == 0 ? _("Local network") : _("Internet"),
		              connections_text (zone_count[i]), NULL,
		              zone_count[i], zone_in[i]);
		n->programs = who->len;
		link_add_open (FALSE, zone_count[i], zone_in[i]);
		g_array_unref (who);
	}

	/* What was turned away. */
	for (i = 0; i < blocks->len && i < MAX_BLOCKED_DRAWN; i++) {
		const TopoBlock *b = g_ptr_array_index (blocks, i);
		gchar *what = block_what (b);
		gchar *times = times_text (b->count);

		node_add (NODE_BLOCKED, b->remote,
		          g_strconcat (what, DOT, times, NULL), b->remote,
		          b->count, 0);
		link_add_blocked (b->count, b->inbound);
		g_free (what);
		g_free (times);
	}

	if (had_focus) {
		focus_node = find_node (focus_kind, focus_key);
		if (focus_node < 0)
			focus_node = 0;
	}
	g_free (focus_key);

	model_dirty = FALSE;
	sync_widgets ();
}

static void
ensure_model (void)
{
	if (model_dirty || nodes == NULL)
		rebuild_model ();
}

static TopoNode *
node_nth (guint index)
{
	return g_ptr_array_index (nodes, index);
}

static guint
count_blocked_links (void)
{
	guint i, n = 0;

	for (i = 0; links != NULL && i < links->len; i++)
		if (((const TopoLink *) g_ptr_array_index (links, i))->blocked)
			n++;
	return n;
}

void
fs_topology_set_connections (const GList *connections)
{
	take_connections (connections);
	conns_known = TRUE;
	model_dirty = TRUE;
	ensure_model ();
}

void
fs_topology_refresh (void)
{
	const FsBackend *backend = fs_backend ();

	if (backend == NULL || backend->list_connections == NULL) {
		take_connections (NULL);
		conns_known = FALSE;
	} else {
		GList *list = backend->list_connections ();

		take_connections (list);
		conns_known = TRUE;
		g_list_free_full (list, (GDestroyNotify) fs_connection_free);
	}

	expire_blocks (g_get_monotonic_time ());
	model_dirty = TRUE;
	ensure_model ();
}

guint
fs_topology_node_count (void)
{
	ensure_model ();
	return nodes->len;
}

const gchar *
fs_topology_node_title (guint index)
{
	ensure_model ();
	return index < nodes->len ? node_nth (index)->title : NULL;
}

const gchar *
fs_topology_node_detail (guint index)
{
	ensure_model ();
	return index < nodes->len ? node_nth (index)->detail : NULL;
}

guint
fs_topology_node_connections (guint index)
{
	ensure_model ();
	return index < nodes->len ? node_nth (index)->count : 0;
}

gint
fs_topology_find_node (const gchar *title)
{
	guint i;

	ensure_model ();
	for (i = 0; i < nodes->len; i++)
		if (g_strcmp0 (node_nth (i)->title, title) == 0)
			return (gint) i;
	return -1;
}

guint
fs_topology_link_count (void)
{
	ensure_model ();
	return links->len;
}

guint
fs_topology_blocked_link_count (void)
{
	ensure_model ();
	return count_blocked_links ();
}

guint
fs_topology_blocked_count (void)
{
	return blocks != NULL ? blocks->len : 0;
}

FsTopologyFlow
fs_topology_node_flow (guint index)
{
	guint i;

	ensure_model ();
	for (i = 0; i < links->len; i++) {
		const TopoLink *l = g_ptr_array_index (links, i);

		if (l->node == index)
			return l->flow;
	}
	return FS_TOPOLOGY_FLOW_NONE;
}

/* What stands where the programs would be when there are none. */
static const gchar *
empty_text (void)
{
	if (!conns_known)
		return _("This computer's open connections cannot be "
		         "listed here.");
	if (conns->len == 0)
		return _("No open connections right now.");
	return NULL;
}

const gchar *
fs_topology_empty_text (void)
{
	ensure_model ();
	return empty_text ();
}

/* ------------------------------------------------------------- layout */

/* Which of the three columns a node stands in. */
static gint
node_column (const TopoNode *n)
{
	switch (n->kind) {
	case NODE_PROGRAM:
	case NODE_OTHER:
		return 0;
	case NODE_SELF:
		return 1;
	default:
		return 2;
	}
}

static void
count_columns (guint *n_left, guint *n_zone, guint *n_block)
{
	guint i;

	*n_left = *n_zone = *n_block = 0;
	for (i = 0; i < nodes->len; i++) {
		switch (node_nth (i)->kind) {
		case NODE_PROGRAM:
		case NODE_OTHER:
			(*n_left)++;
			break;
		case NODE_LAN:
		case NODE_NET:
			(*n_zone)++;
			break;
		case NODE_BLOCKED:
			(*n_block)++;
			break;
		default:
			break;
		}
	}
}

static gdouble
stack_height (guint n, gdouble gap)
{
	return n == 0 ? 0.0 : n * NODE_H + (n - 1) * gap;
}

/* The right column: the destinations, then a caption and the blocked
 * addresses. */
static gdouble
right_height (guint n_zone, guint n_block, gdouble gap)
{
	gdouble h = stack_height (n_zone, gap);

	if (n_block > 0)
		h += (n_zone > 0 ? gap : 0.0) + SECTION_H +
		     stack_height (n_block, gap);
	return h;
}

/* The space between the nodes of a column: wider when the diagram is
 * taller than it needs to be, the same in both columns. */
static gdouble
node_gap (guint n_left, guint n_zone, guint n_block, gdouble inner_h)
{
	gdouble gap = NODE_GAP_MAX;
	guint n_right = n_zone + n_block;

	if (n_left > 1)
		gap = MIN (gap, (inner_h - n_left * NODE_H) / (n_left - 1));
	if (n_right > 1)
		gap = MIN (gap, (inner_h - n_right * NODE_H -
		                 (n_block > 0 ? SECTION_H : 0.0)) / (n_right - 1));
	return floor (MAX (gap, NODE_GAP));
}

/* This computer grows with the lines that meet it, so that each has its
 * own place on its edge. */
static gdouble
self_height (guint n_left, guint n_right)
{
	guint most = MAX (n_left, n_right);

	return MAX (88.0, 34.0 + (most > 0 ? most - 1 : 0) * PORT_GAP);
}

/* The height the diagram needs for the model it holds. */
static gint
needed_height (void)
{
	guint n_left, n_zone, n_block;
	gdouble h;

	count_columns (&n_left, &n_zone, &n_block);
	h = self_height (n_left, n_zone + n_block) + 2 * WALL_OVER +
	    WALL_LABEL_H;
	h = MAX (h, stack_height (n_left, NODE_GAP));
	h = MAX (h, right_height (n_zone, n_block, NODE_GAP));
	h += PAD_TOP + PAD_BOTTOM;
	return (gint) MAX (h, (gdouble) MIN_H);
}

/* Places every node for a diagram of this size: programs down the left,
 * This computer in the middle with the firewall bar on its right, the
 * destinations and the blocked addresses down the right.  Each column
 * is centred on the height. */
static void
layout (gdouble width, gdouble height)
{
	guint n_left, n_zone, n_block, n_right;
	guint i_left = 0, i_right = 0, i;
	gdouble side_w, centre_w, inner_h, gap, x_left, x_right, y_left, y_right;
	gdouble mid_y, step_left, step_right;
	TopoNode *self = node_nth (0);

	count_columns (&n_left, &n_zone, &n_block);
	n_right = n_zone + n_block;

	side_w = floor (CLAMP ((width - 2 * PAD_X) * 0.25, 150.0, 260.0));
	centre_w = floor (CLAMP (width * 0.19, 150.0, 210.0));
	inner_h = MAX (height - PAD_TOP - PAD_BOTTOM, 0.0);
	mid_y = PAD_TOP + inner_h / 2.0;
	gap = node_gap (n_left, n_zone, n_block, inner_h);

	self->w = centre_w;
	self->h = self_height (n_left, n_right);
	self->x = floor ((width - (centre_w + WALL_GAP + WALL_W)) / 2.0);
	self->y = floor (mid_y - WALL_LABEL_H / 2.0 - self->h / 2.0);
	self->y = MAX (self->y, PAD_TOP + WALL_OVER);
	wall_x = self->x + self->w + WALL_GAP;

	x_left = PAD_X;
	x_right = floor (width - PAD_X - side_w);
	flow_x0 = x_left + side_w;
	flow_x1 = x_right;
	y_left = floor (MAX (PAD_TOP,
	                     mid_y - stack_height (n_left, gap) / 2.0));
	y_right = floor (MAX (PAD_TOP,
	                      mid_y - right_height (n_zone, n_block, gap) / 2.0));

	for (i = 1; i < nodes->len; i++) {
		TopoNode *n = node_nth (i);

		n->w = side_w;
		n->h = NODE_H;
		if (node_column (n) == 0) {
			n->x = x_left;
			n->y = y_left;
			y_left += NODE_H + gap;
		} else {
			if (n->kind == NODE_BLOCKED && i_right == n_zone)
				y_right += SECTION_H;
			n->x = x_right;
			n->y = y_right;
			y_right += NODE_H + gap;
			i_right++;
		}
	}

	/* Where each line meets This computer: in the order of the nodes,
	 * so no two lines cross. */
	step_left = n_left > 1
		? MIN (PORT_GAP, (self->h - 34.0) / (n_left - 1)) : 0.0;
	step_right = n_right > 1
		? MIN (PORT_GAP, (self->h - 34.0) / (n_right - 1)) : 0.0;
	i_right = 0;
	for (i = 0; i < links->len; i++) {
		TopoLink *l = g_ptr_array_index (links, i);
		gdouble cy = self->y + self->h / 2.0;

		if (l->left) {
			l->port_y = floor (cy + (i_left - (n_left - 1) / 2.0) *
			                   step_left) + 0.5;
			i_left++;
		} else {
			l->port_y = floor (cy + (i_right - (n_right - 1) / 2.0) *
			                   step_right) + 0.5;
			i_right++;
		}
	}
}

/* The width to lay the diagram out in when its area is `width' wide.
 * The details panel lies over the right of the page; while it shows one
 * of this page's nodes, the diagram keeps to what is left of it, so the
 * node just opened and its neighbours stay in view and can be clicked.
 * Never less than the diagram's smallest width: in a window too narrow
 * for both, the right column goes under the panel as before.  The draw
 * handler and the hit test both ask here, so they cannot disagree. */
static gdouble
diagram_width (gdouble width)
{
	GtkWidget *drawer;
	gint x = 0;

	if (drawing_area == NULL || fs_drawer_owner () != &drawer_owner)
		return width;

	drawer = fs_drawer_widget ();
	if (!gtk_widget_get_mapped (drawer) ||
	    !gtk_widget_translate_coordinates (drawer, drawing_area, 0, 0,
	                                       &x, NULL))
		return width;
	return MIN (width, MAX ((gdouble) x, (gdouble) MIN_W));
}

static void
layout_for_area (void)
{
	gdouble w = MIN_W, h = needed_height ();

	if (drawing_area != NULL &&
	    gtk_widget_get_allocated_width (drawing_area) > 1) {
		w = diagram_width (gtk_widget_get_allocated_width (drawing_area));
		h = gtk_widget_get_allocated_height (drawing_area);
	}
	layout (w, h);
}

static gint
node_at (gdouble x, gdouble y)
{
	guint i;

	for (i = 0; nodes != NULL && i < nodes->len; i++) {
		const TopoNode *n = node_nth (i);

		if (x >= n->x && x < n->x + n->w && y >= n->y && y < n->y + n->h)
			return (gint) i;
	}
	return -1;
}

gint
fs_topology_diagram_width (void)
{
	return (gint) drawn_width;
}

gboolean
fs_topology_node_rect (guint index, GdkRectangle *rect)
{
	const TopoNode *n;

	ensure_model ();
	if (index >= nodes->len)
		return FALSE;

	layout_for_area ();
	n = node_nth (index);
	if (rect != NULL) {
		rect->x = (gint) n->x;
		rect->y = (gint) n->y;
		rect->width = (gint) n->w;
		rect->height = (gint) n->h;
	}
	return TRUE;
}

/* ------------------------------------------------------------ drawing */

typedef struct
{
	GdkRGBA accent, ring, bad, surface, node, node_hover, edge;
	GdkRGBA ink, ink_weak, ink_weaker;
} Palette;

/* Read at every draw, so the diagram follows Dark mode and the accent
 * colour like the rest of the window. */
static void
palette_read (Palette *p)
{
	fs_theme_color ("fs_accent",        "#5aa2ff", &p->accent);
	fs_theme_color ("fs_accent_fill",   "#007aff", &p->ring);
	fs_theme_color ("fs_bad",           "#ff6259", &p->bad);
	fs_theme_color ("fs_surface",       "#211e1e", &p->surface);
	fs_theme_color ("fs_surface_2",     "#2a2626", &p->node);
	fs_theme_color ("fs_surface_3",     "#353030", &p->node_hover);
	fs_theme_color ("fs_border_strong", "#4a4545", &p->edge);
	fs_theme_color ("fs_text_strong",   "#fdfcfc", &p->ink);
	fs_theme_color ("fs_text_weak",     "#a8a4a4", &p->ink_weak);
	fs_theme_color ("fs_text_weaker",   "#8f8a8a", &p->ink_weaker);
}

static void
ink (cairo_t *cr, const GdkRGBA *c, gdouble alpha)
{
	cairo_set_source_rgba (cr, c->red, c->green, c->blue, c->alpha * alpha);
}

static void
rounded_rect (cairo_t *cr, gdouble x, gdouble y, gdouble w, gdouble h,
              gdouble r)
{
	cairo_new_sub_path (cr);
	cairo_arc (cr, x + w - r, y + r,     r, -G_PI / 2, 0);
	cairo_arc (cr, x + w - r, y + h - r, r, 0,          G_PI / 2);
	cairo_arc (cr, x + r,     y + h - r, r, G_PI / 2,   G_PI);
	cairo_arc (cr, x + r,     y + r,     r, G_PI,       3 * G_PI / 2);
	cairo_close_path (cr);
}

/* A layout in the widget's own font (the theme's), scaled; with a
 * width it is cut to one line with an ellipsis, or wrapped. */
static PangoLayout *
text_layout (GtkWidget *widget, const gchar *text, gdouble scale,
             gboolean bold, gdouble width, PangoEllipsizeMode ellipsize)
{
	PangoLayout *layout = gtk_widget_create_pango_layout (widget, text);
	PangoFontDescription *desc = pango_font_description_copy (
		pango_context_get_font_description (
			pango_layout_get_context (layout)));
	gint size = pango_font_description_get_size (desc);

	if (size > 0 && scale != 1.0) {
		if (pango_font_description_get_size_is_absolute (desc))
			pango_font_description_set_absolute_size (desc,
			                                          size * scale);
		else
			pango_font_description_set_size (desc,
			                                 (gint) (size * scale));
	}
	if (bold)
		pango_font_description_set_weight (desc, PANGO_WEIGHT_SEMIBOLD);
	pango_layout_set_font_description (layout, desc);
	pango_font_description_free (desc);

	if (width > 0) {
		pango_layout_set_width (layout, (gint) (width * PANGO_SCALE));
		if (ellipsize != PANGO_ELLIPSIZE_NONE)
			pango_layout_set_ellipsize (layout, ellipsize);
		else
			pango_layout_set_wrap (layout, PANGO_WRAP_WORD_CHAR);
	}
	return layout;
}

/* [ draw_lines ] -- up to three lines of text, the block centred on the
 * height of the box.  The first is the title. */
static void
draw_lines (cairo_t *cr, GtkWidget *widget, const Palette *p,
            gdouble x, gdouble y, gdouble w, gdouble h,
            const gchar *title, PangoEllipsizeMode title_cut,
            const gchar *second, const gchar *third)
{
	const gchar *texts[3] = { title, second, third };
	PangoLayout *layouts[3] = { NULL, NULL, NULL };
	gint heights[3] = { 0, 0, 0 };
	gdouble total = 0.0, at;
	guint i, n = 0;

	for (i = 0; i < 3; i++) {
		if (is_blank (texts[i]))
			continue;
		layouts[i] = text_layout (widget, texts[i], i == 0 ? 1.0 : 0.92,
		                          i == 0, w,
		                          i == 0 ? title_cut : PANGO_ELLIPSIZE_END);
		pango_layout_get_pixel_size (layouts[i], NULL, &heights[i]);
		total += heights[i];
		n++;
	}
	if (n > 1)
		total += (n - 1) * 2.0;

	at = y + (h - total) / 2.0;
	for (i = 0; i < 3; i++) {
		if (layouts[i] == NULL)
			continue;
		ink (cr, i == 0 ? &p->ink : &p->ink_weak, 1.0);
		cairo_move_to (cr, x, floor (at));
		pango_cairo_show_layout (cr, layouts[i]);
		at += heights[i] + 2.0;
		g_object_unref (layouts[i]);
	}
}

static void
draw_caption (cairo_t *cr, GtkWidget *widget, const Palette *p,
              const gchar *text, gdouble x, gdouble y, gdouble w)
{
	PangoLayout *layout = text_layout (widget, text, 0.88, FALSE, w,
	                                   PANGO_ELLIPSIZE_END);

	ink (cr, &p->ink_weaker, 1.0);
	cairo_move_to (cr, x, y);
	pango_cairo_show_layout (cr, layout);
	g_object_unref (layout);
}

static gdouble
link_width (guint count)
{
	return 1.5 + 0.5 * (MIN (MAX (count, 1u), 6u) - 1);
}

static void
curve (cairo_t *cr, gdouble x1, gdouble y1, gdouble x2, gdouble y2)
{
	gdouble half = (x2 - x1) / 2.0;

	cairo_curve_to (cr, x1 + half, y1, x2 - half, y2, x2, y2);
}

/* A filled arrowhead with its tip at (x, y), pointing right for
 * dir > 0 and left otherwise.  Every line meets its node level, so no
 * angle is needed. */
static void
arrowhead (cairo_t *cr, gdouble x, gdouble y, gdouble dir, gdouble size)
{
	gdouble back = dir > 0 ? -size : size;

	cairo_move_to (cr, x, y);
	cairo_line_to (cr, x + back, y - size * 0.55);
	cairo_line_to (cr, x + back, y + size * 0.55);
	cairo_close_path (cr);
	cairo_fill (cr);
}

/* Where a line starts and ends, and which way it is heading at its
 * end: 1 for rightwards, -1 for leftwards. */
typedef struct
{
	gdouble x0, y0, x1, y1, dir;
} Trace;

/* [ trace_open ] -- the path of a line that carries open connections,
 * from where they were opened to where they lead.  A line that carries
 * both kinds is traced as an outbound one; it is drawn with no
 * direction (draw_open_link). */
static void
trace_open (cairo_t *cr, const TopoLink *l, Trace *t)
{
	const TopoNode *self = node_nth (0);
	const TopoNode *other = node_nth (l->node);
	gboolean reverse = l->flow == FS_TOPOLOGY_FLOW_INBOUND;
	gdouble oy = floor (other->y + other->h / 2.0) + 0.5;
	gdouble py = l->port_y;

	if (l->left) {
		gdouble ox = other->x + other->w, sx = self->x;

		if (!reverse) {
			cairo_move_to (cr, ox, oy);
			curve (cr, ox, oy, sx, py);
			*t = (Trace) { ox, oy, sx, py, 1.0 };
		} else {
			cairo_move_to (cr, sx, py);
			curve (cr, sx, py, ox, oy);
			*t = (Trace) { sx, py, ox, oy, -1.0 };
		}
	} else {
		gdouble ox = other->x, sx = self->x + self->w;
		gdouble wx = wall_x + WALL_W;

		if (!reverse) {
			cairo_move_to (cr, sx, py);
			cairo_line_to (cr, wx, py);
			curve (cr, wx, py, ox, oy);
			*t = (Trace) { sx, py, ox, oy, 1.0 };
		} else {
			cairo_move_to (cr, ox, oy);
			curve (cr, ox, oy, wx, py);
			cairo_line_to (cr, sx, py);
			*t = (Trace) { ox, oy, sx, py, -1.0 };
		}
	}
}

/* How far the dashes of a pattern `period' long have travelled. */
static gdouble
dash_offset (gdouble period)
{
	return -fmod (phase_s * FLOW_SPEED, period);
}

static void
draw_open_link (cairo_t *cr, const TopoLink *l, const Palette *p,
                gboolean moving)
{
	static const double dashes[2] = { 6.0, 10.0 };
	gboolean both = l->flow == FS_TOPOLOGY_FLOW_MIXED;
	gdouble lw = link_width (l->count);
	Trace t = { 0, 0, 0, 0, 1 };

	/* Dashes that ran one way along a line that carries both kinds
	 * would be wrong about some of them: such a line stands still. */
	if (both)
		moving = FALSE;

	cairo_set_line_width (cr, lw);
	cairo_set_line_cap (cr, CAIRO_LINE_CAP_BUTT);
	cairo_set_dash (cr, NULL, 0, 0);

	/* The line of the node under the pointer stands out a little. */
	trace_open (cr, l, &t);
	ink (cr, &p->accent,
	     (moving ? 0.30 : 0.70) + ((gint) l->node == hover_node ? 0.25 : 0.0));
	cairo_stroke (cr);

	if (moving) {
		trace_open (cr, l, &t);
		cairo_set_line_cap (cr, CAIRO_LINE_CAP_ROUND);
		cairo_set_dash (cr, dashes, 2, dash_offset (16.0));
		ink (cr, &p->accent, 0.95);
		cairo_stroke (cr);
		cairo_set_dash (cr, NULL, 0, 0);
	} else {
		ink (cr, &p->accent, 1.0);
		arrowhead (cr, t.x1, t.y1, t.dir, 7.0 + lw);
		if (both)
			arrowhead (cr, t.x0, t.y0, -t.dir, 7.0 + lw);
	}
}

/* Where the blocked marker of a line sits: against the firewall bar, on
 * the side the traffic came from. */
static gdouble
marker_x (const TopoLink *l)
{
	return l->inbound ? wall_x + WALL_W + 1.0 + MARK_R
	                  : wall_x - 1.0 - MARK_R;
}

/* A blocked line.  Inbound: dashes run from the remote address to the
 * firewall bar and stop there.  Outbound: they run from This computer
 * to the bar and stop there; the stretch beyond the bar, which nothing
 * travelled, is drawn faint and still. */
static void
draw_blocked_link (cairo_t *cr, const TopoLink *l, const Palette *p,
                   gboolean moving)
{
	static const double dashes[2] = { 5.0, 5.0 };
	static const double stub[2] = { 3.0, 3.0 };
	const TopoNode *self = node_nth (0);
	const TopoNode *other = node_nth (l->node);
	gdouble ox = other->x;
	gdouble oy = floor (other->y + other->h / 2.0) + 0.5;
	gdouble py = l->port_y, mx = marker_x (l);

	cairo_set_line_width (cr, 1.75);
	cairo_set_line_cap (cr, CAIRO_LINE_CAP_BUTT);

	if (l->inbound) {
		gdouble stop = mx + MARK_R;

		cairo_move_to (cr, ox, oy);
		curve (cr, ox, oy, stop, py);
		cairo_set_dash (cr, dashes, 2, moving ? dash_offset (10.0) : 0.0);
		ink (cr, &p->bad, 0.95);
		cairo_stroke (cr);
		cairo_set_dash (cr, NULL, 0, 0);
		if (!moving)
			arrowhead (cr, stop + 1.0, py, -1.0, 8.0);
	} else {
		gdouble wx = wall_x + WALL_W;

		cairo_move_to (cr, self->x + self->w, py);
		cairo_line_to (cr, mx - MARK_R, py);
		cairo_set_dash (cr, stub, 2, moving ? dash_offset (6.0) : 0.0);
		ink (cr, &p->bad, 0.95);
		cairo_stroke (cr);

		cairo_move_to (cr, wx, py);
		curve (cr, wx, py, ox, oy);
		cairo_set_dash (cr, dashes, 2, 0.0);
		ink (cr, &p->bad, 0.40);
		cairo_stroke (cr);
		cairo_set_dash (cr, NULL, 0, 0);
		ink (cr, &p->bad, 0.55);
		arrowhead (cr, ox, oy, 1.0, 8.0);
	}
}

/* The blocked marker: a filled disc with a bar across it. */
static void
draw_marker (cairo_t *cr, const Palette *p, gdouble x, gdouble y)
{
	cairo_set_dash (cr, NULL, 0, 0);
	ink (cr, &p->surface, 1.0);
	cairo_arc (cr, x, y, MARK_R + 1.5, 0, 2 * G_PI);
	cairo_fill (cr);
	ink (cr, &p->bad, 1.0);
	cairo_arc (cr, x, y, MARK_R, 0, 2 * G_PI);
	cairo_fill (cr);
	ink (cr, &p->surface, 1.0);
	cairo_set_line_width (cr, 2.0);
	cairo_set_line_cap (cr, CAIRO_LINE_CAP_BUTT);
	cairo_move_to (cr, x - 3.5, y);
	cairo_line_to (cr, x + 3.5, y);
	cairo_stroke (cr);
}

/* The firewall: a slim bar at This computer's right edge.  Solid while
 * the firewall runs, an empty outline while it is stopped. */
static void
draw_wall (cairo_t *cr, GtkWidget *widget, const Palette *p)
{
	const TopoNode *self = node_nth (0);
	gboolean running = firewall_running ();
	gboolean stopped = fs_statusview_get_state () == FS_FW_STOPPED;
	gdouble y = self->y - WALL_OVER, h = self->h + 2 * WALL_OVER;
	PangoLayout *layout;
	gint tw, th;

	cairo_set_dash (cr, NULL, 0, 0);
	ink (cr, &p->surface, 1.0);
	rounded_rect (cr, wall_x, y, WALL_W, h, WALL_W / 2.0);
	cairo_fill (cr);
	if (running) {
		ink (cr, &p->ink_weak, 1.0);
		rounded_rect (cr, wall_x, y, WALL_W, h, WALL_W / 2.0);
		cairo_fill (cr);
	} else {
		ink (cr, &p->ink_weaker, 1.0);
		cairo_set_line_width (cr, 1.0);
		rounded_rect (cr, wall_x + 0.5, y + 0.5, WALL_W - 1.0, h - 1.0,
		              (WALL_W - 1.0) / 2.0);
		cairo_stroke (cr);
	}

	layout = text_layout (widget, stopped ? _("StockFW (stopped)")
	                                      : _("StockFW"),
	                      0.88, FALSE, 0, PANGO_ELLIPSIZE_NONE);
	pango_layout_get_pixel_size (layout, &tw, &th);
	ink (cr, &p->ink_weaker, 1.0);
	cairo_move_to (cr, floor (wall_x + WALL_W - tw), floor (y + h + 5.0));
	pango_cairo_show_layout (cr, layout);
	g_object_unref (layout);
}

static void
draw_node (cairo_t *cr, GtkWidget *widget, const Palette *p, guint index,
           gboolean focused)
{
	const TopoNode *n = node_nth (index);
	gboolean hovered = (gint) index == hover_node;
	gboolean shown = drawer_marked && n->kind == drawer_kind &&
	                 g_strcmp0 (n->key, drawer_key) == 0;
	gchar *third = NULL;

	rounded_rect (cr, n->x + 0.5, n->y + 0.5, n->w - 1.0, n->h - 1.0, NODE_R);
	ink (cr, hovered ? &p->node_hover : &p->node, 1.0);
	cairo_fill_preserve (cr);
	cairo_set_dash (cr, NULL, 0, 0);
	if (shown) {
		cairo_set_line_width (cr, 1.5);
		ink (cr, &p->accent, 1.0);
	} else if (n->kind == NODE_BLOCKED) {
		cairo_set_line_width (cr, 1.0);
		ink (cr, &p->bad, hovered ? 1.0 : 0.65);
	} else {
		cairo_set_line_width (cr, 1.0);
		ink (cr, hovered ? &p->ink_weaker : &p->edge, 1.0);
	}
	cairo_stroke (cr);

	if (n->kind == NODE_SELF && conns_known)
		third = open_connections_text (n->count);
	draw_lines (cr, widget, p, n->x + NODE_PAD, n->y, n->w - 2 * NODE_PAD,
	            n->h, n->title,
	            n->kind == NODE_BLOCKED ? PANGO_ELLIPSIZE_MIDDLE
	                                    : PANGO_ELLIPSIZE_END,
	            n->detail, third);
	g_free (third);

	if (focused) {
		rounded_rect (cr, n->x - 2.0, n->y - 2.0, n->w + 4.0, n->h + 4.0,
		              NODE_R + 2.5);
		cairo_set_line_width (cr, 2.0);
		ink (cr, &p->ring, 0.85);
		cairo_stroke (cr);
	}
}

static void
set_hover (GtkWidget *widget, gint index)
{
	GdkWindow *window;

	if (index == hover_node)
		return;
	hover_node = index;

	window = gtk_widget_get_window (widget);
	if (window != NULL) {
		GdkCursor *hand = index >= 0
			? gdk_cursor_new_from_name (gtk_widget_get_display (widget),
			                            "pointer")
			: NULL;

		gdk_window_set_cursor (window, hand);
		if (hand != NULL)
			g_object_unref (hand);
	}
	gtk_widget_queue_draw (widget);
}

static gboolean
on_draw (GtkWidget *widget, cairo_t *cr, gpointer data)
{
	gdouble width = gtk_widget_get_allocated_width (widget);
	gdouble height = gtk_widget_get_allocated_height (widget);
	gdouble laid;
	gboolean moving = animations_enabled ();
	gboolean ring = gtk_widget_has_visible_focus (widget);
	GdkRectangle clip = { 0, 0, (gint) width, (gint) height };
	const gchar *empty;
	Palette p;
	guint i;

	(void) data;
	if (nodes == NULL || nodes->len == 0 || width < 2 || height < 2)
		return FALSE;

	palette_read (&p);
	if (!gdk_cairo_get_clip_rectangle (cr, &clip))
		return FALSE;

	/* A frame of the animation repaints the middle strip only.  When
	 * the drawer has moved since the last one, every node stands
	 * somewhere else: the rest is painted in the next frame. */
	laid = diagram_width (width);
	if (laid != drawn_width && clip.width < (gint) width)
		gtk_widget_queue_draw (widget);
	drawn_width = laid;
	layout (laid, height);

	drawer_marked = fs_drawer_owner () == &drawer_owner;

	/* The model may have changed under a pointer that did not move. */
	set_hover (widget, pointer_inside ? node_at (pointer_x, pointer_y) : -1);

	for (i = 0; i < links->len; i++) {
		const TopoLink *l = g_ptr_array_index (links, i);

		if (!l->blocked)
			draw_open_link (cr, l, &p, moving);
	}
	for (i = 0; i < links->len; i++) {
		const TopoLink *l = g_ptr_array_index (links, i);

		if (l->blocked)
			draw_blocked_link (cr, l, &p, moving);
	}

	draw_wall (cr, widget, &p);
	for (i = 0; i < links->len; i++) {
		const TopoLink *l = g_ptr_array_index (links, i);

		if (l->blocked)
			draw_marker (cr, &p, marker_x (l), l->port_y);
	}

	/* Captions over the columns, and over the blocked addresses. */
	for (i = 1; i < nodes->len; i++) {
		const TopoNode *n = node_nth (i);
		const TopoNode *before = node_nth (i - 1);
		const gchar *text = NULL;

		if (node_column (n) == 0 && node_column (before) != 0)
			text = _("Programs");
		else if (n->kind == NODE_BLOCKED && before->kind != NODE_BLOCKED)
			text = _("Blocked in the last 10 minutes");
		else if (node_column (n) == 2 && node_column (before) != 2)
			text = _("Connected to");
		if (text != NULL && n->x < clip.x + clip.width &&
		    n->x + n->w > clip.x)
			draw_caption (cr, widget, &p, text, n->x + 2.0, n->y - 22.0,
			              n->w - 2.0);
	}

	/* A frame of the animation repaints the middle strip only: the
	 * nodes outside it need no new text laid out. */
	for (i = 0; i < nodes->len; i++) {
		const TopoNode *n = node_nth (i);

		if (n->x - 4.0 < clip.x + clip.width && n->x + n->w + 4.0 > clip.x)
			draw_node (cr, widget, &p, i, ring && (gint) i == focus_node);
	}

	empty = empty_text ();
	if (empty != NULL) {
		const TopoNode *self = node_nth (0);
		PangoLayout *text = text_layout (widget, empty, 1.0, FALSE,
		                                 MAX (self->x - 2 * PAD_X, 60.0),
		                                 PANGO_ELLIPSIZE_NONE);
		gint th;

		pango_layout_get_pixel_size (text, NULL, &th);
		ink (cr, &p.ink_weak, 1.0);
		cairo_move_to (cr, PAD_X,
		               floor (self->y + (self->h - th) / 2.0));
		pango_cairo_show_layout (cr, text);
		g_object_unref (text);
	}

	return FALSE;
}

/* ---------------------------------------------------------- animation */

static gboolean
on_tick (GtkWidget *widget, GdkFrameClock *clock, gpointer data)
{
	gint64 now = gdk_frame_clock_get_frame_time (clock);

	(void) data;
	/* From the clock's time, not a count of frames: a 60 Hz and a
	 * 144 Hz screen show the same speed.  Starting from where the
	 * dashes stood keeps them from jumping when the page comes back. */
	if (tick_origin_us == 0)
		tick_origin_us = now - (gint64) (phase_s * G_USEC_PER_SEC);
	phase_s = (now - tick_origin_us) / (gdouble) G_USEC_PER_SEC;

	/* Only the strip the lines cross changes from frame to frame; the
	 * side columns are left as they were painted. */
	if (now - tick_drawn_us >= FRAME_US) {
		gboolean marked = fs_drawer_owner () == &drawer_owner;
		gdouble width = diagram_width (
			gtk_widget_get_allocated_width (widget));

		tick_drawn_us = now;
		/* The drawer closed, or is sliding: every node moves. */
		if (marked != drawer_marked || width != drawn_width)
			gtk_widget_queue_draw (widget);
		else if (flow_x1 > flow_x0)
			gtk_widget_queue_draw_area (widget, (gint) flow_x0 - 2, 0,
				(gint) (flow_x1 - flow_x0) + 4,
				gtk_widget_get_allocated_height (widget));
		else
			gtk_widget_queue_draw (widget);
	}
	return G_SOURCE_CONTINUE;
}

/* TRUE when the diagram has a line whose dashes travel: a blocked one,
 * or one whose open connections were all opened the same way. */
static gboolean
lines_move (void)
{
	guint i;

	for (i = 0; links != NULL && i < links->len; i++) {
		const TopoLink *l = g_ptr_array_index (links, i);

		if (l->blocked || l->flow != FS_TOPOLOGY_FLOW_MIXED)
			return TRUE;
	}
	return FALSE;
}

/* The lines move only while the diagram is on screen, has lines that
 * move, and GTK animations are on.  A page that is not the current
 * one, the table view and a hidden window all unmap the diagram. */
static void
anim_sync (void)
{
	gboolean want = drawing_area != NULL && area_mapped &&
	                lines_move () && animations_enabled ();

	if (want && tick_id == 0) {
		tick_origin_us = 0;
		tick_drawn_us = 0;
		tick_id = gtk_widget_add_tick_callback (drawing_area, on_tick,
		                                        NULL, NULL);
	} else if (!want && tick_id != 0) {
		if (drawing_area != NULL)
			gtk_widget_remove_tick_callback (drawing_area, tick_id);
		tick_id = 0;
	}
}

gboolean
fs_topology_animating (void)
{
	return tick_id != 0;
}

gboolean
fs_topology_polling (void)
{
	return poll_id != 0;
}

void
fs_topology_set_phase (gdouble seconds)
{
	phase_s = seconds;
	tick_origin_us = 0;
	if (drawing_area != NULL)
		gtk_widget_queue_draw (drawing_area);
}

gdouble
fs_topology_get_phase (void)
{
	return phase_s;
}

static void
update_legend_note (void)
{
	if (legend_note == NULL)
		return;

	gtk_label_set_text (GTK_LABEL (legend_note), animations_enabled ()
		? _("Movement shows open connections and the way they were "
		    "opened, not how much data moves. A blocked address stays "
		    "for 10 minutes after its last block.")
		: _("Arrows show the way open connections were opened, not "
		    "how much data moves. A blocked address stays for "
		    "10 minutes after its last block."));
}

static void
on_animations_notify (GObject *settings, GParamSpec *pspec, gpointer data)
{
	(void) settings;
	(void) pspec;
	(void) data;
	anim_sync ();
	update_legend_note ();
	if (legend != NULL)
		gtk_widget_queue_draw (legend);
	if (drawing_area != NULL)
		gtk_widget_queue_draw (drawing_area);
}

/* ------------------------------------------------------------ details */

/* A two-line row of a drawer list: what it is, and a quieter line
 * about it. */
static void
drawer_row (GtkWidget *list, const gchar *primary, const gchar *secondary,
            gboolean mono)
{
	GtkWidget *row = gtk_box_new (GTK_ORIENTATION_VERTICAL, 1);
	GtkWidget *label = gtk_label_new (primary);

	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_label_set_ellipsize (GTK_LABEL (label), PANGO_ELLIPSIZE_MIDDLE);
	gtk_label_set_selectable (GTK_LABEL (label), TRUE);
	gtk_widget_set_can_focus (label, FALSE);
	gtk_widget_set_tooltip_text (label, primary);
	add_class (label, "fs-drawer-value");
	if (mono)
		add_class (label, "mono");
	gtk_box_pack_start (GTK_BOX (row), label, FALSE, FALSE, 0);

	if (!is_blank (secondary)) {
		label = gtk_label_new (secondary);
		gtk_label_set_xalign (GTK_LABEL (label), 0.0);
		gtk_label_set_ellipsize (GTK_LABEL (label), PANGO_ELLIPSIZE_END);
		add_class (label, "fs-drawer-name");
		gtk_box_pack_start (GTK_BOX (row), label, FALSE, FALSE, 0);
	}
	gtk_box_pack_start (GTK_BOX (list), row, FALSE, FALSE, 0);
}

static void
drawer_more (GtkWidget *list, guint more)
{
	gchar *text;
	GtkWidget *label;

	if (more == 0)
		return;
	text = g_strdup_printf (_("and %u more"), more);
	label = gtk_label_new (text);
	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	add_class (label, "fs-drawer-name");
	gtk_box_pack_start (GTK_BOX (list), label, FALSE, FALSE, 0);
	g_free (text);
}

static void
drawer_count (GtkWidget *fields, const gchar *name, guint n)
{
	gchar *text = g_strdup_printf ("%u", n);

	fs_drawer_field (fields, name, text, FALSE);
	g_free (text);
}

/* "50 opened here, 1 opened from outside": the two kinds of connection
 * behind a line drawn with an arrowhead at each end.  NULL when there
 * is one kind only: then the line itself says which. */
static gchar *
split_text (guint count, guint inbound)
{
	if (inbound == 0 || inbound >= count)
		return NULL;
	return g_strdup_printf (_("%u opened here, %u opened from outside"),
	                        count - inbound, inbound);
}

/* The same in a drawer, as a field of its own. */
static void
drawer_split (GtkWidget *fields, guint count, guint inbound)
{
	gchar *text = split_text (count, inbound);

	if (text != NULL)
		fs_drawer_field (fields, _("Direction"), text, FALSE);
	g_free (text);
}

/* "HTTPS, port 443 . Outbound" */
static gchar *
conn_line (const TopoConn *c)
{
	GString *s = g_string_new (NULL);

	if (service_named (c->service))
		g_string_append (s, c->service);
	if (!is_blank (c->port)) {
		if (s->len > 0)
			g_string_append (s, ", ");
		g_string_append_printf (s, _("port %s"), c->port);
	}
	if (s->len > 0)
		g_string_append (s, DOT);
	g_string_append (s, c->inbound ? _("Inbound") : _("Outbound"));
	return g_string_free (s, FALSE);
}

/* The open connections of one program, or of every program that has no
 * node of its own (`program' NULL). */
static GtkWidget *
program_body (const gchar *program)
{
	GtkWidget *body = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	GtkWidget *fields = fs_drawer_fields_new ();
	GtkWidget *list = gtk_box_new (GTK_ORIENTATION_VERTICAL, 8);
	guint to_lan = 0, to_net = 0, shown = 0, total = 0, inbound = 0, i;

	for (i = 0; i < conns->len; i++) {
		const TopoConn *c = g_ptr_array_index (conns, i);
		gboolean mine;

		if (program != NULL) {
			mine = strcmp (c->program, program) == 0;
		} else {
			guint k;

			mine = TRUE;
			for (k = 0; k < n_named && mine; k++)
				mine = strcmp (c->program, g_array_index (
					tallies, Tally, k).name) != 0;
		}
		if (!mine)
			continue;

		total++;
		if (c->inbound)
			inbound++;
		if (c->local)
			to_lan++;
		else
			to_net++;
		if (shown < DRAWER_ROWS) {
			gchar *line = conn_line (c);
			gchar *with = program != NULL
				? line : g_strconcat (c->program, DOT, line, NULL);

			drawer_row (list, c->remote, with, TRUE);
			if (with != line)
				g_free (with);
			g_free (line);
			shown++;
		}
	}

	if (program != NULL)
		fs_drawer_field (fields, _("Program"), program, FALSE);
	drawer_count (fields, _("Open connections"), total);
	drawer_split (fields, total, inbound);
	if (to_lan > 0)
		drawer_count (fields, _("To the local network"), to_lan);
	if (to_net > 0)
		drawer_count (fields, _("To the internet"), to_net);
	gtk_box_pack_start (GTK_BOX (body), fields, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (body),
	                    fs_drawer_section (_("Open connections")),
	                    FALSE, FALSE, 0);
	drawer_more (list, total - shown);
	gtk_box_pack_start (GTK_BOX (body), list, FALSE, FALSE, 0);
	return body;
}

/* The programs that talk to the local network or to the internet. */
static GtkWidget *
zone_body (const TopoNode *n)
{
	GtkWidget *body = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	GtkWidget *list = gtk_box_new (GTK_ORIENTATION_VERTICAL, 8);
	GArray *who = tally_programs (n->kind == NODE_LAN ? 1 : 2);
	guint i;

	if (flow_of (n->count, n->inbound) == FS_TOPOLOGY_FLOW_MIXED) {
		GtkWidget *fields = fs_drawer_fields_new ();

		drawer_split (fields, n->count, n->inbound);
		gtk_box_pack_start (GTK_BOX (body), fields, FALSE, FALSE, 0);
	}

	gtk_box_pack_start (GTK_BOX (body), fs_drawer_section (_("Programs")),
	                    FALSE, FALSE, 0);
	for (i = 0; i < who->len && i < DRAWER_ROWS; i++) {
		const Tally *t = &g_array_index (who, Tally, i);
		gchar *count = connections_text (t->count);

		drawer_row (list, t->name, count, FALSE);
		g_free (count);
	}
	drawer_more (list, who->len > DRAWER_ROWS ? who->len - DRAWER_ROWS : 0);
	gtk_box_pack_start (GTK_BOX (body), list, FALSE, FALSE, 0);
	g_array_unref (who);
	return body;
}

static GtkWidget *
self_body (const TopoNode *n)
{
	GtkWidget *body = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	GtkWidget *fields = fs_drawer_fields_new ();
	guint to_lan = 0, to_net = 0, i;

	for (i = 0; i < conns->len; i++) {
		if (((const TopoConn *) g_ptr_array_index (conns, i))->local)
			to_lan++;
		else
			to_net++;
	}

	fs_drawer_field (fields, _("Name"), g_get_host_name (), FALSE);
	if (conns_known) {
		drawer_count (fields, _("Open connections"), conns->len);
		drawer_split (fields, n->count, n->inbound);
		drawer_count (fields, _("Programs"), tallies->len);
		drawer_count (fields, _("To the local network"), to_lan);
		drawer_count (fields, _("To the internet"), to_net);
		if (conns_inside > 0)
			drawer_count (fields, _("Inside this computer (not drawn)"),
			              conns_inside);
	} else {
		fs_drawer_field (fields, _("Open connections"),
		                 _("Cannot be listed here"), FALSE);
	}
	if (blocks_capped ()) {
		gchar *more = g_strdup_printf (_("More than %u"), blocks->len);

		fs_drawer_field (fields,
		                 _("Addresses blocked in the last 10 minutes"),
		                 more, FALSE);
		g_free (more);
	} else {
		drawer_count (fields,
		              _("Addresses blocked in the last 10 minutes"),
		              blocks->len);
	}
	gtk_box_pack_start (GTK_BOX (body), fields, FALSE, FALSE, 0);
	return body;
}

static void
run_show_in_events (gpointer data)
{
	fs_hitview_set_filter (data);
	fs_app_show_page (FS_PAGE_EVENTS);
}

static const TopoBlock *
find_block (const gchar *remote)
{
	guint i;

	for (i = 0; blocks != NULL && i < blocks->len; i++) {
		const TopoBlock *b = g_ptr_array_index (blocks, i);

		if (g_strcmp0 (b->remote, remote) == 0)
			return b;
	}
	return NULL;
}

/* One blocked address.  Sets the line under the drawer's title, to be
 * freed. */
static GtkWidget *
blocked_body (const TopoBlock *b, gchar **subtitle)
{
	GtkWidget *body = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	GtkWidget *fields = fs_drawer_fields_new ();
	gchar *what = block_what (b);
	gchar *first = clock_text (b->first_wall);
	gchar *last = clock_text (b->last_wall);
	gchar *often = g_strdup_printf (
		g_dngettext (NULL, "%u time, since %s", "%u times, since %s",
		             b->count), b->count, first);

	*subtitle = g_strdup_printf (b->inbound ? _("Blocked inbound %s")
	                                        : _("Blocked outbound %s"),
	                             what);

	fs_drawer_field (fields, _("Remote address"), b->remote, TRUE);
	fs_drawer_field (fields, _("Where it is"),
	                 b->local ? _("Local network") : _("Internet"), FALSE);
	fs_drawer_field (fields, _("Direction"),
	                 b->inbound ? _("Inbound: it tried to reach this "
	                                "computer")
	                            : _("Outbound: this computer tried to "
	                                "reach it"), FALSE);
	if (service_named (b->service))
		fs_drawer_field (fields, _("Service"), b->service, FALSE);
	fs_drawer_field (fields, _("Port"), b->port, TRUE);
	fs_drawer_field (fields, _("Protocol"), b->protocol, FALSE);
	fs_drawer_field (fields, _("Blocked"), often, FALSE);
	fs_drawer_field (fields, _("Last blocked"), last, FALSE);
	gtk_box_pack_start (GTK_BOX (body), fields, FALSE, FALSE, 0);

	g_free (what);
	g_free (first);
	g_free (last);
	g_free (often);
	return body;
}

/* How much of the page's width the drawer lies over once it has slid
 * in, while it shows one of this page's nodes; 0 otherwise, and where
 * no window hosts the drawer. */
static gint
drawer_overlap (void)
{
	GtkWidget *drawer, *host, *panel;
	gint panel_w = 0, right = 0;

	if (page == NULL || fs_drawer_owner () != &drawer_owner)
		return 0;

	drawer = fs_drawer_widget ();
	host = gtk_widget_get_parent (drawer);
	panel = gtk_bin_get_child (GTK_BIN (drawer));
	if (host == NULL || panel == NULL ||
	    !gtk_widget_translate_coordinates (page, host,
			gtk_widget_get_allocated_width (page), 0, &right, NULL))
		return 0;

	gtk_widget_get_preferred_width (panel, NULL, &panel_w);
	right -= gtk_widget_get_allocated_width (host) - panel_w;
	/* And the page's own gap between the card and the panel. */
	return right > 0 ? right + DRAWER_GAP : 0;
}

/* Keeps `widget' out from under the drawer by `want' pixels, or by as
 * many as it can give up without asking for a wider page. */
static void
reserve_end (GtkWidget *widget, gint want)
{
	gint min = 0, room;

	if (widget == NULL)
		return;
	/* The width it asks for counts the margin it has now. */
	gtk_widget_get_preferred_width (widget, &min, NULL);
	min -= gtk_widget_get_margin_end (widget);
	room = gtk_widget_get_allocated_width (page) - min;
	gtk_widget_set_margin_end (widget, CLAMP (want, 0, MAX (room, 0)));
}

/* While the drawer shows one of this page's nodes, the page keeps to
 * the width the drawer leaves: the caption and the legend wrap there
 * and the card ends where the panel begins, so nothing is cut off under
 * it.  The diagram has a smallest width of its own (diagram_width). */
static void
reserve_for_drawer (void)
{
	gint want = drawer_overlap ();

	reserve_end (top_bar, want);
	reserve_end (diagram_card, want);
}

static void
on_drawer_moved (GtkWidget *area)
{
	gtk_widget_queue_draw (area);
}

static void
on_drawer_revealed (GtkWidget *area)
{
	reserve_for_drawer ();
	gtk_widget_queue_draw (area);
}

/* The page is laid out beside the drawer, so it must hear when the
 * drawer opens, slides or closes; its own button, Escape and a page
 * switch close it without a word to this page.  Asked for once for
 * each diagram and drawer; the handlers go with either. */
static void
watch_drawer (void)
{
	GtkWidget *drawer;

	if (drawing_area == NULL)
		return;
	drawer = fs_drawer_widget ();
	if (g_signal_handler_find (drawer,
	                           G_SIGNAL_MATCH_FUNC | G_SIGNAL_MATCH_DATA,
	                           0, 0, NULL, on_drawer_moved,
	                           drawing_area) != 0)
		return;

	g_signal_connect_object (drawer, "size-allocate",
	                         G_CALLBACK (on_drawer_moved), drawing_area,
	                         G_CONNECT_SWAPPED);
	g_signal_connect_object (drawer, "notify::reveal-child",
	                         G_CALLBACK (on_drawer_revealed), drawing_area,
	                         G_CONNECT_SWAPPED);
}

/* Every label under `widget', one to a line: what a drawer body says,
 * for telling whether a newer one would say anything else. */
static void
collect_text (GtkWidget *widget, gpointer data)
{
	GString *text = data;

	if (GTK_IS_LABEL (widget)) {
		g_string_append (text, gtk_label_get_text (GTK_LABEL (widget)));
		g_string_append_c (text, '\n');
	} else if (GTK_IS_CONTAINER (widget)) {
		gtk_container_foreach (GTK_CONTAINER (widget), collect_text, text);
	}
}

/* [ show_node ] -- puts the details of node `index' of the present
 * model in the drawer.  FALSE when it has none to show.
 *
 * `refresh' is for details that are already on show: the drawer is
 * left alone when it would say the same, so that reading it, scrolling
 * it or selecting text in it is not disturbed every time the model is
 * rebuilt.  The keyboard is never moved here. */
static gboolean
show_node (guint index, gboolean refresh)
{
	const TopoNode *n = node_nth (index);
	const gchar *under = n->detail;
	gchar *subtitle = NULL;
	GtkWidget *body = NULL;
	FsDrawerAction action = {
		_("Show in Events"), "btn-primary", run_show_in_events, NULL
	};
	guint n_actions = 0;
	GString *text;

	switch (n->kind) {
	case NODE_SELF:
		body = self_body (n);
		break;
	case NODE_PROGRAM:
		subtitle = open_connections_text (n->count);
		body = program_body (n->key);
		break;
	case NODE_OTHER:
		body = program_body (NULL);
		break;
	case NODE_LAN:
	case NODE_NET: {
		gchar *a = open_connections_text (n->count);
		gchar *b = programs_text (n->programs);

		subtitle = g_strdup_printf (_("%s from %s"), a, b);
		body = zone_body (n);
		g_free (a);
		g_free (b);
		break;
	}
	case NODE_BLOCKED: {
		const TopoBlock *b = find_block (n->key);
		gchar *address;

		if (b == NULL)
			return FALSE;
		body = blocked_body (b, &subtitle);
		/* The action's data lives as long as the body it belongs
		 * to. */
		address = g_strdup (b->remote);
		g_object_set_data_full (G_OBJECT (body), "topology-address",
		                        address, g_free);
		action.data = address;
		n_actions = 1;
		break;
	}
	}
	if (subtitle != NULL)
		under = subtitle;

	text = g_string_new (n->title);
	g_string_append_c (text, '\n');
	g_string_append (text, under != NULL ? under : "");
	g_string_append_c (text, '\n');
	collect_text (body, text);

	if (refresh && fs_drawer_owner () == &drawer_owner &&
	    g_strcmp0 (text->str, drawer_text) == 0) {
		/* Nothing new to say: the body built for the comparison
		 * goes, and the one on show stays as it is. */
		g_object_ref_sink (body);
		gtk_widget_destroy (body);
		g_object_unref (body);
		g_string_free (text, TRUE);
	} else {
		fs_drawer_open (&drawer_owner, n->title, under, body,
		                n_actions > 0 ? &action : NULL, n_actions);
		watch_drawer ();
		reserve_for_drawer ();
		g_free (drawer_text);
		drawer_text = g_string_free (text, FALSE);
	}
	g_free (subtitle);

	if (drawer_kind != n->kind || g_strcmp0 (drawer_key, n->key) != 0) {
		g_free (drawer_key);
		drawer_kind = n->kind;
		drawer_key = g_strdup (n->key);
	}
	if (drawing_area != NULL)
		gtk_widget_queue_draw (drawing_area);
	return TRUE;
}

/* The model was rebuilt while the drawer shows one of its nodes: the
 * drawer follows, so it never says what the diagram beside it no
 * longer does.  A node that left the diagram (a program that closed
 * its connections, a block ten minutes old) takes its details with
 * it. */
static void
refresh_drawer (void)
{
	gint at;

	if (fs_drawer_owner () != &drawer_owner)
		return;

	at = find_node (drawer_kind, drawer_key);
	if (at < 0 || !show_node ((guint) at, TRUE))
		fs_drawer_close ();
}

gboolean
fs_topology_activate_node (guint index)
{
	/* The diagram is repainted a little after the blocks change
	 * (model_touch), and until then a click or Enter names a node of
	 * the picture still on screen, where a new block may since have
	 * moved every blocked address down by one.  The node is found
	 * again by what it is, not by where it was; one that has gone
	 * opens nothing. */
	if (model_dirty && nodes != NULL && index < nodes->len) {
		const TopoNode *n = node_nth (index);
		NodeKind kind = n->kind;
		gchar *key = g_strdup (n->key);
		gint at;

		ensure_model ();
		at = find_node (kind, key);
		g_free (key);
		if (at < 0)
			return FALSE;
		index = (guint) at;
	}

	ensure_model ();
	if (index >= nodes->len)
		return FALSE;
	return show_node (index, FALSE);
}

/* The first lines of a node's tooltip: its whole name, and its count. */
static gchar *
tooltip_head (const TopoNode *n)
{
	gchar *a, *b, *text;

	switch (n->kind) {
	case NODE_SELF:
		if (!conns_known)
			return g_strdup_printf ("%s (%s)", n->title, n->detail);
		a = open_connections_text (n->count);
		text = g_strdup_printf ("%s (%s)\n%s", n->title, n->detail, a);
		g_free (a);
		return text;
	case NODE_PROGRAM:
		a = open_connections_text (n->count);
		text = g_strdup_printf ("%s\n%s", n->key, a);
		g_free (a);
		return text;
	case NODE_BLOCKED: {
		const TopoBlock *blk = find_block (n->key);

		if (blk == NULL)
			return g_strdup (n->title);
		a = clock_text (blk->last_wall);
		text = g_strdup_printf (_("%s\n%s, last at %s"), n->title,
		                        n->detail, a);
		g_free (a);
		return text;
	}
	default:
		a = open_connections_text (n->count);
		b = programs_text (n->programs);
		text = g_strdup_printf (_("%s\n%s from %s"), n->title, a, b);
		g_free (a);
		g_free (b);
		return text;
	}
}

/* What the tooltip of a node says.  Behind a line with an arrowhead at
 * each end it also counts the connections opened each way. */
static gchar *
node_tooltip (const TopoNode *n)
{
	gchar *head = tooltip_head (n);
	gchar *split = n->kind != NODE_BLOCKED && conns_known
		? split_text (n->count, n->inbound) : NULL;
	gchar *text;

	if (split == NULL)
		return head;
	text = g_strconcat (head, "\n", split, NULL);
	g_free (head);
	g_free (split);
	return text;
}

gchar *
fs_topology_node_tooltip (guint index)
{
	ensure_model ();
	return index < nodes->len ? node_tooltip (node_nth (index)) : NULL;
}

/* -------------------------------------------------- pointer and keys */

static gboolean
on_motion (GtkWidget *widget, GdkEventMotion *event, gpointer data)
{
	(void) data;
	pointer_inside = TRUE;
	pointer_x = event->x;
	pointer_y = event->y;
	if (nodes != NULL && nodes->len > 0) {
		layout_for_area ();
		set_hover (widget, node_at (event->x, event->y));
	}
	return FALSE;
}

static gboolean
on_leave (GtkWidget *widget, GdkEventCrossing *event, gpointer data)
{
	(void) event;
	(void) data;
	pointer_inside = FALSE;
	set_hover (widget, -1);
	return FALSE;
}

static gboolean
on_button_press (GtkWidget *widget, GdkEventButton *event, gpointer data)
{
	gint index;

	(void) data;
	if (event->type != GDK_BUTTON_PRESS || event->button != 1 ||
	    nodes == NULL || nodes->len == 0)
		return FALSE;

	gtk_widget_grab_focus (widget);
	layout_for_area ();
	index = node_at (event->x, event->y);
	if (index < 0)
		return FALSE;

	focus_node = index;
	fs_topology_activate_node ((guint) index);
	gtk_widget_queue_draw (widget);
	return TRUE;
}

/* The node the keyboard moves to: up and down within a column, left
 * and right to the node of the next column that is nearest in height. */
static gint
focus_neighbour (gint from, gint dx, gint dy)
{
	const TopoNode *here = node_nth ((guint) from);
	gint column = node_column (here);
	gint best = from;
	gdouble best_gap = G_MAXDOUBLE;
	guint i;

	if (dy != 0) {
		gint i_from = from + dy;

		for (; i_from >= 0 && (guint) i_from < nodes->len; i_from += dy)
			if (node_column (node_nth ((guint) i_from)) == column)
				return i_from;
		return from;
	}

	for (i = 0; i < nodes->len; i++) {
		const TopoNode *n = node_nth (i);
		gdouble gap;

		if (node_column (n) != column + dx)
			continue;
		gap = fabs ((n->y + n->h / 2.0) - (here->y + here->h / 2.0));
		if (gap < best_gap) {
			best_gap = gap;
			best = (gint) i;
		}
	}
	return best;
}

static gboolean
on_key_press (GtkWidget *widget, GdkEventKey *event, gpointer data)
{
	gint to;

	(void) data;
	if (nodes == NULL || nodes->len == 0)
		return FALSE;
	if (focus_node < 0 || (guint) focus_node >= nodes->len)
		focus_node = 0;
	layout_for_area ();
	to = focus_node;

	switch (event->keyval) {
	case GDK_KEY_Up:
	case GDK_KEY_KP_Up:
		to = focus_neighbour (focus_node, 0, -1);
		break;
	case GDK_KEY_Down:
	case GDK_KEY_KP_Down:
		to = focus_neighbour (focus_node, 0, 1);
		break;
	case GDK_KEY_Left:
	case GDK_KEY_KP_Left:
		to = focus_neighbour (focus_node, -1, 0);
		break;
	case GDK_KEY_Right:
	case GDK_KEY_KP_Right:
		to = focus_neighbour (focus_node, 1, 0);
		break;
	case GDK_KEY_Return:
	case GDK_KEY_KP_Enter:
	case GDK_KEY_ISO_Enter:
	case GDK_KEY_space:
		fs_topology_activate_node ((guint) focus_node);
		return TRUE;
	default:
		return FALSE;
	}

	/* The arrows stay in the diagram; Tab leaves it.  While the drawer
	 * shows one of the nodes it follows the ring, so that the panel
	 * always names what has the keyboard. */
	if (to != focus_node) {
		focus_node = to;
		if (fs_drawer_owner () == &drawer_owner)
			fs_topology_activate_node ((guint) to);
	}
	gtk_widget_queue_draw (widget);
	return TRUE;
}

static gboolean
on_focus_change (GtkWidget *widget, GdkEventFocus *event, gpointer data)
{
	(void) data;
	if (event->in && focus_node < 0)
		focus_node = 0;
	gtk_widget_queue_draw (widget);
	return FALSE;
}

static gboolean
on_query_tooltip (GtkWidget *widget, gint x, gint y, gboolean keyboard,
                  GtkTooltip *tooltip, gpointer data)
{
	const TopoNode *n;
	GdkRectangle area;
	gchar *text;
	gint index;

	(void) widget;
	(void) data;
	if (nodes == NULL || nodes->len == 0)
		return FALSE;

	layout_for_area ();
	index = keyboard ? focus_node : node_at (x, y);
	if (index < 0 || (guint) index >= nodes->len)
		return FALSE;

	n = node_nth ((guint) index);
	text = node_tooltip (n);
	gtk_tooltip_set_text (tooltip, text);
	g_free (text);

	area.x = (gint) n->x;
	area.y = (gint) n->y;
	area.width = (gint) n->w;
	area.height = (gint) n->h;
	gtk_tooltip_set_tip_area (tooltip, &area);
	return TRUE;
}

static void
on_area_map (GtkWidget *widget, gpointer data)
{
	(void) widget;
	(void) data;
	area_mapped = TRUE;
	anim_sync ();
}

static void
on_area_unmap (GtkWidget *widget, gpointer data)
{
	(void) widget;
	(void) data;
	area_mapped = FALSE;
	pointer_inside = FALSE;
	hover_node = -1;
	anim_sync ();
}

/* -------------------------------------------------------------- table */

static void
table_set_nth (guint row, const gchar *program, const gchar *remote,
               const gchar *port, const gchar *service,
               const gchar *direction, const gchar *status)
{
	GtkTreeModel *model = GTK_TREE_MODEL (list_store);
	GtkTreeIter iter;

	if (!gtk_tree_model_iter_nth_child (model, &iter, NULL, (gint) row))
		gtk_list_store_append (list_store, &iter);
	gtk_list_store_set (list_store, &iter,
	                    COL_PROGRAM, program,
	                    COL_REMOTE, remote,
	                    COL_PORT, port,
	                    COL_SERVICE, service,
	                    COL_DIRECTION, direction,
	                    COL_STATUS, status,
	                    -1);
}

/* One row for each open connection, then one for each blocked address.
 * Rows are rewritten in place so a selection or a scroll position is
 * not lost every three seconds. */
static void
fill_table (void)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	guint row = 0, i;

	if (list_store == NULL)
		return;
	ensure_data ();

	for (i = 0; i < conns->len; i++) {
		const TopoConn *c = g_ptr_array_index (conns, i);

		table_set_nth (row++, c->program, c->remote, c->port, c->service,
		               c->inbound ? _("Inbound") : _("Outbound"),
		               _("Open"));
	}
	for (i = 0; i < blocks->len; i++) {
		const TopoBlock *b = g_ptr_array_index (blocks, i);
		gchar *status = g_strdup_printf (
			g_dngettext (NULL, "Blocked %u time", "Blocked %u times",
			             b->count), b->count);

		table_set_nth (row++, "", b->remote, b->port, b->service,
		               b->inbound ? _("Inbound") : _("Outbound"), status);
		g_free (status);
	}

	model = GTK_TREE_MODEL (list_store);
	while (gtk_tree_model_iter_nth_child (model, &iter, NULL, (gint) row))
		gtk_list_store_remove (list_store, &iter);
}

guint
fs_topology_table_rows (void)
{
	ensure_model ();
	fill_table ();
	return list_store != NULL
		? (guint) gtk_tree_model_iter_n_children (
			GTK_TREE_MODEL (list_store), NULL)
		: 0;
}

void
fs_topology_set_table (gboolean table)
{
	table_shown = table;
	if (stack == NULL)
		return;

	if (table)
		fill_table ();
	gtk_stack_set_visible_child_name (GTK_STACK (stack),
	                                  table ? "table" : "graph");
	if (table_toggle != NULL) {
		syncing = TRUE;
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (table_toggle),
		                              table);
		syncing = FALSE;
	}
}

static void
on_table_toggled (GtkToggleButton *button, gpointer data)
{
	(void) data;
	if (!syncing)
		fs_topology_set_table (gtk_toggle_button_get_active (button));
}

/* ------------------------------------------------------------ widgets */

/* The sentence above the diagram: what it is showing, in numbers. */
static gchar *
caption_text (void)
{
	GString *s = g_string_new (NULL);
	const gchar *empty = empty_text ();
	guint n_blocked = blocks->len;

	if (empty != NULL) {
		g_string_append (s, empty);
	} else {
		gchar *a = open_connections_text (conns->len);
		gchar *b = programs_text (tallies->len);

		g_string_append_printf (s, _("%s from %s."), a, b);
		g_free (a);
		g_free (b);
	}

	if (conns_inside > 0) {
		g_string_append_c (s, ' ');
		g_string_append_printf (s, g_dngettext (NULL,
			"%u more stays inside this computer and is not drawn.",
			"%u more stay inside this computer and are not drawn.",
			conns_inside), conns_inside);
	}

	g_string_append_c (s, ' ');
	if (n_blocked == 0)
		g_string_append (s, _("Nothing was blocked in the last "
		                      "10 minutes (counted since StockFW "
		                      "opened)."));
	else if (blocks_capped ())
		/* Past the cap the number is a floor, and the table is not
		 * the whole list either. */
		g_string_append_printf (s, _("More than %u addresses were "
			"blocked in the last 10 minutes (counted since StockFW "
			"opened)."), n_blocked);
	else
		g_string_append_printf (s, g_dngettext (NULL,
			"%u address was blocked in the last 10 minutes (counted "
			"since StockFW opened).",
			"%u addresses were blocked in the last 10 minutes "
			"(counted since StockFW opened).",
			n_blocked), n_blocked);

	if (n_blocked > MAX_BLOCKED_DRAWN) {
		g_string_append_c (s, ' ');
		if (blocks_capped ())
			g_string_append_printf (s, _("The diagram draws the newest "
				"%u; the table lists the newest %u."),
				(guint) MAX_BLOCKED_DRAWN, n_blocked);
		else
			g_string_append_printf (s, _("The diagram draws the newest "
				"%u; the table lists them all."),
				(guint) MAX_BLOCKED_DRAWN);
	}
	return g_string_free (s, FALSE);
}

/* The model was rebuilt: bring what shows it up to date. */
static void
sync_widgets (void)
{
	if (caption_label != NULL) {
		gchar *text = caption_text ();

		gtk_label_set_text (GTK_LABEL (caption_label), text);
		g_free (text);
	}
	if (table_shown)
		fill_table ();
	if (drawing_area != NULL) {
		gtk_widget_set_size_request (drawing_area, MIN_W, needed_height ());
		gtk_widget_queue_draw (drawing_area);
	}
	refresh_drawer ();
	anim_sync ();
}

static gboolean
on_poll (gpointer data)
{
	(void) data;
	fs_topology_refresh ();
	return G_SOURCE_CONTINUE;
}

/* The backend is asked only while the page is on show. */
static void
on_page_map (GtkWidget *widget, gpointer data)
{
	(void) widget;
	(void) data;
	page_mapped = TRUE;
	fs_topology_refresh ();
	if (poll_id == 0)
		poll_id = g_timeout_add (POLL_MS, on_poll, NULL);
}

static void
stop_sources (void)
{
	if (poll_id != 0) {
		g_source_remove (poll_id);
		poll_id = 0;
	}
	if (rebuild_id != 0) {
		g_source_remove (rebuild_id);
		rebuild_id = 0;
	}
}

static void
on_page_unmap (GtkWidget *widget, gpointer data)
{
	(void) widget;
	(void) data;
	page_mapped = FALSE;
	stop_sources ();
}

static void
on_page_destroy (GtkWidget *widget, gpointer data)
{
	(void) data;
	if (widget != page)
		return;

	page_mapped = FALSE;
	area_mapped = FALSE;
	stop_sources ();
	anim_sync ();

	if (anim_settings != NULL && anim_handler != 0)
		g_signal_handler_disconnect (anim_settings, anim_handler);
	anim_settings = NULL;
	anim_handler = 0;

	if (fs_drawer_owner () == &drawer_owner)
		fs_drawer_close ();
	g_clear_pointer (&drawer_text, g_free);
	drawn_width = 0.0;

	page = NULL;
	top_bar = NULL;
	diagram_card = NULL;
	drawing_area = NULL;
	stack = NULL;
	table_toggle = NULL;
	caption_label = NULL;
	legend = NULL;
	legend_note = NULL;
	list_store = NULL;
	table_shown = FALSE;
	hover_node = -1;
	focus_node = -1;
	pointer_inside = FALSE;
}

/* What a sample in the legend shows. */
enum
{
	SWATCH_OPEN,
	SWATCH_BOTH,          /* open connections opened both ways */
	SWATCH_BLOCKED
};

/* The legend's samples: a line as the diagram draws an open connection,
 * one as it draws connections opened both ways, and one as it draws a
 * block, marker included. */
static gboolean
on_swatch_draw (GtkWidget *widget, cairo_t *cr, gpointer data)
{
	static const double open_dashes[2] = { 6.0, 10.0 };
	static const double block_dashes[2] = { 5.0, 5.0 };
	gint kind = GPOINTER_TO_INT (data);
	gdouble w = gtk_widget_get_allocated_width (widget);
	gdouble y = floor (gtk_widget_get_allocated_height (widget) / 2.0) + 0.5;
	Palette p;

	palette_read (&p);
	if (kind == SWATCH_BLOCKED) {
		cairo_set_line_width (cr, 1.75);
		cairo_set_dash (cr, block_dashes, 2, 0);
		ink (cr, &p.bad, 0.95);
		cairo_move_to (cr, MARK_R * 2 + 1.0, y);
		cairo_line_to (cr, w, y);
		cairo_stroke (cr);
		draw_marker (cr, &p, MARK_R + 1.5, y);
	} else if (kind == SWATCH_BOTH) {
		/* Still, whatever the animation setting, as in the diagram. */
		cairo_set_line_width (cr, 2.5);
		ink (cr, &p.accent, 0.70);
		cairo_move_to (cr, 6.0, y);
		cairo_line_to (cr, w - 6.0, y);
		cairo_stroke (cr);
		ink (cr, &p.accent, 1.0);
		arrowhead (cr, 0, y, -1.0, 9.5);
		arrowhead (cr, w, y, 1.0, 9.5);
	} else if (animations_enabled ()) {
		cairo_set_line_width (cr, 2.5);
		ink (cr, &p.accent, 0.30);
		cairo_move_to (cr, 0, y);
		cairo_line_to (cr, w, y);
		cairo_stroke (cr);
		cairo_set_line_cap (cr, CAIRO_LINE_CAP_ROUND);
		cairo_set_dash (cr, open_dashes, 2, -3.0);
		ink (cr, &p.accent, 0.95);
		cairo_move_to (cr, 0, y);
		cairo_line_to (cr, w, y);
		cairo_stroke (cr);
	} else {
		cairo_set_line_width (cr, 2.5);
		ink (cr, &p.accent, 0.70);
		cairo_move_to (cr, 0, y);
		cairo_line_to (cr, w - 6.0, y);
		cairo_stroke (cr);
		ink (cr, &p.accent, 1.0);
		arrowhead (cr, w, y, 1.0, 9.5);
	}
	return FALSE;
}

static void
legend_item (GtkWidget *row, gint kind, const gchar *text)
{
	GtkWidget *swatch = gtk_drawing_area_new ();
	GtkWidget *label = gtk_label_new (text);

	gtk_widget_set_size_request (swatch, 36, 16);
	gtk_widget_set_valign (swatch, GTK_ALIGN_CENTER);
	g_signal_connect (swatch, "draw", G_CALLBACK (on_swatch_draw),
	                  GINT_TO_POINTER (kind));
	add_class (label, "chart-legend");
	gtk_widget_set_margin_end (label, 12);
	gtk_box_pack_start (GTK_BOX (row), swatch, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (row), label, FALSE, FALSE, 0);
}

static void
table_column (GtkWidget *view, const gchar *title, gint column,
              gboolean expand)
{
	GtkCellRenderer *cell = gtk_cell_renderer_text_new ();
	GtkTreeViewColumn *col = gtk_tree_view_column_new_with_attributes (
		title, cell, "text", column, NULL);

	g_object_set (cell, "xpad", 8, NULL);
	if (expand) {
		g_object_set (cell, "ellipsize", PANGO_ELLIPSIZE_MIDDLE, NULL);
		gtk_tree_view_column_set_expand (col, TRUE);
		gtk_tree_view_column_set_min_width (col, 140);
	}
	gtk_tree_view_column_set_resizable (col, TRUE);
	gtk_tree_view_append_column (GTK_TREE_VIEW (view), col);
}

GtkWidget *
fs_topology_page (void)
{
	GtkWidget *bar, *card, *view, *scroll, *row;
	AtkObject *atk;

	ensure_data ();

	page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	/* The window's page frame supplies the margins. */

	/* ---- what is on show, and the switch to the table ---- */
	bar = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);

	caption_label = gtk_label_new (NULL);
	gtk_widget_set_name (caption_label, "topology-caption");
	gtk_label_set_xalign (GTK_LABEL (caption_label), 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (caption_label), TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (caption_label), 80);
	gtk_widget_set_valign (caption_label, GTK_ALIGN_CENTER);
	add_class (caption_label, "muted");
	gtk_box_pack_start (GTK_BOX (bar), caption_label, TRUE, TRUE, 0);

	/* At the end of the row, which the details panel would lie over:
	 * reserve_for_drawer () moves the row's end out from under it, or
	 * this button could be reached with Tab but not seen or clicked. */
	table_toggle = gtk_toggle_button_new_with_label (_("Show as table"));
	gtk_widget_set_name (table_toggle, "topology-table-toggle");
	add_class (table_toggle, "btn-subtle");
	gtk_widget_set_valign (table_toggle, GTK_ALIGN_START);
	gtk_widget_set_tooltip_text (table_toggle,
		_("List every open connection and the blocked addresses"));
	g_signal_connect (table_toggle, "toggled",
	                  G_CALLBACK (on_table_toggled), NULL);
	gtk_box_pack_end (GTK_BOX (bar), table_toggle, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (page), bar, FALSE, FALSE, 0);
	top_bar = bar;

	/* ---- the diagram or the table, and the legend under it ---- */
	card = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	add_class (card, "card");

	stack = gtk_stack_new ();
	gtk_widget_set_hexpand (stack, TRUE);
	gtk_widget_set_vexpand (stack, TRUE);

	drawing_area = gtk_drawing_area_new ();
	gtk_widget_set_name (drawing_area, "topology-diagram");
	gtk_widget_set_size_request (drawing_area, MIN_W, MIN_H);
	gtk_widget_set_can_focus (drawing_area, TRUE);
	gtk_widget_set_has_tooltip (drawing_area, TRUE);
	gtk_widget_add_events (drawing_area, GDK_POINTER_MOTION_MASK |
	                       GDK_LEAVE_NOTIFY_MASK | GDK_BUTTON_PRESS_MASK |
	                       GDK_KEY_PRESS_MASK | GDK_FOCUS_CHANGE_MASK);
	g_signal_connect (drawing_area, "draw", G_CALLBACK (on_draw), NULL);
	g_signal_connect (drawing_area, "motion-notify-event",
	                  G_CALLBACK (on_motion), NULL);
	g_signal_connect (drawing_area, "leave-notify-event",
	                  G_CALLBACK (on_leave), NULL);
	g_signal_connect (drawing_area, "button-press-event",
	                  G_CALLBACK (on_button_press), NULL);
	g_signal_connect (drawing_area, "key-press-event",
	                  G_CALLBACK (on_key_press), NULL);
	g_signal_connect (drawing_area, "focus-in-event",
	                  G_CALLBACK (on_focus_change), NULL);
	g_signal_connect (drawing_area, "focus-out-event",
	                  G_CALLBACK (on_focus_change), NULL);
	g_signal_connect (drawing_area, "query-tooltip",
	                  G_CALLBACK (on_query_tooltip), NULL);
	g_signal_connect (drawing_area, "map", G_CALLBACK (on_area_map), NULL);
	g_signal_connect (drawing_area, "unmap", G_CALLBACK (on_area_unmap),
	                  NULL);
	atk = gtk_widget_get_accessible (drawing_area);
	if (atk != NULL) {
		atk_object_set_name (atk, _("Topology diagram"));
		atk_object_set_description (atk,
			_("Use the arrow keys to move between the programs, this "
			  "computer and what it is connected to; Enter opens the "
			  "details. Show as table lists every connection."));
	}
	gtk_stack_add_named (GTK_STACK (stack), drawing_area, "graph");

	list_store = gtk_list_store_new (N_COLS, G_TYPE_STRING, G_TYPE_STRING,
	                                 G_TYPE_STRING, G_TYPE_STRING,
	                                 G_TYPE_STRING, G_TYPE_STRING);
	view = gtk_tree_view_new_with_model (GTK_TREE_MODEL (list_store));
	g_object_unref (list_store);
	gtk_widget_set_name (view, "topology-table");
	add_class (view, "data-grid");
	table_column (view, _("Program"), COL_PROGRAM, TRUE);
	table_column (view, _("Remote address"), COL_REMOTE, TRUE);
	table_column (view, _("Port"), COL_PORT, FALSE);
	table_column (view, _("Service"), COL_SERVICE, FALSE);
	table_column (view, _("Direction"), COL_DIRECTION, FALSE);
	table_column (view, _("Status"), COL_STATUS, FALSE);
	atk = gtk_widget_get_accessible (view);
	if (atk != NULL)
		atk_object_set_name (atk, _("Open connections and blocked "
		                            "addresses"));

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_min_content_height (
		GTK_SCROLLED_WINDOW (scroll), MIN_H);
	gtk_container_add (GTK_CONTAINER (scroll), view);
	gtk_stack_add_named (GTK_STACK (stack), scroll, "table");

	gtk_box_pack_start (GTK_BOX (card), stack, TRUE, TRUE, 0);

	/* The samples in a row and the note under them: beside them it had
	 * a few words to a line once the card was narrow (next to the
	 * drawer, or in a small window). */
	legend = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
	gtk_widget_set_name (legend, "topology-legend");
	add_class (legend, "card-foot");
	row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	legend_item (row, SWATCH_OPEN, _("Open connections"));
	legend_item (row, SWATCH_BOTH, _("Opened both ways"));
	legend_item (row, SWATCH_BLOCKED, _("Blocked at the firewall"));
	gtk_box_pack_start (GTK_BOX (legend), row, FALSE, FALSE, 0);
	legend_note = gtk_label_new (NULL);
	gtk_label_set_xalign (GTK_LABEL (legend_note), 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (legend_note), TRUE);
	add_class (legend_note, "chart-legend");
	gtk_box_pack_start (GTK_BOX (legend), legend_note, FALSE, FALSE, 0);
	update_legend_note ();
	gtk_box_pack_start (GTK_BOX (card), legend, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (page), card, TRUE, TRUE, 0);
	diagram_card = card;

	anim_settings = gtk_settings_get_default ();
	if (anim_settings != NULL)
		anim_handler = g_signal_connect (anim_settings,
			"notify::gtk-enable-animations",
			G_CALLBACK (on_animations_notify), NULL);

	g_signal_connect (page, "map", G_CALLBACK (on_page_map), NULL);
	g_signal_connect (page, "unmap", G_CALLBACK (on_page_unmap), NULL);
	g_signal_connect (page, "destroy", G_CALLBACK (on_page_destroy), NULL);

	/* Whatever was blocked before the page was built is already
	 * remembered; the connections are asked for when it is first shown. */
	model_dirty = TRUE;
	ensure_model ();

	return page;
}
