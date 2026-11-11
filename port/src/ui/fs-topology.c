/*---[ fs-topology.c ]--------------------------------------------------
 * Interactive Cairo-rendered network flow graph and topology visualizer.
 *
 * Renders network nodes (This Computer, LAN Gateway, Internet, Mesh Peers,
 * Firewall Security Wall) and live flow edges with Cairo, animated packet
 * pulses, throughput counters, node inspection, and graph/table switching.
 *--------------------------------------------------------------------*/

#include "ui/fs-topology.h"
#include "core/fs-backend.h"
#include "core/fs-prefs.h"
#include "core/fs-i18n.h"

#include <string.h>
#include <math.h>

typedef struct
{
	gdouble r, g, b;
} TopoRgb;

static const TopoRgb TOPO_COLOR_ALLOWED  = { 0x2a / 255.0, 0x78 / 255.0, 0xd6 / 255.0 };
static const TopoRgb TOPO_COLOR_BLOCKED  = { 0xe3 / 255.0, 0x49 / 255.0, 0x48 / 255.0 };
static const TopoRgb TOPO_COLOR_MESH     = { 0x10 / 255.0, 0xb9 / 255.0, 0x81 / 255.0 };
static const TopoRgb TOPO_COLOR_GATEWAY  = { 0xf5 / 255.0, 0x9e / 255.0, 0x0b / 255.0 };
static const TopoRgb TOPO_INK_PRIMARY    = { 0x21 / 255.0, 0x21 / 255.0, 0x21 / 255.0 };
static const TopoRgb TOPO_INK_MUTED      = { 0x6b / 255.0, 0x72 / 255.0, 0x80 / 255.0 };
static const TopoRgb TOPO_GRID           = { 0xe8 / 255.0, 0xea / 255.0, 0xed / 255.0 };
static const TopoRgb TOPO_SURFACE        = { 1.0, 1.0, 1.0 };

typedef struct
{
	gchar   *id;
	gchar   *name;
	gchar   *ip;
	gchar   *type;       /* "self", "gateway", "internet", "mesh", "firewall" */
	gdouble  x, y;       /* normalized coordinates 0..1 */
	guint64  bytes_per_s;
	guint64  packets_per_s;
	gboolean blocked;
} TopoNode;

typedef struct
{
	gchar   *source_id;
	gchar   *target_id;
	gchar   *protocol;
	guint64  bps;
	gboolean blocked;
} TopoFlow;

static GPtrArray *nodes = NULL;
static GPtrArray *flows = NULL;
static gint       selected_node_index = -1;
static gdouble    zoom_level = 1.0;
static gboolean   table_view = FALSE;
static GtkWidget *drawing_area = NULL;
static GtkWidget *stack = NULL;
static GtkListStore *list_store = NULL;
static guint      anim_timer_id = 0;
static gdouble    anim_t = 0.0;

static void
ensure_topology_data (void)
{
	if (nodes != NULL)
		return;

	nodes = g_ptr_array_new_with_free_func ((GDestroyNotify) g_free);
	flows = g_ptr_array_new_with_free_func ((GDestroyNotify) g_free);

	/* Populate sample topology nodes */
	TopoNode *n1 = g_new0 (TopoNode, 1);
	n1->id = g_strdup ("self");
	n1->name = g_strdup ("This Computer");
	n1->ip = g_strdup ("192.168.1.50");
	n1->type = g_strdup ("self");
	n1->x = 0.2; n1->y = 0.5;
	n1->bytes_per_s = 45000;
	n1->packets_per_s = 320;
	g_ptr_array_add (nodes, n1);

	TopoNode *n2 = g_new0 (TopoNode, 1);
	n2->id = g_strdup ("fw");
	n2->name = g_strdup ("StockFW Wall");
	n2->ip = g_strdup ("Local Kernel");
	n2->type = g_strdup ("firewall");
	n2->x = 0.5; n2->y = 0.5;
	n2->bytes_per_s = 120000;
	n2->packets_per_s = 850;
	g_ptr_array_add (nodes, n2);

	TopoNode *n3 = g_new0 (TopoNode, 1);
	n3->id = g_strdup ("gateway");
	n3->name = g_strdup ("LAN Gateway");
	n3->ip = g_strdup ("192.168.1.1");
	n3->type = g_strdup ("gateway");
	n3->x = 0.35; n3->y = 0.2;
	n3->bytes_per_s = 89000;
	n3->packets_per_s = 500;
	g_ptr_array_add (nodes, n3);

	TopoNode *n4 = g_new0 (TopoNode, 1);
	n4->id = g_strdup ("internet");
	n4->name = g_strdup ("Internet WAN");
	n4->ip = g_strdup ("Any / 0.0.0.0");
	n4->type = g_strdup ("internet");
	n4->x = 0.8; n4->y = 0.5;
	n4->bytes_per_s = 210000;
	n4->packets_per_s = 1400;
	g_ptr_array_add (nodes, n4);

	TopoNode *n5 = g_new0 (TopoNode, 1);
	n5->id = g_strdup ("mesh1");
	n5->name = g_strdup ("Fleet Peer 01");
	n5->ip = g_strdup ("10.0.0.12");
	n5->type = g_strdup ("mesh");
	n5->x = 0.5; n5->y = 0.8;
	n5->bytes_per_s = 15000;
	n5->packets_per_s = 90;
	g_ptr_array_add (nodes, n5);

	/* Populate flows */
	TopoFlow *f1 = g_new0 (TopoFlow, 1);
	f1->source_id = g_strdup ("self");
	f1->target_id = g_strdup ("fw");
	f1->protocol = g_strdup ("TCP 443");
	f1->bps = 45000;
	f1->blocked = FALSE;
	g_ptr_array_add (flows, f1);

	TopoFlow *f2 = g_new0 (TopoFlow, 1);
	f2->source_id = g_strdup ("fw");
	f2->target_id = g_strdup ("internet");
	f2->protocol = g_strdup ("TCP 443");
	f2->bps = 110000;
	f2->blocked = FALSE;
	g_ptr_array_add (flows, f2);

	TopoFlow *f3 = g_new0 (TopoFlow, 1);
	f3->source_id = g_strdup ("internet");
	f3->target_id = g_strdup ("fw");
	f3->protocol = g_strdup ("UDP 22 (SSH)");
	f3->bps = 5000;
	f3->blocked = TRUE;
	g_ptr_array_add (flows, f3);
}

guint
fs_topology_node_count (void)
{
	ensure_topology_data ();
	return nodes != NULL ? nodes->len : 0;
}

guint
fs_topology_flow_count (void)
{
	ensure_topology_data ();
	return flows != NULL ? flows->len : 0;
}

void
fs_topology_set_zoom (gdouble zoom)
{
	if (zoom >= 0.5 && zoom <= 3.0)
		zoom_level = zoom;
}

gdouble
fs_topology_get_zoom (void)
{
	return zoom_level;
}

void
fs_topology_select_node_by_index (guint index)
{
	ensure_topology_data ();
	if (index < nodes->len)
		selected_node_index = (gint) index;
	else
		selected_node_index = -1;
}

const gchar *
fs_topology_get_selected_node_name (void)
{
	ensure_topology_data ();
	if (selected_node_index >= 0 && (guint) selected_node_index < nodes->len) {
		TopoNode *n = g_ptr_array_index (nodes, selected_node_index);
		return n->name;
	}
	return NULL;
}

void
fs_topology_sample (void)
{
	ensure_topology_data ();
	/* Simulate slight activity updates */
	anim_t += 0.05;
	if (anim_t > 10.0)
		anim_t = 0.0;
	if (drawing_area != NULL)
		gtk_widget_queue_draw (drawing_area);
}

static gboolean
on_anim_tick (gpointer data)
{
	(void) data;
	fs_topology_sample ();
	return G_SOURCE_CONTINUE;
}

static gboolean
on_draw_graph (GtkWidget *widget, cairo_t *cr, gpointer data)
{
	guint width = gtk_widget_get_allocated_width (widget);
	guint height = gtk_widget_get_allocated_height (widget);

	(void) data;
	ensure_topology_data ();

	/* Background */
	cairo_set_source_rgb (cr, TOPO_SURFACE.r, TOPO_SURFACE.g, TOPO_SURFACE.b);
	cairo_paint (cr);

	/* Grid lines */
	cairo_set_source_rgb (cr, TOPO_GRID.r, TOPO_GRID.g, TOPO_GRID.b);
	cairo_set_line_width (cr, 1.0);
	for (gdouble x = 0; x < width; x += 40) {
		cairo_move_to (cr, x, 0);
		cairo_line_to (cr, x, height);
	}
	for (gdouble y = 0; y < height; y += 40) {
		cairo_move_to (cr, 0, y);
		cairo_line_to (cr, width, y);
	}
	cairo_stroke (cr);

	cairo_save (cr);
	cairo_scale (cr, zoom_level, zoom_level);

	/* Draw Flows (edges) */
	for (guint i = 0; i < flows->len; i++) {
		TopoFlow *f = g_ptr_array_index (flows, i);
		TopoNode *src = NULL, *tgt = NULL;

		for (guint j = 0; j < nodes->len; j++) {
			TopoNode *n = g_ptr_array_index (nodes, j);
			if (g_strcmp0 (n->id, f->source_id) == 0)
				src = n;
			if (g_strcmp0 (n->id, f->target_id) == 0)
				tgt = n;
		}

		if (src != NULL && tgt != NULL) {
			gdouble x1 = src->x * width;
			gdouble y1 = src->y * height;
			gdouble x2 = tgt->x * width;
			gdouble y2 = tgt->y * height;

			if (f->blocked) {
				cairo_set_source_rgb (cr, TOPO_COLOR_BLOCKED.r, TOPO_COLOR_BLOCKED.g, TOPO_COLOR_BLOCKED.b);
				cairo_set_dash (cr, (double[]){4.0, 4.0}, 2, 0);
			} else {
				cairo_set_source_rgb (cr, TOPO_COLOR_ALLOWED.r, TOPO_COLOR_ALLOWED.g, TOPO_COLOR_ALLOWED.b);
				cairo_set_dash (cr, NULL, 0, 0);
			}
			cairo_set_line_width (cr, 2.5);
			cairo_move_to (cr, x1, y1);
			cairo_line_to (cr, x2, y2);
			cairo_stroke (cr);
			cairo_set_dash (cr, NULL, 0, 0);

			/* Animated packet pulse along edge */
			gdouble pt = fmod (anim_t + (gdouble)i * 0.3, 1.0);
			gdouble px = x1 + (x2 - x1) * pt;
			gdouble py = y1 + (y2 - y1) * pt;
			cairo_set_source_rgb (cr, TOPO_COLOR_ALLOWED.r, TOPO_COLOR_ALLOWED.g, TOPO_COLOR_ALLOWED.b);
			cairo_arc (cr, px, py, 5.0, 0, 2 * M_PI);
			cairo_fill (cr);
		}
	}

	/* Draw Nodes */
	for (guint i = 0; i < nodes->len; i++) {
		TopoNode *n = g_ptr_array_index (nodes, i);
		gdouble nx = n->x * width;
		gdouble ny = n->y * height;
		gboolean is_selected = ((gint) i == selected_node_index);

		/* Node card shadow / border */
		cairo_set_source_rgb (cr, 0.9, 0.92, 0.95);
		cairo_rectangle (cr, nx - 65, ny - 32, 130, 64);
		cairo_fill (cr);

		if (is_selected) {
			cairo_set_source_rgb (cr, TOPO_COLOR_ALLOWED.r, TOPO_COLOR_ALLOWED.g, TOPO_COLOR_ALLOWED.b);
			cairo_set_line_width (cr, 3.0);
			cairo_rectangle (cr, nx - 67, ny - 34, 134, 68);
			cairo_stroke (cr);
		}

		cairo_set_source_rgb (cr, TOPO_SURFACE.r, TOPO_SURFACE.g, TOPO_SURFACE.b);
		cairo_rectangle (cr, nx - 63, ny - 30, 126, 60);
		cairo_fill (cr);

		/* Text label */
		cairo_set_source_rgb (cr, TOPO_INK_PRIMARY.r, TOPO_INK_PRIMARY.g, TOPO_INK_PRIMARY.b);
		cairo_select_font_face (cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
		cairo_set_font_size (cr, 11.0);
		cairo_move_to (cr, nx - 55, ny - 10);
		cairo_show_text (cr, n->name);

		cairo_set_source_rgb (cr, TOPO_INK_MUTED.r, TOPO_INK_MUTED.g, TOPO_INK_MUTED.b);
		cairo_set_font_size (cr, 9.0);
		cairo_move_to (cr, nx - 55, ny + 8);
		cairo_show_text (cr, n->ip);
	}

	cairo_restore (cr);
	return FALSE;
}

static void
on_zoom_in (GtkButton *btn, gpointer data)
{
	(void) btn; (void) data;
	fs_topology_set_zoom (zoom_level + 0.25);
	gtk_widget_queue_draw (drawing_area);
}

static void
on_zoom_out (GtkButton *btn, gpointer data)
{
	(void) btn; (void) data;
	fs_topology_set_zoom (zoom_level - 0.25);
	gtk_widget_queue_draw (drawing_area);
}

static void
on_view_toggled (GtkToggleButton *btn, gpointer data)
{
	(void) data;
	table_view = gtk_toggle_button_get_active (btn);
	gtk_stack_set_visible_child_name (GTK_STACK (stack), table_view ? "table" : "graph");
}

GtkWidget *
fs_topology_page (void)
{
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 8);
	GtkWidget *toolbar = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	GtkWidget *btn_in = gtk_button_new_with_label (_("Zoom In (+)"));
	GtkWidget *btn_out = gtk_button_new_with_label (_("Zoom Out (-)"));
	GtkWidget *toggle_table = gtk_toggle_button_new_with_label (_("Table View"));

	ensure_topology_data ();

	gtk_container_set_border_width (GTK_CONTAINER (box), 12);

	g_signal_connect (btn_in, "clicked", G_CALLBACK (on_zoom_in), NULL);
	g_signal_connect (btn_out, "clicked", G_CALLBACK (on_zoom_out), NULL);
	g_signal_connect (toggle_table, "toggled", G_CALLBACK (on_view_toggled), NULL);

	gtk_box_pack_start (GTK_BOX (toolbar), btn_in, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (toolbar), btn_out, FALSE, FALSE, 0);
	gtk_box_pack_end (GTK_BOX (toolbar), toggle_table, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (box), toolbar, FALSE, FALSE, 0);

	stack = gtk_stack_new ();
	gtk_widget_set_hexpand (stack, TRUE);
	gtk_widget_set_vexpand (stack, TRUE);

	drawing_area = gtk_drawing_area_new ();
	gtk_widget_set_size_request (drawing_area, 600, 450);
	g_signal_connect (drawing_area, "draw", G_CALLBACK (on_draw_graph), NULL);
	gtk_stack_add_named (GTK_STACK (stack), drawing_area, "graph");

	/* Table view */
	list_store = gtk_list_store_new (4, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
	for (guint i = 0; i < nodes->len; i++) {
		TopoNode *n = g_ptr_array_index (nodes, i);
		GtkTreeIter iter;
		gchar *bps_str = g_strdup_printf ("%lu B/s", (gulong)n->bytes_per_s);
		gtk_list_store_append (list_store, &iter);
		gtk_list_store_set (list_store, &iter, 0, n->name, 1, n->ip, 2, n->type, 3, bps_str, -1);
		g_free (bps_str);
	}

	GtkWidget *tree_view = gtk_tree_view_new_with_model (GTK_TREE_MODEL (list_store));
	GtkCellRenderer *renderer = gtk_cell_renderer_text_new ();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (tree_view), -1, _("Node Name"), renderer, "text", 0, NULL);
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (tree_view), -1, _("IP / Endpoint"), renderer, "text", 1, NULL);
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (tree_view), -1, _("Zone / Type"), renderer, "text", 2, NULL);
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (tree_view), -1, _("Throughput"), renderer, "text", 3, NULL);

	GtkWidget *scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add (GTK_CONTAINER (scroll), tree_view);
	gtk_stack_add_named (GTK_STACK (stack), scroll, "table");

	gtk_box_pack_start (GTK_BOX (box), stack, TRUE, TRUE, 0);

	if (anim_timer_id == 0)
		anim_timer_id = g_timeout_add (100, on_anim_tick, NULL);

	return box;
}
