/*---[ fs-nexora.c ]---------------------------------------------------
 * The Nexora page: a PREVIEW of a layout, filled with fixed sample
 * figures.
 *
 * No anomaly model runs in StockFW (the scorer is unfinished and lives
 * in src/experimental/), so nothing on this page is measured on this
 * computer.  The page says so in its header badge, on every card and in
 * its footer, and the figures do not move: 1.0.9 redrew them with
 * random numbers every three seconds under a "Telemetry Active" badge,
 * which read as live readings of the machine.  When a real engine is
 * connected, feed it in here and drop the sample wording.
 *--------------------------------------------------------------------*/

#include "ui/fs-nexora.h"
#include "ui/fs-icons.h"
#include "core/fs-i18n.h"
#include "core/fs-util.h"

#include <string.h>

typedef struct
{
	gdouble r, g, b;
} Rgb;

static GtkWidget *nexora_page_widget = NULL;
static GtkWidget *confidence_label = NULL;
static GtkWidget *psi_label = NULL;
static GtkWidget *window_stats_label = NULL;
static GtkWidget *counter_label = NULL;
static GtkWidget *status_label = NULL;
static GtkWidget *chart_area = NULL;

static gboolean is_busy = FALSE;

/* Fixed sample figures, not readings. */
static const gdouble current_confidence = 0.984;
static const gdouble current_psi = 0.042;
static const guint active_labels_count = 1248;

#define WINDOW_POINTS 15
static const guint window_requests[WINDOW_POINTS] = {
	120, 145, 132, 160, 189, 210, 195, 240, 265, 250, 280, 310, 295, 330, 355
};
static const guint window_threats[WINDOW_POINTS] = {
	2, 1, 3, 0, 4, 2, 5, 1, 2, 0, 3, 1, 2, 4, 1
};

static void
add_class (GtkWidget *widget, const gchar *klass)
{
	gtk_style_context_add_class (gtk_widget_get_style_context (widget), klass);
}

static GtkWidget *
label_new (const gchar *text, const gchar *klass, gfloat xalign)
{
	GtkWidget *label = gtk_label_new (text);

	gtk_label_set_xalign (GTK_LABEL (label), xalign);
	if (klass != NULL)
		add_class (label, klass);
	return label;
}

static GtkWidget *
card_new (GtkOrientation orientation, gint spacing)
{
	GtkWidget *box = gtk_box_new (orientation, spacing);

	add_class (box, "card");
	return box;
}

static gboolean
on_chart_draw (GtkWidget *widget, cairo_t *cr, gpointer user_data)
{
	GtkAllocation alloc;
	gint width, height;
	gint i;
	gdouble max_val = 400.0;
	gdouble col_width;

	(void) user_data;

	gtk_widget_get_allocation (widget, &alloc);
	width = alloc.width;
	height = alloc.height;

	/* Background */
	cairo_set_source_rgb (cr, 1.0, 1.0, 1.0);
	cairo_paint (cr);

	/* Gridlines */
	cairo_set_source_rgb (cr, 0.90, 0.92, 0.95);
	cairo_set_line_width (cr, 1.0);
	for (i = 1; i <= 4; i++) {
		gdouble y = (height - 30) * (i / 4.0);
		cairo_move_to (cr, 40, y);
		cairo_line_to (cr, width - 20, y);
		cairo_stroke (cr);
	}

	col_width = (width - 60.0) / WINDOW_POINTS;

	/* Draw sliding window bars (Requests) */
	for (i = 0; i < WINDOW_POINTS; i++) {
		gdouble val = window_requests[i];
		gdouble h = (val / max_val) * (height - 50);
		gdouble x = 50 + i * col_width + 4;
		gdouble y = height - 30 - h;

		cairo_set_source_rgba (cr, 0.16, 0.47, 0.84, 0.90); /* Blue */
		cairo_rectangle (cr, x, y, col_width - 8, h);
		cairo_fill (cr);
	}

	/* Draw sliding window threat line */
	cairo_set_source_rgb (cr, 0.89, 0.29, 0.28); /* Red/Orange threat */
	cairo_set_line_width (cr, 2.5);
	cairo_set_line_cap (cr, CAIRO_LINE_CAP_ROUND);
	cairo_set_line_join (cr, CAIRO_LINE_JOIN_ROUND);
	for (i = 0; i < WINDOW_POINTS; i++) {
		gdouble val = window_threats[i] * 25.0; /* scale for visibility */
		gdouble x = 50 + i * col_width + (col_width / 2.0);
		gdouble y = height - 30 - ((val / max_val) * (height - 50));

		if (i == 0)
			cairo_move_to (cr, x, y);
		else
			cairo_line_to (cr, x, y);
	}
	cairo_stroke (cr);

	return FALSE;
}

static GtkWidget *
build_header (void)
{
	GtkWidget *header = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
	GtkWidget *titles = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
	GtkWidget *badge;

	add_class (header, "page-head");

	gtk_box_pack_start (GTK_BOX (titles),
	                    label_new (_("Nexora"), "page-title", 0.0),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (titles),
	                    label_new (_("Preview of a planned page. The figures below are fixed samples, not measurements from this computer."), "page-subtitle", 0.0),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (header), titles, TRUE, TRUE, 0);

	badge = label_new (_("Preview: sample data"), "nexora-badge-warn", 0.5);
	gtk_widget_set_valign (badge, GTK_ALIGN_CENTER);
	gtk_box_pack_start (GTK_BOX (header), badge, FALSE, FALSE, 0);

	return header;
}

static GtkWidget *
stat_card_new (const gchar *caption, GtkWidget **value_out, const gchar *badge_text, const gchar *badge_class, const gchar *val_markup)
{
	GtkWidget *card = card_new (GTK_ORIENTATION_VERTICAL, 8);
	GtkWidget *cap_label = label_new (caption, "stat-caption", 0.0);
	GtkWidget *val_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
	GtkWidget *val_label = label_new ("", "stat-big", 0.0);

	add_class (card, "stat-card");
	gtk_box_pack_start (GTK_BOX (card), cap_label, FALSE, FALSE, 0);

	if (val_markup != NULL)
		gtk_label_set_markup (GTK_LABEL (val_label), val_markup);
	gtk_box_pack_start (GTK_BOX (val_box), val_label, TRUE, TRUE, 0);

	if (badge_text != NULL) {
		GtkWidget *badge = label_new (badge_text, badge_class != NULL ? badge_class : "nexora-badge-ok", 0.5);
		gtk_widget_set_valign (badge, GTK_ALIGN_CENTER);
		gtk_box_pack_start (GTK_BOX (val_box), badge, FALSE, FALSE, 0);
	}
	gtk_box_pack_start (GTK_BOX (card), val_box, FALSE, FALSE, 0);

	if (value_out != NULL)
		*value_out = val_label;
	return card;
}

GtkWidget *
fs_nexora_page (void)
{
	GtkWidget *box;
	GtkWidget *grid;
	GtkWidget *card;
	GtkWidget *scroll;

	box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 20);
	add_class (box, "page");
	nexora_page_widget = box;

	/* Top Header */
	gtk_box_pack_start (GTK_BOX (box), build_header (), FALSE, FALSE, 0);

	/* Metrics Grid Cards */
	grid = gtk_grid_new ();
	gtk_grid_set_row_spacing (GTK_GRID (grid), 16);
	gtk_grid_set_column_spacing (GTK_GRID (grid), 16);
	gtk_grid_set_column_homogeneous (GTK_GRID (grid), TRUE);
	gtk_widget_set_hexpand (grid, TRUE);
	gtk_box_pack_start (GTK_BOX (box), grid, FALSE, FALSE, 0);

	/* 1. AEGIS-ML Confidence Card */
	card = stat_card_new (_("MODEL CONFIDENCE"), &confidence_label,
	                      _("Sample"), "nexora-badge-warn",
	                      "<span font='28' weight='900' foreground='#2a78d6'>98.4%</span>");
	gtk_grid_attach (GTK_GRID (grid), card, 0, 0, 1, 1);

	/* 2. PSI Drift Gauge Card */
	card = stat_card_new (_("POPULATION STABILITY INDEX (PSI)"), &psi_label,
	                      _("Sample"), "nexora-badge-warn",
	                      "<span font='28' weight='900' foreground='#059669'>0.042</span>");
	gtk_grid_attach (GTK_GRID (grid), card, 1, 0, 1, 1);

	/* 3. Active Label Counters Card */
	card = stat_card_new (_("LABELLED EVENTS"), &counter_label,
	                      _("Sample"), "nexora-badge-warn",
	                      "<span font='28' weight='900' foreground='#d97706'>1,248</span>");
	gtk_grid_attach (GTK_GRID (grid), card, 2, 0, 1, 1);

	/* 15-minute Sliding Window Chart Card */
	card = card_new (GTK_ORIENTATION_VERTICAL, 12);
	add_class (card, "padded-card");
	{
		GtkWidget *head = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
		gtk_box_pack_start (GTK_BOX (head),
		                    label_new (_("15-minute window (sample)"), "card-heading", 0.0),
		                    TRUE, TRUE, 0);
		gtk_box_pack_start (GTK_BOX (card), head, FALSE, FALSE, 0);

		chart_area = gtk_drawing_area_new ();
		gtk_widget_set_size_request (chart_area, -1, 240);
		g_signal_connect (G_OBJECT (chart_area), "draw", G_CALLBACK (on_chart_draw), NULL);
		gtk_box_pack_start (GTK_BOX (card), chart_area, TRUE, TRUE, 0);

		window_stats_label = label_new (_("Sample chart of 15 one-minute slots. Blue bars: connections, red line: flagged connections."), "muted", 0.0);
		gtk_label_set_line_wrap (GTK_LABEL (window_stats_label), TRUE);
		gtk_box_pack_start (GTK_BOX (card), window_stats_label, FALSE, FALSE, 0);
	}
	gtk_box_pack_start (GTK_BOX (box), card, TRUE, TRUE, 0);

	/* Status bar at bottom */
	status_label = label_new (_("Nothing on this page is connected to the firewall yet. For what is really happening, see Events and Activity."), "muted", 0.0);
	gtk_box_pack_start (GTK_BOX (box), status_label, FALSE, FALSE, 0);

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_AUTOMATIC,
	                                GTK_POLICY_AUTOMATIC);
	gtk_container_add (GTK_CONTAINER (scroll), box);

	gtk_widget_show_all (scroll);
	return scroll;
}

gboolean
fs_nexora_busy (void)
{
	return is_busy;
}

guint
fs_nexora_counter_count (void)
{
	return active_labels_count;
}

gdouble
fs_nexora_get_confidence (void)
{
	return current_confidence;
}

gdouble
fs_nexora_get_psi (void)
{
	return current_psi;
}
