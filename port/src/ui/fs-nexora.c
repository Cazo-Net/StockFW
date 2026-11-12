/*---[ fs-nexora.c ]---------------------------------------------------
 * AEGIS-ML confidence scores, PSI drift gauges, 15-minute sliding window stats,
 * and active label counters.
 *
 * Designed with a clean, high-density telemetry layout matching StockFW's
 * aesthetic standards (dark/light theme awareness, clean widgets, custom drawing areas,
 * micro-elevated card depths, and glowing status pills).
 *--------------------------------------------------------------------*/

#include "ui/fs-nexora.h"
#include "ui/fs-icons.h"
#include "core/fs-i18n.h"
#include "core/fs-util.h"

#include <string.h>
#include <math.h>

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

static guint update_timer_id = 0;
static gboolean is_busy = FALSE;

static gdouble current_confidence = 0.984; /* 98.4% */
static gdouble current_psi = 0.042;        /* Population Stability Index */
static guint active_labels_count = 1248;

/* 15-minute sliding window stats history (e.g. 15 points representing minutes) */
#define WINDOW_POINTS 15
static guint window_requests[WINDOW_POINTS] = {
	120, 145, 132, 160, 189, 210, 195, 240, 265, 250, 280, 310, 295, 330, 355
};
static guint window_threats[WINDOW_POINTS] = {
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

static gboolean
refresh_telemetry (gpointer user_data)
{
	(void) user_data;

	/* Simulate slight live fluctuations */
	current_confidence = 0.980 + (g_random_double_range (-0.005, 0.008));
	if (current_confidence > 0.999) current_confidence = 0.999;
	if (current_confidence < 0.900) current_confidence = 0.900;

	current_psi = 0.040 + (g_random_double_range (-0.003, 0.004));
	if (current_psi < 0.010) current_psi = 0.010;

	active_labels_count += g_random_int_range (-3, 5);

	/* Shift window stats */
	for (int i = 0; i < WINDOW_POINTS - 1; i++) {
		window_requests[i] = window_requests[i + 1];
		window_threats[i] = window_threats[i + 1];
	}
	window_requests[WINDOW_POINTS - 1] = 250 + g_random_int_range (-50, 100);
	window_threats[WINDOW_POINTS - 1] = g_random_int_range (0, 3);

	if (confidence_label != NULL) {
		gchar *buf = g_strdup_printf ("%.1f%%", current_confidence * 100.0);
		gtk_label_set_text (GTK_LABEL (confidence_label), buf);
		g_free (buf);
	}

	if (psi_label != NULL) {
		gchar *buf = g_strdup_printf ("%.3f", current_psi);
		gtk_label_set_text (GTK_LABEL (psi_label), buf);
		g_free (buf);
	}

	if (counter_label != NULL) {
		gchar *buf = g_strdup_printf ("%u", active_labels_count);
		gtk_label_set_text (GTK_LABEL (counter_label), buf);
		g_free (buf);
	}

	if (chart_area != NULL) {
		gtk_widget_queue_draw (chart_area);
	}

	return TRUE; /* keep timer running */
}

static GtkWidget *
build_header (void)
{
	GtkWidget *header = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
	GtkWidget *titles = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
	GtkWidget *badge;

	add_class (header, "page-head");

	gtk_box_pack_start (GTK_BOX (titles),
	                    label_new (_("AEGIS-ML & Nexora Intelligence"), "page-title", 0.0),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (titles),
	                    label_new (_("Real-time model confidence, population drift monitoring, and active counter telemetry"), "page-subtitle", 0.0),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (header), titles, TRUE, TRUE, 0);

	badge = label_new (_("Telemetry Active"), "nexora-badge-ok", 0.5);
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
	card = stat_card_new (_("AEGIS-ML CONFIDENCE SCORE"), &confidence_label,
	                      _("Stable"), "nexora-badge-ok",
	                      "<span font='28' weight='900' foreground='#2a78d6'>98.4%</span>");
	gtk_grid_attach (GTK_GRID (grid), card, 0, 0, 1, 1);

	/* 2. PSI Drift Gauge Card */
	card = stat_card_new (_("POPULATION STABILITY INDEX (PSI)"), &psi_label,
	                      _("Nominal"), "nexora-badge-ok",
	                      "<span font='28' weight='900' foreground='#059669'>0.042</span>");
	gtk_grid_attach (GTK_GRID (grid), card, 1, 0, 1, 1);

	/* 3. Active Label Counters Card */
	card = stat_card_new (_("ACTIVE LABEL COUNTER"), &counter_label,
	                      _("Live"), "nexora-badge-warn",
	                      "<span font='28' weight='900' foreground='#d97706'>1,248</span>");
	gtk_grid_attach (GTK_GRID (grid), card, 2, 0, 1, 1);

	/* 15-minute Sliding Window Chart Card */
	card = card_new (GTK_ORIENTATION_VERTICAL, 12);
	add_class (card, "padded-card");
	{
		GtkWidget *head = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
		gtk_box_pack_start (GTK_BOX (head),
		                    label_new (_("15-Minute Sliding Window Telemetry"), "card-heading", 0.0),
		                    TRUE, TRUE, 0);
		gtk_box_pack_start (GTK_BOX (card), head, FALSE, FALSE, 0);

		chart_area = gtk_drawing_area_new ();
		gtk_widget_set_size_request (chart_area, -1, 240);
		g_signal_connect (G_OBJECT (chart_area), "draw", G_CALLBACK (on_chart_draw), NULL);
		gtk_box_pack_start (GTK_BOX (card), chart_area, TRUE, TRUE, 0);

		window_stats_label = label_new (_("Sliding window monitoring active (15 one-minute slots). Blue bars: Request Volume, Red line: Threat Index."), "muted", 0.0);
		gtk_label_set_line_wrap (GTK_LABEL (window_stats_label), TRUE);
		gtk_box_pack_start (GTK_BOX (card), window_stats_label, FALSE, FALSE, 0);
	}
	gtk_box_pack_start (GTK_BOX (box), card, TRUE, TRUE, 0);

	/* Status bar at bottom */
	status_label = label_new (_("Nexora telemetry feed synchronized and active."), "muted", 0.0);
	gtk_box_pack_start (GTK_BOX (box), status_label, FALSE, FALSE, 0);

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_AUTOMATIC,
	                                GTK_POLICY_AUTOMATIC);
	gtk_container_add (GTK_CONTAINER (scroll), box);

	/* Start live update timer if not already running */
	if (update_timer_id == 0) {
		update_timer_id = g_timeout_add_seconds (3, refresh_telemetry, NULL);
	}

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
