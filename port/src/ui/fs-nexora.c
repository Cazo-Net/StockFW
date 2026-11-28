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
#include "ui/fs-themecolor.h"

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

/* ---- the sample chart ------------------------------------------------
 *
 * Bars: the connections of each one-minute slot, on the left scale.
 * Line: the flagged connections, on the right scale.  Every colour is
 * the theme's by name, asked for at each paint, so the chart follows
 * Dark mode and the accent colour like the rest of the window. */

/* The two scales share the gridlines: five lines, four steps each. */
#define CHART_LEFT_MAX   400.0   /* connections */
#define CHART_RIGHT_MAX  8.0     /* flagged     */
#define CHART_STEPS      4

#define CHART_PAD_LEFT   36
#define CHART_PAD_RIGHT  26
#define CHART_PAD_TOP    10
#define CHART_PAD_BOTTOM 24

/* A small label; anchor: 0 left, 0.5 centre, 1 right; y is the centre. */
static void
chart_text (cairo_t *cr, GtkWidget *widget, const gchar *text, gdouble x,
            gdouble y, gdouble anchor)
{
	PangoLayout *layout = gtk_widget_create_pango_layout (widget, text);
	PangoFontDescription *desc = pango_font_description_copy (
		pango_context_get_font_description (
			pango_layout_get_context (layout)));
	gint tw, th;

	pango_font_description_set_size (desc, 8.5 * PANGO_SCALE);
	pango_layout_set_font_description (layout, desc);
	pango_font_description_free (desc);

	pango_layout_get_pixel_size (layout, &tw, &th);
	fs_theme_source (cr, "fs_text_weak", "#a8a4a4", 1.0);
	cairo_move_to (cr, x - anchor * tw, y - th / 2.0);
	pango_cairo_show_layout (cr, layout);
	g_object_unref (layout);
}

/* A bar with its two top corners rounded. */
static void
chart_bar (cairo_t *cr, gdouble x, gdouble y, gdouble w, gdouble h)
{
	gdouble r = MIN (3.0, MIN (w / 2.0, h));

	cairo_new_sub_path (cr);
	cairo_arc (cr, x + r, y + r, r, G_PI, 3 * G_PI / 2);
	cairo_arc (cr, x + w - r, y + r, r, -G_PI / 2, 0);
	cairo_line_to (cr, x + w, y + h);
	cairo_line_to (cr, x, y + h);
	cairo_close_path (cr);
}

static gboolean
on_chart_draw (GtkWidget *widget, cairo_t *cr, gpointer user_data)
{
	gint width = gtk_widget_get_allocated_width (widget);
	gint height = gtk_widget_get_allocated_height (widget);
	gdouble left = CHART_PAD_LEFT;
	gdouble right = width - CHART_PAD_RIGHT;
	gdouble top = CHART_PAD_TOP;
	gdouble bottom = height - CHART_PAD_BOTTOM;
	gdouble plot_w = right - left, plot_h = bottom - top;
	gdouble col_width, bar_w;
	gint i;

	(void) user_data;

	if (plot_w < 60 || plot_h < 40)
		return FALSE;

/* One mapping for the gridlines, the bars and the line. */
#define Y_AT(frac) (top + plot_h * (1.0 - (frac)))
#define X_MID(slot) (left + ((slot) + 0.5) * col_width)

	col_width = plot_w / WINDOW_POINTS;
	bar_w = CLAMP (col_width * 0.56, 4.0, 36.0);

	/* Background */
	fs_theme_source (cr, "fs_surface", "#211e1e", 1.0);
	cairo_paint (cr);

	/* Gridlines on whole pixels, with both scales' labels. */
	cairo_set_line_width (cr, 1.0);
	for (i = 0; i <= CHART_STEPS; i++) {
		gdouble frac = (gdouble) i / CHART_STEPS;
		gdouble y = (gint) Y_AT (frac) + 0.5;
		gchar buf[16];

		if (i == 0)
			fs_theme_source (cr, "fs_border_strong", "#4a4545", 1.0);
		else
			fs_theme_source (cr, "fs_border", "#2f2b2b", 1.0);
		cairo_move_to (cr, left, y);
		cairo_line_to (cr, right, y);
		cairo_stroke (cr);

		g_snprintf (buf, sizeof buf, "%d",
		            (gint) (CHART_LEFT_MAX * frac + 0.5));
		chart_text (cr, widget, buf, left - 8, y, 1.0);
		g_snprintf (buf, sizeof buf, "%d",
		            (gint) (CHART_RIGHT_MAX * frac + 0.5));
		chart_text (cr, widget, buf, right + 8, y, 0.0);
	}

	/* Time under every fifth slot; the last slot is now. */
	for (i = WINDOW_POINTS - 1; i >= 0; i -= 5) {
		gint ago = WINDOW_POINTS - 1 - i;
		gchar *t = ago == 0 ? g_strdup (_("now"))
		                    : g_strdup_printf (_("-%d min"), ago);

		chart_text (cr, widget, t, X_MID (i), bottom + 12, 0.5);
		g_free (t);
	}

	/* Bars: connections. */
	fs_theme_source (cr, "fs_accent_fill", "#007aff", 0.55);
	for (i = 0; i < WINDOW_POINTS; i++) {
		gdouble y = Y_AT (window_requests[i] / CHART_LEFT_MAX);

		chart_bar (cr, X_MID (i) - bar_w / 2.0, y, bar_w,
		           (gint) bottom - y);
	}
	cairo_fill (cr);

	/* Line: flagged connections, a point per slot. */
	fs_theme_source (cr, "fs_bad", "#ff6259", 1.0);
	cairo_set_line_width (cr, 1.5);
	cairo_set_line_cap (cr, CAIRO_LINE_CAP_ROUND);
	cairo_set_line_join (cr, CAIRO_LINE_JOIN_ROUND);
	for (i = 0; i < WINDOW_POINTS; i++) {
		gdouble y = Y_AT (window_threats[i] / CHART_RIGHT_MAX);

		if (i == 0)
			cairo_move_to (cr, X_MID (i), y);
		else
			cairo_line_to (cr, X_MID (i), y);
	}
	cairo_stroke (cr);
	for (i = 0; i < WINDOW_POINTS; i++) {
		gdouble y = Y_AT (window_threats[i] / CHART_RIGHT_MAX);

		fs_theme_source (cr, "fs_surface", "#211e1e", 1.0);
		cairo_arc (cr, X_MID (i), y, 4.0, 0, 2 * G_PI);
		cairo_fill (cr);
		fs_theme_source (cr, "fs_bad", "#ff6259", 1.0);
		cairo_arc (cr, X_MID (i), y, 2.5, 0, 2 * G_PI);
		cairo_fill (cr);
	}

#undef Y_AT
#undef X_MID
	return FALSE;
}

/* A legend mark: the bar's fill, or the line with its point. */
static gboolean
on_legend_draw (GtkWidget *widget, cairo_t *cr, gpointer user_data)
{
	gint w = gtk_widget_get_allocated_width (widget);
	gint h = gtk_widget_get_allocated_height (widget);

	if (GPOINTER_TO_INT (user_data) == 0) {
		fs_theme_source (cr, "fs_accent_fill", "#007aff", 0.55);
		chart_bar (cr, (w - 8) / 2.0, (h - 10) / 2.0, 8, 10);
		cairo_fill (cr);
	} else {
		fs_theme_source (cr, "fs_bad", "#ff6259", 1.0);
		cairo_set_line_width (cr, 1.5);
		cairo_set_line_cap (cr, CAIRO_LINE_CAP_ROUND);
		cairo_move_to (cr, 1, h / 2.0);
		cairo_line_to (cr, w - 1, h / 2.0);
		cairo_stroke (cr);
		cairo_arc (cr, w / 2.0, h / 2.0, 2.5, 0, 2 * G_PI);
		cairo_fill (cr);
	}
	return FALSE;
}

/* One legend entry: its mark and what it stands for. */
static void
legend_add (GtkWidget *legend, gint mark, const gchar *text)
{
	GtkWidget *sw = gtk_drawing_area_new ();
	GtkWidget *lb = label_new (text, "chart-legend", 0.0);

	gtk_widget_set_size_request (sw, 16, 12);
	gtk_widget_set_valign (sw, GTK_ALIGN_CENTER);
	g_signal_connect (sw, "draw", G_CALLBACK (on_legend_draw),
	                  GINT_TO_POINTER (mark));
	gtk_widget_set_margin_start (sw, 12);
	gtk_box_pack_start (GTK_BOX (legend), sw, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (legend), lb, FALSE, FALSE, 0);
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

	/* 1. "Confidence" card (a sample figure; no model runs) */
	card = stat_card_new (_("MODEL CONFIDENCE"), &confidence_label,
	                      _("Sample"), "nexora-badge-warn",
	                      "98.4%");
	gtk_grid_attach (GTK_GRID (grid), card, 0, 0, 1, 1);

	/* 2. PSI Drift Gauge Card */
	card = stat_card_new (_("POPULATION STABILITY INDEX (PSI)"), &psi_label,
	                      _("Sample"), "nexora-badge-warn",
	                      "0.042");
	gtk_grid_attach (GTK_GRID (grid), card, 1, 0, 1, 1);

	/* 3. Active Label Counters Card */
	card = stat_card_new (_("LABELLED EVENTS"), &counter_label,
	                      _("Sample"), "nexora-badge-warn",
	                      "1,248");
	gtk_grid_attach (GTK_GRID (grid), card, 2, 0, 1, 1);

	/* 15-minute Sliding Window Chart Card */
	card = card_new (GTK_ORIENTATION_VERTICAL, 12);
	add_class (card, "padded-card");
	{
		GtkWidget *head = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
		GtkWidget *legend = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 5);

		gtk_box_pack_start (GTK_BOX (head),
		                    label_new (_("15-minute window (sample)"), "card-heading", 0.0),
		                    TRUE, TRUE, 0);
		/* Which mark is which, and which scale it is read on. */
		legend_add (legend, 0, _("Connections (left scale)"));
		legend_add (legend, 1, _("Flagged (right scale)"));
		gtk_widget_set_valign (legend, GTK_ALIGN_CENTER);
		gtk_box_pack_end (GTK_BOX (head), legend, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (card), head, FALSE, FALSE, 0);

		chart_area = gtk_drawing_area_new ();
		gtk_widget_set_size_request (chart_area, -1, 240);
		atk_object_set_name (gtk_widget_get_accessible (chart_area),
		                     _("Sample chart"));
		atk_object_set_description (
			gtk_widget_get_accessible (chart_area),
			_("Sample chart of 15 one-minute slots. Bars: connections. Line: flagged connections."));
		g_signal_connect (G_OBJECT (chart_area), "draw", G_CALLBACK (on_chart_draw), NULL);
		gtk_box_pack_start (GTK_BOX (card), chart_area, TRUE, TRUE, 0);

		/* No colour names: the bars take the accent colour, and both
		 * marks change with Dark mode. */
		window_stats_label = label_new (_("Sample chart of 15 one-minute slots. Bars: connections. Line: flagged connections."), "muted", 0.0);
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
