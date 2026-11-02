/*---[ fs-activityview.c ]-----------------------------------------------
 * The Activity page described in fs-activityview.h.
 *
 * Drawing follows the same rules as the local dashboard's graphs:
 * 2 px lines on a recessive grid, one y axis per graph, round time
 * ticks spaced for their labels, a direct label at each line's end as
 * well as the legend, one crosshair with one tooltip, a shaded "no
 * data" stretch before the app started, and a table view holding the
 * same numbers.  Colours are the validated light palette: allowed and
 * received #2a78d6, blocked #e34948, sent #eb6834.
 *--------------------------------------------------------------------*/

#include "ui/fs-activityview.h"
#include "ui/fs-hitview.h"
#include "core/fs-backend.h"
#include "core/fs-prefs.h"
#include "core/fs-netparse.h"
#include "core/fs-i18n.h"

#include <string.h>

#define SAMPLE_MS    2000
#define MAX_POINTS   120

/* Plot margins: room for "100 kB/s" on the left and a direct label on
 * the right. */
#define M_LEFT   62
#define M_RIGHT  86
#define M_TOP    12
#define M_BOTTOM 26

typedef struct
{
	gdouble r, g, b;
} Rgb;

static const Rgb COLOR_ALLOWED  = { 0x2a / 255.0, 0x78 / 255.0, 0xd6 / 255.0 };
static const Rgb COLOR_BLOCKED  = { 0xe3 / 255.0, 0x49 / 255.0, 0x48 / 255.0 };
static const Rgb COLOR_RECEIVED = { 0x2a / 255.0, 0x78 / 255.0, 0xd6 / 255.0 };
static const Rgb COLOR_SENT     = { 0xeb / 255.0, 0x68 / 255.0, 0x34 / 255.0 };

/* Ink, grid and surface, matching fs-theme.css. */
static const Rgb INK_PRIMARY = { 0x21 / 255.0, 0x21 / 255.0, 0x21 / 255.0 };
static const Rgb INK_MUTED   = { 0x6b / 255.0, 0x72 / 255.0, 0x80 / 255.0 };
static const Rgb GRID        = { 0xe8 / 255.0, 0xea / 255.0, 0xed / 255.0 };
static const Rgb BASELINE    = { 0xc4 / 255.0, 0xc9 / 255.0, 0xcf / 255.0 };
static const Rgb SURFACE     = { 1.0, 1.0, 1.0 };

#define MAX_SERIES 2

/* A rate is never negative, so this marks a point with no data. */
#define NO_DATA (-1.0)

/* No libm: the page needs only these three, and keeping the binary's
 * link line as it was keeps the installer's soname check honest. */
static gdouble
pfloor (gdouble x)
{
	gdouble i = (gdouble) (gint64) x;

	return i > x ? i - 1 : i;
}

static gdouble
pabs (gdouble x)
{
	return x < 0 ? -x : x;
}

typedef struct
{
	const gchar *title;
	gboolean     per_minute;       /* events: per minute; else bytes/s */

	GtkWidget   *card;
	GtkWidget   *area;
	GtkWidget   *stack;
	GtkWidget   *legend;
	GtkWidget   *subtitle;
	GtkWidget   *note;
	GtkListStore *store;
	GtkWidget   *table;
	GtkTreeViewColumn *value_columns[MAX_SERIES];

	/* The window last read. */
	guint        n_series;
	const gchar *labels[MAX_SERIES];
	Rgb          colors[MAX_SERIES];
	guint        n;
	guint        step;
	gint64       start;
	guint64     *values[MAX_SERIES];
	guint       *covered;

	gint         hover;            /* point index, -1 for none */
} Chart;

static FsActivity        *events_series = NULL;
static FsActivity        *net_series    = NULL;
static FsActivitySampler *sampler       = NULL;
static GList             *last_stats    = NULL;   /* FsIfaceStat*, newest */
static GList             *prev_stats    = NULL;
static gint64             last_us = 0, prev_us = 0;

static guint     range_s   = 3600;
static gchar    *device    = NULL;      /* NULL = all adapters */
static gchar    *device_list_key = NULL;
static gboolean  show_table = FALSE;
static gboolean  syncing    = FALSE;

static Chart     events_chart = { .title = N_("Policy activity"), .per_minute = TRUE };
static Chart     net_chart    = { .title = N_("Network I/O"),     .per_minute = FALSE };

static GtkWidget *range_buttons[4];
static const guint range_values[4] = { 900, 3600, 21600, 86400 };
static GtkWidget *device_combo  = NULL;
static GtkWidget *table_toggle  = NULL;
static GtkWidget *tile_blocked  = NULL, *tile_blocked_sub = NULL;
static GtkWidget *tile_allowed  = NULL, *tile_allowed_sub = NULL;
static GtkWidget *tile_allowed_card = NULL;
static GtkWidget *tile_rx       = NULL, *tile_tx = NULL;
static GtkWidget *tile_net_sub  = NULL;

/* ----------------------------------------------------------- series */

static void
ensure_series (void)
{
	if (events_series == NULL)
		events_series = fs_activity_new (NULL, NULL);

	if (net_series == NULL) {
		net_series = fs_activity_new (NULL, NULL);
		sampler    = fs_activity_sampler_new (net_series);
	}
}

/* [ logs_allowed ]
 * Windows logs every decision (events 5156 and 5157); the Linux kernel
 * log carries only what StockFW's rules drop or reject.  An allowed
 * line that is always zero on Linux would claim "nothing was allowed",
 * so there it is not drawn at all. */
static gboolean
logs_allowed (void)
{
	/* Windows logs accepted connections (5156).  Linux does since 1.0.7
	 * when "Log allowed connections" is on: the policy's accepts go
	 * through a chain that logs each new connection (sampled). */
	if ((fs_backend ()->fw_honors & FS_FWHON_LOG_ALLOWED) != 0)
		return fs_prefs_get_bool (FS_PREFS_FW_LOG_ALLOWED, TRUE);

	return g_strcmp0 (fs_backend ()->name, "linux") != 0;
}

FsActivity *
fs_activityview_events (void)
{
	ensure_series ();
	return events_series;
}

FsActivity *
fs_activityview_network (void)
{
	ensure_series ();
	return net_series;
}

gboolean
fs_activityview_shows_allowed (void)
{
	return logs_allowed ();
}

/* [ hit_time ] -- an event's own time in unix seconds, or `fallback'. */
static gint64
hit_time (const FsHit *hit, gint64 fallback)
{
	gchar stamp[21];
	GDateTime *dt;
	gint64 t;

	/* Both backends stamp events in UTC as "YYYY-MM-DDTHH:MM:SS"
	 * followed by a fraction of any length and a 'Z' (Windows writes
	 * seven digits); the whole seconds are all a 10 s slot needs, and
	 * the Events page parses its Time column the same way. */
	if (hit->time == NULL || strlen (hit->time) < 19)
		return fallback;

	memcpy (stamp, hit->time, 19);
	stamp[19] = 'Z';
	stamp[20] = '\0';
	dt = g_date_time_new_from_iso8601 (stamp, NULL);

	if (dt == NULL)
		return fallback;

	t = g_date_time_to_unix (dt);
	g_date_time_unref (dt);
	return t;
}

void
fs_activityview_note_hit (const FsHit *hit)
{
	if (hit == NULL)
		return;

	ensure_series ();

	/* At the event's own time: the Windows reader delivers a batch of
	 * recent history at start, and those events belong where they
	 * happened.  Events from before the app started are dropped by
	 * the series -- that stretch is drawn as "no data". */
	fs_activity_add_at (events_series,
	                    fs_hit_is_blocked (hit) ? FS_ACTIVITY_BLOCKED
	                                            : FS_ACTIVITY_ALLOWED,
	                    hit_time (hit, fs_activity_now (events_series)), 1);
}

/* ----------------------------------------------------------- format */

static gchar *
format_rate (gdouble bytes_per_s)
{
	static const gchar *units[] = { "B/s", "kB/s", "MB/s", "GB/s" };
	guint u = 0;

	while (bytes_per_s >= 1000.0 && u + 1 < G_N_ELEMENTS (units)) {
		bytes_per_s /= 1000.0;
		u++;
	}

	if (u == 0)
		return g_strdup_printf ("%.0f %s", bytes_per_s, units[u]);

	return g_strdup_printf (bytes_per_s < 10 ? "%.1f %s" : "%.0f %s",
	                        bytes_per_s, units[u]);
}

static gchar *
format_per_minute (gdouble per_min)
{
	if (per_min == 0)
		return g_strdup ("0/min");
	if (per_min < 10 && per_min != pfloor (per_min))
		return g_strdup_printf ("%.1f/min", per_min);

	return g_strdup_printf ("%.0f/min", per_min);
}

static gchar *
format_value (const Chart *c, gdouble v)
{
	return c->per_minute ? format_per_minute (v) : format_rate (v);
}

static gchar *
format_clock (gint64 t, gboolean with_seconds)
{
	GDateTime *dt = g_date_time_new_from_unix_local (t);
	gchar *s = g_date_time_format (dt, with_seconds ? "%H:%M:%S" : "%H:%M");

	g_date_time_unref (dt);
	return s;
}

/* -------------------------------------------------------- the window */

static void
chart_clear_window (Chart *c)
{
	for (guint s = 0; s < MAX_SERIES; s++)
		g_clear_pointer (&c->values[s], g_free);
	g_clear_pointer (&c->covered, g_free);
	c->n = 0;
}

static void
chart_read (Chart *c, FsActivity *activity, const gchar * const *names)
{
	chart_clear_window (c);

	c->step    = fs_activity_step_for (range_s, MAX_POINTS);
	c->n       = (range_s + c->step - 1) / c->step;
	c->covered = g_new0 (guint, c->n);

	for (guint s = 0; s < c->n_series; s++) {
		c->values[s] = g_new0 (guint64, c->n);
		fs_activity_window (activity, names[s], c->step, c->n,
		                    c->values[s], s == 0 ? c->covered : NULL,
		                    &c->start);
	}

	if (c->hover >= (gint) c->n)
		c->hover = -1;
}

/* [ chart_rate ] -- point i of series s as a rate, or NO_DATA. */
static gdouble
chart_rate (const Chart *c, guint s, guint i)
{
	guint cov;

	if (i >= c->n || c->covered == NULL || c->values[s] == NULL)
		return NO_DATA;

	cov = c->covered[i];
	if (cov == 0)
		return NO_DATA;

	return c->per_minute ? (gdouble) c->values[s][i] * 60.0 / cov
	                     : (gdouble) c->values[s][i] / cov;
}

static void
refresh_events_chart (void)
{
	const gchar *names[MAX_SERIES];
	Chart *c = &events_chart;

	if (logs_allowed ()) {
		c->n_series  = 2;
		names[0]     = FS_ACTIVITY_ALLOWED;
		names[1]     = FS_ACTIVITY_BLOCKED;
		c->labels[0] = _("Allowed");
		c->labels[1] = _("Blocked");
		c->colors[0] = COLOR_ALLOWED;
		c->colors[1] = COLOR_BLOCKED;
	} else {
		c->n_series  = 1;
		names[0]     = FS_ACTIVITY_BLOCKED;
		c->labels[0] = _("Blocked");
		c->colors[0] = COLOR_BLOCKED;
	}

	chart_read (c, events_series, names);
}

static void
refresh_net_chart (void)
{
	Chart *c = &net_chart;
	gchar *rx = NULL, *tx = NULL;
	const gchar *names[MAX_SERIES];

	if (device != NULL) {
		rx = fs_activity_device_series (device, FALSE);
		tx = fs_activity_device_series (device, TRUE);
	}

	c->n_series  = 2;
	names[0]     = rx != NULL ? rx : FS_ACTIVITY_NET_RX;
	names[1]     = tx != NULL ? tx : FS_ACTIVITY_NET_TX;
	c->labels[0] = _("Received");
	c->labels[1] = _("Sent");
	c->colors[0] = COLOR_RECEIVED;
	c->colors[1] = COLOR_SENT;

	chart_read (c, net_series, names);

	g_free (rx);
	g_free (tx);
}

/* ------------------------------------------------------------ drawing */

static void
set_rgb (cairo_t *cr, const Rgb *c)
{
	cairo_set_source_rgb (cr, c->r, c->g, c->b);
}

/* A round gridline step for four gridlines above zero. */
static gdouble
nice_step (gdouble v)
{
	gdouble p = 1, n;

	if (!(v > 0))
		return 1;

	while (p * 10 <= v)
		p *= 10;
	while (p > v)
		p /= 10;
	n = v / p;

	return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
}

/* Round time steps; the smallest that suits the range and leaves room
 * for a label between ticks at this width. */
static guint
tick_every (guint range, gdouble px_per_s)
{
	static const guint steps[] = { 60, 120, 180, 300, 600, 900, 1800,
	                               3600, 7200, 10800, 21600, 43200 };
	guint floor_s = range <= 900 ? 180 : range <= 3600 ? 600
	              : range <= 21600 ? 3600 : 10800;

	for (guint i = 0; i < G_N_ELEMENTS (steps); i++)
		if (steps[i] >= floor_s && steps[i] * px_per_s >= 64)
			return steps[i];

	return steps[G_N_ELEMENTS (steps) - 1];
}

static PangoLayout *
small_layout (GtkWidget *widget, const gchar *text, gboolean bold)
{
	PangoLayout *layout = gtk_widget_create_pango_layout (widget, text);
	PangoFontDescription *desc = pango_font_description_copy (
		pango_context_get_font_description (
			pango_layout_get_context (layout)));

	pango_font_description_set_size (desc, 8.5 * PANGO_SCALE);
	if (bold)
		pango_font_description_set_weight (desc, PANGO_WEIGHT_SEMIBOLD);
	pango_layout_set_font_description (layout, desc);
	pango_font_description_free (desc);

	return layout;
}

/* [ draw_text ] -- anchor: 0 left, 0.5 centre, 1 right; y is the centre. */
static void
draw_text (cairo_t *cr, GtkWidget *w, const gchar *text, gdouble x,
           gdouble y, gdouble anchor, const Rgb *ink, gboolean bold)
{
	PangoLayout *layout = small_layout (w, text, bold);
	gint tw, th;

	pango_layout_get_pixel_size (layout, &tw, &th);
	set_rgb (cr, ink);
	cairo_move_to (cr, x - anchor * tw, y - th / 2.0);
	pango_cairo_show_layout (cr, layout);
	g_object_unref (layout);
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

static void
draw_tooltip (cairo_t *cr, GtkWidget *w, const Chart *c, gdouble px,
              gint width, gint height)
{
	gchar *from = format_clock (c->start + (gint64) c->hover * c->step,
	                            c->step < 60);
	gchar *to   = format_clock (c->start + (gint64) (c->hover + 1) * c->step,
	                            c->step < 60);
	gchar *head = c->covered[c->hover] == 0
	              ? g_strdup_printf (_("%s – %s · no data"), from, to)
	              : g_strdup_printf ("%s – %s", from, to);
	gchar *lines[MAX_SERIES] = { NULL, NULL };
	gdouble bw = 0, bh, bx, by;
	gint tw, th;
	PangoLayout *layout;

	layout = small_layout (w, head, FALSE);
	pango_layout_get_pixel_size (layout, &tw, &th);
	g_object_unref (layout);
	bw = tw;

	for (guint s = 0; s < c->n_series; s++) {
		gdouble v = chart_rate (c, s, (guint) c->hover);
		gchar *val = v < 0 ? g_strdup ("–") : format_value (c, v);

		lines[s] = g_strdup_printf ("%s  %s", val, c->labels[s]);
		g_free (val);

		layout = small_layout (w, lines[s], TRUE);
		pango_layout_get_pixel_size (layout, &tw, NULL);
		g_object_unref (layout);
		bw = MAX (bw, tw + 18);
	}

	bw += 20;
	bh  = 12 + (c->n_series + 1) * (th + 4);
	bx  = px + 12;
	if (bx + bw > width - 4)
		bx = px - 12 - bw;
	by  = M_TOP + 4;
	if (by + bh > height - M_BOTTOM)
		by = MAX (2, height - M_BOTTOM - bh);

	/* Card: white, hairline border, a soft shadow. */
	cairo_set_source_rgba (cr, 0, 0, 0, 0.08);
	rounded_rect (cr, bx + 1, by + 2, bw, bh, 6);
	cairo_fill (cr);
	set_rgb (cr, &SURFACE);
	rounded_rect (cr, bx, by, bw, bh, 6);
	cairo_fill_preserve (cr);
	set_rgb (cr, &BASELINE);
	cairo_set_line_width (cr, 1);
	cairo_stroke (cr);

	draw_text (cr, w, head, bx + 10, by + 6 + th / 2.0, 0, &INK_MUTED, FALSE);

	for (guint s = 0; s < c->n_series; s++) {
		gdouble ly = by + 6 + (s + 1) * (th + 4) + th / 2.0;

		cairo_set_source_rgb (cr, c->colors[s].r, c->colors[s].g,
		                      c->colors[s].b);
		cairo_set_line_width (cr, 2);
		cairo_move_to (cr, bx + 10, ly);
		cairo_line_to (cr, bx + 20, ly);
		cairo_stroke (cr);
		draw_text (cr, w, lines[s], bx + 26, ly, 0, &INK_PRIMARY, TRUE);
		g_free (lines[s]);
	}

	g_free (from);
	g_free (to);
	g_free (head);
}

static gboolean
on_chart_draw (GtkWidget *w, cairo_t *cr, gpointer data)
{
	Chart *c = data;
	gint width  = gtk_widget_get_allocated_width (w);
	gint height = gtk_widget_get_allocated_height (w);
	gdouble iw = width - M_LEFT - M_RIGHT;
	gdouble ih = height - M_TOP - M_BOTTOM;
	gdouble max = 0, ymax, label_y[MAX_SERIES];
	gint first = -1, last = -1;
	guint every;

	if (c->n == 0 || iw < 40 || ih < 30)
		return FALSE;

	for (guint i = 0; i < c->n; i++) {
		if (c->covered[i] == 0)
			continue;
		if (first < 0)
			first = (gint) i;
		last = (gint) i;
		for (guint s = 0; s < c->n_series; s++)
			max = MAX (max, chart_rate (c, s, i));
	}

	ymax = nice_step (max / 4) * 4;

#define X(i) (M_LEFT + ((c->n <= 1) ? iw : ((gdouble) (i) / (c->n - 1)) * iw))
#define Y(v) (M_TOP + ih - ((v) / ymax) * ih)

	/* No-data stretch: shaded and labelled, so it never reads as an
	 * idle firewall. */
	if (first != 0) {
		gdouble x1 = first < 0 ? M_LEFT + iw : X (first);

		cairo_set_source_rgba (cr, 0.42, 0.45, 0.50, 0.07);
		cairo_rectangle (cr, M_LEFT, M_TOP, x1 - M_LEFT, ih);
		cairo_fill (cr);
		if (x1 - M_LEFT > 70)
			draw_text (cr, w, _("no data"), M_LEFT + 8, M_TOP + 12, 0,
			           &INK_MUTED, FALSE);
	}

	/* Grid and y labels. */
	cairo_set_line_width (cr, 1);
	for (gint g = 0; g <= 4; g++) {
		gdouble gv = ymax * g / 4, gy = pfloor (Y (gv)) + 0.5;
		gchar *label = format_value (c, gv);

		set_rgb (cr, g == 0 ? &BASELINE : &GRID);
		cairo_move_to (cr, M_LEFT, gy);
		cairo_line_to (cr, M_LEFT + iw, gy);
		cairo_stroke (cr);
		draw_text (cr, w, label, M_LEFT - 8, gy, 1, &INK_MUTED, FALSE);
		g_free (label);
	}

	/* x labels on round times. */
	every = tick_every (range_s, iw / MAX (1.0, (gdouble) (c->n - 1) * c->step));
	for (gint64 ts = ((c->start + every - 1) / every) * every;
	     ts <= c->start + (gint64) (c->n - 1) * c->step; ts += every) {
		gdouble xi = (gdouble) (ts - c->start) / c->step;
		gchar *label = format_clock (ts, FALSE);

		draw_text (cr, w, label, X (xi), height - M_BOTTOM / 2.0 + 2, 0.5,
		           &INK_MUTED, FALSE);
		g_free (label);
	}

	if (first < 0) {
		draw_text (cr, w, _("Waiting for the first measurement…"),
		           M_LEFT + iw / 2, M_TOP + ih / 2, 0.5, &INK_MUTED, FALSE);
		return FALSE;
	}

	/* Lines, broken where there is no data. */
	cairo_set_line_join (cr, CAIRO_LINE_JOIN_ROUND);
	cairo_set_line_cap (cr, CAIRO_LINE_CAP_ROUND);
	for (guint s = 0; s < c->n_series; s++) {
		gboolean pen = FALSE;

		cairo_set_source_rgb (cr, c->colors[s].r, c->colors[s].g,
		                      c->colors[s].b);
		cairo_set_line_width (cr, 2);

		for (guint i = 0; i < c->n; i++) {
			gdouble v = chart_rate (c, s, i);

			if (v < 0) {
				pen = FALSE;
				continue;
			}
			if (pen)
				cairo_line_to (cr, X (i), Y (v));
			else
				cairo_move_to (cr, X (i), Y (v));
			pen = TRUE;
		}
		cairo_stroke (cr);
	}

	/* End points: a dot with a surface ring, and a direct label beside
	 * it (nudged apart when two would collide). */
	for (guint s = 0; s < c->n_series; s++)
		label_y[s] = Y (chart_rate (c, s, (guint) last));
	if (c->n_series == 2 && pabs (label_y[0] - label_y[1]) < 14) {
		gdouble mid = (label_y[0] + label_y[1]) / 2;
		gboolean first_above = label_y[0] <= label_y[1];

		label_y[0] = mid + (first_above ? -7 : 7);
		label_y[1] = mid + (first_above ? 7 : -7);
	}

	for (guint s = 0; s < c->n_series; s++) {
		gdouble x = X (last), y = Y (chart_rate (c, s, (guint) last));

		set_rgb (cr, &SURFACE);
		cairo_arc (cr, x, y, 5, 0, 2 * G_PI);
		cairo_fill (cr);
		cairo_set_source_rgb (cr, c->colors[s].r, c->colors[s].g,
		                      c->colors[s].b);
		cairo_arc (cr, x, y, 3.5, 0, 2 * G_PI);
		cairo_fill (cr);
		draw_text (cr, w, c->labels[s], x + 9, label_y[s], 0,
		           &INK_PRIMARY, TRUE);
	}

	/* Crosshair and tooltip. */
	if (c->hover >= 0 && c->hover < (gint) c->n) {
		gdouble hx = pfloor (X (c->hover)) + 0.5;

		cairo_set_source_rgba (cr, 0.42, 0.45, 0.50, 0.7);
		cairo_set_line_width (cr, 1);
		cairo_move_to (cr, hx, M_TOP);
		cairo_line_to (cr, hx, M_TOP + ih);
		cairo_stroke (cr);

		for (guint s = 0; s < c->n_series; s++) {
			gdouble v = chart_rate (c, s, (guint) c->hover);

			if (v < 0)
				continue;
			set_rgb (cr, &SURFACE);
			cairo_arc (cr, hx, Y (v), 5, 0, 2 * G_PI);
			cairo_fill (cr);
			cairo_set_source_rgb (cr, c->colors[s].r, c->colors[s].g,
			                      c->colors[s].b);
			cairo_arc (cr, hx, Y (v), 3.5, 0, 2 * G_PI);
			cairo_fill (cr);
		}

		draw_tooltip (cr, w, c, hx, width, height);
	}

#undef X
#undef Y

	return FALSE;
}

/* --------------------------------------------------------- hover/keys */

static gboolean
on_chart_motion (GtkWidget *w, GdkEventMotion *ev, gpointer data)
{
	Chart *c = data;
	gdouble iw = gtk_widget_get_allocated_width (w) - M_LEFT - M_RIGHT;
	gint i;

	if (c->n < 2 || iw <= 0)
		return FALSE;

	i = (gint) pfloor ((ev->x - M_LEFT) / iw * (c->n - 1) + 0.5);
	i = CLAMP (i, 0, (gint) c->n - 1);

	if (i != c->hover) {
		c->hover = i;
		gtk_widget_queue_draw (w);
	}

	return FALSE;
}

static gboolean
on_chart_leave (GtkWidget *w, GdkEventCrossing *ev, gpointer data)
{
	Chart *c = data;

	(void) ev;
	if (!gtk_widget_has_focus (w) && c->hover != -1) {
		c->hover = -1;
		gtk_widget_queue_draw (w);
	}

	return FALSE;
}

static gboolean
on_chart_key (GtkWidget *w, GdkEventKey *ev, gpointer data)
{
	Chart *c = data;

	if (c->n == 0)
		return FALSE;

	switch (ev->keyval) {
	case GDK_KEY_Left:
		c->hover = c->hover < 0 ? (gint) c->n - 1 : MAX (0, c->hover - 1);
		break;
	case GDK_KEY_Right:
		c->hover = c->hover < 0 ? (gint) c->n - 1
		                        : MIN ((gint) c->n - 1, c->hover + 1);
		break;
	case GDK_KEY_Home:
		c->hover = 0;
		break;
	case GDK_KEY_End:
		c->hover = (gint) c->n - 1;
		break;
	case GDK_KEY_Escape:
		c->hover = -1;
		break;
	default:
		return FALSE;
	}

	gtk_widget_queue_draw (w);
	return TRUE;
}

static gboolean
on_chart_focus_out (GtkWidget *w, GdkEventFocus *ev, gpointer data)
{
	Chart *c = data;

	(void) ev;
	c->hover = -1;
	gtk_widget_queue_draw (w);
	return FALSE;
}

static gboolean
on_chart_button (GtkWidget *w, GdkEventButton *ev, gpointer data)
{
	(void) ev;
	(void) data;
	gtk_widget_grab_focus (w);
	return FALSE;
}

/* ------------------------------------------------------------- tables */

static void
fill_table (Chart *c)
{
	GtkTreeIter iter;

	gtk_list_store_clear (c->store);

	for (guint s = 0; s < MAX_SERIES; s++)
		if (c->value_columns[s] != NULL) {
			gtk_tree_view_column_set_visible (c->value_columns[s],
			                                  s < c->n_series);
			if (s < c->n_series)
				gtk_tree_view_column_set_title (c->value_columns[s],
				                                c->labels[s]);
		}

	/* Newest first: the table is read top-down for "what just
	 * happened". */
	for (gint i = (gint) c->n - 1; i >= 0; i--) {
		gchar *from, *vals[MAX_SERIES] = { NULL, NULL };

		if (c->covered[i] == 0)
			continue;

		from = format_clock (c->start + (gint64) i * c->step, c->step < 60);
		for (guint s = 0; s < c->n_series; s++)
			vals[s] = format_value (c, chart_rate (c, s, (guint) i));

		gtk_list_store_append (c->store, &iter);
		gtk_list_store_set (c->store, &iter, 0, from,
		                    1, vals[0] ? vals[0] : "",
		                    2, vals[1] ? vals[1] : "", -1);
		g_free (from);
		g_free (vals[0]);
		g_free (vals[1]);
	}
}

guint
fs_activityview_table_rows (void)
{
	if (events_chart.store == NULL)
		return 0;

	fill_table (&events_chart);
	return (guint) gtk_tree_model_iter_n_children (
		GTK_TREE_MODEL (events_chart.store), NULL);
}

/* ------------------------------------------------------------ refresh */

static void
set_label_number (GtkWidget *label, guint64 n)
{
	gchar *text = g_strdup_printf ("%" G_GUINT64_FORMAT, n);

	gtk_label_set_text (GTK_LABEL (label), text);
	g_free (text);
}

/* Bytes per second between the last two samples, for one device or
 * all of them. */
static void
current_rates (gdouble *rx, gdouble *tx)
{
	gdouble dt = (last_us - prev_us) / (gdouble) G_USEC_PER_SEC;

	*rx = *tx = -1;
	if (prev_stats == NULL || last_stats == NULL || dt <= 0)
		return;

	*rx = *tx = 0;
	for (GList *l = last_stats; l != NULL; l = l->next) {
		const FsIfaceStat *now = l->data;

		if (device != NULL && g_strcmp0 (now->device, device) != 0)
			continue;

		for (GList *p = prev_stats; p != NULL; p = p->next) {
			const FsIfaceStat *was = p->data;

			if (g_strcmp0 (was->device, now->device) != 0)
				continue;
			if (now->received >= was->received)
				*rx += (now->received - was->received) / dt;
			if (now->sent >= was->sent)
				*tx += (now->sent - was->sent) / dt;
		}
	}
}

static void
refresh_tiles (void)
{
	gdouble rx, tx;
	gchar *since = format_clock (fs_activity_started (events_series), FALSE);
	gchar *sub;

	set_label_number (tile_blocked,
	                  fs_activity_total (events_series, FS_ACTIVITY_BLOCKED, 3600));
	sub = g_strdup_printf (_("%" G_GUINT64_FORMAT " in 24 h · counting since %s"),
	                       fs_activity_total (events_series, FS_ACTIVITY_BLOCKED,
	                                          FS_ACTIVITY_SPAN_S), since);
	gtk_label_set_text (GTK_LABEL (tile_blocked_sub), sub);
	g_free (sub);

	gtk_widget_set_visible (tile_allowed_card, logs_allowed ());
	set_label_number (tile_allowed,
	                  fs_activity_total (events_series, FS_ACTIVITY_ALLOWED, 3600));
	sub = g_strdup_printf (_("%" G_GUINT64_FORMAT " in 24 h"),
	                       fs_activity_total (events_series, FS_ACTIVITY_ALLOWED,
	                                          FS_ACTIVITY_SPAN_S));
	gtk_label_set_text (GTK_LABEL (tile_allowed_sub), sub);
	g_free (sub);

	current_rates (&rx, &tx);
	if (rx < 0) {
		gtk_label_set_text (GTK_LABEL (tile_rx), "–");
		gtk_label_set_text (GTK_LABEL (tile_tx), "–");
	} else {
		gchar *r = format_rate (rx), *t = format_rate (tx);

		gtk_label_set_text (GTK_LABEL (tile_rx), r);
		gtk_label_set_text (GTK_LABEL (tile_tx), t);
		g_free (r);
		g_free (t);
	}
	gtk_label_set_text (GTK_LABEL (tile_net_sub),
	                    device != NULL ? device : _("all adapters"));

	g_free (since);
}

static void
refresh_notes (void)
{
	gchar *sub;

	if (!fs_hitview_active ())
		gtk_label_set_text (GTK_LABEL (events_chart.note),
			_("Event monitoring is off, so nothing is being counted. "
			  "Start it from the Events page."));
	else if (!logs_allowed ())
		gtk_label_set_text (GTK_LABEL (events_chart.note),
			_("On Linux the kernel log carries only the packets "
			  "StockFW's rules drop or reject, so this graph shows "
			  "blocked traffic; allowed traffic shows under Network I/O."));
	else
		gtk_label_set_text (GTK_LABEL (events_chart.note),
			_("Counts the events the Events page lists, after its "
			  "filters."));

	sub = g_strdup_printf (_("%s per minute, as listed on the Events page"),
	                       logs_allowed () ? _("Allowed and blocked events")
	                                       : _("Blocked packets"));
	gtk_label_set_text (GTK_LABEL (events_chart.subtitle), sub);
	g_free (sub);

	sub = g_strdup_printf (_("Average throughput, %s"),
	                       device != NULL ? device : _("all adapters"));
	gtk_label_set_text (GTK_LABEL (net_chart.subtitle), sub);
	g_free (sub);
}

static void rebuild_legend (Chart *c);

static void
refresh_all (void)
{
	ensure_series ();
	refresh_events_chart ();
	refresh_net_chart ();

	if (events_chart.area == NULL)
		return;

	rebuild_legend (&events_chart);
	rebuild_legend (&net_chart);
	refresh_tiles ();
	refresh_notes ();

	if (show_table) {
		fill_table (&events_chart);
		fill_table (&net_chart);
	} else {
		gtk_widget_queue_draw (events_chart.area);
		gtk_widget_queue_draw (net_chart.area);
	}
}

/* [ sync_devices ] -- the adapter picker follows the adapters seen. */
static void
sync_devices (void)
{
	GString *key = g_string_new (NULL);

	for (GList *l = last_stats; l != NULL; l = l->next)
		g_string_append_printf (key, "%s\n",
		                        ((FsIfaceStat *) l->data)->device);

	if (device_combo != NULL && g_strcmp0 (key->str, device_list_key) != 0) {
		gint active = 0, i = 1;

		syncing = TRUE;
		gtk_combo_box_text_remove_all (GTK_COMBO_BOX_TEXT (device_combo));
		gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (device_combo), "",
		                           _("All adapters"));
		for (GList *l = last_stats; l != NULL; l = l->next, i++) {
			const FsIfaceStat *s = l->data;

			gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (device_combo),
			                           s->device, s->device);
			if (g_strcmp0 (s->device, device) == 0)
				active = i;
		}
		gtk_combo_box_set_active (GTK_COMBO_BOX (device_combo), active);
		syncing = FALSE;

		g_free (device_list_key);
		device_list_key = g_strdup (key->str);
	}

	g_string_free (key, TRUE);
}

void
fs_activityview_sample (void)
{
	const FsBackend *backend = fs_backend ();
	GList *stats;

	ensure_series ();

	if (backend->list_interface_stats == NULL)
		return;

	stats = backend->list_interface_stats ();
	fs_activity_sampler_feed (sampler, stats);

	g_list_free_full (prev_stats, (GDestroyNotify) fs_iface_stat_free);
	prev_stats = last_stats;
	prev_us    = last_us;
	last_stats = stats;
	last_us    = g_get_monotonic_time ();

	sync_devices ();
}

static gboolean
on_sample_timeout (gpointer data)
{
	(void) data;

	fs_activityview_sample ();

	/* Redraw only when someone can see it; the sampling above runs
	 * regardless, so the graph is complete when the page is opened. */
	if (events_chart.card != NULL && gtk_widget_get_mapped (events_chart.card))
		refresh_all ();

	return G_SOURCE_CONTINUE;
}

/* ------------------------------------------------------------- controls */

void
fs_activityview_set_range (guint seconds)
{
	for (guint i = 0; i < G_N_ELEMENTS (range_values); i++)
		if (range_values[i] == seconds) {
			range_s = seconds;
			if (range_buttons[i] != NULL && !syncing) {
				syncing = TRUE;
				gtk_toggle_button_set_active (
					GTK_TOGGLE_BUTTON (range_buttons[i]), TRUE);
				syncing = FALSE;
			}
			events_chart.hover = net_chart.hover = -1;
			refresh_all ();
			return;
		}
}

guint
fs_activityview_get_range (void)
{
	return range_s;
}

static void
on_range_toggled (GtkToggleButton *button, gpointer data)
{
	if (syncing || !gtk_toggle_button_get_active (button))
		return;

	fs_activityview_set_range (GPOINTER_TO_UINT (data));
}

static void
on_device_changed (GtkComboBox *combo, gpointer data)
{
	const gchar *id;

	(void) data;
	if (syncing)
		return;

	id = gtk_combo_box_get_active_id (combo);
	g_free (device);
	device = (id != NULL && id[0] != '\0') ? g_strdup (id) : NULL;
	net_chart.hover = -1;
	refresh_all ();
}

void
fs_activityview_set_table (gboolean table)
{
	show_table = table;

	if (events_chart.stack == NULL)
		return;

	gtk_stack_set_visible_child_name (GTK_STACK (events_chart.stack),
	                                  table ? "table" : "chart");
	gtk_stack_set_visible_child_name (GTK_STACK (net_chart.stack),
	                                  table ? "table" : "chart");

	if (table_toggle != NULL) {
		gtk_button_set_label (GTK_BUTTON (table_toggle),
		                      table ? _("Show as graph") : _("Show as table"));
		if (!syncing) {
			syncing = TRUE;
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (table_toggle),
			                              table);
			syncing = FALSE;
		}
	}

	refresh_all ();
}

static void
on_table_toggled (GtkToggleButton *button, gpointer data)
{
	(void) data;
	if (syncing)
		return;

	fs_activityview_set_table (gtk_toggle_button_get_active (button));
}

/* ------------------------------------------------------------ building */

static void
add_class (GtkWidget *w, const gchar *cls)
{
	gtk_style_context_add_class (gtk_widget_get_style_context (w), cls);
}

static gboolean
on_swatch_draw (GtkWidget *w, cairo_t *cr, gpointer data)
{
	const Rgb *c = data;
	gint h = gtk_widget_get_allocated_height (w);

	cairo_set_source_rgb (cr, c->r, c->g, c->b);
	cairo_set_line_width (cr, 2);
	cairo_set_line_cap (cr, CAIRO_LINE_CAP_ROUND);
	cairo_move_to (cr, 1, h / 2.0);
	cairo_line_to (cr, 13, h / 2.0);
	cairo_stroke (cr);
	return FALSE;
}

static void
rebuild_legend (Chart *c)
{
	GList *children = gtk_container_get_children (GTK_CONTAINER (c->legend));

	/* Rebuild only when the series set changed. */
	if (g_list_length (children) == c->n_series * 2) {
		g_list_free (children);
		return;
	}

	for (GList *l = children; l != NULL; l = l->next)
		gtk_widget_destroy (l->data);
	g_list_free (children);

	for (guint s = 0; s < c->n_series; s++) {
		GtkWidget *sw = gtk_drawing_area_new ();
		GtkWidget *lb = gtk_label_new (c->labels[s]);

		gtk_widget_set_size_request (sw, 14, 12);
		g_signal_connect (sw, "draw", G_CALLBACK (on_swatch_draw),
		                  &c->colors[s]);
		add_class (lb, "chart-legend");
		gtk_box_pack_start (GTK_BOX (c->legend), sw, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (c->legend), lb, FALSE, FALSE, 0);
		gtk_widget_set_margin_end (lb, 10);
		gtk_widget_show (sw);
		gtk_widget_show (lb);
	}
}

static GtkWidget *
build_chart_card (Chart *c, const gchar *a11y_name)
{
	GtkWidget *card, *box, *title, *table_scroll;
	GtkCellRenderer *cell;
	AtkObject *atk;

	card = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
	add_class (card, "chart-card");
	c->card = card;
	c->hover = -1;

	title = gtk_label_new (_(c->title));
	gtk_label_set_xalign (GTK_LABEL (title), 0);
	add_class (title, "card-title");
	gtk_box_pack_start (GTK_BOX (card), title, FALSE, FALSE, 0);

	c->subtitle = gtk_label_new (NULL);
	gtk_label_set_xalign (GTK_LABEL (c->subtitle), 0);
	add_class (c->subtitle, "dim-label");
	gtk_box_pack_start (GTK_BOX (card), c->subtitle, FALSE, FALSE, 0);

	c->legend = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 4);
	gtk_widget_set_margin_top (c->legend, 4);
	gtk_box_pack_start (GTK_BOX (card), c->legend, FALSE, FALSE, 0);

	c->stack = gtk_stack_new ();
	gtk_widget_set_vexpand (c->stack, TRUE);

	c->area = gtk_drawing_area_new ();
	gtk_widget_set_size_request (c->area, 320, 200);
	gtk_widget_set_can_focus (c->area, TRUE);
	gtk_widget_add_events (c->area, GDK_POINTER_MOTION_MASK |
	                       GDK_LEAVE_NOTIFY_MASK | GDK_BUTTON_PRESS_MASK |
	                       GDK_KEY_PRESS_MASK | GDK_FOCUS_CHANGE_MASK);
	g_signal_connect (c->area, "draw", G_CALLBACK (on_chart_draw), c);
	g_signal_connect (c->area, "motion-notify-event",
	                  G_CALLBACK (on_chart_motion), c);
	g_signal_connect (c->area, "leave-notify-event",
	                  G_CALLBACK (on_chart_leave), c);
	g_signal_connect (c->area, "key-press-event",
	                  G_CALLBACK (on_chart_key), c);
	g_signal_connect (c->area, "focus-out-event",
	                  G_CALLBACK (on_chart_focus_out), c);
	g_signal_connect (c->area, "button-press-event",
	                  G_CALLBACK (on_chart_button), c);
	atk = gtk_widget_get_accessible (c->area);
	if (atk != NULL) {
		atk_object_set_name (atk, a11y_name);
		atk_object_set_description (atk,
			_("Use the arrow keys to read one interval; "
			  "Show as table lists every interval"));
	}
	gtk_stack_add_named (GTK_STACK (c->stack), c->area, "chart");

	c->store = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_STRING,
	                               G_TYPE_STRING);
	c->table = gtk_tree_view_new_with_model (GTK_TREE_MODEL (c->store));
	g_object_unref (c->store);
	add_class (c->table, "data-grid");
	cell = gtk_cell_renderer_text_new ();
	gtk_tree_view_append_column (GTK_TREE_VIEW (c->table),
		gtk_tree_view_column_new_with_attributes (_("From"), cell,
		                                          "text", 0, NULL));
	for (guint s = 0; s < MAX_SERIES; s++) {
		cell = gtk_cell_renderer_text_new ();
		c->value_columns[s] = gtk_tree_view_column_new_with_attributes (
			"", cell, "text", (gint) s + 1, NULL);
		gtk_tree_view_column_set_expand (c->value_columns[s], TRUE);
		gtk_tree_view_append_column (GTK_TREE_VIEW (c->table),
		                             c->value_columns[s]);
	}
	table_scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (table_scroll),
	                                GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_container_add (GTK_CONTAINER (table_scroll), c->table);
	gtk_stack_add_named (GTK_STACK (c->stack), table_scroll, "table");

	box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	gtk_box_pack_start (GTK_BOX (box), c->stack, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (card), box, TRUE, TRUE, 0);

	c->note = gtk_label_new (NULL);
	gtk_label_set_xalign (GTK_LABEL (c->note), 0);
	gtk_label_set_line_wrap (GTK_LABEL (c->note), TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (c->note), 60);
	add_class (c->note, "dim-label");
	gtk_box_pack_start (GTK_BOX (card), c->note, FALSE, FALSE, 0);

	return card;
}

static GtkWidget *
build_tile (const gchar *caption, GtkWidget **value, GtkWidget **sub)
{
	GtkWidget *tile = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	GtkWidget *cap = gtk_label_new (caption);

	add_class (tile, "stat-tile");
	gtk_label_set_xalign (GTK_LABEL (cap), 0);
	add_class (cap, "stat-caption");
	gtk_box_pack_start (GTK_BOX (tile), cap, FALSE, FALSE, 0);

	*value = gtk_label_new ("–");
	gtk_label_set_xalign (GTK_LABEL (*value), 0);
	add_class (*value, "stat-value");
	gtk_box_pack_start (GTK_BOX (tile), *value, FALSE, FALSE, 0);

	if (sub != NULL) {
		*sub = gtk_label_new (NULL);
		gtk_label_set_xalign (GTK_LABEL (*sub), 0);
		gtk_label_set_ellipsize (GTK_LABEL (*sub), PANGO_ELLIPSIZE_END);
		add_class (*sub, "dim-label");
		gtk_box_pack_start (GTK_BOX (tile), *sub, FALSE, FALSE, 0);
	}

	return tile;
}

static GtkWidget *
build_net_tile (void)
{
	GtkWidget *tile = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	GtkWidget *cap = gtk_label_new (_("Throughput now"));
	GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	GtkWidget *sw;

	add_class (tile, "stat-tile");
	gtk_label_set_xalign (GTK_LABEL (cap), 0);
	add_class (cap, "stat-caption");
	gtk_box_pack_start (GTK_BOX (tile), cap, FALSE, FALSE, 0);

	sw = gtk_drawing_area_new ();
	gtk_widget_set_size_request (sw, 14, 12);
	g_signal_connect (sw, "draw", G_CALLBACK (on_swatch_draw),
	                  (gpointer) &COLOR_RECEIVED);
	gtk_box_pack_start (GTK_BOX (row), sw, FALSE, FALSE, 0);
	tile_rx = gtk_label_new ("–");
	add_class (tile_rx, "stat-value");
	gtk_box_pack_start (GTK_BOX (row), tile_rx, FALSE, FALSE, 0);

	sw = gtk_drawing_area_new ();
	gtk_widget_set_size_request (sw, 14, 12);
	gtk_widget_set_margin_start (sw, 10);
	g_signal_connect (sw, "draw", G_CALLBACK (on_swatch_draw),
	                  (gpointer) &COLOR_SENT);
	gtk_box_pack_start (GTK_BOX (row), sw, FALSE, FALSE, 0);
	tile_tx = gtk_label_new ("–");
	add_class (tile_tx, "stat-value");
	gtk_box_pack_start (GTK_BOX (row), tile_tx, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (tile), row, FALSE, FALSE, 0);

	tile_net_sub = gtk_label_new (NULL);
	gtk_label_set_xalign (GTK_LABEL (tile_net_sub), 0);
	add_class (tile_net_sub, "dim-label");
	gtk_box_pack_start (GTK_BOX (tile), tile_net_sub, FALSE, FALSE, 0);

	return tile;
}

static void
on_page_map (GtkWidget *w, gpointer data)
{
	(void) w;
	(void) data;
	refresh_all ();
}

GtkWidget *
fs_activityview_page (void)
{
	GtkWidget *page, *bar, *seg, *lbl, *tiles, *grid, *scroll;
	static const gchar *range_labels[4] = {
		N_("15 min"), N_("1 hour"), N_("6 hours"), N_("24 hours")
	};

	ensure_series ();

	page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	/* The window's page frame supplies the margins. */

	/* ---- filters: one row above everything they affect ---- */
	bar = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);

	seg = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	add_class (seg, "linked");
	add_class (seg, "segmented");
	for (guint i = 0; i < 4; i++) {
		range_buttons[i] = i == 0
			? gtk_radio_button_new_with_label (NULL, _(range_labels[i]))
			: gtk_radio_button_new_with_label_from_widget (
				GTK_RADIO_BUTTON (range_buttons[0]), _(range_labels[i]));
		gtk_toggle_button_set_mode (GTK_TOGGLE_BUTTON (range_buttons[i]),
		                            FALSE);
		add_class (range_buttons[i], "seg-button");
		g_signal_connect (range_buttons[i], "toggled",
		                  G_CALLBACK (on_range_toggled),
		                  GUINT_TO_POINTER (range_values[i]));
		gtk_box_pack_start (GTK_BOX (seg), range_buttons[i], FALSE, FALSE, 0);
	}
	syncing = TRUE;
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (range_buttons[1]), TRUE);
	syncing = FALSE;
	gtk_box_pack_start (GTK_BOX (bar), seg, FALSE, FALSE, 0);

	lbl = gtk_label_new (_("Adapter"));
	add_class (lbl, "dim-label");
	gtk_widget_set_margin_start (lbl, 8);
	gtk_box_pack_start (GTK_BOX (bar), lbl, FALSE, FALSE, 0);

	device_combo = gtk_combo_box_text_new ();
	gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (device_combo), "",
	                           _("All adapters"));
	gtk_combo_box_set_active (GTK_COMBO_BOX (device_combo), 0);
	g_signal_connect (device_combo, "changed",
	                  G_CALLBACK (on_device_changed), NULL);
	gtk_box_pack_start (GTK_BOX (bar), device_combo, FALSE, FALSE, 0);

	table_toggle = gtk_toggle_button_new_with_label (_("Show as table"));
	add_class (table_toggle, "btn-subtle");
	g_signal_connect (table_toggle, "toggled",
	                  G_CALLBACK (on_table_toggled), NULL);
	gtk_box_pack_end (GTK_BOX (bar), table_toggle, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (page), bar, FALSE, FALSE, 0);

	/* ---- headline numbers ---- */
	tiles = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
	gtk_box_set_homogeneous (GTK_BOX (tiles), TRUE);
	gtk_box_pack_start (GTK_BOX (tiles),
		build_tile (_("Blocked · last hour"), &tile_blocked, &tile_blocked_sub),
		TRUE, TRUE, 0);
	tile_allowed_card = build_tile (_("Allowed · last hour"), &tile_allowed,
	                                &tile_allowed_sub);
	/* Its children shown now; the tile itself is the backend's to
	 * show or hide (refresh_tiles), so the page's show_all skips it. */
	gtk_widget_show_all (tile_allowed_card);
	gtk_widget_set_no_show_all (tile_allowed_card, TRUE);
	gtk_box_pack_start (GTK_BOX (tiles), tile_allowed_card, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (tiles), build_net_tile (), TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (page), tiles, FALSE, FALSE, 0);

	/* ---- the two graphs, side by side ---- */
	grid = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
	gtk_box_set_homogeneous (GTK_BOX (grid), TRUE);
	gtk_box_pack_start (GTK_BOX (grid),
		build_chart_card (&events_chart, _("Policy activity graph")),
		TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (grid),
		build_chart_card (&net_chart, _("Network I/O graph")),
		TRUE, TRUE, 0);
	gtk_widget_set_vexpand (grid, TRUE);
	gtk_box_pack_start (GTK_BOX (page), grid, TRUE, TRUE, 0);

	g_signal_connect (page, "map", G_CALLBACK (on_page_map), NULL);

	/* First sample now (the baseline), then every two seconds. */
	fs_activityview_sample ();
	g_timeout_add (SAMPLE_MS, on_sample_timeout, NULL);

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_container_add (GTK_CONTAINER (scroll), page);

	refresh_all ();

	return scroll;
}
