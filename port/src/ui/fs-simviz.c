/*---[ fs-simviz.c ]----------------------------------------------------
 * The What-If Simulation Visualizer.
 *
 * Layout, top to bottom: a header bar with the title and (X), the
 * question as a pill, the diagram, a banner with the verdict and the
 * packet details, the explanation, and a footer.
 *
 * The diagram is flat and vector-drawn with cairo -- a PC, a brick
 * wall with a flame, a globe or a server, dotted green lines, and an
 * envelope that travels.  It plays one of three scripts:
 *
 *   allowed  the packet reaches the firewall, the wall flashes green,
 *            a check pops, the packet continues, the far node glows;
 *   blocked  the packet reaches the wall, the wall shakes red, an X
 *            pops, the packet bounces back and fades, the far line
 *            turns gray;
 *   error    no verdict at all: the scene dims and shows a "?" --
 *            an unreadable line must not look like a firewall
 *            decision.
 *
 * The scripts live in fs_simviz_state_at(): pure arithmetic over
 * (outcome, seconds), no GTK and no clock, so tests assert every
 * frame.  This file only maps that state onto pixels.
 *
 * Light theme by default; the palette is one table, so a dark theme
 * is a second table, not a rewrite.
 *--------------------------------------------------------------------*/

#include "fs-simviz.h"
#include "core/fs-i18n.h"

#include <gdk/gdkkeysyms.h>
#include <string.h>

/* =====================================================================
 * Pure timeline
 * ===================================================================== */

FsSimvizOutcome
fs_simviz_outcome_of (const FsSimulationResult *result)
{
	if (result == NULL)
		return FS_SIMVIZ_ERROR;

	return result->would_block ? FS_SIMVIZ_BLOCKED : FS_SIMVIZ_ALLOWED;
}

/* Phase marks, seconds from play start. */
#define T_REACH   1.10  /* the packet is at the firewall          */
#define T_VERDICT 1.15  /* the check/X pops in                    */
#define T_TAIL    1.30  /* blocked: the far line turns gray      */
#define T_LEG2    1.40  /* allowed: the second leg starts        */
#define T_BOUNCE  1.45  /* blocked: the packet starts falling    */
#define T_GONE    1.65  /* blocked: the packet is gone           */
#define T_GLOW    2.20  /* allowed: the far node starts glowing  */
#define T_ARRIVE  2.40  /* allowed: the packet arrives            */

/* Smoothstep: slow in, slow out, no overshoot. */
static gdouble
ease (gdouble x)
{
	if (x <= 0.0)
		return 0.0;
	if (x >= 1.0)
		return 1.0;
	return x * x * (3.0 - 2.0 * x);
}

/* Ramp 0..1 over [start, start+span], clamped. */
static gdouble
ramp (gdouble t, gdouble start, gdouble span)
{
	if (t <= start)
		return 0.0;
	if (t >= start + span)
		return 1.0;
	return (t - start) / span;
}

FsSimvizState
fs_simviz_state_at (FsSimvizOutcome outcome, gdouble t)
{
	FsSimvizState s;

	memset (&s, 0, sizeof s);
	s.packet = -1.0;
	s.packet_alpha = 0.0;
	s.t = t;

	/* An unreadable line has no timeline at all: one frozen,
	 * packetless, badgeless frame however long you look at it. */
	if (outcome == FS_SIMVIZ_ERROR) {
		s.done = TRUE;
		return s;
	}

	if (t >= FS_SIMVIZ_DURATION) {
		/* Freeze on the end state. */
		s.done = TRUE;
		if (outcome == FS_SIMVIZ_ALLOWED) {
			s.packet = 1.0;
			s.packet_alpha = 1.0;
			s.fw_green = 1.0;
			s.show_check = TRUE;
			s.dest_glow = 1.0;
		} else {
			s.fw_red = 1.0;
			s.show_x = TRUE;
			s.tail_blocked = TRUE;
		}
		return s;
	}

	if (outcome == FS_SIMVIZ_ALLOWED) {
		if (t < T_REACH) {
			s.packet = 0.5 * ease (t / T_REACH);
		} else if (t < T_LEG2) {
			s.packet = 0.5;               /* held at the wall */
		} else {
			s.packet = 0.5 + 0.5 *
			  ease ((t - T_LEG2) / (T_ARRIVE - T_LEG2));
		}
		s.packet_alpha = 1.0;
		s.fw_green = ramp (t, T_REACH, 0.30);
		s.show_check = (t >= T_VERDICT);
		s.dest_glow = ramp (t, T_GLOW, 0.40);
	} else {  /* FS_SIMVIZ_BLOCKED */
		if (t < T_REACH) {
			s.packet = 0.5 * ease (t / T_REACH);
			s.packet_alpha = 1.0;
		} else if (t < T_BOUNCE) {
			s.packet = 0.5;
			s.packet_alpha = 1.0;
		} else if (t < T_GONE) {
			/* Bounce back from the wall, fading as it goes. */
			gdouble k = ease ((t - T_BOUNCE) / (T_GONE - T_BOUNCE));

			s.packet = 0.5 - 0.18 * k;
			s.packet_alpha = 1.0 - k;
		}
		s.fw_red = ramp (t, T_REACH, 0.25);
		/* The shake lives only while the wall is actively
		 * rejecting; the end state is a still red wall. */
		s.shake = (t >= T_REACH && t < T_GONE) ? s.fw_red : 0.0;
		s.show_x = (t >= T_VERDICT);
		s.tail_blocked = (t >= T_TAIL);
	}

	return s;
}

/* =====================================================================
 * Palette (light theme; one table, so dark is a second table)
 * ===================================================================== */
typedef struct
{
	gdouble r, g, b, a;
} Color;

#define RGB(r, g, b) { (r) / 255.0, (g) / 255.0, (b) / 255.0, 1.0 }

static const Color C_WHITE    = RGB (255, 255, 255);
static const Color C_BORDER   = RGB (229, 231, 235);
static const Color C_TEXT     = RGB (17, 24, 39);
static const Color C_ACCENT   = RGB (59, 130, 246);
static const Color C_ACCENT_L = RGB (219, 234, 254);
static const Color C_GREEN    = RGB (34, 197, 94);
static const Color C_RED      = RGB (239, 68, 68);
static const Color C_LINE_G   = RGB (156, 163, 175);
static const Color C_BRICK    = RGB (254, 215, 170);
static const Color C_BRICK_L  = RGB (253, 186, 116);
static const Color C_FLAME    = RGB (249, 115, 22);
static const Color C_FLAME_I  = RGB (251, 191, 36);

static void
set_color (cairo_t *cr, const Color *c, gdouble alpha_mul)
{
	cairo_set_source_rgba (cr, c->r, c->g, c->b,
	                       c->a * (alpha_mul < 0.0 ? 0.0 : alpha_mul));
}

/* =====================================================================
 * One-time CSS for the window's widgets (badges, chip, panels)
 * ===================================================================== */
static gboolean css_installed = FALSE;

static void
install_css (void)
{
	static const gchar *css =
		".fs-simviz           { background-color: #ffffff; }\n"
		".fs-simviz-title     { font-size: 1.15em; font-weight: bold;\n"
		"                       color: #111827; }\n"
		".fs-simviz-chip      { background-color: #eff6ff;\n"
		"                       color: #2563eb; border-radius: 12px;\n"
		"                       padding: 3px 12px; }\n"
		".fs-simviz-badge-ok  { background-color: #dcfce7;\n"
		"                       color: #16a34a; border-radius: 6px;\n"
		"                       padding: 6px 18px; font-weight: bold;\n"
		"                       font-size: 1.15em; }\n"
		".fs-simviz-badge-bad { background-color: #fee2e2;\n"
		"                       color: #dc2626; border-radius: 6px;\n"
		"                       padding: 6px 18px; font-weight: bold;\n"
		"                       font-size: 1.15em; }\n"
		".fs-simviz-panel     { background-color: #f9fafb;\n"
		"                       border-radius: 8px; padding: 8px 10px; }\n"
		".fs-simviz-caption   { color: #6b7280; font-size: 0.8em; }\n"
		".fs-simviz-value     { font-weight: bold; color: #111827; }\n"
		".fs-simviz-suggest   { color: #6b7280; }\n"
		".fs-simviz-examples  { color: #6b7280;\n"
		"                       font-family: monospace; }\n"
		"button.fs-simviz-primary { background-color: #3b82f6;\n"
		"                       color: #ffffff; border: none;\n"
		"                       border-radius: 6px;\n"
		"                       padding: 6px 20px;\n"
		"                       font-weight: bold; }\n"
		"button.fs-simviz-primary:hover { background-color: #2563eb; }\n";
	GtkCssProvider *provider;
	GError *error = NULL;

	if (css_installed)
		return;

	provider = gtk_css_provider_new ();
	if (gtk_css_provider_load_from_data (provider, css, -1, &error)) {
		gtk_style_context_add_provider_for_screen (
			gdk_screen_get_default (),
			GTK_STYLE_PROVIDER (provider),
			GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	}
	g_clear_error (&error);
	g_object_unref (provider);

	css_installed = TRUE;
}

/* =====================================================================
 * Context
 * ===================================================================== */
typedef struct
{
	GtkWidget      *area;
	GtkWidget      *dialog;
	FsSimvizOutcome outcome;
	FsSimvizState   state;
	gboolean        dest_is_globe;   /* FALSE: server (inbound)    */
	gboolean        dest_is_local;   /* TRUE: the card is ours    */

	/* Owned display strings. */
	gchar *origin_label;
	gchar *dest_label;
	gchar *query;
	gchar *explanation;   /* bare reason, or NULL in the error state */
	gchar *suggestion;    /* "To allow this, ..." or NULL           */
	gchar *details[5];    /* protocol, source, dest, port, direction */

	gint64 t0_us;
	guint  timer_id;
} SimvizCtx;

/* Triangle wave in [-1, 1] -- a shake without libm. */
static gdouble
wave (gdouble t)
{
	gdouble phase = t * 9.0;
	gdouble f = phase - (gdouble) ((gint64) phase);

	return (f < 0.5) ? (1.0 - 4.0 * f) : (4.0 * f - 3.0);
}

/* =====================================================================
 * Drawing: flat vector pieces
 * ===================================================================== */
static void
rounded_rect (cairo_t *cr, gdouble x, gdouble y, gdouble w, gdouble h,
              gdouble r)
{
	gdouble r2 = (w < h ? w : h) / 2.0;

	if (r > r2)
		r = r2;

	cairo_new_sub_path (cr);
	cairo_arc (cr, x + w - r, y + r, r, -1.5707963, 0.0);
	cairo_arc (cr, x + w - r, y + h - r, r, 0.0, 1.5707963);
	cairo_arc (cr, x + r, y + h - r, r, 1.5707963, 3.1415927);
	cairo_arc (cr, x + r, y + r, r, 3.1415927, 4.7123890);
	cairo_close_path (cr);
}

/* A node card: white box, hairline border, optional green glow. */
static void
draw_node_card (cairo_t *cr, gdouble cx, gdouble cy, gdouble w, gdouble h,
                gdouble glow)
{
	if (glow > 0.0) {
		cairo_save (cr);
		rounded_rect (cr, cx - w / 2.0 - 5, cy - h / 2.0 - 5,
		              w + 10, h + 10, 13);
		set_color (cr, &C_GREEN, 0.16 * glow);
		cairo_fill (cr);
		cairo_restore (cr);
	}

	rounded_rect (cr, cx - w / 2.0, cy - h / 2.0, w, h, 10);
	set_color (cr, &C_WHITE, 1.0);
	cairo_fill (cr);
	set_color (cr, &C_BORDER, 1.0);
	cairo_set_line_width (cr, 1.4);
	cairo_stroke (cr);
}

/* The PC/monitor icon: a screen, a stand, a base. */
static void
draw_pc (cairo_t *cr, gdouble cx, gdouble cy)
{
	rounded_rect (cr, cx - 15, cy - 14, 30, 20, 3);
	set_color (cr, &C_ACCENT_L, 1.0);
	cairo_fill (cr);
	set_color (cr, &C_ACCENT, 1.0);
	cairo_set_line_width (cr, 1.4);
	cairo_stroke (cr);

	cairo_move_to (cr, cx - 6, cy + 7);
	cairo_line_to (cr, cx - 4, cy + 13);
	cairo_move_to (cr, cx + 6, cy + 7);
	cairo_line_to (cr, cx + 4, cy + 13);
	cairo_move_to (cr, cx - 9, cy + 14);
	cairo_line_to (cr, cx + 9, cy + 14);
	cairo_set_line_width (cr, 1.6);
	cairo_stroke (cr);
}

/* The server icon: two rack units with a status light each. */
static void
draw_server (cairo_t *cr, gdouble cx, gdouble cy)
{
	for (gint i = 0; i < 2; i++) {
		gdouble y = cy - 15 + i * 16;

		rounded_rect (cr, cx - 15, y, 30, 13, 2);
		set_color (cr, &C_ACCENT_L, 1.0);
		cairo_fill (cr);
		set_color (cr, &C_ACCENT, 1.0);
		cairo_set_line_width (cr, 1.1);
		cairo_stroke (cr);

		cairo_arc (cr, cx + 10, y + 6.5, 2.0, 0.0, 6.2831853);
		set_color (cr, &C_ACCENT, 1.0);
		cairo_fill (cr);

		cairo_move_to (cr, cx - 12, y + 4.5);
		cairo_line_to (cr, cx + 3, y + 4.5);
		cairo_move_to (cr, cx - 12, y + 8.5);
		cairo_line_to (cr, cx + 3, y + 8.5);
		set_color (cr, &C_ACCENT, 0.5);
		cairo_set_line_width (cr, 1.0);
		cairo_stroke (cr);
	}
}

/* The globe icon: circle, equator, meridian. */
static void
draw_globe (cairo_t *cr, gdouble cx, gdouble cy)
{
	cairo_arc (cr, cx, cy, 15, 0.0, 6.2831853);
	set_color (cr, &C_ACCENT_L, 1.0);
	cairo_fill (cr);
	set_color (cr, &C_ACCENT, 1.0);
	cairo_set_line_width (cr, 1.4);
	cairo_stroke (cr);

	/* Meridian: an ellipse squashed on x. */
	cairo_save (cr);
	cairo_translate (cr, cx, cy);
	cairo_scale (cr, 0.45, 1.0);
	cairo_arc (cr, 0.0, 0.0, 15, 0.0, 6.2831853);
	cairo_restore (cr);
	set_color (cr, &C_ACCENT, 0.8);
	cairo_set_line_width (cr, 1.1);
	cairo_stroke (cr);

	cairo_move_to (cr, cx - 15, cy);
	cairo_line_to (cr, cx + 15, cy);
	cairo_stroke (cr);
}

/* The firewall: a brick wall with a flame on top.  `wash_red` /
 * `wash_green` tint the wall with the verdict; `t` drives the shake. */
static void
draw_firewall (cairo_t *cr, gdouble cx, gdouble cy, gdouble wash_red,
               gdouble wash_green, gdouble shake, gdouble t)
{
	gdouble wall_x = cx - 32;
	gdouble wall_y = cy - 8;
	gdouble wall_w = 64;
	gdouble wall_h = 30;

	cairo_save (cr);
	cairo_translate (cr, shake * 4.0 * wave (t), 0.0);

	/* Flame above the wall: two teardrops. */
	cairo_save (cr);
	cairo_translate (cr, cx, cy - 12);

	cairo_move_to (cr, -8, 4);
	cairo_curve_to (cr, -10, -6, -4, -8, -1, -18);
	cairo_curve_to (cr, 2, -9, 10, -6, 8, 4);
	cairo_curve_to (cr, 6, 9, -6, 9, -8, 4);
	cairo_close_path (cr);
	set_color (cr, &C_FLAME, 1.0);
	cairo_fill (cr);

	cairo_move_to (cr, -4, 4);
	cairo_curve_to (cr, -5, -1, -2, -3, 0, -8);
	cairo_curve_to (cr, 2, -3, 5, -1, 4, 4);
	cairo_curve_to (cr, 3, 7, -3, 7, -4, 4);
	cairo_close_path (cr);
	set_color (cr, &C_FLAME_I, 1.0);
	cairo_fill (cr);
	cairo_restore (cr);

	/* The wall: three offset rows of bricks. */
	cairo_save (cr);
	rounded_rect (cr, wall_x, wall_y, wall_w, wall_h, 3);
	cairo_clip (cr);

	set_color (cr, &C_WHITE, 1.0);
	cairo_paint (cr);

	for (gint row = 0; row < 3; row++) {
		gdouble y = wall_y + row * 10.0;
		gdouble off = (row % 2 == 0) ? 0.0 : 8.0;

		for (gdouble x = wall_x - off; x < wall_x + wall_w;
		     x += 16.0) {
			cairo_rectangle (cr, x + 1, y + 1, 14, 8);
			set_color (cr, &C_BRICK, 1.0);
			cairo_fill (cr);
		}
	}
	cairo_restore (cr);

	/* Wall outline + verdict wash. */
	rounded_rect (cr, wall_x, wall_y, wall_w, wall_h, 3);
	set_color (cr, &C_BRICK_L, 1.0);
	cairo_set_line_width (cr, 1.3);
	cairo_stroke (cr);

	if (wash_red > 0.0) {
		rounded_rect (cr, wall_x, wall_y, wall_w, wall_h, 3);
		set_color (cr, &C_RED, 0.38 * wash_red);
		cairo_fill (cr);
	}
	if (wash_green > 0.0) {
		rounded_rect (cr, wall_x, wall_y, wall_w, wall_h, 3);
		set_color (cr, &C_GREEN, 0.35 * wash_green);
		cairo_fill (cr);
	}

	cairo_restore (cr);
}

/* The PDU envelope. */
static void
draw_packet (cairo_t *cr, gdouble x, gdouble y, gdouble alpha)
{
	if (alpha <= 0.0)
		return;

	cairo_save (cr);
	cairo_translate (cr, x, y);

	rounded_rect (cr, -15, -10, 30, 20, 4);
	set_color (cr, &C_WHITE, alpha);
	cairo_fill (cr);
	set_color (cr, &C_ACCENT, alpha);
	cairo_set_line_width (cr, 1.6);
	cairo_stroke (cr);

	cairo_move_to (cr, -15, -10);
	cairo_line_to (cr, 0, 2);
	cairo_line_to (cr, 15, -10);
	cairo_set_line_width (cr, 1.4);
	cairo_stroke (cr);

	cairo_restore (cr);
}

/* The verdict medallion above the wall. */
static void
draw_medallion (cairo_t *cr, gdouble x, gdouble y, gboolean green,
                gdouble pop)
{
	if (pop <= 0.0)
		return;

	cairo_save (cr);
	cairo_translate (cr, x, y);
	cairo_scale (cr, 0.5 + 0.5 * pop, 0.5 + 0.5 * pop);

	cairo_arc (cr, 0.0, 0.0, 15.0, 0.0, 6.2831853);
	set_color (cr, green ? &C_GREEN : &C_RED, pop);
	cairo_fill (cr);

	set_color (cr, &C_WHITE, pop);
	cairo_set_line_width (cr, 2.6);
	cairo_set_line_cap (cr, CAIRO_LINE_CAP_ROUND);

	if (green) {
		cairo_move_to (cr, -6.5, 0.5);
		cairo_line_to (cr, -2.0, 5.5);
		cairo_line_to (cr, 7.0, -5.5);
	} else {
		cairo_move_to (cr, -5.0, -5.0);
		cairo_line_to (cr, 5.0, 5.0);
		cairo_move_to (cr, 5.0, -5.0);
		cairo_line_to (cr, -5.0, 5.0);
	}
	cairo_stroke (cr);

	cairo_restore (cr);
}

/* A centered label anchored at (x, y), in the theme font. */
static void
draw_label (cairo_t *cr, GtkWidget *widget, const gchar *text,
            gdouble x, gdouble y, gboolean bold, gdouble size_pt,
            const Color *color)
{
	PangoLayout *layout;
	PangoFontDescription *font;
	PangoRectangle logical;
	GtkStyleContext *style;

	if (text == NULL || *text == '\0')
		return;

	set_color (cr, color, 1.0);

	layout = gtk_widget_create_pango_layout (widget, text);
	style = gtk_widget_get_style_context (widget);
	gtk_style_context_get (style, gtk_style_context_get_state (style),
	                       "font", &font, NULL);
	pango_font_description_set_size (font, (gint) (size_pt * PANGO_SCALE));
	if (bold)
		pango_font_description_set_weight (font, PANGO_WEIGHT_BOLD);
	pango_layout_set_font_description (layout, font);
	pango_font_description_free (font);

	pango_layout_get_extents (layout, NULL, &logical);
	cairo_move_to (cr, x - logical.width / 2.0 / PANGO_SCALE, y);
	pango_cairo_show_layout (cr, layout);
	g_object_unref (layout);
}

/* =====================================================================
 * The draw callback
 * ===================================================================== */
static gboolean
on_draw (GtkWidget *widget, cairo_t *cr, gpointer data)
{
	SimvizCtx *ctx = data;
	GtkAllocation alloc;
	gdouble w, h, x1, x2, x3, cy, badge_y;
	FsSimvizState *s = &ctx->state;

	gtk_widget_get_allocation (widget, &alloc);
	w = alloc.width;
	h = alloc.height;

	x1 = w * 0.14;
	x2 = w * 0.50;
	x3 = w * 0.86;
	cy = h * 0.46;
	badge_y = cy - 52.0;
	if (badge_y < 20.0)
		badge_y = 20.0;

	/* Background. */
	set_color (cr, &C_WHITE, 1.0);
	cairo_paint (cr);

	/* The lines, drawn under the cards.  Line one stays green; the
	 * segment past the wall grays out only once the wall has said
	 * no. */
	cairo_set_line_width (cr, 2.0);
	{
		gdouble dotted[2] = { 1.6, 3.6 };
		gdouble dashed[2] = { 7.0, 5.0 };

		cairo_set_dash (cr, dotted, 2, 0.0);
		set_color (cr, &C_GREEN, 1.0);
		cairo_move_to (cr, x1 + 34.0, cy);
		cairo_line_to (cr, x2 - 48.0, cy);
		cairo_stroke (cr);

		cairo_set_dash (cr, s->tail_blocked ? dashed : dotted, 2, 0.0);
		set_color (cr, s->tail_blocked ? &C_LINE_G : &C_GREEN, 1.0);
		cairo_move_to (cr, x2 + 48.0, cy);
		cairo_line_to (cr, x3 - 34.0, cy);
		cairo_stroke (cr);
		cairo_set_dash (cr, NULL, 0, 0.0);
	}

	/* The far card first, so its glow sits under its own box. */
	draw_node_card (cr, x3, cy, 64, 54, s->dest_glow);
	if (ctx->dest_is_globe)
		draw_globe (cr, x3, cy);
	else
		draw_server (cr, x3, cy);

	/* The near card: our machine or the remote one, always a PC. */
	draw_node_card (cr, x1, cy, 64, 54, 0.0);
	draw_pc (cr, x1, cy);

	/* The firewall card: a wide card with the wall drawn over it. */
	draw_node_card (cr, x2, cy, 88, 54, 0.0);
	draw_firewall (cr, x2, cy, s->fw_red, s->fw_green, s->shake, s->t);

	/* The packet. */
	if (s->packet >= 0.0) {
		gdouble packet_x = (s->packet <= 0.5)
		         ? x1 + (x2 - x1) * (s->packet / 0.5)
		         : x2 + (x3 - x2) * ((s->packet - 0.5) / 0.5);

		draw_packet (cr, packet_x, cy, s->packet_alpha);
	}

	/* The verdict medallion. */
	if (ctx->outcome == FS_SIMVIZ_ALLOWED)
		draw_medallion (cr, x2, badge_y, TRUE, s->fw_green);
	else if (ctx->outcome == FS_SIMVIZ_BLOCKED)
		draw_medallion (cr, x2, badge_y, FALSE, s->fw_red);

	/* Labels under the cards. */
	draw_label (cr, widget, ctx->origin_label, x1, cy + 36.0,
	            TRUE, 9.0, &C_TEXT);
	draw_label (cr, widget, "StockFW", x2, cy + 36.0,
	            TRUE, 9.0, &C_TEXT);
	draw_label (cr, widget, ctx->dest_label, x3, cy + 36.0,
	            TRUE, 9.0, &C_TEXT);

	/* Error state: wash the scene toward the background, then leave
	 * a "?" where the verdict would have been.  No packet, no
	 * check, no X -- an unreadable line is not a decision. */
	if (ctx->outcome == FS_SIMVIZ_ERROR) {
		set_color (cr, &C_WHITE, 0.55);
		cairo_paint (cr);

		cairo_arc (cr, x2, badge_y, 15.0, 0.0, 6.2831853);
		set_color (cr, &C_LINE_G, 1.0);
		cairo_fill (cr);
		draw_label (cr, widget, "?", x2, badge_y - 8.0,
		            TRUE, 12.0, &C_WHITE);
	}

	return TRUE;
}

/* =====================================================================
 * The clock
 * ===================================================================== */
static void
stop_play (SimvizCtx *ctx)
{
	if (ctx->timer_id != 0) {
		g_source_remove (ctx->timer_id);
		ctx->timer_id = 0;
	}
}

static gboolean
tick (gpointer data)
{
	SimvizCtx *ctx = data;
	gdouble t = (g_get_monotonic_time () - ctx->t0_us) /
	            (gdouble) G_USEC_PER_SEC;

	ctx->state = fs_simviz_state_at (ctx->outcome, t);
	gtk_widget_queue_draw (ctx->area);

	if (t >= FS_SIMVIZ_DURATION) {
		ctx->timer_id = 0;
		return G_SOURCE_REMOVE;
	}
	return G_SOURCE_CONTINUE;
}

static void
start_play (SimvizCtx *ctx)
{
	stop_play (ctx);
	ctx->t0_us = g_get_monotonic_time ();
	ctx->state = fs_simviz_state_at (ctx->outcome, 0.0);
	gtk_widget_queue_draw (ctx->area);

	if (ctx->outcome == FS_SIMVIZ_ERROR)
		return;                 /* nothing plays */

	ctx->timer_id = g_timeout_add (33, tick, ctx);
}

static void
ctx_free (gpointer data)
{
	SimvizCtx *ctx = data;

	stop_play (ctx);
	g_free (ctx->origin_label);
	g_free (ctx->dest_label);
	g_free (ctx->query);
	g_free (ctx->explanation);
	g_free (ctx->suggestion);
	for (guint i = 0; i < G_N_ELEMENTS (ctx->details); i++)
		g_free (ctx->details[i]);
	g_free (ctx);
}

/* =====================================================================
 * Widget walkers -- exposed for the smoke test, which reads the
 * window the way the user does: by what is on screen.
 * ===================================================================== */
GtkWidget *
fs_simviz_find_label (GtkWidget *root, const gchar *needle)
{
	if (root == NULL || needle == NULL)
		return NULL;

	if (GTK_IS_LABEL (root)) {
		const gchar *text = gtk_label_get_text (GTK_LABEL (root));

		if (text != NULL && strstr (text, needle) != NULL)
			return root;
	}

	if (GTK_IS_CONTAINER (root)) {
		GList *children = gtk_container_get_children (
			GTK_CONTAINER (root));
		GList *l;
		GtkWidget *hit = NULL;

		for (l = children; l != NULL && hit == NULL; l = l->next)
			hit = fs_simviz_find_label (GTK_WIDGET (l->data), needle);

		g_list_free (children);
		return hit;
	}

	return NULL;
}

GtkWidget *
fs_simviz_find_button (GtkWidget *root, const gchar *needle)
{
	if (root == NULL || needle == NULL)
		return NULL;

	if (GTK_IS_BUTTON (root) &&
	    fs_simviz_find_label (root, needle) != NULL)
		return root;

	if (GTK_IS_CONTAINER (root)) {
		GList *children = gtk_container_get_children (
			GTK_CONTAINER (root));
		GList *l;
		GtkWidget *hit = NULL;

		for (l = children; l != NULL && hit == NULL; l = l->next)
			hit = fs_simviz_find_button (GTK_WIDGET (l->data), needle);

		g_list_free (children);
		return hit;
	}

	return NULL;
}

/* =====================================================================
 * Content assembly
 * ===================================================================== */
static GtkWidget *
make_chip (const gchar *text)
{
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	GtkWidget *label = gtk_label_new (text != NULL && *text != '\0'
	                                  ? text : _("(no question)"));

	gtk_style_context_add_class (gtk_widget_get_style_context (box),
	                             "fs-simviz-chip");
	gtk_label_set_ellipsize (GTK_LABEL (label), PANGO_ELLIPSIZE_END);
	gtk_label_set_max_width_chars (GTK_LABEL (label), 72);
	gtk_box_pack_start (GTK_BOX (box), label, FALSE, FALSE, 0);
	return box;
}

static GtkWidget *
make_detail (const gchar *caption, const gchar *value)
{
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	GtkWidget *cap = gtk_label_new (_(caption));
	GtkWidget *val = gtk_label_new (value != NULL ? value : _("n/a"));

	gtk_style_context_add_class (gtk_widget_get_style_context (cap),
	                             "fs-simviz-caption");
	gtk_style_context_add_class (gtk_widget_get_style_context (val),
	                             "fs-simviz-value");
	gtk_label_set_xalign (GTK_LABEL (cap), 0.0);
	gtk_label_set_xalign (GTK_LABEL (val), 0.0);
	gtk_box_pack_start (GTK_BOX (box), cap, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (box), val, FALSE, FALSE, 0);
	return box;
}

static GtkWidget *
button_with_icon (const gchar *icon_name, const gchar *label)
{
	GtkWidget *btn = gtk_button_new ();
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 4);
	GtkWidget *img = gtk_image_new_from_icon_name (icon_name,
	                                               GTK_ICON_SIZE_BUTTON);
	GtkWidget *lbl = gtk_label_new (label);

	gtk_box_pack_start (GTK_BOX (box), img, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (box), lbl, FALSE, FALSE, 0);
	gtk_container_add (GTK_CONTAINER (btn), box);
	return btn;
}

/* Response trampolines: a button answers the dialog, nothing else. */
static void
on_close_clicked (GtkButton *btn, gpointer data)
{
	(void) btn;
	gtk_dialog_response (GTK_DIALOG (data), GTK_RESPONSE_CLOSE);
}

static void
on_create_clicked (GtkButton *btn, gpointer data)
{
	(void) btn;
	gtk_dialog_response (GTK_DIALOG (data), FS_SIMVIZ_RESPONSE_CREATE);
}

static void
on_replay_clicked (GtkButton *btn, gpointer data)
{
	(void) btn;
	start_play (data);
}

/* Esc closes the window, whatever the theme does with key bindings. */
static gboolean
on_key_press (GtkWidget *widget, GdkEventKey *event, gpointer data)
{
	(void) data;

	if (event->keyval == GDK_KEY_Escape) {
		gtk_dialog_response (GTK_DIALOG (widget),
		                     GTK_RESPONSE_DELETE_EVENT);
		return TRUE;
	}
	return FALSE;
}

/* The display strings the diagram and the banner read. */
static void
fill_labels (SimvizCtx *ctx, const FsSimulationResult *result,
             const FsScenario *sc, const gchar *query)
{
	gboolean inbound = (sc != NULL && sc->inbound);
	gboolean have_addr = (sc != NULL && sc->had_addr &&
	                      sc->remote_ip != NULL);
	gboolean icmp = (sc != NULL &&
	                 g_strcmp0 (sc->protocol, "ICMP") == 0);
	guint port = (sc != NULL) ? sc->port : 0;
	gboolean had_port = (sc != NULL && sc->had_port);

	ctx->query = g_strdup (query != NULL ? query : "");

	/* The left card is where the packet starts: our machine for an
	 * outbound line, the remote one for an inbound line. */
	ctx->origin_label = g_strdup (inbound
	                              ? (have_addr ? sc->remote_ip : _("any"))
	                              : _("local"));

	/* The right card is where it is going.  Inbound ends at our
	 * machine, and "local:22" says both halves of the address. */
	ctx->dest_is_globe = !inbound;
	ctx->dest_is_local = inbound;

	if (inbound)
		ctx->dest_label = had_port
			? g_strdup_printf (_("local:%u"), port)
			: g_strdup (_("local"));
	else
		ctx->dest_label = g_strdup (have_addr ? sc->remote_ip
		                                      : _("WWW"));

	if (result != NULL && result->reason != NULL)
		ctx->explanation = g_strdup (result->reason);

	/* Only a blocked verdict offers a way out -- and only when the
	 * line parsed, because the rule comes from the scenario. */
	if (sc != NULL && result != NULL && result->would_block) {
		gchar *sentence = fs_copilot_allow_suggestion (sc);

		if (sentence != NULL) {
			ctx->suggestion = g_strdup_printf (
				_("To allow this, add a rule: %s"), sentence);
			g_free (sentence);
		}
	}

	/* Details row: the five facts, each honest about "not named". */
	ctx->details[0] = g_strdup (sc != NULL ? sc->protocol : _("n/a"));
	ctx->details[1] = inbound
		? g_strdup (have_addr ? sc->remote_ip : _("any"))
		: g_strdup (_("local"));
	ctx->details[2] = inbound
		? g_strdup (_("local"))
		: g_strdup (have_addr ? sc->remote_ip : _("anywhere"));
	ctx->details[3] = had_port
		? g_strdup_printf ("%u", port)
		: g_strdup (icmp ? _("n/a") : _("any"));
	ctx->details[4] = inbound ? g_strdup (_("Inbound"))
	                          : g_strdup (_("Outbound"));
}

GtkWidget *
fs_simviz_dialog_new (const FsSimulationResult *result,
                      const FsScenario *scenario,
                      const gchar *query)
{
	SimvizCtx *ctx;
	GtkWidget *dialog;
	GtkWidget *header;
	GtkWidget *vbox;
	GtkWidget *chip_row;
	GtkWidget *area;
	GtkWidget *footer;
	GtkWidget *replay_btn = NULL;
	GtkWidget *create_btn = NULL;
	GtkWidget *close_btn;
	GtkWidget *spacer;
	FsSimvizOutcome outcome = fs_simviz_outcome_of (result);

	install_css ();

	ctx = g_new0 (SimvizCtx, 1);
	ctx->outcome = outcome;
	ctx->state = fs_simviz_state_at (outcome, 0.0);
	fill_labels (ctx, result, scenario, query);

	dialog = gtk_dialog_new ();
	ctx->dialog = dialog;
	g_object_set_data_full (G_OBJECT (dialog), "fs-simviz-ctx", ctx,
	                        ctx_free);
	g_signal_connect (dialog, "key-press-event",
	                  G_CALLBACK (on_key_press), NULL);

	gtk_window_set_title (GTK_WINDOW (dialog), _("What-If Simulation"));
	gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);
	gtk_window_set_default_size (GTK_WINDOW (dialog), 660, -1);

	header = gtk_header_bar_new ();
	gtk_header_bar_set_show_close_button (GTK_HEADER_BAR (header), TRUE);
	gtk_header_bar_set_title (GTK_HEADER_BAR (header),
	                          _("What-If Simulation"));
	gtk_window_set_titlebar (GTK_WINDOW (dialog), header);

	vbox = gtk_box_new (GTK_ORIENTATION_VERTICAL, 8);
	gtk_container_set_border_width (GTK_CONTAINER (vbox), 12);
	gtk_widget_set_size_request (vbox, 520, -1);
	gtk_style_context_add_class (gtk_widget_get_style_context (vbox),
	                             "fs-simviz");
	gtk_container_add (GTK_CONTAINER (
		gtk_dialog_get_content_area (GTK_DIALOG (dialog))), vbox);

	/* 1. The question, as a pill. */
	chip_row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_box_pack_start (GTK_BOX (chip_row), make_chip (ctx->query),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (vbox), chip_row, FALSE, FALSE, 0);

	/* 2. The diagram. */
	area = gtk_drawing_area_new ();
	ctx->area = area;
	gtk_widget_set_size_request (area, -1, 280);
	gtk_widget_set_hexpand (area, TRUE);
	g_signal_connect (area, "draw", G_CALLBACK (on_draw), ctx);
	gtk_box_pack_start (GTK_BOX (vbox), area, TRUE, TRUE, 0);

	/* 3. The banner: badge + packet details.  The error state has
	 *    no verdict and no packet, so it gets no banner either --
	 *    absent, not decorative. */
	if (outcome != FS_SIMVIZ_ERROR) {
		GtkWidget *banner = gtk_box_new (GTK_ORIENTATION_HORIZONTAL,
		                                 14);
		GtkWidget *badge;
		GtkWidget *details;
		static const gchar *captions[5] = {
			"PROTOCOL", "SOURCE", "DESTINATION", "PORT",
			"DIRECTION"
		};

		gtk_style_context_add_class (
			gtk_widget_get_style_context (banner), "fs-simviz-panel");
		gtk_container_set_border_width (GTK_CONTAINER (banner), 6);

		badge = gtk_label_new (outcome == FS_SIMVIZ_ALLOWED
		                       ? _("ALLOWED") : _("BLOCKED"));
		gtk_style_context_add_class (
			gtk_widget_get_style_context (badge),
			outcome == FS_SIMVIZ_ALLOWED ? "fs-simviz-badge-ok"
			                             : "fs-simviz-badge-bad");
		gtk_box_pack_start (GTK_BOX (banner), badge, FALSE, FALSE, 4);

		details = gtk_grid_new ();
		gtk_grid_set_column_spacing (GTK_GRID (details), 16);
		gtk_grid_set_row_spacing (GTK_GRID (details), 2);
		for (guint i = 0; i < 5; i++)
			gtk_grid_attach (GTK_GRID (details),
			                 make_detail (captions[i],
			                              ctx->details[i]),
			                 (gint) i, 0, 1, 1);
		gtk_box_pack_start (GTK_BOX (banner), details, TRUE, TRUE, 0);
		gtk_box_pack_start (GTK_BOX (vbox), banner, FALSE, FALSE, 0);
	}

	/* 4. The explanation -- or the honest "could not read it". */
	if (outcome == FS_SIMVIZ_ERROR) {
		GtkWidget *warn = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
		GtkWidget *icon = gtk_image_new_from_icon_name (
			"dialog-warning", GTK_ICON_SIZE_DIALOG);
		GtkWidget *msg = gtk_label_new (
			_("Couldn't understand this query."));
		GtkWidget *examples;

		gtk_style_context_add_class (
			gtk_widget_get_style_context (msg), "fs-simviz-title");
		gtk_label_set_xalign (GTK_LABEL (msg), 0.0);
		gtk_box_pack_start (GTK_BOX (warn), icon, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (warn), msg, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (vbox), warn, FALSE, FALSE, 4);

		examples = gtk_label_new (
			_("e.g.  allow SSH from 192.168.1.50 on port 22\n"
			  "      block port 80 outbound\n"
			  "      allow ping from 192.168.1.5"));
		gtk_style_context_add_class (
			gtk_widget_get_style_context (examples),
			"fs-simviz-examples");
		gtk_label_set_xalign (GTK_LABEL (examples), 0.0);
		gtk_box_pack_start (GTK_BOX (vbox), examples, FALSE, FALSE, 0);
	} else {
		GtkWidget *expl = gtk_label_new (ctx->explanation);

		gtk_style_context_add_class (
			gtk_widget_get_style_context (expl), "fs-simviz-panel");
		gtk_label_set_line_wrap (GTK_LABEL (expl), TRUE);
		gtk_label_set_max_width_chars (GTK_LABEL (expl), 72);
		gtk_label_set_xalign (GTK_LABEL (expl), 0.0);
		gtk_box_pack_start (GTK_BOX (vbox), expl, FALSE, FALSE, 0);

		if (ctx->suggestion != NULL) {
			GtkWidget *sug = gtk_label_new (ctx->suggestion);

			gtk_style_context_add_class (
				gtk_widget_get_style_context (sug),
				"fs-simviz-suggest");
			gtk_label_set_line_wrap (GTK_LABEL (sug), TRUE);
			gtk_label_set_max_width_chars (GTK_LABEL (sug), 72);
			gtk_label_set_xalign (GTK_LABEL (sug), 0.0);
			gtk_box_pack_start (GTK_BOX (vbox), sug, FALSE, FALSE,
			                    0);
		}
	}

	/* 5. The footer. */
	footer = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	gtk_box_pack_start (GTK_BOX (vbox), footer, FALSE, FALSE, 4);

	if (outcome != FS_SIMVIZ_ERROR) {
		replay_btn = button_with_icon ("media-playback-start",
		                               _("Replay"));
		g_signal_connect (replay_btn, "clicked",
		                  G_CALLBACK (on_replay_clicked), ctx);
		gtk_box_pack_start (GTK_BOX (footer), replay_btn, FALSE,
		                    FALSE, 0);
	}

	if (outcome == FS_SIMVIZ_BLOCKED && scenario != NULL) {
		/* Present only when it can do something real: the rule is
		 * built from the very scenario the verdict answered. */
		create_btn = button_with_icon ("list-add",
		                               _("Create This Rule"));
		g_signal_connect (create_btn, "clicked",
		                  G_CALLBACK (on_create_clicked), dialog);
	}

	spacer = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_widget_set_hexpand (spacer, TRUE);
	gtk_box_pack_start (GTK_BOX (footer), spacer, TRUE, TRUE, 0);

	if (create_btn != NULL)
		gtk_box_pack_start (GTK_BOX (footer), create_btn, FALSE,
		                    FALSE, 0);

	close_btn = gtk_button_new_with_label (_("Close"));
	gtk_style_context_add_class (gtk_widget_get_style_context (close_btn),
	                             "fs-simviz-primary");
	g_signal_connect (close_btn, "clicked",
	                  G_CALLBACK (on_close_clicked), dialog);
	gtk_box_pack_end (GTK_BOX (footer), close_btn, FALSE, FALSE, 0);
	gtk_widget_set_can_default (close_btn, TRUE);
	gtk_dialog_set_default_response (GTK_DIALOG (dialog),
	                                 GTK_RESPONSE_CLOSE);

	return dialog;
}

FsSimvizResponse
fs_simviz_run (GtkWidget *parent,
               const FsSimulationResult *result,
               const FsScenario *scenario,
               const gchar *query)
{
	GtkWidget *dialog;
	SimvizCtx *ctx;
	gint response;

	dialog = fs_simviz_dialog_new (result, scenario, query);

	if (parent != NULL && GTK_IS_WINDOW (parent)) {
		gtk_window_set_transient_for (GTK_WINDOW (dialog),
		                              GTK_WINDOW (parent));
		gtk_window_set_position (GTK_WINDOW (dialog),
		                         GTK_WIN_POS_CENTER_ON_PARENT);
	} else {
		gtk_window_set_position (GTK_WINDOW (dialog),
		                         GTK_WIN_POS_CENTER);
	}

	gtk_widget_show_all (dialog);

	ctx = g_object_get_data (G_OBJECT (dialog), "fs-simviz-ctx");
	if (ctx != NULL)
		start_play (ctx);

	response = gtk_dialog_run (GTK_DIALOG (dialog));

	if (ctx != NULL)
		stop_play (ctx);

	gtk_widget_destroy (dialog);

	return (response == FS_SIMVIZ_RESPONSE_CREATE)
	       ? FS_SIMVIZ_CREATE_RULE : FS_SIMVIZ_CLOSED;
}
