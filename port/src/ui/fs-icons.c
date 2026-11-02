/*---[ fs-icons.c ]-----------------------------------------------------
 * Line icons drawn with cairo.  See fs-icons.h.
 *
 * Every path is written on the 24-unit grid the mockup's SVG icons use,
 * so the shapes match the design one for one; fs_icon_draw scales the
 * grid to the requested size.
 *--------------------------------------------------------------------*/

#include "ui/fs-icons.h"

#include <math.h>

#define ICON_KIND_KEY "fs-icon-kind"

static void
shield_path (cairo_t *cr)
{
	/* M12 3 l7 3 v6 c0 4.5 -3 7.7 -7 9 c-4 -1.3 -7 -4.5 -7 -9 V6 z */
	cairo_move_to (cr, 12, 3);
	cairo_line_to (cr, 19, 6);
	cairo_line_to (cr, 19, 12);
	cairo_curve_to (cr, 19, 16.5, 16, 19.7, 12, 21);
	cairo_curve_to (cr, 8, 19.7, 5, 16.5, 5, 12);
	cairo_line_to (cr, 5, 6);
	cairo_close_path (cr);
}

static void
check_mark (cairo_t *cr)
{
	cairo_move_to (cr, 9, 12);
	cairo_line_to (cr, 11, 14);
	cairo_line_to (cr, 15, 10);
}

static void
circle (cairo_t *cr, gdouble x, gdouble y, gdouble r)
{
	cairo_new_sub_path (cr);
	cairo_arc (cr, x, y, r, 0, 2 * G_PI);
}

static void
rounded_rect (cairo_t *cr, gdouble x, gdouble y, gdouble w, gdouble h,
              gdouble r)
{
	cairo_new_sub_path (cr);
	cairo_arc (cr, x + w - r, y + r, r, -G_PI / 2, 0);
	cairo_arc (cr, x + w - r, y + h - r, r, 0, G_PI / 2);
	cairo_arc (cr, x + r, y + h - r, r, G_PI / 2, G_PI);
	cairo_arc (cr, x + r, y + r, r, G_PI, 3 * G_PI / 2);
	cairo_close_path (cr);
}

void
fs_icon_draw (cairo_t *cr, FsIconKind kind, gdouble size)
{
	gboolean fill_dots = FALSE;

	cairo_save (cr);
	cairo_scale (cr, size / 24.0, size / 24.0);
	cairo_set_line_width (cr, 2.0);
	cairo_set_line_cap (cr, CAIRO_LINE_CAP_ROUND);
	cairo_set_line_join (cr, CAIRO_LINE_JOIN_ROUND);
	cairo_new_path (cr);

	switch (kind) {
	case FS_ICON_SHIELD:
		shield_path (cr);
		break;

	case FS_ICON_SHIELD_CHECK:
		shield_path (cr);
		check_mark (cr);
		break;

	case FS_ICON_SHIELD_X:
		shield_path (cr);
		cairo_move_to (cr, 9.5, 9.5);
		cairo_line_to (cr, 14.5, 14.5);
		cairo_move_to (cr, 14.5, 9.5);
		cairo_line_to (cr, 9.5, 14.5);
		break;

	case FS_ICON_SHIELD_ALERT:
		shield_path (cr);
		cairo_move_to (cr, 12, 8);
		cairo_line_to (cr, 12, 12.5);
		cairo_stroke (cr);
		circle (cr, 12, 15.8, 1.2);
		fill_dots = TRUE;
		break;

	case FS_ICON_SHIELD_QUESTION:
		shield_path (cr);
		cairo_move_to (cr, 10, 9.6);
		cairo_curve_to (cr, 10.2, 7.6, 13.9, 7.6, 14, 9.8);
		cairo_curve_to (cr, 14, 11.4, 12, 11.4, 12, 13);
		cairo_stroke (cr);
		circle (cr, 12, 15.8, 1.2);
		fill_dots = TRUE;
		break;

	case FS_ICON_LIST:
		cairo_move_to (cr, 4, 6);
		cairo_line_to (cr, 20, 6);
		cairo_move_to (cr, 4, 12);
		cairo_line_to (cr, 20, 12);
		cairo_move_to (cr, 4, 18);
		cairo_line_to (cr, 14, 18);
		break;

	case FS_ICON_ACTIVITY:
		cairo_move_to (cr, 3, 17);
		cairo_line_to (cr, 8, 11);
		cairo_line_to (cr, 12, 15);
		cairo_line_to (cr, 20, 6);
		break;

	case FS_ICON_SLIDERS:
		cairo_move_to (cr, 5, 4);
		cairo_line_to (cr, 5, 7);
		cairo_move_to (cr, 5, 11);
		cairo_line_to (cr, 5, 20);
		cairo_move_to (cr, 12, 4);
		cairo_line_to (cr, 12, 13);
		cairo_move_to (cr, 12, 17);
		cairo_line_to (cr, 12, 20);
		cairo_move_to (cr, 19, 4);
		cairo_line_to (cr, 19, 6);
		cairo_move_to (cr, 19, 10);
		cairo_line_to (cr, 19, 20);
		circle (cr, 5, 9, 2);
		circle (cr, 12, 15, 2);
		circle (cr, 19, 8, 2);
		break;

	case FS_ICON_CHAT:
		/* A speech bubble with its tail at the lower left. */
		cairo_move_to (cr, 7, 5);
		cairo_line_to (cr, 18, 5);
		cairo_curve_to (cr, 19.7, 5, 21, 6.3, 21, 8);
		cairo_line_to (cr, 21, 14);
		cairo_curve_to (cr, 21, 15.7, 19.7, 17, 18, 17);
		cairo_line_to (cr, 10, 17);
		cairo_line_to (cr, 5, 21);
		cairo_line_to (cr, 5, 17);
		cairo_curve_to (cr, 3.9, 16.6, 3, 15.4, 3, 14);
		cairo_line_to (cr, 3, 8);
		cairo_curve_to (cr, 3, 6.3, 4.6, 5, 7, 5);
		cairo_close_path (cr);
		break;

	case FS_ICON_CHECK_CIRCLE:
		circle (cr, 12, 12, 9);
		check_mark (cr);
		break;

	case FS_ICON_SETTINGS:
		/* Two horizontal sliders: preferences. */
		cairo_move_to (cr, 4, 7);
		cairo_line_to (cr, 13, 7);
		cairo_move_to (cr, 17, 7);
		cairo_line_to (cr, 20, 7);
		cairo_move_to (cr, 4, 17);
		cairo_line_to (cr, 7, 17);
		cairo_move_to (cr, 11, 17);
		cairo_line_to (cr, 20, 17);
		circle (cr, 15, 7, 2);
		circle (cr, 9, 17, 2);
		break;

	case FS_ICON_INFO:
		circle (cr, 12, 12, 9);
		cairo_move_to (cr, 12, 11);
		cairo_line_to (cr, 12, 16);
		cairo_stroke (cr);
		circle (cr, 12, 8, 1.2);
		fill_dots = TRUE;
		break;

	case FS_ICON_LOCK:
		rounded_rect (cr, 5, 11, 14, 10, 2);
		cairo_move_to (cr, 8, 11);
		cairo_line_to (cr, 8, 8);
		cairo_arc (cr, 12, 8, 4, G_PI, 2 * G_PI);
		cairo_line_to (cr, 16, 11);
		break;

	case FS_ICON_UNLOCK:
		rounded_rect (cr, 5, 11, 14, 10, 2);
		cairo_move_to (cr, 8, 11);
		cairo_line_to (cr, 8, 8);
		cairo_arc (cr, 12, 8, 4, G_PI, 1.85 * G_PI);
		break;

	case FS_ICON_PLAY:
		cairo_move_to (cr, 8, 5);
		cairo_line_to (cr, 19, 12);
		cairo_line_to (cr, 8, 19);
		cairo_close_path (cr);
		break;

	case FS_ICON_STOP:
		rounded_rect (cr, 6, 6, 12, 12, 1.5);
		break;

	case FS_ICON_ADAPTER:
		rounded_rect (cr, 3, 7, 18, 10, 2);
		cairo_move_to (cr, 7, 17);
		cairo_line_to (cr, 7, 20);
		cairo_move_to (cr, 12, 17);
		cairo_line_to (cr, 12, 20);
		cairo_move_to (cr, 17, 17);
		cairo_line_to (cr, 17, 20);
		break;

	case FS_ICON_WIFI:
		cairo_new_sub_path (cr);
		cairo_arc (cr, 12, 19, 13, -3 * G_PI / 4, -G_PI / 4);
		cairo_new_sub_path (cr);
		cairo_arc (cr, 12, 19, 8.5, -3 * G_PI / 4, -G_PI / 4);
		cairo_new_sub_path (cr);
		cairo_arc (cr, 12, 19, 4, -3 * G_PI / 4, -G_PI / 4);
		cairo_stroke (cr);
		circle (cr, 12, 19, 1.3);
		fill_dots = TRUE;
		break;

	case FS_ICON_SEARCH:
		circle (cr, 11, 11, 7);
		cairo_move_to (cr, 20, 20);
		cairo_line_to (cr, 16, 16);
		break;

	case FS_ICON_DOT:
		circle (cr, 12, 12, 12);
		fill_dots = TRUE;
		break;

	case FS_ICON_HELP:
		circle (cr, 12, 12, 9);
		/* The hook: an arc over the top, then down to the stem. */
		cairo_new_sub_path (cr);
		cairo_arc (cr, 12, 9.5, 2.6, G_PI, 2 * G_PI + 0.35);
		cairo_curve_to (cr, 14.4, 11.4, 12, 11.6, 12, 13.6);
		cairo_stroke (cr);
		circle (cr, 12, 16.8, 1.2);
		fill_dots = TRUE;
		break;

	case FS_ICON_BACK:
		cairo_move_to (cr, 19, 12);
		cairo_line_to (cr, 5, 12);
		cairo_move_to (cr, 11, 6);
		cairo_line_to (cr, 5, 12);
		cairo_line_to (cr, 11, 18);
		break;

	case FS_ICON_FORWARD:
		cairo_move_to (cr, 5, 12);
		cairo_line_to (cr, 19, 12);
		cairo_move_to (cr, 13, 6);
		cairo_line_to (cr, 19, 12);
		cairo_line_to (cr, 13, 18);
		break;

	case FS_ICON_COPY:
		rounded_rect (cr, 9, 9, 11, 11, 2);
		cairo_move_to (cr, 15, 9);
		cairo_line_to (cr, 15, 6);
		cairo_curve_to (cr, 15, 4.9, 14.1, 4, 13, 4);
		cairo_line_to (cr, 6, 4);
		cairo_curve_to (cr, 4.9, 4, 4, 4.9, 4, 6);
		cairo_line_to (cr, 4, 13);
		cairo_curve_to (cr, 4, 14.1, 4.9, 15, 6, 15);
		cairo_line_to (cr, 9, 15);
		break;

	case FS_ICON_TERMINAL:
		rounded_rect (cr, 3, 5, 18, 14, 2);
		cairo_move_to (cr, 7, 10);
		cairo_line_to (cr, 10, 12.5);
		cairo_line_to (cr, 7, 15);
		cairo_move_to (cr, 12, 15);
		cairo_line_to (cr, 16, 15);
		break;

	case FS_ICON_KEYBOARD:
		rounded_rect (cr, 2.5, 6, 19, 12, 2);
		/* Round caps make each zero-length stroke a key. */
		for (gint k = 0; k < 5; k++) {
			cairo_move_to (cr, 6 + 3 * k, 10);
			cairo_line_to (cr, 6 + 3 * k, 10);
		}
		cairo_move_to (cr, 8, 14);
		cairo_line_to (cr, 16, 14);
		break;

	case FS_ICON_MONITOR:
		rounded_rect (cr, 3, 4, 18, 12, 2);
		cairo_move_to (cr, 12, 16);
		cairo_line_to (cr, 12, 20);
		cairo_move_to (cr, 8, 20);
		cairo_line_to (cr, 16, 20);
		break;

	case FS_ICON_CLOCK:
		circle (cr, 12, 12, 9);
		cairo_move_to (cr, 12, 7);
		cairo_line_to (cr, 12, 12);
		cairo_line_to (cr, 15.5, 14);
		break;

	case FS_ICON_N_KINDS:
	default:
		break;
	}

	if (fill_dots)
		cairo_fill (cr);
	else
		cairo_stroke (cr);

	cairo_restore (cr);
}

static gboolean
on_icon_draw (GtkWidget *widget, cairo_t *cr, gpointer data)
{
	GtkStyleContext *ctx = gtk_widget_get_style_context (widget);
	FsIconKind kind = fs_icon_get_kind (widget);
	gint w = gtk_widget_get_allocated_width (widget);
	gint h = gtk_widget_get_allocated_height (widget);
	gint size = MIN (w, h);
	GdkRGBA color;

	(void) data;

	gtk_style_context_get_color (ctx, gtk_style_context_get_state (ctx),
	                             &color);
	gdk_cairo_set_source_rgba (cr, &color);

	/* Centred in whatever the parent gave it. */
	cairo_translate (cr, (w - size) / 2.0, (h - size) / 2.0);
	fs_icon_draw (cr, kind, size);
	return FALSE;
}

/* A parent button changing state (hover, checked) changes the colour
 * this widget inherits, but does not by itself repaint it. */
static void
on_icon_style_updated (GtkWidget *widget, gpointer data)
{
	(void) data;
	gtk_widget_queue_draw (widget);
}

GtkWidget *
fs_icon_new (FsIconKind kind, gint size)
{
	GtkWidget *area = gtk_drawing_area_new ();

	gtk_widget_set_size_request (area, size, size);
	gtk_widget_set_halign (area, GTK_ALIGN_CENTER);
	gtk_widget_set_valign (area, GTK_ALIGN_CENTER);
	gtk_style_context_add_class (gtk_widget_get_style_context (area),
	                             "fs-icon");
	g_object_set_data (G_OBJECT (area), ICON_KIND_KEY,
	                   GINT_TO_POINTER (kind));
	g_signal_connect (area, "draw", G_CALLBACK (on_icon_draw), NULL);
	g_signal_connect (area, "style-updated",
	                  G_CALLBACK (on_icon_style_updated), NULL);
	return area;
}

void
fs_icon_set_kind (GtkWidget *icon, FsIconKind kind)
{
	g_return_if_fail (GTK_IS_WIDGET (icon));

	if (fs_icon_get_kind (icon) == kind)
		return;
	g_object_set_data (G_OBJECT (icon), ICON_KIND_KEY,
	                   GINT_TO_POINTER (kind));
	gtk_widget_queue_draw (icon);
}

FsIconKind
fs_icon_get_kind (GtkWidget *icon)
{
	return (FsIconKind) GPOINTER_TO_INT (
		g_object_get_data (G_OBJECT (icon), ICON_KIND_KEY));
}
