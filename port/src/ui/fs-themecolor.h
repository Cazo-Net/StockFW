/* Theme colours for code that paints with cairo or sets a cell
 * renderer's colour by hand, where CSS does not reach.
 *
 * fs-theme.css names every colour of the look (fs_surface, fs_border,
 * fs_text_weak, ...) and Dark mode swaps their values.  Drawing code
 * asks for a colour by the same name each time it paints, so a chart
 * or a list row follows the mode like everything else.  The fallback
 * is used when no StockFW stylesheet is installed on the screen (a
 * smoke test that builds one page on the system theme).
 *
 * Header-only on purpose: no source list to keep in step. */
#ifndef FS_THEMECOLOR_H
#define FS_THEMECOLOR_H

#include <gtk/gtk.h>

G_BEGIN_DECLS

/* The named colour `name' as it resolves now, or `fallback' (a colour
 * string gdk_rgba_parse() reads). */
static inline void
fs_theme_color (const gchar *name, const gchar *fallback, GdkRGBA *out)
{
	static GtkStyleContext *ctx = NULL;

	if (ctx == NULL) {
		GtkWidgetPath *path = gtk_widget_path_new ();

		gtk_widget_path_append_type (path, GTK_TYPE_WINDOW);
		ctx = gtk_style_context_new ();
		gtk_style_context_set_path (ctx, path);
		gtk_widget_path_unref (path);
	}

	if (gtk_style_context_lookup_color (ctx, name, out))
		return;
	if (fallback == NULL || !gdk_rgba_parse (out, fallback)) {
		out->red = out->green = out->blue = 0.5;
		out->alpha = 1.0;
	}
}

/* Makes the named colour cairo's source, at `alpha' times its own. */
static inline void
fs_theme_source (cairo_t *cr, const gchar *name, const gchar *fallback,
                 gdouble alpha)
{
	GdkRGBA c;

	fs_theme_color (name, fallback, &c);
	cairo_set_source_rgba (cr, c.red, c.green, c.blue, c.alpha * alpha);
}

/* "#rrggbb" for Pango markup.  Free with g_free. */
static inline gchar *
fs_theme_hex (const gchar *name, const gchar *fallback)
{
	GdkRGBA c;

	fs_theme_color (name, fallback, &c);
	return g_strdup_printf ("#%02x%02x%02x",
	                        (guint) (c.red * 255 + 0.5),
	                        (guint) (c.green * 255 + 0.5),
	                        (guint) (c.blue * 255 + 0.5));
}

G_END_DECLS

#endif /* FS_THEMECOLOR_H */
