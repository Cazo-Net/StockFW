/* Teeth for the light theme: src/ui/fs-theme.css, compiled into the
 * binary as fs-theme-css.h (same string the application installs).
 * Two promises the eyes made during review, both of which have
 * visibly regressed once already:
 *
 *   1. GEOMETRY -- a sidebar item (1.0.7; the tab buttons before it)
 *      allocates the SAME height in every state (checked, prelight,
 *      active, and both class variants: with and without
 *      .nav-active).  The original page-switch "shake" was the
 *      active/transient tab carrying Adwaita's default button
 *      metrics (+2px border + different padding), which resized the
 *      band -- and with it the whole page -- on every switch.  Any
 *      per-state or per-class metric difference fails here before a
 *      user ever sees the jitter.
 *
 *   2. COLOUR -- primary actions paint the ink #16181D (hover
 *      #2A2F39), the selected sidebar item paints #2A2F39 even in the
 *      checked-before-class beat, a selected list row is the neutral
 *      #EAF0FB rather than the alert red it used to be, and no state
 *      shows Adwaita's 1px white inset highlight above the face (the
 *      "bit of white above any button").
 *
 * The checks read the stylesheet the way the app applies it: install
 * the generated CSS on the default screen at APPLICATION priority,
 * then ask GTK for sizes and rendered pixels.
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "fs-theme-css.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	if (!(cond)) {                                             \
		printf ("FAIL: ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
		failures++;                                         \
	} else {                                                  \
		printf ("ok:   ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
	}                                                         \
} while (0)

/* The same install path as fs-app.c's install_theme(): one provider,
 * APPLICATION priority, default screen. */
static gboolean
install_theme (void)
{
	GtkCssProvider *provider = gtk_css_provider_new ();
	GError *error = NULL;

	if (!gtk_css_provider_load_from_data (provider, fs_theme_css,
	                                      -1, &error)) {
		CHECK (FALSE, "theme stylesheet parses (%s)",
		       error ? error->message : "unknown error");
		g_clear_error (&error);
		g_object_unref (provider);
		return FALSE;
	}

	gtk_style_context_add_provider_for_screen (
		gdk_screen_get_default (),
		GTK_STYLE_PROVIDER (provider),
		GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	g_object_unref (provider);
	return TRUE;
}

/* ---------------------------------------------------------------- *
 * 1. Geometry: one height for every state x class combination      *
 * ---------------------------------------------------------------- */

static const GtkStateFlags state_matrix[] = {
	0,
	GTK_STATE_FLAG_PRELIGHT,
	GTK_STATE_FLAG_ACTIVE,
	GTK_STATE_FLAG_ACTIVE | GTK_STATE_FLAG_PRELIGHT,
	GTK_STATE_FLAG_CHECKED,
	GTK_STATE_FLAG_CHECKED | GTK_STATE_FLAG_PRELIGHT,
	GTK_STATE_FLAG_CHECKED | GTK_STATE_FLAG_ACTIVE,
	GTK_STATE_FLAG_CHECKED | GTK_STATE_FLAG_ACTIVE |
		GTK_STATE_FLAG_PRELIGHT,
};

static const gchar *
state_name (GtkStateFlags st)
{
	if (st == 0) return "normal";
	if (st & GTK_STATE_FLAG_CHECKED)
		return (st & GTK_STATE_FLAG_ACTIVE) ?
		       (st & GTK_STATE_FLAG_PRELIGHT ?
		        "checked+active+prelight" : "checked+active") :
		       (st & GTK_STATE_FLAG_PRELIGHT ?
		        "checked+prelight" : "checked");
	if (st & GTK_STATE_FLAG_ACTIVE)
		return (st & GTK_STATE_FLAG_PRELIGHT ?
		        "active+prelight" : "active");
	return "prelight";
}

static void
check_nav_heights (void)
{
	static const gchar *with_class[]    = { "nav-item", "nav-active" };
	static const gchar *without_class[] = { "nav-item" };
	const gchar **combos[] = { without_class, with_class };
	const gchar *combo_names[] = {
		"nav-item only (the checked-before-class beat)",
		"nav-item + nav-active"
	};
	gint base_min = -1, base_nat = -1;
	guint ci, si;

	/* One baseline across ALL sixteen measurements: if any state or
	 * class variant sizes differently, the band moves and the page
	 * shakes. */
	for (ci = 0; ci < G_N_ELEMENTS (combos); ci++) {
		GtkWidget *btn = gtk_button_new_with_label ("Copilot");
		GtkStyleContext *ctx = gtk_widget_get_style_context (btn);
		guint n_cls = (ci == 0) ? 1 : 2;

		/* Hidden widgets report a 0 size request, which would make
		 * every comparison vacuously equal. */
		gtk_widget_show (btn);

		for (si = 0; si < n_cls; si++)
			gtk_style_context_add_class (ctx, combos[ci][si]);

		for (si = 0; si < G_N_ELEMENTS (state_matrix); si++) {
			gint min = -1, nat = -1;

			gtk_style_context_set_state (ctx, state_matrix[si]);
			gtk_widget_get_preferred_height (btn, &min, &nat);

			if (base_min < 0) {
				base_min = min;
				base_nat = nat;
				continue;
			}
			CHECK (min == base_min && nat == base_nat,
			       "%s / %s: height %d min / %d nat matches band baseline %d/%d",
			       combo_names[ci], state_name (state_matrix[si]),
			       min, nat, base_min, base_nat);
		}
		gtk_widget_destroy (btn);
	}

	CHECK (base_min > 0 && base_nat > 0,
	       "sidebar item reports a real size request (%d min / %d nat)",
	       base_min, base_nat);
}

/* ---------------------------------------------------------------- *
 * 2. Colour: accent red, no white sliver                            *
 * ---------------------------------------------------------------- */

/* Render a widget's background+frame in one state into an ARGB32
 * image surface (the same gtk_render_* path the screen uses). */
static cairo_surface_t *
render_state (GtkWidget *w, GtkStateFlags st, gint width, gint height)
{
	GtkStyleContext *ctx = gtk_widget_get_style_context (w);
	cairo_surface_t *surface;
	cairo_t *cr;

	gtk_style_context_set_state (ctx, st);
	surface = cairo_image_surface_create (CAIRO_FORMAT_ARGB32,
	                                      width, height);
	cr = cairo_create (surface);
	gtk_render_background (ctx, cr, 0, 0, width, height);
	gtk_render_frame (ctx, cr, 0, 0, width, height);
	cairo_destroy (cr);
	cairo_surface_flush (surface);
	return surface;
}

/* ARGB32 premultiplied, little-endian: bytes are B,G,R,A. */
static void
pixel_at (cairo_surface_t *s, gint x, gint y, gint *r, gint *g, gint *b)
{
	const guchar *data = cairo_image_surface_get_data (s);
	int stride = cairo_image_surface_get_stride (s);
	const guchar *p = data + (y * stride) + (x * 4);

	*b = p[0];
	*g = p[1];
	*r = p[2];
}

static gboolean
near (gint v, gint target, gint tol)
{
	return v >= target - tol && v <= target + tol;
}

static void
check_fill (const gchar *label, const gchar *klass, const gchar *klass2,
            GtkStateFlags st, gint er, gint eg, gint eb)
{
	GtkWidget *btn = gtk_button_new_with_label ("Run Analysis");
	GtkStyleContext *ctx = gtk_widget_get_style_context (btn);
	cairo_surface_t *s;
	gint r, g, b;

	gtk_style_context_add_class (ctx, klass);
	if (klass2 != NULL)
		gtk_style_context_add_class (ctx, klass2);

	s = render_state (btn, st, 140, 36);
	pixel_at (s, 70, 18, &r, &g, &b);
	CHECK (near (r, er, 2) && near (g, eg, 2) && near (b, eb, 2),
	       "%s: centre paints rgb(%d,%d,%d) (want %d,%d,%d)",
	       label, r, g, b, er, eg, eb);
	cairo_surface_destroy (s);
	gtk_widget_destroy (btn);
}

static void
check_no_white_sliver (const gchar *label, const gchar *klass,
                       GtkStateFlags st)
{
	GtkWidget *btn = gtk_button_new_with_label ("Run Analysis");
	GtkStyleContext *ctx = gtk_widget_get_style_context (btn);
	cairo_surface_t *s;
	gint r, g, b;
	gboolean white = FALSE;
	gint y;

	gtk_style_context_add_class (ctx, klass);
	s = render_state (btn, st, 140, 36);

	/* First few rows just inside the 1px border: Adwaita's inset
	 * highlight used to paint 255,255,255 here on hover/focus. */
	for (y = 1; y <= 3; y++) {
		pixel_at (s, 70, y, &r, &g, &b);
		if (r > 235 && g > 235 && b > 235)
			white = TRUE;
	}
	CHECK (!white, "%s: no white sliver under the top border",
	       label);
	cairo_surface_destroy (s);
	gtk_widget_destroy (btn);
}

static void
check_colours (void)
{
	/* Primary actions: #16181D face, #2A2F39 hover, never white. */
	check_fill ("btn-primary rest face", "btn-primary", NULL, 0,
	            0x16, 0x18, 0x1d);
	check_fill ("btn-primary hover face", "btn-primary", NULL,
	            GTK_STATE_FLAG_PRELIGHT, 0x2a, 0x2f, 0x39);
	check_no_white_sliver ("btn-primary hover", "btn-primary",
	                       GTK_STATE_FLAG_PRELIGHT);
	check_no_white_sliver ("btn-primary focused", "btn-primary",
	                       GTK_STATE_FLAG_FOCUSED);

	/* Selected sidebar item: filled with the class, AND in the
	 * transient checked-before-class beat that used to fall back to
	 * the theme. */
	check_fill ("selected item (checked + nav-active)",
	            "nav-item", "nav-active",
	            GTK_STATE_FLAG_CHECKED, 0x2a, 0x2f, 0x39);
	check_fill ("checked beat without nav-active class",
	            "nav-item", NULL,
	            GTK_STATE_FLAG_CHECKED, 0x2a, 0x2f, 0x39);
	check_fill ("selected item at rest", "nav-item", "nav-active",
	            0, 0x2a, 0x2f, 0x39);

	/* A selected row is a neutral highlight, not an alarm. */
	{
		GtkWidget *view = gtk_tree_view_new ();
		GtkStyleContext *ctx = gtk_widget_get_style_context (view);
		GdkRGBA *bg = NULL;

		gtk_style_context_set_state (ctx, GTK_STATE_FLAG_SELECTED);
		gtk_style_context_get (ctx, GTK_STATE_FLAG_SELECTED,
		                       "background-color", &bg, NULL);
		CHECK (bg != NULL &&
		       near ((gint) (bg->red * 255 + 0.5), 0xea, 2) &&
		       near ((gint) (bg->green * 255 + 0.5), 0xf0, 2) &&
		       near ((gint) (bg->blue * 255 + 0.5), 0xfb, 2),
		       "a selected list row is the neutral #EAF0FB "
		       "(got %.0f,%.0f,%.0f)",
		       bg ? bg->red * 255 : -1, bg ? bg->green * 255 : -1,
		       bg ? bg->blue * 255 : -1);
		if (bg != NULL)
			gdk_rgba_free (bg);
		gtk_widget_destroy (view);
	}

	/* The sliver killer must actually be in the stylesheet -- a
	 * render pipeline that skips box-shadows would otherwise hide
	 * its removal. */
	CHECK (strstr (fs_theme_css, "box-shadow: none") != NULL,
	       "stylesheet clears box-shadow (white-sliver fix present)");
}

int
main (int argc, char **argv)
{
	gtk_init (&argc, &argv);

	if (install_theme ()) {
		check_nav_heights ();
		check_colours ();
	}

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);

	return failures ? 1 : 0;
}
