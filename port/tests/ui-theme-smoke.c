/* Teeth for the theme: src/ui/fs-theme.css, compiled into the binary
 * as fs-theme-css.h (same string the application installs), and the
 * light palette laid over it, src/ui/fs-theme-light.h.
 *
 * Three promises, the first two of which have visibly regressed once
 * already:
 *
 *   1. GEOMETRY -- a sidebar item allocates the SAME height in every
 *      state (checked, prelight, active, and both class variants: with
 *      and without .nav-active).  The original page-switch "shake" was
 *      the active/transient item carrying the system theme's default
 *      button metrics (+2px border + different padding), which resized
 *      the band -- and with it the whole page -- on every switch.  Any
 *      per-state or per-class metric difference fails here before a
 *      user ever sees the jitter.
 *
 *   2. COLOUR -- every face is one of the stylesheet's named colours:
 *      primary actions paint fs_primary (hover fs_primary_hover), the
 *      selected sidebar item paints fs_surface_2 even in the
 *      checked-before-class beat, a selected list row is the neutral
 *      fs_surface_3 rather than an alarm colour, and no state shows
 *      the system theme's inset highlight as a sliver of another
 *      colour under the top border.  The expected values are read
 *      from the stylesheet's own names, so a palette change does not
 *      need this file edited; a rule that stops using the palette
 *      fails.
 *
 *   3. TWO MODES -- the stylesheet is the dark palette; the light one
 *      redefines the same names.  It must parse, name every colour the
 *      stylesheet names, and actually change what the canvas and a
 *      primary button paint when it is installed above it.
 *
 * The checks read the stylesheet the way the app applies it: install
 * the generated CSS on the default screen at APPLICATION priority,
 * then ask GTK for sizes and rendered pixels.
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "fs-theme-css.h"
#include "../src/ui/fs-theme-light.h"

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

/* One of the stylesheet's named colours (@define-color), as it
 * resolves on the screen now. */
static gboolean
named (const gchar *name, gint *r, gint *g, gint *b)
{
	GtkWidget *probe = gtk_label_new (NULL);
	GdkRGBA c;
	gboolean found = gtk_style_context_lookup_color (
		gtk_widget_get_style_context (probe), name, &c);

	*r = found ? (gint) (c.red * 255 + 0.5) : -1;
	*g = found ? (gint) (c.green * 255 + 0.5) : -1;
	*b = found ? (gint) (c.blue * 255 + 0.5) : -1;
	gtk_widget_destroy (probe);
	return found;
}

static void
check_fill (const gchar *label, const gchar *klass, const gchar *klass2,
            GtkStateFlags st, const gchar *colour)
{
	gint er, eg, eb;

	named (colour, &er, &eg, &eb);
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
	       "%s: centre paints rgb(%d,%d,%d) (want %s %d,%d,%d)",
	       label, r, g, b, colour, er, eg, eb);
	cairo_surface_destroy (s);
	gtk_widget_destroy (btn);
	}
}

/* The system theme's inset highlight used to paint a pale band in the
 * first rows under the top border on hover and focus.  With a flat
 * face those rows are the face: any other colour there is a sliver. */
static void
check_no_sliver (const gchar *label, const gchar *klass, GtkStateFlags st)
{
	GtkWidget *btn = gtk_button_new_with_label ("Run Analysis");
	GtkStyleContext *ctx = gtk_widget_get_style_context (btn);
	cairo_surface_t *s;
	gint r, g, b, cr, cg, cb;
	gboolean sliver = FALSE;
	gint y;

	gtk_style_context_add_class (ctx, klass);
	s = render_state (btn, st, 140, 36);
	pixel_at (s, 70, 18, &cr, &cg, &cb);

	for (y = 1; y <= 3; y++) {
		pixel_at (s, 70, y, &r, &g, &b);
		if (!near (r, cr, 2) || !near (g, cg, 2) || !near (b, cb, 2))
			sliver = TRUE;
	}
	CHECK (!sliver, "%s: no sliver of another colour under the top border",
	       label);
	cairo_surface_destroy (s);
	gtk_widget_destroy (btn);
}

static void
check_colours (void)
{
	gint er, eg, eb;

	/* Primary actions: fs_primary, fs_primary_hover on hover. */
	check_fill ("btn-primary rest face", "btn-primary", NULL, 0,
	            "fs_primary");
	check_fill ("btn-primary hover face", "btn-primary", NULL,
	            GTK_STATE_FLAG_PRELIGHT, "fs_primary_hover");
	check_no_sliver ("btn-primary rest", "btn-primary", 0);
	check_no_sliver ("btn-primary hover", "btn-primary",
	                 GTK_STATE_FLAG_PRELIGHT);
	check_no_sliver ("btn-primary focused", "btn-primary",
	                 GTK_STATE_FLAG_FOCUSED);
	check_no_sliver ("btn-subtle hover", "btn-subtle",
	                 GTK_STATE_FLAG_PRELIGHT);
	check_no_sliver ("btn-subtle focused", "btn-subtle",
	                 GTK_STATE_FLAG_FOCUSED);

	/* Selected sidebar item: filled with the class, AND in the
	 * transient checked-before-class beat that used to fall back to
	 * the theme. */
	check_fill ("selected item (checked + nav-active)",
	            "nav-item", "nav-active",
	            GTK_STATE_FLAG_CHECKED, "fs_surface_2");
	check_fill ("checked beat without nav-active class",
	            "nav-item", NULL,
	            GTK_STATE_FLAG_CHECKED, "fs_surface_2");
	check_fill ("selected item at rest", "nav-item", "nav-active",
	            0, "fs_surface_2");

	/* A selected row is a neutral highlight, not an alarm. */
	{
		GtkWidget *view = gtk_tree_view_new ();
		GtkStyleContext *ctx = gtk_widget_get_style_context (view);
		GdkRGBA *bg = NULL;

		named ("fs_surface_3", &er, &eg, &eb);
		gtk_style_context_set_state (ctx, GTK_STATE_FLAG_SELECTED);
		gtk_style_context_get (ctx, GTK_STATE_FLAG_SELECTED,
		                       "background-color", &bg, NULL);
		CHECK (bg != NULL &&
		       near ((gint) (bg->red * 255 + 0.5), er, 2) &&
		       near ((gint) (bg->green * 255 + 0.5), eg, 2) &&
		       near ((gint) (bg->blue * 255 + 0.5), eb, 2),
		       "a selected list row is the neutral fs_surface_3 "
		       "(got %.0f,%.0f,%.0f, want %d,%d,%d)",
		       bg ? bg->red * 255 : -1, bg ? bg->green * 255 : -1,
		       bg ? bg->blue * 255 : -1, er, eg, eb);
		if (bg != NULL)
			gdk_rgba_free (bg);
		gtk_widget_destroy (view);
	}

	/* The sliver killer must actually be in the stylesheet -- a
	 * render pipeline that skips box-shadows would otherwise hide
	 * its removal. */
	CHECK (strstr (fs_theme_css, "box-shadow: none") != NULL,
	       "stylesheet clears box-shadow (sliver fix present)");

	/* The flat look: no gradient and no glow anywhere. */
	CHECK (strstr (fs_theme_css, "linear-gradient") == NULL,
	       "stylesheet draws no gradients");
	CHECK (strstr (fs_theme_css, "text-shadow: 0") == NULL,
	       "stylesheet draws no glows");
}

/* The colour a widget's style resolves to for background-color. */
static gboolean
bg_is (GtkWidget *w, gint r, gint g, gint b, gchar **got)
{
	GtkStyleContext *ctx = gtk_widget_get_style_context (w);
	GdkRGBA *bg = NULL;
	gboolean ok;

	gtk_style_context_get (ctx, gtk_style_context_get_state (ctx),
	                       "background-color", &bg, NULL);
	ok = bg != NULL &&
	     near ((gint) (bg->red * 255 + 0.5), r, 2) &&
	     near ((gint) (bg->green * 255 + 0.5), g, 2) &&
	     near ((gint) (bg->blue * 255 + 0.5), b, 2);
	*got = bg != NULL ? g_strdup_printf ("%.0f,%.0f,%.0f",
	                                     bg->red * 255, bg->green * 255,
	                                     bg->blue * 255)
	                  : g_strdup ("none");
	if (bg != NULL)
		gdk_rgba_free (bg);
	return ok;
}

/* A dialog's button row: Enter's button (the default response) is the
 * primary, the other one the quiet secondary on the card surface --
 * the pair every confirm and staging dialog shows. */
static void
check_dialog_buttons (void)
{
	GtkWidget *dialog = gtk_dialog_new_with_buttons (
		"theme smoke", NULL, 0,
		"_Cancel", GTK_RESPONSE_CANCEL,
		"_OK", GTK_RESPONSE_OK, NULL);
	GtkWidget *ok, *cancel;
	gchar *got;
	gint r, g, b;

	gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);
	ok = gtk_dialog_get_widget_for_response (GTK_DIALOG (dialog),
	                                         GTK_RESPONSE_OK);
	cancel = gtk_dialog_get_widget_for_response (GTK_DIALOG (dialog),
	                                             GTK_RESPONSE_CANCEL);

	named ("fs_primary", &r, &g, &b);
	CHECK (bg_is (ok, r, g, b, &got),
	       "dialog default button (OK) is fs_primary (got %s)", got);
	g_free (got);
	named ("fs_surface", &r, &g, &b);
	CHECK (bg_is (cancel, r, g, b, &got),
	       "dialog Cancel is the secondary on fs_surface (got %s)", got);
	g_free (got);

	gtk_widget_destroy (dialog);
}

/* ---------------------------------------------------------------- *
 * 3. Two modes: the light palette over the dark stylesheet          *
 * ---------------------------------------------------------------- */

static gdouble
luminance_of (const gchar *name)
{
	gint r, g, b;

	if (!named (name, &r, &g, &b))
		return -1.0;
	return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255.0;
}

static void
check_light_palette (void)
{
	GtkCssProvider *light = gtk_css_provider_new ();
	GError *error = NULL;
	const gchar *at = fs_theme_css;
	guint names = 0, missing = 0;
	gdouble dark_bg, dark_ink, light_bg, light_ink;

	/* Every fs_ name the stylesheet defines has a light value. */
	while ((at = strstr (at, "@define-color fs_")) != NULL) {
		const gchar *start = at + strlen ("@define-color ");
		gsize len = strcspn (start, " \t");
		gchar *needle = g_strdup_printf ("@define-color %.*s ",
		                                 (int) len, start);

		names++;
		if (strstr (fs_theme_light_css, needle) == NULL) {
			printf ("      light palette lacks %.*s\n",
			        (int) len, start);
			missing++;
		}
		g_free (needle);
		at = start;
	}
	CHECK (names >= 20 && missing == 0,
	       "the light palette defines all %u named colours (%u missing)",
	       names, missing);

	dark_bg = luminance_of ("fs_bg");
	dark_ink = luminance_of ("fs_text_strong");
	CHECK (dark_bg >= 0 && dark_bg < 0.2 && dark_ink > 0.8,
	       "the stylesheet alone is dark: canvas %.2f, ink %.2f",
	       dark_bg, dark_ink);

	if (!gtk_css_provider_load_from_data (light, fs_theme_light_css, -1,
	                                      &error)) {
		CHECK (FALSE, "light palette parses (%s)",
		       error ? error->message : "unknown error");
		g_clear_error (&error);
		g_object_unref (light);
		return;
	}
	CHECK (TRUE, "light palette parses");

	gtk_style_context_add_provider_for_screen (
		gdk_screen_get_default (), GTK_STYLE_PROVIDER (light),
		GTK_STYLE_PROVIDER_PRIORITY_APPLICATION + 1);

	light_bg = luminance_of ("fs_bg");
	light_ink = luminance_of ("fs_text_strong");
	CHECK (light_bg > 0.8 && light_ink < 0.2,
	       "with the light palette the canvas is light: canvas %.2f, "
	       "ink %.2f", light_bg, light_ink);

	/* The rules follow the names: the same checks hold in light. */
	check_fill ("light: btn-primary rest face", "btn-primary", NULL, 0,
	            "fs_primary");
	check_fill ("light: selected sidebar item", "nav-item", "nav-active",
	            GTK_STATE_FLAG_CHECKED, "fs_surface_2");
	CHECK (luminance_of ("fs_primary") < 0.2,
	       "light: the primary button is the dark inverse of the canvas");

	gtk_style_context_remove_provider_for_screen (
		gdk_screen_get_default (), GTK_STYLE_PROVIDER (light));
	g_object_unref (light);

	CHECK (luminance_of ("fs_bg") < 0.2,
	       "taking the light palette away restores the dark canvas");
}

int
main (int argc, char **argv)
{
	gtk_init (&argc, &argv);

	if (install_theme ()) {
		check_nav_heights ();
		check_colours ();
		check_dialog_buttons ();
		check_light_palette ();
	}

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);

	return failures ? 1 : 0;
}
