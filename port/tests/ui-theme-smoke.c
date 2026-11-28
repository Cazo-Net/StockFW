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
 *   4. ACCENTS AND DENSITY -- the sheets of src/ui/fs-theme-accent.h,
 *      which Preferences > General > Appearance lays over both.  An
 *      accent renames fs_accent and fs_accent_fill and nothing else;
 *      in the dark and in the light mode its text reads at 4.5:1 on
 *      every ground, its fill stands 3:1 off the card, a switch's
 *      slider and the white drawn on it, and it is not one of the
 *      verdict colours.  The comfortable density only ever pads single
 *      components, by the same amount in every state, and taking a
 *      sheet away gives back exactly what was there.
 *
 *   5. SHARED CLASSES -- the Overview's status board and the Threat
 *      Intel page's status card are built from the same classes; each
 *      keeps its own padding, facts and title size.  An adapter's kind
 *      on the Overview is inked by the stylesheet in both modes.
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
#include "../src/ui/fs-theme-accent.h"

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

/* ---------------------------------------------------------------- *
 * 4. Accents and density: the sheets of fs-theme-accent.h           *
 * ---------------------------------------------------------------- */

/* sRGB to linear light, WCAG's formula, without libm: the 2.4 power
 * is a square times the square of a fifth root (Newton, from 1.0). */
static gdouble
linear (gdouble v)
{
	gdouble a, y = 1.0;

	if (v <= 0.03928)
		return v / 12.92;
	a = (v + 0.055) / 1.055;
	for (guint i = 0; i < 60; i++)
		y -= (y * y * y * y * y - a) / (5 * y * y * y * y);
	return a * a * y * y;
}

static gdouble
wcag_luminance (gdouble r, gdouble g, gdouble b)
{
	return 0.2126 * linear (r) + 0.7152 * linear (g) + 0.0722 * linear (b);
}

static gdouble
wcag_ratio (gdouble l1, gdouble l2)
{
	return (MAX (l1, l2) + 0.05) / (MIN (l1, l2) + 0.05);
}

/* The WCAG contrast of two named colours as they resolve now. */
static gdouble
contrast_of (const gchar *one, const gchar *other)
{
	gint r, g, b, r2, g2, b2;

	if (!named (one, &r, &g, &b) || !named (other, &r2, &g2, &b2))
		return 0.0;
	return wcag_ratio (wcag_luminance (r / 255.0, g / 255.0, b / 255.0),
	                   wcag_luminance (r2 / 255.0, g2 / 255.0, b2 / 255.0));
}

/* What a sheet of @define-color lines says a name is. */
static gboolean
sheet_colour (const gchar *sheet, const gchar *name,
              gint *r, gint *g, gint *b)
{
	gchar *needle = g_strdup_printf ("@define-color %s ", name);
	const gchar *at = strstr (sheet, needle);
	gboolean found = FALSE;
	GdkRGBA c;

	*r = *g = *b = -1;
	if (at != NULL) {
		gchar *text;

		at += strlen (needle);
		text = g_strndup (at, strcspn (at, ";"));
		found = gdk_rgba_parse (&c, g_strstrip (text));
		g_free (text);
	}
	if (found) {
		*r = (gint) (c.red * 255 + 0.5);
		*g = (gint) (c.green * 255 + 0.5);
		*b = (gint) (c.blue * 255 + 0.5);
	}
	g_free (needle);
	return found;
}

static guint
count_of (const gchar *text, const gchar *needle)
{
	guint n = 0;

	while ((text = strstr (text, needle)) != NULL) {
		n++;
		text += strlen (needle);
	}
	return n;
}

/* The focus ring of a switch against its slider, as the theme computes
 * it now.  The slider is a CSS node, not a widget, so it is reached
 * through a widget path: window > switch:focus > slider.  0 when the
 * ring is not solid, thinner than 2px or see-through. */
static gdouble
switch_ring_contrast (void)
{
	GtkWidgetPath *path = gtk_widget_path_new ();
	GtkStyleContext *ctx = gtk_style_context_new ();
	GdkRGBA *ring = NULL, *slider = NULL;
	GtkBorderStyle style = GTK_BORDER_STYLE_NONE;
	gint width = 0;
	gdouble ratio = 0.0;

	gtk_widget_path_append_type (path, GTK_TYPE_WINDOW);
	gtk_widget_path_iter_set_object_name (path, -1, "window");
	gtk_widget_path_append_type (path, GTK_TYPE_SWITCH);
	gtk_widget_path_iter_set_object_name (path, -1, "switch");
	gtk_widget_path_iter_set_state (path, -1, GTK_STATE_FLAG_FOCUSED);
	gtk_widget_path_append_type (path, GTK_TYPE_WIDGET);
	gtk_widget_path_iter_set_object_name (path, -1, "slider");
	gtk_style_context_set_path (ctx, path);
	gtk_style_context_set_screen (ctx, gdk_screen_get_default ());

	gtk_style_context_get (ctx, gtk_style_context_get_state (ctx),
	                       "outline-color", &ring,
	                       "outline-style", &style,
	                       "outline-width", &width,
	                       "background-color", &slider, NULL);

	if (ring != NULL && slider != NULL &&
	    style == GTK_BORDER_STYLE_SOLID && width >= 2 && ring->alpha == 1.0)
		ratio = wcag_ratio (
			wcag_luminance (ring->red, ring->green, ring->blue),
			wcag_luminance (slider->red, slider->green, slider->blue));

	if (ring != NULL)
		gdk_rgba_free (ring);
	if (slider != NULL)
		gdk_rgba_free (slider);
	g_object_unref (ctx);
	gtk_widget_path_unref (path);
	return ratio;
}

/* One accent in one mode (the caller has the mode's palette on the
 * screen): what its sheet says, and what the screen says with the
 * sheet installed where fs-app.c installs it. */
static void
check_accent_sheet (const FsThemeAccent *accent, gboolean dark)
{
	static const gchar *const grounds[] = {
		"fs_bg", "fs_bg_side", "fs_surface", "fs_surface_2",
	};
	const gchar *sheet = dark ? accent->dark : accent->light;
	const gchar *mode = dark ? "dark" : "light";
	gboolean is_default = accent == &fs_theme_accents[0];
	GtkCssProvider *provider = gtk_css_provider_new ();
	GError *error = NULL;
	gint pr, pg, pb, qr, qg, qb;     /* the palette's accent and fill  */
	gint ir, ig, ib, wr, wg, wb;     /* fs_info and fs_on_accent       */
	gint er, eg, eb, fr, fg, fb;     /* what the sheet says            */
	gint r, g, b, r2, g2, b2;
	gboolean same;

	named ("fs_accent", &pr, &pg, &pb);
	named ("fs_accent_fill", &qr, &qg, &qb);
	named ("fs_info", &ir, &ig, &ib);
	named ("fs_on_accent", &wr, &wg, &wb);

	CHECK (count_of (sheet, "@define-color") == 2 &&
	       sheet_colour (sheet, "fs_accent", &er, &eg, &eb) &&
	       sheet_colour (sheet, "fs_accent_fill", &fr, &fg, &fb) &&
	       strchr (sheet, '{') == NULL,
	       "%s, %s: the sheet names fs_accent and fs_accent_fill and "
	       "nothing else", accent->id, mode);

	same = er == pr && eg == pg && eb == pb &&
	       fr == qr && fg == qg && fb == qb;
	if (is_default)
		CHECK (same, "%s, %s: the default accent is what the palette "
		       "already says (%d,%d,%d and %d,%d,%d)", accent->id, mode,
		       pr, pg, pb, qr, qg, qb);
	else
		CHECK (!(er == pr && eg == pg && eb == pb) &&
		       !(fr == qr && fg == qg && fb == qb),
		       "%s, %s: the accent is not the palette's blue",
		       accent->id, mode);

	if (!gtk_css_provider_load_from_data (provider, sheet, -1, &error)) {
		CHECK (FALSE, "%s, %s: the sheet parses (%s)", accent->id, mode,
		       error ? error->message : "unknown error");
		g_clear_error (&error);
		g_object_unref (provider);
		return;
	}
	gtk_style_context_add_provider_for_screen (
		gdk_screen_get_default (), GTK_STYLE_PROVIDER (provider),
		GTK_STYLE_PROVIDER_PRIORITY_APPLICATION + 2);

	named ("fs_accent", &r, &g, &b);
	named ("fs_accent_fill", &r2, &g2, &b2);
	CHECK (r == er && g == eg && b == eb &&
	       r2 == fr && g2 == fg && b2 == fb,
	       "%s, %s: installed, fs_accent is %d,%d,%d and fs_accent_fill "
	       "%d,%d,%d", accent->id, mode, r, g, b, r2, g2, b2);

	/* The rules follow the name. */
	{
		GtkWidget *sw = gtk_switch_new ();
		GtkStyleContext *ctx = gtk_widget_get_style_context (sw);
		GdkRGBA *bg = NULL;

		gtk_style_context_set_state (ctx, GTK_STATE_FLAG_CHECKED);
		gtk_style_context_get (ctx, GTK_STATE_FLAG_CHECKED,
		                       "background-color", &bg, NULL);
		CHECK (bg != NULL &&
		       near ((gint) (bg->red * 255 + 0.5), fr, 1) &&
		       near ((gint) (bg->green * 255 + 0.5), fg, 1) &&
		       near ((gint) (bg->blue * 255 + 0.5), fb, 1),
		       "%s, %s: a switch that is on paints the accent's fill",
		       accent->id, mode);
		if (bg != NULL)
			gdk_rgba_free (bg);
		gtk_widget_destroy (sw);
	}

	/* The accent is two names: nothing else moved, and it is not a
	 * verdict colour. */
	named ("fs_info", &r, &g, &b);
	named ("fs_on_accent", &r2, &g2, &b2);
	CHECK (r == ir && g == ig && b == ib &&
	       r2 == wr && g2 == wg && b2 == wb,
	       "%s, %s: fs_info and fs_on_accent stay as the palette has them",
	       accent->id, mode);
	named ("fs_ok", &r, &g, &b);
	named ("fs_warn", &r2, &g2, &b2);
	CHECK (!(r == er && g == eg && b == eb) &&
	       !(r2 == er && g2 == eg && b2 == eb) &&
	       !(r == fr && g == fg && b == fb) &&
	       !(r2 == fr && g2 == fg && b2 == fb),
	       "%s, %s: neither accent colour is fs_ok or fs_warn",
	       accent->id, mode);

	for (guint i = 0; i < G_N_ELEMENTS (grounds); i++) {
		gdouble ratio = contrast_of ("fs_accent", grounds[i]);

		CHECK (ratio >= 4.5, "%s, %s: accent text on %s is %.2f:1 "
		       "(want 4.5)", accent->id, mode, grounds[i], ratio);
	}
	CHECK (contrast_of ("fs_accent_fill", "fs_surface") >= 3.0 &&
	       contrast_of ("fs_accent_fill", "fs_text_strong") >= 3.0 &&
	       contrast_of ("fs_accent_fill", "fs_on_accent") >= 3.0,
	       "%s, %s: the fill is %.2f:1 on the card, %.2f:1 against a "
	       "switch's slider and %.2f:1 under its white (want 3)",
	       accent->id, mode,
	       contrast_of ("fs_accent_fill", "fs_surface"),
	       contrast_of ("fs_accent_fill", "fs_text_strong"),
	       contrast_of ("fs_accent_fill", "fs_on_accent"));
	CHECK (switch_ring_contrast () >= 3.0,
	       "%s, %s: a focused switch is ringed solid, %.2f:1 against its "
	       "slider", accent->id, mode, switch_ring_contrast ());

	gtk_style_context_remove_provider_for_screen (
		gdk_screen_get_default (), GTK_STYLE_PROVIDER (provider));
	g_object_unref (provider);

	named ("fs_accent", &r, &g, &b);
	named ("fs_accent_fill", &r2, &g2, &b2);
	CHECK (r == pr && g == pg && b == pb &&
	       r2 == qr && g2 == qg && b2 == qb,
	       "%s, %s: taking the sheet away gives the palette's accent back",
	       accent->id, mode);
}

static void
check_accents (void)
{
	GtkCssProvider *light = gtk_css_provider_new ();

	CHECK (G_N_ELEMENTS (fs_theme_accents) == 3 &&
	       g_strcmp0 (fs_theme_accents[0].id, "blue") == 0 &&
	       g_strcmp0 (fs_theme_accents[1].id, "green") == 0 &&
	       g_strcmp0 (fs_theme_accents[2].id, "amber") == 0,
	       "three accents: blue (the default), green and amber");

	for (guint i = 0; i < G_N_ELEMENTS (fs_theme_accents); i++)
		check_accent_sheet (&fs_theme_accents[i], TRUE);

	if (gtk_css_provider_load_from_data (light, fs_theme_light_css, -1,
	                                     NULL)) {
		gtk_style_context_add_provider_for_screen (
			gdk_screen_get_default (), GTK_STYLE_PROVIDER (light),
			GTK_STYLE_PROVIDER_PRIORITY_APPLICATION + 1);
		for (guint i = 0; i < G_N_ELEMENTS (fs_theme_accents); i++)
			check_accent_sheet (&fs_theme_accents[i], FALSE);
		gtk_style_context_remove_provider_for_screen (
			gdk_screen_get_default (), GTK_STYLE_PROVIDER (light));
	}
	g_object_unref (light);
}

/* The height a sidebar item asks for, the same in all sixteen state
 * and class combinations of check_nav_heights (), or -1. */
static gint
nav_item_height (const gchar *also)
{
	gint height = -1;
	gboolean one = TRUE;

	for (guint ci = 0; ci < 2; ci++) {
		GtkWidget *btn = gtk_button_new_with_label ("Copilot");
		GtkStyleContext *ctx = gtk_widget_get_style_context (btn);

		gtk_widget_show (btn);
		gtk_style_context_add_class (ctx, "nav-item");
		if (also != NULL)
			gtk_style_context_add_class (ctx, also);
		if (ci == 1)
			gtk_style_context_add_class (ctx, "nav-active");
		for (guint si = 0; si < G_N_ELEMENTS (state_matrix); si++) {
			gint min = -1;

			gtk_style_context_set_state (ctx, state_matrix[si]);
			gtk_widget_get_preferred_height (btn, &min, NULL);
			if (height < 0)
				height = min;
			else if (min != height)
				one = FALSE;
		}
		gtk_widget_destroy (btn);
	}
	return one ? height : -1;
}

/* A column heading of a list, measured where the theme reaches it:
 * treeview > header > button. */
static gint
heading_height (void)
{
	GtkWidget *window = gtk_offscreen_window_new ();
	GtkWidget *view = gtk_tree_view_new ();
	GtkTreeViewColumn *column = gtk_tree_view_column_new_with_attributes (
		"Name", gtk_cell_renderer_text_new (), NULL);
	gint min = -1;

	gtk_tree_view_append_column (GTK_TREE_VIEW (view), column);
	gtk_container_add (GTK_CONTAINER (window), view);
	gtk_widget_show_all (window);
	gtk_widget_get_preferred_height (
		gtk_tree_view_column_get_button (column), &min, NULL);
	gtk_widget_destroy (window);
	return min;
}

/* A row of a list box that carries a class the theme styles. */
static gint
list_row_height (const gchar *klass)
{
	GtkWidget *list = gtk_list_box_new ();
	GtkWidget *row = gtk_list_box_row_new ();
	gint min = -1;

	gtk_style_context_add_class (gtk_widget_get_style_context (list), klass);
	gtk_container_add (GTK_CONTAINER (row), gtk_label_new ("Row"));
	gtk_container_add (GTK_CONTAINER (list), row);
	gtk_widget_show_all (list);
	gtk_widget_get_preferred_height (row, &min, NULL);
	gtk_widget_destroy (list);
	return min;
}

static gint
menu_item_height (void)
{
	GtkWidget *menu = gtk_menu_new ();
	GtkWidget *item = gtk_menu_item_new_with_label ("Item");
	gint min = -1;

	gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
	gtk_widget_show (item);
	gtk_widget_get_preferred_height (item, &min, NULL);
	gtk_widget_destroy (menu);
	return min;
}

/* The top and bottom padding of a box that carries a class (and sits
 * in a box that carries another, when one is given). */
static gint
padding_of (const gchar *klass, const gchar *inside)
{
	GtkWidget *outer = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	GtkStyleContext *ctx = gtk_widget_get_style_context (box);
	GtkBorder padding = { 0 };

	if (inside != NULL)
		gtk_style_context_add_class (
			gtk_widget_get_style_context (outer), inside);
	gtk_style_context_add_class (ctx, klass);
	gtk_container_add (GTK_CONTAINER (outer), box);
	gtk_style_context_get_padding (ctx, gtk_style_context_get_state (ctx),
	                               &padding);
	gtk_widget_destroy (outer);
	return padding.top + padding.bottom;
}

/* The same for a button that carries a class: the Overview's latest
 * blocks are buttons. */
static gint
button_padding_of (const gchar *klass)
{
	GtkWidget *button = gtk_button_new ();
	GtkStyleContext *ctx = gtk_widget_get_style_context (button);
	GtkBorder padding = { 0 };

	g_object_ref_sink (button);
	gtk_style_context_add_class (ctx, klass);
	gtk_style_context_get_padding (ctx, gtk_style_context_get_state (ctx),
	                               &padding);
	gtk_widget_destroy (button);
	g_object_unref (button);
	return padding.top + padding.bottom;
}

/* Everything the comfortable sheet pads, measured now. */
enum {
	D_NAV, D_SIDE, D_HEADING, D_HELP_ROW, D_PALETTE_ROW, D_MENU_ITEM,
	D_PREF_ROW, D_RECENT_ROW, D_PROFILE_ROW, D_CARD_PROFILE_ROW, D_N
};

static const gchar *const density_names[D_N] = {
	"a sidebar item", "a sidebar item of Preferences and Help",
	"a column heading", "a Help topic", "a command palette row",
	"a menu item", "a setting in Preferences", "an Overview event row",
	"a profile row", "a profile row in a card",
};

static void
measure_density (gint out[D_N])
{
	out[D_NAV] = nav_item_height (NULL);
	out[D_SIDE] = nav_item_height ("side-item");
	out[D_HEADING] = heading_height ();
	out[D_HELP_ROW] = list_row_height ("help-topics");
	out[D_PALETTE_ROW] = list_row_height ("fs-palette-list");
	out[D_MENU_ITEM] = menu_item_height ();
	out[D_PREF_ROW] = padding_of ("pref-row", NULL);
	out[D_RECENT_ROW] = button_padding_of ("recent-row");
	out[D_PROFILE_ROW] = padding_of ("profile-row", NULL);
	out[D_CARD_PROFILE_ROW] = padding_of ("profile-row", "card-frame");
}

static void
check_density (void)
{
	GtkCssProvider *provider = gtk_css_provider_new ();
	GError *error = NULL;
	gchar **rules = g_strsplit (fs_theme_comfortable_css, "}", -1);
	guint n_rules = 0, bare = 0, other = 0;
	gint compact[D_N], comfortable[D_N], after[D_N];
	gboolean back = TRUE;

	/* The sheet outranks every rule of the stylesheet, so each of its
	 * selectors names one component (a class, or an element inside
	 * another) and each declaration is a top or bottom padding.  The
	 * one exception is the headings' `transition: none', which keeps
	 * the system theme from animating that padding. */
	for (guint i = 0; rules[i] != NULL; i++) {
		gchar *brace = strchr (rules[i], '{');
		gchar **selectors, **declarations;

		if (brace == NULL)
			continue;
		n_rules++;
		*brace = '\0';
		selectors = g_strsplit (rules[i], ",", -1);
		for (guint s = 0; selectors[s] != NULL; s++) {
			const gchar *selector = g_strstrip (selectors[s]);

			if (strchr (selector, '.') == NULL &&
			    strchr (selector, ' ') == NULL) {
				printf ("      bare selector: %s\n", selector);
				bare++;
			}
		}
		g_strfreev (selectors);

		declarations = g_strsplit (brace + 1, ";", -1);
		for (guint d = 0; declarations[d] != NULL; d++) {
			const gchar *declaration = g_strstrip (declarations[d]);

			if (*declaration == '\0')
				continue;
			if (!g_str_has_prefix (declaration, "padding-top:") &&
			    !g_str_has_prefix (declaration, "padding-bottom:") &&
			    g_strcmp0 (declaration, "transition: none") != 0) {
				printf ("      not a row padding: %s\n", declaration);
				other++;
			}
		}
		g_strfreev (declarations);
	}
	g_strfreev (rules);
	CHECK (n_rules >= 6 && bare == 0,
	       "comfortable: each of the %u rules names one component "
	       "(%u bare selectors)", n_rules, bare);
	CHECK (other == 0,
	       "comfortable: the sheet sets top and bottom padding only "
	       "(%u other declarations)", other);
	CHECK (count_of (fs_theme_comfortable_css, "padding-top:") ==
	       count_of (fs_theme_comfortable_css, "padding-bottom:") &&
	       count_of (fs_theme_comfortable_css, "padding-top:") == n_rules,
	       "comfortable: every rule pads above and below alike");
	CHECK (FS_THEME_COMFORTABLE_YPAD == 3,
	       "comfortable: a tree row gets the same 3px as the styled rows");

	measure_density (compact);
	for (guint i = 0; i < D_N; i++)
		CHECK (compact[i] > 0, "compact: %s measures (%dpx)",
		       density_names[i], compact[i]);

	if (!gtk_css_provider_load_from_data (provider,
	                                      fs_theme_comfortable_css, -1,
	                                      &error)) {
		CHECK (FALSE, "comfortable: the sheet parses (%s)",
		       error ? error->message : "unknown error");
		g_clear_error (&error);
		g_object_unref (provider);
		return;
	}
	gtk_style_context_add_provider_for_screen (
		gdk_screen_get_default (), GTK_STYLE_PROVIDER (provider),
		GTK_STYLE_PROVIDER_PRIORITY_APPLICATION + 2);

	/* 3px above and below, except the Overview's event rows, which
	 * already had the most room and get 2px. */
	measure_density (comfortable);
	for (guint i = 0; i < D_N; i++) {
		gint want = compact[i] + 6;

		CHECK (comfortable[i] == want,
		       "comfortable: %s goes from %dpx to %dpx (want %d)",
		       density_names[i], compact[i], comfortable[i], want);
	}
	CHECK (comfortable[D_NAV] > 0 && comfortable[D_SIDE] > 0,
	       "comfortable: a sidebar item is one height in every state, "
	       "selected or not");

	gtk_style_context_remove_provider_for_screen (
		gdk_screen_get_default (), GTK_STYLE_PROVIDER (provider));
	g_object_unref (provider);

	measure_density (after);
	for (guint i = 0; i < D_N; i++)
		back = back && after[i] == compact[i];
	CHECK (back, "taking the comfortable sheet away gives the compact "
	       "rows back");
}

/* ---------------------------------------------------------------- *
 * 5. The Overview's classes, where another page shares them          *
 * ---------------------------------------------------------------- */

/* A card as both pages build it: a box `.hero' holding a fact
 * (`.hero-tile') and a title (`.hero-title'), named when it is the
 * Threat Intel page's.  Gives the card's and the fact's padding (top /
 * left), the fact's border and the title's size. */
static void
measure_status_card (const gchar *name, gint out[6])
{
	GtkWidget *card = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	GtkWidget *fact = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	GtkWidget *title = gtk_label_new ("Off");
	GtkStyleContext *ctx;
	GtkBorder box = { 0 };
	gdouble size = 0;

	g_object_ref_sink (card);
	if (name != NULL)
		gtk_widget_set_name (card, name);
	gtk_style_context_add_class (gtk_widget_get_style_context (card),
	                             "hero");
	gtk_style_context_add_class (gtk_widget_get_style_context (fact),
	                             "hero-tile");
	gtk_style_context_add_class (gtk_widget_get_style_context (title),
	                             "hero-title");
	gtk_container_add (GTK_CONTAINER (card), fact);
	gtk_container_add (GTK_CONTAINER (card), title);

	ctx = gtk_widget_get_style_context (card);
	gtk_style_context_get_padding (ctx, gtk_style_context_get_state (ctx),
	                               &box);
	out[0] = box.top;
	out[1] = box.left;
	ctx = gtk_widget_get_style_context (fact);
	gtk_style_context_get_padding (ctx, gtk_style_context_get_state (ctx),
	                               &box);
	out[2] = box.top;
	out[3] = box.left;
	gtk_style_context_get_border (ctx, gtk_style_context_get_state (ctx),
	                              &box);
	out[4] = box.top;
	ctx = gtk_widget_get_style_context (title);
	gtk_style_context_get (ctx, gtk_style_context_get_state (ctx),
	                       "font-size", &size, NULL);
	out[5] = (gint) (size + 0.5);

	gtk_widget_destroy (card);
	g_object_unref (card);
}

/* Whether a label of these two classes is written in the named colour
 * as it resolves now. */
static gboolean
label_ink_is (const gchar *klass, const gchar *klass2, const gchar *name)
{
	GtkWidget *label = gtk_label_new ("Ethernet");
	GtkStyleContext *ctx = gtk_widget_get_style_context (label);
	GdkRGBA ink, want;
	gboolean same;

	g_object_ref_sink (label);
	gtk_style_context_add_class (ctx, klass);
	gtk_style_context_add_class (ctx, klass2);
	gtk_style_context_get_color (ctx, gtk_style_context_get_state (ctx),
	                             &ink);
	same = gtk_style_context_lookup_color (ctx, name, &want) &&
	       gdk_rgba_equal (&ink, &want);
	gtk_widget_destroy (label);
	g_object_unref (label);
	return same;
}

static void
check_shared_classes (void)
{
	GtkCssProvider *light = gtk_css_provider_new ();
	gint board[6], intel[6];
	gboolean dark_ink, light_ink = FALSE;

	/* The Overview's status board keeps its padding in two inner
	 * boxes and does not box its facts.  The Threat Intel page's
	 * status card (ui/fs-intelview.c, #intel-hero) is built from the
	 * same classes without those boxes: its padding, its boxed facts
	 * and its title's size are its own. */
	measure_status_card (NULL, board);
	CHECK (board[0] == 0 && board[1] == 0 && board[2] == 0 &&
	       board[3] == 0 && board[4] == 0 && board[5] == 14,
	       "the Overview's board: no padding on the card itself, facts "
	       "not boxed, a 14px title (card %d/%d, fact %d/%d border %d, "
	       "title %d)", board[0], board[1], board[2], board[3], board[4],
	       board[5]);
	measure_status_card ("intel-hero", intel);
	CHECK (intel[0] == 16 && intel[1] == 16,
	       "the Threat Intel status card keeps 16px of padding (%d/%d)",
	       intel[0], intel[1]);
	CHECK (intel[2] == 8 && intel[3] == 12 && intel[4] == 1,
	       "its facts stay boxed: 8px 12px inside a 1px border (%d/%d, "
	       "border %d)", intel[2], intel[3], intel[4]);
	CHECK (intel[5] == 16, "and its title stays 16px (%d)", intel[5]);

	/* An adapter's kind (Overview, Network adapters) takes its ink
	 * from the stylesheet, so a row that is kept across a Dark mode
	 * switch is repainted in the new palette. */
	dark_ink = label_ink_is ("adapter-name", "adapter-kind",
	                         "fs_text_weak");
	if (gtk_css_provider_load_from_data (light, fs_theme_light_css, -1,
	                                     NULL)) {
		gtk_style_context_add_provider_for_screen (
			gdk_screen_get_default (), GTK_STYLE_PROVIDER (light),
			GTK_STYLE_PROVIDER_PRIORITY_APPLICATION + 1);
		light_ink = label_ink_is ("adapter-name", "adapter-kind",
		                          "fs_text_weak");
		gtk_style_context_remove_provider_for_screen (
			gdk_screen_get_default (), GTK_STYLE_PROVIDER (light));
	}
	g_object_unref (light);
	CHECK (dark_ink && light_ink,
	       "an adapter's kind is written in fs_text_weak, dark (%d) and "
	       "light (%d)", dark_ink, light_ink);
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
		check_accents ();
		check_density ();
		check_shared_classes ();
	}

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);

	return failures ? 1 : 0;
}
