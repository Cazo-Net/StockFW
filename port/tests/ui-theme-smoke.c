/* Teeth for the light theme: src/ui/fs-theme.css, compiled into the
 * binary as fs-theme-css.h (same string the application installs).
 * Two promises the eyes made during review, both of which have
 * visibly regressed once already:
 *
 *   1. GEOMETRY -- a tab button allocates the SAME height in every
 *      state (checked, prelight, active, and both class variants:
 *      with and without .tab-active).  The original page-switch
 *      "shake" was the active/transient tab carrying Adwaita's
 *      default button metrics (+2px border + different padding),
 *      which resized the tab band -- and with it the whole page --
 *      on every switch, plus one-way window growth the toplevel
 *      never shrank back from.  Any per-state or per-class metric
 *      difference fails here before a user ever sees the jitter.
 *
 *   2. COLOUR -- primary actions and the active tab pill paint the
 *      accent red #AE0000 (hover #8B0000), the pill paints red even
 *      in the checked-before-class beat, and no state shows
 *      Adwaita's 1px white inset highlight above the face (the
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
check_tab_heights (void)
{
	static const gchar *with_class[]    = { "tab-button", "tab-active" };
	static const gchar *without_class[] = { "tab-button" };
	const gchar **combos[] = { without_class, with_class };
	const gchar *combo_names[] = {
		"tab-button only (the checked-before-class beat)",
		"tab-button + tab-active"
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
	       "tab button reports a real size request (%d min / %d nat)",
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
	/* Primary actions: #AE0000 face, #8B0000 hover, never white. */
	check_fill ("btn-primary rest face", "btn-primary", NULL, 0,
	            0xae, 0x00, 0x00);
	check_fill ("btn-primary hover face", "btn-primary", NULL,
	            GTK_STATE_FLAG_PRELIGHT, 0x8b, 0x00, 0x00);
	check_no_white_sliver ("btn-primary hover", "btn-primary",
	                       GTK_STATE_FLAG_PRELIGHT);
	check_no_white_sliver ("btn-primary focused", "btn-primary",
	                       GTK_STATE_FLAG_FOCUSED);

	/* Active tab pill: red with the class, AND in the transient
	 * checked-before-class beat that used to fall back to the theme. */
	check_fill ("active tab (checked + tab-active)",
	            "tab-button", "tab-active",
	            GTK_STATE_FLAG_CHECKED, 0xae, 0x00, 0x00);
	check_fill ("checked beat without tab-active class",
	            "tab-button", NULL,
	            GTK_STATE_FLAG_CHECKED, 0xae, 0x00, 0x00);
	check_fill ("active tab at rest", "tab-button", "tab-active",
	            0, 0xae, 0x00, 0x00);

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
		check_tab_heights ();
		check_colours ();
	}

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);

	return failures ? 1 : 0;
}
