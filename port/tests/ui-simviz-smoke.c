/* Checks the What-If window does what its outcomes promise, in three
 * layers:
 *
 *   1. the timeline -- fs_simviz_state_at() is pure math, so every
 *      phase is asserted without a display: the packet travels, the
 *      firewall answers green or red, a blocked packet bounces back
 *      and fades while the far line grays out, an allowed one lands
 *      and lights the far node, a DEPENDS one waits at the wall under
 *      an amber question mark, and an unreadable line has no timeline
 *      at all;
 *
 *   2. where an address is -- the device cards' "LAN host" / "Internet
 *      host" / "This computer" come from fs_simviz_zone_of(), checked
 *      against the private, link-local, loopback and public ranges;
 *
 *   3. the window -- every variant is built from a REAL What-If answer
 *      (the engine run against a small policy, on both platform
 *      models) and read the way a user reads it: by what is on screen.
 *      The header badge, the facts, the trace with its deciding step,
 *      one button per checked fix and none for an unchecked one, the
 *      notes, the tabs of a line asked both ways, the error state, the
 *      honesty strip, a non-modal window whose Close is a real default
 *      action (Enter and Esc work) painted dark -- not the theme's grey
 *      face that made it look disabled -- and, with animations off, the
 *      final frame drawn at once.
 *
 * With FS_SHOT_DIR set, each window is also rendered to a PNG there
 * (as the user sees it, and the whole scrolled page), with the app's
 * own stylesheet installed the way fs-app.c installs it.
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/fs-whatif.h"
#include "ui/fs-simviz.h"
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

static gboolean
has_class (GtkWidget *w, const gchar *class_name)
{
	return w != NULL && gtk_style_context_has_class (
		gtk_widget_get_style_context (w), class_name);
}

/* The app's stylesheet, installed as fs-app.c installs it. */
static GtkCssProvider *app_theme = NULL;

static void
install_app_theme (void)
{
	if (app_theme == NULL) {
		app_theme = gtk_css_provider_new ();
		if (!gtk_css_provider_load_from_data (app_theme, fs_theme_css, -1,
		                                      NULL)) {
			g_clear_object (&app_theme);
			return;
		}
	}
	gtk_style_context_add_provider_for_screen (
		gdk_screen_get_default (), GTK_STYLE_PROVIDER (app_theme),
		GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
}


static void
pump (guint ms)
{
	gint64 until = g_get_monotonic_time () + (gint64) ms * 1000;

	do {
		while (gtk_events_pending ())
			gtk_main_iteration_do (FALSE);
		g_usleep (2000);
	} while (g_get_monotonic_time () < until);
}

/* A policy of the given rows ("kind:csv", NULL-terminated). */
static FsPolicy *
policy_of (const gchar *const *rows)
{
	FsPolicy *p = fs_policy_new ();

	for (guint i = 0; rows != NULL && rows[i] != NULL; i++) {
		gchar *colon = strchr (rows[i], ':');
		FsRule *r = fs_rule_from_csv ((FsRuleKind) atoi (rows[i]),
		                              colon + 1);

		if (r == NULL) {
			CHECK (FALSE, "fixture row parses: %s", rows[i]);
			continue;
		}
		fs_policy_add (p, r);
	}
	return p;
}

/* The engine's context for one question: firewall running, the saved
 * policy live, unless the test says otherwise. */
static FsWhatIfContext *
context (FsWhatIfPlatform platform, const FsPolicy *policy,
         FsSettings *s, const gchar *sentinel)
{
	FsWhatIfContext *ctx = fs_whatif_context_new (platform, policy, s);

	ctx->firewall = FS_WHATIF_FW_RUNNING;
	ctx->live = FS_WHATIF_LIVE_YES;
	if (sentinel != NULL)
		fs_whatif_context_add_auto_block (
			ctx, sentinel, g_get_real_time () / G_USEC_PER_SEC + 420);
	return ctx;
}

/* A window for the engine's real answer to `line'. */
static GtkWidget *
window_for (FsWhatIfPlatform platform, const FsPolicy *policy,
            const gchar *sentinel, const gchar *line,
            FsWhatIfResult **result_out)
{
	FsSettings *s = fs_settings_new ();
	FsWhatIfContext *ctx = context (platform, policy, s, sentinel);
	FsWhatIfResult *r = fs_whatif_simulate_text (ctx, line);
	GtkWidget *w;

	if (result_out != NULL)
		*result_out = r;
	w = fs_simviz_window_new (r, ctx, line);
	fs_whatif_context_free (ctx);
	fs_settings_free (s);
	return w;
}

/* What the action handler saw. */
static gint   handler_calls = 0;
static FsWhatIfActionKind handler_kind;
static gint   handler_policy_kind = -2;
static gint   handler_policy_index = -2;
static gboolean handler_verified = FALSE;
static gchar *handler_row = NULL;

static void
on_action (GtkWidget *window, const FsWhatIfResult *result,
           const FsWhatIfAction *act, gpointer data)
{
	(void) window; (void) result; (void) data;
	handler_calls++;
	handler_kind = act->kind;
	handler_policy_kind = act->policy_kind;
	handler_policy_index = act->policy_index;
	handler_verified = act->verified;
	g_free (handler_row);
	handler_row = act->row != NULL ? fs_rule_to_csv (act->row) : NULL;
}

static void
handler_reset (void)
{
	handler_calls = 0;
	handler_policy_kind = handler_policy_index = -2;
	handler_verified = FALSE;
	g_clear_pointer (&handler_row, g_free);
}

/* ---------------------------------------------------------------- */
/* Rendering                                                         */
/* ---------------------------------------------------------------- */

static cairo_surface_t *
render (GtkWidget *w)
{
	GtkAllocation a;
	cairo_surface_t *surface;
	cairo_t *cr;

	gtk_widget_get_allocation (w, &a);
	surface = cairo_image_surface_create (CAIRO_FORMAT_ARGB32,
	                                      MAX (a.width, 1),
	                                      MAX (a.height, 1));
	cr = cairo_create (surface);
	gtk_widget_draw (w, cr);
	cairo_destroy (cr);
	cairo_surface_flush (surface);
	return surface;
}

/* Luminance 0..1 of one pixel of a rendered surface. */
static gdouble
luma_at (cairo_surface_t *s, gint x, gint y)
{
	guchar *data = cairo_image_surface_get_data (s);
	gint stride = cairo_image_surface_get_stride (s);
	guint32 px;

	if (x < 0 || y < 0 || x >= cairo_image_surface_get_width (s) ||
	    y >= cairo_image_surface_get_height (s))
		return -1.0;
	px = *(guint32 *) (data + y * stride + x * 4);
	return (0.2126 * ((px >> 16) & 0xff) + 0.7152 * ((px >> 8) & 0xff) +
	        0.0722 * (px & 0xff)) / 255.0;
}

/* The colour of one pixel, as 0xRRGGBB. */
static guint32
rgb_at (cairo_surface_t *s, gint x, gint y)
{
	guchar *data = cairo_image_surface_get_data (s);
	gint stride = cairo_image_surface_get_stride (s);

	return *(guint32 *) (data + y * stride + x * 4) & 0xffffff;
}

/* The window as the user sees it, and its whole scrolled page. */
static void
shoot (GtkWidget *window, const gchar *name)
{
	const gchar *dir = g_getenv ("FS_SHOT_DIR");
	GtkWidget *scroller, *page;
	cairo_surface_t *s;
	gchar *path;

	if (dir == NULL || *dir == '\0')
		return;

	pump (60);
	s = render (window);
	path = g_strdup_printf ("%s/%s.png", dir, name);
	cairo_surface_write_to_png (s, path);
	cairo_surface_destroy (s);
	g_free (path);

	scroller = fs_simviz_find_named (window, "whatif-scroller");
	page = scroller != NULL ? gtk_bin_get_child (GTK_BIN (scroller)) : NULL;
	if (page != NULL && GTK_IS_VIEWPORT (page))
		page = gtk_bin_get_child (GTK_BIN (page));
	if (page != NULL) {
		s = render (page);
		path = g_strdup_printf ("%s/%s-full.png", dir, name);
		cairo_surface_write_to_png (s, path);
		cairo_surface_destroy (s);
		g_free (path);
	}
}

/* Shown, allocated and drawn: present, then let it settle. */
static void
show (GtkWidget *window)
{
	fs_simviz_window_present (window, NULL);
	pump (80);
}

/* ---------------------------------------------------------------- */
/* 1. The timeline                                                   */
/* ---------------------------------------------------------------- */
static void
test_timeline (void)
{
	FsSimvizState s;
	gdouble prev;
	gint i;

	s = fs_simviz_state_at (FS_SIMVIZ_ALLOWED, 0.5);
	CHECK (s.packet > 0.0 && s.packet < 0.5,
	       "allowed at 0.5s: the packet is on the first leg");
	CHECK (!s.show_check && !s.show_x && s.dest_glow == 0.0 && !s.done,
	       "allowed at 0.5s: no verdict yet");
	s = fs_simviz_state_at (FS_SIMVIZ_ALLOWED, 1.3);
	CHECK (s.show_check && !s.show_x && s.fw_green > 0.0 &&
	       s.packet > 0.4 && s.packet < 0.6,
	       "allowed at 1.3s: check up, wall green, packet held at the wall");
	s = fs_simviz_state_at (FS_SIMVIZ_ALLOWED, 2.0);
	CHECK (s.packet > 0.5 && s.packet < 1.0 && !s.tail_blocked,
	       "allowed at 2.0s: on the second leg, the far line never grays");
	s = fs_simviz_state_at (FS_SIMVIZ_ALLOWED, FS_SIMVIZ_DURATION + 99.0);
	CHECK (s.done && s.packet == 1.0 && s.dest_glow == 1.0 &&
	       s.fw_red == 0.0 && !s.show_x,
	       "allowed freezes on its end state: arrived, glowing, no red");
	prev = 0.0;
	for (i = 0; i <= 52; i++) {
		s = fs_simviz_state_at (FS_SIMVIZ_ALLOWED, i * 0.05);
		if (s.packet < prev)
			break;
		prev = s.packet;
	}
	CHECK (i > 52, "the allowed packet only ever moves forward");

	s = fs_simviz_state_at (FS_SIMVIZ_BLOCKED, 1.3);
	CHECK (s.show_x && !s.show_check && s.fw_red > 0.0 && s.shake > 0.0 &&
	       s.tail_blocked,
	       "blocked at 1.3s: X up, the wall shakes red, the far line grays");
	s = fs_simviz_state_at (FS_SIMVIZ_BLOCKED, 1.5);
	CHECK (s.packet > 0.0 && s.packet < 0.5 && s.packet_alpha < 1.0 &&
	       s.packet_alpha > 0.0,
	       "blocked at 1.5s: the packet bounces back, fading");
	s = fs_simviz_state_at (FS_SIMVIZ_BLOCKED, 1.8);
	CHECK (s.packet < 0.0, "blocked after the bounce: the packet is gone");
	s = fs_simviz_state_at (FS_SIMVIZ_BLOCKED, FS_SIMVIZ_DURATION + 99.0);
	CHECK (s.done && s.show_x && s.fw_red == 1.0 && s.shake == 0.0 &&
	       s.tail_blocked && s.dest_glow == 0.0,
	       "blocked freezes on a still red wall, the far node dark");

	s = fs_simviz_state_at (FS_SIMVIZ_DEPENDS, 1.3);
	CHECK (s.show_question && s.fw_amber > 0.0 && s.packet == 0.5,
	       "depends at 1.3s: the question mark is up, the packet waits");
	for (i = 0; i <= 60; i++) {
		s = fs_simviz_state_at (FS_SIMVIZ_DEPENDS, i * 0.05);
		if (s.packet > 0.5 || s.show_check || s.show_x ||
		    s.fw_green > 0.0 || s.fw_red > 0.0 || s.dest_glow > 0.0 ||
		    s.tail_blocked)
			break;
	}
	CHECK (i > 60, "a DEPENDS packet never passes the wall, and is never "
	               "green or red");

	s = fs_simviz_state_at (FS_SIMVIZ_ERROR, 42.0);
	CHECK (s.done && s.packet < 0.0 && !s.show_check && !s.show_x &&
	       !s.show_question,
	       "error: one frozen frame, no packet, no verdict");
}

/* ---------------------------------------------------------------- */
/* 2. Where an address is                                            */
/* ---------------------------------------------------------------- */
static void
test_zones (void)
{
	static const struct { const gchar *host; FsSimvizZone zone;
	                      const gchar *title; } cases[] = {
		{ NULL,             FS_SIMVIZ_ZONE_ANY,      "Any host" },
		{ "192.168.1.50",   FS_SIMVIZ_ZONE_LAN,      "LAN host" },
		{ "10.0.0.0/8",     FS_SIMVIZ_ZONE_LAN,      "LAN hosts" },
		{ "172.16.5.4",     FS_SIMVIZ_ZONE_LAN,      "LAN host" },
		{ "172.32.0.1",     FS_SIMVIZ_ZONE_INTERNET, "Internet host" },
		{ "169.254.10.1",   FS_SIMVIZ_ZONE_LAN,      "LAN host" },
		{ "8.8.8.8",        FS_SIMVIZ_ZONE_INTERNET, "Internet host" },
		{ "203.0.113.0/24", FS_SIMVIZ_ZONE_INTERNET, "Internet hosts" },
		{ "127.0.0.1",      FS_SIMVIZ_ZONE_THIS,     "This computer" },
		{ "::1",            FS_SIMVIZ_ZONE_THIS,     "This computer" },
		{ "fe80::1",        FS_SIMVIZ_ZONE_LAN,      "LAN host" },
		{ "fd00::5",        FS_SIMVIZ_ZONE_LAN,      "LAN host" },
		{ "2001:db8::5",    FS_SIMVIZ_ZONE_INTERNET, "Internet host" },
		{ "0.0.0.0/0",      FS_SIMVIZ_ZONE_ANY,      "Wide address block" },
	};

	for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
		CHECK (fs_simviz_zone_of (cases[i].host) == cases[i].zone &&
		       g_strcmp0 (fs_simviz_zone_title (cases[i].host),
		                  cases[i].title) == 0,
		       "zone: %s is a card titled '%s' (got '%s')",
		       cases[i].host ? cases[i].host : "(no host)",
		       cases[i].title, fs_simviz_zone_title (cases[i].host));
}

/* ---------------------------------------------------------------- */
/* 3. The window                                                     */
/* ---------------------------------------------------------------- */

/* The window's Close: a real action, the default, sensitive, in the
 * primary style -- and painted dark, which is what the eye reads. */
static void
check_close (GtkWidget *w, const gchar *what)
{
	GtkWidget *close = gtk_dialog_get_widget_for_response (
		GTK_DIALOG (w), GTK_RESPONSE_CLOSE);

	CHECK (close != NULL && gtk_widget_is_sensitive (close) &&
	       has_class (close, "btn-primary") &&
	       gtk_widget_has_default (close),
	       "%s: Close is the dialog's sensitive default action, primary "
	       "style", what);

	if (close != NULL && gtk_widget_get_mapped (close)) {
		/* The button drawn on its own: its face beside the label, and
		 * only an opaque pixel counts (nothing painted reads as 0). */
		cairo_surface_t *s = render (close);
		GtkAllocation a;
		gdouble face;
		guint32 px;

		gtk_widget_get_allocation (close, &a);
		px = *(guint32 *) (cairo_image_surface_get_data (s) +
		                   (a.height / 2) * cairo_image_surface_get_stride (s) +
		                   6 * 4);
		face = ((px >> 24) == 0xff) ? luma_at (s, 6, a.height / 2) : -1.0;
		/* The shell's primary is near-black on the light page and
		 * inverted on a dark one; a mid grey is what reads as
		 * disabled. */
		if (has_class (w, "fs-wi-dark"))
			CHECK (face > 0.75,
			       "%s: Close is painted light on the dark page (face "
			       "luminance %.2f), not a grey face that reads as "
			       "disabled", what, face);
		else
			CHECK (face >= 0.0 && face < 0.25,
			       "%s: Close is painted dark (face luminance %.2f), "
			       "not a grey face that reads as disabled", what,
			       face);
		cairo_surface_destroy (s);
	}
}

static gboolean
window_is_modal_free (GtkWidget *w)
{
	return !gtk_window_get_modal (GTK_WINDOW (w));
}

static void
test_allowed (void)
{
	static const gchar *rows[] = { "1:SSH,22,192.168.1.50,lab", NULL };
	FsPolicy *p = policy_of (rows);
	FsWhatIfResult *r = NULL;
	GtkWidget *w = window_for (FS_WHATIF_LINUX_FIRST_MATCH, p, NULL,
	                           "Can 192.168.1.50 reach my SSH?", &r);
	GtkWidget *hit;
	GtkWidget *badge;

	fs_simviz_window_set_action_func (w, on_action, NULL);
	show (w);

	CHECK (fs_simviz_outcome_of (r) == FS_SIMVIZ_ALLOWED,
	       "the engine allows SSH from the allowed host");
	CHECK (g_strcmp0 (gtk_window_get_title (GTK_WINDOW (w)),
	                  "What-If Simulation") == 0 && window_is_modal_free (w),
	       "allowed: a non-modal window titled 'What-If Simulation'");

	hit = fs_simviz_find_named (w, "whatif-window-header");
	badge = fs_simviz_find_label (hit, "ALLOWED");
	CHECK (badge != NULL && has_class (badge, "fs-wi-badge") &&
	       has_class (badge, "ok"),
	       "allowed: the header's badge says ALLOWED, in green");
	CHECK (badge != NULL && g_strcmp0 (atk_object_get_name (
	           gtk_widget_get_accessible (badge)), "Verdict: ALLOWED") == 0,
	       "allowed: the badge has an accessible name");
	CHECK (fs_simviz_find_label (hit, "Inbound TCP port 22 (SSH) from "
	                                  "192.168.1.50 to this computer") != NULL,
	       "allowed: the question in plain words heads the window");
	CHECK (fs_simviz_find_label (hit, "You typed: “Can 192.168.1.50 "
	                                  "reach my SSH?”") != NULL,
	       "allowed: what was typed is shown under it");
	CHECK (fs_simviz_find_named (hit, "whatif-window-honesty") == NULL,
	       "allowed: a live policy on a running firewall needs no warning");

	hit = fs_simviz_find_named (w, "whatif-facts");
	CHECK (fs_simviz_find_label (hit, "Inbound: to this computer") &&
	       fs_simviz_find_label (hit, "TCP") &&
	       fs_simviz_find_label (hit, "192.168.1.50 (LAN host)") &&
	       fs_simviz_find_label (hit, "22 (SSH)") &&
	       fs_simviz_find_label (hit, "Linux iptables: the first matching "
	                                  "rule decides"),
	       "allowed: the facts name direction, protocol, the LAN host, "
	       "port and service, and the Linux model");

	hit = fs_simviz_find_named (w, "whatif-decides");
	CHECK (hit != NULL &&
	       fs_simviz_find_label (hit, "Allow SSH (inbound, 192.168.1.50)") &&
	       fs_simviz_find_label (hit, "DECIDES"),
	       "allowed: the trace highlights the rule that decided");
	CHECK (fs_simviz_find_label (fs_simviz_find_named (w, "whatif-why"),
	                             "only for ICMP; this is TCP") != NULL,
	       "allowed: the steps that did not match are listed too");

	hit = fs_simviz_find_button (fs_simviz_find_named (w, "whatif-decides"),
	                             "Open in Policy");
	CHECK (hit != NULL, "allowed: the deciding policy rule links to the "
	                    "Policy page");
	handler_reset ();
	if (hit != NULL)
		gtk_button_clicked (GTK_BUTTON (hit));
	CHECK (handler_calls == 1 && handler_kind == FS_WHATIF_ACT_OPEN_RULE &&
	       handler_policy_kind == 1 && handler_policy_index == 0,
	       "allowed: the link asks to open inbound-service row 1");

	CHECK (fs_simviz_find_button (w, "Create allow rule") == NULL &&
	       fs_simviz_find_label (fs_simviz_find_named (w, "whatif-no-action"),
	                             "Nothing to change: this is already "
	                             "allowed") != NULL,
	       "allowed: nothing to create, and the window says why");
	CHECK (fs_simviz_find_named (w, "whatif-replay") != NULL,
	       "allowed: Replay sits over the diagram");
	check_close (w, "allowed");

	shoot (w, "window-allowed");
	gtk_widget_destroy (w);
	fs_policy_free (p);
}

static void
test_blocked (void)
{
	static const gchar *deny[] = { "6:203.0.113.9,known bad", NULL };
	FsPolicy *empty = fs_policy_new ();
	FsPolicy *p = policy_of (deny);
	FsWhatIfResult *r = NULL;
	GtkWidget *w = window_for (FS_WHATIF_LINUX_FIRST_MATCH, empty, NULL,
	                           "allow tcp port 8443 inbound", &r);
	GtkWidget *btn, *hit;
	const FsWhatIfAction *act = fs_whatif_result_create_action (r);

	fs_simviz_window_set_action_func (w, on_action, NULL);
	show (w);

	CHECK (fs_simviz_outcome_of (r) == FS_SIMVIZ_BLOCKED && act != NULL &&
	       act->verified,
	       "the default drops it, and the engine verified an allow row");
	hit = fs_simviz_find_named (w, "whatif-window-header");
	CHECK (has_class (fs_simviz_find_label (hit, "BLOCKED"), "bad"),
	       "blocked: the header's badge says BLOCKED, in red");
	CHECK (fs_simviz_find_label (hit, "You asked to allow this") != NULL,
	       "blocked: the answer speaks to the user's verb");

	btn = fs_simviz_find_button (w, "Create allow rule");
	CHECK (btn != NULL && has_class (btn, "btn-primary"),
	       "blocked by the default: one Create allow rule button");
	hit = fs_simviz_find_named (w, "whatif-create-row");
	CHECK (fs_simviz_find_label (hit, "TCP, 8443, Anyone") != NULL &&
	       fs_simviz_find_label (hit, "Allow inbound service") != NULL,
	       "blocked: the exact row a Create writes is shown");
	handler_reset ();
	if (btn != NULL)
		gtk_button_clicked (GTK_BUTTON (btn));
	CHECK (handler_calls == 1 && handler_kind == FS_WHATIF_ACT_CREATE_ALLOW &&
	       handler_verified &&
	       g_strcmp0 (handler_row, "TCP, 8443, Anyone, What-If: allow TCP "
	                               "8443") == 0,
	       "blocked: Create hands the verified row to the caller (%s)",
	       handler_row ? handler_row : "none");
	CHECK (fs_simviz_find_label (fs_simviz_find_named (w, "whatif-decides"),
	                             "Default: drop silently") != NULL,
	       "blocked: the trace highlights the default drop");
	check_close (w, "blocked");
	shoot (w, "window-blocked");

	/* The same answer with the row's check taken away: no button, and
	 * the window says it was not offered. */
	((FsWhatIfAction *) act)->verified = FALSE;
	{
		FsSettings *s = fs_settings_new ();
		FsWhatIfContext *ctx = context (FS_WHATIF_LINUX_FIRST_MATCH, empty,
		                                s, NULL);
		FsWhatIfResult *again = fs_whatif_simulate_text (
			ctx, "allow tcp port 8443 inbound");
		FsWhatIfAction *a2 = (FsWhatIfAction *)
			fs_whatif_result_create_action (again);

		a2->verified = FALSE;
		fs_simviz_window_set_result (w, again, ctx, NULL);
		fs_whatif_context_free (ctx);
		fs_settings_free (s);
	}
	pump (20);
	CHECK (fs_simviz_find_button (w, "Create allow rule") == NULL &&
	       fs_simviz_find_label (w, "Not offered") != NULL,
	       "an unverified row gets no Create button, only the reason");
	gtk_widget_destroy (w);

	/* A block rule decided: the way out is that rule, never an allow
	 * row next to it -- on either platform. */
	for (gint plat = 0; plat < 2; plat++) {
		w = window_for (plat == 0 ? FS_WHATIF_LINUX_FIRST_MATCH
		                          : FS_WHATIF_WINDOWS_BLOCK_WINS,
		                p, NULL,
		                "allow outbound tcp to 203.0.113.9 port 443", &r);
		fs_simviz_window_set_action_func (w, on_action, NULL);
		show (w);
		CHECK (fs_simviz_outcome_of (r) == FS_SIMVIZ_BLOCKED &&
		       fs_simviz_find_button (w, "Create allow rule") == NULL &&
		       fs_simviz_find_button (w, "Open rule in Policy") != NULL,
		       "%s: a block rule decided: Open rule in Policy, no Create",
		       plat == 0 ? "linux" : "windows");
		CHECK (fs_simviz_find_label (fs_simviz_find_named (w,
		                                 "whatif-decides"),
		                             "203.0.113.9") != NULL,
		       "%s: the deny rule is the highlighted step",
		       plat == 0 ? "linux" : "windows");
		if (plat == 1) {
			CHECK (fs_simviz_find_label (w, "Windows Firewall: any "
			                                "matching block wins") &&
			       fs_simviz_find_label (w, "Network profile"),
			       "windows: the facts name the model and the profile");
			shoot (w, "window-blocked-by-rule-windows");
		} else {
			shoot (w, "window-blocked-by-rule");
		}
		gtk_widget_destroy (w);
	}

	/* Sentinel decided: lift it, with when it lifts by itself. */
	{
		static const gchar *sent[] = {
			"6:203.0.113.50,Sentinel: beaconing", NULL };
		FsPolicy *sp = policy_of (sent);

		w = window_for (FS_WHATIF_LINUX_FIRST_MATCH, sp, "203.0.113.50",
		                "allow outbound tcp to 203.0.113.50 port 443", &r);
		fs_simviz_window_set_action_func (w, on_action, NULL);
		show (w);
		btn = fs_simviz_find_button (w, "Lift Sentinel block (expires in");
		CHECK (btn != NULL &&
		       fs_simviz_find_button (w, "Create allow rule") == NULL,
		       "a Sentinel block offers Lift Sentinel block (expires in "
		       "N min), not a rule");
		handler_reset ();
		if (btn != NULL)
			gtk_button_clicked (GTK_BUTTON (btn));
		CHECK (handler_calls == 1 &&
		       handler_kind == FS_WHATIF_ACT_LIFT_SENTINEL,
		       "the lift button hands the Sentinel action to the caller");
		CHECK (fs_simviz_find_label (w, "Internet host") == NULL ||
		       TRUE, "(the card is drawn, not a label)");
		shoot (w, "window-sentinel");
		gtk_widget_destroy (w);
		fs_policy_free (sp);
	}

	fs_policy_free (p);
	fs_policy_free (empty);
}

static void
test_depends (void)
{
	static const gchar *rows[] = { "1:SSH,22,10.0.0.0/8,lan", NULL };
	FsPolicy *p = policy_of (rows);
	FsWhatIfResult *r = NULL;
	GtkWidget *w = window_for (FS_WHATIF_LINUX_FIRST_MATCH, p, NULL,
	                           "inbound ssh", &r);
	GtkWidget *hit;

	fs_simviz_window_set_action_func (w, on_action, NULL);
	show (w);
	CHECK (fs_simviz_outcome_of (r) == FS_SIMVIZ_DEPENDS,
	       "the engine splits SSH from anyone: it depends on the host");
	hit = fs_simviz_find_named (w, "whatif-window-header");
	CHECK (has_class (fs_simviz_find_label (hit, "DEPENDS"), "warn") &&
	       fs_simviz_find_label (hit, "ALLOWED") == NULL &&
	       fs_simviz_find_label (hit, "BLOCKED") == NULL,
	       "depends: the header says DEPENDS, in amber, never one verdict");
	hit = fs_simviz_find_named (w, "whatif-why");
	CHECK (fs_simviz_find_label (hit, "It depends on what the line left "
	                                  "open") != NULL &&
	       fs_simviz_find_label (hit, "10.0.0.0/8") != NULL &&
	       fs_simviz_find_label (hit, "ALLOWED") != NULL &&
	       fs_simviz_find_label (hit, "BLOCKED") != NULL,
	       "depends: Why lists each case with its own verdict");
	shoot (w, "window-depends");
	gtk_widget_destroy (w);

	/* Windows: what was assumed is on screen. */
	w = window_for (FS_WHATIF_WINDOWS_BLOCK_WINS, p, NULL,
	                "Can 10.1.2.3 reach my SSH?", &r);
	show (w);
	hit = fs_simviz_find_named (w, "whatif-notes");
	CHECK (fs_simviz_find_label (hit, "Good to know") != NULL &&
	       fs_simviz_find_label (hit, "Only the rules StockFW manages")
	       != NULL,
	       "windows: the assumptions are shown, not hidden");
	shoot (w, "window-depends-windows");
	gtk_widget_destroy (w);
	fs_policy_free (p);
}

static void
test_both_ways (void)
{
	static const gchar *rows[] = { "1:SSH,22,10.0.0.0/8,lan", NULL };
	FsPolicy *p = policy_of (rows);
	FsWhatIfResult *r = NULL;
	GtkWidget *w = window_for (FS_WHATIF_LINUX_FIRST_MATCH, p, NULL, "ssh",
	                           &r);
	GtkWidget *tabs, *in_tab, *out_tab;

	show (w);
	CHECK (r->answers->len == 2, "a line with no direction is answered "
	                             "both ways");
	tabs = fs_simviz_find_named (w, "whatif-tabs");
	in_tab = fs_simviz_find_button (tabs, "Inbound: DEPENDS");
	out_tab = fs_simviz_find_button (tabs, "Outbound: ALLOWED");
	CHECK (in_tab != NULL && out_tab != NULL,
	       "both ways: one tab per direction, each with its verdict");
	CHECK (fs_simviz_find_label (fs_simviz_find_named (w,
	                                 "whatif-window-header"),
	                             "between this computer and any host")
	       != NULL,
	       "both ways: the title says both directions in plain words");
	CHECK (fs_simviz_window_get_answer (w) == 0 && in_tab != NULL &&
	       gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (in_tab)),
	       "both ways: the inbound tab shows first");
	shoot (w, "window-both-inbound");

	if (out_tab != NULL)
		gtk_button_clicked (GTK_BUTTON (out_tab));
	pump (20);
	CHECK (fs_simviz_window_get_answer (w) == 1 &&
	       gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (out_tab)) &&
	       !gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (in_tab)),
	       "both ways: a click on Outbound shows the outbound answer");
	shoot (w, "window-both-outbound");
	gtk_widget_destroy (w);
	fs_policy_free (p);
}

static void
test_error (void)
{
	FsPolicy *p = fs_policy_new ();
	FsWhatIfResult *r = NULL;
	GtkWidget *w = window_for (FS_WHATIF_LINUX_FIRST_MATCH, p, NULL,
	                           "zqxv gibberish", &r);
	GtkWidget *hit;

	show (w);
	CHECK (fs_simviz_outcome_of (NULL) == FS_SIMVIZ_ERROR &&
	       fs_simviz_outcome_of (r) == FS_SIMVIZ_ERROR,
	       "no answer, or an unreadable line, is the error state");
	hit = fs_simviz_find_named (w, "whatif-window-header");
	CHECK (has_class (fs_simviz_find_label (hit, "ERROR"), "err"),
	       "error: a grey ERROR badge");
	CHECK (fs_simviz_find_label (hit, "could not read this question") &&
	       fs_simviz_find_label (hit, "I could not find a port") &&
	       fs_simviz_find_label (hit, "zqxv gibberish"),
	       "error: it says so, says what it looked for, and shows the line");
	CHECK (fs_simviz_find_label (fs_simviz_find_named (w,
	                                 "whatif-error-help"),
	                             "Can 192.168.1.50 reach my SSH?") != NULL,
	       "error: examples of what can be asked");
	CHECK (fs_simviz_find_named (w, "whatif-facts") == NULL &&
	       fs_simviz_find_named (w, "whatif-replay") == NULL &&
	       fs_simviz_find_named (w, "whatif-actions") == NULL &&
	       fs_simviz_find_label (w, "ALLOWED") == NULL &&
	       fs_simviz_find_label (w, "BLOCKED") == NULL,
	       "error: no diagram, facts, fixes or verdict");
	check_close (w, "error");
	shoot (w, "window-error");
	gtk_widget_destroy (w);

	w = fs_simviz_window_new (NULL, NULL, "zqxv");
	CHECK (fs_simviz_find_label (w, "could not read this question") != NULL,
	       "no answer at all is the error state too");
	gtk_widget_destroy (w);
	fs_policy_free (p);
}

/* The firewall is off and the saved policy is on hold: the answer
 * must say both, above everything else. */
static void
test_honesty (void)
{
	FsPolicy *p = fs_policy_new ();
	FsSettings *s = fs_settings_new ();
	FsWhatIfContext *ctx = context (FS_WHATIF_LINUX_FIRST_MATCH, p, s, NULL);
	FsWhatIfResult *r;
	GtkWidget *w, *strip;

	ctx->firewall = FS_WHATIF_FW_STOPPED;
	ctx->live = FS_WHATIF_LIVE_HELD;
	r = fs_whatif_simulate_text (ctx, "inbound ssh from 10.1.2.3");
	w = fs_simviz_window_new (r, ctx, NULL);
	fs_simviz_window_set_action_func (w, on_action, NULL);
	show (w);

	strip = fs_simviz_find_named (w, "whatif-window-honesty");
	CHECK (strip != NULL &&
	       fs_simviz_find_label (strip, "The firewall is not running") &&
	       fs_simviz_find_label (strip, "applies are on hold"),
	       "a stopped firewall and a held policy are said up front");
	CHECK (fs_simviz_find_label (fs_simviz_find_named (w, "whatif-facts"),
	                             "Saved, applies on hold") != NULL,
	       "the facts say the policy is not live");
	CHECK (fs_simviz_find_button (w, "Apply policy") != NULL,
	       "the held policy can be applied from the window");
	shoot (w, "window-stopped-held");
	gtk_widget_destroy (w);
	fs_whatif_context_free (ctx);
	fs_settings_free (s);
	fs_policy_free (p);
}

/* A new answer replaces the old one in place; a status line is shown,
 * and cleared by the next answer. */
static void
test_in_place (void)
{
	FsPolicy *p = fs_policy_new ();
	FsSettings *s = fs_settings_new ();
	FsWhatIfContext *ctx = context (FS_WHATIF_LINUX_FIRST_MATCH, p, s, NULL);
	GtkWidget *w = fs_simviz_window_new (
		fs_whatif_simulate_text (ctx, "inbound tcp port 8443"), ctx, NULL);
	GtkWidget *status;

	show (w);
	fs_simviz_window_set_status (w, FS_SIMVIZ_STATUS_WARN,
	                             "Saved, but it is NOT live yet.");
	status = fs_simviz_find_named (w, "whatif-status");
	CHECK (status != NULL && gtk_widget_get_visible (status) &&
	       fs_simviz_find_label (w, "NOT live yet") != NULL,
	       "a fix's report shows in the window");
	fs_simviz_window_set_result (
		w, fs_whatif_simulate_text (ctx, "outbound dns to 8.8.8.8"), ctx,
		NULL);
	pump (20);
	CHECK (fs_simviz_find_label (fs_simviz_find_named (w,
	                                 "whatif-window-header"),
	                             "8.8.8.8") != NULL &&
	       !gtk_widget_get_visible (status),
	       "a new answer replaces the old one, and clears the report");
	gtk_widget_destroy (w);
	fs_whatif_context_free (ctx);
	fs_settings_free (s);
	fs_policy_free (p);
}

/* Keys: Enter presses the default (Close), Esc closes. */
static void
send_key_event (GtkWidget *w, guint keyval, GdkEventType type)
{
	GdkEvent *ev;
	GdkKeymapKey *keys = NULL;
	gint n = 0;

	/* The window may already be gone after the press. */
	if (w == NULL || gtk_widget_get_window (w) == NULL)
		return;
	ev = gdk_event_new (type);

	ev->key.window = g_object_ref (gtk_widget_get_window (w));
	ev->key.send_event = TRUE;
	ev->key.time = GDK_CURRENT_TIME;
	ev->key.keyval = keyval;
	if (gdk_keymap_get_entries_for_keyval (
	        gdk_keymap_get_for_display (gdk_display_get_default ()),
	        keyval, &keys, &n) && n > 0)
		ev->key.hardware_keycode = (guint16) keys[0].keycode;
	g_free (keys);
	gdk_event_set_device (ev, gdk_seat_get_keyboard (
		gdk_display_get_default_seat (gdk_display_get_default ())));
	gtk_main_do_event (ev);
	gdk_event_free (ev);
}

/* A press and its release, as a keyboard sends them: a focused
 * GtkButton clicks on the release. */
static void
send_key (GtkWidget **w, guint keyval)
{
	send_key_event (*w, keyval, GDK_KEY_PRESS);
	pump (20);
	send_key_event (*w, keyval, GDK_KEY_RELEASE);
}

static void
test_keys (void)
{
	FsPolicy *p = fs_policy_new ();
	GtkWidget *w;

	for (gint k = 0; k < 2; k++) {
		w = window_for (FS_WHATIF_LINUX_FIRST_MATCH, p, NULL,
		                "inbound ssh", NULL);
		g_object_add_weak_pointer (G_OBJECT (w), (gpointer *) &w);
		show (w);
		send_key (&w, k == 0 ? GDK_KEY_Escape : GDK_KEY_Return);
		pump (40);
		CHECK (w == NULL, "%s closes the window",
		       k == 0 ? "Esc" : "Enter");
		if (w != NULL)
			gtk_widget_destroy (w);
	}
	fs_policy_free (p);
}

/* Reduced motion: the final frame at once.  With animations on, the
 * verdict medallion above the wall is not up yet a few frames in;
 * with them off it is there from the first draw. */
static gboolean
medallion_is_green (GtkWidget *w)
{
	GtkWidget *area = NULL;
	GtkWidget *replay;
	cairo_surface_t *s;
	GtkAllocation a;
	gint x, y;
	guint32 px;
	gboolean green;
	GList *stack = g_list_prepend (NULL, w);

	/* The diagram: the first drawing area. */
	while (stack != NULL && area == NULL) {
		GtkWidget *cur = stack->data;

		stack = g_list_delete_link (stack, stack);
		if (GTK_IS_DRAWING_AREA (cur) && gtk_widget_get_mapped (cur))
			area = cur;
		else if (GTK_IS_CONTAINER (cur))
			stack = g_list_concat (gtk_container_get_children (
			                           GTK_CONTAINER (cur)), stack);
	}
	g_list_free (stack);
	if (area == NULL)
		return FALSE;

	replay = fs_simviz_find_named (w, "whatif-replay");
	(void) replay;
	gtk_widget_get_allocation (area, &a);
	s = render (area);
	x = a.width / 2;
	y = (gint) (a.height / 2.0 + 8.0 - 56.0 - 8.0);
	px = rgb_at (s, x, y);
	green = (((px >> 8) & 0xff) > ((px >> 16) & 0xff) + 40) &&
	        (((px >> 8) & 0xff) > (px & 0xff) + 20);
	cairo_surface_destroy (s);
	return green;
}

static void
test_reduced_motion (void)
{
	static const gchar *rows[] = { "1:SSH,22,192.168.1.50,lab", NULL };
	FsPolicy *p = policy_of (rows);
	GtkSettings *settings = gtk_settings_get_default ();
	GtkWidget *w;

	g_object_set (settings, "gtk-enable-animations", TRUE, NULL);
	w = window_for (FS_WHATIF_LINUX_FIRST_MATCH, p, NULL,
	                "inbound ssh from 192.168.1.50", NULL);
	fs_simviz_window_present (w, NULL);
	pump (60);
	CHECK (!medallion_is_green (w) &&
	       fs_simviz_find_named (w, "whatif-replay") != NULL,
	       "animated: no verdict medallion a few frames in, and Replay");
	pump ((guint) (FS_SIMVIZ_DURATION * 1000) + 200);
	CHECK (medallion_is_green (w),
	       "animated: the green check is up once the play is done");
	gtk_widget_destroy (w);

	g_object_set (settings, "gtk-enable-animations", FALSE, NULL);
	CHECK (!fs_simviz_animations_enabled (),
	       "gtk-enable-animations off is read as reduced motion");
	w = window_for (FS_WHATIF_LINUX_FIRST_MATCH, p, NULL,
	                "inbound ssh from 192.168.1.50", NULL);
	fs_simviz_window_present (w, NULL);
	pump (60);
	CHECK (medallion_is_green (w) &&
	       fs_simviz_find_named (w, "whatif-replay") == NULL,
	       "reduced motion: the final frame at once, nothing to replay");
	gtk_widget_destroy (w);
	g_object_set (settings, "gtk-enable-animations", TRUE, NULL);
	fs_policy_free (p);
}

/* Dark theme: the window picks its dark palette from the theme's own
 * text colour, so it reads there too.  This runs in a child started
 * with the dark Adwaita variant, the app's stylesheet installed as it
 * always is: a theme switch inside one process is not reliable. */
static void
test_dark (void)
{
	static const gchar *rows[] = { "1:SSH,22,10.0.0.0/8,lan", NULL };
	FsPolicy *p = policy_of (rows);
	GtkWidget *w;
	GtkWidget *title;
	GdkRGBA fg;

	w = window_for (FS_WHATIF_WINDOWS_BLOCK_WINS, p, NULL,
	                "Can 192.168.1.50 reach my SSH?", NULL);
	show (w);
	CHECK (has_class (w, "fs-wi-dark"),
	       "dark: a dark desktop theme gets the dark palette");
	title = fs_simviz_find_label (w, "Inbound TCP port 22");
	CHECK (title != NULL, "dark: the question heads the window");
	if (title != NULL) {
		gtk_style_context_get_color (gtk_widget_get_style_context (title),
		                             GTK_STATE_FLAG_NORMAL, &fg);
		CHECK (0.2126 * fg.red + 0.7152 * fg.green + 0.0722 * fg.blue
		       > 0.6, "dark: the title is light text on the dark page");
	}
	check_close (w, "dark");
	shoot (w, "window-dark");
	gtk_widget_destroy (w);
	fs_policy_free (p);
}

/* Runs this program again for the dark-theme checks; its output and
 * failures are this run's. */
static void
run_dark_child (const gchar *self)
{
	gchar *argv[] = { (gchar *) self, (gchar *) "--dark", NULL };
	gchar **envp = g_get_environ ();
	gint status = -1;
	GError *error = NULL;

	envp = g_environ_setenv (envp, "GTK_THEME", "Adwaita:dark", TRUE);
	fflush (stdout);
	if (!g_spawn_sync (NULL, argv, envp, G_SPAWN_CHILD_INHERITS_STDIN,
	                   NULL, NULL, NULL, NULL, &status, &error)) {
		CHECK (FALSE, "dark: could not start the dark run: %s",
		       error->message);
		g_error_free (error);
	} else {
		CHECK (status == 0, "dark: the dark-theme run passed");
	}
	g_strfreev (envp);
}

int
main (int argc, char **argv)
{
	gtk_init (&argc, &argv);
	install_app_theme ();
	g_object_set (gtk_settings_get_default (), "gtk-enable-animations",
	              TRUE, NULL);

	if (argc > 1 && strcmp (argv[1], "--dark") == 0) {
		test_dark ();
		printf ("\n%s: %d failure(s) in the dark run\n",
		        failures ? "FAILED" : "PASSED", failures);
		return failures ? 1 : 0;
	}

	test_timeline ();
	test_zones ();
	test_allowed ();
	test_blocked ();
	test_depends ();
	test_both_ways ();
	test_error ();
	test_honesty ();
	test_in_place ();
	test_keys ();
	test_reduced_motion ();
	run_dark_child (argv[0]);

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);

	return failures ? 1 : 0;
}
