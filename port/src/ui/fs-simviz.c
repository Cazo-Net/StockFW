/*---[ fs-simviz.c ]----------------------------------------------------
 * The What-If Details window.
 *
 * Layout, top to bottom, inside a scrolled page on the app's canvas:
 *
 *   header     the verdict badge, the question in plain words, what was
 *              typed, the one-line answer, and -- when the answer rests
 *              on something that is not the live firewall (the firewall
 *              is off, the saved policy is not the one loaded) -- an
 *              amber strip that says so;
 *   tabs       a line asked without a direction is answered both ways:
 *              one tab per direction, each with its own verdict;
 *   diagram    where the traffic starts, the StockFW wall, where it is
 *              going.  Each device card says what it is ("This
 *              computer", "LAN host 192.168.1.50", "Internet host") and
 *              which network it sits on; the service card names the
 *              port.  A packet plays the verdict (see below).  Replay is
 *              a small round button over the diagram;
 *   facts      protocol, from, to, port or service, direction, the
 *              firewall model, and on Windows the network profile;
 *   why        the engine's trace as a numbered list, the deciding step
 *              highlighted; a rule from the policy links to its row;
 *   what you can do   one button per fix the engine checked, with the
 *              exact row a Create would write; or why there is none;
 *   good to know      everything the answer had to assume;
 *   footer     Close: a real dialog action (Enter and Esc work).
 *
 * The diagram plays one of four scripts:
 *
 *   allowed  the packet reaches the wall, the wall flashes green, a
 *            check pops, the packet continues, the far card glows;
 *   blocked  the packet reaches the wall, the wall shakes red, an X
 *            pops, the packet bounces back and fades, the far line
 *            turns gray;
 *   depends  the answer differs by case: the packet waits at the
 *            wall, the wall turns amber and a "?" pops -- the cases
 *            are spelled out under "Why";
 *   error    no verdict at all, so no diagram either.
 *
 * The scripts live in fs_simviz_state_at(): pure arithmetic over
 * (outcome, seconds), no GTK and no clock, so tests assert every
 * frame.  With animations turned off the final frame is drawn at once.
 *
 * Colours: a light and a dark palette, picked from the theme's own text
 * colour, so the window reads in both.  The light one is the 1.0.7
 * shell's: white cards on #f4f5f7, ink #16181d, muted #5b6472.
 *--------------------------------------------------------------------*/

#include "fs-simviz.h"
#include "core/fs-i18n.h"
#include "core/fs-util.h"
#include "core/fs-netplace.h"
#include "core/fs-backend.h"

#include <gdk/gdkkeysyms.h>
#include <string.h>

/* =====================================================================
 * Pure timeline
 * ===================================================================== */

static FsSimvizOutcome
outcome_of_verdict (FsWhatIfVerdict verdict)
{
	switch (verdict) {
	case FS_WHATIF_ALLOWED: return FS_SIMVIZ_ALLOWED;
	case FS_WHATIF_BLOCKED: return FS_SIMVIZ_BLOCKED;
	case FS_WHATIF_DEPENDS: return FS_SIMVIZ_DEPENDS;
	case FS_WHATIF_ERROR:
	default:                return FS_SIMVIZ_ERROR;
	}
}

FsSimvizOutcome
fs_simviz_outcome_of (const FsWhatIfResult *result)
{
	if (result == NULL || result->query == NULL ||
	    result->answers == NULL || result->answers->len == 0)
		return FS_SIMVIZ_ERROR;

	return outcome_of_verdict (result->verdict);
}

FsSimvizOutcome
fs_simviz_outcome_of_answer (const FsWhatIfAnswer *answer)
{
	return answer != NULL ? outcome_of_verdict (answer->verdict)
	                      : FS_SIMVIZ_ERROR;
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

	/* It depends: the packet goes to the wall and waits there.  No
	 * flash either way and nothing past the wall -- the cases are a
	 * list under the diagram, not a pass or a bounce. */
	if (outcome == FS_SIMVIZ_DEPENDS) {
		s.packet = (t < T_REACH) ? 0.5 * ease (t / T_REACH) : 0.5;
		s.packet_alpha = 1.0;
		s.fw_amber = ramp (t, T_REACH, 0.30);
		s.show_question = (t >= T_VERDICT);
		if (t >= FS_SIMVIZ_DURATION) {
			s.done = TRUE;
			s.packet = 0.5;
			s.fw_amber = 1.0;
			s.show_question = TRUE;
		}
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
 * Zones: where an address is, in the words of the device cards
 * ===================================================================== */

/* The network part of "a.b.c.d/n" or "v6/n", and its prefix length
 * (-1 for a plain address). */
static gchar *
split_block (const gchar *host, gint *prefix)
{
	const gchar *slash = strchr (host, '/');

	*prefix = -1;
	if (slash == NULL)
		return g_strdup (host);

	*prefix = (gint) g_ascii_strtoll (slash + 1, NULL, 10);
	return g_strndup (host, (gsize) (slash - host));
}

FsSimvizZone
fs_simviz_zone_of (const gchar *host)
{
	static const gchar *lan[] = {
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
		"fc00::/7", "fe80::/10", "ff00::/8", NULL
	};
	static const gchar *self[] = { "127.0.0.0/8", "::1/128", NULL };
	FsSimvizZone zone = FS_SIMVIZ_ZONE_INTERNET;
	gchar *net;
	gint prefix;
	gboolean v6;

	if (host == NULL || *host == '\0' || fs_util_target_is_anyone (host))
		return FS_SIMVIZ_ZONE_ANY;

	net = split_block (host, &prefix);
	v6 = (strchr (net, ':') != NULL);

	/* A block wider than any private range spans both worlds. */
	if (prefix >= 0 && prefix < (v6 ? 7 : 8)) {
		g_free (net);
		return FS_SIMVIZ_ZONE_ANY;
	}

	for (guint i = 0; self[i] != NULL; i++)
		if (fs_util_addr_in_cidr (self[i], net))
			zone = FS_SIMVIZ_ZONE_THIS;

	for (guint i = 0; zone == FS_SIMVIZ_ZONE_INTERNET && lan[i] != NULL;
	     i++)
		if (fs_util_addr_in_cidr (lan[i], net))
			zone = FS_SIMVIZ_ZONE_LAN;

	g_free (net);
	return zone;
}

const gchar *
fs_simviz_zone_title (const gchar *host)
{
	gboolean block = (host != NULL && strchr (host, '/') != NULL);

	switch (fs_simviz_zone_of (host)) {
	case FS_SIMVIZ_ZONE_THIS:
		return _("This computer");
	case FS_SIMVIZ_ZONE_LAN:
		return block ? _("LAN hosts") : _("LAN host");
	case FS_SIMVIZ_ZONE_INTERNET:
		return block ? _("Internet hosts") : _("Internet host");
	case FS_SIMVIZ_ZONE_ANY:
	default:
		return (host != NULL) ? _("Wide address block")
		                      : _("Any host");
	}
}

/* =====================================================================
 * Palette: light and dark, one table each
 * ===================================================================== */
typedef struct
{
	gdouble r, g, b, a;
} Color;

#define RGB(r, g, b) { (r) / 255.0, (g) / 255.0, (b) / 255.0, 1.0 }

typedef struct
{
	Color canvas;      /* the diagram's ground (the card)       */
	Color node;        /* device card face                      */
	Color node_this;   /* this computer's card face             */
	Color border;
	Color ink;
	Color muted;
	Color icon;        /* icon strokes                          */
	Color icon_fill;
	Color line;        /* the path before any verdict           */
	Color line_off;    /* the far line once blocked             */
	Color green;
	Color red;
	Color amber;
	Color brick;
	Color brick_edge;
	Color mortar;
	Color flame;
	Color flame_in;
	Color packet;
	Color tag_lan_bg, tag_lan_fg;
	Color tag_net_bg, tag_net_fg;
	Color tag_this_bg, tag_this_fg;
	Color tag_any_bg, tag_any_fg;
} Palette;

static const Palette LIGHT = {
	.canvas      = RGB (255, 255, 255),
	.node        = RGB (250, 251, 252),
	.node_this   = RGB (244, 246, 250),
	.border      = RGB (221, 225, 231),
	.ink         = RGB (22, 24, 29),
	.muted       = RGB (91, 100, 114),
	.icon        = RGB (58, 66, 80),
	.icon_fill   = RGB (234, 238, 244),
	.line        = RGB (174, 181, 192),
	.line_off    = RGB (214, 218, 224),
	.green       = RGB (30, 127, 79),
	.red         = RGB (180, 35, 24),
	.amber       = RGB (196, 120, 0),
	.brick       = RGB (236, 222, 210),
	.brick_edge  = RGB (196, 168, 146),
	.mortar      = RGB (250, 247, 244),
	.flame       = RGB (198, 40, 40),
	.flame_in    = RGB (245, 158, 11),
	.packet      = RGB (22, 24, 29),
	.tag_lan_bg  = RGB (234, 240, 251), .tag_lan_fg  = RGB (29, 78, 216),
	.tag_net_bg  = RGB (241, 237, 251), .tag_net_fg  = RGB (91, 33, 182),
	.tag_this_bg = RGB (238, 240, 243), .tag_this_fg = RGB (22, 24, 29),
	.tag_any_bg  = RGB (244, 245, 247), .tag_any_fg  = RGB (91, 100, 114),
};

static const Palette DARK = {
	.canvas      = RGB (29, 32, 39),
	.node        = RGB (38, 42, 51),
	.node_this   = RGB (42, 47, 57),
	.border      = RGB (60, 66, 78),
	.ink         = RGB (231, 233, 238),
	.muted       = RGB (160, 168, 182),
	.icon        = RGB (201, 206, 214),
	.icon_fill   = RGB (50, 56, 68),
	.line        = RGB (110, 118, 132),
	.line_off    = RGB (70, 76, 88),
	.green       = RGB (74, 222, 128),
	.red         = RGB (248, 113, 113),
	.amber       = RGB (251, 191, 36),
	.brick       = RGB (92, 72, 58),
	.brick_edge  = RGB (130, 100, 80),
	.mortar      = RGB (45, 40, 38),
	.flame       = RGB (239, 83, 80),
	.flame_in    = RGB (251, 191, 36),
	.packet      = RGB (231, 233, 238),
	.tag_lan_bg  = RGB (30, 42, 68),  .tag_lan_fg  = RGB (147, 180, 245),
	.tag_net_bg  = RGB (42, 33, 64),  .tag_net_fg  = RGB (196, 181, 253),
	.tag_this_bg = RGB (50, 56, 68),  .tag_this_fg = RGB (231, 233, 238),
	.tag_any_bg  = RGB (44, 48, 57),  .tag_any_fg  = RGB (160, 168, 182),
};

static void
set_color (cairo_t *cr, const Color *c, gdouble alpha_mul)
{
	cairo_set_source_rgba (cr, c->r, c->g, c->b,
	                       c->a * (alpha_mul < 0.0 ? 0.0 : alpha_mul));
}

/* =====================================================================
 * CSS: the window and the Copilot card, light and dark
 * ===================================================================== */
static const gchar *simviz_css =
	/* The window: the shell's canvas, cards on it. */
	".fs-wi-page { background-color: #f4f5f7; }\n"
	".fs-wi-page scrolledwindow, .fs-wi-page viewport {\n"
	"  background-color: #f4f5f7; border: none; }\n"
	".fs-wi-card { background-color: #ffffff; border: 1px solid #e3e6eb;\n"
	"  border-radius: 12px; padding: 16px 18px;\n"
	"  box-shadow: 0 1px 2px rgba(16,24,40,0.06); }\n"
	".fs-wi-card.diagram { padding: 4px; }\n"
	".fs-wi-heading { font-size: 13px; font-weight: bold; color: #16181d; }\n"
	".fs-wi-sub { font-size: 12px; color: #5b6472; }\n"
	".fs-wi-text { font-size: 13px; color: #16181d; }\n"
	".fs-wi-muted { font-size: 13px; color: #5b6472; }\n"
	".fs-wi-title { font-size: 17px; font-weight: bold; color: #16181d; }\n"
	".fs-wi-mono { font-family: \"JetBrains Mono\", \"Cascadia Mono\",\n"
	"  \"DejaVu Sans Mono\", monospace; font-size: 12px; }\n"
	/* The header: the Overview's verdict card. */
	".fs-wi-hero { border-radius: 12px; padding: 18px 20px;\n"
	"  border: 1px solid #dadfe6; background-color: #f6f7f9; }\n"
	".fs-wi-hero.ok   { background-color: #f4fbf7; border-color: #bfe3cf; }\n"
	".fs-wi-hero.bad  { background-color: #fef4f3; border-color: #f4c7c3; }\n"
	".fs-wi-hero.warn { background-color: #fff8eb; border-color: #f3d9a4; }\n"
	/* Verdict badges, shared with the card. */
	".fs-wi-badge { border-radius: 6px; padding: 3px 10px;\n"
	"  font-weight: bold; font-size: 12px; border: 1px solid transparent; }\n"
	".fs-wi-badge.ok   { color: #1e7f4f; background-color: #e3f4ea;\n"
	"  border-color: #bfe3cf; }\n"
	".fs-wi-badge.bad  { color: #b42318; background-color: #fde8e6;\n"
	"  border-color: #f4c7c3; }\n"
	".fs-wi-badge.warn { color: #8a5300; background-color: #fff1d6;\n"
	"  border-color: #f3d9a4; }\n"
	".fs-wi-badge.err  { color: #3a4250; background-color: #eef0f3;\n"
	"  border-color: #d5dae1; }\n"
	".fs-wi-badge.big  { font-size: 13px; padding: 5px 12px; }\n"
	/* Strips: something the answer rests on that is not the live
	 * firewall, and what a fix did. */
	".fs-wi-strip { border-radius: 8px; padding: 8px 12px; font-size: 13px;\n"
	"  border: 1px solid #f3d9a4; background-color: #fff8eb; color: #6b3f00; }\n"
	".fs-wi-strip.ok  { border-color: #bfe3cf; background-color: #f4fbf7;\n"
	"  color: #145a38; }\n"
	".fs-wi-strip.bad { border-color: #f4c7c3; background-color: #fef4f3;\n"
	"  color: #8a1c12; }\n"
	/* Facts. */
	".fs-wi-caption { font-size: 12px; color: #5b6472; }\n"
	".fs-wi-value { font-size: 13px; font-weight: 600; color: #16181d; }\n"
	/* The trace. */
	".fs-wi-step { padding: 7px 10px; border-radius: 8px; }\n"
	".fs-wi-note { font-style: italic; font-size: 12px; }\n"
	".fs-wi-fold { padding: 6px 10px; }\n"
	".fs-wi-fold > title { color: #5b6472; font-size: 13px; }\n"
	".fs-wi-dark .fs-wi-fold > title { color: #a0a8b6; }\n"
	".fs-wi-step.decides.ok   { background-color: #f0f9f4;\n"
	"  border: 1px solid #bfe3cf; }\n"
	".fs-wi-step.decides.bad  { background-color: #fef4f3;\n"
	"  border: 1px solid #f4c7c3; }\n"
	".fs-wi-step.decides.warn { background-color: #fff8eb;\n"
	"  border: 1px solid #f3d9a4; }\n"
	".fs-wi-stepnum { font-size: 11px; font-weight: bold; color: #5b6472;\n"
	"  background-color: #eef0f3; border-radius: 11px; min-width: 22px;\n"
	"  min-height: 22px; }\n"
	".fs-wi-step.decides .fs-wi-stepnum { color: #ffffff;\n"
	"  background-color: #16181d; }\n"
	".fs-wi-rule { font-size: 13px; font-weight: 600; color: #16181d; }\n"
	".fs-wi-step.skipped .fs-wi-rule { font-weight: normal; color: #5b6472; }\n"
	".fs-wi-detail { font-size: 12px; color: #5b6472; }\n"
	".fs-wi-tag { font-size: 11px; font-weight: bold; border-radius: 4px;\n"
	"  padding: 1px 6px; color: #5b6472; background-color: #eef0f3; }\n"
	".fs-wi-tag.ok   { color: #1e7f4f; background-color: #e3f4ea; }\n"
	".fs-wi-tag.bad  { color: #b42318; background-color: #fde8e6; }\n"
	".fs-wi-tag.warn { color: #8a5300; background-color: #fff1d6; }\n"
	".fs-wi-case { font-size: 13px; color: #16181d; }\n"
	/* Fixes. */
	".fs-wi-action { padding: 12px 0 2px 0; border-top: 1px solid #eef0f3; }\n"
	".fs-wi-action.first { border-top: none; padding-top: 4px; }\n"
	".fs-wi-code { background-color: #f6f7f9; border: 1px solid #e3e6eb;\n"
	"  border-radius: 6px; padding: 6px 10px; color: #16181d; }\n"
	/* Buttons, the shell's, scoped so no theme face shows through. */
	".fs-wi-page button.btn-primary, .fs-wi-card button.btn-primary,\n"
	".fs-wi-dialog .dialog-action-area button.btn-primary {\n"
	"  background-image: none; background-color: #16181d;\n"
	"  border: 1px solid #16181d; border-radius: 8px; color: #ffffff;\n"
	"  padding: 7px 16px; font-weight: 600; font-size: 13px;\n"
	"  box-shadow: none; text-shadow: none; }\n"
	".fs-wi-page button.btn-primary:hover, .fs-wi-card button.btn-primary:hover,\n"
	".fs-wi-dialog .dialog-action-area button.btn-primary:hover {\n"
	"  background-color: #2a2f39; border-color: #2a2f39; }\n"
	".fs-wi-page button.btn-primary label, .fs-wi-card button.btn-primary label,\n"
	".fs-wi-dialog .dialog-action-area button.btn-primary label {\n"
	"  color: #ffffff; }\n"
	".fs-wi-page button.btn-subtle, .fs-wi-card button.btn-subtle {\n"
	"  background-image: none; background-color: #ffffff;\n"
	"  border: 1px solid #cdd2da; border-radius: 8px; color: #16181d;\n"
	"  padding: 7px 14px; font-weight: 600; font-size: 13px;\n"
	"  box-shadow: none; text-shadow: none; }\n"
	".fs-wi-page button.btn-subtle:hover, .fs-wi-card button.btn-subtle:hover {\n"
	"  background-color: #f4f5f7; border-color: #aeb5c0; }\n"
	".fs-wi-dialog .dialog-action-area { padding: 10px 16px 14px 16px;\n"
	"  border-top: 1px solid #e3e6eb; background-color: #ffffff; }\n"
	".fs-wi-dialog .dialog-action-area button { min-width: 96px; }\n"
	"button.fs-wi-link { background-image: none; background-color: transparent;\n"
	"  border: none; box-shadow: none; padding: 0 2px; min-height: 0;\n"
	"  color: #1d4ed8; font-size: 12px; }\n"
	"button.fs-wi-link:hover { color: #1e3a8a; background-color: transparent; }\n"
	"button.fs-wi-link label { color: inherit; }\n"
	"button.fs-wi-iconbtn { background-image: none; background-color: #ffffff;\n"
	"  border: 1px solid #cdd2da; border-radius: 16px; padding: 4px;\n"
	"  min-width: 24px; min-height: 24px; box-shadow: none; }\n"
	"button.fs-wi-iconbtn:hover { background-color: #f4f5f7; }\n"
	/* Direction tabs: one segmented control. */
	".fs-wi-seg button { background-image: none; background-color: #ffffff;\n"
	"  border: 1px solid #cdd2da; border-radius: 0; color: #16181d;\n"
	"  padding: 6px 16px; font-size: 13px; box-shadow: none; }\n"
	".fs-wi-seg button:first-child { border-radius: 8px 0 0 8px; }\n"
	".fs-wi-seg button:last-child { border-radius: 0 8px 8px 0;\n"
	"  border-left-width: 0; }\n"
	".fs-wi-seg button label, .fs-wi-seg button:backdrop label {\n"
	"  color: #16181d; }\n"
	".fs-wi-seg button:backdrop { background-color: #ffffff;\n"
	"  border-color: #cdd2da; }\n"
	".fs-wi-seg button:hover { background-color: #f4f5f7; }\n"
	".fs-wi-seg button:checked, .fs-wi-seg button:checked:backdrop,\n"
	".fs-wi-seg button:checked:hover { background-color: #16181d;\n"
	"  border-color: #16181d; color: #ffffff; font-weight: 600; }\n"
	".fs-wi-seg button:checked label,\n"
	".fs-wi-seg button:checked:backdrop label { color: #ffffff; }\n"
	/* The Copilot card. */
	"button.fs-wi-example { background-image: none; background-color: #ffffff;\n"
	"  border: 1px solid #d5dae1; border-radius: 14px; padding: 3px 12px;\n"
	"  min-height: 0; font-size: 12px; color: #16181d; box-shadow: none; }\n"
	"button.fs-wi-example:hover { background-color: #f4f5f7;\n"
	"  border-color: #aeb5c0; }\n"
	".fs-wi-chip { font-size: 12px; border-radius: 6px; padding: 2px 8px;\n"
	"  color: #16181d; background-color: #eef2f7; border: 1px solid #dfe5ee; }\n"
	".fs-wi-chip.open { color: #5b6472; background-color: transparent;\n"
	"  border: 1px dashed #c4cad3; }\n"
	".fs-wi-chip.verb { color: #16181d; background-color: #ffffff;\n"
	"  border: 1px solid #cdd2da; }\n"
	".fs-wi-chip.ignored { color: #8a5300; background-color: #fff8eb;\n"
	"  border: 1px solid #f3d9a4; }\n"
	".fs-wi-result { border: 1px solid #e3e6eb; border-radius: 10px;\n"
	"  padding: 10px 12px; background-color: #fafbfc; }\n"
	".fs-wi-result.ok   { border-color: #bfe3cf; background-color: #f6fcf8; }\n"
	".fs-wi-result.bad  { border-color: #f4c7c3; background-color: #fef7f6; }\n"
	".fs-wi-result.warn { border-color: #f3d9a4; background-color: #fffaf0; }\n"
	"button.fs-wi-history { background-image: none;\n"
	"  background-color: transparent; border: none; border-radius: 6px;\n"
	"  padding: 3px 6px; min-height: 0; box-shadow: none; }\n"
	"button.fs-wi-history:hover {\n"
	"  background-color: alpha(currentColor, 0.08); }\n"
	/* The answer row has a light surface of its own whatever the
	 * theme: its text is the light palette's ink, never the theme's. */
	".fs-wi-result label { color: #16181d; }\n"
	".fs-wi-dot { font-size: 10px; }\n"
	".fs-wi-dot.ok { color: #1e7f4f; } .fs-wi-dot.bad { color: #b42318; }\n"
	".fs-wi-dot.warn { color: #c47800; } .fs-wi-dot.err { color: #8b93a1; }\n"

	/* ---- dark: the same layout on dark surfaces ---- */
	".fs-wi-dark.fs-wi-page, .fs-wi-dark .fs-wi-page,\n"
	".fs-wi-dark scrolledwindow, .fs-wi-dark viewport {\n"
	"  background-color: #15171c; }\n"
	".fs-wi-dark .fs-wi-card { background-color: #1d2027;\n"
	"  border-color: #2f3440; }\n"
	".fs-wi-dark .fs-wi-heading, .fs-wi-dark .fs-wi-text,\n"
	".fs-wi-dark .fs-wi-title, .fs-wi-dark .fs-wi-value,\n"
	".fs-wi-dark .fs-wi-rule, .fs-wi-dark .fs-wi-case { color: #e7e9ee; }\n"
	".fs-wi-dark .fs-wi-sub, .fs-wi-dark .fs-wi-muted,\n"
	".fs-wi-dark .fs-wi-caption, .fs-wi-dark .fs-wi-detail,\n"
	".fs-wi-dark .fs-wi-step.skipped .fs-wi-rule { color: #a0a8b6; }\n"
	".fs-wi-dark .fs-wi-hero { background-color: #1d2027;\n"
	"  border-color: #2f3440; }\n"
	".fs-wi-dark .fs-wi-hero.ok   { background-color: #16251d;\n"
	"  border-color: #275a3d; }\n"
	".fs-wi-dark .fs-wi-hero.bad  { background-color: #2a1816;\n"
	"  border-color: #6b2a24; }\n"
	".fs-wi-dark .fs-wi-hero.warn { background-color: #2a2113;\n"
	"  border-color: #6b5220; }\n"
	".fs-wi-dark .fs-wi-badge.ok   { color: #86efac; background-color: #183a27;\n"
	"  border-color: #275a3d; }\n"
	".fs-wi-dark .fs-wi-badge.bad  { color: #fca5a5; background-color: #3d1d1a;\n"
	"  border-color: #6b2a24; }\n"
	".fs-wi-dark .fs-wi-badge.warn { color: #fcd34d; background-color: #3a2c12;\n"
	"  border-color: #6b5220; }\n"
	".fs-wi-dark .fs-wi-badge.err  { color: #cbd2dc; background-color: #2c313b;\n"
	"  border-color: #444b58; }\n"
	".fs-wi-dark .fs-wi-strip { background-color: #2a2113;\n"
	"  border-color: #6b5220; color: #fcd34d; }\n"
	".fs-wi-dark .fs-wi-strip.ok { background-color: #16251d;\n"
	"  border-color: #275a3d; color: #86efac; }\n"
	".fs-wi-dark .fs-wi-strip.bad { background-color: #2a1816;\n"
	"  border-color: #6b2a24; color: #fca5a5; }\n"
	".fs-wi-dark .fs-wi-step.decides.ok   { background-color: #16251d;\n"
	"  border-color: #275a3d; }\n"
	".fs-wi-dark .fs-wi-step.decides.bad  { background-color: #2a1816;\n"
	"  border-color: #6b2a24; }\n"
	".fs-wi-dark .fs-wi-step.decides.warn { background-color: #2a2113;\n"
	"  border-color: #6b5220; }\n"
	".fs-wi-dark .fs-wi-stepnum { color: #cbd2dc; background-color: #2c313b; }\n"
	".fs-wi-dark .fs-wi-step.decides .fs-wi-stepnum { color: #15171c;\n"
	"  background-color: #e7e9ee; }\n"
	".fs-wi-dark .fs-wi-tag { color: #cbd2dc; background-color: #2c313b; }\n"
	".fs-wi-dark .fs-wi-tag.ok   { color: #86efac; background-color: #183a27; }\n"
	".fs-wi-dark .fs-wi-tag.bad  { color: #fca5a5; background-color: #3d1d1a; }\n"
	".fs-wi-dark .fs-wi-tag.warn { color: #fcd34d; background-color: #3a2c12; }\n"
	".fs-wi-dark .fs-wi-action { border-top-color: #2f3440; }\n"
	".fs-wi-dark .fs-wi-code { background-color: #15171c;\n"
	"  border-color: #2f3440; color: #e7e9ee; }\n"
	".fs-wi-dark button.btn-primary,\n"
	".fs-wi-dark.fs-wi-dialog .dialog-action-area button.btn-primary {\n"
	"  background-color: #e7e9ee; border-color: #e7e9ee; color: #15171c; }\n"
	".fs-wi-dark button.btn-primary label,\n"
	".fs-wi-dark.fs-wi-dialog .dialog-action-area button.btn-primary label {\n"
	"  color: #15171c; }\n"
	".fs-wi-dark button.btn-primary:hover,\n"
	".fs-wi-dark.fs-wi-dialog .dialog-action-area button.btn-primary:hover {\n"
	"  background-color: #ffffff; border-color: #ffffff; }\n"
	".fs-wi-dark button.btn-subtle, .fs-wi-dark button.fs-wi-iconbtn {\n"
	"  background-color: #262a33; border-color: #3c424e; color: #e7e9ee; }\n"
	".fs-wi-dark button.btn-subtle label { color: #e7e9ee; }\n"
	".fs-wi-dark button.btn-subtle:hover, .fs-wi-dark button.fs-wi-iconbtn:hover {\n"
	"  background-color: #2f3440; }\n"
	".fs-wi-dark.fs-wi-dialog .dialog-action-area {\n"
	"  background-color: #1d2027; border-top-color: #2f3440; }\n"
	".fs-wi-dark button.fs-wi-link { color: #93b4f5; }\n"
	".fs-wi-dark .fs-wi-seg button { background-color: #262a33;\n"
	"  border-color: #3c424e; color: #e7e9ee; }\n"
	".fs-wi-dark .fs-wi-seg button label,\n"
	".fs-wi-dark .fs-wi-seg button:backdrop label { color: #e7e9ee; }\n"
	".fs-wi-dark .fs-wi-seg button:backdrop { background-color: #262a33; }\n"
	".fs-wi-dark .fs-wi-seg button:checked { background-color: #e7e9ee;\n"
	"  border-color: #e7e9ee; }\n"
	".fs-wi-dark .fs-wi-seg button:checked label { color: #15171c; }\n";

static GdkScreen *css_screen = NULL;

void
fs_simviz_install_css (void)
{
	GdkScreen *screen = gdk_screen_get_default ();
	GtkCssProvider *provider;
	GError *error = NULL;

	if (screen == NULL || screen == css_screen)
		return;

	provider = gtk_css_provider_new ();
	if (gtk_css_provider_load_from_data (provider, simviz_css, -1, &error))
		gtk_style_context_add_provider_for_screen (
			screen, GTK_STYLE_PROVIDER (provider),
			GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	else
		g_warning ("What-If styles: %s", error->message);
	g_clear_error (&error);
	g_object_unref (provider);

	css_screen = screen;
}

gboolean
fs_simviz_animations_enabled (void)
{
	GtkSettings *settings = gtk_settings_get_default ();
	gboolean on = TRUE;

	if (settings != NULL)
		g_object_get (settings, "gtk-enable-animations", &on, NULL);
	return on;
}

/* Dark when the theme writes light text: whatever the theme, its own
 * text colour says which palette reads on it. */
static gboolean
theme_is_dark (GtkWidget *widget)
{
	GtkStyleContext *style = gtk_widget_get_style_context (widget);
	GdkRGBA fg;

	gtk_style_context_get_color (style, gtk_style_context_get_state (style),
	                             &fg);
	return (0.2126 * fg.red + 0.7152 * fg.green + 0.0722 * fg.blue) > 0.6;
}

/* =====================================================================
 * Small widget helpers
 * ===================================================================== */
static void
add_class (GtkWidget *w, const gchar *name)
{
	if (name != NULL)
		gtk_style_context_add_class (gtk_widget_get_style_context (w),
		                             name);
}

static void
set_a11y_name (GtkWidget *w, const gchar *name)
{
	AtkObject *acc = gtk_widget_get_accessible (w);

	if (acc != NULL && name != NULL)
		atk_object_set_name (acc, name);
}

/* A label: wrapped or not, left-aligned, with up to two classes. */
static GtkWidget *
text_label (const gchar *text, const gchar *cls, const gchar *cls2,
            gboolean wrap)
{
	GtkWidget *l = gtk_label_new (text != NULL ? text : "");

	gtk_label_set_xalign (GTK_LABEL (l), 0.0);
	gtk_label_set_yalign (GTK_LABEL (l), 0.5);
	if (wrap) {
		gtk_label_set_line_wrap (GTK_LABEL (l), TRUE);
		gtk_label_set_line_wrap_mode (GTK_LABEL (l), PANGO_WRAP_WORD_CHAR);
		gtk_label_set_max_width_chars (GTK_LABEL (l), 80);
	}
	add_class (l, cls);
	add_class (l, cls2);
	return l;
}

static const gchar *
verdict_class (FsWhatIfVerdict v)
{
	switch (v) {
	case FS_WHATIF_ALLOWED: return "ok";
	case FS_WHATIF_BLOCKED: return "bad";
	case FS_WHATIF_DEPENDS: return "warn";
	case FS_WHATIF_ERROR:
	default:                return "err";
	}
}

GtkWidget *
fs_simviz_badge_new (FsWhatIfVerdict verdict)
{
	GtkWidget *badge = gtk_label_new (fs_whatif_verdict_name (verdict));
	gchar *name = g_strdup_printf (_("Verdict: %s"),
	                               fs_whatif_verdict_name (verdict));

	fs_simviz_install_css ();
	add_class (badge, "fs-wi-badge");
	add_class (badge, verdict_class (verdict));
	gtk_widget_set_valign (badge, GTK_ALIGN_CENTER);
	gtk_widget_set_halign (badge, GTK_ALIGN_START);
	set_a11y_name (badge, name);
	g_free (name);
	return badge;
}

/* A white card with a heading (and an optional line under it).
 * Returns the card; content goes in with gtk_box_pack_start. */
static GtkWidget *
card_new (const gchar *heading, const gchar *sub)
{
	GtkWidget *card = gtk_box_new (GTK_ORIENTATION_VERTICAL, 8);

	add_class (card, "fs-wi-card");
	if (heading != NULL) {
		GtkWidget *h = text_label (heading, "fs-wi-heading", NULL, FALSE);

		gtk_box_pack_start (GTK_BOX (card), h, FALSE, FALSE, 0);
	}
	if (sub != NULL)
		gtk_box_pack_start (GTK_BOX (card),
		                    text_label (sub, "fs-wi-sub", NULL, TRUE),
		                    FALSE, FALSE, 0);
	return card;
}

/* =====================================================================
 * Window state
 * ===================================================================== */
typedef struct _Win Win;

/* One direction's answer, as one tab. */
typedef struct
{
	Win                  *win;
	const FsWhatIfAnswer *answer;
	guint                 index;
	GtkWidget            *area;
	GtkWidget            *replay;
	FsSimvizOutcome       outcome;
	FsSimvizState         state;
	gboolean              stopped;     /* the firewall is off: it decided */

	/* The two device cards: left is where the packet starts. */
	gchar        *left_title, *left_sub, *left_extra;
	FsSimvizZone  left_zone;
	gchar        *right_title, *right_sub, *right_extra;
	FsSimvizZone  right_zone;
	gchar        *wall_sub;
} Page;

struct _Win
{
	GtkWidget        *dialog;
	GtkWidget        *body;        /* scrolled page's vbox: status + content */
	GtkWidget        *status;      /* the strip a fix reports in       */
	GtkWidget        *content;     /* rebuilt for every result         */
	GtkWidget        *stack;
	GPtrArray        *tabs;        /* GtkToggleButton*, one per answer  */
	GPtrArray        *pages;       /* Page*                             */
	guint             current;
	gboolean          dark;
	gboolean          animate;
	gboolean          switching;

	FsWhatIfResult   *result;
	gchar            *typed;       /* the line as typed                */

	/* What the context said, copied. */
	gboolean          have_ctx;
	FsWhatIfPlatform  platform;
	FsWhatIfFwState   firewall;
	guint             profiles_in_use;
	gint              profile_enabled[3];
	FsWhatIfLive      live;
	gchar            *live_detail;

	FsSimvizActionFunc func;
	gpointer           func_data;

	gint64            t0_us;
	guint             timer_id;
};

static void
page_free (gpointer data)
{
	Page *p = data;

	g_free (p->left_title);
	g_free (p->left_sub);
	g_free (p->left_extra);
	g_free (p->right_title);
	g_free (p->right_sub);
	g_free (p->right_extra);
	g_free (p->wall_sub);
	g_free (p);
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

/* Triangle wave in [-1, 1] -- a shake without libm. */
static gdouble
wave (gdouble t)
{
	gdouble phase = t * 9.0;
	gdouble f = phase - (gdouble) ((gint64) phase);

	return (f < 0.5) ? (1.0 - 4.0 * f) : (4.0 * f - 3.0);
}

/* Text in the theme font, anchored by its centre-top (align 0.5) or
 * its left-top (align 0.0).  Returns the width drawn. */
static gdouble
draw_text (cairo_t *cr, GtkWidget *widget, const gchar *text, gdouble x,
           gdouble y, gdouble align, gboolean bold, gdouble size_pt,
           const Color *color, gdouble max_w)
{
	PangoLayout *layout;
	PangoFontDescription *font;
	PangoRectangle logical;
	GtkStyleContext *style;

	if (text == NULL || *text == '\0')
		return 0.0;

	layout = gtk_widget_create_pango_layout (widget, text);
	style = gtk_widget_get_style_context (widget);
	gtk_style_context_get (style, gtk_style_context_get_state (style),
	                       "font", &font, NULL);
	pango_font_description_set_size (font, (gint) (size_pt * PANGO_SCALE));
	pango_font_description_set_weight (font, bold ? PANGO_WEIGHT_BOLD
	                                              : PANGO_WEIGHT_NORMAL);
	pango_layout_set_font_description (layout, font);
	pango_font_description_free (font);
	if (max_w > 0.0) {
		pango_layout_set_width (layout, (gint) (max_w * PANGO_SCALE));
		pango_layout_set_ellipsize (layout, PANGO_ELLIPSIZE_END);
	}

	pango_layout_get_pixel_extents (layout, NULL, &logical);
	set_color (cr, color, 1.0);
	cairo_move_to (cr, x - align * logical.width, y);
	pango_cairo_show_layout (cr, layout);
	g_object_unref (layout);
	return logical.width;
}

/* The pill above a device card naming its network. */
static void
draw_zone_tag (cairo_t *cr, GtkWidget *widget, const Palette *pal,
               FsSimvizZone zone, gboolean is_this, gdouble cx, gdouble y)
{
	const gchar *text;
	const Color *bg, *fg;
	PangoLayout *layout;
	PangoFontDescription *font;
	PangoRectangle ink;
	GtkStyleContext *style;
	gdouble w, h = 18.0;

	if (is_this) {
		text = _("THIS COMPUTER");
		bg = &pal->tag_this_bg; fg = &pal->tag_this_fg;
	} else if (zone == FS_SIMVIZ_ZONE_LAN) {
		text = _("LOCAL NETWORK");
		bg = &pal->tag_lan_bg; fg = &pal->tag_lan_fg;
	} else if (zone == FS_SIMVIZ_ZONE_INTERNET) {
		text = _("INTERNET");
		bg = &pal->tag_net_bg; fg = &pal->tag_net_fg;
	} else if (zone == FS_SIMVIZ_ZONE_THIS) {
		text = _("LOOPBACK");
		bg = &pal->tag_this_bg; fg = &pal->tag_this_fg;
	} else {
		text = _("LAN OR INTERNET");
		bg = &pal->tag_any_bg; fg = &pal->tag_any_fg;
	}

	layout = gtk_widget_create_pango_layout (widget, text);
	style = gtk_widget_get_style_context (widget);
	gtk_style_context_get (style, gtk_style_context_get_state (style),
	                       "font", &font, NULL);
	pango_font_description_set_size (font, 7 * PANGO_SCALE);
	pango_font_description_set_weight (font, PANGO_WEIGHT_BOLD);
	pango_layout_set_font_description (layout, font);
	pango_font_description_free (font);
	pango_layout_get_pixel_extents (layout, NULL, &ink);
	w = ink.width + 16.0;

	rounded_rect (cr, cx - w / 2.0, y, w, h, 9.0);
	set_color (cr, bg, 1.0);
	cairo_fill (cr);

	set_color (cr, fg, 1.0);
	cairo_move_to (cr, cx - ink.width / 2.0, y + (h - ink.height) / 2.0);
	pango_cairo_show_layout (cr, layout);
	g_object_unref (layout);
}

/* This computer: a monitor on a stand. */
static void
draw_icon_monitor (cairo_t *cr, const Palette *pal, gdouble cx, gdouble cy)
{
	rounded_rect (cr, cx - 15, cy - 12, 30, 20, 3);
	set_color (cr, &pal->icon_fill, 1.0);
	cairo_fill_preserve (cr);
	set_color (cr, &pal->icon, 1.0);
	cairo_set_line_width (cr, 1.6);
	cairo_stroke (cr);

	cairo_move_to (cr, cx, cy + 8);
	cairo_line_to (cr, cx, cy + 13);
	cairo_move_to (cr, cx - 8, cy + 14);
	cairo_line_to (cr, cx + 8, cy + 14);
	cairo_set_line_cap (cr, CAIRO_LINE_CAP_ROUND);
	cairo_stroke (cr);
	cairo_set_line_cap (cr, CAIRO_LINE_CAP_BUTT);
}

/* A LAN host: a laptop. */
static void
draw_icon_laptop (cairo_t *cr, const Palette *pal, gdouble cx, gdouble cy)
{
	rounded_rect (cr, cx - 13, cy - 12, 26, 18, 2.5);
	set_color (cr, &pal->icon_fill, 1.0);
	cairo_fill_preserve (cr);
	set_color (cr, &pal->icon, 1.0);
	cairo_set_line_width (cr, 1.6);
	cairo_stroke (cr);

	cairo_move_to (cr, cx - 18, cy + 9);
	cairo_line_to (cr, cx + 18, cy + 9);
	cairo_line_to (cr, cx + 15, cy + 13);
	cairo_line_to (cr, cx - 15, cy + 13);
	cairo_close_path (cr);
	set_color (cr, &pal->icon_fill, 1.0);
	cairo_fill_preserve (cr);
	set_color (cr, &pal->icon, 1.0);
	cairo_set_line_join (cr, CAIRO_LINE_JOIN_ROUND);
	cairo_stroke (cr);
	cairo_set_line_join (cr, CAIRO_LINE_JOIN_MITER);
}

/* An Internet host: a globe. */
static void
draw_icon_globe (cairo_t *cr, const Palette *pal, gdouble cx, gdouble cy)
{
	cairo_arc (cr, cx, cy, 14, 0.0, 6.2831853);
	set_color (cr, &pal->icon_fill, 1.0);
	cairo_fill_preserve (cr);
	set_color (cr, &pal->icon, 1.0);
	cairo_set_line_width (cr, 1.6);
	cairo_stroke (cr);

	cairo_save (cr);
	cairo_translate (cr, cx, cy);
	cairo_scale (cr, 0.45, 1.0);
	cairo_arc (cr, 0.0, 0.0, 14, 0.0, 6.2831853);
	cairo_restore (cr);
	cairo_set_line_width (cr, 1.2);
	cairo_stroke (cr);

	cairo_move_to (cr, cx - 14, cy);
	cairo_line_to (cr, cx + 14, cy);
	cairo_move_to (cr, cx - 11.5, cy - 7);
	cairo_line_to (cr, cx + 11.5, cy - 7);
	cairo_move_to (cr, cx - 11.5, cy + 7);
	cairo_line_to (cr, cx + 11.5, cy + 7);
	cairo_stroke (cr);
}

/* Any host: three linked nodes -- a network, not one machine. */
static void
draw_icon_network (cairo_t *cr, const Palette *pal, gdouble cx, gdouble cy)
{
	const gdouble pts[3][2] = { { 0, -11 }, { -12, 9 }, { 12, 9 } };

	set_color (cr, &pal->icon, 1.0);
	cairo_set_line_width (cr, 1.4);
	for (gint i = 0; i < 3; i++) {
		cairo_move_to (cr, cx + pts[i][0], cy + pts[i][1]);
		cairo_line_to (cr, cx + pts[(i + 1) % 3][0],
		               cy + pts[(i + 1) % 3][1]);
	}
	cairo_stroke (cr);
	for (gint i = 0; i < 3; i++) {
		cairo_arc (cr, cx + pts[i][0], cy + pts[i][1], 5.0, 0.0,
		           6.2831853);
		set_color (cr, &pal->icon_fill, 1.0);
		cairo_fill_preserve (cr);
		set_color (cr, &pal->icon, 1.0);
		cairo_stroke (cr);
	}
}

/* A device card: face, hairline, icon, title, address, service. */
static void
draw_device (cairo_t *cr, GtkWidget *widget, const Palette *pal,
             gdouble cx, gdouble cy, gdouble w, gdouble h,
             gboolean is_this, FsSimvizZone zone, const gchar *title,
             const gchar *sub, const gchar *extra, gdouble glow)
{
	gdouble top = cy - h / 2.0;

	if (glow > 0.0) {
		rounded_rect (cr, cx - w / 2.0 - 5, top - 5, w + 10, h + 10, 15);
		set_color (cr, &pal->green, 0.18 * glow);
		cairo_fill (cr);
	}

	rounded_rect (cr, cx - w / 2.0, top, w, h, 12);
	set_color (cr, is_this ? &pal->node_this : &pal->node, 1.0);
	cairo_fill_preserve (cr);
	if (glow > 0.0) {
		Color mix = pal->border;

		mix.r += (pal->green.r - mix.r) * glow;
		mix.g += (pal->green.g - mix.g) * glow;
		mix.b += (pal->green.b - mix.b) * glow;
		set_color (cr, &mix, 1.0);
		cairo_set_line_width (cr, 1.0 + glow);
	} else {
		set_color (cr, &pal->border, 1.0);
		cairo_set_line_width (cr, 1.0);
	}
	cairo_stroke (cr);

	if (is_this || zone == FS_SIMVIZ_ZONE_THIS)
		draw_icon_monitor (cr, pal, cx, top + 26);
	else if (zone == FS_SIMVIZ_ZONE_LAN)
		draw_icon_laptop (cr, pal, cx, top + 26);
	else if (zone == FS_SIMVIZ_ZONE_INTERNET)
		draw_icon_globe (cr, pal, cx, top + 26);
	else
		draw_icon_network (cr, pal, cx, top + 26);

	{
		gdouble y = top + 48;

		draw_text (cr, widget, title, cx, y, 0.5, TRUE, 9.5,
		           &pal->ink, w - 12);
		y += 18;
		if (sub != NULL && *sub != '\0') {
			draw_text (cr, widget, sub, cx, y, 0.5, FALSE, 8.5,
			           &pal->muted, w - 12);
			y += 15;
		}
		draw_text (cr, widget, extra, cx, y, 0.5, FALSE, 8.5,
		           &pal->muted, w - 12);
	}
}

/* The firewall: a brick wall with a flame on top.  The washes tint
 * the wall with the verdict; `t' drives the shake.  `off' draws it
 * greyed: the firewall is not running. */
static void
draw_firewall (cairo_t *cr, const Palette *pal, gdouble cx, gdouble cy,
               const FsSimvizState *s, gboolean off)
{
	gdouble wall_w = 76, wall_h = 42;
	gdouble wall_x = cx - wall_w / 2.0;
	gdouble wall_y = cy - wall_h / 2.0 + 6;
	gdouble a = off ? 0.35 : 1.0;

	cairo_save (cr);
	cairo_translate (cr, s->shake * 4.0 * wave (s->t), 0.0);

	/* Flame above the wall: two teardrops. */
	cairo_save (cr);
	cairo_translate (cr, cx, wall_y - 2);
	cairo_move_to (cr, -9, 2);
	cairo_curve_to (cr, -11, -8, -4, -10, -1, -20);
	cairo_curve_to (cr, 2, -11, 11, -8, 9, 2);
	cairo_curve_to (cr, 7, 7, -7, 7, -9, 2);
	cairo_close_path (cr);
	set_color (cr, &pal->flame, a);
	cairo_fill (cr);
	cairo_move_to (cr, -4.5, 2);
	cairo_curve_to (cr, -5.5, -3, -2, -5, 0, -10);
	cairo_curve_to (cr, 2, -5, 5.5, -3, 4.5, 2);
	cairo_curve_to (cr, 3.5, 5, -3.5, 5, -4.5, 2);
	cairo_close_path (cr);
	set_color (cr, &pal->flame_in, a);
	cairo_fill (cr);
	cairo_restore (cr);

	/* Four offset rows of bricks. */
	cairo_save (cr);
	rounded_rect (cr, wall_x, wall_y, wall_w, wall_h, 4);
	cairo_clip (cr);
	set_color (cr, &pal->mortar, 1.0);
	cairo_paint (cr);
	for (gint row = 0; row < 4; row++) {
		gdouble y = wall_y + row * 10.5;
		gdouble off_x = (row % 2 == 0) ? 0.0 : 9.0;

		for (gdouble x = wall_x - off_x; x < wall_x + wall_w; x += 18.0) {
			rounded_rect (cr, x + 1, y + 1, 16, 8.5, 1.5);
			set_color (cr, &pal->brick, a);
			cairo_fill (cr);
		}
	}
	cairo_restore (cr);

	rounded_rect (cr, wall_x, wall_y, wall_w, wall_h, 4);
	set_color (cr, &pal->brick_edge, a);
	cairo_set_line_width (cr, 1.2);
	cairo_stroke (cr);

	if (s->fw_red > 0.0) {
		rounded_rect (cr, wall_x, wall_y, wall_w, wall_h, 4);
		set_color (cr, &pal->red, 0.42 * s->fw_red);
		cairo_fill (cr);
	}
	if (s->fw_green > 0.0) {
		rounded_rect (cr, wall_x, wall_y, wall_w, wall_h, 4);
		set_color (cr, &pal->green, 0.38 * s->fw_green);
		cairo_fill (cr);
	}
	if (s->fw_amber > 0.0) {
		rounded_rect (cr, wall_x, wall_y, wall_w, wall_h, 4);
		set_color (cr, &pal->amber, 0.40 * s->fw_amber);
		cairo_fill (cr);
	}

	cairo_restore (cr);
}

/* The packet: a small envelope, in the verdict's colour once known. */
static void
draw_packet (cairo_t *cr, const Palette *pal, gdouble x, gdouble y,
             gdouble alpha, const Color *tint)
{
	if (alpha <= 0.0)
		return;

	cairo_save (cr);
	cairo_translate (cr, x, y);
	rounded_rect (cr, -13, -9, 26, 18, 3.5);
	set_color (cr, &pal->canvas, alpha);
	cairo_fill_preserve (cr);
	set_color (cr, tint, alpha);
	cairo_set_line_width (cr, 1.8);
	cairo_stroke (cr);
	cairo_move_to (cr, -13, -9);
	cairo_line_to (cr, 0, 1.5);
	cairo_line_to (cr, 13, -9);
	cairo_set_line_width (cr, 1.5);
	cairo_set_line_join (cr, CAIRO_LINE_JOIN_ROUND);
	cairo_stroke (cr);
	cairo_restore (cr);
}

typedef enum { MEDAL_CHECK, MEDAL_X, MEDAL_QUESTION } Medal;

static void
draw_medallion (cairo_t *cr, const Palette *pal, gdouble x, gdouble y,
                Medal medal, gdouble pop)
{
	if (pop <= 0.0)
		return;

	cairo_save (cr);
	cairo_translate (cr, x, y);
	cairo_scale (cr, 0.5 + 0.5 * pop, 0.5 + 0.5 * pop);

	cairo_arc (cr, 0.0, 0.0, 13.0, 0.0, 6.2831853);
	set_color (cr, medal == MEDAL_CHECK ? &pal->green
	               : medal == MEDAL_X ? &pal->red : &pal->amber, pop);
	cairo_fill (cr);

	set_color (cr, &pal->canvas, pop);
	cairo_set_line_width (cr, 2.4);
	cairo_set_line_cap (cr, CAIRO_LINE_CAP_ROUND);

	if (medal == MEDAL_CHECK) {
		cairo_move_to (cr, -5.5, 0.5);
		cairo_line_to (cr, -1.5, 4.5);
		cairo_line_to (cr, 6.0, -4.5);
		cairo_stroke (cr);
	} else if (medal == MEDAL_X) {
		cairo_move_to (cr, -4.5, -4.5);
		cairo_line_to (cr, 4.5, 4.5);
		cairo_move_to (cr, 4.5, -4.5);
		cairo_line_to (cr, -4.5, 4.5);
		cairo_stroke (cr);
	} else {
		cairo_arc (cr, 0.0, -3.0, 3.8, 3.4, 6.2831853 + 0.9);
		cairo_line_to (cr, 0.0, 2.0);
		cairo_stroke (cr);
		cairo_arc (cr, 0.0, 6.0, 1.4, 0.0, 6.2831853);
		cairo_fill (cr);
	}

	cairo_restore (cr);
}

/* A dotted path with an arrow head at its far end. */
static void
draw_path (cairo_t *cr, const Color *c, gdouble x0, gdouble x1, gdouble y,
           gboolean dashed, gboolean arrow)
{
	gdouble dotted[2] = { 0.1, 5.0 };
	gdouble dash[2] = { 6.0, 5.0 };

	cairo_save (cr);
	set_color (cr, c, 1.0);
	cairo_set_line_cap (cr, CAIRO_LINE_CAP_ROUND);
	cairo_set_line_width (cr, dashed ? 1.6 : 2.6);
	cairo_set_dash (cr, dashed ? dash : dotted, 2, 0.0);
	cairo_move_to (cr, x0, y);
	cairo_line_to (cr, x1 - (arrow ? 6.0 : 0.0), y);
	cairo_stroke (cr);
	cairo_set_dash (cr, NULL, 0, 0.0);
	if (arrow) {
		cairo_move_to (cr, x1, y);
		cairo_line_to (cr, x1 - 7.0, y - 4.5);
		cairo_line_to (cr, x1 - 7.0, y + 4.5);
		cairo_close_path (cr);
		cairo_fill (cr);
	}
	cairo_restore (cr);
}

/* =====================================================================
 * The draw callback
 * ===================================================================== */
static gboolean
on_draw (GtkWidget *widget, cairo_t *cr, gpointer data)
{
	Page *pg = data;
	const Palette *pal = pg->win->dark ? &DARK : &LIGHT;
	const FsSimvizState *s = &pg->state;
	GtkAllocation alloc;
	gdouble w, h, cw, ch, x1, x2, x3, cy, wall_half, leg1_a, leg1_b;
	gdouble leg2_a, leg2_b, medal_y;
	const Color *tint;

	gtk_widget_get_allocation (widget, &alloc);
	w = alloc.width;
	h = alloc.height;

	cw = CLAMP (w * 0.24, 132.0, 176.0);
	ch = 98.0;
	x1 = 20.0 + cw / 2.0;
	x3 = w - 20.0 - cw / 2.0;
	x2 = w / 2.0;
	cy = h / 2.0 + 8.0;
	wall_half = 38.0;
	medal_y = cy - 56.0;

	set_color (cr, &pal->canvas, 1.0);
	rounded_rect (cr, 0, 0, w, h, 10);
	cairo_fill (cr);

	/* The two legs, under everything else. */
	leg1_a = x1 + cw / 2.0 + 6.0;
	leg1_b = x2 - wall_half - 8.0;
	leg2_a = x2 + wall_half + 8.0;
	leg2_b = x3 - cw / 2.0 - 6.0;

	draw_path (cr, pg->outcome == FS_SIMVIZ_DEPENDS && s->fw_amber > 0.0
	               ? &pal->amber : &pal->line,
	           leg1_a, leg1_b, cy, FALSE, TRUE);
	if (s->tail_blocked)
		draw_path (cr, &pal->line_off, leg2_a, leg2_b, cy, TRUE, FALSE);
	else
		draw_path (cr, s->dest_glow > 0.0 ? &pal->green : &pal->line,
		           leg2_a, leg2_b, cy,
		           pg->outcome == FS_SIMVIZ_DEPENDS, TRUE);

	/* The device cards and their networks. */
	draw_zone_tag (cr, widget, pal, pg->left_zone,
	               pg->left_zone == FS_SIMVIZ_ZONE_THIS &&
	               pg->left_sub == NULL, x1, cy - ch / 2.0 - 26.0);
	draw_device (cr, widget, pal, x1, cy, cw, ch,
	             pg->left_zone == FS_SIMVIZ_ZONE_THIS && pg->left_sub == NULL,
	             pg->left_zone, pg->left_title, pg->left_sub,
	             pg->left_extra, 0.0);
	draw_zone_tag (cr, widget, pal, pg->right_zone,
	               pg->right_zone == FS_SIMVIZ_ZONE_THIS &&
	               pg->right_sub == NULL, x3, cy - ch / 2.0 - 26.0);
	draw_device (cr, widget, pal, x3, cy, cw, ch,
	             pg->right_zone == FS_SIMVIZ_ZONE_THIS &&
	             pg->right_sub == NULL,
	             pg->right_zone, pg->right_title, pg->right_sub,
	             pg->right_extra, s->dest_glow);

	/* The wall and its name. */
	draw_firewall (cr, pal, x2, cy, s, pg->stopped);
	draw_text (cr, widget, "StockFW", x2, cy + 32.0, 0.5, TRUE, 9.5,
	           &pal->ink, 0.0);
	draw_text (cr, widget, pg->wall_sub, x2, cy + 49.0, 0.5, FALSE, 8.0,
	           &pal->muted, (x3 - x1) - cw - 8.0);

	/* The packet: ink before the wall answers, then the verdict. */
	tint = &pal->packet;
	if (s->fw_green > 0.5)
		tint = &pal->green;
	else if (s->fw_red > 0.5)
		tint = &pal->red;
	else if (s->fw_amber > 0.5)
		tint = &pal->amber;
	if (s->packet >= 0.0) {
		gdouble px = (s->packet <= 0.5)
			? leg1_a + (leg1_b - leg1_a) * (s->packet / 0.5)
			: leg2_a + (leg2_b - 16.0 - leg2_a) *
			  ((s->packet - 0.5) / 0.5);

		draw_packet (cr, pal, px, cy, s->packet_alpha, tint);
	}

	if (pg->outcome == FS_SIMVIZ_ALLOWED && s->show_check)
		draw_medallion (cr, pal, x2, medal_y, MEDAL_CHECK, s->fw_green);
	else if (pg->outcome == FS_SIMVIZ_BLOCKED && s->show_x)
		draw_medallion (cr, pal, x2, medal_y, MEDAL_X, s->fw_red);
	else if (pg->outcome == FS_SIMVIZ_DEPENDS && s->show_question)
		draw_medallion (cr, pal, x2, medal_y, MEDAL_QUESTION, s->fw_amber);

	return TRUE;
}

/* =====================================================================
 * The clock
 * ===================================================================== */
static Page *
current_page (Win *win)
{
	if (win->pages == NULL || win->current >= win->pages->len)
		return NULL;
	return g_ptr_array_index (win->pages, win->current);
}

static void
stop_play (Win *win)
{
	if (win->timer_id != 0) {
		g_source_remove (win->timer_id);
		win->timer_id = 0;
	}
}

static gboolean
tick (gpointer data)
{
	Win *win = data;
	Page *pg = current_page (win);
	gdouble t = (g_get_monotonic_time () - win->t0_us) /
	            (gdouble) G_USEC_PER_SEC;

	if (pg == NULL) {
		win->timer_id = 0;
		return G_SOURCE_REMOVE;
	}

	pg->state = fs_simviz_state_at (pg->outcome, t);
	gtk_widget_queue_draw (pg->area);

	if (t >= FS_SIMVIZ_DURATION) {
		win->timer_id = 0;
		return G_SOURCE_REMOVE;
	}
	return G_SOURCE_CONTINUE;
}

/* Plays the shown tab from the start -- or, with animations off,
 * shows its final frame. */
static void
start_play (Win *win)
{
	Page *pg = current_page (win);

	stop_play (win);
	if (pg == NULL || pg->area == NULL)
		return;

	if (!win->animate) {
		pg->state = fs_simviz_state_at (pg->outcome,
		                                FS_SIMVIZ_DURATION);
		gtk_widget_queue_draw (pg->area);
		return;
	}

	win->t0_us = g_get_monotonic_time ();
	pg->state = fs_simviz_state_at (pg->outcome, 0.0);
	gtk_widget_queue_draw (pg->area);
	win->timer_id = g_timeout_add (33, tick, win);
}

/* =====================================================================
 * Widget walkers -- exposed for the smoke tests, which read the
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
		GtkWidget *hit = NULL;

		for (GList *l = children; l != NULL && hit == NULL; l = l->next)
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
		GtkWidget *hit = NULL;

		for (GList *l = children; l != NULL && hit == NULL; l = l->next)
			hit = fs_simviz_find_button (GTK_WIDGET (l->data), needle);

		g_list_free (children);
		return hit;
	}

	return NULL;
}

GtkWidget *
fs_simviz_find_named (GtkWidget *root, const gchar *name)
{
	if (root == NULL || name == NULL)
		return NULL;

	if (g_strcmp0 (gtk_widget_get_name (root), name) == 0)
		return root;

	if (GTK_IS_CONTAINER (root)) {
		GList *children = gtk_container_get_children (
			GTK_CONTAINER (root));
		GtkWidget *hit = NULL;

		for (GList *l = children; l != NULL && hit == NULL; l = l->next)
			hit = fs_simviz_find_named (GTK_WIDGET (l->data), name);

		g_list_free (children);
		return hit;
	}

	return NULL;
}

/* =====================================================================
 * Words
 * ===================================================================== */
static const gchar *
proto_words (const FsWhatIfQuery *q)
{
	if (q->icmp_type != NULL)
		return g_str_equal (q->icmp_type, "echo-request") ? _("ICMP ping")
		       : g_str_equal (q->icmp_type, "echo-reply")
		         ? _("ICMP ping reply") : _("ICMP");
	switch (q->protocol) {
	case FS_WHATIF_PROTO_TCP:  return "TCP";
	case FS_WHATIF_PROTO_UDP:  return "UDP";
	case FS_WHATIF_PROTO_ICMP: return _("ICMP");
	case FS_WHATIF_PROTO_ANY:
	default:                   return q->port != 0 ? _("TCP or UDP")
	                                               : _("Any protocol");
	}
}

/* "port 22 · SSH", "ping", "any port". */
static gchar *
service_words (const FsWhatIfQuery *q)
{
	if (q->protocol == FS_WHATIF_PROTO_ICMP || q->icmp_type != NULL)
		return g_strdup (proto_words (q));
	if (q->port == 0)
		return g_strdup (_("any port"));
	if (q->service != NULL)
		return g_strdup_printf (_("port %u · %s"), q->port, q->service);
	return g_strdup_printf (_("port %u"), q->port);
}

static const gchar *
live_words (FsWhatIfLive live)
{
	switch (live) {
	case FS_WHATIF_LIVE_YES:    return _("Live: the firewall runs it");
	case FS_WHATIF_LIVE_HELD:   return _("Saved, applies on hold");
	case FS_WHATIF_LIVE_FAILED: return _("Saved, the last apply failed");
	case FS_WHATIF_LIVE_STALE:  return _("Changed since the last apply");
	case FS_WHATIF_LIVE_UNKNOWN:
	default:                    return _("No record that it was applied");
	}
}

static const gchar *
origin_words (FsWhatIfOrigin origin)
{
	switch (origin) {
	case FS_WHATIF_ORIGIN_DEFAULT:  return _("Default");
	case FS_WHATIF_ORIGIN_POLICY:   return _("Your policy");
	case FS_WHATIF_ORIGIN_SENTINEL: return _("Sentinel");
	case FS_WHATIF_ORIGIN_SETTINGS: return _("Preferences");
	case FS_WHATIF_ORIGIN_BUILTIN:  return _("Built in");
	case FS_WHATIF_ORIGIN_STOPPED:  return _("Firewall off");
	default:                        return "";
	}
}

static const gchar *
rule_kind_words (FsRuleKind kind)
{
	switch (kind) {
	case FS_RULE_INBOUND_ALLOW_FROM:     return _("Allow connections from host");
	case FS_RULE_INBOUND_ALLOW_SERVICE:  return _("Allow inbound service");
	case FS_RULE_INBOUND_FORWARD:        return _("Forward service");
	case FS_RULE_OUTBOUND_ALLOW_TO:      return _("Allow connections to host");
	case FS_RULE_OUTBOUND_ALLOW_FROM:    return _("Allow outbound from host");
	case FS_RULE_OUTBOUND_ALLOW_SERVICE: return _("Allow outbound service");
	case FS_RULE_OUTBOUND_DENY_TO:       return _("Deny connections to host");
	case FS_RULE_OUTBOUND_DENY_FROM:     return _("Deny outbound from host");
	case FS_RULE_OUTBOUND_DENY_SERVICE:  return _("Deny outbound service");
	default:                             return _("Policy");
	}
}

/* The question in plain words, both directions at once. */
static gchar *
both_ways_title (const FsWhatIfQuery *q)
{
	gchar *svc = service_words (q);
	gchar *t;

	if (q->protocol == FS_WHATIF_PROTO_ICMP || q->icmp_type != NULL)
		t = g_strdup_printf (_("%s between this computer and %s"), svc,
		                     q->host != NULL ? q->host : _("any host"));
	else
		t = g_strdup_printf (_("%s %s between this computer and %s"),
		                     proto_words (q), svc,
		                     q->host != NULL ? q->host : _("any host"));
	g_free (svc);
	return t;
}

/* =====================================================================
 * Content: the header
 * ===================================================================== */

/* The action handler, with a pointer that stays valid for the call. */
static void
run_action (Win *win, const FsWhatIfAction *act)
{
	FsWhatIfResult *keep = win->result;

	if (win->func == NULL || act == NULL)
		return;
	/* win->result may be replaced (and its free deferred) inside. */
	win->func (win->dialog, keep, act, win->func_data);
}

static void
on_action_clicked (GtkButton *btn, gpointer data)
{
	Win *win = data;
	const FsWhatIfAction *act = g_object_get_data (G_OBJECT (btn),
	                                               "fs-wi-action");

	run_action (win, act);
}

/* A rule name in the trace: open that row on the Policy page. */
static void
on_rule_link_clicked (GtkButton *btn, gpointer data)
{
	Win *win = data;
	FsWhatIfAction act;

	memset (&act, 0, sizeof act);
	act.kind = FS_WHATIF_ACT_OPEN_RULE;
	act.policy_kind = GPOINTER_TO_INT (
		g_object_get_data (G_OBJECT (btn), "fs-wi-kind"));
	act.policy_index = GPOINTER_TO_INT (
		g_object_get_data (G_OBJECT (btn), "fs-wi-index"));
	act.label = (gchar *) gtk_widget_get_tooltip_text (GTK_WIDGET (btn));
	act.verified = TRUE;
	run_action (win, &act);
	g_free (act.label);
}

static GtkWidget *
build_header (Win *win)
{
	const FsWhatIfResult *r = win->result;
	FsWhatIfVerdict v = (r != NULL) ? r->verdict : FS_WHATIF_ERROR;
	GtkWidget *hero = gtk_box_new (GTK_ORIENTATION_VERTICAL, 10);
	GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 14);
	GtkWidget *col = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
	GtkWidget *badge = fs_simviz_badge_new (v);
	GtkWidget *title;
	gchar *typed;
	gchar *t;

	add_class (hero, "fs-wi-hero");
	add_class (hero, v == FS_WHATIF_ERROR ? NULL : verdict_class (v));
	gtk_widget_set_name (hero, "whatif-window-header");
	add_class (badge, "big");
	gtk_widget_set_valign (badge, GTK_ALIGN_START);
	gtk_widget_set_margin_top (badge, 2);
	gtk_box_pack_start (GTK_BOX (row), badge, FALSE, FALSE, 0);

	if (fs_simviz_outcome_of (r) == FS_SIMVIZ_ERROR)
		t = g_strdup (_("StockFW could not read this question"));
	else if (r->answers->len > 1)
		t = both_ways_title (r->query);
	else
		t = g_strdup (((FsWhatIfAnswer *)
		               g_ptr_array_index (r->answers, 0))->probe);
	title = text_label (t, "fs-wi-title", NULL, TRUE);
	gtk_label_set_selectable (GTK_LABEL (title), FALSE);
	gtk_box_pack_start (GTK_BOX (col), title, FALSE, FALSE, 0);
	g_free (t);

	if (win->typed != NULL && *win->typed != '\0') {
		typed = g_strdup_printf (_("You typed: “%s”"), win->typed);
		gtk_box_pack_start (GTK_BOX (col),
		                    text_label (typed, "fs-wi-sub", NULL, TRUE),
		                    FALSE, FALSE, 0);
		g_free (typed);
	}
	gtk_box_pack_start (GTK_BOX (row), col, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (hero), row, FALSE, FALSE, 0);

	/* The answer in one paragraph: the engine's own summary. */
	if (r != NULL) {
		const gchar *line = (fs_simviz_outcome_of (r) == FS_SIMVIZ_ERROR)
		                    ? (r->error != NULL ? r->error : r->summary)
		                    : r->summary;

		if (line != NULL)
			gtk_box_pack_start (GTK_BOX (hero),
			                    text_label (line, "fs-wi-text", NULL,
			                                TRUE),
			                    FALSE, FALSE, 0);
	}

	/* What the answer rests on that is not the firewall as it runs. */
	if (fs_simviz_outcome_of (r) != FS_SIMVIZ_ERROR) {
		GString *warn = g_string_new (NULL);

		if (r->stopped_decides) {
			/* Right now nothing is filtered; what the saved policy
			 * says is only what happens once it runs. */
			g_string_append_printf (warn,
				_("Firewall off: %s right now, because nothing is "
				  "filtered. With the saved policy, once it runs: %s."),
				fs_whatif_verdict_name (r->verdict),
				fs_whatif_verdict_name (r->verdict_running));
			if (win->live == FS_WHATIF_LIVE_HELD ||
			    win->live == FS_WHATIF_LIVE_FAILED ||
			    win->live == FS_WHATIF_LIVE_STALE)
				g_string_append_printf (warn,
					_(" Starting it may not load that policy: %s."),
					win->live == FS_WHATIF_LIVE_HELD
					? _("applies are on hold")
					: win->live == FS_WHATIF_LIVE_FAILED
					? _("the last apply failed")
					: _("it changed after it was last applied"));
		} else if (win->live == FS_WHATIF_LIVE_HELD ||
		           win->live == FS_WHATIF_LIVE_FAILED ||
		           win->live == FS_WHATIF_LIVE_STALE) {
			g_string_append_printf (warn,
				_("This answer describes the saved policy, and the "
				  "firewall is not running it yet: %s."),
				win->live == FS_WHATIF_LIVE_HELD
				? _("applies are on hold")
				: win->live == FS_WHATIF_LIVE_FAILED
				? _("the last apply failed")
				: _("it changed after it was last applied"));
		}
		if (warn->len > 0) {
			GtkWidget *strip = text_label (warn->str, "fs-wi-strip",
			                               NULL, TRUE);

			gtk_widget_set_name (strip, "whatif-window-honesty");
			gtk_box_pack_start (GTK_BOX (hero), strip, FALSE, FALSE, 0);
		}
		g_string_free (warn, TRUE);
	}

	return hero;
}

/* =====================================================================
 * Content: one direction's page
 * ===================================================================== */

/* Fills the device cards of a page from the question and direction. */
static void
page_fill_devices (Page *pg, const FsWhatIfQuery *q)
{
	const gchar *host = q->host;
	gchar *svc = service_words (q);
	FsSimvizZone zone = fs_simviz_zone_of (host);
	const gchar *remote_title = fs_simviz_zone_title (host);
	const gchar *remote_sub = host != NULL ? host : _("any address");

	if (pg->answer->inbound) {
		pg->left_title = g_strdup (remote_title);
		pg->left_sub = g_strdup (remote_sub);
		pg->left_zone = zone;
		pg->right_title = g_strdup (_("This computer"));
		pg->right_sub = NULL;
		pg->right_extra = svc;
		svc = NULL;
		pg->right_zone = FS_SIMVIZ_ZONE_THIS;
	} else {
		pg->left_title = g_strdup (_("This computer"));
		pg->left_zone = FS_SIMVIZ_ZONE_THIS;
		pg->right_title = g_strdup (remote_title);
		pg->right_sub = g_strdup (remote_sub);
		pg->right_extra = svc;
		svc = NULL;
		pg->right_zone = zone;
	}
	g_free (svc);
}

static void
on_replay_clicked (GtkButton *btn, gpointer data)
{
	(void) btn;
	start_play (data);
}

static GtkWidget *
build_diagram (Win *win, Page *pg)
{
	GtkWidget *card = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	GtkWidget *overlay = gtk_overlay_new ();
	GtkWidget *area = gtk_drawing_area_new ();
	gchar *a11y;

	add_class (card, "fs-wi-card");
	add_class (card, "diagram");

	pg->area = area;
	gtk_widget_set_size_request (area, 560, 210);
	gtk_widget_set_hexpand (area, TRUE);
	g_signal_connect (area, "draw", G_CALLBACK (on_draw), pg);
	gtk_container_add (GTK_CONTAINER (overlay), area);

	a11y = g_strdup_printf (_("Diagram: %s, %s"),
	                        pg->answer->probe,
	                        fs_whatif_verdict_name (pg->answer->verdict));
	set_a11y_name (area, a11y);
	g_free (a11y);

	/* Replay: a small round button over the diagram.  With animations
	 * off there is nothing to replay. */
	if (win->animate) {
		GtkWidget *btn = gtk_button_new_from_icon_name (
			"media-playlist-repeat", GTK_ICON_SIZE_SMALL_TOOLBAR);

		add_class (btn, "fs-wi-iconbtn");
		gtk_widget_set_tooltip_text (btn, _("Replay"));
		set_a11y_name (btn, _("Replay the animation"));
		gtk_widget_set_name (btn, "whatif-replay");
		gtk_widget_set_halign (btn, GTK_ALIGN_END);
		gtk_widget_set_valign (btn, GTK_ALIGN_START);
		gtk_widget_set_margin_top (btn, 10);
		gtk_widget_set_margin_end (btn, 10);
		g_signal_connect (btn, "clicked", G_CALLBACK (on_replay_clicked),
		                  win);
		gtk_overlay_add_overlay (GTK_OVERLAY (overlay), btn);
		pg->replay = btn;
	}

	gtk_box_pack_start (GTK_BOX (card), overlay, FALSE, FALSE, 0);
	return card;
}

static void
grid_fact (GtkWidget *grid, gint col, gint row, const gchar *caption,
           const gchar *value)
{
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	GtkWidget *v = text_label (value, "fs-wi-value", NULL, TRUE);

	gtk_label_set_max_width_chars (GTK_LABEL (v), 36);
	gtk_label_set_selectable (GTK_LABEL (v), TRUE);
	gtk_widget_set_can_focus (v, FALSE);
	gtk_box_pack_start (GTK_BOX (box),
	                    text_label (caption, "fs-wi-caption", NULL, FALSE),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (box), v, FALSE, FALSE, 0);
	gtk_widget_set_hexpand (box, TRUE);
	gtk_grid_attach (GTK_GRID (grid), box, col, row, 1, 1);
}

static GtkWidget *
build_facts (Win *win, Page *pg)
{
	const FsWhatIfQuery *q = win->result->query;
	gboolean in = pg->answer->inbound;
	GtkWidget *card = card_new (_("The connection"), NULL);
	GtkWidget *grid = gtk_grid_new ();
	gchar *from, *to, *port, *profile = NULL;
	const gchar *host_words;
	gint row = 0;

	gtk_grid_set_column_spacing (GTK_GRID (grid), 24);
	gtk_grid_set_row_spacing (GTK_GRID (grid), 12);
	gtk_grid_set_column_homogeneous (GTK_GRID (grid), TRUE);
	gtk_widget_set_name (grid, "whatif-facts");

	host_words = q->host != NULL ? q->host : _("any host");
	if (q->host != NULL) {
		gchar *where = g_strdup_printf ("%s (%s)", q->host,
		                                fs_simviz_zone_title (q->host));
		from = in ? where : g_strdup (_("This computer"));
		to = in ? g_strdup (_("This computer")) : where;
	} else {
		from = g_strdup (in ? host_words : _("This computer"));
		to = g_strdup (in ? _("This computer") : host_words);
	}
	if (q->protocol == FS_WHATIF_PROTO_ICMP || q->icmp_type != NULL)
		port = g_strdup (_("None: ICMP has no ports"));
	else if (q->port == 0)
		port = g_strdup (_("Any port"));
	else if (q->service != NULL)
		port = g_strdup_printf ("%u (%s)", q->port, q->service);
	else
		port = g_strdup_printf ("%u", q->port);

	grid_fact (grid, 0, row, _("Direction"),
	           in ? _("Inbound: to this computer")
	              : _("Outbound: from this computer"));
	grid_fact (grid, 1, row++, _("Protocol"), proto_words (q));
	grid_fact (grid, 0, row, _("From"), from);
	grid_fact (grid, 1, row++, _("To"), to);
	grid_fact (grid, 0, row, _("Port / service"), port);
	grid_fact (grid, 1, row++, _("Firewall model"),
	           win->platform == FS_WHATIF_WINDOWS_BLOCK_WINS
	           ? _("Windows Firewall: any matching block wins")
	           : _("Linux iptables: the first matching rule decides"));

	if (win->platform == FS_WHATIF_WINDOWS_BLOCK_WINS) {
		GString *s = g_string_new (NULL);

		for (gint p = 0; p < FS_PROFILE_COUNT; p++) {
			if (win->profiles_in_use != 0 &&
			    (win->profiles_in_use & FS_PROFILE_BIT (p)) == 0)
				continue;
			if (s->len > 0)
				g_string_append (s, ", ");
			g_string_append (s, fs_profile_name (p));
			if (win->profile_enabled[p] == 0)
				g_string_append (s, _(" (off)"));
		}
		if (win->profiles_in_use == 0)
			g_string_append (s, _(": not known which is in use, so "
			                      "every one was considered"));
		else
			g_string_append (s, _(" (in use)"));
		profile = g_string_free (s, FALSE);
	}

	grid_fact (grid, 0, row,
	           win->platform == FS_WHATIF_WINDOWS_BLOCK_WINS
	           ? _("Network profile") : _("Firewall"),
	           win->platform == FS_WHATIF_WINDOWS_BLOCK_WINS
	           ? profile
	           : win->firewall == FS_WHATIF_FW_STOPPED ? _("Not running")
	           : win->firewall == FS_WHATIF_FW_RUNNING ? _("Running")
	           : _("Not known (assumed running)"));
	grid_fact (grid, 1, row++, _("Saved policy"),
	           !win->have_ctx ? _("Not known")
	           : (win->live == FS_WHATIF_LIVE_YES &&
	              win->firewall == FS_WHATIF_FW_STOPPED)
	           ? _("Last applied, but the firewall is stopped")
	           : live_words (win->live));
	if (win->platform == FS_WHATIF_WINDOWS_BLOCK_WINS)
		grid_fact (grid, 0, row++, _("Firewall"),
		           win->firewall == FS_WHATIF_FW_STOPPED ? _("Not running")
		           : win->firewall == FS_WHATIF_FW_RUNNING ? _("Running")
		           : _("Not known (assumed running)"));

	gtk_box_pack_start (GTK_BOX (card), grid, FALSE, FALSE, 4);
	g_free (from);
	g_free (to);
	g_free (port);
	g_free (profile);
	return card;
}

/* A folded run of rules: while folded, its rows are hidden outright,
 * so Tab does not walk through rows nobody can see. */
static void
on_fold_expanded (GObject *exp, GParamSpec *pspec, gpointer data)
{
	GtkWidget *inner = data;

	(void) pspec;
	if (gtk_expander_get_expanded (GTK_EXPANDER (exp))) {
		gtk_widget_set_no_show_all (inner, FALSE);
		gtk_widget_show_all (inner);
	} else {
		gtk_widget_hide (inner);
		gtk_widget_set_no_show_all (inner, TRUE);
	}
}

/* The scroller the window's body sits in, scrolled to the top: a new
 * answer, or a status line (which is the body's first row), is read
 * from there. */
static void
scroll_to_top (Win *win)
{
	GtkWidget *sw = gtk_widget_get_ancestor (win->body,
	                                         GTK_TYPE_SCROLLED_WINDOW);
	GtkAdjustment *adj;

	if (sw == NULL)
		return;
	adj = gtk_scrolled_window_get_vadjustment (GTK_SCROLLED_WINDOW (sw));
	gtk_adjustment_set_value (adj, gtk_adjustment_get_lower (adj));
}

/* One step of the trace, numbered as the user counts them. */
static GtkWidget *
build_step (Win *win, Page *pg, guint i, guint number,
            const FsWhatIfStep *st)
{
	gboolean decides = ((gint) i == pg->answer->decided_by);
	gboolean has_rule = (st->rule != NULL && *st->rule != '\0');
	GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
	GtkWidget *col = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	GtkWidget *num;
	GtkWidget *title;
	GtkWidget *tag = NULL;
	gchar *n = g_strdup_printf ("%u", number);
	gchar *detail;

	add_class (row, "fs-wi-step");
	if (st->kind == FS_WHATIF_STEP_SKIPPED)
		add_class (row, "skipped");
	if (decides) {
		add_class (row, "decides");
		add_class (row, pg->answer->verdict == FS_WHATIF_DEPENDS ? "warn"
		                : st->allows ? "ok" : "bad");
		gtk_widget_set_name (row, "whatif-decides");
	}

	num = gtk_label_new (n);
	add_class (num, "fs-wi-stepnum");
	gtk_widget_set_valign (num, GTK_ALIGN_START);
	gtk_box_pack_start (GTK_BOX (row), num, FALSE, FALSE, 0);
	g_free (n);

	title = text_label (has_rule ? st->rule : st->detail, "fs-wi-rule", NULL,
	                    TRUE);
	gtk_box_pack_start (GTK_BOX (col), title, FALSE, FALSE, 0);

	if (has_rule && st->detail != NULL) {
		detail = g_strdup_printf ("%s · %s",
		                          origin_words (st->origin), st->detail);
		gtk_box_pack_start (GTK_BOX (col),
		                    text_label (detail, "fs-wi-detail", NULL, TRUE),
		                    FALSE, FALSE, 0);
		g_free (detail);
	}

	/* A policy row: a link to it on the Policy page. */
	if (has_rule && st->policy_kind >= 0 && st->policy_index >= 0 &&
	    win->func != NULL) {
		GtkWidget *link = gtk_button_new_with_label (_("Open in Policy"));
		gchar *tip = g_strdup_printf (_("Open rule '%s'"), st->rule);

		add_class (link, "fs-wi-link");
		gtk_button_set_relief (GTK_BUTTON (link), GTK_RELIEF_NONE);
		gtk_widget_set_halign (link, GTK_ALIGN_START);
		gtk_widget_set_tooltip_text (link, tip);
		set_a11y_name (link, tip);
		g_object_set_data (G_OBJECT (link), "fs-wi-kind",
		                   GINT_TO_POINTER (st->policy_kind));
		g_object_set_data (G_OBJECT (link), "fs-wi-index",
		                   GINT_TO_POINTER (st->policy_index));
		g_signal_connect (link, "clicked",
		                  G_CALLBACK (on_rule_link_clicked), win);
		gtk_box_pack_start (GTK_BOX (col), link, FALSE, FALSE, 0);
		g_free (tip);
	}
	gtk_box_pack_start (GTK_BOX (row), col, TRUE, TRUE, 0);

	if (decides)
		tag = gtk_label_new (_("DECIDES"));
	else if (st->kind == FS_WHATIF_STEP_MATCHED)
		tag = gtk_label_new (_("matches"));
	else if (st->kind == FS_WHATIF_STEP_SKIPPED)
		tag = gtk_label_new (_("no match"));
	if (tag != NULL) {
		add_class (tag, "fs-wi-tag");
		if (decides || st->kind == FS_WHATIF_STEP_MATCHED)
			add_class (tag, pg->answer->verdict == FS_WHATIF_DEPENDS &&
			                decides ? "warn" : st->allows ? "ok" : "bad");
		gtk_widget_set_valign (tag, GTK_ALIGN_START);
		gtk_box_pack_end (GTK_BOX (row), tag, FALSE, FALSE, 0);
	}

	return row;
}

static GtkWidget *
build_why (Win *win, Page *pg)
{
	const FsWhatIfAnswer *a = pg->answer;
	GtkWidget *card = card_new (_("Why"),
		win->platform == FS_WHATIF_WINDOWS_BLOCK_WINS
		? _("Windows Firewall checks every rule: a matching block wins "
		    "over any allow, and with neither the profile's default "
		    "decides.")
		: _("StockFW checked these rules in order; the first one that "
		    "matches decides."));
	GtkWidget *list = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);

	gtk_widget_set_name (card, "whatif-why");

	/* It depends: each case and what decides it, before the trace of
	 * the one case it follows. */
	if (a->verdict == FS_WHATIF_DEPENDS && a->cases != NULL &&
	    a->cases->len > 0) {
		GtkWidget *cases = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);

		gtk_box_pack_start (GTK_BOX (cases),
		                    text_label (_("It depends on what the line "
		                                  "left open:"),
		                                "fs-wi-text", NULL, TRUE),
		                    FALSE, FALSE, 0);
		for (guint i = 0; i < a->cases->len; i++) {
			const FsWhatIfCase *c = g_ptr_array_index (a->cases, i);
			GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
			GtkWidget *b = fs_simviz_badge_new (c->verdict);
			gchar *t = (c->rule != NULL && *c->rule != '\0')
				? g_strdup_printf (_("%s: by '%s'"), c->condition,
				                   c->rule)
				: g_strdup_printf (_("%s: by the default"),
				                   c->condition);

			gtk_widget_set_valign (b, GTK_ALIGN_START);
			gtk_box_pack_start (GTK_BOX (row), b, FALSE, FALSE, 0);
			gtk_box_pack_start (GTK_BOX (row),
			                    text_label (t, "fs-wi-case", NULL, TRUE),
			                    TRUE, TRUE, 0);
			gtk_box_pack_start (GTK_BOX (cases), row, FALSE, FALSE, 0);
			g_free (t);
		}
		gtk_box_pack_start (GTK_BOX (card), cases, FALSE, FALSE, 4);
	}

	/* The trace.  A note the engine left without a rule (which case
	 * it followed) is a caption, not a numbered step; a long run of
	 * rules that did not match folds away so the one that decided is
	 * in view, still numbered as the firewall checks them. */
	{
		guint number = 0;
		guint i = 0;

		while (i < a->steps->len) {
			const FsWhatIfStep *st = g_ptr_array_index (a->steps, i);
			guint run = 0;

			if (st->kind == FS_WHATIF_STEP_NOTE &&
			    (st->rule == NULL || *st->rule == '\0')) {
				gchar *t = g_strdup (st->detail != NULL ? st->detail
				                                        : "");
				GtkWidget *l;

				if (t[0] != '\0')
					t[0] = g_ascii_toupper (t[0]);
				l = text_label (t, "fs-wi-muted", "fs-wi-note", TRUE);
				gtk_widget_set_margin_bottom (l, 6);
				gtk_box_pack_start (GTK_BOX (list), l, FALSE, FALSE, 0);
				g_free (t);
				i++;
				continue;
			}

			while (i + run < a->steps->len &&
			       (gint) (i + run) != a->decided_by &&
			       ((const FsWhatIfStep *) g_ptr_array_index (
			            a->steps, i + run))->kind ==
			       FS_WHATIF_STEP_SKIPPED)
				run++;

			if (run >= 3) {
				GtkWidget *inner = gtk_box_new (GTK_ORIENTATION_VERTICAL,
				                                2);
				gchar *t = g_strdup_printf (
					_("Rules %u to %u did not match"),
					number + 1, number + run);
				GtkWidget *exp = gtk_expander_new (t);

				add_class (exp, "fs-wi-fold");
				gtk_widget_set_name (exp, "whatif-skipped");
				for (guint k = 0; k < run; k++) {
					number++;
					gtk_box_pack_start (GTK_BOX (inner),
					                    build_step (win, pg, i + k, number,
					                                g_ptr_array_index (
					                                    a->steps, i + k)),
					                    FALSE, FALSE, 0);
				}
				gtk_widget_set_margin_top (inner, 4);
				gtk_widget_set_no_show_all (inner, TRUE);
				gtk_widget_set_name (inner, "whatif-skipped-rows");
				g_signal_connect (exp, "notify::expanded",
				                  G_CALLBACK (on_fold_expanded), inner);
				gtk_container_add (GTK_CONTAINER (exp), inner);
				gtk_box_pack_start (GTK_BOX (list), exp, FALSE, FALSE, 2);
				g_free (t);
				i += run;
				continue;
			}

			number++;
			gtk_box_pack_start (GTK_BOX (list),
			                    build_step (win, pg, i, number, st),
			                    FALSE, FALSE, 0);
			i++;
		}
	}
	gtk_box_pack_start (GTK_BOX (card), list, FALSE, FALSE, 4);
	return card;
}

/* The button for an action, or NULL when it may not run: a change
 * that was not checked (CREATE_*, LIFT_SENTINEL, START_FIREWALL) gets
 * no button.  Opening a rule or the Preferences and applying the
 * saved policy change nothing the engine has to check. */
static GtkWidget *
action_button (Win *win, const FsWhatIfAction *act)
{
	GtkWidget *btn;
	gchar *label = NULL;
	const gchar *cls = "btn-subtle";

	switch (act->kind) {
	case FS_WHATIF_ACT_CREATE_ALLOW:
		if (!act->verified || act->row == NULL)
			return NULL;
		/* Opening a port to every address is offered, never
		 * suggested: no primary style, and the button says so. */
		if (fs_util_target_is_anyone (act->row->target)) {
			label = g_strdup (_("Create allow rule for everyone"));
			cls = "btn-subtle";
		} else {
			label = g_strdup (_("Create allow rule"));
			cls = "btn-primary";
		}
		break;
	case FS_WHATIF_ACT_CREATE_BLOCK:
		if (!act->verified || act->row == NULL)
			return NULL;
		label = g_strdup (_("Create block rule"));
		cls = "btn-primary";
		break;
	case FS_WHATIF_ACT_OPEN_RULE:
		label = g_strdup (_("Open rule in Policy"));
		break;
	case FS_WHATIF_ACT_LIFT_SENTINEL:
		if (!act->verified)
			return NULL;
		if (act->expires_unix > 0) {
			gint64 now = g_get_real_time () / G_USEC_PER_SEC;
			GDateTime *at = g_date_time_new_from_unix_local (
				act->expires_unix);
			gchar *hhmm = at != NULL ? g_date_time_format (at, "%H:%M")
			                         : NULL;

			label = (act->expires_unix > now && hhmm != NULL)
				? g_strdup_printf (_("Lift Sentinel block (it ends by "
				                     "itself at %s)"), hhmm)
				: g_strdup (_("Lift Sentinel block (ending now)"));
			g_free (hhmm);
			if (at != NULL)
				g_date_time_unref (at);
		} else {
			label = g_strdup (_("Lift Sentinel block"));
		}
		cls = "btn-primary";
		break;
	case FS_WHATIF_ACT_OPEN_ICMP_SETTINGS:
		label = g_strdup (_("Open ICMP settings"));
		break;
	case FS_WHATIF_ACT_OPEN_SETTINGS:
		label = g_strdup (_("Open Protection settings"));
		break;
	case FS_WHATIF_ACT_START_FIREWALL:
		if (!act->verified)
			return NULL;
		label = g_strdup (act->label != NULL ? act->label
		                                     : _("Start the firewall"));
		cls = "btn-primary";
		break;
	case FS_WHATIF_ACT_APPLY_POLICY:
		label = g_strdup (_("Apply policy"));
		break;
	default:
		return NULL;
	}

	btn = gtk_button_new_with_label (label);
	add_class (btn, cls);
	gtk_widget_set_valign (btn, GTK_ALIGN_START);
	set_a11y_name (btn, act->label != NULL ? act->label : label);
	g_object_set_data (G_OBJECT (btn), "fs-wi-action", (gpointer) act);
	g_signal_connect (btn, "clicked", G_CALLBACK (on_action_clicked), win);
	g_free (label);
	return btn;
}

/* Why nothing is offered, in one or two sentences. */
static gchar *
no_action_words (Win *win, const Page *pg)
{
	const FsWhatIfAnswer *a = pg->answer;
	const FsWhatIfQuery *q = win->result->query;
	FsWhatIfVerdict want = (q->verb == FS_WHATIF_VERB_BLOCK)
	                       ? FS_WHATIF_BLOCKED : FS_WHATIF_ALLOWED;

	if (a->origin == FS_WHATIF_ORIGIN_STOPPED && want == FS_WHATIF_ALLOWED)
		return g_strdup_printf (
			_("Allowed only because the firewall is off. Once it runs, "
			  "the saved policy makes this %s."),
			fs_whatif_verdict_name (win->result->verdict_running));

	if (a->verdict == want)
		return g_strdup_printf (
			_("Nothing to change: this is already %s%s."),
			want == FS_WHATIF_ALLOWED ? _("allowed") : _("blocked"),
			q->verb != FS_WHATIF_VERB_NONE ? _(", as you asked") : "");

	if ((a->origin == FS_WHATIF_ORIGIN_POLICY ||
	     a->origin == FS_WHATIF_ORIGIN_SENTINEL ||
	     a->origin == FS_WHATIF_ORIGIN_SETTINGS) &&
	    a->rule != NULL && want == FS_WHATIF_ALLOWED)
		return g_strdup_printf (
			win->platform == FS_WHATIF_WINDOWS_BLOCK_WINS
			? _("Blocked by '%s'. An allow rule cannot override a block "
			    "on Windows: that block has to change.")
			: _("Blocked by '%s', which comes before any allow rule "
			    "StockFW could add: that block has to change."),
			a->rule);

	if (a->origin == FS_WHATIF_ORIGIN_BUILTIN && a->rule != NULL)
		return g_strdup_printf (
			_("'%s' is built in: StockFW keeps it so the computer keeps "
			  "working, and no rule or setting changes it."), a->rule);

	if (a->verdict == FS_WHATIF_DEPENDS)
		return g_strdup (
			_("No single change gives every case the answer you asked "
			  "for. The cases under Why show what decides each one."));

	return g_strdup (_("StockFW has no checked change to offer for this. "
	                   "Good to know, below, says what it considered."));
}

static GtkWidget *
build_actions (Win *win, Page *pg)
{
	const FsWhatIfAnswer *a = pg->answer;
	GtkWidget *card = card_new (_("What you can do"), NULL);
	guint shown = 0;

	gtk_widget_set_name (card, "whatif-actions");

	for (guint i = 0; i < a->actions->len; i++) {
		const FsWhatIfAction *act = g_ptr_array_index (a->actions, i);
		GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 16);
		GtkWidget *col = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
		GtkWidget *btn = action_button (win, act);

		add_class (row, "fs-wi-action");
		if (shown == 0)
			add_class (row, "first");

		gtk_box_pack_start (GTK_BOX (col),
		                    text_label (act->label, "fs-wi-rule", NULL,
		                                TRUE),
		                    FALSE, FALSE, 0);
		if (act->explanation != NULL)
			gtk_box_pack_start (GTK_BOX (col),
			                    text_label (act->explanation,
			                                "fs-wi-detail", NULL, TRUE),
			                    FALSE, FALSE, 0);

		/* The exact row a Create writes, as the Policy page shows it. */
		if (btn != NULL && act->row != NULL &&
		    (act->kind == FS_WHATIF_ACT_CREATE_ALLOW ||
		     act->kind == FS_WHATIF_ACT_CREATE_BLOCK)) {
			gchar *csv = fs_rule_to_csv (act->row);
			gchar *t = g_strdup_printf (_("Rule to add (%s):\n%s"),
			                            rule_kind_words (act->row->kind),
			                            csv);
			GtkWidget *code = text_label (t, "fs-wi-code", "fs-wi-mono",
			                              TRUE);

			gtk_widget_set_name (code, "whatif-create-row");
			gtk_label_set_selectable (GTK_LABEL (code), TRUE);
			gtk_widget_set_can_focus (code, FALSE);
			gtk_widget_set_margin_top (code, 4);
			gtk_box_pack_start (GTK_BOX (col), code, FALSE, FALSE, 0);
			g_free (t);
			g_free (csv);
		} else if (btn == NULL) {
			gtk_box_pack_start (GTK_BOX (col),
			                    text_label (_("Not offered: it was checked "
			                                  "and does not give the answer "
			                                  "you asked for."),
			                                "fs-wi-detail", NULL, TRUE),
			                    FALSE, FALSE, 0);
		}

		gtk_box_pack_start (GTK_BOX (row), col, TRUE, TRUE, 0);
		if (btn != NULL)
			gtk_box_pack_end (GTK_BOX (row), btn, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (card), row, FALSE, FALSE, 0);
		shown++;
	}

	if (shown == 0) {
		gchar *why = no_action_words (win, pg);
		GtkWidget *l = text_label (why, "fs-wi-muted", NULL, TRUE);

		gtk_widget_set_name (l, "whatif-no-action");
		gtk_box_pack_start (GTK_BOX (card), l, FALSE, FALSE, 0);
		g_free (why);
	}

	return card;
}

static GtkWidget *
build_page (Win *win, Page *pg, gboolean several)
{
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);

	/* With two directions the header carries the shared summary; each
	 * tab says its own answer first. */
	if (several && pg->answer->reason != NULL) {
		GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);

		gtk_box_pack_start (GTK_BOX (row),
		                    fs_simviz_badge_new (pg->answer->verdict),
		                    FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (row),
		                    text_label (pg->answer->probe, "fs-wi-rule",
		                                NULL, TRUE),
		                    TRUE, TRUE, 0);
		gtk_box_pack_start (GTK_BOX (box), row, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (box),
		                    text_label (pg->answer->reason, "fs-wi-text",
		                                NULL, TRUE),
		                    FALSE, FALSE, 0);
	}

	gtk_box_pack_start (GTK_BOX (box), build_diagram (win, pg),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (box), build_actions (win, pg),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (box), build_facts (win, pg),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (box), build_why (win, pg),
	                    FALSE, FALSE, 0);
	return box;
}

/* =====================================================================
 * Content: tabs, notes, the error state
 * ===================================================================== */
static void
on_tab_toggled (GtkToggleButton *btn, gpointer data)
{
	Win *win = data;
	guint index = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (btn),
	                                                   "fs-wi-index"));

	if (win->switching)
		return;
	/* A click on the tab already showing keeps it showing. */
	if (!gtk_toggle_button_get_active (btn)) {
		if (index == win->current) {
			win->switching = TRUE;
			gtk_toggle_button_set_active (btn, TRUE);
			win->switching = FALSE;
		}
		return;
	}
	fs_simviz_window_show_answer (win->dialog, index);
}

static GtkWidget *
build_tabs (Win *win)
{
	GtkWidget *seg = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);

	add_class (seg, "fs-wi-seg");
	add_class (seg, "linked");
	gtk_widget_set_halign (seg, GTK_ALIGN_START);
	gtk_widget_set_name (seg, "whatif-tabs");

	for (guint i = 0; i < win->pages->len; i++) {
		Page *pg = g_ptr_array_index (win->pages, i);
		gchar *t = g_strdup_printf ("%s: %s",
		                            pg->answer->inbound ? _("Inbound")
		                                                : _("Outbound"),
		                            fs_whatif_verdict_name (
		                                pg->answer->verdict));
		GtkWidget *b = gtk_toggle_button_new_with_label (t);

		set_a11y_name (b, t);
		g_object_set_data (G_OBJECT (b), "fs-wi-index",
		                   GUINT_TO_POINTER (i));
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (b), i == 0);
		g_signal_connect (b, "toggled", G_CALLBACK (on_tab_toggled), win);
		gtk_box_pack_start (GTK_BOX (seg), b, FALSE, FALSE, 0);
		g_ptr_array_add (win->tabs, b);
		g_free (t);
	}
	return seg;
}

static GtkWidget *
build_notes (Win *win)
{
	const FsWhatIfResult *r = win->result;
	GtkWidget *card;
	GtkWidget *list;

	if (r == NULL || r->notes == NULL || r->notes->len == 0)
		return NULL;

	card = card_new (_("Good to know"), NULL);
	gtk_widget_set_name (card, "whatif-notes");
	list = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
	for (guint i = 0; i < r->notes->len; i++) {
		GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
		GtkWidget *dot = gtk_label_new ("•");

		add_class (dot, "fs-wi-muted");
		gtk_widget_set_valign (dot, GTK_ALIGN_START);
		gtk_box_pack_start (GTK_BOX (row), dot, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (row),
		                    text_label (g_ptr_array_index (r->notes, i),
		                                "fs-wi-text", NULL, TRUE),
		                    TRUE, TRUE, 0);
		gtk_box_pack_start (GTK_BOX (list), row, FALSE, FALSE, 0);
	}
	gtk_box_pack_start (GTK_BOX (card), list, FALSE, FALSE, 0);
	return card;
}

static GtkWidget *
build_error (Win *win)
{
	GtkWidget *card = card_new (_("How to ask"),
		_("Name what the connection is about: a service, a port, a host "
		  "or a direction. For example:"));
	static const gchar *examples[] = {
		"Can 192.168.1.50 reach my SSH?",
		"Is outbound DNS to 8.8.8.8 allowed?",
		"block RDP from the internet",
		"allow tcp port 8443 inbound",
		"allow ping from 192.168.1.5",
		NULL
	};

	(void) win;
	gtk_widget_set_name (card, "whatif-error-help");
	for (guint i = 0; examples[i] != NULL; i++) {
		GtkWidget *l = text_label (examples[i], "fs-wi-mono", "fs-wi-text",
		                           FALSE);

		gtk_widget_set_margin_start (l, 8);
		gtk_box_pack_start (GTK_BOX (card), l, FALSE, FALSE, 0);
	}
	return card;
}

/* (Re)builds everything under the status strip from win->result. */
static void
build_content (Win *win)
{
	const FsWhatIfResult *r = win->result;
	GtkWidget *content = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);

	win->content = content;
	win->current = 0;
	win->tabs = g_ptr_array_new ();
	win->pages = g_ptr_array_new_with_free_func (page_free);

	gtk_box_pack_start (GTK_BOX (content), build_header (win),
	                    FALSE, FALSE, 0);

	if (fs_simviz_outcome_of (r) == FS_SIMVIZ_ERROR) {
		gtk_box_pack_start (GTK_BOX (content), build_error (win),
		                    FALSE, FALSE, 0);
	} else {
		gboolean several = (r->answers->len > 1);

		win->stack = gtk_stack_new ();
		gtk_stack_set_homogeneous (GTK_STACK (win->stack), FALSE);
		gtk_stack_set_transition_type (GTK_STACK (win->stack),
		                               GTK_STACK_TRANSITION_TYPE_NONE);

		for (guint i = 0; i < r->answers->len; i++) {
			Page *pg = g_new0 (Page, 1);
			gchar *name = g_strdup_printf ("answer-%u", i);

			pg->win = win;
			pg->index = i;
			pg->answer = g_ptr_array_index (r->answers, i);
			pg->outcome = fs_simviz_outcome_of_answer (pg->answer);
			pg->stopped = (pg->answer->origin == FS_WHATIF_ORIGIN_STOPPED);
			pg->wall_sub = g_strdup (
				pg->stopped ? _("not running: nothing is filtered")
				: win->platform == FS_WHATIF_WINDOWS_BLOCK_WINS
				? _("Windows Firewall: a block wins")
				: _("first matching rule decides"));
			page_fill_devices (pg, r->query);
			g_ptr_array_add (win->pages, pg);

			gtk_stack_add_named (GTK_STACK (win->stack),
			                     build_page (win, pg, several), name);
			g_free (name);
		}

		if (several)
			gtk_box_pack_start (GTK_BOX (content), build_tabs (win),
			                    FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (content), win->stack,
		                    FALSE, FALSE, 0);
	}

	{
		GtkWidget *notes = build_notes (win);

		if (notes != NULL)
			gtk_box_pack_start (GTK_BOX (content), notes, FALSE, FALSE, 0);
	}

	gtk_box_pack_start (GTK_BOX (win->body), content, FALSE, FALSE, 0);
	gtk_widget_show_all (content);
	if (win->stack != NULL)
		gtk_stack_set_visible_child_name (GTK_STACK (win->stack),
		                                  "answer-0");
}

static void
clear_content (Win *win)
{
	stop_play (win);
	if (win->content != NULL) {
		gtk_widget_destroy (win->content);
		win->content = NULL;
	}
	win->stack = NULL;
	g_clear_pointer (&win->tabs, g_ptr_array_unref);
	g_clear_pointer (&win->pages, g_ptr_array_unref);
}

static void
copy_typed (Win *win, const FsWhatIfResult *result, const gchar *typed)
{
	gchar *old = win->typed;

	if (typed == NULL && result != NULL && result->query != NULL)
		typed = result->query->text;
	win->typed = g_strdup (typed);
	g_free (old);
}

static void
copy_ctx (Win *win, const FsWhatIfContext *ctx)
{
	g_clear_pointer (&win->live_detail, g_free);
	win->have_ctx = (ctx != NULL);
	win->platform = ctx != NULL ? ctx->platform
	                            : fs_whatif_native_platform ();
	win->firewall = ctx != NULL ? ctx->firewall : FS_WHATIF_FW_UNKNOWN;
	win->profiles_in_use = ctx != NULL ? ctx->profiles_in_use : 0;
	for (gint p = 0; p < 3; p++)
		win->profile_enabled[p] = ctx != NULL ? ctx->profile_enabled[p] : -1;
	win->live = ctx != NULL ? ctx->live : FS_WHATIF_LIVE_UNKNOWN;
	if (ctx != NULL && ctx->live_detail != NULL)
		win->live_detail = g_strdup (ctx->live_detail);
}

static void
win_free (gpointer data)
{
	Win *win = data;

	stop_play (win);
	g_clear_pointer (&win->tabs, g_ptr_array_unref);
	g_clear_pointer (&win->pages, g_ptr_array_unref);
	if (win->result != NULL)
		fs_whatif_result_free (win->result);
	g_free (win->live_detail);
	g_free (win->typed);
	g_free (win);
}

static Win *
win_of (GtkWidget *window)
{
	return window != NULL
	       ? g_object_get_data (G_OBJECT (window), "fs-simviz-win") : NULL;
}

/* =====================================================================
 * The window
 * ===================================================================== */
static void
on_response (GtkDialog *dialog, gint response, gpointer data)
{
	(void) response;
	(void) data;
	gtk_widget_destroy (GTK_WIDGET (dialog));
}

/* Esc closes, whatever the theme does with key bindings. */
static gboolean
on_key_press (GtkWidget *widget, GdkEventKey *event, gpointer data)
{
	(void) data;

	if (event->keyval == GDK_KEY_Escape) {
		gtk_dialog_response (GTK_DIALOG (widget), GTK_RESPONSE_CLOSE);
		return TRUE;
	}
	return FALSE;
}

GtkWidget *
fs_simviz_window_new (FsWhatIfResult *result, const FsWhatIfContext *ctx,
                      const gchar *typed)
{
	Win *win = g_new0 (Win, 1);
	GtkWidget *dialog;
	GtkWidget *area;
	GtkWidget *scroller;
	GtkWidget *close;

	fs_simviz_install_css ();

	dialog = gtk_dialog_new ();
	win->dialog = dialog;
	win->result = result;
	win->animate = fs_simviz_animations_enabled ();
	copy_ctx (win, ctx);
	copy_typed (win, result, typed);
	g_object_set_data_full (G_OBJECT (dialog), "fs-simviz-win", win,
	                        win_free);

	gtk_window_set_title (GTK_WINDOW (dialog), _("What-If Simulation"));
	gtk_window_set_modal (GTK_WINDOW (dialog), FALSE);
	gtk_window_set_default_size (GTK_WINDOW (dialog), 760, 640);
	gtk_window_set_type_hint (GTK_WINDOW (dialog),
	                          GDK_WINDOW_TYPE_HINT_DIALOG);
	add_class (dialog, "fs-wi-dialog");
	add_class (dialog, "fs-wi-page");

	win->dark = theme_is_dark (dialog);
	if (win->dark)
		add_class (dialog, "fs-wi-dark");

	area = gtk_dialog_get_content_area (GTK_DIALOG (dialog));
	gtk_box_set_spacing (GTK_BOX (area), 0);
	gtk_container_set_border_width (GTK_CONTAINER (area), 0);

	scroller = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroller),
	                                GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scroller),
	                                     GTK_SHADOW_NONE);
	gtk_widget_set_vexpand (scroller, TRUE);
	gtk_widget_set_name (scroller, "whatif-scroller");
	gtk_box_pack_start (GTK_BOX (area), scroller, TRUE, TRUE, 0);

	win->body = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	add_class (win->body, "fs-wi-page");
	gtk_container_set_border_width (GTK_CONTAINER (win->body), 20);
	gtk_container_add (GTK_CONTAINER (scroller), win->body);

	win->status = text_label ("", "fs-wi-strip", NULL, TRUE);
	gtk_widget_set_name (win->status, "whatif-status");
	gtk_widget_set_no_show_all (win->status, TRUE);
	gtk_box_pack_start (GTK_BOX (win->body), win->status, FALSE, FALSE, 0);

	build_content (win);

	/* Close: a real action of the dialog, its default -- Enter presses
	 * it, Esc closes -- in the shell's primary style, which sets its
	 * own face (background-image: none), so no theme gradient can
	 * make it look disabled. */
	close = gtk_dialog_add_button (GTK_DIALOG (dialog), _("Close"),
	                               GTK_RESPONSE_CLOSE);
	add_class (close, "btn-primary");
	gtk_widget_set_name (close, "whatif-close");
	set_a11y_name (close, _("Close the What-If window"));
	gtk_dialog_set_default_response (GTK_DIALOG (dialog),
	                                 GTK_RESPONSE_CLOSE);

	g_signal_connect (dialog, "response", G_CALLBACK (on_response), NULL);
	g_signal_connect (dialog, "key-press-event", G_CALLBACK (on_key_press),
	                  NULL);

	gtk_widget_show_all (area);
	return dialog;
}

static gboolean
free_result_idle (gpointer data)
{
	fs_whatif_result_free (data);
	return G_SOURCE_REMOVE;
}

void
fs_simviz_window_set_result (GtkWidget *window, FsWhatIfResult *result,
                             const FsWhatIfContext *ctx, const gchar *typed)
{
	Win *win = win_of (window);
	FsWhatIfResult *old;

	if (win == NULL) {
		if (result != NULL)
			fs_whatif_result_free (result);
		return;
	}

	old = win->result;
	clear_content (win);
	win->result = result;
	copy_ctx (win, ctx);
	copy_typed (win, result, typed);
	fs_simviz_window_set_status (window, FS_SIMVIZ_STATUS_OK, NULL);
	build_content (win);
	scroll_to_top (win);
	if (gtk_widget_get_mapped (window)) {
		GtkWidget *close = gtk_dialog_get_widget_for_response (
			GTK_DIALOG (window), GTK_RESPONSE_CLOSE);
		GtkWidget *focus = gtk_window_get_focus (GTK_WINDOW (window));

		/* The button pressed went with the old content: keep the
		 * keyboard somewhere real. */
		if (close != NULL && (focus == NULL ||
		                      !gtk_widget_get_mapped (focus) ||
		                      gtk_widget_is_ancestor (focus, win->body)))
			gtk_widget_grab_focus (close);
		start_play (win);
	}

	/* An action handler may be running on the old result: let it
	 * finish before the result goes. */
	if (old != NULL && old != result)
		g_idle_add (free_result_idle, old);
}

const FsWhatIfResult *
fs_simviz_window_get_result (GtkWidget *window)
{
	Win *win = win_of (window);

	return win != NULL ? win->result : NULL;
}

void
fs_simviz_window_set_action_func (GtkWidget *window, FsSimvizActionFunc func,
                                  gpointer user_data)
{
	Win *win = win_of (window);

	if (win == NULL)
		return;
	win->func = func;
	win->func_data = user_data;

	/* The rule links in the trace exist only with a handler. */
	clear_content (win);
	build_content (win);
}

static gboolean
start_play_idle (gpointer data)
{
	GtkWidget *window = data;
	Win *win = win_of (window);

	if (win != NULL)
		start_play (win);
	g_object_unref (window);
	return G_SOURCE_REMOVE;
}

void
fs_simviz_window_present (GtkWidget *window, GtkWidget *parent)
{
	Win *win = win_of (window);
	GtkWidget *close;

	if (win == NULL)
		return;

	if (parent != NULL) {
		GtkWidget *top = gtk_widget_get_toplevel (parent);

		if (GTK_IS_WINDOW (top)) {
			gboolean dark = theme_is_dark (top);

			/* The window it opens from says which palette reads:
			 * the main window may be styled apart from the theme
			 * a new dialog would get. */
			if (dark != win->dark) {
				GtkStyleContext *sc =
					gtk_widget_get_style_context (window);

				win->dark = dark;
				if (dark)
					gtk_style_context_add_class (sc, "fs-wi-dark");
				else
					gtk_style_context_remove_class (sc, "fs-wi-dark");
				gtk_widget_queue_draw (window);
			}
			gtk_window_set_transient_for (GTK_WINDOW (window),
			                              GTK_WINDOW (top));
			gtk_window_set_destroy_with_parent (GTK_WINDOW (window),
			                                    TRUE);
			gtk_window_set_position (GTK_WINDOW (window),
			                         GTK_WIN_POS_CENTER_ON_PARENT);
		}
	}

	gtk_widget_show (window);
	close = gtk_dialog_get_widget_for_response (GTK_DIALOG (window),
	                                            GTK_RESPONSE_CLOSE);
	if (close != NULL)
		gtk_widget_grab_focus (close);
	gtk_window_present (GTK_WINDOW (window));
	g_idle_add (start_play_idle, g_object_ref (window));
}

void
fs_simviz_window_show_answer (GtkWidget *window, guint index)
{
	Win *win = win_of (window);
	gchar *name;

	if (win == NULL || win->stack == NULL || win->pages == NULL ||
	    index >= win->pages->len)
		return;

	win->current = index;
	name = g_strdup_printf ("answer-%u", index);
	gtk_stack_set_visible_child_name (GTK_STACK (win->stack), name);
	g_free (name);

	win->switching = TRUE;
	for (guint i = 0; win->tabs != NULL && i < win->tabs->len; i++)
		gtk_toggle_button_set_active (g_ptr_array_index (win->tabs, i),
		                              i == index);
	win->switching = FALSE;

	if (gtk_widget_get_mapped (window))
		start_play (win);
	else {
		Page *pg = current_page (win);

		if (pg != NULL)
			pg->state = fs_simviz_state_at (pg->outcome,
			                                FS_SIMVIZ_DURATION);
	}
}

guint
fs_simviz_window_get_answer (GtkWidget *window)
{
	Win *win = win_of (window);

	return win != NULL ? win->current : 0;
}

void
fs_simviz_window_set_status (GtkWidget *window, FsSimvizStatus level,
                             const gchar *text)
{
	Win *win = win_of (window);
	GtkStyleContext *style;

	if (win == NULL)
		return;

	style = gtk_widget_get_style_context (win->status);
	gtk_style_context_remove_class (style, "ok");
	gtk_style_context_remove_class (style, "bad");

	if (text == NULL || *text == '\0') {
		gtk_label_set_text (GTK_LABEL (win->status), "");
		gtk_widget_hide (win->status);
		return;
	}

	if (level == FS_SIMVIZ_STATUS_OK)
		gtk_style_context_add_class (style, "ok");
	else if (level == FS_SIMVIZ_STATUS_BAD)
		gtk_style_context_add_class (style, "bad");
	gtk_label_set_text (GTK_LABEL (win->status), text);
	gtk_widget_show (win->status);
	/* What an action did is said at the top: show it. */
	scroll_to_top (win);
}
