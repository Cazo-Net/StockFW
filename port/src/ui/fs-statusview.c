/*---[ fs-statusview.c ]------------------------------------------------
 * The Overview page (a status board since 2.0.0; the 1.0.7 Overview
 * and the Status page before it).
 *
 * Top to bottom, the answer first and the detail after it:
 *   header       "Overview", which machine and address, Lock policy
 *   board        one coloured card: the state in one large word
 *                ("Protected"), the sentences that explain it, the one
 *                button that changes it (Start or Stop), and four facts
 *                in a strip along its foot: IPv4, IPv6, the policy,
 *                the engine
 *   profiles     Windows only: the three firewall profiles, the ones
 *                in force marked "In use"
 *   traffic      a live graph of what the real adapters received and
 *                sent over the last two minutes
 *   programs     the five programs with the most open connections
 *   blocks       the last few blocked events; a row opens its details
 *   totals       events in and out (and how many were blocked), open
 *                connections, traffic now
 *   connections  open connections with a filter box; connections
 *                between two programs on this computer are hidden
 *                behind a "Show them" link, because no rule sees them.
 *                A row opens its details in the drawer
 *   adapters     real adapters; virtual ones (Docker bridges, Hyper-V,
 *                VPN tunnels) behind a "Show them" link
 *
 * Every number on the page is one the backend reported.  A backend
 * that cannot list connections or adapters gets no card for them (the
 * traffic card stays and says the counters are missing), and "Threat
 * intel" is not shown until it exists.
 *--------------------------------------------------------------------*/

#include "ui/fs-statusview.h"
#include "ui/fs-intelview.h"
#include "ui/fs-app.h"
#include "ui/fs-dialogs.h"
#include "ui/fs-drawer.h"
#include "ui/fs-hitview.h"
#include "ui/fs-icons.h"
#include "ui/fs-tray.h"
#include "ui/fs-policyview.h"
#include "core/fs-apply.h"
#include "core/fs-backend.h"
#include "core/fs-blocktally.h"
#include "core/fs-intel.h"
#include "core/fs-netplace.h"
#include "core/fs-util.h"
#include "core/fs-i18n.h"

#include <string.h>
#include <gdk-pixbuf/gdk-pixbuf.h>

#include "ui/fs-themecolor.h"

/* How often the live panels are resampled.  Interface counters are
 * cheap; enumerating sockets is dearer, so it runs less often. */
#define NET_REFRESH_MS    2000
#define CONN_REFRESH_MS   3000
/* The network place and the profile switches (Windows).  Moving from
 * home to a cafe is the change this catches, so seconds are plenty. */
#define PLACE_REFRESH_MS  5000

/* How many blocked events the Latest blocks card keeps. */
#define RECENT_MAX        5

/* The Traffic card: one point per network refresh, two minutes of them. */
#define TRAFFIC_POINTS    60

/* How many programs the Busiest programs card ranks. */
#define BUSY_MAX          5

/* UTF-8 spelled out, so the source stays ASCII. */
#define DOT   " \xc2\xb7 "     /* " . " middle dot */
#define DOWN  "\xe2\x86\x93 "  /* down arrow       */
#define UP    "\xe2\x86\x91 "  /* up arrow         */

static FsFirewallState current_state = FS_FW_NONE;

/* Set by the Lock toggle.  While TRUE the Policy page refuses to write
 * rules -- the lock is a real gate, not a label. */
static gboolean policy_locked = FALSE;

static FsPolicy *shared_policy = NULL;

static FsStatusChanged changed_cb = NULL;
static gpointer        changed_user = NULL;

/* The verdict, as last judged. */
static FsVerdict verdict_level = FS_VERDICT_UNKNOWN;
static gchar    *verdict_text = NULL;

/* IPv6, as last read from the backend.  ipv6_known is FALSE where the
 * backend has no ipv6_state slot (Windows Firewall applies every rule
 * to both families, so there is nothing to ask). */
static gboolean    ipv6_known = FALSE;
static FsIpv6State ipv6_st = FS_IPV6_UNKNOWN;
static gchar      *ipv6_detail = NULL;

/* Where this computer is connected and which profiles are in force
 * (Windows; NULL elsewhere), and which profile states could be read
 * (prof_known) and are on (prof_on), as FS_PROFILE_BIT masks.  A
 * profile in use that is off is a network with no firewall on it. */
static FsNetworkPlace *net_place = NULL;
static guint           prof_known = 0;
static guint           prof_on = 0;

/* ---- widgets ---- */
static GtkWidget *subtitle_label;
static gchar     *primary_where = NULL;   /* "eth0 . 192.168.1.20" */
static GtkWidget *lock_button, *lock_icon, *lock_label;

static GtkWidget *hero, *hero_icon, *hero_title, *hero_body;
/* The verdict's own short word ("Protected"), set large. */
static GtkWidget *state_word;
static GtkWidget *power_button, *power_icon, *power_label;

enum { TILE_IPV4, TILE_IPV6, TILE_POLICY, TILE_ENGINE, N_TILES };
static GtkWidget *tile_value[N_TILES];

/* Per-profile switches, used only when the backend supports them. */
static GtkWidget *profile_switches[FS_PROFILE_COUNT];
static GtkWidget *profile_in_use[FS_PROFILE_COUNT];
static GtkWidget *profiles_frame;

/* Events counters: [direction][total=0 serious=1]. */
static guint events[2][2];

enum { TOTAL_IN, TOTAL_OUT, TOTAL_CONN, TOTAL_TRAFFIC, N_TOTALS };
static GtkWidget *total_value[N_TOTALS];
static GtkWidget *total_note[N_TOTALS];
static GtkWidget *sparkline_area[N_TOTALS];

#define SPARK_POINTS 20
static gdouble spark_history[N_TOTALS][SPARK_POINTS];
static guint   spark_count[N_TOTALS] = { 0 };

static void
push_spark_value (gint which, gdouble val)
{
	if (which < 0 || which >= N_TOTALS)
		return;
	if (spark_count[which] < SPARK_POINTS) {
		spark_history[which][spark_count[which]++] = val;
	} else {
		for (guint j = 0; j < SPARK_POINTS - 1; j++)
			spark_history[which][j] = spark_history[which][j + 1];
		spark_history[which][SPARK_POINTS - 1] = val;
	}
	if (sparkline_area[which] != NULL)
		gtk_widget_queue_draw (sparkline_area[which]);
}

static gboolean
on_sparkline_draw (GtkWidget *widget, cairo_t *cr, gpointer data)
{
	gint which = GPOINTER_TO_INT (data);
	GtkAllocation alloc;
	guint count = spark_count[which];
	gdouble min_v = 0, max_v = 1;
	gdouble w, h;

	gtk_widget_get_allocation (widget, &alloc);
	w = (gdouble) alloc.width;
	h = (gdouble) alloc.height;
	if (w < 12 || h < 10)
		return FALSE;

	if (count < 2) {
		fs_theme_source (cr, "fs_border_strong", "#4a4545", 1.0);
		cairo_set_line_width (cr, 1.0);
		cairo_move_to (cr, 0, h - 2);
		cairo_line_to (cr, w, h - 2);
		cairo_stroke (cr);
		return FALSE;
	}

	min_v = spark_history[which][0];
	max_v = spark_history[which][0];
	for (guint i = 1; i < count; i++) {
		if (spark_history[which][i] < min_v) min_v = spark_history[which][i];
		if (spark_history[which][i] > max_v) max_v = spark_history[which][i];
	}
	if (max_v - min_v < 0.001) {
		max_v = min_v + 1.0;
	}

	/* Room at the right for the dot on the newest point. */
	w -= 5.0;

	/* The accent comes from the theme at each paint, so the line
	 * follows Dark mode and the accent the user chose.  The fill ends
	 * under the newest point, not at the widget's far corner. */
	fs_theme_source (cr, "fs_accent", "#5aa2ff", 0.10);
	cairo_move_to (cr, 0, h);
	for (guint i = 0; i < count; i++) {
		gdouble x = (gdouble) i / (gdouble) (SPARK_POINTS - 1) * w;
		gdouble norm = (spark_history[which][i] - min_v) / (max_v - min_v);
		gdouble y = h - 4 - norm * (h - 8);
		cairo_line_to (cr, x, y);
	}
	cairo_line_to (cr, (gdouble) (count - 1) / (gdouble) (SPARK_POINTS - 1) * w,
	               h);
	cairo_close_path (cr);
	cairo_fill (cr);

	fs_theme_source (cr, "fs_accent", "#5aa2ff", 1.0);
	cairo_set_line_width (cr, 2.0);
	cairo_set_line_cap (cr, CAIRO_LINE_CAP_ROUND);
	cairo_set_line_join (cr, CAIRO_LINE_JOIN_ROUND);

	for (guint i = 0; i < count; i++) {
		gdouble x = (gdouble) i / (gdouble) (SPARK_POINTS - 1) * w;
		gdouble norm = (spark_history[which][i] - min_v) / (max_v - min_v);
		gdouble y = h - 4 - norm * (h - 8);
		if (i == 0)
			cairo_move_to (cr, x, y);
		else
			cairo_line_to (cr, x, y);
	}
	cairo_stroke (cr);

	{
		gdouble x = (gdouble) (count - 1) / (gdouble) (SPARK_POINTS - 1) * w;
		gdouble norm = (spark_history[which][count - 1] - min_v) / (max_v - min_v);
		gdouble y = h - 4 - norm * (h - 8);

		fs_theme_source (cr, "fs_surface", "#211e1e", 1.0);
		cairo_arc (cr, x, y, 5.0, 0, 2 * 3.1415926535);
		cairo_fill (cr);

		fs_theme_source (cr, "fs_accent", "#5aa2ff", 1.0);
		cairo_arc (cr, x, y, 3.5, 0, 2 * 3.1415926535);
		cairo_fill (cr);
	}

	return FALSE;
}

/* Open connections. */
enum
{
	CONN_COL_ICON,
	CONN_COL_PROGRAM,
	CONN_COL_REMOTE,
	CONN_COL_PORT,
	CONN_COL_SERVICE,
	CONN_COL_DIRECTION,
	CONN_COL_LOCAL,        /* gboolean: both ends are this computer */
	/* Not shown in the list; the details drawer reads them. */
	CONN_COL_LOCAL_END,    /* this computer's address, and its port  */
	CONN_COL_STATE,        /* "ESTABLISHED"...; "" when not reported */
	CONN_N_COLS
};

static GtkListStore *conn_store;
static GtkTreeModel *conn_filter;
static GtkWidget    *connections_card;
static GtkWidget    *conn_search;
static GtkWidget    *conn_note;
static GtkWidget    *conn_toggle;
static gboolean      show_local = FALSE;
static guint         conn_total = 0;   /* rows in the last sample  */
static guint         conn_local = 0;   /* of which loopback-only   */

/* The owner token this page gives the drawer for a connection. */
static gint conn_drawer_owner;

/* Adapters. */
static GtkWidget  *adapters_card;
static GtkWidget  *adapters_list;
static GtkWidget  *adapters_note;
static GtkWidget  *adapters_toggle;
static gboolean    show_virtual = FALSE;
static GHashTable *net_samples = NULL;

/* Traffic: what the real adapters received and sent, in bytes per
 * second, oldest point first.  One point per network refresh.  Bytes
 * are counted into traffic_acc as they are read and turned into a
 * point when at least half a refresh period has passed, so a second
 * reading in between (the adapters card's "Show them") adds no point
 * and loses no byte. */
static guint64    traffic_rx[TRAFFIC_POINTS];
static guint64    traffic_tx[TRAFFIC_POINTS];
static guint      traffic_count = 0;
static gboolean   traffic_known = FALSE;    /* the backend has counters */
static gboolean   traffic_started = FALSE;  /* traffic_stamp is set     */
static gint64     traffic_stamp;
static guint64    traffic_acc_rx, traffic_acc_tx;
static GtkWidget *traffic_area;
static GtkWidget *traffic_legend;
static GtkWidget *traffic_rx_value, *traffic_tx_value;
static GtkWidget *traffic_note;

/* The page's clock, monotonic microseconds.  A test puts its own in
 * (fs_statusview_set_clock) so that a rate is a known number. */
static gint64 (*page_clock) (void) = NULL;

/* Busiest programs: the top few of the last connections sample. */
typedef struct
{
	GtkWidget *box;
	GtkWidget *name;
	GtkWidget *bar;
	GtkWidget *count;
} BusyRow;

static GtkWidget *busy_card;
static GtkWidget *busy_list;
static GtkWidget *busy_empty;
static BusyRow    busy_rows[BUSY_MAX];
static gchar     *busy_name[BUSY_MAX];
static guint      busy_count[BUSY_MAX];
static guint      busy_n = 0;

/* Latest blocks: newest at the head.  The event itself is kept, so a
 * row can open its details. */
typedef struct
{
	gchar *title;
	gchar *detail;
	FsHit *hit;
} RecentBlock;

/* The card has RECENT_MAX rows from the start and re-labels them as
 * blocks arrive: a row that was destroyed and built again on every
 * block would drop the pointer's hover and the keyboard's focus. */
typedef struct
{
	GtkWidget *button;
	GtkWidget *title;
	GtkWidget *detail;
} RecentRow;

static GQueue     recent = G_QUEUE_INIT;
static GtkWidget *recent_list;
static GtkWidget *recent_empty;
static RecentRow  recent_rows[RECENT_MAX];

/* The page's timers, removed when the page is destroyed. */
static guint net_timer = 0, conn_timer = 0, place_timer = 0;

/* Previous interface sample, so consecutive polls yield a rate. */
typedef struct
{
	guint64 received;
	guint64 sent;
	gint64  stamp;   /* monotonic microseconds */
} NetSample;

static void update_overview (void);

/* ------------------------------------------------------------ helpers */

static void
add_class (GtkWidget *widget, const gchar *klass)
{
	gtk_style_context_add_class (gtk_widget_get_style_context (widget),
	                             klass);
}

static void
swap_class (GtkWidget *widget, const gchar *const *all, const gchar *on)
{
	GtkStyleContext *ctx = gtk_widget_get_style_context (widget);

	for (guint i = 0; all[i] != NULL; i++)
		gtk_style_context_remove_class (ctx, all[i]);
	if (on != NULL)
		gtk_style_context_add_class (ctx, on);
}

static GtkWidget *
label_new (const gchar *text, const gchar *klass, gfloat xalign)
{
	GtkWidget *label = gtk_label_new (text);

	gtk_label_set_xalign (GTK_LABEL (label), xalign);
	if (klass != NULL)
		add_class (label, klass);
	return label;
}

/* A white card: rounded, one hairline border. */
static GtkWidget *
card_new (GtkOrientation orientation, gint spacing)
{
	GtkWidget *box = gtk_box_new (orientation, spacing);

	add_class (box, "card");
	return box;
}

/* A flat button that reads as a link ("Show them"). */
static GtkWidget *
link_button_new (const gchar *text)
{
	GtkWidget *button = gtk_button_new_with_label (text);

	gtk_button_set_relief (GTK_BUTTON (button), GTK_RELIEF_NONE);
	add_class (button, "fs-link");
	gtk_widget_set_valign (button, GTK_ALIGN_CENTER);
	return button;
}

/* A button with a drawn icon and a label. */
static GtkWidget *
icon_button_new (FsIconKind icon, const gchar *text, GtkWidget **icon_out,
                 GtkWidget **label_out, gboolean toggle)
{
	GtkWidget *button = toggle ? gtk_toggle_button_new ()
	                           : gtk_button_new ();
	GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	GtkWidget *image = fs_icon_new (icon, 16);
	GtkWidget *label = gtk_label_new (text);

	gtk_box_pack_start (GTK_BOX (row), image, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (row), label, FALSE, FALSE, 0);
	gtk_widget_set_halign (row, GTK_ALIGN_CENTER);
	gtk_container_add (GTK_CONTAINER (button), row);

	if (icon_out != NULL)
		*icon_out = image;
	if (label_out != NULL)
		*label_out = label;
	return button;
}

/* [ format_bytes ]
 * Binary units, one decimal above kilobytes: the original printed
 * "1.4 GB", not "1503238553". */
static gchar *
format_bytes (guint64 bytes)
{
	const guint64 kib = 1024;
	const guint64 mib = kib * 1024;
	const guint64 gib = mib * 1024;

	if (bytes >= gib)
		return g_strdup_printf ("%.1f GiB", (gdouble) bytes / (gdouble) gib);
	if (bytes >= mib)
		return g_strdup_printf ("%.1f MiB", (gdouble) bytes / (gdouble) mib);
	if (bytes >= kib)
		return g_strdup_printf ("%.1f KiB", (gdouble) bytes / (gdouble) kib);

	return g_strdup_printf ("%u B", (guint) bytes);
}

static gchar *
format_rate (guint64 bytes_per_second)
{
	gchar *amount, *text;

	if (bytes_per_second == 0)
		return g_strdup (_("Idle"));

	amount = format_bytes (bytes_per_second);
	text = g_strdup_printf ("%s/s", amount);
	g_free (amount);
	return text;
}

/* The same, with nothing put in words: a legend reads "0 B/s". */
static gchar *
format_speed (guint64 bytes_per_second)
{
	gchar *amount = format_bytes (bytes_per_second);
	gchar *text = g_strdup_printf ("%s/s", amount);

	g_free (amount);
	return text;
}

static gint64
page_now (void)
{
	return page_clock != NULL ? page_clock () : g_get_monotonic_time ();
}

void
fs_statusview_set_clock (gint64 (*clock) (void))
{
	page_clock = clock;
}

/* Adapters that are not hardware: Docker and libvirt bridges, veth
 * pairs, Hyper-V switches, VPN tunnels.  Real, but noise on a page
 * that answers "is this computer protected". */
static gboolean
adapter_is_virtual (const FsIfaceStat *stat)
{
	return stat->kind != NULL &&
	       (strcmp (stat->kind, "Virtual") == 0 ||
	        strcmp (stat->kind, "Tunnel") == 0 ||
	        strcmp (stat->kind, "Loopback") == 0);
}

static gboolean
state_is_running (FsFirewallState state)
{
	return state == FS_FW_RUNNING || state == FS_FW_LOCKED ||
	       state == FS_FW_HIT;
}

/* ------------------------------------------------------------ verdict */

const gchar *
fs_statusview_verdict (FsVerdict *level)
{
	if (level != NULL)
		*level = verdict_level;
	return verdict_text != NULL ? verdict_text : _("State unknown");
}

void
fs_statusview_set_changed_cb (FsStatusChanged cb, gpointer user)
{
	changed_cb = cb;
	changed_user = user;

	if (cb != NULL)
		cb (user);
}

void
fs_statusview_set_policy (FsPolicy *policy)
{
	shared_policy = policy;
	update_overview ();
}

static guint
policy_rule_count (void)
{
	guint n = 0;

	if (shared_policy == NULL)
		return 0;

	for (gint kind = 0; kind < FS_RULE_N_KINDS; kind++)
		n += fs_policy_count (shared_policy, (FsRuleKind) kind);
	return n;
}

static void
set_tile (gint tile, const gchar *text, const gchar *tone)
{
	static const gchar *const tones[] = { "good", "warn", "bad", NULL };

	if (tile_value[tile] == NULL)
		return;

	gtk_label_set_text (GTK_LABEL (tile_value[tile]), text);
	swap_class (tile_value[tile], tones, tone);
}

static void
update_policy_tile (void)
{
	guint n = policy_rule_count ();
	gchar *text;

	if (n == 0)
		text = g_strdup (_("No rules yet"));
	else
		text = g_strdup_printf (g_dngettext (NULL, "%u rule", "%u rules",
		                                     n), n);

	if (policy_locked) {
		gchar *locked = g_strconcat (text, DOT, _("locked"), NULL);

		g_free (text);
		text = locked;
	}

	set_tile (TILE_POLICY, text, NULL);
	g_free (text);
}

/* [ update_overview ]
 * Judges the machine from the firewall state and the IPv6 answer, and
 * writes that one judgement into the verdict card, its four facts, the
 * power button and the sidebar (through changed_cb). */
static void
update_overview (void)
{
	static const gchar *const levels[] = {
		"level-unknown", "level-ok", "level-warn", "level-bad", NULL
	};
	const FsBackend *backend = fs_backend ();
	gboolean running = state_is_running (current_state);
	gboolean usable = backend->available ();
	const gchar *title;
	GString *body = g_string_new (NULL);
	FsIconKind icon;
	FsVerdict level;
	const gchar *word;
	/* Profiles in force that are switched off.  primary_open: one of
	 * them covers the network the computer is mainly on (or the
	 * backend named no network, so "this network" is all it can be). */
	guint unguarded = fs_network_place_unguarded (net_place, prof_known,
	                                              prof_on);
	const FsNetwork *primary = fs_network_place_primary (net_place);
	gboolean primary_open = unguarded != 0 &&
		(primary == NULL || primary->profile < 0 ||
		 (unguarded & FS_PROFILE_BIT (primary->profile)) != 0);

	if (!running) {
		unguarded = 0;
		primary_open = FALSE;
	}

	if (running) {
		if (unguarded != 0) {
			gchar *why = fs_network_place_unguarded_sentence (
				net_place, unguarded, backend->display_name);

			/* "Running" is true of the service and false of this
			 * network: Windows keeps the profiles apart, and the
			 * one in force here filters nothing. */
			if (primary_open) {
				level = FS_VERDICT_BAD;
				icon = FS_ICON_SHIELD_X;
				title = _("This network is not protected");
				word = _("Not protected");
			} else {
				level = FS_VERDICT_WARN;
				icon = FS_ICON_SHIELD_ALERT;
				title = _("Some networks are not protected");
				word = _("Partly protected");
			}
			g_string_append (body, why);
			g_free (why);
		} else if (ipv6_known && ipv6_st == FS_IPV6_UNFILTERED) {
			level = FS_VERDICT_WARN;
			icon = FS_ICON_SHIELD_ALERT;
			title = _("IPv6 is not protected");
			word = _("IPv6 not protected");
			g_string_append (body, _("IPv4 is filtered, but IPv6 "
			                         "traffic passes unfiltered."));
			if (ipv6_detail != NULL && *ipv6_detail != '\0') {
				g_string_append_c (body, ' ');
				g_string_append (body, _(ipv6_detail));
			}
		} else if (ipv6_known && ipv6_st == FS_IPV6_UNKNOWN) {
			level = FS_VERDICT_OK;
			icon = FS_ICON_SHIELD_CHECK;
			title = _("The firewall is running");
			word = _("Running");
			g_string_append (body, ipv6_detail != NULL && *ipv6_detail
			                       ? _(ipv6_detail)
			                       : _("StockFW could not check "
			                           "whether IPv6 is filtered."));
		} else if (ipv6_known && ipv6_st == FS_IPV6_ABSENT) {
			level = FS_VERDICT_OK;
			icon = FS_ICON_SHIELD_CHECK;
			title = _("This computer is protected");
			word = _("Protected");
			g_string_append (body, _("Your policy is in force. This "
			                         "system has no IPv6, so IPv4 is "
			                         "all there is to filter."));
		} else {
			level = FS_VERDICT_OK;
			icon = FS_ICON_SHIELD_CHECK;
			title = _("This computer is protected");
			word = _("Protected");
			g_string_append (body, _("Your policy is in force for "
			                         "IPv4 and IPv6."));
		}

		/* Which profile is doing the protecting, where there are
		 * profiles: "Windows Defender Firewall is applying the
		 * Private profile." */
		if (unguarded == 0) {
			gchar *using = fs_network_place_in_use_sentence (
				net_place, backend->display_name);

			if (using != NULL) {
				g_string_append_c (body, ' ');
				g_string_append (body, using);
				g_free (using);
			}
		}

		if (current_state == FS_FW_LOCKED || policy_locked)
			g_string_append (body, _(" Policy changes are locked."));

		/* The blocklists, as the Threat Intel page last read them:
		 * "not in force" with the platform's reason, never folded
		 * into "protected" [S10]. */
		{
			gchar *intel = fs_intelview_summary ();

			if (intel != NULL) {
				g_string_append_c (body, ' ');
				g_string_append (body, intel);
				g_free (intel);
			}
		}
	} else if (current_state == FS_FW_STOPPED) {
		level = FS_VERDICT_BAD;
		icon = FS_ICON_SHIELD_X;
		title = _("This computer is not protected");
		word = _("Not protected");
		g_string_append (body, _("The firewall is stopped, so no "
		                         "traffic is filtered. Start it to put "
		                         "your policy in force."));
	} else {
		level = FS_VERDICT_UNKNOWN;
		icon = FS_ICON_SHIELD_QUESTION;
		title = _("The firewall's state is unknown");
		word = _("State unknown");
		g_string_append (body, _("StockFW could not read the "
		                         "firewall's state."));
		if (!usable)
			g_string_append (body, _(" The firewall tools are not "
			                         "available to this account."));
	}

	verdict_level = level;
	g_free (verdict_text);
	verdict_text = g_strdup (word);

	if (hero != NULL) {
		swap_class (hero, levels, levels[level]);
		fs_icon_set_kind (hero_icon, icon);
		/* The board's large word is the verdict's own, the one the
		 * sidebar and `stockfw status' print: never a second wording
		 * of the same state. */
		gtk_label_set_text (GTK_LABEL (state_word), word);
		gtk_label_set_text (GTK_LABEL (hero_title), title);
		gtk_label_set_text (GTK_LABEL (hero_body), body->str);
	}

	/* The power button: Stop while running, Start otherwise.  Start is
	 * the primary action of a stopped firewall, so it is filled. */
	if (power_button != NULL) {
		static const gchar *const looks[] = {
			"btn-primary", "btn-subtle", NULL
		};

		gtk_label_set_text (GTK_LABEL (power_label),
		                    running ? _("Stop firewall")
		                            : _("Start firewall"));
		fs_icon_set_kind (power_icon, running ? FS_ICON_STOP
		                                      : FS_ICON_PLAY);
		swap_class (power_button, looks,
		            running ? "btn-subtle" : "btn-primary");
		gtk_widget_set_sensitive (power_button, usable);
	}

	/* The four facts. */
	if (primary_open)
		set_tile (TILE_IPV4, _("Not filtered here"), "bad");
	else if (unguarded != 0)
		set_tile (TILE_IPV4, _("Partly filtered"), "warn");
	else if (running)
		set_tile (TILE_IPV4, _("Filtered"), "good");
	else if (current_state == FS_FW_STOPPED)
		set_tile (TILE_IPV4, _("Not filtered"), "bad");
	else
		set_tile (TILE_IPV4, _("Unknown"), NULL);

	if (ipv6_known && ipv6_st == FS_IPV6_ABSENT)
		set_tile (TILE_IPV6, _("None on this system"), NULL);
	else if (primary_open)
		set_tile (TILE_IPV6, _("Not filtered here"), "bad");
	else if (unguarded != 0)
		set_tile (TILE_IPV6, _("Partly filtered"), "warn");
	else if (current_state == FS_FW_STOPPED)
		set_tile (TILE_IPV6, _("Not filtered"), "bad");
	else if (!running)
		set_tile (TILE_IPV6, _("Unknown"), NULL);
	else if (!ipv6_known || ipv6_st == FS_IPV6_FILTERED)
		set_tile (TILE_IPV6, _("Filtered"), "good");
	else if (ipv6_st == FS_IPV6_UNFILTERED)
		set_tile (TILE_IPV6, _("Not filtered"), "warn");
	else
		set_tile (TILE_IPV6, _("Unknown"), NULL);

	update_policy_tile ();
	set_tile (TILE_ENGINE, backend->display_name != NULL
	                       ? backend->display_name : _("Unknown"), NULL);

	g_string_free (body, TRUE);

	if (changed_cb != NULL)
		changed_cb (changed_user);
}

/* ------------------------------------------------------------ profiles */

static void refresh_place (gboolean rejudge);
static void update_subtitle (void);

/* [ on_profile_toggled ]
 * Fired when the user flips a profile switch.  We read which profile
 * from the widget's user-data property rather than threading state
 * through the signal payload. */
static void
on_profile_toggled (GtkSwitch *sw, GParamSpec *pspec, gpointer data)
{
	gboolean active = gtk_switch_get_active (sw);
	gpointer ud = g_object_get_data (G_OBJECT (sw), "user-data");
	gint profile = GPOINTER_TO_INT (ud);
	GError *error = NULL;

	(void) pspec;
	(void) data;

	if (!fs_backend ()->set_profile_enabled (profile, active, &error)) {
		fs_dialogs_error (NULL, _("Could not change the firewall profile"),
		                  error ? error->message : NULL);
		g_clear_error (&error);

		/* Revert the switch: the change did not happen. */
		g_signal_handlers_block_by_func (sw, on_profile_toggled, NULL);
		gtk_switch_set_active (sw, !active);
		g_signal_handlers_unblock_by_func (sw, on_profile_toggled, NULL);
		return;
	}

	/* Switching on the profile in use is the fix the verdict card
	 * asks for, so the card answers at once, not at the next poll. */
	refresh_place (TRUE);
}

static void
refresh_profiles (void)
{
	const FsBackend *backend = fs_backend ();

	/* Reflect the real profile states whenever the main state
	 * changes.  Done with the signal blocked so the refresh itself
	 * does not read as a user toggle.  The states are kept too: the
	 * verdict needs to know whether the profile in use is on. */
	prof_known = 0;
	prof_on = 0;
	for (gint i = 0; i < FS_PROFILE_COUNT; i++) {
		gboolean enabled = FALSE;

		if (!backend->get_profile_enabled (i, &enabled))
			continue;
		prof_known |= FS_PROFILE_BIT (i);
		if (enabled)
			prof_on |= FS_PROFILE_BIT (i);

		if (profile_switches[i] != NULL &&
		    gtk_switch_get_active (GTK_SWITCH (profile_switches[i])) !=
		    enabled) {
			g_signal_handlers_block_by_func (profile_switches[i],
			                                 on_profile_toggled, NULL);
			gtk_switch_set_active (GTK_SWITCH (profile_switches[i]),
			                       enabled);
			g_signal_handlers_unblock_by_func (profile_switches[i],
			                                   on_profile_toggled, NULL);
		}
	}
}

/* [ refresh_place ]
 * Re-reads where the computer is connected and the profile switches,
 * marks the profiles in force "In use", and -- when `rejudge' and
 * anything changed -- re-judges the verdict card.  Moving from a
 * Private network at home to a Public one at a cafe changes which
 * profile protects the machine without touching the firewall's state,
 * so this runs on its own timer, not only on state changes. */
static void
refresh_place (gboolean rejudge)
{
	const FsBackend *backend = fs_backend ();
	FsNetworkPlace *now;
	guint known_before = prof_known, on_before = prof_on;
	gboolean changed;

	if (backend->network_place == NULL)
		return;

	now = backend->network_place ();
	refresh_profiles ();

	changed = !fs_network_place_equal (now, net_place) ||
	          prof_known != known_before || prof_on != on_before;
	fs_network_place_free (net_place);
	net_place = now;
	update_subtitle ();

	for (gint i = 0; i < FS_PROFILE_COUNT; i++) {
		if (profile_in_use[i] == NULL)
			continue;
		gtk_widget_set_visible (profile_in_use[i], net_place != NULL &&
		                        (net_place->in_use &
		                         FS_PROFILE_BIT (i)) != 0);
	}

	if (changed)
		fs_tray_set_firewall (current_state,
		                      fs_network_place_kind (net_place));
	if (rejudge && changed)
		update_overview ();
}

/* -------------------------------------------------------------- totals */

static void
set_total (gint which, const gchar *value, const gchar *note)
{
	if (total_value[which] == NULL)
		return;

	gtk_label_set_text (GTK_LABEL (total_value[which]), value);
	gtk_label_set_text (GTK_LABEL (total_note[which]), note);
}

static void
update_counters (void)
{
	for (gint dir = 0; dir < 2; dir++) {
		gchar *value = g_strdup_printf ("%u", events[dir][0]);
		gchar *note = g_strdup_printf (_("%u blocked"), events[dir][1]);

		set_total (dir == 0 ? TOTAL_IN : TOTAL_OUT, value, note);
		push_spark_value (dir == 0 ? TOTAL_IN : TOTAL_OUT, (gdouble) events[dir][0]);
		g_free (value);
		g_free (note);
	}
}

void
fs_statusview_event_in (gboolean serious)
{
	events[0][0]++;
	if (serious)
		events[0][1]++;

	update_counters ();
}

void
fs_statusview_event_out (gboolean serious)
{
	events[1][0]++;
	if (serious)
		events[1][1]++;

	update_counters ();
}

void
fs_statusview_events_reset (void)
{
	events[0][0] = events[0][1] = 0;
	events[1][0] = events[1][1] = 0;

	push_spark_value (TOTAL_IN, 0.0);
	push_spark_value (TOTAL_OUT, 0.0);
	update_counters ();
}

/* ------------------------------------------------------- recent blocks */

static void
recent_block_free (gpointer data)
{
	RecentBlock *b = data;

	g_free (b->title);
	g_free (b->detail);
	fs_hit_free (b->hit);
	g_free (b);
}

/* The service column carries the parser's "[BLOCKED]" marker; the card
 * says "Blocked" in words instead. */
static gchar *
clean_service (const FsHit *hit)
{
	gchar *service = g_strdup (hit->service != NULL ? hit->service : "");
	gchar *mark = strstr (service, "[BLOCKED]");

	if (mark != NULL)
		memmove (mark, mark + 9, strlen (mark + 9) + 1);
	g_strstrip (service);

	if (*service == '\0') {
		g_free (service);
		if (hit->port != NULL && *hit->port != '\0')
			service = g_strdup_printf (_("port %s"), hit->port);
		else if (hit->protocol != NULL && *hit->protocol != '\0')
			service = g_strdup (hit->protocol);
		else
			service = g_strdup (_("traffic"));
	}
	return service;
}

/* [ on_recent_clicked ]
 * A row of Latest blocks, pressed or activated from the keyboard: the
 * event's details open in the drawer, as they do from the Events list. */
static void
on_recent_clicked (GtkButton *button, gpointer data)
{
	RecentBlock *b = g_queue_peek_nth (&recent, GPOINTER_TO_UINT (data));

	(void) button;
	if (b != NULL && b->hit != NULL)
		fs_hitview_show_details (b->hit);
}

/* One row of Latest blocks, empty: update_recent () fills and shows it. */
static void
recent_row_build (guint n)
{
	RecentRow *row = &recent_rows[n];
	GtkWidget *line = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
	GtkWidget *dot = fs_icon_new (FS_ICON_DOT, 8);
	GtkWidget *text = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	GtkWidget *more = fs_icon_new (FS_ICON_FORWARD, 14);

	row->button = gtk_button_new ();
	gtk_button_set_relief (GTK_BUTTON (row->button), GTK_RELIEF_NONE);
	add_class (row->button, "recent-row");
	gtk_widget_set_tooltip_text (row->button,
	                             _("Show this event's details"));

	add_class (dot, "dot-bad");
	gtk_widget_set_valign (dot, GTK_ALIGN_START);
	gtk_widget_set_margin_top (dot, 5);
	row->title = label_new (NULL, "recent-title", 0.0);
	gtk_label_set_ellipsize (GTK_LABEL (row->title), PANGO_ELLIPSIZE_END);
	row->detail = label_new (NULL, "recent-detail", 0.0);
	gtk_label_set_ellipsize (GTK_LABEL (row->detail), PANGO_ELLIPSIZE_END);
	add_class (more, "recent-more");
	gtk_widget_set_valign (more, GTK_ALIGN_CENTER);

	gtk_box_pack_start (GTK_BOX (text), row->title, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (text), row->detail, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (line), dot, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (line), text, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (line), more, FALSE, FALSE, 0);
	gtk_container_add (GTK_CONTAINER (row->button), line);
	gtk_widget_show_all (line);

	/* Shown by update_recent (), and only while it has an event. */
	gtk_widget_set_no_show_all (row->button, TRUE);
	g_signal_connect (row->button, "clicked",
	                  G_CALLBACK (on_recent_clicked), GUINT_TO_POINTER (n));
	gtk_box_pack_start (GTK_BOX (recent_list), row->button, FALSE, FALSE, 0);
}

/* [ update_recent ]
 * Writes the queue into the card's rows, in place. */
static void
update_recent (void)
{
	GList *l = recent.head;

	if (recent_list == NULL)
		return;

	for (guint i = 0; i < RECENT_MAX; i++, l = l != NULL ? l->next : NULL) {
		RecentRow *row = &recent_rows[i];
		RecentBlock *b = l != NULL ? l->data : NULL;
		AtkObject *atk;
		gchar *name;

		if (row->button == NULL)
			continue;
		if (b == NULL) {
			gtk_widget_hide (row->button);
			continue;
		}

		gtk_label_set_text (GTK_LABEL (row->title), b->title);
		gtk_label_set_text (GTK_LABEL (row->detail), b->detail);
		/* The whole row is one button: a screen reader hears what
		 * was blocked, then what pressing it does. */
		name = g_strdup_printf ("%s, %s", b->title, b->detail);
		atk = gtk_widget_get_accessible (row->button);
		if (atk != NULL)
			atk_object_set_name (atk, name);
		g_free (name);
		gtk_widget_show (row->button);
	}

	gtk_widget_set_visible (recent_empty, recent.length == 0);
}

void
fs_statusview_note_block (const FsHit *hit)
{
	gboolean inbound;
	const gchar *remote;
	const gchar *when;
	gchar *service;
	RecentBlock *b;

	if (hit == NULL)
		return;

	inbound = hit->direction != NULL &&
	          (g_ascii_strcasecmp (hit->direction, "In") == 0 ||
	           g_ascii_strcasecmp (hit->direction, "Inbound") == 0);
	remote = inbound ? hit->source : hit->destination;
	service = clean_service (hit);

	/* "Nov  2 10:42:01" and "2026-11-02 10:42:01" both end in the
	 * time of day, which is all a card about the last few minutes
	 * needs. */
	when = hit->time != NULL ? strrchr (hit->time, ' ') : NULL;
	when = when != NULL ? when + 1 : (hit->time != NULL ? hit->time : "");

	b = g_new0 (RecentBlock, 1);
	b->title = g_strdup_printf (inbound ? _("Blocked inbound %s")
	                                    : _("Blocked outbound %s"),
	                            service);
	b->detail = g_strdup_printf ("%s" DOT "%s" DOT "%s",
	                             remote != NULL && *remote ? remote
	                                                       : _("unknown"),
	                             hit->rule != NULL && *hit->rule
	                             ? hit->rule : _("Policy"),
	                             when);
	b->hit = fs_hit_copy (hit);
	g_free (service);

	g_queue_push_head (&recent, b);
	while (recent.length > RECENT_MAX)
		recent_block_free (g_queue_pop_tail (&recent));

	update_recent ();

	/* The tray's "Blocked today" and its Recent blocks. */
	{
		GDateTime *now = g_date_time_new_now_local ();

		fs_block_tally_note (hit, now);
		g_date_time_unref (now);
	}
	fs_tray_refresh ();
}

gchar **
fs_statusview_recent_blocks (void)
{
	gchar **out = g_new0 (gchar *, recent.length + 1);
	guint i = 0;

	for (GList *l = recent.head; l != NULL; l = l->next, i++) {
		RecentBlock *b = l->data;

		out[i] = g_strconcat (b->title, "\n", b->detail, NULL);
	}
	return out;
}

/* ------------------------------------------------------------- traffic */

/* [ traffic_nice_ceiling ]
 * The top of the graph's scale for a peak of `peak' bytes per second:
 * the smallest of 1, 2, 5, 10, 20, 50, 100, 200, 500 times a binary
 * unit (the page counts in KiB and MiB everywhere) that holds it.  The
 * floor is 1 KiB/s, so a few stray bytes do not draw a mountain. */
static guint64
traffic_nice_ceiling (guint64 peak)
{
	static const guint steps[] = { 1, 2, 5, 10, 20, 50, 100, 200, 500 };
	guint64 unit = 1024;

	/* KiB, MiB, GiB, TiB: past that, the peak itself. */
	for (guint power = 0; power < 4; power++, unit *= 1024)
		for (guint i = 0; i < G_N_ELEMENTS (steps); i++)
			if (peak <= steps[i] * unit)
				return steps[i] * unit;
	return peak;
}

/* A ceiling in words: "500 KiB/s", "2 MiB/s".  Whole numbers, because
 * the ceiling is one. */
static gchar *
traffic_scale_text (guint64 ceiling)
{
	static const gchar *const units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
	guint unit = 0;

	while (unit + 1 < G_N_ELEMENTS (units) && ceiling >= 1024 &&
	       ceiling % 1024 == 0) {
		ceiling /= 1024;
		unit++;
	}
	return g_strdup_printf ("%" G_GUINT64_FORMAT " %s/s", ceiling,
	                        units[unit]);
}

static guint64
traffic_peak (void)
{
	guint64 peak = 0;

	for (guint i = 0; i < traffic_count; i++) {
		peak = MAX (peak, traffic_rx[i]);
		peak = MAX (peak, traffic_tx[i]);
	}
	return peak;
}

guint64
fs_statusview_traffic_scale (void)
{
	return traffic_nice_ceiling (traffic_peak ());
}

guint
fs_statusview_traffic_points (guint64 **received, guint64 **sent)
{
	if (received != NULL) {
		*received = g_new0 (guint64, traffic_count + 1);
		memcpy (*received, traffic_rx, sizeof (guint64) * traffic_count);
	}
	if (sent != NULL) {
		*sent = g_new0 (guint64, traffic_count + 1);
		memcpy (*sent, traffic_tx, sizeof (guint64) * traffic_count);
	}
	return traffic_count;
}

/* The legend's two numbers and the card's sentence. */
static void
update_traffic_labels (void)
{
	if (traffic_area == NULL)
		return;

	if (traffic_known && traffic_count > 0) {
		gchar *rx = format_speed (traffic_rx[traffic_count - 1]);
		gchar *tx = format_speed (traffic_tx[traffic_count - 1]);

		gtk_label_set_text (GTK_LABEL (traffic_rx_value), rx);
		gtk_label_set_text (GTK_LABEL (traffic_tx_value), tx);
		g_free (rx);
		g_free (tx);
	} else {
		/* Counters, but no second reading to take a rate from yet. */
		gtk_label_set_text (GTK_LABEL (traffic_rx_value), "-");
		gtk_label_set_text (GTK_LABEL (traffic_tx_value), "-");
	}

	gtk_widget_set_visible (traffic_legend, traffic_known);
	gtk_label_set_text (GTK_LABEL (traffic_note), traffic_known
		? _("Everything the network adapters of this computer carried "
		    "in the last two minutes, whether or not the firewall "
		    "filtered it.")
		: _("This computer's adapter counters are not available."));
	gtk_widget_queue_draw (traffic_area);
}

/* [ traffic_sample ]
 * One reading of the counters: `received' and `sent' are the bytes the
 * real adapters moved since the reading before (the virtual ones',
 * where no real adapter is up: refresh_network). */
static void
traffic_sample (gint64 now, guint64 received, guint64 sent)
{
	traffic_known = TRUE;

	if (!traffic_started) {
		/* The first reading has nothing before it to measure from. */
		traffic_started = TRUE;
		traffic_stamp = now;
		traffic_acc_rx = traffic_acc_tx = 0;
	} else {
		traffic_acc_rx += received;
		traffic_acc_tx += sent;

		if (now - traffic_stamp >= (gint64) NET_REFRESH_MS * 1000 / 2) {
			gdouble elapsed = (gdouble) (now - traffic_stamp) /
			                  1000000.0;

			if (traffic_count == TRAFFIC_POINTS) {
				memmove (traffic_rx, traffic_rx + 1,
				         sizeof (guint64) * (TRAFFIC_POINTS - 1));
				memmove (traffic_tx, traffic_tx + 1,
				         sizeof (guint64) * (TRAFFIC_POINTS - 1));
				traffic_count--;
			}
			traffic_rx[traffic_count] =
				(guint64) ((gdouble) traffic_acc_rx / elapsed);
			traffic_tx[traffic_count] =
				(guint64) ((gdouble) traffic_acc_tx / elapsed);
			traffic_count++;

			traffic_stamp = now;
			traffic_acc_rx = traffic_acc_tx = 0;
		}
	}

	update_traffic_labels ();
}

/* The backend has no counters (or lost them): an empty graph that says
 * so, never the last line left standing as if it were live. */
static void
traffic_reset (void)
{
	traffic_known = FALSE;
	traffic_started = FALSE;
	traffic_count = 0;
	traffic_acc_rx = traffic_acc_tx = 0;
	update_traffic_labels ();
}

/* Where the graph is drawn inside its widget: room above for the scale
 * label, below for the two ends of the time axis, and at the right for
 * the dot on the newest point. */
#define TRAFFIC_PAD_TOP     18.0
#define TRAFFIC_PAD_BOTTOM  18.0
#define TRAFFIC_PAD_RIGHT   4.0

/* The distance between two points of a graph `w' wide. */
static gdouble
traffic_step (gdouble w)
{
	return (w - TRAFFIC_PAD_RIGHT) / (gdouble) (TRAFFIC_POINTS - 1);
}

static gdouble
traffic_x (guint i, gdouble w)
{
	/* Newest at the right edge; older points one step left each, so
	 * the line grows in from the right while the two minutes fill. */
	return w - TRAFFIC_PAD_RIGHT -
	       (gdouble) (traffic_count - 1 - i) * traffic_step (w);
}

static void
traffic_path (cairo_t *cr, const guint64 *series, guint64 ceiling,
              gdouble w, gdouble top, gdouble base)
{
	for (guint i = 0; i < traffic_count; i++) {
		gdouble v = (gdouble) MIN (series[i], ceiling) / (gdouble) ceiling;
		gdouble y = base - v * (base - top);

		if (i == 0)
			cairo_move_to (cr, traffic_x (i, w), y);
		else
			cairo_line_to (cr, traffic_x (i, w), y);
	}
}

/* Small text in the widget's own face, its top-left or top-right corner
 * at x, y. */
static void
traffic_text (GtkWidget *widget, cairo_t *cr, const gchar *text,
              gdouble x, gdouble y, gboolean right)
{
	PangoLayout *layout = gtk_widget_create_pango_layout (widget, text);
	PangoAttrList *attrs = pango_attr_list_new ();
	gint tw, th;

	pango_attr_list_insert (attrs, pango_attr_scale_new (0.85));
	pango_layout_set_attributes (layout, attrs);
	pango_attr_list_unref (attrs);
	pango_layout_get_pixel_size (layout, &tw, &th);

	fs_theme_source (cr, "fs_text_weak", "#a8a4a4", 1.0);
	cairo_move_to (cr, right ? x - tw : x, y);
	pango_cairo_show_layout (cr, layout);
	g_object_unref (layout);
}

/* [ on_traffic_draw ]
 * Received as the accent line over a soft fill, sent as a quiet grey
 * line, both from a zero baseline up to a round ceiling.  Every colour
 * is asked of the theme at each paint.  No smoothing: a point is what
 * was measured. */
static gboolean
on_traffic_draw (GtkWidget *widget, cairo_t *cr, gpointer data)
{
	GtkAllocation alloc;
	gdouble w, h, top, base;
	guint64 ceiling;
	gchar *scale;

	(void) data;

	gtk_widget_get_allocation (widget, &alloc);
	w = (gdouble) alloc.width;
	h = (gdouble) alloc.height;
	if (w < 40 || h < TRAFFIC_PAD_TOP + TRAFFIC_PAD_BOTTOM + 8)
		return FALSE;

	top = TRAFFIC_PAD_TOP + 0.5;
	base = h - TRAFFIC_PAD_BOTTOM - 0.5;

	cairo_set_line_width (cr, 1.0);

	if (!traffic_known) {
		/* No counters: the baseline alone. */
		fs_theme_source (cr, "fs_border_strong", "#4a4545", 1.0);
		cairo_move_to (cr, 0, base);
		cairo_line_to (cr, w, base);
		cairo_stroke (cr);
		return FALSE;
	}

	ceiling = fs_statusview_traffic_scale ();

	/* Two quiet gridlines: the ceiling and half of it. */
	fs_theme_source (cr, "fs_border", "#2f2b2b", 1.0);
	cairo_move_to (cr, 0, top);
	cairo_line_to (cr, w, top);
	cairo_move_to (cr, 0, (gdouble) (gint) ((top + base) / 2) + 0.5);
	cairo_line_to (cr, w, (gdouble) (gint) ((top + base) / 2) + 0.5);
	cairo_stroke (cr);

	scale = traffic_scale_text (ceiling);
	traffic_text (widget, cr, scale, w, 0, TRUE);
	g_free (scale);
	traffic_text (widget, cr, _("2 minutes ago"), 0, base + 3, FALSE);
	traffic_text (widget, cr, _("now"), w, base + 3, TRUE);

	if (traffic_count > 0) {
		gdouble last = traffic_x (traffic_count - 1, w);
		gdouble first = traffic_x (0, w);

		cairo_set_line_join (cr, CAIRO_LINE_JOIN_ROUND);
		cairo_set_line_cap (cr, CAIRO_LINE_CAP_ROUND);

		/* Received: the fill, down to the baseline. */
		if (traffic_count > 1) {
			traffic_path (cr, traffic_rx, ceiling, w, top, base);
			cairo_line_to (cr, last, base);
			cairo_line_to (cr, first, base);
			cairo_close_path (cr);
			fs_theme_source (cr, "fs_accent", "#5aa2ff", 0.15);
			cairo_fill (cr);
		}

		/* Sent, under the received line where they cross. */
		fs_theme_source (cr, "fs_text_weak", "#a8a4a4", 1.0);
		if (traffic_count > 1) {
			cairo_set_line_width (cr, 1.5);
			traffic_path (cr, traffic_tx, ceiling, w, top, base);
			cairo_stroke (cr);
		}
		cairo_arc (cr, last, base - (gdouble) MIN (
		                   traffic_tx[traffic_count - 1], ceiling) /
		               (gdouble) ceiling * (base - top),
		           2.5, 0, 2 * G_PI);
		cairo_fill (cr);

		fs_theme_source (cr, "fs_accent", "#5aa2ff", 1.0);
		if (traffic_count > 1) {
			cairo_set_line_width (cr, 1.75);
			traffic_path (cr, traffic_rx, ceiling, w, top, base);
			cairo_stroke (cr);
		}
		cairo_arc (cr, last, base - (gdouble) MIN (
		                   traffic_rx[traffic_count - 1], ceiling) /
		               (gdouble) ceiling * (base - top),
		           2.5, 0, 2 * G_PI);
		cairo_fill (cr);
	}

	/* The zero baseline, over the fill's lower edge. */
	cairo_set_line_width (cr, 1.0);
	fs_theme_source (cr, "fs_border_strong", "#4a4545", 1.0);
	cairo_move_to (cr, 0, base);
	cairo_line_to (cr, w, base);
	cairo_stroke (cr);

	return FALSE;
}

/* [ on_traffic_tooltip ]
 * The two numbers of the point under the pointer. */
static gboolean
on_traffic_tooltip (GtkWidget *widget, gint x, gint y, gboolean keyboard,
                    GtkTooltip *tooltip, gpointer data)
{
	gdouble w = (gdouble) gtk_widget_get_allocated_width (widget);
	gdouble step = traffic_step (w);
	gchar *rx, *tx, *text;
	guint back, i;

	(void) y;
	(void) data;

	if (keyboard || !traffic_known || traffic_count == 0 || step <= 0)
		return FALSE;

	/* How many points back from the newest one the pointer is. */
	back = (guint) (MAX (w - TRAFFIC_PAD_RIGHT - (gdouble) x, 0.0) / step +
	                0.5);
	if (back >= traffic_count)
		return FALSE;
	i = traffic_count - 1 - back;

	rx = format_speed (traffic_rx[i]);
	tx = format_speed (traffic_tx[i]);
	if (back == 0)
		text = g_strdup_printf (_("Now: received %s, sent %s"), rx, tx);
	else
		text = g_strdup_printf (_("About %u s ago: received %s, sent %s"),
		                        back * (NET_REFRESH_MS / 1000), rx, tx);
	gtk_tooltip_set_text (tooltip, text);
	g_free (rx);
	g_free (tx);
	g_free (text);
	return TRUE;
}

/* ------------------------------------------------------------ adapters */

/* What a row says of its adapter that does not change from sample to
 * sample.  While it holds, the row is kept and only its numbers are
 * rewritten; a row rebuilt every two seconds would lose its tooltip
 * under the pointer each time. */
static gchar *
adapter_key (const FsIfaceStat *stat)
{
	return g_strdup_printf ("%s\n%s\n%s\n%d", stat->device,
	                        stat->kind != NULL ? stat->kind : "",
	                        stat->ip != NULL ? stat->ip : "", stat->up);
}

/* An adapter's row: what it is and where, with its numbers still empty
 * (adapter_row_set). */
static GtkWidget *
adapter_row (const FsIfaceStat *stat)
{
	GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
	GtkWidget *tile = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	GtkWidget *text = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	GtkWidget *nums = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	GtkWidget *line = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	gboolean wireless = g_strcmp0 (stat->kind, "Wireless") == 0;
	gchar *name;
	GtkWidget *label;

	gtk_widget_set_size_request (tile, 36, 36);
	gtk_widget_set_valign (tile, GTK_ALIGN_CENTER);
	add_class (tile, "adapter-tile");
	gtk_box_pack_start (GTK_BOX (tile),
	                    fs_icon_new (wireless ? FS_ICON_WIFI
	                                          : FS_ICON_ADAPTER, 18),
	                    TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (row), tile, FALSE, FALSE, 0);

	/* The name, then the kind in the secondary ink.  The kind is a
	 * label of its own so that its colour is the stylesheet's
	 * (.adapter-kind): a colour written into the name's markup would
	 * stay the other palette's after a Dark mode switch, for as long
	 * as the row is kept. */
	name = g_markup_printf_escaped ("<b>%s</b>", stat->device);
	label = label_new (NULL, "adapter-name", 0.0);
	gtk_label_set_markup (GTK_LABEL (label), name);
	gtk_label_set_ellipsize (GTK_LABEL (label), PANGO_ELLIPSIZE_END);
	gtk_box_pack_start (GTK_BOX (line), label, FALSE, FALSE, 0);
	g_free (name);
	if (stat->kind != NULL && *stat->kind != '\0') {
		name = g_strdup_printf (DOT "%s%s", stat->kind,
		                        stat->up ? "" : _(" (down)"));
		label = label_new (name, "adapter-name", 0.0);
		add_class (label, "adapter-kind");
		gtk_label_set_ellipsize (GTK_LABEL (label), PANGO_ELLIPSIZE_END);
		gtk_box_pack_start (GTK_BOX (line), label, TRUE, TRUE, 0);
		g_free (name);
	}
	gtk_box_pack_start (GTK_BOX (text), line, FALSE, FALSE, 0);

	label = label_new (stat->ip != NULL ? stat->ip : _("No IPv4 address"),
	                   stat->ip != NULL ? "mono" : "muted", 0.0);
	add_class (label, "adapter-ip");
	gtk_box_pack_start (GTK_BOX (text), label, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (row), text, TRUE, TRUE, 0);

	label = label_new (NULL, "adapter-num", 1.0);
	gtk_widget_set_tooltip_text (label, _("Received since the adapter "
	                                      "came up"));
	gtk_box_pack_start (GTK_BOX (nums), label, FALSE, FALSE, 0);
	g_object_set_data (G_OBJECT (row), "fs-down", label);
	label = label_new (NULL, "adapter-num-muted", 1.0);
	gtk_widget_set_tooltip_text (label, _("Sent since the adapter came up"));
	gtk_box_pack_start (GTK_BOX (nums), label, FALSE, FALSE, 0);
	g_object_set_data (G_OBJECT (row), "fs-up", label);
	label = label_new (NULL, "adapter-num-muted", 1.0);
	gtk_widget_set_tooltip_text (label, _("Traffic right now"));
	gtk_box_pack_start (GTK_BOX (nums), label, FALSE, FALSE, 0);
	g_object_set_data (G_OBJECT (row), "fs-speed", label);
	gtk_widget_set_valign (nums, GTK_ALIGN_CENTER);
	gtk_box_pack_start (GTK_BOX (row), nums, FALSE, FALSE, 0);

	g_object_set_data_full (G_OBJECT (row), "fs-adapter",
	                        adapter_key (stat), g_free);
	add_class (row, "adapter-row");
	return row;
}

/* The three numbers of an adapter's row, which change at every sample. */
static void
adapter_row_set (GtkWidget *row, const FsIfaceStat *stat, guint64 rate)
{
	gchar *rx = format_bytes (stat->received);
	gchar *tx = format_bytes (stat->sent);
	gchar *speed = format_rate (rate);
	gchar *down = g_strconcat (DOWN, rx, NULL);
	gchar *up = g_strconcat (UP, tx, NULL);

	gtk_label_set_text (g_object_get_data (G_OBJECT (row), "fs-down"), down);
	gtk_label_set_text (g_object_get_data (G_OBJECT (row), "fs-up"), up);
	gtk_label_set_text (g_object_get_data (G_OBJECT (row), "fs-speed"),
	                    speed);

	g_free (rx);
	g_free (tx);
	g_free (down);
	g_free (up);
	g_free (speed);
}

/* [ refresh_network ]
 * Sample the interface counters, turn two consecutive samples into a
 * rate, and bring the adapters card, the Traffic graph, the Traffic
 * total and the header's "which machine" line up to date. */
static void
refresh_network (void)
{
	const FsBackend *backend = fs_backend ();
	GList *stats, *l, *rows, *row_at;
	gint64 now;
	guint hidden = 0, shown = 0;
	guint64 total_rate = 0, total_rx = 0, total_tx = 0;
	guint64 moved_rx = 0, moved_tx = 0;
	guint64 soft_rate = 0, soft_rx = 0, soft_tx = 0;
	guint64 soft_moved_rx = 0, soft_moved_tx = 0;
	guint real_up = 0;
	const FsIfaceStat *primary = NULL;
	guint64 primary_bytes = 0;

	if (adapters_card == NULL)
		return;

	update_policy_tile ();

	stats = backend->list_interface_stats != NULL
	        ? backend->list_interface_stats () : NULL;
	if (stats == NULL) {
		/* Nothing to show.  Hide the card rather than present an
		 * empty one as if it were live; no-show-all keeps the
		 * window-wide show_all from bringing it back. */
		gtk_widget_set_no_show_all (adapters_card, TRUE);
		gtk_widget_hide (adapters_card);
		g_hash_table_remove_all (net_samples);
		set_total (TOTAL_TRAFFIC, "-", _("No adapter counters"));
		traffic_reset ();
		g_clear_pointer (&primary_where, g_free);
		update_subtitle ();
		return;
	}
	gtk_widget_set_no_show_all (adapters_card, FALSE);
	gtk_widget_show (adapters_card);

	/* The rows on show, walked in step with the adapters: a row that
	 * is still about the same adapter is kept. */
	rows = gtk_container_get_children (GTK_CONTAINER (adapters_list));
	row_at = rows;

	now = page_now ();

	for (l = stats; l != NULL; l = l->next) {
		FsIfaceStat *stat = l->data;
		NetSample *prev = g_hash_table_lookup (net_samples, stat->device);
		guint64 rate = 0, dr = 0, ds = 0;
		GtkWidget *row = NULL;
		gchar *key;

		if (prev != NULL) {
			/* A counter that went backwards means the adapter
			 * was reset, not that traffic was un-sent. */
			dr = stat->received >= prev->received
			   ? stat->received - prev->received : 0;
			ds = stat->sent >= prev->sent
			   ? stat->sent - prev->sent : 0;

			if (now > prev->stamp) {
				gdouble elapsed = (gdouble) (now - prev->stamp) /
				                  1000000.0;

				rate = (guint64) ((gdouble) (dr + ds) / elapsed);
			}
		}

		prev = g_new0 (NetSample, 1);
		prev->received = stat->received;
		prev->sent     = stat->sent;
		prev->stamp    = now;
		g_hash_table_insert (net_samples, g_strdup (stat->device), prev);

		if (adapter_is_virtual (stat)) {
			hidden++;
			/* Kept aside for a computer with no real adapter
			 * up (below).  Loopback never left the machine. */
			if (g_strcmp0 (stat->kind, "Loopback") != 0) {
				soft_rate += rate;
				soft_rx += stat->received;
				soft_tx += stat->sent;
				soft_moved_rx += dr;
				soft_moved_tx += ds;
			}
			if (!show_virtual)
				continue;
		} else {
			/* Totals are the real adapters' only: bridged
			 * container traffic also crosses a real one, and
			 * counting both would count it twice. */
			total_rate += rate;
			total_rx += stat->received;
			total_tx += stat->sent;
			moved_rx += dr;
			moved_tx += ds;
			if (stat->up)
				real_up++;

			if (stat->ip != NULL && stat->up &&
			    stat->received + stat->sent >= primary_bytes) {
				primary = stat;
				primary_bytes = stat->received + stat->sent;
			}
		}

		key = adapter_key (stat);
		if (row_at != NULL &&
		    g_strcmp0 (g_object_get_data (G_OBJECT (row_at->data),
		                                  "fs-adapter"), key) == 0) {
			row = row_at->data;
			row_at = row_at->next;
		} else {
			/* A different adapter here: this row and the ones
			 * after it are out of step, so they go. */
			for (; row_at != NULL; row_at = row_at->next)
				gtk_widget_destroy (GTK_WIDGET (row_at->data));
			row = adapter_row (stat);
			gtk_box_pack_start (GTK_BOX (adapters_list), row,
			                    FALSE, FALSE, 0);
		}
		g_free (key);
		adapter_row_set (row, stat, rate);
		shown++;
	}

	for (; row_at != NULL; row_at = row_at->next)
		gtk_widget_destroy (GTK_WIDGET (row_at->data));
	g_list_free (rows);

	gtk_widget_show_all (adapters_list);

	/* No real adapter is up: a container, whose only adapter is one
	 * end of a veth pair, or a computer on a PPP or tunnel link alone.
	 * What the software adapters carry is then all there is, with no
	 * real adapter for it to be counted through a second time; leaving
	 * it out would draw a measured-looking 0 B/s under traffic. */
	if (real_up == 0) {
		total_rate += soft_rate;
		total_rx += soft_rx;
		total_tx += soft_tx;
		moved_rx += soft_moved_rx;
		moved_tx += soft_moved_tx;
	}

	traffic_sample (now, moved_rx, moved_tx);

	if (hidden > 0) {
		gchar *text = show_virtual
			? g_strdup_printf (g_dngettext (NULL,
				"%u virtual adapter is shown.",
				"%u virtual adapters are shown.", hidden), hidden)
			: g_strdup_printf (g_dngettext (NULL,
				"%u virtual adapter (containers, VMs, VPN) is hidden.",
				"%u virtual adapters (containers, VMs, VPN) are hidden.",
				hidden), hidden);

		gtk_label_set_text (GTK_LABEL (adapters_note), text);
		gtk_button_set_label (GTK_BUTTON (adapters_toggle),
		                      show_virtual ? _("Hide them")
		                                   : _("Show them"));
		gtk_widget_show (adapters_note);
		gtk_widget_show (adapters_toggle);
		g_free (text);
	} else if (shown == 0) {
		gtk_label_set_text (GTK_LABEL (adapters_note),
		                    _("No adapter is up."));
		gtk_widget_show (adapters_note);
		gtk_widget_hide (adapters_toggle);
	} else {
		gtk_widget_hide (adapters_note);
		gtk_widget_hide (adapters_toggle);
	}

	/* Traffic now. */
	{
		gchar *rate = format_rate (total_rate);
		gchar *rx = format_bytes (total_rx);
		gchar *tx = format_bytes (total_tx);
		gchar *note = g_strdup_printf (DOWN "%s" DOT UP "%s", rx, tx);

		set_total (TOTAL_TRAFFIC, rate, note);
		push_spark_value (TOTAL_TRAFFIC, (gdouble) total_rate);
		g_free (rate);
		g_free (rx);
		g_free (tx);
		g_free (note);
	}

	/* "eth0 . 192.168.1.20", for the subtitle. */
	g_free (primary_where);
	primary_where = primary != NULL
		? g_strdup_printf ("%s" DOT "%s", primary->device, primary->ip)
		: NULL;
	update_subtitle ();

	/* The backend documents the lists as caller-owned; freeing them
	 * here is what keeps a 2 second timer from leaking every sample. */
	g_list_free_full (stats, (GDestroyNotify) fs_iface_stat_free);
}

/* [ update_subtitle ]
 * "This computer . HomeNet (Wi-Fi) . Private network" where the backend
 * knows the network (Windows), else "This computer . eth0 .
 * 192.168.1.20", else "This computer".  Called by both refreshers: the
 * network place does not depend on adapter counters being readable. */
static void
update_subtitle (void)
{
	if (subtitle_label != NULL) {
		gchar *where = fs_network_place_subtitle (net_place);
		const gchar *tail = where != NULL ? where : primary_where;
		gchar *text = tail != NULL
			? g_strdup_printf ("%s" DOT "%s", _("This computer"),
			                   tail)
			: g_strdup (_("This computer"));

		g_free (where);

		gtk_label_set_text (GTK_LABEL (subtitle_label), text);
		g_free (text);
	}
}

static void
on_adapters_toggle (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;

	show_virtual = !show_virtual;
	refresh_network ();
}

/* --------------------------------------------------------- connections */

/* [ store_set_nth ]
 * Sets row N, appending it when the store has not reached N yet.  Going
 * row by row like this keeps the scroll position and selection stable
 * across refreshes, which clear-and-refill would throw away every
 * couple of seconds. */
static void
conn_set_nth (gint n, GdkPixbuf *icon, const gchar *program, const gchar *remote,
              const gchar *port, const gchar *service,
              const gchar *direction, gboolean local,
              const gchar *local_end, const gchar *state)
{
	GtkTreeIter iter;

	if (!gtk_tree_model_iter_nth_child (GTK_TREE_MODEL (conn_store),
	                                    &iter, NULL, n))
		gtk_list_store_append (conn_store, &iter);

	gtk_list_store_set (conn_store, &iter,
	                    CONN_COL_ICON, icon,
	                    CONN_COL_PROGRAM, program,
	                    CONN_COL_REMOTE, remote,
	                    CONN_COL_PORT, port,
	                    CONN_COL_SERVICE, service,
	                    CONN_COL_DIRECTION, direction,
	                    CONN_COL_LOCAL, local,
	                    CONN_COL_LOCAL_END, local_end,
	                    CONN_COL_STATE, state,
	                    -1);
}

/* A connection whose owner could not be read: the backends write "?"
 * (another user's socket without root, a protected process), or
 * nothing at all. */
static gboolean
program_is_unknown (const gchar *program)
{
	return program == NULL || *program == '\0' ||
	       strcmp (program, "?") == 0;
}

/* ---------------------------------------------------- busiest programs */

typedef struct
{
	const gchar *name;
	guint        count;
} BusyEntry;

/* Most connections first; the name settles a tie, so two polls of the
 * same sockets give the same order. */
static gint
busy_compare (gconstpointer a, gconstpointer b)
{
	const BusyEntry *x = a, *y = b;

	if (x->count != y->count)
		return x->count > y->count ? -1 : 1;
	return g_strcmp0 (x->name, y->name);
}

/* [ update_busiest ]
 * Ranks the programs of the last sample (name -> open connections to
 * other computers) and writes the top few into the card's rows, in
 * place.  A NULL table means the backend cannot list connections. */
static void
update_busiest (GHashTable *counts)
{
	GArray *entries;
	GHashTableIter iter;
	gpointer key, value;

	for (guint i = 0; i < BUSY_MAX; i++)
		g_clear_pointer (&busy_name[i], g_free);
	busy_n = 0;

	if (counts == NULL)
		return;

	entries = g_array_new (FALSE, FALSE, sizeof (BusyEntry));
	g_hash_table_iter_init (&iter, counts);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		BusyEntry entry = { key, GPOINTER_TO_UINT (value) };

		g_array_append_val (entries, entry);
	}
	g_array_sort (entries, busy_compare);

	for (guint i = 0; i < entries->len && i < BUSY_MAX; i++) {
		const BusyEntry *entry = &g_array_index (entries, BusyEntry, i);

		busy_name[i] = g_strdup (entry->name);
		busy_count[i] = entry->count;
		busy_n++;
	}
	g_array_free (entries, TRUE);

	if (busy_card == NULL)
		return;

	for (guint i = 0; i < BUSY_MAX; i++) {
		BusyRow *row = &busy_rows[i];
		gboolean used = i < busy_n;

		if (used) {
			gchar *count = g_strdup_printf ("%u", busy_count[i]);

			gtk_label_set_text (GTK_LABEL (row->name), busy_name[i]);
			gtk_widget_set_tooltip_text (row->name, busy_name[i]);
			gtk_label_set_text (GTK_LABEL (row->count), count);
			g_free (count);
			gtk_widget_queue_draw (row->bar);
		}
		gtk_widget_set_visible (row->box, used);
	}
	gtk_widget_set_visible (busy_list, busy_n > 0);
	gtk_widget_set_visible (busy_empty, busy_n == 0);
}

gchar **
fs_statusview_busiest_programs (void)
{
	gchar **out = g_new0 (gchar *, busy_n + 1);

	for (guint i = 0; i < busy_n; i++)
		out[i] = g_strdup_printf ("%s\t%u", busy_name[i], busy_count[i]);
	return out;
}

/* [ on_busy_bar_draw ]
 * A row's bar: its share of the busiest program's connections, so the
 * first row is always full and the rest are read against it. */
static gboolean
on_busy_bar_draw (GtkWidget *widget, cairo_t *cr, gpointer data)
{
	guint n = GPOINTER_TO_UINT (data);
	gdouble w = (gdouble) gtk_widget_get_allocated_width (widget);
	gdouble h = (gdouble) gtk_widget_get_allocated_height (widget);
	gdouble len, r = 3.0, y;

	if (n >= busy_n || busy_count[0] == 0 || w < 4 || h < 4)
		return FALSE;

	y = (gdouble) (gint) ((h - 2 * r) / 2);
	len = (gdouble) busy_count[n] / (gdouble) busy_count[0] * w;
	/* Never less than a dot: one connection beside two hundred is
	 * still a connection. */
	len = MAX (len, 2 * r);

	cairo_new_sub_path (cr);
	cairo_arc (cr, len - r, y + r, r, -G_PI / 2, G_PI / 2);
	cairo_arc (cr, r, y + r, r, G_PI / 2, 3 * G_PI / 2);
	cairo_close_path (cr);
	fs_theme_source (cr, "fs_accent", "#5aa2ff", 0.40);
	cairo_fill (cr);
	return FALSE;
}

static void
conn_trim (gint keep)
{
	GtkTreeIter iter;

	while (gtk_tree_model_iter_n_children (GTK_TREE_MODEL (conn_store),
	                                       NULL) > keep &&
	       gtk_tree_model_iter_nth_child (GTK_TREE_MODEL (conn_store),
	                                      &iter, NULL, keep))
		gtk_list_store_remove (conn_store, &iter);
}

static gboolean
conn_visible (GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
	const gchar *needle;
	gchar *fields[5] = { NULL };
	gboolean local = FALSE, visible;

	(void) data;

	gtk_tree_model_get (model, iter,
	                    CONN_COL_PROGRAM, &fields[0],
	                    CONN_COL_REMOTE, &fields[1],
	                    CONN_COL_PORT, &fields[2],
	                    CONN_COL_SERVICE, &fields[3],
	                    CONN_COL_DIRECTION, &fields[4],
	                    CONN_COL_LOCAL, &local, -1);

	needle = conn_search != NULL
	         ? gtk_entry_get_text (GTK_ENTRY (conn_search)) : NULL;
	visible = (show_local || !local) &&
	          fs_util_filter_match (needle, (const gchar *const *) fields, 5);

	for (gint i = 0; i < 5; i++)
		g_free (fields[i]);
	return visible;
}

static void
update_conn_note (guint total, guint local)
{
	guint visible = (guint) gtk_tree_model_iter_n_children (conn_filter,
	                                                        NULL);
	const gchar *needle = gtk_entry_get_text (GTK_ENTRY (conn_search));
	gchar *text = NULL;

	if (total == 0)
		text = g_strdup (_("No open connections right now."));
	else if (visible == 0 && needle != NULL && *needle != '\0')
		text = g_strdup_printf (_("No connection matches \"%s\"."),
		                        needle);
	else if (local > 0)
		text = show_local
			? g_strdup_printf (g_dngettext (NULL,
				"Showing %u local connection (between programs "
				"on this computer).",
				"Showing %u local connections (between programs "
				"on this computer).", local), local)
			: g_strdup_printf (g_dngettext (NULL,
				"%u local connection (between programs on this "
				"computer) is hidden.",
				"%u local connections (between programs on this "
				"computer) are hidden.", local), local);

	gtk_widget_set_visible (conn_note, text != NULL);
	if (text != NULL)
		gtk_label_set_text (GTK_LABEL (conn_note), text);
	gtk_widget_set_visible (conn_toggle, local > 0 && total > 0);
	gtk_button_set_label (GTK_BUTTON (conn_toggle),
	                      show_local ? _("Hide them") : _("Show them"));
	g_free (text);
}

static void
refresh_connections (void)
{
	const FsBackend *backend = fs_backend ();
	GList *conns, *l;
	GHashTable *programs;
	/* One name for every connection whose owner could not be read. */
	const gchar *unknown = _("Unknown program");
	guint row = 0, local = 0, remote_count = 0;

	if (conn_store == NULL || connections_card == NULL)
		return;

	if (backend->list_connections == NULL) {
		gtk_widget_set_no_show_all (connections_card, TRUE);
		gtk_widget_hide (connections_card);
		/* The ranking is of the same list: no list, no card. */
		gtk_widget_set_no_show_all (busy_card, TRUE);
		gtk_widget_hide (busy_card);
		update_busiest (NULL);
		set_total (TOTAL_CONN, "-", _("Not reported here"));
		return;
	}

	conns = backend->list_connections ();
	/* Program -> how many connections to other computers it has open. */
	programs = g_hash_table_new (g_str_hash, g_str_equal);

	for (l = conns; l != NULL; l = l->next) {
		FsConnection *c = l->data;
		/* Both backends put this computer's end in `source' and
		 * the other computer's in `destination', whichever side
		 * opened the connection. */
		const gchar *remote = c->destination;
		const gchar *here = c->source;
		gboolean is_local = fs_util_is_loopback_address (c->source) &&
		                    fs_util_is_loopback_address (c->destination);
		gchar *local_end = NULL;

		if (here != NULL && *here != '\0')
			local_end = c->local_port != 0
				? g_strdup_printf (_("%s, port %u"), here,
				                   c->local_port)
				: g_strdup (here);

		conn_set_nth ((gint) row,
			              NULL,
		              c->program != NULL ? c->program : "",
		              remote != NULL ? remote : "",
		              c->port != NULL ? c->port : "",
		              c->service != NULL ? c->service : "",
		              c->direction != NULL ? c->direction : "",
		              is_local,
		              local_end != NULL ? local_end : "",
		              c->state != NULL ? c->state : "");
		g_free (local_end);
		row++;

		if (is_local) {
			local++;
		} else {
			const gchar *name = program_is_unknown (c->program)
			                    ? unknown : c->program;
			guint n = GPOINTER_TO_UINT (g_hash_table_lookup (programs,
			                                                 name));

			remote_count++;
			g_hash_table_insert (programs, (gpointer) name,
			                     GUINT_TO_POINTER (n + 1));
		}
	}

	update_busiest (programs);

	conn_trim ((gint) row);
	conn_total = row;
	conn_local = local;
	gtk_tree_model_filter_refilter (GTK_TREE_MODEL_FILTER (conn_filter));
	update_conn_note (row, local);

	{
		gchar *value = g_strdup_printf ("%u", remote_count);
		guint n = g_hash_table_size (programs);
		gchar *note = g_strdup_printf (g_dngettext (NULL, "%u program",
		                                            "%u programs", n), n);

		set_total (TOTAL_CONN, value, note);
		push_spark_value (TOTAL_CONN, (gdouble) remote_count);
		g_free (value);
		g_free (note);
	}

	/* The program names are borrowed from the list: drop the set
	 * before the list it points into. */
	g_hash_table_destroy (programs);
	g_list_free_full (conns, (GDestroyNotify) fs_connection_free);
}

/* Typing and Show/Hide re-filter the last sample; they do not ask the
 * backend to enumerate every socket again. */
static void
refilter_connections (void)
{
	gtk_tree_model_filter_refilter (GTK_TREE_MODEL_FILTER (conn_filter));
	update_conn_note (conn_total, conn_local);
}

static void
on_conn_search_changed (GtkSearchEntry *entry, gpointer data)
{
	(void) entry;
	(void) data;
	refilter_connections ();
}

static void
on_conn_toggle (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;

	show_local = !show_local;
	refilter_connections ();
}

/* The drawer's "Show in Events": the Events page, filtered to the
 * connection's remote address (as the Copilot's button of that name
 * filters to its finding). */
static void
on_conn_show_events (gpointer data)
{
	const gchar *remote = data;

	if (remote != NULL && *remote != '\0')
		fs_hitview_set_filter (remote);
	fs_app_show_page (FS_PAGE_EVENTS);
}

/* [ on_conn_activated ]
 * Enter or a double click on a connection: its details open in the
 * drawer, with what the list has no column for (this computer's end,
 * the TCP state) and how many connections the same program holds. */
static void
on_conn_activated (GtkTreeView *view, GtkTreePath *path,
                   GtkTreeViewColumn *column, gpointer data)
{
	GtkTreeModel *model = gtk_tree_view_get_model (view);
	GtkTreeIter iter, it;
	gchar *program = NULL, *remote = NULL, *port = NULL, *service = NULL;
	gchar *direction = NULL, *local_end = NULL, *state = NULL;
	gchar *subtitle, *count, *stamp, *note_text, *remote_copy;
	const gchar *title;
	guint same = 0, same_local = 0;
	gboolean unknown, more;
	GtkWidget *body, *fields, *tally, *note;
	GDateTime *now;
	FsDrawerAction action;

	(void) column;
	(void) data;

	if (conn_store == NULL || !gtk_tree_model_get_iter (model, &iter, path))
		return;

	gtk_tree_model_get (model, &iter,
	                    CONN_COL_PROGRAM, &program,
	                    CONN_COL_REMOTE, &remote,
	                    CONN_COL_PORT, &port,
	                    CONN_COL_SERVICE, &service,
	                    CONN_COL_DIRECTION, &direction,
	                    CONN_COL_LOCAL_END, &local_end,
	                    CONN_COL_STATE, &state, -1);
	unknown = program_is_unknown (program);
	title = unknown ? _("Unknown program") : program;

	/* The same program's connections in the sample on show.  Programs
	 * that could not be named count as one, as on the Busiest programs
	 * card. */
	more = gtk_tree_model_get_iter_first (GTK_TREE_MODEL (conn_store), &it);
	while (more) {
		gchar *other = NULL;
		gboolean is_local = FALSE;

		gtk_tree_model_get (GTK_TREE_MODEL (conn_store), &it,
		                    CONN_COL_PROGRAM, &other,
		                    CONN_COL_LOCAL, &is_local, -1);
		if (unknown ? program_is_unknown (other)
		            : g_strcmp0 (other, program) == 0) {
			if (is_local)
				same_local++;
			else
				same++;
		}
		g_free (other);
		more = gtk_tree_model_iter_next (GTK_TREE_MODEL (conn_store), &it);
	}

	if (port != NULL && *port != '\0')
		subtitle = g_strdup_printf (_("%s, port %s"), remote, port);
	else
		subtitle = g_strdup (remote);

	if (same_local > 0)
		count = g_strdup_printf (_("%u to other computers, and %u "
		                           "between programs on this computer"),
		                         same, same_local);
	else
		count = g_strdup_printf (_("%u to other computers"), same);

	body = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	fields = fs_drawer_fields_new ();
	fs_drawer_field (fields, _("Program"), title, !unknown);
	fs_drawer_field (fields, _("Remote address"), remote, TRUE);
	fs_drawer_field (fields, _("Port"), port, TRUE);
	fs_drawer_field (fields, _("Service"), service, FALSE);
	fs_drawer_field (fields, _("Direction"), direction, FALSE);
	fs_drawer_field (fields, _("Local address"), local_end, TRUE);
	fs_drawer_field (fields, _("State"), state, FALSE);
	gtk_box_pack_start (GTK_BOX (body), fields, FALSE, FALSE, 0);

	/* The program's count sits under a heading of its own, not in the
	 * grid: a name that long would take the width the addresses need. */
	tally = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
	gtk_box_pack_start (GTK_BOX (tally),
	                    fs_drawer_section (unknown
	                        ? _("Open connections of unnamed programs")
	                        : _("Open connections of this program")),
	                    FALSE, FALSE, 0);
	note = label_new (count, "fs-drawer-value", 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (note), TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (note), 40);
	gtk_box_pack_start (GTK_BOX (tally), note, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (body), tally, FALSE, FALSE, 0);

	/* A connection is a moment: say which one this was. */
	now = g_date_time_new_now_local ();
	stamp = g_date_time_format (now, "%H:%M:%S");
	note_text = g_strdup_printf (_("As listed at %s. The connection may "
	                               "have closed since."), stamp);
	note = label_new (note_text, "muted", 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (note), TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (note), 40);
	gtk_box_pack_start (GTK_BOX (body), note, FALSE, FALSE, 0);
	g_date_time_unref (now);
	g_free (stamp);
	g_free (note_text);

	/* The action's address lives as long as the body it belongs to. */
	remote_copy = g_strdup (remote);
	g_object_set_data_full (G_OBJECT (body), "fs-conn-remote", remote_copy,
	                        g_free);
	action.label = _("Show in Events");
	action.klass = "btn-subtle";
	action.run = on_conn_show_events;
	action.data = remote_copy;

	fs_drawer_open (&conn_drawer_owner, title, subtitle, body, &action, 1);

	g_free (subtitle);
	g_free (count);
	g_free (program);
	g_free (remote);
	g_free (port);
	g_free (service);
	g_free (direction);
	g_free (local_end);
	g_free (state);
}

void
fs_statusview_intel_changed (void)
{
	update_overview ();
}

void
fs_statusview_refresh (void)
{
	refresh_network ();
	refresh_connections ();
}

/* [ on_net_timeout ] [ on_conn_timeout ]
 * g_timeout_add wants a gboolean back; these return TRUE to keep the
 * timer running. */
static gboolean
on_net_timeout (gpointer data)
{
	(void) data;
	refresh_network ();
	return TRUE;
}

static gboolean
on_conn_timeout (gpointer data)
{
	(void) data;
	refresh_connections ();
	return TRUE;
}

static gboolean
on_place_timeout (gpointer data)
{
	(void) data;
	refresh_place (TRUE);
	return TRUE;
}

/* --------------------------------------------------------------- actions */

/* [ the blocklists follow Start and Stop ]
 * Design 6.5: a Stop removes the threat-intel blocklists and records
 * them as suspended, a Start applies them again through the gate,
 * under the same hold as any apply.  The work (reading this computer's
 * addresses, resolving the feeds' hosts, loading up to hundreds of
 * thousands of addresses) runs off the main loop, one job at a time and
 * in order, so a Stop followed at once by a Start never races; a
 * failure is shown once it is known.  Nothing happens where no list
 * was ever turned on. */
typedef struct
{
	gboolean start;
	gchar   *source;
	gchar   *hold;
	gchar   *error;   /* set by the worker; NULL when they followed */
	gchar   *notes;
	gchar   *not_in_force; /* applied, but the firewall does not
	                        * enforce them (Windows: off for the
	                        * profile in use): why */
} IntelJob;

static GThreadPool *intel_pool;

static void
intel_job_free (IntelJob *job)
{
	g_free (job->source);
	g_free (job->hold);
	g_free (job->error);
	g_free (job->notes);
	g_free (job->not_in_force);
	g_free (job);
}

static gboolean
intel_job_done (gpointer data)
{
	IntelJob *job = data;

	if (job->error != NULL) {
		gchar *text = job->notes != NULL
		              ? g_strdup_printf ("%s\n\n%s", job->error,
		                                 job->notes)
		              : g_strdup (job->error);

		fs_dialogs_error (NULL, job->start
			? _("The firewall started, but its blocklists could not "
			    "be applied")
			: _("The firewall stopped, but its blocklists could not "
			    "be removed"), text);
		g_free (text);
	} else if (job->not_in_force != NULL) {
		/* Applied, and blocking nothing: said as plainly as a
		 * failure, never left to read as "in force" [S10]. */
		fs_dialogs_error (NULL, _("The firewall started, but its "
		                          "blocklists are not in force"),
		                  job->not_in_force);
	}
	intel_job_free (job);
	/* The engine's state changed (Stop took the lists down, Start put
	 * them back): the Overview and the tray read it again now, not at
	 * the Threat Intel page's next tick (review T1). */
	fs_intelview_refresh ();
	return G_SOURCE_REMOVE;
}

static void
intel_job_run (gpointer data, gpointer user_data)
{
	IntelJob *job = data;
	const FsBackend *backend = fs_backend ();
	GError *error = NULL;

	(void) user_data;
	if (job->start) {
		FsIntelOutcome *o = fs_intel_resume (backend, job->source,
		                                     job->hold, &error);

		if (o != NULL && o->result == FS_APPLY_FAILED && error == NULL)
#ifdef G_OS_WIN32
			job->error = g_strdup (_("Windows Firewall does not hold "
			                         "them."));
#else
			job->error = g_strdup (_("The kernel does not hold them."));
#endif
		if (o != NULL && o->result == FS_APPLY_OK &&
		    o->not_in_force != NULL)
			job->not_in_force = g_strdup (o->not_in_force);
		if (o != NULL && o->notes != NULL && o->notes->len > 0) {
			GString *notes = g_string_new (NULL);

			for (guint i = 0; i < o->notes->len; i++)
				g_string_append_printf (notes, "%s%s",
				                        i ? "\n" : "",
				                        (gchar *) o->notes->pdata[i]);
			job->notes = g_string_free (notes, FALSE);
		}
		fs_intel_outcome_free (o);
	} else {
		fs_intel_suspend (backend, job->source, &error);
	}
	if (error != NULL && job->error == NULL)
		job->error = g_strdup (error->message);
	g_clear_error (&error);
	g_idle_add (intel_job_done, job);
}

void
fs_statusview_intel_follow (gboolean start, const gchar *source)
{
	IntelJob *job = g_new0 (IntelJob, 1);

	job->start = start;
	job->source = g_strdup (source);
	/* The same hold as every apply the page makes: audit-only mode,
	 * or the Overview's Lock.  A Start under the Lock leaves the lists
	 * not loaded rather than load a change the Lock was holding. */
	job->hold = g_strdup (fs_intelview_hold_reason ());
	/* One thread at most: the jobs run in the order pushed. */
	if (intel_pool == NULL)
		intel_pool = g_thread_pool_new (intel_job_run, NULL, 1, FALSE,
		                                NULL);
	g_thread_pool_push (intel_pool, job, NULL);
}

/* [ fs_statusview_firewall_start ] -- see fs-statusview.h.  Through
 * the start gate, so the Start button, the tray's Resume and the start
 * on launch are held, refused and audited the same way. */
gboolean
fs_statusview_firewall_start (GtkWidget *parent, const gchar *source)
{
	FsStartReport report =
		fs_statusview_firewall_start_report (parent, source);

	return report == FS_START_RUNNING || report == FS_START_RUNNING_HELD;
}

/* [ fs_statusview_firewall_start_report ] -- see fs-statusview.h. */
FsStartReport
fs_statusview_firewall_start_report (GtkWidget *parent, const gchar *source)
{
	const FsBackend *backend = fs_backend ();
	FsApplyOutcome *outcome;
	GError *error = NULL;
	gboolean started, had_journal;
	FsStartReport report = FS_START_FAILED;

	if (shared_policy == NULL) {
		/* Never start on a policy nobody loaded: on Linux that
		 * would install an empty ruleset over the real one. */
		fs_dialogs_error (parent, _("Failed to start the firewall"),
		                  _("The policy has not been loaded yet."));
		return FS_START_FAILED;
	}

	{
		gchar *journal = fs_apply_journal_path ();

		had_journal = g_file_test (journal, G_FILE_TEST_EXISTS);
		g_free (journal);
	}
	outcome = fs_firewall_start_safe (backend, shared_policy,
	                                  source != NULL ? source : "window",
	                                  fs_policyview_hold_reason (),
	                                  &error);
	started = (outcome->result == FS_APPLY_OK);

	if (outcome->result == FS_APPLY_DRY_RUN) {
		gchar *why;

		report = FS_START_HELD;
		why = g_strdup_printf (
			_("Changes are being held (%s) and no policy has been "
			  "applied before, so there is nothing safe to start "
			  "with.  Turn the hold off on the Policy page, then "
			  "start the firewall."),
			outcome->hold_reason != NULL ? outcome->hold_reason
			                             : "");

		fs_dialogs_info (parent, _("The firewall was not started"),
		                 why);
		g_free (why);
	} else if (!started) {
		fs_dialogs_error (parent, _("Failed to start the firewall"),
		                  error != NULL ? error->message
		                  : fs_util_apply_result_to_string (
		                        (int) outcome->result));
	} else {
		report = (outcome->held && backend->start_applies_policy)
		       ? FS_START_RUNNING_HELD : FS_START_RUNNING;
		fs_statusview_set_state (backend->get_state != NULL
		                         ? backend->get_state () : FS_FW_NONE);
		/* The blocklists follow the Start (off the main loop). */
		fs_statusview_intel_follow (TRUE, source != NULL ? source
		                                                 : "window");

		if (outcome->held && backend->start_applies_policy) {
			gchar *why = g_strdup_printf (
				_("The firewall is running the last policy that "
				  "was applied.  Changes made since then stay "
				  "held (%s)."),
				outcome->hold_reason != NULL
				? outcome->hold_reason : "");

			fs_dialogs_info (parent,
			                 _("Firewall started with the last "
			                   "applied policy"), why);
			g_free (why);
		} else if (had_journal && backend->start_applies_policy &&
		           (outcome->impact->added > 0 ||
		            outcome->impact->removed > 0)) {
			/* A start brings back what was applied; saved changes
			 * that never were stay off until Apply.  Say so, or
			 * the Policy page reads as if it were in force. */
			GString *why = g_string_new (
				_("The firewall is running the last policy that "
				  "was applied.  Changes saved on the Policy page "
				  "since then are not in force yet: apply them "
				  "there to put them live."));

			if (outcome->notes != NULL)
				g_string_append_printf (why, "\n\n%s",
				                        outcome->notes);
			fs_dialogs_info (parent,
			                 _("Firewall started with the last "
			                   "applied policy"), why->str);
			g_string_free (why, TRUE);
		} else if (outcome->notes != NULL) {
			/* Started, with notes: what the policy in force does
			 * not cover (a block whose name could not be looked
			 * up, IPv6 without ip6tables).  The user pressed
			 * Start, so this is the moment. */
			fs_dialogs_info (parent,
			                 _("Firewall started, with notes"),
			                 outcome->notes);
		}
	}

	g_clear_error (&error);
	fs_apply_outcome_free (outcome);
	return report;
}

/* [ fs_statusview_stop_consequence ] -- see fs-statusview.h. */
const gchar *
fs_statusview_stop_consequence (void)
{
	if (fs_backend ()->start_applies_policy)
		return _("StockFW takes its rules out of the firewall.  Until "
		         "you resume, the ports and addresses your policy "
		         "blocks are no longer blocked.\n\nEvent monitoring "
		         "keeps running.  Resume protection puts the policy "
		         "back.");

	return _("Windows Defender Firewall is switched off for every "
	         "network profile (Domain, Private and Public).  Until you "
	         "resume, nothing is filtered.\n\nYour rules are kept.  "
	         "Resume protection switches the profiles back on.");
}

/* [ fs_statusview_firewall_stop ] -- see fs-statusview.h. */
gboolean
fs_statusview_firewall_stop (GtkWidget *parent, const gchar *source)
{
	const FsBackend *backend = fs_backend ();
	GtkWidget *dialog, *button;
	GError *error = NULL;
	gint response;

	dialog = gtk_message_dialog_new (parent != NULL
	                                 ? GTK_WINDOW (parent) : NULL,
	                                 GTK_DIALOG_MODAL,
	                                 GTK_MESSAGE_WARNING,
	                                 GTK_BUTTONS_NONE,
	                                 "%s", _("Pause protection?"));
	gtk_window_set_title (GTK_WINDOW (dialog), _("Pause protection"));
	gtk_message_dialog_format_secondary_text (
		GTK_MESSAGE_DIALOG (dialog), "%s",
		fs_statusview_stop_consequence ());
	gtk_dialog_add_button (GTK_DIALOG (dialog), _("_Cancel"),
	                       GTK_RESPONSE_CANCEL);
	button = gtk_dialog_add_button (GTK_DIALOG (dialog),
	                                _("_Pause protection"),
	                                GTK_RESPONSE_ACCEPT);
	gtk_style_context_add_class (gtk_widget_get_style_context (button),
	                             "destructive-action");
	/* Enter must not switch a firewall off: Cancel is the default. */
	gtk_dialog_set_default_response (GTK_DIALOG (dialog),
	                                 GTK_RESPONSE_CANCEL);
	gtk_window_set_keep_above (GTK_WINDOW (dialog), TRUE);

	response = gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);

	if (response != GTK_RESPONSE_ACCEPT)
		return FALSE;

	if (!fs_firewall_stop_logged (backend,
	                              source != NULL ? source : "window",
	                              &error)) {
		fs_dialogs_error (parent, _("Failed to stop the firewall"),
		                  error ? error->message : NULL);
		g_clear_error (&error);
		return FALSE;
	}

	fs_statusview_set_state (backend->get_state != NULL
	                         ? backend->get_state () : FS_FW_NONE);
	fs_statusview_intel_follow (FALSE, source != NULL ? source : "window");
	return TRUE;
}

static void
on_power_clicked (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;

	if (state_is_running (current_state))
		fs_statusview_firewall_stop (gtk_widget_get_toplevel (
		                                 GTK_WIDGET (button)),
		                             "window");
	else
		fs_statusview_firewall_start (gtk_widget_get_toplevel (
		                                  GTK_WIDGET (button)),
		                              "window");
}

static void
on_view_events (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;
	fs_app_show_page (FS_PAGE_EVENTS);
}

static void
sync_lock_button (void)
{
	if (lock_button == NULL)
		return;

	g_signal_handlers_block_matched (lock_button, G_SIGNAL_MATCH_DATA,
	                                 0, 0, NULL, NULL, &lock_button);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (lock_button),
	                              policy_locked);
	g_signal_handlers_unblock_matched (lock_button, G_SIGNAL_MATCH_DATA,
	                                   0, 0, NULL, NULL, &lock_button);
	gtk_label_set_text (GTK_LABEL (lock_label),
	                    policy_locked ? _("Policy locked")
	                                  : _("Lock policy"));
	fs_icon_set_kind (lock_icon, policy_locked ? FS_ICON_LOCK
	                                           : FS_ICON_UNLOCK);
}

/* [ on_lock_toggled ]
 * A real gate: while locked the Policy page refuses to apply.  Nothing
 * at the OS level is touched, so this is undoable and never leaves the
 * machine with a rule set the user cannot see. */
static void
on_lock_toggled (GtkToggleButton *button, gpointer data)
{
	(void) data;

	policy_locked = gtk_toggle_button_get_active (button);

	if (policy_locked && current_state == FS_FW_RUNNING)
		current_state = FS_FW_LOCKED;
	else if (!policy_locked && current_state == FS_FW_LOCKED)
		current_state = FS_FW_RUNNING;

	fs_statusview_set_state (current_state);
}

gboolean
fs_statusview_policy_locked (void)
{
	return policy_locked;
}

void
fs_statusview_set_state (FsFirewallState state)
{
	current_state = state;

	sync_lock_button ();
	refresh_profiles ();
	/* Re-read the place without judging: refresh_ipv6 judges next,
	 * with everything fresh. */
	refresh_place (FALSE);

	/* The tray's header and tooltip carry the same state, so the
	 * background app answers a glance while the window is hidden.  No
	 * icon up: fs-tray.c keeps it for the next one. */
	fs_tray_set_firewall (state, fs_network_place_kind (net_place));
	fs_statusview_refresh_ipv6 ();
}

/* [ fs_statusview_refresh_ipv6 ] -- see fs-statusview.h.
 * Re-reads the backend's IPv6 answer and re-judges the machine.  A
 * firewall that reads "running" while half the traffic passes
 * unfiltered is exactly the gap 1.0.7 closed, so a not-filtered IPv6
 * turns the whole verdict amber, not a footnote. */
void
fs_statusview_refresh_ipv6 (void)
{
	const FsBackend *backend = fs_backend ();

	g_clear_pointer (&ipv6_detail, g_free);
	ipv6_known = backend->ipv6_state != NULL;
	ipv6_st = ipv6_known ? backend->ipv6_state (&ipv6_detail)
	                     : FS_IPV6_UNKNOWN;

	update_overview ();
}

FsFirewallState
fs_statusview_get_state (void)
{
	return current_state;
}

/* [ fs_statusview_reread_state ] -- see fs-statusview.h. */
void
fs_statusview_reread_state (void)
{
	const FsBackend *backend = fs_backend ();
	FsFirewallState now;

	if (backend->get_state == NULL)
		return;

	now = backend->get_state ();
	if (now == FS_FW_RUNNING && policy_locked)
		now = FS_FW_LOCKED;

	/* On either way: keep the finer state this page already shows
	 * (locked, hit) rather than flatten it. */
	if (now == current_state ||
	    (state_is_running (now) && state_is_running (current_state)))
		return;

	fs_statusview_set_state (now);
}

/* ------------------------------------------------------------------ page */

static GtkWidget *
build_header (void)
{
	GtkWidget *header = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
	GtkWidget *titles = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);

	add_class (header, "page-head");

	gtk_box_pack_start (GTK_BOX (titles),
	                    label_new (_("Overview"), "page-title", 0.0),
	                    FALSE, FALSE, 0);
	subtitle_label = label_new (_("This computer"), "page-subtitle", 0.0);
	gtk_box_pack_start (GTK_BOX (titles), subtitle_label, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (header), titles, TRUE, TRUE, 0);

	lock_button = icon_button_new (FS_ICON_UNLOCK, _("Lock policy"),
	                               &lock_icon, &lock_label, TRUE);
	add_class (lock_button, "btn-subtle");
	gtk_widget_set_valign (lock_button, GTK_ALIGN_CENTER);
	gtk_widget_set_tooltip_text (lock_button,
		_("While locked, the Policy page refuses to apply changes."));
	g_signal_connect_data (lock_button, "toggled",
	                       G_CALLBACK (on_lock_toggled), &lock_button,
	                       NULL, 0);
	gtk_box_pack_start (GTK_BOX (header), lock_button, FALSE, FALSE, 0);

	return header;
}

static GtkWidget *
build_hero (void)
{
	static const gchar *captions[N_TILES] = {
		N_("IPv4 traffic"), N_("IPv6 traffic"), N_("Policy"),
		N_("Engine")
	};
	GtkWidget *top, *tile, *text, *facts;

	/* The board: the answer and its one button on top, the four facts
	 * in a strip along the foot.  One card, no boxes inside it. */
	hero = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	add_class (hero, "hero");
	add_class (hero, "level-unknown");

	top = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 18);
	add_class (top, "hero-top");

	tile = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_widget_set_size_request (tile, 56, 56);
	gtk_widget_set_valign (tile, GTK_ALIGN_START);
	add_class (tile, "hero-icon-tile");
	hero_icon = fs_icon_new (FS_ICON_SHIELD_QUESTION, 30);
	add_class (hero_icon, "hero-icon");
	gtk_box_pack_start (GTK_BOX (tile), hero_icon, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (top), tile, FALSE, FALSE, 0);

	text = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	/* The state in one word, large enough to read from across the
	 * room; update_overview () writes the verdict's own word into it
	 * and the card's level colours it. */
	state_word = label_new (NULL, "state-word", 0.0);
	gtk_label_set_ellipsize (GTK_LABEL (state_word), PANGO_ELLIPSIZE_END);
	gtk_box_pack_start (GTK_BOX (text), state_word, FALSE, FALSE, 0);
	hero_title = label_new (NULL, "hero-title", 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (hero_title), TRUE);
	gtk_box_pack_start (GTK_BOX (text), hero_title, FALSE, FALSE, 0);
	hero_body = label_new (NULL, "hero-body", 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (hero_body), TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (hero_body), 76);
	gtk_box_pack_start (GTK_BOX (text), hero_body, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (top), text, TRUE, TRUE, 0);

	/* The one control that changes the state. */
	power_button = icon_button_new (FS_ICON_PLAY, _("Start firewall"),
	                                &power_icon, &power_label, FALSE);
	add_class (power_button, "btn-primary");
	add_class (power_button, "power-button");
	gtk_widget_set_valign (power_button, GTK_ALIGN_CENTER);
	g_signal_connect (power_button, "clicked",
	                  G_CALLBACK (on_power_clicked), NULL);
	gtk_box_pack_start (GTK_BOX (top), power_button, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (hero), top, FALSE, FALSE, 0);

	/* Four facts, side by side. */
	facts = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	add_class (facts, "hero-facts");
	gtk_box_set_homogeneous (GTK_BOX (facts), TRUE);

	for (gint i = 0; i < N_TILES; i++) {
		GtkWidget *fact = gtk_box_new (GTK_ORIENTATION_VERTICAL, 3);

		add_class (fact, "hero-tile");
		if (i > 0)
			add_class (fact, "hero-tile-next");
		gtk_box_pack_start (GTK_BOX (fact),
		                    label_new (_(captions[i]), "tile-caption", 0.0),
		                    FALSE, FALSE, 0);
		tile_value[i] = label_new ("", "tile-value", 0.0);
		gtk_label_set_ellipsize (GTK_LABEL (tile_value[i]),
		                         PANGO_ELLIPSIZE_END);
		gtk_box_pack_start (GTK_BOX (fact), tile_value[i], FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (facts), fact, TRUE, TRUE, 0);
	}
	gtk_box_pack_start (GTK_BOX (hero), facts, FALSE, FALSE, 0);

	return hero;
}

/* [ build_traffic ]
 * The live graph: what the real adapters received and sent, one point
 * per network refresh, two minutes wide. */
static GtkWidget *
build_traffic (void)
{
	GtkWidget *card = card_new (GTK_ORIENTATION_VERTICAL, 8);
	GtkWidget *head = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
	GtkWidget *dot, *label;
	AtkObject *atk;

	add_class (card, "padded-card");
	add_class (card, "traffic-card");

	gtk_box_pack_start (GTK_BOX (head),
	                    label_new (_("Traffic"), "card-heading", 0.0),
	                    FALSE, FALSE, 0);

	/* The legend, with the two newest numbers, straight after the
	 * heading.  The numbers have a fixed width, so the legend does not
	 * shift as they change every two seconds. */
	traffic_legend = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_widget_set_margin_start (traffic_legend, 8);

	dot = fs_icon_new (FS_ICON_DOT, 8);
	add_class (dot, "legend-received");
	gtk_widget_set_valign (dot, GTK_ALIGN_CENTER);
	gtk_box_pack_start (GTK_BOX (traffic_legend), dot, FALSE, FALSE, 0);
	label = label_new (_("Received"), "legend-name", 0.0);
	gtk_box_pack_start (GTK_BOX (traffic_legend), label, FALSE, FALSE, 0);
	traffic_rx_value = label_new ("-", "legend-value", 0.0);
	gtk_label_set_width_chars (GTK_LABEL (traffic_rx_value), 12);
	gtk_box_pack_start (GTK_BOX (traffic_legend), traffic_rx_value,
	                    FALSE, FALSE, 0);

	dot = fs_icon_new (FS_ICON_DOT, 8);
	add_class (dot, "legend-sent");
	gtk_widget_set_valign (dot, GTK_ALIGN_CENTER);
	gtk_box_pack_start (GTK_BOX (traffic_legend), dot, FALSE, FALSE, 0);
	label = label_new (_("Sent"), "legend-name", 0.0);
	gtk_box_pack_start (GTK_BOX (traffic_legend), label, FALSE, FALSE, 0);
	traffic_tx_value = label_new ("-", "legend-value", 0.0);
	gtk_label_set_width_chars (GTK_LABEL (traffic_tx_value), 12);
	gtk_box_pack_start (GTK_BOX (traffic_legend), traffic_tx_value,
	                    FALSE, FALSE, 0);
	/* Shown by update_traffic_labels (), while there are counters. */
	gtk_widget_show_all (traffic_legend);
	gtk_widget_hide (traffic_legend);
	gtk_widget_set_no_show_all (traffic_legend, TRUE);
	gtk_box_pack_start (GTK_BOX (head), traffic_legend, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (card), head, FALSE, FALSE, 0);

	traffic_area = gtk_drawing_area_new ();
	gtk_widget_set_size_request (traffic_area, -1, 150);
	gtk_widget_set_has_tooltip (traffic_area, TRUE);
	atk = gtk_widget_get_accessible (traffic_area);
	if (atk != NULL)
		atk_object_set_name (atk, _("Graph of adapter traffic over the "
		                            "last two minutes"));
	g_signal_connect (traffic_area, "draw", G_CALLBACK (on_traffic_draw),
	                  NULL);
	g_signal_connect (traffic_area, "query-tooltip",
	                  G_CALLBACK (on_traffic_tooltip), NULL);
	gtk_box_pack_start (GTK_BOX (card), traffic_area, FALSE, FALSE, 0);

	traffic_note = label_new (NULL, "muted", 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (traffic_note), TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (traffic_note), 90);
	gtk_widget_set_tooltip_text (traffic_note,
		_("Bytes per second over the real adapters, read every two "
		  "seconds. Virtual adapters are left out so bridged traffic is "
		  "not counted twice."));
	gtk_box_pack_start (GTK_BOX (card), traffic_note, FALSE, FALSE, 0);

	update_traffic_labels ();
	return card;
}

/* [ build_busiest ]
 * The programs with the most open connections, as a small bar chart. */
static GtkWidget *
build_busiest (void)
{
	GtkWidget *note;

	busy_card = card_new (GTK_ORIENTATION_VERTICAL, 10);
	add_class (busy_card, "padded-card");
	gtk_box_pack_start (GTK_BOX (busy_card),
	                    label_new (_("Busiest programs"), "card-heading",
	                               0.0),
	                    FALSE, FALSE, 0);

	/* One row per rank, there from the start and filled in place by
	 * update_busiest (): the name and the count on a line, the bar
	 * under them across the card, so a long name has the whole width. */
	busy_list = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	add_class (busy_list, "busy-list");
	gtk_widget_set_no_show_all (busy_list, TRUE);

	for (guint i = 0; i < BUSY_MAX; i++) {
		BusyRow *row = &busy_rows[i];
		GtkWidget *line = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);

		row->box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 5);

		row->name = label_new (NULL, "busy-name", 0.0);
		gtk_label_set_ellipsize (GTK_LABEL (row->name),
		                         PANGO_ELLIPSIZE_MIDDLE);
		gtk_box_pack_start (GTK_BOX (line), row->name, TRUE, TRUE, 0);
		row->count = label_new (NULL, "busy-count", 1.0);
		gtk_box_pack_start (GTK_BOX (line), row->count, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (row->box), line, FALSE, FALSE, 0);

		row->bar = gtk_drawing_area_new ();
		gtk_widget_set_size_request (row->bar, 60, 6);
		g_signal_connect (row->bar, "draw",
		                  G_CALLBACK (on_busy_bar_draw),
		                  GUINT_TO_POINTER (i));
		gtk_box_pack_start (GTK_BOX (row->box), row->bar, FALSE, FALSE, 0);

		gtk_widget_show_all (row->box);
		gtk_widget_hide (row->box);
		gtk_widget_set_no_show_all (row->box, TRUE);
		gtk_box_pack_start (GTK_BOX (busy_list), row->box, FALSE, FALSE, 0);
	}
	gtk_box_pack_start (GTK_BOX (busy_card), busy_list, FALSE, FALSE, 0);

	busy_empty = label_new (_("No open connections right now."), "muted",
	                        0.0);
	gtk_label_set_line_wrap (GTK_LABEL (busy_empty), TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (busy_empty), 40);
	gtk_widget_set_no_show_all (busy_empty, TRUE);
	gtk_widget_show (busy_empty);
	gtk_box_pack_start (GTK_BOX (busy_card), busy_empty, FALSE, FALSE, 0);

	/* What the bars are, and what they are not. */
	note = label_new (_("By number of open TCP connections to other "
	                    "computers, not by data volume."), "muted", 0.0);
	add_class (note, "card-note");
	gtk_label_set_line_wrap (GTK_LABEL (note), TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (note), 40);
	gtk_widget_set_valign (note, GTK_ALIGN_END);
	gtk_box_pack_end (GTK_BOX (busy_card), note, FALSE, FALSE, 0);

	return busy_card;
}

static GtkWidget *
build_profiles (void)
{
	static const gchar *names[FS_PROFILE_COUNT] = {
		N_("Domain"), N_("Private"), N_("Public")
	};
	static const gchar *about[FS_PROFILE_COUNT] = {
		N_("Work networks with a domain controller"),
		N_("Home and other trusted networks"),
		N_("Cafes, airports, hotels and other public places")
	};
	GtkWidget *inner = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	gboolean any = FALSE;

	/* A GtkFrame titled "Firewall profiles": the visibility test finds
	 * it by that title. */
	profiles_frame = gtk_frame_new (_("Firewall profiles"));
	add_class (profiles_frame, "card-frame");
	/* The card draws the border; the frame's own would be a second
	 * box inside it (as the Policy and Copilot cards already do). */
	gtk_frame_set_shadow_type (GTK_FRAME (profiles_frame), GTK_SHADOW_NONE);
	gtk_container_add (GTK_CONTAINER (profiles_frame), inner);

	for (gint i = 0; i < FS_PROFILE_COUNT; i++) {
		GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
		GtkWidget *text = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
		GtkWidget *toggle = gtk_switch_new ();
		gboolean enabled = FALSE;

		add_class (row, "profile-row");
		gtk_box_pack_start (GTK_BOX (text),
		                    label_new (_(names[i]), "profile-label", 0.0),
		                    FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (text),
		                    label_new (_(about[i]), "muted", 0.0),
		                    FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (row), text, TRUE, TRUE, 0);

		/* "In use": the profile protecting a connected network now.
		 * Shown by refresh_place(); no-show-all so the page-wide
		 * show_all() cannot claim a profile is in use. */
		profile_in_use[i] = label_new (_("In use"), "in-use", 0.5);
		gtk_widget_set_valign (profile_in_use[i], GTK_ALIGN_CENTER);
		gtk_widget_set_no_show_all (profile_in_use[i], TRUE);
		gtk_box_pack_start (GTK_BOX (row), profile_in_use[i],
		                    FALSE, FALSE, 0);

		g_object_set_data (G_OBJECT (toggle), "user-data",
		                   GINT_TO_POINTER (i));
		gtk_widget_set_valign (toggle, GTK_ALIGN_CENTER);
		atk_object_set_name (gtk_widget_get_accessible (toggle),
		                     _(names[i]));
		if (fs_backend ()->get_profile_enabled (i, &enabled)) {
			gtk_switch_set_active (GTK_SWITCH (toggle), enabled);
			any = TRUE;
		}
		g_signal_connect (toggle, "notify::active",
		                  G_CALLBACK (on_profile_toggled), NULL);
		gtk_box_pack_start (GTK_BOX (row), toggle, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (inner), row, FALSE, FALSE, 0);

		profile_switches[i] = toggle;
	}

	/* The backend decides whether to show this: Windows has three
	 * profiles, Linux has one global state and hides the card.  It is
	 * marked no-show-all before hiding, because fs-app.c calls
	 * gtk_widget_show_all() on the whole window after this page is
	 * built -- without the flag that walk re-shows the frame and
	 * presents Linux with three switches that can only ever answer
	 * "Linux has a single firewall state". */
	if (!any) {
		gtk_widget_set_no_show_all (profiles_frame, TRUE);
		gtk_widget_hide (profiles_frame);
	}

	return profiles_frame;
}

static GtkWidget *
build_totals (void)
{
	static const gchar *captions[N_TOTALS] = {
		N_("Inbound events"), N_("Outbound events"),
		N_("Open connections"), N_("Traffic now")
	};
	GtkWidget *grid = gtk_grid_new ();

	gtk_grid_set_column_spacing (GTK_GRID (grid), 16);
	gtk_grid_set_column_homogeneous (GTK_GRID (grid), TRUE);

	for (gint i = 0; i < N_TOTALS; i++) {
		GtkWidget *card = card_new (GTK_ORIENTATION_VERTICAL, 4);

		add_class (card, "stat-card");
		gtk_box_pack_start (GTK_BOX (card),
		                    label_new (_(captions[i]), "tile-caption", 0.0),
		                    FALSE, FALSE, 0);
		total_value[i] = label_new ("0", "stat-big", 0.0);
		gtk_box_pack_start (GTK_BOX (card), total_value[i], FALSE, FALSE, 0);

		sparkline_area[i] = gtk_drawing_area_new ();
		gtk_widget_set_size_request (sparkline_area[i], -1, 26);
		g_signal_connect (sparkline_area[i], "draw",
		                  G_CALLBACK (on_sparkline_draw), GINT_TO_POINTER (i));
		gtk_box_pack_start (GTK_BOX (card), sparkline_area[i], FALSE, FALSE, 2);

		total_note[i] = label_new ("", "stat-note", 0.0);
		gtk_label_set_ellipsize (GTK_LABEL (total_note[i]),
		                         PANGO_ELLIPSIZE_END);
		gtk_box_pack_start (GTK_BOX (card), total_note[i], FALSE, FALSE, 0);
		gtk_grid_attach (GTK_GRID (grid), card, i, 0, 1, 1);
	}

	gtk_widget_set_tooltip_text (gtk_widget_get_parent (total_value[TOTAL_IN]),
		_("Events logged since StockFW opened."));
	gtk_widget_set_tooltip_text (gtk_widget_get_parent (total_value[TOTAL_OUT]),
		_("Events logged since StockFW opened."));
	gtk_widget_set_tooltip_text (gtk_widget_get_parent (total_value[TOTAL_CONN]),
		_("Connections to other computers. Local ones are not counted."));
	gtk_widget_set_tooltip_text (gtk_widget_get_parent (total_value[TOTAL_TRAFFIC]),
		_("Right now, and received / sent in total, over the real "
		  "adapters (virtual ones are left out so bridged traffic is "
		  "not counted twice)."));
	return grid;
}

static GtkTreeViewColumn *
conn_icon_column (GtkWidget *view, gint col)
{
	GtkCellRenderer *renderer = gtk_cell_renderer_pixbuf_new ();
	GtkTreeViewColumn *column;

	g_object_set (renderer, "ypad", 6, "xpad", 6, NULL);
	column = gtk_tree_view_column_new_with_attributes ("", renderer,
	                                                   "pixbuf", col, NULL);
	gtk_tree_view_append_column (GTK_TREE_VIEW (view), column);
	return column;
}

/* A "muted" column's ink is the theme's secondary text colour, asked
 * for at each paint so it follows Dark mode. */
static void
muted_cell_data (GtkTreeViewColumn *column, GtkCellRenderer *renderer,
                 GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
	GdkRGBA weak;

	(void) column;
	(void) model;
	(void) iter;
	(void) data;

	fs_theme_color ("fs_text_weak", "#a8a4a4", &weak);
	g_object_set (renderer, "foreground-rgba", &weak, NULL);
}

static GtkTreeViewColumn *
conn_column (GtkWidget *view, const gchar *title, gint col,
             const gchar *klass)
{
	GtkCellRenderer *renderer = gtk_cell_renderer_text_new ();
	GtkTreeViewColumn *column;

	g_object_set (renderer, "ypad", 6, "xpad", 10, NULL);
	if (g_strcmp0 (klass, "mono") == 0)
		g_object_set (renderer, "family", "monospace", NULL);
	else if (g_strcmp0 (klass, "bold") == 0)
		g_object_set (renderer, "weight", PANGO_WEIGHT_SEMIBOLD, NULL);

	column = gtk_tree_view_column_new_with_attributes (title, renderer,
	                                                   "text", col, NULL);
	if (g_strcmp0 (klass, "muted") == 0)
		gtk_tree_view_column_set_cell_data_func (column, renderer,
		                                         muted_cell_data,
		                                         NULL, NULL);
	gtk_tree_view_column_set_resizable (column, TRUE);
	gtk_tree_view_column_set_sort_column_id (column, col);
	gtk_tree_view_append_column (GTK_TREE_VIEW (view), column);
	return column;
}

static GtkWidget *
build_connections (void)
{
	GtkWidget *head, *view, *scroll, *foot;
	GtkTreeModel *sorted;

	connections_card = card_new (GTK_ORIENTATION_VERTICAL, 0);
	add_class (connections_card, "list-card");

	head = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
	add_class (head, "card-head");
	gtk_box_pack_start (GTK_BOX (head),
	                    label_new (_("Open connections"), "card-heading", 0.0),
	                    TRUE, TRUE, 0);
	conn_search = gtk_search_entry_new ();
	gtk_entry_set_placeholder_text (GTK_ENTRY (conn_search),
	                                _("Filter by program, address or service"));
	gtk_entry_set_width_chars (GTK_ENTRY (conn_search), 30);
	gtk_widget_set_valign (conn_search, GTK_ALIGN_CENTER);
	g_signal_connect (conn_search, "search-changed",
	                  G_CALLBACK (on_conn_search_changed), NULL);
	gtk_box_pack_start (GTK_BOX (head), conn_search, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (connections_card), head, FALSE, FALSE, 0);

	conn_store = gtk_list_store_new (CONN_N_COLS, GDK_TYPE_PIXBUF,
	                                 G_TYPE_STRING, G_TYPE_STRING,
	                                 G_TYPE_STRING, G_TYPE_STRING,
	                                 G_TYPE_STRING, G_TYPE_BOOLEAN,
	                                 G_TYPE_STRING, G_TYPE_STRING);
	conn_filter = gtk_tree_model_filter_new (GTK_TREE_MODEL (conn_store),
	                                         NULL);
	gtk_tree_model_filter_set_visible_func (GTK_TREE_MODEL_FILTER (conn_filter),
	                                        conn_visible, NULL, NULL);
	sorted = gtk_tree_model_sort_new_with_model (conn_filter);

	view = gtk_tree_view_new_with_model (sorted);
	g_object_unref (sorted);
	add_class (view, "overview-grid");
	gtk_tree_view_set_enable_search (GTK_TREE_VIEW (view), FALSE);
	/* Enter or a double click opens the row's details in the drawer. */
	g_signal_connect (view, "row-activated",
	                  G_CALLBACK (on_conn_activated), NULL);
	gtk_widget_set_tooltip_text (view, _("Press Enter or double-click a "
	                                     "connection for its details."));
	{
		AtkObject *atk = gtk_widget_get_accessible (view);

		if (atk != NULL)
			atk_object_set_name (atk, _("Open connections"));
	}
	conn_icon_column (view, CONN_COL_ICON);
	conn_column (view, _("Program"), CONN_COL_PROGRAM, "bold");
	conn_column (view, _("Remote address"), CONN_COL_REMOTE, "mono");
	conn_column (view, _("Port"), CONN_COL_PORT, "mono");
	conn_column (view, _("Service"), CONN_COL_SERVICE, NULL);
	conn_column (view, _("Direction"), CONN_COL_DIRECTION, "muted");

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_AUTOMATIC,
	                                GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scroll),
	                                     GTK_SHADOW_NONE);
	gtk_widget_set_size_request (scroll, -1, 200);
	gtk_container_add (GTK_CONTAINER (scroll), view);
	gtk_box_pack_start (GTK_BOX (connections_card), scroll, TRUE, TRUE, 0);

	foot = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	add_class (foot, "card-foot");
	conn_note = label_new ("", "muted", 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (conn_note), TRUE);
	gtk_widget_set_no_show_all (conn_note, TRUE);
	gtk_box_pack_start (GTK_BOX (foot), conn_note, FALSE, FALSE, 0);
	conn_toggle = link_button_new (_("Show them"));
	gtk_widget_set_no_show_all (conn_toggle, TRUE);
	g_signal_connect (conn_toggle, "clicked", G_CALLBACK (on_conn_toggle),
	                  NULL);
	gtk_box_pack_start (GTK_BOX (foot), conn_toggle, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (connections_card), foot, FALSE, FALSE, 0);

	return connections_card;
}

static GtkWidget *
build_adapters (void)
{
	GtkWidget *foot;

	adapters_card = card_new (GTK_ORIENTATION_VERTICAL, 10);
	add_class (adapters_card, "padded-card");
	gtk_box_pack_start (GTK_BOX (adapters_card),
	                    label_new (_("Network adapters"), "card-heading", 0.0),
	                    FALSE, FALSE, 0);

	adapters_list = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	gtk_box_pack_start (GTK_BOX (adapters_card), adapters_list,
	                    FALSE, FALSE, 0);

	foot = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	adapters_note = label_new ("", "muted", 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (adapters_note), TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (adapters_note), 30);
	gtk_widget_set_no_show_all (adapters_note, TRUE);
	gtk_box_pack_start (GTK_BOX (foot), adapters_note, FALSE, FALSE, 0);
	adapters_toggle = link_button_new (_("Show them"));
	gtk_widget_set_no_show_all (adapters_toggle, TRUE);
	g_signal_connect (adapters_toggle, "clicked",
	                  G_CALLBACK (on_adapters_toggle), NULL);
	gtk_box_pack_start (GTK_BOX (foot), adapters_toggle, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (adapters_card), foot, FALSE, FALSE, 0);

	return adapters_card;
}

static GtkWidget *
build_recent (void)
{
	GtkWidget *card = card_new (GTK_ORIENTATION_VERTICAL, 10);
	GtkWidget *foot = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	GtkWidget *all = link_button_new (_("All events"));

	/* Not "padded-card": the rows carry the side padding themselves
	 * (see .recent-card in the theme). */
	add_class (card, "recent-card");
	gtk_box_pack_start (GTK_BOX (card),
	                    label_new (_("Latest blocks"), "card-heading", 0.0),
	                    FALSE, FALSE, 0);

	/* The rows exist from the start; update_recent () fills them. */
	recent_list = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	add_class (recent_list, "recent-list");
	for (guint i = 0; i < RECENT_MAX; i++)
		recent_row_build (i);
	gtk_box_pack_start (GTK_BOX (card), recent_list, FALSE, FALSE, 0);

	recent_empty = label_new (_("Nothing has been blocked since StockFW "
	                            "opened."), "muted", 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (recent_empty), TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (recent_empty), 40);
	gtk_widget_set_no_show_all (recent_empty, TRUE);
	gtk_widget_show (recent_empty);
	gtk_box_pack_start (GTK_BOX (card), recent_empty, FALSE, FALSE, 0);

	/* The whole list is one page away. */
	gtk_widget_set_tooltip_text (all, _("Open the Events page"));
	g_signal_connect (all, "clicked", G_CALLBACK (on_view_events), NULL);
	add_class (foot, "recent-foot");
	gtk_box_pack_start (GTK_BOX (foot), all, FALSE, FALSE, 0);
	gtk_widget_set_valign (foot, GTK_ALIGN_END);
	gtk_box_pack_end (GTK_BOX (card), foot, FALSE, FALSE, 0);

	update_recent ();
	return card;
}

/* [ on_page_destroy ]
 * The page is going: its timers stop and every pointer into it is
 * forgotten, so a late state change or a block noted afterwards finds
 * nothing to write to instead of a freed widget.  What the page has
 * measured (the latest blocks, the event counters) is kept. */
static void
on_page_destroy (GtkWidget *widget, gpointer data)
{
	(void) widget;
	(void) data;

	if (net_timer != 0)
		g_source_remove (net_timer);
	if (conn_timer != 0)
		g_source_remove (conn_timer);
	if (place_timer != 0)
		g_source_remove (place_timer);
	net_timer = conn_timer = place_timer = 0;

	subtitle_label = NULL;
	lock_button = lock_icon = lock_label = NULL;
	hero = hero_icon = hero_title = hero_body = state_word = NULL;
	power_button = power_icon = power_label = NULL;
	profiles_frame = NULL;
	for (gint i = 0; i < N_TILES; i++)
		tile_value[i] = NULL;
	for (gint i = 0; i < FS_PROFILE_COUNT; i++)
		profile_switches[i] = profile_in_use[i] = NULL;
	for (gint i = 0; i < N_TOTALS; i++)
		total_value[i] = total_note[i] = sparkline_area[i] = NULL;

	connections_card = conn_search = conn_note = conn_toggle = NULL;
	g_clear_object (&conn_filter);
	g_clear_object (&conn_store);

	adapters_card = adapters_list = adapters_note = adapters_toggle = NULL;
	g_clear_pointer (&net_samples, g_hash_table_destroy);

	traffic_area = traffic_legend = traffic_note = NULL;
	traffic_rx_value = traffic_tx_value = NULL;
	traffic_known = traffic_started = FALSE;
	traffic_count = 0;

	busy_card = busy_list = busy_empty = NULL;
	memset (busy_rows, 0, sizeof busy_rows);
	for (guint i = 0; i < BUSY_MAX; i++)
		g_clear_pointer (&busy_name[i], g_free);
	busy_n = 0;

	recent_list = recent_empty = NULL;
	memset (recent_rows, 0, sizeof recent_rows);
}

/* [ fs_statusview_page ] */
GtkWidget *
fs_statusview_page (void)
{
	GtkWidget *scroll, *page, *now_row, *lower, *side;

	page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
	add_class (page, "overview");

	/* The answer first: the board, then (Windows) the profiles that
	 * explain and fix it. */
	gtk_box_pack_start (GTK_BOX (page), build_header (), FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), build_hero (), FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), build_profiles (), FALSE, FALSE, 0);

	/* What is happening now: the traffic, then who and what. */
	gtk_box_pack_start (GTK_BOX (page), build_traffic (), FALSE, FALSE, 0);
	now_row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 16);
	gtk_box_set_homogeneous (GTK_BOX (now_row), TRUE);
	gtk_box_pack_start (GTK_BOX (now_row), build_busiest (), TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (now_row), build_recent (), TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (page), now_row, FALSE, FALSE, 0);

	/* The detail: the totals, every connection, every adapter. */
	gtk_box_pack_start (GTK_BOX (page), build_totals (), FALSE, FALSE, 0);
	lower = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 16);
	gtk_box_pack_start (GTK_BOX (lower), build_connections (),
	                    TRUE, TRUE, 0);
	side = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	gtk_widget_set_size_request (side, 300, -1);
	gtk_box_pack_start (GTK_BOX (side), build_adapters (), FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (lower), side, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), lower, TRUE, TRUE, 0);

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_AUTOMATIC,
	                                GTK_POLICY_AUTOMATIC);
	gtk_container_add (GTK_CONTAINER (scroll), page);
	g_signal_connect (scroll, "destroy", G_CALLBACK (on_page_destroy), NULL);

	net_samples = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                     g_free, g_free);

	update_counters ();
	fs_statusview_set_state (FS_FW_NONE);

	net_timer = g_timeout_add (NET_REFRESH_MS, on_net_timeout, NULL);
	conn_timer = g_timeout_add (CONN_REFRESH_MS, on_conn_timeout, NULL);
	if (fs_backend ()->network_place != NULL)
		place_timer = g_timeout_add (PLACE_REFRESH_MS, on_place_timeout,
		                             NULL);

	/* First sample immediately so the panels are not empty for two
	 * seconds after startup. */
	fs_statusview_refresh ();

	return scroll;
}
