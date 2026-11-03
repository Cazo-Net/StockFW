/*---[ fs-statusview.c ]------------------------------------------------
 * The Overview page (1.0.7 redesign; the Status page before it).
 *
 * Top to bottom:
 *   header       "Overview", which machine and address, Lock policy
 *   verdict      one coloured card that says, in a sentence, whether
 *                this computer is protected, with the one button that
 *                changes that (Start or Stop) and four facts beside it:
 *                IPv4, IPv6, the policy, the engine
 *   profiles     Windows only: the three firewall profiles, the ones
 *                in force marked "In use"
 *   totals       events in and out (and how many were blocked), open
 *                connections, traffic now
 *   connections  open connections with a filter box; connections
 *                between two programs on this computer are hidden
 *                behind a "Show them" link, because no rule sees them
 *   adapters     real adapters; virtual ones (Docker bridges, Hyper-V,
 *                VPN tunnels) behind a "Show them" link
 *   recent       the last few blocked events
 *
 * Every number on the page is one the backend reported.  A backend
 * that cannot list connections or adapters gets no card for them, and
 * "Threat intel" is not shown until it exists.
 *--------------------------------------------------------------------*/

#include "ui/fs-statusview.h"
#include "ui/fs-intelview.h"
#include "ui/fs-app.h"
#include "ui/fs-dialogs.h"
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

/* How often the live panels are resampled.  Interface counters are
 * cheap; enumerating sockets is dearer, so it runs less often. */
#define NET_REFRESH_MS    2000
#define CONN_REFRESH_MS   3000
/* The network place and the profile switches (Windows).  Moving from
 * home to a cafe is the change this catches, so seconds are plenty. */
#define PLACE_REFRESH_MS  5000

/* How many blocked events the Recent blocks card keeps. */
#define RECENT_MAX        5

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

/* Open connections. */
enum
{
	CONN_COL_PROGRAM,
	CONN_COL_REMOTE,
	CONN_COL_PORT,
	CONN_COL_SERVICE,
	CONN_COL_DIRECTION,
	CONN_COL_LOCAL,        /* gboolean: both ends are this computer */
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

/* Adapters. */
static GtkWidget  *adapters_card;
static GtkWidget  *adapters_list;
static GtkWidget  *adapters_note;
static GtkWidget  *adapters_toggle;
static gboolean    show_virtual = FALSE;
static GHashTable *net_samples = NULL;

/* Recent blocks: newest at the head. */
typedef struct
{
	gchar *title;
	gchar *detail;
} RecentBlock;

static GQueue     recent = G_QUEUE_INIT;
static GtkWidget *recent_list;
static GtkWidget *recent_empty;

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

	update_counters ();
}

/* ------------------------------------------------------- recent blocks */

static void
recent_block_free (gpointer data)
{
	RecentBlock *b = data;

	g_free (b->title);
	g_free (b->detail);
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

static void
rebuild_recent (void)
{
	GList *children, *l;

	if (recent_list == NULL)
		return;

	children = gtk_container_get_children (GTK_CONTAINER (recent_list));
	for (l = children; l != NULL; l = l->next)
		gtk_widget_destroy (GTK_WIDGET (l->data));
	g_list_free (children);

	for (l = recent.head; l != NULL; l = l->next) {
		RecentBlock *b = l->data;
		GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
		GtkWidget *dot = fs_icon_new (FS_ICON_DOT, 8);
		GtkWidget *text = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
		GtkWidget *title = label_new (b->title, "recent-title", 0.0);
		GtkWidget *detail = label_new (b->detail, "recent-detail", 0.0);

		add_class (row, "recent-row");
		add_class (dot, "dot-bad");
		gtk_widget_set_valign (dot, GTK_ALIGN_START);
		gtk_widget_set_margin_top (dot, 5);
		gtk_label_set_ellipsize (GTK_LABEL (detail), PANGO_ELLIPSIZE_END);
		gtk_box_pack_start (GTK_BOX (text), title, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (text), detail, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (row), dot, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (row), text, TRUE, TRUE, 0);
		gtk_box_pack_start (GTK_BOX (recent_list), row, FALSE, FALSE, 0);
		gtk_widget_show_all (row);
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
	g_free (service);

	g_queue_push_head (&recent, b);
	while (recent.length > RECENT_MAX)
		recent_block_free (g_queue_pop_tail (&recent));

	rebuild_recent ();

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

/* ------------------------------------------------------------ adapters */

static GtkWidget *
adapter_row (const FsIfaceStat *stat, guint64 rate)
{
	GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
	GtkWidget *tile = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	GtkWidget *text = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	GtkWidget *nums = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	gboolean wireless = g_strcmp0 (stat->kind, "Wireless") == 0;
	gchar *name, *rx, *tx, *down, *up, *speed;
	GtkWidget *label;

	gtk_widget_set_size_request (tile, 36, 36);
	gtk_widget_set_valign (tile, GTK_ALIGN_CENTER);
	add_class (tile, "adapter-tile");
	gtk_box_pack_start (GTK_BOX (tile),
	                    fs_icon_new (wireless ? FS_ICON_WIFI
	                                          : FS_ICON_ADAPTER, 18),
	                    TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (row), tile, FALSE, FALSE, 0);

	if (stat->kind != NULL && *stat->kind != '\0')
		name = g_markup_printf_escaped ("<b>%s</b><span foreground=\"#5B6472\">"
		                                DOT "%s%s</span>",
		                                stat->device, stat->kind,
		                                stat->up ? "" : _(" (down)"));
	else
		name = g_markup_printf_escaped ("<b>%s</b>", stat->device);
	label = label_new (NULL, "adapter-name", 0.0);
	gtk_label_set_markup (GTK_LABEL (label), name);
	gtk_label_set_ellipsize (GTK_LABEL (label), PANGO_ELLIPSIZE_END);
	gtk_box_pack_start (GTK_BOX (text), label, FALSE, FALSE, 0);
	g_free (name);

	label = label_new (stat->ip != NULL ? stat->ip : _("No IPv4 address"),
	                   stat->ip != NULL ? "mono" : "muted", 0.0);
	add_class (label, "adapter-ip");
	gtk_box_pack_start (GTK_BOX (text), label, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (row), text, TRUE, TRUE, 0);

	rx = format_bytes (stat->received);
	tx = format_bytes (stat->sent);
	speed = format_rate (rate);
	down = g_strconcat (DOWN, rx, NULL);
	up = g_strconcat (UP, tx, NULL);

	label = label_new (down, "adapter-num", 1.0);
	gtk_widget_set_tooltip_text (label, _("Received since the adapter "
	                                      "came up"));
	gtk_box_pack_start (GTK_BOX (nums), label, FALSE, FALSE, 0);
	label = label_new (up, "adapter-num-muted", 1.0);
	gtk_widget_set_tooltip_text (label, _("Sent since the adapter came up"));
	gtk_box_pack_start (GTK_BOX (nums), label, FALSE, FALSE, 0);
	label = label_new (speed, "adapter-num-muted", 1.0);
	gtk_widget_set_tooltip_text (label, _("Traffic right now"));
	gtk_box_pack_start (GTK_BOX (nums), label, FALSE, FALSE, 0);
	gtk_widget_set_valign (nums, GTK_ALIGN_CENTER);
	gtk_box_pack_start (GTK_BOX (row), nums, FALSE, FALSE, 0);

	g_free (rx);
	g_free (tx);
	g_free (down);
	g_free (up);
	g_free (speed);

	add_class (row, "adapter-row");
	return row;
}

/* [ refresh_network ]
 * Sample the interface counters, turn two consecutive samples into a
 * rate, and rebuild the adapters card, the Traffic total and the
 * header's "which machine" line. */
static void
refresh_network (void)
{
	const FsBackend *backend = fs_backend ();
	GList *stats, *l, *children;
	gint64 now;
	guint hidden = 0, shown = 0;
	guint64 total_rate = 0, total_rx = 0, total_tx = 0;
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
		g_clear_pointer (&primary_where, g_free);
		update_subtitle ();
		return;
	}
	gtk_widget_set_no_show_all (adapters_card, FALSE);
	gtk_widget_show (adapters_card);

	children = gtk_container_get_children (GTK_CONTAINER (adapters_list));
	for (l = children; l != NULL; l = l->next)
		gtk_widget_destroy (GTK_WIDGET (l->data));
	g_list_free (children);

	now = g_get_monotonic_time ();

	for (l = stats; l != NULL; l = l->next) {
		FsIfaceStat *stat = l->data;
		NetSample *prev = g_hash_table_lookup (net_samples, stat->device);
		guint64 rate = 0;

		if (prev != NULL && now > prev->stamp) {
			gdouble elapsed = (gdouble) (now - prev->stamp) / 1000000.0;
			/* A counter that went backwards means the adapter
			 * was reset, not that traffic was un-sent. */
			guint64 dr = stat->received >= prev->received
			           ? stat->received - prev->received : 0;
			guint64 ds = stat->sent >= prev->sent
			           ? stat->sent - prev->sent : 0;

			rate = (guint64) ((gdouble) (dr + ds) / elapsed);
		}

		prev = g_new0 (NetSample, 1);
		prev->received = stat->received;
		prev->sent     = stat->sent;
		prev->stamp    = now;
		g_hash_table_insert (net_samples, g_strdup (stat->device), prev);

		if (adapter_is_virtual (stat)) {
			hidden++;
			if (!show_virtual)
				continue;
		} else {
			/* Totals are the real adapters' only: bridged
			 * container traffic also crosses a real one, and
			 * counting both would count it twice. */
			total_rate += rate;
			total_rx += stat->received;
			total_tx += stat->sent;

			if (stat->ip != NULL && stat->up &&
			    stat->received + stat->sent >= primary_bytes) {
				primary = stat;
				primary_bytes = stat->received + stat->sent;
			}
		}

		gtk_box_pack_start (GTK_BOX (adapters_list),
		                    adapter_row (stat, rate), FALSE, FALSE, 0);
		shown++;
	}

	gtk_widget_show_all (adapters_list);

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
conn_set_nth (gint n, const gchar *program, const gchar *remote,
              const gchar *port, const gchar *service,
              const gchar *direction, gboolean local)
{
	GtkTreeIter iter;

	if (!gtk_tree_model_iter_nth_child (GTK_TREE_MODEL (conn_store),
	                                    &iter, NULL, n))
		gtk_list_store_append (conn_store, &iter);

	gtk_list_store_set (conn_store, &iter,
	                    CONN_COL_PROGRAM, program,
	                    CONN_COL_REMOTE, remote,
	                    CONN_COL_PORT, port,
	                    CONN_COL_SERVICE, service,
	                    CONN_COL_DIRECTION, direction,
	                    CONN_COL_LOCAL, local,
	                    -1);
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
	guint row = 0, local = 0, remote_count = 0;

	if (conn_store == NULL || connections_card == NULL)
		return;

	if (backend->list_connections == NULL) {
		gtk_widget_set_no_show_all (connections_card, TRUE);
		gtk_widget_hide (connections_card);
		set_total (TOTAL_CONN, "-", _("Not reported here"));
		return;
	}

	conns = backend->list_connections ();
	programs = g_hash_table_new (g_str_hash, g_str_equal);

	for (l = conns; l != NULL; l = l->next) {
		FsConnection *c = l->data;
		gboolean inbound = g_strcmp0 (c->direction, "Inbound") == 0;
		const gchar *remote = inbound ? c->source : c->destination;
		gboolean is_local = fs_util_is_loopback_address (c->source) &&
		                    fs_util_is_loopback_address (c->destination);

		conn_set_nth ((gint) row,
		              c->program != NULL ? c->program : "",
		              remote != NULL ? remote : "",
		              c->port != NULL ? c->port : "",
		              c->service != NULL ? c->service : "",
		              c->direction != NULL ? c->direction : "",
		              is_local);
		row++;

		if (is_local) {
			local++;
		} else {
			remote_count++;
			if (c->program != NULL && *c->program != '\0')
				g_hash_table_add (programs, c->program);
		}
	}

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
	GtkWidget *left, *tile, *text, *buttons, *grid, *events_button;

	hero = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 24);
	add_class (hero, "hero");
	add_class (hero, "level-unknown");

	left = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 18);

	tile = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_widget_set_size_request (tile, 56, 56);
	gtk_widget_set_valign (tile, GTK_ALIGN_START);
	add_class (tile, "hero-icon-tile");
	hero_icon = fs_icon_new (FS_ICON_SHIELD_QUESTION, 30);
	add_class (hero_icon, "hero-icon");
	gtk_box_pack_start (GTK_BOX (tile), hero_icon, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (left), tile, FALSE, FALSE, 0);

	text = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
	hero_title = label_new (NULL, "hero-title", 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (hero_title), TRUE);
	gtk_box_pack_start (GTK_BOX (text), hero_title, FALSE, FALSE, 0);
	hero_body = label_new (NULL, "hero-body", 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (hero_body), TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (hero_body), 60);
	gtk_box_pack_start (GTK_BOX (text), hero_body, FALSE, FALSE, 0);

	buttons = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	gtk_widget_set_margin_top (buttons, 10);
	power_button = icon_button_new (FS_ICON_PLAY, _("Start firewall"),
	                                &power_icon, &power_label, FALSE);
	add_class (power_button, "btn-primary");
	g_signal_connect (power_button, "clicked",
	                  G_CALLBACK (on_power_clicked), NULL);
	gtk_box_pack_start (GTK_BOX (buttons), power_button, FALSE, FALSE, 0);

	events_button = gtk_button_new_with_label (_("View events"));
	add_class (events_button, "btn-subtle");
	g_signal_connect (events_button, "clicked",
	                  G_CALLBACK (on_view_events), NULL);
	gtk_box_pack_start (GTK_BOX (buttons), events_button, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (text), buttons, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (left), text, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (hero), left, TRUE, TRUE, 0);

	/* Four facts, two by two. */
	grid = gtk_grid_new ();
	gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
	gtk_grid_set_column_spacing (GTK_GRID (grid), 10);
	gtk_grid_set_column_homogeneous (GTK_GRID (grid), TRUE);
	gtk_widget_set_size_request (grid, 360, -1);
	gtk_widget_set_valign (grid, GTK_ALIGN_CENTER);

	for (gint i = 0; i < N_TILES; i++) {
		GtkWidget *fact = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);

		add_class (fact, "hero-tile");
		gtk_box_pack_start (GTK_BOX (fact),
		                    label_new (_(captions[i]), "tile-caption", 0.0),
		                    FALSE, FALSE, 0);
		tile_value[i] = label_new ("", "tile-value", 0.0);
		gtk_label_set_ellipsize (GTK_LABEL (tile_value[i]),
		                         PANGO_ELLIPSIZE_END);
		gtk_box_pack_start (GTK_BOX (fact), tile_value[i], FALSE, FALSE, 0);
		gtk_grid_attach (GTK_GRID (grid), fact, i % 2, i / 2, 1, 1);
	}
	gtk_box_pack_start (GTK_BOX (hero), grid, FALSE, FALSE, 0);

	return hero;
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

	gtk_grid_set_column_spacing (GTK_GRID (grid), 14);
	gtk_grid_set_column_homogeneous (GTK_GRID (grid), TRUE);

	for (gint i = 0; i < N_TOTALS; i++) {
		GtkWidget *card = card_new (GTK_ORIENTATION_VERTICAL, 4);

		add_class (card, "stat-card");
		gtk_box_pack_start (GTK_BOX (card),
		                    label_new (_(captions[i]), "tile-caption", 0.0),
		                    FALSE, FALSE, 0);
		total_value[i] = label_new ("0", "stat-big", 0.0);
		gtk_box_pack_start (GTK_BOX (card), total_value[i], FALSE, FALSE, 0);
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
	else if (g_strcmp0 (klass, "muted") == 0)
		g_object_set (renderer, "foreground", "#5B6472", NULL);

	column = gtk_tree_view_column_new_with_attributes (title, renderer,
	                                                   "text", col, NULL);
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

	conn_store = gtk_list_store_new (CONN_N_COLS, G_TYPE_STRING,
	                                 G_TYPE_STRING, G_TYPE_STRING,
	                                 G_TYPE_STRING, G_TYPE_STRING,
	                                 G_TYPE_BOOLEAN);
	conn_filter = gtk_tree_model_filter_new (GTK_TREE_MODEL (conn_store),
	                                         NULL);
	gtk_tree_model_filter_set_visible_func (GTK_TREE_MODEL_FILTER (conn_filter),
	                                        conn_visible, NULL, NULL);
	sorted = gtk_tree_model_sort_new_with_model (conn_filter);

	view = gtk_tree_view_new_with_model (sorted);
	g_object_unref (sorted);
	add_class (view, "overview-grid");
	gtk_tree_view_set_enable_search (GTK_TREE_VIEW (view), FALSE);
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
	GtkWidget *head = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	GtkWidget *all = link_button_new (_("All events"));

	add_class (card, "padded-card");
	gtk_box_pack_start (GTK_BOX (head),
	                    label_new (_("Recent blocks"), "card-heading", 0.0),
	                    TRUE, TRUE, 0);
	g_signal_connect (all, "clicked", G_CALLBACK (on_view_events), NULL);
	gtk_box_pack_start (GTK_BOX (head), all, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (card), head, FALSE, FALSE, 0);

	recent_list = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	gtk_box_pack_start (GTK_BOX (card), recent_list, FALSE, FALSE, 0);

	recent_empty = label_new (_("Nothing has been blocked since StockFW "
	                            "opened."), "muted", 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (recent_empty), TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (recent_empty), 30);
	gtk_widget_set_no_show_all (recent_empty, TRUE);
	gtk_widget_show (recent_empty);
	gtk_box_pack_start (GTK_BOX (card), recent_empty, FALSE, FALSE, 0);

	rebuild_recent ();
	return card;
}

/* [ fs_statusview_page ] */
GtkWidget *
fs_statusview_page (void)
{
	GtkWidget *scroll, *page, *lower, *side;

	page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 20);
	add_class (page, "overview");

	gtk_box_pack_start (GTK_BOX (page), build_header (), FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), build_hero (), FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), build_profiles (), FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), build_totals (), FALSE, FALSE, 0);

	lower = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 20);
	gtk_box_pack_start (GTK_BOX (lower), build_connections (),
	                    TRUE, TRUE, 0);
	side = gtk_box_new (GTK_ORIENTATION_VERTICAL, 20);
	gtk_widget_set_size_request (side, 300, -1);
	gtk_box_pack_start (GTK_BOX (side), build_adapters (), FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (side), build_recent (), FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (lower), side, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), lower, TRUE, TRUE, 0);

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_AUTOMATIC,
	                                GTK_POLICY_AUTOMATIC);
	gtk_container_add (GTK_CONTAINER (scroll), page);

	net_samples = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                     g_free, g_free);

	update_counters ();
	fs_statusview_set_state (FS_FW_NONE);

	g_timeout_add (NET_REFRESH_MS,  on_net_timeout,  NULL);
	g_timeout_add (CONN_REFRESH_MS, on_conn_timeout, NULL);
	if (fs_backend ()->network_place != NULL)
		g_timeout_add (PLACE_REFRESH_MS, on_place_timeout, NULL);

	/* First sample immediately so the panels are not empty for two
	 * seconds after startup. */
	fs_statusview_refresh ();

	return scroll;
}
