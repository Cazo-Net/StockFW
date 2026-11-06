/*---[ fs-copilot.c ]---------------------------------------------------
 * Copilot: rule-based, local analysis of the event log.
 *
 * Keeps a per-application baseline (ports, destinations, hours, rate)
 * and runs a fixed set of checks on every event: first use of a port,
 * new public destinations, rate spikes, timed check-ins (beacons),
 * fan-out, inbound port scans, repeated login attempts and traffic a
 * block list stopped.  Each check is a threshold written below; each
 * finding carries the events behind it, the numbers next to the limit,
 * and what else could explain it.  Nothing here leaves the computer.
 *--------------------------------------------------------------------*/

#include "core/fs-copilot.h"
#include "core/fs-util.h"
#include "core/fs-service.h"
#include "core/fs-i18n.h"
#include "core/fs-fwrule.h"
#include "core/fs-rules.h"
#include "core/fs-apply.h"
#include "core/fs-netplace.h"
#include "core/fs-iprange.h"
#include "core/fs-hostnet.h"

#include <gio/gio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

struct _FsCopilot
{
	/* Learned application profiles. */
	GHashTable *profiles;           /* app_name -> FsAppProfile* */

	/* Current insights. */
	GList *insights;

	/* Policy for simulation (set via fs_copilot_set_policy). */
	FsPolicy *policy;

	/* Configuration. */
	gboolean learning_enabled;
	guint min_samples_for_baseline; /* Min connections before analyzing */

	/* Sentinel (1.0.4): covert-channel and fan-out state.  Arrival
	 * times are bucketed to whole seconds, so a polled batch of
	 * records counts as one moment instead of a fake burst. */
	GHashTable *beacon_stamps;      /* "app|host:port/proto" ->
	                                 * GArray<BeaconEv>                 */
	GHashTable *beacon_reported;    /* same key -> stage 1 / 2          */
	GHashTable *beacon_total;       /* same key -> contacts ever timed
	                                 * (the stamps keep the newest 32) */
	GHashTable *fanout;             /* app -> FanoutState*              */

	/* 1.0.7: inbound checks and report memory. */
	GHashTable *scan;               /* source -> ScanState*             */
	GHashTable *brute;              /* source -> GArray<BruteEv>        */
	GHashTable *reported_at;        /* "check|subject" -> unix sec      */
	guint64     events_seen;

	/* The DNS servers and default gateways this computer uses.  DNS
	 * (53, 853) to a resolver is never timed, and no automatic block
	 * ever targets a resolver or a gateway, on any port.  Read from
	 * the system (fs_hostnet_read) and again at most once a minute,
	 * unless a caller or the environment fixed them. */
	FsRangeSet *resolvers;
	FsRangeSet *gateways;
	gboolean    net_fixed;
	gint64      net_read_at;        /* monotonic seconds                */
};

typedef struct
{
	GHashTable *seen;               /* host -> last bucketed second     */
	GHashTable *blocked;            /* blocked host -> bucketed second  */
	gboolean    reported;           /* current window already told      */
	gint64      last;               /* newest second, for eviction      */
} FanoutState;

typedef struct
{
	gint64       sec;               /* monotonic second                 */
	gint64       unix_sec;
	guint        port;
	gboolean     blocked;
	const gchar *proto;             /* static string                    */
	const gchar *src;               /* an aggregate's member (a key of
	                                 * its members table), else NULL    */
} ScanEv;

typedef struct
{
	GArray     *ev;                 /* ScanEv, oldest first             */
	GHashTable *members;            /* IPv6 /64 only: its addresses     */
} ScanState;

typedef struct
{
	gint64   sec;
	gint64   unix_sec;
	gboolean blocked;
	guint    port;
} BruteEv;

/* One timed contact, as its own log line had it. */
typedef struct
{
	gint64   sec;                   /* monotonic second                 */
	gboolean blocked;
	gchar   *rule;                  /* what blocked it, or NULL         */
} BeaconEv;

static void
beacon_ev_clear (gpointer data)
{
	BeaconEv *b = data;

	g_free (b->rule);
	b->rule = NULL;
}

static void
fanout_state_free (gpointer data)
{
	FanoutState *f = data;

	g_hash_table_unref (f->seen);
	g_hash_table_unref (f->blocked);
	g_free (f);
}

static void
scan_state_free (gpointer data)
{
	ScanState *st = data;

	g_array_unref (st->ev);
	if (st->members != NULL)
		g_hash_table_unref (st->members);
	g_free (st);
}

/* Forward declarations. */
static void copilot_read_network (FsCopilot *copilot);
static gboolean hit_is_blocked_marker (const FsHit *hit);
static FsAppProfile *app_profile_new (const gchar *name, const gchar *path,
                                      gint64 now_unix);
static void app_profile_free (FsAppProfile *profile);
static void app_profile_record_connection (FsAppProfile *profile,
                                           const gchar *remote_ip,
                                           guint port,
                                           const gchar *protocol,
                                           gboolean inbound,
                                           guint64 bytes,
                                           gint64 now_unix);
static gboolean is_novel_port (FsAppProfile *profile, guint port);
static gboolean is_novel_destination (FsAppProfile *profile,
                                      const gchar *remote_ip);
static gboolean is_novel_hour (FsAppProfile *profile, gint64 now_unix);
static gboolean rate_spike_take (FsAppProfile *profile, gint64 now_unix);
static void behavior_analyze (FsCopilot *copilot, FsAppProfile *profile,
                              const gchar *app_name,
                              const gchar *remote_ip, guint port,
                              gint64 now_unix, const FsHit *hit,
                              gboolean inbound);
static void emit_insight (FsCopilot *copilot, FsInsight *insight);
static gboolean sentinel_hit_is_inbound (const FsHit *hit);
static void hit_app_key (const FsHit *hit, gchar *buf, gsize size);
static FsInsight *create_insight (FsInsightType type,
                                  FsCopilotSeverity severity,
                                  const gchar *title,
                                  gchar *description,
                                  const gchar *app_name,
                                  const gchar *destination);

/* ---- Sentinel thresholds (exercised by tests/test-core.sh) --------- */
#define FS_SENTINEL_BEACON_MIN_SAMPLES 6    /* contacts before judging   */
#define FS_SENTINEL_BEACON_MAX_CV      0.30 /* interval regularity       */
#define FS_SENTINEL_BEACON_MIN_MEAN_S  10   /* seconds between contacts  */
#define FS_SENTINEL_BEACON_MAX_MEAN_S  600
#define FS_SENTINEL_BEACON_MAX_STAMPS  32
#define FS_SENTINEL_FANOUT_WINDOW_S    60   /* rolling window, seconds   */
#define FS_SENTINEL_FANOUT_LIMIT       60   /* distinct hosts, any       */
#define FS_SENTINEL_FANOUT_BLOCKED     10   /* distinct hosts, blocked   */

/* P6 (false-outage hardening): how many recorded connections to one
 * destination make it ESTABLISHED for that application.  Below this a
 * destination is still "new"; at or above it, auto-block withholds and
 * the finding stays visible instead.  The count is the same one
 * behavior.csv persists, so the protection survives a restart. */
#define FS_SENTINEL_BASELINE_DEST_MIN  3

static FsInsight *sentinel_beacon_check (FsCopilot *copilot,
                                         const FsHit *hit,
                                         gint64 now_us, gint64 now_unix);
static FsInsight *sentinel_fanout_check (FsCopilot *copilot,
                                         const FsHit *hit,
                                         gint64 now_us, gint64 now_unix);
static FsInsight *inbound_scan_check (FsCopilot *copilot, const FsHit *hit,
                                      gint64 now_us, gint64 now_unix,
                                      FsInsight **net_out);
static FsInsight *brute_force_check (FsCopilot *copilot, const FsHit *hit,
                                     gint64 now_us, gint64 now_unix);
static FsInsight *threat_intel_check (FsCopilot *copilot, const FsHit *hit,
                                      gint64 now_unix);

/* ---- 1.0.7 checks (exercised by tests/test-core.sh) ---------------- */
#define FS_SENTINEL_BEACON_AUTO_MIN    8    /* contacts before auto-block */
#define FS_SCAN_PORTS_60S              12   /* distinct local ports, 60 s */
#define FS_SCAN_PORTS_10M              25   /* distinct local ports, 10 min */
#define FS_SCAN_SHORT_WINDOW_S         60   /* the short scan window, s  */
#define FS_SCAN_WINDOW_S               600
#define FS_SCAN_MAX_EVENTS             512  /* per source                */
#define FS_SCAN_MAX_SOURCES            1024 /* then the stalest goes     */
#define FS_SCAN_MAX_MEMBERS            256  /* addresses named per /64   */
#define FS_BRUTE_ATTEMPTS              10   /* attempts ...              */
#define FS_BRUTE_WINDOW_S              300  /* ... inside 5 minutes      */
#define FS_BRUTE_MAX_KEYS              1024
#define FS_REPORT_QUIET_S              3600 /* one report per hour       */
#define FS_NEWDEST_MIN_CONNECTIONS     50   /* profile size ...          */
#define FS_NEWDEST_MIN_AGE_S           (7 * 86400) /* ... and age        */
#define FS_NEWDEST_CHURN               20   /* new hosts in 7 days: browser-like */
#define FS_FANOUT_MAX_APPS             256

/* ---- Behavior analysis bounds (P2) -------------------------------
 * Every structure here is bounded (Chapter 9):256 applications,
 * 256 ports and 1024 destinations per application, 200 insights in
 * the list, one rate report per 10-minute bucket. */
#define FS_BEHAVIOR_MAX_APPS          256
#define FS_BEHAVIOR_MAX_PORTS         256
#define FS_BEHAVIOR_MAX_DESTS         1024
#define FS_COPILOT_MAX_INSIGHTS       200
#define FS_BEHAVIOR_WINDOW_S          600    /* rate window: 10 minutes */
#define FS_BEHAVIOR_RATE_MIN_BUCKETS  8      /* buckets before judging rate */
#define FS_BEHAVIOR_RATE_MIN_EVENTS   10     /* floor: events per bucket    */
#define FS_BEHAVIOR_HOURS_MIN_DISTINCT 4     /* hours before judging hours  */

/* [ fs_copilot_new ] */
FsCopilot *
fs_copilot_new (void)
{
	FsCopilot *copilot = g_new0 (FsCopilot, 1);

	copilot->profiles = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                           g_free, (GDestroyNotify) app_profile_free);
	copilot->insights = NULL;
	copilot->policy = NULL;
	copilot->learning_enabled = TRUE;
	copilot->min_samples_for_baseline = 10; /* Need 10 connections baseline */

	copilot->beacon_stamps = g_hash_table_new_full (
		g_str_hash, g_str_equal, g_free,
		(GDestroyNotify) g_array_unref);
	copilot->beacon_reported = g_hash_table_new_full (
		g_str_hash, g_str_equal, g_free, NULL);
	copilot->beacon_total = g_hash_table_new_full (
		g_str_hash, g_str_equal, g_free, NULL);
	copilot->fanout = g_hash_table_new_full (
		g_str_hash, g_str_equal, g_free, fanout_state_free);
	copilot->scan = g_hash_table_new_full (
		g_str_hash, g_str_equal, g_free, scan_state_free);
	copilot->brute = g_hash_table_new_full (
		g_str_hash, g_str_equal, g_free,
		(GDestroyNotify) g_array_unref);
	copilot->reported_at = g_hash_table_new_full (
		g_str_hash, g_str_equal, g_free, g_free);

	/* DNS to the resolvers is periodic by nature, and the resolvers
	 * and gateways are what the computer cannot do without. */
	copilot_read_network (copilot);

	return copilot;
}

/* ---- the resolvers and gateways ---------------------------------- */

/* The last copilot's resolvers and gateways, for fs_insight_is_auto_safe,
 * which judges an insight on its own.  One copilot runs in the app. */
G_LOCK_DEFINE_STATIC (infra);
static FsRangeSet      *infra_set   = NULL;
static const FsCopilot *infra_owner = NULL;

static void
copilot_publish_network (FsCopilot *copilot)
{
	FsRangeSet *all = fs_range_set_new ();

	if (copilot->resolvers != NULL)
		fs_range_set_union (all, copilot->resolvers);
	if (copilot->gateways != NULL)
		fs_range_set_union (all, copilot->gateways);
	fs_range_set_normalize (all);

	G_LOCK (infra);
	if (infra_set != NULL)
		fs_range_set_free (infra_set);
	infra_set = all;
	infra_owner = copilot;
	G_UNLOCK (infra);
}

static void
copilot_take_network (FsCopilot *copilot, FsRangeSet *resolvers,
                      FsRangeSet *gateways)
{
	if (copilot->resolvers != NULL)
		fs_range_set_free (copilot->resolvers);
	if (copilot->gateways != NULL)
		fs_range_set_free (copilot->gateways);
	copilot->resolvers = resolvers;
	copilot->gateways = gateways;
	copilot_publish_network (copilot);
}

static gchar *
read_env_file (const gchar *var)
{
	const gchar *path = g_getenv (var);
	gchar *text = NULL;

	if (path == NULL || *path == '\0' ||
	    !g_file_get_contents (path, &text, NULL, NULL))
		return NULL;
	return text;
}

/* [ copilot_read_network ]
 * STOCKFW_RESOLV_CONF set (tests): that file, STOCKFW_RESOLVED_CONF as
 * systemd-resolved's upstream list and STOCKFW_ROUTE_FILE as
 * /proc/net/route, and nothing else, ever again.  Otherwise the system
 * (fs_hostnet_read): resolv.conf, and behind a local stub
 * (127.0.0.53) the upstream servers systemd-resolved and
 * NetworkManager list; the default gateways; on Windows, every
 * adapter's DNS servers and gateways. */
static void
copilot_read_network (FsCopilot *copilot)
{
	gchar *rc = read_env_file ("STOCKFW_RESOLV_CONF");

	copilot->net_read_at = g_get_monotonic_time () / G_USEC_PER_SEC;
	if (rc != NULL || g_getenv ("STOCKFW_RESOLV_CONF") != NULL) {
		gchar *resolved = read_env_file ("STOCKFW_RESOLVED_CONF");
		gchar *route = read_env_file ("STOCKFW_ROUTE_FILE");

		fs_copilot_set_network (copilot, rc, resolved, route);
		g_free (resolved);
		g_free (route);
	} else {
		FsHostNet *h = fs_hostnet_read (NULL);

		copilot_take_network (copilot, fs_range_set_copy (h->resolvers),
		                      fs_range_set_copy (h->gateways));
		fs_hostnet_free (h);
	}
	g_free (rc);
}

/* Networks change (a laptop moves): the system's lists are read again
 * at most once a minute. */
static void
copilot_network_fresh (FsCopilot *copilot)
{
	gint64 now = g_get_monotonic_time () / G_USEC_PER_SEC;

	if (!copilot->net_fixed && now - copilot->net_read_at >= 60)
		copilot_read_network (copilot);
}

/* [ fs_copilot_set_network ] */
void
fs_copilot_set_network (FsCopilot *copilot, const gchar *resolv_conf,
                        const gchar *resolved, const gchar *route)
{
	if (copilot == NULL)
		return;
	copilot->net_fixed = TRUE;
	copilot_take_network (copilot,
	                      fs_hostnet_parse_resolvers (resolv_conf, resolved,
	                                                  NULL),
	                      route != NULL ? fs_hostnet_parse_route (route)
	                                    : fs_range_set_new ());
}

/* [ fs_copilot_set_resolvers ] */
void
fs_copilot_set_resolvers (FsCopilot *copilot, const gchar *resolv_conf)
{
	fs_copilot_set_network (copilot, resolv_conf, NULL, NULL);
}

/* An address that is one of this computer's resolvers or gateways. */
static gboolean
copilot_is_infrastructure (FsCopilot *copilot, const gchar *addr)
{
	return (copilot->resolvers != NULL &&
	        fs_range_set_contains_text (copilot->resolvers, addr)) ||
	       (copilot->gateways != NULL &&
	        fs_range_set_contains_text (copilot->gateways, addr));
}

/* TRUE when the resolver list names no server off this computer: only
 * a local stub (127.0.0.53) whose upstream could not be read, or
 * nothing at all.  DNS then goes to servers this computer does not
 * know, and no DNS destination may be blocked automatically. */
static gboolean
copilot_dns_upstream_unknown (FsCopilot *copilot)
{
	const FsRangeSet *r = copilot->resolvers;

	if (r == NULL)
		return TRUE;
	for (guint i = 0; i < r->v4->len; i++) {
		const FsRange4 *x = &g_array_index (r->v4, FsRange4, i);

		if ((x->start >> 24) != 127 || (x->end >> 24) != 127)
			return FALSE;
	}
	for (guint i = 0; i < r->v6->len; i++) {
		const FsRange6 *x = &g_array_index (r->v6, FsRange6, i);

		if (x->start.hi != 0 || x->start.lo != 1 ||
		    x->end.hi != 0 || x->end.lo != 1)
			return FALSE;
	}
	return TRUE;
}

/* [ fs_copilot_events_seen ] */
guint64
fs_copilot_events_seen (FsCopilot *copilot)
{
	return copilot != NULL ? copilot->events_seen : 0;
}

/* [ fs_copilot_set_policy ]
 * Attach a policy to the copilot for what-if simulation.  The copilot
 * does not take ownership -- the caller remains responsible for the
 * policy's lifetime.  Passing NULL clears the reference. */
void
fs_copilot_set_policy (FsCopilot *copilot, FsPolicy *policy)
{
	if (copilot == NULL)
		return;
	copilot->policy = policy;
}

/* [ fs_copilot_get_policy ]
 * Get the currently attached policy (may be NULL). */
FsPolicy *
fs_copilot_get_policy (FsCopilot *copilot)
{
	return (copilot != NULL) ? copilot->policy : NULL;
}

/* [ fs_copilot_free ] */
void
fs_copilot_free (FsCopilot *copilot)
{
	if (copilot == NULL)
		return;

	g_hash_table_unref (copilot->profiles);
	g_hash_table_unref (copilot->beacon_stamps);
	g_hash_table_unref (copilot->beacon_reported);
	g_hash_table_unref (copilot->beacon_total);
	g_hash_table_unref (copilot->fanout);
	g_hash_table_unref (copilot->scan);
	g_hash_table_unref (copilot->brute);
	g_hash_table_unref (copilot->reported_at);
	if (copilot->resolvers != NULL)
		fs_range_set_free (copilot->resolvers);
	if (copilot->gateways != NULL)
		fs_range_set_free (copilot->gateways);
	G_LOCK (infra);
	if (infra_owner == copilot) {
		if (infra_set != NULL)
			fs_range_set_free (infra_set);
		infra_set = NULL;
		infra_owner = NULL;
	}
	G_UNLOCK (infra);
	g_list_free_full (copilot->insights, (GDestroyNotify) fs_insight_free);
	g_free (copilot);
}

/* [ fs_copilot_feed_event ] */
void
fs_copilot_feed_event (FsCopilot *copilot, const FsHit *hit)
{
	fs_copilot_feed_event_full (copilot, hit, g_get_monotonic_time (),
	                            time (NULL));
}

/* [ fs_copilot_feed_event_at ] */
void
fs_copilot_feed_event_at (FsCopilot *copilot, const FsHit *hit,
                          gint64 now_us)
{
	fs_copilot_feed_event_full (copilot, hit, now_us, time (NULL));
}

/* [ evict_lru_profile ]
 * Room for a newcomer when the profile table is full: the least
 * recently seen application goes.  Its insights are plain strings and
 * stay valid; only its learned history resets. */
static void
evict_lru_profile (FsCopilot *copilot)
{
	GHashTableIter iter;
	gpointer key, value;
	gpointer oldest_key = NULL;
	FsAppProfile *oldest = NULL;

	g_hash_table_iter_init (&iter, copilot->profiles);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		FsAppProfile *p = value;

		if (oldest == NULL || p->last_seen < oldest->last_seen) {
			oldest = p;
			oldest_key = key;
		}
	}

	if (oldest_key != NULL)
		g_hash_table_remove (copilot->profiles, oldest_key);
}

/* [ fs_copilot_feed_event_full ]
 * One event, three jobs: teach the profile, run Sentinel, then judge
 * the event against the baseline it just joined -- correlating every
 * signal (port, destination, hour, rate) into a single finding
 * instead of the else-if chain that reported one signal and silently
 * dropped the others. */
void
fs_copilot_feed_event_full (FsCopilot *copilot, const FsHit *hit,
                            gint64 now_us, gint64 now_unix)
{
	gchar app_buf[256];
	const gchar *app_name;
	const gchar *remote_ip;
	const gchar *protocol;
	guint port;
	gboolean inbound;
	FsAppProfile *profile;

	if (copilot == NULL || hit == NULL || !copilot->learning_enabled)
		return;

	/* The per-application key.  The Windows backend appends
	 * " [BLOCKED]" to the service field of dropped events; without
	 * stripping it here, every blocked connection would start a
	 * SECOND profile for the same program and split the history the
	 * baseline is supposed to compare against.  Events without an
	 * Application Name carry the port's service name instead -- that
	 * is what the log held, and the profile's key says so. */
	hit_app_key (hit, app_buf, sizeof app_buf);
	app_name = app_buf;

	/* Which end is the remote host depends on the direction: an
	 * outbound packet carries OUR address as the source.  Taking
	 * `source' unconditionally taught every outbound event that our
	 * own IP was a destination -- the baseline learned the wrong half
	 * of the conversation.  The direction test is case-insensitive
	 * because the Windows backend writes "in"/"out". */
	inbound = sentinel_hit_is_inbound (hit);
	if (inbound)
		remote_ip = (hit->source != NULL && *hit->source != '\0')
		            ? hit->source : hit->destination;
	else
		remote_ip = (hit->destination != NULL &&
		             *hit->destination != '\0')
		            ? hit->destination : hit->source;

	port = 0;
	if (hit->port != NULL && *hit->port != '\0') {
		glong parsed = strtol (hit->port, NULL, 10);

		if (parsed > 0 && parsed <= 65535)
			port = (guint) parsed;
	}

	protocol = hit->protocol != NULL ? hit->protocol : "TCP";

	/* Get or create profile.
	 *
	 * The insert belongs inside the "not found" branch and nowhere
	 * else.  g_hash_table_insert() on a key that already exists frees
	 * the OLD value through the table's destroy notify -- and when the
	 * profile came from the lookup, old value and new value are the
	 * same object.  So the unconditional insert used to free the very
	 * profile it then stored: the table kept a dangling pointer, the
	 * next event wrote into freed memory, and the one after that freed
	 * it again.  That was the crash behind monitoring the log --
	 * g_hash_table_lookup() inside the anomaly checks on the freed
	 * profile->common_ports (integer divide-by-zero or access violation
	 * in libglib), plus the heap fail-fasts from the double free. */
	profile = g_hash_table_lookup (copilot->profiles, app_name);
	if (profile == NULL)
	{
		if (g_hash_table_size (copilot->profiles) >=
		    FS_BEHAVIOR_MAX_APPS)
			evict_lru_profile (copilot);

		profile = app_profile_new (app_name, NULL, now_unix);
		g_hash_table_insert (copilot->profiles, g_strdup (app_name),
		                     profile);
	}

	/* A refused inbound attempt is a stranger's choice of port and
	 * address, not something the program did: it counts as activity,
	 * but it teaches the profile no port and no destination (a scan
	 * would otherwise fill both sets and mark the profile partial). */
	if (inbound && hit_is_blocked_marker (hit))
		app_profile_record_connection (profile, NULL, 0, protocol,
		                               inbound, 0, now_unix);
	else
		app_profile_record_connection (profile, remote_ip, port,
		                               protocol, inbound, 0, now_unix);

	copilot->events_seen++;

	/* Sentinel runs on every event, baseline or not: a control
	 * channel has to be caught in its first minutes, not after the
	 * learning baseline has had its 10 samples.  The inbound checks
	 * and the block-list check run on every event too. */
	{
		FsInsight *found[6];

		found[0] = sentinel_beacon_check (copilot, hit, now_us, now_unix);
		found[1] = sentinel_fanout_check (copilot, hit, now_us, now_unix);
		found[2] = inbound_scan_check (copilot, hit, now_us, now_unix,
		                               &found[5]);
		found[3] = brute_force_check (copilot, hit, now_us, now_unix);
		found[4] = threat_intel_check (copilot, hit, now_unix);

		for (guint i = 0; i < G_N_ELEMENTS (found); i++) {
			if (found[i] == NULL)
				continue;
			found[i]->timestamp = now_unix;
			emit_insight (copilot, found[i]);
		}
	}

	/* Judge the event against the baseline once it has one. */
	if (profile->total_connections >= copilot->min_samples_for_baseline)
		behavior_analyze (copilot, profile, app_name, remote_ip,
		                  port, now_unix, hit, inbound);
}

/* [ fs_copilot_get_insights ] */
GList *
fs_copilot_get_insights (FsCopilot *copilot)
{
	if (copilot == NULL)
		return NULL;

	return g_list_copy (copilot->insights);
}

/* [ fs_copilot_clear_insights ] */
void
fs_copilot_clear_insights (FsCopilot *copilot)
{
	if (copilot == NULL)
		return;

	g_list_free_full (copilot->insights, (GDestroyNotify) fs_insight_free);
	copilot->insights = NULL;
}

/* ---- What-If ---------------------------------------------------------
 * The simulator is fs-whatif.c.  These two entry points keep the
 * copilot's older calls answering with it: the model of the platform
 * this build runs on, the attached policy, and Firewall preferences as
 * a fresh install has them.  Callers that know more -- the real
 * preferences, whether the firewall runs, Sentinel's blocks -- build
 * an FsWhatIfContext and call fs_whatif_simulate() themselves, as the
 * Copilot page and the command line do. */

/* [ result_from_whatif ] -- takes ownership of w. */
static FsSimulationResult *
result_from_whatif (FsWhatIfResult *w)
{
	FsSimulationResult *r = g_new0 (FsSimulationResult, 1);
	const FsWhatIfAnswer *a = (w->answers->len > 0)
	                          ? g_ptr_array_index (w->answers, 0) : NULL;

	r->whatif = w;
	r->verdict = w->verdict;
	r->would_block = (w->verdict == FS_WHATIF_BLOCKED);
	r->affected_connections = 1;

	if (w->verdict == FS_WHATIF_ERROR || a == NULL) {
		r->scenario = g_strdup (w->query != NULL ? w->query->text : "");
		r->reason = g_strdup (w->error != NULL ? w->error : w->summary);
		r->explanation = g_strdup (r->reason);
		return r;
	}

	r->scenario = g_strdup (w->answers->len == 1 ? a->probe
	                                             : w->query->text);
	r->matching_rule = g_strdup (a->rule);
	r->reason = g_strdup (w->answers->len == 1 ? a->reason : w->summary);
	r->explanation = g_strdup_printf (_("Simulation: %s would be %s. "
	                                    "Reason: %s"),
	                                  r->scenario,
	                                  fs_whatif_verdict_name (w->verdict),
	                                  r->reason);
	return r;
}

/* [ fs_copilot_simulate ]
 * One probe given field by field.  A host that is not an address or a
 * block is an error: answering for "any host" instead would be a
 * guess the caller cannot see. */
FsSimulationResult *
fs_copilot_simulate (FsCopilot *copilot,
                     const gchar *app_name,
                     const gchar *remote_ip,
                     guint port,
                     const gchar *protocol,
                     gboolean inbound)
{
	FsWhatIfContext *ctx;
	FsWhatIfQuery *q = fs_whatif_query_new ();
	FsWhatIfResult *w;

	q->direction = inbound ? FS_WHATIF_DIR_INBOUND : FS_WHATIF_DIR_OUTBOUND;
	q->port = (port <= 65535) ? port : 0;
	q->service = (app_name != NULL && *app_name != '\0')
	             ? g_strdup (app_name) : NULL;

	if (g_strcmp0 (protocol, "TCP") == 0 || g_strcmp0 (protocol, "tcp") == 0)
		q->protocol = FS_WHATIF_PROTO_TCP;
	else if (g_strcmp0 (protocol, "UDP") == 0 ||
	         g_strcmp0 (protocol, "udp") == 0)
		q->protocol = FS_WHATIF_PROTO_UDP;
	else if (protocol != NULL && g_ascii_strcasecmp (protocol, "ICMP") == 0) {
		q->protocol = FS_WHATIF_PROTO_ICMP;
		q->port = 0;
	}

	{
		GString *t = g_string_new (inbound ? "inbound" : "outbound");

		if (protocol != NULL && *protocol != '\0')
			g_string_append_printf (t, " %s", protocol);
		if (q->port > 0)
			g_string_append_printf (t, " port %u", q->port);
		if (remote_ip != NULL && *remote_ip != '\0')
			g_string_append_printf (t, inbound ? " from %s" : " to %s",
			                        remote_ip);
		q->text = g_string_free (t, FALSE);
	}

	if (remote_ip != NULL && *remote_ip != '\0') {
		FsFamily fam = fs_util_target_families (remote_ip);

		if (fs_util_target_is_anyone (remote_ip)) {
			/* any host: left open */
		} else if (fam != FS_FAMILY_IPV4 && fam != FS_FAMILY_IPV6) {
			FsWhatIfResult *bad;
			FsSimulationResult *r;

			fs_whatif_query_free (q);
			bad = fs_whatif_simulate (NULL, NULL);
			g_free (bad->error);
			bad->error = g_strdup_printf (_("\"%s\" is not an address or "
			                                "a block of addresses."),
			                              remote_ip);
			r = result_from_whatif (bad);
			return r;
		} else {
			q->host = g_strdup (remote_ip);
		}
	}

	ctx = fs_whatif_context_new (fs_whatif_native_platform (),
	                             copilot != NULL ? copilot->policy : NULL,
	                             NULL);
	w = fs_whatif_simulate (ctx, q);
	fs_whatif_context_free (ctx);
	fs_whatif_query_free (q);
	return result_from_whatif (w);
}

/* [ fs_copilot_simulate_text ] */
FsSimulationResult *
fs_copilot_simulate_text (FsCopilot *copilot, const gchar *text,
                          FsWhatIfQuery **parsed_out)
{
	FsWhatIfContext *ctx;
	FsWhatIfResult *w;
	gchar *trimmed;

	if (parsed_out != NULL)
		*parsed_out = NULL;

	trimmed = g_strstrip (g_strdup (text != NULL ? text : ""));
	if (*trimmed == '\0') {
		g_free (trimmed);
		return NULL;
	}
	g_free (trimmed);

	ctx = fs_whatif_context_new (fs_whatif_native_platform (),
	                             copilot != NULL ? copilot->policy : NULL,
	                             NULL);
	w = fs_whatif_simulate_text (ctx, text);
	fs_whatif_context_free (ctx);

	if (parsed_out != NULL && w->query != NULL)
		*parsed_out = fs_whatif_query_copy (w->query);

	return result_from_whatif (w);
}

/* [ fs_copilot_whatif_observe ] */
void
fs_copilot_whatif_observe (FsWhatIfContext *ctx, const FsBackend *backend,
                           gboolean state_reliable)
{
	if (ctx == NULL || backend == NULL)
		return;

	if (backend->get_state != NULL &&
	    (backend->available == NULL || backend->available ())) {
		switch (backend->get_state ()) {
		case FS_FW_RUNNING:
		case FS_FW_LOCKED:     /* the Policy Lock: still filtering */
		case FS_FW_HIT:
			ctx->firewall = FS_WHATIF_FW_RUNNING;
			break;
		case FS_FW_STOPPED:
			ctx->firewall = state_reliable ? FS_WHATIF_FW_STOPPED
			                               : FS_WHATIF_FW_UNKNOWN;
			break;
		case FS_FW_NONE:
		default:
			ctx->firewall = FS_WHATIF_FW_UNKNOWN;
			break;
		}
	}

	if (ctx->platform == FS_WHATIF_WINDOWS_BLOCK_WINS) {
		if (backend->network_place != NULL) {
			FsNetworkPlace *place = backend->network_place ();

			if (place != NULL) {
				ctx->profiles_in_use = place->in_use;
				fs_network_place_free (place);
			}
		}

		for (gint p = 0; p < 3; p++) {
			gboolean on = FALSE, in_block = TRUE, out_block = FALSE;

			if (backend->get_profile_enabled != NULL &&
			    backend->get_profile_enabled (p, &on))
				ctx->profile_enabled[p] = on ? 1 : 0;

			if (backend->get_profile_defaults != NULL &&
			    backend->get_profile_defaults (p, &in_block,
			                                   &out_block)) {
				ctx->default_inbound[p] = in_block
					? FS_WHATIF_DEFAULT_BLOCK : FS_WHATIF_DEFAULT_ALLOW;
				ctx->default_outbound[p] = out_block
					? FS_WHATIF_DEFAULT_BLOCK : FS_WHATIF_DEFAULT_ALLOW;
			}

			if (backend->get_profile_block_all_inbound != NULL &&
			    backend->get_profile_block_all_inbound (p, &on))
				ctx->block_all_inbound[p] = on ? 1 : 0;
		}
	}

	/* STOCKFW_LOCAL_ADDRESSES (tests): this computer's addresses, comma
	 * separated, instead of its adapters'; set and empty means none.
	 * Each private one is a LAN the health check probes, so a suite
	 * that fixes STOCKFW_LAN_PREFIX fixes these too, or the machine
	 * running it would decide whether a narrowing is verified. */
	if (g_getenv ("STOCKFW_LOCAL_ADDRESSES") != NULL) {
		gchar **addrs = g_strsplit (g_getenv ("STOCKFW_LOCAL_ADDRESSES"),
		                            ",", -1);

		for (gint i = 0; addrs[i] != NULL; i++) {
			g_strstrip (addrs[i]);
			if (*addrs[i] != '\0')
				fs_whatif_context_add_local_address (ctx, addrs[i]);
		}
		g_strfreev (addrs);
	} else if (backend->list_interfaces != NULL) {
		GList *ifaces = backend->list_interfaces ();

		for (GList *l = ifaces; l != NULL; l = l->next) {
			FsInterface *iface = l->data;

			if (iface->ip != NULL && *iface->ip != '\0')
				fs_whatif_context_add_local_address (ctx, iface->ip);
			fs_interface_free (iface);
		}
		g_list_free (ifaces);
	}
}

/* [ fs_copilot_whatif_live ] */
void
fs_copilot_whatif_live (FsWhatIfContext *ctx, const FsPolicy *saved,
                        const gchar *hold_reason)
{
	FsPolicy *applied;
	GError *error = NULL;

	if (ctx == NULL)
		return;

	g_clear_pointer (&ctx->live_detail, g_free);

	if (hold_reason != NULL && *hold_reason != '\0') {
		ctx->live = FS_WHATIF_LIVE_HELD;
		ctx->live_detail = g_strdup (hold_reason);
		return;
	}

	if (saved == NULL) {
		ctx->live = FS_WHATIF_LIVE_UNKNOWN;
		return;
	}

	applied = fs_policy_new ();
	if (fs_apply_journal_load (applied, &error))
		ctx->live = fs_whatif_policy_same (saved, applied)
		            ? FS_WHATIF_LIVE_YES : FS_WHATIF_LIVE_STALE;
	else
		ctx->live = FS_WHATIF_LIVE_UNKNOWN;
	g_clear_error (&error);
	fs_policy_free (applied);
}

/* [ fs_copilot_get_profile ] */
const FsAppProfile *
fs_copilot_get_profile (FsCopilot *copilot, const gchar *app_name)
{
	if (copilot == NULL || app_name == NULL)
		return NULL;

	return g_hash_table_lookup (copilot->profiles, app_name);
}

/* [ fs_copilot_get_all_profiles ] */
GList *
fs_copilot_get_all_profiles (FsCopilot *copilot)
{
	if (copilot == NULL)
		return NULL;

	GList *list = NULL;
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init (&iter, copilot->profiles);
	while (g_hash_table_iter_next (&iter, &key, &value))
		list = g_list_prepend (list, value);

	return list;
}

/* [ fs_copilot_export_json ] */
gchar *
fs_copilot_export_json (FsCopilot *copilot)
{
	if (copilot == NULL)
		return NULL;

	/* Simplified JSON export - in production would use JSON-GLib. */
	GString *json = g_string_new ("{ \"profiles\": {");
	gboolean first = TRUE;

	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init (&iter, copilot->profiles);
	while (g_hash_table_iter_next (&iter, &key, &value))
	{
		FsAppProfile *p = value;
		if (!first) g_string_append (json, ", ");
		first = FALSE;

		g_string_append_printf (json, "\"%s\": { \"connections\": %" G_GUINT64_FORMAT
		                        ", \"bytes_sent\": %" G_GUINT64_FORMAT
		                        ", \"bytes_recv\": %" G_GUINT64_FORMAT
		                        ", \"first_seen\": %" G_GUINT64_FORMAT
		                        ", \"last_seen\": %" G_GUINT64_FORMAT " }",
		                        (const gchar *) key,
		                        p->total_connections,
		                        p->total_bytes_sent,
		                        p->total_bytes_recv,
		                        p->first_seen,
		                        p->last_seen);
	}

	g_string_append (json, "} }");
	return g_string_free (json, FALSE);
}

/* [ fs_copilot_import_json ] */
gboolean
fs_copilot_import_json (FsCopilot *copilot, const gchar *json)
{
	/* Would parse JSON and rebuild profiles. Simplified for now. */
	(void) copilot; (void) json;
	return FALSE;
}

/* ---- Historical behavior baseline (P2) ----------------------------
 * One CSV row per learned fact, in the trust store's dialect (the
 * shared writer/parser in fs-util): a "meta" row carries totals and
 * first/last seen, a "rate" row the frequency state, and
 * port/dest/hour rows the learned sets.  The file is what makes the
 * baseline HISTORICAL -- a restart resumes yesterday's knowledge
 * instead of relearning it and calling every old port new. */

/* [ parse_u64 ] -- strict: digits only, the whole field. */
static gboolean
parse_u64 (const gchar *text, guint64 *out)
{
	gchar *end = NULL;
	guint64 value;

	if (text == NULL || *text == '\0' || !g_ascii_isdigit (*text))
		return FALSE;

	value = g_ascii_strtoull (text, &end, 10);
	if (end == text || *end != '\0')
		return FALSE;

	*out = value;
	return TRUE;
}

/* [ fs_copilot_baseline_path ] -- follows the trust store's
 * convention; STOCKFW_BEHAVIOR_FILE overrides it for the tests. */
gchar *
fs_copilot_baseline_path (void)
{
	const gchar *env = g_getenv ("STOCKFW_BEHAVIOR_FILE");

	if (env != NULL && *env != '\0')
		return g_strdup (env);

#ifdef G_OS_WIN32
	/* Same home as stockfw.conf and trust.csv: the roaming AppData
	 * folder, not the local one g_get_user_config_dir() would give. */
	{
		const gchar *appdata = g_getenv ("APPDATA");

		if (appdata != NULL && *appdata != '\0')
			return g_build_filename (appdata, "stockfw",
			                         "behavior.csv", NULL);

		return g_build_filename (g_get_home_dir (), "AppData",
		                         "Roaming", "stockfw",
		                         "behavior.csv", NULL);
	}
#else
	return g_build_filename (g_get_user_config_dir (), "stockfw",
	                         "behavior.csv", NULL);
#endif
}

/* [ cmp_app_name ] -- g_strcmp0 as a GCompareFunc, without the cast
 * GCC's -Wcast-function-type would complain about. */
static gint
cmp_app_name (gconstpointer a, gconstpointer b)
{
	return g_strcmp0 ((const gchar *) a, (const gchar *) b);
}

/* [ fs_copilot_baseline_save ]
 * Deterministic output: application names sorted, one group per
 * application (meta, rate, partial flag, ports, destinations, hours),
 * so two saves of the same state are the same file. */
gboolean
fs_copilot_baseline_save (FsCopilot *copilot, const gchar *path,
                          GError **error)
{
	GString *out;
	GList *names = NULL;
	GList *l;
	GHashTableIter iter;
	gpointer key, value;
	gboolean ok;

	if (copilot == NULL || path == NULL || *path == '\0') {
		if (error != NULL)
			g_set_error_literal (error, G_IO_ERROR,
			                     G_IO_ERROR_INVALID_ARGUMENT,
			                     "behavior baseline has no file to write");
		return FALSE;
	}

	if (!fs_util_ensure_parent_dir (path)) {
		if (error != NULL)
			g_set_error_literal (error, G_IO_ERROR,
			                     G_IO_ERROR_FAILED,
			                     "the baseline directory could not be created");
		return FALSE;
	}

	g_hash_table_iter_init (&iter, copilot->profiles);
	while (g_hash_table_iter_next (&iter, &key, &value))
		names = g_list_prepend (names, (gchar *) key);
	names = g_list_sort (names, cmp_app_name);

	out = g_string_new ("# StockFW behavior baseline v1\n");

	for (l = names; l != NULL; l = l->next) {
		const gchar *app = l->data;
		FsAppProfile *p = g_hash_table_lookup (copilot->profiles, app);
		gchar num[3][32];

		if (p == NULL)
			continue;

		/* meta: total connections, first seen, last seen.  Every
		 * row's first field is written with first=TRUE -- the flag
		 * skips the separator, and each row starts a new line. */
		g_snprintf (num[0], sizeof num[0],
		            "%" G_GUINT64_FORMAT, p->total_connections);
		g_snprintf (num[1], sizeof num[1],
		            "%" G_GUINT64_FORMAT, p->first_seen);
		g_snprintf (num[2], sizeof num[2],
		            "%" G_GUINT64_FORMAT, p->last_seen);
		fs_util_csv_append_field (out, app, TRUE);
		fs_util_csv_append_field (out, "meta", FALSE);
		fs_util_csv_append_field (out, num[0], FALSE);
		fs_util_csv_append_field (out, num[1], FALSE);
		fs_util_csv_append_field (out, num[2], FALSE);
		g_string_append_c (out, '\n');

		/* rate: EWMA x1000, buckets closed, bucket reported */
		g_snprintf (num[0], sizeof num[0], "%u", p->rate_ema_milli);
		g_snprintf (num[1], sizeof num[1], "%u", p->rate_buckets);
		g_snprintf (num[2], sizeof num[2],
		            "%" G_GUINT64_FORMAT, p->rate_reported);
		fs_util_csv_append_field (out, app, TRUE);
		fs_util_csv_append_field (out, "rate", FALSE);
		fs_util_csv_append_field (out, num[0], FALSE);
		fs_util_csv_append_field (out, num[1], FALSE);
		fs_util_csv_append_field (out, num[2], FALSE);
		g_string_append_c (out, '\n');

		/* partial: this profile's sets were capped somewhere */
		if (p->baseline_partial) {
			fs_util_csv_append_field (out, app, TRUE);
			fs_util_csv_append_field (out, "partial", FALSE);
			g_string_append_c (out, '\n');
		}

		/* ports */
		{
			GHashTableIter set_iter;
			gpointer pkey, pvalue;

			g_hash_table_iter_init (&set_iter, p->common_ports);
			while (g_hash_table_iter_next (&set_iter, &pkey,
			                               &pvalue)) {
				g_snprintf (num[0], sizeof num[0], "%u",
				            GPOINTER_TO_UINT (pkey));
				g_snprintf (num[1], sizeof num[1], "%u",
				            *(guint *) pvalue);
				fs_util_csv_append_field (out, app, TRUE);
				fs_util_csv_append_field (out, "port", FALSE);
				fs_util_csv_append_field (out, num[0], FALSE);
				fs_util_csv_append_field (out, num[1], FALSE);
				g_string_append_c (out, '\n');
			}
		}

		/* destinations */
		{
			GHashTableIter set_iter;
			gpointer pkey, pvalue;

			g_hash_table_iter_init (&set_iter,
			                        p->common_destinations);
			while (g_hash_table_iter_next (&set_iter, &pkey,
			                               &pvalue)) {
				g_snprintf (num[1], sizeof num[1], "%u",
				            *(guint *) pvalue);
				fs_util_csv_append_field (out, app, TRUE);
				fs_util_csv_append_field (out, "dest", FALSE);
				fs_util_csv_append_field (out, (const gchar *)
				                          pkey, FALSE);
				fs_util_csv_append_field (out, num[1], FALSE);
				g_string_append_c (out, '\n');
			}
		}

		/* hours */
		{
			GHashTableIter set_iter;
			gpointer pkey, pvalue;

			g_hash_table_iter_init (&set_iter, p->hourly_activity);
			while (g_hash_table_iter_next (&set_iter, &pkey,
			                               &pvalue)) {
				g_snprintf (num[0], sizeof num[0], "%u",
				            GPOINTER_TO_UINT (pkey));
				g_snprintf (num[1], sizeof num[1],
				            "%" G_GUINT64_FORMAT,
				            *(guint64 *) pvalue);
				fs_util_csv_append_field (out, app, TRUE);
				fs_util_csv_append_field (out, "hour", FALSE);
				fs_util_csv_append_field (out, num[0], FALSE);
				fs_util_csv_append_field (out, num[1], FALSE);
				g_string_append_c (out, '\n');
			}
		}

		/* first contacts with new hosts in the last 7 days, oldest
		 * first: the "meets new hosts all the time" memory, so a
		 * browser is still one after a restart */
		for (guint i = 0; p->new_dest_times != NULL &&
		     i < p->new_dest_times->len; i++) {
			g_snprintf (num[0], sizeof num[0], "%" G_GINT64_FORMAT,
			            g_array_index (p->new_dest_times, gint64, i));
			fs_util_csv_append_field (out, app, TRUE);
			fs_util_csv_append_field (out, "newdest", FALSE);
			fs_util_csv_append_field (out, num[0], FALSE);
			g_string_append_c (out, '\n');
		}
	}

	g_list_free (names);

	ok = g_file_set_contents (path, out->str, out->len, error);
	g_string_free (out, TRUE);
	return ok;
}

/* [ fs_copilot_baseline_load ]
 * Merges the file into whatever the copilot already knows: meta rows
 * replace totals, fact rows accumulate (a port row adds its count).
 * Unknown rows are skipped -- a newer format still loads what it
 * understands.  Rows refused by a cap mark that profile partial, so
 * a truncated baseline never claims to know everything. */
gboolean
fs_copilot_baseline_load (FsCopilot *copilot, const gchar *path,
                          GError **error)
{
	gchar *contents = NULL;
	gchar **lines;
	guint i;

	if (copilot == NULL || path == NULL) {
		if (error != NULL)
			g_set_error_literal (error, G_IO_ERROR,
			                     G_IO_ERROR_INVALID_ARGUMENT,
			                     "behavior baseline load needs a file");
		return FALSE;
	}

	if (!g_file_get_contents (path, &contents, NULL, error)) {
		/* A file that is not there is a fresh start, not a failure. */
		if (error != NULL && *error != NULL &&
		    g_error_matches (*error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
			g_clear_error (error);
		return FALSE;
	}

	lines = g_strsplit (contents, "\n", -1);
	g_free (contents);

	for (i = 0; lines[i] != NULL; i++) {
		GPtrArray *fields;
		const gchar *app, *kind;
		FsAppProfile *p;
		guint64 a, b, c;

		g_strstrip (lines[i]);
		if (*lines[i] == '\0' || *lines[i] == '#')
			continue;

		fields = fs_util_csv_split_line (lines[i]);
		if (fields->len < 2) {
			g_ptr_array_unref (fields);
			continue;
		}

		app = g_ptr_array_index (fields, 0);
		kind = g_ptr_array_index (fields, 1);
		if (*app == '\0') {
			g_ptr_array_unref (fields);
			continue;
		}

		/* An unknown kind is skipped whole -- and creates no
		 * profile: nothing understands the row, so nothing should
		 * pretend this application was learned from it. */
		if (g_strcmp0 (kind, "meta") != 0 &&
		    g_strcmp0 (kind, "rate") != 0 &&
		    g_strcmp0 (kind, "partial") != 0 &&
		    g_strcmp0 (kind, "port") != 0 &&
		    g_strcmp0 (kind, "dest") != 0 &&
		    g_strcmp0 (kind, "hour") != 0 &&
		    g_strcmp0 (kind, "newdest") != 0) {
			g_ptr_array_unref (fields);
			continue;
		}

		p = g_hash_table_lookup (copilot->profiles, app);
		if (p == NULL) {
			if (g_hash_table_size (copilot->profiles) >=
			    FS_BEHAVIOR_MAX_APPS) {
				g_ptr_array_unref (fields);
				continue;   /* whole app past the cap: ignored */
			}
			p = app_profile_new (app, NULL, time (NULL));
			g_hash_table_insert (copilot->profiles,
			                     g_strdup (app), p);
		}

		if (g_strcmp0 (kind, "meta") == 0) {
			if (fields->len >= 5 &&
			    parse_u64 (g_ptr_array_index (fields, 2), &a) &&
			    parse_u64 (g_ptr_array_index (fields, 3), &b) &&
			    parse_u64 (g_ptr_array_index (fields, 4), &c)) {
				p->total_connections = a;
				p->first_seen = b;
				p->last_seen = c;
			}
		} else if (g_strcmp0 (kind, "rate") == 0) {
			if (fields->len >= 5 &&
			    parse_u64 (g_ptr_array_index (fields, 2), &a) &&
			    parse_u64 (g_ptr_array_index (fields, 3), &b) &&
			    parse_u64 (g_ptr_array_index (fields, 4), &c)) {
				p->rate_ema_milli = (guint) MIN (a,
				                                  G_MAXUINT);
				p->rate_buckets = (guint) MIN (b, G_MAXUINT);
				p->rate_reported = c;
			}
		} else if (g_strcmp0 (kind, "partial") == 0) {
			p->baseline_partial = TRUE;
		} else if (g_strcmp0 (kind, "port") == 0) {
			if (fields->len >= 4 &&
			    parse_u64 (g_ptr_array_index (fields, 2), &a) &&
			    parse_u64 (g_ptr_array_index (fields, 3), &b) &&
			    a > 0 && a <= 65535) {
				guint *existing = g_hash_table_lookup (
					p->common_ports,
					GUINT_TO_POINTER ((guint) a));
				if (existing != NULL)
					*existing += (guint) MIN (b, G_MAXUINT);
				else if (g_hash_table_size (p->common_ports) >=
				         FS_BEHAVIOR_MAX_PORTS)
					p->baseline_partial = TRUE;
				else {
					guint *slot = g_new (guint, 1);
					*slot = (guint) MIN (b, G_MAXUINT);
					g_hash_table_insert (p->common_ports,
					                     GUINT_TO_POINTER (
					                             (guint) a),
					                     slot);
				}
			}
		} else if (g_strcmp0 (kind, "dest") == 0) {
			const gchar *addr = g_ptr_array_index (fields, 2);

			if (fields->len >= 4 && *addr != '\0' &&
			    parse_u64 (g_ptr_array_index (fields, 3), &b)) {
				guint *existing = g_hash_table_lookup (
					p->common_destinations, addr);
				if (existing != NULL)
					*existing += (guint) MIN (b, G_MAXUINT);
				else if (g_hash_table_size (
				         p->common_destinations) >=
				         FS_BEHAVIOR_MAX_DESTS)
					p->baseline_partial = TRUE;
				else {
					guint *slot = g_new (guint, 1);
					*slot = (guint) MIN (b, G_MAXUINT);
					g_hash_table_insert (
						p->common_destinations,
						g_strdup (addr), slot);
				}
			}
		} else if (g_strcmp0 (kind, "hour") == 0) {
			if (fields->len >= 4 &&
			    parse_u64 (g_ptr_array_index (fields, 2), &a) &&
			    parse_u64 (g_ptr_array_index (fields, 3), &b) &&
			    a < 24) {
				guint64 *existing = g_hash_table_lookup (
					p->hourly_activity,
					GUINT_TO_POINTER ((guint) a));
				if (existing != NULL)
					*existing += b;
				else {
					guint64 *slot = g_new (guint64, 1);
					*slot = b;
					g_hash_table_insert (p->hourly_activity,
					                     GUINT_TO_POINTER (
					                             (guint) a),
					                     slot);
				}
			}
		} else if (g_strcmp0 (kind, "newdest") == 0) {
			if (fields->len >= 3 &&
			    parse_u64 (g_ptr_array_index (fields, 2), &a) &&
			    a <= (guint64) G_MAXINT64) {
				gint64 t = (gint64) a;
				guint at = p->new_dest_times->len;

				/* kept sorted, at most 64, newest kept */
				while (at > 0 && g_array_index (p->new_dest_times,
				                                gint64, at - 1) > t)
					at--;
				g_array_insert_val (p->new_dest_times, at, t);
				if (p->new_dest_times->len > 64)
					g_array_remove_index (p->new_dest_times, 0);
			}
		}
		/* Unknown kinds were skipped above: a newer format still
		 * loads what this reader understands. */

		g_ptr_array_unref (fields);
	}

	g_strfreev (lines);
	return TRUE;
}

/* [ fs_insight_free ] */
void
fs_insight_free (FsInsight *insight)
{
	if (insight == NULL)
		return;

	g_free (insight->title);
	g_free (insight->description);
	g_free (insight->application);
	g_free (insight->destination);
	g_free (insight->suggested_rule);
	g_free (insight->rule_csv);
	g_free (insight->key);
	g_free (insight->subject);
	g_free (insight->why);
	g_free (insight->benign);
	g_free (insight->withheld);
	g_free (insight->whatif_line);
	g_free (insight->events_filter);
	if (insight->evidence != NULL)
		g_ptr_array_unref (insight->evidence);
	g_free (insight);
}

/* [ fs_evidence_free ] */
void
fs_evidence_free (FsEvidence *ev)
{
	if (ev == NULL)
		return;
	g_free (ev->remote);
	g_free (ev->protocol);
	g_free (ev->rule);
	g_free (ev);
}

/* [ fs_insight_type_name ] */
const gchar *
fs_insight_type_name (FsInsightType type)
{
	switch (type) {
	case FS_INSIGHT_UNUSUAL_PORT:        return _("New port");
	case FS_INSIGHT_UNUSUAL_DESTINATION: return _("New destination");
	case FS_INSIGHT_UNUSUAL_VOLUME:      return _("Connection rate");
	case FS_INSIGHT_UNUSUAL_TIME:        return _("New hour");
	case FS_INSIGHT_BEACON:              return _("Timed contacts");
	case FS_INSIGHT_FANOUT:              return _("Fan-out");
	case FS_INSIGHT_INBOUND_SCAN:        return _("Port scan");
	case FS_INSIGHT_BRUTE_FORCE:         return _("Login attempts");
	case FS_INSIGHT_THREAT_INTEL:        return _("Block list");
	default:                             return _("Finding");
	}
}

/* [ fs_simulation_result_free ] */
void
fs_simulation_result_free (FsSimulationResult *result)
{
	if (result == NULL)
		return;

	g_free (result->scenario);
	g_free (result->matching_rule);
	g_free (result->explanation);
	g_free (result->reason);
	fs_whatif_result_free (result->whatif);
	g_free (result);
}

/* [ fs_insight_to_rule ] */
FsRule *
fs_insight_to_rule (const FsInsight *insight)
{
	if (insight == NULL || insight->rule_csv == NULL ||
	    *insight->rule_csv == '\0')
		return NULL;

	return fs_rule_from_csv (insight->rule_kind, insight->rule_csv);
}

/* [ fs_insight_apply ]
 * Stage an insight's rule: add a copy to the policy and persist.  The
 * persist helper rolls the store back when the write fails, so FALSE
 * here always means "the disk and the store do not carry this rule". */
gboolean
fs_insight_apply (const FsInsight *insight, FsPolicy *policy)
{
	FsRule *rule = fs_insight_to_rule (insight);
	gboolean ok;

	if (rule == NULL)
		return FALSE;

	if (policy == NULL) {
		fs_rule_free (rule);
		return FALSE;
	}

	ok = fs_policy_add_persist (policy, rule);
	fs_rule_free (rule);
	return ok;
}

/* [ fs_insight_is_auto_safe ]
 * The auto-block invariant, in one place: an insight may be staged
 * WITHOUT a human only when its rule can only TIGHTEN the policy --
 * an outbound deny.  Suggestions that open things (service allows,
 * which legacy insights carry for the user's confirmed Apply button)
 * are never safe to stage automatically, whatever their flag says.
 *
 * P6 adds a second gate at this choke point: even a deny is refused
 * when its destination is one of the classes that must never be
 * auto-blocked (multicast, loopback, link-local, the private LAN).
 * These are protocol infrastructure and the user's own machines --
 * the 2026-10-10 incident was exactly this: Windows' own LLMNR
 * multicast and two LAN hosts auto-blocked as "beacons".  The DNS
 * servers and default gateways of the newest copilot are refused the
 * same way, whatever their address class. */
gboolean
fs_insight_is_auto_safe (const FsInsight *insight)
{
	FsRule *rule;
	gboolean safe;

	if (insight == NULL || insight->rule_csv == NULL ||
	    *insight->rule_csv == '\0')
		return FALSE;

	if (insight->rule_kind != FS_RULE_OUTBOUND_DENY_TO &&
	    insight->rule_kind != FS_RULE_OUTBOUND_DENY_SERVICE)
		return FALSE;

	rule = fs_rule_from_csv (insight->rule_kind, insight->rule_csv);
	if (rule == NULL)
		return FALSE;

	safe = !fs_sentinel_dest_never_auto_block (rule->target);

	/* Nor this computer's own DNS servers and default gateways: a
	 * block on them, on any port, cuts the computer off. */
	if (safe) {
		G_LOCK (infra);
		if (infra_set != NULL &&
		    fs_range_set_contains_text (infra_set, rule->target))
			safe = FALSE;
		G_UNLOCK (infra);
	}
	fs_rule_free (rule);

	return safe;
}

/* [ parse_ipv4_strict ] -- four decimal octets, dots between, nothing
 * else.  Hostnames and junk fail: they are not classifiable, and an
 * unclassifiable destination is never auto-blocked. */
static gboolean
parse_ipv4_strict (const gchar *s, guint8 out[4])
{
	guint i;

	if (s == NULL || *s == '\0')
		return FALSE;

	for (i = 0; i < 4; i++) {
		guint value = 0;
		gint digits = 0;

		while (digits < 3 && g_ascii_isdigit (*s)) {
			value = value * 10 + (guint) (*s - '0');
			s++;
			digits++;
		}

		if (digits == 0 || value > 255)
			return FALSE;

		out[i] = (guint8) value;

		if (i < 3) {
			if (*s != '.')
				return FALSE;
			s++;
		}
	}

	return *s == '\0';
}

/* [ v4_dest_never_auto_block ] -- the IPv4 classes that are protocol
 * infrastructure or the user's own address space.  Blocking any of
 * them "automatically" has already broken real machines: 224.0.0.252
 * is Windows' own LLMNR, 239.255.255.250 is SSDP discovery, and the
 * 192.168/16 hits were the user's own LAN hosts. */
static gboolean
v4_dest_never_auto_block (const guint8 o[4])
{
	if (o[0] == 0)                                 /* "this network"   */
		return TRUE;
	if (o[0] == 10)                                /* RFC 1918         */
		return TRUE;
	if (o[0] == 100 && o[1] >= 64 && o[1] <= 127)  /* CGNAT 100.64/10  */
		return TRUE;
	if (o[0] == 127)                               /* loopback         */
		return TRUE;
	if (o[0] == 169 && o[1] == 254)                /* link-local       */
		return TRUE;
	if (o[0] == 172 && o[1] >= 16 && o[1] <= 31)   /* RFC 1918         */
		return TRUE;
	if (o[0] == 192 && o[1] == 168)                /* RFC 1918         */
		return TRUE;
	if (o[0] >= 224 && o[0] <= 239)                /* multicast 224/4  */
		return TRUE;
	if (o[0] >= 240)                               /* reserved 240/4,
	                                                * incl. broadcast  */
		return TRUE;

	return FALSE;
}

/* [ fs_sentinel_dest_never_auto_block ]
 * TRUE when no automatic block may ever target this destination.
 * Literal addresses only: anything that does not parse as an IP is
 * unclassifiable, and unclassifiable means withheld.  Sentinel hits
 * always carry literal addresses, so this costs nothing real and a
 * future source of junk destinations cannot smuggle a block through.
 *
 * IPv4-mapped IPv6 (::ffff:a.b.c.d) is judged as the IPv4 address it
 * stands for, so the mapping cannot launder a LAN address into
 * "public". */
gboolean
fs_sentinel_dest_never_auto_block (const gchar *dest)
{
	guint8 v4[4];
	GInetAddress *addr;
	gboolean never = TRUE;

	if (dest == NULL || *dest == '\0')
		return TRUE;

	if (parse_ipv4_strict (dest, v4))
		return v4_dest_never_auto_block (v4);

	addr = g_inet_address_new_from_string (dest);
	if (addr == NULL)
		return TRUE;   /* not an address: withheld */

	{
		const guint8 *b = g_inet_address_to_bytes (addr);

		if (g_inet_address_get_family (addr) == G_SOCKET_FAMILY_IPV4) {
			never = v4_dest_never_auto_block (b);
		} else {
			gboolean v6_never = FALSE;

			if (g_inet_address_get_is_loopback (addr) ||
			    g_inet_address_get_is_multicast (addr) ||
			    g_inet_address_get_is_link_local (addr) ||
			    g_inet_address_get_is_site_local (addr) ||
			    g_inet_address_get_is_any (addr))
				v6_never = TRUE;
			else if ((b[0] & 0xfe) == 0xfc)          /* ULA fc00::/7    */
				v6_never = TRUE;
			else if (b[0] == 0 && b[1] == 0 && b[2] == 0 &&
			         b[3] == 0 && b[4] == 0 && b[5] == 0 &&
			         b[6] == 0 && b[7] == 0 && b[8] == 0 &&
			         b[9] == 0 && b[10] == 0xff && b[11] == 0xff)
				/* ::ffff:a.b.c.d: judged as the IPv4 it stands
				 * for, so the mapping cannot launder a LAN
				 * address into "public". */
				v6_never = v4_dest_never_auto_block (b + 12);

			never = v6_never;
		}
	}

	g_object_unref (addr);
	return never;
}

/* [ baseline_dest_count ] -- how many connections from `app' to
 * `dest' the historical behavior baseline holds (any port). */
static guint
baseline_dest_count (FsCopilot *copilot, const gchar *app,
                     const gchar *dest)
{
	FsAppProfile *profile;
	guint *count;

	if (copilot == NULL || app == NULL || dest == NULL || *dest == '\0')
		return 0;

	profile = g_hash_table_lookup (copilot->profiles, app);
	if (profile == NULL || profile->common_destinations == NULL)
		return 0;

	count = g_hash_table_lookup (profile->common_destinations, dest);
	if (count == NULL)
		return 0;

	return *count;
}

/* [ fs_copilot_baseline_dest_established ]
 * The other half of the P6 gate: a destination the behavior baseline
 * already records for THIS application is normal traffic, and normal
 * traffic is never auto-blocked, however metronomic its timing looks.
 * That is the browser-to-CDN case from the incident: brave.exe had
 * 27 recorded connections to the "beacon" host -- established,
 * not covert. */
gboolean
fs_copilot_baseline_dest_established (FsCopilot *copilot,
                                      const gchar *app,
                                      const gchar *dest)
{
	return baseline_dest_count (copilot, app, dest) >=
	       FS_SENTINEL_BASELINE_DEST_MIN;
}

/* [ hit_app_key ] -- the per-application profile key, shared by the
 * profile feed and by Sentinel so both consult the SAME baseline row:
 * the service field, minus the Windows backend's " [BLOCKED]"
 * marker, "Unknown" when absent. */
static void
hit_app_key (const FsHit *hit, gchar *buf, gsize size)
{
	g_strlcpy (buf, hit->service != NULL ? hit->service : "", size);

	if (g_str_has_suffix (buf, " [BLOCKED]"))
		buf[strlen (buf) - strlen (" [BLOCKED]")] = '\0';

	if (*buf == '\0')
		g_strlcpy (buf, "Unknown", size);
}

/* [ key_is_program_on_port ] / [ hit_key_is_program ]
 * Whether the profile key names a program (the Windows log's
 * Application Name, "brave.exe") rather than the port's service name
 * ("https", "Unknown"), which is all a Linux log line carries and which
 * every program on that port shares. */
static gboolean
key_is_program_on_port (const gchar *port_text, const gchar *key)
{
	glong port = port_text != NULL ? strtol (port_text, NULL, 10) : 0;
	gchar *svc;
	gboolean program;

	if (g_strcmp0 (key, "Unknown") == 0 || g_strcmp0 (key, _("Unknown")) == 0)
		return FALSE;
	svc = port > 0 && port <= 65535 ? fs_service_lookup_port ((gint) port)
	                                : NULL;
	program = svc == NULL || g_ascii_strcasecmp (svc, key) != 0;
	g_free (svc);
	return program;
}

static gboolean
hit_key_is_program (const FsHit *hit, const gchar *key)
{
	return key_is_program_on_port (hit->port, key);
}

/* [ sentinel_dest_auto_ok_before_run ]
 * The beacon's form of the verdict.  The baseline count includes the
 * metronomic run that is being flagged right now -- those samples are
 * the SUSPICION, not the history, so they come off before comparing:
 * a first-contact stranger's six contacts leave zero history and stay
 * auto-blockable, while a CDN with recorded history beyond the run
 * reads as established and stays report-only.  Subtracting is exact
 * for the run (one dest:port, all in the window); other ports and
 * older contacts to the same destination keep counting, which is
 * precisely the evidence the incident's browser case rested on. */
static gboolean
sentinel_dest_auto_ok_before_run (FsCopilot *copilot, const gchar *app,
                                  const gchar *dest, guint run_samples)
{
	guint before;

	if (fs_sentinel_dest_never_auto_block (dest))
		return FALSE;

	before = baseline_dest_count (copilot, app, dest);
	before = before > run_samples ? before - run_samples : 0;

	return before < FS_SENTINEL_BASELINE_DEST_MIN;
}

/* [ sentinel_dest_established_elsewhere ]
 * The block a beacon stages is "deny outbound to dest": every program,
 * every port.  So a destination ANOTHER program's baseline holds as
 * established (a browser's CDN, an update server) is never blocked
 * automatically because a newer program polls it.  Returns that
 * program and its count, or NULL. */
static const gchar *
sentinel_dest_established_elsewhere (FsCopilot *copilot, const gchar *app,
                                     const gchar *dest, guint *count_out)
{
	GHashTableIter it;
	gpointer k, v;
	const gchar *best = NULL;
	guint best_n = 0;

	g_hash_table_iter_init (&it, copilot->profiles);
	while (g_hash_table_iter_next (&it, &k, &v)) {
		FsAppProfile *p = v;
		guint *n;

		if (g_strcmp0 (k, app) == 0)
			continue;
		n = g_hash_table_lookup (p->common_destinations, dest);
		if (n != NULL && *n >= FS_SENTINEL_BASELINE_DEST_MIN &&
		    (*n > best_n ||
		     (*n == best_n && g_strcmp0 (k, best) < 0))) {
			best = k;
			best_n = *n;
		}
	}
	if (count_out != NULL)
		*count_out = best_n;
	return best;
}

/* [ key_names_program ]
 * A profile key seen without its port: a program unless it is one of
 * the names a Linux log line can carry instead (a service name from
 * the port table, ICMP, ICMPv6, "Unknown"). */
static gboolean
key_names_program (const gchar *key)
{
	if (key == NULL || g_strcmp0 (key, "Unknown") == 0 ||
	    g_strcmp0 (key, _("Unknown")) == 0 ||
	    g_ascii_strcasecmp (key, "ICMP") == 0 ||
	    g_ascii_strcasecmp (key, "ICMPv6") == 0)
		return FALSE;
	return fs_service_find (key) == NULL;
}

/* [ policy_allows_dest ]
 * TRUE when the policy holds an outbound "allow to host" row of the
 * user's whose target names this destination: the same address, or a
 * network or range around it.  "Anyone" rows do not count (they say
 * nothing about this host).  A Sentinel block is "deny outbound to
 * host", and on Windows a block outranks an allow, so staging one over
 * such a row would silently overrule the user's own Allow. */
static gboolean
policy_allows_dest (const FsPolicy *policy, const gchar *dest)
{
	GPtrArray *rows;

	if (policy == NULL || dest == NULL)
		return FALSE;
	rows = policy->kinds[FS_RULE_OUTBOUND_ALLOW_TO];
	for (guint i = 0; rows != NULL && i < rows->len; i++) {
		const FsRule *r = g_ptr_array_index (rows, i);
		FsRangeSet *set;
		gboolean hit;

		if (r->target == NULL || *r->target == '\0' ||
		    fs_util_target_is_anyone (r->target))
			continue;
		if (g_ascii_strcasecmp (r->target, dest) == 0)
			return TRUE;
		set = fs_range_set_new ();
		hit = fs_range_set_add_text (set, r->target);
		if (hit) {
			fs_range_set_normalize (set);
			hit = fs_range_set_contains_text (set, dest);
		}
		fs_range_set_free (set);
		if (hit)
			return TRUE;
	}
	return FALSE;
}

/* [ beacon_auto_withheld ]
 * The beacon's automatic-block gates, in one place, so the finding
 * when it is made and Sentinel's pass when it stages (which can be
 * much later: after a tray pause, a switch from Detect only, a failed
 * write's retry) judge with the same rules and the same, current,
 * facts.  NULL when the automatic block may go ahead; otherwise why
 * not, as the drawer shows it.  `run' is how many contacts the timed
 * run holds in all (its samples are the suspicion, not history), and
 * `stamps' how many the series holds now. */
static gchar *
beacon_auto_withheld (FsCopilot *copilot, const gchar *app,
                      const gchar *dst, const gchar *port,
                      guint run, guint stamps)
{
	guint portnum = port != NULL ? (guint) strtoul (port, NULL, 10) : 0;
	gboolean dns_port = portnum == 53 || portnum == 853;
	gboolean program = key_is_program_on_port (port, app);
	const gchar *other;
	guint other_n = 0;

	if (stamps < FS_SENTINEL_BEACON_AUTO_MIN)
		return g_strdup_printf (
			_("Report only for now: an automatic block waits for %d "
			  "contacts, and there are %u."),
			FS_SENTINEL_BEACON_AUTO_MIN, stamps);
	if (fs_sentinel_dest_never_auto_block (dst))
		return g_strdup (
			_("Report only: the destination is on the local network "
			  "or is network infrastructure, which is never blocked "
			  "automatically."));
	if (copilot_is_infrastructure (copilot, dst))
		return g_strdup (
			_("Report only: this address is one of this computer's "
			  "DNS servers or its default gateway, which are never "
			  "blocked automatically."));
	if (dns_port && copilot_dns_upstream_unknown (copilot))
		return g_strdup (
			_("Report only: DNS on this computer goes through a "
			  "local resolver whose upstream servers could not be "
			  "read, and this may be one of them."));
	if (policy_allows_dest (copilot->policy, dst))
		return g_strdup (
			_("Report only: you allowed this destination in your "
			  "policy, and an automatic block would overrule your "
			  "allow."));
	if (!sentinel_dest_auto_ok_before_run (copilot, app, dst, run))
		return g_strdup (program
			? _("Report only: this program already talked to this "
			    "destination before the run, so it is normal traffic "
			    "for it.")
			: _("Report only: traffic on this port already reached "
			    "this destination before the run, so it is normal "
			    "traffic for it."));
	other = sentinel_dest_established_elsewhere (copilot, app, dst,
	                                             &other_n);
	if (other != NULL)
		return key_names_program (other)
			? g_strdup_printf (
				_("Report only: %s has %u recorded connections to "
				  "this destination, and the block would apply to "
				  "every program."), other, other_n)
			: g_strdup_printf (
				_("Report only: traffic on the %s port (any program) "
				  "has %u recorded connections to this destination, "
				  "and the block would apply to every program."),
				other, other_n);
	return NULL;
}

/* [ fs_copilot_beacon_recheck ] -- see fs-copilot.h. */
gboolean
fs_copilot_beacon_recheck (FsCopilot *copilot, FsInsight *insight)
{
	const gchar *series, *bar, *colon, *slash;
	GArray *stamps;
	gchar *app, *dst, *port, *why;
	guint run, n;

	if (copilot == NULL || insight == NULL)
		return FALSE;
	if (!insight->auto_applicable)
		return FALSE;
	if (insight->type != FS_INSIGHT_BEACON)
		return TRUE;

	/* "beacon|app|dst:port/proto": the series key after "beacon|". */
	if (insight->key == NULL ||
	    !g_str_has_prefix (insight->key, "beacon|"))
		goto refuse;
	series = insight->key + strlen ("beacon|");
	bar    = strrchr (series, '|');
	colon  = bar != NULL ? strrchr (bar, ':') : NULL;
	slash  = colon != NULL ? strchr (colon, '/') : NULL;
	if (bar == NULL || colon == NULL || slash == NULL)
		goto refuse;

	stamps = g_hash_table_lookup (copilot->beacon_stamps, series);
	n   = stamps != NULL ? stamps->len : insight->count;
	run = GPOINTER_TO_UINT (g_hash_table_lookup (copilot->beacon_total,
	                                             series));
	if (run < n)
		run = n;

	app  = g_strndup (series, (gsize) (bar - series));
	dst  = g_strndup (bar + 1, (gsize) (colon - bar - 1));
	port = g_strndup (colon + 1, (gsize) (slash - colon - 1));
	copilot_network_fresh (copilot);
	why  = beacon_auto_withheld (copilot, app, dst, port, run, n);
	g_free (app);
	g_free (dst);
	g_free (port);
	if (why == NULL)
		return TRUE;

	g_free (insight->withheld);
	insight->withheld = why;
	insight->auto_applicable = FALSE;
	return FALSE;

refuse:
	/* A beacon whose series cannot be read back cannot be re-judged,
	 * and what cannot be re-judged is not blocked automatically. */
	g_free (insight->withheld);
	insight->withheld = g_strdup (
		_("Report only: the finding could not be checked again."));
	insight->auto_applicable = FALSE;
	return FALSE;
}

/* [ app_profile_new ] */
static FsAppProfile *
app_profile_new (const gchar *name, const gchar *path, gint64 now_unix)
{
	FsAppProfile *profile = g_new0 (FsAppProfile, 1);
	profile->app_name = g_strdup (name);
	profile->app_path = path ? g_strdup (path) : NULL;
	/* Every value is a g_new'd counter (record_connection and the
	 * profile loader), so the tables own and free them: without a
	 * value destructor each counter outlived its profile, and a
	 * long monitoring session leaked one per port, destination and
	 * hour of every application the LRU cap evicted. */
	profile->common_ports = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                               NULL, g_free);
	profile->common_destinations = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                                      g_free, g_free);
	profile->hourly_activity = g_hash_table_new_full (g_direct_hash, g_direct_equal,
                                                      NULL, g_free);
	profile->first_seen = (guint64) now_unix;
	profile->new_dest_times = g_array_new (FALSE, FALSE, sizeof (gint64));
	return profile;
}

/* [ app_profile_free ] */
static void
app_profile_free (FsAppProfile *profile)
{
	if (profile == NULL)
		return;

	g_free (profile->app_name);
	g_free (profile->app_path);
	g_hash_table_unref (profile->common_ports);
	g_hash_table_unref (profile->common_destinations);
	g_hash_table_unref (profile->hourly_activity);
	if (profile->new_dest_times != NULL)
		g_array_unref (profile->new_dest_times);
	g_free (profile);
}

/* [ app_profile_record_connection ]
 * The single write path of a profile: totals, port, destination,
 * hour of day, and the open rate window.  The clock arrives from the
 * caller (feed_event_full), so the tests drive wall time and every
 * timing finding is deterministic.  Port 0 (ICMP, unparsed) is not a
 * port and is never stored.  The set tables are bounded; hitting a
 * cap marks the profile partial so no later signal can claim a
 * truncated baseline knows everything. */
static void
app_profile_record_connection (FsAppProfile *profile,
                               const gchar *remote_ip,
                               guint port,
                               const gchar *protocol,
                               gboolean inbound,
                               guint64 bytes,
                               gint64 now_unix)
{
	guint64 bucket;
	GDateTime *dt;
	gint hour;

	(void) protocol;
	(void) inbound;

	profile->total_connections++;
	profile->last_seen = (guint64) now_unix;

	if (bytes > 0)
	{
		if (bytes > 0) /* Direction inferred from context */
			profile->total_bytes_recv += bytes;
		else
			profile->total_bytes_sent += bytes;
	}

	/* Record port usage. */
	if (port != 0)
	{
		guint *port_count = g_hash_table_lookup (profile->common_ports,
		                                         GUINT_TO_POINTER (port));
		if (port_count == NULL)
		{
			if (g_hash_table_size (profile->common_ports) >=
			    FS_BEHAVIOR_MAX_PORTS)
				profile->baseline_partial = TRUE;
			else {
				guint *new_count = g_new (guint, 1);
				*new_count = 1;
				g_hash_table_insert (profile->common_ports,
				                     GUINT_TO_POINTER (port),
				                     new_count);
			}
		}
		else
		{
			(*port_count)++;
		}
	}

	/* Record destination. */
	if (remote_ip && *remote_ip)
	{
		guint *dest_count = g_hash_table_lookup (profile->common_destinations,
		                                         remote_ip);
		if (dest_count == NULL)
		{
			if (g_hash_table_size (profile->common_destinations) >=
			    FS_BEHAVIOR_MAX_DESTS)
				profile->baseline_partial = TRUE;
			else {
				guint *new_count = g_new (guint, 1);
				*new_count = 1;
				g_hash_table_insert (profile->common_destinations,
				                     g_strdup (remote_ip),
				                     new_count);
			}
		}
		else
		{
			(*dest_count)++;
		}
	}

	/* Record hourly activity from the caller's wall clock. */
	dt = g_date_time_new_from_unix_local (now_unix);
	hour = dt != NULL ? g_date_time_get_hour (dt) : 0;
	if (dt != NULL)
		g_date_time_unref (dt);

	{
		guint64 *hour_count = g_hash_table_lookup (profile->hourly_activity,
		                                           GUINT_TO_POINTER (hour));
		if (hour_count == NULL)
		{
			guint64 *new_count = g_new (guint64, 1);
			*new_count = 1;
			g_hash_table_insert (profile->hourly_activity,
			                     GUINT_TO_POINTER (hour), new_count);
		}
		else
		{
			(*hour_count)++;
		}
	}

	/* Record the rate window: close the open one when the clock has
	 * moved to another 10-minute bucket, then count this event in the
	 * current bucket.  The established rate is an integer EWMA
	 * (x1000, alpha 0.25) seeded with the first closed bucket. */
	bucket = (guint64) ((now_unix / FS_BEHAVIOR_WINDOW_S) *
	                    FS_BEHAVIOR_WINDOW_S);
	if (bucket == 0)
		bucket = FS_BEHAVIOR_WINDOW_S;   /* guard: 0 means "no window" */

	if (profile->rate_window_start != 0 &&
	    profile->rate_window_start != bucket)
	{
		if (profile->rate_buckets == 0)
			profile->rate_ema_milli =
				profile->rate_window_count * 1000;
		else
			profile->rate_ema_milli = (guint) (
				(gint64) profile->rate_ema_milli +
				((250 * ((gint64) profile->rate_window_count * 1000 -
				         (gint64) profile->rate_ema_milli)) / 1000));
		profile->rate_buckets++;
		profile->rate_window_count = 0;
	}

	profile->rate_window_start = bucket;
	profile->rate_window_count++;
}

/* [ is_novel_port ]
 * Recording happens BEFORE analysis, so a port first used by THIS
 * event has a count of exactly 1 -- that is the whole honest test.
 * (The old check fired while the count was < 3, so the same port was
 * reported two or three times while its message claimed the app had
 * "never used it before".) */
static gboolean
is_novel_port (FsAppProfile *profile, guint port)
{
	guint *count;

	if (port == 0)
		return FALSE;

	count = g_hash_table_lookup (profile->common_ports,
	                             GUINT_TO_POINTER (port));
	return count != NULL && *count == 1;
}

/* [ is_novel_destination ] -- same discipline: count == 1 means this
 * event made first contact. */
static gboolean
is_novel_destination (FsAppProfile *profile, const gchar *remote_ip)
{
	guint *count;

	if (remote_ip == NULL || *remote_ip == '\0')
		return FALSE;

	count = g_hash_table_lookup (profile->common_destinations, remote_ip);
	return count != NULL && *count == 1;
}

/* [ is_novel_hour ]
 * The first time an application is active in an hour -- but only once
 * it has ESTABLISHED hours to be outside of: with fewer than four
 * hour buckets the profile has no "usual hours" yet, and calling any
 * new hour unusual would be theater. */
static gboolean
is_novel_hour (FsAppProfile *profile, gint64 now_unix)
{
	GDateTime *dt;
	guint64 *count;
	gboolean novel;

	dt = g_date_time_new_from_unix_local (now_unix);
	if (dt == NULL)
		return FALSE;

	count = g_hash_table_lookup (profile->hourly_activity,
	                             GUINT_TO_POINTER (g_date_time_get_hour (dt)));
	g_date_time_unref (dt);

	if (count == NULL || *count != 1)
		return FALSE;

	novel = g_hash_table_size (profile->hourly_activity) >=
	        FS_BEHAVIOR_HOURS_MIN_DISTINCT;
	return novel;
}

/* [ rate_spike_take ]
 * Connection frequency: this event's 10-minute bucket holds far more
 * than the rate the application has established over the previous
 * buckets.  TRUE at most once per bucket (rate_reported is consumed
 * here -- the count keeps growing while the bucket is open, and one
 * report per burst is the honest number).  Integer arithmetic only:
 * same inputs, same verdict, every run. */
static gboolean
rate_spike_take (FsAppProfile *profile, gint64 now_unix)
{
	guint64 window;
	guint threshold;

	if (profile->rate_buckets < FS_BEHAVIOR_RATE_MIN_BUCKETS)
		return FALSE;                   /* rate not established yet */

	window = (guint64) ((now_unix / FS_BEHAVIOR_WINDOW_S) *
	                    FS_BEHAVIOR_WINDOW_S);
	if (window == 0)
		window = FS_BEHAVIOR_WINDOW_S;

	if (profile->rate_window_start != window)
		return FALSE;                   /* only the open bucket counts */
	if (profile->rate_reported == window)
		return FALSE;                   /* already reported this burst */
	if (profile->rate_window_count < FS_BEHAVIOR_RATE_MIN_EVENTS)
		return FALSE;                   /* floor, whatever the rate */

	threshold = (profile->rate_ema_milli / 1000) * 3 + 5;
	if (profile->rate_window_count <= threshold)
		return FALSE;

	profile->rate_reported = window;
	return TRUE;
}

/* [ brief_ports ] / [ brief_hours ]
 * The numbers a signal line shows: up to six sorted ports, up to
 * eight sorted hours, "... past the cut, "none" when empty.  Bounded
 * on purpose -- a finding is a sentence, not a dump. */
static gint
cmp_port_key (gconstpointer a, gconstpointer b)
{
	return (gint) GPOINTER_TO_UINT (a) - (gint) GPOINTER_TO_UINT (b);
}

static gchar *
brief_ports (FsAppProfile *profile)
{
	GList *keys = g_hash_table_get_keys (profile->common_ports);
	GString *out = g_string_new (NULL);
	GList *l;
	guint n = 0;

	keys = g_list_sort (keys, cmp_port_key);
	for (l = keys; l != NULL; l = l->next) {
		if (n == 6) {
			g_string_append (out, ", ...");
			break;
		}
		if (n > 0)
			g_string_append (out, ", ");
		g_string_append_printf (out, "%u",
		                        GPOINTER_TO_UINT (l->data));
		n++;
	}
	g_list_free (keys);

	if (out->len == 0)
		g_string_append (out, "none");

	return g_string_free (out, FALSE);
}

static gchar *
brief_hours (FsAppProfile *profile)
{
	GList *keys = g_hash_table_get_keys (profile->hourly_activity);
	GString *out = g_string_new (NULL);
	GList *l;
	guint n = 0;

	keys = g_list_sort (keys, cmp_port_key);
	for (l = keys; l != NULL; l = l->next) {
		if (n == 8) {
			g_string_append (out, ", ...");
			break;
		}
		if (n > 0)
			g_string_append (out, ", ");
		g_string_append_printf (out, "%02u",
		                        GPOINTER_TO_UINT (l->data));
		n++;
	}
	g_list_free (keys);

	if (out->len == 0)
		g_string_append (out, "none");

	return g_string_free (out, FALSE);
}

static FsEvidence *evidence_from_hit (const FsHit *hit, gboolean inbound,
                                      gint64 when);
static void insight_add_evidence (FsInsight *insight, FsEvidence *ev);
static gboolean hit_is_blocked_marker (const FsHit *hit);

/* [ newdest_churn ]
 * How many first contacts the app made in the last seven days, after
 * forgetting older ones.  Bounded: only the newest 64 are kept, which
 * is far past the churn limit. */
static guint
newdest_churn (FsAppProfile *profile, gint64 now_unix)
{
	GArray *t = profile->new_dest_times;

	while (t->len > 0 &&
	       g_array_index (t, gint64, 0) < now_unix - FS_NEWDEST_MIN_AGE_S)
		g_array_remove_index (t, 0);
	return t->len;
}

static void
newdest_note (FsAppProfile *profile, gint64 now_unix)
{
	g_array_append_val (profile->new_dest_times, now_unix);
	if (profile->new_dest_times->len > 64)
		g_array_remove_index (profile->new_dest_times, 0);
}

/* [ behavior_analyze ]
 * Correlate, don't chain.  Every signal this event raises goes into ONE
 * finding whose description lists each signal with its numbers.
 *
 *   new port         the app's first use of a port (count == 1), once
 *                    the profile has its 10-event baseline;
 *   new destination  a first contact with a public address, only for a
 *                    profile at least 7 days old with 50 connections,
 *                    not capped, and not "browser-like" (20 or more new
 *                    hosts in 7 days); one finding per app per hour;
 *   new hour         the first activity in an hour, once 4 hours are
 *                    known;
 *   rate spike       this 10-minute bucket far above the app's own
 *                    rate (connections, not bytes: the logs carry no
 *                    byte counts).
 *
 * Each signal alone is Info; two together are a Warning.  A finding
 * here never carries a rule: an anomaly is not answered by allowing it,
 * and a block is the user's call (Ask What-If shows what it would do). */
static void
behavior_analyze (FsCopilot *copilot, FsAppProfile *profile,
                  const gchar *app_name, const gchar *remote_ip,
                  guint port, gint64 now_unix, const FsHit *hit,
                  gboolean inbound)
{
	gboolean sig_port, sig_dest, sig_hour, sig_rate;
	GPtrArray *lines;
	GPtrArray *whys;
	GString *desc;
	FsInsightType type;
	FsCopilotSeverity severity;
	FsInsight *insight;
	gchar *title;
	guint n, i;
	gint64 age = now_unix - (gint64) profile->first_seen;

	(void) copilot;

	/* Inbound, the remote host picks the local port: a stranger's
	 * probe is not the program "using" a port (and a scan would be
	 * hundreds of such findings), so the signal is outbound only, like
	 * the new-destination one.  The scan check reports inbound ports. */
	sig_port = !profile->baseline_partial && !inbound &&
	           is_novel_port (profile, port);
	sig_dest = !profile->baseline_partial && !inbound &&
	           is_novel_destination (profile, remote_ip);
	if (sig_dest) {
		guint churn = newdest_churn (profile, now_unix);

		newdest_note (profile, now_unix);
		if (profile->total_connections < FS_NEWDEST_MIN_CONNECTIONS ||
		    age < FS_NEWDEST_MIN_AGE_S ||
		    churn >= FS_NEWDEST_CHURN ||
		    fs_range_set_contains_text (fs_range_protected (),
		                                remote_ip) ||
		    fs_sentinel_dest_never_auto_block (remote_ip))
			sig_dest = FALSE;
	}
	sig_hour = is_novel_hour (profile, now_unix);
	sig_rate = rate_spike_take (profile, now_unix);

	if (!sig_port && !sig_dest && !sig_hour && !sig_rate)
		return;

	lines = g_ptr_array_new_with_free_func (g_free);
	whys = g_ptr_array_new_with_free_func (g_free);

	if (sig_port) {
		gchar *known = brief_ports (profile);

		g_ptr_array_add (lines, g_strdup_printf (
			_("first use of port %u. Before this, the baseline knew "
			  "%s"),
			port, known));
		g_ptr_array_add (whys, g_strdup_printf (
			_("port %u had 0 earlier uses in %" G_GUINT64_FORMAT
			  " recorded connections"), port,
			profile->total_connections - 1));
		g_free (known);
	}
	if (sig_dest) {
		g_ptr_array_add (lines, g_strdup_printf (
			_("first contact with %s. The baseline knew %u "
			  "destinations"),
			remote_ip,
			g_hash_table_size (profile->common_destinations) - 1));
		g_ptr_array_add (whys, g_strdup_printf (
			_("a public address never seen in %" G_GUINT64_FORMAT
			  " connections over %" G_GINT64_FORMAT " days (the check "
			  "needs 50 connections and 7 days)"),
			profile->total_connections - 1, age / 86400));
	}
	if (sig_hour) {
		GDateTime *dt = g_date_time_new_from_unix_local (now_unix);
		gchar *hours = brief_hours (profile);
		gint hour = dt != NULL ? g_date_time_get_hour (dt) : 0;

		g_ptr_array_add (lines, g_strdup_printf (
			_("first activity at %02d:00. Established hours: %s"),
			hour, hours));
		g_ptr_array_add (whys, g_strdup_printf (
			_("no earlier activity at %02d:00, with %u other hours known "
			  "(the check needs 4)"), hour,
			g_hash_table_size (profile->hourly_activity) - 1));
		g_free (hours);
		if (dt != NULL)
			g_date_time_unref (dt);
	}
	if (sig_rate) {
		g_ptr_array_add (lines, g_strdup_printf (
			_("%u connections in the last 10 minutes. The usual "
			  "rate is about %u per 10 minutes"),
			profile->rate_window_count,
			profile->rate_ema_milli / 1000));
		g_ptr_array_add (whys, g_strdup_printf (
			_("%u connections in this 10-minute bucket; the limit is 3 "
			  "times the usual %u plus 5, and at least 10"),
			profile->rate_window_count,
			profile->rate_ema_milli / 1000));
	}

	n = lines->len;

	type = sig_port ? FS_INSIGHT_UNUSUAL_PORT
	     : sig_dest ? FS_INSIGHT_UNUSUAL_DESTINATION
	     : sig_rate ? FS_INSIGHT_UNUSUAL_VOLUME
	     :            FS_INSIGHT_UNUSUAL_TIME;
	severity = n > 1 ? FS_COPILOT_WARNING : FS_COPILOT_INFO;

	if (n > 1)
		title = g_strdup_printf (_("Several changes at once for %s"),
		                         app_name);
	else if (sig_port)
		title = g_strdup_printf (_("%s used port %u for the first time"),
		                         app_name, port);
	else if (sig_dest)
		title = g_strdup_printf (_("New destinations for %s"), app_name);
	else if (sig_rate)
		title = g_strdup_printf (_("Connection rate spike for %s"),
		                         app_name);
	else
		title = g_strdup_printf (_("%s active at a new hour"), app_name);

	desc = g_string_new (NULL);
	g_string_append_printf (desc,
	                        _("%s differs from its established "
	                          "baseline:"),
	                        app_name);
	for (i = 0; i < n; i++)
		g_string_append_printf (desc, "\n- %s",
		                        (const gchar *)
		                        g_ptr_array_index (lines, i));

	insight = create_insight (type, severity, title,
	                          g_string_free (desc, FALSE), app_name,
	                          (sig_dest || sig_port) ? remote_ip : NULL);
	g_free (title);

	{
		GString *w = g_string_new (NULL);

		for (i = 0; i < whys->len; i++) {
			const gchar *t = g_ptr_array_index (whys, i);

			if (i > 0)
				g_string_append (w, "; ");
			g_string_append_c (w, g_ascii_toupper (t[0]));
			g_string_append (w, t + 1);
		}
		g_string_append_c (w, '.');
		insight->why = g_string_free (w, FALSE);
	}
	insight->benign = g_strdup (
		sig_rate && n == 1
		? _("Updates, backups, syncs and page loads with many parts make "
		    "bursts of connections too.")
		: _("Updates, new features and new servers of the same service "
		    "change what a program talks to."));

	/* The dedup key: a new destination in the same hour joins the open
	 * finding; every other signal is one finding per subject. */
	if (sig_dest && n == 1)
		insight->key = g_strdup_printf ("dest|%s|%" G_GINT64_FORMAT,
		                                app_name, now_unix / 3600);
	else if (sig_port)
		insight->key = g_strdup_printf ("port|%s|%u", app_name, port);
	else if (sig_rate)
		insight->key = g_strdup_printf ("rate|%s|%" G_GUINT64_FORMAT,
		                                app_name,
		                                profile->rate_window_start);
	else
		insight->key = g_strdup_printf ("hour|%s|%" G_GINT64_FORMAT,
		                                app_name, now_unix / 3600);
	insight->subject = g_strdup (app_name);
	if (remote_ip != NULL && *remote_ip != '\0') {
		const gchar *proto = hit->protocol != NULL &&
			g_ascii_strcasecmp (hit->protocol, "UDP") == 0
			? "udp" : "tcp";

		insight->events_filter = g_strdup (remote_ip);
		if (port != 0)
			insight->whatif_line = g_strdup_printf (
				inbound ? "inbound %s port %u from %s"
				        : "outbound %s port %u to %s",
				proto, port, remote_ip);
	}
	insight_add_evidence (insight, evidence_from_hit (hit, inbound,
	                                                  now_unix));

	insight->timestamp = now_unix;
	emit_insight (copilot, insight);

	g_ptr_array_unref (lines);
	g_ptr_array_unref (whys);
}

/* The four baseline signals are one check (behavior); every other
 * type is its own.  Escalation needs two different checks. */
static gint
insight_family (FsInsightType type)
{
	switch (type) {
	case FS_INSIGHT_UNUSUAL_PORT:
	case FS_INSIGHT_UNUSUAL_DESTINATION:
	case FS_INSIGHT_UNUSUAL_VOLUME:
	case FS_INSIGHT_UNUSUAL_TIME:
		return -1;
	default:
		return (gint) type;
	}
}

/* [ emit_insight ]
 * Every finding enters through here.
 *
 *   - Dedup: a finding whose key matches an open one updates it (count,
 *     evidence, numbers, auto-block state) instead of adding a row, so
 *     a long run is one finding that grows, not a list that floods.
 *   - Escalation: two DIFFERENT checks on the same subject within an
 *     hour make both Critical, and each says so (the four baseline
 *     signals count as one check).
 *   - Bound: the list holds at most 200; the oldest falls off. */
static void
emit_insight (FsCopilot *copilot, FsInsight *insight)
{
	GList *l;

	if (insight->count == 0)
		insight->count = 1;

	if (insight->key != NULL) {
		for (l = copilot->insights; l != NULL; l = l->next) {
			FsInsight *old = l->data;

			if (g_strcmp0 (old->key, insight->key) != 0)
				continue;

			/* A check that re-reports its whole run (timed contacts,
			 * a scan, login attempts) replaces the evidence; the
			 * others add their event to it. */
			if (insight->type == FS_INSIGHT_BEACON ||
			    insight->type == FS_INSIGHT_INBOUND_SCAN ||
			    insight->type == FS_INSIGHT_BRUTE_FORCE) {
				old->count = insight->count;
				if (old->evidence != NULL)
					g_ptr_array_set_size (old->evidence, 0);
			} else {
				old->count += insight->count;
			}
			old->timestamp = insight->timestamp;
			if (insight->severity > old->severity)
				old->severity = insight->severity;
			/* A beacon now blocked by a list or a country or network
			 * rule carries no block and no What-If line: an earlier
			 * report's must not stay on the card (CORRECTNESS-2). */
			if (insight->type == FS_INSIGHT_BEACON &&
			    insight->rule_csv == NULL) {
				g_clear_pointer (&old->rule_csv, g_free);
				g_clear_pointer (&old->suggested_rule, g_free);
				g_clear_pointer (&old->whatif_line, g_free);
			}
#define TAKE(f) do { if (insight->f != NULL) { g_free (old->f); \
                     old->f = insight->f; insight->f = NULL; } } while (0)
			TAKE (title);
			TAKE (description);
			TAKE (why);
			TAKE (benign);
			TAKE (suggested_rule);
			TAKE (rule_csv);
			TAKE (whatif_line);
#undef TAKE
			g_free (old->withheld);
			old->withheld = insight->withheld;
			insight->withheld = NULL;
			old->rule_kind = insight->rule_kind;
			old->auto_applicable = insight->auto_applicable;
			while (insight->evidence != NULL &&
			       insight->evidence->len > 0)
				insight_add_evidence (old,
					g_ptr_array_steal_index (insight->evidence, 0));
			fs_insight_free (insight);

			/* Keep it at the top: it is the newest news. */
			copilot->insights = g_list_remove_link (copilot->insights, l);
			copilot->insights = g_list_concat (l, copilot->insights);
			return;
		}
	}

	if (insight->subject != NULL) {
		for (l = copilot->insights; l != NULL; l = l->next) {
			FsInsight *old = l->data;
			gchar *note;

			if (insight_family (old->type) ==
			    insight_family (insight->type) ||
			    g_strcmp0 (old->subject, insight->subject) != 0 ||
			    insight->timestamp - old->timestamp > FS_REPORT_QUIET_S)
				continue;

			insight->severity = FS_COPILOT_CRITICAL;
			note = g_strdup_printf (
				_("%s Also flagged as \"%s\" within the hour, so this is "
				  "Critical."), insight->why != NULL ? insight->why : "",
				fs_insight_type_name (old->type));
			g_free (insight->why);
			insight->why = note;
			if (old->severity != FS_COPILOT_CRITICAL) {
				old->severity = FS_COPILOT_CRITICAL;
				note = g_strdup_printf (
					_("%s Also flagged as \"%s\" within the hour, so this "
					  "is Critical."), old->why != NULL ? old->why : "",
					fs_insight_type_name (insight->type));
				g_free (old->why);
				old->why = note;
			}
			break;
		}
	}

	copilot->insights = g_list_prepend (copilot->insights, insight);

	/* The bound.  What falls off first is the oldest baseline finding
	 * (new port, destination, hour, rate): those are Info-level and
	 * there can be many.  A Sentinel, scan, login or block-list
	 * finding goes only when nothing else is left, so a flood of
	 * small findings can never push the one that matters out. */
	while (g_list_length (copilot->insights) > FS_COPILOT_MAX_INSIGHTS) {
		GList *victim = NULL;

		for (l = g_list_last (copilot->insights); l != NULL; l = l->prev)
			if (insight_family (((FsInsight *) l->data)->type) == -1) {
				victim = l;
				break;
			}
		if (victim == NULL)
			victim = g_list_last (copilot->insights);

		fs_insight_free (victim->data);
		copilot->insights = g_list_delete_link (copilot->insights,
		                                        victim);
	}
}

/* ---- evidence ----------------------------------------------------- */

static gboolean
hit_is_blocked_marker (const FsHit *hit)
{
	return hit->service != NULL &&
	       strstr (hit->service, " [BLOCKED]") != NULL;
}

/* [ evidence_from_hit ] -- one row of "What we saw". */
static FsEvidence *
evidence_from_hit (const FsHit *hit, gboolean inbound, gint64 when)
{
	FsEvidence *ev = g_new0 (FsEvidence, 1);
	const gchar *remote = inbound ? hit->source : hit->destination;

	ev->when = when;
	ev->inbound = inbound;
	ev->remote = g_strdup (remote != NULL ? remote : "");
	ev->port = hit->port != NULL ? (guint) strtoul (hit->port, NULL, 10)
	                             : 0;
	if (ev->port > 65535)
		ev->port = 0;
	ev->protocol = g_strdup (hit->protocol != NULL ? hit->protocol : "");
	ev->blocked = hit_is_blocked_marker (hit) ||
	              (hit->rule != NULL && *hit->rule != '\0');
	ev->rule = g_strdup (hit->rule);
	return ev;
}

static void
insight_add_evidence (FsInsight *insight, FsEvidence *ev)
{
	if (ev == NULL)
		return;
	if (insight->evidence == NULL)
		insight->evidence = g_ptr_array_new_with_free_func (
			(GDestroyNotify) fs_evidence_free);
	g_ptr_array_add (insight->evidence, ev);
	while (insight->evidence->len > FS_INSIGHT_MAX_EVIDENCE)
		g_ptr_array_remove_index (insight->evidence, 0);
}

/* [ reported_recently ] -- once per subject per hour; takes the slot. */
static gboolean
report_take (FsCopilot *copilot, const gchar *what, gint64 now_unix)
{
	gint64 *at = g_hash_table_lookup (copilot->reported_at, what);

	if (at != NULL && now_unix - *at < FS_REPORT_QUIET_S)
		return FALSE;

	if (g_hash_table_size (copilot->reported_at) > 4096) {
		GHashTableIter it;
		gpointer k, v;

		g_hash_table_iter_init (&it, copilot->reported_at);
		while (g_hash_table_iter_next (&it, &k, &v))
			if (now_unix - *(gint64 *) v >= FS_REPORT_QUIET_S)
				g_hash_table_iter_remove (&it);
	}
	at = g_new (gint64, 1);
	*at = now_unix;
	g_hash_table_insert (copilot->reported_at, g_strdup (what), at);
	return TRUE;
}

/* The class of a remote address, for the inbound checks. */
typedef enum { ADDR_PUBLIC, ADDR_LAN, ADDR_IGNORE } AddrClass;

static AddrClass
addr_class (const gchar *text)
{
	guint32 a;
	FsU128 v6;
	FsAddrFamily fam;

	if (text == NULL || *text == '\0')
		return ADDR_IGNORE;
	fam = fs_addr_parse (text, &a, &v6);
	if (fam == FS_AF_V4) {
		guint8 o0 = a >> 24, o1 = (a >> 16) & 255;

		if (o0 == 0 || o0 == 127 || o0 >= 224 ||
		    (o0 == 169 && o1 == 254))
			return ADDR_IGNORE;
		if (o0 == 10 || (o0 == 172 && (o1 & 0xf0) == 16) ||
		    (o0 == 192 && o1 == 168) || (o0 == 100 && (o1 & 0xc0) == 64))
			return ADDR_LAN;
		return ADDR_PUBLIC;
	}
	if (fam == FS_AF_V6) {
		guint16 top = (guint16) (v6.hi >> 48);

		if ((v6.hi == 0 && v6.lo <= 1) || (top & 0xffc0) == 0xfe80 ||
		    (top & 0xff00) == 0xff00)
			return ADDR_IGNORE;
		if ((top & 0xfe00) == 0xfc00)
			return ADDR_LAN;
		return ADDR_PUBLIC;
	}
	return ADDR_IGNORE;
}

static gdouble
sqrt_d (gdouble x)
{
	gdouble r = x > 1.0 ? x : 1.0;

	if (x <= 0.0)
		return 0.0;
	for (gint i = 0; i < 60; i++)
		r = 0.5 * (r + x / r);
	return r;
}

/* ---- Sentinel: timed contacts and fan-out ------------------------- */

/* [ sentinel_hit_is_inbound ]
 * The Windows backend writes "in"/"out"; the parser "In"/"Out". */
static gboolean
sentinel_hit_is_inbound (const FsHit *hit)
{
	if (hit->direction == NULL)
		return FALSE;

	return g_ascii_strcasecmp (hit->direction, "In") == 0 ||
	       g_ascii_strcasecmp (hit->direction, "Inbound") == 0;
}

/* [ sentinel_hit_is_blocked ]
 * The backends append " [BLOCKED]" to the service field of dropped
 * events; blocked fan-out is the strongest scan signal. */
static gboolean
sentinel_hit_is_blocked (const FsHit *hit)
{
	return hit_is_blocked_marker (hit);
}

/* A list's block and a country or network rule's block both carry
 * "Threat intel: <name>" (fs_intel_rule_text: one log marker, one
 * id space for lists and location rules). */
static gboolean
hit_rule_is_intel (const FsHit *hit)
{
	return hit->rule != NULL &&
	       g_str_has_prefix (hit->rule, "Threat intel:");
}

/* [ sentinel_beacon_check ]
 * Regularity, not content: a host contacted every N seconds with
 * near-fixed intervals.  Per application and destination:port, so two
 * programs polling one server are two series.  Arrival times are
 * bucketed to whole seconds (a polled batch is one moment), the series
 * is capped at 32; each contact keeps its own refused flag and rule,
 * and TCP and UDP are separate series.  Reported at 6 regular contacts;
 * the automatic block waits for 8 (the report is updated when they
 * arrive).  NTP (port 123) and DNS or DNS over TLS (53, 853) to this
 * computer's resolvers are periodic by nature and never timed.  The
 * automatic block is withheld for the LAN and infrastructure, for this
 * computer's resolvers and gateways on any port, for DNS while the
 * upstream resolvers are unknown, for a destination the user's policy
 * allows outbound, and for a destination this program or ANY other
 * program already has a history with (the block applies to every
 * program).  The gates are in beacon_auto_withheld, which the staging
 * pass asks again (fs_copilot_beacon_recheck). */
static FsInsight *
sentinel_beacon_check (FsCopilot *copilot, const FsHit *hit, gint64 now_us,
                       gint64 now_unix)
{
	const gchar *dst, *port;
	gchar app_buf[256];
	gchar *key;
	gboolean key_owned = FALSE;
	GArray *stamps;
	gint64 sec, last, sum = 0;
	gdouble mean, var = 0.0, cv;
	guint i, n_diff, portnum;
	gint stage, want;
	gboolean udp, dns_port;

	if (sentinel_hit_is_inbound (hit))
		return NULL;

	dst  = hit->destination;
	port = hit->port;
	if (dst == NULL || *dst == '\0' || port == NULL || *port == '\0')
		return NULL;

	portnum = (guint) strtoul (port, NULL, 10);
	if (portnum == 123)
		return NULL;                    /* time sync runs on a timer */
	copilot_network_fresh (copilot);
	dns_port = portnum == 53 || portnum == 853;
	if (dns_port && copilot->resolvers != NULL &&
	    fs_range_set_contains_text (copilot->resolvers, dst))
		return NULL;                    /* our own resolvers: DNS and
	                                         * DNS over TLS            */

	hit_app_key (hit, app_buf, sizeof app_buf);
	sec = now_us / G_USEC_PER_SEC;
	udp = hit->protocol != NULL &&
	      g_ascii_strcasecmp (hit->protocol, "UDP") == 0;
	key = g_strdup_printf ("%s|%s:%s/%s", app_buf, dst, port,
	                       udp ? "udp" : "tcp");

	stamps = g_hash_table_lookup (copilot->beacon_stamps, key);
	if (stamps == NULL) {
		stamps = g_array_new (FALSE, TRUE, sizeof (BeaconEv));
		g_array_set_clear_func (stamps, beacon_ev_clear);
		g_hash_table_insert (copilot->beacon_stamps, key, stamps);
		key_owned = TRUE;
	}

	last = stamps->len > 0
	       ? g_array_index (stamps, BeaconEv, stamps->len - 1).sec : -1;
	if (stamps->len == 0 || last < sec) {
		BeaconEv b;

		/* Each contact keeps what its own log line said. */
		b.sec = sec;
		b.blocked = hit_is_blocked_marker (hit) ||
		            (hit->rule != NULL && *hit->rule != '\0');
		b.rule = hit->rule != NULL && *hit->rule != '\0'
		         ? g_strdup (hit->rule) : NULL;
		g_array_append_val (stamps, b);
		if (stamps->len > FS_SENTINEL_BEACON_MAX_STAMPS)
			g_array_remove_index (stamps, 0);
		g_hash_table_insert (copilot->beacon_total, g_strdup (key),
			GUINT_TO_POINTER (GPOINTER_TO_UINT (g_hash_table_lookup (
				copilot->beacon_total, key)) + 1));
	}
	/* last == sec: same-second batch, no new information. */

	if (stamps->len < FS_SENTINEL_BEACON_MIN_SAMPLES)
		goto out;

	n_diff = stamps->len - 1;
	for (i = 0; i < n_diff; i++)
		sum += g_array_index (stamps, BeaconEv, i + 1).sec -
		       g_array_index (stamps, BeaconEv, i).sec;

	mean = (gdouble) sum / n_diff;
	for (i = 0; i < n_diff; i++) {
		gdouble d = (gdouble) (g_array_index (stamps, BeaconEv, i + 1).sec -
		                       g_array_index (stamps, BeaconEv, i).sec);

		var += (d - mean) * (d - mean);
	}

	if (mean < FS_SENTINEL_BEACON_MIN_MEAN_S ||
	    mean > FS_SENTINEL_BEACON_MAX_MEAN_S ||
	    var / n_diff > (FS_SENTINEL_BEACON_MAX_CV *
	                    FS_SENTINEL_BEACON_MAX_CV) * mean * mean)
		goto out;

	/* Stage 1: reported.  Stage 2: reported with enough contacts for
	 * the automatic block to be considered. */
	stage = GPOINTER_TO_INT (g_hash_table_lookup (copilot->beacon_reported,
	                                              key));
	want = stamps->len >= FS_SENTINEL_BEACON_AUTO_MIN ? 2 : 1;
	if (stage >= want)
		goto out;
	g_hash_table_insert (copilot->beacon_reported, g_strdup (key),
	                     GINT_TO_POINTER (want));
	cv = mean > 0 ? sqrt_d (var / n_diff) / mean : 0.0;

	{
		gboolean intel = hit_rule_is_intel (hit);
		gchar *title = g_strdup_printf (
			_("Contacts at a near-fixed interval: %s to %s"),
			app_buf, dst);
		FsInsight *insight = create_insight (
			FS_INSIGHT_BEACON,
			intel ? FS_COPILOT_CRITICAL : FS_COPILOT_WARNING,
			title,
			g_strdup_printf (
				_("%s contacted %s on port %s %u times, about every "
				  "%d seconds. Malware check-ins look like this, but so "
				  "do update checks and keep-alives."),
				app_buf, dst, port, stamps->len, (gint) (mean + 0.5)),
			app_buf, dst);
		guint first = stamps->len > FS_INSIGHT_MAX_EVIDENCE
		              ? stamps->len - FS_INSIGHT_MAX_EVIDENCE : 0;

		g_free (title);
		insight->why = g_strdup_printf (
			_("%u contacts; mean interval %d s (the check looks at 10 to "
			  "600 s); variation %.2f of the mean (the limit is %.2f)%s."),
			stamps->len, (gint) (mean + 0.5), cv,
			FS_SENTINEL_BEACON_MAX_CV,
			intel ? _("; the destination is also on a block list") : "");
		insight->benign = g_strdup (
			_("Update checks, keep-alives, time sync, push notifications "
			  "and telemetry also run on a timer."));
		insight->key = g_strdup_printf ("beacon|%s", key);
		insight->count = stamps->len;
		insight->subject = g_strdup (dst);
		insight->events_filter = g_strdup (dst);
		/* Blocked by a list or a country or network rule: no What-If
		 * line and no block rule (CORRECTNESS-2).  What-If does not
		 * consult those, so it would answer "Allowed" and make a block
		 * rule look like a change, when the address is blocked
		 * already. */
		if (!intel)
			insight->whatif_line = g_strdup_printf (
				"outbound %s port %s to %s", udp ? "udp" : "tcp",
				port, dst);
		/* One row per contact, from that contact's own record: its
		 * time, whether it was refused and by what. */
		for (i = first; i < stamps->len; i++) {
			const BeaconEv *b = &g_array_index (stamps, BeaconEv, i);
			FsEvidence *ev = g_new0 (FsEvidence, 1);

			/* the wall time, from the monotonic gap to now */
			ev->when = now_unix - (sec - b->sec);
			ev->inbound = FALSE;
			ev->remote = g_strdup (dst);
			ev->port = portnum <= 65535 ? portnum : 0;
			ev->protocol = g_strdup (udp ? "UDP" : "TCP");
			ev->blocked = b->blocked;
			ev->rule = g_strdup (b->rule);
			insight_add_evidence (insight, ev);
		}

		if (intel) {
			insight->withheld = g_strdup (
				_("Nothing to stage: a blocklist or a country or "
				  "network rule already blocks it."));
			insight->auto_applicable = FALSE;
			if (!key_owned)
				g_free (key);
			return insight;
		}

		insight->suggested_rule = g_strdup_printf (
			_("Block outbound traffic to %s"), dst);
		insight->rule_csv = g_strdup_printf (
			"%s, %s", dst, "Sentinel: periodic beacon");
		insight->rule_kind = FS_RULE_OUTBOUND_DENY_TO;

		/* P6: the finding is always reported; the automatic block is
		 * withheld for the reasons beacon_auto_withheld gives.  The
		 * staging pass asks the same question again with the facts of
		 * that moment (fs_copilot_beacon_recheck). */
		insight->withheld = beacon_auto_withheld (
			copilot, app_buf, dst, port,
			MAX (stamps->len, GPOINTER_TO_UINT (g_hash_table_lookup (
				copilot->beacon_total, key))),
			stamps->len);
		insight->auto_applicable = insight->withheld == NULL;

		if (!key_owned)
			g_free (key);
		return insight;
	}

out:
	if (!key_owned)
		g_free (key);
	return NULL;
}

/* [ sentinel_fanout_check ]
 * One program (one service on Linux) reaching many distinct hosts
 * inside a minute: 60 hosts, or 10 refused hosts.  Kept per app, so a
 * busy machine with many programs does not add up to one "burst".  One
 * report per window per app; the episode ends when the window empties.
 * No single guilty host exists, so this carries no rule. */
static FsInsight *
sentinel_fanout_check (FsCopilot *copilot, const FsHit *hit, gint64 now_us,
                       gint64 now_unix)
{
	const gchar *dst;
	gchar app_buf[256];
	gint64 sec, window_start;
	guint n_any, n_blocked;
	GHashTableIter iter;
	gpointer k, v;
	FanoutState *st;
	FsInsight *insight;
	gboolean program;

	if (sentinel_hit_is_inbound (hit))
		return NULL;

	dst = hit->destination;
	if (dst == NULL || *dst == '\0')
		return NULL;

	hit_app_key (hit, app_buf, sizeof app_buf);
	sec          = now_us / G_USEC_PER_SEC;
	window_start = sec - FS_SENTINEL_FANOUT_WINDOW_S;

	st = g_hash_table_lookup (copilot->fanout, app_buf);
	if (st == NULL) {
		if (g_hash_table_size (copilot->fanout) >= FS_FANOUT_MAX_APPS) {
			g_hash_table_iter_init (&iter, copilot->fanout);
			while (g_hash_table_iter_next (&iter, &k, &v))
				if (((FanoutState *) v)->last < window_start)
					g_hash_table_iter_remove (&iter);
			if (g_hash_table_size (copilot->fanout) >=
			    FS_FANOUT_MAX_APPS)
				return NULL;
		}
		st = g_new0 (FanoutState, 1);
		st->seen = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                  g_free, NULL);
		st->blocked = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                     g_free, NULL);
		g_hash_table_insert (copilot->fanout, g_strdup (app_buf), st);
	}

	g_hash_table_iter_init (&iter, st->seen);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		if (GPOINTER_TO_INT (v) < window_start)
			g_hash_table_iter_remove (&iter);
	}

	g_hash_table_iter_init (&iter, st->blocked);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		if (GPOINTER_TO_INT (v) < window_start)
			g_hash_table_iter_remove (&iter);
	}

	/* An emptied window starts a fresh episode. */
	if (g_hash_table_size (st->seen) == 0)
		st->reported = FALSE;

	g_hash_table_insert (st->seen, g_strdup (dst),
	                     GINT_TO_POINTER ((gint) sec));
	st->last = sec;

	if (sentinel_hit_is_blocked (hit))
		g_hash_table_insert (st->blocked, g_strdup (dst),
		                     GINT_TO_POINTER ((gint) sec));

	n_any     = g_hash_table_size (st->seen);
	n_blocked = g_hash_table_size (st->blocked);
	program   = hit_key_is_program (hit, app_buf);

	/* A key that is a port's service name ("https", what Linux logs
	 * carry) stands for every program using that port, so a busy page
	 * in any browser reaches 60 hosts.  There only refused hosts
	 * count; the any-host limit needs a real program name. */
	if (n_blocked < FS_SENTINEL_FANOUT_BLOCKED &&
	    (!program || n_any < FS_SENTINEL_FANOUT_LIMIT))
		return NULL;

	if (st->reported)
		return NULL;

	st->reported = TRUE;

	{
		gchar *title = g_strdup_printf (
			_("%s reached %u hosts in a minute"), app_buf, n_any);

		insight = create_insight (
			FS_INSIGHT_FANOUT, FS_COPILOT_WARNING, title,
			g_strdup_printf (
				_("In the last %d seconds %s contacted %u distinct "
				  "remote hosts, %u of them refused. Scans and worms "
				  "look like this. Right-click a row in Events to block "
				  "a host."),
				FS_SENTINEL_FANOUT_WINDOW_S, app_buf, n_any, n_blocked),
			app_buf, NULL);
		g_free (title);
	}
	insight->why = program
		? g_strdup_printf (
			_("%u distinct hosts (the limit is %d) and %u refused hosts "
			  "(the limit is %d) in %d seconds."),
			n_any, FS_SENTINEL_FANOUT_LIMIT, n_blocked,
			FS_SENTINEL_FANOUT_BLOCKED, FS_SENTINEL_FANOUT_WINDOW_S)
		: g_strdup_printf (
			_("%u refused hosts (the limit is %d) among %u distinct hosts "
			  "in %d seconds. %s is a port's service name, which covers "
			  "every program on that port, so only refused hosts count."),
			n_blocked, FS_SENTINEL_FANOUT_BLOCKED, n_any,
			FS_SENTINEL_FANOUT_WINDOW_S, app_buf);
	insight->benign = g_strdup (
		_("Browsers opening a busy page, peer-to-peer programs and "
		  "network discovery reach many hosts quickly too."));
	insight->key = g_strdup_printf ("fanout|%s|%" G_GINT64_FORMAT, app_buf,
	                                sec);
	insight->subject = g_strdup (app_buf);
	insight->events_filter = g_strdup (app_buf);
	insight_add_evidence (insight, evidence_from_hit (hit, FALSE,
	                                                  now_unix));

	/* No single guilty host exists, so this detection carries no
	 * rule: auto-block must never guess. */
	insight->suggested_rule = NULL;
	insight->rule_csv = NULL;
	insight->auto_applicable = FALSE;
	insight->withheld = g_strdup (
		_("Report only: there is no single host to block."));

	return insight;
}

/* ---- inbound checks ----------------------------------------------- */

/* [ insight_open ] -- whether a finding with this key is on the list. */
static gboolean
insight_open (FsCopilot *copilot, const gchar *key)
{
	for (GList *l = copilot->insights; l != NULL; l = l->next)
		if (g_strcmp0 (((FsInsight *) l->data)->key, key) == 0)
			return TRUE;
	return FALSE;
}

/* [ report_or_update ]
 * The once-per-hour report memory says whether a NEW finding may be
 * raised.  When it may not, a finding still open under the same key is
 * updated instead (its count, ports and evidence grow with the run), so
 * a 40-port scan never reads "12 ports" because the first report came
 * at 12.  FALSE: nothing to emit. */
static gboolean
report_or_update (FsCopilot *copilot, const gchar *key, gint64 now_unix)
{
	if (report_take (copilot, key, now_unix))
		return TRUE;
	return insight_open (copilot, key);
}

/* [ scan_state_newest ] -- the newest event's second, or G_MININT64. */
static gint64
scan_state_newest (const ScanState *st)
{
	return st->ev->len > 0
	       ? g_array_index (st->ev, ScanEv, st->ev->len - 1).sec
	       : G_MININT64;
}

/* [ scan_state_get ]
 * The state for one subject (a source address, or an IPv6 /64).  When
 * the table is full, expired subjects go first and then the one heard
 * from longest ago: a full table never makes the check deaf to a new
 * scanner (it used to refuse every newcomer once 1024 sources sat in
 * the window). */
static ScanState *
scan_state_get (FsCopilot *copilot, const gchar *subject, gint64 sec,
                gboolean aggregate)
{
	ScanState *st = g_hash_table_lookup (copilot->scan, subject);

	if (st != NULL)
		return st;

	if (g_hash_table_size (copilot->scan) >= FS_SCAN_MAX_SOURCES) {
		GHashTableIter it;
		gpointer k, v, oldest_k = NULL;
		gint64 oldest = G_MAXINT64;

		g_hash_table_iter_init (&it, copilot->scan);
		while (g_hash_table_iter_next (&it, &k, &v))
			if (scan_state_newest (v) < sec - FS_SCAN_WINDOW_S)
				g_hash_table_iter_remove (&it);
		if (g_hash_table_size (copilot->scan) >= FS_SCAN_MAX_SOURCES) {
			g_hash_table_iter_init (&it, copilot->scan);
			while (g_hash_table_iter_next (&it, &k, &v))
				if (scan_state_newest (v) < oldest) {
					oldest = scan_state_newest (v);
					oldest_k = k;
				}
			if (oldest_k != NULL)
				g_hash_table_remove (copilot->scan, oldest_k);
		}
	}
	st = g_new0 (ScanState, 1);
	st->ev = g_array_new (FALSE, FALSE, sizeof (ScanEv));
	if (aggregate)
		st->members = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                     g_free, NULL);
	g_hash_table_insert (copilot->scan, g_strdup (subject), st);
	return st;
}

/* [ v6_net64 ] -- "2001:db8:1:2::/64" for a public IPv6 source, else
 * NULL.  A scanner that rotates its address inside one /64 (any IPv6
 * host can) is one scanner. */
static gchar *
v6_net64 (const gchar *src)
{
	guint32 v4;
	FsU128 v6;
	guint8 b[16];
	GInetAddress *a;
	gchar *text, *out;

	if (fs_addr_parse (src, &v4, &v6) != FS_AF_V6)
		return NULL;
	for (gint i = 0; i < 8; i++)
		b[i] = (guint8) (v6.hi >> (56 - 8 * i));
	memset (b + 8, 0, 8);
	a = g_inet_address_new_from_bytes (b, G_SOCKET_FAMILY_IPV6);
	text = g_inet_address_to_string (a);
	out = g_strdup_printf ("%s/64", text);
	g_free (text);
	g_object_unref (a);
	return out;
}

/* [ scan_judge ]
 * One subject's run: record the event, trim the window, and build the
 * finding when the run crosses a limit.  `display' is what the finding
 * names; `members' counts the addresses of an aggregate. */
static FsInsight *
scan_judge (FsCopilot *copilot, const gchar *subject, gboolean aggregate,
            const gchar *src, const FsHit *hit, guint port, AddrClass cls,
            gint64 sec, gint64 now_unix)
{
	ScanState *st = scan_state_get (copilot, subject, sec, aggregate);
	ScanEv ev;
	GHashTable *d60, *d600;
	GString *ports_list, *allowed_list;
	guint n_blocked = 0, n60, n600, n_members = 0;
	FsInsight *insight;
	gchar *what;

	ev.sec = sec;
	ev.unix_sec = now_unix;
	ev.port = port;
	ev.blocked = hit_is_blocked_marker (hit);
	ev.proto = hit->protocol != NULL &&
	           g_ascii_strcasecmp (hit->protocol, "UDP") == 0 ? "UDP" : "TCP";
	ev.src = NULL;
	if (st->members != NULL) {
		gpointer stored = NULL;

		if (g_hash_table_lookup_extended (st->members, src, &stored, NULL))
			ev.src = stored;
		else if (g_hash_table_size (st->members) < FS_SCAN_MAX_MEMBERS) {
			stored = g_strdup (src);
			g_hash_table_add (st->members, stored);
			ev.src = stored;
		}
	}
	g_array_append_val (st->ev, ev);
	while (st->ev->len > 0 &&
	       (st->ev->len > FS_SCAN_MAX_EVENTS ||
	        g_array_index (st->ev, ScanEv, 0).sec < sec - FS_SCAN_WINDOW_S))
		g_array_remove_index (st->ev, 0);

	d60 = g_hash_table_new (g_direct_hash, g_direct_equal);
	d600 = g_hash_table_new (g_direct_hash, g_direct_equal);
	{
		GHashTable *srcs = g_hash_table_new (g_direct_hash,
		                                     g_direct_equal);

		for (guint i = 0; i < st->ev->len; i++) {
			const ScanEv *e = &g_array_index (st->ev, ScanEv, i);

			g_hash_table_add (d600, GUINT_TO_POINTER (e->port));
			if (e->sec >= sec - FS_SCAN_SHORT_WINDOW_S)
				g_hash_table_add (d60, GUINT_TO_POINTER (e->port));
			if (e->src != NULL)
				g_hash_table_add (srcs, (gpointer) e->src);
		}
		n_members = g_hash_table_size (srcs);
		g_hash_table_unref (srcs);
	}
	n60 = g_hash_table_size (d60);
	n600 = g_hash_table_size (d600);
	g_hash_table_unref (d60);
	g_hash_table_unref (d600);

	if (n60 < FS_SCAN_PORTS_60S && n600 < FS_SCAN_PORTS_10M)
		return NULL;
	/* An aggregate stands for SEVERAL addresses; one address alone is
	 * already its own subject. */
	if (aggregate && n_members < 2)
		return NULL;

	what = g_strdup_printf ("scan|%s", subject);
	if (!report_or_update (copilot, what, now_unix)) {
		g_free (what);
		return NULL;
	}

	/* The ports, in the order first seen; the ones that got through. */
	ports_list = g_string_new (NULL);
	allowed_list = g_string_new (NULL);
	{
		GHashTable *listed = g_hash_table_new (g_direct_hash,
		                                       g_direct_equal);
		GHashTable *ok = g_hash_table_new (g_direct_hash, g_direct_equal);
		guint shown = 0;

		for (guint i = 0; i < st->ev->len; i++) {
			const ScanEv *e = &g_array_index (st->ev, ScanEv, i);

			if (e->blocked)
				n_blocked++;
			else if (!g_hash_table_contains (ok,
			                                 GUINT_TO_POINTER (e->port))) {
				g_hash_table_add (ok, GUINT_TO_POINTER (e->port));
				g_string_append_printf (allowed_list, "%s%u",
				                        allowed_list->len ? ", " : "",
				                        e->port);
			}
			if (g_hash_table_contains (listed, GUINT_TO_POINTER (e->port)))
				continue;
			g_hash_table_add (listed, GUINT_TO_POINTER (e->port));
			if (shown++ < 20)
				g_string_append_printf (ports_list, "%s%u",
				                        ports_list->len ? ", " : "",
				                        e->port);
		}
		if (shown > 20)
			g_string_append (ports_list, ", ...");
		g_hash_table_unref (listed);
		g_hash_table_unref (ok);
	}

	{
		gchar *who = aggregate
			? g_strdup_printf (_("%s (%u addresses)"), subject, n_members)
			: g_strdup (subject);
		gchar *title = g_strdup_printf (
			_("%s probed %u ports on this computer"), who, n600);

		insight = create_insight (
			FS_INSIGHT_INBOUND_SCAN,
			(cls == ADDR_LAN || allowed_list->len == 0)
			? FS_COPILOT_INFO : FS_COPILOT_WARNING,
			title,
			allowed_list->len == 0
			? g_strdup_printf (
				_("%s tried %u different local ports (%s). Every attempt "
				  "the log shows was refused."), who, n600,
				ports_list->str)
			: g_strdup_printf (
				_("%s tried %u different local ports (%s). Some got "
				  "through to ports your policy allows: %s. Check that "
				  "those services are meant to be reachable."), who,
				n600, ports_list->str, allowed_list->str),
			NULL, subject);
		g_free (title);
		g_free (who);
	}
	insight->why = g_strdup_printf (
		_("%u distinct ports in the last 60 seconds (the limit is %d) and "
		  "%u in 10 minutes (the limit is %d), from %s; %u of %u "
		  "attempts refused%s."),
		n60, FS_SCAN_PORTS_60S, n600, FS_SCAN_PORTS_10M,
		aggregate ? _("one IPv6 /64 network") : _("one source"),
		n_blocked, st->ev->len,
		cls == ADDR_LAN ? _("; the source is on the local network") : "");
	insight->benign = g_strdup (
		_("Network scanners you run yourself, monitoring tools, printers "
		  "and some games probe many ports too."));
	insight->key = what;
	insight->subject = g_strdup (subject);
	insight->events_filter = g_strdup (aggregate ? src : subject);
	insight->whatif_line = g_strdup_printf ("inbound tcp port %u from %s",
	                                        port, src);
	insight->withheld = g_strdup (
		_("Report only: the policy blocks inbound traffic by default, and "
		  "Sentinel never changes inbound rules."));
	{
		guint first = st->ev->len > FS_INSIGHT_MAX_EVIDENCE
		              ? st->ev->len - FS_INSIGHT_MAX_EVIDENCE : 0;

		for (guint i = first; i < st->ev->len; i++) {
			const ScanEv *e = &g_array_index (st->ev, ScanEv, i);
			FsEvidence *row = g_new0 (FsEvidence, 1);

			row->when = e->unix_sec;
			row->inbound = TRUE;
			row->remote = g_strdup (e->src != NULL ? e->src : subject);
			row->port = e->port;
			row->protocol = g_strdup (e->proto);
			row->blocked = e->blocked;
			insight_add_evidence (insight, row);
		}
	}
	insight->count = st->ev->len;
	g_string_free (ports_list, TRUE);
	g_string_free (allowed_list, TRUE);
	return insight;
}

/* [ inbound_scan_check ]
 * One source reaching many distinct local ports: 12 in 60 seconds, or
 * 25 in 10 minutes.  Counts DISTINCT ports, never events, so a retry
 * storm on one port is not a scan.  ICMP, loopback, multicast and
 * link-local sources are ignored; a LAN source is Info.  A public IPv6
 * source is also counted with the rest of its /64, so a scanner that
 * rotates addresses inside it is still one scanner (*net_out gets that
 * finding; it needs two or more addresses).  One new report per subject
 * per hour; later events update the open finding.  The policy has no
 * inbound deny, so this never changes the policy: its action is the
 * health check. */
static FsInsight *
inbound_scan_check (FsCopilot *copilot, const FsHit *hit, gint64 now_us,
                    gint64 now_unix, FsInsight **net_out)
{
	const gchar *src;
	guint port;
	gint64 sec = now_us / G_USEC_PER_SEC;
	AddrClass cls;
	FsInsight *own;
	gchar *net64;

	*net_out = NULL;
	if (!sentinel_hit_is_inbound (hit))
		return NULL;
	src = hit->source;
	port = hit->port != NULL ? (guint) strtoul (hit->port, NULL, 10) : 0;
	if (port == 0 || port > 65535)
		return NULL;
	cls = addr_class (src);
	if (cls == ADDR_IGNORE || g_strcmp0 (src, hit->destination) == 0)
		return NULL;

	own = scan_judge (copilot, src, FALSE, src, hit, port, cls, sec,
	                  now_unix);

	net64 = cls == ADDR_PUBLIC ? v6_net64 (src) : NULL;
	if (net64 != NULL) {
		*net_out = scan_judge (copilot, net64, TRUE, src, hit, port, cls,
		                       sec, now_unix);
		g_free (net64);
	}
	return own;
}

static const struct { guint port; const gchar *name; } login_ports[] = {
	{ 22, "SSH" }, { 3389, "RDP" }, { 5900, "VNC" }, { 23, "Telnet" },
	{ 21, "FTP" }, { 445, "SMB" },
};

/* The login service a policy row names, by its service name. */
static const gchar *
login_service_name (const gchar *service)
{
	static const struct { const gchar *word; const gchar *name; } names[] = {
		{ "ssh", "SSH" }, { "rdp", "RDP" }, { "remote desktop", "RDP" },
		{ "ms-wbt-server", "RDP" }, { "vnc", "VNC" },
		{ "telnet", "Telnet" }, { "ftp", "FTP" }, { "smb", "SMB" },
		{ "microsoft-ds", "SMB" },
	};
	gchar *low;
	const gchar *found = NULL;

	if (service == NULL)
		return NULL;
	low = g_ascii_strdown (service, -1);
	g_strstrip (low);
	for (guint i = 0; i < G_N_ELEMENTS (names) && found == NULL; i++)
		if (g_strcmp0 (low, names[i].word) == 0)
			found = names[i].name;
	g_free (low);
	return found;
}

/* [ login_port_name ]
 * The login service on a local port: the fixed list, then the policy's
 * inbound service rows that name SSH, RDP, VNC, Telnet, FTP or SMB on
 * a port of their own ("SSH, 2222, Anyone"; a range of up to 16 ports
 * counts too).  NULL when the port is no login port. */
static const gchar *
login_port_name (FsCopilot *copilot, guint port)
{
	for (guint i = 0; i < G_N_ELEMENTS (login_ports); i++)
		if (login_ports[i].port == port)
			return login_ports[i].name;
	if (copilot->policy == NULL)
		return NULL;
	for (gint k = FS_RULE_INBOUND_ALLOW_SERVICE;
	     k <= FS_RULE_INBOUND_FORWARD; k++) {
		GPtrArray *rows = copilot->policy->kinds[k];

		for (guint i = 0; rows != NULL && i < rows->len; i++) {
			const FsRule *r = g_ptr_array_index (rows, i);
			const gchar *name = login_service_name (r->service);
			const gchar *ptext = r->port;
			gchar *end = NULL;
			gulong lo, hi;

			if (name == NULL || ptext == NULL)
				continue;
			lo = strtoul (ptext, &end, 10);
			hi = lo;
			if (end != NULL && *end == '-')
				hi = strtoul (end + 1, &end, 10);
			if (end == NULL || *end != '\0' || lo == 0 || hi < lo ||
			    hi - lo >= 16)
				continue;
			if (port >= lo && port <= hi)
				return name;
		}
	}
	return NULL;
}

/* [ brute_force_check ]
 * Repeated connections to login services: one source, 10 or more
 * inbound TCP connections in 5 minutes, counted across every login
 * port together (9 on SSH and 9 on RDP are 18), on 22, 3389, 5900, 23,
 * 21, 445 or a port the policy gives SSH, RDP, VNC, Telnet, FTP or
 * SMB.  The log cannot tell a failed login from a good one, so the
 * severity rests on the refused attempts:
 *   none refused       "connections", Info; Warning from the internet
 *                      when the policy lets the source in;
 *   some refused       Critical from the internet when the policy lets
 *                      the source in (Warning from the LAN); Warning
 *                      when some were allowed and some refused;
 *   all refused        Info.
 * "Lets the source in" is What-If's ALLOWED, or its DEPENDS when the
 * log shows connections this computer let in: the Copilot asks What-If
 * without the network in use, and on Windows an inbound from a private
 * address depends on it (StockFW blocks reserved sources on Public
 * networks), while an allowed connection in the log is the answer for
 * the network this computer was on.
 * Never carries a rule. */
static FsInsight *
brute_force_check (FsCopilot *copilot, const FsHit *hit, gint64 now_us,
                   gint64 now_unix)
{
	const gchar *src, *name;
	guint port;
	gint64 sec = now_us / G_USEC_PER_SEC;
	GArray *st;
	BruteEv ev;
	AddrClass cls;
	guint n_blocked = 0;
	FsWhatIfVerdict verdict = FS_WHATIF_ERROR;
	FsCopilotSeverity sev;
	FsInsight *insight;
	GString *services, *ports;
	gchar *what;
	gboolean none_refused, lets_in;

	if (!sentinel_hit_is_inbound (hit))
		return NULL;
	if (hit->protocol != NULL && g_ascii_strcasecmp (hit->protocol, "TCP"))
		return NULL;
	port = hit->port != NULL ? (guint) strtoul (hit->port, NULL, 10) : 0;
	if (port == 0 || port > 65535)
		return NULL;
	name = login_port_name (copilot, port);
	src = hit->source;
	cls = addr_class (src);
	if (name == NULL || cls == ADDR_IGNORE)
		return NULL;

	st = g_hash_table_lookup (copilot->brute, src);
	if (st == NULL) {
		if (g_hash_table_size (copilot->brute) >= FS_BRUTE_MAX_KEYS) {
			GHashTableIter it;
			gpointer k, v, oldest_k = NULL;
			gint64 oldest = G_MAXINT64;

			/* Expired sources first, then the one heard from
			 * longest ago: never deaf to a newcomer. */
			g_hash_table_iter_init (&it, copilot->brute);
			while (g_hash_table_iter_next (&it, &k, &v)) {
				GArray *o = v;

				if (o->len == 0 ||
				    g_array_index (o, BruteEv, o->len - 1).sec <=
				    sec - FS_BRUTE_WINDOW_S)
					g_hash_table_iter_remove (&it);
			}
			g_hash_table_iter_init (&it, copilot->brute);
			while (g_hash_table_size (copilot->brute) >=
			       FS_BRUTE_MAX_KEYS &&
			       g_hash_table_iter_next (&it, &k, &v)) {
				GArray *o = v;
				gint64 last = g_array_index (o, BruteEv,
				                             o->len - 1).sec;

				if (last < oldest) {
					oldest = last;
					oldest_k = k;
				}
			}
			if (g_hash_table_size (copilot->brute) >=
			    FS_BRUTE_MAX_KEYS && oldest_k != NULL)
				g_hash_table_remove (copilot->brute, oldest_k);
		}
		st = g_array_new (FALSE, FALSE, sizeof (BruteEv));
		g_hash_table_insert (copilot->brute, g_strdup (src), st);
	}

	ev.sec = sec;
	ev.unix_sec = now_unix;
	ev.blocked = hit_is_blocked_marker (hit);
	ev.port = port;
	g_array_append_val (st, ev);
	/* The window: attempts older than five minutes no longer count. */
	while (st->len > 0 &&
	       (st->len > 64 ||
	        g_array_index (st, BruteEv, 0).sec <= sec - FS_BRUTE_WINDOW_S))
		g_array_remove_index (st, 0);

	if (st->len < FS_BRUTE_ATTEMPTS)
		return NULL;
	what = g_strdup_printf ("brute|%s", src);
	if (!report_or_update (copilot, what, now_unix)) {
		g_free (what);
		return NULL;
	}

	/* The services and ports tried, in the order first seen. */
	services = g_string_new (NULL);
	ports = g_string_new (NULL);
	{
		GHashTable *seen_port = g_hash_table_new (g_direct_hash,
		                                          g_direct_equal);
		GHashTable *seen_name = g_hash_table_new (g_str_hash,
		                                          g_str_equal);

		for (guint i = 0; i < st->len; i++) {
			const BruteEv *e = &g_array_index (st, BruteEv, i);
			const gchar *n = login_port_name (copilot, e->port);

			if (e->blocked)
				n_blocked++;
			if (n == NULL)
				n = name;
			if (!g_hash_table_contains (seen_name, n)) {
				g_hash_table_add (seen_name, (gpointer) n);
				g_string_append_printf (services, "%s%s",
				                        services->len ? _(" and ") : "",
				                        n);
			}
			if (!g_hash_table_contains (seen_port,
			                            GUINT_TO_POINTER (e->port))) {
				g_hash_table_add (seen_port,
				                  GUINT_TO_POINTER (e->port));
				g_string_append_printf (ports, "%s%u",
				                        ports->len ? ", " : "", e->port);
			}
		}
		g_hash_table_unref (seen_port);
		g_hash_table_unref (seen_name);
	}

	/* Would the policy let this source in, on any of those ports? */
	if (copilot->policy != NULL) {
		GHashTable *asked = g_hash_table_new (g_direct_hash,
		                                      g_direct_equal);

		for (guint i = 0; i < st->len; i++) {
			guint p = g_array_index (st, BruteEv, i).port;
			FsWhatIfContext *ctx;
			FsWhatIfQuery *q;
			FsWhatIfResult *r;

			if (g_hash_table_contains (asked, GUINT_TO_POINTER (p)))
				continue;
			g_hash_table_add (asked, GUINT_TO_POINTER (p));
			ctx = fs_whatif_context_new (fs_whatif_native_platform (),
			                             copilot->policy, NULL);
			q = fs_whatif_query_new ();
			ctx->firewall = FS_WHATIF_FW_RUNNING;
			q->direction = FS_WHATIF_DIR_INBOUND;
			q->protocol = FS_WHATIF_PROTO_TCP;
			q->port = p;
			q->host = g_strdup (src);
			q->text = g_strdup_printf ("inbound tcp port %u from %s", p,
			                           src);
			r = fs_whatif_simulate (ctx, q);
			/* ALLOWED on any port wins; BLOCKED needs every
			 * port; an unclear answer stays unclear. */
			if (r->verdict == FS_WHATIF_ALLOWED)
				verdict = FS_WHATIF_ALLOWED;
			else if (verdict == FS_WHATIF_ERROR ||
			         (verdict == FS_WHATIF_BLOCKED &&
			          r->verdict != FS_WHATIF_BLOCKED))
				verdict = r->verdict;
			fs_whatif_result_free (r);
			fs_whatif_query_free (q);
			fs_whatif_context_free (ctx);
		}
		g_hash_table_unref (asked);
	}

	none_refused = n_blocked == 0;
	/* Some connections were let in, and What-If says "it depends":
	 * the log answers it for the network in use. */
	lets_in = verdict == FS_WHATIF_ALLOWED ||
	          (verdict == FS_WHATIF_DEPENDS && n_blocked < st->len);
	if (none_refused)
		sev = lets_in && cls != ADDR_LAN
		      ? FS_COPILOT_WARNING : FS_COPILOT_INFO;
	else if (lets_in)
		sev = cls == ADDR_LAN ? FS_COPILOT_WARNING : FS_COPILOT_CRITICAL;
	else
		sev = n_blocked < st->len && cls != ADDR_LAN ? FS_COPILOT_WARNING
		                                             : FS_COPILOT_INFO;
	{
		gchar *title;
		gint64 span = g_array_index (st, BruteEv, st->len - 1).sec -
		              g_array_index (st, BruteEv, 0).sec;

		if (none_refused)
			title = g_strdup_printf (
				lets_in
				? _("Repeated %s connections from %s, which the policy "
				    "lets in")
				: _("Repeated %s connections from %s"),
				services->str, src);
		else
			title = g_strdup_printf (
				lets_in
				? _("Repeated %s attempts from %s, and the policy lets "
				    "it in")
				: _("Repeated %s attempts from %s"),
				services->str, src);

		insight = create_insight (
			FS_INSIGHT_BRUTE_FORCE, sev, title,
			g_strdup_printf (
				_("%s made %u connections to %s (%s %s) in %"
				  G_GINT64_FORMAT " seconds, %u of them refused. %s %s"),
				src, st->len, services->str,
				strchr (ports->str, ',') != NULL ? _("ports") : _("port"),
				ports->str, span, n_blocked,
				verdict == FS_WHATIF_ALLOWED
				? _("What-If says your policy allows this source on this "
				    "port, so the connections can reach the login prompt.")
				: verdict == FS_WHATIF_BLOCKED
				? _("What-If says your policy blocks this source on this "
				    "port.")
				: lets_in
				? _("What-If says the answer depends, for example on the "
				    "network in use, and the log shows this computer let "
				    "some of these connections in.")
				: _("What-If could not say whether your policy lets this "
				    "source in."),
				none_refused
				? _("The log cannot tell a failed login from a good one, "
				    "so this may be your own use, such as a deploy or a "
				    "sync job.")
				: _("Allowed attempts appear only when allowed-event "
				    "logging is on.")),
			NULL, src);
		g_free (title);
	}
	insight->why = g_strdup_printf (
		_("%u connections in 5 minutes to login ports (%s; the limit is "
		  "%d, counted across all of them); %u refused; What-If for this "
		  "source: %s%s."),
		st->len, ports->str, FS_BRUTE_ATTEMPTS, n_blocked,
		fs_whatif_verdict_name (verdict),
		cls == ADDR_LAN ? _("; the source is on the local network") : "");
	insight->benign = g_strdup (
		_("A saved password that is out of date, a backup or sync job, a "
		  "deploy tool or a monitoring check can connect many times."));
	insight->key = what;
	insight->subject = g_strdup (src);
	insight->events_filter = g_strdup (src);
	insight->whatif_line = g_strdup_printf ("inbound tcp port %u from %s",
	                                        port, src);
	insight->withheld = g_strdup (
		_("Report only: Sentinel never changes inbound rules. If the "
		  "policy lets this source in, the policy health check offers a "
		  "verified narrowing."));
	{
		guint first = st->len > FS_INSIGHT_MAX_EVIDENCE
		              ? st->len - FS_INSIGHT_MAX_EVIDENCE : 0;

		for (guint i = first; i < st->len; i++) {
			const BruteEv *e = &g_array_index (st, BruteEv, i);
			FsEvidence *row = g_new0 (FsEvidence, 1);

			row->when = e->unix_sec;
			row->inbound = TRUE;
			row->remote = g_strdup (src);
			row->port = e->port;
			row->protocol = g_strdup ("TCP");
			row->blocked = e->blocked;
			insight_add_evidence (insight, row);
		}
	}
	insight->count = st->len;
	g_string_free (services, TRUE);
	g_string_free (ports, TRUE);
	return insight;
}

/* [ threat_intel_check ]
 * Traffic a block list or a country rule stopped, when the log line
 * says so (hit->rule).  Outbound: one finding per app and destination
 * (a program on this computer tried to reach a listed address).
 * Inbound: rolled up to one finding per list per hour, because the
 * internet's background noise would otherwise fill the page.  Costs
 * nothing when those engines are off. */
static FsInsight *
threat_intel_check (FsCopilot *copilot, const FsHit *hit, gint64 now_unix)
{
	gboolean inbound;
	gchar app_buf[256];
	const gchar *remote;
	FsInsight *insight;

	(void) copilot;

	if (!hit_rule_is_intel (hit))
		return NULL;
	inbound = sentinel_hit_is_inbound (hit);
	remote = inbound ? hit->source : hit->destination;
	if (remote == NULL || *remote == '\0')
		return NULL;
	hit_app_key (hit, app_buf, sizeof app_buf);

	if (inbound) {
		gchar *title = g_strdup_printf (
			_("Inbound connections dropped by %s"), hit->rule);

		insight = create_insight (
			FS_INSIGHT_THREAT_INTEL, FS_COPILOT_INFO, title,
			g_strdup_printf (
				_("Hosts on %s tried to connect to this computer and were "
				  "dropped. This is mostly background noise from the "
				  "internet; the count and the latest ones are below."),
				hit->rule),
			NULL, NULL);
		g_free (title);
		insight->key = g_strdup_printf ("intel-in|%s|%" G_GINT64_FORMAT,
		                                hit->rule, now_unix / 3600);
		insight->why = g_strdup_printf (
			_("The log names the rule that dropped them: %s."),
			hit->rule);
		insight->benign = g_strdup (
			_("Listed addresses are often shared or reused; a dropped "
			  "inbound attempt has not reached anything."));
		insight->events_filter = g_strdup (hit->rule);
	} else {
		gchar *title = g_strdup_printf (
			_("%s tried to reach %s, which %s blocks"), app_buf, remote,
			hit->rule);

		insight = create_insight (
			FS_INSIGHT_THREAT_INTEL, FS_COPILOT_WARNING, title,
			g_strdup_printf (
				_("A program on this computer (%s) tried to connect to "
				  "%s, an address on %s. The connection was blocked."),
				app_buf, remote, hit->rule),
			app_buf, remote);
		g_free (title);
		insight->key = g_strdup_printf ("intel|%s|%s", app_buf, remote);
		insight->subject = g_strdup (remote);
		insight->why = g_strdup_printf (
			_("The log names the rule that blocked it: %s."), hit->rule);
		insight->benign = g_strdup (
			_("Block lists include shared hosting and advertising "
			  "addresses that ordinary pages load."));
		insight->events_filter = g_strdup (remote);
		/* No What-If line (1.0.7 release review, CORRECTNESS-2): the
		 * What-If engine answers from the policy alone and does not
		 * consult blocklists or country and network rules, so for this
		 * address it would say "Allowed" next to a card that says the
		 * connection was blocked. */
	}
	insight->withheld = g_strdup (
		_("Nothing to stage: a blocklist or a country or network rule "
		  "already blocks it."));
	insight_add_evidence (insight, evidence_from_hit (hit, inbound,
	                                                  now_unix));
	return insight;
}

/* [ create_insight ] */
static FsInsight *
create_insight (FsInsightType type,
                FsCopilotSeverity severity,
                const gchar *title,
                gchar *description,
                const gchar *app_name,
                const gchar *destination)
{
	FsInsight *insight = g_new0 (FsInsight, 1);
	insight->type = type;
	insight->severity = severity;
	insight->title = g_strdup (title);
	/* Every caller passes a freshly formatted string here, so the
	 * description is taken over as it stands. */
	insight->description = description;
	/* Only Sentinel's deny rows carry a rule; they set the kind. */
	insight->rule_kind = FS_RULE_OUTBOUND_DENY_TO;
	insight->application = g_strdup (app_name);
	insight->destination = destination ? g_strdup (destination) : NULL;
	insight->count = 1;
	return insight;
}

/* [ fs_copilot_checks ]
 * "What is checked", built from the constants the checks above use, so
 * the words cannot drift from the engine (master plan G5).  The
 * desktop app keeps its own text (ui/fs-copilot.c); the terminal and
 * the daemon read this. */
gchar **
fs_copilot_checks (void)
{
	GPtrArray *out = g_ptr_array_new ();
	gint cv = (gint) (FS_SENTINEL_BEACON_MAX_CV * 100.0 + 0.5);

	g_ptr_array_add (out, g_strdup_printf (
#ifdef G_OS_WIN32
		"Contacts at a near-fixed interval: %d or more, %d s to %d min "
		"apart, timing varying under %d %% (auto-block needs %d, to an "
		"unknown public address no other program uses and your policy "
		"does not allow). DNS to this computer's own DNS servers is not "
		"timed.",
#else
		"Contacts at a near-fixed interval: %d or more, %d s to %d min "
		"apart, timing varying under %d %% (auto-block needs %d, to an "
		"unknown public address that traffic on other ports does not use "
		"and your policy does not allow). DNS to this computer's own DNS "
		"servers is not timed.",
#endif
		FS_SENTINEL_BEACON_MIN_SAMPLES, FS_SENTINEL_BEACON_MIN_MEAN_S,
		FS_SENTINEL_BEACON_MAX_MEAN_S / 60, cv,
		FS_SENTINEL_BEACON_AUTO_MIN));
	g_ptr_array_add (out, g_strdup_printf (
		"Fan-out: one program reaching %d or more hosts in %d s, or %d "
		"refused hosts. When the log names a port's service instead of a "
		"program, only the refused hosts count.",
		FS_SENTINEL_FANOUT_LIMIT, FS_SENTINEL_FANOUT_WINDOW_S,
		FS_SENTINEL_FANOUT_BLOCKED));
	g_ptr_array_add (out, g_strdup_printf (
		"Inbound scan: one source trying %d ports in %d s, or %d in %d "
		"min. Addresses of one IPv6 /64 are also counted together.",
		FS_SCAN_PORTS_60S, FS_SCAN_SHORT_WINDOW_S, FS_SCAN_PORTS_10M,
		FS_SCAN_WINDOW_S / 60));
	{
		GString *names = g_string_new (NULL);

		for (guint i = 0; i < G_N_ELEMENTS (login_ports); i++)
			g_string_append_printf (names, "%s%s", i == 0 ? ""
			                        : i + 1 == G_N_ELEMENTS (login_ports)
			                        ? " or " : ", ",
			                        login_ports[i].name);
		g_ptr_array_add (out, g_strdup_printf (
			"Login attempts: %d in %d min from one source to %s, on "
			"their usual ports or the ports your policy names for them, "
			"and whether your policy lets that source in.",
			FS_BRUTE_ATTEMPTS, FS_BRUTE_WINDOW_S / 60, names->str));
		g_string_free (names, TRUE);
	}
	g_ptr_array_add (out, g_strdup (
		"Block list or country rule hits, outbound and inbound."));
	g_ptr_array_add (out, g_strdup_printf (
		"A known app using a new port, a new public destination (after %d "
		"days and %d connections), a new hour (after %d hours seen), or a "
		"rate spike (after %d windows of %d min).",
		(gint) (FS_NEWDEST_MIN_AGE_S / 86400), FS_NEWDEST_MIN_CONNECTIONS,
		FS_BEHAVIOR_HOURS_MIN_DISTINCT, FS_BEHAVIOR_RATE_MIN_BUCKETS,
		FS_BEHAVIOR_WINDOW_S / 60));
	g_ptr_array_add (out, g_strdup (
		"Policy health: duplicates, rules another rule covers, allows a "
		"deny overrides, wide or risky inbound allows, deny rules that "
		"reach nothing."));
	g_ptr_array_add (out, NULL);
	return (gchar **) g_ptr_array_free (out, FALSE);
}
