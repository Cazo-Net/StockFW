/*---[ fs-copilot.h ]---------------------------------------------------
 * Copilot: rule-based, local analysis of the event log and the policy.
 * Every finding states the rule that raised it and the events behind
 * it.
 *
 * It is a set of fixed, documented checks (thresholds and counts, see
 * the FS_SENTINEL_* and FS_BEHAVIOR_* constants in fs-copilot.c), not a
 * model: the same events always give the same findings.  It runs on
 * this computer and sends nothing anywhere.  The policy half is
 * fs-health.h; "would this be allowed?" is fs-whatif.h.
 *--------------------------------------------------------------------*/
#ifndef FS_COPILOT_H
#define FS_COPILOT_H

#include <glib.h>
#include "core/fs-types.h"
#include "core/fs-rules.h"
#include "core/fs-fwrule.h"
#include "core/fs-whatif.h"
#include "core/fs-backend.h"

G_BEGIN_DECLS

/* Analysis severity levels. */
typedef enum
{
	FS_COPILOT_INFO,
	FS_COPILOT_WARNING,
	FS_COPILOT_CRITICAL
} FsCopilotSeverity;

/* What the Copilot reports.  Each type is one documented check. */
typedef enum
{
	FS_INSIGHT_UNUSUAL_PORT,         /* first use of a port by a known app   */
	FS_INSIGHT_UNUSUAL_DESTINATION,  /* new public destination, known app    */
	FS_INSIGHT_UNUSUAL_VOLUME,       /* connection rate spike                */
	FS_INSIGHT_UNUSUAL_TIME,         /* first activity in a new hour         */
	FS_INSIGHT_BEACON,               /* contacts at a near-fixed interval    */
	FS_INSIGHT_FANOUT,               /* one app, many hosts in a minute      */
	FS_INSIGHT_INBOUND_SCAN,         /* one source, many local ports         */
	FS_INSIGHT_BRUTE_FORCE,          /* repeated attempts on a login port    */
	FS_INSIGHT_THREAT_INTEL          /* traffic a block list or country rule hit */
} FsInsightType;

/* One event behind a finding, as the log gave it. */
typedef struct
{
	gint64    when;          /* unix seconds                          */
	gboolean  inbound;
	gchar    *remote;        /* the other end                         */
	guint     port;          /* 0 = none (ICMP)                       */
	gchar    *protocol;
	gboolean  blocked;
	gchar    *rule;          /* what blocked it, when the log says    */
} FsEvidence;

void fs_evidence_free (FsEvidence *ev);

#define FS_INSIGHT_MAX_EVIDENCE 12

/* A single finding. */
typedef struct
{
	FsInsightType        type;
	FsCopilotSeverity    severity;
	gchar               *title;           /* one line                       */
	gchar               *description;     /* what was seen, in sentences    */
	gchar               *application;     /* app (Windows) or service (Linux) */
	gchar               *destination;     /* the remote host, if one        */
	gchar               *suggested_rule;  /* the rule in words, or NULL     */
	gchar               *rule_csv;        /* a deny row, or NULL            */
	FsRuleKind          rule_kind;        /* policy kind rule_csv parses as */
	guint64              timestamp;       /* last updated, unix seconds     */
	gboolean             auto_applicable; /* Sentinel may stage it (deny only) */

	/* 1.0.7: the evidence and the reasoning. */
	gchar               *key;             /* "type|app|subject": a new event
	                                       * for an open finding updates it */
	gchar               *subject;         /* the host or app it is about    */
	gchar               *why;             /* the numbers next to the limits */
	gchar               *benign;          /* "Could be harmless because"    */
	gchar               *withheld;        /* why Sentinel will not auto-block,
	                                       * or NULL                        */
	gchar               *whatif_line;     /* a line for the What-If card    */
	gchar               *events_filter;   /* text for the Events filter     */
	GPtrArray           *evidence;        /* FsEvidence*, newest last, at most
	                                       * FS_INSIGHT_MAX_EVIDENCE        */
	guint                count;           /* events that matched so far     */
} FsInsight;

/* A "what-if" simulation result: the What-If engine's answer
 * (fs-whatif.h) with the fields older callers read. */
typedef struct
{
	gchar               *scenario;        /* Human-readable scenario */
	FsWhatIfVerdict      verdict;         /* ALLOWED / BLOCKED / DEPENDS /
	                                       * ERROR (a line that could
	                                       * not be read)             */
	gboolean             would_block;     /* verdict == BLOCKED       */
	gchar               *matching_rule;   /* Which rule would match */
	gchar               *explanation;     /* Why, as one log sentence */
	gchar               *reason;          /* Why, without the
	                                       * "Simulation: ... would be"
	                                       * wrapper -- what the
	                                       * visualizer shows under
	                                       * "Explanation"            */
	guint                affected_connections; /* Est. connections affected */
	FsWhatIfResult      *whatif;          /* the whole answer: both
	                                       * directions, trace, cases,
	                                       * verified actions (owned)  */
} FsSimulationResult;

/* Application behavior profile learned over time. */
typedef struct
{
	gchar               *app_name;
	gchar               *app_path;
	GHashTable          *common_ports;        /* port -> count */
	GHashTable          *common_destinations; /* IP -> count */
	GHashTable          *hourly_activity;     /* hour -> count */
	guint64             total_connections;
	guint64             total_bytes_sent;
	guint64             total_bytes_recv;
	guint64             first_seen;
	guint64             last_seen;

	/* Connection frequency (P2): events per 10-minute wall-clock
	 * bucket.  The established rate is an EWMA over closed buckets
	 * (x1000, integer, alpha 0.25); rate findings fire once per
	 * bucket (rate_reported is the bucket already reported, 0 for
	 * none).  baseline_partial marks a profile whose port/destination
	 * sets were capped on save, load or ingest -- it can no longer
	 * claim "never seen before", so novelty signals stay quiet for
	 * it. */
	guint64             rate_window_start;    /* open bucket, unix sec; 0 = none */
	guint               rate_window_count;    /* events in the open bucket       */
	guint               rate_ema_milli;       /* events/bucket x1000             */
	guint               rate_buckets;         /* buckets closed so far           */
	guint64             rate_reported;        /* bucket already reported, 0 none */
	gboolean            baseline_partial;

	/* 1.0.7: first contacts with new destinations in the last 7 days
	 * (unix seconds, the newest 64, saved in behavior.csv as "newdest"
	 * rows).  20 or more marks the app as one that meets new hosts all
	 * the time (a browser), and new-destination findings stay quiet for
	 * it, after a restart too. */
	GArray             *new_dest_times;
} FsAppProfile;

/* Opaque copilot context. */
typedef struct _FsCopilot FsCopilot;

/* Create/destroy copilot. */
FsCopilot *fs_copilot_new (void);
void       fs_copilot_free (FsCopilot *copilot);

/* Feed a network event to the copilot for learning/analysis. */
void fs_copilot_feed_event (FsCopilot *copilot, const FsHit *hit);

/* Same, with an explicit arrival time in monotonic microseconds.
 * Production passes g_get_monotonic_time(); the Sentinel detector
 * tests drive time through this so beacon regularity is deterministic. */
void fs_copilot_feed_event_at (FsCopilot *copilot, const FsHit *hit,
                               gint64 now_us);

/* Same, with an explicit wall-clock arrival time in unix seconds as
 * well: hourly buckets and rate windows read the wall clock, so the
 * behavior tests drive it to make timing findings deterministic.
 * Production passes time(NULL). */
void fs_copilot_feed_event_full (FsCopilot *copilot, const FsHit *hit,
                                 gint64 now_us, gint64 now_unix);

/* The current findings, newest first.  The list is the caller's (free
 * with g_list_free); the findings stay the copilot's. */
GList *fs_copilot_get_insights (FsCopilot *copilot);

/* How many events have been fed since the copilot was made. */
guint64 fs_copilot_events_seen (FsCopilot *copilot);

/* The DNS servers and default gateways this computer uses.  Sentinel
 * does not time DNS (port 53) or DNS over TLS (853) to a resolver, and
 * never blocks a resolver or a gateway automatically, on any port
 * (fs_insight_is_auto_safe refuses them too).  When the only resolver
 * is a local stub whose upstream is unknown, no DNS destination is
 * blocked automatically.
 *
 * fs_copilot_new reads them from the system with fs_hostnet_read
 * (resolv.conf and, behind a 127.0.0.53 stub, systemd-resolved's and
 * NetworkManager's upstream lists, /proc/net/route; on Windows every
 * adapter's DNS servers and gateways) and again at most once a minute.
 * With STOCKFW_RESOLV_CONF set it reads that file instead, with
 * STOCKFW_RESOLVED_CONF as the upstream list and STOCKFW_ROUTE_FILE as
 * /proc/net/route, and never re-reads (tests).
 *
 * fs_copilot_set_network takes the texts (resolv.conf, the upstream
 * list, /proc/net/route; any may be NULL) and fixes them; set_resolvers
 * is set_network with resolv.conf only. */
void fs_copilot_set_network (FsCopilot *copilot, const gchar *resolv_conf,
                             const gchar *resolved, const gchar *route);
void fs_copilot_set_resolvers (FsCopilot *copilot, const gchar *resolv_conf);

/* "Unusual port", "Beacon", ... */
const gchar *fs_insight_type_name (FsInsightType type);

/* Clear all insights. */
void fs_copilot_clear_insights (FsCopilot *copilot);

/* Run a "what-if" simulation for one probe given field by field
 * (protocol "TCP" / "UDP" / "ICMP" or NULL for either, port 0 for any,
 * remote_ip an address, a block or NULL for any host) with the What-If
 * engine: the native platform's model, the attached policy and
 * fresh-install Firewall preferences.  A remote_ip that is not an
 * address gives an ERROR verdict.  Never NULL. */
FsSimulationResult *fs_copilot_simulate (FsCopilot *copilot,
                                         const gchar *app_name,
                                         const gchar *remote_ip,
                                         guint port,
                                         const gchar *protocol,
                                         gboolean inbound);

/* Parse a What-If line and run it, as above.  NULL only for an empty
 * line; a line that cannot be read gives an ERROR verdict carrying the
 * parser's message.  parsed_out, when not NULL, receives a copy of the
 * query the line was read as (NULL on an error) for the caller to free
 * with fs_whatif_query_free. */
FsSimulationResult *fs_copilot_simulate_text (FsCopilot *copilot,
                                              const gchar *text,
                                              FsWhatIfQuery **parsed_out);

/* Fills in what a What-If context can learn from the backend: whether
 * the firewall runs, this computer's addresses, and on Windows the
 * network profiles in force, which of them are on and their default
 * actions.  Slots the backend lacks leave their part unknown, and the
 * answer says what it assumed.  state_reliable FALSE when the backend's
 * "stopped" cannot be trusted (on Linux without root every chain reads
 * as missing): a stopped reading then stays unknown, because answering
 * "allowed, the firewall is off" for a firewall that runs would be
 * wrong in the dangerous direction. */
void fs_copilot_whatif_observe (FsWhatIfContext *ctx,
                                const FsBackend *backend,
                                gboolean state_reliable);

/* Whether `saved' is the policy the firewall has loaded: held when
 * hold_reason is set (audit-only mode, the Policy Lock), otherwise the
 * apply journal compared row by row (live, or changed since), unknown
 * without a journal. */
void fs_copilot_whatif_live (FsWhatIfContext *ctx, const FsPolicy *saved,
                             const gchar *hold_reason);

/* Get learned profile for an application (or NULL if unknown). */
const FsAppProfile *fs_copilot_get_profile (FsCopilot *copilot,
                                            const gchar *app_name);

/* Get all known application profiles. */
GList *fs_copilot_get_all_profiles (FsCopilot *copilot);

/* Export copilot state to JSON (for persistence). */
gchar *fs_copilot_export_json (FsCopilot *copilot);

/* Import copilot state from JSON. */
gboolean fs_copilot_import_json (FsCopilot *copilot, const gchar *json);

/* The historical behavior baseline (P2): one CSV row per learned fact
 * (totals, rate state, ports, destinations, hourly buckets) so a
 * restart resumes with yesterday's history instead of learning it
 * again.  Path follows the trust store's convention;
 * STOCKFW_BEHAVIOR_FILE overrides it (tests).  Caller frees with
 * g_free. */
gchar *fs_copilot_baseline_path (void);

/* Save/load the baseline.  Load of a missing file is a fresh start:
 * it returns FALSE with no error set.  Rows beyond the per-profile
 * caps mark that profile baseline_partial (novelty signals go quiet
 * for it rather than claim a truncated baseline knows everything).
 * Save makes the parent directory as needed. */
gboolean fs_copilot_baseline_save (FsCopilot *copilot, const gchar *path,
                                   GError **error);
gboolean fs_copilot_baseline_load (FsCopilot *copilot, const gchar *path,
                                   GError **error);

/* Attach a policy for what-if simulation.  The copilot does not take
 * ownership; passing NULL clears the reference. */
void fs_copilot_set_policy (FsCopilot *copilot, FsPolicy *policy);

/* Get the currently attached policy (may be NULL). */
FsPolicy *fs_copilot_get_policy (FsCopilot *copilot);

/* Free helpers. */
void fs_insight_free (FsInsight *insight);
void fs_simulation_result_free (FsSimulationResult *result);

/* Stage an insight's suggestion: parse rule_csv as insight->rule_kind.
 * fs_insight_to_rule returns a caller-owned rule or NULL.  The apply
 * helper adds it to the policy and saves, rolling the store back when
 * the write fails; FALSE when the insight carries no rule, the CSV
 * does not parse, or the rule is already stored. */
FsRule   *fs_insight_to_rule (const FsInsight *insight);
gboolean   fs_insight_apply   (const FsInsight *insight, FsPolicy *policy);

/* TRUE only when the insight's rule can be staged without a human:
 * it must be able to only tighten the policy (an outbound deny), and
 * its destination must not be one of the classes that must never be
 * auto-blocked (P6: multicast / broadcast / loopback / link-local /
 * the private address space, or anything unparseable).
 * Auto-block consults this; the confirmed Apply button does not. */
gboolean   fs_insight_is_auto_safe (const FsInsight *insight);

/* P6 (false-outage hardening).  TRUE when NO automatic block may ever
 * target this destination: the reserved and private IPv4 ranges, the
 * multicast/broadcast/reserved tail, IPv6 loopback / link-local /
 * multicast / ULA, IPv4-mapped forms of any of those, and anything
 * that is not a literal address at all.  Pure; unit-tested. */
gboolean   fs_sentinel_dest_never_auto_block (const gchar *dest);

/* P6.  TRUE when the historical behavior baseline already records at
 * least FS_SENTINEL_BASELINE_DEST_MIN connections from `app' to
 * `dest': an established destination is normal traffic, and Sentinel
 * reports (but never automatically blocks) even metronomic traffic to
 * it.  The beacon check also withholds when ANY other program's
 * baseline holds the destination, because the block it stages applies
 * to every program and every port. */
gboolean   fs_copilot_baseline_dest_established (FsCopilot *copilot,
                                                 const gchar *app,
                                                 const gchar *dest);

G_END_DECLS

#endif /* FS_COPILOT_H */