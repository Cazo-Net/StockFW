/*---[ fs-copilot.h ]---------------------------------------------------
 * Smart Firewall Copilot - AI-powered network behavior analysis.
 *
 * A unique innovation: no other firewall GUI has an AI copilot that
 * learns application network behavior, detects anomalies, suggests
 * rules with natural-language explanations, and simulates "what-if"
 * scenarios before applying.
 *--------------------------------------------------------------------*/
#ifndef FS_COPILOT_H
#define FS_COPILOT_H

#include <glib.h>
#include "core/fs-types.h"
#include "core/fs-rules.h"
#include "core/fs-fwrule.h"

G_BEGIN_DECLS

/* Analysis severity levels. */
typedef enum
{
	FS_COPILOT_INFO,
	FS_COPILOT_WARNING,
	FS_COPILOT_CRITICAL
} FsCopilotSeverity;

/* Types of insights the copilot can generate. */
typedef enum
{
	FS_INSIGHT_NEW_APPLICATION,      /* App seen for first time */
	FS_INSIGHT_UNUSUAL_PORT,         /* App using unexpected port */
	FS_INSIGHT_UNUSUAL_DESTINATION,  /* App talking to new IP/region */
	FS_INSIGHT_UNUSUAL_VOLUME,       /* Sudden spike in traffic */
	FS_INSIGHT_UNUSUAL_TIME,         /* Activity at unusual hours */
	FS_INSIGHT_RULE_CONFLICT,        /* Rules that contradict */
	FS_INSIGHT_REDUNDANT_RULE,       /* Rule covered by another */
	FS_INSIGHT_MISSING_RULE,         /* Traffic not covered by any rule */
	FS_INSIGHT_SUSPICIOUS_BEHAVIOR,  /* Potential malware/C2 */
	FS_INSIGHT_RULE_OPTIMIZATION,    /* Rules can be merged/simplified */
	FS_INSIGHT_BEACON,               /* Periodic callback traffic: covert channel */
	FS_INSIGHT_FANOUT                /* Burst of distinct destinations: scan/spread */
} FsInsightType;

/* A single insight from the copilot. */
typedef struct
{
	FsInsightType        type;
	FsCopilotSeverity    severity;
	gchar               *title;           /* Short human-readable title */
	gchar               *description;     /* Detailed explanation */
	gchar               *application;     /* App name/path if known */
	gchar               *destination;     /* Remote host/port if applicable */
	gchar               *suggested_rule;  /* Natural-language rule suggestion */
	gchar               *rule_csv;        /* CSV rule ready to apply */
	FsRuleKind          rule_kind;        /* policy kind rule_csv parses as */
	guint64              timestamp;       /* When detected */
	gboolean             auto_applicable; /* Can be applied without review */
} FsInsight;

/* A "what-if" simulation result. */
typedef struct
{
	gchar               *scenario;        /* Human-readable scenario */
	gboolean             would_block;     /* Would traffic be blocked? */
	gchar               *matching_rule;   /* Which rule would match */
	gchar               *explanation;     /* Why, as one log sentence */
	gchar               *reason;          /* Why, without the
	                                       * "Simulation: ... would be"
	                                       * wrapper -- what the
	                                       * visualizer shows under
	                                       * "Explanation"            */
	guint                affected_connections; /* Est. connections affected */
} FsSimulationResult;

/* A parsed What-If Simulator line: the grammar is deliberately small
 * (direction keywords, a host, a port or service name, a protocol) so
 * that what the simulator evaluates is always what the user typed --
 * plain data, freed with fs_scenario_free. */
typedef struct
{
	gboolean inbound;    /* TRUE when the traffic arrives at us         */
	guint    port;       /* service port; 0 when the line named none   */
	gchar   *protocol;   /* "TCP", "UDP" or "ICMP"                      */
	gchar   *remote_ip;  /* address or CIDR the line named, or NULL     */
	gchar   *app;        /* application/service the line named, or NULL */
	gboolean had_port;   /* the line actually carried a port            */
	gboolean had_addr;   /* the line actually carried an address        */
} FsScenario;

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

/* Get current insights (caller frees with g_list_free_full + fs_insight_free). */
GList *fs_copilot_get_insights (FsCopilot *copilot);

/* Clear all insights. */
void fs_copilot_clear_insights (FsCopilot *copilot);

/* Run a "what-if" simulation: given current rules + a hypothetical packet,
 * would it be allowed or blocked? */
FsSimulationResult *fs_copilot_simulate (FsCopilot *copilot,
                                         const gchar *app_name,
                                         const gchar *remote_ip,
                                         guint port,
                                         const gchar *protocol,
                                         gboolean inbound);

/* Parse one What-If line into its scenario fields.  Returns NULL only
 * for NULL/empty input; a line that names nothing still parses, with
 * the had_port/had_addr flags clear and the documented defaults
 * (outbound, any host, any port).  Caller frees with fs_scenario_free. */
FsScenario *fs_copilot_parse_scenario (const gchar *text);
void        fs_scenario_free (FsScenario *scenario);

/* Parse a What-If line and run it against the policy in one step.
 * Returns NULL when the line is empty.  When parsed_out is non-NULL it
 * receives the scenario for the caller to free; otherwise the scenario
 * is freed here. */
FsSimulationResult *fs_copilot_simulate_text (FsCopilot *copilot,
                                              const gchar *text,
                                              FsScenario **parsed_out);

/* The "how to allow this" sentence for a parsed scenario: "Allow
 * inbound TCP port 22 from 192.168.1.5."  Returns a newly allocated
 * string, NULL only for NULL input.  Presentation reads this so the
 * suggestion and the tests speak the same words. */
gchar *fs_copilot_allow_suggestion (const FsScenario *scenario);

/* The policy rule that would let a parsed scenario through: the
 * service-allow kind of the scenario's direction, the scenario's port
 * and host.  Caller frees with fs_rule_free; NULL for NULL input. */
FsRule *fs_copilot_allow_rule_for (const FsScenario *scenario);

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
 * it must be able to only tighten the policy (an outbound deny).
 * Auto-block consults this; the confirmed Apply button does not. */
gboolean   fs_insight_is_auto_safe (const FsInsight *insight);

G_END_DECLS

#endif /* FS_COPILOT_H */