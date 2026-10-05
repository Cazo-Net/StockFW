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
	FS_INSIGHT_RULE_OPTIMIZATION     /* Rules can be merged/simplified */
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
	guint64              timestamp;       /* When detected */
	gboolean             auto_applicable; /* Can be applied without review */
} FsInsight;

/* A "what-if" simulation result. */
typedef struct
{
	gchar               *scenario;        /* Human-readable scenario */
	gboolean             would_block;     /* Would traffic be blocked? */
	gchar               *matching_rule;   /* Which rule would match */
	gchar               *explanation;     /* Why */
	guint                affected_connections; /* Est. connections affected */
} FsSimulationResult;

/* Application behavior profile learned over time. */
typedef struct
{
	gchar               *app_name;
	gchar               *app_path;
	GHashTable          *common_ports;        /* port -> count */
	GHashTable          *common_destinations; /* IP:port -> count */
	GHashTable          *hourly_activity;     /* hour -> byte count */
	guint64             total_connections;
	guint64             total_bytes_sent;
	guint64             total_bytes_recv;
	guint64             first_seen;
	guint64             last_seen;
} FsAppProfile;

/* Opaque copilot context. */
typedef struct _FsCopilot FsCopilot;

/* Create/destroy copilot. */
FsCopilot *fs_copilot_new (void);
void       fs_copilot_free (FsCopilot *copilot);

/* Feed a network event to the copilot for learning/analysis. */
void fs_copilot_feed_event (FsCopilot *copilot, const FsHit *hit);

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

/* Get learned profile for an application (or NULL if unknown). */
const FsAppProfile *fs_copilot_get_profile (FsCopilot *copilot,
                                            const gchar *app_name);

/* Get all known application profiles. */
GList *fs_copilot_get_all_profiles (FsCopilot *copilot);

/* Export copilot state to JSON (for persistence). */
gchar *fs_copilot_export_json (FsCopilot *copilot);

/* Import copilot state from JSON. */
gboolean fs_copilot_import_json (FsCopilot *copilot, const gchar *json);

/* Free helpers. */
void fs_insight_free (FsInsight *insight);
void fs_simulation_result_free (FsSimulationResult *result);

G_END_DECLS

#endif /* FS_COPILOT_H */