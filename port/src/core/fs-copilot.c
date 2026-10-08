/*---[ fs-copilot.c ]---------------------------------------------------
 * Smart Firewall Copilot - Implementation.
 *
 * Learns application network behavior, detects anomalies, suggests
 * rules with natural-language explanations, and simulates "what-if"
 * scenarios before applying.
 *--------------------------------------------------------------------*/

#include "core/fs-copilot.h"
#include "core/fs-util.h"
#include "core/fs-service.h"
#include "core/fs-i18n.h"
#include "core/fs-fwrule.h"
#include "core/fs-rules.h"

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
	gdouble anomaly_threshold;      /* Standard deviations for anomaly */
	guint min_samples_for_baseline; /* Min connections before analyzing */

	/* Sentinel (1.0.4): covert-channel and fan-out state.  Arrival
	 * times are bucketed to whole seconds, so a polled batch of
	 * records counts as one moment instead of a fake burst. */
	GHashTable *beacon_stamps;      /* "host:port" -> GArray<gint64> */
	GHashTable *beacon_reported;    /* "host:port" -> TRUE           */
	GHashTable *fanout_seen;        /* host -> last bucketed second  */
	GHashTable *fanout_blocked;     /* blocked host -> bucketed sec  */
	gboolean    fanout_reported;    /* current window already told   */
};

/* Forward declarations. */
static FsAppProfile *app_profile_new (const gchar *name, const gchar *path);
static void app_profile_free (FsAppProfile *profile);
static void app_profile_record_connection (FsAppProfile *profile,
                                           const gchar *remote_ip,
                                           guint port,
                                           const gchar *protocol,
                                           gboolean inbound,
                                           guint64 bytes);
static gboolean is_anomalous_port (FsAppProfile *profile, guint port);
static gboolean is_anomalous_destination (FsAppProfile *profile,
                                          const gchar *remote_ip);
static gboolean is_anomalous_time (FsAppProfile *profile);
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

static FsInsight *sentinel_beacon_check (FsCopilot *copilot,
                                         const FsHit *hit,
                                         gint64 now_us);
static FsInsight *sentinel_fanout_check (FsCopilot *copilot,
                                         const FsHit *hit,
                                         gint64 now_us);
/* Note: simulate_against_rules() was declared here once but never
 * written or called.  fs_copilot_simulate() says in its own comment
 * that it still uses heuristics rather than the rule engine, which is
 * what the declaration used to imply and was not true. */

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
	copilot->anomaly_threshold = 2.0;       /* 2 standard deviations */
	copilot->min_samples_for_baseline = 10; /* Need 10 connections baseline */

	copilot->beacon_stamps = g_hash_table_new_full (
		g_str_hash, g_str_equal, g_free,
		(GDestroyNotify) g_array_unref);
	copilot->beacon_reported = g_hash_table_new_full (
		g_str_hash, g_str_equal, g_free, NULL);
	copilot->fanout_seen = g_hash_table_new_full (
		g_str_hash, g_str_equal, g_free, NULL);
	copilot->fanout_blocked = g_hash_table_new_full (
		g_str_hash, g_str_equal, g_free, NULL);
	copilot->fanout_reported = FALSE;

	return copilot;
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
	g_hash_table_unref (copilot->fanout_seen);
	g_hash_table_unref (copilot->fanout_blocked);
	g_list_free_full (copilot->insights, (GDestroyNotify) fs_insight_free);
	g_free (copilot);
}

/* [ fs_copilot_feed_event ] */
void
fs_copilot_feed_event (FsCopilot *copilot, const FsHit *hit)
{
	fs_copilot_feed_event_at (copilot, hit, g_get_monotonic_time ());
}

/* [ fs_copilot_feed_event_at ] */
void
fs_copilot_feed_event_at (FsCopilot *copilot, const FsHit *hit,
                          gint64 now_us)
{
	if (copilot == NULL || hit == NULL || !copilot->learning_enabled)
		return;

	/* Extract app name from hit - in reality this would come from
	 * process tracking. For now, infer from port/service. */
	const gchar *app_name = hit->service ? hit->service : "Unknown";
	const gchar *remote_ip = hit->source ? hit->source : hit->destination;
	guint port = hit->port ? atoi (hit->port) : 0;
	const gchar *protocol = hit->protocol ? hit->protocol : "TCP";
	gboolean inbound = (hit->direction && g_strcmp0 (hit->direction, "In") == 0);

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
	 * g_hash_table_lookup() inside is_anomalous_port() on the freed
	 * profile->common_ports (integer divide-by-zero or access violation
	 * in libglib), plus the heap fail-fasts from the double free. */
	FsAppProfile *profile = g_hash_table_lookup (copilot->profiles, app_name);
	if (profile == NULL)
	{
		profile = app_profile_new (app_name, NULL);
		g_hash_table_insert (copilot->profiles, g_strdup (app_name), profile);
	}

	app_profile_record_connection (profile, remote_ip, port, protocol,
	                               inbound, 0);

	/* Sentinel runs on every event, baseline or not: a control
	 * channel has to be caught in its first minutes, not after the
	 * learning baseline has had its 10 samples. */
	{
		FsInsight *beacon = sentinel_beacon_check (copilot, hit, now_us);
		FsInsight *fanout = sentinel_fanout_check (copilot, hit, now_us);

		if (beacon != NULL) {
			beacon->timestamp = time (NULL);
			copilot->insights = g_list_prepend (copilot->insights,
			                                    beacon);
		}
		if (fanout != NULL) {
			fanout->timestamp = time (NULL);
			copilot->insights = g_list_prepend (copilot->insights,
			                                    fanout);
		}
	}

	/* Analyze for anomalies if we have enough baseline. */
	if (profile->total_connections >= copilot->min_samples_for_baseline)
	{
		FsInsight *insight = NULL;

		if (is_anomalous_port (profile, port))
		{
			insight = create_insight (FS_INSIGHT_UNUSUAL_PORT,
			                          FS_COPILOT_WARNING,
			                          _("Unusual port for application"),
			                          g_strdup_printf (_("Application '%s' is using port %u, "
			                                            "which it has never used before. "
			                                            "This could indicate a new service or compromise."),
			                                         app_name, port),
			                          app_name,
			                          g_strdup_printf ("%s:%u", remote_ip ? remote_ip : "?", port));
			insight->suggested_rule = g_strdup_printf (_("Allow %s on port %u for %s"),
			                                           app_name, port, remote_ip ? remote_ip : "any");
			insight->rule_csv = g_strdup_printf ("%s, %u, %s, %s",
			                                     app_name, port,
			                                     remote_ip ? remote_ip : "Anyone",
			                                     _("Auto-generated by Copilot"));
			insight->auto_applicable = TRUE;
		}
		else if (is_anomalous_destination (profile, remote_ip))
		{
			insight = create_insight (FS_INSIGHT_UNUSUAL_DESTINATION,
			                          FS_COPILOT_WARNING,
			                          _("Unusual destination"),
			                          g_strdup_printf (_("Application '%s' is connecting to %s, "
			                                            "which it has never contacted before. "
			                                            "Verify this is expected."),
			                                         app_name, remote_ip ? remote_ip : "?"),
			                          app_name,
			                          remote_ip ? g_strdup (remote_ip) : NULL);
			insight->suggested_rule = g_strdup_printf (_("Allow %s to connect to %s"),
			                                           app_name, remote_ip ? remote_ip : "that host");
			insight->rule_csv = g_strdup_printf ("%s, %u, %s, %s",
			                                     app_name, port,
			                                     remote_ip ? remote_ip : "Anyone",
			                                     _("Auto-generated by Copilot"));
			insight->auto_applicable = TRUE;
		}
		else if (is_anomalous_time (profile))
		{
			insight = create_insight (FS_INSIGHT_UNUSUAL_TIME,
			                          FS_COPILOT_INFO,
			                          _("Activity at unusual time"),
			                          g_strdup_printf (_("Application '%s' is active at %s, "
			                                            "outside its normal hours."),
			                                         app_name,
			                                         ctime (&(time_t){time(NULL)})),
			                          app_name,
			                          NULL);
		}

		if (insight != NULL)
		{
			/* create_insight() already carried the application
			 * name; re-assigning it here leaked the first copy. */
			insight->timestamp = time (NULL);
			copilot->insights = g_list_prepend (copilot->insights, insight);
		}
	}
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

/* [ fs_copilot_simulate ]
 * Runs a what-if simulation against the attached policy.  If no policy
 * is attached, falls back to heuristic defaults (deny inbound, allow
 * outbound) and notes the limitation in the explanation. */
FsSimulationResult *
fs_copilot_simulate (FsCopilot *copilot,
                     const gchar *app_name,
                     const gchar *remote_ip,
                     guint port,
                     const gchar *protocol,
                     gboolean inbound)
{
	FsSimulationResult *result = g_new0 (FsSimulationResult, 1);

	/* Build the human-readable scenario string. */
	result->scenario = g_strdup_printf (_("%s %s connection from %s to %s:%u (%s)"),
	                                    inbound ? _("Inbound") : _("Outbound"),
	                                    protocol ? protocol : "TCP",
	                                    remote_ip ? remote_ip : "anywhere",
	                                    inbound ? "local" : remote_ip,
	                                    port,
	                                    (app_name && *app_name) ? app_name
	                                                          : _("an application"));

	/* If no policy is attached, fall back to heuristic defaults. */
	if (copilot == NULL || copilot->policy == NULL)
	{
		if (inbound)
		{
			result->would_block = TRUE;
			result->matching_rule = g_strdup (_("Default deny (no policy loaded)"));
			result->explanation = g_strdup (_("No firewall policy is loaded in the copilot. "
			                                  "Default behavior: deny inbound. "
			                                  "Load a policy in the Policy tab for accurate simulation."));
		}
		else
		{
			result->would_block = FALSE;
			result->matching_rule = g_strdup (_("Default allow (no policy loaded)"));
			result->explanation = g_strdup (_("No firewall policy is loaded in the copilot. "
			                                  "Default behavior: allow outbound. "
			                                  "Load a policy in the Policy tab for accurate simulation."));
		}

		result->affected_connections = 1;
		result->explanation = g_strdup_printf (_("Simulation: %s connection from %s to %s:%u (%s) "
		                                         "would be %s. Reason: %s"),
		                                       inbound ? _("inbound") : _("outbound"),
		                                       remote_ip ? remote_ip : "anywhere",
		                                       inbound ? "local" : remote_ip,
		                                       port,
		                                       protocol ? protocol : "TCP",
		                                       result->would_block ? _("BLOCKED") : _("ALLOWED"),
		                                       result->explanation);
		return result;
	}

	/* Expand the policy into concrete rules. */
	GList *rules = fs_fwrule_from_policy (copilot->policy);
	if (rules == NULL)
	{
		/* No rules in policy -- use defaults. */
		if (inbound)
		{
			result->would_block = TRUE;
			result->matching_rule = g_strdup (_("Default deny (empty policy)"));
			result->explanation = g_strdup (_("The loaded policy contains no rules. "
			                                  "Default behavior: deny inbound."));
		}
		else
		{
			result->would_block = FALSE;
			result->matching_rule = g_strdup (_("Default allow (empty policy)"));
			result->explanation = g_strdup (_("The loaded policy contains no rules. "
			                                  "Default behavior: allow outbound."));
		}
	}
	else
	{
		/* Match the scenario against each rule in order.
		 * First match wins (like a real firewall). */
		FsRuleProtocol proto = FS_PROTO_ANY;
		if (protocol != NULL)
		{
			if (g_strcmp0 (protocol, "TCP") == 0)
				proto = FS_PROTO_TCP;
			else if (g_strcmp0 (protocol, "UDP") == 0)
				proto = FS_PROTO_UDP;
		}

		const gchar *remote_addr = (remote_ip && *remote_ip) ? remote_ip : NULL;
		const gchar *local_addr = inbound ? NULL : remote_addr; /* for outbound, remote is destination */

		GList *match = NULL;
		for (GList *l = rules; l != NULL; l = l->next)
		{
			FsFwRule *rule = l->data;

			/* Direction must match. */
			if (rule->direction != (inbound ? FS_DIR_INBOUND : FS_DIR_OUTBOUND))
				continue;

			/* Protocol must match (ANY matches TCP/UDP). */
			if (rule->protocol != FS_PROTO_ANY && rule->protocol != proto)
				continue;

			/* Local port must match. */
			if (rule->local_port != 0 && rule->local_port != (gint)port)
				continue;

			/* Remote port must match. */
			if (rule->remote_port != 0 && rule->remote_port != (gint)port)
				continue;

			/* Local address must match. */
			if (rule->local_address != NULL && local_addr != NULL)
			{
				if (g_strcmp0 (rule->local_address, local_addr) != 0)
					continue;
			}

			/* Remote address must match. */
			if (rule->remote_address != NULL && remote_addr != NULL)
			{
				if (g_strcmp0 (rule->remote_address, remote_addr) != 0)
					continue;
			}

			/* All criteria matched. */
			match = l;
			break;
		}

		if (match != NULL)
		{
			FsFwRule *rule = match->data;
			result->would_block = (rule->action == FS_ACTION_BLOCK);
			result->matching_rule = g_strdup (rule->name);
			result->explanation = g_strdup_printf (_("Matched rule '%s' (%s %s)."),
			                                       rule->name,
			                                       result->would_block ? _("blocks") : _("allows"),
			                                       inbound ? _("inbound") : _("outbound"));
		}
		else
		{
			/* No rule matched -- apply default policy. */
			if (inbound)
			{
				result->would_block = TRUE;
				result->matching_rule = g_strdup (_("Default deny (no matching rule)"));
				result->explanation = g_strdup (_("No rule in the loaded policy matches this connection. "
				                                  "Default policy: deny inbound."));
			}
			else
			{
				result->would_block = FALSE;
				result->matching_rule = g_strdup (_("Default allow (no matching rule)"));
				result->explanation = g_strdup (_("No rule in the loaded policy matches this connection. "
				                                  "Default policy: allow outbound."));
			}
		}

		fs_fwrule_list_free (rules);
	}

	result->affected_connections = 1;
	result->explanation = g_strdup_printf (_("Simulation: %s connection from %s to %s:%u (%s) "
	                                         "would be %s. Reason: %s"),
	                                       inbound ? _("inbound") : _("outbound"),
	                                       remote_ip ? remote_ip : "anywhere",
	                                       inbound ? "local" : remote_ip,
	                                       port,
	                                       protocol ? protocol : "TCP",
	                                       result->would_block ? _("BLOCKED") : _("ALLOWED"),
	                                       result->explanation);

	return result;
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
	g_free (insight);
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
 * are never safe to stage automatically, whatever their flag says. */
gboolean
fs_insight_is_auto_safe (const FsInsight *insight)
{
	if (insight == NULL || insight->rule_csv == NULL ||
	    *insight->rule_csv == '\0')
		return FALSE;

	return insight->rule_kind == FS_RULE_OUTBOUND_DENY_TO ||
	       insight->rule_kind == FS_RULE_OUTBOUND_DENY_SERVICE;
}

/* [ app_profile_new ] */
static FsAppProfile *
app_profile_new (const gchar *name, const gchar *path)
{
	FsAppProfile *profile = g_new0 (FsAppProfile, 1);
	profile->app_name = g_strdup (name);
	profile->app_path = path ? g_strdup (path) : NULL;
	profile->common_ports = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                               NULL, NULL);
	profile->common_destinations = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                                      g_free, NULL);
	profile->hourly_activity = g_hash_table_new_full (g_direct_hash, g_direct_equal,
                                                      NULL, NULL);
	profile->first_seen = time (NULL);
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
	g_free (profile);
}

/* [ app_profile_record_connection ] */
static void
app_profile_record_connection (FsAppProfile *profile,
                               const gchar *remote_ip,
                               guint port,
                               const gchar *protocol,
                               gboolean inbound,
                               guint64 bytes)
{
	profile->total_connections++;
	profile->last_seen = time (NULL);

	if (bytes > 0)
	{
		if (bytes > 0) /* Direction inferred from context */
			profile->total_bytes_recv += bytes;
		else
			profile->total_bytes_sent += bytes;
	}

	/* Record port usage. */
	guint *port_count = g_hash_table_lookup (profile->common_ports,
	                                         GUINT_TO_POINTER (port));
	if (port_count == NULL)
	{
		guint *new_count = g_new (guint, 1);
		*new_count = 1;
		g_hash_table_insert (profile->common_ports,
		                     GUINT_TO_POINTER (port), new_count);
	}
	else
	{
		(*port_count)++;
	}

	/* Record destination. */
	if (remote_ip && *remote_ip)
	{
		guint *dest_count = g_hash_table_lookup (profile->common_destinations,
		                                         remote_ip);
		if (dest_count == NULL)
		{
			guint *new_count = g_new (guint, 1);
			*new_count = 1;
			g_hash_table_insert (profile->common_destinations,
			                     g_strdup (remote_ip), new_count);
		}
		else
		{
			(*dest_count)++;
		}
	}

	/* Record hourly activity. */
	time_t now = time (NULL);
	struct tm *tm = localtime (&now);
	guint hour = tm->tm_hour;
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

/* [ is_anomalous_port ] */
static gboolean
is_anomalous_port (FsAppProfile *profile, guint port)
{
	if (port == 0)
		return FALSE;

	guint *count = g_hash_table_lookup (profile->common_ports,
	                                    GUINT_TO_POINTER (port));
	return (count == NULL || *count < 3); /* Anomalous if never seen or < 3 times */
}

/* [ is_anomalous_destination ] */
static gboolean
is_anomalous_destination (FsAppProfile *profile, const gchar *remote_ip)
{
	if (remote_ip == NULL || *remote_ip == '\0')
		return FALSE;

	guint *count = g_hash_table_lookup (profile->common_destinations, remote_ip);
	return (count == NULL || *count < 3);
}

/* [ is_anomalous_time ] */
static gboolean
is_anomalous_time (FsAppProfile *profile)
{
	time_t now = time (NULL);
	struct tm *tm = localtime (&now);
	guint hour = tm->tm_hour;

	guint64 *count = g_hash_table_lookup (profile->hourly_activity,
	                                      GUINT_TO_POINTER (hour));
	if (count == NULL || *count < 5)
		return TRUE; /* Unusual if < 5 connections in this hour historically */

	return FALSE;
}

/* ---- Sentinel: covert-channel and fan-out detection ---------------- */

/* [ sentinel_hit_is_inbound ]
 * The rogue-agent problem is egress: what leaves the host.  Sentinel
 * watches outbound events only. */
static gboolean
sentinel_hit_is_inbound (const FsHit *hit)
{
	if (hit->direction == NULL)
		return FALSE;

	return g_ascii_strcasecmp (hit->direction, "In") == 0 ||
	       g_ascii_strcasecmp (hit->direction, "Inbound") == 0;
}

/* [ sentinel_hit_is_blocked ]
 * The Windows backend appends " [BLOCKED]" to the service field of
 * dropped events; blocked fan-out is the strongest scan signal. */
static gboolean
sentinel_hit_is_blocked (const FsHit *hit)
{
	return hit->service != NULL &&
	       strstr (hit->service, " [BLOCKED]") != NULL;
}

/* [ sentinel_beacon_check ]
 * Regularity, not content: a host contacted every N seconds with
 * metronomic intervals is running a check-in loop, because humans,
 * page loads and even scheduled jobs jitter.  Arrival times are
 * bucketed to whole seconds (a polled batch is one moment), the
 * interval series is capped, and each host:port is reported once. */
static FsInsight *
sentinel_beacon_check (FsCopilot *copilot, const FsHit *hit, gint64 now_us)
{
	const gchar *dst, *port;
	gchar *key;
	gboolean key_owned = FALSE;
	GArray *stamps;
	gint64 sec, last, sum = 0;
	gdouble mean, var = 0.0;
	guint i, n_diff;

	if (sentinel_hit_is_inbound (hit))
		return NULL;

	dst  = hit->destination;
	port = hit->port;
	if (dst == NULL || *dst == '\0' || port == NULL || *port == '\0')
		return NULL;

	sec = now_us / G_USEC_PER_SEC;
	key = g_strdup_printf ("%s:%s", dst, port);

	stamps = g_hash_table_lookup (copilot->beacon_stamps, key);
	if (stamps == NULL) {
		stamps = g_array_new (FALSE, TRUE, sizeof (gint64));
		g_hash_table_insert (copilot->beacon_stamps, key, stamps);
		key_owned = TRUE;
	}

	if (stamps->len == 0) {
		g_array_append_val (stamps, sec);
	} else {
		last = g_array_index (stamps, gint64, stamps->len - 1);

		if (last < sec) {
			g_array_append_val (stamps, sec);
			if (stamps->len > FS_SENTINEL_BEACON_MAX_STAMPS)
				g_array_remove_index (stamps, 0);
		}
		/* last == sec: same-second batch, no new information. */
	}

	if (stamps->len < FS_SENTINEL_BEACON_MIN_SAMPLES)
		goto out;

	n_diff = stamps->len - 1;
	for (i = 0; i < n_diff; i++)
		sum += g_array_index (stamps, gint64, i + 1) -
		       g_array_index (stamps, gint64, i);

	mean = (gdouble) sum / n_diff;
	for (i = 0; i < n_diff; i++) {
		gdouble d = (gdouble) (g_array_index (stamps, gint64, i + 1) -
		                       g_array_index (stamps, gint64, i));

		var += (d - mean) * (d - mean);
	}

	/* Regularity as cv^2 against the threshold -- no sqrt(), so no
	 * libm dependency in the test build. */
	if (mean < FS_SENTINEL_BEACON_MIN_MEAN_S ||
	    mean > FS_SENTINEL_BEACON_MAX_MEAN_S ||
	    var / n_diff > (FS_SENTINEL_BEACON_MAX_CV *
	                    FS_SENTINEL_BEACON_MAX_CV) * mean * mean)
		goto out;

	if (g_hash_table_contains (copilot->beacon_reported, key))
		goto out;

	g_hash_table_insert (copilot->beacon_reported, g_strdup (key),
	                     GINT_TO_POINTER (1));

	{
		FsInsight *insight = create_insight (
			FS_INSIGHT_BEACON, FS_COPILOT_CRITICAL,
			_("Periodic beacon traffic detected"),
			g_strdup_printf (
				_("Connection to %s:%s repeated %u times at "
				  "near-identical intervals of about %d "
				  "seconds. Traffic this metronomic is the "
				  "signature of a control channel checking "
				  "in. StockFW suggests blocking further "
				  "outbound traffic to this destination."),
				dst, port, stamps->len, (gint) (mean + 0.5)),
			hit->service, dst);

		insight->suggested_rule = g_strdup_printf (
			_("Block outbound traffic to %s"), dst);
		insight->rule_csv = g_strdup_printf (
			"%s, %s", dst, "Sentinel: periodic beacon");
		insight->rule_kind = FS_RULE_OUTBOUND_DENY_TO;
		insight->auto_applicable = TRUE;

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
 * One program reaching many distinct hosts inside a short window is a
 * scan, a worm or data leaving by many doors.  Blocked hosts count on
 * their own, lower, threshold: legitimate bulk traffic is mostly
 * allowed, scanning is mostly refused.  One report per window; the
 * episode ends when the window empties. */
static FsInsight *
sentinel_fanout_check (FsCopilot *copilot, const FsHit *hit, gint64 now_us)
{
	const gchar *dst;
	gint64 sec, window_start;
	guint n_any, n_blocked;
	GHashTableIter iter;
	gpointer k, v;
	FsInsight *insight;

	if (sentinel_hit_is_inbound (hit))
		return NULL;

	dst = hit->destination;
	if (dst == NULL || *dst == '\0')
		return NULL;

	sec         = now_us / G_USEC_PER_SEC;
	window_start = sec - FS_SENTINEL_FANOUT_WINDOW_S;

	g_hash_table_iter_init (&iter, copilot->fanout_seen);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		if (GPOINTER_TO_INT (v) < window_start)
			g_hash_table_iter_remove (&iter);
	}

	g_hash_table_iter_init (&iter, copilot->fanout_blocked);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		if (GPOINTER_TO_INT (v) < window_start)
			g_hash_table_iter_remove (&iter);
	}

	/* An emptied window starts a fresh episode. */
	if (g_hash_table_size (copilot->fanout_seen) == 0)
		copilot->fanout_reported = FALSE;

	g_hash_table_insert (copilot->fanout_seen, g_strdup (dst),
	                     GINT_TO_POINTER ((gint) sec));

	if (sentinel_hit_is_blocked (hit))
		g_hash_table_insert (copilot->fanout_blocked, g_strdup (dst),
		                     GINT_TO_POINTER ((gint) sec));

	n_any     = g_hash_table_size (copilot->fanout_seen);
	n_blocked = g_hash_table_size (copilot->fanout_blocked);

	if (n_blocked < FS_SENTINEL_FANOUT_BLOCKED &&
	    n_any < FS_SENTINEL_FANOUT_LIMIT)
		return NULL;

	if (copilot->fanout_reported)
		return NULL;

	copilot->fanout_reported = TRUE;

	insight = create_insight (
		FS_INSIGHT_FANOUT, FS_COPILOT_CRITICAL,
		_("Burst of distinct destinations"),
		g_strdup_printf (
			_("In the last %d seconds this host contacted %u "
			  "distinct remote hosts, %u of them while being "
			  "blocked. One program fanning out like this is a "
			  "scan, a worm or data leaving by many doors. "
			  "Right-click a row in Events to block a host."),
			FS_SENTINEL_FANOUT_WINDOW_S, n_any, n_blocked),
		hit->service, NULL);

	/* No single guilty host exists, so this detection carries no
	 * rule: auto-block must never guess. */
	insight->suggested_rule = g_strdup (
		_("Review the events and block the hosts that should not "
		  "be reached"));
	insight->rule_csv = NULL;
	insight->auto_applicable = FALSE;

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
	/* Every caller passes a freshly formatted string here (and a
	 * literal for the title), so the description is taken over as it
	 * stands -- the g_strdup this used to do leaked one string per
	 * insight. */
	insight->description = description;
	/* Legacy suggestions are CSV rows shaped as outbound service
	 * allows; Sentinel block suggestions override this with the deny
	 * kind they were built for. */
	insight->rule_kind = FS_RULE_OUTBOUND_ALLOW_SERVICE;
	insight->application = g_strdup (app_name);
	insight->destination = destination ? g_strdup (destination) : NULL;
	return insight;
}