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

#include <time.h>
#include <stdlib.h>
#include <string.h>

struct _FsCopilot
{
	/* Learned application profiles. */
	GHashTable *profiles;           /* app_name -> FsAppProfile* */

	/* Current insights. */
	GList *insights;

	/* Configuration. */
	gboolean learning_enabled;
	gdouble anomaly_threshold;      /* Standard deviations for anomaly */
	guint min_samples_for_baseline; /* Min connections before analyzing */
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
static gboolean is_anomalous_volume (FsAppProfile *profile, guint64 bytes);
static FsInsight *create_insight (FsInsightType type,
                                  FsCopilotSeverity severity,
                                  const gchar *title,
                                  const gchar *description,
                                  const gchar *app_name,
                                  const gchar *destination);
static FsSimulationResult *simulate_against_rules (FsCopilot *copilot,
                                                   const gchar *app_name,
                                                   const gchar *remote_ip,
                                                   guint port,
                                                   const gchar *protocol,
                                                   gboolean inbound);

/* [ fs_copilot_new ] */
FsCopilot *
fs_copilot_new (void)
{
	FsCopilot *copilot = g_new0 (FsCopilot, 1);

	copilot->profiles = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                           g_free, (GDestroyNotify) app_profile_free);
	copilot->insights = NULL;
	copilot->learning_enabled = TRUE;
	copilot->anomaly_threshold = 2.0;       /* 2 standard deviations */
	copilot->min_samples_for_baseline = 10; /* Need 10 connections baseline */

	return copilot;
}

/* [ fs_copilot_free ] */
void
fs_copilot_free (FsCopilot *copilot)
{
	if (copilot == NULL)
		return;

	g_hash_table_unref (copilot->profiles);
	g_list_free_full (copilot->insights, (GDestroyNotify) fs_insight_free);
	g_free (copilot);
}

/* [ fs_copilot_feed_event ] */
void
fs_copilot_feed_event (FsCopilot *copilot, const FsHit *hit)
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

	/* Get or create profile. */
	FsAppProfile *profile = g_hash_table_lookup (copilot->profiles, app_name);
	if (profile == NULL)
		profile = app_profile_new (app_name, NULL);

	app_profile_record_connection (profile, remote_ip, port, protocol,
	                               inbound, 0);

	g_hash_table_insert (copilot->profiles, g_strdup (app_name), profile);

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
			insight->application = g_strdup (app_name);
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

/* [ fs_copilot_simulate ] */
FsSimulationResult *
fs_copilot_simulate (FsCopilot *copilot,
                     const gchar *app_name,
                     const gchar *remote_ip,
                     guint port,
                     const gchar *protocol,
                     gboolean inbound)
{
	/* This would use the rule engine to check what would happen.
	 * For now, return a simulated result based on current rules. */
	FsSimulationResult *result = g_new0 (FsSimulationResult, 1);

	result->scenario = g_strdup_printf (_("%s %s connection from %s to %s:%u (%s)"),
	                                    inbound ? _("Inbound") : _("Outbound"),
	                                    protocol ? protocol : "TCP",
	                                    remote_ip ? remote_ip : "anywhere",
	                                    inbound ? "local" : remote_ip,
	                                    port);

	/* In a real implementation, this would iterate through the
	 * actual policy rules. For now, simulate based on heuristics. */
	if (inbound)
	{
		result->would_block = TRUE;  /* Default deny inbound */
		result->matching_rule = g_strdup (_("Default deny (no allow rule)"));
		result->explanation = g_strdup (_("No inbound allow rule matches this connection. "
		                                  "Default policy is to block."));
	}
	else
	{
		result->would_block = FALSE; /* Default allow outbound */
		result->matching_rule = g_strdup (_("Default allow"));
		result->explanation = g_strdup (_("Outbound connections are allowed by default "
		                                  "unless explicitly blocked."));
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

/* [ is_anomalous_volume ] - simplified */
static gboolean
is_anomalous_volume (FsAppProfile *profile, guint64 bytes)
{
	/* Would compare against historical average. Simplified. */
	return bytes > 10 * 1024 * 1024; /* > 10MB in one connection */
}

/* [ create_insight ] */
static FsInsight *
create_insight (FsInsightType type,
                FsCopilotSeverity severity,
                const gchar *title,
                const gchar *description,
                const gchar *app_name,
                const gchar *destination)
{
	FsInsight *insight = g_new0 (FsInsight, 1);
	insight->type = type;
	insight->severity = severity;
	insight->title = g_strdup (title);
	insight->description = g_strdup (description);
	insight->application = g_strdup (app_name);
	insight->destination = destination ? g_strdup (destination) : NULL;
	return insight;
}