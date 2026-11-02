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
#include "core/fs-apply.h"
#include "core/fs-netplace.h"

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
                              gint64 now_unix);
static void emit_insight (FsCopilot *copilot, FsInsight *insight);
static gboolean sentinel_hit_is_inbound (const FsHit *hit);
static void hit_app_key (const FsHit *hit, gchar *buf, gsize size);
static gboolean sentinel_dest_auto_ok (FsCopilot *copilot,
                                       const gchar *app,
                                       const gchar *dest);
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
                                         gint64 now_us);
static FsInsight *sentinel_fanout_check (FsCopilot *copilot,
                                         const FsHit *hit,
                                         gint64 now_us);

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

	app_profile_record_connection (profile, remote_ip, port, protocol,
	                               inbound, 0, now_unix);

	/* Sentinel runs on every event, baseline or not: a control
	 * channel has to be caught in its first minutes, not after the
	 * learning baseline has had its 10 samples. */
	{
		FsInsight *beacon = sentinel_beacon_check (copilot, hit, now_us);
		FsInsight *fanout = sentinel_fanout_check (copilot, hit, now_us);

		if (beacon != NULL) {
			beacon->timestamp = now_unix;
			emit_insight (copilot, beacon);
		}
		if (fanout != NULL) {
			fanout->timestamp = now_unix;
			emit_insight (copilot, fanout);
		}
	}

	/* Judge the event against the baseline once it has one. */
	if (profile->total_connections >= copilot->min_samples_for_baseline)
		behavior_analyze (copilot, profile, app_name, remote_ip,
		                  port, now_unix);
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

	if (backend->list_interfaces != NULL) {
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
		    g_strcmp0 (kind, "hour") != 0) {
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
 * multicast and two LAN hosts auto-blocked as "beacons". */
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

/* [ sentinel_dest_auto_ok ] -- both P6 gates in one verdict: the
 * destination class and the established baseline. */
static gboolean
sentinel_dest_auto_ok (FsCopilot *copilot, const gchar *app,
                       const gchar *dest)
{
	if (fs_sentinel_dest_never_auto_block (dest))
		return FALSE;

	if (fs_copilot_baseline_dest_established (copilot, app, dest))
		return FALSE;

	return TRUE;
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

/* [ behavior_analyze ]
 * P2's whole point: correlate, don't chain.  Every signal this event
 * raises -- new port, new destination, first activity in an hour,
 * rate far above the app's own -- goes into ONE finding whose
 * description lists each signal with its numbers, so the reader sees
 * what fired and why together.  Two or more signals on one event
 * escalate to CRITICAL: that is what correlation buys.  A correlated
 * finding carries no suggested rule; a single port/destination one
 * keeps the legacy allow suggestion (an outbound service allow,
 * never auto-safe, so the Sentinel path cannot stage it). */
static void
behavior_analyze (FsCopilot *copilot, FsAppProfile *profile,
                  const gchar *app_name, const gchar *remote_ip,
                  guint port, gint64 now_unix)
{
	gboolean sig_port, sig_dest, sig_hour, sig_rate;
	GPtrArray *lines;
	GString *desc;
	FsInsightType type;
	FsCopilotSeverity severity;
	FsInsight *insight;
	const gchar *title;
	gchar *owned_title = NULL;
	gchar *dest_owned = NULL;
	guint n, i;

	sig_port = !profile->baseline_partial &&
	           is_novel_port (profile, port);
	sig_dest = !profile->baseline_partial &&
	           is_novel_destination (profile, remote_ip);
	sig_hour = is_novel_hour (profile, now_unix);
	sig_rate = rate_spike_take (profile, now_unix);

	if (!sig_port && !sig_dest && !sig_hour && !sig_rate)
		return;

	lines = g_ptr_array_new_with_free_func (g_free);

	if (sig_port) {
		gchar *known = brief_ports (profile);

		g_ptr_array_add (lines, g_strdup_printf (
			_("first use of port %u -- before this, the baseline "
			  "knew %s"),
			port, known));
		g_free (known);
	}
	if (sig_dest) {
		g_ptr_array_add (lines, g_strdup_printf (
			_("first contact with %s -- the baseline knew %u "
			  "destinations"),
			remote_ip,
			g_hash_table_size (profile->common_destinations) - 1));
	}
	if (sig_hour) {
		GDateTime *dt = g_date_time_new_from_unix_local (now_unix);
		gchar *hours = brief_hours (profile);
		gint hour = dt != NULL ? g_date_time_get_hour (dt) : 0;

		g_ptr_array_add (lines, g_strdup_printf (
			_("first activity at %02d:00 -- established hours: %s"),
			hour, hours));
		g_free (hours);
		if (dt != NULL)
			g_date_time_unref (dt);
	}
	if (sig_rate) {
		g_ptr_array_add (lines, g_strdup_printf (
			_("%u connections in the last 10 minutes -- the usual "
			  "rate is about %u per 10 minutes"),
			profile->rate_window_count,
			profile->rate_ema_milli / 1000));
	}

	n = lines->len;

	type = sig_port ? FS_INSIGHT_UNUSUAL_PORT
	     : sig_dest ? FS_INSIGHT_UNUSUAL_DESTINATION
	     : sig_rate ? FS_INSIGHT_UNUSUAL_VOLUME
	     :            FS_INSIGHT_UNUSUAL_TIME;
	severity = n > 1 ? FS_COPILOT_CRITICAL
	         : (type == FS_INSIGHT_UNUSUAL_TIME ? FS_COPILOT_INFO
	                                             : FS_COPILOT_WARNING);

	if (n > 1) {
		title = owned_title = g_strdup_printf (
			_("Multiple signals for %s"), app_name);
	} else if (sig_port) {
		title = _("Unusual port for application");
	} else if (sig_dest) {
		title = _("Unusual destination");
	} else if (sig_rate) {
		title = _("Unusual connection rate");
	} else {
		title = _("Activity at unusual time");
	}

	desc = g_string_new (NULL);
	g_string_append_printf (desc,
	                        _("%s deviates from its established "
	                          "baseline:"),
	                        app_name);
	for (i = 0; i < n; i++)
		g_string_append_printf (desc, "\n- %s",
		                        (const gchar *)
		                        g_ptr_array_index (lines, i));

	if (sig_dest && remote_ip != NULL && *remote_ip != '\0')
		dest_owned = g_strdup (remote_ip);
	else if (sig_port && remote_ip != NULL && *remote_ip != '\0')
		dest_owned = g_strdup_printf ("%s:%u", remote_ip, port);

	insight = create_insight (type, severity, title,
	                          g_string_free (desc, FALSE), app_name,
	                          dest_owned);

	if (n == 1 && port != 0 && remote_ip != NULL &&
	    *remote_ip != '\0' && (sig_port || sig_dest)) {
		if (sig_port)
			insight->suggested_rule = g_strdup_printf (
				_("Allow %s on port %u for %s"),
				app_name, port, remote_ip);
		else
			insight->suggested_rule = g_strdup_printf (
				_("Allow %s to connect to %s"),
				app_name, remote_ip);
		insight->rule_csv = g_strdup_printf ("%s, %u, %s, %s",
		                                     app_name, port,
		                                     remote_ip,
		                                     _("Auto-generated by Copilot"));
		/* P6: same two gates as Sentinel's own blocks -- an
		 * established baseline destination is never auto-staged. */
		insight->auto_applicable =
			sentinel_dest_auto_ok (copilot, app_name, remote_ip);
	}

	insight->timestamp = now_unix;
	emit_insight (copilot, insight);

	g_ptr_array_unref (lines);
	g_free (owned_title);
	g_free (dest_owned);
}

/* [ emit_insight ]
 * Every insight enters through here: the list is bounded (Chapter
 * 9).  The oldest falls off at the cap, so a scanning flood cannot
 * grow the list without end. */
static void
emit_insight (FsCopilot *copilot, FsInsight *insight)
{
	copilot->insights = g_list_prepend (copilot->insights, insight);

	while (g_list_length (copilot->insights) > FS_COPILOT_MAX_INSIGHTS) {
		GList *oldest = g_list_last (copilot->insights);

		fs_insight_free (oldest->data);
		copilot->insights = g_list_delete_link (copilot->insights,
		                                        oldest);
	}
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

		/* P6: the finding is always reported; the automatic block is
		 * withheld when the destination is protocol infrastructure
		 * (multicast, loopback, the LAN) or when the application's
		 * own baseline -- beyond this very run -- already knows it. */
		{
			gchar app_buf[256];

			hit_app_key (hit, app_buf, sizeof app_buf);
			insight->auto_applicable =
				sentinel_dest_auto_ok_before_run (
					copilot, app_buf, dst, stamps->len);
		}

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