/*---[ fs-dashboard.c ]--------------------------------------------------
 * `stockfw dashboard': a live, local, read-only web dashboard.
 *
 * A firewall tool that opens a listening socket has to be more careful
 * than the thing it is showing, so the server is deliberately small
 * and every request crosses the same checks:
 *
 *   - It binds 127.0.0.1 only.  There is no option to listen on another
 *     address: the dashboard shows connection lists and kernel-log
 *     events, which are not for the network.
 *   - Every /api/ call must carry the per-run token (128 bits from the
 *     kernel's CSPRNG) in an X-StockFW-Token header.  The token travels
 *     in the URL fragment, which the browser never sends; the page moves
 *     it into sessionStorage and strips it from the address bar.  A
 *     custom header cannot be sent cross-origin without a CORS
 *     preflight, which this server never answers, so another web page in
 *     the same browser cannot read the API or ride the token.
 *   - The Host header must be 127.0.0.1:<port> or localhost:<port>.  That
 *     closes DNS rebinding: a hostile name re-pointed at 127.0.0.1 still
 *     arrives with its own Host and is refused.
 *   - GET and HEAD only, a 16 KB cap on the request head, a 10 s socket
 *     timeout and at most 32 connections at once.
 *   - The API is read-only.  Changing the firewall stays with
 *     `stockfw apply' and the desktop app, where a human confirms it.
 *     The what-if simulator is a question, not a change.
 *   - The page is compiled into the binary and carries a strict
 *     Content-Security-Policy with a per-run nonce: no external script,
 *     style, font or image can load, so nothing leaves the machine.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "core/fs-activity.h"
#include "core/fs-apply.h"
#include "core/fs-copilot.h"
#include "core/fs-json.h"
#include "core/fs-netparse.h"
#include "core/fs-util.h"
#include "stockfw-logo-64.h"
#include "fs-dashboard-html.h"

#include <gio/gio.h>
#include <glib-unix.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define DASH_MAX_HEAD        16384
#define DASH_MAX_CONNECTIONS 32
#define DASH_RECENT_EVENTS   500
#define DASH_SAMPLE_MS       2000
#define DASH_HISTORY_LINES   20000

typedef struct
{
	GSocketService    *service;
	guint16            port;
	gchar              token[33];
	gchar              nonce[33];
	gchar             *host_ip;      /* "127.0.0.1:<port>" */
	gchar             *host_name;    /* "localhost:<port>" */
	gchar             *page;         /* the HTML with the nonce in it */
	gint64             started;

	FsActivity        *events;       /* allowed / blocked */
	FsActivity        *net;          /* rx / tx, per device */
	FsActivitySampler *sampler;
	GQueue            *recent;       /* FsHit*, newest first */
	guint64            session_events;
	gboolean           monitoring;
	gchar             *monitor_note; /* why not, or where from */
	gboolean           backfilled;

	GList             *stats_now;    /* FsIfaceStat*, last sample */
	GList             *stats_prev;
	gint64             stats_now_us;
	gint64             stats_prev_us;

	guint              open_connections;
	GMainLoop         *loop;
} Dash;

typedef struct
{
	Dash              *dash;
	GSocketConnection *connection;
	GString           *head;
	guint8             buffer[4096];
} Conn;

/* --------------------------------------------------------------- secrets */

/* [ random_hex ]
 * n bytes from the kernel's CSPRNG as 2n hex digits.  GLib's g_random
 * is a Mersenne Twister -- fine for jitter, wrong for a credential --
 * so refuse to start rather than fall back to it. */
static gboolean
random_hex (gchar *out, gsize n_bytes)
{
	guint8 bytes[32];
	FILE *fp;
	gsize got;

	g_return_val_if_fail (n_bytes <= sizeof (bytes), FALSE);

	fp = fopen ("/dev/urandom", "rb");
	if (fp == NULL)
		return FALSE;

	got = fread (bytes, 1, n_bytes, fp);
	fclose (fp);

	if (got != n_bytes)
		return FALSE;

	for (gsize i = 0; i < n_bytes; i++)
		g_snprintf (out + i * 2, 3, "%02x", bytes[i]);

	return TRUE;
}

/* [ token_equal ] -- constant-time comparison of a presented token. */
static gboolean
token_equal (const gchar *expected, const gchar *presented)
{
	gsize len = strlen (expected);
	guint8 diff = 0;

	if (presented == NULL || strlen (presented) != len)
		return FALSE;

	for (gsize i = 0; i < len; i++)
		diff |= (guint8) (expected[i] ^ presented[i]);

	return diff == 0;
}

/* --------------------------------------------------------------- the data */

static void
note_hit (Dash *dash, const FsHit *hit, gint64 when)
{
	gboolean blocked = fs_hit_is_blocked (hit);

	fs_activity_add_at (dash->events,
	                    blocked ? FS_ACTIVITY_BLOCKED : FS_ACTIVITY_ALLOWED,
	                    when, 1);
}

static void
remember_hit (Dash *dash, const FsHit *hit)
{
	g_queue_push_head (dash->recent, fs_hit_copy (hit));

	while (g_queue_get_length (dash->recent) > DASH_RECENT_EVENTS)
		fs_hit_free (g_queue_pop_tail (dash->recent));
}

static void
on_live_hit (const FsHit *hit, gpointer data)
{
	Dash *dash = data;

	dash->session_events++;
	note_hit (dash, hit, fs_activity_now (dash->events));
	remember_hit (dash, hit);
}

static gboolean
on_sample (gpointer data)
{
	Dash *dash = data;
	const FsBackend *backend = fs_backend ();
	GList *stats;

	if (backend->list_interface_stats == NULL)
		return G_SOURCE_CONTINUE;

	stats = backend->list_interface_stats ();
	fs_activity_sampler_feed (dash->sampler, stats);

	g_list_free_full (dash->stats_prev, (GDestroyNotify) fs_iface_stat_free);
	dash->stats_prev    = dash->stats_now;
	dash->stats_prev_us = dash->stats_now_us;
	dash->stats_now     = stats;
	dash->stats_now_us  = g_get_monotonic_time ();

	return G_SOURCE_CONTINUE;
}

/* [ load_events ]
 * Backfill the Policy activity series from the kernel log -- the log is
 * the archive -- then follow it live.  Coverage starts at the first
 * stamped line read, because from there on the record is complete. */
static void
load_events (Dash *dash)
{
	const FsBackend *backend = fs_backend ();
	GError *error = NULL;
	gint64 complete_from = 0;
	GPtrArray *history;

	history = fs_cli_log_history (DASH_HISTORY_LINES, &complete_from,
	                              &error);

	if (history != NULL && complete_from > 0) {
		dash->events = fs_activity_new_at (NULL, NULL, complete_from);
		dash->backfilled = TRUE;

		for (guint i = 0; i < history->len; i++) {
			const FsHit *hit = g_ptr_array_index (history, i);
			GDateTime *when = g_date_time_new_from_iso8601 (hit->time,
			                                                NULL);

			if (when != NULL) {
				note_hit (dash, hit, g_date_time_to_unix (when));
				g_date_time_unref (when);
			}
			remember_hit (dash, hit);
		}
	} else {
		dash->events = fs_activity_new (NULL, NULL);
	}

	if (history != NULL)
		g_ptr_array_unref (history);
	g_clear_error (&error);

	if (backend->log_start != NULL &&
	    backend->log_start (on_live_hit, dash, &error)) {
		dash->monitoring = TRUE;
		dash->monitor_note = g_strdup (dash->backfilled
			? "Live, with history from the kernel log"
			: "Live since the dashboard started");
	} else {
		dash->monitoring = FALSE;
		dash->monitor_note = g_strdup (error != NULL ? error->message
		                               : "This backend has no event source.");
	}

	g_clear_error (&error);
}

/* ------------------------------------------------------------ the API */

static gchar *
policy_json (void)
{
	gboolean on_disk;
	gint malformed;
	FsPolicy *policy = fs_cli_load_policy (&on_disk, &malformed);
	GString *out = g_string_new ("{");
	gboolean first = TRUE;

	fs_json_kv_str (out, "rules_dir", fs_util_rules_dir ()); g_string_append_c (out, ',');
	fs_json_kv_bool (out, "saved", on_disk);                 g_string_append_c (out, ',');
	fs_json_kv_int (out, "malformed", malformed);            g_string_append_c (out, ',');
	fs_json_kv_str (out, "hold", fs_apply_hold_reason ());
	g_string_append (out, ",\"rules\":[");

	for (gint k = 0; k < FS_RULE_N_KINDS; k++) {
		GPtrArray *rules = policy->kinds[k];

		for (guint i = 0; i < rules->len; i++) {
			FsRule *r = g_ptr_array_index (rules, i);
			gchar *summary = fs_cli_rule_summary (r);

			if (!first)
				g_string_append_c (out, ',');
			first = FALSE;

			g_string_append_c (out, '{');
			fs_json_kv_str (out, "kind", fs_cli_kind_name (r->kind)); g_string_append_c (out, ',');
			fs_json_kv_uint (out, "number", i + 1);              g_string_append_c (out, ',');
			fs_json_kv_str (out, "summary", summary);            g_string_append_c (out, ',');
			fs_json_kv_str (out, "comment", r->comment);
			g_string_append_c (out, '}');
			g_free (summary);
		}
	}

	g_string_append (out, "]}");
	fs_policy_free (policy);

	return g_string_free (out, FALSE);
}

static void
rates_for (Dash *dash, const gchar *device, gdouble *rx, gdouble *tx)
{
	gdouble seconds;

	*rx = *tx = 0;

	if (dash->stats_prev == NULL || dash->stats_now_us <= dash->stats_prev_us)
		return;

	seconds = (gdouble) (dash->stats_now_us - dash->stats_prev_us) /
	          G_USEC_PER_SEC;

	for (GList *l = dash->stats_now; l != NULL; l = l->next) {
		FsIfaceStat *s = l->data;

		if (device != NULL && g_strcmp0 (s->device, device) != 0)
			continue;

		for (GList *p = dash->stats_prev; p != NULL; p = p->next) {
			FsIfaceStat *o = p->data;

			if (g_strcmp0 (o->device, s->device) == 0 &&
			    s->received >= o->received && s->sent >= o->sent) {
				*rx += (gdouble) (s->received - o->received) / seconds;
				*tx += (gdouble) (s->sent - o->sent) / seconds;
			}
		}
	}
}

/* [ is_loopback ] -- 127.0.0.0/8 or ::1 */
static gboolean
is_loopback (const gchar *addr)
{
	return addr != NULL &&
	       (g_str_has_prefix (addr, "127.") || strcmp (addr, "::1") == 0);
}

/* [ own_connections_drop ]
 * The dashboard's own sockets -- this server's accepted connections
 * and the browser's side of them -- are loopback connections on our
 * port.  They are real, but they exist only because someone is
 * looking, so they are left out of what the dashboard reports. */
static GList *
own_connections_drop (Dash *dash, GList *conns)
{
	gchar *ours = g_strdup_printf ("%u", dash->port);
	GList *l = conns;

	while (l != NULL) {
		GList *next = l->next;
		FsConnection *c = l->data;

		if (g_strcmp0 (c->port, ours) == 0 &&
		    is_loopback (c->source) && is_loopback (c->destination)) {
			fs_connection_free (c);
			conns = g_list_delete_link (conns, l);
		}
		l = next;
	}

	g_free (ours);
	return conns;
}

static gchar *
summary_json (Dash *dash)
{
	const FsBackend *backend = fs_backend ();
	gboolean root = (geteuid () == 0);
	FsFirewallState state = root ? backend->get_state () : FS_FW_NONE;
	GList *conns = own_connections_drop (dash,
	                   backend->list_connections != NULL
	                   ? backend->list_connections () : NULL);
	gboolean on_disk;
	FsPolicy *policy = fs_cli_load_policy (&on_disk, NULL);
	guint rules = 0;
	gdouble rx, tx;
	GString *out = g_string_new ("{");
	const gchar *state_word;

	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		rules += fs_policy_count (policy, (FsRuleKind) k);

	switch (state) {
	case FS_FW_RUNNING: state_word = "running"; break;
	case FS_FW_STOPPED: state_word = "stopped"; break;
	case FS_FW_LOCKED:  state_word = "locked";  break;
	default:            state_word = "unknown"; break;
	}

	rates_for (dash, NULL, &rx, &tx);

	fs_json_kv_str (out, "version", FS_VERSION);                g_string_append_c (out, ',');
	fs_json_kv_str (out, "backend", backend->name);            g_string_append_c (out, ',');
	fs_json_kv_str (out, "backend_name", backend->display_name); g_string_append_c (out, ',');
	fs_json_kv_str (out, "host", g_get_host_name ());          g_string_append_c (out, ',');
	fs_json_kv_str (out, "state", state_word);                 g_string_append_c (out, ',');
	fs_json_kv_bool (out, "root", root);                       g_string_append_c (out, ',');
	fs_json_kv_uint (out, "rules", rules);                     g_string_append_c (out, ',');
	fs_json_kv_bool (out, "policy_saved", on_disk);            g_string_append_c (out, ',');
	fs_json_kv_str (out, "rules_dir", fs_util_rules_dir ());   g_string_append_c (out, ',');
	fs_json_kv_str (out, "hold", fs_apply_hold_reason ());     g_string_append_c (out, ',');
	fs_json_kv_bool (out, "monitoring", dash->monitoring);     g_string_append_c (out, ',');
	fs_json_kv_str (out, "monitor_note", dash->monitor_note);  g_string_append_c (out, ',');
	fs_json_kv_bool (out, "logs_allowed",
	                 g_strcmp0 (backend->name, "linux") != 0);
	g_string_append_c (out, ',');
	fs_json_kv_uint (out, "blocked_1h",
	                 fs_activity_total (dash->events, FS_ACTIVITY_BLOCKED, 3600));
	g_string_append_c (out, ',');
	fs_json_kv_uint (out, "allowed_1h",
	                 fs_activity_total (dash->events, FS_ACTIVITY_ALLOWED, 3600));
	g_string_append_c (out, ',');
	fs_json_kv_uint (out, "blocked_24h",
	                 fs_activity_total (dash->events, FS_ACTIVITY_BLOCKED,
	                                    FS_ACTIVITY_SPAN_S));
	g_string_append_c (out, ',');
	fs_json_kv_int (out, "events_since", fs_activity_started (dash->events));
	g_string_append_c (out, ',');
	g_string_append_printf (out, "\"rx_per_s\":%.0f,\"tx_per_s\":%.0f,", rx, tx);
	fs_json_kv_uint (out, "connections", g_list_length (conns)); g_string_append_c (out, ',');
	fs_json_kv_int (out, "started", dash->started);            g_string_append_c (out, ',');
	fs_json_kv_int (out, "now", g_get_real_time () / G_USEC_PER_SEC);
	g_string_append_c (out, '}');

	g_list_free_full (conns, (GDestroyNotify) fs_connection_free);
	fs_policy_free (policy);

	return g_string_free (out, FALSE);
}

static void
series_json (GString *out, FsActivity *activity, const gchar *series,
             guint step, guint n)
{
	guint64 *values = g_new0 (guint64, n);

	fs_activity_window (activity, series, step, n, values, NULL, NULL);

	g_string_append_c (out, '[');
	for (guint i = 0; i < n; i++)
		g_string_append_printf (out, "%s%" G_GUINT64_FORMAT,
		                        i ? "," : "", values[i]);
	g_string_append_c (out, ']');

	g_free (values);
}

static void
covered_json (GString *out, FsActivity *activity, guint step, guint n)
{
	guint *covered = g_new0 (guint, n);

	fs_activity_window (activity, NULL, step, n, NULL, covered, NULL);

	g_string_append_c (out, '[');
	for (guint i = 0; i < n; i++)
		g_string_append_printf (out, "%s%u", i ? "," : "", covered[i]);
	g_string_append_c (out, ']');

	g_free (covered);
}

static gchar *
activity_json (Dash *dash, GHashTable *params)
{
	const gchar *range_s = params ? g_hash_table_lookup (params, "range") : NULL;
	const gchar *device  = params ? g_hash_table_lookup (params, "device") : NULL;
	guint range = range_s != NULL ? (guint) g_ascii_strtoull (range_s, NULL, 10)
	                              : 3600;
	guint step, n;
	gint64 start;
	GString *out = g_string_new ("{");
	gchar *rx = NULL, *tx = NULL;
	GList *names;

	if (range < 600)
		range = 600;
	if (range > FS_ACTIVITY_SPAN_S)
		range = FS_ACTIVITY_SPAN_S;

	step = fs_activity_step_for (range, 120);
	n = (range + step - 1) / step;

	fs_activity_window (dash->events, NULL, step, n, NULL, NULL, &start);

	if (device != NULL && *device != '\0') {
		rx = fs_activity_device_series (device, FALSE);
		tx = fs_activity_device_series (device, TRUE);
	}

	fs_json_kv_uint (out, "range", range);  g_string_append_c (out, ',');
	fs_json_kv_uint (out, "step", step);    g_string_append_c (out, ',');
	fs_json_kv_uint (out, "points", n);     g_string_append_c (out, ',');
	fs_json_kv_int (out, "start", start);   g_string_append_c (out, ',');
	fs_json_kv_str (out, "device", rx != NULL ? device : NULL);
	g_string_append (out, ",\"events\":{\"allowed\":");
	series_json (out, dash->events, FS_ACTIVITY_ALLOWED, step, n);
	g_string_append (out, ",\"blocked\":");
	series_json (out, dash->events, FS_ACTIVITY_BLOCKED, step, n);
	g_string_append (out, ",\"covered\":");
	if (dash->monitoring || dash->backfilled)
		covered_json (out, dash->events, step, n);
	else
		g_string_append (out, "null");
	g_string_append (out, "},\"net\":{\"rx\":");
	series_json (out, dash->net, rx ? rx : FS_ACTIVITY_NET_RX, step, n);
	g_string_append (out, ",\"tx\":");
	series_json (out, dash->net, tx ? tx : FS_ACTIVITY_NET_TX, step, n);
	g_string_append (out, ",\"covered\":");
	covered_json (out, dash->net, step, n);
	g_string_append (out, "},\"devices\":[");

	names = fs_activity_series_names (dash->net);
	{
		gboolean first = TRUE;

		for (GList *l = names; l != NULL; l = l->next) {
			const gchar *name = l->data;
			gsize len = strlen (name);

			/* "net.<device>.rx" -> <device>; skip the totals. */
			if (!g_str_has_prefix (name, "net.") ||
			    !g_str_has_suffix (name, ".rx") || len <= 7)
				continue;

			{
				gchar *dev = g_strndup (name + 4, len - 7);

				if (!first)
					g_string_append_c (out, ',');
				first = FALSE;
				fs_json_string (out, dev);
				g_free (dev);
			}
		}
	}
	g_list_free (names);
	g_string_append (out, "]}");

	g_free (rx);
	g_free (tx);

	return g_string_free (out, FALSE);
}

static gchar *
events_json (Dash *dash, GHashTable *params)
{
	const gchar *limit_s = params ? g_hash_table_lookup (params, "limit") : NULL;
	guint limit = limit_s != NULL ? (guint) g_ascii_strtoull (limit_s, NULL, 10)
	                              : 200;
	GString *out = g_string_new ("[");
	guint i = 0;

	if (limit == 0 || limit > DASH_RECENT_EVENTS)
		limit = DASH_RECENT_EVENTS;

	for (GList *l = dash->recent->head; l != NULL && i < limit; l = l->next, i++) {
		const FsHit *hit = l->data;
		gchar *service = fs_hit_service_name (hit);

		if (i > 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "time", hit->time);             g_string_append_c (out, ',');
		fs_json_kv_str (out, "direction", hit->direction);   g_string_append_c (out, ',');
		fs_json_kv_str (out, "source", hit->source);         g_string_append_c (out, ',');
		fs_json_kv_str (out, "destination", hit->destination); g_string_append_c (out, ',');
		fs_json_kv_str (out, "port", hit->port);             g_string_append_c (out, ',');
		fs_json_kv_str (out, "protocol", hit->protocol);     g_string_append_c (out, ',');
		fs_json_kv_str (out, "service", service);            g_string_append_c (out, ',');
		fs_json_kv_bool (out, "blocked", fs_hit_is_blocked (hit));
		g_string_append_c (out, '}');
		g_free (service);
	}

	g_string_append_c (out, ']');
	return g_string_free (out, FALSE);
}

static gchar *
connections_json (Dash *dash)
{
	const FsBackend *backend = fs_backend ();
	GList *conns = own_connections_drop (dash,
	                   backend->list_connections != NULL
	                   ? backend->list_connections () : NULL);
	GString *out = g_string_new ("[");

	for (GList *l = conns; l != NULL; l = l->next) {
		FsConnection *c = l->data;

		if (l != conns)
			g_string_append_c (out, ',');
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "local", c->source);          g_string_append_c (out, ',');
		fs_json_kv_str (out, "remote", c->destination);    g_string_append_c (out, ',');
		fs_json_kv_str (out, "port", c->port);             g_string_append_c (out, ',');
		fs_json_kv_str (out, "service", c->service);       g_string_append_c (out, ',');
		fs_json_kv_str (out, "program", c->program);       g_string_append_c (out, ',');
		fs_json_kv_str (out, "direction", c->direction);
		g_string_append_c (out, '}');
	}

	g_string_append_c (out, ']');
	g_list_free_full (conns, (GDestroyNotify) fs_connection_free);

	return g_string_free (out, FALSE);
}

static gchar *
interfaces_json (Dash *dash)
{
	GString *out = g_string_new ("[");

	for (GList *l = dash->stats_now; l != NULL; l = l->next) {
		FsIfaceStat *s = l->data;
		gdouble rx, tx;

		rates_for (dash, s->device, &rx, &tx);

		if (l != dash->stats_now)
			g_string_append_c (out, ',');
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "device", s->device);       g_string_append_c (out, ',');
		fs_json_kv_str (out, "type", s->kind);           g_string_append_c (out, ',');
		fs_json_kv_str (out, "ip", s->ip);               g_string_append_c (out, ',');
		fs_json_kv_bool (out, "up", s->up);              g_string_append_c (out, ',');
		fs_json_kv_uint (out, "received", s->received);  g_string_append_c (out, ',');
		fs_json_kv_uint (out, "sent", s->sent);          g_string_append_c (out, ',');
		g_string_append_printf (out, "\"rx_per_s\":%.0f,\"tx_per_s\":%.0f", rx, tx);
		g_string_append_c (out, '}');
	}

	g_string_append_c (out, ']');
	return g_string_free (out, FALSE);
}

static gchar *
simulate_json (GHashTable *params, guint *status)
{
	const gchar *q = params ? g_hash_table_lookup (params, "q") : NULL;
	FsPolicy *policy;
	FsCopilot *copilot;
	FsScenario *scenario = NULL;
	FsSimulationResult *result;
	GString *out;
	gchar *suggest;

	if (q == NULL || *q == '\0' || strlen (q) > 300) {
		*status = 400;
		return g_strdup ("{\"error\":\"Describe the traffic in up to 300 "
		                 "characters.\"}");
	}

	policy = fs_cli_load_policy (NULL, NULL);
	copilot = fs_copilot_new ();
	fs_copilot_set_policy (copilot, policy);
	result = fs_copilot_simulate_text (copilot, q, &scenario);

	if (result == NULL) {
		fs_copilot_free (copilot);
		fs_policy_free (policy);
		*status = 400;
		return g_strdup ("{\"error\":\"Nothing to simulate.\"}");
	}

	suggest = result->would_block ? fs_copilot_allow_suggestion (scenario)
	                              : NULL;
	out = g_string_new ("{");
	fs_json_kv_str (out, "input", q);                          g_string_append_c (out, ',');
	fs_json_kv_str (out, "verdict", result->would_block ? "BLOCKED" : "ALLOWED");
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "scenario", result->scenario);       g_string_append_c (out, ',');
	fs_json_kv_str (out, "direction", scenario->inbound ? "inbound" : "outbound");
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "protocol", scenario->protocol);     g_string_append_c (out, ',');
	if (scenario->had_port)
		fs_json_kv_uint (out, "port", scenario->port);
	else
		fs_json_kv_str (out, "port", NULL);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "remote", scenario->remote_ip);      g_string_append_c (out, ',');
	fs_json_kv_str (out, "rule", result->matching_rule);      g_string_append_c (out, ',');
	fs_json_kv_str (out, "reason", result->reason);           g_string_append_c (out, ',');
	fs_json_kv_str (out, "suggestion", suggest);
	g_string_append_c (out, '}');

	g_free (suggest);
	fs_simulation_result_free (result);
	fs_scenario_free (scenario);
	fs_copilot_free (copilot);
	fs_policy_free (policy);

	*status = 200;
	return g_string_free (out, FALSE);
}

/* ---------------------------------------------------------------- HTTP */

static const gchar *
status_text (guint status)
{
	switch (status) {
	case 200: return "OK";
	case 204: return "No Content";
	case 400: return "Bad Request";
	case 401: return "Unauthorized";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 405: return "Method Not Allowed";
	case 431: return "Request Header Fields Too Large";
	case 503: return "Service Unavailable";
	default:  return "Error";
	}
}

static void
on_written (GObject *source, GAsyncResult *result, gpointer data)
{
	Conn *conn = data;

	g_output_stream_write_all_finish (G_OUTPUT_STREAM (source), result,
	                                  NULL, NULL);
	g_io_stream_close (G_IO_STREAM (conn->connection), NULL, NULL);

	conn->dash->open_connections--;
	g_object_unref (conn->connection);
	g_string_free (conn->head, TRUE);
	g_free (conn);
}

/* [ respond ] -- write one complete response and close. */
static void
respond (Conn *conn, guint status, const gchar *type, const guint8 *body,
         gsize body_len, gboolean head_only)
{
	Dash *dash = conn->dash;
	GString *out = g_string_new (NULL);
	GOutputStream *stream;
	GBytes *bytes;
	gsize size;
	gpointer data;

	g_string_append_printf (out,
		"HTTP/1.1 %u %s\r\n"
		"Content-Type: %s\r\n"
		"Content-Length: %" G_GSIZE_FORMAT "\r\n"
		"Cache-Control: no-store\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"X-Frame-Options: DENY\r\n"
		"Referrer-Policy: no-referrer\r\n"
		"Cross-Origin-Opener-Policy: same-origin\r\n"
		"Cross-Origin-Resource-Policy: same-origin\r\n"
		"Content-Security-Policy: default-src 'none'; "
		"script-src 'nonce-%s'; style-src 'nonce-%s'; "
		"connect-src 'self'; img-src 'self'; base-uri 'none'; "
		"form-action 'none'; frame-ancestors 'none'\r\n"
		"Connection: close\r\n\r\n",
		status, status_text (status), type, body_len,
		dash->nonce, dash->nonce);

	if (!head_only && body != NULL)
		g_string_append_len (out, (const gchar *) body, (gssize) body_len);

	size  = out->len;
	data  = g_string_free (out, FALSE);
	bytes = g_bytes_new_take (data, size);

	stream = g_io_stream_get_output_stream (G_IO_STREAM (conn->connection));

	/* write_all_async does not copy: the GBytes stays alive in the
	 * closure until the write has finished. */
	g_object_set_data_full (G_OBJECT (conn->connection), "fs-response",
	                        bytes, (GDestroyNotify) g_bytes_unref);
	g_output_stream_write_all_async (stream, g_bytes_get_data (bytes, NULL),
	                                 size, G_PRIORITY_DEFAULT, NULL,
	                                 on_written, conn);
}

static void
respond_json (Conn *conn, guint status, gchar *json, gboolean head_only)
{
	respond (conn, status, "application/json; charset=utf-8",
	         (const guint8 *) json, strlen (json), head_only);
	g_free (json);
}

static void
respond_error (Conn *conn, guint status, const gchar *message)
{
	GString *out = g_string_new ("{");

	fs_json_kv_str (out, "error", message);
	g_string_append_c (out, '}');
	respond_json (conn, status, g_string_free (out, FALSE), FALSE);
}

/* [ header_value ] -- a request header, case-insensitively; NULL if absent. */
static gchar *
header_value (gchar **lines, const gchar *name)
{
	gsize n = strlen (name);

	for (guint i = 1; lines[i] != NULL; i++) {
		if (g_ascii_strncasecmp (lines[i], name, n) == 0 &&
		    lines[i][n] == ':') {
			gchar *value = g_strdup (lines[i] + n + 1);

			return g_strstrip (value);
		}
	}

	return NULL;
}

static void
handle_request (Conn *conn)
{
	Dash *dash = conn->dash;
	gchar **lines, **parts;
	gchar *host, *token, *path, *query;
	GHashTable *params = NULL;
	gboolean head_only;

	lines = g_strsplit (conn->head->str, "\r\n", -1);
	parts = g_strsplit (lines[0], " ", 3);

	if (g_strv_length (parts) != 3 || !g_str_has_prefix (parts[2], "HTTP/1.")) {
		respond_error (conn, 400, "Malformed request line.");
		goto out;
	}

	if (strcmp (parts[0], "GET") != 0 && strcmp (parts[0], "HEAD") != 0) {
		respond_error (conn, 405, "Read-only: GET and HEAD only.");
		goto out;
	}
	head_only = strcmp (parts[0], "HEAD") == 0;

	/* DNS rebinding: only our own two spellings of ourselves. */
	host = header_value (lines, "Host");
	if (host == NULL || (g_ascii_strcasecmp (host, dash->host_ip) != 0 &&
	                     g_ascii_strcasecmp (host, dash->host_name) != 0)) {
		g_free (host);
		respond_error (conn, 403, "Unexpected Host header.");
		goto out;
	}
	g_free (host);

	path  = parts[1];
	query = strchr (path, '?');
	if (query != NULL) {
		*query++ = '\0';
		params = g_uri_parse_params (query, -1, "&",
		                             G_URI_PARAMS_WWW_FORM, NULL);
	}

	if (strcmp (path, "/") == 0 || strcmp (path, "/index.html") == 0) {
		respond (conn, 200, "text/html; charset=utf-8",
		         (const guint8 *) dash->page, strlen (dash->page),
		         head_only);
		goto out_params;
	}

	if (strcmp (path, "/logo.png") == 0) {
		respond (conn, 200, "image/png", stockfw_logo_64_png,
		         stockfw_logo_64_png_len, head_only);
		goto out_params;
	}

	if (!g_str_has_prefix (path, "/api/")) {
		respond_error (conn, 404, "Not found.");
		goto out_params;
	}

	token = header_value (lines, "X-StockFW-Token");
	if (!token_equal (dash->token, token)) {
		g_free (token);
		respond_error (conn, 401, "This dashboard link is not valid for "
		               "the running `stockfw dashboard'. Open the URL it "
		               "printed when it started.");
		goto out_params;
	}
	g_free (token);

	if (strcmp (path, "/api/summary") == 0) {
		respond_json (conn, 200, summary_json (dash), head_only);
	} else if (strcmp (path, "/api/activity") == 0) {
		respond_json (conn, 200, activity_json (dash, params), head_only);
	} else if (strcmp (path, "/api/events") == 0) {
		respond_json (conn, 200, events_json (dash, params), head_only);
	} else if (strcmp (path, "/api/connections") == 0) {
		respond_json (conn, 200, connections_json (conn->dash), head_only);
	} else if (strcmp (path, "/api/interfaces") == 0) {
		respond_json (conn, 200, interfaces_json (dash), head_only);
	} else if (strcmp (path, "/api/policy") == 0) {
		respond_json (conn, 200, policy_json (), head_only);
	} else if (strcmp (path, "/api/simulate") == 0) {
		guint status = 200;
		gchar *json = simulate_json (params, &status);

		respond_json (conn, status, json, head_only);
	} else {
		respond_error (conn, 404, "No such API endpoint.");
	}

out_params:
	if (params != NULL)
		g_hash_table_unref (params);
out:
	g_strfreev (parts);
	g_strfreev (lines);
}

static void on_read (GObject *source, GAsyncResult *result, gpointer data);

static void
read_more (Conn *conn)
{
	GInputStream *in = g_io_stream_get_input_stream (
		G_IO_STREAM (conn->connection));

	g_input_stream_read_async (in, conn->buffer, sizeof (conn->buffer),
	                           G_PRIORITY_DEFAULT, NULL, on_read, conn);
}

static void
drop_connection (Conn *conn)
{
	g_io_stream_close (G_IO_STREAM (conn->connection), NULL, NULL);
	conn->dash->open_connections--;
	g_object_unref (conn->connection);
	g_string_free (conn->head, TRUE);
	g_free (conn);
}

static void
on_read (GObject *source, GAsyncResult *result, gpointer data)
{
	Conn *conn = data;
	gssize got = g_input_stream_read_finish (G_INPUT_STREAM (source),
	                                         result, NULL);
	gchar *end;

	if (got <= 0) {
		drop_connection (conn);
		return;
	}

	g_string_append_len (conn->head, (const gchar *) conn->buffer, got);

	end = strstr (conn->head->str, "\r\n\r\n");

	/* The cap holds however the bytes were split across reads: a
	 * head that ends inside the read that crossed the limit is still
	 * too large. */
	if ((end != NULL ? (gsize) (end - conn->head->str) : conn->head->len)
	    > DASH_MAX_HEAD) {
		respond_error (conn, 431, "Request head too large.");
		return;
	}

	if (end != NULL) {
		/* A GET has no body; whatever follows the head is ignored. */
		g_string_truncate (conn->head, (gsize) (end - conn->head->str));
		handle_request (conn);
		return;
	}

	read_more (conn);
}

static gboolean
on_incoming (GSocketService *service, GSocketConnection *connection,
             GObject *source, gpointer data)
{
	Dash *dash = data;
	GSocket *socket = g_socket_connection_get_socket (connection);
	Conn *conn;

	if (dash->open_connections >= DASH_MAX_CONNECTIONS) {
		g_io_stream_close (G_IO_STREAM (connection), NULL, NULL);
		return TRUE;
	}

	g_socket_set_timeout (socket, 10);

	conn = g_new0 (Conn, 1);
	conn->dash = dash;
	conn->connection = g_object_ref (connection);
	conn->head = g_string_sized_new (1024);
	dash->open_connections++;

	read_more (conn);
	return TRUE;
}

/* ------------------------------------------------------------- startup */

static gboolean
on_quit_signal (gpointer data)
{
	g_main_loop_quit (((Dash *) data)->loop);
	return G_SOURCE_REMOVE;
}

/* [ open_browser ]
 * xdg-open for the invoking user.  Never as root: a browser running as
 * root is a far bigger attack surface than anything it would show, so
 * under sudo the URL is printed and opening it is left to the user. */
static gboolean
open_browser (const gchar *url)
{
	gchar *argv[] = { (gchar *) "xdg-open", (gchar *) url, NULL };

	if (geteuid () == 0)
		return FALSE;
	if (g_getenv ("DISPLAY") == NULL && g_getenv ("WAYLAND_DISPLAY") == NULL)
		return FALSE;

	return g_spawn_async (NULL, argv, NULL,
	                      G_SPAWN_SEARCH_PATH |
	                      G_SPAWN_STDOUT_TO_DEV_NULL |
	                      G_SPAWN_STDERR_TO_DEV_NULL,
	                      NULL, NULL, NULL, NULL);
}

gint
fs_cli_cmd_dashboard (gint argc, gchar **argv)
{
	Dash dash = { 0 };
	guint16 want_port = 0;
	gboolean no_open = FALSE;
	GInetAddress *loopback;
	GSocketAddress *address, *bound = NULL;
	GError *error = NULL;
	gchar *url;
	guint sample_id;

	for (gint i = 1; i < argc; i++) {
		if ((strcmp (argv[i], "--port") == 0 || strcmp (argv[i], "-p") == 0)
		    && i + 1 < argc) {
			gchar *end = NULL;
			guint64 p = g_ascii_strtoull (argv[++i], &end, 10);

			if (end == NULL || *end != '\0' || p == 0 || p > 65535) {
				fs_cli_error ("--port wants a number from 1 to 65535");
				return FS_EXIT_USAGE;
			}
			want_port = (guint16) p;
		} else if (strcmp (argv[i], "--no-open") == 0) {
			no_open = TRUE;
		} else {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			fs_cli_hint ("there is deliberately no --bind: the dashboard "
			             "only ever listens on 127.0.0.1");
			return FS_EXIT_USAGE;
		}
	}

	if (!random_hex (dash.token, 16) || !random_hex (dash.nonce, 16)) {
		fs_cli_error ("cannot read /dev/urandom for the access token");
		return FS_EXIT_FAILURE;
	}

	dash.service = g_socket_service_new ();
	loopback = g_inet_address_new_loopback (G_SOCKET_FAMILY_IPV4);
	address = g_inet_socket_address_new (loopback, want_port);
	g_object_unref (loopback);

	if (!g_socket_listener_add_address (G_SOCKET_LISTENER (dash.service),
	                                    address, G_SOCKET_TYPE_STREAM,
	                                    G_SOCKET_PROTOCOL_TCP, NULL,
	                                    &bound, &error)) {
		fs_cli_error ("cannot listen on 127.0.0.1:%u: %s", want_port,
		              error->message);
		if (want_port != 0)
			fs_cli_hint ("leave out --port to let the system pick a "
			             "free one");
		g_error_free (error);
		g_object_unref (address);
		g_object_unref (dash.service);
		return FS_EXIT_FAILURE;
	}
	g_object_unref (address);

	dash.port = g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (bound));
	g_object_unref (bound);

	dash.host_ip   = g_strdup_printf ("127.0.0.1:%u", dash.port);
	dash.host_name = g_strdup_printf ("localhost:%u", dash.port);
	dash.started   = g_get_real_time () / G_USEC_PER_SEC;

	/* The page's inline style and script carry this run's nonce;
	 * nothing else is allowed to execute or style it. */
	{
		gchar **pieces = g_strsplit (fs_dashboard_html, "{{NONCE}}", -1);

		dash.page = g_strjoinv (dash.nonce, pieces);
		g_strfreev (pieces);
	}

	dash.recent  = g_queue_new ();
	dash.net     = fs_activity_new (NULL, NULL);
	dash.sampler = fs_activity_sampler_new (dash.net);

	load_events (&dash);
	on_sample (&dash);
	sample_id = g_timeout_add (DASH_SAMPLE_MS, on_sample, &dash);

	g_signal_connect (dash.service, "incoming", G_CALLBACK (on_incoming), &dash);
	g_socket_service_start (dash.service);

	url = g_strdup_printf ("http://127.0.0.1:%u/#token=%s", dash.port,
	                       dash.token);

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "url", url);           g_string_append_c (out, ',');
		fs_json_kv_uint (out, "port", dash.port);   g_string_append_c (out, ',');
		fs_json_kv_bool (out, "monitoring", dash.monitoring);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		printf ("%sStockFW dashboard%s  %s\n\n", fs_cli_bold (),
		        fs_cli_reset (), url);
		printf ("  %-11s 127.0.0.1:%u only, read-only, this run's token\n",
		        "Listening", dash.port);
		printf ("  %-11s %s\n", "Events",
		        dash.monitor_note != NULL ? dash.monitor_note : "-");
		if (!dash.monitoring && geteuid () != 0)
			printf ("  %-11s %srun `sudo stockfw dashboard' for live "
			        "events%s\n", "", fs_cli_dim (), fs_cli_reset ());
	}

	if (!no_open && !open_browser (url) && !fs_cli.json) {
		if (geteuid () == 0)
			printf ("\n  Open the URL above in your browser (it is not "
			        "started as root).\n");
		else
			printf ("\n  Open the URL above in your browser.\n");
	}

	if (!fs_cli.json)
		printf ("%s\n  Ctrl-C stops the dashboard.%s\n", fs_cli_dim (),
		        fs_cli_reset ());
	fflush (stdout);

	dash.loop = g_main_loop_new (NULL, FALSE);
	g_unix_signal_add (SIGINT, on_quit_signal, &dash);
	g_unix_signal_add (SIGTERM, on_quit_signal, &dash);
	g_main_loop_run (dash.loop);

	/* Teardown, in the order things were started. */
	g_socket_service_stop (dash.service);
	g_socket_listener_close (G_SOCKET_LISTENER (dash.service));
	g_source_remove (sample_id);
	if (dash.monitoring && fs_backend ()->log_stop != NULL)
		fs_backend ()->log_stop ();

	g_main_loop_unref (dash.loop);
	g_object_unref (dash.service);
	g_queue_free_full (dash.recent, (GDestroyNotify) fs_hit_free);
	g_list_free_full (dash.stats_now, (GDestroyNotify) fs_iface_stat_free);
	g_list_free_full (dash.stats_prev, (GDestroyNotify) fs_iface_stat_free);
	fs_activity_sampler_free (dash.sampler);
	fs_activity_free (dash.net);
	fs_activity_free (dash.events);
	g_free (dash.monitor_note);
	g_free (dash.page);
	g_free (dash.host_ip);
	g_free (dash.host_name);
	g_free (url);

	if (!fs_cli.json && !fs_cli.quiet)
		printf ("\nDashboard stopped.\n");

	return FS_EXIT_OK;
}
