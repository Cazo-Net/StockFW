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
 *   - Every /api/ call needs a session key (256 bits) in an
 *     X-StockFW-Session header.  The browser gets the key for a launch
 *     code (128 bits, one use, 120 s) with POST /api/session; the code
 *     travels only in the URL fragment, which the browser never sends,
 *     and in a 0600 launch file.  The link with the code is printed
 *     only when stdout is a terminal; otherwise the path of the launch
 *     file is.  `stockfw dashboard link' gets a new code.  A custom
 *     header cannot be sent cross-origin without a CORS preflight,
 *     which this server never answers, and POST needs a same-origin
 *     Origin, Sec-Fetch-* and a JSON body.  That part is
 *     fs-dash-auth.c (15.3.2).
 *   - The Host header must be exactly 127.0.0.1:<port>.  That closes
 *     DNS rebinding: a hostile name re-pointed at 127.0.0.1 still
 *     arrives with its own Host and is refused.  `localhost' is refused
 *     too: another account may listen on [::1] at the same port.
 *   - Only connections from 127.0.0.1 whose socket belongs to the user
 *     the dashboard serves (its own uid, or SUDO_UID under sudo; never
 *     uid 0) are read at all; deadlines and per-uid slots keep slow
 *     senders from locking the user out.  That part, the server
 *     itself, is fs-dash-http.c.
 *   - GET and HEAD only, but POST for the session itself; a 16 KB cap
 *     on the request head.  An /api/ GET that carries Origin or
 *     Sec-Fetch-Site must be same-origin.
 *   - The API is read-only.  Changing the firewall stays with
 *     `stockfw apply' and the desktop app, where a human confirms it.
 *     The what-if simulator is a question, not a change.
 *   - No code travels in an argument list, where any local account
 *     could read it from /proc/<pid>/cmdline of xdg-open or of the
 *     browser it starts (1.0.7 release review, SECURITY-3).  The
 *     browser is handed the launch file, which redirects to the URL
 *     with the code in the fragment; it is removed once the code is
 *     used, after 120 s, and when the dashboard stops.
 *   - The page is compiled into the binary and carries a strict
 *     Content-Security-Policy with a per-run nonce: no external script,
 *     style, font or image can load, so nothing leaves the machine.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "cli/fs-dash-auth.h"
#include "cli/fs-dash-http.h"
#include "core/fs-activity.h"
#include "core/fs-apply.h"
#include "core/fs-copilot.h"
#include "core/fs-intel.h"
#include "core/fs-json.h"
#include "core/fs-netparse.h"
#include "core/fs-util.h"
#include "core/fs-toolpath.h"
#include "stockfw-logo-64.h"
#include "fs-dashboard-html.h"

#include <gio/gio.h>
#include <glib-unix.h>
#include <glib/gstdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <gio/gunixsocketaddress.h>

#define DASH_RECENT_EVENTS   500
#define DASH_SAMPLE_MS       2000
#define DASH_HISTORY_LINES   20000

typedef struct
{
	FsDashHttp        *http;
	guint16            port;
	uid_t              peer_uid;     /* whose browser is served */
	gid_t              peer_gid;
	FsDashAuth        *auth;         /* codes and sessions (2B) */
	guint16            origin_port;  /* --origin-port, or 0 */
	gboolean           allow_windows;
	gboolean           told_ownerless;
	gchar              nonce[33];
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
	/* WP-C: a log file this account can read, followed here when the
	 * backend's reader is not available (it needs root). */
	gchar             *follow_path;
	goffset            follow_offset;
	GString           *follow_partial;
	guint              follow_id;

	GList             *stats_now;    /* FsIfaceStat*, last sample */
	GList             *stats_prev;
	gint64             stats_now_us;
	gint64             stats_prev_us;

	GMainLoop         *loop;
} Dash;

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

/* === WP-C === */
/* [ follow_parse ]
 * One kernel-log line as an event, read the way fs_cli_log_history
 * reads it: a threat-intel block only when its set is one StockFW
 * applied, a policy event named by its verdict.  NULL for any other
 * line. */
static FsHit *
follow_parse (const gchar *line)
{
	FsHit parsed = { 0 };
	FsHit *hit;
	gchar *intel_id = NULL;

	if (fs_netparse_intel_line (line, &parsed, NULL, &intel_id)) {
		if (!fs_intel_applied_has (intel_id)) {
			g_free (intel_id);
			fs_netparse_clear_hit (&parsed);
			return NULL;
		}
		fs_netparse_name_blocked (&parsed);
		parsed.rule = fs_intel_rule_text (intel_id);
		g_free (intel_id);
	} else if (fs_netparse_log_line (line, &parsed, NULL)) {
		fs_netparse_name_by_verdict (&parsed,
		                             fs_netparse_log_verdict (line));
	} else {
		return NULL;
	}
	hit = fs_hit_new ();
	*hit = parsed;
	return hit;
}

/* [ on_follow ] -- new whole lines of the followed file. */
static gboolean
on_follow (gpointer data)
{
	Dash *dash = data;
	GStatBuf st;
	FILE *file;
	gchar buf[8192];
	gsize got;

	if (g_stat (dash->follow_path, &st) != 0)
		return G_SOURCE_CONTINUE;
	if ((goffset) st.st_size < dash->follow_offset) {
		dash->follow_offset = 0;            /* rotated or cut short */
		g_string_truncate (dash->follow_partial, 0);
	}
	if ((goffset) st.st_size == dash->follow_offset)
		return G_SOURCE_CONTINUE;
	file = g_fopen (dash->follow_path, "rb");
	if (file == NULL)
		return G_SOURCE_CONTINUE;
	if (fseeko (file, (off_t) dash->follow_offset, SEEK_SET) == 0)
		while ((got = fread (buf, 1, sizeof buf, file)) > 0) {
			dash->follow_offset += (goffset) got;
			g_string_append_len (dash->follow_partial, buf, (gssize) got);
		}
	fclose (file);

	for (;;) {
		gchar *nl = memchr (dash->follow_partial->str, '\n',
		                    dash->follow_partial->len);
		gchar *line;
		FsHit *hit;

		if (nl == NULL)
			break;
		line = g_strndup (dash->follow_partial->str,
		                  (gsize) (nl - dash->follow_partial->str));
		g_string_erase (dash->follow_partial, 0,
		                nl - dash->follow_partial->str + 1);
		hit = follow_parse (line);
		if (hit != NULL) {
			on_live_hit (hit, dash);
			fs_hit_free (hit);
		}
		g_free (line);
	}
	return G_SOURCE_CONTINUE;
}

/* [ follow_start ]
 * Monitoring is decided by what this account can read (the probe of
 * `stockfw status', fs_cli_log_readable), not by its user id: when the
 * backend's reader is refused, a readable log file is followed here. */
static gboolean
follow_start (Dash *dash)
{
	gchar *source = NULL;
	GStatBuf st;

	if (!fs_cli_log_readable (&source, NULL) || source == NULL ||
	    !g_file_test (source, G_FILE_TEST_IS_REGULAR) ||
	    g_stat (source, &st) != 0) {
		g_free (source);
		return FALSE;
	}
	dash->follow_path = source;
	dash->follow_offset = (goffset) st.st_size;
	dash->follow_partial = g_string_new (NULL);
	dash->follow_id = g_timeout_add (500, on_follow, dash);
	return TRUE;
}
/* === end WP-C === */

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
	} else if (follow_start (dash)) {
		gchar *safe = fs_cli_out_safe (dash->follow_path);

		dash->monitoring = TRUE;
		dash->monitor_note = g_strdup_printf (
			"Live from %s (readable without root)", safe);
		g_free (safe);
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
	/* Allowed connections reach the event stream on Windows (audit
	 * policy) and, from 1.0.7, on Linux while "Log allowed
	 * connections" is on. */
	{
		gboolean logs_allowed = TRUE;

		if ((backend->fw_honors & FS_FWHON_LOG_ALLOWED) != 0) {
			FsSettings *settings = fs_settings_new ();

			fs_settings_load_prefs (settings);
			logs_allowed = settings->log_allowed;
			fs_settings_free (settings);
		}
		fs_json_kv_bool (out, "logs_allowed", logs_allowed);
		g_string_append_c (out, ',');
	}
	/* Whether IPv6 is filtered; a backend without the probe covers
	 * both families with every rule (Windows Firewall). */
	{
		/* The probe runs ip6tables; the page polls every 5 s, so the
		 * answer is kept for 30 s rather than spawned each time. */
		static gint64 v6_at = 0;
		static FsIpv6State v6_state = FS_IPV6_FILTERED;
		static gchar *v6_detail = NULL;
		gint64 now_us = g_get_monotonic_time ();

		if (v6_at == 0 || now_us - v6_at > 30 * G_USEC_PER_SEC) {
			g_clear_pointer (&v6_detail, g_free);
			if (backend->ipv6_state != NULL)
				v6_state = backend->ipv6_state (&v6_detail);
			else
				v6_detail = g_strdup ("Windows Firewall applies every "
				                      "rule to IPv4 and IPv6.");
			v6_at = now_us;
		}

		fs_json_key (out, "ipv6");
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "state", fs_ipv6_state_to_string (v6_state));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "detail", v6_detail);
		g_string_append (out, "},");
	}
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
	fs_json_kv_str (out, "fingerprint", fs_dash_auth_fingerprint (dash->auth));
	g_string_append_c (out, ',');
	fs_json_kv_bool (out, "allow_windows", dash->allow_windows);
	g_string_append_c (out, ',');
	fs_json_kv_int (out, "now", g_get_real_time () / G_USEC_PER_SEC);
	g_string_append_c (out, '}');

	g_list_free_full (conns, (GDestroyNotify) fs_connection_free);
	fs_policy_free (policy);

	return g_string_free (out, FALSE);
}

/* [ intel_json ]
 * The threat-intel blocklists, read-only (design 8): the state the
 * kernel is in and the lists turned on, with their licence and credit.
 * Never creates the store; nothing here can change a list. */
static gchar *
intel_json (void)
{
	GString *out = g_string_new (NULL);

	fs_cli_intel_json (out, TRUE);
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
		fs_json_kv_str (out, "rule", hit->rule);             g_string_append_c (out, ',');
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
	FsWhatIfResult *result;
	GString *out;
	gboolean assume;

	if (q == NULL || *q == '\0' || strlen (q) > 300) {
		*status = 400;
		return g_strdup ("{\"error\":\"Describe the traffic in up to 300 "
		                 "characters.\"}");
	}

	/* assume_running=1 asks about the policy as if the firewall ran,
	 * like the command line's --assume-running. */
	assume = params != NULL &&
	         g_strcmp0 (g_hash_table_lookup (params, "assume_running"),
	                    "1") == 0;
	result = fs_cli_whatif (q, assume);

	if (result->verdict == FS_WHATIF_ERROR) {
		out = g_string_new ("{");
		fs_json_kv_str (out, "error", result->error);
		g_string_append_c (out, '}');
		fs_whatif_result_free (result);
		*status = 400;
		return g_string_free (out, FALSE);
	}

	out = g_string_new (NULL);
	fs_cli_whatif_json (out, result, q);
	fs_whatif_result_free (result);

	*status = 200;
	return g_string_free (out, FALSE);
}

/* ------------------------------------------------------------ routing */

/* [ origin_ok ]
 * The request's Origin is this server, as the Host it used: Host has
 * passed fs-dash-http.c's check, so it is 127.0.0.1:PORT or the
 * --origin-port one. */
static gboolean
origin_ok (FsDashConn *conn, gboolean required)
{
	guint n = fs_dash_conn_header_count (conn, "Origin");
	gchar *origin, *host, *want;
	gboolean ok;

	if (n == 0)
		return !required;
	if (n != 1)
		return FALSE;
	origin = fs_dash_conn_header (conn, "Origin");
	host = fs_dash_conn_header (conn, "Host");
	want = g_strconcat ("http://", host, NULL);
	ok = strcmp (origin, want) == 0;
	g_free (origin);
	g_free (host);
	g_free (want);
	return ok;
}

/* [ header_is ] -- the header appears once, with one of the values. */
static gboolean
header_is (FsDashConn *conn, const gchar *name, const gchar *a,
           const gchar *b)
{
	gchar *v;
	gboolean ok;

	if (fs_dash_conn_header_count (conn, name) != 1)
		return FALSE;
	v = fs_dash_conn_header (conn, name);
	ok = strcmp (v, a) == 0 || (b != NULL && strcmp (v, b) == 0);
	g_free (v);
	return ok;
}

/* [ post_checks ]
 * D3 step 3, for every POST: what only the dashboard's own page sends
 * (T3, T4).  A form on another site cannot send JSON, and fetch from
 * another site sends its own Origin and Sec-Fetch-Site.  FALSE when it
 * has answered. */
static gboolean
post_checks (FsDashConn *conn)
{
	if (!origin_ok (conn, TRUE)) {
		fs_dash_respond_error (conn, 403, "Origin must be this dashboard.");
		return FALSE;
	}
	if (!header_is (conn, "Sec-Fetch-Site", "same-origin", NULL) ||
	    !header_is (conn, "Sec-Fetch-Mode", "cors", "same-origin") ||
	    !header_is (conn, "Sec-Fetch-Dest", "empty", NULL)) {
		fs_dash_respond_error (conn, 403, "Only the dashboard's own page "
		                       "may send this.");
		return FALSE;
	}
	if (!header_is (conn, "Content-Type", "application/json", NULL)) {
		fs_dash_respond_error (conn, 415, "Send application/json.");
		return FALSE;
	}
	if (!fs_dash_conn_has_length (conn)) {
		fs_dash_respond_error (conn, 411, "Content-Length is needed.");
		return FALSE;
	}
	return TRUE;
}

/* [ get_checks ]
 * D3 step 4: an /api/ GET that says where it comes from must come from
 * this page.  A request with neither header (curl, or a browser that
 * sends none) goes on to the session check. */
static gboolean
get_checks (FsDashConn *conn)
{
	guint sites = fs_dash_conn_header_count (conn, "Sec-Fetch-Site");

	if (!origin_ok (conn, FALSE) ||
	    (sites != 0 && !header_is (conn, "Sec-Fetch-Site", "same-origin",
	                               NULL))) {
		fs_dash_respond_error (conn, 403, "Cross-origin requests are "
		                       "refused.");
		return FALSE;
	}
	return TRUE;
}

/* [ body_code ] -- the code of {"code":"<32 hex>"}, or NULL. */
static gchar *
body_code (FsDashConn *conn)
{
	gsize len = 0;
	const gchar *body = fs_dash_conn_body (conn, &len);
	gchar *text, *code = NULL;
	GMatchInfo *m = NULL;
	static GRegex *re = NULL;

	if (body == NULL || len > 256)
		return NULL;
	if (re == NULL)
		re = g_regex_new ("^\\s*\\{\\s*\"code\"\\s*:\\s*\"([0-9a-f]{32})\""
		                  "\\s*\\}\\s*$", G_REGEX_RAW, 0, NULL);
	text = g_strndup (body, len);
	if (strlen (text) == len && g_regex_match (re, text, 0, &m))
		code = g_match_info_fetch (m, 1);
	g_match_info_free (m);
	g_free (text);
	return code;
}

/* [ conn_via ] -- how the browser reaches us: wsl, ssh or local. */
static FsDashVia
conn_via (Dash *dash, FsDashConn *conn)
{
	gchar *host, *ssh;
	FsDashVia via = FS_DASH_VIA_LOCAL;

	if (fs_dash_conn_ownerless (conn))
		return FS_DASH_VIA_WSL;
	if (dash->origin_port == 0 || dash->origin_port == dash->port)
		return via;
	host = fs_dash_conn_header (conn, "Host");
	ssh = g_strdup_printf ("127.0.0.1:%u", dash->origin_port);
	if (g_strcmp0 (host, ssh) == 0)
		via = FS_DASH_VIA_SSH;
	g_free (host);
	g_free (ssh);
	return via;
}

/* [ session_open ] -- POST /api/session {"code": "..."}. */
static void
session_open (Dash *dash, FsDashConn *conn)
{
	static const gchar *vias[] = { "local", "ssh", "wsl" };
	gchar *code = body_code (conn);
	gchar *key = NULL;
	FsDashVia via = conn_via (dash, conn);
	FsDashRedeem r;
	GString *out;

	if (code == NULL) {
		fs_dash_respond_error (conn, 400, "Send {\"code\": \"...\"}.");
		return;
	}
	r = fs_dash_auth_redeem (dash->auth, code, via, &key);
	memset (code, 0, strlen (code));
	g_free (code);

	switch (r) {
	case FS_DASH_REDEEM_UNKNOWN:
		fs_dash_respond_error (conn, 401, "This link is not valid for "
		                       "the running dashboard.");
		return;
	case FS_DASH_REDEEM_EXPIRED:
		fs_dash_respond_error (conn, 410, "This link has expired. Run "
		                       "stockfw dashboard link for a new one.");
		return;
	case FS_DASH_REDEEM_REUSED:
		/* The alert: someone else may have had the link (T9). */
		fs_cli_error ("a used dashboard link was presented again: every "
		              "session was ended");
		fs_cli_hint ("run `stockfw dashboard link' for a new link");
		fs_dash_respond_error (conn, 410, "This link was already used. "
		                       "Every session has been ended. Run "
		                       "stockfw dashboard link for a new one.");
		return;
	case FS_DASH_REDEEM_OK:
		break;
	}

	out = g_string_new ("{");
	fs_json_kv_str (out, "session", key);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "fingerprint", fs_dash_auth_fingerprint (dash->auth));
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "via", vias[via]);
	g_string_append_c (out, ',');
	fs_json_kv_uint (out, "read_lifetime", FS_DASH_READ_LIFE_S);
	g_string_append_c (out, '}');
	memset (key, 0, strlen (key));
	g_free (key);
	fs_dash_respond_json (conn, 200, g_string_free (out, FALSE));
}

static gboolean
is_page (const gchar *path)
{
	return strcmp (path, "/") == 0 || strcmp (path, "/index.html") == 0 ||
	       strcmp (path, "/logo.png") == 0;
}

/* [ handle_request ]
 * Every request that passed fs-dash-http.c's checks (peer, Host,
 * Upgrade, sizes, deadlines) lands here and is answered once.  The
 * order is the plan's (D3): the method for the path, the POST or GET
 * checks, then the session. */
static void
handle_request (FsDashConn *conn, gpointer data)
{
	Dash *dash = data;
	const gchar *method = fs_dash_conn_method (conn);
	const gchar *path = fs_dash_conn_path (conn);
	GHashTable *params = fs_dash_conn_params (conn);
	gboolean get = strcmp (method, "GET") == 0 || strcmp (method, "HEAD") == 0;
	gboolean post = strcmp (method, "POST") == 0;
	gboolean session_path = strcmp (path, "/api/session") == 0 ||
	                        strcmp (path, "/api/session/end") == 0;
	gchar *key;

	if (!is_page (path) && !g_str_has_prefix (path, "/api/")) {
		fs_dash_respond_error (conn, 404, "Not found.");
		return;
	}
	/* 1. The method for the path.  OPTIONS never gets a CORS answer. */
	if (session_path ? !post : !get) {
		fs_dash_respond_error (conn, 405, session_path
		                       ? "POST only."
		                       : "Read-only: GET and HEAD only.");
		return;
	}

	if (strcmp (path, "/") == 0 || strcmp (path, "/index.html") == 0) {
		fs_dash_respond (conn, 200, "text/html; charset=utf-8",
		                 (const guint8 *) dash->page, strlen (dash->page));
		return;
	}
	if (strcmp (path, "/logo.png") == 0) {
		fs_dash_respond (conn, 200, "image/png", stockfw_logo_64_png,
		                 stockfw_logo_64_png_len);
		return;
	}

	/* 2. POST: only the page itself.  GET: same-origin if it says. */
	if (post ? !post_checks (conn) : !get_checks (conn))
		return;

	if (strcmp (path, "/api/session") == 0) {
		session_open (dash, conn);
		return;
	}

	/* 3. The session. */
	key = fs_dash_conn_header (conn, "X-StockFW-Session");
	if (fs_dash_conn_header_count (conn, "X-StockFW-Session") != 1 ||
	    fs_dash_auth_check (dash->auth, key, FALSE) != FS_DASH_SESSION_OK) {
		g_free (key);
		fs_dash_respond_error (conn, 401, "No valid session for the "
		                       "running dashboard. Run stockfw dashboard "
		                       "link for a new link.");
		return;
	}

	if (strcmp (path, "/api/session/end") == 0) {
		fs_dash_auth_end (dash->auth, key);
		g_free (key);
		fs_dash_respond_json (conn, 200, g_strdup ("{\"ended\":true}"));
		return;
	}
	g_free (key);

	if (strcmp (path, "/api/summary") == 0) {
		fs_dash_respond_json (conn, 200, summary_json (dash));
	} else if (strcmp (path, "/api/activity") == 0) {
		fs_dash_respond_json (conn, 200, activity_json (dash, params));
	} else if (strcmp (path, "/api/events") == 0) {
		fs_dash_respond_json (conn, 200, events_json (dash, params));
	} else if (strcmp (path, "/api/connections") == 0) {
		fs_dash_respond_json (conn, 200, connections_json (dash));
	} else if (strcmp (path, "/api/interfaces") == 0) {
		fs_dash_respond_json (conn, 200, interfaces_json (dash));
	} else if (strcmp (path, "/api/policy") == 0) {
		fs_dash_respond_json (conn, 200, policy_json ());
	} else if (strcmp (path, "/api/intel") == 0) {
		fs_dash_respond_json (conn, 200, intel_json ());
	} else if (strcmp (path, "/api/simulate") == 0) {
		guint status = 200;
		gchar *json = simulate_json (params, &status);

		fs_dash_respond_json (conn, status, json);
	} else {
		fs_dash_respond_error (conn, 404, "No such API endpoint.");
	}
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
 * under sudo the link is printed and opening it is left to the user.
 * xdg-open gets the launch file's path, never the URL with the code
 * (see the top of this file). */
static gboolean
open_browser (const gchar *file)
{
	gchar *argv[] = { NULL, NULL, NULL };
	gboolean ok;

	if (geteuid () == 0 || file == NULL)
		return FALSE;
	if (g_getenv ("DISPLAY") == NULL && g_getenv ("WAYLAND_DISPLAY") == NULL)
		return FALSE;

	argv[0] = fs_toolpath_find ("xdg-open");
	if (argv[0] == NULL)
		return FALSE;
	argv[1] = (gchar *) file;
	ok = g_spawn_async (NULL, argv, NULL,
	                    G_SPAWN_STDOUT_TO_DEV_NULL |
	                    G_SPAWN_STDERR_TO_DEV_NULL,
	                    NULL, NULL, NULL, NULL);
	g_free (argv[0]);
	return ok;
}

/* [ served_uid ]
 * The one account whose connections the dashboard reads: its own, or
 * under sudo the invoking user's (SUDO_UID, set by sudo, which only
 * root could have changed).  Never uid 0: a browser does not run as
 * root, so a root-owned client is someone else's process.  FALSE as
 * root without a usable SUDO_UID.  *gid is that account's group
 * (SUDO_GID, else its passwd entry), for the files made for it. */
static gboolean
served_uid (uid_t *uid, gid_t *gid)
{
	const gchar *v;
	gchar *end = NULL;
	guint64 u;
	struct passwd *pw;

	if (geteuid () != 0) {
		*uid = geteuid ();
		*gid = getegid ();
		return TRUE;
	}
	v = g_getenv ("SUDO_UID");
	if (v == NULL || !g_ascii_isdigit (*v))
		return FALSE;
	u = g_ascii_strtoull (v, &end, 10);
	if (*end != '\0' || u == 0 || u >= G_MAXUINT32)
		return FALSE;
	*uid = (uid_t) u;

	v = g_getenv ("SUDO_GID");
	if (v != NULL && g_ascii_isdigit (*v)) {
		u = g_ascii_strtoull (v, &end, 10);
		if (*end == '\0' && u != 0 && u < G_MAXUINT32) {
			*gid = (gid_t) u;
			return TRUE;
		}
	}
	pw = getpwuid (*uid);
	*gid = pw != NULL && pw->pw_gid != 0 ? pw->pw_gid : (gid_t) *uid;
	return TRUE;
}

/* [ served_runtime_dir ]
 * Where the launch files and the link socket go: the served user's
 * runtime directory.  Not root: GLib's ($XDG_RUNTIME_DIR, or the cache
 * directory without it).  Under sudo: $XDG_RUNTIME_DIR if sudo kept
 * it, else /run/user/<uid>, and only when that directory belongs to
 * the user.  NULL when there is none. */
static gchar *
served_runtime_dir (uid_t uid)
{
	const gchar *env = g_getenv ("XDG_RUNTIME_DIR");
	gchar *dir;
	struct stat st;

	if (geteuid () != 0)
		return g_strdup (g_get_user_runtime_dir ());
	if (env != NULL && g_path_is_absolute (env))
		dir = g_strdup (env);
	else
		dir = g_strdup_printf ("/run/user/%u", (guint) uid);
	if (lstat (dir, &st) != 0 || !S_ISDIR (st.st_mode) || st.st_uid != uid) {
		g_free (dir);
		return NULL;
	}
	return dir;
}

static gboolean
on_auth_tick (gpointer data)
{
	fs_dash_auth_tick (((Dash *) data)->auth);
	return G_SOURCE_CONTINUE;
}

/* [ on_ownerless_refused ]
 * On WSL without --allow-windows: a peer with no socket owner is
 * probably a browser on the Windows side.  Said once. */
static void
on_ownerless_refused (gpointer unused, gpointer data)
{
	Dash *dash = data;

	if (dash->told_ownerless)
		return;
	dash->told_ownerless = TRUE;
	fs_cli_error ("refused a connection with no owner on this machine: "
	              "under WSL that is a browser on the Windows side");
	fs_cli_hint ("start the dashboard with --allow-windows to let it in, "
	             "or use a browser inside WSL");
	fflush (stderr);
}

/* -------------------------------------------------------------- link */

/* [ unix_listening ]
 * TRUE when /proc/net/unix lists a listening socket bound to `path'. */
static gboolean
unix_listening (const gchar *path)
{
	gchar *text = NULL;
	gchar **lines;
	gboolean found = FALSE;

	if (!g_file_get_contents ("/proc/net/unix", &text, NULL, NULL))
		return FALSE;
	lines = g_strsplit (text, "\n", -1);
	/* Num RefCount Protocol Flags Type St Inode Path */
	for (guint i = 1; lines[i] != NULL && !found; i++) {
		guint flags = 0, st = 0;
		gint at = -1;

		if (sscanf (lines[i], "%*s %*x %*x %x %*x %x %*u %n", &flags, &st,
		            &at) == 2 && at > 0)
			found = (flags & 0x10000) != 0 && st == 1 &&
			        strcmp (lines[i] + at, path) == 0;
	}
	g_strfreev (lines);
	g_free (text);
	return found;
}

/* [ socket_live ]
 * TRUE when a dashboard listens on the socket at `path'.  A socket left
 * by a dashboard that was killed (SIGKILL, a crash) is not counted as a
 * running dashboard, and is removed (review of PR 2).  /proc/net/unix
 * answers first, since a connect makes a live dashboard issue a code;
 * a socket it does not list (another network namespace, say) is tried
 * with a connect, and only ECONNREFUSED counts as gone.  The directory
 * is the user's own, 0700. */
static gboolean
socket_live (const gchar *path)
{
	struct sockaddr_un sa;
	gint fd;
	gboolean live = TRUE;

	if (unix_listening (path) || strlen (path) >= sizeof (sa.sun_path))
		return TRUE;
	memset (&sa, 0, sizeof (sa));
	sa.sun_family = AF_UNIX;
	strcpy (sa.sun_path, path);
	fd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return TRUE;
	if (connect (fd, (struct sockaddr *) &sa, sizeof (sa)) != 0 &&
	    errno == ECONNREFUSED) {
		g_unlink (path);
		live = FALSE;
	}
	close (fd);
	return live;
}

/* [ link_socket ]
 * The socket of the dashboard on `port', or of the only one running for
 * this account when port is 0.  NULL after printing why.  Sockets of
 * dashboards that are gone are skipped (and removed). */
static gchar *
link_socket (guint16 port, gint *status)
{
	gchar *dir = fs_dash_auth_socket_dir (g_get_user_runtime_dir ());
	GPtrArray *found = g_ptr_array_new_with_free_func (g_free);
	GDir *d;
	gchar *path = NULL;
	const gchar *name;

	*status = FS_EXIT_FAILURE;
	d = g_dir_open (dir, 0, NULL);
	while (d != NULL && (name = g_dir_read_name (d)) != NULL) {
		guint p = 0;
		gchar tail = 0;

		if (sscanf (name, "dash-%u.so%c", &p, &tail) == 2 && tail == 'c' &&
		    g_str_has_suffix (name, ".sock") && p > 0 && p < 65536 &&
		    (port == 0 || p == port)) {
			gchar *one = g_build_filename (dir, name, NULL);

			if (socket_live (one))
				g_ptr_array_add (found, one);
			else
				g_free (one);
		}
	}
	if (d != NULL)
		g_dir_close (d);

	if (found->len == 0) {
		if (port != 0)
			fs_cli_error ("no dashboard of this account listens on port %u",
			              port);
		else
			fs_cli_error ("no dashboard is running for this account");
		fs_cli_hint ("start one with `stockfw dashboard' (its socket "
		             "would be in %s)", dir);
	} else if (found->len > 1) {
		GString *ports = g_string_new (NULL);

		for (guint i = 0; i < found->len; i++) {
			const gchar *b = strrchr (g_ptr_array_index (found, i), '/');

			g_string_append_printf (ports, "%s%.*s", i ? ", " : "",
			                        (gint) (strlen (b + 1) - 10), b + 6);
		}
		fs_cli_error ("%u dashboards are running (ports %s)",
		              found->len, ports->str);
		fs_cli_hint ("say which: stockfw dashboard link --port N");
		g_string_free (ports, TRUE);
		*status = FS_EXIT_USAGE;
	} else {
		path = g_strdup (g_ptr_array_index (found, 0));
		*status = FS_EXIT_OK;
	}
	g_ptr_array_unref (found);
	g_free (dir);
	return path;
}

/* [ dashboard_link ]
 * `stockfw dashboard link': a new launch code from the running
 * dashboard, over its UNIX socket.  The link (with the code) is printed
 * only on a terminal; otherwise the launch file's path is. */
static gint
dashboard_link (guint16 port)
{
	GSocketClient *client;
	GSocketConnection *conn;
	GSocketAddress *address;
	GInputStream *in;
	gchar buf[4096];
	gsize got = 0;
	gchar *path;
	gchar **lines;
	const gchar *code = NULL, *file = NULL, *fp = NULL, *port_s = NULL;
	const gchar *origin_s = NULL;
	GError *error = NULL;
	gint status;

	if (geteuid () == 0) {
		fs_cli_error ("run `stockfw dashboard link' as the account the "
		              "dashboard serves, without sudo");
		return FS_EXIT_FAILURE;
	}
	path = link_socket (port, &status);
	if (path == NULL)
		return status;

	client = g_socket_client_new ();
	g_socket_client_set_timeout (client, 5);
	address = g_unix_socket_address_new (path);
	conn = g_socket_client_connect (client, G_SOCKET_CONNECTABLE (address),
	                                NULL, &error);
	g_object_unref (address);
	g_object_unref (client);
	if (conn == NULL) {
		fs_cli_error ("cannot reach the dashboard at %s: %s", path,
		              error->message);
		fs_cli_hint ("it may have stopped; start it again");
		g_error_free (error);
		g_free (path);
		return FS_EXIT_FAILURE;
	}
	in = g_io_stream_get_input_stream (G_IO_STREAM (conn));
	g_input_stream_read_all (in, buf, sizeof (buf) - 1, &got, NULL, NULL);
	buf[got] = '\0';
	g_io_stream_close (G_IO_STREAM (conn), NULL, NULL);
	g_object_unref (conn);

	lines = g_strsplit (buf, "\n", -1);
	for (guint i = 0; lines[i] != NULL; i++) {
		if (g_str_has_prefix (lines[i], "code="))
			code = lines[i] + 5;
		else if (g_str_has_prefix (lines[i], "file="))
			file = lines[i] + 5;
		else if (g_str_has_prefix (lines[i], "fingerprint="))
			fp = lines[i] + 12;
		else if (g_str_has_prefix (lines[i], "port="))
			port_s = lines[i] + 5;
		else if (g_str_has_prefix (lines[i], "origin_port="))
			origin_s = lines[i] + 12;
	}
	if (code == NULL || strlen (code) != 32 || port_s == NULL || fp == NULL) {
		fs_cli_error ("the dashboard at %s gave no link", path);
		fs_cli_hint ("it answers only the account it serves");
		g_strfreev (lines);
		g_free (path);
		return FS_EXIT_FAILURE;
	}

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_uint (out, "port", g_ascii_strtoull (port_s, NULL, 10));
		g_string_append_c (out, ',');
		if (origin_s != NULL) {
			fs_json_kv_uint (out, "origin_port",
			                 g_ascii_strtoull (origin_s, NULL, 10));
			g_string_append_c (out, ',');
		}
		if (file != NULL && *file != '\0')
			fs_json_kv_str (out, "link_file", file);
		else
			g_string_append (out, "\"link_file\":null");
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "fingerprint", fp);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (isatty (STDOUT_FILENO)) {
		printf ("http://127.0.0.1:%s/#code=%s\n", port_s, code);
		/* --origin-port: the same code through `ssh -L N:...'
		 * (review of PR 2: only the server's port was printed). */
		if (origin_s != NULL)
			printf ("  Over SSH: http://127.0.0.1:%s/#code=%s\n",
			        origin_s, code);
		printf ("  One use, for 2 minutes.  Fingerprint %s.\n", fp);
	} else if (file != NULL && *file != '\0') {
		printf ("%s\n", file);
	} else {
		fs_cli_error ("stdout is not a terminal and the dashboard could "
		              "not write a launch file");
		g_strfreev (lines);
		g_free (path);
		return FS_EXIT_FAILURE;
	}
	memset (buf, 0, sizeof (buf));
	g_strfreev (lines);
	g_free (path);
	return FS_EXIT_OK;
}

/* ------------------------------------------------------------ the run */

static gboolean
parse_port (const gchar *opt, const gchar *v, guint16 *port)
{
	gchar *end = NULL;
	guint64 p = g_ascii_strtoull (v, &end, 10);

	if (!g_ascii_isdigit (*v) || end == NULL || *end != '\0' ||
	    p == 0 || p > 65535) {
		fs_cli_error ("%s wants a number from 1 to 65535", opt);
		return FALSE;
	}
	*port = (guint16) p;
	return TRUE;
}

gint
fs_cli_cmd_dashboard (gint argc, gchar **argv)
{
	Dash dash = { 0 };
	guint16 want_port = 0;
	gboolean no_open = FALSE, link = FALSE;
	gboolean tty;
	GError *error = NULL;
	gchar *url, *runtime, *link_error = NULL;
	const gchar *code, *file = NULL;
	guint sample_id, tick_id;

	for (gint i = 1; i < argc; i++) {
		const gchar *v = NULL;
		gint bad = FS_EXIT_OK;

		if (fs_cli_take_opt (argc, argv, &i, "--port", &v, &bad) ||
		    fs_cli_take_opt (argc, argv, &i, "-p", &v, &bad)) {
			if (v == NULL)
				return bad;
			if (!parse_port ("--port", v, &want_port))
				return FS_EXIT_USAGE;
		} else if (fs_cli_take_opt (argc, argv, &i, "--origin-port", &v,
		                            &bad)) {
			if (v == NULL)
				return bad;
			if (!parse_port ("--origin-port", v, &dash.origin_port))
				return FS_EXIT_USAGE;
		} else if (fs_cli_is_option_at (argv, i) &&
		           strcmp (argv[i], "--no-open") == 0) {
			no_open = TRUE;
		} else if (fs_cli_is_option_at (argv, i) &&
		           strcmp (argv[i], "--allow-windows") == 0) {
			dash.allow_windows = TRUE;
		} else if (fs_cli_is_option_at (argv, i)) {
			fs_cli_unknown_option ("dashboard", argv[i]);
			fs_cli_hint ("there is deliberately no --bind: the dashboard "
			             "only ever listens on 127.0.0.1");
			return FS_EXIT_USAGE;
		} else if (!link && strcmp (argv[i], "link") == 0) {
			link = TRUE;
		} else {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			fs_cli_hint ("there is deliberately no --bind: the dashboard "
			             "only ever listens on 127.0.0.1");
			return FS_EXIT_USAGE;
		}
	}

	if (link) {
		if (no_open || dash.origin_port != 0 || dash.allow_windows) {
			fs_cli_error ("`dashboard link' takes only --port");
			return FS_EXIT_USAGE;
		}
		return dashboard_link (want_port);
	}

	if (!served_uid (&dash.peer_uid, &dash.peer_gid)) {
		fs_cli_error ("the dashboard does not serve uid 0: as root it "
		              "needs SUDO_UID, the account whose browser opens it");
		fs_cli_hint ("run it as yourself, or with sudo from your own "
		             "account");
		return FS_EXIT_FAILURE;
	}
	/* Fail closed (T21): Windows peers only on WSL, and only when
	 * asked for. */
	if (dash.allow_windows && !fs_dash_is_wsl ()) {
		fs_cli_error ("--allow-windows is for WSL only, and this is not WSL");
		return FS_EXIT_USAGE;
	}

	dash.auth = fs_dash_auth_new ();
	if (dash.auth == NULL || !random_hex (dash.nonce, 16)) {
		fs_cli_error ("cannot read /dev/urandom for the launch code");
		fs_dash_auth_free (dash.auth);
		return FS_EXIT_FAILURE;
	}
	runtime = served_runtime_dir (dash.peer_uid);
	fs_dash_auth_set_user (dash.auth, dash.peer_uid, dash.peer_gid, runtime);
	/* The link, with its code, goes to a terminal only (T11): piped
	 * or as JSON, the launch file's path is printed instead. */
	tty = isatty (STDOUT_FILENO) && !fs_cli.json;

	dash.http = fs_dash_http_new (want_port, dash.peer_uid, &error);
	if (dash.http == NULL) {
		fs_cli_error ("cannot listen on 127.0.0.1:%u: %s", want_port,
		              error->message);
		if (want_port != 0)
			fs_cli_hint ("leave out --port to let the system pick a "
			             "free one");
		g_error_free (error);
		fs_dash_auth_free (dash.auth);
		g_free (runtime);
		return FS_EXIT_FAILURE;
	}
	dash.port = fs_dash_http_port (dash.http);
	fs_dash_http_set_nonce (dash.http, dash.nonce);
	if (dash.origin_port != 0) {
		/* ssh -L N:127.0.0.1:PORT (T22): the browser's end. */
		gchar *host = g_strdup_printf ("127.0.0.1:%u", dash.origin_port);

		fs_dash_http_allow_host (dash.http, host);
		g_free (host);
	}
	if (dash.allow_windows)
		fs_dash_http_allow_ownerless (dash.http, TRUE);
	else if (fs_dash_is_wsl ())
		fs_dash_http_on_ownerless_refused (dash.http, on_ownerless_refused,
		                                   &dash);

	if (dash.origin_port != 0 && dash.origin_port != dash.port)
		fs_dash_auth_set_origin_port (dash.auth, dash.origin_port);
	if (!fs_dash_auth_listen_link (dash.auth, dash.port, &error)) {
		link_error = g_strdup (error->message);
		g_clear_error (&error);
	}
	code = fs_dash_auth_issue (dash.auth, dash.port, &file);
	if (code == NULL || (!tty && file == NULL)) {
		if (code == NULL)
			fs_cli_error ("cannot read /dev/urandom for the launch code");
		else
			fs_cli_error ("cannot write the launch file in %s, and stdout "
			              "is not a terminal: the link has nowhere to go",
			              runtime != NULL ? runtime
			                              : "the runtime directory");
		fs_cli_hint ("run it in a terminal, or set XDG_RUNTIME_DIR to a "
		             "directory of uid %u", (guint) dash.peer_uid);
		fs_dash_auth_free (dash.auth);
		fs_dash_http_free (dash.http);
		g_free (runtime);
		g_free (link_error);
		return FS_EXIT_FAILURE;
	}
	dash.started = g_get_real_time () / G_USEC_PER_SEC;

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
	tick_id = g_timeout_add_seconds (1, on_auth_tick, &dash);

	fs_dash_http_start (dash.http, handle_request, &dash);

	url = g_strdup_printf ("http://127.0.0.1:%u/", dash.port);

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "url", url);           g_string_append_c (out, ',');
		fs_json_kv_uint (out, "port", dash.port);   g_string_append_c (out, ',');
		fs_json_kv_str (out, "link_file", file);    g_string_append_c (out, ',');
		fs_json_kv_str (out, "fingerprint",
		                fs_dash_auth_fingerprint (dash.auth));
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "monitoring", dash.monitoring);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		if (tty)
			printf ("%sStockFW dashboard%s  %s#code=%s\n\n", fs_cli_bold (),
			        fs_cli_reset (), url, code);
		else
			printf ("%sStockFW dashboard%s  %s\n\n", fs_cli_bold (),
			        fs_cli_reset (), url);
		printf ("  %-11s 127.0.0.1:%u only, read-only\n", "Listening",
		        dash.port);
		if (tty)
			printf ("  %-11s one use, for 2 minutes; `stockfw dashboard "
			        "link' makes a new one\n", "Link");
		else
			printf ("  %-11s %s\n  %-11s open it in your browser: one use, "
			        "for 2 minutes\n", "Link file", file, "");
		printf ("  %-11s %s (the page shows the same)\n", "Fingerprint",
		        fs_dash_auth_fingerprint (dash.auth));
		if (dash.origin_port != 0 && dash.origin_port != dash.port) {
			printf ("  %-11s ssh -L %u:127.0.0.1:%u <this host>, then "
			        "http://127.0.0.1:%u/", "Over SSH", dash.origin_port,
			        dash.port, dash.origin_port);
			if (tty)
				printf ("#code=%s", code);
			printf ("\n");
		}
		if (dash.allow_windows)
			printf ("  %-11s browsers on the Windows side are let in "
			        "(--allow-windows)\n", "WSL");
		if (geteuid () == 0)
			printf ("  %-11s uid %u only (SUDO_UID)\n", "Serves",
			        (guint) dash.peer_uid);
		if (link_error != NULL)
			printf ("  %-11s `stockfw dashboard link' is not available: "
			        "%s\n", "New links", link_error);
		printf ("  %-11s %s\n", "Events",
		        dash.monitor_note != NULL ? dash.monitor_note : "-");
		if (!dash.monitoring && geteuid () != 0) {
			gchar *args = fs_cli_user_args ();
			gchar *again = fs_cli_sudo_hint (args);

			printf ("  %-11s %srun `%s' for live events%s\n", "",
			        fs_cli_dim (), again, fs_cli_reset ());
			g_free (again);
			g_free (args);
		}
	}

	if (!no_open && open_browser (file)) {
		if (!fs_cli.json) {
			/* xdg-open started, but whether the browser can read
			 * the launch file is not known here: a snap or Flatpak
			 * browser is usually not allowed into $XDG_RUNTIME_DIR
			 * or a hidden folder, and shows an error instead
			 * (code review of the release, finding 1). */
			printf ("\n  A browser was started with the link.  If it "
			        "shows an error and not the dashboard\n  (a snap "
			        "or Flatpak browser may not read the file it was "
			        "given),\n  open the link above in it; it works "
			        "once.\n");
		}
	} else if (!fs_cli.json) {
		const gchar *what = tty ? "link" : "link file";

		if (geteuid () == 0)
			printf ("\n  Open the %s above in your browser (it is not "
			        "started as root).\n", what);
		else
			printf ("\n  Open the %s above in your browser.\n", what);
	}

	if (!fs_cli.json)
		printf ("%s\n  Ctrl-C stops the dashboard.%s\n", fs_cli_dim (),
		        fs_cli_reset ());
	fflush (stdout);

	dash.loop = g_main_loop_new (NULL, FALSE);
	g_unix_signal_add (SIGINT, on_quit_signal, &dash);
	g_unix_signal_add (SIGTERM, on_quit_signal, &dash);
	/* Closing the terminal sends SIGHUP: the launch files and the link
	 * socket must go then too (review of PR 2). */
	g_unix_signal_add (SIGHUP, on_quit_signal, &dash);
	g_main_loop_run (dash.loop);

	/* Teardown, in the order things were started. */
	g_source_remove (tick_id);
	g_source_remove (sample_id);
	if (dash.follow_id != 0) {
		g_source_remove (dash.follow_id);
		g_string_free (dash.follow_partial, TRUE);
		g_free (dash.follow_path);
	} else if (dash.monitoring && fs_backend ()->log_stop != NULL)
		fs_backend ()->log_stop ();

	/* Launch files and the link socket go; every key dies with us. */
	fs_dash_auth_free (dash.auth);
	g_main_loop_unref (dash.loop);
	fs_dash_http_free (dash.http);
	g_queue_free_full (dash.recent, (GDestroyNotify) fs_hit_free);
	g_list_free_full (dash.stats_now, (GDestroyNotify) fs_iface_stat_free);
	g_list_free_full (dash.stats_prev, (GDestroyNotify) fs_iface_stat_free);
	fs_activity_sampler_free (dash.sampler);
	fs_activity_free (dash.net);
	fs_activity_free (dash.events);
	g_free (dash.monitor_note);
	g_free (dash.page);
	g_free (url);
	g_free (runtime);
	g_free (link_error);

	if (!fs_cli.json && !fs_cli.quiet)
		printf ("\nDashboard stopped.\n");

	return FS_EXIT_OK;
}

/* ------------------------------------------------------- the commands */

static const FsCliOption dashboard_opts[] = {
	{ "--port",          TRUE,  NULL },
	{ "-p",              TRUE,  NULL },
	{ "--origin-port",   TRUE,  NULL },
	{ "--no-open",       FALSE, NULL },
	{ "--allow-windows", FALSE, NULL },
	{ NULL, FALSE, NULL }
};

const FsCliCommandDef fs_cli_dashboard_commands[] = {
	{ "dashboard", fs_cli_cmd_dashboard,
"Usage: stockfw dashboard [--port N] [--no-open] [--origin-port N]\n"
"                         [--allow-windows] [--json]\n"
"       stockfw dashboard link [--port N] [--json]\n"
"\n"
"Serves a live dashboard -- status, the Policy activity and Network I/O\n"
"graphs, recent events, connections, the policy, the threat-intel\n"
"blocklists and the what-if simulator -- and opens it in your browser.\n"
"\n"
"The link it prints holds a code that works once, for 2 minutes; the\n"
"browser swaps it for a session.  The link is printed only to a\n"
"terminal: piped, or with --json, you get the path of a launch file\n"
"(0600) to open instead.  `stockfw dashboard link' gets a new link\n"
"from the running dashboard (--port N when more than one runs).  Check\n"
"that the fingerprint on the page is the one in the terminal.\n"
"\n"
"  --origin-port N   also answer as 127.0.0.1:N, the local end of\n"
"                    `ssh -L N:127.0.0.1:PORT host'\n"
"  --allow-windows   under WSL, let in browsers on the Windows side\n"
"\n"
"Security: it listens on 127.0.0.1 only and answers only connections\n"
"from your own account (under sudo, the account in SUDO_UID; never\n"
"root).  The address must be 127.0.0.1:PORT (not localhost), and the\n"
"API is read-only: changing the firewall stays with `stockfw apply'\n"
"and the desktop app.  Under sudo the browser is not started as root;\n"
"open the printed link yourself.  Stop it with Ctrl-C.\n",
	  dashboard_opts, NULL },

	{ NULL, NULL, NULL, NULL, NULL }
};
