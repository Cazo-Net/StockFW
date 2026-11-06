/*---[ fs-cli-status.c ]----------------------------------------------------
 * `stockfw status', and the status snapshot the live event line
 * reads.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "core/fs-apply.h"
#include "core/fs-audit.h"
#include "core/fs-autostart.h"
#include "core/fs-autoblock.h"
#include "core/fs-prefs.h"
#include "core/fs-toolpath.h"
#include "core/fs-copilot.h"
#include "core/fs-eventlog.h"
#include "core/fs-eventstore.h"
#include "core/fs-intel.h"
#include "core/fs-health.h"
#include "core/fs-service.h"
#include "core/fs-json.h"
#include "core/fs-netparse.h"
#include "core/fs-script.h"
#include "core/fs-util.h"
#include "core/fs-verdict.h"
#include "core/fs-netplace.h"

#include <glib-unix.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


/* === WP-C === */

/* ------------------------------------------------------- blocked today */

/* [ hit_epoch ] -- an event's time in seconds, or 0 when unreadable. */
static gint64
hit_epoch (const FsHit *hit)
{
	gint64 ticks = 0;
	GDateTime *when;
	gint64 epoch;

	if (hit->time == NULL)
		return 0;
	if (fs_event_time_parse (hit->time, &ticks) != FS_EVENT_TIME_OTHER)
		return ticks / 10000000;
	when = g_date_time_new_from_iso8601 (hit->time, NULL);
	if (when == NULL)
		return 0;
	epoch = g_date_time_to_unix (when);
	g_date_time_unref (when);
	return epoch;
}

typedef struct
{
	gint64  since;      /* local midnight, seconds */
	gint64  count;
	FsHit  *last;
	gint64  last_epoch;
} TodayScan;

static void
today_take (TodayScan *scan, const FsHit *hit, gint64 epoch)
{
	if (!fs_hit_is_blocked (hit) || epoch < scan->since)
		return;
	scan->count++;
	if (epoch >= scan->last_epoch) {
		if (scan->last != NULL)
			fs_hit_free (scan->last);
		scan->last = fs_hit_copy (hit);
		scan->last_epoch = epoch;
	}
}

static void
on_today_hit (const FsHit *hit, gint64 ticks, gpointer data)
{
	today_take (data, hit, ticks / 10000000);
}

gint64
fs_cli_blocked_today (FsHit **last_block, const gchar **source)
{
	GDateTime *now = g_date_time_new_now_local ();
	GDateTime *midnight = g_date_time_new (g_date_time_get_timezone (now),
	                                       g_date_time_get_year (now),
	                                       g_date_time_get_month (now),
	                                       g_date_time_get_day_of_month (now),
	                                       0, 0, 0);
	TodayScan scan = { 0, 0, NULL, 0 };
	gchar *dir = fs_eventlog_default_dir ();
	gboolean history;

	scan.since = g_date_time_to_unix (midnight);
	g_date_time_unref (midnight);
	g_date_time_unref (now);

	if (last_block != NULL)
		*last_block = NULL;
	if (source != NULL)
		*source = NULL;

	/* The saved history while it is being kept (or named for a test);
	 * a folder left from a time it was on would count nothing new. */
	history = g_file_test (dir, G_FILE_TEST_IS_DIR) &&
	          (g_getenv ("STOCKFW_EVENTS_DIR") != NULL ||
	           fs_prefs_bool (FS_PREFS_EVENTS_HISTORY));

	if (history) {
		fs_eventlog_foreach (dir, scan.since * G_USEC_PER_SEC, 0,
		                     on_today_hit, &scan, NULL);
		if (source != NULL)
			*source = "history";
	} else {
		GPtrArray *hits = fs_cli_log_history (20000, NULL, NULL);

		if (hits == NULL) {
			g_free (dir);
			return -1;
		}
		for (guint i = 0; i < hits->len; i++) {
			const FsHit *hit = g_ptr_array_index (hits, i);

			today_take (&scan, hit, hit_epoch (hit));
		}
		g_ptr_array_unref (hits);
		if (source != NULL)
			*source = "kernel_log";
	}
	g_free (dir);

	if (last_block != NULL)
		*last_block = scan.last;
	else if (scan.last != NULL)
		fs_hit_free (scan.last);
	return scan.count;
}

/* ------------------------------------------------------------- helpers */

static const gchar *
state_name (FsFirewallState state)
{
	switch (state) {
	case FS_FW_RUNNING: return "running";
	case FS_FW_STOPPED: return "stopped";
	case FS_FW_LOCKED:  return "locked";
	default:            return "unknown";
	}
}

static const gchar *
boot_unit_name (FsBootUnit unit)
{
	switch (unit) {
	case FS_BOOT_UNIT_ENABLED:  return "enabled";
	case FS_BOOT_UNIT_DISABLED: return "disabled";
	case FS_BOOT_UNIT_ABSENT:   return "absent";
	default:                    return "none";
	}
}

/* [ local_stamp ] -- "2026-11-03 09:12:04" local, ISO under fs_cli.utc. */
static gchar *
local_stamp (gint64 epoch, const gchar *format)
{
	GDateTime *utc = g_date_time_new_from_unix_utc (epoch);
	GDateTime *local;
	gchar *text;

	if (utc == NULL)
		return g_strdup ("?");
	if (fs_cli.utc) {
		text = g_date_time_format (utc, "%Y-%m-%dT%H:%M:%SZ");
		g_date_time_unref (utc);
		return text;
	}
	local = g_date_time_to_local (utc);
	text = g_date_time_format (local, format);
	g_date_time_unref (local);
	g_date_time_unref (utc);
	return text;
}

/* [ thousands ] -- 1284 as "1,284". */
static gchar *
thousands (gint64 n)
{
	gchar *digits = g_strdup_printf ("%" G_GINT64_FORMAT, n);
	GString *out = g_string_new (NULL);
	gsize len = strlen (digits);

	for (gsize i = 0; i < len; i++) {
		if (i > 0 && (len - i) % 3 == 0 && digits[i - 1] != '-')
			g_string_append_c (out, ',');
		g_string_append_c (out, digits[i]);
	}
	g_free (digits);
	return g_string_free (out, FALSE);
}

static const gchar *
value_of (GHashTable *values, const gchar *key)
{
	const gchar *v = values != NULL ? g_hash_table_lookup (values, key)
	                                : NULL;

	return v != NULL ? v : "";
}

static gboolean
is_on (GHashTable *values, const gchar *key)
{
	return strcmp (value_of (values, key), "true") == 0;
}

/* The ICMP types the Preferences window lists, in its words. */
static const struct { const gchar *key; const gchar *label; } icmp_types[] = {
	{ FS_PREFS_FW_ICMP_ECHO_REQUEST,    "echo request" },
	{ FS_PREFS_FW_ICMP_ECHO_REPLY,      "echo reply" },
	{ FS_PREFS_FW_ICMP_TRACEROUTE,      "traceroute" },
	{ FS_PREFS_FW_ICMP_MSTRACEROUTE,    "Windows traceroute" },
	{ FS_PREFS_FW_ICMP_UNREACHABLE,     "unreachable" },
	{ FS_PREFS_FW_ICMP_TIMESTAMPING,    "timestamps" },
	{ FS_PREFS_FW_ICMP_MASKING,         "address masks" },
	{ FS_PREFS_FW_ICMP_REDIRECTION,     "redirects" },
	{ FS_PREFS_FW_ICMP_SOURCE_QUENCHES, "source quench" },
};

static void
print_line (const gchar *label, const gchar *text)
{
	printf ("  %-12s %s\n", label, text);
}

/* [ print_settings ] -- the firewall settings, for status -v. */
static void
print_settings (GHashTable *values)
{
	GString *s = g_string_new (NULL);
	const gchar *ext = value_of (values, FS_PREFS_FW_EXT_IF);
	const gchar *intf = value_of (values, FS_PREFS_FW_INT_IF);
	gchar *e = fs_cli_out_safe (*ext ? ext : "none");
	gchar *n = fs_cli_out_safe (*intf ? intf : "none");

	print_line ("Inbound", "blocked unless a rule allows it");
	print_line ("Outbound", is_on (values, FS_PREFS_FW_RESTRICTIVE_OUTBOUND)
	            ? "blocked unless a rule allows it (restrictive)"
	            : "allowed unless a rule blocks it");
	print_line ("Blocked as", is_on (values, FS_PREFS_FW_DENY_PACKETS)
	            ? "dropped silently (DROP)"
	            : "refused with an error packet (REJECT)");

	if (!is_on (values, FS_PREFS_FW_FILTER_ICMP)) {
		g_string_assign (s, "not filtered");
	} else {
		for (guint i = 0; i < G_N_ELEMENTS (icmp_types); i++)
			if (is_on (values, icmp_types[i].key))
				g_string_append_printf (s, "%s%s", s->len ? ", " : "",
				                        icmp_types[i].label);
		g_string_prepend (s, s->len ? "allowed: " : "all blocked");
	}
	print_line ("ICMP", s->str);

	print_line ("Logging", is_on (values, FS_PREFS_FW_LOG_ALLOWED)
	            ? "blocked traffic and allowed new connections"
	            : "blocked traffic only");

	g_string_printf (s, "external %s, internal %s", e, n);
	print_line ("Interfaces", s->str);
	print_line ("NAT", is_on (values, FS_PREFS_FW_NAT) ? "on" : "off");

	g_string_truncate (s, 0);
	if (is_on (values, FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST))
		g_string_append (s, "external broadcast");
	if (is_on (values, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST))
		g_string_append_printf (s, "%sinternal broadcast",
		                        s->len ? ", " : "");
	if (is_on (values, FS_PREFS_FW_BLOCK_NON_ROUTABLES))
		g_string_append_printf (s, "%snon-routable sources",
		                        s->len ? ", " : "");
	print_line ("Also blocks", s->len ? s->str : "nothing more");

	g_free (e);
	g_free (n);
	g_string_free (s, TRUE);
}

/* ------------------------------------------------------------- verdict */

/* [ status_verdict ]
 * The Overview's verdict (B3, A24), from what this command read: the
 * firewall state (unknown without root), the IPv6 answer as the
 * desktop app takes it (no slot: not known, so the families are not
 * judged apart), the network place where the backend has profiles,
 * the audit-only hold and the blocklist sentence. */
static FsVerdictResult *
status_verdict (FsFirewallState state, gboolean ipv6_known, FsIpv6State ipv6,
                const gchar *ipv6_detail, const gchar *hold)
{
	const FsBackend *backend = fs_backend ();
	FsVerdictInput in;
	FsVerdictResult *v;
	FsNetworkPlace *place = NULL;
	gchar *intel;

	memset (&in, 0, sizeof in);
	in.state = state;
	in.backend_usable = backend->available != NULL && backend->available ();
	in.ipv6_known = ipv6_known;
	in.ipv6 = ipv6;
	in.ipv6_detail = ipv6_detail;
	in.display_name = backend->display_name;
	in.hold_reason = hold;
	if (backend->network_place != NULL &&
	    backend->get_profile_enabled != NULL) {
		place = backend->network_place ();
		for (gint i = 0; place != NULL && i < FS_PROFILE_COUNT; i++) {
			gboolean enabled = FALSE;

			if (!backend->get_profile_enabled (i, &enabled))
				continue;
			in.profiles_known |= FS_PROFILE_BIT (i);
			if (enabled)
				in.profiles_on |= FS_PROFILE_BIT (i);
		}
	}
	in.place = place;
	intel = fs_intel_summary (backend);
	in.intel_summary = intel;
	v = fs_verdict_compute (&in);
	g_free (intel);
	if (place != NULL)
		fs_network_place_free (place);
	return v;
}

/* [ indent_wrap ] -- text indented by `indent' spaces, every line
 * of it, and wrapped to the terminal's width (none in a pipe). */
static gchar *
indent_wrap (const gchar *text, guint indent)
{
	guint width = fs_cli_term_width ();
	gchar **words = g_strsplit (text, " ", -1);
	GString *out = g_string_new (NULL);
	guint col = 0;

	for (guint w = 0; words[w] != NULL; w++) {
		guint len = (guint) g_utf8_strlen (words[w], -1);

		if (*words[w] == '\0')
			continue;
		if (col == 0 || (width > indent + 10 && col + 1 + len > width)) {
			if (col > 0)
				g_string_append_c (out, '\n');
			for (guint i = 0; i < indent; i++)
				g_string_append_c (out, ' ');
			col = indent;
		} else {
			g_string_append_c (out, ' ');
			col++;
		}
		g_string_append (out, words[w]);
		col += len;
	}
	g_strfreev (words);
	return g_string_free (out, FALSE);
}

/* [ print_verdict ] -- line 1 of `status': the dot and the card's
 * title in the verdict's colour, then its sentences, wrapped. */
static void
print_verdict (const FsVerdictResult *v)
{
	const gchar *dot, *color;
	gchar *title = fs_cli_out_safe (v->title);
	gchar *body = fs_cli_out_safe (v->body);
	gchar *wrapped;

	switch (v->level) {
	case FS_VERDICT_LEVEL_OK:
		dot = fs_cli_sym (FS_CLI_SYM_ON); color = fs_cli_green ();
		break;
	case FS_VERDICT_LEVEL_BAD:
		dot = fs_cli_sym (FS_CLI_SYM_OFF); color = fs_cli_red ();
		break;
	case FS_VERDICT_LEVEL_WARN:
		dot = "!"; color = fs_cli_amber ();
		break;
	default:
		dot = "?"; color = fs_cli_amber ();
		break;
	}
	printf ("%s%s%s %s%s\n", color, fs_cli_bold (), dot, title,
	        fs_cli_reset ());
	if (*body) {
		wrapped = indent_wrap (body, 2);
		printf ("%s%s%s\n", fs_cli_dim (), wrapped, fs_cli_reset ());
		g_free (wrapped);
	}
	g_free (title);
	g_free (body);
}

static void
verdict_json (GString *out, const FsVerdictResult *v)
{
	g_string_append_c (out, '{');
	fs_json_kv_str (out, "level", fs_verdict_level_name (v->level));
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "key", v->key);     g_string_append_c (out, ',');
	fs_json_kv_str (out, "word", v->word);   g_string_append_c (out, ',');
	fs_json_kv_str (out, "title", v->title); g_string_append_c (out, ',');
	fs_json_kv_str (out, "body", v->body);
	g_string_append_c (out, '}');
}

/* -------------------------------------------------------------- status */

gint
fs_cli_cmd_status (gint argc, gchar **argv)
{
	const FsBackend *backend = fs_backend ();
	gboolean root = (geteuid () == 0);
	gboolean verbose = FALSE;
	gboolean on_disk;
	gint malformed;
	FsPolicy *policy, *applied = NULL;
	FsPolicyImpact *impact = NULL;
	FsFirewallState state = FS_FW_NONE;
	const gchar *hold = fs_apply_hold_reason ();
	GList *stats = NULL, *conns = NULL;
	const gchar *state_word;
	FsIpv6State ipv6;
	gchar *ipv6_detail = NULL;
	FsCliLive live;
	gboolean settings_pending = FALSE;
	FsCliAuditEntry *last_apply;
	gboolean readable;
	gchar *mon_source = NULL, *mon_problem = NULL;
	gint64 blocked;
	FsHit *last_block = NULL;
	const gchar *blocked_source = NULL;
	FsBootUnit boot = fs_autostart_boot_unit ();
	const gchar *host = g_get_host_name ();
	FsVerdictResult *verdict = NULL;

	for (gint i = 1; i < argc; i++) {
		if (!fs_cli_is_option_at (argv, i)) {
			fs_cli_error ("status takes no arguments");
			return FS_EXIT_USAGE;
		}
		if (strcmp (argv[i], "-v") == 0 ||
		    strcmp (argv[i], "--verbose") == 0) {
			verbose = TRUE;
		} else if (strcmp (argv[i], "--utc") == 0) {
			fs_cli.utc = TRUE;
		} else {
			fs_cli_unknown_option ("status", argv[i]);
			return FS_EXIT_USAGE;
		}
	}

	policy = fs_cli_load_policy (&on_disk, &malformed);

	/* Reading netfilter needs CAP_NET_ADMIN.  Without it the backend
	 * would answer "stopped" for a firewall it could not see; say
	 * "unknown" instead. */
	if (root)
		state = backend->get_state ();
	state_word = state_name (state);

	live = fs_cli_policy_state (policy, &applied, &settings_pending);
	if (applied != NULL)
		impact = fs_policy_impact (applied, policy);
	last_apply = fs_cli_audit_last_apply ();
	/* Decided by trying to read, never by the user id (survey A10). */
	readable = fs_cli_log_readable (&mon_source, &mon_problem);
	blocked = fs_cli_blocked_today (&last_block, &blocked_source);

	/* -q: one line, for a prompt or a script. */
	if (fs_cli.quiet && !fs_cli.json) {
		GString *line = g_string_new (state_word);

		if (state != FS_FW_STOPPED) {
			if (live == FS_CLI_LIVE_SAME)
				g_string_append (line, ", live");
			else if (live == FS_CLI_LIVE_PENDING && impact != NULL)
				g_string_append_printf (line, ", %u change%s pending",
				                        impact->added + impact->removed,
				                        impact->added + impact->removed == 1
				                        ? "" : "s");
			else if (live == FS_CLI_LIVE_PENDING)
				g_string_append (line, ", changes pending");
			else if (live == FS_CLI_LIVE_NO_JOURNAL)
				g_string_append (line, ", never applied");
		}
		if (settings_pending)
			g_string_append (line, ", settings pending");
		if (hold != NULL)
			g_string_append (line, ", audit-only");
		printf ("%s\n", line->str);
		g_string_free (line, TRUE);
		goto done;
	}

	if (backend->list_interface_stats != NULL)
		stats = backend->list_interface_stats ();
	if (backend->list_connections != NULL)
		conns = backend->list_connections ();

	/* IPv6: Linux answers (1.0.7); a backend without the slot covers
	 * both families with every rule (Windows Firewall). */
	if (backend->ipv6_state != NULL) {
		ipv6 = backend->ipv6_state (&ipv6_detail);
	} else {
		ipv6 = FS_IPV6_FILTERED;
		ipv6_detail = g_strdup ("Windows Firewall applies every rule to "
		                        "IPv4 and IPv6.");
	}

	/* Line 1 (and "verdict" in --json): the Overview's judgement. */
	verdict = status_verdict (state, backend->ipv6_state != NULL, ipv6,
	                          ipv6_detail, hold);

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "version", FS_VERSION);       g_string_append_c (out, ',');
		fs_json_kv_str (out, "backend", backend->name);   g_string_append_c (out, ',');
		fs_json_kv_str (out, "state", state_word);        g_string_append_c (out, ',');
		fs_json_key (out, "verdict");
		verdict_json (out, verdict);
		g_string_append_c (out, ',');
		fs_json_key (out, "ipv6");
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "state", fs_ipv6_state_to_string (ipv6));  g_string_append_c (out, ',');
		fs_json_kv_str (out, "detail", ipv6_detail);
		g_string_append (out, "},");
		fs_json_kv_bool (out, "root", root);              g_string_append_c (out, ',');
		fs_json_kv_str (out, "rules_dir", fs_util_rules_dir ()); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "policy_saved", on_disk);   g_string_append_c (out, ',');
		fs_json_kv_int (out, "malformed_rules", malformed); g_string_append_c (out, ',');
		fs_json_key (out, "rules");
		g_string_append_c (out, '{');
		for (gint k = 0; k < FS_RULE_N_KINDS; k++) {
			if (k > 0)
				g_string_append_c (out, ',');
			fs_json_kv_uint (out, fs_cli_kind_name ((FsRuleKind) k),
			                 fs_policy_count (policy, (FsRuleKind) k));
		}
		g_string_append (out, "},");
		fs_json_kv_str (out, "apply_hold", hold);         g_string_append_c (out, ',');
		/* Set by readability since 1.0.8; it was the user id. */
		fs_json_kv_bool (out, "monitoring_available", readable);
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "connections", g_list_length (conns));
		g_string_append_c (out, ',');
		/* Threat intel: the state the kernel is in, never just the
		 * configuration (design 6.6). */
		fs_json_key (out, "intel");
		fs_cli_intel_json (out, FALSE);
		g_string_append (out, ",\"interfaces\":[");
		for (GList *l = stats; l != NULL; l = l->next) {
			FsIfaceStat *s = l->data;

			if (l != stats)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "device", s->device);   g_string_append_c (out, ',');
			fs_json_kv_str (out, "type", s->kind);       g_string_append_c (out, ',');
			fs_json_kv_str (out, "ip", s->ip);           g_string_append_c (out, ',');
			fs_json_kv_bool (out, "up", s->up);          g_string_append_c (out, ',');
			fs_json_kv_uint (out, "received", s->received); g_string_append_c (out, ',');
			fs_json_kv_uint (out, "sent", s->sent);
			g_string_append_c (out, '}');
		}
		g_string_append (out, "],");

		/* 1.0.8 (cli-plan.md C2): fields are only added. */
		fs_json_kv_str (out, "live", fs_cli_live_name (live));
		g_string_append (out, ",\"pending\":");
		if (impact != NULL) {
			g_string_append_c (out, '{');
			fs_json_kv_uint (out, "added", impact->added);
			g_string_append_c (out, ',');
			fs_json_kv_uint (out, "removed", impact->removed);
			g_string_append_c (out, ',');
			fs_json_kv_bool (out, "settings", settings_pending);
			g_string_append_c (out, '}');
		} else {
			g_string_append (out, "null");
		}
		g_string_append (out, ",\"last_apply\":");
		if (last_apply != NULL)
			fs_cli_audit_entry_json (out, last_apply, FALSE);
		else
			g_string_append (out, "null");
		g_string_append (out, ",\"monitoring\":{");
		fs_json_kv_bool (out, "readable", readable);    g_string_append_c (out, ',');
		fs_json_kv_str (out, "source", mon_source);     g_string_append_c (out, ',');
		fs_json_kv_str (out, "problem", mon_problem);
		g_string_append (out, "},\"blocked_today\":");
		if (blocked >= 0)
			g_string_append_printf (out, "%" G_GINT64_FORMAT, blocked);
		else
			g_string_append (out, "null");
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "blocked_source", blocked_source);
		g_string_append (out, ",\"last_block\":");
		if (last_block != NULL)
			fs_cli_hit_row_json (out, last_block);
		else
			g_string_append (out, "null");
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "boot_unit", boot_unit_name (boot));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "host", host);

		if (verbose) {
			GHashTable *values = fs_prefs_firewall_values ();
			GHashTableIter it;
			gpointer k, v;
			gboolean first = TRUE;
			gint64 next_lift = 0;
			gint staged = fs_cli_sentinel_staged (&next_lift);
			gchar *mode = fs_prefs_get_string (FS_PREFS_SENTINEL_MODE,
			                                   "auto");
			gchar *dir = fs_eventlog_default_dir ();
			guint64 bytes = 0;
			guint files = 0;

			if (g_file_test (dir, G_FILE_TEST_IS_DIR))
				fs_eventlog_usage (dir, &bytes, &files);

			g_string_append (out, ",\"settings\":{");
			g_hash_table_iter_init (&it, values);
			while (g_hash_table_iter_next (&it, &k, &v)) {
				if (!first)
					g_string_append_c (out, ',');
				first = FALSE;
				fs_json_kv_str (out, k, v);
			}
			g_string_append (out, "},\"sentinel\":{");
			fs_json_kv_str (out, "mode", mode != NULL && *mode ? mode
			                                                   : "auto");
			g_string_append_c (out, ',');
			fs_json_kv_int (out, "staged", staged);
			g_string_append (out, ",\"next_lift_epoch\":");
			if (next_lift > 0)
				g_string_append_printf (out, "%" G_GINT64_FORMAT,
				                        next_lift);
			else
				g_string_append (out, "null");
			g_string_append (out, "},\"history\":{");
			fs_json_kv_bool (out, "enabled",
			                 fs_prefs_bool (FS_PREFS_EVENTS_HISTORY));
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "dir", dir);           g_string_append_c (out, ',');
			fs_json_kv_uint (out, "bytes", bytes);      g_string_append_c (out, ',');
			fs_json_kv_uint (out, "files", files);
			g_string_append (out, "},");
			fs_json_kv_str (out, "policy_lock",
			                "Desktop app Policy Lock is not enforced by "
			                "the CLI");
			g_free (dir);
			g_free (mode);
			g_hash_table_unref (values);
		}
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		const gchar *dot, *color;
		gchar *safe_host = fs_cli_out_safe (host);
		GString *t = g_string_new (NULL);
		guint total = fs_cli_policy_total (policy);

		if (state == FS_FW_RUNNING) {
			dot = fs_cli_sym (FS_CLI_SYM_ON); color = fs_cli_green ();
		} else if (state == FS_FW_STOPPED) {
			dot = fs_cli_sym (FS_CLI_SYM_OFF); color = fs_cli_red ();
		} else {
			dot = "?"; color = fs_cli_amber ();
		}

		print_verdict (verdict);
		printf ("\n%sStockFW %s%s  %s%s %s %s%s\n\n", fs_cli_bold (),
		        FS_VERSION, fs_cli_reset (), fs_cli_dim (),
		        backend->display_name, fs_cli_sym (FS_CLI_SYM_SEP),
		        safe_host, fs_cli_reset ());
		g_free (safe_host);

		printf ("  %-12s %s%s %s%s", "Firewall", color, dot, state_word,
		        fs_cli_reset ());
		if (!root)
			printf ("%s  (reading the firewall needs root)%s",
			        fs_cli_dim (), fs_cli_reset ());
		printf ("\n");

		/* IPv6 gets its own line: "running" says nothing about a
		 * family that passes unfiltered. */
		{
			const gchar *c6 = ipv6 == FS_IPV6_FILTERED ? fs_cli_green ()
			                : ipv6 == FS_IPV6_UNFILTERED ? fs_cli_amber ()
			                : fs_cli_dim ();
			const gchar *w6 = ipv6 == FS_IPV6_FILTERED ? "filtered"
			                : ipv6 == FS_IPV6_UNFILTERED ? "not filtered"
			                : ipv6 == FS_IPV6_ABSENT ? "none on this system"
			                : "unknown";

			printf ("  %-12s %s%s%s", "IPv6", c6, w6, fs_cli_reset ());
			if (ipv6_detail != NULL && ipv6 != FS_IPV6_FILTERED &&
			    ipv6 != FS_IPV6_ABSENT)
				printf ("%s  (%s)%s", fs_cli_dim (), ipv6_detail,
				        fs_cli_reset ());
			printf ("\n");
		}

		/* Policy: is what is saved what is live? */
		if (!on_disk) {
			g_string_printf (t, "none saved yet in %s",
			                 fs_util_rules_dir ());
		} else {
			g_string_printf (t, "%u rule%s, ", total,
			                 total == 1 ? "" : "s");
			switch (live) {
			case FS_CLI_LIVE_SAME:
				g_string_append (t, "live");
				break;
			case FS_CLI_LIVE_PENDING:
				if (impact != NULL &&
				    impact->added + impact->removed > 0)
					g_string_append_printf (
						t, "%u change%s not applied (stockfw policy diff)",
						impact->added + impact->removed,
						impact->added + impact->removed == 1 ? "" : "s");
				else
					g_string_append (t, "saved in another order than "
					                    "applied (stockfw apply)");
				break;
			case FS_CLI_LIVE_NO_JOURNAL:
				g_string_append (t, "never applied (stockfw apply)");
				break;
			case FS_CLI_LIVE_STOPPED:
				g_string_append (t, "firewall stopped");
				break;
			default:
				g_string_append (t, root ? "live state unknown (the "
				                           "apply record cannot be read)"
				                         : "unknown (needs root)");
				break;
			}
			if (settings_pending)
				g_string_append (t, "; settings changed since the last "
				                    "apply");
		}
		print_line ("Policy", t->str);

		if (malformed > 0)
			printf ("  %-12s %s%d malformed rule%s skipped%s\n", "",
			        fs_cli_amber (), malformed, malformed == 1 ? "" : "s",
			        fs_cli_reset ());

		if (last_apply != NULL) {
			gchar *when = local_stamp (last_apply->epoch,
			                           "%Y-%m-%d %H:%M");
			gchar *what = fs_cli_out_safe (last_apply->action);

			g_string_printf (t, "%s  %s", when, what);
			if (last_apply->origin != NULL)
				g_string_append_printf (t, " (%s)", last_apply->origin);
			print_line ("Last apply", t->str);
			g_free (what);
			g_free (when);
		} else {
			print_line ("Last apply", "none recorded");
		}

		if (blocked < 0) {
			print_line ("Blocked", "today: unknown (no log to read)");
		} else {
			gchar *n = thousands (blocked);

			g_string_printf (t, "today %s", n);
			if (last_block != NULL) {
				gboolean in = g_strcmp0 (last_block->direction, "out") != 0;
				gchar *proto = fs_cli_out_safe (last_block->protocol
				                                ? last_block->protocol
				                                : "-");
				gchar *port = fs_cli_out_safe (last_block->port
				                               ? last_block->port : "");
				gchar *peer = fs_cli_out_safe (in ? last_block->source
				                               : last_block->destination);
				gchar *at = local_stamp (hit_epoch (last_block), "%H:%M");

				g_string_append_printf (t, " %s last %s%s%s %s %s at %s",
				                        fs_cli_sym (FS_CLI_SYM_SEP), proto,
				                        *port ? " " : "", port,
				                        in ? "from" : "to", peer, at);
				g_free (proto);
				g_free (port);
				g_free (peer);
				g_free (at);
			}
			print_line ("Blocked", t->str);
			g_free (n);
		}

		fs_cli_intel_status_line ();

		print_line ("Apply mode", hold != NULL
		            ? "audit-only: applies are recorded, the firewall is "
		              "left untouched"
		            : "live");

		if (readable) {
			gchar *src = fs_cli_out_safe (mon_source);

			g_string_printf (t, "reading %s", src);
			g_free (src);
		} else {
			gchar *why = fs_cli_out_safe (mon_problem);

			g_string_printf (t, "%s%s%s", fs_cli_amber (),
			                 "not available", fs_cli_reset ());
			if (*why)
				g_string_append_printf (t, "%s  (%s)%s", fs_cli_dim (),
				                        why, fs_cli_reset ());
			g_free (why);
		}
		print_line ("Monitoring", t->str);

		switch (boot) {
		case FS_BOOT_UNIT_ENABLED:
			print_line ("At boot", "stockfw.service enabled");
			break;
		case FS_BOOT_UNIT_DISABLED:
			print_line ("At boot", "stockfw.service installed, not enabled");
			break;
		case FS_BOOT_UNIT_ABSENT:
			print_line ("At boot", "no stockfw.service: the rules are not "
			                       "put back at boot");
			break;
		default:
			break;
		}

		if (verbose) {
			GHashTable *values = fs_prefs_firewall_values ();
			gint64 next_lift = 0;
			gint staged = fs_cli_sentinel_staged (&next_lift);
			gchar *mode = fs_prefs_get_string (FS_PREFS_SENTINEL_MODE,
			                                   "auto");
			gchar *dir = fs_eventlog_default_dir ();

			printf ("\n");
			print_line ("Rules dir", fs_util_rules_dir ());
			for (gint k = 0; k < FS_RULE_N_KINDS; k++) {
				guint n = fs_policy_count (policy, (FsRuleKind) k);

				if (n > 0)
					printf ("  %-12s %s%3u  %s%s\n", "", fs_cli_dim (), n,
					        fs_cli_kind_name ((FsRuleKind) k),
					        fs_cli_reset ());
			}
			print_settings (values);

			if (fs_prefs_bool (FS_PREFS_EVENTS_HISTORY)) {
				guint64 bytes = 0;
				guint files = 0;
				gchar *size;

				if (g_file_test (dir, G_FILE_TEST_IS_DIR))
					fs_eventlog_usage (dir, &bytes, &files);
				size = fs_cli_format_bytes (bytes);
				g_string_printf (t, "kept, %s in %u file%s (%s)", size,
				                 files, files == 1 ? "" : "s", dir);
				g_free (size);
			} else {
				g_string_assign (t, "not kept");
			}
			print_line ("History", t->str);

			g_string_printf (t, "%s, %d staged",
			                 mode != NULL && *mode ? mode : "auto", staged);
			if (next_lift > 0) {
				gchar *at = local_stamp (next_lift, "%H:%M:%S");

				g_string_append_printf (t, ", next lift %s", at);
				g_free (at);
			}
			g_string_append (t, " (stockfw sentinel)");
			print_line ("Sentinel", t->str);
			print_line ("Note", "Desktop app Policy Lock is not enforced "
			                    "by the CLI");
			printf ("\n");
			g_free (dir);
			g_free (mode);
			g_hash_table_unref (values);
		}

		for (GList *l = stats; l != NULL; l = l->next) {
			FsIfaceStat *s = l->data;
			gchar *rx = fs_cli_format_bytes (s->received);
			gchar *tx = fs_cli_format_bytes (s->sent);

			gchar *dev = fs_cli_out_safe (s->device);

			printf ("  %-12s %-10s %-15s %s %s  %s %s%s\n",
			        l == stats ? "Adapters" : "", dev,
			        s->ip ? s->ip : "-", fs_cli_sym (FS_CLI_SYM_DOWN), rx,
			        fs_cli_sym (FS_CLI_SYM_UP), tx,
			        s->up ? "" : "  (down)");
			g_free (dev);
			g_free (rx);
			g_free (tx);
		}

		printf ("  %-12s %u active\n", "Connections", g_list_length (conns));
		g_string_free (t, TRUE);
	}

done:
	fs_verdict_result_free (verdict);
	g_list_free_full (stats, (GDestroyNotify) fs_iface_stat_free);
	g_list_free_full (conns, (GDestroyNotify) fs_connection_free);
	g_free (ipv6_detail);
	g_free (mon_source);
	g_free (mon_problem);
	if (last_block != NULL)
		fs_hit_free (last_block);
	fs_cli_audit_entry_free (last_apply);
	if (impact != NULL)
		fs_policy_impact_free (impact);
	fs_policy_free (applied);
	fs_policy_free (policy);

	return FS_EXIT_OK;
}

/* === end WP-C === */

/* ---------------------------------------------------------------- stop */

/* [ fs_cli_stop_consequence ] -- what a stop takes away, in the words
 * of the desktop app's "Pause protection?" (B5), for this backend. */
const gchar *
fs_cli_stop_consequence (void)
{
	if (fs_backend ()->start_applies_policy)
		return "StockFW takes its rules out of the firewall.  Until you "
		       "start it again, the ports and addresses your policy "
		       "blocks are no longer blocked, and threat-intel "
		       "blocklists are taken down too.  `stockfw start' puts "
		       "the last applied policy back.";
	return "Windows Defender Firewall is switched off for every network "
	       "profile (Domain, Private and Public).  Until you start it "
	       "again, nothing is filtered.  Your rules are kept.";
}

/* [ fs_cli_stop_confirm ] -- see fs-cli.h. */
gboolean
fs_cli_stop_confirm (gboolean yes)
{
	const FsBackend *backend = fs_backend ();
	gchar answer[16] = "";
	gchar *text;

	if (yes || !isatty (STDIN_FILENO))
		return TRUE;
	/* Stopped already: there is no protection to pause. */
	if (backend->get_state != NULL &&
	    backend->get_state () == FS_FW_STOPPED)
		return TRUE;

	text = indent_wrap (fs_cli_stop_consequence (), 2);
	fprintf (stderr, "%sPause protection?%s\n%s\n", fs_cli_bold (),
	         fs_cli_reset (), text);
	g_free (text);
	/* Enter must not switch a firewall off: No is the default. */
	fprintf (stderr, "Stop the firewall? [y/N] ");
	fflush (stderr);
	if (fgets (answer, sizeof answer, stdin) != NULL &&
	    (g_ascii_strcasecmp (g_strstrip (answer), "y") == 0 ||
	     g_ascii_strcasecmp (answer, "yes") == 0))
		return TRUE;
	fs_cli_error ("not stopped: the firewall was left as it was");
	return FALSE;
}

/* ------------------------------------------------------------ snapshot */

/* [ fs_cli_status_snapshot ]
 * The facts of the live event line: the firewall state (root only),
 * live or pending, the audit-only hold, blocked today, the Sentinel
 * mode and staged count, and whether the log can be read -- the same
 * readers `stockfw status' uses. */
FsCliStatusSnapshot *
fs_cli_status_snapshot (void)
{
	FsCliStatusSnapshot *snap = g_new0 (FsCliStatusSnapshot, 1);
	FsPolicy *saved = fs_cli_load_policy (NULL, NULL);

	snap->state = FS_FW_NONE;
	if (geteuid () == 0 && fs_backend ()->get_state != NULL)
		snap->state = fs_backend ()->get_state ();
	snap->live = fs_cli_policy_state (saved, NULL, &snap->settings_pending);
	snap->held = fs_apply_hold_reason () != NULL;
	snap->blocked_today = fs_cli_blocked_today (NULL, NULL);
	snap->sentinel_mode = fs_prefs_get_string (FS_PREFS_SENTINEL_MODE,
	                                           "auto");
	snap->sentinel_staged = fs_cli_sentinel_staged (NULL);
	snap->monitor_readable = fs_cli_log_readable (&snap->monitor_source,
	                                              &snap->monitor_problem);
	fs_policy_free (saved);
	return snap;
}

void
fs_cli_status_snapshot_free (FsCliStatusSnapshot *snap)
{
	if (snap == NULL)
		return;
	g_free (snap->sentinel_mode);
	g_free (snap->monitor_source);
	g_free (snap->monitor_problem);
	g_free (snap);
}

/* ------------------------------------------------------- the commands */

static const FsCliOption status_opts[] = {
	{ "-v",        FALSE, NULL },
	{ "--verbose", FALSE, NULL },
	{ "--utc",     FALSE, NULL },
	{ NULL, FALSE, NULL }
};

const FsCliCommandDef fs_cli_status_commands[] = {
	{ "status", fs_cli_cmd_status,
"Usage: stockfw status [-v] [--utc] [--json]\n"
"\n"
"The first line is the verdict of the desktop app's Overview: \"This\n"
"computer is protected\", \"IPv6 is not protected\", \"This computer is\n"
"not protected\" or \"The firewall's state is unknown\" (without root),\n"
"with its reasons under it: IPv6, audit-only mode holding changes, and\n"
"whether the threat-intel blocklists are in force.  --json gives it as\n"
"\"verdict\": {level, key, word, title, body}.\n"
"\n"
"Then it shows the firewall state, whether the saved policy is the one that\n"
"is live (or how many changes are not applied yet), the last apply,\n"
"start or stop from the audit log, how many packets were blocked\n"
"today and the last one, whether audit-only mode holds applies back,\n"
"which kernel log this account can read (tried, not guessed from the\n"
"user id), whether stockfw.service puts the rules back at boot, and\n"
"the adapters and connection count.  Reading the firewall state\n"
"needs root; without it the state is reported as unknown.\n"
"\n"
"-v adds the rules directory, the firewall settings (outbound mode,\n"
"DROP or REJECT, ICMP, logging, interfaces, NAT), the event history\n"
"and Sentinel.  -q prints one line: \"running, live\".\n",
	  status_opts, NULL },

	{ NULL, NULL, NULL, NULL, NULL }
};
