/*---[ fs-cli-cmds.c ]------------------------------------------------------
 * Helpers the `stockfw' commands share: rule kinds, the policy,
 * What-If, the kernel log, event rows.  The commands themselves live in
 * fs-cli-policy.c, fs-cli-status.c, fs-cli-events.c, fs-cli-views.c,
 * fs-cli-intel.c and fs-dashboard.c.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "core/fs-apply.h"
#include "core/fs-audit.h"
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

#include <glib-unix.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <errno.h>
#include <fcntl.h>
#ifndef G_OS_WIN32
#include <grp.h>
#endif
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------- helpers */

static const gchar *kind_names[FS_RULE_N_KINDS] = {
	"inbound-allow-from",
	"inbound-allow-service",
	"inbound-forward",
	"outbound-allow-to",
	"outbound-allow-from",
	"outbound-allow-service",
	"outbound-deny-to",
	"outbound-deny-from",
	"outbound-deny-service",
};

const gchar *
fs_cli_kind_name (FsRuleKind kind)
{
	return (kind >= 0 && kind < FS_RULE_N_KINDS) ? kind_names[kind] : "?";
}

const gchar * const *
fs_cli_kind_names (void)
{
	return kind_names;
}

gboolean
fs_cli_kind_parse (const gchar *name, FsRuleKind *kind)
{
	for (gint i = 0; i < FS_RULE_N_KINDS; i++) {
		if (g_strcmp0 (name, kind_names[i]) == 0) {
			*kind = (FsRuleKind) i;
			return TRUE;
		}
	}

	return FALSE;
}

gchar *
fs_cli_rule_summary (const FsRule *rule)
{
	switch (rule->kind) {
	case FS_RULE_INBOUND_FORWARD:
		/* [addr]:port for IPv6, as DNAT writes it: 2001:db8::5:80
		 * reads as a different address. */
		return g_strdup_printf ("%s  port %s -> %s%s%s:%s",
		                        rule->service ? rule->service : "?",
		                        rule->port ? rule->port : "?",
		                        fs_util_target_families (rule->to) ==
		                            FS_FAMILY_IPV6 ? "[" : "",
		                        rule->to ? rule->to : "?",
		                        fs_util_target_families (rule->to) ==
		                            FS_FAMILY_IPV6 ? "]" : "",
		                        rule->to_port ? rule->to_port : "?");
	case FS_RULE_INBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_DENY_SERVICE:
		return g_strdup_printf ("%s  port %s  for %s",
		                        rule->service ? rule->service : "?",
		                        rule->port ? rule->port : "?",
		                        rule->target ? rule->target : "?");
	default:
		return g_strdup (rule->target ? rule->target : "?");
	}
}

FsPolicy *
fs_cli_load_policy (gboolean *on_disk, gint *malformed)
{
	FsPolicy *policy = fs_policy_new ();
	gint bad = 0;
	gboolean any = fs_policy_load (policy, &bad);

	if (on_disk != NULL)
		*on_disk = any;
	if (malformed != NULL)
		*malformed = bad;

	return policy;
}

gint
fs_cli_need_root (const gchar *what)
{
	/* The user's own command again, with sudo and this program's full
	 * path: a bare program name may find another copy, or none, on
	 * root's PATH. */
	gchar *args = fs_cli_user_args ();
	gchar *again = fs_cli_sudo_hint (*args != '\0' ? args : what);

	fs_cli_error ("%s needs root privileges", what);
	fs_cli_hint (FS_CLI_RIGHTS ", e.g. `%s'", again);
	g_free (again);
	g_free (args);
	return FS_EXIT_NEED_ROOT;
}

/* [ backend_context ]
 * The Linux backend builds iptables rules from the policy and the
 * Advanced Options settings; hand it both, as the app does at start. */
FsSettings *
fs_cli_backend_context (FsPolicy *policy)
{
	FsSettings *settings = fs_settings_new ();

	fs_settings_load_prefs (settings);
	fs_backend_set_context (policy, settings);

	return settings;
}

guint
fs_cli_policy_total (const FsPolicy *policy)
{
	guint total = 0;

	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		total += fs_policy_count (policy, (FsRuleKind) k);

	return total;
}

/* [ hit_row_json ] -- one event as a JSON object. */
void
fs_cli_hit_row_json (GString *out, const FsHit *hit)
{
	gchar *service = fs_hit_service_name (hit);

	g_string_append_c (out, '{');
	fs_json_kv_str (out, "time", hit->time);             g_string_append_c (out, ',');
	fs_json_kv_str (out, "direction", hit->direction);   g_string_append_c (out, ',');
	fs_json_kv_str (out, "source", hit->source);         g_string_append_c (out, ',');
	fs_json_kv_str (out, "destination", hit->destination); g_string_append_c (out, ',');
	fs_json_kv_str (out, "port", hit->port);             g_string_append_c (out, ',');
	fs_json_kv_str (out, "protocol", hit->protocol);     g_string_append_c (out, ',');
	fs_json_kv_str (out, "service", service);            g_string_append_c (out, ',');
	fs_json_kv_str (out, "in", hit->in);                 g_string_append_c (out, ',');
	fs_json_kv_str (out, "out", hit->out);               g_string_append_c (out, ',');
	fs_json_kv_str (out, "rule", hit->rule);             g_string_append_c (out, ',');
	fs_json_kv_bool (out, "blocked", fs_hit_is_blocked (hit));
	g_string_append_c (out, '}');
	g_free (service);
}

/* [ local_time ] -- an event's ISO UTC stamp in local time. */
gchar *
fs_cli_local_time (const gchar *iso)
{
	GDateTime *utc, *local;
	gchar *text;

	if (iso == NULL)
		return g_strdup ("");

	utc = g_date_time_new_from_iso8601 (iso, NULL);
	if (utc == NULL)
		return g_strdup (iso);

	if (fs_cli.utc) {
		text = fs_cli_time_text (g_date_time_to_unix (utc),
		                         FS_CLI_TIME_ISO);
		g_date_time_unref (utc);
		return text;
	}

	local = g_date_time_to_local (utc);
	text  = g_date_time_format (local, "%b %d %H:%M:%S");
	g_date_time_unref (local);
	g_date_time_unref (utc);

	return text;
}

/* [ append_lines_json ] -- "a\nb" as ["a","b"]; NULL as []. */
void
fs_cli_append_lines_json (GString *out, const gchar *text)
{
	gchar **lines = g_strsplit (text != NULL ? text : "", "\n", -1);
	gboolean first = TRUE;

	g_string_append_c (out, '[');
	for (gint i = 0; lines[i] != NULL; i++) {
		if (*lines[i] == '\0')
			continue;
		if (!first)
			g_string_append_c (out, ',');
		fs_json_string (out, lines[i]);
		first = FALSE;
	}
	g_string_append_c (out, ']');
	g_strfreev (lines);
}

/* [ print_notes ] -- an apply's notes, one amber line each. */
void
fs_cli_print_notes (const gchar *notes)
{
	gchar **lines;

	/* -q: no notes (cli-plan.md section 4, A1). */
	if (notes == NULL || fs_cli.quiet)
		return;

	lines = g_strsplit (notes, "\n", -1);
	for (gint i = 0; lines[i] != NULL; i++) {
		gchar *safe;

		if (*lines[i] == '\0')
			continue;
		safe = fs_cli_out_safe (lines[i]);
		printf ("%snote:%s %s\n", fs_cli_amber (), fs_cli_reset (), safe);
		g_free (safe);
	}
	g_strfreev (lines);
}

/* ------------------------------------------------------- policy state */

const gchar *
fs_cli_live_name (FsCliLive live)
{
	switch (live) {
	case FS_CLI_LIVE_SAME:       return "same";
	case FS_CLI_LIVE_PENDING:    return "pending";
	case FS_CLI_LIVE_NO_JOURNAL: return "no_journal";
	case FS_CLI_LIVE_STOPPED:    return "stopped";
	default:                     return "unknown";
	}
}

FsCliLive
fs_cli_policy_state (const FsPolicy *saved, FsPolicy **applied_out,
                     gboolean *settings_pending)
{
	FsPolicy *applied = fs_policy_new ();
	GError *error = NULL;
	FsCliLive live;

	if (applied_out != NULL)
		*applied_out = NULL;
	if (settings_pending != NULL)
		*settings_pending = FALSE;

	if (!fs_apply_journal_load (applied, &error)) {
		live = g_error_matches (error, FS_APPLY_ERROR,
		                        FS_APPLY_ERR_NO_JOURNAL)
		       ? FS_CLI_LIVE_NO_JOURNAL : FS_CLI_LIVE_UNKNOWN;
		g_clear_error (&error);
		fs_policy_free (applied);
		return live;
	}

	if (settings_pending != NULL)
		*settings_pending = fs_apply_settings_pending ();

	/* Reading netfilter needs root; without it "stopped" is a guess. */
	if (geteuid () == 0 && fs_backend ()->get_state != NULL &&
	    fs_backend ()->get_state () == FS_FW_STOPPED)
		live = FS_CLI_LIVE_STOPPED;
	else if (saved != NULL && fs_whatif_policy_same (saved, applied))
		live = FS_CLI_LIVE_SAME;
	else
		live = FS_CLI_LIVE_PENDING;

	if (applied_out != NULL)
		*applied_out = applied;
	else
		fs_policy_free (applied);
	return live;
}

/* ------------------------------------------------------- references */

gchar *
fs_cli_rule_ref (FsRuleKind kind, guint number)
{
	return g_strdup_printf ("%s:%u", fs_cli_kind_name (kind), number);
}

/* [ ref_number ] -- a 1-based rule number, digits only. */
static gboolean
ref_number (const gchar *text, guint *number)
{
	gchar *end = NULL;
	guint64 n;

	if (text == NULL || !g_ascii_isdigit (*text))
		return FALSE;
	n = g_ascii_strtoull (text, &end, 10);
	if (end == NULL || *end != '\0' || n == 0 || n > G_MAXUINT)
		return FALSE;
	*number = (guint) n;
	return TRUE;
}

gboolean
fs_cli_rule_ref_parse (const gchar *text, const gchar *next_arg,
                       FsRuleKind *kind, guint *number, gboolean *used_next)
{
	const gchar *sep;

	if (used_next != NULL)
		*used_next = FALSE;
	if (text == NULL)
		return FALSE;

	/* KIND:N, and KIND#N as typed in a shell without EXTENDED_GLOB. */
	sep = strpbrk (text, ":#");
	if (sep != NULL) {
		gchar *name = g_strndup (text, (gsize) (sep - text));
		gboolean ok = fs_cli_kind_parse (name, kind) &&
		              ref_number (sep + 1, number);

		g_free (name);
		return ok;
	}

	/* KIND N, as two words. */
	if (fs_cli_kind_parse (text, kind) && ref_number (next_arg, number)) {
		if (used_next != NULL)
			*used_next = TRUE;
		return TRUE;
	}
	return FALSE;
}

/* ------------------------------------------------------- the kernel log */

#ifndef G_OS_WIN32
/* [ in_group ] -- is this process a member of the named group? */
static gboolean
in_group (const gchar *name)
{
	struct group *gr = getgrnam (name);
	gid_t groups[256];
	gint n;

	if (gr == NULL)
		return FALSE;
	if (getegid () == gr->gr_gid)
		return TRUE;
	n = getgroups (G_N_ELEMENTS (groups), groups);
	for (gint i = 0; i < n; i++)
		if (groups[i] == gr->gr_gid)
			return TRUE;
	return FALSE;
}
#endif

/* [ try_open ] -- can the file be opened for reading, now, by us? */
static gboolean
try_open (const gchar *path, gchar **problem)
{
	int fd = g_open (path, O_RDONLY | O_CLOEXEC, 0);

	if (fd >= 0) {
		close (fd);
		return TRUE;
	}
	if (problem != NULL)
		*problem = g_strdup_printf ("cannot read %s: %s", path,
		                            g_strerror (errno));
	return FALSE;
}

gboolean
fs_cli_log_readable (gchar **source, gchar **problem)
{
	const gchar *override = g_getenv ("STOCKFW_LOG_FILE");

	if (source != NULL)
		*source = NULL;
	if (problem != NULL)
		*problem = NULL;

	/* The same order fs_cli_log_history reads in. */
	if (override != NULL && *override != '\0') {
		if (source != NULL)
			*source = g_strdup (override);
		return try_open (override, problem);
	}
	if (g_file_test ("/var/log/kern.log", G_FILE_TEST_EXISTS)) {
		if (source != NULL)
			*source = g_strdup ("/var/log/kern.log");
		return try_open ("/var/log/kern.log", problem);
	}

	if (source != NULL)
		*source = g_strdup ("the journal");
#ifndef G_OS_WIN32
	if (geteuid () == 0 || in_group ("systemd-journal") ||
	    in_group ("adm"))
		return TRUE;
#endif
	if (problem != NULL)
		*problem = g_strdup ("the journal's kernel messages are for root "
		                     "and the systemd-journal and adm groups");
	return FALSE;
}
/* ------------------------------------------------------------ what-if */

/* [ fs_cli_whatif ] */
FsWhatIfResult *
fs_cli_whatif (const gchar *line, gboolean assume_running)
{
	FsPolicy *policy = fs_cli_load_policy (NULL, NULL);
	FsWhatIfResult *result = fs_cli_whatif_policy (policy, line,
	                                               assume_running);

	fs_policy_free (policy);
	return result;
}

/* [ fs_cli_whatif_policy ]
 * Sentinel's staged blocks are not added yet: their reader is WP-C's
 * (cli-plan.md A3). */
FsWhatIfResult *
fs_cli_whatif_policy (const FsPolicy *policy, const gchar *line,
                      gboolean assume_running)
{
	FsSettings *settings = fs_settings_new ();
	FsWhatIfContext *ctx;
	FsWhatIfResult *result;

	fs_settings_load_prefs (settings);
	ctx = fs_whatif_context_new (fs_whatif_native_platform (), policy,
	                             settings);

	/* Reading netfilter needs CAP_NET_ADMIN: without it every chain
	 * reads as missing, and "stopped" would turn into "allowed". */
	fs_copilot_whatif_observe (ctx, fs_backend (), geteuid () == 0);
	if (assume_running)
		ctx->firewall = FS_WHATIF_FW_RUNNING;
	fs_copilot_whatif_live (ctx, policy, fs_apply_hold_reason ());

	result = fs_whatif_simulate_text (ctx, line);

	fs_whatif_context_free (ctx);
	fs_settings_free (settings);
	return result;
}

static const gchar *
whatif_origin_word (FsWhatIfOrigin origin)
{
	switch (origin) {
	case FS_WHATIF_ORIGIN_DEFAULT:  return "default";
	case FS_WHATIF_ORIGIN_POLICY:   return "policy";
	case FS_WHATIF_ORIGIN_SENTINEL: return "sentinel";
	case FS_WHATIF_ORIGIN_SETTINGS: return "settings";
	case FS_WHATIF_ORIGIN_BUILTIN:  return "builtin";
	case FS_WHATIF_ORIGIN_STOPPED:  return "stopped";
	default:                        return "unknown";
	}
}

static const gchar *
whatif_action_word (FsWhatIfActionKind kind)
{
	switch (kind) {
	case FS_WHATIF_ACT_CREATE_ALLOW:       return "create-allow";
	case FS_WHATIF_ACT_CREATE_BLOCK:       return "create-block";
	case FS_WHATIF_ACT_OPEN_RULE:          return "open-rule";
	case FS_WHATIF_ACT_LIFT_SENTINEL:      return "lift-sentinel";
	case FS_WHATIF_ACT_OPEN_ICMP_SETTINGS: return "open-icmp-settings";
	case FS_WHATIF_ACT_OPEN_SETTINGS:      return "open-settings";
	case FS_WHATIF_ACT_START_FIREWALL:     return "start-firewall";
	case FS_WHATIF_ACT_APPLY_POLICY:       return "apply-policy";
	default:                               return "unknown";
	}
}

static void
json_kv_int (GString *out, const gchar *key, gint value)
{
	if (value < 0) {
		fs_json_kv_str (out, key, NULL);
		return;
	}
	fs_json_kv_uint (out, key, (guint64) value);
}

/* The answer the flat fields describe: the only one, or the first
 * whose verdict is the overall one. */
static const FsWhatIfAnswer *
whatif_main_answer (const FsWhatIfResult *r)
{
	if (r->answers->len == 0)
		return NULL;
	if (r->answers->len == 1)
		return g_ptr_array_index (r->answers, 0);

	for (guint i = 0; i < r->answers->len; i++) {
		const FsWhatIfAnswer *a = g_ptr_array_index (r->answers, i);

		if (a->verdict == r->verdict)
			return a;
	}
	return NULL;
}

/* [ fs_cli_whatif_json ] */
void
fs_cli_whatif_json (GString *out, const FsWhatIfResult *r,
                    const gchar *input)
{
	const FsWhatIfQuery *q = r->query;
	const FsWhatIfAnswer *main_a = whatif_main_answer (r);
	const FsWhatIfAction *primary = fs_whatif_result_primary_action (r);
	const FsWhatIfAction *suggest = primary;

	if (suggest == NULL) {
		for (guint i = 0; i < r->answers->len && suggest == NULL; i++) {
			const FsWhatIfAnswer *a = g_ptr_array_index (r->answers, i);

			if (a->actions->len > 0)
				suggest = g_ptr_array_index (a->actions, 0);
		}
	}

	g_string_append_c (out, '{');
	fs_json_kv_str (out, "input", input);              g_string_append_c (out, ',');
	fs_json_kv_str (out, "verdict", fs_whatif_verdict_name (r->verdict));
	g_string_append_c (out, ',');

	if (r->verdict == FS_WHATIF_ERROR || q == NULL) {
		fs_json_kv_str (out, "error", r->error);
		g_string_append_c (out, '}');
		return;
	}

	fs_json_kv_str (out, "summary", r->summary);        g_string_append_c (out, ',');
	fs_json_kv_str (out, "scenario", r->answers->len == 1 && main_a != NULL
	                                 ? main_a->probe : q->text);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "direction",
	                q->direction == FS_WHATIF_DIR_INBOUND ? "inbound"
	                : q->direction == FS_WHATIF_DIR_OUTBOUND ? "outbound"
	                                                        : "both");
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "protocol",
	                q->protocol == FS_WHATIF_PROTO_TCP ? "TCP"
	                : q->protocol == FS_WHATIF_PROTO_UDP ? "UDP"
	                : q->protocol == FS_WHATIF_PROTO_ICMP ? "ICMP" : NULL);
	g_string_append_c (out, ',');
	if (q->port > 0)
		fs_json_kv_uint (out, "port", q->port);
	else
		fs_json_kv_str (out, "port", NULL);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "remote", q->host);            g_string_append_c (out, ',');
	fs_json_kv_str (out, "rule", main_a != NULL ? main_a->rule : NULL);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "reason", r->answers->len == 1 && main_a != NULL
	                               ? main_a->reason : r->summary);
	g_string_append_c (out, ',');
	if (suggest != NULL) {
		gchar *s = g_strdup_printf ("%s: %s", suggest->label,
		                            suggest->explanation != NULL
		                            ? suggest->explanation : "");

		fs_json_kv_str (out, "suggestion", s);
		g_free (s);
	} else {
		fs_json_kv_str (out, "suggestion", NULL);
	}
	g_string_append_c (out, ',');

	/* What the line was read as. */
	g_string_append_printf (out, "\"confidence\":%.2f,", q->confidence);
	g_string_append (out, "\"read_as\":[");
	for (guint i = 0; i < q->pieces->len; i++) {
		const FsWhatIfPiece *p = g_ptr_array_index (q->pieces, i);

		if (i > 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "text", p->text);       g_string_append_c (out, ',');
		fs_json_kv_str (out, "meaning", p->meaning);
		g_string_append_c (out, '}');
	}
	g_string_append (out, "],");

	/* Each direction in full: trace, cases, actions. */
	g_string_append (out, "\"answers\":[");
	for (guint i = 0; i < r->answers->len; i++) {
		const FsWhatIfAnswer *a = g_ptr_array_index (r->answers, i);

		if (i > 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "direction", a->inbound ? "inbound" : "outbound");
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "verdict", fs_whatif_verdict_name (a->verdict));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "probe", a->probe);      g_string_append_c (out, ',');
		fs_json_kv_str (out, "reason", a->reason);    g_string_append_c (out, ',');
		fs_json_kv_str (out, "rule", a->rule);        g_string_append_c (out, ',');
		fs_json_kv_str (out, "origin", whatif_origin_word (a->origin));
		g_string_append_c (out, ',');
		json_kv_int (out, "policy_kind", a->policy_kind);
		g_string_append_c (out, ',');
		json_kv_int (out, "policy_row", a->policy_index);
		g_string_append (out, ",\"cases\":[");
		for (guint k = 0; k < a->cases->len; k++) {
			const FsWhatIfCase *c = g_ptr_array_index (a->cases, k);

			if (k > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "verdict", fs_whatif_verdict_name (c->verdict));
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "condition", c->condition);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "rule", c->rule);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "origin", whatif_origin_word (c->origin));
			g_string_append_c (out, '}');
		}
		g_string_append (out, "],\"trace\":[");
		for (guint k = 0; k < a->steps->len; k++) {
			const FsWhatIfStep *st = g_ptr_array_index (a->steps, k);

			if (k > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "step",
			                st->kind == FS_WHATIF_STEP_MATCHED ? "matched"
			                : st->kind == FS_WHATIF_STEP_NOTE ? "note"
			                                                   : "skipped");
			g_string_append_c (out, ',');
			fs_json_kv_bool (out, "decides", (gint) k == a->decided_by);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "rule", st->rule);  g_string_append_c (out, ',');
			fs_json_kv_str (out, "origin", whatif_origin_word (st->origin));
			g_string_append_c (out, ',');
			json_kv_int (out, "policy_kind", st->policy_kind);
			g_string_append_c (out, ',');
			json_kv_int (out, "policy_row", st->policy_index);
			g_string_append_c (out, ',');
			fs_json_kv_bool (out, "allows", st->allows);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "detail", st->detail);
			g_string_append_c (out, '}');
		}
		g_string_append (out, "],\"actions\":[");
		for (guint k = 0; k < a->actions->len; k++) {
			const FsWhatIfAction *act = g_ptr_array_index (a->actions, k);
			gchar *csv = act->row != NULL ? fs_rule_to_csv (act->row) : NULL;

			if (k > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "kind", whatif_action_word (act->kind));
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "label", act->label);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "explanation", act->explanation);
			g_string_append_c (out, ',');
			fs_json_kv_bool (out, "verified", act->verified);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "gives", fs_whatif_verdict_name (act->gives));
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "row_kind", act->row != NULL
			                ? fs_cli_kind_name (act->row->kind) : NULL);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "row", csv);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "target", act->target);
			g_string_append_c (out, '}');
			g_free (csv);
		}
		g_string_append (out, "]}");
	}
	g_string_append (out, "],\"notes\":[");
	for (guint i = 0; i < r->notes->len; i++) {
		if (i > 0)
			g_string_append_c (out, ',');
		fs_json_string (out, g_ptr_array_index (r->notes, i));
	}
	g_string_append (out, "]}");
}
/* ---------------------------------------------------------- kernel log */

/* [ read_tail_lines ] -- the last max_lines lines of a text. */
static gchar **
read_tail_lines (const gchar *text, guint max_lines)
{
	gchar **lines = g_strsplit (text, "\n", -1);
	guint n = g_strv_length (lines);

	if (n > max_lines) {
		gchar **tail = g_new0 (gchar *, max_lines + 1);

		for (guint i = 0; i < max_lines; i++)
			tail[i] = g_strdup (lines[n - max_lines + i]);
		g_strfreev (lines);
		return tail;
	}

	return lines;
}

/* [ read_kmsg_history ]
 * Every record still in the kernel ring buffer (/dev/kmsg, opened at
 * its start), converted to stamped log lines; NULL when it cannot be
 * opened.  The fallback when neither rsyslog nor journald keeps a copy
 * -- WSL, containers, minimal installs -- where the ring is the only
 * kernel log there is. */
static gchar *
read_kmsg_history (void)
{
	int fd = open ("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	GString *out;
	gchar record[8192];
	gint64 now_real = g_get_real_time ();
	gint64 now_mono = g_get_monotonic_time ();

	if (fd < 0)
		return NULL;

	out = g_string_new (NULL);

	for (;;) {
		gssize got = read (fd, record, sizeof (record) - 1);
		gchar *line;

		if (got < 0) {
			if (errno == EPIPE || errno == EINTR)
				continue;     /* overwritten records: go on */
			break;            /* EAGAIN: the end of the ring */
		}
		if (got == 0)
			break;

		record[got] = '\0';
		line = fs_netparse_kmsg_line (record, (gsize) got,
		                              now_real, now_mono);
		if (line != NULL) {
			g_string_append (out, line);
			g_string_append_c (out, '\n');
			g_free (line);
		}
	}

	close (fd);
	return g_string_free (out, FALSE);
}

GPtrArray *
fs_cli_log_history (guint max_lines, gint64 *complete_from, GError **error)
{
	const gchar *override = g_getenv ("STOCKFW_LOG_FILE");
	gchar *text = NULL;
	gchar **lines;
	GPtrArray *hits;
	GError *local = NULL;

	if (override != NULL && *override != '\0') {
		if (!g_file_get_contents (override, &text, NULL, error))
			return NULL;
	} else if (g_file_test ("/var/log/kern.log", G_FILE_TEST_EXISTS)) {
		if (!g_file_get_contents ("/var/log/kern.log", &text, NULL,
		                          &local)) {
			g_set_error (error, local->domain, local->code,
			             "cannot read /var/log/kern.log: %s "
			             "(root or the adm group can)", local->message);
			g_error_free (local);
			return NULL;
		}
	} else {
		/* argv, no shell: nothing here is ever interpolated. */
		gchar *n = g_strdup_printf ("%u", MAX (max_lines * 4, 2000u));
		/* By its full path: as root from the system directories
		 * only, never the caller's PATH [S0]. */
		gchar *journalctl = fs_toolpath_find ("journalctl");
		gchar *argv[] = { journalctl, (gchar *) "-k",
		                  (gchar *) "-o", (gchar *) "short",
		                  (gchar *) "--no-pager", (gchar *) "-n", n,
		                  NULL };
		gchar *err = NULL;
		gint wait = 0;
		gboolean spawned, journal_ok;

		if (journalctl == NULL) {
			spawned = FALSE;
			g_set_error (&local, G_SPAWN_ERROR, G_SPAWN_ERROR_NOENT,
			             "journalctl was not found %s",
			             fs_toolpath_where ());
		} else
			spawned = g_spawn_sync (NULL, argv, NULL, 0, NULL, NULL,
			                        &text, &err, &wait, &local);
		g_free (journalctl);
		g_free (n);
		journal_ok = spawned && g_spawn_check_wait_status (wait, NULL) &&
		             (err == NULL ||
		              strstr (err, "No journal files") == NULL);

		if (!journal_ok) {
			/* No usable journal (no journald, as in WSL and most
			 * containers, or no journalctl at all): the kernel's own
			 * ring buffer is then the only copy of the log. */
			gchar *ring = read_kmsg_history ();

			if (ring != NULL) {
				g_free (text);
				text = ring;
				journal_ok = TRUE;
			}
		}

		if (!journal_ok) {
			if (!spawned)
				g_set_error (error, local->domain, local->code,
				             "no kernel log to read: no "
				             "/var/log/kern.log, /dev/kmsg is not "
				             "readable, and journalctl failed (%s)",
				             local->message);
			else if (geteuid () == 0)
				g_set_error (error, G_SPAWN_ERROR,
				             G_SPAWN_ERROR_FAILED,
				             "no kernel log found: there is no "
				             "/var/log/kern.log, /dev/kmsg cannot be "
				             "read, and the journal holds no kernel "
				             "messages");
			else
				g_set_error (error, G_SPAWN_ERROR,
				             G_SPAWN_ERROR_FAILED,
				             "the kernel log is not readable by this "
				             "account (root, or the adm / "
				             "systemd-journal group, can read it)");
			g_clear_error (&local);
			g_free (text);
			g_free (err);
			return NULL;
		}
		g_clear_error (&local);
		g_free (err);
	}

	/* Plenty of foreign kernel lines sit between ours; keep a window
	 * wide enough that max_lines of OUR events usually survive. */
	lines = read_tail_lines (text, MAX (max_lines * 50, 20000u));
	g_free (text);

	hits = g_ptr_array_new_with_free_func ((GDestroyNotify) fs_hit_free);

	if (complete_from != NULL) {
		*complete_from = 0;

		for (guint i = 0; lines[i] != NULL && *complete_from == 0; i++) {
			gchar *stamp = fs_netparse_line_time (lines[i], NULL);
			GDateTime *when = stamp != NULL
				? g_date_time_new_from_iso8601 (stamp, NULL) : NULL;

			if (when != NULL) {
				*complete_from = g_date_time_to_unix (when);
				g_date_time_unref (when);
			}
			g_free (stamp);
		}
	}

	for (guint i = 0; lines[i] != NULL; i++) {
		FsHit parsed = { 0 };
		FsHit *hit;
		gchar *intel_id = NULL;

		/* A threat-intel block, read as the backend's live feed reads
		 * it: kept only when <id> is a set of the rule set StockFW
		 * applied [S17.3], and named after its list. */
		if (fs_netparse_intel_line (lines[i], &parsed, NULL, &intel_id)) {
			if (!fs_intel_applied_has (intel_id)) {
				g_free (intel_id);
				fs_netparse_clear_hit (&parsed);
				continue;
			}
			fs_netparse_name_blocked (&parsed);
			parsed.rule = fs_intel_rule_text (intel_id);
			g_free (intel_id);
		} else if (fs_netparse_log_line (lines[i], &parsed, NULL)) {
			fs_netparse_name_by_verdict (&parsed,
			                             fs_netparse_log_verdict (lines[i]));
		} else {
			continue;
		}
		hit = fs_hit_new ();
		*hit = parsed;          /* the fields move into the heap hit */
		g_ptr_array_add (hits, hit);
	}

	g_strfreev (lines);

	while (hits->len > max_lines)
		g_ptr_array_remove_index (hits, 0);

	return hits;
}

/* [ hit_row ] -- one event as table cells (caller frees with g_strfreev). */
/* [ address_text ] -- an address as the table shows it: IPv6 in its
 * short form (2001:db8::1, not 2001:0db8:0000:...). */
static gchar *
address_text (const gchar *text)
{
	GInetAddress *a;
	gchar *out;

	if (text == NULL || *text == '\0')
		return g_strdup ("-");
	if (strchr (text, ':') == NULL)
		return g_strdup (text);
	a = g_inet_address_new_from_string (text);
	if (a == NULL)
		return g_strdup (text);
	out = g_inet_address_to_string (a);
	g_object_unref (a);
	return out;
}

gchar **
fs_cli_hit_row (const FsHit *hit)
{
	gchar **row = g_new0 (gchar *, 10);
	gboolean blocked = fs_hit_is_blocked (hit);
	gchar *service = fs_hit_service_name (hit);

	row[0] = fs_cli_local_time (hit->time);
	row[1] = g_strdup (blocked ? "BLOCKED" : "ALLOWED");
	row[2] = g_strdup (g_ascii_strcasecmp (hit->direction ? hit->direction
	                                                      : "in", "in") == 0
	                   ? "in" : "out");
	row[3] = address_text (hit->source);
	row[4] = address_text (hit->destination);
	row[5] = g_strdup (hit->port ? hit->port : "-");
	row[6] = service;
	row[7] = g_strdup (hit->protocol ? hit->protocol : "-");
	/* Why it was dropped, when the log says: "Threat intel: <list>". */
	row[8] = g_strdup (hit->rule != NULL && *hit->rule ? hit->rule : "-");

	/* Log fields are what the kernel printed, interface names and
	 * list names included: nothing reaches the terminal raw. */
	for (guint i = 0; i < 9; i++) {
		gchar *safe = fs_cli_out_safe (row[i]);

		g_free (row[i]);
		row[i] = safe;
	}
	return row;
}

