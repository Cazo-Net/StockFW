/*---[ fs-cli-policy.c ]----------------------------------------------------
 * `stockfw policy', `check', `apply', `start', `stop', `simulate' and
 * (cli-plan.md WP-B); `copilot' moved to fs-cli-copilot.c (PR 4).
 *
 * One way to name a rule everywhere: KIND:N ("inbound-allow-service:3",
 * 1-based, numbered as `policy list' numbers it).  A line of a rule
 * file that is not a rule is reported as FILE:LINE: reason, once, by
 * the command that read it; `apply' refuses while there are any.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "cli/fs-cli-act.h"
#include "control/fs-control.h"
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
#include "core/fs-iprange.h"
#include "core/fs-lockout.h"
#include "core/fs-service.h"
#include "core/fs-json.h"
#include "core/fs-netparse.h"
#include "core/fs-script.h"
#include "core/fs-util.h"

#include <glib/gstdio.h>
#include <glib-unix.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* [ kind_field_count ] -- fields before the comment, per kind. */
static gint
kind_field_count (FsRuleKind kind)
{
	gint n = 0;

	fs_rule_columns (kind, &n);
	return n - 1;
}

/* [ unknown_kind ] -- "unknown rule kind", with the closest kind. */
static void
unknown_kind (const gchar *name)
{
	const gchar *best = fs_cli_suggest (name, fs_cli_kind_names (),
	                                    FS_RULE_N_KINDS);

	if (best != NULL)
		fs_cli_error ("unknown rule kind: %s (did you mean %s?)", name,
		              best);
	else
		fs_cli_error ("unknown rule kind: %s", name);
}

/* [ warn ] -- "stockfw: warning: ...", even under -q: a warning is
 * about the firewall, not a hint about the tool. */
static void G_GNUC_PRINTF (1, 2)
warn (const gchar *format, ...)
{
	va_list args;
	gchar *text, *safe;

	va_start (args, format);
	text = g_strdup_vprintf (format, args);
	va_end (args);
	safe = fs_cli_out_safe (text);
	fprintf (stderr, "stockfw: %swarning:%s %s\n",
	         fs_cli.color_err ? "\033[1;33m" : "",
	         fs_cli.color_err ? "\033[0m" : "", safe);
	g_free (safe);
	g_free (text);
}

/* --------------------------------------------------- loading, problems */

FsPolicy *
fs_cli_load_policy_report (gboolean *on_disk, GPtrArray **problems)
{
	FsPolicy *policy = fs_policy_new ();
	GPtrArray *found = NULL;
	gboolean any = fs_policy_load_report (policy, &found);

	if (on_disk != NULL)
		*on_disk = any;
	if (problems != NULL)
		*problems = found;
	else
		g_ptr_array_unref (found);
	return policy;
}

/* [ problem_line ] -- "/etc/stockfw/inbound/allow-service:7: reason:
 * \"text\"", safe for a terminal. */
static gchar *
problem_line (const FsPolicyProblem *p)
{
	gchar *path = fs_util_rules_path (p->file);
	gchar *raw = g_strdup_printf ("%s:%u: %s: \"%s\"",
	                              path != NULL ? path : p->file, p->line,
	                              p->reason, p->text);
	gchar *safe = fs_cli_out_safe (raw);

	g_free (raw);
	g_free (path);
	return safe;
}

void
fs_cli_print_problems (const GPtrArray *problems)
{
	for (guint i = 0; problems != NULL && i < problems->len; i++) {
		gchar *line = problem_line (g_ptr_array_index (problems, i));

		fs_cli_error ("%s", line);
		g_free (line);
	}
	if (problems != NULL && problems->len == 1)
		fs_cli_hint ("this line is not a rule and is left out; "
		             "`stockfw check' lists it, apply refuses until "
		             "it is fixed");
	else if (problems != NULL && problems->len > 1)
		fs_cli_hint ("these lines are not rules and are left out; "
		             "`stockfw check' lists them, apply refuses until "
		             "they are fixed");
}

/* [ not_rules ] -- "is not a rule" or "are not rules", for n lines. */
static const gchar *
not_rules (guint n)
{
	return n == 1 ? "is not a rule" : "are not rules";
}

/* [ refuse_lossy_save ] -- policy add and remove rewrite the rule
 * files from memory, and a line that is not a rule is not in memory:
 * the save would delete it without a word.  So they refuse, name the
 * lines, and leave the files as they are.  TRUE when refused. */
static gboolean
refuse_lossy_save (GPtrArray *problems)
{
	if (problems == NULL || problems->len == 0)
		return FALSE;
	fs_cli_print_problems (problems);
	fs_cli_error ("not saved: %u line%s of the policy %s, and saving "
	              "would delete %s", problems->len,
	              problems->len == 1 ? "" : "s", not_rules (problems->len),
	              problems->len == 1 ? "it" : "them");
	fs_cli_hint ("fix or delete %s in the file by hand, then run the "
	             "command again", problems->len == 1 ? "it" : "them");
	return TRUE;
}

/* ------------------------------------------------------ rule objects */

void
fs_cli_rule_json (GString *out, const FsRule *rule, guint number)
{
	gchar *ref = fs_cli_rule_ref (rule->kind, number);
	gchar *summary = fs_cli_rule_summary (rule);

	g_string_append_c (out, '{');
	fs_json_kv_str (out, "ref", ref);                      g_string_append_c (out, ',');
	fs_json_kv_str (out, "kind", fs_cli_kind_name (rule->kind)); g_string_append_c (out, ',');
	fs_json_kv_uint (out, "number", number);               g_string_append_c (out, ',');
	g_string_append (out, "\"fields\":{");
	fs_json_kv_str (out, "service", rule->service);       g_string_append_c (out, ',');
	fs_json_kv_str (out, "port", rule->port);             g_string_append_c (out, ',');
	fs_json_kv_str (out, "target", rule->target);         g_string_append_c (out, ',');
	fs_json_kv_str (out, "to", rule->to);                 g_string_append_c (out, ',');
	fs_json_kv_str (out, "to_port", rule->to_port);
	g_string_append (out, "},");
	fs_json_kv_str (out, "comment", rule->comment != NULL &&
	                *rule->comment != '\0' ? rule->comment : NULL);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "summary", summary);
	g_string_append_c (out, '}');
	g_free (summary);
	g_free (ref);
}

/* [ rule_line ] -- "inbound-allow-service:2  SSH  port 22  for X
 * [IPv4 only]", safe for a terminal. */
static gchar *
rule_line (const FsRule *rule, guint number)
{
	gboolean names = (fs_backend ()->fw_honors & FS_FWHON_HOST_NAMES) != 0;
	gchar *ref = fs_cli_rule_ref (rule->kind, number);
	gchar *summary = fs_cli_rule_summary (rule);
	FsFamily fam = fs_rule_coverage (rule, names, NULL);
	gchar *raw = g_strdup_printf ("%s  %s  [%s]", ref, summary,
	                              fam == FS_FAMILY_NONE
	                              ? "covers nothing"
	                              : fs_util_families_label (fam));
	gchar *safe = fs_cli_out_safe (raw);

	g_free (raw);
	g_free (summary);
	g_free (ref);
	return safe;
}

/* [ first_address ]
 * An address inside a host field, for a question about the row's own
 * traffic: the address itself, the first host of a network, or NULL
 * for Anyone, a name or nothing. */
static gchar *
first_address (const gchar *host)
{
	FsRange4 r4;
	FsRange6 r6;
	FsAddrFamily fam;

	if (host == NULL || *host == '\0' ||
	    g_ascii_strcasecmp (host, FS_TARGET_ANY) == 0)
		return NULL;
	fam = fs_range_parse (host, &r4, &r6, NULL, NULL);
	if (fam == FS_AF_V4) {
		guint32 a = r4.start;

		if (r4.end > r4.start)
			a++;   /* the network's first host, not the network */
		return g_strdup_printf ("%u.%u.%u.%u", (a >> 24) & 0xff,
		                        (a >> 16) & 0xff, (a >> 8) & 0xff,
		                        a & 0xff);
	}
	if (fam == FS_AF_V6) {
		r6.end = r6.start;
		if (r6.start.lo != G_MAXUINT64) {
			r6.start.lo++;
			r6.end = r6.start;
		}
		return fs_range6_to_string (&r6);
	}
	return NULL;
}

/* [ first_port ] -- "22" of "22", "1024" of "1024:2048"; NULL else. */
static gchar *
first_port (const gchar *port)
{
	gsize n;

	if (port == NULL || !g_ascii_isdigit (*port))
		return NULL;
	n = strspn (port, "0123456789");
	return g_strndup (port, n);
}

/* [ row_question ]
 * The What-If line that asks about a row's own traffic ("inbound tcp
 * port 22 from 192.168.1.1"), or NULL for a forward (not simulated). */
static gchar *
row_question (const FsRule *rule)
{
	gchar *host = first_address (rule->target);
	gchar *port = first_port (rule->port);
	GString *q = g_string_new (NULL);
	const gchar *proto = rule->service != NULL &&
	                     g_ascii_strcasecmp (rule->service, "UDP") == 0
	                     ? "udp" : "tcp";

	switch (rule->kind) {
	case FS_RULE_INBOUND_ALLOW_SERVICE:
		g_string_append (q, "inbound ");
		if (port != NULL)
			g_string_append_printf (q, "%s port %s", proto, port);
		else
			g_string_append (q, rule->service);
		if (host != NULL)
			g_string_append_printf (q, " from %s", host);
		break;
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_DENY_SERVICE:
		g_string_append (q, "outbound ");
		if (port != NULL)
			g_string_append_printf (q, "%s port %s", proto, port);
		else
			g_string_append (q, rule->service);
		if (host != NULL)
			g_string_append_printf (q, " to %s", host);
		break;
	case FS_RULE_INBOUND_ALLOW_FROM:
		if (host != NULL)
			g_string_append_printf (q, "inbound tcp from %s", host);
		break;
	case FS_RULE_OUTBOUND_ALLOW_TO:
	case FS_RULE_OUTBOUND_DENY_TO:
		if (host != NULL)
			g_string_append_printf (q, "outbound tcp to %s", host);
		break;
	default:
		/* outbound-*-from names this computer's own source address,
		 * a forward is not simulated. */
		break;
	}
	g_free (host);
	g_free (port);
	if (q->len == 0) {
		g_string_free (q, TRUE);
		return NULL;
	}
	return g_string_free (q, FALSE);
}

/* [ row_check ]
 * The one-line What-If check of a row's own traffic on the saved
 * policy, printed as "Check: ... -> VERDICT (saved policy)" or added
 * to `json' as "check":{question, verdict} (null when there is none). */
static void
row_check (const FsRule *rule, GString *json)
{
	gchar *q = row_question (rule);
	FsWhatIfResult *r = q != NULL ? fs_cli_whatif (q, TRUE) : NULL;

	if (json != NULL) {
		g_string_append (json, ",\"check\":");
		if (r == NULL || r->verdict == FS_WHATIF_ERROR) {
			g_string_append (json, "null");
		} else {
			g_string_append_c (json, '{');
			fs_json_kv_str (json, "question", q);
			g_string_append_c (json, ',');
			fs_json_kv_str (json, "verdict",
			                fs_whatif_verdict_name (r->verdict));
			g_string_append_c (json, '}');
		}
	} else if (r != NULL && r->verdict != FS_WHATIF_ERROR &&
	           !fs_cli.quiet) {
		printf ("Check: %s %s %s (saved policy)\n", q,
		        fs_cli_sym (FS_CLI_SYM_ARROW),
		        fs_whatif_verdict_name (r->verdict));
	}
	if (r != NULL)
		fs_whatif_result_free (r);
	g_free (q);
}

/* [ own_policy_note ] -- a policy edited without sudo is the user's
 * own; apply as root reads /etc/stockfw (survey A12). */
static void
own_policy_note (void)
{
	if (fs_cli.quiet || fs_cli.json || geteuid () == 0 ||
	    g_str_has_prefix (fs_util_rules_dir (), "/etc"))
		return;
	printf ("%snote: this is your own policy (%s); with sudo, stockfw "
	        "reads and applies /etc/stockfw.%s\n", fs_cli_dim (),
	        fs_util_rules_dir (), fs_cli_reset ());
}

/* [ not_live_line ] */
static void
not_live_line (void)
{
	gchar *apply;

	if (fs_cli.quiet || fs_cli.json)
		return;
	apply = fs_cli_sudo_hint ("apply");
	printf ("%sNot live yet: %s   (preview: stockfw policy diff)%s\n",
	        fs_cli_dim (), apply, fs_cli_reset ());
	g_free (apply);
}

/* --------------------------------------------------------------- check */

gint
fs_cli_cmd_check (gint argc, gchar **argv)
{
	GPtrArray *problems = NULL;
	gboolean on_disk;
	FsPolicy *policy;
	guint rules;

	for (gint i = 1; i < argc; i++) {
		if (fs_cli_is_option_at (argv, i))
			fs_cli_unknown_option ("check", argv[i]);
		else
			fs_cli_error ("unexpected argument: %s", argv[i]);
		return FS_EXIT_USAGE;
	}

	policy = fs_cli_load_policy_report (&on_disk, &problems);
	rules = fs_cli_policy_total (policy);

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "rules_dir", fs_util_rules_dir ());
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "saved", on_disk);
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "rules", rules);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "ok", problems->len == 0);
		g_string_append (out, ",\"problems\":[");
		for (guint i = 0; i < problems->len; i++) {
			const FsPolicyProblem *p = g_ptr_array_index (problems, i);
			gchar *path = fs_util_rules_path (p->file);

			if (i > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "file", p->file);     g_string_append_c (out, ',');
			fs_json_kv_str (out, "path", path);        g_string_append_c (out, ',');
			fs_json_kv_uint (out, "line", p->line);    g_string_append_c (out, ',');
			fs_json_kv_str (out, "text", p->text);     g_string_append_c (out, ',');
			fs_json_kv_str (out, "reason", p->reason);
			g_string_append_c (out, '}');
			g_free (path);
		}
		g_string_append (out, "]}");
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		for (guint i = 0; i < problems->len; i++) {
			gchar *line = problem_line (g_ptr_array_index (problems, i));

			printf ("%s\n", line);
			g_free (line);
		}
		if (problems->len > 0)
			printf ("%u problem%s; apply refuses until %s fixed.\n",
			        problems->len, problems->len == 1 ? "" : "s",
			        problems->len == 1 ? "it is" : "they are");
		else if (!fs_cli.quiet && !on_disk)
			printf ("No policy saved yet in %s.\n",
			        fs_util_rules_dir ());
		else if (!fs_cli.quiet)
			printf ("%u rule%s in %s, no problems.\n", rules,
			        rules == 1 ? "" : "s", fs_util_rules_dir ());
	}

	{
		gint status = problems->len > 0 ? FS_EXIT_FAILURE : FS_EXIT_OK;

		g_ptr_array_unref (problems);
		fs_policy_free (policy);
		return status;
	}
}

/* -------------------------------------------------------------- policy */

/* [ kind_in_dir ] -- in: the inbound kinds, out: the outbound ones. */
static gboolean
kind_in_dir (gint kind, gint dir)
{
	if (dir == 0)
		return TRUE;
	return dir > 0 ? kind <= FS_RULE_INBOUND_FORWARD
	               : kind > FS_RULE_INBOUND_FORWARD;
}

/* [ row_matches ] -- --grep: case-insensitive, in the row and comment. */
static gboolean
row_matches (const FsRule *rule, const gchar *grep)
{
	gchar *csv, *hay, *needle;
	gboolean hit;

	if (grep == NULL)
		return TRUE;
	csv = fs_rule_to_csv (rule);
	hay = g_utf8_strdown (csv, -1);
	needle = g_utf8_strdown (grep, -1);
	hit = strstr (hay, needle) != NULL;
	g_free (needle);
	g_free (hay);
	g_free (csv);
	return hit;
}

/* [ row_status ] -- "live" or "pending" for --status, from the
 * journal; "unknown" when it could not be read. */
static const gchar *
row_status (const FsRule *rule, FsCliLive live, const FsPolicy *applied)
{
	if (live == FS_CLI_LIVE_UNKNOWN)
		return "unknown";
	if (live == FS_CLI_LIVE_STOPPED || applied == NULL ||
	    !fs_policy_contains (applied, rule))
		return "pending";
	return "live";
}

static gint
policy_list (gint argc, gchar **argv)
{
	FsRuleKind only = FS_RULE_N_KINDS;
	gint dir = 0;
	const gchar *grep = NULL;
	gboolean with_status = FALSE;
	gboolean on_disk;
	GPtrArray *problems = NULL;
	FsPolicy *policy, *applied = NULL;
	FsCliLive live = FS_CLI_LIVE_UNKNOWN;
	gboolean names = (fs_backend ()->fw_honors & FS_FWHON_HOST_NAMES) != 0;
	guint shown = 0;

	for (gint i = 0; i < argc; i++) {
		const gchar *v;
		gint status = FS_EXIT_OK;

		if (fs_cli_take_opt (argc, argv, &i, "--kind", &v, &status)) {
			if (v == NULL)
				return status;
			if (!fs_cli_kind_parse (v, &only)) {
				unknown_kind (v);
				fs_cli_hint ("see `stockfw help policy' for the kinds");
				return FS_EXIT_USAGE;
			}
		} else if (fs_cli_take_opt (argc, argv, &i, "--grep", &v,
		                            &status)) {
			if (v == NULL)
				return status;
			grep = v;
		} else if (fs_cli_is_option_at (argv, i) &&
		           strcmp (argv[i], "--status") == 0) {
			with_status = TRUE;
		} else if (fs_cli_is_option_at (argv, i)) {
			fs_cli_unknown_option ("policy list", argv[i]);
			return FS_EXIT_USAGE;
		} else if (g_strcmp0 (argv[i], "in") == 0 ||
		           g_strcmp0 (argv[i], "inbound") == 0) {
			dir = 1;
		} else if (g_strcmp0 (argv[i], "out") == 0 ||
		           g_strcmp0 (argv[i], "outbound") == 0) {
			dir = -1;
		} else if (fs_cli_kind_parse (argv[i], &only)) {
			/* a positional kind */
		} else {
			unknown_kind (argv[i]);
			fs_cli_hint ("stockfw policy list [KIND|in|out] [--grep "
			             "TEXT] [--status]");
			return FS_EXIT_USAGE;
		}
	}

	policy = fs_cli_load_policy_report (&on_disk, &problems);
	if (with_status)
		live = fs_cli_policy_state (policy, &applied, NULL);

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "rules_dir", fs_util_rules_dir ());
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "saved", on_disk);
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "malformed_rules", problems->len);
		if (with_status) {
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "live", fs_cli_live_name (live));
		}
		g_string_append (out, ",\"rules\":[");
		{
			gboolean first = TRUE;

			for (gint k = 0; k < FS_RULE_N_KINDS; k++) {
				GPtrArray *rules = policy->kinds[k];

				if (only != FS_RULE_N_KINDS && (gint) only != k)
					continue;
				if (!kind_in_dir (k, dir))
					continue;

				for (guint i = 0; i < rules->len; i++) {
					FsRule *r = g_ptr_array_index (rules, i);
					gchar *ref;

					if (!row_matches (r, grep))
						continue;
					ref = fs_cli_rule_ref (r->kind, i + 1);
					if (!first)
						g_string_append_c (out, ',');
					first = FALSE;
					g_string_append_c (out, '{');
					fs_json_kv_str (out, "kind", fs_cli_kind_name (r->kind)); g_string_append_c (out, ',');
					fs_json_kv_uint (out, "number", i + 1);   g_string_append_c (out, ',');
					fs_json_kv_str (out, "rule_ref", ref);     g_string_append_c (out, ',');
					fs_json_kv_str (out, "service", r->service); g_string_append_c (out, ',');
					fs_json_kv_str (out, "port", r->port);    g_string_append_c (out, ',');
					fs_json_kv_str (out, "target", r->target); g_string_append_c (out, ',');
					fs_json_kv_str (out, "to", r->to);        g_string_append_c (out, ',');
					fs_json_kv_str (out, "to_port", r->to_port); g_string_append_c (out, ',');
					fs_json_kv_str (out, "comment", r->comment);
					g_string_append_c (out, ',');
					if (with_status) {
						fs_json_kv_str (out, "status",
						                row_status (r, live, applied));
						g_string_append_c (out, ',');
					}
					{
						gchar *why = NULL;
						FsFamily fam = fs_rule_coverage (r, names, &why);

						fs_json_key (out, "covers");
						g_string_append_c (out, '[');
						if (fam & FS_FAMILY_IPV4)
							g_string_append (out, "\"ipv4\"");
						if (fam == FS_FAMILY_BOTH)
							g_string_append_c (out, ',');
						if (fam & FS_FAMILY_IPV6)
							g_string_append (out, "\"ipv6\"");
						g_string_append (out, "],");
						fs_json_kv_str (out, "covers_why", why);
						g_free (why);
					}
					g_string_append_c (out, '}');
					g_free (ref);
				}
			}
		}
		g_string_append (out, "]}");
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
		goto done;
	}

	fs_cli_print_problems (problems);

	if (!on_disk) {
		printf ("No policy saved yet in %s.\n", fs_util_rules_dir ());
		printf ("%sAdd a rule with `stockfw policy add', or start from "
		        "the default rules (DHCP and DNS out) with `stockfw policy "
		        "init'.%s\n", fs_cli_dim (), fs_cli_reset ());
		goto done;
	}

	for (gint k = 0; k < FS_RULE_N_KINDS; k++) {
		GPtrArray *rules = policy->kinds[k];
		guint hits = 0;

		if (only != FS_RULE_N_KINDS && (gint) only != k)
			continue;
		if (!kind_in_dir (k, dir))
			continue;
		for (guint i = 0; i < rules->len; i++)
			if (row_matches (g_ptr_array_index (rules, i), grep))
				hits++;
		if (only == FS_RULE_N_KINDS && hits == 0)
			continue;

		printf ("%s%s%s %s(%u)%s\n", fs_cli_bold (),
		        fs_cli_kind_name ((FsRuleKind) k), fs_cli_reset (),
		        fs_cli_dim (), rules->len, fs_cli_reset ());

		for (guint i = 0; i < rules->len; i++) {
			FsRule *r = g_ptr_array_index (rules, i);
			gchar *line, *comment;

			if (!row_matches (r, grep))
				continue;
			shown++;
			/* A comment or a name is whatever the file holds: never
			 * let it steer the terminal. */
			line = rule_line (r, i + 1);
			comment = fs_cli_out_safe (r->comment);
			printf ("  %s", line);
			if (with_status) {
				const gchar *st = row_status (r, live, applied);

				printf ("  %s%s%s",
				        g_strcmp0 (st, "live") == 0 ? fs_cli_green ()
				                                    : fs_cli_amber (),
				        st, fs_cli_reset ());
			}
			if (*comment != '\0')
				printf ("  %s# %s%s", fs_cli_dim (), comment,
				        fs_cli_reset ());
			printf ("\n");
			g_free (comment);
			g_free (line);
		}

		if (hits == 0)
			printf ("  %s(none)%s\n", fs_cli_dim (), fs_cli_reset ());
	}

	if (fs_cli_policy_total (policy) == 0 && only == FS_RULE_N_KINDS &&
	    dir == 0)
		printf ("The policy in %s is empty.\n", fs_util_rules_dir ());
	else if (grep != NULL && shown == 0)
		printf ("No rule matches \"%s\".\n", grep);

done:
	if (applied != NULL)
		fs_policy_free (applied);
	g_ptr_array_unref (problems);
	fs_policy_free (policy);
	return FS_EXIT_OK;
}

/* [ take_ref ]
 * A rule reference from argv: "KIND:N", "KIND#N" or "KIND N".  Moves
 * *i past what it used.  Prints the error and returns FALSE when there
 * is none, or when the policy has no such row. */
static gboolean
take_ref (gint argc, gchar **argv, gint *i, const FsPolicy *policy,
          FsRuleKind *kind, guint *number, const gchar *usage)
{
	gboolean used_next = FALSE;
	const gchar *text = *i < argc ? argv[*i] : NULL;

	if (text == NULL ||
	    !fs_cli_rule_ref_parse (text, *i + 1 < argc ? argv[*i + 1] : NULL,
	                            kind, number, &used_next)) {
		FsRuleKind k;

		if (text != NULL && strpbrk (text, ":#") != NULL) {
			gchar *name = g_strndup (text, strcspn (text, ":#"));

			if (!fs_cli_kind_parse (name, &k))
				unknown_kind (name);
			else
				fs_cli_error ("not a rule number: %s", text);
			g_free (name);
		} else if (text != NULL && !fs_cli_kind_parse (text, &k)) {
			unknown_kind (text);
		} else {
			fs_cli_error ("usage: %s", usage);
		}
		fs_cli_hint ("`stockfw policy list' shows each rule's "
		             "reference, like inbound-allow-service:1");
		return FALSE;
	}
	*i += used_next ? 2 : 1;

	if (*number > policy->kinds[*kind]->len) {
		fs_cli_error ("%s has no rule number %u (it has %u)",
		              fs_cli_kind_name (*kind), *number,
		              policy->kinds[*kind]->len);
		return FALSE;
	}
	return TRUE;
}

static gint
policy_show (gint argc, gchar **argv)
{
	FsPolicy *policy, *applied = NULL;
	GPtrArray *problems = NULL;
	FsRuleKind kind;
	guint number;
	gint i = 0;
	const FsRule *rule;
	FsCliLive live;
	const gchar *st;
	gboolean names = (fs_backend ()->fw_honors & FS_FWHON_HOST_NAMES) != 0;
	gchar *why = NULL;
	FsFamily fam;

	policy = fs_cli_load_policy_report (NULL, &problems);
	if (!take_ref (argc, argv, &i, policy, &kind, &number,
	               "stockfw policy show KIND:N")) {
		g_ptr_array_unref (problems);
		fs_policy_free (policy);
		return FS_EXIT_USAGE;
	}
	if (i < argc) {
		fs_cli_error ("unexpected argument: %s", argv[i]);
		g_ptr_array_unref (problems);
		fs_policy_free (policy);
		return FS_EXIT_USAGE;
	}

	rule = g_ptr_array_index (policy->kinds[kind], number - 1);
	live = fs_cli_policy_state (policy, &applied, NULL);
	st = row_status (rule, live, applied);
	fam = fs_rule_coverage (rule, names, &why);

	if (fs_cli.json) {
		GString *out = g_string_new (NULL);

		gchar *ref = fs_cli_rule_ref (kind, number);

		/* The rule object, plus where it is and what it reaches. */
		fs_cli_rule_json (out, rule, number);
		g_string_truncate (out, out->len - 1);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "rule_ref", ref);
		g_string_append_c (out, ',');
		g_free (ref);
		fs_json_kv_str (out, "rules_dir", fs_util_rules_dir ());
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "status", st);
		g_string_append_c (out, ',');
		fs_json_key (out, "covers");
		g_string_append_c (out, '[');
		if (fam & FS_FAMILY_IPV4)
			g_string_append (out, "\"ipv4\"");
		if (fam == FS_FAMILY_BOTH)
			g_string_append_c (out, ',');
		if (fam & FS_FAMILY_IPV6)
			g_string_append (out, "\"ipv6\"");
		g_string_append (out, "],");
		fs_json_kv_str (out, "covers_why", why);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		gint n = 0;
		const gchar * const *labels = fs_rule_columns (kind, &n);
		const gchar *values[5] = { NULL };
		gchar *ref = fs_cli_rule_ref (kind, number);
		gchar *safe_why = fs_cli_out_safe (why);

		switch (kind) {
		case FS_RULE_INBOUND_FORWARD:
			values[0] = rule->service; values[1] = rule->port;
			values[2] = rule->to;      values[3] = rule->to_port;
			values[4] = rule->comment;
			break;
		case FS_RULE_INBOUND_ALLOW_SERVICE:
		case FS_RULE_OUTBOUND_ALLOW_SERVICE:
		case FS_RULE_OUTBOUND_DENY_SERVICE:
			values[0] = rule->service; values[1] = rule->port;
			values[2] = rule->target;  values[3] = rule->comment;
			break;
		default:
			values[0] = rule->target;  values[1] = rule->comment;
			break;
		}

		printf ("%s%s%s\n", fs_cli_bold (), ref, fs_cli_reset ());
		for (gint c = 0; c < n && c < 5; c++) {
			gchar *v = fs_cli_out_safe (values[c] != NULL &&
			                            *values[c] != '\0'
			                            ? values[c] : "-");

			printf ("  %-14s %s\n", labels[c], v);
			g_free (v);
		}
		printf ("  %-14s %s\n", "Covers",
		        fam == FS_FAMILY_NONE ? "nothing"
		                              : fs_util_families_label (fam));
		if (*safe_why != '\0')
			printf ("  %-14s %s\n", "", safe_why);
		printf ("  %-14s %s\n", "Status",
		        g_strcmp0 (st, "live") == 0 ? "live (in the last apply)"
		        : g_strcmp0 (st, "pending") == 0 ? "not live yet"
		        : "unknown (the applied policy cannot be read)");
		g_free (safe_why);
		g_free (ref);
	}

	g_free (why);
	if (applied != NULL)
		fs_policy_free (applied);
	g_ptr_array_unref (problems);
	fs_policy_free (policy);
	return FS_EXIT_OK;
}

/* [ service_default_port ]
 * The port of a well-known service named case-insensitively ("ssh",
 * "HTTPS"), or NULL when the name is unknown or the service spans
 * several ports (Samba, NFS) -- those need an explicit port. */
static const gchar *
service_default_port (const gchar *name, const gchar **canonical)
{
	guint n = 0;
	const FsService *list = fs_service_user_list (&n);

	for (guint i = 0; i < n; i++) {
		if (g_ascii_strcasecmp (list[i].name, name) != 0)
			continue;

		for (const gchar *p = list[i].ports; *p != '\0'; p++)
			if (!g_ascii_isdigit (*p))
				return NULL;

		*canonical = list[i].name;
		return list[i].ports;
	}

	return NULL;
}

/* With the apply code below: an edit op sent with or without --apply,
 * the refusal when the lockout question was not confirmed, and what
 * the apply after the edit did (3D). */
static FsControlResult *edit_send (const gchar *op, GVariant *base,
                                   gboolean apply, gboolean yes,
                                   GString *lock, gint *status);
static gint edit_refused (const gchar *verb, const GString *lock,
                          gint status);
static gint edit_applied (const FsControlResult *r, const GString *lock,
                          GString *json);

/* [ edit_failed ] -- an edit op that did not save: why, and the exit
 * status. */
static gint
edit_failed (const FsControlResult *r)
{
	gint status = r->status == FS_CONTROL_USAGE ? FS_EXIT_USAGE
	            : r->status == FS_CONTROL_NEED_ROOT ? FS_EXIT_NEED_ROOT
	            : FS_EXIT_FAILURE;

	if (!refuse_lossy_save (r->problems)) {
		fs_cli_error ("%s", r->error);
		if (r->hint != NULL)
			fs_cli_hint ("%s", r->hint);
	}
	return status;
}

/* [ take_edit_opts ]
 * --apply and --yes (-y), as add, edit and remove take them.  TRUE
 * when argv[i] was one. */
static gboolean
take_edit_opts (gchar **argv, gint i, gboolean *apply, gboolean *yes)
{
	if (!fs_cli_is_option_at (argv, i))
		return FALSE;
	if (strcmp (argv[i], "--apply") == 0) {
		*apply = TRUE;
		return TRUE;
	}
	if (strcmp (argv[i], "--yes") == 0 || strcmp (argv[i], "-y") == 0) {
		*yes = TRUE;
		return TRUE;
	}
	return FALSE;
}

/* [ lockout_note_after_edit ]
 * As root, an edit of the saved policy does not reach the firewall,
 * but the next apply would: say so when that apply would cut an SSH
 * session (the lockout guard proper runs at apply). */
static void
lockout_note_after_edit (const FsPolicy *policy)
{
	FsRangeSet *own = NULL, *peers = NULL;
	GArray *ports = NULL;
	FsSettings *settings;
	FsLockoutReport *report;

	if (geteuid () != 0 || fs_cli.json)
		return;
	fs_lockout_sessions (&own, &peers, &ports);
	settings = fs_settings_new ();
	fs_settings_load_prefs (settings);
	report = fs_lockout_check_own (policy, settings, own, peers, ports);
	if (fs_lockout_report_cuts (report))
		warn ("once applied, this policy would block your SSH session "
		      "from %s to port %u: %s", report->worst->peer,
		      report->worst->port,
		      fs_whatif_verdict_name (report->verdict));
	fs_lockout_report_free (report);
	fs_settings_free (settings);
	fs_range_set_free (own);
	fs_range_set_free (peers);
	g_array_unref (ports);
}

static gint
policy_add (gint argc, gchar **argv)
{
	FsRuleKind kind;
	const gchar *comment = "", *first;
	gboolean both = FALSE;
	GPtrArray *fields;
	gint want;
	const FsRule *rule, *twin;
	gboolean paired, apply = FALSE, yes = FALSE;
	guint number, twin_number;
	GVariantBuilder b;
	GVariant *base;
	GString *lock;
	FsControlResult *r;
	gint status = FS_EXIT_OK;

	if (argc < 1 || !fs_cli_kind_parse (argv[0], &kind)) {
		if (argc < 1)
			fs_cli_error ("policy add needs a rule kind");
		else
			unknown_kind (argv[0]);
		fs_cli_hint ("see `stockfw help policy' for the kinds and their "
		             "fields");
		return FS_EXIT_USAGE;
	}

	want = kind_field_count (kind);
	fields = g_ptr_array_new ();

	for (gint i = 1; i < argc; i++) {
		const gchar *v;
		gint status = FS_EXIT_OK;

		if (fs_cli_take_opt (argc, argv, &i, "--comment", &v, &status)) {
			if (v == NULL) {
				g_ptr_array_unref (fields);
				return status;
			}
			comment = v;
		} else if (!fs_cli_is_positional_at (argv, i) &&
		           strcmp (argv[i], "--both") == 0) {
			both = TRUE;
		} else if (take_edit_opts (argv, i, &apply, &yes)) {
			/* taken */
		} else if (fs_cli_is_option_at (argv, i)) {
			/* Never let a mistyped option become a rule field; a
			 * field that starts with a dash goes after "--". */
			fs_cli_unknown_option ("policy add", argv[i]);
			g_ptr_array_unref (fields);
			return FS_EXIT_USAGE;
		} else
			g_ptr_array_add (fields, argv[i]);
	}

	/* "policy add inbound-allow-service SSH": a known single-port
	 * service needs no port, and a missing FOR means anyone -- the
	 * same defaults the desktop app's Add dialog starts from. */
	if (want == 3 && fields->len == 1 && kind != FS_RULE_INBOUND_FORWARD) {
		const gchar *canonical = NULL;
		const gchar *port = service_default_port (
		                        g_ptr_array_index (fields, 0), &canonical);

		if (port == NULL) {
			fs_cli_error ("no single default port for \"%s\"",
			              (const gchar *) g_ptr_array_index (fields, 0));
			fs_cli_hint ("give the port too: stockfw policy add %s %s "
			             "PORT Anyone", argv[0],
			             (const gchar *) g_ptr_array_index (fields, 0));
			g_ptr_array_unref (fields);
			return FS_EXIT_USAGE;
		}
		g_ptr_array_index (fields, 0) = (gpointer) canonical;
		g_ptr_array_add (fields, (gpointer) port);
		g_ptr_array_add (fields, (gpointer) "Anyone");
	}

	if ((gint) fields->len != want) {
		gint n = 0;
		const gchar * const *labels = fs_rule_columns (kind, &n);
		GString *expect = g_string_new (NULL);

		for (gint c = 0; c < want; c++)
			g_string_append_printf (expect, "%s<%s>",
			                        c ? " " : "", labels[c]);

		fs_cli_error ("%s takes %d field%s, got %u", argv[0], want,
		              want == 1 ? "" : "s", fields->len);
		fs_cli_hint ("stockfw policy add %s %s [--comment TEXT]",
		             argv[0], expect->str);
		g_string_free (expect, TRUE);
		g_ptr_array_unref (fields);
		return FS_EXIT_USAGE;
	}

	/* The fields go to the control layer one by one, never as a CSV
	 * row: fs_rule_validate there refuses a comma or a line break, the
	 * policy files having no quoting. */
	for (guint i = 0; i < fields->len; i++)
		if (!g_utf8_validate (g_ptr_array_index (fields, i), -1, NULL)) {
			fs_cli_error ("a field must be UTF-8 text");
			g_ptr_array_unref (fields);
			return FS_EXIT_USAGE;
		}
	if (!g_utf8_validate (comment, -1, NULL)) {
		fs_cli_error ("a comment must be UTF-8 text");
		g_ptr_array_unref (fields);
		return FS_EXIT_USAGE;
	}

	if (apply && geteuid () != 0) {
		g_ptr_array_unref (fields);
		return fs_cli_need_root ("policy add --apply");
	}

	first = g_ptr_array_index (fields, 0);
	g_ptr_array_add (fields, NULL);
	g_variant_builder_init (&b, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&b, "{sv}", "kind",
	                       g_variant_new_string (fs_cli_kind_name (kind)));
	g_variant_builder_add (&b, "{sv}", "fields",
	                       g_variant_new_strv ((const gchar * const *)
	                                           fields->pdata, -1));
	g_variant_builder_add (&b, "{sv}", "comment",
	                       g_variant_new_string (comment));
	g_variant_builder_add (&b, "{sv}", "both", g_variant_new_boolean (both));
	g_variant_builder_add (&b, "{sv}", "apply", g_variant_new_boolean (apply));
	base = g_variant_ref_sink (g_variant_builder_end (&b));
	lock = g_string_new (NULL);
	r = edit_send ("policy.add", base, apply, yes, lock, &status);
	g_variant_unref (base);

	if (r->status == FS_CONTROL_CONFIRM) {
		status = edit_refused ("added", lock, status);
		g_string_free (lock, TRUE);
		g_ptr_array_unref (fields);
		fs_control_result_free (r);
		return status;
	}
	if (r->status != FS_CONTROL_OK && r->outcome == NULL) {
		status = r->status == FS_CONTROL_USAGE ? FS_EXIT_USAGE
		       : r->status == FS_CONTROL_NEED_ROOT ? FS_EXIT_NEED_ROOT
		       : FS_EXIT_FAILURE;

		if (r->invalid_rule) {
			if (want == 1)
				fs_cli_error ("\"%s\" is not a valid address, network "
				              "or host name for %s", first,
				              fs_cli_kind_name (kind));
			else
				fs_cli_error ("not a valid %s rule: %s",
				              fs_cli_kind_name (kind),
				              r->problem != NULL ? r->problem
				              : "check the host, port or range");
			fs_cli_hint ("hosts are addresses, networks (10.0.0.0/8) "
			             "or \"Anyone\"; ports are 1-65535 or a range "
			             "1024:2048");
		} else if (!refuse_lossy_save (r->problems)) {
			fs_cli_error ("%s", r->error);
			if (r->hint != NULL)
				fs_cli_hint ("%s", r->hint);
		}
		g_string_free (lock, TRUE);
		g_ptr_array_unref (fields);
		fs_control_result_free (r);
		return status;
	}
	g_ptr_array_unref (fields);

	rule = r->rule;
	twin = r->twin;
	number = r->number;

	if (r->already) {
		if (fs_cli.json) {
			GString *out = g_string_new ("{");

			fs_json_kv_bool (out, "added", FALSE);         g_string_append_c (out, ',');
			fs_json_kv_bool (out, "already", TRUE);        g_string_append_c (out, ',');
			fs_json_kv_str (out, "kind", fs_cli_kind_name (kind)); g_string_append_c (out, ',');
			fs_json_kv_str (out, "rules_dir", fs_util_rules_dir ());
			g_string_append (out, ",\"rule\":");
			fs_cli_rule_json (out, rule, number);
			if (apply)
				status = edit_applied (r, lock, out);
			g_string_append_c (out, '}');
			fs_cli_print_json (out);
			g_string_free (out, TRUE);
		} else {
			gchar *line = rule_line (rule, number);

			if (!fs_cli.quiet)
				printf ("Already in the policy: %s\n", line);
			if (apply)
				status = edit_applied (r, lock, NULL);
			g_free (line);
		}
		g_string_free (lock, TRUE);
		fs_control_result_free (r);
		return status;
	}

	paired = twin != NULL;
	twin_number = r->twin_number;

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, "added", TRUE);           g_string_append_c (out, ',');
		fs_json_kv_str (out, "kind", fs_cli_kind_name (kind)); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "both_directions", paired); g_string_append_c (out, ',');
		if (!apply) {
			fs_json_kv_bool (out, "applied", FALSE);
			g_string_append_c (out, ',');
		}
		fs_json_kv_str (out, "rules_dir", fs_util_rules_dir ());
		g_string_append (out, ",\"rule\":");
		fs_cli_rule_json (out, rule, number);
		if (paired) {
			g_string_append (out, ",\"twin\":");
			fs_cli_rule_json (out, twin, twin_number);
		}
		row_check (rule, out);
		if (apply)
			status = edit_applied (r, lock, out);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		if (!fs_cli.quiet) {
			gchar *line = rule_line (rule, number);

			printf ("%sAdded%s %s", fs_cli_green (), fs_cli_reset (),
			        line);
			if (paired) {
				gchar *ref = fs_cli_rule_ref (twin->kind, twin_number);

				printf ("  and %s", ref);
				g_free (ref);
			}
			printf ("\n");
			g_free (line);
			row_check (rule, NULL);
		}
		status = edit_applied (r, lock, NULL);
		if (!apply)
			own_policy_note ();
	}

	if (!apply)
		lockout_note_after_edit (r->policy);
	g_string_free (lock, TRUE);
	fs_control_result_free (r);
	return status;
}

static gint
policy_remove (gint argc, gchar **argv)
{
	FsRuleKind kind;
	FsPolicy *policy;
	guint number;
	gint i = 0;
	gchar *line, *csv;
	GPtrArray *problems = NULL, *words;
	GVariantBuilder b;
	GVariant *base;
	GString *lock;
	FsControlResult *r;
	gboolean apply = FALSE, yes = FALSE;
	gint status = FS_EXIT_OK;

	/* --apply and --yes anywhere; the rest is the reference. */
	words = g_ptr_array_new ();
	for (gint w = 0; w < argc; w++) {
		if (take_edit_opts (argv, w, &apply, &yes))
			continue;
		if (fs_cli_is_option_at (argv, w)) {
			fs_cli_unknown_option ("policy remove", argv[w]);
			g_ptr_array_unref (words);
			return FS_EXIT_USAGE;
		}
		g_ptr_array_add (words, argv[w]);
	}
	g_ptr_array_add (words, NULL);
	argc = (gint) words->len - 1;
	argv = (gchar **) words->pdata;
	if (apply && geteuid () != 0) {
		g_ptr_array_unref (words);
		return fs_cli_need_root ("policy remove --apply");
	}

	policy = fs_cli_load_policy_report (NULL, &problems);
	if (refuse_lossy_save (problems)) {
		g_ptr_array_unref (problems);
		g_ptr_array_unref (words);
		fs_policy_free (policy);
		return FS_EXIT_USAGE;
	}
	g_ptr_array_unref (problems);
	if (!take_ref (argc, argv, &i, policy, &kind, &number,
	               "stockfw policy remove KIND:N  (or KIND N)")) {
		g_ptr_array_unref (words);
		fs_policy_free (policy);
		return FS_EXIT_USAGE;
	}
	if (i < argc) {
		fs_cli_error ("unexpected argument: %s", argv[i]);
		g_ptr_array_unref (words);
		fs_policy_free (policy);
		return FS_EXIT_USAGE;
	}
	g_ptr_array_unref (words);

	/* The row as read goes with the number: if another writer changed
	 * the policy since, the control layer refuses (CONFLICT) rather
	 * than remove whatever row is number N now. */
	csv = fs_rule_to_csv (g_ptr_array_index (policy->kinds[kind],
	                                         number - 1));
	fs_policy_free (policy);
	g_variant_builder_init (&b, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&b, "{sv}", "kind",
	                       g_variant_new_string (fs_cli_kind_name (kind)));
	g_variant_builder_add (&b, "{sv}", "number",
	                       g_variant_new_uint32 (number));
	if (g_utf8_validate (csv, -1, NULL))
		g_variant_builder_add (&b, "{sv}", "csv",
		                       g_variant_new_string (csv));
	g_free (csv);
	g_variant_builder_add (&b, "{sv}", "apply", g_variant_new_boolean (apply));
	base = g_variant_ref_sink (g_variant_builder_end (&b));
	lock = g_string_new (NULL);
	r = edit_send ("policy.remove", base, apply, yes, lock, &status);
	g_variant_unref (base);

	if (r->status == FS_CONTROL_CONFIRM) {
		status = edit_refused ("removed", lock, status);
		g_string_free (lock, TRUE);
		fs_control_result_free (r);
		return status;
	}
	if (!r->saved) {
		status = edit_failed (r);
		g_string_free (lock, TRUE);
		fs_control_result_free (r);
		return status;
	}

	line = rule_line (r->rule, number);
	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, "removed", TRUE); g_string_append_c (out, ',');
		fs_json_kv_str (out, "kind", fs_cli_kind_name (kind));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "rules_dir", fs_util_rules_dir ());
		g_string_append (out, ",\"rule\":");
		fs_cli_rule_json (out, r->rule, number);
		row_check (r->rule, out);
		if (apply)
			status = edit_applied (r, lock, out);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		if (!fs_cli.quiet) {
			printf ("%sRemoved%s %s\n", fs_cli_red (), fs_cli_reset (),
			        line);
			row_check (r->rule, NULL);
		}
		status = edit_applied (r, lock, NULL);
	}

	if (!apply)
		lockout_note_after_edit (r->policy);
	g_free (line);
	g_string_free (lock, TRUE);
	fs_control_result_free (r);
	return status;
}

/* [ rule_field ] -- field c of a rule, in the order `policy add' takes
 * them (the CSV order, less the comment). */
static const gchar *
rule_field (const FsRule *rule, gint c)
{
	switch (rule->kind) {
	case FS_RULE_INBOUND_FORWARD: {
		const gchar *f[] = { rule->service, rule->port, rule->to,
		                     rule->to_port };
		return c < 4 ? f[c] : NULL;
	}
	case FS_RULE_INBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_DENY_SERVICE: {
		const gchar *f[] = { rule->service, rule->port, rule->target };
		return c < 3 ? f[c] : NULL;
	}
	default:
		return c == 0 ? rule->target : NULL;
	}
}

/* [ policy_edit ]
 * E4: one rule changed in place -- same kind, same number, one save
 * (policy.replace, fs_policy_replace_persist).  All of the kind's
 * fields, "-" keeping a field as it is, or none when only --comment
 * changes.  The comment is kept unless --comment is given.  The row
 * read here goes with the request, so a row another writer changed
 * meanwhile is refused (CONFLICT), never overwritten. */
static gint
policy_edit (gint argc, gchar **argv)
{
	FsPolicy *policy;
	GPtrArray *problems = NULL, *words, *fields;
	FsRuleKind kind;
	guint number;
	gint i = 0, want;
	const gchar *comment = NULL;
	gboolean apply = FALSE, yes = FALSE;
	const FsRule *old;
	gchar *csv;
	GVariantBuilder b;
	GVariant *base;
	GString *lock;
	FsControlResult *r;
	gint status = FS_EXIT_OK;
	static const gchar usage[] =
		"stockfw policy edit KIND:N [FIELD...] [--comment TEXT]";

	words = g_ptr_array_new ();
	for (gint w = 0; w < argc; w++) {
		const gchar *v;
		gint st = FS_EXIT_OK;

		if (fs_cli_take_opt (argc, argv, &w, "--comment", &v, &st)) {
			if (v == NULL) {
				g_ptr_array_unref (words);
				return st;
			}
			comment = v;
		} else if (take_edit_opts (argv, w, &apply, &yes)) {
			/* taken */
		} else if (fs_cli_is_option_at (argv, w)) {
			fs_cli_unknown_option ("policy edit", argv[w]);
			g_ptr_array_unref (words);
			return FS_EXIT_USAGE;
		} else {
			g_ptr_array_add (words, argv[w]);
		}
	}
	g_ptr_array_add (words, NULL);
	if (apply && geteuid () != 0) {
		g_ptr_array_unref (words);
		return fs_cli_need_root ("policy edit --apply");
	}

	policy = fs_cli_load_policy_report (NULL, &problems);
	if (refuse_lossy_save (problems) ||
	    !take_ref ((gint) words->len - 1, (gchar **) words->pdata, &i,
	               policy, &kind, &number, usage)) {
		g_ptr_array_unref (problems);
		g_ptr_array_unref (words);
		fs_policy_free (policy);
		return FS_EXIT_USAGE;
	}
	g_ptr_array_unref (problems);

	old = g_ptr_array_index (policy->kinds[kind], number - 1);
	want = kind_field_count (kind);
	fields = g_ptr_array_new ();
	for (guint w = (guint) i; w + 1 < words->len; w++) {
		const gchar *f = g_ptr_array_index (words, w);
		gint c = (gint) fields->len;

		/* "-" keeps the field as it is. */
		g_ptr_array_add (fields, (gpointer) (strcmp (f, "-") == 0 &&
		                                     c < want
		                                     ? rule_field (old, c) : f));
	}
	g_ptr_array_unref (words);

	if (fields->len == 0 && comment == NULL) {
		fs_cli_error ("nothing to change: give the fields, or --comment");
		fs_cli_hint ("%s  (\"-\" keeps a field)", usage);
		g_ptr_array_unref (fields);
		fs_policy_free (policy);
		return FS_EXIT_USAGE;
	}
	if (fields->len == 0) {
		for (gint c = 0; c < want; c++)
			g_ptr_array_add (fields, (gpointer) rule_field (old, c));
	} else if ((gint) fields->len != want) {
		gint n = 0;
		const gchar * const *labels = fs_rule_columns (kind, &n);
		GString *expect = g_string_new (NULL);

		for (gint c = 0; c < want; c++)
			g_string_append_printf (expect, "%s<%s>",
			                        c ? " " : "", labels[c]);
		fs_cli_error ("%s takes %d field%s, got %u",
		              fs_cli_kind_name (kind), want, want == 1 ? "" : "s",
		              fields->len);
		fs_cli_hint ("stockfw policy edit %s:%u %s  (\"-\" keeps a "
		             "field)", fs_cli_kind_name (kind), number,
		             expect->str);
		g_string_free (expect, TRUE);
		g_ptr_array_unref (fields);
		fs_policy_free (policy);
		return FS_EXIT_USAGE;
	}

	for (guint f = 0; f < fields->len; f++)
		if (g_ptr_array_index (fields, f) == NULL)
			g_ptr_array_index (fields, f) = (gpointer) "";
	for (guint f = 0; f < fields->len; f++)
		if (!g_utf8_validate (g_ptr_array_index (fields, f), -1, NULL)) {
			fs_cli_error ("a field must be UTF-8 text");
			g_ptr_array_unref (fields);
			fs_policy_free (policy);
			return FS_EXIT_USAGE;
		}
	if (comment != NULL && !g_utf8_validate (comment, -1, NULL)) {
		fs_cli_error ("a comment must be UTF-8 text");
		g_ptr_array_unref (fields);
		fs_policy_free (policy);
		return FS_EXIT_USAGE;
	}

	csv = fs_rule_to_csv (old);
	g_ptr_array_add (fields, NULL);
	g_variant_builder_init (&b, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&b, "{sv}", "kind",
	                       g_variant_new_string (fs_cli_kind_name (kind)));
	g_variant_builder_add (&b, "{sv}", "number",
	                       g_variant_new_uint32 (number));
	if (g_utf8_validate (csv, -1, NULL))
		g_variant_builder_add (&b, "{sv}", "csv",
		                       g_variant_new_string (csv));
	g_variant_builder_add (&b, "{sv}", "fields",
	                       g_variant_new_strv ((const gchar * const *)
	                                           fields->pdata, -1));
	if (comment != NULL)
		g_variant_builder_add (&b, "{sv}", "comment",
		                       g_variant_new_string (comment));
	g_variant_builder_add (&b, "{sv}", "apply", g_variant_new_boolean (apply));
	base = g_variant_ref_sink (g_variant_builder_end (&b));
	g_free (csv);
	g_ptr_array_unref (fields);
	fs_policy_free (policy);

	lock = g_string_new (NULL);
	r = edit_send ("policy.replace", base, apply, yes, lock, &status);
	g_variant_unref (base);

	if (r->status == FS_CONTROL_CONFIRM) {
		status = edit_refused ("changed", lock, status);
	} else if (!r->saved) {
		if (r->invalid_rule) {
			fs_cli_error ("not a valid %s rule: %s",
			              fs_cli_kind_name (kind),
			              r->problem != NULL ? r->problem
			              : "check the host, port or range");
			fs_cli_hint ("hosts are addresses, networks (10.0.0.0/8) "
			             "or \"Anyone\"; ports are 1-65535 or a range "
			             "1024:2048");
			status = FS_EXIT_USAGE;
		} else {
			status = edit_failed (r);
		}
	} else if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, "changed", TRUE);  g_string_append_c (out, ',');
		fs_json_kv_str (out, "kind", fs_cli_kind_name (kind));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "rules_dir", fs_util_rules_dir ());
		g_string_append (out, ",\"rule\":");
		fs_cli_rule_json (out, r->rule, r->number);
		g_string_append (out, ",\"was\":");
		fs_cli_rule_json (out, r->old, r->number);
		row_check (r->rule, out);
		status = edit_applied (r, lock, out);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		if (!fs_cli.quiet) {
			gchar *line = rule_line (r->rule, r->number);
			gchar *was = fs_cli_rule_summary (r->old);
			gchar *safe_was = fs_cli_out_safe (was);

			printf ("%sChanged%s %s\n", fs_cli_green (), fs_cli_reset (),
			        line);
			printf ("%s  was: %s%s\n", fs_cli_dim (), safe_was,
			        fs_cli_reset ());
			if (g_strcmp0 (r->old->comment, r->rule->comment) != 0) {
				gchar *c = fs_cli_out_safe (r->rule->comment);

				printf ("  comment: %s\n", *c != '\0' ? c : "(none)");
				g_free (c);
			}
			g_free (safe_was);
			g_free (was);
			g_free (line);
			row_check (r->rule, NULL);
		}
		status = edit_applied (r, lock, NULL);
		if (!apply)
			own_policy_note ();
	}

	if (r->saved && !apply)
		lockout_note_after_edit (r->policy);
	g_string_free (lock, TRUE);
	fs_control_result_free (r);
	return status;
}

/* [ policy_init ]
 * A19: the default rules a first run of the desktop app seeds (DHCP
 * and DNS out), saved -- for a computer that never had the desktop
 * app.  A saved policy with rules is replaced only with --force. */
static gint
policy_init (gint argc, gchar **argv)
{
	gboolean force = FALSE;
	GVariantBuilder b;
	FsControlActor actor;
	FsControlResult *r;
	gint status = FS_EXIT_OK;

	for (gint i = 0; i < argc; i++) {
		if (fs_cli_is_option_at (argv, i) &&
		    strcmp (argv[i], "--force") == 0) {
			force = TRUE;
		} else if (fs_cli_is_option_at (argv, i)) {
			fs_cli_unknown_option ("policy init", argv[i]);
			return FS_EXIT_USAGE;
		} else {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			return FS_EXIT_USAGE;
		}
	}

	g_variant_builder_init (&b, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&b, "{sv}", "force", g_variant_new_boolean (force));
	actor = fs_control_actor_self ("cli");
	r = fs_control_do (&actor, "policy.init", g_variant_builder_end (&b));

	if (!r->saved) {
		status = r->status == FS_CONTROL_USAGE ? FS_EXIT_USAGE
		       : FS_EXIT_FAILURE;
		fs_cli_error ("%s", r->error);
		if (r->hint != NULL)
			fs_cli_hint ("%s", r->hint);
	} else if (fs_cli.json) {
		GString *out = g_string_new ("{");
		guint shown = 0;

		fs_json_kv_bool (out, "initialized", TRUE); g_string_append_c (out, ',');
		fs_json_kv_str (out, "rules_dir", fs_util_rules_dir ());
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "replaced", r->dropped);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "applied", FALSE);
		g_string_append (out, ",\"rules\":[");
		for (gint k = 0; k < FS_RULE_N_KINDS; k++)
			for (guint n = 0; n < r->policy->kinds[k]->len; n++) {
				if (shown++ > 0)
					g_string_append_c (out, ',');
				fs_cli_rule_json (out,
				                  g_ptr_array_index (r->policy->kinds[k], n),
				                  n + 1);
			}
		g_string_append (out, "]}");
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (!fs_cli.quiet) {
		gchar *dir = fs_cli_out_safe (fs_util_rules_dir ());

		printf ("%sSaved%s the default rules in %s", fs_cli_green (),
		        fs_cli_reset (), dir);
		if (r->dropped > 0)
			printf (" (they replace %u rule%s)", r->dropped,
			        r->dropped == 1 ? "" : "s");
		printf (":\n");
		for (gint k = 0; k < FS_RULE_N_KINDS; k++)
			for (guint n = 0; n < r->policy->kinds[k]->len; n++) {
				gchar *line = rule_line (
				        g_ptr_array_index (r->policy->kinds[k], n), n + 1);

				printf ("  %s\n", line);
				g_free (line);
			}
		g_free (dir);
		printf ("Nothing comes in unless a rule allows it.  Add what this "
		        "computer serves,\nfor example: stockfw policy add "
		        "inbound-allow-service SSH\n");
		not_live_line ();
		own_policy_note ();
	}

	fs_control_result_free (r);
	return status;
}

/* ------------------------------------------------- diff and the preview */

/* [ Diff ] -- saved against applied, row by row (CSV identity, as the
 * apply gate's impact counts them). */
typedef struct
{
	GPtrArray *added;     /* const FsRule*, borrowed from saved      */
	GArray    *added_n;   /* guint: numbers in the saved policy      */
	GPtrArray *removed;   /* const FsRule*, borrowed from applied    */
	GArray    *removed_n; /* guint: numbers as applied               */
	guint      unchanged;
} Diff;

static Diff *
diff_new (const FsPolicy *saved, const FsPolicy *applied)
{
	Diff *d = g_new0 (Diff, 1);

	d->added = g_ptr_array_new ();
	d->added_n = g_array_new (FALSE, FALSE, sizeof (guint));
	d->removed = g_ptr_array_new ();
	d->removed_n = g_array_new (FALSE, FALSE, sizeof (guint));

	for (gint k = 0; k < FS_RULE_N_KINDS; k++) {
		for (guint i = 0; i < saved->kinds[k]->len; i++) {
			const FsRule *r = g_ptr_array_index (saved->kinds[k], i);
			guint n = i + 1;

			if (applied != NULL && fs_policy_contains (applied, r)) {
				d->unchanged++;
				continue;
			}
			g_ptr_array_add (d->added, (gpointer) r);
			g_array_append_val (d->added_n, n);
		}
		for (guint i = 0; applied != NULL &&
		                  i < applied->kinds[k]->len; i++) {
			const FsRule *r = g_ptr_array_index (applied->kinds[k], i);
			guint n = i + 1;

			if (fs_policy_contains (saved, r))
				continue;
			g_ptr_array_add (d->removed, (gpointer) r);
			g_array_append_val (d->removed_n, n);
		}
	}
	return d;
}

static void
diff_free (Diff *d)
{
	g_ptr_array_unref (d->added);
	g_array_unref (d->added_n);
	g_ptr_array_unref (d->removed);
	g_array_unref (d->removed_n);
	g_free (d);
}

static void
diff_rows_json (GString *out, const gchar *key, GPtrArray *rows,
                GArray *numbers)
{
	fs_json_key (out, key);
	g_string_append_c (out, '[');
	for (guint i = 0; i < rows->len; i++) {
		if (i > 0)
			g_string_append_c (out, ',');
		fs_cli_rule_json (out, g_ptr_array_index (rows, i),
		                  g_array_index (numbers, guint, i));
	}
	g_string_append_c (out, ']');
}

static void
diff_rows_print (const Diff *d)
{
	for (guint i = 0; i < d->added->len; i++) {
		gchar *line = rule_line (g_ptr_array_index (d->added, i),
		                         g_array_index (d->added_n, guint, i));

		printf ("%s+%s %s\n", fs_cli_green (), fs_cli_reset (), line);
		g_free (line);
	}
	for (guint i = 0; i < d->removed->len; i++) {
		gchar *line = rule_line (g_ptr_array_index (d->removed, i),
		                         g_array_index (d->removed_n, guint, i));

		printf ("%s-%s %s  %s(as applied)%s\n", fs_cli_red (),
		        fs_cli_reset (), line, fs_cli_dim (), fs_cli_reset ());
		g_free (line);
	}
	printf ("= %u rule%s unchanged\n", d->unchanged,
	        d->unchanged == 1 ? "" : "s");
}

/* [ is_name ] -- a host field that is a name, looked up at apply. */
static gboolean
is_name (const gchar *host)
{
	FsRange4 r4;
	FsRange6 r6;

	return host != NULL && *host != '\0' &&
	       g_ascii_strcasecmp (host, FS_TARGET_ANY) != 0 &&
	       fs_range_parse (host, &r4, &r6, NULL, NULL) == FS_AF_NONE;
}

/* [ preview_notes ]
 * What an apply would say afterwards and can be known before it: a
 * forward with no external interface is left out, and a host name is
 * looked up at apply (whether that works cannot be known here). */
static GPtrArray *
preview_notes (const FsPolicy *policy)
{
	GPtrArray *notes = g_ptr_array_new_with_free_func (g_free);
	gchar *ext = fs_prefs_string (FS_PREFS_FW_EXT_IF);
	GPtrArray *fwd = policy->kinds[FS_RULE_INBOUND_FORWARD];

	for (guint i = 0; i < fwd->len; i++) {
		const FsRule *r = g_ptr_array_index (fwd, i);
		gchar *ref = fs_cli_rule_ref (FS_RULE_INBOUND_FORWARD, i + 1);

		if (ext == NULL || *ext == '\0')
			g_ptr_array_add (notes, g_strdup_printf (
				"%s: the forward to %s will be left out: no "
				"external interface is set (desktop app: "
				"Preferences)", ref, r->to != NULL ? r->to : "?"));
		else if (is_name (r->to))
			g_ptr_array_add (notes, g_strdup_printf (
				"%s: %s will be looked up at apply", ref, r->to));
		g_free (ref);
	}
	for (gint k = 0; k < FS_RULE_N_KINDS; k++) {
		if (k == FS_RULE_INBOUND_FORWARD)
			continue;
		for (guint i = 0; i < policy->kinds[k]->len; i++) {
			const FsRule *r = g_ptr_array_index (policy->kinds[k], i);
			gchar *ref;

			if (!is_name (r->target))
				continue;
			ref = fs_cli_rule_ref ((FsRuleKind) k, i + 1);
			g_ptr_array_add (notes, g_strdup_printf (
				"%s: %s will be looked up at apply", ref, r->target));
			g_free (ref);
		}
	}
	g_free (ext);
	return notes;
}

static void
notes_json (GString *out, const GPtrArray *notes)
{
	fs_json_key (out, "notes");
	g_string_append_c (out, '[');
	for (guint i = 0; i < notes->len; i++) {
		if (i > 0)
			g_string_append_c (out, ',');
		fs_json_string (out, g_ptr_array_index (notes, i));
	}
	g_string_append_c (out, ']');
}

static void
notes_print (const GPtrArray *notes)
{
	if (fs_cli.quiet)
		return;
	for (guint i = 0; i < notes->len; i++) {
		gchar *safe = fs_cli_out_safe (g_ptr_array_index (notes, i));

		printf ("%snote:%s %s\n", fs_cli_amber (), fs_cli_reset (), safe);
		g_free (safe);
	}
}

/* [ firewall_word ] -- "running", "stopped" or "unknown", as root
 * only (netfilter cannot be read without it). */
static const gchar *
firewall_word (FsFirewallState *state_out)
{
	FsFirewallState st = FS_FW_NONE;

	if (geteuid () == 0 && fs_backend ()->get_state != NULL)
		st = fs_backend ()->get_state ();
	if (state_out != NULL)
		*state_out = st;
	switch (st) {
	case FS_FW_STOPPED: return "stopped";
	case FS_FW_NONE:    return "unknown";
	default:            return "running";
	}
}

/* [ journal_epoch ] -- when the journal was written, or 0. */
static gint64
journal_epoch (void)
{
	gchar *path = fs_apply_journal_path ();
	GStatBuf st;
	gint64 when = 0;

	if (path != NULL && g_stat (path, &st) == 0)
		when = (gint64) st.st_mtime;
	g_free (path);
	return when;
}

static gint
policy_diff (gint argc, gchar **argv)
{
	FsPolicy *saved, *applied = NULL;
	GPtrArray *problems = NULL;
	gboolean settings_pending = FALSE;
	FsCliLive live;
	GError *error = NULL;
	Diff *d;
	GPtrArray *notes;
	gint64 when;
	const gchar *fw;

	for (gint i = 0; i < argc; i++) {
		if (fs_cli_is_option_at (argv, i))
			fs_cli_unknown_option ("policy diff", argv[i]);
		else
			fs_cli_error ("unexpected argument: %s", argv[i]);
		return FS_EXIT_USAGE;
	}

	saved = fs_cli_load_policy_report (NULL, &problems);

	/* An unreadable journal is a question of rights, and says so. */
	{
		FsPolicy *probe = fs_policy_new ();

		if (!fs_apply_journal_load (probe, &error) &&
		    !g_error_matches (error, FS_APPLY_ERROR,
		                      FS_APPLY_ERR_NO_JOURNAL)) {
			gboolean rights = g_error_matches (error, FS_APPLY_ERROR,
			                                   FS_APPLY_ERR_UNREADABLE);

			fs_cli_error ("the record of the applied policy cannot be "
			              "read: %s", error->message);
			if (rights && geteuid () != 0) {
				gchar *again = fs_cli_sudo_hint ("policy diff");

				fs_cli_hint ("it is root's; run `%s'", again);
				g_free (again);
			}
			g_clear_error (&error);
			fs_policy_free (probe);
			g_ptr_array_unref (problems);
			fs_policy_free (saved);
			return rights ? FS_EXIT_NEED_ROOT : FS_EXIT_FAILURE;
		}
		g_clear_error (&error);
		fs_policy_free (probe);
	}

	live = fs_cli_policy_state (saved, &applied, &settings_pending);
	d = diff_new (saved, applied);
	notes = preview_notes (saved);
	when = applied != NULL ? journal_epoch () : 0;
	fw = firewall_word (NULL);

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "rules_dir", fs_util_rules_dir ());
		g_string_append_c (out, ',');
		if (when > 0)
			fs_json_kv_time (out, "applied_at", when);
		else
			g_string_append (out, "\"applied_at\":null,\"epoch\":null");
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "live", fs_cli_live_name (live));
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "settings_pending", settings_pending);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "firewall_state", fw);
		g_string_append_c (out, ',');
		diff_rows_json (out, "added", d->added, d->added_n);
		g_string_append_c (out, ',');
		diff_rows_json (out, "removed", d->removed, d->removed_n);
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "unchanged", d->unchanged);
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "malformed_rules", problems->len);
		g_string_append_c (out, ',');
		notes_json (out, notes);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		fs_cli_print_problems (problems);
		if (applied == NULL) {
			printf ("Saved %s; nothing was applied yet: every rule is "
			        "new.\n", fs_util_rules_dir ());
		} else {
			gchar *t = fs_cli_time_text (when, FS_CLI_TIME_FULL);

			printf ("Saved %s vs applied %s\n", fs_util_rules_dir (), t);
			g_free (t);
		}
		diff_rows_print (d);
		if (settings_pending)
			printf ("Settings changed since the last apply.\n");
		notes_print (notes);
		if (d->added->len > 0 || d->removed->len > 0 ||
		    settings_pending || live == FS_CLI_LIVE_STOPPED) {
			gchar *apply = fs_cli_sudo_hint ("apply");

			printf ("Firewall: %s.  Make it live: %s\n",
			        g_strcmp0 (fw, "unknown") == 0
			        ? "unknown (needs root)" : fw, apply);
			g_free (apply);
		} else {
			printf ("Firewall: %s.  The saved policy is the applied "
			        "one.\n", g_strcmp0 (fw, "unknown") == 0
			        ? "unknown (needs root)" : fw);
		}
	}

	g_ptr_array_unref (notes);
	diff_free (d);
	if (applied != NULL)
		fs_policy_free (applied);
	g_ptr_array_unref (problems);
	fs_policy_free (saved);
	return FS_EXIT_OK;
}

gint
fs_cli_cmd_policy (gint argc, gchar **argv)
{
	const gchar *sub = argc > 1 ? argv[1] : "list";
	static const gchar * const subs[] = {
		"list", "show", "add", "edit", "remove", "diff", "init"
	};

	if (strcmp (sub, "list") == 0 || strcmp (sub, "ls") == 0)
		return policy_list (argc > 1 ? argc - 2 : 0, argv + 2);
	if (strcmp (sub, "show") == 0)
		return policy_show (argc - 2, argv + 2);
	if (strcmp (sub, "add") == 0)
		return policy_add (argc - 2, argv + 2);
	if (strcmp (sub, "remove") == 0 || strcmp (sub, "rm") == 0)
		return policy_remove (argc - 2, argv + 2);
	if (strcmp (sub, "edit") == 0)
		return policy_edit (argc - 2, argv + 2);
	if (strcmp (sub, "init") == 0)
		return policy_init (argc - 2, argv + 2);
	if (strcmp (sub, "diff") == 0)
		return policy_diff (argc - 2, argv + 2);

	/* `policy --kind KIND' is `policy list --kind KIND', and so is
	 * `policy in' or `policy inbound-allow-service'. */
	if (fs_cli_is_option_at (argv, 1))
		return policy_list (argc - 1, argv + 1);
	{
		FsRuleKind k;

		if (fs_cli_kind_parse (sub, &k) || strcmp (sub, "in") == 0 ||
		    strcmp (sub, "out") == 0)
			return policy_list (argc - 1, argv + 1);
	}

	{
		const gchar *best = fs_cli_suggest (sub, subs, G_N_ELEMENTS (subs));

		if (best != NULL)
			fs_cli_error ("unknown policy action: %s (did you mean "
			              "`stockfw policy %s'?)", sub, best);
		else
			fs_cli_error ("unknown policy action: %s", sub);
	}
	fs_cli_hint ("policy list | show | add | edit | remove | diff | init");
	return FS_EXIT_USAGE;
}

/* ------------------------------------------------------- lockout guard */

/* [ lockout_ref ] -- the rule the worst pair stops at, or NULL. */
static gchar *
lockout_ref (const FsLockoutReport *report)
{
	if (report->worst != NULL && report->worst->policy_kind >= 0)
		return fs_cli_rule_ref ((FsRuleKind) report->worst->policy_kind,
		                        (guint) report->worst->policy_index + 1);
	return NULL;
}

/* [ lockout_warn ] -- the warning, and the rows that name the port. */
static void
lockout_warn (const FsLockoutReport *report, const FsPolicy *policy)
{
	const FsLockoutPair *w = report->worst;
	gchar *ref = lockout_ref (report);
	gchar *port_text = g_strdup_printf ("%u", w->port);
	GPtrArray *rows = policy->kinds[FS_RULE_INBOUND_ALLOW_SERVICE];
	/* The reason can name a rule after the policy's rows. */
	gchar *why = fs_cli_out_safe (ref != NULL ? ref
	                              : w->reason != NULL ? w->reason
	                              : "no rule allows it");

	warn ("this policy would block your SSH session");
	g_printerr ("  from %s to port %u: %s (%s)\n", w->peer, w->port,
	            fs_whatif_verdict_name (w->verdict), why);
	g_free (why);
	for (guint i = 0; i < rows->len; i++) {
		const FsRule *r = g_ptr_array_index (rows, i);
		gchar *first = first_port (r->port);

		if (g_strcmp0 (first, port_text) == 0) {
			gchar *rref = fs_cli_rule_ref (r->kind, i + 1);
			gchar *who = fs_cli_out_safe (r->target);
			gchar *svc = fs_cli_out_safe (r->service);

			g_printerr ("  %s %s allows %s only\n", rref, svc, who);
			g_free (svc);
			g_free (who);
			g_free (rref);
		}
		g_free (first);
	}
	g_free (port_text);
	g_free (ref);
}

/* [ lockout_ask ] -- --yes goes on; a terminal on stdin is asked;
 * anything else is refused.  TRUE to go on. */
static gboolean
lockout_ask (const gchar *verb, gboolean yes, gboolean *confirmed)
{
	if (yes) {
		*confirmed = TRUE;
		return TRUE;
	}
	if (isatty (0)) {
		gchar answer[16] = "";

		g_printerr ("%s anyway? [y/N] ", verb);
		fflush (stderr);
		if (fgets (answer, sizeof answer, stdin) != NULL &&
		    (g_ascii_strncasecmp (answer, "y", 1) == 0)) {
			*confirmed = TRUE;
			return TRUE;
		}
		fs_cli_error ("not done: the firewall was left as it was");
		return FALSE;
	}
	fs_cli_error ("refused: pass --yes to %s anyway",
	              strcmp (verb, "Start") == 0 ? "start" : "apply");
	return FALSE;
}

/* [ lockout_json ] -- the "lockout":{...} member. */
static void
lockout_json (GString *json, const FsLockoutReport *report,
              gboolean confirmed)
{
	gchar *ref = lockout_ref (report);

	g_string_append (json, ",\"lockout\":{");
	fs_json_kv_bool (json, "checked", report->checked);
	g_string_append_c (json, ',');
	if (!report->checked) {
		fs_json_kv_str (json, "reason", report->why_not);
	} else {
		fs_json_kv_str (json, "client", report->worst->peer);
		g_string_append_c (json, ',');
		fs_json_kv_uint (json, "port", report->worst->port);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "verdict",
		                fs_whatif_verdict_name (report->verdict));
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "rule_ref", ref);
		g_string_append_c (json, ',');
		fs_json_kv_uint (json, "peers", report->pairs->len);
		g_string_append_c (json, ',');
		fs_json_kv_uint (json, "skipped", report->skipped);
		g_string_append_c (json, ',');
		fs_json_kv_bool (json, "confirmed", confirmed);
	}
	g_string_append_c (json, '}');
	g_free (ref);
}

/* [ lockout_guard ]
 * The dry run's guard: would `policy' cut an SSH session of this
 * computer?  It only warns (the real apply and start are guarded by
 * the control layer, control_guarded).  Appends "lockout":{...} to
 * json when given. */
static void
lockout_guard (const FsPolicy *policy, GString *json)
{
	FsRangeSet *own = NULL, *peers = NULL;
	GArray *ports = NULL;
	FsSettings *settings = fs_settings_new ();
	FsLockoutReport *report;

	fs_settings_load_prefs (settings);
	fs_lockout_sessions (&own, &peers, &ports);
	/* This session's own peer first, so a busy host's other sessions
	 * cannot push it past the cap. */
	report = fs_lockout_check_own (policy, settings, own, peers, ports);
	if (fs_lockout_report_cuts (report))
		lockout_warn (report, policy);
	if (json != NULL)
		lockout_json (json, report, FALSE);

	fs_lockout_report_free (report);
	fs_range_set_free (own);
	fs_range_set_free (peers);
	g_array_unref (ports);
	fs_settings_free (settings);
}

/* [ control_send ] -- an op with `base' (a{sv}, or NULL; not taken)
 * and "yes". */
static FsControlResult *
control_send (const gchar *op, GVariant *base, gboolean yes)
{
	FsControlActor actor = fs_control_actor_self ("cli");
	GVariantDict d;

	g_variant_dict_init (&d, base);
	g_variant_dict_insert (&d, "yes", "b", yes);
	return fs_control_do (&actor, op, g_variant_dict_end (&d));
}

/* [ control_guarded ]
 * An op the lockout guard stands in front of (apply, start).  The
 * control layer never asks: when the op would cut an SSH session it
 * answers CONFIRM and changes nothing, so the warning is shown here,
 * the user asked (or --yes taken), and the op sent again with "yes".
 * `seen', when given, sees the first answer before any question.
 * Appends the "lockout" member to `lock'.  Never NULL; still CONFIRM
 * when the user did not confirm (*status = FS_EXIT_FAILURE). */
static FsControlResult *
control_guarded (const gchar *op, GVariant *base, gboolean yes,
                 const gchar *verb, GString *lock, gint *status,
                 void (*seen) (const FsControlResult *r))
{
	FsControlResult *r = control_send (op, base, yes);
	gboolean confirmed = FALSE;

	if (seen != NULL)
		seen (r);
	if (r->lockout != NULL && fs_lockout_report_cuts (r->lockout))
		lockout_warn (r->lockout, r->lockout_policy);
	if (r->status == FS_CONTROL_CONFIRM) {
		if (lockout_ask (verb, FALSE, &confirmed)) {
			fs_control_result_free (r);
			r = control_send (op, base, TRUE);
		} else {
			*status = FS_EXIT_FAILURE;
		}
	}
	if (r->lockout != NULL)
		lockout_json (lock, r->lockout, r->lockout_confirmed);
	return r;
}

/* --------------------------------------------------------------- apply */

static const gchar *
was_word (FsFirewallState st)
{
	switch (st) {
	case FS_FW_STOPPED: return "stopped";
	case FS_FW_NONE:    return "unknown";
	default:            return "running";
	}
}

static gboolean intel_print (const FsControlIntel *in, GString *json);

static gint
apply_dry_run (FsPolicy *policy, gboolean verbose, gboolean yes)
{
	FsPolicy *applied = fs_policy_new ();
	gboolean have = fs_apply_journal_load (applied, NULL);
	FsPolicyImpact *impact = fs_policy_impact (have ? applied : NULL,
	                                           policy);
	Diff *d = diff_new (policy, have ? applied : NULL);
	GPtrArray *notes = preview_notes (policy);
	gchar *desc = fs_policy_impact_describe (impact);
	FsFirewallState st;
	const gchar *fw = firewall_word (&st);
	gint status = FS_EXIT_OK;
	GString *lock = g_string_new (NULL);

	/* Any user: it only reports. */
	(void) yes;
	lockout_guard (policy, lock);

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, "dry_run", TRUE);       g_string_append_c (out, ',');
		fs_json_kv_uint (out, "added", impact->added); g_string_append_c (out, ',');
		fs_json_kv_uint (out, "removed", impact->removed); g_string_append_c (out, ',');
		fs_json_kv_uint (out, "unchanged", impact->unchanged); g_string_append_c (out, ',');
		fs_json_kv_str (out, "impact", desc);         g_string_append_c (out, ',');
		fs_json_kv_str (out, "firewall_state", fw);   g_string_append_c (out, ',');
		diff_rows_json (out, "added_rules", d->added, d->added_n);
		g_string_append_c (out, ',');
		diff_rows_json (out, "removed_rules", d->removed, d->removed_n);
		g_string_append_c (out, ',');
		notes_json (out, notes);
		g_string_append (out, lock->str);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		if (st == FS_FW_STOPPED)
			printf ("The firewall is stopped: apply would load the "
			        "whole policy (%u rules) and start it.\n",
			        fs_cli_policy_total (policy));
		printf ("Would apply: %s\n", desc);
		diff_rows_print (d);
		notes_print (notes);
		if (verbose) {
			FsSettings *settings = fs_settings_new ();
			static const FsFamily fams[] = { FS_FAMILY_IPV4,
			                                 FS_FAMILY_IPV6 };

			fs_settings_load_prefs (settings);
			for (guint f = 0; f < G_N_ELEMENTS (fams); f++) {
				for (gint in = 1; in >= 0; in--) {
					gchar *text = fs_whatif_linux_chain_text (
						policy, settings, fams[f], in);

					printf ("\n%s%s %s chain%s\n", fs_cli_bold (),
					        fams[f] == FS_FAMILY_IPV4 ? "IPv4" : "IPv6",
					        in ? "INBOUND" : "OUTBOUND",
					        fs_cli_reset ());
					printf ("%s", text);
					if (*text != '\0' && text[strlen (text) - 1] != '\n')
						printf ("\n");
					g_free (text);
				}
			}
			fs_settings_free (settings);
		}
		printf ("%sNothing was changed (dry run).%s\n",
		        fs_cli_dim (), fs_cli_reset ());
	}

	g_string_free (lock, TRUE);
	g_free (desc);
	g_ptr_array_unref (notes);
	diff_free (d);
	fs_policy_impact_free (impact);
	fs_policy_free (applied);
	return status;
}

/* [ apply_status ] -- the exit status an apply outcome gives. */
static gint
apply_status (const FsApplyOutcome *outcome)
{
	if (outcome->held || outcome->result == FS_APPLY_OK)
		return FS_EXIT_OK;
	if (outcome->result == FS_APPLY_NO_PRIVILEGE)
		return FS_EXIT_NEED_ROOT;
	return FS_EXIT_FAILURE;
}

/* [ apply_json_members ]
 * The members of `apply --json' ("applied" ... "notes", the lockout
 * member `lock' and "intel"), without the braces: `apply' prints them
 * as its object, an edit with --apply as its "apply" member. */
static void
apply_json_members (GString *out, const FsControlResult *r,
                    const gchar *lock)
{
	const FsApplyOutcome *outcome = r->outcome;
	gchar *desc = fs_policy_impact_describe (outcome->impact);

	fs_json_kv_bool (out, "applied", outcome->applied);   g_string_append_c (out, ',');
	fs_json_kv_bool (out, "held", outcome->held);         g_string_append_c (out, ',');
	fs_json_kv_str (out, "hold_reason", outcome->hold_reason); g_string_append_c (out, ',');
	fs_json_kv_bool (out, "narrow", outcome->narrow);     g_string_append_c (out, ',');
	fs_json_kv_bool (out, "settings", outcome->settings); g_string_append_c (out, ',');
	fs_json_kv_str (out, "firewall_was", was_word (outcome->firewall_was));
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "result",
	                fs_util_apply_result_to_string ((int) outcome->result));
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "impact", desc);                 g_string_append_c (out, ',');
	fs_json_kv_str (out, "error", r->error);              g_string_append_c (out, ',');
	fs_json_kv_bool (out, "rollback_attempted", outcome->rollback_attempted); g_string_append_c (out, ',');
	fs_json_kv_bool (out, "rollback_verified", outcome->rollback_verified);
	g_string_append_c (out, ',');
	fs_json_key (out, "notes");
	fs_cli_append_lines_json (out, outcome->notes);
	g_string_append (out, lock);
	/* An apply that started a stopped firewall brought the
	 * blocklists back, as a start does. */
	if (r->intel.ran)
		intel_print (&r->intel, out);
	g_free (desc);
}

/* [ apply_print ] -- what `apply' prints for an outcome. */
static void
apply_print (const FsControlResult *r)
{
	const FsApplyOutcome *outcome = r->outcome;
	const gchar *errmsg = r->error;
	gchar *desc = fs_policy_impact_describe (outcome->impact);

	if (outcome->held) {
		printf ("%sHeld:%s %s.  The firewall was left untouched.\n",
		        fs_cli_amber (), fs_cli_reset (), outcome->hold_reason);
		printf ("Recorded in the audit log: %s\n", desc);
	} else if (outcome->result == FS_APPLY_OK) {
		if (outcome->firewall_was == FS_FW_STOPPED)
			printf ("%sApplied%s (whole policy; the firewall was "
			        "stopped and is now running): %s\n",
			        fs_cli_green (), fs_cli_reset (), desc);
		else if (outcome->narrow && outcome->impact->added == 0 &&
		         outcome->impact->removed == 0)
			printf ("Nothing to change: the policy already matches the "
			        "firewall.\n");
		else
			printf ("%sApplied%s (%s): %s\n", fs_cli_green (),
			        fs_cli_reset (),
			        outcome->narrow ? "only the changes" : "whole policy",
			        desc);
		/* A policy apply also sends the firewall settings saved and
		 * not applied (the control op loads the saved preferences):
		 * say so, as `config set' said they wait for an apply. */
		if (outcome->settings)
			printf ("The saved firewall settings went out with it: "
			        "they differed from the ones last applied.\n");
		fs_cli_print_notes (outcome->notes);
		if (r->intel.ran)
			intel_print (&r->intel, NULL);
	} else {
		fs_cli_error ("%s", errmsg != NULL ? errmsg
		              : fs_util_apply_result_to_string ((int) outcome->result));
		if (outcome->rollback_attempted && outcome->rollback_verified)
			fs_cli_hint ("the firewall was restored to the last applied "
			             "policy, and that restore was verified");
		else if (outcome->rollback_attempted)
			fs_cli_error ("the rollback ALSO failed: the firewall may be "
			              "inconsistent -- check `stockfw status'");
		else
			fs_cli_hint ("no applied policy was recorded, so there was "
			             "nothing to roll back to");
	}
	g_free (desc);
}

/* [ edit_send ]
 * 3D: an edit op (policy.add, .remove, .replace) with `base' params.
 * With --apply the control layer applies the saved policy under the
 * same lock, and the lockout guard stands in front of both: the
 * warning, the question and the second send are control_guarded's,
 * and a CONFIRM that was not confirmed saved nothing.  `lock' gets the
 * lockout member. */
static FsControlResult *
edit_send (const gchar *op, GVariant *base, gboolean apply, gboolean yes,
           GString *lock, gint *status)
{
	if (!apply)
		return control_send (op, base, FALSE);
	return control_guarded (op, base, yes, "Apply", lock, status, NULL);
}

/* [ edit_refused ]
 * An edit with --apply the user did not confirm: nothing was saved.
 * `verb' is the JSON word ("added", "removed", "changed"). */
static gint
edit_refused (const gchar *verb, const GString *lock, gint status)
{
	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, verb, FALSE);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "saved", FALSE);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "error", "refused: the policy would block "
		                "an SSH session (pass --yes)");
		g_string_append (out, lock->str);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		fs_cli_hint ("nothing was saved: the policy files are as they "
		             "were");
	}
	return status;
}

/* [ edit_applied ]
 * After an edit was saved: with --apply, what the apply did (an
 * "applied" member and an "apply" object in JSON), else the "not live
 * yet" line.  Returns the exit status. */
static gint
edit_applied (const FsControlResult *r, const GString *lock, GString *json)
{
	if (json != NULL) {
		g_string_append_c (json, ',');
		fs_json_kv_bool (json, "applied", r->outcome != NULL &&
		                 r->outcome->applied);
		if (r->outcome != NULL) {
			g_string_append (json, ",\"apply\":{");
			apply_json_members (json, r, lock->str);
			g_string_append_c (json, '}');
		}
	} else if (r->outcome != NULL) {
		if (!fs_cli.quiet || apply_status (r->outcome) != FS_EXIT_OK)
			apply_print (r);
	} else {
		not_live_line ();
	}
	return r->outcome != NULL ? apply_status (r->outcome) : FS_EXIT_OK;
}

/* === PR4-C === */
/* What `events act' and `simulate --do' (fs-cli-act.c) share with
 * `apply': the guarded send, the apply's own text and JSON, and the
 * preview of `apply --dry-run'. */
FsControlResult *
fs_cli_control_guarded (const gchar *op, GVariant *base, gboolean yes,
                        const gchar *verb, GString *lock, gint *status)
{
	return control_guarded (op, base, yes, verb, lock, status, NULL);
}

void
fs_cli_apply_print (const FsControlResult *r)
{
	apply_print (r);
}

void
fs_cli_apply_json_members (GString *out, const FsControlResult *r,
                           const gchar *lock)
{
	apply_json_members (out, r, lock);
}

gint
fs_cli_apply_status (const FsApplyOutcome *outcome)
{
	return apply_status (outcome);
}

/* [ fs_cli_apply_preview ]
 * What applying `after' would put on the firewall, as `apply --dry-run'
 * says it: the stopped firewall it would start, the impact, every row
 * that goes live or comes off, the notes, and the lockout guard's
 * warning (stderr).  With json, a "preview" member is appended
 * instead (and "lockout"). */
void
fs_cli_apply_preview (const FsPolicy *after, GString *json)
{
	FsPolicy *applied = fs_policy_new ();
	gboolean have = fs_apply_journal_load (applied, NULL);
	FsPolicyImpact *impact = fs_policy_impact (have ? applied : NULL, after);
	Diff *d = diff_new (after, have ? applied : NULL);
	GPtrArray *notes = preview_notes (after);
	gchar *desc = fs_policy_impact_describe (impact);
	FsFirewallState st;
	const gchar *fw = firewall_word (&st);

	if (json != NULL) {
		g_string_append (json, ",\"preview\":{");
		fs_json_kv_str (json, "impact", desc);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "firewall_state", fw);
		g_string_append_c (json, ',');
		diff_rows_json (json, "added_rules", d->added, d->added_n);
		g_string_append_c (json, ',');
		diff_rows_json (json, "removed_rules", d->removed, d->removed_n);
		g_string_append_c (json, ',');
		notes_json (json, notes);
		g_string_append_c (json, '}');
		lockout_guard (after, json);
	} else {
		if (st == FS_FW_STOPPED)
			printf ("The firewall is stopped: the apply loads the "
			        "whole policy (%u rules) and starts it.\n",
			        fs_cli_policy_total (after));
		printf ("The apply: %s\n", desc);
		diff_rows_print (d);
		notes_print (notes);
		lockout_guard (after, NULL);
	}

	g_free (desc);
	g_ptr_array_unref (notes);
	diff_free (d);
	fs_policy_impact_free (impact);
	fs_policy_free (applied);
}
/* === end PR4-C === */

gint
fs_cli_cmd_apply (gint argc, gchar **argv)
{
	gboolean dry_run = FALSE, verbose = FALSE, yes = FALSE;
	FsPolicy *policy;
	FsControlResult *r;
	GPtrArray *problems = NULL;
	gboolean on_disk;
	gint status = FS_EXIT_OK;
	GString *lock;

	for (gint i = 1; i < argc; i++) {
		if (fs_cli_is_option_at (argv, i) &&
		    (strcmp (argv[i], "--dry-run") == 0 ||
		     strcmp (argv[i], "-n") == 0)) {
			dry_run = TRUE;
		} else if (fs_cli_is_option_at (argv, i) &&
		           (strcmp (argv[i], "-v") == 0 ||
		            strcmp (argv[i], "--verbose") == 0)) {
			verbose = TRUE;
		} else if (fs_cli_is_option_at (argv, i) &&
		           (strcmp (argv[i], "--yes") == 0 ||
		            strcmp (argv[i], "-y") == 0)) {
			yes = TRUE;
		} else if (fs_cli_is_option_at (argv, i)) {
			fs_cli_unknown_option ("apply", argv[i]);
			return FS_EXIT_USAGE;
		} else {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			return FS_EXIT_USAGE;
		}
	}

	policy = fs_cli_load_policy_report (&on_disk, &problems);

	if (!on_disk) {
		fs_cli_error ("no policy saved in %s -- nothing to apply",
		              fs_util_rules_dir ());
		if (geteuid () == 0 && g_getenv ("SUDO_USER") != NULL)
			fs_cli_hint ("as root the policy is read from /etc/stockfw; "
			             "a policy edited without sudo lives in "
			             "~/.stockfw");
		g_ptr_array_unref (problems);
		fs_policy_free (policy);
		return FS_EXIT_FAILURE;
	}

	/* A line that is not a rule would simply be missing from the
	 * firewall: refused, the dry run included, until it is fixed. */
	if (problems->len > 0) {
		fs_cli_print_problems (problems);
		fs_cli_error ("not applied: %u line%s of the policy %s",
		              problems->len, problems->len == 1 ? "" : "s",
		              not_rules (problems->len));
		g_ptr_array_unref (problems);
		fs_policy_free (policy);
		return FS_EXIT_USAGE;
	}
	g_ptr_array_unref (problems);

	if (dry_run) {
		status = apply_dry_run (policy, verbose, yes);
		fs_policy_free (policy);
		return status;
	}

	if (geteuid () != 0) {
		fs_policy_free (policy);
		return fs_cli_need_root ("apply");
	}

	lock = g_string_new (NULL);
	r = control_guarded ("apply", NULL, yes, "Apply", lock, &status, NULL);
	fs_policy_free (policy);
	if (r->status == FS_CONTROL_CONFIRM) {
		if (fs_cli.json) {
			GString *out = g_string_new ("{");

			fs_json_kv_bool (out, "applied", FALSE);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "error", "refused: the policy would "
			                "block an SSH session (pass --yes)");
			g_string_append (out, lock->str);
			g_string_append_c (out, '}');
			fs_cli_print_json (out);
			g_string_free (out, TRUE);
		}
		g_string_free (lock, TRUE);
		fs_control_result_free (r);
		return status;
	}
	if (r->outcome == NULL) {
		/* Refused before the gate: what was read above changed under
		 * the lock, or the lock could not be taken. */
		if (r->problems != NULL && r->problems->len > 0)
			fs_cli_print_problems (r->problems);
		fs_cli_error ("not applied: %s", r->error);
		status = r->status == FS_CONTROL_USAGE ? FS_EXIT_USAGE
		       : r->status == FS_CONTROL_NEED_ROOT ? FS_EXIT_NEED_ROOT
		       : FS_EXIT_FAILURE;
		g_string_free (lock, TRUE);
		fs_control_result_free (r);
		return status;
	}

	status = apply_status (r->outcome);
	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		apply_json_members (out, r, lock->str);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		apply_print (r);
	}

	g_string_free (lock, TRUE);
	fs_control_result_free (r);

	return status;
}

/* --------------------------------------------------------- start / stop */

/* [ intel_print ]
 * The threat-intel blocklists follow the user's Stop and Start (design
 * 6.5): the control layer removed them after a stop and applied them
 * again after a start (fs_intel_suspend, fs_intel_resume).  Appends an
 * "intel" member to `json' when given, else prints; FALSE when the
 * blocklists did not follow. */
static gboolean
intel_print (const FsControlIntel *in, GString *json)
{
	if (json != NULL) {
		g_string_append_c (json, ',');
		fs_json_key (json, "intel");
		g_string_append_c (json, '{');
		fs_json_kv_bool (json, "ok", in->ok);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "result", in->result);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "hold", in->hold);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "error", in->error);
		g_string_append_c (json, ',');
		fs_json_key (json, "notes");
		fs_cli_append_lines_json (json, in->notes);
		g_string_append_c (json, '}');
	} else if (!in->ok) {
		fs_cli_error ("the blocklists could not be %s: %s",
		              in->start ? "applied" : "removed",
		              in->error != NULL ? in->error
		                                : FS_CLI_LIVE " does not hold "
		                                  "them");
		fs_cli_print_notes (in->notes);
	} else if (in->held) {
		printf ("%snote:%s blocklists not applied: %s\n", fs_cli_amber (),
		        fs_cli_reset (), in->hold);
	} else if (in->outcome) {
		if (!fs_cli.quiet)
			printf ("Blocklists applied (%u list%s).\n", in->sets,
			        in->sets == 1 ? "" : "s");
		fs_cli_print_notes (in->notes);
	}
	return in->ok;
}

/* [ start_seen ] -- Q6: the start loads the journal, not the file, so
 * lines of the file that are not rules do not stop it; they are named,
 * and apply refuses until they are fixed.  When nothing was ever
 * applied they do stop it, and are named with the refusal. */
static void
start_seen (const FsControlResult *r)
{
	guint malformed = r->problems != NULL ? r->problems->len : 0;

	if (malformed == 0)
		return;
	if (r->outcome == NULL && r->status == FS_CONTROL_FAILED) {
		fs_cli_print_problems (r->problems);
		return;
	}
	if (fs_cli.json)
		return;
	fs_cli_print_problems (r->problems);
	warn ("%u line%s of the saved policy %s; the start uses the last "
	      "applied policy", malformed, malformed == 1 ? "" : "s",
	      not_rules (malformed));
}

static gint
start_or_stop (gint argc, gchar **argv, gboolean start)
{
	FsControlResult *r;
	gboolean ok, intel_ok = TRUE, yes = FALSE;
	const gchar *notes;
	GString *out = NULL;
	gint status = FS_EXIT_OK;
	GString *lock;

	for (gint i = 1; i < argc; i++) {
		if (fs_cli_is_option_at (argv, i) &&
		    (strcmp (argv[i], "--yes") == 0 ||
		     strcmp (argv[i], "-y") == 0)) {
			yes = TRUE;
		} else if (fs_cli_is_option_at (argv, i)) {
			fs_cli_unknown_option (start ? "start" : "stop", argv[i]);
			return FS_EXIT_USAGE;
		} else {
			fs_cli_error ("%s takes no arguments",
			              start ? "start" : "stop");
			return FS_EXIT_USAGE;
		}
	}

	if (geteuid () != 0)
		return fs_cli_need_root (start ? "start" : "stop");
	/* A stop asks first on a terminal, as Pause protection does (B5). */
	if (!start && !fs_cli_stop_confirm (yes))
		return FS_EXIT_FAILURE;

	/* The bodies are the control layer's (firewall.start, which takes
	 * the journal's settings, 3B; firewall.stop). */
	lock = g_string_new (NULL);
	r = start ? control_guarded ("firewall.start", NULL, yes, "Start", lock,
	                             &status, start_seen)
	          : control_send ("firewall.stop", NULL, FALSE);

	if (r->status == FS_CONTROL_CONFIRM) {
		if (fs_cli.json) {
			out = g_string_new ("{");
			fs_json_kv_bool (out, "ok", FALSE);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "error", "refused: the policy "
			                "would block an SSH session (pass "
			                "--yes)");
			g_string_append (out, lock->str);
			g_string_append_c (out, '}');
			fs_cli_print_json (out);
			g_string_free (out, TRUE);
		}
		g_string_free (lock, TRUE);
		fs_control_result_free (r);
		return status;
	}

	/* Already there: nothing was done, and nothing is on the audit
	 * record.  A stop still ran the backend's stop, unlogged, and took
	 * the blocklists down. */
	if ((start && r->was == FS_FW_RUNNING) ||
	    (!start && r->was == FS_FW_STOPPED)) {
		guint n = r->live_rules;

		if (fs_cli.json) {
			out = g_string_new ("{");
			fs_json_kv_bool (out, "changed", FALSE); g_string_append_c (out, ',');
			fs_json_kv_str (out, "was", was_word (r->was));
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "error", NULL);
			g_string_append (out, ",\"notes\":[]");
			if (r->intel.ran)
				intel_ok = intel_print (&r->intel, out);
			g_string_append_c (out, ',');
			fs_json_kv_bool (out, "ok", intel_ok);
			g_string_append_c (out, '}');
			fs_cli_print_json (out);
			g_string_free (out, TRUE);
		} else {
			if (!fs_cli.quiet) {
				if (start)
					printf ("Already running (%u rule%s live).  "
					        "Nothing changed.\n",
					        n, n == 1 ? "" : "s");
				else
					printf ("Already stopped.\n");
			}
			if (r->intel.ran)
				intel_ok = intel_print (&r->intel, NULL);
		}
		g_string_free (lock, TRUE);
		fs_control_result_free (r);
		return intel_ok ? FS_EXIT_OK : FS_EXIT_FAILURE;
	}

	if (start) {
		const FsApplyOutcome *outcome = r->outcome;

		ok = outcome != NULL && outcome->result == FS_APPLY_OK;
		notes = ok ? outcome->notes : NULL;
		if (ok && outcome->held && !fs_cli.json && !fs_cli.quiet)
			printf ("%sHeld:%s %s.  Started with the last applied "
			        "policy; later changes stay held.\n",
			        fs_cli_amber (), fs_cli_reset (),
			        outcome->hold_reason);
		else if (ok && r->journal &&
		         fs_backend ()->start_applies_policy &&
		         (outcome->impact->added > 0 ||
		          outcome->impact->removed > 0) &&
		         !fs_cli.json && !fs_cli.quiet) {
			guint n = outcome->impact->added + outcome->impact->removed;

			printf ("Started with the last applied policy; %u saved "
			        "change%s %s not live yet (stockfw policy diff).\n",
			        n, n == 1 ? "" : "s", n == 1 ? "is" : "are");
		}
	} else {
		ok = r->changed;
		notes = NULL;
	}

	if (fs_cli.json) {
		out = g_string_new ("{");
		fs_json_kv_bool (out, "ok", ok);  g_string_append_c (out, ',');
		fs_json_kv_bool (out, "changed", ok); g_string_append_c (out, ',');
		fs_json_kv_str (out, "was", was_word (r->was));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "error", ok ? NULL : r->error);
		g_string_append_c (out, ',');
		fs_json_key (out, "notes");
		fs_cli_append_lines_json (out, notes);
		g_string_append (out, lock->str);
	} else if (ok) {
		if (!fs_cli.quiet)
			printf ("Firewall %s.\n", start ? "started" : "stopped");
		fs_cli_print_notes (notes);
	} else {
		fs_cli_error ("could not %s the firewall: %s",
		              start ? "start" : "stop",
		              r->error != NULL ? r->error : "unknown error");
	}

	/* Only once the firewall itself did what was asked: a Start that
	 * failed applied no blocklist, a Stop that failed removed none. */
	if (ok && r->intel.ran)
		intel_ok = intel_print (&r->intel, out);

	if (out != NULL) {
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	}

	g_string_free (lock, TRUE);
	fs_control_result_free (r);

	return ok && intel_ok ? FS_EXIT_OK : FS_EXIT_FAILURE;
}

gint fs_cli_cmd_start (gint argc, gchar **argv) { return start_or_stop (argc, argv, TRUE); }
gint fs_cli_cmd_stop  (gint argc, gchar **argv) { return start_or_stop (argc, argv, FALSE); }

/* ------------------------------------------------------------ simulate */

/* [ replace_once ] -- `text' with the first `from' replaced by `to'. */
static gchar *
replace_once (gchar *text, const gchar *from, const gchar *to)
{
	gchar *at = strstr (text, from);
	gchar *out;

	if (at == NULL)
		return text;
	*at = '\0';
	out = g_strconcat (text, to, at + strlen (from), NULL);
	g_free (text);
	return out;
}

/* [ refs_in_actions ]
 * The Policy page wording of "open rule" fixes, in the terms of this
 * tool: "(Outbound: deny to host, row 1) ... Edit or remove it on the
 * Policy page." becomes "(outbound-deny-to:1) ... See `stockfw policy
 * show outbound-deny-to:1'." */
static void
refs_in_actions (FsWhatIfResult *r)
{
	for (guint i = 0; i < r->answers->len; i++) {
		FsWhatIfAnswer *a = g_ptr_array_index (r->answers, i);

		for (guint k = 0; k < a->actions->len; k++) {
			FsWhatIfAction *act = g_ptr_array_index (a->actions, k);
			gchar *ref, *see, *row, *open;

			if (act->kind != FS_WHATIF_ACT_OPEN_RULE ||
			    act->policy_kind < 0 || act->explanation == NULL)
				continue;
			ref = fs_cli_rule_ref ((FsRuleKind) act->policy_kind,
			                       (guint) act->policy_index + 1);
			row = g_strdup_printf (", row %d)", act->policy_index + 1);
			open = strstr (act->explanation, row);
			if (open != NULL) {
				gchar *paren = g_strrstr_len (act->explanation,
				                              open - act->explanation,
				                              "(");

				if (paren != NULL) {
					gchar *head = g_strndup (act->explanation,
					                         paren - act->explanation);
					gchar *fixed = g_strdup_printf (
						"%s(%s)%s", head, ref, open + strlen (row));

					g_free (head);
					g_free (act->explanation);
					act->explanation = fixed;
				}
			}
			see = g_strdup_printf ("See `stockfw policy show %s'.", ref);
			act->explanation = replace_once (act->explanation,
			                                 "Edit or remove it on the "
			                                 "Policy page.", see);
			g_free (see);
			g_free (row);
			g_free (ref);
		}
	}
}

gint
fs_cli_cmd_simulate (gint argc, gchar **argv)
{
	FsWhatIfResult *result;
	GPtrArray *words = g_ptr_array_new ();
	gboolean assume_running = FALSE, use_applied = FALSE, yes = FALSE;
	guint do_n = 0;
	gchar *line;
	gint status;
	FsPolicy *applied = NULL;

	for (gint i = 1; i < argc; i++) {
		const gchar *v = NULL;
		gint bad = FS_EXIT_OK;

		if (fs_cli_take_opt (argc, argv, &i, "--do", &v, &bad)) {
			/* 4C: run fix N of the answer (fs-cli-act.c). */
			if (v == NULL || !fs_cli_simulate_do_number (v, &do_n)) {
				g_ptr_array_free (words, TRUE);
				return FS_EXIT_USAGE;
			}
		} else if (fs_cli_is_option_at (argv, i) &&
		           (strcmp (argv[i], "--yes") == 0 ||
		            strcmp (argv[i], "-y") == 0)) {
			yes = TRUE;
		} else if (fs_cli_is_option_at (argv, i) &&
		           strcmp (argv[i], "--assume-running") == 0) {
			assume_running = TRUE;
		} else if (fs_cli_is_option_at (argv, i) &&
		           strcmp (argv[i], "--applied") == 0) {
			use_applied = TRUE;
		} else if (fs_cli_is_option_at (argv, i)) {
			/* A mistyped option is not a word of the question:
			 * folded in, it would answer a different one.  A line
			 * that starts with a dash goes after "--". */
			fs_cli_unknown_option ("simulate", argv[i]);
			g_ptr_array_free (words, TRUE);
			return FS_EXIT_USAGE;
		} else {
			g_ptr_array_add (words, argv[i]);
		}
	}
	g_ptr_array_add (words, NULL);

	if (yes && do_n == 0) {
		g_ptr_array_free (words, TRUE);
		fs_cli_error ("--yes goes with --do");
		return FS_EXIT_USAGE;
	}
	if (do_n > 0 && use_applied) {
		g_ptr_array_free (words, TRUE);
		fs_cli_error ("--do works on the saved policy, not with --applied");
		return FS_EXIT_USAGE;
	}
	if (words->len < 2) {
		g_ptr_array_free (words, TRUE);
		fs_cli_error ("simulate needs a description of the traffic");
		fs_cli_hint ("stockfw simulate \"allow ssh from 192.168.1.50 on "
		             "port 22\"");
		return FS_EXIT_USAGE;
	}

	if (use_applied) {
		GError *error = NULL;

		applied = fs_policy_new ();
		if (!fs_apply_journal_load (applied, &error)) {
			gboolean none = g_error_matches (error, FS_APPLY_ERROR,
			                                 FS_APPLY_ERR_NO_JOURNAL);

			if (none)
				fs_cli_error ("no policy was applied yet, so there is "
				              "no applied policy to ask");
			else
				fs_cli_error ("the applied policy cannot be read: %s",
				              error->message);
			g_clear_error (&error);
			fs_policy_free (applied);
			g_ptr_array_free (words, TRUE);
			return none ? FS_EXIT_FAILURE : FS_EXIT_NEED_ROOT;
		}
	}

	/* Unquoted words are one line, as the user would have typed it. */
	line = g_strjoinv (" ", (gchar **) words->pdata);
	g_ptr_array_free (words, TRUE);

	result = applied != NULL
	         ? fs_cli_whatif_policy (applied, line, assume_running)
	         : fs_cli_whatif (line, assume_running);

	/* --do N (4C): the fix is run, and its outcome is the answer; in
	 * text the question's answer comes first, so the fix is seen in its
	 * place. */
	if (do_n > 0) {
		if (!fs_cli.json && !fs_cli.quiet &&
		    result->verdict != FS_WHATIF_ERROR) {
			gchar *raw, *safe, *text;

			refs_in_actions (result);
			raw = fs_whatif_result_describe (result);
			safe = fs_cli_out_safe_lines (raw);
			text = fs_cli_whatif_number_actions (result, safe);
			printf ("%s\n", text);
			g_free (text);
			g_free (safe);
			g_free (raw);
		}
		status = fs_cli_simulate_do (result, line, assume_running, do_n,
		                             yes);
		fs_whatif_result_free (result);
		g_free (line);
		return status;
	}

	switch (result->verdict) {
	case FS_WHATIF_ALLOWED: status = FS_EXIT_OK;      break;
	case FS_WHATIF_BLOCKED: status = FS_EXIT_BLOCKED; break;
	case FS_WHATIF_DEPENDS: status = FS_EXIT_DEPENDS; break;
	case FS_WHATIF_ERROR:
	default:                status = FS_EXIT_USAGE;   break;
	}

	if (fs_cli.json) {
		GString *out = g_string_new (NULL);

		fs_cli_whatif_json (out, result, line);
		g_string_truncate (out, out->len - 1);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "policy", applied != NULL ? "applied"
		                                               : "saved");
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (result->verdict == FS_WHATIF_ERROR) {
		fs_cli_error ("%s", result->error);
		fs_cli_hint ("stockfw simulate \"allow ssh from 192.168.1.50 on "
		             "port 22\"");
	} else if (fs_cli.quiet) {
		/* -q: the verdict word alone, for `if [ "$(stockfw -q
		 * simulate ...)" = BLOCKED ]'. */
		printf ("%s\n", fs_whatif_verdict_name (result->verdict));
	} else {
		gchar *text, *rest;
		const gchar *colour =
			result->verdict == FS_WHATIF_ALLOWED ? fs_cli_green ()
			: result->verdict == FS_WHATIF_BLOCKED ? fs_cli_red ()
			                                       : fs_cli_amber ();

		gchar *raw;

		refs_in_actions (result);
		/* The description names rules after the policy's rows (a
		 * service name, a comment, a host), which may come from any
		 * writer of the policy files: through fs_cli_out_safe, line
		 * by line, as `policy list' shows them. */
		raw = fs_whatif_result_describe (result);
		text = fs_cli_out_safe_lines (raw);
		g_free (raw);
		/* Each fix gets its number, for --do N. */
		raw = text;
		text = fs_cli_whatif_number_actions (result, raw);
		g_free (raw);
		rest = strchr (text, '\n');

		/* The summary names the verdict; it gets the colour. */
		if (rest != NULL)
			*rest++ = '\0';
		printf ("%s%s%s\n", colour, text, fs_cli_reset ());
		for (guint i = 0; i < result->answers->len; i++) {
			const FsWhatIfAnswer *a =
				g_ptr_array_index (result->answers, i);

			if (a->policy_kind >= 0) {
				gchar *ref = fs_cli_rule_ref (
					(FsRuleKind) a->policy_kind,
					(guint) a->policy_index + 1);

				printf ("Decided by %s%s\n", ref,
				        result->answers->len > 1
				        ? (a->inbound ? " (inbound)" : " (outbound)")
				        : "");
				g_free (ref);
			}
		}
		if (applied != NULL) {
			gint64 when = journal_epoch ();
			gchar *t = fs_cli_time_text (when, FS_CLI_TIME_FULL);

			printf ("(applied policy, %s)\n", t);
			g_free (t);
		}
		printf ("%s", rest != NULL ? rest : "");
		printf ("%sA simulation only: nothing was written.%s\n",
		        fs_cli_dim (), fs_cli_reset ());
		g_free (text);
	}

	fs_whatif_result_free (result);
	g_free (line);
	if (applied != NULL)
		fs_policy_free (applied);

	return status;
}

/* ------------------------------------------------------- the commands */

static const FsCliOption policy_opts[] = {
	{ "--kind",    TRUE,  "list" },
	{ "--grep",    TRUE,  "list" },
	{ "--status",  FALSE, "list" },
	{ "--comment", TRUE,  "add"  },
	{ "--both",    FALSE, "add"  },
	{ "--apply",   FALSE, "add"  },
	{ "--yes",     FALSE, "add"  },
	{ "-y",        FALSE, "add"  },
	{ "--comment", TRUE,  "edit" },
	{ "--apply",   FALSE, "edit" },
	{ "--yes",     FALSE, "edit" },
	{ "-y",        FALSE, "edit" },
	{ "--apply",   FALSE, "remove" },
	{ "--yes",     FALSE, "remove" },
	{ "-y",        FALSE, "remove" },
	{ "--force",   FALSE, "init" },
	{ NULL, FALSE, NULL }
};

/* apply -n is still read as --dry-run (fs_cli_cmd_apply), but it is
 * not listed here: it stays an undocumented alias (cli-plan.md section
 * 3), out of the man page and completion, where it would read like the
 * -n N of events and audit. */
static const FsCliOption apply_opts[] = {
	{ "--dry-run", FALSE, NULL },
	{ "--verbose", FALSE, NULL },
	{ "-v",        FALSE, NULL },
	{ "--yes",     FALSE, NULL },
	{ "-y",        FALSE, NULL },
	{ NULL, FALSE, NULL }
};

static const FsCliOption start_opts[] = {
	{ "--yes", FALSE, NULL },
	{ "-y",    FALSE, NULL },
	{ NULL, FALSE, NULL }
};

static const FsCliOption simulate_opts[] = {
	{ "--assume-running", FALSE, NULL },
	{ "--applied",        FALSE, NULL },
	{ "--do",             TRUE,  NULL },
	{ "--yes",            FALSE, NULL },
	{ "-y",               FALSE, NULL },
	{ NULL, FALSE, NULL }
};

static const FsCliOption no_opts[] = {
	{ NULL, FALSE, NULL }
};

const FsCliCommandDef fs_cli_policy_commands[] = {
	{ "policy", fs_cli_cmd_policy,
"Usage: stockfw policy list [KIND|in|out] [--grep TEXT] [--status]\n"
"       stockfw policy show REF\n"
"       stockfw policy add KIND FIELD... [--comment TEXT] [--both]\n"
"                          [--apply [--yes]]\n"
"       stockfw policy edit REF [FIELD...] [--comment TEXT]\n"
"                          [--apply [--yes]]\n"
"       stockfw policy remove REF [--apply [--yes]]\n"
"       stockfw policy diff\n"
"       stockfw policy init [--force]\n"
"\n"
"Edits the saved policy -- the files the desktop app's Policy page\n"
"shows.  Changes are validated (hosts, ports and ranges fail closed)\n"
"and saved; nothing reaches the firewall until `stockfw apply', or\n"
"--apply.  One writer at a time: an edit waits for another to finish.\n"
"\n"
"A rule's reference REF is KIND:N, numbered as `policy list' shows it\n"
"(inbound-allow-service:2).  KIND#N and KIND N work too.\n"
"\n"
"  list    the rules, by kind or direction; --grep TEXT keeps the rows\n"
"          that hold TEXT; --status marks each row live or pending\n"
"  show    one rule: its fields, what it covers, live or pending\n"
"  add     a rule; it prints the reference and a What-If check of the\n"
"          rule's own traffic on the saved policy\n"
"  edit    a rule in place: same kind, same number, one save.  Give\n"
"          all of its fields (\"-\" keeps one as it is), or none to\n"
"          change only the comment; the comment is kept unless\n"
"          --comment is given (--comment '' clears it)\n"
"  remove  a rule, by its reference\n"
"  diff    the saved policy against the applied one: + rows to add,\n"
"          - rows to take away (numbered as applied)\n"
"  init    saves the default rules (DHCP and DNS out) the desktop app\n"
"          starts from; --force replaces a policy that has rules\n"
"\n"
"--apply then applies the saved policy, as `stockfw apply' does, under\n"
"the same lock (root).  The SSH check runs first, on the policy the\n"
"edit gives: when it would block your SSH session, nothing is saved\n"
"unless you confirm, or pass --yes.\n"
"\n"
"Kinds and their fields:\n"
"  inbound-allow-from      HOST\n"
"  inbound-allow-service   SERVICE PORT FOR\n"
"  inbound-forward         SERVICE FIREWALL-PORT TO PORT\n"
"  outbound-allow-to       HOST\n"
"  outbound-allow-from     HOST\n"
"  outbound-allow-service  SERVICE PORT FOR\n"
"  outbound-deny-to        HOST\n"
"  outbound-deny-from      HOST\n"
"  outbound-deny-service   SERVICE PORT FOR\n"
"\n"
"FOR is a host, a network (192.168.1.0/24) or \"Anyone\".  --both also\n"
"adds the opposite-direction twin of an allow rule, as one change.  A\n"
"field or comment that starts with a dash goes after \"--\" or as\n"
"--comment=TEXT.\n"
"\n"
"add, edit and remove refuse while a line of the files is not a rule\n"
"(`stockfw check'): saving would delete that line.  A comma or a line\n"
"break in a field or comment is refused: the files have no quoting.\n"
"\n"
"Examples:\n"
"  stockfw policy add inbound-allow-service SSH 22 192.168.1.0/24\n"
"  stockfw policy add outbound-deny-to 203.0.113.9 --comment bad\n"
"  stockfw policy show inbound-allow-service:1\n"
"  stockfw policy edit inbound-allow-service:1 - 2222 -\n"
"  stockfw policy edit outbound-deny-to:1 --comment 'old server'\n"
"  stockfw policy remove outbound-deny-to:1 --apply\n",
	  policy_opts, NULL },

	{ "check", fs_cli_cmd_check,
"Usage: stockfw check [--json]\n"
"\n"
"Reads the saved policy and lists every line that is not a rule, as\n"
"FILE:LINE: reason.  Such a line is left out of the policy, so apply\n"
"refuses until it is fixed; start still starts the last applied\n"
"policy.  Exits 0 when there is no problem and 1 when there is one.\n"
"Needs no root: it reads the rules directory of the user running it.\n",
	  no_opts, NULL },

	{ "apply", fs_cli_cmd_apply,
"Usage: stockfw apply [--dry-run [-v]] [--yes] [--json]\n"
"\n"
"Pushes the saved policy to the firewall through the same apply gate\n"
"the desktop app uses: only what changed is touched, a failed apply is\n"
"rolled back to the last applied policy and the rollback is verified,\n"
"and every attempt is one line in the audit log.  When the firewall is\n"
"stopped, the whole policy is loaded and the firewall starts.  When\n"
"audit-only mode is on (Policy page), the firewall is left untouched\n"
"and the would-be change is recorded.  A policy with lines that are\n"
"not rules is refused (`stockfw check').  Needs root.\n"
"\n"
"--dry-run lists the rows that would be added and removed and the\n"
"notes known before applying; -v adds the chains it would write.\n"
"\n"
"Over SSH, the policy is checked first: when it would block your SSH\n"
"session (or another one to this computer), you are asked on a\n"
"terminal, and without one the apply is refused unless --yes is given.\n",
	  apply_opts, NULL },

	{ "start", fs_cli_cmd_start,
"Usage: stockfw start [--yes]\n"
"\n"
"Starts the firewall with the last APPLIED policy -- what `stockfw\n"
"apply' last put live -- so saved changes that were never applied stay\n"
"off, and Sentinel blocks whose ten minutes ran out are left out.  The\n"
"boot unit (stockfw.service) runs this at every boot.  When nothing was\n"
"ever applied, the saved policy is started instead, and the start is\n"
"refused if there is none or a line of it is malformed.  Lines that are\n"
"not rules only give a warning when there is an applied policy.\n"
"Threat-intel blocklists that are turned on are applied again, through\n"
"the same gate (audit-only mode holds them too); if they cannot be,\n"
"the firewall still runs and the exit status is non-zero.  Running\n"
"already: nothing is done.  The SSH check of `apply' runs too (--yes).\n"
"Needs root.\n",
	  start_opts, NULL },

	{ "stop", fs_cli_cmd_stop,
"Usage: stockfw stop [--yes]\n"
"\n"
"Removes StockFW's own chains, and its threat-intel blocklists until\n"
"the next start.  Rules owned by Docker, libvirt or anything else are\n"
"left alone.  On a terminal it first says what stopping takes away and\n"
"asks \"Stop the firewall? [y/N]\"; Enter or any answer but y leaves it\n"
"running (exit 1).  --yes skips the question; with no terminal on\n"
"stdin (a script, the boot unit) it stops without asking, as before.\n"
"When it is stopped already, nothing is asked and the stop is not\n"
"logged, but threat-intel blocklists are still taken down; with threat\n"
"intel set up, that writes an intel-suspend line to the audit log.\n"
"Needs root.\n",
	  start_opts, NULL },

	{ "simulate", fs_cli_cmd_simulate,
"Usage: stockfw simulate \"<traffic>\" [--assume-running] [--applied]\n"
"                        [--json]\n"
"       stockfw simulate \"<traffic>\" --do N [--yes]\n"
"\n"
"Answers ALLOWED, BLOCKED or DEPENDS for described traffic against the\n"
"saved policy and Firewall preferences, the way the Copilot page's\n"
"What-If Simulator does: the rules checked, the one that decided (as\n"
"KIND:N), and fixes that were checked before they are offered.  What\n"
"the line leaves open (host, port, protocol, direction) is answered\n"
"for every case: DEPENDS names the split.  When the firewall is not\n"
"running the answer says so; --assume-running answers as if it were.\n"
"--applied asks the last applied policy instead of the saved one.\n"
"Without --do it writes nothing: it is a question, not a change.  Exits\n"
"0 for ALLOWED, 5 for BLOCKED, 6 for DEPENDS and 2 for a line it cannot\n"
"read, so scripts can branch on it.  With -q only the verdict word is\n"
"printed.\n"
"An unknown option is refused rather than read as part of the question.\n"
"\n"
"The fixes are numbered 1, 2 ... in the answer.  --do N runs fix N, as\n"
"the What-If window's buttons do.  The question is answered against the\n"
"policy as it is now and the fix is shown before anything changes; it\n"
"is asked about with [y/N] on a terminal, and without one --yes is\n"
"needed (nothing is ever waited for).  A rule to create must be one\n"
"StockFW writes for you (one address or block, one port, one protocol)\n"
"and must still do only what was asked, else it exits 2 and writes\n"
"nothing.  A block is saved and put live alone (the last applied policy\n"
"plus the row); an allow is saved and the saved policy applied, shown\n"
"in full first.  Lifting Sentinel's block takes only its own block off.\n"
"Starting the firewall is `stockfw start' (the start gate: audit-only\n"
"mode holds it, with an audit line); applying is `stockfw apply'.  A\n"
"fix that opens a rule or a setting prints the command to run.  Exit 0\n"
"when done, 1 when not done, 2 for a fix that is refused, 3 without\n"
"root.\n"
"\n"
"Examples:\n"
"  stockfw simulate \"allow ssh from 192.168.1.50 on port 22\"\n"
"  stockfw simulate \"inbound rdp\"\n"
"  stockfw simulate \"outbound tcp to 203.0.113.9 port 443\"\n",
	  simulate_opts, NULL },

	{ NULL, NULL, NULL, NULL, NULL }
};
