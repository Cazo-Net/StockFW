/*---[ fs-cli-policy.c ]----------------------------------------------------
 * `stockfw policy', `apply', `start', `stop', `simulate' and
 * `copilot'.
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

/* -------------------------------------------------------------- policy */

static gint
policy_list (gint argc, gchar **argv)
{
	FsRuleKind only = FS_RULE_N_KINDS;
	gboolean on_disk;
	gint malformed;
	FsPolicy *policy;
	gboolean names = (fs_backend ()->fw_honors & FS_FWHON_HOST_NAMES) != 0;

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
		} else if (fs_cli_is_option_at (argv, i)) {
			fs_cli_unknown_option ("policy list", argv[i]);
			return FS_EXIT_USAGE;
		} else {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			return FS_EXIT_USAGE;
		}
	}

	policy = fs_cli_load_policy (&on_disk, &malformed);

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "rules_dir", fs_util_rules_dir ());
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "saved", on_disk);
		g_string_append (out, ",\"rules\":[");
		{
			gboolean first = TRUE;

			for (gint k = 0; k < FS_RULE_N_KINDS; k++) {
				GPtrArray *rules = policy->kinds[k];

				if (only != FS_RULE_N_KINDS && (gint) only != k)
					continue;

				for (guint i = 0; i < rules->len; i++) {
					FsRule *r = g_ptr_array_index (rules, i);

					if (!first)
						g_string_append_c (out, ',');
					first = FALSE;
					g_string_append_c (out, '{');
					fs_json_kv_str (out, "kind", fs_cli_kind_name (r->kind)); g_string_append_c (out, ',');
					fs_json_kv_uint (out, "number", i + 1);   g_string_append_c (out, ',');
					fs_json_kv_str (out, "service", r->service); g_string_append_c (out, ',');
					fs_json_kv_str (out, "port", r->port);    g_string_append_c (out, ',');
					fs_json_kv_str (out, "target", r->target); g_string_append_c (out, ',');
					fs_json_kv_str (out, "to", r->to);        g_string_append_c (out, ',');
					fs_json_kv_str (out, "to_port", r->to_port); g_string_append_c (out, ',');
					fs_json_kv_str (out, "comment", r->comment);
					g_string_append_c (out, ',');
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
				}
			}
		}
		g_string_append (out, "]}");
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
		fs_policy_free (policy);
		return FS_EXIT_OK;
	}

	if (!on_disk) {
		printf ("No policy saved yet in %s.\n", fs_util_rules_dir ());
		printf ("%sAdd a rule with `stockfw policy add', or open the "
		        "desktop app once to seed the defaults.%s\n",
		        fs_cli_dim (), fs_cli_reset ());
		fs_policy_free (policy);
		return FS_EXIT_OK;
	}

	for (gint k = 0; k < FS_RULE_N_KINDS; k++) {
		GPtrArray *rules = policy->kinds[k];

		if (only != FS_RULE_N_KINDS && (gint) only != k)
			continue;
		if (only == FS_RULE_N_KINDS && rules->len == 0)
			continue;

		printf ("%s%s%s %s(%u)%s\n", fs_cli_bold (),
		        fs_cli_kind_name ((FsRuleKind) k), fs_cli_reset (),
		        fs_cli_dim (), rules->len, fs_cli_reset ());

		for (guint i = 0; i < rules->len; i++) {
			FsRule *r = g_ptr_array_index (rules, i);
			gchar *raw = fs_cli_rule_summary (r);
			/* A comment or a name is whatever the file holds: never
			 * let it steer the terminal. */
			gchar *summary = fs_cli_out_safe (raw);
			gchar *comment = fs_cli_out_safe (r->comment);

			FsFamily fam = fs_rule_coverage (r, names, NULL);

			g_free (raw);
			printf ("  %3u  %s", i + 1, summary);
			printf ("  %s[%s]%s",
			        fam == FS_FAMILY_NONE ? fs_cli_amber () : fs_cli_dim (),
			        fam == FS_FAMILY_NONE ? "covers nothing"
			                              : fs_util_families_label (fam),
			        fs_cli_reset ());
			if (*comment != '\0')
				printf ("  %s# %s%s", fs_cli_dim (), comment,
				        fs_cli_reset ());
			printf ("\n");
			g_free (comment);
			g_free (summary);
		}

		if (rules->len == 0)
			printf ("  %s(none)%s\n", fs_cli_dim (), fs_cli_reset ());
	}

	if (fs_cli_policy_total (policy) == 0 && only == FS_RULE_N_KINDS)
		printf ("The policy in %s is empty.\n", fs_util_rules_dir ());

	if (malformed > 0)
		fs_cli_hint ("%d malformed rule%s in %s %s skipped", malformed,
		             malformed == 1 ? "" : "s", fs_util_rules_dir (),
		             malformed == 1 ? "was" : "were");

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

static gint
policy_add (gint argc, gchar **argv)
{
	FsRuleKind kind;
	const gchar *comment = "", *first;
	gboolean both = FALSE;
	GPtrArray *fields;
	gint want;
	FsRule *rule, *twin = NULL;
	FsPolicy *policy;
	gchar *csv, *summary;
	gboolean ok, paired;

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

	/* The policy files are comma-separated with no quoting: a comma
	 * inside a field would silently become a field boundary. */
	g_ptr_array_add (fields, (gpointer) comment);
	for (guint i = 0; i < fields->len; i++) {
		const gchar *f = g_ptr_array_index (fields, i);

		if (strpbrk (f, ",\n\r") != NULL) {
			fs_cli_error ("a field may not contain a comma or a line "
			              "break: \"%s\"", f);
			g_ptr_array_unref (fields);
			return FS_EXIT_USAGE;
		}
	}

	first = g_ptr_array_index (fields, 0);
	g_ptr_array_add (fields, NULL);
	csv = g_strjoinv (",", (gchar **) fields->pdata);
	g_ptr_array_unref (fields);

	rule = fs_rule_from_csv (kind, csv);
	g_free (csv);

	if (rule == NULL || !fs_rule_fields_sane (rule)) {
		if (want == 1)
			fs_cli_error ("\"%s\" is not a valid address, network or "
			              "host name for %s", first,
			              fs_cli_kind_name (kind));
		else
			fs_cli_error ("not a valid %s rule: check the host, port or "
			              "range", fs_cli_kind_name (kind));
		fs_cli_hint ("hosts are addresses, networks (10.0.0.0/8) or "
		             "\"Anyone\"; ports are 1-65535 or a range 1024:2048");
		fs_rule_free (rule);
		return FS_EXIT_USAGE;
	}

	if (both) {
		twin = fs_rule_counterpart (rule);
		if (twin == NULL) {
			fs_cli_error ("%s has no opposite-direction twin; --both "
			              "only applies to allow rules",
			              fs_cli_kind_name (kind));
			fs_rule_free (rule);
			return FS_EXIT_USAGE;
		}
	}

	policy = fs_cli_load_policy (NULL, NULL);
	summary = fs_cli_rule_summary (rule);

	if (fs_policy_contains (policy, rule) &&
	    (twin == NULL || fs_policy_contains (policy, twin))) {
		if (!fs_cli.quiet)
			printf ("Already in the policy: %s %s\n",
			        fs_cli_kind_name (kind), summary);
		fs_rule_free (rule);
		fs_rule_free (twin);
		g_free (summary);
		fs_policy_free (policy);
		return FS_EXIT_OK;
	}

	/* The policy stores copies (fs_policy_add), so the rules stay ours
	 * to free whether the save works or not. */
	paired = twin != NULL;
	if (paired)
		ok = fs_policy_add_persist_pair (policy, rule, twin);
	else
		ok = fs_policy_add_persist (policy, rule);
	fs_rule_free (rule);
	fs_rule_free (twin);

	if (!ok) {
		fs_cli_error ("could not save the policy in %s",
		              fs_util_rules_dir ());
		if (geteuid () != 0 &&
		    g_str_has_prefix (fs_util_rules_dir (), "/etc"))
			fs_cli_hint ("%s is root's; run with sudo",
			             fs_util_rules_dir ());
		g_free (summary);
		fs_policy_free (policy);
		return FS_EXIT_FAILURE;
	}

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, "added", TRUE);           g_string_append_c (out, ',');
		fs_json_kv_str (out, "kind", fs_cli_kind_name (kind)); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "both_directions", paired); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "applied", FALSE);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (!fs_cli.quiet) {
		printf ("%s+%s %s %s%s\n", fs_cli_green (), fs_cli_reset (),
		        fs_cli_kind_name (kind), summary,
		        paired ? "  (and its opposite direction)" : "");
		gchar *apply = fs_cli_sudo_hint ("apply");

		printf ("%sSaved in %s.  Not live yet: run `%s'.%s\n",
		        fs_cli_dim (), fs_util_rules_dir (), apply, fs_cli_reset ());
		g_free (apply);
	}

	g_free (summary);
	fs_policy_free (policy);
	return FS_EXIT_OK;
}

static gint
policy_remove (gint argc, gchar **argv)
{
	FsRuleKind kind;
	FsPolicy *policy;
	gchar *end = NULL;
	guint64 n;
	FsRule *rule, *copy;
	gchar *summary;

	if (argc != 2 || !fs_cli_kind_parse (argv[0], &kind)) {
		fs_cli_error ("usage: stockfw policy remove KIND N");
		fs_cli_hint ("`stockfw policy list --kind KIND' shows the numbers");
		return FS_EXIT_USAGE;
	}

	n = g_ascii_strtoull (argv[1], &end, 10);
	policy = fs_cli_load_policy (NULL, NULL);

	if (end == NULL || *end != '\0' || n == 0 ||
	    n > policy->kinds[kind]->len) {
		fs_cli_error ("%s has no rule number %s (it has %u)",
		              fs_cli_kind_name (kind), argv[1],
		              policy->kinds[kind]->len);
		fs_policy_free (policy);
		return FS_EXIT_USAGE;
	}

	rule = g_ptr_array_index (policy->kinds[kind], n - 1);
	copy = fs_rule_copy (rule);
	summary = fs_cli_rule_summary (copy);

	if (!fs_policy_remove_persist (policy, copy)) {
		fs_cli_error ("could not save the policy in %s",
		              fs_util_rules_dir ());
		fs_rule_free (copy);
		g_free (summary);
		fs_policy_free (policy);
		return FS_EXIT_FAILURE;
	}

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, "removed", TRUE); g_string_append_c (out, ',');
		fs_json_kv_str (out, "kind", fs_cli_kind_name (kind));
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (!fs_cli.quiet) {
		printf ("%s-%s %s %s\n", fs_cli_red (), fs_cli_reset (),
		        fs_cli_kind_name (kind), summary);
		gchar *apply = fs_cli_sudo_hint ("apply");

		printf ("%sSaved.  Not live yet: run `%s'.%s\n",
		        fs_cli_dim (), apply, fs_cli_reset ());
		g_free (apply);
	}

	fs_rule_free (copy);
	g_free (summary);
	fs_policy_free (policy);
	return FS_EXIT_OK;
}

gint
fs_cli_cmd_policy (gint argc, gchar **argv)
{
	const gchar *sub = argc > 1 ? argv[1] : "list";

	if (strcmp (sub, "list") == 0 || strcmp (sub, "ls") == 0)
		return policy_list (argc > 1 ? argc - 2 : 0, argv + 2);
	if (strcmp (sub, "add") == 0)
		return policy_add (argc - 2, argv + 2);
	if (strcmp (sub, "remove") == 0 || strcmp (sub, "rm") == 0)
		return policy_remove (argc - 2, argv + 2);

	/* `policy --kind KIND' is `policy list --kind KIND'. */
	if (fs_cli_is_option_at (argv, 1))
		return policy_list (argc - 1, argv + 1);

	fs_cli_error ("unknown policy action: %s", sub);
	fs_cli_hint ("policy list | policy add | policy remove");
	return FS_EXIT_USAGE;
}

/* --------------------------------------------------------------- apply */

gint
fs_cli_cmd_apply (gint argc, gchar **argv)
{
	gboolean dry_run = FALSE;
	FsPolicy *policy;
	FsSettings *settings;
	FsApplyOutcome *outcome;
	GError *error = NULL;
	gboolean on_disk;
	gint status;
	gchar *desc;

	for (gint i = 1; i < argc; i++) {
		if (fs_cli_is_option_at (argv, i) &&
		    (strcmp (argv[i], "--dry-run") == 0 ||
		     strcmp (argv[i], "-n") == 0)) {
			dry_run = TRUE;
		} else if (fs_cli_is_option_at (argv, i)) {
			fs_cli_unknown_option ("apply", argv[i]);
			return FS_EXIT_USAGE;
		} else {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			return FS_EXIT_USAGE;
		}
	}

	policy = fs_cli_load_policy (&on_disk, NULL);

	if (!on_disk) {
		fs_cli_error ("no policy saved in %s -- nothing to apply",
		              fs_util_rules_dir ());
		if (geteuid () == 0 && g_getenv ("SUDO_USER") != NULL)
			fs_cli_hint ("as root the policy is read from /etc/stockfw; "
			             "a policy edited without sudo lives in "
			             "~/.stockfw");
		fs_policy_free (policy);
		return FS_EXIT_FAILURE;
	}

	if (dry_run) {
		FsPolicyImpact *impact = fs_policy_impact_preview (policy);

		desc = fs_policy_impact_describe (impact);
		if (fs_cli.json) {
			GString *out = g_string_new ("{");

			fs_json_kv_bool (out, "dry_run", TRUE);       g_string_append_c (out, ',');
			fs_json_kv_uint (out, "added", impact->added); g_string_append_c (out, ',');
			fs_json_kv_uint (out, "removed", impact->removed); g_string_append_c (out, ',');
			fs_json_kv_uint (out, "unchanged", impact->unchanged); g_string_append_c (out, ',');
			fs_json_kv_str (out, "impact", desc);
			g_string_append_c (out, '}');
			fs_cli_print_json (out);
			g_string_free (out, TRUE);
		} else {
			printf ("Would apply: %s\n", desc);
			printf ("%sNothing was changed (dry run).%s\n",
			        fs_cli_dim (), fs_cli_reset ());
		}
		g_free (desc);
		fs_policy_impact_free (impact);
		fs_policy_free (policy);
		return FS_EXIT_OK;
	}

	if (geteuid () != 0) {
		fs_policy_free (policy);
		return fs_cli_need_root ("apply");
	}

	settings = fs_cli_backend_context (policy);
	outcome = fs_policy_apply_safe (fs_backend (), policy, "cli",
	                                fs_apply_hold_reason (), &error);
	desc = fs_policy_impact_describe (outcome->impact);

	if (outcome->held) {
		status = FS_EXIT_OK;
	} else if (outcome->result == FS_APPLY_OK) {
		status = FS_EXIT_OK;
	} else if (outcome->result == FS_APPLY_NO_PRIVILEGE) {
		status = FS_EXIT_NEED_ROOT;
	} else {
		status = FS_EXIT_FAILURE;
	}

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, "applied", outcome->applied);   g_string_append_c (out, ',');
		fs_json_kv_bool (out, "held", outcome->held);         g_string_append_c (out, ',');
		fs_json_kv_str (out, "hold_reason", outcome->hold_reason); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "narrow", outcome->narrow);     g_string_append_c (out, ',');
		fs_json_kv_str (out, "result",
		                fs_util_apply_result_to_string ((int) outcome->result));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "impact", desc);                 g_string_append_c (out, ',');
		fs_json_kv_str (out, "error", error ? error->message : NULL); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "rollback_attempted", outcome->rollback_attempted); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "rollback_verified", outcome->rollback_verified);
		g_string_append_c (out, ',');
		fs_json_key (out, "notes");
		fs_cli_append_lines_json (out, outcome->notes);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (outcome->held) {
		printf ("%sHeld:%s %s.  The firewall was left untouched.\n",
		        fs_cli_amber (), fs_cli_reset (), outcome->hold_reason);
		printf ("Recorded in the audit log: %s\n", desc);
	} else if (outcome->result == FS_APPLY_OK) {
		if (outcome->impact->added == 0 && outcome->impact->removed == 0)
			printf ("Nothing to change: the policy already matches the "
			        "firewall.\n");
		else
			printf ("%sApplied%s (%s): %s\n", fs_cli_green (),
			        fs_cli_reset (),
			        outcome->narrow ? "only the changes" : "whole policy",
			        desc);
		fs_cli_print_notes (outcome->notes);
	} else {
		fs_cli_error ("%s", error != NULL ? error->message
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
	g_clear_error (&error);
	fs_apply_outcome_free (outcome);
	fs_settings_free (settings);
	fs_policy_free (policy);

	return status;
}

/* --------------------------------------------------------- start / stop */

/* [ intel_follow ]
 * The threat-intel blocklists follow the user's Stop and Start (design
 * 6.5): after the firewall stopped they are removed and recorded as
 * suspended (fs_intel_suspend); after it started they are applied again
 * through the gate, under the same hold as any apply (fs_intel_resume).
 * Nothing happens where no list was ever turned on.  Appends an "intel"
 * member to `json' when given, else prints; FALSE when the blocklists
 * did not follow. */
static gboolean
intel_follow (gboolean start, GString *json)
{
	const FsBackend *backend = fs_backend ();
	FsIntelOutcome *o = NULL;
	GError *error = NULL;
	GString *notes = g_string_new (NULL);
	const gchar *result;
	gboolean ok;

	if (start) {
		o = fs_intel_resume (backend, "cli", fs_apply_hold_reason (),
		                     &error);
		ok = error == NULL && (o == NULL || o->result != FS_APPLY_FAILED);
		if (o == NULL)
			result = error != NULL ? "failed" : "none";
		else if (o->held)
			result = "held";
		else
			result = o->result == FS_APPLY_OK ? "applied" : "failed";
	} else {
		ok = fs_intel_suspend (backend, "cli", &error);
		result = ok ? "suspended" : "failed";
	}
	for (guint i = 0; o != NULL && o->notes != NULL && i < o->notes->len;
	     i++)
		g_string_append_printf (notes, "%s\n",
		                        (gchar *) g_ptr_array_index (o->notes, i));

	if (json != NULL) {
		g_string_append_c (json, ',');
		fs_json_key (json, "intel");
		g_string_append_c (json, '{');
		fs_json_kv_bool (json, "ok", ok);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "result", result);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "hold", o != NULL ? o->hold_reason : NULL);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "error", error ? error->message : NULL);
		g_string_append_c (json, ',');
		fs_json_key (json, "notes");
		fs_cli_append_lines_json (json, notes->str);
		g_string_append_c (json, '}');
	} else if (!ok) {
		fs_cli_error ("the blocklists could not be %s: %s",
		              start ? "applied" : "removed",
		              error != NULL ? error->message
		                            : FS_CLI_LIVE " does not hold "
		                              "them");
		fs_cli_print_notes (notes->str);
	} else if (o != NULL && o->held) {
		printf ("%snote:%s blocklists not applied: %s\n", fs_cli_amber (),
		        fs_cli_reset (), o->hold_reason);
	} else if (o != NULL) {
		if (!fs_cli.quiet)
			printf ("Blocklists applied (%u list%s).\n", o->sets,
			        o->sets == 1 ? "" : "s");
		fs_cli_print_notes (notes->str);
	}

	g_string_free (notes, TRUE);
	g_clear_error (&error);
	fs_intel_outcome_free (o);
	return ok;
}

static gint
start_or_stop (gint argc, gboolean start)
{
	FsPolicy *policy;
	FsSettings *settings;
	GError *error = NULL;
	gboolean ok, intel_ok = TRUE, on_disk = FALSE;
	gint malformed = 0;
	gchar *notes;
	GString *out = NULL;

	if (argc > 1) {
		fs_cli_error ("%s takes no arguments", start ? "start" : "stop");
		return FS_EXIT_USAGE;
	}

	if (geteuid () != 0)
		return fs_cli_need_root (start ? "start" : "stop");

	/* Load first, always: the backend starts from the policy it was
	 * handed, and an unloaded one is an empty one. */
	policy = fs_cli_load_policy (&on_disk, &malformed);
	settings = fs_cli_backend_context (policy);

	if (start) {
		FsApplyOutcome *outcome;
		FsPolicy *lift = fs_policy_new ();
		gchar *mode = fs_prefs_get_string (FS_PREFS_SENTINEL_MODE,
		                                   "auto");
		gchar *journal = fs_apply_journal_path ();
		gboolean have_journal = g_file_test (journal,
		                                     G_FILE_TEST_EXISTS);

		g_free (journal);

		/* Sentinel's blocks whose ten minutes ran out while nothing
		 * was running to lift them (a reboot) come out of the file,
		 * and the start leaves every one of them out of what it
		 * installs. */
		fs_autoblock_expire (policy, g_get_real_time () / G_USEC_PER_SEC,
		                     g_strcmp0 (mode, "auto") != 0, lift);
		g_free (mode);

		if (fs_backend ()->start_applies_policy && !have_journal &&
		    (!on_disk || malformed > 0)) {
			/* Nothing was ever applied, so this start would be the
			 * first apply of the file: refused when there is no
			 * file or a line of it could not be read, rather than
			 * starting a policy that is empty or missing rules. */
			fs_audit_log ("firewall start refused",
			              !on_disk
			              ? "cli | refused | no policy saved and none "
			                "applied before"
			              : "cli | refused | malformed lines in the "
			                "saved policy and none applied before");
			if (!on_disk)
				g_set_error (&error, FS_APPLY_ERROR, 0,
				             "no policy saved in %s and none applied "
				             "before, so there is nothing to start",
				             fs_util_rules_dir ());
			else
				g_set_error (&error, FS_APPLY_ERROR, 0,
				             "%d line(s) of the policy in %s could not "
				             "be read and no policy was applied before; "
				             "fix them, then run `stockfw apply'",
				             malformed, fs_util_rules_dir ());
			ok = FALSE;
			notes = NULL;
			fs_policy_free (lift);
			goto report;
		}

		/* Through the start gate: the last APPLIED policy is what
		 * starts (changes saved but not applied stay off, held or
		 * not), audit-only mode is honoured, and the start is on the
		 * audit record. */
		outcome = fs_firewall_start_lifting (fs_backend (), policy, lift,
		                                     "cli",
		                                     fs_apply_hold_reason (),
		                                     &error);
		fs_policy_free (lift);
		ok = (outcome->result == FS_APPLY_OK);
		if (outcome->result == FS_APPLY_DRY_RUN && error == NULL)
			g_set_error (&error, FS_APPLY_ERROR, 0,
			             "held (%s) and no policy was ever applied, "
			             "so there is nothing safe to start with",
			             outcome->hold_reason);
		else if (!ok && error == NULL)
			g_set_error_literal (&error, FS_APPLY_ERROR, 0,
				fs_util_apply_result_to_string (
					(int) outcome->result));
		notes = ok ? g_strdup (outcome->notes) : NULL;
		if (ok && outcome->held && !fs_cli.json && !fs_cli.quiet)
			printf ("%sHeld:%s %s.  Started with the last applied "
			        "policy; later changes stay held.\n",
			        fs_cli_amber (), fs_cli_reset (),
			        outcome->hold_reason);
		else if (ok && have_journal &&
		         fs_backend ()->start_applies_policy &&
		         (outcome->impact->added > 0 ||
		          outcome->impact->removed > 0) &&
		         !fs_cli.json && !fs_cli.quiet)
			printf ("%sNot applied:%s the saved policy has changes "
			        "that are not live.  Started with the last "
			        "applied policy; `stockfw apply --dry-run' lists "
			        "them, `stockfw apply' puts them live.\n",
			        fs_cli_amber (), fs_cli_reset ());
		fs_apply_outcome_free (outcome);
	} else {
		ok = fs_firewall_stop_logged (fs_backend (), "cli", &error);
		notes = NULL;
	}

report:
	if (fs_cli.json) {
		out = g_string_new ("{");
		fs_json_kv_bool (out, "ok", ok);  g_string_append_c (out, ',');
		fs_json_kv_str (out, "error", error ? error->message : NULL);
		g_string_append_c (out, ',');
		fs_json_key (out, "notes");
		fs_cli_append_lines_json (out, notes);
	} else if (ok) {
		if (!fs_cli.quiet)
			printf ("Firewall %s.\n", start ? "started" : "stopped");
		fs_cli_print_notes (notes);
	} else {
		fs_cli_error ("could not %s the firewall: %s",
		              start ? "start" : "stop",
		              error ? error->message : "unknown error");
	}

	/* Only once the firewall itself did what was asked: a Start that
	 * failed applies no blocklist, a Stop that failed removes none. */
	if (ok)
		intel_ok = intel_follow (start, out);

	if (out != NULL) {
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	}

	g_clear_error (&error);
	g_free (notes);
	fs_settings_free (settings);
	fs_policy_free (policy);

	return ok && intel_ok ? FS_EXIT_OK : FS_EXIT_FAILURE;
}

gint fs_cli_cmd_start (gint argc, gchar **argv) { return start_or_stop (argc, TRUE); }
gint fs_cli_cmd_stop  (gint argc, gchar **argv) { return start_or_stop (argc, FALSE); }

gint
fs_cli_cmd_simulate (gint argc, gchar **argv)
{
	FsWhatIfResult *result;
	GPtrArray *words = g_ptr_array_new ();
	gboolean assume_running = FALSE;
	gchar *line;
	gint status;

	for (gint i = 1; i < argc; i++) {
		if (fs_cli_is_option_at (argv, i) &&
		    strcmp (argv[i], "--assume-running") == 0) {
			assume_running = TRUE;
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

	if (words->len < 2) {
		g_ptr_array_free (words, TRUE);
		fs_cli_error ("simulate needs a description of the traffic");
		fs_cli_hint ("stockfw simulate \"allow ssh from 192.168.1.50 on "
		             "port 22\"");
		return FS_EXIT_USAGE;
	}

	/* Unquoted words are one line, as the user would have typed it. */
	line = g_strjoinv (" ", (gchar **) words->pdata);
	g_ptr_array_free (words, TRUE);

	result = fs_cli_whatif (line, assume_running);

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
		gchar *text = fs_whatif_result_describe (result);
		gchar *rest = strchr (text, '\n');
		const gchar *colour =
			result->verdict == FS_WHATIF_ALLOWED ? fs_cli_green ()
			: result->verdict == FS_WHATIF_BLOCKED ? fs_cli_red ()
			                                       : fs_cli_amber ();

		/* The summary names the verdict; it gets the colour. */
		if (rest != NULL)
			*rest++ = '\0';
		printf ("%s%s%s\n%s", colour, text, fs_cli_reset (),
		        rest != NULL ? rest : "");
		printf ("%sA simulation only: nothing was written.%s\n",
		        fs_cli_dim (), fs_cli_reset ());
		g_free (text);
	}

	fs_whatif_result_free (result);
	g_free (line);

	return status;
}

/* ------------------------------------------------------------- copilot */

/* "checks":[{probe, before, after}, ...]: a fix's What-If checks. */
static void
health_checks_json (GString *out, const GPtrArray *checks)
{
	g_string_append (out, "\"checks\":[");
	for (guint k = 0; checks != NULL && k < checks->len; k++) {
		const FsHealthCheck *c = g_ptr_array_index (checks, k);

		if (k > 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "probe", c->probe);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "before", fs_whatif_verdict_name (c->before));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "after", fs_whatif_verdict_name (c->after));
		g_string_append_c (out, '}');
	}
	g_string_append_c (out, ']');
}

/* [ health_json ] -- one schema, shared with the dashboard if it ever
 * serves it: version, the rule count, the platform model, findings. */
static void
health_json (GString *out, const GPtrArray *findings, guint rules,
             FsWhatIfPlatform platform)
{
	g_string_append (out, "{\"version\":1,");
	fs_json_kv_uint (out, "policy_rules", rules);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "platform",
	                platform == FS_WHATIF_WINDOWS_BLOCK_WINS
	                ? "windows-block-wins" : "linux-first-match");
	g_string_append (out, ",\"findings\":[");
	for (guint i = 0; i < findings->len; i++) {
		const FsHealthFinding *f = g_ptr_array_index (findings, i);

		if (i > 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "kind", fs_health_kind_name (f->kind));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "severity",
		                fs_health_severity_name (f->severity));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "title", f->title);
		g_string_append (out, ",\"rule\":{");
		fs_json_kv_str (out, "kind",
		                fs_health_rule_kind_name ((FsRuleKind) f->policy_kind));
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "index", (guint64) MAX (f->policy_index, 0));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "csv", f->rule_csv);
		g_string_append (out, "},");
		if (f->other_csv != NULL && f->other_kind >= 0) {
			g_string_append (out, "\"other\":{");
			fs_json_kv_str (out, "kind", fs_health_rule_kind_name (
				(FsRuleKind) f->other_kind));
			g_string_append_c (out, ',');
			fs_json_kv_uint (out, "index",
			                 (guint64) MAX (f->other_index, 0));
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "csv", f->other_csv);
			g_string_append (out, "},");
		}
		fs_json_kv_str (out, "why", f->why);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "evidence", f->evidence);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "whatif", f->whatif_line);
		g_string_append (out, ",\"fix\":");
		if (f->fix == FS_HEALTH_FIX_NONE) {
			g_string_append (out, "null,");
			fs_json_kv_str (out, "no_fix_reason", f->no_fix_reason);
			/* A fix that was tried and failed its checks: what it
			 * would have changed and the checks, which the reason
			 * points to. */
			if (f->checks != NULL && f->checks->len > 0) {
				g_string_append (out, ",\"tried\":{");
				fs_json_kv_str (out, "before", f->fix_before);
				g_string_append_c (out, ',');
				fs_json_kv_str (out, "after", f->fix_after);
				g_string_append_c (out, ',');
				health_checks_json (out, f->checks);
				g_string_append_c (out, '}');
			}
		} else {
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "label", f->fix_label);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "before", f->fix_before);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "after", f->fix_after);
			g_string_append_c (out, ',');
			fs_json_kv_bool (out, "verified", f->verified);
			g_string_append_c (out, ',');
			health_checks_json (out, f->checks);
			g_string_append_c (out, '}');
		}
		g_string_append_c (out, '}');
	}
	g_string_append (out, "]}");
}

/* [ copilot_health ]
 * The Copilot page's policy health check on the saved policy, with the
 * same What-If context `simulate' builds.  It writes nothing: a fix is
 * printed with the checks that verify it, and making it stays with the
 * desktop app (or `stockfw policy').  Exit 0 with no findings, 7 with
 * findings, 2 when the policy cannot be read in full. */
static gint
copilot_health (void)
{
	gint malformed = 0;
	FsPolicy *policy = fs_cli_load_policy (NULL, &malformed);
	FsSettings *settings;
	FsWhatIfContext *ctx;
	GPtrArray *findings;
	gchar *prefix;
	guint rules = 0;
	gint status;

	if (malformed > 0) {
		fs_cli_error ("%d policy row(s) could not be read, so the check "
		              "would be incomplete", malformed);
		fs_cli_hint ("see `stockfw policy list'");
		fs_policy_free (policy);
		return FS_EXIT_USAGE;
	}
	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		rules += policy->kinds[k]->len;

	settings = fs_settings_new ();
	fs_settings_load_prefs (settings);
	ctx = fs_whatif_context_new (fs_whatif_native_platform (), policy,
	                             settings);
	fs_copilot_whatif_observe (ctx, fs_backend (), geteuid () == 0);
	prefix = fs_health_lan_prefix_auto (fs_backend ());
	findings = fs_health_check (ctx, prefix);
	status = findings->len > 0 ? FS_EXIT_FINDINGS : FS_EXIT_OK;

	if (fs_cli.json) {
		GString *out = g_string_new (NULL);

		health_json (out, findings, rules, ctx->platform);
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		printf ("%s%u rules checked, %u finding%s%s\n", fs_cli_bold (),
		        rules, findings->len, findings->len == 1 ? "" : "s",
		        fs_cli_reset ());
		for (guint i = 0; i < findings->len; i++) {
			const FsHealthFinding *f = g_ptr_array_index (findings, i);
			const gchar *colour =
				f->severity == FS_COPILOT_CRITICAL ? fs_cli_red ()
				: f->severity == FS_COPILOT_WARNING ? fs_cli_amber ()
				                                    : fs_cli_dim ();

			printf ("\n%s[%s]%s %s\n", colour,
			        fs_health_severity_name (f->severity),
			        fs_cli_reset (), f->title);
			printf ("  rule:  %s #%d: %s\n",
			        fs_health_rule_kind_name ((FsRuleKind) f->policy_kind),
			        f->policy_index + 1, f->rule_csv);
			if (f->why != NULL)
				printf ("  why:   %s\n", f->why);
			if (f->fix != FS_HEALTH_FIX_NONE && f->verified) {
				printf ("  fix:   %s: %s -> %s\n", f->fix_label,
				        f->fix_before,
				        f->fix_after != NULL ? f->fix_after : "(removed)");
				for (guint k = 0; k < f->checks->len; k++) {
					const FsHealthCheck *c =
						g_ptr_array_index (f->checks, k);

					printf ("         checked: %s: %s -> %s\n", c->probe,
					        fs_whatif_verdict_name (c->before),
					        fs_whatif_verdict_name (c->after));
				}
			} else if (f->no_fix_reason != NULL) {
				printf ("  %sno fix offered: %s%s\n", fs_cli_dim (),
				        f->no_fix_reason, fs_cli_reset ());
				if (f->checks != NULL && f->checks->len > 0)
					printf ("  tried: %s -> %s\n", f->fix_before,
					        f->fix_after != NULL ? f->fix_after
					                             : "(removed)");
				for (guint k = 0; f->checks != NULL &&
				                  k < f->checks->len; k++) {
					const FsHealthCheck *c =
						g_ptr_array_index (f->checks, k);

					printf ("         checked: %s: %s -> %s\n", c->probe,
					        fs_whatif_verdict_name (c->before),
					        fs_whatif_verdict_name (c->after));
				}
			}
		}
		if (findings->len == 0)
			printf ("No overlaps, conflicts or open risky services.\n");
		printf ("%sA check only: nothing was written. Fixes are made on "
		        "the Copilot page.%s\n", fs_cli_dim (), fs_cli_reset ());
	}

	g_ptr_array_unref (findings);
	g_free (prefix);
	fs_whatif_context_free (ctx);
	fs_settings_free (settings);
	fs_policy_free (policy);
	return status;
}

/* [ fs_cli_cmd_copilot ] */
gint
fs_cli_cmd_copilot (gint argc, gchar **argv)
{
	if (argc < 2 || strcmp (argv[1], "health") != 0) {
		fs_cli_error ("copilot needs a subcommand");
		fs_cli_hint ("stockfw copilot health [--json]");
		return FS_EXIT_USAGE;
	}
	if (argc > 2) {
		fs_cli_error ("unexpected argument: %s", argv[2]);
		fs_cli_hint ("stockfw copilot health [--json]");
		return FS_EXIT_USAGE;
	}
	return copilot_health ();
}

/* ------------------------------------------------------- the commands */

static const FsCliOption policy_opts[] = {
	{ "--kind",    TRUE,  "list" },
	{ "--comment", TRUE,  "add"  },
	{ "--both",    FALSE, "add"  },
	{ NULL, FALSE, NULL }
};

static const FsCliOption apply_opts[] = {
	{ "--dry-run", FALSE, NULL },
	{ "-n",        FALSE, NULL },
	{ NULL, FALSE, NULL }
};

static const FsCliOption simulate_opts[] = {
	{ "--assume-running", FALSE, NULL },
	{ NULL, FALSE, NULL }
};

static const FsCliOption no_opts[] = {
	{ NULL, FALSE, NULL }
};

const FsCliCommandDef fs_cli_policy_commands[] = {
	{ "policy", fs_cli_cmd_policy,
"Usage: stockfw policy list [--kind KIND] [--json]\n"
"       stockfw policy add KIND FIELD... [--comment TEXT] [--both]\n"
"       stockfw policy remove KIND N\n"
"\n"
"Edits the saved policy -- the files the desktop app's Policy page\n"
"shows.  Changes are validated (hosts, ports and ranges fail closed)\n"
"and saved; nothing reaches the firewall until `stockfw apply'.\n"
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
"adds the opposite-direction twin of an allow rule, as one change.\n"
"N is the rule's number in `stockfw policy list --kind KIND'.  A field\n"
"or comment that starts with a dash goes after \"--\" or as\n"
"--comment=TEXT.\n"
"\n"
"Examples:\n"
"  stockfw policy add inbound-allow-service SSH 22 192.168.1.0/24 --comment admin\n"
"  stockfw policy add outbound-deny-to 203.0.113.9\n"
"  stockfw policy remove outbound-deny-to 1\n",
	  policy_opts, NULL },

	{ "apply", fs_cli_cmd_apply,
"Usage: stockfw apply [--dry-run] [--json]\n"
"\n"
"Pushes the saved policy to the firewall through the same apply gate\n"
"the desktop app uses: only what changed is touched, a failed apply is\n"
"rolled back to the last applied policy and the rollback is verified,\n"
"and every attempt is one line in the audit log.  When audit-only mode\n"
"is on (Policy page), the firewall is left untouched and the would-be\n"
"change is recorded.  --dry-run only reports the impact.  Needs root.\n",
	  apply_opts, NULL },

	{ "start", fs_cli_cmd_start,
"Usage: stockfw start\n"
"\n"
"Starts the firewall with the last APPLIED policy -- what `stockfw\n"
"apply' last put live -- so saved changes that were never applied stay\n"
"off, and Sentinel blocks whose ten minutes ran out are left out.  The\n"
"boot unit (stockfw.service) runs this at every boot.  When nothing was\n"
"ever applied, the saved policy is started instead, and the start is\n"
"refused if there is none or a line of it is malformed.  Threat-intel\n"
"blocklists that are turned on are applied again, through the same gate\n"
"(audit-only mode holds them too); if they cannot be, the firewall still\n"
"runs and the exit status is non-zero.  Needs root.\n",
	  no_opts, NULL },

	{ "stop", fs_cli_cmd_stop,
"Usage: stockfw stop\n"
"\n"
"Removes StockFW's own chains, and its threat-intel blocklists until\n"
"the next start.  Rules owned by Docker, libvirt or anything else are\n"
"left alone.  Needs root.\n",
	  no_opts, NULL },

	{ "simulate", fs_cli_cmd_simulate,
"Usage: stockfw simulate \"<traffic>\" [--assume-running] [--json]\n"
"\n"
"Answers ALLOWED, BLOCKED or DEPENDS for described traffic against the\n"
"saved policy and Firewall preferences, the way the Copilot page's\n"
"What-If Simulator does: the rules checked, the one that decided, and\n"
"fixes that were checked before they are offered.  What the line\n"
"leaves open (host, port, protocol, direction) is answered for every\n"
"case: DEPENDS names the split.  When the firewall is not running the\n"
"answer says so; --assume-running answers as if it were.  It writes\n"
"nothing: it is a question, not a change.  Exits 0 for ALLOWED, 5 for\n"
"BLOCKED, 6 for DEPENDS and 2 for a line it cannot read, so scripts\n"
"can branch on it.  With -q only the verdict word is printed.  An\n"
"unknown option is refused rather than read as part of the question.\n"
"\n"
"Examples:\n"
"  stockfw simulate \"allow ssh from 192.168.1.50 on port 22\"\n"
"  stockfw simulate \"inbound rdp\"\n"
"  stockfw simulate \"outbound tcp to 203.0.113.9 port 443\"\n",
	  simulate_opts, NULL },

	{ "copilot", fs_cli_cmd_copilot,
"Usage: stockfw copilot health [--json]\n"
"\n"
"Runs the Copilot page's policy health check on the saved policy:\n"
"rules that repeat another, rules another rule already covers, allows a\n"
"deny makes unreachable, outbound allows that do nothing while outbound\n"
"traffic is allowed, wide or risky inbound allows from anyone, and deny\n"
"rules that reach no address family.  These are fixed rules, not a\n"
"model.  Each fix is shown with the What-If checks that verify it, and\n"
"one that does not verify is not offered.  It writes nothing: fixes\n"
"are made on the Copilot page.  The local network a narrowing uses is\n"
"the first adapter with a private IPv4 address.\n"
"\n"
"Exits 0 with no findings, 7 with findings, and 2 when the policy\n"
"cannot be read in full.  In --json, rule.index counts from 0.\n",
	  no_opts, NULL },

	{ NULL, NULL, NULL, NULL, NULL }
};
