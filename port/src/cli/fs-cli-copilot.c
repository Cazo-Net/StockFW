/*---[ fs-cli-copilot.c ]-----------------------------------------------
 * `stockfw copilot' and `stockfw sentinel': the desktop app's Copilot
 * page and Sentinel in a terminal (master plan PR 4, package 4B):
 *
 *   copilot health [--severity L] [--fix N [--yes]]
 *   copilot scan [--since T] [--history]
 *   copilot show ID | block ID [--yes]   (same --since, --history)
 *   copilot checks
 *   copilot changes [--undo ID]
 *   sentinel [list] | lift TARGET|--all|--expired | mode [auto|detect]
 *
 * Reads are done here.  Every write is an fs_control op (copilot.block,
 * copilot.fix, copilot.undo, sentinel.lift, sentinel.mode), which takes
 * the policy lock; blocks go live through fs_firewall_add_live and
 * lifts through the fs_autoblock_lift_* helpers (core, 4A).  A question
 * is asked only when stdin is a terminal; without one a change needs
 * --yes and is refused without it.
 *
 * There is no daemon yet (PR 7), so `copilot scan' replays the events
 * on record into a fresh Copilot: the saved policy attached first, no
 * learning baseline.  A finding's ID is the first 8 hex digits of the
 * SHA-256 of its key ("type|app|subject"), so the same events give the
 * same IDs in the next command.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "control/fs-changelog.h"
#include "control/fs-control.h"
#include "core/fs-apply.h"
#include "core/fs-autoblock.h"
#include "core/fs-copilot.h"
#include "core/fs-eventlog.h"
#include "core/fs-eventstore.h"
#include "core/fs-health.h"
#include "core/fs-json.h"
#include "core/fs-prefs.h"
#include "core/fs-util.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* === PR4-B === */

/* ------------------------------------------------------------ helpers */

/* [ say ] -- one line of text from outside, made safe for a terminal;
 * pre and post (colour) stay outside. */
static void G_GNUC_PRINTF (3, 4)
say (const gchar *pre, const gchar *post, const gchar *format, ...)
{
	va_list args;
	gchar *raw, *safe;

	va_start (args, format);
	raw = g_strdup_vprintf (format, args);
	va_end (args);
	safe = fs_cli_out_safe (raw);
	printf ("%s%s%s\n", pre, safe, post);
	g_free (safe);
	g_free (raw);
}

/* [ say_wrapped ] -- prose from outside, wrapped with a hanging indent. */
static void
say_wrapped (const gchar *label, const gchar *text)
{
	gchar *safe = fs_cli_out_safe (text);
	gchar *line = g_strdup_printf ("%-12s%s", label, safe);
	gchar *wrapped = fs_cli_wrap (line, 12);

	printf ("%s\n", wrapped);
	g_free (wrapped);
	g_free (line);
	g_free (safe);
}

/* [ cmd_line ] -- "stockfw WORDS 'ARG'": a command to paste, the
 * argument quoted for a shell. */
static gchar *
cmd_line (const gchar *words, const gchar *arg)
{
	gchar *q = g_shell_quote (arg != NULL ? arg : "");
	gchar *s = g_strdup_printf ("stockfw %s %s", words, q);

	g_free (q);
	return s;
}

/* [ ask ] -- `question' [y/N] on a terminal; --yes goes on; with no
 * terminal on stdin nothing is asked and the change is refused, naming
 * --yes.  TRUE to go on. */
static gboolean
ask (const gchar *question, const gchar *refused, gboolean yes)
{
	gchar answer[16] = "";

	if (yes)
		return TRUE;
	if (!isatty (STDIN_FILENO)) {
		fs_cli_error ("refused: no terminal to ask on; pass --yes to %s",
		              refused);
		return FALSE;
	}
	fprintf (stderr, "%s [y/N] ", question);
	fflush (stderr);
	if (fgets (answer, sizeof answer, stdin) == NULL ||
	    (g_ascii_strcasecmp (g_strstrip (answer), "y") != 0 &&
	     g_ascii_strcasecmp (answer, "yes") != 0)) {
		fs_cli_error ("not done: nothing was changed");
		return FALSE;
	}
	return TRUE;
}

/* [ window_warning ] -- a StockFW window running as root keeps its own
 * copy of the policy and of Sentinel's list, and writes them back when
 * it saves (15.5.1), as `config set' warns (fs-cli-config.c). */
static void
window_warning (void)
{
	if (fs_cli_root_gui_running ())
		fprintf (stderr, "stockfw: %swarning:%s a StockFW window is "
		         "running as root: it keeps its own copy of the policy "
		         "and of Sentinel's blocks and writes them back when it "
		         "saves, so this change may be undone.  Close it and "
		         "open it again.\n",
		         fs_cli.color_err ? "\033[1;33m" : "",
		         fs_cli.color_err ? "\033[0m" : "");
}

/* [ op_exit ] -- an op's status as an exit code, its error printed
 * (text mode) or the whole result (--json). */
static gint
op_exit (FsControlResult *r)
{
	if (fs_cli.json) {
		gchar *json = fs_control_result_json (r);
		GString *out = g_string_new (json);

		fs_cli_print_json (out);
		g_string_free (out, TRUE);
		g_free (json);
	} else if (r->status != FS_CONTROL_OK) {
		if (r->problems != NULL)
			fs_cli_print_problems (r->problems);
		fs_cli_error ("%s", r->error != NULL ? r->error : "failed");
		if (r->hint != NULL)
			fs_cli_hint ("%s", r->hint);
	}
	switch (r->status) {
	case FS_CONTROL_OK:        return FS_EXIT_OK;
	case FS_CONTROL_USAGE:     return FS_EXIT_USAGE;
	case FS_CONTROL_NEED_ROOT: return FS_EXIT_NEED_ROOT;
	default:                   return FS_EXIT_FAILURE;
	}
}

/* [ live_words ] -- what a live edit did to the firewall. */
static void
live_words (const FsApplyOutcome *o, const gchar *none)
{
	if (fs_cli.quiet)
		return;
	if (o == NULL)
		printf ("%s\n", none);
	else if (o->held)
		say ("", "", "Held (%s): the firewall was not changed.",
		     o->hold_reason != NULL ? o->hold_reason : "held");
	else if (o->result == FS_APPLY_DRY_RUN &&
	         o->firewall_was == FS_FW_STOPPED)
		printf ("The firewall is stopped: the change is recorded for the "
		        "next start, and the firewall was left stopped.\n");
	else if (o->result == FS_APPLY_OK)
		printf ("The firewall was changed (%s).\n",
		        o->applied ? "live now" : "no change was needed");
}

/* ------------------------------------------------------------- health */

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

/* [ finding_ref ] -- "inbound-allow-service:1" for a finding's row. */
static gchar *
finding_ref (gint kind, gint index)
{
	if (kind < 0 || kind >= FS_RULE_N_KINDS || index < 0)
		return NULL;
	return fs_cli_rule_ref ((FsRuleKind) kind, (guint) index + 1);
}

/* [ health_json ] -- one schema, shared with the dashboard if it ever
 * serves it: version, the rule count, the platform model, findings.
 * number (PR 4) is what --fix takes. */
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
		gchar *ref = finding_ref (f->policy_kind, f->policy_index);

		if (i > 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, '{');
		fs_json_kv_uint (out, "number", i + 1);
		g_string_append_c (out, ',');
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
		fs_json_kv_str (out, "rule_ref", ref);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "csv", f->rule_csv);
		g_string_append (out, "},");
		g_free (ref);
		if (f->other_csv != NULL && f->other_kind >= 0) {
			gchar *oref = finding_ref (f->other_kind, f->other_index);

			g_string_append (out, "\"other\":{");
			fs_json_kv_str (out, "kind", fs_health_rule_kind_name (
				(FsRuleKind) f->other_kind));
			g_string_append_c (out, ',');
			fs_json_kv_uint (out, "index",
			                 (guint64) MAX (f->other_index, 0));
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "rule_ref", oref);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "csv", f->other_csv);
			g_string_append (out, "},");
			g_free (oref);
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

/* [ print_checks ] -- a fix's What-If checks, one line each. */
static void
print_checks (const GPtrArray *checks, const gchar *indent)
{
	for (guint k = 0; checks != NULL && k < checks->len; k++) {
		const FsHealthCheck *c = g_ptr_array_index (checks, k);

		say ("", "", "%schecked: %s: %s -> %s", indent, c->probe,
		     fs_whatif_verdict_name (c->before),
		     fs_whatif_verdict_name (c->after));
	}
}

/* [ health_saved ]
 * The Copilot page's policy health check on the saved policy, with the
 * same What-If context `simulate' builds.  NULL (and *rc) when the
 * policy cannot be read in full. */
static GPtrArray *
health_saved (guint *rules, FsWhatIfPlatform *platform, gint *rc)
{
	GPtrArray *problems = NULL;
	FsPolicy *policy = fs_cli_load_policy_report (NULL, &problems);
	FsSettings *settings;
	FsWhatIfContext *ctx;
	GPtrArray *findings;
	gchar *prefix;

	*rules = 0;
	if (problems->len > 0) {
		fs_cli_print_problems (problems);
		fs_cli_error ("%u policy line%s %s, so the check would "
		              "be incomplete", problems->len,
		              problems->len == 1 ? "" : "s",
		              problems->len == 1 ? "is not a rule"
		                                 : "are not rules");
		g_ptr_array_unref (problems);
		fs_policy_free (policy);
		*rc = FS_EXIT_USAGE;
		return NULL;
	}
	g_ptr_array_unref (problems);
	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		*rules += policy->kinds[k]->len;

	settings = fs_settings_new ();
	fs_settings_load_prefs (settings);
	ctx = fs_whatif_context_new (fs_whatif_native_platform (), policy,
	                             settings);
	fs_copilot_whatif_observe (ctx, fs_backend (), geteuid () == 0);
	prefix = fs_health_lan_prefix_auto (fs_backend ());
	findings = fs_health_check (ctx, prefix);
	*platform = ctx->platform;
	g_free (prefix);
	fs_whatif_context_free (ctx);
	fs_settings_free (settings);
	fs_policy_free (policy);
	return findings;
}

/* [ health_fix ] -- G11: `copilot health --fix N'.  The fix is shown
 * with its What-If checks, confirmed, and made by copilot.fix, which
 * runs the check again under the lock and refuses a fix that changed. */
static gint
health_fix (const GPtrArray *findings, guint number, gboolean yes)
{
	const FsHealthFinding *f;
	FsControlActor actor = fs_control_actor_self ("cli");
	GVariantBuilder b;
	FsControlResult *r;
	gint rc;

	if (number == 0 || number > findings->len) {
		fs_cli_error ("there is no finding %u (the check found %u)",
		              number, findings->len);
		fs_cli_hint ("`stockfw copilot health' numbers them");
		return FS_EXIT_USAGE;
	}
	f = g_ptr_array_index (findings, number - 1);
	if (f->fix == FS_HEALTH_FIX_NONE || !f->verified) {
		gchar *safe = fs_cli_out_safe (f->no_fix_reason != NULL
		                               ? f->no_fix_reason
		                               : "no fix was verified");

		fs_cli_error ("finding %u has no fix: %s", number, safe);
		g_free (safe);
		return FS_EXIT_FAILURE;
	}

	if (!fs_cli.json) {
		say (fs_cli_bold (), fs_cli_reset (), "Fix %u: %s", number,
		     f->fix_label);
		say ("", "", "  before: %s", f->fix_before);
		say ("", "", "  after:  %s", f->fix_after != NULL ? f->fix_after
		                                                   : "(removed)");
		printf ("  Checked by What-If (before -> after):\n");
		print_checks (f->checks, "    ");
	}
	if (!ask ("Make this fix and save the policy?", "make the fix", yes))
		return FS_EXIT_FAILURE;
	window_warning ();

	g_variant_builder_init (&b, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&b, "{sv}", "number", g_variant_new_uint32 (number));
	g_variant_builder_add (&b, "{sv}", "before",
	                       g_variant_new_string (f->fix_before));
	if (f->fix_after != NULL)
		g_variant_builder_add (&b, "{sv}", "after",
		                       g_variant_new_string (f->fix_after));
	g_variant_builder_add (&b, "{sv}", "label",
	                       g_variant_new_string (f->fix_label));
	r = fs_control_do (&actor, "copilot.fix", g_variant_builder_end (&b));
	rc = op_exit (r);
	if (r->status == FS_CONTROL_OK && !fs_cli.json && !fs_cli.quiet) {
		say ("", "", "Fixed: %s.  The policy is saved; `stockfw apply' "
		     "puts it live.", r->fix_label);
		if (r->fix_whatif != NULL) {
			gchar *cmd = cmd_line ("simulate", r->fix_whatif);

			say ("", "", "Check it:  %s", cmd);
			g_free (cmd);
		}
		if (r->change_id > 0)
			printf ("Undo it:   stockfw copilot changes --undo %u\n",
			        r->change_id);
	}
	if (r->status == FS_CONTROL_OK && r->change_error != NULL)
		fs_cli_error ("the fix is made, but the change log could not be "
		              "written: %s", r->change_error);
	fs_control_result_free (r);
	return rc;
}

/* [ copilot_health ]
 * The check on the saved policy, as the Copilot page's health card.
 * It writes nothing, unless --fix N is given.  Exit 0 with no findings
 * at or above `threshold', 7 with such findings, 2 when the policy
 * cannot be read in full. */
static gint
copilot_health (FsCopilotSeverity threshold, guint fix, gboolean yes)
{
	FsWhatIfPlatform platform = FS_WHATIF_LINUX_FIRST_MATCH;
	GPtrArray *findings;
	guint rules = 0, counted = 0;
	gint rc = FS_EXIT_OK;

	findings = health_saved (&rules, &platform, &rc);
	if (findings == NULL)
		return rc;
	if (fix > 0) {
		rc = health_fix (findings, fix, yes);
		g_ptr_array_unref (findings);
		return rc;
	}
	for (guint i = 0; i < findings->len; i++) {
		const FsHealthFinding *f = g_ptr_array_index (findings, i);

		if (f->severity >= threshold)
			counted++;
	}

	if (fs_cli.json) {
		GString *out = g_string_new (NULL);

		health_json (out, findings, rules, platform);
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
			gchar *ref = finding_ref (f->policy_kind, f->policy_index);

			printf ("\n%s[%s]%s ", colour,
			        fs_health_severity_name (f->severity),
			        fs_cli_reset ());
			say ("", "", "%s", f->title);
			say ("", "", "  rule:  %s: %s", ref != NULL ? ref : "?",
			     f->rule_csv);
			g_free (ref);
			/* A finding about two rows names both. */
			if (f->other_csv != NULL && f->other_kind >= 0) {
				gchar *oref = finding_ref (f->other_kind,
				                           f->other_index);

				say ("", "", "  and:   %s: %s",
				     oref != NULL ? oref : "?", f->other_csv);
				g_free (oref);
			}
			if (f->why != NULL)
				say ("", "", "  why:   %s", f->why);
			if (f->fix != FS_HEALTH_FIX_NONE && f->verified) {
				say ("", "", "  fix:   %s: %s -> %s", f->fix_label,
				     f->fix_before, f->fix_after != NULL
				     ? f->fix_after : "(removed)");
				print_checks (f->checks, "         ");
				printf ("  make:  stockfw copilot health --fix %u\n",
				        i + 1);
			} else if (f->no_fix_reason != NULL) {
				say (fs_cli_dim (), fs_cli_reset (),
				     "  no fix offered: %s", f->no_fix_reason);
				if (f->checks != NULL && f->checks->len > 0)
					say ("", "", "  tried: %s -> %s", f->fix_before,
					     f->fix_after != NULL ? f->fix_after
					                          : "(removed)");
				print_checks (f->checks, "         ");
			}
			/* G12: the finding's own question, ready to paste. */
			if (f->whatif_line != NULL) {
				gchar *cmd = cmd_line ("simulate", f->whatif_line);

				say ("", "", "  ask:   %s", cmd);
				g_free (cmd);
			}
		}
		if (findings->len == 0)
			printf ("No overlaps, conflicts or open risky services.\n");
		if (!fs_cli.quiet)
			printf ("%sA check only: nothing was written. Make a fix "
			        "with `stockfw copilot health --fix N', or with "
			        "`stockfw policy remove' and `stockfw policy "
			        "add'.%s\n", fs_cli_dim (), fs_cli_reset ());
	}

	g_ptr_array_unref (findings);
	return counted > 0 ? FS_EXIT_FINDINGS : FS_EXIT_OK;
}

/* --------------------------------------------------------------- scan */

typedef struct
{
	const gchar *since;
	gboolean     history;
} ScanOpts;

typedef struct
{
	FsCopilot *copilot;
	gint64     since_us;
	guint      fed;
	guint      untimed;
} Replay;

/* [ replay_one ] -- one event, at its own time. */
static void
replay_one (Replay *rp, const FsHit *hit, gint64 ticks)
{
	gint64 us;

	if (ticks <= 0 &&
	    fs_event_time_parse (hit->time, &ticks) == FS_EVENT_TIME_OTHER) {
		gint64 epoch = fs_cli_hit_epoch (hit);

		if (epoch < 0) {
			rp->untimed++;
			return;
		}
		ticks = epoch * 10000000;
	}
	us = ticks / 10;
	if (rp->since_us != 0 && us < rp->since_us)
		return;
	fs_copilot_feed_event_full (rp->copilot, hit, us, us / G_USEC_PER_SEC);
	rp->fed++;
}

static void
on_saved_hit (const FsHit *hit, gint64 ticks, gpointer data)
{
	replay_one (data, hit, ticks);
}

/* [ scan_run ]
 * G5 before the daemon: the events on record replayed into a fresh
 * Copilot, the saved policy attached first (the checks ask it), no
 * learning baseline.  *policy_out (owned by the caller) is that policy:
 * the copilot keeps a pointer to it.  NULL with *rc when the events
 * cannot be read. */
static FsCopilot *
scan_run (const ScanOpts *o, FsPolicy **policy_out, guint *events,
          const gchar **source, gint *rc)
{
	Replay rp = { 0 };
	GError *error = NULL;

	if (!fs_cli_parse_window (o->since, NULL, &rp.since_us, NULL)) {
		*rc = FS_EXIT_USAGE;
		return NULL;
	}
	*policy_out = fs_cli_load_policy (NULL, NULL);
	rp.copilot = fs_copilot_new ();
	fs_copilot_set_policy (rp.copilot, *policy_out);

	if (o->history) {
		gchar *dir = fs_eventlog_default_dir ();

		if (!g_file_test (dir, G_FILE_TEST_IS_DIR)) {
			gchar *safe = fs_cli_out_safe (dir);

			fs_cli_error ("no saved event history in %s", safe);
			fs_cli_hint ("the desktop app saves it while Preferences > "
			             "Events > Keep event history is on");
			g_free (safe);
			g_free (dir);
			*rc = FS_EXIT_FAILURE;
			goto fail;
		}
		fs_eventlog_foreach (dir, rp.since_us, 0, on_saved_hit, &rp, NULL);
		g_free (dir);
		*source = "history";
	} else {
		GPtrArray *hits = fs_cli_log_history (100000, NULL, &error);

		if (hits == NULL) {
			fs_cli_error ("%s", error->message);
			g_error_free (error);
			if (geteuid () != 0) {
				gchar *args = fs_cli_user_args ();
				gchar *again = fs_cli_sudo_hint (args);

				fs_cli_hint ("try `%s', or add --history for the "
				             "history the desktop app saved", again);
				g_free (again);
				g_free (args);
			}
			*rc = geteuid () != 0 ? FS_EXIT_NEED_ROOT : FS_EXIT_FAILURE;
			goto fail;
		}
		for (guint i = 0; i < hits->len; i++)
			replay_one (&rp, g_ptr_array_index (hits, i), 0);
		g_ptr_array_unref (hits);
		*source = "kernel log";
	}
	*events = rp.fed;
	if (rp.untimed > 0 && !fs_cli.quiet)
		fprintf (stderr, "stockfw: %u event%s without a readable time "
		         "left out\n", rp.untimed, rp.untimed == 1 ? "" : "s");
	return rp.copilot;
fail:
	fs_copilot_free (rp.copilot);
	fs_policy_free (*policy_out);
	*policy_out = NULL;
	return NULL;
}

/* [ insight_id ] -- the first 8 hex digits of SHA-256 (key). */
static gchar *
insight_id (const FsInsight *ins)
{
	gchar *sum = g_compute_checksum_for_string (
		G_CHECKSUM_SHA256, ins->key != NULL ? ins->key
		                   : ins->title != NULL ? ins->title : "", -1);

	sum[8] = '\0';
	return sum;
}

static gint
insight_cmp (gconstpointer a, gconstpointer b)
{
	const FsInsight *x = a, *y = b;

	if (x->severity != y->severity)
		return (gint) y->severity - (gint) x->severity;
	return x->timestamp < y->timestamp ? 1
	       : x->timestamp > y->timestamp ? -1 : 0;
}

/* The findings, most severe first, then newest; g_list_free. */
static GList *
scan_findings (FsCopilot *copilot)
{
	return g_list_sort (fs_copilot_get_insights (copilot), insight_cmp);
}

static const gchar *
severity_word (FsCopilotSeverity s)
{
	return s == FS_COPILOT_CRITICAL ? "critical"
	       : s == FS_COPILOT_WARNING ? "warning" : "info";
}

/* [ staged_at ] -- when Sentinel staged this finding's rule, or 0. */
static gint64
staged_at (const FsInsight *ins)
{
	gchar *path, *want;
	GPtrArray *rows;
	gint64 at = 0;
	FsRule *rule;

	if (ins->rule_csv == NULL)
		return 0;
	rule = fs_insight_to_rule (ins);
	if (rule == NULL)
		return 0;
	want = fs_rule_to_csv (rule);
	path = fs_autoblock_state_path ();
	rows = fs_cli_sentinel_read (path, NULL, NULL);
	g_free (path);
	for (guint i = 0; rows != NULL && i < rows->len && at == 0; i++) {
		FsCliSentinelBlock *b = g_ptr_array_index (rows, i);
		gchar *csv = b->rule != NULL ? fs_rule_to_csv (b->rule) : NULL;

		if (b->kind == rule->kind && g_strcmp0 (csv, want) == 0)
			at = b->epoch;
		g_free (csv);
	}
	if (rows != NULL)
		g_ptr_array_unref (rows);
	fs_rule_free (rule);
	g_free (want);
	return at;
}

/* [ sentinel_words ] -- what Sentinel did, or will not do, for it
 * (ui/fs-copilot.c auto_block_words, without the window's session). */
static gchar *
sentinel_words (const FsInsight *ins)
{
	gint64 at = staged_at (ins);

	if (at != 0) {
		gchar *a = fs_cli_time_text (at, FS_CLI_TIME_SHORT);
		gchar *u = fs_cli_time_text (at + FS_AUTOBLOCK_TTL_S,
		                             FS_CLI_TIME_SHORT);
		gchar *s = g_strdup_printf ("Blocked automatically at %s; the "
		                            "block lifts at %s.", a, u);

		g_free (a);
		g_free (u);
		return s;
	}
	if (ins->withheld != NULL)
		return g_strdup_printf ("Not blocked automatically: %s",
		                        ins->withheld);
	if (ins->auto_applicable)
		return g_strdup_printf ("Sentinel may block this automatically, "
		                        "for %d minutes, when its mode is auto.",
		                        FS_AUTOBLOCK_TTL_S / 60);
	return g_strdup ("Never blocked automatically: only outbound "
	                 "contacts to unknown public addresses are.");
}

static void
insight_json (GString *out, const FsInsight *ins, gboolean full)
{
	gchar *id = insight_id (ins);
	gchar *words = sentinel_words (ins);

	g_string_append_c (out, '{');
	fs_json_kv_str (out, "id", id);                          g_string_append_c (out, ',');
	fs_json_kv_str (out, "type", fs_insight_type_name (ins->type));
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "severity", severity_word (ins->severity));
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "title", ins->title);               g_string_append_c (out, ',');
	fs_json_kv_str (out, "subject", ins->subject);           g_string_append_c (out, ',');
	fs_json_kv_str (out, "application", ins->application);   g_string_append_c (out, ',');
	fs_json_kv_str (out, "destination", ins->destination);   g_string_append_c (out, ',');
	fs_json_kv_uint (out, "count", ins->count);              g_string_append_c (out, ',');
	fs_json_kv_time (out, "last", (gint64) ins->timestamp);  g_string_append_c (out, ',');
	fs_json_kv_bool (out, "auto_applicable", ins->auto_applicable);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "withheld", ins->withheld);         g_string_append_c (out, ',');
	fs_json_kv_str (out, "sentinel", words);                 g_string_append_c (out, ',');
	fs_json_kv_str (out, "whatif", ins->whatif_line);        g_string_append_c (out, ',');
	fs_json_kv_str (out, "events_filter", ins->events_filter);
	g_string_append (out, ",\"rule\":");
	if (ins->rule_csv != NULL) {
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "kind", fs_cli_kind_name (ins->rule_kind));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "csv", ins->rule_csv);
		g_string_append_c (out, '}');
	} else {
		g_string_append (out, "null");
	}
	if (full) {
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "description", ins->description);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "why", ins->why);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "benign", ins->benign);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "suggested_rule", ins->suggested_rule);
		g_string_append (out, ",\"evidence\":[");
		for (guint i = 0; ins->evidence != NULL && i < ins->evidence->len;
		     i++) {
			const FsEvidence *ev = g_ptr_array_index (ins->evidence, i);

			if (i > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_time (out, "when", ev->when);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "direction", ev->inbound ? "in" : "out");
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "remote", ev->remote);
			g_string_append_c (out, ',');
			fs_json_kv_uint (out, "port", ev->port);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "protocol", ev->protocol);
			g_string_append_c (out, ',');
			fs_json_kv_bool (out, "blocked", ev->blocked);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "rule", ev->rule);
			g_string_append_c (out, '}');
		}
		g_string_append_c (out, ']');
	}
	g_string_append_c (out, '}');
	g_free (words);
	g_free (id);
}

/* [ copilot_scan ] -- `copilot scan': the findings, with their IDs. */
static gint
copilot_scan (const ScanOpts *o)
{
	FsPolicy *policy = NULL;
	const gchar *source = NULL;
	guint events = 0, n = 0;
	gint rc = FS_EXIT_OK;
	FsCopilot *copilot = scan_run (o, &policy, &events, &source, &rc);
	GList *all;

	if (copilot == NULL)
		return rc;
	all = scan_findings (copilot);
	n = g_list_length (all);

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_uint (out, "version", 1);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "source", source);
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "events", events);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "baseline", FALSE);
		g_string_append (out, ",\"findings\":[");
		for (GList *l = all; l != NULL; l = l->next) {
			if (l != all)
				g_string_append_c (out, ',');
			insight_json (out, l->data, FALSE);
		}
		g_string_append (out, "]}");
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		if (!fs_cli.plain && !fs_cli.quiet)
			printf ("%s%u event%s from the %s, %u finding%s%s\n",
			        fs_cli_bold (), events, events == 1 ? "" : "s",
			        source, n, n == 1 ? "" : "s", fs_cli_reset ());
		if (n > 0) {
			static const gchar *headers[] = { "ID", "SEVERITY", "TYPE",
			                                  "SUBJECT", "SEEN", "TITLE" };
			GPtrArray *table = g_ptr_array_new_with_free_func (
				(GDestroyNotify) g_strfreev);

			for (GList *l = all; l != NULL; l = l->next) {
				const FsInsight *ins = l->data;
				gchar **row = g_new0 (gchar *, 7);

				row[0] = insight_id (ins);
				row[1] = g_strdup (severity_word (ins->severity));
				row[2] = g_strdup (fs_insight_type_name (ins->type));
				row[3] = g_strdup (ins->subject != NULL ? ins->subject
				                   : ins->destination != NULL
				                   ? ins->destination : "");
				row[4] = g_strdup_printf ("%u", ins->count);
				row[5] = g_strdup (ins->title);
				g_ptr_array_add (table, row);
			}
			fs_cli_table_ex (headers, 6, table, 0, 5);
			g_ptr_array_unref (table);
		}
		if (!fs_cli.quiet && !fs_cli.plain)
			fprintf (stderr, "%sA replay of the events on record, without "
			         "the desktop app's learned baseline.  `stockfw "
			         "copilot show ID' gives one in full.%s\n",
			         fs_cli_dim (), fs_cli_reset ());
	}
	g_list_free (all);
	fs_copilot_free (copilot);
	fs_policy_free (policy);
	return n > 0 ? FS_EXIT_FINDINGS : FS_EXIT_OK;
}

/* [ scan_find ] -- the finding with this ID (or a unique prefix of 4
 * or more digits), from a fresh scan.  NULL with *rc when there is
 * none; the copilot and policy are the caller's. */
static const FsInsight *
scan_find (const ScanOpts *o, const gchar *want, FsCopilot **copilot,
           FsPolicy **policy, gint *rc)
{
	const gchar *source = NULL;
	guint events = 0, matches = 0;
	const FsInsight *found = NULL;
	GList *all;

	if (strlen (want) < 4 || strspn (want, "0123456789abcdefABCDEF") !=
	    strlen (want)) {
		fs_cli_error ("a finding's ID is the hex number `copilot scan' "
		              "prints (4 digits or more)");
		*rc = FS_EXIT_USAGE;
		return NULL;
	}
	*copilot = scan_run (o, policy, &events, &source, rc);
	if (*copilot == NULL)
		return NULL;
	all = scan_findings (*copilot);
	for (GList *l = all; l != NULL; l = l->next) {
		gchar *id = insight_id (l->data);

		if (g_ascii_strncasecmp (id, want, strlen (want)) == 0) {
			found = l->data;
			matches++;
		}
		g_free (id);
	}
	g_list_free (all);
	if (matches == 1)
		return found;
	if (matches == 0)
		fs_cli_error ("no finding %s in this scan of the %s (%u events)",
		              want, source, events);
	else
		fs_cli_error ("%s names %u findings; give more of the ID", want,
		              matches);
	if (matches == 0)
		fs_cli_hint ("`stockfw copilot scan%s' lists them", o->history
		             ? " --history" : "");
	*rc = FS_EXIT_FAILURE;
	return NULL;
}

/* [ copilot_show ] -- G6: the finding's drawer. */
static gint
copilot_show (const ScanOpts *o, const gchar *want)
{
	FsCopilot *copilot = NULL;
	FsPolicy *policy = NULL;
	gint rc = FS_EXIT_OK;
	const FsInsight *ins = scan_find (o, want, &copilot, &policy, &rc);
	gchar *id, *words;

	if (ins == NULL) {
		fs_copilot_free (copilot);
		fs_policy_free (policy);
		return rc;
	}
	if (fs_cli.json) {
		GString *out = g_string_new (NULL);

		insight_json (out, ins, TRUE);
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
		goto out;
	}

	id = insight_id (ins);
	words = sentinel_words (ins);
	say (fs_cli_bold (), fs_cli_reset (), "%s  [%s] %s", id,
	     severity_word (ins->severity), fs_insight_type_name (ins->type));
	say_wrapped ("", ins->title);
	printf ("\n");
	if (ins->application != NULL)
		say_wrapped ("Program:", ins->application);
	if (ins->subject != NULL)
		say_wrapped ("About:", ins->subject);
	if (ins->description != NULL)
		say_wrapped ("In full:", ins->description);
	if (ins->why != NULL)
		say_wrapped ("Why:", ins->why);
	if (ins->benign != NULL)
		say_wrapped ("Harmless?", ins->benign);
	say_wrapped ("Sentinel:", words);

	if (ins->evidence != NULL && ins->evidence->len > 0) {
		static const gchar *headers[] = { "TIME", "DIR", "REMOTE", "PORT",
		                                  "PROTO", "RESULT", "RULE" };
		GPtrArray *table = g_ptr_array_new_with_free_func (
			(GDestroyNotify) g_strfreev);

		printf ("\nWhat was seen (%u event%s, the last %u):\n", ins->count,
		        ins->count == 1 ? "" : "s", ins->evidence->len);
		for (guint i = 0; i < ins->evidence->len; i++) {
			const FsEvidence *ev = g_ptr_array_index (ins->evidence, i);
			gchar **row = g_new0 (gchar *, 8);

			row[0] = fs_cli_time_text (ev->when, FS_CLI_TIME_SHORT);
			row[1] = g_strdup (ev->inbound ? "in" : "out");
			row[2] = g_strdup (ev->remote != NULL ? ev->remote : "");
			row[3] = ev->port > 0 ? g_strdup_printf ("%u", ev->port)
			                      : g_strdup ("-");
			row[4] = g_strdup (ev->protocol != NULL ? ev->protocol : "");
			row[5] = g_strdup (ev->blocked ? "blocked" : "allowed");
			row[6] = g_strdup (ev->rule != NULL ? ev->rule : "");
			g_ptr_array_add (table, row);
		}
		fs_cli_table_ex (headers, 7, table, 0, 6);
		g_ptr_array_unref (table);
	}

	printf ("\n");
	if (ins->rule_csv != NULL &&
	    ins->rule_kind == FS_RULE_OUTBOUND_DENY_TO) {
		say ("", "", "Block rule:  %s: %s",
		     fs_cli_kind_name (ins->rule_kind), ins->rule_csv);
		say ("", "", "  add it:    stockfw copilot block %s", id);
	}
	if (ins->whatif_line != NULL) {
		gchar *cmd = cmd_line ("simulate", ins->whatif_line);

		say ("", "", "Ask What-If: %s", cmd);
		g_free (cmd);
	}
	if (ins->destination != NULL || ins->subject != NULL) {
		const gchar *addr = ins->destination != NULL ? ins->destination
		                                             : ins->subject;
		gchar *cmd = cmd_line (o->history ? "events --history --addr"
		                                  : "events --addr", addr);

		/* --addr takes one address; a subject that is not one (a
		 * program, a /64) gets the text filter instead. */
		if (strchr (addr, '/') != NULL || strchr (addr, ' ') != NULL) {
			g_free (cmd);
			cmd = cmd_line (o->history ? "events --history --grep"
			                           : "events --grep", addr);
		}
		say ("", "", "In Events:   %s", cmd);
		g_free (cmd);
	}
	g_free (words);
	g_free (id);
out:
	fs_copilot_free (copilot);
	fs_policy_free (policy);
	return FS_EXIT_OK;
}

/* [ copilot_block ] -- G7: "Block outbound to this address", checked
 * by What-If, confirmed, saved, put live with add_live, logged. */
static gint
copilot_block (const ScanOpts *o, const gchar *want, gboolean yes)
{
	FsCopilot *copilot = NULL;
	FsPolicy *policy = NULL;
	gint rc = FS_EXIT_OK;
	const FsInsight *ins;
	FsControlActor actor = fs_control_actor_self ("cli");
	FsControlResult *r = NULL;
	gchar *question;

	if (geteuid () != 0)
		return fs_cli_need_root ("copilot block");
	ins = scan_find (o, want, &copilot, &policy, &rc);
	if (ins == NULL)
		goto out;
	if (ins->rule_csv == NULL ||
	    ins->rule_kind != FS_RULE_OUTBOUND_DENY_TO ||
	    ins->whatif_line == NULL) {
		fs_cli_error ("this finding has no block rule to offer");
		rc = FS_EXIT_FAILURE;
		goto out;
	}
	if (!fs_cli.json) {
		/* As copilot.block saves it: the user's rule, not Sentinel's. */
		const gchar *at = strstr (ins->rule_csv, ", Sentinel:");
		gchar *shown = at != NULL
		               ? g_strdup_printf ("%.*s, Copilot:%s",
		                                  (gint) (at - ins->rule_csv),
		                                  ins->rule_csv,
		                                  at + strlen (", Sentinel:"))
		               : g_strdup (ins->rule_csv);

		say ("", "", "Rule:     %s: %s", fs_cli_kind_name (ins->rule_kind),
		     shown);
		g_free (shown);
		say ("", "", "What-If:  \"%s\" is checked before it is saved: it "
		     "must be ALLOWED now and BLOCKED with the rule.",
		     ins->whatif_line);
	}
	question = g_strdup ("Add this block rule, save it and put it live?");
	if (!ask (question, "add the block rule", yes)) {
		g_free (question);
		rc = FS_EXIT_FAILURE;
		goto out;
	}
	g_free (question);
	window_warning ();

	for (gint round = 0; round < 2; round++) {
		GVariantBuilder b;

		g_variant_builder_init (&b, G_VARIANT_TYPE_VARDICT);
		g_variant_builder_add (&b, "{sv}", "kind", g_variant_new_string (
			fs_cli_kind_name (ins->rule_kind)));
		g_variant_builder_add (&b, "{sv}", "csv",
		                       g_variant_new_string (ins->rule_csv));
		g_variant_builder_add (&b, "{sv}", "whatif",
		                       g_variant_new_string (ins->whatif_line));
		g_variant_builder_add (&b, "{sv}", "yes",
		                       g_variant_new_boolean (yes || round > 0));
		fs_control_result_free (r);
		r = fs_control_do (&actor, "copilot.block",
		                   g_variant_builder_end (&b));
		if (r->status != FS_CONTROL_CONFIRM || round > 0)
			break;
		/* The lockout guard: this block would cut an SSH session. */
		{
			const gchar *peer = r->lockout != NULL && r->lockout->worst
			                    ? r->lockout->worst->peer : "?";

			say ("", "", "This block would cut the SSH session from %s.",
			     peer);
		}
		if (yes || !ask ("Block anyway?", "block anyway", FALSE))
			break;
	}
	rc = op_exit (r);
	if (r->status == FS_CONTROL_OK && !fs_cli.json && !fs_cli.quiet) {
		gchar *ref = fs_cli_rule_ref (r->rule->kind, r->number);

		say ("", "", "Block rule added as %s.", ref);
		g_free (ref);
		live_words (r->outcome, "Nothing was applied before, so the rule "
		            "goes live with the next `stockfw apply'.");
		if (r->change_id > 0)
			printf ("Undo it: stockfw copilot changes --undo %u\n",
			        r->change_id);
	}
	if (r->status == FS_CONTROL_OK && r->change_error != NULL)
		fs_cli_error ("the rule is added, but the change log could not be "
		              "written: %s", r->change_error);
out:
	fs_control_result_free (r);
	fs_copilot_free (copilot);
	fs_policy_free (policy);
	return rc;
}

/* [ copilot_checks ] -- "What is checked", from the engine's own
 * constants (fs_copilot_checks). */
static gint
copilot_checks (void)
{
	gchar **checks = fs_copilot_checks ();

	if (fs_cli.json) {
		GString *out = g_string_new ("{\"checks\":[");

		for (guint i = 0; checks[i] != NULL; i++) {
			if (i > 0)
				g_string_append_c (out, ',');
			fs_json_string (out, checks[i]);
		}
		g_string_append (out, "]}");
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		if (!fs_cli.quiet && !fs_cli.plain)
			printf ("%sWhat the Copilot checks%s\n", fs_cli_bold (),
			        fs_cli_reset ());
		for (guint i = 0; checks[i] != NULL; i++) {
			gchar *line = g_strdup_printf ("- %s", checks[i]);
			gchar *w = fs_cli_wrap (line, 2);

			printf ("%s\n", w);
			g_free (w);
			g_free (line);
		}
		if (!fs_cli.quiet && !fs_cli.plain)
			printf ("%sFixed rules with these numbers, not a model: the "
			        "same events always give the same findings.%s\n",
			        fs_cli_dim (), fs_cli_reset ());
	}
	g_strfreev (checks);
	return FS_EXIT_OK;
}

/* ------------------------------------------------------------ changes */

/* [ copilot_changes ] -- G13: "Changes made by the Copilot", from the
 * change log; with --undo ID, one of them put back. */
static gint
copilot_changes (guint undo)
{
	GPtrArray *all;
	guint bad = 0;
	GError *error = NULL;
	gchar *path = fs_changelog_path ();
	gint rc = FS_EXIT_OK;

	if (undo > 0) {
		FsChange *c = fs_changelog_find (undo, NULL);
		FsControlActor actor = fs_control_actor_self ("cli");
		FsControlResult *r;
		GVariantBuilder b;

		if (c != NULL && c->kind == FS_CHANGE_BLOCK_RULE &&
		    geteuid () != 0) {
			fs_change_free (c);
			g_free (path);
			return fs_cli_need_root ("copilot changes --undo");
		}
		fs_change_free (c);
		window_warning ();
		g_variant_builder_init (&b, G_VARIANT_TYPE_VARDICT);
		g_variant_builder_add (&b, "{sv}", "id", g_variant_new_uint32 (undo));
		r = fs_control_do (&actor, "copilot.undo",
		                   g_variant_builder_end (&b));
		rc = op_exit (r);
		if (r->status == FS_CONTROL_OK && !fs_cli.json && !fs_cli.quiet) {
			say ("", "", "Undone: %s.", r->fix_label);
			if (g_strcmp0 (r->change_kind, "health-fix") == 0)
				printf ("The policy is saved; `stockfw apply' puts it "
				        "live.\n");
			else
				live_words (r->outcome, "The rule was not live, so the "
				            "firewall was not changed.");
		}
		if (r->status == FS_CONTROL_OK && r->change_error != NULL)
			fs_cli_error ("undone, but the change log could not be "
			              "written: %s", r->change_error);
		fs_control_result_free (r);
		g_free (path);
		return rc;
	}

	all = fs_changelog_read (&bad, &error);
	if (all == NULL) {
		fs_cli_error ("%s", error->message);
		g_error_free (error);
		g_free (path);
		return FS_EXIT_FAILURE;
	}
	if (bad > 0) {
		gchar *safe = fs_cli_out_safe (path);

		fprintf (stderr, "stockfw: %u damaged line%s in %s skipped\n", bad,
		         bad == 1 ? "" : "s", safe);
		g_free (safe);
	}

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "file", path);
		g_string_append (out, ",\"changes\":[");
		for (guint i = 0; i < all->len; i++) {
			const FsChange *c = g_ptr_array_index (all, i);

			if (i > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_uint (out, "id", c->id);
			g_string_append_c (out, ',');
			fs_json_kv_time (out, "at", c->at);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "type", fs_change_kind_name (c->kind));
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "label", c->label);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "kind", fs_cli_kind_name (c->rule_kind));
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "source", c->source);
			g_string_append_c (out, ',');
			if (c->kind == FS_CHANGE_BLOCK_RULE) {
				fs_json_kv_str (out, "csv", c->csv);
			} else {
				fs_json_kv_str (out, "before", c->undo->before_csv);
				g_string_append_c (out, ',');
				fs_json_kv_str (out, "after", c->undo->after_csv);
			}
			g_string_append_c (out, ',');
			fs_json_kv_bool (out, "undone", c->undone_at != 0);
			if (c->undone_at != 0) {
				GDateTime *u = g_date_time_new_from_unix_utc (
					c->undone_at);
				gchar *iso = u != NULL ? g_date_time_format (
					u, "%Y-%m-%dT%H:%M:%SZ") : NULL;

				/* One "epoch" per object: the change's own. */
				g_string_append_c (out, ',');
				fs_json_kv_str (out, "undone_at", iso);
				g_string_append_c (out, ',');
				fs_json_kv_int (out, "undone_epoch", c->undone_at);
				g_free (iso);
				if (u != NULL)
					g_date_time_unref (u);
			}
			g_string_append_c (out, '}');
		}
		g_string_append (out, "]}");
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (all->len == 0) {
		if (!fs_cli.quiet)
			printf ("No changes made by the Copilot.\n");
	} else {
		static const gchar *headers[] = { "ID", "WHEN", "CHANGE", "STATE" };
		GPtrArray *table = g_ptr_array_new_with_free_func (
			(GDestroyNotify) g_strfreev);

		for (guint i = 0; i < all->len; i++) {
			const FsChange *c = g_ptr_array_index (all, i);
			gchar **row = g_new0 (gchar *, 5);

			row[0] = g_strdup_printf ("%u", c->id);
			row[1] = fs_cli_time_text (c->at, FS_CLI_TIME_SHORT);
			row[2] = g_strdup (c->label != NULL ? c->label : "");
			if (c->undone_at != 0) {
				gchar *t = fs_cli_time_text (c->undone_at,
				                             FS_CLI_TIME_SHORT);

				row[3] = g_strdup_printf ("undone %s", t);
				g_free (t);
			} else {
				row[3] = g_strdup ("in force");
			}
			g_ptr_array_add (table, row);
		}
		fs_cli_table_ex (headers, 4, table, 0, 2);
		g_ptr_array_unref (table);
		if (!fs_cli.quiet && !fs_cli.plain)
			fprintf (stderr, "%sUndo one with `stockfw copilot changes "
			         "--undo ID'.  Sentinel's own blocks are in `stockfw "
			         "sentinel'.%s\n", fs_cli_dim (), fs_cli_reset ());
	}
	g_ptr_array_unref (all);
	g_free (path);
	return rc;
}

/* ------------------------------------------------------------ parsing */

static gboolean
parse_number (const gchar *opt, const gchar *v, guint *out)
{
	gchar *end = NULL;
	guint64 n;

	if (v == NULL || !g_ascii_isdigit (*v))
		goto bad;
	n = g_ascii_strtoull (v, &end, 10);
	if (end == NULL || *end != '\0' || n == 0 || n > G_MAXUINT32)
		goto bad;
	*out = (guint) n;
	return TRUE;
bad:
	fs_cli_error ("%s takes a number from 1, not `%s'", opt,
	              v != NULL ? v : "");
	return FALSE;
}

static const gchar *const copilot_subs[] = {
	"health", "scan", "show", "block", "checks", "changes"
};

/* [ fs_cli_cmd_copilot ] */
gint
fs_cli_cmd_copilot (gint argc, gchar **argv)
{
	static const gchar * const levels[] = { "info", "warning", "critical" };
	FsCopilotSeverity threshold = FS_COPILOT_INFO;
	ScanOpts scan = { NULL, FALSE };
	const gchar *sub = argc > 1 ? argv[1] : NULL;
	const gchar *id = NULL;
	gboolean yes = FALSE;
	guint fix = 0, undo = 0;
	guint k;

	for (k = 0; sub != NULL && k < G_N_ELEMENTS (copilot_subs); k++)
		if (strcmp (sub, copilot_subs[k]) == 0)
			break;
	if (sub == NULL || fs_cli_is_option_at (argv, 1) ||
	    k == G_N_ELEMENTS (copilot_subs)) {
		const gchar *best = sub != NULL
			? fs_cli_suggest (sub, copilot_subs,
			                  G_N_ELEMENTS (copilot_subs)) : NULL;

		if (sub == NULL || fs_cli_is_option_at (argv, 1))
			fs_cli_error ("copilot needs a subcommand");
		else
			fs_cli_error ("unknown copilot subcommand: %s", sub);
		if (best != NULL)
			fs_cli_hint ("did you mean `copilot %s'?", best);
		else
			fs_cli_hint ("stockfw copilot health|scan|show|block|checks|"
			             "changes; `stockfw help copilot'");
		return FS_EXIT_USAGE;
	}

	for (gint i = 2; i < argc; i++) {
		const gchar *v;
		gint status = FS_EXIT_OK;

		if (strcmp (sub, "health") == 0 &&
		    fs_cli_take_opt (argc, argv, &i, "--severity", &v, &status)) {
			if (v == NULL)
				return status;
			for (k = 0; k < G_N_ELEMENTS (levels); k++)
				if (g_ascii_strcasecmp (v, levels[k]) == 0)
					break;
			if (k == G_N_ELEMENTS (levels)) {
				const gchar *best = fs_cli_suggest (v, levels, 3);

				if (best != NULL)
					fs_cli_error ("unknown severity: %s (did you mean "
					              "%s?)", v, best);
				else
					fs_cli_error ("unknown severity: %s", v);
				fs_cli_hint ("--severity info|warning|critical");
				return FS_EXIT_USAGE;
			}
			threshold = k == 0 ? FS_COPILOT_INFO
			          : k == 1 ? FS_COPILOT_WARNING
			                   : FS_COPILOT_CRITICAL;
		} else if (strcmp (sub, "health") == 0 &&
		           fs_cli_take_opt (argc, argv, &i, "--fix", &v, &status)) {
			if (v == NULL)
				return status;
			if (!parse_number ("--fix", v, &fix))
				return FS_EXIT_USAGE;
		} else if (strcmp (sub, "changes") == 0 &&
		           fs_cli_take_opt (argc, argv, &i, "--undo", &v, &status)) {
			if (v == NULL)
				return status;
			if (!parse_number ("--undo", v, &undo))
				return FS_EXIT_USAGE;
		} else if ((strcmp (sub, "scan") == 0 || strcmp (sub, "show") == 0 ||
		            strcmp (sub, "block") == 0) &&
		           fs_cli_take_opt (argc, argv, &i, "--since", &v, &status)) {
			if (v == NULL)
				return status;
			scan.since = v;
		} else if ((strcmp (sub, "scan") == 0 || strcmp (sub, "show") == 0 ||
		            strcmp (sub, "block") == 0) &&
		           !fs_cli_is_positional (i) &&
		           strcmp (argv[i], "--history") == 0) {
			scan.history = TRUE;
		} else if ((strcmp (sub, "health") == 0 ||
		            strcmp (sub, "block") == 0) &&
		           !fs_cli_is_positional (i) &&
		           (strcmp (argv[i], "--yes") == 0 ||
		            strcmp (argv[i], "-y") == 0)) {
			yes = TRUE;
		} else if (fs_cli_is_option_at (argv, i)) {
			fs_cli_unknown_option ("copilot", argv[i]);
			return FS_EXIT_USAGE;
		} else if ((strcmp (sub, "show") == 0 ||
		            strcmp (sub, "block") == 0) && id == NULL) {
			id = argv[i];
		} else {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			fs_cli_hint ("`stockfw help copilot'");
			return FS_EXIT_USAGE;
		}
	}

	if (strcmp (sub, "health") == 0) {
		if (yes && fix == 0) {
			fs_cli_error ("--yes goes with --fix");
			return FS_EXIT_USAGE;
		}
		return copilot_health (threshold, fix, yes);
	}
	if (strcmp (sub, "scan") == 0)
		return copilot_scan (&scan);
	if (strcmp (sub, "checks") == 0)
		return copilot_checks ();
	if (strcmp (sub, "changes") == 0)
		return copilot_changes (undo);
	if (id == NULL) {
		fs_cli_error ("copilot %s needs a finding's ID", sub);
		fs_cli_hint ("`stockfw copilot scan' lists them");
		return FS_EXIT_USAGE;
	}
	if (strcmp (sub, "show") == 0)
		return copilot_show (&scan, id);
	return copilot_block (&scan, id, yes);
}

/* ----------------------------------------------------------- sentinel */

/* [ lift_print ] -- what a lift did. */
static void
lift_print (const FsControlResult *r, const gchar *what)
{
	const FsAutoblockLift *l = r->lift;
	GString *targets = g_string_new (NULL);

	if (l == NULL || fs_cli.quiet)
		return;
	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		for (guint i = 0; i < l->lifted->kinds[k]->len; i++) {
			const FsRule *rule = g_ptr_array_index (l->lifted->kinds[k], i);

			g_string_append_printf (targets, "%s%s",
			                        targets->len > 0 ? ", " : "",
			                        rule->target != NULL ? rule->target
			                        : rule->service != NULL
			                        ? rule->service : "?");
		}
	if (l->rows == 0 && l->removed == 0) {
		say ("", "", "Nothing to lift: %s.", what);
	} else {
		say ("", "", "Lifted %u Sentinel block%s: %s.", l->rows,
		     l->rows == 1 ? "" : "s",
		     targets->len > 0 ? targets->str : "(none in the policy)");
		live_words (l->outcome, "None of them was live, so the firewall "
		            "was not changed.");
		if (l->kept > 0)
			printf ("%u block%s still live %s kept in Sentinel's file, "
			        "due now: the next `stockfw sentinel lift --expired' "
			        "or start takes %s off.\n", l->kept,
			        l->kept == 1 ? "" : "s",
			        l->kept == 1 ? "is" : "are",
			        l->kept == 1 ? "it" : "them");
	}
	g_string_free (targets, TRUE);
}

static gint
sentinel_lift (gint argc, gchar **argv)
{
	const gchar *target = NULL;
	gboolean all = FALSE, expired = FALSE;
	FsControlActor actor = fs_control_actor_self ("cli");
	FsControlResult *r;
	GVariantBuilder b;
	gchar *what;
	gint rc;

	for (gint i = 2; i < argc; i++) {
		if (!fs_cli_is_positional (i) && strcmp (argv[i], "--all") == 0)
			all = TRUE;
		else if (!fs_cli_is_positional (i) &&
		         strcmp (argv[i], "--expired") == 0)
			expired = TRUE;
		else if (fs_cli_is_option_at (argv, i)) {
			fs_cli_unknown_option ("sentinel", argv[i]);
			return FS_EXIT_USAGE;
		} else if (target == NULL)
			target = argv[i];
		else {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			return FS_EXIT_USAGE;
		}
	}
	if ((target != NULL) + all + expired != 1) {
		fs_cli_error ("sentinel lift takes one of: an address, --all or "
		              "--expired");
		fs_cli_hint ("stockfw sentinel lift 203.0.113.9 | --all | "
		             "--expired; `stockfw sentinel' lists the blocks");
		return FS_EXIT_USAGE;
	}
	if (target != NULL && *target == '\0') {
		fs_cli_error ("sentinel lift needs an address");
		return FS_EXIT_USAGE;
	}
	if (geteuid () != 0)
		return fs_cli_need_root ("sentinel lift");
	window_warning ();

	g_variant_builder_init (&b, G_VARIANT_TYPE_VARDICT);
	if (target != NULL)
		g_variant_builder_add (&b, "{sv}", "target",
		                       g_variant_new_string (target));
	g_variant_builder_add (&b, "{sv}", "all", g_variant_new_boolean (all));
	g_variant_builder_add (&b, "{sv}", "expired",
	                       g_variant_new_boolean (expired));
	r = fs_control_do (&actor, "sentinel.lift", g_variant_builder_end (&b));
	rc = op_exit (r);
	what = target != NULL
	       ? g_strdup_printf ("no Sentinel block for %s", target)
	       : g_strdup (all ? "Sentinel has no block staged"
	                       : "no Sentinel block has run out");
	if (!fs_cli.json && r->lift != NULL)
		lift_print (r, what);
	g_free (what);
	fs_control_result_free (r);
	return rc;
}

static gint
sentinel_mode (gint argc, gchar **argv)
{
	FsControlActor actor = fs_control_actor_self ("cli");
	FsControlResult *r;
	GVariantBuilder b;
	const gchar *want = NULL;
	gint rc;

	for (gint i = 2; i < argc; i++) {
		if (fs_cli_is_option_at (argv, i)) {
			fs_cli_unknown_option ("sentinel", argv[i]);
			return FS_EXIT_USAGE;
		}
		if (want != NULL) {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			return FS_EXIT_USAGE;
		}
		want = argv[i];
	}
	if (want == NULL) {
		gchar *mode;

		fs_prefs_load ();
		mode = fs_prefs_get_string (FS_PREFS_SENTINEL_MODE, "auto");
		if (mode == NULL || *mode == '\0') {
			g_free (mode);
			mode = g_strdup ("auto");
		}
		if (fs_cli.json) {
			GString *out = g_string_new ("{");

			fs_json_kv_str (out, "mode", mode);
			g_string_append_c (out, '}');
			fs_cli_print_json (out);
			g_string_free (out, TRUE);
		} else {
			say ("", "", "%s", mode);
		}
		g_free (mode);
		return FS_EXIT_OK;
	}
	if (strcmp (want, "auto") != 0 && strcmp (want, "detect") != 0) {
		fs_cli_error ("sentinel mode takes auto or detect, not `%s'", want);
		return FS_EXIT_USAGE;
	}
	if (geteuid () != 0)
		return fs_cli_need_root ("sentinel mode");
	window_warning ();
	g_variant_builder_init (&b, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&b, "{sv}", "mode", g_variant_new_string (want));
	r = fs_control_do (&actor, "sentinel.mode", g_variant_builder_end (&b));
	rc = op_exit (r);
	if (!fs_cli.json && !fs_cli.quiet && r->mode != NULL) {
		say ("", "", "Sentinel mode: %s (was %s).", r->mode, r->mode_was);
		if (strcmp (r->mode, "detect") == 0)
			printf ("Sentinel reports findings and blocks nothing by "
			        "itself.\n");
		else
			printf ("Sentinel may block an outbound contact for %d "
			        "minutes; it runs while the desktop app runs.\n",
			        FS_AUTOBLOCK_TTL_S / 60);
	}
	if (!fs_cli.json && r->lift != NULL)
		lift_print (r, "Sentinel had no block staged");
	fs_control_result_free (r);
	return rc;
}

static const gchar *const sentinel_subs[] = { "list", "lift", "mode" };

/* [ fs_cli_cmd_sentinel ] */
static gint
fs_cli_cmd_sentinel (gint argc, gchar **argv)
{
	const gchar *sub = argc > 1 && !fs_cli_is_option_at (argv, 1)
	                   ? argv[1] : NULL;

	if (sub == NULL || strcmp (sub, "list") == 0)
		return fs_cli_sentinel_list (argc, argv);
	if (strcmp (sub, "lift") == 0)
		return sentinel_lift (argc, argv);
	if (strcmp (sub, "mode") == 0)
		return sentinel_mode (argc, argv);
	{
		const gchar *best = fs_cli_suggest (sub, sentinel_subs,
		                                    G_N_ELEMENTS (sentinel_subs));

		fs_cli_error ("unknown sentinel subcommand: %s", sub);
		if (best != NULL)
			fs_cli_hint ("did you mean `sentinel %s'?", best);
		else
			fs_cli_hint ("stockfw sentinel list|lift|mode");
	}
	return FS_EXIT_USAGE;
}

/* ------------------------------------------------------- the commands */

static const FsCliOption copilot_opts[] = {
	{ "--severity", TRUE,  "health" },
	{ "--fix",      TRUE,  "health" },
	{ "--yes",      FALSE, "health" },
	{ "-y",         FALSE, "health" },
	{ "--since",    TRUE,  "scan" },
	{ "--history",  FALSE, "scan" },
	{ "--since",    TRUE,  "show" },
	{ "--history",  FALSE, "show" },
	{ "--since",    TRUE,  "block" },
	{ "--history",  FALSE, "block" },
	{ "--yes",      FALSE, "block" },
	{ "-y",         FALSE, "block" },
	{ "--undo",     TRUE,  "changes" },
	{ NULL, FALSE, NULL }
};

static const FsCliOption sentinel_opts[] = {
	{ "--all",     FALSE, "lift" },
	{ "--expired", FALSE, "lift" },
	{ NULL, FALSE, NULL }
};

/* === end PR4-B === */

const FsCliCommandDef fs_cli_copilot_commands[] = {
	/* === PR4-B === */
	{ "copilot", fs_cli_cmd_copilot,
"Usage: stockfw copilot health [--severity info|warning|critical]\n"
"                              [--fix N [--yes]]\n"
"       stockfw copilot scan [--since T] [--history]\n"
"       stockfw copilot show ID [--since T] [--history]\n"
"       stockfw copilot block ID [--yes] [--since T] [--history]\n"
"       stockfw copilot checks\n"
"       stockfw copilot changes [--undo ID]\n"
"\n"
"The Copilot page in a terminal.  These are fixed rules, not a model.\n"
"\n"
"  health   the policy health check on the saved policy: rules that\n"
"           repeat another, rules another rule already covers, allows\n"
"           a deny makes unreachable, outbound allows that do nothing\n"
"           while outbound traffic is allowed, wide or risky inbound\n"
"           allows from anyone, and deny rules that reach no address\n"
"           family.  Each fix is shown with the What-If checks that\n"
"           verify it; one that does not verify is not offered.  Each\n"
"           finding has a ready `stockfw simulate' line.  It writes\n"
"           nothing, unless --fix N is given: finding N's fix is shown,\n"
"           confirmed, checked again and saved (not applied: run\n"
"           `stockfw apply'), and logged in `copilot changes'.\n"
"  scan     the findings of the events on record: the kernel log (root,\n"
"           or a reader of it), or with --history the history the\n"
"           desktop app saved.  --since T starts there (24h, 2026-11-03).\n"
"           A replay into a fresh Copilot with the saved policy, without\n"
"           the desktop app's learned baseline, so the findings that need\n"
"           one (new port, new destination, new hour, rate) are rare.\n"
"           Each finding has an ID: the same events give the same ID.\n"
"  show     one finding in full: what was seen, why it was flagged, why\n"
"           it could be harmless, what Sentinel did, the block rule, and\n"
"           ready `stockfw simulate' and `stockfw events' lines\n"
"  block    adds the finding's outbound block rule, after What-If says\n"
"           the traffic is ALLOWED now and BLOCKED with it; saves it and\n"
"           puts only that rule live (root).  Saved changes nobody\n"
"           applied stay off the firewall.  On a stopped firewall it is\n"
"           recorded for the next start\n"
"  checks   what the checks look for, with the engine's own numbers\n"
"  changes  the changes made by `copilot block' and `copilot health\n"
"           --fix', kept in a file (STOCKFW_CHANGELOG_FILE); --undo ID\n"
"           puts one back (a block is also lifted from the firewall)\n"
"\n"
"A change asks on a terminal; with no terminal on stdin it is refused\n"
"unless --yes is given.  Undo does not ask.\n"
"\n"
"Exits: health and scan 0 with no findings, 7 with findings (health: at\n"
"or above --severity, info by default); 2 when the policy cannot be\n"
"read in full.  In --json, rule.index counts from 0, rule.rule_ref is\n"
"the KIND:N reference and number is what --fix takes.\n",
	  copilot_opts, NULL },

	{ "sentinel", fs_cli_cmd_sentinel,
"Usage: stockfw sentinel [list] [--json]\n"
"       stockfw sentinel lift TARGET | --all | --expired\n"
"       stockfw sentinel mode [auto|detect]\n"
"\n"
"  list   Sentinel's staged blocks, read from its state file: the\n"
"         address, the rule (as KIND:N in `policy list'), when it was\n"
"         staged, when it lifts (ten minutes later) and why.  The header\n"
"         gives Sentinel's mode.\n"
"  lift   takes Sentinel's blocks down now: those for one address\n"
"         (also the ones it wrote in an earlier session; your own rules\n"
"         are never touched), --all of them, or the --expired ones (ten\n"
"         minutes are up).  Each comes out of the state file and the\n"
"         policy, and off the firewall; the rest of what is live is not\n"
"         touched, and a stopped firewall is not started (root).\n"
"  mode   prints the mode; `auto' lets Sentinel block, `detect' only\n"
"         reports, and lifts every block now, as the Copilot page's\n"
"         switch does (root).\n"
"\n"
"A StockFW window running as root keeps its own list and policy and\n"
"may write them back: close it first.\n",
	  sentinel_opts, NULL },
	/* === end PR4-B === */
	{ NULL, NULL, NULL, NULL, NULL }
};
