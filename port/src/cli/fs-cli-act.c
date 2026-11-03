/*---[ fs-cli-act.c ]----------------------------------------------------
 * `stockfw events act' and `stockfw simulate --do' (master plan PR 4,
 * package 4C): the Events page's row menu and the What-If window's fix
 * buttons, in a terminal.
 *
 * Each action shows what it will do before it does it: the event or
 * the fix, the exact rule, and what goes live.  It then asks [y/N] when
 * stdin is a terminal; without one it needs --yes and never waits for
 * input.  Writes go through the control layer (fs_control_do, under the
 * policy lock):
 *
 *   - a block (block-dest, block-service, a What-If block) is saved and
 *     put live alone with fs_firewall_add_live: the last applied policy
 *     plus the row, so a saved change nobody applied stays off;
 *   - an allow (allow-dest, trust-source, a What-If allow) widens what
 *     gets through, so the whole apply of the saved policy is shown
 *     first, then the row is saved and the saved policy applied, as
 *     `stockfw apply' does; allow-dest lifts Sentinel's blocks of the
 *     address first (fs_autoblock_lift_for_dest);
 *   - untrust-source removes the row and takes it off alone
 *     (fs_firewall_lift_live);
 *   - What-If "start" and "apply" are `stockfw start' and `stockfw
 *     apply': the start gate (fs_firewall_start_safe's family, with the
 *     hold, the audit line and the journal), never the backend's start.
 *
 * Everything from outside (log fields, rule fields, comments, the
 * engine's text that names them) is printed through fs_cli_out_safe.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "cli/fs-cli-act.h"
#include "control/fs-control.h"
#include "core/fs-apply.h"
#include "core/fs-autoblock.h"
#include "core/fs-eventrule.h"
#include "core/fs-json.h"
#include "core/fs-prefs.h"
#include "core/fs-util.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* What was printed to stdout goes out before an error on stderr, so a
 * pipe that takes both reads them in order. */
#define act_error(...) \
	G_STMT_START { fflush (stdout); fs_cli_error (__VA_ARGS__); } G_STMT_END

/* ------------------------------------------------------------ actions */

typedef enum
{
	ACT_BLOCK,     /* a deny row, live alone            */
	ACT_ALLOW,     /* an allow row, the saved policy applied */
	ACT_UNTRUST    /* an inbound allow removed, alone   */
} ActWay;

typedef struct
{
	const gchar       *name;
	ActWay             way;
	FsEventRuleAction  rule;     /* not for ACT_UNTRUST */
	gboolean           inbound;  /* the event's direction */
} EventAct;

static const EventAct event_acts[] = {
	{ "block-dest",     ACT_BLOCK,   FS_EVENTRULE_BLOCK_DEST,    FALSE },
	{ "block-service",  ACT_BLOCK,   FS_EVENTRULE_BLOCK_SERVICE, FALSE },
	{ "allow-dest",     ACT_ALLOW,   FS_EVENTRULE_ALLOW_DEST,    FALSE },
	{ "trust-source",   ACT_ALLOW,   FS_EVENTRULE_TRUST_SOURCE,  TRUE  },
	{ "untrust-source", ACT_UNTRUST, FS_EVENTRULE_TRUST_SOURCE,  TRUE  },
};

static const EventAct *
event_act (const gchar *name)
{
	for (guint i = 0; name != NULL && i < G_N_ELEMENTS (event_acts); i++)
		if (strcmp (event_acts[i].name, name) == 0)
			return &event_acts[i];
	return NULL;
}

gboolean
fs_cli_events_act_known (const gchar *action)
{
	return event_act (action) != NULL;
}

void
fs_cli_events_act_usage (const gchar *given)
{
	const gchar *names[G_N_ELEMENTS (event_acts)];
	const gchar *near;

	for (guint i = 0; i < G_N_ELEMENTS (event_acts); i++)
		names[i] = event_acts[i].name;
	if (given == NULL) {
		act_error ("events act needs an action");
	} else if ((near = fs_cli_suggest (given, names,
	                                   G_N_ELEMENTS (names))) != NULL) {
		act_error ("not an event action: %s (did you mean %s?)", given,
		              near);
	} else {
		act_error ("not an event action: %s", given);
	}
	fs_cli_hint ("block-dest, block-service, allow-dest, trust-source or "
	             "untrust-source: `stockfw events act block-dest --addr "
	             "203.0.113.9'");
}

/* ------------------------------------------------------------ helpers */

static gint
act_need_root (const gchar *what)
{
	fflush (stdout);
	return fs_cli_need_root (what);
}

/* [ warn ] -- "stockfw: warning: ...", even under -q, as in
 * fs-cli-policy.c. */
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

/* [ confirm ]
 * --yes goes on.  A terminal on stdin is asked "QUESTION [y/N]" (No by
 * default).  Without a terminal nothing is asked and nothing waited
 * for: refused, with --yes named.  TRUE to go on. */
static gboolean
confirm (const gchar *question, gboolean yes)
{
	gchar answer[16] = "";

	if (yes)
		return TRUE;
	fflush (stdout);
	if (!isatty (0)) {
		act_error ("refused: there is no terminal to ask on, and "
		              "nothing was changed");
		fs_cli_hint ("pass --yes to do it without a question");
		return FALSE;
	}
	g_printerr ("%s [y/N] ", question);
	fflush (stderr);
	if (fgets (answer, sizeof answer, stdin) != NULL &&
	    (g_ascii_strcasecmp (g_strstrip (answer), "y") == 0 ||
	     g_ascii_strcasecmp (answer, "yes") == 0))
		return TRUE;
	act_error ("not done: nothing was changed");
	return FALSE;
}

/* [ say ] -- one line of the action's own text, from outside text. */
static void G_GNUC_PRINTF (1, 2)
say (const gchar *format, ...)
{
	va_list args;
	gchar *text, *safe;

	if (fs_cli.quiet || fs_cli.json)
		return;
	va_start (args, format);
	text = g_strdup_vprintf (format, args);
	va_end (args);
	safe = fs_cli_out_safe_lines (text);
	printf ("%s\n", safe);
	g_free (safe);
	g_free (text);
}

/* [ say_lead ] -- say() after a coloured lead word ("Saved", "Live:"):
 * the colour stays outside the escaped text, or the terminal would
 * show its escape bytes as \x1b text. */
static void G_GNUC_PRINTF (3, 4)
say_lead (const gchar *colour, const gchar *lead, const gchar *format, ...)
{
	va_list args;
	gchar *text, *safe;

	if (fs_cli.quiet || fs_cli.json)
		return;
	va_start (args, format);
	text = g_strdup_vprintf (format, args);
	va_end (args);
	safe = fs_cli_out_safe_lines (text);
	printf ("%s%s%s %s\n", colour, lead, fs_cli_reset (), safe);
	g_free (safe);
	g_free (text);
}

/* "outbound-deny-to  203.0.113.9  (Blocked from event view)" */
static gchar *
rule_text (const FsRule *rule)
{
	gchar *summary = fs_cli_rule_summary (rule);
	gchar *text = g_strdup_printf ("%s  %s%s%s%s",
	                               fs_cli_kind_name (rule->kind), summary,
	                               rule->comment != NULL &&
	                               *rule->comment != '\0' ? "  (" : "",
	                               rule->comment != NULL ? rule->comment
	                                                     : "",
	                               rule->comment != NULL &&
	                               *rule->comment != '\0' ? ")" : "");

	g_free (summary);
	return text;
}

/* "203.0.113.9  (Blocked from event view)": after its KIND:N. */
static gchar *
rule_summary (const FsRule *rule)
{
	gchar *summary = fs_cli_rule_summary (rule);
	gchar *text = rule->comment != NULL && *rule->comment != '\0'
	              ? g_strdup_printf ("%s  (%s)", summary, rule->comment)
	              : g_strdup (summary);

	g_free (summary);
	return text;
}

/* The fields of a rule in the order `policy add' takes them. */
static GVariant *
rule_fields (const FsRule *rule)
{
	GVariantBuilder b;

	g_variant_builder_init (&b, G_VARIANT_TYPE ("as"));
	switch (rule->kind) {
	case FS_RULE_INBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_DENY_SERVICE:
		g_variant_builder_add (&b, "s", rule->service ? rule->service : "");
		g_variant_builder_add (&b, "s", rule->port ? rule->port : "");
		g_variant_builder_add (&b, "s", rule->target ? rule->target : "");
		break;
	default:
		g_variant_builder_add (&b, "s", rule->target ? rule->target : "");
		break;
	}
	return g_variant_builder_end (&b);
}

static gboolean
hit_inbound (const FsHit *hit)
{
	return hit->direction != NULL &&
	       (g_ascii_strcasecmp (hit->direction, "in") == 0 ||
	        g_ascii_strcasecmp (hit->direction, "inbound") == 0);
}

/* [ sentinel_blocks_of ]
 * How many of Sentinel's blocks lifting `dest' takes: the state file's
 * rows for it, and the policy's outbound-deny-to rows Sentinel wrote
 * for it ("Sentinel:" comment).  The rows to drop from `after' go
 * there too (nullable). */
static guint
sentinel_blocks_of (const FsPolicy *policy, const gchar *dest,
                    FsPolicy *after)
{
	gchar *path = fs_autoblock_state_path ();
	GPtrArray *rows = fs_cli_sentinel_read (path, NULL, NULL);
	GPtrArray *deny = policy->kinds[FS_RULE_OUTBOUND_DENY_TO];
	GHashTable *seen = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                          g_free, NULL);
	guint n = 0;

	for (guint i = 0; rows != NULL && i < rows->len; i++) {
		const FsCliSentinelBlock *b = g_ptr_array_index (rows, i);

		if (b->rule != NULL && b->rule->target != NULL &&
		    g_ascii_strcasecmp (b->rule->target, dest) == 0 &&
		    g_hash_table_add (seen, fs_rule_to_csv (b->rule))) {
			n++;
			if (after != NULL)
				fs_policy_remove (after, b->rule);
		}
	}
	for (guint i = 0; i < deny->len; i++) {
		FsRule *r = g_ptr_array_index (deny, i);

		if (r->target != NULL && g_ascii_strcasecmp (r->target, dest) == 0 &&
		    r->comment != NULL &&
		    g_str_has_prefix (r->comment, "Sentinel:") &&
		    g_hash_table_add (seen, fs_rule_to_csv (r))) {
			n++;
			if (after != NULL)
				fs_policy_remove (after, r);
		}
	}
	g_hash_table_unref (seen);
	if (rows != NULL)
		g_ptr_array_unref (rows);
	g_free (path);
	return n;
}

static gint
exit_for (FsControlStatus status)
{
	switch (status) {
	case FS_CONTROL_OK:        return FS_EXIT_OK;
	case FS_CONTROL_USAGE:     return FS_EXIT_USAGE;
	case FS_CONTROL_NEED_ROOT: return FS_EXIT_NEED_ROOT;
	default:                   return FS_EXIT_FAILURE;
	}
}

/* [ gui_warning ] -- a root window keeps its own copy of the policy
 * and of Sentinel's blocks and writes them back when it saves (15.5.1):
 * said before anything is written. */
static void
gui_warning (void)
{
	if (fs_cli_root_gui_running ())
		warn ("a StockFW window is running as root: it keeps its own copy "
		      "of the policy and of Sentinel's blocks and writes them "
		      "back when it saves, so this change may be undone. Close "
		      "it and open it again to see the change");
}

/* ------------------------------------------------------ the preview */

/* [ preview ]
 * What the action will do, before it is asked about.  rule/twin: the
 * rows to add (ACT_BLOCK, ACT_ALLOW) or the row to remove (ACT_UNTRUST).
 * lift_dest: Sentinel's blocks of it are lifted (allow-dest). */
static void
preview (ActWay way, const FsRule *rule, const FsRule *twin,
         const gchar *lift_dest, gboolean no_apply, GString *json)
{
	FsPolicy *saved = fs_cli_load_policy (NULL, NULL);
	FsPolicy *journal = fs_policy_new ();
	gboolean have = fs_apply_journal_load (journal, NULL);
	gboolean already = fs_policy_contains (saved, rule) &&
	                   (twin == NULL || fs_policy_contains (saved, twin));
	guint sentinel = lift_dest != NULL
	                 ? sentinel_blocks_of (saved, lift_dest, NULL) : 0;

	if (way == ACT_UNTRUST) {
		say ("It is removed from the policy%s.",
		     no_apply ? " (--no-apply: only saved)"
		     : have ? " and taken off the firewall alone: the last "
		              "applied policy less this rule"
		            : "; nothing was applied yet, so the firewall is not "
		              "touched");
		if (rule->target != NULL)
			say ("The default-deny inbound policy then blocks %s again.",
			     rule->target);
	} else if (already) {
		say ("It is in the policy already: nothing is added.");
	}

	if (way == ACT_BLOCK) {
		if (no_apply)
			say ("It is saved only (--no-apply): it goes live with the "
			     "next `stockfw apply'.");
		else if (!have)
			say ("It is saved.  Nothing was applied yet, so it goes live "
			     "with the next `stockfw apply' or `stockfw start'.");
		else if (fs_policy_contains (journal, rule) &&
		         (twin == NULL || fs_policy_contains (journal, twin)))
			say ("It is live already.");
		else
			say ("It is saved, then put live alone: the last applied "
			     "policy plus this rule.  Nothing else that is saved "
			     "and not applied goes live with it.");
	} else if (way == ACT_ALLOW) {
		if (no_apply) {
			say ("It is saved only (--no-apply): it goes live with the "
			     "next `stockfw apply'.");
			if (sentinel > 0)
				say ("Sentinel's block%s of %s stay%s: without "
				     "--no-apply %s lifted.", sentinel == 1 ? "" : "s",
				     lift_dest, sentinel == 1 ? "s" : "",
				     sentinel == 1 ? "it is" : "they are");
		} else {
			FsPolicy *after = fs_policy_new ();

			for (gint k = 0; k < FS_RULE_N_KINDS; k++)
				for (guint i = 0; i < saved->kinds[k]->len; i++)
					fs_policy_add (after,
					               g_ptr_array_index (saved->kinds[k], i));
			if (!fs_policy_contains (after, rule))
				fs_policy_add (after, (FsRule *) rule);
			if (twin != NULL && !fs_policy_contains (after, twin))
				fs_policy_add (after, (FsRule *) twin);
			if (lift_dest != NULL)
				sentinel_blocks_of (saved, lift_dest, after);
			if (sentinel > 0)
				say ("Sentinel's block%s of %s %s lifted first (%u).",
				     sentinel == 1 ? "" : "s", lift_dest,
				     sentinel == 1 ? "is" : "are", sentinel);
			say ("An allow widens what gets through, so the saved policy "
			     "is applied with it, all of it:");
			fs_cli_apply_preview (after, json);
			fs_policy_free (after);
		}
	}
	if (json != NULL) {
		g_string_append_c (json, ',');
		fs_json_kv_bool (json, "journal", have);
		g_string_append_c (json, ',');
		fs_json_kv_uint (json, "sentinel_blocks", sentinel);
	}
	fs_policy_free (journal);
	fs_policy_free (saved);
}

/* ------------------------------------------------------- the outcome */

/* [ report ] -- what the op did, in words.  Returns the exit status. */
static gint
report (ActWay way, const FsControlResult *r, gboolean no_apply)
{
	const FsApplyOutcome *o = r->outcome;
	gint status = exit_for (r->status);

	if (!r->saved && !r->already) {
		if (r->problems != NULL && r->problems->len > 0)
			fs_cli_print_problems (r->problems);
		act_error ("not done: %s", r->error != NULL ? r->error
		              : fs_control_status_name (r->status));
		if (r->hint != NULL)
			fs_cli_hint ("%s", r->hint);
		return status == FS_EXIT_OK ? FS_EXIT_FAILURE : status;
	}

	if (!fs_cli.quiet) {
		gchar *ref = r->rule != NULL
		             ? fs_cli_rule_ref (r->rule->kind,
		                                r->number > 0 ? r->number : 1)
		             : NULL;
		gchar *text = r->rule != NULL ? rule_summary (r->rule)
		                              : g_strdup ("?");

		if (way == ACT_UNTRUST)
			say ("Removed %s  %s", ref != NULL ? ref : "", text);
		else if (r->already)
			say ("Already in the policy, nothing was added: %s  %s",
			     ref != NULL ? ref : "", text);
		else
			say_lead (fs_cli_green (), "Saved", "%s  %s",
			          ref != NULL ? ref : "", text);
		if (r->twin != NULL && r->saved) {
			gchar *tref = fs_cli_rule_ref (r->twin->kind, r->twin_number);
			gchar *ttext = rule_summary (r->twin);

			say ("Saved %s  %s", tref, ttext);
			g_free (ttext);
			g_free (tref);
		}
		g_free (text);
		g_free (ref);
	}

	if (no_apply)
		return status;

	if (r->lift != NULL && !fs_cli.quiet) {
		const FsAutoblockLift *l = r->lift;

		if (l->rows > 0 || l->removed > 0)
			say ("Sentinel's blocks lifted: %u (%u out of the policy%s).",
			     l->rows + (l->removed > l->rows ? l->removed - l->rows
			                                      : 0),
			     l->removed,
			     l->kept > 0 ? "; some stay live until the next start, "
			                   "the lift was held or failed" : "");
	}
	if (r->lift_error != NULL)
		act_error ("Sentinel's block could not be lifted: %s",
		              r->lift_error);

	if (way == ACT_ALLOW) {
		if (o != NULL)
			fs_cli_apply_print (r);
		else if (r->error != NULL)
			act_error ("%s", r->error);
		return o != NULL && r->lift_error == NULL
		       ? fs_cli_apply_status (o) : status;
	}

	/* A block, or an untrust: the live edit. */
	if (o == NULL) {
		if (r->status != FS_CONTROL_OK)
			act_error ("not live: %s", r->error != NULL ? r->error : "?");
		else if (!r->journal)
			say ("Not live yet: nothing was applied before, so it goes "
			     "live with the next `stockfw apply' or `stockfw "
			     "start'.");
		else
			say (way == ACT_BLOCK ? "It was live already."
			                      : "It was not live.");
	} else if (o->held) {
		say_lead (fs_cli_amber (), "Held:", "%s.  The firewall was left "
		          "untouched; the change is saved.",
		          o->hold_reason != NULL ? o->hold_reason : "?");
	} else if (o->result == FS_APPLY_DRY_RUN &&
	           o->firewall_was == FS_FW_STOPPED) {
		say ("The firewall is stopped: the change is recorded for the "
		     "next start, and the firewall stays stopped.");
	} else if (o->result == FS_APPLY_OK) {
		gchar *desc = fs_policy_impact_describe (o->impact);

		say_lead (fs_cli_green (), "Live:", "only this change went out "
		          "(%s).", desc);
		g_free (desc);
		fs_cli_print_notes (o->notes);
	} else {
		act_error ("not live: %s", r->error != NULL ? r->error
		              : fs_util_apply_result_to_string ((int) o->result));
		if (o->rollback_attempted && o->rollback_verified)
			fs_cli_hint ("the firewall was restored to the last applied "
			             "policy, and that restore was verified");
	}
	return status;
}

/* [ send ]
 * The op, with the lockout guard in front of live work.  CONFIRM that
 * was not confirmed: nothing was changed, *status says why. */
static FsControlResult *
send (const gchar *op, GVariant *base, gboolean live, gboolean yes,
      GString *lock, gint *status)
{
	FsControlActor actor;
	GVariantDict d;

	fflush (stdout);
	if (live)
		return fs_cli_control_guarded (op, base, yes, "Apply", lock,
		                               status);
	actor = fs_control_actor_self ("cli");
	g_variant_dict_init (&d, base);
	return fs_control_do (&actor, op, g_variant_dict_end (&d));
}

/* [ run_lock ] -- the guard's "lockout" member in the reply.  An allow
 * that goes live has had its preview's "lockout" put at the top level
 * (fs_cli_apply_preview), so its own goes under "apply", as on success:
 * one object never carries the same key twice. */
static void
run_lock (GString *json, const GString *lock, gboolean nested)
{
	if (lock->len == 0)
		return;
	if (!nested) {
		g_string_append (json, lock->str);
		return;
	}
	g_string_append (json, ",\"apply\":{");
	g_string_append (json, lock->str + 1);   /* without its comma */
	g_string_append_c (json, '}');
}

/* [ run_rule ]
 * The rule op for `way', from the confirmation on.  Prints the
 * outcome (text, or one JSON object with `json_head' first); returns
 * the exit status. */
static gint
run_rule (ActWay way, const FsRule *rule, gboolean both, gboolean no_apply,
          gboolean yes, const gchar *lift_dest, const gchar *from,
          GString *json)
{
	GVariantDict d;
	GVariant *base;
	FsControlResult *r;
	GString *lock = g_string_new (NULL);
	gint status = FS_EXIT_OK;
	const gchar *op;

	g_variant_dict_init (&d, NULL);
	if (way == ACT_UNTRUST) {
		op = "rule.untrust";
		g_variant_dict_insert (&d, "target", "s",
		                       rule->target != NULL ? rule->target : "");
	} else {
		op = way == ACT_BLOCK ? "rule.block" : "rule.allow";
		g_variant_dict_insert (&d, "kind", "s",
		                       fs_cli_kind_name (rule->kind));
		g_variant_dict_insert_value (&d, "fields", rule_fields (rule));
		g_variant_dict_insert (&d, "comment", "s",
		                       rule->comment != NULL ? rule->comment : "");
		g_variant_dict_insert (&d, "both", "b", both);
		if (lift_dest != NULL)
			g_variant_dict_insert (&d, "lift_dest", "s", lift_dest);
	}
	g_variant_dict_insert (&d, "no_apply", "b", no_apply);
	g_variant_dict_insert (&d, "from", "s", from);
	if (strcmp (from, "whatif") == 0)
		g_variant_dict_insert (&d, "whatif", "b", TRUE);
	base = g_variant_ref_sink (g_variant_dict_end (&d));

	r = send (op, base, !no_apply, yes, lock, &status);
	g_variant_unref (base);

	if (r->status == FS_CONTROL_CONFIRM) {
		if (json != NULL) {
			g_string_append (json, ",\"done\":false,");
			fs_json_kv_str (json, "error", "refused: it would block an "
			                "SSH session (pass --yes)");
			run_lock (json, lock, way == ACT_ALLOW && !no_apply);
		} else {
			fs_cli_hint ("nothing was saved: the policy files are as they "
			             "were");
		}
		fs_control_result_free (r);
		g_string_free (lock, TRUE);
		return status != FS_EXIT_OK ? status : FS_EXIT_FAILURE;
	}

	if (json != NULL) {
		gchar *res = fs_control_result_json (r);

		status = exit_for (r->status);
		g_string_append_c (json, ',');
		fs_json_kv_bool (json, "done", r->saved || r->already);
		g_string_append (json, ",\"result\":");
		g_string_append (json, res);
		if (r->outcome != NULL && way == ACT_ALLOW) {
			g_string_append (json, ",\"apply\":{");
			fs_cli_apply_json_members (json, r, lock->str);
			g_string_append_c (json, '}');
			if (r->status == FS_CONTROL_OK)
				status = fs_cli_apply_status (r->outcome);
		} else {
			run_lock (json, lock, way == ACT_ALLOW && !no_apply);
		}
		g_free (res);
	} else {
		status = report (way, r, no_apply);
	}
	fs_control_result_free (r);
	g_string_free (lock, TRUE);
	return status;
}

/* ------------------------------------------------------- events act */

typedef struct
{
	const FsHit *hit;       /* borrowed from the events             */
	FsRule      *rule;      /* the row to add or remove             */
} Candidate;

static void
candidate_free (Candidate *c)
{
	fs_rule_free (c->rule);
	g_free (c);
}

static void
event_table (const FsHit *hit)
{
	static const gchar *const headers[] = {
		"TIME", "VERDICT", "DIR", "SOURCE", "DESTINATION", "PORT",
		"SERVICE", "PROTO", "RULE"
	};
	GPtrArray *rows = g_ptr_array_new_with_free_func (
		(GDestroyNotify) g_strfreev);

	g_ptr_array_add (rows, fs_cli_hit_row (hit));
	fs_cli_table (headers, G_N_ELEMENTS (headers), rows, 40);
	g_ptr_array_unref (rows);
}

gint
fs_cli_events_act (const gchar *action, GPtrArray *events, guint pick,
                   gboolean both, gboolean no_apply, gboolean yes)
{
	const EventAct *a = event_act (action);
	GPtrArray *cands = g_ptr_array_new_with_free_func (
		(GDestroyNotify) candidate_free);
	GHashTable *seen = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                          g_free, NULL);
	FsPolicy *policy = NULL;
	const Candidate *c;
	GString *json = NULL;
	FsRule *twin = NULL;
	const gchar *lift_dest = NULL;
	gint rc = FS_EXIT_OK;

	if (a == NULL) {
		fs_cli_events_act_usage (action);
		rc = FS_EXIT_USAGE;
		goto out;
	}
	if (both && a->way != ACT_ALLOW) {
		act_error ("--both goes with an allow (allow-dest, "
		              "trust-source): a block has no twin");
		rc = FS_EXIT_USAGE;
		goto out;
	}
	if (a->way == ACT_UNTRUST)
		policy = fs_cli_load_policy (NULL, NULL);

	/* Newest first; events that give the same rule count once. */
	for (guint i = events != NULL ? events->len : 0; i-- > 0;) {
		const FsHit *hit = g_ptr_array_index (events, i);
		FsRule *rule = NULL;
		Candidate *cand;

		if (a->way == ACT_UNTRUST) {
			GPtrArray *trust = policy->kinds[FS_RULE_INBOUND_ALLOW_FROM];

			if (!hit_inbound (hit) || hit->source == NULL)
				continue;
			for (guint k = 0; k < trust->len && rule == NULL; k++) {
				const FsRule *t = g_ptr_array_index (trust, k);

				if (t->target != NULL &&
				    g_ascii_strcasecmp (t->target, hit->source) == 0)
					rule = fs_rule_copy (t);
			}
		} else {
			rule = fs_eventrule_build (hit, a->rule);
		}
		if (rule == NULL)
			continue;
		if (!g_hash_table_add (seen, fs_rule_to_csv (rule))) {
			fs_rule_free (rule);
			continue;
		}
		cand = g_new0 (Candidate, 1);
		cand->hit = hit;
		cand->rule = rule;
		g_ptr_array_add (cands, cand);
	}

	if (cands->len == 0) {
		act_error ("no event the filters kept fits %s%s", action,
		              a->way == ACT_UNTRUST
		              ? " (an inbound event whose source has an "
		                "inbound-allow-from rule)"
		              : a->inbound ? " (an inbound event with a source)"
		                           : " (an outbound event with a "
		                             "destination)");
		fs_cli_hint ("see them with `stockfw events' and the same filters");
		rc = FS_EXIT_FAILURE;
		goto out;
	}
	if (pick > cands->len) {
		act_error ("--pick %u: there %s only %u to choose from", pick,
		              cands->len == 1 ? "is" : "are", cands->len);
		rc = FS_EXIT_USAGE;
		goto out;
	}
	if (pick == 0 && cands->len > 1) {
		/* Several rules to choose from: listed, nothing done. */
		if (fs_cli.json) {
			json = g_string_new ("{");
			fs_json_kv_str (json, "error", "several events fit: choose "
			                "one with --pick N");
			g_string_append (json, ",\"choices\":[");
			for (guint i = 0; i < cands->len; i++) {
				const Candidate *x = g_ptr_array_index (cands, i);

				if (i > 0)
					g_string_append_c (json, ',');
				g_string_append_c (json, '{');
				fs_json_kv_uint (json, "pick", i + 1);
				g_string_append (json, ",\"event\":");
				fs_cli_hit_row_json (json, x->hit);
				g_string_append (json, ",\"rule\":");
				fs_cli_rule_json (json, x->rule, 0);
				g_string_append_c (json, '}');
			}
			g_string_append (json, "]}");
			fs_cli_print_json (json);
		} else {
			static const gchar *const headers[] = {
				"PICK", "TIME", "SOURCE", "DESTINATION", "PORT", "RULE"
			};
			GPtrArray *rows = g_ptr_array_new_with_free_func (
				(GDestroyNotify) g_strfreev);

			for (guint i = 0; i < cands->len; i++) {
				const Candidate *x = g_ptr_array_index (cands, i);
				gchar **cells = fs_cli_hit_row (x->hit);
				gchar **row = g_new0 (gchar *, 7);

				row[0] = g_strdup_printf ("%u", i + 1);
				row[1] = g_strdup (cells[0]);
				row[2] = g_strdup (cells[3]);
				row[3] = g_strdup (cells[4]);
				row[4] = g_strdup (cells[5]);
				row[5] = rule_text (x->rule);
				g_ptr_array_add (rows, row);
				g_strfreev (cells);
			}
			fs_cli_table (headers, G_N_ELEMENTS (headers), rows, 60);
			g_ptr_array_unref (rows);
		}
		act_error ("%u events fit, each with its own rule: choose one "
		              "with --pick N (nothing was changed)", cands->len);
		rc = FS_EXIT_USAGE;
		goto out;
	}
	c = g_ptr_array_index (cands, pick > 0 ? pick - 1 : 0);

	if (both) {
		twin = fs_rule_counterpart (c->rule);
		if (twin == NULL) {
			act_error ("%s has no twin in the other direction",
			              fs_cli_kind_name (c->rule->kind));
			rc = FS_EXIT_USAGE;
			goto out;
		}
	}
	if (a->way == ACT_ALLOW && c->rule->kind == FS_RULE_OUTBOUND_ALLOW_TO)
		lift_dest = c->rule->target;

	/* Root first: a refusal after the question would waste it. */
	if (!no_apply && geteuid () != 0) {
		rc = act_need_root ("events act");
		goto out;
	}

	/* What will happen, then the question. */
	if (fs_cli.json) {
		json = g_string_new ("{");
		fs_json_kv_str (json, "action", action);
		g_string_append (json, ",\"event\":");
		fs_cli_hit_row_json (json, c->hit);
		g_string_append (json, ",\"rule\":");
		fs_cli_rule_json (json, c->rule, 0);
		if (twin != NULL) {
			g_string_append (json, ",\"twin\":");
			fs_cli_rule_json (json, twin, 0);
		}
	} else if (!fs_cli.quiet) {
		gchar *text = rule_text (c->rule);

		printf ("Event:\n");
		event_table (c->hit);
		say ("%s %s", a->way == ACT_UNTRUST ? "Rule to remove:" : "Rule:",
		     text);
		g_free (text);
		if (twin != NULL) {
			text = rule_text (twin);
			say ("Twin: %s", text);
			g_free (text);
		}
	}
	preview (a->way, c->rule, twin, lift_dest, no_apply, json);
	gui_warning ();

	if (!confirm (a->way == ACT_UNTRUST
	              ? (no_apply ? "Remove this rule?"
	                          : "Remove this rule and take it off the "
	                            "firewall?")
	              : no_apply ? "Save this rule?"
	              : a->way == ACT_BLOCK ? "Save this rule and put it live?"
	              : "Save this rule and apply the policy?", yes)) {
		if (json != NULL) {
			g_string_append (json, ",\"done\":false,");
			fs_json_kv_str (json, "error", "refused: not confirmed "
			                "(pass --yes)");
			g_string_append_c (json, '}');
			fs_cli_print_json (json);
		}
		rc = FS_EXIT_FAILURE;
		goto out;
	}

	rc = run_rule (a->way, c->rule, both, no_apply, yes, lift_dest, "event",
	               json);
	if (json != NULL) {
		g_string_append_c (json, '}');
		fs_cli_print_json (json);
	}

out:
	if (json != NULL)
		g_string_free (json, TRUE);
	fs_rule_free (twin);
	fs_policy_free (policy);
	g_hash_table_unref (seen);
	g_ptr_array_unref (cands);
	return rc;
}

/* ------------------------------------------------------ simulate --do */

gboolean
fs_cli_simulate_do_number (const gchar *text, guint *n)
{
	gchar *end = NULL;
	guint64 v = g_ascii_strtoull (text, &end, 10);

	if (!g_ascii_isdigit (*text) || end == NULL || *end != '\0' || v < 1 ||
	    v > 1000) {
		act_error ("--do wants the number of a fix (1, 2 ...), not `%s'",
		              text);
		return FALSE;
	}
	*n = (guint) v;
	return TRUE;
}

/* The fixes of every answer, in the order the answer prints them. */
static GPtrArray *
all_actions (const FsWhatIfResult *result)
{
	GPtrArray *list = g_ptr_array_new ();

	for (guint i = 0; result->answers != NULL &&
	                  i < result->answers->len; i++) {
		const FsWhatIfAnswer *a = g_ptr_array_index (result->answers, i);

		for (guint k = 0; k < a->actions->len; k++)
			g_ptr_array_add (list, g_ptr_array_index (a->actions, k));
	}
	return list;
}

gchar *
fs_cli_whatif_number_actions (const FsWhatIfResult *result,
                              const gchar *text)
{
	GPtrArray *acts = all_actions (result);
	gchar **lines = g_strsplit (text, "\n", -1);
	GString *out = g_string_new (NULL);
	guint k = 0;

	/* The engine prints each fix as "  [kind] label: explanation", in
	 * this order; a line is numbered only when its label is the next
	 * fix's. */
	for (guint i = 0; lines[i] != NULL; i++) {
		const gchar *line = lines[i];

		if (k < acts->len && g_str_has_prefix (line, "  [")) {
			const FsWhatIfAction *act = g_ptr_array_index (acts, k);
			gchar *label = fs_cli_out_safe (act->label);
			gchar *want = g_strdup_printf ("] %s:", label);
			const gchar *close = strstr (line, "] ");

			if (close != NULL && g_str_has_prefix (close, want)) {
				g_string_append_printf (out, "  %u %s", ++k, line + 2);
				line = NULL;
			}
			g_free (want);
			g_free (label);
		}
		if (line != NULL)
			g_string_append (out, line);
		if (lines[i + 1] != NULL)
			g_string_append_c (out, '\n');
	}
	g_strfreev (lines);
	g_ptr_array_unref (acts);
	return g_string_free (out, FALSE);
}

/* "firewall.icmp.echo_request": the `config' name of the FsSettings
 * field a settings fix names. */
static gchar *
setting_config_name (const gchar *field)
{
	if (field == NULL)
		return NULL;
	if (strcmp (field, "filter_icmp") == 0)
		return g_strdup ("firewall.icmp.enable");
	if (g_str_has_prefix (field, "icmp_"))
		return g_strconcat ("firewall.icmp.", field + 5, NULL);
	return g_strconcat ("firewall.", field, NULL);
}

static const gchar *
action_word (FsWhatIfActionKind kind)
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
	default:                               return "?";
	}
}

/* [ do_command ] -- an action that is a command of its own: printed. */
static gint
do_command (const FsWhatIfAction *act, guint n, const gchar *command,
            const gchar *then)
{
	if (fs_cli.json) {
		GString *json = g_string_new ("{");

		fs_json_kv_uint (json, "do", n);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "kind", action_word (act->kind));
		g_string_append_c (json, ',');
		fs_json_kv_bool (json, "done", FALSE);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "command", command);
		g_string_append_c (json, '}');
		fs_cli_print_json (json);
		g_string_free (json, TRUE);
	} else {
		say ("Run: %s", command);
		if (then != NULL)
			say ("%s", then);
	}
	return FS_EXIT_OK;
}

/* [ do_delegate ] -- `stockfw start' or `stockfw apply', as typed. */
static gint
do_delegate (FsCliCommand cmd, const gchar *name, gboolean yes)
{
	gchar *argv[3] = { (gchar *) name, yes ? (gchar *) "--yes" : NULL,
	                   NULL };

	fflush (stdout);
	return cmd (yes ? 2 : 1, argv);
}

/* [ do_create ] -- H8: a rule from the What-If, checked again. */
static gint
do_create (const FsWhatIfResult *result, const FsWhatIfAction *act,
           guint n, gboolean assume_running, gboolean yes)
{
	FsWhatIfAction check = *act;
	FsRule *row;
	gboolean block = act->kind == FS_WHATIF_ACT_CREATE_BLOCK;
	gchar *why = NULL, *text;
	GString *json = NULL;
	gint rc;

	if (!act->verified || act->row == NULL) {
		act_error ("fix %u was not checked, so it is not written", n);
		return FS_EXIT_USAGE;
	}
	row = fs_rule_copy (act->row);
#ifdef FS_ACT_TESTING
	/* stockfw-act-test only: a fix whose port the test widens, to see
	 * the refusal below do its work. */
	if (g_getenv ("STOCKFW_TEST_FIX_PORT") != NULL && row->port != NULL) {
		g_free (row->port);
		row->port = g_strdup (g_getenv ("STOCKFW_TEST_FIX_PORT"));
	}
#endif
	check.row = row;

	/* Only a row StockFW writes on the user's behalf (one address or
	 * block, one port, one protocol). */
	if (!fs_whatif_row_is_safe (&check, &why)) {
		act_error ("not written: fix %u is not a rule StockFW writes "
		              "for you (%s)", n, why != NULL ? why : "?");
		g_free (why);
		fs_rule_free (row);
		return FS_EXIT_USAGE;
	}

	if (geteuid () != 0) {
		fs_rule_free (row);
		return act_need_root ("simulate --do");
	}

	text = rule_text (row);
	if (fs_cli.json) {
		json = g_string_new ("{");
		fs_json_kv_uint (json, "do", n);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "kind", action_word (act->kind));
		g_string_append (json, ",\"rule\":");
		fs_cli_rule_json (json, row, 0);
	} else {
		say ("Rule: %s", text);
	}
	g_free (text);
	preview (block ? ACT_BLOCK : ACT_ALLOW, row, NULL, NULL, FALSE, json);
	gui_warning ();

	if (!confirm ("Create this rule?", yes)) {
		if (json != NULL) {
			g_string_append (json, ",\"done\":false,");
			fs_json_kv_str (json, "error", "refused: not confirmed "
			                "(pass --yes)");
			g_string_append_c (json, '}');
			fs_cli_print_json (json);
			g_string_free (json, TRUE);
		}
		fs_rule_free (row);
		return FS_EXIT_FAILURE;
	}

	/* The policy may have changed since the question was answered (the
	 * question may have waited): checked once more against the policy
	 * as it is now. */
	{
		FsPolicy *now = fs_cli_load_policy (NULL, NULL);
		FsSettings *settings = NULL;
		FsWhatIfContext *ctx = fs_cli_whatif_context (now, assume_running,
		                                              &settings);
		gboolean still = fs_whatif_action_verify (ctx, result->query,
		                                          &check, &why);

		fs_whatif_context_free (ctx);
		fs_settings_free (settings);
		fs_policy_free (now);
		if (!still) {
			act_error ("not written: the policy changed since this was "
			              "checked, and the rule no longer does only what "
			              "was asked (%s); simulate the line again",
			              why != NULL ? why : "?");
			g_free (why);
			if (json != NULL)
				g_string_free (json, TRUE);
			fs_rule_free (row);
			return FS_EXIT_FAILURE;
		}
	}

	rc = run_rule (block ? ACT_BLOCK : ACT_ALLOW, row, FALSE, FALSE, yes,
	               NULL, "whatif", json);
	if (json != NULL) {
		g_string_append_c (json, '}');
		fs_cli_print_json (json);
		g_string_free (json, TRUE);
	}
	fs_rule_free (row);
	return rc;
}

/* [ do_lift ] -- H9: Sentinel's block of the destination. */
static gint
do_lift (const FsWhatIfAction *act, guint n, gboolean yes)
{
	GVariantDict d;
	FsControlActor actor;
	FsControlResult *r;
	gint rc;

	if (!act->verified || act->target == NULL || *act->target == '\0') {
		act_error ("fix %u was not checked, so nothing is lifted", n);
		return FS_EXIT_USAGE;
	}
	if (geteuid () != 0)
		return act_need_root ("simulate --do");
	say ("Sentinel blocked %s automatically.  Lifting it removes only "
	     "Sentinel's own block; your rules are not touched.", act->target);
	gui_warning ();
	if (!confirm ("Lift Sentinel's block?", yes))
		return FS_EXIT_FAILURE;

	g_variant_dict_init (&d, NULL);
	g_variant_dict_insert (&d, "target", "s", act->target);
	actor = fs_control_actor_self ("cli");
	r = fs_control_do (&actor, "whatif.lift", g_variant_dict_end (&d));
	rc = exit_for (r->status);
	if (fs_cli.json) {
		GString *json = g_string_new ("{");
		gchar *res = fs_control_result_json (r);

		fs_json_kv_uint (json, "do", n);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "kind", action_word (act->kind));
		g_string_append_c (json, ',');
		fs_json_kv_bool (json, "done", r->status == FS_CONTROL_OK);
		g_string_append (json, ",\"result\":");
		g_string_append (json, res);
		g_string_append_c (json, '}');
		fs_cli_print_json (json);
		g_string_free (json, TRUE);
		g_free (res);
	} else if (r->status != FS_CONTROL_OK) {
		act_error ("not lifted: %s", r->error != NULL ? r->error : "?");
	} else {
		const FsApplyOutcome *o = r->lift->outcome;

		/* Rows out of Sentinel's file, or policy rows it no longer
		 * names (an earlier session's): the larger is the count. */
		say_lead (fs_cli_green (), "Lifted", "Sentinel's block of %s (%u).",
		          act->target, MAX (r->lift->rows, r->lift->removed));
		if (o != NULL && o->held)
			say_lead (fs_cli_amber (), "Held:", "%s.  It stays live until "
			          "the next start.",
			          o->hold_reason != NULL ? o->hold_reason : "?");
		else if (o == NULL)
			say ("It was not live.");
	}
	fs_control_result_free (r);
	return rc;
}

gint
fs_cli_simulate_do (const FsWhatIfResult *result, const gchar *line,
                    gboolean assume_running, guint n, gboolean yes)
{
	GPtrArray *acts;
	const FsWhatIfAction *act;
	gint rc = FS_EXIT_OK;

	(void) line;
	fflush (stdout);
	if (result->verdict == FS_WHATIF_ERROR) {
		act_error ("%s", result->error != NULL ? result->error : "?");
		return FS_EXIT_USAGE;
	}
	acts = all_actions (result);
	if (n > acts->len) {
		if (acts->len == 0)
			act_error ("the answer offers no fix, so there is no fix %u",
			              n);
		else
			act_error ("there is no fix %u: the answer offers %u", n,
			              acts->len);
		g_ptr_array_unref (acts);
		return FS_EXIT_USAGE;
	}
	act = g_ptr_array_index (acts, n - 1);
	g_ptr_array_unref (acts);

	say ("Fix %u: %s", n, act->label != NULL ? act->label : "?");

	switch (act->kind) {
	case FS_WHATIF_ACT_CREATE_ALLOW:
	case FS_WHATIF_ACT_CREATE_BLOCK:
		rc = do_create (result, act, n, assume_running, yes);
		break;
	case FS_WHATIF_ACT_LIFT_SENTINEL:
		rc = do_lift (act, n, yes);
		break;
	case FS_WHATIF_ACT_OPEN_RULE: {
		gchar *ref = act->policy_kind >= 0 &&
		             act->policy_kind < FS_RULE_N_KINDS
		             ? fs_cli_rule_ref ((FsRuleKind) act->policy_kind,
		                                (guint) act->policy_index + 1)
		             : NULL;
		gchar *cmd = ref != NULL
		             ? g_strdup_printf ("stockfw policy show %s", ref)
		             : g_strdup ("stockfw policy list");
		gchar *then = ref != NULL
		              ? g_strdup_printf ("Change it with `stockfw policy "
		                                 "edit %s ...' or `stockfw policy "
		                                 "remove %s'.", ref, ref)
		              : NULL;

		rc = do_command (act, n, cmd, then);
		g_free (then);
		g_free (cmd);
		g_free (ref);
		break;
	}
	case FS_WHATIF_ACT_OPEN_ICMP_SETTINGS:
	case FS_WHATIF_ACT_OPEN_SETTINGS: {
		gchar *name = setting_config_name (act->setting);
		gchar *cmd = name != NULL
		             ? g_strdup_printf ("stockfw config set %s %s --apply",
		                                name, act->setting_on ? "on" : "off")
		             : g_strdup ("stockfw config list --firewall");

		rc = do_command (act, n, cmd, "It needs root; then ask the "
		                 "question again.");
		g_free (cmd);
		g_free (name);
		break;
	}
	case FS_WHATIF_ACT_START_FIREWALL:
		/* H12: the start gate, as `stockfw start' runs it (the hold,
		 * the audit line, the journal), never the backend's start. */
		if (geteuid () != 0)
			return act_need_root ("simulate --do");
		say ("It starts the firewall through the start gate, as `stockfw "
		     "start' does: the last applied policy (the saved one when "
		     "none was ever applied), and audit-only mode holds it.");
		if (!confirm ("Start the firewall now?", yes))
			return FS_EXIT_FAILURE;
		rc = do_delegate (fs_cli_cmd_start, "start", yes);
		break;
	case FS_WHATIF_ACT_APPLY_POLICY:
		if (geteuid () != 0)
			return act_need_root ("simulate --do");
		say ("It applies the saved policy, as `stockfw apply' does.");
		if (!confirm ("Apply the saved policy now?", yes))
			return FS_EXIT_FAILURE;
		rc = do_delegate (fs_cli_cmd_apply, "apply", yes);
		break;
	default:
		act_error ("fix %u is not one this tool can run", n);
		rc = FS_EXIT_USAGE;
		break;
	}
	return rc;
}
