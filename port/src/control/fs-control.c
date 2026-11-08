/*---[ fs-control.c ]----------------------------------------------------
 * The control layer: every write, in one place.  See fs-control.h.
 *
 * The bodies of PR 1's write commands (policy add and remove, apply,
 * start, stop) moved here from cli/fs-cli-policy.c, which now parses,
 * asks and prints, and nothing else.  Each op takes the policy lock for
 * its whole length and reads the policy and the preferences again
 * under it, so a write another process made a moment ago is the base
 * of this one, never overwritten.
 *--------------------------------------------------------------------*/
#include "control/fs-control.h"
#include "control/fs-changelog.h"
#include "core/fs-audit.h"
#include "core/fs-autoblock.h"
#include "core/fs-copilot.h"
#include "core/fs-health.h"
#include "core/fs-hostnet.h"
#include "core/fs-iprange.h"
#include "core/fs-json.h"
#include "core/fs-script.h"
#include "core/fs-util.h"
#include "core/fs-whatif.h"

#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------- names */

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

const gchar * const *
fs_control_kind_names (void)
{
	return kind_names;
}

gboolean
fs_control_kind_parse (const gchar *name, FsRuleKind *kind)
{
	for (gint i = 0; i < FS_RULE_N_KINDS; i++) {
		if (g_strcmp0 (name, kind_names[i]) == 0) {
			*kind = (FsRuleKind) i;
			return TRUE;
		}
	}
	return FALSE;
}

const gchar *
fs_control_status_name (FsControlStatus status)
{
	switch (status) {
	case FS_CONTROL_OK:        return "ok";
	case FS_CONTROL_FAILED:    return "failed";
	case FS_CONTROL_USAGE:     return "usage";
	case FS_CONTROL_NEED_ROOT: return "need-root";
	case FS_CONTROL_CONFIRM:   return "confirm";
	case FS_CONTROL_CONFLICT:  return "conflict";
	default:                   return "failed";
	}
}

FsControlActor
fs_control_actor_self (const gchar *channel)
{
	FsControlActor a;

	a.channel = channel != NULL ? channel : "cli";
	a.uid = (gint) geteuid ();
	return a;
}

/* ---------------------------------------------------- backend context */

/* The backend keeps pointers to the policy and settings it was handed
 * (fs_backend_set_context), so control owns the pair it handed last and
 * frees it only when it hands another. */
static FsSettingsContextFunc set_context_func = fs_backend_set_context;
static FsPolicy   *ctx_policy = NULL;
static FsSettings *ctx_settings = NULL;

void
fs_control_set_context_func (FsSettingsContextFunc func)
{
	set_context_func = func != NULL ? func : fs_backend_set_context;
}

static void
hand_context (FsPolicy *policy, FsSettings *settings)
{
	FsPolicy *old_p = ctx_policy;
	FsSettings *old_s = ctx_settings;

	ctx_policy = policy;
	ctx_settings = settings;
	set_context_func (policy, settings);
	/* Saved preferences, unless live_context says otherwise. */
	fs_firewall_live_keeps_settings (FALSE);
	if (old_p != policy)
		fs_policy_free (old_p);
	if (old_s != settings)
		fs_settings_free (old_s);
}

/* ------------------------------------------------------------ helpers */

static FsPolicy *
policy_copy (const FsPolicy *p)
{
	FsPolicy *c = fs_policy_new ();

	for (gint k = 0; p != NULL && k < FS_RULE_N_KINDS; k++)
		for (guint i = 0; i < p->kinds[k]->len; i++)
			fs_policy_add (c, g_ptr_array_index (p->kinds[k], i));
	return c;
}

static guint
policy_total (const FsPolicy *p)
{
	guint n = 0;

	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		n += fs_policy_count (p, (FsRuleKind) k);
	return n;
}

/* The 1-based number of the stored row equal to `rule', or 0. */
static guint
rule_number (const FsPolicy *policy, const FsRule *rule)
{
	gchar *want = fs_rule_to_csv (rule);
	GPtrArray *rows = policy->kinds[rule->kind];
	guint found = 0;

	for (guint i = 0; i < rows->len && found == 0; i++) {
		gchar *csv = fs_rule_to_csv (g_ptr_array_index (rows, i));

		if (g_strcmp0 (csv, want) == 0)
			found = i + 1;
		g_free (csv);
	}
	g_free (want);
	return found;
}

static void
fail (FsControlResult *r, FsControlStatus status, const gchar *hint,
      const gchar *format, ...) G_GNUC_PRINTF (4, 5);

static void
fail (FsControlResult *r, FsControlStatus status, const gchar *hint,
      const gchar *format, ...)
{
	va_list ap;

	r->status = status;
	g_free (r->error);
	va_start (ap, format);
	r->error = g_strdup_vprintf (format, ap);
	va_end (ap);
	g_free (r->hint);
	r->hint = g_strdup (hint);
}

static gboolean
need_root (FsControlResult *r, const FsControlActor *actor)
{
	if (actor->uid == 0)
		return TRUE;
	fail (r, FS_CONTROL_NEED_ROOT, NULL, "%s needs root privileges", r->op);
	return FALSE;
}

/* Params, a{sv}.  Strings are borrowed from `params'. */
static const gchar *
p_str (GVariant *params, const gchar *key)
{
	const gchar *s = NULL;

	if (params == NULL || !g_variant_lookup (params, key, "&s", &s))
		return NULL;
	return s;
}

static gboolean
p_bool (GVariant *params, const gchar *key)
{
	gboolean b = FALSE;

	if (params == NULL || !g_variant_lookup (params, key, "b", &b))
		return FALSE;
	return b;
}

static guint
p_uint (GVariant *params, const gchar *key)
{
	guint32 u = 0;

	if (params == NULL || !g_variant_lookup (params, key, "u", &u))
		return 0;
	return u;
}

/* g_free the array (the strings are borrowed); NULL when absent. */
static const gchar **
p_strv (GVariant *params, const gchar *key, gsize *n)
{
	const gchar **v = NULL;

	*n = 0;
	if (params == NULL || !g_variant_lookup (params, key, "^a&s", &v))
		return NULL;
	*n = g_strv_length ((gchar **) v);
	return v;
}

/* [ load_policy ]
 * The saved policy, read now (under the lock).  Lines that are not
 * rules are refused for any op that saves: the save would drop them
 * without a word (15.2.7).  FALSE: refused, r says why. */
static FsPolicy *
load_policy (FsControlResult *r, gboolean refuse_problems,
             gboolean *on_disk)
{
	FsPolicy *policy = fs_policy_new ();
	GPtrArray *problems = NULL;
	gboolean any = fs_policy_load_report (policy, &problems);

	if (on_disk != NULL)
		*on_disk = any;
	if (problems->len > 0 && refuse_problems) {
		r->problems = problems;
		fail (r, FS_CONTROL_USAGE, NULL,
		      "%u line%s of the policy %s", problems->len,
		      problems->len == 1 ? "" : "s",
		      problems->len == 1 ? "is not a rule" : "are not rules");
		fs_policy_free (policy);
		return NULL;
	}
	if (problems->len > 0)
		r->problems = problems;
	else
		g_ptr_array_unref (problems);
	return policy;
}

/* [ rule_from_fields ]
 * The fields of a kind in CSV order, never through the CSV itself: a
 * comma in a field must reach fs_rule_validate, not split the row. */
static FsRule *
rule_from_fields (FsControlResult *r, FsRuleKind kind,
                  const gchar * const *fields, gsize n, const gchar *comment)
{
	gint cols = 0;
	gsize want;
	FsRule *rule;

	fs_rule_columns (kind, &cols);
	want = cols > 0 ? (gsize) cols - 1 : 0;   /* less the comment */
	if (n != want) {
		fail (r, FS_CONTROL_USAGE, NULL, "%s takes %u field%s, got %u",
		      kind_names[kind], (guint) want, want == 1 ? "" : "s",
		      (guint) n);
		return NULL;
	}

	rule = fs_rule_new (kind);
	switch (kind) {
	case FS_RULE_INBOUND_FORWARD:
		rule->service = g_strdup (fields[0]);
		rule->port    = g_strdup (fields[1]);
		rule->to      = g_strdup (fields[2]);
		rule->to_port = g_strdup (fields[3]);
		break;
	case FS_RULE_INBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_DENY_SERVICE:
		rule->service = g_strdup (fields[0]);
		rule->port    = g_strdup (fields[1]);
		rule->target  = g_strdup (fields[2]);
		break;
	default:
		rule->target  = g_strdup (fields[0]);
		break;
	}
	rule->comment = g_strdup (comment != NULL ? comment : "");

	/* The fields as fs_rule_from_csv would store them: trimmed. */
	if (rule->service) g_strstrip (rule->service);
	if (rule->port)    g_strstrip (rule->port);
	if (rule->target)  g_strstrip (rule->target);
	if (rule->to)      g_strstrip (rule->to);
	if (rule->to_port) g_strstrip (rule->to_port);
	g_strstrip (rule->comment);

	return rule;
}

/* [ rule_checked ] -- T15 first, then the fields themselves (F-1). */
static gboolean
rule_checked (FsControlResult *r, const FsRule *rule)
{
	GError *error = NULL;

	if (!fs_rule_validate (rule, &error)) {
		fail (r, FS_CONTROL_USAGE, NULL, "%s", error->message);
		g_error_free (error);
		return FALSE;
	}
	r->problem = fs_rule_problem (rule);
	if (r->problem != NULL) {
		r->invalid_rule = TRUE;
		fail (r, FS_CONTROL_USAGE, NULL, "not a valid %s rule: %s",
		      kind_names[rule->kind], r->problem);
		return FALSE;
	}
	return TRUE;
}

static void
save_failed (FsControlResult *r)
{
	fail (r, FS_CONTROL_FAILED, NULL, "could not save the policy in %s",
	      fs_util_rules_dir ());
	if (geteuid () != 0 && g_str_has_prefix (fs_util_rules_dir (), "/etc"))
		r->hint = g_strdup_printf ("%s is root's; run with sudo",
		                           fs_util_rules_dir ());
}

/* [ guard ]
 * The lockout guard (master plan section 2): would `policy' under
 * `settings' cut an SSH session of this computer?  Records the report;
 * FALSE (CONFIRM, nothing changed) when it would and the caller did not
 * say yes. */
static gboolean
guard (FsControlResult *r, const FsPolicy *policy, const FsSettings *settings,
       gboolean yes)
{
	FsRangeSet *own = NULL, *peers = NULL;
	GArray *ports = NULL;

	fs_lockout_sessions (&own, &peers, &ports);
	/* This session's own peer first, so a busy host's other sessions
	 * cannot push it past the cap. */
	r->lockout = fs_lockout_check_own (policy, settings, own, peers, ports);
	r->lockout_policy = policy_copy (policy);
	fs_range_set_free (own);
	fs_range_set_free (peers);
	g_array_unref (ports);

	if (!fs_lockout_report_cuts (r->lockout))
		return TRUE;
	if (yes) {
		r->lockout_confirmed = TRUE;
		return TRUE;
	}
	fail (r, FS_CONTROL_CONFIRM, NULL,
	      "this policy would block your SSH session");
	return FALSE;
}

/* [ intel_follow ]
 * The threat-intel blocklists follow the user's Stop and Start (design
 * 6.5; B7): after the firewall stopped they are removed and recorded as
 * suspended (fs_intel_suspend); after it started they are applied again
 * through the gate, under the same hold as any apply (fs_intel_resume).
 * Nothing happens where no list was ever turned on. */
static void
intel_follow (FsControlResult *r, const FsControlActor *actor,
              gboolean start)
{
	const FsBackend *backend = fs_backend ();
	FsIntelOutcome *o = NULL;
	GError *error = NULL;
	GString *notes = g_string_new (NULL);
	FsControlIntel *in = &r->intel;

	in->ran = TRUE;
	in->start = start;
	if (start) {
		o = fs_intel_resume (backend, actor->channel,
		                     fs_apply_hold_reason (), &error);
		in->ok = error == NULL && (o == NULL || o->result != FS_APPLY_FAILED);
		if (o == NULL)
			in->result = error != NULL ? "failed" : "none";
		else if (o->held)
			in->result = "held";
		else
			in->result = o->result == FS_APPLY_OK ? "applied" : "failed";
	} else {
		in->ok = fs_intel_suspend (backend, actor->channel, &error);
		in->result = in->ok ? "suspended" : "failed";
	}
	for (guint i = 0; o != NULL && o->notes != NULL && i < o->notes->len;
	     i++)
		g_string_append_printf (notes, "%s\n",
		                        (gchar *) g_ptr_array_index (o->notes, i));

	in->hold = o != NULL ? g_strdup (o->hold_reason) : NULL;
	in->held = o != NULL && o->held;
	in->sets = o != NULL ? o->sets : 0;
	in->error = error != NULL ? g_strdup (error->message) : NULL;
	in->notes = g_string_free (notes, FALSE);
	in->outcome = o != NULL;

	g_clear_error (&error);
	fs_intel_outcome_free (o);
}

/* [ apply_now ]
 * `policy' under `settings' through the gate, the policy lock held by
 * the caller; both are taken (the backend keeps them as its context).
 * The guard has run already. */
static void
apply_now (FsControlResult *r, const FsControlActor *actor,
           FsPolicy *policy, FsSettings *settings)
{
	GError *error = NULL;

	hand_context (policy, settings);
	r->outcome = fs_policy_apply_safe (fs_backend (), policy,
	                                   actor->channel,
	                                   fs_apply_hold_reason (), &error);

	if (r->outcome->held || r->outcome->result == FS_APPLY_OK) {
		r->status = FS_CONTROL_OK;
	} else {
		r->status = r->outcome->result == FS_APPLY_NO_PRIVILEGE
		          ? FS_CONTROL_NEED_ROOT : FS_CONTROL_FAILED;
		g_free (r->error);
		r->error = g_strdup (error != NULL ? error->message
		           : fs_util_apply_result_to_string (
		                 (int) r->outcome->result));
	}
	/* An apply that started a stopped firewall brings the blocklists
	 * back, as a start does. */
	if (r->outcome->applied && r->outcome->firewall_was == FS_FW_STOPPED)
		intel_follow (r, actor, TRUE);

	g_clear_error (&error);
}

/* [ edit_guard ]
 * 3D, "apply" on an edit: before anything is saved, root is checked
 * and the lockout guard runs on `after', the policy the edit gives.
 * FALSE: refused (NEED_ROOT, or CONFIRM), nothing changed.  TRUE when
 * the edit may go on, or when no apply was asked for. */
static gboolean
edit_guard (FsControlResult *r, const FsControlActor *actor,
            GVariant *params, const FsPolicy *after)
{
	FsSettings *settings;
	gboolean ok = TRUE;

	if (!p_bool (params, "apply"))
		return TRUE;
	if (!need_root (r, actor))
		return FALSE;
	fs_prefs_load ();
	settings = fs_settings_new ();
	fs_settings_load_prefs (settings);
	/* Held, the firewall is not touched: no session to keep. */
	if (fs_apply_hold_reason () == NULL)
		ok = guard (r, after, settings, p_bool (params, "yes"));
	fs_settings_free (settings);
	return ok;
}

/* [ edit_apply ]
 * After a saved edit (or none: "already"), still under the lock: the
 * saved policy as it now is goes through the gate, as `apply' does. */
static void
edit_apply (FsControlResult *r, const FsControlActor *actor,
            GVariant *params)
{
	FsSettings *settings;

	if (!p_bool (params, "apply"))
		return;
	settings = fs_settings_new ();
	fs_settings_load_prefs (settings);
	apply_now (r, actor, policy_copy (r->policy), settings);
}

/* ---------------------------------------------------------- the ops */

/* Defined with the binary-text helpers below. Policy import uses a string
 * today; the declaration keeps the control operation independent of the
 * physical location of those helpers. */
static const gchar *p_text (GVariant *params, const gchar *key);

static void
op_policy_add (FsControlResult *r, const FsControlActor *actor,
               GVariant *params)
{
	FsRuleKind kind;
	gsize n = 0;
	const gchar **fields = p_strv (params, "fields", &n);
	FsRule *rule;
	FsPolicyLock *lock;
	GError *error = NULL;
	gboolean ok;

	if (!fs_control_kind_parse (p_str (params, "kind"), &kind)) {
		fail (r, FS_CONTROL_USAGE, NULL, "not a rule kind: %s",
		      p_str (params, "kind") != NULL ? p_str (params, "kind")
		                                     : "(none)");
		g_free (fields);
		return;
	}
	rule = rule_from_fields (r, kind, fields, n, p_str (params, "comment"));
	g_free (fields);
	if (rule == NULL)
		return;
	r->rule = rule;
	if (!rule_checked (r, rule))
		return;

	if (p_bool (params, "both")) {
		r->twin = fs_rule_counterpart (rule);
		if (r->twin == NULL) {
			fail (r, FS_CONTROL_USAGE, NULL,
			      "%s has no opposite-direction twin; --both only "
			      "applies to allow rules", kind_names[kind]);
			return;
		}
	}

	lock = fs_policy_lock (&error);
	if (lock == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_error_free (error);
		return;
	}

	r->policy = load_policy (r, TRUE, NULL);
	if (r->policy == NULL) {
		fs_policy_unlock (lock);
		return;
	}

	if (fs_policy_contains (r->policy, rule) &&
	    (r->twin == NULL || fs_policy_contains (r->policy, r->twin))) {
		r->already = TRUE;
		r->number = rule_number (r->policy, rule);
		if (edit_guard (r, actor, params, r->policy))
			edit_apply (r, actor, params);
		fs_policy_unlock (lock);
		return;
	}

	if (p_bool (params, "apply")) {
		FsPolicy *after = policy_copy (r->policy);

		if (!fs_policy_contains (after, rule))
			fs_policy_add (after, rule);
		if (r->twin != NULL && !fs_policy_contains (after, r->twin))
			fs_policy_add (after, r->twin);
		ok = edit_guard (r, actor, params, after);
		fs_policy_free (after);
		if (!ok) {
			fs_policy_unlock (lock);
			return;
		}
	}

	/* The policy stores copies (fs_policy_add), so the rules stay the
	 * result's whether the save works or not. */
	ok = r->twin != NULL
	   ? fs_policy_add_persist_pair (r->policy, rule, r->twin)
	   : fs_policy_add_persist (r->policy, rule);

	if (!ok) {
		fs_policy_unlock (lock);
		save_failed (r);
		return;
	}
	r->saved = TRUE;
	r->number = rule_number (r->policy, rule);
	if (r->twin != NULL)
		r->twin_number = rule_number (r->policy, r->twin);
	edit_apply (r, actor, params);
	fs_policy_unlock (lock);
}

/* [ take_row ] -- the row a remove or an edit names, checked against
 * the one the caller read (csv).  NULL: refused. */
static const FsRule *
take_row (FsControlResult *r, GVariant *params, FsRuleKind *kind)
{
	guint number = p_uint (params, "number");
	const gchar *csv = p_str (params, "csv");
	const FsRule *row;
	gchar *now;

	if (!fs_control_kind_parse (p_str (params, "kind"), kind)) {
		fail (r, FS_CONTROL_USAGE, NULL, "not a rule kind: %s",
		      p_str (params, "kind") != NULL ? p_str (params, "kind")
		                                     : "(none)");
		return NULL;
	}
	if (number < 1 || number > r->policy->kinds[*kind]->len) {
		fail (r, FS_CONTROL_USAGE, NULL, "%s has no rule number %u (it "
		      "has %u)", kind_names[*kind], number,
		      r->policy->kinds[*kind]->len);
		return NULL;
	}
	row = g_ptr_array_index (r->policy->kinds[*kind], number - 1);
	now = fs_rule_to_csv (row);
	if (csv != NULL && strcmp (csv, now) != 0) {
		g_free (now);
		fail (r, FS_CONTROL_CONFLICT,
		      "run `stockfw policy list' and name the rule again",
		      "%s:%u is no longer the rule that was read: the policy "
		      "changed", kind_names[*kind], number);
		return NULL;
	}
	g_free (now);
	r->number = number;
	return row;
}

static void
op_policy_remove (FsControlResult *r, const FsControlActor *actor,
                  GVariant *params)
{
	FsRuleKind kind;
	const FsRule *row;
	FsPolicyLock *lock;
	GError *error = NULL;
	gboolean ok;

	lock = fs_policy_lock (&error);
	if (lock == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_error_free (error);
		return;
	}
	r->policy = load_policy (r, TRUE, NULL);
	if (r->policy == NULL || (row = take_row (r, params, &kind)) == NULL) {
		fs_policy_unlock (lock);
		return;
	}

	r->rule = fs_rule_copy (row);
	if (p_bool (params, "apply")) {
		FsPolicy *after = policy_copy (r->policy);

		fs_policy_remove (after, r->rule);
		ok = edit_guard (r, actor, params, after);
		fs_policy_free (after);
		if (!ok) {
			fs_policy_unlock (lock);
			return;
		}
	}
	ok = fs_policy_remove_persist (r->policy, r->rule);
	if (!ok) {
		fs_policy_unlock (lock);
		save_failed (r);
		return;
	}
	r->saved = TRUE;
	edit_apply (r, actor, params);
	fs_policy_unlock (lock);
}

static void
op_policy_replace (FsControlResult *r, const FsControlActor *actor,
                   GVariant *params)
{
	FsRuleKind kind;
	const FsRule *row;
	FsRule *rule;
	FsPolicyLock *lock;
	GError *error = NULL;
	gsize n = 0;
	const gchar **fields;
	const gchar *comment = p_str (params, "comment");

	lock = fs_policy_lock (&error);
	if (lock == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_error_free (error);
		return;
	}
	r->policy = load_policy (r, TRUE, NULL);
	if (r->policy == NULL || (row = take_row (r, params, &kind)) == NULL) {
		fs_policy_unlock (lock);
		return;
	}
	r->old = fs_rule_copy (row);

	/* No comment given: the row keeps its own. */
	fields = p_strv (params, "fields", &n);
	rule = rule_from_fields (r, kind, fields, n,
	                         comment != NULL ? comment : r->old->comment);
	g_free (fields);
	if (rule == NULL) {
		fs_policy_unlock (lock);
		return;
	}
	r->rule = rule;
	if (!rule_checked (r, rule)) {
		fs_policy_unlock (lock);
		return;
	}

	if (p_bool (params, "apply")) {
		FsPolicy *after = policy_copy (r->policy);
		GPtrArray *rows = after->kinds[kind];
		gboolean ok;

		/* The row in place, as fs_policy_replace_persist will put it
		 * (the copy holds rows in the same order). */
		fs_rule_free (g_ptr_array_index (rows, r->number - 1));
		g_ptr_array_index (rows, r->number - 1) = fs_rule_copy (rule);
		ok = edit_guard (r, actor, params, after);
		fs_policy_free (after);
		if (!ok) {
			fs_policy_unlock (lock);
			return;
		}
	}

	if (!fs_policy_replace_nth_persist (r->policy, (gint) r->number - 1,
	                                    r->old, rule, &error)) {
		fail (r, g_error_matches (error, FS_RULES_ERROR,
		                          FS_RULES_ERR_SAVE)
		         ? FS_CONTROL_FAILED : FS_CONTROL_USAGE,
		      NULL, "%s", error->message);
		g_error_free (error);
		fs_policy_unlock (lock);
		return;
	}
	r->saved = TRUE;
	edit_apply (r, actor, params);
	fs_policy_unlock (lock);
}

static void
op_policy_import (FsControlResult *r, const FsControlActor *actor,
                  GVariant *params)
{
	const gchar *text = p_text (params, "text");
	gboolean replace = p_bool (params, "replace");
	gboolean apply = p_bool (params, "apply");
	FsPolicyLock *lock;
	GError *error = NULL;
	FsPolicy *incoming;
	GPtrArray *problems = NULL;
	guint added = 0, duplicates = 0, rejected = 0;

	if (text == NULL) {
		fail (r, FS_CONTROL_USAGE, NULL, "policy.import needs text");
		return;
	}
	incoming = fs_policy_import_parse (text, &problems, &error);
	if (problems != NULL) {
		rejected = problems->len;
		r->problems = problems;
	}
	/* An import is all-or-nothing: a malformed line must never cause the
	 * valid prefix to be saved while silently dropping the rest. */
	if (incoming != NULL && rejected > 0) {
		fs_policy_free (incoming);
		fail (r, FS_CONTROL_USAGE, NULL,
		      "the import contains %u invalid line%s", rejected,
		      rejected == 1 ? "" : "s");
		return;
	}
	if (incoming == NULL) {
		fail (r, FS_CONTROL_USAGE, NULL, "%s",
		      error != NULL ? error->message : "invalid policy export text");
		g_clear_error (&error);
		return;
	}

	if (apply && !need_root (r, actor)) {
		fs_policy_free (incoming);
		return;
	}

	lock = fs_policy_lock (&error);
	if (lock == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_error_free (error);
		fs_policy_free (incoming);
		return;
	}

	r->policy = load_policy (r, FALSE, NULL);
	if (r->policy == NULL) {
		fs_policy_unlock (lock);
		fs_policy_free (incoming);
		return;
	}

	if (replace) {
		added = policy_total (incoming);
		fs_policy_clear (r->policy);
		for (gint k = 0; k < FS_RULE_N_KINDS; k++)
			for (guint i = 0; i < incoming->kinds[k]->len; i++)
				fs_policy_add (r->policy, g_ptr_array_index (incoming->kinds[k], i));
	} else {
		if (!fs_policy_merge (r->policy, incoming, FALSE, &added, &duplicates, &error)) {
			fail (r, FS_CONTROL_FAILED, NULL, "%s", error != NULL ? error->message : "merge failed");
			g_clear_error (&error);
			fs_policy_unlock (lock);
			fs_policy_free (incoming);
			return;
		}
	}
	fs_policy_free (incoming);

	if (apply) {
		FsSettings *settings;
		if (!edit_guard (r, actor, params, r->policy)) {
			fs_policy_unlock (lock);
			return;
		}
		settings = fs_settings_new ();
		fs_settings_load_prefs (settings);
		if (!fs_policy_save (r->policy)) {
			fs_settings_free (settings);
			fs_policy_unlock (lock);
			save_failed (r);
			return;
		}
		r->saved = TRUE;
		r->imported = added;
		r->duplicates = duplicates;
		r->rejected = rejected;
		apply_now (r, actor, policy_copy (r->policy), settings);
		fs_policy_unlock (lock);
		return;
	}

	if (!fs_policy_save (r->policy)) {
		fs_policy_unlock (lock);
		save_failed (r);
		return;
	}
	r->saved = TRUE;
	r->imported = added;
	r->duplicates = duplicates;
	r->rejected = rejected;
	fs_policy_unlock (lock);
}

/* [ op_policy_init ]
 * A1/A19: the default rules a first run of the desktop app seeds
 * (fs_policy_install_defaults), saved.  A saved policy that holds a
 * rule, or a line that is not one, is replaced only with "force". */
static void
op_policy_init (FsControlResult *r, const FsControlActor *actor,
                GVariant *params)
{
	FsPolicyLock *lock;
	GError *error = NULL;
	gboolean on_disk = FALSE;
	guint had;

	(void) actor;
	lock = fs_policy_lock (&error);
	if (lock == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_error_free (error);
		return;
	}
	r->policy = load_policy (r, FALSE, &on_disk);
	had = policy_total (r->policy);
	if ((had > 0 || r->problems != NULL) && !p_bool (params, "force")) {
		fail (r, FS_CONTROL_USAGE,
		      "pass --force to replace it with the default rules",
		      "a policy is saved already in %s (%u rule%s%s)",
		      fs_util_rules_dir (), had, had == 1 ? "" : "s",
		      r->problems != NULL ? ", and lines that are not rules"
		                          : "");
		fs_policy_unlock (lock);
		return;
	}

	fs_policy_install_defaults (r->policy);
	if (!fs_policy_save (r->policy)) {
		fs_policy_unlock (lock);
		save_failed (r);
		return;
	}
	r->saved = TRUE;
	r->dropped = had;
	fs_policy_unlock (lock);
}

/* [ op_apply ] -- the saved policy, through the gate (E7). */
static void
op_apply (FsControlResult *r, const FsControlActor *actor, GVariant *params)
{
	FsPolicyLock *lock;
	GError *error = NULL;
	FsPolicy *policy;
	FsSettings *settings;
	gboolean on_disk = FALSE;

	if (!need_root (r, actor))
		return;
	lock = fs_policy_lock (&error);
	if (lock == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_error_free (error);
		return;
	}
	fs_prefs_load ();

	policy = load_policy (r, TRUE, &on_disk);
	if (policy == NULL) {
		fs_policy_unlock (lock);
		return;
	}
	if (!on_disk) {
		r->no_policy = TRUE;
		fail (r, FS_CONTROL_FAILED, NULL,
		      "no policy saved in %s -- nothing to apply",
		      fs_util_rules_dir ());
		fs_policy_free (policy);
		fs_policy_unlock (lock);
		return;
	}

	settings = fs_settings_new ();
	fs_settings_load_prefs (settings);
	/* Held, the firewall is not touched: no session to keep. */
	if (fs_apply_hold_reason () == NULL &&
	    !guard (r, policy, settings, p_bool (params, "yes"))) {
		fs_settings_free (settings);
		fs_policy_free (policy);
		fs_policy_unlock (lock);
		return;
	}

	apply_now (r, actor, policy, settings);
	fs_policy_unlock (lock);
}

/* [ op_start ]
 * Through the start gate: the last APPLIED policy is what starts, and
 * (3B) under the settings it was applied with, when the journal records
 * them; changes saved and not applied stay off, policy and settings
 * alike.  An older journal, or none, takes the saved preferences. */
static void
op_start (FsControlResult *r, const FsControlActor *actor, GVariant *params)
{
	const FsBackend *backend = fs_backend ();
	FsPolicyLock *lock;
	GError *error = NULL;
	FsPolicy *policy, *journal, *lift;
	FsSettings *settings;
	GHashTable *recorded = NULL;
	gboolean on_disk = FALSE, journal_ok, have_journal;
	gchar *mode, *jpath;
	guint malformed;

	if (!need_root (r, actor))
		return;
	lock = fs_policy_lock (&error);
	if (lock == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_error_free (error);
		return;
	}
	fs_prefs_load ();

	/* Already running: nothing to do, and nothing on the audit
	 * record. */
	r->was = backend->get_state != NULL ? backend->get_state () : FS_FW_NONE;
	if (r->was == FS_FW_RUNNING) {
		FsPolicy *live = fs_policy_new ();

		r->live_rules = fs_apply_journal_load (live, NULL)
		              ? policy_total (live) : 0;
		fs_policy_free (live);
		fs_policy_unlock (lock);
		return;
	}

	/* Load first, always: the backend starts from the policy it was
	 * handed, and an unloaded one is an empty one. */
	policy = load_policy (r, FALSE, &on_disk);
	malformed = r->problems != NULL ? r->problems->len : 0;

	journal = fs_policy_new ();
	journal_ok = fs_apply_journal_load (journal, NULL);
	have_journal = journal_ok;
	jpath = fs_apply_journal_path ();
	/* A journal that exists but cannot be read is the gate's to
	 * refuse; for the checks below it counts as there. */
	if (!have_journal && g_file_test (jpath, G_FILE_TEST_EXISTS))
		have_journal = TRUE;
	g_free (jpath);
	r->journal = have_journal;

	/* 3B: the settings the journal's policy went out with; the saved
	 * preferences only when the journal does not record any. */
	settings = journal_ok ? fs_settings_from_journal (&recorded) : NULL;
	r->settings_from_journal = settings != NULL;
	if (settings == NULL) {
		settings = fs_settings_new ();
		fs_settings_load_prefs (settings);
	}

	if (backend->start_applies_policy && !have_journal &&
	    (!on_disk || malformed > 0)) {
		/* Nothing was ever applied, so this start would be the first
		 * apply of the file: refused when there is no file or a line
		 * of it could not be read, rather than starting a policy that
		 * is empty or missing rules. */
		gchar *line = g_strdup_printf ("%s | refused | %s",
			actor->channel,
			!on_disk ? "no policy saved and none applied before"
			         : "malformed lines in the saved policy and none "
			           "applied before");

		fs_audit_log ("firewall start refused", line);
		g_free (line);
		r->no_policy = !on_disk;
		if (!on_disk)
			fail (r, FS_CONTROL_FAILED, NULL,
			      "no policy saved in %s and none applied before, so "
			      "there is nothing to start", fs_util_rules_dir ());
		else
			fail (r, FS_CONTROL_FAILED, NULL,
			      "%u line(s) of the policy in %s could not be read "
			      "and no policy was applied before; fix them "
			      "(`stockfw check'), then run `stockfw apply'",
			      malformed, fs_util_rules_dir ());
		goto out;
	}

	/* The lockout guard, on what the start installs: the journal when
	 * there is one, else the file.  Held (audit-only), a start with a
	 * journal still installs it (fs_firewall_start_lifting), so it is
	 * guarded too; only a held start with no journal leaves the
	 * firewall alone. */
	if ((fs_apply_hold_reason () == NULL ? (journal_ok || !have_journal)
	                                     : journal_ok) &&
	    !guard (r, journal_ok ? journal : policy, settings,
	            p_bool (params, "yes")))
		goto out;

	/* Sentinel's blocks whose ten minutes ran out while nothing was
	 * running to lift them (a reboot) come out of the file, and the
	 * start leaves every one of them out of what it installs. */
	lift = fs_policy_new ();
	mode = fs_prefs_get_string (FS_PREFS_SENTINEL_MODE, "auto");
	fs_autoblock_expire (policy, g_get_real_time () / G_USEC_PER_SEC,
	                     g_strcmp0 (mode, "auto") != 0, lift);
	g_free (mode);

	hand_context (policy, settings);
	policy = NULL;
	settings = NULL;
	r->outcome = fs_firewall_start_recorded (backend, ctx_policy, lift,
	                                         recorded, actor->channel,
	                                         fs_apply_hold_reason (),
	                                         &error);
	fs_policy_free (lift);

	if (r->outcome->result == FS_APPLY_OK) {
		r->status = FS_CONTROL_OK;
		r->changed = TRUE;
		intel_follow (r, actor, TRUE);
	} else if (r->outcome->result == FS_APPLY_DRY_RUN && error == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL,
		      "held (%s) and no policy was ever applied, so there is "
		      "nothing safe to start with", r->outcome->hold_reason);
	} else {
		fail (r, FS_CONTROL_FAILED, NULL, "%s",
		      error != NULL ? error->message
		      : fs_util_apply_result_to_string ((int) r->outcome->result));
	}

out:
	if (recorded != NULL)
		g_hash_table_unref (recorded);
	fs_settings_free (settings);
	fs_policy_free (policy);
	fs_policy_free (journal);
	g_clear_error (&error);
	fs_policy_unlock (lock);
}

/* [ op_stop ] -- never held: stopping is the user's own way out. */
static void
op_stop (FsControlResult *r, const FsControlActor *actor, GVariant *params)
{
	const FsBackend *backend = fs_backend ();
	FsPolicyLock *lock;
	GError *error = NULL;
	FsPolicy *policy;
	FsSettings *settings;

	(void) params;
	if (!need_root (r, actor))
		return;
	lock = fs_policy_lock (&error);
	if (lock == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_error_free (error);
		return;
	}

	r->was = backend->get_state != NULL ? backend->get_state () : FS_FW_NONE;
	if (r->was == FS_FW_STOPPED) {
		/* Already there: the backend's stop still runs, unlogged, and
		 * the blocklists come down: they live in their own table, so
		 * a firewall whose chains are gone can still hold them. */
		if (backend->stop != NULL)
			(void) backend->stop (NULL);
		intel_follow (r, actor, FALSE);
		if (!r->intel.ok)
			r->status = FS_CONTROL_FAILED;
		fs_policy_unlock (lock);
		return;
	}

	policy = load_policy (r, FALSE, NULL);
	settings = fs_settings_new ();
	fs_settings_load_prefs (settings);
	hand_context (policy, settings);

	if (fs_firewall_stop_logged (backend, actor->channel, &error)) {
		r->changed = TRUE;
		intel_follow (r, actor, FALSE);
		if (!r->intel.ok)
			r->status = FS_CONTROL_FAILED;
	} else {
		fail (r, FS_CONTROL_FAILED, NULL, "%s",
		      error != NULL ? error->message : "unknown error");
	}
	g_clear_error (&error);
	fs_policy_unlock (lock);
}

/* [ devices_present ] -- the backend's devices, NULL-ended. */
static gchar **
devices_present (void)
{
	const FsBackend *backend = fs_backend ();
	GPtrArray *names = g_ptr_array_new ();
	GList *ifaces = backend->list_interfaces != NULL
	              ? backend->list_interfaces () : NULL;

	for (GList *l = ifaces; l != NULL; l = l->next) {
		FsInterface *i = l->data;

		if (i->name != NULL)
			g_ptr_array_add (names, g_strdup (i->name));
	}
	g_list_free_full (ifaces, (GDestroyNotify) fs_interface_free);
	g_ptr_array_add (names, NULL);
	return (gchar **) g_ptr_array_free (names, FALSE);
}

/* [ default_text ] -- a table row's default as settings.set takes it. */
static const gchar *
default_text (const FsPrefSpec *spec)
{
	if (spec->type == FS_PREF_BOOL)
		return spec->bool_default ? "true" : "false";
	return spec->string_default != NULL ? spec->string_default : "";
}

/* [ op_settings_set ]
 * Root's copy of the preferences (master plan: the CLI writes
 * preferences, root's copy).  Validated as the Preferences window
 * would, then only the keys given are written (fs_prefs_set_persist).
 * "reset" names keys that go back to the table's default: checked as
 * that value, and removed from the file.  Turning audit-only mode on
 * or off is written to the audit log with the actor's channel. */
static void
op_settings_set (FsControlResult *r, const FsControlActor *actor,
                 GVariant *params)
{
	gsize nk = 0, nv = 0, nr = 0;
	const gchar **keys = p_strv (params, "keys", &nk);
	const gchar **values = p_strv (params, "values", &nv);
	const gchar **reset = p_strv (params, "reset", &nr);
	const FsBackend *backend = fs_backend ();
	gchar **devices;
	GError *error = NULL;
	GPtrArray *ck, *cv, *wk, *wv;
	GHashTableIter it;
	gpointer k, v;
	gboolean audit_before;

	if (!need_root (r, actor))
		goto out;
	if (nk != nv || nk + nr == 0) {
		fail (r, FS_CONTROL_USAGE, NULL,
		      "settings.set needs as many values as keys");
		goto out;
	}

	/* The set to check: the values given, and each reset key as its
	 * default. */
	ck = g_ptr_array_new ();
	cv = g_ptr_array_new ();
	for (gsize i = 0; i < nk; i++) {
		g_ptr_array_add (ck, (gpointer) keys[i]);
		g_ptr_array_add (cv, (gpointer) values[i]);
	}
	for (gsize i = 0; i < nr; i++) {
		const FsPrefSpec *spec = fs_prefs_spec (reset[i]);

		g_ptr_array_add (ck, (gpointer) reset[i]);
		g_ptr_array_add (cv, (gpointer) (spec != NULL
		                                 ? default_text (spec) : ""));
	}

	fs_prefs_load ();
	audit_before = fs_apply_audit_only ();
	devices = devices_present ();
	r->check = fs_prefs_validate ((const gchar * const *) ck->pdata,
	                              (const gchar * const *) cv->pdata,
	                              ck->len, backend->fw_sections,
	                              backend->fw_honors,
	                              (const gchar * const *) devices);
	g_strfreev (devices);
	g_ptr_array_unref (ck);
	g_ptr_array_unref (cv);
	if (r->check->refusals->len > 0) {
		const FsPrefsIssue *first = g_ptr_array_index (r->check->refusals,
		                                               0);

		fail (r, FS_CONTROL_USAGE, NULL, "%s", first->reason);
		goto out;
	}

	wk = g_ptr_array_new ();
	wv = g_ptr_array_new ();
	g_hash_table_iter_init (&it, r->check->values);
	while (g_hash_table_iter_next (&it, &k, &v)) {
		gboolean is_reset = FALSE;

		for (gsize i = 0; i < nr && !is_reset; i++)
			is_reset = g_strcmp0 (reset[i], k) == 0;
		g_ptr_array_add (wk, k);
		g_ptr_array_add (wv, is_reset ? NULL : v);
	}
	if (!fs_prefs_set_persist ((const gchar * const *) wk->pdata,
	                           (const gchar * const *) wv->pdata, wk->len,
	                           &r->prefs_unreadable, &error)) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_error_free (error);
	} else if (fs_apply_audit_only () != audit_before) {
		gchar *line = g_strdup_printf ("%s | %s", actor->channel,
		                               fs_apply_audit_only () ? "on"
		                                                      : "off");

		fs_audit_log ("audit-only mode", line);
		g_free (line);
	}
	g_ptr_array_unref (wk);
	g_ptr_array_unref (wv);

out:
	g_free (keys);
	g_free (values);
	g_free (reset);
}

/* [ op_settings_apply ] (J36)
 * The saved firewall settings, put in force under the policy that is
 * live (the journal's), with the lockout guard first; with no journal
 * they can only go out with the saved policy, which this applies too. */
static void
op_settings_apply (FsControlResult *r, const FsControlActor *actor,
                   GVariant *params)
{
	FsPolicyLock *lock;
	GError *error = NULL;
	FsPolicy *saved, *under;
	FsSettings *settings;
	gboolean on_disk = FALSE;

	if (!need_root (r, actor))
		return;
	lock = fs_policy_lock (&error);
	if (lock == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_error_free (error);
		return;
	}
	fs_prefs_load ();

	saved = load_policy (r, FALSE, &on_disk);
	under = fs_policy_new ();
	r->journal = fs_apply_journal_load (under, NULL);
	if (!r->journal) {
		fs_policy_free (under);
		if (!on_disk || (r->problems != NULL && r->problems->len > 0)) {
			fail (r, FS_CONTROL_FAILED, NULL,
			      "no applied policy is on record and the saved one "
			      "%s, so the settings have nothing to go out with",
			      !on_disk ? "is missing" : "has lines that are not "
			      "rules");
			fs_policy_free (saved);
			fs_policy_unlock (lock);
			return;
		}
		under = saved;
		saved = NULL;
	}
	r->unapplied = fs_policy_impact (r->journal ? under : NULL,
	                                 saved != NULL ? saved : under);

	settings = fs_settings_new ();
	fs_settings_load_prefs (settings);
	if (fs_apply_hold_reason () == NULL &&
	    !guard (r, under, settings, p_bool (params, "yes"))) {
		fs_settings_free (settings);
		fs_policy_free (under);
		fs_policy_free (saved);
		fs_policy_unlock (lock);
		return;
	}

	r->outcome = fs_settings_apply_saved (fs_backend (), set_context_func,
	                                      under, settings, NULL,
	                                      actor->channel,
	                                      fs_apply_hold_reason (), &error);
	/* The backend keeps the pair it was handed last. */
	hand_context (under, settings);

	if (r->outcome == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "nothing to apply");
	} else if (r->outcome->held || r->outcome->result == FS_APPLY_OK) {
		r->status = FS_CONTROL_OK;
	} else {
		fail (r, FS_CONTROL_FAILED, NULL, "%s",
		      error != NULL ? error->message
		      : fs_util_apply_result_to_string ((int) r->outcome->result));
	}
	g_clear_error (&error);
	fs_policy_free (saved);
	fs_policy_unlock (lock);
}

/* ----------------------------------------------------------- PR 4 ops */

/* Each package of PR 4 writes its op functions between its markers:
 * 4B copilot and sentinel, 4C event and What-If actions, 4D trust and
 * intel.  Core gives them fs_firewall_add_live, the fs_autoblock_lift_*
 * helpers and fs_intel_exceptions_from_text (4A). */

/* === PR4-B === */

/* [ live_context ]
 * The backend's context for a live edit (add_live, lift_live): the
 * policy as saved and the settings that are live -- the journal's when
 * it records them (3B), else the saved preferences -- so a live edit
 * never carries a settings change nobody applied. */
static void
live_context (const FsPolicy *policy)
{
	FsSettings *settings = fs_settings_from_journal (NULL);

	gboolean recorded = (settings != NULL);

	if (settings == NULL) {
		settings = fs_settings_new ();
		fs_settings_load_prefs (settings);
	}
	hand_context (policy_copy (policy), settings);
	/* The journal then keeps the settings it records (fs-apply.h). */
	fs_firewall_live_keeps_settings (recorded);
}

/* [ live_failed ] -- an outcome that is neither OK, held nor a dry
 * run (a stopped firewall's "recorded for the next start"). */
static gboolean
live_failed (const FsApplyOutcome *o)
{
	return o != NULL && !o->held && o->result != FS_APPLY_OK &&
	       o->result != FS_APPLY_DRY_RUN;
}

/* [ lift_done ] -- the status of a lift helper's result. */
static void
lift_done (FsControlResult *r, FsAutoblockLift *lift, const GError *error)
{
	r->lift = lift;
	if (lift == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s",
		      error != NULL ? error->message : "the lift did not run");
		return;
	}
	if (live_failed (lift->outcome)) {
		fail (r, lift->outcome->result == FS_APPLY_NO_PRIVILEGE
		      ? FS_CONTROL_NEED_ROOT : FS_CONTROL_FAILED, NULL,
		      "the blocks left the policy, but the firewall was not "
		      "changed: %s", error != NULL ? error->message
		      : fs_util_apply_result_to_string (
		            (int) lift->outcome->result));
		return;
	}
	if (!lift->state_saved)
		fail (r, FS_CONTROL_FAILED, NULL,
		      "Sentinel's state file could not be written");
}

/* [ op_sentinel_lift ] -- G8, A16: `sentinel lift TARGET|--all|
 * --expired'. */
static void
op_sentinel_lift (FsControlResult *r, const FsControlActor *actor,
                  GVariant *params)
{
	const gchar *target = p_str (params, "target");
	gboolean all = p_bool (params, "all");
	gboolean expired = p_bool (params, "expired");
	FsAutoblockLift *lift;
	FsPolicyLock *lock;
	GError *error = NULL;

	if ((target != NULL && *target != '\0') + all + expired != 1) {
		fail (r, FS_CONTROL_USAGE, NULL,
		      "name one of target, all or expired");
		return;
	}
	if (!need_root (r, actor))
		return;
	lock = fs_policy_lock (&error);
	if (lock == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_error_free (error);
		return;
	}
	r->policy = load_policy (r, TRUE, NULL);
	if (r->policy == NULL) {
		fs_policy_unlock (lock);
		return;
	}
	fs_prefs_load ();
	live_context (r->policy);
	if (all)
		lift = fs_autoblock_lift_all (fs_backend (), r->policy, NULL,
		                              actor->channel,
		                              fs_apply_hold_reason (), &error);
	else if (expired)
		lift = fs_autoblock_lift_expired (fs_backend (), r->policy,
		                                  g_get_real_time () /
		                                  G_USEC_PER_SEC, actor->channel,
		                                  fs_apply_hold_reason (), &error);
	else
		lift = fs_autoblock_lift_for_dest (fs_backend (), r->policy,
		                                   target, "lifted by user",
		                                   actor->channel,
		                                   fs_apply_hold_reason (),
		                                   &error);
	lift_done (r, lift, error);
	g_clear_error (&error);
	fs_policy_unlock (lock);
}

/* [ op_sentinel_mode ] -- G1: the mode saved; "detect" lifts every
 * block Sentinel staged, as the Copilot page's switch does. */
static void
op_sentinel_mode (FsControlResult *r, const FsControlActor *actor,
                  GVariant *params)
{
	const gchar *mode = p_str (params, "mode");
	const gchar *keys[1] = { FS_PREFS_SENTINEL_MODE };
	const gchar *values[1];
	FsPolicyLock *lock;
	GError *error = NULL;
	gboolean bad = FALSE;

	if (g_strcmp0 (mode, "auto") != 0 && g_strcmp0 (mode, "detect") != 0) {
		fail (r, FS_CONTROL_USAGE, NULL,
		      "Sentinel's mode is auto or detect, not %s",
		      mode != NULL ? mode : "(none)");
		return;
	}
	if (!need_root (r, actor))
		return;
	lock = fs_policy_lock (&error);
	if (lock == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_error_free (error);
		return;
	}
	fs_prefs_load ();
	r->mode_was = fs_prefs_get_string (FS_PREFS_SENTINEL_MODE, "auto");
	if (r->mode_was == NULL || *r->mode_was == '\0') {
		g_free (r->mode_was);
		r->mode_was = g_strdup ("auto");
	}
	values[0] = mode;
	if (!fs_prefs_set_persist (keys, values, 1, &bad, &error)) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_clear_error (&error);
		fs_policy_unlock (lock);
		return;
	}
	r->prefs_unreadable = bad;
	r->mode = g_strdup (mode);
	{
		gchar *detail = g_strdup_printf ("%s -> %s (%s)", r->mode_was,
		                                 mode, actor->channel);

		fs_audit_log ("sentinel mode", detail);
		g_free (detail);
	}

	if (strcmp (mode, "detect") == 0) {
		FsAutoblockLift *lift;

		r->policy = load_policy (r, TRUE, NULL);
		if (r->policy == NULL) {
			/* The mode is saved; the blocks stay until they
			 * expire.  r says why. */
			fs_policy_unlock (lock);
			return;
		}
		live_context (r->policy);
		lift = fs_autoblock_lift_all (fs_backend (), r->policy,
		                              "Sentinel switched to detect only",
		                              actor->channel,
		                              fs_apply_hold_reason (), &error);
		lift_done (r, lift, error);
		g_clear_error (&error);
	}
	fs_policy_unlock (lock);
}

/* [ whatif_verdict ] -- `line' against `policy' with the saved
 * preferences, the firewall taken as running the policy. */
static FsWhatIfVerdict
whatif_verdict (const FsControlActor *actor, const FsPolicy *policy,
                const FsSettings *settings, const gchar *line)
{
	FsWhatIfContext *ctx = fs_whatif_context_new (
		fs_whatif_native_platform (), policy, settings);
	FsWhatIfResult *w;
	FsWhatIfVerdict v;

	fs_copilot_whatif_observe (ctx, fs_backend (), actor->uid == 0);
	ctx->firewall = FS_WHATIF_FW_RUNNING;
	ctx->live = FS_WHATIF_LIVE_YES;
	w = fs_whatif_simulate_text (ctx, line);
	v = w->verdict;
	fs_whatif_result_free (w);
	fs_whatif_context_free (ctx);
	return v;
}

/* [ block_verdicts ]
 * The What-If check of a block rule (ui/fs-copilot.c block_rule_verify):
 * `line' against the saved policy, then with `rule' added.  The rule is
 * a help only when it turns ALLOWED into BLOCKED. */
static void
block_verdicts (FsControlResult *r, const FsControlActor *actor,
                const FsPolicy *policy, const FsRule *rule,
                const gchar *line)
{
	FsSettings *settings = fs_settings_new ();
	FsPolicy *with = policy_copy (policy);

	fs_settings_load_prefs (settings);
	r->whatif_before = whatif_verdict (actor, policy, settings, line);
	fs_policy_add (with, (FsRule *) rule);   /* copied */
	r->whatif_after = whatif_verdict (actor, with, settings, line);
	fs_policy_free (with);
	fs_settings_free (settings);
}

/* [ op_copilot_block ] -- G7: "Block outbound to this address". */
static void
op_copilot_block (FsControlResult *r, const FsControlActor *actor,
                  GVariant *params)
{
	const gchar *csv = p_str (params, "csv");
	const gchar *line = p_str (params, "whatif");
	FsRuleKind kind;
	FsPolicyLock *lock;
	FsPolicy *add, *journal;
	GError *error = NULL;

	if (!fs_control_kind_parse (p_str (params, "kind"), &kind) ||
	    kind != FS_RULE_OUTBOUND_DENY_TO) {
		fail (r, FS_CONTROL_USAGE, NULL,
		      "a Copilot block is an outbound-deny-to rule");
		return;
	}
	if (csv == NULL || line == NULL || *line == '\0') {
		fail (r, FS_CONTROL_USAGE, NULL,
		      "a Copilot block needs its rule and its What-If line");
		return;
	}
	r->rule = fs_rule_from_csv (kind, csv);
	if (r->rule == NULL) {
		fail (r, FS_CONTROL_USAGE, NULL, "the rule could not be read");
		return;
	}
	/* The user's own rule now, not Sentinel's: a "Sentinel:" comment
	 * would let a later lift for the address take it out
	 * (fs_autoblock_lift_for_dest). */
	if (r->rule->comment != NULL &&
	    g_str_has_prefix (r->rule->comment, "Sentinel:")) {
		gchar *c = g_strconcat ("Copilot:",
		                        r->rule->comment + strlen ("Sentinel:"),
		                        NULL);

		g_free (r->rule->comment);
		r->rule->comment = c;
	}
	if (!rule_checked (r, r->rule))
		return;
	r->whatif_line = g_strdup (line);
	r->whatif_before = r->whatif_after = FS_WHATIF_ERROR;
	if (!need_root (r, actor))
		return;

	lock = fs_policy_lock (&error);
	if (lock == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_error_free (error);
		return;
	}
	fs_prefs_load ();
	r->policy = load_policy (r, TRUE, NULL);
	if (r->policy == NULL)
		goto out;
	if (fs_policy_contains (r->policy, r->rule)) {
		r->already = TRUE;
		r->number = rule_number (r->policy, r->rule);
		fail (r, FS_CONTROL_USAGE, NULL,
		      "that rule is already in your policy");
		goto out;
	}

	/* Checked again now, on the policy as it is under the lock. */
	block_verdicts (r, actor, r->policy, r->rule, line);
	if (r->whatif_before != FS_WHATIF_ALLOWED) {
		fail (r, FS_CONTROL_USAGE, NULL,
		      "What-If says \"%s\" is %s already, so a block rule would "
		      "change nothing", line,
		      fs_whatif_verdict_name (r->whatif_before));
		goto out;
	}
	if (r->whatif_after != FS_WHATIF_BLOCKED) {
		fail (r, FS_CONTROL_USAGE, NULL,
		      "What-If says the rule would leave \"%s\" %s", line,
		      fs_whatif_verdict_name (r->whatif_after));
		goto out;
	}

	/* The lockout guard, on what goes live: the journal plus the rule. */
	journal = fs_policy_new ();
	if (fs_apply_hold_reason () == NULL &&
	    fs_apply_journal_load (journal, NULL)) {
		FsSettings *settings = fs_settings_from_journal (NULL);
		gboolean ok;

		if (settings == NULL) {
			settings = fs_settings_new ();
			fs_settings_load_prefs (settings);
		}
		if (!fs_policy_contains (journal, r->rule))
			fs_policy_add (journal, r->rule);
		ok = guard (r, journal, settings, p_bool (params, "yes"));
		fs_settings_free (settings);
		if (!ok) {
			fs_policy_free (journal);
			goto out;
		}
	}
	fs_policy_free (journal);

	if (!fs_policy_add_persist (r->policy, r->rule)) {
		save_failed (r);
		goto out;
	}
	r->saved = TRUE;
	r->number = rule_number (r->policy, r->rule);
	{
		gchar *row = fs_rule_to_csv (r->rule);
		gchar *detail = g_strdup_printf ("%s (%s)", row, actor->channel);

		fs_audit_log ("copilot block rule added", detail);
		g_free (detail);
		r->change_id = fs_changelog_add_block_rule (kind, row,
		                                            actor->channel,
		                                            &error);
		g_free (row);
		if (r->change_id == 0) {
			r->change_error = g_strdup (error->message);
			g_clear_error (&error);
		}
	}

	add = fs_policy_new ();
	fs_policy_add (add, r->rule);
	live_context (r->policy);
	r->outcome = fs_firewall_add_live (fs_backend (), add, actor->channel,
	                                   fs_apply_hold_reason (), &error);
	fs_policy_free (add);
	if (r->outcome == NULL && error != NULL)
		fail (r, FS_CONTROL_FAILED, NULL,
		      "the rule is saved, but it was not put live: %s",
		      error->message);
	else if (live_failed (r->outcome))
		fail (r, r->outcome->result == FS_APPLY_NO_PRIVILEGE
		      ? FS_CONTROL_NEED_ROOT : FS_CONTROL_FAILED, NULL,
		      "the rule is saved, but it was not put live: %s",
		      error != NULL ? error->message
		      : fs_util_apply_result_to_string (
		            (int) r->outcome->result));
	g_clear_error (&error);
out:
	fs_policy_unlock (lock);
}

/* [ health_findings ] -- the Copilot page's health check on `policy',
 * with the context `copilot health' builds. */
static GPtrArray *
health_findings (const FsControlActor *actor, const FsPolicy *policy)
{
	FsSettings *settings = fs_settings_new ();
	FsWhatIfContext *ctx;
	GPtrArray *findings;
	gchar *prefix;

	fs_settings_load_prefs (settings);
	ctx = fs_whatif_context_new (fs_whatif_native_platform (), policy,
	                             settings);
	fs_copilot_whatif_observe (ctx, fs_backend (), actor->uid == 0);
	prefix = fs_health_lan_prefix_auto (fs_backend ());
	findings = fs_health_check (ctx, prefix);
	g_free (prefix);
	fs_whatif_context_free (ctx);
	fs_settings_free (settings);
	return findings;
}

/* [ op_copilot_fix ] -- G11: a health fix, made only when the check,
 * run again under the lock, still offers the fix the caller showed. */
static void
op_copilot_fix (FsControlResult *r, const FsControlActor *actor,
                GVariant *params)
{
	guint number = p_uint (params, "number");
	const gchar *before = p_str (params, "before");
	const gchar *after = p_str (params, "after");
	const gchar *label = p_str (params, "label");
	FsPolicyLock *lock;
	GPtrArray *findings = NULL;
	const FsHealthFinding *f;
	FsHealthUndo *undo = NULL;
	GError *error = NULL;
	gchar *why = NULL;

	if (number == 0 || before == NULL || label == NULL) {
		fail (r, FS_CONTROL_USAGE, NULL,
		      "a fix needs the finding's number, its before row and its "
		      "label");
		return;
	}
	lock = fs_policy_lock (&error);
	if (lock == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_error_free (error);
		return;
	}
	fs_prefs_load ();
	r->policy = load_policy (r, TRUE, NULL);
	if (r->policy == NULL)
		goto out;
	findings = health_findings (actor, r->policy);
	f = number <= findings->len ? g_ptr_array_index (findings, number - 1)
	                            : NULL;
	if (f == NULL || f->fix == FS_HEALTH_FIX_NONE || !f->verified ||
	    g_strcmp0 (f->fix_before, before) != 0 ||
	    g_strcmp0 (f->fix_after, after) != 0 ||
	    g_strcmp0 (f->fix_label, label) != 0) {
		fail (r, FS_CONTROL_CONFLICT, NULL,
		      "the policy changed since the check, and finding %u no "
		      "longer offers that fix; nothing was written", number);
		goto out;
	}
	r->fix_label = g_strdup (f->fix_label);
	r->fix_before = g_strdup (f->fix_before);
	r->fix_after = g_strdup (f->fix_after);
	r->fix_whatif = g_strdup (f->whatif_line);
	if (!fs_health_fix_apply (r->policy, f, &undo, &why)) {
		fail (r, FS_CONTROL_FAILED, NULL, "nothing was changed: %s",
		      why != NULL ? why : "?");
		g_free (why);
		goto out;
	}
	r->saved = TRUE;
	r->change_id = fs_changelog_add_health_fix (undo, actor->channel,
	                                            &error);
	if (r->change_id == 0) {
		r->change_error = g_strdup (error->message);
		g_clear_error (&error);
	}
	fs_health_undo_free (undo);
out:
	if (findings != NULL)
		g_ptr_array_unref (findings);
	fs_policy_unlock (lock);
}

/* [ op_copilot_undo ] -- G13: a change of the log put back. */
static void
op_copilot_undo (FsControlResult *r, const FsControlActor *actor,
                 GVariant *params)
{
	guint id = p_uint (params, "id");
	FsPolicyLock *lock;
	FsChange *c;
	GError *error = NULL;
	gchar *why = NULL;

	lock = fs_policy_lock (&error);
	if (lock == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_error_free (error);
		return;
	}
	c = fs_changelog_find (id, &error);
	if (c == NULL) {
		if (error != NULL)
			fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		else
			fail (r, FS_CONTROL_USAGE, NULL,
			      "there is no change %u in the change log", id);
		g_clear_error (&error);
		fs_policy_unlock (lock);
		return;
	}
	r->change_id = c->id;
	r->change_kind = g_strdup (fs_change_kind_name (c->kind));
	r->fix_label = g_strdup (c->label);
	if (c->undone_at != 0) {
		fail (r, FS_CONTROL_USAGE, NULL, "change %u was undone already",
		      id);
		goto out;
	}
	if (c->kind == FS_CHANGE_BLOCK_RULE && !need_root (r, actor))
		goto out;

	fs_prefs_load ();
	r->policy = load_policy (r, TRUE, NULL);
	if (r->policy == NULL)
		goto out;

	if (c->kind == FS_CHANGE_HEALTH_FIX) {
		r->fix_before = g_strdup (c->undo->before_csv);
		r->fix_after = g_strdup (c->undo->after_csv);
		if (!fs_health_undo_apply (r->policy, c->undo, &why)) {
			fail (r, FS_CONTROL_FAILED, NULL, "nothing was changed: %s",
			      why != NULL ? why : "?");
			g_free (why);
			goto out;
		}
	} else {
		FsRule *rule = fs_rule_from_csv (c->rule_kind, c->csv);
		FsPolicy *lift;

		if (rule == NULL || !fs_policy_contains (r->policy, rule)) {
			fs_rule_free (rule);
			fail (r, FS_CONTROL_FAILED, NULL,
			      "the rule is no longer in the policy; nothing was "
			      "changed");
			goto out;
		}
		if (!fs_policy_remove_persist (r->policy, rule)) {
			fs_rule_free (rule);
			save_failed (r);
			goto out;
		}
		r->rule = rule;
		{
			gchar *detail = g_strdup_printf ("%s (%s)", c->csv,
			                                 actor->channel);

			fs_audit_log ("copilot block rule undone", detail);
			g_free (detail);
		}
		lift = fs_policy_new ();
		fs_policy_add (lift, rule);
		live_context (r->policy);
		r->outcome = fs_firewall_lift_live (fs_backend (), lift,
		                                    actor->channel,
		                                    fs_apply_hold_reason (),
		                                    &error);
		fs_policy_free (lift);
		if (r->outcome == NULL && error != NULL)
			fail (r, FS_CONTROL_FAILED, NULL,
			      "the rule left the policy, but not the firewall: %s",
			      error->message);
		else if (live_failed (r->outcome))
			fail (r, FS_CONTROL_FAILED, NULL,
			      "the rule left the policy, but not the firewall: %s",
			      error != NULL ? error->message
			      : fs_util_apply_result_to_string (
			            (int) r->outcome->result));
		g_clear_error (&error);
	}
	r->saved = TRUE;
	if (!fs_changelog_mark_undone (c->id, actor->channel, &error)) {
		r->change_error = g_strdup (error->message);
		g_clear_error (&error);
	}
out:
	fs_change_free (c);
	fs_policy_unlock (lock);
}

/* === end PR4-B === */

/* === PR4-C === */
/* Event and What-If actions (4C): `events act' and `simulate --do'.
 *
 *   rule.block    a deny row (and, with "both", its twin) is saved, then
 *                 put on the firewall alone through fs_firewall_add_live:
 *                 the journal plus the rows, never the saved file, so a
 *                 saved allow that nobody applied stays off (C14)
 *   rule.allow    an allow row is saved; "lift_dest" then lifts
 *                 Sentinel's blocks of that address
 *                 (fs_autoblock_lift_for_dest, C14); then the saved
 *                 policy is applied, as `apply' does: an allow widens
 *                 what gets through, so the terminal shows the whole
 *                 apply before it asks.  With the firewall stopped
 *                 (fs_firewall_live_records_only) nothing is applied:
 *                 the rows are recorded for the next start through
 *                 fs_firewall_add_live, and the firewall stays stopped
 *   rule.untrust  the inbound-allow-from row for "target" is removed and
 *                 taken off the firewall alone (fs_firewall_lift_live,
 *                 C15)
 *   whatif.lift   Sentinel's blocks of "target" are lifted (H9)
 *
 * "no_apply" b: rule.* only save.  "whatif" b: the row is a What-If fix
 * and must pass fs_whatif_row_is_safe (H8), whoever sends it.  "from"
 * s: "event" or "whatif", for the audit line.  Live work needs root,
 * and the lockout guard stands in front of it (CONFIRM: nothing
 * changed). */

static gboolean
kind_is_block (FsRuleKind kind)
{
	return kind == FS_RULE_OUTBOUND_DENY_TO ||
	       kind == FS_RULE_OUTBOUND_DENY_FROM ||
	       kind == FS_RULE_OUTBOUND_DENY_SERVICE;
}

/* [ act_rows ] -- the row (and its twin) of rule.block or rule.allow,
 * checked.  FALSE: refused, r says why. */
static gboolean
act_rows (FsControlResult *r, GVariant *params, gboolean block)
{
	FsRuleKind kind;
	gsize n = 0;
	const gchar **fields;

	if (!fs_control_kind_parse (p_str (params, "kind"), &kind)) {
		fail (r, FS_CONTROL_USAGE, NULL, "not a rule kind: %s",
		      p_str (params, "kind") != NULL ? p_str (params, "kind")
		                                     : "(none)");
		return FALSE;
	}
	if (kind_is_block (kind) != block || kind == FS_RULE_INBOUND_FORWARD) {
		fail (r, FS_CONTROL_USAGE, NULL, "%s is not %s rule",
		      kind_names[kind], block ? "a block" : "an allow");
		return FALSE;
	}
	fields = p_strv (params, "fields", &n);
	r->rule = rule_from_fields (r, kind, fields, n,
	                            p_str (params, "comment"));
	g_free (fields);
	if (r->rule == NULL || !rule_checked (r, r->rule))
		return FALSE;

	/* A What-If fix: only a row StockFW may write on the user's behalf
	 * (one address or block, one port, one protocol). */
	if (p_bool (params, "whatif")) {
		FsWhatIfAction act;
		gchar *why = NULL;

		memset (&act, 0, sizeof act);
		act.kind = block ? FS_WHATIF_ACT_CREATE_BLOCK
		                 : FS_WHATIF_ACT_CREATE_ALLOW;
		act.row = r->rule;
		if (!fs_whatif_row_is_safe (&act, &why)) {
			fail (r, FS_CONTROL_USAGE, NULL,
			      "not a rule StockFW writes for you: %s",
			      why != NULL ? why : "it was not checked");
			g_free (why);
			return FALSE;
		}
	}

	if (p_bool (params, "both")) {
		r->twin = fs_rule_counterpart (r->rule);
		if (r->twin == NULL) {
			fail (r, FS_CONTROL_USAGE, NULL,
			      "%s has no opposite-direction twin; --both only "
			      "applies to allow rules", kind_names[kind]);
			return FALSE;
		}
	}
	return TRUE;
}

/* [ act_audit ] -- "event rule added | cli | <csv>". */
static void
act_audit (const FsControlActor *actor, GVariant *params, const gchar *what,
           const FsRule *rule)
{
	gboolean whatif = g_strcmp0 (p_str (params, "from"), "whatif") == 0;
	gchar *csv = fs_rule_to_csv (rule);
	gchar *action = g_strdup_printf ("%s %s", whatif ? "what-if" : "event",
	                                 what);
	gchar *detail = g_strdup_printf ("%s | %s", actor->channel, csv);

	fs_audit_log (action, detail);
	g_free (detail);
	g_free (action);
	g_free (csv);
}

/* [ act_save ] -- the rows saved, under the lock (r->policy is the
 * policy read under it); "already" when they are all there.  FALSE:
 * the save failed. */
static gboolean
act_save (FsControlResult *r, const FsControlActor *actor, GVariant *params)
{
	if (fs_policy_contains (r->policy, r->rule) &&
	    (r->twin == NULL || fs_policy_contains (r->policy, r->twin))) {
		r->already = TRUE;
	} else {
		gboolean ok = r->twin != NULL
		            ? fs_policy_add_persist_pair (r->policy, r->rule,
		                                          r->twin)
		            : fs_policy_add_persist (r->policy, r->rule);

		if (!ok) {
			save_failed (r);
			return FALSE;
		}
		r->saved = TRUE;
		act_audit (actor, params, "rule added", r->rule);
		if (r->twin != NULL)
			act_audit (actor, params, "rule added (bi-directional twin)",
			           r->twin);
	}
	r->number = rule_number (r->policy, r->rule);
	if (r->twin != NULL)
		r->twin_number = rule_number (r->policy, r->twin);
	return TRUE;
}

/* [ saved_settings ] -- the saved Firewall preferences, read now. */
static FsSettings *
saved_settings (void)
{
	FsSettings *settings = fs_settings_new ();

	fs_prefs_load ();
	fs_settings_load_prefs (settings);
	return settings;
}

/* [ journal_edit ] -- the journal (what is live) with the rows of `add'
 * in it, or `drop' out of it; NULL when there is no journal. */
static FsPolicy *
journal_edit (const FsPolicy *add, FsRule *drop)
{
	FsPolicy *j = fs_policy_new ();

	if (!fs_apply_journal_load (j, NULL)) {
		fs_policy_free (j);
		return NULL;
	}
	for (gint k = 0; add != NULL && k < FS_RULE_N_KINDS; k++)
		for (guint i = 0; i < add->kinds[k]->len; i++) {
			FsRule *row = g_ptr_array_index (add->kinds[k], i);

			if (!fs_policy_contains (j, row))
				fs_policy_add (j, row);
		}
	if (drop != NULL)
		fs_policy_remove (j, drop);
	return j;
}

/* [ act_guard ] -- the lockout guard on `after' (taken), unless a hold
 * keeps the firewall untouched or there is no `after'.  `live_edit':
 * `after' goes out through add_live or lift_live, under the settings
 * that are live (live_context), not the saved ones.  FALSE: CONFIRM,
 * nothing changed. */
static gboolean
act_guard (FsControlResult *r, GVariant *params, FsPolicy *after,
           gboolean live_edit)
{
	FsSettings *settings;
	gboolean ok = TRUE;

	if (after == NULL)
		return TRUE;
	if (fs_apply_hold_reason () == NULL) {
		settings = live_edit ? fs_settings_from_journal (NULL) : NULL;
		if (settings == NULL)
			settings = saved_settings ();
		ok = guard (r, after, settings, p_bool (params, "yes"));
		fs_settings_free (settings);
	}
	fs_policy_free (after);
	return ok;
}

/* [ live_result ] -- r's status after a live edit.  A NULL outcome with
 * no error: nothing to change on the firewall (no journal, or the rows
 * are live already, or not live). */
static void
live_result (FsControlResult *r, GError *error)
{
	if (r->outcome == NULL) {
		if (error != NULL)
			fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		else
			r->live_none = TRUE;
		return;
	}
	if (r->outcome->held || r->outcome->result == FS_APPLY_OK ||
	    r->outcome->result == FS_APPLY_DRY_RUN)
		return;
	fail (r, r->outcome->result == FS_APPLY_NO_PRIVILEGE
	         ? FS_CONTROL_NEED_ROOT : FS_CONTROL_FAILED, NULL, "%s",
	      error != NULL ? error->message
	      : fs_util_apply_result_to_string ((int) r->outcome->result));
}

/* [ act_lock ] -- the policy lock, and the policy read under it. */
static FsPolicyLock *
act_lock (FsControlResult *r)
{
	GError *error = NULL;
	FsPolicyLock *lock = fs_policy_lock (&error);
	FsPolicy *journal;

	if (lock == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_error_free (error);
		return NULL;
	}
	r->policy = load_policy (r, TRUE, NULL);
	if (r->policy == NULL) {
		fs_policy_unlock (lock);
		return NULL;
	}
	journal = fs_policy_new ();
	r->journal = fs_apply_journal_load (journal, NULL);
	fs_policy_free (journal);
	return lock;
}

static void
op_rule_block (FsControlResult *r, const FsControlActor *actor,
               GVariant *params)
{
	gboolean live = !p_bool (params, "no_apply");
	FsPolicyLock *lock;
	FsPolicy *add;
	GError *error = NULL;

	if (!act_rows (r, params, TRUE))
		return;
	if (live && !need_root (r, actor))
		return;
	lock = act_lock (r);
	if (lock == NULL)
		return;

	add = fs_policy_new ();
	fs_policy_add (add, r->rule);
	if (r->twin != NULL)
		fs_policy_add (add, r->twin);

	/* Guarded on what will be live: the journal plus the rows. */
	if ((!live || act_guard (r, params, journal_edit (add, NULL), TRUE)) &&
	    act_save (r, actor, params) && live) {
		live_context (r->policy);
		r->outcome = fs_firewall_add_live (fs_backend (), add,
		                                   actor->channel,
		                                   fs_apply_hold_reason (), &error);
		live_result (r, error);
	}
	g_clear_error (&error);
	fs_policy_free (add);
	fs_policy_unlock (lock);
}

static void
op_rule_allow (FsControlResult *r, const FsControlActor *actor,
               GVariant *params)
{
	gboolean live = !p_bool (params, "no_apply");
	const gchar *dest = p_str (params, "lift_dest");
	FsPolicyLock *lock;
	FsPolicy *after, *add;
	GError *error = NULL;
	gboolean record;

	if (!act_rows (r, params, FALSE))
		return;
	if (live && !need_root (r, actor))
		return;
	lock = act_lock (r);
	if (lock == NULL)
		return;

	/* PR 4 review: a stopped firewall stays stopped.  An apply there
	 * would start it (on Linux an apply IS a start), so the rows are
	 * only recorded for the next start, as a block is (add_live). */
	record = live && fs_firewall_live_records_only (fs_backend (),
	                                                fs_apply_hold_reason ());
	add = fs_policy_new ();
	fs_policy_add (add, r->rule);
	if (r->twin != NULL)
		fs_policy_add (add, r->twin);

	/* Guarded on what will be live: the whole saved policy, rows in
	 * (or, stopped, the journal plus the rows: what the start puts
	 * back). */
	if (live) {
		if (record) {
			after = journal_edit (add, NULL);
		} else {
			after = policy_copy (r->policy);
			if (!fs_policy_contains (after, r->rule))
				fs_policy_add (after, r->rule);
			if (r->twin != NULL && !fs_policy_contains (after, r->twin))
				fs_policy_add (after, r->twin);
		}
		if (!act_guard (r, params, after, record)) {
			fs_policy_free (add);
			fs_policy_unlock (lock);
			return;
		}
	}
	if (!act_save (r, actor, params) || !live) {
		fs_policy_free (add);
		fs_policy_unlock (lock);
		return;
	}

	/* The user's Allow is the last word for this address: Sentinel's
	 * blocks of it go first, as on the Events page (P6). */
	if (dest != NULL && *dest != '\0') {
		hand_context (policy_copy (r->policy), saved_settings ());
		r->lift = fs_autoblock_lift_for_dest (fs_backend (), r->policy,
		                                      dest, NULL, actor->channel,
		                                      fs_apply_hold_reason (),
		                                      &error);
		if (r->lift == NULL)
			r->lift_error = g_strdup (error != NULL ? error->message
			                          : "the lift was refused");
		g_clear_error (&error);
		/* The lift wrote the file: read it again. */
		fs_policy_free (r->policy);
		r->policy = load_policy (r, FALSE, NULL);
	}

	if (record) {
		live_context (r->policy);
		r->outcome = fs_firewall_add_live (fs_backend (), add,
		                                   actor->channel,
		                                   fs_apply_hold_reason (), &error);
		live_result (r, error);
		g_clear_error (&error);
	} else {
		apply_now (r, actor, policy_copy (r->policy), saved_settings ());
	}
	fs_policy_free (add);
	if (r->lift_error != NULL && r->status == FS_CONTROL_OK)
		fail (r, FS_CONTROL_FAILED, NULL,
		      "Sentinel's block of %s could not be lifted: %s", dest,
		      r->lift_error);
	fs_policy_unlock (lock);
}

static void
op_rule_untrust (FsControlResult *r, const FsControlActor *actor,
                 GVariant *params)
{
	gboolean live = !p_bool (params, "no_apply");
	const gchar *target = p_str (params, "target");
	GPtrArray *rows;
	FsRule *row = NULL;
	FsPolicyLock *lock;
	GError *error = NULL;

	if (target == NULL || *target == '\0') {
		fail (r, FS_CONTROL_USAGE, NULL, "no source address given");
		return;
	}
	if (live && !need_root (r, actor))
		return;
	lock = act_lock (r);
	if (lock == NULL)
		return;

	/* Matched on the address alone, as the Events page does: the row
	 * may carry any comment. */
	rows = r->policy->kinds[FS_RULE_INBOUND_ALLOW_FROM];
	for (guint i = 0; i < rows->len && row == NULL; i++) {
		FsRule *x = g_ptr_array_index (rows, i);

		if (x->target != NULL &&
		    g_ascii_strcasecmp (x->target, target) == 0) {
			row = x;
			r->number = i + 1;
		}
	}
	if (row == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL,
		      "%s is not trusted: no inbound-allow-from rule names it, "
		      "so the default-deny inbound policy already blocks it",
		      target);
		fs_policy_unlock (lock);
		return;
	}
	r->rule = fs_rule_copy (row);

	/* Guarded on what will be live: the journal less the row. */
	if (live && !act_guard (r, params, journal_edit (NULL, r->rule), TRUE)) {
		fs_policy_unlock (lock);
		return;
	}
	if (!fs_policy_remove_persist (r->policy, row)) {
		save_failed (r);
		fs_policy_unlock (lock);
		return;
	}
	r->saved = TRUE;
	act_audit (actor, params, "trust removed", r->rule);

	if (live) {
		FsPolicy *lift = fs_policy_new ();

		fs_policy_add (lift, r->rule);
		live_context (r->policy);
		r->outcome = fs_firewall_lift_live (fs_backend (), lift,
		                                    actor->channel,
		                                    fs_apply_hold_reason (), &error);
		live_result (r, error);
		fs_policy_free (lift);
	}
	g_clear_error (&error);
	fs_policy_unlock (lock);
}

static void
op_whatif_lift (FsControlResult *r, const FsControlActor *actor,
                GVariant *params)
{
	const gchar *target = p_str (params, "target");
	const FsApplyOutcome *o;
	FsPolicyLock *lock;
	GError *error = NULL;

	if (target == NULL || *target == '\0') {
		fail (r, FS_CONTROL_USAGE, NULL, "no address given");
		return;
	}
	if (!need_root (r, actor))
		return;
	lock = act_lock (r);
	if (lock == NULL)
		return;

	live_context (r->policy);
	r->lift = fs_autoblock_lift_for_dest (fs_backend (), r->policy, target,
	                                      "lifted from What-If",
	                                      actor->channel,
	                                      fs_apply_hold_reason (), &error);
	o = r->lift != NULL ? r->lift->outcome : NULL;
	if (r->lift == NULL)
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error != NULL
		      ? error->message : "the lift was refused");
	else if (r->lift->rows == 0 && r->lift->removed == 0)
		fail (r, FS_CONTROL_FAILED, NULL,
		      "no Sentinel block of %s could be lifted (it may have "
		      "expired already)", target);
	else if (o != NULL && !o->held && o->result != FS_APPLY_OK &&
	         o->result != FS_APPLY_DRY_RUN)
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error != NULL
		      ? error->message
		      : fs_util_apply_result_to_string ((int) o->result));
	g_clear_error (&error);
	fs_policy_unlock (lock);
}
/* === end PR4-C === */

/* === PR4-D === */

/* [ p_text ] -- a text param as a string (s) or as bytes (ay): a file
 * the terminal read may hold bytes that are not UTF-8 (a comment in
 * Latin-1), which a GVariant string cannot carry.  Borrowed. */
static const gchar *
p_text (GVariant *params, const gchar *key)
{
	const gchar *s = NULL;

	if (params == NULL)
		return NULL;
	if (g_variant_lookup (params, key, "&s", &s) ||
	    g_variant_lookup (params, key, "^&ay", &s))
		return s;
	return NULL;
}

/* [ intel_fail ] -- an engine error as the op's status; frees it.  A
 * store that needs root is NEED_ROOT, a bad request (unknown id, a
 * value that does not read) USAGE, anything else FAILED. */
static void
intel_fail (FsControlResult *r, GError *error, const gchar *what)
{
	FsControlStatus status = FS_CONTROL_FAILED;

	if (g_error_matches (error, FS_INTEL_ERROR, FS_INTEL_ERR_NEEDS_ROOT))
		status = FS_CONTROL_NEED_ROOT;
	else if (g_error_matches (error, FS_INTEL_ERROR, FS_INTEL_ERR_UNKNOWN) ||
	         g_error_matches (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID) ||
	         g_error_matches (error, FS_INTEL_ERROR, FS_INTEL_ERR_CONSENT))
		status = FS_CONTROL_USAGE;
	fail (r, status, NULL, "%s", error != NULL ? error->message : what);
	g_clear_error (&error);
}

/* [ intel_put_in_force ]
 * After a save (F0), under the lock the caller holds: the blocklists
 * in force while the firewall runs, through the gate (its hold, its
 * audit line), as the Threat Intel page's apply_now does.  With the
 * firewall stopped nothing is loaded: fs_intel_resume puts the saved
 * lists in force at the next start, and loading them now would block
 * while the firewall is off. */
static void
intel_put_in_force (FsControlResult *r, const FsControlActor *actor,
                    const FsIntelConfig *config)
{
	const FsBackend *backend = fs_backend ();
	FsFirewallState st = backend->get_state != NULL ? backend->get_state ()
	                                                : FS_FW_NONE;
	GError *error = NULL;

	if (st != FS_FW_RUNNING && st != FS_FW_LOCKED && st != FS_FW_HIT) {
		r->intel_apply = "stopped";
		return;
	}
	r->intel_outcome = fs_intel_apply_safe (backend, config, NULL,
	                                        actor->channel,
	                                        fs_apply_hold_reason (), &error);
	if (r->intel_outcome != NULL && r->intel_outcome->held) {
		r->intel_apply = "held";
	} else if (r->intel_outcome != NULL &&
	           r->intel_outcome->result == FS_APPLY_OK) {
		r->intel_apply = "applied";
	} else {
		r->intel_apply = "failed";
		fail (r, FS_CONTROL_FAILED, NULL, "the lists were not put in "
		      "force: %s", error != NULL ? error->message
		      : "the firewall refused them");
	}
	g_clear_error (&error);
}

/* [ intel_begin ]
 * Root first when an apply is asked for (nothing saved without it),
 * then the policy lock: the intel store comes after it in the lock
 * order.  NULL: refused, r says why. */
static FsPolicyLock *
intel_begin (FsControlResult *r, const FsControlActor *actor,
             gboolean apply)
{
	FsPolicyLock *lock;
	GError *error = NULL;

	if (apply && !need_root (r, actor))
		return NULL;
	lock = fs_policy_lock (&error);
	if (lock == NULL) {
		fail (r, FS_CONTROL_FAILED, NULL, "%s", error->message);
		g_error_free (error);
	}
	return lock;
}

/* [ op_intel_apply ] -- the saved blocklists, in force (F0). */
static void
op_intel_apply (FsControlResult *r, const FsControlActor *actor,
                GVariant *params)
{
	FsPolicyLock *lock = intel_begin (r, actor, TRUE);
	FsIntelConfig *config;
	GError *error = NULL;

	(void) params;
	if (lock == NULL)
		return;
	config = fs_intel_config_load (&error);
	if (config == NULL) {
		intel_fail (r, error, "the configuration could not be read");
	} else {
		intel_put_in_force (r, actor, config);
		fs_intel_config_free (config);
	}
	fs_policy_unlock (lock);
}

/* [ op_intel_exceptions_set ] (F11)
 * The whole allow list replaced by `text', read as the page's editor
 * reads it (fs_intel_exceptions_from_text).  A line that does not read
 * refuses the whole text, before anything is written. */
static void
op_intel_exceptions_set (FsControlResult *r, const FsControlActor *actor,
                         GVariant *params)
{
	const gchar *text = p_text (params, "text");
	gboolean apply = p_bool (params, "apply");
	FsPolicyLock *lock;
	FsIntelConfig *config;
	FsRangeSet *set;
	GError *error = NULL;

	if (text == NULL) {
		fail (r, FS_CONTROL_USAGE, NULL, "intel.exceptions.set needs text");
		return;
	}
	set = fs_intel_exceptions_from_text (text, &error);
	if (set == NULL) {
		/* Whatever the reader says, it is the request that is wrong. */
		fail (r, FS_CONTROL_USAGE, NULL, "%s", error != NULL ? error->message
		      : "the text does not read");
		g_clear_error (&error);
		return;
	}
	lock = intel_begin (r, actor, apply);
	if (lock == NULL) {
		fs_range_set_free (set);
		return;
	}
	config = fs_intel_config_load (&error);
	if (config == NULL) {
		fs_range_set_free (set);
		intel_fail (r, error, "the configuration could not be read");
		fs_policy_unlock (lock);
		return;
	}
	fs_range_set_free (config->exceptions);
	config->exceptions = set;
	if (!fs_intel_config_save (config, &error)) {
		intel_fail (r, error, "the configuration could not be saved");
	} else {
		r->intel_saved = TRUE;
		r->intel_exceptions = fs_range_set_copy (config->exceptions);
		if (apply)
			intel_put_in_force (r, actor, config);
	}
	fs_intel_config_free (config);
	fs_policy_unlock (lock);
}

/* [ op_intel_import ] (F12, F13)
 * A local list from `text', replacing the list of the same name; an
 * empty (or blank) text removes that list, as the page's "Your
 * blocklist" editor does. */
static void
op_intel_import (FsControlResult *r, const FsControlActor *actor,
                 GVariant *params)
{
	const gchar *name = p_str (params, "name");
	const gchar *text = p_text (params, "text");
	const gchar *dir_s = p_str (params, "dir");
	const gchar *what = p_str (params, "what");
	gboolean apply = p_bool (params, "apply");
	FsIntelDir dir = 0;
	FsPolicyLock *lock;
	FsIntelConfig *config;
	GError *error = NULL;
	gchar *blank;
	gboolean empty;

	if (name == NULL || *name == '\0' || text == NULL) {
		fail (r, FS_CONTROL_USAGE, NULL, "intel.import needs name and text");
		return;
	}
	if (dir_s != NULL) {
		if (strcmp (dir_s, "in") == 0)
			dir = FS_INTEL_DIR_IN;
		else if (strcmp (dir_s, "out") == 0)
			dir = FS_INTEL_DIR_OUT;
		else if (strcmp (dir_s, "both") == 0)
			dir = FS_INTEL_DIR_BOTH;
		else {
			fail (r, FS_CONTROL_USAGE, NULL,
			      "the direction must be in, out or both");
			return;
		}
	}
	blank = g_strstrip (g_strdup (text));
	empty = *blank == '\0';
	g_free (blank);
	r->intel_name = g_strdup (name);

	lock = intel_begin (r, actor, apply);
	if (lock == NULL)
		return;
	if (empty && !fs_intel_store_exists ()) {
		/* Nothing was ever stored: no list to remove, and no store
		 * is made for nothing. */
		fs_policy_unlock (lock);
		return;
	}
	config = fs_intel_config_load (&error);
	if (config == NULL) {
		intel_fail (r, error, "the configuration could not be read");
		fs_policy_unlock (lock);
		return;
	}
	if (empty) {
		FsIntelListConf *l = fs_intel_config_list_by_name (config, name);

		if (l == NULL) {
			/* Not there: removed already.  Nothing to write. */
			fs_intel_config_free (config);
			fs_policy_unlock (lock);
			return;
		}
		r->intel_id = g_strdup (l->id);
		r->intel_dir = l->dir;
		g_free (r->intel_name);
		r->intel_name = g_strdup (l->name);
		if (!fs_intel_config_remove (config, r->intel_id, &error)) {
			intel_fail (r, error, "the list could not be removed");
			fs_intel_config_free (config);
			fs_policy_unlock (lock);
			return;
		}
		r->intel_removed = TRUE;
	} else if (!fs_intel_import_text (config, text, strlen (text),
	                                  what != NULL ? what : "the text",
	                                  name, dir, &r->intel_stats,
	                                  &r->intel_id, &error)) {
		intel_fail (r, error, "the list was not imported");
		fs_intel_config_free (config);
		fs_policy_unlock (lock);
		return;
	} else {
		const FsIntelListConf *l = fs_intel_config_list (config,
		                                                 r->intel_id);

		r->intel_dir = l != NULL ? l->dir : FS_INTEL_DIR_BOTH;
	}
	if (!fs_intel_config_save (config, &error)) {
		intel_fail (r, error, "the configuration could not be saved");
	} else {
		r->intel_saved = TRUE;
		if (apply)
			intel_put_in_force (r, actor, config);
	}
	fs_intel_config_free (config);
	fs_policy_unlock (lock);
}

/* === end PR4-D === */

/* ------------------------------------------------------------ the door */

typedef void (*OpFunc) (FsControlResult *r, const FsControlActor *actor,
                        GVariant *params);

static const struct
{
	const gchar *name;
	OpFunc       run;
} ops[] = {
	{ "policy.add",     op_policy_add },
	{ "policy.remove",  op_policy_remove },
	{ "policy.replace", op_policy_replace },
	{ "policy.init",    op_policy_init },
	{ "policy.import",  op_policy_import },
	{ "apply",          op_apply },
	{ "firewall.start", op_start },
	{ "firewall.stop",  op_stop },
	{ "settings.set",   op_settings_set },
	{ "settings.apply", op_settings_apply },
	/* PR 4: each package adds its ops between its markers. */
	/* === PR4-B === */
	{ "sentinel.lift",  op_sentinel_lift },
	{ "sentinel.mode",  op_sentinel_mode },
	{ "copilot.block",  op_copilot_block },
	{ "copilot.fix",    op_copilot_fix },
	{ "copilot.undo",   op_copilot_undo },
	/* === end PR4-B === */
	/* === PR4-C === */
	{ "rule.block",     op_rule_block },
	{ "rule.allow",     op_rule_allow },
	{ "rule.untrust",   op_rule_untrust },
	{ "whatif.lift",    op_whatif_lift },
	/* === end PR4-C === */
	/* === PR4-D === */
	{ "intel.apply",          op_intel_apply },
	{ "intel.exceptions.set", op_intel_exceptions_set },
	{ "intel.import",         op_intel_import },
	/* === end PR4-D === */
};

FsControlResult *
fs_control_do (const FsControlActor *actor, const gchar *op,
               GVariant *params)
{
	FsControlResult *r = g_new0 (FsControlResult, 1);
	FsControlActor self;

	if (params != NULL)
		g_variant_ref_sink (params);
	if (actor == NULL) {
		self = fs_control_actor_self ("cli");
		actor = &self;
	}
	r->op = g_strdup (op != NULL ? op : "");
	r->status = FS_CONTROL_OK;
	r->was = FS_FW_NONE;

	if (params != NULL &&
	    !g_variant_is_of_type (params, G_VARIANT_TYPE_VARDICT)) {
		fail (r, FS_CONTROL_USAGE, NULL, "params must be a{sv}");
	} else {
		guint i;

		for (i = 0; i < G_N_ELEMENTS (ops); i++)
			if (g_strcmp0 (op, ops[i].name) == 0)
				break;
		if (i == G_N_ELEMENTS (ops))
			fail (r, FS_CONTROL_USAGE, NULL, "unknown op: %s", r->op);
		else
			ops[i].run (r, actor, params);
	}

	if (params != NULL)
		g_variant_unref (params);
	return r;
}

void
fs_control_result_free (FsControlResult *r)
{
	if (r == NULL)
		return;
	g_free (r->op);
	g_free (r->error);
	g_free (r->hint);
	fs_rule_free (r->rule);
	fs_rule_free (r->twin);
	fs_rule_free (r->old);
	g_free (r->problem);
	fs_policy_free (r->policy);
	if (r->problems != NULL)
		g_ptr_array_unref (r->problems);
	fs_apply_outcome_free (r->outcome);
	fs_policy_impact_free (r->unapplied);
	g_free (r->intel.hold);
	g_free (r->intel.error);
	g_free (r->intel.notes);
	fs_lockout_report_free (r->lockout);
	fs_policy_free (r->lockout_policy);
	fs_prefs_check_free (r->check);
	/* === PR4-B === */
	fs_autoblock_lift_free (r->lift);
	g_free (r->mode_was);
	g_free (r->mode);
	g_free (r->change_error);
	g_free (r->change_kind);
	g_free (r->fix_label);
	g_free (r->fix_before);
	g_free (r->fix_after);
	g_free (r->fix_whatif);
	g_free (r->whatif_line);
	/* === end PR4-B === */
	/* === PR4-C === */
	/* r->lift (shared with 4B) is freed above */
	g_free (r->lift_error);
	/* === end PR4-C === */
	/* === PR4-D === */
	fs_intel_outcome_free (r->intel_outcome);
	g_free (r->intel_id);
	g_free (r->intel_name);
	if (r->intel_exceptions != NULL)
		fs_range_set_free (r->intel_exceptions);
	/* === end PR4-D === */
	g_free (r);
}

/* ------------------------------------------------------------- JSON */

static void
rule_json (GString *out, const gchar *key, const FsRule *rule, guint number)
{
	gchar *csv;

	g_string_append_c (out, ',');
	fs_json_key (out, key);
	if (rule == NULL) {
		g_string_append (out, "null");
		return;
	}
	csv = fs_rule_to_csv (rule);
	g_string_append_c (out, '{');
	fs_json_kv_str (out, "kind", kind_names[rule->kind]);
	g_string_append_c (out, ',');
	fs_json_kv_uint (out, "number", number);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "csv", csv);
	g_string_append_c (out, '}');
	g_free (csv);
}

static void
issues_json (GString *out, const gchar *key, const GPtrArray *list)
{
	g_string_append_c (out, ',');
	fs_json_key (out, key);
	g_string_append_c (out, '[');
	for (guint i = 0; list != NULL && i < list->len; i++) {
		const FsPrefsIssue *is = g_ptr_array_index (list, i);

		if (i > 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "key", is->key);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "reason", is->reason);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "topic", is->topic);
		g_string_append_c (out, '}');
	}
	g_string_append_c (out, ']');
}

/* === PR4-B === */
/* [ lift_json ] -- ,"lift":{rows, removed, gone, kept, state_saved,
 * lifted[{kind, csv}], firewall{...}|null}. */
static void
lift_json (GString *out, const FsAutoblockLift *lift)
{
	gboolean first = TRUE;

	g_string_append (out, ",\"lift\":{");
	fs_json_kv_uint (out, "rows", lift->rows);
	g_string_append_c (out, ',');
	fs_json_kv_uint (out, "removed", lift->removed);
	g_string_append_c (out, ',');
	fs_json_kv_uint (out, "gone", lift->gone);
	g_string_append_c (out, ',');
	fs_json_kv_uint (out, "kept", lift->kept);
	g_string_append_c (out, ',');
	fs_json_kv_bool (out, "state_saved", lift->state_saved);
	g_string_append (out, ",\"lifted\":[");
	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		for (guint i = 0; i < lift->lifted->kinds[k]->len; i++) {
			gchar *csv = fs_rule_to_csv (
				g_ptr_array_index (lift->lifted->kinds[k], i));

			if (!first)
				g_string_append_c (out, ',');
			first = FALSE;
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "kind", kind_names[k]);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "csv", csv);
			g_string_append_c (out, '}');
			g_free (csv);
		}
	g_string_append (out, "],\"firewall\":");
	if (lift->outcome == NULL) {
		g_string_append (out, "null");
	} else {
		const FsApplyOutcome *o = lift->outcome;

		g_string_append_c (out, '{');
		fs_json_kv_bool (out, "applied", o->applied);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "held", o->held);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "hold_reason", o->hold_reason);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "recorded_for_next_start",
		                 !o->held && o->result == FS_APPLY_DRY_RUN &&
		                 o->firewall_was == FS_FW_STOPPED);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "result", fs_util_apply_result_to_string (
		                    (int) o->result));
		g_string_append_c (out, '}');
	}
	g_string_append_c (out, '}');
}
/* === end PR4-B === */

gchar *
fs_control_result_json (const FsControlResult *r)
{
	GString *out = g_string_new ("{");

	fs_json_kv_str (out, "op", r->op);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "status", fs_control_status_name (r->status));
	g_string_append_c (out, ',');
	fs_json_kv_bool (out, "ok", r->status == FS_CONTROL_OK);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "error", r->error);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "hint", r->hint);

	if (r->rule != NULL || r->old != NULL || r->already) {
		rule_json (out, "rule", r->rule, r->number);
		if (r->twin != NULL)
			rule_json (out, "twin", r->twin, r->twin_number);
		if (r->old != NULL)
			rule_json (out, "old", r->old, r->number);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "already", r->already);
	}
	if (g_str_has_prefix (r->op, "policy.")) {
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "saved", r->saved);
	}
	if (g_strcmp0 (r->op, "policy.init") == 0) {
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "dropped", r->dropped);
	}
	if (g_strcmp0 (r->op, "policy.import") == 0) {
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "imported", r->imported);
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "duplicates", r->duplicates);
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "rejected", r->rejected);
	}
	if (r->problems != NULL) {
		g_string_append (out, ",\"problems\":[");
		for (guint i = 0; i < r->problems->len; i++) {
			const FsPolicyProblem *p = g_ptr_array_index (r->problems, i);

			if (i > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "file", p->file);
			g_string_append_c (out, ',');
			fs_json_kv_uint (out, "line", p->line);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "reason", p->reason);
			g_string_append_c (out, '}');
		}
		g_string_append_c (out, ']');
	}
	if (r->outcome != NULL) {
		gchar *desc = fs_policy_impact_describe (r->outcome->impact);

		g_string_append (out, ",\"outcome\":{");
		fs_json_kv_bool (out, "applied", r->outcome->applied);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "held", r->outcome->held);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "hold_reason", r->outcome->hold_reason);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "result", fs_util_apply_result_to_string (
		                    (int) r->outcome->result));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "impact", desc);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "rollback_attempted",
		                 r->outcome->rollback_attempted);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "rollback_verified",
		                 r->outcome->rollback_verified);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "notes", r->outcome->notes);
		g_string_append_c (out, '}');
		g_free (desc);
	}
	if (g_str_has_prefix (r->op, "firewall.")) {
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "changed", r->changed);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "settings_from_journal",
		                 r->settings_from_journal);
	}
	if (r->intel.ran) {
		g_string_append (out, ",\"intel\":{");
		fs_json_kv_bool (out, "ok", r->intel.ok);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "result", r->intel.result);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "hold", r->intel.hold);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "error", r->intel.error);
		g_string_append_c (out, '}');
	}
	if (r->lockout != NULL) {
		g_string_append (out, ",\"lockout\":{");
		fs_json_kv_bool (out, "checked", r->lockout->checked);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "cuts", fs_lockout_report_cuts (r->lockout));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "client", r->lockout->worst != NULL
		                ? r->lockout->worst->peer : NULL);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "confirmed", r->lockout_confirmed);
		g_string_append_c (out, '}');
	}
	if (r->check != NULL) {
		issues_json (out, "refusals", r->check->refusals);
		issues_json (out, "warnings", r->check->warnings);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "unreadable_kept", r->prefs_unreadable);
	}
	/* === PR4-B === */
	/* 4C's ops write their own "lift" object below */
	if (r->lift != NULL && !g_str_has_prefix (r->op, "rule.") &&
	    g_strcmp0 (r->op, "whatif.lift") != 0)
		lift_json (out, r->lift);
	if (g_strcmp0 (r->op, "sentinel.mode") == 0) {
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "mode_was", r->mode_was);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "mode", r->mode);
	}
	if (g_str_has_prefix (r->op, "copilot.")) {
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "saved", r->saved);
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "change_id", r->change_id);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "change_error", r->change_error);
	}
	if (g_strcmp0 (r->op, "copilot.undo") == 0) {
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "change_kind", r->change_kind);
	}
	if (g_strcmp0 (r->op, "copilot.fix") == 0 ||
	    g_strcmp0 (r->op, "copilot.undo") == 0) {
		g_string_append (out, ",\"fix\":{");
		fs_json_kv_str (out, "label", r->fix_label);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "before", r->fix_before);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "after", r->fix_after);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "whatif", r->fix_whatif);
		g_string_append_c (out, '}');
	}
	if (r->whatif_line != NULL) {
		gboolean asked = r->whatif_before != FS_WHATIF_ERROR ||
		                 r->whatif_after != FS_WHATIF_ERROR;

		g_string_append (out, ",\"whatif\":{");
		fs_json_kv_str (out, "line", r->whatif_line);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "before", asked
		                ? fs_whatif_verdict_name (r->whatif_before) : NULL);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "after", asked
		                ? fs_whatif_verdict_name (r->whatif_after) : NULL);
		g_string_append_c (out, '}');
	}
	/* === end PR4-B === */
	/* === PR4-C === */
	if (g_str_has_prefix (r->op, "rule.")) {
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "saved", r->saved);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "journal", r->journal);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "live_none", r->live_none);
	}
	if ((g_str_has_prefix (r->op, "rule.") ||
	     g_strcmp0 (r->op, "whatif.lift") == 0) &&
	    (r->lift != NULL || r->lift_error != NULL)) {
		const FsApplyOutcome *o = r->lift != NULL ? r->lift->outcome : NULL;

		g_string_append (out, ",\"lift\":{");
		fs_json_kv_uint (out, "rows", r->lift != NULL ? r->lift->rows : 0);
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "removed",
		                 r->lift != NULL ? r->lift->removed : 0);
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "kept", r->lift != NULL ? r->lift->kept : 0);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "live", o != NULL && o->applied);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "held", o != NULL && o->held);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "error", r->lift_error);
		g_string_append_c (out, '}');
	}
	/* === end PR4-C === */
	/* === PR4-D === */
	if (g_str_has_prefix (r->op, "intel.")) {
		const FsIntelOutcome *o = r->intel_outcome;

		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "saved", r->intel_saved);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "applied",
		                 g_strcmp0 (r->intel_apply, "applied") == 0);
		g_string_append (out, ",\"apply\":");
		if (r->intel_apply == NULL) {
			g_string_append (out, "null");
		} else {
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "result", r->intel_apply);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "hold_reason",
			                o != NULL ? o->hold_reason : NULL);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "digest", o != NULL ? o->digest : NULL);
			g_string_append_c (out, ',');
			fs_json_kv_uint (out, "sets", o != NULL ? o->sets : 0);
			g_string_append_c (out, '}');
		}
	}
	if (g_strcmp0 (r->op, "intel.import") == 0) {
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "id", r->intel_id);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "name", r->intel_name);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "removed", r->intel_removed);
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "entries", r->intel_stats.entries);
	}
	if (r->intel_exceptions != NULL) {
		gchar *text = fs_range_set_to_text (r->intel_exceptions);
		gchar **lines = g_strsplit (text, "\n", -1);
		gboolean first = TRUE;

		g_string_append (out, ",\"exceptions\":[");
		for (guint i = 0; lines[i] != NULL; i++) {
			if (*lines[i] == '\0')
				continue;
			if (!first)
				g_string_append_c (out, ',');
			first = FALSE;
			fs_json_string (out, lines[i]);
		}
		g_string_append_c (out, ']');
		g_strfreev (lines);
		g_free (text);
	}
	/* === end PR4-D === */
	g_string_append_c (out, '}');
	return g_string_free (out, FALSE);
}

gchar *
fs_control_do_json (const FsControlActor *actor, const gchar *op,
                    GVariant *params)
{
	FsControlResult *r = fs_control_do (actor, op, params);
	gchar *json = fs_control_result_json (r);

	fs_control_result_free (r);
	return json;
}
