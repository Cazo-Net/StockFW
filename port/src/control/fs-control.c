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
#include "core/fs-audit.h"
#include "core/fs-autoblock.h"
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
	{ "apply",          op_apply },
	{ "firewall.start", op_start },
	{ "firewall.stop",  op_stop },
	{ "settings.set",   op_settings_set },
	{ "settings.apply", op_settings_apply },
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
