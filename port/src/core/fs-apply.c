/*---[ fs-apply.c ]------------------------------------------------------
 * Safe policy enforcement (P3).  See fs-apply.h for the contract.
 *
 * The journal is the pivot: it records the last policy that made it
 * onto the firewall, so the same artifact answers both "what would
 * this apply change?" (impact, previews) and "what do we restore if
 * this apply fails?" (rollback).  A journal that cannot be read is
 * never guessed at -- the apply still runs, the rollback honestly
 * reports that there was nothing to restore, and the audit line says
 * which.
 *--------------------------------------------------------------------*/
#include "core/fs-apply.h"
#include "core/fs-audit.h"
#include "core/fs-prefs.h"
#include "core/fs-util.h"

GQuark
fs_apply_error_quark (void)
{
	return g_quark_from_static_string ("stockfw-apply-error");
}

/* =====================================================================
 * Journal: what is actually live
 * ===================================================================== */

/* [ fs_apply_journal_path ] */
gchar *
fs_apply_journal_path (void)
{
	const gchar *env = g_getenv ("STOCKFW_APPLIED_FILE");

	if (env != NULL && *env != '\0')
		return g_strdup (env);

	return fs_util_rules_path ("applied.csv");
}

/* [ fs_apply_journal_save ]
 * Written only after an apply that the backend called successful, so
 * the file is the restore point for the next failure. */
gboolean
fs_apply_journal_save (const FsPolicy *policy, GError **error)
{
	GString *out;
	gchar *path;
	gboolean ok;

	if (policy == NULL) {
		g_set_error_literal (error, FS_APPLY_ERROR,
		                     FS_APPLY_ERR_UNREADABLE,
		                     "no policy to journal");
		return FALSE;
	}

	path = fs_apply_journal_path ();
	out = g_string_new ("# StockFW applied policy journal v1\n");

	for (gint kind = 0; kind < FS_RULE_N_KINDS; kind++) {
		for (guint i = 0; i < policy->kinds[kind]->len; i++) {
			const FsRule *rule =
				g_ptr_array_index (policy->kinds[kind], i);
			gchar *csv = fs_rule_to_csv (rule);
			gchar *kind_text = g_strdup_printf ("%d", kind);

			fs_util_csv_append_field (out, kind_text, TRUE);
			fs_util_csv_append_field (out, csv, FALSE);
			g_string_append_c (out, '\n');

			g_free (kind_text);
			g_free (csv);
		}
	}

	if (!fs_util_ensure_parent_dir (path)) {
		g_set_error (error, FS_APPLY_ERROR, FS_APPLY_ERR_UNREADABLE,
		             "cannot create the directory for %s", path);
		g_string_free (out, TRUE);
		g_free (path);
		return FALSE;
	}

	ok = g_file_set_contents (path, out->str, out->len, error);

	if (!ok && error != NULL && (*error)->domain != FS_APPLY_ERROR) {
		/* Normalise the domain so callers match on one quark. */
		GError *inner = g_steal_pointer (error);

		g_set_error (error, FS_APPLY_ERROR, FS_APPLY_ERR_UNREADABLE,
		             "%s", inner->message);
		g_error_free (inner);
	}

	g_string_free (out, TRUE);
	g_free (path);

	return ok;
}

/* [ fs_apply_journal_load ]
 * Strict by design: policy files may skip a malformed line and carry
 * on, a rollback target may not.  One bad row and the whole journal
 * is refused -- an honest "nothing to restore" beats a half-truth
 * pushed at the firewall in an emergency. */
gboolean
fs_apply_journal_load (FsPolicy *policy, GError **error)
{
	gchar *path;
	gchar *contents = NULL;
	gchar **lines;
	GError *inner = NULL;
	gint row = 0;

	if (policy == NULL) {
		g_set_error_literal (error, FS_APPLY_ERROR,
		                     FS_APPLY_ERR_UNREADABLE,
		                     "no policy to load into");
		return FALSE;
	}

	fs_policy_clear (policy);
	path = fs_apply_journal_path ();

	if (!g_file_get_contents (path, &contents, NULL, &inner)) {
		gboolean missing =
			g_error_matches (inner, G_FILE_ERROR, G_FILE_ERROR_NOENT) ||
			g_error_matches (inner, G_FILE_ERROR, G_FILE_ERROR_NOTDIR);

		g_set_error (error, FS_APPLY_ERROR,
		             missing ? FS_APPLY_ERR_NO_JOURNAL
		                     : FS_APPLY_ERR_UNREADABLE,
		             "%s", inner->message);
		g_error_free (inner);
		g_free (path);
		return FALSE;
	}

	lines = g_strsplit (contents, "\n", -1);

	for (gint i = 0; lines[i] != NULL; i++) {
		gchar *line = g_strstrip (lines[i]);
		GPtrArray *fields;
		FsRule *rule;
		gchar *end = NULL;
		gint64 kind;

		row = i + 1;

		if (*line == '\0' || *line == '#')
			continue;

		fields = fs_util_csv_split_line (line);

		if (fields->len != 2 ||
		    ((gchar *) g_ptr_array_index (fields, 0))[0] == '\0') {
			g_ptr_array_unref (fields);
			goto malformed;
		}

		kind = g_ascii_strtoll (g_ptr_array_index (fields, 0), &end, 10);

		if (end == NULL || *end != '\0' || kind < 0 ||
		    kind >= FS_RULE_N_KINDS) {
			g_ptr_array_unref (fields);
			goto malformed;
		}

		rule = fs_rule_from_csv ((FsRuleKind) kind,
		                         g_ptr_array_index (fields, 1));
		g_ptr_array_unref (fields);

		if (rule != NULL && !fs_rule_fields_sane (rule)) {
			fs_rule_free (rule);
			rule = NULL;
		}

		if (rule == NULL)
			goto malformed;

		fs_policy_add (policy, rule);
		fs_rule_free (rule);
	}

	g_strfreev (lines);
	g_free (contents);
	g_free (path);
	return TRUE;

malformed:
	g_set_error (error, FS_APPLY_ERROR, FS_APPLY_ERR_MALFORMED,
	             "journal row %d could not be trusted", row);
	g_strfreev (lines);
	g_free (contents);
	g_free (path);
	fs_policy_clear (policy);
	return FALSE;
}

/* =====================================================================
 * Impact: what would this change, against what is live?
 * ===================================================================== */

static gboolean
kind_is_allow (FsRuleKind kind)
{
	switch (kind) {
	case FS_RULE_OUTBOUND_DENY_TO:
	case FS_RULE_OUTBOUND_DENY_FROM:
	case FS_RULE_OUTBOUND_DENY_SERVICE:
		return FALSE;
	default:
		return TRUE;
	}
}

/* [ fs_policy_impact ] */
FsPolicyImpact *
fs_policy_impact (const FsPolicy *before, const FsPolicy *after)
{
	FsPolicyImpact *impact = g_new0 (FsPolicyImpact, 1);

	if (after == NULL)
		return impact;

	for (gint kind = 0; kind < FS_RULE_N_KINDS; kind++) {
		for (guint i = 0; i < after->kinds[kind]->len; i++) {
			const FsRule *rule =
				g_ptr_array_index (after->kinds[kind], i);

			if (before != NULL && fs_policy_contains (before, rule)) {
				impact->unchanged++;
			} else {
				impact->added++;
				if (kind_is_allow ((FsRuleKind) kind))
					impact->added_allows++;
				else
					impact->added_blocks++;
			}
		}

		if (before == NULL)
			continue;

		for (guint i = 0; i < before->kinds[kind]->len; i++) {
			const FsRule *rule =
				g_ptr_array_index (before->kinds[kind], i);

			if (fs_policy_contains (after, rule))
				continue;

			impact->removed++;
			if (kind_is_allow ((FsRuleKind) kind))
				impact->removed_allows++;
			else
				impact->removed_blocks++;
		}
	}

	return impact;
}

/* [ fs_policy_impact_describe ] */
gchar *
fs_policy_impact_describe (const FsPolicyImpact *impact)
{
	if (impact == NULL)
		return g_strdup ("no impact measured");

	return g_strdup_printf (
		"+%u added (%u allow, %u block), "
		"-%u removed (%u allow, %u block), "
		"=%u unchanged",
		impact->added, impact->added_allows, impact->added_blocks,
		impact->removed, impact->removed_allows, impact->removed_blocks,
		impact->unchanged);
}

void
fs_policy_impact_free (FsPolicyImpact *impact)
{
	g_free (impact);
}

/* [ fs_policy_impact_preview ] */
FsPolicyImpact *
fs_policy_impact_preview (const FsPolicy *after)
{
	FsPolicy *before = fs_policy_new ();
	FsPolicyImpact *impact;

	/* No journal, unreadable journal: `before' stays empty and every
	 * row counts as added -- nothing is claimed to be live that is
	 * not known to be. */
	fs_apply_journal_load (before, NULL);
	impact = fs_policy_impact (before, after);
	fs_policy_free (before);

	return impact;
}

/* =====================================================================
 * Delta: the narrow work lists
 * ===================================================================== */

static gboolean
list_has_rule (const GList *rules, const FsFwRule *needle)
{
	for (const GList *iter = rules; iter != NULL; iter = iter->next) {
		if (fs_fwrule_equal ((const FsFwRule *) iter->data, needle))
			return TRUE;
	}

	return FALSE;
}

static gboolean
name_is_removed (const GList *remove, const gchar *name)
{
	for (const GList *iter = remove; iter != NULL; iter = iter->next) {
		if (g_strcmp0 (iter->data, name) == 0)
			return TRUE;
	}

	return FALSE;
}

/* [ fs_policy_delta ]
 * Policy rows pair up through the concrete rules they expand to,
 * because that is what the firewall stores: a comment-only row edit
 * and a port change both show as one remove plus one add, and a rule
 * that survives untouched stays out of every list. */
FsPolicyDelta *
fs_policy_delta (const FsPolicy *before, const FsPolicy *after)
{
	FsPolicyDelta *delta = g_new0 (FsPolicyDelta, 1);
	GList *old_rules;
	GList *new_rules;
	GList *iter;

	if (after == NULL) {
		delta->empty = TRUE;
		return delta;
	}

	new_rules = fs_fwrule_from_policy (after);

	if (before == NULL) {
		/* Nothing known to be live: the whole set is an add. */
		delta->add = new_rules;
		delta->empty = (new_rules == NULL);
		return delta;
	}

	old_rules = fs_fwrule_from_policy (before);

	/* Remove: in old, not in new -- as unique names. */
	{
		GHashTable *seen = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                          g_free, NULL);

		for (iter = old_rules; iter != NULL; iter = iter->next) {
			const FsFwRule *rule = iter->data;

			if (list_has_rule (new_rules, rule))
				continue;

			if (g_hash_table_add (seen, g_strdup (rule->name))) {
				delta->remove = g_list_prepend (
					delta->remove, g_strdup (rule->name));
			}
		}

		g_hash_table_destroy (seen);
	}

	/* Add / repair / untouched, from the new side. */
	for (iter = new_rules; iter != NULL; iter = iter->next) {
		FsFwRule *rule = iter->data;

		if (!list_has_rule (old_rules, rule)) {
			delta->add = g_list_prepend (delta->add, rule);
		} else if (name_is_removed (delta->remove, rule->name)) {
			/* Keeping this rule means deleting its name would take
			 * it down with the rule that shares the name -- so it
			 * has to be re-created right after the delete. */
			delta->repair = g_list_prepend (delta->repair, rule);
		} else {
			/* Unchanged: no work, no ownership transfer. */
			fs_fwrule_free (rule);
		}
	}

	g_list_free (new_rules);          /* nodes only; data handled above */
	fs_fwrule_list_free (old_rules);  /* nodes + data                   */

	delta->empty = (delta->remove == NULL &&
	                delta->add == NULL &&
	                delta->repair == NULL);

	return delta;
}

void
fs_policy_delta_free (FsPolicyDelta *delta)
{
	if (delta == NULL)
		return;

	g_list_free_full (delta->remove, g_free);
	g_list_free_full (delta->add, (GDestroyNotify) fs_fwrule_free);
	g_list_free_full (delta->repair, (GDestroyNotify) fs_fwrule_free);
	g_free (delta);
}

/* =====================================================================
 * Audit-only testing mode
 * ===================================================================== */

/* [ fs_apply_audit_only ] */
gboolean
fs_apply_audit_only (void)
{
	return fs_prefs_get_bool (FS_PREFS_AUDIT_ONLY, FALSE);
}

/* [ fs_apply_hold_reason ]
 * English on purpose: the reason is recorded verbatim in the
 * append-only audit log. */
const gchar *
fs_apply_hold_reason (void)
{
	return fs_apply_audit_only () ? "audit-only testing mode" : NULL;
}

/* [ fs_apply_set_audit_only ] */
void
fs_apply_set_audit_only (gboolean on)
{
	fs_prefs_set_bool (FS_PREFS_AUDIT_ONLY, on);
	fs_prefs_save ();
}

/* =====================================================================
 * The gate
 * ===================================================================== */

static gchar *
apply_detail (const gchar *source, const gchar *mode, const gchar *what,
              const gchar *extra, const gchar *tail)
{
	return g_strdup_printf ("%s | %s | %s%s%s%s%s",
	                        source != NULL ? source : "-",
	                        mode != NULL ? mode : "-",
	                        what,
	                        extra != NULL ? " | " : "",
	                        extra != NULL ? extra : "",
	                        tail != NULL ? " | " : "",
	                        tail != NULL ? tail : "");
}

/* [ fs_policy_apply_safe ] */
FsApplyOutcome *
fs_policy_apply_safe (const FsBackend *backend, FsPolicy *policy,
                      const gchar *source, const gchar *hold,
                      GError **error)
{
	FsApplyOutcome *outcome;
	FsPolicy *before;
	GError *journal_error = NULL;
	FsPolicyDelta *delta = NULL;
	gboolean have_before;
	gchar *desc;
	const gchar *mode = "full";

	g_return_val_if_fail (policy != NULL, NULL);

	outcome = g_new0 (FsApplyOutcome, 1);
	outcome->result = FS_APPLY_FAILED;

	before = fs_policy_new ();
	have_before = fs_apply_journal_load (before, &journal_error);

	outcome->impact = fs_policy_impact (have_before ? before : NULL, policy);
	desc = fs_policy_impact_describe (outcome->impact);

	/* Held: audit-only mode or the Policy Lock.  The policy file has
	 * already recorded the change; the firewall is deliberately
	 * untouched and the audit line says so in those words. */
	if (hold != NULL && *hold != '\0') {
		gchar *detail = apply_detail (source, "held", hold, desc, NULL);

		outcome->held = TRUE;
		outcome->hold_reason = hold;
		outcome->result = FS_APPLY_DRY_RUN;
		fs_audit_log ("policy held, firewall untouched", detail);
		g_free (detail);
		goto out;
	}

	if (backend == NULL || backend->available == NULL ||
	    !backend->available ()) {
		gchar *detail = apply_detail (source, "refused",
		                              "no firewall backend available",
		                              desc, NULL);

		outcome->result = FS_APPLY_NO_IPTABLES;
		g_set_error_literal (error, FS_APPLY_ERROR,
		                     FS_APPLY_ERR_NO_BACKEND,
		                     "No firewall backend is available on "
		                     "this system.");
		fs_audit_log ("policy apply refused", detail);
		g_free (detail);
		goto out;
	}

	/* Narrow path -- including the best case of all: nothing changed,
	 * so the firewall is not touched at all. */
	if (have_before) {
		delta = fs_policy_delta (before, policy);

		if (delta->empty) {
			GError *save_error = NULL;
			gchar *detail;

			outcome->result = FS_APPLY_OK;
			outcome->applied = TRUE;
			outcome->narrow = TRUE;

			/* Comment-only edits change policy rows without
			 * changing any firewall rule; sync the journal anyway
			 * so it never goes stale behind the policy's back. */
			if (!fs_apply_journal_save (policy, &save_error)) {
				detail = apply_detail (
					source, "narrow", "no change",
					"journal NOT saved",
					save_error != NULL
						? save_error->message : NULL);
				g_clear_error (&save_error);
			} else {
				detail = apply_detail (source, "narrow",
				                      "no change", desc, NULL);
			}
			fs_audit_log ("policy apply: no change", detail);
			g_free (detail);
			goto out;
		}
	}

	if (delta != NULL && backend->apply_delta != NULL) {
		outcome->narrow = TRUE;
		mode = "narrow";
		outcome->result = backend->apply_delta (delta->remove,
		                                        delta->add,
		                                        delta->repair, error);
	} else {
		outcome->result = backend->apply_rules (policy, error);
	}

	if (outcome->result == FS_APPLY_OK) {
		GError *save_error = NULL;
		gchar *detail;

		outcome->applied = TRUE;
		if (backend->apply_notes != NULL)
			outcome->notes = backend->apply_notes ();

		if (!fs_apply_journal_save (policy, &save_error)) {
			detail = apply_detail (
				source, mode, desc,
				"applied but the journal could not be saved",
				save_error != NULL ? save_error->message : NULL);
			fs_audit_log ("policy applied, journal NOT saved", detail);
			g_free (detail);
			g_clear_error (&save_error);
		} else {
			detail = apply_detail (source, mode, desc, outcome->notes,
			                       NULL);
			fs_audit_log (outcome->notes != NULL
			              ? "policy applied, with notes"
			              : "policy applied", detail);
			g_free (detail);
		}
	} else {
		const gchar *result_text =
			fs_util_apply_result_to_string ((int) outcome->result);
		const gchar *err_text = (error != NULL && *error != NULL)
			? (*error)->message : NULL;
		gchar *detail;

		if (!have_before) {
			/* Honest: there is nothing to restore, and the audit
			 * line says exactly that instead of implying a
			 * rollback happened. */
			outcome->rollback_detail = g_strdup_printf (
				"rollback skipped: no applied-policy journal (%s)",
				journal_error != NULL ? journal_error->message
				                      : "empty");
			detail = apply_detail (
				source, mode, result_text, err_text,
				outcome->rollback_detail);
			fs_audit_log ("policy apply failed", detail);
			g_free (detail);
		} else {
			GError *rollback_error = NULL;
			FsApplyResult rollback_result;

			outcome->rollback_attempted = TRUE;

			/* Full restore of the journal state: the rollback's own
			 * verdict is checked, never assumed. */
			rollback_result = backend->apply_rules (before,
			                                        &rollback_error);
			outcome->rollback_verified =
				(rollback_result == FS_APPLY_OK);
			outcome->rollback_detail = g_strdup_printf (
				"rollback %s: %s%s%s",
				outcome->rollback_verified ? "verified"
				                           : "FAILED",
				fs_util_apply_result_to_string (
					(int) rollback_result),
				rollback_error != NULL ? ": " : "",
				rollback_error != NULL
					? rollback_error->message : "");

			detail = apply_detail (
				source, mode, result_text, err_text,
				outcome->rollback_detail);
			fs_audit_log ("policy apply failed", detail);
			g_free (detail);
			g_clear_error (&rollback_error);
		}
	}

out:
	g_clear_error (&journal_error);
	fs_policy_delta_free (delta);
	fs_policy_free (before);
	g_free (desc);

	return outcome;
}

/* [ fs_apply_outcome_free ] */
void
fs_apply_outcome_free (FsApplyOutcome *outcome)
{
	if (outcome == NULL)
		return;

	fs_policy_impact_free (outcome->impact);
	g_free (outcome->rollback_detail);
	g_free (outcome->notes);
	g_free (outcome);
}

/* =====================================================================
 * Start and stop through the gate (1.0.7)
 * ===================================================================== */

/* [ start_record_live ]
 * A start that installed `policy' (Linux): the journal now says so,
 * and the audit line carries the backend's notes. */
static void
start_record_live (const FsBackend *backend, FsApplyOutcome *outcome,
                   const FsPolicy *policy, const gchar *source,
                   const gchar *mode, const gchar *what,
                   const gchar *extra)
{
	GError *save_error = NULL;
	gchar *detail;

	outcome->applied = TRUE;
	if (backend->apply_notes != NULL)
		outcome->notes = backend->apply_notes ();

	if (!fs_apply_journal_save (policy, &save_error)) {
		detail = apply_detail (source, mode, what,
		                       "started but the journal could not be "
		                       "saved",
		                       save_error != NULL ? save_error->message
		                                          : NULL);
		fs_audit_log ("firewall started, journal NOT saved", detail);
		g_clear_error (&save_error);
	} else {
		detail = apply_detail (source, mode, what, extra,
		                       outcome->notes);
		fs_audit_log ("firewall started", detail);
	}
	g_free (detail);
}

/* [ journal_minus ] -- take every rule of `lift' out of `journal' (in
 * memory only).  Returns how many were there. */
static guint
journal_minus (FsPolicy *journal, const FsPolicy *lift)
{
	guint taken = 0;

	if (lift == NULL)
		return 0;

	for (gint k = 0; k < FS_RULE_N_KINDS; k++) {
		GPtrArray *rules = lift->kinds[k];

		for (guint i = 0; rules != NULL && i < rules->len; i++)
			if (fs_policy_remove (journal,
			                      g_ptr_array_index (rules, i)))
				taken++;
	}
	return taken;
}

/* [ fs_firewall_start_safe ] */
FsApplyOutcome *
fs_firewall_start_safe (const FsBackend *backend, FsPolicy *policy,
                        const gchar *source, const gchar *hold,
                        GError **error)
{
	return fs_firewall_start_lifting (backend, policy, NULL, source, hold,
	                                  error);
}

/* [ fs_firewall_start_lifting ] */
FsApplyOutcome *
fs_firewall_start_lifting (const FsBackend *backend, FsPolicy *policy,
                           const FsPolicy *lift, const gchar *source,
                           const gchar *hold, GError **error)
{
	FsApplyOutcome *outcome;
	FsPolicy *before;
	GError *journal_error = NULL;
	gboolean have_before, held;
	gchar *desc;

	g_return_val_if_fail (policy != NULL, NULL);

	outcome = g_new0 (FsApplyOutcome, 1);
	outcome->result = FS_APPLY_FAILED;

	before = fs_policy_new ();
	have_before = fs_apply_journal_load (before, &journal_error);
	/* What a start leaves off the firewall: the changes not applied
	 * yet (journal -> file).  With no journal, the whole file. */
	outcome->impact = fs_policy_impact (have_before ? before : NULL,
	                                    policy);
	desc = fs_policy_impact_describe (outcome->impact);
	held = (hold != NULL && *hold != '\0');

	if (backend == NULL || backend->available == NULL ||
	    backend->start == NULL || !backend->available ()) {
		gchar *detail = apply_detail (source, "refused",
		                              "no firewall backend available",
		                              desc, NULL);

		outcome->result = FS_APPLY_NO_IPTABLES;
		g_set_error_literal (error, FS_APPLY_ERROR,
		                     FS_APPLY_ERR_NO_BACKEND,
		                     "No firewall backend is available on "
		                     "this system.");
		fs_audit_log ("firewall start refused", detail);
		g_free (detail);
		goto out;
	}

	if (!backend->start_applies_policy) {
		/* Windows profiles: enforcement is switched on, and the
		 * rules in the firewall's own store are whatever the last
		 * apply left there -- the journal is already right and a
		 * hold has nothing to hold back. */
		if (!backend->start (error)) {
			gchar *detail = apply_detail (
				source, "start", "FAILED",
				(error != NULL && *error != NULL)
				? (*error)->message : NULL, NULL);

			fs_audit_log ("firewall start failed", detail);
			g_free (detail);
			goto out;
		}
		outcome->result = FS_APPLY_OK;
		outcome->held = held;
		outcome->hold_reason = held ? hold : NULL;
		{
			gchar *detail = apply_detail (
				source, "start",
				"enforcement switched on, rules unchanged",
				held ? hold : NULL, NULL);

			fs_audit_log ("firewall started", detail);
			g_free (detail);
		}
		goto out;
	}

	/* From here the start installs a policy (Linux), and which one is
	 * the whole question.  A start brings back what was live; it never
	 * puts live what nobody applied -- that is `apply's job, and the
	 * boot unit runs this unattended at every boot. */

	if (!have_before &&
	    !g_error_matches (journal_error, FS_APPLY_ERROR,
	                      FS_APPLY_ERR_NO_JOURNAL)) {
		/* A journal that is there but cannot be trusted: neither it
		 * nor the file (which may hold changes nobody applied) is
		 * safe to start.  Refused, firewall untouched. */
		gchar *detail = apply_detail (
			source, "refused",
			"the applied-policy journal could not be read",
			journal_error != NULL ? journal_error->message : NULL,
			desc);

		outcome->result = FS_APPLY_FAILED;
		g_set_error (error, FS_APPLY_ERROR,
		             journal_error != NULL ? journal_error->code
		                                   : FS_APPLY_ERR_UNREADABLE,
		             "the record of the last applied policy could "
		             "not be read (%s), so there is no safe policy "
		             "to start with; apply the policy to start the "
		             "firewall",
		             journal_error != NULL ? journal_error->message
		                                   : "unknown error");
		fs_audit_log ("firewall start refused", detail);
		g_free (detail);
		goto out;
	}

	if (have_before) {
		/* The last policy that was really live, less the Sentinel
		 * blocks whose time ran out (`lift') -- never the file: it
		 * may hold changes not applied yet, held or simply never
		 * applied. */
		guint lifted = journal_minus (before, lift);
		gchar *what, *pending;

		outcome->held = held;
		outcome->hold_reason = held ? hold : NULL;
		outcome->result = backend->apply_rules != NULL
		                ? backend->apply_rules (before, error)
		                : FS_APPLY_FAILED;

		if (outcome->result != FS_APPLY_OK &&
		    outcome->result != FS_APPLY_PARTIAL) {
			gchar *detail = apply_detail (
				source, held ? "held" : "start",
				fs_util_apply_result_to_string (
					(int) outcome->result),
				(error != NULL && *error != NULL)
				? (*error)->message : NULL, desc);

			fs_audit_log ("firewall start failed", detail);
			g_free (detail);
			goto out;
		}

		outcome->result = FS_APPLY_OK;
		what = lifted > 0
		     ? g_strdup_printf ("started with the last applied "
		                        "policy, %u expired Sentinel block(s) "
		                        "left out; changes not applied stay "
		                        "off the firewall", lifted)
		     : g_strdup ("started with the last applied policy; "
		                 "changes not applied stay off the firewall");
		pending = g_strdup_printf ("%s%snot applied: %s",
		                           held ? hold : "", held ? "; " : "",
		                           desc);
		start_record_live (backend, outcome, before, source,
		                   held ? "held" : "start", what, pending);
		g_free (pending);
		g_free (what);
		goto out;
	}

	/* No journal: nothing was ever applied through the gate. */
	if (held) {
		gchar *detail = apply_detail (
			source, "held", hold,
			"no applied-policy journal to start from", desc);

		outcome->held = TRUE;
		outcome->hold_reason = hold;
		outcome->result = FS_APPLY_DRY_RUN;
		fs_audit_log ("firewall start held, firewall untouched",
		              detail);
		g_free (detail);
		goto out;
	}

	/* Unheld with no record of anything live: this start IS the
	 * first apply of the policy.  The caller vouches that it was
	 * really loaded (`stockfw start' refuses a missing or malformed
	 * policy file before it gets here). */
	if (!backend->start (error)) {
		gchar *detail = apply_detail (
			source, "start", "FAILED",
			(error != NULL && *error != NULL) ? (*error)->message
			                                  : NULL, desc);

		outcome->result = FS_APPLY_FAILED;
		fs_audit_log ("firewall start failed", detail);
		g_free (detail);
		goto out;
	}

	outcome->result = FS_APPLY_OK;
	start_record_live (backend, outcome, policy, source, "start", desc,
	                   "nothing applied before: started the policy "
	                   "file");

out:
	g_clear_error (&journal_error);
	fs_policy_free (before);
	g_free (desc);

	return outcome;
}

/* [ fs_firewall_lift_live ] */
FsApplyOutcome *
fs_firewall_lift_live (const FsBackend *backend, const FsPolicy *lift,
                       const gchar *source, const gchar *hold,
                       GError **error)
{
	FsPolicy *live;
	FsApplyOutcome *outcome = NULL;

	if (lift == NULL)
		return NULL;

	/* Nothing on record as live: nothing to take off. */
	live = fs_policy_new ();
	if (fs_apply_journal_load (live, NULL) &&
	    journal_minus (live, lift) > 0)
		outcome = fs_policy_apply_safe (backend, live, source, hold,
		                                error);

	fs_policy_free (live);
	return outcome;
}

/* [ fs_firewall_stop_logged ] */
gboolean
fs_firewall_stop_logged (const FsBackend *backend, const gchar *source,
                         GError **error)
{
	gboolean ok;
	gchar *detail;

	if (backend == NULL || backend->available == NULL ||
	    backend->stop == NULL || !backend->available ()) {
		g_set_error_literal (error, FS_APPLY_ERROR,
		                     FS_APPLY_ERR_NO_BACKEND,
		                     "No firewall backend is available on "
		                     "this system.");
		detail = apply_detail (source, "refused",
		                       "no firewall backend available", NULL,
		                       NULL);
		fs_audit_log ("firewall stop refused", detail);
		g_free (detail);
		return FALSE;
	}

	ok = backend->stop (error);
	detail = apply_detail (source, "stop", ok ? "stopped" : "FAILED",
	                       (!ok && error != NULL && *error != NULL)
	                       ? (*error)->message : NULL, NULL);
	fs_audit_log (ok ? "firewall stopped" : "firewall stop failed",
	              detail);
	g_free (detail);

	return ok;
}
