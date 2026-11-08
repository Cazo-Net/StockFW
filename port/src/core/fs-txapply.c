/*---[ fs-txapply.c ]----------------------------------------------------
 * Transactional Firewall Policy Application Engine
 *--------------------------------------------------------------------*/
#include "core/fs-txapply.h"

void
fs_tx_rule_spec_free (FsTxRuleSpec *spec)
{
	if (spec == NULL)
		return;

	g_free (spec->name);
	g_free (spec->direction);
	g_free (spec->action);
	g_free (spec->protocol);
	g_free (spec->local_ports);
	g_free (spec->remote_ports);
	g_free (spec->remote_address);
	g_free (spec->program);
	g_free (spec);
}

FsApplyResult
fs_tx_apply (const FsTxOps *ops, gpointer user_data,
             const GList *new_rules, GError **error)
{
	GList *snapshot = NULL;
	GError *local_err = NULL;
	GError *first_err = NULL;
	guint applied = 0;
	guint failed = 0;
	GList *iter;
	gboolean clear_ok;

	if (ops == NULL || ops->snapshot == NULL || ops->clear == NULL ||
	    ops->add_rule == NULL || ops->restore_spec == NULL || ops->verify_present == NULL) {
		g_set_error_literal (error, g_quark_from_static_string ("fs-txapply"),
		                     0, "incomplete transactional ops vtable");
		return FS_APPLY_FAILED;
	}

	/* 1. Take snapshot before any destructive changes. */
	snapshot = ops->snapshot (user_data, &local_err);
	if (local_err != NULL) {
		g_propagate_error (error, local_err);
		g_list_free_full (snapshot, (GDestroyNotify) fs_tx_rule_spec_free);
		return FS_APPLY_FAILED;
	}

	/* 2. Clear existing rules. */
	clear_ok = ops->clear (user_data, &local_err);
	if (!clear_ok) {
		if (local_err != NULL)
			g_propagate_error (error, local_err);
		else
			g_set_error_literal (error, g_quark_from_static_string ("fs-txapply"),
			                     0, "failed to clear existing firewall rules");
		g_list_free_full (snapshot, (GDestroyNotify) fs_tx_rule_spec_free);
		return FS_APPLY_PARTIAL;
	}
	g_clear_error (&local_err);

	/* 3. Apply new rules sequentially. */
	for (iter = (GList *) new_rules; iter != NULL; iter = iter->next) {
		const FsFwRule *rule = iter->data;

		if (ops->add_rule (user_data, rule, &local_err)) {
			applied++;
		} else {
			failed++;
			if (first_err == NULL && local_err != NULL)
				first_err = g_error_copy (local_err);
			g_clear_error (&local_err);
		}
	}

	/* 4. If any rule failed to create, execute verified rollback. */
	if (failed > 0) {
		gboolean rollback_ok = TRUE;
		GError *rollback_err = NULL;

		/* Clear partial new rules first. */
		if (!ops->clear (user_data, &rollback_err)) {
			rollback_ok = FALSE;
		} else {
			g_clear_error (&rollback_err);
			/* Recreate snapshot rules. */
			for (iter = snapshot; iter != NULL; iter = iter->next) {
				const FsTxRuleSpec *spec = iter->data;
				if (!ops->restore_spec (user_data, spec, &rollback_err)) {
					rollback_ok = FALSE;
					break;
				}
			}
			if (rollback_ok && !ops->verify_present (user_data, snapshot, &rollback_err)) {
				rollback_ok = FALSE;
			}
		}

		g_set_error (error, g_quark_from_static_string ("fs-txapply"),
		             (int) failed, "%u of %u rules could not be created%s%s",
		             failed, applied + failed,
		             first_err != NULL ? ": " : "",
		             first_err != NULL ? first_err->message : "");

		if (!rollback_ok) {
			GError *combined = g_error_new (g_quark_from_static_string ("fs-txapply"), 0,
				"%s; ROLLBACK FAILED%s%s",
				(*error)->message,
				rollback_err != NULL ? ": " : "",
				rollback_err != NULL ? rollback_err->message : "unknown reason");
			g_clear_error (error);
			*error = combined;
		}

		g_clear_error (&first_err);
		g_clear_error (&rollback_err);
		g_list_free_full (snapshot, (GDestroyNotify) fs_tx_rule_spec_free);
		return FS_APPLY_PARTIAL;
	}

	g_clear_error (&first_err);
	g_list_free_full (snapshot, (GDestroyNotify) fs_tx_rule_spec_free);
	return FS_APPLY_OK;
}
