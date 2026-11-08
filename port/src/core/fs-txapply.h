/*---[ fs-txapply.h ]----------------------------------------------------
 * Transactional Firewall Policy Application & Rollback (StockFW 1.0.8)
 *
 * Provides a robust, transaction-like policy application engine:
 *   1. Snapshot current live state via platform-supplied ops.
 *   2. Clear existing managed rules (verified by re-enumeration).
 *   3. Apply new rules sequentially with error tracking.
 *   4. On any failure, execute verified rollback to the snapshot.
 *   5. Never report success if any rule failed or rollback was unverified.
 *
 * Pure core: no OS calls, fully testable with scripted fake backends.
 *--------------------------------------------------------------------*/
#ifndef FS_TXAPPLY_H
#define FS_TXAPPLY_H

#include <glib.h>
#include "core/fs-types.h"
#include "core/fs-rules.h"
#include "core/fs-fwrule.h"
#include "core/fs-backend.h"

G_BEGIN_DECLS

/* A structured specification of a single live firewall rule, owned. */
typedef struct
{
	gchar *name;
	gchar *direction;    /* "in" | "out" */
	gchar *action;       /* "allow" | "block" */
	gchar *protocol;     /* "TCP" | "UDP" | "any" */
	gchar *local_ports;
	gchar *remote_ports;
	gchar *remote_address;
	gchar *program;      /* executable path, or "" */
} FsTxRuleSpec;

void fs_tx_rule_spec_free (FsTxRuleSpec *spec);

/* Platform operations vtable for transactional apply. */
typedef struct
{
	/* Enumerate all managed rules currently active. Returns GList of FsTxRuleSpec*. */
	GList *(*snapshot) (gpointer user_data, GError **error);

	/* Remove all managed rules. Returns TRUE on verified zero remaining. */
	gboolean (*clear) (gpointer user_data, GError **error);

	/* Add a single concrete rule. Returns TRUE on success. */
	gboolean (*add_rule) (gpointer user_data, const FsFwRule *rule, GError **error);

	/* Re-add a rule spec during rollback. Returns TRUE on success. */
	gboolean (*restore_spec) (gpointer user_data, const FsTxRuleSpec *spec, GError **error);

	/* Verify all specified rule names are currently active. Returns TRUE if all present. */
	gboolean (*verify_present) (gpointer user_data, const GList *specs, GError **error);
} FsTxOps;

/* Execute transactional policy application.
 * Returns FS_APPLY_OK, FS_APPLY_PARTIAL, or FS_APPLY_FAILED.
 * On failure, attempts rollback to the snapshot and reports rollback status. */
FsApplyResult fs_tx_apply (const FsTxOps *ops, gpointer user_data,
                           const GList *new_rules, GError **error);

G_END_DECLS

#endif /* FS_TXAPPLY_H */
