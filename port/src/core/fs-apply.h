/*---[ fs-apply.h ]------------------------------------------------------
 * Safe policy enforcement (P3).
 *
 * One gate stands between the policy and the firewall:
 *
 *   - the impact of the change is measured against the last policy
 *     that is actually live (the journal), for previews and audit
 *     lines alike;
 *   - a hold -- audit-only testing mode, or the Status page's Policy
 *     Lock -- records the change but never reaches the backend;
 *   - a narrow delta touches only what changed, so untouched rules
 *     are never cleared and recreated (no window with no rules);
 *   - a failed apply rolls back to the journal and the rollback's own
 *     verdict is verified, never assumed;
 *   - every attempt is one append-only audit line.
 *
 * The backend arrives as a parameter, not a global, so the tests
 * drive a scripted fake through every branch with no firewall
 * anywhere.  Nothing in this file calls fs_backend().
 *--------------------------------------------------------------------*/
#ifndef FS_APPLY_H
#define FS_APPLY_H

#include <glib.h>
#include "core/fs-rules.h"
#include "core/fs-fwrule.h"
#include "core/fs-backend.h"

G_BEGIN_DECLS

/* Error domain for the gate and the journal. */
GQuark fs_apply_error_quark (void);
#define FS_APPLY_ERROR (fs_apply_error_quark())

enum
{
	FS_APPLY_ERR_NO_JOURNAL = 1,  /* the journal does not exist yet  */
	FS_APPLY_ERR_UNREADABLE = 2,  /* exists but could not be read    */
	FS_APPLY_ERR_MALFORMED  = 3,  /* a row could not be trusted      */
	FS_APPLY_ERR_NO_BACKEND = 4   /* nothing available to apply with */
};

/* The impact of one policy change, measured against the last applied
 * policy.  Counts are policy rows -- what the user sees on the Policy
 * page -- not concrete firewall rules.  before == NULL means "no
 * record of what is live": everything in after counts as added. */
typedef struct
{
	guint added;
	guint removed;
	guint unchanged;
	guint added_allows;
	guint added_blocks;
	guint removed_allows;
	guint removed_blocks;
} FsPolicyImpact;

FsPolicyImpact *fs_policy_impact        (const FsPolicy *before,
                                         const FsPolicy *after);
/* One line: "+N added (a allow, b block), -M removed ..., =U unchanged".
 * English and untranslated on purpose: this feeds audit lines, which
 * are evidence, not UI. */
gchar          *fs_policy_impact_describe (const FsPolicyImpact *impact);
void            fs_policy_impact_free   (FsPolicyImpact *impact);

/* The same measurement with the journal loaded for you (and freed).
 * With no journal, everything counts as added -- honest: nothing is
 * known to be live. */
FsPolicyImpact *fs_policy_impact_preview (const FsPolicy *after);

/* What changed, as backend work lists:
 *   remove -- unique names of rules that are going away;
 *   add    -- concrete rules to create;
 *   repair -- unchanged rules whose name collides with a removal
 *             (deleting by name would take them too; the backend
 *             re-creates them right after the delete).
 * empty means there is nothing to do at all.  before == NULL means
 * the whole set is an add. */
typedef struct
{
	GList   *remove;   /* gchar*, owned by the delta    */
	GList   *add;      /* FsFwRule*, owned              */
	GList   *repair;   /* FsFwRule*, owned              */
	gboolean empty;
} FsPolicyDelta;

FsPolicyDelta *fs_policy_delta      (const FsPolicy *before,
                                     const FsPolicy *after);
void           fs_policy_delta_free (FsPolicyDelta *delta);

/* One safe apply's full story.  impact is owned and never NULL. */
typedef struct
{
	FsApplyResult   result;            /* the apply's own verdict        */
	gboolean        held;              /* firewall deliberately untouched */
	const gchar    *hold_reason;       /* borrowed; set when held         */
	gboolean        applied;           /* live on the firewall            */
	gboolean        narrow;            /* the delta path was used         */
	gboolean        rollback_attempted;
	gboolean        rollback_verified;
	gchar          *rollback_detail;   /* owned; NULL when no rollback    */
	FsPolicyImpact *impact;            /* owned; never NULL               */
	gchar          *notes;             /* owned; the backend's notes on a
	                                    * successful apply, or NULL     */
} FsApplyOutcome;

/* The single safe path from a policy to the firewall.  The policy
 * file has normally been saved by the caller before this runs; the
 * gate never edits the policy itself.  hold, when non-NULL and
 * non-empty, is the reason the firewall must stay untouched
 * ("audit-only testing mode", "policy locked") and the apply becomes
 * FS_APPLY_DRY_RUN with an audit line.  Returns a caller-owned
 * outcome; NULL only if policy was NULL. */
FsApplyOutcome *fs_policy_apply_safe (const FsBackend *backend,
                                      FsPolicy *policy,
                                      const gchar *source,
                                      const gchar *hold,
                                      GError **error);
void fs_apply_outcome_free (FsApplyOutcome *outcome);

/* Audit-only testing mode: the preference, the hold reason it
 * produces (or NULL when off), and the setter for the Policy page's
 * toggle.  The Status page's Lock is UI state on top of this;
 * callers add their own reason for it. */
gboolean     fs_apply_audit_only    (void);
const gchar *fs_apply_hold_reason   (void);
void         fs_apply_set_audit_only (gboolean on);

/* The journal of what is actually live: the last policy the gate put
 * on the firewall successfully.  One CSV of <kind>,<rule-csv> rows in
 * the shared dialect.  $STOCKFW_APPLIED_FILE overrides the location
 * (tests point it somewhere disposable), otherwise applied.csv in the
 * rules directory. */
gchar    *fs_apply_journal_path   (void);
gboolean  fs_apply_journal_save   (const FsPolicy *policy, GError **error);
/* FALSE with FS_APPLY_ERR_NO_JOURNAL when there is simply no journal
 * yet, FS_APPLY_ERR_UNREADABLE or FS_APPLY_ERR_MALFORMED otherwise.
 * *policy is cleared first, so on failure it is empty, never
 * half-loaded. */
gboolean  fs_apply_journal_load   (FsPolicy *policy, GError **error);

G_END_DECLS

#endif /* FS_APPLY_H */
