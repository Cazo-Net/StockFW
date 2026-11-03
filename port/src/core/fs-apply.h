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
 * the whole set is an add.
 *
 * refused counts the rows of `after' the translation refused
 * (fs_fwrule_expand_checked: a port that does not parse).  They have
 * no rule in any list, so a delta that carried on without them would
 * report success for a row it dropped; a delta with refusals is never
 * empty, and the gate takes the full apply, whose verdict reports
 * them. */
typedef struct
{
	GList   *remove;   /* gchar*, owned by the delta    */
	GList   *add;      /* FsFwRule*, owned              */
	GList   *repair;   /* FsFwRule*, owned              */
	gboolean empty;
	guint    refused;
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
	gboolean        settings;          /* the whole set went out because
	                                    * firewall settings changed: a
	                                    * settings apply, or a policy
	                                    * apply with settings pending   */
	FsFirewallState firewall_was;      /* what the backend read before
	                                    * the apply: FS_FW_NONE when it
	                                    * was not read (no get_state, a
	                                    * hold, no backend)             */
} FsApplyOutcome;

/* The single safe path from a policy to the firewall.  The policy
 * file has normally been saved by the caller before this runs; the
 * gate never edits the policy itself.  hold, when non-NULL and
 * non-empty, is the reason the firewall must stay untouched
 * ("audit-only testing mode", "policy locked") and the apply becomes
 * FS_APPLY_DRY_RUN with an audit line.  Returns a caller-owned
 * outcome; NULL only if policy was NULL.
 *
 * The journal says what the last apply put live, not what is live now:
 * after a stop nothing is.  So where a start installs the policy
 * (start_applies_policy, Linux) the narrow path and the "no change"
 * shortcut are taken only when the backend reads the firewall as
 * running; otherwise the whole policy goes out (apply_rules), which
 * starts the firewall, and the audit mode says "full (firewall was
 * stopped)".  The rollback target is the journal either way. */
FsApplyOutcome *fs_policy_apply_safe (const FsBackend *backend,
                                      FsPolicy *policy,
                                      const gchar *source,
                                      const gchar *hold,
                                      GError **error);
void fs_apply_outcome_free (FsApplyOutcome *outcome);

/* Start the firewall through the gate (1.0.7).  Every start -- the
 * app's "start on program startup", the Start/Resume buttons, `stockfw
 * start' at boot -- comes through here, so a start is held, refused
 * and audited exactly like an apply.  A start brings back what was
 * live; it never puts live a change nobody applied:
 *
 *   - no backend available: refused (FS_APPLY_NO_IPTABLES), nothing
 *     touched;
 *   - a backend whose start only switches enforcement on (Windows
 *     profiles): started, held or not -- the rules in the firewall's
 *     own store do not change, so there is nothing to hold back and
 *     the journal is already right;
 *   - a backend whose start installs a policy (start_applies_policy,
 *     Linux) installs the JOURNAL -- the last policy that was really
 *     live -- less the rules in `lift' (Sentinel blocks whose ten
 *     minutes ran out), held or not.  The policy file may carry
 *     changes not applied yet (held by audit-only mode or the Policy
 *     Lock, or simply never applied); those stay off the firewall, and
 *     the audit line says what they are;
 *   - such a backend with a journal that exists but cannot be read:
 *     refused (FS_APPLY_FAILED), firewall untouched -- neither the
 *     journal nor the file is known to be safe;
 *   - such a backend with no journal at all (nothing ever applied):
 *     held -> FS_APPLY_DRY_RUN, firewall untouched; unheld ->
 *     backend->start(), which installs `policy' (the first apply), and
 *     the journal records it.  The caller must have checked that the
 *     policy really loaded (`stockfw start' refuses a missing or
 *     malformed policy file first).
 *
 * `policy' must be the policy already handed to the backend with
 * fs_backend_set_context(), loaded from disk: the caller loads first,
 * this never does.  `lift' may be NULL.  Returns a caller-owned
 * outcome (result FS_APPLY_OK means the firewall is now running);
 * NULL only if policy was NULL. */
FsApplyOutcome *fs_firewall_start_lifting (const FsBackend *backend,
                                           FsPolicy *policy,
                                           const FsPolicy *lift,
                                           const gchar *source,
                                           const gchar *hold,
                                           GError **error);

/* fs_firewall_start_lifting() with nothing to lift. */
FsApplyOutcome *fs_firewall_start_safe (const FsBackend *backend,
                                        FsPolicy *policy,
                                        const gchar *source,
                                        const gchar *hold,
                                        GError **error);

/* Take the rules in `lift' (Sentinel blocks whose time ran out) off
 * the firewall and nothing else: the journal -- what is live -- less
 * those rules goes through fs_policy_apply_safe(), so the only change
 * the firewall sees is their removal.  The policy FILE is never
 * applied here: it may hold changes nobody applied.  NULL (nothing
 * touched, nothing audited) when there is no journal or none of the
 * rules is in it; otherwise the apply's outcome, caller-owned.  A
 * firewall that is stopped is not started: see the note after
 * fs_firewall_add_live. */
FsApplyOutcome *fs_firewall_lift_live (const FsBackend *backend,
                                       const FsPolicy *lift,
                                       const gchar *source,
                                       const gchar *hold,
                                       GError **error);

/* [ fs_firewall_add_live ] (PR 4, 4A)
 * The mirror of fs_firewall_lift_live: put the rules in `add' on the
 * firewall and nothing else.  The journal -- what is live -- plus
 * those rules goes through fs_policy_apply_safe(), so the only change
 * the firewall sees is their addition.  The policy FILE is never
 * applied here: it may hold changes nobody applied (an allow, say),
 * and a block must not carry them live.  Nor is it written: the
 * caller saves the rows itself (fs_policy_add_persist_pair), before
 * or after.  Used by `copilot block', `events act block-*' and, from
 * PR 5, Sentinel's push.
 *
 * NULL (nothing touched, nothing audited) when `add' is NULL or
 * empty, when there is no journal (nothing is on record as live; the
 * saved rows go out with the next apply, or the first start, which
 * installs the file) or when every rule is already in the journal.
 * Otherwise a caller-owned outcome. */
FsApplyOutcome *fs_firewall_add_live (const FsBackend *backend,
                                      const FsPolicy *add,
                                      const gchar *source,
                                      const gchar *hold,
                                      GError **error);

/* Both live edits on a backend whose start installs the policy
 * (Linux), with a firewall the backend reads as STOPPED and no hold:
 * there an apply IS a start, and a firewall the user stopped is not
 * started behind their back.  The journal is the policy the next start
 * installs, so it alone is changed (with the settings it records kept)
 * and the firewall is untouched: the outcome has result
 * FS_APPLY_DRY_RUN, applied FALSE, held FALSE and firewall_was
 * FS_FW_STOPPED, and the audit line says "recorded for the next
 * start".  Without this a block saved while the firewall is stopped
 * would never go live at the next start (it installs the journal), and
 * a lifted block would come back with it.  A hold (audit-only, the
 * Policy Lock) keeps the journal unchanged too: the outcome is the
 * gate's held DRY_RUN. */

/* [ fs_firewall_live_keeps_settings ] (PR 4 review)
 * TRUE: the caller gave the backend the settings the journal records
 * (fs_settings_from_journal), so a live edit on a running firewall
 * keeps that record as it is, as the stopped path above does.  The
 * settings saved and not applied stay pending (fs_apply_settings_
 * pending) and go out with the next apply, never with a block or a
 * lift.  FALSE (the default): the journal records the saved
 * preferences, which is right for a caller that gave the backend
 * those.  The control layer (src/control) sets it with each context
 * it hands the backend. */
void fs_firewall_live_keeps_settings (gboolean keep);

/* Stop the firewall, on the record.  Never held: a hold keeps policy
 * CHANGES off the firewall, while stopping is the user's own way out
 * of a ruleset that broke something, and must always work.  The audit
 * line says who stopped it and whether it worked. */
gboolean fs_firewall_stop_logged (const FsBackend *backend,
                                  const gchar *source,
                                  GError **error);

/* The same gate for a change of firewall settings (Preferences: ICMP,
 * rejection method, devices ...).  The caller has already put the new
 * settings in the backend's context.  Differences from the policy
 * gate:
 *   - always the whole-set apply_rules, never the narrow path and
 *     never the "no change" shortcut: the policy may be unchanged
 *     while every rule the settings produce is not;
 *   - a rollback runs under the settings that were live: swap (TRUE)
 *     must put the previous settings in the context and swap (FALSE)
 *     the new ones back; the gate calls them around the rollback
 *     only.  The new settings stay in the context afterwards: they
 *     are saved, and the next apply tries them again;
 *   - audit lines say "firewall settings" instead of "policy".
 * Holds, refusals, verdicts and the journal work exactly as in
 * fs_policy_apply_safe.  policy is the one to apply the settings
 * with: Preferences passes the last applied one (the journal's), so
 * Policy-page edits nobody has applied yet do not go out with them. */
typedef void (*FsSettingsSwapFunc) (gboolean previous, gpointer data);

FsApplyOutcome *fs_settings_apply_safe (const FsBackend *backend,
                                        FsPolicy *policy,
                                        const gchar *source,
                                        const gchar *hold,
                                        FsSettingsSwapFunc swap,
                                        gpointer swap_data,
                                        GError **error);

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
 * rules directory.
 *
 * The journal also records which rule translation wrote the live
 * rules (FS_FWRULE_TRANSLATION, a "# rules translation N" line; a
 * journal without one is translation 1).  fs_policy_apply_safe uses
 * the narrow path only when that matches the running code: rules
 * written by an older translation are not what this code would
 * compute from the journal, so a delta against them would leave them
 * in place, and the gate replaces the whole set instead. */
gchar    *fs_apply_journal_path   (void);
gboolean  fs_apply_journal_save   (const FsPolicy *policy, GError **error);
/* FALSE with FS_APPLY_ERR_NO_JOURNAL when there is simply no journal
 * yet, FS_APPLY_ERR_UNREADABLE or FS_APPLY_ERR_MALFORMED otherwise.
 * *policy is cleared first, so on failure it is empty, never
 * half-loaded. */
gboolean  fs_apply_journal_load   (FsPolicy *policy, GError **error);

/* The firewall settings recorded with the journal (each successful
 * apply records the saved preferences it went out with): key ->
 * value text, as fs_prefs_firewall_values gives it.  NULL when there
 * is no journal, or it predates the record.  Caller unrefs. */
GHashTable *fs_apply_journal_settings (void);

/* TRUE when the firewall settings saved now are not the ones recorded
 * with the journal -- saved in Preferences, not applied yet -- or the
 * journal does not record any.  FALSE with no journal at all (every
 * apply is whole then).  While TRUE, fs_policy_apply_safe applies the
 * whole set even for an unchanged policy, so the settings go out with
 * the next policy apply on every backend. */
gboolean    fs_apply_settings_pending (void);

/* ---- PR 3: settings at boot, and "Apply settings now" ---------------- */

/* The journal's recorded settings as an FsSettings (fs_settings_free),
 * or NULL when there is no journal or it predates the record.
 * recorded_out (nullable) receives the key -> value map itself
 * (g_hash_table_unref). */
FsSettings *fs_settings_from_journal (GHashTable **recorded_out);

/* fs_firewall_start_lifting, for a caller that gave the backend other
 * settings than the saved preferences: `recorded' (key -> value text,
 * as fs_apply_journal_settings gives it) is what the journal written by
 * this start records, so the record keeps saying what is live.  NULL
 * records the saved preferences, as fs_firewall_start_lifting does.
 * `stockfw start' (the boot unit) gives the backend the journal's own
 * settings when the journal records them (3B): a boot brings back the
 * settings last applied, never ones saved and not applied. */
FsApplyOutcome *fs_firewall_start_recorded (const FsBackend *backend,
                                            FsPolicy *policy,
                                            const FsPolicy *lift,
                                            GHashTable *recorded,
                                            const gchar *source,
                                            const gchar *hold,
                                            GError **error);

/* How the backend is handed a policy and settings: the platform's
 * fs_backend_set_context, or a test's own.  Core never calls the
 * backend's global itself. */
typedef void (*FsSettingsContextFunc) (FsPolicy *policy,
                                       FsSettings *settings);

/* [ fs_settings_apply_saved ] (J36)
 * Put `settings' (the saved preferences, as loaded) in force under
 * `under', the policy that is live -- the journal's, so policy edits
 * nobody applied stay off -- through fs_settings_apply_safe: holds,
 * the whole-set apply, rollback and the audit line.  The rollback runs
 * under the settings the journal recorded, or, with no record,
 * `saved_before' (the settings saved before this change; NULL: the
 * table's defaults).  set_context hands the backend each pair; the new
 * pair stays in its context afterwards, so `under' and `settings' must
 * outlive the caller's use of the backend.  NULL (nothing touched)
 * when under or settings is NULL. */
FsApplyOutcome *fs_settings_apply_saved (const FsBackend *backend,
                                         FsSettingsContextFunc set_context,
                                         FsPolicy *under,
                                         FsSettings *settings,
                                         const FsSettings *saved_before,
                                         const gchar *source,
                                         const gchar *hold,
                                         GError **error);

G_END_DECLS

#endif /* FS_APPLY_H */
