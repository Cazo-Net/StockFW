/*---[ fs-autoblock.h ]--------------------------------------------------
 * Sentinel's persisted auto-block list, the part that needs no UI.
 *
 * Sentinel (core/fs-sentinel.c) stages a block into the policy and
 * writes one row per staged block to a small state file, so a restart
 * can still lift it ten minutes after it was staged.  The app's own
 * boot restore does that and more (re-arming the timer, the session
 * cooldown).  This file is what a start WITHOUT the app needs --
 * `stockfw start' at boot -- so a block whose ten minutes ran out
 * while the machine was off is not installed again by the next start.
 *
 * State file rows: "S,<epoch>,<kind>,<rule csv>", csv last.
 *--------------------------------------------------------------------*/
#ifndef FS_AUTOBLOCK_H
#define FS_AUTOBLOCK_H

#include <glib.h>
#include "core/fs-apply.h"
#include "core/fs-backend.h"
#include "core/fs-rules.h"

G_BEGIN_DECLS

/* Every Sentinel auto-block lifts this long after it was staged. */
#define FS_AUTOBLOCK_TTL_S 600

/* The preference holding Sentinel's mode: "auto" or "detect". */
#define FS_PREFS_SENTINEL_MODE "/apps/stockfw/client/sentinel/mode"

/* Where the state file lives: next to behavior.csv and trust.csv, in
 * the per-user config directory (%APPDATA%\stockfw on Windows).
 * $STOCKFW_AUTOBLOCK_FILE overrides it (tests).  Caller frees. */
gchar *fs_autoblock_state_path (void);

/* Take out of `policy' (and its files) every staged block whose TTL
 * has run out at `now_epoch' -- or every staged block, when
 * `lift_all' (Sentinel is no longer in auto mode) -- and rewrite the
 * state file with the rows that remain.  A row whose rule could not be
 * removed (disk error) is kept, so a later pass retries it.  Rows the
 * user already deleted from the policy simply go.  Returns how many
 * rules came out of the policy; each is audited.  A missing state
 * file means nothing was staged: 0.
 *
 * `lifted', when not NULL, receives a copy of EVERY row that is due,
 * whether it came out of the file, had already gone from it, or is
 * kept for a retry: the journal of what was live may still hold any of
 * them, and the start must leave them all out
 * (fs_firewall_start_lifting). */
guint fs_autoblock_expire (FsPolicy *policy, gint64 now_epoch,
                           gboolean lift_all, FsPolicy *lifted);

/* ---- PR 4 (4A): lifting from a firewall that runs ------------------ *
 * The lift helpers take Sentinel's blocks down the way the desktop
 * app's Undo, its switch to "Detect only" and an Allow from the Events
 * page do, with no window:
 *
 *   1. the rows chosen are taken out of the state file, and their rules
 *      out of the policy file (fs_policy_remove_persist; each removal
 *      is audited, "sentinel auto-block removed");
 *   2. fs_firewall_lift_live takes the rules off the firewall: the
 *      journal less those rules, never the policy file, which may hold
 *      changes nobody applied.  A stopped firewall is not started (the
 *      journal alone changes, fs-apply.h);
 *   3. a rule that is still live afterwards (the lift was held by
 *      audit-only mode or the Policy Lock, or it failed) keeps a row in
 *      the state file, dated so that it is already due
 *      (now - FS_AUTOBLOCK_TTL_S): `stockfw start', the desktop app's
 *      restore and the next lift_expired leave it out or take it off,
 *      so no block stays live that nothing manages.
 *
 * All three run under the policy lock (re-entrant: the control layer
 * already holds it).  `policy' is the policy as loaded from disk under
 * that lock; it is changed in place.  The helpers never prompt, never
 * print and never start a stopped firewall.
 *
 * The desktop app keeps its own list in memory while it runs and
 * writes the state file from it; a terminal lift while a window runs
 * is overwritten by the window's next save.  The daemon (PR 7) ends
 * that by being the only writer.
 *
 * Each helper returns a caller-owned result (fs_autoblock_lift_free),
 * or NULL with *error set when the policy lock could not be taken
 * (nothing changed).  A missing state file means nothing was staged. */
typedef struct
{
	guint           rows;      /* state rows chosen                    */
	guint           removed;   /* rules taken out of the policy file   */
	guint           gone;      /* chosen, but already gone from it     */
	guint           kept;      /* rows kept in the state file: the
	                            * policy file could not be written, or
	                            * the rule is still live (step 3)       */
	FsPolicy       *lifted;    /* every rule lifted (never NULL)       */
	FsApplyOutcome *outcome;   /* fs_firewall_lift_live's, or NULL when
	                            * none of them was live                 */
	gboolean        state_saved; /* the state file was written (or did
	                            * not need to be)                       */
} FsAutoblockLift;

void fs_autoblock_lift_free (FsAutoblockLift *lift);

/* Every staged block: `sentinel lift --all' and `sentinel mode detect'
 * (G1).  why: the audit's reason ("Sentinel switched to detect only";
 * NULL: "lifted by user"). */
FsAutoblockLift *fs_autoblock_lift_all (const FsBackend *backend,
                                        FsPolicy *policy,
                                        const gchar *why,
                                        const gchar *source,
                                        const gchar *hold,
                                        GError **error);

/* The blocks whose rule's target is `dest' (ASCII case ignored): the
 * staged rows of any kind, and the outbound-deny-to rows of the policy
 * that Sentinel wrote (a comment starting "Sentinel:") for it in an
 * earlier session, as fs_copilot_lift_auto_blocks_for_dest does.  The
 * user's own rules are never touched.  `sentinel lift TARGET', the
 * What-If "lift" action (H9) and `events act allow-dest' (C14).
 * NULL dest or "": nothing chosen.  why: the audit's reason (NULL:
 * "user allowed this destination", the Events page's words). */
FsAutoblockLift *fs_autoblock_lift_for_dest (const FsBackend *backend,
                                             FsPolicy *policy,
                                             const gchar *dest,
                                             const gchar *why,
                                             const gchar *source,
                                             const gchar *hold,
                                             GError **error);

/* The rows whose ten minutes ran out at `now_epoch' (a stamp from the
 * future is kept, as fs_autoblock_expire keeps it): `sentinel lift
 * --expired' (A16), from a firewall that is already running. */
FsAutoblockLift *fs_autoblock_lift_expired (const FsBackend *backend,
                                            FsPolicy *policy,
                                            gint64 now_epoch,
                                            const gchar *source,
                                            const gchar *hold,
                                            GError **error);

G_END_DECLS

#endif /* FS_AUTOBLOCK_H */
