/*---[ fs-sentinel.h ]---------------------------------------------------
 * Sentinel's auto-block engine, without a window (PR 5).
 *
 * Moved out of ui/fs-copilot.c, where it ran on the Copilot page.  It
 * keeps the list of blocks it staged, the session cooldown, the state
 * file (core/fs-autoblock.h), the push of a staged or lifted block to
 * the firewall, the ten-minute expiry on GLib timeouts and the pause.
 * GLib only: no GTK, and it builds on Windows as part of fs-core.
 *
 * The caller (the desktop app's Copilot page, a test, later the daemon)
 * gives it:
 *
 *   - the Copilot whose findings it stages and the shared policy it
 *     writes to (fs_sentinel_attach);
 *   - the mode, "auto" or "detect" (fs_sentinel_set_mode);
 *   - hooks (fs_sentinel_set_hooks): the backend, the hold reason
 *     (audit-only mode, the Policy Lock) and a refresh callback that
 *     says what changed, so a window can redraw;
 *   - optionally a clock (fs_sentinel_set_clock), for tests.
 *
 * The push.  A block staged by the auto pass goes live through
 * fs_firewall_add_live: the journal (what is live) plus the block, so a
 * change saved in the policy and never applied does not ride along.  A
 * block lifted by its expiry or by lift-all comes off through
 * fs_firewall_lift_live: the journal less the block.  Before PR 5 the
 * push applied the whole policy file, unapplied edits included.  With
 * no journal at all (nothing was ever applied) there is nothing to add
 * to: the push then applies the policy, as the first apply or the first
 * start does, and that writes the journal.
 *
 * Everything runs on the thread of the GLib main loop that fires the
 * timers.
 *--------------------------------------------------------------------*/
#ifndef FS_SENTINEL_H
#define FS_SENTINEL_H

#include <glib.h>
#include "core/fs-backend.h"
#include "core/fs-copilot.h"
#include "core/fs-rules.h"

G_BEGIN_DECLS

/* While the disk refuses writes, the auto pass tries once a minute. */
#define FS_SENTINEL_RETRY_US (60 * G_USEC_PER_SEC)

/* The clock Sentinel reads and arms its timers on: the monotonic and
 * the wall clock in microseconds, and the timers that expire blocks
 * and end a pause.  GLib's own by default.  A test hands in a fake
 * clock to run ten minutes in no time (tests/test-sentinel.c); NULL
 * puts GLib's back.  Every field must be set. */
typedef struct
{
	gint64   (*monotonic_us)   (void);
	gint64   (*real_us)        (void);
	guint    (*timeout_ms)     (guint ms, GSourceFunc fn, gpointer data);
	guint    (*timeout_s)      (guint s, GSourceFunc fn, gpointer data);
	gboolean (*source_remove)  (guint id);
} FsSentinelClock;

void fs_sentinel_set_clock (const FsSentinelClock *clock);

/* One block Sentinel staged.  Owned by the engine: read it, never free
 * or change it, and do not keep it past the next engine call (a retire
 * frees it; fs_sentinel_holds says whether it is still staged). */
typedef struct
{
	FsRuleKind kind;
	gchar     *csv;                /* the staged rule, for removal   */
	gchar     *title;              /* the finding's title            */
	gint64     at_us;              /* when it was staged (monotonic) */
	gint64     at_epoch;           /* staging time, wall clock       */
} FsSentinelBlock;

/* What the refresh hook is told. */
typedef enum
{
	/* The policy and its file changed (a block staged or removed). */
	FS_SENTINEL_POLICY_CHANGED,
	/* What Sentinel says about some finding changed: a lift, a gate
	 * that now withholds a block, a pause or a resume that staged. */
	FS_SENTINEL_FINDINGS_CHANGED,
	/* `block' was taken down for good (`why' says how).  Called after
	 * it left the policy and before it leaves the list. */
	FS_SENTINEL_RETIRED,
	/* The pause began, or ended by hand (before the catch-up pass). */
	FS_SENTINEL_PAUSED,
	FS_SENTINEL_RESUMED
} FsSentinelEvent;

typedef struct
{
	/* The backend the push goes to; NULL or returning NULL: none. */
	const FsBackend *(*backend) (void);
	/* Why changes are held (audit-only mode, the Policy Lock), or
	 * NULL.  The desktop app's is fs_policyview_hold_reason. */
	const gchar     *(*hold)    (void);
	/* Told what changed; may be NULL.  `block' and `why' are set for
	 * FS_SENTINEL_RETIRED only. */
	void             (*refresh) (FsSentinelEvent event,
	                             const FsSentinelBlock *block,
	                             const gchar *why);
} FsSentinelHooks;

/* The hooks are copied; NULL clears them. */
void fs_sentinel_set_hooks (const FsSentinelHooks *hooks);

/* The Copilot whose findings the auto pass stages, and the policy it
 * writes to (the shared one: the Policy page edits it too).  Either may
 * be NULL; the auto pass then does nothing. */
void fs_sentinel_attach (FsCopilot *copilot, FsPolicy *policy);

/* "auto" (the default) or "detect".  Only stored: leaving auto mode
 * does not lift anything by itself (the caller calls lift_all). */
void         fs_sentinel_set_mode (const gchar *mode);
const gchar *fs_sentinel_mode     (void);
gboolean     fs_sentinel_is_auto  (void);

/* The auto pass: stages every auto-applicable finding that is not
 * already in the policy, when in auto mode and not paused, and pushes
 * them.  TRUE when something was staged. */
gboolean fs_sentinel_auto_pass (void);

/* Pausing makes sense only in auto mode with a Copilot and a policy
 * (can_pause).  While paused the auto pass stages nothing; blocks
 * already staged keep their own ten minutes.  pause (0) resumes at
 * once and catches up; otherwise it resumes by itself after
 * `seconds'.  Both are audited.  Not persisted across a restart. */
gboolean fs_sentinel_can_pause (void);
gboolean fs_sentinel_paused    (gint64 *seconds_left);
void     fs_sentinel_pause     (guint seconds);

/* Boot restore: take the staged blocks whose ten minutes ran out while
 * StockFW was not running out of `policy', re-arm the rest with their
 * ORIGINAL wall-clock time, and lift everything when not in auto
 * mode.  Attaches `policy'.  Every row that is due is copied into `due'
 * (may be NULL): the caller takes them off the firewall.  TRUE when any
 * row was due.  See fs_copilot_autoblocks_restore (ui/fs-copilot.h). */
gboolean fs_sentinel_restore (FsPolicy *policy, FsPolicy *due);

/* Retry the state-file write when the last one failed.  TRUE when the
 * file matches what is staged. */
gboolean fs_sentinel_flush (void);

/* Lift every staged block (into the cooldown), push, and say so.  TRUE
 * when anything was staged. */
gboolean fs_sentinel_lift_all (const gchar *why);

/* The user's Allow for `dest': retire its staged blocks and remove
 * Sentinel's own rows for it from the policy (a comment starting
 * "Sentinel:"); the user's own rules are never touched.  No push: the
 * caller's push takes it to the firewall.  TRUE when anything
 * changed. */
gboolean fs_sentinel_lift_for_dest (const gchar *dest);

/* Retire one staged block (the Undo button): out of the policy, into
 * the cooldown, out of the list and the state file.  No push: the
 * caller pushes.  FALSE when `block' is not staged (any more). */
gboolean fs_sentinel_retire (FsSentinelBlock *block, const gchar *why);

/* The staged blocks. */
guint            fs_sentinel_count (void);
FsSentinelBlock *fs_sentinel_nth   (guint i);
FsSentinelBlock *fs_sentinel_find  (FsRuleKind kind, const gchar *csv);
gboolean         fs_sentinel_holds (const FsSentinelBlock *block);

/* TRUE when this session took the rule down and will not stage it
 * again. */
gboolean fs_sentinel_cooled (FsRuleKind kind, const gchar *csv);

G_END_DECLS

#endif /* FS_SENTINEL_H */
