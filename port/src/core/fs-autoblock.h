/*---[ fs-autoblock.h ]--------------------------------------------------
 * Sentinel's persisted auto-block list, the part that needs no UI.
 *
 * Sentinel (src/ui/fs-copilot.c) stages a block into the policy and
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
 * file means nothing was staged: 0. */
guint fs_autoblock_expire (FsPolicy *policy, gint64 now_epoch,
                           gboolean lift_all);

G_END_DECLS

#endif /* FS_AUTOBLOCK_H */
