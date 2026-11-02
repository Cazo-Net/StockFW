/*---[ fs-copilot.h ]---------------------------------------------------
 * UI for the Smart Firewall Copilot.
 *--------------------------------------------------------------------*/
#ifndef FS_COPILOT_VIEW_H
#define FS_COPILOT_VIEW_H

#include <gtk/gtk.h>
#include "core/fs-copilot.h"
#include "core/fs-rules.h"

G_BEGIN_DECLS

/* Builds the Copilot tab.  policy is the shared traffic policy the
 * Policy page edits too: the Copilot's "Apply Selected Rule" writes
 * into it, so passing it here is what makes that button do something
 * real instead of only printing a success message. */
GtkWidget *fs_copilot_page (FsCopilot *copilot, FsPolicy *policy);

void fs_copilot_view_refresh (void);

/* Called from the events feed to update the stats counter. */
void fs_copilot_note_event (void);

/* Sentinel auto-block pass: stages every auto-applicable insight
 * (that is not already in the policy) when Sentinel is in auto mode.
 * Returns TRUE when something was staged, so the caller knows whether
 * the insights list needs rebuilding. */
gboolean fs_copilot_sentinel_auto_pass (void);

/* Tray: "Pause Sentinel auto-block for 1 hour".  Pausing only makes
 * sense while Sentinel is in auto mode (can_pause).  While paused the
 * auto pass stages nothing; insights are still reported and blocks
 * already staged keep their own ten minutes.  pause (0) resumes at
 * once (and catches up); otherwise it resumes by itself after
 * `seconds'.  Both are audited.  Not persisted across a restart. */
gboolean fs_copilot_sentinel_can_pause (void);
gboolean fs_copilot_sentinel_paused    (gint64 *seconds_left);
void     fs_copilot_sentinel_pause     (guint seconds);

/* P6 (false-outage hardening).  Boot restore: take the staged
 * auto-blocks whose ten minutes ran out while StockFW was not
 * running out of the policy, re-arm the rest with their ORIGINAL
 * wall-clock time (a restart grants no fresh ten minutes), and lift
 * everything when Sentinel is not in auto mode.  Call once, after
 * the Copilot page has been built with `policy'.
 *
 * The restore only edits the policy and its file.  Every row that is
 * due -- taken out of the policy, already gone from it, or kept there
 * for a retry -- is copied into `due' (may be NULL), because the
 * FIREWALL may still hold it: the caller starts the firewall without
 * them (fs_firewall_start_lifting) or takes them off it
 * (fs_firewall_lift_live).  Never by applying the policy file, which
 * may hold changes nobody applied.  TRUE when any row was due. */
gboolean fs_copilot_autoblocks_restore (FsPolicy *policy, FsPolicy *due);

/* The staged list is written on every stage and every retire; this
 * retries the write when the last one failed, and does nothing
 * otherwise (it never writes an empty list over the file before the
 * restore has read it).  TRUE when the file matches what is staged. */
gboolean fs_copilot_autoblocks_flush (void);

/* Lift every staged auto-block in one go (leaving auto mode does
 * this).  Each retirement enters the session cooldown, so the next
 * auto pass does not stage them straight back.  Returns TRUE when
 * anything was staged. */
gboolean fs_copilot_lift_all_auto_blocks (const gchar *why);

/* The user's explicit Allow for `dest' is the last word: on Windows
 * a block rule outranks an allow rule, so a staged Sentinel block
 * would make the Allow a silent no-op.  Retires staged blocks for
 * that destination and removes Sentinel's own persisted deny rows
 * for it; the user's own rules are never touched.  Returns TRUE when
 * anything changed -- the caller's push then takes it to the
 * firewall. */
gboolean fs_copilot_lift_auto_blocks_for_dest (const gchar *dest);

G_END_DECLS

#endif /* FS_COPILOT_VIEW_H */