/*---[ fs-hitview.h ]---------------------------------------------------
 * The Events page: the real-time list of firewall hits.
 *
 * Ported from hitview.c.  The original tailed the system log with
 * gnome-vfs; the log source is now the platform backend's log_start(),
 * which on Windows reads the firewall event channel.
 *--------------------------------------------------------------------*/
#ifndef FS_HITVIEW_H
#define FS_HITVIEW_H

#include <gtk/gtk.h>
#include "core/fs-types.h"
#include "core/fs-rules.h"

G_BEGIN_DECLS

/* How many rows the list keeps.  Beyond this the OLDEST row is
 * dropped (the list reads newest-first), so a long-running session
 * cannot exhaust memory.  Here because the smoke test asserts the
 * budget against the same number the code uses. */
#define FS_HITVIEW_MAX_ROWS 2000

GtkWidget *fs_hitview_page (void);

/* The policy the right-click Event -> Rule actions stage into.  Set by
 * fs-app.c once the policy exists: the Events page is built before
 * the policy is created, so the pointer arrives after the page. */
void fs_hitview_set_policy (FsPolicy *policy);

/* Appends one hit, newest first (a batch arrives newest-first and
 * must be placed by time, not stacked).  Returns FALSE when the row
 * is already listed: the same row twice is one event. */
gboolean fs_hitview_append (const FsHit *hit);

/* What the Time column shows for a backend timestamp: local clock
 * (plus the date when the event is from another day), or the input
 * unchanged when it is not a wevtutil stamp.  Exposed for the smoke
 * test. */
gchar *fs_hitview_format_time (const gchar *raw);

/* How many hits are currently listed. */
guint fs_hitview_count (void);

/* How many rows pass the filter bar (equals the row count when the
 * filter is empty). */
guint fs_hitview_visible_count (void);

/* Starts / stops the platform event source feeding the list. */
gboolean fs_hitview_start (GError **error);
void     fs_hitview_stop  (void);
gboolean fs_hitview_active (void);

void     fs_hitview_clear  (void);
void     fs_hitview_reload (void);

const FsHit *fs_hitview_selected (void);

/* Puts `text' in the filter bar and filters at once (the Copilot's
 * "Show in Events"). */
void fs_hitview_set_filter (const gchar *text);

/* Why no events arrive (the backend's own reason when it gives one),
 * or NULL while monitoring runs.  Caller frees. */
gchar *fs_hitview_monitor_problem (void);

G_END_DECLS

#endif /* FS_HITVIEW_H */