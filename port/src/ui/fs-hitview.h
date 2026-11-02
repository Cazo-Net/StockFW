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
#include "core/fs-eventstore.h"

G_BEGIN_DECLS

/* How many events the list keeps by default (Preferences > Events
 * sets it, 1,000 to 1,000,000).  Beyond it the event that arrived
 * first is dropped, so a long-running session cannot exhaust memory.
 * Here because the smoke test asserts the budget against the same
 * number the code uses. */
#define FS_HITVIEW_MAX_ROWS FS_EVENTSTORE_DEFAULT_CAPACITY

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

/* The filter bar's settings applied now, rather than after the short
 * typing pause (the smoke test).  FALSE, with the reason shown on the
 * page, when a box holds something that is not a port, an address or
 * a time; the list then keeps its previous filter. */
gboolean fs_hitview_refilter_now (void);

/* The rows the list shows, in the order shown, as CSV (see
 * fs_eventstore_write_csv).  *written: how many. */
gboolean fs_hitview_export_csv (const gchar *path, guint *written,
                                GError **error);

/* The store behind the list (the smoke test reads it). */
FsEventStore *fs_hitview_store (void);

/* Preferences > Events was saved: the list size and the history
 * settings take effect now. */
void fs_hitview_apply_settings (void);

/* Deletes the saved history files.  The list itself is left as it is.
 * Returns how many files went. */
guint fs_hitview_clear_history (GError **error);

/* Where history is kept, and why it is not being written (NULL when
 * it is, or when it is switched off). */
gchar       *fs_hitview_history_dir (void);
const gchar *fs_hitview_history_problem (void);

/* How many events were read from history when the page was built. */
guint fs_hitview_history_loaded (void);

/* Writes out what is queued for the history file and closes it (quit). */
void fs_hitview_shutdown (void);

/* Starts / stops the platform event source feeding the list. */
gboolean fs_hitview_start (GError **error);
void     fs_hitview_stop  (void);
gboolean fs_hitview_active (void);

void     fs_hitview_clear  (void);
void     fs_hitview_reload (void);

const FsHit *fs_hitview_selected (void);

G_END_DECLS

#endif /* FS_HITVIEW_H */