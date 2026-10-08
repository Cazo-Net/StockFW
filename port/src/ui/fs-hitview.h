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

GtkWidget *fs_hitview_page (void);

/* The policy the right-click Event -> Rule actions stage into.  Set by
 * fs-app.c once the policy exists: the Events page is built before
 * the policy is created, so the pointer arrives after the page. */
void fs_hitview_set_policy (FsPolicy *policy);

/* Appends one hit and returns FALSE when the cap is reached. */
gboolean fs_hitview_append (const FsHit *hit);

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

G_END_DECLS

#endif /* FS_HITVIEW_H */