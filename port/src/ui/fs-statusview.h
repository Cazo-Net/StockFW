#ifndef FS_STATUSVIEW_H
#define FS_STATUSVIEW_H

#include <gtk/gtk.h>
#include "core/fs-types.h"

G_BEGIN_DECLS

GtkWidget     *fs_statusview_page (void);

void           fs_statusview_set_state (FsFirewallState state);
FsFirewallState fs_statusview_get_state (void);

/* Called by the backend log callback; drives the counters. */
void fs_statusview_event_in      (gboolean serious);
void fs_statusview_event_out     (gboolean serious);
void fs_statusview_events_reset  (void);

G_END_DECLS

#endif /* FS_STATUSVIEW_H */