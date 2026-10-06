/*---[ fs-copilot.h ]---------------------------------------------------
 * UI for the Smart Firewall Copilot.
 *--------------------------------------------------------------------*/
#ifndef FS_COPILOT_VIEW_H
#define FS_COPILOT_VIEW_H

#include <gtk/gtk.h>
#include "core/fs-copilot.h"

G_BEGIN_DECLS

GtkWidget *fs_copilot_page (FsCopilot *copilot);

void fs_copilot_view_refresh (void);

/* Called from the events feed to update the stats counter. */
void fs_copilot_note_event (void);

G_END_DECLS

#endif /* FS_COPILOT_VIEW_H */