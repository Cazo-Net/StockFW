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

G_END_DECLS

#endif /* FS_COPILOT_VIEW_H */