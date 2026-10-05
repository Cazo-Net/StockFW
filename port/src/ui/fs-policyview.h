/*---[ fs-policyview.h ]------------------------------------------------
 * The Policy page: a list of inbound and outbound rules with add,
 * edit and remove, wired to the FsPolicy store.
 *--------------------------------------------------------------------*/
#ifndef FS_POLICYVIEW_H
#define FS_POLICYVIEW_H

#include <gtk/gtk.h>
#include "core/fs-types.h"
#include "core/fs-rules.h"

G_BEGIN_DECLS

/* Builds the page.  On first run, with no rule files present, the
 * default ruleset is installed so the user starts from something
 * working rather than an empty table. */
GtkWidget *fs_policyview_page (FsPolicy *policy);

/* Re-reads the rule files and refreshes the views. */
void fs_policyview_reload (FsPolicy *policy);

/* Persists the policy to disk. */
gboolean fs_policyview_save (FsPolicy *policy);

G_END_DECLS

#endif /* FS_POLICYVIEW_H */