/*---[ fs-trustview.h ]--------------------------------------------------
 * The Trust page: the trust engine's user surface.
 *
 * Inspect a file (hash, signature, publisher, baseline state),
 * attest or forget it with a confirmation and an audit line, list
 * the baseline with live per-row status, and scan the running
 * processes through the backend.
 *--------------------------------------------------------------------*/
#ifndef FS_TRUSTVIEW_H
#define FS_TRUSTVIEW_H

#include <gtk/gtk.h>

#include "core/fs-trust.h"

G_BEGIN_DECLS

GtkWidget *fs_trustview_page (void);

/* TRUE while an inspect / refresh / scan task is in flight.  The
 * page disables its write buttons meanwhile; the smoke test pumps
 * the main loop until this reads FALSE. */
gboolean fs_trustview_busy (void);

/* The assessment the report grid is showing (borrowed; NULL before
 * the first inspect).  Exposed for the smoke test the same way
 * fs_hitview_count() is. */
const FsTrustAssessment *fs_trustview_current (void);

/* Rows currently in the baseline list: store rows after a refresh,
 * assessed processes after a scan. */
guint fs_trustview_list_count (void);

G_END_DECLS

#endif /* FS_TRUSTVIEW_H */
