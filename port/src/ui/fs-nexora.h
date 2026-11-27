/*---[ fs-nexora.h ]-----------------------------------------------------
 * The Nexora page: a preview with fixed sample figures.  No model runs
 * and nothing is measured on this computer (fs-nexora.c).
 *--------------------------------------------------------------------*/
#ifndef FS_NEXORA_H
#define FS_NEXORA_H

#include <gtk/gtk.h>

G_BEGIN_DECLS

/* The Nexora page: a preview with fixed sample figures (fs-nexora.c). */
GtkWidget *fs_nexora_page (void);

/* Smoke test / introspection helpers */
gboolean fs_nexora_busy (void);
guint fs_nexora_counter_count (void);
gdouble fs_nexora_get_confidence (void);
gdouble fs_nexora_get_psi (void);

G_END_DECLS

#endif /* FS_NEXORA_H */
