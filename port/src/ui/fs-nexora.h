/*---[ fs-nexora.h ]-----------------------------------------------------
 * AEGIS-ML confidence scores, PSI drift gauges, 15-minute sliding window stats,
 * and active label counters for StockFW / Nexora.
 *--------------------------------------------------------------------*/
#ifndef FS_NEXORA_H
#define FS_NEXORA_H

#include <gtk/gtk.h>

G_BEGIN_DECLS

/* Create the Nexora AI & ML Intelligence / Trust Dashboard page */
GtkWidget *fs_nexora_page (void);

/* Smoke test / introspection helpers */
gboolean fs_nexora_busy (void);
guint fs_nexora_counter_count (void);
gdouble fs_nexora_get_confidence (void);
gdouble fs_nexora_get_psi (void);

G_END_DECLS

#endif /* FS_NEXORA_H */
