/*---[ fs-topology.h ]--------------------------------------------------
 * The Topology page: a preview that draws a fixed example diagram, as a
 * graph or a table.  It reads nothing from this computer's network
 * (fs-topology.c).
 *--------------------------------------------------------------------*/
#ifndef FS_TOPOLOGY_H
#define FS_TOPOLOGY_H

#include <gtk/gtk.h>

G_BEGIN_DECLS

/* Builds and returns the Topology page widget. */
GtkWidget *fs_topology_page (void);

/* Moves the markers one step along the lines and redraws.  Nothing
 * calls it in the program; it reads no network data. */
void fs_topology_sample (void);

/* Smoke test and accessor helpers. */
guint fs_topology_node_count (void);
guint fs_topology_flow_count (void);

void  fs_topology_set_zoom (gdouble zoom);
gdouble fs_topology_get_zoom (void);

void  fs_topology_select_node_by_index (guint index);
const gchar *fs_topology_get_selected_node_name (void);

G_END_DECLS

#endif /* FS_TOPOLOGY_H */
