/*---[ fs-topology.h ]--------------------------------------------------
 * Interactive Cairo-rendered network flow graph and topology visualizer.
 *
 * Displays network nodes (This Computer, LAN Gateway, Internet, Mesh Peers,
 * Firewall Wall) and active network flow edges with Cairo rendering, packet
 * animations, throughput counters, node inspection, filtering, and graph/table view.
 *--------------------------------------------------------------------*/
#ifndef FS_TOPOLOGY_H
#define FS_TOPOLOGY_H

#include <gtk/gtk.h>

G_BEGIN_DECLS

/* Builds and returns the Topology page widget. */
GtkWidget *fs_topology_page (void);

/* Samples or updates network flow and node telemetry. */
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
