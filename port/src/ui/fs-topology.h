/*---[ fs-topology.h ]--------------------------------------------------
 * The Topology page: this computer's open connections and the addresses
 * the firewall blocked in the last ten minutes, as a diagram or a
 * table.  Everything on it is read from this computer (fs-topology.c).
 *--------------------------------------------------------------------*/
#ifndef FS_TOPOLOGY_H
#define FS_TOPOLOGY_H

#include <gtk/gtk.h>
#include "core/fs-types.h"

G_BEGIN_DECLS

/* Builds and returns the Topology page widget. */
GtkWidget *fs_topology_page (void);

/* One event, as it arrives: the Events page hands every event it lists
 * to this.  A blocked one is remembered under its remote address for
 * ten minutes after the last block from that address; anything else is
 * ignored.  Safe before the page is built and after it is destroyed. */
void fs_topology_note_hit (const FsHit *hit);

/* TRUE when `address' is on the local side: IPv4 private, loopback,
 * link-local, CGNAT, multicast and broadcast; IPv6 loopback, link-local,
 * unique-local and multicast; an IPv4-mapped form of any of those.
 * Brackets and a zone ("fe80::1%eth0") are accepted.  FALSE for a public
 * address and for text that is not an address. */
gboolean fs_topology_address_is_local (const gchar *address);

/* ---- for the smoke test ------------------------------------------- *
 * The page keeps a model (nodes and the links between them) that is a
 * pure function of the last list of connections and of the remembered
 * blocks, so a test can feed it and read it back without a display
 * clock. */

/* Ask the backend for its open connections now, as the page's own
 * three-second timer does while the page is on show. */
void fs_topology_refresh (void);

/* Take this list (FsConnection*, copied) in place of the backend's. */
void fs_topology_set_connections (const GList *connections);

/* fs_topology_note_hit () with the clock given: `now_us' is on the
 * g_get_monotonic_time () scale. */
void fs_topology_note_hit_at (const FsHit *hit, gint64 now_us);

/* Forget every block older than ten minutes at `now_us'. */
void fs_topology_expire (gint64 now_us);

/* Node 0 is always "This computer".  The programs follow, busiest
 * first, then "Local network" and "Internet" when they have
 * connections, then the blocked addresses, newest first. */
guint        fs_topology_node_count (void);
const gchar *fs_topology_node_title (guint index);
const gchar *fs_topology_node_detail (guint index);
guint        fs_topology_node_connections (guint index);
/* The first node with this title, or -1. */
gint         fs_topology_find_node (const gchar *title);
/* Where the node was drawn, or would be at the diagram's present size.
 * FALSE for an index that does not exist. */
gboolean     fs_topology_node_rect (guint index, GdkRectangle *rect);

guint fs_topology_link_count (void);
guint fs_topology_blocked_link_count (void);
/* How many addresses are remembered as blocked (the diagram draws the
 * newest four; the table lists them all). */
guint fs_topology_blocked_count (void);

/* The sentence the diagram shows where the programs would be when it
 * has none to show, or NULL when it has some. */
const gchar *fs_topology_empty_text (void);

/* TRUE while a frame-clock callback is moving the lines, and while the
 * three-second timer is running. */
gboolean fs_topology_animating (void);
gboolean fs_topology_polling (void);

/* Where the dashes stand, in seconds of travel.  The frame clock sets
 * it while the page animates; a test sets it by hand. */
void    fs_topology_set_phase (gdouble seconds);
gdouble fs_topology_get_phase (void);

/* What a click or Enter on the node does: opens its details in the
 * drawer.  FALSE for an index that does not exist. */
gboolean fs_topology_activate_node (guint index);

/* The "Show as table" switch, and how many rows the table holds. */
void  fs_topology_set_table (gboolean table);
guint fs_topology_table_rows (void);

G_END_DECLS

#endif /* FS_TOPOLOGY_H */
