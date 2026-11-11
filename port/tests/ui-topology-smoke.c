/*---[ ui-topology-smoke.c ]---------------------------------------------
 * UI smoke test for the interactive Cairo network flow graph and topology visualizer.
 *
 * Builds the topology page, tests node/flow counts, zoom controls,
 * node selection, sampling, and offscreen rendering.
 *--------------------------------------------------------------------*/

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "ui/fs-topology.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	if (!(cond)) {                                             \
		printf ("FAIL: ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
		failures++;                                         \
	} else {                                                  \
		printf ("ok:   ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
	}                                                         \
} while (0)

int
main (int argc, char **argv)
{
	GtkWidget *window, *page;

	gtk_init (&argc, &argv);

	window = gtk_offscreen_window_new ();
	page = fs_topology_page ();
	gtk_container_add (GTK_CONTAINER (window), page);
	gtk_widget_show_all (window);

	CHECK (fs_topology_node_count () > 0, "Topology has nodes (%u nodes)", fs_topology_node_count ());
	CHECK (fs_topology_flow_count () > 0, "Topology has flows (%u flows)", fs_topology_flow_count ());

	fs_topology_set_zoom (1.5);
	CHECK (fs_topology_get_zoom () == 1.5, "Topology zoom set and retrieved (1.5)");

	fs_topology_select_node_by_index (0);
	CHECK (g_strcmp0 (fs_topology_get_selected_node_name (), "This Computer") == 0,
	       "Selected node name is 'This Computer'");

	fs_topology_sample ();

	/* Draw offscreen */
	gtk_widget_queue_draw (window);
	while (gtk_events_pending ())
		gtk_main_iteration ();

	gtk_widget_destroy (window);

	if (failures > 0) {
		printf ("FAILED: %d topology smoke test checks failed\n", failures);
		return 1;
	}

	printf ("PASSED: all topology smoke test checks passed\n");
	return 0;
}
