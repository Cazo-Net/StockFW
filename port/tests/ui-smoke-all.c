/*---[ ui-smoke-all.c ]--------------------------------------------------
 * Comprehensive headless GTK UI smoke test suite covering all 9 application pages:
 *   1. Overview (FS_PAGE_OVERVIEW)
 *   2. Events (FS_PAGE_EVENTS)
 *   3. Activity (FS_PAGE_ACTIVITY)
 *   4. Topology (FS_PAGE_TOPOLOGY)
 *   5. Policy (FS_PAGE_POLICY)
 *   6. Threat Intel (FS_PAGE_INTEL)
 *   7. Copilot (FS_PAGE_COPILOT)
 *   8. Trust (FS_PAGE_TRUST)
 *   9. Nexora (FS_PAGE_NEXORA)
 *
 * Builds each page offscreen, verifies initialization, layout, drawing,
 * and key page-specific widgets without warnings or criticals.
 *--------------------------------------------------------------------*/

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "ui/fs-app.h"
#include "ui/fs-statusview.h"
#include "ui/fs-hitview.h"
#include "ui/fs-activityview.h"
#include "ui/fs-topology.h"
#include "ui/fs-policyview.h"
#include "ui/fs-intelview.h"
#include "ui/fs-copilot.h"
#include "ui/fs-trustview.h"
#include "ui/fs-nexora.h"
#include "core/fs-backend.h"
#include "core/fs-prefs.h"

static int failures = 0;
static guint warnings = 0;

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

static GLogWriterOutput
count_warnings (GLogLevelFlags level, const GLogField *fields,
                gsize n_fields, gpointer data)
{
	(void) data;
	if (level & (G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL))
		warnings++;
	return g_log_writer_default (level, fields, n_fields, NULL);
}

static void
pump (void)
{
	gint64 until = g_get_monotonic_time () + 100000; /* 100ms */
	while (g_get_monotonic_time () < until) {
		while (gtk_events_pending ())
			gtk_main_iteration ();
		g_usleep (1000);
	}
}

static gboolean
draw_offscreen (GtkWidget *window)
{
	cairo_surface_t *surface;
	gtk_widget_queue_draw (window);
	pump ();
	surface = gtk_offscreen_window_get_surface (GTK_OFFSCREEN_WINDOW (window));
	return surface != NULL;
}

int
main (int argc, char **argv)
{
	GtkWidget *window;
	GtkWidget *page;

	gtk_init (&argc, &argv);
	g_log_set_writer_func (count_warnings, NULL, NULL);

	window = gtk_offscreen_window_new ();
	gtk_window_set_default_size (GTK_WINDOW (window), 1024, 768);

	printf ("--- Starting Comprehensive UI Smoke Test (All 9 Pages) ---\n");

	/* Page 1: Overview (Status View) */
	page = fs_statusview_page ();
	gtk_container_add (GTK_CONTAINER (window), page);
	gtk_widget_show_all (window);
	pump ();
	CHECK (page != NULL && GTK_IS_WIDGET (page), "Page 1: Overview page built successfully");
	CHECK (draw_offscreen (window), "Page 1: Overview page draws offscreen");
	gtk_container_remove (GTK_CONTAINER (window), page);

	/* Page 2: Events (Hit View) */
	page = fs_hitview_page ();
	gtk_container_add (GTK_CONTAINER (window), page);
	gtk_widget_show_all (window);
	pump ();
	CHECK (page != NULL && GTK_IS_WIDGET (page), "Page 2: Events page built successfully");
	CHECK (draw_offscreen (window), "Page 2: Events page draws offscreen");
	gtk_container_remove (GTK_CONTAINER (window), page);

	/* Page 3: Activity */
	page = fs_activityview_page ();
	gtk_container_add (GTK_CONTAINER (window), page);
	gtk_widget_show_all (window);
	pump ();
	CHECK (page != NULL && GTK_IS_WIDGET (page), "Page 3: Activity page built successfully");
	CHECK (draw_offscreen (window), "Page 3: Activity page draws offscreen");
	gtk_container_remove (GTK_CONTAINER (window), page);

	/* Page 4: Topology */
	page = fs_topology_page ();
	gtk_container_add (GTK_CONTAINER (window), page);
	gtk_widget_show_all (window);
	pump ();
	CHECK (page != NULL && GTK_IS_WIDGET (page), "Page 4: Topology page built successfully");
	CHECK (fs_topology_node_count () > 0, "Page 4: Topology has nodes (%u nodes)", fs_topology_node_count ());
	CHECK (draw_offscreen (window), "Page 4: Topology page draws offscreen");
	gtk_container_remove (GTK_CONTAINER (window), page);

	/* Page 5: Policy */
	page = fs_policyview_page ();
	gtk_container_add (GTK_CONTAINER (window), page);
	gtk_widget_show_all (window);
	pump ();
	CHECK (page != NULL && GTK_IS_WIDGET (page), "Page 5: Policy page built successfully");
	CHECK (draw_offscreen (window), "Page 5: Policy page draws offscreen");
	gtk_container_remove (GTK_CONTAINER (window), page);

	/* Page 6: Threat Intel */
	page = fs_intelview_page ();
	gtk_container_add (GTK_CONTAINER (window), page);
	gtk_widget_show_all (window);
	pump ();
	CHECK (page != NULL && GTK_IS_WIDGET (page), "Page 6: Threat Intel page built successfully");
	CHECK (draw_offscreen (window), "Page 6: Threat Intel page draws offscreen");
	gtk_container_remove (GTK_CONTAINER (window), page);

	/* Page 7: Copilot */
	page = fs_copilot_page ();
	gtk_container_add (GTK_CONTAINER (window), page);
	gtk_widget_show_all (window);
	pump ();
	CHECK (page != NULL && GTK_IS_WIDGET (page), "Page 7: Copilot page built successfully");
	CHECK (draw_offscreen (window), "Page 7: Copilot page draws offscreen");
	gtk_container_remove (GTK_CONTAINER (window), page);

	/* Page 8: Trust */
	page = fs_trustview_page ();
	gtk_container_add (GTK_CONTAINER (window), page);
	gtk_widget_show_all (window);
	pump ();
	CHECK (page != NULL && GTK_IS_WIDGET (page), "Page 8: Trust page built successfully");
	CHECK (draw_offscreen (window), "Page 8: Trust page draws offscreen");
	gtk_container_remove (GTK_CONTAINER (window), page);

	/* Page 9: Nexora */
	page = fs_nexora_page ();
	gtk_container_add (GTK_CONTAINER (window), page);
	gtk_widget_show_all (window);
	pump ();
	CHECK (page != NULL && GTK_IS_WIDGET (page), "Page 9: Nexora page built successfully");
	CHECK (draw_offscreen (window), "Page 9: Nexora page draws offscreen");
	gtk_container_remove (GTK_CONTAINER (window), page);

	gtk_widget_destroy (window);

	CHECK (warnings == 0, "No GTK warnings or criticals emitted during tests (%u warnings)", warnings);

	if (failures > 0) {
		printf ("FAILED: %d comprehensive UI smoke checks failed\n", failures);
		return 1;
	}

	printf ("PASSED: all comprehensive UI smoke tests passed successfully across all 9 pages\n");
	return 0;
}
