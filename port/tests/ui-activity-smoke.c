/* The Activity page (1.0.6): builds it the way fs-app.c does, feeds it
 * events and adapter samples, draws it, and reads the numbers back.
 *
 * What it pins down:
 *   - an event counts at its own time, so one from before the app
 *     started is dropped (the stretch the graph shades "no data")
 *     rather than piled into the current minute -- the Windows reader
 *     delivers a batch of history at start, and a seven-digit
 *     fraction in its stamps must not defeat the parse;
 *   - blocked and allowed are told apart by the shared marker;
 *   - the allowed series is drawn only where the backend logs allowed
 *     traffic, so Linux never shows a flat "nothing was allowed";
 *   - the adapter sampler turns two samples into a throughput series;
 *   - the range picker only takes the four ranges it offers;
 *   - the table view lists the same intervals the graph draws;
 *   - the page draws (graph and table) without a warning, offscreen.
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-activity.h"
#include "core/fs-backend.h"
#include "core/fs-netparse.h"
#include "core/fs-types.h"
#include "ui/fs-activityview.h"

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

/* A stamp `ago' seconds back, in the form `form' (strftime, UTC). */
static gchar *
stamp (gint64 ago, const gchar *form)
{
	GDateTime *now = g_date_time_new_now_utc ();
	GDateTime *t = g_date_time_add_seconds (now, (gdouble) -ago);
	gchar *s = g_date_time_format (t, form);

	g_date_time_unref (t);
	g_date_time_unref (now);
	return s;
}

static void
feed (const gchar *time, gboolean blocked)
{
	FsHit hit = { 0 };

	hit.time    = (gchar *) time;
	hit.service = (gchar *) (blocked ? "SSH" FS_HIT_BLOCKED_MARKER : "HTTPS");
	fs_activityview_note_hit (&hit);
}

static guint warnings = 0;

static GLogWriterOutput
count_warnings (GLogLevelFlags level, const GLogField *fields,
                gsize n_fields, gpointer data)
{
	(void) data;
	if (level & (G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL))
		warnings++;
	return g_log_writer_default (level, fields, n_fields, NULL);
}

/* [ draw_offscreen ]
 * Let the offscreen window lay out and paint (the frame clock runs on
 * the main loop), then take its surface: the page's own draw handlers
 * have run by then, exactly as on screen. */
static gboolean
draw_offscreen (GtkWidget *window)
{
	cairo_surface_t *surface;
	gint64 until = g_get_monotonic_time () + G_USEC_PER_SEC / 3;

	gtk_widget_queue_draw (window);
	while (g_get_monotonic_time () < until) {
		while (gtk_events_pending ())
			gtk_main_iteration ();
		g_usleep (10000);
	}

	surface = gtk_offscreen_window_get_surface (GTK_OFFSCREEN_WINDOW (window));
	if (surface == NULL)
		return FALSE;

	if (g_getenv ("ACTIVITY_SMOKE_PNG") != NULL)
		cairo_surface_write_to_png (surface, g_getenv ("ACTIVITY_SMOKE_PNG"));

	return TRUE;
}

int
main (int argc, char **argv)
{
	GtkWidget *window, *page;
	FsActivity *events, *net;
	gchar *now_iso, *old_iso, *win_old, *win_now;
	guint64 blocked0, allowed0;
	GList *names;
	gboolean have_rx = FALSE;

	gtk_init (&argc, &argv);
	g_log_set_writer_func (count_warnings, NULL, NULL);

	window = gtk_offscreen_window_new ();
	gtk_window_set_default_size (GTK_WINDOW (window), 1100, 760);
	page = fs_activityview_page ();
	gtk_container_add (GTK_CONTAINER (window), page);
	gtk_widget_show_all (window);

	events = fs_activityview_events ();
	net    = fs_activityview_network ();

	CHECK (fs_activityview_get_range () == 3600,
	       "the page opens on the last hour");
	CHECK (fs_activityview_shows_allowed () ==
	       (g_strcmp0 (fs_backend ()->name, "linux") != 0),
	       "the allowed series is drawn only where the backend logs "
	       "allowed traffic (backend: %s)", fs_backend ()->name);

	/* ---- events at their own time ---- */
	now_iso = stamp (0, "%Y-%m-%dT%H:%M:%SZ");
	old_iso = stamp (2 * 86400, "%Y-%m-%dT%H:%M:%SZ");
	win_now = stamp (0, "%Y-%m-%dT%H:%M:%S.1234567Z");
	win_old = stamp (2 * 86400, "%Y-%m-%dT%H:%M:%S.1234567Z");

	blocked0 = fs_activity_total (events, FS_ACTIVITY_BLOCKED, 3600);
	allowed0 = fs_activity_total (events, FS_ACTIVITY_ALLOWED, 3600);

	feed (now_iso, TRUE);
	feed (now_iso, TRUE);
	feed (now_iso, FALSE);
	feed (win_now, TRUE);
	CHECK (fs_activity_total (events, FS_ACTIVITY_BLOCKED, 3600) == blocked0 + 3 &&
	       fs_activity_total (events, FS_ACTIVITY_ALLOWED, 3600) == allowed0 + 1,
	       "blocked and allowed are counted apart by the marker (+3 / +1)");

	feed (old_iso, TRUE);
	feed (win_old, TRUE);
	CHECK (fs_activity_total (events, FS_ACTIVITY_BLOCKED, FS_ACTIVITY_SPAN_S)
	       == blocked0 + 3,
	       "events from before the app started are dropped, not piled "
	       "into now -- including a seven-digit Windows stamp");

	feed (NULL, TRUE);
	CHECK (fs_activity_total (events, FS_ACTIVITY_BLOCKED, 3600) == blocked0 + 4,
	       "an event with no readable time counts now");

	/* ---- adapters ---- */
	fs_activityview_sample ();
	g_usleep (G_USEC_PER_SEC / 5);
	fs_activityview_sample ();
	names = fs_activity_series_names (net);
	for (GList *l = names; l != NULL; l = l->next)
		if (g_strcmp0 (l->data, FS_ACTIVITY_NET_RX) == 0)
			have_rx = TRUE;
	g_list_free (names);
	if (fs_backend ()->list_interface_stats != NULL) {
		GList *stats = fs_backend ()->list_interface_stats ();

		CHECK (stats == NULL || have_rx,
		       "two adapter samples make a throughput series");
		g_list_free_full (stats, (GDestroyNotify) fs_iface_stat_free);
	}

	/* ---- range picker ---- */
	fs_activityview_set_range (86400);
	CHECK (fs_activityview_get_range () == 86400, "24 hours can be picked");
	fs_activityview_set_range (1234);
	CHECK (fs_activityview_get_range () == 86400,
	       "a range the picker does not offer is ignored");
	fs_activityview_set_range (900);

	/* ---- drawing, graph then table ---- */
	CHECK (draw_offscreen (window), "the page draws as a graph");

	fs_activityview_set_table (TRUE);
	CHECK (fs_activityview_table_rows () >= 1,
	       "the table lists the intervals with data (%u rows)",
	       fs_activityview_table_rows ());
	CHECK (draw_offscreen (window), "the page draws as a table");
	fs_activityview_set_table (FALSE);
	draw_offscreen (window);

	CHECK (warnings == 0, "no GTK warning or critical while building, "
	       "feeding and drawing (%u)", warnings);

	g_free (now_iso);
	g_free (old_iso);
	g_free (win_now);
	g_free (win_old);
	gtk_widget_destroy (window);

	printf ("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
