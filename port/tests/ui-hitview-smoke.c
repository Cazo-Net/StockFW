/* Checks the Events page tells the user when it cannot monitor,
 * rather than presenting an empty list as a quiet firewall.
 *
 * The page builds its own reason strip and asks the backend to start
 * monitoring.  Two states are acceptable, and only two:
 *
 *   - monitoring really runs and no strip is shown;
 *   - monitoring cannot run and the strip names the privilege needed.
 *
 * Anything else -- in particular a hidden strip while nothing runs --
 * is the bug, because it leaves an empty list with no stated cause.
 *
 * gtk_widget_show_all() is called on the page here for the same reason
 * fs-app.c does it when the page is added, so the check sees the page
 * in the state the user actually gets.
 */

#include <gtk/gtk.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-backend.h"
#include "core/fs-types.h"
#include "ui/fs-hitview.h"
#include "ui/fs-eventmodel.h"
#include "core/fs-eventstore.h"
#include "core/fs-eventlog.h"
#include "core/fs-prefs.h"

#ifndef G_OS_WIN32
#include <signal.h>
#include <sys/resource.h>
#endif

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

/* The label on the strip: the only text on the page that names the
 * privilege monitoring needs. */
static gboolean
find_reason_label (GtkWidget *widget, GtkWidget **out)
{
	if (GTK_IS_LABEL (widget)) {
		const gchar *text = gtk_label_get_text (GTK_LABEL (widget));

		if (text != NULL && *text != '\0' &&
		    (strstr (text, "Administrator") != NULL ||
		     strstr (text, "root") != NULL)) {
			*out = widget;
			return TRUE;
		}
	}

	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));
		GList *l;

		for (l = children; l != NULL; l = l->next) {
			if (find_reason_label (GTK_WIDGET (l->data), out)) {
				g_list_free (children);
				return TRUE;
			}
		}
		g_list_free (children);
	}

	return FALSE;
}

/* The strip itself, found by its warning icon rather than by position
 * in the box, so reordering the page cannot silently break the test. */
static gboolean
find_strip (GtkWidget *widget, GtkWidget **out)
{
	if (GTK_IS_IMAGE (widget)) {
		const gchar *name = NULL;

		gtk_image_get_icon_name (GTK_IMAGE (widget), &name, NULL);
		if (name != NULL && g_strcmp0 (name, "dialog-warning") == 0) {
			*out = gtk_widget_get_parent (widget);
			return TRUE;
		}
	}

	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));
		GList *l;

		for (l = children; l != NULL; l = l->next) {
			if (find_strip (GTK_WIDGET (l->data), out)) {
				g_list_free (children);
				return TRUE;
			}
		}
		g_list_free (children);
	}

	return FALSE;
}

/* Visible means visible here and all the way up to the page: a
 * widget whose parent is hidden renders nothing however set its own
 * flag is. */
static gboolean
shown_up_to (GtkWidget *widget, GtkWidget *top)
{
	GtkWidget *w;

	for (w = widget; w != NULL; w = gtk_widget_get_parent (w)) {
		if (!gtk_widget_get_visible (w))
			return FALSE;
		if (w == top)
			return TRUE;
	}

	return TRUE;
}

/* The filter bar: a GtkSearchEntry somewhere in the page. */
static gboolean
find_search_entry (GtkWidget *widget, GtkWidget **out)
{
	if (GTK_IS_SEARCH_ENTRY (widget)) {
		*out = widget;
		return TRUE;
	}

	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));
		GList *l;

		for (l = children; l != NULL; l = l->next) {
			if (find_search_entry (GTK_WIDGET (l->data), out)) {
				g_list_free (children);
				return TRUE;
			}
		}
		g_list_free (children);
	}

	return FALSE;
}

/* The count label: the only label on the page that ends in "events". */
static gboolean
find_count_label (GtkWidget *widget, GtkWidget **out)
{
	if (GTK_IS_LABEL (widget)) {
		const gchar *text = gtk_label_get_text (GTK_LABEL (widget));

		if (text != NULL && strstr (text, "events") != NULL) {
			*out = widget;
			return TRUE;
		}
	}

	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));
		GList *l;

		for (l = children; l != NULL; l = l->next) {
			if (find_count_label (GTK_WIDGET (l->data), out)) {
				g_list_free (children);
				return TRUE;
			}
		}
		g_list_free (children);
	}

	return FALSE;
}

/* The event list itself: the order of its rows is the order the user
 * reads. */
static gboolean
find_tree_view (GtkWidget *widget, GtkWidget **out)
{
	if (GTK_IS_TREE_VIEW (widget)) {
		*out = widget;
		return TRUE;
	}

	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));
		GList *l;

		for (l = children; l != NULL; l = l->next) {
			if (find_tree_view (GTK_WIDGET (l->data), out)) {
				g_list_free (children);
				return TRUE;
			}
		}
		g_list_free (children);
	}

	return FALSE;
}

/* The Time cell of visible row n, as the store holds it (column 0
 * is COL_TIME).  Caller frees. */
static gchar *
row_time_at (GtkWidget *tree, guint n)
{
	GtkTreeModel *model = gtk_tree_view_get_model (GTK_TREE_VIEW (tree));
	GtkTreeIter iter;
	gchar *path = g_strdup_printf ("%u", n);
	gchar *time = NULL;

	if (model != NULL &&
	    gtk_tree_model_get_iter_from_string (model, &iter, path))
		gtk_tree_model_get (model, &iter, 0, &time, -1);

	g_free (path);
	return time;
}

/* [ check_filter_bar ]
 * 1.0.4: type a needle, only matching rows remain, the count label
 * says both numbers, clearing brings everything back. */
static void
check_filter_bar (GtkWidget *page)
{
	GtkWidget *entry = NULL;
	GtkWidget *label = NULL;
	FsHit hit;
	guint i;

	static const struct {
		const gchar *dest;
		const gchar *port;
		const gchar *protocol;
		const gchar *service;
		const gchar *direction;
		const gchar *source;
	} rows[] = {
		{ "203.0.113.9",  "443", "TCP", "HTTPS", "Out", "192.168.1.5" },
		{ "198.51.100.7", "53",  "UDP", "DNS",   "Out", "192.168.1.5" },
		{ "192.168.1.99", "22",  "TCP", "SSH",   "In",  "10.0.0.8"    },
	};

	for (i = 0; i < G_N_ELEMENTS (rows); i++) {
		memset (&hit, 0, sizeof hit);
		hit.time        = "12:00:00";
		hit.direction   = (gchar *) rows[i].direction;
		hit.source      = (gchar *) rows[i].source;
		hit.destination = (gchar *) rows[i].dest;
		hit.port        = (gchar *) rows[i].port;
		hit.protocol    = (gchar *) rows[i].protocol;
		hit.service     = (gchar *) rows[i].service;

		CHECK (fs_hitview_append (&hit), "row %u is appended", i);
	}

	CHECK (fs_hitview_count () == G_N_ELEMENTS (rows),
	       "all three rows are listed");
	CHECK (fs_hitview_visible_count () == G_N_ELEMENTS (rows),
	       "with no filter, every row is visible");

	CHECK (find_search_entry (page, &entry),
	       "the page carries a search entry for filtering");
	if (entry == NULL)
		return;

	/* A needle that matches nothing: list intact, visibility zero. */
	gtk_entry_set_text (GTK_ENTRY (entry), "999nope");
	g_signal_emit_by_name (entry, "search-changed");
	CHECK (fs_hitview_count () == G_N_ELEMENTS (rows),
	       "filtering does not delete rows");
	CHECK (fs_hitview_visible_count () == 0,
	       "a non-matching needle hides every row");

	find_count_label (page, &label);
	if (label != NULL) {
		const gchar *text = gtk_label_get_text (GTK_LABEL (label));

		CHECK (strstr (text, "0 of 3 events") != NULL,
		       "the count label reports both numbers (got \"%s\")",
		       text ? text : "(null)");
	}

	/* A needle that matches one row. */
	gtk_entry_set_text (GTK_ENTRY (entry), "DNS");
	g_signal_emit_by_name (entry, "search-changed");
	CHECK (fs_hitview_visible_count () == 1,
	       "a matching needle keeps exactly the matching row");

	/* Case-insensitive, on a different field. */
	gtk_entry_set_text (GTK_ENTRY (entry), "ssh");
	g_signal_emit_by_name (entry, "search-changed");
	CHECK (fs_hitview_visible_count () == 1,
	       "the needle matches case-insensitively");

	/* Clearing restores everything. */
	gtk_entry_set_text (GTK_ENTRY (entry), "");
	g_signal_emit_by_name (entry, "search-changed");
	CHECK (fs_hitview_visible_count () == G_N_ELEMENTS (rows),
	       "clearing the needle restores every row");
}

/* [ check_list_behaviour ]
 * The three ways the list went wrong in live use, each pinned here:
 *
 *   1. order -- two batches as the backend delivers them (newest of
 *      each first) used to be stacked at the bottom, so the list
 *      read as shuffled after every poll; the documented order is
 *      prepend.  An out-of-order old event must land at the bottom:
 *      the order is by time, not by arrival, in either direction.
 *   2. de-duplication -- a Monitor restart re-delivers the trailing
 *      window into a list that still holds those rows; the same row
 *      must not be appended twice, and a Clear must reset that so
 *      Reload can re-read the tail.
 *   3. row budget -- with newest first, the oldest row is the LAST
 *      one; the cap must drop it, not the newest rows.
 *
 * Plus the Time column: a clock, not the raw wevtutil stamp. */
static void
check_list_behaviour (GtkWidget *page)
{
	GtkWidget *tree = NULL;
	FsHit hit;
	guint i;
	gchar *text;

	static const struct {
		const gchar *time;
		const gchar *dest;
	} batch1[] = {
		{ "2026-10-09T12:00:02Z", "198.51.100.1" },
		{ "2026-10-09T12:00:01Z", "198.51.100.2" },
		{ "2026-10-09T12:00:00Z", "198.51.100.3" },
	};
	static const struct {
		const gchar *time;
		const gchar *dest;
	} batch2[] = {                       /* a later poll, all newer */
		{ "2026-10-09T12:00:05Z", "198.51.100.4" },
		{ "2026-10-09T12:00:04Z", "198.51.100.5" },
		{ "2026-10-09T12:00:03Z", "198.51.100.6" },
	};

	CHECK (find_tree_view (page, &tree), "the page carries an event list");
	if (tree == NULL)
		return;

	for (i = 0; i < G_N_ELEMENTS (batch1); i++) {
		memset (&hit, 0, sizeof hit);
		hit.time        = (gchar *) batch1[i].time;
		hit.destination = (gchar *) batch1[i].dest;
		CHECK (fs_hitview_append (&hit), "batch 1 row %u is listed", i);
	}
	for (i = 0; i < G_N_ELEMENTS (batch2); i++) {
		memset (&hit, 0, sizeof hit);
		hit.time        = (gchar *) batch2[i].time;
		hit.destination = (gchar *) batch2[i].dest;
		CHECK (fs_hitview_append (&hit), "batch 2 row %u is listed", i);
	}

	CHECK (fs_hitview_count () == 6, "both batches are listed (6 rows)");

	text = row_time_at (tree, 0);
	CHECK (text != NULL && g_strcmp0 (text, "2026-10-09T12:00:05Z") == 0,
	       "the later batch is at the TOP, not stacked below (got \"%s\")",
	       text ? text : "(null)");
	g_free (text);

	text = row_time_at (tree, 3);
	CHECK (text != NULL && g_strcmp0 (text, "2026-10-09T12:00:02Z") == 0,
	       "batch 1 sits below batch 2 in time order (got \"%s\")",
	       text ? text : "(null)");
	g_free (text);

	/* An event older than everything: by time it goes to the bottom,
	 * wherever it arrived from. */
	memset (&hit, 0, sizeof hit);
	hit.time        = (gchar *) "2026-10-09T11:59:59Z";
	hit.destination = (gchar *) "198.51.100.7";
	CHECK (fs_hitview_append (&hit), "an out-of-order old row is listed");

	text = row_time_at (tree, 6);
	CHECK (text != NULL && g_strcmp0 (text, "2026-10-09T11:59:59Z") == 0,
	       "the old row goes LAST, not first (got \"%s\")",
	       text ? text : "(null)");
	g_free (text);

	/* The redelivered row: one event, not two. */
	memset (&hit, 0, sizeof hit);
	hit.time        = (gchar *) "2026-10-09T12:00:05Z";
	hit.destination = (gchar *) "198.51.100.4";
	CHECK (!fs_hitview_append (&hit),
	       "the same row is not appended a second time");
	CHECK (fs_hitview_count () == 7, "the refused duplicate changed no count");

	/* Clear drops rows AND keys: what was cleared can be listed
	 * again (this is what makes Reload re-read the tail). */
	fs_hitview_clear ();
	CHECK (fs_hitview_count () == 0, "clear empties the list");
	CHECK (fs_hitview_append (&hit), "after a clear the row lists again");

	/* Row budget: FS_HITVIEW_MAX_ROWS + 1 rows, one per second from
	 * 2026-10-09 12:00:00, each newer than the last.  Exactly the
	 * FIRST (oldest) row must be gone; the newest stays on top. */
	fs_hitview_clear ();
	{
		gint64 t0 = 0;
		gchar newest[FS_EVENT_TIME_BUF], second[FS_EVENT_TIME_BUF];

		fs_event_time_parse ("2026-10-09T12:00:00Z", &t0);
		for (i = 0; i < FS_HITVIEW_MAX_ROWS + 1; i++) {
			gchar stamp[FS_EVENT_TIME_BUF];

			fs_event_time_format (t0 + (gint64) i * 10000000,
			                      FS_EVENT_TIME_SECS, stamp);
			memset (&hit, 0, sizeof hit);
			hit.time = stamp;
			hit.destination = (gchar *) "198.51.100.9";
			fs_hitview_append (&hit);
		}
		fs_event_time_format (t0 + (gint64) FS_HITVIEW_MAX_ROWS * 10000000,
		                      FS_EVENT_TIME_SECS, newest);
		fs_event_time_format (t0 + 10000000, FS_EVENT_TIME_SECS, second);

		CHECK (fs_hitview_count () == FS_HITVIEW_MAX_ROWS,
		       "the cap holds (%u rows)", fs_hitview_count ());

		text = row_time_at (tree, 0);
		CHECK (text != NULL && g_strcmp0 (text, newest) == 0,
		       "the NEWEST row is kept on top (got \"%s\")",
		       text ? text : "(null)");
		g_free (text);

		text = row_time_at (tree, FS_HITVIEW_MAX_ROWS - 1);
		CHECK (text != NULL && g_strcmp0 (text, second) == 0,
		       "the OLDEST row is the one dropped (got \"%s\")",
		       text ? text : "(null)");
		g_free (text);
	}

	fs_hitview_clear ();
	CHECK (fs_hitview_count () == 0,
	       "the list is empty again for the filter checks");

	/* The Time column: a clock, not the raw wevtutil stamp.  Neither
	 * check may depend on the day the suite runs: the hardcoded
	 * stamp is permanently another day (%m-%d %H:%M:%S = 14 chars),
	 * and the dynamic one is today's instant round-tripped through
	 * UTC, which must come back as clock only (8 chars) in any
	 * timezone. */
	text = fs_hitview_format_time ("2026-10-09T12:35:34.0780000Z");
	CHECK (text != NULL &&
	       (strlen (text) == 8 || strlen (text) == 14) &&
	       strchr (text, ':') != NULL,
	       "a wevtutil stamp becomes clock text (got \"%s\")",
	       text ? text : "(null)");
	g_free (text);

	{
		GDateTime *now_utc = g_date_time_new_now_utc ();
		gchar *stamp = now_utc != NULL
		               ? g_date_time_format (now_utc,
		                                     "%Y-%m-%dT%H:%M:%S.0000000Z")
		               : NULL;

		if (stamp != NULL) {
			text = fs_hitview_format_time (stamp);
			CHECK (text != NULL && strlen (text) == 8 &&
			       strchr (text, ':') != NULL,
			       "an event from today shows the clock only "
			       "(got \"%s\")", text ? text : "(null)");
			g_free (text);
		} else {
			CHECK (FALSE, "today's stamp could be built");
		}
		g_free (stamp);
		if (now_utc != NULL)
			g_date_time_unref (now_utc);
	}

	text = fs_hitview_format_time ("12:00:00");
	CHECK (text != NULL && g_strcmp0 (text, "12:00:00") == 0,
	       "input that is not a wevtutil stamp passes through unchanged");
	g_free (text);

	text = fs_hitview_format_time (NULL);
	CHECK (text != NULL && *text == '\0',
	       "a NULL stamp reads as empty, not a crash");
	g_free (text);
}


/* ---- at scale (1.0.7) ---------------------------------------------- */

static GtkWidget *
find_named (GtkWidget *widget, const gchar *name)
{
	if (g_strcmp0 (gtk_widget_get_name (widget), name) == 0)
		return widget;

	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));
		GtkWidget *found = NULL;

		for (GList *l = children; l != NULL && found == NULL; l = l->next)
			found = find_named (GTK_WIDGET (l->data), name);
		g_list_free (children);
		return found;
	}

	return NULL;
}

static GArray *frame_costs = NULL;
static gint64  frame_started = 0;

static void
on_frame_start (GdkFrameClock *clock, gpointer data)
{
	frame_started = g_get_monotonic_time ();
}

static void
on_frame_end (GdkFrameClock *clock, gpointer data)
{
	if (frame_costs != NULL && frame_started != 0) {
		gdouble ms = (g_get_monotonic_time () - frame_started) / 1000.0;

		g_array_append_val (frame_costs, ms);
	}
	frame_started = 0;
}

static gint
cmp_double (gconstpointer a, gconstpointer b)
{
	gdouble x = *(const gdouble *) a, y = *(const gdouble *) b;

	return x < y ? -1 : x > y ? 1 : 0;
}

typedef struct
{
	guint   frames;
	guint   missed;
	gdouble median;
	gdouble p95;
	gdouble worst;
} FrameStats;

/* [ measure_scroll ]
 * Scrolls the list `steps' times -- page by page through the top, then
 * jumps across the whole list as a scrollbar drag does -- and times
 * each frame from the frame clock's before-paint to its after-paint
 * (update, layout and paint). */
static void
measure_scroll (GtkWidget *tree, guint steps, FrameStats *st)
{
	GtkWidget *scroll = gtk_widget_get_parent (tree);
	GtkAdjustment *adj = gtk_scrolled_window_get_vadjustment (
		GTK_SCROLLED_WINDOW (scroll));
	GdkFrameClock *clock = gtk_widget_get_frame_clock (tree);
	gdouble upper = gtk_adjustment_get_upper (adj) -
	                gtk_adjustment_get_page_size (adj);
	gulong h1, h2;

	memset (st, 0, sizeof *st);
	frame_costs = g_array_new (FALSE, FALSE, sizeof (gdouble));
	h1 = g_signal_connect (clock, "before-paint",
	                       G_CALLBACK (on_frame_start), NULL);
	h2 = g_signal_connect (clock, "after-paint",
	                       G_CALLBACK (on_frame_end), NULL);

	for (guint i = 0; i < steps; i++) {
		gdouble v = i < steps / 2
		            ? i * gtk_adjustment_get_page_size (adj)
		            : upper * ((i * 7919) % steps) / steps;
		guint have = frame_costs->len;
		gint64 deadline = g_get_monotonic_time () + G_USEC_PER_SEC;

		/* Wrapped back to the top when the list is short. */
		if (v > upper)
			v = upper > 0 ? v - upper * (gint64) (v / upper) : 0;
		/* The same value again would paint nothing. */
		if (v == gtk_adjustment_get_value (adj))
			v = v > 0 ? 0 : MIN (upper, 1.0);

		gtk_adjustment_set_value (adj, v);
		while (frame_costs->len == have &&
		       g_get_monotonic_time () < deadline)
			gtk_main_iteration_do (FALSE);
		if (frame_costs->len == have)
			st->missed++;
	}
	g_signal_handler_disconnect (clock, h1);
	g_signal_handler_disconnect (clock, h2);

	st->frames = frame_costs->len;
	if (frame_costs->len > 0) {
		gdouble *c;

		g_array_sort (frame_costs, cmp_double);
		c = (gdouble *) frame_costs->data;
		st->median = c[st->frames / 2];
		st->p95 = c[(st->frames * 95) / 100];
		st->worst = c[st->frames - 1];
	}
	g_array_unref (frame_costs);
	frame_costs = NULL;
	gtk_adjustment_set_value (adj, 0);
}

static void
pump (void)
{
	while (gtk_events_pending ())
		gtk_main_iteration_do (FALSE);
}

/* A realistic spread: 5,000 hosts, a few dozen ports, a fifth blocked,
 * a third inbound.  Times one every 10 ms from 2026-11-02 08:00 UTC. */
static void
make_event (guint n, FsHit *hit, gchar *time, gchar *src, gchar *dst,
            gchar *port)
{
	static const gchar *const ports[] = { "443", "80", "53", "22", "123",
	                                      "3389", "445", "8080", "993" };
	gint64 t0 = 0;

	fs_event_time_parse ("2026-11-02T08:00:00.0000000Z", &t0);
	fs_event_time_format (t0 + (gint64) n * 100000, FS_EVENT_TIME_FRAC7, time);
	g_snprintf (src, 48, "192.168.%u.%u", (n / 250) % 20, n % 250);
	g_snprintf (dst, 48, "203.0.%u.%u", (n * 7) % 113, (n * 13) % 251);
	g_strlcpy (port, ports[n % G_N_ELEMENTS (ports)], 8);

	memset (hit, 0, sizeof *hit);
	hit->time        = time;
	hit->direction   = (n % 3 == 0) ? (gchar *) "In" : (gchar *) "Out";
	hit->in          = (n % 3 == 0) ? (gchar *) "eth0" : (gchar *) "";
	hit->out         = (n % 3 == 0) ? (gchar *) "" : (gchar *) "eth0";
	hit->port        = port;
	hit->source      = src;
	hit->destination = dst;
	hit->length      = (gchar *) "60";
	hit->tos         = (gchar *) "0x00";
	hit->protocol    = (n % 4 == 0) ? (gchar *) "UDP" : (gchar *) "TCP";
	hit->service     = (n % 5 == 0) ? (gchar *) "SMB [BLOCKED]"
	                                : (gchar *) "HTTPS";
}

/* What the core says the filter should keep, counted over the store. */
static guint
expected (const FsEventFilter *f)
{
	FsEventQuery *q = fs_eventquery_new (f, NULL);
	GArray *seqs = g_array_new (FALSE, FALSE, sizeof (guint64));
	guint n = fs_eventstore_select (fs_hitview_store (), q, seqs);

	g_array_unref (seqs);
	fs_eventquery_free (q);
	return n;
}

static gint
cmp_num (const gchar *a, const gchar *b)
{
	guint64 x = g_ascii_strtoull (a, NULL, 10);
	guint64 y = g_ascii_strtoull (b, NULL, 10);

	return x < y ? -1 : x > y ? 1 : 0;
}

static gchar *
cell (GtkWidget *tree, guint row, gint col)
{
	GtkTreeModel *model = gtk_tree_view_get_model (GTK_TREE_VIEW (tree));
	GtkTreeIter iter;
	gchar *v = NULL;

	if (model != NULL &&
	    gtk_tree_model_iter_nth_child (model, &iter, NULL, (gint) row))
		gtk_tree_model_get (model, &iter, col, &v, -1);
	return v;
}

static void
set_text (GtkWidget *page, const gchar *name, const gchar *text)
{
	GtkWidget *w = find_named (page, name);

	if (w != NULL)
		gtk_entry_set_text (GTK_ENTRY (w), text);
}

static void
shot (GtkWidget *window, const gchar *name)
{
	const gchar *dir = g_getenv ("STOCKFW_EVENTS_SHOTS");
	GdkWindow *gw;
	GdkPixbuf *pix;
	gchar *file;

	if (dir == NULL || *dir == '\0')
		return;

	pump ();
	gw = gtk_widget_get_window (window);
	pix = gdk_pixbuf_get_from_window (gw, 0, 0, gdk_window_get_width (gw),
	                                  gdk_window_get_height (gw));
	file = g_strdup_printf ("%s/%s.png", dir, name);
	if (pix != NULL) {
		gdk_pixbuf_save (pix, file, "png", NULL, NULL);
		g_object_unref (pix);
		printf ("shot: %s\n", file);
	}
	g_free (file);
}

/* [ check_scale ]
 * 100,000 events in a real window: the list holds them without copying
 * them into a GtkListStore, scrolls in milliseconds per frame, filters
 * and sorts all of them, keeps its counts straight while the ring
 * turns over, and exports what it shows. */
static void
check_scale (GtkWidget *page)
{
	GtkWidget *window, *tree = NULL;
	GtkTreeModel *model;
	FrameStats small;
	FsEventFilter f;
	gchar time[FS_EVENT_TIME_BUF], src[48], dst[48], port[8];
	FsHit hit;
	gint64 t;
	guint64 reads0;
	guint n = FS_HITVIEW_MAX_ROWS;
	gdouble append_ms;

	fs_hitview_clear ();

	/* Keep the page alive across the moves in and out of the window. */
	g_object_ref_sink (page);

	window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size (GTK_WINDOW (window), 1240, 760);
	g_object_ref (page);
	if (gtk_widget_get_parent (page) != NULL)
		gtk_container_remove (GTK_CONTAINER (gtk_widget_get_parent (page)),
		                      page);
	gtk_container_add (GTK_CONTAINER (window), page);
	gtk_widget_show_all (window);
	pump ();

	find_tree_view (page, &tree);
	if (tree == NULL) {
		CHECK (FALSE, "the list is there");
		return;
	}

	/* The baseline: the same window with 1,000 rows. */
	for (guint i = 0; i < 1000; i++) {
		make_event (i, &hit, time, src, dst, port);
		fs_hitview_append (&hit);
	}
	pump ();
	measure_scroll (tree, 300, &small);
	fs_hitview_clear ();
	pump ();

	/* Appending into the live, mapped view. */
	model = gtk_tree_view_get_model (GTK_TREE_VIEW (tree));
	reads0 = fs_event_model_value_reads (FS_EVENT_MODEL (model));
	t = g_get_monotonic_time ();
	for (guint i = 0; i < n; i++) {
		make_event (i, &hit, time, src, dst, port);
		fs_hitview_append (&hit);
	}
	append_ms = (g_get_monotonic_time () - t) / 1000.0;
	pump ();
	printf ("measure: appending %u events into the shown list: %.0f ms "
	        "(%.1f us each, history writing included)\n", n, append_ms,
	        append_ms * 1000.0 / n);

	{
		guint64 reads = fs_event_model_value_reads (FS_EVENT_MODEL (model))
		                - reads0;

		printf ("measure: cell values read while %u events were appended "
		        "and shown: %" G_GUINT64_FORMAT "\n", n, reads);
		CHECK (reads < (guint64) n,
		       "appending reads no cell per event: %" G_GUINT64_FORMAT
		       " reads for %u appends (a GtkListStore copy writes 12 "
		       "per event)", reads, n);
	}
	CHECK (fs_hitview_count () == n && fs_hitview_visible_count () == n,
	       "%u events listed, all visible", n);
	CHECK (model != NULL && FS_IS_EVENT_MODEL (model) &&
	       !GTK_IS_LIST_STORE (model) && !GTK_IS_TREE_MODEL_FILTER (model),
	       "the view reads the store through FsEventModel, not a copy in "
	       "a GtkListStore");
	CHECK (gtk_tree_model_iter_n_children (model, NULL) == (gint) n,
	       "the model reports every row (%d)",
	       gtk_tree_model_iter_n_children (model, NULL));
	CHECK (gtk_tree_view_get_fixed_height_mode (GTK_TREE_VIEW (tree)),
	       "fixed-height mode: rows off screen are never measured");

	/* Scrolling: frame cost at 100,000 rows against the same window
	 * holding 1,000.  The view must not get slower with the row count;
	 * what a frame costs at all is Xvfb's software rendering of ~30
	 * rows of text. */
	reads0 = fs_event_model_value_reads (FS_EVENT_MODEL (model));
	{
		FrameStats big;

		measure_scroll (tree, 300, &big);
		printf ("measure: scrolling %u rows: %u frames, layout+paint "
		        "median %.2f ms, p95 %.2f ms, worst %.2f ms (1,000 rows: "
		        "median %.2f ms, p95 %.2f ms)\n", n, big.frames,
		        big.median, big.p95, big.worst, small.median, small.p95);
		CHECK (big.missed == 0 && big.frames == 300,
		       "every scroll step was painted (%u missed)", big.missed);
		CHECK (big.median <= small.median * 1.5 + 2.0 &&
		       big.p95 <= small.p95 * 1.5 + 4.0,
		       "a frame at %u rows costs what it costs at 1,000 (median "
		       "%.1f vs %.1f ms)", n, big.median, small.median);
	}
	{
		guint64 reads = fs_event_model_value_reads (FS_EVENT_MODEL (model))
		                - reads0;

		printf ("measure: cell values read while scrolling: %"
		        G_GUINT64_FORMAT " (%u rows x 12 columns would be %u)\n",
		        reads, n, n * 12);
		/* A screen holds about 30 rows of 11 columns; each cell
		 * reads its text and the blocked flag. */
		CHECK (reads > 0 && reads / 300 < 2400,
		       "only rows on screen are read: %" G_GUINT64_FORMAT
		       " per frame, whatever the %u rows", reads / 300, n);
	}
	pump ();
	shot (window, "events-100k");

	/* Filters, each against the core's own count. */
	{
		struct {
			const gchar *what;
			const gchar *box;
			const gchar *text;
			FsEventFilter f;
		} cases[] = {
			{ "port 22", "events-filter-port", "22",
			  { NULL, 0, NULL, "22", NULL, 0, 0, 0 } },
			{ "CIDR 192.168.3.0/24", "events-filter-address",
			  "192.168.3.0/24",
			  { NULL, 0, NULL, NULL, "192.168.3.0/24", 0, 0, 0 } },
			{ "protocol udp", "events-filter-protocol", "udp",
			  { NULL, 0, "udp", NULL, NULL, 0, 0, 0 } },
		};

		for (guint i = 0; i < G_N_ELEMENTS (cases); i++) {
			guint want = expected (&cases[i].f);
			gdouble ms;

			set_text (page, cases[i].box, cases[i].text);
			t = g_get_monotonic_time ();
			fs_hitview_refilter_now ();
			ms = (g_get_monotonic_time () - t) / 1000.0;
			pump ();
			printf ("measure: filter %u events by %s: %.1f ms "
			        "(rebuild and re-attach included), %u shown\n",
			        n, cases[i].what, ms, fs_hitview_visible_count ());
			CHECK (fs_hitview_visible_count () == want && want > 0 &&
			       want < n, "%s keeps the %u it should", cases[i].what,
			       want);
			set_text (page, cases[i].box, "");
		}
	}

	/* Everything at once: search, direction, action, port range,
	 * block and a time window. */
	{
		GtkWidget *dir = find_named (page, "events-filter-direction");
		GtkWidget *act = find_named (page, "events-filter-action");
		GtkWidget *label = NULL;
		guint want;

		memset (&f, 0, sizeof f);
		f.text = "eth0";
		f.direction = FS_EVQ_DIR_IN;
		f.action = FS_EVQ_ACTION_BLOCKED;
		f.port = "20-500";
		f.address = "192.168.0.0/20";
		fs_event_parse_time_spec ("2026-11-02 00:00", g_get_real_time (),
		                          FALSE, &f.since_us, NULL);
		want = expected (&f);

		gtk_entry_set_text (GTK_ENTRY (find_named (page,
			"events-filter-text")), "eth0");
		gtk_combo_box_set_active (GTK_COMBO_BOX (dir), 1);
		gtk_combo_box_set_active (GTK_COMBO_BOX (act), 1);
		set_text (page, "events-filter-port", "20-500");
		set_text (page, "events-filter-address", "192.168.0.0/20");
		set_text (page, "events-filter-since", "2026-11-02 00:00");
		CHECK (fs_hitview_refilter_now (), "the combined filter applies");
		pump ();
		CHECK (fs_hitview_visible_count () == want,
		       "search, direction, action, port range, block and time "
		       "together keep %u (shown %u)", want,
		       fs_hitview_visible_count ());

		find_count_label (page, &label);
		{
			gchar *expect = want >= 1000
				? g_strdup_printf ("%u,%03u of 100,000 events",
				                   want / 1000, want % 1000)
				: g_strdup_printf ("%u of 100,000 events", want);

			CHECK (label != NULL && strcmp (gtk_label_get_text (
			       GTK_LABEL (label)), expect) == 0,
			       "the count says \"%s\" (got \"%s\")", expect,
			       label ? gtk_label_get_text (GTK_LABEL (label)) : "?");
			g_free (expect);
		}

		/* Every row shown really is inbound, blocked, in the range. */
		{
			gboolean all = TRUE;

			for (guint r = 0; r < fs_hitview_visible_count () && all; r++) {
				gchar *d = cell (tree, r, 1), *p = cell (tree, r, 4);
				gchar *sv = cell (tree, r, 10);

				all = g_strcmp0 (d, "In") == 0 &&
				      cmp_num (p, "20") >= 0 && cmp_num (p, "500") <= 0 &&
				      strstr (sv, "[BLOCKED]") != NULL;
				g_free (d);
				g_free (p);
				g_free (sv);
			}
			CHECK (all, "every row shown matches every part of it");
		}
		shot (window, "events-filtered");

		/* A live event: in when it matches, out when it does not. */
		{
			guint before = fs_hitview_visible_count ();
			guint total = fs_hitview_count ();

			make_event (n + 15, &hit, time, src, dst, port);
			hit.direction = (gchar *) "In";
			hit.in = (gchar *) "eth0";
			hit.port = (gchar *) "22";
			hit.source = (gchar *) "192.168.1.1";
			hit.service = (gchar *) "SSH [BLOCKED]";
			fs_hitview_append (&hit);
			(void) before;
			CHECK (fs_hitview_visible_count () == expected (&f),
			       "a matching live event joins the filtered list "
			       "(%u shown, as the store counts)",
			       fs_hitview_visible_count ());
			{
				gchar *top = cell (tree, 0, 0);

				CHECK (g_strcmp0 (top, time) == 0,
				       "on top, newest first (got %s)", top);
				g_free (top);
			}
			make_event (n + 16, &hit, time, src, dst, port);
			hit.direction = (gchar *) "Out";
			fs_hitview_append (&hit);
			CHECK (fs_hitview_count () == total,
			       "at the cap the ring turned over: still %u", total);
			CHECK (fs_hitview_visible_count () == expected (&f),
			       "a live event that does not match stays out, and "
			       "the count agrees with the store (%u)",
			       fs_hitview_visible_count ());
		}

		/* A box that does not parse: refused, said, old filter kept. */
		{
			GtkWidget *err = find_named (page, "events-filter-error");
			guint before = fs_hitview_visible_count ();

			set_text (page, "events-filter-port", "http");
			CHECK (!fs_hitview_refilter_now (),
			       "\"http\" in the port box is refused");
			CHECK (err != NULL && gtk_widget_get_visible (err) &&
			       strstr (gtk_label_get_text (GTK_LABEL (err)),
			               "not a port") != NULL,
			       "and the page says why (\"%s\")",
			       err ? gtk_label_get_text (GTK_LABEL (err)) : "?");
			CHECK (fs_hitview_visible_count () == before,
			       "the list keeps the filter it had");
			shot (window, "events-bad-port");
			set_text (page, "events-filter-port", "20-500");
			fs_hitview_refilter_now ();
		}

		/* Export: exactly what is shown. */
		{
			gchar *dirp = g_dir_make_tmp ("fs-export-XXXXXX", NULL);
			gchar *path = g_build_filename (dirp, "e.csv", NULL);
			gchar *csv = NULL;
			guint written = 0, lines = 0;

			CHECK (fs_hitview_export_csv (path, &written, NULL) &&
			       written == fs_hitview_visible_count (),
			       "the CSV export writes the %u rows shown", written);
			g_file_get_contents (path, &csv, NULL, NULL);
			for (const gchar *c = csv; c != NULL && *c; c++)
				lines += *c == '\n';
			CHECK (lines == written + 1, "one line each, plus the header");
			g_remove (path);
			g_rmdir (dirp);
			g_free (csv);
			g_free (path);
			g_free (dirp);
		}

		gtk_button_clicked (GTK_BUTTON (find_named (page,
			"events-filter-reset")));
		pump ();
		CHECK (fs_hitview_visible_count () == fs_hitview_count (),
		       "Reset shows everything again");
	}

	/* Sorting by a column: every row, then back to newest first. */
	{
		GtkTreeSortable *sortable = GTK_TREE_SORTABLE (
			gtk_tree_view_get_model (GTK_TREE_VIEW (tree)));
		gboolean ordered = TRUE;
		gdouble ms;
		gint col = -2;
		GtkSortType order;

		gtk_tree_sortable_get_sort_column_id (sortable, &col, &order);
		CHECK (col == 0 && order == GTK_SORT_DESCENDING,
		       "the default sort is time, newest first");

		t = g_get_monotonic_time ();
		gtk_tree_sortable_set_sort_column_id (sortable, 4,
		                                      GTK_SORT_ASCENDING);
		pump ();
		ms = (g_get_monotonic_time () - t) / 1000.0;
		printf ("measure: sort %u rows by port: %.1f ms\n",
		        fs_hitview_visible_count (), ms);

		for (guint r = 0; r + 1 < fs_hitview_visible_count () && ordered;
		     r += 97) {
			gchar *a = cell (tree, r, 4), *b = cell (tree, r + 1, 4);

			ordered = cmp_num (a, b) <= 0;
			g_free (a);
			g_free (b);
		}
		{
			gchar *first = cell (tree, 0, 4);
			gchar *last = cell (tree, fs_hitview_visible_count () - 1, 4);

			CHECK (ordered && g_strcmp0 (first, "22") == 0 &&
			       g_strcmp0 (last, "8080") == 0,
			       "by port, as numbers: 22 first, 8080 last (got %s, "
			       "%s, in order: %d)", first, last, ordered);
			g_free (first);
			g_free (last);
		}

		/* A live event lands where the sort puts it. */
		make_event (n + 40, &hit, time, src, dst, port);
		hit.port = (gchar *) "1";
		fs_hitview_append (&hit);
		{
			gchar *first = cell (tree, 0, 4);

			CHECK (g_strcmp0 (first, "1") == 0,
			       "a new event sorts into place, not on top");
			g_free (first);
		}

		gtk_tree_sortable_set_sort_column_id (sortable, 4,
		                                      GTK_SORT_DESCENDING);
		{
			gchar *first = cell (tree, 0, 4);

			CHECK (g_strcmp0 (first, "8080") == 0,
			       "the other way round: 8080 first");
			g_free (first);
		}

		gtk_tree_sortable_set_sort_column_id (sortable, 0,
		                                      GTK_SORT_DESCENDING);
		{
			gchar *a = cell (tree, 0, 0), *b = cell (tree, 1, 0);

			CHECK (g_strcmp0 (a, b) > 0, "back to newest first");
			g_free (a);
			g_free (b);
		}
	}

	/* The history file is being written. */
	{
		gchar *dir = fs_hitview_history_dir ();
		guint64 bytes = 0;
		guint files = 0;

		fs_hitview_shutdown ();
		fs_eventlog_usage (dir, &bytes, &files);
		CHECK (files > 0 && bytes > (guint64) n * 50,
		       "every event went to the history files too (%u files, "
		       "%" G_GUINT64_FORMAT " bytes)", files, bytes);
		g_free (dir);
	}

	gtk_container_remove (GTK_CONTAINER (window), page);
	gtk_widget_destroy (window);
	fs_hitview_clear ();
	/* main destroys the page; the reference taken above goes then. */
	g_object_unref (page);
}

/* What the strip says, or NULL while it is hidden. */
static gchar *
strip_text (GtkWidget *page)
{
	GtkWidget *strip = NULL;
	GList *children, *l;
	gchar *text = NULL;

	find_strip (page, &strip);
	if (strip == NULL || !shown_up_to (strip, page))
		return NULL;

	children = gtk_container_get_children (GTK_CONTAINER (strip));
	for (l = children; l != NULL && text == NULL; l = l->next)
		if (GTK_IS_LABEL (l->data))
			text = g_strdup (gtk_label_get_text (GTK_LABEL (l->data)));
	g_list_free (children);
	return text;
}

#ifndef G_OS_WIN32
/* Live events, a few at a time, while the main loop runs for up to ms
 * or until the strip says what want asks for (NULL: what it said in
 * was). */
static gboolean
run_until_strip (GtkWidget *page, const gchar *want, const gchar *was,
                 guint ms, guint *next)
{
	gint64 end = g_get_monotonic_time () + (gint64) ms * 1000;
	gchar time[FS_EVENT_TIME_BUF], src[48], dst[48], port[8];
	FsHit hit;

	while (g_get_monotonic_time () < end) {
		gchar *now;
		gboolean done;

		for (guint i = 0; i < 20; i++) {
			make_event ((*next)++, &hit, time, src, dst, port);
			fs_hitview_append (&hit);
		}
		pump ();
		now = strip_text (page);
		done = want != NULL ? (now != NULL && strstr (now, want) != NULL)
		                    : g_strcmp0 (now, was) == 0;
		g_free (now);
		if (done)
			return TRUE;
		g_usleep (50000);
	}
	return FALSE;
}

/* [ check_history_failure ]
 * A full disk in the middle of a session: the strip says history is
 * not being saved, and once there is room again the history goes on
 * and the strip goes back to what it said.  RLIMIT_FSIZE makes write()
 * fail the way a full disk does (EFBIG for ENOSPC).  Nothing is printed
 * while the limit is down: stdout may be a file. */
static void
check_history_failure (GtkWidget *page)
{
	struct rlimit old, low;
	gchar *dir = fs_hitview_history_dir ();
	gchar *before, *failing;
	gboolean warned, recovered;
	guint64 bytes_failing = 0, bytes_after = 0;
	guint next = 900000;

	before = strip_text (page);
	fflush (stdout);
	fflush (stderr);

	signal (SIGXFSZ, SIG_IGN);
	getrlimit (RLIMIT_FSIZE, &old);
	low = old;
	low.rlim_cur = 1;
	setrlimit (RLIMIT_FSIZE, &low);

	warned = run_until_strip (page, "not being saved", NULL, 4000, &next);
	failing = strip_text (page);
	fs_eventlog_usage (dir, &bytes_failing, NULL);

	setrlimit (RLIMIT_FSIZE, &old);
	recovered = run_until_strip (page, NULL, before, 8000, &next);
	signal (SIGXFSZ, SIG_DFL);
	fs_eventlog_usage (dir, &bytes_after, NULL);

	CHECK (warned && failing != NULL &&
	       strstr (failing, "Event history is not being saved") != NULL,
	       "a write that fails in the middle of a session is on the "
	       "strip within seconds (%s)", failing != NULL ? failing : "none");
	CHECK (recovered && fs_hitview_history_problem () == NULL,
	       "with room again, history is written again and the strip goes "
	       "back to what it said before (%s)",
	       before != NULL ? before : "hidden");
	CHECK (bytes_after > bytes_failing,
	       "...and the events after it are in the files (%" G_GUINT64_FORMAT
	       " bytes, %" G_GUINT64_FORMAT " while failing)", bytes_after,
	       bytes_failing);

	g_free (before);
	g_free (failing);
	g_free (dir);
}
#endif

/* Appends burst events to a full store through the model, the way
 * fs_hitview_append does; returns microseconds per event. */
static gdouble
model_burst (FsEventStore *s, FsEventModel *m, guint from, guint burst)
{
	gchar time[FS_EVENT_TIME_BUF], src[48], dst[48], port[8];
	FsHit hit;
	gint64 t = g_get_monotonic_time ();

	for (guint i = 0; i < burst; i++) {
		guint64 seq;

		make_event (from + i, &hit, time, src, dst, port);
		seq = fs_eventstore_append (s, &hit, 0);
		fs_event_model_note_append (m, seq);
	}
	return (gdouble) (g_get_monotonic_time () - t) / burst;
}

static gboolean
same_rows (GArray *a, GArray *b)
{
	return a->len == b->len &&
	       memcmp (a->data, b->data, a->len * sizeof (guint64)) == 0;
}

/* [ check_sorted_burst ]
 * The list at its largest, 1,000,000 events, shown in a real view: a
 * burst of 5,000 live events under the port sort costs about what it
 * costs under the time sort.  Each event used to move up to the whole
 * row array twice (add in sort order, drop the oldest from the middle):
 * about 200 us an event at this size, so a burst of 5,000 a second
 * took the main thread whole.  And the rows kept that way are exactly
 * the rows a sort from scratch gives. */
static void
check_sorted_burst (void)
{
	const guint cap = FS_EVENTSTORE_MAX_CAPACITY;
	const guint burst = 5000;
	FsEventStore *s = fs_eventstore_new (cap);
	gchar time[FS_EVENT_TIME_BUF], src[48], dst[48], port[8];
	FsEventModel *m;
	GtkWidget *win, *scroll, *tree;
	GArray *kept, *fresh;
	FsHit hit;
	gdouble by_time, by_port, by_source, sort_ms;
	gint64 t;

	for (guint i = 0; i < cap; i++) {
		make_event (i, &hit, time, src, dst, port);
		fs_eventstore_append (s, &hit, 0);
	}
	m = fs_event_model_new (s);

	win = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size (GTK_WINDOW (win), 1240, 760);
	scroll = gtk_scrolled_window_new (NULL, NULL);
	tree = gtk_tree_view_new ();
	for (gint c = 0; c < FS_HITCOL_COLOR; c++) {
		GtkTreeViewColumn *col = gtk_tree_view_column_new_with_attributes (
			"c", gtk_cell_renderer_text_new (), "text", c, NULL);

		gtk_tree_view_column_set_sizing (col, GTK_TREE_VIEW_COLUMN_FIXED);
		gtk_tree_view_column_set_fixed_width (col, 100);
		gtk_tree_view_append_column (GTK_TREE_VIEW (tree), col);
	}
	gtk_tree_view_set_fixed_height_mode (GTK_TREE_VIEW (tree), TRUE);
	gtk_tree_view_set_model (GTK_TREE_VIEW (tree), GTK_TREE_MODEL (m));
	gtk_container_add (GTK_CONTAINER (scroll), tree);
	gtk_container_add (GTK_CONTAINER (win), scroll);
	gtk_widget_show_all (win);
	pump ();

	by_time = model_burst (s, m, cap, burst);
	pump ();

	t = g_get_monotonic_time ();
	gtk_tree_sortable_set_sort_column_id (GTK_TREE_SORTABLE (m),
	                                      FS_HITCOL_PORT,
	                                      GTK_SORT_ASCENDING);
	pump ();
	sort_ms = (g_get_monotonic_time () - t) / 1000.0;
	by_port = model_burst (s, m, cap + burst, burst);
	pump ();

	gtk_tree_sortable_set_sort_column_id (GTK_TREE_SORTABLE (m),
	                                      FS_HITCOL_SOURCE,
	                                      GTK_SORT_DESCENDING);
	pump ();
	by_source = model_burst (s, m, cap + 2 * burst, burst);
	pump ();

	printf ("measure: %u live events into %u shown, time sort: %.1f us "
	        "each\n", burst, cap, by_time);
	printf ("measure: sort %u rows by port, view attached: %.0f ms\n",
	        cap, sort_ms);
	printf ("measure: %u live events into %u shown, port sort: %.1f us "
	        "each (%.0f events/s at most)\n", burst, cap, by_port,
	        1e6 / by_port);
	printf ("measure: %u live events into %u shown, source sort "
	        "(descending): %.1f us each\n", burst, cap, by_source);

	CHECK (fs_event_model_n_rows (m) == cap &&
	       gtk_tree_model_iter_n_children (GTK_TREE_MODEL (m), NULL) ==
	       (gint) cap,
	       "the full list stays full while the ring turns over (%u rows)",
	       fs_event_model_n_rows (m));
	CHECK (by_port <= 6.0 * by_time + 20.0 &&
	       by_source <= 6.0 * by_time + 20.0,
	       "at %u rows a live event under another sort costs about what it "
	       "costs under the time sort (port %.1f us, source %.1f us, time "
	       "%.1f us)", cap, by_port, by_source, by_time);

	/* The rows as the events left them, against a sort from scratch. */
	kept = fs_event_model_rows (m);
	gtk_tree_view_set_model (GTK_TREE_VIEW (tree), NULL);
	fs_event_model_rebuild (m);
	fresh = fs_event_model_rows (m);
	CHECK (same_rows (kept, fresh),
	       "after %u adds and drops under three sorts, the rows are those "
	       "a sort from scratch gives", 3 * burst);
	g_array_unref (kept);
	g_array_unref (fresh);

	gtk_widget_destroy (win);
	g_object_unref (m);
	fs_eventstore_free (s);
}

/* [ check_rows_churn ]
 * 20,000 events sorted by port: each live event joins the end of its
 * port's rows and the oldest leaves the start of another's, so the
 * row chunks there split and the ones emptying join their neighbours,
 * over and over.  After each round the rows must be exactly those a
 * sort from scratch gives. */
static void
check_rows_churn (void)
{
	const guint cap = 20000;
	FsEventStore *s = fs_eventstore_new (cap);
	gchar time[FS_EVENT_TIME_BUF], src[48], dst[48], port[8];
	FsEventModel *m;
	FsHit hit;
	guint next = 0, bad_round = 0;

	for (; next < cap; next++) {
		make_event (next, &hit, time, src, dst, port);
		fs_eventstore_append (s, &hit, 0);
	}
	m = fs_event_model_new (s);
	gtk_tree_sortable_set_sort_column_id (GTK_TREE_SORTABLE (m),
	                                      FS_HITCOL_PORT,
	                                      GTK_SORT_ASCENDING);

	for (guint round = 1; round <= 6 && bad_round == 0; round++) {
		GArray *kept, *fresh;

		if (round == 4)
			gtk_tree_sortable_set_sort_column_id (
				GTK_TREE_SORTABLE (m), FS_HITCOL_SERVICE,
				GTK_SORT_DESCENDING);
		model_burst (s, m, next, 3 * cap);
		next += 3 * cap;

		kept = fs_event_model_rows (m);
		fs_event_model_rebuild (m);
		fresh = fs_event_model_rows (m);
		if (!same_rows (kept, fresh) || kept->len != cap)
			bad_round = round;
		g_array_unref (kept);
		g_array_unref (fresh);
	}

	CHECK (bad_round == 0,
	       "rows kept through 360,000 adds and drops at 20,000 (chunks "
	       "split and joined) are those a sort from scratch gives (first "
	       "wrong round: %u)", bad_round);

	g_object_unref (m);
	fs_eventstore_free (s);
}

int
main (int argc, char **argv)
{
	GtkWidget *page;
	GtkWidget *label = NULL;
	GtkWidget *strip = NULL;
	gboolean running;
	gchar *scratch = NULL;
	gchar *config;

	/* Settings in a scratch folder too, before anything reads them. */
	config = g_dir_make_tmp ("fs-hitview-smoke-config-XXXXXX", NULL);
#ifdef G_OS_WIN32
	g_setenv ("APPDATA", config, TRUE);
#else
	g_setenv ("XDG_CONFIG_HOME", config, TRUE);
#endif

	gtk_init (&argc, &argv);

	/* History is kept only once chosen. */
	CHECK (!fs_prefs_bool (FS_PREFS_EVENTS_HISTORY),
	       "event history is off until the user switches it on");
	fs_prefs_set_bool (FS_PREFS_EVENTS_HISTORY, TRUE);

	/* History goes to a scratch folder, never the account's own. */
	if (g_getenv ("STOCKFW_EVENTS_DIR") == NULL) {
		scratch = g_dir_make_tmp ("fs-hitview-smoke-XXXXXX", NULL);
		g_setenv ("STOCKFW_EVENTS_DIR", scratch, TRUE);
	}

	/* History left by an earlier session: the page reads it back. */
	{
		gchar *dir = fs_eventlog_default_dir ();
		FsEventLog *log = fs_eventlog_open (dir, 30, 0, NULL);
		gint64 t0 = g_get_real_time () * 10 - 3600 * 10000000LL;

		for (guint i = 0; log != NULL && i < 500; i++) {
			FsHit h = { 0 };
			gchar stamp[FS_EVENT_TIME_BUF];

			fs_event_time_format (t0 + (gint64) i * 10000000,
			                      FS_EVENT_TIME_SECS, stamp);
			h.time = stamp;
			h.direction = (gchar *) "Out";
			h.destination = (gchar *) "198.51.100.250";
			fs_eventlog_append (log, &h, t0 + (gint64) i * 10000000);
		}
		fs_eventlog_close (log);
		g_free (dir);
	}

	page = fs_hitview_page ();

	CHECK (fs_hitview_history_loaded () == 500 &&
	       fs_hitview_count () >= 500,
	       "the 500 events of an earlier session are listed at start "
	       "(%u read back)", fs_hitview_history_loaded ());
	fs_hitview_clear ();

	/* What fs-app.c:119 does when the page is added to the window. */
	gtk_widget_show_all (page);

	running = fs_hitview_active ();
	find_reason_label (page, &label);
	find_strip (page, &strip);

	printf ("monitoring -> %s\n", running ? "running" : "not running");
	printf ("reason     -> %s\n",
	        label ? gtk_label_get_text (GTK_LABEL (label)) : "(none)");
	printf ("strip      -> %s\n", strip ? "found" : "(none)");

	CHECK (strip != NULL, "the page builds a reason strip");

	if (label != NULL) {
		/* Cannot monitor: the reason must actually reach the screen. */
		CHECK (shown_up_to (label, page),
		       "the reason is visible, not merely created");
		CHECK (strip != NULL && shown_up_to (strip, page),
		       "the strip carrying it is visible too");
		CHECK (!running,
		       "nothing claims to be running while a reason is shown");
	} else {
		/* No reason shown: monitoring had better be real, because
		 * this is exactly the shape of the original bug. */
		CHECK (strip == NULL || !gtk_widget_get_visible (strip),
		       "no reason to give, so the strip stays hidden");
		CHECK (running,
		       "no reason shown, so monitoring must really be running");
	}

	check_list_behaviour (page);
	check_filter_bar (page);
#ifndef G_OS_WIN32
	check_history_failure (page);
#endif
	check_scale (page);
	check_sorted_burst ();
	check_rows_churn ();

	fs_hitview_stop ();
	gtk_widget_destroy (page);

	if (scratch != NULL) {
		fs_hitview_shutdown ();
		fs_eventlog_clear_dir (scratch, NULL);
		g_rmdir (scratch);
		g_free (scratch);
	}

	printf ("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
