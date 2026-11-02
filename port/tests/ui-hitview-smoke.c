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
#include <stdio.h>
#include <string.h>
#ifndef G_OS_WIN32
#include <unistd.h>
#endif

#include "core/fs-backend.h"
#include "core/fs-types.h"
#include "core/fs-copilot.h"
#include "core/fs-prefs.h"
#include "core/fs-util.h"
#include "ui/fs-hitview.h"

/* The app's Copilot (fs-app.c): the Events page feeds it. */
extern FsCopilot *copilot;
static gchar *log_file = NULL;

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

	/* Row budget: 2001 rows, one per second from 12:00:00, each
	 * newer than the last.  The cap is 2000, so exactly the FIRST
	 * (oldest) row must be gone; the newest stays on top. */
	fs_hitview_clear ();
	for (i = 0; i < FS_HITVIEW_MAX_ROWS + 1; i++) {
		memset (&hit, 0, sizeof hit);
		hit.time = g_strdup_printf (
			"2026-10-09T%02d:%02d:%02dZ",
			12 + (gint) (i / 3600), (gint) ((i / 60) % 60),
			(gint) (i % 60));
		hit.destination = (gchar *) "198.51.100.9";
		fs_hitview_append (&hit);
		g_free (hit.time);
	}

	CHECK (fs_hitview_count () == FS_HITVIEW_MAX_ROWS,
	       "the cap holds (%u rows)", fs_hitview_count ());

	text = row_time_at (tree, 0);
	CHECK (text != NULL && g_strcmp0 (text, "2026-10-09T12:33:20Z") == 0,
	       "the NEWEST row is kept on top (got \"%s\")",
	       text ? text : "(null)");
	g_free (text);

	text = row_time_at (tree, FS_HITVIEW_MAX_ROWS - 1);
	CHECK (text != NULL && g_strcmp0 (text, "2026-10-09T12:00:01Z") == 0,
	       "the OLDEST row is the one dropped (got \"%s\")",
	       text ? text : "(null)");
	g_free (text);

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

static void
pump_ms (guint ms)
{
	gint64 until = g_get_monotonic_time () + (gint64) ms * 1000;

	do {
		while (gtk_events_pending ())
			gtk_main_iteration_do (FALSE);
		g_usleep (2000);
	} while (g_get_monotonic_time () < until);
}

/* [ check_feed_order ]
 * The Copilot sees every event, before the list's display filters:
 * with "skip repeats" on, ten identical attempts are one row on the
 * list and still ten events to the checks (a login storm or a timed
 * check-in is exactly a run of identical lines).  Runs where the
 * backend reads the scratch log (Linux as root). */
static void
check_feed_order (void)
{
	const gchar *line =
		"Oct 11 14:30:00 kali kernel: [ 1234.5] STOCKFW-DROP "
		"IN=eth0 OUT= SRC=192.0.2.10 DST=198.51.100.20 "
		"PROTO=TCP SPT=54321 DPT=22 LEN=60";
	gint64 deadline;
	guint64 seen0;
	guint rows0;
	GString *ten;

	if (log_file == NULL || !fs_hitview_active ()) {
		printf ("skip: feed order (the backend is not reading the "
		        "scratch log here)\n");
		return;
	}

	/* Repeats skipped; foreign traffic listed, so the one row the ten
	 * lines make is there to count. */
	fs_prefs_set_bool (FS_PREFS_SKIP_REDUNDANT, TRUE);
	fs_prefs_set_bool (FS_PREFS_SKIP_NOT_FOR_FIREWALL, FALSE);
	fs_hitview_clear ();

	/* Wake: until one line arrives, the tail may not be following. */
	deadline = g_get_monotonic_time () + 8 * G_USEC_PER_SEC;
	while (fs_copilot_events_seen (copilot) == 0 &&
	       g_get_monotonic_time () < deadline) {
		fs_util_append_to_file (log_file,
			"Oct 11 14:29:59 kali kernel: STOCKFW-DROP IN=eth9 OUT= "
			"SRC=0.0.0.0 DST=0.0.0.0 PROTO=TCP SPT=1 DPT=1", TRUE);
		pump_ms (200);
	}
	CHECK (fs_copilot_events_seen (copilot) > 0,
	       "feed order: the scratch log reaches the Copilot");

	seen0 = fs_copilot_events_seen (copilot);
	rows0 = fs_hitview_count ();
	ten = g_string_new (NULL);
	for (guint i = 0; i < 10; i++)
		g_string_append_printf (ten, "%s%s", i > 0 ? "\n" : "", line);
	fs_util_append_to_file (log_file, ten->str, TRUE);
	g_string_free (ten, TRUE);

	deadline = g_get_monotonic_time () + 8 * G_USEC_PER_SEC;
	while (fs_copilot_events_seen (copilot) < seen0 + 10 &&
	       g_get_monotonic_time () < deadline)
		pump_ms (50);
	pump_ms (200);

	CHECK (fs_copilot_events_seen (copilot) == seen0 + 10,
	       "feed order: with skip repeats on, 10 identical events still "
	       "reach the Copilot as 10 (got %" G_GUINT64_FORMAT ")",
	       fs_copilot_events_seen (copilot) - seen0);
	CHECK (fs_hitview_count () == rows0 + 1,
	       "feed order: and the list shows them as one row (got %u)",
	       fs_hitview_count () - rows0);
	fs_prefs_set_bool (FS_PREFS_SKIP_REDUNDANT, FALSE);
}

int
main (int argc, char **argv)
{
	GtkWidget *page;
	GtkWidget *label = NULL;
	GtkWidget *strip = NULL;
	gboolean running;

	gtk_init (&argc, &argv);

	/* Scratch preferences, and as root a scratch kernel log the
	 * backend tails (its own STOCKFW_LOG_FILE seam), so the feed-order
	 * check can put exact lines in front of the real parser. */
	{
		gchar *dir = g_dir_make_tmp ("stockfw-hitview-smoke-XXXXXX",
		                             NULL);

		g_setenv ("XDG_CONFIG_HOME", dir, TRUE);
		g_setenv ("APPDATA", dir, TRUE);
#ifndef G_OS_WIN32
		if (geteuid () == 0) {
			log_file = g_build_filename (dir, "kern.log", NULL);
			g_file_set_contents (log_file, "", 0, NULL);
			g_setenv ("STOCKFW_LOG_FILE", log_file, TRUE);
		}
#endif
		g_free (dir);
	}
	copilot = fs_copilot_new ();

	page = fs_hitview_page ();

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
	check_feed_order ();

	fs_hitview_stop ();
	gtk_widget_destroy (page);

	printf ("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
