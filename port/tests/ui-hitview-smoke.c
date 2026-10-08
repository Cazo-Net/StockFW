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

#include "core/fs-backend.h"
#include "core/fs-types.h"
#include "ui/fs-hitview.h"

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

int
main (int argc, char **argv)
{
	GtkWidget *page;
	GtkWidget *label = NULL;
	GtkWidget *strip = NULL;
	gboolean running;

	gtk_init (&argc, &argv);

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

	check_filter_bar (page);

	fs_hitview_stop ();
	gtk_widget_destroy (page);

	printf ("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
