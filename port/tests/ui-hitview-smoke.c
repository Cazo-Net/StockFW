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

	fs_hitview_stop ();
	gtk_widget_destroy (page);

	printf ("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
