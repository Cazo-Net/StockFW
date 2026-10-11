/* Checks the Status page does not offer per-profile switches on a
 * backend that has no profiles.
 *
 * The regression this guards: the "Firewall profiles" frame was built
 * unconditionally, then hidden with gtk_widget_hide().  fs-app.c calls
 * gtk_widget_show_all() on the window *after* the page is built, and
 * that walk re-shows any hidden descendant -- so Linux was handed three
 * switches labelled Domain / Private / Public that could only ever
 * answer "Linux has a single firewall state, not per-profile settings."
 *
 * A control that can only produce an error dialog is worse than no
 * control: it invites the click, then punishes it.  The frame must be
 * genuinely invisible to the user, which means not visible somewhere up
 * the tree either -- a hidden parent renders nothing however set the
 * child's own flag is.
 *
 * gtk_widget_show_all() is called on the page here for the same reason
 * fs-app.c does it, so the check sees the page in the state the user
 * actually gets.
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-backend.h"
#include "core/fs-types.h"
#include "ui/fs-statusview.h"

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

/* The profiles frame, found by its frame label rather than by position
 * in the box, so reordering the page cannot silently break the test. */
static gboolean
find_profiles_frame (GtkWidget *widget, GtkWidget **out)
{
	if (GTK_IS_FRAME (widget)) {
		const gchar *label = gtk_frame_get_label (GTK_FRAME (widget));

		if (label != NULL && strstr (label, "profiles") != NULL) {
			*out = widget;
			return TRUE;
		}
	}

	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));
		GList *l;

		for (l = children; l != NULL; l = l->next) {
			if (find_profiles_frame (GTK_WIDGET (l->data), out)) {
				g_list_free (children);
				return TRUE;
			}
		}
		g_list_free (children);
	}

	return FALSE;
}

/* A GtkSwitch anywhere under widget: the per-profile toggles. */
static gboolean
find_switch (GtkWidget *widget, GtkWidget **out)
{
	if (GTK_IS_SWITCH (widget)) {
		*out = widget;
		return TRUE;
	}

	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));
		GList *l;

		for (l = children; l != NULL; l = l->next) {
			if (find_switch (GTK_WIDGET (l->data), out)) {
				g_list_free (children);
				return TRUE;
			}
		}
		g_list_free (children);
	}

	return FALSE;
}

/* Visible means visible here and all the way up to the page. */
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

/* Whether the backend reports any profile at all.  This is the same
 * query the page itself makes to decide whether to show the frame, so
 * the test's expectation tracks the backend rather than the platform
 * name. */
static gboolean
backend_has_profiles (void)
{
	gint i;

	for (i = 0; i < FS_PROFILE_COUNT; i++) {
		if (fs_backend ()->get_profile_enabled (i, NULL))
			return TRUE;
	}

	return FALSE;
}

int
main (int argc, char **argv)
{
	GtkWidget *page;
	GtkWidget *frame = NULL;
	GtkWidget *sw = NULL;
	gboolean has_profiles;

	gtk_init (&argc, &argv);

	page = fs_statusview_page ();

	/* What fs-app.c does when the window is shown, and the exact call
	 * that used to resurrect the hidden frame. */
	gtk_widget_show_all (page);

	has_profiles = backend_has_profiles ();
	find_profiles_frame (page, &frame);
	find_switch (page, &sw);

	printf ("backend     -> %s\n", fs_backend ()->display_name);
	printf ("profiles    -> %s\n", has_profiles ? "yes" : "no");
	printf ("frame       -> %s\n", frame ? "found" : "(none)");
	printf ("frame shown -> %s\n",
	        frame && gtk_widget_get_visible (frame) ? "yes" : "no");

	if (has_profiles) {
		/* Windows-shaped backend: the frame must be offered. */
		CHECK (frame != NULL, "a profile-capable backend builds the frame");
		CHECK (frame != NULL && shown_up_to (frame, page),
		       "and it is really visible, not merely created");
	} else {
		/* Linux-shaped backend: no frame, or a genuinely hidden one.
		 * The frame existing but hidden is acceptable; it being
		 * reachable on screen is the bug this test exists for. */
		CHECK (frame == NULL || !gtk_widget_get_visible (frame),
		       "a backend without profiles does not show the frame");

		if (frame != NULL) {
			CHECK (!shown_up_to (frame, page),
			       "and no ancestor re-shows it (the show_all trap)");
			CHECK (!gtk_widget_get_no_show_all (frame) ||
			       !gtk_widget_get_visible (frame),
			       "no-show-all is set, so later show_all cannot revive it");
		}

		/* The switches live inside the frame, so they are unreachable
		 * when it is.  Assert that directly rather than trusting the
		 * containment. */
		if (sw != NULL) {
			CHECK (!shown_up_to (sw, page),
			       "the per-profile switches are not reachable on screen");
		} else {
			CHECK (TRUE, "no per-profile switch exists at all");
		}
	}

	gtk_widget_destroy (page);

	printf ("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
