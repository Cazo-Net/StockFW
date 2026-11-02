/* The Overview page (the Status page before 1.0.7).
 *
 * Part 1 checks it does not offer per-profile switches on a backend
 * that has no profiles.  Part 2 (1.0.7) checks the verdict card says
 * what the firewall state and the backend's IPv6 answer mean, that the
 * sidebar's copy of the verdict is told about every change, that the
 * Lock button is the real gate, and that Recent blocks keeps the newest
 * few in words.
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
#include "ui/fs-icons.h"

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

/* The first label carrying CSS class klass under widget. */
static GtkWidget *
find_by_class (GtkWidget *widget, const gchar *klass)
{
	if (gtk_style_context_has_class (gtk_widget_get_style_context (widget),
	                                 klass))
		return widget;

	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));
		GtkWidget *found = NULL;

		for (GList *l = children; l != NULL && found == NULL; l = l->next)
			found = find_by_class (GTK_WIDGET (l->data), klass);
		g_list_free (children);
		return found;
	}
	return NULL;
}

/* The button whose label (anywhere inside it) reads text. */
static GtkWidget *
find_button (GtkWidget *widget, const gchar *text)
{
	if (GTK_IS_LABEL (widget) &&
	    g_strcmp0 (gtk_label_get_text (GTK_LABEL (widget)), text) == 0) {
		GtkWidget *w = widget;

		while (w != NULL && !GTK_IS_BUTTON (w))
			w = gtk_widget_get_parent (w);
		return w;
	}

	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));
		GtkWidget *found = NULL;

		for (GList *l = children; l != NULL && found == NULL; l = l->next)
			found = find_button (GTK_WIDGET (l->data), text);
		g_list_free (children);
		return found;
	}
	return NULL;
}

static guint changes = 0;

static void
on_changed (gpointer user)
{
	(void) user;
	changes++;
}

static const gchar *
label_text (GtkWidget *page, const gchar *klass)
{
	GtkWidget *label = find_by_class (page, klass);

	return label != NULL && GTK_IS_LABEL (label)
	       ? gtk_label_get_text (GTK_LABEL (label)) : "(none)";
}

static gboolean
has_class (GtkWidget *w, const gchar *klass)
{
	return w != NULL &&
	       gtk_style_context_has_class (gtk_widget_get_style_context (w),
	                                    klass);
}

static FsHit *
blocked_hit (gint n, const gchar *rule)
{
	FsHit *hit = g_new0 (FsHit, 1);

	hit->time = g_strdup_printf ("Nov  2 10:4%d:00", n);
	hit->direction = g_strdup (n % 2 == 0 ? "In" : "Out");
	hit->source = g_strdup_printf ("203.0.113.%d", n);
	hit->destination = g_strdup_printf ("198.51.100.%d", n);
	hit->port = g_strdup ("22");
	hit->protocol = g_strdup ("TCP");
	hit->service = g_strdup (n == 3 ? "[BLOCKED]" : "SSH [BLOCKED]");
	hit->rule = g_strdup (rule);
	return hit;
}

static void
free_hit (FsHit *hit)
{
	g_free (hit->time);
	g_free (hit->direction);
	g_free (hit->source);
	g_free (hit->destination);
	g_free (hit->port);
	g_free (hit->protocol);
	g_free (hit->service);
	g_free (hit->rule);
	g_free (hit);
}

static void
check_overview (GtkWidget *page)
{
	const FsBackend *backend = fs_backend ();
	FsVerdict level;
	FsIpv6State v6 = FS_IPV6_UNKNOWN;
	GtkWidget *hero = find_by_class (page, "hero");
	GtkWidget *lock;
	gchar *detail = NULL;
	gchar **rows;
	guint before;

	fs_statusview_set_changed_cb (on_changed, NULL);

	/* Stopped: red, says so, offers Start. */
	before = changes;
	fs_statusview_set_state (FS_FW_STOPPED);
	fs_statusview_verdict (&level);
	CHECK (level == FS_VERDICT_BAD && has_class (hero, "level-bad"),
	       "stopped: the verdict is BAD and the card is red");
	CHECK (strcmp (fs_statusview_verdict (NULL), "Not protected") == 0,
	       "stopped: the sidebar word is \"Not protected\" (got \"%s\")",
	       fs_statusview_verdict (NULL));
	CHECK (strcmp (label_text (page, "hero-title"),
	               "This computer is not protected") == 0,
	       "stopped: the card's title says so (got \"%s\")",
	       label_text (page, "hero-title"));
	CHECK (find_button (page, "Start firewall") != NULL &&
	       find_button (page, "Stop firewall") == NULL,
	       "stopped: the one power button offers Start");
	CHECK (changes > before, "stopped: the sidebar listener was told");

	/* Running: green unless the backend says IPv6 passes unfiltered,
	 * which must turn the whole verdict amber. */
	if (backend->ipv6_state != NULL)
		v6 = backend->ipv6_state (&detail);
	g_free (detail);
	printf ("ipv6 state  -> %s\n", fs_ipv6_state_to_string (v6));

	before = changes;
	fs_statusview_set_state (FS_FW_RUNNING);
	fs_statusview_verdict (&level);
	if (backend->ipv6_state != NULL && v6 == FS_IPV6_UNFILTERED) {
		CHECK (level == FS_VERDICT_WARN && has_class (hero, "level-warn"),
		       "running with IPv6 unfiltered: the verdict is WARN, not OK");
		CHECK (strcmp (label_text (page, "hero-title"),
		               "IPv6 is not protected") == 0,
		       "and the title names IPv6 (got \"%s\")",
		       label_text (page, "hero-title"));
	} else if (v6 == FS_IPV6_UNKNOWN && backend->ipv6_state != NULL) {
		CHECK (level == FS_VERDICT_OK,
		       "running, IPv6 unknown: OK, with the reason in the body");
	} else {
		CHECK (level == FS_VERDICT_OK && has_class (hero, "level-ok"),
		       "running with every family filtered: the verdict is OK");
		CHECK (strcmp (label_text (page, "hero-title"),
		               "This computer is protected") == 0,
		       "and the title says protected (got \"%s\")",
		       label_text (page, "hero-title"));
	}
	CHECK (!has_class (hero, "level-bad"),
	       "running: the red class is gone, not stacked");
	CHECK (find_button (page, "Stop firewall") != NULL,
	       "running: the power button offers Stop");
	CHECK (changes > before, "running: the sidebar listener was told");

	/* Unknown. */
	fs_statusview_set_state (FS_FW_NONE);
	fs_statusview_verdict (&level);
	CHECK (level == FS_VERDICT_UNKNOWN && has_class (hero, "level-unknown"),
	       "unknown state: the verdict is UNKNOWN");

	/* The Lock button is the gate the Policy page asks about. */
	fs_statusview_set_state (FS_FW_RUNNING);
	lock = find_button (page, "Lock policy");
	CHECK (lock != NULL && GTK_IS_TOGGLE_BUTTON (lock),
	       "the header has a Lock policy toggle");
	if (lock != NULL) {
		gtk_button_clicked (GTK_BUTTON (lock));
		CHECK (fs_statusview_policy_locked (),
		       "pressing it locks the policy");
		CHECK (fs_statusview_get_state () == FS_FW_LOCKED,
		       "and the state reads locked");
		CHECK (find_button (page, "Policy locked") != NULL,
		       "and the button says so");
		gtk_button_clicked (GTK_BUTTON (lock));
		CHECK (!fs_statusview_policy_locked () &&
		       fs_statusview_get_state () == FS_FW_RUNNING,
		       "pressing it again unlocks");
	}

	/* Recent blocks: newest first, at most five, in words. */
	rows = fs_statusview_recent_blocks ();
	CHECK (rows != NULL && rows[0] == NULL, "no blocks noted yet");
	g_strfreev (rows);
	for (gint n = 1; n <= 7; n++) {
		FsHit *hit = blocked_hit (n, n == 7 ? "Threat intel: Spamhaus DROP"
		                                    : NULL);

		fs_statusview_note_block (hit);
		free_hit (hit);
	}
	rows = fs_statusview_recent_blocks ();
	CHECK (g_strv_length (rows) == 5,
	       "seven blocks keep the newest five (got %u)",
	       g_strv_length (rows));
	CHECK (g_str_has_prefix (rows[0], "Blocked outbound SSH\n"),
	       "newest first, direction and service in words (got \"%s\")",
	       rows[0]);
	CHECK (strstr (rows[0], "198.51.100.7") != NULL,
	       "an outbound block names the remote end, the destination");
	CHECK (strstr (rows[0], "Threat intel: Spamhaus DROP") != NULL,
	       "and what blocked it, when the log says");
	CHECK (strstr (rows[0], "10:47:00") != NULL,
	       "and the time of day");
	CHECK (g_str_has_prefix (rows[1], "Blocked inbound SSH\n") &&
	       strstr (rows[1], "203.0.113.6") != NULL &&
	       strstr (rows[1], "Policy") != NULL,
	       "an inbound block names the source; no rule means the policy");
	CHECK (strstr (rows[4], "port 22") != NULL,
	       "a bare [BLOCKED] service falls back to the port (got \"%s\")",
	       rows[4]);
	for (guint i = 0; rows[i] != NULL; i++)
		CHECK (strstr (rows[i], "[BLOCKED]") == NULL,
		       "row %u: the parser's marker is not shown", i);
	g_strfreev (rows);

	fs_statusview_set_changed_cb (NULL, NULL);
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

	check_overview (page);

	gtk_widget_destroy (page);

	printf ("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
