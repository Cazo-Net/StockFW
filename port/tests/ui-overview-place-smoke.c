/* The Overview on a Windows-shaped backend (1.0.7), on any platform.
 *
 * The real Windows backend reads the profile in force from
 * INetFwPolicy2::CurrentProfileTypes and the connected networks from
 * INetworkListManager; neither exists off Windows.  This test supplies
 * fs_backend() itself with a fake that answers the way that backend
 * does, builds the real Overview page, and checks what a user would
 * read on it:
 *
 *   - the subtitle names the network, the medium and its kind;
 *   - the profiles card marks the profile in force "In use", and only
 *     that one, through the page-wide show_all() fs-app.c does;
 *   - the verdict names the profile doing the protecting;
 *   - the profile in use switched off turns the verdict red ("This
 *     network is not protected") while the service still runs, and a
 *     secondary network's profile off turns it amber, not red;
 *   - switching the profile back on from the card clears it at once;
 *   - moving networks (home Private -> cafe Public) is picked up.
 *
 * Teeth: make update_overview ignore `unguarded' (or refresh_place not
 * show the marks) and the corresponding checks fail; see tests/README.
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-backend.h"
#include "core/fs-netplace.h"
#include "ui/fs-statusview.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	printf ((cond) ? "ok:   " : "FAIL: ");                  \
	printf (__VA_ARGS__);                                   \
	printf ("\n");                                          \
	if (!(cond))                                            \
		failures++;                                     \
} while (0)

/* ------------------------------------------------------- fake backend */

static gboolean    fake_on[FS_PROFILE_COUNT] = { TRUE, TRUE, TRUE };
static const char *fake_network = "HomeNet";
static gint        fake_category = FS_PROFILE_PRIVATE;
static gboolean    fake_hyperv = FALSE;   /* + an Unidentified network */
static guint       fake_set_calls = 0;

static gboolean
fake_available (void)
{
	return TRUE;
}

static gboolean
fake_get_profile_enabled (gint profile, gboolean *enabled)
{
	if (profile < 0 || profile >= FS_PROFILE_COUNT)
		return FALSE;
	if (enabled != NULL)
		*enabled = fake_on[profile];
	return TRUE;
}

static gboolean
fake_set_profile_enabled (gint profile, gboolean enabled, GError **error)
{
	(void) error;
	fake_on[profile] = enabled;
	fake_set_calls++;
	return TRUE;
}

/* What fs-backend-windows.c builds: the networks in NLM's order (the
 * virtual switch first, as Windows often lists it) and in_use from
 * CurrentProfileTypes. */
static FsNetworkPlace *
fake_network_place (void)
{
	FsNetworkPlace *place = fs_network_place_new ();

	if (fake_hyperv) {
		fs_network_place_add (place, "Unidentified network",
		                      FS_PROFILE_PUBLIC, "Virtual", FALSE);
		place->in_use |= FS_PROFILE_BIT (FS_PROFILE_PUBLIC);
	}
	fs_network_place_add (place, fake_network, fake_category, "Wi-Fi",
	                      TRUE);
	place->in_use |= FS_PROFILE_BIT (fake_category);
	return place;
}

static const FsBackend fake_backend = {
	.name                = "fake-windows",
	.display_name        = "Windows Defender Firewall",
	.available           = fake_available,
	.get_profile_enabled = fake_get_profile_enabled,
	.set_profile_enabled = fake_set_profile_enabled,
	.network_place       = fake_network_place,
};

const FsBackend *
fs_backend (void)
{
	return &fake_backend;
}

const gchar *
fs_error_domain (void)
{
	return "fake-windows";
}

void
fs_backend_set_context (FsPolicy *policy, FsSettings *settings)
{
	(void) policy;
	(void) settings;
}

/* ------------------------------------------------------------ helpers */

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

/* Every widget carrying klass, in tree order. */
static void
collect_by_class (GtkWidget *widget, const gchar *klass, GPtrArray *out)
{
	if (gtk_style_context_has_class (gtk_widget_get_style_context (widget),
	                                 klass))
		g_ptr_array_add (out, widget);
	if (GTK_IS_CONTAINER (widget)) {
		GList *children = gtk_container_get_children (GTK_CONTAINER (widget));

		for (GList *l = children; l != NULL; l = l->next)
			collect_by_class (GTK_WIDGET (l->data), klass, out);
		g_list_free (children);
	}
}

static const gchar *
text_of (GtkWidget *page, const gchar *klass)
{
	GtkWidget *w = find_by_class (page, klass);

	return w != NULL && GTK_IS_LABEL (w) ? gtk_label_get_text (GTK_LABEL (w))
	                                     : "(none)";
}

/* Visible here and all the way up to the page. */
static gboolean
shown (GtkWidget *widget, GtkWidget *top)
{
	for (GtkWidget *w = widget; w != NULL; w = gtk_widget_get_parent (w)) {
		if (!gtk_widget_get_visible (w))
			return FALSE;
		if (w == top)
			return TRUE;
	}
	return TRUE;
}

/* Which rows' "In use" marks show, as a string: "-P-" = Private only. */
static gchar *
marks (GtkWidget *page)
{
	GPtrArray *pills = g_ptr_array_new ();
	GString *out = g_string_new (NULL);

	collect_by_class (page, "in-use", pills);
	for (guint i = 0; i < pills->len; i++)
		g_string_append_c (out, shown (pills->pdata[i], page)
		                        ? "DPU"[i % 3] : '-');
	g_ptr_array_unref (pills);
	return g_string_free (out, FALSE);
}

/* The 5 s timer, without waiting five seconds. */
static void
poll (void)
{
	fs_statusview_set_state (fs_statusview_get_state ());
	fs_statusview_refresh ();
}

static GtkWidget *
switch_for (GtkWidget *page, gint profile)
{
	GPtrArray *rows = g_ptr_array_new ();
	GtkWidget *sw = NULL;

	collect_by_class (page, "profile-row", rows);
	if ((guint) profile < rows->len) {
		GList *kids = gtk_container_get_children (
			GTK_CONTAINER (rows->pdata[profile]));

		for (GList *l = kids; l != NULL; l = l->next)
			if (GTK_IS_SWITCH (l->data))
				sw = l->data;
		g_list_free (kids);
	}
	g_ptr_array_unref (rows);
	return sw;
}

int
main (int argc, char **argv)
{
	GtkWidget *page;
	GtkWidget *hero;
	FsVerdict level;
	gchar *m;

	gtk_init (&argc, &argv);

	page = fs_statusview_page ();
	gtk_widget_show_all (page);   /* as fs-app.c does */
	fs_statusview_set_state (FS_FW_RUNNING);
	fs_statusview_refresh ();
	hero = find_by_class (page, "hero");

	/* 1. Home, Private, everything on. */
	CHECK (strcmp (text_of (page, "page-subtitle"),
	               "This computer \xc2\xb7 HomeNet (Wi-Fi) \xc2\xb7 "
	               "Private network") == 0,
	       "subtitle names the network, the medium and its kind (got \"%s\")",
	       text_of (page, "page-subtitle"));
	m = marks (page);
	CHECK (strcmp (m, "-P-") == 0,
	       "only Private is marked In use, after show_all (got %s)", m);
	g_free (m);
	fs_statusview_verdict (&level);
	CHECK (level == FS_VERDICT_OK, "all on: the verdict is OK");
	CHECK (strstr (text_of (page, "hero-body"), "Windows Defender Firewall "
	               "is applying the Private profile.") != NULL,
	       "the verdict names the profile doing the protecting (got \"%s\")",
	       text_of (page, "hero-body"));

	/* 2. Private switched off behind the app's back (Windows Security,
	 *    Group Policy): the service still runs, this network has no
	 *    firewall. */
	fake_on[FS_PROFILE_PRIVATE] = FALSE;
	poll ();
	fs_statusview_verdict (&level);
	CHECK (level == FS_VERDICT_BAD &&
	       gtk_style_context_has_class (gtk_widget_get_style_context (hero),
	                                    "level-bad"),
	       "the profile in use off: the verdict is red");
	CHECK (strcmp (text_of (page, "hero-title"),
	               "This network is not protected") == 0,
	       "and says so (got \"%s\")", text_of (page, "hero-title"));
	CHECK (strstr (text_of (page, "hero-body"), "The Private profile of "
	               "Windows Defender Firewall is off, so traffic on HomeNet "
	               "(Wi-Fi) is not filtered.") != NULL,
	       "and why, naming the network (got \"%s\")",
	       text_of (page, "hero-body"));
	CHECK (strcmp (fs_statusview_verdict (NULL), "Not protected") == 0,
	       "the sidebar's word follows (got %s)", fs_statusview_verdict (NULL));

	/* 3. The fix is the switch on the card. */
	{
		GtkWidget *sw = switch_for (page, FS_PROFILE_PRIVATE);

		CHECK (sw != NULL && !gtk_switch_get_active (GTK_SWITCH (sw)),
		       "the Private switch shows off");
		if (sw != NULL)
			gtk_switch_set_active (GTK_SWITCH (sw), TRUE);
		fs_statusview_verdict (&level);
		CHECK (fake_set_calls == 1 && fake_on[FS_PROFILE_PRIVATE] &&
		       level == FS_VERDICT_OK,
		       "switching it on asks the backend once and the verdict "
		       "is OK at once, no poll needed (calls %u)", fake_set_calls);
	}

	/* 4. Public off, but only a virtual switch is on Public: amber. */
	fake_hyperv = TRUE;
	fake_on[FS_PROFILE_PUBLIC] = FALSE;
	poll ();
	fs_statusview_verdict (&level);
	m = marks (page);
	CHECK (strcmp (m, "-PU") == 0, "Private and Public both In use (got %s)",
	       m);
	g_free (m);
	CHECK (level == FS_VERDICT_WARN &&
	       strcmp (text_of (page, "hero-title"),
	               "Some networks are not protected") == 0,
	       "a secondary network's profile off is amber, not red (got \"%s\")",
	       text_of (page, "hero-title"));
	CHECK (strstr (text_of (page, "hero-body"), "Unidentified network "
	               "(Virtual)") != NULL &&
	       strstr (text_of (page, "hero-body"), "HomeNet") == NULL,
	       "and names the virtual switch, not the Wi-Fi (got \"%s\")",
	       text_of (page, "hero-body"));
	CHECK (strstr (text_of (page, "page-subtitle"), "HomeNet (Wi-Fi)") != NULL,
	       "the subtitle still names the internet-facing network");

	/* 5. To the cafe: Public network, Public profile off.  Red. */
	fake_hyperv = FALSE;
	fake_network = "CafeNet";
	fake_category = FS_PROFILE_PUBLIC;
	poll ();
	fs_statusview_verdict (&level);
	CHECK (strstr (text_of (page, "page-subtitle"), "CafeNet (Wi-Fi) \xc2\xb7 "
	               "Public network") != NULL,
	       "moving networks is picked up (got \"%s\")",
	       text_of (page, "page-subtitle"));
	m = marks (page);
	CHECK (strcmp (m, "--U") == 0, "now only Public is In use (got %s)", m);
	g_free (m);
	CHECK (level == FS_VERDICT_BAD, "on the cafe network with Public off: red");

	/* 6. A stopped firewall is judged on its own terms. */
	fs_statusview_set_state (FS_FW_STOPPED);
	CHECK (strcmp (text_of (page, "hero-title"),
	               "This computer is not protected") == 0,
	       "stopped: the stopped verdict, not the profile one");

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED", failures);
	return failures ? 1 : 0;
}
