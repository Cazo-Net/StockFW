/* The Overview's verdict card against the verdict golden table (PR 3,
 * B3), on any platform.
 *
 * `stockfw status' prints the verdict from fs_verdict_compute (core);
 * the desktop app's Overview still computes its own in
 * ui/fs-statusview.c update_overview.  While both exist they must say
 * the same: this test builds the real Overview page against a fake
 * Linux-shaped backend (and one with no IPv6 slot, as Windows), sets
 * each state and IPv6 answer of tests/verdict-golden.h that the window
 * can be given, and checks
 *
 *   - the card's title, its sentences, the sidebar word and the level
 *     are what the golden row says, and
 *   - they are exactly what fs_verdict_compute gives for the same
 *     inputs.
 *
 * The test supplies fs_backend() itself, hence the UI sources without
 * a platform backend.  Teeth: change a sentence or a branch in either
 * copy and a row fails; see tests/README.
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-backend.h"
#include "core/fs-verdict.h"
#include "ui/fs-statusview.h"
#include "verdict-golden.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	printf ((cond) ? "ok:   " : "FAIL: ");                  \
	printf (__VA_ARGS__);                                   \
	printf ("\n");                                          \
	if (!(cond))                                            \
		failures++;                                     \
} while (0)

/* ------------------------------------------------------- fake backend */

static gboolean        fake_usable = TRUE;
static FsIpv6State     fake_v6 = FS_IPV6_FILTERED;
static const gchar    *fake_v6_detail = NULL;
static FsFirewallState fake_state = FS_FW_RUNNING;

static gboolean
fake_available (void)
{
	return fake_usable;
}

static FsFirewallState
fake_get_state (void)
{
	return fake_state;
}

static FsIpv6State
fake_ipv6_state (gchar **detail)
{
	if (detail != NULL)
		*detail = g_strdup (fake_v6_detail);
	return fake_v6;
}

static gboolean
fake_get_profile_enabled (gint profile, gboolean *enabled)
{
	(void) profile;
	(void) enabled;
	return FALSE;
}

static const FsBackend fake_linux = {
	.name                = "fake-linux",
	.display_name        = "test firewall",
	.available           = fake_available,
	.get_state           = fake_get_state,
	.get_profile_enabled = fake_get_profile_enabled,
	.ipv6_state          = fake_ipv6_state,
};

/* No IPv6 slot: every rule covers both families. */
static const FsBackend fake_no_v6 = {
	.name                = "fake-no-ipv6",
	.display_name        = "test firewall",
	.available           = fake_available,
	.get_state           = fake_get_state,
	.get_profile_enabled = fake_get_profile_enabled,
};

static const FsBackend *current = &fake_linux;

const FsBackend *
fs_backend (void)
{
	return current;
}

const gchar *
fs_error_domain (void)
{
	return "fake-linux";
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

static const gchar *
text_of (GtkWidget *page, const gchar *klass)
{
	GtkWidget *w = find_by_class (page, klass);

	return w != NULL && GTK_IS_LABEL (w) ? gtk_label_get_text (GTK_LABEL (w))
	                                     : "(none)";
}

/* The window's FsVerdict, as the core's level (same order). */
static FsVerdictLevel
core_level (FsVerdict level)
{
	switch (level) {
	case FS_VERDICT_OK:   return FS_VERDICT_LEVEL_OK;
	case FS_VERDICT_WARN: return FS_VERDICT_LEVEL_WARN;
	case FS_VERDICT_BAD:  return FS_VERDICT_LEVEL_BAD;
	default:              return FS_VERDICT_LEVEL_UNKNOWN;
	}
}

int
main (int argc, char **argv)
{
	GtkWidget *page;
	guint rows = 0;

	/* No blocklist store: the card adds no blocklist sentence. */
	g_setenv ("STOCKFW_INTEL_DIR", "/nonexistent/stockfw-verdict-smoke",
	          TRUE);
	gtk_init (&argc, &argv);

	page = fs_statusview_page ();
	gtk_widget_show_all (page);   /* as fs-app.c does */

	for (guint i = 0; i < G_N_ELEMENTS (verdict_golden); i++) {
		const VerdictGolden *row = &verdict_golden[i];
		FsVerdictInput in;
		FsVerdictResult *core;
		FsVerdict level;
		const gchar *word, *title, *body;
		gchar *why;

		if (!row->gui)
			continue;
		rows++;

		current = row->v6_known ? &fake_linux : &fake_no_v6;
		fake_usable = row->usable;
		fake_state = row->state;
		fake_v6 = row->v6;
		fake_v6_detail = row->v6_detail;
		/* The page reads IPv6 again on every state change. */
		fs_statusview_set_state (row->state);
		fs_statusview_refresh_ipv6 ();

		word = fs_statusview_verdict (&level);
		title = text_of (page, "hero-title");
		body = text_of (page, "hero-body");

		why = verdict_golden_mismatch (row, core_level (level), NULL, word,
		                               title, body);
		CHECK (why == NULL, "golden row %u (%s): the window's card %s", i,
		       row->key, why != NULL ? why : "is as the table says");
		g_free (why);

		verdict_golden_input (row, &in);
		in.display_name = current->display_name;
		core = fs_verdict_compute (&in);
		CHECK (core->level == core_level (level) &&
		       g_strcmp0 (core->word, word) == 0 &&
		       g_strcmp0 (core->title, title) == 0 &&
		       g_strcmp0 (core->body, body) == 0,
		       "golden row %u (%s): `stockfw status' says what the window "
		       "says (core \"%s\" / \"%s\", window \"%s\" / \"%s\")", i,
		       row->key, core->title, core->body, title, body);
		fs_verdict_result_free (core);
	}

	CHECK (rows >= 10, "%u golden rows were checked against the window",
	       rows);

	printf ("\n%s: %d failure(s)\n", failures == 0 ? "PASSED" : "FAILED",
	        failures);
	return failures == 0 ? 0 : 1;
}
