/*---[ ui-trustview-smoke.c ]--------------------------------------------
 *
 * UI smoke test for the Trust page.
 *
 * Builds the page against a scratch store and audit file, then
 * drives it the way a person would: type a path, press Inspect,
 * press Attest (the confirm dialog answers itself through an idle
 * responder), change the file under the baseline's nose, inspect
 * again and expect CHANGED, press Forget, and read the engine's
 * outcomes back through the page's small accessor seam.
 *
 * 2.0.0: Enter or a double click on a row of the baseline list
 * inspects that file and opens its report in the window's detail
 * drawer (ui/fs-drawer.h), with the fingerprint in full and the
 * page's two actions.  No window hosts the drawer here; the module
 * fills its own unparented revealer, and the checks read what a user
 * would see from fs_drawer_widget ().
 *
 * Deliberately NOT part of StockFW.exe -- the CMake target is
 * EXCLUDE_FROM_ALL -- so no test hook is ever shipped to a user.
 *
 * The store path and the audit file are both pointed at a scratch
 * directory before the page is built (the page loads its store once,
 * at construction), so attest and forget cannot touch a real
 * baseline.
 *
 *----------------------------------------------------------------------*/
#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-trust.h"
#include "ui/fs-trustview.h"
#include "ui/fs-drawer.h"

#define CHECK(cond, ...) do {                                   \
	if (!(cond)) {                                             \
		printf ("FAIL: ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
		failures++;                                         \
	} else {                                                  \
		printf ("ok:   ");                                 \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
	}                                                         \
} while (0)

static int failures = 0;

/* The same bytes test-core.sh hashes: the digest was computed by
 * `sha256sum', not by the code under test. */
static const gchar PAYLOAD_TEXT[] =
	"StockFW trust engine test payload\n";
static const gchar PAYLOAD_SHA[] =
	"7de4fddf8f5fdd52ac594d71ace412adf55291e66b38c18e42c046fd27240d4c";

/* One-shot: the next confirm dialog to appear answers OK. */
static gboolean auto_confirm = FALSE;

static gboolean
confirm_responder (gpointer data)
{
	GList *windows;

	(void) data;

	if (!auto_confirm)
		return G_SOURCE_CONTINUE;

	for (windows = gtk_window_list_toplevels (); windows != NULL;
	     windows = windows->next) {
		if (!GTK_IS_DIALOG (windows->data))
			continue;

		auto_confirm = FALSE;
		gtk_dialog_response (GTK_DIALOG (windows->data),
		                     GTK_RESPONSE_OK);
		break;
	}
	g_list_free (windows);

	return G_SOURCE_CONTINUE;
}

/* How long a task may take before the page counts as wedged, in wall
 * time.  Generous on purpose: the process scan hashes and checks the
 * signature of every distinct image running, and on a cold Windows
 * runner (Defender reading each file for the first time) that took
 * longer than the old cap, which was 5000 turns of a 2 ms sleep --
 * 10 s, or whatever Windows' 15.6 ms timer made of it. */
#define SETTLE_SECONDS 300

static gboolean
wake_up (gpointer data)
{
	(void) data;
	return G_SOURCE_CONTINUE;
}

/* Run the main loop until the page's worker task has reported back
 * (its completion is an event on this loop, so the loop blocks until
 * it comes, no polling sleep), or until the deadline says the page
 * wedged.  Says how long it took, so a slow runner shows in the log. */
static gboolean
pump_until_idle (void)
{
	gint64 start = g_get_monotonic_time ();
	gint64 deadline = start + (gint64) SETTLE_SECONDS * G_USEC_PER_SEC;
	/* Bounds each blocking turn, so the deadline is looked at. */
	guint tick = g_timeout_add (250, wake_up, NULL);
	gboolean settled;

	while (fs_trustview_busy () && g_get_monotonic_time () < deadline)
		g_main_context_iteration (NULL, TRUE);
	while (gtk_events_pending ())
		gtk_main_iteration ();
	g_source_remove (tick);

	settled = !fs_trustview_busy ();
	printf ("       (%s after %.1f s)\n",
	        settled ? "settled" : "still busy",
	        (g_get_monotonic_time () - start) / (gdouble) G_USEC_PER_SEC);
	return settled;
}

static GtkWidget *
find_entry (GtkWidget *root)
{
	GtkWidget *found = NULL;
	GList *children, *l;

	if (GTK_IS_ENTRY (root))
		return root;
	if (!GTK_IS_CONTAINER (root))
		return NULL;

	children = gtk_container_get_children (GTK_CONTAINER (root));
	for (l = children; l != NULL && found == NULL; l = l->next)
		found = find_entry (l->data);
	g_list_free (children);

	return found;
}

static GtkWidget *
find_button (GtkWidget *root, const gchar *label)
{
	GtkWidget *found = NULL;
	GList *children, *l;

	if (GTK_IS_BUTTON (root)) {
		const gchar *text = gtk_button_get_label (
			GTK_BUTTON (root));

		if (g_strcmp0 (text, label) == 0)
			return root;
	}
	if (!GTK_IS_CONTAINER (root))
		return NULL;

	children = gtk_container_get_children (GTK_CONTAINER (root));
	for (l = children; l != NULL && found == NULL; l = l->next)
		found = find_button (l->data, label);
	g_list_free (children);

	return found;
}

/* ---- the detail drawer ---------------------------------------------- */

static GtkWidget *
find_named (GtkWidget *root, const gchar *name)
{
	GtkWidget *found = NULL;
	GList *children, *l;

	if (g_strcmp0 (gtk_widget_get_name (root), name) == 0)
		return root;
	if (!GTK_IS_CONTAINER (root))
		return NULL;

	children = gtk_container_get_children (GTK_CONTAINER (root));
	for (l = children; l != NULL && found == NULL; l = l->next)
		found = find_named (l->data, name);
	g_list_free (children);

	return found;
}

static GtkWidget *
find_tree (GtkWidget *root)
{
	GtkWidget *found = NULL;
	GList *children, *l;

	if (GTK_IS_TREE_VIEW (root))
		return root;
	if (!GTK_IS_CONTAINER (root))
		return NULL;

	children = gtk_container_get_children (GTK_CONTAINER (root));
	for (l = children; l != NULL && found == NULL; l = l->next)
		found = find_tree (l->data);
	g_list_free (children);

	return found;
}

/* A label of the drawer's head, by widget name; NULL while hidden. */
static const gchar *
drawer_text (const gchar *name)
{
	GtkWidget *w = find_named (fs_drawer_widget (), name);

	return w != NULL && GTK_IS_LABEL (w) && gtk_widget_get_visible (w)
		? gtk_label_get_text (GTK_LABEL (w)) : NULL;
}

/* The value beside the field called `name' in a grid of name / value
 * rows somewhere under `root'. */
static const gchar *
field_under (GtkWidget *root, const gchar *name)
{
	const gchar *found = NULL;
	GList *children, *l;

	if (GTK_IS_GRID (root)) {
		gint row;

		for (row = 0; ; row++) {
			GtkWidget *n = gtk_grid_get_child_at (GTK_GRID (root), 0, row);
			GtkWidget *v = gtk_grid_get_child_at (GTK_GRID (root), 1, row);

			if (n == NULL || v == NULL)
				return NULL;
			if (GTK_IS_LABEL (n) && GTK_IS_LABEL (v) &&
			    g_strcmp0 (gtk_label_get_text (GTK_LABEL (n)), name) == 0)
				return gtk_label_get_text (GTK_LABEL (v));
		}
	}
	if (!GTK_IS_CONTAINER (root))
		return NULL;

	children = gtk_container_get_children (GTK_CONTAINER (root));
	for (l = children; l != NULL && found == NULL; l = l->next)
		found = field_under (l->data, name);
	g_list_free (children);

	return found;
}

static const gchar *
drawer_field (const gchar *name)
{
	GtkWidget *body = find_named (fs_drawer_widget (), "fs-drawer-body");

	return body != NULL ? field_under (body, name) : NULL;
}

static gboolean
says_under (GtkWidget *root, const gchar *needle)
{
	gboolean found = FALSE;
	GList *children, *l;

	if (GTK_IS_LABEL (root))
		return strstr (gtk_label_get_text (GTK_LABEL (root)),
		               needle) != NULL;
	if (!GTK_IS_CONTAINER (root))
		return FALSE;

	children = gtk_container_get_children (GTK_CONTAINER (root));
	for (l = children; l != NULL && !found; l = l->next)
		found = says_under (l->data, needle);
	g_list_free (children);

	return found;
}

/* TRUE when a label in the drawer's body contains `needle'. */
static gboolean
drawer_says (const gchar *needle)
{
	GtkWidget *body = find_named (fs_drawer_widget (), "fs-drawer-body");

	return body != NULL && says_under (body, needle);
}

/* The drawer's action button with this label, or NULL. */
static GtkWidget *
drawer_button (const gchar *label)
{
	GtkWidget *foot = find_named (fs_drawer_widget (), "fs-drawer-actions");

	return foot != NULL && gtk_widget_get_visible (foot)
		? find_button (foot, label) : NULL;
}

/* Enter or a double click on row `n' of the list. */
static void
activate_row (GtkWidget *tree, gint n)
{
	GtkTreePath *path = gtk_tree_path_new_from_indices (n, -1);

	gtk_tree_view_set_cursor (GTK_TREE_VIEW (tree), path, NULL, FALSE);
	gtk_tree_view_row_activated (
		GTK_TREE_VIEW (tree), path,
		gtk_tree_view_get_column (GTK_TREE_VIEW (tree), 0));
	gtk_tree_path_free (path);
}

int
main (int argc, char **argv)
{
	GtkWidget *page;
	GtkWidget *entry;
	GtkWidget *tree;
	GtkWidget *inspect, *refresh, *scan, *attest, *forget;
	gchar *dir, *payload, *store_file, *audit_file;
	gchar *contents = NULL;

	gtk_init (&argc, &argv);

	dir = g_build_filename (g_get_tmp_dir (), "stockfw-trustview-smoke",
	                        NULL);
	payload = g_build_filename (dir, "payload.txt", NULL);
	store_file = g_build_filename (dir, "trust.csv", NULL);
	audit_file = g_build_filename (dir, "audit.log", NULL);

	g_mkdir_with_parents (dir, 0700);
	remove (payload);
	remove (store_file);
	remove (audit_file);
	g_setenv ("STOCKFW_TRUST_FILE", store_file, TRUE);
	g_setenv ("STOCKFW_AUDIT_FILE", audit_file, TRUE);
	g_file_set_contents (payload, PAYLOAD_TEXT,
	                     (gssize) strlen (PAYLOAD_TEXT), NULL);

	page = fs_trustview_page ();
	gtk_widget_show_all (page);

	/* What fs-app.c does when the page is added to the window. */
	entry = find_entry (page);
	inspect = find_button (page, "_Inspect");
	refresh = find_button (page, "_Refresh list");
	scan = find_button (page, "Scan _processes");
	attest = find_button (page, "_Attest");
	forget = find_button (page, "_Forget");
	tree = find_tree (page);

	CHECK (entry != NULL, "the page builds a path entry");
	CHECK (inspect != NULL && refresh != NULL && scan != NULL &&
	       attest != NULL && forget != NULL,
	       "the page builds Inspect, Refresh, Scan, Attest and "
	       "Forget");

	/* A timeout, deliberately: a self-requeueing idle source keeps
	 * gtk_events_pending() permanently TRUE and would spin the
	 * pump loop forever on the helper itself (demonstrated). */
	g_timeout_add (50, confirm_responder, NULL);

	/* --- inspect a never-seen file: NEW, with a real digest. */
	gtk_entry_set_text (GTK_ENTRY (entry), payload);
	gtk_button_clicked (GTK_BUTTON (inspect));
	CHECK (pump_until_idle (), "the inspect task settles");

	CHECK (fs_trustview_current () != NULL &&
	       fs_trustview_current ()->report != NULL &&
	       g_strcmp0 (fs_trustview_current ()->report->sha256,
	                  PAYLOAD_SHA) == 0,
	       "the report shows the file's own SHA-256");
	CHECK (fs_trustview_current () != NULL &&
	       fs_trustview_current ()->report != NULL &&
	       fs_trustview_current ()->report->sig ==
	       FS_TRUST_SIG_NOT_APPLICABLE,
	       "a text payload is reported as not an executable");
	CHECK (fs_trustview_current () != NULL &&
	       fs_trustview_current ()->change == FS_TRUST_CHANGE_NEW,
	       "a never-attested file reads as new");
	CHECK (fs_trustview_list_count () == 0,
	       "the baseline list is empty before any attestation");
	CHECK (!fs_drawer_is_open (),
	       "Inspect alone does not open the detail drawer");

	/* --- attest: the confirm dialog answers itself. */
	auto_confirm = TRUE;
	gtk_button_clicked (GTK_BUTTON (attest));
	CHECK (pump_until_idle (), "the attestation's refresh settles");
	CHECK (!auto_confirm, "the confirm dialog appeared and was "
	       "answered");

	CHECK (fs_trustview_current () != NULL &&
	       fs_trustview_current ()->change ==
	       FS_TRUST_CHANGE_UNCHANGED,
	       "right after attesting, the file matches its baseline");
	CHECK (fs_trustview_list_count () == 1,
	       "the attested row reaches the baseline list");

	/* --- the detail drawer: Enter or a double click on the row
	 * inspects the file, and the report opens when it arrives. */
	CHECK (tree != NULL, "the page builds the baseline list");
	gtk_entry_set_text (GTK_ENTRY (entry), "");
	activate_row (tree, 0);
	CHECK (fs_trustview_busy () && !fs_drawer_is_open (),
	       "activating a row starts an inspection; the drawer waits for "
	       "its result");
	CHECK (pump_until_idle (), "the activated row's inspection settles");
	CHECK (g_strcmp0 (gtk_entry_get_text (GTK_ENTRY (entry)), payload) == 0,
	       "the row's path is in the entry, as if typed and inspected");
	CHECK (fs_drawer_is_open (),
	       "the drawer opens once the file has been inspected");
	CHECK (g_strcmp0 (drawer_text ("fs-drawer-title"), "payload.txt") == 0 &&
	       g_strcmp0 (drawer_text ("fs-drawer-subtitle"), dir) == 0,
	       "titled with the file's name, its folder under it (\"%s\")",
	       drawer_text ("fs-drawer-title"));
	CHECK (g_strcmp0 (drawer_field ("File"), payload) == 0,
	       "File is the full path");
	CHECK (drawer_field ("SHA-256") != NULL &&
	       strlen (drawer_field ("SHA-256")) == 64 &&
	       g_strcmp0 (drawer_field ("SHA-256"), PAYLOAD_SHA) == 0,
	       "SHA-256 is the whole digest, not the list's first 16 "
	       "characters");
	CHECK (drawer_field ("Publisher") != NULL &&
	       drawer_field ("Signature") != NULL &&
	       drawer_field ("Size") != NULL &&
	       drawer_field ("Modified") != NULL,
	       "publisher, signature, size and last change are there too");
	CHECK (drawer_says ("Matches the attested baseline."),
	       "and the baseline sentence the card shows");
	CHECK (drawer_button ("Attest") != NULL &&
	       drawer_button ("Forget") != NULL,
	       "the drawer offers Attest and Forget");
	CHECK (find_button (page, "_Attest") == attest &&
	       find_button (page, "_Forget") == forget,
	       "the card keeps its own Attest and Forget");

	CHECK (g_file_get_contents (audit_file, &contents, NULL, NULL) &&
	       strstr (contents, "trust-attest") != NULL &&
	       strstr (contents, PAYLOAD_SHA) != NULL,
	       "the attestation reached the audit log with its hash");
	g_clear_pointer (&contents, g_free);

	/* --- change the bytes under the baseline's nose. */
	g_file_set_contents (payload,
	                     "StockFW trust engine test payload, edited\n",
	                     -1, NULL);
	gtk_button_clicked (GTK_BUTTON (inspect));
	CHECK (pump_until_idle (), "the re-inspect task settles");

	CHECK (fs_trustview_current () != NULL &&
	       fs_trustview_current ()->change ==
	       FS_TRUST_CHANGE_CHANGED,
	       "an edited file reads as CHANGED on the page");
	CHECK (fs_trustview_current () != NULL &&
	       fs_trustview_current ()->baseline_sha256 != NULL &&
	       g_strcmp0 (fs_trustview_current ()->baseline_sha256,
	                  PAYLOAD_SHA) == 0,
	       "the page still knows what was attested");

	/* The open drawer shows the same file as the card, always. */
	CHECK (fs_drawer_is_open () &&
	       drawer_says ("CHANGED since attestation") &&
	       drawer_field ("SHA-256") != NULL &&
	       g_strcmp0 (drawer_field ("SHA-256"), PAYLOAD_SHA) != 0,
	       "the open drawer follows the new inspection: CHANGED, with "
	       "the new digest");

	/* --- the drawer's Attest is the card's: it asks, attests and
	 * writes the audit line. */
	auto_confirm = TRUE;
	if (drawer_button ("Attest") != NULL)
		gtk_button_clicked (GTK_BUTTON (drawer_button ("Attest")));
	CHECK (pump_until_idle (), "the drawer's attestation settles");
	CHECK (!auto_confirm,
	       "the drawer's Attest asked in the confirm dialog first");
	CHECK (fs_trustview_current () != NULL &&
	       fs_trustview_current ()->change == FS_TRUST_CHANGE_UNCHANGED &&
	       fs_drawer_is_open () &&
	       drawer_says ("Matches the attested baseline."),
	       "attested from the drawer, and the drawer says so");
	CHECK (g_file_get_contents (audit_file, &contents, NULL, NULL) &&
	       strstr (contents, "trust-attest") != NULL &&
	       strstr (strstr (contents, "trust-attest") + 1,
	               "trust-attest") != NULL,
	       "the second attestation reached the audit log too");
	g_clear_pointer (&contents, g_free);

	/* --- refresh re-lists the baseline from disk. */
	gtk_button_clicked (GTK_BUTTON (refresh));
	CHECK (pump_until_idle (), "the refresh task settles");
	CHECK (fs_trustview_list_count () == 1,
	       "the baseline row survives the refresh");

	/* --- forget: confirmed, audited, gone. */
	auto_confirm = TRUE;
	gtk_button_clicked (GTK_BUTTON (forget));
	CHECK (pump_until_idle (), "the forget settles");
	CHECK (!auto_confirm, "the forget confirm dialog was answered");
	CHECK (fs_trustview_list_count () == 0,
	       "the forgotten row leaves the list");
	CHECK (fs_trustview_current () == NULL,
	       "forgetting clears the report");
	CHECK (!fs_drawer_is_open (),
	       "and closes the drawer that showed the file");

	CHECK (g_file_get_contents (audit_file, &contents, NULL, NULL) &&
	       strstr (contents, "trust-forget") != NULL,
	       "the removal reached the audit log");
	g_clear_pointer (&contents, g_free);

	/* --- the drawer's Forget is the card's too: attest once more,
	 * open the row, and forget it from the drawer. */
	gtk_entry_set_text (GTK_ENTRY (entry), payload);
	gtk_button_clicked (GTK_BUTTON (inspect));
	CHECK (pump_until_idle () && !fs_drawer_is_open (),
	       "a closed drawer stays closed through an inspection");
	auto_confirm = TRUE;
	gtk_button_clicked (GTK_BUTTON (attest));
	CHECK (pump_until_idle () && !auto_confirm &&
	       fs_trustview_list_count () == 1,
	       "the file is attested again");
	gtk_entry_set_text (GTK_ENTRY (entry), "/somewhere/else");
	activate_row (tree, 0);
	CHECK (pump_until_idle () && fs_drawer_is_open (),
	       "its row opens in the drawer again");
	gtk_entry_set_text (GTK_ENTRY (entry), "/typed/since");
	auto_confirm = TRUE;
	if (drawer_button ("Forget") != NULL)
		gtk_button_clicked (GTK_BUTTON (drawer_button ("Forget")));
	CHECK (pump_until_idle () && !auto_confirm,
	       "the drawer's Forget asked in the confirm dialog first");
	CHECK (fs_trustview_list_count () == 0 &&
	       fs_trustview_current () == NULL && !fs_drawer_is_open (),
	       "the drawer's file is forgotten, whatever the entry held, and "
	       "the drawer closes");
	CHECK (g_file_get_contents (audit_file, &contents, NULL, NULL) &&
	       strstr (contents, "trust-forget") != NULL &&
	       strstr (strstr (contents, "trust-forget") + 1,
	               "trust-forget") != NULL,
	       "that removal reached the audit log as well");
	g_clear_pointer (&contents, g_free);

	/* --- a report that arrives after the user has left the page must
	 * not open the drawer over the page they went to.  The window's
	 * notebook is what takes a page off show, so the page goes into
	 * one here, beside a stand-in for another page.  The switch comes
	 * before the main loop has turned once, so before the result. */
	{
		GtkWidget *book = gtk_notebook_new ();
		GtkWidget *other = gtk_label_new ("another page");

		g_object_ref_sink (book);
		gtk_notebook_append_page (GTK_NOTEBOOK (book), page, NULL);
		gtk_notebook_append_page (GTK_NOTEBOOK (book), other, NULL);
		gtk_widget_show_all (book);

		gtk_entry_set_text (GTK_ENTRY (entry), payload);
		gtk_button_clicked (GTK_BUTTON (inspect));
		pump_until_idle ();
		auto_confirm = TRUE;
		gtk_button_clicked (GTK_BUTTON (attest));
		CHECK (pump_until_idle () && !auto_confirm &&
		       fs_trustview_list_count () == 1 && !fs_drawer_is_open (),
		       "in a notebook now, the file is attested once more");

		gtk_entry_set_text (GTK_ENTRY (entry), "");
		activate_row (tree, 0);
		gtk_notebook_set_current_page (GTK_NOTEBOOK (book), 1);
		CHECK (fs_trustview_busy () &&
		       gtk_notebook_get_current_page (GTK_NOTEBOOK (book)) == 1,
		       "a row is activated and the page left before its report "
		       "is in");
		CHECK (pump_until_idle () && !fs_drawer_is_open (),
		       "the report that arrives then does not open the drawer "
		       "over the other page");
		CHECK (fs_trustview_current () != NULL &&
		       g_strcmp0 (fs_trustview_current ()->path, payload) == 0,
		       "the page's own card has it all the same");

		gtk_notebook_set_current_page (GTK_NOTEBOOK (book), 0);
		gtk_button_clicked (GTK_BUTTON (inspect));
		CHECK (pump_until_idle () && !fs_drawer_is_open (),
		       "back on the page, the request is not left over for the "
		       "next inspection");
		activate_row (tree, 0);
		CHECK (pump_until_idle () && fs_drawer_is_open () &&
		       g_strcmp0 (drawer_field ("File"), payload) == 0,
		       "and a row opens in the drawer as before");

		/* As it was found: nothing attested, the drawer closed. */
		auto_confirm = TRUE;
		if (drawer_button ("Forget") != NULL)
			gtk_button_clicked (GTK_BUTTON (drawer_button ("Forget")));
		CHECK (pump_until_idle () && !auto_confirm &&
		       fs_trustview_list_count () == 0 && !fs_drawer_is_open (),
		       "the file is forgotten again");
	}

	/* --- inspect something that is not there. */
	gtk_entry_set_text (GTK_ENTRY (entry),
	                    "Z:\\definitely\\not\\here.exe");
	gtk_button_clicked (GTK_BUTTON (inspect));
	CHECK (pump_until_idle (), "the missing-file inspect settles");
	CHECK (fs_trustview_current () != NULL &&
	       fs_trustview_current ()->report == NULL &&
	       fs_trustview_current ()->change ==
	       FS_TRUST_CHANGE_UNREADABLE,
	       "a missing file says so instead of showing a report");

#ifdef G_OS_WIN32
	/* --- scan the running processes: the smoke's own image is in
	 * there and readable, so the list cannot come back empty. */
	gtk_button_clicked (GTK_BUTTON (scan));
	CHECK (pump_until_idle (), "the process scan settles");
	CHECK (fs_trustview_list_count () >= 1,
	       "the scan finds at least this process (%u images)",
	       fs_trustview_list_count ());
#endif

	g_unsetenv ("STOCKFW_TRUST_FILE");
	g_unsetenv ("STOCKFW_AUDIT_FILE");
	remove (payload);
	remove (store_file);
	remove (audit_file);
	g_free (payload);
	g_free (store_file);
	g_free (audit_file);
	g_free (dir);

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);

	return failures ? 1 : 0;
}
