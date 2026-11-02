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

int
main (int argc, char **argv)
{
	GtkWidget *page;
	GtkWidget *entry;
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

	CHECK (g_file_get_contents (audit_file, &contents, NULL, NULL) &&
	       strstr (contents, "trust-forget") != NULL,
	       "the removal reached the audit log");
	g_clear_pointer (&contents, g_free);

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
