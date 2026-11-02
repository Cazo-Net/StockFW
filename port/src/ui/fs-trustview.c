/*---[ fs-trustview.c ]--------------------------------------------------
 * The Trust page.
 *
 * Everything expensive happens on a worker thread (hashing a two
 * hundred megabyte installer on the main loop would freeze the
 * window), and the page runs one task at a time: while a task is in
 * flight the write buttons are disabled, so the store is never
 * mutated under a reader.  Attest and forget confirm first and
 * append to the audit log through the engine -- the page itself
 * never writes the baseline file directly.
 *--------------------------------------------------------------------*/

#include <string.h>

#include "ui/fs-trustview.h"
#include "ui/fs-dialogs.h"
#include "core/fs-backend.h"
#include "core/fs-i18n.h"

enum {
	COL_PATH = 0,
	COL_PUBLISHER,
	COL_DIGEST,
	COL_STATUS,
	N_COLS
};

static GtkWidget *page_widget = NULL;

static GtkWidget *path_entry = NULL;
static GtkWidget *inspect_button = NULL;
static GtkWidget *refresh_button = NULL;
static GtkWidget *scan_button = NULL;
static GtkWidget *attest_button = NULL;
static GtkWidget *forget_button = NULL;
static GtkWidget *status_label = NULL;

static GtkWidget *file_label = NULL;
static GtkWidget *publisher_label = NULL;
static GtkWidget *signature_label = NULL;
static GtkWidget *digest_label = NULL;
static GtkWidget *size_label = NULL;
static GtkWidget *mtime_label = NULL;
static GtkWidget *baseline_label = NULL;

static GtkListStore *list_store = NULL;

static FsTrustStore *trust_store = NULL;
static FsTrustAssessment *current = NULL;

/* One task at a time; 0 = idle. */
static guint busy_tasks = 0;

/*----------------------------------------------------------- helpers */

static void set_buttons (void);
static void start_refresh (void);

static GtkWidget *
dialog_parent (void)
{
	GtkWidget *toplevel = gtk_widget_get_toplevel (page_widget);

	/* Not in a window yet (the smoke test builds the page alone):
	 * a parentless dialog is honest, a GTK_WINDOW() cast on a box
	 * is a warning at best. */
	return GTK_IS_WINDOW (toplevel) ? toplevel : NULL;
}

static const gchar *
change_list_name (FsTrustChange change)
{
	switch (change) {
	case FS_TRUST_CHANGE_UNCHANGED: return "in sync";
	case FS_TRUST_CHANGE_CHANGED:   return "CHANGED";
	case FS_TRUST_CHANGE_GONE:      return "missing";
	case FS_TRUST_CHANGE_UNREADABLE:return "unreadable";
	case FS_TRUST_CHANGE_NEW:
	default:                        return "new";
	}
}

static void
set_status (const gchar *text)
{
	gtk_label_set_text (GTK_LABEL (status_label), text ? text : "");
}

/* First 16 hex characters plus an ellipsis: enough to compare two
 * rows by eye without a 64-character column. */
static gchar *
digest_short (const gchar *sha256)
{
	if (sha256 == NULL || *sha256 == '\0')
		return g_strdup ("-");

	return g_strdup_printf ("%.16s...", sha256);
}

static gchar *
format_mtime (gint64 unix_time)
{
	GDateTime *dt;
	gchar *text;

	if (unix_time <= 0)
		return g_strdup ("-");

	dt = g_date_time_new_from_unix_local (unix_time);
	if (dt == NULL)
		return g_strdup ("-");

	text = g_date_time_format (dt, "%Y-%m-%d %H:%M:%S");
	g_date_time_unref (dt);

	return text ? text : g_strdup ("-");
}

/*------------------------------------------------------ the report */

static void
show_assessment (const FsTrustAssessment *assessment)
{
	const FsTrustReport *report;
	gchar *text;

	gtk_label_set_text (GTK_LABEL (file_label),
	                    assessment->path ? assessment->path : "-");

	report = assessment->report;
	if (report == NULL) {
		gtk_label_set_text (GTK_LABEL (publisher_label), "-");
		gtk_label_set_text (GTK_LABEL (signature_label),
		                    _("File not found or unreadable"));
		gtk_label_set_text (GTK_LABEL (digest_label), "-");
		gtk_label_set_text (GTK_LABEL (size_label), "-");
		gtk_label_set_text (GTK_LABEL (mtime_label), "-");
	} else {
		gtk_label_set_text (GTK_LABEL (publisher_label),
		                    report->publisher ? report->publisher
		                                      : _("(no signer)"));
		gtk_label_set_text (GTK_LABEL (signature_label),
		                    fs_trust_sig_name (report->sig));
		gtk_label_set_text (GTK_LABEL (digest_label),
		                    report->sha256);
		text = g_format_size (report->size);
		gtk_label_set_text (GTK_LABEL (size_label), text);
		g_free (text);
		text = format_mtime (report->mtime);
		gtk_label_set_text (GTK_LABEL (mtime_label), text);
		g_free (text);
	}

	switch (assessment->change) {
	case FS_TRUST_CHANGE_NEW:
		gtk_label_set_text (GTK_LABEL (baseline_label),
		                    _("Not attested yet - this file is not "
		                      "in the baseline."));
		break;
	case FS_TRUST_CHANGE_UNCHANGED:
		gtk_label_set_text (GTK_LABEL (baseline_label),
		                    _("Matches the attested baseline."));
		break;
	case FS_TRUST_CHANGE_CHANGED:
		text = g_strdup_printf (
			_("CHANGED since attestation. The baseline has "
			  "hash %s - the file on disk no longer matches "
			  "it."),
			assessment->baseline_sha256 ?
			assessment->baseline_sha256 : "-");
		gtk_label_set_text (GTK_LABEL (baseline_label), text);
		g_free (text);
		break;
	case FS_TRUST_CHANGE_GONE:
		text = g_strdup_printf (
			_("Attested earlier, now missing. The baseline "
			  "remembers hash %s."),
			assessment->baseline_sha256 ?
			assessment->baseline_sha256 : "-");
		gtk_label_set_text (GTK_LABEL (baseline_label), text);
		g_free (text);
		break;
	case FS_TRUST_CHANGE_UNREADABLE:
	default:
		gtk_label_set_text (GTK_LABEL (baseline_label),
		                    _("The file could not be read."));
		break;
	}
}

static void
clear_report (void)
{
	gtk_label_set_text (GTK_LABEL (file_label), "-");
	gtk_label_set_text (GTK_LABEL (publisher_label), "-");
	gtk_label_set_text (GTK_LABEL (signature_label), "-");
	gtk_label_set_text (GTK_LABEL (digest_label), "-");
	gtk_label_set_text (GTK_LABEL (size_label), "-");
	gtk_label_set_text (GTK_LABEL (mtime_label), "-");
	gtk_label_set_text (GTK_LABEL (baseline_label), "-");
}

/* --------------------------------------------------- the list */

static void
rebuild_list (GPtrArray *assessments)
{
	guint i;

	gtk_list_store_clear (list_store);

	for (i = 0; i < assessments->len; i++) {
		FsTrustAssessment *assessment =
			g_ptr_array_index (assessments, i);
		const gchar *digest = assessment->report != NULL ?
		                      assessment->report->sha256 :
		                      assessment->baseline_sha256;
		const gchar *publisher = assessment->report != NULL ?
		                         assessment->report->publisher :
		                         assessment->baseline_publisher;
		GtkTreeIter iter;
		gchar *short_digest = digest_short (digest);

		gtk_list_store_append (list_store, &iter);
		gtk_list_store_set (list_store, &iter,
		                    COL_PATH, assessment->path,
		                    COL_PUBLISHER,
		                    publisher ? publisher : _("(no signer)"),
		                    COL_DIGEST, short_digest,
		                    COL_STATUS,
		                    change_list_name (assessment->change),
		                    -1);
		g_free (short_digest);
	}
}

/* -------------------------------------------------- the workers */

/* Single-file inspect: the path string is the task data (freed with
 * it), the store is read-only while the task flies. */
static void
inspect_worker (GTask *task, gpointer source_object, gpointer task_data,
                GCancellable *cancellable)
{
	const gchar *path = task_data;
	FsTrustAssessment *assessment;

	(void) source_object;
	(void) cancellable;

	assessment = fs_trust_assess (trust_store, path);
	if (assessment == NULL) {
		g_task_return_new_error (task, G_IO_ERROR,
		                         G_IO_ERROR_INVALID_ARGUMENT,
		                         "nothing to assess");
		return;
	}

	g_task_return_pointer (task, assessment,
	                       (GDestroyNotify) fs_trust_assessment_free);
}

/* List scan: task data is a GPtrArray of paths (ownership moves to
 * the task), and every one is assessed against the store. */
static void
assess_list_worker (GTask *task, gpointer source_object,
                    gpointer task_data, GCancellable *cancellable)
{
	GPtrArray *paths = task_data;
	GPtrArray *results;
	guint i;

	(void) source_object;
	(void) cancellable;

	results = g_ptr_array_new_with_free_func (
		(GDestroyNotify) fs_trust_assessment_free);

	for (i = 0; i < paths->len; i++) {
		FsTrustAssessment *assessment = fs_trust_assess (
			trust_store, g_ptr_array_index (paths, i));

		if (assessment != NULL)
			g_ptr_array_add (results, assessment);
	}

	g_task_return_pointer (task, results,
	                       (GDestroyNotify) g_ptr_array_unref);
}

static void
inspect_ready (GObject *source_object, GAsyncResult *result,
               gpointer user_data)
{
	GTask *task = G_TASK (result);
	FsTrustAssessment *assessment;
	GError *error = NULL;

	(void) source_object;
	(void) user_data;

	assessment = g_task_propagate_pointer (task, &error);
	busy_tasks--;

	if (assessment == NULL) {
		set_status (error != NULL ? error->message :
		             _("Nothing to assess."));
		g_clear_error (&error);
	} else {
		g_clear_pointer (&current, fs_trust_assessment_free);
		current = assessment;
		show_assessment (current);
		set_status (current->report != NULL ?
		            _("Report ready.") :
		            _("The file could not be read."));
	}

	set_buttons ();
}

static void
assess_list_ready (GObject *source_object, GAsyncResult *result,
                   gpointer user_data)
{
	GTask *task = G_TASK (result);
	GPtrArray *results;
	GError *error = NULL;

	(void) source_object;
	(void) user_data;

	results = g_task_propagate_pointer (task, &error);
	busy_tasks--;

	if (results == NULL) {
		set_status (error != NULL ? error->message :
		             _("The scan failed."));
		g_clear_error (&error);
	} else {
		gchar *text;

		rebuild_list (results);
		text = g_strdup_printf (_("%u entries."), results->len);
		set_status (text);
		g_free (text);
		g_ptr_array_unref (results);
	}

	set_buttons ();
}

/* ------------------------------------------------ the task starters */

static void
start_inspect (const gchar *path)
{
	GTask *task;

	if (busy_tasks > 0) {
		set_status (_("Still working - one task at a time."));
		return;
	}

	if (path == NULL || *path == '\0') {
		set_status (_("Type the path of a file to inspect."));
		return;
	}

	busy_tasks++;
	set_buttons ();
	set_status (_("Hashing and checking the signature..."));

	task = g_task_new (NULL, NULL, inspect_ready, NULL);
	g_task_set_task_data (task, g_strdup (path), g_free);
	g_task_run_in_thread (task, inspect_worker);
	g_object_unref (task);
}

static void
start_assess_paths (GPtrArray *paths)
{
	GTask *task;

	if (busy_tasks > 0) {
		set_status (_("Still working - one task at a time."));
		g_ptr_array_unref (paths);
		return;
	}

	busy_tasks++;
	set_buttons ();
	set_status (_("Assessing..."));

	task = g_task_new (NULL, NULL, assess_list_ready, NULL);
	g_task_set_task_data (task, paths,
	                      (GDestroyNotify) g_ptr_array_unref);
	g_task_run_in_thread (task, assess_list_worker);
	g_object_unref (task);
}

/* Refresh: every row of the baseline, hashed again. */
static void
start_refresh (void)
{
	GPtrArray *paths;
	guint i, count;

	if (trust_store == NULL)
		return;

	count = fs_trust_store_count (trust_store);
	paths = g_ptr_array_new_with_free_func (g_free);

	for (i = 0; i < count; i++) {
		const gchar *path = fs_trust_store_path_at (trust_store, i);

		if (path != NULL)
			g_ptr_array_add (paths, g_strdup (path));
	}

	start_assess_paths (paths);
}

/* ------------------------------------------------------- the actions */

static void
on_inspect_clicked (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;

	start_inspect (gtk_entry_get_text (GTK_ENTRY (path_entry)));
}

static void
on_refresh_clicked (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;

	if (fs_trust_store_count (trust_store) == 0) {
		set_status (_("The baseline is empty - nothing to refresh."));
		return;
	}

	start_refresh ();
}

static void
on_scan_clicked (GtkButton *button, gpointer data)
{
	const FsBackend *backend = fs_backend ();
	GList *processes, *l;
	GHashTable *seen;
	GPtrArray *paths;

	(void) button;
	(void) data;

	if (backend->list_processes == NULL) {
		set_status (_("This platform cannot list running "
		              "processes."));
		return;
	}

	processes = backend->list_processes ();
	if (processes == NULL) {
		set_status (_("The process list could not be read - "
		              "possibly access denied."));
		return;
	}

	seen = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
	                              NULL);
	paths = g_ptr_array_new_with_free_func (g_free);

	for (l = processes; l != NULL; l = l->next) {
		const gchar *path = l->data;
		gchar *key;

		if (path == NULL || *path == '\0')
			continue;

		key = g_ascii_strdown (path, -1);
		if (g_hash_table_contains (seen, key)) {
			g_free (key);
			continue;
		}
		g_hash_table_insert (seen, key, NULL);
		g_ptr_array_add (paths, g_strdup (path));
	}

	g_list_free_full (processes, g_free);
	g_hash_table_unref (seen);

	if (paths->len == 0) {
		g_ptr_array_unref (paths);
		set_status (_("No readable process paths this account can "
		              "see."));
		return;
	}

	start_assess_paths (paths);
}

static void
on_attest_clicked (GtkButton *button, gpointer data)
{
	const FsTrustReport *report;
	gchar *question;
	gboolean confirmed = FALSE;
	GError *error = NULL;

	(void) button;
	(void) data;

	if (current == NULL || current->report == NULL) {
		set_status (_("Inspect a readable file first."));
		return;
	}

	report = current->report;
	question = g_strdup_printf (
		_("Attest this file as trusted?\n\n%s\n\nSHA-256: %s\n\n"
		  "The attestation is recorded in the audit log."),
		report->path, report->sha256);

	fs_dialogs_confirm (dialog_parent (), question, &confirmed);
	g_free (question);

	if (!confirmed) {
		set_status (_("Attestation cancelled."));
		return;
	}

	if (!fs_trust_attest (trust_store, report)) {
		set_status (_("The baseline could not record the "
		              "attestation."));
		return;
	}

	if (!fs_trust_store_save (trust_store, &error)) {
		fs_dialogs_error (dialog_parent (),
		                  _("Trust baseline"),
		                  error != NULL ? error->message :
		                  _("The baseline could not be saved."));
		g_clear_error (&error);
		set_status (_("Attested in memory, but not saved to disk."));
		return;
	}

	/* These exact bytes were just attested, so the grid says so now;
	 * the refresh below confirms it by hashing the file again. */
	g_clear_pointer (&current->baseline_sha256, g_free);
	g_clear_pointer (&current->baseline_publisher, g_free);
	current->baseline_sha256 = g_strdup (report->sha256);
	current->baseline_publisher = g_strdup (report->publisher);
	current->change = FS_TRUST_CHANGE_UNCHANGED;
	show_assessment (current);

	set_status (_("Attested and recorded in the audit log."));
	start_refresh ();
}

static void
on_forget_clicked (GtkButton *button, gpointer data)
{
	const gchar *path;
	gchar *question;
	gboolean confirmed = FALSE;
	GError *error = NULL;

	(void) button;
	(void) data;

	path = gtk_entry_get_text (GTK_ENTRY (path_entry));
	if (path == NULL || *path == '\0') {
		set_status (_("Type the path to forget."));
		return;
	}

	if (fs_trust_store_count (trust_store) == 0) {
		set_status (_("The baseline is empty - nothing to forget."));
		return;
	}

	question = g_strdup_printf (
		_("Remove this file from the trust baseline?\n\n%s\n\n"
		  "The removal is recorded in the audit log."), path);

	fs_dialogs_confirm (dialog_parent (), question, &confirmed);
	g_free (question);

	if (!confirmed) {
		set_status (_("Nothing was removed."));
		return;
	}

	if (!fs_trust_remove (trust_store, path)) {
		set_status (_("That path is not in the baseline."));
		return;
	}

	if (!fs_trust_store_save (trust_store, &error)) {
		fs_dialogs_error (dialog_parent (),
		                  _("Trust baseline"),
		                  error != NULL ? error->message :
		                  _("The baseline could not be saved."));
		g_clear_error (&error);
	}

	g_clear_pointer (&current, fs_trust_assessment_free);
	clear_report ();
	set_status (_("Forgotten, and recorded in the audit log."));

	if (fs_trust_store_count (trust_store) > 0)
		start_refresh ();
	else
		gtk_list_store_clear (list_store);
}

static void
on_path_changed (GtkEditable *editable, gpointer data)
{
	(void) editable;
	(void) data;
	set_buttons ();
}

/* ------------------------------------------------------ sensitivity */

static void
set_buttons (void)
{
	gboolean idle = (busy_tasks == 0);
	const gchar *path;

	gtk_widget_set_sensitive (inspect_button, idle);
	gtk_widget_set_sensitive (refresh_button, idle);
	gtk_widget_set_sensitive (scan_button, idle);

	gtk_widget_set_sensitive (attest_button,
	                          idle && current != NULL &&
	                          current->report != NULL);

	path = gtk_entry_get_text (GTK_ENTRY (path_entry));
	gtk_widget_set_sensitive (forget_button,
	                          idle && path != NULL && *path != '\0');
}

/* --------------------------------------------------------- building */

static void
add_report_row (GtkGrid *grid, gint row, const gchar *title,
                GtkWidget **label_slot)
{
	GtkWidget *label = gtk_label_new ("-");

	gtk_widget_set_halign (label, GTK_ALIGN_START);
	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_label_set_selectable (GTK_LABEL (label), TRUE);
	gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);

	gtk_grid_attach (grid, gtk_label_new (title), 0, row, 1, 1);
	gtk_grid_attach (grid, label, 1, row, 1, 1);

	*label_slot = label;
}

static void
build_page (void)
{
	GtkWidget *top, *report_frame, *report_box, *report_grid;
	GtkWidget *write_box, *scroller, *tree;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;
	gint row = 0;

	trust_store = fs_trust_store_load (fs_trust_store_path ());

	page_widget = gtk_box_new (GTK_ORIENTATION_VERTICAL, 8);
	gtk_widget_set_margin_start (page_widget, 8);
	gtk_widget_set_margin_end (page_widget, 8);
	gtk_widget_set_margin_top (page_widget, 8);
	gtk_widget_set_margin_bottom (page_widget, 8);

	/* Row one: the path and the actions on it. */
	top = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	path_entry = gtk_entry_new ();
	/* An example path in the platform's own shape. */
#ifdef G_OS_WIN32
	gtk_entry_set_placeholder_text (GTK_ENTRY (path_entry),
	                                _("C:\\Path\\To\\program.exe"));
#else
	gtk_entry_set_placeholder_text (GTK_ENTRY (path_entry),
	                                _("/usr/bin/program"));
#endif
	gtk_widget_set_hexpand (path_entry, TRUE);

	inspect_button = gtk_button_new_with_mnemonic (_("_Inspect"));
	refresh_button = gtk_button_new_with_mnemonic (_("_Refresh list"));
	scan_button = gtk_button_new_with_mnemonic (_("Scan _processes"));

	gtk_box_pack_start (GTK_BOX (top), path_entry, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (top), inspect_button, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (top), refresh_button, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (top), scan_button, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page_widget), top, FALSE, FALSE, 0);

	status_label = gtk_label_new ("");
	gtk_widget_set_halign (status_label, GTK_ALIGN_START);
	gtk_label_set_xalign (GTK_LABEL (status_label), 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (status_label), TRUE);
	gtk_box_pack_start (GTK_BOX (page_widget), status_label, FALSE,
	                    FALSE, 0);

	/* Row two: the report on the inspected file. */
	report_frame = gtk_frame_new (_("Selected file"));
	report_box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
	gtk_widget_set_margin_start (report_box, 8);
	gtk_widget_set_margin_end (report_box, 8);
	gtk_widget_set_margin_top (report_box, 6);
	gtk_widget_set_margin_bottom (report_box, 6);

	report_grid = gtk_grid_new ();
	gtk_grid_set_column_spacing (GTK_GRID (report_grid), 12);
	gtk_grid_set_row_spacing (GTK_GRID (report_grid), 3);

	add_report_row (GTK_GRID (report_grid), row++, _("File:"),
	                &file_label);
	add_report_row (GTK_GRID (report_grid), row++, _("Publisher:"),
	                &publisher_label);
	add_report_row (GTK_GRID (report_grid), row++, _("Signature:"),
	                &signature_label);
	add_report_row (GTK_GRID (report_grid), row++, _("SHA-256:"),
	                &digest_label);
	add_report_row (GTK_GRID (report_grid), row++, _("Size:"),
	                &size_label);
	add_report_row (GTK_GRID (report_grid), row++, _("Modified:"),
	                &mtime_label);
	add_report_row (GTK_GRID (report_grid), row++, _("Baseline:"),
	                &baseline_label);

	gtk_box_pack_start (GTK_BOX (report_box), report_grid, FALSE,
	                    FALSE, 0);

	write_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	attest_button = gtk_button_new_with_mnemonic (_("_Attest"));
	forget_button = gtk_button_new_with_mnemonic (_("_Forget"));
	gtk_box_pack_start (GTK_BOX (write_box), attest_button, FALSE,
	                    FALSE, 0);
	gtk_box_pack_start (GTK_BOX (write_box), forget_button, FALSE,
	                    FALSE, 0);
	gtk_box_pack_start (GTK_BOX (report_box), write_box, FALSE, FALSE,
	                    0);

	gtk_container_add (GTK_CONTAINER (report_frame), report_box);
	gtk_box_pack_start (GTK_BOX (page_widget), report_frame, FALSE,
	                    FALSE, 0);

	/* Row three: the baseline list. */
	list_store = gtk_list_store_new (N_COLS, G_TYPE_STRING,
	                                 G_TYPE_STRING, G_TYPE_STRING,
	                                 G_TYPE_STRING);
	gtk_tree_sortable_set_sort_column_id (
		GTK_TREE_SORTABLE (list_store), COL_PATH, GTK_SORT_ASCENDING);

	tree = gtk_tree_view_new_with_model (GTK_TREE_MODEL (list_store));
	g_object_unref (list_store);   /* the view holds it now */

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes (
		_("Path"), renderer, "text", COL_PATH, NULL);
	gtk_tree_view_column_set_resizable (column, TRUE);
	gtk_tree_view_column_set_expand (column, TRUE);
	gtk_tree_view_append_column (GTK_TREE_VIEW (tree), column);

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes (
		_("Publisher"), renderer, "text", COL_PUBLISHER, NULL);
	gtk_tree_view_column_set_resizable (column, TRUE);
	gtk_tree_view_append_column (GTK_TREE_VIEW (tree), column);

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes (
		_("SHA-256"), renderer, "text", COL_DIGEST, NULL);
	gtk_tree_view_column_set_resizable (column, TRUE);
	gtk_tree_view_append_column (GTK_TREE_VIEW (tree), column);

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes (
		_("Status"), renderer, "text", COL_STATUS, NULL);
	gtk_tree_view_column_set_resizable (column, TRUE);
	gtk_tree_view_append_column (GTK_TREE_VIEW (tree), column);

	gtk_tree_view_set_search_column (GTK_TREE_VIEW (tree), COL_PATH);

	scroller = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroller),
	                                GTK_POLICY_AUTOMATIC,
	                                GTK_POLICY_AUTOMATIC);
	gtk_container_add (GTK_CONTAINER (scroller), tree);
	gtk_widget_set_vexpand (scroller, TRUE);
	gtk_box_pack_start (GTK_BOX (page_widget), scroller, TRUE, TRUE, 0);

	/* Wiring. */
	g_signal_connect (inspect_button, "clicked",
	                  G_CALLBACK (on_inspect_clicked), NULL);
	g_signal_connect (refresh_button, "clicked",
	                  G_CALLBACK (on_refresh_clicked), NULL);
	g_signal_connect (scan_button, "clicked",
	                  G_CALLBACK (on_scan_clicked), NULL);
	g_signal_connect (attest_button, "clicked",
	                  G_CALLBACK (on_attest_clicked), NULL);
	g_signal_connect (forget_button, "clicked",
	                  G_CALLBACK (on_forget_clicked), NULL);
	g_signal_connect (path_entry, "changed",
	                  G_CALLBACK (on_path_changed), NULL);
	g_signal_connect (path_entry, "activate",
	                  G_CALLBACK (on_inspect_clicked), NULL);

	clear_report ();
	set_status (_("Type a path to inspect, or scan the running "
	              "processes."));
	set_buttons ();
}

/*----------------------------------------------------------- public */

GtkWidget *
fs_trustview_page (void)
{
	if (page_widget == NULL)
		build_page ();

	return page_widget;
}

gboolean
fs_trustview_busy (void)
{
	return busy_tasks > 0;
}

const FsTrustAssessment *
fs_trustview_current (void)
{
	return current;
}

guint
fs_trustview_list_count (void)
{
	if (list_store == NULL)
		return 0;

	return (guint) gtk_tree_model_iter_n_children (
		GTK_TREE_MODEL (list_store), NULL);
}
