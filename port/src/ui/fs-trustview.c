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
#include "ui/fs-drawer.h"
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

/* [ the detail drawer ]
 * Activating a row of the list inspects that file and, when the
 * result is in, shows it in the window's drawer (ui/fs-drawer.h).
 * drawer_owner is the token this page gives the drawer; drawer_wanted
 * is set between the activation and its result.  An open drawer of
 * this page always shows `current', the same file as the "Selected
 * file" card. */
static gint     drawer_owner;
static gboolean drawer_wanted = FALSE;

static void trust_details_show (void);
static void trust_details_sync (void);

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

/* [ baseline_text ]
 * How the file compares with the baseline, as a sentence.  The card
 * and the detail drawer both say it.  g_free. */
static gchar *
baseline_text (const FsTrustAssessment *assessment)
{
	switch (assessment->change) {
	case FS_TRUST_CHANGE_NEW:
		return g_strdup (_("Not attested yet - this file is not "
		                   "in the baseline."));
	case FS_TRUST_CHANGE_UNCHANGED:
		return g_strdup (_("Matches the attested baseline."));
	case FS_TRUST_CHANGE_CHANGED:
		return g_strdup_printf (
			_("CHANGED since attestation. The baseline has "
			  "hash %s - the file on disk no longer matches "
			  "it."),
			assessment->baseline_sha256 ?
			assessment->baseline_sha256 : "-");
	case FS_TRUST_CHANGE_GONE:
		return g_strdup_printf (
			_("Attested earlier, now missing. The baseline "
			  "remembers hash %s."),
			assessment->baseline_sha256 ?
			assessment->baseline_sha256 : "-");
	case FS_TRUST_CHANGE_UNREADABLE:
	default:
		return g_strdup (_("The file could not be read."));
	}
}

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

	text = baseline_text (assessment);
	gtk_label_set_text (GTK_LABEL (baseline_label), text);
	g_free (text);
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

		/* A row was activated: its report opens in the drawer.  A
		 * drawer of this page that is already open follows every
		 * inspect, so it never shows another file than the card. */
		if (drawer_wanted || fs_drawer_owner () == &drawer_owner)
			trust_details_show ();
	}
	drawer_wanted = FALSE;

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

/* TRUE when the task was started. */
static gboolean
start_inspect (const gchar *path)
{
	GTask *task;

	if (busy_tasks > 0) {
		set_status (_("Still working - one task at a time."));
		return FALSE;
	}

	if (path == NULL || *path == '\0') {
		set_status (_("Type the path of a file to inspect."));
		return FALSE;
	}

	busy_tasks++;
	set_buttons ();
	set_status (_("Hashing and checking the signature..."));

	task = g_task_new (NULL, NULL, inspect_ready, NULL);
	g_task_set_task_data (task, g_strdup (path), g_free);
	g_task_run_in_thread (task, inspect_worker);
	g_object_unref (task);

	return TRUE;
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

/* [ attest_current ]
 * Attest: the inspected file goes into the baseline.  Shared by the
 * card's button and the detail drawer; both ask first. */
static void
attest_current (void)
{
	const FsTrustReport *report;
	gchar *question;
	gboolean confirmed = FALSE;
	GError *error = NULL;

	/* The card's button is insensitive while a task runs; the
	 * drawer's cannot be, so it is refused here. */
	if (busy_tasks > 0) {
		set_status (_("Still working - one task at a time."));
		return;
	}

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

	/* The question ran a main loop: go on only for the file it asked
	 * about. */
	if (busy_tasks > 0 || current == NULL || current->report != report) {
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
	trust_details_sync ();

	set_status (_("Attested and recorded in the audit log."));
	start_refresh ();
}

static void
on_attest_clicked (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;

	attest_current ();
}

/* [ forget_path ]
 * Forget: `given' leaves the baseline.  Shared by the card's button
 * (the path in the entry) and the detail drawer (the file it shows);
 * both ask first. */
static void
forget_path (const gchar *given)
{
	/* A copy: the entry's text and the drawer's file can both change
	 * while the question is up. */
	gchar *path = g_strdup (given);
	gchar *question;
	gboolean confirmed = FALSE;
	GError *error = NULL;

	if (busy_tasks > 0) {
		set_status (_("Still working - one task at a time."));
		g_free (path);
		return;
	}

	if (path == NULL || *path == '\0') {
		set_status (_("Type the path to forget."));
		g_free (path);
		return;
	}

	if (fs_trust_store_count (trust_store) == 0) {
		set_status (_("The baseline is empty - nothing to forget."));
		g_free (path);
		return;
	}

	question = g_strdup_printf (
		_("Remove this file from the trust baseline?\n\n%s\n\n"
		  "The removal is recorded in the audit log."), path);

	fs_dialogs_confirm (dialog_parent (), question, &confirmed);
	g_free (question);

	if (!confirmed || busy_tasks > 0) {
		set_status (_("Nothing was removed."));
		g_free (path);
		return;
	}

	if (!fs_trust_remove (trust_store, path)) {
		set_status (_("That path is not in the baseline."));
		g_free (path);
		return;
	}
	g_free (path);

	if (!fs_trust_store_save (trust_store, &error)) {
		fs_dialogs_error (dialog_parent (),
		                  _("Trust baseline"),
		                  error != NULL ? error->message :
		                  _("The baseline could not be saved."));
		g_clear_error (&error);
	}

	g_clear_pointer (&current, fs_trust_assessment_free);
	clear_report ();
	trust_details_sync ();
	set_status (_("Forgotten, and recorded in the audit log."));

	if (fs_trust_store_count (trust_store) > 0)
		start_refresh ();
	else
		gtk_list_store_clear (list_store);
}

static void
on_forget_clicked (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;

	forget_path (gtk_entry_get_text (GTK_ENTRY (path_entry)));
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

/* ------------------------------------------------- the detail drawer */

static void
on_details_attest (gpointer data)
{
	(void) data;

	attest_current ();
}

/* The drawer's Forget is for the file the drawer shows, whatever the
 * path entry holds by now. */
static void
on_details_forget (gpointer data)
{
	(void) data;

	if (current != NULL)
		forget_path (current->path);
}

/* A heading and its fields, with a gap above every heading but the
 * first. */
static void
details_group (GtkWidget *body, const gchar *heading, GtkWidget *content)
{
	GtkWidget *section = fs_drawer_section (heading);
	GList *before = gtk_container_get_children (GTK_CONTAINER (body));

	if (before != NULL)
		gtk_widget_set_margin_top (section, 10);
	g_list_free (before);

	gtk_box_pack_start (GTK_BOX (body), section, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (body), content, FALSE, FALSE, 0);
}

/* A sentence in the body: wrapped, and selectable like the field
 * values, since it can carry a fingerprint worth copying. */
static GtkWidget *
details_sentence (const gchar *text, const gchar *klass)
{
	GtkWidget *label = gtk_label_new (text);

	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
	gtk_label_set_line_wrap_mode (GTK_LABEL (label), PANGO_WRAP_WORD_CHAR);
	gtk_label_set_max_width_chars (GTK_LABEL (label), 44);
	gtk_label_set_selectable (GTK_LABEL (label), TRUE);
	gtk_widget_set_can_focus (label, FALSE);
	gtk_style_context_add_class (gtk_widget_get_style_context (label),
	                             klass);
	return label;
}

/* [ trust_details_show ]
 * Fills the drawer from `current': the same report as the "Selected
 * file" card, with the fingerprint in full, and the card's two
 * actions where they can do something. */
static void
trust_details_show (void)
{
	const FsTrustAssessment *assessment = current;
	const FsTrustReport *report;
	FsDrawerAction actions[2];
	guint n_actions = 0;
	GtkWidget *body, *fields;
	gchar *name, *folder, *text;

	if (assessment == NULL || assessment->path == NULL)
		return;
	report = assessment->report;

	body = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);

	fields = fs_drawer_fields_new ();
	fs_drawer_field (fields, _("File"), assessment->path, TRUE);
	if (report != NULL) {
		text = g_format_size (report->size);
		fs_drawer_field (fields, _("Size"), text, FALSE);
		g_free (text);
		text = format_mtime (report->mtime);
		fs_drawer_field (fields, _("Modified"), text, FALSE);
		g_free (text);
	}
	details_group (body, _("On disk"), fields);
	if (report == NULL)
		gtk_box_pack_start (GTK_BOX (body),
		                    details_sentence (
		                    	_("File not found or unreadable"),
		                    	"muted"),
		                    FALSE, FALSE, 0);

	if (report != NULL) {
		fields = fs_drawer_fields_new ();
		fs_drawer_field (fields, _("Publisher"),
		                 report->publisher ? report->publisher
		                                   : _("(no signer)"), FALSE);
		fs_drawer_field (fields, _("Signature"),
		                 fs_trust_sig_name (report->sig), FALSE);
		fs_drawer_field (fields, _("SHA-256"), report->sha256, TRUE);
		details_group (body, _("Signature and fingerprint"), fields);
	}

	text = baseline_text (assessment);
	details_group (body, _("Baseline"),
	               details_sentence (text, "fs-drawer-value"));
	g_free (text);

	/* Attest needs a file that was read; Forget one the baseline
	 * holds.  Both ask first, as the card's buttons do. */
	if (report != NULL) {
		actions[n_actions].label = _("Attest");
		actions[n_actions].klass = "btn-subtle";
		actions[n_actions].run = on_details_attest;
		actions[n_actions].data = NULL;
		n_actions++;
	}
	if (assessment->baseline_sha256 != NULL) {
		actions[n_actions].label = _("Forget");
		actions[n_actions].klass = "btn-danger";
		actions[n_actions].run = on_details_forget;
		actions[n_actions].data = NULL;
		n_actions++;
	}

	name = g_path_get_basename (assessment->path);
	folder = g_path_get_dirname (assessment->path);
	fs_drawer_open (&drawer_owner, name,
	                g_strcmp0 (folder, ".") != 0 ? folder : NULL,
	                body, actions, n_actions);
	g_free (name);
	g_free (folder);
}

/* [ trust_details_sync ]
 * After Attest or Forget changed `current': an open drawer of this
 * page says the new state, or closes when the file was forgotten. */
static void
trust_details_sync (void)
{
	if (fs_drawer_owner () != &drawer_owner)
		return;

	if (current != NULL)
		trust_details_show ();
	else
		fs_drawer_close ();
}

/* [ on_row_activated ]
 * Enter or a double click on a row of the list: inspect that file,
 * as typing its path and pressing Inspect does, and show the report
 * in the drawer when it arrives.  The keyboard focus stays in the
 * list. */
static void
on_row_activated (GtkTreeView *tree, GtkTreePath *path,
                  GtkTreeViewColumn *column, gpointer data)
{
	GtkTreeModel *model = gtk_tree_view_get_model (tree);
	GtkTreeIter iter;
	gchar *file = NULL;

	(void) column;
	(void) data;

	if (model == NULL || !gtk_tree_model_get_iter (model, &iter, path))
		return;

	gtk_tree_model_get (model, &iter, COL_PATH, &file, -1);
	if (file != NULL && *file != '\0') {
		/* Not while a task runs: the entry would then name a file
		 * the card does not show. */
		if (busy_tasks == 0)
			gtk_entry_set_text (GTK_ENTRY (path_entry), file);
		if (start_inspect (file))
			drawer_wanted = TRUE;
	}
	g_free (file);
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

	{
		GtkWidget *name = gtk_label_new (title);

		/* Field names read as quiet labels in a column of their
		 * own, flush left like the values beside them. */
		gtk_label_set_xalign (GTK_LABEL (name), 0.0);
		gtk_widget_set_valign (name, GTK_ALIGN_START);
		gtk_style_context_add_class (
			gtk_widget_get_style_context (name), "muted");
		gtk_grid_attach (grid, name, 0, row, 1, 1);
	}
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

	/* The window's page frame supplies the margins. */
	page_widget = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);

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
	gtk_style_context_add_class (
		gtk_widget_get_style_context (inspect_button), "btn-primary");
	gtk_style_context_add_class (
		gtk_widget_get_style_context (refresh_button), "btn-subtle");
	gtk_style_context_add_class (
		gtk_widget_get_style_context (scan_button), "btn-subtle");

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
	gtk_frame_set_shadow_type (GTK_FRAME (report_frame), GTK_SHADOW_NONE);
	gtk_style_context_add_class (
		gtk_widget_get_style_context (report_frame), "card-frame");
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
	gtk_style_context_add_class (
		gtk_widget_get_style_context (attest_button), "btn-subtle");
	gtk_style_context_add_class (
		gtk_widget_get_style_context (forget_button), "btn-subtle");
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
	gtk_widget_set_name (tree, "trust-list");
	gtk_widget_set_tooltip_text (tree,
		_("Press Enter or double-click a file to inspect it and "
		  "see its full report at the side."));
	g_signal_connect (tree, "row-activated",
	                  G_CALLBACK (on_row_activated), NULL);

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
	g_object_set (renderer, "family", "monospace", NULL);
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
	{
		/* The attested programs, in a card like every other list. */
		GtkWidget *card = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);

		gtk_style_context_add_class (
			gtk_widget_get_style_context (card), "card");
		gtk_style_context_add_class (
			gtk_widget_get_style_context (card), "list-card");
		gtk_box_pack_start (GTK_BOX (card), scroller, TRUE, TRUE, 0);
		gtk_box_pack_start (GTK_BOX (page_widget), card, TRUE, TRUE, 0);
	}

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
