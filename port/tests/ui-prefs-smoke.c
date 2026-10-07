/*---[ ui-prefs-smoke.c ]--------------------------------------------------
 *
 * UI smoke test for the Preferences dialog.
 *
 * It opens the real dialog, walks the section tree one row at a time,
 * checks that each row selects the notebook page it is supposed to, and
 * finally presses Accept.  That covers the three things a unit test
 * cannot see: the pages actually build, the tree and the notebook stay
 * index-aligned, and the save path runs.
 *
 * Deliberately NOT part of StockFW.exe -- the CMake target is
 * EXCLUDE_FROM_ALL -- so no test hook is ever shipped to a user.
 *
 * The caller isolates the preference file by pointing APPDATA (Windows)
 * or XDG_CONFIG_HOME (Linux) at a scratch directory, so Accept cannot
 * disturb the user's real settings.
 *
 *----------------------------------------------------------------------*/
#include <gtk/gtk.h>

#include "core/fs-prefs.h"
#include "ui/fs-dialogs.h"

/* Timeout so a dialog that never appears fails instead of hanging. */
#define SMOKE_STEP_MS  150
#define SMOKE_MAX_RUNS 400

static guint phase = 0;
static guint runs = 0;
static gboolean failed = FALSE;

/* Every row in the tree, depth first, so the children of Interface and
 * Firewall are visited too -- iter_n_children() with a NULL parent only
 * counts the two top level rows. */
static GList *
walk_paths (GtkTreeModel *model, GtkTreeIter *parent, GList *paths)
{
	GtkTreeIter iter;
	gboolean valid;

	for (valid = gtk_tree_model_iter_children (model, &iter, parent);
	     valid;
	     valid = gtk_tree_model_iter_next (model, &iter)) {
		paths = g_list_append (paths, gtk_tree_model_get_path (model, &iter));
		paths = walk_paths (model, &iter, paths);
	}

	return paths;
}

/* [ find_widget ] depth first search for the first descendant of a type */
static GtkWidget *
find_widget (GtkWidget *root, GType type)
{
	GtkWidget *found = NULL;

	if (root == NULL)
		return NULL;

	if (G_TYPE_CHECK_INSTANCE_TYPE (root, type))
		return root;

	if (!GTK_IS_CONTAINER (root))
		return NULL;

	GList *children = gtk_container_get_children (GTK_CONTAINER (root));

	for (GList *l = children; l != NULL && found == NULL; l = l->next)
		found = find_widget (l->data, type);

	g_list_free (children);

	return found;
}

/* [ find_dialog ] the Preferences window, once it exists */
static GtkDialog *
find_dialog (void)
{
	GList *windows = gtk_window_list_toplevels ();
	GtkDialog *found = NULL;

	for (GList *l = windows; l != NULL; l = l->next) {
		GtkWindow *w = l->data;

		if (GTK_IS_DIALOG (w) &&
		    g_strcmp0 (gtk_window_get_title (w), "Preferences") == 0) {
			found = GTK_DIALOG (w);
			break;
		}
	}

	g_list_free (windows);

	return found;
}

/* [ drive_dialog ] one tick of the driver */
static gboolean
drive_dialog (gpointer data)
{
	static GList *paths = NULL;
	GtkDialog *dialog;
	GtkWidget *tree;
	GtkWidget *notebook;
	GtkTreeModel *model;
	guint rows;
	gint page;

	(void) data;

	if (++runs > SMOKE_MAX_RUNS) {
		g_printerr ("ui-prefs-smoke: FAILED, dialog never completed\n");
		failed = TRUE;
		gtk_main_quit ();
		return G_SOURCE_REMOVE;
	}

	dialog = find_dialog ();

	if (dialog == NULL)
		return G_SOURCE_CONTINUE;   /* still being built */

	tree = find_widget (GTK_WIDGET (dialog), GTK_TYPE_TREE_VIEW);
	notebook = find_widget (GTK_WIDGET (dialog), GTK_TYPE_NOTEBOOK);

	if (tree == NULL || notebook == NULL) {
		g_printerr ("ui-prefs-smoke: FAILED, %s missing\n",
		            tree == NULL ? "section tree" : "page notebook");
		failed = TRUE;
		gtk_dialog_response (dialog, GTK_RESPONSE_CANCEL);
		return G_SOURCE_REMOVE;
	}

	model = gtk_tree_view_get_model (GTK_TREE_VIEW (tree));

	/* A tree with a model but no column renders as a blank box --
	 * exactly the bug that shipped once.  The model walk below would
	 * still pass, so the column is checked separately. */
	if (gtk_tree_view_get_n_columns (GTK_TREE_VIEW (tree)) < 1) {
		g_printerr ("ui-prefs-smoke: FAILED, section tree has no "
		            "column, it would render empty\n");
		failed = TRUE;
		gtk_dialog_response (dialog, GTK_RESPONSE_CANCEL);
		return G_SOURCE_REMOVE;
	}

	{
		GList *columns = gtk_tree_view_get_columns (
			GTK_TREE_VIEW (tree));
		GList *l;
		gboolean has_text_renderer = FALSE;

		for (l = columns; l != NULL; l = l->next) {
			GList *cells = gtk_cell_layout_get_cells (
				GTK_CELL_LAYOUT (l->data));

			for (GList *c = cells; c != NULL; c = c->next) {
				if (GTK_IS_CELL_RENDERER_TEXT (c->data))
					has_text_renderer = TRUE;
			}
			g_list_free (cells);
		}
		g_list_free (columns);

		if (!has_text_renderer) {
			g_printerr ("ui-prefs-smoke: FAILED, section tree "
			            "column has no text renderer\n");
			failed = TRUE;
			gtk_dialog_response (dialog, GTK_RESPONSE_CANCEL);
			return G_SOURCE_REMOVE;
		}
	}

	if (paths == NULL)
		paths = walk_paths (model, NULL, NULL);

	rows = g_list_length (paths);

	if (phase < rows) {
		GtkTreePath *path = g_list_nth_data (paths, phase);
		GtkTreeIter iter;
		gchar *label = NULL;
		gint section = -1;

		gtk_tree_view_set_cursor (GTK_TREE_VIEW (tree), path, NULL, FALSE);

		page = gtk_notebook_get_current_page (GTK_NOTEBOOK (notebook));

		if (gtk_tree_model_get_iter (model, &iter, path))
			gtk_tree_model_get (model, &iter, 0, &section, 1, &label, -1);

		g_print ("ui-prefs-smoke: %2u %-20s section %d -> page %d %s\n",
		         phase, label ? label : "?", section, page,
		         page == section ? "ok" : "MISMATCH");

		if (page != section) {
			g_printerr ("ui-prefs-smoke: FAILED\n");
			failed = TRUE;
			gtk_dialog_response (dialog, GTK_RESPONSE_CANCEL);
			return G_SOURCE_REMOVE;
		}

		g_free (label);
		phase++;
		return G_SOURCE_CONTINUE;
	}

	if (phase == rows) {
		g_print ("ui-prefs-smoke: %u sections, all mapped correctly\n", rows);

		if (rows != 8) {
			g_printerr ("ui-prefs-smoke: FAILED, expected 8 sections, got %u\n",
			            rows);
			failed = TRUE;
			gtk_dialog_response (dialog, GTK_RESPONSE_CANCEL);
			return G_SOURCE_REMOVE;
		}

		phase++;
		return G_SOURCE_CONTINUE;
	}

	/* Everything visited: press Accept so the save path runs too. */
	g_print ("ui-prefs-smoke: pressing Accept\n");
	gtk_dialog_response (dialog, GTK_RESPONSE_OK);

	return G_SOURCE_REMOVE;
}

int
main (int argc, char **argv)
{
	gint rc;

	gtk_init (&argc, &argv);
	fs_prefs_load ();

	g_timeout_add (SMOKE_STEP_MS, drive_dialog, NULL);

	fs_dialogs_preferences (NULL);

	if (failed) {
		g_printerr ("ui-prefs-smoke: FAILED\n");
		rc = 1;
	} else {
		g_print ("ui-prefs-smoke: OK\n");
		rc = 0;
	}

	return rc;
}
