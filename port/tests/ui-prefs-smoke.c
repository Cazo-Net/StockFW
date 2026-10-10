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
 * It also asserts the About dialog's credits are valid Pango markup:
 * GtkAboutDialog renders authors WITHOUT escaping them, so the bare
 * '&' in the creator line once made Pango fail and the raw
 * <span size=...> tags showed on screen instead of the name.
 *
 * And it checks the compiled-in light stylesheet (fs-theme-css.h):
 * the sheet must load without a GError, must still carry the palette
 * tokens the design pins down, and must not use the pseudo-class
 * names this GTK3.24 deprecates (:focused, :insensitive) -- GTK only
 * reports those at widget style resolution, where no test can see
 * them, so they are asserted absent as substrings instead.
 *
 *----------------------------------------------------------------------*/
#include <gtk/gtk.h>

#include "core/fs-prefs.h"
#include "core/fs-backend.h"
#include "core/fs-i18n.h"
#include "ui/fs-dialogs.h"
#include "fs-theme-css.h"   /* generated from src/ui/fs-theme.css */

/* Timeout so a dialog that never appears fails instead of hanging. */
#define SMOKE_STEP_MS  150
#define SMOKE_MAX_RUNS 400

static guint phase = 0;
static guint runs = 0;
static gboolean failed = FALSE;

/* The light theme ships inside the binary (fs-theme-css.h,
 * generated from src/ui/fs-theme.css at configure time).  Three
 * assertions, because GTK reports CSS problems three different ways:
 *
 *   - hard parse errors -> load_from_data() returns FALSE with a
 *     GError (demonstrated: "not-a-color" fails the load);
 *   - soft problems (deprecated pseudo-classes) only surface at
 *     widget style resolution, where no test hook can count them --
 *     so those names are asserted absent as substrings instead
 *     (demonstrated: adding ":insensitive" fails this check; it is
 *     exactly what the first themed spawn reported);
 *   - a sheet that parses fine but lost a design colour is invisible
 *     to GTK altogether -- the pinned palette tokens are asserted
 *     present (demonstrated: removing #ae0000 fails this check).
 *
 * No log handler is installed: every CSS defect class found so far
 * is either a hard load failure or one of the two substrings above. */

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

/* [ find_check_under ] depth first search for the check button whose
 * label reads as given (already translated by the caller). */
static GtkWidget *
find_check_under (GtkWidget *root, const gchar *want)
{
	GtkWidget *found = NULL;

	if (root == NULL)
		return NULL;

	if (GTK_IS_CHECK_BUTTON (root)) {
		const gchar *label = gtk_button_get_label (GTK_BUTTON (root));

		if (label != NULL && g_strcmp0 (label, want) == 0)
			return root;
	}

	if (!GTK_IS_CONTAINER (root))
		return NULL;

	GList *children = gtk_container_get_children (GTK_CONTAINER (root));

	for (GList *l = children; l != NULL && found == NULL; l = l->next)
		found = find_check_under (l->data, want);

	g_list_free (children);

	return found;
}

/* [ label_mentions ] TRUE when a label somewhere below reads as
 * containing the needle -- the disclosure-note probe. */
static gboolean
label_mentions (GtkWidget *root, const gchar *needle)
{
	gboolean found = FALSE;

	if (root == NULL)
		return FALSE;

	if (GTK_IS_LABEL (root)) {
		const gchar *text = gtk_label_get_text (GTK_LABEL (root));

		if (text != NULL && g_strrstr (text, needle) != NULL)
			return TRUE;
	}

	if (!GTK_IS_CONTAINER (root))
		return FALSE;

	GList *children = gtk_container_get_children (GTK_CONTAINER (root));

	for (GList *l = children; l != NULL && !found; l = l->next)
		found = label_mentions (l->data, needle);

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
		         page == (gint) phase ? "ok" : "MISMATCH");

		/* Row i must select notebook page i -- the invariant the
		 * sidebar's alignment rests on.  (Not "section == page":
		 * per-page FS_FWSEC_* gating makes the section enums of the
		 * offered pages non-contiguous on purpose.) */
		if (page != (gint) phase) {
			g_printerr ("ui-prefs-smoke: FAILED, sidebar row %u "
			            "selected page %d\n", phase, page);
			failed = TRUE;
			gtk_dialog_response (dialog, GTK_RESPONSE_CANCEL);
			return G_SOURCE_REMOVE;
		}

		/* WYSIWYG: a Firewall sub-page must appear exactly when the
		 * backend's fw_sections bit says it reads it.  A page offered
		 * without its bit asks the user to configure a firewall that
		 * is not listening; a bit without its page hides a real
		 * feature. */
		if (label != NULL) {
			static const struct
			{
				const gchar *label;
				guint32      bit;
			} fw_pages[] = {
				{ "Network Settings", FS_FWSEC_NETWORK },
				{ "ICMP Filtering",   FS_FWSEC_ICMP },
				{ "ToS Filtering",    FS_FWSEC_TOS },
				{ "Advanced Options", FS_FWSEC_ADVANCED }
			};

			for (guint i = 0; i < G_N_ELEMENTS (fw_pages); i++) {
				if (g_strcmp0 (label, _(fw_pages[i].label)) != 0)
					continue;

				if ((fs_backend ()->fw_sections &
				     fw_pages[i].bit) == 0) {
					g_printerr ("ui-prefs-smoke: FAILED, "
					            "\"%s\" is offered but the "
					            "backend does not read it\n",
					            fw_pages[i].label);
					failed = TRUE;
					g_free (label);
					gtk_dialog_response (dialog,
					                     GTK_RESPONSE_CANCEL);
					return G_SOURCE_REMOVE;
				}
			}
		}

		/* The tray switches are implemented (src/ui/fs-tray.c), so
		 * both must be PRESENT and SENSITIVE on the Interface page,
		 * and the page must not still carry the old note admitting
		 * the settings do nothing.  A regression to the disabled
		 * state fails here, not in review. */
		if (label != NULL &&
		    g_strcmp0 (label, _("Interface")) == 0) {
			GtkWidget *iface =
				gtk_notebook_get_nth_page (
					GTK_NOTEBOOK (notebook), page);
			static const gchar *tray_checks[] = {
				"Show a tray icon", "Minimize to the tray"
			};
			gboolean tray_ok = TRUE;

			if (iface == NULL) {
				g_printerr ("ui-prefs-smoke: FAILED, the "
				            "Interface page is not in the "
				            "notebook\n");
				failed = TRUE;
				tray_ok = FALSE;
			}

			for (guint i = 0;
			     iface != NULL && i < G_N_ELEMENTS (tray_checks);
			     i++) {
				GtkWidget *check =
					find_check_under (iface, _(tray_checks[i]));

				if (check == NULL) {
					g_printerr ("ui-prefs-smoke: FAILED, "
					            "\"%s\" is missing from the "
					            "Interface page\n",
					            tray_checks[i]);
					failed = TRUE;
					tray_ok = FALSE;
				} else if (!gtk_widget_get_sensitive (check)) {
					g_printerr ("ui-prefs-smoke: FAILED, "
					            "\"%s\" is insensitive but the "
					            "tray module implements it\n",
					            tray_checks[i]);
					failed = TRUE;
					tray_ok = FALSE;
				}
			}

			if (iface != NULL &&
			    label_mentions (iface, "not implemented")) {
				g_printerr ("ui-prefs-smoke: FAILED, the "
				            "Interface page still carries a "
				            "\"not implemented\" note\n");
				failed = TRUE;
				tray_ok = FALSE;
			}

			if (tray_ok)
				g_print ("ui-prefs-smoke: tray switches "
				         "present, live, and honestly "
				         "described\n");
		}

		/* The settings pages, as the backend's capability bits
		 * declare them.  ICMP is live wherever it is offered (both
		 * backends read it, through the plan on Windows and the
		 * script generator on Linux); the rate-limit disclosure
		 * appears exactly where the backend cannot rate-limit. */
		if (label != NULL &&
		    g_strcmp0 (label, _("ICMP Filtering")) == 0) {
			GtkWidget *icmp_page =
				gtk_notebook_get_nth_page (
					GTK_NOTEBOOK (notebook), page);
			GtkWidget *master = icmp_page != NULL
				? find_check_under (icmp_page,
				                    _("Enable ICMP filtering"))
				: NULL;

			if (master == NULL ||
			    !gtk_widget_get_sensitive (master)) {
				g_printerr ("ui-prefs-smoke: FAILED, the ICMP "
				            "master switch is missing or "
				            "insensitive on an offered page\n");
				failed = TRUE;
			} else {
				g_print ("ui-prefs-smoke: ICMP page live "
				         "(master switch sensitive)\n");
			}

			if (icmp_page != NULL) {
				gboolean wants_note =
					(fs_backend ()->fw_honors &
					 FS_FWHON_RATE_LIMIT) == 0;

				if (wants_note !=
				    label_mentions (icmp_page, "rate limits")) {
					g_printerr ("ui-prefs-smoke: FAILED, the "
					            "ICMP rate-limit disclosure "
					            "does not match "
					            "FS_FWHON_RATE_LIMIT\n");
					failed = TRUE;
				}
			}
		}

		/* Advanced Options: the blocks are live wherever the page
		 * is offered, but the rejection method is live only where
		 * the backend can actually reject -- and where it cannot
		 * (Windows drops silently) it stays disabled with an
		 * admission, never live and inert. */
		if (label != NULL &&
		    g_strcmp0 (label, _("Advanced Options")) == 0) {
			GtkWidget *adv_page =
				gtk_notebook_get_nth_page (
					GTK_NOTEBOOK (notebook), page);
			GtkWidget *reject = adv_page != NULL
				? find_check_under (adv_page,
				                    _("Reject with error packet"))
				: NULL;
			gboolean can = (fs_backend ()->fw_honors &
			                FS_FWHON_REJECT_METHOD) != 0;

			if (reject == NULL) {
				g_printerr ("ui-prefs-smoke: FAILED, the "
				            "rejection radio pair is missing\n");
				failed = TRUE;
			} else if (gtk_widget_get_sensitive (reject) != can) {
				g_printerr ("ui-prefs-smoke: FAILED, the "
				            "rejection method is %s but "
				            "FS_FWHON_REJECT_METHOD says %s\n",
				            gtk_widget_get_sensitive (reject)
					            ? "live" : "disabled",
				            can ? "live" : "disabled");
				failed = TRUE;
			} else if (!can &&
			           !label_mentions (adv_page,
			                            "drops blocked packets")) {
				g_printerr ("ui-prefs-smoke: FAILED, the "
				            "disabled rejection method carries "
				            "no admission note\n");
				failed = TRUE;
			} else {
				g_print ("ui-prefs-smoke: rejection method "
				         "honestly %s\n",
				         can ? "live"
				             : "disabled with a note");
			}

			if (adv_page != NULL) {
				static const gchar *live_checks[] = {
					"Block broadcasts from external network",
					"Block broadcasts from internal network",
					"Block traffic from reserved addresses "
					"on public interfaces"
				};
				gboolean blocks_ok = TRUE;

				for (guint i = 0;
				     i < G_N_ELEMENTS (live_checks); i++) {
					GtkWidget *check =
						find_check_under (adv_page,
						                  _(live_checks[i]));

					if (check == NULL ||
					    !gtk_widget_get_sensitive (check)) {
						g_printerr ("ui-prefs-smoke: "
						            "FAILED, \"%s\" is "
						            "missing or "
						            "insensitive on an "
						            "offered page\n",
						            live_checks[i]);
						failed = TRUE;
						blocks_ok = FALSE;
					}
				}

				if (blocks_ok)
					g_print ("ui-prefs-smoke: broadcast and "
					         "reserved-source blocks live\n");
			}
		}

		g_free (label);
		phase++;
		return G_SOURCE_CONTINUE;
	}

	if (phase == rows) {
		/* Four base pages, plus one per FS_FWSEC_* bit the backend
		 * sets: Linux offers all four sub-pages (8 sections),
		 * Windows offers ICMP Filtering and Advanced Options (6), a
		 * backend that reads no settings offers the base pages
		 * alone (4). */
		guint32 secs = fs_backend ()->fw_sections;
		guint expected = 4;

		for (guint32 bit = 1; bit != 0; bit <<= 1)
			if (secs & bit)
				expected++;

		/* Pin the shipped capability sets.  The count check above
		 * derives from the same bits the pages are gated on, so on
		 * its own it would pass no matter which bits a sabotage
		 * flipped; this anchors them to the backend's identity. */
		if (g_strcmp0 (fs_backend ()->name, "windows") == 0 &&
		    (secs != (FS_FWSEC_ICMP | FS_FWSEC_ADVANCED) ||
		     fs_backend ()->fw_honors != 0)) {
			g_printerr ("ui-prefs-smoke: FAILED, the Windows "
			            "capability set drifted "
			            "(fw_sections=0x%x fw_honors=0x%x)\n",
			            secs, fs_backend ()->fw_honors);
			failed = TRUE;
			gtk_dialog_response (dialog, GTK_RESPONSE_CANCEL);
			return G_SOURCE_REMOVE;
		}

		g_print ("ui-prefs-smoke: %u sections (fw_sections=0x%x), "
		         "all mapped correctly\n", rows, secs);

		if (rows != expected) {
			g_printerr ("ui-prefs-smoke: FAILED, expected %u "
			            "sections for fw_sections=0x%x, got %u\n",
			            expected, secs, rows);
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

	/* About credits: GtkAboutDialog parses the author strings as
	 * markup without escaping them (see fs-dialogs.c), so every
	 * string must be valid Pango markup -- and the creator line must
	 * still READ as written once parsed, neither mangled nor
	 * double-escaped.  Without g_markup_escape_text() the bare '&'
	 * fails here, which is exactly what shipped: the dialog showed
	 * the raw <span size=...> tags. */
	{
		const gchar **authors = fs_dialogs_about_authors ();
		gchar *creator = NULL;

		if (authors == NULL || authors[0] == NULL) {
			g_printerr ("ui-prefs-smoke: FAILED, no About authors\n");
			failed = TRUE;
		} else {
			for (guint i = 0; authors[i] != NULL; i++) {
				GError *error = NULL;
				gchar *plain = NULL;

				if (!pango_parse_markup (authors[i], -1, '\0',
				                          NULL, &plain, NULL,
				                          &error)) {
					g_printerr ("ui-prefs-smoke: FAILED, "
					            "about author %u \"%s\" is "
					            "not valid markup: %s\n",
					            i, authors[i],
					            error != NULL
					            ? error->message : "?");
					failed = TRUE;
				} else {
					g_print ("ui-prefs-smoke: about author "
					         "%u renders as: %s\n",
					         i, plain != NULL ? plain : "");
					if (i == 0) {
						creator = plain;
						plain = NULL;
					}
				}
				g_clear_error (&error);
				g_free (plain);
			}

			if (creator != NULL &&
			    g_strcmp0 (creator,
			               "Qusai Fethalrahman (Qusaifox2@gmail.com)"
			               " - Creator & Original Developer") != 0) {
				g_printerr ("ui-prefs-smoke: FAILED, creator "
				            "line renders as \"%s\"\n", creator);
				failed = TRUE;
			}
		}
		g_free (creator);
	}

	/* The stylesheet checks: load, pinned palette, forbidden
	 * pseudo-classes -- see the file comment for each one's teeth. */
	{
		static const gchar *const tokens[] = {
			"#f0f2f5",   /* canvas                        */
			"#f0f0f0",   /* tab band                      */
			"#ae0000",   /* accent: tab, buttons, select  */
			"#8b0000",   /* accent hover / button border  */
			"#ffebee",   /* blocked row background        */
			"#b71c1c",   /* blocked row text              */
			"#f9f9f9",   /* alternating status rows       */
		};
		static const gchar *const forbidden[] = {
			":focused",     /* GTK4 name; GTK3.24 warns "use
			                   :focus instead" at style resolve */
			":insensitive", /* ditto, use :disabled            */
		};
		GtkCssProvider *provider = gtk_css_provider_new ();
		GError *error = NULL;
		gboolean loaded;

		loaded = gtk_css_provider_load_from_data (provider,
		                                          fs_theme_css,
		                                          -1, &error);

		if (!loaded || error != NULL) {
			g_printerr ("ui-prefs-smoke: FAILED, stylesheet "
			            "did not load: %s\n",
			            error != NULL ? error->message : "?");
			failed = TRUE;
		} else {
			g_print ("ui-prefs-smoke: theme loads clean\n");
		}

		for (guint i = 0; i < G_N_ELEMENTS (tokens); i++) {
			if (g_strstr_len (fs_theme_css, -1, tokens[i]) == NULL) {
				g_printerr ("ui-prefs-smoke: FAILED, theme is "
				            "missing palette token %s\n",
				            tokens[i]);
				failed = TRUE;
			}
		}

		for (guint i = 0; i < G_N_ELEMENTS (forbidden); i++) {
			if (g_strstr_len (fs_theme_css, -1,
			                  forbidden[i]) != NULL) {
				g_printerr ("ui-prefs-smoke: FAILED, theme uses "
				            "deprecated pseudo-class %s\n",
				            forbidden[i]);
				failed = TRUE;
			}
		}

		g_clear_error (&error);
		g_object_unref (provider);
	}

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
