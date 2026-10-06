/*---[ fs-app.c ]-------------------------------------------------------
 * Application object and main window.
 *
 * Replaces gnome_app_new()/gnome_app_set_contents()/gnome_app_set_menus()
 * and the gnome_program_init()/gnome_master_client() startup dance in
 * the original firestarter.c with a plain GtkApplication.
 *--------------------------------------------------------------------*/

#include "ui/fs-app.h"
#include "ui/fs-dialogs.h"
#include "ui/fs-statusview.h"
#include "ui/fs-policyview.h"
#include "ui/fs-hitview.h"
#include "ui/fs-copilot.h"
#include "core/fs-backend.h"
#include "core/fs-prefs.h"
#include "core/fs-rules.h"
#include "core/fs-script.h"
#include "core/fs-copilot.h"
#include "core/fs-i18n.h"
#include "stockfw-logo-64.h"

#include <gdk-pixbuf/gdk-pixbuf.h>

static FsApp fsapp = { NULL, NULL, NULL };

/* Holds one toolbar row per notebook page; only the selected page's
 * row is visible at a time. */
static GtkWidget *toolbar_host = NULL;

/* The traffic policy, shared by the Policy page and Apply. */
static FsPolicy *policy = NULL;

/* Interface and NAT choices, handed to the rule generator. */
static FsSettings *settings = NULL;

/* Smart Firewall Copilot instance. */
FsCopilot *copilot = NULL;

static void
on_delete_event (GtkWidget *widget, GdkEvent *event, gpointer data)
{
	fs_app_quit ();
	gdk_event_free (event);
}

/* [ build_menubar ]
 * GtkApplication takes a GMenuModel, not a GtkMenuBar.  The action names
 * must match the ones registered below. */
static GMenuModel *
build_menubar (void)
{
	GMenu *bar = g_menu_new ();
	GMenu *menu, *section;

	/* File */
	menu = g_menu_new ();
	section = g_menu_new ();
	g_menu_append (section, _("_Preferences"), "app.preferences");
	g_menu_append (section, _("_Quit"), "app.quit");
	g_menu_append_section (menu, NULL, G_MENU_MODEL (section));
	g_object_unref (section);
	g_menu_append_submenu (bar, _("_File"), G_MENU_MODEL (menu));
	g_object_unref (menu);

	/* Help */
	menu = g_menu_new ();
	section = g_menu_new ();
	g_menu_append (section, _("_About"), "app.about");
	g_menu_append_section (menu, NULL, G_MENU_MODEL (section));
	g_object_unref (section);
	g_menu_append_submenu (bar, _("_Help"), G_MENU_MODEL (menu));
	g_object_unref (menu);

	return G_MENU_MODEL (bar);
}

/* [ on_action_quit ]
 * "app.quit" */
static void
on_action_quit (GSimpleAction *action, GVariant *parameter, gpointer data)
{
	fs_app_quit ();
}

/* [ on_action_about ]
 * "app.about" */
static void
on_action_about (GSimpleAction *action, GVariant *parameter, gpointer data)
{
	fs_dialogs_about (fsapp.window);
}

/* [ on_action_preferences ]
 * "app.preferences" */
static void
on_action_preferences (GSimpleAction *action, GVariant *parameter, gpointer data)
{
	fs_dialogs_preferences (fsapp.window);
}

/* [ register_actions ] */
static void
register_actions (void)
{
	GSimpleAction *quit, *about, *preferences;

	quit = g_simple_action_new ("quit", NULL);
	g_signal_connect (quit, "activate", G_CALLBACK (on_action_quit), NULL);
	g_action_map_add_action (G_ACTION_MAP (fsapp.app), G_ACTION (quit));
	g_object_unref (quit);

	about = g_simple_action_new ("about", NULL);
	g_signal_connect (about, "activate", G_CALLBACK (on_action_about), NULL);
	g_action_map_add_action (G_ACTION_MAP (fsapp.app), G_ACTION (about));
	g_object_unref (about);

	preferences = g_simple_action_new ("preferences", NULL);
	g_signal_connect (preferences, "activate", G_CALLBACK (on_action_preferences), NULL);
	g_action_map_add_action (G_ACTION_MAP (fsapp.app), G_ACTION (preferences));
	g_object_unref (preferences);
}

/* [ add_page ]
 * Appends a notebook page and pairs it with a row in the toolbar strip
 * above the notebook.  Every page contributes a row -- even an empty
 * one -- so the strip and the notebook stay index-aligned. */
static void
add_page (const gchar *title, GtkWidget *content, GtkWidget *toolbar)
{
	GtkWidget *label = gtk_label_new (title);

	gtk_widget_show_all (content);
	gtk_notebook_append_page (GTK_NOTEBOOK (fsapp.notebook), content, label);

	if (toolbar == NULL)
		toolbar = gtk_toolbar_new ();

	gtk_box_pack_start (GTK_BOX (toolbar_host), toolbar, FALSE, FALSE, 0);
	gtk_widget_set_no_show_all (toolbar, TRUE);
	gtk_widget_hide (toolbar);
}

/* [ on_page_switched ]
 * Show only the toolbar row that belongs to the selected page. */
static void
on_page_switched (GtkNotebook *notebook, GtkWidget *page, guint page_num,
                  gpointer data)
{
	GList *children;
	guint i = 0;

	(void) notebook;
	(void) page;
	(void) data;

	children = gtk_container_get_children (GTK_CONTAINER (toolbar_host));

	for (GList *l = children; l != NULL; l = l->next, i++) {
		if (i == page_num)
			gtk_widget_show (l->data);
		else
			gtk_widget_hide (l->data);
	}

	g_list_free (children);
}

void
fs_app_activate (GtkApplication *app)
{
	GtkWidget *box;

	fsapp.app = GTK_APPLICATION (app);

	/* Window */
	fsapp.window = gtk_application_window_new (app);
	gtk_window_set_title (GTK_WINDOW (fsapp.window), "StockFW");
	gtk_window_set_default_size (GTK_WINDOW (fsapp.window), 620, 480);

	/* Set window icon from embedded logo */
	{
		GError *error = NULL;
		GdkPixbufLoader *loader = gdk_pixbuf_loader_new ();

		if (gdk_pixbuf_loader_write (loader, stockfw_logo_64_png,
		                             stockfw_logo_64_png_len, &error)) {
			gdk_pixbuf_loader_close (loader, NULL);
			GdkPixbuf *icon = gdk_pixbuf_loader_get_pixbuf (loader);
			if (icon != NULL)
				gtk_window_set_icon (GTK_WINDOW (fsapp.window), icon);
		} else {
			g_clear_error (&error);
		}
		g_object_unref (loader);
	}

	g_signal_connect (fsapp.window, "delete-event",
	                   G_CALLBACK (on_delete_event), NULL);

	box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	gtk_container_add (GTK_CONTAINER (fsapp.window), box);

	register_actions ();
	gtk_application_set_menubar (fsapp.app, build_menubar ());

	/* Set the default icon for ALL windows (main, dialogs, about) */
	{
		GError *error = NULL;
		GdkPixbufLoader *loader = gdk_pixbuf_loader_new ();

		if (gdk_pixbuf_loader_write (loader, stockfw_logo_64_png,
		                             stockfw_logo_64_png_len, &error)) {
			gdk_pixbuf_loader_close (loader, NULL);
			GdkPixbuf *icon = gdk_pixbuf_loader_get_pixbuf (loader);
			if (icon != NULL)
				gtk_window_set_default_icon (icon);
		} else {
			g_clear_error (&error);
		}
		g_object_unref (loader);
	}

	/* Toolbar strip, above the notebook, one row per page. */
	toolbar_host = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	gtk_box_pack_start (GTK_BOX (box), toolbar_host, FALSE, FALSE, 0);

	/* Notebook pages.  Order matches the original: Status, Events,
	 * Policy, with Copilot last. */
	fsapp.notebook = gtk_notebook_new ();
	gtk_widget_set_vexpand (fsapp.notebook, TRUE);
	gtk_box_pack_start (GTK_BOX (box), fsapp.notebook, TRUE, TRUE, 0);

	g_signal_connect (fsapp.notebook, "switch-page",
	                  G_CALLBACK (on_page_switched), NULL);

	add_page (_("Status"), fs_statusview_page (),
	          fs_statusview_toolbar ());
	add_page (_("Events"), fs_hitview_page (), NULL);

	policy = fs_policy_new ();
	settings = fs_settings_new ();
	fs_settings_load_prefs (settings);
	fs_backend_set_context (policy, settings);

	/* "Start the firewall on program startup".  A failure here is not
	 * fatal: the window still opens and the state line reports what
	 * actually happened. */
	if (fs_prefs_get_bool (FS_PREFS_START_ON_GUI, FALSE) &&
	    fs_backend ()->available ()) {
		GError *error = NULL;

		if (!fs_backend ()->start (&error))
			g_clear_error (&error);
	}

	add_page (_("Policy"), fs_policyview_page (policy), NULL);

	/* Smart Firewall Copilot tab */
	copilot = fs_copilot_new ();
	add_page (_("Copilot"), fs_copilot_page (copilot, policy), NULL);

	gtk_widget_show_all (fsapp.window);

	/* show_all() would reveal every toolbar row at once; reapply the
	 * selection so only the current page's row is left visible. */
	on_page_switched (NULL, NULL,
	                  (guint) gtk_notebook_get_current_page (
	                  GTK_NOTEBOOK (fsapp.notebook)), NULL);

	/* Reflect the real firewall state, if the backend knows it. */
	fs_statusview_set_state (fs_backend ()->get_state ());
}

void
fs_app_reload_settings (void)
{
	if (settings == NULL)
		return;

	fs_settings_load_prefs (settings);
	fs_backend_set_context (policy, settings);
}

void
fs_app_quit (void)
{
	fs_prefs_save ();

	if (policy != NULL) {
		fs_policy_free (policy);
		policy = NULL;
	}

	if (settings != NULL) {
		fs_settings_free (settings);
		settings = NULL;
	}

	if (copilot != NULL) {
		fs_copilot_free (copilot);
		copilot = NULL;
	}

	if (fsapp.app != NULL)
		g_application_quit (G_APPLICATION (fsapp.app));
}