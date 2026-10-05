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

static FsApp fsapp = { NULL, NULL, NULL };

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

/* [ register_actions ] */
static void
register_actions (void)
{
	GSimpleAction *quit, *about;

	quit = g_simple_action_new ("quit", NULL);
	g_signal_connect (quit, "activate", G_CALLBACK (on_action_quit), NULL);
	g_action_map_add_action (G_ACTION_MAP (fsapp.app), G_ACTION (quit));
	g_object_unref (quit);

	about = g_simple_action_new ("about", NULL);
	g_signal_connect (about, "activate", G_CALLBACK (on_action_about), NULL);
	g_action_map_add_action (G_ACTION_MAP (fsapp.app), G_ACTION (about));
	g_object_unref (about);
}

/* [ add_page ]
 * Appends a notebook page and returns the tab label. */
static void
add_page (const gchar *title, GtkWidget *content)
{
	GtkWidget *label = gtk_label_new (title);

	gtk_widget_show_all (content);
	gtk_notebook_append_page (GTK_NOTEBOOK (fsapp.notebook), content, label);
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
	gtk_window_set_icon_name (GTK_WINDOW (fsapp.window), "network-server");

	g_signal_connect (fsapp.window, "delete-event",
	                   G_CALLBACK (on_delete_event), NULL);

	box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	gtk_container_add (GTK_CONTAINER (fsapp.window), box);

	register_actions ();
	gtk_application_set_menubar (fsapp.app, build_menubar ());

	/* Notebook pages */
	fsapp.notebook = gtk_notebook_new ();
	gtk_widget_set_vexpand (fsapp.notebook, TRUE);
	gtk_box_pack_start (GTK_BOX (box), fsapp.notebook, TRUE, TRUE, 0);

	add_page (_("Status"), fs_statusview_page ());

	policy = fs_policy_new ();
	settings = fs_settings_new ();
	fs_backend_set_context (policy, settings);

	add_page (_("Policy"), fs_policyview_page (policy));

	add_page (_("Events"), fs_hitview_page ());

	/* Smart Firewall Copilot tab */
	copilot = fs_copilot_new ();
	add_page (_("Copilot"), fs_copilot_page (copilot));

	gtk_widget_show_all (fsapp.window);

	/* Reflect the real firewall state, if the backend knows it. */
	fs_statusview_set_state (fs_backend ()->get_state ());
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