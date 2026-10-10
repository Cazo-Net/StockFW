/*---[ fs-app.c ]-------------------------------------------------------
 * Application object and main window.
 *
 * Replaces gnome_app_new()/gnome_app_set_contents()/gnome_app_set_menus()
 * and the gnome_program_init()/gnome_master_client() startup dance in
 * the original stockfw.c with a plain GtkApplication.
 *
 * Layout (light theme): menubar (GtkApplication) -> custom tab band
 * (the notebook's own tabs are hidden; the band carries the four page
 * buttons) -> per-page toolbar strip -> notebook content.
 *--------------------------------------------------------------------*/

#include "ui/fs-app.h"
#include "ui/fs-dialogs.h"
#include "ui/fs-statusview.h"
#include "ui/fs-policyview.h"
#include "ui/fs-hitview.h"
#include "ui/fs-copilot.h"
#include "ui/fs-trustview.h"
#include "ui/fs-tray.h"
#include "core/fs-backend.h"
#include "core/fs-prefs.h"
#include "core/fs-rules.h"
#include "core/fs-script.h"
#include "core/fs-copilot.h"
#include "core/fs-trust.h"
#include "core/fs-i18n.h"
#include "stockfw-logo-64.h"
#include "fs-theme-css.h"        /* generated from src/ui/fs-theme.css */

#include <gdk-pixbuf/gdk-pixbuf.h>

static FsApp fsapp = { NULL, NULL, NULL };

/* Holds one toolbar row per notebook page; only the selected page's
 * row is visible at a time. */
static GtkWidget *toolbar_host = NULL;

/* The five buttons of the custom tab band, index-aligned with the
 * notebook pages. */
#define FS_TAB_COUNT 5
static GtkWidget *tab_buttons[FS_TAB_COUNT] = {
	NULL, NULL, NULL, NULL, NULL
};

/* Set while the band is being re-synced to the notebook, so the
 * band's own handlers do not fire back into the notebook. */
static gboolean tabs_syncing = FALSE;

/* The traffic policy, shared by the Policy page and Apply. */
static FsPolicy *policy = NULL;

/* Interface and NAT choices, handed to the rule generator. */
static FsSettings *settings = NULL;

/* Smart Firewall Copilot instance. */
FsCopilot *copilot = NULL;

static gboolean
on_delete_event (GtkWidget *widget, GdkEvent *event, gpointer data)
{
	/* GTK owns the event it passes to the handler; freeing it here
	 * made the main loop free the same block a second time when the
	 * window closed -- a double free on every exit. */
	(void) event;
	(void) data;

	/* Background mode: with the tray icon up and "Minimize to the
	 * tray" on, the window closes INTO the icon and the firewall
	 * keeps running behind it; the tray menu's Quit is the way out.
	 * The gate refuses unless an icon is really embedded with the
	 * shell, so this can never hide the window with nothing to bring
	 * it back from. */
	if (fs_tray_hide_on_close ()) {
		gtk_widget_hide (widget);
		return TRUE;
	}

	/* No tray (or the preference is off): quit.  TRUE on both paths --
	 * this handler decides the window's fate, so the default handler
	 * must not destroy it underneath the quit.  The old void return
	 * left this signal's boolean result as whatever the callee had in
	 * a register. */
	fs_app_quit ();
	return TRUE;
}

/* [ on_window_state_event ] -- "Minimize to the tray": the minimize
 * button hides the window behind the icon under the same gate as the
 * close button, for the same reason.  Hiding an already-hidden window
 * cannot happen here: the gate only sees ICONIFIED arriving, and an
 * unmap removes it from the new state. */
static gboolean
on_window_state_event (GtkWidget *widget, GdkEventWindowState *event,
                       gpointer data)
{
	(void) data;

	if ((event->changed_mask & GDK_WINDOW_STATE_ICONIFIED) != 0 &&
	    (event->new_window_state & GDK_WINDOW_STATE_ICONIFIED) != 0 &&
	    fs_tray_hide_on_close ()) {
		gtk_widget_hide (widget);
		return TRUE;
	}

	return FALSE;
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

/* [ sync_tab_band ]
 * Push the notebook's current page into the band: active button gets
 * the "tab-active" class (the one deterministic way to colour the
 * selected tab), the rest lose it. */
static void
sync_tab_band (guint page_num)
{
	tabs_syncing = TRUE;

	for (guint i = 0; i < FS_TAB_COUNT; i++) {
		GtkStyleContext *ctx;

		if (tab_buttons[i] == NULL)
			continue;

		ctx = gtk_widget_get_style_context (tab_buttons[i]);

		if (i == page_num) {
			gtk_toggle_button_set_active (
				GTK_TOGGLE_BUTTON (tab_buttons[i]), TRUE);
			gtk_style_context_add_class (ctx, "tab-active");
		} else {
			gtk_toggle_button_set_active (
				GTK_TOGGLE_BUTTON (tab_buttons[i]), FALSE);
			gtk_style_context_remove_class (ctx, "tab-active");
		}
	}

	tabs_syncing = FALSE;
}

/* [ on_tab_clicked ]
 * A band button was pressed.  A press on the already-active tab
 * toggles the button off; tabs are not optional, so put it straight
 * back instead of leaving the band with no selection. */
static void
on_tab_clicked (GtkToggleButton *button, gpointer data)
{
	guint page = GPOINTER_TO_UINT (data);

	if (tabs_syncing)
		return;

	if (!gtk_toggle_button_get_active (button)) {
		gtk_toggle_button_set_active (button, TRUE);
		return;
	}

	gtk_notebook_set_current_page (GTK_NOTEBOOK (fsapp.notebook),
	                               (gint) page);
}

/* [ build_tab_band ]
 * The full-width light-slate band that replaces the notebook's own
 * tab row: flat buttons, rounded corners, the selected one filled
 * classic blue with white text. */
static GtkWidget *
build_tab_band (void)
{
	static const gchar *labels[FS_TAB_COUNT];
	GtkWidget *band;
	GtkWidget *spacer;

	band = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 4);
	gtk_widget_set_hexpand (band, TRUE);
	gtk_style_context_add_class (gtk_widget_get_style_context (band),
	                             "tab-band");

	labels[0] = _("Status");
	labels[1] = _("Events");
	labels[2] = _("Policy");
	labels[3] = _("Copilot");
	labels[4] = _("Trust");

	for (guint i = 0; i < FS_TAB_COUNT; i++) {
		GtkWidget *btn = gtk_toggle_button_new_with_label (labels[i]);

		gtk_style_context_add_class (gtk_widget_get_style_context (btn),
		                             "tab-button");
		gtk_button_set_relief (GTK_BUTTON (btn), GTK_RELIEF_NONE);
		g_signal_connect (btn, "toggled",
		                  G_CALLBACK (on_tab_clicked),
		                  GUINT_TO_POINTER (i));
		gtk_box_pack_start (GTK_BOX (band), btn, FALSE, FALSE, 0);
		tab_buttons[i] = btn;
	}

	/* Keep the tabs left-aligned when the band is wider than they are. */
	spacer = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_widget_set_hexpand (spacer, TRUE);
	gtk_box_pack_start (GTK_BOX (band), spacer, TRUE, TRUE, 0);

	return band;
}

/* [ on_page_switched ]
 * Show only the toolbar row that belongs to the selected page, and
 * keep the tab band in step with the notebook. */
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

	sync_tab_band (page_num);
}

/* [ install_theme ]
 * One stylesheet for the whole application: the light palette from
 * src/ui/fs-theme.css, compiled into the binary (fs-theme-css.h is
 * generated at configure time), so the installed exe needs no data
 * files beside it. */
static void
install_theme (void)
{
	GtkCssProvider *provider = gtk_css_provider_new ();
	GError *error = NULL;

	if (!gtk_css_provider_load_from_data (provider, fs_theme_css,
	                                       -1, &error)) {
		/* A stylesheet that will not parse must not stop the
		 * window from opening; the app then runs in the system
		 * theme and says so on stderr. */
		g_warning ("StockFW theme failed to load: %s",
		           error ? error->message : "unknown error");
		g_clear_error (&error);
		g_object_unref (provider);
		return;
	}

	gtk_style_context_add_provider_for_screen (
		gdk_screen_get_default (),
		GTK_STYLE_PROVIDER (provider),
		GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

	g_object_unref (provider);
}

/* The trust engine asks the platform for Authenticode verdicts
 * through the backend vtable: core stays portable, the UI stays the
 * only place that knows both halves exist. */
static gboolean
app_trust_signature (const gchar *path, FsTrustSignature *sig,
                     gchar **publisher, gpointer user)
{
	const FsBackend *backend = fs_backend ();

	(void) user;
	if (backend->trust_signature == NULL)
		return FALSE;

	return backend->trust_signature (path, sig, publisher);
}

void
fs_app_activate (GtkApplication *app)
{
	GtkWidget *box;

	fsapp.app = GTK_APPLICATION (app);

	fs_trust_set_signature_provider (app_trust_signature, NULL);

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
	g_signal_connect (fsapp.window, "window-state-event",
	                   G_CALLBACK (on_window_state_event), NULL);

	/* Theme first: everything built below picks up the classes. */
	install_theme ();

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

	/* Tab band, above the toolbar strip: five flat buttons standing
	 * in for the notebook's tab row (which is switched off below). */
	gtk_box_pack_start (GTK_BOX (box), build_tab_band (),
	                    FALSE, FALSE, 0);

	/* Toolbar strip, above the notebook, one row per page. */
	toolbar_host = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	gtk_box_pack_start (GTK_BOX (box), toolbar_host, FALSE, FALSE, 0);

	/* Notebook pages.  Order matches the original: Status, Events,
	 * Policy, with Copilot and Trust last. */
	fsapp.notebook = gtk_notebook_new ();
	gtk_notebook_set_show_tabs (GTK_NOTEBOOK (fsapp.notebook), FALSE);
	gtk_notebook_set_show_border (GTK_NOTEBOOK (fsapp.notebook), FALSE);
	gtk_widget_set_vexpand (fsapp.notebook, TRUE);
	gtk_box_pack_start (GTK_BOX (box), fsapp.notebook, TRUE, TRUE, 0);

	g_signal_connect (fsapp.notebook, "switch-page",
	                  G_CALLBACK (on_page_switched), NULL);

	add_page (_("Status"), fs_statusview_page (),
	          fs_statusview_toolbar ());
	add_page (_("Events"), fs_hitview_page (), NULL);

	policy = fs_policy_new ();

	/* The Events page was built above (before there was a policy to
	 * give it); its right-click Event -> Rule actions need the
	 * pointer now that it exists. */
	fs_hitview_set_policy (policy);

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

	/* Resume the historical behavior baseline (P2): yesterday's
	 * learned ports, destinations, hours and rates are loaded before
	 * the first event arrives, so a restart does not call every old
	 * port new.  A missing file is a fresh start, not an error. */
	{
		gchar *baseline = fs_copilot_baseline_path ();
		GError *baseline_err = NULL;

		if (!fs_copilot_baseline_load (copilot, baseline,
		                               &baseline_err))
			g_clear_error (&baseline_err);
		g_free (baseline);
	}

	add_page (_("Copilot"), fs_copilot_page (copilot, policy), NULL);

	/* Trust tab: the application trust engine's surface. */
	add_page (_("Trust"), fs_trustview_page (), NULL);

	gtk_widget_show_all (fsapp.window);

	/* show_all() would reveal every toolbar row at once; reapply the
	 * selection so only the current page's row is left visible. */
	on_page_switched (NULL, NULL,
	                  (guint) gtk_notebook_get_current_page (
	                  GTK_NOTEBOOK (fsapp.notebook)), NULL);

	/* Reflect the real firewall state, if the backend knows it. */
	fs_statusview_set_state (fs_backend ()->get_state ());

	/* Tray last: the icon reuses the window logo set above, and the
	 * state call just now already fed the tooltip text. */
	fs_tray_set_window (GTK_WINDOW (fsapp.window));
	fs_tray_sync ();
}

void
fs_app_reload_settings (void)
{
	if (settings == NULL)
		return;

	fs_settings_load_prefs (settings);
	fs_backend_set_context (policy, settings);

	/* The Preferences dialog may have toggled the tray switches. */
	fs_tray_sync ();
}

void
fs_app_quit (void)
{
	/* Icon down first: a tray icon that outlives the program is a
	 * dead icon that still looks clickable. */
	fs_tray_uninstall ();

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
		/* Best effort: an unsaved baseline only costs relearning,
		 * never a wrong rule or a lost audit line. */
		gchar *baseline = fs_copilot_baseline_path ();

		fs_copilot_baseline_save (copilot, baseline, NULL);
		g_free (baseline);

		fs_copilot_free (copilot);
		copilot = NULL;
	}

	if (fsapp.app != NULL)
		g_application_quit (G_APPLICATION (fsapp.app));
}