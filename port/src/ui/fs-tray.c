/*---[ fs-tray.c ]-------------------------------------------------------
 * The notification-area surface: StockFW running in the background.
 *
 * GTK3 ships exactly one tray API -- GtkStatusIcon -- deprecated since
 * 3.14 but fully wired on MSYS2: the toolkit calls Shell_NotifyIconW
 * and reports the result honestly through gtk_status_icon_is_embedded()
 * (verified against the live Windows shell by tests/ui-tray-smoke.c).
 * This whole file compiles inside the deprecation guard on purpose --
 * there is no non-deprecated replacement in GTK3, and inventing a
 * half-working Win32 shim would be strictly worse than the documented
 * API that is actually tested.
 *
 * The rule that keeps the background app trustworthy: the window may
 * only hide when an icon is really up to bring it back from.  The gate
 * demands BOTH preferences AND an embedded icon -- never a hidden
 * window with no way to reopen it, which would leave the firewall * running as an unreachable zombie process.
 *--------------------------------------------------------------------*/

#include "ui/fs-tray.h"
#include "ui/fs-app.h"
#include "core/fs-prefs.h"
#include "core/fs-i18n.h"

G_GNUC_BEGIN_IGNORE_DEPRECATIONS

/* The icon (NULL = none), the window Open restores, and the last
 * firewall state sentence fed in by fs_statusview_set_state(). */
static GtkStatusIcon *tray_icon = NULL;
static GtkWindow *tray_window = NULL;
static gchar *tray_state = NULL;
static GtkWidget *tray_menu = NULL;

/* [ update_tooltip ] -- a glance at the tray answers the question a
 * background firewall exists for.  No icon: no-op, the state is kept
 * for the next one. */
static void
update_tooltip (void)
{
	gchar *text;

	if (tray_icon == NULL)
		return;

	text = tray_state != NULL
	     ? g_strdup_printf ("StockFW - %s", tray_state)
	     : g_strdup ("StockFW");

	gtk_status_icon_set_tooltip_text (tray_icon, text);
	g_free (text);
}

/* [ menu_open_activated ] -- the tray menu's Open. */
static void
menu_open_activated (GtkMenuItem *item, gpointer data)
{
	(void) item;
	(void) data;

	fs_tray_show_window ();
}

/* [ menu_quit_activated ] -- the way out of background mode.  File >
 * Quit and this item are the only two exits, and both are real. */
static void
menu_quit_activated (GtkMenuItem *item, gpointer data)
{
	(void) item;
	(void) data;

	fs_app_quit ();
}

/* [ build_menu ] -- Open / Quit, built once and reused. */
static void
build_menu (void)
{
	GtkWidget *item;

	tray_menu = gtk_menu_new ();

	item = gtk_menu_item_new_with_label (_("Open StockFW"));
	g_signal_connect (item, "activate",
	                  G_CALLBACK (menu_open_activated), NULL);
	gtk_menu_shell_append (GTK_MENU_SHELL (tray_menu), item);

	item = gtk_menu_item_new_with_label (_("Quit StockFW"));
	g_signal_connect (item, "activate",
	                  G_CALLBACK (menu_quit_activated), NULL);
	gtk_menu_shell_append (GTK_MENU_SHELL (tray_menu), item);

	gtk_widget_show_all (tray_menu);
}

/* [ on_activate ] -- left click restores the window. */
static void
on_activate (GtkStatusIcon *icon, gpointer data)
{
	(void) icon;
	(void) data;

	fs_tray_show_window ();
}

/* [ on_popup_menu ] -- right click opens the menu, positioned on the
 * icon the way a notification-area menu must be. */
static void
on_popup_menu (GtkStatusIcon *icon, guint button, guint activate_time,
               gpointer data)
{
	(void) data;

	if (tray_menu == NULL)
		build_menu ();

	gtk_menu_popup (GTK_MENU (tray_menu), NULL, NULL,
	                gtk_status_icon_position_menu, icon,
	                button, activate_time);
}

/* [ create_icon ] -- only from fs_tray_sync(), window already known.
 * The icon reuses the window's logo so the tray and the title bar
 * agree; the themed fallback covers a window without one. */
static void
create_icon (void)
{
	GdkPixbuf *logo = gtk_window_get_icon (tray_window);

	tray_icon = logo != NULL
	          ? gtk_status_icon_new_from_pixbuf (logo)
	          : gtk_status_icon_new_from_icon_name ("applications-system");

	g_signal_connect (tray_icon, "activate", G_CALLBACK (on_activate),
	                  NULL);
	g_signal_connect (tray_icon, "popup-menu",
	                  G_CALLBACK (on_popup_menu), NULL);
	update_tooltip ();
}

/* [ destroy_icon ] -- visible=FALSE first so the shell drops the icon
 * before the object goes; then release our reference. */
static void
destroy_icon (void)
{
	if (tray_icon == NULL)
		return;

	gtk_status_icon_set_visible (tray_icon, FALSE);
	g_clear_object (&tray_icon);
}

void
fs_tray_set_window (GtkWindow *window)
{
	tray_window = window;
}

/* [ fs_tray_sync ] -- the icon follows the preference both ways:
 * accepting Preferences with the box ticked brings it up, unticking
 * takes it down while the program keeps running. */
void
fs_tray_sync (void)
{
	gboolean want;

	if (tray_window == NULL)
		return;

	want = fs_prefs_get_bool (FS_PREFS_ENABLE_TRAY_ICON, TRUE);

	if (want && tray_icon == NULL)
		create_icon ();
	else if (!want && tray_icon != NULL)
		destroy_icon ();
}

void
fs_tray_uninstall (void)
{
	destroy_icon ();
}

/* [ fs_tray_active ] -- "an icon is really up": the object exists AND
 * the shell embedded it.  The second half is the honest one -- a shell
 * that refused the icon reads as not active, so nothing downstream
 * hides the window on its strength. */
gboolean
fs_tray_active (void)
{
	return tray_icon != NULL && gtk_status_icon_is_embedded (tray_icon);
}

/* [ fs_tray_hide_on_close ] -- the gate behind close/minimize to tray.
 * All three must hold: the preference asked for it, an icon object
 * exists, and that icon is embedded with the shell.  FALSE with no
 * icon, always: closing the window then quits the program instead of
 * stranding it invisible. */
gboolean
fs_tray_hide_on_close (void)
{
	return fs_prefs_get_bool (FS_PREFS_MINIMIZE_TO_TRAY, TRUE) &&
	       fs_tray_active ();
}

void
fs_tray_show_window (void)
{
	if (tray_window == NULL)
		return;

	/* Show, un-minimize, raise -- in that order: a window minimized
	 * behind the icon comes back iconified if it is only shown. */
	gtk_widget_show (GTK_WIDGET (tray_window));
	gtk_window_deiconify (tray_window);
	gtk_window_present (tray_window);
}

void
fs_tray_set_state (const gchar *text)
{
	g_free (tray_state);
	tray_state = g_strdup (text);
	update_tooltip ();
}

/* [ fs_tray_menu ] -- the popup, for tests that must read its
 * contents without clicking the real shell. */
GtkWidget *
fs_tray_menu (void)
{
	if (tray_menu == NULL)
		build_menu ();

	return tray_menu;
}

GtkStatusIcon *
fs_tray_icon (void)
{
	return tray_icon;
}

G_GNUC_END_IGNORE_DEPRECATIONS
