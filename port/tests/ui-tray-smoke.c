/*---[ ui-tray-smoke.c ]-------------------------------------------------
 * Smoke for the tray/background surface (src/ui/fs-tray.c).
 *
 * What this proves, against the REAL Windows shell (not a mock):
 *
 *   1. The gate fails closed before anything is wired: with no window
 *      remembered, sync installs nothing even with the preference on.
 *   2. "Show a tray icon" off installs nothing, and close-to-tray
 *      refuses even with "Minimize to the tray" on -- no icon, no
 *      hiding, never an unreachable background process.
 *   3. Icon on: the icon is installed AND embedded (Shell_NotifyIcon's
 *      NIM_ADD really succeeded -- the integration a unit test cannot
 *      fake).
 *   4. "Minimize to the tray" gates the hide decision independently of
 *      the icon's presence, in both directions.
 *   5. fs_tray_sync() follows a live preference flip both ways, the
 *      way accepting the Preferences dialog does.
 *   6. The tooltip carries the firewall's state (read back through the
 *      real GtkStatusIcon getter, not the module's own bookkeeping).
 *   7. The popup menu's layout: the two information rows first, Quit
 *      last behind its own separator.  (What each row DOES is
 *      tests/ui-traymenu-smoke.c, against the real app.)
 *   8. The restore path shows a hidden window again.
 *   9. Uninstall takes the icon down and the hide gate refuses again.
 *
 * A real notification-area icon exists for a moment; uninstall removes
 * it.  The preference file is isolated (APPDATA / XDG_CONFIG_HOME
 * pointed at a scratch directory as the very first statement, before
 * fs_prefs can cache its path), so nothing touches the user's config.
 *--------------------------------------------------------------------*/

#include "ui/fs-tray.h"
#include "core/fs-backend.h"
#include "core/fs-prefs.h"
#include "core/fs-i18n.h"

#include <glib/gstdio.h>   /* g_rmdir */

static gint failures = 0;

static void
check (gboolean ok, const gchar *what)
{
	if (ok)
		g_print ("ok:   %s\n", what);
	else {
		g_printerr ("FAIL: %s\n", what);
		failures++;
	}
}

/* Pump the main loop for a while: the shell processes NIM_ADD on its
 * own schedule. */
static void
pump (gint64 microseconds)
{
	gint64 end = g_get_monotonic_time () + microseconds;

	while (g_get_monotonic_time () < end)
		while (g_main_context_iteration (NULL, FALSE))
			;
}

/* Pump until the icon is embedded, with a deadline, then report. */
static gboolean
wait_active (gint64 microseconds)
{
	gint64 end = g_get_monotonic_time () + microseconds;

	while (!fs_tray_active () && g_get_monotonic_time () < end) {
		while (g_main_context_iteration (NULL, FALSE))
			;
		g_usleep (1000);
	}

	return fs_tray_active ();
}

/* [ dir_contains_file ] any regular file at or below dir -- the
 * prefs-save probe.  The scratch dir starts empty, and fs_app_quit()
 * saves the prefs for real, so a file appearing there proves the Quit
 * handler routed into the program's actual quit path. */
static gboolean
dir_contains_file (const gchar *path)
{
	GDir *dir = g_dir_open (path, 0, NULL);
	const gchar *name;
	gboolean found = FALSE;

	if (dir == NULL)
		return FALSE;

	while (!found && (name = g_dir_read_name (dir)) != NULL) {
		gchar *child = g_build_filename (path, name, NULL);

		if (g_file_test (child, G_FILE_TEST_IS_REGULAR))
			found = TRUE;
		else if (g_file_test (child, G_FILE_TEST_IS_DIR))
			found = dir_contains_file (child);

		g_free (child);
	}

	g_dir_close (dir);

	return found;
}

/* [ rm_rf ] recursive scratch cleanup: Quit saves the prefs for real,
 * so the isolated dir is no longer empty when the smoke is done. */
static void
rm_rf (const gchar *path)
{
	GDir *dir = g_dir_open (path, 0, NULL);

	if (dir != NULL) {
		const gchar *name;

		while ((name = g_dir_read_name (dir)) != NULL) {
			gchar *child = g_build_filename (path, name, NULL);

			if (g_file_test (child, G_FILE_TEST_IS_DIR))
				rm_rf (child);
			else
				g_unlink (child);

			g_free (child);
		}

		g_dir_close (dir);
	}

	g_rmdir (path);
}

int
main (int argc, char **argv)
{
	GtkWidget *window;
	GtkWidget *menu;
	GList *items;
	GtkMenuItem *quit_item = NULL;
	GdkPixbuf *logo;
	gchar *scratch;

	/* Isolate the preference file FIRST -- fs_prefs_init() caches the
	 * directory on first use, so nothing may reach prefs before this. */
	scratch = g_dir_make_tmp ("stockfw-tray-XXXXXX", NULL);
	if (scratch == NULL) {
		g_printerr ("ui-tray-smoke: FAILED, no scratch dir\n");
		return 1;
	}
	g_setenv ("APPDATA", scratch, TRUE);
	g_setenv ("XDG_CONFIG_HOME", scratch, TRUE);

	gtk_init (&argc, &argv);
	fs_prefs_load ();

	window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title (GTK_WINDOW (window), "tray smoke");

	/* Give the scratch window the same kind of logo the real window
	 * has, so create_icon() takes its pixbuf branch (the one the app
	 * runs) rather than the themed fallback. */
	logo = gtk_icon_theme_load_icon (gtk_icon_theme_get_default (),
	                                 "applications-system", 48, 0, NULL);
	if (logo != NULL) {
		gtk_window_set_icon (GTK_WINDOW (window), logo);
		g_object_unref (logo);
	}
	check (gtk_window_get_icon (GTK_WINDOW (window)) != NULL,
	       "scratch window has a logo for the tray icon to reuse");

	/* 1. No window remembered: sync must install nothing, whatever
	 * the preference says -- there is no window to restore. */
	fs_prefs_set_bool (FS_PREFS_ENABLE_TRAY_ICON, TRUE);
	fs_tray_sync ();
	check (!fs_tray_active (),
	       "no window remembered: sync installs no icon");

	fs_tray_set_window (GTK_WINDOW (window));

	/* 2. Preference off: nothing installed, and the hide gate stays
	 * shut even though Minimize to the tray asks for hiding. */
	fs_prefs_set_bool (FS_PREFS_MINIMIZE_TO_TRAY, TRUE);
	fs_prefs_set_bool (FS_PREFS_ENABLE_TRAY_ICON, FALSE);
	fs_tray_sync ();
	pump (100 * 1000);
	check (!fs_tray_active (),
	       "Show a tray icon OFF: no icon is installed");
	check (!fs_tray_hide_on_close (),
	       "Show a tray icon OFF: closing quits even with Minimize "
	       "to the tray ON (no icon to come back from)");

	/* 3. Preference on: the icon installs and the shell embeds it. */
	fs_prefs_set_bool (FS_PREFS_ENABLE_TRAY_ICON, TRUE);
	fs_tray_sync ();
	check (wait_active (3 * G_USEC_PER_SEC),
	       "Show a tray icon ON: icon installed and embedded with "
	       "the shell (NIM_ADD really happened)");
	check (fs_tray_hide_on_close (),
	       "both preferences ON and icon embedded: closing hides "
	       "to the tray");

	/* 4. The hide decision follows Minimize to the tray, with the
	 * icon still up the whole time. */
	fs_prefs_set_bool (FS_PREFS_MINIMIZE_TO_TRAY, FALSE);
	check (!fs_tray_hide_on_close (),
	       "Minimize to the tray OFF: closing quits even with the "
	       "icon up");
	check (fs_tray_active (),
	       "toggling Minimize to the tray leaves the icon alone");
	fs_prefs_set_bool (FS_PREFS_MINIMIZE_TO_TRAY, TRUE);
	check (fs_tray_hide_on_close (),
	       "Minimize to the tray ON again: closing hides to the tray");

	/* 5. A live flip, exactly as accepting Preferences drives it:
	 * off takes the icon down, on brings it back. */
	fs_prefs_set_bool (FS_PREFS_ENABLE_TRAY_ICON, FALSE);
	fs_tray_sync ();
	pump (100 * 1000);
	check (!fs_tray_active (),
	       "disabling Show a tray icon takes the icon down while "
	       "the program keeps running");
	check (!fs_tray_hide_on_close (),
	       "icon down: the hide gate fails closed again");

	fs_prefs_set_bool (FS_PREFS_ENABLE_TRAY_ICON, TRUE);
	fs_tray_sync ();
	check (wait_active (3 * G_USEC_PER_SEC),
	       "re-enabling Show a tray icon brings the icon back");

	/* 6. Tooltip: state in through fs_tray_set_firewall, read back
	 * out through the shell-side getter -- not through the module's
	 * own statics, which would only prove the bookkeeping agrees with
	 * itself. */
	fs_tray_set_firewall (FS_FW_RUNNING, "Private network");
	{
		GtkStatusIcon *icon = fs_tray_icon ();
		const gchar *tip;

		/* The getter is deprecated with the rest of GtkStatusIcon;
		 * reading back through it is exactly the point here. */
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS
		tip = icon != NULL ? gtk_status_icon_get_tooltip_text (icon)
		                   : NULL;
		G_GNUC_END_IGNORE_DEPRECATIONS

		check (tip != NULL &&
		       g_str_has_prefix (tip, "StockFW - Firewall on"),
		       "the tray tooltip says the firewall is on");
	}

	/* 7. The menu: the state first, as greyed information (a greyed
	 * row reads as information, an enabled row that does nothing
	 * reads as a broken control), and Quit last behind its own
	 * separator, saying the firewall stays on. */
	menu = fs_tray_menu ();
	check (GTK_IS_MENU (menu), "the tray popup is a GtkMenu");
	items = gtk_container_get_children (GTK_CONTAINER (menu));
	check (g_list_length (items) == 15,
	       "the tray menu has fifteen rows");

	if (g_list_length (items) == 15) {
		GtkWidget *row[15];
		GList *walk;
		guint i;

		for (i = 0, walk = items; walk != NULL; i++, walk = walk->next)
			row[i] = GTK_WIDGET (walk->data);

		check (GTK_IS_MENU_ITEM (row[0]) &&
		       !gtk_widget_get_sensitive (row[0]) &&
		       !gtk_widget_get_sensitive (row[1]),
		       "the two information rows are insensitive");
		{
			/* Opening the menu asks the backend again (a state
			 * fed in earlier may be stale by now), so the row
			 * says what the real backend says this moment. */
			FsFirewallState live = fs_backend ()->get_state ();
			const gchar *want =
				live == FS_FW_RUNNING || live == FS_FW_HIT
				? _("Firewall: On")
				: live == FS_FW_LOCKED
				? _("Firewall: On, policy locked")
				: live == FS_FW_STOPPED ? _("Firewall: Off")
				: _("Firewall: state unknown");
			const gchar *got = gtk_menu_item_get_label (
				GTK_MENU_ITEM (row[0]));

			check (got != NULL && g_str_has_prefix (got, want),
			       "the first row carries the state the backend "
			       "reports when the menu opens");
		}
		check (GTK_IS_SEPARATOR_MENU_ITEM (row[13]),
		       "Quit is fenced off behind its own separator");
		check (g_strcmp0 (gtk_menu_item_get_label (
		                      GTK_MENU_ITEM (row[14])),
		                  _("_Quit (firewall stays on)")) == 0,
		       "Quit is the last row and says the firewall stays on");
		quit_item = GTK_MENU_ITEM (row[14]);
	}
	g_list_free (items);

	/* 7b. The header is not frozen.  Changing the state must show the
	 * new one -- otherwise the tray would confidently report a
	 * firewall state it stopped seeing. */
	fs_tray_set_firewall (FS_FW_STOPPED, NULL);
	{
		GList *again = gtk_container_get_children (
		                   GTK_CONTAINER (menu));

		check (again != NULL &&
		       g_strcmp0 (gtk_menu_item_get_label (
		                      GTK_MENU_ITEM (again->data)),
		                  _("Firewall: Off")) == 0,
		       "the status row follows the state through a later "
		       "change, so it cannot report a stale verdict");
		g_list_free (again);
	}
	fs_tray_set_firewall (FS_FW_RUNNING, NULL);

	/* 8. The restore path: hide the window the way close-to-tray
	 * does, then bring it back the way the tray does. */
	gtk_widget_hide (window);
	check (!gtk_widget_get_visible (window),
	       "the window hides the way close-to-tray hides it");
	fs_tray_show_window ();
	check (gtk_widget_get_visible (window),
	       "the tray's Open path shows the window again");

	/* 9. Teardown: icon down, gate shut. */
	fs_tray_uninstall ();
	pump (100 * 1000);
	check (!fs_tray_active (),
	       "uninstall takes the icon down");
	check (!fs_tray_hide_on_close (),
	       "after uninstall the hide gate refuses: closing quits");

	/* 10. The Quit item is not decoration: activating it must run the
	 * program's real quit path (fs_app_quit).  There is nothing to
	 * tear down in this smoke, so the observable effect is the prefs
	 * save -- a fresh scratch dir gaining a file -- plus the smoke
	 * still standing afterwards (a careless teardown would trip over
	 * the NULL app/settings this smoke runs with). */
	check (!dir_contains_file (scratch),
	       "the scratch prefs dir is still empty before Quit");
	if (quit_item != NULL)
		g_signal_emit_by_name (quit_item, "activate");
	check (quit_item != NULL && dir_contains_file (scratch),
	       "the tray menu's Quit item routes into the real quit "
	       "path (fs_app_quit)");

	gtk_widget_destroy (window);
	rm_rf (scratch);
	g_free (scratch);

	if (failures > 0) {
		g_printerr ("ui-tray-smoke: FAILED, %d failure(s)\n",
		            failures);
		return 1;
	}

	g_print ("ui-tray-smoke: PASSED: 0 failure(s)\n");
	return 0;
}
