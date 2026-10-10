/*---[ fs-tray.h ]-------------------------------------------------------
 * The notification-area surface: how StockFW stays reachable while it
 * runs in the background.
 *
 * Contract (every clause is pinned by tests/ui-tray-smoke.c):
 *
 *   - fs_tray_set_window() remembers the window Open restores; without
 *     it nothing installs and nothing hides (the gate below fails
 *     closed).
 *   - fs_tray_sync() follows the "Show a tray icon" preference both
 *     ways: off means no icon exists at all, on means one is created
 *     and embedded with the shell (Shell_NotifyIcon, really added).
 *   - fs_tray_hide_on_close() is TRUE only when BOTH the "Minimize to
 *     the tray" preference is on AND an icon is actually embedded: with
 *     no icon to come back from, closing the window quits the program
 *     instead of stranding an unreachable background process.
 *   - fs_tray_uninstall() takes the icon down (quit path, so no dead
 *     icon outlives the program).
 *--------------------------------------------------------------------*/
#ifndef FS_TRAY_H
#define FS_TRAY_H

#include <gtk/gtk.h>

G_BEGIN_DECLS

/* The window the tray restores (Open, icon click). */
void fs_tray_set_window (GtkWindow *window);

/* Make the icon match the "Show a tray icon" preference.  Called at
 * startup and again whenever the Preferences dialog is accepted. */
void fs_tray_sync (void);

/* Remove the icon; safe to call when none is up. */
void fs_tray_uninstall (void);

/* TRUE when an icon exists AND the shell embedded it -- i.e. it is * really showing in the notification area right now. */
gboolean fs_tray_active (void);

/* TRUE when closing/minimizing the window must hide it to the tray
 * rather than quit.  Fails closed: see the contract above. */
gboolean fs_tray_hide_on_close (void);

/* Show, un-minimize and raise the window (tray menu, icon click). */
void fs_tray_show_window (void);

/* Firewall state sentence for the tooltip ("The firewall is running").
 * Kept even while no icon is up, so the next icon inherits it. */
void fs_tray_set_state (const gchar *text);

/* The tray popup menu (Open / Quit), for tests that must read its
 * contents without clicking the real shell. */
GtkWidget *fs_tray_menu (void);

/* The status icon itself, so tests can read back what the shell holds
 * (tooltip) through the real getter.  NULL when none is up. */
GtkStatusIcon *fs_tray_icon (void);

G_END_DECLS

#endif /* FS_TRAY_H */
