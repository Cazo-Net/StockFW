/*---[ fs-autostart.h ]--------------------------------------------------
 * "Start StockFW in the background when I sign in".
 *
 * Windows: a Task Scheduler task for the signed-in user, run at logon
 * WITHOUT elevation (LeastPrivilege): the front-end comes up in the
 * notification area showing the firewall's state, and starting StockFW
 * as administrator takes over from it for monitoring and changes.  It
 * never runs elevated without a prompt -- that would hand an
 * administrator's rights to whatever the user's environment makes a GTK
 * program load.  It is registered through the Task Scheduler COM API
 * (no schtasks.exe, so no console window flashes), in the task folder
 * \StockFW, one task per user, for the account that owns the desktop's
 * shell (over-the-shoulder elevation runs this process as another
 * account).  Changing it needs an administrator.
 *
 * Linux: an XDG autostart entry, ~/.config/autostart/stockfw.desktop,
 * running "StockFW --background".  The desktop starts it as the user,
 * without root: it sits in the notification area, showing the state as
 * unknown (iptables cannot be read without root),
 * and can neither change rules nor read the kernel log.  The rules
 * themselves are put back at boot by the stockfw service
 * (installer/linux/stockfw.service), not by this.  When StockFW runs as
 * root through sudo or pkexec, the entry is written into the invoking
 * user's home, with that user's file permissions, never root's.
 *
 * Nothing here touches the firewall.
 *--------------------------------------------------------------------*/
#ifndef FS_AUTOSTART_H
#define FS_AUTOSTART_H

#include <glib.h>

G_BEGIN_DECLS

#define FS_AUTOSTART_ERROR (fs_autostart_error_quark ())
GQuark fs_autostart_error_quark (void);

typedef enum {
	FS_AUTOSTART_ERROR_UNSUPPORTED,   /* no mechanism on this platform  */
	FS_AUTOSTART_ERROR_DENIED,        /* needs an administrator         */
	FS_AUTOSTART_ERROR_FAILED         /* anything else; message says it */
} FsAutostartError;

/* Is there a start-at-sign-in mechanism on this platform at all? */
gboolean fs_autostart_supported (void);

/* Can this copy change the setting now?  FALSE with a one-line reason
 * (caller frees `why', which may be NULL) when not: unsupported, or on
 * Windows not running as administrator. */
gboolean fs_autostart_can_change (gchar **why);

/* Is StockFW set to start at sign-in for the current (desktop) user? */
gboolean fs_autostart_enabled (void);

/* Turn it on or off for the current (desktop) user.  Idempotent:
 * turning on what is on rewrites it (picking up a moved executable),
 * turning off what is off succeeds. */
gboolean fs_autostart_set (gboolean on, GError **error);

/* Remove start-at-sign-in for EVERY user (the Windows uninstaller: the
 * \StockFW task folder and everything in it).  On Linux, the same as
 * fs_autostart_set (FALSE): per-user files are the users' own. */
gboolean fs_autostart_remove_all (GError **error);

/* One or two plain sentences on the mechanism, for a tooltip or the
 * Preferences dialog. */
const gchar *fs_autostart_description (void);

/* Exposed for the tests; portable, so Linux can check what Windows is
 * handed.  All return newly allocated strings. */

/* The Task Scheduler XML for `user' ("DOMAIN\name") running `exe' (a
 * Windows path) with --background at that user's logon, unelevated. */
gchar *fs_autostart_task_xml (const gchar *user, const gchar *exe);

/* The task's name inside \StockFW for `user'. */
gchar *fs_autostart_task_name (const gchar *user);

/* The XDG entry's Exec= value: "StockFW --background" when `bare',
 * else `binary' quoted per the Desktop Entry spec. */
gchar *fs_autostart_desktop_exec (const gchar *binary, gboolean bare);

G_END_DECLS

#endif /* FS_AUTOSTART_H */
