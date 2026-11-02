/*---[ fs-instance.h ]---------------------------------------------------
 * One StockFW per user (Linux) or per sign-in session (Windows), and the
 * channel a second launch (or the uninstaller) uses to reach it.  On
 * Linux that is per uid, not per display: a launch on a second display
 * of the same user brings the first copy's window forward where it is.
 *
 * Two copies of the app each ran their own event monitor, Sentinel,
 * auto-block file, tray icon and quit-time saves (last writer won).  A
 * second launch now finds the first, asks it to show its window (or,
 * with --quit, to quit cleanly) and exits.
 *
 * Why not GApplication's own uniqueness: it rides on the D-Bus session
 * bus.  `sudo StockFW' strips the bus address, so the root copy and the
 * user's copy never see each other, and the Windows build would need
 * gdbus autolaunch, which the installer does not ship.  So:
 *
 *   Linux    an abstract Unix socket, "stockfw-gui-<uid>", where <uid>
 *            is the desktop user's (SUDO_UID / PKEXEC_UID when running
 *            as root through them).  Binding it IS the lock: the kernel
 *            frees it when the process dies, so there is never a stale
 *            lock file.  Each side checks the other's credentials
 *            (SO_PEERCRED): a "show" is taken from that user, root or
 *            the instance's own uid; a "quit" only from root or the
 *            instance's own uid -- an unprivileged user cannot make the
 *            root copy quit.  A name held by some other uid is treated
 *            as squatted: StockFW then runs without the guard rather
 *            than being locked out by another account.
 *
 *   Windows  a named mutex plus two auto-reset events, all in the
 *            session's Local\ namespace, so one copy per sign-in
 *            session whichever account (or elevation) runs it.  The
 *            DACLs: anyone signed in interactively may see the mutex
 *            and signal "show"; "quit" is open to the user's own
 *            processes only when the instance is NOT elevated -- an
 *            elevated copy takes "quit" from administrators (the
 *            uninstaller) and SYSTEM only.  An unelevated second
 *            launch that cannot reach an elevated first says so in a
 *            dialog instead.
 *
 * $STOCKFW_INSTANCE_NAME replaces the name (tests run beside a real
 * StockFW without touching it).
 *--------------------------------------------------------------------*/
#ifndef FS_INSTANCE_H
#define FS_INSTANCE_H

#include <glib.h>

G_BEGIN_DECLS

typedef enum
{
	FS_INSTANCE_SHOW = 1,   /* bring the window to the front */
	FS_INSTANCE_QUIT = 2    /* quit cleanly (saves, rules stay) */
} FsInstanceCommand;

typedef enum
{
	FS_INSTANCE_PRIMARY,    /* this process is the instance          */
	FS_INSTANCE_SECONDARY,  /* another process is; ask it instead    */
	FS_INSTANCE_UNGUARDED   /* could not tell (squatted name, no
	                         * sockets): run without the guard        */
} FsInstanceRole;

typedef enum
{
	FS_INSTANCE_SENT,         /* the running instance took it          */
	FS_INSTANCE_NONE_RUNNING, /* nothing to send to                    */
	FS_INSTANCE_REFUSED,      /* it is there and said no (privilege)   */
	FS_INSTANCE_UNREACHABLE   /* it is there, but cannot be reached    */
} FsInstanceReply;

typedef void (*FsInstanceHandler) (FsInstanceCommand command,
                                   gpointer user_data);

/* Claim the instance name.  Call once, early; the claim lasts until
 * fs_instance_release() or process exit. */
FsInstanceRole  fs_instance_acquire (void);

/* After fs_instance_acquire() said SECONDARY: TRUE when the running
 * copy has fewer privileges than this one -- Linux: it is not root and
 * this process is (`sudo StockFW' while the sign-in copy runs);
 * Windows: it is not elevated and this process is ("StockFW
 * (Elevated)" while the sign-in copy runs).  Such a launch takes the
 * running copy's place (main.c) instead of raising a window that
 * cannot do what the user elevated for. */
gboolean        fs_instance_holder_weaker (void);

/* Primary only: deliver commands to `handler' on the default main
 * context from now on. */
void            fs_instance_listen  (FsInstanceHandler handler,
                                     gpointer user_data);

/* Give the name up (the next launch becomes the primary). */
void            fs_instance_release (void);

/* Ask the running instance to do `command'.  Waits up to timeout_ms
 * for its answer where the platform gives one (Linux). */
FsInstanceReply fs_instance_send    (FsInstanceCommand command,
                                     guint timeout_ms);

/* TRUE once no instance holds the name, waiting up to timeout_ms. */
gboolean        fs_instance_wait_gone (guint timeout_ms);

/* The name in use (for messages and tests). */
const gchar    *fs_instance_name    (void);

G_END_DECLS

#endif /* FS_INSTANCE_H */
