/*---[ fs-dash-auth.h ]---------------------------------------------------
 * The dashboard's credentials (PR 2, 2B; docs 15.3.2).
 *
 *   - Launch code: 128 bits, one use, 120 s.  It travels only in the
 *     URL fragment (#code=) and in a 0600 launch file, which is
 *     deleted when the code is used or expires.
 *   - Session key: 256 bits, given for a code by POST /api/session and
 *     sent back as X-StockFW-Session.  No cookies.  At most 4 at once.
 *     Reads work for 12 h after the code was used; writes need a write
 *     (or the code) in the last 15 minutes.  Keys live in memory only,
 *     so a restart ends them all.
 *   - A code used twice ends every session.
 *   - `stockfw dashboard link' gets a new code over a UNIX socket,
 *     $XDG_RUNTIME_DIR/stockfw/dash-<port>.sock, in a 0700 directory;
 *     only the served uid may connect, checked with SO_PEERCRED before
 *     anything is sent.
 *   - The start fingerprint: random, shown in the terminal and on the
 *     page, so a page from another server can be told apart (T13).
 *
 * Under sudo the process is root and the files belong to the user it
 * serves: every file operation in the user's runtime directory is made
 * with the effective ids switched to that user.  Linux only.
 *--------------------------------------------------------------------*/
#ifndef FS_DASH_AUTH_H
#define FS_DASH_AUTH_H

#include <gio/gio.h>
#include <sys/types.h>

#define FS_DASH_CODE_LIFE_S    120
#define FS_DASH_READ_LIFE_S    (12 * 3600)
#define FS_DASH_WRITE_IDLE_S   (15 * 60)
#define FS_DASH_MAX_SESSIONS   4
/* Codes not yet used; one more ends the oldest. */
#define FS_DASH_MAX_CODES      8

typedef struct _FsDashAuth FsDashAuth;

typedef enum
{
	FS_DASH_VIA_LOCAL,
	FS_DASH_VIA_SSH,     /* the Host was the --origin-port one */
	FS_DASH_VIA_WSL      /* a Windows peer let in by --allow-windows */
} FsDashVia;

typedef enum
{
	FS_DASH_REDEEM_OK,
	FS_DASH_REDEEM_UNKNOWN,   /* never issued: 401 */
	FS_DASH_REDEEM_EXPIRED,   /* older than 120 s: 410 */
	FS_DASH_REDEEM_REUSED     /* used before: 410, every session ended */
} FsDashRedeem;

typedef enum
{
	FS_DASH_SESSION_OK,
	FS_DASH_SESSION_NONE,         /* no such key, or past 12 h: 401 */
	FS_DASH_SESSION_WRITE_STALE   /* a write after 15 min without one */
} FsDashSession;

/* NULL when /dev/urandom cannot be read. */
FsDashAuth  *fs_dash_auth_new          (void);
void         fs_dash_auth_free         (FsDashAuth *auth);

/* The account served and its runtime directory (NULL: none; codes
 * then have no launch file and there is no link socket). */
void         fs_dash_auth_set_user     (FsDashAuth *auth, uid_t uid,
                                        gid_t gid, const gchar *runtime_dir);
const gchar *fs_dash_auth_runtime_dir  (const FsDashAuth *auth);

/* "XXXX-XXXX-XXXX", the same for the whole run. */
const gchar *fs_dash_auth_fingerprint  (const FsDashAuth *auth);

/* Seconds on the auth clock: monotonic.  The test build
 * (FS_DASH_TESTING) adds the number in $STOCKFW_TEST_CLOCK_FILE. */
gint64       fs_dash_auth_now          (FsDashAuth *auth);
/* Unit tests: a clock of their own. */
void         fs_dash_auth_set_clock    (FsDashAuth *auth,
                                        gint64 (*now) (gpointer),
                                        gpointer data);

/* A new code (32 hex).  With a runtime directory, a launch page
 * that sends the browser to http://127.0.0.1:port/#code=... is written
 * as a 0600 file in a new 0700 directory; *file (when not NULL) is its
 * path, owned by auth, or NULL when it could not be written. */
const gchar *fs_dash_auth_issue        (FsDashAuth *auth, guint16 port,
                                        const gchar **file);
FsDashRedeem fs_dash_auth_redeem       (FsDashAuth *auth, const gchar *code,
                                        FsDashVia via, gchar **key);
FsDashSession fs_dash_auth_check       (FsDashAuth *auth, const gchar *key,
                                        gboolean write);
/* A write was made with this key: the 15 minutes start again. */
void         fs_dash_auth_note_write   (FsDashAuth *auth, const gchar *key);
gboolean     fs_dash_auth_end          (FsDashAuth *auth, const gchar *key);
guint        fs_dash_auth_n_sessions   (const FsDashAuth *auth);
/* Expires codes (deleting their launch files) and old sessions; run
 * every second. */
void         fs_dash_auth_tick         (FsDashAuth *auth);

/* `stockfw dashboard link': listens on <runtime>/stockfw/dash-<port>.sock.
 * A connection from the served uid gets "port=", "code=", "file=" and
 * "fingerprint=" lines (and "origin_port=" with --origin-port) and is
 * closed; nothing is read from it. */
void         fs_dash_auth_set_origin_port (FsDashAuth *auth, guint16 port);
gboolean     fs_dash_auth_listen_link  (FsDashAuth *auth, guint16 port,
                                        GError **error);
const gchar *fs_dash_auth_link_path    (const FsDashAuth *auth);
/* <runtime>/stockfw, the directory of the link sockets. */
gchar       *fs_dash_auth_socket_dir   (const gchar *runtime_dir);

/* WSL: "microsoft" in /proc/sys/kernel/osrelease, or WSLInterop.  The
 * test build reads $STOCKFW_TEST_WSL (1 or 0) first. */
gboolean     fs_dash_is_wsl            (void);

#endif /* FS_DASH_AUTH_H */
