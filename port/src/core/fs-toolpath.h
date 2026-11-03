/*---[ fs-toolpath.h ]---------------------------------------------------
 * Where the system tools StockFW runs come from (1.0.7 release review,
 * SECURITY-1 and SECURITY-2).
 *
 * A privileged process must not let whoever started it choose which
 * program runs under a well-known name:
 *
 *   - Linux, as root: iptables, ip6tables, their -save and -restore
 *     tools, nft and journalctl come from /usr/sbin, /usr/bin, /sbin
 *     or /bin only, and are started by that absolute path.  The PATH of
 *     `sudo -E' or of a sudoers without secure_path is never searched
 *     [S0].  Not root: PATH, as before (the tools cannot change the
 *     firewall then, and a user's own PATH is theirs).
 *
 *   - Windows: every program spawn_capture() starts by a bare name
 *     (netsh.exe, wevtutil.exe, auditpol.exe) is run as
 *     <GetSystemDirectoryW()>\<name>, never through CreateProcess's
 *     search, which looks in the program's own folder and the current
 *     folder before System32 [P14].
 *
 * Test builds only (FS_TOOLPATH_TESTING defined, a copy of this file
 * compiled into a test driver): root searches PATH too, so the suites
 * can put a fake nft or ip6tables-restore first on it; and on Windows
 * a tool in $STOCKFW_TEST_TOOL_DIR is run instead of System32's
 * (test-winlog's fake wevtutil.exe).  Release builds have no such
 * hook.
 *--------------------------------------------------------------------*/
#ifndef FS_TOOLPATH_H
#define FS_TOOLPATH_H

#include <glib.h>

G_BEGIN_DECLS

/* The fixed directories root takes its tools from, in this order. */
#define FS_TOOLPATH_SYSTEM_DIRS "/usr/sbin:/usr/bin:/sbin:/bin"

/* Pure but for the file tests.  The first of `dirs' (':'-separated,
 * absolute entries only; others are skipped) that holds `name' as an
 * executable regular file, as an absolute path (caller frees).  NULL
 * when none does, or when `name' is not a bare file name. */
gchar *fs_toolpath_search (const gchar *name, const gchar *dirs);

/* The program to run for `name' (caller frees), or NULL when it is not
 * installed where this process may take it from (see above). */
gchar *fs_toolpath_find (const gchar *name);

/* Where fs_toolpath_find() looks, for messages: "on PATH" or
 * "in /usr/sbin, /usr/bin, /sbin or /bin". */
const gchar *fs_toolpath_where (void);

/* Pure.  The program CreateProcessW is to run for `argv0' on Windows:
 * a bare name (no '\\', '/' or ':') becomes system_dir\name; a full
 * path (drive letter and backslash, or a \\ UNC path) is kept as it
 * is.  NULL for anything else (empty, a relative path with a folder,
 * "C:name", no system_dir): such a program is refused, never searched
 * for.  Caller frees. */
gchar *fs_toolpath_windows (const gchar *system_dir, const gchar *argv0);

/* $STOCKFW_TEST_TOOL_DIR in a test build (FS_TOOLPATH_TESTING); NULL,
 * always, in a release build. */
const gchar *fs_toolpath_test_dir (void);

G_END_DECLS

#endif /* FS_TOOLPATH_H */
