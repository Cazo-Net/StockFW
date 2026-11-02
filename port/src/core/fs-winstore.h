/*---[ fs-winstore.h ]---------------------------------------------------
 * The threat-intel store on Windows (1.0.7, Round 3; design 6.1 and
 * 11.5, [S3]): %ProgramData%\StockFW\intel, which only Administrators
 * and SYSTEM can open, and the file operations fs-intel.c runs in it.
 *
 * Linux keeps a directory descriptor and works relative to it (openat,
 * renameat).  Windows has no such call in Win32, so the store is pinned
 * instead: a handle on the directory, opened without FILE_SHARE_DELETE,
 * which nobody can rename or delete while it is held (nor any parent
 * of it), so the path keeps naming the directory that was checked.
 * Files are opened with FILE_FLAG_OPEN_REPARSE_POINT and refused when
 * they are links, written to a fresh name and moved over the old one
 * (MOVEFILE_WRITE_THROUGH), and read with a size cap, as on Linux.
 *
 * Declared everywhere, defined only on Windows: fs-intel.c calls these
 * only under G_OS_WIN32, and the file compiles to nothing elsewhere
 * (tests/test-core.sh builds every core file on Linux too).
 *--------------------------------------------------------------------*/
#ifndef FS_WINSTORE_H
#define FS_WINSTORE_H

#include <glib.h>

G_BEGIN_DECLS

/* The store's directory, created on first use, or NULL with
 * FS_INTEL_ERROR set:
 *   - default: %ProgramData%\StockFW\intel (the folder from
 *     SHGetFolderPathW, never from the environment).  StockFW needs
 *     to be running as administrator (FS_INTEL_ERR_NEEDS_ROOT
 *     otherwise).  %ProgramData%\StockFW is created readable by Users
 *     and writable by Administrators and SYSTEM only; intel inside it
 *     by Administrators and SYSTEM only (protected DACLs, nothing
 *     inherited from %ProgramData%, which lets every user create
 *     folders).  An existing one must be owned by Administrators,
 *     SYSTEM or TrustedInstaller, grant no other account a right to
 *     change it, and be no link; otherwise FS_INTEL_ERR_UNSAFE_DIR,
 *     never used: a folder another account made first ("squatting")
 *     is refused.  An intel folder others can read is set back to
 *     Administrators and SYSTEM only.
 *   - $STOCKFW_INTEL_DIR (absolute): the same checks on it and its
 *     parent, where the current user is trusted too (so a folder in
 *     the user's own profile works for the tests); created with
 *     SYSTEM, Administrators and the current user when missing.
 * Caller frees. */
gchar   *fs_winstore_dir (GError **error);

/* Whether the store directory exists, found without creating it. */
gboolean fs_winstore_exists (void);

/* Pin `dir' (fs_winstore_dir()'s answer): open it without delete
 * sharing, and check through the handle that it is still a directory,
 * no link, and still safe.  NULL with FS_INTEL_ERR_UNSAFE_DIR. */
gpointer fs_winstore_pin   (const gchar *dir, GError **error);
void     fs_winstore_unpin (gpointer pin);

/* One file in the pinned directory: a plain name (no separator, no
 * ':', not "." or ".."), no link, a regular file, at most `cap' bytes,
 * NUL-terminated.  *missing set when it does not exist.  Errors are
 * FS_INTEL_ERR_STORE. */
gchar   *fs_winstore_read   (const gchar *dir, const gchar *name, gsize cap,
                             gsize *len, gboolean *missing, GError **error);
/* Write a whole file: a fresh temporary name, flushed, moved over the
 * old one with MOVEFILE_WRITE_THROUGH.  The file takes the directory's
 * inherited access list (Administrators and SYSTEM). */
gboolean fs_winstore_write  (const gchar *dir, const gchar *name,
                             const gchar *data, gsize len, GError **error);
/* Remove a file; a missing one is not an error. */
gboolean fs_winstore_unlink (const gchar *dir, const gchar *name,
                             GError **error);

/* The engine lock (fs-intel.c, design 11.12): `name' in the pinned
 * directory, created when missing, opened with read and write sharing
 * and without following a link (a link or a directory there is
 * refused), then locked exclusively with LockFileEx on its first byte.
 * Byte-range locks belong to the handle, so two threads of one process
 * exclude each other, as two processes do.  *waited is set when
 * another holder had it first.  Returns the handle, or NULL when the
 * file cannot be opened or locked (the caller then goes ahead
 * unlocked, as on Linux).  fs_winstore_unlock unlocks and closes it;
 * NULL is accepted. */
gpointer fs_winstore_lock   (const gchar *dir, const gchar *name,
                             gboolean *waited);
void     fs_winstore_unlock (gpointer lock);

/* A file the user chose to import: a regular disk file, at most `cap'
 * bytes, NUL-terminated.  FS_INTEL_ERR_INVALID otherwise. */
gchar   *fs_winstore_read_user_file (const gchar *path, gsize cap,
                                     gsize *len, GError **error);

/* Whether this process runs with administrator rights now (elevated:
 * a UAC-filtered token is not). */
gboolean fs_winstore_is_admin (void);

G_END_DECLS

#endif /* FS_WINSTORE_H */
