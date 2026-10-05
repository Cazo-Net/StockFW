/*---[ fs-util.h ]-------------------------------------------------------
 * Small helpers with no home of their own.  Portable: pure GLib and
 * stdio, no platform calls, no GTK.
 *--------------------------------------------------------------------*/
#ifndef FS_UTIL_H
#define FS_UTIL_H

#include <glib.h>
#include "core/fs-types.h"

G_BEGIN_DECLS

/* Validation.  Both accept empty/NULL as "not set" and return FALSE. */
gboolean fs_util_is_valid_port (const gchar *port);
gboolean fs_util_is_valid_host (const gchar *host);

/* TRUE when a policy target means "every host", so no address match
 * should be emitted.  Shared by the script generator and the rule
 * translator. */
gboolean fs_util_target_is_anyone (const gchar *target);

/* Returns the text between the first marker1 and the following marker2,
 * newly allocated, or NULL.  Free with g_free. */
gchar *fs_util_get_text_between (const gchar *string,
                                 const gchar *marker1,
                                 const gchar *marker2);

/* Reverse DNS with a timeout.  Returns the host name or a copy of the
 * address on failure. */
gchar *fs_util_lookup_ip (const gchar *ip);

/* Appends data to a text file, creating it if needed.  When newline is
 * TRUE a trailing '\n' is added. */
gboolean fs_util_append_to_file (const gchar *path, const gchar *data,
                                 gboolean newline);

/* Removes the 1-based line from a text file, rewriting it. */
gboolean fs_util_remove_line_from_file (const gchar *path, gint position);

/* Ensures every parent directory of path exists. */
gboolean fs_util_ensure_parent_dir (const gchar *path);

/* Directory holding the generated policy files.  Overridable with the
 * FIRESTARTER_RULES_DIR environment variable so the app can run
 * unprivileged for development. */
const gchar *fs_util_rules_dir (void);

/* Convenience: build a path below the rules directory. */
gchar *fs_util_rules_path (const gchar *relative);

/* Human readable form of an FsApplyResult. */
const gchar *fs_util_apply_result_to_string (int result);

G_END_DECLS

#endif /* FS_UTIL_H */