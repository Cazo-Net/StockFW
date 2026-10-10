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

/* TRUE when addr falls inside the CIDR block cidr ("a.b.c.d/len" or an
 * IPv6 prefix).  Both sides must be numeric addresses -- a hostname is
 * never "inside" a block.  Used by the What-If simulator so a block
 * written as a subnet still covers the host being probed. */
gboolean fs_util_addr_in_cidr (const gchar *cidr, const gchar *addr);

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
 * STOCKFW_RULES_DIR environment variable so the app can run
 * unprivileged for development. */
const gchar *fs_util_rules_dir (void);

/* Convenience: build a path below the rules directory. */
gchar *fs_util_rules_path (const gchar *relative);

/* Human readable form of an FsApplyResult. */
const gchar *fs_util_apply_result_to_string (int result);

/* Case-insensitive substring match of needle against one row of
 * fields.  Empty/NULL needle matches everything (the filter bar with
 * nothing typed).  Fields may contain NULL entries, which never
 * match.  Used by the Events page filter bar; kept here so the core
 * suite can cover the matcher without GTK. */
gboolean fs_util_filter_match (const gchar *needle,
                               const gchar *const *fields,
                               gint n_fields);

/* Returns a copy of text with control characters (C0 and DEL)
 * removed, or NULL for NULL.  Rule names go through this before they
 * appear in any textual output (F-3). */
gchar *fs_util_strip_controls (const gchar *text);

/* Quote-aware CSV, shared by the trust store and the copilot's
 * behavior baseline -- one writer, one parser, so what one writes the
 * other can always read.  fs_util_csv_append_field quotes a field
 * only when it carries a comma, a quote or a newline; `first' skips
 * the separating comma for the first field of a row. */
void fs_util_csv_append_field (GString *out, const gchar *value,
                               gboolean first);

/* Splits one line into fields honouring quotes (" doubled inside a
 * quoted field).  Returns a GPtrArray of gchar*; caller frees with
 * g_ptr_array_unref. */
GPtrArray *fs_util_csv_split_line (const gchar *line);

/* Collects our own rule names out of "netsh advfirewall firewall
 * show rule name=all" output.  netsh prints TEXT records -- a
 * "Rule Name:  <name>" line per rule -- not CSV, and the old
 * comma-splitting parser matched zero names because of it: the clear
 * step removed nothing and every full apply piled another copy of
 * each rule onto the firewall (the 2026-10-10 incident reached 479
 * rules with 28 copies of a single name).  Each line yields one
 * candidate -- the rest of a "Rule Name:" label, or the line up to
 * its first comma (bare name / CSV first field; names never contain
 * commas) -- and only candidates carrying our own prefix are kept, so
 * a foreign rule cannot match, and a delete of a name that does not
 * exist is a clean no-op.  Note: like the elevation matcher, the
 * label match assumes English netsh output.  Returns a new GHashTable
 * of name strings (caller destroys with g_hash_table_destroy). */
GHashTable *fs_netsh_rule_names_extract (const gchar *output);

G_END_DECLS

#endif /* FS_UTIL_H */