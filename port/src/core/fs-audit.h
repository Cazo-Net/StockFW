/*---[ fs-audit.h ]------------------------------------------------------
 * Append-only local audit record.
 *
 * Closes the "attempted to cover their tracks" row of the threat model:
 * every detection, auto-block, undo and expiry is written to a file
 * that the application only ever appends to.  The path is overridable
 * (STOCKFW_AUDIT_FILE) so tests point it somewhere disposable.
 *--------------------------------------------------------------------*/
#ifndef FS_AUDIT_H
#define FS_AUDIT_H

#include <glib.h>

G_BEGIN_DECLS

/* Where entries are written.  Honours $STOCKFW_AUDIT_FILE, otherwise
 * the audit.log next to the preferences file.  Caller frees. */
gchar *fs_audit_path (void);

/* Append one line:  <ISO-8601 UTC> | <action> | <detail>
 * Returns TRUE when the line reached the file.  A failing audit write
 * never aborts the caller -- it returns FALSE so the caller can warn. */
gboolean fs_audit_log (const gchar *action, const gchar *detail);

G_END_DECLS

#endif /* FS_AUDIT_H */
