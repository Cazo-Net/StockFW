/*---[ fs-changelog.h ]--------------------------------------------------
 * "Changes made by the Copilot", kept on disk (master plan G13, PR 4,
 * package 4B).
 *
 * The desktop app keeps its list of Copilot changes in memory, so an
 * Undo is lost when the window closes.  The terminal makes each change
 * in its own process, so the list is a file: one JSON object per line
 * (JSONL), appended, never edited in place.
 *
 *   {"v":1,"type":"health-fix","id":N,"at":EPOCH,"source":"cli",
 *    "label":"...","fix":"remove"|"replace","kind":"inbound-allow-service",
 *    "index":I,"before":"csv","after":"csv"|null,"anchor":"csv"|null}
 *   {"v":1,"type":"block-rule","id":N,"at":EPOCH,"source":"cli",
 *    "label":"...","kind":"outbound-deny-to","csv":"csv"}
 *   {"v":1,"type":"undone","id":N,"at":EPOCH,"source":"cli"}
 *
 * A health fix carries what fs_health_undo_apply needs (FsHealthUndo).
 * Ids count up from 1 and are never reused.  When the file holds more
 * than FS_CHANGELOG_MAX changes, the oldest go, with their "undone"
 * lines.  A line that does not read is skipped and counted.
 *
 * Linux-only (src/control): the Windows desktop app keeps its own list.
 * The caller holds the policy lock while it writes, so two writers
 * never take the same id.
 *--------------------------------------------------------------------*/
#ifndef FS_CHANGELOG_H
#define FS_CHANGELOG_H

#include <glib.h>
#include "core/fs-health.h"
#include "core/fs-rules.h"

G_BEGIN_DECLS

#define FS_CHANGELOG_MAX 200

typedef enum
{
	FS_CHANGE_HEALTH_FIX,
	FS_CHANGE_BLOCK_RULE
} FsChangeKind;

typedef struct
{
	guint          id;
	gint64         at;
	FsChangeKind   kind;
	gchar         *label;
	gchar         *source;
	FsRuleKind     rule_kind;
	gchar         *csv;        /* block rule: the row added              */
	FsHealthUndo  *undo;       /* health fix: what puts it back          */
	gint64         undone_at;  /* 0: not undone                          */
} FsChange;

void fs_change_free (FsChange *change);

/* $STOCKFW_CHANGELOG_FILE, or copilot-changes.jsonl in the per-user
 * config folder (next to Sentinel's state file).  g_free. */
gchar *fs_changelog_path (void);

/* Every change in the file, oldest first, with undone_at filled in.
 * A missing file is an empty list.  NULL with *error when the file
 * cannot be read.  bad (nullable) counts the lines that did not read. */
GPtrArray *fs_changelog_read (guint *bad, GError **error);

/* The change with this id, or NULL (fs_change_free). */
FsChange *fs_changelog_find (guint id, GError **error);

/* Appends a change; returns its id, or 0 with *error.  The folder is
 * made 0700 and the file 0600 when missing. */
guint fs_changelog_add_health_fix (const FsHealthUndo *undo,
                                   const gchar *source, GError **error);
guint fs_changelog_add_block_rule (FsRuleKind kind, const gchar *csv,
                                   const gchar *source, GError **error);

/* Records that change `id' was undone. */
gboolean fs_changelog_mark_undone (guint id, const gchar *source,
                                   GError **error);

/* "health-fix", "block-rule". */
const gchar *fs_change_kind_name (FsChangeKind kind);

G_END_DECLS

#endif /* FS_CHANGELOG_H */
