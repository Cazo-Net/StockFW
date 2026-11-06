/*---[ fs-cli-act.h ]----------------------------------------------------
 * What `events act' and `simulate --do' (fs-cli-act.c, master plan PR 4,
 * package 4C) take from `apply' (fs-cli-policy.c): the guarded send to
 * the control layer, the apply's own text and JSON, and the preview of
 * `apply --dry-run'.  Private to the command line.
 *--------------------------------------------------------------------*/
#ifndef FS_CLI_ACT_H
#define FS_CLI_ACT_H

#include <glib.h>
#include "control/fs-control.h"

G_BEGIN_DECLS

/* An op the lockout guard stands in front of: the warning, the question
 * on a terminal (or --yes), and the op sent again with "yes".  `verb'
 * is the question's ("Apply"); `lock' gets the "lockout" JSON member;
 * *status is FS_EXIT_FAILURE when the user did not confirm. */
FsControlResult *fs_cli_control_guarded (const gchar *op, GVariant *base,
                                         gboolean yes, const gchar *verb,
                                         GString *lock, gint *status);
/* `apply's text for an outcome, its JSON members, its exit status. */
void fs_cli_apply_print        (const FsControlResult *r);
void fs_cli_apply_json_members (GString *out, const FsControlResult *r,
                                const gchar *lock);
gint fs_cli_apply_status       (const FsApplyOutcome *outcome);
/* What applying `after' would do, as `apply --dry-run' says it, and the
 * lockout guard's warning; with json a "preview" member instead. */
void fs_cli_apply_preview      (const FsPolicy *after, GString *json);

G_END_DECLS

#endif /* FS_CLI_ACT_H */
