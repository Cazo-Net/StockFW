/*---[ fs-cli-help.c ]--------------------------------------------------
 * `stockfw help topics|TOPIC|--search WORD' and `stockfw about': the
 * desktop app's Help and About in a terminal (master plan PR 4,
 * package 4E).
 *
 * The command table is empty until its package fills it; it is joined
 * in fs-cli-main.c already, so completion and the man page follow.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"

/* === PR4-E === */

const FsCliCommandDef fs_cli_help_commands[] = {
	{ NULL, NULL, NULL, NULL, NULL }
};

/* === end PR4-E === */
