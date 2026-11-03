/*---[ fs-cli-trust.c ]-------------------------------------------------
 * `stockfw trust': the desktop app's Trust page in a terminal (master
 * plan PR 4, package 4D).
 *
 * The command table is empty until its package fills it; it is joined
 * in fs-cli-main.c already, so completion and the man page follow.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"

/* === PR4-D === */

const FsCliCommandDef fs_cli_trust_commands[] = {
	{ NULL, NULL, NULL, NULL, NULL }
};

/* === end PR4-D === */
