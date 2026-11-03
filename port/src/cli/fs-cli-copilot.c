/*---[ fs-cli-copilot.c ]-----------------------------------------------
 * `stockfw copilot' and `stockfw sentinel': the desktop app's Copilot
 * page and Sentinel in a terminal (master plan PR 4, package 4B):
 * `sentinel lift TARGET|--all|--expired', `sentinel mode', `copilot
 * scan|show|block|checks|health|changes'.  Writes go through
 * fs_control_do; blocks go live through fs_firewall_add_live and lifts
 * through the fs_autoblock_lift_* helpers (core, 4A).
 *
 * The command table is empty until its package fills it; it is joined
 * in fs-cli-main.c already, so completion and the man page follow.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"

/* === PR4-B === */

const FsCliCommandDef fs_cli_copilot_commands[] = {
	{ NULL, NULL, NULL, NULL, NULL }
};

/* === end PR4-B === */
