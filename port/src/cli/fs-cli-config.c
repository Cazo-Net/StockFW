/*---[ fs-cli-config.c ]-------------------------------------------------
 * `stockfw config': reading and changing the preferences from the
 * terminal (master plan, PR 3, package 3C).  Every write goes through
 * the control layer (control/fs-control.h: settings.set and
 * settings.apply), which checks the keys with fs_prefs_validate and
 * saves them with fs_prefs_set_persist under the policy lock.
 *
 * Package 3A leaves the table empty and registered, so 3C adds its
 * commands here without touching the registry, and completion and the
 * manual page follow the table.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"

const FsCliCommandDef fs_cli_config_commands[] = {
	{ NULL, NULL, NULL, NULL, NULL }
};
