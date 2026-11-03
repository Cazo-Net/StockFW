/*---[ fs-cli-views.c ]--------------------------------------------------
 * Read-only views over StockFW's own records: `stockfw audit' (the
 * audit log) and `stockfw sentinel list' (Sentinel's staged blocks).
 * Both are WP-C's (cli-plan.md section 4); the table is here so the
 * registry already joins it.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"

/* === WP-C === */
/* === end WP-C === */

/* ------------------------------------------------------- the commands */

const FsCliCommandDef fs_cli_views_commands[] = {
	/* === WP-C commands === */
	/* === end WP-C commands === */
	{ NULL, NULL, NULL, NULL, NULL }
};
