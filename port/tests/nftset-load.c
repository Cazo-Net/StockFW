/*---[ nftset-load.c ]---------------------------------------------------
 * Test driver for test-nftset.sh: fs_nftset_load_csv() on one file.
 *   nftset-load FILE [TABLE [SET]]
 * Prints the counts on success, the error on failure (exit 1).
 *--------------------------------------------------------------------*/
#include <glib.h>
#include "core/fs-nftset.h"

int
main (int argc, char **argv)
{
	FsBlocklistStats st;
	GError *error = NULL;

	if (argc < 2) {
		g_printerr ("usage: nftset-load FILE [TABLE [SET]]\n");
		return 2;
	}
	if (!fs_nftset_load_csv (argv[1],
	                         argc > 2 ? argv[2] : FS_NFT_BLOCKLIST_TABLE,
	                         argc > 3 ? argv[3] : "blocklist",
	                         &st, &error)) {
		g_print ("error: %s\n", error->message);
		g_error_free (error);
		return 1;
	}
	g_print ("loaded: %u entries, %u skipped, header %s, "
	         "%u overlapped protected ranges\n",
	         st.entries, st.skipped, st.header ? "yes" : "no",
	         st.protected_hits);
	return 0;
}
