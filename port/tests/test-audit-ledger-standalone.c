#include <glib.h>
#include <stdio.h>
#include <string.h>
#include "core/fs-audit-ledger.h"

int main (void)
{
	gchar *dir = g_dir_make_tmp ("stockfw-audit-XXXXXX", NULL);
	gchar *ledger_file = g_build_filename (dir, "audit-ledger.log", NULL);
	g_setenv ("STOCKFW_AUDIT_LEDGER_FILE", ledger_file, TRUE);
	g_free (ledger_file);

	gchar *h1 = NULL, *h2 = NULL;
	gboolean ok1 = fs_audit_ledger_log ("EVENT_ONE", "admin", "details one", &h1);
	gboolean ok2 = fs_audit_ledger_log ("EVENT_TWO", "system", "details two", &h2);

	g_assert (ok1);
	g_assert (ok2);
	g_assert (h1 != NULL);
	g_assert (h2 != NULL);

	gchar *path = fs_audit_ledger_path ();
	GPtrArray *entries = fs_audit_ledger_load (path);
	g_assert (entries != NULL);
	g_assert_cmpint (entries->len, ==, 2);

	gboolean valid = fs_audit_ledger_verify_chain (entries);
	g_assert (valid);

	gchar *root = fs_audit_ledger_compute_merkle_root (entries);
	g_assert (root != NULL);
	printf ("Computed Merkle root: %s\n", root);
	g_free (root);

	/* Tamper with entry */
	FsAuditLedgerEntry *e = g_ptr_array_index (entries, 0);
	g_free (e->details);
	e->details = g_strdup ("tampered");

	gboolean valid_tampered = fs_audit_ledger_verify_chain (entries);
	g_assert (!valid_tampered);

	g_ptr_array_free (entries, TRUE);
	g_free (h1);
	g_free (h2);
	g_free (path);
	g_free (dir);

	printf ("ALL AUDIT LEDGER TESTS PASSED!\n");
	return 0;
}
