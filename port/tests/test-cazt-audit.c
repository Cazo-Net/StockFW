#include <glib.h>
#include <stdio.h>
#include <string.h>
#include "core/fs-audit-ledger.h"
#include "core/fs-zero-trust.h"

int main (void)
{
	gchar *dir = g_dir_make_tmp ("stockfw-cazt-audit-XXXXXX", NULL);
	gchar *ledger_file = g_build_filename (dir, "audit-ledger.log", NULL);
	g_setenv ("STOCKFW_AUDIT_LEDGER_FILE", ledger_file, TRUE);
	g_free (ledger_file);

	/* 1. Initialize secret */
	fs_agent_identity_init_secret ((const guint8 *)"test-secret-key-32bytes-long-string!", 32);

	/* 2. Evaluate posture */
	FsDevicePosture posture = {
		.secure_boot_enabled = TRUE,
		.tpm_active = TRUE,
		.disk_encrypted = TRUE,
		.edr_healthy = TRUE,
		.risk_score = 10
	};
	gboolean posture_ok = fs_zero_trust_evaluate_posture (&posture, 50);
	g_assert (posture_ok);

	/* 3. Mint token */
	FsAgentIdentityToken *token = fs_agent_identity_mint (12345, "agnt-test-uuid-0001");
	g_assert (token != NULL);

	/* 4. Verify token */
	gboolean token_valid = fs_agent_identity_verify (token);
	g_assert (token_valid);

	/* 5. Enforce egress gate */
	gboolean egress_ok = fs_zero_trust_enforce_egress_gate (12345, token, "192.168.1.100", 443);
	g_assert (egress_ok);

	/* 6. Capability manifest sign and check */
	FsAgentCapabilityManifest *manifest = fs_agent_capability_manifest_new (
		"agnt-test-uuid-0001", "network,read", "exec,fetch,*",
		(guint64)(g_get_real_time () / G_USEC_PER_SEC + 3600)
	);
	gboolean signed_ok = fs_agent_capability_manifest_sign (manifest);
	g_assert (signed_ok);

	gboolean tool_ok = fs_agent_capability_manifest_check_tool (manifest, "exec");
	g_assert (tool_ok);

	gboolean cap_ok = fs_agent_capability_manifest_check_capability (manifest, "network");
	g_assert (cap_ok);

	fs_agent_capability_manifest_free (manifest);
	fs_agent_identity_token_free (token);

	/* Load ledger and verify chain integrity */
	gchar *path = fs_audit_ledger_path ();
	GPtrArray *entries = fs_audit_ledger_load (path);
	g_assert (entries != NULL);
	g_assert_cmpint (entries->len, >, 0);

	gboolean chain_valid = fs_audit_ledger_verify_chain (entries);
	g_assert (chain_valid);

	gchar *merkle_root = fs_audit_ledger_compute_merkle_root (entries);
	g_assert (merkle_root != NULL);
	printf ("CAZT Audit Ledger Merkle Root: %s (Entries: %u)\n", merkle_root, entries->len);
	g_free (merkle_root);

	g_ptr_array_free (entries, TRUE);
	g_free (path);
	g_free (dir);

	printf ("ALL CAZT AUDIT LEDGER TESTS PASSED SUCCESSFULLY!\n");
	return 0;
}
