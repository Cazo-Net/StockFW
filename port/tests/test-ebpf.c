/*---[ test-ebpf.c ]-----------------------------------------------------
 * Unit tests for Rust aya eBPF bytecode loader and map management integration (`fs-ebpf.c`).
 *--------------------------------------------------------------------*/
#include <glib.h>
#include <string.h>
#include "core/fs-ebpf.h"

static guint failures = 0;

#define CHECK(cond, ...) do {                                   \
	if (cond) {                                             \
		g_print ("ok:   " __VA_ARGS__);                 \
	} else {                                                \
		g_print ("FAIL: " __VA_ARGS__);                 \
		failures++;                                     \
	}                                                       \
	g_print ("\n");                                         \
} while (0)

static void
test_ebpf_policy_and_config (void)
{
	FsFwRule rule;
	memset (&rule, 0, sizeof (rule));
	rule.action = FS_ACTION_BLOCK;

	gchar *policy = fs_ebpf_rule_to_tracing_policy (&rule, "/bin/nc");
	CHECK (policy != NULL && strstr (policy, "TracingPolicy") != NULL && strstr (policy, "Sigkill") != NULL,
	       "tracing policy generated correctly for block action");
	g_free (policy);

	gchar *map_cfg = fs_ebpf_generate_map_config ();
	CHECK (map_cfg != NULL && strstr (map_cfg, "STOCKFW_IP_BLOCKMAP") != NULL,
	       "map config generated correctly");
	g_free (map_cfg);

	gchar *sock_prog = fs_ebpf_generate_socket_filter_program ("/bin/bash", FS_ACTION_BLOCK);
	CHECK (sock_prog != NULL && strstr (sock_prog, "stockfw_tc_egress") != NULL,
	       "socket filter program generated correctly");
	g_free (sock_prog);
}

static void
test_ebpf_manager_integration (void)
{
	GError *error = NULL;
	const guint8 dummy_bytecode[] = {
		0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0xf7, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x40, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	FsEbpfManager *mgr = fs_ebpf_manager_load (dummy_bytecode, sizeof (dummy_bytecode), &error);
	CHECK (mgr != NULL && error == NULL, "ebpf manager loaded bytecode successfully");
	if (error) g_clear_error (&error);

	gboolean attached = fs_ebpf_manager_attach (mgr, "eth0", &error);
	CHECK (attached && error == NULL, "ebpf manager attached programs to interface eth0");
	if (error) g_clear_error (&error);

	gboolean updated = fs_ebpf_manager_update_block_rule (mgr, 0x01020304, 24, 1, &error);
	CHECK (updated && error == NULL, "ebpf manager updated O(1) block map rule successfully");
	if (error) g_clear_error (&error);

	fs_ebpf_manager_free (mgr);

	/* Test invalid bytecode (too small) */
	FsEbpfManager *mgr_bad_size = fs_ebpf_manager_load (dummy_bytecode, 4, &error);
	CHECK (mgr_bad_size == NULL && error != NULL, "ebpf manager correctly rejects undersized bytecode");
	g_clear_error (&error);

	/* Test invalid bytecode (bad magic) */
	const guint8 bad_magic[] = { 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00,
	                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	                             0x01, 0x00, 0xf7, 0x00, 0x01, 0x00, 0x00, 0x00,
	                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	                             0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
	                             0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x40, 0x00,
	                             0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
	FsEbpfManager *mgr_bad_magic = fs_ebpf_manager_load (bad_magic, sizeof (bad_magic), &error);
	CHECK (mgr_bad_magic == NULL && error != NULL, "ebpf manager correctly rejects invalid ELF magic");
	g_clear_error (&error);
}

int
main (int argc, char **argv)
{
	g_print ("---[ Running eBPF Integration Tests ]---\n");
	test_ebpf_policy_and_config ();
	test_ebpf_manager_integration ();

	if (failures == 0) {
		g_print ("ALL TESTS PASSED\n");
		return 0;
	} else {
		g_print ("FAILED: %u test(s)\n", failures);
		return 1;
	}
}
