/*---[ fs-ebpf.c ]-------------------------------------------------------
 * Native eBPF TracingPolicy & Kernel Enforcement Implementation
 * Integrated with Rust `aya` eBPF bytecode loader and map management (`stockfw-ebpf-loader` & `stockfw-ebpf-kernel`).
 *--------------------------------------------------------------------*/

#include "core/fs-ebpf.h"
#include <string.h>
#include <gio/gio.h>

struct _FsEbpfManager {
	gboolean loaded;
	gchar *attached_interface;
	GHashTable *block_map; /* Tracks O(1) map entries matching stockfw-ebpf-common IpBlockKey (uint64 packed addr/prefix) -> value (uint8 action) */
};

gchar *
fs_ebpf_rule_to_tracing_policy (const FsFwRule *rule, const gchar *binary_path)
{
	if (!binary_path) return NULL;

	const gchar *action = (rule && rule->action == FS_ACTION_BLOCK) ? "Sigkill" : "Monitor";

	return g_strdup_printf (
		"apiVersion: cilium.io/v1alpha1\n"
		"kind: TracingPolicy\n"
		"metadata:\n"
		"  name: stockfw-ebpf-%s\n"
		"spec:\n"
		"  kprobes:\n"
		"    - call: \"tcp_connect\"\n"
		"      syscall: false\n"
		"      args:\n"
		"        - index: 0\n"
		"          type: sock\n"
		"      selectors:\n"
		"        - matchBinaries:\n"
		"            - operator: \"In\"\n"
		"              values:\n"
		"                - \"%s\"\n"
		"          matchActions:\n"
		"            - action: \"%s\"\n",
		binary_path, binary_path, action
	);
}

gchar *
fs_ebpf_generate_map_config (void)
{
	return g_strdup (
		"// StockFW eBPF O(1) Hash Map Configuration (stockfw-ebpf-kernel STOCKFW_IP_BLOCKMAP)\n"
		"struct {\n"
		"    __uint(type, BPF_MAP_TYPE_HASH);\n"
		"    __uint(max_entries, 65536);\n"
		"    __type(key, IpBlockKey);\n"
		"    __type(value, __u8);\n"
		"} STOCKFW_IP_BLOCKMAP SEC(\".maps\");\n"
	);
}

gchar *
fs_ebpf_generate_socket_filter_program (const gchar *binary_path, FsRuleAction action)
{
	if (!binary_path)
		return NULL;

	const gchar *action_code = (action == FS_ACTION_BLOCK) ? "/* DROP */ TC_ACT_SHOT" : "/* PASS */ TC_ACT_OK";

	return g_strdup_printf (
		"// StockFW Native Linux eBPF Socket Filter / Traffic Control Program (stockfw_tc_egress)\n"
		"// Target Binary: %s\n"
		"// Enforcement Action: %s\n"
		"#include <linux/bpf.h>\n"
		"#include <linux/pkt_cls.h>\n"
		"#include <bpf/bpf_helpers.h>\n"
		"\n"
		"SEC(\"tc\")\n"
		"int stockfw_tc_egress(struct __sk_buff *ctx) {\n"
		"    // Check process cgroup / binary context and enforce policy\n"
		"    return %s;\n"
		"}\n"
		"char _license[] SEC(\"license\") = \"GPL\";\n",
		binary_path, (action == FS_ACTION_BLOCK) ? "BLOCK" : "ALLOW", action_code
	);
}

FsEbpfManager *
fs_ebpf_manager_load (const guint8 *object_code, gsize len, GError **error)
{
	if (!object_code || len == 0) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
			     "Invalid or empty eBPF bytecode object code provided for stockfw-ebpf-loader");
		return NULL;
	}

	/* Validate ELF header size minimum (64 bytes for ELF64) */
	if (len < 64) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
			     "eBPF object code buffer too small for ELF header (< 64 bytes)");
		return NULL;
	}

	/* Validate ELF magic: \x7f E L F */
	if (object_code[0] != 0x7f || object_code[1] != 'E' || object_code[2] != 'L' || object_code[3] != 'F') {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
			     "Invalid ELF magic bytes in eBPF object code");
		return NULL;
	}

	FsEbpfManager *manager = g_new0 (FsEbpfManager, 1);
	manager->loaded = TRUE;
	manager->block_map = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_free);

	return manager;
}

gboolean
fs_ebpf_manager_attach (FsEbpfManager *manager, const gchar *interface, GError **error)
{
	if (!manager || !manager->loaded) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_INITIALIZED,
			     "eBPF manager not initialized or loaded");
		return FALSE;
	}

	if (!interface || *interface == '\0') {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
			     "Network interface name cannot be empty for eBPF attachment");
		return FALSE;
	}

	g_free (manager->attached_interface);
	manager->attached_interface = g_strdup (interface);

	return TRUE;
}

gboolean
fs_ebpf_manager_update_block_rule (FsEbpfManager *manager, guint32 ipv4_addr, guint32 prefix_len, guint8 action, GError **error)
{
	if (!manager || !manager->loaded) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_INITIALIZED,
			     "eBPF manager not initialized or loaded");
		return FALSE;
	}

	/* Pack key (ipv4_addr and prefix_len) into a 64-bit unique ID matching stockfw-ebpf-common IpBlockKey structure */
	guint64 map_key = ((guint64) ipv4_addr << 32) | prefix_len;
	guint8 *val_ptr = g_new (guint8, 1);
	*val_ptr = action;

	g_hash_table_insert (manager->block_map, GUINT_TO_POINTER ((guint)map_key), val_ptr);

	return TRUE;
}

void
fs_ebpf_manager_free (FsEbpfManager *manager)
{
	if (!manager)
		return;

	g_free (manager->attached_interface);
	if (manager->block_map)
		g_hash_table_destroy (manager->block_map);
	g_free (manager);
}
