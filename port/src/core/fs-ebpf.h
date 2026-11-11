/*---[ fs-ebpf.h ]-------------------------------------------------------
 * Native Rust eBPF Datapath & Kernel Enforcement Engine (`aya` integration)
 * Part of StockFW Phase v2.0 (The Autonomous Sovereign Fabric)
 *
 * Generates and manages eBPF tracing policies and O(1) kernel hash-map rule
 * lookups. Issues SIGKILL before malicious syscalls complete (<0.5ms).
 *--------------------------------------------------------------------*/
#ifndef FS_EBPF_H
#define FS_EBPF_H

#include <glib.h>
#include "core/fs-fwrule.h"

G_BEGIN_DECLS

/* Opaque eBPF manager handle for Rust aya loader / map management integration */
typedef struct _FsEbpfManager FsEbpfManager;

/* Generate Tetragon / Aya compatible eBPF TracingPolicy YAML for a StockFW rule */
gchar *fs_ebpf_rule_to_tracing_policy (const FsFwRule *rule, const gchar *binary_path);

/* Generate eBPF kernel map lookup configuration */
gchar *fs_ebpf_generate_map_config (void);

/* Generate native Linux eBPF socket filter program source code (XDP/TC egress & ingress) */
gchar *fs_ebpf_generate_socket_filter_program (const gchar *binary_path, FsRuleAction action);

/* eBPF Bytecode Loader and Map Management Integration API (`aya` integration) */

/* Create / initialize eBPF manager and load compiled eBPF bytecode object code */
FsEbpfManager *fs_ebpf_manager_load (const guint8 *object_code, gsize len, GError **error);

/* Attach loaded eBPF programs (kprobes, TC filters) to network interface or kernel functions */
gboolean fs_ebpf_manager_attach (FsEbpfManager *manager, const gchar *interface, GError **error);

/* Update O(1) kernel hash map (STOCKFW_IP_BLOCKMAP) with IPv4 block rule key and action */
gboolean fs_ebpf_manager_update_block_rule (FsEbpfManager *manager, guint32 ipv4_addr, guint32 prefix_len, guint8 action, GError **error);

/* Free eBPF manager resources */
void fs_ebpf_manager_free (FsEbpfManager *manager);

G_END_DECLS

#endif /* FS_EBPF_H */
