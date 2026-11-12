/*---[ fs-l7.h ]---------------------------------------------------------
 * L7 Protocol & AI-Agent Egress Governance Engine
 * Part of StockFW Phase v1.3 (The L7 & AI Governor)
 *
 * Provides zero-proxy native DNS query inspection, TLS ClientHello SNI parsing,
 * and AI agent / MCP server egress governance rules.
 *--------------------------------------------------------------------*/
#ifndef FS_L7_H
#define FS_L7_H

#include <glib.h>

G_BEGIN_DECLS

typedef enum
{
	FS_L7_VERDICT_ALLOW = 0,
	FS_L7_VERDICT_BLOCK_DNS_TUNNEL,
	FS_L7_VERDICT_BLOCK_C2_DOMAIN,
	FS_L7_VERDICT_THROTTLE_LLM_EXFIL
} FsL7Verdict;

/* Inspect a DNS query packet payload for entropy and blocklist matching */
FsL7Verdict fs_l7_inspect_dns (const guint8 *packet_data, gsize packet_len, gchar *out_domain, gsize domain_max);

/* Inspect a TLS ClientHello packet for SNI (Server Name Indication) */
FsL7Verdict fs_l7_inspect_tls_sni (const guint8 *packet_data, gsize packet_len, gchar *out_sni, gsize sni_max);

/* Check if an outbound connection to an LLM / MCP endpoint exceeds payload limits */
gboolean fs_l7_govern_llm_egress (const gchar *process_name, const gchar *endpoint_url, guint64 payload_bytes);

G_END_DECLS

#endif /* FS_L7_H */
