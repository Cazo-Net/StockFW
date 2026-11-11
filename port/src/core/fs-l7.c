/*---[ fs-l7.c ]---------------------------------------------------------
 * L7 Protocol & AI-Agent Egress Governance Implementation
 *--------------------------------------------------------------------*/
#include "core/fs-l7.h"
#include <string.h>
#include <stdio.h>
#include <math.h>

static double
calculate_entropy (const gchar *str)
{
	if (!str || *str == '\0') return 0.0;
	gsize len = strlen (str);
	guint counts[256] = {0};
	for (gsize i = 0; i < len; i++) {
		counts[(unsigned char)str[i]]++;
	}

	double entropy = 0.0;
	for (int i = 0; i < 256; i++) {
		if (counts[i] > 0) {
			double freq = (double)counts[i] / len;
			entropy -= freq * log2 (freq);
		}
	}
	return entropy;
}

FsL7Verdict
fs_l7_inspect_dns (const guint8 *packet_data, gsize packet_len, gchar *out_domain, gsize domain_max)
{
	if (!packet_data || packet_len < 12) return FS_L7_VERDICT_ALLOW;

	/* Basic DNS header check and query name extraction simulation */
	// A real implementation parses DNS question section (labels)
	const gchar *sample_domain = "query.example.com";
	if (out_domain) {
		g_strlcpy (out_domain, sample_domain, domain_max);
	}

	double entropy = calculate_entropy (sample_domain);
	if (entropy > 4.5 || packet_len > 512) {
		return FS_L7_VERDICT_BLOCK_DNS_TUNNEL;
	}

	return FS_L7_VERDICT_ALLOW;
}

FsL7Verdict
fs_l7_inspect_tls_sni (const guint8 *packet_data, gsize packet_len, gchar *out_sni, gsize sni_max)
{
	if (!packet_data || packet_len < 43) return FS_L7_VERDICT_ALLOW;

	/* TLS Handshake / ClientHello SNI extension inspection simulation */
	const gchar *sample_sni = "api.openai.com";
	if (out_sni) {
		g_strlcpy (out_sni, sample_sni, sni_max);
	}

	if (g_strcmp0 (sample_sni, "malicious-c2-beacon.evil") == 0) {
		return FS_L7_VERDICT_BLOCK_C2_DOMAIN;
	}

	return FS_L7_VERDICT_ALLOW;
}

gboolean
fs_l7_govern_llm_egress (const gchar *process_name, const gchar *endpoint_url, guint64 payload_bytes)
{
	/* Enforce strict payload limits for LLM and MCP agent traffic (e.g., max 2MB outbound per request) */
	const guint64 MAX_LLM_PAYLOAD_BYTES = 1024 * 1024 * 2; /* 2 MB */

	if (payload_bytes > MAX_LLM_PAYLOAD_BYTES) {
		return FALSE; /* Block or throttle */
	}

	return TRUE; /* Allowed */
}
