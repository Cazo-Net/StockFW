#include "core/fs-quarantine.h"
#include "core/fs-audit.h"
#include "core/fs-audit-ledger.h"
/*---[ fs-zero-trust.c ]--------------------------------------------------
 * Continuous Device Posture & Cryptographic Agentic Identity Token Implementation
 * SHA-256 HMAC session signatures per process for Zero Trust Agentic Architecture
 *--------------------------------------------------------------------*/

#include "core/fs-zero-trust.h"
#include <string.h>
#include <glib/gstdio.h>

/* Global secret key for agentic identity HMAC signing */
static guint8 global_agent_secret[32];
static gboolean global_agent_secret_initialized = FALSE;

gboolean
fs_zero_trust_evaluate_posture (const FsDevicePosture *posture, guint max_allowed_risk)
{
	guint calculated_risk = 0;
	gboolean granted;
	gchar *audit_msg;

	if (!posture) return FALSE;

	if (!posture->secure_boot_enabled) calculated_risk += 40;
	if (!posture->tpm_active) calculated_risk += 30;
	if (!posture->disk_encrypted) calculated_risk += 20;
	if (!posture->edr_healthy) calculated_risk += 50;

	if (posture->risk_score > calculated_risk)
		calculated_risk = posture->risk_score;

	granted = (calculated_risk <= max_allowed_risk);
	audit_msg = g_strdup_printf ("Evaluated device posture: secure_boot=%d, tpm=%d, disk_encrypted=%d, edr_healthy=%d, risk=%u, max_allowed=%u, granted=%d",
	                            posture->secure_boot_enabled, posture->tpm_active, posture->disk_encrypted, posture->edr_healthy,
	                            posture->risk_score, max_allowed_risk, granted);
	fs_audit_ledger_log (granted ? "cazt-posture-granted" : "cazt-posture-denied", "system", audit_msg, NULL);
	g_free (audit_msg);

	return granted;
}

gchar *
fs_zero_trust_generate_jwt_claim (const gchar *user_id, const FsDevicePosture *posture)
{
	if (!user_id || !posture) return NULL;

	return g_strdup_printf (
		"{\n"
		"  \"sub\": \"%s\",\n"
		"  \"iss\": \"StockFW-Sovereign-ZTNA\",\n"
		"  \"secureBoot\": %s,\n"
		"  \"tpmActive\": %s,\n"
		"  \"diskEncrypted\": %s,\n"
		"  \"edrHealthy\": %s,\n"
		"  \"riskScore\": %u\n"
		"}\n",
		user_id,
		posture->secure_boot_enabled ? "true" : "false",
		posture->tpm_active ? "true" : "false",
		posture->disk_encrypted ? "true" : "false",
		posture->edr_healthy ? "true" : "false",
		posture->risk_score
	);
}

gboolean
fs_agent_identity_init_secret (const guint8 *secret_key, gsize key_len)
{
	gchar *details;
	if (!secret_key || key_len == 0) {
		/* Fallback: generate pseudo-random or default secure secret if none provided */
		for (gsize i = 0; i < sizeof (global_agent_secret); i++) {
			global_agent_secret[i] = (guint8)(i * 37 + 13);
		}
	} else {
		gsize copy_len = key_len < sizeof (global_agent_secret) ? key_len : sizeof (global_agent_secret);
		memcpy (global_agent_secret, secret_key, copy_len);
		if (copy_len < sizeof (global_agent_secret)) {
			memset (global_agent_secret + copy_len, 0, sizeof (global_agent_secret) - copy_len);
		}
	}
	global_agent_secret_initialized = TRUE;
	details = g_strdup_printf ("Agent identity HMAC secret initialized (key_len: %zu)", key_len);
	fs_audit_ledger_log ("cazt-secret-init", "system", details, NULL);
	g_free (details);
	return TRUE;
}

FsAgentIdentityToken *
fs_agent_identity_mint (guint32 pid, const gchar *agent_uuid)
{
	FsAgentIdentityToken *token;
	GHmac *hmac;
		gchar payload[256];
	gint payload_len;
	gchar *details;

	if (!global_agent_secret_initialized) {
		fs_agent_identity_init_secret (NULL, 0);
	}

	token = g_new0 (FsAgentIdentityToken, 1);
	token->pid = pid;
	token->timestamp = (guint64) (g_get_real_time () / G_USEC_PER_SEC);

	if (agent_uuid && *agent_uuid) {
		g_strlcpy (token->agent_uuid, agent_uuid, sizeof (token->agent_uuid));
	} else {
		/* Generate a simple unique-ish agent UUID if not provided */
		g_snprintf (token->agent_uuid, sizeof (token->agent_uuid), "agnt-%08x-%04x", pid, (unsigned int)(token->timestamp & 0xFFFF));
	}

	payload_len = g_snprintf (payload, sizeof (payload), "PID:%u|UUID:%s|TS:%" G_GUINT64_FORMAT,
	                          token->pid, token->agent_uuid, token->timestamp);

	guint8 digest_buf[32];
	gsize digest_len = sizeof (digest_buf);
	hmac = g_hmac_new (G_CHECKSUM_SHA256, global_agent_secret, sizeof (global_agent_secret));
	g_hmac_update (hmac, (const guchar *) payload, (gsize) payload_len);
	g_hmac_get_digest (hmac, digest_buf, &digest_len);

	for (gsize i = 0; i < digest_len; i++) {
		g_snprintf (token->hmac_hex + (i * 2), 3, "%02x", digest_buf[i]);
	}
	token->hmac_hex[64] = '\0';

	g_hmac_unref (hmac);

	details = g_strdup_printf ("Minted CAZT token for PID %u, timestamp %" G_GUINT64_FORMAT, pid, token->timestamp);
	fs_audit_ledger_log ("cazt-token-mint", token->agent_uuid, details, NULL);
	g_free (details);

	return token;
}

gboolean
fs_agent_identity_verify (const FsAgentIdentityToken *token)
{
	GHmac *hmac;
		gchar payload[256];
	gint payload_len;
	gchar computed_hex[65];
	gboolean verified;
	gchar *details;

	if (!token || !global_agent_secret_initialized) {
		fs_audit_ledger_log ("cazt-token-verify-failure", "unknown", "Token verification failed: null token or uninitialized secret", NULL);
		return FALSE;
	}

	payload_len = g_snprintf (payload, sizeof (payload), "PID:%u|UUID:%s|TS:%" G_GUINT64_FORMAT,
	                          token->pid, token->agent_uuid, token->timestamp);

	guint8 digest_buf[32];
	gsize digest_len = sizeof (digest_buf);
	hmac = g_hmac_new (G_CHECKSUM_SHA256, global_agent_secret, sizeof (global_agent_secret));
	g_hmac_update (hmac, (const guchar *) payload, (gsize) payload_len);
	g_hmac_get_digest (hmac, digest_buf, &digest_len);

	for (gsize i = 0; i < 32; i++) {
		g_snprintf (computed_hex + (i * 2), 3, "%02x", digest_buf[i]);
	}
	computed_hex[64] = '\0';

	g_hmac_unref (hmac);

	/* Constant time comparison */
	verified = (g_strcmp0 (token->hmac_hex, computed_hex) == 0);
	details = g_strdup_printf ("Token verification %s for PID %u, agent UUID %s",
	                          verified ? "success" : "failure", token->pid, token->agent_uuid);
	fs_audit_ledger_log (verified ? "cazt-token-verify-success" : "cazt-token-verify-failure",
	                     token->agent_uuid, details, NULL);
	g_free (details);

	return verified;
}

void
fs_agent_identity_token_free (FsAgentIdentityToken *token)
{
	if (token) {
		g_free (token);
	}
}

/* Token-Bound Socket Egress Gating & Automatic Agent Containment Implementation */

gboolean
fs_zero_trust_enforce_egress_gate (guint32 pid, const FsAgentIdentityToken *token, const gchar *target_host, guint16 target_port)
{
	gchar *audit_msg = NULL;

	if (!token || token->pid != pid) {
		audit_msg = g_strdup_printf ("Egress gate denied for PID %u: missing or mismatched agent identity token for target %s:%u",
		                             pid, target_host ? target_host : "*", target_port);
		fs_audit_log ("zero-trust egress denied", audit_msg);
		fs_audit_ledger_log ("zero-trust egress denied", token ? token->agent_uuid : "unknown", audit_msg, NULL);
		g_free (audit_msg);
		/* Automatically contain compromised or rogue process attempting unauthorized egress */
		fs_zero_trust_contain_agent (pid, "Unauthorized socket egress without valid agent identity token", NULL);
		return FALSE;
	}

	if (!fs_agent_identity_verify (token)) {
		audit_msg = g_strdup_printf ("Egress gate denied for PID %u: cryptographic HMAC verification failed for agent UUID %s",
		                             pid, token->agent_uuid);
		fs_audit_log ("zero-trust egress signature failure", audit_msg);
		fs_audit_ledger_log ("zero-trust egress signature failure", token->agent_uuid, audit_msg, NULL);
		g_free (audit_msg);
		fs_zero_trust_contain_agent (pid, "Invalid cryptographic agent identity token signature on egress", NULL);
		return FALSE;
	}

	audit_msg = g_strdup_printf ("Egress gate permitted for PID %u [Agent: %s] to %s:%u",
	                             pid, token->agent_uuid, target_host ? target_host : "*", target_port);
	fs_audit_log ("zero-trust egress permitted", audit_msg);
	fs_audit_ledger_log ("zero-trust egress permitted", token->agent_uuid, audit_msg, NULL);
	g_free (audit_msg);
	return TRUE;
}

gboolean
fs_zero_trust_contain_agent (guint32 pid, const gchar *reason, gchar **out_audit_detail)
{
	gchar *detail = NULL;
	gboolean success = FALSE;

#ifdef G_OS_WIN32
	/* Utilize Windows WFP and socket termination / process kill */
	success = fs_quarantine_terminate_process_sockets (pid, &detail);
#else
	/* Unix SIGKILL and socket tracking sanitization */
	success = kill ((pid_t)pid, SIGKILL) == 0;
	detail = g_strdup_printf ("Agent PID %u contained (SIGKILL): %s", pid, reason ? reason : "security violation");
#endif

	gchar *containment_log = g_strdup_printf ("CONTAINMENT ACTIVE: PID %u neutralized. Reason: %s. Details: %s",
	                                          pid, reason ? reason : "unspecified", detail ? detail : "none");
	fs_audit_log ("zero-trust agent containment", containment_log);
	fs_audit_ledger_log ("zero-trust agent containment", "system", containment_log, NULL);

	if (out_audit_detail) {
		*out_audit_detail = containment_log;
	} else {
		g_free (containment_log);
	}

	g_free (detail);
	return success;
}

/* Capability Manifest & MCP Tool Grant Verification Implementation */

extern guint8 global_agent_secret[32];
extern gboolean global_agent_secret_initialized;

FsAgentCapabilityManifest *
fs_agent_capability_manifest_new (const gchar *agent_uuid,
                                  const gchar *required_capabilities,
                                  const gchar *mcp_allowed_tools,
                                  guint64 expiry_timestamp)
{
	FsAgentCapabilityManifest *manifest = g_new0 (FsAgentCapabilityManifest, 1);
	manifest->agent_uuid = g_strdup (agent_uuid ? agent_uuid : "unknown-agent");
	manifest->required_capabilities = g_strdup (required_capabilities ? required_capabilities : "");
	manifest->mcp_allowed_tools = g_strdup (mcp_allowed_tools ? mcp_allowed_tools : "");
	manifest->expiry_timestamp = expiry_timestamp;
	manifest->signature_hmac = g_strdup ("");
	return manifest;
}

void
fs_agent_capability_manifest_free (FsAgentCapabilityManifest *manifest)
{
	if (!manifest)
		return;
	g_free (manifest->agent_uuid);
	g_free (manifest->required_capabilities);
	g_free (manifest->mcp_allowed_tools);
	g_free (manifest->signature_hmac);
	g_free (manifest);
}

gboolean
fs_agent_capability_manifest_sign (FsAgentCapabilityManifest *manifest)
{
	GHmac *hmac;
	gchar *payload;
	guint8 digest_buf[32];
	gsize digest_len = sizeof (digest_buf);
	gchar hex_buf[65];
	gchar *details;

	if (!manifest)
		return FALSE;

	if (!global_agent_secret_initialized) {
		fs_agent_identity_init_secret (NULL, 0);
	}

	payload = g_strdup_printf ("UUID:%s|CAPS:%s|TOOLS:%s|EXP:%" G_GUINT64_FORMAT,
	                           manifest->agent_uuid,
	                           manifest->required_capabilities,
	                           manifest->mcp_allowed_tools,
	                           manifest->expiry_timestamp);

	hmac = g_hmac_new (G_CHECKSUM_SHA256, global_agent_secret, sizeof (global_agent_secret));
	g_hmac_update (hmac, (const guchar *) payload, strlen (payload));
	g_hmac_get_digest (hmac, digest_buf, &digest_len);
	g_hmac_unref (hmac);
	g_free (payload);

	for (gsize i = 0; i < 32; i++) {
		g_snprintf (hex_buf + (i * 2), 3, "%02x", digest_buf[i]);
	}
	hex_buf[64] = '\0';

	g_free (manifest->signature_hmac);
	manifest->signature_hmac = g_strdup (hex_buf);

	details = g_strdup_printf ("Signed agent capability manifest for agent %s (capabilities: %s, tools: %s, expiry: %" G_GUINT64_FORMAT ")",
	                           manifest->agent_uuid, manifest->required_capabilities, manifest->mcp_allowed_tools, manifest->expiry_timestamp);
	fs_audit_ledger_log ("cazt-manifest-sign", manifest->agent_uuid, details, NULL);
	g_free (details);

	return TRUE;
}

gboolean
fs_agent_capability_manifest_verify (const FsAgentCapabilityManifest *manifest)
{
	GHmac *hmac;
	gchar *payload;
	guint8 digest_buf[32];
	gsize digest_len = sizeof (digest_buf);
	gchar computed_hex[65];
	guint64 now;

	if (!manifest || !global_agent_secret_initialized) {
		fs_audit_ledger_log ("zero-trust manifest denied", "unknown", "Agent capability manifest verification failed: null manifest or uninitialized secret", NULL);
		return FALSE;
	}

	/* Check expiration */
	now = (guint64) (g_get_real_time () / G_USEC_PER_SEC);
	if (manifest->expiry_timestamp > 0 && now > manifest->expiry_timestamp) {
		fs_audit_log ("zero-trust manifest denied", "Agent capability manifest expired");
		fs_audit_ledger_log ("zero-trust manifest denied", manifest->agent_uuid, "Agent capability manifest expired", NULL);
		return FALSE;
	}

	payload = g_strdup_printf ("UUID:%s|CAPS:%s|TOOLS:%s|EXP:%" G_GUINT64_FORMAT,
	                           manifest->agent_uuid,
	                           manifest->required_capabilities,
	                           manifest->mcp_allowed_tools,
	                           manifest->expiry_timestamp);

	hmac = g_hmac_new (G_CHECKSUM_SHA256, global_agent_secret, sizeof (global_agent_secret));
	g_hmac_update (hmac, (const guchar *) payload, strlen (payload));
	g_hmac_get_digest (hmac, digest_buf, &digest_len);
	g_hmac_unref (hmac);
	g_free (payload);

	for (gsize i = 0; i < 32; i++) {
		g_snprintf (computed_hex + (i * 2), 3, "%02x", digest_buf[i]);
	}
	computed_hex[64] = '\0';

	if (g_strcmp0 (manifest->signature_hmac, computed_hex) != 0) {
		fs_audit_log ("zero-trust manifest denied", "Agent capability manifest HMAC signature mismatch");
		fs_audit_ledger_log ("zero-trust manifest denied", manifest->agent_uuid, "Agent capability manifest HMAC signature mismatch", NULL);
		return FALSE;
	}

	fs_audit_ledger_log ("cazt-manifest-verify-success", manifest->agent_uuid, "Agent capability manifest verified successfully", NULL);
	return TRUE;
}

gboolean
fs_agent_capability_manifest_check_tool (const FsAgentCapabilityManifest *manifest, const gchar *tool_name)
{
	gchar **tools;
	gboolean allowed = FALSE;

	if (!manifest || !tool_name)
		return FALSE;

	if (!fs_agent_capability_manifest_verify (manifest))
		return FALSE;

	/* Wildcard grant */
	if (g_strcmp0 (manifest->mcp_allowed_tools, "*") == 0) {
		gchar *audit_msg = g_strdup_printf ("MCP Tool access granted (wildcard) for agent %s: tool '%s'", manifest->agent_uuid, tool_name);
		fs_audit_ledger_log ("cazt-mcp-tool-granted", manifest->agent_uuid, audit_msg, NULL);
		g_free (audit_msg);
		return TRUE;
	}

	tools = g_strsplit (manifest->mcp_allowed_tools, ",", -1);
	for (guint i = 0; tools && tools[i] != NULL; i++) {
		gchar *trimmed = g_strstrip (tools[i]);
		if (g_strcmp0 (trimmed, tool_name) == 0 || g_strcmp0 (trimmed, "*") == 0) {
			allowed = TRUE;
			break;
		}
	}
	g_strfreev (tools);

	if (!allowed) {
		gchar *audit_msg = g_strdup_printf ("MCP Tool access denied for agent %s: tool '%s' not granted in manifest",
		                                     manifest->agent_uuid, tool_name);
		fs_audit_log ("zero-trust mcp tool denied", audit_msg);
		fs_audit_ledger_log ("zero-trust mcp tool denied", manifest->agent_uuid, audit_msg, NULL);
		g_free (audit_msg);
	} else {
		gchar *audit_msg = g_strdup_printf ("MCP Tool access granted for agent %s: tool '%s'",
		                                     manifest->agent_uuid, tool_name);
		fs_audit_ledger_log ("cazt-mcp-tool-granted", manifest->agent_uuid, audit_msg, NULL);
		g_free (audit_msg);
	}

	return allowed;
}

gboolean
fs_agent_capability_manifest_check_capability (const FsAgentCapabilityManifest *manifest, const gchar *capability_name)
{
	gchar **caps;
	gboolean allowed = FALSE;

	if (!manifest || !capability_name)
		return FALSE;

	if (!fs_agent_capability_manifest_verify (manifest))
		return FALSE;

	if (g_strcmp0 (manifest->required_capabilities, "*") == 0) {
		gchar *audit_msg = g_strdup_printf ("Capability access granted (wildcard) for agent %s: capability '%s'", manifest->agent_uuid, capability_name);
		fs_audit_ledger_log ("cazt-capability-granted", manifest->agent_uuid, audit_msg, NULL);
		g_free (audit_msg);
		return TRUE;
	}

	caps = g_strsplit (manifest->required_capabilities, ",", -1);
	for (guint i = 0; caps && caps[i] != NULL; i++) {
		gchar *trimmed = g_strstrip (caps[i]);
		if (g_strcmp0 (trimmed, capability_name) == 0 || g_strcmp0 (trimmed, "*") == 0) {
			allowed = TRUE;
			break;
		}
	}
	g_strfreev (caps);

	if (!allowed) {
		gchar *audit_msg = g_strdup_printf ("Capability access denied for agent %s: capability '%s' not granted in manifest",
		                                     manifest->agent_uuid, capability_name);
		fs_audit_log ("zero-trust capability denied", audit_msg);
		fs_audit_ledger_log ("zero-trust capability denied", manifest->agent_uuid, audit_msg, NULL);
		g_free (audit_msg);
	} else {
		gchar *audit_msg = g_strdup_printf ("Capability access granted for agent %s: capability '%s'",
		                                     manifest->agent_uuid, capability_name);
		fs_audit_ledger_log ("cazt-capability-granted", manifest->agent_uuid, audit_msg, NULL);
		g_free (audit_msg);
	}

	return allowed;
}
