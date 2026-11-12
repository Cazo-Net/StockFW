/*---[ fs-zero-trust.h ]--------------------------------------------------
 * Continuous Device Posture & Cryptographic Agentic Identity Tokens
 * Part of StockFW Ultimate Extension (Beyond Phase v3.0)
 *
 * Continuously evaluates device security posture and provides per-process
 * cryptographic agentic identity tokens (SHA-256 HMAC session signatures).
 *--------------------------------------------------------------------*/
#ifndef FS_ZERO_TRUST_H
#define FS_ZERO_TRUST_H

#include <glib.h>

G_BEGIN_DECLS

typedef struct
{
	gboolean secure_boot_enabled;
	gboolean tpm_active;
	gboolean disk_encrypted;
	gboolean edr_healthy;
	guint    risk_score;       /* 0 (secure) to 100 (compromised) */
} FsDevicePosture;

typedef struct
{
	guint32 pid;
	guint64 timestamp;
	gchar   agent_uuid[37];
	gchar   hmac_hex[65];
} FsAgentIdentityToken;

/* Evaluate current host posture and return whether zero-trust access is granted */
gboolean fs_zero_trust_evaluate_posture (const FsDevicePosture *posture, guint max_allowed_risk);

/* Generate dynamic ZTNA policy rule header */
gchar   *fs_zero_trust_generate_jwt_claim (const gchar *user_id, const FsDevicePosture *posture);

/* Cryptographic Agentic Identity Token APIs (SHA-256 HMAC session signatures per process) */
gboolean fs_agent_identity_init_secret (const guint8 *secret_key, gsize key_len);
FsAgentIdentityToken *fs_agent_identity_mint (guint32 pid, const gchar *agent_uuid);
gboolean fs_agent_identity_verify (const FsAgentIdentityToken *token);
void fs_agent_identity_token_free (FsAgentIdentityToken *token);

/* Token-Bound Socket Egress Gating & Automatic Agent Containment APIs */
gboolean fs_zero_trust_enforce_egress_gate (guint32 pid, const FsAgentIdentityToken *token, const gchar *target_host, guint16 target_port);
gboolean fs_zero_trust_contain_agent (guint32 pid, const gchar *reason, gchar **out_audit_detail);

/* Capability Manifest & MCP Tool Grant Verification for AI Agents & Tool Interception */
typedef struct
{
	gchar   *agent_uuid;
	gchar   *required_capabilities; /* comma-separated list or JSON array/string */
	gchar   *mcp_allowed_tools;     /* comma-separated list of allowed Model Context Protocol tools */
	gchar   *signature_hmac;        /* cryptographic HMAC signature over manifest fields */
	guint64  expiry_timestamp;
} FsAgentCapabilityManifest;

FsAgentCapabilityManifest *fs_agent_capability_manifest_new (const gchar *agent_uuid,
                                                              const gchar *required_capabilities,
                                                              const gchar *mcp_allowed_tools,
                                                              guint64 expiry_timestamp);
void fs_agent_capability_manifest_free (FsAgentCapabilityManifest *manifest);

/* Sign manifest using the global agent secret */
gboolean fs_agent_capability_manifest_sign (FsAgentCapabilityManifest *manifest);

/* Verify manifest signature, expiration, and whether requested tool/capability is authorized */
gboolean fs_agent_capability_manifest_verify (const FsAgentCapabilityManifest *manifest);
gboolean fs_agent_capability_manifest_check_tool (const FsAgentCapabilityManifest *manifest, const gchar *tool_name);
gboolean fs_agent_capability_manifest_check_capability (const FsAgentCapabilityManifest *manifest, const gchar *capability_name);

G_END_DECLS

#endif /* FS_ZERO_TRUST_H */
