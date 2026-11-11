/*---[ fs-zero-trust.h ]--------------------------------------------------
 * Continuous Device Posture & Identity-Aware Zero Trust Policy Engine
 * Part of StockFW Ultimate Extension (Beyond Phase v3.0)
 *
 * Continuously evaluates device security posture (secure boot, disk encryption,
 * active EDR signals, user identity) to dynamically gate network access policies.
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

/* Evaluate current host posture and return whether zero-trust access is granted */
gboolean fs_zero_trust_evaluate_posture (const FsDevicePosture *posture, guint max_allowed_risk);

/* Generate dynamic ZTNA policy rule header */
gchar   *fs_zero_trust_generate_jwt_claim (const gchar *user_id, const FsDevicePosture *posture);

G_END_DECLS

#endif /* FS_ZERO_TRUST_H */
