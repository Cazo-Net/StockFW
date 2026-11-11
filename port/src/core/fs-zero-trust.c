/*---[ fs-zero-trust.c ]--------------------------------------------------
 * Continuous Device Posture & Identity-Aware Zero Trust Policy Implementation
 *--------------------------------------------------------------------*/

#include "core/fs-zero-trust.h"
#include <string.h>

gboolean
fs_zero_trust_evaluate_posture (const FsDevicePosture *posture, guint max_allowed_risk)
{
	if (!posture) return FALSE;

	guint calculated_risk = 0;
	if (!posture->secure_boot_enabled) calculated_risk += 40;
	if (!posture->tpm_active) calculated_risk += 30;
	if (!posture->disk_encrypted) calculated_risk += 20;
	if (!posture->edr_healthy) calculated_risk += 50;

	if (posture->risk_score > calculated_risk)
		calculated_risk = posture->risk_score;

	return (calculated_risk <= max_allowed_risk);
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
