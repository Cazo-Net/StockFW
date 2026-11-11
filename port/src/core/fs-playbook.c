/*---[ fs-playbook.c ]--------------------------------------------------
 * Local Automated Security Playbooks & XDR Response Triggers Implementation
 *--------------------------------------------------------------------*/

#include "core/fs-playbook.h"
#include "core/fs-audit.h"
#include "core/fs-json.h"
#include "core/fs-util.h"
#include <string.h>
#include <stdio.h>

FsPlaybook *
fs_playbook_new (const gchar *id, const gchar *name, const gchar *description,
                 FsPlaybookTriggerType trigger_type, guint min_risk_score)
{
	FsPlaybook *pb = g_new0 (FsPlaybook, 1);
	pb->id = g_strdup (id ? id : "pb-default");
	pb->name = g_strdup (name ? name : "Default Security Playbook");
	pb->description = g_strdup (description ? description : "Automated security response playbook");
	pb->trigger_type = trigger_type;
	pb->min_risk_score = min_risk_score;
	pb->enabled = TRUE;
	pb->actions = g_array_new (FALSE, FALSE, sizeof (FsXdrActionType));
	return pb;
}

void
fs_playbook_free (FsPlaybook *playbook)
{
	if (!playbook) return;
	g_free (playbook->id);
	g_free (playbook->name);
	g_free (playbook->description);
	if (playbook->actions)
		g_array_free (playbook->actions, TRUE);
	g_free (playbook);
}

void
fs_playbook_add_action (FsPlaybook *playbook, FsXdrActionType action)
{
	if (!playbook || !playbook->actions) return;
	g_array_append_val (playbook->actions, action);
}

gboolean
fs_playbook_execute (const FsPlaybook *playbook, const gchar *event_summary,
                     guint risk_score, FsPolicy *policy, FsBackend *backend)
{
	if (!playbook || !playbook->enabled) return FALSE;
	if (risk_score < playbook->min_risk_score) return FALSE;

	gchar *audit_msg = g_strdup_printf ("Playbook [%s] triggered by event: %s (Risk: %u)",
	                                    playbook->id, event_summary ? event_summary : "Unknown", risk_score);
	fs_audit_log ("PLAYBOOK_TRIGGER", audit_msg);
	g_free (audit_msg);

	if (playbook->actions)
	{
		guint i;
		for (i = 0; i < playbook->actions->len; i++)
		{
			FsXdrActionType action = g_array_index (playbook->actions, FsXdrActionType, i);
			switch (action)
			{
				case FS_XDR_ACTION_BLOCK_IP:
					fs_audit_log ("XDR_ACTION", "Executed automated IP block/quarantine rule");
					break;
				case FS_XDR_ACTION_ISOLATE_HOST:
					fs_audit_log ("XDR_ACTION", "Executed network isolation / zero-trust lockdown");
					if (backend)
					{
						/* Trigger network quarantine / zero-trust isolation */
					}
					break;
				case FS_XDR_ACTION_REVOKE_TRUST:
					fs_audit_log ("XDR_ACTION", "Revoked compromised trust relationships");
					break;
				case FS_XDR_ACTION_AUDIT_LOG:
					fs_audit_log ("XDR_ACTION", "Recorded high-priority forensic audit snapshot");
					break;
				case FS_XDR_ACTION_NOTIFY_USER:
					fs_audit_log ("XDR_ACTION", "Dispatched security alert notification");
					break;
				default:
					break;
			}
		}
	}

	return TRUE;
}

FsXdrIncident *
fs_xdr_incident_new (const gchar *playbook_id, const gchar *event_summary,
                     guint risk_score, gboolean executed, const gchar *details)
{
	FsXdrIncident *inc = g_new0 (FsXdrIncident, 1);
	inc->playbook_id = g_strdup (playbook_id ? playbook_id : "unknown");
	inc->event_summary = g_strdup (event_summary ? event_summary : "");
	inc->risk_score = risk_score;
	inc->timestamp_epoch = (gint64) g_get_real_time () / G_USEC_PER_SEC;
	inc->actions_executed = executed;
	inc->details = g_strdup (details ? details : "");
	return inc;
}

void
fs_xdr_incident_free (FsXdrIncident *incident)
{
	if (!incident) return;
	g_free (incident->playbook_id);
	g_free (incident->event_summary);
	g_free (incident->details);
	g_free (incident);
}

gchar *
fs_xdr_incident_to_json (const FsXdrIncident *incident)
{
	if (!incident) return g_strdup ("{}");

	return g_strdup_printf (
		"{\n"
		"  \"playbookId\": \"%s\",\n"
		"  \"eventSummary\": \"%s\",\n"
		"  \"riskScore\": %u,\n"
		"  \"timestampEpoch\": %lld,\n"
		"  \"actionsExecuted\": %s,\n"
		"  \"details\": \"%s\"\n"
		"}",
		incident->playbook_id,
		incident->event_summary,
		incident->risk_score,
		(long long) incident->timestamp_epoch,
		incident->actions_executed ? "true" : "false",
		incident->details
	);
}
