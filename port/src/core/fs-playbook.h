/*---[ fs-playbook.h ]---------------------------------------------------
 * Local Automated Security Playbooks & XDR Response Triggers Engine
 *
 * Provides automated incident response (SOAR) capabilities: defines security
 * playbooks, evaluates security events and ML/Zero-Trust threat verdicts,
 * and executes automated XDR response triggers (network isolation, auto-blocking,
 * trust revocation, and tamper-evident audit logging).
 *--------------------------------------------------------------------*/
#ifndef FS_PLAYBOOK_H
#define FS_PLAYBOOK_H

#include <glib.h>
#include "core/fs-types.h"
#include "core/fs-rules.h"
#include "core/fs-backend.h"
#include "core/fs-zero-trust.h"

G_BEGIN_DECLS

typedef enum
{
	FS_PLAYBOOK_TRIGGER_ML_ANOMALY = 0,
	FS_PLAYBOOK_TRIGGER_BRUTE_FORCE,
	FS_PLAYBOOK_TRIGGER_C2_BEACON,
	FS_PLAYBOOK_TRIGGER_POSTURE_BREACH,
	FS_PLAYBOOK_TRIGGER_KEV_MATCH,
	FS_PLAYBOOK_TRIGGER_CUSTOM
} FsPlaybookTriggerType;

typedef enum
{
	FS_XDR_ACTION_BLOCK_IP = 0,
	FS_XDR_ACTION_ISOLATE_HOST,
	FS_XDR_ACTION_REVOKE_TRUST,
	FS_XDR_ACTION_AUDIT_LOG,
	FS_XDR_ACTION_NOTIFY_USER
} FsXdrActionType;

typedef struct
{
	gchar                *id;
	gchar                *name;
	gchar                *description;
	FsPlaybookTriggerType trigger_type;
	guint                 min_risk_score;
	gboolean              enabled;
	GArray               *actions; /* array of FsXdrActionType */
} FsPlaybook;

typedef struct
{
	gchar                 *playbook_id;
	gchar                 *event_summary;
	guint                  risk_score;
	gint64                 timestamp_epoch;
	gboolean               actions_executed;
	gchar                 *details;
} FsXdrIncident;

/* Playbook management */
FsPlaybook *fs_playbook_new (const gchar *id, const gchar *name, const gchar *description, FsPlaybookTriggerType trigger_type, guint min_risk_score);
void        fs_playbook_free (FsPlaybook *playbook);
void        fs_playbook_add_action (FsPlaybook *playbook, FsXdrActionType action);

/* XDR Response Engine execution */
gboolean    fs_playbook_execute (const FsPlaybook *playbook, const gchar *event_summary, guint risk_score, FsPolicy *policy, FsBackend *backend);

/* Incident report generation */
FsXdrIncident *fs_xdr_incident_new (const gchar *playbook_id, const gchar *event_summary, guint risk_score, gboolean executed, const gchar *details);
void           fs_xdr_incident_free (FsXdrIncident *incident);
gchar         *fs_xdr_incident_to_json (const FsXdrIncident *incident);

G_END_DECLS

#endif /* FS_PLAYBOOK_H */
