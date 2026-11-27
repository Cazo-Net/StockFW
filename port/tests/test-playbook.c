/*---[ test-playbook.c ]--------------------------------------------------
 * Experimental (FS_EXPERIMENTAL=ON): the XDR playbook records.  These
 * checks were in test-core.sh for 1.0.9; they moved here with the
 * module, which nothing in the program calls yet.
 *--------------------------------------------------------------------*/
#include <glib.h>
#include <string.h>
#include "experimental/fs-playbook.h"

static guint failures = 0;

#define CHECK(cond, msg) do {                                   \
	if (cond) {                                             \
		g_print ("ok:   %s\n", msg);                    \
	} else {                                                \
		g_print ("FAIL: %s\n", msg);                    \
		failures++;                                     \
	}                                                       \
} while (0)

int
main (void)
{
	{
		FsPlaybook *pb = fs_playbook_new ("pb-1", "Test Playbook", "Description",
		                                  FS_PLAYBOOK_TRIGGER_ML_ANOMALY, 50);
		FsXdrIncident *inc;
		gchar *json;

		CHECK (pb != NULL && g_strcmp0 (pb->id, "pb-1") == 0, "playbook created successfully");
		fs_playbook_add_action (pb, FS_XDR_ACTION_BLOCK_IP);
		fs_playbook_add_action (pb, FS_XDR_ACTION_AUDIT_LOG);

		CHECK (fs_playbook_execute (pb, "Malicious beacon detected", 80, NULL, NULL),
		       "playbook executes when risk score >= min_risk_score");
		CHECK (!fs_playbook_execute (pb, "Low risk event", 20, NULL, NULL),
		       "playbook skips execution when risk score < min_risk_score");

		inc = fs_xdr_incident_new ("pb-1", "Malicious beacon detected", 80, TRUE, "Blocked IP 203.0.113.9");
		CHECK (inc != NULL && g_strcmp0 (inc->playbook_id, "pb-1") == 0, "xdr incident created");

		json = fs_xdr_incident_to_json (inc);
		CHECK (json != NULL && strstr (json, "pb-1") != NULL && strstr (json, "80") != NULL,
		       "xdr incident serializes to JSON correctly");

		g_free (json);
		fs_xdr_incident_free (inc);
		fs_playbook_free (pb);
	}
	g_print ("test-playbook: %u failure(s)\n", failures);
	return failures > 0 ? 1 : 0;
}
