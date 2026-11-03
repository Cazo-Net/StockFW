/*---[ pr4-live-driver.c ]-----------------------------------------------
 * PR 4 (4A) against the real Linux backend, for tests/test-cli.sh,
 * which runs it inside a private network namespace (unshare -n):
 *
 *   fs-pr4-live-driver add-block ADDR   fs_firewall_add_live with one
 *                                       outbound-deny-to ADDR row
 *   fs-pr4-live-driver lift-dest ADDR   fs_autoblock_lift_for_dest
 *   fs-pr4-live-driver lift-expired     fs_autoblock_lift_expired, now
 *
 * The policy, journal, audit and Sentinel state files are wherever the
 * environment points them ($STOCKFW_RULES_DIR, $STOCKFW_APPLIED_FILE,
 * $STOCKFW_AUDIT_FILE, $STOCKFW_AUTOBLOCK_FILE).  The backend gets the
 * saved settings, as `stockfw apply' gives it.  Prints one line,
 * "applied=N held=N result=WORD was=N" ("none" when nothing was live;
 * the word is "recorded-for-next-start" for a stopped firewall), and
 * exits 0 unless the call failed.  Never installed.
 *--------------------------------------------------------------------*/
#include <glib.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-apply.h"
#include "core/fs-autoblock.h"
#include "core/fs-backend.h"
#include "core/fs-prefs.h"
#include "core/fs-rules.h"
#include "core/fs-script.h"
#include "core/fs-util.h"

static int
report (const FsApplyOutcome *o, const GError *error)
{
	if (o == NULL) {
		printf ("none%s%s\n", error != NULL ? ": " : "",
		        error != NULL ? error->message : "");
		return error != NULL ? 1 : 0;
	}
	printf ("applied=%d held=%d result=%s was=%d%s%s\n", o->applied,
	        o->held,
	        !o->held && o->result == FS_APPLY_DRY_RUN &&
	        o->firewall_was == FS_FW_STOPPED
	        ? "recorded-for-next-start"
	        : fs_util_apply_result_to_string ((int) o->result),
	        (int) o->firewall_was, error != NULL ? " error: " : "",
	        error != NULL ? error->message : "");
	return (o->result == FS_APPLY_OK || o->result == FS_APPLY_DRY_RUN)
	       ? 0 : 1;
}

int
main (int argc, char **argv)
{
	FsPolicy *policy = fs_policy_new ();
	FsSettings *settings;
	GError *error = NULL;
	int rc;

	if (argc < 2) {
		fprintf (stderr, "usage: %s add-block ADDR | lift-dest ADDR | "
		         "lift-expired\n", argv[0]);
		return 2;
	}

	fs_prefs_load ();
	settings = fs_settings_new ();
	fs_settings_load_prefs (settings);
	fs_policy_load (policy, NULL);
	fs_backend_set_context (policy, settings);

	if (strcmp (argv[1], "add-block") == 0 && argc == 3) {
		FsPolicy *add = fs_policy_new ();
		FsRule *r = fs_rule_new (FS_RULE_OUTBOUND_DENY_TO);
		FsApplyOutcome *o;

		r->target = g_strdup (argv[2]);
		r->comment = g_strdup ("");
		fs_policy_add (add, r);
		fs_rule_free (r);
		o = fs_firewall_add_live (fs_backend (), add, "pr4 test", NULL,
		                          &error);
		rc = report (o, error);
		fs_apply_outcome_free (o);
		fs_policy_free (add);
	} else if ((strcmp (argv[1], "lift-dest") == 0 && argc == 3) ||
	           (strcmp (argv[1], "lift-expired") == 0 && argc == 2)) {
		FsAutoblockLift *res = argc == 3
			? fs_autoblock_lift_for_dest (fs_backend (), policy,
			                              argv[2], NULL, "pr4 test",
			                              NULL, &error)
			: fs_autoblock_lift_expired (fs_backend (), policy,
			                             g_get_real_time () /
			                             G_USEC_PER_SEC, "pr4 test",
			                             NULL, &error);

		if (res == NULL) {
			printf ("refused: %s\n", error != NULL ? error->message
			                                       : "?");
			rc = 1;
		} else {
			printf ("rows=%u removed=%u gone=%u kept=%u ", res->rows,
			        res->removed, res->gone, res->kept);
			rc = report (res->outcome, error);
		}
		fs_autoblock_lift_free (res);
	} else {
		fprintf (stderr, "usage: %s add-block ADDR | lift-dest ADDR | "
		         "lift-expired\n", argv[0]);
		rc = 2;
	}

	g_clear_error (&error);
	return rc;
}
