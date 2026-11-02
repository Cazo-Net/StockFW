/*---[ intel-backend-driver.c ]------------------------------------------
 * Test driver for test-intel-backend.sh: the Linux backend's threat-
 * intel slots (intel_apply, intel_clear, intel_counters, intel_live),
 * called through fs_backend() exactly as the engine calls them, and the
 * policy slots they must coexist with.
 *
 *   fs-intel-backend-driver COMMAND [SPEC]
 *
 *   slots          the four slot names, each "set" or "NULL"
 *   apply SPEC     intel_apply; prints "applied"
 *   digest SPEC    the rule set's digest (no kernel involved)
 *   clear          intel_clear; prints "cleared"
 *   live           intel_live: "present <digest>", "present without
 *                  digest", "absent" or "unknown"
 *   counters       intel_counters: "<id> <packets> <bytes>" per id,
 *                  sorted, or "none" when the slot returns NULL
 *   policy-apply   apply_rules with a one-rule policy (ext device lo)
 *   policy-stop    stop
 *   policy-clear   clear_rules
 *
 * A failing slot prints "error <kind>: <message>" (kind: permission,
 * not-found, timed-out, invalid, failed) and exits 1; bad usage exits
 * 2.  SPEC is a file with one set per line, "<id> <in|out|both>
 * [<range> ...]"; blank lines and '#' comments are skipped (the format
 * of intelset-driver.c).  Built with FS_BACKEND_TESTING, so
 * $STOCKFW_TEST_NFT_TIMEOUT_MS replaces the backend's nft timeouts.
 *--------------------------------------------------------------------*/
#include <gio/gio.h>
#include <stdlib.h>
#include <string.h>

#include "core/fs-backend.h"
#include "core/fs-intelset.h"
#include "core/fs-rules.h"
#include "core/fs-script.h"

static FsIntelRuleset *
load_spec (const gchar *path)
{
	FsIntelRuleset *ruleset;
	GError *error = NULL;
	gchar *text = NULL, **lines;

	if (!g_file_get_contents (path, &text, NULL, &error)) {
		g_printerr ("spec: %s\n", error->message);
		g_error_free (error);
		return NULL;
	}

	ruleset = fs_intel_ruleset_new ();
	lines = g_strsplit (text, "\n", -1);
	g_free (text);
	for (guint i = 0; lines[i] != NULL; i++) {
		gchar *line = g_strstrip (lines[i]);
		gchar **words;
		GPtrArray *fields;
		FsRangeSet *ranges;
		FsIntelDir dir = FS_INTEL_DIR_IN;
		gboolean good = TRUE;

		if (*line == '\0' || *line == '#')
			continue;

		words = g_strsplit_set (line, " \t", -1);
		fields = g_ptr_array_new ();
		for (guint w = 0; words[w] != NULL; w++)
			if (*words[w] != '\0')
				g_ptr_array_add (fields, words[w]);

		if (fields->len < 2 ||
		    !fs_intel_dir_from_string (g_ptr_array_index (fields, 1),
		                               &dir)) {
			g_printerr ("spec line %u: want <id> <in|out|both> "
			            "[<range>...]\n", i + 1);
			good = FALSE;
		}

		ranges = fs_range_set_new ();
		for (guint f = 2; good && f < fields->len; f++) {
			if (!fs_range_set_add_text (ranges,
			                            g_ptr_array_index (fields, f))) {
				g_printerr ("spec line %u: not a range: %s\n", i + 1,
				            (gchar *) g_ptr_array_index (fields, f));
				good = FALSE;
			}
		}
		fs_range_set_normalize (ranges);

		if (good) {
			/* add takes the ranges, also when it refuses */
			if (!fs_intel_ruleset_add (ruleset,
			                           g_ptr_array_index (fields, 0),
			                           NULL, dir, ranges)) {
				g_printerr ("spec line %u: the rule set refused "
				            "id \"%s\"\n", i + 1,
				            (gchar *) g_ptr_array_index (fields, 0));
				good = FALSE;
			}
			ranges = NULL;
		}

		fs_range_set_free (ranges);
		g_ptr_array_unref (fields);
		g_strfreev (words);
		if (!good) {
			g_strfreev (lines);
			fs_intel_ruleset_free (ruleset);
			return NULL;
		}
	}
	g_strfreev (lines);
	return ruleset;
}

static int
fail (GError *error)
{
	const gchar *kind = "failed";

	if (error == NULL) {
		g_print ("error failed: the slot failed without an error\n");
		return 1;
	}
	if (error->domain == G_IO_ERROR) {
		switch (error->code) {
		case G_IO_ERROR_PERMISSION_DENIED: kind = "permission"; break;
		case G_IO_ERROR_NOT_FOUND:         kind = "not-found";  break;
		case G_IO_ERROR_TIMED_OUT:         kind = "timed-out";  break;
		case G_IO_ERROR_INVALID_ARGUMENT:  kind = "invalid";    break;
		default:                           break;
		}
	}
	g_print ("error %s: %s\n", kind, error->message);
	g_error_free (error);
	return 1;
}

static int
cmd_slots (const FsBackend *b)
{
	g_print ("intel_apply %s\n", b->intel_apply != NULL ? "set" : "NULL");
	g_print ("intel_clear %s\n", b->intel_clear != NULL ? "set" : "NULL");
	g_print ("intel_counters %s\n",
	         b->intel_counters != NULL ? "set" : "NULL");
	g_print ("intel_live %s\n", b->intel_live != NULL ? "set" : "NULL");
	return 0;
}

static int
cmd_apply (const FsBackend *b, const gchar *path, gboolean digest_only)
{
	FsIntelRuleset *ruleset = load_spec (path);
	GError *error = NULL;
	int rc = 0;

	if (ruleset == NULL)
		return 2;
	if (digest_only) {
		gchar *digest = fs_intel_ruleset_digest (ruleset);

		g_print ("%s\n", digest);
		g_free (digest);
	} else if (b->intel_apply (ruleset, &error)) {
		g_print ("applied\n");
	} else {
		rc = fail (error);
	}
	fs_intel_ruleset_free (ruleset);
	return rc;
}

static int
cmd_clear (const FsBackend *b)
{
	GError *error = NULL;

	if (!b->intel_clear (&error))
		return fail (error);
	g_print ("cleared\n");
	return 0;
}

static int
cmd_live (const FsBackend *b)
{
	gchar *digest = (gchar *) "not-touched";

	switch (b->intel_live (&digest)) {
	case FS_INTEL_LIVE_PRESENT:
		if (digest == NULL)
			g_print ("present without digest\n");
		else
			g_print ("present %s\n", digest);
		break;
	case FS_INTEL_LIVE_ABSENT:
		/* The contract: NULL when absent. */
		g_print (digest == NULL ? "absent\n" : "absent, digest set\n");
		break;
	default:
		g_print (digest == NULL ? "unknown\n" : "unknown, digest set\n");
		break;
	}
	g_free (digest);
	return 0;
}

static int
cmd_counters (const FsBackend *b)
{
	GHashTable *counters = b->intel_counters ();
	GList *ids;

	if (counters == NULL) {
		g_print ("none\n");
		return 0;
	}
	ids = g_list_sort (g_hash_table_get_keys (counters),
	                   (GCompareFunc) strcmp);
	for (GList *l = ids; l != NULL; l = l->next) {
		const FsIntelCounter *c = g_hash_table_lookup (counters, l->data);

		g_print ("%s %" G_GUINT64_FORMAT " %" G_GUINT64_FORMAT "\n",
		         (const gchar *) l->data, c->packets, c->bytes);
	}
	g_list_free (ids);
	g_hash_table_unref (counters);
	return 0;
}

static int
cmd_policy (const FsBackend *b, const gchar *what)
{
	FsPolicy *policy = fs_policy_new ();
	FsSettings *settings = fs_settings_new ();
	FsRule *rule;
	GError *error = NULL;
	int rc = 0;

	g_free (settings->ext_device);
	settings->ext_device = g_strdup ("lo");
	settings->nat = FALSE;

	rule = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);
	rule->service = g_strdup ("SSH");
	rule->port = g_strdup ("22");
	rule->target = g_strdup ("192.168.1.0/24");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);
	fs_backend_set_context (policy, settings);

	if (strcmp (what, "policy-apply") == 0) {
		FsApplyResult r = b->apply_rules (policy, &error);

		if (r != FS_APPLY_OK)
			rc = fail (error);
		else
			g_print ("policy applied\n");
	} else if (strcmp (what, "policy-stop") == 0) {
		if (!b->stop (&error))
			rc = fail (error);
		else
			g_print ("policy stopped\n");
	} else {
		if (b->clear_rules (&error) != FS_APPLY_OK)
			rc = fail (error);
		else
			g_print ("policy cleared\n");
	}

	fs_backend_set_context (NULL, NULL);
	fs_policy_free (policy);
	fs_settings_free (settings);
	return rc;
}

static int
usage (void)
{
	g_printerr ("usage: fs-intel-backend-driver slots | apply SPEC | "
	            "digest SPEC | clear | live | counters | policy-apply | "
	            "policy-stop | policy-clear\n");
	return 2;
}

int
main (int argc, char **argv)
{
	const FsBackend *b = fs_backend ();

	if (argc == 2 && strcmp (argv[1], "slots") == 0)
		return cmd_slots (b);
	if (b->intel_apply == NULL || b->intel_clear == NULL ||
	    b->intel_counters == NULL || b->intel_live == NULL) {
		g_print ("error failed: this backend has no intel slots\n");
		return 1;
	}
	if (argc == 3 && strcmp (argv[1], "apply") == 0)
		return cmd_apply (b, argv[2], FALSE);
	if (argc == 3 && strcmp (argv[1], "digest") == 0)
		return cmd_apply (b, argv[2], TRUE);
	if (argc == 2 && strcmp (argv[1], "clear") == 0)
		return cmd_clear (b);
	if (argc == 2 && strcmp (argv[1], "live") == 0)
		return cmd_live (b);
	if (argc == 2 && strcmp (argv[1], "counters") == 0)
		return cmd_counters (b);
	if (argc == 2 && g_str_has_prefix (argv[1], "policy-") &&
	    (strcmp (argv[1], "policy-apply") == 0 ||
	     strcmp (argv[1], "policy-stop") == 0 ||
	     strcmp (argv[1], "policy-clear") == 0))
		return cmd_policy (b, argv[1]);
	return usage ();
}
