/*---[ intelset-driver.c ]-----------------------------------------------
 * Test driver for test-intelset.sh: the threat-intel rule set against a
 * real nft, the way the Linux backend's intel slots use it.
 *
 *   fs-intelset-driver [--timeout-ms N] COMMAND [SPEC]
 *
 *   script SPEC   print the nft script for the rule set in SPEC
 *   digest SPEC   print the rule set's digest
 *   check SPEC    `nft -c' the script; prints "ok"
 *   apply SPEC    apply it in one transaction; prints "applied <digest>"
 *   clear         remove the table; prints "cleared"
 *   live          "present <digest>", "present without digest", "absent",
 *                 or "unknown" (exit 1) when nft's listing cannot be read
 *   counters      "<id> <packets> <bytes>" per id, sorted by id
 *
 * SPEC is a file with one set per line, "<id> <in|out|both> [<range>
 * ...]"; blank lines and '#' comments are skipped.  --timeout-ms gives
 * nft that long instead of FS_NFT_TIMEOUT_MS.  Exit 0 on success, 1
 * when nft fails (the message starts with "error: "), 2 on bad usage.
 *--------------------------------------------------------------------*/
#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include "core/fs-intelset.h"
#include "core/fs-nftset.h"

static guint timeout_ms = 0;   /* 0: the defaults */

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

		/* Split on runs of blanks. */
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

		if (good && !fs_intel_ruleset_add (ruleset,
		                                   g_ptr_array_index (fields, 0),
		                                   NULL, dir, ranges)) {
			g_printerr ("spec line %u: the rule set refused id \"%s\"\n",
			            i + 1, (gchar *) g_ptr_array_index (fields, 0));
			ranges = NULL;   /* add took it */
			good = FALSE;
		} else if (good) {
			ranges = NULL;   /* add took it */
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

static gboolean
run_script (const gchar *script, gboolean check_only, GError **error)
{
	if (timeout_ms > 0)
		return fs_nft_run_script_full (script, check_only, timeout_ms,
		                               error);
	return fs_nft_run_script (script, check_only, error);
}

static gchar *
capture (const gchar *const *args, GError **error)
{
	return fs_nft_capture (args, timeout_ms > 0 ? timeout_ms :
	                       FS_NFT_TIMEOUT_MS, error);
}

static int
fail (GError *error)
{
	g_print ("error: %s\n", error->message);
	g_error_free (error);
	return 1;
}

static int
cmd_with_spec (const gchar *cmd, const gchar *path)
{
	FsIntelRuleset *ruleset = load_spec (path);
	GError *error = NULL;
	gchar *script, *digest;
	int rc = 0;

	if (ruleset == NULL)
		return 2;

	script = fs_intelset_nft_script (ruleset);
	digest = fs_intel_ruleset_digest (ruleset);
	if (script == NULL) {
		g_printerr ("no script: the rule set is not renderable\n");
		rc = 2;
	} else if (strcmp (cmd, "script") == 0) {
		g_print ("%s", script);
	} else if (strcmp (cmd, "digest") == 0) {
		g_print ("%s\n", digest);
	} else if (strcmp (cmd, "check") == 0) {
		if (run_script (script, TRUE, &error))
			g_print ("ok\n");
		else
			rc = fail (error);
	} else if (strcmp (cmd, "apply") == 0) {
		/* What the Linux backend's intel_apply does: the whole
		 * script, one nft call, one transaction. */
		if (run_script (script, FALSE, &error))
			g_print ("applied %s\n", digest);
		else
			rc = fail (error);
	} else {
		g_printerr ("unknown command: %s\n", cmd);
		rc = 2;
	}

	g_free (digest);
	g_free (script);
	fs_intel_ruleset_free (ruleset);
	return rc;
}

static int
cmd_clear (void)
{
	gchar *script = fs_intelset_nft_clear_script ();
	GError *error = NULL;
	int rc = 0;

	if (run_script (script, FALSE, &error))
		g_print ("cleared\n");
	else
		rc = fail (error);
	g_free (script);
	return rc;
}

static int
cmd_live (void)
{
	static const gchar *const args[] = { "-j", "list", "tables", NULL };
	GError *error = NULL;
	gchar *json = capture (args, &error);
	gchar *digest = NULL;
	int rc = 0;

	if (json == NULL)
		return fail (error);
	switch (fs_intelset_nft_parse_live_state (json, &digest)) {
	case FS_INTEL_LIVE_PRESENT:
		if (digest == NULL)
			g_print ("present without digest\n");
		else
			g_print ("present %s\n", digest);
		break;
	case FS_INTEL_LIVE_ABSENT:
		g_print ("absent\n");
		break;
	default:
		/* What intel_live reports as "cannot tell". */
		g_print ("unknown\n");
		rc = 1;
		break;
	}
	g_free (digest);
	g_free (json);
	return rc;
}

static int
cmd_counters (void)
{
	static const gchar *const chains[] = { "input", "output", "forward" };
	GString *listing = g_string_new (NULL);
	GHashTable *counters;
	GList *ids;

	/* One chain at a time, never the table: listing the table would
	 * print every set element [S8.3]. */
	for (guint c = 0; c < G_N_ELEMENTS (chains); c++) {
		const gchar *args[] = { "list", "chain", "inet",
		                        FS_INTEL_NFT_TABLE, chains[c], NULL };
		GError *error = NULL;
		gchar *text = capture (args, &error);

		if (text == NULL) {
			g_string_free (listing, TRUE);
			return fail (error);
		}
		g_string_append (listing, text);
		g_free (text);
	}

	counters = fs_intelset_nft_parse_counters (listing->str);
	ids = g_list_sort (g_hash_table_get_keys (counters),
	                   (GCompareFunc) strcmp);
	for (GList *l = ids; l != NULL; l = l->next) {
		const FsIntelCounter *c = g_hash_table_lookup (counters, l->data);

		g_print ("%s %" G_GUINT64_FORMAT " %" G_GUINT64_FORMAT "\n",
		         (const gchar *) l->data, c->packets, c->bytes);
	}
	g_list_free (ids);
	g_hash_table_unref (counters);
	g_string_free (listing, TRUE);
	return 0;
}

static int
usage (void)
{
	g_printerr ("usage: fs-intelset-driver [--timeout-ms N] "
	            "script|digest|check|apply SPEC | clear | live | "
	            "counters\n");
	return 2;
}

int
main (int argc, char **argv)
{
	int a = 1;

	if (argc > a + 1 && strcmp (argv[a], "--timeout-ms") == 0) {
		timeout_ms = (guint) strtoul (argv[a + 1], NULL, 10);
		if (timeout_ms == 0)
			return usage ();
		a += 2;
	}
	if (argc <= a)
		return usage ();

	if (strcmp (argv[a], "clear") == 0 && argc == a + 1)
		return cmd_clear ();
	if (strcmp (argv[a], "live") == 0 && argc == a + 1)
		return cmd_live ();
	if (strcmp (argv[a], "counters") == 0 && argc == a + 1)
		return cmd_counters ();
	if (argc == a + 2)
		return cmd_with_spec (argv[a], argv[a + 1]);
	return usage ();
}
