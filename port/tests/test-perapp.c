/*---[ test-perapp.c ]--------------------------------------------------
 * Unit tests for Per-Application Firewall Rules (StockFW 1.0.8)
 *--------------------------------------------------------------------*/
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include "core/fs-rules.h"
#include "core/fs-fwrule.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	if (!(cond)) {                                             \
		printf ("FAIL: ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
		failures++;                                         \
	} else {                                                  \
		printf ("ok:   ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
	}                                                         \
} while (0)

int main (void)
{
	FsRule *r1, *r2;
	gchar *csv1, *csv2;
	FsRule *parsed1, *parsed2;
	FsFwRule *fw1;
	GStrv args1;
	gboolean found_program = FALSE;

	/* 1. Rule with program path (with spaces) */
	r1 = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_SERVICE);
	r1->service = g_strdup ("HTTPS");
	r1->port = g_strdup ("443");
	r1->target = g_strdup ("Anyone");
	r1->comment = g_strdup ("Web browsing");
	r1->program = g_strdup ("C:\\Program Files\\Mozilla Firefox\\firefox.exe");

	CHECK (fs_rule_validate (r1, NULL), "rule with program path validates successfully");

	csv1 = fs_rule_to_csv (r1);
	CHECK (csv1 != NULL && strstr (csv1, "C:\\Program Files\\Mozilla Firefox\\firefox.exe") != NULL,
	       "CSV export includes program path: %s", csv1 ? csv1 : "(null)");

	parsed1 = fs_rule_from_csv (FS_RULE_OUTBOUND_ALLOW_SERVICE, csv1);
	CHECK (parsed1 != NULL, "CSV parse succeeds for per-app rule");
	CHECK (g_strcmp0 (parsed1->program, r1->program) == 0,
	       "parsed program matches original: %s", parsed1->program ? parsed1->program : "(null)");

	/* 2. Legacy rule without program path */
	r2 = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);
	r2->service = g_strdup ("SSH");
	r2->port = g_strdup ("22");
	r2->target = g_strdup ("Anyone");
	r2->comment = g_strdup ("Remote admin");

	csv2 = fs_rule_to_csv (r2);
	parsed2 = fs_rule_from_csv (FS_RULE_INBOUND_ALLOW_SERVICE, csv2);
	CHECK (parsed2 != NULL, "legacy 4-field rule parse succeeds");
	CHECK (parsed2->program == NULL, "legacy rule has NULL program");

	/* 3. FsFwRule translation and netsh args emission for per-app rule */
	{
		GList *out = NULL;
		FsPolicy *p = fs_policy_new ();
		fs_policy_add (p, r1);

		guint expanded = fs_fwrule_expand (p, &out);
		CHECK (expanded > 0 && out != NULL, "policy with per-app rule expands to concrete rules (got %u)", expanded);
		if (out != NULL) {
			fw1 = out->data;
			CHECK (g_strcmp0 (fw1->program, r1->program) == 0, "FsFwRule inherits program path");

			args1 = fs_fwrule_netsh_args (fw1);
			CHECK (args1 != NULL, "netsh args generated for per-app rule");
			for (int i = 0; args1[i] != NULL; i++) {
				if (g_str_has_prefix (args1[i], "program=")) {
					found_program = TRUE;
					CHECK (g_strcmp0 (args1[i], "program=C:\\Program Files\\Mozilla Firefox\\firefox.exe") == 0,
					       "netsh arg has exact program path: %s", args1[i]);
				}
			}
			CHECK (found_program, "program= argument emitted in netsh argv");
			g_strfreev (args1);
			fs_fwrule_list_free (out);
		}
		fs_policy_free (p);
	}

	fs_rule_free (r1);
	fs_rule_free (r2);
	g_free (csv1);
	g_free (csv2);
	fs_rule_free (parsed1);
	fs_rule_free (parsed2);

	printf ("\n");
	if (failures == 0) {
		printf ("PASSED: 0 failure(s)\n");
		return 0;
	} else {
		printf ("FAILED: %d failure(s)\n", failures);
		return 1;
	}
}
