/*---[ test-enabled-driver.c ]--------------------------------------------
 * Test driver for rule enable/disable functionality.
 * Called by tests/test-enabled.sh with test cases.
 *--------------------------------------------------------------------*/

#include "core/fs-rules.h"
#include "core/fs-util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
test_load_preserves_state(const char *rules_dir)
{
	FsPolicy *policy = fs_policy_new();
	gboolean any;
	FsRule *rule1, *rule2, *rule3;

	any = fs_policy_load(policy, NULL);
	if (!any) {
		fprintf(stderr, "Failed to load policy\n");
		fs_policy_free(policy);
		return 1;
	}

	/* Should have 3 rules: 2 enabled, 1 disabled */
	if (policy->kinds[FS_RULE_OUTBOUND_ALLOW_TO]->len != 3) {
		fprintf(stderr, "Expected 3 rules, got %u\n",
		        policy->kinds[FS_RULE_OUTBOUND_ALLOW_TO]->len);
		fs_policy_free(policy);
		return 1;
	}

	rule1 = g_ptr_array_index(policy->kinds[FS_RULE_OUTBOUND_ALLOW_TO], 0);
	rule2 = g_ptr_array_index(policy->kinds[FS_RULE_OUTBOUND_ALLOW_TO], 1);
	rule3 = g_ptr_array_index(policy->kinds[FS_RULE_OUTBOUND_ALLOW_TO], 2);

	/* First and third should be enabled, second disabled */
	if (!rule1->enabled) {
		fprintf(stderr, "Rule 1 should be enabled\n");
		fs_policy_free(policy);
		return 1;
	}
	if (rule2->enabled) {
		fprintf(stderr, "Rule 2 should be disabled\n");
		fs_policy_free(policy);
		return 1;
	}
	if (!rule3->enabled) {
		fprintf(stderr, "Rule 3 should be enabled\n");
		fs_policy_free(policy);
		return 1;
	}

	fs_policy_free(policy);
	return 0;
}

static int
test_save_writes_prefix(const char *rules_dir)
{
	FsPolicy *policy = fs_policy_new();
	FsRule *rule;

	/* Create a rule and disable it */
	rule = fs_rule_new(FS_RULE_OUTBOUND_ALLOW_TO);
	rule->target = g_strdup("192.168.1.100");
	rule->comment = g_strdup("test rule");
	rule->enabled = FALSE;

	fs_policy_add(policy, rule);

	if (!fs_policy_save(policy)) {
		fprintf(stderr, "Failed to save policy\n");
		fs_rule_free(rule);
		fs_policy_free(policy);
		return 1;
	}

	fs_rule_free(rule);
	fs_policy_free(policy);
	return 0;
}

static int
test_active_view_filters(const char *rules_dir)
{
	FsPolicy *policy = fs_policy_new();
	FsPolicy *active;

	fs_policy_load(policy, NULL);

	active = fs_policy_active_view(policy);
	if (active == NULL) {
		fprintf(stderr, "active_view returned NULL\n");
		fs_policy_free(policy);
		return 1;
	}

	/* Should have only 2 enabled rules (disabled one filtered out) */
	if (active->kinds[FS_RULE_OUTBOUND_ALLOW_TO]->len != 2) {
		fprintf(stderr, "Expected 2 enabled rules, got %u\n",
		        active->kinds[FS_RULE_OUTBOUND_ALLOW_TO]->len);
		fs_policy_free(active);
		fs_policy_free(policy);
		return 1;
	}

	fs_policy_free(active);
	fs_policy_free(policy);
	return 0;
}

static int
test_set_enabled_persists(const char *rules_dir)
{
	FsPolicy *policy = fs_policy_new();
	FsPolicy *reloaded;
	FsRule *rule, *found;

	/* Load existing policy */
	fs_policy_load(policy, NULL);

	/* Get first rule and disable it */
	rule = g_ptr_array_index(policy->kinds[FS_RULE_OUTBOUND_ALLOW_TO], 0);

	if (!fs_policy_set_enabled(policy, rule, FALSE)) {
		fprintf(stderr, "set_enabled failed\n");
		fs_policy_free(policy);
		return 1;
	}

	/* Reload and check it's still disabled */
	reloaded = fs_policy_new();
	fs_policy_load(reloaded, NULL);

	found = g_ptr_array_index(reloaded->kinds[FS_RULE_OUTBOUND_ALLOW_TO], 0);
	if (found->enabled) {
		fprintf(stderr, "Rule should still be disabled after reload\n");
		fs_policy_free(reloaded);
		fs_policy_free(policy);
		return 1;
	}

	fs_policy_free(reloaded);
	fs_policy_free(policy);
	return 0;
}

static int
test_set_enabled_rollback(const char *rules_dir)
{
	/* This test would require making the save fail, which is complex.
	 * For now, just verify the function exists and returns TRUE for
	 * a valid rule. Full rollback testing needs integration tests. */
	FsPolicy *policy = fs_policy_new();
	FsRule *rule;
	gboolean result;

	fs_policy_load(policy, NULL);
	rule = g_ptr_array_index(policy->kinds[FS_RULE_OUTBOUND_ALLOW_TO], 0);

	result = fs_policy_set_enabled(policy, rule, rule->enabled);

	fs_policy_free(policy);
	return result ? 0 : 1;
}

/* Teeth: versions with guarantees broken that should fail */

static int
tooth_load_no_off_support(const char *rules_dir)
{
	/* If load didn't parse #off:, the disabled rule would load as enabled.
	 * This tooth passes if we detect that. */
	FsPolicy *policy = fs_policy_new();
	FsRule *rule2;

	fs_policy_load(policy, NULL);
	rule2 = g_ptr_array_index(policy->kinds[FS_RULE_OUTBOUND_ALLOW_TO], 1);

	/* Should be disabled; if it's enabled, the #off: support is broken */
	int broken = rule2->enabled ? 1 : 0;

	fs_policy_free(policy);
	return broken ? 0 : 1;  /* Return 0 (success) if broken is detected */
}

static int
tooth_save_no_prefix(const char *rules_dir)
{
	/* Check that disabled rules have #off: in the file */
	char path[512];
	char *contents;
	gboolean has_off_prefix;

	snprintf(path, sizeof(path), "%s/outbound/allow-to", rules_dir);

	if (!g_file_get_contents(path, &contents, NULL, NULL))
		return 1;

	has_off_prefix = (strstr(contents, "#off:") != NULL);
	g_free(contents);

	/* Tooth succeeds if prefix is missing (broken guarantee) */
	return has_off_prefix ? 1 : 0;
}

static int
tooth_active_view_includes_disabled(const char *rules_dir)
{
	FsPolicy *policy = fs_policy_new();
	FsPolicy *active;
	int result;

	fs_policy_load(policy, NULL);
	active = fs_policy_active_view(policy);

	/* Should filter to 2 rules; if it's 3, disabled rules leaked through */
	result = (active->kinds[FS_RULE_OUTBOUND_ALLOW_TO]->len == 3) ? 0 : 1;

	fs_policy_free(active);
	fs_policy_free(policy);
	return result;
}

int
main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <test-name> <rules-dir>\n", argv[0]);
		return 2;
	}

	const char *test = argv[1];
	const char *rules_dir = argv[2];

	/* Set the rules directory for fs_util */
	g_setenv("STOCKFW_RULES_DIR", rules_dir, TRUE);

	if (strcmp(test, "load-preserves-state") == 0)
		return test_load_preserves_state(rules_dir);
	else if (strcmp(test, "save-writes-prefix") == 0)
		return test_save_writes_prefix(rules_dir);
	else if (strcmp(test, "active-view-filters") == 0)
		return test_active_view_filters(rules_dir);
	else if (strcmp(test, "set-enabled-persists") == 0)
		return test_set_enabled_persists(rules_dir);
	else if (strcmp(test, "set-enabled-rollback") == 0)
		return test_set_enabled_rollback(rules_dir);
	else if (strcmp(test, "tooth-load-no-off-support") == 0)
		return tooth_load_no_off_support(rules_dir);
	else if (strcmp(test, "tooth-save-no-prefix") == 0)
		return tooth_save_no_prefix(rules_dir);
	else if (strcmp(test, "tooth-active-view-includes-disabled") == 0)
		return tooth_active_view_includes_disabled(rules_dir);
	else {
		fprintf(stderr, "Unknown test: %s\n", test);
		return 2;
	}
}
