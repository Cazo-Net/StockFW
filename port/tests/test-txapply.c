/*---[ test-txapply.c ]--------------------------------------------------
 * Unit tests for transactional policy application and rollback (fs-txapply.c)
 * Pure core: runs on any platform without a live firewall.
 *--------------------------------------------------------------------*/
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include "core/fs-txapply.h"
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

typedef struct
{
	GList *active_rules;  /* FsTxRuleSpec* */
	guint fail_add_at;    /* fail add_rule on this 1-based index */
	guint add_calls;
	gboolean fail_clear;
	gboolean fail_snapshot;
} FakeBackendState;

static GList *
fake_snapshot (gpointer user_data, GError **error)
{
	FakeBackendState *st = user_data;
	GList *copy = NULL;
	GList *iter;

	if (st->fail_snapshot) {
		g_set_error_literal (error, g_quark_from_static_string ("fake"), 0, "snapshot refused");
		return NULL;
	}

	for (iter = st->active_rules; iter != NULL; iter = iter->next) {
		const FsTxRuleSpec *src = iter->data;
		FsTxRuleSpec *dst = g_new0 (FsTxRuleSpec, 1);
		dst->name = g_strdup (src->name);
		dst->direction = g_strdup (src->direction);
		dst->action = g_strdup (src->action);
		dst->protocol = g_strdup (src->protocol);
		dst->local_ports = g_strdup (src->local_ports);
		dst->remote_ports = g_strdup (src->remote_ports);
		dst->remote_address = g_strdup (src->remote_address);
		dst->program = g_strdup (src->program);
		copy = g_list_append (copy, dst);
	}
	return copy;
}

static gboolean
fake_clear (gpointer user_data, GError **error)
{
	FakeBackendState *st = user_data;

	if (st->fail_clear) {
		g_set_error_literal (error, g_quark_from_static_string ("fake"), 0, "clear refused");
		return FALSE;
	}

	g_list_free_full (st->active_rules, (GDestroyNotify) fs_tx_rule_spec_free);
	st->active_rules = NULL;
	return TRUE;
}

static gboolean
fake_add_rule (gpointer user_data, const FsFwRule *rule, GError **error)
{
	FakeBackendState *st = user_data;
	FsTxRuleSpec *spec;

	st->add_calls++;
	if (st->fail_add_at > 0 && st->add_calls == st->fail_add_at) {
		g_set_error_literal (error, g_quark_from_static_string ("fake"), 0, "simulated add failure");
		return FALSE;
	}

	spec = g_new0 (FsTxRuleSpec, 1);
	spec->name = g_strdup (rule->name ? rule->name : "rule");
	spec->direction = g_strdup (rule->direction == FS_DIR_INBOUND ? "in" : "out");
	spec->action = g_strdup (rule->action == FS_ACTION_ALLOW ? "allow" : "block");
	spec->protocol = g_strdup (rule->protocol == FS_PROTO_TCP ? "TCP" : rule->protocol == FS_PROTO_UDP ? "UDP" : "any");
	spec->local_ports = g_strdup (rule->local_ports ? rule->local_ports : "");
	spec->remote_ports = g_strdup (rule->remote_ports ? rule->remote_ports : "");
	spec->remote_address = g_strdup (rule->remote_address ? rule->remote_address : "");
	spec->program = g_strdup (rule->program ? rule->program : "");

	st->active_rules = g_list_append (st->active_rules, spec);
	return TRUE;
}

static gboolean
fake_restore_spec (gpointer user_data, const FsTxRuleSpec *src, GError **error)
{
	FakeBackendState *st = user_data;
	FsTxRuleSpec *dst = g_new0 (FsTxRuleSpec, 1);

	dst->name = g_strdup (src->name);
	dst->direction = g_strdup (src->direction);
	dst->action = g_strdup (src->action);
	dst->protocol = g_strdup (src->protocol);
	dst->local_ports = g_strdup (src->local_ports);
	dst->remote_ports = g_strdup (src->remote_ports);
	dst->remote_address = g_strdup (src->remote_address);
	dst->program = g_strdup (src->program);

	st->active_rules = g_list_append (st->active_rules, dst);
	return TRUE;
}

static gboolean
fake_verify_present (gpointer user_data, const GList *specs, GError **error)
{
	FakeBackendState *st = user_data;
	const GList *iter;

	for (iter = specs; iter != NULL; iter = iter->next) {
		const FsTxRuleSpec *want = iter->data;
		gboolean found = FALSE;
		GList *a;

		for (a = st->active_rules; a != NULL; a = a->next) {
			const FsTxRuleSpec *have = a->data;
			if (g_strcmp0 (have->name, want->name) == 0) {
				found = TRUE;
				break;
			}
		}
		if (!found) {
			g_set_error (error, g_quark_from_static_string ("fake"), 0,
			             "rule %s missing after rollback", want->name);
			return FALSE;
		}
	}
	return TRUE;
}

static const FsTxOps fake_ops = {
	.snapshot = fake_snapshot,
	.clear = fake_clear,
	.add_rule = fake_add_rule,
	.restore_spec = fake_restore_spec,
	.verify_present = fake_verify_present
};

int main (void)
{
	FsFwRule *r1, *r2;
	GList *rules = NULL;
	FakeBackendState st = { 0 };
	FsApplyResult res;
	GError *error = NULL;

	r1 = fs_fwrule_new ();
	r1->name = g_strdup ("StockFW- Test 1");
	r1->direction = FS_DIR_OUTBOUND;
	r1->action = FS_ACTION_ALLOW;
	r1->protocol = FS_PROTO_TCP;
	r1->remote_ports = g_strdup ("443");
	r1->program = g_strdup ("C:\\App.exe");

	r2 = fs_fwrule_new ();
	r2->name = g_strdup ("StockFW- Test 2");
	r2->direction = FS_DIR_INBOUND;
	r2->action = FS_ACTION_BLOCK;
	r2->protocol = FS_PROTO_UDP;
	r2->local_ports = g_strdup ("53");

	rules = g_list_append (rules, r1);
	rules = g_list_append (rules, r2);

	/* Test 1: Successful apply from empty state. */
	res = fs_tx_apply (&fake_ops, &st, rules, &error);
	CHECK (res == FS_APPLY_OK, "successful apply returns FS_APPLY_OK (got %d)", (int) res);
	CHECK (g_list_length (st.active_rules) == 2, "both rules active");
	CHECK (st.add_calls == 2, "2 add calls made");
	g_clear_error (&error);

	/* Test 2: Apply failure on second rule triggers rollback to snapshot. */
	st.add_calls = 0;
	st.fail_add_at = 2; /* fail on second rule */
	res = fs_tx_apply (&fake_ops, &st, rules, &error);
	CHECK (res == FS_APPLY_PARTIAL, "failing apply returns FS_APPLY_PARTIAL (got %d)", (int) res);
	CHECK (g_list_length (st.active_rules) == 2, "snapshot successfully rolled back (2 original rules present)");
	CHECK (error != NULL, "error set on partial apply");
	g_clear_error (&error);

	fs_fwrule_free (r1);
	fs_fwrule_free (r2);
	g_list_free (rules);
	g_list_free_full (st.active_rules, (GDestroyNotify) fs_tx_rule_spec_free);

	printf ("\n");
	if (failures == 0) {
		printf ("PASSED: 0 failure(s)\n");
		return 0;
	} else {
		printf ("FAILED: %d failure(s)\n", failures);
		return 1;
	}
}
