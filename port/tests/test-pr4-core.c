/*---[ test-pr4-core.c ]-------------------------------------------------
 * The core API of PR 4 (master plan, package 4A), unit by unit:
 *
 *   fs_firewall_add_live (the journal plus the rows, never the saved
 *   file; a stopped firewall is not started, the journal alone
 *   changes), the same rule for fs_firewall_lift_live, the Sentinel
 *   lift helpers fs_autoblock_lift_all, _for_dest and _expired (the
 *   state file, the policy file and the firewall; a rule still live
 *   keeps a row that is already due), and
 *   fs_intel_exceptions_from_text.
 *
 * Pure GLib against src/core with a scripted backend, so it runs on
 * Windows too.  Addresses are documentation ranges (RFC 5737, RFC
 * 3849).  tests/test-cli.sh runs the add_live check against the real
 * Linux backend in a private network namespace (tests/pr4-live-driver.c).
 *
 * Run by tests/test-core.sh.
 *--------------------------------------------------------------------*/
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-apply.h"
#include "core/fs-autoblock.h"
#include "core/fs-backend.h"
#include "core/fs-intel.h"
#include "core/fs-iprange.h"
#include "core/fs-prefs.h"
#include "core/fs-rules.h"
#include "core/fs-util.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do {                                   \
	checks++;                                               \
	if (!(cond)) {                                          \
		printf ("FAIL: ");                              \
		printf (__VA_ARGS__);                           \
		printf ("\n");                                  \
		failures++;                                     \
	} else {                                                \
		printf ("ok:   ");                              \
		printf (__VA_ARGS__);                           \
		printf ("\n");                                  \
	}                                                       \
} while (0)

static gchar *
slurp (const gchar *path)
{
	gchar *text = NULL;

	if (path == NULL || !g_file_get_contents (path, &text, NULL, NULL))
		return g_strdup ("");
	return text;
}

static FsRule *
rule_to (FsRuleKind kind, const gchar *target, const gchar *comment)
{
	FsRule *r = fs_rule_new (kind);

	r->target = g_strdup (target);
	r->comment = g_strdup (comment != NULL ? comment : "");
	return r;
}

static FsRule *
rule_allow_ssh (void)
{
	FsRule *r = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);

	r->service = g_strdup ("SSH");
	r->port = g_strdup ("22");
	r->target = g_strdup ("203.0.113.0/24");
	r->comment = g_strdup ("");
	return r;
}

static guint
total (const FsPolicy *p)
{
	guint n = 0;

	for (gint k = 0; p != NULL && k < FS_RULE_N_KINDS; k++)
		n += p->kinds[k]->len;
	return n;
}

static FsPolicy *
policy_of (FsRule *a, FsRule *b, FsRule *c, FsRule *d)
{
	FsPolicy *p = fs_policy_new ();
	FsRule *list[] = { a, b, c, d };

	for (guint i = 0; i < G_N_ELEMENTS (list); i++)
		if (list[i] != NULL)
			fs_policy_add (p, list[i]);
	return p;
}

static FsPolicy *
journal (void)
{
	FsPolicy *p = fs_policy_new ();

	if (!fs_apply_journal_load (p, NULL)) {
		fs_policy_free (p);
		return NULL;
	}
	return p;
}

/* ---------------------------------------------------- scripted backend */

static gint fake_applies = 0;
static gint fake_starts = 0;
static FsFirewallState fake_state = FS_FW_RUNNING;
static FsPolicy *fake_last = NULL;     /* a copy of the last policy applied */

static gboolean
fake_available (void)
{
	return TRUE;
}

static FsApplyResult
fake_apply_rules (const FsPolicy *policy, GError **error)
{
	(void) error;
	fake_applies++;
	fs_policy_free (fake_last);
	fake_last = fs_policy_new ();
	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		for (guint i = 0; i < policy->kinds[k]->len; i++)
			fs_policy_add (fake_last,
			               g_ptr_array_index (policy->kinds[k], i));
	fake_state = FS_FW_RUNNING;
	return FS_APPLY_OK;
}

static gboolean
fake_start (GError **error)
{
	(void) error;
	fake_starts++;
	fake_state = FS_FW_RUNNING;
	return TRUE;
}

static gboolean
fake_stop (GError **error)
{
	(void) error;
	fake_state = FS_FW_STOPPED;
	return TRUE;
}

static FsFirewallState
fake_get_state (void)
{
	return fake_state;
}

static const FsBackend fake_linux = {
	.name = "fake-pr4",
	.display_name = "scripted fake for PR 4, start installs the policy",
	.start_applies_policy = TRUE,
	.available = fake_available,
	.start = fake_start,
	.stop = fake_stop,
	.apply_rules = fake_apply_rules,
	.get_state = fake_get_state,
};

static void
fake_reset (FsFirewallState state)
{
	fake_applies = fake_starts = 0;
	fake_state = state;
	fs_policy_free (fake_last);
	fake_last = NULL;
}

/* ---------------------------------------------------------- add_live */

static void
test_add_live (void)
{
	FsRule *mine = rule_to (FS_RULE_OUTBOUND_DENY_TO, "198.51.100.1", "");
	FsRule *block = rule_to (FS_RULE_OUTBOUND_DENY_TO, "203.0.113.50",
	                         "copilot");
	FsRule *allow = rule_allow_ssh ();
	FsRule *bad = rule_to (FS_RULE_OUTBOUND_DENY_TO, "203.0.113.51",
	                       "one, two");
	FsPolicy *live = policy_of (mine, NULL, NULL, NULL);
	FsPolicy *saved = policy_of (mine, allow, NULL, NULL);
	FsPolicy *add = policy_of (block, NULL, NULL, NULL);
	FsPolicy *j;
	FsApplyOutcome *o;
	GError *error = NULL;
	gchar *path = fs_apply_journal_path ();
	gchar *before, *after;
	GHashTable *rec_before, *rec_after;

	/* No journal: nothing is on record as live. */
	g_remove (path);
	fake_reset (FS_FW_RUNNING);
	o = fs_firewall_add_live (&fake_linux, add, "test", NULL, &error);
	CHECK (o == NULL && fake_applies == 0,
	       "add_live: no journal, nothing touched");
	fs_apply_outcome_free (o);

	/* The saved file holds an inbound allow nobody applied. */
	CHECK (fs_policy_save (saved), "add_live: the unapplied allow is saved");
	fs_apply_journal_save (live, NULL);

	fake_reset (FS_FW_RUNNING);
	o = fs_firewall_add_live (&fake_linux, add, "test", NULL, &error);
	CHECK (o != NULL && o->applied && fake_applies == 1,
	       "add_live: running, the rows go live (%d applies)", fake_applies);
	CHECK (fake_last != NULL && fs_policy_contains (fake_last, block) &&
	       fs_policy_contains (fake_last, mine),
	       "add_live: what went live is the journal plus the block");
	CHECK (fake_last != NULL && !fs_policy_contains (fake_last, allow) &&
	       total (fake_last) == 2,
	       "add_live: the saved, unapplied allow is NOT live");
	j = journal ();
	CHECK (j != NULL && fs_policy_contains (j, block) &&
	       !fs_policy_contains (j, allow),
	       "add_live: the journal records the block, not the allow");
	fs_policy_free (j);
	fs_apply_outcome_free (o);
	g_clear_error (&error);

	/* Already live: nothing to do. */
	fake_reset (FS_FW_RUNNING);
	o = fs_firewall_add_live (&fake_linux, add, "test", NULL, &error);
	CHECK (o == NULL && fake_applies == 0,
	       "add_live: a row already live changes nothing");
	fs_apply_outcome_free (o);

	/* Held (audit-only, the Policy Lock): firewall and journal stay. */
	fs_apply_journal_save (live, NULL);
	before = slurp (path);
	fake_reset (FS_FW_RUNNING);
	o = fs_firewall_add_live (&fake_linux, add, "test", "audit-only testing mode",
	                          &error);
	after = slurp (path);
	CHECK (o != NULL && o->held && o->result == FS_APPLY_DRY_RUN &&
	       fake_applies == 0 && strcmp (before, after) == 0,
	       "add_live: held, firewall and journal untouched");
	fs_apply_outcome_free (o);
	g_free (before);
	g_free (after);

	/* Stopped: not started; the journal (what the next start installs)
	 * gets the block, and keeps the settings it records. */
	/* The journal records settings other than the saved ones (applied
	 * before a later `config set'): the first one's value is marked. */
	{
		gchar *text = slurp (path);
		gchar *at = strstr (text, "\n# setting ");
		gchar *eq = at != NULL ? strchr (at, '=') : NULL;
		gchar *nl = eq != NULL ? strchr (eq, '\n') : NULL;

		if (nl != NULL) {
			gchar *head = g_strndup (text, (gsize) (eq + 1 - text));
			gchar *marked = g_strconcat (head, "pr4-marker", nl, NULL);

			g_file_set_contents (path, marked, -1, NULL);
			g_free (marked);
			g_free (head);
		}
		g_free (text);
	}
	rec_before = fs_apply_journal_settings ();
	fake_reset (FS_FW_STOPPED);
	o = fs_firewall_add_live (&fake_linux, add, "test", NULL, &error);
	CHECK (o != NULL && !o->applied && !o->held &&
	       o->result == FS_APPLY_DRY_RUN &&
	       o->firewall_was == FS_FW_STOPPED &&
	       fake_applies == 0 && fake_starts == 0 &&
	       fake_state == FS_FW_STOPPED,
	       "add_live: a stopped firewall is not started (%d applies, "
	       "%d starts)", fake_applies, fake_starts);
	j = journal ();
	CHECK (j != NULL && fs_policy_contains (j, block) &&
	       fs_policy_contains (j, mine) && !fs_policy_contains (j, allow),
	       "add_live: ...the journal, which the next start installs, "
	       "has the block and not the allow");
	fs_policy_free (j);
	rec_after = fs_apply_journal_settings ();
	{
		GHashTableIter it;
		gpointer key, value;
		gboolean marked = FALSE, same = rec_before != NULL &&
		                  rec_after != NULL &&
		                  g_hash_table_size (rec_before) ==
		                  g_hash_table_size (rec_after);

		if (rec_before != NULL) {
			g_hash_table_iter_init (&it, rec_before);
			while (g_hash_table_iter_next (&it, &key, &value)) {
				if (g_strcmp0 (value, "pr4-marker") == 0)
					marked = TRUE;
				if (rec_after == NULL ||
				    g_strcmp0 (value, g_hash_table_lookup (
				                   rec_after, key)) != 0)
					same = FALSE;
			}
		}
		CHECK (marked, "add_live: (the journal's record was marked)");
		CHECK (same, "add_live: ...and keeps the settings it records, "
		       "not the saved ones");
	}
	if (rec_before != NULL)
		g_hash_table_unref (rec_before);
	if (rec_after != NULL)
		g_hash_table_unref (rec_after);
	fs_apply_outcome_free (o);
	g_clear_error (&error);
	before = slurp (g_getenv ("STOCKFW_AUDIT_FILE"));
	CHECK (strstr (before, "recorded for the next start") != NULL,
	       "add_live: ...and the audit line says so");
	g_free (before);

	/* lift_live follows the same rule on a stopped firewall. */
	fake_reset (FS_FW_STOPPED);
	o = fs_firewall_lift_live (&fake_linux, add, "test", NULL, &error);
	j = journal ();
	CHECK (o != NULL && fake_applies == 0 && fake_starts == 0 &&
	       j != NULL && !fs_policy_contains (j, block) &&
	       fs_policy_contains (j, mine),
	       "lift_live: stopped, not started; the block leaves the journal");
	fs_policy_free (j);
	fs_apply_outcome_free (o);
	g_clear_error (&error);

	/* A row that would not read back as itself: refused first. */
	{
		FsPolicy *bad_add = policy_of (bad, NULL, NULL, NULL);

		fake_reset (FS_FW_RUNNING);
		o = fs_firewall_add_live (&fake_linux, bad_add, "test", NULL,
		                          &error);
		CHECK (o != NULL && o->result == FS_APPLY_FAILED &&
		       fake_applies == 0 && error != NULL,
		       "add_live: a row with a comma is refused before the backend");
		fs_apply_outcome_free (o);
		g_clear_error (&error);
		fs_policy_free (bad_add);
	}

	{
		FsPolicy *empty = fs_policy_new ();

		g_remove (path);
		fs_policy_save (empty);
		fs_policy_free (empty);
	}
	g_free (path);
	fs_rule_free (mine);
	fs_rule_free (block);
	fs_rule_free (allow);
	fs_rule_free (bad);
	fs_policy_free (live);
	fs_policy_free (saved);
	fs_policy_free (add);
}

/* ---------------------------------------------------- the lift helpers */

static void
write_state (gint64 now, const FsRule *s1, const FsRule *s2)
{
	gchar *path = fs_autoblock_state_path ();
	gchar *c1 = fs_rule_to_csv (s1), *c2 = fs_rule_to_csv (s2);
	gchar *text = g_strdup_printf (
		"S,%" G_GINT64_FORMAT ",%d,%s\n"
		"S,%" G_GINT64_FORMAT ",%d,%s\n",
		now - FS_AUTOBLOCK_TTL_S - 100, (gint) s1->kind, c1,
		now - 100, (gint) s2->kind, c2);

	fs_util_ensure_parent_dir (path);
	g_file_set_contents (path, text, -1, NULL);
	g_free (text);
	g_free (c1);
	g_free (c2);
	g_free (path);
}

static gboolean
state_has (const FsRule *rule)
{
	gchar *path = fs_autoblock_state_path ();
	gchar *text = slurp (path);
	gchar *csv = fs_rule_to_csv (rule);
	gboolean has = strstr (text, csv) != NULL;

	g_free (csv);
	g_free (text);
	g_free (path);
	return has;
}

static void
test_lift_helpers (void)
{
	gint64 now = g_get_real_time () / G_USEC_PER_SEC;
	FsRule *mine = rule_to (FS_RULE_OUTBOUND_DENY_TO, "198.51.100.1", "");
	FsRule *s1 = rule_to (FS_RULE_OUTBOUND_DENY_TO, "203.0.113.10",
	                      "Sentinel: timed contacts");
	FsRule *s2 = rule_to (FS_RULE_OUTBOUND_DENY_TO, "203.0.113.11",
	                      "Sentinel: timed contacts");
	FsRule *p = rule_to (FS_RULE_OUTBOUND_DENY_TO, "203.0.113.12",
	                     "Sentinel: earlier session");
	FsRule *u12 = rule_to (FS_RULE_OUTBOUND_DENY_TO, "203.0.113.12",
	                       "my own");
	FsRule *allow = rule_allow_ssh ();
	FsPolicy *live = policy_of (mine, s1, s2, p);
	FsPolicy *file, *j, *lifted;
	FsAutoblockLift *res;
	GError *error = NULL;
	gchar *audit;

	fs_policy_add (live, u12);
	fs_apply_journal_save (live, NULL);
	file = policy_of (mine, s1, s2, p);
	fs_policy_add (file, u12);
	fs_policy_add (file, allow);
	fs_policy_save (file);
	write_state (now, s1, s2);

	/* --expired: s1 only (s2 has 100 s of its ten minutes). */
	fake_reset (FS_FW_RUNNING);
	res = fs_autoblock_lift_expired (&fake_linux, file, now, "test", NULL,
	                                 &error);
	CHECK (res != NULL && res->rows == 1 && res->removed == 1 &&
	       res->outcome != NULL && res->outcome->applied,
	       "lift_expired: the expired block is chosen and lifted");
	CHECK (fake_last != NULL && !fs_policy_contains (fake_last, s1) &&
	       fs_policy_contains (fake_last, s2) &&
	       !fs_policy_contains (fake_last, allow),
	       "lift_expired: the journal less it went live, the unapplied "
	       "allow did not");
	CHECK (!fs_policy_contains (file, s1) && fs_policy_contains (file, s2),
	       "lift_expired: it left the policy file, the fresh one stayed");
	CHECK (!state_has (s1) && state_has (s2),
	       "lift_expired: its state row is gone, the fresh one's stays");
	fs_autoblock_lift_free (res);
	g_clear_error (&error);

	/* for_dest: Sentinel's earlier-session row for the address, never
	 * the user's own row for it. */
	fake_reset (FS_FW_RUNNING);
	res = fs_autoblock_lift_for_dest (&fake_linux, file, "203.0.113.12",
	                                  NULL, "test", NULL, &error);
	/* The user's own row blocks the same address, so the firewall
	 * itself has nothing to change: the journal says what is live. */
	j = journal ();
	CHECK (res != NULL && res->rows == 0 && res->removed == 1 &&
	       res->outcome != NULL && j != NULL &&
	       !fs_policy_contains (j, p) && fs_policy_contains (j, u12),
	       "lift_for_dest: Sentinel's row from an earlier session is "
	       "lifted live (rows %u, removed %u)",
	       res != NULL ? res->rows : 0, res != NULL ? res->removed : 0);
	fs_policy_free (j);
	CHECK (!fs_policy_contains (file, p) && fs_policy_contains (file, u12),
	       "lift_for_dest: ...and leaves the file; the user's own row "
	       "for the address stays");
	fs_autoblock_lift_free (res);

	/* --all, held: out of the file, still live, so a row that is
	 * already due is kept and the next start leaves the rule out. */
	fake_reset (FS_FW_RUNNING);
	res = fs_autoblock_lift_all (&fake_linux, file, NULL, "test",
	                             "audit-only testing mode", &error);
	CHECK (res != NULL && res->rows == 1 && res->removed == 1 &&
	       res->outcome != NULL && res->outcome->held &&
	       fake_applies == 0 && res->kept == 1,
	       "lift_all held: out of the file, nothing applied, one row kept");
	CHECK (!fs_policy_contains (file, s2) && state_has (s2),
	       "lift_all held: the row for the rule still live stays");
	lifted = fs_policy_new ();
	fs_autoblock_expire (file, now, FALSE, lifted);
	CHECK (fs_policy_contains (lifted, s2) && !state_has (s2),
	       "lift_all held: ...dated as due, so the next start leaves "
	       "it out");
	fs_policy_free (lifted);
	fs_autoblock_lift_free (res);

	/* Lift it live now (the hold is gone): the next lift_expired does. */
	write_state (now, s1, s2);
	fake_reset (FS_FW_RUNNING);
	res = fs_autoblock_lift_all (&fake_linux, file, "Sentinel switched to "
	                             "detect only", "test", NULL, &error);
	j = journal ();
	CHECK (res != NULL && res->outcome != NULL && res->outcome->applied &&
	       j != NULL && !fs_policy_contains (j, s2) &&
	       fs_policy_contains (j, mine) && res->kept == 0 &&
	       !state_has (s2) && !state_has (s1),
	       "lift_all: every staged block lifted live, the state file "
	       "emptied");
	fs_policy_free (j);
	fs_autoblock_lift_free (res);

	/* Stopped: the firewall is not started. */
	fs_apply_journal_save (live, NULL);
	fs_policy_add (file, s2);
	fs_policy_save (file);
	write_state (now, s1, s2);
	fake_reset (FS_FW_STOPPED);
	res = fs_autoblock_lift_for_dest (&fake_linux, file, "203.0.113.11",
	                                  "lifted by user", "test", NULL,
	                                  &error);
	j = journal ();
	CHECK (res != NULL && fake_applies == 0 && fake_starts == 0 &&
	       j != NULL && !fs_policy_contains (j, s2) && !state_has (s2) &&
	       state_has (s1) && !fs_policy_contains (file, s2),
	       "lift_for_dest stopped: not started; out of the journal, the "
	       "file and the state");
	fs_policy_free (j);
	fs_autoblock_lift_free (res);

	/* No state file: nothing staged. */
	{
		gchar *path = fs_autoblock_state_path ();

		g_remove (path);
		g_free (path);
	}
	fake_reset (FS_FW_RUNNING);
	res = fs_autoblock_lift_all (&fake_linux, file, NULL, "test", NULL,
	                             &error);
	CHECK (res != NULL && res->rows == 0 && res->outcome == NULL &&
	       fake_applies == 0 && res->state_saved,
	       "lift_all: no state file, nothing staged, nothing done");
	fs_autoblock_lift_free (res);

	audit = slurp (g_getenv ("STOCKFW_AUDIT_FILE"));
	CHECK (strstr (audit, "sentinel auto-blocks lifted") != NULL &&
	       strstr (audit, "Sentinel switched to detect only") != NULL,
	       "lift helpers: audited, with the reason");
	g_free (audit);

	g_clear_error (&error);
	fs_rule_free (mine);
	fs_rule_free (s1);
	fs_rule_free (s2);
	fs_rule_free (p);
	fs_rule_free (u12);
	fs_rule_free (allow);
	fs_policy_free (live);
	fs_policy_free (file);
}

/* ------------------------------------------- the allow-list editor text */

static void
test_exceptions_text (void)
{
	GError *error = NULL;
	FsRangeSet *set;
	gchar *text;

	set = fs_intel_exceptions_from_text (
		"203.0.113.6 # mail\n"
		"# a whole line of comment\n"
		"\n"
		"198.51.100.0/24\r\n"
		"2001:db8::1   # the office\n", &error);
	CHECK (set != NULL && error == NULL,
	       "exceptions: '203.0.113.6 # mail' and friends are accepted");
	text = set != NULL ? fs_range_set_to_text (set) : g_strdup ("");
	CHECK (set != NULL && fs_range_set_count4 (set) == 2 &&
	       fs_range_set_count6 (set) == 1 &&
	       strstr (text, "203.0.113.6") != NULL &&
	       strstr (text, "mail") == NULL,
	       "exceptions: two IPv4 entries and one IPv6, comments dropped");
	g_free (text);
	fs_range_set_free (set);

	set = fs_intel_exceptions_from_text ("203.0.113.6\n"
	                                     "not-an-address # x\n", &error);
	CHECK (set == NULL && error != NULL &&
	       strstr (error->message, "line 2") != NULL,
	       "exceptions: a line that is not an address refuses the text "
	       "and is named by its number");
	g_clear_error (&error);

	set = fs_intel_exceptions_from_text ("", &error);
	CHECK (set != NULL && fs_range_set_is_empty (set),
	       "exceptions: empty text is no exceptions");
	fs_range_set_free (set);
	set = fs_intel_exceptions_from_text (NULL, &error);
	CHECK (set != NULL && fs_range_set_is_empty (set),
	       "exceptions: NULL text is no exceptions");
	fs_range_set_free (set);
}

/* ------------------------------------------- live edits and settings */

/* The value the journal records for one setting (NULL: none). */
static gchar *
journal_setting (const gchar *key)
{
	GHashTable *rec = fs_apply_journal_settings ();
	gchar *v = rec != NULL ? g_strdup (g_hash_table_lookup (rec, key))
	                       : NULL;

	if (rec != NULL)
		g_hash_table_unref (rec);
	return v;
}

/* A running firewall, a settings change saved and not applied: a live
 * edit whose backend was given the journal's settings keeps the record
 * as it is, so the change stays pending for the next apply (review of
 * PR 4: the record must say what the backend was given). */
static void
test_live_keeps_settings (void)
{
	const gchar *key = FS_PREFS_FW_ICMP_ECHO_REQUEST;
	FsRule *mine = rule_to (FS_RULE_OUTBOUND_DENY_TO, "198.51.100.1", "");
	FsRule *block = rule_to (FS_RULE_OUTBOUND_DENY_TO, "203.0.113.60",
	                         "copilot");
	FsRule *other = rule_to (FS_RULE_OUTBOUND_DENY_TO, "203.0.113.61",
	                         "copilot");
	FsPolicy *live = policy_of (mine, NULL, NULL, NULL);
	FsPolicy *add = policy_of (block, NULL, NULL, NULL);
	FsPolicy *add2 = policy_of (other, NULL, NULL, NULL);
	FsApplyOutcome *o;
	GError *error = NULL;
	gchar *v;

	fs_prefs_set_bool (key, TRUE);
	fs_apply_journal_save (live, NULL);
	fs_prefs_set_bool (key, FALSE);          /* saved, not applied */
	CHECK (fs_apply_settings_pending (),
	       "keeps: (a settings change is pending)");

	fake_reset (FS_FW_RUNNING);
	fs_firewall_live_keeps_settings (TRUE);
	o = fs_firewall_add_live (&fake_linux, add, "test", NULL, &error);
	CHECK (o != NULL && o->result == FS_APPLY_OK && fake_applies == 1,
	       "keeps: add_live on a running firewall goes out");
	v = journal_setting (key);
	CHECK (g_strcmp0 (v, "true") == 0,
	       "keeps: add_live records the settings the backend was given "
	       "(echo_request=%s), not the saved ones", v != NULL ? v : "-");
	g_free (v);
	CHECK (fs_apply_settings_pending (),
	       "keeps: ...so the saved change is still pending");
	fs_apply_outcome_free (o);
	g_clear_error (&error);

	fake_reset (FS_FW_RUNNING);
	o = fs_firewall_lift_live (&fake_linux, add, "test", NULL, &error);
	v = journal_setting (key);
	CHECK (o != NULL && o->result == FS_APPLY_OK &&
	       g_strcmp0 (v, "true") == 0 && fs_apply_settings_pending (),
	       "keeps: lift_live too (echo_request=%s)", v != NULL ? v : "-");
	g_free (v);
	fs_apply_outcome_free (o);
	g_clear_error (&error);

	/* The default: a caller that gave the backend the saved settings
	 * (the desktop app) has those recorded. */
	fs_firewall_live_keeps_settings (FALSE);
	fake_reset (FS_FW_RUNNING);
	o = fs_firewall_add_live (&fake_linux, add2, "test", NULL, &error);
	v = journal_setting (key);
	CHECK (o != NULL && g_strcmp0 (v, "false") == 0 &&
	       !fs_apply_settings_pending (),
	       "keeps: off, the saved settings are recorded (echo_request=%s)",
	       v != NULL ? v : "-");
	g_free (v);
	fs_apply_outcome_free (o);
	g_clear_error (&error);

	fs_prefs_set_bool (key, TRUE);
	fs_policy_free (add2);
	fs_policy_free (add);
	fs_policy_free (live);
	fs_rule_free (other);
	fs_rule_free (block);
	fs_rule_free (mine);
}

/* ------------------------------------------------------------- main */

static void
rm_tree (const gchar *path)
{
	GDir *d = g_dir_open (path, 0, NULL);
	const gchar *name;

	while (d != NULL && (name = g_dir_read_name (d)) != NULL) {
		gchar *child = g_build_filename (path, name, NULL);

		if (g_file_test (child, G_FILE_TEST_IS_DIR) &&
		    !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
			rm_tree (child);
		else
			g_remove (child);
		g_free (child);
	}
	if (d != NULL)
		g_dir_close (d);
	g_rmdir (path);
}

int
main (void)
{
	gchar *dir = g_dir_make_tmp ("stockfw-pr4-XXXXXX", NULL);
	gchar *sub;

	if (dir == NULL) {
		printf ("FAIL: no scratch directory\n");
		return 1;
	}
#ifdef G_OS_WIN32
	g_setenv ("APPDATA", dir, TRUE);
#else
	g_setenv ("XDG_CONFIG_HOME", dir, TRUE);
#endif
	sub = g_build_filename (dir, "rules", NULL);
	g_setenv ("STOCKFW_RULES_DIR", sub, TRUE);
	g_free (sub);
	sub = g_build_filename (dir, "run", NULL);
	g_setenv ("STOCKFW_RUN_DIR", sub, TRUE);
	g_free (sub);
	sub = g_build_filename (dir, "applied.csv", NULL);
	g_setenv ("STOCKFW_APPLIED_FILE", sub, TRUE);
	g_free (sub);
	sub = g_build_filename (dir, "audit.log", NULL);
	g_setenv ("STOCKFW_AUDIT_FILE", sub, TRUE);
	g_free (sub);
	sub = g_build_filename (dir, "autoblocks", NULL);
	g_setenv ("STOCKFW_AUTOBLOCK_FILE", sub, TRUE);
	g_free (sub);

	test_add_live ();
	test_live_keeps_settings ();
	test_lift_helpers ();
	test_exceptions_text ();

	fake_reset (FS_FW_RUNNING);
	printf ("test-pr4-core: %d checks, %d failures\n", checks, failures);
	rm_tree (dir);
	g_free (dir);
	return failures ? 1 : 0;
}
