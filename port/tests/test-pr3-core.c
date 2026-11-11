/*---[ test-pr3-core.c ]-------------------------------------------------
 * The core API of PR 3 (master plan, package 3A), unit by unit:
 *
 *   fs_rule_validate and the writers that call it (the rule files, the
 *   apply journal), fs_policy_replace_persist, the policy lock (POSIX:
 *   a second holder waits), fs_prefs_set_persist (no lost update; an
 *   unreadable file kept as .bad), fs_prefs_validate (the Preferences
 *   window's rules), the Overview verdict, the threat-intel sentence,
 *   fs_netif_is_virtual, the Events filters, fs_settings_from_journal,
 *   fs_firewall_start_recorded and fs_settings_apply_saved.
 *
 * Pure GLib against src/core, so it runs on Windows too; the lock test
 * is POSIX only.  Addresses are documentation ranges (RFC 5737, RFC
 * 3849) so the verdicts hold on either firewall model.
 *
 * Run by tests/test-core.sh.
 *--------------------------------------------------------------------*/
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-apply.h"
#include "core/fs-audit-ledger.h"
#include "core/fs-backend.h"
#include "core/fs-eventfilter.h"
#include "core/fs-prefs.h"
#include "core/fs-rules.h"
#include "core/fs-types.h"
#include "core/fs-util.h"
#include "core/fs-verdict.h"
#include "verdict-golden.h"

#ifndef G_OS_WIN32
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do {                                   \
	checks++;                                               \
	if (!(cond)) {                                          \
		printf ("FAIL: ");                              \
		printf (__VA_ARGS__);                           \
		printf ("\n");                                  \
		failures++;                                     \
	}                                                       \
} while (0)

static gchar *
slurp (const gchar *path)
{
	gchar *text = NULL;

	if (!g_file_get_contents (path, &text, NULL, NULL))
		return g_strdup ("(missing)");
	return text;
}

static FsRule *
rule_target (FsRuleKind kind, const gchar *target, const gchar *comment)
{
	FsRule *r = fs_rule_new (kind);

	r->target = g_strdup (target);
	r->comment = g_strdup (comment);
	return r;
}

static FsRule *
rule_service (const gchar *name, const gchar *port, const gchar *target,
              const gchar *comment)
{
	FsRule *r = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);

	r->service = g_strdup (name);
	r->port = g_strdup (port);
	r->target = g_strdup (target);
	r->comment = g_strdup (comment);
	return r;
}

/* ------------------------------------------------- fs_rule_validate */

static void
test_rule_validate (void)
{
	FsRule *good = rule_target (FS_RULE_OUTBOUND_DENY_TO, "198.51.100.9",
	                            "a plain note");
	FsRule *comma = rule_target (FS_RULE_OUTBOUND_DENY_TO, "198.51.100.9",
	                             "one, two");
	FsRule *nl = rule_service ("SSH", "22", "203.0.113.0/24",
	                           "first\n198.51.100.66,");
	FsRule *cr = rule_service ("SSH", "22\r", "Anyone", "");
	FsPolicy *policy = fs_policy_new ();
	GError *error = NULL;
	gchar *path, *before, *after;

	CHECK (fs_rule_validate (good, NULL), "validate: a plain row passes");
	CHECK (!fs_rule_validate (comma, &error) && error != NULL &&
	       error->domain == FS_RULES_ERROR &&
	       error->code == FS_RULES_ERR_INVALID &&
	       strstr (error->message, "comma") != NULL,
	       "validate: a comma in the comment is refused, and named");
	g_clear_error (&error);
	CHECK (!fs_rule_validate (nl, NULL),
	       "validate: a line break in the comment is refused");
	CHECK (!fs_rule_validate (cr, NULL),
	       "validate: a carriage return in a field is refused");
	/* Review fix: a first field that starts with '#' reads back as a
	 * comment line, so the rule would be gone. */
	{
		FsRule *hash = rule_service (" #evil", "443", "Anyone", "");
		FsRule *hash_to = rule_target (FS_RULE_OUTBOUND_DENY_TO, "#x", "");
		FsRule *hash_note = rule_target (FS_RULE_OUTBOUND_DENY_TO,
		                                 "198.51.100.9", "#1 note");

		CHECK (!fs_rule_validate (hash, &error) && error != NULL &&
		       strstr (error->message, "'#'") != NULL,
		       "validate: a service name that starts with '#' is refused");
		g_clear_error (&error);
		CHECK (!fs_rule_validate (hash_to, NULL),
		       "validate: a target that starts with '#' is refused");
		CHECK (fs_rule_validate (hash_note, NULL),
		       "validate: a '#' later in the row (the comment) passes");
		fs_rule_free (hash);
		fs_rule_free (hash_to);
		fs_rule_free (hash_note);
	}

	/* The writer refuses and leaves the file as it was. */
	fs_policy_add (policy, good);
	CHECK (fs_policy_save (policy), "save: a clean policy is written");
	path = fs_util_rules_path ("outbound/deny-to");
	before = slurp (path);
	fs_policy_add (policy, comma);
	CHECK (!fs_policy_save (policy),
	       "save: a policy holding a comma row is refused");
	after = slurp (path);
	CHECK (strcmp (before, after) == 0,
	       "save: ...and the rule file is left byte for byte");
	g_free (after);
	g_free (before);
	g_free (path);
	fs_policy_free (policy);

	/* The apply journal too: it is the restore point. */
	policy = fs_policy_new ();
	fs_policy_add (policy, good);
	CHECK (fs_apply_journal_save (policy, NULL),
	       "journal: a clean policy is journalled");
	path = fs_apply_journal_path ();
	before = slurp (path);
	fs_policy_add (policy, nl);
	CHECK (!fs_apply_journal_save (policy, &error) && error != NULL,
	       "journal: a row with a line break is never journalled");
	g_clear_error (&error);
	after = slurp (path);
	CHECK (strcmp (before, after) == 0,
	       "journal: ...and the journal is left as it was");
	g_free (after);
	g_free (before);
	g_free (path);
	fs_policy_free (policy);

	fs_rule_free (good);
	fs_rule_free (comma);
	fs_rule_free (nl);
	fs_rule_free (cr);
}

/* ------------------------------------------ fs_policy_replace_persist */

static void
test_replace_persist (void)
{
	FsPolicy *policy = fs_policy_new (), *back;
	FsRule *a = rule_service ("SSH", "22", "203.0.113.0/24", "");
	FsRule *b = rule_service ("HTTP", "80", "Anyone", "web");
	FsRule *c = rule_service ("HTTPS", "443", "Anyone", "");
	FsRule *b2 = rule_service ("HTTP", "8080", "198.51.100.0/24", "web");
	FsRule *bad = rule_service ("HTTP", "8080", "Anyone", "x,y");
	FsRule *other = rule_target (FS_RULE_OUTBOUND_DENY_TO, "198.51.100.1",
	                             "");
	GError *error = NULL;
	gchar *csv;

	fs_policy_add (policy, a);
	fs_policy_add (policy, b);
	fs_policy_add (policy, c);
	CHECK (fs_policy_save (policy), "replace: the base policy is saved");

	CHECK (fs_policy_replace_persist (policy, b, b2, &error),
	       "replace: row 2 is replaced");
	g_clear_error (&error);
	back = fs_policy_new ();
	fs_policy_load (back, NULL);
	csv = fs_rule_to_csv (g_ptr_array_index (
		back->kinds[FS_RULE_INBOUND_ALLOW_SERVICE], 1));
	CHECK (back->kinds[FS_RULE_INBOUND_ALLOW_SERVICE]->len == 3 &&
	       strstr (csv, "8080") != NULL,
	       "replace: ...in place, keeping its number (2 of 3): %s", csv);
	g_free (csv);
	fs_policy_free (back);

	CHECK (!fs_policy_replace_persist (policy, b, c, &error) &&
	       g_error_matches (error, FS_RULES_ERROR, FS_RULES_ERR_NOT_FOUND),
	       "replace: a row no longer there is NOT_FOUND");
	g_clear_error (&error);
	CHECK (!fs_policy_replace_persist (policy, b2, c, &error) &&
	       g_error_matches (error, FS_RULES_ERROR, FS_RULES_ERR_DUPLICATE),
	       "replace: a row already stored elsewhere is DUPLICATE");
	g_clear_error (&error);
	CHECK (!fs_policy_replace_persist (policy, b2, bad, &error) &&
	       g_error_matches (error, FS_RULES_ERROR, FS_RULES_ERR_INVALID),
	       "replace: a comma row is INVALID");
	g_clear_error (&error);
	CHECK (!fs_policy_replace_persist (policy, b2, other, &error) &&
	       g_error_matches (error, FS_RULES_ERROR, FS_RULES_ERR_INVALID),
	       "replace: an edit cannot change the kind");
	g_clear_error (&error);

	/* Review fix: the same row twice (a hand-edited file).  Row 3 by
	 * number is row 3, not the identical row 2 before it. */
	{
		FsPolicy *dup = fs_policy_new ();
		FsRule *x = rule_target (FS_RULE_INBOUND_ALLOW_FROM, "Anyone", "a");
		FsRule *y = rule_target (FS_RULE_INBOUND_ALLOW_FROM, "203.0.113.1",
		                         "x");
		FsRule *z = rule_target (FS_RULE_INBOUND_ALLOW_FROM, "203.0.113.9",
		                         "x");
		GPtrArray *rows = dup->kinds[FS_RULE_INBOUND_ALLOW_FROM];
		gchar *r2, *r3;

		g_ptr_array_add (rows, fs_rule_copy (x));
		g_ptr_array_add (rows, fs_rule_copy (y));
		g_ptr_array_add (rows, fs_rule_copy (y));
		CHECK (fs_policy_replace_nth_persist (dup, 2, y, z, &error),
		       "replace nth: row 3 of two identical rows is replaced");
		g_clear_error (&error);
		r2 = fs_rule_to_csv (g_ptr_array_index (rows, 1));
		r3 = fs_rule_to_csv (g_ptr_array_index (rows, 2));
		CHECK (strstr (r2, "203.0.113.1") != NULL &&
		       strstr (r3, "203.0.113.9") != NULL,
		       "replace nth: ...row 3 changed, row 2 did not: %s / %s",
		       r2, r3);
		g_free (r2);
		g_free (r3);
		CHECK (!fs_policy_replace_nth_persist (dup, 0, y, z, &error) &&
		       g_error_matches (error, FS_RULES_ERROR,
		                        FS_RULES_ERR_NOT_FOUND),
		       "replace nth: a row number that is not `old' is NOT_FOUND");
		g_clear_error (&error);
		fs_policy_free (dup);
		fs_rule_free (x);
		fs_rule_free (y);
		fs_rule_free (z);
	}

	fs_policy_free (policy);
	fs_rule_free (a);
	fs_rule_free (b);
	fs_rule_free (c);
	fs_rule_free (b2);
	fs_rule_free (bad);
	fs_rule_free (other);
}

/* ------------------------------------------------------- policy lock */

#ifndef G_OS_WIN32
static volatile gint lock_taken = 0;

static gpointer
lock_thread (gpointer data)
{
	FsPolicyLock *lock = fs_policy_lock (NULL);

	(void) data;
	g_atomic_int_set (&lock_taken, 1);
	fs_policy_unlock (lock);
	return NULL;
}

static void
test_policy_lock (void)
{
	gchar *run = fs_policy_run_dir ();
	gchar *path = g_build_filename (run, "apply.lock", NULL);
	FsPolicyLock *outer, *inner;
	GThread *t;
	int fd;

	/* Re-entrant within the process: no wait for itself. */
	outer = fs_policy_lock (NULL);
	inner = fs_policy_lock (NULL);
	CHECK (outer != NULL && inner != NULL,
	       "lock: taken twice by one process without waiting");
	fs_policy_unlock (inner);
	fs_policy_unlock (outer);
	CHECK (g_file_test (path, G_FILE_TEST_EXISTS),
	       "lock: <run>/apply.lock is made (%s)", path);

	/* Another holder (another process: a descriptor of its own) holds
	 * apply.lock; fs_policy_lock waits until it lets go. */
	fd = open (path, O_RDWR | O_CLOEXEC);
	CHECK (fd >= 0 && flock (fd, LOCK_EX) == 0,
	       "lock: the test holds apply.lock");
	g_atomic_int_set (&lock_taken, 0);
	t = g_thread_new ("locker", lock_thread, NULL);
	g_usleep (300 * 1000);
	CHECK (g_atomic_int_get (&lock_taken) == 0,
	       "lock: a second writer waits while the lock is held");
	close (fd);
	g_thread_join (t);
	CHECK (g_atomic_int_get (&lock_taken) == 1,
	       "lock: ...and goes on once it is released");

	g_free (path);
	g_free (run);
}
#endif

/* ---------------------------------------------- fs_prefs_set_persist */

static void
test_prefs_set_persist (void)
{
	const gchar *k_a = FS_PREFS_SKIP_REDUNDANT;
	const gchar *k_b = FS_PREFS_FW_LOG_ALLOWED;
	const gchar *keys[1], *values[1];
	gboolean unreadable = TRUE;
	GError *error = NULL;
	gchar *external, *bad, *text;

	fs_prefs_load ();
	/* The text another writer leaves: k_a on. */
	fs_prefs_set_bool (k_a, TRUE);
	fs_prefs_save ();
	external = slurp (fs_prefs_path ());
	/* This process's snapshot says off... */
	fs_prefs_set_bool (k_a, FALSE);
	fs_prefs_save ();
	/* ...and the other writer saves after we read. */
	g_file_set_contents (fs_prefs_path (), external, -1, NULL);

	keys[0] = k_b;
	values[0] = "true";
	CHECK (fs_prefs_set_persist (keys, values, 1, &unreadable, &error),
	       "set_persist: one key is written");
	g_clear_error (&error);
	CHECK (!unreadable, "set_persist: a readable file is not .bad");
	fs_prefs_load ();
	CHECK (fs_prefs_bool (k_b),
	       "set_persist: the key asked for is on disk");
	CHECK (fs_prefs_bool (k_a),
	       "set_persist: another writer's key, saved after our read, "
	       "is kept (no lost update)");

	/* A value a switch does not take: refused, nothing touched. */
	text = slurp (fs_prefs_path ());
	values[0] = "maybe";
	CHECK (!fs_prefs_set_persist (keys, values, 1, NULL, &error) &&
	       g_error_matches (error, FS_PREFS_ERROR, FS_PREFS_ERR_INVALID),
	       "set_persist: \"maybe\" for a switch is refused");
	g_clear_error (&error);
	keys[0] = "/apps/stockfw/no/such/key";
	values[0] = "true";
	CHECK (!fs_prefs_set_persist (keys, values, 1, NULL, &error),
	       "set_persist: a key not in the table is refused");
	g_clear_error (&error);
	external = (g_free (external), slurp (fs_prefs_path ()));
	CHECK (strcmp (text, external) == 0,
	       "set_persist: ...and the file is left as it was");
	g_free (text);
	g_free (external);

	/* A12: an unreadable file is kept as .bad, the defaults written. */
	g_file_set_contents (fs_prefs_path (), "[broken\n\x01\x02 = =\n", -1,
	                     NULL);
	keys[0] = k_b;
	values[0] = "true";
	unreadable = FALSE;
	CHECK (fs_prefs_set_persist (keys, values, 1, &unreadable, NULL) &&
	       unreadable,
	       "set_persist: an unreadable file is reported");
	bad = fs_prefs_backup_path ();
	text = slurp (bad);
	CHECK (strstr (text, "[broken") != NULL,
	       "set_persist: ...kept as %s", bad);
	g_free (text);
	g_free (bad);
	CHECK (fs_prefs_load () && fs_prefs_bool (k_b),
	       "set_persist: ...and a readable file holds the key");
}

/* -------------------------------------------------- fs_prefs_validate */

static const FsPrefsIssue *
first_refusal (const FsPrefsCheck *c)
{
	return c->refusals->len > 0 ? g_ptr_array_index (c->refusals, 0)
	                            : NULL;
}

static FsPrefsCheck *
validate (guint n, const gchar *k0, const gchar *v0, const gchar *k1,
          const gchar *v1, const gchar *k2, const gchar *v2)
{
	const gchar *keys[3] = { k0, k1, k2 };
	const gchar *values[3] = { v0, v1, v2 };
	static const gchar *present[] = { "eth0", "eth1", NULL };

	return fs_prefs_validate (keys, values, n,
	                          FS_FWSEC_NETWORK | FS_FWSEC_ICMP |
	                          FS_FWSEC_ADVANCED,
	                          FS_FWHON_REJECT_METHOD | FS_FWHON_LOG_ALLOWED |
	                          FS_FWHON_OUTBOUND_MODE,
	                          present);
}

static void
test_prefs_validate (void)
{
	FsPrefsCheck *c;
	const FsPrefsIssue *i;
	const gchar *k[1] = { FS_PREFS_FW_NAT };
	const gchar *v[1] = { "on" };

	/* A store with no devices and sharing off. */
	fs_prefs_set_string (FS_PREFS_FW_EXT_IF, "");
	fs_prefs_set_string (FS_PREFS_FW_INT_IF, "");
	fs_prefs_set_bool (FS_PREFS_FW_NAT, FALSE);
	fs_prefs_set_bool (FS_PREFS_FW_FILTER_ICMP, FALSE);
	fs_prefs_set_bool (FS_PREFS_FW_RESTRICTIVE_OUTBOUND, FALSE);

	c = validate (3, FS_PREFS_FW_NAT, "on", FS_PREFS_FW_EXT_IF, "eth0",
	              FS_PREFS_FW_INT_IF, "eth1");
	CHECK (c->refusals->len == 0 && g_hash_table_size (c->values) == 3,
	       "validate: NAT with both devices in one call is accepted");
	CHECK (g_strcmp0 (g_hash_table_lookup (c->values, FS_PREFS_FW_NAT),
	                  "true") == 0,
	       "validate: \"on\" is stored as true");
	fs_prefs_check_free (c);

	c = validate (1, FS_PREFS_FW_NAT, "on", NULL, NULL, NULL, NULL);
	i = first_refusal (c);
	CHECK (i != NULL && g_strcmp0 (i->key, FS_PREFS_FW_NAT) == 0 &&
	       g_strcmp0 (i->reason, "Needs both devices: choose an Internet "
	                  "device and a local network device above.") == 0 &&
	       g_strcmp0 (i->topic, "prefs-network") == 0,
	       "validate: NAT alone is refused with the window's reason");
	fs_prefs_check_free (c);

	c = validate (1, FS_PREFS_FW_EXT_IF, "-j ACCEPT", NULL, NULL, NULL,
	              NULL);
	CHECK (c->refusals->len == 1,
	       "validate: \"-j ACCEPT\" is not a device name");
	fs_prefs_check_free (c);

	c = validate (1, FS_PREFS_FW_EXT_IF, "wlan9", NULL, NULL, NULL, NULL);
	CHECK (c->refusals->len == 0 && c->warnings->len == 1,
	       "validate: a device not present is kept, with the note");
	fs_prefs_check_free (c);

	fs_prefs_set_bool (FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST, FALSE);
	c = validate (1, FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST, "on", NULL,
	              NULL, NULL, NULL);
	i = first_refusal (c);
	CHECK (i != NULL && strstr (i->reason, "Internet device") != NULL &&
	       g_strcmp0 (i->topic, "prefs-protection") == 0,
	       "validate: the broadcast block without an Internet device is "
	       "refused");
	fs_prefs_check_free (c);

	c = validate (1, FS_PREFS_FW_ICMP_ECHO_REQUEST, "off", NULL, NULL,
	              NULL, NULL);
	CHECK (c->refusals->len == 1,
	       "validate: an ICMP type does not move while ICMP filtering is "
	       "off");
	fs_prefs_check_free (c);
	c = validate (2, FS_PREFS_FW_FILTER_ICMP, "on",
	              FS_PREFS_FW_ICMP_ECHO_REQUEST, "off", NULL, NULL);
	CHECK (c->refusals->len == 0,
	       "validate: ...and does with filtering turned on in the same "
	       "set");
	fs_prefs_check_free (c);

	c = validate (1, FS_PREFS_FW_RESTRICTIVE_OUTBOUND, "block", NULL, NULL,
	              NULL, NULL);
	CHECK (c->refusals->len == 0 && c->warnings->len == 1 &&
	       g_strcmp0 (g_hash_table_lookup (
	                      c->values, FS_PREFS_FW_RESTRICTIVE_OUTBOUND),
	                  "true") == 0,
	       "validate: blocking outgoing is accepted, with the warning");
	fs_prefs_check_free (c);

	c = validate (2, FS_PREFS_FW_DENY_PACKETS, "drop",
	              FS_PREFS_FW_DENY_PACKETS, "reject", NULL, NULL);
	CHECK (c->refusals->len == 1, "validate: a key given twice is refused");
	fs_prefs_check_free (c);

	c = validate (1, "/apps/stockfw/firewall/nope", "on", NULL, NULL, NULL,
	              NULL);
	CHECK (c->refusals->len == 1, "validate: an unknown key is refused");
	fs_prefs_check_free (c);

	c = validate (1, FS_PREFS_APPLY_POLICY_INSTANTLY, "on", NULL, NULL,
	              NULL, NULL);
	CHECK (c->refusals->len == 1,
	       "validate: apply-on-every-edit is refused (J12)");
	fs_prefs_check_free (c);

	c = validate (1, FS_PREFS_EVENTS_MAX, "5", NULL, NULL, NULL, NULL);
	CHECK (c->refusals->len == 1,
	       "validate: a number below the window's range is refused");
	fs_prefs_check_free (c);

	c = validate (1, FS_PREFS_FW_DENY_PACKETS, "maybe", NULL, NULL, NULL,
	              NULL);
	CHECK (c->refusals->len == 1, "validate: \"maybe\" is not on or off");
	fs_prefs_check_free (c);

	/* A backend without the Network page does not use NAT. */
	c = fs_prefs_validate (k, v, 1, FS_FWSEC_ICMP, 0, NULL);
	CHECK (c->refusals->len == 1,
	       "validate: a key the backend does not honour is refused");
	fs_prefs_check_free (c);
	CHECK (fs_prefs_key_honoured (FS_PREFS_SKIP_REDUNDANT, 0, 0),
	       "validate: a setting that is not the firewall's always counts");
}

/* ------------------------------------------------------------ verdict */

/* The golden table is shared with the desktop app's Overview smoke
 * (tests/ui-verdict-smoke.c), so both answer from the same rows. */
static void
test_verdict (void)
{
	for (guint i = 0; i < G_N_ELEMENTS (verdict_golden); i++) {
		const VerdictGolden *row = &verdict_golden[i];
		FsVerdictInput in;
		FsVerdictResult *v;
		gchar *why;

		verdict_golden_input (row, &in);
		v = fs_verdict_compute (&in);
		why = verdict_golden_mismatch (row, v->level, v->key, v->word,
		                               v->title, v->body);
		CHECK (why == NULL, "verdict golden row %u (%s): %s", i, row->key,
		       why != NULL ? why : "as the table says");
		g_free (why);
		fs_verdict_result_free (v);
	}

	{
		FsVerdictInput in;
		FsVerdictResult *v;

		memset (&in, 0, sizeof in);
		in.state = FS_FW_RUNNING;
		in.backend_usable = in.ipv6_known = TRUE;
		in.ipv6 = FS_IPV6_FILTERED;
		in.intel_summary = "Threat-intel blocklists are in force.";
		v = fs_verdict_compute (&in);
		CHECK (g_str_has_suffix (v->body, " Threat-intel blocklists are "
		                         "in force."),
		       "verdict: the blocklist sentence ends the body");
		fs_verdict_result_free (v);
	}
}

static void
test_intel_summary_text (void)
{
	gchar *t;

	t = fs_intel_summary_text (FS_INTEL_STATE_ENFORCED, NULL, 0, TRUE);
	CHECK (g_strcmp0 (t, "Threat-intel blocklists are in force.") == 0,
	       "intel sentence: enforced");
	g_free (t);
	t = fs_intel_summary_text (FS_INTEL_STATE_ENFORCED, NULL, 2, TRUE);
	CHECK (t != NULL && strstr (t, "except 2 lists that are") != NULL,
	       "intel sentence: two lists not applied yet (%s)", t);
	g_free (t);
	t = fs_intel_summary_text (FS_INTEL_STATE_NOT_IN_FORCE, "why", 0, TRUE);
	CHECK (g_strcmp0 (t, "Threat-intel blocklists are not in force: why")
	       == 0, "intel sentence: not in force, with the detail");
	g_free (t);
	t = fs_intel_summary_text (FS_INTEL_STATE_DIFFERS, NULL, 0, FALSE);
	CHECK (t != NULL && strstr (t, "turned off, but rules are still") != NULL,
	       "intel sentence: off but rules left");
	g_free (t);
	t = fs_intel_summary_text (FS_INTEL_STATE_OFF, NULL, 0, FALSE);
	CHECK (t == NULL, "intel sentence: nothing when off");
	g_free (t);
}

/* -------------------------------------------------- netif and filters */

static void
test_netif_virtual (void)
{
	static const struct { const gchar *kind; gboolean virt; } rows[] = {
		{ "Virtual", TRUE }, { "Tunnel", TRUE }, { "Loopback", TRUE },
		{ "Ethernet", FALSE }, { "Wireless", FALSE }, { NULL, FALSE },
	};

	for (guint i = 0; i < G_N_ELEMENTS (rows); i++) {
		FsIfaceStat s;

		memset (&s, 0, sizeof s);
		s.kind = (gchar *) rows[i].kind;
		CHECK (fs_netif_is_virtual (&s) == rows[i].virt,
		       "netif: %s is %s", rows[i].kind ? rows[i].kind : "(none)",
		       rows[i].virt ? "virtual" : "hardware");
	}
	CHECK (!fs_netif_is_virtual (NULL), "netif: NULL is not virtual");
}

static guint addr_reads = 0;

static GList *
fake_addrs (void)
{
	FsInterface *i = g_new0 (FsInterface, 1);

	addr_reads++;
	i->name = g_strdup ("eth0");
	i->ip = g_strdup ("203.0.113.5");
	return g_list_append (NULL, i);
}

static void
hit_set (FsHit *h, const gchar *dir, const gchar *src, const gchar *dst,
         const gchar *port)
{
	memset (h, 0, sizeof *h);
	h->direction = (gchar *) dir;
	h->source = (gchar *) src;
	h->destination = (gchar *) dst;
	h->port = (gchar *) port;
	h->protocol = (gchar *) "TCP";
}

static void
test_hit_filter (void)
{
	FsHitFilter *f = fs_hit_filter_new (fake_addrs);
	FsHit h, other, bcast, out;

	hit_set (&h, "In", "198.51.100.7", "203.0.113.5", "22");
	hit_set (&other, "In", "198.51.100.7", "203.0.113.5", "23");
	hit_set (&bcast, "In", "198.51.100.7", "198.51.100.255", "137");
	hit_set (&out, "Out", "203.0.113.5", "198.51.100.9", "443");

	CHECK (!fs_hit_filter_is_redundant (f, &h),
	       "filter: nothing remembered, nothing is a repeat");
	fs_hit_filter_remember (f, &h);
	CHECK (fs_hit_filter_is_redundant (f, &h),
	       "filter: the same event again is a repeat");
	CHECK (!fs_hit_filter_is_redundant (f, &other),
	       "filter: another port is not a repeat");
	CHECK (!fs_hit_filter_keep (f, &h, TRUE, FALSE) &&
	       fs_hit_filter_keep (f, &h, FALSE, FALSE),
	       "filter: a repeat is left out only with skip-repeats on");

	CHECK (fs_hit_filter_is_for_me (f, &h),
	       "filter: 203.0.113.5 is this computer's");
	CHECK (!fs_hit_filter_keep (f, &bcast, FALSE, TRUE),
	       "filter: a broadcast is not for this computer");
	CHECK (fs_hit_filter_keep (f, &out, FALSE, TRUE),
	       "filter: an event this computer sent is kept");
	CHECK (fs_hit_filter_keep (f, &bcast, FALSE, FALSE),
	       "filter: with the filter off everything is kept");
	CHECK (addr_reads == 1,
	       "filter: the addresses are read once, not per event (%u)",
	       addr_reads);
	fs_hit_filter_refresh (f);
	fs_hit_filter_is_for_me (f, &h);
	CHECK (addr_reads == 2, "filter: refresh reads them again");
	fs_hit_filter_free (f);
}

/* ------------------------------------- settings: boot and apply-saved */

static gint fake_applies = 0;
static gint fake_fail_first = 0;
static gint fake_starts = 0;

static gboolean
fake_available (void)
{
	return TRUE;
}

static FsApplyResult
fake_apply_rules (const FsPolicy *policy, GError **error)
{
	(void) policy;
	fake_applies++;
	if (fake_fail_first > 0) {
		fake_fail_first--;
		g_set_error_literal (error, g_quark_from_static_string ("fake"),
		                     1, "scripted failure");
		return FS_APPLY_FAILED;
	}
	return FS_APPLY_OK;
}

static gboolean
fake_start (GError **error)
{
	(void) error;
	fake_starts++;
	return TRUE;
}

static gboolean
fake_stop (GError **error)
{
	(void) error;
	return TRUE;
}

static const FsBackend fake_backend = {
	.name = "fake-pr3",
	.display_name = "scripted fake for PR 3",
	.start_applies_policy = TRUE,
	.available = fake_available,
	.start = fake_start,
	.stop = fake_stop,
	.apply_rules = fake_apply_rules,
};

static FsPolicy   *ctx_policy = NULL;
static FsSettings *ctx_settings = NULL;
static guint       ctx_calls = 0;

static void
fake_context (FsPolicy *policy, FsSettings *settings)
{
	ctx_policy = policy;
	ctx_settings = settings;
	ctx_calls++;
}

static void
test_settings_journal (void)
{
	FsPolicy *policy = fs_policy_new ();
	FsRule *r = rule_service ("SSH", "22", "203.0.113.0/24", "");
	FsSettings *s, *saved;
	GHashTable *recorded = NULL;
	FsApplyOutcome *o;
	GError *error = NULL;
	gchar *path = fs_apply_journal_path ();

	fs_policy_add (policy, r);
	fs_rule_free (r);

	/* The journal records the settings saved at apply time: ICMP
	 * filtering on. */
	fs_prefs_set_bool (FS_PREFS_FW_FILTER_ICMP, TRUE);
	CHECK (fs_apply_journal_save (policy, NULL),
	       "boot: the journal is written");
	/* Then the user saves another choice and does not apply it. */
	fs_prefs_set_bool (FS_PREFS_FW_FILTER_ICMP, FALSE);

	s = fs_settings_from_journal (&recorded);
	CHECK (s != NULL && s->filter_icmp && recorded != NULL,
	       "boot: the journal's settings are read back (ICMP filtering "
	       "on, as applied)");

	/* The start writes a new journal; it records what was given. */
	fake_starts = fake_applies = 0;
	o = fs_firewall_start_recorded (&fake_backend, policy, NULL, recorded,
	                                "test", NULL, &error);
	CHECK (o != NULL && o->result == FS_APPLY_OK &&
	       fake_starts + fake_applies >= 1,
	       "boot: the start goes through the gate (%d: %s)",
	       o != NULL ? (int) o->result : -1,
	       error != NULL ? error->message : "no error");
	fs_apply_outcome_free (o);
	g_clear_error (&error);
	fs_settings_free (s);
	g_hash_table_unref (recorded);
	s = fs_settings_from_journal (NULL);
	CHECK (s != NULL && s->filter_icmp,
	       "boot: ...and the journal it writes still records the settings "
	       "that went out, not the ones saved since");
	fs_settings_free (s);

	/* Older journal: no settings lines, so NULL (prefs are used). */
	{
		gchar *text = slurp (path);
		GString *old = g_string_new (NULL);
		gchar **lines = g_strsplit (text, "\n", -1);

		for (guint i = 0; lines[i] != NULL; i++)
			if (!g_str_has_prefix (lines[i], "# setting "))
				g_string_append_printf (old, "%s\n", lines[i]);
		g_file_set_contents (path, old->str, -1, NULL);
		CHECK (fs_settings_from_journal (NULL) == NULL,
		       "boot: a journal from before the record gives no "
		       "settings");
		g_strfreev (lines);
		g_string_free (old, TRUE);
		g_free (text);
	}

	/* fs_settings_apply_saved: under the journal's policy, the new
	 * settings stay in the backend's context even after a rollback. */
	CHECK (fs_apply_journal_save (policy, NULL),
	       "apply-saved: a journal to roll back to");
	saved = fs_settings_new ();
	saved->filter_icmp = TRUE;
	ctx_calls = 0;
	fake_applies = 0;
	o = fs_settings_apply_saved (&fake_backend, fake_context, policy, saved,
	                             NULL, "test", NULL, &error);
	CHECK (o != NULL && o->result == FS_APPLY_OK && fake_applies >= 1 &&
	       ctx_policy == policy && ctx_settings == saved,
	       "apply-saved: applied, the backend holds the policy and the "
	       "new settings");
	fs_apply_outcome_free (o);
	g_clear_error (&error);

	fake_fail_first = 1;
	o = fs_settings_apply_saved (&fake_backend, fake_context, policy, saved,
	                             NULL, "test", NULL, &error);
	CHECK (o != NULL && o->result != FS_APPLY_OK && o->rollback_attempted,
	       "apply-saved: a failed apply is rolled back");
	CHECK (ctx_settings == saved,
	       "apply-saved: ...and the backend is not left holding the "
	       "freed rollback settings");
	fs_apply_outcome_free (o);
	g_clear_error (&error);
	fake_fail_first = 0;

	CHECK (fs_settings_apply_saved (&fake_backend, fake_context, NULL,
	                                saved, NULL, "test", NULL, NULL) == NULL,
	       "apply-saved: no policy, nothing touched");

	fs_settings_free (saved);
	fs_policy_free (policy);
	g_free (path);
}

/* ---------------------------------------- T15 before the backend */

/* Review fix: a row that would not read back as itself is refused
 * before the backend is touched, not only by the journal after it. */
static void
test_gate_validates (void)
{
	FsPolicy *policy = fs_policy_new ();
	FsRule *ok = rule_target (FS_RULE_INBOUND_ALLOW_FROM, "203.0.113.9", "");
	FsRule *bad = rule_target (FS_RULE_OUTBOUND_DENY_TO, "198.51.100.9",
	                           "web, primary");
	FsApplyOutcome *o;
	GError *error = NULL;
	gint applies, starts;

	fs_policy_add (policy, ok);
	fs_policy_add (policy, bad);
	applies = fake_applies;
	starts = fake_starts;
	o = fs_policy_apply_safe (&fake_backend, policy, "test", NULL, &error);
	CHECK (o != NULL && o->result == FS_APPLY_FAILED && !o->applied &&
	       error != NULL && fake_applies == applies,
	       "gate: a comma row is refused before the backend applies");
	fs_apply_outcome_free (o);
	g_clear_error (&error);
	o = fs_firewall_start_safe (&fake_backend, policy, "test", NULL, &error);
	CHECK (o != NULL && o->result == FS_APPLY_FAILED &&
	       fake_starts == starts && fake_applies == applies,
	       "gate: ...and before a start installs it");
	fs_apply_outcome_free (o);
	g_clear_error (&error);

	fs_policy_free (policy);
	fs_rule_free (ok);
	fs_rule_free (bad);
}

#ifndef G_OS_WIN32
/* ------------------------------------- the desktop app's applies wait */

/* Review fix: the gate itself takes the policy lock, so an apply, a
 * start or a stop by a caller that did not (the desktop app) waits
 * for a terminal's apply instead of racing it to the backend and the
 * journal. */
static volatile gint gate_done = 0;

static gpointer
gate_thread (gpointer data)
{
	FsPolicy *policy = fs_policy_new ();
	FsApplyOutcome *o = NULL;
	gint what = GPOINTER_TO_INT (data);

	if (what == 0)
		o = fs_policy_apply_safe (&fake_backend, policy, "test", NULL,
		                          NULL);
	else if (what == 1)
		o = fs_firewall_start_safe (&fake_backend, policy, "test", NULL,
		                            NULL);
	else
		fs_firewall_stop_logged (&fake_backend, "test", NULL);
	fs_apply_outcome_free (o);
	fs_policy_free (policy);
	g_atomic_int_set (&gate_done, 1);
	return NULL;
}

static void
test_gate_takes_lock (void)
{
	static const gchar *const names[] = { "an apply", "a start", "a stop" };
	gchar *run = fs_policy_run_dir ();
	gchar *path = g_build_filename (run, "apply.lock", NULL);

	for (gint what = 0; what < 3; what++) {
		int fd = open (path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
		GThread *t;

		CHECK (fd >= 0 && flock (fd, LOCK_EX) == 0,
		       "gate lock: the test holds apply.lock");
		g_atomic_int_set (&gate_done, 0);
		t = g_thread_new ("gate", gate_thread, GINT_TO_POINTER (what));
		g_usleep (300 * 1000);
		CHECK (g_atomic_int_get (&gate_done) == 0,
		       "gate lock: %s waits while another writer holds the lock",
		       names[what]);
		close (fd);
		g_thread_join (t);
		CHECK (g_atomic_int_get (&gate_done) == 1,
		       "gate lock: ...and runs once it is released");
	}
	g_free (path);
	g_free (run);
}
#endif

static void
test_audit_ledger (void)
{
	gchar *h1 = NULL, *h2 = NULL;
	gchar *path = fs_audit_ledger_path ();
	GPtrArray *entries;
	gchar *merkle_root;

	CHECK (fs_audit_ledger_log ("POLICY_CHANGE", "admin", "rule added", &h1),
	       "audit ledger: first entry logged successfully");
	CHECK (h1 != NULL && strlen (h1) == 64,
	       "audit ledger: first hash computed and 64 chars (SHA-256)");

	CHECK (fs_audit_ledger_log ("AUTO_BLOCK", "sentinel", "ip blocked", &h2),
	       "audit ledger: second entry logged successfully");
	CHECK (h2 != NULL && strlen (h2) == 64,
	       "audit ledger: second hash computed");

	entries = fs_audit_ledger_load (path);
	CHECK (entries != NULL && entries->len == 2,
	       "audit ledger: loaded 2 entries from ledger file");

	CHECK (fs_audit_ledger_verify_chain (entries),
	       "audit ledger: chain verification passes on valid chain");

	merkle_root = fs_audit_ledger_compute_merkle_root (entries);
	CHECK (merkle_root != NULL && strlen (merkle_root) == 64,
	       "audit ledger: Merkle root computed successfully");
	g_free (merkle_root);

	/* Tamper with entry 0 details */
	if (entries && entries->len > 0) {
		FsAuditLedgerEntry *e0 = g_ptr_array_index (entries, 0);
		g_free (e0->details);
		e0->details = g_strdup ("tampered details");
	}

	CHECK (!fs_audit_ledger_verify_chain (entries),
	       "audit ledger: chain verification fails on tampered entry");

	if (entries)
		g_ptr_array_free (entries, TRUE);
	g_free (h1);
	g_free (h2);
	g_free (path);
}

/* The scratch directory, removed at the end (Windows has no TMPDIR to
 * put it under the test's own folder). */
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
	gchar *dir = g_dir_make_tmp ("stockfw-pr3-XXXXXX", NULL);
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

	test_rule_validate ();
	test_replace_persist ();
#ifndef G_OS_WIN32
	test_policy_lock ();
#endif
	test_prefs_set_persist ();
	test_prefs_validate ();
	test_verdict ();
	test_intel_summary_text ();
	test_netif_virtual ();
	test_hit_filter ();
	test_settings_journal ();
	test_gate_validates ();
#ifndef G_OS_WIN32
	test_gate_takes_lock ();
#endif

	printf ("test-pr3-core: %d checks, %d failures\n", checks, failures);
	rm_tree (dir);
	g_free (dir);
	return failures ? 1 : 0;
}
