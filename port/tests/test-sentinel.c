/*---[ test-sentinel.c ]--------------------------------------------------
 * The Sentinel engine on a fake clock (the gate of PR 5).
 *
 * Written before the engine moves out of ui/fs-copilot.c into core, and
 * against what it does now, so the move can be checked against it.
 * Ten minutes, an hour of pause and a restart all run in no time: the
 * engine reads its clocks and arms its timers through the clock this
 * test hands in, and the timers fire only when the test moves the
 * clock on.  A fake backend counts the pushes and keeps what each one
 * was given.
 *
 * What it pins (each with the check that holds it):
 *
 *   stage    an auto pass stages a beacon's block: into the policy, one
 *            "S,<epoch>,<kind>,<csv>" row in the state file with the
 *            wall-clock second it was staged, audited, and pushed once
 *            (the push holds the block);
 *   expiry   the block is still there 599 s later and gone at 600 s:
 *            out of the policy, the state file shrinks to no row, the
 *            expiry is audited, and one push without the block;
 *   cooldown a block that expired is not staged again by the next
 *            pass, though its finding still asks for it; a pass with
 *            nothing new pushes nothing;
 *   pause    while paused, a pass stages nothing and the time left
 *            counts down on the clock; resuming by hand is audited and
 *            stages what came in meanwhile; once the hour is over the
 *            next pass stages again;
 *   retire   lift-all takes every staged block down (policy, state
 *            file, one push) and cools it; the Allow-lift for one
 *            destination retires its staged block and Sentinel's old
 *            row for it, never the user's own rule, and leaves the
 *            push to its caller; an expiry timer left behind by a
 *            lifted block fires with nothing to do and pushes nothing;
 *   push     a held push (audit-only) does not reach the backend and
 *            says "staged, not live" with the reason; a failed push
 *            says "staged, not live" with the result;
 *   restore  (a second process, a restart) a row past its ten minutes
 *            comes out of the policy and is handed back as due; a
 *            fresh row keeps its ORIGINAL clock: staged 300 s before
 *            the restart, it lifts 300 s after it, not 600 s.  The
 *            restore reads the wall clock it is handed: the fake
 *            clock runs years ahead of the real one, so a restore
 *            that read the real clock would drop every row.
 *
 * Not pinned on purpose: WHAT a push gives the firewall beyond the
 * staged block.  Today it is the whole policy, unapplied edits
 * included; PR 5 moves the push to fs_firewall_add_live, which leaves
 * them out.  Nor is the resume that the pause's own timer does: it
 * fires once the pause is over, when the engine already reads "not
 * paused", so today it neither audits nor catches up (with GLib's
 * second timers that depends on rounding).
 *
 * The engine is reached through the few calls under "the engine" below;
 * when it moves to core only those lines change.  Needs a display for
 * now (the engine still lives on the Copilot page): run it under
 * xvfb-run.  Everything it writes goes to a scratch directory.
 *--------------------------------------------------------------------*/

#include <gtk/gtk.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-apply.h"
#include "core/fs-backend.h"
#include "core/fs-copilot.h"
#include "core/fs-rules.h"
#include "ui/fs-copilot.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	gboolean ok_ = (cond) ? TRUE : FALSE;                   \
	printf (ok_ ? "ok:   " : "FAIL: ");                     \
	printf (__VA_ARGS__);                                   \
	printf ("\n");                                          \
	fflush (stdout);                                        \
	if (!ok_)                                               \
		failures++;                                     \
} while (0)

#define TTL_S 600

/* Public documentation addresses: no gate keeps them from a block. */
#define DEST_A "203.0.113.50"
#define DEST_B "203.0.113.51"
#define DEST_C "203.0.113.52"
#define DEST_D "198.51.100.60"
#define DEST_E "203.0.113.53"
#define DEST_F "203.0.113.54"

/* ------------------------------------------------------ the fake clock */

/* Years ahead of the real wall clock, on purpose (see restore). */
#define FAKE_EPOCH_S G_GINT64_CONSTANT (1893456000)   /* 2030-01-01 */

typedef struct
{
	guint       id;
	gint64      due_us;
	GSourceFunc fn;
	gpointer    data;
} FakeTimer;

static gint64  fake_mono_us = 0;
static gint64  fake_real_us = 0;
static GArray *fake_timers = NULL;
static guint   fake_next_id = 1;

static gint64 fake_monotonic (void) { return fake_mono_us; }
static gint64 fake_real (void) { return fake_real_us; }

static guint
fake_add (gint64 after_us, GSourceFunc fn, gpointer data)
{
	FakeTimer t = { fake_next_id++, fake_mono_us + after_us, fn, data };

	g_array_append_val (fake_timers, t);
	return t.id;
}

static guint
fake_timeout_ms (guint ms, GSourceFunc fn, gpointer data)
{
	return fake_add ((gint64) ms * 1000, fn, data);
}

static guint
fake_timeout_s (guint s, GSourceFunc fn, gpointer data)
{
	return fake_add ((gint64) s * G_USEC_PER_SEC, fn, data);
}

static gboolean
fake_remove (guint id)
{
	for (guint i = 0; i < fake_timers->len; i++)
		if (g_array_index (fake_timers, FakeTimer, i).id == id) {
			g_array_remove_index (fake_timers, i);
			return TRUE;
		}
	return FALSE;
}

static const FsSentinelClock fake_clock = {
	fake_monotonic, fake_real, fake_timeout_ms, fake_timeout_s,
	fake_remove
};

/* Move both clocks on by `s' seconds, firing every timer that falls
 * due on the way, earliest first, each at its own time. */
static void
advance (gint64 s)
{
	gint64 target = fake_mono_us + s * G_USEC_PER_SEC;

	for (;;) {
		guint pick = G_MAXUINT;
		FakeTimer t;

		for (guint i = 0; i < fake_timers->len; i++) {
			FakeTimer *c = &g_array_index (fake_timers, FakeTimer, i);

			if (c->due_us <= target &&
			    (pick == G_MAXUINT ||
			     c->due_us < g_array_index (fake_timers, FakeTimer,
			                                pick).due_us))
				pick = i;
		}
		if (pick == G_MAXUINT)
			break;
		t = g_array_index (fake_timers, FakeTimer, pick);
		g_array_remove_index (fake_timers, pick);
		fake_real_us += t.due_us - fake_mono_us;
		fake_mono_us = t.due_us;
		if (t.fn (t.data) == G_SOURCE_CONTINUE)
			fake_add (0, t.fn, t.data);   /* not used by Sentinel */
	}
	fake_real_us += target - fake_mono_us;
	fake_mono_us = target;
}

static gint64
fake_epoch (void)
{
	return fake_real_us / G_USEC_PER_SEC;
}

/* ---------------------------------------------------- the fake backend */

static guint      pushes = 0;
static gboolean   push_fails = FALSE;
static GPtrArray *pushed = NULL;          /* "kind|csv" of the last push */

static GPtrArray *
snapshot (const FsPolicy *policy)
{
	GPtrArray *rows = g_ptr_array_new_with_free_func (g_free);

	for (gint k = 0; policy != NULL && k < FS_RULE_N_KINDS; k++)
		for (guint i = 0; i < policy->kinds[k]->len; i++) {
			gchar *csv = fs_rule_to_csv (
				g_ptr_array_index (policy->kinds[k], i));

			g_ptr_array_add (rows, g_strdup_printf ("%d|%s", k, csv));
			g_free (csv);
		}
	return rows;
}

static gboolean fake_available (void) { return TRUE; }
static FsFirewallState fake_get_state (void) { return FS_FW_RUNNING; }

static FsApplyResult
fake_apply_rules (const FsPolicy *policy, GError **error)
{
	pushes++;
	if (pushed != NULL)
		g_ptr_array_unref (pushed);
	pushed = snapshot (policy);
	if (push_fails) {
		g_set_error_literal (error, g_quark_from_static_string ("fake"),
		                     1, "the fake backend refuses");
		return FS_APPLY_FAILED;
	}
	return FS_APPLY_OK;
}

static GList *fake_none (void) { return NULL; }

static gboolean
fake_log_start (FsLogFunc cb, gpointer user, GError **error)
{
	(void) cb; (void) user; (void) error;
	return TRUE;
}
static void     fake_log_stop (void) { }
static gboolean fake_log_active (void) { return TRUE; }
static const gchar *fake_log_text (void) { return NULL; }
static guint64  fake_log_skipped (void) { return 0; }

static FsIpv6State
fake_ipv6 (gchar **detail)
{
	if (detail != NULL)
		*detail = NULL;
	return FS_IPV6_FILTERED;
}

static gboolean
fake_get_profile (gint profile, gboolean *on)
{
	(void) profile; (void) on;
	return FALSE;
}

static const FsBackend fake_backend = {
	.name                 = "fake",
	.display_name         = "Fake (Sentinel)",
	.start_applies_policy = TRUE,
	.available            = fake_available,
	.get_state            = fake_get_state,
	.apply_rules          = fake_apply_rules,
	.list_interfaces      = fake_none,
	.list_interface_stats = fake_none,
	.list_connections     = fake_none,
	.list_processes       = fake_none,
	.log_start            = fake_log_start,
	.log_stop             = fake_log_stop,
	.log_active           = fake_log_active,
	.log_source           = fake_log_text,
	.log_problem          = fake_log_text,
	.log_skipped          = fake_log_skipped,
	.get_profile_enabled  = fake_get_profile,
	.ipv6_state           = fake_ipv6,
};

const FsBackend *
fs_backend (void)
{
	return &fake_backend;
}

const gchar *
fs_error_domain (void)
{
	return "fake";
}

void
fs_backend_set_context (FsPolicy *policy, FsSettings *settings)
{
	(void) policy;
	(void) settings;
}

/* ---------------------------------------------------------- the engine */

static FsCopilot *copilot = NULL;
static FsPolicy  *policy = NULL;
static GtkWidget *page = NULL;

static void
engine_start (void)
{
	gint malformed = 0;

	fs_copilot_sentinel_set_clock (&fake_clock);
	policy = fs_policy_new ();
	fs_policy_load (policy, &malformed);   /* FALSE: nothing saved yet */
	copilot = fs_copilot_new ();
	page = fs_copilot_page (copilot, policy);
	g_object_ref_sink (page);
}

#define engine_pass()           fs_copilot_sentinel_auto_pass ()
#define engine_restore(due)     fs_copilot_autoblocks_restore (policy, (due))
#define engine_pause(s)         fs_copilot_sentinel_pause (s)
#define engine_paused(left)     fs_copilot_sentinel_paused (left)
#define engine_lift_all(why)    fs_copilot_lift_all_auto_blocks (why)
#define engine_lift_dest(dest)  fs_copilot_lift_auto_blocks_for_dest (dest)

/* ------------------------------------------------------------- helpers */

static gchar *scratch = NULL;

static gchar *
in_scratch (const gchar *name)
{
	return g_build_filename (scratch, name, NULL);
}

static void
isolate (void)
{
	gchar *p;

	scratch = g_dir_make_tmp ("stockfw-sentinel-XXXXXX", NULL);
	if (scratch == NULL) {
		printf ("FAIL: no scratch directory\n");
		exit (1);
	}
	p = in_scratch ("rules");
	g_mkdir_with_parents (p, 0700);
	g_setenv ("STOCKFW_RULES_DIR", p, TRUE);
	g_free (p);
#define SCRATCH_ENV(var, name) do {                               \
		gchar *p_ = in_scratch (name);                        \
		g_setenv (var, p_, TRUE);                             \
		g_free (p_);                                          \
	} while (0)
	SCRATCH_ENV ("STOCKFW_AUDIT_FILE", "audit.log");
	SCRATCH_ENV ("STOCKFW_APPLIED_FILE", "applied.csv");
	SCRATCH_ENV ("STOCKFW_AUTOBLOCK_FILE", "autoblocks");
	SCRATCH_ENV ("STOCKFW_BEHAVIOR_FILE", "behavior.csv");
	SCRATCH_ENV ("STOCKFW_TRUST_FILE", "trust.csv");
	g_setenv ("APPDATA", scratch, TRUE);
	g_setenv ("XDG_CONFIG_HOME", scratch, TRUE);
	g_setenv ("HOME", scratch, TRUE);
	g_setenv ("STOCKFW_LAN_PREFIX", "192.168.1.0/24", TRUE);
	g_setenv ("STOCKFW_LOCAL_ADDRESSES", "", TRUE);

	fake_timers = g_array_new (FALSE, FALSE, sizeof (FakeTimer));
	fake_mono_us = (gint64) 5000 * G_USEC_PER_SEC;
	fake_real_us = FAKE_EPOCH_S * G_USEC_PER_SEC;
}

static void
rm_rf (const gchar *path)
{
	GDir *dir = g_dir_open (path, 0, NULL);

	if (dir != NULL) {
		const gchar *name;

		while ((name = g_dir_read_name (dir)) != NULL) {
			gchar *child = g_build_filename (path, name, NULL);

			if (g_file_test (child, G_FILE_TEST_IS_DIR))
				rm_rf (child);
			else
				g_unlink (child);
			g_free (child);
		}
		g_dir_close (dir);
	}
	g_rmdir (path);
}

static gchar *
file_text (const gchar *name)
{
	gchar *path = in_scratch (name);
	gchar *text = NULL;

	if (!g_file_get_contents (path, &text, NULL, NULL))
		text = g_strdup ("");
	g_free (path);
	return text;
}

static gsize
file_size (const gchar *name)
{
	gchar *text = file_text (name);
	gsize n = strlen (text);

	g_free (text);
	return n;
}

static guint
state_rows (void)
{
	gchar *text = file_text ("autoblocks");
	gchar **lines = g_strsplit (text, "\n", -1);
	guint n = 0;

	for (guint i = 0; lines[i] != NULL; i++)
		if (g_str_has_prefix (lines[i], "S,"))
			n++;
	g_strfreev (lines);
	g_free (text);
	return n;
}

static gboolean
file_says (const gchar *name, const gchar *needle)
{
	gchar *text = file_text (name);
	gboolean hit = strstr (text, needle) != NULL;

	g_free (text);
	return hit;
}

static guint
audit_count (const gchar *needle)
{
	gchar *text = file_text ("audit.log");
	guint n = 0;

	for (const gchar *p = strstr (text, needle); p != NULL;
	     p = strstr (p + 1, needle))
		n++;
	g_free (text);
	return n;
}

/* Every push the engine tries says how it went in the audit log, even
 * one the gate finds nothing to do for (the backend is not called). */
static guint
push_tries (void)
{
	return audit_count ("sentinel auto-block is live") +
	       audit_count ("sentinel auto-block staged, not live");
}

/* The block a beacon to `dest' asks for. */
static gchar *
block_csv (const gchar *dest)
{
	return g_strdup_printf ("%s, Sentinel: periodic beacon", dest);
}

static gboolean
policy_has (FsPolicy *p, FsRuleKind kind, const gchar *csv)
{
	FsRule *rule = fs_rule_from_csv (kind, csv);
	gboolean in = rule != NULL && fs_policy_contains (p, rule);

	fs_rule_free (rule);
	return in;
}

static gboolean
has_block (const gchar *dest)
{
	gchar *csv = block_csv (dest);
	gboolean in = policy_has (policy, FS_RULE_OUTBOUND_DENY_TO, csv);

	g_free (csv);
	return in;
}

static gboolean
pushed_block (const gchar *dest)
{
	gchar *csv = block_csv (dest);
	FsRule *rule = fs_rule_from_csv (FS_RULE_OUTBOUND_DENY_TO, csv);
	gchar *norm = fs_rule_to_csv (rule);
	gchar *key = g_strdup_printf ("%d|%s", (int) FS_RULE_OUTBOUND_DENY_TO,
	                              norm);
	gboolean hit = FALSE;

	for (guint i = 0; pushed != NULL && i < pushed->len && !hit; i++)
		hit = g_strcmp0 (g_ptr_array_index (pushed, i), key) == 0;
	fs_rule_free (rule);
	g_free (norm);
	g_free (key);
	g_free (csv);
	return hit;
}

static void
put_rule (FsPolicy *p, FsRuleKind kind, const gchar *csv)
{
	FsRule *rule = fs_rule_from_csv (kind, csv);

	if (rule == NULL) {
		printf ("FAIL: cannot read the rule \"%s\"\n", csv);
		failures++;
		return;
	}
	fs_policy_add (p, rule);
	fs_rule_free (rule);
}

/* Eight contacts to `dest', exactly 60 s apart, from one program: a
 * beacon that asks to be blocked. */
static void
feed_beacon (const gchar *dest, gint64 t0_s)
{
	FsHit hit;

	memset (&hit, 0, sizeof hit);
	hit.direction   = "Out";
	hit.source      = "192.168.1.7";
	hit.destination = (gchar *) dest;
	hit.port        = "443";
	hit.protocol    = "TCP";
	hit.service     = "beacon.exe";
	for (gint i = 0; i < 8; i++)
		fs_copilot_feed_event_at (copilot, &hit,
			(t0_s + (gint64) i * 60) * G_USEC_PER_SEC);
}

/* ------------------------------------------------- the running session */

static void
test_session (void)
{
	gchar *row;
	gsize full;
	gint64 left = -1;
	guint before, tried;

	engine_start ();
	CHECK (page != NULL, "the engine starts (on the Copilot page)");

	/* ---- stage ---- */
	feed_beacon (DEST_A, 100000);
	before = pushes;
	CHECK (engine_pass (), "stage: the pass stages the beacon's block");
	CHECK (has_block (DEST_A), "stage: the block is in the policy");
	row = g_strdup_printf ("S,%" G_GINT64_FORMAT ",%d,%s", fake_epoch (),
	                       (int) FS_RULE_OUTBOUND_DENY_TO,
	                       DEST_A ", Sentinel: periodic beacon");
	CHECK (state_rows () == 1 && file_says ("autoblocks", row),
	       "stage: one state row, with the wall-clock second it was "
	       "staged (%s)", row);
	g_free (row);
	CHECK (audit_count ("| sentinel auto-block | " DEST_A) == 1,
	       "stage: audited");
	CHECK (pushes == before + 1 && pushed_block (DEST_A),
	       "push: one push, and it holds the block");
	CHECK (audit_count ("sentinel auto-block is live") == 1,
	       "push: audited as live");
	full = file_size ("autoblocks");

	/* ---- expiry ---- */
	before = pushes;
	tried = push_tries ();
	advance (TTL_S - 1);
	CHECK (has_block (DEST_A) && state_rows () == 1 && pushes == before &&
	       push_tries () == tried,
	       "expiry: still blocked after 599 s, nothing pushed");
	advance (1);
	CHECK (!has_block (DEST_A), "expiry: lifted at 600 s");
	CHECK (state_rows () == 0 && file_size ("autoblocks") < full,
	       "expiry: the state file shrinks (%" G_GSIZE_FORMAT " -> %"
	       G_GSIZE_FORMAT " bytes)", full, file_size ("autoblocks"));
	CHECK (audit_count ("expired after 10 minutes") == 1,
	       "expiry: audited");
	CHECK (pushes == before + 1 && !pushed_block (DEST_A),
	       "push: one push after the expiry, without the block");

	/* ---- cooldown ---- */
	before = pushes;
	tried = push_tries ();
	CHECK (!engine_pass () && !has_block (DEST_A) && state_rows () == 0,
	       "cooldown: the expired block is not staged again");
	CHECK (pushes == before && push_tries () == tried,
	       "push: a pass with nothing new pushes nothing");

	/* ---- pause ---- */
	feed_beacon (DEST_B, 200000);
	engine_pause (3600);
	CHECK (engine_paused (&left) && left == 3600,
	       "pause: paused, 3600 s left (%" G_GINT64_FORMAT ")", left);
	CHECK (!engine_pass () && !has_block (DEST_B),
	       "pause: a paused pass stages nothing");
	CHECK (audit_count ("sentinel auto-block paused") == 1,
	       "pause: audited");
	advance (1800);
	CHECK (engine_paused (&left) && left == 1800,
	       "pause: the time left follows the clock (%" G_GINT64_FORMAT
	       ")", left);
	CHECK (!has_block (DEST_B), "pause: still nothing staged");
	before = pushes;
	engine_pause (0);
	CHECK (!engine_paused (NULL), "pause: resumed by hand");
	CHECK (audit_count ("sentinel auto-block resumed") == 1,
	       "pause: the resume is audited");
	CHECK (has_block (DEST_B) && state_rows () == 1 &&
	       pushes == before + 1,
	       "pause: the resume stages what came in meanwhile, and "
	       "pushes it");
	/* The pause's own timer was taken back: an hour on, nothing
	 * resumes twice. */
	engine_pause (3600);
	feed_beacon (DEST_C, 300000);
	CHECK (!engine_pass () && !has_block (DEST_C),
	       "pause: paused again, nothing staged");
	advance (3599);
	CHECK (engine_paused (&left) && left == 1,
	       "pause: one second left after 3599 s");
	advance (1);
	CHECK (!engine_paused (NULL), "pause: over after an hour");
	CHECK (!has_block (DEST_B) && state_rows () == 0,
	       "expiry: the block staged at the resume lifted on its own "
	       "clock during the second pause");
	CHECK (engine_pass () && has_block (DEST_C),
	       "pause: once over, the next pass stages again");

	/* ---- retire ---- */
	before = pushes;
	CHECK (engine_lift_all ("lifted by user"),
	       "retire: lift-all lifts the staged block");
	CHECK (!has_block (DEST_C) && state_rows () == 0,
	       "retire: out of the policy and the state file");
	CHECK (pushes == before + 1 && !pushed_block (DEST_C),
	       "push: one push after lift-all, without the block");
	CHECK (!engine_lift_all ("lifted by user"),
	       "retire: lift-all with nothing staged says so");
	CHECK (!engine_pass () && !has_block (DEST_C),
	       "cooldown: a lifted block is not staged again");
	before = pushes;
	tried = push_tries ();
	advance (TTL_S);
	CHECK (pushes == before && push_tries () == tried &&
	       state_rows () == 0,
	       "expiry: the timer the lifted block left behind pushes "
	       "nothing");

	/* The user's Allow: the staged block and Sentinel's own row from
	 * an earlier session go, the user's own rule stays, and the
	 * caller pushes. */
	{
		gchar *old = block_csv (DEST_E);

		feed_beacon (DEST_D, 400000);
		CHECK (engine_pass () && has_block (DEST_D),
		       "stage: a block to lift");
		put_rule (policy, FS_RULE_OUTBOUND_DENY_TO, old);
		put_rule (policy, FS_RULE_OUTBOUND_DENY_TO,
		          DEST_E ", my own block");
		fs_policy_save (policy);
		before = pushes;
		tried = push_tries ();
		CHECK (engine_lift_dest (DEST_D) && !has_block (DEST_D) &&
		       state_rows () == 0,
		       "retire: the Allow lifts the staged block");
		CHECK (engine_lift_dest (DEST_E) && !has_block (DEST_E),
		       "retire: the Allow lifts Sentinel's old row");
		CHECK (policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
		                   DEST_E ", my own block"),
		       "retire: the user's own rule stays");
		CHECK (pushes == before && push_tries () == tried,
		       "push: the Allow-lift leaves the push to its caller");
		CHECK (!engine_pass () && !has_block (DEST_D),
		       "cooldown: the lifted block is not staged again");
		g_free (old);
	}

	/* ---- push: held, failed ---- */
	fs_apply_set_audit_only (TRUE);
	before = pushes;
	feed_beacon (DEST_F, 500000);
	CHECK (engine_pass () && has_block (DEST_F) && state_rows () == 1,
	       "stage: staged while audit-only is on");
	CHECK (pushes == before,
	       "push: held by audit-only, the backend is not called");
	CHECK (file_says ("audit.log", "sentinel auto-block staged, not live "
	                  "| audit-only testing mode"),
	       "push: audited as held, with the reason");
	fs_apply_set_audit_only (FALSE);
	CHECK (engine_lift_all ("lifted by user"),
	       "retire: lift-all after the held stage");
	push_fails = TRUE;
	feed_beacon ("203.0.113.55", 600000);
	before = pushes;
	CHECK (engine_pass (), "stage: staged with a failing backend");
	CHECK (pushes > before &&
	       audit_count ("sentinel auto-block staged, not live") == 2,
	       "push: a failed push is audited as not live");
	push_fails = FALSE;

	g_object_unref (page);
}

/* --------------------------------------------------------- the restart */

static void
test_restore (void)
{
	FsPolicy *due = fs_policy_new ();
	gchar *fresh = block_csv ("203.0.113.60");
	gchar *stale = block_csv ("203.0.113.61");
	gchar *path, *rows;

	engine_start ();

	/* The last session staged `fresh' 300 s and `stale' 700 s ago. */
	put_rule (policy, FS_RULE_OUTBOUND_DENY_TO, fresh);
	put_rule (policy, FS_RULE_OUTBOUND_DENY_TO, stale);
	fs_policy_save (policy);
	rows = g_strdup_printf (
		"S,%" G_GINT64_FORMAT ",%d,%s\nS,%" G_GINT64_FORMAT ",%d,%s\n",
		fake_epoch () - 300, (int) FS_RULE_OUTBOUND_DENY_TO, fresh,
		fake_epoch () - 700, (int) FS_RULE_OUTBOUND_DENY_TO, stale);
	path = in_scratch ("autoblocks");
	g_file_set_contents (path, rows, -1, NULL);
	g_free (path);
	g_free (rows);

	CHECK (engine_restore (due), "restore: a row was due");
	CHECK (!policy_has (policy, FS_RULE_OUTBOUND_DENY_TO, stale) &&
	       policy_has (due, FS_RULE_OUTBOUND_DENY_TO, stale),
	       "restore: the row past its ten minutes is lifted and due");
	CHECK (policy_has (policy, FS_RULE_OUTBOUND_DENY_TO, fresh) &&
	       !policy_has (due, FS_RULE_OUTBOUND_DENY_TO, fresh),
	       "restore: the fresh row is kept");
	CHECK (state_rows () == 1 && file_says ("autoblocks", fresh),
	       "restore: the state file holds the fresh row only");
	CHECK (audit_count ("1 expired while StockFW was not running") == 1,
	       "restore: audited");

	advance (299);
	CHECK (policy_has (policy, FS_RULE_OUTBOUND_DENY_TO, fresh),
	       "restore: still blocked 299 s after the restart");
	advance (1);
	CHECK (!policy_has (policy, FS_RULE_OUTBOUND_DENY_TO, fresh) &&
	       state_rows () == 0,
	       "restore: lifted 300 s after the restart, on its original "
	       "clock (not a fresh ten minutes)");
	CHECK (audit_count ("expired after 10 minutes") == 1,
	       "restore: the expiry is audited");

	fs_policy_free (due);
	g_free (fresh);
	g_free (stale);
	g_object_unref (page);
}

/* ---------------------------------------------------------------- main */

/* A GLib or GTK warning on the way is a failure too. */
static guint warnings = 0;

static GLogWriterOutput
count_warnings (GLogLevelFlags level, const GLogField *fields,
                gsize n_fields, gpointer data)
{
	(void) data;
	if (level & (G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL))
		warnings++;
	return g_log_writer_default (level, fields, n_fields, NULL);
}

static int
run_child (const gchar *self, const gchar *part)
{
	gchar *argv[] = { (gchar *) self, (gchar *) part, NULL };
	gchar *out = NULL;
	gint status = 0;
	GError *error = NULL;
	int bad = 0;

	if (!g_spawn_sync (NULL, argv, NULL, G_SPAWN_DEFAULT,
	                   NULL, NULL, &out, NULL, &status, &error)) {
		printf ("FAIL: could not run the %s part: %s\n", part,
		        error->message);
		g_clear_error (&error);
		return 1;
	}
	fputs (out != NULL ? out : "", stdout);
	if (!g_spawn_check_wait_status (status, NULL)) {
		bad = 1;
		if (out == NULL || strstr (out, "FAIL") == NULL)
			printf ("FAIL: the %s part exited badly\n", part);
	}
	g_free (out);
	return bad;
}

int
main (int argc, char **argv)
{
	int bad = 0;

	if (argc < 2) {
		/* One process each: the restore is a restart. */
		bad += run_child (argv[0], "session");
		bad += run_child (argv[0], "restore");
		printf ("\ntest-sentinel: %s\n", bad ? "FAILED" : "PASSED");
		return bad ? 1 : 0;
	}

	g_log_set_writer_func (count_warnings, NULL, NULL);
	isolate ();
	gtk_init (&argc, &argv);

	if (strcmp (argv[1], "session") == 0)
		test_session ();
	else if (strcmp (argv[1], "restore") == 0)
		test_restore ();
	else {
		printf ("FAIL: no part called %s\n", argv[1]);
		failures++;
	}

	CHECK (warnings == 0, "no GLib or GTK warning (%u)", warnings);
	rm_rf (scratch);
	g_free (scratch);
	printf ("%s part: %d failure(s)\n", argv[1], failures);
	return failures ? 1 : 0;
}
