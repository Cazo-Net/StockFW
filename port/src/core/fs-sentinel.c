/*---[ fs-sentinel.c ]---------------------------------------------------
 * Sentinel's auto-block engine, without a window: see the header.
 *
 * Moved from ui/fs-copilot.c (PR 5).  What it does is unchanged but
 * for the push, which now goes through fs_firewall_add_live and
 * fs_firewall_lift_live instead of applying the whole policy file.
 *--------------------------------------------------------------------*/

#include "core/fs-sentinel.h"
#include "core/fs-apply.h"
#include "core/fs-audit.h"
#include "core/fs-autoblock.h"
#include "core/fs-util.h"

#include <string.h>

/* =====================================================================
 * State
 *
 * Mode is detect|auto (default auto), cached so the per-event pass
 * does not read the key file.  Auto-blocked rules are tracked with
 * the time they were staged: the user can undo any of them, and
 * every one expires ten minutes after staging (FS_AUTOBLOCK_TTL_S)
 * unless it was staged manually through the Policy page first.
 * ===================================================================== */
static gchar      sentinel_mode[16] = "auto";
static FsCopilot *engine_copilot = NULL;
static FsPolicy  *engine_policy = NULL;
static FsSentinelHooks hooks = { NULL, NULL, NULL, NULL };

static GPtrArray *auto_blocks       = NULL;  /* FsSentinelBlock*, freed */
static guint      auto_block_expiry_id = 0;
/* Tray "Pause Sentinel auto-block for 1 hour": while this monotonic
 * time is in the future, the auto pass stages nothing.  Blocks already
 * staged keep their own ten minutes.  Not persisted: a restart
 * resumes auto-block. */
static gint64     sentinel_paused_until = 0;
static guint      sentinel_resume_id = 0;
static gint64     auto_block_last_fail = 0;
static gboolean   auto_block_failed_once = FALSE;

/* P6: session memory of every auto-block this process staged and then
 * took down (expiry, Undo, user allow, mode switch).  Staging the
 * same rule again is the 2026-10-10 incident -- drop after ten
 * minutes, re-block the next second, forever -- so the auto pass
 * refuses it.  Memory-only by design: it protects the session from a
 * loop and never outlives the process, so a restart makes a fresh
 * decision instead of inheriting a grudge. */
static GHashTable *auto_block_cooldown = NULL;  /* "kind|csv" -> TRUE */

/* The clock the engine reads and arms its timers on: GLib's, unless a
 * test hands in a fake one (fs_sentinel_set_clock).  Wrapped, so the
 * table is a constant on every platform. */
static gint64 glib_monotonic_us (void) { return g_get_monotonic_time (); }
static gint64 glib_real_us (void) { return g_get_real_time (); }

static guint
glib_timeout_ms (guint ms, GSourceFunc fn, gpointer data)
{
	return g_timeout_add (ms, fn, data);
}

static guint
glib_timeout_s (guint s, GSourceFunc fn, gpointer data)
{
	return g_timeout_add_seconds (s, fn, data);
}

static gboolean glib_source_remove (guint id) { return g_source_remove (id); }

static const FsSentinelClock glib_clock = {
	glib_monotonic_us, glib_real_us, glib_timeout_ms, glib_timeout_s,
	glib_source_remove
};
static const FsSentinelClock *sentinel_clock = &glib_clock;

static gboolean auto_block_expire_cb (gpointer data);

/* [ fs_sentinel_set_clock ] */
void
fs_sentinel_set_clock (const FsSentinelClock *clock)
{
	sentinel_clock = clock != NULL ? clock : &glib_clock;
}

/* [ fs_sentinel_set_hooks ] */
void
fs_sentinel_set_hooks (const FsSentinelHooks *h)
{
	if (h != NULL)
		hooks = *h;
	else
		memset (&hooks, 0, sizeof hooks);
}

/* [ fs_sentinel_attach ] */
void
fs_sentinel_attach (FsCopilot *copilot, FsPolicy *policy)
{
	engine_copilot = copilot;
	engine_policy = policy;
}

/* [ fs_sentinel_set_mode ] */
void
fs_sentinel_set_mode (const gchar *mode)
{
	g_strlcpy (sentinel_mode,
	           (mode != NULL && *mode != '\0') ? mode : "auto",
	           sizeof sentinel_mode);
}

const gchar *
fs_sentinel_mode (void)
{
	return sentinel_mode;
}

gboolean
fs_sentinel_is_auto (void)
{
	return g_strcmp0 (sentinel_mode, "auto") == 0;
}

static void
refresh (FsSentinelEvent event, const FsSentinelBlock *block,
         const gchar *why)
{
	if (hooks.refresh != NULL)
		hooks.refresh (event, block, why);
}

/* =====================================================================
 * Sentinel auto-block: stage, undo, expire
 *
 * In auto mode every auto-applicable insight whose rule is not already
 * in the policy is staged (add + save, rolled back on a failed write)
 * and pushed at the firewall.  Each staged rule carries the time it
 * was staged: Undo lifts one immediately, and all of them lift ten
 * minutes after staging -- a false positive must not be a permanent
 * policy change.  Every step is written to the append-only audit log.
 * ===================================================================== */

/* [ fs_sentinel_find ] */
FsSentinelBlock *
fs_sentinel_find (FsRuleKind kind, const gchar *csv)
{
	guint i;

	if (auto_blocks == NULL || csv == NULL)
		return NULL;

	for (i = 0; i < auto_blocks->len; i++) {
		FsSentinelBlock *ab = g_ptr_array_index (auto_blocks, i);

		if (ab->kind == kind && g_strcmp0 (ab->csv, csv) == 0)
			return ab;
	}

	return NULL;
}

guint
fs_sentinel_count (void)
{
	return auto_blocks != NULL ? auto_blocks->len : 0;
}

FsSentinelBlock *
fs_sentinel_nth (guint i)
{
	if (auto_blocks == NULL || i >= auto_blocks->len)
		return NULL;
	return g_ptr_array_index (auto_blocks, i);
}

gboolean
fs_sentinel_holds (const FsSentinelBlock *block)
{
	return block != NULL && auto_blocks != NULL &&
	       g_ptr_array_find (auto_blocks, block, NULL);
}

static void
auto_block_free (gpointer data)
{
	FsSentinelBlock *ab = data;

	if (ab == NULL)
		return;

	g_free (ab->csv);
	g_free (ab->title);
	g_free (ab);
}

/* =====================================================================
 * P6 (false-outage hardening): cooldown memory + persistent staging
 *
 * The 2026-10-10 incident was three silent loops stacked: a
 * ten-minute expiry whose re-stage ran forever, staging records that
 * lived only in memory while the policy rows they created survived
 * every restart, and a user Allow that the block rule outranked on
 * Windows.  These helpers close all three: the cooldown breaks the
 * re-stage loop, the state file gives the boot restore something to
 * expire, and the lift functions give the user's Allow the last word.
 * ===================================================================== */

static gchar *
auto_block_key (FsRuleKind kind, const gchar *csv)
{
	return g_strdup_printf ("%d|%s", (int) kind, csv != NULL ? csv : "");
}

static void
auto_block_cooldown_add (FsRuleKind kind, const gchar *csv)
{
	if (auto_block_cooldown == NULL)
		auto_block_cooldown = g_hash_table_new_full (g_str_hash,
		                                             g_str_equal,
		                                             g_free, NULL);

	g_hash_table_add (auto_block_cooldown, auto_block_key (kind, csv));
}

/* [ fs_sentinel_cooled ] */
gboolean
fs_sentinel_cooled (FsRuleKind kind, const gchar *csv)
{
	gboolean hit;
	gchar *key;

	if (auto_block_cooldown == NULL)
		return FALSE;

	key = auto_block_key (kind, csv);
	hit = g_hash_table_contains (auto_block_cooldown, key);
	g_free (key);

	return hit;
}

/* TRUE while the file is behind the array: the last write failed.
 * fs_sentinel_flush() retries it (the periodic save and the end of
 * the session call it), so one failed write is not left until the
 * next stage or retire happens to come along. */
static gboolean auto_block_state_unsaved = FALSE;

/* [ auto_block_state_save ]
 * Rewrite the staged list from the array: one row per block this
 * session staged -- "S,<epoch>,<kind>,<csv>", csv last so its commas
 * survive the split.  Called on every stage and every retire, so the
 * file mirrors the session's OWN blocks and never a user's manual
 * rule.  A failed write is audited, not swallowed: without this file
 * a restart turns managed blocks into orphans nobody expires.  Once
 * per run of failures, so a retry every few minutes against a full
 * disk does not fill the audit log; the recovery is audited too. */
static void
auto_block_state_save (void)
{
	gchar *path = fs_autoblock_state_path ();
	gchar *dir;
	GString *out;
	GError *error = NULL;
	guint i;

	out = g_string_new (NULL);

	if (auto_blocks != NULL) {
		for (i = 0; i < auto_blocks->len; i++) {
			FsSentinelBlock *ab = g_ptr_array_index (auto_blocks, i);

			g_string_append_printf (out, "S,%" G_GINT64_FORMAT ",%d,%s\n",
			                        ab->at_epoch, (int) ab->kind,
			                        ab->csv != NULL ? ab->csv : "");
		}
	}

	dir = g_path_get_dirname (path);
	g_mkdir_with_parents (dir, 0700);
	g_free (dir);

	if (!g_file_set_contents (path, out->str, -1, &error)) {
		if (!auto_block_state_unsaved)
			fs_audit_log ("sentinel auto-block state save failed",
			              error != NULL ? error->message : path);
		auto_block_state_unsaved = TRUE;
		g_clear_error (&error);
	} else if (auto_block_state_unsaved) {
		fs_audit_log ("sentinel auto-block state saved after a failed "
		              "write", path);
		auto_block_state_unsaved = FALSE;
	}

	g_string_free (out, TRUE);
	g_free (path);
}

/* [ fs_sentinel_flush ] */
gboolean
fs_sentinel_flush (void)
{
	if (auto_block_state_unsaved)
		auto_block_state_save ();

	return !auto_block_state_unsaved;
}

/* [ rows_add ] -- a copy of the block's rule into `rows'. */
static void
rows_add (FsPolicy *rows, FsRuleKind kind, const gchar *csv)
{
	FsRule *rule = fs_rule_from_csv (kind, csv);

	if (rule != NULL && !fs_policy_contains (rows, rule))
		fs_policy_add (rows, rule);        /* stores a copy */
	fs_rule_free (rule);
}

static gboolean
rows_empty (const FsPolicy *rows)
{
	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		if (fs_policy_count (rows, (FsRuleKind) k) > 0)
			return FALSE;
	return TRUE;
}

/* [ journal_holds ] -- TRUE when the journal records every row. */
static gboolean
journal_holds (const FsPolicy *rows)
{
	FsPolicy *live = fs_policy_new ();
	gboolean all = fs_apply_journal_load (live, NULL);

	for (gint k = 0; all && k < FS_RULE_N_KINDS; k++)
		for (guint i = 0; all && i < rows->kinds[k]->len; i++)
			all = fs_policy_contains (live,
				g_ptr_array_index (rows->kinds[k], i));
	fs_policy_free (live);
	return all;
}

/* [ live_push ]
 * fs_firewall_add_live or fs_firewall_lift_live, with the backend
 * given the settings that are live.  The desktop app's backend holds
 * the SAVED preferences, which may hold a change saved and not applied
 * (Preferences, "Later").  When the journal records the settings it
 * went out with, the settings hook puts those in the backend for this
 * one push and the journal keeps that record
 * (fs_firewall_live_keeps_settings), so the saved change stays pending
 * and goes out with the next apply, not with a block or a lift. */
static FsApplyOutcome *
live_push (const FsBackend *backend, const FsPolicy *rows, gboolean add,
           const gchar *source, const gchar *hold, GError **error)
{
	FsSettings *live = hooks.settings != NULL
	                 ? fs_settings_from_journal (NULL) : NULL;
	FsApplyOutcome *outcome;

	if (live != NULL) {
		hooks.settings (live);
		fs_firewall_live_keeps_settings (TRUE);
	}
	outcome = add ? fs_firewall_add_live (backend, rows, source, hold,
	                                      error)
	              : fs_firewall_lift_live (backend, rows, source, hold,
	                                       error);
	if (live != NULL) {
		fs_firewall_live_keeps_settings (FALSE);
		hooks.settings (NULL);
		fs_settings_free (live);
	}
	return outcome;
}

/* [ block_push ]
 * Put the blocks just staged (`add') on the firewall, or take the
 * blocks just lifted off it, and record honestly whether that went
 * live -- through the gate, so a held or rolled-back push never gets
 * an "is live" line.  Only those rows change: fs_firewall_add_live and
 * fs_firewall_lift_live start from the journal (what is live), never
 * from the policy file, which may hold changes nobody applied.
 *
 * With no journal at all, nothing was ever applied: there is no record
 * to add to, and the add applies the policy as the first apply does
 * (as the start gate does with no journal, fs-apply.h).  That apply
 * writes the journal, so from then on only the block goes out.  A
 * journal that cannot be read is not guessed at: the block is staged,
 * not live.
 *
 * A lift with no journal, or one that cannot be read, cannot start
 * from the record, and the block may be on the firewall all the same
 * (an apply that went out and whose journal could not be saved).  It
 * then applies the policy, which no longer holds the block, as the
 * push did before PR 5, so a block does not outlive its ten minutes
 * for want of a record.  Not on a firewall that a start installs
 * (Linux) while it is stopped: nothing is on it, and an apply there
 * would start it.
 *
 * When add_live or lift_live has nothing to do (NULL): an add of rows
 * already live is live; a lift of rows that are not on record as live
 * says so.  Every push leaves an audit line.  The outcome, or NULL, is
 * the caller's. */
static FsApplyOutcome *
block_push (const FsPolicy *rows, gboolean add, const gchar *source,
            GError **error)
{
	const FsBackend *backend;
	const gchar *hold;
	FsApplyOutcome *outcome;
	FsPolicy *live;
	GError *journal_error = NULL;
	gboolean have, none;

	if (engine_policy == NULL || rows == NULL || rows_empty (rows))
		return NULL;

	backend = hooks.backend != NULL ? hooks.backend () : NULL;
	hold = hooks.hold != NULL ? hooks.hold () : NULL;

	live = fs_policy_new ();
	have = fs_apply_journal_load (live, &journal_error);
	none = !have && g_error_matches (journal_error, FS_APPLY_ERROR,
	                                 FS_APPLY_ERR_NO_JOURNAL);
	fs_policy_free (live);
	g_clear_error (&journal_error);

	if (add) {
		if (!have && !none) {
			fs_audit_log ("sentinel auto-block staged, not live",
			              "the record of what is live cannot be "
			              "read");
			return NULL;
		}
		outcome = none
		        ? fs_policy_apply_safe (backend, engine_policy,
		                                source, hold, error)
		        : live_push (backend, rows, TRUE, source, hold, error);
	} else if (have) {
		outcome = live_push (backend, rows, FALSE, source, hold, error);
	} else if (backend != NULL && backend->start_applies_policy &&
	           backend->get_state != NULL &&
	           backend->get_state () == FS_FW_STOPPED) {
		outcome = NULL;
	} else {
		fs_audit_log ("sentinel auto-block lift applies the policy",
		              none ? "there is no record of what is live"
		                   : "the record of what is live cannot be "
		                     "read");
		outcome = fs_policy_apply_safe (backend, engine_policy, source,
		                                hold, error);
	}

	if (outcome == NULL) {
		if (add)
			fs_audit_log ("sentinel auto-block is live",
			              "already live");
		else
			fs_audit_log ("sentinel auto-block lifted, not on "
			              "record as live",
			              "nothing on the firewall changed");
		return NULL;
	}

	if (outcome->applied) {
		fs_audit_log ("sentinel auto-block is live",
		              fs_util_apply_result_to_string ((int) outcome->result));
		if (add && !journal_holds (rows))
			fs_audit_log ("sentinel auto-block not on record",
			              "the record of what is live was not "
			              "saved; a full apply clears the block");
	} else if (outcome->held)
		fs_audit_log ("sentinel auto-block staged, not live",
		              outcome->hold_reason);
	else
		fs_audit_log ("sentinel auto-block staged, not live",
		              fs_util_apply_result_to_string ((int) outcome->result));

	return outcome;
}

/* [ auto_block_push ] -- block_push, for a caller that keeps nothing. */
static void
auto_block_push (const FsPolicy *rows, gboolean add)
{
	GError *error = NULL;
	FsApplyOutcome *outcome = block_push (rows, add,
	                                      "sentinel auto-block", &error);

	if (outcome != NULL)
		fs_apply_outcome_free (outcome);
	g_clear_error (&error);
}

/* [ auto_block_drop ]
 * Take one staged auto-block back out of the policy.  The removal is
 * persisted with the same rollback-on-failure discipline as the add,
 * so a failed write keeps the rule (and says so) rather than
 * pretending the block is gone.  Does not touch the array; callers
 * remove the entry. */
static void
auto_block_drop (FsSentinelBlock *ab, const gchar *why)
{
	FsRule *rule;
	gboolean removed = FALSE;
	gchar *detail;

	if (ab == NULL)
		return;

	if (engine_policy != NULL) {
		rule = fs_rule_from_csv (ab->kind, ab->csv);

		if (rule != NULL) {
			removed = fs_policy_remove_persist (engine_policy, rule);
			fs_rule_free (rule);
		}
	}

	detail = g_strdup_printf ("%s (%s)", ab->csv, why);
	fs_audit_log (removed ? "sentinel auto-block removed"
	                      : "sentinel auto-block removal had no effect",
	              detail);
	g_free (detail);

	if (removed)
		refresh (FS_SENTINEL_POLICY_CHANGED, NULL, NULL);
}

/* [ auto_block_rule_in_policy ]
 * TRUE when the staged rule is (still) in the policy: either the user
 * put it there, or the removal just failed.  The boot restore keeps
 * tracking such a row so the expiry timer retries the drop instead of
 * leaving a block nobody manages. */
static gboolean
auto_block_rule_in_policy (FsSentinelBlock *ab)
{
	FsRule *rule;
	gboolean in;

	if (ab == NULL || engine_policy == NULL)
		return FALSE;

	rule = fs_rule_from_csv (ab->kind, ab->csv);
	if (rule == NULL)
		return TRUE;   /* cannot see it: assume the worst */

	in = fs_policy_contains (engine_policy, rule);
	fs_rule_free (rule);

	return in;
}

/* [ auto_block_retire ]
 * Take a staged auto-block down for good: out of the policy, into the
 * session cooldown so the auto pass cannot stage it right back, and
 * out of the array (freeing it) when it was in one -- which also
 * rewrites the state file, so a retirement never leaves a stale row
 * behind.  The refresh hook hears of it first (the Changes card keeps
 * it, with how it ended).  `lifted', when not NULL, gets a copy of
 * the rule for the push. */
static void
auto_block_retire (FsSentinelBlock *ab, const gchar *why, FsPolicy *lifted)
{
	if (ab == NULL)
		return;

	auto_block_drop (ab, why);
	auto_block_cooldown_add (ab->kind, ab->csv);
	if (lifted != NULL)
		rows_add (lifted, ab->kind, ab->csv);

	refresh (FS_SENTINEL_RETIRED, ab, why);

	if (auto_blocks != NULL && g_ptr_array_remove (auto_blocks, ab))
		auto_block_state_save ();
}

/* [ fs_sentinel_retire ] */
gboolean
fs_sentinel_retire (FsSentinelBlock *block, const gchar *why)
{
	if (!fs_sentinel_holds (block))
		return FALSE;
	auto_block_retire (block, why, NULL);
	return TRUE;
}

/* [ fs_sentinel_undo ] */
gboolean
fs_sentinel_undo (FsSentinelBlock *block, const gchar *why,
                  FsApplyOutcome **outcome, GError **error)
{
	FsPolicy *rows;
	FsApplyOutcome *o;

	if (outcome != NULL)
		*outcome = NULL;
	if (!fs_sentinel_holds (block))
		return FALSE;

	rows = fs_policy_new ();
	auto_block_retire (block, why, rows);
	o = block_push (rows, FALSE, "sentinel auto-block undone", error);
	if (outcome != NULL)
		*outcome = o;
	else if (o != NULL)
		fs_apply_outcome_free (o);
	fs_policy_free (rows);
	return TRUE;
}

/* [ auto_block_expire_cb ]
 * The ten-minute time-box.  First call is one TTL after the first
 * auto-block; later calls reschedule for the earliest rule still
 * inside its window. */
static gboolean
auto_block_expire_cb (gpointer data)
{
	gint64 now = sentinel_clock->monotonic_us ();
	gboolean dropped = FALSE;
	FsPolicy *lifted;
	guint i;

	(void) data;

	if (auto_blocks == NULL) {
		auto_block_expiry_id = 0;
		return G_SOURCE_REMOVE;
	}

	lifted = fs_policy_new ();

	for (i = 0; i < auto_blocks->len; ) {
		FsSentinelBlock *ab = g_ptr_array_index (auto_blocks, i);

		if (now - ab->at_us >=
		    (gint64) FS_AUTOBLOCK_TTL_S * G_USEC_PER_SEC) {
			/* Retire, not plain drop: the cooldown is what stops the
			 * expiry -> immediate re-stage loop that ran for two days
			 * in the 2026-10-10 incident. */
			auto_block_retire (ab, "expired after 10 minutes", lifted);
			dropped = TRUE;
		} else {
			i++;
		}
	}

	if (dropped)
		auto_block_push (lifted, FALSE);
	fs_policy_free (lifted);

	if (auto_blocks->len == 0) {
		auto_block_expiry_id = 0;
		return G_SOURCE_REMOVE;
	}

	/* Some rule is still inside its window: come back for the
	 * earliest of those, not a fixed tick. */
	{
		gint64 next = -1;

		for (i = 0; i < auto_blocks->len; i++) {
			FsSentinelBlock *ab = g_ptr_array_index (auto_blocks, i);
			gint64 due = ab->at_us +
				(gint64) FS_AUTOBLOCK_TTL_S * G_USEC_PER_SEC;

			if (next < 0 || due < next)
				next = due;
		}

		auto_block_expiry_id = sentinel_clock->timeout_ms (
			(guint) (((next - now) / G_USEC_PER_SEC) * 1000 + 1000),
			auto_block_expire_cb, NULL);
	}

	return G_SOURCE_REMOVE;
}

/* [ fs_sentinel_auto_pass ] */
gboolean
fs_sentinel_auto_pass (void)
{
	GList *insights, *l;
	gboolean changed = FALSE;
	gboolean rechecked_out = FALSE;
	FsPolicy *staged;
	gint64 now;

	if (engine_copilot == NULL || engine_policy == NULL ||
	    g_strcmp0 (sentinel_mode, "auto") != 0)
		return FALSE;

	if (fs_sentinel_paused (NULL))
		return FALSE;

	if (auto_blocks == NULL)
		auto_blocks = g_ptr_array_new_with_free_func (auto_block_free);

	now = sentinel_clock->monotonic_us ();

	/* While the disk is refusing writes, do not hammer it once per
	 * event: one attempt per minute, one audit line per episode. */
	if (auto_block_failed_once &&
	    now - auto_block_last_fail < FS_SENTINEL_RETRY_US)
		return FALSE;

	/* The re-check reads the user's allow rows from the copilot's
	 * policy: it must be the one this pass writes to. */
	if (fs_copilot_get_policy (engine_copilot) != engine_policy)
		fs_copilot_set_policy (engine_copilot, engine_policy);

	insights = fs_copilot_get_insights (engine_copilot);
	staged = fs_policy_new ();

	for (l = insights; l != NULL; l = l->next) {
		FsInsight *ins = l->data;
		FsSentinelBlock *ab;
		FsRule *probe;

		if (!ins->auto_applicable)
			continue;

		/* The auto-block invariant: stage only rules that TIGHTEN the
		 * policy, whatever the insight's own flag claims -- legacy
		 * insights flag service allows TRUE for the user's confirmed
		 * Apply button, and those are never staged here. */
		if (!fs_insight_is_auto_safe (ins))
			continue;

		/* The finding's gates were judged when it was made; this pass
		 * may run much later (a pause ending, a switch from Detect
		 * only, the retry after a failed write).  Judge them again
		 * now: another program may use the host by now, or the user
		 * may have allowed it.  A gate that now withholds updates the
		 * finding's drawer text. */
		if (!fs_copilot_beacon_recheck (engine_copilot, ins)) {
			rechecked_out = TRUE;
			continue;
		}

		if (fs_sentinel_find (ins->rule_kind, ins->rule_csv) != NULL)
			continue;

		/* P6: never re-stage what this session staged and took back
		 * down (expiry, Undo, user allow, mode switch).  The incident
		 * was exactly this loop: drop after ten minutes, stage again
		 * the next second. */
		if (fs_sentinel_cooled (ins->rule_kind, ins->rule_csv))
			continue;

		/* Already in the policy but not staged by us: the user put
		 * it there, so it is not ours to manage or expire. */
		probe = fs_insight_to_rule (ins);
		if (probe == NULL)
			continue;

		if (fs_policy_contains (engine_policy, probe)) {
			fs_rule_free (probe);
			continue;
		}
		fs_rule_free (probe);

		if (!fs_insight_apply (ins, engine_policy)) {
			if (!auto_block_failed_once) {
				fs_audit_log ("sentinel auto-block failed",
				              ins->rule_csv);
				auto_block_failed_once = TRUE;
			}
			auto_block_last_fail = now;
			continue;
		}

		auto_block_failed_once = FALSE;

		ab = g_new0 (FsSentinelBlock, 1);
		ab->kind  = ins->rule_kind;
		ab->csv   = g_strdup (ins->rule_csv);
		ab->title = g_strdup (ins->title);
		ab->at_us = now;
		ab->at_epoch = sentinel_clock->real_us () / G_USEC_PER_SEC;
		g_ptr_array_add (auto_blocks, ab);
		rows_add (staged, ab->kind, ab->csv);

		fs_audit_log ("sentinel auto-block", ins->rule_csv);
		changed = TRUE;

		if (auto_block_expiry_id == 0)
			auto_block_expiry_id = sentinel_clock->timeout_s (
				FS_AUTOBLOCK_TTL_S, auto_block_expire_cb, NULL);
	}

	g_list_free (insights);

	if (changed) {
		auto_block_state_save ();
		refresh (FS_SENTINEL_POLICY_CHANGED, NULL, NULL);
		auto_block_push (staged, TRUE);
	}
	fs_policy_free (staged);

	/* A finding that a gate now withholds says so in its drawer. */
	if (rechecked_out && !changed)
		refresh (FS_SENTINEL_FINDINGS_CHANGED, NULL, NULL);

	return changed;
}

/* [ fs_sentinel_lift_all ]
 * Take every staged auto-block down at once -- the Undo button does
 * one, this does the set.  Leaving auto mode uses it, and it is what
 * a "stop blocking things NOW" would want.  Returns TRUE when
 * anything was staged. */
gboolean
fs_sentinel_lift_all (const gchar *why)
{
	gboolean lifted = FALSE;
	FsPolicy *rows = fs_policy_new ();

	while (auto_blocks != NULL && auto_blocks->len > 0) {
		FsSentinelBlock *ab = g_ptr_array_index (auto_blocks,
		                                         auto_blocks->len - 1);

		auto_block_retire (ab, why != NULL ? why : "lifted by user",
		                   rows);
		lifted = TRUE;
	}

	if (lifted) {
		refresh (FS_SENTINEL_POLICY_CHANGED, NULL, NULL);
		auto_block_push (rows, FALSE);
		refresh (FS_SENTINEL_FINDINGS_CHANGED, NULL, NULL);
	}
	fs_policy_free (rows);

	return lifted;
}

/* [ comment_is_sentinel ]
 * A policy comment belongs to Sentinel when it starts with the
 * Sentinel prefix, allowing for however many spaces the CSV split
 * left in front of it. */
static gboolean
comment_is_sentinel (const gchar *comment)
{
	if (comment == NULL)
		return FALSE;

	while (g_ascii_isspace (*comment))
		comment++;

	return g_str_has_prefix (comment, "Sentinel:");
}

/* [ fs_sentinel_lift_for_dest ]
 * The user's explicit Allow for a destination is the last word.  On
 * Windows a block rule outranks an allow rule, so an event-view Allow
 * that left the Sentinel block standing was a silent no-op -- the
 * "user's Allow lost silently" failure of the 2026-10-10 incident.
 * Staged blocks for this destination are retired (cooldown included,
 * so the next pass cannot stage them straight back) and persisted
 * rows that SENTINEL created for it are removed from the policy;
 * the user's own rules are never touched.  Returns TRUE when anything
 * changed -- the caller's own push then takes the result to the
 * firewall. */
gboolean
fs_sentinel_lift_for_dest (const gchar *dest)
{
	gboolean changed = FALSE;
	guint i;

	if (dest == NULL || *dest == '\0')
		return FALSE;

	/* 1. Blocks this session staged. */
	if (auto_blocks != NULL) {
		for (i = 0; i < auto_blocks->len; ) {
			FsSentinelBlock *ab = g_ptr_array_index (auto_blocks, i);
			FsRule *probe = fs_rule_from_csv (ab->kind, ab->csv);
			gboolean match = probe != NULL && probe->target != NULL &&
				g_ascii_strcasecmp (probe->target, dest) == 0;

			fs_rule_free (probe);

			if (match) {
				auto_block_retire (ab, "user allowed this destination",
				                   NULL);
				changed = TRUE;
			} else {
				i++;
			}
		}
	}

	/* 2. Rows Sentinel wrote to the policy in an earlier session:
	 *    outbound deny, this destination, a Sentinel comment. */
	if (engine_policy != NULL) {
		GPtrArray *rows = engine_policy->kinds[FS_RULE_OUTBOUND_DENY_TO];

		for (i = 0; i < rows->len; ) {
			FsRule *r = g_ptr_array_index (rows, i);

			if (r->target != NULL && r->comment != NULL &&
			    g_ascii_strcasecmp (r->target, dest) == 0 &&
			    comment_is_sentinel (r->comment)) {
				gchar *target = g_strdup (r->target);

				if (fs_policy_remove_persist (engine_policy, r)) {
					fs_audit_log ("sentinel rule removed "
					              "(user allow for destination)",
					              target);
					changed = TRUE;
					/* index i now points at the next row */
				} else {
					fs_audit_log ("sentinel rule removal had no effect",
					              target);
					i++;
				}

				g_free (target);
			} else {
				i++;
			}
		}
	}

	if (changed)
		refresh (FS_SENTINEL_POLICY_CHANGED, NULL, NULL);

	return changed;
}

/* [ fs_sentinel_restore ]
 * Boot restore, called once from fs-app.c after the Copilot page owns
 * the shared policy -- before any apply can push a stale block.
 * Reads the staged list the previous session persisted: rows older
 * than the ten-minute TTL come out of the policy (they expired while
 * StockFW was not running to expire them), a Sentinel mode that is
 * not "auto" takes the lot down, and fresh rows are re-staged with
 * their original wall-clock time so the REMAINING TTL is honored --
 * a restart must not grant a fresh ten minutes.  The state file is
 * rewritten to mirror what survived, and any row whose removal
 * failed stays tracked so the expiry timer retries it instead of
 * leaving a block nobody manages. */
gboolean
fs_sentinel_restore (FsPolicy *policy, FsPolicy *due)
{
	gchar *path;
	gchar *contents = NULL;
	gchar **lines;
	guint i;
	gint64 now_epoch;
	guint stale = 0, lifted = 0, armed = 0, gone = 0, retried = 0;

	if (policy == NULL)
		return FALSE;

	/* The shared policy, even if the Copilot page is not built yet:
	 * the drop helper works through this pointer. */
	engine_policy = policy;

	path = fs_autoblock_state_path ();

	if (!g_file_get_contents (path, &contents, NULL, NULL)) {
		g_free (path);
		return FALSE;              /* nothing was staged last session */
	}

	now_epoch = sentinel_clock->real_us () / G_USEC_PER_SEC;
	lines = g_strsplit (contents, "\n", -1);

	if (auto_blocks == NULL)
		auto_blocks = g_ptr_array_new_with_free_func (auto_block_free);

	for (i = 0; lines[i] != NULL; i++) {
		const gchar *line = lines[i];
		gchar **parts;
		FsSentinelBlock *ab;
		gint64 epoch;
		gint kind;

		if (*line == '\0' || *line == '#')
			continue;

		parts = g_strsplit (line, ",", 4);

		if (g_strv_length (parts) != 4 || g_strcmp0 (parts[0], "S") != 0 ||
		    *parts[3] == '\0') {
			g_strfreev (parts);
			continue;
		}

		epoch = g_ascii_strtoll (parts[1], NULL, 10);
		kind  = (gint) g_ascii_strtoll (parts[2], NULL, 10);

		if (epoch <= 0 || epoch > now_epoch ||
		    kind < 0 || kind >= FS_RULE_N_KINDS) {
			g_strfreev (parts);
			continue;
		}

		ab = g_new0 (FsSentinelBlock, 1);
		ab->kind     = (FsRuleKind) kind;
		ab->csv      = g_strdup (parts[3]);
		ab->at_epoch = epoch;
		/* Backdate the monotonic clock from the wall clock: the TTL
		 * counts from staging, not from boot. */
		ab->at_us    = sentinel_clock->monotonic_us () -
		               (now_epoch - epoch) * G_USEC_PER_SEC;
		g_strfreev (parts);

		if (now_epoch - epoch >= FS_AUTOBLOCK_TTL_S ||
		    g_strcmp0 (sentinel_mode, "auto") != 0) {
			const gchar *why =
				now_epoch - epoch >= FS_AUTOBLOCK_TTL_S
				? "expired while StockFW was not running"
				: "Sentinel is not in auto mode";

			/* Due, whether or not the policy still holds it: the
			 * firewall may (the journal says), and the caller takes
			 * it off there. */
			if (due != NULL)
				rows_add (due, ab->kind, ab->csv);

			if (auto_block_rule_in_policy (ab))
				auto_block_drop (ab, why);

			if (auto_block_rule_in_policy (ab)) {
				/* The removal failed (disk or ACL): keep the row
				 * tracked, the expiry timer retries the drop. */
				g_ptr_array_add (auto_blocks, ab);
				retried++;
			} else {
				auto_block_cooldown_add (ab->kind, ab->csv);
				auto_block_free (ab);

				if (g_strcmp0 (why, "Sentinel is not in auto mode") == 0)
					lifted++;
				else
					stale++;
			}
		} else if (!auto_block_rule_in_policy (ab)) {
			/* The user already deleted the rule themselves: forget
			 * the row, remember the cooldown. */
			auto_block_cooldown_add (ab->kind, ab->csv);
			auto_block_free (ab);
			gone++;
		} else {
			g_ptr_array_add (auto_blocks, ab);
			armed++;
		}
	}

	g_strfreev (lines);

	/* The file now mirrors what survived. */
	auto_block_state_save ();

	/* Re-arm the expiry timer for the earliest survivor: restored
	 * rows may have under a minute of TTL left. */
	if (auto_blocks->len > 0 && auto_block_expiry_id == 0) {
		gint64 next = -1;
		gint64 remain_s;

		for (i = 0; i < auto_blocks->len; i++) {
			FsSentinelBlock *ab = g_ptr_array_index (auto_blocks, i);
			gint64 at = ab->at_us +
				(gint64) FS_AUTOBLOCK_TTL_S * G_USEC_PER_SEC;

			if (next < 0 || at < next)
				next = at;
		}

		remain_s = (next - sentinel_clock->monotonic_us ()) /
		           G_USEC_PER_SEC;
		if (remain_s < 1)
			remain_s = 1;

		auto_block_expiry_id = sentinel_clock->timeout_s (
			(guint) remain_s, auto_block_expire_cb, NULL);
	}

	if (stale > 0 || lifted > 0 || armed > 0 || gone > 0 || retried > 0) {
		gchar *detail = g_strdup_printf (
			"%u expired while StockFW was not running, %u lifted "
			"(Sentinel not in auto mode), %u re-armed, %u already "
			"gone from the policy, %u kept for a removal retry",
			stale, lifted, armed, gone, retried);

		fs_audit_log ("sentinel auto-blocks restored", detail);
		g_free (detail);
	}

	g_free (contents);
	g_free (path);

	/* Rows are due: the firewall may still hold them until a start or
	 * a lift.  The caller decides which (fs-app.c), from `due'. */
	return stale > 0 || lifted > 0 || retried > 0;
}

/* ===== Sentinel pause (tray menu) ================================ */

/* [ fs_sentinel_can_pause ] */
gboolean
fs_sentinel_can_pause (void)
{
	return engine_copilot != NULL && engine_policy != NULL &&
	       g_strcmp0 (sentinel_mode, "auto") == 0;
}

/* [ fs_sentinel_paused ] */
gboolean
fs_sentinel_paused (gint64 *seconds_left)
{
	gint64 now = sentinel_clock->monotonic_us ();

	if (sentinel_paused_until <= now) {
		if (seconds_left != NULL)
			*seconds_left = 0;
		return FALSE;
	}
	if (seconds_left != NULL)
		*seconds_left = (sentinel_paused_until - now + G_USEC_PER_SEC - 1) /
		                G_USEC_PER_SEC;
	return TRUE;
}

static gboolean
sentinel_resume_cb (gpointer data)
{
	(void) data;

	sentinel_resume_id = 0;
	fs_sentinel_pause (0);
	return G_SOURCE_REMOVE;
}

/* [ fs_sentinel_pause ] */
void
fs_sentinel_pause (guint seconds)
{
	gboolean was_paused = fs_sentinel_paused (NULL);

	if (sentinel_resume_id != 0) {
		sentinel_clock->source_remove (sentinel_resume_id);
		sentinel_resume_id = 0;
	}

	if (seconds == 0) {
		sentinel_paused_until = 0;
		if (!was_paused)
			return;
		fs_audit_log ("sentinel auto-block resumed",
		              "tray | auto-block stages critical insights again");
		refresh (FS_SENTINEL_RESUMED, NULL, NULL);
		/* Catch up on what arrived while paused. */
		if (fs_sentinel_auto_pass ())
			refresh (FS_SENTINEL_FINDINGS_CHANGED, NULL, NULL);
		return;
	}

	sentinel_paused_until = sentinel_clock->monotonic_us () +
	                        (gint64) seconds * G_USEC_PER_SEC;
	sentinel_resume_id = sentinel_clock->timeout_s (seconds,
	                                                sentinel_resume_cb, NULL);
	{
		gchar *detail = g_strdup_printf (
			"tray | nothing new is staged for %u minutes; blocks already "
			"staged keep their own ten minutes", seconds / 60);

		fs_audit_log ("sentinel auto-block paused", detail);
		g_free (detail);
	}
	refresh (FS_SENTINEL_PAUSED, NULL, NULL);
}
