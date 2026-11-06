/*---[ fs-autoblock.c ]--------------------------------------------------
 * Sentinel's persisted auto-block list without the UI: see the header.
 *--------------------------------------------------------------------*/

#include "core/fs-autoblock.h"
#include "core/fs-audit.h"
#include "core/fs-util.h"

#include <string.h>

/* [ fs_autoblock_state_path ] */
gchar *
fs_autoblock_state_path (void)
{
	const gchar *env = g_getenv ("STOCKFW_AUTOBLOCK_FILE");

	if (env != NULL && *env != '\0')
		return g_strdup (env);

#ifdef G_OS_WIN32
	{
		const gchar *appdata = g_getenv ("APPDATA");

		if (appdata != NULL && *appdata != '\0')
			return g_build_filename (appdata, "stockfw",
			                         "autoblocks", NULL);

		return g_build_filename (g_get_home_dir (), "AppData",
		                         "Roaming", "stockfw", "autoblocks",
		                         NULL);
	}
#else
	return g_build_filename (g_get_user_config_dir (), "stockfw",
	                         "autoblocks", NULL);
#endif
}

/* ------------------------------------------------- one pass over rows */

/* Which rows a pass takes: the epoch and the rule as read (the rule is
 * NULL when its CSV did not parse). */
typedef gboolean (*RowChosen) (gint64 epoch, const FsRule *rule,
                               gpointer data);

typedef struct
{
	GString  *keep;      /* the file's next text, "\n"-ended rows     */
	FsPolicy *retry;     /* chosen rows kept: their removal failed    */
	gboolean  read;      /* the state file was there                  */
	gboolean  changed;   /* the file must be written                  */
	guint     rows;      /* rows chosen                               */
	guint     removed;   /* rules taken out of the policy file        */
	guint     gone;      /* chosen, already gone from the policy      */
	guint     kept;      /* chosen and kept: the removal failed       */
	guint     left;      /* not chosen, kept as they were             */
} Pass;

/* [ state_pass ]
 * Read the state file.  For each row `chosen' takes, its rule goes
 * into `lifted' (wherever it still is: the journal may hold it) and out
 * of `policy' and its files.  A row whose rule could not be removed
 * (disk error) is kept, so a later pass retries it; a row whose rule
 * the user already deleted simply goes.  Rows not chosen are kept as
 * they are; rows this format does not write are dropped, as the app's
 * own restore drops them.  Nothing is written here: pass->keep is the
 * file's next text. */
static void
state_pass (FsPolicy *policy, RowChosen chosen, gpointer data,
            const gchar *why, FsPolicy *lifted, Pass *pass)
{
	gchar *path, *contents = NULL;
	gchar **lines;

	memset (pass, 0, sizeof *pass);
	pass->keep = g_string_new (NULL);
	pass->retry = fs_policy_new ();

	path = fs_autoblock_state_path ();
	pass->read = g_file_get_contents (path, &contents, NULL, NULL);
	g_free (path);
	if (!pass->read)
		return;

	lines = g_strsplit (contents, "\n", -1);

	for (guint i = 0; lines[i] != NULL; i++) {
		gchar **parts;
		gint64 epoch;
		gint kind;
		FsRule *rule;

		if (*lines[i] == '\0' || *lines[i] == '#')
			continue;

		parts = g_strsplit (lines[i], ",", 4);
		if (g_strv_length (parts) != 4 ||
		    g_strcmp0 (parts[0], "S") != 0 || *parts[3] == '\0') {
			/* Not a row this format writes: drop it, as the app's
			 * own restore does. */
			g_strfreev (parts);
			pass->changed = TRUE;
			continue;
		}

		epoch = g_ascii_strtoll (parts[1], NULL, 10);
		kind = (gint) g_ascii_strtoll (parts[2], NULL, 10);

		if (epoch <= 0 || kind < 0 || kind >= FS_RULE_N_KINDS) {
			g_strfreev (parts);
			pass->changed = TRUE;
			continue;
		}

		rule = fs_rule_from_csv ((FsRuleKind) kind, parts[3]);

		if (!chosen (epoch, rule, data)) {
			g_string_append_printf (pass->keep, "%s\n", lines[i]);
			pass->left++;
			fs_rule_free (rule);
			g_strfreev (parts);
			continue;
		}

		pass->changed = TRUE;
		pass->rows++;

		/* Chosen, wherever it still is: the journal may hold it. */
		if (rule != NULL && lifted != NULL &&
		    !fs_policy_contains (lifted, rule))
			fs_policy_add (lifted, rule);     /* stores a copy */

		if (rule == NULL || !fs_policy_contains (policy, rule)) {
			/* The user already took it out: forget the row. */
			pass->gone++;
		} else if (fs_policy_remove_persist (policy, rule)) {
			gchar *detail = g_strdup_printf ("%s (%s)", parts[3],
			                                 why);

			fs_audit_log ("sentinel auto-block removed", detail);
			g_free (detail);
			pass->removed++;
		} else {
			/* Could not write the policy: keep the row so the
			 * next pass retries, never a block nobody manages. */
			fs_audit_log ("sentinel auto-block removal had no effect",
			              parts[3]);
			g_string_append_printf (pass->keep, "%s\n", lines[i]);
			fs_policy_add (pass->retry, rule);
			pass->kept++;
		}

		fs_rule_free (rule);
		g_strfreev (parts);
	}

	g_strfreev (lines);
	g_free (contents);
}

static void
pass_clear (Pass *pass)
{
	if (pass->keep != NULL)
		g_string_free (pass->keep, TRUE);
	fs_policy_free (pass->retry);
	pass->keep = NULL;
	pass->retry = NULL;
}

/* [ pass_save ] -- write the state file; TRUE when it was written. */
static gboolean
pass_save (const Pass *pass)
{
	GError *error = NULL;
	gchar *path = fs_autoblock_state_path ();
	gboolean ok;

	ok = fs_util_ensure_parent_dir (path) &&
	     g_file_set_contents (path, pass->keep->str, -1, &error);
	if (!ok)
		fs_audit_log ("sentinel auto-block state save failed",
		              error != NULL ? error->message : path);
	g_clear_error (&error);
	g_free (path);
	return ok;
}

/* ------------------------------------------------------- at the start */

typedef struct
{
	gint64   now;
	gboolean all;
} ExpireData;

static gboolean
chosen_expired (gint64 epoch, const FsRule *rule, gpointer data)
{
	const ExpireData *d = data;

	(void) rule;
	/* Still inside its ten minutes: the app's restore re-arms it.  A
	 * stamp from the future (the clock moved back) is kept too, for
	 * that same restore to judge. */
	return d->all || (epoch <= d->now &&
	                  d->now - epoch >= FS_AUTOBLOCK_TTL_S);
}

/* [ fs_autoblock_expire ] */
guint
fs_autoblock_expire (FsPolicy *policy, gint64 now_epoch, gboolean lift_all,
                     FsPolicy *lifted)
{
	ExpireData d = { now_epoch, lift_all };
	Pass pass;
	guint dropped;

	if (policy == NULL)
		return 0;

	state_pass (policy, chosen_expired, &d,
	            lift_all ? "Sentinel is not in auto mode"
	                     : "expired while StockFW was not running",
	            lifted, &pass);

	if (pass.changed)
		pass_save (&pass);

	if (pass.removed > 0 || pass.gone > 0) {
		gchar *detail = g_strdup_printf (
			"%u removed from the policy, %u already gone, %u kept",
			pass.removed, pass.gone, pass.kept + pass.left);

		fs_audit_log ("sentinel auto-blocks expired before start",
		              detail);
		g_free (detail);
	}

	dropped = pass.removed;
	pass_clear (&pass);
	return dropped;
}

/* =====================================================================
 * PR 4 (4A): lifting from a firewall that runs
 * ===================================================================== */

/* [ fs_autoblock_lift_free ] */
void
fs_autoblock_lift_free (FsAutoblockLift *lift)
{
	if (lift == NULL)
		return;
	fs_policy_free (lift->lifted);
	fs_apply_outcome_free (lift->outcome);
	g_free (lift);
}

/* [ comment_is_sentinel ]
 * A policy comment belongs to Sentinel when it starts with the
 * Sentinel prefix, allowing for the spaces the CSV split left in front
 * of it (as ui/fs-copilot.c reads it). */
static gboolean
comment_is_sentinel (const gchar *comment)
{
	if (comment == NULL)
		return FALSE;
	while (g_ascii_isspace (*comment))
		comment++;
	return g_str_has_prefix (comment, "Sentinel:");
}

/* [ policy_rows_for_dest ]
 * The outbound-deny-to rows Sentinel wrote for `dest' in an earlier
 * session that no state row names any more: out of the policy, into
 * `lifted'.  A row that could not be removed stays (and is not lifted:
 * the next apply would put it back), and the audit says so. */
static void
policy_rows_for_dest (FsPolicy *policy, const gchar *dest,
                      const gchar *why, FsPolicy *lifted,
                      FsAutoblockLift *res)
{
	GPtrArray *rows = policy->kinds[FS_RULE_OUTBOUND_DENY_TO];

	for (guint i = 0; i < rows->len; ) {
		FsRule *r = g_ptr_array_index (rows, i);
		FsRule *copy;

		if (r->target == NULL ||
		    g_ascii_strcasecmp (r->target, dest) != 0 ||
		    !comment_is_sentinel (r->comment)) {
			i++;
			continue;
		}

		copy = fs_rule_copy (r);
		if (fs_policy_remove_persist (policy, copy)) {
			gchar *detail = g_strdup_printf ("%s (%s)",
			                                 copy->target, why);

			fs_audit_log ("sentinel rule removed", detail);
			g_free (detail);
			if (!fs_policy_contains (lifted, copy))
				fs_policy_add (lifted, copy);
			res->removed++;
			/* i now points at the next row */
		} else {
			fs_audit_log ("sentinel rule removal had no effect",
			              copy->target);
			i++;
		}
		fs_rule_free (copy);
	}
}

static guint
policy_total (const FsPolicy *policy)
{
	guint n = 0;

	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		n += policy->kinds[k]->len;
	return n;
}

/* [ lift_run ]
 * The three steps of the header, under the policy lock. */
static FsAutoblockLift *
lift_run (const FsBackend *backend, FsPolicy *policy, RowChosen chosen,
          gpointer data, const gchar *dest, const gchar *why,
          gint64 now_epoch, const gchar *source, const gchar *hold,
          GError **error)
{
	FsAutoblockLift *res;
	FsPolicyLock *lock;
	FsPolicy *live;
	GError *journal_error = NULL;
	gboolean have_live, live_unknown;
	Pass pass;

	g_return_val_if_fail (policy != NULL, NULL);

	lock = fs_policy_lock (error);
	if (lock == NULL)
		return NULL;

	res = g_new0 (FsAutoblockLift, 1);
	res->lifted = fs_policy_new ();

	/* 1. The state file and the policy file. */
	state_pass (policy, chosen, data, why, res->lifted, &pass);
	if (dest != NULL)
		policy_rows_for_dest (policy, dest, why, res->lifted, res);
	res->rows = pass.rows;
	res->removed += pass.removed;
	res->gone = pass.gone;
	res->kept = pass.kept;

	/* 2. Off the firewall: the journal less these rules. */
	if (policy_total (res->lifted) > 0)
		res->outcome = fs_firewall_lift_live (backend, res->lifted,
		                                      source, hold, error);

	/* 3. A rule still live keeps a row that is already due, so the
	 * next start leaves it out and the next lift takes it off.  A
	 * journal that cannot be read: every lifted rule may be live. */
	live = fs_policy_new ();
	have_live = fs_apply_journal_load (live, &journal_error);
	live_unknown = !have_live &&
	               !g_error_matches (journal_error, FS_APPLY_ERROR,
	                                 FS_APPLY_ERR_NO_JOURNAL);
	g_clear_error (&journal_error);
	for (gint k = 0; k < FS_RULE_N_KINDS; k++) {
		GPtrArray *rules = res->lifted->kinds[k];

		for (guint i = 0; i < rules->len; i++) {
			FsRule *rule = g_ptr_array_index (rules, i);
			gchar *csv;

			if (fs_policy_contains (pass.retry, rule))
				continue;          /* its row is kept already */
			if (!live_unknown &&
			    !(have_live && fs_policy_contains (live, rule)))
				continue;
			csv = fs_rule_to_csv (rule);
			g_string_append_printf (pass.keep,
			                        "S,%" G_GINT64_FORMAT ",%d,%s\n",
			                        MAX (now_epoch -
			                             FS_AUTOBLOCK_TTL_S, 1),
			                        (gint) k, csv);
			g_free (csv);
			pass.changed = TRUE;
			res->kept++;
		}
	}
	fs_policy_free (live);

	res->state_saved = !pass.changed || pass_save (&pass);

	if (res->rows > 0 || res->removed > 0) {
		gchar *detail = g_strdup_printf (
			"%s | %s | %u removed from the policy, %u already gone, "
			"%u kept, %s",
			source != NULL ? source : "-", why, res->removed,
			res->gone, res->kept,
			res->outcome == NULL ? "none was live"
			: res->outcome->applied ? "taken off the firewall"
			: res->outcome->held ? "held: still live"
			: res->outcome->firewall_was == FS_FW_STOPPED &&
			  res->outcome->result == FS_APPLY_DRY_RUN
			  ? "firewall stopped: left out of the next start"
			: "the firewall was NOT changed");

		fs_audit_log ("sentinel auto-blocks lifted", detail);
		g_free (detail);
	}

	pass_clear (&pass);
	fs_policy_unlock (lock);
	return res;
}

static gboolean
chosen_all (gint64 epoch, const FsRule *rule, gpointer data)
{
	(void) epoch;
	(void) rule;
	(void) data;
	return TRUE;
}

static gboolean
chosen_dest (gint64 epoch, const FsRule *rule, gpointer data)
{
	(void) epoch;
	return rule != NULL && rule->target != NULL &&
	       g_ascii_strcasecmp (rule->target, data) == 0;
}

/* [ fs_autoblock_lift_all ] */
FsAutoblockLift *
fs_autoblock_lift_all (const FsBackend *backend, FsPolicy *policy,
                       const gchar *why, const gchar *source,
                       const gchar *hold, GError **error)
{
	return lift_run (backend, policy, chosen_all, NULL, NULL,
	                 why != NULL ? why : "lifted by user",
	                 g_get_real_time () / G_USEC_PER_SEC, source, hold,
	                 error);
}

/* [ fs_autoblock_lift_for_dest ] */
FsAutoblockLift *
fs_autoblock_lift_for_dest (const FsBackend *backend, FsPolicy *policy,
                            const gchar *dest, const gchar *why,
                            const gchar *source, const gchar *hold,
                            GError **error)
{
	if (dest == NULL || *dest == '\0') {
		FsAutoblockLift *res = g_new0 (FsAutoblockLift, 1);

		res->lifted = fs_policy_new ();
		res->state_saved = TRUE;
		return res;
	}
	return lift_run (backend, policy, chosen_dest, (gpointer) dest, dest,
	                 why != NULL ? why : "user allowed this destination",
	                 g_get_real_time () / G_USEC_PER_SEC, source, hold,
	                 error);
}

/* [ fs_autoblock_lift_expired ] */
FsAutoblockLift *
fs_autoblock_lift_expired (const FsBackend *backend, FsPolicy *policy,
                           gint64 now_epoch, const gchar *source,
                           const gchar *hold, GError **error)
{
	ExpireData d = { now_epoch, FALSE };

	return lift_run (backend, policy, chosen_expired, &d, NULL,
	                 "expired", now_epoch, source, hold, error);
}
