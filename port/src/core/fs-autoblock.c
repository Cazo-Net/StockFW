/*---[ fs-autoblock.c ]--------------------------------------------------
 * Sentinel's persisted auto-block list without the UI: see the header.
 *--------------------------------------------------------------------*/

#include "core/fs-autoblock.h"
#include "core/fs-audit.h"

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

/* [ fs_autoblock_expire ] */
guint
fs_autoblock_expire (FsPolicy *policy, gint64 now_epoch, gboolean lift_all,
                     FsPolicy *lifted)
{
	gchar *path, *contents = NULL;
	gchar **lines;
	GString *keep;
	guint dropped = 0, kept = 0, gone = 0;
	gboolean changed = FALSE;

	if (policy == NULL)
		return 0;

	path = fs_autoblock_state_path ();
	if (!g_file_get_contents (path, &contents, NULL, NULL)) {
		g_free (path);
		return 0;
	}

	keep = g_string_new (NULL);
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
			changed = TRUE;
			continue;
		}

		epoch = g_ascii_strtoll (parts[1], NULL, 10);
		kind = (gint) g_ascii_strtoll (parts[2], NULL, 10);

		if (epoch <= 0 || kind < 0 || kind >= FS_RULE_N_KINDS) {
			g_strfreev (parts);
			changed = TRUE;
			continue;
		}

		/* Still inside its ten minutes: the app's restore re-arms
		 * it.  A stamp from the future (the clock moved back) is
		 * kept too, for that same restore to judge. */
		if (!lift_all && (epoch > now_epoch ||
		                  now_epoch - epoch < FS_AUTOBLOCK_TTL_S)) {
			g_string_append_printf (keep, "%s\n", lines[i]);
			kept++;
			g_strfreev (parts);
			continue;
		}

		changed = TRUE;
		rule = fs_rule_from_csv ((FsRuleKind) kind, parts[3]);

		/* Due, wherever it still is: the start leaves it out of
		 * the journal too. */
		if (rule != NULL && lifted != NULL &&
		    !fs_policy_contains (lifted, rule))
			fs_policy_add (lifted, rule);     /* stores a copy */

		if (rule == NULL || !fs_policy_contains (policy, rule)) {
			/* The user already took it out: forget the row. */
			gone++;
		} else if (fs_policy_remove_persist (policy, rule)) {
			gchar *detail = g_strdup_printf (
				"%s (%s)", parts[3],
				lift_all ? "Sentinel is not in auto mode"
				         : "expired while StockFW was not running");

			fs_audit_log ("sentinel auto-block removed", detail);
			g_free (detail);
			dropped++;
		} else {
			/* Could not write the policy: keep the row so the
			 * next pass retries, never a block nobody manages. */
			fs_audit_log ("sentinel auto-block removal had no effect",
			              parts[3]);
			g_string_append_printf (keep, "%s\n", lines[i]);
			kept++;
		}

		fs_rule_free (rule);
		g_strfreev (parts);
	}

	if (changed) {
		GError *error = NULL;

		if (!g_file_set_contents (path, keep->str, -1, &error)) {
			fs_audit_log ("sentinel auto-block state save failed",
			              error != NULL ? error->message : path);
			g_clear_error (&error);
		}
	}

	if (dropped > 0 || gone > 0) {
		gchar *detail = g_strdup_printf (
			"%u removed from the policy, %u already gone, %u kept",
			dropped, gone, kept);

		fs_audit_log ("sentinel auto-blocks expired before start",
		              detail);
		g_free (detail);
	}

	g_strfreev (lines);
	g_string_free (keep, TRUE);
	g_free (contents);
	g_free (path);

	return dropped;
}
