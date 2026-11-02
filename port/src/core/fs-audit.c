/*---[ fs-audit.c ]------------------------------------------------------*/
#include "core/fs-audit.h"
#include "core/fs-prefs.h"

#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

/* [ fs_audit_path ] */
gchar *
fs_audit_path (void)
{
	const gchar *override = g_getenv ("STOCKFW_AUDIT_FILE");

	if (override != NULL && *override != '\0')
		return g_strdup (override);

	/* Next to the preferences file, so the record lives with the
	 * rest of the application's state. */
	{
		const gchar *prefs = fs_prefs_path ();
		gchar *dir;
		gchar *result;

		if (prefs == NULL)
			return g_build_filename (g_get_user_config_dir (),
			                        "stockfw", "audit.log", NULL);

		dir = g_path_get_dirname (prefs);
		result = g_build_filename (dir, "audit.log", NULL);
		g_free (dir);
		return result;
	}
}

/* [ fs_audit_log ] */
gboolean
fs_audit_log (const gchar *action, const gchar *detail)
{
	gchar *path;
	gchar *dir;
	GDateTime *now;
	gchar *stamp;
	FILE *file;
	gint written;

	if (action == NULL || *action == '\0')
		return FALSE;

	path = fs_audit_path ();
	dir  = g_path_get_dirname (path);

	/* The file only ever grows: fopen in append mode never rewrites
	 * existing bytes, so nothing downstream can truncate history. */
	g_mkdir_with_parents (dir, 0700);
	g_free (dir);

	file = g_fopen (path, "a");
	if (file == NULL) {
		g_free (path);
		return FALSE;
	}

	now   = g_date_time_new_now_utc ();
	stamp = g_date_time_format (now, "%Y-%m-%dT%H:%M:%SZ");
	g_date_time_unref (now);

	/* One entry is one line: a line break inside an action or a
	 * detail (a multi-line backend message, a note list) would
	 * otherwise read as a second, forged entry. */
	{
		gchar *one_action = g_strdelimit (g_strdup (action), "\r\n", ' ');
		gchar *one_detail = g_strdelimit (
			g_strdup ((detail != NULL && *detail != '\0') ? detail : "-"),
			"\r\n", ' ');

		written = fprintf (file, "%s | %s | %s\n", stamp, one_action,
		                   one_detail);
		g_free (one_action);
		g_free (one_detail);
	}

	g_free (stamp);
	g_free (path);

	return fclose (file) == 0 && written > 0;
}
