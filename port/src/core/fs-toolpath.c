/*---[ fs-toolpath.c ]---------------------------------------------------
 * Where the system tools StockFW runs come from.  See fs-toolpath.h.
 *--------------------------------------------------------------------*/

#include "core/fs-toolpath.h"

#include <string.h>

#ifndef G_OS_WIN32
#include <unistd.h>
#endif

static gboolean
is_bare_name (const gchar *name)
{
	return name != NULL && *name != '\0' &&
	       strcmp (name, ".") != 0 && strcmp (name, "..") != 0 &&
	       strchr (name, '/') == NULL && strchr (name, '\\') == NULL &&
	       strchr (name, ':') == NULL;
}

gchar *
fs_toolpath_search (const gchar *name, const gchar *dirs)
{
	gchar **list;
	gchar *found = NULL;

	if (!is_bare_name (name) || dirs == NULL)
		return NULL;

	list = g_strsplit (dirs, ":", -1);
	for (guint i = 0; list[i] != NULL && found == NULL; i++) {
		gchar *path;

		/* Only absolute entries: "" or "." would be the current
		 * directory, which is as untrusted as any PATH. */
		if (list[i][0] != '/')
			continue;
		path = g_build_filename (list[i], name, NULL);
		if (g_file_test (path, G_FILE_TEST_IS_REGULAR) &&
		    g_file_test (path, G_FILE_TEST_IS_EXECUTABLE))
			found = path;
		else
			g_free (path);
	}
	g_strfreev (list);
	return found;
}

/* Whether this process must not trust the PATH it was given: root, or
 * set-user-ID.  Test builds trust it always (see the header). */
static gboolean
fixed_dirs_only (void)
{
#if defined(FS_TOOLPATH_TESTING) || defined(G_OS_WIN32)
	return FALSE;
#else
	return geteuid () == 0 || geteuid () != getuid ();
#endif
}

gchar *
fs_toolpath_find (const gchar *name)
{
	if (!is_bare_name (name))
		return NULL;
	if (fixed_dirs_only ())
		return fs_toolpath_search (name, FS_TOOLPATH_SYSTEM_DIRS);
	return g_find_program_in_path (name);
}

const gchar *
fs_toolpath_where (void)
{
	return fixed_dirs_only () ? "in /usr/sbin, /usr/bin, /sbin or /bin"
	                          : "on PATH";
}

const gchar *
fs_toolpath_test_dir (void)
{
#ifdef FS_TOOLPATH_TESTING
	return g_getenv ("STOCKFW_TEST_TOOL_DIR");
#else
	return NULL;
#endif
}

gchar *
fs_toolpath_windows (const gchar *system_dir, const gchar *argv0)
{
	gsize n;

	if (argv0 == NULL || *argv0 == '\0')
		return NULL;

	/* Already a full path: "X:\..." or a "\\server\share\..." name. */
	if ((g_ascii_isalpha (argv0[0]) && argv0[1] == ':' &&
	     argv0[2] == '\\') ||
	    (argv0[0] == '\\' && argv0[1] == '\\'))
		return g_strdup (argv0);

	if (!is_bare_name (argv0) || system_dir == NULL ||
	    system_dir[0] == '\0')
		return NULL;

	n = strlen (system_dir);
	if (system_dir[n - 1] == '\\')
		return g_strconcat (system_dir, argv0, NULL);
	return g_strconcat (system_dir, "\\", argv0, NULL);
}
