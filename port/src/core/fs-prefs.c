/*---[ fs-prefs.c ]------------------------------------------------------
 * GKeyFile-backed settings store.
 *--------------------------------------------------------------------*/

#include "core/fs-prefs.h"
#include "core/fs-util.h"

#include <stdio.h>
#include <string.h>

#define FS_PREFS_GROUP_PREFIX "/apps/firestarter/"
#define FS_PREFS_GROUP_CLIENT  "client"
#define FS_PREFS_GROUP_FW      "firewall"
#define FS_PREFS_GROUP_UI      "client"

static GKeyFile *prefs_file = NULL;
static gchar    *prefs_path = NULL;
static gboolean  prefs_dirty = FALSE;

/* [ prefs_default_path ]
 * $XDG_CONFIG_HOME/firestarter/firestarter.conf on Linux (what
 * g_get_user_config_dir() gives us), and %APPDATA%\firestarter on
 * Windows.  g_get_user_config_dir() returns the *local* AppData folder
 * on Windows, which is the wrong place for user settings. */
static gchar *
prefs_default_path (void)
{
#ifdef G_OS_WIN32
	const gchar *appdata = g_getenv ("APPDATA");

	if (appdata != NULL && *appdata != '\0')
		return g_build_filename (appdata, "firestarter",
		                         "firestarter.conf", NULL);

	return g_build_filename (g_get_home_dir (), "AppData", "Roaming",
	                         "firestarter", "firestarter.conf", NULL);
#else
	return g_build_filename (g_get_user_config_dir (),
	                         "firestarter",
	                         "firestarter.conf",
	                         NULL);
#endif
}

/* [ prefs_split_key ]
 * "/apps/firestarter/firewall/icmp/enable"
 *   -> group "firewall", key "icmp/enable"
 * The sub-path may contain slashes, which ini keys allow. */
static void
prefs_split_key (const gchar *key, gchar **group, gchar **leaf)
{
	if (group != NULL)
		*group = g_strdup (FS_PREFS_GROUP_CLIENT);

	if (leaf == NULL)
		return;

	if (key == NULL) {
		*leaf = g_strdup ("");
		return;
	}

	if (g_str_has_prefix (key, FS_PREFS_GROUP_PREFIX)) {
		const gchar *rest = key + strlen (FS_PREFS_GROUP_PREFIX);
		const gchar *slash = strchr (rest, '/');

		if (slash != NULL) {
			gchar *g = g_strndup (rest, (gsize) (slash - rest));

			if (group != NULL) {
				g_free (*group);
				*group = g_ascii_strdown (g, -1);
			}
			g_free (g);
			*leaf = g_strdup (slash + 1);
		} else {
			if (group != NULL) {
				g_free (*group);
				*group = g_strdup (FS_PREFS_GROUP_CLIENT);
			}
			*leaf = g_strdup (rest);
		}
	} else {
		*leaf = g_strdup (key);
	}
}

void
fs_prefs_init (void)
{
	if (prefs_file == NULL)
		prefs_file = g_key_file_new ();
}

gboolean
fs_prefs_load (void)
{
	GError *error = NULL;

	fs_prefs_init ();

	if (prefs_path == NULL)
		prefs_path = prefs_default_path ();

	if (!g_file_test (prefs_path, G_FILE_TEST_EXISTS))
		return FALSE;

	if (!g_key_file_load_from_file (prefs_file, prefs_path,
	                                G_KEY_FILE_KEEP_COMMENTS, &error)) {
		g_warning ("Could not read settings from %s: %s",
		           prefs_path, error->message);
		g_error_free (error);
		return FALSE;
	}

	prefs_dirty = FALSE;
	return TRUE;
}

gboolean
fs_prefs_save (void)
{
	GError *error = NULL;

	fs_prefs_init ();

	if (prefs_path == NULL)
		prefs_path = prefs_default_path ();

	/* g_key_file_save_to_file() writes via a temp file in the target
	 * directory, so that directory has to exist first. */
	if (!fs_util_ensure_parent_dir (prefs_path)) {
		g_warning ("Could not create the settings directory for %s",
		           prefs_path);
		return FALSE;
	}

	if (!g_key_file_save_to_file (prefs_file, prefs_path, &error)) {
		g_warning ("Could not write settings to %s: %s",
		           prefs_path, error->message);
		g_error_free (error);
		return FALSE;
	}

	prefs_dirty = FALSE;
	return TRUE;
}

const gchar *
fs_prefs_path (void)
{
	if (prefs_path == NULL)
		prefs_path = prefs_default_path ();

	return prefs_path;
}

gboolean
fs_prefs_get_bool (const gchar *key, gboolean fallback)
{
	gchar *group = NULL;
	gchar *leaf = NULL;
	GError *error = NULL;
	gboolean value;

	fs_prefs_init ();
	prefs_split_key (key, &group, &leaf);

	/* The error must be collected, not passed as NULL: g_key_file
	 * returns FALSE for a missing key as well as for a real FALSE, so
	 * without it the fallback argument was dead code and every
	 * default in the application was silently ignored. */
	value = g_key_file_get_boolean (prefs_file, group, leaf, &error);

	if (error != NULL) {
		g_clear_error (&error);
		value = fallback;
	}

	g_free (group);
	g_free (leaf);

	return value;
}

void
fs_prefs_set_bool (const gchar *key, gboolean value)
{
	gchar *group = NULL;
	gchar *leaf = NULL;

	fs_prefs_init ();
	prefs_split_key (key, &group, &leaf);

	g_key_file_set_boolean (prefs_file, group, leaf, value);
	prefs_dirty = TRUE;

	g_free (group);
	g_free (leaf);
}

gchar *
fs_prefs_get_string (const gchar *key, const gchar *fallback)
{
	gchar *group = NULL;
	gchar *leaf = NULL;
	gchar *value;

	fs_prefs_init ();
	prefs_split_key (key, &group, &leaf);

	value = g_key_file_get_string (prefs_file, group, leaf, NULL);

	g_free (group);
	g_free (leaf);

	if (value == NULL && fallback != NULL)
		return g_strdup (fallback);

	return value;
}

void
fs_prefs_set_string (const gchar *key, const gchar *value)
{
	gchar *group = NULL;
	gchar *leaf = NULL;

	fs_prefs_init ();
	prefs_split_key (key, &group, &leaf);

	if (value == NULL)
		g_key_file_remove_key (prefs_file, group, leaf, NULL);
	else
		g_key_file_set_string (prefs_file, group, leaf, value);

	prefs_dirty = TRUE;

	g_free (group);
	g_free (leaf);
}

gint
fs_prefs_get_int (const gchar *key, gint fallback)
{
	gchar *group = NULL;
	gchar *leaf = NULL;
	GError *error = NULL;
	gint value;

	fs_prefs_init ();
	prefs_split_key (key, &group, &leaf);

	/* Same reason as fs_prefs_get_bool: a missing key has to become
	 * the fallback rather than 0. */
	value = g_key_file_get_integer (prefs_file, group, leaf, &error);

	if (error != NULL) {
		g_clear_error (&error);
		value = fallback;
	}

	g_free (group);
	g_free (leaf);

	return value;
}

void
fs_prefs_set_int (const gchar *key, gint value)
{
	gchar *group = NULL;
	gchar *leaf = NULL;

	fs_prefs_init ();
	prefs_split_key (key, &group, &leaf);

	g_key_file_set_integer (prefs_file, group, leaf, value);
	prefs_dirty = TRUE;

	g_free (group);
	g_free (leaf);
}

void
fs_prefs_set_defaults (void)
{
	fs_prefs_init ();

	if (!g_key_file_has_key (prefs_file, FS_PREFS_GROUP_CLIENT,
	                         "first_run", NULL))
		fs_prefs_set_bool (FS_PREFS_FIRST_RUN, TRUE);

	if (!g_key_file_has_key (prefs_file, FS_PREFS_GROUP_CLIENT,
	                         "enable_tray_icon", NULL))
		fs_prefs_set_bool (FS_PREFS_ENABLE_TRAY_ICON, TRUE);

	if (!g_key_file_has_key (prefs_file, FS_PREFS_GROUP_CLIENT,
	                         "minimize_to_tray", NULL))
		fs_prefs_set_bool (FS_PREFS_MINIMIZE_TO_TRAY, TRUE);

	if (!g_key_file_has_key (prefs_file, FS_PREFS_GROUP_CLIENT,
	                         "filter/redundant", NULL))
		fs_prefs_set_bool (FS_PREFS_SKIP_REDUNDANT, FALSE);

	if (!g_key_file_has_key (prefs_file, FS_PREFS_GROUP_CLIENT,
	                         "filter/not_for_firewall", NULL))
		fs_prefs_set_bool (FS_PREFS_SKIP_NOT_FOR_FIREWALL, TRUE);

	if (!g_key_file_has_key (prefs_file, FS_PREFS_GROUP_CLIENT,
	                         "policy_auto_apply", NULL))
		fs_prefs_set_bool (FS_PREFS_APPLY_POLICY_INSTANTLY, FALSE);

	fs_prefs_set_bool (FS_PREFS_FW_NAT, FALSE);
	fs_prefs_set_bool (FS_PREFS_FW_FILTER_ICMP, TRUE);
	fs_prefs_set_bool (FS_PREFS_FW_FILTER_TOS, TRUE);
	fs_prefs_set_bool (FS_PREFS_FW_DENY_PACKETS, TRUE);
	fs_prefs_set_bool (FS_PREFS_FW_BLOCK_NON_ROUTABLES, TRUE);
	fs_prefs_set_bool (FS_PREFS_FW_RESTRICTIVE_OUTBOUND, FALSE);

	fs_prefs_save ();
}