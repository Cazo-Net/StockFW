/*---[ fs-prefs.c ]------------------------------------------------------
 * GKeyFile-backed settings store.
 *--------------------------------------------------------------------*/

#include "core/fs-prefs.h"
#include "core/fs-util.h"

#include <stdio.h>
#include <string.h>
#ifndef G_OS_WIN32
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

#define FS_PREFS_GROUP_PREFIX "/apps/stockfw/"
#define FS_PREFS_GROUP_CLIENT  "client"
#define FS_PREFS_GROUP_FW      "firewall"
#define FS_PREFS_GROUP_UI      "client"

static GKeyFile *prefs_file = NULL;
static gchar    *prefs_path = NULL;
static gboolean  prefs_dirty = FALSE;

/* [ prefs_default_path ]
 * $XDG_CONFIG_HOME/stockfw/stockfw.conf on Linux (what
 * g_get_user_config_dir() gives us), and %APPDATA%\stockfw on
 * Windows.  g_get_user_config_dir() returns the *local* AppData folder
 * on Windows, which is the wrong place for user settings. */
static gchar *
prefs_default_path (void)
{
#ifdef G_OS_WIN32
	const gchar *appdata = g_getenv ("APPDATA");

	if (appdata != NULL && *appdata != '\0')
		return g_build_filename (appdata, "stockfw",
		                         "stockfw.conf", NULL);

	return g_build_filename (g_get_home_dir (), "AppData", "Roaming",
	                         "stockfw", "stockfw.conf", NULL);
#else
	return g_build_filename (g_get_user_config_dir (),
	                         "stockfw",
	                         "stockfw.conf",
	                         NULL);
#endif
}

/* [ prefs_split_key ]
 * "/apps/stockfw/firewall/icmp/enable"
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

/* [ prefs_copy_file ] -- byte for byte, replacing dest. */
static gboolean
prefs_copy_file (const gchar *src, const gchar *dest)
{
	gchar *contents = NULL;
	gsize length = 0;
	gboolean ok;

	if (!g_file_get_contents (src, &contents, &length, NULL))
		return FALSE;

	ok = g_file_set_contents (dest, contents, (gssize) length, NULL);
	g_free (contents);

	return ok;
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
		gchar *backup = fs_prefs_backup_path ();

		g_warning ("Could not read settings from %s: %s",
		           prefs_path, error->message);
		g_error_free (error);

		/* The caller writes defaults next, over this file.  Keep the
		 * user's copy first: a stray edit or a half-written file is
		 * usually one line away from being readable again. */
		if (!prefs_copy_file (prefs_path, backup))
			g_warning ("Could not keep a copy of the unreadable "
			           "settings file as %s", backup);
		else
			g_warning ("The unreadable settings file was kept as %s",
			           backup);
		g_free (backup);

		/* A failed load leaves the store in no known state; start
		 * clean. */
		g_key_file_free (prefs_file);
		prefs_file = g_key_file_new ();
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

gchar *
fs_prefs_backup_path (void)
{
	return g_strconcat (fs_prefs_path (), ".bad", NULL);
}

gboolean
fs_prefs_dirty (void)
{
	return prefs_dirty;
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

/* =====================================================================
 * The settings table
 * ===================================================================== */

#define SPEC_BOOL(macro, def, fw) \
	{ macro, #macro, FS_PREF_BOOL, def, NULL, fw }
#define SPEC_STRING(macro, def, fw) \
	{ macro, #macro, FS_PREF_STRING, FALSE, def, fw }

/* The one place a default lives.  The last column marks the settings
 * that change the rules the firewall gets: changing one of those is
 * what makes the Preferences window offer to apply. */
static const FsPrefSpec prefs_table[] = {
	/* The window and the tray */
	SPEC_BOOL (FS_PREFS_ENABLE_TRAY_ICON,        TRUE,  FALSE),
	SPEC_BOOL (FS_PREFS_MINIMIZE_TO_TRAY,        TRUE,  FALSE),
	SPEC_BOOL (FS_PREFS_DARK_MODE,               FALSE, FALSE),
	SPEC_BOOL (FS_PREFS_START_ON_GUI,            FALSE, FALSE),

	/* Events */
	SPEC_BOOL (FS_PREFS_SKIP_REDUNDANT,          FALSE, FALSE),
	SPEC_BOOL (FS_PREFS_SKIP_NOT_FOR_FIREWALL,   TRUE,  FALSE),
	SPEC_STRING (FS_PREFS_EVENTS_MAX,            "100000", FALSE),
	/* Off until chosen: a month of addresses, ports and devices on
	 * disk is the user's call, not an upgrade's. */
	SPEC_BOOL (FS_PREFS_EVENTS_HISTORY,          FALSE, FALSE),
	SPEC_STRING (FS_PREFS_EVENTS_HISTORY_DAYS,   "30",  FALSE),
	SPEC_STRING (FS_PREFS_EVENTS_HISTORY_MB,     "200", FALSE),

	/* Policy.  Auto-apply is off: the original asked for an explicit
	 * Apply, and applying on every edit is noisy when not elevated. */
	SPEC_BOOL (FS_PREFS_APPLY_POLICY_INSTANTLY,  FALSE, FALSE),
	SPEC_BOOL (FS_PREFS_AUDIT_ONLY,              FALSE, FALSE),

	/* Network (Linux) */
	SPEC_STRING (FS_PREFS_FW_EXT_IF,             "",    TRUE),
	SPEC_STRING (FS_PREFS_FW_INT_IF,             "",    TRUE),
	SPEC_BOOL (FS_PREFS_FW_NAT,                  FALSE, TRUE),

	/* ICMP.  The original shipped no default for the types; these keep
	 * a normal machine working: ping, traceroute and the unreachable
	 * reports on, the privacy-questionable ones off. */
	SPEC_BOOL (FS_PREFS_FW_FILTER_ICMP,          TRUE,  TRUE),
	SPEC_BOOL (FS_PREFS_FW_ICMP_ECHO_REQUEST,    TRUE,  TRUE),
	SPEC_BOOL (FS_PREFS_FW_ICMP_ECHO_REPLY,      TRUE,  TRUE),
	SPEC_BOOL (FS_PREFS_FW_ICMP_TRACEROUTE,      TRUE,  TRUE),
	SPEC_BOOL (FS_PREFS_FW_ICMP_MSTRACEROUTE,    TRUE,  TRUE),
	SPEC_BOOL (FS_PREFS_FW_ICMP_UNREACHABLE,     TRUE,  TRUE),
	SPEC_BOOL (FS_PREFS_FW_ICMP_TIMESTAMPING,    FALSE, TRUE),
	SPEC_BOOL (FS_PREFS_FW_ICMP_MASKING,         FALSE, TRUE),
	SPEC_BOOL (FS_PREFS_FW_ICMP_REDIRECTION,     FALSE, TRUE),
	SPEC_BOOL (FS_PREFS_FW_ICMP_SOURCE_QUENCHES, FALSE, TRUE),

	/* Firewall behaviour and protection.  deny_packets TRUE drops
	 * blocked packets silently, FALSE answers with an error packet. */
	SPEC_BOOL (FS_PREFS_FW_DENY_PACKETS,         TRUE,  TRUE),
	SPEC_BOOL (FS_PREFS_FW_RESTRICTIVE_OUTBOUND, FALSE, TRUE),
	SPEC_BOOL (FS_PREFS_FW_LOG_ALLOWED,          TRUE,  TRUE),
	SPEC_BOOL (FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST, FALSE, TRUE),
	SPEC_BOOL (FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST, FALSE, TRUE),
	SPEC_BOOL (FS_PREFS_FW_BLOCK_NON_ROUTABLES,  TRUE,  TRUE),
};

const FsPrefSpec *
fs_prefs_specs (guint *n_specs)
{
	if (n_specs != NULL)
		*n_specs = G_N_ELEMENTS (prefs_table);

	return prefs_table;
}

const FsPrefSpec *
fs_prefs_spec (const gchar *key)
{
	if (key == NULL)
		return NULL;

	for (guint i = 0; i < G_N_ELEMENTS (prefs_table); i++)
		if (strcmp (prefs_table[i].key, key) == 0)
			return &prefs_table[i];

	return NULL;
}

/* [ fs_prefs_bool ]
 * A key outside the table is a programming error: it reads as FALSE
 * after a critical, so a typo never silently turns something on. */
gboolean
fs_prefs_bool (const gchar *key)
{
	const FsPrefSpec *spec = fs_prefs_spec (key);

	g_return_val_if_fail (spec != NULL && spec->type == FS_PREF_BOOL,
	                      FALSE);

	return fs_prefs_get_bool (key, spec->bool_default);
}

gchar *
fs_prefs_string (const gchar *key)
{
	const FsPrefSpec *spec = fs_prefs_spec (key);

	g_return_val_if_fail (spec != NULL && spec->type == FS_PREF_STRING,
	                      g_strdup (""));

	return fs_prefs_get_string (key, spec->string_default);
}

guint
fs_prefs_uint (const gchar *key, guint min, guint max)
{
	const FsPrefSpec *spec = fs_prefs_spec (key);
	gchar *text, *end = NULL;
	guint64 value;

	g_return_val_if_fail (spec != NULL && spec->type == FS_PREF_STRING,
	                      min);

	text = fs_prefs_get_string (key, spec->string_default);
	g_strstrip (text);
	value = g_ascii_strtoull (text, &end, 10);
	if (!g_ascii_isdigit (*text) || end == NULL || *end != '\0')
		value = g_ascii_strtoull (spec->string_default, NULL, 10);
	g_free (text);

	return (guint) CLAMP (value, (guint64) min, (guint64) max);
}

gboolean
fs_prefs_has_key (const gchar *key)
{
	gchar *group = NULL;
	gchar *leaf = NULL;
	gboolean has;

	fs_prefs_init ();
	prefs_split_key (key, &group, &leaf);
	has = g_key_file_has_key (prefs_file, group, leaf, NULL);
	g_free (group);
	g_free (leaf);

	return has;
}

/* [ fs_prefs_firewall_values ]
 * What the rule generator would read now, as text: the apply journal
 * records it beside the policy it applied, so a later apply can tell
 * whether the settings on the firewall are still the saved ones. */
GHashTable *
fs_prefs_firewall_values (void)
{
	GHashTable *values = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                            NULL, g_free);

	for (guint i = 0; i < G_N_ELEMENTS (prefs_table); i++) {
		const FsPrefSpec *spec = &prefs_table[i];
		gchar *value;

		if (!spec->firewall)
			continue;

		if (spec->type == FS_PREF_BOOL)
			value = g_strdup (fs_prefs_bool (spec->key)
			                  ? "true" : "false");
		else
			value = fs_prefs_string (spec->key);
		g_hash_table_insert (values, (gpointer) spec->key,
		                     value != NULL ? value : g_strdup (""));
	}

	return values;
}

void
fs_prefs_set_defaults (void)
{
	fs_prefs_init ();

	for (guint i = 0; i < G_N_ELEMENTS (prefs_table); i++) {
		const FsPrefSpec *spec = &prefs_table[i];

		if (fs_prefs_has_key (spec->key))
			continue;

		/* Strings stay unset: an empty device name and a missing one
		 * mean the same, and nothing is gained by writing it. */
		if (spec->type == FS_PREF_BOOL)
			fs_prefs_set_bool (spec->key, spec->bool_default);
	}

	fs_prefs_save ();
}

/* =====================================================================
 * Editing a copy
 * ===================================================================== */

typedef struct
{
	gboolean b, orig_b;
	gchar   *s, *orig_s;
	gboolean writable;
} EditValue;

struct _FsPrefsEdit
{
	EditValue values[G_N_ELEMENTS (prefs_table)];
};

static EditValue *
edit_value (FsPrefsEdit *edit, const gchar *key, FsPrefType type)
{
	const FsPrefSpec *spec = fs_prefs_spec (key);

	g_return_val_if_fail (edit != NULL, NULL);
	g_return_val_if_fail (spec != NULL && spec->type == type, NULL);

	return &edit->values[spec - prefs_table];
}

FsPrefsEdit *
fs_prefs_edit_new (void)
{
	FsPrefsEdit *edit = g_new0 (FsPrefsEdit, 1);

	for (guint i = 0; i < G_N_ELEMENTS (prefs_table); i++) {
		const FsPrefSpec *spec = &prefs_table[i];
		EditValue *v = &edit->values[i];

		if (spec->type == FS_PREF_BOOL) {
			v->orig_b = v->b = fs_prefs_bool (spec->key);
		} else {
			v->orig_s = fs_prefs_string (spec->key);
			if (v->orig_s == NULL)
				v->orig_s = g_strdup ("");
			v->s = g_strdup (v->orig_s);
		}
	}

	return edit;
}

void
fs_prefs_edit_free (FsPrefsEdit *edit)
{
	if (edit == NULL)
		return;

	for (guint i = 0; i < G_N_ELEMENTS (prefs_table); i++) {
		g_free (edit->values[i].s);
		g_free (edit->values[i].orig_s);
	}
	g_free (edit);
}

gboolean
fs_prefs_edit_get_bool (FsPrefsEdit *edit, const gchar *key)
{
	EditValue *v = edit_value (edit, key, FS_PREF_BOOL);

	return v != NULL ? v->b : FALSE;
}

void
fs_prefs_edit_set_bool (FsPrefsEdit *edit, const gchar *key, gboolean value)
{
	EditValue *v = edit_value (edit, key, FS_PREF_BOOL);

	if (v != NULL)
		v->b = value ? TRUE : FALSE;
}

gboolean
fs_prefs_edit_orig_bool (FsPrefsEdit *edit, const gchar *key)
{
	EditValue *v = edit_value (edit, key, FS_PREF_BOOL);

	return v != NULL ? v->orig_b : FALSE;
}

const gchar *
fs_prefs_edit_get_string (FsPrefsEdit *edit, const gchar *key)
{
	EditValue *v = edit_value (edit, key, FS_PREF_STRING);

	return v != NULL ? v->s : "";
}

void
fs_prefs_edit_set_string (FsPrefsEdit *edit, const gchar *key,
                          const gchar *value)
{
	EditValue *v = edit_value (edit, key, FS_PREF_STRING);

	if (v == NULL)
		return;

	g_free (v->s);
	v->s = g_strdup (value != NULL ? value : "");
}

const gchar *
fs_prefs_edit_orig_string (FsPrefsEdit *edit, const gchar *key)
{
	EditValue *v = edit_value (edit, key, FS_PREF_STRING);

	return v != NULL ? v->orig_s : "";
}

void
fs_prefs_edit_set_writable (FsPrefsEdit *edit, const gchar *key,
                            gboolean writable)
{
	const FsPrefSpec *spec = fs_prefs_spec (key);

	g_return_if_fail (edit != NULL && spec != NULL);

	edit->values[spec - prefs_table].writable = writable;
}

static gboolean
value_changed (const FsPrefSpec *spec, const EditValue *v)
{
	if (spec->type == FS_PREF_BOOL)
		return v->b != v->orig_b;

	return g_strcmp0 (v->s, v->orig_s) != 0;
}

gboolean
fs_prefs_edit_changed (FsPrefsEdit *edit, const gchar *key)
{
	const FsPrefSpec *spec = fs_prefs_spec (key);

	g_return_val_if_fail (edit != NULL && spec != NULL, FALSE);

	return value_changed (spec, &edit->values[spec - prefs_table]);
}

guint
fs_prefs_edit_n_changed (FsPrefsEdit *edit)
{
	guint n = 0;

	g_return_val_if_fail (edit != NULL, 0);

	for (guint i = 0; i < G_N_ELEMENTS (prefs_table); i++)
		if (value_changed (&prefs_table[i], &edit->values[i]))
			n++;

	return n;
}

guint
fs_prefs_edit_n_pending (FsPrefsEdit *edit)
{
	guint n = 0;

	g_return_val_if_fail (edit != NULL, 0);

	for (guint i = 0; i < G_N_ELEMENTS (prefs_table); i++)
		if (edit->values[i].writable &&
		    value_changed (&prefs_table[i], &edit->values[i]))
			n++;

	return n;
}

guint
fs_prefs_edit_commit (FsPrefsEdit *edit, gboolean *firewall_changed)
{
	guint written = 0;
	gboolean fw = FALSE;

	if (firewall_changed != NULL)
		*firewall_changed = FALSE;

	g_return_val_if_fail (edit != NULL, 0);

	for (guint i = 0; i < G_N_ELEMENTS (prefs_table); i++) {
		const FsPrefSpec *spec = &prefs_table[i];
		EditValue *v = &edit->values[i];

		if (!v->writable || !value_changed (spec, v))
			continue;

		if (spec->type == FS_PREF_BOOL)
			fs_prefs_set_bool (spec->key, v->b);
		else
			fs_prefs_set_string (spec->key, v->s);

		/* The snapshot now matches the store: committing the same
		 * edit twice writes nothing the second time. */
		v->orig_b = v->b;
		g_free (v->orig_s);
		v->orig_s = g_strdup (v->s);

		written++;
		if (spec->firewall)
			fw = TRUE;
	}

	if (firewall_changed != NULL)
		*firewall_changed = fw;

	return written;
}

/* =====================================================================
 * Writing some keys, and only those (PR 3)
 * ===================================================================== */

GQuark
fs_prefs_error_quark (void)
{
	return g_quark_from_static_string ("stockfw-prefs-error");
}

/* [ prefs_write_defaults ] -- fs_prefs_set_defaults without the save. */
static void
prefs_write_defaults (void)
{
	for (guint i = 0; i < G_N_ELEMENTS (prefs_table); i++) {
		const FsPrefSpec *spec = &prefs_table[i];

		/* As fs_prefs_set_defaults: strings stay unset. */
		if (!fs_prefs_has_key (spec->key) && spec->type == FS_PREF_BOOL)
			fs_prefs_set_bool (spec->key, spec->bool_default);
	}
}

/* [ fs_prefs_set_persist ] */
/* [ prefs_extra_key ]
 * Keys outside the table that fs_prefs_set_persist writes too, with the
 * values each takes (NULL: back to its default).  Sentinel's mode is set
 * on the Copilot page, not in Preferences (PR 4, 4B: `sentinel mode'). */
static gboolean
prefs_extra_key (const gchar *key, const gchar *value)
{
	if (g_strcmp0 (key, "/apps/stockfw/client/sentinel/mode") == 0)
		return value == NULL || strcmp (value, "auto") == 0 ||
		       strcmp (value, "detect") == 0;
	return FALSE;
}

gboolean
fs_prefs_set_persist (const gchar * const *keys, const gchar * const *values,
                      guint n, gboolean *was_unreadable, GError **error)
{
	gboolean ok = FALSE;
#ifndef G_OS_WIN32
	gchar *lock_path = NULL;
	int fd = -1;
#endif

	if (was_unreadable != NULL)
		*was_unreadable = FALSE;

	/* Every key and value is checked before anything is touched. */
	for (guint i = 0; i < n; i++) {
		const FsPrefSpec *spec = fs_prefs_spec (keys[i]);

		if (spec == NULL && !prefs_extra_key (keys[i], values[i])) {
			g_set_error (error, FS_PREFS_ERROR, FS_PREFS_ERR_INVALID,
			             "%s is not a setting", keys[i]);
			return FALSE;
		}
		if (spec != NULL && values[i] != NULL &&
		    spec->type == FS_PREF_BOOL &&
		    strcmp (values[i], "true") != 0 &&
		    strcmp (values[i], "false") != 0) {
			g_set_error (error, FS_PREFS_ERROR, FS_PREFS_ERR_INVALID,
			             "%s takes true or false, not \"%s\"", keys[i],
			             values[i]);
			return FALSE;
		}
	}

	if (!fs_util_ensure_parent_dir (fs_prefs_path ())) {
		g_set_error (error, FS_PREFS_ERROR, FS_PREFS_ERR_SAVE,
		             "cannot create the settings directory for %s",
		             fs_prefs_path ());
		return FALSE;
	}

#ifndef G_OS_WIN32
	/* One writer: flock on "<file>.lock".  Another writer's change
	 * made before we hold it is read back below, never lost. */
	lock_path = g_strconcat (fs_prefs_path (), ".lock", NULL);
	fd = open (lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0) {
		g_set_error (error, FS_PREFS_ERROR, FS_PREFS_ERR_SAVE,
		             "cannot open the lock %s: %s", lock_path,
		             g_strerror (errno));
		g_free (lock_path);
		return FALSE;
	}
	while (flock (fd, LOCK_EX) != 0) {
		if (errno == EINTR)
			continue;
		g_set_error (error, FS_PREFS_ERROR, FS_PREFS_ERR_SAVE,
		             "cannot lock %s: %s", lock_path, g_strerror (errno));
		close (fd);
		g_free (lock_path);
		return FALSE;
	}
#endif

	/* Re-read under the lock: what is on disk now is the base. */
	if (prefs_file != NULL) {
		g_key_file_free (prefs_file);
		prefs_file = NULL;
	}
	fs_prefs_init ();
	if (g_file_test (fs_prefs_path (), G_FILE_TEST_EXISTS) &&
	    !fs_prefs_load ()) {
		/* A12: the unreadable file was kept as <file>.bad by
		 * fs_prefs_load; the defaults are written in its place,
		 * then the keys asked for. */
		if (was_unreadable != NULL)
			*was_unreadable = TRUE;
		prefs_write_defaults ();
	}

	for (guint i = 0; i < n; i++) {
		const FsPrefSpec *spec = fs_prefs_spec (keys[i]);

		if (values[i] == NULL) {
			/* Back to the table's default: the key goes. */
			gchar *group = NULL, *leaf = NULL;

			prefs_split_key (keys[i], &group, &leaf);
			g_key_file_remove_key (prefs_file, group, leaf, NULL);
			prefs_dirty = TRUE;
			g_free (group);
			g_free (leaf);
		} else if (spec != NULL && spec->type == FS_PREF_BOOL) {
			fs_prefs_set_bool (keys[i], strcmp (values[i], "true") == 0);
		} else {
			fs_prefs_set_string (keys[i], values[i]);
		}
	}

	ok = fs_prefs_save ();
	if (!ok)
		g_set_error (error, FS_PREFS_ERROR, FS_PREFS_ERR_SAVE,
		             "could not write the settings to %s",
		             fs_prefs_path ());

#ifndef G_OS_WIN32
	close (fd);   /* releases the flock */
	g_free (lock_path);
#endif
	return ok;
}
