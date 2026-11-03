/*---[ fs-cli-config.c ]-------------------------------------------------
 * `stockfw config': reading and changing the preferences from the
 * terminal (master plan, PR 3, package 3C).  Every write goes through
 * the control layer (control/fs-control.h: settings.set and
 * settings.apply), which checks the keys with fs_prefs_validate and
 * saves them with fs_prefs_set_persist under the file's lock.
 *
 *   config [list] [--firewall] [--changed]
 *   config get NAME
 *   config set NAME VALUE [NAME VALUE]... [--apply] [--yes]
 *   config reset NAME... [--apply] [--yes]
 *   config apply [--yes]
 *   config devices
 *   config audit-only [on|off]
 *
 * NAME is a setting of the table (fs_prefs_specs): its dotted name
 * ("firewall.icmp.echo_request"), its key ("/apps/stockfw/firewall/nat"
 * or "firewall/nat"), or its last part when no other setting ends the
 * same way ("nat", "ext_if").  "-" and "_" are the same.
 *
 * Only root writes, and only root's copy: the firewall, the boot unit
 * and `apply' run as root read that one.  A firewall setting that is
 * saved is not in force until the next apply: `config apply' (or `set
 * --apply'), or a policy apply, which sends the saved settings too; a
 * boot starts with the settings last applied (3B), never with ones
 * only saved.
 *--------------------------------------------------------------------*/
#define _GNU_SOURCE              /* struct ucred */
#include "cli/fs-cli.h"
#include "control/fs-control.h"
#include "core/fs-apply.h"
#include "core/fs-json.h"
#include "core/fs-lockout.h"
#include "core/fs-prefs.h"
#include "core/fs-script.h"
#include "core/fs-util.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define PREFIX "/apps/stockfw/"

/* -------------------------------------------------------------- names */

/* [ setting_name ] -- the dotted name a setting is shown by:
 * "/apps/stockfw/client/filter/redundant" is "filter.redundant",
 * "/apps/stockfw/firewall/nat" is "firewall.nat".  g_free. */
static gchar *
setting_name (const FsPrefSpec *spec)
{
	const gchar *rel = spec->key;
	gchar *name;

	if (g_str_has_prefix (rel, PREFIX))
		rel += strlen (PREFIX);
	if (g_str_has_prefix (rel, "client/"))
		rel += strlen ("client/");
	name = g_strdup (rel);
	g_strdelimit (name, "/", '.');
	return name;
}

/* "-" reads as "_", "/" as ".", any case. */
static gchar *
normal (const gchar *word)
{
	gchar *n = g_ascii_strdown (word, -1);

	g_strdelimit (n, "-", '_');
	g_strdelimit (n, "/", '.');
	return n;
}

static const gchar *
leaf (const gchar *key)
{
	const gchar *slash = strrchr (key, '/');

	return slash != NULL ? slash + 1 : key;
}

/* [ resolve ] -- the setting `word' names, or NULL. */
static const FsPrefSpec *
resolve (const gchar *word)
{
	guint n;
	const FsPrefSpec *specs = fs_prefs_specs (&n);
	const FsPrefSpec *found = NULL;
	gchar *want;
	guint leaves = 0;

	if (word == NULL || *word == '\0')
		return NULL;
	if (fs_prefs_spec (word) != NULL)
		return fs_prefs_spec (word);

	want = normal (word);
	/* Friendly names the help uses. */
	if (strcmp (want, "audit_only") == 0) {
		g_free (want);
		return fs_prefs_spec (FS_PREFS_AUDIT_ONLY);
	}
	if (strcmp (want, "icmp") == 0) {
		g_free (want);
		return fs_prefs_spec (FS_PREFS_FW_FILTER_ICMP);
	}

	for (guint i = 0; i < n && found == NULL; i++) {
		gchar *name = setting_name (&specs[i]);
		gchar *nn = normal (name);
		gchar *rel = normal (specs[i].key + strlen (PREFIX));

		if (strcmp (want, nn) == 0 || strcmp (want, rel) == 0)
			found = &specs[i];
		g_free (rel);
		g_free (nn);
		g_free (name);
	}
	/* The last part alone, when only one setting ends that way. */
	for (guint i = 0; i < n && found == NULL; i++) {
		gchar *l = normal (leaf (specs[i].key));

		if (strcmp (want, l) == 0)
			leaves++;
		g_free (l);
	}
	for (guint i = 0; i < n && found == NULL && leaves == 1; i++) {
		gchar *l = normal (leaf (specs[i].key));

		if (strcmp (want, l) == 0)
			found = &specs[i];
		g_free (l);
	}
	g_free (want);
	return found;
}

/* [ shown ] -- the settings `list' offers: the ones this firewall acts
 * on (as the Preferences window shows them), less "apply policy
 * changes immediately", which the terminal never sets (J12). */
static gboolean
shown (const FsPrefSpec *spec)
{
	const FsBackend *b = fs_backend ();

	return fs_prefs_key_honoured (spec->key, b->fw_sections,
	                              b->fw_honors) &&
	       strcmp (spec->key, FS_PREFS_APPLY_POLICY_INSTANTLY) != 0;
}

/* Every name `list' shows, for "did you mean" and completion.  The
 * strings live as long as the process. */
static const gchar * const *
names_shown (guint *n_out)
{
	static GPtrArray *names = NULL;

	if (names == NULL) {
		guint n;
		const FsPrefSpec *specs = fs_prefs_specs (&n);

		names = g_ptr_array_new ();
		for (guint i = 0; i < n; i++)
			if (shown (&specs[i]))
				g_ptr_array_add (names, setting_name (&specs[i]));
		g_ptr_array_add (names, g_strdup ("audit-only"));
		g_ptr_array_add (names, NULL);
	}
	if (n_out != NULL)
		*n_out = names->len - 1;
	return (const gchar * const *) names->pdata;
}

const gchar * const *
fs_cli_config_names (void)
{
	return names_shown (NULL);
}

static void
unknown_setting (const gchar *word)
{
	guint n;
	const gchar * const *names = names_shown (&n);
	const gchar *best = fs_cli_suggest (word, names, n);

	if (best != NULL)
		fs_cli_error ("unknown setting: %s (did you mean %s?)", word, best);
	else
		fs_cli_error ("unknown setting: %s", word);
	fs_cli_hint ("`stockfw config list' shows every setting");
}

/* ------------------------------------------------------------- values */

/* The value as the settings file holds it now: "true"/"false" for a
 * switch, else the text ("" for no device).  g_free. */
static gchar *
value_now (const FsPrefSpec *spec)
{
	if (spec->type == FS_PREF_BOOL)
		return g_strdup (fs_prefs_bool (spec->key) ? "true" : "false");
	return fs_prefs_string (spec->key);
}

static const gchar *
default_value (const FsPrefSpec *spec)
{
	if (spec->type == FS_PREF_BOOL)
		return spec->bool_default ? "true" : "false";
	return spec->string_default != NULL ? spec->string_default : "";
}

/* [ shown_value ] -- "on"/"off" for a switch, "-" for no device, else
 * the text, made safe for a terminal.  g_free. */
static gchar *
shown_value (const FsPrefSpec *spec, const gchar *value)
{
	if (value == NULL)
		return g_strdup ("-");
	if (spec->type == FS_PREF_BOOL)
		return g_strdup (strcmp (value, "true") == 0 ? "on" : "off");
	if (*value == '\0')
		return g_strdup ("-");
	return fs_cli_out_safe (value);
}

static void
value_json (GString *out, const gchar *key, const FsPrefSpec *spec,
            const gchar *value)
{
	fs_json_key (out, key);
	if (value == NULL)
		g_string_append (out, "null");
	else if (spec->type == FS_PREF_BOOL)
		g_string_append (out, strcmp (value, "true") == 0 ? "true"
		                                                   : "false");
	else
		fs_json_string (out, value);
}

/* ----------------------------------------------------------- warnings */

/* [ warn ] -- "stockfw: warning: ...", even under -q. */
static void G_GNUC_PRINTF (1, 2)
warn (const gchar *format, ...)
{
	va_list args;
	gchar *text, *safe;

	va_start (args, format);
	text = g_strdup_vprintf (format, args);
	va_end (args);
	safe = fs_cli_out_safe (text);
	fprintf (stderr, "stockfw: %swarning:%s %s\n",
	         fs_cli.color_err ? "\033[1;33m" : "",
	         fs_cli.color_err ? "\033[0m" : "", safe);
	g_free (safe);
	g_free (text);
}

/* [ gui_probe ] -- does the instance socket `name' (abstract) belong
 * to a process running as root? */
static gboolean
gui_probe (const gchar *name)
{
	struct sockaddr_un addr;
	struct ucred cred;
	socklen_t len = sizeof cred;
	gsize n = MIN (strlen (name), sizeof addr.sun_path - 2);
	gint fd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	                  0);
	gboolean root = FALSE;

	if (fd < 0)
		return FALSE;
	memset (&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	memcpy (addr.sun_path + 1, name, n);
	if (connect (fd, (struct sockaddr *) &addr,
	             (socklen_t) (offsetof (struct sockaddr_un, sun_path) + 1 +
	                          n)) == 0 &&
	    getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0)
		root = cred.uid == 0;
	close (fd);
	return root;
}

/* [ root_gui_running ]
 * Is a StockFW window running as root?  It keeps its own copy of the
 * settings in memory and writes it back when it saves, so a change made
 * here can be undone by it, and its window does not show the change.
 * Found by its instance socket (core/fs-instance.c): an abstract name
 * "stockfw-gui-<uid>" (or $STOCKFW_INSTANCE_NAME), whose owner is
 * root. */
static gboolean
root_gui_running (void)
{
	const gchar *env = g_getenv ("STOCKFW_INSTANCE_NAME");
	gchar *contents = NULL;
	gchar **lines;
	gboolean found = FALSE;

	if (!g_file_get_contents ("/proc/net/unix", &contents, NULL, NULL))
		return FALSE;
	lines = g_strsplit (contents, "\n", -1);
	for (guint i = 1; lines[i] != NULL && !found; i++) {
		gchar **f = g_strsplit_set (lines[i], " ", -1);
		guint nf = g_strv_length (f);
		const gchar *path = nf > 0 ? f[nf - 1] : NULL;

		if (path != NULL && path[0] == '@' &&
		    (env != NULL && *env != '\0'
		     ? strcmp (path + 1, env) == 0
		     : g_str_has_prefix (path + 1, "stockfw-gui-")))
			found = gui_probe (path + 1);
		g_strfreev (f);
	}
	g_strfreev (lines);
	g_free (contents);
	return found;
}

static void
root_gui_warning (gboolean running)
{
	if (running)
		warn ("a StockFW window is running as root: it keeps its own "
		      "copy of the settings and writes it back when it saves. "
		      "Close it and open it again to see this change, or it "
		      "may be undone");
}

/* [ unreadable_warning ] -- A12: what was kept, and what was written. */
static void
unreadable_warning (void)
{
	gchar *bad = fs_prefs_backup_path ();

	warn ("the settings file %s could not be read: it was kept as %s and "
	      "the defaults were written with this change", fs_prefs_path (),
	      bad);
	g_free (bad);
}

/* ----------------------------------------------------------- list, get */

static gint
config_list (gint argc, gchar **argv)
{
	gboolean firewall = FALSE, changed = FALSE;
	guint n;
	const FsPrefSpec *specs = fs_prefs_specs (&n);
	GHashTable *live = fs_apply_journal_settings ();
	gboolean readable = !g_file_test (fs_prefs_path (), G_FILE_TEST_EXISTS)
	                    || fs_prefs_load ();
	gboolean pending = fs_apply_settings_pending ();
	GPtrArray *rows = g_ptr_array_new_with_free_func (
		(GDestroyNotify) g_strfreev);
	GString *json = g_string_new (NULL);
	guint shown_n = 0;

	for (gint i = 1; i < argc; i++) {
		if (fs_cli_is_option_at (argv, i) &&
		    strcmp (argv[i], "--firewall") == 0) {
			firewall = TRUE;
		} else if (fs_cli_is_option_at (argv, i) &&
		           strcmp (argv[i], "--changed") == 0) {
			changed = TRUE;
		} else if (fs_cli_is_option_at (argv, i)) {
			fs_cli_unknown_option ("config", argv[i]);
			goto usage;
		} else {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			fs_cli_hint ("`stockfw config get NAME' shows one setting");
			goto usage;
		}
	}

	g_string_append (json, "{");
	fs_json_kv_str (json, "file", fs_prefs_path ());
	g_string_append_c (json, ',');
	fs_json_kv_bool (json, "readable", readable);
	g_string_append_c (json, ',');
	fs_json_kv_bool (json, "applied_recorded", live != NULL);
	g_string_append_c (json, ',');
	fs_json_kv_bool (json, "pending", pending);
	g_string_append (json, ",\"settings\":[");

	for (guint i = 0; i < n; i++) {
		const FsPrefSpec *s = &specs[i];
		gchar *now, *name;
		const gchar *in_force;
		gboolean differs;

		if (!shown (s) || (firewall && !s->firewall))
			continue;
		now = value_now (s);
		differs = strcmp (now, default_value (s)) != 0;
		if (changed && !differs) {
			g_free (now);
			continue;
		}
		name = setting_name (s);
		in_force = s->firewall && live != NULL
		         ? g_hash_table_lookup (live, s->key) : NULL;

		if (shown_n++ > 0)
			g_string_append_c (json, ',');
		g_string_append_c (json, '{');
		fs_json_kv_str (json, "name", name);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "key", s->key);
		g_string_append_c (json, ',');
		value_json (json, "value", s, now);
		g_string_append_c (json, ',');
		value_json (json, "default", s, default_value (s));
		g_string_append_c (json, ',');
		fs_json_kv_bool (json, "changed", differs);
		g_string_append_c (json, ',');
		fs_json_kv_bool (json, "firewall", s->firewall);
		g_string_append_c (json, ',');
		value_json (json, "applied", s, in_force);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "topic", fs_prefs_key_topic (s->key));
		g_string_append_c (json, '}');

		{
			gchar **row = g_new0 (gchar *, 5);

			row[0] = g_strdup (name);
			row[1] = shown_value (s, now);
			row[2] = shown_value (s, default_value (s));
			row[3] = !s->firewall ? g_strdup ("")
			       : shown_value (s, in_force);
			g_ptr_array_add (rows, row);
		}
		g_free (name);
		g_free (now);
	}
	g_string_append (json, "]}");

	if (fs_cli.json) {
		fs_cli_print_json (json);
	} else {
		static const gchar *headers[] = { "SETTING", "VALUE", "DEFAULT",
		                                  "APPLIED" };

		if (!readable)
			warn ("the settings file %s could not be read: these are "
			      "the defaults; the next `config set' keeps it as "
			      "%s.bad and writes them", fs_prefs_path (),
			      fs_prefs_path ());
		fs_cli_table_ex (headers, 4, rows, 0, -1);
		if (!fs_cli.plain && !fs_cli.quiet) {
			if (pending && live != NULL)
				printf ("\nSaved firewall settings differ from the ones "
				        "last applied (APPLIED).  The firewall, and a "
				        "boot, use the applied ones until the next "
				        "apply: `stockfw config apply', or a policy "
				        "apply (`stockfw apply', --apply), which sends "
				        "them too.\n");
			else if (pending)
				printf ("\nNo applied settings are on record: the next "
				        "apply sends every firewall setting.\n");
		}
	}

	g_string_free (json, TRUE);
	g_ptr_array_unref (rows);
	if (live != NULL)
		g_hash_table_unref (live);
	return FS_EXIT_OK;

usage:
	g_string_free (json, TRUE);
	g_ptr_array_unref (rows);
	if (live != NULL)
		g_hash_table_unref (live);
	return FS_EXIT_USAGE;
}

static gint
config_get (gint argc, gchar **argv)
{
	const FsPrefSpec *spec;
	gchar *now, *name;

	if (argc != 2 || fs_cli_is_option_at (argv, 1)) {
		if (argc > 1 && fs_cli_is_option_at (argv, 1))
			fs_cli_unknown_option ("config", argv[1]);
		else
			fs_cli_error ("config get takes one setting");
		fs_cli_hint ("stockfw config get NAME");
		return FS_EXIT_USAGE;
	}
	spec = resolve (argv[1]);
	if (spec == NULL) {
		unknown_setting (argv[1]);
		return FS_EXIT_USAGE;
	}
	now = value_now (spec);
	name = setting_name (spec);
	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "name", name);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "key", spec->key);
		g_string_append_c (out, ',');
		value_json (out, "value", spec, now);
		g_string_append_c (out, ',');
		value_json (out, "default", spec, default_value (spec));
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "firewall", spec->firewall);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		gchar *safe = spec->type == FS_PREF_BOOL
		            ? g_strdup (strcmp (now, "true") == 0 ? "on" : "off")
		            : fs_cli_out_safe (now);

		printf ("%s\n", safe);
		g_free (safe);
	}
	g_free (name);
	g_free (now);
	return FS_EXIT_OK;
}

/* ------------------------------------------------------------ devices */

static gint
config_devices (gint argc, gchar **argv)
{
	const FsBackend *b = fs_backend ();
	GList *ifaces = b->list_interfaces != NULL ? b->list_interfaces ()
	                                           : NULL;
	gchar *ext = fs_prefs_string (FS_PREFS_FW_EXT_IF);
	gchar *intf = fs_prefs_string (FS_PREFS_FW_INT_IF);
	gboolean ext_seen = FALSE, int_seen = FALSE;
	GPtrArray *rows = g_ptr_array_new_with_free_func (
		(GDestroyNotify) g_strfreev);
	GString *json = g_string_new ("{\"devices\":[");
	guint count = 0;

	if (argc > 1) {
		if (fs_cli_is_option_at (argv, 1))
			fs_cli_unknown_option ("config", argv[1]);
		else
			fs_cli_error ("unexpected argument: %s", argv[1]);
		g_list_free_full (ifaces, (GDestroyNotify) fs_interface_free);
		g_ptr_array_unref (rows);
		g_string_free (json, TRUE);
		g_free (ext);
		g_free (intf);
		return FS_EXIT_USAGE;
	}

	for (GList *l = ifaces; l != NULL; l = l->next) {
		FsInterface *i = l->data;
		gboolean is_ext = *ext != '\0' && g_strcmp0 (i->name, ext) == 0;
		gboolean is_int = *intf != '\0' && g_strcmp0 (i->name, intf) == 0;
		const gchar *role = is_ext ? "internet"
		                  : is_int ? "local network" : "";
		gchar **row = g_new0 (gchar *, 4);

		ext_seen |= is_ext;
		int_seen |= is_int;
		row[0] = g_strdup (i->name);
		row[1] = g_strdup (i->ip != NULL ? i->ip : "");
		row[2] = g_strdup (role);
		g_ptr_array_add (rows, row);

		if (count++ > 0)
			g_string_append_c (json, ',');
		g_string_append_c (json, '{');
		fs_json_kv_str (json, "name", i->name);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "address", i->ip);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "role", *role != '\0' ? role : NULL);
		g_string_append_c (json, ',');
		fs_json_kv_bool (json, "present", TRUE);
		g_string_append_c (json, '}');
	}
	/* A chosen device that is not there now stays chosen (the window
	 * marks it "not present"). */
	for (guint d = 0; d < 2; d++) {
		const gchar *name = d == 0 ? ext : intf;
		gchar **row;

		if (*name == '\0' || (d == 0 ? ext_seen : int_seen))
			continue;
		row = g_new0 (gchar *, 4);
		row[0] = g_strdup (name);
		row[1] = g_strdup ("(not present)");
		row[2] = g_strdup (d == 0 ? "internet" : "local network");
		g_ptr_array_add (rows, row);
		if (count++ > 0)
			g_string_append_c (json, ',');
		g_string_append_c (json, '{');
		fs_json_kv_str (json, "name", name);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "address", NULL);
		g_string_append_c (json, ',');
		fs_json_kv_str (json, "role", d == 0 ? "internet"
		                                     : "local network");
		g_string_append_c (json, ',');
		fs_json_kv_bool (json, "present", FALSE);
		g_string_append_c (json, '}');
	}
	g_string_append (json, "]}");

	if (fs_cli.json) {
		fs_cli_print_json (json);
	} else {
		static const gchar *headers[] = { "DEVICE", "ADDRESS", "CHOSEN AS" };

		fs_cli_table_ex (headers, 3, rows, 0, -1);
		if (!fs_cli.plain && !fs_cli.quiet && (fs_backend ()->fw_sections &
		                                       FS_FWSEC_NETWORK))
			printf ("\nChoose with `stockfw config set ext_if DEVICE "
			        "int_if DEVICE'.\n");
	}

	g_list_free_full (ifaces, (GDestroyNotify) fs_interface_free);
	g_ptr_array_unref (rows);
	g_string_free (json, TRUE);
	g_free (ext);
	g_free (intf);
	return FS_EXIT_OK;
}

/* -------------------------------------------------------------- apply */

/* One firewall setting the apply changes: journal -> saved. */
typedef struct
{
	const FsPrefSpec *spec;
	gchar            *from;     /* NULL: nothing on record             */
	gchar            *to;
} Change;

static void
change_free (Change *c)
{
	g_free (c->from);
	g_free (c->to);
	g_free (c);
}

/* [ settings_diff ] -- the saved firewall settings that are not the
 * ones the journal records (all of them when it records none). */
static GPtrArray *
settings_diff (GHashTable *recorded)
{
	guint n;
	const FsPrefSpec *specs = fs_prefs_specs (&n);
	GPtrArray *out = g_ptr_array_new_with_free_func (
		(GDestroyNotify) change_free);

	for (guint i = 0; i < n; i++) {
		const FsPrefSpec *s = &specs[i];
		gchar *now;
		const gchar *was;

		if (!s->firewall || !shown (s))
			continue;
		now = value_now (s);
		was = recorded != NULL ? g_hash_table_lookup (recorded, s->key)
		                       : NULL;
		if (recorded != NULL && g_strcmp0 (was, now) == 0) {
			g_free (now);
			continue;
		}
		{
			Change *c = g_new0 (Change, 1);

			c->spec = s;
			c->from = g_strdup (was);
			c->to = now;
			g_ptr_array_add (out, c);
		}
	}
	return out;
}

/* [ count_lines ] -- every line of the generated chains, as counts. */
static void
count_lines (GHashTable *counts, const FsPolicy *policy,
             const FsSettings *settings, gint sign)
{
	static const FsFamily fams[] = { FS_FAMILY_IPV4, FS_FAMILY_IPV6 };

	for (guint f = 0; f < G_N_ELEMENTS (fams); f++) {
		for (gint dir = 0; dir < 2; dir++) {
			gchar *text = dir == 0
				? fs_script_generate_inbound_family (policy, settings,
				                                     fams[f])
				: fs_script_generate_outbound_family (policy, settings,
				                                      fams[f]);
			gchar **lines = g_strsplit (text != NULL ? text : "", "\n",
			                            -1);

			for (guint i = 0; lines[i] != NULL; i++) {
				gchar *line = g_strstrip (g_strdup (lines[i]));
				gint have;

				/* Rules only: not comments, blank lines or the
				 * script's own plumbing. */
				if (strstr (line, " -A ") == NULL &&
				    !g_str_has_prefix (line, "-A ")) {
					g_free (line);
					continue;
				}
				have = GPOINTER_TO_INT (g_hash_table_lookup (counts,
				                                             line));
				g_hash_table_replace (counts, line,
				                      GINT_TO_POINTER (have + sign));
			}
			g_strfreev (lines);
			g_free (text);
		}
	}
}

/* [ rules_impact ] -- firewall rules the new settings add and remove,
 * under `policy', against the settings `before'. */
static void
rules_impact (const FsPolicy *policy, const FsSettings *before,
              const FsSettings *after, guint *added, guint *removed)
{
	GHashTable *counts = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                            g_free, NULL);
	GHashTableIter it;
	gpointer k, v;

	*added = *removed = 0;
	count_lines (counts, policy, before, -1);
	count_lines (counts, policy, after, +1);
	g_hash_table_iter_init (&it, counts);
	while (g_hash_table_iter_next (&it, &k, &v)) {
		gint d = GPOINTER_TO_INT (v);

		if (d > 0)
			*added += (guint) d;
		else
			*removed += (guint) -d;
	}
	g_hash_table_unref (counts);
}

typedef struct
{
	GPtrArray *changes;        /* Change*                            */
	gboolean   recorded;       /* the journal records settings       */
	gboolean   journal;        /* a policy was applied before        */
	guint      rules_added;
	guint      rules_removed;
	gboolean   counted;        /* the two counts above mean something */
	guint      unapplied;      /* saved policy rows left out         */
	FsFirewallState state;
} Preview;

static void
preview_clear (Preview *p)
{
	if (p->changes != NULL)
		g_ptr_array_unref (p->changes);
	p->changes = NULL;
}

/* [ preview_make ] -- what `config apply' would do, read before it. */
static void
preview_make (Preview *p)
{
	FsPolicy *journal = fs_policy_new ();
	GHashTable *recorded = fs_apply_journal_settings ();
	const FsBackend *b = fs_backend ();

	memset (p, 0, sizeof *p);
	p->journal = fs_apply_journal_load (journal, NULL);
	p->recorded = recorded != NULL;
	p->changes = settings_diff (recorded);
	p->state = b->get_state != NULL ? b->get_state () : FS_FW_NONE;

	if (p->journal) {
		FsPolicy *saved = fs_cli_load_policy (NULL, NULL);
		FsPolicyImpact *imp = fs_policy_impact (journal, saved);

		p->unapplied = imp->added + imp->removed;
		fs_policy_impact_free (imp);
		fs_policy_free (saved);
	}
	if (p->journal && recorded != NULL) {
		FsSettings *before = fs_settings_new ();
		FsSettings *after = fs_settings_new ();

		fs_settings_load_values (before, recorded);
		fs_settings_load_prefs (after);
		rules_impact (journal, before, after, &p->rules_added,
		              &p->rules_removed);
		p->counted = TRUE;
		fs_settings_free (after);
		fs_settings_free (before);
	}
	if (recorded != NULL)
		g_hash_table_unref (recorded);
	fs_policy_free (journal);
}

static void
preview_print (const Preview *p)
{
	if (p->changes->len > 0 && p->recorded) {
		printf ("Firewall settings to apply:\n");
		for (guint i = 0; i < p->changes->len; i++) {
			const Change *c = g_ptr_array_index (p->changes, i);
			gchar *name = setting_name (c->spec);
			gchar *from = shown_value (c->spec, c->from);
			gchar *to = shown_value (c->spec, c->to);

			printf ("  %-34s %s %s %s\n", name, from,
			        fs_cli_sym (FS_CLI_SYM_ARROW), to);
			g_free (to);
			g_free (from);
			g_free (name);
		}
	} else if (!p->recorded) {
		printf ("No applied settings are on record: every firewall "
		        "setting goes out.\n");
	}
	if (p->counted)
		printf ("Impact: %u firewall rule%s added, %u removed.\n",
		        p->rules_added, p->rules_added == 1 ? "" : "s",
		        p->rules_removed);
	if (p->journal)
		printf ("Under the policy last applied%s.\n",
		        p->unapplied > 0
		        ? ": saved policy changes that are not applied stay off "
		          "(`stockfw apply' puts them in force)" : "");
	else
		printf ("No policy was applied before: the saved policy goes out "
		        "with them.\n");
	if (p->state == FS_FW_STOPPED)
		printf ("The firewall is stopped: this starts it.\n");
}

static void
preview_json (GString *out, const Preview *p)
{
	g_string_append (out, ",\"preview\":{");
	fs_json_kv_bool (out, "recorded", p->recorded);
	g_string_append_c (out, ',');
	fs_json_kv_bool (out, "journal", p->journal);
	g_string_append_c (out, ',');
	if (p->counted) {
		fs_json_kv_uint (out, "rules_added", p->rules_added);
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "rules_removed", p->rules_removed);
		g_string_append_c (out, ',');
	}
	fs_json_kv_uint (out, "policy_changes_left_off", p->unapplied);
	g_string_append (out, ",\"changes\":[");
	for (guint i = 0; i < p->changes->len; i++) {
		const Change *c = g_ptr_array_index (p->changes, i);
		gchar *name = setting_name (c->spec);

		if (i > 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "name", name);
		g_string_append_c (out, ',');
		value_json (out, "from", c->spec, c->from);
		g_string_append_c (out, ',');
		value_json (out, "to", c->spec, c->to);
		g_string_append_c (out, '}');
		g_free (name);
	}
	g_string_append (out, "]}");
}

/* [ lockout_warn ] -- the guard's warning. */
static void
lockout_warn (const FsLockoutReport *report)
{
	const FsLockoutPair *w = report->worst;
	gchar *why = fs_cli_out_safe (w->reason != NULL ? w->reason
	                              : "no rule allows it");

	warn ("these settings would block your SSH session");
	g_printerr ("  from %s to port %u: %s (%s)\n", w->peer, w->port,
	            fs_whatif_verdict_name (w->verdict), why);
	g_free (why);
}

static gboolean
lockout_ask (gboolean yes)
{
	if (yes)
		return TRUE;
	if (isatty (0)) {
		gchar answer[16] = "";

		g_printerr ("Apply anyway? [y/N] ");
		fflush (stderr);
		if (fgets (answer, sizeof answer, stdin) != NULL &&
		    g_ascii_strncasecmp (answer, "y", 1) == 0)
			return TRUE;
		fs_cli_error ("not done: the firewall was left as it was; the "
		              "settings stay saved");
		return FALSE;
	}
	fs_cli_error ("refused: pass --yes to apply anyway; the settings stay "
	              "saved");
	return FALSE;
}

static FsControlResult *
send_apply (gboolean yes)
{
	FsControlActor actor = fs_control_actor_self ("cli");
	GVariantBuilder b;

	g_variant_builder_init (&b, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&b, "{sv}", "yes", g_variant_new_boolean (yes));
	return fs_control_do (&actor, "settings.apply",
	                      g_variant_builder_end (&b));
}

/* [ settings_apply ]
 * The saved firewall settings under the policy last applied (J36):
 * the difference and its impact first, then the control layer's
 * settings.apply with the lockout guard.  Appends "apply":{...} to
 * json when given (the caller prints it), else prints. */
static gint
settings_apply (gboolean yes, GString *json)
{
	Preview p;
	FsControlResult *r;
	gint status = FS_EXIT_OK;
	gboolean asked_no = FALSE;
	GString *out = g_string_new (NULL);

	fs_prefs_load ();
	preview_make (&p);

	g_string_append (out, "{");
	if (p.journal && p.recorded && p.changes->len == 0) {
		fs_json_kv_bool (out, "applied", FALSE);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "nothing_to_apply", TRUE);
		preview_json (out, &p);
		g_string_append_c (out, '}');
		if (json != NULL)
			g_string_append (json, out->str);
		else
			printf ("Nothing to apply: the firewall already has the "
			        "saved settings.\n");
		g_string_free (out, TRUE);
		preview_clear (&p);
		return FS_EXIT_OK;
	}
	if (json == NULL)
		preview_print (&p);

	r = send_apply (yes);
	if (r->lockout != NULL && fs_lockout_report_cuts (r->lockout))
		lockout_warn (r->lockout);
	if (r->status == FS_CONTROL_CONFIRM) {
		if (lockout_ask (FALSE)) {
			fs_control_result_free (r);
			r = send_apply (TRUE);
		} else {
			asked_no = TRUE;
		}
	}

	if (asked_no || r->status == FS_CONTROL_CONFIRM) {
		fs_json_kv_bool (out, "applied", FALSE);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "error", "refused: the settings would block "
		                "an SSH session (pass --yes)");
		status = FS_EXIT_FAILURE;
	} else if (r->outcome == NULL) {
		fs_cli_error ("not applied: %s", r->error);
		fs_json_kv_bool (out, "applied", FALSE);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "error", r->error);
		status = r->status == FS_CONTROL_USAGE ? FS_EXIT_USAGE
		       : r->status == FS_CONTROL_NEED_ROOT ? FS_EXIT_NEED_ROOT
		       : FS_EXIT_FAILURE;
	} else {
		const FsApplyOutcome *o = r->outcome;

		fs_json_kv_bool (out, "applied", o->applied);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "held", o->held);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "hold_reason", o->hold_reason);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "result",
		                fs_util_apply_result_to_string ((int) o->result));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "error", r->error);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "under_journal", r->journal);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "rollback_attempted", o->rollback_attempted);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "rollback_verified", o->rollback_verified);
		g_string_append_c (out, ',');
		fs_json_key (out, "notes");
		fs_cli_append_lines_json (out, o->notes);

		if (o->held) {
			if (json == NULL)
				printf ("%sHeld:%s %s.  The firewall was left "
				        "untouched; the settings stay saved.\n",
				        fs_cli_amber (), fs_cli_reset (),
				        o->hold_reason);
		} else if (r->status == FS_CONTROL_OK) {
			if (json == NULL) {
				printf ("%sApplied%s the firewall settings under the "
				        "%s policy.\n", fs_cli_green (),
				        fs_cli_reset (),
				        r->journal ? "last applied" : "saved");
				fs_cli_print_notes (o->notes);
				if (!fs_cli.quiet)
					printf ("A boot now starts with these settings: "
					        "they are the last applied.\n");
			}
		} else {
			status = o->result == FS_APPLY_NO_PRIVILEGE
			       ? FS_EXIT_NEED_ROOT : FS_EXIT_FAILURE;
			fs_cli_error ("%s", r->error != NULL ? r->error
			              : fs_util_apply_result_to_string (
			                    (int) o->result));
			if (o->rollback_attempted && o->rollback_verified)
				fs_cli_hint ("the firewall was restored to the settings "
				             "last applied, and that restore was "
				             "verified");
			else if (o->rollback_attempted)
				fs_cli_error ("the rollback ALSO failed: the firewall "
				              "may be inconsistent -- check `stockfw "
				              "status'");
		}
	}
	if (r->lockout != NULL) {
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "lockout_cuts",
		                 fs_lockout_report_cuts (r->lockout));
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "lockout_confirmed", r->lockout_confirmed);
	}
	preview_json (out, &p);
	g_string_append_c (out, '}');
	if (json != NULL)
		g_string_append (json, out->str);

	g_string_free (out, TRUE);
	fs_control_result_free (r);
	preview_clear (&p);
	return status;
}

static gint
config_apply (gint argc, gchar **argv)
{
	gboolean yes = FALSE;
	gint status;

	for (gint i = 1; i < argc; i++) {
		if (fs_cli_is_option_at (argv, i) &&
		    (strcmp (argv[i], "--yes") == 0 ||
		     strcmp (argv[i], "-y") == 0)) {
			yes = TRUE;
		} else if (fs_cli_is_option_at (argv, i)) {
			fs_cli_unknown_option ("config", argv[i]);
			return FS_EXIT_USAGE;
		} else {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			fs_cli_hint ("config apply takes no setting: `config set NAME "
			             "VALUE --apply' saves and applies");
			return FS_EXIT_USAGE;
		}
	}
	if (geteuid () != 0)
		return fs_cli_need_root ("config apply");

	if (fs_cli.json) {
		GString *out = g_string_new (NULL);

		status = settings_apply (yes, out);
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		status = settings_apply (yes, NULL);
	}
	return status;
}

/* ---------------------------------------------------------- set, reset */

/* [ send_set ] -- settings.set: keys = values, and reset keys. */
static FsControlResult *
send_set (GPtrArray *keys, GPtrArray *values, GPtrArray *reset)
{
	FsControlActor actor = fs_control_actor_self ("cli");
	GVariantBuilder b;

	g_variant_builder_init (&b, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&b, "{sv}", "keys",
		g_variant_new_strv ((const gchar * const *) keys->pdata,
		                    keys->len));
	g_variant_builder_add (&b, "{sv}", "values",
		g_variant_new_strv ((const gchar * const *) values->pdata,
		                    values->len));
	g_variant_builder_add (&b, "{sv}", "reset",
		g_variant_new_strv ((const gchar * const *) reset->pdata,
		                    reset->len));
	return fs_control_do (&actor, "settings.set",
	                      g_variant_builder_end (&b));
}

static void
issues_json (GString *out, const gchar *key, const GPtrArray *issues)
{
	fs_json_key (out, key);
	g_string_append_c (out, '[');
	for (guint i = 0; issues != NULL && i < issues->len; i++) {
		const FsPrefsIssue *is = g_ptr_array_index (issues, i);
		const FsPrefSpec *spec = is->key != NULL ? fs_prefs_spec (is->key)
		                                         : NULL;
		gchar *name = spec != NULL ? setting_name (spec) : NULL;

		if (i > 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "name", name);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "reason", is->reason);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "topic", is->topic);
		g_string_append_c (out, '}');
		g_free (name);
	}
	g_string_append_c (out, ']');
}

/* [ write_settings ]
 * The body of `set', `reset' and `audit-only': one settings.set, then
 * what changed, what it means, and --apply.  `keys'/`values' and
 * `reset' hold the table's keys. */
static gint
write_settings (GPtrArray *keys, GPtrArray *values, GPtrArray *reset,
                gboolean apply, gboolean yes)
{
	FsControlResult *r;
	GPtrArray *before = g_ptr_array_new_with_free_func (g_free);
	GPtrArray *all = g_ptr_array_new ();
	GString *json = g_string_new ("{");
	gboolean firewall_changed = FALSE, history = FALSE, audit = FALSE;
	gboolean root_gui;
	gint status = FS_EXIT_OK;
	guint nchanged = 0;

	for (guint i = 0; i < keys->len; i++)
		g_ptr_array_add (all, g_ptr_array_index (keys, i));
	for (guint i = 0; i < reset->len; i++)
		g_ptr_array_add (all, g_ptr_array_index (reset, i));

	/* What the file holds now, to say what changed. */
	fs_prefs_load ();
	for (guint i = 0; i < all->len; i++)
		g_ptr_array_add (before,
		                 value_now (fs_prefs_spec (g_ptr_array_index (all,
		                                                              i))));

	r = send_set (keys, values, reset);

	if (r->status != FS_CONTROL_OK) {
		if (r->check != NULL && r->check->refusals->len > 0) {
			for (guint i = 0; i < r->check->refusals->len; i++) {
				const FsPrefsIssue *is =
					g_ptr_array_index (r->check->refusals, i);
				const FsPrefSpec *spec = is->key != NULL
				                       ? fs_prefs_spec (is->key) : NULL;
				gchar *name = spec != NULL ? setting_name (spec) : NULL;

				if (name != NULL)
					fs_cli_error ("%s: %s", name, is->reason);
				else
					fs_cli_error ("%s", is->reason);
				g_free (name);
			}
			{
				const FsPrefsIssue *first =
					g_ptr_array_index (r->check->refusals, 0);

				if (first->key != NULL &&
				    strcmp (first->key, FS_PREFS_FW_NAT) == 0)
					fs_cli_hint ("choose both devices in the same call: "
					             "`stockfw config set nat on ext_if "
					             "DEVICE int_if DEVICE' (`stockfw config "
					             "devices' lists them)");
				fs_cli_hint ("help topic: %s; nothing was saved",
				             first->topic);
			}
		} else {
			fs_cli_error ("not saved: %s", r->error != NULL ? r->error
			                                               : "failed");
		}
		status = r->status == FS_CONTROL_USAGE ? FS_EXIT_USAGE
		       : r->status == FS_CONTROL_NEED_ROOT ? FS_EXIT_NEED_ROOT
		       : FS_EXIT_FAILURE;
		if (fs_cli.json) {
			fs_json_kv_bool (json, "saved", FALSE);
			g_string_append_c (json, ',');
			fs_json_kv_str (json, "error", r->error);
			g_string_append_c (json, ',');
			issues_json (json, "refusals",
			             r->check != NULL ? r->check->refusals : NULL);
			g_string_append_c (json, '}');
			fs_cli_print_json (json);
		}
		goto out;
	}

	/* Saved. */
	root_gui = root_gui_running ();
	fs_json_kv_bool (json, "saved", TRUE);
	g_string_append_c (json, ',');
	fs_json_kv_str (json, "file", fs_prefs_path ());
	g_string_append (json, ",\"changes\":[");
	for (guint i = 0; i < all->len; i++) {
		const FsPrefSpec *spec = fs_prefs_spec (g_ptr_array_index (all, i));
		const gchar *was = g_ptr_array_index (before, i);
		gchar *now = value_now (spec);
		gchar *name = setting_name (spec);
		gboolean differs = g_strcmp0 (was, now) != 0;

		if (i > 0)
			g_string_append_c (json, ',');
		g_string_append_c (json, '{');
		fs_json_kv_str (json, "name", name);
		g_string_append_c (json, ',');
		value_json (json, "from", spec, was);
		g_string_append_c (json, ',');
		value_json (json, "to", spec, now);
		g_string_append_c (json, ',');
		fs_json_kv_bool (json, "changed", differs);
		g_string_append_c (json, '}');

		if (!fs_cli.json) {
			gchar *from = shown_value (spec, was);
			gchar *to = shown_value (spec, now);

			if (differs)
				printf ("%s: %s %s %s\n", name, from,
				        fs_cli_sym (FS_CLI_SYM_ARROW), to);
			else
				printf ("%s: %s (unchanged)\n", name, to);
			g_free (to);
			g_free (from);
		}
		if (differs) {
			nchanged++;
			firewall_changed |= spec->firewall;
			history |= g_str_has_prefix (spec->key,
			                             "/apps/stockfw/client/events/")
			        || strcmp (spec->key, FS_PREFS_SKIP_REDUNDANT) == 0
			        || strcmp (spec->key,
			                   FS_PREFS_SKIP_NOT_FOR_FIREWALL) == 0;
			audit |= strcmp (spec->key, FS_PREFS_AUDIT_ONLY) == 0;
		}
		g_free (name);
		g_free (now);
	}
	g_string_append (json, "],");
	issues_json (json, "warnings", r->check->warnings);
	g_string_append_c (json, ',');
	fs_json_kv_bool (json, "unreadable_kept", r->prefs_unreadable);
	g_string_append_c (json, ',');
	fs_json_kv_bool (json, "root_gui", root_gui);
	g_string_append_c (json, ',');
	fs_json_kv_bool (json, "pending", fs_apply_settings_pending ());

	fflush (stdout);
	for (guint i = 0; i < r->check->warnings->len; i++) {
		const FsPrefsIssue *is = g_ptr_array_index (r->check->warnings, i);
		const FsPrefSpec *spec = is->key != NULL ? fs_prefs_spec (is->key)
		                                         : NULL;
		gchar *name = spec != NULL ? setting_name (spec) : NULL;

		warn ("%s%s%s", name != NULL ? name : "", name != NULL ? ": " : "",
		      is->reason);
		g_free (name);
	}
	if (r->prefs_unreadable)
		unreadable_warning ();
	root_gui_warning (root_gui);

	if (!fs_cli.json && !fs_cli.quiet) {
		if (audit)
			printf (fs_apply_audit_only ()
			        ? "Audit-only mode is on: applies and starts are held "
			          "and written to the audit log; the firewall is not "
			          "touched.\n"
			        : "Audit-only mode is off: applies reach the firewall "
			          "again.\n");
		if (history)
			printf ("The event settings are read by the desktop app: "
			        "the event history is written only while it "
			        "runs.\n");
	}

	if (apply && (firewall_changed || fs_apply_settings_pending ())) {
		if (fs_cli.json) {
			g_string_append (json, ",\"apply\":");
			status = settings_apply (yes, json);
		} else {
			status = settings_apply (yes, NULL);
		}
	} else if (firewall_changed && !fs_cli.json && !fs_cli.quiet) {
		printf ("Saved, not applied: the firewall, and a boot, keep the "
		        "settings last applied until the next apply: `stockfw "
		        "config apply', or a policy apply (`stockfw apply', "
		        "--apply), which sends them too.\n");
	} else if (apply && !fs_cli.json && nchanged == 0) {
		printf ("Nothing to apply: the firewall already has the saved "
		        "settings.\n");
	}
	if (fs_cli.json) {
		g_string_append_c (json, '}');
		fs_cli_print_json (json);
	}

out:
	g_string_free (json, TRUE);
	g_ptr_array_unref (all);
	g_ptr_array_unref (before);
	fs_control_result_free (r);
	return status;
}

/* [ take_flags ] -- --apply and --yes/-y, from anywhere; anything else
 * that reads as an option is an error.  Plain words go to `words'. */
static gboolean
take_flags (gint argc, gchar **argv, gboolean *apply, gboolean *yes,
            GPtrArray *words)
{
	for (gint i = 1; i < argc; i++) {
		if (fs_cli_is_option_at (argv, i) && strcmp (argv[i], "--apply") == 0)
			*apply = TRUE;
		else if (fs_cli_is_option_at (argv, i) &&
		         (strcmp (argv[i], "--yes") == 0 ||
		          strcmp (argv[i], "-y") == 0))
			*yes = TRUE;
		else if (fs_cli_is_option_at (argv, i) && strcmp (argv[i], "-") != 0) {
			fs_cli_unknown_option ("config", argv[i]);
			return FALSE;
		} else
			g_ptr_array_add (words, argv[i]);
	}
	return TRUE;
}

static gint
config_set (gint argc, gchar **argv)
{
	gboolean apply = FALSE, yes = FALSE;
	GPtrArray *words = g_ptr_array_new ();
	GPtrArray *keys = g_ptr_array_new ();
	GPtrArray *values = g_ptr_array_new ();
	GPtrArray *reset = g_ptr_array_new ();
	gint status;

	if (!take_flags (argc, argv, &apply, &yes, words)) {
		status = FS_EXIT_USAGE;
		goto out;
	}
	if (words->len == 0 || words->len % 2 != 0) {
		fs_cli_error (words->len == 0 ? "config set needs a setting and "
		              "a value" : "config set takes NAME VALUE pairs: "
		              "one value is missing");
		fs_cli_hint ("stockfw config set NAME VALUE [NAME VALUE]... "
		             "[--apply]");
		status = FS_EXIT_USAGE;
		goto out;
	}
	for (guint i = 0; i < words->len; i += 2) {
		const gchar *word = g_ptr_array_index (words, i);
		const FsPrefSpec *spec = resolve (word);

		if (spec == NULL) {
			unknown_setting (word);
			status = FS_EXIT_USAGE;
			goto out;
		}
		g_ptr_array_add (keys, (gpointer) spec->key);
		g_ptr_array_add (values, g_ptr_array_index (words, i + 1));
	}
	if (geteuid () != 0) {
		status = fs_cli_need_root ("config set");
		fs_cli_hint ("the firewall, the boot unit and `apply' run as "
		             "root read root's copy of the settings, and only "
		             "root writes it");
		goto out;
	}
	status = write_settings (keys, values, reset, apply, yes);

out:
	g_ptr_array_unref (words);
	g_ptr_array_unref (keys);
	g_ptr_array_unref (values);
	g_ptr_array_unref (reset);
	return status;
}

static gint
config_reset (gint argc, gchar **argv)
{
	gboolean apply = FALSE, yes = FALSE;
	GPtrArray *words = g_ptr_array_new ();
	GPtrArray *keys = g_ptr_array_new ();
	GPtrArray *values = g_ptr_array_new ();
	GPtrArray *reset = g_ptr_array_new ();
	gint status;

	if (!take_flags (argc, argv, &apply, &yes, words)) {
		status = FS_EXIT_USAGE;
		goto out;
	}
	if (words->len == 0) {
		fs_cli_error ("config reset needs a setting");
		fs_cli_hint ("stockfw config reset NAME... [--apply]");
		status = FS_EXIT_USAGE;
		goto out;
	}
	for (guint i = 0; i < words->len; i++) {
		const FsPrefSpec *spec = resolve (g_ptr_array_index (words, i));

		if (spec == NULL) {
			unknown_setting (g_ptr_array_index (words, i));
			status = FS_EXIT_USAGE;
			goto out;
		}
		g_ptr_array_add (reset, (gpointer) spec->key);
	}
	if (geteuid () != 0) {
		status = fs_cli_need_root ("config reset");
		goto out;
	}
	status = write_settings (keys, values, reset, apply, yes);

out:
	g_ptr_array_unref (words);
	g_ptr_array_unref (keys);
	g_ptr_array_unref (values);
	g_ptr_array_unref (reset);
	return status;
}

/* [ config_audit_only ] -- `config audit-only [on|off]' (J13, B2): the
 * same as `config set audit-only on|off'; with no word, the state. */
static gint
config_audit_only (gint argc, gchar **argv)
{
	GPtrArray *keys, *values, *reset;
	gint status;

	if (argc == 1) {
		if (fs_cli.json) {
			GString *out = g_string_new ("{");

			fs_json_kv_bool (out, "audit_only", fs_apply_audit_only ());
			g_string_append_c (out, '}');
			fs_cli_print_json (out);
			g_string_free (out, TRUE);
		} else {
			printf ("%s\n", fs_apply_audit_only () ? "on" : "off");
		}
		return FS_EXIT_OK;
	}
	if (argc != 2 || fs_cli_is_option_at (argv, 1)) {
		fs_cli_error ("config audit-only takes on or off");
		return FS_EXIT_USAGE;
	}
	if (geteuid () != 0)
		return fs_cli_need_root ("config audit-only");

	keys = g_ptr_array_new ();
	values = g_ptr_array_new ();
	reset = g_ptr_array_new ();
	g_ptr_array_add (keys, (gpointer) FS_PREFS_AUDIT_ONLY);
	g_ptr_array_add (values, argv[1]);
	status = write_settings (keys, values, reset, FALSE, FALSE);
	g_ptr_array_unref (keys);
	g_ptr_array_unref (values);
	g_ptr_array_unref (reset);
	return status;
}

/* ------------------------------------------------------------ command */

static gint
fs_cli_cmd_config (gint argc, gchar **argv)
{
	const gchar *sub = argc > 1 && !fs_cli_is_option_at (argv, 1)
	                 ? argv[1] : "list";
	gint shift = argc > 1 && !fs_cli_is_option_at (argv, 1) ? 1 : 0;
	static const gchar *subs[] = { "list", "get", "set", "reset", "apply",
	                               "devices", "audit-only" };

	if (strcmp (sub, "list") == 0)
		return config_list (argc - shift, argv + shift);
	if (strcmp (sub, "get") == 0)
		return config_get (argc - 1, argv + 1);
	if (strcmp (sub, "set") == 0)
		return config_set (argc - 1, argv + 1);
	if (strcmp (sub, "reset") == 0)
		return config_reset (argc - 1, argv + 1);
	if (strcmp (sub, "apply") == 0)
		return config_apply (argc - 1, argv + 1);
	if (strcmp (sub, "devices") == 0)
		return config_devices (argc - 1, argv + 1);
	if (strcmp (sub, "audit-only") == 0)
		return config_audit_only (argc - 1, argv + 1);

	{
		const gchar *best = fs_cli_suggest (sub, subs, G_N_ELEMENTS (subs));

		if (best != NULL)
			fs_cli_error ("unknown config action: %s (did you mean %s?)",
			              sub, best);
		else
			fs_cli_error ("unknown config action: %s", sub);
		fs_cli_hint ("config list | get | set | reset | apply | devices "
		             "| audit-only");
	}
	return FS_EXIT_USAGE;
}

static const FsCliOption config_opts[] = {
	{ "--firewall", FALSE, "list"  },
	{ "--changed",  FALSE, "list"  },
	{ "--apply",    FALSE, "set"   },
	{ "--apply",    FALSE, "reset" },
	{ "--yes",      FALSE, NULL    },
	{ "-y",         FALSE, NULL    },
	{ NULL, FALSE, NULL }
};

const FsCliCommandDef fs_cli_config_commands[] = {
	{ "config", fs_cli_cmd_config,
"Usage: stockfw config [list] [--firewall] [--changed]\n"
"       stockfw config get NAME\n"
"       stockfw config set NAME VALUE [NAME VALUE]... [--apply] [--yes]\n"
"       stockfw config reset NAME... [--apply] [--yes]\n"
"       stockfw config apply [--yes]\n"
"       stockfw config devices\n"
"       stockfw config audit-only [on|off]\n"
"\n"
"The settings of the desktop app's Preferences window.  `list' shows\n"
"each one this firewall acts on, its value, its default and, for a\n"
"firewall setting, the value last applied (--firewall: those only;\n"
"--changed: the ones not at their default).  `get' prints one value.\n"
"NAME is the name `list' shows (firewall.icmp.echo_request), the key\n"
"(firewall/nat), or its last part when that is unique (nat, ext_if,\n"
"echo_request); audit-only and icmp are names too.  A switch takes\n"
"on/off (also true/false, yes/no, 1/0); firewall.deny_packets takes\n"
"drop or reject, firewall.restrictive_outbound block or allow; a device\n"
"is a name from `config devices', or '' for none.\n"
"\n"
"`set' and `reset' write root's copy of the settings, the one the\n"
"firewall, the boot unit and `apply' run as root read; they need root.\n"
"They follow the Preferences window's rules and refuse with its\n"
"reasons: connection sharing (nat) needs both devices, which can be set\n"
"in the same call; the broadcast and reserved-address blocks need the\n"
"Internet device; an ICMP type needs ICMP filtering on; the history\n"
"limits need the history on.  Only the settings named are written: two\n"
"`set' calls at once each keep their own.  A file that cannot be read\n"
"is kept as stockfw.conf.bad and the defaults are written with the\n"
"change.\n"
"\n"
"A firewall setting that is saved is not in force until it is applied:\n"
"the firewall and a boot (`stockfw start') keep the settings last\n"
"applied.  The next apply of either kind sends them: `config apply',\n"
"and also a policy apply (`stockfw apply', `policy ... --apply'), which\n"
"says so.  `config apply', or --apply, shows what changes and how many\n"
"firewall rules that adds and removes, checks that your SSH session\n"
"stays open (--yes to go on anyway), and applies the settings under the\n"
"policy last applied: policy changes saved and not applied stay off.\n"
"With no policy applied before, the saved policy goes out with them.\n"
"Audit-only mode holds the apply (exit 0, recorded in the audit log).\n"
"\n"
"`audit-only on' turns on audit-only testing mode: applies and starts\n"
"are held and written to the audit log, and the firewall is not\n"
"touched.  The change itself is written to the audit log too.\n"
"\n"
"The event settings (filter.*, events.*) are read by the desktop\n"
"app: the event history is written only while it runs.  A StockFW\n"
"window running as root keeps its own copy of the settings and writes\n"
"it back when it saves: `set' warns when one is running.\n"
"\n"
"Exit status: 0 done (or held), 1 failed, 2 usage (an unknown setting,\n"
"a value it does not take, a dependency the window would refuse;\n"
"nothing is written), 3 needs root.\n",
	  config_opts, NULL },

	{ NULL, NULL, NULL, NULL, NULL }
};
