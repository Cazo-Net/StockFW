/*---[ fs-changelog.c ]--------------------------------------------------
 * "Changes made by the Copilot" on disk.  See fs-changelog.h.
 *
 * The reader takes only what the writer writes: one flat JSON object
 * per line whose values are strings, whole numbers, null, true or
 * false.  Anything else makes the line unreadable, and it is skipped.
 *--------------------------------------------------------------------*/
#include "control/fs-changelog.h"
#include "control/fs-control.h"
#include "core/fs-json.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void
fs_change_free (FsChange *c)
{
	if (c == NULL)
		return;
	g_free (c->label);
	g_free (c->source);
	g_free (c->csv);
	fs_health_undo_free (c->undo);
	g_free (c);
}

const gchar *
fs_change_kind_name (FsChangeKind kind)
{
	return kind == FS_CHANGE_HEALTH_FIX ? "health-fix" : "block-rule";
}

gchar *
fs_changelog_path (void)
{
	const gchar *env = g_getenv ("STOCKFW_CHANGELOG_FILE");

	if (env != NULL && *env != '\0')
		return g_strdup (env);
	return g_build_filename (g_get_user_config_dir (), "stockfw",
	                         "copilot-changes.jsonl", NULL);
}

/* ------------------------------------------------------------ reader */

/* A JSON string at *p (just after the opening quote) up to its closing
 * quote; *p moves past it.  NULL when it is not one. */
static gchar *
read_string (const gchar **p)
{
	GString *s = g_string_new (NULL);
	const gchar *q = *p;

	while (*q != '\0' && *q != '"') {
		if ((guchar) *q < 0x20)
			goto bad;
		if (*q != '\\') {
			g_string_append_c (s, *q++);
			continue;
		}
		q++;
		switch (*q) {
		case '"':  g_string_append_c (s, '"');  break;
		case '\\': g_string_append_c (s, '\\'); break;
		case '/':  g_string_append_c (s, '/');  break;
		case 'b':  g_string_append_c (s, '\b'); break;
		case 'f':  g_string_append_c (s, '\f'); break;
		case 'n':  g_string_append_c (s, '\n'); break;
		case 'r':  g_string_append_c (s, '\r'); break;
		case 't':  g_string_append_c (s, '\t'); break;
		case 'u': {
			gunichar c = 0;

			for (gint k = 1; k <= 4; k++) {
				if (!g_ascii_isxdigit (q[k]))
					goto bad;
				c = c * 16 + (gunichar) g_ascii_xdigit_value (q[k]);
			}
			q += 4;
			/* A surrogate pair: the low half follows. */
			if (c >= 0xD800 && c <= 0xDBFF && q[1] == '\\' &&
			    q[2] == 'u') {
				gunichar lo = 0;

				for (gint k = 3; k <= 6; k++) {
					if (!g_ascii_isxdigit (q[k]))
						goto bad;
					lo = lo * 16 +
					     (gunichar) g_ascii_xdigit_value (q[k]);
				}
				if (lo < 0xDC00 || lo > 0xDFFF)
					goto bad;
				c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
				q += 6;
			}
			if (c == 0 || (c >= 0xD800 && c <= 0xDFFF))
				goto bad;
			g_string_append_unichar (s, c);
			break;
		}
		default:
			goto bad;
		}
		q++;
	}
	if (*q != '"')
		goto bad;
	*p = q + 1;
	return g_string_free (s, FALSE);
bad:
	g_string_free (s, TRUE);
	return NULL;
}

/* One line as key -> value (a string; NULL for null).  Whole numbers,
 * true and false come as their text.  NULL when the line does not
 * read. */
static GHashTable *
read_line (const gchar *line)
{
	GHashTable *t = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                       g_free, g_free);
	const gchar *p = line;

	while (g_ascii_isspace (*p))
		p++;
	if (*p++ != '{')
		goto bad;
	for (;;) {
		gchar *key, *value = NULL;

		while (g_ascii_isspace (*p))
			p++;
		if (*p == '}' && g_hash_table_size (t) == 0) {
			p++;
			break;
		}
		if (*p++ != '"' || (key = read_string (&p)) == NULL)
			goto bad;
		while (g_ascii_isspace (*p))
			p++;
		if (*p++ != ':') {
			g_free (key);
			goto bad;
		}
		while (g_ascii_isspace (*p))
			p++;
		if (*p == '"') {
			p++;
			value = read_string (&p);
			if (value == NULL) {
				g_free (key);
				goto bad;
			}
		} else if (strncmp (p, "null", 4) == 0) {
			p += 4;
		} else if (strncmp (p, "true", 4) == 0) {
			value = g_strdup ("true");
			p += 4;
		} else if (strncmp (p, "false", 5) == 0) {
			value = g_strdup ("false");
			p += 5;
		} else if (*p == '-' || g_ascii_isdigit (*p)) {
			const gchar *start = p;

			if (*p == '-')
				p++;
			if (!g_ascii_isdigit (*p)) {
				g_free (key);
				goto bad;
			}
			while (g_ascii_isdigit (*p))
				p++;
			value = g_strndup (start, (gsize) (p - start));
		} else {
			g_free (key);
			goto bad;
		}
		if (g_hash_table_contains (t, key)) {
			g_free (key);
			g_free (value);
			goto bad;
		}
		g_hash_table_insert (t, key, value);
		while (g_ascii_isspace (*p))
			p++;
		if (*p == ',') {
			p++;
			continue;
		}
		if (*p++ != '}')
			goto bad;
		break;
	}
	while (g_ascii_isspace (*p))
		p++;
	if (*p != '\0')
		goto bad;
	return t;
bad:
	g_hash_table_unref (t);
	return NULL;
}

static const gchar *
get (GHashTable *t, const gchar *key)
{
	return g_hash_table_lookup (t, key);
}

static gboolean
get_int (GHashTable *t, const gchar *key, gint64 *out)
{
	const gchar *v = get (t, key);
	gchar *end = NULL;

	if (v == NULL || *v == '\0')
		return FALSE;
	errno = 0;
	*out = g_ascii_strtoll (v, &end, 10);
	return errno == 0 && end != NULL && *end == '\0';
}

/* One "health-fix" or "block-rule" line as a change; NULL when a field
 * it needs is missing or wrong. */
static FsChange *
change_from (GHashTable *t)
{
	const gchar *type = get (t, "type");
	FsChange *c;
	gint64 id = 0, at = 0, index = 0;
	FsRuleKind kind;

	if (!get_int (t, "id", &id) || id <= 0 || id > G_MAXUINT ||
	    !get_int (t, "at", &at) ||
	    !fs_control_kind_parse (get (t, "kind"), &kind))
		return NULL;
	c = g_new0 (FsChange, 1);
	c->id = (guint) id;
	c->at = at;
	c->rule_kind = kind;
	c->label = g_strdup (get (t, "label"));
	c->source = g_strdup (get (t, "source"));

	if (g_strcmp0 (type, "block-rule") == 0) {
		c->kind = FS_CHANGE_BLOCK_RULE;
		c->csv = g_strdup (get (t, "csv"));
		if (c->csv != NULL)
			return c;
	} else if (g_strcmp0 (type, "health-fix") == 0 &&
	           get_int (t, "index", &index) && index >= 0 &&
	           index <= G_MAXINT && get (t, "before") != NULL &&
	           (g_strcmp0 (get (t, "fix"), "remove") == 0 ||
	            (g_strcmp0 (get (t, "fix"), "replace") == 0 &&
	             get (t, "after") != NULL))) {
		FsHealthUndo *u = g_new0 (FsHealthUndo, 1);

		c->kind = FS_CHANGE_HEALTH_FIX;
		u->kind = g_strcmp0 (get (t, "fix"), "remove") == 0
		          ? FS_HEALTH_FIX_REMOVE : FS_HEALTH_FIX_REPLACE;
		u->rule_kind = kind;
		u->index = (gint) index;
		u->before_csv = g_strdup (get (t, "before"));
		u->after_csv = g_strdup (get (t, "after"));
		u->anchor_csv = g_strdup (get (t, "anchor"));
		u->label = g_strdup (c->label);
		c->undo = u;
		return c;
	}
	fs_change_free (c);
	return NULL;
}

/* Every line of the file: changes (with undone_at) and the ids of the
 * "undone" lines, which compaction keeps with their change. */
static GPtrArray *
read_all (const gchar *path, guint *bad, gboolean *exists, GError **error)
{
	gchar *text = NULL;
	gchar **lines;
	GPtrArray *out;
	GError *e = NULL;

	if (bad != NULL)
		*bad = 0;
	*exists = TRUE;
	if (!g_file_get_contents (path, &text, NULL, &e)) {
		if (g_error_matches (e, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
			g_error_free (e);
			*exists = FALSE;
			return g_ptr_array_new_with_free_func (
				(GDestroyNotify) fs_change_free);
		}
		g_propagate_error (error, e);
		return NULL;
	}

	out = g_ptr_array_new_with_free_func ((GDestroyNotify) fs_change_free);
	lines = g_strsplit (text, "\n", -1);
	for (guint i = 0; lines[i] != NULL; i++) {
		GHashTable *t;
		gint64 id = 0, at = 0;

		if (*g_strstrip (lines[i]) == '\0')
			continue;
		t = read_line (lines[i]);
		if (t == NULL || g_strcmp0 (get (t, "v"), "1") != 0) {
			if (bad != NULL)
				(*bad)++;
		} else if (g_strcmp0 (get (t, "type"), "undone") == 0) {
			/* An undo marks the change it names, which comes
			 * before it. */
			if (!get_int (t, "id", &id) || !get_int (t, "at", &at) ||
			    id <= 0 || id > G_MAXUINT || at <= 0) {
				if (bad != NULL)
					(*bad)++;
			} else
				for (guint k = 0; k < out->len; k++) {
					FsChange *c = g_ptr_array_index (out, k);

					if (c->id == (guint) id && c->undone_at == 0)
						c->undone_at = at;
				}
		} else {
			FsChange *c = change_from (t);

			if (c != NULL)
				g_ptr_array_add (out, c);
			else if (bad != NULL)
				(*bad)++;
		}
		if (t != NULL)
			g_hash_table_unref (t);
	}
	g_strfreev (lines);
	g_free (text);
	return out;
}

GPtrArray *
fs_changelog_read (guint *bad, GError **error)
{
	gchar *path = fs_changelog_path ();
	gboolean exists;
	GPtrArray *all = read_all (path, bad, &exists, error);

	g_free (path);
	return all;
}

FsChange *
fs_changelog_find (guint id, GError **error)
{
	GPtrArray *all = fs_changelog_read (NULL, error);
	FsChange *found = NULL;

	if (all == NULL)
		return NULL;
	for (guint i = 0; i < all->len && found == NULL; i++) {
		FsChange *c = g_ptr_array_index (all, i);

		if (c->id == id)
			found = g_ptr_array_steal_index (all, i);
	}
	g_ptr_array_unref (all);
	return found;
}

/* ------------------------------------------------------------ writer */

static void
line_start (GString *s, const gchar *type, guint id, const gchar *source)
{
	g_string_append_c (s, '{');
	fs_json_kv_int (s, "v", 1);
	g_string_append_c (s, ',');
	fs_json_kv_str (s, "type", type);
	g_string_append_c (s, ',');
	fs_json_kv_uint (s, "id", id);
	g_string_append_c (s, ',');
	fs_json_kv_int (s, "at", g_get_real_time () / G_USEC_PER_SEC);
	g_string_append_c (s, ',');
	fs_json_kv_str (s, "source", source != NULL ? source : "cli");
}

static void
change_line (GString *s, const FsChange *c)
{
	const gchar *kind = fs_control_kind_names ()[c->rule_kind];

	g_string_append_c (s, '{');
	fs_json_kv_int (s, "v", 1);
	g_string_append_c (s, ',');
	fs_json_kv_str (s, "type", fs_change_kind_name (c->kind));
	g_string_append_c (s, ',');
	fs_json_kv_uint (s, "id", c->id);
	g_string_append_c (s, ',');
	fs_json_kv_int (s, "at", c->at);
	g_string_append_c (s, ',');
	fs_json_kv_str (s, "source", c->source);
	g_string_append_c (s, ',');
	fs_json_kv_str (s, "label", c->label);
	g_string_append_c (s, ',');
	fs_json_kv_str (s, "kind", kind);
	g_string_append_c (s, ',');
	if (c->kind == FS_CHANGE_BLOCK_RULE) {
		fs_json_kv_str (s, "csv", c->csv);
	} else {
		fs_json_kv_str (s, "fix", c->undo->kind == FS_HEALTH_FIX_REMOVE
		                          ? "remove" : "replace");
		g_string_append_c (s, ',');
		fs_json_kv_int (s, "index", c->undo->index);
		g_string_append_c (s, ',');
		fs_json_kv_str (s, "before", c->undo->before_csv);
		g_string_append_c (s, ',');
		fs_json_kv_str (s, "after", c->undo->after_csv);
		g_string_append_c (s, ',');
		fs_json_kv_str (s, "anchor", c->undo->anchor_csv);
	}
	g_string_append (s, "}\n");
}

/* Appends `text' (whole lines) to the file, made 0600 in a 0700 folder
 * when missing. */
static gboolean
append (const gchar *path, const gchar *text, GError **error)
{
	gchar *dir = g_path_get_dirname (path);
	gsize len = strlen (text), done = 0;
	gint fd;

	if (g_mkdir_with_parents (dir, 0700) != 0) {
		gint e = errno;

		g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (e),
		             "could not make %s: %s", dir, g_strerror (e));
		g_free (dir);
		return FALSE;
	}
	g_free (dir);
	fd = open (path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
	           0600);
	if (fd < 0) {
		gint e = errno;

		g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (e),
		             "could not open %s: %s", path, g_strerror (e));
		return FALSE;
	}
	while (done < len) {
		ssize_t n = write (fd, text + done, len - done);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			gint e = errno;

			g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (e),
			             "could not write %s: %s", path, g_strerror (e));
			close (fd);
			return FALSE;
		}
		done += (gsize) n;
	}
	if (fsync (fd) != 0 || close (fd) != 0) {
		gint e = errno;

		g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (e),
		             "could not write %s: %s", path, g_strerror (e));
		return FALSE;
	}
	return TRUE;
}

/* More than FS_CHANGELOG_MAX changes: the file is written again with
 * the newest of them and their "undone" lines. */
static void
compact (const gchar *path, GPtrArray *all)
{
	GString *s;
	guint from;

	if (all->len <= FS_CHANGELOG_MAX)
		return;
	from = all->len - FS_CHANGELOG_MAX;
	s = g_string_new (NULL);
	for (guint i = from; i < all->len; i++) {
		const FsChange *c = g_ptr_array_index (all, i);

		change_line (s, c);
		if (c->undone_at != 0) {
			g_string_append_c (s, '{');
			fs_json_kv_int (s, "v", 1);
			g_string_append (s, ",\"type\":\"undone\",");
			fs_json_kv_uint (s, "id", c->id);
			g_string_append_c (s, ',');
			fs_json_kv_int (s, "at", c->undone_at);
			g_string_append_c (s, ',');
			fs_json_kv_str (s, "source", c->source);
			g_string_append (s, "}\n");
		}
	}
	/* g_file_set_contents keeps the mode of the file it replaces only
	 * on some systems: set it again. */
	if (g_file_set_contents (path, s->str, (gssize) s->len, NULL))
		chmod (path, 0600);
	g_string_free (s, TRUE);
}

static guint
add_change (FsChange *c, GError **error)
{
	gchar *path = fs_changelog_path ();
	gboolean exists;
	GPtrArray *all = read_all (path, NULL, &exists, error);
	GString *s;
	guint id = 0;

	if (all == NULL) {
		g_free (path);
		return 0;
	}
	for (guint i = 0; i < all->len; i++) {
		const FsChange *o = g_ptr_array_index (all, i);

		c->id = MAX (c->id, o->id);
	}
	c->id++;
	c->at = g_get_real_time () / G_USEC_PER_SEC;
	s = g_string_new (NULL);
	change_line (s, c);
	if (append (path, s->str, error)) {
		id = c->id;
		g_ptr_array_unref (all);
		all = read_all (path, NULL, &exists, NULL);
		if (all != NULL)
			compact (path, all);
	}
	if (all != NULL)
		g_ptr_array_unref (all);
	g_string_free (s, TRUE);
	g_free (path);
	return id;
}

guint
fs_changelog_add_health_fix (const FsHealthUndo *undo, const gchar *source,
                             GError **error)
{
	FsChange c = { 0 };
	FsHealthUndo u;
	gchar *label;
	guint id;

	g_return_val_if_fail (undo != NULL, 0);
	u = *undo;
	label = g_strdup_printf ("Policy fix: %s",
	                         undo->label != NULL ? undo->label : "");
	c.kind = FS_CHANGE_HEALTH_FIX;
	c.rule_kind = undo->rule_kind;
	c.label = label;
	c.source = (gchar *) (source != NULL ? source : "cli");
	c.undo = &u;
	id = add_change (&c, error);
	g_free (label);
	return id;
}

guint
fs_changelog_add_block_rule (FsRuleKind kind, const gchar *csv,
                             const gchar *source, GError **error)
{
	FsChange c = { 0 };
	gchar *label = g_strdup_printf ("Block rule added: %s", csv);
	guint id;

	c.kind = FS_CHANGE_BLOCK_RULE;
	c.rule_kind = kind;
	c.csv = (gchar *) csv;
	c.label = label;
	c.source = (gchar *) (source != NULL ? source : "cli");
	id = add_change (&c, error);
	g_free (label);
	return id;
}

gboolean
fs_changelog_mark_undone (guint id, const gchar *source, GError **error)
{
	gchar *path = fs_changelog_path ();
	GString *s = g_string_new (NULL);
	gboolean ok;

	line_start (s, "undone", id, source);
	g_string_append (s, "}\n");
	ok = append (path, s->str, error);
	g_string_free (s, TRUE);
	g_free (path);
	return ok;
}
