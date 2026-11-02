/*---[ fs-json.c ]-------------------------------------------------------
 * The writer described in fs-json.h.
 *--------------------------------------------------------------------*/
#include "core/fs-json.h"

void
fs_json_string (GString *out, const gchar *s)
{
	gchar *valid;

	if (s == NULL) {
		g_string_append (out, "null");
		return;
	}

	/* A log field is bytes, not promised UTF-8; JSON must be. */
	valid = g_utf8_make_valid (s, -1);

	g_string_append_c (out, '"');

	for (const guchar *p = (const guchar *) valid; *p != '\0'; p++) {
		switch (*p) {
		case '"':  g_string_append (out, "\\\""); break;
		case '\\': g_string_append (out, "\\\\"); break;
		case '\b': g_string_append (out, "\\b");  break;
		case '\f': g_string_append (out, "\\f");  break;
		case '\n': g_string_append (out, "\\n");  break;
		case '\r': g_string_append (out, "\\r");  break;
		case '\t': g_string_append (out, "\\t");  break;
		case '<': case '>': case '&':
			g_string_append_printf (out, "\\u%04x", *p);
			break;
		default:
			if (*p < 0x20 || *p == 0x7f)
				g_string_append_printf (out, "\\u%04x", *p);
			else
				g_string_append_c (out, (gchar) *p);
		}
	}

	g_string_append_c (out, '"');
	g_free (valid);
}

void
fs_json_key (GString *out, const gchar *key)
{
	fs_json_string (out, key);
	g_string_append_c (out, ':');
}

void
fs_json_kv_str (GString *out, const gchar *key, const gchar *value)
{
	fs_json_key (out, key);
	fs_json_string (out, value);
}

void
fs_json_kv_int (GString *out, const gchar *key, gint64 value)
{
	fs_json_key (out, key);
	g_string_append_printf (out, "%" G_GINT64_FORMAT, value);
}

void
fs_json_kv_uint (GString *out, const gchar *key, guint64 value)
{
	fs_json_key (out, key);
	g_string_append_printf (out, "%" G_GUINT64_FORMAT, value);
}

void
fs_json_kv_bool (GString *out, const gchar *key, gboolean value)
{
	fs_json_key (out, key);
	g_string_append (out, value ? "true" : "false");
}
