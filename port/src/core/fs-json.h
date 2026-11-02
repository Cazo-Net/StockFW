/*---[ fs-json.h ]-------------------------------------------------------
 * The smallest JSON writer that is still correct.
 *
 * The CLI's --json output and the local dashboard's API both put
 * strings that came off the wire (hostnames, service names, rule
 * comments, kernel-log fields) into JSON.  Every one goes through
 * fs_json_string, which escapes quotes, backslashes and control
 * characters, repairs invalid UTF-8 and also escapes '<', '>' and '&'
 * so a value can never close a <script> block it is embedded in.
 *--------------------------------------------------------------------*/
#ifndef FS_JSON_H
#define FS_JSON_H

#include <glib.h>

G_BEGIN_DECLS

/* Append s as a JSON string literal; NULL appends null. */
void fs_json_string (GString *out, const gchar *s);

/* Append "key": (callers write the separating commas). */
void fs_json_key (GString *out, const gchar *key);

/* Append "key":"value" / "key":number / "key":true|false. */
void fs_json_kv_str  (GString *out, const gchar *key, const gchar *value);
void fs_json_kv_int  (GString *out, const gchar *key, gint64 value);
void fs_json_kv_uint (GString *out, const gchar *key, guint64 value);
void fs_json_kv_bool (GString *out, const gchar *key, gboolean value);

G_END_DECLS

#endif /* FS_JSON_H */
