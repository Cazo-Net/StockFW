/*---[ fs-util.c ]-------------------------------------------------------
 * Small helpers with no home of their own.
 *--------------------------------------------------------------------*/

#include "core/fs-util.h"
#include "core/fs-backend.h"

#include <glib/gstdio.h>
#include <gio/gio.h>

#include "core/fs-rules.h"

#ifdef G_OS_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* [ fs_util_is_valid_port ]
 * Accepts a single port ("80") or a range ("1024:65535"), matching what
 * the original editor accepted. */
gboolean
fs_util_is_valid_port (const gchar *port)
{
	const gchar *colon;
	gchar *endptr = NULL;
	gint first, last;

	if (port == NULL || *port == '\0')
		return FALSE;

	colon = strchr (port, ':');

	if (colon == NULL) {
		first = (gint) strtol (port, &endptr, 10);

		if (endptr == port || *endptr != '\0')
			return FALSE;

		return (first >= 0 && first <= 65535);
	}

	if (colon != port && *(colon + 1) != '\0') {
		first = (gint) strtol (port, &endptr, 10);

		if (endptr != colon)
			return FALSE;

		last = (gint) strtol (colon + 1, &endptr, 10);

		if (*endptr != '\0')
			return FALSE;

		if (first < 0 || last > 65535 || first > last)
			return FALSE;

		return TRUE;
	}

	return FALSE;
}

/* [ fs_util_is_valid_host ]
 * Accepts a dotted quad, a hostname, or the "*" wildcard. */
gboolean
fs_util_is_valid_host (const gchar *host)
{
	const gchar *p;
	gboolean digits_only = TRUE;
	gchar **parts;
	gsize n_parts;
	gsize i;
	gboolean valid = TRUE;

	if (host == NULL || *host == '\0')
		return FALSE;

	if (strcmp (host, "*") == 0)
		return TRUE;

	for (p = host; *p != '\0'; p++) {
		if (*p != '.' && !g_ascii_isdigit (*p)) {
			digits_only = FALSE;
			break;
		}
	}

	if (!digits_only) {
		/* Hostname: dot separated labels of letters, digits, - and _ */
		if (host[0] == '.' || host[strlen (host) - 1] == '.')
			return FALSE;

		if (strstr (host, "..") != NULL)
			return FALSE;

		for (p = host; *p != '\0'; p++) {
			if (!g_ascii_isalnum (*p) && *p != '.' &&
			    *p != '-' && *p != '_')
				return FALSE;
		}

		return TRUE;
	}

	/* Dotted quad: exactly four octets in the range 0-255. */
	parts = g_strsplit (host, ".", -1);
	n_parts = g_strv_length (parts);

	if (n_parts != 4)
		valid = FALSE;

	for (i = 0; valid && i < n_parts; i++) {
		const gchar *octet = parts[i];

		if (*octet == '\0' || strlen (octet) > 3) {
			valid = FALSE;
			break;
		}

		for (p = octet; *p != '\0'; p++) {
			if (!g_ascii_isdigit (*p)) {
				valid = FALSE;
				break;
			}
		}

		if (!valid)
			break;

		if (g_ascii_strtoll (octet, NULL, 10) > 255)
			valid = FALSE;
	}

	g_strfreev (parts);

	return valid;
}

/* [ fs_util_target_is_anyone ] */
gboolean
fs_util_target_is_anyone (const gchar *target)
{
	if (target == NULL || *target == '\0')
		return TRUE;

	return (g_ascii_strcasecmp (target, FS_TARGET_ANY) == 0 ||
	        g_strcmp0 (target, "*") == 0 ||
	        g_ascii_strcasecmp (target, "any") == 0 ||
	        g_ascii_strcasecmp (target, "all") == 0);
}

/* [ fs_util_get_text_between ] */
gchar *
fs_util_get_text_between (const gchar *string,
                          const gchar *marker1,
                          const gchar *marker2)
{
	const gchar *start, *end;

	if (string == NULL || marker1 == NULL || marker2 == NULL)
		return NULL;

	start = strstr (string, marker1);

	if (start == NULL)
		return NULL;

	start += strlen (marker1);

	end = strstr (start, marker2);

	if (end == NULL)
		return NULL;

	return g_strndup (start, (gsize) (end - start));
}

/* [ fs_util_lookup_ip ]
 * Reverse DNS.  Note that g_resolver_lookup_by_name() blocks, so this
 * must not be called from the GTK main loop without a worker thread. */
gchar *
fs_util_lookup_ip (const gchar *ip)
{
	struct sockaddr_storage sa;
	gchar host[NI_MAXHOST];

	if (ip == NULL || *ip == '\0')
		return NULL;

	memset (&sa, 0, sizeof (sa));

	if (g_inet_address_new_from_string (ip) == NULL)
		return g_strdup (ip);

	/* getnameinfo() is the only reverse lookup available on both
	 * platforms; GResolver has no reverse equivalent. */
	if (inet_pton (AF_INET, ip, &(((struct sockaddr_in *) &sa)->sin_addr)) == 1) {
		sa.ss_family = AF_INET;
	} else if (inet_pton (AF_INET6, ip,
	                      &(((struct sockaddr_in6 *) &sa)->sin6_addr)) == 1) {
		sa.ss_family = AF_INET6;
	} else {
		return g_strdup (ip);
	}

	if (getnameinfo ((struct sockaddr *) &sa, sizeof (sa),
	                 host, sizeof (host), NULL, 0,
	                 NI_NAMEREQD) != 0)
		return g_strdup (ip);

	return g_strdup (host);
}

gboolean
fs_util_ensure_parent_dir (const gchar *path)
{
	gchar *dir;
	gboolean ok;

	if (path == NULL)
		return FALSE;

	dir = g_path_get_dirname (path);

	if (dir == NULL)
		return FALSE;

	ok = (g_mkdir_with_parents (dir, 0755) == 0);

	g_free (dir);

	return ok;
}

gboolean
fs_util_append_to_file (const gchar *path, const gchar *data,
                        gboolean newline)
{
	FILE *fp;

	if (path == NULL || data == NULL)
		return FALSE;

	if (!fs_util_ensure_parent_dir (path))
		return FALSE;

	fp = fopen (path, "a");

	if (fp == NULL)
		return FALSE;

	fputs (data, fp);

	if (newline)
		fputc ('\n', fp);

	fclose (fp);

	return TRUE;
}

gboolean
fs_util_remove_line_from_file (const gchar *path, gint position)
{
	gchar *contents = NULL;
	gsize length = 0;
	gchar **lines;
	GString *out;
	gint index = 0;
	gsize i;
	gboolean ok;

	if (path == NULL || position < 1)
		return FALSE;

	if (!g_file_get_contents (path, &contents, &length, NULL))
		return FALSE;

	lines = g_strsplit (contents, "\n", -1);
	out = g_string_new (NULL);
	ok = FALSE;

	for (i = 0; lines[i] != NULL; i++) {
		index++;

		if (index == position)
			continue;

		if (i > 0)
			g_string_append_c (out, '\n');

		g_string_append (out, lines[i]);
	}

	ok = fs_util_ensure_parent_dir (path) &&
	     (g_file_set_contents (path, out->str, out->len, NULL) == TRUE);

	g_string_free (out, TRUE);
	g_strfreev (lines);
	g_free (contents);

	return ok;
}

const gchar *
fs_util_rules_dir (void)
{
	static gchar *cached = NULL;
	const gchar *env = g_getenv ("FIRESTARTER_RULES_DIR");

	if (env != NULL && *env != '\0')
		return env;

	if (cached == NULL) {
#ifdef G_OS_WIN32
		cached = g_build_filename (g_get_user_data_dir (),
		                           "firestarter", NULL);
#else
		/* /etc/firestarter needs root; prefer a per-user copy unless the
		 * environment explicitly points at a system location. */
		if (geteuid () != 0)
			cached = g_build_filename (g_get_home_dir (),
			                           ".firestarter", NULL);
		else
			cached = g_strdup ("/etc/firestarter");
#endif
	}

	return cached;
}

gchar *
fs_util_rules_path (const gchar *relative)
{
	const gchar *dir = fs_util_rules_dir ();

	if (dir == NULL)
		return NULL;

	return g_build_filename (dir, relative, NULL);
}

const gchar *
fs_util_apply_result_to_string (int result)
{
	switch ((FsApplyResult) result) {
	case FS_APPLY_OK:
		return "Rules applied";
	case FS_APPLY_NO_IPTABLES:
		return "iptables was not found";
	case FS_APPLY_EXT_IF_FAILED:
		return "The external interface could not be configured";
	case FS_APPLY_INT_IF_FAILED:
		return "The internal interface could not be configured";
	case FS_APPLY_NO_PRIVILEGE:
		return "Administrator privileges are required";
	case FS_APPLY_PARTIAL:
		return "Only some of the rules could be applied";
	case FS_APPLY_FAILED:
	default:
		return "Failed to apply the firewall rules";
	}
}