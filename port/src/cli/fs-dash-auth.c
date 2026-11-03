/*---[ fs-dash-auth.c ]---------------------------------------------------
 * The dashboard's launch codes, session keys, launch files, link
 * socket and start fingerprint (PR 2, 2B).  See fs-dash-auth.h and
 * docs/ARCHITECTURE-AND-SECURITY.md 15.3.2.
 *
 * Nothing here prints.  Codes and keys are compared in constant time
 * and live in this process's memory only.
 *--------------------------------------------------------------------*/
#include "cli/fs-dash-auth.h"

#include <gio/gunixsocketaddress.h>
#include <glib/gstdio.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef enum { CODE_LIVE, CODE_USED, CODE_EXPIRED } CodeState;

/* Codes kept (live, used or expired) so that a used or expired one gets
 * 410 rather than 401; the oldest finished ones go first. */
#define KEEP_CODES 64

typedef struct
{
	gchar     hex[33];
	gint64    issued;
	CodeState state;
	gchar    *file;   /* the launch page, while it exists */
	gchar    *dir;
} Code;

typedef struct
{
	gchar     key[65];
	gint64    created;
	gint64    last_write;
	FsDashVia via;
} Session;

struct _FsDashAuth
{
	uid_t           uid;
	gid_t           gid;
	gchar          *runtime;
	gchar           fingerprint[16];
	GPtrArray      *codes;      /* Code*, oldest first */
	GPtrArray      *sessions;   /* Session*, oldest first */
	gint64        (*clock) (gpointer);
	gpointer        clock_data;

	GSocketService *link;
	gchar          *link_path;
	guint16         port;
	guint16         origin_port;  /* --origin-port, or 0 */
};

/* ------------------------------------------------------------ secrets */

/* [ random_bytes ]
 * From the kernel's CSPRNG.  GLib's g_random is a Mersenne Twister,
 * wrong for a credential, so there is no fallback. */
static gboolean
random_bytes (guint8 *out, gsize n)
{
	FILE *fp = fopen ("/dev/urandom", "rb");
	gsize got;

	if (fp == NULL)
		return FALSE;
	got = fread (out, 1, n, fp);
	fclose (fp);
	return got == n;
}

static gboolean
random_hex (gchar *out, gsize n_bytes)
{
	guint8 bytes[32];

	g_return_val_if_fail (n_bytes <= sizeof (bytes), FALSE);
	if (!random_bytes (bytes, n_bytes))
		return FALSE;
	for (gsize i = 0; i < n_bytes; i++)
		g_snprintf (out + i * 2, 3, "%02x", bytes[i]);
	memset (bytes, 0, sizeof (bytes));
	return TRUE;
}

/* [ same_secret ] -- constant time for two strings of length len. */
static gboolean
same_secret (const gchar *a, const gchar *b, gsize len)
{
	guint8 diff = 0;

	for (gsize i = 0; i < len; i++)
		diff |= (guint8) (a[i] ^ b[i]);
	return diff == 0;
}

static gboolean
is_lower_hex (const gchar *s, gsize len)
{
	if (s == NULL || strlen (s) != len)
		return FALSE;
	for (gsize i = 0; i < len; i++)
		if (!g_ascii_isxdigit (s[i]) || g_ascii_isupper (s[i]))
			return FALSE;
	return TRUE;
}

/* --------------------------------------------- the served user's ids */

typedef struct
{
	gboolean switched;
	gid_t    egid;
	gint     n_groups;
	gid_t   *groups;
} Ids;

/* [ ids_user ]
 * As root (under sudo), take the served user's effective ids and drop
 * the supplementary groups, so that files in the user's runtime
 * directory are made, read and removed with the user's rights only: a
 * symlink the user put there leads nowhere the user could not go.
 * Not root: nothing to do. */
static gboolean
ids_user (const FsDashAuth *auth, Ids *s)
{
	memset (s, 0, sizeof (*s));
	if (geteuid () != 0 || auth->uid == 0)
		return TRUE;

	s->egid = getegid ();
	s->n_groups = getgroups (0, NULL);
	if (s->n_groups < 0)
		return FALSE;
	s->groups = g_new0 (gid_t, MAX (s->n_groups, 1));
	if (getgroups (s->n_groups, s->groups) < 0) {
		g_free (s->groups);
		return FALSE;
	}
	s->switched = TRUE;
	if (setgroups (0, NULL) != 0 || setegid (auth->gid) != 0 ||
	    seteuid (auth->uid) != 0) {
		/* Back to root at once; the caller does nothing. */
		if (seteuid (0) != 0 || setegid (s->egid) != 0 ||
		    setgroups ((gsize) s->n_groups, s->groups) != 0)
			g_error ("cannot return to root's ids");
		g_free (s->groups);
		s->switched = FALSE;
		return FALSE;
	}
	return TRUE;
}

static void
ids_back (Ids *s)
{
	if (!s->switched)
		return;
	if (seteuid (0) != 0 || setegid (s->egid) != 0 ||
	    setgroups ((gsize) s->n_groups, s->groups) != 0)
		g_error ("cannot return to root's ids");
	g_free (s->groups);
	s->switched = FALSE;
}

/* ------------------------------------------------------------- clock */

gint64
fs_dash_auth_now (FsDashAuth *auth)
{
	gint64 now;

	if (auth->clock != NULL)
		return auth->clock (auth->clock_data);
	now = g_get_monotonic_time () / G_USEC_PER_SEC;
#ifdef FS_DASH_TESTING
	{
		/* The test build only: seconds to add, read every time, so
		 * a test can move a running dashboard 12 h ahead. */
		const gchar *f = g_getenv ("STOCKFW_TEST_CLOCK_FILE");
		gchar *text = NULL;

		if (f != NULL && g_file_get_contents (f, &text, NULL, NULL)) {
			now += g_ascii_strtoll (g_strstrip (text), NULL, 10);
			g_free (text);
		}
	}
#endif
	return now;
}

void
fs_dash_auth_set_clock (FsDashAuth *auth, gint64 (*now) (gpointer),
                        gpointer data)
{
	auth->clock = now;
	auth->clock_data = data;
}

/* ------------------------------------------------------- launch files */

/* [ launch_write ]
 * The page that sends a browser on to `url': a 0600 file in a new 0700
 * directory under the runtime directory, written as the served user.
 * The code is in the file only, never in an argument list, where any
 * account could read it from /proc/<pid>/cmdline (14.8).  One way on
 * only (a meta refresh, plus a link to click): 1.0.7 also had a
 * script, and two navigations would now present the code twice, which
 * ends every session. */
static gboolean
launch_write (FsDashAuth *auth, const gchar *url, Code *code)
{
	gchar *tmpl, *path, *html;
	const gchar *at;
	gssize left;
	gint fd;
	Ids ids;

	if (auth->runtime == NULL || !ids_user (auth, &ids))
		return FALSE;

	tmpl = g_build_filename (auth->runtime, "stockfw-dashboard-XXXXXX", NULL);
	if (g_mkdtemp_full (tmpl, 0700) == NULL) {
		ids_back (&ids);
		g_free (tmpl);
		return FALSE;
	}
	path = g_build_filename (tmpl, "open.html", NULL);
	fd = open (path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
	           0600);
	if (fd < 0) {
		g_rmdir (tmpl);
		ids_back (&ids);
		g_free (tmpl);
		g_free (path);
		return FALSE;
	}
	/* url is ours: digits, hex and fixed text, nothing to escape. */
	html = g_strdup_printf (
		"<!doctype html>\n<meta charset=\"utf-8\">\n"
		"<meta name=\"referrer\" content=\"no-referrer\">\n"
		"<meta http-equiv=\"refresh\" content=\"0;url=%s\">\n"
		"<title>StockFW dashboard</title>\n"
		"<p><a href=\"%s\">Open the StockFW dashboard</a></p>\n",
		url, url);
	at = html;
	left = (gssize) strlen (html);
	while (left > 0) {
		gssize n = write (fd, at, (gsize) left);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		at += n;
		left -= n;
	}
	close (fd);
	memset (html, 0, strlen (html));
	g_free (html);
	if (left != 0) {
		g_unlink (path);
		g_rmdir (tmpl);
		ids_back (&ids);
		g_free (tmpl);
		g_free (path);
		return FALSE;
	}
	ids_back (&ids);
	code->dir = tmpl;
	code->file = path;
	return TRUE;
}

static void
launch_remove (FsDashAuth *auth, Code *code)
{
	Ids ids;

	if (code->file == NULL)
		return;
	if (ids_user (auth, &ids)) {
		g_unlink (code->file);
		g_rmdir (code->dir);
		ids_back (&ids);
	}
	g_clear_pointer (&code->file, g_free);
	g_clear_pointer (&code->dir, g_free);
}

/* ------------------------------------------------------------- codes */

static void
code_finish (FsDashAuth *auth, Code *code, CodeState state)
{
	code->state = state;
	launch_remove (auth, code);
}

static void
code_free (Code *code)
{
	memset (code->hex, 0, sizeof (code->hex));
	g_free (code->file);
	g_free (code->dir);
	g_free (code);
}

/* [ codes_trim ] -- keep KEEP_CODES, dropping the oldest finished. */
static void
codes_trim (FsDashAuth *auth)
{
	for (guint i = 0; auth->codes->len > KEEP_CODES && i < auth->codes->len; ) {
		Code *c = g_ptr_array_index (auth->codes, i);

		if (c->state != CODE_LIVE)
			g_ptr_array_remove_index (auth->codes, i);
		else
			i++;
	}
}

const gchar *
fs_dash_auth_issue (FsDashAuth *auth, guint16 port, const gchar **file)
{
	Code *code;
	guint live = 0;
	gchar *url;

	if (file != NULL)
		*file = NULL;

	/* A bounded number of codes waiting: one more ends the oldest. */
	for (guint i = 0; i < auth->codes->len; i++)
		if (((Code *) g_ptr_array_index (auth->codes, i))->state == CODE_LIVE)
			live++;
	for (guint i = 0; live >= FS_DASH_MAX_CODES && i < auth->codes->len; i++) {
		Code *c = g_ptr_array_index (auth->codes, i);

		if (c->state == CODE_LIVE) {
			code_finish (auth, c, CODE_EXPIRED);
			live--;
		}
	}

	code = g_new0 (Code, 1);
	if (!random_hex (code->hex, 16)) {
		g_free (code);
		return NULL;
	}
	code->issued = fs_dash_auth_now (auth);
	code->state = CODE_LIVE;

	url = g_strdup_printf ("http://127.0.0.1:%u/#code=%s", port, code->hex);
	launch_write (auth, url, code);
	memset (url, 0, strlen (url));
	g_free (url);

	g_ptr_array_add (auth->codes, code);
	codes_trim (auth);
	if (file != NULL)
		*file = code->file;
	return code->hex;
}

static void
sessions_end_all (FsDashAuth *auth)
{
	g_ptr_array_set_size (auth->sessions, 0);
}

FsDashRedeem
fs_dash_auth_redeem (FsDashAuth *auth, const gchar *hex, FsDashVia via,
                     gchar **key)
{
	gint64 now = fs_dash_auth_now (auth);
	Code *code = NULL;
	Session *s;

	*key = NULL;
	if (!is_lower_hex (hex, 32))
		return FS_DASH_REDEEM_UNKNOWN;

	for (guint i = 0; i < auth->codes->len; i++) {
		Code *c = g_ptr_array_index (auth->codes, i);

		if (same_secret (c->hex, hex, 32))
			code = c;
	}
	if (code == NULL)
		return FS_DASH_REDEEM_UNKNOWN;

	/* Used before: someone else has the link too (T9).  Every
	 * session ends; the user gets a new link from the terminal. */
	if (code->state == CODE_USED) {
		sessions_end_all (auth);
		return FS_DASH_REDEEM_REUSED;
	}
	if (code->state == CODE_EXPIRED ||
	    now - code->issued > FS_DASH_CODE_LIFE_S) {
		code_finish (auth, code, CODE_EXPIRED);
		return FS_DASH_REDEEM_EXPIRED;
	}
	code_finish (auth, code, CODE_USED);

	s = g_new0 (Session, 1);
	if (!random_hex (s->key, 32)) {
		g_free (s);
		return FS_DASH_REDEEM_UNKNOWN;
	}
	s->created = now;
	/* The code was a fresh link: writes may follow for 15 min. */
	s->last_write = now;
	s->via = via;
	/* At most FS_DASH_MAX_SESSIONS: the oldest gives way. */
	while (auth->sessions->len >= FS_DASH_MAX_SESSIONS)
		g_ptr_array_remove_index (auth->sessions, 0);
	g_ptr_array_add (auth->sessions, s);
	*key = g_strdup (s->key);
	return FS_DASH_REDEEM_OK;
}

static Session *
session_find (FsDashAuth *auth, const gchar *key, guint *index)
{
	Session *found = NULL;

	if (!is_lower_hex (key, 64))
		return NULL;
	for (guint i = 0; i < auth->sessions->len; i++) {
		Session *s = g_ptr_array_index (auth->sessions, i);

		if (same_secret (s->key, key, 64)) {
			found = s;
			if (index != NULL)
				*index = i;
		}
	}
	return found;
}

FsDashSession
fs_dash_auth_check (FsDashAuth *auth, const gchar *key, gboolean write)
{
	gint64 now = fs_dash_auth_now (auth);
	guint index = 0;
	Session *s = session_find (auth, key, &index);

	if (s == NULL)
		return FS_DASH_SESSION_NONE;
	/* Reads: 12 h from the code, so a monitor tab lasts the day. */
	if (now - s->created > FS_DASH_READ_LIFE_S) {
		g_ptr_array_remove_index (auth->sessions, index);
		return FS_DASH_SESSION_NONE;
	}
	/* Writes: one in the last 15 minutes, or a fresh link (E7). */
	if (write && now - s->last_write > FS_DASH_WRITE_IDLE_S)
		return FS_DASH_SESSION_WRITE_STALE;
	return FS_DASH_SESSION_OK;
}

void
fs_dash_auth_note_write (FsDashAuth *auth, const gchar *key)
{
	Session *s = session_find (auth, key, NULL);

	if (s != NULL)
		s->last_write = fs_dash_auth_now (auth);
}

gboolean
fs_dash_auth_end (FsDashAuth *auth, const gchar *key)
{
	guint index = 0;

	if (session_find (auth, key, &index) == NULL)
		return FALSE;
	g_ptr_array_remove_index (auth->sessions, index);
	return TRUE;
}

guint
fs_dash_auth_n_sessions (const FsDashAuth *auth)
{
	return auth->sessions->len;
}

void
fs_dash_auth_tick (FsDashAuth *auth)
{
	gint64 now = fs_dash_auth_now (auth);

	/* The launch file goes after 120 s even if nobody asks (T12). */
	for (guint i = 0; i < auth->codes->len; i++) {
		Code *c = g_ptr_array_index (auth->codes, i);

		if (c->state == CODE_LIVE && now - c->issued > FS_DASH_CODE_LIFE_S)
			code_finish (auth, c, CODE_EXPIRED);
	}
	for (guint i = 0; i < auth->sessions->len; ) {
		Session *s = g_ptr_array_index (auth->sessions, i);

		if (now - s->created > FS_DASH_READ_LIFE_S)
			g_ptr_array_remove_index (auth->sessions, i);
		else
			i++;
	}
}

/* -------------------------------------------------------- link socket */

gchar *
fs_dash_auth_socket_dir (const gchar *runtime_dir)
{
	return g_build_filename (runtime_dir, "stockfw", NULL);
}

static gboolean
on_link (GSocketService *service, GSocketConnection *connection,
         GObject *source, gpointer data)
{
	FsDashAuth *auth = data;
	GSocket *sock = g_socket_connection_get_socket (connection);
	GCredentials *cred = g_socket_get_credentials (sock, NULL);
	gboolean ok = FALSE;

	/* SO_PEERCRED, before anything is sent; nothing is ever read. */
	if (cred != NULL) {
		uid_t uid = g_credentials_get_unix_user (cred, NULL);

		ok = uid != (uid_t) -1 && uid == auth->uid;
		g_object_unref (cred);
	}
	if (ok) {
		const gchar *file = NULL;
		const gchar *code = fs_dash_auth_issue (auth, auth->port, &file);
		gchar *reply;
		GOutputStream *out;

		if (code != NULL) {
			gchar *origin = auth->origin_port != 0
				? g_strdup_printf ("origin_port=%u\n", auth->origin_port)
				: g_strdup ("");

			reply = g_strdup_printf ("port=%u\n%scode=%s\nfile=%s\n"
			                         "fingerprint=%s\n", auth->port,
			                         origin, code,
			                         file != NULL ? file : "",
			                         auth->fingerprint);
			g_free (origin);
			g_socket_set_timeout (sock, 2);
			out = g_io_stream_get_output_stream (G_IO_STREAM (connection));
			g_output_stream_write_all (out, reply, strlen (reply), NULL,
			                           NULL, NULL);
			memset (reply, 0, strlen (reply));
			g_free (reply);
		}
	}
	g_io_stream_close (G_IO_STREAM (connection), NULL, NULL);
	return TRUE;
}

void
fs_dash_auth_set_origin_port (FsDashAuth *auth, guint16 port)
{
	auth->origin_port = port;
}

gboolean
fs_dash_auth_listen_link (FsDashAuth *auth, guint16 port, GError **error)
{
	gchar *dir, *path;
	struct stat st;
	GSocketAddress *address;
	gboolean ok = FALSE;
	mode_t old_mask;
	Ids ids;

	if (auth->runtime == NULL) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
		             "no runtime directory for uid %u", (guint) auth->uid);
		return FALSE;
	}
	if (!ids_user (auth, &ids)) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED,
		             "cannot act as uid %u", (guint) auth->uid);
		return FALSE;
	}

	dir = fs_dash_auth_socket_dir (auth->runtime);
	path = g_strdup_printf ("%s/dash-%u.sock", dir, port);
	if (g_mkdir (dir, 0700) != 0 && errno != EEXIST) {
		g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno),
		             "cannot make %s: %s", dir, g_strerror (errno));
		goto out;
	}
	/* Ours and closed: a directory, of the served uid, 0700. */
	if (lstat (dir, &st) != 0 || !S_ISDIR (st.st_mode) ||
	    st.st_uid != auth->uid || (st.st_mode & 077) != 0) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED,
		             "%s is not a 0700 directory of uid %u", dir,
		             (guint) auth->uid);
		goto out;
	}
	/* A socket left by a dashboard that died: this port is ours now,
	 * so that dashboard is gone. */
	if (lstat (path, &st) == 0) {
		if (!S_ISSOCK (st.st_mode) || st.st_uid != auth->uid ||
		    g_unlink (path) != 0) {
			g_set_error (error, G_IO_ERROR, G_IO_ERROR_EXISTS,
			             "%s is in the way", path);
			goto out;
		}
	}

	auth->link = g_socket_service_new ();
	address = g_unix_socket_address_new (path);
	old_mask = umask (077);
	ok = g_socket_listener_add_address (G_SOCKET_LISTENER (auth->link),
	                                    address, G_SOCKET_TYPE_STREAM,
	                                    G_SOCKET_PROTOCOL_DEFAULT, NULL,
	                                    NULL, error);
	umask (old_mask);
	g_object_unref (address);
	if (!ok) {
		g_clear_object (&auth->link);
		goto out;
	}
	auth->port = port;
	auth->link_path = g_steal_pointer (&path);
	g_signal_connect (auth->link, "incoming", G_CALLBACK (on_link), auth);
	g_socket_service_start (auth->link);

out:
	ids_back (&ids);
	g_free (dir);
	g_free (path);
	return ok;
}

const gchar *
fs_dash_auth_link_path (const FsDashAuth *auth)
{
	return auth->link_path;
}

/* -------------------------------------------------------------- WSL */

gboolean
fs_dash_is_wsl (void)
{
	gchar *text = NULL;
	gboolean wsl = FALSE;

#ifdef FS_DASH_TESTING
	{
		const gchar *t = g_getenv ("STOCKFW_TEST_WSL");

		if (t != NULL)
			return strcmp (t, "1") == 0;
	}
#endif
	if (g_file_get_contents ("/proc/sys/kernel/osrelease", &text, NULL,
	                         NULL)) {
		gchar *low = g_ascii_strdown (text, -1);

		wsl = strstr (low, "microsoft") != NULL;
		g_free (low);
		g_free (text);
	}
	return wsl || g_file_test ("/proc/sys/fs/binfmt_misc/WSLInterop",
	                           G_FILE_TEST_EXISTS);
}

/* ------------------------------------------------------------ the rest */

FsDashAuth *
fs_dash_auth_new (void)
{
	FsDashAuth *auth = g_new0 (FsDashAuth, 1);
	guint8 fp[6];

	if (!random_bytes (fp, sizeof (fp))) {
		g_free (auth);
		return NULL;
	}
	g_snprintf (auth->fingerprint, sizeof (auth->fingerprint),
	            "%02X%02X-%02X%02X-%02X%02X",
	            fp[0], fp[1], fp[2], fp[3], fp[4], fp[5]);
	auth->uid = geteuid ();
	auth->gid = getegid ();
	auth->codes = g_ptr_array_new_with_free_func ((GDestroyNotify) code_free);
	auth->sessions = g_ptr_array_new_with_free_func (g_free);
	return auth;
}

void
fs_dash_auth_set_user (FsDashAuth *auth, uid_t uid, gid_t gid,
                       const gchar *runtime_dir)
{
	auth->uid = uid;
	auth->gid = gid;
	g_free (auth->runtime);
	auth->runtime = g_strdup (runtime_dir);
}

const gchar *
fs_dash_auth_runtime_dir (const FsDashAuth *auth)
{
	return auth->runtime;
}

const gchar *
fs_dash_auth_fingerprint (const FsDashAuth *auth)
{
	return auth->fingerprint;
}

void
fs_dash_auth_free (FsDashAuth *auth)
{
	if (auth == NULL)
		return;
	if (auth->link != NULL) {
		Ids ids;

		g_socket_service_stop (auth->link);
		g_socket_listener_close (G_SOCKET_LISTENER (auth->link));
		g_object_unref (auth->link);
		if (ids_user (auth, &ids)) {
			g_unlink (auth->link_path);
			ids_back (&ids);
		}
	}
	for (guint i = 0; i < auth->codes->len; i++)
		launch_remove (auth, g_ptr_array_index (auth->codes, i));
	g_ptr_array_unref (auth->codes);
	for (guint i = 0; i < auth->sessions->len; i++) {
		Session *s = g_ptr_array_index (auth->sessions, i);

		memset (s->key, 0, sizeof (s->key));
	}
	g_ptr_array_unref (auth->sessions);
	g_free (auth->link_path);
	g_free (auth->runtime);
	g_free (auth);
}
