/*---[ fs-fetch.c ]------------------------------------------------------
 * One hardened HTTPS download through curl, into memory.  See
 * fs-fetch.h; design section 5 [S0, S2, S9, P14].
 *
 * curl does the HTTP and the TLS.  Everything around it is decided
 * here, because a root process hands its children far more than it
 * means to: which curl runs (an absolute path, never a search), what
 * it reads before our arguments (nothing: `-q' first), what it finds in
 * its environment (two variables we chose), which account it runs as
 * (`nobody', no groups, no way back), and how much of what it prints
 * we hold (the body over a pipe, counted here, so a host that streams
 * forever is cut off at the cap whatever curl's own --max-filesize
 * does; before curl 8.4 it did nothing for a chunked body).
 *
 * The transfer runs on a private GMainContext pushed as the thread
 * default for the call, so fs_fetch() blocks only its caller and never
 * dispatches anything that belongs to another loop.
 *--------------------------------------------------------------------*/

#include "core/fs-fetch.h"

#include <gio/gio.h>
#include <string.h>

#ifdef G_OS_UNIX
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#endif

#ifdef G_OS_WIN32
#include <windows.h>
#endif

#define DEFAULT_USER_AGENT  "StockFW/" FS_VERSION
#define CONNECT_TIMEOUT_S   "20"
#define URL_MAX             2048
#define USER_AGENT_MAX      256

/* Our own kill comes this long after curl's --max-time, so curl's own
 * clearer message normally wins and the timer only stops a curl that
 * does not keep to its limit. */
#define KILL_GRACE_S        5

#define READ_CHUNK          (64 * 1024)
/* What we keep of curl's stderr; the rest is read and dropped, so a
 * chatty curl can neither block on a full pipe nor fill our memory. */
#define STDERR_MAX          (64 * 1024)
/* The part of curl's first stderr line a message carries. */
#define DETAIL_MAX          300

#ifdef G_OS_UNIX
/* The status the child exits with when it cannot become `nobody'.
 * curl's own exit statuses stop near 100, so this one is ours. */
#define EXIT_CANNOT_DROP    125
#endif

GQuark
fs_fetch_error_quark (void)
{
	return g_quark_from_static_string ("fs-fetch-error");
}

/* ============================================================== rules */

/* At most `max' bytes, each printable ASCII other than space.  What
 * goes into curl's argv must not carry a space, a control character or
 * a byte some other layer might read differently. */
static gboolean
is_token_text (const gchar *s, gsize max)
{
	gsize n;

	for (n = 0; s[n] != '\0'; n++)
		if (n >= max || (guchar) s[n] < 0x21 || (guchar) s[n] > 0x7e)
			return FALSE;
	return TRUE;
}

/* The URL rule of design 4.4, the same one fs_feed_url_is_acceptable()
 * applies when a feed is configured.  It is checked again here, at the
 * last point before the URL becomes an argument of a program that talks
 * to the network, so the boundary never depends on what a caller
 * checked.  On FALSE, *why says why in words fit for a message. */
static gboolean
url_is_acceptable (const gchar *url, const gchar **why)
{
	const gchar *auth, *auth_end, *host_end;

	if (url == NULL || *url == '\0') {
		*why = "no address was given";
		return FALSE;
	}
	if (*url == '-') {
		*why = "an address may not start with '-'";
		return FALSE;
	}
	if (strlen (url) > URL_MAX) {
		*why = "the address is longer than 2048 bytes";
		return FALSE;
	}
	if (!is_token_text (url, URL_MAX)) {
		*why = "the address holds a space, a control character or "
		       "a character outside ASCII";
		return FALSE;
	}
	if (g_ascii_strncasecmp (url, "https://", 8) != 0) {
		*why = "only https:// addresses are allowed";
		return FALSE;
	}

	auth = url + 8;
	auth_end = auth + strcspn (auth, "/?#");
	if (memchr (auth, '@', (gsize) (auth_end - auth)) != NULL) {
		*why = "the address may not carry a user name (user@host)";
		return FALSE;
	}

	/* The host is the authority without its port; an IPv6 literal
	 * keeps its brackets and must have something inside them. */
	if (*auth == '[') {
		const gchar *close = memchr (auth, ']',
		                             (gsize) (auth_end - auth));

		host_end = (close == NULL || close == auth + 1) ? auth
		                                                : close + 1;
	} else {
		const gchar *colon = memchr (auth, ':',
		                             (gsize) (auth_end - auth));

		host_end = colon != NULL ? colon : auth_end;
	}
	if (host_end == auth) {
		*why = "the address has no host name";
		return FALSE;
	}
	return TRUE;
}

gboolean
fs_fetch_proxy_is_acceptable (const gchar *proxy)
{
	if (proxy == NULL || *proxy == '-' || !is_token_text (proxy, URL_MAX))
		return FALSE;
	return g_ascii_strncasecmp (proxy, "http://", 7) == 0 ||
	       g_ascii_strncasecmp (proxy, "https://", 8) == 0;
}

/* The user agent becomes a request header: printable ASCII (spaces are
 * fine there), so a caller's CR or LF can never add a header. */
static gboolean
user_agent_is_acceptable (const gchar *ua)
{
	gsize n;

	for (n = 0; ua[n] != '\0'; n++)
		if (n >= USER_AGENT_MAX ||
		    (guchar) ua[n] < 0x20 || (guchar) ua[n] > 0x7e)
			return FALSE;
	return n > 0;
}

/* ================================================================ curl */

#ifdef G_OS_WIN32
/* [Unverified on Windows] GetSystemDirectoryW / GetSystemWindows-
 * DirectoryW as UTF-8, or NULL.  Caller frees. */
static gchar *
windows_dir (gboolean system32)
{
	wchar_t buf[MAX_PATH + 1];
	UINT size = (UINT) G_N_ELEMENTS (buf);
	UINT n = system32 ? GetSystemDirectoryW (buf, size)
	                  : GetSystemWindowsDirectoryW (buf, size);

	if (n == 0 || n >= size)
		return NULL;
	return g_utf16_to_utf8 ((const gunichar2 *) buf, (glong) n,
	                        NULL, NULL, NULL);
}
#endif

const gchar *
fs_fetch_curl_path (void)
{
#ifdef G_OS_WIN32
	/* [Unverified on Windows] The inbox curl in System32, by its full
	 * path: CreateProcess would search the program's folder and the
	 * current folder first, so a bare "curl" could run a planted
	 * curl.exe elevated [P14]. */
	static gchar *path = NULL;
	static gsize once = 0;

	if (g_once_init_enter (&once)) {
		gchar *dir = windows_dir (TRUE);

		path = dir != NULL ? g_build_filename (dir, "curl.exe", NULL)
		                   : NULL;
		g_free (dir);
		g_once_init_leave (&once, 1);
	}
	if (path != NULL && g_file_test (path, G_FILE_TEST_IS_REGULAR))
		return path;
	return NULL;
#else
	/* Fixed places, never a PATH search: the PATH of whoever started
	 * a root process is not ours to trust [S0]. */
	static const gchar *const places[] = { "/usr/bin/curl", "/bin/curl" };

	for (guint i = 0; i < G_N_ELEMENTS (places); i++)
		if (g_file_test (places[i], G_FILE_TEST_IS_REGULAR) &&
		    g_file_test (places[i], G_FILE_TEST_IS_EXECUTABLE))
			return places[i];
	return NULL;
#endif
}

/* Everything before the limits, in the header's order.  `-q' must be
 * the very first argument: anywhere else curl has already read a
 * curlrc, and a curlrc can turn off certificate checks, add a proxy or
 * make curl write any file [S0].  --globoff: curl expands [1-9] and
 * {a,b} in a URL into one transfer each, so one URL that passed the
 * rule could become thousands of requests or reach hosts it does not
 * name, and a query such as "?f[type]=ip" would fail as a bad range. */
static const gchar *const ARGV_HEAD[] = {
	"-q",
	"--proto", "=https",
	"--proto-redir", "=https",
	"--proto-default", "https",
	"--tlsv1.2",
	"--fail",
	"--silent",
	"--show-error",
	"--location",
	"--max-redirs", "3",
	"--globoff",
};

gchar **
fs_fetch_argv (const FsFetchRequest *request, const gchar *curl)
{
	const gchar *why = NULL;
	const gchar *ua;
	GPtrArray *argv;

	if (request == NULL || curl == NULL || *curl == '\0' ||
	    request->max_bytes == 0 || request->timeout_s == 0 ||
	    !url_is_acceptable (request->url, &why))
		return NULL;
	if (request->proxy != NULL &&
	    !fs_fetch_proxy_is_acceptable (request->proxy))
		return NULL;
	ua = request->user_agent != NULL ? request->user_agent
	                                 : DEFAULT_USER_AGENT;
	if (!user_agent_is_acceptable (ua))
		return NULL;

	argv = g_ptr_array_new ();
	g_ptr_array_add (argv, g_strdup (curl));
	for (guint i = 0; i < G_N_ELEMENTS (ARGV_HEAD); i++)
		g_ptr_array_add (argv, g_strdup (ARGV_HEAD[i]));

	/* curl's own size cap is only the second guard: fs_fetch() counts
	 * the body itself [S9]. */
	g_ptr_array_add (argv, g_strdup ("--max-filesize"));
	g_ptr_array_add (argv, g_strdup_printf ("%" G_GSIZE_FORMAT,
	                                        request->max_bytes));
	g_ptr_array_add (argv, g_strdup ("--max-time"));
	g_ptr_array_add (argv, g_strdup_printf ("%u", request->timeout_s));
	g_ptr_array_add (argv, g_strdup ("--connect-timeout"));
	g_ptr_array_add (argv, g_strdup (CONNECT_TIMEOUT_S));
	g_ptr_array_add (argv, g_strdup ("--user-agent"));
	g_ptr_array_add (argv, g_strdup (ua));
	/* The body goes to the pipe, never to a file: no path for a
	 * symlink to redirect, nothing left behind on failure [S2]. */
	g_ptr_array_add (argv, g_strdup ("--output"));
	g_ptr_array_add (argv, g_strdup ("-"));
	if (request->proxy != NULL) {
		g_ptr_array_add (argv, g_strdup ("--proxy"));
		g_ptr_array_add (argv, g_strdup (request->proxy));
	} else {
		g_ptr_array_add (argv, g_strdup ("--noproxy"));
		g_ptr_array_add (argv, g_strdup ("*"));
	}
	g_ptr_array_add (argv, g_strdup ("--url"));
	g_ptr_array_add (argv, g_strdup (request->url));
	g_ptr_array_add (argv, NULL);

	return (gchar **) g_ptr_array_free (argv, FALSE);
}

gchar **
fs_fetch_envp (void)
{
	gchar **envp = g_new0 (gchar *, 3);

#ifdef G_OS_WIN32
	/* [Unverified on Windows] Winsock needs SystemRoot; the second
	 * keeps CreateProcess from looking in the current folder for
	 * anything curl itself starts.  The value comes from the system,
	 * not from our own environment. */
	gchar *root = windows_dir (FALSE);

	envp[0] = g_strconcat ("SystemRoot=",
	                       root != NULL ? root : "C:\\Windows", NULL);
	envp[1] = g_strdup ("NoDefaultCurrentDirectoryInExePath=1");
	g_free (root);
#else
	/* Nothing a user could have planted: no HOME (curlrc), no
	 * CURL_CA_BUNDLE / SSL_CERT_* (trust), no SSLKEYLOGFILE (session
	 * keys), no *_proxy (routing) [S0]. */
	envp[0] = g_strdup ("PATH=/usr/sbin:/usr/bin:/sbin:/bin");
	envp[1] = g_strdup ("LC_ALL=C");
#endif
	return envp;
}

gint
fs_fetch_classify_exit (gint status)
{
	switch (status) {
	case 5: case 6: case 7: case 16: case 18: case 52: case 55: case 56:
		return FS_FETCH_ERR_NETWORK;
	case 28:
		return FS_FETCH_ERR_TIMEOUT;
	case 35: case 51: case 53: case 54: case 58: case 59: case 60:
	case 77: case 80: case 82: case 83: case 90: case 91:
		return FS_FETCH_ERR_TLS;
	case 22:
		return FS_FETCH_ERR_HTTP;
	case 63:
		return FS_FETCH_ERR_TOO_LARGE;
	case 1: case 47:
		return FS_FETCH_ERR_URL;
	default:
		return FS_FETCH_ERR_FAILED;
	}
}

/* ============================================================ account */

#ifdef G_OS_UNIX
typedef struct
{
	uid_t uid;
	gid_t gid;
} Account;

/* `nobody' from the account database.  Looked up before the fork: the
 * child may only make async-signal-safe calls, and an NSS lookup is
 * not one.  getpwnam_r, so that two downloads on two threads never
 * share getpwnam's static buffer. */
static gboolean
lookup_nobody (Account *out)
{
	struct passwd pw, *found = NULL;
	gsize size = 1024;
	gchar *buf = NULL;
	gint rc;

	do {
		g_free (buf);
		size *= 4;
		buf = g_malloc (size);
		rc = getpwnam_r ("nobody", &pw, buf, size, &found);
	} while (rc == ERANGE && size < 1024 * 1024);

	if (rc == 0 && found != NULL) {
		out->uid = pw.pw_uid;
		out->gid = pw.pw_gid;
	}
	g_free (buf);
	return rc == 0 && found != NULL;
}

/* The child setup: runs in the child between fork and exec, so only
 * async-signal-safe calls, and failure is _exit, never a return that
 * would let curl start as root.  Groups first, then the gid, then the
 * uid: once the uid is gone the other two can no longer be changed.
 * Then prove that root cannot be had back, and keep any set-uid
 * program curl could be tricked into starting from giving it back. */
static void
become_nobody (gpointer data)
{
	const Account *who = data;

	if (setgroups (0, NULL) != 0 || setgid (who->gid) != 0 ||
	    setuid (who->uid) != 0)
		_exit (EXIT_CANNOT_DROP);
	if (setuid (0) == 0 || getuid () != who->uid ||
	    geteuid () != who->uid || getgid () != who->gid ||
	    getegid () != who->gid)
		_exit (EXIT_CANNOT_DROP);
#ifdef PR_SET_NO_NEW_PRIVS
	if (prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
		_exit (EXIT_CANNOT_DROP);
#endif
}
#endif /* G_OS_UNIX */

/* =========================================================== transfer */

typedef struct
{
	GSubprocess  *proc;
	GCancellable *cancel;      /* stops the pipe reads once we stop curl */
	gsize         max_bytes;
	GByteArray   *body;
	GString      *err;         /* the first STDERR_MAX bytes of stderr  */
	gboolean      out_done;
	gboolean      err_done;
	gboolean      exited;
	gint          stopped;     /* why we killed curl: 0, or an
	                            * FS_FETCH_ERR_* code                    */
	GError       *read_error;  /* stdout could not be read              */
	guint8        out_buf[READ_CHUNK];
	guint8        err_buf[READ_CHUNK];
} Transfer;

/* Kill curl and give up on its pipes: what it printed so far no longer
 * matters.  The wait for its exit still runs to the end in the loop, so
 * nothing is left running when fs_fetch() returns.  The first reason
 * given is the one reported. */
static void
stop_transfer (Transfer *t, gint why)
{
	if (t->stopped == 0)
		t->stopped = why;
	g_subprocess_force_exit (t->proc);
	g_cancellable_cancel (t->cancel);
}

static void on_stdout (GObject *source, GAsyncResult *res, gpointer data);
static void on_stderr (GObject *source, GAsyncResult *res, gpointer data);

static void
read_stdout (Transfer *t)
{
	/* Never ask for more than one byte past the cap, so we never hold
	 * more than max_bytes + 1: that one byte is the proof the body is
	 * too large.  body->len <= max_bytes whenever this runs. */
	gsize room = t->max_bytes - t->body->len;
	gsize want = room >= READ_CHUNK ? READ_CHUNK : room + 1;

	g_input_stream_read_async (g_subprocess_get_stdout_pipe (t->proc),
	                           t->out_buf, want, G_PRIORITY_DEFAULT,
	                           t->cancel, on_stdout, t);
}

static void
read_stderr (Transfer *t)
{
	g_input_stream_read_async (g_subprocess_get_stderr_pipe (t->proc),
	                           t->err_buf, sizeof t->err_buf,
	                           G_PRIORITY_DEFAULT, t->cancel,
	                           on_stderr, t);
}

static void
on_stdout (GObject *source, GAsyncResult *res, gpointer data)
{
	Transfer *t = data;
	GError *error = NULL;
	gssize n;

	n = g_input_stream_read_finish (G_INPUT_STREAM (source), res, &error);
	if (n > 0) {
		g_byte_array_append (t->body, t->out_buf, (guint) n);
		if (t->body->len > t->max_bytes) {
			stop_transfer (t, FS_FETCH_ERR_TOO_LARGE);
			t->out_done = TRUE;
			return;
		}
		read_stdout (t);
		return;
	}

	if (n < 0 && t->stopped == 0 &&
	    !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		t->read_error = error;
		error = NULL;
		stop_transfer (t, FS_FETCH_ERR_FAILED);
	}
	g_clear_error (&error);
	t->out_done = TRUE;
}

static void
on_stderr (GObject *source, GAsyncResult *res, gpointer data)
{
	Transfer *t = data;
	gssize n;

	n = g_input_stream_read_finish (G_INPUT_STREAM (source), res, NULL);
	if (n <= 0) {   /* end, error or cancelled: nothing more to keep */
		t->err_done = TRUE;
		return;
	}
	if (t->err->len < STDERR_MAX)
		g_string_append_len (t->err, (const gchar *) t->err_buf,
		                     (gssize) MIN ((gsize) n,
		                                   STDERR_MAX - t->err->len));
	read_stderr (t);
}

static void
on_child_exit (GObject *source, GAsyncResult *res, gpointer data)
{
	Transfer *t = data;

	g_subprocess_wait_finish (G_SUBPROCESS (source), res, NULL);
	t->exited = TRUE;
}

static gboolean
on_deadline (gpointer data)
{
	stop_transfer (data, FS_FETCH_ERR_TIMEOUT);
	return G_SOURCE_REMOVE;
}

/* ============================================================ results */

/* curl's first stderr line as one line of UI text: its "curl: (60) "
 * prefix dropped, anything but printable ASCII turned into '?', cut at
 * DETAIL_MAX bytes.  NULL when curl said nothing.  Caller frees. */
static gchar *
curl_detail (const GString *err)
{
	const gchar *s = err->str;
	gsize len;
	GString *out;

	while (*s == '\r' || *s == '\n' || *s == ' ' || *s == '\t')
		s++;
	len = strcspn (s, "\r\n");

	if (len > 7 && strncmp (s, "curl: (", 7) == 0) {
		gsize k = 7;

		while (k < len && g_ascii_isdigit (s[k]))
			k++;
		if (k > 7 && k + 1 < len && s[k] == ')' && s[k + 1] == ' ') {
			s += k + 2;
			len -= k + 2;
		}
	}
	if (len == 0)
		return NULL;

	out = g_string_sized_new (MIN (len, DETAIL_MAX) + 4);
	for (gsize i = 0; i < len && i < DETAIL_MAX; i++)
		g_string_append_c (out, ((guchar) s[i] >= 0x20 &&
		                         (guchar) s[i] <= 0x7e) ? s[i] : '?');
	if (len > DETAIL_MAX)
		g_string_append (out, "...");
	return g_string_free (out, FALSE);
}

/* The error for a curl that ran and exited (or died) on its own. */
static void
set_curl_error (GError **error, GSubprocess *proc, const GString *err,
                gboolean dropped)
{
	gchar *detail = curl_detail (err);
	gint status, code;

	if (!g_subprocess_get_if_exited (proc)) {
#ifdef G_OS_UNIX
		g_set_error (error, FS_FETCH_ERROR, FS_FETCH_ERR_FAILED,
		             "Could not download: curl was stopped by "
		             "signal %d", g_subprocess_get_term_sig (proc));
#else
		g_set_error_literal (error, FS_FETCH_ERROR,
		                     FS_FETCH_ERR_FAILED,
		                     "Could not download: curl was stopped");
#endif
		g_free (detail);
		return;
	}

	status = g_subprocess_get_exit_status (proc);
#ifdef G_OS_UNIX
	if (dropped && status == EXIT_CANNOT_DROP) {
		g_set_error_literal (error, FS_FETCH_ERROR,
		                     FS_FETCH_ERR_PRIVILEGE,
		                     "Could not download: curl could not be "
		                     "started as the account `nobody'");
		g_free (detail);
		return;
	}
#endif

	code = fs_fetch_classify_exit (status);
	if (code == FS_FETCH_ERR_FAILED || detail == NULL)
		g_set_error (error, FS_FETCH_ERROR, code,
		             "Could not download: curl failed with exit "
		             "status %d%s%s", status,
		             detail != NULL ? ": " : "",
		             detail != NULL ? detail : "");
	else
		g_set_error (error, FS_FETCH_ERROR, code,
		             "Could not download: %s", detail);
	g_free (detail);
}

/* =============================================================== fetch */

#ifdef FS_FETCH_TESTING
/* Test builds only: "--cacert <path>" just before "--url", so the test
 * server's CA is trusted and nothing else changes. */
static gchar **
with_test_cacert (gchar **argv, const gchar *cacert)
{
	guint n = g_strv_length (argv);
	gchar **out = g_new0 (gchar *, n + 3);
	guint k = 0;

	g_assert (n >= 2 && strcmp (argv[n - 2], "--url") == 0);
	for (guint i = 0; i < n; i++) {
		if (i == n - 2) {
			out[k++] = g_strdup ("--cacert");
			out[k++] = g_strdup (cacert);
		}
		out[k++] = argv[i];
	}
	g_free (argv);   /* the strings now belong to out */
	return out;
}
#endif

GBytes *
fs_fetch (const FsFetchRequest *request, GError **error)
{
	const gchar *why = NULL;
	const gchar *curl;
	gboolean dropped = FALSE;
	GSubprocessLauncher *launcher;
	GMainContext *context;
	GSource *deadline;
	GError *local = NULL;
	gchar **argv, **envp;
	Transfer *t;
	GBytes *result = NULL;
	guint deadline_s;
#ifdef G_OS_UNIX
	Account nobody = { 0, 0 };
#endif
#ifdef G_OS_WIN32
	gchar *cwd;
#endif

	g_return_val_if_fail (request != NULL, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	/* ---- refusals: nothing has been started yet */
	if (!url_is_acceptable (request->url, &why)) {
		g_set_error (error, FS_FETCH_ERROR, FS_FETCH_ERR_URL,
		             "Could not download: %s", why);
		return NULL;
	}
	if (request->proxy != NULL &&
	    !fs_fetch_proxy_is_acceptable (request->proxy)) {
		g_set_error_literal (error, FS_FETCH_ERROR, FS_FETCH_ERR_URL,
		                     "Could not download: the proxy is not "
		                     "an http:// or https:// address StockFW "
		                     "accepts");
		return NULL;
	}
	if (request->max_bytes == 0 || request->timeout_s == 0 ||
	    request->max_bytes >= G_MAXUINT ||
	    (request->user_agent != NULL &&
	     !user_agent_is_acceptable (request->user_agent))) {
		g_set_error_literal (error, FS_FETCH_ERROR,
		                     FS_FETCH_ERR_FAILED,
		                     "Could not download: the request has no "
		                     "usable size limit, time limit or user "
		                     "agent");
		return NULL;
	}

	curl = fs_fetch_curl_path ();
#ifdef FS_FETCH_TESTING
	{
		const gchar *test_curl = g_getenv ("STOCKFW_TEST_CURL");

		/* Absolute only: a bare name would be looked up in our own
		 * PATH, the very search the release lookup never makes. */
		if (test_curl != NULL && *test_curl != '\0') {
			if (!g_path_is_absolute (test_curl)) {
				g_set_error (error, FS_FETCH_ERROR,
				             FS_FETCH_ERR_NO_CURL,
				             "Could not download: curl is not "
				             "installed (%s is not an absolute "
				             "path)", test_curl);
				return NULL;
			}
			curl = test_curl;
		}
	}
#endif
	if (curl == NULL) {
#ifdef G_OS_WIN32
		g_set_error_literal (error, FS_FETCH_ERROR,
		                     FS_FETCH_ERR_NO_CURL,
		                     "Could not download: curl is not "
		                     "installed (no curl.exe in the Windows "
		                     "system folder)");
#else
		g_set_error_literal (error, FS_FETCH_ERROR,
		                     FS_FETCH_ERR_NO_CURL,
		                     "Could not download: curl is not "
		                     "installed (looked for /usr/bin/curl and "
		                     "/bin/curl)");
#endif
		return NULL;
	}

#ifdef G_OS_UNIX
	/* Root never downloads as root [S2.5]: curl parses what a remote
	 * host sends, so it runs as `nobody', and without that account
	 * there is no download. */
	if (geteuid () == 0) {
		if (!lookup_nobody (&nobody)) {
			g_set_error_literal (error, FS_FETCH_ERROR,
			                     FS_FETCH_ERR_PRIVILEGE,
			                     "Could not download: there is no "
			                     "account `nobody' to run curl as, "
			                     "and StockFW does not download as "
			                     "root");
			return NULL;
		}
		if (nobody.uid == 0 || nobody.gid == 0) {
			g_set_error_literal (error, FS_FETCH_ERROR,
			                     FS_FETCH_ERR_PRIVILEGE,
			                     "Could not download: the account "
			                     "`nobody' has root's user or group "
			                     "id; StockFW does not download as "
			                     "root");
			return NULL;
		}
		dropped = TRUE;
	}
#endif

	argv = fs_fetch_argv (request, curl);
	g_assert (argv != NULL);   /* everything it checks passed above */
#ifdef FS_FETCH_TESTING
	{
		const gchar *cacert = g_getenv ("STOCKFW_TEST_CACERT");

		if (cacert != NULL && *cacert != '\0')
			argv = with_test_cacert (argv, cacert);
	}
#endif

	/* ---- spawn: stdin is /dev/null (no STDIN flag), every other
	 * descriptor of ours is closed in the child (no INHERIT_FDS), and
	 * the environment is exactly fs_fetch_envp(): set_environ replaces
	 * the copy of ours a new launcher starts with. */
	launcher = g_subprocess_launcher_new (G_SUBPROCESS_FLAGS_STDOUT_PIPE |
	                                      G_SUBPROCESS_FLAGS_STDERR_PIPE);
	envp = fs_fetch_envp ();
	g_subprocess_launcher_set_environ (launcher, envp);
#ifdef G_OS_WIN32
	/* [Unverified on Windows] No privilege drop on Windows (Round 3);
	 * the working folder is the system folder, never the caller's. */
	cwd = windows_dir (TRUE);
	if (cwd != NULL)
		g_subprocess_launcher_set_cwd (launcher, cwd);
	g_free (cwd);
#else
	/* Nothing relative may resolve inside the caller's directory. */
	g_subprocess_launcher_set_cwd (launcher, "/");
	if (dropped)
		g_subprocess_launcher_set_child_setup (launcher, become_nobody,
		                                       &nobody, NULL);
#endif

	t = g_new0 (Transfer, 1);
	t->proc = g_subprocess_launcher_spawnv (launcher,
	                                        (const gchar * const *) argv,
	                                        &local);
	g_object_unref (launcher);
	g_strfreev (envp);
	g_strfreev (argv);

	if (t->proc == NULL) {
		if (g_error_matches (local, G_SPAWN_ERROR, G_SPAWN_ERROR_NOENT) ||
		    g_error_matches (local, G_SPAWN_ERROR,
		                     G_SPAWN_ERROR_NOTDIR) ||
		    g_error_matches (local, G_IO_ERROR, G_IO_ERROR_NOT_FOUND))
			g_set_error (error, FS_FETCH_ERROR,
			             FS_FETCH_ERR_NO_CURL,
			             "Could not download: curl is not "
			             "installed (%s)", curl);
		else
			g_set_error (error, FS_FETCH_ERROR,
			             FS_FETCH_ERR_FAILED,
			             "Could not download: curl could not be "
			             "started: %s", local->message);
		g_error_free (local);
		g_free (t);
		return NULL;
	}

	/* ---- the transfer, on our own context */
	context = g_main_context_new ();
	g_main_context_push_thread_default (context);

	t->cancel = g_cancellable_new ();
	t->max_bytes = request->max_bytes;
	t->body = g_byte_array_sized_new (
		(guint) MIN (request->max_bytes + 1, (gsize) READ_CHUNK));
	t->err = g_string_new (NULL);

	read_stdout (t);
	read_stderr (t);
	g_subprocess_wait_async (t->proc, NULL, on_child_exit, t);

	deadline_s = request->timeout_s > G_MAXUINT - KILL_GRACE_S
	             ? G_MAXUINT : request->timeout_s + KILL_GRACE_S;
	deadline = g_timeout_source_new_seconds (deadline_s);
	g_source_set_callback (deadline, on_deadline, t, NULL);
	g_source_attach (deadline, context);

	while (!(t->out_done && t->err_done && t->exited))
		g_main_context_iteration (context, TRUE);

	g_source_destroy (deadline);
	g_source_unref (deadline);

	/* ---- the outcome: our own stops first, then curl's word */
	switch (t->stopped) {
	case FS_FETCH_ERR_TOO_LARGE:
		g_set_error (error, FS_FETCH_ERROR, FS_FETCH_ERR_TOO_LARGE,
		             "Could not download: the file is larger than the "
		             "limit of %" G_GSIZE_FORMAT " bytes",
		             request->max_bytes);
		break;
	case FS_FETCH_ERR_TIMEOUT:
		g_set_error (error, FS_FETCH_ERROR, FS_FETCH_ERR_TIMEOUT,
		             "Could not download: no complete answer within "
		             "%u seconds", request->timeout_s);
		break;
	case FS_FETCH_ERR_FAILED:
		g_set_error (error, FS_FETCH_ERROR, FS_FETCH_ERR_FAILED,
		             "Could not download: curl's output could not be "
		             "read: %s", t->read_error->message);
		break;
	default:
		if (g_subprocess_get_if_exited (t->proc) &&
		    g_subprocess_get_exit_status (t->proc) == 0) {
			result = g_byte_array_free_to_bytes (t->body);
			t->body = NULL;
		} else {
			set_curl_error (error, t->proc, t->err, dropped);
		}
		break;
	}

	g_main_context_pop_thread_default (context);
	g_main_context_unref (context);

	if (t->body != NULL)
		g_byte_array_unref (t->body);
	g_string_free (t->err, TRUE);
	g_clear_error (&t->read_error);
	g_object_unref (t->cancel);
	g_object_unref (t->proc);
	g_free (t);
	return result;
}
