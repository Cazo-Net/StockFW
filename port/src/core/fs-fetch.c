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
 * dispatches anything that belongs to another loop.  On Windows curl is
 * started without GLib, with no console window (see "transfer, on
 * Windows" below).
 *--------------------------------------------------------------------*/

#ifdef _WIN32
/* PROC_THREAD_ATTRIBUTE_HANDLE_LIST for the curl start on Windows: the
 * same floor as the Windows backend, set before any header. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#endif

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

/* CMake defines FS_VERSION for every target; tests/test-core.sh compiles
 * every file of src/core by hand without it. */
#ifndef FS_VERSION
#define FS_VERSION "dev"
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
#ifndef G_OS_WIN32
	GSubprocess  *proc;
	GCancellable *cancel;      /* stops the pipe reads once we stop curl */
#endif
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

#ifndef G_OS_WIN32
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
#endif /* !G_OS_WIN32 */

#ifdef G_OS_WIN32
/* ================================================ transfer, on Windows
 *
 * curl.exe is a console program.  Started through GLib (GSubprocess or
 * g_spawn), a console program gets a console window of its own whenever
 * its parent has none, and the window app never has one: GLib cannot
 * pass CREATE_NO_WINDOW.  Every threat-intel install or update flashed
 * one console window per list on the owner's screen (2026-11-03).  So
 * on Windows curl is started with CreateProcessW and CREATE_NO_WINDOW,
 * as the backend starts netsh and wevtutil (ARCH 3.7).
 *
 * The output comes back over two anonymous pipes, so no byte of the
 * body touches the disk.  Nothing here blocks on them: every POLL_MS
 * the loop waits on the process, then takes what each pipe holds
 * (PeekNamedPipe says how much), so curl never stalls on a full pipe,
 * and the size cap and the deadline are checked between reads. */

#define POLL_MS              50
/* After curl has exited, how long its pipes may stay open (another
 * process inherited a write end) before we stop reading them. */
#define DRAIN_AFTER_EXIT_MS  2000
/* After we kill curl, how long we wait for it to be gone. */
#define KILL_WAIT_MS         10000
/* Reads from one pipe per round, at most: a curl that writes to stderr
 * without end must not keep the loop from its deadline. */
#define READS_PER_ROUND      16
/* The pipes' buffer: with the default (a few KiB) curl stalls on a full
 * pipe between our rounds, and a round that read anything never waits,
 * so the transfer is not held to a few KiB per POLL_MS. */
#define PIPE_BUFFER          (1024 * 1024)

enum { PIPE_DATA, PIPE_EMPTY, PIPE_CLOSED, PIPE_FAILED };

/* Takes what the pipe holds now, at most cap bytes, without blocking.
 * PIPE_CLOSED once every write end is closed and the pipe is empty. */
static gint
win_pipe_read (HANDLE h, guint8 *buf, DWORD cap, DWORD *got,
               DWORD *last_error)
{
	DWORD avail = 0;

	*got = 0;
	if (!PeekNamedPipe (h, NULL, 0, NULL, &avail, NULL)) {
		*last_error = GetLastError ();
		return *last_error == ERROR_BROKEN_PIPE ? PIPE_CLOSED
		                                        : PIPE_FAILED;
	}
	if (avail == 0)
		return PIPE_EMPTY;
	if (!ReadFile (h, buf, MIN (avail, cap), got, NULL)) {
		*last_error = GetLastError ();
		return *last_error == ERROR_BROKEN_PIPE ? PIPE_CLOSED
		                                        : PIPE_FAILED;
	}
	return *got > 0 ? PIPE_DATA : PIPE_EMPTY;
}

/* One argument of a command line, quoted so that the C runtime's parser
 * (the CommandLineToArgvW rules) hands it to curl unchanged. */
static void
win_append_arg (GString *cmd, const gchar *arg)
{
	gsize backslashes = 0;

	if (*arg != '\0' && strpbrk (arg, " \t\n\v\"") == NULL) {
		g_string_append (cmd, arg);
		return;
	}
	g_string_append_c (cmd, '"');
	for (const gchar *p = arg; *p != '\0'; p++) {
		if (*p == '\\') {
			backslashes++;
			continue;
		}
		/* Backslashes before a quote are doubled, plus one for the
		 * quote; anywhere else they stand as they are. */
		if (*p == '"')
			backslashes = backslashes * 2 + 1;
		for (; backslashes > 0; backslashes--)
			g_string_append_c (cmd, '\\');
		g_string_append_c (cmd, *p);
	}
	/* Backslashes running into the closing quote are doubled. */
	for (backslashes *= 2; backslashes > 0; backslashes--)
		g_string_append_c (cmd, '\\');
	g_string_append_c (cmd, '"');
}

/* Two NAME=value entries in the order Windows wants an environment
 * block: by name, ignoring case. */
static gint
win_env_compare (const gchar *x, const gchar *y)
{
	gsize nx = strcspn (x, "="), ny = strcspn (y, "=");
	gint c = g_ascii_strncasecmp (x, y, MIN (nx, ny));

	if (c != 0)
		return c;
	return nx < ny ? -1 : nx > ny ? 1 : 0;
}

/* envp as a CreateProcessW environment block, sorted by name: each
 * NAME=value in UTF-16 with its NUL, then one more NUL. */
static gunichar2 *
win_env_block (gchar **envp)
{
	GArray *block = g_array_new (FALSE, FALSE, sizeof (gunichar2));
	const gunichar2 nul = 0;
	guint count = g_strv_length (envp);
	gchar **sorted = g_memdup2 (envp, (count + 1) * sizeof (gchar *));

	/* A handful of entries: an insertion sort. */
	for (guint i = 1; i < count; i++)
		for (guint j = i; j > 0 &&
		     win_env_compare (sorted[j - 1], sorted[j]) > 0; j--) {
			gchar *swap = sorted[j - 1];

			sorted[j - 1] = sorted[j];
			sorted[j] = swap;
		}
	for (guint i = 0; sorted[i] != NULL; i++) {
		glong n = 0;
		gunichar2 *w = g_utf8_to_utf16 (sorted[i], -1, NULL, &n, NULL);

		if (w == NULL || n == 0) {
			g_free (w);
			continue;
		}
		g_array_append_vals (block, w, (guint) n);
		g_array_append_val (block, nul);
		g_free (w);
	}
	g_free (sorted);   /* the strings still belong to envp */
	if (block->len == 0)
		g_array_append_val (block, nul);
	g_array_append_val (block, nul);
	return (gunichar2 *) g_array_free (block, FALSE);
}

static void
win_stop (Transfer *t, HANDLE process, gint why)
{
	if (t->stopped == 0)
		t->stopped = why;
	TerminateProcess (process, 1);
}

/* Runs curl (argv[0] is its full path) with exactly envp, in the system
 * folder, and collects into t what it prints.  TRUE once curl ran:
 * *exited says whether it was seen to end and *code is its exit code.
 * FALSE with @error set when it could not be started. */
static gboolean
win_run_curl (Transfer *t, gchar **argv, gchar **envp, guint deadline_s,
              gboolean *exited, DWORD *code, GError **error)
{
	SECURITY_ATTRIBUTES sa;
	STARTUPINFOEXW si;
	PROCESS_INFORMATION pi;
	HANDLE in = INVALID_HANDLE_VALUE;
	HANDLE out_r = NULL, out_w = NULL, err_r = NULL, err_w = NULL;
	HANDLE inherit[3];
	PPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
	SIZE_T attr_size = 0;
	gboolean use_attrs = FALSE, started = FALSE;
	gboolean out_open = TRUE, err_open = TRUE;
	gunichar2 *wprog = NULL, *wcmd = NULL, *wenv = NULL, *wcwd = NULL;
	GString *cmd = g_string_new (NULL);
	gchar *cwd = windows_dir (TRUE);
	gint64 deadline, ended_at = 0, killed_at = 0;
	gboolean busy_before = FALSE;
	DWORD last = 0;

	*exited = FALSE;
	*code = 0;

	for (guint i = 0; argv[i] != NULL; i++) {
		if (i > 0)
			g_string_append_c (cmd, ' ');
		win_append_arg (cmd, argv[i]);
	}
	wprog = g_utf8_to_utf16 (argv[0], -1, NULL, NULL, NULL);
	wcmd = g_utf8_to_utf16 (cmd->str, -1, NULL, NULL, NULL);
	wenv = win_env_block (envp);
	/* The working folder is the system folder, never the caller's. */
	if (cwd != NULL)
		wcwd = g_utf8_to_utf16 (cwd, -1, NULL, NULL, NULL);
	if (wprog == NULL || wcmd == NULL) {
		g_set_error_literal (error, FS_FETCH_ERROR,
		                     FS_FETCH_ERR_FAILED,
		                     "Could not download: curl's command line "
		                     "is not valid text");
		goto out;
	}

	/* Two pipes; only their write ends, and the null device as stdin,
	 * go to curl. */
	memset (&sa, 0, sizeof sa);
	sa.nLength = sizeof sa;
	sa.bInheritHandle = TRUE;
	if (!CreatePipe (&out_r, &out_w, &sa, PIPE_BUFFER) ||
	    !CreatePipe (&err_r, &err_w, &sa, PIPE_BUFFER) ||
	    !SetHandleInformation (out_r, HANDLE_FLAG_INHERIT, 0) ||
	    !SetHandleInformation (err_r, HANDLE_FLAG_INHERIT, 0) ||
	    (in = CreateFileW (L"NUL", GENERIC_READ,
	                       FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
	                       OPEN_EXISTING, 0, NULL)) ==
	    INVALID_HANDLE_VALUE) {
		gchar *msg = g_win32_error_message ((gint) GetLastError ());

		g_set_error (error, FS_FETCH_ERROR, FS_FETCH_ERR_FAILED,
		             "Could not download: curl could not be started: "
		             "%s", msg);
		g_free (msg);
		goto out;
	}

	/* curl inherits those three handles and nothing else; if the list
	 * cannot be set up, plain inheritance is untidy, never broken. */
	inherit[0] = in;
	inherit[1] = out_w;
	inherit[2] = err_w;
	InitializeProcThreadAttributeList (NULL, 1, 0, &attr_size);
	if (attr_size > 0) {
		attrs = g_malloc (attr_size);
		if (!InitializeProcThreadAttributeList (attrs, 1, 0,
		                                        &attr_size)) {
			g_clear_pointer (&attrs, g_free);
		} else if (!UpdateProcThreadAttribute (
			attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit,
			sizeof inherit, NULL, NULL)) {
			DeleteProcThreadAttributeList (attrs);
			g_clear_pointer (&attrs, g_free);
		} else {
			use_attrs = TRUE;
		}
	}

	memset (&si, 0, sizeof si);
	si.StartupInfo.cb = use_attrs ? sizeof (STARTUPINFOEXW)
	                              : sizeof (STARTUPINFOW);
	si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
	si.StartupInfo.hStdInput = in;
	si.StartupInfo.hStdOutput = out_w;
	si.StartupInfo.hStdError = err_w;
	si.lpAttributeList = use_attrs ? attrs : NULL;
	memset (&pi, 0, sizeof pi);

	/* lpApplicationName is the full path, so no search is made. */
	if (!CreateProcessW ((const wchar_t *) wprog, (wchar_t *) wcmd,
	                     NULL, NULL, TRUE,
	                     CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT |
	                     (use_attrs ? EXTENDED_STARTUPINFO_PRESENT : 0),
	                     wenv, (const wchar_t *) wcwd,
	                     &si.StartupInfo, &pi)) {
		DWORD e = GetLastError ();
		gchar *msg = g_win32_error_message ((gint) e);

		if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND)
			g_set_error (error, FS_FETCH_ERROR,
			             FS_FETCH_ERR_NO_CURL,
			             "Could not download: curl is not "
			             "installed (%s)", argv[0]);
		else
			g_set_error (error, FS_FETCH_ERROR,
			             FS_FETCH_ERR_FAILED,
			             "Could not download: curl could not be "
			             "started: %s", msg);
		g_free (msg);
		goto out;
	}
	started = TRUE;

	/* Our copies of what curl inherited go now: its exit closes the
	 * last write ends, and that ends the reads below. */
	CloseHandle (pi.hThread);
	CloseHandle (out_w);
	out_w = NULL;
	CloseHandle (err_w);
	err_w = NULL;
	CloseHandle (in);
	in = INVALID_HANDLE_VALUE;

	deadline = g_get_monotonic_time () +
	           (gint64) deadline_s * G_USEC_PER_SEC;
	while (!*exited || out_open || err_open) {
		DWORD got = 0;
		gint64 now;
		gint r;
		guint n;
		/* A round that read anything: no waiting in the next one. */
		gboolean busy = FALSE;

		if (!*exited &&
		    WaitForSingleObject (pi.hProcess,
		                         busy_before ? 0 : POLL_MS) ==
		    WAIT_OBJECT_0) {
			*exited = TRUE;
			ended_at = g_get_monotonic_time ();
		}

		/* Never ask for more than one byte past the cap: that one
		 * byte is the proof the body is too large. */
		for (n = 0; out_open; n++) {
			gsize room = t->max_bytes - t->body->len;
			DWORD want = room >= READ_CHUNK ? (DWORD) READ_CHUNK
			                                : (DWORD) room + 1;

			if (n == READS_PER_ROUND) {
				busy = TRUE;
				break;
			}
			r = win_pipe_read (out_r, t->out_buf, want, &got,
			                   &last);
			if (r == PIPE_EMPTY)
				break;
			if (r == PIPE_DATA) {
				busy = TRUE;
				g_byte_array_append (t->body, t->out_buf, got);
				if (t->body->len > t->max_bytes) {
					win_stop (t, pi.hProcess,
					          FS_FETCH_ERR_TOO_LARGE);
					out_open = err_open = FALSE;
				}
				continue;
			}
			if (r == PIPE_FAILED && t->stopped == 0) {
				gchar *msg = g_win32_error_message ((gint) last);

				t->read_error = g_error_new_literal (
					G_IO_ERROR,
					g_io_error_from_win32_error ((gint) last),
					msg);
				g_free (msg);
				win_stop (t, pi.hProcess, FS_FETCH_ERR_FAILED);
				err_open = FALSE;
			}
			out_open = FALSE;
		}

		/* stderr: the first STDERR_MAX bytes kept, the rest read and
		 * dropped. */
		for (n = 0; err_open; n++) {
			if (n == READS_PER_ROUND) {
				busy = TRUE;
				break;
			}
			r = win_pipe_read (err_r, t->err_buf,
			                   (DWORD) sizeof t->err_buf, &got, &last);
			if (r == PIPE_EMPTY)
				break;
			if (r == PIPE_DATA) {
				busy = TRUE;
				if (t->err->len < STDERR_MAX)
					g_string_append_len (
						t->err, (const gchar *) t->err_buf,
						(gssize) MIN ((gsize) got,
						              STDERR_MAX - t->err->len));
				continue;
			}
			err_open = FALSE;
		}

		now = g_get_monotonic_time ();
		if (t->stopped == 0 && now >= deadline) {
			win_stop (t, pi.hProcess, FS_FETCH_ERR_TIMEOUT);
			out_open = err_open = FALSE;
		}
		if (t->stopped != 0 && killed_at == 0)
			killed_at = now;
		if (!*exited && killed_at != 0 &&
		    now - killed_at > (gint64) KILL_WAIT_MS * 1000)
			break;   /* TerminateProcess did not take: give up */
		if (*exited && (out_open || err_open)) {
			if (now - ended_at > (gint64) DRAIN_AFTER_EXIT_MS * 1000)
				out_open = err_open = FALSE;
			else if (!busy)
				Sleep (POLL_MS);
		}
		busy_before = busy;
	}

	if (*exited && !GetExitCodeProcess (pi.hProcess, code))
		*exited = FALSE;
	CloseHandle (pi.hProcess);

out:
	if (attrs != NULL) {
		if (use_attrs)
			DeleteProcThreadAttributeList (attrs);
		g_free (attrs);
	}
	if (in != INVALID_HANDLE_VALUE)
		CloseHandle (in);
	if (out_r != NULL)
		CloseHandle (out_r);
	if (out_w != NULL)
		CloseHandle (out_w);
	if (err_r != NULL)
		CloseHandle (err_r);
	if (err_w != NULL)
		CloseHandle (err_w);
	g_free (wprog);
	g_free (wcmd);
	g_free (wenv);
	g_free (wcwd);
	g_free (cwd);
	g_string_free (cmd, TRUE);
	return started;
}
#endif /* G_OS_WIN32 */

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
set_curl_error (GError **error, gboolean exited, gint status,
                gint term_sig, const GString *err, gboolean dropped)
{
	gchar *detail = curl_detail (err);
	gint code;

	if (!exited) {
#ifdef G_OS_UNIX
		g_set_error (error, FS_FETCH_ERROR, FS_FETCH_ERR_FAILED,
		             "Could not download: curl was stopped by "
		             "signal %d", term_sig);
#else
		g_set_error_literal (error, FS_FETCH_ERROR,
		                     FS_FETCH_ERR_FAILED,
		                     "Could not download: curl was stopped");
#endif
		g_free (detail);
		return;
	}

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
	gboolean exited = FALSE;
	gint status = 0, term_sig = 0;
	gchar **argv, **envp;
	Transfer *t;
	GBytes *result = NULL;
	guint deadline_s;
#ifdef G_OS_WIN32
	DWORD code = 0;
#else
	GSubprocessLauncher *launcher;
	GMainContext *context;
	GSource *deadline;
	GError *local = NULL;
#endif
#ifdef G_OS_UNIX
	Account nobody = { 0, 0 };
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

	deadline_s = request->timeout_s > G_MAXUINT - KILL_GRACE_S
	             ? G_MAXUINT : request->timeout_s + KILL_GRACE_S;
	t = g_new0 (Transfer, 1);
	t->max_bytes = request->max_bytes;
	t->body = g_byte_array_sized_new (
		(guint) MIN (request->max_bytes + 1, (gsize) READ_CHUNK));
	t->err = g_string_new (NULL);
	envp = fs_fetch_envp ();

#ifdef G_OS_WIN32
	/* [Unverified on Windows] No privilege drop on Windows: curl runs
	 * with StockFW's rights (a known gap, design 11.8).  No console
	 * window, the system folder as its working folder, exactly envp:
	 * win_run_curl. */
	if (!win_run_curl (t, argv, envp, deadline_s, &exited, &code,
	                   error)) {
		g_strfreev (envp);
		g_strfreev (argv);
		g_byte_array_unref (t->body);
		g_string_free (t->err, TRUE);
		g_free (t);
		return NULL;
	}
	g_strfreev (envp);
	g_strfreev (argv);
	status = (gint) code;
#else
	/* ---- spawn: stdin is /dev/null (no STDIN flag), every other
	 * descriptor of ours is closed in the child (no INHERIT_FDS), and
	 * the environment is exactly fs_fetch_envp(): set_environ replaces
	 * the copy of ours a new launcher starts with. */
	launcher = g_subprocess_launcher_new (G_SUBPROCESS_FLAGS_STDOUT_PIPE |
	                                      G_SUBPROCESS_FLAGS_STDERR_PIPE);
	g_subprocess_launcher_set_environ (launcher, envp);
	/* Nothing relative may resolve inside the caller's directory. */
	g_subprocess_launcher_set_cwd (launcher, "/");
#ifdef G_OS_UNIX
	if (dropped)
		g_subprocess_launcher_set_child_setup (launcher, become_nobody,
		                                       &nobody, NULL);
#endif

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
		g_byte_array_unref (t->body);
		g_string_free (t->err, TRUE);
		g_free (t);
		return NULL;
	}

	/* ---- the transfer, on our own context */
	context = g_main_context_new ();
	g_main_context_push_thread_default (context);

	t->cancel = g_cancellable_new ();
	read_stdout (t);
	read_stderr (t);
	g_subprocess_wait_async (t->proc, NULL, on_child_exit, t);

	deadline = g_timeout_source_new_seconds (deadline_s);
	g_source_set_callback (deadline, on_deadline, t, NULL);
	g_source_attach (deadline, context);

	while (!(t->out_done && t->err_done && t->exited))
		g_main_context_iteration (context, TRUE);

	g_source_destroy (deadline);
	g_source_unref (deadline);

	exited = g_subprocess_get_if_exited (t->proc);
	if (exited)
		status = g_subprocess_get_exit_status (t->proc);
#ifdef G_OS_UNIX
	else
		term_sig = g_subprocess_get_term_sig (t->proc);
#endif
	g_main_context_pop_thread_default (context);
	g_main_context_unref (context);
#endif /* G_OS_WIN32 */

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
		if (exited && status == 0) {
			result = g_byte_array_free_to_bytes (t->body);
			t->body = NULL;
		} else {
			set_curl_error (error, exited, status, term_sig, t->err,
			                dropped);
		}
		break;
	}

	if (t->body != NULL)
		g_byte_array_unref (t->body);
	g_string_free (t->err, TRUE);
	g_clear_error (&t->read_error);
#ifndef G_OS_WIN32
	g_object_unref (t->cancel);
	g_object_unref (t->proc);
#endif
	g_free (t);
	return result;
}
