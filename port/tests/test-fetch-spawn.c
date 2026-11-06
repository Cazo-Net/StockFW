/*---[ test-fetch-spawn.c ]----------------------------------------------
 * How fs_fetch() starts curl and reads it, against tests/fake-curl.c in
 * curl's place (STOCKFW_TEST_CURL).  Runs on Windows and Linux; the
 * console window checks are Windows only.
 *
 * On Windows curl is started with CreateProcessW and CREATE_NO_WINDOW
 * (fs-fetch.c, "transfer, on Windows"): through GLib, every threat
 * intel install or update opened one console window per list on the
 * owner's screen (2026-11-03).  This test runs as the window app does,
 * with no console of its own (FreeConsole), and checks that the fake
 * curl has no console window; then, as the control, starts the same
 * fake through GSubprocess, the old way, and checks that it does get a
 * window on the screen, so the first check could fail.
 *
 * Also: the body arrives exactly, also at the cap; one byte over is
 * TOO_LARGE; curl's exit code and first stderr line make the message; a
 * curl that hangs is killed at the deadline; a flood on stderr is read
 * and dropped; every argument reaches curl unchanged (quotes, spaces,
 * backslashes); curl gets exactly fs_fetch_envp() and the system folder
 * (Windows) or / (Linux) as its working folder; a missing curl is
 * NO_CURL; twenty downloads leave no handle or descriptor behind.
 *
 * Usage: fs-fetch-spawn-test [path to fs-fake-curl]
 * (default: fs-fake-curl next to this program).  Not as root on Linux:
 * fs_fetch() would run the fake as nobody (tests/test-fetch.sh covers
 * that).
 *--------------------------------------------------------------------*/
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <gio/gio.h>
#include <string.h>

#include "core/fs-fetch.h"

static guint failures = 0;

#define CHECK(cond, ...) do {                                   \
	if (cond) {                                             \
		g_print ("ok:   " __VA_ARGS__);                 \
	} else {                                                \
		g_print ("FAIL: " __VA_ARGS__);                 \
		failures++;                                     \
	}                                                       \
	g_print ("\n");                                         \
} while (0)

#define FAKE_HOST "https://fake.invalid"

static GBytes *
fetch_ua (const gchar *path, gsize max_bytes, guint timeout_s,
          const gchar *user_agent, GError **error)
{
	gchar *url = g_strconcat (FAKE_HOST, path, NULL);
	FsFetchRequest r = { url, max_bytes, timeout_s, NULL, user_agent };
	GBytes *b = fs_fetch (&r, error);

	g_free (url);
	return b;
}

static GBytes *
fetch (const gchar *path, gsize max_bytes, guint timeout_s,
       GError **error)
{
	return fetch_ua (path, max_bytes, timeout_s, NULL, error);
}

/* The body as a string (it holds no NUL), or NULL. */
static gchar *
fetch_text (const gchar *path, GError **error)
{
	GBytes *b = fetch (path, 1024 * 1024, 30, error);
	gchar *s;

	if (b == NULL)
		return NULL;
	s = g_strndup (g_bytes_get_data (b, NULL), g_bytes_get_size (b));
	g_bytes_unref (b);
	return s;
}

static gchar *
sibling_fake (const gchar *argv0)
{
#ifdef _WIN32
	wchar_t buf[MAX_PATH + 1];
	DWORD n = GetModuleFileNameW (NULL, buf, G_N_ELEMENTS (buf));
	gchar *self, *dir, *fake;

	if (n == 0 || n >= G_N_ELEMENTS (buf))
		return NULL;
	self = g_utf16_to_utf8 ((const gunichar2 *) buf, n, NULL, NULL, NULL);
	dir = g_path_get_dirname (self);
	fake = g_build_filename (dir, "fs-fake-curl.exe", NULL);
	g_free (dir);
	g_free (self);
	return fake;
#else
	gchar *self = g_file_read_link ("/proc/self/exe", NULL);
	gchar *dir, *fake;

	if (self == NULL)
		return NULL;
	dir = g_path_get_dirname (self);
	fake = g_build_filename (dir, "fs-fake-curl", NULL);
	g_free (dir);
	g_free (self);
	return fake;
#endif
}

/* ------------------------------------------------- no console window */

static void
test_console (const gchar *fake)
{
	GError *error = NULL;
	gchar *body = fetch_text ("/ok", &error);

	CHECK (body != NULL && g_str_has_prefix (body, "fake curl body\n"),
	       "the fake curl ran and its body came back (%s)",
	       body != NULL ? "yes" : error->message);
#ifdef _WIN32
	/* none: no console window at all; hidden: one that is never on
	 * the screen.  Either way the owner sees nothing. */
	CHECK (body != NULL && strstr (body, "\nconsole=") != NULL &&
	       strstr (body, "\nconsole=visible\n") == NULL,
	       "curl started by fs_fetch() has no console window on the "
	       "screen (fake says: %s)",
	       body != NULL && strstr (body, "console=") != NULL
	       ? strstr (body, "console=") : "-");
	{
		/* The control: the way fs_fetch() started curl before. */
		const gchar *argv[] = { fake, "--url", FAKE_HOST "/ok", NULL };
		GSubprocess *p;
		gchar *out = NULL;
		GError *e = NULL;

		p = g_subprocess_newv (argv, G_SUBPROCESS_FLAGS_STDOUT_PIPE |
		                       G_SUBPROCESS_FLAGS_STDERR_PIPE, &e);
		if (p != NULL)
			g_subprocess_communicate_utf8 (p, NULL, NULL, &out,
			                               NULL, &e);
		CHECK (out != NULL &&
		       strstr (out, "\nconsole=visible\n") != NULL,
		       "control: the same fake started through GSubprocess "
		       "(the old way) gets a console window on the screen, so "
		       "the check above can fail (fake says: %s)",
		       out != NULL ? (strstr (out, "console=") != NULL
		                      ? strstr (out, "console=") : out)
		                   : e != NULL ? e->message : "nothing");
		g_free (out);
		g_clear_error (&e);
		g_clear_object (&p);
	}
#else
	(void) fake;
	CHECK (body != NULL && strstr (body, "\nconsole=n/a\n") != NULL,
	       "no console check off Windows");
#endif
	g_free (body);
	g_clear_error (&error);
}

/* ------------------------------------------------------------- sizes */

static void
check_bytes (gsize n, gsize cap)
{
	gchar *path = g_strdup_printf ("/bytes/%" G_GSIZE_FORMAT, n);
	GError *error = NULL;
	GBytes *b = fetch (path, cap, 30, &error);
	gsize size = 0;
	const guint8 *d = b != NULL ? g_bytes_get_data (b, &size) : NULL;
	gboolean all_x = b != NULL;

	for (gsize i = 0; all_x && i < size; i++)
		all_x = d[i] == 'x';
	if (n <= cap) {
		CHECK (b != NULL && size == n && all_x,
		       "%" G_GSIZE_FORMAT " bytes under a cap of %"
		       G_GSIZE_FORMAT " arrive exactly (got %" G_GSIZE_FORMAT
		       "%s)", n, cap, size,
		       error != NULL ? error->message : "");
	} else {
		CHECK (b == NULL &&
		       g_error_matches (error, FS_FETCH_ERROR,
		                        FS_FETCH_ERR_TOO_LARGE),
		       "%" G_GSIZE_FORMAT " bytes over a cap of %"
		       G_GSIZE_FORMAT " are TOO_LARGE (%s)", n, cap,
		       error != NULL ? error->message : "no error");
	}
	if (b != NULL)
		g_bytes_unref (b);
	g_clear_error (&error);
	g_free (path);
}

/* A body of a few MiB arrives at pipe speed, not a few KiB per poll
 * (the Windows loop once waited 50 ms after every small read). */
static void
test_speed (void)
{
	GError *error = NULL;
	gint64 t0 = g_get_monotonic_time ();
	GBytes *b = fetch ("/bytes/8000000", 10000000, 60, &error);
	gdouble took = (g_get_monotonic_time () - t0) /
	               (gdouble) G_USEC_PER_SEC;

	CHECK (b != NULL && g_bytes_get_size (b) == 8000000 && took < 10.0,
	       "8 MB arrive in %.1f s (under 10 s)%s%s", took,
	       error != NULL ? ": " : "", error != NULL ? error->message : "");
	if (b != NULL)
		g_bytes_unref (b);
	g_clear_error (&error);
}

static void
test_sizes (void)
{
	check_bytes (900000, 1000000);
	check_bytes (1000000, 1000000);
	check_bytes (1000001, 1000000);
	check_bytes (3000000, 1000000);
	check_bytes (0, 10);
}

/* ---------------------------------------------- curl's word, timeout */

static void
test_failures (const gchar *fake)
{
	GError *error = NULL;
	GBytes *b;
	gint64 t0;
	gdouble took;
	gchar *missing;

	b = fetch ("/exit6", 1000, 30, &error);
	CHECK (b == NULL &&
	       g_error_matches (error, FS_FETCH_ERROR, FS_FETCH_ERR_NETWORK) &&
	       strstr (error->message, "Could not resolve host") != NULL,
	       "curl's exit 6 is NETWORK and its stderr line is in the "
	       "message (%s)", error != NULL ? error->message : "no error");
	g_clear_error (&error);

	b = fetch ("/no-such-page", 1000, 30, &error);
	CHECK (b == NULL &&
	       g_error_matches (error, FS_FETCH_ERROR, FS_FETCH_ERR_HTTP),
	       "curl's exit 22 is HTTP (%s)",
	       error != NULL ? error->message : "no error");
	g_clear_error (&error);

	t0 = g_get_monotonic_time ();
	b = fetch ("/hang", 1000, 1, &error);
	took = (g_get_monotonic_time () - t0) / (gdouble) G_USEC_PER_SEC;
	CHECK (b == NULL &&
	       g_error_matches (error, FS_FETCH_ERROR, FS_FETCH_ERR_TIMEOUT) &&
	       took < 20.0,
	       "a curl that hangs is killed at the deadline: TIMEOUT after "
	       "%.1f s (%s)", took,
	       error != NULL ? error->message : "no error");
	g_clear_error (&error);

	b = fetch ("/stderr-flood", 1000, 30, &error);
	CHECK (b != NULL && g_bytes_get_size (b) == 11 &&
	       memcmp (g_bytes_get_data (b, NULL), "flood done\n", 11) == 0,
	       "4 MiB on stderr are read and dropped; the body still "
	       "arrives (%s)", error != NULL ? error->message : "ok");
	if (b != NULL)
		g_bytes_unref (b);
	g_clear_error (&error);

	missing = g_strconcat (fake, "-missing", NULL);
	g_setenv ("STOCKFW_TEST_CURL", missing, TRUE);
	b = fetch ("/ok", 1000, 30, &error);
	CHECK (b == NULL &&
	       g_error_matches (error, FS_FETCH_ERROR, FS_FETCH_ERR_NO_CURL),
	       "a curl that is not there is NO_CURL (%s)",
	       error != NULL ? error->message : "no error");
	if (b != NULL)
		g_bytes_unref (b);
	g_clear_error (&error);
	g_setenv ("STOCKFW_TEST_CURL", fake, TRUE);
	g_free (missing);
}

/* ------------------------------------------- arguments, env, folder */

static void
check_argv (const gchar *user_agent)
{
	gchar *url = g_strconcat (FAKE_HOST, "/argv", NULL);
	FsFetchRequest r = { url, 100000, 30, NULL, user_agent };
	gchar **want = fs_fetch_argv (&r, "curl");
	GString *expect = g_string_new (NULL);
	GError *error = NULL;
	GBytes *b = fs_fetch (&r, &error);
	gchar *got = b != NULL ? g_strndup (g_bytes_get_data (b, NULL),
	                                    g_bytes_get_size (b))
	                       : NULL;

	for (guint i = 1; want != NULL && want[i] != NULL; i++)
		g_string_append_printf (expect, "[%s]\n", want[i]);
	CHECK (want != NULL && got != NULL &&
	       strcmp (got, expect->str) == 0,
	       "every argument reaches curl unchanged, user agent <%s>%s%s",
	       user_agent,
	       got == NULL ? ": " : "",
	       got == NULL ? (error != NULL ? error->message : "") : "");
	if (got != NULL && strcmp (got, expect->str) != 0)
		g_print ("      want:\n%s      got:\n%s", expect->str, got);
	g_free (got);
	if (b != NULL)
		g_bytes_unref (b);
	g_clear_error (&error);
	g_string_free (expect, TRUE);
	g_strfreev (want);
	g_free (url);
}

static gint
compare_str (gconstpointer a, gconstpointer b)
{
	return strcmp (*(const gchar *const *) a, *(const gchar *const *) b);
}

/* Lines of `text', sorted, as one string. */
static gchar *
sorted_lines (const gchar *text)
{
	gchar **lines = g_strsplit (text, "\n", -1);
	GPtrArray *keep = g_ptr_array_new ();
	gchar *joined;

	for (guint i = 0; lines[i] != NULL; i++)
		if (*lines[i] != '\0')
			g_ptr_array_add (keep, lines[i]);
	g_ptr_array_sort (keep, compare_str);
	g_ptr_array_add (keep, NULL);
	joined = g_strjoinv ("\n", (gchar **) keep->pdata);
	g_ptr_array_free (keep, TRUE);
	g_strfreev (lines);
	return joined;
}

static void
test_child_world (void)
{
	GError *error = NULL;
	gchar *env = fetch_text ("/env", &error);
	gchar **want_env = fs_fetch_envp ();
	gchar *want_joined = g_strjoinv ("\n", want_env);
	gchar *want = sorted_lines (want_joined);
	gchar *got = env != NULL ? sorted_lines (env) : NULL;
	gchar *cwd;
	gchar *want_cwd;

	CHECK (got != NULL && strcmp (got, want) == 0,
	       "curl's environment is exactly fs_fetch_envp()");
	if (got != NULL && strcmp (got, want) != 0)
		g_print ("      want:\n%s\n      got:\n%s\n", want, got);
	g_clear_error (&error);
	g_free (got);
	g_free (want);
	g_free (want_joined);
	g_strfreev (want_env);
	g_free (env);

	cwd = fetch_text ("/cwd", &error);
#ifdef _WIN32
	{
		wchar_t buf[MAX_PATH + 1];
		UINT n = GetSystemDirectoryW (buf, G_N_ELEMENTS (buf));

		want_cwd = n > 0 && n < G_N_ELEMENTS (buf)
		           ? g_utf16_to_utf8 ((const gunichar2 *) buf, n,
		                              NULL, NULL, NULL)
		           : g_strdup ("?");
	}
#else
	want_cwd = g_strdup ("/");
#endif
	if (cwd != NULL)
		g_strchomp (cwd);
	CHECK (cwd != NULL && g_ascii_strcasecmp (cwd, want_cwd) == 0,
	       "curl's working folder is %s, never ours (got %s)", want_cwd,
	       cwd != NULL ? cwd : error->message);
	g_clear_error (&error);
	g_free (cwd);
	g_free (want_cwd);
}

/* ------------------------------------------------------------ leaks */

static guint
open_handles (void)
{
#ifdef _WIN32
	DWORD n = 0;

	GetProcessHandleCount (GetCurrentProcess (), &n);
	return (guint) n;
#else
	GDir *d = g_dir_open ("/proc/self/fd", 0, NULL);
	guint n = 0;

	if (d == NULL)
		return 0;
	while (g_dir_read_name (d) != NULL)
		n++;
	g_dir_close (d);
	return n;
#endif
}

static void
test_no_leaks (void)
{
	guint before, after;

	g_free (fetch_text ("/ok", NULL));   /* warm-up */
	before = open_handles ();
	for (guint i = 0; i < 20; i++)
		g_free (fetch_text ("/ok", NULL));
	after = open_handles ();
	CHECK (after <= before + 2,
	       "twenty downloads leave no handle behind (%u before, %u "
	       "after)", before, after);
}

int
main (int argc, char **argv)
{
	gchar *fake;

#ifdef _WIN32
	/* As the window app: no console of its own, so a console program
	 * it starts the plain way would get a window of its own. */
	FreeConsole ();
#else
	if (geteuid () == 0) {
		g_print ("SKIP: not as root (fs_fetch() would run the fake "
		         "curl as nobody; tests/test-fetch.sh covers that)\n");
		return 0;
	}
#endif
	g_unsetenv ("STOCKFW_TEST_CACERT");
	fake = argc > 1 ? g_strdup (argv[1]) : sibling_fake (argv[0]);
	if (fake == NULL || !g_path_is_absolute (fake) ||
	    !g_file_test (fake, G_FILE_TEST_IS_REGULAR)) {
		g_print ("FAIL: no fake curl at %s\n",
		         fake != NULL ? fake : "(unknown)");
		return 1;
	}
	g_setenv ("STOCKFW_TEST_CURL", fake, TRUE);
	g_print ("fake curl: %s\n", fake);

	test_console (fake);
	test_sizes ();
	test_speed ();
	test_failures (fake);
	check_argv ("a b");
	check_argv ("\"");
	check_argv ("\\");
	check_argv ("ends with a backslash\\");
	check_argv ("x \"y\" \\\"z\\\" w\\\\");
	check_argv ("\\\\\"\\\\");
	check_argv ("StockFW/1.0.8 (tab-free; \"quoted\" C:\\path\\)");
	test_child_world ();
	test_no_leaks ();

	g_free (fake);
	g_print ("\n%s: %u failure(s)\n", failures ? "FAILED" : "PASSED",
	         failures);
	return failures ? 1 : 0;
}
