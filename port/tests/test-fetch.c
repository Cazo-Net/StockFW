/*---[ test-fetch.c ]----------------------------------------------------
 * Downloads (fs-fetch, 1.0.7 design section 5): the pure pieces, and
 * the driver that test-fetch.sh runs against a local HTTPS server with
 * a throwaway CA inside a private network namespace.  Built with
 * FS_FETCH_TESTING, the only build in which STOCKFW_TEST_CURL and
 * STOCKFW_TEST_CACERT mean anything.
 *
 *   fs-fetch-test golden
 *       argv, environment, the proxy rule, the exit table, and the
 *       refusals that happen before anything is spawned.  No network,
 *       no root.
 *   fs-fetch-test fetch [options] URL
 *       one fs_fetch() and checks on what came back:
 *         --what TEXT     the case's name in the ok/FAIL lines
 *         --max N         max_bytes (default 1 MiB)
 *         --timeout S     timeout_s (default 20)
 *         --proxy URL     the proxy
 *         --expect CODE   ok, NO_CURL, URL, PRIVILEGE, TOO_LARGE,
 *                         TIMEOUT, TLS, HTTP, NETWORK or FAILED
 *         --len N         the body has N bytes
 *         --sha256 HEX    the body's SHA-256
 *         --msg TEXT      the message contains TEXT
 *         --msg-is TEXT   the message is exactly TEXT
 *         --msg-max N     the message has at most N bytes
 *         --within S      fs_fetch() returned within S seconds
 *         --gone TOKEN    when it returned, no live process had TOKEN
 *                         in its command line: curl was stopped and
 *                         waited for, not left behind
 *         --threads N     N fetches at once, one per thread (1-8);
 *                         each must meet the expectations
 *         --repeat N      N fetches one after the other (2-50), each
 *                         meeting the expectations, and this process
 *                         holds no more descriptors after the last
 *                         than after the first: no path leaks a pipe
 *         --peak-growth K this process's peak memory (VmHWM) grew by
 *                         at most K KiB during the fetch: what curl
 *                         prints is held only up to its bounds
 *         --isolated      a source ready on the caller's default main
 *                         context must not run during the call: the
 *                         fetch iterates a context of its own
 *   fs-fetch-test report [--what TEXT] [--marker FILE] URL
 *       fs_fetch() through the reporting stand-in curl named by
 *       STOCKFW_TEST_CURL, then checks what that stand-in was given:
 *       its account, groups, capabilities, no_new_privs, environment,
 *       argv, stdin, working directory and descriptors, and that the
 *       caller itself is still root with its own groups (the drop
 *       happened in the child only).  FILE is held open, not
 *       close-on-exec, during the call: curl must not get it.  Run as
 *       root (curl must have been made `nobody').
 *
 * Every check prints "ok:   ..." or "FAIL: ..."; `golden' ends with
 * the PASSED/FAILED line, `fetch' and `report' leave the total to the
 * script.  The exit status is 1 when anything failed.
 *--------------------------------------------------------------------*/
#define _GNU_SOURCE   /* getresuid, getresgid */
#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

static const gchar *const CODE_NAMES[] = {
	"ok", "NO_CURL", "URL", "PRIVILEGE", "TOO_LARGE", "TIMEOUT", "TLS",
	"HTTP", "NETWORK", "FAILED"
};

static const gchar *
code_name (gint code)
{
	if (code >= 0 && code < (gint) G_N_ELEMENTS (CODE_NAMES))
		return CODE_NAMES[code];
	return "(unknown)";
}

static gint
code_from_name (const gchar *name)
{
	for (guint i = 0; i < G_N_ELEMENTS (CODE_NAMES); i++)
		if (strcmp (name, CODE_NAMES[i]) == 0)
			return (gint) i;
	g_printerr ("unknown code %s\n", name);
	exit (2);
}

/* The FS_FETCH_ERR_* code of an outcome, 0 for a body. */
static gint
outcome (GBytes *body, const GError *error)
{
	if (body != NULL)
		return 0;
	if (error == NULL || error->domain != FS_FETCH_ERROR)
		return -1;
	return error->code;
}

static gchar *
joined (gchar **argv)
{
	return argv != NULL ? g_strjoinv (" ", argv) : g_strdup ("(null)");
}

/* ============================================================= golden */

static const FsFetchRequest BASE = {
	"https://feeds.example.net/list.txt?key=s3cr3t",
	33554432, 120, NULL, NULL
};

static gboolean
argv_is (gchar **got, const gchar *const *want)
{
	guint i;

	if (got == NULL)
		return FALSE;
	for (i = 0; want[i] != NULL; i++)
		if (got[i] == NULL || strcmp (got[i], want[i]) != 0)
			return FALSE;
	return got[i] == NULL;
}

static void
test_argv (void)
{
	const gchar *const want[] = {
		"/usr/bin/curl", "-q",
		"--proto", "=https", "--proto-redir", "=https",
		"--proto-default", "https", "--tlsv1.2",
		"--fail", "--silent", "--show-error",
		"--location", "--max-redirs", "3", "--globoff",
		"--max-filesize", "33554432", "--max-time", "120",
		"--connect-timeout", "20",
		"--user-agent", "StockFW/" FS_VERSION,
		"--output", "-", "--noproxy", "*",
		"--url", "https://feeds.example.net/list.txt?key=s3cr3t",
		NULL
	};
	const gchar *const want_proxy[] = {
		"/bin/curl", "-q",
		"--proto", "=https", "--proto-redir", "=https",
		"--proto-default", "https", "--tlsv1.2",
		"--fail", "--silent", "--show-error",
		"--location", "--max-redirs", "3", "--globoff",
		"--max-filesize", "1000", "--max-time", "5",
		"--connect-timeout", "20",
		"--user-agent", "StockFW-test/1 (fetch)",
		"--output", "-", "--proxy", "http://proxy.example.net:3128",
		"--url", "https://feeds.example.net/x",
		NULL
	};
	FsFetchRequest req = BASE;
	gchar **argv, *text;

	argv = fs_fetch_argv (&req, "/usr/bin/curl");
	text = joined (argv);
	CHECK (argv_is (argv, want), "argv golden, no proxy (%s)", text);
	CHECK (argv != NULL && strcmp (argv[1], "-q") == 0,
	       "-q is the first argument: anywhere else curl has already "
	       "read a curlrc");
	g_free (text);
	g_strfreev (argv);

	req.url = "https://feeds.example.net/x";
	req.max_bytes = 1000;
	req.timeout_s = 5;
	req.proxy = "http://proxy.example.net:3128";
	req.user_agent = "StockFW-test/1 (fetch)";
	argv = fs_fetch_argv (&req, "/bin/curl");
	text = joined (argv);
	CHECK (argv_is (argv, want_proxy),
	       "argv golden, with a proxy and a user agent (%s)", text);
	g_free (text);
	g_strfreev (argv);
}

static void
expect_refused (const FsFetchRequest *req, const gchar *curl,
                const gchar *what)
{
	gchar **argv = fs_fetch_argv (req, curl);

	CHECK (argv == NULL, "argv refuses %s", what);
	g_strfreev (argv);
}

static void
test_argv_refusals (void)
{
	static const struct { const gchar *url, *what; } bad_urls[] = {
		{ "http://feeds.example.net/x", "http://" },
		{ "ftp://feeds.example.net/x", "ftp://" },
		{ "feeds.example.net/x", "a URL without a scheme" },
		{ "https://", "https:// with no host" },
		{ "https:///x", "an empty host before the path" },
		{ "https://:443/x", "a port with no host" },
		{ "https://[]/x", "empty IPv6 brackets" },
		{ "https://[2001:db8::1/x", "an unclosed IPv6 bracket" },
		{ "https://user@feeds.example.net/x", "a user@ part" },
		{ "https://user:pw@feeds.example.net/x", "a user:password@ part" },
		{ "https://evil.example\\@feeds.example.net/", "an @ behind a backslash" },
		{ "https://feeds.example.net/a b", "a space" },
		{ "https://feeds.example.net/a\tb", "a tab" },
		{ "https://feeds.example.net/a\nb", "a newline" },
		{ "https://feeds.example.net/\xc3\xa9", "non-ASCII" },
		{ "-https://feeds.example.net/x", "a leading '-'" },
		{ "", "an empty URL" },
	};
	static const struct { const gchar *proxy, *what; } bad_proxies[] = {
		{ "socks5://127.0.0.1:1080", "a socks5 proxy" },
		{ "ftp://proxy.example.net", "an ftp proxy" },
		{ "proxy.example.net:3128", "a proxy without a scheme" },
		{ "http://proxy example:3128", "a proxy with a space" },
		{ "-http://proxy.example.net", "a proxy starting with '-'" },
		{ "", "an empty proxy" },
	};
	FsFetchRequest req = BASE;
	gchar *long_url, *long_proxy;

	for (guint i = 0; i < G_N_ELEMENTS (bad_urls); i++) {
		req.url = bad_urls[i].url;
		expect_refused (&req, "/usr/bin/curl", bad_urls[i].what);
	}
	req.url = NULL;
	expect_refused (&req, "/usr/bin/curl", "a NULL URL");

	/* 2048 bytes is the limit, 2049 is over it. */
	{
		GString *s = g_string_new ("https://feeds.example.net/");

		while (s->len < 2048)
			g_string_append_c (s, 'a');
		long_url = g_string_free (s, FALSE);
	}
	req.url = long_url;
	{
		gchar **argv = fs_fetch_argv (&req, "/usr/bin/curl");

		CHECK (argv != NULL, "argv takes a URL of exactly 2048 bytes");
		g_strfreev (argv);
	}
	{
		gchar *longer = g_strconcat (long_url, "a", NULL);

		req.url = longer;
		expect_refused (&req, "/usr/bin/curl", "a URL of 2049 bytes");
		g_free (longer);
	}
	g_free (long_url);

	req = BASE;
	for (guint i = 0; i < G_N_ELEMENTS (bad_proxies); i++) {
		req.proxy = bad_proxies[i].proxy;
		expect_refused (&req, "/usr/bin/curl", bad_proxies[i].what);
	}
	long_proxy = g_strnfill (2049 - 7, 'p');
	{
		gchar *p = g_strconcat ("http://", long_proxy, NULL);

		req.proxy = p;
		expect_refused (&req, "/usr/bin/curl", "a proxy of 2049 bytes");
		g_free (p);
	}
	g_free (long_proxy);

	req = BASE;
	req.max_bytes = 0;
	expect_refused (&req, "/usr/bin/curl", "max_bytes 0");
	req = BASE;
	req.timeout_s = 0;
	expect_refused (&req, "/usr/bin/curl", "timeout_s 0");
	req = BASE;
	expect_refused (&req, NULL, "a NULL curl");
	expect_refused (&req, "", "an empty curl path");
	expect_refused (NULL, "/usr/bin/curl", "a NULL request");
	req.user_agent = "StockFW\r\nX-Injected: 1";
	expect_refused (&req, "/usr/bin/curl",
	                "a user agent with CR LF (header injection)");
	req.user_agent = "";
	expect_refused (&req, "/usr/bin/curl", "an empty user agent");
	req.user_agent = "StockFW\x7f";
	expect_refused (&req, "/usr/bin/curl", "a user agent with DEL");

	/* 256 bytes of user agent is the limit, 257 is over it. */
	{
		gchar *ua = g_strnfill (256, 'u');
		gchar **argv;

		req.user_agent = ua;
		argv = fs_fetch_argv (&req, "/usr/bin/curl");
		CHECK (argv != NULL, "argv takes a user agent of exactly 256 "
		       "bytes");
		g_strfreev (argv);
		g_free (ua);
		ua = g_strnfill (257, 'u');
		req.user_agent = ua;
		expect_refused (&req, "/usr/bin/curl",
		                "a user agent of 257 bytes");
		g_free (ua);
	}
}

static void
test_argv_accepts (void)
{
	static const gchar *const good[] = {
		"https://feeds.example.net/",
		"https://feeds.example.net",
		"HTTPS://Feeds.Example.NET/x",
		"https://feeds.example.net:8443/x",
		"https://[2001:db8::1]:8443/list",
		"https://192.0.2.1/x?key=a&b=c#frag",
		"https://a/",
	};
	FsFetchRequest req = BASE;

	for (guint i = 0; i < G_N_ELEMENTS (good); i++) {
		gchar **argv;

		req.url = good[i];
		argv = fs_fetch_argv (&req, "/usr/bin/curl");
		CHECK (argv != NULL && argv[g_strv_length (argv) - 1] != NULL &&
		       strcmp (argv[g_strv_length (argv) - 1], good[i]) == 0,
		       "argv takes %s, unchanged, as the last argument",
		       good[i]);
		g_strfreev (argv);
	}
	req = BASE;
	req.proxy = "https://user:pw@proxy.example.net:3128";
	{
		gchar **argv = fs_fetch_argv (&req, "/usr/bin/curl");

		CHECK (argv != NULL, "argv takes an https:// proxy with "
		       "credentials");
		g_strfreev (argv);
	}
}

static void
test_envp (void)
{
	const gchar *const want[] = {
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", NULL
	};
	gchar **envp = fs_fetch_envp ();
	gchar *text = joined (envp);

	CHECK (argv_is (envp, want),
	       "the environment is exactly PATH and LC_ALL=C (%s)", text);
	g_free (text);
	g_strfreev (envp);
}

static void
test_proxy_rule (void)
{
	static const struct { const gchar *proxy; gboolean ok; } cases[] = {
		{ "http://proxy.example.net:3128", TRUE },
		{ "https://proxy.example.net:3129", TRUE },
		{ "HTTP://proxy.example.net", TRUE },
		{ "http://user:pw@proxy.example.net:3128", TRUE },
		{ "socks5h://proxy.example.net", FALSE },
		{ "proxy.example.net:3128", FALSE },
		{ "http://proxy.example.net/ x", FALSE },
		{ "http://proxy.example.net/\x01", FALSE },
		{ "http://proxy.example.net/\xc3\xa9", FALSE },
		{ "-http://proxy.example.net", FALSE },
		{ "", FALSE },
		{ NULL, FALSE },
	};

	for (guint i = 0; i < G_N_ELEMENTS (cases); i++) {
		gchar *shown = cases[i].proxy != NULL
			? g_strescape (cases[i].proxy, NULL)
			: g_strdup ("(null)");

		CHECK (fs_fetch_proxy_is_acceptable (cases[i].proxy) ==
		       cases[i].ok, "proxy rule: \"%s\" is %s", shown,
		       cases[i].ok ? "accepted" : "refused");
		g_free (shown);
	}
}

static void
test_classify (void)
{
	static const struct { gint status, code; } table[] = {
		{ 5, FS_FETCH_ERR_NETWORK },  { 6, FS_FETCH_ERR_NETWORK },
		{ 7, FS_FETCH_ERR_NETWORK },  { 16, FS_FETCH_ERR_NETWORK },
		{ 18, FS_FETCH_ERR_NETWORK }, { 52, FS_FETCH_ERR_NETWORK },
		{ 55, FS_FETCH_ERR_NETWORK }, { 56, FS_FETCH_ERR_NETWORK },
		{ 28, FS_FETCH_ERR_TIMEOUT },
		{ 35, FS_FETCH_ERR_TLS }, { 51, FS_FETCH_ERR_TLS },
		{ 53, FS_FETCH_ERR_TLS }, { 54, FS_FETCH_ERR_TLS },
		{ 58, FS_FETCH_ERR_TLS }, { 59, FS_FETCH_ERR_TLS },
		{ 60, FS_FETCH_ERR_TLS }, { 77, FS_FETCH_ERR_TLS },
		{ 80, FS_FETCH_ERR_TLS }, { 82, FS_FETCH_ERR_TLS },
		{ 83, FS_FETCH_ERR_TLS }, { 90, FS_FETCH_ERR_TLS },
		{ 91, FS_FETCH_ERR_TLS },
		{ 22, FS_FETCH_ERR_HTTP },
		{ 63, FS_FETCH_ERR_TOO_LARGE },
		{ 1, FS_FETCH_ERR_URL }, { 47, FS_FETCH_ERR_URL },
		/* everything else */
		{ 0, FS_FETCH_ERR_FAILED },  { 2, FS_FETCH_ERR_FAILED },
		{ 3, FS_FETCH_ERR_FAILED },  { 4, FS_FETCH_ERR_FAILED },
		{ 8, FS_FETCH_ERR_FAILED },  { 23, FS_FETCH_ERR_FAILED },
		{ 26, FS_FETCH_ERR_FAILED }, { 27, FS_FETCH_ERR_FAILED },
		{ 61, FS_FETCH_ERR_FAILED }, { 92, FS_FETCH_ERR_FAILED },
		{ 125, FS_FETCH_ERR_FAILED }, { 255, FS_FETCH_ERR_FAILED },
		{ -1, FS_FETCH_ERR_FAILED },
	};
	guint wrong = 0;

	for (guint i = 0; i < G_N_ELEMENTS (table); i++) {
		gint got = fs_fetch_classify_exit (table[i].status);

		if (got != table[i].code) {
			g_print ("      exit %d: %s, expected %s\n",
			         table[i].status, code_name (got),
			         code_name (table[i].code));
			wrong++;
		}
	}
	CHECK (wrong == 0, "curl's exit statuses map as the header's table "
	       "says (%u of %u wrong)", wrong,
	       (guint) G_N_ELEMENTS (table));
}

static void
test_curl_path (void)
{
	const gchar *path = fs_fetch_curl_path ();
	const gchar *want = NULL;

	if (g_file_test ("/usr/bin/curl", G_FILE_TEST_IS_EXECUTABLE))
		want = "/usr/bin/curl";
	else if (g_file_test ("/bin/curl", G_FILE_TEST_IS_EXECUTABLE))
		want = "/bin/curl";
	CHECK (g_strcmp0 (path, want) == 0,
	       "the curl path is a fixed absolute one, never a search "
	       "(%s)", path != NULL ? path : "none here");
}

/* fs_fetch() on a request it must refuse before spawning anything.
 * STOCKFW_TEST_CURL names no file, so a call that got as far as
 * spawning would fail with NO_CURL instead. */
static void
expect_fetch_refused (const FsFetchRequest *req, gint code,
                      const gchar *what)
{
	GError *error = NULL;
	GBytes *body = fs_fetch (req, &error);
	gint got = outcome (body, error);

	CHECK (got == code, "fs_fetch: %s -> %s (got %s: %s)", what,
	       code_name (code), code_name (got),
	       error != NULL ? error->message : "a body");
	if (error != NULL)
		CHECK (strchr (error->message, '\n') == NULL &&
		       g_str_has_prefix (error->message,
		                         "Could not download: ") &&
		       strstr (error->message, "s3cr3t") == NULL,
		       "  ... in one line, without the URL's query string");
	g_clear_error (&error);
	if (body != NULL)
		g_bytes_unref (body);
}

static void
test_fetch_refusals (void)
{
	FsFetchRequest req = BASE;

	g_setenv ("STOCKFW_TEST_CURL", "/nonexistent/stockfw-test/curl",
	          TRUE);
	g_unsetenv ("STOCKFW_TEST_CACERT");

	req.url = "http://feeds.example.net/list.txt?key=s3cr3t";
	expect_fetch_refused (&req, FS_FETCH_ERR_URL,
	                      "an http:// URL is refused before spawning");
	req.url = "https://user@feeds.example.net/?key=s3cr3t";
	expect_fetch_refused (&req, FS_FETCH_ERR_URL,
	                      "a user@ URL is refused before spawning");
	req = BASE;
	req.proxy = "socks5://127.0.0.1:1080";
	expect_fetch_refused (&req, FS_FETCH_ERR_URL,
	                      "a socks5 proxy is refused before spawning");
	req = BASE;
	req.max_bytes = 0;
	expect_fetch_refused (&req, FS_FETCH_ERR_FAILED,
	                      "max_bytes 0 is refused before spawning");
	req = BASE;
	req.timeout_s = 0;
	expect_fetch_refused (&req, FS_FETCH_ERR_FAILED,
	                      "timeout_s 0 is refused before spawning");
	req = BASE;
	req.user_agent = "StockFW\r\nX-Injected: 1";
	expect_fetch_refused (&req, FS_FETCH_ERR_FAILED,
	                      "a user agent with CR LF is refused before "
	                      "spawning");

	/* The body is held in a GByteArray, whose length is a guint: a
	 * cap it could not count up to (+1) is refused, the largest one
	 * it can is not. */
	req = BASE;
	req.max_bytes = (gsize) G_MAXUINT;
	expect_fetch_refused (&req, FS_FETCH_ERR_FAILED,
	                      "max_bytes G_MAXUINT is refused before "
	                      "spawning");
	req.max_bytes = (gsize) G_MAXUINT - 1;
	expect_fetch_refused (&req, FS_FETCH_ERR_NO_CURL,
	                      "max_bytes G_MAXUINT - 1 reaches the spawn");

	/* The control: the same override with a good request does get
	 * as far as spawning, and says curl is missing. */
	req = BASE;
	expect_fetch_refused (&req, FS_FETCH_ERR_NO_CURL,
	                      "a good request reaches the spawn; a missing "
	                      "curl is NO_CURL");

	g_setenv ("STOCKFW_TEST_CURL", "curl", TRUE);
	expect_fetch_refused (&req, FS_FETCH_ERR_NO_CURL,
	                      "a test curl by bare name is never searched "
	                      "for in PATH");
	g_unsetenv ("STOCKFW_TEST_CURL");
}

static gint
cmd_golden (void)
{
	CHECK (g_strcmp0 (g_quark_to_string (FS_FETCH_ERROR),
	                  "fs-fetch-error") == 0, "the error domain is "
	       "fs-fetch-error");
	test_argv ();
	test_argv_refusals ();
	test_argv_accepts ();
	test_envp ();
	test_proxy_rule ();
	test_classify ();
	test_curl_path ();
	test_fetch_refusals ();

	g_print ("\n%s: %u failure(s)\n", failures ? "FAILED" : "PASSED",
	         failures);
	return failures ? 1 : 0;
}

/* ============================================================== fetch */

/* The command line is NUL-separated, so no string search will do. */
static gboolean
bytes_contain (const gchar *hay, gsize len, const gchar *needle)
{
	gsize n = strlen (needle);

	for (gsize i = 0; n > 0 && n <= len && i <= len - n; i++)
		if (memcmp (hay + i, needle, n) == 0)
			return TRUE;
	return FALSE;
}

/* A live process, other than this one and its parent (the timeout(1)
 * that runs it carries the same URL), whose command line holds token.
 * Zombies have an empty command line, so a curl that was killed but
 * not yet reaped is not counted: what is counted is a curl that is
 * still running. */
static gint
process_with_token (const gchar *token)
{
	GDir *dir = g_dir_open ("/proc", 0, NULL);
	const gchar *name;
	gint found = 0;

	if (dir == NULL)
		return 0;
	while (found == 0 && (name = g_dir_read_name (dir)) != NULL) {
		gchar *path, *cmd = NULL;
		gsize len = 0;
		gint pid = atoi (name);

		if (pid <= 0 || pid == getpid () || pid == getppid ())
			continue;
		path = g_strdup_printf ("/proc/%d/cmdline", pid);
		if (g_file_get_contents (path, &cmd, &len, NULL) &&
		    bytes_contain (cmd, len, token))
			found = pid;
		g_free (cmd);
		g_free (path);
	}
	g_dir_close (dir);
	return found;
}

#define MAX_THREADS 8

typedef struct
{
	const FsFetchRequest *req;
	GBytes  *body;
	GError  *error;
	gdouble  elapsed;
} Run;

typedef struct
{
	const gchar *expect, *sha, *msg, *msg_is;
	gint64       len, msg_max;
	gdouble      within;
} Expect;

static gpointer
run_fetch (gpointer data)
{
	Run *r = data;
	gint64 t0 = g_get_monotonic_time ();

	r->body = fs_fetch (r->req, &r->error);
	r->elapsed = (gdouble) (g_get_monotonic_time () - t0) /
	             G_USEC_PER_SEC;
	return NULL;
}

static gboolean
mark_dispatched (gpointer data)
{
	*(gboolean *) data = TRUE;
	return G_SOURCE_REMOVE;
}

static gboolean
is_printable_ascii (const gchar *s)
{
	for (; *s != '\0'; s++)
		if ((guchar) *s < 0x20 || (guchar) *s > 0x7e)
			return FALSE;
	return TRUE;
}

/* This process's peak resident memory so far (VmHWM), in KiB. */
static guint64
peak_kib (void)
{
	gchar *status = NULL, *line;
	guint64 kib = 0;

	if (!g_file_get_contents ("/proc/self/status", &status, NULL, NULL))
		return 0;
	line = strstr (status, "\nVmHWM:");
	if (line != NULL)
		kib = g_ascii_strtoull (line + 7, NULL, 10);
	g_free (status);
	return kib;
}

/* The descriptors this process holds now (the listing's own one
 * included, the same every time). */
static guint
open_fds (void)
{
	GDir *dir = g_dir_open ("/proc/self/fd", 0, NULL);
	guint n = 0;

	if (dir == NULL)
		return 0;
	while (g_dir_read_name (dir) != NULL)
		n++;
	g_dir_close (dir);
	return n;
}

/* The same once it holds still.  GLib's worker thread closes the
 * child's pidfd just after it has reported the exit, so for a moment
 * after fs_fetch() returns one more descriptor may still be open; a
 * real leak never goes away. */
static guint
settled_fds (void)
{
	guint n = open_fds (), prev;

	for (guint i = 0; i < 20; i++) {
		g_usleep (G_USEC_PER_SEC / 50);
		prev = n;
		n = open_fds ();
		if (n == prev)
			break;
	}
	return n;
}

static void
check_run (const Run *r, const Expect *x, const gchar *what)
{
	gint got = outcome (r->body, r->error);

	if (r->body != NULL)
		g_print ("      (%s: ok, %" G_GSIZE_FORMAT " bytes in "
		         "%.2f s)\n", what, g_bytes_get_size (r->body),
		         r->elapsed);
	else
		g_print ("      (%s: %s in %.2f s: %s)\n", what,
		         code_name (got), r->elapsed,
		         r->error != NULL ? r->error->message : "?");

	CHECK (got == code_from_name (x->expect), "%s: %s (got %s)", what,
	       x->expect, code_name (got));
	if (x->len >= 0)
		CHECK (r->body != NULL &&
		       g_bytes_get_size (r->body) == (gsize) x->len,
		       "%s: the body has %" G_GINT64_FORMAT " bytes", what,
		       x->len);
	if (x->sha != NULL) {
		gchar *hex = r->body != NULL
			? g_compute_checksum_for_bytes (G_CHECKSUM_SHA256,
			                                r->body)
			: NULL;

		CHECK (g_strcmp0 (hex, x->sha) == 0,
		       "%s: the body is the file the server sent", what);
		g_free (hex);
	}
	if (r->error != NULL) {
		CHECK (strchr (r->error->message, '\n') == NULL &&
		       strchr (r->error->message, '\r') == NULL &&
		       g_str_has_prefix (r->error->message,
		                         "Could not download: "),
		       "%s: the message is one line for the UI", what);
		/* What curl printed comes from a remote host's doing: no
		 * escape sequence, tab or other control byte may reach a
		 * terminal, a log line or the UI through it. */
		CHECK (is_printable_ascii (r->error->message),
		       "%s: the message is printable ASCII only", what);
	}
	if (x->msg != NULL)
		CHECK (r->error != NULL &&
		       strstr (r->error->message, x->msg) != NULL,
		       "%s: the message says \"%s\"", what, x->msg);
	if (x->msg_is != NULL)
		CHECK (r->error != NULL &&
		       strcmp (r->error->message, x->msg_is) == 0,
		       "%s: the message is \"%s\"", what, x->msg_is);
	if (x->msg_max >= 0)
		CHECK (r->error != NULL &&
		       (gint64) strlen (r->error->message) <= x->msg_max,
		       "%s: the message has at most %" G_GINT64_FORMAT
		       " bytes (%" G_GSIZE_FORMAT ")", what, x->msg_max,
		       r->error != NULL ? strlen (r->error->message) : 0);
	if (x->within >= 0)
		CHECK (r->elapsed <= x->within, "%s: returned within %.0f s "
		       "(%.2f s)", what, x->within, r->elapsed);
}

static gint
cmd_fetch (gint argc, gchar **argv)
{
	FsFetchRequest req = { NULL, 1024 * 1024, 20, NULL, NULL };
	Expect x = { "ok", NULL, NULL, NULL, -1, -1, -1 };
	Run runs[MAX_THREADS];
	const gchar *what = "fetch", *gone = NULL;
	gboolean isolated = FALSE, dispatched = FALSE;
	guint threads = 1, idle = 0, repeat = 1, fds_first = 0;
	gint alive = 0;
	gint64 peak_growth = -1;
	guint64 peak_before = 0;

	memset (runs, 0, sizeof runs);
	for (gint i = 2; i < argc; i++) {
		const gchar *a = argv[i];
		const gchar *v = i + 1 < argc ? argv[i + 1] : NULL;

		if (a[0] != '-' || a[1] != '-') {
			req.url = a;
			continue;
		}
		if (strcmp (a, "--isolated") == 0) {
			isolated = TRUE;
			continue;
		}
		if (v == NULL) {
			g_printerr ("%s needs a value\n", a);
			return 2;
		}
		i++;
		if (strcmp (a, "--what") == 0)          what = v;
		else if (strcmp (a, "--max") == 0)      req.max_bytes = g_ascii_strtoull (v, NULL, 10);
		else if (strcmp (a, "--timeout") == 0)  req.timeout_s = (guint) g_ascii_strtoull (v, NULL, 10);
		else if (strcmp (a, "--proxy") == 0)    req.proxy = v;
		else if (strcmp (a, "--threads") == 0)  threads = (guint) g_ascii_strtoull (v, NULL, 10);
		else if (strcmp (a, "--repeat") == 0)   repeat = (guint) g_ascii_strtoull (v, NULL, 10);
		else if (strcmp (a, "--peak-growth") == 0) peak_growth = g_ascii_strtoll (v, NULL, 10);
		else if (strcmp (a, "--expect") == 0)   x.expect = v;
		else if (strcmp (a, "--len") == 0)      x.len = g_ascii_strtoll (v, NULL, 10);
		else if (strcmp (a, "--sha256") == 0)   x.sha = v;
		else if (strcmp (a, "--msg") == 0)      x.msg = v;
		else if (strcmp (a, "--msg-is") == 0)   x.msg_is = v;
		else if (strcmp (a, "--msg-max") == 0)  x.msg_max = g_ascii_strtoll (v, NULL, 10);
		else if (strcmp (a, "--within") == 0)   x.within = g_ascii_strtod (v, NULL);
		else if (strcmp (a, "--gone") == 0)     gone = v;
		else {
			g_printerr ("unknown option %s\n", a);
			return 2;
		}
	}
	if (req.url == NULL || threads < 1 || threads > MAX_THREADS ||
	    repeat < 1 || repeat > 50 || (repeat > 1 && threads > 1) ||
	    (peak_growth >= 0 && (threads > 1 || repeat > 1))) {
		g_printerr ("fetch: no URL, --threads not 1-%d, --repeat not "
		            "1-50, or --threads, --repeat or --peak-growth "
		            "together\n", MAX_THREADS);
		return 2;
	}
	(void) code_from_name (x.expect);   /* a typo is a usage error */

	/* One after the other, every outcome checked.  The first fetch
	 * also starts what GLib keeps for good (its worker thread and
	 * wakeup descriptors), so the count is taken after it: every
	 * later one must hand back all it opened, pipes included. */
	if (repeat > 1) {
		for (guint i = 0; i < repeat; i++) {
			gchar *label = g_strdup_printf ("%s [%u of %u]", what,
			                                i + 1, repeat);

			memset (&runs[0], 0, sizeof runs[0]);
			runs[0].req = &req;
			run_fetch (&runs[0]);
			check_run (&runs[0], &x, label);
			g_free (label);
			g_clear_error (&runs[0].error);
			if (runs[0].body != NULL)
				g_bytes_unref (runs[0].body);
			if (i == 0)
				fds_first = settled_fds ();
		}
		{
			guint fds_last = settled_fds ();

			CHECK (fds_last == fds_first,
			       "%s: %u fetches in a row leave no descriptor "
			       "open (%u after the first, %u after the last)",
			       what, repeat, fds_first, fds_last);
		}
		if (gone != NULL)
			CHECK (process_with_token (gone) == 0,
			       "%s: no curl is left running after %u fetches",
			       what, repeat);
		return failures ? 1 : 0;
	}

	/* A source of the caller's own (global default) context, ready at
	 * once: a fs_fetch() that iterated that context instead of its own
	 * would run it. */
	if (isolated)
		idle = g_idle_add (mark_dispatched, &dispatched);

	for (guint i = 0; i < threads; i++)
		runs[i].req = &req;
	if (threads == 1) {
		peak_before = peak_kib ();
		run_fetch (&runs[0]);
	} else {
		GThread *th[MAX_THREADS];

		for (guint i = 0; i < threads; i++)
			th[i] = g_thread_new ("fetch", run_fetch, &runs[i]);
		for (guint i = 0; i < threads; i++)
			g_thread_join (th[i]);
	}
	if (gone != NULL)
		alive = process_with_token (gone);

	for (guint i = 0; i < threads; i++) {
		gchar *label = threads > 1
			? g_strdup_printf ("%s [thread %u]", what, i + 1)
			: g_strdup (what);

		check_run (&runs[i], &x, label);
		g_free (label);
		g_clear_error (&runs[i].error);
		if (runs[i].body != NULL)
			g_bytes_unref (runs[i].body);
	}
	if (isolated) {
		CHECK (!dispatched, "%s: fs_fetch ran on its own main context "
		       "(nothing of the caller's was dispatched)", what);
		if (!dispatched)
			g_source_remove (idle);
	}
	if (gone != NULL)
		CHECK (alive == 0, "%s: curl is gone when fs_fetch returns "
		       "(%s)", what, alive != 0 ? "a process is still running"
		                                : "nothing left running");
	if (peak_growth >= 0) {
		guint64 grown = peak_kib () - peak_before;

		CHECK (peak_before > 0 && grown <= (guint64) peak_growth,
		       "%s: peak memory grew by at most %" G_GINT64_FORMAT
		       " KiB (%" G_GUINT64_FORMAT " KiB)", what, peak_growth,
		       grown);
	}
	return failures ? 1 : 0;
}

/* ============================================================= report */

/* "CapEff: 0000000000000000" -> no capability in that set. */
static gboolean
caps_none (const gchar *value)
{
	gchar *v;
	gboolean none;

	if (value == NULL)
		return FALSE;
	v = g_strstrip (g_strdup (value));
	none = *v != '\0' && strspn (v, "0") == strlen (v);
	g_free (v);
	return none;
}

/* This process's real, effective and saved ids and its groups, as one
 * line to compare before and after a fetch. */
static gchar *
own_credentials (void)
{
	uid_t ru, eu, su;
	gid_t rg, eg, sg;
	gid_t groups[256];
	gint n = getgroups (G_N_ELEMENTS (groups), groups);
	GString *out = g_string_new (NULL);

	if (getresuid (&ru, &eu, &su) != 0 || getresgid (&rg, &eg, &sg) != 0)
		g_string_append (out, "?");
	else
		g_string_append_printf (out, "uid %u %u %u gid %u %u %u",
		                        (guint) ru, (guint) eu, (guint) su,
		                        (guint) rg, (guint) eg, (guint) sg);
	g_string_append (out, " groups");
	for (gint i = 0; i < n; i++)
		g_string_append_printf (out, " %u", (guint) groups[i]);
	return g_string_free (out, FALSE);
}

/* "Uid: 65534 65534 65534 65534" -> every id equals want. */
static gboolean
ids_all (const gchar *line, guint want)
{
	gchar **ids;
	guint n = 0, bad = 0;

	if (line == NULL)
		return FALSE;
	ids = g_strsplit_set (line, " \t", -1);
	for (guint i = 0; ids[i] != NULL; i++) {
		if (*ids[i] == '\0')
			continue;
		n++;
		if (g_ascii_strtoull (ids[i], NULL, 10) != want)
			bad++;
	}
	g_strfreev (ids);
	return n == 4 && bad == 0;   /* real, effective, saved, filesystem */
}

static const gchar *
field (GPtrArray *lines, const gchar *prefix)
{
	for (guint i = 0; i < lines->len; i++) {
		const gchar *l = g_ptr_array_index (lines, i);

		if (g_str_has_prefix (l, prefix))
			return l + strlen (prefix);
	}
	return NULL;
}

/* The values of every line starting with prefix, in order. */
static gchar **
fields (GPtrArray *lines, const gchar *prefix)
{
	GPtrArray *out = g_ptr_array_new ();

	for (guint i = 0; i < lines->len; i++) {
		const gchar *l = g_ptr_array_index (lines, i);

		if (g_str_has_prefix (l, prefix))
			g_ptr_array_add (out, g_strdup (l + strlen (prefix)));
	}
	g_ptr_array_add (out, NULL);
	return (gchar **) g_ptr_array_free (out, FALSE);
}

/* "NAME NAME ...": the variables' names, never their values, at most
 * twelve. */
static gchar *
env_names (gchar **env)
{
	GString *out = g_string_new (NULL);
	guint n = g_strv_length (env);

	for (guint i = 0; i < n && i < 12; i++) {
		if (i > 0)
			g_string_append_c (out, ' ');
		g_string_append_len (out, env[i],
		                     (gssize) strcspn (env[i], "="));
	}
	if (n > 12)
		g_string_append_printf (out, " and %u more", n - 12);
	return g_string_free (out, FALSE);
}

static gint
cmd_report (gint argc, gchar **argv)
{
	FsFetchRequest req = { NULL, 1024 * 1024, 20, NULL, NULL };
	const gchar *what = "report", *marker = NULL;
	const gchar *curl = g_getenv ("STOCKFW_TEST_CURL");
	const gchar *cacert = g_getenv ("STOCKFW_TEST_CACERT");
	struct passwd *pw = getpwnam ("nobody");
	GError *error = NULL;
	GBytes *body;
	GPtrArray *lines;
	gchar **want_argv, **got_argv, **want_env, **got_env, **fds;
	gchar *text, *a, *b, *creds_before, *creds_after;
	const gchar *groups, *nnp;
	gint held = -1;
	guint leaked = 0;

	for (gint i = 2; i < argc; i++) {
		if (strcmp (argv[i], "--what") == 0 && i + 1 < argc)
			what = argv[++i];
		else if (strcmp (argv[i], "--marker") == 0 && i + 1 < argc)
			marker = argv[++i];
		else
			req.url = argv[i];
	}
	if (req.url == NULL || curl == NULL || pw == NULL ||
	    geteuid () != 0) {
		g_printerr ("report: needs root, a URL, STOCKFW_TEST_CURL and "
		            "an account `nobody'\n");
		return 2;
	}

	/* Deliberately not close-on-exec: only the spawn's own closing of
	 * descriptors keeps it from curl. */
	if (marker != NULL)
		held = open (marker, O_RDONLY);

	creds_before = own_credentials ();
	body = fs_fetch (&req, &error);
	creds_after = own_credentials ();
	if (held >= 0)
		close (held);
	/* The account change belongs in the child alone: a drop done in
	 * this process, or in a child that shares its memory, would leave
	 * the firewall itself without root. */
	CHECK (strcmp (creds_before, creds_after) == 0 &&
	       g_str_has_prefix (creds_after, "uid 0 0 0 gid 0 0 0 "),
	       "%s: the caller is still root with its own groups (%s)", what,
	       creds_after);
	g_free (creds_before);
	g_free (creds_after);
	CHECK (body != NULL, "%s: the stand-in curl ran and reported (%s)",
	       what, error != NULL ? error->message : "ok");
	if (body == NULL) {
		g_clear_error (&error);
		return 1;
	}

	{
		gchar *copy = g_strndup (g_bytes_get_data (body, NULL),
		                         g_bytes_get_size (body));
		gchar **split = g_strsplit (copy, "\n", -1);

		lines = g_ptr_array_new_with_free_func (g_free);
		for (guint i = 0; split[i] != NULL; i++)
			g_ptr_array_add (lines, g_strdup (split[i]));
		g_strfreev (split);
		g_free (copy);
	}

	/* ---- the account */
	CHECK (ids_all (field (lines, "Uid: "), pw->pw_uid),
	       "%s: curl runs as nobody: real, effective, saved and "
	       "filesystem uid %u (%s)", what, (guint) pw->pw_uid,
	       field (lines, "Uid: ") ? field (lines, "Uid: ") : "?");
	CHECK (ids_all (field (lines, "Gid: "), pw->pw_gid),
	       "%s: and every gid is nobody's group %u (%s)", what,
	       (guint) pw->pw_gid,
	       field (lines, "Gid: ") ? field (lines, "Gid: ") : "?");
	groups = field (lines, "Groups:");
	text = groups != NULL ? g_strstrip (g_strdup (groups)) : NULL;
	CHECK (text != NULL && *text == '\0',
	       "%s: with no supplementary groups (\"%s\")", what,
	       text != NULL ? text : "?");
	g_free (text);
	nnp = field (lines, "NoNewPrivs:");
	text = nnp != NULL ? g_strstrip (g_strdup (nnp)) : NULL;
	CHECK (g_strcmp0 (text, "1") == 0,
	       "%s: and no_new_privs set: no set-uid program can give root "
	       "back (%s)", what, text != NULL ? text : "?");
	g_free (text);
	/* Leaving uid 0 clears the permitted, effective and ambient sets;
	 * a capability kept through the change (a securebit, an ambient
	 * set) would be root's power under nobody's name. */
	{
		const gchar *prm = field (lines, "CapPrm: ");
		const gchar *eff = field (lines, "CapEff: ");
		const gchar *amb = field (lines, "CapAmb: ");

		CHECK (caps_none (prm) && caps_none (eff) && caps_none (amb),
		       "%s: and holds no capability: permitted, effective "
		       "and ambient sets empty (%s / %s / %s)", what,
		       prm != NULL ? prm : "?", eff != NULL ? eff : "?",
		       amb != NULL ? amb : "?");
	}

	/* ---- the environment.  On a mismatch only the names are shown:
	 * the values would be the caller's, tokens included. */
	want_env = fs_fetch_envp ();
	got_env = fields (lines, "env ");
	a = joined (want_env);
	b = env_names (got_env);
	CHECK (g_strv_equal ((const gchar * const *) want_env,
	                     (const gchar * const *) got_env),
	       "%s: curl's environment is exactly \"%s\" (got %u: %s)",
	       what, a, g_strv_length (got_env), b);
	g_free (a);
	g_free (b);
	g_strfreev (want_env);
	g_strfreev (got_env);

	/* ---- argv: exactly fs_fetch_argv(), plus --cacert before --url
	 * when the test CA is in use */
	want_argv = fs_fetch_argv (&req, curl);
	if (cacert != NULL && *cacert != '\0' && want_argv != NULL) {
		guint n = g_strv_length (want_argv);
		gchar **with = g_new0 (gchar *, n + 3);

		for (guint i = 0, k = 0; i < n; i++) {
			if (i == n - 2) {
				with[k++] = g_strdup ("--cacert");
				with[k++] = g_strdup (cacert);
			}
			with[k++] = g_strdup (want_argv[i]);
		}
		g_strfreev (want_argv);
		want_argv = with;
	}
	got_argv = fields (lines, "arg ");
	CHECK (g_strcmp0 (field (lines, "argv0 "), curl) == 0,
	       "%s: argv[0] is the curl path, absolute", what);
	a = want_argv != NULL ? g_strjoinv (" ", want_argv + 1)
	                      : g_strdup ("(null)");
	b = g_strjoinv (" ", got_argv);
	CHECK (want_argv != NULL &&
	       g_strv_equal ((const gchar * const *) (want_argv + 1),
	                     (const gchar * const *) got_argv),
	       "%s: curl's arguments are the golden argv (%s)", what, b);
	if (want_argv == NULL ||
	    !g_strv_equal ((const gchar * const *) (want_argv + 1),
	                   (const gchar * const *) got_argv))
		g_print ("      wanted: %s\n", a);
	CHECK (got_argv[0] != NULL && strcmp (got_argv[0], "-q") == 0,
	       "%s: -q is curl's first argument", what);
	g_free (a);
	g_free (b);
	g_strfreev (want_argv);
	g_strfreev (got_argv);

	/* ---- stdin, working directory, descriptors */
	CHECK (g_strcmp0 (field (lines, "stdin "), "/dev/null") == 0,
	       "%s: curl's stdin is /dev/null (%s)", what,
	       field (lines, "stdin ") ? field (lines, "stdin ") : "?");
	CHECK (g_strcmp0 (field (lines, "cwd "), "/") == 0,
	       "%s: curl's working directory is / (%s)", what,
	       field (lines, "cwd ") ? field (lines, "cwd ") : "?");
	fds = fields (lines, "fd ");
	for (guint i = 0; fds[i] != NULL; i++) {
		gchar *sp = strchr (fds[i], ' ');
		gint num = atoi (fds[i]);
		const gchar *target = sp != NULL ? sp + 1 : "";

		/* 0-2 are the pipes and /dev/null; the shell running the
		 * stand-in keeps its own script open; nothing else may be
		 * there, the held marker least of all. */
		if (num <= 2 || strcmp (target, curl) == 0)
			continue;
		g_print ("      descriptor %d reached curl: %s\n", num,
		         target);
		leaked++;
	}
	CHECK (leaked == 0 && g_strv_length (fds) >= 3,
	       "%s: no descriptor of the caller reached curl%s", what,
	       marker != NULL ? " (the held marker file included)" : "");
	g_strfreev (fds);

	g_ptr_array_unref (lines);
	g_bytes_unref (body);
	return failures ? 1 : 0;
}

/* =============================================================== main */

int
main (int argc, char **argv)
{
	if (argc >= 2 && strcmp (argv[1], "golden") == 0)
		return cmd_golden ();
	if (argc >= 3 && strcmp (argv[1], "fetch") == 0)
		return cmd_fetch (argc, argv);
	if (argc >= 3 && strcmp (argv[1], "report") == 0)
		return cmd_report (argc, argv);

	g_printerr ("usage: fs-fetch-test golden\n"
	            "       fs-fetch-test fetch [options] URL\n"
	            "       fs-fetch-test report [--what TEXT] "
	            "[--marker FILE] URL\n");
	return 2;
}
