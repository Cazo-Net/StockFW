/*---[ fake-curl.c ]-----------------------------------------------------
 * A stand-in for curl that fs_fetch() starts in tests/test-fetch-spawn.c
 * (STOCKFW_TEST_CURL).  It reads only --url and --user-agent and does
 * what the URL's path asks:
 *
 *   /ok            "fake curl body", then "console=<what it has>":
 *                  none (no console window), hidden (a window nobody
 *                  sees), visible (a window on the screen) on Windows,
 *                  n/a elsewhere
 *   /bytes/<n>     n bytes of 'x'
 *   /exit6         curl's "Could not resolve host" on stderr, exit 6
 *   /hang          sleeps two minutes
 *   /stderr-flood  4 MiB on stderr, then "flood done"
 *   /argv          every argument after argv[0], one "[arg]" per line
 *   /env           its whole environment, one entry per line
 *   /cwd           its working folder
 *   anything else  exit 22, as curl --fail on an HTTP error
 *
 * Plain C, no GLib: fs_fetch() gives it no PATH on Windows, so it must
 * start with no DLL beyond the system's.
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#else
#include <unistd.h>
extern char **environ;
#endif

static void
pause_seconds (unsigned s)
{
#ifdef _WIN32
	Sleep (s * 1000u);
#else
	sleep (s);
#endif
}

static const char *
console_state (void)
{
#ifdef _WIN32
	HWND w = GetConsoleWindow ();

	if (w == NULL)
		return "none";
	return IsWindowVisible (w) ? "visible" : "hidden";
#else
	return "n/a";
#endif
}

static void
print_env (void)
{
#ifdef _WIN32
	char *block = GetEnvironmentStringsA ();

	for (char *p = block; p != NULL && *p != '\0'; p += strlen (p) + 1)
		printf ("%s\n", p);
	if (block != NULL)
		FreeEnvironmentStringsA (block);
#else
	for (char **e = environ; *e != NULL; e++)
		printf ("%s\n", *e);
#endif
}

static void
print_cwd (void)
{
#ifdef _WIN32
	char buf[MAX_PATH + 1];
	DWORD n = GetCurrentDirectoryA (sizeof buf, buf);

	printf ("%s\n", n > 0 && n < sizeof buf ? buf : "?");
#else
	char buf[4096];

	printf ("%s\n", getcwd (buf, sizeof buf) != NULL ? buf : "?");
#endif
}

int
main (int argc, char **argv)
{
	const char *url = NULL;
	const char *path;

#ifdef _WIN32
	_setmode (_fileno (stdout), _O_BINARY);
	_setmode (_fileno (stderr), _O_BINARY);
#endif
	for (int i = 1; i + 1 < argc; i++)
		if (strcmp (argv[i], "--url") == 0)
			url = argv[i + 1];
	if (url == NULL || strncmp (url, "https://", 8) != 0) {
		fprintf (stderr, "curl: (3) URL rejected: no --url\n");
		return 3;
	}
	path = strchr (url + 8, '/');
	if (path == NULL)
		path = "/";

	if (strcmp (path, "/ok") == 0) {
		printf ("fake curl body\nconsole=%s\n", console_state ());
		return 0;
	}
	if (strncmp (path, "/bytes/", 7) == 0) {
		static char chunk[65536];
		unsigned long long left = strtoull (path + 7, NULL, 10);

		memset (chunk, 'x', sizeof chunk);
		while (left > 0) {
			size_t n = left < sizeof chunk ? (size_t) left
			                               : sizeof chunk;

			if (fwrite (chunk, 1, n, stdout) != n)
				return 23;   /* curl's "write error" */
			left -= n;
		}
		return 0;
	}
	if (strcmp (path, "/exit6") == 0) {
		fprintf (stderr, "curl: (6) Could not resolve host: "
		         "fake.invalid\n");
		return 6;
	}
	if (strcmp (path, "/hang") == 0) {
		pause_seconds (120);
		return 0;
	}
	if (strcmp (path, "/stderr-flood") == 0) {
		static char line[1024];

		memset (line, 'e', sizeof line - 1);
		line[sizeof line - 2] = '\n';
		for (int i = 0; i < 4096; i++)
			fputs (line, stderr);
		printf ("flood done\n");
		return 0;
	}
	if (strcmp (path, "/argv") == 0) {
		for (int i = 1; i < argc; i++)
			printf ("[%s]\n", argv[i]);
		return 0;
	}
	if (strcmp (path, "/env") == 0) {
		print_env ();
		return 0;
	}
	if (strcmp (path, "/cwd") == 0) {
		print_cwd ();
		return 0;
	}
	fprintf (stderr, "curl: (22) The requested URL returned error: "
	         "404\n");
	return 22;
}
