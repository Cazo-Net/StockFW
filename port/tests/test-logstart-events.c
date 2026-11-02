/* End-to-end test of the Linux event monitor: a real kernel-log line
 * must travel the whole path -- fork, tail -F, pipe, 250ms poll,
 * fs_netparse_log_line, callback -- and arrive as a correctly
 * populated FsHit.  A foreign line with no STOCKFW-DROP marker must not.
 *
 * This is the gap test-logstart.c left open: that one proves the
 * monitor is either honestly running or honestly refused.  It never
 * proves that when it IS running, traffic actually shows up -- the
 * silent-empty-list failure is exactly a monitor that runs but parses
 * nothing.
 *
 * Driven through STOCKFW_LOG_FILE, the backend's own override seam, so
 * the real tail/parser code runs against a scratch file.  Needs root
 * (the backend refuses without it).
 *
 * Timing note: tail -n 0 -F prints only lines that arrive AFTER it
 * opens the file, so a single append right after log_start() can be
 * lost to the fork/exec race (diagnosed: immediate append -> 0 caught,
 * settled append -> 1).  The test therefore wakes the monitor with a
 * sentinel line (SRC=0.0.0.0) until delivery is PROVEN, then and only
 * then appends the line it asserts on.  Sentinels are counted apart
 * from the assertion line, so a late sentinel cannot fake a result.
 *
 *   sudo ./tests/test-logstart-events.sh
 */

#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-backend.h"
#include "core/fs-util.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	if (!(cond)) {                                             \
		printf ("FAIL: ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
		failures++;                                         \
	} else {                                                  \
		printf ("ok:   ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
	}                                                         \
} while (0)

/* The callback receives a pointer to on_log_poll's stack FsHit, freed
 * the moment it returns.  Deep-copy the fields under test or they
 * dangle before the assertions run.
 * Shape: "src|dst|proto|port|out|in|dir|service" */
static GPtrArray *seen;

static void
on_hit (const FsHit *hit, gpointer user_data)
{
	(void) user_data;

	g_ptr_array_add (seen,
		g_strdup_printf ("%s|%s|%s|%s|%s|%s|%s|%s",
		                 hit->source ? hit->source : "-",
		                 hit->destination ? hit->destination : "-",
		                 hit->protocol ? hit->protocol : "-",
		                 hit->port ? hit->port : "-",
		                 hit->out ? hit->out : "-",
		                 hit->in ? hit->in : "-",
		                 hit->direction ? hit->direction : "-",
		                 hit->service ? hit->service : "-"));
}

/* Iterate the default main context for up to timeout_ms, or until
 * count_matching(prefix) >= want.  Non-blocking iteration still fires
 * the 250ms poll source: it becomes ready after 250ms of wall time and
 * the next iteration dispatches it. */
static guint count_matching (const gchar *prefix);

static gboolean
spin_until_match (const gchar *prefix, guint want, gint timeout_ms)
{
	gint64 deadline = g_get_monotonic_time () + (gint64) timeout_ms * 1000;

	while (count_matching (prefix) < want &&
	       g_get_monotonic_time () < deadline)
		g_main_context_iteration (NULL, FALSE);

	return count_matching (prefix) >= want;
}

static gboolean
spin_ms (gint timeout_ms)
{
	gint64 deadline = g_get_monotonic_time () + (gint64) timeout_ms * 1000;

	while (g_get_monotonic_time () < deadline)
		g_main_context_iteration (NULL, FALSE);

	return TRUE;
}

static guint
count_matching (const gchar *prefix)
{
	guint i, n = 0;

	for (i = 0; i < seen->len; i++) {
		const gchar *s = g_ptr_array_index (seen, i);

		if (g_str_has_prefix (s, prefix))
			n++;
	}

	return n;
}

static const gchar *
first_matching (const gchar *prefix)
{
	guint i;

	for (i = 0; i < seen->len; i++) {
		const gchar *s = g_ptr_array_index (seen, i);

		if (g_str_has_prefix (s, prefix))
			return s;
	}

	return NULL;
}

int
main (void)
{
	const FsBackend *backend = fs_backend ();
	GError *error = NULL;
	gchar *dir;
	gchar *logfile;
	gchar *line;
	gboolean started;

	seen = g_ptr_array_new_with_free_func (g_free);

	if (backend->log_start == NULL) {
		printf ("SKIP: this backend has no event source\n");
		return 0;
	}

	/* Scratch log, pointed at by the backend's own override. */
	dir = g_dir_make_tmp ("stockfw-logtest-XXXXXX", NULL);
	logfile = g_build_filename (dir, "kern.log", NULL);
	g_file_set_contents (logfile, "", 0, NULL);
	g_setenv ("STOCKFW_LOG_FILE", logfile, TRUE);

	started = backend->log_start (on_hit, NULL, &error);
	CHECK (started, "log_start succeeds as root (with STOCKFW_LOG_FILE)");
	if (!started) {
		printf ("    reason: %s\n", error ? error->message : "(none)");
		return 1;
	}
	CHECK (backend->log_active (), "log_active reads TRUE while running");

	/* WAKE: append a sentinel every 200ms until one is delivered.  This
	 * both clears the fork/exec race and PROVES the pipeline moves
	 * traffic -- a monitor that runs but parses nothing is the exact
	 * silent failure this test exists to catch. */
	{
		gint64 deadline = g_get_monotonic_time () + 8 * G_USEC_PER_SEC;

		while (count_matching ("0.0.0.0|") == 0 &&
		       g_get_monotonic_time () < deadline) {
			line = g_strdup (
				"Oct 11 14:29:59 kali kernel: STOCKFW-DROP "
				"IN=eth9 OUT= SRC=0.0.0.0 DST=0.0.0.0 "
				"PROTO=TCP SPT=1 DPT=1");
			fs_util_append_to_file (logfile, line, TRUE);
			g_free (line);
			spin_ms (200);
		}
	}
	CHECK (count_matching ("0.0.0.0|") >= 1,
	       "monitor delivers: a real STOCKFW-DROP line reached the "
	       "callback through fork -> tail -> pipe -> poll -> parse");

	/* THE LINE UNDER TEST: full rsyslog-style format, every key the
	 * parser extracts.  Sentinel delivery above means tail is following,
	 * so this single append is not racing anything. */
	line = g_strdup (
		"Oct 11 14:30:00 kali kernel: [ 1234.567890] STOCKFW-DROP "
		"IN=eth0 OUT= SRC=192.0.2.10 DST=198.51.100.20 "
		"PROTO=TCP SPT=54321 DPT=443 LEN=60");
	fs_util_append_to_file (logfile, line, TRUE);
	g_free (line);

	spin_until_match ("192.0.2.10|", 1, 5000);

	CHECK (count_matching ("192.0.2.10|") == 1,
	       "the assertion line arrived exactly once (got %u)",
	       count_matching ("192.0.2.10|"));

	if (count_matching ("192.0.2.10|") >= 1) {
		const gchar *s = first_matching ("192.0.2.10|");

		/* The port is the DESTINATION port (443, the service being
		 * reached) and OUT stays the empty interface it was.  This
		 * line used to read "...|54321|443|eth0|in": SPT landed in
		 * the Port column and DPT overwrote the OUT interface, so
		 * every Linux event was named after its ephemeral source
		 * port.  The service carries the blocked marker, because
		 * every line the script logs is a drop. */
		CHECK (strcmp (s,
		               "192.0.2.10|198.51.100.20|TCP|443||eth0|in|"
		               "HTTPS [BLOCKED]") == 0,
		       "every field parsed: src, dst, proto, destination port, "
		       "empty OUT, in-interface, direction, service + blocked "
		       "marker -- got [%s]", s);
	}

	/* REJECT mode logs with its own prefix.  Before, only
	 * STOCKFW-DROP was recognised, so choosing "reject" in Advanced
	 * Options silently emptied the Events page. */
	line = g_strdup (
		"2026-10-11T14:30:00.500000+02:00 kali kernel: [ 1234.6] "
		"STOCKFW-REJECT IN=eth0 OUT= SRC=192.0.2.11 "
		"DST=198.51.100.21 LEN=40 PROTO=TCP SPT=40000 DPT=22");
	fs_util_append_to_file (logfile, line, TRUE);
	g_free (line);

	spin_until_match ("192.0.2.11|", 1, 5000);

	CHECK (count_matching ("192.0.2.11|") == 1 &&
	       g_str_has_suffix (first_matching ("192.0.2.11|"),
	                         "|22||eth0|in|SSH [BLOCKED]"),
	       "a STOCKFW-REJECT line is an event too, port 22 named SSH "
	       "and marked blocked -- got [%s]",
	       count_matching ("192.0.2.11|") ? first_matching ("192.0.2.11|")
	                                       : "(nothing)");

	/* One line written in two pieces, with a pause between them long
	 * enough for several polls to drain the first half on its own.
	 * The reader must wait for the newline instead of parsing two
	 * broken halves (the old reader split each read() on '\n' and
	 * dropped whatever straddled the boundary). */
	{
		FILE *fp = fopen (logfile, "a");

		fputs ("Oct 11 14:30:02 kali kernel: STOCKFW-DROP IN=eth0 OUT= "
		       "SRC=192.0.2.12 DST=19", fp);
		fclose (fp);
		spin_ms (700);

		fp = fopen (logfile, "a");
		fputs ("8.51.100.22 PROTO=UDP SPT=5000 DPT=53\n", fp);
		fclose (fp);
	}

	spin_until_match ("192.0.2.12|", 1, 5000);

	CHECK (count_matching ("192.0.2.12|") == 1 &&
	       g_str_has_prefix (first_matching ("192.0.2.12|"),
	                         "192.0.2.12|198.51.100.22|UDP|53|"),
	       "a line split across two reads arrives once and whole -- "
	       "got [%s]",
	       count_matching ("192.0.2.12|") ? first_matching ("192.0.2.12|")
	                                       : "(nothing)");

	/* A foreign line: same shape, no marker.  Must not become an event
	 * -- this is what keeps unrelated kernel noise off the Events page.
	 * Checked by its own sentinel source, immune to late wake lines. */
	line = g_strdup (
		"Oct 11 14:30:01 kali kernel: [ 1234.567891] "
		"IN=eth0 OUT= SRC=192.0.2.99 DST=198.51.100.99 "
		"PROTO=UDP SPT=1111 DPT=2222");
	fs_util_append_to_file (logfile, line, TRUE);
	g_free (line);

	spin_ms (800);   /* > several 250ms polls */

	CHECK (count_matching ("192.0.2.99|") == 0,
	       "a line without the STOCKFW-DROP marker is not reported "
	       "(foreign kernel noise stays off the page)");

	backend->log_stop ();
	CHECK (!backend->log_active (), "log_stop really stops it");

	g_clear_error (&error);
	g_unlink (logfile);
	g_rmdir (dir);

	printf ("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
