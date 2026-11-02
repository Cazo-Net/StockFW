/* Verifies the Windows event pipeline: de-duplication across polls and
 * the field mapping of parsed records, plus the process-spawning
 * behaviour the "(Not Responding)" fix rests on.
 *
 * The bugs this guards against:
 *
 *  1. The poll loop skipped a record only when its text contained "the
 *     last timestamp", which was really the previously processed
 *     record's timestamp.  Two identical batches (what wevtutil returns
 *     every five seconds when nothing new happens) therefore came out
 *     as two full deliveries -- the Events list filled with copies.
 *
 *  2. "port" was filled from Source Port (an ephemeral client port) so
 *     every service lookup missed, and Destination Port went into the
 *     "Out" column, which the original reserved for the interface.
 *
 *  3. The protocol number-to-name conversion overwrote the allocated
 *     string without freeing it (a leak per event).
 *
 *  4. Children were spawned through g_spawn_sync, which cannot pass
 *     CREATE_NO_WINDOW: every wevtutil poll flashed a console window
 *     and its unbounded wait on the main loop froze the UI behind a
 *     paused conhost.  spawn_capture() must give children no console
 *     window, must kill them at the timeout, and the poll must run
 *     the query on a worker thread (poll_in_flight goes FALSE only
 *     when the main-loop delivery has run).
 *
 *  5. The fixtures invented a record format wevtutil never emits.
 *     Real output carries "Event[n]" markers, indented headers and
 *     NUL padding; g_strsplit stops at the first NUL and a blank-line
 *     split cuts records in half, so live events never appeared even
 *     with the log readable.  On top of that, stock Windows has the
 *     "Filtering Platform Connection" audit off, so the log holds
 *     nothing to parse -- log_start now enables it while it holds
 *     Administrator rights.  The end-to-end test drives the whole
 *     path through a fake wevtutil.exe whose output is byte-honest.
 *
 *  6. (1.0.7) Each poll read only the newest ten events (/c:10), so a
 *     burst of thousands reached the list as ten.  Every poll now
 *     reads every 5156/5157 event after the last record it delivered,
 *     in XML (core/fs-winevt.c, whose parsing and bookkeeping
 *     tests/test-winevt.sh checks on every platform).  The text-form
 *     parser and the seen-record set that items 1 and 5 were about
 *     are gone with it; test_e2e_delivery drives the new reader
 *     through the real spawn against a fake log of thousands of
 *     events (fake-wevtutil.c, tests/winevt-fixture.h).
 *
 * The static functions are reached by including the backend source,
 * exactly as the parser has no public entry point.  Windows-only: on
 * Linux this test builds nothing.
 *
 *   ./tests/test-winlog.sh
 */

#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

/* The unit under test.  Its own headers are pulled in by the source. */
#include "platform/windows/fs-backend-windows.c"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	if (!(cond)) {                                             \
		printf ("FAIL: ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
		failures++;                                        \
	} else {                                                  \
		printf ("ok:   ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
	}                                                         \
} while (0)

/* ---------------------------------------------------------------------
 * spawn_capture() and the asynchronous poll: the console-window flash
 * and the "(Not Responding)" freeze.
 */

/* The test binary re-invokes itself as the child whose console state
 * is being inspected. */
static gchar *
self_exe (void)
{
	WCHAR wide[MAX_PATH];
	DWORD len = GetModuleFileNameW (NULL, wide, G_N_ELEMENTS (wide));

	if (len == 0 || len >= G_N_ELEMENTS (wide))
		return NULL;

	return g_utf16_to_utf8 (wide, -1, NULL, NULL, NULL);
}

/* [ test_spawn_output_capture ]
 * The cheapest end-to-end proof that spawn_capture() captures: a child
 * writes to stdout, the parent reads it back from the temp file. */
static void
test_spawn_output_capture (void)
{
	gchar *args[] = { "cmd.exe", "/c", "echo hello from the child", NULL };
	gchar *output = NULL;
	gchar *err_text = NULL;
	gint status = -1;
	gboolean ok;

	ok = spawn_capture (args, 10000, &output, &err_text, &status, NULL);

	CHECK (ok, "spawn_capture starts cmd.exe");
	CHECK (ok && status == 0,
	       "the child exited 0 (got %d)", status);
	CHECK (output != NULL &&
	       strstr (output, "hello from the child") != NULL,
	       "the child's stdout was captured (got %s)",
	       output ? g_strstrip (output) : "(null)");

	g_free (output);
	g_free (err_text);
}

/* [ test_spawn_no_console ]
 * The window flash itself: the child started by spawn_capture() must
 * have no console window (CREATE_NO_WINDOW), while the same child
 * started by a plain CreateProcess -- the behaviour g_spawn had --
 * does get one.  The control only has teeth where the parent process
 * itself has a console; in a console-less environment (mintty,
 * Windows Terminal's pseudo console) both sides legitimately report
 * no window, and the test says so rather than pretending it checked
 * something. */
static void
test_spawn_no_console (void)
{
	gchar *self = self_exe ();
	gchar *args[3];
	gchar *output = NULL;
	gint status = -1;
	gboolean ok;
	gchar *line;
	gint captured_console = -1;

	if (self == NULL) {
		CHECK (FALSE, "could not resolve the test binary's own path");
		return;
	}

	args[0] = self;
	args[1] = "--console-report";
	args[2] = NULL;

	ok = spawn_capture (args, 10000, &output, NULL, &status, NULL);

	CHECK (ok, "spawn_capture starts the console-report child");

	line = (ok && output != NULL)
	       ? strstr (output, "console_window=") : NULL;
	if (line != NULL)
		captured_console =
			(gint) g_ascii_strtoll (line + strlen ("console_window="),
			                        NULL, 10);

	/* The invariant the fix exists for -- holds in every
	 * environment, windowed console or pseudo console. */
	CHECK (captured_console == 0,
	       "spawn_capture's child has no console window (got %d)",
	       captured_console);

	g_free (output);

	/* Control: same child, plain CreateProcess, no
	 * CREATE_NO_WINDOW -- exactly what g_spawn used to do. */
	{
		gchar *cmd_line = build_command_line (args);
		gunichar2 *wide = g_utf8_to_utf16 (cmd_line, -1, NULL,
		                                   NULL, NULL);
		STARTUPINFOW si;
		PROCESS_INFORMATION pi;
		DWORD code = (DWORD) -1;

		memset (&si, 0, sizeof si);
		si.cb = sizeof si;
		memset (&pi, 0, sizeof pi);

		if (wide != NULL &&
		    CreateProcessW (NULL, wide, NULL, NULL, FALSE, 0,
		                    NULL, NULL, &si, &pi)) {
			WaitForSingleObject (pi.hProcess, 10000);
			GetExitCodeProcess (pi.hProcess, &code);
			CloseHandle (pi.hThread);
			CloseHandle (pi.hProcess);
		}
		g_free (wide);
		g_free (cmd_line);

		if (GetConsoleWindow () != NULL) {
			/* Teeth: this environment can show the difference,
			 * so the control must prove the probe detects one. */
			CHECK (code == 1,
			       "control: without CREATE_NO_WINDOW the child "
			       "does get a console window (got exit %lu)",
			       (unsigned long) code);
		} else {
			printf ("note: no console in this environment; "
			        "control spawn reported exit %ld\n",
			        (long) code);
		}
	}

	g_free (self);
}

/* [ test_spawn_timeout ]
 * The freeze: a child that never finishes must be killed when the
 * budget runs out and reported as ERROR_TIMEOUT, instead of blocking
 * the caller -- which on the GTK main loop meant "(Not Responding)". */
static void
test_spawn_timeout (void)
{
	gchar *args[] = { "cmd.exe", "/c", "ping -n 30 127.0.0.1", NULL };
	gchar *output = NULL;
	gint status = -1;
	gint64 t0;
	gint64 elapsed_ms;
	gboolean ok;

	t0 = g_get_monotonic_time ();
	ok = spawn_capture (args, 1500, &output, NULL, &status, NULL);
	elapsed_ms = (g_get_monotonic_time () - t0) / 1000;

	CHECK (ok, "a child killed at the timeout still counts as started");
	CHECK (status == ERROR_TIMEOUT,
	       "the killed child reports ERROR_TIMEOUT 1460 (got %d)",
	       status);
	CHECK (elapsed_ms < 10000,
	       "the wait ended at the 1500ms budget, not at the child's "
	       "30s ping (took %ld ms)", (long) elapsed_ms);

	g_free (output);
}

/* [ test_poll_async ]
 * The tick must dispatch to a worker and deliver on the main loop --
 * never run wevtutil on the calling thread.  poll_in_flight is the
 * observable: TRUE after dispatch, FALSE only once the delivery
 * callback has run.  A synchronous implementation fails the second
 * check; one that removes poll_in_flight fails to compile. */
static void
test_poll_async (void)
{
	gint waits;

	CHECK (!poll_in_flight,
	       "no query is in flight before the first tick");

	poll_events (NULL);   /* must return without running wevtutil */

	CHECK (poll_in_flight,
	       "the tick dispatched a worker instead of blocking");

	/* The worker runs a real wevtutil query (exit 5 without
	 * Administrator rights, well inside the 10s spawn budget) and
	 * posts the result back; pump until the delivery ran. */
	for (waits = 0; poll_in_flight && waits < 1500; waits++) {
		g_main_context_iteration (NULL, FALSE);
		g_usleep (10000);   /* 1500 * 10ms = 15s > spawn budget */
	}
	g_main_context_iteration (NULL, FALSE);

	CHECK (!poll_in_flight,
	       "the worker's result was delivered on the main loop");

	/* Stopping must invalidate a result still on its way. */
	{
		guint before = log_generation;

		firewalled_log_stop ();
		CHECK (log_generation > before,
		       "stopping bumps the generation so a late result "
		       "from the old session is dropped");
	}
}

/* [ test_e2e_delivery ]
 * End-to-end through every stage the production path uses, without
 * needing Administrator rights: a fake wevtutil.exe sits beside the
 * test binary (CreateProcess finds it before System32) and answers
 * like a Security log holding the records STOCKFW_FAKE_WEVTUTIL_LOG
 * names ("first last", tests/winevt-fixture.h), honouring the
 * query's EventRecordID>, /c: and /rd:, with NUL padding.  log_start's
 * probe, the worker thread, spawn_capture_max's temp-file capture,
 * NUL stripping, XML parsing, the cursor and main-loop delivery all
 * have to work for the counts below. */
static guint   e2e_hits = 0;
static gchar  *e2e_port = NULL;
static gchar  *e2e_direction = NULL;
static gchar  *e2e_in = NULL;
static gchar  *e2e_out = NULL;
static gchar  *e2e_last_time = NULL;
static gboolean e2e_ordered = TRUE;

static void
on_e2e_hit (const FsHit *hit, gpointer user_data)
{
	(void) user_data;

	e2e_hits++;
	if (e2e_hits == 1) {
		e2e_port = g_strdup (hit->port);
		e2e_direction = g_strdup (hit->direction);
		e2e_in = g_strdup (hit->in);
		e2e_out = g_strdup (hit->out);
	}
	/* Oldest first: the fixture's times rise with the record number
	 * (within an hour, which every batch here stays in). */
	if (e2e_last_time != NULL && hit->time != NULL &&
	    strcmp (hit->time, e2e_last_time) < 0)
		e2e_ordered = FALSE;
	g_free (e2e_last_time);
	e2e_last_time = g_strdup (hit->time);
}

/* Pump the main loop until the in-flight query has been delivered. */
static void
e2e_pump (void)
{
	gint waits;

	for (waits = 0; poll_in_flight && waits < 3500; waits++) {
		g_main_context_iteration (NULL, FALSE);
		g_usleep (10000);   /* 35 s cap, past the 30 s poll budget */
	}
	g_main_context_iteration (NULL, FALSE);
}

static void
e2e_poll (const gchar *log)
{
	g_setenv ("STOCKFW_FAKE_WEVTUTIL_LOG", log, TRUE);
	poll_events (NULL);
	e2e_pump ();
}

static void
test_e2e_delivery (void)
{
	GError *error = NULL;
	gboolean started;
	gchar *args_path, *args_text = NULL;
	guint before;

	/* The fake must be next to the test binary; test-winlog.sh
	 * builds it.  Failing loudly here beats failing obscurely in the
	 * probe below. */
	{
		gchar *self = self_exe ();
		gchar *dir = self != NULL ? g_path_get_dirname (self) : NULL;
		gchar *fake = dir != NULL
		              ? g_build_filename (dir, "wevtutil.exe", NULL)
		              : NULL;
		gunichar2 *wfake = fake != NULL
		                   ? g_utf8_to_utf16 (fake, -1, NULL, NULL, NULL)
		                   : NULL;
		gboolean present = wfake != NULL &&
		                   GetFileAttributesW (wfake) !=
		                   INVALID_FILE_ATTRIBUTES;

		CHECK (present,
		       "fake wevtutil.exe sits beside the test binary");
		g_free (wfake);
		g_free (fake);
		g_free (dir);
		g_free (self);

		if (!present)
			return;
	}

	args_path = g_build_filename (g_get_tmp_dir (),
	                              "stockfw-fake-wevtutil-args.txt", NULL);
	g_remove (args_path);
	g_setenv ("STOCKFW_FAKE_WEVTUTIL_ARGS", args_path, TRUE);
	g_setenv ("STOCKFW_FAKE_WEVTUTIL_LOG", "1 2", TRUE);

	e2e_hits = 0;
	e2e_ordered = TRUE;
	g_clear_pointer (&e2e_port, g_free);
	g_clear_pointer (&e2e_direction, g_free);
	g_clear_pointer (&e2e_in, g_free);
	g_clear_pointer (&e2e_out, g_free);
	g_clear_pointer (&e2e_last_time, g_free);

	started = firewalled_log_start (on_e2e_hit, NULL, &error);

	CHECK (started,
	       "log_start's probe runs against the fake wevtutil%s%s",
	       started ? "" : ": ",
	       started ? "" : (error != NULL ? error->message : "no error"));

	if (!started) {
		g_clear_error (&error);
		g_free (args_path);
		return;
	}
	CHECK (log_cursor.last_id == 2,
	       "start: the reader starts after the newest record (got %"
	       G_GUINT64_FORMAT ")", log_cursor.last_id);

	e2e_poll ("1 2");
	CHECK (e2e_hits == 0,
	       "records from before the start are not delivered (got %u)",
	       e2e_hits);

	/* The owner's case: 4,000 events in one five-second poll
	 * (records 3..4006, four of them logons the query leaves out). */
	e2e_poll ("1 4006");
	CHECK (e2e_hits == 4000,
	       "a burst of 4,000 arrives whole end-to-end (got %u)", e2e_hits);
	CHECK (e2e_ordered, "oldest first");
	CHECK (g_strcmp0 (e2e_port, "22") == 0 &&
	       g_strcmp0 (e2e_direction, "in") == 0,
	       "the first hit is record 3: inbound, port 22 (got %s %s)",
	       e2e_direction ? e2e_direction : "(null)",
	       e2e_port ? e2e_port : "(null)");
	CHECK (g_strcmp0 (e2e_in, "192.168.1.10") == 0 &&
	       g_strcmp0 (e2e_out, "192.168.1.50") == 0,
	       "the delivered hit shows local/remote addresses");
	CHECK (firewalled_log_skipped () == 0, "nothing skipped");

	/* The fake answers the same log again: nothing twice. */
	e2e_poll ("1 4006");
	CHECK (e2e_hits == 4000,
	       "the next poll re-delivers nothing (got %u)", e2e_hits);

	/* Past the cap: 30,030 records more; the newest 10,000 come, the
	 * rest is counted. */
	before = e2e_hits;
	e2e_poll ("1 34036");
	CHECK (e2e_hits - before == FS_WINEVT_POLL_CAP,
	       "past the cap: 10,000 delivered (got %u)", e2e_hits - before);
	CHECK (firewalled_log_skipped () > 0 &&
	       firewalled_log_skipped () == log_cursor.skipped,
	       "the skip shows through log_skipped (%" G_GUINT64_FORMAT ")",
	       firewalled_log_skipped ());

	/* The log is cleared: numbers start again at 1. */
	before = e2e_hits;
	e2e_poll ("1 5");
	e2e_poll ("1 5");
	CHECK (e2e_hits - before == 5 && log_cursor.clears == 1,
	       "after a clear the 5 new records arrive (got %u)",
	       e2e_hits - before);

	/* An event log that refuses the record condition: the poll asks
	 * again without it, and only the new records come. */
	before = e2e_hits;
	{
		guint64 skipped = firewalled_log_skipped ();

		g_setenv ("STOCKFW_FAKE_WEVTUTIL_NO_RECORDID", "1", TRUE);
		e2e_poll ("1 9");
		g_unsetenv ("STOCKFW_FAKE_WEVTUTIL_NO_RECORDID");
		CHECK (e2e_hits - before == 4 &&
		       firewalled_log_skipped () == skipped,
		       "a refused record condition: the 4 new records still "
		       "arrive, once, nothing counted as skipped (got %u)",
		       e2e_hits - before);

		/* Still refused, and the log is cleared and gets 3 new
		 * records, all below the cursor (9).  The fallback answers
		 * them whatever the cursor; the probe used to run only on
		 * an answer without <Event, so the clear was never seen
		 * and nothing arrived. */
		before = e2e_hits;
		g_setenv ("STOCKFW_FAKE_WEVTUTIL_NO_RECORDID", "1", TRUE);
		e2e_poll ("1 3");
		g_unsetenv ("STOCKFW_FAKE_WEVTUTIL_NO_RECORDID");
		CHECK (e2e_hits - before == 3 && log_cursor.clears == 2,
		       "a refused record condition and a cleared log: the "
		       "clear is seen and the 3 new records arrive (got %u)",
		       e2e_hits - before);
	}

	/* What the fake was run with, one line per run, each argument in
	 * brackets: the query must arrive as one argument. */
	if (g_file_get_contents (args_path, &args_text, NULL, NULL)) {
		CHECK (strstr (args_text,
		               "[/q:*[System[(EventID=5156 or EventID=5157) and "
		               "EventRecordID>4006]]][/c:10000][/rd:true][/f:xml]")
		       != NULL,
		       "the poll's query reached wevtutil as one argument");
		CHECK (strstr (args_text, "[/c:10]") == NULL,
		       "no poll asked for ten");
		CHECK (strstr (args_text, "[qe][Security][/c:1][/rd:true][/f:xml]")
		       != NULL,
		       "the probe asked for the newest record of any kind");
	} else {
		CHECK (FALSE, "the fake recorded its arguments in %s", args_path);
	}

	firewalled_log_stop ();
	CHECK (!poll_in_flight, "monitoring stopped cleanly");

	g_unsetenv ("STOCKFW_FAKE_WEVTUTIL_ARGS");
	g_unsetenv ("STOCKFW_FAKE_WEVTUTIL_LOG");
	g_remove (args_path);
	g_free (args_path);
	g_free (args_text);
	g_clear_pointer (&e2e_port, g_free);
	g_clear_pointer (&e2e_direction, g_free);
	g_clear_pointer (&e2e_in, g_free);
	g_clear_pointer (&e2e_out, g_free);
	g_clear_pointer (&e2e_last_time, g_free);
}

/* [ run_spawn_probe ]
 * The real teeth for the window-flash bug, run as a separate
 * invocation (--spawn-probe) from test-winlog.sh after FreeConsole().
 * This process then has no console at all -- precisely what
 * StockFW.exe is -- so both spawns reproduce the production shape:
 *
 *   (a) spawn_capture() must give the child no console window.
 *       g_spawn's behaviour (a plain CreateProcess from a
 *       console-less parent) created a fresh conhost window every
 *       time, which is the flash the screenshot caught.  If
 *       CREATE_NO_WINDOW ever disappears from spawn_capture, this
 *       check fails: the child would report console_window=1.
 *
 *   (b) the control: the same child, started the plain way from this
 *       console-less parent, must get a console.  That proves this
 *       environment can exhibit the difference at all -- without it,
 *       (a) passing would prove nothing.
 */
static void
run_spawn_probe (void)
{
	gchar *self = self_exe ();
	gchar *args[3];
	gchar *output = NULL;
	gint status = -1;
	gboolean ok;
	gchar *line;
	gint captured_console = -1;
	DWORD control_code = (DWORD) -1;

	if (self == NULL) {
		CHECK (FALSE, "could not resolve the test binary's own path");
		return;
	}

	args[0] = self;
	args[1] = "--console-report";
	args[2] = NULL;

	/* (a) The production spawn. */
	ok = spawn_capture (args, 10000, &output, NULL, &status, NULL);

	CHECK (ok, "probe: spawn_capture starts the child");

	line = (ok && output != NULL)
	       ? strstr (output, "console_window=") : NULL;
	if (line != NULL)
		captured_console =
			(gint) g_ascii_strtoll (line + strlen ("console_window="),
			                        NULL, 10);

	CHECK (captured_console == 0,
	       "probe: a console-less parent's capture child has no "
	       "console window (got %d)", captured_console);

	g_free (output);

	/* (b) The control: plain CreateProcess, no CREATE_NO_WINDOW --
	 * exactly what g_spawn did.  From a parent with no console this
	 * must produce one. */
	{
		gchar *cmd_line = build_command_line (args);
		gunichar2 *wide = g_utf8_to_utf16 (cmd_line, -1, NULL,
		                                   NULL, NULL);
		STARTUPINFOW si;
		PROCESS_INFORMATION pi;

		memset (&si, 0, sizeof si);
		si.cb = sizeof si;
		memset (&pi, 0, sizeof pi);

		if (wide != NULL &&
		    CreateProcessW (NULL, wide, NULL, NULL, FALSE, 0,
		                    NULL, NULL, &si, &pi)) {
			WaitForSingleObject (pi.hProcess, 10000);
			GetExitCodeProcess (pi.hProcess, &control_code);
			CloseHandle (pi.hThread);
			CloseHandle (pi.hProcess);
			CHECK (control_code == 1,
			       "probe: control -- without CREATE_NO_WINDOW a "
			       "console-less parent's child does get a console "
			       "(teeth, got exit %lu)",
			       (unsigned long) control_code);
		} else {
			CHECK (FALSE, "probe: the control spawn did not start");
		}

		g_free (wide);
		g_free (cmd_line);
	}

	g_free (self);
}

int
main (int argc, char **argv)
{
	/* Child mode: spawned by the tests below to report whether
	 * Windows gave it a console window.  The exit code carries the
	 * same answer for the control spawn, which reads no output. */
	if (argc > 1 && g_strcmp0 (argv[1], "--console-report") == 0) {
		HWND console = GetConsoleWindow ();

		printf ("console_window=%d\n", console != NULL ? 1 : 0);
		return console != NULL ? 1 : 0;
	}

	/* Probe mode: become what StockFW.exe is -- a process with no
	 * console at all -- and reproduce the production shape of the
	 * window-flash bug from there.  stdout must be redirected to a
	 * file by the caller: FreeConsole() drops a console stdout, while
	 * a file handle keeps working.  See run_spawn_probe(). */
	if (argc > 1 && g_strcmp0 (argv[1], "--spawn-probe") == 0) {
		FreeConsole ();
		Sleep (200);   /* let the released console settle */
		run_spawn_probe ();
		return failures ? 1 : 0;
	}

	test_spawn_output_capture ();
	test_spawn_no_console ();
	test_spawn_timeout ();
	test_poll_async ();
	test_e2e_delivery ();

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);

	return failures ? 1 : 0;
}
