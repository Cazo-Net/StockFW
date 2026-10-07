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
 * The static functions are reached by including the backend source,
 * exactly as the parser has no public entry point.  Windows-only: on
 * Linux this test builds nothing.
 *
 *   ./tests/test-winlog.sh
 */

#include <glib.h>
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

/* A wevtutil /f:text record for one permitted inbound SSH connection:
 * destination port 22, source an ephemeral client port. */
static const gchar *RECORD_A =
	"Event Id: 5156\r\n"
	"Date: 2026-10-07T09:15:01.1000000Z\r\n"
	"Description:\r\n"
	"The Windows Filtering Platform permitted a connection.\r\n"
	"\r\n"
	"Network Information:\r\n"
	"    Direction: Inbound\r\n"
	"    Source Address: 192.168.1.50\r\n"
	"    Source Port: 51234\r\n"
	"    Destination Address: 192.168.1.10\r\n"
	"    Destination Port: 22\r\n"
	"    Protocol: 6\r\n"
	"    Application Name: \\device\\harddiskvolume3\\openssh\\sshd.exe\r\n";

/* A blocked outbound DNS query: destination port 53, UDP. */
static const gchar *RECORD_B =
	"Event Id: 5157\r\n"
	"Date: 2026-10-07T09:15:02.2000000Z\r\n"
	"Description:\r\n"
	"The Windows Filtering Platform has blocked a connection.\r\n"
	"\r\n"
	"Network Information:\r\n"
	"    Direction: Outbound\r\n"
	"    Source Address: 192.168.1.10\r\n"
	"    Source Port: 49152\r\n"
	"    Destination Address: 8.8.8.8\r\n"
	"    Destination Port: 53\r\n"
	"    Protocol: 17\r\n"
	"    Application Name: \\device\\harddiskvolume3\\app\\resolver.exe\r\n";

/* No destination address: must be rejected, not shown half-filled. */
static const gchar *RECORD_JUNK =
	"Event Id: 5156\r\n"
	"Date: 2026-10-07T09:15:03.3000000Z\r\n"
	"Description:\r\n"
	"Something without any network information at all.\r\n";

static void
test_parse_inbound (void)
{
	FsHit hit = { 0 };

	CHECK (parse_firewall_event (RECORD_A, &hit),
	       "inbound record parses");

	CHECK (hit.port != NULL && g_strcmp0 (hit.port, "22") == 0,
	       "port is the destination port 22 (got %s)",
	       hit.port ? hit.port : "(null)");
	CHECK (g_strcmp0 (hit.direction, "in") == 0,
	       "direction reads in (got %s)",
	       hit.direction ? hit.direction : "(null)");
	CHECK (g_strcmp0 (hit.protocol, "TCP") == 0,
	       "protocol 6 becomes TCP (got %s)",
	       hit.protocol ? hit.protocol : "(null)");
	CHECK (g_strcmp0 (hit.source, "192.168.1.50") == 0,
	       "source address kept");
	CHECK (g_strcmp0 (hit.destination, "192.168.1.10") == 0,
	       "destination address kept");
	CHECK (g_strcmp0 (hit.in, "192.168.1.10") == 0,
	       "In column shows the local side (got %s)",
	       hit.in ? hit.in : "(null)");
	CHECK (g_strcmp0 (hit.out, "192.168.1.50") == 0,
	       "Out column shows the remote side (got %s)",
	       hit.out ? hit.out : "(null)");
	CHECK (hit.service != NULL && strstr (hit.service, "sshd.exe") != NULL,
	       "service names the application (got %s)",
	       hit.service ? hit.service : "(null)");
	CHECK (strstr (hit.service, "[BLOCKED]") == NULL,
	       "a permitted connection is not marked blocked");

	free_hit_fields (&hit);
}

static void
test_parse_blocked (void)
{
	FsHit hit = { 0 };

	CHECK (parse_firewall_event (RECORD_B, &hit),
	       "blocked record parses");

	CHECK (hit.port != NULL && g_strcmp0 (hit.port, "53") == 0,
	       "port is the destination port 53 (got %s)",
	       hit.port ? hit.port : "(null)");
	CHECK (g_strcmp0 (hit.direction, "out") == 0,
	       "direction reads out (got %s)",
	       hit.direction ? hit.direction : "(null)");
	CHECK (g_strcmp0 (hit.protocol, "UDP") == 0,
	       "protocol 17 becomes UDP (got %s)",
	       hit.protocol ? hit.protocol : "(null)");
	CHECK (hit.service != NULL &&
	       strstr (hit.service, "[BLOCKED]") != NULL,
	       "a blocked connection carries the blocked marker (got %s)",
	       hit.service ? hit.service : "(null)");
	CHECK (g_strcmp0 (hit.in, "192.168.1.10") == 0,
	       "outbound: In column shows the local side");
	CHECK (g_strcmp0 (hit.out, "8.8.8.8") == 0,
	       "outbound: Out column shows the remote side");

	free_hit_fields (&hit);
}

static void
test_parse_junk (void)
{
	FsHit hit = { 0 };

	CHECK (!parse_firewall_event (RECORD_JUNK, &hit),
	       "a record with no address is rejected");
	CHECK (hit.port == NULL && hit.time == NULL && hit.source == NULL,
	       "a rejected record leaks no fields");

	free_hit_fields (&hit);
}

/* The heart of it: what wevtutil hands back every five seconds when
 * the network is quiet is the same batch over and over.  The second
 * batch must produce nothing. */
static void
test_dedup_batches (void)
{
	guint delivered = 0;
	guint i;

	forget_all_records ();

	for (i = 0; i < 2; i++) {          /* poll 1, then poll 2 */
		const gchar *batch[] = { RECORD_A, RECORD_B, NULL };
		guint j;

		for (j = 0; batch[j] != NULL; j++) {
			if (record_seen (batch[j]))
				continue;

			remember_record (batch[j]);

			{
				FsHit hit = { 0 };

				if (parse_firewall_event (batch[j], &hit))
					delivered++;

				free_hit_fields (&hit);
			}
		}
	}

	CHECK (delivered == 2,
	       "the same batch twice delivers 2 events, not 4 (got %u)",
	       delivered);

	/* A genuinely new record still gets through. */
	CHECK (!record_seen (RECORD_JUNK), "an unseen record is not seen");
	remember_record (RECORD_JUNK);
	CHECK (record_seen (RECORD_JUNK), "a remembered record is seen");

	/* Stopping monitoring starts a clean slate: after a restart the
	 * newest events must be shown again, not swallowed as repeats. */
	forget_all_records ();
	CHECK (!record_seen (RECORD_A),
	       "forget_all_records clears the set (restart works)");
}

/* The table is bounded: it holds a couple of batches, never history. */
static void
test_dedup_bounded (void)
{
	gint i;

	forget_all_records ();

	for (i = 0; i < SEEN_RECORDS_MAX * 3; i++) {
		gchar *fake = g_strdup_printf ("synthetic record %d", i);

		remember_record (fake);
		g_free (fake);
	}

	CHECK (g_queue_get_length (&seen_order) <= SEEN_RECORDS_MAX,
	       "the seen set stays bounded (got %u entries)",
	       g_queue_get_length (&seen_order));

	/* The oldest entries were evicted, the newest are kept. */
	CHECK (!record_seen ("synthetic record 0"),
	       "the oldest record was evicted");

	{
		gchar *newest = g_strdup_printf ("synthetic record %d",
		                                 SEEN_RECORDS_MAX * 3 - 1);

		CHECK (record_seen (newest), "the newest record is kept");
		g_free (newest);
	}

	forget_all_records ();
}

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

	test_parse_inbound ();
	test_parse_blocked ();
	test_parse_junk ();
	test_dedup_batches ();
	test_dedup_bounded ();
	test_spawn_output_capture ();
	test_spawn_no_console ();
	test_spawn_timeout ();
	test_poll_async ();

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);

	return failures ? 1 : 0;
}
