/* A stand-in wevtutil.exe for test-winlog's end-to-end test.
 *
 * CreateProcess searches the calling process's directory before
 * System32, so this binary -- built next to the test -- answers the
 * backend's probe and every poll.  That exercises the whole production
 * path (spawn_capture_max, temp-file capture, NUL stripping, XML
 * parsing, the record cursor, worker thread + main-loop delivery)
 * without Administrator rights to read the real Security log.
 *
 * It answers like a Security log holding the records
 * $STOCKFW_FAKE_WEVTUTIL_LOG names ("first last", default "1 2"),
 * each one as tests/winevt-fixture.h writes it -- wevtutil's raw
 * /f:xml shape -- with a NUL after each record, the padding real
 * output carries: if capture ever stops stripping it, parsing stops
 * at the first record and the counts in test_e2e_delivery fail.
 *
 * It takes what the backend sends: qe Security, an optional /q: (a
 * query naming EventID=5156 leaves the logon records out, and
 * "EventRecordID>N" starts after N), /c:N, /rd:true and /f:xml.
 * Anything else exits 87 (ERROR_INVALID_PARAMETER), as wevtutil does.
 * With $STOCKFW_FAKE_WEVTUTIL_NO_RECORDID=1 it refuses a query with an
 * EventRecordID condition (exit 15001, ERROR_EVT_INVALID_QUERY), as an
 * event log service that will not take it would.
 * With $STOCKFW_FAKE_WEVTUTIL_ARGS set it appends its arguments there,
 * one line per run, each in brackets, so the test can see the query
 * arrived as one argument.
 *
 *   cc -I tests fake-wevtutil.c -o wevtutil.exe   (done by test-winlog.sh)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#include "winevt-fixture.h"

static void
to_stdout (const char *bytes, size_t len, void *data)
{
	(void) data;
	fwrite (bytes, 1, len, stdout);
}

int
main (int argc, char **argv)
{
	unsigned long long first = 1, last = 2, after = 0;
	unsigned long long count = (unsigned long long) -1;
	int firewall_only = 0, newest_first = 0, xml = 0, i;
	const char *log = getenv ("STOCKFW_FAKE_WEVTUTIL_LOG");
	const char *args = getenv ("STOCKFW_FAKE_WEVTUTIL_ARGS");

	if (args != NULL && *args != '\0') {
		FILE *f = fopen (args, "ab");

		if (f != NULL) {
			for (i = 1; i < argc; i++)
				fprintf (f, "[%s]", argv[i]);
			fprintf (f, "\n");
			fclose (f);
		}
	}

	if (log != NULL)
		sscanf (log, "%llu %llu", &first, &last);

	if (argc < 3 || strcmp (argv[1], "qe") != 0 ||
	    strcmp (argv[2], "Security") != 0) {
		fprintf (stderr, "The parameter is incorrect.\n");
		return 87;
	}

	for (i = 3; i < argc; i++) {
		const char *a = argv[i];

		if (strncmp (a, "/q:", 3) == 0) {
			const char *id = strstr (a, "EventRecordID>");
			const char *refuse =
				getenv ("STOCKFW_FAKE_WEVTUTIL_NO_RECORDID");

			/* An event log service that will not take the
			 * record condition. */
			if (id != NULL && refuse != NULL && *refuse == '1') {
				fprintf (stderr, "The specified query is "
				         "invalid.\n");
				return 15001;
			}

			firewall_only = strstr (a, "EventID=5156") != NULL;
			if (id != NULL)
				after = strtoull (id + strlen ("EventRecordID>"),
				                  NULL, 10);
		} else if (strncmp (a, "/c:", 3) == 0) {
			count = strtoull (a + 3, NULL, 10);
		} else if (strcmp (a, "/rd:true") == 0) {
			newest_first = 1;
		} else if (strcmp (a, "/f:xml") == 0) {
			xml = 1;
		} else {
			fprintf (stderr, "The parameter is incorrect.\n");
			return 87;
		}
	}
	if (!xml) {
		fprintf (stderr, "The parameter is incorrect.\n");
		return 87;
	}

#ifdef _WIN32
	/* The fixture writes \r\n itself. */
	_setmode (_fileno (stdout), _O_BINARY);
#endif

	winevt_fixture_query (first, last, firewall_only, after, count,
	                      newest_first, 1, to_stdout, NULL);
	fflush (stdout);

	return 0;
}
