/* Verifies the Windows event pipeline: de-duplication across polls and
 * the field mapping of parsed records.
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

int
main (void)
{
	test_parse_inbound ();
	test_parse_blocked ();
	test_parse_junk ();
	test_dedup_batches ();
	test_dedup_bounded ();

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);

	return failures ? 1 : 0;
}
