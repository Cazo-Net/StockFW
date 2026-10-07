/* A stand-in wevtutil.exe for test-winlog's end-to-end test.
 *
 * CreateProcess searches the calling process's directory before
 * System32, so this binary -- built next to the test -- answers the
 * backend's probe and every poll with a canned two-record Security
 * batch.  That exercises the whole production path (spawn_capture,
 * temp-file capture, NUL stripping, Event[ splitting, parsing,
 * de-duplication, worker thread + main-loop delivery) without
 * Administrator rights to read the real Security log.
 *
 * The batch is byte-honest against real `wevtutil qe ... /f:text`
 * output: "Event[n]" markers, indented headers, blank lines inside
 * the records -- and NUL padding after fixed-width values, exactly
 * the bytes that come off the wire on a real system.  The padding is
 * the point: if capture ever stops stripping it, g_strsplit
 * truncates at the first NUL, no fields survive, and the end-to-end
 * delivery check fails.
 *
 * Records mirror RECORD_A / RECORD_B in test-winlog.c (permitted
 * inbound SSH to port 22, blocked outbound DNS to port 53).
 *
 *   cc fake-wevtutil.c -o wevtutil.exe      (done by test-winlog.sh)
 */

#include <stdio.h>

int
main (void)
{
	/* String concatenation keeps the embedded \0 bytes; sizeof - 1
	 * hands fwrite every byte but the final terminator. */
	static const char batch[] =
		"Event[0]\r\n"
		"  Log Name: Security\r\n"
		"  Source: Microsoft-Windows-Security-Auditing\r\n"
		"  Date: 2026-10-07T09:15:01.1000000Z\r\n"
		"  Event ID: 5156\r\n"
		"  Task: Filtering Platform Connection\r\n"
		"  Level: Information\0\r\n"
		"  Keyword: Audit Success\r\n"
		"  Computer: DESKTOP-TEST\r\n"
		"  Description: \r\n"
		"The Windows Filtering Platform permitted a connection.\r\n"
		"\r\n"
		"    Application Information:\r\n"
		"        Process ID: 0x2a3c\r\n"
		"        Application Name: \\device\\harddiskvolume3\\openssh\\sshd.exe\r\n"
		"\r\n"
		"    Network Information:\r\n"
		"        Direction: Inbound\r\n"
		"        Source Address: 192.168.1.50\r\n"
		"        Source Port: 51234\r\n"
		"        Destination Address: 192.168.1.10\r\n"
		"        Destination Port: 22\r\n"
		"        Protocol: 6\r\n"
		"\r\n"
		"Event[1]\r\n"
		"  Log Name: Security\r\n"
		"  Source: Microsoft-Windows-Security-Auditing\r\n"
		"  Date: 2026-10-07T09:15:02.2000000Z\r\n"
		"  Event ID: 5157\r\n"
		"  Task: Filtering Platform Connection\r\n"
		"  Level: Information\0\r\n"
		"  Keyword: Audit Success\r\n"
		"  Computer: DESKTOP-TEST\r\n"
		"  Description: \r\n"
		"The Windows Filtering Platform has blocked a connection.\r\n"
		"\r\n"
		"    Application Information:\r\n"
		"        Process ID: 0x4e20\r\n"
		"        Application Name: \\device\\harddiskvolume3\\app\\resolver.exe\r\n"
		"\r\n"
		"    Network Information:\r\n"
		"        Direction: Outbound\r\n"
		"        Source Address: 192.168.1.10\r\n"
		"        Source Port: 49152\r\n"
		"        Destination Address: 8.8.8.8\r\n"
		"        Destination Port: 53\r\n"
		"        Protocol: 17\0\r\n"
		"\r\n";

	fwrite (batch, 1, sizeof (batch) - 1, stdout);
	fflush (stdout);

	return 0;
}
