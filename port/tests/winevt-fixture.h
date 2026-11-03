/* A fake Windows Security log, for the Security-log reader's tests:
 * tests/test-winevt.c (every platform, through core/fs-winevt.c) and
 * tests/fake-wevtutil.c (the wevtutil.exe stand-in test-winlog.sh
 * puts beside the Windows test).  Plain C, no GLib, so the fake
 * wevtutil.exe builds with a bare compiler.
 *
 * The log holds the records first..last.  Record n is:
 *
 *   n odd    5156, permitted, inbound TCP to port 22 (sshd.exe),
 *            source port 40000 + n % 20000
 *   n even   5157, blocked, outbound UDP to port 53, from an
 *            application whose name has an XML entity in it
 *            ("r&amp;d.exe")
 *   n % 1000 == 999   4624 (a logon), no network fields: a record the
 *            firewall query never returns, but the newest-record
 *            probe can.
 *
 * Each record is wevtutil's raw /f:xml shape (single-quoted attributes,
 * %%14592 / %%14593 for the direction, the System block first), one
 * element after another with no root.  The fake adds the NUL padding
 * real wevtutil output carries; core/fs-winevt.c never sees it,
 * because the backend strips NULs at capture (read_handle_output).
 */
#ifndef WINEVT_FIXTURE_H
#define WINEVT_FIXTURE_H

#include <stdio.h>
#include <string.h>

static int
winevt_fixture_is_logon (unsigned long long n)
{
	return n % 1000 == 999;
}

/* One record, into buf.  Returns its length. */
static int
winevt_fixture_event (char *buf, size_t size, unsigned long long n)
{
	/* Record n was written n seconds after 2026-11-02T10:00:00Z, so
	 * the times rise with the record number across hours and days
	 * (until the end of November, past any log a test asks for).  They
	 * used to be "10:mm:ss" with mm = n / 60 % 60, which wrapped back
	 * to 10:00:00 at record 3600, and the end-to-end "oldest first"
	 * check of test-winlog, which reads the times, failed on a reader
	 * that delivered every record in order. */
	unsigned long long t = 36000ULL + n;
	unsigned day = (unsigned) (2 + t / 86400);
	unsigned hour = (unsigned) (t / 3600 % 24);
	unsigned min = (unsigned) (t / 60 % 60), sec = (unsigned) (t % 60);

	if (winevt_fixture_is_logon (n))
		return snprintf (buf, size,
			"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
			"<System><Provider Name='Microsoft-Windows-Security-Auditing' "
			"Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>"
			"<EventID>4624</EventID><Version>2</Version><Level>0</Level>"
			"<Task>12544</Task><Opcode>0</Opcode>"
			"<Keywords>0x8020000000000000</Keywords>"
			"<TimeCreated SystemTime='2026-11-%02uT%02u:%02u:%02u.0000000Z'/>"
			"<EventRecordID>%llu</EventRecordID><Correlation/>"
			"<Execution ProcessID='4' ThreadID='5028'/>"
			"<Channel>Security</Channel><Computer>DESKTOP-TEST</Computer>"
			"<Security/></System><EventData>"
			"<Data Name='TargetUserName'>someone</Data>"
			"<Data Name='LogonType'>2</Data></EventData></Event>\r\n",
			day, hour, min, sec, n);

	if (n % 2 == 1)
		return snprintf (buf, size,
			"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
			"<System><Provider Name='Microsoft-Windows-Security-Auditing' "
			"Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>"
			"<EventID>5156</EventID><Version>1</Version><Level>0</Level>"
			"<Task>12810</Task><Opcode>0</Opcode>"
			"<Keywords>0x8020000000000000</Keywords>"
			"<TimeCreated SystemTime='2026-11-%02uT%02u:%02u:%02u.1000000Z'/>"
			"<EventRecordID>%llu</EventRecordID><Correlation/>"
			"<Execution ProcessID='4' ThreadID='5028'/>"
			"<Channel>Security</Channel><Computer>DESKTOP-TEST</Computer>"
			"<Security/></System><EventData>"
			"<Data Name='ProcessID'>10812</Data>"
			"<Data Name='Application'>\\device\\harddiskvolume3\\openssh\\sshd.exe</Data>"
			"<Data Name='Direction'>%%%%14592</Data>"
			"<Data Name='SourceAddress'>192.168.1.50</Data>"
			"<Data Name='SourcePort'>%llu</Data>"
			"<Data Name='DestAddress'>192.168.1.10</Data>"
			"<Data Name='DestPort'>22</Data>"
			"<Data Name='Protocol'>6</Data>"
			"<Data Name='FilterRTID'>0</Data>"
			"<Data Name='LayerName'>%%%%14610</Data>"
			"<Data Name='LayerRTID'>44</Data>"
			"<Data Name='RemoteUserID'>S-1-0-0</Data>"
			"<Data Name='RemoteMachineID'>S-1-0-0</Data>"
			"</EventData></Event>\r\n",
			day, hour, min, sec, n, 40000 + n % 20000);

	return snprintf (buf, size,
		"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
		"<System><Provider Name='Microsoft-Windows-Security-Auditing' "
		"Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>"
		"<EventID>5157</EventID><Version>1</Version><Level>0</Level>"
		"<Task>12810</Task><Opcode>0</Opcode>"
		"<Keywords>0x8010000000000000</Keywords>"
		"<TimeCreated SystemTime='2026-11-%02uT%02u:%02u:%02u.2000000Z'/>"
		"<EventRecordID>%llu</EventRecordID><Correlation/>"
		"<Execution ProcessID='4' ThreadID='5028'/>"
		"<Channel>Security</Channel><Computer>DESKTOP-TEST</Computer>"
		"<Security/></System><EventData>"
		"<Data Name='ProcessID'>20000</Data>"
		"<Data Name='Application'>\\device\\harddiskvolume3\\app\\r&amp;d.exe</Data>"
		"<Data Name='Direction'>%%%%14593</Data>"
		"<Data Name='SourceAddress'>192.168.1.10</Data>"
		"<Data Name='SourcePort'>%llu</Data>"
		"<Data Name='DestAddress'>8.8.8.8</Data>"
		"<Data Name='DestPort'>53</Data>"
		"<Data Name='Protocol'>17</Data>"
		"<Data Name='FilterRTID'>0</Data>"
		"<Data Name='LayerName'>%%%%14611</Data>"
		"<Data Name='LayerRTID'>48</Data>"
		"<Data Name='RemoteUserID'>S-1-0-0</Data>"
		"<Data Name='RemoteMachineID'>S-1-0-0</Data>"
		"</EventData></Event>\r\n",
		day, hour, min, sec, n, 40000 + n % 20000);
}

typedef void (*WinevtFixtureWrite) (const char *bytes, size_t len,
                                    void *data);

/* What `wevtutil qe Security' answers for the log first..last:
 * firewall_only (a /q: naming 5156/5157) leaves the logons out, after
 * is the EventRecordID> of the query (0: none), count the /c:,
 * newest_first the /rd:true.  nul_padding adds a NUL after each
 * record, as real output has.  Returns how many records it wrote. */
static unsigned long long
winevt_fixture_query (unsigned long long first, unsigned long long last,
                      int firewall_only, unsigned long long after,
                      unsigned long long count, int newest_first,
                      int nul_padding, WinevtFixtureWrite write,
                      void *data)
{
	char buf[2048];
	unsigned long long lo = first > after + 1 ? first : after + 1;
	unsigned long long n, written = 0;

	if (last < lo || first == 0)
		return 0;

	for (n = 0; n <= last - lo && written < count; n++) {
		unsigned long long id = newest_first ? last - n : lo + n;
		int len;

		if (firewall_only && winevt_fixture_is_logon (id))
			continue;
		len = winevt_fixture_event (buf, sizeof buf, id);
		write (buf, (size_t) len, data);
		if (nul_padding)
			write ("\0", 1, data);
		written++;
	}
	return written;
}

#endif /* WINEVT_FIXTURE_H */
