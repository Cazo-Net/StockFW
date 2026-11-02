/* The Windows Security-log reader's logic (core/fs-winevt.c), on any
 * platform: wevtutil's XML parsed into the same rows the text reader
 * made, the query and argv each poll runs, and a poll loop against a
 * fake log (tests/winevt-fixture.h) through bursts, a burst past the
 * cap, a cut-short read, a cleared log and slow reads.
 *
 * Before 1.0.7 the Windows backend read the newest ten events every
 * five seconds (/c:10): a burst of 4,000 reached the list as ten.
 * These checks drive the code the backend now runs; test-winlog.sh
 * runs the same fake log through the real spawn on Windows.
 *
 *   cd port && bash tests/test-winevt.sh
 */

#include <glib.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-winevt.h"
#include "core/fs-eventstore.h"
#include "core/fs-netparse.h"
#include "core/fs-types.h"
#include "winevt-fixture.h"

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

/* ---- the fake log ------------------------------------------------- */

static void
to_gstring (const char *bytes, size_t len, void *data)
{
	g_string_append_len (data, bytes, (gssize) len);
}

/* What one poll's wevtutil would print for the log first..last, NULs
 * already stripped (as read_handle_output does). */
static gchar *
fake_poll (guint64 first, guint64 last, guint64 after, guint count)
{
	GString *out = g_string_new (NULL);

	winevt_fixture_query (first, last, TRUE, after, count, TRUE, FALSE,
	                      to_gstring, out);
	return g_string_free (out, FALSE);
}

static guint64
fake_newest (guint64 first, guint64 last)
{
	GString *out = g_string_new (NULL);
	GPtrArray *events;
	guint64 newest;

	winevt_fixture_query (first, last, FALSE, 0, 1, TRUE, FALSE,
	                      to_gstring, out);
	events = fs_winevt_parse_xml (out->str, NULL);
	newest = fs_winevt_newest (events);
	g_ptr_array_unref (events);
	g_string_free (out, TRUE);
	return newest;
}

/* Firewall records in a..b (the logons are not). */
static guint64
firewall_in (guint64 a, guint64 b)
{
	guint64 n = 0;

	for (guint64 id = a; id <= b; id++)
		if (!winevt_fixture_is_logon (id))
			n++;
	return n;
}

typedef struct
{
	guint   delivered;
	guint64 first_id, last_id;
	gboolean ascending;   /* each record above the one before   */
	FsEventStore *store;  /* when set, every hit goes in         */
} Poll;

/* One poll as the backend's poll_worker + poll_deliver run it: the
 * query after the cursor, the empty-poll probe, the take. */
static void
run_poll (FsWinEvtCursor *cursor, guint64 first, guint64 last, Poll *p)
{
	guint asked = cursor->cap;
	guint64 after = cursor->last_id;
	gchar *output = fake_poll (first, last, after, asked);
	GPtrArray *events, *fresh;
	gboolean cut = FALSE;
	guint64 prev = 0;

	{
		FsEventStore *store = p->store;

		memset (p, 0, sizeof *p);
		p->store = store;
	}
	p->ascending = TRUE;

	fs_winevt_poll_done (cursor, FALSE);
	if (after > 0 && strstr (output, "<Event") == NULL)
		fs_winevt_check_newest (cursor, fake_newest (first, last));

	events = fs_winevt_parse_xml (output, &cut);
	fresh = fs_winevt_take (cursor, events, asked, cut);
	for (guint i = 0; i < fresh->len; i++) {
		const FsWinEvent *e = g_ptr_array_index (fresh, i);

		if (i == 0)
			p->first_id = e->record_id;
		if (e->record_id <= prev)
			p->ascending = FALSE;
		prev = p->last_id = e->record_id;
		p->delivered++;
		if (p->store != NULL)
			fs_eventstore_append (p->store, e->hit, 0);
	}
	g_ptr_array_unref (fresh);
	g_ptr_array_unref (events);
	g_free (output);
}

/* ---- parsing ------------------------------------------------------ */

static FsWinEvent *
one_event (guint64 id, GPtrArray **keep)
{
	GString *out = g_string_new (NULL);
	GPtrArray *events;

	winevt_fixture_query (id, id, FALSE, 0, 1, TRUE, FALSE, to_gstring, out);
	events = fs_winevt_parse_xml (out->str, NULL);
	g_string_free (out, TRUE);
	*keep = events;
	return events->len == 1 ? g_ptr_array_index (events, 0) : NULL;
}

static void
test_parse (void)
{
	GPtrArray *keep;
	FsWinEvent *e;
	gboolean cut = TRUE;

	printf ("\n# parsing wevtutil /f:xml\n");

	e = one_event (1001, &keep);
	CHECK (e != NULL && e->record_id == 1001 && e->event_id == 5156 &&
	       e->hit != NULL, "5156: record 1001, a hit");
	if (e != NULL && e->hit != NULL) {
		FsHit *h = e->hit;

		CHECK (g_strcmp0 (h->direction, "in") == 0,
		       "%%%%14592 reads inbound (got %s)", h->direction);
		CHECK (g_strcmp0 (h->port, "22") == 0,
		       "port is the destination port (got %s)", h->port);
		CHECK (g_strcmp0 (h->source, "192.168.1.50") == 0 &&
		       g_strcmp0 (h->destination, "192.168.1.10") == 0,
		       "source and destination addresses");
		CHECK (g_strcmp0 (h->in, "192.168.1.10") == 0 &&
		       g_strcmp0 (h->out, "192.168.1.50") == 0,
		       "In/Out: the local side, then the remote, inbound");
		CHECK (g_strcmp0 (h->protocol, "TCP") == 0,
		       "protocol 6 reads TCP (got %s)", h->protocol);
		CHECK (g_strcmp0 (h->service, "sshd.exe") == 0,
		       "the service is the program's file name (got %s)",
		       h->service);
		CHECK (g_strcmp0 (h->time, "2026-11-02T10:16:41.1000000Z") == 0,
		       "the time is TimeCreated's SystemTime (got %s)", h->time);
		CHECK (!fs_hit_is_blocked (h), "a 5156 is not blocked");
	}
	g_ptr_array_unref (keep);

	e = one_event (1002, &keep);
	CHECK (e != NULL && e->event_id == 5157 && e->hit != NULL,
	       "5157: a hit");
	if (e != NULL && e->hit != NULL) {
		FsHit *h = e->hit;

		CHECK (g_strcmp0 (h->direction, "out") == 0,
		       "%%%%14593 reads outbound (got %s)", h->direction);
		CHECK (g_strcmp0 (h->protocol, "UDP") == 0, "protocol 17 reads UDP");
		CHECK (g_strcmp0 (h->in, "192.168.1.10") == 0 &&
		       g_strcmp0 (h->out, "8.8.8.8") == 0,
		       "In/Out: the local side, then the remote, outbound");
		CHECK (g_strcmp0 (h->service, "r&d.exe [BLOCKED]") == 0,
		       "&amp; unescaped and [BLOCKED] added (got %s)", h->service);
		CHECK (fs_hit_is_blocked (h), "a 5157 is blocked");
	}
	g_ptr_array_unref (keep);

	e = one_event (1999, &keep);
	CHECK (e != NULL && e->record_id == 1999 && e->event_id == 4624 &&
	       e->hit == NULL,
	       "another event id: its record number is read, no hit");
	g_ptr_array_unref (keep);

	/* Hand-written shapes: double quotes, the rendered direction words,
	 * a numeric reference, no DestAddress, no record number. */
	{
		const gchar *xml =
			"\xEF\xBB\xBF<Event xmlns=\"x\"><System><EventID Qualifiers=\"\">5157"
			"</EventID><TimeCreated SystemTime=\"2026-01-01T00:00:00Z\"/>"
			"<EventRecordID>7</EventRecordID></System><EventData>"
			"<Data Name=\"Direction\">Outbound</Data>"
			"<Data Name=\"Application\">C:\\a\\caf&#233;.exe</Data>"
			"<Data Name=\"DestAddress\">2001:db8::1</Data>"
			"<Data Name=\"DestPort\">443</Data>"
			"<Data Name=\"Protocol\">58</Data></EventData></Event>"
			"<Event><System><EventID>5156</EventID>"
			"<EventRecordID>8</EventRecordID></System><EventData>"
			"<Data Name=\"SourceAddress\">10.0.0.1</Data>"
			"</EventData></Event>"
			"<Event><System><EventID>5156</EventID></System><EventData>"
			"<Data Name=\"DestAddress\">10.0.0.2</Data></EventData></Event>";
		GPtrArray *events = fs_winevt_parse_xml (xml, &cut);
		FsWinEvent *a = events->len > 0 ? g_ptr_array_index (events, 0) : NULL;
		FsWinEvent *b = events->len > 1 ? g_ptr_array_index (events, 1) : NULL;
		FsWinEvent *c = events->len > 2 ? g_ptr_array_index (events, 2) : NULL;

		CHECK (events->len == 3 && !cut,
		       "three elements, a BOM before them, not cut");
		CHECK (a != NULL && a->hit != NULL && a->event_id == 5157 &&
		       g_strcmp0 (a->hit->direction, "out") == 0 &&
		       g_strcmp0 (a->hit->service, "caf\xC3\xA9.exe [BLOCKED]") == 0 &&
		       g_strcmp0 (a->hit->protocol, "58") == 0,
		       "double quotes, EventID with an attribute, \"Outbound\", "
		       "&#233; and an unknown protocol number");
		CHECK (b != NULL && b->hit == NULL && b->record_id == 8,
		       "no DestAddress: no hit (the text reader's rule)");
		CHECK (c != NULL && c->hit != NULL && c->record_id == 0,
		       "no record number: parsed, record 0");
		{
			FsWinEvtCursor cur;
			GPtrArray *fresh;

			fs_winevt_cursor_init (&cur, 0);
			fresh = fs_winevt_take (&cur, events, 100, FALSE);
			CHECK (fresh->len == 1 && cur.last_id == 8,
			       "take: record 0 is never delivered (it could not "
			       "be told from itself next poll), record 8 moves the "
			       "cursor though it has no hit");
			g_ptr_array_unref (fresh);
		}
		g_ptr_array_unref (events);
	}

	/* Cut short: the last element is half there. */
	{
		gchar *full = fake_poll (1, 10, 0, 100);
		gsize len = strlen (full);
		GPtrArray *events;

		full[len - 300] = '\0';
		events = fs_winevt_parse_xml (full, &cut);
		CHECK (cut && events->len == 9,
		       "cut short: the half element is left out and said "
		       "(got %u events, cut %d)", events->len, cut);
		g_ptr_array_unref (events);
		g_free (full);
	}

	{
		GPtrArray *events = fs_winevt_parse_xml ("", &cut);

		CHECK (events->len == 0 && !cut, "empty output: no events");
		g_ptr_array_unref (events);
		events = fs_winevt_parse_xml (NULL, &cut);
		CHECK (events->len == 0 && !cut, "NULL output: no events");
		g_ptr_array_unref (events);
	}
}

/* ---- the command ---------------------------------------------------- */

static void
test_argv (void)
{
	gchar **argv = fs_winevt_poll_argv (34002, 10000);
	gchar **probe = fs_winevt_probe_argv ();
	gchar *q0 = fs_winevt_query (0);
	const gchar *want[] = {
		"wevtutil.exe", "qe", "Security",
		"/q:*[System[(EventID=5156 or EventID=5157) and EventRecordID>34002]]",
		"/c:10000", "/rd:true", "/f:xml", NULL
	};
	const gchar *want_probe[] = {
		"wevtutil.exe", "qe", "Security", "/c:1", "/rd:true", "/f:xml", NULL
	};
	gboolean same = g_strv_length (argv) == 7;

	printf ("\n# the command each poll runs\n");

	for (guint i = 0; same && want[i] != NULL; i++)
		same = g_strcmp0 (argv[i], want[i]) == 0;
	CHECK (same, "poll argv: every 5156/5157 after the last record, "
	       "newest first, up to the cap, XML (argv[3] %s)",
	       argv[3] != NULL ? argv[3] : "(null)");
	CHECK (g_strcmp0 (argv[4], "/c:10") != 0, "not /c:10 any more");

	same = g_strv_length (probe) == 6;
	for (guint i = 0; same && want_probe[i] != NULL; i++)
		same = g_strcmp0 (probe[i], want_probe[i]) == 0;
	CHECK (same, "probe argv: the newest record of any kind");

	CHECK (g_strcmp0 (q0, "*[System[(EventID=5156 or EventID=5157)]]") == 0,
	       "after 0: no record condition");

	/* Built from numbers only: nothing a shell would read twice. */
	CHECK (strpbrk (argv[3], "&|<\"%^") == NULL,
	       "no shell metacharacter in the query (it goes as one argv "
	       "element, never through cmd.exe)");

	g_strfreev (argv);
	g_strfreev (probe);
	g_free (q0);
}

/* ---- the poll loop -------------------------------------------------- */

static void
test_loop (void)
{
	FsWinEvtCursor cur;
	Poll p = { 0 };
	FsEventStore *store = fs_eventstore_new (100000);
	gint64 t0, us;

	printf ("\n# polls against a fake log\n");

	/* Start: two old records in the log.  They are not delivered. */
	fs_winevt_cursor_init (&cur, fake_newest (1, 2));
	CHECK (cur.last_id == 2 && cur.cap == FS_WINEVT_POLL_CAP,
	       "start: the cursor sits after the newest record (2)");
	run_poll (&cur, 1, 2, &p);
	CHECK (p.delivered == 0, "nothing new: nothing delivered");

	/* The owner's case: 4,000 events in one five-second poll. */
	p.store = store;
	t0 = g_get_monotonic_time ();
	run_poll (&cur, 1, 4002 + 4, &p);   /* 4 logons in 3..4006 */
	us = g_get_monotonic_time () - t0;
	CHECK (p.delivered == 4000 && p.ascending && p.first_id == 3 &&
	       p.last_id == 4006,
	       "a burst of 4,000: all 4,000 delivered, oldest first, once "
	       "(got %u, %" G_GUINT64_FORMAT "..%" G_GUINT64_FORMAT ")",
	       p.delivered, p.first_id, p.last_id);
	CHECK (fs_eventstore_length (store) == 4000,
	       "all 4,000 are in the event store behind the list (%u)",
	       fs_eventstore_length (store));
	CHECK (cur.skipped == 0, "nothing skipped");
	printf ("      (parse and take of 4,000 events: %.1f ms)\n", us / 1000.0);

	run_poll (&cur, 1, 4006, &p);
	CHECK (p.delivered == 0 && cur.last_id == 4006,
	       "the same log again: nothing delivered twice");

	/* Three new records: just those. */
	run_poll (&cur, 1, 4009, &p);
	CHECK (p.delivered == 3 && p.first_id == 4007,
	       "three new: three delivered (got %u)", p.delivered);

	/* A burst past the cap: 30,000 firewall records and the logons
	 * among them.  The newest 10,000 are read, the rest counted. */
	{
		guint64 last = 4009, top = last;

		while (firewall_in (last + 1, top) < 30000)
			top++;
		t0 = g_get_monotonic_time ();
		run_poll (&cur, 1, top, &p);
		us = g_get_monotonic_time () - t0;
		CHECK (p.delivered == FS_WINEVT_POLL_CAP && p.ascending &&
		       p.last_id == top,
		       "past the cap: the newest 10,000 delivered, in order "
		       "(got %u)", p.delivered);
		CHECK (cur.skipped == p.first_id - last - 1 &&
		       cur.skipped >= firewall_in (last + 1, p.first_id - 1),
		       "skipped: the record gap below the oldest read, %"
		       G_GUINT64_FORMAT ", an upper bound on the %"
		       G_GUINT64_FORMAT " firewall events in it",
		       cur.skipped, firewall_in (last + 1, p.first_id - 1));
		printf ("      (parse and take of 10,000 events: %.1f ms)\n",
		        us / 1000.0);
		CHECK (us < 2 * G_USEC_PER_SEC,
		       "10,000 events parse in well under a poll (%.0f ms)",
		       us / 1000.0);
		last = top;

		run_poll (&cur, 1, last, &p);
		CHECK (p.delivered == 0, "the poll after: nothing again");
	}

	/* A cut-short read counts its gap even when it is not full. */
	{
		FsWinEvtCursor c2;
		gchar *out = fake_poll (1, 120, 100, 100);
		GPtrArray *events, *fresh;
		gboolean cut = FALSE;

		fs_winevt_cursor_init (&c2, 100);
		/* Newest first: cutting the end loses the oldest. */
		out[strlen (out) - 400] = '\0';
		events = fs_winevt_parse_xml (out, &cut);
		fresh = fs_winevt_take (&c2, events, 100, cut);
		CHECK (cut && fresh->len == 19 && c2.skipped == 1 &&
		       c2.last_id == 120,
		       "cut short: 19 of 20 delivered, the lost one counted");
		g_ptr_array_unref (fresh);
		g_ptr_array_unref (events);
		g_free (out);
	}

	/* The log is cleared: numbers start again at 1. */
	{
		guint64 before = cur.last_id;

		run_poll (&cur, 1, 5, &p);
		CHECK (p.delivered == 0 && cur.last_id == 0 && cur.clears == 1,
		       "cleared: the empty poll's probe (newest 5 < %"
		       G_GUINT64_FORMAT ") sends the cursor back to 0", before);
		run_poll (&cur, 1, 5, &p);
		CHECK (p.delivered == 5 && p.first_id == 1,
		       "after the clear: all 5 since it delivered (got %u)",
		       p.delivered);
		run_poll (&cur, 1, 5, &p);
		CHECK (p.delivered == 0 && cur.clears == 1,
		       "and not again; a quiet log is not taken for a clear");
	}

	/* Rollover keeps numbering: the oldest records go, nothing else
	 * changes. */
	{
		run_poll (&cur, 3, 8, &p);
		CHECK (p.delivered == 3 && p.first_id == 6 && cur.clears == 1,
		       "rollover (oldest records gone, numbers go on): only "
		       "the new ones");
	}

	/* Ids that come back below the cursor or twice are not delivered. */
	{
		FsWinEvtCursor c3;
		GString *s = g_string_new (NULL);
		GPtrArray *events, *fresh;

		winevt_fixture_query (1, 10, TRUE, 0, 100, TRUE, FALSE,
		                      to_gstring, s);
		winevt_fixture_query (5, 12, TRUE, 0, 100, FALSE, FALSE,
		                      to_gstring, s);
		fs_winevt_cursor_init (&c3, 4);
		events = fs_winevt_parse_xml (s->str, NULL);
		fresh = fs_winevt_take (&c3, events, 1000, FALSE);
		CHECK (fresh->len == 8 && c3.last_id == 12,
		       "two overlapping batches, both orders: 5..12 once each "
		       "(got %u)", fresh->len);
		g_ptr_array_unref (fresh);
		g_ptr_array_unref (events);
		g_string_free (s, TRUE);
	}

	/* The event log refused the record condition: the backend asks
	 * for the newest FS_WINEVT_FALLBACK_CAP with no condition.  The
	 * batch reaches back past the cursor, so only the new records are
	 * delivered and nothing counts as skipped, though it is full. */
	{
		FsWinEvtCursor c5;
		GString *s = g_string_new (NULL);
		GPtrArray *events, *fresh;

		/* 30 records, the newest 20 asked: 11..30 come back. */
		winevt_fixture_query (1, 30, TRUE, 0, 20, TRUE, FALSE,
		                      to_gstring, s);
		fs_winevt_cursor_init (&c5, 25);
		events = fs_winevt_parse_xml (s->str, NULL);
		fresh = fs_winevt_take (&c5, events, 20, FALSE);
		CHECK (fresh->len == 5 && c5.last_id == 30 && c5.skipped == 0,
		       "no record condition (fallback): a full batch reaching "
		       "back past the cursor delivers the 5 new, skips nothing "
		       "(got %u, skipped %" G_GUINT64_FORMAT ")", fresh->len,
		       c5.skipped);
		g_ptr_array_unref (fresh);
		g_ptr_array_unref (events);
		g_string_free (s, TRUE);
	}

	/* The same with a logon record (999) between the cursor (998) and
	 * the oldest new firewall record (1000): the batch still reaches
	 * back past the cursor, so record 999 is not counted as skipped. */
	{
		FsWinEvtCursor c6;
		GString *s = g_string_new (NULL);
		GPtrArray *events, *fresh;

		/* 980..1010, firewall only, the newest 20 asked: 990..1010
		 * without 999. */
		winevt_fixture_query (980, 1010, TRUE, 0, 20, TRUE, FALSE,
		                      to_gstring, s);
		fs_winevt_cursor_init (&c6, 998);
		events = fs_winevt_parse_xml (s->str, NULL);
		fresh = fs_winevt_take (&c6, events, 20, FALSE);
		CHECK (events->len == 20 && fresh->len == 11 &&
		       c6.last_id == 1010 && c6.skipped == 0,
		       "no record condition (fallback): a full batch reaching "
		       "back past the cursor over a logon record delivers the "
		       "11 new, skips nothing (read %u, got %u, skipped %"
		       G_GUINT64_FORMAT ")", events->len, fresh->len,
		       c6.skipped);
		g_ptr_array_unref (fresh);
		g_ptr_array_unref (events);
		g_string_free (s, TRUE);
	}

	/* Slow reads: half after a timeout, never below the floor, back up
	 * after reads that work. */
	{
		FsWinEvtCursor c4;
		guint steps = 0;

		fs_winevt_cursor_init (&c4, 0);
		fs_winevt_poll_done (&c4, TRUE);
		CHECK (c4.cap == FS_WINEVT_POLL_CAP / 2, "timeout: half (%u)", c4.cap);
		for (guint i = 0; i < 20; i++)
			fs_winevt_poll_done (&c4, TRUE);
		CHECK (c4.cap == FS_WINEVT_POLL_MIN, "never below %u (%u)",
		       FS_WINEVT_POLL_MIN, c4.cap);
		while (c4.cap < FS_WINEVT_POLL_CAP && steps < 20) {
			fs_winevt_poll_done (&c4, FALSE);
			steps++;
		}
		CHECK (c4.cap == FS_WINEVT_POLL_CAP && steps == 5,
		       "back to the cap in %u good polls", steps);
	}

	fs_eventstore_free (store);
}

int
main (void)
{
	test_parse ();
	test_argv ();
	test_loop ();

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);
	return failures ? 1 : 0;
}
