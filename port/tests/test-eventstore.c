/* The event store and the event history (core/fs-eventstore.c,
 * core/fs-eventlog.c).  GLib only; built by tests/test-eventstore.sh.
 *
 *   test-eventstore            the checks
 *   test-eventstore bench N    append N events, filter, write and load
 *                              history; prints times and RSS
 */

#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "core/fs-eventstore.h"
#include "core/fs-eventlog.h"
#include "core/fs-types.h"

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

/* A synthetic event: n picks the fields, so the same n is the same
 * event.  Time: 2026-11-02T10:00:00 + n/10 s, wevtutil-style. */
typedef struct
{
	gchar time[40], src[48], dst[48], port[8], len[8];
	FsHit hit;
} Ev;

static void
ev_make (Ev *e, guint n)
{
	gint64 ticks = 0;

	fs_event_time_parse ("2026-11-02T10:00:00.0000000Z", &ticks);
	ticks += (gint64) n * 1000000;   /* 0.1 s apart */
	fs_event_time_format (ticks, FS_EVENT_TIME_FRAC7, e->time);
	g_snprintf (e->src, sizeof e->src, "10.%u.%u.%u", (n / 65536) % 256,
	            (n / 256) % 256, n % 256 % 50);
	g_snprintf (e->dst, sizeof e->dst, "203.0.113.%u", n % 200);
	g_snprintf (e->port, sizeof e->port, "%u",
	            (n % 7 == 0) ? 22 : (n % 3 == 0) ? 53 : 443);
	g_snprintf (e->len, sizeof e->len, "%u", 40 + n % 1400);

	memset (&e->hit, 0, sizeof e->hit);
	e->hit.time        = e->time;
	e->hit.direction   = (n % 2) ? "In" : "Out";
	e->hit.in          = (n % 2) ? "eth0" : "";
	e->hit.out         = (n % 2) ? "" : "eth0";
	e->hit.port        = e->port;
	e->hit.source      = e->src;
	e->hit.destination = e->dst;
	e->hit.length      = e->len;
	e->hit.tos         = "0x00";
	e->hit.protocol    = (n % 3 == 0) ? "UDP" : "TCP";
	e->hit.service     = (n % 5 == 0) ? "SSH [BLOCKED]" : "HTTPS";
	e->hit.rule        = (n % 50 == 0) ? "Threat intel: Spamhaus DROP" : NULL;
}

static gboolean
hits_equal (const FsHit *a, const FsHit *b)
{
#define S(x) ((x) != NULL ? (x) : "")
	return strcmp (S (a->time), S (b->time)) == 0 &&
	       strcmp (S (a->direction), S (b->direction)) == 0 &&
	       strcmp (S (a->in), S (b->in)) == 0 &&
	       strcmp (S (a->out), S (b->out)) == 0 &&
	       strcmp (S (a->port), S (b->port)) == 0 &&
	       strcmp (S (a->source), S (b->source)) == 0 &&
	       strcmp (S (a->destination), S (b->destination)) == 0 &&
	       strcmp (S (a->length), S (b->length)) == 0 &&
	       strcmp (S (a->tos), S (b->tos)) == 0 &&
	       strcmp (S (a->protocol), S (b->protocol)) == 0 &&
	       strcmp (S (a->service), S (b->service)) == 0 &&
	       strcmp (S (a->rule), S (b->rule)) == 0;
#undef S
}

/* ------------------------------------------------------------ times */

static void
test_times (void)
{
	gint64 t = 0, t2 = 0;
	gchar buf[FS_EVENT_TIME_BUF];

	CHECK (fs_event_time_parse ("2026-10-09T12:35:34.0780000Z", &t) ==
	       FS_EVENT_TIME_FRAC7, "wevtutil stamp reads as FRAC7");
	fs_event_time_format (t, FS_EVENT_TIME_FRAC7, buf);
	CHECK (strcmp (buf, "2026-10-09T12:35:34.0780000Z") == 0,
	       "and comes back as the same text (got %s)", buf);

	{
		GDateTime *dt = g_date_time_new_from_iso8601 (
			"2026-10-09T12:35:34.078Z", NULL);

		CHECK (t / 10 == g_date_time_to_unix (dt) * G_USEC_PER_SEC +
		       g_date_time_get_microsecond (dt),
		       "ticks agree with GDateTime");
		g_date_time_unref (dt);
	}

	CHECK (fs_event_time_parse ("2026-10-09T12:00:05Z", &t2) ==
	       FS_EVENT_TIME_SECS, "kernel-log stamp reads as SECS");
	fs_event_time_format (t2, FS_EVENT_TIME_SECS, buf);
	CHECK (strcmp (buf, "2026-10-09T12:00:05Z") == 0,
	       "and comes back the same (got %s)", buf);
	CHECK (fs_event_time_parse ("2028-02-29T00:00:00Z", NULL) ==
	       FS_EVENT_TIME_SECS, "a leap day reads");
	CHECK (fs_event_time_parse ("2026-02-29T00:00:00Z", NULL) ==
	       FS_EVENT_TIME_OTHER, "29 February of a common year is text");
	CHECK (fs_event_time_parse ("2026-04-31T00:00:00Z", NULL) ==
	       FS_EVENT_TIME_OTHER, "31 April is text");
	CHECK (fs_event_time_parse ("12:00:00", NULL) == FS_EVENT_TIME_OTHER,
	       "a bare clock is text");
	CHECK (fs_event_time_parse ("2026-10-09T25:00:00Z", NULL) ==
	       FS_EVENT_TIME_OTHER, "hour 25 is text");
	CHECK (fs_event_time_parse ("2026-10-09T12:00:00.078Z", NULL) ==
	       FS_EVENT_TIME_OTHER, "a 3-digit fraction is text (kept whole)");

	fs_event_time_day (t, buf);
	CHECK (strcmp (buf, "2026-10-09") == 0, "UTC day of a stamp");
}

static void
test_time_specs (void)
{
	gint64 now = 1793613600LL * G_USEC_PER_SEC;  /* 2026-11-02 10:00 UTC */
	gint64 v = -1, v2 = -1;
	GError *error = NULL;

	CHECK (fs_event_parse_time_spec ("", now, FALSE, &v, NULL) && v == 0,
	       "empty: no bound");
	CHECK (fs_event_parse_time_spec ("2h", now, FALSE, &v, NULL) &&
	       v == now - 2 * 3600LL * G_USEC_PER_SEC, "2h: two hours back");
	CHECK (fs_event_parse_time_spec ("15m", now, FALSE, &v, NULL) &&
	       v == now - 15 * 60LL * G_USEC_PER_SEC, "15m");
	CHECK (fs_event_parse_time_spec ("3d", now, FALSE, &v, NULL) &&
	       v == now - 3 * 86400LL * G_USEC_PER_SEC, "3d");
	CHECK (fs_event_parse_time_spec ("now", now, FALSE, &v, NULL) &&
	       v == now, "now");
	CHECK (fs_event_parse_time_spec ("2026-11-01", now, FALSE, &v, NULL) &&
	       fs_event_parse_time_spec ("2026-11-01", now, TRUE, &v2, NULL) &&
	       v2 - v >= 23 * 3600LL * G_USEC_PER_SEC &&
	       v2 - v <= 25 * 3600LL * G_USEC_PER_SEC,
	       "a date as an end takes in the whole day");
	CHECK (fs_event_parse_time_spec ("2026-11-01 14:30", now, FALSE, &v2,
	                                 NULL) &&
	       v2 - v == (14 * 3600 + 30 * 60) * (gint64) G_USEC_PER_SEC,
	       "date and clock, local");
	CHECK (fs_event_parse_time_spec ("2026-11-01T14:30:00Z", now, FALSE,
	                                 &v, NULL) &&
	       v == 1793543400LL * G_USEC_PER_SEC, "an ISO stamp with Z");
	CHECK (!fs_event_parse_time_spec ("yesterday", now, FALSE, &v, &error) &&
	       error != NULL, "words are refused, with a reason");
	g_clear_error (&error);
	CHECK (!fs_event_parse_time_spec ("5x", now, FALSE, &v, NULL),
	       "an unknown unit is refused");
}

/* ----------------------------------------------------------- store */

typedef struct
{
	GArray *seqs;
	gboolean readable;
	FsEventStore *store;
} EvictLog;

static void
on_evict (FsEventStore *store, guint64 seq, gpointer data)
{
	EvictLog *log = data;

	g_array_append_val (log->seqs, seq);
	/* The event can still be read in the call. */
	if (!fs_eventstore_has (store, seq) ||
	    *fs_eventstore_field (store, seq, FS_EV_SOURCE) == '\0')
		log->readable = FALSE;
}

static void
test_store_basics (void)
{
	FsEventStore *s = fs_eventstore_new (10);
	Ev e;
	guint64 seq;
	FsHit *back;
	gchar buf[FS_EVENT_TIME_BUF];

	CHECK (fs_eventstore_capacity (s) == FS_EVENTSTORE_MIN_CAPACITY,
	       "a capacity below the minimum is raised to it");

	ev_make (&e, 5);
	seq = fs_eventstore_append (s, &e.hit, 0);
	CHECK (seq == 1, "the first event is seq 1");
	back = fs_eventstore_get_hit (s, seq);
	CHECK (back != NULL && hits_equal (back, &e.hit),
	       "every field comes back as given");
	fs_hit_free (back);
	CHECK (strcmp (fs_eventstore_time_text (s, seq, buf), e.time) == 0,
	       "the time text is rebuilt exactly");
	CHECK (fs_eventstore_is_blocked (s, seq), "SSH [BLOCKED] is blocked");
	CHECK (fs_eventstore_is_inbound (s, seq) && !fs_eventstore_is_outbound (s, seq),
	       "In is inbound");

	/* An unreadable stamp: kept as text, timed by its arrival. */
	{
		FsHit h = { 0 };

		h.time = "12:00:00";
		h.destination = "198.51.100.1";
		seq = fs_eventstore_append (s, &h, 1000000);
		CHECK (seq == 2 &&
		       strcmp (fs_eventstore_time_text (s, seq, buf), "12:00:00") == 0,
		       "a stamp in no known format is kept as text");
		CHECK (fs_eventstore_time_us (s, seq) == 1000000,
		       "and the event is timed by its arrival");
		back = fs_eventstore_get_hit (s, seq);
		CHECK (back->rule == NULL && back->source != NULL &&
		       *back->source == '\0', "absent fields read as empty");
		fs_hit_free (back);
	}

	fs_eventstore_free (s);
}

static void
test_store_eviction (void)
{
	FsEventStore *s = fs_eventstore_new (1000);
	EvictLog log = { g_array_new (FALSE, FALSE, sizeof (guint64)), TRUE, s };
	Ev e;
	gboolean in_order = TRUE;

	fs_eventstore_set_evict_func (s, on_evict, &log);

	for (guint n = 0; n < 1500; n++) {
		ev_make (&e, n);
		fs_eventstore_append (s, &e.hit, 0);
	}

	CHECK (fs_eventstore_length (s) == 1000, "the ring holds its capacity");
	CHECK (fs_eventstore_first_seq (s) == 501 &&
	       fs_eventstore_last_seq (s) == 1500,
	       "the first 500 to arrive are the ones dropped");
	CHECK (log.seqs->len == 500, "the evict func heard each drop (%u)",
	       log.seqs->len);
	for (guint i = 0; i < log.seqs->len; i++)
		if (g_array_index (log.seqs, guint64, i) != i + 1)
			in_order = FALSE;
	CHECK (in_order, "drops come oldest first");
	CHECK (log.readable, "a dropped event can be read during the call");
	CHECK (!fs_eventstore_has (s, 500) && fs_eventstore_has (s, 501),
	       "a dropped seq is gone, the next one stays");

	/* Grow, then shrink: the newest stay. */
	g_array_set_size (log.seqs, 0);
	fs_eventstore_set_capacity (s, 5000);
	CHECK (fs_eventstore_length (s) == 1000 &&
	       fs_eventstore_first_seq (s) == 501, "growing keeps everything");
	for (guint n = 1500; n < 2000; n++) {
		ev_make (&e, n);
		fs_eventstore_append (s, &e.hit, 0);
	}
	CHECK (fs_eventstore_length (s) == 1500 && log.seqs->len == 0,
	       "a grown ring takes more before dropping");
	fs_eventstore_set_capacity (s, 1200);
	CHECK (fs_eventstore_length (s) == 1200 &&
	       fs_eventstore_first_seq (s) == 801 && log.seqs->len == 300,
	       "shrinking drops the oldest, through the evict func");
	{
		FsHit *h = fs_eventstore_get_hit (s, 2000);

		ev_make (&e, 1999);
		CHECK (h != NULL && hits_equal (h, &e.hit),
		       "after a resize the newest still reads right");
		fs_hit_free (h);
	}

	CHECK (fs_eventstore_set_capacity (s, 5000000) ==
	       FS_EVENTSTORE_MAX_CAPACITY, "the capacity is capped at 1,000,000");

	g_array_unref (log.seqs);
	fs_eventstore_free (s);
}

static void
test_store_interning (void)
{
	FsEventStore *s = fs_eventstore_new (1000);
	Ev e;
	guint before;

	for (guint n = 0; n < 1000; n++) {
		/* Distinct times so nothing is a repeat. */
		ev_make (&e, n);
		e.hit.source = "192.0.2.1";
		fs_eventstore_append (s, &e.hit, 0);
	}

	/* 1000 events: one source, 200 destinations, 3 ports, ... */
	before = fs_eventstore_n_strings (s);
	CHECK (before < 1500, "1000 events hold %u distinct strings, not "
	       "12,000", before);

	/* The same text from two events is one string. */
	CHECK (fs_eventstore_field_id (s, 1, FS_EV_SOURCE) ==
	       fs_eventstore_field_id (s, 999, FS_EV_SOURCE),
	       "a repeated source is one interned string");

	/* Replace every event: strings no longer used are freed. */
	for (guint n = 0; n < 1000; n++) {
		Ev f;

		ev_make (&f, 100000 + n);
		f.hit.source = "192.0.2.2";
		f.hit.length = "60";
		f.hit.destination = "198.51.100.1";
		fs_eventstore_append (s, &f.hit, 0);
	}
	CHECK (fs_eventstore_n_strings (s) < 20,
	       "after the ring turned over, only the strings in use remain "
	       "(%u)", fs_eventstore_n_strings (s));
	CHECK (fs_eventstore_n_atoms (s) <= before + 20,
	       "freed ids are reused, the table does not grow (%u slots)",
	       fs_eventstore_n_atoms (s));

	fs_eventstore_free (s);
}

static void
test_store_dedup (void)
{
	FsEventStore *s = fs_eventstore_new (1000);
	Ev e;

	ev_make (&e, 1);
	CHECK (fs_eventstore_append (s, &e.hit, 0) != 0, "first copy accepted");
	CHECK (fs_eventstore_append (s, &e.hit, 0) == 0,
	       "the same event again is refused");
	CHECK (fs_eventstore_length (s) == 1 && fs_eventstore_n_strings (s) > 0,
	       "a refused repeat leaves no trace");

	for (guint n = 2; n < 70; n++) {
		Ev f;

		ev_make (&f, n);
		fs_eventstore_append (s, &f.hit, 0);
	}
	CHECK (fs_eventstore_append (s, &e.hit, 0) != 0,
	       "beyond the last 64 it is an event again");

	/* Text stamps: the same text is the same event whatever its
	 * arrival time. */
	{
		FsHit h = { 0 };

		h.time = "12:00:00";
		h.destination = "198.51.100.77";
		CHECK (fs_eventstore_append (s, &h, 1) != 0 &&
		       fs_eventstore_append (s, &h, 2) == 0,
		       "a text-stamped repeat is refused despite a later arrival");
	}

	fs_eventstore_clear (s);
	CHECK (fs_eventstore_length (s) == 0 && fs_eventstore_n_strings (s) == 0,
	       "clear empties the store and its strings");
	CHECK (fs_eventstore_append (s, &e.hit, 0) != 0,
	       "after clear the event lists again");
	CHECK (fs_eventstore_first_seq (s) > 70, "seqs keep counting after clear");

	fs_eventstore_free (s);
}

/* ---------------------------------------------------------- queries */

static guint
count_matches (FsEventStore *s, const FsEventFilter *f)
{
	GError *error = NULL;
	FsEventQuery *q = fs_eventquery_new (f, &error);
	GArray *seqs = g_array_new (FALSE, FALSE, sizeof (guint64));
	guint n;

	if (q == NULL) {
		printf ("     (query refused: %s)\n", error->message);
		g_error_free (error);
		g_array_unref (seqs);
		return G_MAXUINT;
	}
	n = fs_eventstore_select (s, q, seqs);
	g_array_unref (seqs);
	fs_eventquery_free (q);
	return n;
}

/* The answer by brute force over FsHit copies. */
static guint
count_brute (FsEventStore *s, const FsEventFilter *f)
{
	FsEventQuery *q = fs_eventquery_new (f, NULL);
	guint n = 0;

	for (guint64 seq = fs_eventstore_first_seq (s);
	     seq != 0 && seq <= fs_eventstore_last_seq (s); seq++) {
		FsHit *h = fs_eventstore_get_hit (s, seq);

		if (fs_eventquery_match_hit (q, h, fs_eventstore_time_us (s, seq)))
			n++;
		fs_hit_free (h);
	}
	fs_eventquery_free (q);
	return n;
}

static void
test_queries (void)
{
	FsEventStore *s = fs_eventstore_new (10000);
	FsEventFilter f;
	GError *error = NULL;
	Ev e;
	guint n;
	gint64 t0 = 0;

	for (guint i = 0; i < 2000; i++) {
		ev_make (&e, i);
		fs_eventstore_append (s, &e.hit, 0);
	}
	/* Two IPv6 events. */
	{
		FsHit h = { 0 };

		h.time = "2026-11-02T12:00:00Z";
		h.direction = "Outbound";
		h.source = "2001:db8::5";
		h.destination = "2001:db8:1::9";
		h.port = "443";
		h.protocol = "tcp";
		h.service = "HTTPS";
		fs_eventstore_append (s, &h, 0);
		h.time = "2026-11-02T12:00:01Z";
		h.destination = "fe80::1";
		fs_eventstore_append (s, &h, 0);
	}

	memset (&f, 0, sizeof f);
	CHECK (count_matches (s, &f) == 2002, "no filter: everything");

	f.text = "ssh";
	n = count_matches (s, &f);
	CHECK (n == 400, "text, case-insensitive, in the service (%u)", n);
	f.text = "spamhaus";
	CHECK (count_matches (s, &f) == 40, "text reaches the rule field");
	f.text = "203.0.113.17";
	n = count_matches (s, &f);
	CHECK (n == 110, "text is a substring test: .17 and .170-.179 (%u)", n);

	memset (&f, 0, sizeof f);
	f.direction = FS_EVQ_DIR_IN;
	CHECK (count_matches (s, &f) == 1000, "direction: inbound only");
	f.direction = FS_EVQ_DIR_OUT;
	CHECK (count_matches (s, &f) == 1002,
	       "direction: outbound, both spellings (Out, Outbound)");

	memset (&f, 0, sizeof f);
	f.action = FS_EVQ_ACTION_BLOCKED;
	CHECK (count_matches (s, &f) == 400, "action: blocked");
	f.action = FS_EVQ_ACTION_ALLOWED;
	CHECK (count_matches (s, &f) == 1602, "action: allowed");

	memset (&f, 0, sizeof f);
	f.protocol = "TCP";
	n = count_matches (s, &f);
	CHECK (n == 1335, "protocol, whole and case-insensitive (%u)", n);
	f.protocol = "TC";
	CHECK (count_matches (s, &f) == 0, "protocol is not a substring test");

	memset (&f, 0, sizeof f);
	f.port = "22";
	n = count_matches (s, &f);
	CHECK (n == 286, "a single port (%u)", n);
	f.port = "20-60";
	n = count_matches (s, &f);
	CHECK (n == 286 + 571, "a port range: 22 and 53 (%u)", n);
	f.port = "443:443";
	n = count_matches (s, &f);
	CHECK (n == 2002 - 286 - 571, "colon range form (%u)", n);
	f.port = "70000";
	CHECK (count_matches (s, &f) == G_MAXUINT, "port 70000 is refused");
	f.port = "abc";
	CHECK (fs_eventquery_new (&f, &error) == NULL && error != NULL &&
	       error->code == FS_EVENTQUERY_ERROR_PORT,
	       "a word as port is refused with a port error");
	g_clear_error (&error);

	memset (&f, 0, sizeof f);
	f.address = "203.0.113.0/29";      /* .0 .. .7 */
	n = count_matches (s, &f);
	CHECK (n == 80, "a CIDR block matches the destination (%u)", n);
	f.address = "10.0.0.0/8";
	CHECK (count_matches (s, &f) == 2000, "or the source");
	f.address = "10.0.7.0-10.0.7.255";
	n = count_matches (s, &f);
	CHECK (n == 208, "an explicit range: sources of events 1792-1999 (%u)", n);
	f.address = "203.0.113.17";
	CHECK (count_matches (s, &f) == 10, "a single address");
	f.address = "2001:db8::/32";
	CHECK (count_matches (s, &f) == 2, "IPv6 CIDR");
	f.address = "fe80::/10";
	CHECK (count_matches (s, &f) == 1, "link-local block, destination only");
	f.address = "10.0.0.0/33";
	CHECK (fs_eventquery_new (&f, &error) == NULL &&
	       error->code == FS_EVENTQUERY_ERROR_ADDRESS,
	       "a /33 is refused with an address error");
	g_clear_error (&error);
	f.address = "example.com";
	CHECK (count_matches (s, &f) == G_MAXUINT, "names are not resolved");

	/* Time: events are 0.1 s apart from 10:00:00 UTC. */
	fs_event_time_parse ("2026-11-02T10:00:00Z", &t0);
	memset (&f, 0, sizeof f);
	f.since_us = t0 / 10 + 100 * G_USEC_PER_SEC;    /* 10:01:40 */
	f.until_us = t0 / 10 + 110 * G_USEC_PER_SEC;    /* 10:01:50 */
	n = count_matches (s, &f);
	CHECK (n == 100, "a ten-second window holds 100 events, since "
	       "inclusive, until exclusive (%u)", n);
	f.until_us = f.since_us;
	CHECK (fs_eventquery_new (&f, &error) == NULL &&
	       error->code == FS_EVENTQUERY_ERROR_TIME,
	       "an empty time range is refused");
	g_clear_error (&error);

	/* Combined, and the cached path agrees with the plain one. */
	{
		static const FsEventFilter combos[] = {
			{ "eth0", FS_EVQ_DIR_IN, "tcp", "443", "10.0.0.0/16",
			  FS_EVQ_ACTION_ALLOWED, 0, 0 },
			{ "203.0.113.1", FS_EVQ_DIR_ANY, NULL, "20-60", NULL,
			  FS_EVQ_ACTION_BLOCKED, 0, 0 },
			{ NULL, FS_EVQ_DIR_OUT, "UDP", NULL, "203.0.113.0/25",
			  FS_EVQ_ACTION_ANY, 0, 0 },
			{ "https", FS_EVQ_DIR_ANY, NULL, NULL, "2001:db8::/32",
			  FS_EVQ_ACTION_ANY, 0, 0 },
		};
		gboolean agree = TRUE;

		for (guint i = 0; i < G_N_ELEMENTS (combos); i++) {
			guint a = count_matches (s, &combos[i]);
			guint b = count_brute (s, &combos[i]);

			if (a != b) {
				printf ("     combo %u: store %u, plain %u\n", i, a, b);
				agree = FALSE;
			}
		}
		CHECK (agree, "the store's cached answers agree with the "
		       "per-event answers the command line uses");
	}

	fs_eventstore_free (s);
}

/* A cached answer belongs to a string, not to its id: once the string
 * is freed and the id reused for another, the query must ask again. */
static void
test_query_cache_reuse (void)
{
	FsEventStore *s = fs_eventstore_new (1000);
	FsEventFilter f = { 0 };
	FsEventQuery *q;
	Ev e;
	guint64 seq;
	guint32 old_id;

	f.text = "needle";
	q = fs_eventquery_new (&f, NULL);

	ev_make (&e, 1);
	e.hit.rule = "needle rule";
	seq = fs_eventstore_append (s, &e.hit, 0);
	CHECK (fs_eventquery_match (q, s, seq), "the needle is found");
	old_id = fs_eventstore_field_id (s, seq, FS_EV_RULE);

	/* Push it out; its strings are freed. */
	for (guint n = 2; n < 1100; n++) {
		ev_make (&e, n);
		e.hit.rule = NULL;
		fs_eventstore_append (s, &e.hit, 0);
	}

	/* New strings until one of them is given the freed id. */
	seq = 0;
	for (guint n = 0; n < 5000 && seq == 0; n++) {
		gchar rule[32];
		guint64 got;

		ev_make (&e, 10000 + n);
		g_snprintf (rule, sizeof rule, "other rule %u", n);
		e.hit.rule = rule;
		got = fs_eventstore_append (s, &e.hit, 0);
		if (fs_eventstore_field_id (s, got, FS_EV_RULE) == old_id)
			seq = got;
	}
	CHECK (seq != 0, "the freed id was given to a new string");
	CHECK (seq != 0 && !fs_eventquery_match (q, s, seq),
	       "the query does not answer for the new string from the old "
	       "string's cache");

	fs_eventquery_free (q);
	fs_eventstore_free (s);
}

/* -------------------------------------------------------------- CSV */

static void
test_csv (const gchar *tmp)
{
	FsEventStore *s = fs_eventstore_new (1000);
	gchar *path = g_build_filename (tmp, "out.csv", NULL);
	FsHit h = { 0 };
	guint64 seqs[3];
	guint written = 0;
	gchar *text = NULL;
	GStatBuf st;

	h.time = "2026-11-02T10:00:00Z";
	h.direction = "Out";
	h.source = "192.0.2.1";
	h.destination = "198.51.100.1";
	h.service = "Web, \"secure\" [BLOCKED]";
	seqs[0] = fs_eventstore_append (s, &h, 0);
	h.time = "2026-11-02T10:00:01Z";
	h.service = "=HYPERLINK(\"x\")";
	h.rule = "-cmd";
	seqs[1] = fs_eventstore_append (s, &h, 0);
	seqs[2] = 9999;                       /* not held: skipped */

	CHECK (fs_eventstore_write_csv (s, seqs, 3, path, &written, NULL) &&
	       written == 2, "two rows written, the missing seq skipped");
	g_file_get_contents (path, &text, NULL, NULL);
	CHECK (text != NULL && g_str_has_prefix (text, "time,direction,in,"),
	       "a header row first");
	CHECK (text != NULL &&
	       strstr (text, "\"Web, \"\"secure\"\" [BLOCKED]\",blocked") != NULL,
	       "commas and quotes are quoted, the action column says blocked");
	CHECK (text != NULL && strstr (text, "\"'=HYPERLINK") != NULL &&
	       strstr (text, "\"'-cmd\"") != NULL,
	       "a formula-looking field is defused with an apostrophe");
#ifndef G_OS_WIN32
	CHECK (g_stat (path, &st) == 0 && (st.st_mode & 0777) == 0600,
	       "the export is readable by its owner only (%o)",
	       (unsigned) (st.st_mode & 0777));
#else
	(void) st;
#endif
	g_free (text);
	g_free (path);
	fs_eventstore_free (s);
}

/* ---------------------------------------------------------- history */

static void
write_raw (const gchar *path, const gchar *text, gboolean append)
{
	FILE *f = g_fopen (path, append ? "ab" : "wb");

	fputs (text, f);
	fclose (f);
}

static void
test_log_lines (void)
{
	GString *line = g_string_new (NULL);
	FsHit h = { 0 }, back;
	gint64 ticks = 0;
	gchar *copy;

	h.time = "2026-11-02T10:00:00.0000001Z";
	h.direction = "In";
	h.source = "a\tb\\c\nd\re";
	h.service = "SSH [BLOCKED]";
	fs_eventlog_format_line (line, &h, 17930000000000001LL);
	CHECK (strchr (line->str, '\n') == line->str + line->len - 1,
	       "one line per event, whatever the fields hold");

	copy = g_strdup (line->str);
	CHECK (fs_eventlog_parse_line (copy, &back, &ticks) &&
	       ticks == 17930000000000001LL &&
	       strcmp (back.source, h.source) == 0 && back.rule == NULL &&
	       strcmp (back.service, h.service) == 0,
	       "escapes round-trip (tab, backslash, CR, LF)");
	g_free (copy);

	copy = g_strdup (line->str);
	copy[25] ^= 1;
	CHECK (!fs_eventlog_parse_line (copy, &back, &ticks),
	       "a damaged byte fails the checksum");
	g_free (copy);

	copy = g_strndup (line->str, line->len - 6);
	CHECK (!fs_eventlog_parse_line (copy, &back, &ticks),
	       "a line cut short is refused");
	g_free (copy);

	copy = g_strdup ("garbage\tline\n");
	CHECK (!fs_eventlog_parse_line (copy, &back, &ticks),
	       "a foreign line is refused");
	g_free (copy);

	g_string_free (line, TRUE);
}

static void
test_log_roundtrip (const gchar *tmp)
{
	gchar *dir = g_build_filename (tmp, "rt", NULL);
	FsEventStore *a = fs_eventstore_new (10000);
	FsEventStore *b = fs_eventstore_new (10000);
	FsEventLog *log;
	FsEventLogStats st;
	GError *error = NULL;
	gboolean same = TRUE;
	Ev e;

	log = fs_eventlog_open (dir, 30, 0, &error);
	CHECK (log != NULL, "the history folder opens (%s)",
	       error ? error->message : "ok");
	if (log == NULL)
		return;

	for (guint n = 0; n < 3000; n++) {
		guint64 seq;

		ev_make (&e, n);
		seq = fs_eventstore_append (a, &e.hit, 0);
		fs_eventlog_append (log, &e.hit, fs_eventstore_ticks (a, seq));
	}
	/* A text-stamped event: its arrival time is what the file keeps. */
	{
		FsHit h = { 0 };
		guint64 seq;

		h.time = "Nov  2 11:00:00";
		h.destination = "198.51.100.200";
		seq = fs_eventstore_append (a, &h, 1793622000LL * G_USEC_PER_SEC);
		fs_eventlog_append (log, &h, fs_eventstore_ticks (a, seq));
	}
	fs_eventlog_close (log);

	fs_eventlog_load_recent (dir, b, 10000, &st);
	CHECK (st.loaded == 3001 && st.bad_lines == 0,
	       "all 3001 events load back (%u, %u bad)", st.loaded, st.bad_lines);

	for (guint64 i = 0; i < fs_eventstore_length (a) && same; i++) {
		guint64 sa = fs_eventstore_first_seq (a) + i;
		guint64 sb = fs_eventstore_first_seq (b) + i;
		FsHit *ha = fs_eventstore_get_hit (a, sa);
		FsHit *hb = fs_eventstore_get_hit (b, sb);

		same = ha != NULL && hb != NULL && hits_equal (ha, hb) &&
		       fs_eventstore_ticks (a, sa) == fs_eventstore_ticks (b, sb);
		if (!same)
			printf ("     differs at %" G_GUINT64_FORMAT "\n", i);
		fs_hit_free (ha);
		fs_hit_free (hb);
	}
	CHECK (same, "every field and time survives the round trip");

	/* The monitor re-delivers its trailing window after a restart:
	 * the store refuses what history already holds. */
	ev_make (&e, 2999);
	CHECK (fs_eventstore_append (b, &e.hit, 0) == 0,
	       "an event re-delivered after a restart is not listed twice");

	fs_eventstore_free (a);
	fs_eventstore_free (b);
	g_free (dir);
}

static gchar *
only_log_file (const gchar *dir)
{
	GDir *d = g_dir_open (dir, 0, NULL);
	const gchar *name;
	gchar *found = NULL;

	while (d != NULL && (name = g_dir_read_name (d)) != NULL)
		if (g_str_has_suffix (name, ".log") && found == NULL)
			found = g_build_filename (dir, name, NULL);
	if (d != NULL)
		g_dir_close (d);
	return found;
}

static void
test_log_partial_and_perms (const gchar *tmp)
{
	gchar *dir = g_build_filename (tmp, "partial", NULL);
	FsEventStore *s = fs_eventstore_new (1000);
	FsEventLog *log;
	FsEventLogStats st;
	gchar *file;
	Ev e;

#ifndef G_OS_WIN32
	/* A folder that already exists with loose permissions is
	 * tightened. */
	g_mkdir_with_parents (dir, 0755);
	g_chmod (dir, 0755);
#endif

	log = fs_eventlog_open (dir, 30, 0, NULL);
	for (guint n = 0; n < 10; n++) {
		ev_make (&e, n);
		fs_eventlog_append (log, &e.hit, 17930000000000000LL + n * 10000000LL);
	}
	fs_eventlog_close (log);

	file = only_log_file (dir);
	CHECK (file != NULL, "one history file was written");
	if (file == NULL)
		return;

#ifndef G_OS_WIN32
	{
		GStatBuf sb;

		CHECK (g_stat (dir, &sb) == 0 && (sb.st_mode & 0777) == 0700,
		       "the folder is owner-only (%o)",
		       (unsigned) (sb.st_mode & 0777));
		CHECK (g_stat (file, &sb) == 0 && (sb.st_mode & 0777) == 0600,
		       "the file is owner-only (%o)",
		       (unsigned) (sb.st_mode & 0777));
		/* Loosened by hand: the next open puts it back. */
		g_chmod (file, 0644);
	}
#endif

	/* A crash in the middle of a line. */
	write_raw (file, "17930000999999999\t2026-11-02T10:00:00Z\tIn\teth", TRUE);

	fs_eventlog_load_recent (dir, s, 1000, &st);
	CHECK (st.loaded == 10 && st.bad_lines == 1,
	       "the cut line is skipped, the ten before it load (%u, %u bad)",
	       st.loaded, st.bad_lines);

	/* The next session writes after it: its first line is whole. */
	log = fs_eventlog_open (dir, 30, 0, NULL);
	ev_make (&e, 50);
	fs_eventlog_append (log, &e.hit, 17930000000000000LL + 50 * 10000000LL);
	fs_eventlog_close (log);

	fs_eventstore_clear (s);
	fs_eventlog_load_recent (dir, s, 1000, &st);
	CHECK (st.loaded == 11 && st.bad_lines == 1,
	       "a line written after the cut one reads (%u, %u bad)",
	       st.loaded, st.bad_lines);

#ifndef G_OS_WIN32
	{
		GStatBuf sb;

		CHECK (g_stat (file, &sb) == 0 && (sb.st_mode & 0777) == 0600,
		       "a loosened file is owner-only again once written (%o)",
		       (unsigned) (sb.st_mode & 0777));
	}
#endif

	/* Damage in the middle of the file costs that line only. */
	{
		gchar *text = NULL;
		gsize len = 0;
		gchar *mid;

		g_file_get_contents (file, &text, &len, NULL);
		mid = strstr (text, "203.0.113.5");
		if (mid != NULL)
			mid[0] = '7';
		g_file_set_contents (file, text, (gssize) len, NULL);
		g_free (text);

		fs_eventstore_clear (s);
		fs_eventlog_load_recent (dir, s, 1000, &st);
		CHECK (st.loaded == 10 && st.bad_lines == 2,
		       "a damaged line is skipped, the rest load (%u, %u bad)",
		       st.loaded, st.bad_lines);
	}

	g_free (file);
	fs_eventstore_free (s);
	g_free (dir);
}

static void
test_log_limits (const gchar *tmp)
{
	gchar *dir = g_build_filename (tmp, "limits", NULL);
	gint64 now = g_get_real_time ();
	gint64 now_ticks = now * 10;
	FsEventLog *log;
	guint64 bytes = 0;
	guint files = 0;
	Ev e;

	g_mkdir_with_parents (dir, 0700);

	/* Age: files for 40 and 31 days ago go, 29 days ago stays. */
	{
		const gint ages[] = { 40, 31, 29 };

		for (guint i = 0; i < G_N_ELEMENTS (ages); i++) {
			gchar day[16];
			gchar *name, *path;

			fs_event_time_day (now_ticks - (gint64) ages[i] *
			                   864000000000LL, day);
			name = g_strdup_printf ("events-%s-000.log", day);
			path = g_build_filename (dir, name, NULL);
			write_raw (path, "# StockFW event history 1\n", FALSE);
			g_free (path);
			g_free (name);
		}
		/* Not ours: never touched. */
		{
			gchar *other = g_build_filename (dir, "notes.txt", NULL);

			write_raw (other, "keep me\n", FALSE);
			g_free (other);
		}
	}

	log = fs_eventlog_open (dir, 30, 1024 * 1024, NULL);
	fs_eventlog_usage (dir, &bytes, &files);
	CHECK (files == 1, "files older than 30 days are deleted on open, "
	       "the 29-day-old one stays (%u left)", files);
	{
		gchar *other = g_build_filename (dir, "notes.txt", NULL);

		CHECK (g_file_test (other, G_FILE_TEST_EXISTS),
		       "a file that is not history is left alone");
		g_free (other);
	}

	/* Size: 3 MB of events into a 1 MB cap. */
	for (guint n = 0; n < 24000; n++) {
		ev_make (&e, n);
		fs_eventlog_append (log, &e.hit, now_ticks + n);
	}
	fs_eventlog_flush (log, NULL);
	fs_eventlog_usage (dir, &bytes, &files);
	CHECK (bytes <= 1024 * 1024 + 1024 * 1024 / 20 + 70000,
	       "the folder stays near its 1 MB cap (%" G_GUINT64_FORMAT
	       " bytes in %u files)", bytes, files);
	CHECK (files > 10, "history is split into parts, so the oldest can "
	       "go (%u files)", files);

	/* What remains is the newest. */
	{
		FsEventStore *s = fs_eventstore_new (FS_EVENTSTORE_MAX_CAPACITY);
		FsHit *last;

		fs_eventlog_load_recent (dir, s, 1000000, NULL);
		last = fs_eventstore_get_hit (s, fs_eventstore_last_seq (s));
		ev_make (&e, 23999);
		CHECK (last != NULL && hits_equal (last, &e.hit),
		       "the newest event survives the cap");
		fs_hit_free (last);
		fs_eventstore_free (s);
	}

	/* A tighter limit takes effect at once. */
	fs_eventlog_set_limits (log, 30, 1);    /* clamped to 1 MB */
	fs_eventlog_set_limits (log, 1, 1024 * 1024);
	fs_eventlog_usage (dir, &bytes, &files);
	CHECK (bytes <= 1024 * 1024 + 70000, "set_limits prunes at once");

	CHECK (fs_eventlog_clear (log, NULL) == files &&
	       (fs_eventlog_usage (dir, &bytes, &files), files == 0),
	       "clear deletes every history file");
	ev_make (&e, 1);
	fs_eventlog_append (log, &e.hit, now_ticks);
	fs_eventlog_close (log);
	fs_eventlog_usage (dir, &bytes, &files);
	CHECK (files == 1, "and the log keeps writing after a clear");

	g_free (dir);
}

static void
test_log_bounded_load (const gchar *tmp)
{
	gchar *dir = g_build_filename (tmp, "bounded", NULL);
	FsEventLog *log = fs_eventlog_open (dir, 3650, 0, NULL);
	FsEventStore *s = fs_eventstore_new (2000);
	FsEventLogStats st;
	gint64 t0 = 0;
	Ev e;

	fs_event_time_parse ("2026-10-01T00:00:00Z", &t0);
	/* 5000 events over five days, one file each. */
	for (guint n = 0; n < 5000; n++) {
		ev_make (&e, n);
		fs_eventlog_append (log, &e.hit,
		                    t0 + (gint64) (n / 1000) * 864000000000LL + n);
	}
	fs_eventlog_close (log);

	fs_eventlog_load_recent (dir, s, 1200, &st);
	CHECK (st.loaded == 1200, "load stops at its bound (%u)", st.loaded);
	CHECK (st.files == 2, "only the files needed are read (%u of 5)",
	       st.files);
	{
		FsHit *first = fs_eventstore_get_hit (s, fs_eventstore_first_seq (s));

		ev_make (&e, 3800);
		if (first != NULL && !hits_equal (first, &e.hit))
			printf ("     first loaded: %s %s, want %s %s\n",
			        first->time, first->source, e.time, e.src);
		CHECK (first != NULL && hits_equal (first, &e.hit),
		       "the newest 1200 are the ones loaded");
		fs_hit_free (first);
	}

	fs_eventstore_free (s);
	g_free (dir);
}

static void
count_cb (const FsHit *hit, gint64 ticks, gpointer data)
{
	(void) hit;
	(void) ticks;
	(*(guint *) data)++;
}

static void
test_log_foreach (const gchar *tmp)
{
	gchar *dir = g_build_filename (tmp, "bounded", NULL);
	FsEventLogStats st;
	guint count = 0;
	gint64 t0 = 0;

	fs_event_time_parse ("2026-10-01T00:00:00Z", &t0);
	fs_eventlog_foreach (dir, (t0 + 3 * 864000000000LL) / 10, 0, count_cb,
	                     &count, &st);
	CHECK (count == 2000 && st.files == 2,
	       "--since reads only the days it needs (%u events, %u files)",
	       count, st.files);

	count = 0;
	fs_eventlog_foreach (dir, (t0 + 1 * 864000000000LL) / 10,
	                     (t0 + 2 * 864000000000LL) / 10, count_cb, &count,
	                     &st);
	CHECK (count == 1000, "a one-day range holds that day (%u)", count);
	g_free (dir);
}

/* ------------------------------------------------------------ bench */

static glong
rss_kb (void)
{
	gchar *text = NULL;
	glong kb = -1;

	if (g_file_get_contents ("/proc/self/status", &text, NULL, NULL)) {
		const gchar *p = strstr (text, "VmRSS:");

		if (p != NULL)
			kb = strtol (p + 6, NULL, 10);
	}
	g_free (text);
	return kb;
}

static gdouble
ms_since (gint64 t)
{
	return (g_get_monotonic_time () - t) / 1000.0;
}

static void
bench (guint n, const gchar *tmp)
{
	FsEventStore *s = fs_eventstore_new (MAX (n, FS_EVENTSTORE_MIN_CAPACITY));
	glong rss0 = rss_kb ();
	gint64 t;
	Ev e;
	GArray *seqs = g_array_new (FALSE, FALSE, sizeof (guint64));
	gchar *dir = g_build_filename (tmp, "bench", NULL);
	FsEventLog *log;
	FsEventLogStats st;
	guint64 bytes = 0;

	/* What making the synthetic events costs on its own, so the
	 * store's share can be read off the next line. */
	t = g_get_monotonic_time ();
	for (guint i = 0; i < n; i++)
		ev_make (&e, i);
	printf ("bench: generate %u synthetic events (no store): %.1f ms\n",
	        n, ms_since (t));

	t = g_get_monotonic_time ();
	for (guint i = 0; i < n; i++) {
		ev_make (&e, i);
		fs_eventstore_append (s, &e.hit, 0);
	}
	printf ("bench: generate and append %u events: %.1f ms (%.0f ns each), RSS +%ld KB "
	        "(%.1f bytes/event), store reports %" G_GSIZE_FORMAT " bytes, "
	        "%u distinct strings\n",
	        n, ms_since (t), ms_since (t) * 1e6 / n, rss_kb () - rss0,
	        (rss_kb () - rss0) * 1024.0 / n, fs_eventstore_memory (s),
	        fs_eventstore_n_strings (s));

	/* Again, with the ring full: every append also drops one. */
	t = g_get_monotonic_time ();
	for (guint i = 0; i < n; i++) {
		ev_make (&e, n + i);
		fs_eventstore_append (s, &e.hit, 0);
	}
	printf ("bench: append %u more into the full ring (each drops the "
	        "oldest): %.1f ms\n", n, ms_since (t));

	{
		static const struct { const gchar *what; FsEventFilter f; } qs[] = {
			{ "text \"203.0.113.17\"", { "203.0.113.17", 0, NULL, NULL, NULL, 0, 0, 0 } },
			{ "text \"ssh\"",          { "ssh", 0, NULL, NULL, NULL, 0, 0, 0 } },
			{ "port 22",               { NULL, 0, NULL, "22", NULL, 0, 0, 0 } },
			{ "CIDR 10.0.0.0/12",      { NULL, 0, NULL, NULL, "10.0.0.0/12", 0, 0, 0 } },
			{ "blocked inbound TCP",   { NULL, FS_EVQ_DIR_IN, "TCP", NULL, NULL, FS_EVQ_ACTION_BLOCKED, 0, 0 } },
		};

		for (guint i = 0; i < G_N_ELEMENTS (qs); i++) {
			FsEventQuery *q = fs_eventquery_new (&qs[i].f, NULL);
			guint hits;

			g_array_set_size (seqs, 0);
			t = g_get_monotonic_time ();
			hits = fs_eventstore_select (s, q, seqs);
			printf ("bench: filter %u by %s: %.1f ms (%u match)\n",
			        fs_eventstore_length (s), qs[i].what, ms_since (t),
			        hits);
			fs_eventquery_free (q);
		}
	}

	/* History: write, then load as at start. */
	fs_eventlog_clear_dir (dir, NULL);
	log = fs_eventlog_open (dir, 3650, (guint64) 100000 * 1024 * 1024, NULL);
	t = g_get_monotonic_time ();
	for (guint64 seq = fs_eventstore_first_seq (s);
	     seq <= fs_eventstore_last_seq (s); seq++) {
		FsHit *h = fs_eventstore_get_hit (s, seq);

		fs_eventlog_append (log, h, fs_eventstore_ticks (s, seq));
		fs_hit_free (h);
	}
	fs_eventlog_close (log);
	fs_eventlog_usage (dir, &bytes, NULL);
	printf ("bench: write %u events to history: %.1f ms, %.1f MB on disk "
	        "(%.0f bytes/event)\n", fs_eventstore_length (s), ms_since (t),
	        bytes / 1048576.0, (gdouble) bytes / fs_eventstore_length (s));

	{
		FsEventStore *b = fs_eventstore_new (MAX (n, FS_EVENTSTORE_MIN_CAPACITY));

		t = g_get_monotonic_time ();
		fs_eventlog_load_recent (dir, b, n, &st);
		printf ("bench: load the newest %u events from history (start-up): "
		        "%.1f ms, %u files, %.1f MB read\n", st.loaded, ms_since (t),
		        st.files, st.bytes / 1048576.0);
		fs_eventstore_free (b);
	}

	fs_eventlog_clear_dir (dir, NULL);
	g_array_unref (seqs);
	fs_eventstore_free (s);
	g_free (dir);
}

int
main (int argc, char **argv)
{
	gchar *tmp = g_dir_make_tmp ("fs-eventstore-XXXXXX", NULL);

	if (argc == 3 && strcmp (argv[1], "bench") == 0) {
		bench ((guint) g_ascii_strtoull (argv[2], NULL, 10), tmp);
		return 0;
	}

	test_times ();
	test_time_specs ();
	test_store_basics ();
	test_store_eviction ();
	test_store_interning ();
	test_store_dedup ();
	test_queries ();
	test_query_cache_reuse ();
	test_csv (tmp);
	test_log_lines ();
	test_log_roundtrip (tmp);
	test_log_partial_and_perms (tmp);
	test_log_limits (tmp);
	test_log_bounded_load (tmp);
	test_log_foreach (tmp);

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);
	return failures ? 1 : 0;
}
