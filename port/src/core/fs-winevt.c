/*---[ fs-winevt.c ]----------------------------------------------------
 * Parsing and bookkeeping for the Windows Security-log reader.  See
 * fs-winevt.h.  GLib only: no spawning, no Windows API.
 *--------------------------------------------------------------------*/
#include "core/fs-winevt.h"
#include "core/fs-i18n.h"
#include "core/fs-service.h"

#include <string.h>
#include <stdlib.h>

void
fs_winevt_free (FsWinEvent *event)
{
	if (event == NULL)
		return;
	if (event->hit != NULL)
		fs_hit_free (event->hit);
	g_free (event);
}

/* ---------------------------------------------------------------- XML */

/* [ unescape ] -- the five XML entities and numeric references; an
 * entity it does not know is kept as written.  The result is valid
 * UTF-8 whatever the bytes were (wevtutil writes in the console code
 * page when its output is a file). */
static gchar *
unescape (const gchar *p, gsize len)
{
	GString *out = g_string_sized_new (len);
	const gchar *end = p + len;
	gchar *valid;

	while (p < end) {
		const gchar *semi;

		if (*p != '&') {
			g_string_append_c (out, *p++);
			continue;
		}
		semi = memchr (p, ';', (gsize) (end - p));
		if (semi == NULL || semi - p > 10) {
			g_string_append_c (out, *p++);
			continue;
		}
		if (semi - p == 3 && strncmp (p, "&lt", 3) == 0)
			g_string_append_c (out, '<');
		else if (semi - p == 3 && strncmp (p, "&gt", 3) == 0)
			g_string_append_c (out, '>');
		else if (semi - p == 4 && strncmp (p, "&amp", 4) == 0)
			g_string_append_c (out, '&');
		else if (semi - p == 5 && strncmp (p, "&quot", 5) == 0)
			g_string_append_c (out, '"');
		else if (semi - p == 5 && strncmp (p, "&apos", 5) == 0)
			g_string_append_c (out, '\'');
		else if (p[1] == '#') {
			gchar *num_end = NULL;
			guint64 cp = (p[2] == 'x' || p[2] == 'X')
			             ? g_ascii_strtoull (p + 3, &num_end, 16)
			             : g_ascii_strtoull (p + 2, &num_end, 10);

			if (num_end != semi || cp == 0 || cp > 0x10FFFF ||
			    !g_unichar_validate ((gunichar) cp)) {
				g_string_append_len (out, p, semi - p + 1);
			} else {
				g_string_append_unichar (out, (gunichar) cp);
			}
		} else {
			g_string_append_len (out, p, semi - p + 1);
		}
		p = semi + 1;
	}

	valid = g_utf8_make_valid (out->str, (gssize) out->len);
	g_string_free (out, TRUE);
	return valid;
}

/* [ find_tag ]
 * The next "<name" in [p, end) that is that element and not a longer
 * name starting the same way ("<Event" is not "<EventID"). */
static const gchar *
find_tag (const gchar *p, const gchar *end, const gchar *name)
{
	gsize n = strlen (name);

	while (p < end) {
		const gchar *lt = memchr (p, '<', (gsize) (end - p));

		if (lt == NULL || (gsize) (end - lt) < n + 2)
			return NULL;
		if (strncmp (lt + 1, name, n) == 0) {
			gchar c = lt[1 + n];

			if (c == '>' || c == ' ' || c == '/' || c == '\t' ||
			    c == '\r' || c == '\n')
				return lt;
		}
		p = lt + 1;
	}
	return NULL;
}

/* [ find_str ] -- memmem, which not every C library has. */
static const gchar *
find_str (const gchar *p, const gchar *end, const gchar *s)
{
	gsize n = strlen (s);

	while (p != NULL && p < end && (gsize) (end - p) >= n) {
		const gchar *hit = memchr (p, s[0], (gsize) (end - p));

		if (hit == NULL || (gsize) (end - hit) < n)
			return NULL;
		if (memcmp (hit, s, n) == 0)
			return hit;
		p = hit + 1;
	}
	return NULL;
}

/* [ element_text ]
 * The text of the first <name ...>text</name> in [p, end), unescaped,
 * or NULL ("<name/>" too). */
static gchar *
element_text (const gchar *p, const gchar *end, const gchar *name)
{
	const gchar *open = find_tag (p, end, name);
	const gchar *gt, *close;
	gchar *closing;

	if (open == NULL)
		return NULL;
	gt = memchr (open, '>', (gsize) (end - open));
	if (gt == NULL || gt[-1] == '/')
		return NULL;
	closing = g_strconcat ("</", name, ">", NULL);
	close = find_str (gt + 1, end, closing);
	g_free (closing);
	if (close == NULL)
		return NULL;
	return unescape (gt + 1, (gsize) (close - gt - 1));
}

/* [ attribute ] -- the value of attr="..." or attr='...' inside the
 * tag that starts at `tag'. */
static gchar *
attribute (const gchar *tag, const gchar *end, const gchar *attr)
{
	const gchar *gt = memchr (tag, '>', (gsize) (end - tag));
	gsize n = strlen (attr);
	const gchar *p;

	if (gt == NULL)
		return NULL;
	for (p = tag; p + n + 2 < gt; p++) {
		const gchar *q;
		gchar quote;

		if ((p[-1] != ' ' && p[-1] != '\t' && p[-1] != '\r' &&
		     p[-1] != '\n') || strncmp (p, attr, n) != 0 ||
		    p[n] != '=')
			continue;
		quote = p[n + 1];
		if (quote != '\'' && quote != '"')
			continue;
		q = memchr (p + n + 2, quote, (gsize) (gt - (p + n + 2)));
		if (q == NULL)
			return NULL;
		return unescape (p + n + 2, (gsize) (q - (p + n + 2)));
	}
	return NULL;
}

/* [ data_field ] -- <Data Name='name'>value</Data> in EventData. */
static gchar *
data_field (const gchar *p, const gchar *end, const gchar *name)
{
	while (p < end) {
		const gchar *tag = find_tag (p, end, "Data");
		gchar *which;
		gboolean match;

		if (tag == NULL)
			return NULL;
		which = attribute (tag + 1, end, "Name");
		match = g_strcmp0 (which, name) == 0;
		g_free (which);
		if (match) {
			const gchar *gt = memchr (tag, '>', (gsize) (end - tag));
			const gchar *close;

			if (gt == NULL || gt[-1] == '/')
				return NULL;
			close = find_str (gt + 1, end, "</Data>");
			if (close == NULL)
				return NULL;
			return unescape (gt + 1, (gsize) (close - gt - 1));
		}
		p = tag + 5;
	}
	return NULL;
}

static guint64
parse_u64 (const gchar *text)
{
	gchar *end = NULL;
	guint64 v;

	if (text == NULL || !g_ascii_isdigit (*text))
		return 0;
	v = g_ascii_strtoull (text, &end, 10);
	return end != NULL && *end == '\0' ? v : 0;
}

/* [ make_hit ]
 * The FsHit a 5156/5157 event stands for, field for field as the text
 * reader before 1.0.7 made it, so the Events list, the history files
 * and the Copilot see the same rows: port is the destination port,
 * In and Out the local and the remote side by direction, the service
 * the program's file name, "[BLOCKED]" after it for 5157. */
static FsHit *
make_hit (const gchar *p, const gchar *end, guint event_id, gchar *time)
{
	FsHit *hit;
	gchar *dest = data_field (p, end, "DestAddress");
	gchar *dir, *app, *proto;
	gboolean inbound;

	if (dest == NULL || *dest == '\0') {
		g_free (dest);
		g_free (time);
		return NULL;
	}

	hit = fs_hit_new ();
	hit->time = time;
	hit->destination = dest;
	hit->source = data_field (p, end, "SourceAddress");
	hit->port = data_field (p, end, "DestPort");

	/* %%14592 is Inbound and %%14593 Outbound in the raw XML; the
	 * rendered words are taken too. */
	dir = data_field (p, end, "Direction");
	inbound = dir == NULL ||
	          g_strcmp0 (dir, "%%14592") == 0 ||
	          g_ascii_strncasecmp (dir, "Inbound", 7) == 0;
	if (dir != NULL && g_strcmp0 (dir, "%%14593") == 0)
		inbound = FALSE;
	g_free (dir);
	hit->direction = g_strdup (inbound ? "in" : "out");

	if (inbound) {
		hit->in  = g_strdup (hit->destination);
		hit->out = g_strdup (hit->source != NULL ? hit->source : "?");
	} else {
		hit->in  = g_strdup (hit->source != NULL ? hit->source : "?");
		hit->out = g_strdup (hit->destination);
	}

	proto = data_field (p, end, "Protocol");
	if (g_strcmp0 (proto, "6") == 0)
		hit->protocol = g_strdup ("TCP");
	else if (g_strcmp0 (proto, "17") == 0)
		hit->protocol = g_strdup ("UDP");
	else if (g_strcmp0 (proto, "1") == 0)
		hit->protocol = g_strdup ("ICMP");
	else
		hit->protocol = g_strdup (proto);
	g_free (proto);

	app = data_field (p, end, "Application");
	if (app != NULL && *app != '\0') {
		const gchar *base = strrchr (app, '\\');

		/* Preserve the full executable path: an Event → Per-App Rule
		 * needs the program identity, not just the file name. */
		hit->program = g_strdup (app);
		base = base != NULL ? base + 1 : app;
		if (*base != '\0')
			hit->service = g_strdup (base);
	}
	g_free (app);
	if (hit->service == NULL)
		hit->service = fs_service_lookup_port (
			atoi (hit->port != NULL ? hit->port : "0"));
	if (hit->service == NULL)
		hit->service = g_strdup (_("Unknown"));

	if (event_id == FS_WINEVT_BLOCKED) {
		gchar *old = hit->service;

		hit->service = g_strdup_printf ("%s [BLOCKED]", old);
		g_free (old);
	}

	return hit;
}

static FsWinEvent *
parse_event (const gchar *p, const gchar *end)
{
	FsWinEvent *event = g_new0 (FsWinEvent, 1);
	const gchar *system_end = find_str (p, end, "</System>");
	const gchar *sys_end = system_end != NULL ? system_end : end;
	gchar *text;

	text = element_text (p, sys_end, "EventRecordID");
	event->record_id = parse_u64 (text);
	g_free (text);

	text = element_text (p, sys_end, "EventID");
	event->event_id = (guint) MIN (parse_u64 (text), G_MAXUINT);
	g_free (text);

	if (event->event_id == FS_WINEVT_PERMITTED ||
	    event->event_id == FS_WINEVT_BLOCKED) {
		const gchar *tc = find_tag (p, sys_end, "TimeCreated");

		event->hit = make_hit (sys_end, end, event->event_id,
		                       tc != NULL ? attribute (tc + 1, sys_end,
		                                               "SystemTime")
		                                  : NULL);
	}

	return event;
}

GPtrArray *
fs_winevt_parse_xml (const gchar *xml, gboolean *cut)
{
	GPtrArray *events = g_ptr_array_new_with_free_func (
		(GDestroyNotify) fs_winevt_free);
	const gchar *p = xml;
	const gchar *end;

	if (cut != NULL)
		*cut = FALSE;
	if (xml == NULL)
		return events;
	end = xml + strlen (xml);

	while (p < end) {
		const gchar *open = find_tag (p, end, "Event");
		const gchar *close;

		if (open == NULL)
			break;
		close = find_str (open, end, "</Event>");
		if (close == NULL) {
			/* Ends inside an element: the output was cut. */
			if (cut != NULL)
				*cut = TRUE;
			break;
		}
		g_ptr_array_add (events, parse_event (open, close));
		p = close + strlen ("</Event>");
	}

	return events;
}

/* -------------------------------------------------------------- query */

gchar *
fs_winevt_query (guint64 after)
{
	if (after == 0)
		return g_strdup ("*[System[(EventID=5156 or EventID=5157)]]");
	return g_strdup_printf ("*[System[(EventID=5156 or EventID=5157) "
	                        "and EventRecordID>%" G_GUINT64_FORMAT "]]",
	                        after);
}

gchar **
fs_winevt_poll_argv (guint64 after, guint count)
{
	gchar *query = fs_winevt_query (after);
	gchar **argv = g_new0 (gchar *, 8);

	argv[0] = g_strdup ("wevtutil.exe");
	argv[1] = g_strdup ("qe");
	argv[2] = g_strdup ("Security");
	argv[3] = g_strconcat ("/q:", query, NULL);
	argv[4] = g_strdup_printf ("/c:%u", MAX (count, 1u));
	argv[5] = g_strdup ("/rd:true");
	argv[6] = g_strdup ("/f:xml");
	g_free (query);
	return argv;
}

gchar **
fs_winevt_probe_argv (void)
{
	gchar **argv = g_new0 (gchar *, 7);

	argv[0] = g_strdup ("wevtutil.exe");
	argv[1] = g_strdup ("qe");
	argv[2] = g_strdup ("Security");
	argv[3] = g_strdup ("/c:1");
	argv[4] = g_strdup ("/rd:true");
	argv[5] = g_strdup ("/f:xml");
	return argv;
}

/* ------------------------------------------------------------- cursor */

void
fs_winevt_cursor_init (FsWinEvtCursor *cursor, guint64 newest)
{
	memset (cursor, 0, sizeof *cursor);
	cursor->last_id = newest;
	cursor->cap = FS_WINEVT_POLL_CAP;
}

guint64
fs_winevt_newest (GPtrArray *events)
{
	guint64 newest = 0;

	for (guint i = 0; events != NULL && i < events->len; i++) {
		const FsWinEvent *e = g_ptr_array_index (events, i);

		newest = MAX (newest, e->record_id);
	}
	return newest;
}

static gint
cmp_record (gconstpointer a, gconstpointer b)
{
	const FsWinEvent *x = *(const FsWinEvent * const *) a;
	const FsWinEvent *y = *(const FsWinEvent * const *) b;

	return x->record_id < y->record_id ? -1 : x->record_id > y->record_id;
}

GPtrArray *
fs_winevt_take (FsWinEvtCursor *cursor, GPtrArray *events, guint asked,
                gboolean cut)
{
	GPtrArray *fresh = g_ptr_array_new ();
	GPtrArray *out = g_ptr_array_new ();
	guint64 last = cursor->last_id;
	guint64 prev = 0;
	gboolean reached = FALSE;   /* read back to the cursor or past it */

	/* Everything read that is newer than the cursor, each record
	 * once.  An event without a record number cannot be placed, so it
	 * is not delivered: it could be delivered again on every poll. */
	for (guint i = 0; i < events->len; i++) {
		FsWinEvent *e = g_ptr_array_index (events, i);

		if (e->record_id > last)
			g_ptr_array_add (fresh, e);
		else if (e->record_id != 0)
			reached = TRUE;
	}
	g_ptr_array_sort (fresh, cmp_record);

	/* Full or cut short: the query did not reach back to the cursor,
	 * so the gap below the oldest one read was not read. */
	if (fresh->len > 0 && !reached && (events->len >= asked || cut)) {
		const FsWinEvent *oldest = g_ptr_array_index (fresh, 0);

		if (oldest->record_id > last + 1)
			cursor->skipped += oldest->record_id - last - 1;
	}

	for (guint i = 0; i < fresh->len; i++) {
		FsWinEvent *e = g_ptr_array_index (fresh, i);

		if (e->record_id == prev)
			continue;
		prev = e->record_id;
		cursor->last_id = MAX (cursor->last_id, e->record_id);
		if (e->hit != NULL) {
			g_ptr_array_add (out, e);
			cursor->delivered++;
		}
	}

	g_ptr_array_unref (fresh);
	return out;
}

/* [ fs_winevt_needs_probe ]
 * With the record condition, any event in the output is above the
 * cursor, so "no <Event" was enough.  Without it (the fallback), the
 * newest firewall records come back whatever the cursor, and a log
 * cleared and filled again answered with records that were all below
 * the cursor: the probe never ran, the clear was never noticed and
 * nothing was delivered until the numbers climbed back past the old
 * cursor.  So the test is on the record numbers, not on the text. */
gboolean
fs_winevt_needs_probe (const gchar *xml, guint64 after)
{
	const gchar *p, *end;

	if (after == 0)
		return FALSE;
	if (xml == NULL)
		return TRUE;

	end = xml + strlen (xml);
	for (p = xml; p < end;) {
		const gchar *tag = find_tag (p, end, "EventRecordID");
		gchar *text;
		guint64 id;

		if (tag == NULL)
			break;
		text = element_text (tag, end, "EventRecordID");
		id = parse_u64 (text);
		g_free (text);
		if (id > after)
			return FALSE;
		p = tag + 1;
	}
	return TRUE;
}

gboolean
fs_winevt_check_newest (FsWinEvtCursor *cursor, guint64 newest)
{
	if (newest >= cursor->last_id)
		return FALSE;

	/* Numbers went backwards: the log was cleared.  Everything in it
	 * now came after the clear. */
	cursor->last_id = 0;
	cursor->clears++;
	return TRUE;
}

void
fs_winevt_poll_done (FsWinEvtCursor *cursor, gboolean timed_out)
{
	if (cursor->cap == 0)
		cursor->cap = FS_WINEVT_POLL_CAP;

	if (timed_out)
		cursor->cap = MAX (cursor->cap / 2, FS_WINEVT_POLL_MIN);
	else
		cursor->cap = (guint) MIN ((guint64) cursor->cap * 2,
		                           (guint64) FS_WINEVT_POLL_CAP);
}
