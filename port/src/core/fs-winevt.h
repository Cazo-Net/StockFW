/*---[ fs-winevt.h ]----------------------------------------------------
 * Reading Windows firewall events out of the Security log (1.0.7).
 *
 * The Windows backend runs `wevtutil qe Security ... /f:xml' every five
 * seconds on a worker thread.  Until 1.0.7 it asked for the newest ten
 * events (/c:10) in text form and threw away the ones it had seen, so
 * a burst of more than ten connections in five seconds never reached
 * the Events list: on Windows the list could not receive a real burst
 * however large it was.
 *
 * Now every poll asks for the events after the last one it saw, by the
 * log's own record number (EventRecordID, which only grows, across
 * every event id):
 *
 *   wevtutil qe Security
 *     /q:*[System[(EventID=5156 or EventID=5157) and EventRecordID>N]]
 *     /c:CAP /rd:true /f:xml
 *
 * newest first, at most CAP of them (FS_WINEVT_POLL_CAP, 10,000 a
 * poll: 2,000 a second).  The text form carries no record number, so
 * the output is XML.  Nothing here spawns anything: this file is the
 * parsing and the bookkeeping, GLib only, so the tests run it on every
 * platform with canned wevtutil output.
 *
 *   No duplicates   an event is delivered only when its record number
 *                   is above the last one delivered, whatever the
 *                   query returned, and the batch is delivered oldest
 *                   first.
 *   Skips counted   when a poll comes back full (CAP events) or cut
 *                   short, the events between the last one delivered
 *                   and the oldest one read were not read.  Their
 *                   number is not known exactly (the record numbers
 *                   count every Security event, not only 5156/5157),
 *                   so what is counted is the gap in record numbers:
 *                   an upper bound, shown as "up to N skipped".
 *   Start           log_start reads the newest record of any kind
 *                   (no query, /c:1) and starts after it, so events
 *                   from before StockFW started are not delivered
 *                   again on top of the saved history.
 *   Clear/rollover  a poll that finds nothing also reads the newest
 *                   record of any kind.  Below the last one delivered,
 *                   the log was cleared (numbers start again at 1):
 *                   the next poll reads from the start of the log.  A
 *                   log that rolls over keeps numbering, so rollover
 *                   needs nothing.
 *   No condition    an event log service that refuses the record
 *                   condition (an error other than access denied or the
 *                   timeout) gets the query without it, at most
 *                   FS_WINEVT_FALLBACK_CAP newest, and the cursor drops
 *                   what it has seen; a batch that reaches back to the
 *                   cursor skipped nothing.
 *   Slow reads      a query that runs into the spawn timeout is
 *                   killed; the next poll asks for half as many
 *                   (never fewer than FS_WINEVT_POLL_MIN), and each
 *                   poll that works doubles it back towards the cap.
 *--------------------------------------------------------------------*/
#ifndef FS_WINEVT_H
#define FS_WINEVT_H

#include <glib.h>
#include "core/fs-types.h"

G_BEGIN_DECLS

#define FS_WINEVT_POLL_CAP   10000u
#define FS_WINEVT_POLL_MIN     500u
/* When the event log refuses the EventRecordID condition, the poll
 * asks for the newest this many with no condition and the cursor
 * drops what it has seen. */
#define FS_WINEVT_FALLBACK_CAP 2000u

/* Event ids of the Windows Filtering Platform audit. */
#define FS_WINEVT_PERMITTED   5156u
#define FS_WINEVT_BLOCKED     5157u

typedef struct
{
	guint64 record_id;  /* EventRecordID, 0 when it had none        */
	guint   event_id;   /* EventID                                  */
	FsHit  *hit;        /* NULL: not a firewall event with an
	                     * address (another event id, or no
	                     * DestAddress)                             */
} FsWinEvent;

void        fs_winevt_free        (FsWinEvent *event);

/* Every complete <Event> element of `xml' (wevtutil /f:xml output:
 * one element after another, with or without line breaks), in output
 * order, as FsWinEvent* (the array frees them).  *cut (may be NULL):
 * TRUE when the text ends inside an element, i.e. the output was cut
 * short; that element is left out. */
GPtrArray  *fs_winevt_parse_xml   (const gchar *xml, gboolean *cut);

/* The /q: value for the events after record `after' (0: all). */
gchar      *fs_winevt_query       (guint64 after);

/* The whole argv for one poll (after, at most `count', newest first)
 * and for the probe (the newest record of any kind).  NULL-terminated,
 * g_strfreev. */
gchar     **fs_winevt_poll_argv   (guint64 after, guint count);
gchar     **fs_winevt_probe_argv  (void);

typedef struct
{
	guint64 last_id;    /* the newest record delivered or skipped   */
	guint64 delivered;  /* events delivered this session            */
	guint64 skipped;    /* upper bound on events not read           */
	guint   clears;     /* times the log was seen cleared           */
	guint   cap;        /* how many the next poll asks for          */
} FsWinEvtCursor;

/* A cursor that starts after `newest' (the probe's answer, 0 for an
 * empty log). */
void        fs_winevt_cursor_init (FsWinEvtCursor *cursor, guint64 newest);

/* One poll's events (as parsed, any order) against the cursor: the
 * firewall events to deliver, oldest first, each record once, as
 * borrowed FsWinEvent* from `events' (free the returned array before
 * `events').  `asked' is how many the poll asked for, `cut' whether
 * the output was cut short.  Moves the cursor past everything read
 * and counts the skipped gap. */
GPtrArray  *fs_winevt_take        (FsWinEvtCursor *cursor, GPtrArray *events,
                                   guint asked, gboolean cut);

/* After a poll that found nothing: the newest record of any kind in
 * the log now.  Below the cursor, the log was cleared: the cursor goes
 * back to 0 and TRUE is returned. */
gboolean    fs_winevt_check_newest (FsWinEvtCursor *cursor, guint64 newest);

/* How many the next poll asks for, after one that timed out or not. */
void        fs_winevt_poll_done   (FsWinEvtCursor *cursor, gboolean timed_out);

/* The newest record number among `events' (0 when none has one). */
guint64     fs_winevt_newest      (GPtrArray *events);

G_END_DECLS

#endif /* FS_WINEVT_H */
