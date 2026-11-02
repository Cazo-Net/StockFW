/*---[ fs-eventstore.h ]-------------------------------------------------
 * The in-memory event store behind the Events page (1.0.7).
 *
 * The page used to keep its rows in a GtkListStore capped at 2000:
 * every row was twelve heap strings, and every append walked the list
 * to find its place.  The store keeps events here instead, GTK-free,
 * so the core suite can pin it down and the command line can use it:
 *
 *   - a ring buffer of fixed-size records (56 bytes each): appending
 *     is O(1), and once the ring is full the event that arrived first
 *     is dropped to make room;
 *   - every text field is interned: a record holds 32-bit ids into a
 *     table of distinct strings, each string kept once with a count
 *     of the records that use it and freed with the last of them.
 *     The event's time is kept as a number (100 ns ticks since 1970,
 *     UTC) and the text the backend gave is rebuilt from it, so a
 *     time stamp costs no string at all;
 *   - filters (FsEventQuery) are decided once per distinct string and
 *     then read from a cache, so a query over 100,000 events tests a
 *     few thousand strings, not a million;
 *   - the same row twice in a row is one event: the store remembers
 *     the last 64 records it accepted and refuses an identical one
 *     (a monitor restart re-delivers its trailing window).
 *
 * Events are named by a sequence number (seq), 1 for the first event
 * the store ever accepted, never reused; a seq stays valid until its
 * event is dropped or the store is cleared.
 *--------------------------------------------------------------------*/
#ifndef FS_EVENTSTORE_H
#define FS_EVENTSTORE_H

#include <glib.h>
#include "core/fs-types.h"

G_BEGIN_DECLS

#define FS_EVENTSTORE_DEFAULT_CAPACITY  100000u
#define FS_EVENTSTORE_MIN_CAPACITY        1000u
#define FS_EVENTSTORE_MAX_CAPACITY     1000000u

/* The fields of one event.  FS_EV_TIME .. FS_EV_SERVICE are in the
 * order of FsHitColumn, so a list column index is a field index. */
typedef enum
{
	FS_EV_TIME = 0,
	FS_EV_DIRECTION,
	FS_EV_IN,
	FS_EV_OUT,
	FS_EV_PORT,
	FS_EV_SOURCE,
	FS_EV_DESTINATION,
	FS_EV_LENGTH,
	FS_EV_TOS,
	FS_EV_PROTOCOL,
	FS_EV_SERVICE,
	FS_EV_RULE,
	FS_EV_N_FIELDS
} FsEventField;

typedef struct _FsEventStore FsEventStore;

/* Called for each event just before it is dropped to make room (not
 * on fs_eventstore_clear).  The event can still be read in the call. */
typedef void (*FsEventEvictFunc) (FsEventStore *store, guint64 seq,
                                  gpointer user_data);

/* capacity is clamped to MIN..MAX. */
FsEventStore *fs_eventstore_new          (guint capacity);
void          fs_eventstore_free         (FsEventStore *store);
void          fs_eventstore_set_evict_func (FsEventStore *store,
                                          FsEventEvictFunc func,
                                          gpointer user_data);

guint         fs_eventstore_capacity     (const FsEventStore *store);
/* Changes the capacity (clamped).  Shrinking drops the events that
 * arrived first, through the evict func.  Returns the new capacity. */
guint         fs_eventstore_set_capacity (FsEventStore *store,
                                          guint capacity);

/* Accepts one event.  received_us (g_get_real_time() units) is the
 * event's time when its own stamp is not one the store can read.
 * Returns the new event's seq, or 0 when the hit repeats one of the
 * last 64 accepted (or is NULL). */
guint64       fs_eventstore_append       (FsEventStore *store,
                                          const FsHit *hit,
                                          gint64 received_us);

/* Drops every event and forgets the repeats; seqs keep counting. */
void          fs_eventstore_clear        (FsEventStore *store);

guint         fs_eventstore_length       (const FsEventStore *store);
/* The oldest and newest seq held; 0 when empty. */
guint64       fs_eventstore_first_seq    (const FsEventStore *store);
guint64       fs_eventstore_last_seq     (const FsEventStore *store);
gboolean      fs_eventstore_has          (const FsEventStore *store,
                                          guint64 seq);

/* The event's time: 100 ns ticks since 1970 UTC, and the same in
 * microseconds. */
gint64        fs_eventstore_ticks        (const FsEventStore *store,
                                          guint64 seq);
gint64        fs_eventstore_time_us      (const FsEventStore *store,
                                          guint64 seq);

/* A text field as the backend gave it ("" when it had none).  For
 * FS_EV_TIME use fs_eventstore_time_text.  Borrowed: valid until the
 * event is dropped. */
const gchar  *fs_eventstore_field        (const FsEventStore *store,
                                          guint64 seq, FsEventField field);
/* The time text as the backend gave it, rebuilt into buf when the
 * store keeps it as a number.  Returns buf or a borrowed string. */
#define FS_EVENT_TIME_BUF 40
const gchar  *fs_eventstore_time_text    (const FsEventStore *store,
                                          guint64 seq,
                                          gchar buf[FS_EVENT_TIME_BUF]);

gboolean      fs_eventstore_is_blocked   (const FsEventStore *store,
                                          guint64 seq);
gboolean      fs_eventstore_is_inbound   (const FsEventStore *store,
                                          guint64 seq);
gboolean      fs_eventstore_is_outbound  (const FsEventStore *store,
                                          guint64 seq);

/* A heap copy of the event (fs_hit_free). */
FsHit        *fs_eventstore_get_hit      (const FsEventStore *store,
                                          guint64 seq);

/* The interned strings: an event's id for a field (not FS_EV_TIME),
 * and the text behind an id ("" for 0, NULL for a free id).  The
 * view sorts by ranking the distinct strings once. */
guint32       fs_eventstore_field_id     (const FsEventStore *store,
                                          guint64 seq, FsEventField field);
const gchar  *fs_eventstore_atom         (const FsEventStore *store,
                                          guint32 id);
guint         fs_eventstore_n_atoms      (const FsEventStore *store);
/* Distinct strings held right now (ids in use). */
guint         fs_eventstore_n_strings    (const FsEventStore *store);

/* Bytes the store holds: records, the string table and the strings. */
gsize         fs_eventstore_memory       (const FsEventStore *store);

/* ---- time stamps ----------------------------------------------------
 *
 * The two stamps the backends write, read without GDateTime:
 *   FS_EVENT_TIME_FRAC7  "YYYY-MM-DDTHH:MM:SS.fffffffZ" (wevtutil)
 *   FS_EVENT_TIME_SECS   "YYYY-MM-DDTHH:MM:SSZ"         (kernel log)
 * Anything else is FS_EVENT_TIME_OTHER and is kept as text. */
typedef enum
{
	FS_EVENT_TIME_OTHER = 0,
	FS_EVENT_TIME_FRAC7,
	FS_EVENT_TIME_SECS
} FsEventTimeFormat;

FsEventTimeFormat fs_event_time_parse  (const gchar *text, gint64 *ticks);
/* Writes the stamp for ticks in format (not OTHER) into buf. */
void              fs_event_time_format (gint64 ticks, FsEventTimeFormat format,
                                        gchar buf[FS_EVENT_TIME_BUF]);
/* "YYYY-MM-DD" (UTC) of ticks into buf (11 bytes or more). */
void              fs_event_time_day    (gint64 ticks, gchar buf[16]);

/* ---- queries ------------------------------------------------------- */

typedef enum
{
	FS_EVQ_DIR_ANY = 0,
	FS_EVQ_DIR_IN,
	FS_EVQ_DIR_OUT
} FsEventDirFilter;

typedef enum
{
	FS_EVQ_ACTION_ANY = 0,
	FS_EVQ_ACTION_BLOCKED,
	FS_EVQ_ACTION_ALLOWED
} FsEventActionFilter;

/* What the filter bar and `stockfw events' can ask for.  Every part
 * is optional (NULL / empty / ANY / 0) and the parts are ANDed.
 *
 *   text       case-insensitive, anywhere in any text field (direction,
 *              devices, port, addresses, length, ToS, protocol,
 *              service, rule; the time has its own range below)
 *   protocol   the protocol, case-insensitive, whole
 *   port       "443", "1000-2000" or "1000:2000": the event's port
 *   address    an address, CIDR block ("10.0.0.0/8") or range
 *              ("a-b"), either family: the source OR the destination
 *              is inside it
 *   since_us   events at or after this time (g_get_real_time units)
 *   until_us   events before this time */
typedef struct
{
	const gchar         *text;
	FsEventDirFilter     direction;
	const gchar         *protocol;
	const gchar         *port;
	const gchar         *address;
	FsEventActionFilter  action;
	gint64               since_us;
	gint64               until_us;
} FsEventFilter;

typedef struct _FsEventQuery FsEventQuery;

#define FS_EVENTQUERY_ERROR (fs_eventquery_error_quark ())
GQuark fs_eventquery_error_quark (void);

typedef enum
{
	FS_EVENTQUERY_ERROR_PORT,
	FS_EVENTQUERY_ERROR_ADDRESS,
	FS_EVENTQUERY_ERROR_TIME
} FsEventQueryError;

/* NULL with error when the port or address cannot be read, or the
 * range is empty (since >= until).  filter may be NULL: everything. */
FsEventQuery *fs_eventquery_new       (const FsEventFilter *filter,
                                       GError **error);
void          fs_eventquery_free      (FsEventQuery *query);
/* TRUE when the query lets every event through. */
gboolean      fs_eventquery_is_empty  (const FsEventQuery *query);

/* One stored event; the per-string answers are cached in the query. */
gboolean      fs_eventquery_match     (FsEventQuery *query,
                                       const FsEventStore *store,
                                       guint64 seq);
/* The same question for an event that is not in a store (the command
 * line reading the history file).  time_us is the event's time. */
gboolean      fs_eventquery_match_hit (const FsEventQuery *query,
                                       const FsHit *hit, gint64 time_us);

/* Every stored event the query lets through, oldest first, appended
 * to seqs (a GArray of guint64).  Returns how many. */
guint         fs_eventstore_select    (const FsEventStore *store,
                                       FsEventQuery *query,
                                       GArray *seqs);

/* Reads a time for --since / --until and the From / To boxes:
 *   ""                    0: no bound
 *   "now"
 *   "90s" "15m" "2h" "3d" "1w"   that long before now_us
 *   "YYYY-MM-DD"          local midnight; as an end bound (end TRUE)
 *                         the midnight after, so "to 2026-11-01"
 *                         takes in the whole day
 *   "YYYY-MM-DD HH:MM[:SS]" or with a T: local time
 *   an ISO-8601 stamp with Z or an offset
 * FALSE with error otherwise. */
gboolean      fs_event_parse_time_spec (const gchar *text, gint64 now_us,
                                        gboolean end, gint64 *out_us,
                                        GError **error);

/* ---- export ---------------------------------------------------------
 *
 * The events named by seqs, in that order, as CSV (RFC 4180, UTF-8,
 * header row): time (as the backend gave it), direction, in, out, port,
 * source, destination, length, tos, protocol, service, action
 * (blocked/allowed), rule.  A field a spreadsheet would run as a
 * formula (leading = + @, or - not followed by a digit) is written
 * with a leading apostrophe.  The file is replaced whole and readable
 * by its owner only.  Seqs no longer held are skipped; *written says
 * how many rows went out. */
gboolean      fs_eventstore_write_csv  (const FsEventStore *store,
                                        const guint64 *seqs, guint n_seqs,
                                        const gchar *path, guint *written,
                                        GError **error);
/* One CSV row for an event (no newline), appended to out. */
void          fs_event_csv_row         (GString *out, const FsHit *hit,
                                        gboolean blocked);

G_END_DECLS

#endif /* FS_EVENTSTORE_H */
