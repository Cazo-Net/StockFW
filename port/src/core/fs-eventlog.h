/*---[ fs-eventlog.h ]---------------------------------------------------
 * Event history on disk (1.0.7).
 *
 * Every event the Events page accepts is also appended to a log file
 * in the user's data folder, so the list survives a restart and the
 * command line can search back further than the list holds:
 *
 *   Linux    ~/.local/share/stockfw/events/
 *   Windows  %LOCALAPPDATA%\stockfw\events\
 *   (STOCKFW_EVENTS_DIR overrides both; the tests use it.)
 *
 * One file per UTC day, split into parts so no single file grows past
 * a twentieth of the size cap (at least 16 KB, at most 32 MB):
 * events-YYYY-MM-DD-NNN.log, the part three digits or more (-1000
 * follows -999).  A session goes on after the day's highest part, so
 * the day and then the part number give the time order.  An event is
 * filed under its own day, a late one under the file being written,
 * and one stamped after today under today.  Each line is one event,
 * tab-separated, with a checksum at the end:
 *
 *   ticks  time  direction  in  out  port  source  destination
 *   length  tos  protocol  service  rule  checksum
 *
 * ticks are 100 ns since 1970 UTC; text fields escape backslash, tab,
 * CR and LF; the checksum is FNV-1a 32 of everything before it, in
 * hex.  A line that is cut short (a crash mid-write) or damaged fails
 * its checksum and is skipped; the next writer starts a fresh line.
 *
 * Owner-only: the folder is created 0700 and each file 0600 on Linux.
 * On Windows the folder is under %LOCALAPPDATA%, whose permissions
 * already admit only the account, SYSTEM and Administrators.
 *
 * One writer: fs_eventlog_open locks <dir>/.lock (flock on Linux, a
 * file opened without sharing on Windows) until the log is closed or
 * the process ends.  A second copy of StockFW on the same folder gets
 * FS_EVENTLOG_ERROR_IN_USE and writes nothing, so no event is saved
 * twice and no two writers interleave lines.  Reading needs no lock.
 *
 * Limits: files older than the day limit and, oldest first, files
 * past the size cap are deleted when the log opens, when it moves to
 * a new file, and when the cap is passed.  A file counts as of the day
 * it was last written when that is before the day in its name.  Writes
 * are buffered and flushed by the caller (the Events page flushes
 * every second), so a crash loses at most the last unflushed second.
 *
 * A failed write (disk full, a quota, an I/O error) is not the end:
 * the events queued for it are dropped and counted, and the next
 * flush tries again after a back-off of 1 s doubling to 60 s (at once
 * after fs_eventlog_set_limits).  The first write that works clears
 * the problem.
 *
 * Reading streams each file in chunks, and the load at start counts
 * back from the end of the newest files, so it reads only the bytes
 * of the events it loads.
 *--------------------------------------------------------------------*/
#ifndef FS_EVENTLOG_H
#define FS_EVENTLOG_H

#include <glib.h>
#include "core/fs-types.h"
#include "core/fs-eventstore.h"

G_BEGIN_DECLS

#define FS_EVENTLOG_DEFAULT_DAYS   30u
#define FS_EVENTLOG_DEFAULT_MB    200u
#define FS_EVENTLOG_MIN_DAYS        1u
#define FS_EVENTLOG_MAX_DAYS     3650u
#define FS_EVENTLOG_MIN_MB          1u
#define FS_EVENTLOG_MAX_MB      10000u

typedef struct _FsEventLog FsEventLog;

#define FS_EVENTLOG_ERROR (fs_eventlog_error_quark ())
GQuark fs_eventlog_error_quark (void);

typedef enum
{
	/* Another process has this folder's history open for writing. */
	FS_EVENTLOG_ERROR_IN_USE = 1
} FsEventLogError;

/* STOCKFW_EVENTS_DIR, or <user data dir>/stockfw/events.  Caller frees. */
gchar      *fs_eventlog_default_dir (void);

/* Opens (creating, owner-only) the folder and prunes it to the limits.
 * max_bytes 0 or max_days 0 mean the defaults.  NULL with error when
 * the folder cannot be created, or FS_EVENTLOG_ERROR_IN_USE when
 * another process (another copy of StockFW) has it open: one writer
 * per folder, by a lock on <dir>/.lock held until fs_eventlog_close
 * or the end of the process. */
FsEventLog *fs_eventlog_open       (const gchar *dir, guint max_days,
                                    guint64 max_bytes, GError **error);
/* Flushes and closes. */
void        fs_eventlog_close      (FsEventLog *log);
const gchar *fs_eventlog_dir       (const FsEventLog *log);

/* New limits; prunes at once, and a failed write is tried again at the
 * next flush. */
void        fs_eventlog_set_limits (FsEventLog *log, guint max_days,
                                    guint64 max_bytes);

/* Queues one event (ticks as the store holds them) for the next flush;
 * flushes by itself past 64 KB.  FALSE while writing is failing (the
 * reason is in fs_eventlog_problem): the event waits for the next try
 * while the queue has room, and is dropped and counted after that. */
gboolean    fs_eventlog_append     (FsEventLog *log, const FsHit *hit,
                                    gint64 ticks);
gboolean    fs_eventlog_flush      (FsEventLog *log, GError **error);
/* Why writing is failing, or NULL once a write works again. */
const gchar *fs_eventlog_problem   (const FsEventLog *log);
/* Events lost to failed writes since the log was opened. */
guint64     fs_eventlog_dropped    (const FsEventLog *log);

/* Deletes every history file in the folder (the log stays open and
 * starts a new file).  Returns how many files went. */
guint       fs_eventlog_clear      (FsEventLog *log, GError **error);
/* The same from a process that is not the writer: it holds the lock
 * while it deletes, and deletes nothing (FS_EVENTLOG_ERROR_IN_USE)
 * while a log is open on dir, in another process or in this one. */
guint       fs_eventlog_clear_dir  (const gchar *dir, GError **error);

/* What the folder holds now. */
void        fs_eventlog_usage      (const gchar *dir, guint64 *bytes,
                                    guint *files);

/* Prunes dir to the limits as of now_us: files of days more than
 * max_days before today's (UTC) are deleted, then the oldest files
 * until the rest fit max_bytes.  keep (a file name, or NULL) is never
 * deleted.  Returns how many files went. */
guint       fs_eventlog_prune_dir  (const gchar *dir, guint max_days,
                                    guint64 max_bytes, gint64 now_us,
                                    const gchar *keep);

typedef struct
{
	guint   files;       /* files read                                 */
	guint64 bytes;       /* bytes read                                 */
	guint   lines;       /* lines that read as events                  */
	guint   bad_lines;   /* lines skipped: cut short, damaged, foreign */
	guint   loaded;      /* events the store accepted                  */
} FsEventLogStats;

/* Loads the most recent events, at most max_events, into store, oldest
 * first, as fs_eventstore_append would take them live.  Only the bytes
 * needed are read: back from the newest file's end until enough lines
 * are counted.
 * stats may be NULL.  Returns how many the store accepted. */
guint       fs_eventlog_load_recent (const gchar *dir, FsEventStore *store,
                                     guint max_events,
                                     FsEventLogStats *stats);

/* Calls func for every event in dir with since_us <= time < until_us
 * (0: open), oldest file first.  Files of days wholly outside the range
 * are not opened.  The hit's strings are borrowed for the call. */
typedef void (*FsEventLogFunc) (const FsHit *hit, gint64 ticks,
                                gpointer user_data);
void        fs_eventlog_foreach    (const gchar *dir, gint64 since_us,
                                    gint64 until_us, FsEventLogFunc func,
                                    gpointer user_data,
                                    FsEventLogStats *stats);

/* One line as written (with its newline), and back.  parse_line
 * edits line in place and points hit's fields into it. */
void        fs_eventlog_format_line (GString *out, const FsHit *hit,
                                     gint64 ticks);
gboolean    fs_eventlog_parse_line  (gchar *line, FsHit *hit,
                                     gint64 *ticks);

G_END_DECLS

#endif /* FS_EVENTLOG_H */
