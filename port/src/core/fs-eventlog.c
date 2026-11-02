/*---[ fs-eventlog.c ]---------------------------------------------------
 * Event history on disk.  See fs-eventlog.h.
 *--------------------------------------------------------------------*/

#include "core/fs-eventlog.h"

#include <glib/gstdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef G_OS_WIN32
#include <io.h>
#include <windows.h>
#else
#include <sys/file.h>
#include <unistd.h>
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define HEADER       "# StockFW event history 1\n"
#define N_FIELDS     13                  /* before the checksum */
#define FLUSH_AT     (64 * 1024)
#define TICKS_PER_DAY ((gint64) 864000000000)

struct _FsEventLog
{
	gchar   *dir;
	guint    max_days;
	guint64  max_bytes;

	int      fd;            /* -1 until the first flush needs it */
	gchar    cur_day[16];   /* "" before the first event         */
	gint64   cur_daynum;    /* cur_day, as days since 1970       */
	guint    cur_part;
	gboolean part_known;    /* cur_part looked up for cur_day    */
	gchar   *cur_name;
	guint64  cur_size;
	guint64  total_bytes;   /* every history file, about          */

	GString *buf;
	gchar   *problem;       /* the last write failure, until a write
	                         * works again                        */
	gint64   retry_at;      /* monotonic us: the next try         */
	guint    retry_s;       /* the back-off now                   */
	guint64  dropped;       /* events lost to failed writes       */

	/* The writer lock on <dir>/.lock (fs_eventlog_open). */
#ifdef G_OS_WIN32
	HANDLE   lock;          /* INVALID_HANDLE_VALUE: none         */
#else
	int      lock;          /* -1: none                           */
#endif
};

G_DEFINE_QUARK (fs-eventlog-error-quark, fs_eventlog_error)

/* ------------------------------------------------------------ names */

/* "events-YYYY-MM-DD-N.log", N three to nine digits.  Parts are written
 * as %03u, so the 1000th of a day is -1000: a fixed length of three
 * used to hide it and every later part from the limits, the load and
 * Delete history, and the folder grew past its cap without bound. */
#define NAME_DAY_END 17               /* "events-YYYY-MM-DD"            */
#define PART_DIGITS_MAX 9
#define PART_LAST 999999999u

static gboolean
is_log_name (const gchar *name)
{
	gsize len = strlen (name);
	gsize digits;

	if (len < NAME_DAY_END + 1 + 3 + 4 ||
	    len > NAME_DAY_END + 1 + PART_DIGITS_MAX + 4 ||
	    !g_str_has_prefix (name, "events-") ||
	    !g_str_has_suffix (name, ".log") || name[NAME_DAY_END] != '-')
		return FALSE;

	for (guint i = 7; i < NAME_DAY_END; i++) {
		gboolean dash = (i == 11 || i == 14);

		if (dash ? name[i] != '-' : !g_ascii_isdigit (name[i]))
			return FALSE;
	}

	digits = len - NAME_DAY_END - 1 - 4;
	for (gsize i = 0; i < digits; i++)
		if (!g_ascii_isdigit (name[NAME_DAY_END + 1 + i]))
			return FALSE;

	return TRUE;
}

static guint
name_part (const gchar *name)
{
	return (guint) g_ascii_strtoull (name + NAME_DAY_END + 1, NULL, 10);
}

/* Days since 1970 of a file name's date. */
static gint64
name_day (const gchar *name)
{
	gchar stamp[24];
	gint64 ticks = 0;

	g_snprintf (stamp, sizeof stamp, "%.10sT00:00:00Z", name + 7);
	if (fs_event_time_parse (stamp, &ticks) == FS_EVENT_TIME_OTHER)
		return 0;

	return ticks / TICKS_PER_DAY;
}

typedef struct
{
	gchar   *name;
	gint64   day;       /* the name's day                                */
	guint    part;
	guint64  size;
	/* The day it counts as for the limits: the name's, or the day it
	 * was last written when that is earlier.  A file named for a day
	 * after it was written (an event stamped in the future, before
	 * such stamps were filed under today) would otherwise sort as the
	 * newest, outlive the real recent files under the size cap, and
	 * escape the age limit until that future date. */
	gint64   age_day;
	gint64   mtime;     /* seconds; 0 when unknown                       */
} LogFile;

static void
log_file_free (gpointer p)
{
	LogFile *f = p;

	g_free (f->name);
	g_free (f);
}

static gint
cmp_files (gconstpointer a, gconstpointer b)
{
	const LogFile *x = *(const LogFile * const *) a;
	const LogFile *y = *(const LogFile * const *) b;

	if (x->age_day != y->age_day)
		return x->age_day < y->age_day ? -1 : 1;
	if (x->mtime != y->mtime)
		return x->mtime < y->mtime ? -1 : 1;
	if (x->day != y->day)
		return x->day < y->day ? -1 : 1;
	if (x->part != y->part)
		return x->part < y->part ? -1 : 1;
	return strcmp (x->name, y->name);
}

/* [ list_logs ]
 * The history files in dir, oldest first: by age_day, then by when
 * each was last written, then by the name's day and the part as a
 * number (part 1000 after 999).  A day's parts are written in order (a
 * session goes on after the highest part there is, see open_current),
 * so the last write and the part number agree; the write time is what
 * puts a misdated file where its events belong. */
static GPtrArray *
list_logs (const gchar *dir)
{
	GPtrArray *files = g_ptr_array_new_with_free_func (log_file_free);
	GDir *d = g_dir_open (dir, 0, NULL);
	const gchar *name;

	if (d == NULL)
		return files;

	while ((name = g_dir_read_name (d)) != NULL) {
		LogFile *f;
		gchar *path;
		GStatBuf st;

		if (!is_log_name (name))
			continue;

		f = g_new0 (LogFile, 1);
		f->name = g_strdup (name);
		f->day = name_day (name);
		f->part = name_part (name);
		f->age_day = f->day;

		path = g_build_filename (dir, name, NULL);
		if (g_stat (path, &st) == 0) {
			gint64 written = (gint64) st.st_mtime / 86400;

			f->size = (guint64) st.st_size;
			f->mtime = (gint64) st.st_mtime;
			if (st.st_mtime > 0 && written < f->day)
				f->age_day = written;
		}
		g_free (path);

		g_ptr_array_add (files, f);
	}

	g_dir_close (d);
	g_ptr_array_sort (files, cmp_files);

	return files;
}

#define LOG_AT(files, i) ((LogFile *) g_ptr_array_index ((files), (i)))

static guint64
file_size (const gchar *path)
{
	GStatBuf st;

	if (g_stat (path, &st) != 0)
		return 0;

	return (guint64) st.st_size;
}

gchar *
fs_eventlog_default_dir (void)
{
	const gchar *env = g_getenv ("STOCKFW_EVENTS_DIR");

	if (env != NULL && *env != '\0')
		return g_strdup (env);

	return g_build_filename (g_get_user_data_dir (), "stockfw", "events",
	                         NULL);
}

/* ------------------------------------------------------------- lines */

static guint32
fnv1a (const gchar *p, gsize n)
{
	guint32 h = 2166136261u;

	for (gsize i = 0; i < n; i++) {
		h ^= (guchar) p[i];
		h *= 16777619u;
	}

	return h;
}

static void
put_escaped (GString *out, const gchar *s)
{
	if (s == NULL)
		return;

	for (; *s != '\0'; s++) {
		switch (*s) {
		case '\\': g_string_append (out, "\\\\"); break;
		case '\t': g_string_append (out, "\\t");  break;
		case '\n': g_string_append (out, "\\n");  break;
		case '\r': g_string_append (out, "\\r");  break;
		default:   g_string_append_c (out, *s);   break;
		}
	}
}

void
fs_eventlog_format_line (GString *out, const FsHit *h, gint64 ticks)
{
	gsize start = out->len;
	const gchar *fields[] = {
		h->time, h->direction, h->in, h->out, h->port, h->source,
		h->destination, h->length, h->tos, h->protocol, h->service,
		h->rule
	};

	g_string_append_printf (out, "%" G_GINT64_FORMAT, ticks);
	for (guint i = 0; i < G_N_ELEMENTS (fields); i++) {
		g_string_append_c (out, '\t');
		put_escaped (out, fields[i]);
	}

	g_string_append_printf (out, "\t%08x\n",
	                        fnv1a (out->str + start, out->len - start));
}

/* In place: the unescaped text is never longer. */
static gboolean
unescape (gchar *s)
{
	gchar *w = s;

	for (gchar *r = s; *r != '\0'; r++) {
		if (*r != '\\') {
			*w++ = *r;
			continue;
		}
		r++;
		switch (*r) {
		case '\\': *w++ = '\\'; break;
		case 't':  *w++ = '\t'; break;
		case 'n':  *w++ = '\n'; break;
		case 'r':  *w++ = '\r'; break;
		default:   return FALSE;   /* also a lone trailing backslash */
		}
	}
	*w = '\0';

	return TRUE;
}

gboolean
fs_eventlog_parse_line (gchar *line, FsHit *hit, gint64 *ticks)
{
	gchar *fields[N_FIELDS];
	gchar *tab, *p, *end;
	gsize len;
	guint64 crc;
	guint n = 0;

	memset (hit, 0, sizeof *hit);
	len = strlen (line);
	if (len > 0 && line[len - 1] == '\n')
		line[--len] = '\0';
	if (len > 0 && line[len - 1] == '\r')
		line[--len] = '\0';

	tab = strrchr (line, '\t');
	if (tab == NULL || strlen (tab + 1) != 8)
		return FALSE;

	crc = g_ascii_strtoull (tab + 1, &end, 16);
	if (*end != '\0' || crc != fnv1a (line, (gsize) (tab - line)))
		return FALSE;
	*tab = '\0';

	for (p = line; n < N_FIELDS; n++) {
		fields[n] = p;
		p = strchr (p, '\t');
		if (p == NULL) {
			n++;
			break;
		}
		*p++ = '\0';
	}
	if (n != N_FIELDS || p != NULL)
		return FALSE;

	*ticks = g_ascii_strtoll (fields[0], &end, 10);
	if (*fields[0] == '\0' || *end != '\0')
		return FALSE;

	for (guint i = 1; i < N_FIELDS; i++)
		if (!unescape (fields[i]))
			return FALSE;

	hit->time        = fields[1];
	hit->direction   = fields[2];
	hit->in          = fields[3];
	hit->out         = fields[4];
	hit->port        = fields[5];
	hit->source      = fields[6];
	hit->destination = fields[7];
	hit->length      = fields[8];
	hit->tos         = fields[9];
	hit->protocol    = fields[10];
	hit->service     = fields[11];
	hit->rule        = *fields[12] != '\0' ? fields[12] : NULL;

	return TRUE;
}

/* --------------------------------------------------------------- log */

/* A part is a twentieth of the cap, between 16 KB and 32 MB.  Without
 * the top, the 10,000 MB setting made 500 MB parts, and the start read
 * a whole one to show the last 1,000 events. */
#define PART_MIN ((guint64) 16 * 1024)
#define PART_TOP ((guint64) 32 * 1024 * 1024)

/* After a failed write, the next try waits 1 s, then 2, 4 ... 60 s. */
#define RETRY_MAX_S 60u

static guint64
part_max (const FsEventLog *log)
{
	return CLAMP (log->max_bytes / 20, PART_MIN, PART_TOP);
}

/* Lines of a buffer that could be events (not headers, not empty). */
static guint
count_lines (const gchar *text, gsize len)
{
	const gchar *p = text, *end = text + len;
	guint n = 0;

	while (p < end) {
		const gchar *nl = memchr (p, '\n', (gsize) (end - p));
		const gchar *stop = nl != NULL ? nl : end;

		if (stop > p && *p != '#')
			n++;
		p = stop + 1;
	}

	return n;
}

/* [ set_problem ]
 * Writing failed.  What was queued is dropped and counted, the file is
 * closed, and the next flush after the back-off tries again: a full
 * disk that gets space back, or a quota raised, resumes the history
 * without a restart. */
static void
set_problem (FsEventLog *log, const gchar *what, int err)
{
	g_free (log->problem);
	log->problem = g_strdup_printf ("%s: %s", what, g_strerror (err));
	log->dropped += count_lines (log->buf->str, log->buf->len);
	g_string_truncate (log->buf, 0);
	if (log->fd >= 0) {
		close (log->fd);
		log->fd = -1;
	}

	log->retry_s = log->retry_s == 0 ? 1 : MIN (log->retry_s * 2,
	                                            RETRY_MAX_S);
	log->retry_at = g_get_monotonic_time () +
	                (gint64) log->retry_s * G_USEC_PER_SEC;
}

static gboolean
make_dir (const gchar *dir, GError **error)
{
	if (g_mkdir_with_parents (dir, 0700) != 0) {
		int err = errno;

		g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (err),
		             "cannot create %s: %s", dir, g_strerror (err));
		return FALSE;
	}
#ifndef G_OS_WIN32
	/* An existing folder keeps whatever it had; history is the
	 * account's own. */
	g_chmod (dir, 0700);
#endif
	return TRUE;
}

void
fs_eventlog_usage (const gchar *dir, guint64 *bytes, guint *files)
{
	GPtrArray *list = list_logs (dir);
	guint64 total = 0;

	for (guint i = 0; i < list->len; i++)
		total += LOG_AT (list, i)->size;

	if (bytes != NULL)
		*bytes = total;
	if (files != NULL)
		*files = list->len;
	g_ptr_array_unref (list);
}

guint
fs_eventlog_prune_dir (const gchar *dir, guint max_days, guint64 max_bytes,
                       gint64 now_us, const gchar *keep)
{
	GPtrArray *list = list_logs (dir);
	gint64 today = (now_us * 10) / TICKS_PER_DAY;
	gboolean *gone = g_new0 (gboolean, list->len + 1);
	guint64 total = 0;
	guint removed = 0;

	for (guint i = 0; i < list->len; i++) {
		LogFile *f = LOG_AT (list, i);
		gchar *path;

		total += f->size;
		if (max_days == 0 ||
		    f->age_day >= today - (gint64) max_days ||
		    g_strcmp0 (f->name, keep) == 0)
			continue;

		path = g_build_filename (dir, f->name, NULL);
		if (g_remove (path) == 0) {
			gone[i] = TRUE;
			total -= f->size;
			removed++;
		}
		g_free (path);
	}

	/* Oldest first, today's earlier parts included, until the rest
	 * fit. */
	for (guint i = 0; i < list->len && max_bytes > 0 &&
	                  total > max_bytes; i++) {
		LogFile *f = LOG_AT (list, i);
		gchar *path;

		if (gone[i] || g_strcmp0 (f->name, keep) == 0)
			continue;

		path = g_build_filename (dir, f->name, NULL);
		if (g_remove (path) == 0) {
			total -= f->size;
			removed++;
		}
		g_free (path);
	}

	g_free (gone);
	g_ptr_array_unref (list);

	return removed;
}

/* [ take_lock ]
 * One writer per folder.  Two copies of StockFW appending to the same
 * day's file would interleave their lines and save each event twice
 * (both read the same firewall log).  One copy per user is the
 * instance guard's job (core/fs-instance.h), but it can be bypassed:
 * a squatted instance name, or a privileged copy that could not make
 * the running one quit, runs "unguarded" beside it.  The lock holds
 * for as long as the log is open, and the system drops it when the
 * process ends, so there is never a stale lock to clean up.
 *
 * Linux: flock() on <dir>/.lock (0600).  Windows: <dir>\.lock opened
 * with no sharing.  A lock file that cannot be opened at all (the
 * folder is someone else's) is no reason to refuse: writing will say
 * what is wrong.  Returns FALSE only when another writer holds it. */
#define LOCK_NAME ".lock"

static gboolean
take_lock (FsEventLog *log, GError **error)
{
	gchar *path = g_build_filename (log->dir, LOCK_NAME, NULL);
	gboolean busy = FALSE;
#ifdef G_OS_WIN32
	gunichar2 *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);

	log->lock = INVALID_HANDLE_VALUE;
	if (wide != NULL) {
		log->lock = CreateFileW (wide, GENERIC_READ | GENERIC_WRITE, 0,
		                         NULL, OPEN_ALWAYS,
		                         FILE_ATTRIBUTE_HIDDEN, NULL);
		busy = log->lock == INVALID_HANDLE_VALUE &&
		       GetLastError () == ERROR_SHARING_VIOLATION;
	}
	g_free (wide);
#else
	log->lock = open (path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
	                  0600);
	if (log->lock >= 0 && flock (log->lock, LOCK_EX | LOCK_NB) != 0) {
		busy = errno == EWOULDBLOCK || errno == EAGAIN;
		close (log->lock);
		log->lock = -1;
	}
#endif
	if (busy)
		g_set_error (error, FS_EVENTLOG_ERROR, FS_EVENTLOG_ERROR_IN_USE,
		             "another copy of StockFW is saving the history in "
		             "%s; this one does not write it", log->dir);
	g_free (path);
	return !busy;
}

static void
drop_lock (FsEventLog *log)
{
#ifdef G_OS_WIN32
	if (log->lock != INVALID_HANDLE_VALUE)
		CloseHandle (log->lock);
	log->lock = INVALID_HANDLE_VALUE;
#else
	if (log->lock >= 0)
		close (log->lock);     /* drops the flock */
	log->lock = -1;
#endif
}

FsEventLog *
fs_eventlog_open (const gchar *dir, guint max_days, guint64 max_bytes,
                  GError **error)
{
	FsEventLog *log;

	g_return_val_if_fail (dir != NULL, NULL);

	if (!make_dir (dir, error))
		return NULL;

	log = g_new0 (FsEventLog, 1);
	log->dir = g_strdup (dir);
	log->fd = -1;
	if (!take_lock (log, error)) {
		g_free (log->dir);
		g_free (log);
		return NULL;
	}
	log->buf = g_string_sized_new (FLUSH_AT + 1024);
	fs_eventlog_set_limits (log, max_days, max_bytes);

	return log;
}

const gchar *
fs_eventlog_dir (const FsEventLog *log)
{
	return log != NULL ? log->dir : NULL;
}

void
fs_eventlog_set_limits (FsEventLog *log, guint max_days, guint64 max_bytes)
{
	g_return_if_fail (log != NULL);

	log->max_days = max_days > 0
		? CLAMP (max_days, FS_EVENTLOG_MIN_DAYS, FS_EVENTLOG_MAX_DAYS)
		: FS_EVENTLOG_DEFAULT_DAYS;
	log->max_bytes = max_bytes > 0
		? CLAMP (max_bytes,
		         (guint64) FS_EVENTLOG_MIN_MB * 1024 * 1024,
		         (guint64) FS_EVENTLOG_MAX_MB * 1024 * 1024)
		: (guint64) FS_EVENTLOG_DEFAULT_MB * 1024 * 1024;

	/* Saving Preferences is also the user's "try again": a failed
	 * write is retried at the next flush, not after the back-off. */
	log->retry_at = 0;

	fs_eventlog_prune_dir (log->dir, log->max_days, log->max_bytes,
	                       g_get_real_time (), log->cur_name);
	fs_eventlog_usage (log->dir, &log->total_bytes, NULL);
}

static void
close_current (FsEventLog *log)
{
	if (log->fd >= 0)
		close (log->fd);
	log->fd = -1;
	g_clear_pointer (&log->cur_name, g_free);
	log->cur_size = 0;
}

/* The highest part there is of cur_day, or 0. */
static guint
last_part (FsEventLog *log)
{
	GPtrArray *list = list_logs (log->dir);
	gchar *prefix = g_strdup_printf ("events-%s-", log->cur_day);
	guint best = 0;

	for (guint i = 0; i < list->len; i++) {
		LogFile *f = LOG_AT (list, i);

		if (g_str_has_prefix (f->name, prefix))
			best = MAX (best, f->part);
	}

	g_free (prefix);
	g_ptr_array_unref (list);
	return best;
}

/* [ open_current ]
 * The file for cur_day: the last part that still has room, or a new
 * one.  A session goes on from the highest part of the day there is,
 * never a lower free number: once the size cap had deleted the day's
 * first parts, a restart wrote the newest events into -000, which then
 * sorted as the oldest, so the start did not show them and the next
 * prune deleted them first.  A file whose last line was cut short gets
 * a newline first, so the next line starts clean (the cut one fails
 * its checksum). */
static gboolean
open_current (FsEventLog *log)
{
	gchar *path = NULL;
	gint fd;
	GStatBuf st;

	if (log->fd >= 0)
		return TRUE;

	if (!log->part_known) {
		log->cur_part = last_part (log);
		log->part_known = TRUE;
	}

	for (;; log->cur_part++) {
		g_free (log->cur_name);
		log->cur_name = g_strdup_printf ("events-%s-%03u.log",
		                                 log->cur_day, log->cur_part);
		g_free (path);
		path = g_build_filename (log->dir, log->cur_name, NULL);

		if (log->cur_part >= PART_LAST ||
		    file_size (path) < part_max (log))
			break;
	}

	fd = g_open (path, O_WRONLY | O_CREAT | O_APPEND | O_BINARY |
	                   O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0) {
		set_problem (log, path, errno);
		g_free (path);
		return FALSE;
	}

#ifndef G_OS_WIN32
	if (fchmod (fd, 0600) != 0) {
		int err = errno;

		close (fd);
		set_problem (log, path, err);
		g_free (path);
		return FALSE;
	}
#endif

	log->fd = fd;
	log->cur_size = 0;
	if (g_stat (path, &st) == 0)
		log->cur_size = (guint64) st.st_size;

	if (log->cur_size == 0) {
		g_string_prepend (log->buf, HEADER);
	} else {
		gchar last = '\n';
		gint rfd = g_open (path, O_RDONLY | O_BINARY, 0);

		if (rfd >= 0) {
			if (lseek (rfd, -1, SEEK_END) >= 0 &&
			    read (rfd, &last, 1) != 1)
				last = '\n';
			close (rfd);
		}
		if (last != '\n')
			g_string_prepend_c (log->buf, '\n');
	}

	g_free (path);
	return TRUE;
}

gboolean
fs_eventlog_flush (FsEventLog *log, GError **error)
{
	const gchar *p;
	gsize left;

	if (log == NULL)
		return TRUE;

	/* Failing: wait out the back-off, then try again with whatever
	 * was queued since. */
	if (log->problem != NULL &&
	    (g_get_monotonic_time () < log->retry_at || log->buf->len == 0)) {
		g_set_error_literal (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
		                     log->problem);
		return FALSE;
	}

	if (log->buf->len == 0)
		return TRUE;

#ifndef G_OS_WIN32
	/* The file deleted from outside while open (by hand, or a tool
	 * that ignored the lock): writing on would fill a file no one can
	 * see, and lose every event in it.  Start a new one instead.
	 * Windows does not delete a file this log has open. */
	if (log->fd >= 0) {
		struct stat st;

		if (fstat (log->fd, &st) == 0 && st.st_nlink == 0) {
			close_current (log);
			log->part_known = FALSE;
			fs_eventlog_usage (log->dir, &log->total_bytes, NULL);
		}
	}
#endif

	if (!open_current (log)) {
		g_set_error_literal (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
		                     log->problem);
		return FALSE;
	}

	p = log->buf->str;
	left = log->buf->len;
	while (left > 0) {
		gssize n = write (log->fd, p, (unsigned int) left);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			int err = n < 0 ? errno : ENOSPC;
			gchar *what = g_strdup_printf ("writing %s",
			                               log->cur_name);

			/* What did reach the file is not counted as lost. */
			g_string_erase (log->buf, 0, (gssize) (p - log->buf->str));
			set_problem (log, what, err);
			g_free (what);
			g_set_error_literal (error, G_FILE_ERROR,
			                     g_file_error_from_errno (err),
			                     log->problem);
			return FALSE;
		}
		p += n;
		left -= (gsize) n;
		log->cur_size += (guint64) n;
		log->total_bytes += (guint64) n;
	}
	g_string_truncate (log->buf, 0);

	/* Written again: the problem is over. */
	g_clear_pointer (&log->problem, g_free);
	log->retry_s = 0;
	log->retry_at = 0;

	/* A full part: the next flush starts the next one. */
	if (log->cur_size >= part_max (log)) {
		close_current (log);
		if (log->cur_part < PART_LAST)
			log->cur_part++;
	}

	if (log->total_bytes > log->max_bytes) {
		fs_eventlog_prune_dir (log->dir, log->max_days, log->max_bytes,
		                       g_get_real_time (), log->cur_name);
		fs_eventlog_usage (log->dir, &log->total_bytes, NULL);
	}

	return TRUE;
}

/* [ fs_eventlog_append ]
 * The file is the event's day, with two exceptions.  A late event
 * older than the file being written joins that file.  An event stamped
 * after today (a clock that jumped ahead and came back, a garbled
 * stamp) is filed under today: going by the newest stamp seen, one
 * such event used to move every later event of the session into the
 * future day's file, which the size cap then kept over the real recent
 * files.  And when the file being written is itself after today (the
 * clock was put back), the log moves back to today. */
gboolean
fs_eventlog_append (FsEventLog *log, const FsHit *hit, gint64 ticks)
{
	gint64 today, day;

	if (log == NULL || hit == NULL)
		return FALSE;

	/* Failing, with the queue for the next try full: try now if the
	 * back-off is over, else this one is lost, and counted. */
	if (log->problem != NULL && log->buf->len >= FLUSH_AT &&
	    !fs_eventlog_flush (log, NULL)) {
		log->dropped++;
		return FALSE;
	}

	today = (g_get_real_time () * 10) / TICKS_PER_DAY;
	day = ticks >= 0 ? ticks / TICKS_PER_DAY : 0;
	if (day > today)
		day = today;

	if (log->cur_day[0] == '\0' || day > log->cur_daynum ||
	    log->cur_daynum > today) {
		if (log->cur_day[0] != '\0' && log->problem == NULL)
			fs_eventlog_flush (log, NULL);
		close_current (log);
		fs_event_time_day (day * TICKS_PER_DAY, log->cur_day);
		log->cur_daynum = day;
		log->cur_part = 0;
		log->part_known = FALSE;
		fs_eventlog_prune_dir (log->dir, log->max_days, log->max_bytes,
		                       g_get_real_time (), NULL);
		fs_eventlog_usage (log->dir, &log->total_bytes, NULL);
	}

	/* The file open, so its size is known before the queue is
	 * measured against the part's room: a session that went on in a
	 * part half full used to overrun it by a whole queue. */
	if (log->fd < 0 && log->problem == NULL)
		open_current (log);

	fs_eventlog_format_line (log->buf, hit, ticks);

	if (log->buf->len >= FLUSH_AT ||
	    log->cur_size + log->buf->len >= part_max (log))
		return fs_eventlog_flush (log, NULL);

	return log->problem == NULL;
}

const gchar *
fs_eventlog_problem (const FsEventLog *log)
{
	return log != NULL ? log->problem : NULL;
}

guint64
fs_eventlog_dropped (const FsEventLog *log)
{
	return log != NULL ? log->dropped : 0;
}

void
fs_eventlog_close (FsEventLog *log)
{
	if (log == NULL)
		return;

	/* The last try, whatever the back-off says. */
	log->retry_at = 0;
	fs_eventlog_flush (log, NULL);
	close_current (log);
	drop_lock (log);
	g_string_free (log->buf, TRUE);
	g_free (log->problem);
	g_free (log->dir);
	g_free (log);
}

static guint
delete_logs (const gchar *dir, GError **error)
{
	GPtrArray *list = list_logs (dir);
	guint removed = 0;

	for (guint i = 0; i < list->len; i++) {
		gchar *path = g_build_filename (dir, LOG_AT (list, i)->name,
		                                NULL);

		if (g_remove (path) == 0)
			removed++;
		else if (error != NULL && *error == NULL)
			g_set_error (error, G_FILE_ERROR,
			             g_file_error_from_errno (errno),
			             "cannot delete %s: %s", path,
			             g_strerror (errno));
		g_free (path);
	}

	g_ptr_array_unref (list);
	return removed;
}

/* [ fs_eventlog_clear_dir ]
 * Delete history from a copy that is not the writer.  It takes the
 * writer's lock for as long as it deletes, so it deletes nothing while
 * another copy has the history open: on Linux that copy would go on
 * appending to the file it has open after the name was gone, and every
 * event it saved after the delete was lost without a word, until it
 * moved to a new part or a new day. */
guint
fs_eventlog_clear_dir (const gchar *dir, GError **error)
{
	FsEventLog probe = { 0 };
	guint removed;

	g_return_val_if_fail (dir != NULL, 0);

	probe.dir = (gchar *) dir;
	if (!g_file_test (dir, G_FILE_TEST_IS_DIR))
		return 0;
	if (!take_lock (&probe, NULL)) {
		g_set_error (error, FS_EVENTLOG_ERROR, FS_EVENTLOG_ERROR_IN_USE,
		             "another copy of StockFW is saving the history in "
		             "%s; nothing was deleted (delete it from that copy, "
		             "or quit it first)", dir);
		return 0;
	}
	removed = delete_logs (dir, error);
	drop_lock (&probe);
	return removed;
}

guint
fs_eventlog_clear (FsEventLog *log, GError **error)
{
	guint removed;

	if (log == NULL)
		return 0;

	g_string_truncate (log->buf, 0);
	close_current (log);
	log->cur_part = 0;
	log->part_known = FALSE;
	log->cur_day[0] = '\0';
	log->cur_daynum = 0;
	g_clear_pointer (&log->problem, g_free);
	log->retry_s = 0;
	log->retry_at = 0;

	removed = delete_logs (log->dir, error);
	fs_eventlog_usage (log->dir, &log->total_bytes, NULL);

	return removed;
}

/* ----------------------------------------------------------- reading */

/* Files are read in chunks, so memory stays at one chunk and one line
 * whatever a file's size; a line longer than LINE_LONGEST is damage. */
#define READ_CHUNK   (256 * 1024)
#define LINE_LONGEST (64 * 1024)

#ifdef G_OS_WIN32
#define seek64 _fseeki64
#define tell64 _ftelli64
#else
#define seek64 fseeko
#define tell64 ftello
#endif

typedef void (*LineFunc) (const FsHit *hit, gint64 ticks, gpointer data);

/* One line, without its newline; line[len] may be overwritten. */
static void
take_line (gchar *line, gsize len, LineFunc func, gpointer data,
           FsEventLogStats *stats)
{
	FsHit hit;
	gint64 ticks;

	if (len == 0 || line[0] == '#')
		return;

	line[len] = '\0';
	if (fs_eventlog_parse_line (line, &hit, &ticks)) {
		if (stats != NULL)
			stats->lines++;
		func (&hit, ticks, data);
	} else if (stats != NULL) {
		stats->bad_lines++;
	}
}

/* Every event line of one file from byte `from' on. */
static void
read_file (const gchar *path, gint64 from, LineFunc func, gpointer data,
           FsEventLogStats *stats)
{
	FILE *f = g_fopen (path, "rb");
	gchar *chunk;
	GString *carry;
	gboolean too_long = FALSE;
	gsize n;

	if (f == NULL)
		return;
	if (from > 0 && seek64 (f, from, SEEK_SET) != 0) {
		fclose (f);
		return;
	}

	if (stats != NULL)
		stats->files++;

	chunk = g_malloc (READ_CHUNK + 1);
	carry = g_string_new (NULL);

	while ((n = fread (chunk, 1, READ_CHUNK, f)) > 0) {
		gchar *p = chunk, *end = chunk + n;

		if (stats != NULL)
			stats->bytes += n;

		while (p < end) {
			gchar *nl = memchr (p, '\n', (gsize) (end - p));
			gsize len = (gsize) ((nl != NULL ? nl : end) - p);

			/* A line that goes on in the next chunk. */
			if (nl == NULL) {
				if (!too_long &&
				    carry->len + len <= LINE_LONGEST)
					g_string_append_len (carry, p,
					                     (gssize) len);
				else {
					too_long = TRUE;
					g_string_truncate (carry, 0);
				}
				break;
			}

			if (too_long || carry->len + len > LINE_LONGEST) {
				if (stats != NULL)
					stats->bad_lines++;
			} else if (carry->len > 0) {
				g_string_append_len (carry, p, (gssize) len);
				take_line (carry->str, carry->len, func, data,
				           stats);
			} else {
				take_line (p, len, func, data, stats);
			}
			too_long = FALSE;
			g_string_truncate (carry, 0);
			p = nl + 1;
		}
	}

	/* A last line with no newline: cut short, or being written. */
	if (too_long) {
		if (stats != NULL)
			stats->bad_lines++;
	} else if (carry->len > 0) {
		take_line (carry->str, carry->len, func, data, stats);
	}

	g_string_free (carry, TRUE);
	g_free (chunk);
	fclose (f);
}

/* [ count_back ]
 * Counts event lines back from the end of path until `need' are found,
 * reading only those bytes.  Returns the offset of the first one
 * counted (0 when the whole file was needed) and sets *found. */
static gint64
count_back (const gchar *path, guint need, guint *found)
{
	FILE *f = g_fopen (path, "rb");
	gchar *buf;
	gint64 pos, line_end;
	gint next = -1;          /* the byte after the one being looked at */
	gint64 result = 0;
	gboolean whole = TRUE;

	*found = 0;
	if (f == NULL || need == 0) {
		if (f != NULL)
			fclose (f);
		return 0;
	}
	if (seek64 (f, 0, SEEK_END) != 0 || (pos = tell64 (f)) < 0) {
		fclose (f);
		return 0;
	}

	buf = g_malloc (READ_CHUNK);
	line_end = pos;
	while (pos > 0 && whole) {
		gsize len = (gsize) MIN ((gint64) READ_CHUNK, pos);

		pos -= (gint64) len;
		if (seek64 (f, pos, SEEK_SET) != 0 ||
		    fread (buf, 1, len, f) != len) {
			whole = FALSE;
			break;
		}

		for (gsize i = len; i-- > 0;) {
			gint64 at = pos + (gint64) i;

			if (buf[i] == '\n') {
				/* The line after it: [at + 1, line_end). */
				if (line_end > at + 1 && next != '#' &&
				    ++*found == need) {
					result = at + 1;
					whole = FALSE;
					break;
				}
				line_end = at;
			}
			next = (guchar) buf[i];
		}
	}

	/* The file's first line. */
	if (whole && line_end > 0 && next != '#')
		++*found;

	g_free (buf);
	fclose (f);
	return result;
}

typedef struct
{
	FsEventStore    *store;
	FsEventLogStats *stats;
	guint            loaded;
} LoadCtx;

static void
load_one (const FsHit *hit, gint64 ticks, gpointer data)
{
	LoadCtx *ctx = data;

	if (fs_eventstore_append (ctx->store, hit, ticks / 10) != 0)
		ctx->loaded++;
}

guint
fs_eventlog_load_recent (const gchar *dir, FsEventStore *store,
                         guint max_events, FsEventLogStats *stats)
{
	GPtrArray *list;
	guint need = max_events;
	gint start = -1;
	gint64 start_at = 0;
	LoadCtx ctx = { store, stats, 0 };

	if (stats != NULL)
		memset (stats, 0, sizeof *stats);
	if (dir == NULL || store == NULL || max_events == 0)
		return 0;

	list = list_logs (dir);

	/* Newest first, counting back from each file's end, until the
	 * files hold enough: only the bytes to be loaded are read. */
	for (gint i = (gint) list->len - 1; i >= 0 && need > 0; i--) {
		gchar *path = g_build_filename (dir, LOG_AT (list, i)->name,
		                                NULL);
		guint found = 0;

		start_at = count_back (path, need, &found);
		start = i;
		need -= MIN (found, need);
		g_free (path);
	}

	/* Then oldest first, into the store. */
	for (guint i = start >= 0 ? (guint) start : list->len;
	     i < list->len; i++) {
		gchar *path = g_build_filename (dir, LOG_AT (list, i)->name,
		                                NULL);

		read_file (path, (gint) i == start ? start_at : 0, load_one,
		           &ctx, stats);
		g_free (path);
	}

	g_ptr_array_unref (list);
	if (stats != NULL)
		stats->loaded = ctx.loaded;

	return ctx.loaded;
}

typedef struct
{
	gint64          since_ticks;
	gint64          until_ticks;
	FsEventLogFunc  func;
	gpointer        data;
} ForeachCtx;

static void
foreach_one (const FsHit *hit, gint64 ticks, gpointer data)
{
	ForeachCtx *ctx = data;

	if (ctx->since_ticks != 0 && ticks < ctx->since_ticks)
		return;
	if (ctx->until_ticks != 0 && ticks >= ctx->until_ticks)
		return;

	ctx->func (hit, ticks, ctx->data);
}

void
fs_eventlog_foreach (const gchar *dir, gint64 since_us, gint64 until_us,
                     FsEventLogFunc func, gpointer user_data,
                     FsEventLogStats *stats)
{
	GPtrArray *list;
	ForeachCtx ctx = { since_us * 10, until_us * 10, func, user_data };
	gint64 since_day = since_us > 0 ? (since_us * 10) / TICKS_PER_DAY : 0;

	if (stats != NULL)
		memset (stats, 0, sizeof *stats);
	if (dir == NULL || func == NULL)
		return;

	list = list_logs (dir);
	for (guint i = 0; i < list->len; i++) {
		LogFile *f = LOG_AT (list, i);
		gchar *path;

		/* A file holds events of its day or earlier, so a day
		 * before the start has nothing in range.  (A stamp that was
		 * in the future when it arrived is filed under the day it
		 * arrived, and a range starting after that day misses it;
		 * the stamp is wrong anyway.) */
		if (since_us > 0 && f->day < since_day)
			continue;

		path = g_build_filename (dir, f->name, NULL);
		read_file (path, 0, foreach_one, &ctx, stats);
		g_free (path);
	}

	g_ptr_array_unref (list);
}
