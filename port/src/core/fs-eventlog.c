/*---[ fs-eventlog.c ]---------------------------------------------------
 * Event history on disk.  See fs-eventlog.h.
 *--------------------------------------------------------------------*/

#include "core/fs-eventlog.h"

#include <glib/gstdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef G_OS_WIN32
#include <io.h>
#else
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
	guint    cur_part;
	gchar   *cur_name;
	guint64  cur_size;
	guint64  total_bytes;   /* every history file, about          */

	GString *buf;
	gchar   *problem;
};

/* ------------------------------------------------------------ names */

/* "events-YYYY-MM-DD-NNN.log" */
static gboolean
is_log_name (const gchar *name)
{
	if (strlen (name) != 25 || !g_str_has_prefix (name, "events-") ||
	    !g_str_has_suffix (name, ".log"))
		return FALSE;

	for (guint i = 7; i < 21; i++) {
		gboolean dash = (i == 11 || i == 14 || i == 17);

		if (dash ? name[i] != '-' : !g_ascii_isdigit (name[i]))
			return FALSE;
	}

	return TRUE;
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

static gint
cmp_names (gconstpointer a, gconstpointer b)
{
	return strcmp (*(const gchar * const *) a, *(const gchar * const *) b);
}

/* The history files in dir, oldest first. */
static GPtrArray *
list_logs (const gchar *dir)
{
	GPtrArray *names = g_ptr_array_new_with_free_func (g_free);
	GDir *d = g_dir_open (dir, 0, NULL);
	const gchar *name;

	if (d == NULL)
		return names;

	while ((name = g_dir_read_name (d)) != NULL)
		if (is_log_name (name))
			g_ptr_array_add (names, g_strdup (name));

	g_dir_close (d);
	g_ptr_array_sort (names, cmp_names);

	return names;
}

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

static guint64
part_max (const FsEventLog *log)
{
	return MAX (log->max_bytes / 20, (guint64) 16384);
}

static void
set_problem (FsEventLog *log, const gchar *what, int err)
{
	g_free (log->problem);
	log->problem = g_strdup_printf ("%s: %s", what, g_strerror (err));
	g_string_truncate (log->buf, 0);
	if (log->fd >= 0) {
		close (log->fd);
		log->fd = -1;
	}
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
	GPtrArray *names = list_logs (dir);
	guint64 total = 0;

	for (guint i = 0; i < names->len; i++) {
		gchar *path = g_build_filename (dir, names->pdata[i], NULL);

		total += file_size (path);
		g_free (path);
	}

	if (bytes != NULL)
		*bytes = total;
	if (files != NULL)
		*files = names->len;
	g_ptr_array_unref (names);
}

guint
fs_eventlog_prune_dir (const gchar *dir, guint max_days, guint64 max_bytes,
                       gint64 now_us, const gchar *keep)
{
	GPtrArray *names = list_logs (dir);
	gint64 today = (now_us * 10) / TICKS_PER_DAY;
	guint64 *sizes = g_new0 (guint64, names->len + 1);
	gboolean *gone = g_new0 (gboolean, names->len + 1);
	guint64 total = 0;
	guint removed = 0;

	for (guint i = 0; i < names->len; i++) {
		gchar *path = g_build_filename (dir, names->pdata[i], NULL);

		sizes[i] = file_size (path);
		total += sizes[i];

		if (max_days > 0 &&
		    name_day (names->pdata[i]) < today - (gint64) max_days &&
		    g_strcmp0 (names->pdata[i], keep) != 0 &&
		    g_remove (path) == 0) {
			gone[i] = TRUE;
			total -= sizes[i];
			removed++;
		}
		g_free (path);
	}

	for (guint i = 0; i < names->len && max_bytes > 0 &&
	                  total > max_bytes; i++) {
		gchar *path;

		if (gone[i] || g_strcmp0 (names->pdata[i], keep) == 0)
			continue;

		path = g_build_filename (dir, names->pdata[i], NULL);
		if (g_remove (path) == 0) {
			total -= sizes[i];
			removed++;
		}
		g_free (path);
	}

	g_free (sizes);
	g_free (gone);
	g_ptr_array_unref (names);

	return removed;
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

/* [ open_current ]
 * The file for cur_day: the last part that still has room, or a new
 * one.  A file whose last line was cut short gets a newline first, so
 * the next line starts clean (the cut one fails its checksum). */
static gboolean
open_current (FsEventLog *log)
{
	gchar *path = NULL;
	gint fd;
	GStatBuf st;

	if (log->fd >= 0)
		return TRUE;

	for (;; log->cur_part++) {
		g_free (log->cur_name);
		log->cur_name = g_strdup_printf ("events-%s-%03u.log",
		                                 log->cur_day, log->cur_part);
		g_free (path);
		path = g_build_filename (log->dir, log->cur_name, NULL);

		if (log->cur_part >= 999 || file_size (path) < part_max (log))
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
		set_problem (log, path, errno);
		close (fd);
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

	if (log->problem != NULL) {
		g_set_error_literal (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
		                     log->problem);
		return FALSE;
	}

	if (log->buf->len == 0)
		return TRUE;

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

	/* A full part: the next flush starts the next one. */
	if (log->cur_size >= part_max (log)) {
		close_current (log);
		log->cur_part++;
	}

	if (log->total_bytes > log->max_bytes) {
		fs_eventlog_prune_dir (log->dir, log->max_days, log->max_bytes,
		                       g_get_real_time (), log->cur_name);
		fs_eventlog_usage (log->dir, &log->total_bytes, NULL);
	}

	return TRUE;
}

gboolean
fs_eventlog_append (FsEventLog *log, const FsHit *hit, gint64 ticks)
{
	gchar day[16];

	if (log == NULL || hit == NULL)
		return FALSE;
	if (log->problem != NULL)
		return FALSE;

	/* The file is the event's day, but never an earlier one than the
	 * file being written: a late, older event joins today's file. */
	fs_event_time_day (ticks, day);
	if (strcmp (day, log->cur_day) > 0) {
		if (log->cur_day[0] != '\0' && !fs_eventlog_flush (log, NULL))
			return FALSE;
		close_current (log);
		g_strlcpy (log->cur_day, day, sizeof log->cur_day);
		log->cur_part = 0;
		fs_eventlog_prune_dir (log->dir, log->max_days, log->max_bytes,
		                       g_get_real_time (), NULL);
		fs_eventlog_usage (log->dir, &log->total_bytes, NULL);
	}

	fs_eventlog_format_line (log->buf, hit, ticks);

	if (log->buf->len >= FLUSH_AT ||
	    log->cur_size + log->buf->len >= part_max (log))
		return fs_eventlog_flush (log, NULL);

	return TRUE;
}

const gchar *
fs_eventlog_problem (const FsEventLog *log)
{
	return log != NULL ? log->problem : NULL;
}

void
fs_eventlog_close (FsEventLog *log)
{
	if (log == NULL)
		return;

	fs_eventlog_flush (log, NULL);
	close_current (log);
	g_string_free (log->buf, TRUE);
	g_free (log->problem);
	g_free (log->dir);
	g_free (log);
}

guint
fs_eventlog_clear_dir (const gchar *dir, GError **error)
{
	GPtrArray *names = list_logs (dir);
	guint removed = 0;

	for (guint i = 0; i < names->len; i++) {
		gchar *path = g_build_filename (dir, names->pdata[i], NULL);

		if (g_remove (path) == 0)
			removed++;
		else if (error != NULL && *error == NULL)
			g_set_error (error, G_FILE_ERROR,
			             g_file_error_from_errno (errno),
			             "cannot delete %s: %s", path,
			             g_strerror (errno));
		g_free (path);
	}

	g_ptr_array_unref (names);
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
	log->cur_day[0] = '\0';
	g_clear_pointer (&log->problem, g_free);

	removed = fs_eventlog_clear_dir (log->dir, error);
	fs_eventlog_usage (log->dir, &log->total_bytes, NULL);

	return removed;
}

/* ----------------------------------------------------------- reading */

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

typedef void (*LineFunc) (const FsHit *hit, gint64 ticks, gpointer data);

/* Every event line of one file, skipping the first `skip' candidates. */
static void
read_file (const gchar *path, guint skip, LineFunc func, gpointer data,
           FsEventLogStats *stats)
{
	gchar *text = NULL;
	gsize len = 0;
	gchar *p, *end;
	guint seen = 0;

	if (!g_file_get_contents (path, &text, &len, NULL))
		return;

	if (stats != NULL) {
		stats->files++;
		stats->bytes += len;
	}

	p = text;
	end = text + len;
	while (p < end) {
		gchar *nl = memchr (p, '\n', (gsize) (end - p));
		gchar *stop = nl != NULL ? nl : end;
		FsHit hit;
		gint64 ticks;

		if (stop > p && *p != '#') {
			if (seen++ >= skip) {
				*stop = '\0';
				if (fs_eventlog_parse_line (p, &hit, &ticks)) {
					if (stats != NULL)
						stats->lines++;
					func (&hit, ticks, data);
				} else if (stats != NULL) {
					stats->bad_lines++;
				}
			}
		}
		p = stop + 1;
	}

	g_free (text);
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
	GPtrArray *names;
	guint need = max_events;
	gint start = -1;
	guint skip = 0;
	LoadCtx ctx = { store, stats, 0 };

	if (stats != NULL)
		memset (stats, 0, sizeof *stats);
	if (dir == NULL || store == NULL || max_events == 0)
		return 0;

	names = list_logs (dir);

	/* Newest first, counting, until the files hold enough. */
	for (gint i = (gint) names->len - 1; i >= 0 && need > 0; i--) {
		gchar *path = g_build_filename (dir, names->pdata[i], NULL);
		gchar *text = NULL;
		gsize len = 0;

		if (g_file_get_contents (path, &text, &len, NULL)) {
			guint n = count_lines (text, len);

			start = i;
			if (n >= need) {
				skip = n - need;
				need = 0;
			} else {
				skip = 0;
				need -= n;
			}
		}
		g_free (text);
		g_free (path);
	}

	/* Then oldest first, into the store. */
	for (guint i = start >= 0 ? (guint) start : names->len;
	     i < names->len; i++) {
		gchar *path = g_build_filename (dir, names->pdata[i], NULL);

		read_file (path, (gint) i == start ? skip : 0, load_one, &ctx,
		           stats);
		g_free (path);
	}

	g_ptr_array_unref (names);
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
	GPtrArray *names;
	ForeachCtx ctx = { since_us * 10, until_us * 10, func, user_data };
	gint64 since_day = since_us > 0 ? (since_us * 10) / TICKS_PER_DAY : 0;

	if (stats != NULL)
		memset (stats, 0, sizeof *stats);
	if (dir == NULL || func == NULL)
		return;

	names = list_logs (dir);
	for (guint i = 0; i < names->len; i++) {
		gchar *path;

		/* A file holds events of its day or earlier, never later,
		 * so a day before the start has nothing in range. */
		if (since_us > 0 && name_day (names->pdata[i]) < since_day)
			continue;

		path = g_build_filename (dir, names->pdata[i], NULL);
		read_file (path, 0, foreach_one, &ctx, stats);
		g_free (path);
	}

	g_ptr_array_unref (names);
}
