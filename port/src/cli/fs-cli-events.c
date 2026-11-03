/*---[ fs-cli-events.c ]----------------------------------------------------
 * `stockfw events', `connections', `listening' and `interfaces'
 * (cli-plan.md WP-D).
 *
 * events reads the kernel log (or the history the desktop app saves),
 * filters it with the same query the Events page runs, and prints a
 * table, CSV, JSON, a summary, or a live stream whose rows line up
 * with the table's header.  connections and listening read the
 * /proc/net socket tables through the core parsers; listening asks the
 * What-If engine whether each open port is reachable.  interfaces
 * prints the adapters' traffic once or every few seconds.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "core/fs-activity.h"
#include "core/fs-apply.h"
#include "core/fs-eventfilter.h"
#include "core/fs-eventlog.h"
#include "core/fs-eventstore.h"
#include "core/fs-health.h"
#include "core/fs-hostnet.h"
#include "core/fs-json.h"
#include "core/fs-netparse.h"
#include "core/fs-prefs.h"
#include "core/fs-util.h"

#include <gio/gio.h>
#include <glib-unix.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

/* ------------------------------------------------------- shared helpers */

/* [ parse_dir ] -- in, out, both; inbound and outbound as aliases. */
static gboolean
parse_dir (const gchar *opt, const gchar *v, FsEventDirFilter *dir,
           gboolean allow_both)
{
	if (g_ascii_strcasecmp (v, "in") == 0 ||
	    g_ascii_strcasecmp (v, "inbound") == 0)
		*dir = FS_EVQ_DIR_IN;
	else if (g_ascii_strcasecmp (v, "out") == 0 ||
	         g_ascii_strcasecmp (v, "outbound") == 0)
		*dir = FS_EVQ_DIR_OUT;
	else if (allow_both && g_ascii_strcasecmp (v, "both") == 0)
		*dir = FS_EVQ_DIR_ANY;
	else {
		fs_cli_error ("%s wants in, out%s, not `%s'", opt,
		              allow_both ? " or both" : "", v);
		return FALSE;
	}
	return TRUE;
}

/* [ parse_count ] -- a whole number up to `max'. */
static gboolean
parse_count (const gchar *opt, const gchar *v, guint64 max, guint *out)
{
	gchar *end = NULL;
	guint64 n;

	n = g_ascii_strtoull (v, &end, 10);
	if (!g_ascii_isdigit (*v) || end == NULL || *end != '\0' || n > max) {
		fs_cli_error ("%s wants a number up to %" G_GUINT64_FORMAT, opt, max);
		return FALSE;
	}
	*out = (guint) n;
	return TRUE;
}

typedef struct
{
	guint lo;
	guint hi;
} PortRange;

/* [ parse_port_list ]
 * "22,443,8000:8100" or "1000-2000": ranges appended to `ranges'
 * (PortRange).  An error is printed for a list that cannot be read. */
static gboolean
parse_port_list (const gchar *opt, const gchar *text, GArray *ranges)
{
	gchar **items = g_strsplit (text, ",", -1);
	gboolean ok = items[0] != NULL;

	for (gint i = 0; ok && items[i] != NULL; i++) {
		gchar *item = g_strstrip (items[i]);
		gchar *sep = strpbrk (item, "-:");
		gchar *end = NULL;
		guint64 lo, hi;
		PortRange r;

		lo = g_ascii_strtoull (item, &end, 10);
		if (!g_ascii_isdigit (*item) || end != (sep != NULL ? sep : item + strlen (item)))
			ok = FALSE;
		hi = lo;
		if (ok && sep != NULL) {
			hi = g_ascii_strtoull (sep + 1, &end, 10);
			if (!g_ascii_isdigit (sep[1]) || *end != '\0')
				ok = FALSE;
		}
		if (ok && (lo < 1 || hi > 65535 || lo > hi))
			ok = FALSE;
		if (ok) {
			r.lo = (guint) lo;
			r.hi = (guint) hi;
			g_array_append_val (ranges, r);
		}
	}
	if (!ok)
		fs_cli_error ("%s wants ports from 1 to 65535: 22, 1000-2000, "
		              "1000:2000, or a list such as 22,443,8000:8100; "
		              "not `%s'", opt, text);
	g_strfreev (items);
	return ok;
}

static gboolean
port_in (const GArray *ranges, guint port)
{
	for (guint i = 0; i < ranges->len; i++) {
		const PortRange *r = &g_array_index (ranges, PortRange, i);

		if (port >= r->lo && port <= r->hi)
			return TRUE;
	}
	return FALSE;
}

/* [ address_short ] -- IPv6 in its short form; "-" for none. */
static gchar *
address_short (const gchar *text)
{
	GInetAddress *a;
	gchar *out;

	if (text == NULL || *text == '\0')
		return g_strdup ("-");
	if (strchr (text, ':') == NULL)
		return g_strdup (text);
	a = g_inet_address_new_from_string (text);
	if (a == NULL)
		return g_strdup (text);
	out = g_inet_address_to_string (a);
	g_object_unref (a);
	return out;
}

/* [ is_loopback_text ] -- 127.0.0.0/8 or ::1 */
static gboolean
is_loopback_text (const gchar *addr)
{
	GInetAddress *a;
	gboolean yes;

	if (addr == NULL)
		return FALSE;
	a = g_inet_address_new_from_string (addr);
	if (a == NULL)
		return FALSE;
	yes = g_inet_address_get_is_loopback (a);
	g_object_unref (a);
	return yes;
}

/* "1,284" */
static gchar *
count_text (guint64 n)
{
	gchar *digits = g_strdup_printf ("%" G_GUINT64_FORMAT, n);
	GString *out = g_string_new (NULL);
	gsize len = strlen (digits);

	for (gsize i = 0; i < len; i++) {
		if (i > 0 && (len - i) % 3 == 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, digits[i]);
	}
	g_free (digits);
	return g_string_free (out, FALSE);
}

/* "12 s", "5 min", "2 h 10 min" */
static gchar *
duration_text (gint64 seconds)
{
	if (seconds < 60)
		return g_strdup_printf ("%d s", (gint) MAX (seconds, 0));
	if (seconds < 3600)
		return g_strdup_printf ("%d min", (gint) (seconds / 60));
	if (seconds % 3600 < 60)
		return g_strdup_printf ("%d h", (gint) (seconds / 3600));
	return g_strdup_printf ("%d h %d min", (gint) (seconds / 3600),
	                        (gint) (seconds % 3600 / 60));
}

/* A short time for a summary cell: "11-03 10:42" local, or ISO with
 * --utc. */
static gchar *
short_stamp (gint64 epoch)
{
	GDateTime *t, *local;
	gchar *text;

	if (epoch < 0)
		return g_strdup ("-");
	if (fs_cli.utc)
		return fs_cli_time_text (epoch, FS_CLI_TIME_ISO);
	t = g_date_time_new_from_unix_utc (epoch);
	local = g_date_time_to_local (t);
	text = g_date_time_format (local, "%m-%d %H:%M");
	g_date_time_unref (local);
	g_date_time_unref (t);
	return text;
}

/* "2026-11-03 10:42" local, or ISO with --utc. */
static gchar *
window_stamp (gint64 epoch)
{
	GDateTime *t, *local;
	gchar *text;

	if (fs_cli.utc)
		return fs_cli_time_text (epoch, FS_CLI_TIME_ISO);
	t = g_date_time_new_from_unix_utc (epoch);
	local = g_date_time_to_local (t);
	text = g_date_time_format (local, "%Y-%m-%d %H:%M");
	g_date_time_unref (local);
	g_date_time_unref (t);
	return text;
}

/* -------------------------------------------------------------- events */

static const gchar *const event_headers[] = {
	"TIME", "VERDICT", "DIR", "SOURCE", "DESTINATION",
	"PORT", "SERVICE", "PROTO", "RULE"
};
static const gchar *const event_wide_headers[] = {
	"TIME", "VERDICT", "DIR", "IN", "OUT", "SOURCE", "DESTINATION",
	"PORT", "SERVICE", "PROTO", "LEN", "TOS", "RULE"
};
#define EVENT_COLS      G_N_ELEMENTS (event_headers)
#define EVENT_WIDE_COLS G_N_ELEMENTS (event_wide_headers)

/* The CSV columns, as the desktop app's export writes them. */
static const gchar csv_header[] =
	"time,direction,in,out,port,source,destination,length,tos,"
	"protocol,service,action,rule";

/* [ Display ]
 * The two filters of Preferences > Events (C18, J5, J6), run the way
 * the Events page runs them: on the stream as it comes, before the
 * list's own filters and before anything is counted.  A repeat is the
 * same port, protocol, source and destination as the last event let
 * through; "not for this computer" is an inbound event to an address
 * that is none of this machine's (broadcast, multicast, a neighbour's).
 * `--collapse-repeats' and `--for-me' turn them on, `--prefs-filters'
 * takes them from the preferences, as the desktop app does. */
typedef struct
{
	FsHitFilter *filter;     /* NULL: neither filter is on              */
	gboolean     repeats;
	gboolean     not_for_me;
	guint64      seen;
	guint64      repeats_hidden;
	guint64      not_for_me_hidden;
} Display;

/* [ display_keep ] -- TRUE when the event goes on to the list. */
static gboolean
display_keep (Display *d, const FsHit *hit)
{
	if (d == NULL)
		return TRUE;
	d->seen++;
	if (d->filter == NULL)
		return TRUE;
	if (d->repeats && fs_hit_filter_is_redundant (d->filter, hit)) {
		d->repeats_hidden++;
		return FALSE;
	}
	if (d->not_for_me && !fs_hit_filter_keep (d->filter, hit, FALSE, TRUE)) {
		d->not_for_me_hidden++;
		return FALSE;
	}
	fs_hit_filter_remember (d->filter, hit);
	return TRUE;
}

typedef struct
{
	GPtrArray  *queries;     /* FsEventQuery*, any may match; NULL: all */
	Display    *display;
	gboolean    wide;
	gboolean    csv;
	guint      *widths;      /* -f: the frozen column widths          */
	/* -f */
	guint       printed;
	guint       blocked;
	gint64      started_us;
	const gchar *log_file;   /* $STOCKFW_LOG_FILE being followed      */
	GMainLoop  *loop;
	gboolean    interrupted;
	gint        rc;
	/* -f: the live status line on stderr (15.2.5) */
	gboolean    status_on;
	gboolean    status_drawn;
	FsCliStatusSnapshot *snap;
	gint64      snap_us;      /* when snap was read (monotonic)       */
	gint64      blocked_base; /* blocked today when following began   */
	guint64     blocked_live; /* blocked events seen since then       */
	gint        day;          /* the local day blocked_base counts    */
} EventsState;

/* [ hit_time_us ] -- the hit's own time, 0 when it cannot be read. */
static gint64
hit_time_us (const FsHit *hit)
{
	gint64 ticks = 0;

	if (fs_event_time_parse (hit->time, &ticks) == FS_EVENT_TIME_OTHER)
		return 0;
	return ticks / 10;
}

/* [ queries_match ]
 * The filters of `stockfw events', the query the Events page runs;
 * --port with a list runs one query per range and keeps an event any
 * of them lets through.  A kernel-log stamp that cannot be read has no
 * time, so it fails a --since or --until. */
static gboolean
queries_match (const GPtrArray *queries, const FsHit *hit, gint64 time_us)
{
	if (queries == NULL)
		return TRUE;
	for (guint i = 0; i < queries->len; i++)
		if (fs_eventquery_match_hit (g_ptr_array_index (queries, i), hit,
		                             time_us))
			return TRUE;
	return FALSE;
}

/* [ event_row ] -- the table cells: 9, or 13 with --wide. */
static gchar **
event_row (const FsHit *hit, gboolean wide)
{
	gchar **base = fs_cli_hit_row (hit);
	gchar **row;
	gint64 epoch;

	if (!wide)
		return base;

	row = g_new0 (gchar *, EVENT_WIDE_COLS + 1);
	epoch = fs_cli_hit_epoch (hit);
	row[0] = epoch >= 0 ? fs_cli_time_text (epoch, FS_CLI_TIME_FULL)
	                    : g_strdup (base[0]);
	row[1] = g_strdup (base[1]);
	row[2] = g_strdup (base[2]);
	row[3] = fs_cli_out_safe (hit->in != NULL && *hit->in ? hit->in : "-");
	row[4] = fs_cli_out_safe (hit->out != NULL && *hit->out ? hit->out : "-");
	row[5] = g_strdup (base[3]);
	row[6] = g_strdup (base[4]);
	row[7] = g_strdup (base[5]);
	row[8] = g_strdup (base[6]);
	row[9] = g_strdup (base[7]);
	row[10] = fs_cli_out_safe (hit->length != NULL && *hit->length
	                           ? hit->length : "-");
	row[11] = fs_cli_out_safe (hit->tos != NULL && *hit->tos ? hit->tos : "-");
	row[12] = g_strdup (base[8]);
	g_strfreev (base);
	return row;
}

/* [ csv_line ] -- one event as the export writes it: the service name
 * without the marker, the verdict as its own column, and the rule the
 * event names (never the log marker).  The core's writer adds the
 * formula guard; the row then goes through fs_cli_out_safe, as every
 * other event row does, so a log field or a list name holding ESC, a
 * C1 control or a bidi control cannot steer the terminal (or the one
 * that later shows the file).  A line break in a field is escaped too,
 * so a row stays one line. */
static void
csv_line (const FsHit *hit)
{
	GString *out = g_string_new (NULL);
	FsHit view = *hit;
	gchar *service = fs_hit_service_name (hit);
	gchar *rule = fs_cli_hit_rule_name (hit);
	gchar *safe;

	view.service = service;
	view.rule = rule;
	fs_event_csv_row (out, &view, fs_hit_is_blocked (hit));
	safe = fs_cli_out_safe (out->str);
	printf ("%s\n", safe);
	g_free (safe);
	g_string_free (out, TRUE);
	g_free (service);
	g_free (rule);
}

/* [ status_line_hook ]
 * The live event line (master plan PR 1, adjustment 2).  When stdout
 * and stderr are both terminals, a status line sits under the rows on
 * stderr: before a row it is cleared (\r\033[K), after the row it is
 * drawn again, and on the 2 s tick it is redrawn, with the facts read
 * again (fs_cli_status_snapshot) every 5 s.  It shows the firewall
 * state, live or pending, HELD (audit-only), blocked today, Sentinel
 * and where the events come from.  Blocked today is the count when
 * following began plus every blocked event seen since, so no line is
 * counted twice.  Every text from outside goes through
 * fs_cli_out_safe, and the line is cut to the terminal's width so it
 * never wraps (a wrapped line cannot be cleared with \r). */
typedef enum
{
	STATUS_BEFORE_ROW,
	STATUS_AFTER_ROW,
	STATUS_TICK,
	STATUS_STOP
} StatusMoment;

#define STATUS_REFRESH_US (5 * G_USEC_PER_SEC)

/* [ status_line_wanted ]
 * Never with --json or --csv, with -q, with --no-status-line, when
 * stdout or stderr is not a terminal, or with TERM=dumb. */
static gboolean
status_line_wanted (gboolean csv, gboolean off)
{
	const gchar *term = g_getenv ("TERM");

	if (off || fs_cli.json || csv || fs_cli.quiet)
		return FALSE;
	if (!isatty (STDOUT_FILENO) || !isatty (STDERR_FILENO))
		return FALSE;
	return term == NULL || g_ascii_strcasecmp (term, "dumb") != 0;
}

static gint
local_day (void)
{
	GDateTime *now = g_date_time_new_now_local ();
	gint day = g_date_time_get_year (now) * 1000 +
	           g_date_time_get_day_of_year (now);

	g_date_time_unref (now);
	return day;
}

static void
status_snapshot_read (EventsState *st)
{
	fs_cli_status_snapshot_free (st->snap);
	st->snap = fs_cli_status_snapshot ();
	st->snap_us = g_get_monotonic_time ();
}

/* [ status_line_start ] -- the first snapshot, when following begins. */
static void
status_line_start (EventsState *st)
{
	if (!st->status_on)
		return;
	status_snapshot_read (st);
	st->blocked_base = st->snap->blocked_today;
	st->blocked_live = 0;
	st->day = local_day ();
}

static const gchar *
status_state_word (FsFirewallState state)
{
	switch (state) {
	case FS_FW_RUNNING: return "running";
	case FS_FW_STOPPED: return "stopped";
	case FS_FW_LOCKED:  return "locked";
	default:            return "state unknown";
	}
}

/* [ status_line_text ] -- the line, before it is cut to the width. */
static gchar *
status_line_text (const EventsState *st)
{
	const FsCliStatusSnapshot *snap = st->snap;
	GString *line = g_string_new (NULL);
	gchar *sep = g_strdup_printf (" %s ", fs_cli_sym (FS_CLI_SYM_SEP));
	gchar *text;

	g_string_append (line, status_state_word (snap->state));
	if (snap->state != FS_FW_STOPPED) {
		const gchar *live;

		switch (snap->live) {
		case FS_CLI_LIVE_SAME:       live = "live";            break;
		case FS_CLI_LIVE_PENDING:    live = "changes pending"; break;
		case FS_CLI_LIVE_NO_JOURNAL: live = "never applied";   break;
		case FS_CLI_LIVE_STOPPED:    live = "stopped";         break;
		default:                     live = "live: unknown";   break;
		}
		g_string_append_printf (line, "%s%s", sep, live);
	}
	if (snap->settings_pending)
		g_string_append_printf (line, "%ssettings pending", sep);
	if (snap->held)
		g_string_append_printf (line, "%sHELD (audit-only)", sep);

	if (st->blocked_base >= 0)
		g_string_append_printf (line, "%sblocked today %" G_GUINT64_FORMAT,
		                        sep, (guint64) st->blocked_base +
		                        st->blocked_live);
	else
		g_string_append_printf (line, "%sblocked today unknown, %"
		                        G_GUINT64_FORMAT " since start", sep,
		                        st->blocked_live);

	text = fs_cli_out_safe (snap->sentinel_mode);
	g_string_append_printf (line, "%sSentinel %s", sep, text);
	g_free (text);
	if (snap->sentinel_staged > 0)
		g_string_append_printf (line, ", %d staged", snap->sentinel_staged);

	if (snap->monitor_readable) {
		text = fs_cli_out_safe (snap->monitor_source != NULL
		                        ? snap->monitor_source : "the kernel log");
		g_string_append_printf (line, "%sfrom %s", sep, text);
	} else {
		text = fs_cli_out_safe (snap->monitor_problem != NULL
		                        ? snap->monitor_problem
		                        : "the kernel log cannot be read");
		g_string_append_printf (line, "%slog: %s", sep, text);
	}
	g_free (text);

	g_free (sep);
	return g_string_free (line, FALSE);
}

/* [ status_line_fit ]
 * At most width - 1 columns (writing the last column makes some
 * terminals wrap), with an ellipsis when cut.  A wide character
 * counts two. */
static gchar *
status_line_fit (const gchar *text, guint width)
{
	const gchar *ell = fs_cli_sym (FS_CLI_SYM_ELLIPSIS);
	guint ell_w = (guint) g_utf8_strlen (ell, -1);
	guint used = 0, room = (width < 2 ? 2 : width) - 1;
	guint keep = room > ell_w ? room - ell_w : 0;
	const gchar *p, *cut = NULL;

	for (p = text; *p != '\0'; p = g_utf8_next_char (p)) {
		guint w = g_unichar_iswide (g_utf8_get_char (p)) ? 2 : 1;

		if (cut == NULL && used + w > keep)
			cut = p;
		if (used + w > room) {
			GString *out = g_string_new_len (text, cut - text);

			g_string_append (out, ell);
			return g_string_free (out, FALSE);
		}
		used += w;
	}
	return g_strdup (text);
}

/* [ status_day_roll ] -- after midnight the count starts again.  Run
 * before a blocked event is counted as well as before a draw, so the
 * first event of a new day is counted in the new day, not wiped with
 * the old one. */
static void
status_day_roll (EventsState *st)
{
	gint day = local_day ();

	if (day != st->day) {
		st->day = day;
		st->blocked_base = 0;
		st->blocked_live = 0;
	}
}

static void
status_line_draw (EventsState *st)
{
	guint width = fs_cli_term_width ();
	gchar *text, *fit;

	status_day_roll (st);
	text = status_line_text (st);
	/* ws_col 0 and no $COLUMNS: 80 rather than a line that wraps. */
	fit = status_line_fit (text, width > 0 ? width : 80);
	fprintf (stderr, "\r\033[K%s%s%s", fs_cli_dim (), fit, fs_cli_reset ());
	fflush (stderr);
	st->status_drawn = TRUE;
	g_free (fit);
	g_free (text);
}

static void
status_line_clear (EventsState *st)
{
	if (!st->status_drawn)
		return;
	fputs ("\r\033[K", stderr);
	fflush (stderr);
	st->status_drawn = FALSE;
}

static void
status_line_hook (EventsState *st, StatusMoment moment)
{
	if (!st->status_on || st->snap == NULL)
		return;

	switch (moment) {
	case STATUS_BEFORE_ROW:
		status_line_clear (st);
		break;
	case STATUS_TICK:
		if (g_get_monotonic_time () - st->snap_us >= STATUS_REFRESH_US)
			status_snapshot_read (st);
		status_line_draw (st);
		break;
	case STATUS_AFTER_ROW:
		status_line_draw (st);
		break;
	case STATUS_STOP:
		status_line_clear (st);
		fs_cli_status_snapshot_free (st->snap);
		st->snap = NULL;
		break;
	}
}

/* [ print_live_hit ] -- one followed event, in the table's columns. */
static void
print_live_hit (const FsHit *hit, EventsState *st)
{
	if (!queries_match (st->queries, hit, hit_time_us (hit)))
		return;

	status_line_hook (st, STATUS_BEFORE_ROW);
	if (fs_cli.json) {
		GString *out = g_string_new (NULL);

		fs_cli_hit_row_json (out, hit);
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (st->csv) {
		csv_line (hit);
	} else {
		guint n = st->wide ? EVENT_WIDE_COLS : EVENT_COLS;
		gchar **row = event_row (hit, st->wide);
		const gchar *colours[EVENT_WIDE_COLS] = { NULL };

		colours[0] = fs_cli_dim ();
		colours[1] = fs_hit_is_blocked (hit) ? fs_cli_red ()
		                                     : fs_cli_green ();
		fs_cli_table_row (row, n, st->widths, colours);
		g_strfreev (row);
	}
	fflush (stdout);

	st->printed++;
	if (fs_hit_is_blocked (hit))
		st->blocked++;
	status_line_hook (st, STATUS_AFTER_ROW);
}

static void
on_live_hit (const FsHit *hit, gpointer data)
{
	EventsState *st = data;

	/* Blocked today counts every blocked event, whatever the filters
	 * let through. */
	if (st->status_on && fs_hit_is_blocked (hit)) {
		status_day_roll (st);
		st->blocked_live++;
	}
	if (!display_keep (st->display, hit))
		return;
	print_live_hit (hit, data);
}

static gboolean
on_follow_signal (gpointer data)
{
	EventsState *st = data;

	st->interrupted = TRUE;
	g_main_loop_quit (st->loop);
	return G_SOURCE_REMOVE;
}

/* [ on_reader_check ]
 * Every 2 s: is the event reader still running?  The backend says so
 * for its own reader (a tail or journalctl child that exited, a
 * kernel ring buffer read that failed).  `tail -F' on a file named by
 * STOCKFW_LOG_FILE keeps waiting for a file that is gone or can no
 * longer be read, so for that source the file is opened here too. */
static gboolean
on_reader_check (gpointer data)
{
	EventsState *st = data;
	const FsBackend *backend = fs_backend ();
	gchar *why = NULL;

	if (backend->log_active != NULL && !backend->log_active ()) {
		const gchar *problem = backend->log_problem != NULL
		                       ? backend->log_problem () : NULL;
		const gchar *lead = "The event reader stopped: ";

		if (problem == NULL || *problem == '\0')
			why = g_strdup ("no reason was given");
		else if (g_str_has_prefix (problem, lead))
			why = g_strdup (problem + strlen (lead));
		else
			why = g_strdup (problem);
	} else if (st->log_file != NULL) {
		gint fd = open (st->log_file, O_RDONLY | O_CLOEXEC | O_NONBLOCK |
		                O_NOCTTY);

		if (fd < 0)
			why = g_strdup_printf ("%s cannot be read: %s", st->log_file,
			                       g_strerror (errno));
		else
			close (fd);
	}

	if (why != NULL) {
		gsize len = strlen (why);

		if (len > 0 && why[len - 1] == '.')
			why[len - 1] = '\0';
		status_line_hook (st, STATUS_STOP);
		fs_cli_error ("the event reader stopped: %s", why);
		g_free (why);
		st->rc = FS_EXIT_FAILURE;
		g_main_loop_quit (st->loop);
		return G_SOURCE_REMOVE;
	}

	status_line_hook (st, STATUS_TICK);
	return G_SOURCE_CONTINUE;
}

/* The newest `want' matching events of the saved history, oldest
 * first.  The hit's strings are only lent for the call: kept ones are
 * copied. */
typedef struct
{
	const GPtrArray *queries;
	Display         *display;
	GQueue           kept;
	guint            want;
	guint            matched;
} HistoryScan;

static void
on_history_hit (const FsHit *hit, gint64 ticks, gpointer data)
{
	HistoryScan *scan = data;

	if (!display_keep (scan->display, hit) ||
	    !queries_match (scan->queries, hit, ticks / 10))
		return;

	scan->matched++;
	if (scan->want == 0)
		return;
	g_queue_push_tail (&scan->kept, fs_hit_copy (hit));
	if (scan->kept.length > scan->want)
		fs_hit_free (g_queue_pop_head (&scan->kept));
}

static GPtrArray *
read_saved_history (const gchar *dir, const FsEventFilter *filter,
                    const GPtrArray *queries, Display *display, guint want,
                    FsEventLogStats *stats)
{
	HistoryScan scan = { queries, display, G_QUEUE_INIT, want, 0 };
	GPtrArray *hits = g_ptr_array_new_with_free_func (
		(GDestroyNotify) fs_hit_free);

	fs_eventlog_foreach (dir, filter->since_us, filter->until_us,
	                     on_history_hit, &scan, stats);
	while (scan.kept.length > 0)
		g_ptr_array_add (hits, g_queue_pop_head (&scan.kept));
	return hits;
}

/* [ coverage_note ]
 * How far back the kernel log reaches, on stderr: the journal holds
 * the current boot only (as read here), kern.log what logrotate kept. */
static void
coverage_note (void)
{
	gchar *source = NULL;
	const gchar *override = g_getenv ("STOCKFW_LOG_FILE");

	if (fs_cli.quiet || (override != NULL && *override != '\0'))
		return;
	fs_cli_log_readable (&source, NULL);
	if (g_strcmp0 (source, "the journal") == 0)
		fprintf (stderr, "%sRead from the journal: current boot only.%s\n",
		         fs_cli_dim (), fs_cli_reset ());
	else if (source != NULL)
		fprintf (stderr, "%sRead from %s; older events are in its rotated "
		         "files.%s\n", fs_cli_dim (), source, fs_cli_reset ());
	g_free (source);
}

/* ------------------------------------------------------ events --summary */

static const gchar *const by_keys[] = {
	"src", "dst", "port", "service", "dir", "rule", "hour"
};

typedef struct
{
	gchar      *key;
	gchar      *service;     /* --by port: the port's service name     */
	guint64     blocked;
	guint64     allowed;
	GHashTable *ports;       /* port number -> count                   */
	gint64      first;
	gint64      last;
} Group;

typedef struct
{
	const gchar *name;
	GHashTable  *groups;     /* key -> Group*                          */
} ByTable;

typedef struct
{
	const GPtrArray *queries;
	Display  *display;
	gint64    from_us;
	gint64    to_us;
	guint     step;          /* seconds per bucket                     */
	guint     n_buckets;
	guint64  *b_blocked;
	guint64  *b_allowed;
	guint64   blocked;
	guint64   allowed;
	GPtrArray *by;           /* ByTable*                               */
} Summary;

static void
group_free (Group *g)
{
	g_free (g->key);
	g_free (g->service);
	g_hash_table_unref (g->ports);
	g_free (g);
}

/* [ summary_key ] -- what an event counts under for one --by key. */
static gchar *
summary_key (const FsHit *hit, const gchar *by, gint64 epoch)
{
	if (strcmp (by, "src") == 0)
		return address_short (hit->source);
	if (strcmp (by, "dst") == 0)
		return address_short (hit->destination);
	if (strcmp (by, "port") == 0) {
		gchar *proto = g_ascii_strdown (hit->protocol != NULL &&
		                                *hit->protocol ? hit->protocol
		                                               : "-", -1);
		gchar *key = hit->port != NULL && *hit->port
		             ? g_strdup_printf ("%s/%s", hit->port, proto)
		             : g_strdup (proto);

		g_free (proto);
		return key;
	}
	if (strcmp (by, "service") == 0) {
		gchar *name = fs_hit_service_name (hit);

		if (*name == '\0') {
			g_free (name);
			name = g_strdup ("-");
		}
		return name;
	}
	if (strcmp (by, "dir") == 0)
		return g_strdup (g_ascii_strcasecmp (hit->direction ? hit->direction
		                                     : "in", "in") == 0 ? "in" : "out");
	if (strcmp (by, "rule") == 0) {
		gchar *name = fs_cli_hit_rule_name (hit);

		return name != NULL ? name : g_strdup ("-");
	}
	/* hour */
	if (epoch < 0)
		return g_strdup ("-");
	{
		GDateTime *t = g_date_time_new_from_unix_utc (epoch - epoch % 3600);
		GDateTime *shown = fs_cli.utc ? g_date_time_ref (t)
		                              : g_date_time_to_local (t);
		gchar *key = g_date_time_format (shown, fs_cli.utc
		                                 ? "%Y-%m-%dT%H:00Z"
		                                 : "%Y-%m-%d %H:00");

		g_date_time_unref (shown);
		g_date_time_unref (t);
		return key;
	}
}

static void
summary_add (Summary *s, const FsHit *hit, gint64 time_us)
{
	gboolean blocked = fs_hit_is_blocked (hit);
	gint64 epoch = time_us > 0 ? time_us / G_USEC_PER_SEC : -1;

	if (!display_keep (s->display, hit) ||
	    !queries_match (s->queries, hit, time_us))
		return;

	if (blocked)
		s->blocked++;
	else
		s->allowed++;

	if (time_us >= s->from_us && time_us < s->to_us && s->n_buckets > 0) {
		guint b = (guint) ((time_us - s->from_us) / G_USEC_PER_SEC / s->step);

		if (b < s->n_buckets) {
			if (blocked)
				s->b_blocked[b]++;
			else
				s->b_allowed[b]++;
		}
	}

	for (guint i = 0; i < s->by->len; i++) {
		ByTable *t = g_ptr_array_index (s->by, i);
		gchar *key = summary_key (hit, t->name, epoch);
		Group *g = g_hash_table_lookup (t->groups, key);
		guint port = hit->port != NULL ? (guint) atoi (hit->port) : 0;

		if (g == NULL) {
			g = g_new0 (Group, 1);
			g->key = key;
			g->ports = g_hash_table_new (g_direct_hash, g_direct_equal);
			g->first = g->last = epoch;
			if (strcmp (t->name, "port") == 0) {
				g->service = fs_hit_service_name (hit);
				if (*g->service == '\0') {
					g_free (g->service);
					g->service = g_strdup ("-");
				}
			}
			g_hash_table_insert (t->groups, key, g);
		} else {
			g_free (key);
		}
		if (blocked)
			g->blocked++;
		else
			g->allowed++;
		if (port > 0)
			g_hash_table_insert (g->ports, GUINT_TO_POINTER (port),
			                     GUINT_TO_POINTER (GPOINTER_TO_UINT (
			                         g_hash_table_lookup (g->ports,
			                             GUINT_TO_POINTER (port))) + 1));
		if (epoch >= 0) {
			if (g->first < 0 || epoch < g->first)
				g->first = epoch;
			if (epoch > g->last)
				g->last = epoch;
		}
	}
}

static void
on_summary_history_hit (const FsHit *hit, gint64 ticks, gpointer data)
{
	summary_add (data, hit, ticks / 10);
}

/* Biggest first, then by name. */
static gint
group_order (gconstpointer a, gconstpointer b)
{
	const Group *x = *(const Group * const *) a;
	const Group *y = *(const Group * const *) b;
	guint64 tx = x->blocked + x->allowed, ty = y->blocked + y->allowed;

	if (tx != ty)
		return tx > ty ? -1 : 1;
	return strcmp (x->key, y->key);
}

static GPtrArray *
sorted_groups (const ByTable *t)
{
	GPtrArray *list = g_ptr_array_new ();
	GHashTableIter iter;
	gpointer value;

	g_hash_table_iter_init (&iter, t->groups);
	while (g_hash_table_iter_next (&iter, NULL, &value))
		g_ptr_array_add (list, value);
	g_ptr_array_sort (list, group_order);
	return list;
}

/* The port a group saw most (the lower number on a tie); 0: none. */
static guint
group_top_port (const Group *g)
{
	GHashTableIter iter;
	gpointer k, v;
	guint best = 0, best_n = 0;

	g_hash_table_iter_init (&iter, g->ports);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		guint port = GPOINTER_TO_UINT (k), n = GPOINTER_TO_UINT (v);

		if (n > best_n || (n == best_n && port < best)) {
			best = port;
			best_n = n;
		}
	}
	return best;
}

/* [ bucket_step ]
 * The dashboard's step (fs_activity_step_for) for about 24 bars; a
 * window longer than a day takes whole hours or days, so the bar line
 * stays short. */
static guint
bucket_step (gint64 range_s)
{
	static const guint longer[] = { 7200, 10800, 14400, 21600, 43200, 86400 };
	guint step = fs_activity_step_for ((guint) MIN (range_s, G_MAXUINT), 24);

	for (guint i = 0; i < G_N_ELEMENTS (longer) &&
	     (range_s + step - 1) / step > 24; i++)
		step = longer[i];
	/* More than 48 bars: whole days, as few as fit in 48, worked out
	 * in 64 bits.  A window of thousands of years (--until 9999-12-30
	 * with no --since) needs more than a guint of seconds per bar; the
	 * old `step += 86400' loop wrapped round to 0 there and divided by
	 * it (SIGFPE).  The step stops at the most whole days a guint
	 * holds, and such a window gets a few more bars (75 at most up to
	 * the year 9999). */
	if ((range_s + step - 1) / step > 48) {
		const guint64 max_step = (G_MAXUINT / 86400u) * 86400u;
		guint64 want = ((guint64) range_s + 47) / 48;

		want = (want + 86399) / 86400 * 86400;
		step = (guint) MIN (want, max_step);
	}
	return step;
}

static gchar *
step_text (guint step)
{
	if (step < 60)
		return g_strdup_printf ("per %u s", step);
	if (step < 3600)
		return g_strdup_printf ("per %u min", step / 60);
	if (step == 3600)
		return g_strdup ("per hour");
	if (step < 86400)
		return g_strdup_printf ("per %u h", step / 3600);
	if (step == 86400)
		return g_strdup ("per day");
	return g_strdup_printf ("per %u days", step / 86400);
}

/* [ bars ] -- one bar per bucket; .:-=# outside a UTF-8 locale. */
static gchar *
bars (const Summary *s)
{
	static const gchar *const utf8[] = {
		"\xe2\x96\x81", "\xe2\x96\x82", "\xe2\x96\x83", "\xe2\x96\x84",
		"\xe2\x96\x85", "\xe2\x96\x86", "\xe2\x96\x87", "\xe2\x96\x88"
	};
	static const gchar *const ascii[] = { ".", ":", "-", "=", "#" };
	gboolean is_utf8 = g_get_charset (NULL);
	const gchar *const *glyph = is_utf8 ? utf8 : ascii;
	guint levels = is_utf8 ? G_N_ELEMENTS (utf8) : G_N_ELEMENTS (ascii);
	guint64 max = 0;
	GString *out = g_string_new (NULL);

	for (guint i = 0; i < s->n_buckets; i++)
		max = MAX (max, s->b_blocked[i] + s->b_allowed[i]);
	for (guint i = 0; i < s->n_buckets; i++) {
		guint64 v = s->b_blocked[i] + s->b_allowed[i];
		guint level = v == 0 || max == 0 ? 0
		              : (guint) (1 + (v * (levels - 1) - 1) / max);

		g_string_append (out, glyph[MIN (level, levels - 1)]);
	}
	return g_string_free (out, FALSE);
}

static void
summary_json (const Summary *s, const gchar *source, guint top)
{
	GString *out = g_string_new ("{");
	gint64 from = s->from_us / G_USEC_PER_SEC, to = s->to_us / G_USEC_PER_SEC;
	gchar *t;

	t = fs_cli_time_text (from, FS_CLI_TIME_ISO);
	fs_json_kv_str (out, "from", t);
	g_free (t);
	g_string_append_printf (out, ",\"from_epoch\":%" G_GINT64_FORMAT, from);
	t = fs_cli_time_text (to, FS_CLI_TIME_ISO);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "to", t);
	g_free (t);
	g_string_append_printf (out, ",\"to_epoch\":%" G_GINT64_FORMAT ",", to);
	fs_json_kv_str (out, "source", source);
	g_string_append_printf (out, ",\"total\":%" G_GUINT64_FORMAT
	                        ",\"blocked\":%" G_GUINT64_FORMAT
	                        ",\"allowed\":%" G_GUINT64_FORMAT
	                        ",\"step\":%u,\"buckets\":[",
	                        s->blocked + s->allowed, s->blocked, s->allowed,
	                        s->step);
	for (guint i = 0; i < s->n_buckets; i++) {
		gint64 start = from + (gint64) i * s->step;

		if (i > 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, '{');
		fs_json_kv_time (out, "start", start);
		g_string_append_printf (out, ",\"blocked\":%" G_GUINT64_FORMAT
		                        ",\"allowed\":%" G_GUINT64_FORMAT "}",
		                        s->b_blocked[i], s->b_allowed[i]);
	}
	g_string_append (out, "],\"by\":{");
	for (guint i = 0; i < s->by->len; i++) {
		const ByTable *bt = g_ptr_array_index (s->by, i);
		GPtrArray *groups = sorted_groups (bt);

		if (i > 0)
			g_string_append_c (out, ',');
		fs_json_key (out, bt->name);
		g_string_append_c (out, '[');
		for (guint k = 0; k < groups->len && k < top; k++) {
			const Group *g = g_ptr_array_index (groups, k);
			guint top_port = group_top_port (g);

			if (k > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "key", g->key);
			g_string_append_printf (out, ",\"blocked\":%" G_GUINT64_FORMAT
			                        ",\"allowed\":%" G_GUINT64_FORMAT
			                        ",\"distinct_ports\":%u,\"top_port\":",
			                        g->blocked, g->allowed,
			                        g_hash_table_size (g->ports));
			if (top_port > 0)
				g_string_append_printf (out, "%u", top_port);
			else
				g_string_append (out, "null");
			if (g->service != NULL) {
				g_string_append_c (out, ',');
				fs_json_kv_str (out, "service", g->service);
			}
			g_string_append (out, ",\"first\":");
			if (g->first >= 0) {
				t = fs_cli_time_text (g->first, FS_CLI_TIME_ISO);
				fs_json_string (out, t);
				g_free (t);
			} else
				g_string_append (out, "null");
			g_string_append (out, ",\"last\":");
			if (g->last >= 0) {
				t = fs_cli_time_text (g->last, FS_CLI_TIME_ISO);
				fs_json_string (out, t);
				g_free (t);
			} else
				g_string_append (out, "null");
			g_string_append_c (out, '}');
		}
		g_string_append_c (out, ']');
		g_ptr_array_unref (groups);
	}
	g_string_append (out, "}}");
	fs_cli_print_json (out);
	g_string_free (out, TRUE);
}

static const gchar *
by_heading (const gchar *name)
{
	if (strcmp (name, "src") == 0)     return "SOURCE";
	if (strcmp (name, "dst") == 0)     return "DESTINATION";
	if (strcmp (name, "service") == 0) return "SERVICE";
	if (strcmp (name, "dir") == 0)     return "DIR";
	if (strcmp (name, "rule") == 0)    return "RULE";
	if (strcmp (name, "hour") == 0)    return "HOUR";
	return "PORT";
}

static void
summary_text (const Summary *s, const gchar *source, guint top)
{
	gchar *b = count_text (s->blocked), *a = count_text (s->allowed);
	gchar *from = window_stamp (s->from_us / G_USEC_PER_SEC);
	gchar *to = window_stamp (s->to_us / G_USEC_PER_SEC);
	gchar *line = bars (s), *per = step_text (s->step);

	printf ("%s%s blocked%s, %s allowed %s %s %s %s (from %s)\n",
	        fs_cli_bold (), b, fs_cli_reset (), a,
	        fs_cli_sym (FS_CLI_SYM_SEP), from, fs_cli_sym (FS_CLI_SYM_ARROW),
	        to, source);
	if (s->n_buckets > 0)
		printf ("%-9s %s\n", per, line);
	g_free (b); g_free (a); g_free (from); g_free (to);
	g_free (line); g_free (per);

	for (guint i = 0; i < s->by->len; i++) {
		const ByTable *bt = g_ptr_array_index (s->by, i);
		GPtrArray *groups = sorted_groups (bt);
		GPtrArray *rows = g_ptr_array_new_with_free_func (
			(GDestroyNotify) g_strfreev);
		gboolean by_port = strcmp (bt->name, "port") == 0;

		for (guint k = 0; k < groups->len && k < top; k++) {
			const Group *g = g_ptr_array_index (groups, k);
			gchar **row = g_new0 (gchar *, 8);
			guint c = 0;

			row[c++] = g_strdup (g->key);
			if (by_port)
				row[c++] = g_strdup (g->service);
			row[c++] = g_strdup_printf ("%" G_GUINT64_FORMAT, g->blocked);
			row[c++] = g_strdup_printf ("%" G_GUINT64_FORMAT, g->allowed);
			if (!by_port) {
				guint tp = group_top_port (g);
				gchar *name = tp > 0 ? fs_netparse_port_name (tp) : NULL;

				row[c++] = g_strdup_printf ("%u", g_hash_table_size (g->ports));
				row[c++] = tp == 0 ? g_strdup ("-")
				           : name != NULL ? g_strdup_printf ("%u %s", tp, name)
				           : g_strdup_printf ("%u", tp);
				g_free (name);
			}
			row[c++] = short_stamp (g->first);
			row[c++] = short_stamp (g->last);
			g_ptr_array_add (rows, row);
		}

		if (!fs_cli.plain)
			printf ("\n");
		if (rows->len == 0) {
			if (!fs_cli.quiet)
				printf ("%sNo events in this window.%s\n", fs_cli_dim (),
				        fs_cli_reset ());
		} else if (by_port) {
			const gchar *headers[] = {
				"PORT", "SERVICE", "BLOCKED", "ALLOWED", "FIRST", "LAST"
			};

			fs_cli_table_ex (headers, 6, rows, 40, 1);
		} else {
			const gchar *headers[] = {
				by_heading (bt->name), "BLOCKED", "ALLOWED", "PORTS",
				"TOP PORT", "FIRST", "LAST"
			};

			fs_cli_table_ex (headers, 7, rows, 40, 0);
		}
		g_ptr_array_unref (rows);
		g_ptr_array_unref (groups);
	}
}

/* [ run_summary ] -- `events --summary': every matching event counted. */
static gint
run_summary (const FsEventFilter *filter, const GPtrArray *queries,
             Display *display, gboolean saved, const gchar *dir,
             GPtrArray *by_names, guint top)
{
	Summary s = { 0 };
	gchar *source = NULL;
	gint64 range_s;
	gint rc = FS_EXIT_OK;

	s.queries = queries;
	s.display = display;
	s.to_us = filter->until_us > 0 ? filter->until_us : g_get_real_time ();
	s.from_us = filter->since_us;
	if (s.from_us >= s.to_us)
		s.from_us = s.to_us - G_USEC_PER_SEC;
	range_s = MAX ((s.to_us - s.from_us) / G_USEC_PER_SEC, 1);
	s.step = bucket_step (range_s);
	/* Buckets start on the step, so they land on round times: rounded
	 * down, also before 1970 (C's % is negative there, which moved the
	 * start later than --since). */
	{
		gint64 off = s.from_us / G_USEC_PER_SEC % (gint64) s.step;

		if (off < 0)
			off += s.step;
		s.from_us -= off * G_USEC_PER_SEC;
	}
	s.n_buckets = (guint) (((s.to_us - s.from_us) / G_USEC_PER_SEC +
	                        s.step - 1) / s.step);
	s.b_blocked = g_new0 (guint64, MAX (s.n_buckets, 1));
	s.b_allowed = g_new0 (guint64, MAX (s.n_buckets, 1));
	s.by = g_ptr_array_new ();
	for (guint i = 0; i < by_names->len; i++) {
		ByTable *t = g_new0 (ByTable, 1);

		t->name = g_ptr_array_index (by_names, i);
		t->groups = g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
		                                   (GDestroyNotify) group_free);
		g_ptr_array_add (s.by, t);
	}

	if (saved) {
		FsEventLogStats stats = { 0 };

		/* Streamed: a year of history is never held in memory. */
		fs_eventlog_foreach (dir, filter->since_us, filter->until_us,
		                     on_summary_history_hit, &s, &stats);
		source = g_strdup (dir);
	} else {
		GError *error = NULL;
		GPtrArray *hits = fs_cli_log_history (FS_EVENTSTORE_MAX_CAPACITY,
		                                      NULL, &error);

		if (hits == NULL) {
			fs_cli_error ("%s", error->message);
			g_error_free (error);
			rc = geteuid () != 0 ? FS_EXIT_NEED_ROOT : FS_EXIT_FAILURE;
			goto out;
		}
		for (guint i = 0; i < hits->len; i++) {
			const FsHit *hit = g_ptr_array_index (hits, i);

			summary_add (&s, hit, hit_time_us (hit));
		}
		g_ptr_array_unref (hits);
		fs_cli_log_readable (&source, NULL);
	}

	if (fs_cli.json)
		summary_json (&s, source, top);
	else
		summary_text (&s, source != NULL ? source : "the kernel log", top);

out:
	for (guint i = 0; i < s.by->len; i++) {
		ByTable *t = g_ptr_array_index (s.by, i);

		g_hash_table_unref (t->groups);
		g_free (t);
	}
	g_ptr_array_unref (s.by);
	g_free (s.b_blocked);
	g_free (s.b_allowed);
	g_free (source);
	return rc;
}

/* ---------------------------------------- events --stats, --clear-history */

/* [ history_writer_active ]
 * Does a copy of StockFW hold the history folder's writer lock now
 * (core/fs-eventlog.c: flock on <dir>/.lock while a log is open)?  A
 * shared lock that cannot be had means it does.  Nothing is created:
 * no lock file, no writer. */
static gboolean
history_writer_active (const gchar *dir)
{
	gchar *path = g_build_filename (dir, ".lock", NULL);
	gint fd = open (path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
	gboolean held = FALSE;

	g_free (path);
	if (fd < 0)
		return FALSE;
	if (flock (fd, LOCK_SH | LOCK_NB) != 0)
		held = errno == EWOULDBLOCK || errno == EAGAIN;
	close (fd);
	return held;
}

/* [ history_problem ]
 * "Not being written: ..." of Preferences > Events (J11), as far as a
 * process that is not the writer can tell: NULL while a copy of
 * StockFW writes the folder. */
static const gchar *
history_problem (const gchar *dir)
{
	if (history_writer_active (dir))
		return NULL;
	if (!fs_prefs_bool (FS_PREFS_EVENTS_HISTORY))
		return "Keep event history is off (Preferences > Events)";
	return "no copy of StockFW is running to write it (the desktop app "
	       "writes it while it runs)";
}

/* [ history_usage_text ]
 * The Preferences window's usage line: "1.2 MB in 3 files, in DIR."
 * or "No saved history in DIR.", then "Not being written: why" when
 * that applies.  Safe for a terminal. */
static gchar *
history_usage_text (const gchar *dir, guint64 bytes, guint files,
                    const gchar *problem)
{
	gchar *safe = fs_cli_out_safe (dir);
	gchar *size = fs_cli_format_bytes (bytes);
	GString *t = g_string_new (NULL);

	if (files == 0)
		g_string_printf (t, "No saved history in %s.", safe);
	else
		g_string_printf (t, "%s in %u file%s, in %s.", size, files,
		                 files == 1 ? "" : "s", safe);
	if (problem != NULL)
		g_string_append_printf (t, "\nNot being written: %s.", problem);
	g_free (size);
	g_free (safe);
	return g_string_free (t, FALSE);
}

static void
history_json (GString *out, const gchar *dir, guint64 bytes, guint files,
              const gchar *problem)
{
	g_string_append_c (out, '{');
	fs_json_kv_str (out, "dir", dir);                 g_string_append_c (out, ',');
	fs_json_kv_bool (out, "keep_history",
	                 fs_prefs_bool (FS_PREFS_EVENTS_HISTORY));
	g_string_append_c (out, ',');
	fs_json_kv_uint (out, "bytes", bytes);            g_string_append_c (out, ',');
	fs_json_kv_uint (out, "files", files);            g_string_append_c (out, ',');
	fs_json_kv_bool (out, "being_written", problem == NULL);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "problem", problem);
	g_string_append_c (out, '}');
}

/* [ print_history_lines ] -- "History  ..." with a hanging indent. */
static void
print_history_lines (const gchar *label, const gchar *text)
{
	gchar **lines = g_strsplit (text, "\n", -1);

	for (guint i = 0; lines[i] != NULL; i++)
		printf ("%-11s %s\n", i == 0 ? label : "", lines[i]);
	g_strfreev (lines);
}

/* [ clear_history ]
 * `events --clear-history' (J11): the usage and why it is not being
 * written first, then "Delete ...? [y/N]" on a terminal (No by
 * default; --yes skips it, and without a terminal --yes is needed),
 * then fs_eventlog_clear_dir, which deletes nothing while another
 * copy is writing the folder. */
static gint
clear_history (const gchar *dir, gboolean yes)
{
	guint64 bytes = 0, after_bytes = 0;
	guint files = 0, after_files = 0, removed = 0;
	const gchar *problem;
	gchar *text;
	GError *error = NULL;
	gint rc = FS_EXIT_OK;

	if (g_file_test (dir, G_FILE_TEST_IS_DIR))
		fs_eventlog_usage (dir, &bytes, &files);
	problem = history_problem (dir);
	text = history_usage_text (dir, bytes, files, problem);
	if (!fs_cli.json)
		print_history_lines ("History", text);
	g_free (text);

	if (files == 0) {
		if (fs_cli.json) {
			GString *out = g_string_new ("{");

			fs_json_kv_uint (out, "deleted", 0);
			g_string_append (out, ",\"history\":");
			history_json (out, dir, bytes, files, problem);
			g_string_append (out, ",\"error\":null}");
			fs_cli_print_json (out);
			g_string_free (out, TRUE);
		} else if (!fs_cli.quiet) {
			printf ("Nothing to delete.\n");
		}
		return FS_EXIT_OK;
	}

	if (!yes) {
		gchar answer[16] = "";
		gchar *safe;

		if (!isatty (STDIN_FILENO)) {
			fs_cli_error ("refused: pass --yes to delete the saved event "
			              "history");
			return FS_EXIT_FAILURE;
		}
		safe = fs_cli_out_safe (dir);
		fprintf (stderr, "Delete the saved event history?  Every history "
		         "file in %s is deleted now.  [y/N] ", safe);
		g_free (safe);
		fflush (stderr);
		if (fgets (answer, sizeof answer, stdin) == NULL ||
		    (g_ascii_strcasecmp (g_strstrip (answer), "y") != 0 &&
		     g_ascii_strcasecmp (answer, "yes") != 0)) {
			fs_cli_error ("not deleted: the history was left as it was");
			return FS_EXIT_FAILURE;
		}
	}

	removed = fs_eventlog_clear_dir (dir, &error);
	fs_eventlog_usage (dir, &after_bytes, &after_files);
	if (error != NULL) {
		fs_cli_error ("%s%s", g_error_matches (error, FS_EVENTLOG_ERROR,
		                                       FS_EVENTLOG_ERROR_IN_USE)
		              ? "" : "some history was not deleted: ",
		              error->message);
		rc = FS_EXIT_FAILURE;
	}

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_uint (out, "deleted", removed);
		g_string_append (out, ",\"history\":");
		history_json (out, dir, after_bytes, after_files,
		              history_problem (dir));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "error", error != NULL ? error->message
		                                            : NULL);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (!fs_cli.quiet || error == NULL) {
		gchar *safe = fs_cli_out_safe (dir);

		printf ("Deleted %u history file%s from %s.\n", removed,
		        removed == 1 ? "" : "s", safe);
		g_free (safe);
		if (after_files > 0) {
			text = history_usage_text (dir, after_bytes, after_files,
			                           NULL);
			print_history_lines ("Left", text);
			g_free (text);
		}
	}
	g_clear_error (&error);
	return rc;
}

/* [ Stats ] -- `events --stats': what the filters made of the events. */
typedef struct
{
	const GPtrArray *queries;
	Display         *display;
	guint64          outside;       /* hidden by the list's filters   */
	guint64          in_blocked, in_allowed, out_blocked, out_allowed;
} Stats;

static void
stats_add (Stats *st, const FsHit *hit, gint64 time_us)
{
	gboolean blocked;

	if (!display_keep (st->display, hit))
		return;
	if (!queries_match (st->queries, hit, time_us)) {
		st->outside++;
		return;
	}
	blocked = fs_hit_is_blocked (hit);
	if (fs_hit_is_outbound (hit)) {
		if (blocked)
			st->out_blocked++;
		else
			st->out_allowed++;
	} else if (blocked) {
		st->in_blocked++;
	} else {
		st->in_allowed++;
	}
}

static void
on_stats_history_hit (const FsHit *hit, gint64 ticks, gpointer data)
{
	stats_add (data, hit, ticks / 10);
}

/* [ run_stats ]
 * How many events were read, how many each filter hid (repeats, not
 * for this computer, the list's own filters) and how many were left,
 * inbound and outbound, blocked and allowed -- the Overview's Totals
 * (B10) over the events read -- then the history: how much is saved,
 * where, and why it is not being written. */
static gint
run_stats (const FsEventFilter *filter, const GPtrArray *queries,
           Display *display, gboolean saved, const gchar *dir)
{
	Stats st = { queries, display, 0, 0, 0, 0, 0 };
	gchar *source = NULL, *hdir = NULL;
	gchar *log_error = NULL;
	guint64 bytes = 0, shown;
	guint files = 0;
	const gchar *problem;
	FsEventLogStats lstats = { 0 };
	gint rc = FS_EXIT_OK;

	if (saved) {
		fs_eventlog_foreach (dir, filter->since_us, filter->until_us,
		                     on_stats_history_hit, &st, &lstats);
		source = g_strdup (dir);
	} else {
		GError *error = NULL;
		GPtrArray *hits = fs_cli_log_history (FS_EVENTSTORE_MAX_CAPACITY,
		                                      NULL, &error);

		if (hits == NULL) {
			log_error = g_strdup (error->message);
			g_error_free (error);
			rc = geteuid () != 0 ? FS_EXIT_NEED_ROOT : FS_EXIT_FAILURE;
		} else {
			for (guint i = 0; i < hits->len; i++) {
				const FsHit *hit = g_ptr_array_index (hits, i);

				stats_add (&st, hit, hit_time_us (hit));
			}
			g_ptr_array_unref (hits);
			fs_cli_log_readable (&source, NULL);
		}
	}
	shown = st.in_blocked + st.in_allowed + st.out_blocked + st.out_allowed;

	hdir = dir != NULL ? g_strdup (dir) : fs_eventlog_default_dir ();
	if (g_file_test (hdir, G_FILE_TEST_IS_DIR))
		fs_eventlog_usage (hdir, &bytes, &files);
	problem = history_problem (hdir);

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "source", log_error != NULL ? NULL
		                : source != NULL ? source : "the kernel log");
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "error", log_error);  g_string_append_c (out, ',');
		fs_json_kv_uint (out, "read", display->seen); g_string_append_c (out, ',');
		fs_json_kv_uint (out, "shown", shown);     g_string_append (out, ",\"inbound\":{");
		fs_json_kv_uint (out, "blocked", st.in_blocked);   g_string_append_c (out, ',');
		fs_json_kv_uint (out, "allowed", st.in_allowed);   g_string_append (out, "},\"outbound\":{");
		fs_json_kv_uint (out, "blocked", st.out_blocked);  g_string_append_c (out, ',');
		fs_json_kv_uint (out, "allowed", st.out_allowed);  g_string_append (out, "},\"hidden\":{");
		fs_json_kv_uint (out, "repeats", display->repeats_hidden);
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "not_for_me", display->not_for_me_hidden);
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "filters", st.outside);
		g_string_append (out, "},\"filters\":{");
		fs_json_kv_bool (out, "collapse_repeats", display->repeats);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "for_me", display->not_for_me);
		g_string_append (out, "},");
		fs_json_kv_uint (out, "bad_lines", lstats.bad_lines);
		g_string_append (out, ",\"history\":");
		history_json (out, hdir, bytes, files, problem);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		gchar *text;

		if (log_error != NULL) {
			printf ("%-11s %s%s%s\n", "Events", fs_cli_amber (),
			        "the kernel log cannot be read", fs_cli_reset ());
		} else {
			gchar *n = count_text (display->seen);
			gchar *k = count_text (shown);
			gchar *src = fs_cli_out_safe (source != NULL ? source
			                              : "the kernel log");

			printf ("%-11s %s read from %s, %s shown\n", "Events", n,
			        src, k);
			g_free (n); g_free (k); g_free (src);
			n = count_text (st.in_blocked);
			k = count_text (st.in_allowed);
			printf ("%-11s %s blocked, %s allowed\n", "  Inbound", n, k);
			g_free (n); g_free (k);
			n = count_text (st.out_blocked);
			k = count_text (st.out_allowed);
			printf ("%-11s %s blocked, %s allowed\n", "  Outbound", n, k);
			g_free (n); g_free (k);
			{
				gchar *r = count_text (display->repeats_hidden);
				gchar *m = count_text (display->not_for_me_hidden);
				gchar *o = count_text (st.outside);

				printf ("%-11s %s repeat%s%s, %s not for this computer%s, "
				        "%s by the filters\n", "  Hidden", r,
				        display->repeats_hidden == 1 ? "" : "s",
				        display->repeats ? "" : " (off)", m,
				        display->not_for_me ? "" : " (off)", o);
				g_free (r); g_free (m); g_free (o);
			}
		}
		text = history_usage_text (hdir, bytes, files, problem);
		print_history_lines ("History", text);
		g_free (text);
		if (saved && lstats.bad_lines > 0 && !fs_cli.quiet)
			fprintf (stderr, "%s%u damaged or cut-short line(s) in the "
			         "history were skipped.%s\n", fs_cli_dim (),
			         lstats.bad_lines, fs_cli_reset ());
	}
	if (log_error != NULL) {
		fs_cli_error ("%s", log_error);
		fs_cli_hint ("`stockfw events --stats --history' counts the history "
		             "the desktop app saved");
	}

	g_free (log_error);
	g_free (source);
	g_free (hdir);
	return rc;
}

/* [ add_by_keys ] -- "--by src,port": checked against the keys. */
static gboolean
add_by_keys (const gchar *v, GPtrArray *names)
{
	gchar **keys = g_strsplit (v, ",", -1);
	gboolean ok = keys[0] != NULL;

	for (gint i = 0; ok && keys[i] != NULL; i++) {
		const gchar *found = NULL;

		for (guint k = 0; k < G_N_ELEMENTS (by_keys); k++)
			if (g_ascii_strcasecmp (keys[i], by_keys[k]) == 0)
				found = by_keys[k];
		if (found == NULL) {
			const gchar *near = fs_cli_suggest (keys[i], by_keys,
			                                    G_N_ELEMENTS (by_keys));

			if (near != NULL)
				fs_cli_error ("--by does not know `%s' (did you mean %s?)",
				              keys[i], near);
			else
				fs_cli_error ("--by does not know `%s'", keys[i]);
			fs_cli_hint ("--by takes src, dst, port, service, dir, rule "
			             "or hour, or several with commas");
			ok = FALSE;
		} else {
			gboolean dup = FALSE;

			for (guint k = 0; k < names->len; k++)
				dup |= g_ptr_array_index (names, k) == (gpointer) found;
			if (!dup)
				g_ptr_array_add (names, (gpointer) found);
		}
	}
	g_strfreev (keys);
	return ok;
}

gint
fs_cli_cmd_events (gint argc, gchar **argv)
{
	static const gchar *const protos[] = { "tcp", "udp", "icmp", "icmpv6" };
	guint count = 20, top = 10;
	gboolean follow = FALSE, saved = FALSE, reverse = FALSE;
	gboolean summary = FALSE, want_blocked = FALSE, want_allowed = FALSE;
	gboolean by_given = FALSE, top_given = FALSE, no_status = FALSE;
	gboolean stats_wanted = FALSE, clear = FALSE, yes = FALSE;
	gboolean prefs_filters = FALSE;
	Display display = { 0 };
	const gchar *since = NULL, *until = NULL, *dir_opt = NULL;
	const gchar *port_opt = NULL;
	FsEventFilter filter = { 0 };
	EventsState st = { 0 };
	FsEventLogStats stats = { 0 };
	GPtrArray *history = NULL;
	GPtrArray *by_names = g_ptr_array_new ();
	GArray *ranges = g_array_new (FALSE, FALSE, sizeof (PortRange));
	gchar *dir = NULL;
	GError *error = NULL;
	gint rc = FS_EXIT_OK;

	for (gint i = 1; i < argc; i++) {
		const gchar *v = NULL;
		gint bad = FS_EXIT_OK;

		if (fs_cli_take_opt (argc, argv, &i, "-n", &v, &bad) ||
		    fs_cli_take_opt (argc, argv, &i, "--lines", &v, &bad) ||
		    fs_cli_take_opt (argc, argv, &i, "--limit", &v, &bad)) {
			if (v != NULL &&
			    !parse_count ("-n", v, FS_EVENTSTORE_MAX_CAPACITY, &count))
				bad = FS_EXIT_USAGE;
		} else if (fs_cli_take_opt (argc, argv, &i, "--since", &v, &bad)) {
			since = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--until", &v, &bad)) {
			until = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--grep", &v, &bad)) {
			filter.text = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--proto", &v, &bad)) {
			gboolean known = FALSE;

			for (guint k = 0; v != NULL && k < G_N_ELEMENTS (protos); k++)
				known |= g_ascii_strcasecmp (v, protos[k]) == 0;
			if (v != NULL && !known) {
				gchar *low = g_ascii_strdown (v, -1);
				const gchar *near = fs_cli_suggest (low, protos,
				                                    G_N_ELEMENTS (protos));

				if (near != NULL)
					fs_cli_error ("--proto wants tcp, udp, icmp or icmpv6, "
					              "not `%s' (did you mean %s?)", v, near);
				else
					fs_cli_error ("--proto wants tcp, udp, icmp or icmpv6, "
					              "not `%s'", v);
				g_free (low);
				bad = FS_EXIT_USAGE;
			}
			filter.protocol = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--port", &v, &bad)) {
			if (v != NULL && !parse_port_list ("--port", v, ranges))
				bad = FS_EXIT_USAGE;
			port_opt = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--addr", &v, &bad)) {
			filter.address = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--history-dir", &v,
		                            &bad)) {
			dir_opt = v;
			saved = TRUE;
		} else if (fs_cli_take_opt (argc, argv, &i, "--dir", &v, &bad) ||
		           fs_cli_take_opt (argc, argv, &i, "--direction", &v,
		                            &bad)) {
			if (v != NULL && !parse_dir ("--dir", v, &filter.direction, TRUE))
				bad = FS_EXIT_USAGE;
		} else if (fs_cli_take_opt (argc, argv, &i, "--by", &v, &bad)) {
			by_given = TRUE;
			if (v != NULL && !add_by_keys (v, by_names))
				bad = FS_EXIT_USAGE;
		} else if (fs_cli_take_opt (argc, argv, &i, "--top", &v, &bad)) {
			top_given = TRUE;
			if (v != NULL && !parse_count ("--top", v, 100000, &top))
				bad = FS_EXIT_USAGE;
		} else if (!fs_cli_is_option_at (argv, i)) {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			bad = FS_EXIT_USAGE;
		} else if (strcmp (argv[i], "-f") == 0 ||
		           strcmp (argv[i], "--follow") == 0) {
			follow = TRUE;
		} else if (strcmp (argv[i], "--history") == 0) {
			saved = TRUE;
		} else if (strcmp (argv[i], "--blocked") == 0) {
			want_blocked = TRUE;
		} else if (strcmp (argv[i], "--allowed") == 0) {
			want_allowed = TRUE;
		} else if (strcmp (argv[i], "--utc") == 0) {
			fs_cli.utc = TRUE;
		} else if (strcmp (argv[i], "--wide") == 0) {
			st.wide = TRUE;
		} else if (strcmp (argv[i], "-r") == 0 ||
		           strcmp (argv[i], "--reverse") == 0) {
			reverse = TRUE;
		} else if (strcmp (argv[i], "--csv") == 0) {
			st.csv = TRUE;
		} else if (strcmp (argv[i], "--summary") == 0) {
			summary = TRUE;
		} else if (strcmp (argv[i], "--no-status-line") == 0) {
			no_status = TRUE;
		} else if (strcmp (argv[i], "--collapse-repeats") == 0) {
			display.repeats = TRUE;
		} else if (strcmp (argv[i], "--for-me") == 0) {
			display.not_for_me = TRUE;
		} else if (strcmp (argv[i], "--prefs-filters") == 0) {
			prefs_filters = TRUE;
		} else if (strcmp (argv[i], "--stats") == 0) {
			stats_wanted = TRUE;
		} else if (strcmp (argv[i], "--clear-history") == 0) {
			clear = TRUE;
		} else if (strcmp (argv[i], "--yes") == 0 ||
		           strcmp (argv[i], "-y") == 0) {
			yes = TRUE;
		} else {
			fs_cli_unknown_option ("events", argv[i]);
			bad = FS_EXIT_USAGE;
		}
		/* A value option with no value, or one that cannot be read:
		 * the error is printed. */
		if (bad != FS_EXIT_OK) {
			rc = bad;
			goto out;
		}
	}

	if (want_blocked && want_allowed) {
		fs_cli_error ("--blocked and --allowed cannot be used together "
		              "(leave both out for every event)");
		rc = FS_EXIT_USAGE;
		goto out;
	}
	filter.action = want_blocked ? FS_EVQ_ACTION_BLOCKED
	              : want_allowed ? FS_EVQ_ACTION_ALLOWED
	              : FS_EVQ_ACTION_ANY;
	if (st.csv && fs_cli.json) {
		fs_cli_error ("--csv and --json cannot be used together");
		rc = FS_EXIT_USAGE;
		goto out;
	}
	if (summary && (follow || st.csv)) {
		fs_cli_error ("--summary cannot be used with %s",
		              follow ? "-f" : "--csv");
		rc = FS_EXIT_USAGE;
		goto out;
	}
	/* One thing at a time: deleting the history, its numbers, a
	 * summary, or the events themselves. */
	if (clear && (follow || summary || stats_wanted || st.csv)) {
		fs_cli_error ("--clear-history cannot be used with %s",
		              follow ? "-f" : summary ? "--summary"
		              : stats_wanted ? "--stats" : "--csv");
		rc = FS_EXIT_USAGE;
		goto out;
	}
	if (stats_wanted && (follow || summary || st.csv)) {
		fs_cli_error ("--stats cannot be used with %s",
		              follow ? "-f" : summary ? "--summary" : "--csv");
		rc = FS_EXIT_USAGE;
		goto out;
	}
	if (yes && !clear) {
		fs_cli_error ("--yes goes with --clear-history");
		rc = FS_EXIT_USAGE;
		goto out;
	}
	if (clear) {
		dir = dir_opt != NULL ? g_strdup (dir_opt)
		                      : fs_eventlog_default_dir ();
		rc = clear_history (dir, yes);
		if (rc != FS_EXIT_OK && dir_opt == NULL && geteuid () == 0 &&
		    g_getenv ("SUDO_USER") != NULL)
			fs_cli_hint ("under sudo this is root's history; give "
			             "--history-dir for yours");
		goto out;
	}

	/* The Events page's two filters (C18): asked for, or as the
	 * preferences have them. */
	if (prefs_filters) {
		display.repeats |= fs_prefs_bool (FS_PREFS_SKIP_REDUNDANT);
		display.not_for_me |= fs_prefs_bool (FS_PREFS_SKIP_NOT_FOR_FIREWALL);
	}
	if (display.repeats || display.not_for_me)
		display.filter = fs_hit_filter_new (fs_backend ()->list_interfaces);
	st.display = &display;

	if ((by_given || top_given) && !summary) {
		fs_cli_error ("%s goes with --summary", by_given ? "--by" : "--top");
		fs_cli_hint ("for example `stockfw events --summary --by src --top 5'");
		rc = FS_EXIT_USAGE;
		goto out;
	}

	/* A summary covers a window: the last day unless one is given. */
	if (summary && since == NULL && until == NULL)
		since = "24h";
	if (!fs_cli_parse_window (since, until, &filter.since_us,
	                          &filter.until_us)) {
		rc = FS_EXIT_USAGE;
		goto out;
	}

	/* One query, or one per --port range; any of them may match. */
	st.queries = g_ptr_array_new_with_free_func (
		(GDestroyNotify) fs_eventquery_free);
	for (guint r = 0; r < MAX (ranges->len, 1u); r++) {
		FsEventFilter one = filter;
		gchar *port = NULL;
		FsEventQuery *query;

		if (ranges->len > 0) {
			const PortRange *pr = &g_array_index (ranges, PortRange, r);

			port = pr->lo == pr->hi ? g_strdup_printf ("%u", pr->lo)
			       : g_strdup_printf ("%u-%u", pr->lo, pr->hi);
			one.port = port;
		}
		query = fs_eventquery_new (&one, &error);
		g_free (port);
		if (query == NULL) {
			fs_cli_error ("%s", error->message);
			g_clear_error (&error);
			rc = FS_EXIT_USAGE;
			goto out;
		}
		g_ptr_array_add (st.queries, query);
	}
	if (st.queries->len == 1 &&
	    fs_eventquery_is_empty (g_ptr_array_index (st.queries, 0)))
		g_clear_pointer (&st.queries, g_ptr_array_unref);
	(void) port_opt;

	if (saved) {
		/* The history the desktop app saves for this account (root's
		 * own under sudo: point --history-dir at the user's). */
		dir = dir_opt != NULL ? g_strdup (dir_opt)
		                      : fs_eventlog_default_dir ();
		if (!g_file_test (dir, G_FILE_TEST_IS_DIR)) {
			fs_cli_error ("no saved event history in %s", dir);
			fs_cli_hint ("the desktop app saves it while Preferences > "
			             "Events > Keep event history is on%s",
			             geteuid () == 0 && g_getenv ("SUDO_USER")
			             ? "; under sudo this is root's folder, give "
			               "--history-dir for yours" : "");
			rc = FS_EXIT_FAILURE;
			goto out;
		}
	}

	if (summary) {
		if (by_names->len == 0) {
			g_ptr_array_add (by_names, (gpointer) "src");
			g_ptr_array_add (by_names, (gpointer) "port");
		}
		rc = run_summary (&filter, st.queries, &display, saved, dir,
		                  by_names, top);
		goto out;
	}

	if (stats_wanted) {
		rc = run_stats (&filter, st.queries, &display, saved, dir);
		goto out;
	}

	if (saved) {
		history = read_saved_history (dir, &filter, st.queries, &display,
		                              count, &stats);
	} else if (count > 0) {
		/* With a filter, look further back so N matches can be
		 * found, then keep the newest N of them. */
		history = fs_cli_log_history (st.queries != NULL ||
		                              display.filter != NULL
		                              ? MAX (count, 100000u) : count,
		                              NULL, &error);

		if (history == NULL) {
			fs_cli_error ("%s", error->message);
			g_error_free (error);
			if (geteuid () != 0)
			{
				gchar *args = fs_cli_user_args ();
				gchar *again = fs_cli_sudo_hint (args);

				fs_cli_hint ("try `%s', or `stockfw events "
				             "--history' for the history the desktop "
				             "app saved", again);
				g_free (again);
				g_free (args);
			}
			rc = geteuid () != 0 ? FS_EXIT_NEED_ROOT : FS_EXIT_FAILURE;
			goto out;
		}
		if (st.queries != NULL || display.filter != NULL) {
			GPtrArray *kept = g_ptr_array_new_with_free_func (
				(GDestroyNotify) fs_hit_free);

			for (guint i = 0; i < history->len; i++) {
				FsHit *hit = g_ptr_array_index (history, i);

				if (display_keep (&display, hit) &&
				    queries_match (st.queries, hit, hit_time_us (hit))) {
					g_ptr_array_index (history, i) = NULL;
					g_ptr_array_add (kept, hit);
				}
			}
			g_ptr_array_unref (history);
			history = kept;
		}
		while (history->len > count)
			g_ptr_array_remove_index (history, 0);
		if (!follow)
			coverage_note ();
	}

	/* -r: newest first. */
	if (history != NULL && reverse)
		for (guint a = 0, b = history->len; a + 1 < b; a++, b--) {
			gpointer t = history->pdata[a];

			history->pdata[a] = history->pdata[b - 1];
			history->pdata[b - 1] = t;
		}

	if (fs_cli.json && !follow) {
		GString *out = g_string_new ("[");

		for (guint i = 0; history != NULL && i < history->len; i++) {
			if (out->len > 1)
				g_string_append_c (out, ',');
			fs_cli_hit_row_json (out, g_ptr_array_index (history, i));
		}
		g_string_append_c (out, ']');
		if (history != NULL)
			fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (fs_cli.json) {
		/* --follow --json: the history as NDJSON too. */
		for (guint i = 0; history != NULL && i < history->len; i++)
			print_live_hit (g_ptr_array_index (history, i), &st);
	} else if (st.csv) {
		printf ("%s\n", csv_header);
		for (guint i = 0; history != NULL && i < history->len; i++)
			csv_line (g_ptr_array_index (history, i));
	} else {
		const gchar *const *headers = st.wide ? event_wide_headers
		                                      : event_headers;
		guint n = st.wide ? EVENT_WIDE_COLS : EVENT_COLS;
		GPtrArray *rows = g_ptr_array_new_with_free_func (
			(GDestroyNotify) g_strfreev);

		for (guint i = 0; history != NULL && i < history->len; i++)
			g_ptr_array_add (rows, event_row (g_ptr_array_index (history, i),
			                                  st.wide));

		if (rows->len > 0)
			fs_cli_table (headers, n, rows, 40);

		if (follow) {
			/* The live rows go under this header, in these widths
			 * (cli-plan.md D1, survey A6).  With no backlog the
			 * widths come from sample cells: an IPv4 address is 15
			 * wide, a wider cell is cut on a terminal only. */
			if (rows->len == 0) {
				gchar *stamp = fs_cli_time_text (
					g_get_real_time () / G_USEC_PER_SEC,
					st.wide ? FS_CLI_TIME_FULL : FS_CLI_TIME_SHORT);
				gchar *sample[EVENT_WIDE_COLS + 1] = { NULL };

				if (st.wide) {
					const gchar *w[] = {
						stamp, "BLOCKED", "out", "eth0", "eth0",
						"255.255.255.255", "255.255.255.255", "65535",
						"Unknown", "ICMPv6", "1500", "0x00", "-"
					};
					memcpy (sample, w, sizeof (w));
				} else {
					const gchar *w[] = {
						stamp, "BLOCKED", "out", "255.255.255.255",
						"255.255.255.255", "65535", "Unknown", "ICMPv6", "-"
					};
					memcpy (sample, w, sizeof (w));
				}
				g_ptr_array_add (rows, g_strdupv (sample));
				st.widths = fs_cli_table_widths (headers, n, rows, 40, -1);
				fs_cli_table_header (headers, n, st.widths);
				g_free (stamp);
			} else {
				st.widths = fs_cli_table_widths (headers, n, rows, 40, -1);
			}
		} else if (rows->len == 0 && history != NULL && !fs_cli.quiet) {
			printf ("%s%s%s\n", fs_cli_dim (),
			        saved ? "No saved events match."
			        : st.queries != NULL || display.filter != NULL
			        ? "No StockFW events in the kernel log match."
			        : "No StockFW events in the kernel log yet.",
			        fs_cli_reset ());
		}
		g_ptr_array_unref (rows);
	}
	if (saved && stats.bad_lines > 0 && !fs_cli.quiet && !fs_cli.json)
		fprintf (stderr, "%s%u damaged or cut-short line(s) in the "
		         "history were skipped.%s\n", fs_cli_dim (),
		         stats.bad_lines, fs_cli_reset ());
	/* What the two filters left out, so an empty list is explained. */
	if (!follow && display.filter != NULL && !fs_cli.quiet &&
	    !fs_cli.json && (display.repeats_hidden > 0 ||
	                     display.not_for_me_hidden > 0)) {
		gchar *r = count_text (display.repeats_hidden);
		gchar *m = count_text (display.not_for_me_hidden);

		fprintf (stderr, "%sHidden: %s repeat%s, %s not for this "
		         "computer.%s\n", fs_cli_dim (), r,
		         display.repeats_hidden == 1 ? "" : "s", m,
		         fs_cli_reset ());
		g_free (r);
		g_free (m);
	}

	if (follow) {
		const FsBackend *backend = fs_backend ();
		const gchar *override = g_getenv ("STOCKFW_LOG_FILE");
		guint check;

		fflush (stdout);
		if (st.csv && history == NULL)
			printf ("%s\n", csv_header);
		if (backend->log_start == NULL ||
		    !backend->log_start (on_live_hit, &st, &error)) {
			fs_cli_error ("cannot follow events: %s",
			              error ? error->message : "no event source");
			g_clear_error (&error);
			rc = geteuid () != 0 ? FS_EXIT_NEED_ROOT : FS_EXIT_FAILURE;
			goto out;
		}
		if (override != NULL && *override != '\0')
			st.log_file = override;

		if (!fs_cli.quiet) {
			const gchar *source = backend->log_source != NULL
			                      ? backend->log_source () : NULL;

			fprintf (stderr, "%sFollowing new events from %s -- Ctrl-C to "
			         "stop.%s\n", fs_cli_dim (),
			         source != NULL ? source : "the kernel log",
			         fs_cli_reset ());
		}

		st.loop = g_main_loop_new (NULL, FALSE);
		st.started_us = g_get_monotonic_time ();
		st.printed = st.blocked = 0;
		st.rc = FS_EXIT_OK;
		st.status_on = status_line_wanted (st.csv, no_status);
		status_line_start (&st);
		status_line_hook (&st, STATUS_AFTER_ROW);
		g_unix_signal_add (SIGINT, on_follow_signal, &st);
		g_unix_signal_add (SIGTERM, on_follow_signal, &st);
		check = g_timeout_add_seconds (2, on_reader_check, &st);
		g_main_loop_run (st.loop);
		g_main_loop_unref (st.loop);
		if (st.rc == FS_EXIT_OK)
			g_source_remove (check);

		backend->log_stop ();
		rc = st.rc;
		/* Whatever ended it, the line is not left behind. */
		if (!st.interrupted || fs_cli.quiet)
			status_line_hook (&st, STATUS_STOP);

		/* Ctrl-C: what was seen, on stderr; the exit stays 0. */
		if (st.interrupted && !fs_cli.quiet) {
			gchar *took = duration_text ((g_get_monotonic_time () -
			                              st.started_us) / G_USEC_PER_SEC);

			status_line_hook (&st, STATUS_STOP);
			fprintf (stderr, "%s%u event%s (%u blocked) in %s%s\n",
			         fs_cli.json ? "" : "\n", st.printed,
			         st.printed == 1 ? "" : "s", st.blocked, took, "");
			g_free (took);
		}
	}

out:
	if (history != NULL)
		g_ptr_array_unref (history);
	if (st.queries != NULL)
		g_ptr_array_unref (st.queries);
	g_free (st.widths);
	fs_cli_status_snapshot_free (st.snap);
	g_ptr_array_unref (by_names);
	g_array_unref (ranges);
	g_free (dir);
	fs_hit_filter_free (display.filter);
	return rc;
}

/* ------------------------------------------------- sockets (/proc/net) */

/* /proc/net/NAME, or $STOCKFW_PROC_NET_DIR/NAME (tests: fixture tables;
 * only the command line reads it, and only to show them). */
static gchar *
proc_net_path (const gchar *name)
{
	const gchar *dir = g_getenv ("STOCKFW_PROC_NET_DIR");

	return g_build_filename (dir != NULL && *dir != '\0' ? dir : "/proc/net",
	                         name, NULL);
}

static GList *
read_table (const gchar *name, gboolean udp, gboolean ipv6)
{
	gchar *path = proc_net_path (name);
	gchar *text = NULL;
	GList *list = NULL;

	if (g_file_get_contents (path, &text, NULL, NULL))
		list = udp ? fs_netparse_proc_udp (text, ipv6)
		           : fs_netparse_proc_tcp (text, ipv6);
	g_free (text);
	g_free (path);
	return list;
}

static GList *
read_sockets (gboolean tcp, gboolean udp)
{
	GList *list = NULL;

	if (tcp) {
		list = g_list_concat (list, read_table ("tcp", FALSE, FALSE));
		list = g_list_concat (list, read_table ("tcp6", FALSE, TRUE));
	}
	if (udp) {
		list = g_list_concat (list, read_table ("udp", TRUE, FALSE));
		list = g_list_concat (list, read_table ("udp6", TRUE, TRUE));
	}
	return list;
}

/* The owner map, when the backend has one (Linux); NULL otherwise. */
static GHashTable *
socket_owners (void)
{
	const FsBackend *backend = fs_backend ();

	return backend->socket_owners != NULL ? backend->socket_owners () : NULL;
}

/* "10.0.0.5:22", "[2001:db8::1]:443" */
static gchar *
endpoint_text (const gchar *addr, guint port)
{
	gchar *a = address_short (addr);
	gchar *text;

	if (port == 0)
		return a;
	text = strchr (a, ':') != NULL ? g_strdup_printf ("[%s]:%u", a, port)
	                               : g_strdup_printf ("%s:%u", a, port);
	g_free (a);
	return text;
}

/* --------------------------------------------------------- connections */

static const gchar *const by_conn_keys[] = { "remote", "program", "port" };

static gboolean
conn_passes (const FsConnection *c, FsEventQuery *addr, const GArray *ports,
             const gchar *program, FsEventDirFilter dir, const gchar *state,
             gboolean no_local)
{
	if (addr != NULL) {
		FsHit probe = { 0 };

		probe.source = c->source;
		probe.destination = c->destination;
		if (!fs_eventquery_match_hit (addr, &probe, 0))
			return FALSE;
	}
	if (ports->len > 0) {
		guint p = c->port != NULL ? (guint) atoi (c->port) : 0;

		if (!port_in (ports, c->local_port) && !port_in (ports, c->remote_port) &&
		    !port_in (ports, p))
			return FALSE;
	}
	if (program != NULL) {
		gchar *want = g_utf8_casefold (program, -1);
		gchar *have = g_utf8_casefold (c->program != NULL ? c->program : "", -1);
		gboolean hit = strstr (have, want) != NULL;

		g_free (want);
		g_free (have);
		if (!hit)
			return FALSE;
	}
	if (dir == FS_EVQ_DIR_IN && g_strcmp0 (c->direction, "Inbound") != 0)
		return FALSE;
	if (dir == FS_EVQ_DIR_OUT && g_strcmp0 (c->direction, "Outbound") != 0)
		return FALSE;
	if (state != NULL && g_ascii_strcasecmp (state, c->state != NULL
	                                         ? c->state : "") != 0)
		return FALSE;
	if (no_local && (is_loopback_text (c->destination) ||
	                 g_strcmp0 (c->source, c->destination) == 0))
		return FALSE;
	return TRUE;
}

static gchar *
conn_key (const FsConnection *c, const gchar *by)
{
	if (strcmp (by, "remote") == 0)
		return address_short (c->destination);
	if (strcmp (by, "program") == 0)
		return g_strdup (c->program != NULL ? c->program : "?");
	return g_strdup_printf ("%s/%s", c->port != NULL ? c->port : "-",
	                        g_strcmp0 (c->protocol, "UDP") == 0 ? "udp" : "tcp");
}

typedef struct
{
	gchar *key;
	guint  count;
} Tally;

static gint
tally_order (gconstpointer a, gconstpointer b)
{
	const Tally *x = *(const Tally * const *) a;
	const Tally *y = *(const Tally * const *) b;

	if (x->count != y->count)
		return x->count > y->count ? -1 : 1;
	return strcmp (x->key, y->key);
}

static void
tally_free (Tally *t)
{
	g_free (t->key);
	g_free (t);
}

static void
json_port (GString *out, const gchar *key, guint port)
{
	fs_json_key (out, key);
	if (port > 0)
		g_string_append_printf (out, "%u", port);
	else
		g_string_append (out, "null");
}

gint
fs_cli_cmd_connections (gint argc, gchar **argv)
{
	const FsBackend *backend = fs_backend ();
	FsEventFilter addr_filter = { 0 };
	FsEventQuery *addr = NULL;
	GArray *ports = g_array_new (FALSE, FALSE, sizeof (PortRange));
	const gchar *program = NULL, *state = NULL, *by = NULL;
	FsEventDirFilter dir = FS_EVQ_DIR_ANY;
	gboolean no_local = FALSE, udp = FALSE;
	GList *conns = NULL, *kept = NULL;
	GError *error = NULL;
	gint rc = FS_EXIT_OK;

	for (gint i = 1; i < argc; i++) {
		const gchar *v = NULL;
		gint bad = FS_EXIT_OK;

		if (fs_cli_take_opt (argc, argv, &i, "--addr", &v, &bad)) {
			addr_filter.address = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--port", &v, &bad)) {
			if (v != NULL && !parse_port_list ("--port", v, ports))
				bad = FS_EXIT_USAGE;
		} else if (fs_cli_take_opt (argc, argv, &i, "--program", &v, &bad)) {
			program = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--dir", &v, &bad) ||
		           fs_cli_take_opt (argc, argv, &i, "--direction", &v,
		                            &bad)) {
			if (v != NULL && !parse_dir ("--dir", v, &dir, TRUE))
				bad = FS_EXIT_USAGE;
		} else if (fs_cli_take_opt (argc, argv, &i, "--state", &v, &bad)) {
			gboolean known = FALSE;
			const gchar *names[13];
			guint n = 0;

			for (guint s = 1; s <= 12; s++)
				names[n++] = fs_netparse_tcp_state_name (s);
			for (guint s = 0; v != NULL && s < n; s++)
				known |= g_ascii_strcasecmp (v, names[s]) == 0;
			if (v != NULL && !known) {
				gchar *up = g_ascii_strup (v, -1);
				const gchar *near = fs_cli_suggest (up, names, n);

				fs_cli_error ("--state does not know `%s'%s%s%s", v,
				              near ? " (did you mean " : "",
				              near ? near : "", near ? "?)" : "");
				fs_cli_hint ("states are the kernel's: ESTABLISHED, "
				             "SYN_SENT, CLOSE_WAIT, FIN_WAIT1...");
				g_free (up);
				bad = FS_EXIT_USAGE;
			}
			state = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--by", &v, &bad)) {
			by = NULL;
			for (guint k = 0; v != NULL && k < G_N_ELEMENTS (by_conn_keys); k++)
				if (g_ascii_strcasecmp (v, by_conn_keys[k]) == 0)
					by = by_conn_keys[k];
			if (v != NULL && by == NULL) {
				const gchar *near = fs_cli_suggest (v, by_conn_keys,
				                                    G_N_ELEMENTS (by_conn_keys));

				fs_cli_error ("--by wants remote, program or port, not "
				              "`%s'%s%s%s", v, near ? " (did you mean " : "",
				              near ? near : "", near ? "?)" : "");
				bad = FS_EXIT_USAGE;
			}
		} else if (!fs_cli_is_option_at (argv, i)) {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			bad = FS_EXIT_USAGE;
		} else if (strcmp (argv[i], "--no-local") == 0) {
			no_local = TRUE;
		} else if (strcmp (argv[i], "--udp") == 0) {
			udp = TRUE;
		} else {
			fs_cli_unknown_option ("connections", argv[i]);
			bad = FS_EXIT_USAGE;
		}
		if (bad != FS_EXIT_OK) {
			rc = bad;
			goto out;
		}
	}

	if (addr_filter.address != NULL) {
		addr = fs_eventquery_new (&addr_filter, &error);
		if (addr == NULL) {
			fs_cli_error ("%s", error->message);
			g_error_free (error);
			rc = FS_EXIT_USAGE;
			goto out;
		}
	}

	if (backend->socket_owners != NULL) {
		/* The tables read here, so connected UDP can be added and a
		 * fixture can stand in for /proc/net. */
		GList *sockets = read_sockets (TRUE, udp);
		GHashTable *owners = sockets != NULL ? socket_owners () : NULL;

		conns = fs_netparse_connections (sockets, owners);
		if (owners != NULL)
			g_hash_table_unref (owners);
		g_list_free_full (sockets, (GDestroyNotify) fs_net_socket_free);
	} else if (backend->list_connections != NULL) {
		conns = backend->list_connections ();
	} else {
		fs_cli_error ("this backend cannot list connections");
		rc = FS_EXIT_FAILURE;
		goto out;
	}

	for (GList *l = conns; l != NULL; l = l->next)
		if (conn_passes (l->data, addr, ports, program, dir, state, no_local))
			kept = g_list_prepend (kept, l->data);
	kept = g_list_reverse (kept);

	if (by != NULL) {
		GHashTable *seen = g_hash_table_new (g_str_hash, g_str_equal);
		GPtrArray *tallies = g_ptr_array_new_with_free_func (
			(GDestroyNotify) tally_free);

		for (GList *l = kept; l != NULL; l = l->next) {
			gchar *key = conn_key (l->data, by);
			Tally *t = g_hash_table_lookup (seen, key);

			if (t == NULL) {
				t = g_new0 (Tally, 1);
				t->key = key;
				g_hash_table_insert (seen, t->key, t);
				g_ptr_array_add (tallies, t);
			} else {
				g_free (key);
			}
			t->count++;
		}
		g_ptr_array_sort (tallies, tally_order);

		if (fs_cli.json) {
			GString *out = g_string_new ("[");

			for (guint i = 0; i < tallies->len; i++) {
				const Tally *t = g_ptr_array_index (tallies, i);

				if (i > 0)
					g_string_append_c (out, ',');
				g_string_append_c (out, '{');
				fs_json_kv_str (out, "key", t->key);
				g_string_append_printf (out, ",\"count\":%u}", t->count);
			}
			g_string_append_c (out, ']');
			fs_cli_print_json (out);
			g_string_free (out, TRUE);
		} else if (tallies->len == 0) {
			if (!fs_cli.quiet)
				printf ("No connections match.\n");
		} else {
			const gchar *headers[] = {
				strcmp (by, "remote") == 0 ? "REMOTE"
				: strcmp (by, "program") == 0 ? "PROGRAM" : "PORT",
				"COUNT"
			};
			GPtrArray *rows = g_ptr_array_new_with_free_func (
				(GDestroyNotify) g_strfreev);

			for (guint i = 0; i < tallies->len; i++) {
				const Tally *t = g_ptr_array_index (tallies, i);
				gchar **row = g_new0 (gchar *, 3);

				row[0] = g_strdup (t->key);
				row[1] = g_strdup_printf ("%u", t->count);
				g_ptr_array_add (rows, row);
			}
			fs_cli_table_ex (headers, 2, rows, 0, 0);
			g_ptr_array_unref (rows);
		}
		g_ptr_array_unref (tallies);
		g_hash_table_unref (seen);
	} else if (fs_cli.json) {
		GString *out = g_string_new ("[");

		for (GList *l = kept; l != NULL; l = l->next) {
			FsConnection *c = l->data;

			if (l != kept)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "local", c->source);          g_string_append_c (out, ',');
			fs_json_kv_str (out, "remote", c->destination);    g_string_append_c (out, ',');
			fs_json_kv_str (out, "port", c->port);             g_string_append_c (out, ',');
			fs_json_kv_str (out, "protocol", c->protocol);     g_string_append_c (out, ',');
			fs_json_kv_str (out, "service", c->service);       g_string_append_c (out, ',');
			fs_json_kv_str (out, "program", c->program);       g_string_append_c (out, ',');
			fs_json_kv_str (out, "direction", c->direction);   g_string_append_c (out, ',');
			json_port (out, "local_port", c->local_port);      g_string_append_c (out, ',');
			json_port (out, "remote_port", c->remote_port);    g_string_append_c (out, ',');
			fs_json_kv_str (out, "state", c->state);
			g_string_append_c (out, '}');
		}
		g_string_append_c (out, ']');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (kept == NULL) {
		if (!fs_cli.quiet)
			printf (conns == NULL ? "No active %s connections.\n"
			        : "No connections match.\n", udp ? "TCP or UDP" : "TCP");
	} else {
		static const gchar *headers[] = {
			"LOCAL", "REMOTE", "PORT", "SERVICE", "DIRECTION", "STATE",
			"PROGRAM"
		};
		GPtrArray *rows = g_ptr_array_new_with_free_func (
			(GDestroyNotify) g_strfreev);
		gboolean unknown_owner = FALSE;

		for (GList *l = kept; l != NULL; l = l->next) {
			FsConnection *c = l->data;
			gchar **row = g_new0 (gchar *, 8);

			row[0] = endpoint_text (c->source, c->local_port);
			row[1] = endpoint_text (c->destination, c->remote_port);
			row[2] = g_strdup (c->port != NULL ? c->port : "-");
			row[3] = g_strdup (c->service != NULL ? c->service : "-");
			row[4] = g_strdup (c->direction != NULL ? c->direction : "-");
			row[5] = g_strdup (c->state != NULL ? c->state
			                   : g_strcmp0 (c->protocol, "UDP") == 0
			                   ? "UDP" : "-");
			row[6] = g_strdup (c->program != NULL ? c->program : "?");
			g_ptr_array_add (rows, row);

			if (g_strcmp0 (c->program, "?") == 0)
				unknown_owner = TRUE;
		}

		fs_cli_table_ex (headers, 7, rows, 40, 6);
		g_ptr_array_unref (rows);

		/* A legend: stderr, so the table stays the only stdout. */
		fflush (stdout);
		if (unknown_owner && geteuid () != 0 && !fs_cli.quiet)
			fprintf (stderr, "%s\"?\" is another user's program; root can "
			         "see every owner.%s\n", fs_cli_dim (), fs_cli_reset ());
	}

out:
	g_list_free (kept);
	g_list_free_full (conns, (GDestroyNotify) fs_connection_free);
	if (addr != NULL)
		fs_eventquery_free (addr);
	g_array_unref (ports);
	return rc;
}

/* ----------------------------------------------------------- listening */

/* The two sample sources a port is asked about. */
#define INTERNET_SAMPLE "203.0.113.10"

typedef struct
{
	FsWhatIfVerdict verdict;
	gchar          *rule_ref;  /* "inbound-allow-service:1", or NULL     */
	gchar          *decided;   /* what the DECIDED BY column says        */
} PortAnswer;

typedef struct
{
	gboolean    udp;
	guint       port;
	gchar      *bind;
	gint        family;
	gchar      *program;      /* NULL: owner unknown                    */
	gboolean    local;        /* bound to loopback only                  */
	PortAnswer  lan;
	PortAnswer  internet;
} Listener;

static void
listener_free (Listener *l)
{
	g_free (l->bind);
	g_free (l->program);
	g_free (l->lan.rule_ref);
	g_free (l->lan.decided);
	g_free (l->internet.rule_ref);
	g_free (l->internet.decided);
	g_free (l);
}

static const gchar *
verdict_word (FsWhatIfVerdict v)
{
	switch (v) {
	case FS_WHATIF_ALLOWED: return "ALLOWED";
	case FS_WHATIF_BLOCKED: return "BLOCKED";
	case FS_WHATIF_DEPENDS: return "DEPENDS";
	default:                return "UNKNOWN";
	}
}

/* [ ask ] -- one What-If question: may `src' reach this port? */
static void
ask (const FsPolicy *policy, gboolean udp, guint port, const gchar *src,
     PortAnswer *answer)
{
	gchar *line = g_strdup_printf ("inbound %s port %u from %s",
	                               udp ? "udp" : "tcp", port, src);
	/* The policy's answer: whether the firewall runs now is said
	 * once, in the header, not folded into every verdict. */
	FsWhatIfResult *r = fs_cli_whatif_policy (policy, line, TRUE);
	const FsWhatIfAnswer *a = r->answers != NULL && r->answers->len > 0
	                          ? g_ptr_array_index (r->answers, 0) : NULL;

	answer->verdict = r->verdict;
	if (a != NULL && a->policy_kind >= 0 && a->policy_index >= 0 &&
	    a->policy_kind < FS_RULE_N_KINDS) {
		answer->rule_ref = fs_cli_rule_ref ((FsRuleKind) a->policy_kind,
		                                    (guint) a->policy_index + 1);
		answer->decided = g_strdup (answer->rule_ref);
	} else if (a != NULL && a->origin == FS_WHATIF_ORIGIN_DEFAULT) {
		answer->decided = g_strdup (a->verdict == FS_WHATIF_ALLOWED
		                            ? "default inbound allow"
		                            : "default inbound block");
	} else if (a != NULL && a->rule != NULL) {
		answer->decided = g_strdup (a->rule);
	} else {
		answer->decided = g_strdup ("-");
	}
	fs_whatif_result_free (r);
	g_free (line);
}

/* [ lan_sample ] -- an address inside the LAN prefix: its tenth host. */
static gchar *
lan_sample (const gchar *prefix)
{
	gchar **parts;
	GInetAddress *net;
	guint bits;
	gchar *out = NULL;

	if (prefix == NULL)
		return NULL;
	parts = g_strsplit (prefix, "/", 2);
	net = g_inet_address_new_from_string (parts[0]);
	bits = parts[1] != NULL ? (guint) atoi (parts[1]) : 32;
	if (net != NULL &&
	    g_inet_address_get_family (net) == G_SOCKET_FAMILY_IPV4) {
		guint8 b[4];
		guint32 v;
		GInetAddress *host;

		memcpy (b, g_inet_address_to_bytes (net), 4);
		v = ((guint32) b[0] << 24) | ((guint32) b[1] << 16) |
		    ((guint32) b[2] << 8) | b[3];
		v += bits <= 28 ? 10 : bits < 32 ? 1 : 0;
		b[0] = v >> 24; b[1] = v >> 16; b[2] = v >> 8; b[3] = v;
		host = g_inet_address_new_from_bytes (b, G_SOCKET_FAMILY_IPV4);
		out = g_inet_address_to_string (host);
		g_object_unref (host);
	}
	if (net != NULL)
		g_object_unref (net);
	g_strfreev (parts);
	return out;
}

static gint
listener_order (gconstpointer a, gconstpointer b)
{
	const Listener *x = *(const Listener * const *) a;
	const Listener *y = *(const Listener * const *) b;

	if (x->udp != y->udp)
		return x->udp ? 1 : -1;
	if (x->port != y->port)
		return x->port < y->port ? -1 : 1;
	return x->family - y->family;
}

static gboolean
reachable (FsWhatIfVerdict v)
{
	return v == FS_WHATIF_ALLOWED || v == FS_WHATIF_DEPENDS;
}

static void
answer_json (GString *out, const gchar *key, const Listener *l,
             const PortAnswer *a)
{
	fs_json_key (out, key);
	if (l->local) {
		g_string_append (out, "null");
		return;
	}
	g_string_append_c (out, '{');
	fs_json_kv_str (out, "verdict", verdict_word (a->verdict));
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "rule_ref", a->rule_ref);
	g_string_append_c (out, '}');
}

gint
fs_cli_cmd_listening (gint argc, gchar **argv)
{
	const FsBackend *backend = fs_backend ();
	gboolean want_tcp = TRUE, want_udp = TRUE, all = FALSE;
	gboolean only_tcp = FALSE, only_udp = FALSE;
	FsPolicy *saved, *applied = NULL;
	const FsPolicy *policy;
	GList *sockets;
	GHashTable *owners, *seen;
	GPtrArray *list;
	gchar *prefix, *lan;
	gboolean have_lan_prefix;
	gint running = -1;     /* -1 unknown, 0 stopped, 1 running */
	gboolean unknown_owner = FALSE;

	for (gint i = 1; i < argc; i++) {
		if (!fs_cli_is_option_at (argv, i)) {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			return FS_EXIT_USAGE;
		} else if (strcmp (argv[i], "--tcp") == 0) {
			only_tcp = TRUE;
		} else if (strcmp (argv[i], "--udp") == 0) {
			only_udp = TRUE;
		} else if (strcmp (argv[i], "--all") == 0) {
			all = TRUE;
		} else {
			fs_cli_unknown_option ("listening", argv[i]);
			return FS_EXIT_USAGE;
		}
	}
	if (only_tcp != only_udp) {
		want_tcp = only_tcp;
		want_udp = only_udp;
	}

	/* The policy that is live when it can be told (the apply journal),
	 * else the saved one. */
	saved = fs_cli_load_policy (NULL, NULL);
	fs_cli_policy_state (saved, &applied, NULL);
	policy = applied != NULL ? applied : saved;
	if (geteuid () == 0 && backend->get_state != NULL) {
		FsFirewallState state = backend->get_state ();

		running = state == FS_FW_RUNNING || state == FS_FW_LOCKED ||
		          state == FS_FW_HIT ? 1 : state == FS_FW_STOPPED ? 0 : -1;
	}

	prefix = fs_health_lan_prefix_auto (backend);
	have_lan_prefix = prefix != NULL;
	lan = lan_sample (prefix);
	if (lan == NULL)
		lan = g_strdup ("192.168.1.10");

	sockets = read_sockets (want_tcp, want_udp);
	owners = sockets != NULL ? socket_owners () : NULL;
	seen = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	list = g_ptr_array_new_with_free_func ((GDestroyNotify) listener_free);

	for (GList *l = sockets; l != NULL; l = l->next) {
		const FsNetSocket *s = l->data;
		Listener *li;
		gchar *key;
		const gchar *owner;

		if (!fs_netparse_socket_is_listening (s))
			continue;
		key = g_strdup_printf ("%s %s %u", s->udp ? "udp" : "tcp",
		                       s->local_addr, s->local_port);
		if (g_hash_table_contains (seen, key)) {
			g_free (key);
			continue;
		}
		g_hash_table_add (seen, key);

		li = g_new0 (Listener, 1);
		li->udp = s->udp;
		li->port = s->local_port;
		li->bind = address_short (s->local_addr);
		li->family = s->ipv6 && strchr (s->local_addr, ':') != NULL ? 6 : 4;
		owner = owners != NULL && s->inode != 0
		        ? g_hash_table_lookup (owners, &s->inode) : NULL;
		li->program = owner != NULL && strcmp (owner, "?") != 0
		              ? fs_cli_out_safe (owner) : NULL;
		li->local = is_loopback_text (s->local_addr);
		if (!li->local) {
			/* The bind address does not change what the policy
			 * says: the question names the port and protocol. */
			ask (policy, li->udp, li->port, lan, &li->lan);
			ask (policy, li->udp, li->port, INTERNET_SAMPLE, &li->internet);
		}
		g_ptr_array_add (list, li);
	}
	g_ptr_array_sort (list, listener_order);

	if (fs_cli.json) {
		GString *out = g_string_new ("[");

		for (guint i = 0; i < list->len; i++) {
			const Listener *li = g_ptr_array_index (list, i);

			if (i > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "proto", li->udp ? "udp" : "tcp");
			g_string_append_printf (out, ",\"port\":%u,", li->port);
			fs_json_kv_str (out, "bind", li->bind);
			g_string_append_printf (out, ",\"family\":%d,", li->family);
			fs_json_kv_str (out, "program", li->program);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "scope", li->local ? "local" : "all");
			g_string_append_c (out, ',');
			answer_json (out, "lan", li, &li->lan);
			g_string_append_c (out, ',');
			answer_json (out, "internet", li, &li->internet);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "policy", applied != NULL ? "applied"
			                                               : "saved");
			g_string_append (out, ",\"firewall_running\":");
			g_string_append (out, running < 0 ? "null"
			                      : running ? "true" : "false");
			g_string_append_c (out, '}');
		}
		g_string_append_c (out, ']');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		static const gchar *headers[] = {
			"PORT", "PROGRAM", "LISTENS ON", "FROM LAN", "FROM INTERNET",
			"DECIDED BY"
		};
		GPtrArray *rows = g_ptr_array_new_with_free_func (
			(GDestroyNotify) g_strfreev);
		guint hidden = 0, n_internet = 0, n_lan = 0, n_blocked = 0;
		const Listener *prev = NULL;    /* the last row's listener */

		for (guint i = 0; i < list->len; i++) {
			const Listener *li = g_ptr_array_index (list, i);
			gchar **row;
			const PortAnswer *why;

			if (li->local && !all) {
				hidden++;
				continue;
			}
			if (fs_cli.quiet && (li->local || !reachable (li->internet.verdict)))
				continue;

			/* The same port, program and answers on another family
			 * (0.0.0.0 and ::): one row, both binds. */
			if (prev != NULL) {
				gchar **last = g_ptr_array_index (rows, rows->len - 1);

				if (prev->udp == li->udp && prev->port == li->port &&
				    prev->local == li->local &&
				    g_strcmp0 (prev->program, li->program) == 0 &&
				    prev->lan.verdict == li->lan.verdict &&
				    prev->internet.verdict == li->internet.verdict) {
					gchar *both = g_strconcat (last[2], ", ", li->bind, NULL);

					g_free (last[2]);
					last[2] = both;
					continue;
				}
			}

			if (li->program == NULL)
				unknown_owner = TRUE;
			why = reachable (li->internet.verdict) ? &li->internet
			      : reachable (li->lan.verdict) ? &li->lan : &li->internet;
			row = g_new0 (gchar *, 7);
			row[0] = g_strdup_printf ("%u/%s", li->port, li->udp ? "udp" : "tcp");
			row[1] = g_strdup (li->program != NULL ? li->program : "?");
			row[2] = g_strdup (li->bind);
			if (li->local) {
				row[3] = g_strdup ("-");
				row[4] = g_strdup ("-");
				row[5] = g_strdup ("this computer only");
			} else {
				row[3] = g_strdup (verdict_word (li->lan.verdict));
				row[4] = g_strdup (verdict_word (li->internet.verdict));
				row[5] = g_strdup (why->decided);
				if (reachable (li->internet.verdict))
					n_internet++;
				else if (reachable (li->lan.verdict))
					n_lan++;
				else
					n_blocked++;
			}
			g_ptr_array_add (rows, row);
			prev = li;
		}

		if (!fs_cli.quiet) {
			printf ("%sAsked of the %s policy, for a LAN address (%s%s) and "
			        "an internet address (%s).%s\n", fs_cli_dim (),
			        applied != NULL ? "applied" : "saved", lan,
			        have_lan_prefix ? "" : ", a sample", INTERNET_SAMPLE,
			        fs_cli_reset ());
			if (running == 0)
				printf ("%sThe firewall is stopped: every port below is "
				        "open now; the verdicts are for when it runs.%s\n",
				        fs_cli_amber (), fs_cli_reset ());
		}
		if (rows->len > 0)
			fs_cli_table_ex (headers, 6, rows, 40, 5);
		else if (!fs_cli.quiet)
			printf ("No listening sockets%s.\n", hidden > 0
			        ? " except for this computer only" : "");

		if (!fs_cli.quiet) {
			if (hidden > 0)
				printf ("+ %u socket%s for this computer only (stockfw "
				        "listening --all)\n", hidden, hidden == 1 ? "" : "s");
			if (n_internet + n_lan + n_blocked > 0)
				printf ("%u port%s reachable from the internet %s %u from "
				        "the LAN only %s %u blocked\n", n_internet,
				        n_internet == 1 ? "" : "s",
				        fs_cli_sym (FS_CLI_SYM_SEP), n_lan,
				        fs_cli_sym (FS_CLI_SYM_SEP), n_blocked);
			fflush (stdout);
			if (unknown_owner)
				fprintf (stderr, "%s\"?\": the owner could not be read%s.%s\n",
				         fs_cli_dim (), geteuid () != 0
				         ? " (another user's program; root can see every "
				           "owner)" : "", fs_cli_reset ());
		}
		g_ptr_array_unref (rows);
	}

	g_ptr_array_unref (list);
	g_hash_table_unref (seen);
	if (owners != NULL)
		g_hash_table_unref (owners);
	g_list_free_full (sockets, (GDestroyNotify) fs_net_socket_free);
	g_free (prefix);
	g_free (lan);
	if (applied != NULL)
		fs_policy_free (applied);
	fs_policy_free (saved);
	return FS_EXIT_OK;
}

/* ---------------------------------------------------------- interfaces */

static void
rates (const FsIfaceStat *s, GList *before, gdouble seconds,
       gdouble *rx, gdouble *tx)
{
	*rx = *tx = 0;
	for (GList *b = before; b != NULL && seconds > 0; b = b->next) {
		FsIfaceStat *p = b->data;

		if (g_strcmp0 (p->device, s->device) == 0 &&
		    s->received >= p->received && s->sent >= p->sent) {
			*rx = (gdouble) (s->received - p->received) / seconds;
			*tx = (gdouble) (s->sent - p->sent) / seconds;
		}
	}
}

/* [ print_interfaces ]
 * One frame.  `seconds' is the real time between the two samples
 * (g_get_monotonic_time), not the interval asked for: a sleep runs
 * long, and the first frame of --watch was once divided by 2 when it
 * had been measured over 1 s, showing half the rate. */
static void
print_interfaces (GList *now, GList *before, gdouble seconds, gboolean all,
                  gboolean no_virtual)
{
	guint virtuals = 0;

	if (fs_cli.json) {
		GString *out = g_string_new ("[");

		for (GList *l = now; l != NULL; l = l->next) {
			FsIfaceStat *s = l->data;
			gdouble rx, tx;

			if (!s->up && !all)
				continue;
			if (no_virtual && fs_netif_is_virtual (s))
				continue;
			rates (s, before, seconds, &rx, &tx);
			if (out->len > 1)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "device", s->device);     g_string_append_c (out, ',');
			fs_json_kv_str (out, "type", s->kind);         g_string_append_c (out, ',');
			fs_json_kv_str (out, "ip", s->ip);             g_string_append_c (out, ',');
			fs_json_kv_bool (out, "up", s->up);            g_string_append_c (out, ',');
			fs_json_kv_uint (out, "received", s->received); g_string_append_c (out, ',');
			fs_json_kv_uint (out, "sent", s->sent);        g_string_append_c (out, ',');
			g_string_append_printf (out, "\"rx_per_s\":%.0f,\"tx_per_s\":%.0f",
			                        rx, tx);
			g_string_append_c (out, '}');
		}
		g_string_append_c (out, ']');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
		return;
	}

	{
		gchar *down = g_strconcat (fs_cli_sym (FS_CLI_SYM_DOWN), " NOW", NULL);
		gchar *up = g_strconcat (fs_cli_sym (FS_CLI_SYM_UP), " NOW", NULL);
		const gchar *headers[] = {
			"ADAPTER", "TYPE", "ADDRESS", "RECEIVED", "SENT",
			down, up
		};
		GPtrArray *rows = g_ptr_array_new_with_free_func (
			(GDestroyNotify) g_strfreev);
		guint hidden = 0;

		for (GList *l = now; l != NULL; l = l->next) {
			FsIfaceStat *s = l->data;
			gchar **row;
			gdouble rx, tx;

			if (!s->up && !all) {
				hidden++;
				continue;
			}
			/* B12: bridges, tunnels and the like, behind "Show
			 * them" on the Overview. */
			if (no_virtual && fs_netif_is_virtual (s)) {
				virtuals++;
				continue;
			}
			rates (s, before, seconds, &rx, &tx);
			row = g_new0 (gchar *, 8);
			row[0] = g_strconcat (s->device, s->up ? "" : " (down)", NULL);
			row[1] = g_strdup (s->kind ? s->kind : "-");
			row[2] = g_strdup (s->ip ? s->ip : "-");
			row[3] = fs_cli_format_bytes (s->received);
			row[4] = fs_cli_format_bytes (s->sent);
			row[5] = fs_cli_format_rate (rx);
			row[6] = fs_cli_format_rate (tx);
			g_ptr_array_add (rows, row);
		}

		if (rows->len == 0 && virtuals > 0)
			printf ("No network adapters but virtual ones (leave out "
			        "--no-virtual to see them).\n");
		else if (rows->len == 0)
			printf ("No network adapters with traffic counters%s.\n",
			        hidden > 0 ? " are up (--all shows the others)" : "");
		else
			fs_cli_table_ex (headers, 7, rows, 32, 2);
		if (hidden > 0 && rows->len > 0 && !fs_cli.quiet)
			fprintf (stderr, "%s%u adapter%s down (--all shows %s).%s\n",
			         fs_cli_dim (), hidden, hidden == 1 ? " is" : "s are",
			         hidden == 1 ? "it" : "them", fs_cli_reset ());
		if (virtuals > 0 && rows->len > 0 && !fs_cli.quiet)
			fprintf (stderr, "%s%u virtual adapter%s hidden (bridges, "
			         "tunnels, containers: --no-virtual).%s\n",
			         fs_cli_dim (), virtuals, virtuals == 1 ? "" : "s",
			         fs_cli_reset ());
		g_ptr_array_unref (rows);
		g_free (down);
		g_free (up);
	}
}

static gboolean watch_stop = FALSE;

static gboolean
on_watch_signal (gpointer data)
{
	(void) data;
	watch_stop = TRUE;
	return G_SOURCE_CONTINUE;
}

/* Sleep `seconds', waking for Ctrl-C or SIGTERM. */
static void
watch_sleep (guint seconds)
{
	for (guint t = 0; t < seconds * 10 && !watch_stop; t++) {
		g_usleep (G_USEC_PER_SEC / 10);
		while (g_main_context_iteration (NULL, FALSE))
			;
	}
}

gint
fs_cli_cmd_interfaces (gint argc, gchar **argv)
{
	const FsBackend *backend = fs_backend ();
	gboolean watch = FALSE, all = FALSE, no_virtual = FALSE;
	guint interval = 2, frames = 0;    /* 0 frames: until Ctrl-C */
	gboolean clear;
	GList *before, *now;
	gint64 t_before, t_now;

	for (gint i = 1; i < argc; i++) {
		const gchar *v = NULL;
		gint bad = FS_EXIT_OK;

		if (fs_cli_take_opt (argc, argv, &i, "-c", &v, &bad) ||
		    fs_cli_take_opt (argc, argv, &i, "--count", &v, &bad)) {
			if (v != NULL && (!parse_count ("-c", v, 1000000, &frames) ||
			                  frames == 0)) {
				if (frames == 0 && v != NULL && g_ascii_isdigit (*v))
					fs_cli_error ("-c wants 1 or more frames");
				return FS_EXIT_USAGE;
			}
			watch = TRUE;
		} else if (bad != FS_EXIT_OK) {
			return bad;
		} else if (fs_cli_is_option_at (argv, i) &&
		           (strcmp (argv[i], "--watch") == 0 ||
		            strcmp (argv[i], "-w") == 0)) {
			watch = TRUE;
		} else if (fs_cli_is_option_at (argv, i) &&
		           g_str_has_prefix (argv[i], "--watch=")) {
			if (!parse_count ("--watch", argv[i] + 8, 3600, &interval) ||
			    interval == 0) {
				if (interval == 0)
					fs_cli_error ("--watch wants 1 to 3600 seconds");
				return FS_EXIT_USAGE;
			}
			watch = TRUE;
		} else if (fs_cli_is_option_at (argv, i) &&
		           strcmp (argv[i], "--all") == 0) {
			all = TRUE;
		} else if (fs_cli_is_option_at (argv, i) &&
		           strcmp (argv[i], "--no-virtual") == 0) {
			no_virtual = TRUE;
		} else if (fs_cli_is_option_at (argv, i)) {
			fs_cli_unknown_option ("interfaces", argv[i]);
			return FS_EXIT_USAGE;
		} else {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			return FS_EXIT_USAGE;
		}
		if (bad != FS_EXIT_OK)
			return bad;
	}

	if (backend->list_interface_stats == NULL) {
		fs_cli_error ("this backend has no traffic counters");
		return FS_EXIT_FAILURE;
	}

	t_before = g_get_monotonic_time ();
	before = backend->list_interface_stats ();
	g_usleep (G_USEC_PER_SEC);
	now = backend->list_interface_stats ();
	t_now = g_get_monotonic_time ();

	if (!watch) {
		print_interfaces (now, before, (gdouble) (t_now - t_before) /
		                  G_USEC_PER_SEC, all, no_virtual);
	} else {
		guint shown = 0;

		/* The screen is redrawn on a terminal, whatever the colour;
		 * a pipe gets one frame after another.  With --json each
		 * frame is one line (NDJSON). */
		clear = !fs_cli.json && isatty (STDOUT_FILENO);
		g_unix_signal_add (SIGINT, on_watch_signal, NULL);
		g_unix_signal_add (SIGTERM, on_watch_signal, NULL);
		if (!clear && !fs_cli.json && !fs_cli.quiet)
			fprintf (stderr, "%sRefreshing every %u s -- Ctrl-C to stop.%s\n",
			         fs_cli_dim (), interval, fs_cli_reset ());

		while (!watch_stop) {
			if (clear)
				printf ("\033[H\033[2J");
			print_interfaces (now, before, (gdouble) (t_now - t_before) /
			                  G_USEC_PER_SEC, all, no_virtual);
			fflush (stdout);
			if (clear && !fs_cli.quiet)
				fprintf (stderr, "%sRefreshing every %u s -- Ctrl-C to "
				         "stop.%s\n", fs_cli_dim (), interval,
				         fs_cli_reset ());
			if (frames > 0 && ++shown >= frames)
				break;

			g_list_free_full (before, (GDestroyNotify) fs_iface_stat_free);
			before = now;
			t_before = t_now;
			watch_sleep (interval);
			now = backend->list_interface_stats ();
			t_now = g_get_monotonic_time ();
		}
	}

	g_list_free_full (before, (GDestroyNotify) fs_iface_stat_free);
	g_list_free_full (now, (GDestroyNotify) fs_iface_stat_free);

	return FS_EXIT_OK;
}

/* ------------------------------------------------------- the commands */

static const FsCliOption events_opts[] = {
	{ "-n",            TRUE,  NULL },
	{ "--lines",       TRUE,  NULL },
	{ "--limit",       TRUE,  NULL },
	{ "--since",       TRUE,  NULL },
	{ "--until",       TRUE,  NULL },
	{ "--grep",        TRUE,  NULL },
	{ "--proto",       TRUE,  NULL },
	{ "--port",        TRUE,  NULL },
	{ "--addr",        TRUE,  NULL },
	{ "--history-dir", TRUE,  NULL },
	{ "--dir",         TRUE,  NULL },
	{ "--direction",   TRUE,  NULL },
	{ "--by",          TRUE,  NULL },
	{ "--top",         TRUE,  NULL },
	{ "-f",            FALSE, NULL },
	{ "--follow",      FALSE, NULL },
	{ "--history",     FALSE, NULL },
	{ "--blocked",     FALSE, NULL },
	{ "--allowed",     FALSE, NULL },
	{ "--utc",         FALSE, NULL },
	{ "--wide",        FALSE, NULL },
	{ "-r",            FALSE, NULL },
	{ "--reverse",     FALSE, NULL },
	{ "--csv",         FALSE, NULL },
	{ "--summary",     FALSE, NULL },
	{ "--no-status-line", FALSE, NULL },
	{ "--collapse-repeats", FALSE, NULL },
	{ "--for-me",        FALSE, NULL },
	{ "--prefs-filters", FALSE, NULL },
	{ "--stats",         FALSE, NULL },
	{ "--clear-history", FALSE, NULL },
	{ "--yes",           FALSE, NULL },
	{ "-y",              FALSE, NULL },
	{ NULL, FALSE, NULL }
};

static const FsCliOption connections_opts[] = {
	{ "--addr",      TRUE,  NULL },
	{ "--port",      TRUE,  NULL },
	{ "--program",   TRUE,  NULL },
	{ "--dir",       TRUE,  NULL },
	{ "--direction", TRUE,  NULL },
	{ "--state",     TRUE,  NULL },
	{ "--by",        TRUE,  NULL },
	{ "--no-local",  FALSE, NULL },
	{ "--udp",       FALSE, NULL },
	{ NULL, FALSE, NULL }
};

static const FsCliOption listening_opts[] = {
	{ "--tcp", FALSE, NULL },
	{ "--udp", FALSE, NULL },
	{ "--all", FALSE, NULL },
	{ NULL, FALSE, NULL }
};

static const FsCliOption interfaces_opts[] = {
	{ "-c",      TRUE,  NULL },
	{ "--count", TRUE,  NULL },
	{ "--watch", FALSE, NULL },
	{ "-w",      FALSE, NULL },
	{ "--all",   FALSE, NULL },
	{ "--no-virtual", FALSE, NULL },
	{ NULL, FALSE, NULL }
};

const FsCliCommandDef fs_cli_events_commands[] = {
	{ "events", fs_cli_cmd_events,
"Usage: stockfw events [-n N] [-f [--no-status-line]] [--history]\n"
"                      [--json|--csv] [--wide] [-r] [--utc] [filters]\n"
"       stockfw events --summary [--by KEY[,KEY]] [--top N] [filters]\n"
"       stockfw events --stats [--history] [filters]\n"
"       stockfw events --clear-history [--history-dir DIR] [--yes]\n"
"\n"
"The last N (default 20, up to 1000000) events, oldest first (-r: newest\n"
"first).  By default they are read from the kernel log, which usually\n"
"needs root (or the adm group).  --history reads the history the desktop\n"
"app saves instead (Preferences > Events > Keep event history), in\n"
"~/.local/share/stockfw/events or STOCKFW_EVENTS_DIR; it is the\n"
"account's own, so no root is needed, and under sudo it is root's:\n"
"--history-dir DIR reads another folder.\n"
"\n"
"Output:\n"
"  -f, --follow          keep printing new events, in the table's\n"
"                        columns, until Ctrl-C (which prints a count);\n"
"                        with --json one object per line (NDJSON).  If\n"
"                        the event reader stops, it says why and exits 1.\n"
"                        On a terminal a status line under the rows\n"
"                        shows the state, live or pending, HELD\n"
"                        (audit-only), blocked today, Sentinel and the\n"
"                        event source\n"
"  --no-status-line      -f without that line (it is never shown with\n"
"                        --json, --csv, -q, TERM=dumb or in a pipe)\n"
"  --wide                full time with year and zone, plus the IN and\n"
"                        OUT devices, LEN and TOS\n"
"  --utc                 times as ISO-8601 UTC (2026-11-03T09:04:37Z)\n"
"  --csv                 CSV with a header row, as the desktop app\n"
"                        exports it (formulas are made harmless)\n"
"  -n N, --limit N       how many (--summary counts every event)\n"
"  --summary             counts per source and per port, and a bar per\n"
"                        hour, over --since (default: the last 24 h)\n"
"  --by KEY              what the summary counts by: src, dst, port,\n"
"                        service, dir, rule or hour (default src,port)\n"
"  --top N               rows per summary table (default 10)\n"
"  --stats               how many events were read, how many each filter\n"
"                        hid, inbound and outbound, blocked and allowed;\n"
"                        then the saved history: its size, its folder\n"
"                        and, when it is not being written, why\n"
"\n"
"The two filters of Preferences > Events run first, on the events as\n"
"they come, as the Events page runs them (stderr says how many each hid):\n"
"  --collapse-repeats    hide an event with the same port, protocol,\n"
"                        source and destination as the one before it\n"
"  --for-me              hide inbound events to addresses that are not\n"
"                        this computer's (broadcast, multicast, others)\n"
"  --prefs-filters       both as the preferences set them (\"Hide\n"
"                        repeated events\", \"Skip events not addressed\n"
"                        to this computer\"); under sudo, root's\n"
"\n"
"--clear-history deletes the saved history (the folder of --history, or\n"
"--history-dir).  It first shows what is there and why it is not being\n"
"written, then asks \"[y/N]\" on a terminal; --yes skips the question,\n"
"and without a terminal --yes is needed.  While another copy of StockFW\n"
"is writing the folder, nothing is deleted (exit 1).\n"
"\n"
"Filters, all of which must match (the Events page has the same):\n"
"  --since T, --until T  a time: 15m, 2h, 3d, 1w, now, 2026-11-01,\n"
"                        \"2026-11-01 14:30\", or ISO with Z; --until\n"
"                        with a date takes in that whole day\n"
"  --grep TEXT           a column of the Events list contains TEXT\n"
"                        (any case): the time, direction, devices,\n"
"                        port, addresses, length, ToS, protocol or\n"
"                        service, or the list that blocked it\n"
"  --dir in|out|both     the direction (also inbound, outbound;\n"
"                        --direction is the same)\n"
"  --proto P             tcp, udp, icmp or icmpv6\n"
"  --port P              443, 1000-2000, 1000:2000, or a list such as\n"
"                        22,443,8000:8100 (any of them)\n"
"  --addr A              source or destination in A: an address, a\n"
"                        CIDR block (10.0.0.0/8, fd00::/8) or a-b\n"
"  --blocked, --allowed  the verdict (one of them)\n"
"\n"
"The RULE column names the threat-intel list that blocked an event.\n"
"\n"
"Examples:\n"
"  stockfw events --history --since 1d --port 22,3389 --dir in\n"
"  stockfw events --summary --since 7d --by src --top 5\n"
"  stockfw events --history -n 1000 --addr 203.0.113.0/24 --csv\n"
"  stockfw events -f --prefs-filters\n"
"  stockfw events --stats --history --since 1d --collapse-repeats\n",
	  events_opts, NULL },

	{ "connections", fs_cli_cmd_connections,
"Usage: stockfw connections [--json] [--udp] [--by remote|program|port]\n"
"                           [--addr A] [--port P] [--program NAME]\n"
"                           [--dir in|out] [--state STATE] [--no-local]\n"
"\n"
"Connected TCP sockets (IPv4 and IPv6) with both ends, the service, the\n"
"direction, the TCP state and the owning program.  Another user's\n"
"program shows as \"?\" unless run as root.\n"
"\n"
"  --udp           connected UDP sockets too\n"
"  --addr A        either end in A (an address, CIDR block or a-b)\n"
"  --port P        either end's port in P (22, 1000-2000, 22,443)\n"
"  --program NAME  the program's name contains NAME\n"
"  --dir in|out    accepted here, or opened from here\n"
"  --state STATE   ESTABLISHED, SYN_SENT, CLOSE_WAIT...\n"
"  --no-local      leave out connections within this computer\n"
"  --by KEY        one row per remote address, program or port, with\n"
"                  a COUNT\n",
	  connections_opts, NULL },

	{ "listening", fs_cli_cmd_listening,
"Usage: stockfw listening [--tcp|--udp] [--all] [--json]\n"
"\n"
"Every listening TCP socket and bound UDP socket, the program behind it,\n"
"and whether the policy lets a LAN address and an internet address reach\n"
"it (asked of the What-If engine, with the rule that decides).  The\n"
"policy is the applied one when the apply journal can be read, else the\n"
"saved one; the first line says which, and the two addresses asked\n"
"(STOCKFW_LAN_PREFIX sets the LAN).  A rule limited to other addresses\n"
"can still let them in.  Sockets only this computer can reach\n"
"(127.0.0.1, ::1) are counted, and shown with --all.  With -q, only the\n"
"ports the internet can reach.  The program needs root for other users'\n"
"sockets.  The exit status is 0.\n",
	  listening_opts, NULL },

	{ "interfaces", fs_cli_cmd_interfaces,
"Usage: stockfw interfaces [--watch[=SECS]] [-c COUNT] [--all]\n"
"                          [--no-virtual] [--json]\n"
"\n"
"Network adapters that are up, with their type, address, total traffic\n"
"and the current rate (measured over one second).  --all shows the\n"
"adapters that are down too.  --no-virtual leaves out virtual ones\n"
"(bridges, veth and tun devices, Docker's, tunnels), as the Overview\n"
"does until \"Show them\", and says on stderr how many.  --watch refreshes every SECS seconds\n"
"(default 2) until Ctrl-C; -c COUNT stops after that many frames.  With\n"
"--json and --watch, each frame is one line (NDJSON).  Alias: stockfw net\n",
	  interfaces_opts, "net" },

	{ NULL, NULL, NULL, NULL, NULL }
};
