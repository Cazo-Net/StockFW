/*---[ fs-cli-events.c ]----------------------------------------------------
 * `stockfw events', `connections' and `interfaces'.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "core/fs-apply.h"
#include "core/fs-audit.h"
#include "core/fs-autoblock.h"
#include "core/fs-prefs.h"
#include "core/fs-toolpath.h"
#include "core/fs-copilot.h"
#include "core/fs-eventlog.h"
#include "core/fs-eventstore.h"
#include "core/fs-intel.h"
#include "core/fs-health.h"
#include "core/fs-service.h"
#include "core/fs-json.h"
#include "core/fs-netparse.h"
#include "core/fs-script.h"
#include "core/fs-util.h"

#include <glib-unix.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


/* -------------------------------------------------------------- events */

typedef struct
{
	FsEventQuery *query;     /* NULL: every event */
	guint         printed;
} EventsState;

/* [ hit_passes ]
 * The filters of `stockfw events', the same query the Events page
 * runs.  A kernel-log stamp that cannot be read has no time, so it
 * fails a --since or --until. */
static gboolean
hit_passes (const FsEventQuery *query, const FsHit *hit)
{
	gint64 ticks = 0;

	if (query == NULL)
		return TRUE;
	if (fs_event_time_parse (hit->time, &ticks) == FS_EVENT_TIME_OTHER)
		ticks = 0;
	return fs_eventquery_match_hit (query, hit, ticks / 10);
}

static void
print_hit (const FsHit *hit, EventsState *st)
{
	if (!hit_passes (st->query, hit))
		return;

	if (fs_cli.json) {
		GString *out = g_string_new (NULL);

		fs_cli_hit_row_json (out, hit);
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		/* Live lines cannot be sized to the widest row that has not
		 * arrived yet: IPv4-wide columns, longer values push on. */
		gchar **row = fs_cli_hit_row (hit);
		gboolean blocked = fs_hit_is_blocked (hit);

		printf ("%s%s%s  %s%-7s%s  %-3s  %-15s %s %-15s  %-5s  %s/%s%s%s\n",
		        fs_cli_dim (), row[0], fs_cli_reset (),
		        blocked ? fs_cli_red () : fs_cli_green (), row[1],
		        fs_cli_reset (), row[2], row[3],
		        fs_cli_sym (FS_CLI_SYM_ARROW), row[4], row[5], row[6],
		        row[7], strcmp (row[8], "-") != 0 ? "  " : "",
		        strcmp (row[8], "-") != 0 ? row[8] : "");
		g_strfreev (row);
	}

	fflush (stdout);
	st->printed++;
}

static void
on_live_hit (const FsHit *hit, gpointer data)
{
	print_hit (hit, data);
}

static gboolean
on_sigint (gpointer data)
{
	g_main_loop_quit (data);
	return G_SOURCE_REMOVE;
}

/* The newest `want' matching events of the saved history, oldest
 * first.  The hit's strings are only lent for the call: kept ones are
 * copied. */
typedef struct
{
	const FsEventQuery *query;
	GQueue              kept;
	guint               want;
	guint               matched;
} HistoryScan;

static void
on_history_hit (const FsHit *hit, gint64 ticks, gpointer data)
{
	HistoryScan *scan = data;

	if (scan->query != NULL &&
	    !fs_eventquery_match_hit (scan->query, hit, ticks / 10))
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
                    const FsEventQuery *query, guint want,
                    FsEventLogStats *stats)
{
	HistoryScan scan = { query, G_QUEUE_INIT, want, 0 };
	GPtrArray *hits = g_ptr_array_new_with_free_func (
		(GDestroyNotify) fs_hit_free);

	fs_eventlog_foreach (dir, filter->since_us, filter->until_us,
	                     on_history_hit, &scan, stats);
	while (scan.kept.length > 0)
		g_ptr_array_add (hits, g_queue_pop_head (&scan.kept));
	return hits;
}

gint
fs_cli_cmd_events (gint argc, gchar **argv)
{
	guint count = 20;
	gboolean follow = FALSE, saved = FALSE;
	const gchar *since = NULL, *until = NULL, *dir_opt = NULL;
	FsEventFilter filter = { 0 };
	EventsState st = { NULL, 0 };
	FsEventLogStats stats = { 0 };
	GPtrArray *history = NULL;
	gchar *dir = NULL;
	GError *error = NULL;
	gint rc = FS_EXIT_OK;

	for (gint i = 1; i < argc; i++) {
		const gchar *v = NULL;
		gint bad = FS_EXIT_OK;

		if (fs_cli_take_opt (argc, argv, &i, "-n", &v, &bad) ||
		    fs_cli_take_opt (argc, argv, &i, "--lines", &v, &bad)) {
			gchar *end = NULL;
			guint64 n;

			if (v == NULL)
				return bad;
			n = g_ascii_strtoull (v, &end, 10);
			if (!g_ascii_isdigit (*v) || end == NULL || *end != '\0' ||
			    n > FS_EVENTSTORE_MAX_CAPACITY) {
				fs_cli_error ("-n wants a number up to %u",
				              FS_EVENTSTORE_MAX_CAPACITY);
				return FS_EXIT_USAGE;
			}
			count = (guint) n;
		} else if (fs_cli_take_opt (argc, argv, &i, "--since", &v, &bad)) {
			since = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--until", &v, &bad)) {
			until = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--grep", &v, &bad)) {
			filter.text = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--proto", &v, &bad)) {
			filter.protocol = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--port", &v, &bad)) {
			filter.port = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--addr", &v, &bad)) {
			filter.address = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--history-dir", &v,
		                            &bad)) {
			dir_opt = v;
			saved = TRUE;
		} else if (fs_cli_take_opt (argc, argv, &i, "--dir", &v, &bad)) {
			if (v == NULL)
				;
			else if (g_ascii_strcasecmp (v, "in") == 0)
				filter.direction = FS_EVQ_DIR_IN;
			else if (g_ascii_strcasecmp (v, "out") == 0)
				filter.direction = FS_EVQ_DIR_OUT;
			else {
				fs_cli_error ("--dir wants in or out, not `%s'", v);
				return FS_EXIT_USAGE;
			}
		} else if (!fs_cli_is_option_at (argv, i)) {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			return FS_EXIT_USAGE;
		} else if (strcmp (argv[i], "-f") == 0 ||
		           strcmp (argv[i], "--follow") == 0) {
			follow = TRUE;
		} else if (strcmp (argv[i], "--history") == 0) {
			saved = TRUE;
		} else if (strcmp (argv[i], "--blocked") == 0) {
			filter.action = FS_EVQ_ACTION_BLOCKED;
		} else if (strcmp (argv[i], "--allowed") == 0) {
			filter.action = FS_EVQ_ACTION_ALLOWED;
		} else {
			fs_cli_unknown_option ("events", argv[i]);
			return FS_EXIT_USAGE;
		}
		/* A value option with no value: the error is printed. */
		if (bad != FS_EXIT_OK)
			return bad;
	}

	if (!fs_cli_parse_window (since, until, &filter.since_us,
	                          &filter.until_us))
		return FS_EXIT_USAGE;
	st.query = fs_eventquery_new (&filter, &error);
	if (st.query == NULL) {
		fs_cli_error ("%s", error->message);
		g_error_free (error);
		return FS_EXIT_USAGE;
	}
	if (fs_eventquery_is_empty (st.query))
		g_clear_pointer (&st.query, fs_eventquery_free);

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
		history = read_saved_history (dir, &filter, st.query, count,
		                              &stats);
	} else if (count > 0) {
		/* With a filter, look further back so N matches can be
		 * found, then keep the newest N of them. */
		history = fs_cli_log_history (st.query != NULL
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
		if (st.query != NULL) {
			GPtrArray *kept = g_ptr_array_new_with_free_func (
				(GDestroyNotify) fs_hit_free);

			for (guint i = 0; i < history->len; i++) {
				FsHit *hit = g_ptr_array_index (history, i);

				if (hit_passes (st.query, hit)) {
					g_ptr_array_index (history, i) = NULL;
					g_ptr_array_add (kept, hit);
				}
			}
			g_ptr_array_unref (history);
			history = kept;
		}
		while (history->len > count)
			g_ptr_array_remove_index (history, 0);
	}

	if (history != NULL && count > 0) {
		if (fs_cli.json && !follow) {
			GString *out = g_string_new ("[");

			for (guint i = 0; i < history->len; i++) {
				if (out->len > 1)
					g_string_append_c (out, ',');
				fs_cli_hit_row_json (out, g_ptr_array_index (history, i));
			}
			g_string_append_c (out, ']');
			fs_cli_print_json (out);
			g_string_free (out, TRUE);
		} else if (fs_cli.json) {
			/* --follow --json: the history as NDJSON too. */
			for (guint i = 0; i < history->len; i++)
				print_hit (g_ptr_array_index (history, i), &st);
		} else {
			static const gchar *headers[] = {
				"TIME", "VERDICT", "DIR", "SOURCE", "DESTINATION",
				"PORT", "SERVICE", "PROTO", "RULE"
			};
			GPtrArray *rows = g_ptr_array_new_with_free_func (
				(GDestroyNotify) g_strfreev);

			for (guint i = 0; i < history->len; i++)
				g_ptr_array_add (rows,
				                 fs_cli_hit_row (g_ptr_array_index (history,
				                                             i)));

			st.printed = rows->len;
			if (rows->len > 0)
				fs_cli_table (headers, 9, rows, 40);
			g_ptr_array_unref (rows);

			if (st.printed == 0 && !fs_cli.quiet)
				printf ("%s%s%s\n", fs_cli_dim (),
				        saved ? "No saved events match."
				        : st.query != NULL
				        ? "No StockFW events in the kernel log match."
				        : "No StockFW events in the kernel log yet.",
				        fs_cli_reset ());
		}
	}
	if (saved && stats.bad_lines > 0 && !fs_cli.quiet && !fs_cli.json)
		fprintf (stderr, "%s%u damaged or cut-short line(s) in the "
		         "history were skipped.%s\n", fs_cli_dim (),
		         stats.bad_lines, fs_cli_reset ());

	if (follow) {
		const FsBackend *backend = fs_backend ();
		GMainLoop *loop;

		if (backend->log_start == NULL ||
		    !backend->log_start (on_live_hit, &st, &error)) {
			fs_cli_error ("cannot follow events: %s",
			              error ? error->message : "no event source");
			g_clear_error (&error);
			rc = geteuid () != 0 ? FS_EXIT_NEED_ROOT : FS_EXIT_FAILURE;
			goto out;
		}

		if (!fs_cli.json && !fs_cli.quiet)
			fprintf (stderr, "%sFollowing new events -- Ctrl-C to stop.%s\n",
			         fs_cli_dim (), fs_cli_reset ());

		loop = g_main_loop_new (NULL, FALSE);
		g_unix_signal_add (SIGINT, on_sigint, loop);
		g_unix_signal_add (SIGTERM, on_sigint, loop);
		g_main_loop_run (loop);
		g_main_loop_unref (loop);

		backend->log_stop ();
	}

out:
	if (history != NULL)
		g_ptr_array_unref (history);
	if (st.query != NULL)
		fs_eventquery_free (st.query);
	g_free (dir);
	return rc;
}

/* --------------------------------------------------------- connections */

gint
fs_cli_cmd_connections (gint argc, gchar **argv)
{
	const FsBackend *backend = fs_backend ();
	GList *conns;

	if (argc > 1) {
		fs_cli_error ("connections takes no arguments");
		return FS_EXIT_USAGE;
	}

	if (backend->list_connections == NULL) {
		fs_cli_error ("this backend cannot list connections");
		return FS_EXIT_FAILURE;
	}

	conns = backend->list_connections ();

	if (fs_cli.json) {
		GString *out = g_string_new ("[");

		for (GList *l = conns; l != NULL; l = l->next) {
			FsConnection *c = l->data;

			if (l != conns)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "local", c->source);          g_string_append_c (out, ',');
			fs_json_kv_str (out, "remote", c->destination);    g_string_append_c (out, ',');
			fs_json_kv_str (out, "port", c->port);             g_string_append_c (out, ',');
			fs_json_kv_str (out, "protocol", c->protocol);     g_string_append_c (out, ',');
			fs_json_kv_str (out, "service", c->service);       g_string_append_c (out, ',');
			fs_json_kv_str (out, "program", c->program);       g_string_append_c (out, ',');
			fs_json_kv_str (out, "direction", c->direction);
			g_string_append_c (out, '}');
		}
		g_string_append_c (out, ']');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (conns == NULL) {
		if (!fs_cli.quiet)
			printf ("No active TCP connections.\n");
	} else {
		static const gchar *headers[] = {
			"LOCAL", "REMOTE", "PORT", "SERVICE", "DIRECTION", "PROGRAM"
		};
		GPtrArray *rows = g_ptr_array_new_with_free_func (g_free);
		gboolean unknown_owner = FALSE;

		for (GList *l = conns; l != NULL; l = l->next) {
			FsConnection *c = l->data;
			gchar **row = g_new0 (gchar *, 7);

			row[0] = c->source;
			row[1] = c->destination;
			row[2] = c->port;
			row[3] = c->service;
			row[4] = c->direction;
			row[5] = c->program;
			g_ptr_array_add (rows, row);

			if (g_strcmp0 (c->program, "?") == 0)
				unknown_owner = TRUE;
		}

		fs_cli_table (headers, 6, rows, 40);
		g_ptr_array_unref (rows);

		if (unknown_owner && geteuid () != 0 && !fs_cli.quiet)
			printf ("%s\"?\" is another user's program; root can see "
			        "every owner.%s\n", fs_cli_dim (), fs_cli_reset ());
	}

	g_list_free_full (conns, (GDestroyNotify) fs_connection_free);
	return FS_EXIT_OK;
}

/* ---------------------------------------------------------- interfaces */

static void
print_interfaces (GList *now, GList *before, gdouble seconds)
{
	if (fs_cli.json) {
		GString *out = g_string_new ("[");

		for (GList *l = now; l != NULL; l = l->next) {
			FsIfaceStat *s = l->data;
			gdouble rx = 0, tx = 0;

			for (GList *b = before; b != NULL; b = b->next) {
				FsIfaceStat *p = b->data;

				if (g_strcmp0 (p->device, s->device) == 0 &&
				    s->received >= p->received && s->sent >= p->sent) {
					rx = (gdouble) (s->received - p->received) / seconds;
					tx = (gdouble) (s->sent - p->sent) / seconds;
				}
			}

			if (l != now)
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

		for (GList *l = now; l != NULL; l = l->next) {
			FsIfaceStat *s = l->data;
			gchar **row = g_new0 (gchar *, 8);
			gdouble rx = 0, tx = 0;

			for (GList *b = before; b != NULL; b = b->next) {
				FsIfaceStat *p = b->data;

				if (g_strcmp0 (p->device, s->device) == 0 &&
				    s->received >= p->received && s->sent >= p->sent) {
					rx = (gdouble) (s->received - p->received) / seconds;
					tx = (gdouble) (s->sent - p->sent) / seconds;
				}
			}

			row[0] = g_strconcat (s->device, s->up ? "" : " (down)", NULL);
			row[1] = g_strdup (s->kind ? s->kind : "-");
			row[2] = g_strdup (s->ip ? s->ip : "-");
			row[3] = fs_cli_format_bytes (s->received);
			row[4] = fs_cli_format_bytes (s->sent);
			row[5] = fs_cli_format_rate (rx);
			row[6] = fs_cli_format_rate (tx);
			g_ptr_array_add (rows, row);
		}

		if (rows->len == 0)
			printf ("No network adapters with traffic counters.\n");
		else
			fs_cli_table (headers, 7, rows, 32);
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

gint
fs_cli_cmd_interfaces (gint argc, gchar **argv)
{
	const FsBackend *backend = fs_backend ();
	gboolean watch = FALSE;
	GList *before, *now;

	for (gint i = 1; i < argc; i++) {
		if (fs_cli_is_option_at (argv, i) &&
		    (strcmp (argv[i], "--watch") == 0 ||
		     strcmp (argv[i], "-w") == 0)) {
			watch = TRUE;
		} else if (fs_cli_is_option_at (argv, i)) {
			fs_cli_unknown_option ("interfaces", argv[i]);
			return FS_EXIT_USAGE;
		} else {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			return FS_EXIT_USAGE;
		}
	}

	if (backend->list_interface_stats == NULL) {
		fs_cli_error ("this backend has no traffic counters");
		return FS_EXIT_FAILURE;
	}

	before = backend->list_interface_stats ();
	g_usleep (G_USEC_PER_SEC);
	now = backend->list_interface_stats ();

	if (!watch) {
		print_interfaces (now, before, 1.0);
	} else {
		g_unix_signal_add (SIGINT, on_watch_signal, NULL);

		while (!watch_stop) {
			if (!fs_cli.json && fs_cli.color)
				printf ("\033[H\033[2J");
			print_interfaces (now, before, 2.0);
			if (!fs_cli.json)
				printf ("%sRefreshing every 2 s -- Ctrl-C to stop.%s\n",
				        fs_cli_dim (), fs_cli_reset ());
			fflush (stdout);

			g_list_free_full (before, (GDestroyNotify) fs_iface_stat_free);
			before = now;

			for (gint t = 0; t < 20 && !watch_stop; t++) {
				g_usleep (G_USEC_PER_SEC / 10);
				while (g_main_context_iteration (NULL, FALSE))
					;
			}
			now = backend->list_interface_stats ();
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
	{ "--since",       TRUE,  NULL },
	{ "--until",       TRUE,  NULL },
	{ "--grep",        TRUE,  NULL },
	{ "--proto",       TRUE,  NULL },
	{ "--port",        TRUE,  NULL },
	{ "--addr",        TRUE,  NULL },
	{ "--history-dir", TRUE,  NULL },
	{ "--dir",         TRUE,  NULL },
	{ "-f",            FALSE, NULL },
	{ "--follow",      FALSE, NULL },
	{ "--history",     FALSE, NULL },
	{ "--blocked",     FALSE, NULL },
	{ "--allowed",     FALSE, NULL },
	{ NULL, FALSE, NULL }
};

static const FsCliOption connections_opts[] = {
	{ NULL, FALSE, NULL }
};

static const FsCliOption interfaces_opts[] = {
	{ "--watch", FALSE, NULL },
	{ "-w",      FALSE, NULL },
	{ NULL, FALSE, NULL }
};

const FsCliCommandDef fs_cli_events_commands[] = {
	{ "events", fs_cli_cmd_events,
"Usage: stockfw events [-n N] [-f|--follow] [--history] [--json]\n"
"                      [--since T] [--until T] [--grep TEXT]\n"
"                      [--dir in|out] [--proto P] [--port P]\n"
"                      [--addr A] [--blocked|--allowed]\n"
"\n"
"The last N (default 20, up to 1000000) events, oldest first.  By\n"
"default they are read from the kernel log, which usually needs root\n"
"(or the adm group).  --history reads the history the desktop app\n"
"saves instead (Preferences > Events > Keep event history), in\n"
"~/.local/share/stockfw/events or STOCKFW_EVENTS_DIR; it is the\n"
"account's own, so no root is needed, and under sudo it is root's:\n"
"--history-dir DIR reads another folder.  -f keeps following new\n"
"events until Ctrl-C (with --json, one object per line).\n"
"\n"
"Filters, all of which must match (the Events page has the same):\n"
"  --since T, --until T  a time: 15m, 2h, 3d, 1w, now, 2026-11-01,\n"
"                        \"2026-11-01 14:30\", or ISO with Z; --until\n"
"                        with a date takes in that whole day\n"
"  --grep TEXT           a column of the Events list contains TEXT\n"
"                        (any case): the time, direction, devices,\n"
"                        port, addresses, length, ToS, protocol or\n"
"                        service, or the list that blocked it\n"
"  --dir in|out          the direction\n"
"  --proto P             TCP, UDP, ICMP...\n"
"  --port P              443, 1000-2000 or 1000:2000\n"
"  --addr A              source or destination in A: an address, a\n"
"                        CIDR block (10.0.0.0/8, fd00::/8) or a-b\n"
"  --blocked, --allowed  the verdict\n"
"\n"
"Examples:\n"
"  stockfw events --history --since 1d --port 22 --dir in\n"
"  stockfw events --history -n 1000 --addr 203.0.113.0/24 --json\n",
	  events_opts, NULL },

	{ "connections", fs_cli_cmd_connections,
"Usage: stockfw connections [--json]\n"
"\n"
"Connected TCP sockets (IPv4 and IPv6) with the remote service, the\n"
"direction and the owning program.  Another user's program shows as\n"
"\"?\" unless run as root.\n",
	  connections_opts, NULL },

	{ "interfaces", fs_cli_cmd_interfaces,
"Usage: stockfw interfaces [--watch] [--json]\n"
"\n"
"Network adapters with their type, address, total traffic and the\n"
"current rate (measured over one second).  --watch refreshes every two\n"
"seconds until Ctrl-C.  Alias: stockfw net\n",
	  interfaces_opts, "net" },

	{ NULL, NULL, NULL, NULL, NULL }
};
