/*---[ fs-cli-activity.c ]------------------------------------------------
 * `stockfw activity': the desktop app's Activity page in a terminal
 * (D1-D7).
 *
 * There is no resident process yet to keep the series (the daemon of
 * PR 7 will), so the command rebuilds them each time, the way the
 * dashboard does: from the saved event history while it is kept, else
 * from the kernel log.  Each event is counted into a fresh FsActivity
 * (core/fs-activity.c) at its own time, and the series is read back
 * with fs_activity_window, so a point the source could not have seen
 * is "no data", never a zero that reads as an idle firewall.  Then:
 *
 *   - a sparkline per series (blocked, and allowed when the firewall
 *     logs allowed traffic), the range on one line;
 *   - the tiles: blocked in the last hour and in 24 h with "counting
 *     since", allowed likewise, and the throughput now (one second of
 *     samples, all adapters or --device);
 *   - --table: one row per point (D3);
 *   - notes on stderr: where the counts come from, and that the Linux
 *     kernel log carries only dropped packets unless "Log allowed" is
 *     on (D7).
 *
 * Every text from outside (paths, device names) goes through
 * fs_cli_out_safe.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "core/fs-activity.h"
#include "core/fs-eventlog.h"
#include "core/fs-eventstore.h"
#include "core/fs-json.h"
#include "core/fs-netparse.h"
#include "core/fs-prefs.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* The Activity page's ranges (D1). */
static const struct { const gchar *name; guint seconds; const gchar *words; }
ranges[] = {
	{ "15m", 15 * 60,      "last 15 minutes" },
	{ "1h",  60 * 60,      "last hour" },
	{ "6h",  6 * 60 * 60,  "last 6 hours" },
	{ "24h", 24 * 60 * 60, "last 24 hours" },
};

/* At most this many points; fewer when the terminal is narrower. */
#define ACTIVITY_MAX_POINTS 60
/* The label column: "  Blocked  ". */
#define ACTIVITY_LABEL      11

typedef struct
{
	gint64   epoch;
	gboolean blocked;
} Count;

typedef struct
{
	GArray *counts;     /* Count, in the order read */
	gint64  since;      /* nothing older is read    */
} Backfill;

static void
take (Backfill *b, const FsHit *hit, gint64 epoch)
{
	Count c;

	if (epoch < b->since)
		return;
	c.epoch = epoch;
	c.blocked = fs_hit_is_blocked (hit);
	g_array_append_val (b->counts, c);
}

static void
on_history_hit (const FsHit *hit, gint64 ticks, gpointer data)
{
	take (data, hit, ticks / 10000000);
}

/* [ spark ] -- one point as a bar: "·" no data, "▁" zero, then up to
 * "█" at the series' largest point (ASCII: " ", "_" ... "#"). */
static const gchar *
spark (guint64 value, guint covered, guint64 max)
{
	static const gchar *const bars[] = {
		"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"
	};
	static const gchar *const ascii[] = {
		"_", ".", ":", "-", "=", "+", "*", "#"
	};
	gboolean utf8 = g_get_charset (NULL);
	guint level;

	if (covered == 0)
		return utf8 ? "·" : " ";
	if (value == 0 || max == 0)
		return utf8 ? bars[0] : ascii[0];
	/* Any count shows above zero: 1..7. */
	level = 1 + (guint) ((value - 1) * 6 / MAX (max - 1, 1));
	if (level > 7)
		level = 7;
	return utf8 ? bars[level] : ascii[level];
}

static gchar *
clock_text (gint64 epoch)
{
	return fs_cli_time_text (epoch, fs_cli.utc ? FS_CLI_TIME_ISO
	                                           : FS_CLI_TIME_SHORT);
}

static gchar *
count_words (guint64 n)
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

/* [ total_words ] -- a total, or "unknown" when the record ends before
 * now (stop >= 0): a history nobody writes has no count to now. */
static gchar *
total_words (gint64 stop, guint64 n)
{
	return stop >= 0 ? g_strdup ("unknown") : count_words (n);
}

/* [ throughput ]
 * Bytes per second now, received and sent, over one second: every
 * adapter that is up, or only `device'.  FALSE when the backend has no
 * counters, or the device is not there (*found FALSE). */
static gboolean
throughput (const gchar *device, gdouble *rx, gdouble *tx, gboolean *found)
{
	const FsBackend *backend = fs_backend ();
	GList *before, *now;
	gint64 t0, t1;
	gdouble seconds;

	*rx = *tx = 0;
	*found = device == NULL;
	if (backend->list_interface_stats == NULL)
		return FALSE;

	t0 = g_get_monotonic_time ();
	before = backend->list_interface_stats ();
	g_usleep (G_USEC_PER_SEC);
	now = backend->list_interface_stats ();
	t1 = g_get_monotonic_time ();
	seconds = (gdouble) (t1 - t0) / G_USEC_PER_SEC;

	for (GList *l = now; l != NULL; l = l->next) {
		FsIfaceStat *s = l->data;

		if (device != NULL && g_strcmp0 (s->device, device) != 0)
			continue;
		if (device == NULL && !s->up)
			continue;
		*found = TRUE;
		for (GList *b = before; b != NULL; b = b->next) {
			FsIfaceStat *p = b->data;

			if (g_strcmp0 (p->device, s->device) == 0 &&
			    s->received >= p->received && s->sent >= p->sent &&
			    seconds > 0) {
				*rx += (gdouble) (s->received - p->received) / seconds;
				*tx += (gdouble) (s->sent - p->sent) / seconds;
			}
		}
	}
	g_list_free_full (before, (GDestroyNotify) fs_iface_stat_free);
	g_list_free_full (now, (GDestroyNotify) fs_iface_stat_free);
	return *found;
}

/* [ device_names ] -- the adapters with counters, for "did you mean". */
static GPtrArray *
device_names (void)
{
	const FsBackend *backend = fs_backend ();
	GPtrArray *names = g_ptr_array_new_with_free_func (g_free);
	GList *stats = backend->list_interface_stats != NULL
	               ? backend->list_interface_stats () : NULL;

	for (GList *l = stats; l != NULL; l = l->next)
		g_ptr_array_add (names, g_strdup (((FsIfaceStat *) l->data)->device));
	g_list_free_full (stats, (GDestroyNotify) fs_iface_stat_free);
	return names;
}

static void
series_json (GString *out, const gchar *key, const guint64 *values,
             const guint *covered, guint n)
{
	fs_json_key (out, key);
	g_string_append_c (out, '[');
	for (guint i = 0; i < n; i++) {
		if (i > 0)
			g_string_append_c (out, ',');
		if (covered[i] == 0)
			g_string_append (out, "null");
		else
			g_string_append_printf (out, "%" G_GUINT64_FORMAT, values[i]);
	}
	g_string_append_c (out, ']');
}

static void
print_spark (const gchar *label, const guint64 *values, const guint *covered,
             guint n, const gchar *color)
{
	guint64 max = 0;
	GString *line = g_string_new (NULL);

	for (guint i = 0; i < n; i++)
		if (covered[i] > 0 && values[i] > max)
			max = values[i];
	for (guint i = 0; i < n; i++)
		g_string_append (line, spark (values[i], covered[i], max));
	printf ("  %-*s%s%s%s", ACTIVITY_LABEL - 2, label, color, line->str,
	        fs_cli_reset ());
	if (max > 0)
		printf ("%s  max %" G_GUINT64_FORMAT "%s", fs_cli_dim (), max,
		        fs_cli_reset ());
	printf ("\n");
	g_string_free (line, TRUE);
}

gint
fs_cli_cmd_activity (gint argc, gchar **argv)
{
	const gchar *range_opt = "1h", *device = NULL, *dir_opt = NULL;
	gboolean table = FALSE, saved = FALSE, no_rate = FALSE;
	guint range_s = 0, step, n_points, max_points;
	const gchar *range_words = NULL;
	Backfill fill;
	FsActivity *activity = NULL;
	gchar *dir = NULL, *source = NULL;
	const gchar *source_kind;
	gint64 now = g_get_real_time () / G_USEC_PER_SEC;
	gint64 started = 0, start_epoch = 0, complete_from = 0;
	gint64 stop = -1;           /* >= 0: the record ends there */
	guint64 *blocked = NULL, *allowed = NULL;
	guint *covered = NULL, *covered_a = NULL;
	gboolean logs_allowed = fs_prefs_bool (FS_PREFS_FW_LOG_ALLOWED);
	gboolean have_rate = FALSE, found = TRUE;
	gdouble rx = 0, tx = 0;
	GPtrArray *notes = g_ptr_array_new_with_free_func (g_free);
	gint rc = FS_EXIT_OK;

	fill.counts = g_array_new (FALSE, FALSE, sizeof (Count));
	fill.since = now - FS_ACTIVITY_SPAN_S;

	for (gint i = 1; i < argc; i++) {
		const gchar *v = NULL;
		gint bad = FS_EXIT_OK;

		if (fs_cli_take_opt (argc, argv, &i, "--range", &v, &bad)) {
			if (v != NULL)
				range_opt = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--device", &v, &bad)) {
			device = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--history-dir", &v,
		                            &bad)) {
			dir_opt = v;
			saved = TRUE;
		} else if (bad != FS_EXIT_OK) {
			/* the value is missing: said already */
		} else if (!fs_cli_is_option_at (argv, i)) {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			bad = FS_EXIT_USAGE;
		} else if (strcmp (argv[i], "--table") == 0) {
			table = TRUE;
		} else if (strcmp (argv[i], "--history") == 0) {
			saved = TRUE;
		} else if (strcmp (argv[i], "--no-rate") == 0) {
			no_rate = TRUE;
		} else if (strcmp (argv[i], "--utc") == 0) {
			fs_cli.utc = TRUE;
		} else {
			fs_cli_unknown_option ("activity", argv[i]);
			bad = FS_EXIT_USAGE;
		}
		if (bad != FS_EXIT_OK) {
			rc = bad;
			goto out;
		}
	}

	for (guint r = 0; r < G_N_ELEMENTS (ranges); r++)
		if (g_ascii_strcasecmp (range_opt, ranges[r].name) == 0) {
			range_s = ranges[r].seconds;
			range_words = ranges[r].words;
		}
	if (range_s == 0) {
		const gchar *names[G_N_ELEMENTS (ranges)];
		const gchar *near;

		for (guint r = 0; r < G_N_ELEMENTS (ranges); r++)
			names[r] = ranges[r].name;
		near = fs_cli_suggest (range_opt, names, G_N_ELEMENTS (ranges));
		if (near != NULL)
			fs_cli_error ("--range wants 15m, 1h, 6h or 24h, not `%s' (did "
			              "you mean %s?)", range_opt, near);
		else
			fs_cli_error ("--range wants 15m, 1h, 6h or 24h, not `%s'",
			              range_opt);
		rc = FS_EXIT_USAGE;
		goto out;
	}

	/* D2: the adapter is checked before anything is read. */
	if (device != NULL && !no_rate) {
		GPtrArray *names = device_names ();
		gboolean known = FALSE;

		for (guint i = 0; i < names->len; i++)
			known |= g_strcmp0 (names->pdata[i], device) == 0;
		if (!known) {
			gchar *safe = fs_cli_out_safe (device);
			const gchar *near = fs_cli_suggest (
				device, (const gchar * const *) names->pdata, names->len);

			if (near != NULL)
				fs_cli_error ("no adapter `%s' (did you mean %s?)", safe,
				              near);
			else
				fs_cli_error ("no adapter `%s'", safe);
			fs_cli_hint ("`stockfw interfaces --all' lists them");
			g_free (safe);
			g_ptr_array_unref (names);
			rc = FS_EXIT_USAGE;
			goto out;
		}
		g_ptr_array_unref (names);
	}

	/* The source: the saved history while it is kept (or asked for),
	 * else the kernel log, as `status' counts blocked today. */
	dir = dir_opt != NULL ? g_strdup (dir_opt) : fs_eventlog_default_dir ();
	if (!saved && g_file_test (dir, G_FILE_TEST_IS_DIR) &&
	    (g_getenv ("STOCKFW_EVENTS_DIR") != NULL ||
	     fs_prefs_bool (FS_PREFS_EVENTS_HISTORY))) {
		/* Kept, but only a running copy writes it: a history nobody
		 * writes ends at its last event, the kernel log does not. */
		saved = fs_cli_history_writer_active (dir);
		if (!saved) {
			gchar *safe = fs_cli_out_safe (dir);

			g_ptr_array_add (notes, g_strdup_printf (
				"The saved history in %s is not being written now (no "
				"copy of StockFW runs to write it): read the kernel log "
				"instead (--history reads the history anyway).", safe));
			g_free (safe);
		}
	}
	if (saved) {
		FsEventLogStats stats = { 0 };

		if (!g_file_test (dir, G_FILE_TEST_IS_DIR)) {
			gchar *safe = fs_cli_out_safe (dir);

			fs_cli_error ("no saved event history in %s", safe);
			g_free (safe);
			rc = FS_EXIT_FAILURE;
			goto out;
		}
		fs_eventlog_foreach (dir, fill.since * G_USEC_PER_SEC, 0,
		                     on_history_hit, &fill, &stats);
		source_kind = "history";
		source = g_strdup (dir);
		/* The history holds what was kept: from its first event in
		 * the last day on, the record is taken as complete. */
		started = now;
		for (guint i = 0; i < fill.counts->len; i++)
			started = MIN (started,
			               g_array_index (fill.counts, Count, i).epoch);
		/* ...up to now only while a copy of StockFW writes it.  Else
		 * the record ends at its last event: after that, no data. */
		if (!fs_cli_history_writer_active (dir)) {
			stop = started;
			for (guint i = 0; i < fill.counts->len; i++)
				stop = MAX (stop,
				            g_array_index (fill.counts, Count, i).epoch);
		}
	} else {
		GError *error = NULL;
		GPtrArray *hits = fs_cli_log_history (FS_EVENTSTORE_MAX_CAPACITY,
		                                      &complete_from, &error);

		if (hits == NULL) {
			fs_cli_error ("%s", error->message);
			g_error_free (error);
			fs_cli_hint ("`stockfw activity --history' counts the history "
			             "the desktop app saved");
			rc = geteuid () != 0 ? FS_EXIT_NEED_ROOT : FS_EXIT_FAILURE;
			goto out;
		}
		for (guint i = 0; i < hits->len; i++) {
			const FsHit *hit = g_ptr_array_index (hits, i);
			gint64 epoch = fs_cli_hit_epoch (hit);

			if (epoch >= 0)
				take (&fill, hit, epoch);
		}
		g_ptr_array_unref (hits);
		source_kind = "kernel_log";
		fs_cli_log_readable (&source, NULL);
		/* From the first stamped line read on, the record is
		 * complete; with none read, nothing is known before now. */
		started = complete_from > 0 ? complete_from : now;
	}

	activity = fs_activity_new_at (NULL, NULL, started);
	started = fs_activity_started (activity);
	for (guint i = 0; i < fill.counts->len; i++) {
		const Count *c = &g_array_index (fill.counts, Count, i);

		fs_activity_add_at (activity, c->blocked ? FS_ACTIVITY_BLOCKED
		                                         : FS_ACTIVITY_ALLOWED,
		                    c->epoch, 1);
	}

	/* The points: as many as fit beside the label, at most 60. */
	max_points = ACTIVITY_MAX_POINTS;
	{
		guint width = fs_cli_term_width ();

		if (width > ACTIVITY_LABEL + 20 &&
		    width - ACTIVITY_LABEL - 12 < max_points)
			max_points = width - ACTIVITY_LABEL - 12;
	}
	step = fs_activity_step_for (range_s, max_points);
	n_points = (range_s + step - 1) / step;
	blocked = g_new0 (guint64, n_points);
	allowed = g_new0 (guint64, n_points);
	covered = g_new0 (guint, n_points);
	covered_a = g_new0 (guint, n_points);
	step = fs_activity_window (activity, FS_ACTIVITY_BLOCKED, step, n_points,
	                           blocked, covered, &start_epoch);
	fs_activity_window (activity, FS_ACTIVITY_ALLOWED, step, n_points,
	                    allowed, covered_a, NULL);
	/* A history nobody writes: nothing is known after `stop', so no
	 * zero there that reads as an idle firewall. */
	if (stop >= 0)
		for (guint i = 0; i < n_points; i++) {
			gint64 from = start_epoch + (gint64) i * step;
			guint upto = from > stop ? 0 : (guint) (stop - from + 1);

			covered[i] = MIN (covered[i], upto);
			covered_a[i] = MIN (covered_a[i], upto);
		}

	if (!no_rate)
		have_rate = throughput (device, &rx, &tx, &found);

	/* D7: the notes. */
	{
		gchar *safe = fs_cli_out_safe (source != NULL ? source
		                               : "the kernel log");
		gchar *since = clock_text (started);

		g_ptr_array_add (notes, g_strdup_printf (
			"Counted from %s%s, every event (the desktop app's display "
			"filters are not applied); counting since %s.",
			saved ? "the saved history in " : "", safe, since));
		g_free (since);
		g_free (safe);
	}
	if (stop >= 0) {
		gchar *last = clock_text (stop);

		g_ptr_array_add (notes, g_strdup_printf (
			"No copy of StockFW is writing this history now: nothing is "
			"known after its last event (%s), so later points show no "
			"data and the totals are not counted.", last));
		g_free (last);
	}
	if (!logs_allowed)
		g_ptr_array_add (notes, g_strdup (
			"On Linux the kernel log carries only the packets StockFW's "
			"rules drop or reject, so this shows blocked traffic; allowed "
			"traffic shows under Network (Log allowed is off)."));

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "range", range_opt);       g_string_append_c (out, ',');
		fs_json_kv_uint (out, "range_s", range_s);      g_string_append_c (out, ',');
		fs_json_kv_uint (out, "step_s", step);          g_string_append_c (out, ',');
		fs_json_kv_uint (out, "points", n_points);      g_string_append_c (out, ',');
		g_string_append_printf (out, "\"start_epoch\":%" G_GINT64_FORMAT ",",
		                        start_epoch);
		g_string_append_printf (out, "\"counting_since\":%" G_GINT64_FORMAT
		                        ",", started);
		fs_json_kv_str (out, "source", source_kind);    g_string_append_c (out, ',');
		fs_json_kv_str (out, "source_path", source);    g_string_append_c (out, ',');
		fs_json_kv_bool (out, "logs_allowed", logs_allowed);
		g_string_append_c (out, ',');
		series_json (out, "blocked", blocked, covered, n_points);
		g_string_append_c (out, ',');
		series_json (out, "allowed", allowed, covered_a, n_points);
		/* A record that ends before now has no total "in the last
		 * hour": null, not a count that leaves the rest out. */
		if (stop >= 0) {
			g_string_append (out, ",\"totals\":{\"blocked_1h\":null,"
			                 "\"blocked_24h\":null,\"allowed_1h\":null,"
			                 "\"allowed_24h\":null");
		} else {
			g_string_append (out, ",\"totals\":{");
			fs_json_kv_uint (out, "blocked_1h",
			                 fs_activity_total (activity, FS_ACTIVITY_BLOCKED,
			                                    3600));
			g_string_append_c (out, ',');
			fs_json_kv_uint (out, "blocked_24h",
			                 fs_activity_total (activity, FS_ACTIVITY_BLOCKED,
			                                    FS_ACTIVITY_SPAN_S));
			g_string_append_c (out, ',');
			fs_json_kv_uint (out, "allowed_1h",
			                 fs_activity_total (activity, FS_ACTIVITY_ALLOWED,
			                                    3600));
			g_string_append_c (out, ',');
			fs_json_kv_uint (out, "allowed_24h",
			                 fs_activity_total (activity, FS_ACTIVITY_ALLOWED,
			                                    FS_ACTIVITY_SPAN_S));
		}
		g_string_append (out, "},\"network\":");
		if (have_rate) {
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "device", device);  g_string_append_c (out, ',');
			g_string_append_printf (out, "\"rx_per_s\":%.0f,\"tx_per_s\":%.0f}",
			                        rx, tx);
		} else {
			g_string_append (out, "null");
		}
		g_string_append (out, ",\"notes\":[");
		for (guint i = 0; i < notes->len; i++) {
			if (i > 0)
				g_string_append_c (out, ',');
			fs_json_string (out, notes->pdata[i]);
		}
		g_string_append (out, "]}");
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (table) {
		static const gchar *headers[] = { "TIME", "BLOCKED", "ALLOWED" };
		GPtrArray *rows = g_ptr_array_new_with_free_func (
			(GDestroyNotify) g_strfreev);

		for (guint i = 0; i < n_points; i++) {
			gchar **row = g_new0 (gchar *, 4);

			row[0] = clock_text (start_epoch + (gint64) i * step);
			row[1] = covered[i] == 0 ? g_strdup ("-")
			         : g_strdup_printf ("%" G_GUINT64_FORMAT, blocked[i]);
			row[2] = covered_a[i] == 0 || !logs_allowed ? g_strdup ("-")
			         : g_strdup_printf ("%" G_GUINT64_FORMAT, allowed[i]);
			g_ptr_array_add (rows, row);
		}
		fs_cli_table (headers, 3, rows, 0);
		g_ptr_array_unref (rows);
	} else {
		gchar *from = clock_text (start_epoch);
		gchar *b1 = total_words (stop, fs_activity_total (activity,
		                                            FS_ACTIVITY_BLOCKED, 3600));
		gchar *b24 = total_words (stop, fs_activity_total (activity,
		                                             FS_ACTIVITY_BLOCKED,
		                                             FS_ACTIVITY_SPAN_S));
		gchar *since = clock_text (started);
		gchar *per = step < 60 ? g_strdup_printf ("%u s", step)
		             : g_strdup_printf ("%u min", step / 60);

		printf ("%sActivity%s  %s %s%s %s per point%s\n", fs_cli_bold (),
		        fs_cli_reset (), range_words, fs_cli_sym (FS_CLI_SYM_SEP),
		        fs_cli_dim (), per, fs_cli_reset ());
		print_spark ("Blocked", blocked, covered, n_points, fs_cli_red ());
		if (logs_allowed)
			print_spark ("Allowed", allowed, covered_a, n_points,
			             fs_cli_green ());
		printf ("  %-*s%s%s%*s%s\n", ACTIVITY_LABEL - 2, "", fs_cli_dim (),
		        from, (gint) MAX ((gint) n_points - (gint) g_utf8_strlen (from, -1), 4),
		        "now", fs_cli_reset ());
		printf ("\n");
		printf ("  %-*s%s in the last hour %s %s in 24 h %s counting since "
		        "%s\n", ACTIVITY_LABEL - 2, "Blocked", b1,
		        fs_cli_sym (FS_CLI_SYM_SEP), b24, fs_cli_sym (FS_CLI_SYM_SEP),
		        since);
		if (logs_allowed) {
			gchar *a1 = total_words (stop, fs_activity_total (
				activity, FS_ACTIVITY_ALLOWED, 3600));
			gchar *a24 = total_words (stop, fs_activity_total (
				activity, FS_ACTIVITY_ALLOWED, FS_ACTIVITY_SPAN_S));

			printf ("  %-*s%s in the last hour %s %s in 24 h\n",
			        ACTIVITY_LABEL - 2, "Allowed", a1,
			        fs_cli_sym (FS_CLI_SYM_SEP), a24);
			g_free (a1);
			g_free (a24);
		}
		if (have_rate) {
			gchar *r = fs_cli_format_rate (rx), *t = fs_cli_format_rate (tx);
			gchar *dev = fs_cli_out_safe (device != NULL ? device
			                              : "all adapters");

			printf ("  %-*s%s %s  %s %s  %s(%s, now)%s\n",
			        ACTIVITY_LABEL - 2, "Network",
			        fs_cli_sym (FS_CLI_SYM_DOWN), r,
			        fs_cli_sym (FS_CLI_SYM_UP), t, fs_cli_dim (), dev,
			        fs_cli_reset ());
			g_free (r);
			g_free (t);
			g_free (dev);
		}
		g_free (from);
		g_free (b1);
		g_free (b24);
		g_free (since);
		g_free (per);
	}

	fflush (stdout);
	if (!fs_cli.json && !fs_cli.quiet)
		for (guint i = 0; i < notes->len; i++)
			fprintf (stderr, "%snote: %s%s\n", fs_cli_dim (),
			         (const gchar *) notes->pdata[i], fs_cli_reset ());

out:
	if (activity != NULL)
		fs_activity_free (activity);
	g_array_unref (fill.counts);
	g_ptr_array_unref (notes);
	g_free (blocked);
	g_free (allowed);
	g_free (covered);
	g_free (covered_a);
	g_free (dir);
	g_free (source);
	(void) found;
	return rc;
}

/* ------------------------------------------------------- the command */

static const FsCliOption activity_opts[] = {
	{ "--range",       TRUE,  NULL },
	{ "--device",      TRUE,  NULL },
	{ "--history-dir", TRUE,  NULL },
	{ "--history",     FALSE, NULL },
	{ "--table",       FALSE, NULL },
	{ "--no-rate",     FALSE, NULL },
	{ "--utc",         FALSE, NULL },
	{ NULL, FALSE, NULL }
};

const FsCliCommandDef fs_cli_activity_commands[] = {
	{ "activity", fs_cli_cmd_activity,
"Usage: stockfw activity [--range 15m|1h|6h|24h] [--device DEV] [--table]\n"
"                        [--history | --history-dir DIR] [--no-rate]\n"
"                        [--utc] [--json]\n"
"\n"
"The desktop app's Activity page: blocked (and, when the firewall logs\n"
"them, allowed) events per point over the range (default 1h), as a\n"
"sparkline; the blocked count in the last hour and in 24 h, and since\n"
"when it counts; and the network throughput now, of every adapter or\n"
"of --device (measured over one second; --no-rate leaves it out).\n"
"\n"
"The series are rebuilt from the saved event history while it is kept\n"
"and a copy of StockFW writes it (or with --history, --history-dir),\n"
"else from the kernel log, which usually needs root.  A point before\n"
"the source could have seen anything is no data (a dot, null in\n"
"--json), not a zero; so is a point after the last event of a history\n"
"nobody writes now, whose totals are then unknown.  --table\n"
"prints one row per point.  Notes on stderr say where the counts come\n"
"from and, on Linux, that only blocked packets are in the kernel log\n"
"unless Log allowed is on.\n"
"\n"
"Examples:\n"
"  stockfw activity --range 24h\n"
"  stockfw activity --history --table --range 15m\n",
	  activity_opts, NULL },

	{ NULL, NULL, NULL, NULL, NULL }
};
