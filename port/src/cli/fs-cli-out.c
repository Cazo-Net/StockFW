/*---[ fs-cli-out.c ]----------------------------------------------------
 * `stockfw': the output helpers every command prints through -- errors
 * and hints, colour, tables fitted to the terminal, prose wrapping,
 * terminal-safe text, symbols with an ASCII fallback, times, and the
 * hints that name this program by its full path.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "core/fs-eventstore.h"
#include "core/fs-json.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef G_OS_WIN32
#include <sys/ioctl.h>
#endif

/* ------------------------------------------------------- safe text */

/* [ is_hidden_control ] -- the C1 controls and the bidi controls,
 * which reorder or hide what follows them on a terminal. */
static gboolean
is_hidden_control (gunichar u)
{
	return (u >= 0x80 && u <= 0x9f) ||
	       u == 0x061c || u == 0x200e || u == 0x200f ||
	       (u >= 0x202a && u <= 0x202e) ||
	       (u >= 0x2066 && u <= 0x2069);
}

gchar *
fs_cli_out_safe (const gchar *text)
{
	const gchar *p, *end;
	GString *out;

	if (text == NULL)
		return g_strdup ("");

	end = text + strlen (text);
	out = g_string_sized_new ((gsize) (end - text));

	for (p = text; p < end; ) {
		guchar c = (guchar) *p;
		gunichar u;
		const gchar *next;

		if (c < 0x20 || c == 0x7f) {
			g_string_append_printf (out, "\\x%02x", c);
			p++;
			continue;
		}
		if (c < 0x80) {
			g_string_append_c (out, (gchar) c);
			p++;
			continue;
		}

		u = g_utf8_get_char_validated (p, end - p);
		if (u == (gunichar) -1 || u == (gunichar) -2) {
			g_string_append_printf (out, "\\x%02x", c);
			p++;
			continue;
		}
		next = g_utf8_next_char (p);
		if (is_hidden_control (u))
			g_string_append_printf (out, "\\u%04x", (guint) u);
		else
			g_string_append_len (out, p, next - p);
		p = next;
	}

	return g_string_free (out, FALSE);
}

/* [ fs_cli_out_safe_lines ] -- out_safe line by line: a notice keeps
 * its breaks. */
gchar *
fs_cli_out_safe_lines (const gchar *text)
{
	gchar **lines = g_strsplit (text != NULL ? text : "", "\n", -1);
	gchar *joined;

	for (guint i = 0; lines[i] != NULL; i++) {
		gchar *safe = fs_cli_out_safe (lines[i]);

		g_free (lines[i]);
		lines[i] = safe;
	}
	joined = g_strjoinv ("\n", lines);
	g_strfreev (lines);
	return joined;
}

/* ------------------------------------------------------- notices */

static void
notice (const gchar *label, const gchar *colour, const gchar *format,
        va_list args)
{
	gchar *text = g_strdup_vprintf (format, args);
	gchar *safe = fs_cli_out_safe_lines (text);

	fprintf (stderr, "stockfw: %s%s:%s %s\n",
	         fs_cli.color_err ? colour : "", label,
	         fs_cli.color_err ? "\033[0m" : "", safe);
	g_free (safe);
	g_free (text);
}

void
fs_cli_error (const gchar *format, ...)
{
	va_list args;

	va_start (args, format);
	notice ("error", "\033[1;31m", format, args);
	va_end (args);
}

void
fs_cli_hint (const gchar *format, ...)
{
	va_list args;

	/* -q: errors and the result only. */
	if (fs_cli.quiet)
		return;

	va_start (args, format);
	notice ("hint", "\033[1;33m", format, args);
	va_end (args);
}

const gchar *fs_cli_bold  (void) { return fs_cli.color ? "\033[1m"  : ""; }
const gchar *fs_cli_dim   (void) { return fs_cli.color ? "\033[2m"  : ""; }
const gchar *fs_cli_red   (void) { return fs_cli.color ? "\033[31m" : ""; }
const gchar *fs_cli_green (void) { return fs_cli.color ? "\033[32m" : ""; }
const gchar *fs_cli_amber (void) { return fs_cli.color ? "\033[33m" : ""; }
const gchar *fs_cli_reset (void) { return fs_cli.color ? "\033[0m"  : ""; }

void
fs_cli_print_json (GString *json)
{
	fwrite (json->str, 1, json->len, stdout);
	fputc ('\n', stdout);
}

/* ------------------------------------------------------- numbers */

gchar *
fs_cli_format_bytes (guint64 bytes)
{
	static const gchar *units[] = { "B", "kB", "MB", "GB", "TB", "PB" };
	gdouble value = (gdouble) bytes;
	guint unit = 0;

	while (value >= 1000.0 && unit < G_N_ELEMENTS (units) - 1) {
		value /= 1000.0;
		unit++;
	}

	if (unit == 0)
		return g_strdup_printf ("%" G_GUINT64_FORMAT " B", bytes);

	return g_strdup_printf ("%.1f %s", value, units[unit]);
}

gchar *
fs_cli_format_rate (gdouble bytes_per_second)
{
	gchar *size;
	gchar *text;

	if (bytes_per_second < 0)
		bytes_per_second = 0;

	size = fs_cli_format_bytes ((guint64) (bytes_per_second + 0.5));
	text = g_strconcat (size, "/s", NULL);
	g_free (size);

	return text;
}

/* ------------------------------------------------------- symbols */

const gchar *
fs_cli_sym (FsCliSym sym)
{
	static const gchar *utf8[]  = { "●", "○", "↓", "↑", "→", "…", "·" };
	static const gchar *ascii[] = { "*", "o", "v", "^", "->", "...", "-" };

	if ((guint) sym >= G_N_ELEMENTS (utf8))
		return "?";
	return g_get_charset (NULL) ? utf8[sym] : ascii[sym];
}

/* ------------------------------------------------------- the terminal */

guint
fs_cli_term_width (void)
{
	const gchar *columns;
	guint64 n;

	/* A pipe or a file gets every character: no width at all. */
	if (!isatty (STDOUT_FILENO))
		return 0;

#if !defined G_OS_WIN32 && defined TIOCGWINSZ
	{
		struct winsize ws;

		if (ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
			return ws.ws_col;
	}
#endif

	/* A terminal that does not say its size (ws_col 0: some serial
	 * consoles, `script' without a size): $COLUMNS. */
	columns = g_getenv ("COLUMNS");
	if (columns == NULL || !g_ascii_isdigit (*columns))
		return 0;
	n = g_ascii_strtoull (columns, NULL, 10);
	return n > 0 && n < 10000 ? (guint) n : 0;
}

/* [ cell_text ] -- a cell cut to `width' characters with an ellipsis. */
static gchar *
cell_text (const gchar *cell, guint width)
{
	const gchar *ell = fs_cli_sym (FS_CLI_SYM_ELLIPSIS);
	glong ell_len = g_utf8_strlen (ell, -1);
	glong len;

	if (cell == NULL)
		cell = "";

	len = g_utf8_strlen (cell, -1);
	if (width == 0 || len <= (glong) width)
		return g_strdup (cell);

	if ((glong) width <= ell_len) {
		const gchar *end = g_utf8_offset_to_pointer (cell, width);

		return g_strndup (cell, (gsize) (end - cell));
	} else {
		const gchar *end = g_utf8_offset_to_pointer (cell,
		                                             width - ell_len);
		gchar *cut = g_strndup (cell, (gsize) (end - cell));
		gchar *text = g_strconcat (cut, ell, NULL);

		g_free (cut);
		return text;
	}
}

/* [ fit_widths ] -- shrink the columns until the table fits `term'
 * characters: flex_col first, then always the widest one that can
 * still give, never below its header (or 1). */
static void
fit_widths (guint *widths, const guint *floors, guint n_cols, gint flex_col,
            guint term)
{
	guint total = 2 * (n_cols - 1);

	for (guint c = 0; c < n_cols; c++)
		total += widths[c];
	if (total <= term)
		return;

	if (flex_col >= 0 && (guint) flex_col < n_cols) {
		guint give = MIN (total - term,
		                  widths[flex_col] - floors[flex_col]);

		widths[flex_col] -= give;
		total -= give;
	}

	while (total > term) {
		gint widest = -1;

		for (guint c = 0; c < n_cols; c++)
			if (widths[c] > floors[c] &&
			    (widest < 0 || widths[c] > widths[widest]))
				widest = (gint) c;
		if (widest < 0)
			break;
		widths[widest]--;
		total--;
	}
}

void
fs_cli_table_ex (const gchar * const *headers, guint n_cols, GPtrArray *rows,
                 guint max_cell, gint flex_col)
{
	guint *widths, *floors;
	guint term;
	GPtrArray *cells;

	if (n_cols == 0)
		return;

	/* --plain: one line per row, cells tab-separated, no header and no
	 * colour, nothing cut -- for cut, awk and while-read loops. */
	if (fs_cli.plain) {
		for (guint r = 0; r < rows->len; r++) {
			gchar **row = g_ptr_array_index (rows, r);

			for (guint c = 0; c < n_cols; c++) {
				gchar *safe = fs_cli_out_safe (row[c]);

				printf ("%s%s", c > 0 ? "\t" : "", safe);
				g_free (safe);
			}
			printf ("\n");
		}
		return;
	}

	if (fs_cli.full)
		max_cell = 0;

	widths = g_new0 (guint, n_cols);
	floors = g_new0 (guint, n_cols);
	cells = g_ptr_array_new_with_free_func ((GDestroyNotify) g_strfreev);

	for (guint c = 0; c < n_cols; c++) {
		widths[c] = (guint) g_utf8_strlen (headers[c], -1);
		floors[c] = MAX (widths[c], 1u);
	}

	for (guint r = 0; r < rows->len; r++) {
		gchar **row = g_ptr_array_index (rows, r);
		gchar **cut = g_new0 (gchar *, n_cols + 1);

		for (guint c = 0; c < n_cols; c++) {
			gchar *safe = fs_cli_out_safe (row[c]);

			cut[c] = cell_text (safe, max_cell);
			g_free (safe);
			widths[c] = MAX (widths[c],
			                 (guint) g_utf8_strlen (cut[c], -1));
		}
		g_ptr_array_add (cells, cut);
	}

	/* On a terminal, fit it; a pipe gets every character. */
	term = fs_cli.full ? 0 : fs_cli_term_width ();
	if (term > 0) {
		fit_widths (widths, floors, n_cols, flex_col, term);
		for (guint r = 0; r < cells->len; r++) {
			gchar **row = g_ptr_array_index (cells, r);

			for (guint c = 0; c < n_cols; c++) {
				gchar *cut = cell_text (row[c], widths[c]);

				g_free (row[c]);
				row[c] = cut;
			}
		}
	}

	/* Header. */
	printf ("%s", fs_cli_bold ());
	for (guint c = 0; c < n_cols; c++) {
		if (c + 1 < n_cols)
			printf ("%-*s  ", (gint) (widths[c] + strlen (headers[c]) -
			                          g_utf8_strlen (headers[c], -1)),
			        headers[c]);
		else
			printf ("%s", headers[c]);
	}
	printf ("%s\n", fs_cli_reset ());

	for (guint r = 0; r < cells->len; r++) {
		gchar **row = g_ptr_array_index (cells, r);

		for (guint c = 0; c < n_cols; c++) {
			if (c + 1 < n_cols) {
				/* printf pads by bytes; pad by characters. */
				glong chars = g_utf8_strlen (row[c], -1);

				printf ("%s%*s  ", row[c],
				        (gint) (widths[c] - (guint) chars), "");
			} else {
				printf ("%s", row[c]);
			}
		}
		printf ("\n");
	}

	g_ptr_array_unref (cells);
	g_free (floors);
	g_free (widths);
}

void
fs_cli_table (const gchar * const *headers, guint n_cols, GPtrArray *rows,
              guint max_width)
{
	fs_cli_table_ex (headers, n_cols, rows, max_width, -1);
}

gchar *
fs_cli_wrap (const gchar *text, guint indent)
{
	guint width = fs_cli_term_width ();
	GString *out;
	gchar **lines;

	if (text == NULL)
		return g_strdup ("");
	if (width == 0 || width <= indent + 10)
		return g_strdup (text);

	out = g_string_new (NULL);
	lines = g_strsplit (text, "\n", -1);
	for (guint l = 0; lines[l] != NULL; l++) {
		gchar **words = g_strsplit (lines[l], " ", -1);
		guint col = 0;
		gboolean first = TRUE;

		if (l > 0)
			g_string_append_c (out, '\n');
		for (guint w = 0; words[w] != NULL; w++) {
			guint len = (guint) g_utf8_strlen (words[w], -1);

			if (*words[w] == '\0')
				continue;
			if (!first && col + 1 + len > width) {
				g_string_append_c (out, '\n');
				for (guint s = 0; s < indent; s++)
					g_string_append_c (out, ' ');
				col = indent;
				first = TRUE;
			}
			if (!first) {
				g_string_append_c (out, ' ');
				col++;
			}
			g_string_append (out, words[w]);
			col += len;
			first = FALSE;
		}
		g_strfreev (words);
	}
	g_strfreev (lines);
	return g_string_free (out, FALSE);
}

/* ------------------------------------------------------- times */

gchar *
fs_cli_time_text (gint64 epoch, FsCliTimeStyle style)
{
	GDateTime *utc = g_date_time_new_from_unix_utc (epoch);
	GDateTime *local;
	gchar *text;

	if (utc == NULL)
		return g_strdup ("?");

	if (fs_cli.utc || style == FS_CLI_TIME_ISO) {
		text = g_date_time_format (utc, "%Y-%m-%dT%H:%M:%SZ");
		g_date_time_unref (utc);
		return text;
	}

	local = g_date_time_to_local (utc);
	text = g_date_time_format (local, style == FS_CLI_TIME_FULL
	                                  ? "%Y-%m-%d %H:%M:%S %Z"
	                                  : "%b %d %H:%M:%S");
	g_date_time_unref (local);
	g_date_time_unref (utc);
	return text;
}

void
fs_json_kv_time (GString *out, const gchar *key, gint64 epoch)
{
	GDateTime *utc = g_date_time_new_from_unix_utc (epoch);
	gchar *iso = utc != NULL
	             ? g_date_time_format (utc, "%Y-%m-%dT%H:%M:%SZ") : NULL;

	fs_json_kv_str (out, key, iso);
	g_string_append_c (out, ',');
	fs_json_kv_int (out, "epoch", epoch);
	g_free (iso);
	if (utc != NULL)
		g_date_time_unref (utc);
}

gboolean
fs_cli_parse_window (const gchar *since, const gchar *until,
                     gint64 *since_us, gint64 *until_us)
{
	gint64 now = g_get_real_time ();
	const gchar *names[2] = { "--since", "--until" };
	const gchar *texts[2] = { since, until };
	gint64 *outs[2] = { since_us, until_us };

	for (guint k = 0; k < 2; k++) {
		GError *error = NULL;

		if (texts[k] == NULL)
			continue;
		if (fs_event_parse_time_spec (texts[k], now, k == 1, outs[k],
		                              &error))
			continue;
		fs_cli_error ("%s: %s", names[k], error->message);
		fs_cli_hint ("a time is 15m, 2h, 3d, 1w, now, 2026-11-01, "
		             "\"2026-11-01 14:30\" or ISO with Z");
		g_error_free (error);
		return FALSE;
	}
	return TRUE;
}

/* ------------------------------------------------------- hints */

/* [ shell_word ] -- a word as a shell reads it back: quoted only when
 * it holds anything but the plain characters of a command line. */
static gchar *
shell_word (const gchar *word)
{
	if (word != NULL && *word != '\0' &&
	    strspn (word, "abcdefghijklmnopqrstuvwxyz"
	                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	                  "0123456789_./:=,@%+-") == strlen (word))
		return g_strdup (word);
	return g_shell_quote (word != NULL ? word : "");
}

gchar *
fs_cli_user_args (void)
{
	GString *out = g_string_new (NULL);

	for (gint i = 0; i < fs_cli.user_argc; i++) {
		gchar *w = shell_word (fs_cli.user_argv[i]);

		if (i > 0)
			g_string_append_c (out, ' ');
		g_string_append (out, w);
		g_free (w);
	}
	return g_string_free (out, FALSE);
}

gchar *
fs_cli_sudo_hint (const gchar *args)
{
	gchar *exe = NULL, *word, *text;
	const gchar *sudo = FS_CLI_SUDO;

#ifdef __linux__
	exe = g_file_read_link ("/proc/self/exe", NULL);
	if (exe != NULL && g_str_has_suffix (exe, " (deleted)"))
		g_clear_pointer (&exe, g_free);
#endif
#ifndef G_OS_WIN32
	/* Root needs no sudo; the full path still helps under a PATH
	 * that differs. */
	if (geteuid () == 0)
		sudo = "";
#endif
	word = shell_word (exe != NULL ? exe : "stockfw");
	text = g_strdup_printf ("%s%s%s%s", sudo, word,
	                        args != NULL && *args != '\0' ? " " : "",
	                        args != NULL ? args : "");
	g_free (word);
	g_free (exe);
	return text;
}

/* === WP-D === */
/* A table printed a row at a time (`events -f'): the widths are frozen
 * from the rows known up front, laid out as fs_cli_table_ex lays them
 * out, and every later row is printed at those widths. */

guint *
fs_cli_table_widths (const gchar * const *headers, guint n_cols,
                     GPtrArray *rows, guint max_cell, gint flex_col)
{
	guint *widths = g_new0 (guint, n_cols);
	guint *floors = g_new0 (guint, n_cols);
	guint term;

	if (fs_cli.full)
		max_cell = 0;
	for (guint c = 0; c < n_cols; c++) {
		widths[c] = (guint) g_utf8_strlen (headers[c], -1);
		floors[c] = MAX (widths[c], 1u);
	}
	for (guint r = 0; rows != NULL && r < rows->len; r++) {
		gchar **row = g_ptr_array_index (rows, r);

		for (guint c = 0; c < n_cols; c++) {
			gchar *safe = fs_cli_out_safe (row[c]);
			gchar *cut = cell_text (safe, max_cell);

			widths[c] = MAX (widths[c], (guint) g_utf8_strlen (cut, -1));
			g_free (cut);
			g_free (safe);
		}
	}
	term = fs_cli.full ? 0 : fs_cli_term_width ();
	if (term > 0 && n_cols > 0)
		fit_widths (widths, floors, n_cols, flex_col, term);
	g_free (floors);
	return widths;
}

void
fs_cli_table_header (const gchar * const *headers, guint n_cols,
                     const guint *widths)
{
	if (fs_cli.plain)
		return;
	printf ("%s", fs_cli_bold ());
	for (guint c = 0; c < n_cols; c++) {
		if (c + 1 < n_cols)
			printf ("%-*s  ", (gint) (widths[c] + strlen (headers[c]) -
			                          g_utf8_strlen (headers[c], -1)),
			        headers[c]);
		else
			printf ("%s", headers[c]);
	}
	printf ("%s\n", fs_cli_reset ());
}

void
fs_cli_table_row (gchar **row, guint n_cols, const guint *widths,
                  const gchar * const *colours)
{
	gboolean cut = !fs_cli.full && fs_cli_term_width () > 0;

	for (guint c = 0; c < n_cols; c++) {
		gchar *safe = fs_cli_out_safe (row[c]);
		const gchar *colour = colours != NULL && colours[c] != NULL &&
		                      *colours[c] != '\0' && !fs_cli.plain
		                      ? colours[c] : NULL;
		gchar *text;
		glong chars;

		if (fs_cli.plain) {
			printf ("%s%s", c > 0 ? "\t" : "", safe);
			g_free (safe);
			continue;
		}
		/* A wider cell is cut on a terminal, so the columns stay
		 * under their header; a pipe gets every character. */
		text = cut ? cell_text (safe, widths[c]) : g_strdup (safe);
		chars = g_utf8_strlen (text, -1);
		printf ("%s%s%s", colour != NULL ? colour : "", text,
		        colour != NULL ? fs_cli_reset () : "");
		if (c + 1 < n_cols)
			printf ("%*s  ", (gint) (chars < (glong) widths[c]
			                         ? widths[c] - (guint) chars : 0), "");
		g_free (text);
		g_free (safe);
	}
	printf ("\n");
}
/* === end WP-D === */
