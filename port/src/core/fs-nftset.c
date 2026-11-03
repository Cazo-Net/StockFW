/*---[ fs-nftset.c ]-----------------------------------------------------
 * A blocklist file into an nftables set.  See fs-nftset.h.
 *--------------------------------------------------------------------*/

#include "core/fs-nftset.h"
#include "core/fs-toolpath.h"

#include <gio/gio.h>
#include <glib/gstdio.h>
#include <string.h>

#ifdef G_OS_UNIX
#include <signal.h>
#include <time.h>
#endif

/* Elements per `add element' statement: keeps each line of the script a
 * sane length; the statements still share one transaction. */
#define ELEMENTS_PER_STATEMENT 1000

/* ============================================================ parsing */

/* The first field of a stripped data line, as a new string: a quoted
 * field's inside, or everything up to the first separator. */
static gchar *
first_field (const gchar *line)
{
	if (*line == '"') {
		const gchar *close = strchr (line + 1, '"');

		if (close == NULL)
			return g_strdup (line + 1);
		return g_strndup (line + 1, (gsize) (close - line - 1));
	}
	return g_strndup (line, strcspn (line, ",; \t"));
}

static gboolean
has_ascii_letter (const gchar *s)
{
	for (; *s != '\0'; s++)
		if (g_ascii_isalpha (*s))
			return TRUE;
	return FALSE;
}

FsRangeSet *
fs_blocklist_parse_csv (const gchar *text, gsize len, FsBlocklistStats *stats)
{
	FsBlocklistStats local = { 0 };
	FsRangeSet *set = fs_range_set_new ();
	gchar *copy, **lines;
	gboolean seen_data = FALSE;

	if (stats == NULL)
		stats = &local;
	memset (stats, 0, sizeof *stats);

	if (text == NULL)
		return set;

	/* The text may not be NUL-terminated (a mapped file); own a copy. */
	copy = g_strndup (text, len);
	lines = g_strsplit (copy, "\n", -1);
	g_free (copy);

	for (guint i = 0; lines[i] != NULL; i++) {
		gchar *line = lines[i];
		gchar *field;
		gboolean ok;

		/* A trailing empty piece after the final newline is not a
		 * line of the file. */
		if (lines[i + 1] == NULL && *line == '\0')
			break;
		stats->lines++;

		if (i == 0 && g_str_has_prefix (line, "\xEF\xBB\xBF"))
			line += 3;   /* UTF-8 byte order mark */
		line = g_strstrip (line);

		if (*line == '\0' || *line == '#' || *line == ';')
			continue;

		field = first_field (line);
		g_strstrip (field);
		ok = *field != '\0' && fs_range_set_add_text (set, field);

		if (ok) {
			stats->entries++;
		} else if (!seen_data && has_ascii_letter (field)) {
			stats->header = TRUE;   /* "ip,comment", "address" */
		} else {
			stats->skipped++;
			if (stats->first_bad_line == 0)
				stats->first_bad_line = i + 1;
		}
		seen_data = TRUE;
		g_free (field);
	}
	g_strfreev (lines);

	fs_range_set_normalize (set);
	return set;
}

/* ============================================================== script */

gboolean
fs_nft_name_is_valid (const gchar *name)
{
	gsize n;

	if (name == NULL || !g_ascii_isalpha (name[0]))
		return FALSE;
	n = strlen (name);
	if (n > 31)
		return FALSE;
	for (gsize i = 1; i < n; i++)
		if (!g_ascii_isalnum (name[i]) && name[i] != '_')
			return FALSE;
	return TRUE;
}

/* `add element inet T S { a, b, ... }' lines, ELEMENTS_PER_STATEMENT at
 * a time, from an array of already formatted elements. */
static void
append_elements (GString *out, const gchar *table, const gchar *set,
                 GPtrArray *elems)
{
	for (guint i = 0; i < elems->len; i += ELEMENTS_PER_STATEMENT) {
		guint end = MIN (elems->len, i + ELEMENTS_PER_STATEMENT);

		g_string_append_printf (out, "add element inet %s %s { ",
		                        table, set);
		for (guint k = i; k < end; k++) {
			if (k > i)
				g_string_append (out, ", ");
			g_string_append (out, g_ptr_array_index (elems, k));
		}
		g_string_append (out, " }\n");
	}
}

gchar *
fs_nftset_script (const gchar *table, const gchar *set,
                  const FsRangeSet *ranges)
{
	GString *out;
	GPtrArray *elems;
	gchar *set6;

	if (!fs_nft_name_is_valid (table) || !fs_nft_name_is_valid (set) ||
	    strlen (set) > 30)   /* room for the "6" */
		return NULL;

	set6 = g_strconcat (set, "6", NULL);
	out = g_string_new (NULL);

	/* Declarations create the table and sets when they are missing
	 * and leave existing ones (and their chains) alone. */
	g_string_append_printf (out,
		"table inet %s {\n"
		"\tset %s {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t}\n"
		"\tset %s {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t}\n"
		"}\n",
		table, set, set6);

	/* Replace, not merge: last load's entries must not linger. */
	g_string_append_printf (out, "flush set inet %s %s\n", table, set);
	g_string_append_printf (out, "flush set inet %s %s\n", table, set6);

	elems = g_ptr_array_new_with_free_func (g_free);
	for (guint i = 0; ranges != NULL && i < ranges->v4->len; i++)
		g_ptr_array_add (elems, fs_range4_to_string (
			&g_array_index (ranges->v4, FsRange4, i)));
	append_elements (out, table, set, elems);
	g_ptr_array_set_size (elems, 0);

	for (guint i = 0; ranges != NULL && i < ranges->v6->len; i++)
		g_ptr_array_add (elems, fs_range6_to_string (
			&g_array_index (ranges->v6, FsRange6, i)));
	append_elements (out, table, set6, elems);
	g_ptr_array_unref (elems);

	g_free (set6);
	return g_string_free (out, FALSE);
}

/* ================================================================= run */

/* Writing to the stdin of an nft that has died raises SIGPIPE, whose
 * default action would end this process -- the root GUI or the CLI --
 * instead of failing one apply.  It is held back in this thread while
 * nft runs (GLib writes to a pipe from the thread that iterates the
 * context, and that is this one), and one that arrived is discarded
 * before the mask is restored.  The process-wide disposition is left
 * alone. */
typedef struct
{
#ifdef G_OS_UNIX
	sigset_t saved;
#else
	int      unused;
#endif
} SigpipeHold;

static void
sigpipe_hold (SigpipeHold *hold)
{
#ifdef G_OS_UNIX
	sigset_t set;

	sigemptyset (&set);
	sigaddset (&set, SIGPIPE);
	pthread_sigmask (SIG_BLOCK, &set, &hold->saved);
#endif
}

static void
sigpipe_release (SigpipeHold *hold)
{
#ifdef G_OS_UNIX
	if (!sigismember (&hold->saved, SIGPIPE)) {
		struct timespec now = { 0, 0 };
		sigset_t set;

		sigemptyset (&set);
		sigaddset (&set, SIGPIPE);
		while (sigtimedwait (&set, NULL, &now) == SIGPIPE)
			;
	}
	pthread_sigmask (SIG_SETMASK, &hold->saved, NULL);
#endif
}

/* One nft run: its pipes, and the timer that kills it [S8.4]. */
typedef struct
{
	GSubprocess  *proc;
	GCancellable *cancel;
	gboolean      communicated;
	gboolean      waited;
	gboolean      timed_out;
	GBytes       *out;
	GBytes       *err;
	GError       *error;
} NftRun;

static void
nft_run_communicated (GObject *source, GAsyncResult *result, gpointer data)
{
	NftRun *run = data;

	g_subprocess_communicate_finish (G_SUBPROCESS (source), result,
	                                 &run->out, &run->err, &run->error);
	run->communicated = TRUE;
}

static void
nft_run_waited (GObject *source, GAsyncResult *result, gpointer data)
{
	NftRun *run = data;

	g_subprocess_wait_finish (G_SUBPROCESS (source), result, NULL);
	run->waited = TRUE;
}

static gboolean
nft_run_expired (gpointer data)
{
	NftRun *run = data;

	/* SIGKILL, and stop reading: a child of a wrapper may hold the
	 * pipes open long after the process we started is gone. */
	run->timed_out = TRUE;
	g_subprocess_force_exit (run->proc);
	g_cancellable_cancel (run->cancel);
	return G_SOURCE_REMOVE;
}

/* The first line of nft's complaint, at most 300 bytes and valid UTF-8,
 * for an error message: nft prints the offending statement and a caret
 * under it on the lines after.  Never NULL. */
static gchar *
first_line (GBytes *bytes)
{
	const gchar *data = NULL;
	gsize len = 0, start = 0, n;
	gchar *line;

	if (bytes != NULL)
		data = g_bytes_get_data (bytes, &len);
	if (data == NULL)
		return g_strdup ("");

	while (start < len && g_ascii_isspace (data[start]))
		start++;
	for (n = 0; start + n < len && n < 300; n++)
		if (data[start + n] == '\n' || data[start + n] == '\0')
			break;
	line = g_utf8_make_valid (data + start, (gssize) n);
	return g_strstrip (line);
}

/* Runs `nft <args>' with `input' on stdin (NULL: stdin is /dev/null),
 * collecting stdout when `out' is not NULL, and kills it after
 * timeout_ms.  TRUE when nft ran to its end, whatever its exit status:
 * *exit_ok says whether it exited 0, *complaint (caller frees) is the
 * first line of its stderr.  FALSE with error when nft could not be
 * started, timed out, or its pipes failed. */
static gboolean
nft_spawn (const gchar *const *args, const gchar *input, guint timeout_ms,
           GBytes **out, gboolean *exit_ok, gchar **complaint,
           GError **error)
{
	GSubprocessFlags flags = G_SUBPROCESS_FLAGS_STDERR_PIPE;
	GPtrArray *argv = g_ptr_array_new ();
	GBytes *stdin_bytes = NULL;
	GMainContext *ctx;
	GSource *timer;
	SigpipeHold hold;
	NftRun run;
	GError *local = NULL;
	gboolean ok = FALSE, finished;
	/* By its full path: as root from the system directories only,
	 * never the PATH of whoever started us [S0]. */
	gchar *nft = fs_toolpath_find ("nft");

	if (nft == NULL) {
		g_ptr_array_unref (argv);
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
		             "Could not run nft (is the nftables package "
		             "installed?): nft was not found %s",
		             fs_toolpath_where ());
		return FALSE;
	}
	memset (&run, 0, sizeof run);
	g_ptr_array_add (argv, nft);
	for (guint i = 0; args[i] != NULL; i++)
		g_ptr_array_add (argv, (gpointer) args[i]);
	g_ptr_array_add (argv, NULL);

	if (input != NULL) {
		flags |= G_SUBPROCESS_FLAGS_STDIN_PIPE;
		stdin_bytes = g_bytes_new_static (input, strlen (input));
	}
	flags |= out != NULL ? G_SUBPROCESS_FLAGS_STDOUT_PIPE :
	                       G_SUBPROCESS_FLAGS_STDOUT_SILENCE;

	/* A private main context, current in this thread while nft runs:
	 * a worker thread can call this, and the caller's own loop (the
	 * UI's) is never iterated behind its back. */
	ctx = g_main_context_new ();
	g_main_context_push_thread_default (ctx);

	/* An argv, not a command line: no shell ever sees an argument,
	 * and a script travels on stdin.  nft is the absolute path found
	 * above, as the backend finds iptables-restore. */
	run.proc = g_subprocess_newv ((const gchar *const *) argv->pdata,
	                              flags, &local);
	if (run.proc == NULL) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
		             "Could not run nft (is the nftables package "
		             "installed?): %s", local->message);
		g_error_free (local);
		goto out;
	}

	/* Held only after the spawn, so nft itself starts with the
	 * ordinary signal mask. */
	sigpipe_hold (&hold);

	/* communicate() writes all of stdin while draining stdout and
	 * stderr, so a large script cannot deadlock against a full pipe. */
	run.cancel = g_cancellable_new ();
	g_subprocess_communicate_async (run.proc, stdin_bytes, run.cancel,
	                                nft_run_communicated, &run);
	timer = g_timeout_source_new (timeout_ms);
	g_source_set_callback (timer, nft_run_expired, &run, NULL);
	g_source_attach (timer, ctx);

	while (!run.communicated)
		g_main_context_iteration (ctx, TRUE);
	g_source_destroy (timer);
	g_source_unref (timer);

	/* After a failure nft may still be running: make sure it is gone,
	 * and wait for it either way, so its exit status is known and
	 * every pipe operation has ended before the context goes away. */
	if (run.error != NULL)
		g_subprocess_force_exit (run.proc);
	g_subprocess_wait_async (run.proc, NULL, nft_run_waited, &run);
	while (!run.waited)
		g_main_context_iteration (ctx, TRUE);
	while (g_main_context_pending (ctx))
		g_main_context_iteration (ctx, FALSE);

	sigpipe_release (&hold);

	/* nft that exited on its own just as the timer fired still counts
	 * as finished; one the timer killed did not. */
	finished = run.error == NULL && g_subprocess_get_if_exited (run.proc);
	if (run.timed_out && !finished) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
		             "nft timed out: it did not finish within %u.%03u s "
		             "and was stopped", timeout_ms / 1000,
		             timeout_ms % 1000);
	} else if (run.error != NULL) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
		             "Could not talk to nft: %s", run.error->message);
	} else {
		*exit_ok = finished &&
		           g_subprocess_get_exit_status (run.proc) == 0;
		*complaint = first_line (run.err);
		if (**complaint == '\0' && !finished) {
			g_free (*complaint);
			*complaint = g_strdup ("nft was killed by a signal");
		}
		if (out != NULL)
			*out = run.out != NULL ? g_bytes_ref (run.out) : NULL;
		ok = TRUE;
	}

out:
	g_main_context_pop_thread_default (ctx);
	g_main_context_unref (ctx);
	g_clear_error (&run.error);
	g_clear_pointer (&run.out, g_bytes_unref);
	g_clear_pointer (&run.err, g_bytes_unref);
	g_clear_object (&run.cancel);
	g_clear_object (&run.proc);
	g_clear_pointer (&stdin_bytes, g_bytes_unref);
	g_ptr_array_unref (argv);
	g_free (nft);
	return ok;
}

gboolean
fs_nft_run_script_full (const gchar *script, gboolean check_only,
                        guint timeout_ms, GError **error)
{
	static const gchar *const apply_args[] = { "-f", "-", NULL };
	static const gchar *const check_args[] = { "-c", "-f", "-", NULL };
	gboolean exit_ok = FALSE;
	gchar *complaint = NULL;

	g_return_val_if_fail (script != NULL, FALSE);
	g_return_val_if_fail (timeout_ms > 0, FALSE);

	if (!nft_spawn (check_only ? check_args : apply_args, script,
	                timeout_ms, NULL, &exit_ok, &complaint, error))
		return FALSE;

	if (!exit_ok)
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
		             "nft refused the change: %s",
		             *complaint != '\0' ? complaint : "no reason given");
	g_free (complaint);
	return exit_ok;
}

gboolean
fs_nft_run_script (const gchar *script, gboolean check_only, GError **error)
{
	return fs_nft_run_script_full (script, check_only, FS_NFT_TIMEOUT_MS,
	                               error);
}

gchar *
fs_nft_capture (const gchar *const *args, guint timeout_ms, GError **error)
{
	GBytes *out = NULL;
	gboolean exit_ok = FALSE;
	gchar *complaint = NULL, *text = NULL;
	const gchar *data = NULL;
	gsize len = 0;

	g_return_val_if_fail (args != NULL, NULL);
	g_return_val_if_fail (timeout_ms > 0, NULL);

	if (!nft_spawn (args, NULL, timeout_ms, &out, &exit_ok, &complaint,
	                error))
		return NULL;

	if (!exit_ok) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
		             "nft failed: %s",
		             *complaint != '\0' ? complaint : "no reason given");
		goto out;
	}

	if (out != NULL)
		data = g_bytes_get_data (out, &len);
	/* Listings are parsed as text; a NUL or a broken sequence means
	 * this is not the nft we think it is. */
	if (data != NULL && !g_utf8_validate_len (data, len, NULL)) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
		             "nft printed something that is not UTF-8 text");
		goto out;
	}
	text = g_strndup (data != NULL ? data : "", len);

out:
	g_free (complaint);
	g_clear_pointer (&out, g_bytes_unref);
	return text;
}

/* ============================================================== guards */

/* Whether any interval of `set' overlaps a protected range; counts
 * them.  Both are normalized. */
static guint
count_protected_overlaps (const FsRangeSet *set)
{
	const FsRangeSet *prot = fs_range_protected ();
	guint hits = 0;

	for (guint i = 0; i < set->v4->len; i++) {
		const FsRange4 *a = &g_array_index (set->v4, FsRange4, i);

		for (guint k = 0; k < prot->v4->len; k++) {
			const FsRange4 *p = &g_array_index (prot->v4, FsRange4, k);

			if (a->start <= p->end && p->start <= a->end) {
				hits++;
				break;
			}
		}
	}
	for (guint i = 0; i < set->v6->len; i++) {
		const FsRange6 *a = &g_array_index (set->v6, FsRange6, i);

		for (guint k = 0; k < prot->v6->len; k++) {
			const FsRange6 *p = &g_array_index (prot->v6, FsRange6, k);
			gboolean a_before_p_end =
				a->start.hi < p->end.hi ||
				(a->start.hi == p->end.hi && a->start.lo <= p->end.lo);
			gboolean p_before_a_end =
				p->start.hi < a->end.hi ||
				(p->start.hi == a->end.hi && p->start.lo <= a->end.lo);

			if (a_before_p_end && p_before_a_end) {
				hits++;
				break;
			}
		}
	}
	return hits;
}

static gboolean
check_coverage (const FsRangeSet *set, GError **error)
{
	guint64 total = 0;

	for (guint i = 0; i < set->v4->len; i++) {
		const FsRange4 *r = &g_array_index (set->v4, FsRange4, i);
		guint64 n = fs_range4_size (r);

		if (n > FS_BLOCKLIST_MAX_V4_SPAN) {
			gchar *s = fs_range4_to_string (r);

			g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
			             "%s is wider than a /8; a blocklist that "
			             "blocks that much is refused", s);
			g_free (s);
			return FALSE;
		}
		total += n;
	}
	if (total > FS_BLOCKLIST_MAX_V4_TOTAL) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
		             "the list covers %" G_GUINT64_FORMAT " IPv4 "
		             "addresses, more than an eighth of the internet; "
		             "it is refused", total);
		return FALSE;
	}

	for (guint i = 0; i < set->v6->len; i++) {
		const FsRange6 *r = &g_array_index (set->v6, FsRange6, i);
		guint64 hi = r->end.hi - r->start.hi -
		             (r->end.lo < r->start.lo ? 1 : 0);

		/* end - start >= 2^(128-16) means wider than a /16. */
		if ((hi >> (64 - FS_BLOCKLIST_MAX_V6_PREFIX)) != 0) {
			gchar *s = fs_range6_to_string (r);

			g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
			             "%s is wider than a /%d; a blocklist that "
			             "blocks that much is refused", s,
			             FS_BLOCKLIST_MAX_V6_PREFIX);
			g_free (s);
			return FALSE;
		}
	}
	return TRUE;
}

gboolean
fs_nftset_load_csv (const gchar *path, const gchar *table, const gchar *set,
                    FsBlocklistStats *stats, GError **error)
{
	FsBlocklistStats local = { 0 };
	GStatBuf st;
	gchar *text = NULL, *script = NULL;
	gsize len = 0;
	FsRangeSet *ranges = NULL;
	gboolean ok = FALSE;

	g_return_val_if_fail (path != NULL, FALSE);

	if (stats == NULL)
		stats = &local;
	memset (stats, 0, sizeof *stats);

	if (!fs_nft_name_is_valid (table) || !fs_nft_name_is_valid (set) ||
	    strlen (set) > 30) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
		             "not a valid nftables table or set name");
		return FALSE;
	}

	/* Size first, so a runaway download is never read into memory. */
	if (g_stat (path, &st) != 0) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
		             "cannot read %s", path);
		return FALSE;
	}
	if ((guint64) st.st_size > FS_BLOCKLIST_MAX_BYTES) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
		             "%s is larger than %u MiB; refused", path,
		             FS_BLOCKLIST_MAX_BYTES / (1024u * 1024u));
		return FALSE;
	}
	if (!g_file_get_contents (path, &text, &len, error))
		return FALSE;

	ranges = fs_blocklist_parse_csv (text, len, stats);
	g_free (text);

	/* An empty list would flush the set: a failed download must never
	 * turn into "block nothing". */
	if (stats->entries == 0) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
		             "%s has no addresses; the set was left as it was",
		             path);
		goto out;
	}
	/* Mostly not addresses: an HTML error page, the wrong file. */
	if (stats->skipped > stats->entries) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
		             "%u of %u lines in %s are not addresses (first at "
		             "line %u); this does not look like a blocklist",
		             stats->skipped, stats->skipped + stats->entries,
		             path, stats->first_bad_line);
		goto out;
	}

	stats->protected_hits = count_protected_overlaps (ranges);
	fs_range_set_subtract (ranges, fs_range_protected ());

	if (!check_coverage (ranges, error))
		goto out;

	script = fs_nftset_script (table, set, ranges);
	ok = fs_nft_run_script (script, FALSE, error);

out:
	g_free (script);
	fs_range_set_free (ranges);
	return ok;
}
