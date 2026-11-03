/*---[ fs-cli-views.c ]--------------------------------------------------
 * Read-only views over StockFW's own records: `stockfw audit' (the
 * audit log) and `stockfw sentinel list' (Sentinel's staged blocks).
 * Both are WP-C's (cli-plan.md section 4).  Neither writes anything:
 * the Sentinel file is parsed here, never through fs_autoblock_expire,
 * which rewrites it.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "core/fs-audit.h"
#include "core/fs-autoblock.h"
#include "core/fs-json.h"
#include "core/fs-prefs.h"

#include <glib-unix.h>
#include <glib/gstdio.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifndef G_OS_WIN32
#include <pwd.h>
#endif

/* === WP-C === */

/* ------------------------------------------------------- audit lines */

void
fs_cli_audit_entry_free (FsCliAuditEntry *e)
{
	if (e == NULL)
		return;
	g_free (e->action);
	g_free (e->origin);
	g_free (e->detail);
	g_free (e->raw);
	g_free (e);
}

/* [ gate_action ]
 * An action the apply gate writes (fs-apply.c): its detail starts with
 * the caller's name, "cli" or one of the desktop app's ("policy page",
 * "event menu", "window" ...). */
static gboolean
gate_action (const gchar *action)
{
	return g_str_has_prefix (action, "policy appl") ||
	       g_str_has_prefix (action, "firewall ");
}

/* [ fs_cli_audit_parse_line ]
 * "<ISO UTC> | <action> | <detail>", as fs_audit_log writes it.  The
 * origin is read only where the layout is known (pinned from a real
 * apply, start and stop in a private namespace):
 *   gate lines:   "<source> | <mode> | <what>[ | ...]"
 *   intel lines:  "source=<source> result=..."
 * and is NULL everywhere else, never guessed. */
FsCliAuditEntry *
fs_cli_audit_parse_line (const gchar *line)
{
	gchar **parts;
	GDateTime *when;
	FsCliAuditEntry *e;

	if (line == NULL || *line == '\0')
		return NULL;

	parts = g_strsplit (line, " | ", 3);
	if (g_strv_length (parts) != 3 || *parts[1] == '\0' ||
	    !g_str_has_suffix (parts[0], "Z")) {
		g_strfreev (parts);
		return NULL;
	}
	when = g_date_time_new_from_iso8601 (parts[0], NULL);
	if (when == NULL) {
		g_strfreev (parts);
		return NULL;
	}

	e = g_new0 (FsCliAuditEntry, 1);
	e->epoch = g_date_time_to_unix (when);
	g_date_time_unref (when);
	e->action = g_strdup (parts[1]);
	e->raw = g_strdup (line);

	if (gate_action (parts[1])) {
		gchar **d = g_strsplit (parts[2], " | ", 2);

		if (g_strv_length (d) == 2 && strcmp (d[0], "-") != 0 &&
		    *d[0] != '\0') {
			e->origin = g_strdup (strcmp (d[0], "cli") == 0 ? "cli"
			                                               : "gui");
			e->detail = g_strdup (d[1]);
		}
		g_strfreev (d);
	} else if (g_str_has_prefix (parts[1], "intel-") &&
	           g_str_has_prefix (parts[2], "source=")) {
		const gchar *src = parts[2] + strlen ("source=");
		gsize n = strcspn (src, " ");

		if (n > 0)
			e->origin = g_strdup (n == 3 && strncmp (src, "cli", 3) == 0
			                      ? "cli" : "gui");
	}
	if (e->detail == NULL)
		e->detail = g_strdup (parts[2]);

	g_strfreev (parts);
	return e;
}

GPtrArray *
fs_cli_audit_read (const gchar *path, guint *lines_total, guint *bad_lines,
                   GError **error)
{
	gchar *text = NULL;
	gchar **lines;
	GPtrArray *out;

	if (lines_total != NULL)
		*lines_total = 0;
	if (bad_lines != NULL)
		*bad_lines = 0;
	if (!g_file_get_contents (path, &text, NULL, error))
		return NULL;

	out = g_ptr_array_new_with_free_func (
		(GDestroyNotify) fs_cli_audit_entry_free);
	lines = g_strsplit (text, "\n", -1);
	for (guint i = 0; lines[i] != NULL; i++) {
		FsCliAuditEntry *e;

		g_strchomp (lines[i]);
		if (*lines[i] == '\0')
			continue;
		if (lines_total != NULL)
			(*lines_total)++;
		e = fs_cli_audit_parse_line (lines[i]);
		if (e != NULL)
			g_ptr_array_add (out, e);
		else if (bad_lines != NULL)
			(*bad_lines)++;
	}
	g_strfreev (lines);
	g_free (text);
	return out;
}

FsCliAuditEntry *
fs_cli_audit_last_apply (void)
{
	gchar *path = fs_audit_path ();
	GPtrArray *all = fs_cli_audit_read (path, NULL, NULL, NULL);
	FsCliAuditEntry *last = NULL;

	g_free (path);
	if (all == NULL)
		return NULL;
	for (guint i = all->len; i > 0 && last == NULL; i--) {
		FsCliAuditEntry *e = g_ptr_array_index (all, i - 1);

		if (gate_action (e->action))
			last = g_ptr_array_steal_index (all, i - 1);
	}
	g_ptr_array_unref (all);
	return last;
}

void
fs_cli_audit_entry_json (GString *out, const FsCliAuditEntry *e,
                         gboolean with_raw)
{
	g_string_append_c (out, '{');
	fs_json_kv_time (out, "time", e->epoch);  g_string_append_c (out, ',');
	fs_json_kv_str (out, "action", e->action); g_string_append_c (out, ',');
	fs_json_kv_str (out, "origin", e->origin); g_string_append_c (out, ',');
	fs_json_kv_str (out, "detail", e->detail);
	if (with_raw) {
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "raw", e->raw);
	}
	g_string_append_c (out, '}');
}

/* --------------------------------------------------- Sentinel's file */

void
fs_cli_sentinel_block_free (FsCliSentinelBlock *b)
{
	if (b == NULL)
		return;
	g_free (b->csv);
	fs_rule_free (b->rule);
	g_free (b);
}

/* [ fs_cli_sentinel_read ]
 * The rows "S,<epoch>,<kind>,<csv>" of the state file, read the way
 * fs_autoblock_expire reads them, but nothing is written back. */
GPtrArray *
fs_cli_sentinel_read (const gchar *path, guint *bad_rows, GError **error)
{
	gchar *text = NULL;
	gchar **lines;
	GPtrArray *out;

	if (bad_rows != NULL)
		*bad_rows = 0;
	if (!g_file_get_contents (path, &text, NULL, error))
		return NULL;

	out = g_ptr_array_new_with_free_func (
		(GDestroyNotify) fs_cli_sentinel_block_free);
	lines = g_strsplit (text, "\n", -1);
	for (guint i = 0; lines[i] != NULL; i++) {
		gchar **parts;
		gint64 epoch, kind;
		FsCliSentinelBlock *b;

		g_strchomp (lines[i]);
		if (*lines[i] == '\0' || *lines[i] == '#')
			continue;
		parts = g_strsplit (lines[i], ",", 4);
		epoch = g_strv_length (parts) == 4
		        ? g_ascii_strtoll (parts[1], NULL, 10) : 0;
		kind = g_strv_length (parts) == 4
		       ? g_ascii_strtoll (parts[2], NULL, 10) : -1;
		if (g_strv_length (parts) != 4 || strcmp (parts[0], "S") != 0 ||
		    *parts[3] == '\0' || epoch <= 0 || kind < 0 ||
		    kind >= FS_RULE_N_KINDS) {
			if (bad_rows != NULL)
				(*bad_rows)++;
			g_strfreev (parts);
			continue;
		}
		b = g_new0 (FsCliSentinelBlock, 1);
		b->epoch = epoch;
		b->kind = (FsRuleKind) kind;
		b->csv = g_strdup (parts[3]);
		b->rule = fs_rule_from_csv (b->kind, b->csv);
		g_ptr_array_add (out, b);
		g_strfreev (parts);
	}
	g_strfreev (lines);
	g_free (text);
	return out;
}

/* [ fs_cli_sentinel_whatif ]
 * Sentinel's staged blocks that are still in the policy, handed to the
 * What-If engine with the time each one lifts -- what the desktop
 * app's own What-If adds from its live list (ui/fs-copilot.c). */
void
fs_cli_sentinel_whatif (FsWhatIfContext *ctx, const FsPolicy *policy)
{
	gchar *path = fs_autoblock_state_path ();
	GPtrArray *rows = fs_cli_sentinel_read (path, NULL, NULL);

	g_free (path);
	if (rows == NULL)
		return;
	for (guint i = 0; i < rows->len; i++) {
		FsCliSentinelBlock *b = g_ptr_array_index (rows, i);

		if (b->kind != FS_RULE_OUTBOUND_DENY_TO || b->rule == NULL ||
		    b->rule->target == NULL)
			continue;
		if (policy != NULL && !fs_policy_contains (policy, b->rule))
			continue;
		fs_whatif_context_add_auto_block (ctx, b->rule->target,
		                                  b->epoch + FS_AUTOBLOCK_TTL_S);
	}
	g_ptr_array_unref (rows);
}

gint
fs_cli_sentinel_staged (gint64 *next_lift)
{
	gchar *path = fs_autoblock_state_path ();
	GPtrArray *rows = fs_cli_sentinel_read (path, NULL, NULL);
	gint64 now = g_get_real_time () / G_USEC_PER_SEC;
	gint n;

	g_free (path);
	if (next_lift != NULL)
		*next_lift = 0;
	if (rows == NULL)
		return 0;
	n = (gint) rows->len;
	for (guint i = 0; i < rows->len && next_lift != NULL; i++) {
		FsCliSentinelBlock *b = g_ptr_array_index (rows, i);
		gint64 lifts = b->epoch + FS_AUTOBLOCK_TTL_S;

		if (lifts > now && (*next_lift == 0 || lifts < *next_lift))
			*next_lift = lifts;
	}
	g_ptr_array_unref (rows);
	return n;
}

/* ----------------------------------------------------------- helpers */

/* [ when_text ] -- "2026-11-03 09:12:04" local, ISO UTC under --utc. */
static gchar *
when_text (gint64 epoch, const gchar *local_format)
{
	GDateTime *utc = g_date_time_new_from_unix_utc (epoch);
	GDateTime *local;
	gchar *text;

	if (utc == NULL)
		return g_strdup ("?");
	if (fs_cli.utc) {
		text = g_date_time_format (utc, "%Y-%m-%dT%H:%M:%SZ");
		g_date_time_unref (utc);
		return text;
	}
	local = g_date_time_to_local (utc);
	text = g_date_time_format (local, local_format);
	g_date_time_unref (local);
	g_date_time_unref (utc);
	return text;
}

/* --------------------------------------------------------------- audit */

/* The words --action takes, and what each matches in an action. */
static const gchar *const action_words[] = {
	"apply", "start", "stop", "intel", "sentinel", "health", "trust",
	"policy", NULL
};

/* [ action_matches ]
 * WORD is a word of the action: "start" matches "firewall started"
 * and "firewall start refused", "trust" matches "trust-attest". */
static gboolean
action_matches (const gchar *action, const gchar *word)
{
	gchar **words = g_strsplit_set (action, " -:,()", -1);
	gboolean hit = FALSE;
	gchar *past = g_strconcat (word, "ed", NULL);
	gchar *pastp = g_strdup_printf ("%sped", word);   /* stopped */
	gchar *pasty = NULL;

	/* applied */
	if (g_str_has_suffix (word, "y"))
		pasty = g_strdup_printf ("%.*sied", (int) strlen (word) - 1, word);

	for (guint i = 0; words[i] != NULL && !hit; i++)
		hit = strcmp (words[i], word) == 0 ||
		      strcmp (words[i], past) == 0 ||
		      strcmp (words[i], pastp) == 0 ||
		      (pasty != NULL && strcmp (words[i], pasty) == 0);
	g_strfreev (words);
	g_free (past);
	g_free (pastp);
	g_free (pasty);
	return hit;
}

typedef struct
{
	const gchar *action;     /* --action word, or NULL     */
	gchar       *grep;       /* lower case, or NULL        */
	gint64       since;      /* seconds; 0: open           */
	gint64       until;
} AuditFilter;

static gboolean
audit_passes (const AuditFilter *f, const FsCliAuditEntry *e)
{
	if (f->since != 0 && e->epoch < f->since)
		return FALSE;
	if (f->until != 0 && e->epoch >= f->until)
		return FALSE;
	if (f->action != NULL && !action_matches (e->action, f->action))
		return FALSE;
	if (f->grep != NULL) {
		gchar *low = g_utf8_strdown (e->raw, -1);
		gboolean ok = strstr (low, f->grep) != NULL;

		g_free (low);
		if (!ok)
			return FALSE;
	}
	return TRUE;
}

static gchar **
audit_row (const FsCliAuditEntry *e)
{
	gchar **row = g_new0 (gchar *, 5);
	gchar **fields = g_strsplit (e->detail != NULL ? e->detail : "",
	                             " | ", -1);

	row[0] = when_text (e->epoch, "%Y-%m-%d %H:%M:%S");
	row[1] = g_strdup (e->action);
	row[2] = g_strdup (e->origin != NULL ? e->origin : "-");
	row[3] = g_strjoinv ("; ", fields);
	g_strfreev (fields);
	return row;
}

/* [ audit_print_live ] -- one row of a followed log, in fixed columns
 * so rows printed one at a time line up. */
static void
audit_print_live (const FsCliAuditEntry *e)
{
	if (fs_cli.json) {
		GString *out = g_string_new (NULL);

		fs_cli_audit_entry_json (out, e, TRUE);
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		gchar **row = audit_row (e);
		gchar *safe[4];

		for (guint i = 0; i < 4; i++)
			safe[i] = fs_cli_out_safe (row[i]);
		if (fs_cli.plain)
			printf ("%s\t%s\t%s\t%s\n", safe[0], safe[1], safe[2],
			        safe[3]);
		else
			printf ("%-19s  %-30s  %-4s  %s\n", safe[0], safe[1],
			        safe[2], safe[3]);
		for (guint i = 0; i < 4; i++)
			g_free (safe[i]);
		g_strfreev (row);
	}
	fflush (stdout);
}

typedef struct
{
	gchar       *path;
	goffset      offset;
	GString     *partial;
	AuditFilter *filter;
	GMainLoop   *loop;
} AuditFollow;

static gboolean
on_audit_poll (gpointer data)
{
	AuditFollow *f = data;
	GStatBuf st;
	FILE *file;
	gchar buf[4096];
	gsize got;

	if (g_stat (f->path, &st) != 0)
		return G_SOURCE_CONTINUE;      /* rotated away: wait for it */
	if ((goffset) st.st_size < f->offset) {
		f->offset = 0;                 /* cut short: read it afresh */
		g_string_truncate (f->partial, 0);
	}
	if ((goffset) st.st_size == f->offset)
		return G_SOURCE_CONTINUE;

	file = g_fopen (f->path, "rb");
	if (file == NULL)
		return G_SOURCE_CONTINUE;
	if (fseeko (file, (off_t) f->offset, SEEK_SET) == 0) {
		while ((got = fread (buf, 1, sizeof buf, file)) > 0) {
			f->offset += (goffset) got;
			g_string_append_len (f->partial, buf, (gssize) got);
		}
	}
	fclose (file);

	for (;;) {
		gchar *nl = memchr (f->partial->str, '\n', f->partial->len);
		gchar *line;
		FsCliAuditEntry *e;

		if (nl == NULL)
			break;
		line = g_strndup (f->partial->str,
		                  (gsize) (nl - f->partial->str));
		g_string_erase (f->partial, 0, nl - f->partial->str + 1);
		g_strchomp (line);
		e = fs_cli_audit_parse_line (line);
		if (e != NULL && audit_passes (f->filter, e))
			audit_print_live (e);
		else if (e == NULL && *line != '\0')
			fprintf (stderr, "stockfw: a damaged audit line was "
			         "skipped\n");
		fs_cli_audit_entry_free (e);
		g_free (line);
	}
	return G_SOURCE_CONTINUE;
}

static gboolean
on_audit_quit (gpointer data)
{
	g_main_loop_quit (data);
	return G_SOURCE_REMOVE;
}

/* [ sudo_user_note ]
 * Under sudo the log read is root's own.  When the invoking user has
 * one too (the desktop app's), say where it is; it is never read as
 * root unless asked for with --file. */
static void
sudo_user_note (const gchar *path)
{
#ifndef G_OS_WIN32
	const gchar *user = g_getenv ("SUDO_USER");
	struct passwd *pw;
	gchar *theirs;

	if (geteuid () != 0 || user == NULL || *user == '\0' || fs_cli.quiet)
		return;
	pw = getpwnam (user);
	if (pw == NULL || pw->pw_dir == NULL)
		return;
	theirs = g_build_filename (pw->pw_dir, ".config", "stockfw",
	                           "audit.log", NULL);
	if (strcmp (theirs, path) != 0 &&
	    g_file_test (theirs, G_FILE_TEST_EXISTS)) {
		gchar *u = fs_cli_out_safe (user);

		fs_cli_hint ("the desktop app's log for %s is %s; read it with "
		             "--file", u, theirs);
		g_free (u);
	}
	g_free (theirs);
#else
	(void) path;
#endif
}

static gint
fs_cli_cmd_audit (gint argc, gchar **argv)
{
	guint count = 20;
	gboolean follow = FALSE, reverse = FALSE;
	const gchar *since = NULL, *until = NULL, *file_opt = NULL;
	gint64 since_us = 0, until_us = 0;
	AuditFilter filter = { NULL, NULL, 0, 0 };
	GPtrArray *all, *shown;
	guint total = 0, bad = 0;
	gchar *path;
	GError *error = NULL;
	gint rc = FS_EXIT_OK;

	for (gint i = 1; i < argc; i++) {
		const gchar *v = NULL;
		gint st = FS_EXIT_OK;

		if (fs_cli_take_opt (argc, argv, &i, "-n", &v, &st) ||
		    fs_cli_take_opt (argc, argv, &i, "--limit", &v, &st)) {
			gchar *end = NULL;
			guint64 n;

			if (v == NULL)
				return st;
			n = g_ascii_strtoull (v, &end, 10);
			if (!g_ascii_isdigit (*v) || end == NULL || *end != '\0' ||
			    n > G_MAXUINT) {
				fs_cli_error ("-n wants a number (0: every entry)");
				return FS_EXIT_USAGE;
			}
			count = (guint) n;
		} else if (fs_cli_take_opt (argc, argv, &i, "--since", &v, &st)) {
			since = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--until", &v, &st)) {
			until = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--action", &v, &st)) {
			if (v != NULL && !g_strv_contains (action_words, v)) {
				const gchar *best = fs_cli_suggest (
					v, action_words, g_strv_length ((gchar **) action_words));

				fs_cli_error ("--action wants one of apply, start, stop, "
				              "intel, sentinel, health, trust, policy; "
				              "not `%s'", v);
				if (best != NULL)
					fs_cli_hint ("did you mean --action %s?", best);
				return FS_EXIT_USAGE;
			}
			filter.action = v;
		} else if (fs_cli_take_opt (argc, argv, &i, "--grep", &v, &st)) {
			if (v != NULL) {
				g_free (filter.grep);
				filter.grep = g_utf8_strdown (v, -1);
			}
		} else if (fs_cli_take_opt (argc, argv, &i, "--file", &v, &st)) {
			file_opt = v;
		} else if (!fs_cli_is_option_at (argv, i)) {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			g_free (filter.grep);
			return FS_EXIT_USAGE;
		} else if (strcmp (argv[i], "-f") == 0 ||
		           strcmp (argv[i], "--follow") == 0) {
			follow = TRUE;
		} else if (strcmp (argv[i], "-r") == 0 ||
		           strcmp (argv[i], "--reverse") == 0) {
			reverse = TRUE;
		} else if (strcmp (argv[i], "--utc") == 0) {
			fs_cli.utc = TRUE;
		} else {
			fs_cli_unknown_option ("audit", argv[i]);
			g_free (filter.grep);
			return FS_EXIT_USAGE;
		}
		if (st != FS_EXIT_OK) {
			g_free (filter.grep);
			return st;
		}
	}

	if (!fs_cli_parse_window (since, until, &since_us, &until_us)) {
		g_free (filter.grep);
		return FS_EXIT_USAGE;
	}
	filter.since = since != NULL ? since_us / G_USEC_PER_SEC : 0;
	filter.until = until != NULL ? until_us / G_USEC_PER_SEC : 0;

	if (file_opt != NULL) {
		GStatBuf st;

		/* Never follow a link or read a device someone pointed at. */
		if (g_lstat (file_opt, &st) != 0) {
			fs_cli_error ("cannot read %s: %s", file_opt,
			              g_strerror (errno));
			g_free (filter.grep);
			return FS_EXIT_FAILURE;
		}
		if (!S_ISREG (st.st_mode)) {
			fs_cli_error ("%s is not a regular file", file_opt);
			g_free (filter.grep);
			return FS_EXIT_FAILURE;
		}
		path = g_strdup (file_opt);
	} else {
		path = fs_audit_path ();
		sudo_user_note (path);
	}

	all = fs_cli_audit_read (path, &total, &bad, &error);
	if (all == NULL) {
		if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
			fs_cli_error ("nothing recorded yet: there is no audit log "
			              "at %s", path);
		else
			fs_cli_error ("%s", error->message);
		g_clear_error (&error);
		g_free (path);
		g_free (filter.grep);
		return FS_EXIT_FAILURE;
	}

	/* Never dropped without a word. */
	if (bad > 0)
		fprintf (stderr, "stockfw: %u damaged line%s skipped\n", bad,
		         bad == 1 ? "" : "s");

	shown = g_ptr_array_new ();
	for (guint i = 0; i < all->len; i++)
		if (audit_passes (&filter, g_ptr_array_index (all, i)))
			g_ptr_array_add (shown, g_ptr_array_index (all, i));
	if (count > 0)
		while (shown->len > count)
			g_ptr_array_remove_index (shown, 0);
	if (reverse)
		for (guint a = 0, b = shown->len; b > a + 1; a++, b--) {
			gpointer t = shown->pdata[a];

			shown->pdata[a] = shown->pdata[b - 1];
			shown->pdata[b - 1] = t;
		}

	if (fs_cli.json && !follow) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "file", path);           g_string_append_c (out, ',');
		fs_json_kv_uint (out, "lines_total", total);  g_string_append_c (out, ',');
		fs_json_kv_uint (out, "bad_lines", bad);      g_string_append_c (out, ',');
		g_string_append (out, "\"entries\":[");
		for (guint i = 0; i < shown->len; i++) {
			if (i > 0)
				g_string_append_c (out, ',');
			fs_cli_audit_entry_json (out, g_ptr_array_index (shown, i),
			                         TRUE);
		}
		g_string_append (out, "]}");
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (follow) {
		for (guint i = 0; i < shown->len; i++)
			audit_print_live (g_ptr_array_index (shown, i));
	} else {
		if (!fs_cli.plain && !fs_cli.quiet) {
			gchar *safe = fs_cli_out_safe (path);

			printf ("Audit log %s  (%u line%s", safe, total,
			        total == 1 ? "" : "s");
			if (all->len > 0) {
				const FsCliAuditEntry *first = g_ptr_array_index (all, 0);
				const FsCliAuditEntry *last =
					g_ptr_array_index (all, all->len - 1);
				gchar *d1 = when_text (first->epoch, "%Y-%m-%d");
				gchar *d2 = when_text (last->epoch, "%Y-%m-%d");

				printf (", %s %s %s", d1, fs_cli_sym (FS_CLI_SYM_ARROW),
				        d2);
				g_free (d1);
				g_free (d2);
			}
			printf (")\n");
			g_free (safe);
		}
		if (shown->len == 0) {
			if (!fs_cli.quiet && !fs_cli.plain)
				printf ("%sNo entries match.%s\n", fs_cli_dim (),
				        fs_cli_reset ());
		} else {
			static const gchar *headers[] = { "TIME", "ACTION", "FROM",
			                                  "DETAIL" };
			GPtrArray *rows = g_ptr_array_new_with_free_func (
				(GDestroyNotify) g_strfreev);

			for (guint i = 0; i < shown->len; i++)
				g_ptr_array_add (rows,
				                 audit_row (g_ptr_array_index (shown, i)));
			fs_cli_table_ex (headers, 4, rows, 0, 3);
			g_ptr_array_unref (rows);
		}
	}
	fflush (stdout);

	if (follow) {
		AuditFollow f = { path, 0, g_string_new (NULL), &filter, NULL };
		GStatBuf st;

		if (g_stat (path, &st) == 0)
			f.offset = (goffset) st.st_size;
		if (!fs_cli.json && !fs_cli.quiet)
			fprintf (stderr, "%sFollowing %s -- Ctrl-C to stop.%s\n",
			         fs_cli_dim (), path, fs_cli_reset ());
		f.loop = g_main_loop_new (NULL, FALSE);
		g_timeout_add (500, on_audit_poll, &f);
		g_unix_signal_add (SIGINT, on_audit_quit, f.loop);
		g_unix_signal_add (SIGTERM, on_audit_quit, f.loop);
		g_main_loop_run (f.loop);
		g_main_loop_unref (f.loop);
		g_string_free (f.partial, TRUE);
	}

	g_ptr_array_unref (shown);
	g_ptr_array_unref (all);
	g_free (path);
	g_free (filter.grep);
	return rc;
}

/* ------------------------------------------------------------ sentinel */

/* [ policy_ref ] -- "outbound-deny-to:3" for the rule in the saved
 * policy, or NULL when it is not there (lifted, or removed by hand). */
static gchar *
policy_ref (const FsPolicy *policy, const FsCliSentinelBlock *b)
{
	GPtrArray *rows;

	if (policy == NULL || b->rule == NULL)
		return NULL;
	rows = policy->kinds[b->kind];
	for (guint i = 0; i < rows->len; i++) {
		gchar *csv = fs_rule_to_csv (g_ptr_array_index (rows, i));
		gchar *mine = fs_rule_to_csv (b->rule);
		gboolean same = g_strcmp0 (csv, mine) == 0;

		g_free (csv);
		g_free (mine);
		if (same)
			return fs_cli_rule_ref (b->kind, i + 1);
	}
	return NULL;
}

static const gchar *
block_why (const FsCliSentinelBlock *b)
{
	const gchar *c = b->rule != NULL ? b->rule->comment : NULL;

	if (c == NULL)
		return "";
	if (g_str_has_prefix (c, "Sentinel:"))
		c += strlen ("Sentinel:");
	while (*c == ' ')
		c++;
	return c;
}

static gint
fs_cli_cmd_sentinel (gint argc, gchar **argv)
{
	static const gchar *const subs[] = { "list", NULL };
	gchar *path, *mode;
	GPtrArray *rows;
	guint bad = 0;
	GError *error = NULL;
	FsPolicy *policy;
	gint64 now = g_get_real_time () / G_USEC_PER_SEC;

	for (gint i = 1; i < argc; i++) {
		if (fs_cli_is_option_at (argv, i)) {
			fs_cli_unknown_option ("sentinel", argv[i]);
			return FS_EXIT_USAGE;
		}
		if (i == 1 && strcmp (argv[i], "list") == 0)
			continue;
		if (i == 1) {
			const gchar *best = fs_cli_suggest (argv[i], subs, 1);

			fs_cli_error ("unknown sentinel subcommand: %s", argv[i]);
			if (best != NULL)
				fs_cli_hint ("did you mean `sentinel %s'?", best);
			else
				fs_cli_hint ("this version only lists Sentinel's blocks: "
				             "`sentinel list'");
			return FS_EXIT_USAGE;
		}
		fs_cli_error ("unexpected argument: %s", argv[i]);
		return FS_EXIT_USAGE;
	}

	path = fs_autoblock_state_path ();
	mode = fs_prefs_get_string (FS_PREFS_SENTINEL_MODE, "auto");
	if (mode == NULL || *mode == '\0') {
		g_free (mode);
		mode = g_strdup ("auto");
	}
	rows = fs_cli_sentinel_read (path, &bad, &error);
	if (rows == NULL &&
	    !g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
		fs_cli_error ("%s", error->message);
		g_clear_error (&error);
		g_free (path);
		g_free (mode);
		return FS_EXIT_FAILURE;
	}
	g_clear_error (&error);
	if (rows == NULL)
		rows = g_ptr_array_new ();
	if (bad > 0)
		fprintf (stderr, "stockfw: %u damaged row%s in %s skipped\n", bad,
		         bad == 1 ? "" : "s", path);
	policy = fs_cli_load_policy (NULL, NULL);

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "mode", mode);   g_string_append_c (out, ',');
		fs_json_kv_str (out, "file", path);   g_string_append_c (out, ',');
		fs_json_kv_uint (out, "ttl_seconds", FS_AUTOBLOCK_TTL_S);
		g_string_append (out, ",\"blocks\":[");
		for (guint i = 0; i < rows->len; i++) {
			FsCliSentinelBlock *b = g_ptr_array_index (rows, i);
			gchar *ref = policy_ref (policy, b);
			gint64 lifts = b->epoch + FS_AUTOBLOCK_TTL_S;
			GDateTime *u = g_date_time_new_from_unix_utc (lifts);
			gchar *iso = u != NULL
			             ? g_date_time_format (u, "%Y-%m-%dT%H:%M:%SZ")
			             : NULL;

			if (i > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "target",
			                b->rule != NULL ? b->rule->target : NULL);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "kind", fs_cli_kind_name (b->kind));
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "rule_ref", ref);  g_string_append_c (out, ',');
			fs_json_kv_time (out, "staged", b->epoch);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "expires", iso);   g_string_append_c (out, ',');
			fs_json_kv_int (out, "expires_epoch", lifts);
			g_string_append_c (out, ',');
			fs_json_kv_bool (out, "expired", lifts <= now);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "why", block_why (b));
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "rule", b->csv);
			g_string_append_c (out, '}');
			g_free (iso);
			if (u != NULL)
				g_date_time_unref (u);
			g_free (ref);
		}
		g_string_append (out, "]}");
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		if (!fs_cli.plain && !fs_cli.quiet) {
			gchar *safe = fs_cli_out_safe (path);

			printf ("Sentinel %s  %s%s %s%s\n", mode, fs_cli_dim (),
			        fs_cli_sym (FS_CLI_SYM_SEP), safe, fs_cli_reset ());
			g_free (safe);
		}
		if (rows->len == 0) {
			if (!fs_cli.plain && !fs_cli.quiet)
				printf ("%sNothing staged.%s\n", fs_cli_dim (),
				        fs_cli_reset ());
		} else {
			static const gchar *headers[] = { "TARGET", "KIND", "STAGED",
			                                  "LIFTS", "WHY" };
			GPtrArray *table = g_ptr_array_new_with_free_func (
				(GDestroyNotify) g_strfreev);

			for (guint i = 0; i < rows->len; i++) {
				FsCliSentinelBlock *b = g_ptr_array_index (rows, i);
				gchar **row = g_new0 (gchar *, 6);
				gchar *ref = policy_ref (policy, b);
				gint64 lifts = b->epoch + FS_AUTOBLOCK_TTL_S;
				gchar *at = when_text (lifts, "%Y-%m-%d %H:%M:%S");

				row[0] = g_strdup (b->rule != NULL && b->rule->target
				                   ? b->rule->target : b->csv);
				row[1] = ref != NULL ? ref
				         : g_strdup_printf ("%s (not in the policy)",
				                            fs_cli_kind_name (b->kind));
				row[2] = when_text (b->epoch, "%Y-%m-%d %H:%M:%S");
				row[3] = lifts <= now
				         ? g_strdup_printf ("due since %s", at)
				         : g_strdup (at);
				row[4] = g_strdup (block_why (b));
				g_free (at);
				g_ptr_array_add (table, row);
			}
			fs_cli_table_ex (headers, 5, table, 0, 4);
			g_ptr_array_unref (table);
		}
		if (!fs_cli.quiet && !fs_cli.plain && rows->len > 0)
			fprintf (stderr, "%sA block lifts %u minutes after it was "
			         "staged.  This list is read-only.%s\n",
			         fs_cli_dim (), FS_AUTOBLOCK_TTL_S / 60,
			         fs_cli_reset ());
	}

	fs_policy_free (policy);
	g_ptr_array_unref (rows);
	g_free (path);
	g_free (mode);
	return FS_EXIT_OK;
}

/* === end WP-C === */

/* ------------------------------------------------------- the commands */

/* === WP-C commands === */
static const FsCliOption audit_opts[] = {
	{ "-n",        TRUE,  NULL },
	{ "--limit",   TRUE,  NULL },
	{ "--since",   TRUE,  NULL },
	{ "--until",   TRUE,  NULL },
	{ "--action",  TRUE,  NULL },
	{ "--grep",    TRUE,  NULL },
	{ "--file",    TRUE,  NULL },
	{ "-f",        FALSE, NULL },
	{ "--follow",  FALSE, NULL },
	{ "-r",        FALSE, NULL },
	{ "--reverse", FALSE, NULL },
	{ "--utc",     FALSE, NULL },
	{ NULL, FALSE, NULL }
};

static const FsCliOption sentinel_opts[] = {
	{ NULL, FALSE, NULL }
};
/* === end WP-C commands === */

const FsCliCommandDef fs_cli_views_commands[] = {
	/* === WP-C commands === */
	{ "audit", fs_cli_cmd_audit,
"Usage: stockfw audit [-n N] [--since T] [--until T] [--action A]\n"
"                     [--grep TEXT] [-r] [-f] [--utc] [--file PATH]\n"
"\n"
"The audit log: every apply, start and stop, and what threat intel,\n"
"Sentinel, the health check and Trust did, as StockFW wrote it.\n"
"The last N entries (default 20, 0 for all), oldest first; -r puts\n"
"the newest first.  --action keeps one kind: apply, start, stop,\n"
"intel, sentinel, health, trust or policy.  --grep keeps entries\n"
"that hold TEXT (any case).  Times are local; --utc gives ISO UTC.\n"
"-f keeps following new entries until Ctrl-C (with --json, one\n"
"object per line).  FROM is cli or gui where the line says so.\n"
"\n"
"The log is the account's own (STOCKFW_AUDIT_FILE overrides it), so\n"
"no root is needed; under sudo it is root's.  --file reads another\n"
"one, and must name a regular file.  Exit 1 when there is no log.\n",
	  audit_opts, NULL },

	{ "sentinel", fs_cli_cmd_sentinel,
"Usage: stockfw sentinel [list] [--json]\n"
"\n"
"Sentinel's staged blocks, read from its state file and never\n"
"changed: the address, the rule (as KIND:N in `policy list'), when it\n"
"was staged, when it lifts (ten minutes later) and why.  The header\n"
"gives Sentinel's mode (auto or detect).  Lifting a block by hand is\n"
"not in this version.\n",
	  sentinel_opts, NULL },
	/* === end WP-C commands === */
	{ NULL, NULL, NULL, NULL, NULL }
};
