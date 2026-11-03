/*---[ fs-cli-trust.c ]-------------------------------------------------
 * `stockfw trust': the desktop app's Trust page in a terminal (master
 * plan PR 4, package 4D; I1-I5).
 *
 * A file's SHA-256, size and date, and how it compares with the
 * baseline of files the user attested (core/fs-trust.h).  On Linux
 * there is no signature check, so the baseline is a hash baseline: it
 * tells that a file changed since it was attested, not who made it.
 *
 * The baseline is the user's own (trust.csv in the user's config
 * folder, or $STOCKFW_TRUST_FILE).  No root and no daemon: under sudo
 * it is root's baseline, and the command says so.  Attest and forget
 * ask first on a terminal, as the page does; without one they need
 * --yes, and never wait for an answer.  Each writes its audit line
 * (fs_trust_attest, fs_trust_remove), and the read, the change and the
 * save happen under an flock on <baseline>.lock, so two terminals
 * never lose each other's change.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "core/fs-json.h"
#include "core/fs-trust.h"
#include "core/fs-util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

/* === PR4-D === */

/* ------------------------------------------------------------- words */

/* The baseline column, in the page's words. */
static const gchar *
change_word (FsTrustChange change)
{
	switch (change) {
	case FS_TRUST_CHANGE_NEW:        return "not attested";
	case FS_TRUST_CHANGE_UNCHANGED:  return "matches";
	case FS_TRUST_CHANGE_CHANGED:    return "CHANGED";
	case FS_TRUST_CHANGE_GONE:       return "GONE";
	case FS_TRUST_CHANGE_UNREADABLE:
	default:                         return "unreadable";
	}
}

/* The same for --json. */
static const gchar *
change_key (FsTrustChange change)
{
	switch (change) {
	case FS_TRUST_CHANGE_NEW:        return "new";
	case FS_TRUST_CHANGE_UNCHANGED:  return "unchanged";
	case FS_TRUST_CHANGE_CHANGED:    return "changed";
	case FS_TRUST_CHANGE_GONE:       return "gone";
	case FS_TRUST_CHANGE_UNREADABLE:
	default:                         return "unreadable";
	}
}

static const gchar *
change_colour (FsTrustChange change)
{
	switch (change) {
	case FS_TRUST_CHANGE_UNCHANGED: return fs_cli_green ();
	case FS_TRUST_CHANGE_CHANGED:
	case FS_TRUST_CHANGE_GONE:      return fs_cli_red ();
	default:                        return fs_cli_amber ();
	}
}

static const gchar *
sig_key (FsTrustSignature sig)
{
	switch (sig) {
	case FS_TRUST_SIG_VALID:          return "valid";
	case FS_TRUST_SIG_INVALID:        return "invalid";
	case FS_TRUST_SIG_UNSIGNED:       return "unsigned";
	case FS_TRUST_SIG_NOT_APPLICABLE: return "not-applicable";
	case FS_TRUST_SIG_UNKNOWN:
	default:                          return "not-checked";
	}
}

/* --------------------------------------------------------- the store */

/* [ store_note ]
 * Under sudo the baseline is root's (the config folder of the account
 * that runs the command), not the user's: say so, once, on stderr. */
static void
store_note (const gchar *file)
{
	const gchar *who = g_getenv ("SUDO_USER");

	if (geteuid () != 0 || who == NULL || *who == '\0' ||
	    strcmp (who, "root") == 0)
		return;
	fs_cli_hint ("this is root's trust baseline (%s), not %s's: under sudo "
	             "the baseline is root's; run it without sudo for yours",
	             file, who);
}

/* [ abs_path ] -- the path as the baseline records it: absolute, so it
 * means the same file from any folder.  Symbolic links are kept: the
 * page attests the path typed, and so does this. */
static gchar *
abs_path (const gchar *path)
{
	return g_canonicalize_filename (path, NULL);
}

/* [ store_lock ]
 * flock on <baseline>.lock, made 0600 with the baseline's folder.  The
 * descriptor, or -1 with the error printed. */
static gint
store_lock (const gchar *file)
{
	gchar *lock_path = g_strconcat (file, ".lock", NULL);
	gchar *safe = fs_cli_out_safe (lock_path);
	gint fd;

	if (!fs_util_ensure_parent_dir (file)) {
		fs_cli_error ("cannot make the folder for %s", safe);
		g_free (safe);
		g_free (lock_path);
		return -1;
	}
	fd = open (lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0) {
		fs_cli_error ("cannot open %s: %s", safe, g_strerror (errno));
	} else {
		while (flock (fd, LOCK_EX) != 0) {
			if (errno == EINTR)
				continue;
			fs_cli_error ("cannot lock %s: %s", safe, g_strerror (errno));
			close (fd);
			fd = -1;
			break;
		}
	}
	g_free (safe);
	g_free (lock_path);
	return fd;
}

static void
store_unlock (gint fd)
{
	if (fd >= 0)
		close (fd);
}

/* [ confirm ]
 * The page's question, on a terminal.  TRUE to go on: --yes, or the
 * answer y.  Without a terminal on stdin it never asks and never
 * waits: it refuses and names --yes. */
static gboolean
confirm (gboolean yes, const gchar *question, const gchar *verb)
{
	gchar answer[16] = "";

	if (yes)
		return TRUE;
	if (!isatty (STDIN_FILENO)) {
		fs_cli_error ("refused: nothing to ask on (stdin is not a "
		              "terminal); pass --yes to %s", verb);
		return FALSE;
	}
	fprintf (stderr, "%s [y/N] ", question);
	fflush (stderr);
	if (fgets (answer, sizeof answer, stdin) != NULL &&
	    (g_ascii_strcasecmp (g_strstrip (answer), "y") == 0 ||
	     g_ascii_strcasecmp (answer, "yes") == 0))
		return TRUE;
	fs_cli_error ("not changed: the baseline was left as it was");
	return FALSE;
}

/* ----------------------------------------------------------- reports */

static gchar *
mtime_text (gint64 t)
{
	return t > 0 ? fs_cli_time_text (t, FS_CLI_TIME_FULL) : g_strdup ("-");
}

/* One assessment as JSON. */
static void
assessment_json (GString *out, const FsTrustAssessment *a)
{
	const FsTrustReport *rep = a->report;

	g_string_append_c (out, '{');
	fs_json_kv_str (out, "path", a->path);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "status", change_key (a->change));
	g_string_append_c (out, ',');
	fs_json_kv_bool (out, "readable", rep != NULL);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "sha256", rep != NULL ? rep->sha256 : NULL);
	g_string_append_c (out, ',');
	if (rep != NULL) {
		fs_json_kv_uint (out, "size", rep->size);
		g_string_append_c (out, ',');
		fs_json_kv_time (out, "modified", rep->mtime);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "executable", rep->executable);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "signature", sig_key (rep->sig));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "publisher", rep->publisher);
		g_string_append_c (out, ',');
	}
	fs_json_kv_str (out, "baseline_sha256", a->baseline_sha256);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "baseline_publisher", a->baseline_publisher);
	g_string_append_c (out, '}');
}

/* The report as the page shows it: File, Publisher, Signature,
 * SHA-256, Size, Modified, Baseline. */
static void
assessment_print (const FsTrustAssessment *a)
{
	const FsTrustReport *rep = a->report;
	gchar *path = fs_cli_out_safe (a->path);
	gchar *line;

	printf ("  %-10s %s\n", "File", path);
	if (rep == NULL) {
		printf ("  %-10s %s\n", "Signature", "File not found or unreadable");
	} else {
		gchar *pub = fs_cli_out_safe (rep->publisher);
		gchar *size = fs_cli_format_bytes (rep->size);
		gchar *when = mtime_text (rep->mtime);

		printf ("  %-10s %s\n", "Publisher",
		        rep->publisher != NULL ? pub : "(no signer)");
		printf ("  %-10s %s\n", "Signature", fs_trust_sig_name (rep->sig));
		printf ("  %-10s %s\n", "SHA-256", rep->sha256);
		printf ("  %-10s %s\n", "Size", size);
		printf ("  %-10s %s\n", "Modified", when);
		g_free (when);
		g_free (size);
		g_free (pub);
	}
	switch (a->change) {
	case FS_TRUST_CHANGE_NEW:
		line = g_strdup ("Not attested yet: this file is not in the "
		                 "baseline.");
		break;
	case FS_TRUST_CHANGE_UNCHANGED:
		line = g_strdup ("Matches the attested baseline.");
		break;
	case FS_TRUST_CHANGE_CHANGED:
		line = g_strdup_printf ("CHANGED since attestation.  The baseline "
		                        "has hash %s; the file on disk no longer "
		                        "matches it.", a->baseline_sha256);
		break;
	case FS_TRUST_CHANGE_GONE:
		line = g_strdup_printf ("GONE: attested earlier, now missing.  The "
		                        "baseline remembers hash %s.",
		                        a->baseline_sha256);
		break;
	default:
		line = g_strdup ("The file could not be read.");
		break;
	}
	{
		gchar *wrapped = fs_cli_wrap (line, 13);

		printf ("  %-10s %s%s%s\n", "Baseline", change_colour (a->change),
		        wrapped, fs_cli_reset ());
		g_free (wrapped);
	}
	g_free (line);
	g_free (path);
}

/* ---------------------------------------------------------- commands */

/* `trust inspect PATH...' (I1, I2). */
static gint
trust_inspect (gint argc, gchar **argv, FsTrustStore *store)
{
	gint status = FS_EXIT_OK;
	GString *out = fs_cli.json ? g_string_new ("{\"files\":[") : NULL;

	if (argc == 0) {
		fs_cli_error ("usage: stockfw trust inspect PATH...");
		if (out != NULL)
			g_string_free (out, TRUE);
		return FS_EXIT_USAGE;
	}
	for (gint i = 0; i < argc; i++) {
		gchar *path = abs_path (argv[i]);
		FsTrustAssessment *a = fs_trust_assess (store, path);

		if (a->report == NULL)
			status = FS_EXIT_FAILURE;
		if (out != NULL) {
			if (i > 0)
				g_string_append_c (out, ',');
			assessment_json (out, a);
		} else {
			if (i > 0)
				printf ("\n");
			assessment_print (a);
		}
		fs_trust_assessment_free (a);
		g_free (path);
	}
	if (out != NULL) {
		g_string_append (out, "],");
		fs_json_kv_str (out, "baseline", fs_trust_store_file (store));
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	}
	return status;
}

/* `trust list' (I5) and `trust check [PATH...]': every baseline row
 * hashed again (or the paths given).  check exits 1 when one is
 * CHANGED or GONE. */
static gint
trust_list (gint argc, gchar **argv, FsTrustStore *store, gboolean check)
{
	static const gchar *headers[] = { "PATH", "PUBLISHER", "SHA-256",
	                                  "STATUS" };
	GPtrArray *paths = g_ptr_array_new_with_free_func (g_free);
	GPtrArray *rows = g_ptr_array_new_with_free_func (
		(GDestroyNotify) g_strfreev);
	GString *out = fs_cli.json ? g_string_new ("{\"files\":[") : NULL;
	guint changed = 0, gone = 0, same = 0;
	gint status;

	if (!check && argc > 0) {
		fs_cli_error ("trust list takes no arguments");
		fs_cli_hint ("`stockfw trust check PATH...' checks some files");
		g_ptr_array_unref (paths);
		g_ptr_array_unref (rows);
		if (out != NULL)
			g_string_free (out, TRUE);
		return FS_EXIT_USAGE;
	}
	if (argc > 0) {
		for (gint i = 0; i < argc; i++)
			g_ptr_array_add (paths, abs_path (argv[i]));
	} else {
		for (guint i = 0; i < fs_trust_store_count (store); i++)
			g_ptr_array_add (paths,
			                 g_strdup (fs_trust_store_path_at (store, i)));
	}

	for (guint i = 0; i < paths->len; i++) {
		FsTrustAssessment *a = fs_trust_assess (store,
		                                        g_ptr_array_index (paths, i));
		const FsTrustReport *rep = a->report;
		gchar **row = g_new0 (gchar *, 5);

		if (a->change == FS_TRUST_CHANGE_CHANGED)
			changed++;
		else if (a->change == FS_TRUST_CHANGE_GONE)
			gone++;
		else if (a->change == FS_TRUST_CHANGE_UNCHANGED)
			same++;
		if (out != NULL) {
			if (i > 0)
				g_string_append_c (out, ',');
			assessment_json (out, a);
		}
		row[0] = g_strdup (a->path);
		row[1] = g_strdup (rep != NULL && rep->publisher != NULL
		                   ? rep->publisher
		                   : a->baseline_publisher != NULL
		                   ? a->baseline_publisher : "(no signer)");
		row[2] = g_strdup (rep != NULL ? rep->sha256
		                   : a->baseline_sha256 != NULL
		                   ? a->baseline_sha256 : "-");
		row[3] = g_strdup (change_word (a->change));
		g_ptr_array_add (rows, row);
		fs_trust_assessment_free (a);
	}

	status = check && (changed > 0 || gone > 0) ? FS_EXIT_FAILURE
	                                            : FS_EXIT_OK;
	if (out != NULL) {
		g_string_append (out, "],");
		fs_json_kv_str (out, "baseline", fs_trust_store_file (store));
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "attested", fs_trust_store_count (store));
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "unchanged", same);
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "changed", changed);
		g_string_append_c (out, ',');
		fs_json_kv_uint (out, "gone", gone);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (paths->len == 0) {
		gchar *safe = fs_cli_out_safe (fs_trust_store_file (store));

		if (!fs_cli.quiet)
			printf ("The baseline is empty (%s).  `stockfw trust attest "
			        "FILE' adds a file.\n", safe);
		g_free (safe);
	} else {
		if (!fs_cli.quiet || changed > 0 || gone > 0)
			fs_cli_table_ex (headers, 4, rows, 0, 0);
		if (!fs_cli.quiet) {
			gchar *safe = fs_cli_out_safe (fs_trust_store_file (store));

			printf ("\n%s%u attested in %s: %u match%s, %u changed, %u "
			        "gone.%s\n", fs_cli_dim (), fs_trust_store_count (store),
			        safe, same, same == 1 ? "" : "es", changed, gone,
			        fs_cli_reset ());
			g_free (safe);
		}
	}
	g_ptr_array_unref (rows);
	g_ptr_array_unref (paths);
	return status;
}

/* `trust attest PATH [--yes]' (I3): the page's "Attest this file as
 * trusted?" with the path and the hash, then the baseline records
 * exactly the bytes that were shown. */
static gint
trust_attest (const gchar *arg, gboolean yes, const gchar *file)
{
	gchar *path = abs_path (arg);
	gchar *safe = fs_cli_out_safe (path);
	GError *error = NULL;
	FsTrustReport *rep = fs_trust_inspect (path, &error);
	FsTrustStore *store;
	gchar *question;
	gint fd, status = FS_EXIT_OK;

	if (rep == NULL) {
		fs_cli_error ("cannot read %s: %s", safe,
		              error != NULL ? error->message : "unknown error");
		g_clear_error (&error);
		g_free (safe);
		g_free (path);
		return FS_EXIT_FAILURE;
	}
	question = g_strdup_printf ("Attest this file as trusted?\n\n  %s\n\n  "
	                            "SHA-256: %s\n\nThe attestation is recorded "
	                            "in the audit log.  Attest?", safe,
	                            rep->sha256);
	if (!confirm (yes, question, "attest it")) {
		g_free (question);
		fs_trust_report_free (rep);
		g_free (safe);
		g_free (path);
		return FS_EXIT_FAILURE;
	}
	g_free (question);

	fd = store_lock (file);
	if (fd < 0) {
		fs_trust_report_free (rep);
		g_free (safe);
		g_free (path);
		return FS_EXIT_FAILURE;
	}
	/* Read again under the lock: another terminal's change is kept. */
	store = fs_trust_store_load (file);
	if (!fs_trust_attest (store, rep)) {
		fs_cli_error ("the baseline could not record the attestation");
		status = FS_EXIT_FAILURE;
	} else if (!fs_trust_store_save (store, &error)) {
		fs_cli_error ("the baseline could not be saved: %s",
		              error != NULL ? error->message : "unknown error");
		g_clear_error (&error);
		status = FS_EXIT_FAILURE;
	}
	store_unlock (fd);

	if (status == FS_EXIT_OK) {
		if (fs_cli.json) {
			GString *out = g_string_new ("{");

			fs_json_kv_bool (out, "attested", TRUE);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "path", path);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "sha256", rep->sha256);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "baseline", file);
			g_string_append_c (out, '}');
			fs_cli_print_json (out);
			g_string_free (out, TRUE);
		} else if (!fs_cli.quiet) {
			printf ("%sAttested%s %s (SHA-256 %s), and recorded in the "
			        "audit log.\n", fs_cli_green (), fs_cli_reset (), safe,
			        rep->sha256);
		}
	}
	fs_trust_store_free (store);
	fs_trust_report_free (rep);
	g_free (safe);
	g_free (path);
	return status;
}

/* `trust forget PATH [--yes]' (I4). */
static gint
trust_forget (const gchar *arg, gboolean yes, const gchar *file)
{
	gchar *path = abs_path (arg);
	gchar *safe = fs_cli_out_safe (path);
	FsTrustStore *store = fs_trust_store_load (file);
	FsTrustAssessment *a = fs_trust_assess (store, path);
	GError *error = NULL;
	gboolean known = a->baseline_sha256 != NULL;
	gchar *question;
	gint fd, status = FS_EXIT_OK;

	fs_trust_assessment_free (a);
	fs_trust_store_free (store);
	if (!known) {
		fs_cli_error ("%s is not in the baseline", safe);
		fs_cli_hint ("`stockfw trust list' shows what is");
		g_free (safe);
		g_free (path);
		return FS_EXIT_FAILURE;
	}
	question = g_strdup_printf ("Remove this file from the trust baseline?"
	                            "\n\n  %s\n\nThe removal is recorded in the "
	                            "audit log.  Remove it?", safe);
	if (!confirm (yes, question, "remove it")) {
		g_free (question);
		g_free (safe);
		g_free (path);
		return FS_EXIT_FAILURE;
	}
	g_free (question);

	fd = store_lock (file);
	if (fd < 0) {
		g_free (safe);
		g_free (path);
		return FS_EXIT_FAILURE;
	}
	store = fs_trust_store_load (file);
	if (!fs_trust_remove (store, path)) {
		/* Another terminal forgot it in the meantime. */
		fs_cli_error ("%s is not in the baseline any more", safe);
		status = FS_EXIT_FAILURE;
	} else if (!fs_trust_store_save (store, &error)) {
		fs_cli_error ("the baseline could not be saved: %s",
		              error != NULL ? error->message : "unknown error");
		g_clear_error (&error);
		status = FS_EXIT_FAILURE;
	}
	store_unlock (fd);
	fs_trust_store_free (store);

	if (status == FS_EXIT_OK) {
		if (fs_cli.json) {
			GString *out = g_string_new ("{");

			fs_json_kv_bool (out, "forgotten", TRUE);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "path", path);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "baseline", file);
			g_string_append_c (out, '}');
			fs_cli_print_json (out);
			g_string_free (out, TRUE);
		} else if (!fs_cli.quiet) {
			printf ("%sForgotten:%s %s is no longer in the baseline; "
			        "recorded in the audit log.\n", fs_cli_red (),
			        fs_cli_reset (), safe);
		}
	}
	g_free (safe);
	g_free (path);
	return status;
}

static gint
fs_cli_cmd_trust (gint argc, gchar **argv)
{
	const gchar *sub = argc > 1 ? argv[1] : "list";
	gchar *file = fs_trust_store_path ();
	GPtrArray *words = g_ptr_array_new ();
	gboolean yes = FALSE;
	gint status;

	/* The words after the action, and --yes. */
	for (gint i = 2; i < argc; i++) {
		if (fs_cli_is_option_at (argv, i) &&
		    (strcmp (argv[i], "--yes") == 0 || strcmp (argv[i], "-y") == 0)) {
			yes = TRUE;
		} else if (fs_cli_is_option_at (argv, i)) {
			fs_cli_unknown_option ("trust", argv[i]);
			g_ptr_array_unref (words);
			g_free (file);
			return FS_EXIT_USAGE;
		} else {
			g_ptr_array_add (words, argv[i]);
		}
	}
	if (yes && strcmp (sub, "attest") != 0 && strcmp (sub, "forget") != 0) {
		fs_cli_error ("--yes goes with trust attest and trust forget");
		g_ptr_array_unref (words);
		g_free (file);
		return FS_EXIT_USAGE;
	}
	if (!fs_cli.json)
		store_note (file);

	if (strcmp (sub, "attest") == 0 || strcmp (sub, "forget") == 0) {
		if (words->len != 1) {
			fs_cli_error ("usage: stockfw trust %s PATH [--yes]", sub);
			status = FS_EXIT_USAGE;
		} else if (strcmp (sub, "attest") == 0) {
			status = trust_attest (g_ptr_array_index (words, 0), yes, file);
		} else {
			status = trust_forget (g_ptr_array_index (words, 0), yes, file);
		}
	} else if (strcmp (sub, "inspect") == 0 || strcmp (sub, "list") == 0 ||
	           strcmp (sub, "ls") == 0 || strcmp (sub, "check") == 0) {
		FsTrustStore *store = fs_trust_store_load (file);

		if (strcmp (sub, "inspect") == 0)
			status = trust_inspect ((gint) words->len,
			                        (gchar **) words->pdata, store);
		else
			status = trust_list ((gint) words->len,
			                     (gchar **) words->pdata, store,
			                     strcmp (sub, "check") == 0);
		fs_trust_store_free (store);
	} else {
		static const gchar *subs[] = { "inspect", "list", "check",
		                               "attest", "forget" };
		const gchar *best = fs_cli_suggest (sub, subs, G_N_ELEMENTS (subs));

		if (best != NULL)
			fs_cli_error ("unknown trust action: %s (did you mean %s?)",
			              sub, best);
		else
			fs_cli_error ("unknown trust action: %s", sub);
		fs_cli_hint ("see `stockfw help trust'");
		status = FS_EXIT_USAGE;
	}
	g_ptr_array_unref (words);
	g_free (file);
	return status;
}

static const FsCliOption trust_opts[] = {
	{ "--yes", FALSE, NULL },
	{ "-y",    FALSE, NULL },
	{ NULL, FALSE, NULL }
};

const FsCliCommandDef fs_cli_trust_commands[] = {
	{ "trust", fs_cli_cmd_trust,
"Usage: stockfw trust [list]                Every attested file, hashed again\n"
"       stockfw trust check [PATH...]       The same; exit 1 on CHANGED or GONE\n"
"       stockfw trust inspect PATH...       A file's hash, size, date, baseline\n"
"       stockfw trust attest PATH [--yes]   Record the file as it is now\n"
"       stockfw trust forget PATH [--yes]   Take it out of the baseline\n"
"\n"
"The Trust page of the desktop app.  A file you attest is recorded with\n"
"its SHA-256; `check' (and `list') hash every attested file again and\n"
"say whether it still matches (matches), changed since you attested it\n"
"(CHANGED) or is missing (GONE).  On Linux there is no signature check:\n"
"the baseline tells you that a file changed, not who made it.\n"
"\n"
"The baseline is yours: trust.csv in your config folder\n"
"(~/.config/stockfw), or $STOCKFW_TRUST_FILE.  No root is needed.  Under\n"
"sudo the baseline is root's, not yours, and the command says so.\n"
"Paths are recorded absolute.  Attest and forget ask first on a\n"
"terminal and write an audit line; without a terminal they need --yes\n"
"and never wait for an answer.\n"
"\n"
"Exit status: 0 done; 1 check found a file CHANGED or GONE, inspect\n"
"could not read a file, attest or forget was refused or failed; 2 usage.\n",
	  trust_opts, NULL },

	{ NULL, NULL, NULL, NULL, NULL }
};

/* === end PR4-D === */
