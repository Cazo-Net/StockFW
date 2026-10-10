/*---[ fs-trust.c ]------------------------------------------------------
 * Application trust engine: portable half.
 *
 * Hashes and file facts come from GLib alone; Authenticode is the
 * platform's job and arrives through a provider callback.  The store
 * is a quoted CSV so a path or a publisher name may hold a comma
 * without lying about the columns.  Every attestation is appended to
 * the audit log -- the baseline is a claim about what a file *was*,
 * and the log is the only witness history we keep.
 *--------------------------------------------------------------------*/
#include <string.h>
#include <gio/gio.h>

#include "core/fs-trust.h"
#include "core/fs-audit.h"

/*------------------------------------------------------ provider slot */

static FsTrustSignatureFunc trust_sig_fn    = NULL;
static gpointer             trust_sig_user  = NULL;

void
fs_trust_set_signature_provider (FsTrustSignatureFunc fn, gpointer user_data)
{
	trust_sig_fn   = fn;
	trust_sig_user = user_data;
}

const gchar *
fs_trust_sig_name (FsTrustSignature sig)
{
	switch (sig) {
	case FS_TRUST_SIG_VALID:         return "Signed and verified";
	case FS_TRUST_SIG_INVALID:       return "Signed but invalid";
	case FS_TRUST_SIG_UNSIGNED:      return "Not signed";
	case FS_TRUST_SIG_NOT_APPLICABLE: return "Not an executable";
	case FS_TRUST_SIG_UNKNOWN:
	default:                         return "Signature not checked";
	}
}

/*----------------------------------------------------------- inspect */

FsTrustReport *
fs_trust_inspect (const gchar *path, GError **error)
{
	GFile *file;
	GFileInfo *info;
	GInputStream *stream;
	GChecksum *sum;
	FsTrustReport *report;
	gchar head[2];
	gchar buffer[65536];
	gssize n, head_n;
	gchar *publisher = NULL;
	FsTrustSignature sig;
	GError *local = NULL;

	if (path == NULL || *path == '\0') {
		g_set_error_literal (error, G_IO_ERROR,
		                     G_IO_ERROR_INVALID_ARGUMENT,
		                     "no path to inspect");
		return NULL;
	}

	file = g_file_new_for_path (path);
	info = g_file_query_info (file,
	                          G_FILE_ATTRIBUTE_STANDARD_SIZE ","
	                          G_FILE_ATTRIBUTE_TIME_MODIFIED,
	                          G_FILE_QUERY_INFO_NONE, NULL,
	                          error);
	if (info == NULL) {
		g_object_unref (file);
		return NULL;
	}

	stream = G_INPUT_STREAM (g_file_read (file, NULL, &local));
	g_object_unref (file);
	if (stream == NULL) {
		g_propagate_error (error, local);
		g_object_unref (info);
		return NULL;
	}

	/* One pass over the bytes: the first two decide executability,
	 * the whole stream feeds the hash.  A file this small on screen
	 * can be two hundred megabytes on disk, so no read_to_end. */
	sum = g_checksum_new (G_CHECKSUM_SHA256);

	head_n = g_input_stream_read (stream, head, 2, NULL, &local);
	if (head_n < 0) {
		g_propagate_error (error, local);
		g_checksum_free (sum);
		g_object_unref (stream);
		g_object_unref (info);
		return NULL;
	}
	if (head_n > 0)
		g_checksum_update (sum, head, (gsize) head_n);

	while ((n = g_input_stream_read (stream, buffer, sizeof (buffer),
	                                 NULL, &local)) > 0)
		g_checksum_update (sum, buffer, (gsize) n);

	if (n < 0) {
		/* A hash we could not finish is not a hash: refuse the
		 * report rather than hand out a half-measured digest. */
		g_propagate_error (error, local);
		g_checksum_free (sum);
		g_object_unref (stream);
		g_object_unref (info);
		return NULL;
	}

	g_input_stream_close (stream, NULL, NULL);
	g_object_unref (stream);

	report = g_new0 (FsTrustReport, 1);
	report->path   = g_strdup (path);
	report->size   = g_file_info_get_size (info);
	report->sha256 = g_strdup (g_checksum_get_string (sum));
	g_checksum_free (sum);

	{
		GDateTime *mtime_dt = g_file_info_get_modification_date_time (info);

		if (mtime_dt != NULL) {
			report->mtime = g_date_time_to_unix (mtime_dt);
			g_date_time_unref (mtime_dt);
		}
	}
	g_object_unref (info);

	report->executable = (head_n == 2 && head[0] == 'M' &&
	                      head[1] == 'Z');

	if (!report->executable) {
		report->sig = FS_TRUST_SIG_NOT_APPLICABLE;
		return report;
	}

	sig = FS_TRUST_SIG_UNKNOWN;
	if (trust_sig_fn != NULL &&
	    trust_sig_fn (path, &sig, &publisher, trust_sig_user)) {
		report->sig       = sig;
		report->publisher = publisher;
	} else {
		/* Executable, nobody to ask: honest ignorance beats a
		 * guessed state. */
		report->sig = FS_TRUST_SIG_UNKNOWN;
		g_free (publisher);
	}

	return report;
}

void
fs_trust_report_free (FsTrustReport *report)
{
	if (report == NULL)
		return;

	g_free (report->path);
	g_free (report->sha256);
	g_free (report->publisher);
	g_free (report);
}

/*--------------------------------------------------------- assessment */

void
fs_trust_assessment_free (FsTrustAssessment *assessment)
{
	if (assessment == NULL)
		return;

	fs_trust_report_free (assessment->report);
	g_free (assessment->baseline_sha256);
	g_free (assessment->baseline_publisher);
	g_free (assessment->path);
	g_free (assessment);
}

/*-------------------------------------------------------------- store */

typedef struct
{
	gchar *path;
	gchar *sha256;
	guint64 size;
	gint64 mtime;
	FsTrustSignature sig;
	gchar *publisher;
	gint64 first_seen;
	gint64 last_seen;
} FsTrustEntry;

struct _FsTrustStore
{
	gchar *file;
	GPtrArray *rows;   /* FsTrustEntry*, insertion order */
};

static void
entry_free (gpointer data)
{
	FsTrustEntry *entry = data;

	if (entry == NULL)
		return;

	g_free (entry->path);
	g_free (entry->sha256);
	g_free (entry->publisher);
	g_free (entry);
}

gchar *
fs_trust_store_path (void)
{
	const gchar *env = g_getenv ("STOCKFW_TRUST_FILE");

	if (env != NULL && *env != '\0')
		return g_strdup (env);

#ifdef G_OS_WIN32
	/* Same home as stockfw.conf: the roaming AppData folder, not the
	 * local one g_get_user_config_dir() would give us. */
	{
		const gchar *appdata = g_getenv ("APPDATA");

		if (appdata != NULL && *appdata != '\0')
			return g_build_filename (appdata, "stockfw",
			                         "trust.csv", NULL);

		return g_build_filename (g_get_home_dir (), "AppData",
		                         "Roaming", "stockfw", "trust.csv",
		                         NULL);
	}
#else
	return g_build_filename (g_get_user_config_dir (), "stockfw",
	                         "trust.csv", NULL);
#endif
}

FsTrustStore *
fs_trust_store_new (const gchar *csv_path)
{
	FsTrustStore *store = g_new0 (FsTrustStore, 1);

	store->file = g_strdup (csv_path);
	store->rows = g_ptr_array_new_with_free_func (entry_free);

	return store;
}

void
fs_trust_store_free (FsTrustStore *store)
{
	if (store == NULL)
		return;

	g_ptr_array_unref (store->rows);
	g_free (store->file);
	g_free (store);
}

const gchar *
fs_trust_store_file (FsTrustStore *store)
{
	return store != NULL ? store->file : NULL;
}

guint
fs_trust_store_count (FsTrustStore *store)
{
	return store != NULL ? store->rows->len : 0;
}

/* Windows paths do not distinguish case, so neither does the lookup.
 * ASCII folding is enough: both sides of a Windows path are ASCII
 * for comparison purposes, and over-folding one exotic Linux path
 * cannot pick the wrong hash. */
static FsTrustEntry *
store_lookup (FsTrustStore *store, const gchar *path)
{
	guint i;

	if (store == NULL || path == NULL)
		return NULL;

	for (i = 0; i < store->rows->len; i++) {
		FsTrustEntry *entry = g_ptr_array_index (store->rows, i);

		if (g_ascii_strcasecmp (entry->path, path) == 0)
			return entry;
	}

	return NULL;
}

/*----------------------------------------------------------- CSV I/O */

/* Quote a field the way a spreadsheet would: only when it must. */
static void
csv_append_field (GString *out, const gchar *value, gboolean first)
{
	gboolean quote;

	if (!first)
		g_string_append_c (out, ',');

	if (value == NULL)
		value = "";

	quote = (strchr (value, ',') != NULL ||
	         strchr (value, '"') != NULL ||
	         strchr (value, '\n') != NULL ||
	         strchr (value, '\r') != NULL);

	if (!quote) {
		g_string_append (out, value);
		return;
	}

	g_string_append_c (out, '"');
	for (; *value != '\0'; value++) {
		if (*value == '"')
			g_string_append_c (out, '"');
		g_string_append_c (out, *value);
	}
	g_string_append_c (out, '"');
}

/* Split one line into fields, honouring quotes.  Returns a GPtrArray
 * of gchar* (caller frees with g_ptr_array_unref). */
static GPtrArray *
csv_split_line (const gchar *line)
{
	GPtrArray *fields = g_ptr_array_new_with_free_func (g_free);
	GString *field = g_string_new (NULL);
	gboolean quoted = FALSE;
	gboolean started = FALSE;

	while (*line != '\0') {
		if (quoted) {
			if (*line == '"') {
				if (*(line + 1) == '"') {
					g_string_append_c (field, '"');
					line += 2;
					continue;
				}
				quoted = FALSE;
				line++;
				continue;
			}
			g_string_append_c (field, *line);
			line++;
			continue;
		}

		if (*line == '"' && !started) {
			quoted = TRUE;
			started = TRUE;
			line++;
			continue;
		}
		if (*line == ',') {
			g_ptr_array_add (fields, g_string_free (field, FALSE));
			field = g_string_new (NULL);
			started = FALSE;
			line++;
			continue;
		}
		g_string_append_c (field, *line);
		started = TRUE;
		line++;
	}
	g_ptr_array_add (fields, g_string_free (field, FALSE));

	return fields;
}

static const gchar *
sig_to_token (FsTrustSignature sig)
{
	switch (sig) {
	case FS_TRUST_SIG_VALID:          return "valid";
	case FS_TRUST_SIG_INVALID:        return "invalid";
	case FS_TRUST_SIG_UNSIGNED:       return "unsigned";
	case FS_TRUST_SIG_NOT_APPLICABLE: return "na";
	case FS_TRUST_SIG_UNKNOWN:
	default:                          return "unknown";
	}
}

static FsTrustSignature
sig_from_token (const gchar *token)
{
	if (g_strcmp0 (token, "valid") == 0)
		return FS_TRUST_SIG_VALID;
	if (g_strcmp0 (token, "invalid") == 0)
		return FS_TRUST_SIG_INVALID;
	if (g_strcmp0 (token, "unsigned") == 0)
		return FS_TRUST_SIG_UNSIGNED;
	if (g_strcmp0 (token, "na") == 0)
		return FS_TRUST_SIG_NOT_APPLICABLE;
	return FS_TRUST_SIG_UNKNOWN;
}

FsTrustStore *
fs_trust_store_load (const gchar *csv_path)
{
	FsTrustStore *store = fs_trust_store_new (csv_path);
	gchar *contents = NULL;
	gchar **lines = NULL;
	gsize i;

	if (csv_path == NULL)
		return store;

	if (!g_file_get_contents (csv_path, &contents, NULL, NULL))
		return store;   /* missing file: an empty baseline */

	lines = g_strsplit (contents, "\n", -1);
	g_free (contents);

	for (i = 0; lines[i] != NULL; i++) {
		GPtrArray *fields;
		const gchar *line = lines[i];
		FsTrustEntry *entry;
		gchar *end = NULL;

		/* Trailing CR from an editor on another platform. */
		g_strchomp (lines[i]);

		if (*line == '\0' || *line == '#')
			continue;

		fields = csv_split_line (line);
		if (fields->len != 8) {
			g_ptr_array_unref (fields);
			continue;   /* one bad row must not lose the store */
		}

		entry = g_new0 (FsTrustEntry, 1);
		entry->path   = g_strdup (g_ptr_array_index (fields, 0));
		entry->sha256 = g_strdup (g_ptr_array_index (fields, 1));
		entry->size   = g_ascii_strtoull (g_ptr_array_index (fields, 2),
		                                  &end, 10);
		entry->mtime  = g_ascii_strtoll (g_ptr_array_index (fields, 3),
		                                 &end, 10);
		entry->sig    = sig_from_token (g_ptr_array_index (fields, 4));
		entry->publisher = g_strdup (g_ptr_array_index (fields, 5));
		entry->first_seen = g_ascii_strtoll (g_ptr_array_index (fields, 6),
		                                     &end, 10);
		entry->last_seen = g_ascii_strtoll (g_ptr_array_index (fields, 7),
		                                    &end, 10);
		g_ptr_array_unref (fields);

		/* A row without a path or a hash says nothing; drop it. */
		if (*entry->path == '\0' || *entry->sha256 == '\0') {
			entry_free (entry);
			continue;
		}
		if (entry->publisher != NULL && *entry->publisher == '\0') {
			g_free (entry->publisher);
			entry->publisher = NULL;
		}

		g_ptr_array_add (store->rows, entry);
	}

	g_strfreev (lines);
	return store;
}

gboolean
fs_trust_store_save (FsTrustStore *store, GError **error)
{
	GString *out;
	guint i;
	gboolean ok;

	if (store == NULL || store->file == NULL) {
		g_set_error_literal (error, G_IO_ERROR,
		                     G_IO_ERROR_INVALID_ARGUMENT,
		                     "trust store has no file to write");
		return FALSE;
	}

	out = g_string_new ("# StockFW trust baseline v1\n");

	for (i = 0; i < store->rows->len; i++) {
		FsTrustEntry *entry = g_ptr_array_index (store->rows, i);
		gchar size[32], mtime[32], first[32], last[32];

		g_snprintf (size, sizeof (size), "%" G_GUINT64_FORMAT,
		            entry->size);
		g_snprintf (mtime, sizeof (mtime), "%" G_GINT64_FORMAT,
		            entry->mtime);
		g_snprintf (first, sizeof (first), "%" G_GINT64_FORMAT,
		            entry->first_seen);
		g_snprintf (last, sizeof (last), "%" G_GINT64_FORMAT,
		            entry->last_seen);

		csv_append_field (out, entry->path, i == 0);
		/* After the first row a comma is needed before every field
		 * of the row -- including the first.  csv_append_field's
		 * `first' only skips that separator, so append the rest
		 * with first = FALSE. */
		csv_append_field (out, entry->sha256, FALSE);
		csv_append_field (out, size, FALSE);
		csv_append_field (out, mtime, FALSE);
		csv_append_field (out, sig_to_token (entry->sig), FALSE);
		csv_append_field (out, entry->publisher, FALSE);
		csv_append_field (out, first, FALSE);
		csv_append_field (out, last, FALSE);
		g_string_append_c (out, '\n');
	}

	ok = g_file_set_contents (store->file, out->str, out->len,
	                          error);
	g_string_free (out, TRUE);
	return ok;
}

/*----------------------------------------------------- assess / attest */

FsTrustAssessment *
fs_trust_assess (FsTrustStore *store, const gchar *path)
{
	FsTrustAssessment *assessment;
	FsTrustEntry *entry;
	GError *local = NULL;

	if (path == NULL)
		return NULL;

	assessment = g_new0 (FsTrustAssessment, 1);
	assessment->path = g_strdup (path);

	entry = store_lookup (store, path);
	if (entry != NULL) {
		assessment->baseline_sha256    = g_strdup (entry->sha256);
		assessment->baseline_publisher = g_strdup (entry->publisher);
	}

	assessment->report = fs_trust_inspect (path, &local);
	if (local != NULL)
		g_error_free (local);   /* the outcome is the enum below */

	if (assessment->report == NULL) {
		if (entry != NULL)
			assessment->change = FS_TRUST_CHANGE_GONE;
		else
			assessment->change = FS_TRUST_CHANGE_UNREADABLE;
	} else if (entry == NULL) {
		assessment->change = FS_TRUST_CHANGE_NEW;
	} else if (g_ascii_strcasecmp (assessment->report->sha256,
	                                entry->sha256) == 0) {
		assessment->change = FS_TRUST_CHANGE_UNCHANGED;
	} else {
		/* Same path, other bytes: the file was replaced since the
		 * user vouched for it.  This is the row P1 exists for. */
		assessment->change = FS_TRUST_CHANGE_CHANGED;
	}

	return assessment;
}

gboolean
fs_trust_attest (FsTrustStore *store, const FsTrustReport *report)
{
	FsTrustEntry *entry;
	gint64 now;
	gchar *detail;

	if (store == NULL || store->file == NULL || report == NULL ||
	    report->path == NULL || report->sha256 == NULL)
		return FALSE;

	now = (gint64) (g_get_real_time () / G_USEC_PER_SEC);
	entry = store_lookup (store, report->path);

	if (entry != NULL) {
		/* Re-attestation keeps the first date: how long we have
		 * been watching is part of the record. */
		g_free (entry->sha256);
		g_free (entry->publisher);
	} else {
		entry = g_new0 (FsTrustEntry, 1);
		entry->path = g_strdup (report->path);
		entry->first_seen = now;
		g_ptr_array_add (store->rows, entry);
	}

	entry->sha256   = g_strdup (report->sha256);
	entry->size     = report->size;
	entry->mtime    = report->mtime;
	entry->sig      = report->sig;
	entry->publisher = g_strdup (report->publisher);
	entry->last_seen = now;

	detail = g_strdup_printf ("path=%s sha256=%s sig=%s publisher=%s",
	                          entry->path, entry->sha256,
	                          sig_to_token (entry->sig),
	                          entry->publisher ? entry->publisher : "-");
	fs_audit_log ("trust-attest", detail);
	g_free (detail);

	return TRUE;
}

gboolean
fs_trust_remove (FsTrustStore *store, const gchar *path)
{
	FsTrustEntry *entry;
	gchar *detail;

	entry = store_lookup (store, path);
	if (entry == NULL)
		return FALSE;

	detail = g_strdup_printf ("path=%s sha256=%s", entry->path,
	                          entry->sha256);
	fs_audit_log ("trust-forget", detail);
	g_free (detail);

	/* store_lookup walked the same array the free func owns. */
	g_ptr_array_remove_fast (store->rows, entry);
	return TRUE;
}
