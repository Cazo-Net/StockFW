/*---[ fs-audit-ledger.c ]-------------------------------------------------
 * Cryptographic Sovereign Audit Ledger Implementation
 * Tamper-evident hash-chaining with SHA-256 verification and Merkle tree root computation.
 *--------------------------------------------------------------------*/

#include "core/fs-audit-ledger.h"
#include "core/fs-prefs.h"

#include <string.h>
#include <time.h>
#include <glib/gstdio.h>
#include <glib/gchecksum.h>

#define DEFAULT_GENESIS_HASH "0000000000000000000000000000000000000000000000000000000000000000"

FsAuditLedgerEntry *
fs_audit_ledger_entry_new (gint64 timestamp,
                           const gchar *event_type,
                           const gchar *actor,
                           const gchar *details,
                           const gchar *prev_hash,
                           const gchar *current_hash)
{
	FsAuditLedgerEntry *entry = g_new0 (FsAuditLedgerEntry, 1);
	entry->timestamp = timestamp;
	entry->event_type = g_strdup (event_type ? event_type : "UNKNOWN");
	entry->actor = g_strdup (actor ? actor : "SYSTEM");
	entry->details = g_strdup (details ? details : "");
	entry->prev_hash = g_strdup (prev_hash ? prev_hash : DEFAULT_GENESIS_HASH);
	entry->current_hash = g_strdup (current_hash ? current_hash : DEFAULT_GENESIS_HASH);
	return entry;
}

void
fs_audit_ledger_entry_free (FsAuditLedgerEntry *entry)
{
	if (!entry)
		return;
	g_free (entry->event_type);
	g_free (entry->actor);
	g_free (entry->details);
	g_free (entry->prev_hash);
	g_free (entry->current_hash);
	g_free (entry);
}

gchar *
fs_audit_ledger_path (void)
{
	const gchar *override = g_getenv ("STOCKFW_AUDIT_LEDGER_FILE");

	if (override != NULL && *override != '\0')
		return g_strdup (override);

	{
		const gchar *prefs = fs_prefs_path ();
		gchar *dir;
		gchar *result;

		if (prefs == NULL)
			return g_build_filename (g_get_user_config_dir (),
			                        "stockfw", "audit-ledger.log", NULL);

		dir = g_path_get_dirname (prefs);
		result = g_build_filename (dir, "audit-ledger.log", NULL);
		g_free (dir);
		return result;
	}
}

gchar *
fs_audit_ledger_append (const gchar *prev_hash, const gchar *event_type, const gchar *actor, const gchar *details)
{
	gint64 now = (gint64) time (NULL);
	gchar *safe_event = g_strdelimit (g_strdup (event_type ? event_type : "UNKNOWN"), "\r\n|", ' ');
	gchar *safe_actor = g_strdelimit (g_strdup (actor ? actor : "SYSTEM"), "\r\n|", ' ');
	gchar *safe_details = g_strdelimit (g_strdup (details ? details : ""), "\r\n|", ' ');
	const gchar *p_hash = (prev_hash && *prev_hash != '\0') ? prev_hash : DEFAULT_GENESIS_HASH;

	gchar *raw_string = g_strdup_printf (
		"%" G_GINT64_FORMAT "|%s|%s|%s|%s",
		now,
		p_hash,
		safe_event,
		safe_actor,
		safe_details
	);

	GChecksum *checksum = g_checksum_new (G_CHECKSUM_SHA256);
	g_checksum_update (checksum, (const guchar *) raw_string, strlen (raw_string));
	const gchar *hash_str = g_checksum_get_string (checksum);
	gchar *result_hash = g_strdup (hash_str);

	g_checksum_free (checksum);
	g_free (raw_string);
	g_free (safe_event);
	g_free (safe_actor);
	g_free (safe_details);

	return result_hash;
}

gboolean
fs_audit_ledger_log (const gchar *event_type, const gchar *actor, const gchar *details, gchar **out_current_hash)
{
	gchar *path;
	gchar *dir;
	FILE *file;
	GPtrArray *entries;
	gchar *prev_hash = NULL;
	gint64 now = (gint64) time (NULL);
	gchar *current_hash = NULL;
	gint written;

	path = fs_audit_ledger_path ();
	dir  = g_path_get_dirname (path);

	g_mkdir_with_parents (dir, 0700);
	g_free (dir);

	/* Load existing ledger to determine prev_hash from the last entry */
	entries = fs_audit_ledger_load (path);
	if (entries && entries->len > 0) {
		FsAuditLedgerEntry *last = g_ptr_array_index (entries, entries->len - 1);
		if (last && last->current_hash)
			prev_hash = g_strdup (last->current_hash);
	}
	if (!prev_hash)
		prev_hash = g_strdup (DEFAULT_GENESIS_HASH);

	if (entries)
		g_ptr_array_free (entries, TRUE);

	current_hash = fs_audit_ledger_append (prev_hash, event_type, actor, details);
	if (!current_hash) {
		g_free (prev_hash);
		g_free (path);
		return FALSE;
	}

	file = g_fopen (path, "a");
	if (file == NULL) {
		g_free (prev_hash);
		g_free (current_hash);
		g_free (path);
		return FALSE;
	}

	{
		gchar *safe_event = g_strdelimit (g_strdup (event_type ? event_type : "UNKNOWN"), "\r\n|", ' ');
		gchar *safe_actor = g_strdelimit (g_strdup (actor ? actor : "SYSTEM"), "\r\n|", ' ');
		gchar *safe_details = g_strdelimit (g_strdup (details ? details : ""), "\r\n|", ' ');

		written = fprintf (file, "%" G_GINT64_FORMAT " | %s | %s | %s | %s | %s\n",
		                   now, safe_event, safe_actor, safe_details, prev_hash, current_hash);

		g_free (safe_event);
		g_free (safe_actor);
		g_free (safe_details);
	}

	fclose (file);

	if (out_current_hash)
		*out_current_hash = g_strdup (current_hash);

	g_free (prev_hash);
	g_free (current_hash);
	g_free (path);

	return written > 0;
}

GPtrArray *
fs_audit_ledger_load (const gchar *path)
{
	gchar *contents = NULL;
	GPtrArray *entries;
	gchar **lines;
	guint i;

	if (!path || !g_file_get_contents (path, &contents, NULL, NULL))
		return NULL;

	entries = g_ptr_array_new_with_free_func ((GDestroyNotify) fs_audit_ledger_entry_free);
	lines = g_strsplit (contents, "\n", -1);
	g_free (contents);

	for (i = 0; lines[i] != NULL; i++) {
		gchar *line = g_strstrip (lines[i]);
		gchar **parts;

		if (*line == '\0' || *line == '#')
			continue;

		parts = g_strsplit (line, "|", 6);
		if (parts && parts[0] && parts[1] && parts[2] && parts[3] && parts[4] && parts[5]) {
			gint64 timestamp = g_ascii_strtoll (g_strstrip (parts[0]), NULL, 10);
			gchar *event_type = g_strstrip (parts[1]);
			gchar *actor = g_strstrip (parts[2]);
			gchar *details = g_strstrip (parts[3]);
			gchar *prev_hash = g_strstrip (parts[4]);
			gchar *current_hash = g_strstrip (parts[5]);

			FsAuditLedgerEntry *entry = fs_audit_ledger_entry_new (
				timestamp, event_type, actor, details, prev_hash, current_hash
			);
			g_ptr_array_add (entries, entry);
			g_strfreev (parts);
		} else if (parts) {
			g_strfreev (parts);
		}
	}

	g_strfreev (lines);
	return entries;
}

gboolean
fs_audit_ledger_verify_chain (GPtrArray *entries)
{
	if (!entries || entries->len == 0)
		return TRUE;

	for (guint i = 0; i < entries->len; i++) {
		FsAuditLedgerEntry *curr = g_ptr_array_index (entries, i);
		if (!curr)
			return FALSE;

		/* Check linkage to previous entry */
		const gchar *expected_prev = (i == 0) ? DEFAULT_GENESIS_HASH :
			((FsAuditLedgerEntry *) g_ptr_array_index (entries, i - 1))->current_hash;

		if (!curr->prev_hash || strcmp (curr->prev_hash, expected_prev) != 0)
			return FALSE;

		/* Re-compute current hash */
		gchar *raw_string = g_strdup_printf (
			"%" G_GINT64_FORMAT "|%s|%s|%s|%s",
			curr->timestamp,
			curr->prev_hash,
			curr->event_type ? curr->event_type : "UNKNOWN",
			curr->actor ? curr->actor : "SYSTEM",
			curr->details ? curr->details : ""
		);

		GChecksum *checksum = g_checksum_new (G_CHECKSUM_SHA256);
		g_checksum_update (checksum, (const guchar *) raw_string, strlen (raw_string));
		const gchar *calc_hash = g_checksum_get_string (checksum);

		gboolean match = (curr->current_hash && strcmp (curr->current_hash, calc_hash) == 0);

		g_checksum_free (checksum);
		g_free (raw_string);

		if (!match)
			return FALSE;
	}

	return TRUE;
}

gchar *
fs_audit_ledger_compute_merkle_root (GPtrArray *entries)
{
	if (!entries || entries->len == 0) {
		GChecksum *checksum = g_checksum_new (G_CHECKSUM_SHA256);
		g_checksum_update (checksum, (const guchar *) "", 0);
		gchar *res = g_strdup (g_checksum_get_string (checksum));
		g_checksum_free (checksum);
		return res;
	}

	guint num_entries = entries->len;
	GPtrArray *current_level = g_ptr_array_new_with_free_func ((GDestroyNotify) g_free);

	for (guint i = 0; i < num_entries; i++) {
		FsAuditLedgerEntry *entry = g_ptr_array_index (entries, i);
		if (entry && entry->current_hash) {
			g_ptr_array_add (current_level, g_strdup (entry->current_hash));
		} else {
			g_ptr_array_add (current_level, g_strdup (DEFAULT_GENESIS_HASH));
		}
	}

	while (current_level->len > 1) {
		GPtrArray *next_level = g_ptr_array_new_with_free_func ((GDestroyNotify) g_free);
		for (guint i = 0; i < current_level->len; i += 2) {
			gchar *left = g_ptr_array_index (current_level, i);
			gchar *right = (i + 1 < current_level->len) ? g_ptr_array_index (current_level, i + 1) : left;

			gchar *combined = g_strconcat (left, right, NULL);
			GChecksum *checksum = g_checksum_new (G_CHECKSUM_SHA256);
			g_checksum_update (checksum, (const guchar *) combined, strlen (combined));
			g_ptr_array_add (next_level, g_strdup (g_checksum_get_string (checksum)));
			g_checksum_free (checksum);
			g_free (combined);
		}
		g_ptr_array_free (current_level, TRUE);
		current_level = next_level;
	}

	gchar *root = g_strdup (g_ptr_array_index (current_level, 0));
	g_ptr_array_free (current_level, TRUE);
	return root;
}
