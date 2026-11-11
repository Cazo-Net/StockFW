/*---[ fs-audit-ledger.h ]-------------------------------------------------
 * Cryptographic Sovereign Audit Ledger & Tamper-Evident Hash Chain
 * Part of StockFW Phase v3.0 (The Guinness Standard)
 *
 * Hash-chains every policy change, auto-block event, and sentinel trigger
 * into an append-only cryptographic ledger for absolute forensic auditability.
 *--------------------------------------------------------------------*/
#ifndef FS_AUDIT_LEDGER_H
#define FS_AUDIT_LEDGER_H

#include <glib.h>

G_BEGIN_DECLS

typedef struct
{
	gint64 timestamp;
	gchar *event_type;
	gchar *actor;
	gchar *details;
	gchar *prev_hash;
	gchar *current_hash;
} FsAuditLedgerEntry;

/* Allocate and free ledger entries */
FsAuditLedgerEntry *fs_audit_ledger_entry_new (gint64 timestamp,
                                              const gchar *event_type,
                                              const gchar *actor,
                                              const gchar *details,
                                              const gchar *prev_hash,
                                              const gchar *current_hash);
void fs_audit_ledger_entry_free (FsAuditLedgerEntry *entry);

/* Where ledger entries are written. Honours $STOCKFW_AUDIT_LEDGER_FILE,
 * otherwise audit-ledger.log next to preferences. Caller frees. */
gchar *fs_audit_ledger_path (void);

/* Append a new cryptographically hash-chained entry in-memory, returning its current hash (caller frees) */
gchar *fs_audit_ledger_append (const gchar *prev_hash,
                               const gchar *event_type,
                               const gchar *actor,
                               const gchar *details);

/* Log an entry to disk, appending to the audit ledger file with hash chaining */
gboolean fs_audit_ledger_log (const gchar *event_type,
                              const gchar *actor,
                              const gchar *details,
                              gchar **out_current_hash);

/* Load audit ledger entries from file path */
GPtrArray *fs_audit_ledger_load (const gchar *path);

/* Verify integrity of the audit ledger chain and entry hashes */
gboolean fs_audit_ledger_verify_chain (GPtrArray *entries);

/* Compute Merkle tree root hash of all ledger entries */
gchar *fs_audit_ledger_compute_merkle_root (GPtrArray *entries);

G_END_DECLS

#endif /* FS_AUDIT_LEDGER_H */
