/*---[ fs-quarantine.h ]--------------------------------------------------
 * Process Socket Termination & Encrypted Quarantine Vault Engine
 * Part of StockFW Ultimate Security Extension
 *
 * Provides capabilities to:
 * 1. Terminate suspicious processes and their associated network sockets.
 * 2. Isolate malicious files/artifacts into an encrypted quarantine vault
 *    using authenticated AES-256-GCM encryption with secure key derivation.
 *--------------------------------------------------------------------*/
#ifndef FS_QUARANTINE_H
#define FS_QUARANTINE_H

#include <glib.h>

G_BEGIN_DECLS

typedef struct
{
    gchar     *quarantine_id;
    gchar     *original_path;
    gchar     *threat_name;
    gint64     timestamp;
    guint64    file_size;
    gchar     *vault_path;
} FsQuarantineRecord;

/* Initialize quarantine subsystem and vault directory */
gboolean fs_quarantine_init (const gchar *vault_base_dir);

/* Terminate a process by PID and forcibly close/tear down its active TCP/UDP sockets */
gboolean fs_quarantine_terminate_process_sockets (guint pid, gchar **out_audit_detail);

/* Isolate a suspicious file into the encrypted quarantine vault */
gboolean fs_quarantine_isolate_file (const gchar *file_path, const gchar *threat_name,
                                     gchar **out_quarantine_id, gchar **out_vault_path);

/* Restore a quarantined file from the vault back to its original path */
gboolean fs_quarantine_restore_file (const gchar *quarantine_id, GError **error);

/* Permanently delete a quarantined item from the vault */
gboolean fs_quarantine_purge_item (const gchar *quarantine_id, GError **error);

/* List all items currently in the quarantine vault */
GPtrArray *fs_quarantine_list_items (void);

/* Free a quarantine record */
void fs_quarantine_record_free (FsQuarantineRecord *record);

G_END_DECLS

#endif /* FS_QUARANTINE_H */
