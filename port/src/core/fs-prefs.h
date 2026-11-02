/*---[ fs-prefs.h ]------------------------------------------------------
 * Persistent settings.
 *
 * The original code used GConf 2, which no longer exists.  These days the
 * portable answer is a GKeyFile (plain ini) on every platform, so the
 * same settings code works on Windows and Linux unchanged.
 *
 * The key strings are kept in their original GConf form
 * ("/apps/stockfw/client/enable_tray_icon") so that the thousands of
 * existing call sites port without edits; internally they are mapped
 * onto ini groups and keys.
 *--------------------------------------------------------------------*/
#ifndef FS_PREFS_H
#define FS_PREFS_H

#include <glib.h>

G_BEGIN_DECLS

/* Original GConf keys, unchanged.  Every key the application reads is
 * also in the settings table below (fs_prefs_specs), which holds its
 * type and its one default. */
#define FS_PREFS_ENABLE_TRAY_ICON "/apps/stockfw/client/enable_tray_icon"
#define FS_PREFS_MINIMIZE_TO_TRAY "/apps/stockfw/client/minimize_to_tray"

#define FS_PREFS_SKIP_REDUNDANT          "/apps/stockfw/client/filter/redundant"
#define FS_PREFS_SKIP_NOT_FOR_FIREWALL   "/apps/stockfw/client/filter/not_for_firewall"
#define FS_PREFS_APPLY_POLICY_INSTANTLY  "/apps/stockfw/client/policy_auto_apply"
/* P3 audit-only testing mode: changes reach the policy file and the
 * audit log but never the firewall, until the user turns it off. */
#define FS_PREFS_AUDIT_ONLY              "/apps/stockfw/client/policy_audit_only"

/* Reserved for starting StockFW with the session; not read yet, and
 * not in the table until something acts on it. */
#define FS_PREFS_START_ON_BOOT    "/apps/stockfw/client/start_firewall_on_boot"
#define FS_PREFS_START_ON_GUI     "/apps/stockfw/client/start_firewall_on_gui"

#define FS_PREFS_FW_EXT_IF "/apps/stockfw/firewall/ext_if"
#define FS_PREFS_FW_INT_IF "/apps/stockfw/firewall/int_if"
#define FS_PREFS_FW_NAT    "/apps/stockfw/firewall/nat"

#define FS_PREFS_FW_FILTER_ICMP "/apps/stockfw/firewall/icmp/enable"
#define FS_PREFS_FW_ICMP_ECHO_REQUEST  "/apps/stockfw/firewall/icmp/echo_request"
#define FS_PREFS_FW_ICMP_ECHO_REPLY    "/apps/stockfw/firewall/icmp/echo_reply"
#define FS_PREFS_FW_ICMP_TRACEROUTE    "/apps/stockfw/firewall/icmp/traceroute"
#define FS_PREFS_FW_ICMP_MSTRACEROUTE  "/apps/stockfw/firewall/icmp/mstraceroute"
#define FS_PREFS_FW_ICMP_UNREACHABLE   "/apps/stockfw/firewall/icmp/unreachable"
#define FS_PREFS_FW_ICMP_TIMESTAMPING  "/apps/stockfw/firewall/icmp/timestamping"
#define FS_PREFS_FW_ICMP_MASKING       "/apps/stockfw/firewall/icmp/masking"
#define FS_PREFS_FW_ICMP_REDIRECTION   "/apps/stockfw/firewall/icmp/redirection"
#define FS_PREFS_FW_ICMP_SOURCE_QUENCHES "/apps/stockfw/firewall/icmp/source_quenches"

#define FS_PREFS_FW_DENY_PACKETS            "/apps/stockfw/firewall/deny_packets"
#define FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST "/apps/stockfw/firewall/block_external_broadcast"
#define FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST "/apps/stockfw/firewall/block_internal_broadcast"
#define FS_PREFS_FW_BLOCK_NON_ROUTABLES      "/apps/stockfw/firewall/block_non_routables"
#define FS_PREFS_FW_RESTRICTIVE_OUTBOUND     "/apps/stockfw/firewall/restrictive_outbound"
/* 1.0.7: log accepted new connections (Linux; Windows logs them via
 * its own audit policy). */
#define FS_PREFS_FW_LOG_ALLOWED              "/apps/stockfw/firewall/log_allowed"

/* ---- the settings table (1.0.7) ------------------------------------
 *
 * One row per setting: its key, its type and its default.  Every
 * reader asks fs_prefs_bool() / fs_prefs_string(), which fall back to
 * this default, so the Preferences window, the rule generator and the
 * pages that act on a setting can no longer disagree about what an
 * unset key means (they once did: the window showed "Apply policy
 * changes immediately" ticked while the Policy page treated it as
 * off).  tests/test-core.sh checks every consumer against it. */
typedef enum
{
	FS_PREF_BOOL = 0,
	FS_PREF_STRING
} FsPrefType;

typedef struct
{
	const gchar *key;
	const gchar *name;        /* the FS_PREFS_* macro's name, for tests */
	FsPrefType   type;
	gboolean     bool_default;
	const gchar *string_default;
	gboolean     firewall;    /* changes the rules the firewall gets */
} FsPrefSpec;

/* The whole table, n_specs rows. */
const FsPrefSpec *fs_prefs_specs (guint *n_specs);
/* The row for key, or NULL when key is not a table setting. */
const FsPrefSpec *fs_prefs_spec  (const gchar *key);

/* Table-backed readers: the stored value, or the table's default. */
gboolean  fs_prefs_bool   (const gchar *key);
gchar    *fs_prefs_string (const gchar *key);

/* TRUE when the settings file holds key at all. */
gboolean  fs_prefs_has_key (const gchar *key);

/* Every firewall setting (the table rows marked firewall) as it reads
 * now: key (static) -> value text, "true"/"false" for switches and
 * the string itself otherwise ("" for no device).  Caller unrefs. */
GHashTable *fs_prefs_firewall_values (void);

/* ---- editing a copy (the Preferences window) -----------------------
 *
 * A snapshot of every table setting.  The window changes the copy;
 * commit writes back only the keys whose value differs from the
 * snapshot AND that were marked writable (a control that is shown and
 * able to act).  A key nobody touched, or one whose control cannot
 * work here, is never written -- so saving never rewrites a value the
 * user did not change. */
typedef struct _FsPrefsEdit FsPrefsEdit;

FsPrefsEdit *fs_prefs_edit_new          (void);
void         fs_prefs_edit_free         (FsPrefsEdit *edit);
gboolean     fs_prefs_edit_get_bool     (FsPrefsEdit *edit, const gchar *key);
void         fs_prefs_edit_set_bool     (FsPrefsEdit *edit, const gchar *key,
                                         gboolean value);
const gchar *fs_prefs_edit_get_string   (FsPrefsEdit *edit, const gchar *key);
void         fs_prefs_edit_set_string   (FsPrefsEdit *edit, const gchar *key,
                                         const gchar *value);
/* The value the snapshot started from. */
gboolean     fs_prefs_edit_orig_bool    (FsPrefsEdit *edit, const gchar *key);
const gchar *fs_prefs_edit_orig_string  (FsPrefsEdit *edit, const gchar *key);
void         fs_prefs_edit_set_writable (FsPrefsEdit *edit, const gchar *key,
                                         gboolean writable);
gboolean     fs_prefs_edit_changed      (FsPrefsEdit *edit, const gchar *key);
/* Changed keys, writable or not. */
guint        fs_prefs_edit_n_changed    (FsPrefsEdit *edit);
/* Changed AND writable keys: exactly what commit would write now. */
guint        fs_prefs_edit_n_pending    (FsPrefsEdit *edit);
/* Writes the changed, writable keys into the store (not to disk: call
 * fs_prefs_save after).  Returns how many were written; firewall_changed
 * says whether any of them was a firewall setting. */
guint        fs_prefs_edit_commit       (FsPrefsEdit *edit,
                                         gboolean *firewall_changed);

/* Load / save.  fs_prefs_load is safe to call more than once.  A file
 * that exists but cannot be parsed is copied to fs_prefs_backup_path()
 * before FALSE is returned, so the defaults written after it never
 * destroy the only copy of the user's settings. */
void fs_prefs_init  (void);
gboolean fs_prefs_load (void);
gboolean fs_prefs_save (void);
const gchar *fs_prefs_path (void);
/* Where an unreadable settings file is kept: "<path>.bad".  Caller frees. */
gchar       *fs_prefs_backup_path (void);

/* TRUE when a setter changed something since the last load or save:
 * what the running program's periodic save checks (1.0.7). */
gboolean fs_prefs_dirty (void);

gboolean  fs_prefs_get_bool   (const gchar *key, gboolean fallback);
void      fs_prefs_set_bool   (const gchar *key, gboolean value);
gchar    *fs_prefs_get_string (const gchar *key, const gchar *fallback);
void      fs_prefs_set_string (const gchar *key, const gchar *value);
gint      fs_prefs_get_int    (const gchar *key, gint fallback);
void      fs_prefs_set_int    (const gchar *key, gint value);

/* Writes the table default of every setting the file does not hold
 * yet, then saves.  Keys the file already holds are left alone. */
void fs_prefs_set_defaults (void);

G_END_DECLS

#endif /* FS_PREFS_H */