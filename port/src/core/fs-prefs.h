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
/* 1.0.7: how many events the Events list keeps (a number, stored as
 * text: 1000..1000000), and the history on disk -- on or off, how many
 * days, how many megabytes (core/fs-eventlog.h). */
#define FS_PREFS_EVENTS_MAX              "/apps/stockfw/client/events/max_events"
#define FS_PREFS_EVENTS_HISTORY          "/apps/stockfw/client/events/keep_history"
#define FS_PREFS_EVENTS_HISTORY_DAYS     "/apps/stockfw/client/events/history_days"
#define FS_PREFS_EVENTS_HISTORY_MB       "/apps/stockfw/client/events/history_mb"
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

/* A number setting (a FS_PREF_STRING row holding digits): the stored
 * value clamped to min..max, or the table's default when the stored
 * text is not a number. */
guint     fs_prefs_uint   (const gchar *key, guint min, guint max);

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

/* ---- PR 3: the terminal writes settings -------------------------- */

GQuark fs_prefs_error_quark (void);
#define FS_PREFS_ERROR (fs_prefs_error_quark ())
typedef enum
{
	FS_PREFS_ERR_INVALID,   /* not a setting, or not a value it takes */
	FS_PREFS_ERR_SAVE       /* the file could not be locked or written */
} FsPrefsError;

/* [ fs_prefs_set_persist ]
 * Change only `keys' (n of them) and write the file: flock on
 * "<file>.lock" (not on Windows), re-read the file under it, set each
 * key (a switch takes "true" or "false"; a NULL value removes the key,
 * so it reads as the table's default), save.  Every other key keeps
 * what the file held when the lock was taken, so two writers of
 * different keys both keep theirs.  A file that cannot be read is kept
 * as fs_prefs_backup_path() and the defaults are written with the
 * keys (A12); *was_unreadable (nullable) says so.  Refused before
 * anything is touched: a key that is not in the table, a switch value
 * that is not true or false.  Validate first (fs_prefs_validate): this
 * only writes.  The in-memory store is replaced by the file's. */
gboolean fs_prefs_set_persist (const gchar * const *keys,
                               const gchar * const *values, guint n,
                               gboolean *was_unreadable, GError **error);

/* ---- PR 3: what the Preferences window allows, without the window --
 *
 * fs_prefs_validate (fs-prefs-check.c) decides a set of changes the way
 * the Preferences window does: the keys the backend honours (its
 * FS_FWSEC_* and FS_FWHON_* bits), each value's form, and the
 * dependencies between keys, checked on the whole set at once (NAT
 * with both devices in one call is fine).  Refusals carry the window's
 * own reason text and the Help topic of the page it is on; warnings are
 * what the window shows beside an accepted choice.  The fake-backend
 * Preferences smoke checks the two against each other. */
typedef struct
{
	const gchar *key;      /* the table's key; NULL: the set as a whole */
	gchar       *reason;   /* one sentence                              */
	const gchar *topic;    /* "prefs-network", ...                      */
} FsPrefsIssue;

typedef struct
{
	GPtrArray  *refusals;  /* FsPrefsIssue*; empty when the set is fine */
	GPtrArray  *warnings;  /* FsPrefsIssue*                             */
	/* Each accepted key -> the value to store ("true"/"false", the
	 * number or device as text, "" for no device).  Keys are the
	 * table's own strings. */
	GHashTable *values;
} FsPrefsCheck;

/* keys[i] = values[i], n pairs, against the store as loaded now.
 * Values take on/off, true/false, yes/no, 1/0 for switches (and
 * drop/reject for the rejection method, block/allow for outgoing),
 * digits in range for numbers, a device name or "" for the devices.
 * devices (nullable, NULL-ended) are the devices present: a device
 * not among them is accepted with a warning, as the window marks it
 * "not present".  Never NULL; fs_prefs_check_free. */
FsPrefsCheck *fs_prefs_validate (const gchar * const *keys,
                                 const gchar * const *values, guint n,
                                 guint32 fw_sections, guint32 fw_honors,
                                 const gchar * const *devices);
void          fs_prefs_check_free (FsPrefsCheck *check);

/* Does a backend with these bits act on `key'?  Settings that are not
 * firewall settings always count; a firewall setting counts where the
 * window shows its row. */
gboolean      fs_prefs_key_honoured (const gchar *key, guint32 fw_sections,
                                     guint32 fw_honors);
/* The Help topic of the Preferences page a key is on ("prefs-icmp"),
 * "preferences" for a key on none. */
const gchar  *fs_prefs_key_topic    (const gchar *key);

G_END_DECLS

#endif /* FS_PREFS_H */