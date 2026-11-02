/*---[ fs-intel.h ]------------------------------------------------------
 * The threat-intel engine (1.0.7): configuration, the store, updates,
 * building the rule set, the apply gate, the lifecycle, the honest
 * state, and lookups.  Design: docs/1.0.7-threat-intel-design.md,
 * section 6 (and 4, 5, 7 for the pieces it drives).
 *
 *   config   which feeds and local lists are on, in which direction,
 *            whose terms were accepted, custom feeds, exceptions, the
 *            master switch, a proxy.  intel.conf.
 *   store    <id>.list (normalized ranges) and <id>.state per source;
 *            applied.state: what the kernel was last given.
 *   update   download (only enabled feeds whose terms were accepted --
 *            StockFW makes no network request otherwise), parse, judge,
 *            store.
 *   build    config + store + what must stay reachable -> rule set.
 *   gate     audit-only / Policy Lock honoured; counters carried; one
 *            audit line per attempt.
 *   state    what the kernel is actually doing, never just the config.
 *   lookup   which lists hold one address, and would it be blocked.
 *
 * Everything is synchronous.  The UI calls the slow parts (update,
 * apply) from a worker thread; nothing here touches GTK.  The backend
 * arrives as a parameter, so the tests drive a fake one.
 *
 * A "source" is anything that becomes a set: a catalog feed, a custom
 * feed ("custom-<slug>") or a local list ("local-<slug>").  Ids follow
 * fs_intel_id_is_valid().
 *--------------------------------------------------------------------*/
#ifndef FS_INTEL_H
#define FS_INTEL_H

#include <glib.h>
#include "core/fs-backend.h"
#include "core/fs-feed.h"
#include "core/fs-hostnet.h"
#include "core/fs-intelset.h"
#include "core/fs-iprange.h"

G_BEGIN_DECLS

GQuark fs_intel_error_quark (void);
#define FS_INTEL_ERROR (fs_intel_error_quark ())

enum
{
	FS_INTEL_ERR_CONFIG = 1,   /* intel.conf invalid (names the key)     */
	FS_INTEL_ERR_STORE,        /* a store file unreadable / unwritable   */
	FS_INTEL_ERR_UNSAFE_DIR,   /* the store directory failed the check   */
	FS_INTEL_ERR_NEEDS_ROOT,   /* Linux, not root, no usable override    */
	FS_INTEL_ERR_UNSUPPORTED,  /* this platform cannot do threat intel   */
	FS_INTEL_ERR_UNKNOWN,      /* no such feed or list                   */
	FS_INTEL_ERR_CONSENT,      /* the feed's terms were not accepted     */
	FS_INTEL_ERR_TAMPERED,     /* a stored list fails the guards         */
	FS_INTEL_ERR_TOO_BIG,      /* the rule set is over a limit           */
	FS_INTEL_ERR_INVALID       /* a bad argument (URL, range, name)      */
};

/* ---- store directory (design 6.1) ---------------------------------- */

/* The directory, created on first use (0700; on Linux as root the
 * parent /var/lib/stockfw is created 0755).  Linux as root:
 * /var/lib/stockfw/intel.  $STOCKFW_INTEL_DIR overrides it, for root
 * and non-root alike, only when that directory and every parent are
 * owned by the current user or by root and not writable by group or
 * others; otherwise FS_INTEL_ERR_UNSAFE_DIR.  Linux non-root with no
 * override: FS_INTEL_ERR_NEEDS_ROOT.  Windows: FS_INTEL_ERR_UNSUPPORTED
 * (Round 3).  Caller frees. */
gchar *fs_intel_dir (GError **error);

/* ---- configuration (design 6.2) ------------------------------------ */

typedef struct
{
	gchar       *id;          /* catalog id or "custom-<slug>"           */
	gboolean     enabled;
	FsIntelDir   dir;
	gint64       accepted_at; /* unix s the terms were accepted; 0 never */
	gboolean     custom;
	gchar       *name;        /* custom only (catalog: NULL)             */
	gchar       *url;         /* custom only                             */
	FsFeedFormat format;      /* custom only                             */
} FsIntelFeedConf;

typedef struct
{
	gchar     *id;            /* "local-<slug>"                          */
	gchar     *name;          /* as the user typed it                    */
	gboolean   enabled;
	FsIntelDir dir;
	gint64     imported_at;
} FsIntelListConf;

typedef struct
{
	gboolean    enabled;      /* master switch; default TRUE             */
	gchar      *proxy;        /* NULL, or fs_fetch_proxy_is_acceptable() */
	GPtrArray  *feeds;        /* FsIntelFeedConf*: every catalog feed in
	                           * catalog order (defaults: off, the
	                           * catalog's direction), then custom feeds */
	GPtrArray  *lists;        /* FsIntelListConf*                        */
	FsRangeSet *exceptions;   /* normalized; never blocked               */
} FsIntelConfig;

FsIntelConfig *fs_intel_config_new  (void);           /* the defaults   */
void           fs_intel_config_free (FsIntelConfig *config);
/* intel.conf from the store directory.  A missing file is the
 * defaults.  Unknown keys and groups are ignored; an invalid value
 * fails the load with FS_INTEL_ERR_CONFIG naming the group and key. */
FsIntelConfig *fs_intel_config_load (GError **error);
gboolean       fs_intel_config_save (const FsIntelConfig *config,
                                     GError **error);

FsIntelFeedConf *fs_intel_config_feed (const FsIntelConfig *config,
                                       const gchar *id);
FsIntelListConf *fs_intel_config_list (const FsIntelConfig *config,
                                       const gchar *id);
/* The display name of any source id: catalog name, custom name, list
 * name; NULL when unknown.  Borrowed. */
const gchar     *fs_intel_config_label (const FsIntelConfig *config,
                                        const gchar *id);

/* Turn a feed on.  A feed whose terms were never accepted needs
 * accept_terms (then accepted_at becomes now); without it the call
 * fails with FS_INTEL_ERR_CONSENT and changes nothing.  dir 0 keeps the
 * feed's current direction. */
gboolean fs_intel_config_enable_feed  (FsIntelConfig *config,
                                       const gchar *id, FsIntelDir dir,
                                       gboolean accept_terms,
                                       GError **error);
gboolean fs_intel_config_disable_feed (FsIntelConfig *config,
                                       const gchar *id, GError **error);
/* A custom feed: id "custom-<slug of name>"; the URL must pass
 * fs_feed_url_is_acceptable.  Typing the URL is the consent, so it is
 * added enabled with accepted_at = now.  *id_out (nullable) receives
 * the id. */
gboolean fs_intel_config_add_custom (FsIntelConfig *config,
                                     const gchar *name, const gchar *url,
                                     FsFeedFormat format, FsIntelDir dir,
                                     gchar **id_out, GError **error);
/* Remove a custom feed or a local list from the config and delete its
 * store files.  Catalog feeds cannot be removed (disable them). */
gboolean fs_intel_config_remove (FsIntelConfig *config, const gchar *id,
                                 GError **error);
/* Set a local list's or feed's direction / enabled flag. */
gboolean fs_intel_config_set_dir     (FsIntelConfig *config,
                                      const gchar *id, FsIntelDir dir,
                                      GError **error);
gboolean fs_intel_config_set_enabled (FsIntelConfig *config,
                                      const gchar *id, gboolean enabled,
                                      GError **error);

/* The consent text for one feed (design 8): the host contacted, how
 * often, what the host learns (this computer's public address and
 * "StockFW/<version>"), the licence or "see the terms" with the terms
 * URL, a non-commercial warning when it applies, and that lists contain
 * mistakes and how to add an exception.  Several short paragraphs,
 * translated, plain text.  NULL for an unknown id.  Caller frees. */
gchar *fs_intel_consent_text (const FsIntelConfig *config,
                              const gchar *id);

/* ---- local lists (design 6.3) --------------------------------------- */

/* Read the file at `path' (at most FS_FEED_MAX_BYTES, a regular file),
 * parse it with fs_feed_parse_csv(), and store it as source
 * "local-<slug of name>", added to the config (enabled, `dir') or
 * replacing the list of that name.  The config is NOT saved: the
 * caller saves it.  *id_out (nullable) receives the id. */
gboolean fs_intel_import_list (FsIntelConfig *config, const gchar *path,
                               const gchar *name, FsIntelDir dir,
                               FsFeedParseStats *stats, gchar **id_out,
                               GError **error);

/* ---- per-source state (design 6.1) ---------------------------------- */

typedef struct
{
	gchar        *id;
	gint64        fetched_at;     /* last accepted copy, unix s; 0 never  */
	gint64        attempted_at;   /* last attempt                         */
	gint64        content_date;   /* of the stored copy; 0 unknown        */
	gchar        *sha256;         /* of the raw body of the stored copy   */
	guint         entries;
	guint         count4, count6; /* intervals stored                     */
	guint64       cover4;
	FsFeedHistory history;
	gchar        *last_error;     /* NULL when the last attempt worked    */
	gchar        *refused;        /* NULL, or why the last copy was
	                               * refused (the guard's sentence)       */
	guint64       carried_packets;/* counters carried across re-applies   */
	guint64       carried_bytes;
	gint64        counted_since;  /* unix s the first counter was taken   */
} FsIntelSourceState;

/* NULL when the source was never stored. */
FsIntelSourceState *fs_intel_source_state (const gchar *id);
void                fs_intel_source_state_free (FsIntelSourceState *s);
/* The stored list, re-checked with the parse guards (span floor and
 * coverage caps); a list that fails them is FS_INTEL_ERR_TAMPERED.  A
 * missing list is FS_INTEL_ERR_STORE. */
FsRangeSet *fs_intel_source_load (const gchar *id, GError **error);

/* Due for an update: never fetched, or the last attempt is older than
 * the feed's interval (catalog) or 24 h (custom).  Stale: the copy is
 * older than 7 intervals, from content_date when known, else from
 * fetched_at.  `now' in unix seconds. */
gboolean fs_intel_source_is_due   (const FsIntelConfig *config,
                                   const gchar *id, gint64 now);
gboolean fs_intel_source_is_stale (const FsIntelConfig *config,
                                   const gchar *id, gint64 now);

/* ---- updates (design 6.7) ------------------------------------------- */

/* The downloader.  The default calls fs_fetch() with the feed's URL,
 * the config's proxy, FS_FEED_MAX_BYTES and a 120 s timeout. */
typedef GBytes *(*FsIntelFetcher) (const gchar *url, const gchar *proxy,
                                   gpointer user_data, GError **error);
/* Tests replace it; NULL restores the default.  Process-wide. */
void fs_intel_set_fetcher (FsIntelFetcher fetcher, gpointer user_data);

typedef enum
{
	FS_INTEL_UPDATE_NOW             = 1 << 0,  /* ignore the schedule   */
	FS_INTEL_UPDATE_ACCEPT_SHRINK   = 1 << 1,  /* FS_FEED_ACCEPT_SHRINK */
	FS_INTEL_UPDATE_ACCEPT_COVERAGE = 1 << 2   /* ... _COVERAGE         */
} FsIntelUpdateFlags;

typedef enum
{
	FS_INTEL_UPDATED = 0,       /* a new copy was stored                */
	FS_INTEL_UNCHANGED,         /* same SHA-256 as the stored copy      */
	FS_INTEL_NOT_DUE,
	FS_INTEL_NEEDS_CONSENT,     /* enabled but terms not accepted       */
	FS_INTEL_REFUSED,           /* parse or judge refused it            */
	FS_INTEL_FAILED             /* the download failed                  */
} FsIntelUpdateOutcome;

typedef struct
{
	gchar               *id;
	FsIntelUpdateOutcome outcome;
	gchar               *message;   /* one line for the UI and the CLI  */
	guint                entries;   /* of the stored copy afterwards    */
} FsIntelUpdateResult;

void fs_intel_update_result_free (FsIntelUpdateResult *result);

/* Update the enabled feeds (catalog and custom) that are due, or with
 * only_id just that one (it must be enabled).  Local lists are never
 * fetched.  Every download goes through the fetcher only after the
 * enabled + accepted check, so a default configuration makes no
 * request at all [S14].  One audit line per feed attempted.  Returns
 * FsIntelUpdateResult* in config order (GPtrArray with a free func);
 * never NULL. */
GPtrArray *fs_intel_update (const FsIntelConfig *config,
                            const gchar *only_id, guint flags,
                            gint64 now);

/* ---- building (design 6.4) ------------------------------------------ */

#define FS_INTEL_MAX_INTERVALS 300000u
#define FS_INTEL_MAX_UNION4    (G_GUINT64_CONSTANT (1) << 26)

/* The rule set for the current config: one set per enabled source with
 * a stored copy (label = fs_intel_config_label), each minus the
 * protected ranges, the exceptions and everything in `host' (NULL:
 * nothing), with IPv4 mapped into 64:ff9b::/96 for out/both sets.  The
 * master switch off => an empty rule set.  notes (nullable) receives
 * gchar* sentences: sources left out and why, what was kept reachable
 * ("Kept reachable: 198.51.100.7, the SSH session running this"),
 * subset feeds both on.  Over FS_INTEL_MAX_INTERVALS or
 * FS_INTEL_MAX_UNION4: NULL with FS_INTEL_ERR_TOO_BIG naming the
 * largest sets.  A tampered stored list: NULL with
 * FS_INTEL_ERR_TAMPERED. */
FsIntelRuleset *fs_intel_build (const FsIntelConfig *config,
                                const FsHostNet *host,
                                GPtrArray **notes, GError **error);

/* ---- the gate and the lifecycle (design 6.5) ------------------------ */

typedef struct
{
	FsApplyResult result;     /* OK, DRY_RUN (held), FAILED             */
	gboolean      held;
	gchar        *hold_reason;
	gchar        *digest;     /* of the rule set given to the kernel    */
	guint         sets;
	guint         count4, count6;
	GPtrArray    *notes;      /* gchar*, from the build; never NULL     */
} FsIntelOutcome;

void fs_intel_outcome_free (FsIntelOutcome *outcome);

/* Build and enforce.  hold non-empty => nothing reaches the backend,
 * the result is FS_APPLY_DRY_RUN.  A backend without intel_apply =>
 * FS_APPLY_FAILED with FS_INTEL_ERR_UNSUPPORTED.  Before intel_apply,
 * the live counters are added to each source's carried totals.  On
 * success applied.state records the digest, the set ids and counts,
 * and suspended = FALSE.  `host' NULL means fs_hostnet_read() with the
 * enabled feeds' hosts.  One audit line ("intel-apply") per call.
 * Returns NULL only when the build failed (error set). */
FsIntelOutcome *fs_intel_apply_safe (const FsBackend *backend,
                                     const FsIntelConfig *config,
                                     const FsHostNet *host,
                                     const gchar *source,
                                     const gchar *hold, GError **error);

/* The user stopped the firewall: carry the counters, remove the table
 * (intel_clear), mark applied.state suspended.  A no-op (TRUE) when the
 * backend has no intel slots.  One audit line. */
gboolean fs_intel_suspend (const FsBackend *backend, const gchar *source,
                           GError **error);

/* The user started the firewall: when the master switch is on and some
 * source is enabled, fs_intel_apply_safe(); otherwise nothing (NULL
 * outcome, no error). */
FsIntelOutcome *fs_intel_resume (const FsBackend *backend,
                                 const gchar *source, const gchar *hold,
                                 GError **error);

/* ---- state (design 6.6) --------------------------------------------- */

typedef enum
{
	FS_INTEL_STATE_UNKNOWN = 0,
	FS_INTEL_STATE_OFF,          /* master off, or nothing enabled      */
	FS_INTEL_STATE_ENFORCED,     /* live digest == applied digest       */
	FS_INTEL_STATE_NOT_LOADED,   /* should be enforced; table missing   */
	FS_INTEL_STATE_DIFFERS,      /* a table, but not the applied one    */
	FS_INTEL_STATE_SUSPENDED,    /* the user stopped the firewall       */
	FS_INTEL_STATE_UNSUPPORTED,  /* no intel slots on this platform     */
	FS_INTEL_STATE_NEEDS_ROOT    /* cannot read the kernel or the store */
} FsIntelState;

/* "unknown" "off" "enforced" "not-loaded" "differs" "suspended"
 * "unsupported" "needs-root": the stable words for JSON and audit. */
const gchar *fs_intel_state_to_string (FsIntelState state);

/* Compare the kernel (backend->intel_live) with applied.state and the
 * config.  detail (nullable) receives one translated sentence for the
 * UI ("2 lists are enforced: Spamhaus DROP (IPv4), Feodo Tracker.").
 * config NULL => loaded from the store. */
FsIntelState fs_intel_state (const FsBackend *backend,
                             const FsIntelConfig *config,
                             gchar **detail);

/* Blocked packets per source id: carried totals plus the live
 * counters.  gchar* -> FsIntelCounter* (owned by the table); never
 * NULL. */
GHashTable *fs_intel_counters (const FsBackend *backend);

/* ---- lookup (design 6.8) -------------------------------------------- */

typedef struct
{
	GPtrArray *sources;      /* gchar* ids of enabled sources listing it */
	FsIntelDir dir;          /* union of their directions; 0 none        */
	gboolean   is_protected; /* fs_range_protected()                     */
	gboolean   is_exception;
	gboolean   is_host;      /* kept reachable by `host'                 */
	gboolean   blocked;      /* listed and none of the three above       */
} FsIntelLookup;

/* FALSE when `addr' is not a single address (v4, v6, v4-mapped v6).
 * Reads the enabled sources' stored lists.  host may be NULL. */
gboolean fs_intel_lookup (const FsIntelConfig *config,
                          const FsHostNet *host, const gchar *addr,
                          FsIntelLookup *result);
void     fs_intel_lookup_clear (FsIntelLookup *result);

/* "Blocked by threat intel: Spamhaus DROP (IPv4), Feodo Tracker" or
 * NULL when not blocked.  Caller frees. */
gchar   *fs_intel_lookup_sentence (const FsIntelConfig *config,
                                   const FsIntelLookup *result);

/* ---- applied journal ------------------------------------------------- */

/* Whether `id' is a set in the rule set last applied (and not
 * suspended): the kernel log parser accepts a "STOCKFW-TI <id>" line
 * only then [S17.3].  Cheap: cached by applied.state's mtime. */
gboolean fs_intel_applied_has (const gchar *id);

G_END_DECLS

#endif /* FS_INTEL_H */
