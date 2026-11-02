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
#include "core/fs-geodb.h"

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
 * parent /var/lib/stockfw is created 0755); an existing one that group
 * or others can read is set to 0700, and one whose mode cannot be
 * changed is FS_INTEL_ERR_UNSAFE_DIR.  Linux as root:
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

/* A location rule (design 12.3): countries or network owners (ASes)
 * from the location database, compiled into a set at every build. */
typedef enum
{
	FS_INTEL_LOCATION_COUNTRY = 1,   /* id "country-<slug>"             */
	FS_INTEL_LOCATION_ASN     = 2    /* id "asn-<slug>"                 */
} FsIntelLocationKind;

#define FS_INTEL_LOCATION_MAX_VALUES 1000u

typedef struct
{
	gchar              *id;
	gchar              *name;       /* as the user typed it            */
	FsIntelLocationKind kind;
	gchar             **countries;  /* COUNTRY: upper-case codes,
	                                 * NULL-terminated, no duplicates  */
	GArray             *asns;       /* ASN: guint32, ascending, no 0,
	                                 * no duplicates; NULL for COUNTRY  */
	gboolean            enabled;
	FsIntelDir          dir;
} FsIntelLocationConf;

typedef struct
{
	gboolean    enabled;      /* master switch; default TRUE             */
	gchar      *proxy;        /* NULL, or fs_fetch_proxy_is_acceptable() */
	GPtrArray  *feeds;        /* FsIntelFeedConf*: every catalog feed in
	                           * catalog order (defaults: off, the
	                           * catalog's direction), then custom feeds */
	GPtrArray  *lists;        /* FsIntelListConf*                        */
	FsRangeSet *exceptions;   /* normalized; never blocked               */
	/* Round 2 (design 12.2): the location database and its rules.     */
	gboolean    geo_enabled;      /* download it, use it; default FALSE  */
	gint64      geo_accepted_at;  /* its terms accepted, unix s; 0 never */
	GPtrArray  *locations;        /* FsIntelLocationConf*                */
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
 * replacing the list of that name (the same name in any case or
 * spacing).  A different name whose slug is already another list's id
 * ("Office VPN" and "office-vpn") is refused with FS_INTEL_ERR_INVALID
 * before anything is written.  The config is NOT saved: the caller
 * saves it.  *id_out (nullable) receives the id. */
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
/* The stored list, re-checked: strict syntax, the entry count and the
 * coverage caps, counted exactly as fs_feed_parse() counts them (so
 * whatever the parser accepted loads again); a list that fails them is
 * FS_INTEL_ERR_TAMPERED.  The parser's per-entry span floor is not
 * re-applied: a stored list is normalized, and adjacent entries that
 * each passed it are merged into wider intervals (eight adjacent /10s
 * are stored as one /7), so the caps are what bounds a tampered list.
 * Protected space in it is taken out, never blocked.  A missing list
 * is FS_INTEL_ERR_STORE. */
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
 * never NULL.
 *
 * The location database (design 12.5): with only_id FS_INTEL_GEO_ID
 * just the database (FAILED, without a request, while it is off); with
 * only_id NULL it comes after the feeds while it is on.  It is
 * downloaded only with the master switch on, the database on and its
 * terms accepted (NEEDS_CONSENT otherwise), at most once a day unless
 * FS_INTEL_UPDATE_NOW; REFUSED keeps the copy in use (an older one, a
 * bad signature, a copy from the future).  Its result's id is
 * FS_INTEL_GEO_ID and its entries 0; one audit line per attempt. */
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
 * FS_INTEL_ERR_TAMPERED.
 *
 * After the lists, while the location database is on (design 12.6):
 * one set per enabled location rule, the copy in use enumerated for its
 * countries or AS numbers, minus the same subtractions (exceptions win),
 * outbound rules also in 64:ff9b::/96.  Notes: a database not yet
 * downloaded (the rules are not enforced), a stale copy, a code the
 * database does not name, a rule that matches nothing, and the anycast
 * prefixes each rule kept.  Location sets have their own limit,
 * FS_INTEL_MAX_LOCATION_INTERVALS over all of them (NULL with
 * FS_INTEL_ERR_TOO_BIG), and do not count toward the lists' caps.  A
 * copy in use that no longer verifies: NULL with FS_INTEL_ERR_TAMPERED
 * (fail closed: the kernel keeps what it had). */
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

/* Every host a download contacts, to keep reachable (design 6.4,
 * [S7.2]): each enabled feed's host (a catalog feed's, or the host of a
 * custom feed's URL), the location database's host
 * (location.ipfire.org) while it is on and its terms accepted (12.5),
 * and -- when any of those is there and a proxy is configured -- the
 * proxy's host, since every download connects to the proxy rather than
 * to the feed.  Duplicates once.  NULL-terminated, never NULL;
 * g_strfreev(). */
gchar **fs_intel_update_hosts (const FsIntelConfig *config);

/* Build and enforce.  hold non-empty => nothing reaches the backend,
 * the result is FS_APPLY_DRY_RUN.  A backend without intel_apply =>
 * FS_APPLY_FAILED with FS_INTEL_ERR_UNSUPPORTED.  What the kernel holds
 * after intel_apply decides, not its verdict [S10].  The live counters,
 * read before intel_apply, are added to each source's carried totals
 * only when the replacement is proven [N8, P8]: a new digest where
 * another (or no table) was, or -- when the digest is the one already
 * loaded, which a refused transaction also leaves -- counters that went
 * down.  So a re-apply of an unchanged rule set that the tool fails
 * never counts the same packets twice, and is FS_APPLY_FAILED, with a
 * note that the same rules are still in force.  On success
 * applied.state records the digest, the set ids, the ids whose set has
 * rules (some addresses), the counts, and suspended = FALSE.  `host'
 * NULL means fs_hostnet_read (fs_intel_update_hosts ()).  One audit
 * line ("intel-apply") per call.  Returns NULL only when the build
 * failed (error set). */
FsIntelOutcome *fs_intel_apply_safe (const FsBackend *backend,
                                     const FsIntelConfig *config,
                                     const FsHostNet *host,
                                     const gchar *source,
                                     const gchar *hold, GError **error);

/* The user stopped the firewall: carry the counters, remove the table
 * (intel_clear), mark applied.state suspended.  With no table in the
 * kernel nothing is cleared.  A tool that is not there
 * (G_IO_ERROR_NOT_FOUND: Linux without nft) is not an error when
 * applied.state says StockFW left no table.  A no-op (TRUE) when the
 * backend has no intel slots.  With no store directory at all (no list
 * was ever turned on) nothing is created: a table found anyway is
 * removed, otherwise nothing happens.  One audit line when anything
 * was done. */
gboolean fs_intel_suspend (const FsBackend *backend, const gchar *source,
                           GError **error);

/* The user started the firewall.  First applied.state stops saying
 * "suspended" (it then records nothing loaded), so a Start whose apply
 * is held, refused or fails reads "not-loaded", never "suspended";
 * then, when the master switch is on and some source is enabled,
 * fs_intel_apply_safe() with host NULL; otherwise nothing (NULL
 * outcome, no error).  A no-op (NULL, no error) when the backend has
 * no intel slots, like fs_intel_suspend, or when there is no store
 * directory (no list was ever turned on; none is created). */
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
 * config NULL => loaded from the store.  Enforced needs the live
 * digest to be the applied one and every applied set that has
 * addresses to still have its counter rules (backend->intel_counters,
 * which lists the chains, never the sets): a table whose chains were
 * flushed is "differs".  Not seen: elements taken out of a set, or
 * some of a list's rules removed while others remain.  Nothing turned
 * on is "off" even when the kernel cannot be read, unless applied.state
 * says StockFW left a table there. */
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
	GPtrArray *sources;      /* gchar* ids of enabled feeds and local
	                          * lists listing it                         */
	FsIntelDir dir;          /* union of the directions of sources and
	                          * locations; 0 none                        */
	gboolean   is_protected; /* fs_range_protected()                     */
	gboolean   is_exception;
	gboolean   is_host;      /* kept reachable by `host'                 */
	gboolean   blocked;      /* listed or located, and none of the three
	                          * above                                    */
	/* Round 2 (design 12.8), filled while the location database is on
	 * and a usable copy is in the store: */
	GPtrArray *locations;    /* gchar* ids of enabled location rules
	                          * holding it; never NULL after a lookup   */
	gboolean   geo_found;    /* the database has a network for it        */
	gchar      country[3];   /* registered in; "" none                   */
	gchar     *country_name; /* NULL when the database names none        */
	guint32    asn;          /* 0 none                                   */
	gchar     *as_name;      /* NULL when unnamed                        */
	guint      geo_flags;    /* FS_GEODB_FLAG_*                          */
	gchar     *network;      /* the matching network, "a.b.c.0/24"       */
} FsIntelLookup;

/* FALSE when `addr' is not a single address (v4, v6, v4-mapped v6).
 * Reads the enabled sources' stored lists and, while the location
 * database is on, the copy in use (cached as for fs_intel_geo_lookup):
 * the enabled location rules that hold the address -- for a NAT64
 * address, the IPv4 address inside it, for rules that block outbound,
 * as the build maps it -- and its country, AS and network.  host may
 * be NULL. */
gboolean fs_intel_lookup (const FsIntelConfig *config,
                          const FsHostNet *host, const gchar *addr,
                          FsIntelLookup *result);
void     fs_intel_lookup_clear (FsIntelLookup *result);

/* "Blocked by threat intel: Spamhaus DROP (IPv4), Feodo Tracker" or
 * NULL when not blocked.  Caller frees. */
gchar   *fs_intel_lookup_sentence (const FsIntelConfig *config,
                                   const FsIntelLookup *result);

/* ---- Round 2: the location database and location rules (design 12) - */

/* The id of the location database in update results and labels. */
#define FS_INTEL_GEO_ID "location"
/* At most this many intervals over every location set (12.6). */
#define FS_INTEL_MAX_LOCATION_INTERVALS 500000u

/* Whether country and network-owner blocking can work here: FALSE on
 * Windows until Round 3 (12.10). */
gboolean fs_intel_geo_supported (void);

/* What kind of source an id names (design 12.7). */
typedef enum
{
	FS_INTEL_KIND_UNKNOWN = 0,
	FS_INTEL_KIND_FEED,          /* catalog feed                         */
	FS_INTEL_KIND_CUSTOM,        /* "custom-"                            */
	FS_INTEL_KIND_LIST,          /* "local-"                             */
	FS_INTEL_KIND_COUNTRY,       /* "country-"                           */
	FS_INTEL_KIND_ASN            /* "asn-"                               */
} FsIntelSourceKind;

/* From the id alone (its prefix, or the catalog). */
FsIntelSourceKind fs_intel_source_kind (const gchar *id);

/* The consent text for the location database (12.2): the host, how
 * often, what the host learns, the size, the licence status,
 * "registered in", anycast.  Plain text, translated.  Caller frees. */
gchar *fs_intel_geo_consent_text (const FsIntelConfig *config);
/* One line for every screen that shows location data: where it comes
 * from and its licence status (12.1).  Caller frees. */
gchar *fs_intel_geo_attribution (void);

/* Turn the location database on.  Terms never accepted need
 * accept_terms (then geo_accepted_at becomes now); without it
 * FS_INTEL_ERR_CONSENT and nothing changes.  Where it cannot work
 * (fs_intel_geo_supported), FS_INTEL_ERR_UNSUPPORTED.  Off keeps the
 * rules and enforces none of them. */
gboolean fs_intel_config_enable_geo  (FsIntelConfig *config,
                                      gboolean accept_terms,
                                      GError **error);
void     fs_intel_config_disable_geo (FsIntelConfig *config);

FsIntelLocationConf *fs_intel_config_location (const FsIntelConfig *config,
                                               const gchar *id);

/* A location rule: id "country-<slug of name>" or "asn-<slug>", enabled,
 * in `dir'.  values: country codes (two letters, any case) for COUNTRY,
 * AS numbers ("13335" or "AS13335") for ASN; 1 to
 * FS_INTEL_LOCATION_MAX_VALUES after duplicates are dropped.  Needs the
 * database's terms accepted (FS_INTEL_ERR_CONSENT otherwise); a bad
 * value or name is FS_INTEL_ERR_INVALID naming it; a name whose id is
 * already a rule is refused.  The config is not saved: the caller
 * saves.  *id_out (nullable) receives the id. */
gboolean fs_intel_config_add_location (FsIntelConfig *config,
                                       const gchar *name,
                                       FsIntelLocationKind kind,
                                       const gchar *const *values,
                                       FsIntelDir dir, gchar **id_out,
                                       GError **error);
/* Replace a rule's values (the same rules as add). */
gboolean fs_intel_config_set_location_values (FsIntelConfig *config,
                                              const gchar *id,
                                              const gchar *const *values,
                                              GError **error);

/* The location database in the store. */
typedef struct
{
	gboolean present;        /* a copy that verifies and checks is there */
	gint64   created_at;     /* of the copy in use; 0 none               */
	gboolean stale;          /* older than FS_GEODB_STALE_S at `now'      */
	gint64   attempted_at;   /* last update attempt; 0 never             */
	gint64   fetched_at;     /* last successful update; 0 never          */
	gchar   *last_error;     /* the last attempt failed: why             */
	gchar   *refused;        /* the last download was refused: why       */
	gchar   *damaged;        /* the copy in use fails verify/check: why  */
	gchar   *license;        /* as the file declares it                  */
	guint    networks, countries, ases;
} FsIntelGeoStatus;

/* FALSE (error set) only when the store cannot be opened. */
gboolean fs_intel_geo_status (FsIntelGeoStatus *status, gint64 now,
                              GError **error);
void     fs_intel_geo_status_clear (FsIntelGeoStatus *status);

/* The picker, from the copy in use: every country (FsGeodbCountry*,
 * ascending by code) and an AS search (FsGeodbAs*, as
 * fs_geodb_search_as).  NULL with an error when there is no usable
 * copy.  Caller unrefs. */
GPtrArray *fs_intel_geo_countries (GError **error);
GPtrArray *fs_intel_geo_search_as (const gchar *query, guint max,
                                   GError **error);

/* What a selection covers (design 12.6). */
typedef struct
{
	guint   prefixes4, prefixes6;   /* the fewest CIDR prefixes          */
	guint64 addresses4;
	guint64 addresses6;             /* saturating                        */
	guint   anycast_prefixes;       /* prefixes of the part that lies in
	                                 * networks flagged anycast          */
	guint64 anycast_addresses4;
	guint64 anycast_addresses6;     /* saturating                        */
} FsIntelLocationStats;

/* The picker's preview: `values' as fs_intel_config_add_location takes
 * them, against the copy in use, after the protected ranges and the
 * config's exceptions are taken out (config nullable; this computer's
 * own addresses are not taken out: they depend on where it is when it
 * applies).  FALSE with an error for a bad value or no usable copy. */
gboolean fs_intel_location_stats (const FsIntelConfig *config,
                                  FsIntelLocationKind kind,
                                  const gchar *const *values,
                                  FsIntelLocationStats *stats,
                                  GError **error);

/* One address to its registered country, AS and flags, from the copy
 * in use, without evaluating any rule: the cheap call for events and
 * connections.  The opened database is cached per process and reopened
 * only when location.db changes (device, inode, size, mtime).  FALSE
 * with an error when the database is off in `config', there is no
 * usable copy, or `addr' is not an address; TRUE with match->found
 * FALSE when no network holds it.  Clear with fs_geodb_match_clear(). */
gboolean fs_intel_geo_lookup (const FsIntelConfig *config,
                              const gchar *addr, FsGeodbMatch *match,
                              GError **error);

/* ---- applied journal ------------------------------------------------- */

/* Whether `id' is a set in the rule set last applied (and not
 * suspended): the kernel log parser accepts a "STOCKFW-TI <id>" line
 * only then [S17.3].  Cheap: cached by applied.state's mtime. */
gboolean fs_intel_applied_has (const gchar *id);

G_END_DECLS

#endif /* FS_INTEL_H */
