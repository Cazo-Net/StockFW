/*---[ fs-intel.h ]------------------------------------------------------
 * The threat-intel engine (1.0.7): configuration, the on-disk store,
 * downloads, building the rule set, the apply gate, and lookups.
 *
 *   config   which feeds are on (and their direction), custom feeds,
 *            countries and AS numbers to block, exceptions, the
 *            location-data URL, and the master switch.  intel.conf.
 *   store    per feed <id>.list (normalized ranges) and <id>.state
 *            (when, what, how it went); location.sfwgeo.
 *   update   download (only feeds the user enabled -- StockFW makes no
 *            network request otherwise), parse, guard, store.
 *   build    config + store + location db -> FsIntelRuleset.
 *   gate     audit-only / Policy Lock honoured, one audit line per try.
 *   lookup   country, network owner, listing feeds for one address.
 *
 * Directory: $STOCKFW_INTEL_DIR, else /var/lib/stockfw/intel for root
 * on Linux, else <rules dir>/intel.  Created 0755 on first write; files
 * are written to a temp name in the same directory and renamed.
 *--------------------------------------------------------------------*/
#ifndef FS_INTEL_H
#define FS_INTEL_H

#include <glib.h>
#include "core/fs-backend.h"
#include "core/fs-feed.h"
#include "core/fs-geo.h"
#include "core/fs-intelset.h"
#include "core/fs-iprange.h"

G_BEGIN_DECLS

GQuark fs_intel_error_quark (void);
#define FS_INTEL_ERROR (fs_intel_error_quark ())

enum
{
	FS_INTEL_ERR_CONFIG = 1,   /* intel.conf unreadable or invalid      */
	FS_INTEL_ERR_FETCH,        /* download failed                       */
	FS_INTEL_ERR_PARSE,        /* body refused by the parser            */
	FS_INTEL_ERR_GUARD,        /* refused by the shrink guard           */
	FS_INTEL_ERR_STORE,        /* could not write the store             */
	FS_INTEL_ERR_UNKNOWN_FEED,
	FS_INTEL_ERR_NO_GEO,       /* location data needed but missing      */
	FS_INTEL_ERR_UNSUPPORTED   /* backend cannot enforce threat intel   */
};

/* The store directory (see above).  Caller frees. */
gchar *fs_intel_dir (void);

/* ---- configuration ------------------------------------------------ */

typedef struct
{
	gchar       *id;        /* catalog id, or "custom-<name>"           */
	gchar       *name;      /* display name                             */
	gchar       *url;       /* https://                                 */
	FsFeedFormat format;
	FsIntelDir   dir;
	gboolean     enabled;
	gboolean     custom;    /* FALSE for catalog feeds                  */
	guint        interval_hours;
} FsIntelFeedConf;

typedef struct
{
	gboolean    enabled;    /* master switch: FALSE => empty rule set   */
	GPtrArray  *feeds;      /* FsIntelFeedConf*: every catalog feed,
	                         * in catalog order, then the custom ones   */
	GPtrArray  *countries;  /* gchar*, ISO alpha-2 upper case, sorted   */
	GArray     *asns;       /* guint32, sorted, unique                  */
	FsIntelDir  geo_dir;    /* direction of the location set (IN)       */
	FsRangeSet *exceptions; /* never blocked; normalized                */
	gchar      *geo_url;    /* location source; default iptoasn         */
} FsIntelConfig;

/* Defaults: master switch on, every feed off, no countries, no ASNs,
 * geo_dir IN, no exceptions, geo_url = FS_INTEL_DEFAULT_GEO_URL. */
#define FS_INTEL_DEFAULT_GEO_URL \
	"https://iptoasn.com/data/ip2asn-combined.tsv.gz"

FsIntelConfig   *fs_intel_config_new   (void);
void             fs_intel_config_free  (FsIntelConfig *config);
/* A missing file is not an error (defaults).  Unknown keys are kept
 * out; invalid values (bad URL, bad country, bad range) fail the load
 * with FS_INTEL_ERR_CONFIG naming the key. */
FsIntelConfig   *fs_intel_config_load  (GError **error);
gboolean         fs_intel_config_save  (const FsIntelConfig *config,
                                        GError **error);
FsIntelFeedConf *fs_intel_config_feed  (const FsIntelConfig *config,
                                        const gchar *id);
/* Add a custom feed; its id becomes "custom-<slug of name>".  FALSE
 * when the URL is not acceptable or the id is taken. */
gboolean         fs_intel_config_add_custom (FsIntelConfig *config,
                                             const gchar *name,
                                             const gchar *url,
                                             FsFeedFormat format,
                                             GError **error);
gboolean         fs_intel_config_remove_custom (FsIntelConfig *config,
                                                const gchar *id);
/* Enable exactly the catalog's recommended feeds (others untouched). */
void             fs_intel_config_enable_recommended (FsIntelConfig *config);

/* ---- store -------------------------------------------------------- */

typedef struct
{
	gchar  *id;
	gint64  fetched_at;      /* last successful update, unix s; 0 never */
	gint64  attempted_at;    /* last attempt                            */
	gchar  *source_url;      /* the URL that answered                    */
	gchar  *sha256;          /* of the raw body                          */
	guint   count4;          /* intervals stored                         */
	guint   count6;
	FsFeedParseStats stats;  /* of the last accepted body                */
	gchar  *last_error;      /* NULL when the last attempt succeeded     */
} FsIntelFeedState;

/* NULL when the feed was never fetched. */
FsIntelFeedState *fs_intel_feed_state (const gchar *id);
void              fs_intel_feed_state_free (FsIntelFeedState *state);
/* The stored list, or NULL with error (missing file is an error here). */
FsRangeSet       *fs_intel_feed_load  (const gchar *id, GError **error);
/* TRUE when the feed is due for an update (never fetched, or older than
 * its interval). */
gboolean          fs_intel_feed_is_due   (const FsIntelFeedConf *feed,
                                          gint64 now);
/* TRUE when the stored copy is older than 7 x its interval. */
gboolean          fs_intel_feed_is_stale (const FsIntelFeedConf *feed,
                                          gint64 now);

/* ---- downloads ---------------------------------------------------- */

/* Download `url' into the file `dest' (which the fetcher creates).
 * Returns FALSE with a GError on any failure. */
typedef gboolean (*FsIntelFetchFunc) (const gchar *url,
                                      const gchar *dest,
                                      gpointer user_data,
                                      GError **error);

/* The default fetcher: curl with a fixed, argv-only command line (see
 * the design doc, s4).  Fails cleanly when curl is not installed. */
gboolean fs_intel_fetch_curl (const gchar *url, const gchar *dest,
                              gpointer user_data, GError **error);
/* Tests replace the fetcher; NULL restores curl. */
void     fs_intel_set_fetcher (FsIntelFetchFunc func, gpointer user_data);

typedef struct
{
	gchar   *id;
	gboolean ok;
	gboolean skipped;        /* not due (and not forced)                 */
	gchar   *message;        /* one line for the UI/CLI                  */
	guint    count4;
	guint    count6;
} FsIntelUpdateResult;

void fs_intel_update_result_free (FsIntelUpdateResult *result);

/* Update the enabled feeds that are due (only_id NULL), or one feed
 * (only_id, enabled or not -- an explicit request is consent).  force
 * ignores "not due" and the shrink guard.  Returns FsIntelUpdateResult*
 * per feed considered (GPtrArray with free func).  A failed update
 * never removes the previous good copy. */
GPtrArray *fs_intel_update (const FsIntelConfig *config,
                            const gchar *only_id, gboolean force);

/* Location data: download config->geo_url (or import a local file when
 * `path' is not NULL) and compile location.sfwgeo.  The previous file
 * is kept on any failure. */
gboolean fs_intel_geo_update (const FsIntelConfig *config,
                              const gchar *path, GError **error);
/* The compiled database's path (may not exist).  Caller frees. */
gchar   *fs_intel_geo_path (void);

/* ---- building and applying ---------------------------------------- */

/* Everything the kernel should block, from the config and the store:
 * one set per enabled feed that has a stored list (a feed never fetched
 * contributes nothing and is reported in *notes), one "geo" set when
 * countries or ASNs are selected (FS_INTEL_ERR_NO_GEO when they are but
 * there is no location data), each minus the protected ranges, the
 * system's DNS resolvers and the exceptions.  notes (nullable)
 * receives human sentences about anything left out.  Master switch off
 * => an empty rule set. */
FsIntelRuleset *fs_intel_build (const FsIntelConfig *config,
                                GPtrArray **notes, GError **error);

/* The gate.  hold non-empty => nothing reaches the backend, the result
 * is FS_APPLY_DRY_RUN and an audit line says why.  A backend without
 * intel_apply => FS_APPLY_FAILED with FS_INTEL_ERR_UNSUPPORTED.  One
 * audit line per call ("intel-apply"). */
FsApplyResult fs_intel_apply_safe (const FsBackend *backend,
                                   const FsIntelRuleset *ruleset,
                                   const gchar *source,
                                   const gchar *hold,
                                   GError **error);

/* ---- lookups ------------------------------------------------------ */

/* A loaded view of the store for fast lookups: every stored feed list
 * and the location database.  Cheap to query from the UI thread. */
typedef struct _FsIntelIndex FsIntelIndex;

FsIntelIndex *fs_intel_index_load   (const FsIntelConfig *config);
void          fs_intel_index_free   (FsIntelIndex *index);
/* The process-wide index, loaded on first use and reloaded when the
 * store changes (by mtime).  Never NULL. */
FsIntelIndex *fs_intel_index_shared (void);
void          fs_intel_index_invalidate (void);

typedef struct
{
	gchar     country[3];   /* "" unknown                               */
	const gchar *country_name; /* static; NULL unknown                  */
	guint32   asn;          /* 0 unknown                                */
	gchar    *owner;        /* NULL unknown                             */
	GPtrArray *feeds;       /* gchar* feed ids listing the address      */
	gboolean  is_protected; /* in fs_range_protected()                  */
	gboolean  is_exception; /* in the user's exceptions                 */
	gboolean  blocked;      /* would the current config block it        */
} FsIntelLookup;

/* FALSE when `addr' is not an address. */
gboolean fs_intel_lookup (FsIntelIndex *index, const gchar *addr,
                          FsIntelLookup *result);
void     fs_intel_lookup_clear (FsIntelLookup *result);

/* "US", "AS13335 Cloudflare", "Spamhaus DROP, Feodo" one-liners for the
 * table columns; "" when unknown.  Caller frees. */
gchar *fs_intel_lookup_country_text (const FsIntelLookup *result);
gchar *fs_intel_lookup_network_text (const FsIntelLookup *result);
gchar *fs_intel_lookup_feeds_text   (const FsIntelLookup *result);

G_END_DECLS

#endif /* FS_INTEL_H */
