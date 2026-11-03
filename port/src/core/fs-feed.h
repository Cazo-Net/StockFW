/*---[ fs-feed.h ]-------------------------------------------------------
 * Threat-intel feeds (1.0.7): the built-in catalog, the formats feeds
 * publish, the strict parser, and the judge that decides whether a new
 * download may replace the copy we have.
 *
 * Nothing here touches the network or the disk: fs-fetch.c downloads,
 * fs-intel.c stores, this module only judges bytes.  Every limit exists
 * so a hostile or broken feed cannot block the internet, eat memory or
 * smuggle text into a log line.  Design: docs/1.0.7-threat-intel-
 * design.md, section 4.
 *--------------------------------------------------------------------*/
#ifndef FS_FEED_H
#define FS_FEED_H

#include <glib.h>
#include "core/fs-iprange.h"
#include "core/fs-intelset.h"   /* FsIntelDir */

G_BEGIN_DECLS

GQuark fs_feed_error_quark (void);
#define FS_FEED_ERROR (fs_feed_error_quark ())

enum
{
	FS_FEED_ERR_TOO_LARGE = 1,  /* over FS_FEED_MAX_BYTES or a NUL byte */
	FS_FEED_ERR_TOO_MANY,       /* over FS_FEED_MAX_ENTRIES entries     */
	FS_FEED_ERR_NOT_A_LIST,     /* mostly not addresses (HTML ...), or
	                             * poisoned (too broad >= kept)         */
	FS_FEED_ERR_COVERAGE,       /* over a coverage cap                  */
	FS_FEED_ERR_URL             /* fs_feed_url_is_acceptable() refused  */
};

typedef enum
{
	FS_FEED_FMT_PLAIN = 1,      /* one address/CIDR/range per line; '#'
	                             * and ';' start comments; anything
	                             * after the first whitespace, ';' or
	                             * ',' is ignored                       */
	FS_FEED_FMT_SPAMHAUS_JSON,  /* NDJSON: objects with a "cidr" string;
	                             * the "type":"metadata" object gives
	                             * "timestamp" and "records"            */
	FS_FEED_FMT_DSHIELD         /* start<TAB>end<TAB>prefix... rows,
	                             * '#' comments, a "Start" header row   */
} FsFeedFormat;

/* "plain" / "spamhaus-json" / "dshield" <-> enum (exact, lower case).
 * to_string returns NULL for a value that is none of the three. */
const gchar *fs_feed_format_to_string   (FsFeedFormat fmt);
gboolean     fs_feed_format_from_string (const gchar *text,
                                         FsFeedFormat *fmt);

/* One built-in feed.  All strings are static, in English; the UI
 * translates name/category/description through the usual _() macro. */
typedef struct
{
	const gchar *id;             /* fs_intel_id_is_valid(), <= 32 chars */
	const gchar *name;           /* "Spamhaus DROP (IPv4)"              */
	const gchar *category;       /* "Hijacked networks"                 */
	const gchar *description;    /* one sentence                        */
	const gchar *url;            /* https://, the only URL contacted    */
	const gchar *host;           /* the host in url, for consent text   */
	const gchar *info_url;       /* the publisher's page about the list */
	const gchar *terms_url;      /* where its terms of use are; never
	                              * NULL                                */
	const gchar *license;        /* licence name, only where verified
	                              * ("CC0 1.0"); NULL means "see the
	                              * provider's terms"                   */
	gboolean     noncommercial;  /* the terms forbid commercial use     */
	FsFeedFormat format;
	FsIntelDir   default_dir;
	guint        interval_hours; /* how often an update is due          */
	gboolean     recommended;    /* in the "Recommended" preset         */
	const gchar *includes;       /* space-separated ids this list
	                              * already contains, or NULL           */
	gboolean     has_v6;         /* the list publishes IPv6 entries     */
	const gchar *credit;         /* the attribution shown wherever the
	                              * list is named (Spamhaus asks for
	                              * credit in a product); never NULL    */
} FsFeedInfo;

/* The catalog, in display order (design section 4.1).  *n receives the
 * count. */
const FsFeedInfo *fs_feed_catalog      (guint *n);
const FsFeedInfo *fs_feed_catalog_find (const gchar *id);

/* ---- limits (design 4.3) ------------------------------------------ */

#define FS_FEED_MAX_BYTES     (32u * 1024u * 1024u)
#define FS_FEED_MAX_ENTRIES   200000u
#define FS_FEED_MAX_LINE      4096u
/* The widest piece of one entry that is left after the protected
 * ranges are taken out: an IPv4 piece of more than 2^22 addresses (a
 * /10) or an IPv6 piece of more than 2^99 (a /29) makes the entry too
 * broad.  Measured on the interval, never on a prefix length [S1, S4]. */
#define FS_FEED_MAX_SPAN4     (G_GUINT64_CONSTANT (1) << 22)
#define FS_FEED_MAX_SPAN6_LOG2 99u
/* Coverage caps on a whole list: IPv4 addresses, and IPv6 counted in
 * /64 networks (an interval's /64 count rounds up). */
#define FS_FEED_MAX_COVER4    (G_GUINT64_CONSTANT (1) << 25)
#define FS_FEED_MAX_COVER6_64 (G_GUINT64_CONSTANT (1) << 42)

typedef struct
{
	guint   lines;            /* physical lines                         */
	guint   comments;         /* blank, comment and header lines        */
	guint   entries;          /* data lines that gave a usable entry:
	                           * kept, even when all of it was
	                           * protected space                        */
	guint   invalid;          /* data lines that did not parse          */
	guint   first_invalid;    /* 1-based line number; 0 when none       */
	guint   too_broad;        /* entries dropped by the span floor (not
	                           * counted in entries)                    */
	guint   protected_hits;   /* kept entries that overlapped protected
	                           * ranges (that part was taken out)      */
	guint   host_bits;        /* CIDRs with host bits set (kept,
	                           * masked)                                */
	guint   v4;               /* intervals in the result, per family    */
	guint   v6;
	guint64 cover4;           /* IPv4 addresses in the result           */
	guint64 cover6_64;        /* IPv6 /64 networks in the result
	                           * (saturating)                           */
	gint64  content_date;     /* unix seconds from the list itself; 0
	                           * when it carries none                   */
	guint   meta_records;     /* Spamhaus metadata "records"; 0 none    */
} FsFeedParseStats;

/* Parse a feed body into a normalized set from which the protected
 * ranges (fs_range_protected) are already subtracted.  Refuses (NULL +
 * FS_FEED_ERROR) a body that is too large or holds a NUL byte, has more
 * than FS_FEED_MAX_ENTRIES entries, is not a list (nothing parsed while
 * lines were invalid, or more invalid data lines than entries), is
 * poisoned, or is over a coverage cap.  Poisoned (NOT_A_LIST): at least
 * as many entries were too broad as were kept (too_broad > 0 and
 * too_broad >= entries), so 221 /8s, 1,000 /9s or 82 IPv6 /16s are
 * refused, while an aggregate whose wide entries are all protected
 * space (FireHOL's 224.0.0.0/3) loses nothing and is accepted.  A
 * well-formed list with no entries is not an error: it returns an empty
 * set (fs_feed_judge decides about that).  A UTF-8 BOM and CRLF are
 * accepted.  stats may be NULL; when given it is filled on success and
 * on failure alike (up to the line that hit the entry cap, for
 * TOO_MANY). */
FsRangeSet *fs_feed_parse (const gchar *data, gsize len, FsFeedFormat fmt,
                           FsFeedParseStats *stats, GError **error);

/* The same guards for a file the user imports (design 6.3), read with
 * fs_blocklist_parse_csv()'s CSV rules: first field, an optional
 * header, quoted fields.  content_date is always 0. */
FsRangeSet *fs_feed_parse_csv (const gchar *data, gsize len,
                               FsFeedParseStats *stats, GError **error);

/* IPv6 coverage of `set' in /64 networks, as the coverage cap counts
 * it (FsFeedParseStats.cover6_64): an interval of d + 1 addresses
 * counts ceil ((d + 1) / 2^64) = d.hi + 1, the counts are added, and
 * the sum saturates.  The engine re-checks a stored list with this
 * same count, so a list the parser accepted can always be loaded
 * again. */
guint64 fs_feed_cover6_64 (const FsRangeSet *set);

/* The design's URL rule (4.4): https:// only, <= 2048 bytes, printable
 * ASCII with no spaces, no "user@" part, a non-empty host, not starting
 * with '-'.  The host must be a DNS name (letters, digits, '-', '.',
 * '_') or a bracketed IPv6 literal, with an optional port 1-65535.  On
 * FALSE, error (FS_FEED_ERROR, FS_FEED_ERR_URL) says why in one
 * sentence. */
gboolean fs_feed_url_is_acceptable (const gchar *url, GError **error);

/* The URL as every surface but the feed editor shows it: a query
 * string becomes "?…" [S18], and a "user:password@" part (which the
 * URL rule refuses, but a refusal may still show) becomes "…@".
 * NULL for NULL.  Caller frees. */
gchar *fs_feed_url_redacted (const gchar *url);

/* ---- may a new copy replace the old one? (design 4.5) ------------- */

#define FS_FEED_HISTORY 7u

typedef struct
{
	guint   n;                          /* accepted copies remembered  */
	guint   entries[FS_FEED_HISTORY];   /* newest first                */
	guint64 cover4[FS_FEED_HISTORY];
	gint64  content_date;               /* of the newest copy; 0 none  */
} FsFeedHistory;

typedef enum
{
	FS_FEED_ACCEPT_SHRINK   = 1 << 0,   /* --accept-shrink              */
	FS_FEED_ACCEPT_COVERAGE = 1 << 1    /* --accept-coverage            */
} FsFeedAcceptFlags;

typedef enum
{
	FS_FEED_VERDICT_OK = 0,
	FS_FEED_VERDICT_EMPTY,      /* nothing now, something before        */
	FS_FEED_VERDICT_SHRANK,     /* < 1/4 of the recent largest          */
	FS_FEED_VERDICT_GREW,       /* coverage > 2x and > +2^22 addresses  */
	FS_FEED_VERDICT_ROLLBACK    /* older content date than ours         */
} FsFeedVerdict;

/* Judge a parsed copy against the history.  An empty history accepts
 * anything that parsed.  EMPTY: the new copy has no intervals while the
 * copy in use (the newest) blocked something: it covered IPv4
 * addresses, or had more entries than the new copy (an unchanged list
 * of protected space only is not EMPTY).  SHRANK: entries, or IPv4
 * coverage, below a quarter of the largest of the recent copies (when
 * that was 8 or more, or 2^16 or more); a recent copy that was itself
 * below a quarter of the copies before it was let in by an accepted
 * shrink, so the copies older than it no longer count.  GREW: IPv4
 * coverage more than twice the largest recent coverage (all recent
 * copies) and more than 2^22 above it.  ROLLBACK: both copies dated
 * and the new one older.  Checked in the
 * order EMPTY, ROLLBACK, SHRANK, GREW; the first that applies and is
 * not overridden is the verdict.  EMPTY, SHRANK and ROLLBACK are
 * overridden by FS_FEED_ACCEPT_SHRINK, GREW by FS_FEED_ACCEPT_COVERAGE.
 * why, when not NULL, receives one sentence for the UI and the audit
 * line when the verdict is not OK ("The new copy has 3 entries; recent
 * copies had up to 1,614."), and NULL when it is OK.  Caller frees
 * *why. */
FsFeedVerdict fs_feed_judge (const FsFeedParseStats *now,
                             const FsFeedHistory *history,
                             guint flags, gchar **why);

/* Push an accepted copy onto the history (newest first, at most
 * FS_FEED_HISTORY kept). */
void fs_feed_history_push (FsFeedHistory *history,
                           const FsFeedParseStats *accepted);

G_END_DECLS

#endif /* FS_FEED_H */
