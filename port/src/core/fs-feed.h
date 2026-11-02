/*---[ fs-feed.h ]-------------------------------------------------------
 * Threat-intel feeds (1.0.7): the built-in catalog, the list formats
 * the feeds publish, and the strict parser that turns a download into
 * a normalized FsRangeSet.
 *
 * Nothing here touches the network or the disk; fs-intel.c fetches and
 * stores, this module only judges bytes.  Every limit below exists so a
 * hostile or broken feed cannot block the internet, eat the machine's
 * memory, or smuggle text into a log line.
 *--------------------------------------------------------------------*/
#ifndef FS_FEED_H
#define FS_FEED_H

#include <glib.h>
#include "core/fs-iprange.h"

G_BEGIN_DECLS

typedef enum
{
	FS_FEED_FMT_AUTO = 0,     /* sniff: '{' first => Spamhaus JSON,
	                           * three-column numeric => DShield,
	                           * otherwise plain                       */
	FS_FEED_FMT_PLAIN,        /* one address/CIDR/range per line;
	                           * '#' and ';' start comments; anything
	                           * after the first whitespace or ';' on a
	                           * line is ignored (FireHOL netset/ipset,
	                           * Spamhaus .txt, abuse.ch, blocklist.de,
	                           * ET, CINS, Tor bulk list)               */
	FS_FEED_FMT_SPAMHAUS_JSON,/* NDJSON, one object per line with a
	                           * "cidr" string; other lines (the
	                           * trailing metadata object) ignored      */
	FS_FEED_FMT_DSHIELD       /* "start<TAB>end<TAB>bits..." rows,
	                           * '#' comments, a "Start" header row     */
} FsFeedFormat;

/* "plain" / "spamhaus-json" / "dshield" / "auto" <-> enum. */
const gchar *fs_feed_format_to_string   (FsFeedFormat fmt);
gboolean     fs_feed_format_from_string (const gchar *text,
                                         FsFeedFormat *fmt);

/* One built-in feed.  All strings are static. */
typedef struct
{
	const gchar *id;            /* [a-z0-9-], unique, <= 32 chars       */
	const gchar *name;          /* "Spamhaus DROP"                      */
	const gchar *category;      /* "Hijacked networks", "Botnet C2" ... */
	const gchar *url;           /* https:// primary                     */
	const gchar *mirror_url;    /* https:// fallback, or NULL           */
	const gchar *info_url;      /* the provider's page                  */
	const gchar *license;       /* short terms line, shown in the UI    */
	const gchar *description;   /* one sentence for the UI              */
	FsFeedFormat format;
	guint        interval_hours;/* how often an update is due           */
	gboolean     recommended;   /* part of the "Recommended" preset     */
} FsFeedInfo;

/* The catalog, in display order.  *n receives the count. */
const FsFeedInfo *fs_feed_catalog      (guint *n);
const FsFeedInfo *fs_feed_catalog_find (const gchar *id);

/* Limits. */
#define FS_FEED_MAX_BYTES    (32u * 1024u * 1024u)
#define FS_FEED_MAX_ENTRIES  1000000u
#define FS_FEED_MAX_LINE     4096u
/* Broader than this is refused as "too broad": no real blocklist
 * lists a /7, and a feed that does is broken or hostile. */
#define FS_FEED_MIN_PREFIX4  8u
#define FS_FEED_MIN_PREFIX6  16u

typedef struct
{
	guint lines;          /* physical lines seen                      */
	guint accepted;       /* entries kept (before normalizing)         */
	guint comments;       /* blank and comment lines                   */
	guint invalid;        /* lines that did not parse                  */
	guint too_broad;      /* refused by the prefix floor               */
	guint host_bits;      /* CIDRs with host bits set (masked, kept)   */
	guint v4;             /* intervals after normalizing               */
	guint v6;
} FsFeedParseStats;

/* Parse a feed body.  Errors (GError, NULL return):
 *   - len > FS_FEED_MAX_BYTES, or an embedded NUL byte;
 *   - more than FS_FEED_MAX_ENTRIES accepted entries;
 *   - nothing at all parsed while some lines were invalid (a page of
 *     HTML instead of a list) -- an empty but well-formed list (only
 *     comments) is NOT an error, it returns an empty set.
 * A UTF-8 BOM and CRLF line ends are accepted.  The returned set is
 * normalized.  stats may be NULL. */
FsRangeSet *fs_feed_parse (const gchar *data, gsize len,
                           FsFeedFormat fmt,
                           FsFeedParseStats *stats,
                           GError **error);

/* [a-z0-9][a-z0-9-]{0,31} -- also what may appear in a log prefix. */
gboolean fs_feed_id_is_valid (const gchar *id);

/* A URL StockFW is willing to hand to the downloader: "https://",
 * <= 2048 bytes, printable ASCII only (no spaces or controls), no
 * "user@" credentials, a non-empty host.  On FALSE, error says why. */
gboolean fs_feed_url_is_acceptable (const gchar *url, GError **error);

G_END_DECLS

#endif /* FS_FEED_H */
