/*---[ fs-geo.h ]--------------------------------------------------------
 * Offline location data (1.0.7): which country and which network owner
 * (autonomous system) an address belongs to.
 *
 * Source data (text) is compiled once into a compact binary file,
 * location.sfwgeo, and every lookup afterwards is a binary search over
 * a read-only mapping.  The reader treats the file as untrusted: every
 * count and offset is bounds-checked when it is opened, so a truncated
 * or tampered file is refused with an error, never read past its end.
 *
 * Accepted sources (fs_geo_builder_add_*):
 *   FS_GEO_FMT_IPTOASN   iptoasn.com ip2asn-{combined,v4,v6}.tsv:
 *                        "start<TAB>end<TAB>asn<TAB>CC<TAB>owner"
 *                        (asn 0 = not routed; CC "None" = unknown)
 *   FS_GEO_FMT_CSV_COUNTRY  "start,end,CC"       (ip-location-db,
 *                                                  DB-IP Lite country)
 *   FS_GEO_FMT_CSV_ASN      "start,end,asn,owner" (ip-location-db ASN;
 *                        the owner may be double-quoted with "" escapes)
 * A source may be gzip-compressed (detected by its magic bytes).
 *
 * Registration-based data (iptoasn) says where a network is registered,
 * not where a device is; the UI says "registered in" for that reason.
 *--------------------------------------------------------------------*/
#ifndef FS_GEO_H
#define FS_GEO_H

#include <glib.h>
#include "core/fs-iprange.h"

G_BEGIN_DECLS

typedef enum
{
	FS_GEO_FMT_AUTO = 0,     /* sniff the first data line */
	FS_GEO_FMT_IPTOASN,
	FS_GEO_FMT_CSV_COUNTRY,
	FS_GEO_FMT_CSV_ASN
} FsGeoFormat;

/* Limits on what a builder accepts. */
#define FS_GEO_MAX_SOURCE_BYTES  (512u * 1024u * 1024u) /* after gunzip */
#define FS_GEO_MAX_ROWS          8000000u
#define FS_GEO_MAX_OWNER         128u    /* bytes kept of an AS owner  */

/* ---- countries ---------------------------------------------------- */

/* ISO 3166-1 alpha-2 (upper case) -> English short name; NULL when the
 * code is not assigned.  "EU", "AP" and "ZZ"-style pseudo-codes are not
 * countries and return NULL. */
const gchar *fs_geo_country_name (const gchar *cc);
gboolean     fs_geo_country_is_valid (const gchar *cc);
/* Every assigned code, sorted by code.  *n receives the count. */
const gchar * const *fs_geo_country_codes (guint *n);

/* ---- reading ------------------------------------------------------ */

typedef struct _FsGeoDb FsGeoDb;

FsGeoDb *fs_geo_open  (const gchar *path, GError **error);
void     fs_geo_close (FsGeoDb *db);

typedef struct
{
	gint64       built_at;    /* unix seconds                          */
	const gchar *source;      /* free text recorded by the builder      */
	guint        country4;    /* rows in each table                     */
	guint        country6;
	guint        asn4;
	guint        asn6;
	guint        owners;      /* distinct AS numbers with a name        */
} FsGeoInfo;

void fs_geo_info (const FsGeoDb *db, FsGeoInfo *info);

typedef struct
{
	gchar        country[3];  /* "" when unknown                        */
	guint32      asn;         /* 0 when unknown                         */
	const gchar *owner;       /* borrowed from the db; NULL if unknown  */
} FsGeoResult;

/* Look up one address (v4, v6, v4-mapped v6).  FALSE when the text is
 * not an address; TRUE otherwise, with empty fields for what the data
 * does not cover. */
gboolean fs_geo_lookup (const FsGeoDb *db, const gchar *addr,
                        FsGeoResult *result);

/* Owner name for an AS number, or NULL. */
const gchar *fs_geo_owner (const FsGeoDb *db, guint32 asn);

/* All ranges registered to any of the countries (codes upper case) or
 * any of the AS numbers.  Either list may be empty/NULL.  Normalized;
 * caller frees.  Unknown codes simply match nothing. */
FsRangeSet *fs_geo_ranges_for (const FsGeoDb *db,
                               const gchar * const *countries,
                               const guint32 *asns, guint n_asns);

/* ---- building ----------------------------------------------------- */

typedef struct _FsGeoBuilder FsGeoBuilder;

FsGeoBuilder *fs_geo_builder_new  (void);
void          fs_geo_builder_free (FsGeoBuilder *builder);

/* Add one source held in memory (gzip detected and inflated, bounded by
 * FS_GEO_MAX_SOURCE_BYTES).  Rows that do not parse are counted and
 * skipped; a source where nothing parses is an error.  rows_out, when
 * not NULL, receives the accepted row count. */
gboolean fs_geo_builder_add_data (FsGeoBuilder *builder,
                                  const guint8 *data, gsize len,
                                  FsGeoFormat fmt, guint *rows_out,
                                  GError **error);
gboolean fs_geo_builder_add_file (FsGeoBuilder *builder,
                                  const gchar *path, FsGeoFormat fmt,
                                  guint *rows_out, GError **error);

/* Free text stored in the file's header (e.g. "iptoasn.com 2026-11-02"). */
void     fs_geo_builder_set_source (FsGeoBuilder *builder,
                                    const gchar *source);

/* Write the compiled database atomically (temp file + rename, 0644).
 * Overlapping rows from the sources are resolved last-added-wins for
 * the overlap.  Fails when no row was added. */
gboolean fs_geo_builder_write (FsGeoBuilder *builder, const gchar *path,
                               GError **error);

G_END_DECLS

#endif /* FS_GEO_H */
