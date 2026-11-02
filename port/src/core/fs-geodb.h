/*---[ fs-geodb.h ]------------------------------------------------------
 * A hardened reader for the IPFire location database (1.0.7 threat
 * intel, round 2).  Design: docs/1.0.7-threat-intel-design.md, section
 * 11.
 *
 * The database is a file in libloc's format version 1, published daily
 * by the IPFire project at FS_GEODB_URL as an xz-compressed file.  This
 * module is our own reader, written from the published layout facts
 * (offsets, sizes, byte order); it shares no code with libloc.
 *
 * Trust model, in the order the checks run:
 *
 *   1. unpack  the .xz download is decoded as a stream, with a memory
 *              limit, into a temporary file next to the store; more
 *              than FS_GEODB_MAX_DB_BYTES of output is refused.
 *   2. verify  the file carries two signature slots.  Before any other
 *              field is read, at least one slot must hold an ECDSA
 *              P-521 / SHA-256 signature, made with IPFire's key (pinned
 *              in fs-geodb.c), over the magic, the header with both
 *              signatures and both signature lengths zeroed, and every
 *              byte after the header.  There is no "unsigned" path.
 *   3. check   every offset and length of the header is checked, with
 *              checked arithmetic, against the file size; sections lie
 *              inside the file, after the header, and never overlap;
 *              the network trie is walked once at open and must be a
 *              tree (no node reached twice) of depth 128 at most, every
 *              node and network index in range; every string in range
 *              and terminated inside the pool; the AS and country tables
 *              strictly sorted.  A file that fails any check is refused
 *              whole.  Accessors range-check again on every access.
 *   4. judge   a new copy replaces the one in use only when it was
 *              created later, and not further ahead of the clock than
 *              FS_GEODB_FUTURE_SKEW_S (the format has no expiry, so
 *              this is the anti-rollback rule).  Every failure keeps the
 *              last good copy.
 *
 * Location means *registration*: the country of a network is where its
 * address space is registered, never a measured position.  Words shown
 * to users say "registered in".
 *
 * An open FsGeodb is read-only (an mmap of the verified file) and may be
 * used from several threads at once.
 *--------------------------------------------------------------------*/
#ifndef FS_GEODB_H
#define FS_GEODB_H

#include <glib.h>
#include <gio/gio.h>
#include "core/fs-iprange.h"

G_BEGIN_DECLS

/* Where IPFire publishes the database (format version 1). */
#define FS_GEODB_URL   "https://location.ipfire.org/databases/1/location.db.xz"
/* The file name of the copy in use, inside the threat-intel store. */
#define FS_GEODB_FILE  "location.db"

/* The largest compressed download accepted (the real one is ~6 MB). */
#define FS_GEODB_MAX_XZ_BYTES   (64u * 1024u * 1024u)
/* The largest database accepted, unpacked or opened (~50 MB today). */
#define FS_GEODB_MAX_DB_BYTES   (256u * 1024u * 1024u)
/* The xz decoder's memory limit: every xz preset (-9 needs 65 MiB)
 * decodes within it; a stream asking for more is refused. */
#define FS_GEODB_XZ_MEMLIMIT    (96u * 1024u * 1024u)
/* How far ahead of our clock a new copy's creation time may be. */
#define FS_GEODB_FUTURE_SKEW_S  (24 * 3600)
/* A copy older than this is stale (IPFire publishes daily). */
#define FS_GEODB_STALE_S        (30 * 24 * 3600)
/* The trie never goes deeper than one bit per IPv6 address bit. */
#define FS_GEODB_MAX_DEPTH      128u
/* Strings (vendor, description, licence, AS and country names) longer
 * than this make the file malformed. */
#define FS_GEODB_MAX_STRING     4096u
/* The download's whole-transfer time limit. */
#define FS_GEODB_FETCH_TIMEOUT_S 300u

GQuark fs_geodb_error_quark (void);
#define FS_GEODB_ERROR (fs_geodb_error_quark ())

enum
{
	FS_GEODB_ERR_IO = 1,        /* a file could not be read or written     */
	FS_GEODB_ERR_TOO_LARGE,     /* over a size cap                         */
	FS_GEODB_ERR_XZ,            /* not a valid xz stream, or over the
	                             * decoder's memory limit                  */
	FS_GEODB_ERR_SIGNATURE,     /* no slot verifies with the pinned key    */
	FS_GEODB_ERR_FORMAT,        /* not a location database, or malformed   */
	FS_GEODB_ERR_ROLLBACK,      /* not newer than the copy in use          */
	FS_GEODB_ERR_FUTURE,        /* created too far ahead of our clock      */
	FS_GEODB_ERR_INVALID,       /* a bad argument (address, filter, path)  */
	FS_GEODB_ERR_UNSUPPORTED    /* not available on this platform          */
};

/* Network flags, as the format defines them. */
enum
{
	FS_GEODB_FLAG_ANONYMOUS_PROXY    = 1 << 0,
	FS_GEODB_FLAG_SATELLITE_PROVIDER = 1 << 1,
	FS_GEODB_FLAG_ANYCAST            = 1 << 2,
	FS_GEODB_FLAG_DROP               = 1 << 3   /* "hostile, safe to drop" */
};
#define FS_GEODB_FLAGS_KNOWN 0x0fu

typedef struct _FsGeodb FsGeodb;

/* ---- open and close ------------------------------------------------- */

/* Open a database file: a regular file (never a symbolic link) of at
 * most FS_GEODB_MAX_DB_BYTES, mapped read-only, verified against the
 * pinned key, then checked whole.  NULL with FS_GEODB_ERROR set:
 * FORMAT (not a location database, unknown version, or malformed),
 * SIGNATURE, TOO_LARGE or IO. */
FsGeodb *fs_geodb_open  (const gchar *path, GError **error);
void     fs_geodb_close (FsGeodb *db);

typedef struct
{
	gint64       created_at;    /* unix seconds, from the signed header    */
	const gchar *vendor;        /* printable UTF-8; owned by the db        */
	const gchar *description;
	const gchar *license;
	guint        signed_slot;   /* 1 or 2: the slot that verified          */
	guint64      size;          /* bytes                                   */
	guint        networks;      /* records in each table                   */
	guint        nodes;
	guint        ases;
	guint        countries;
} FsGeodbInfo;

/* The database's metadata.  Owned by the db. */
const FsGeodbInfo *fs_geodb_info (const FsGeodb *db);

/* ---- lookup --------------------------------------------------------- */

typedef struct
{
	gboolean     found;         /* FALSE: no network holds the address     */
	gchar        country[3];    /* "DE"; "" when the network has none      */
	guint32      asn;           /* 0 when none                             */
	gchar       *as_name;       /* NULL when the AS is not in the database */
	guint        flags;         /* FS_GEODB_FLAG_*                         */
	FsAddrFamily family;        /* of the matched network                  */
	guint        prefix_len;    /* 0-32 or 0-128                           */
	gchar       *network;       /* "10.1.0.0/16", "2001:db8::/32"          */
} FsGeodbMatch;

/* The most specific network holding one address.  IPv4 addresses (and
 * IPv4-mapped IPv6 ones, ::ffff:a.b.c.d) are looked up among the IPv4
 * networks only; IPv6 networks never answer for IPv4 addresses.
 * Returns FALSE with FS_GEODB_ERR_INVALID only when `address' is not an
 * IPv4 or IPv6 address (no names, prefixes or zone ids); "nothing
 * found" is TRUE with match->found FALSE.  Clear the match with
 * fs_geodb_match_clear(). */
gboolean fs_geodb_lookup      (const FsGeodb *db, const gchar *address,
                               FsGeodbMatch *match, GError **error);
gboolean fs_geodb_lookup_inet (const FsGeodb *db, GInetAddress *address,
                               FsGeodbMatch *match, GError **error);
void     fs_geodb_match_clear (FsGeodbMatch *match);

/* ---- enumerate (for nftables interval sets) ------------------------- */

typedef struct
{
	const gchar *const *countries;  /* NULL-terminated codes, or NULL     */
	const guint32      *asns;       /* n_asns numbers, or NULL            */
	gsize               n_asns;
	guint               flags;      /* any of these FS_GEODB_FLAG_*; 0 none */
} FsGeodbFilter;

/* Every address whose most specific network (as fs_geodb_lookup answers
 * it) has a country in the filter, an AS in the filter, or one of the
 * filter's flags.  The result is normalized (sorted, merged, adjacent
 * intervals joined), so the same database and filter always give the
 * same set.  Country codes are two letters (either case).  NULL with
 * FS_GEODB_ERR_INVALID for a bad code; an empty filter gives an empty
 * set. */
FsRangeSet *fs_geodb_enumerate (const FsGeodb *db,
                                const FsGeodbFilter *filter,
                                GError **error);

/* A normalized set as the fewest CIDR prefixes that cover exactly it:
 * IPv4 first, then IPv6, each ascending.  Strings; caller frees with
 * g_ptr_array_unref. */
GPtrArray *fs_geodb_set_prefixes (const FsRangeSet *set);

/* ---- countries and ASes (the picker) -------------------------------- */

typedef struct
{
	gchar  code[3];          /* "DE"                                      */
	gchar  continent[3];     /* "EU"; "" when the database has none       */
	gchar *name;             /* "Germany"                                 */
} FsGeodbCountry;

typedef struct
{
	guint32 asn;
	gchar  *name;
} FsGeodbAs;

/* Every country, ascending by code.  FsGeodbCountry*, caller unrefs. */
GPtrArray *fs_geodb_countries (const FsGeodb *db);
/* One country by code (either case); NULL when there is none.  Free
 * with fs_geodb_country_free. */
FsGeodbCountry *fs_geodb_country (const FsGeodb *db, const gchar *code);
void            fs_geodb_country_free (FsGeodbCountry *country);

/* The name of one AS; NULL when it is not in the database. */
gchar     *fs_geodb_as_name   (const FsGeodb *db, guint32 asn);
/* ASes whose name contains `query' (ASCII case-insensitive), or whose
 * number is `query' ("13335" or "AS13335"), ascending by number, at most
 * `max' (0: no limit).  FsGeodbAs*, caller unrefs. */
GPtrArray *fs_geodb_search_as (const FsGeodb *db, const gchar *query,
                               guint max);
void       fs_geodb_as_free   (FsGeodbAs *as);

/* ---- freshness and anti-rollback ------------------------------------ */

typedef enum
{
	FS_GEODB_NEWER = 0,     /* may replace the copy in use              */
	FS_GEODB_SAME,          /* created at the same second: not newer    */
	FS_GEODB_OLDER,         /* a rollback                               */
	FS_GEODB_FROM_FUTURE    /* created too far ahead of our clock       */
} FsGeodbVerdict;

/* Judge a new copy created at `offered' against the copy in use
 * (created at `current', 0 when there is none; or the newest copy ever
 * accepted, see fs_geodb_install_xz) at time `now' (unix seconds).  The future check comes first.  *reason (nullable) gets one
 * sentence for anything but FS_GEODB_NEWER, else NULL. */
FsGeodbVerdict fs_geodb_judge (gint64 offered, gint64 current, gint64 now,
                               gchar **reason);
/* Older than FS_GEODB_STALE_S at `now'. */
gboolean       fs_geodb_is_stale (gint64 created_at, gint64 now);

/* ---- unpack, install, update ---------------------------------------- */

/* Decode the xz stream `xz' into `out_fd' (written from its current
 * position), at most `max_out' bytes (0: FS_GEODB_MAX_DB_BYTES), with
 * the decoder limited to FS_GEODB_XZ_MEMLIMIT.  One stream, nothing
 * after it.  *written (nullable) gets the bytes written, also on
 * failure.  FS_GEODB_ERR_TOO_LARGE as soon as the output would pass
 * max_out; FS_GEODB_ERR_XZ for a bad stream; FS_GEODB_ERR_IO. */
gboolean fs_geodb_unpack_xz (GBytes *xz, int out_fd, guint64 max_out,
                             guint64 *written, GError **error);

typedef enum
{
	FS_GEODB_UPDATED = 0,   /* a new copy is in use                     */
	FS_GEODB_UNCHANGED,     /* the download is the copy we have         */
	FS_GEODB_REFUSED,       /* too large, bad xz, bad signature,
	                         * malformed, a rollback or from the future */
	FS_GEODB_FAILED         /* the download or the store failed         */
} FsGeodbOutcome;

/* Install a downloaded .xz into `store_dir' (an existing directory,
 * normally fs_intel_dir()): unpack it to a fresh temporary file there
 * (O_EXCL, 0600, no symlinks), open and verify that, judge it against
 * the floor, and only then rename it over FS_GEODB_FILE.  On any
 * failure the temporary file is removed and the copy in use is left
 * exactly as it was.  Installs into one store are serialised (flock on
 * the store), and each one first removes the temporary files of an
 * install that was killed.  The error (set for REFUSED and FAILED)
 * says why.
 *
 * The floor (review GEO-ROLLBACK-1) is the larger of the copy in use
 * (when it verifies) and `min_created', the creation time of the newest
 * copy the caller ever accepted (0: none), so that a copy in use that
 * is damaged or gone does not let an older signed copy back in.  A
 * copy older than the floor is a rollback; one created at the floor is
 * UNCHANGED when it is the good copy in use, and otherwise repairs it
 * (UPDATED).
 *
 * *created_at (nullable) gets the creation time of the copy in use
 * afterwards (0 when there is none).  Linux only for now; elsewhere
 * FAILED with FS_GEODB_ERR_UNSUPPORTED. */
FsGeodbOutcome fs_geodb_install_xz (const gchar *store_dir, GBytes *xz,
                                    gint64 now, gint64 min_created,
                                    gint64 *created_at, GError **error);

/* Open the copy in use in `store_dir' (no symbolic link). */
FsGeodb *fs_geodb_open_store (const gchar *store_dir, GError **error);

/* The downloader.  The default calls fs_fetch() with FS_GEODB_URL, the
 * proxy, FS_GEODB_MAX_XZ_BYTES and FS_GEODB_FETCH_TIMEOUT_S; fs_fetch
 * names StockFW in the User-Agent.  Tests replace it; NULL restores the
 * default.  Process-wide. */
typedef GBytes *(*FsGeodbFetcher) (const gchar *url, const gchar *proxy,
                                   gpointer user_data, GError **error);
void fs_geodb_set_fetcher (FsGeodbFetcher fetcher, gpointer user_data);

/* Download FS_GEODB_URL and install it (fs_geodb_install_xz, with the
 * same `min_created').  This is a network request: callers make it
 * only when the user turned country or network-owner blocking on. */
FsGeodbOutcome fs_geodb_update (const gchar *store_dir, const gchar *proxy,
                                gint64 now, gint64 min_created,
                                gint64 *created_at, GError **error);

/* ---- the pieces, for the tests -------------------------------------- */

/* The pinned public key, PEM.  Static string. */
const gchar *fs_geodb_pinned_key_pem (void);

#ifdef FS_GEODB_TESTING
/* Test builds only: verify with this PEM public key instead of the
 * pinned one (NULL restores the pinned key).  Process-wide.  Release
 * builds have no such function. */
void     fs_geodb_testing_set_key (const gchar *pem);
/* Test builds only: the checks of step 3 on a buffer, without the
 * signature step (for the fuzzer and the mutation loop).  The buffer
 * must outlive the db. */
FsGeodb *fs_geodb_testing_open_unverified (const guint8 *data, gsize size,
                                           GError **error);
#endif

G_END_DECLS

#endif /* FS_GEODB_H */
