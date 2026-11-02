/*---[ fs-iprange.h ]----------------------------------------------------
 * Address ranges for the threat-intel engine (1.0.7).
 *
 * Every blocklist, country and exception ends up here as a set of
 * inclusive address intervals, one array per family:
 *
 *   IPv4  guint32 in host byte order
 *   IPv6  a 128-bit value as two guint64 halves (hi, lo)
 *
 * A *normalized* set is sorted by start and has no two intervals that
 * overlap or touch (a.end + 1 == b.start is merged).  nftables interval
 * sets refuse overlapping elements and Windows rules are shorter when
 * merged, so every consumer is handed normalized sets.  Functions that
 * need a normalized argument say so; fs_range_set_normalize() makes one.
 *
 * Parsing is strict (inet_pton) and never resolves names.
 *--------------------------------------------------------------------*/
#ifndef FS_IPRANGE_H
#define FS_IPRANGE_H

#include <glib.h>

G_BEGIN_DECLS

typedef enum
{
	FS_AF_NONE = 0,
	FS_AF_V4   = 4,
	FS_AF_V6   = 6
} FsAddrFamily;

typedef struct
{
	guint64 hi;
	guint64 lo;
} FsU128;

typedef struct
{
	guint32 start;   /* inclusive, host byte order */
	guint32 end;     /* inclusive                  */
} FsRange4;

typedef struct
{
	FsU128 start;    /* inclusive */
	FsU128 end;      /* inclusive */
} FsRange6;

typedef struct
{
	GArray *v4;      /* FsRange4 */
	GArray *v6;      /* FsRange6 */
} FsRangeSet;

/* ---- single values ------------------------------------------------ */

/* Parse one address, CIDR ("a/n") or explicit range ("a-b", start <= end)
 * of either family.  Surrounding whitespace is NOT accepted: callers
 * strip.  An IPv4-mapped IPv6 address (::ffff:a.b.c.d, with a prefix
 * of /96 or longer when one is given) is returned as IPv4.
 *
 *   prefix_len   set to the prefix for CIDR input, to the full width
 *                (32/128) for a single address, and to 0 for "a-b"
 *                input.  May be NULL.
 *   host_bits    set TRUE when a CIDR had bits set below its prefix
 *                (the range is still returned, masked to the network).
 *                May be NULL.
 *
 * Returns the family, or FS_AF_NONE when the text is not one of the
 * accepted forms (out-of-range prefix, garbage, a hostname, ...). */
FsAddrFamily fs_range_parse (const gchar *text,
                             FsRange4 *r4, FsRange6 *r6,
                             guint *prefix_len, gboolean *host_bits);

/* One address (no prefix, no range) to a value.  ::ffff:a.b.c.d is
 * returned as IPv4.  FS_AF_NONE when not an address. */
FsAddrFamily fs_addr_parse (const gchar *text, guint32 *v4, FsU128 *v6);

/* "a.b.c.d" when start == end, "a.b.c.d/n" when the interval is exactly
 * one CIDR block, "a.b.c.d-e.f.g.h" otherwise.  IPv6 is printed in the
 * RFC 5952 canonical form (inet_ntop).  Caller frees. */
gchar *fs_range4_to_string (const FsRange4 *r);
gchar *fs_range6_to_string (const FsRange6 *r);

/* Number of addresses in an interval (v6 saturates at G_MAXUINT64). */
guint64 fs_range4_size (const FsRange4 *r);
guint64 fs_range6_size (const FsRange6 *r);

/* ---- sets --------------------------------------------------------- */

FsRangeSet *fs_range_set_new   (void);
FsRangeSet *fs_range_set_copy  (const FsRangeSet *set);
void        fs_range_set_free  (FsRangeSet *set);
gboolean    fs_range_set_is_empty (const FsRangeSet *set);

/* Append without normalizing (cheap; call normalize once at the end). */
void     fs_range_set_add4     (FsRangeSet *set, guint32 start, guint32 end);
void     fs_range_set_add6     (FsRangeSet *set, FsU128 start, FsU128 end);
/* Parse with fs_range_parse() and append.  FALSE (set unchanged) when
 * the text does not parse. */
gboolean fs_range_set_add_text (FsRangeSet *set, const gchar *text);

/* Sort and merge overlapping or adjacent intervals, in place. */
void fs_range_set_normalize (FsRangeSet *set);

/* into |= other.  Result is normalized. */
void fs_range_set_union    (FsRangeSet *into, const FsRangeSet *other);
/* set -= remove.  Both must be normalized; the result is normalized.
 * An interval that straddles a removed one is split. */
void fs_range_set_subtract (FsRangeSet *set, const FsRangeSet *remove);

/* Membership by binary search.  The set must be normalized. */
gboolean fs_range_set_contains4 (const FsRangeSet *set, guint32 addr);
gboolean fs_range_set_contains6 (const FsRangeSet *set, FsU128 addr);
/* A single address in text form (v4, v6, or v4-mapped v6). */
gboolean fs_range_set_contains_text (const FsRangeSet *set,
                                     const gchar *addr);

/* Interval counts per family, and the number of addresses covered
 * (v6 saturating). */
guint   fs_range_set_count4 (const FsRangeSet *set);
guint   fs_range_set_count6 (const FsRangeSet *set);
guint64 fs_range_set_addresses4 (const FsRangeSet *set);
guint64 fs_range_set_addresses6 (const FsRangeSet *set);

/* ---- the stored text form ---------------------------------------- *
 * One interval per line, printed with fs_range{4,6}_to_string(), v4
 * first, then v6, each family sorted.  This is what <id>.list holds.
 * from_text() is strict: blank lines and '#' comments are allowed, any
 * other line that does not parse is an error (our own files are never
 * "mostly right").  The result is normalized. */
gchar      *fs_range_set_to_text   (const FsRangeSet *set);
FsRangeSet *fs_range_set_from_text (const gchar *text, GError **error);

/* ---- ranges that must never be blocked --------------------------- *
 * Loopback, unspecified, RFC 1918, CGNAT, link-local, multicast,
 * reserved/broadcast, special-purpose (192.0.0.0/24, 192.88.99.0/24,
 * 198.18.0.0/15), ULA, IPv4-mapped, NAT64.  Normalized; owned by the
 * module, never free it.  See docs/1.0.7-threat-intel-design.md, s3. */
const FsRangeSet *fs_range_protected (void);

/* Nameserver addresses from resolv.conf text ("nameserver <addr>"
 * lines; zone suffixes like %eth0 dropped; anything else ignored), as
 * single-address intervals.  Pure: the caller reads the file. */
FsRangeSet *fs_range_set_from_resolv_conf (const gchar *text);

G_END_DECLS

#endif /* FS_IPRANGE_H */
