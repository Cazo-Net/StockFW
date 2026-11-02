/*---[ fs-nftset.h ]-----------------------------------------------------
 * A blocklist file into an nftables set (1.0.7, Linux).
 *
 * Three steps, each usable on its own:
 *
 *   1. fs_blocklist_parse_csv()  text -> FsRangeSet.  Pure.  Takes the
 *      first field of each line, so a plain list, a CSV with a header
 *      and comments after the address ("1.2.3.0/24 ; SBL123") all read.
 *   2. fs_nftset_script()        FsRangeSet -> an nft script.  Pure.
 *   3. fs_nft_run_script()       the script -> `nft -f -` on stdin, via
 *      GSubprocess.  No shell, no system(): the addresses never pass
 *      through anything that could interpret them.
 *
 * fs_nftset_load_csv() is the three together, with the guards a feed
 * from the internet needs: an empty, mostly unparseable or absurdly
 * wide list is refused and the set keeps what it had; ranges that must
 * never be blocked (loopback, the LAN, link-local, multicast) are
 * subtracted first.
 *
 * nftables sets hold one address family each, so a set named "blocklist"
 * is two sets: `blocklist' (ipv4_addr) and `blocklist6' (ipv6_addr).
 *--------------------------------------------------------------------*/
#ifndef FS_NFTSET_H
#define FS_NFTSET_H

#include <glib.h>
#include "core/fs-iprange.h"

G_BEGIN_DECLS

/* The table StockFW's threat-intel sets live in (design doc, s6). */
#define FS_NFT_INTEL_TABLE "stockfw_intel"

/* Per-file limits.  A blocklist file over this size is refused before
 * it is read. */
#define FS_BLOCKLIST_MAX_BYTES   (64u * 1024u * 1024u)

/* Coverage caps: no single IPv4 interval wider than a /8, no IPv6
 * interval wider than a /16, and no more than 2^29 IPv4 addresses in
 * all (an eighth of the address space).  Real feeds stay far below
 * these; a poisoned or garbled one ("0.0.0.0/1") does not. */
#define FS_BLOCKLIST_MAX_V4_SPAN   (G_GUINT64_CONSTANT (1) << 24)
#define FS_BLOCKLIST_MAX_V4_TOTAL  (G_GUINT64_CONSTANT (1) << 29)
#define FS_BLOCKLIST_MAX_V6_PREFIX 16

typedef struct
{
	guint lines;            /* lines in the file                        */
	guint entries;          /* data lines that gave an address or range */
	guint skipped;          /* data lines that did not parse            */
	guint first_bad_line;   /* 1-based; 0 when none                     */
	gboolean header;        /* the first data line was a header         */
	guint protected_hits;   /* entries that overlapped protected ranges */
} FsBlocklistStats;

/* Text -> ranges, normalized.  Never fails: what does not parse is
 * counted in stats (which may be NULL).  Rules:
 *   - blank lines and lines starting with '#' or ';' are comments;
 *   - the first field is the address: everything up to the first ',',
 *     ';', tab or space; surrounding double quotes are dropped;
 *   - a first data line that does not parse and contains a letter is a
 *     CSV header and is skipped, not counted as bad. */
FsRangeSet *fs_blocklist_parse_csv (const gchar *text, gsize len,
                                    FsBlocklistStats *stats);

/* TRUE when `name' can be an nft table or set name: an ASCII letter,
 * then letters, digits or '_', 31 characters at most.  Names go into
 * the script verbatim, so nothing else is accepted. */
gboolean fs_nft_name_is_valid (const gchar *name);

/* The script that leaves `table' (family inet) holding sets `set' and
 * `set'6 with exactly `ranges' (which must be normalized), created if
 * missing.  One transaction: flush, then add, so `nft -f' applies all of
 * it or none of it.  Elements go 1000 to a statement.  NULL when a name
 * is not valid.  Caller frees. */
gchar *fs_nftset_script (const gchar *table, const gchar *set,
                         const FsRangeSet *ranges);

/* Runs `nft -f -' (or `nft -c -f -' with check_only) with `script' on
 * stdin.  On failure the error carries nft's first error line.  `nft'
 * is found on PATH, as the backend finds iptables-restore. */
gboolean fs_nft_run_script (const gchar *script, gboolean check_only,
                            GError **error);

/* Read `path', guard it, subtract protected ranges, and replace the
 * contents of `set'/`set'6 in table `table' in one transaction.  On any
 * failure the sets keep their previous contents and *error says why.
 * stats may be NULL. */
gboolean fs_nftset_load_csv (const gchar *path, const gchar *table,
                             const gchar *set, FsBlocklistStats *stats,
                             GError **error);

G_END_DECLS

#endif /* FS_NFTSET_H */
