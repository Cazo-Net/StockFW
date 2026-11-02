/*---[ fs-intelset.h ]---------------------------------------------------
 * The threat-intel rule set (1.0.7) and its nftables rendering.
 *
 * A rule set is what the kernel should block, already decided: one set
 * per enabled feed or local list, each with an id, a direction and a
 * normalized FsRangeSet from which everything that must stay reachable
 * has been subtracted.  fs-intel.c builds it; the backend enforces it.
 *
 * Everything here is pure, so the core suite can check every byte nft
 * would receive.  The design is docs/1.0.7-threat-intel-design.md,
 * section 7; the bracketed tags ([N0] ...) name the review findings a
 * rule answers.
 *--------------------------------------------------------------------*/
#ifndef FS_INTELSET_H
#define FS_INTELSET_H

#include <glib.h>
#include "core/fs-iprange.h"
#include "core/fs-backend.h"   /* the FsIntelRuleset typedef */

G_BEGIN_DECLS

/* Direction of a set [N0, S6, P1]:
 *   IN    connections the listed address starts are stopped; this
 *         computer can still connect to it (replies come back);
 *   OUT   connections this computer (or a routed LAN host) starts to
 *         the listed address are stopped; it can still connect in;
 *   BOTH  every packet from or to the listed address. */
typedef enum
{
	FS_INTEL_DIR_IN   = 1,
	FS_INTEL_DIR_OUT  = 2,
	FS_INTEL_DIR_BOTH = 3
} FsIntelDir;

/* "in" / "out" / "both" <-> enum.  from_string is exact (lower case). */
const gchar *fs_intel_dir_to_string   (FsIntelDir dir);
gboolean     fs_intel_dir_from_string (const gchar *text, FsIntelDir *dir);

/* ^[a-z0-9][a-z0-9-]{0,39}$.  Ids are printed into nft set names, rule
 * comments and log prefixes, so nothing else is ever accepted -- an id
 * is refused, never cleaned up [N7]. */
gboolean fs_intel_id_is_valid (const gchar *id);

typedef struct
{
	gchar      *id;       /* fs_intel_id_is_valid()                    */
	gchar      *label;    /* human name: "Spamhaus DROP"; display only  */
	FsIntelDir  dir;
	FsRangeSet *ranges;   /* normalized; owned                          */
} FsIntelSet;

struct _FsIntelRuleset
{
	GPtrArray *sets;      /* FsIntelSet*, owned, in display order       */
};

FsIntelRuleset *fs_intel_ruleset_new  (void);
void            fs_intel_ruleset_free (FsIntelRuleset *ruleset);

/* Takes ownership of `ranges' (normalized by the caller), also on
 * failure, when it is freed.  FALSE when the id is invalid, already in
 * the rule set, or dir is not one of the three values. */
gboolean fs_intel_ruleset_add (FsIntelRuleset *ruleset, const gchar *id,
                               const gchar *label, FsIntelDir dir,
                               FsRangeSet *ranges);

const FsIntelSet *fs_intel_ruleset_find (const FsIntelRuleset *ruleset,
                                         const gchar *id);

/* Totals over every set: intervals per family. */
guint fs_intel_ruleset_count4 (const FsIntelRuleset *ruleset);
guint fs_intel_ruleset_count6 (const FsIntelRuleset *ruleset);

/* The rule set's fingerprint: the first 32 lower-case hex digits of the
 * SHA-256 of its canonical form -- for each set in order, the line
 * "<id>\t<dir>\n" followed by fs_range_set_to_text() of its ranges.
 * Labels are not part of it (they never reach the kernel).  The empty
 * rule set has a digest too.  Caller frees. */
gchar *fs_intel_ruleset_digest (const FsIntelRuleset *ruleset);

/* ---- Linux: nftables ---------------------------------------------- */

#define FS_INTEL_NFT_TABLE   "stockfw_intel"   /* family inet          */
#define FS_INTEL_LOG_MARKER  "STOCKFW-TI"      /* kernel log prefix     */
#define FS_INTEL_DIGEST_TAG  "sfw:"            /* table comment prefix  */
#define FS_INTEL_NFT_CHUNK   1000u             /* elements a statement  */

/* "s_<id with every '-' as '_'>_4" (family 4) or "..._6".  Caller
 * frees.  NULL when the id is not valid. */
gchar *fs_intelset_nft_set_name (const gchar *id, FsAddrFamily family);

/* The whole transaction for `nft -f -':
 *
 *   table inet stockfw_intel {}          (create if missing, so the
 *   delete table inet stockfw_intel       delete cannot fail)
 *   table inet stockfw_intel {
 *   	comment "sfw:<digest>"
 *   	set <name> { type ipv4_addr; flags interval; }   one per family
 *   	...                                              that has ranges
 *   	chain input   { type filter hook input priority filter - 10;
 *   	                policy accept;  comment "sfw:<digest>"
 *   	                iif "lo" accept  <rules> }
 *   	chain output  { ... oif "lo" accept <rules> }
 *   	chain forward { ... <rules> }
 *   }
 *   add element inet stockfw_intel <name> { a, b, ... }  <= 1000 each
 *
 * Every statement and rule ends with a newline [N7]; the three chains
 * are always present, so readers see one shape.  Per set and family
 * (F = ip or ip6, @S the set), the rules of design section 7:
 *
 *   IN    input, forward:  F saddr @S ct direction original  -> drop
 *   OUT   output, forward: F daddr @S ct direction original  -> reject
 *   BOTH  input, forward:  F saddr @S -> drop;
 *         output, forward: F daddr @S -> reject
 *
 * where each blocking rule is a pair:
 *   <match> limit rate 10/second burst 20 packets
 *           log prefix "STOCKFW-TI <id> " level info
 *   <match> counter drop comment "<id>"
 *   (or: counter reject with icmpx type admin-prohibited comment "<id>")
 *
 * A family with no ranges in a set has neither set nor rules.  The
 * empty rule set yields just the first two lines: the table is removed.
 * NULL only when a set is one fs_intel_ruleset_add() would have
 * refused -- an invalid id or direction, or an id used twice -- which
 * only a struct filled in by hand can hold.  Caller frees. */
gchar *fs_intelset_nft_script (const FsIntelRuleset *ruleset);

/* The script that removes the table, and only it; harmless when it is
 * not there.  Caller frees. */
gchar *fs_intelset_nft_clear_script (void);

/* Packet counters of one rule set id. */
typedef struct
{
	guint64 packets;
	guint64 bytes;
} FsIntelCounter;

/* Counters per set id from the text of `nft list chain inet
 * stockfw_intel <chain>' (one or more chains concatenated): every line
 * with "counter packets P bytes B" and comment "<id>" adds to that id.
 * Lines without both are ignored; a comment that is not a valid id is
 * ignored.  Returns gchar* -> FsIntelCounter*, both owned by the table;
 * never NULL. */
GHashTable *fs_intelset_nft_parse_counters (const gchar *listing);

/* From the output of `nft -j list tables': whether table inet
 * stockfw_intel is there, and the digest in its comment ("sfw:" taken
 * off; NULL when it has no such comment).  Strict and small: it looks
 * only for the object with "family": "inet" and "name":
 * "stockfw_intel".  FALSE when the table is absent -- and also when the
 * text is not a whole listing, which fs_intelset_nft_parse_live_state()
 * tells apart; *digest is set to NULL first.  digest may be NULL. */
gboolean fs_intelset_nft_parse_live (const gchar *json, gchar **digest);

/* The same with the three answers kept apart [S10]: PRESENT (with
 * *digest as above), ABSENT (a whole listing without the table), or
 * UNKNOWN when `json' is not a whole `nft -j list tables' document (no
 * top-level "nftables" list, broken or trailing text): a listing that
 * cannot be read says nothing about the kernel, so it must not read
 * as a missing table. */
FsIntelLive fs_intelset_nft_parse_live_state (const gchar *json,
                                              gchar **digest);

/* The same answer from `nft -j list chains', which nft 1.0.9 prints
 * without fetching a single set element (`list tables' fetches them
 * all: seconds for a large country, design 12.7).  PRESENT when some
 * chain of table inet stockfw_intel is listed, with *digest from the
 * comment of its chain "input" (NULL when that chain or its comment is
 * missing); ABSENT when a whole listing holds no chain of it -- which a
 * table without chains also gives, so a caller that must tell those
 * apart asks `list tables' then; UNKNOWN as above. */
FsIntelLive fs_intelset_nft_parse_chains_live (const gchar *json,
                                               gchar **digest);

G_END_DECLS

#endif /* FS_INTELSET_H */
