/*---[ fs-intelset.h ]---------------------------------------------------
 * The threat-intel rule set (1.0.7) and its two renderings.
 *
 * A rule set is what the kernel should block, already decided: one set
 * per enabled feed and one for the location (country/ASN) selection,
 * each with a direction and a normalized FsRangeSet from which the
 * protected ranges, the DNS resolvers and the user's exceptions have
 * been subtracted.  fs-intel.c builds it; the backends enforce it.
 *
 * The renderings are pure functions so the core suite can check every
 * byte the kernel or netsh would receive, on any platform:
 *
 *   fs_intelset_nft_script()   one nftables transaction (Linux)
 *   fs_intelset_netsh_rules()  netsh add-rule argument lists (Windows)
 *--------------------------------------------------------------------*/
#ifndef FS_INTELSET_H
#define FS_INTELSET_H

#include <glib.h>
#include "core/fs-iprange.h"
#include "core/fs-backend.h"   /* the FsIntelRuleset typedef */

G_BEGIN_DECLS

typedef enum
{
	FS_INTEL_DIR_IN   = 1,     /* match the remote as source, inbound   */
	FS_INTEL_DIR_OUT  = 2,     /* match the remote as destination, out  */
	FS_INTEL_DIR_BOTH = 3
} FsIntelDir;

/* "in" / "out" / "both" <-> enum. */
const gchar *fs_intel_dir_to_string   (FsIntelDir dir);
gboolean     fs_intel_dir_from_string (const gchar *text, FsIntelDir *dir);

typedef struct
{
	gchar      *id;       /* "feed-<feed id>" or "geo"; [a-z0-9-] only,
	                       * <= 40 chars: it is printed into nft set
	                       * names and log prefixes                     */
	gchar      *label;    /* human name: "Spamhaus DROP", "Location"    */
	FsIntelDir  dir;
	FsRangeSet *ranges;   /* normalized; owned                          */
} FsIntelSet;

struct _FsIntelRuleset
{
	GPtrArray *sets;      /* FsIntelSet*, owned, in display order       */
};

FsIntelRuleset *fs_intel_ruleset_new  (void);
void            fs_intel_ruleset_free (FsIntelRuleset *ruleset);
/* Takes ownership of `ranges'.  The id must satisfy the rule above;
 * FALSE (and ranges freed) when it does not. */
gboolean        fs_intel_ruleset_add  (FsIntelRuleset *ruleset,
                                       const gchar *id,
                                       const gchar *label,
                                       FsIntelDir dir,
                                       FsRangeSet *ranges);
const FsIntelSet *fs_intel_ruleset_find (const FsIntelRuleset *ruleset,
                                         const gchar *id);
/* Totals over every set (intervals, not addresses). */
guint fs_intel_ruleset_count4 (const FsIntelRuleset *ruleset);
guint fs_intel_ruleset_count6 (const FsIntelRuleset *ruleset);

/* ---- Linux: nftables ---------------------------------------------- */

#define FS_INTEL_NFT_TABLE  "stockfw_intel"   /* family inet          */
#define FS_INTEL_LOG_MARKER "STOCKFW-TI"      /* kernel log prefix     */

/* The whole transaction for `nft -f -': create-if-missing, delete, and
 * re-create the table with every set and rule, so it applies whole or
 * not at all.  An empty rule set yields a script that leaves no table
 * behind.  Caller frees. */
gchar *fs_intelset_nft_script (const FsIntelRuleset *ruleset);

/* The script that removes the table (and only it). */
gchar *fs_intelset_nft_clear_script (void);

/* Packet counters per set id from `nft list table inet stockfw_intel'
 * text output (the rules carry comment "<set id>").  gchar* ->
 * guint64*, both owned by the table; never NULL. */
GHashTable *fs_intelset_nft_parse_counters (const gchar *listing);

/* ---- Windows: netsh ----------------------------------------------- */

/* Limits per generated rule. */
#define FS_INTEL_NETSH_MAX_RANGES 1000u
#define FS_INTEL_NETSH_MAX_CHARS  8000u   /* length of remoteip=...     */

/* The rules to create: a GPtrArray of GStrv (each a full argv starting
 * "netsh", "advfirewall", "firewall", "add", "rule", ...), and in
 * *names the rule names in the same order (GPtrArray of gchar*), so the
 * backend can record them and delete exactly those later.  Names are
 * "StockFW-TI <set id> <in|out> <n>".  Caller frees both arrays
 * (they have free functions set). */
GPtrArray *fs_intelset_netsh_rules (const FsIntelRuleset *ruleset,
                                    GPtrArray **names);

/* The argv that deletes one rule by exact name. */
gchar **fs_intelset_netsh_delete_argv (const gchar *name);

G_END_DECLS

#endif /* FS_INTELSET_H */
