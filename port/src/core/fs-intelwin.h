/*---[ fs-intelwin.h ]---------------------------------------------------
 * The threat-intel rule set on Windows (1.0.7, Round 3): how a rule set
 * becomes Windows Firewall rules, and how the rules read back become
 * an answer again.
 *
 * Everything here is pure, so the core suite checks every name and
 * every address string the Windows backend would hand to the firewall,
 * and every verdict it would draw from what it reads back, on any
 * platform.  The COM calls themselves live in
 * platform/windows/fs-backend-windows.c.  Design:
 * docs/design/1.0.7-threat-intel-design.md, section 11.
 *
 * The shape on the firewall, per apply ("generation", gNNNNNNNN):
 *
 *   every rule is in the rule group "StockFW Threat Intel", blocks,
 *   applies to every profile, protocol and interface, and names its
 *   addresses in RemoteAddresses, never more than FS_INTELWIN_MAX_TOKENS
 *   of them nor FS_INTELWIN_MAX_CHARS characters;
 *
 *   "SFW-TI <id> <in|out> IPv<4|6> <i>/<n> <gen>"  one per chunk: the
 *        list, the rule's direction (a "both" list has an inbound and
 *        an outbound copy), the family, which chunk of how many;
 *
 *   "SFW-TI manifest <gen>"  one, disabled (it blocks nothing; its
 *        RemoteAddresses is the documentation address 192.0.2.1, so
 *        enabling it by hand still blocks nothing that exists), whose
 *        description records the rule set's digest, the plan hash
 *        over every rule above, and how many there are.
 *
 * The plan hash lets a read-back prove it found exactly the rules an
 * apply wrote -- none missing, none added, none edited -- and only
 * then report the digest the engine compares with what it applied.
 * The manifest makes a rule set whose lists are all empty (everything
 * subtracted) still visible, as the nft table with no sets is on Linux.
 *--------------------------------------------------------------------*/
#ifndef FS_INTELWIN_H
#define FS_INTELWIN_H

#include <glib.h>
#include "core/fs-backend.h"
#include "core/fs-intelset.h"
#include "core/fs-iprange.h"

G_BEGIN_DECLS

/* The rule group every threat-intel rule is in, and nothing else of
 * StockFW's: the policy's rules are named "StockFW-..." and live
 * outside it, so applying or clearing the policy never touches a list,
 * and removing the lists never touches the policy. */
#define FS_INTELWIN_GROUP        "StockFW Threat Intel"
/* Every name starts so; never "StockFW-", which the policy's clear
 * removes (design 10, [P0]). */
#define FS_INTELWIN_PREFIX       "SFW-TI "
#define FS_INTELWIN_MANIFEST     "manifest"
/* The manifest's RemoteAddresses: TEST-NET-1, documentation only. */
#define FS_INTELWIN_MANIFEST_REMOTE "192.0.2.1"

/* Chunk limits per rule (design 11.2).  Microsoft documents no limit
 * on RemoteAddresses.  Windows 7 is reported to take at most 1000
 * addresses a rule, later versions 10,000, and blocklist tools that
 * write Windows Firewall rules split at 1000 or 10,000; 1000 is the
 * value every supported Windows takes.  The character cap keeps each
 * string under 32,767 UTF-16 units, the longest a UNICODE_STRING can
 * hold, in case any layer between the API and the filter engine stores
 * it as one: 1000 IPv6 ranges can reach 79,000 characters. */
#define FS_INTELWIN_MAX_TOKENS   1000u
#define FS_INTELWIN_MAX_CHARS    32000u

/* NET_FW_RULE_DIRECTION values. */
typedef enum
{
	FS_INTELWIN_IN  = 1,
	FS_INTELWIN_OUT = 2
} FsIntelWinDir;

/* One rule to create. */
typedef struct
{
	gchar        *name;
	gchar        *description;
	FsIntelWinDir dir;
	FsAddrFamily  family;   /* FS_AF_NONE for the manifest              */
	gboolean      enabled;  /* FALSE only for the manifest              */
	gchar        *remote;   /* RemoteAddresses, comma-separated         */
	guint         tokens;   /* addresses, CIDRs or ranges in `remote'   */
} FsIntelWinRule;

typedef struct
{
	gchar     *gen;         /* "g" and 8 lower-case hex digits          */
	gchar     *digest;      /* fs_intel_ruleset_digest()                */
	gchar     *plan;        /* the plan hash (32 hex digits)            */
	GPtrArray *rules;       /* FsIntelWinRule*: in set order, inbound
	                         * before outbound, IPv4 before IPv6, chunk
	                         * order; the manifest last.  Empty for the
	                         * empty rule set, which leaves no rule.    */
} FsIntelWinPlan;

/* "g" followed by exactly 8 lower-case hex digits. */
gboolean fs_intelwin_gen_is_valid (const gchar *gen);

/* A generation not in `taken' (NULL-terminated, may be NULL), derived
 * from `seed' (the backend passes a random number).  Caller frees. */
gchar   *fs_intelwin_gen_new (guint32 seed, const gchar *const *taken);

/* The rules for `ruleset' under generation `gen', at most max_tokens
 * addresses and max_chars characters per rule (the backend passes
 * FS_INTELWIN_MAX_*; tests pass small ones).  Each interval becomes one
 * token, as fs_range4_to_string()/fs_range6_to_string() print it: an
 * address, a CIDR block or "a-b"; a token is never split.  NULL when
 * the gen is invalid, a limit is 0, or the rule set holds a set
 * fs_intel_ruleset_add() would have refused (hand-filled structs). */
FsIntelWinPlan *fs_intelwin_plan (const FsIntelRuleset *ruleset,
                                  const gchar *gen, guint max_tokens,
                                  guint max_chars);
void            fs_intelwin_plan_free (FsIntelWinPlan *plan);

/* ---- reading back --------------------------------------------------- */

/* RemoteAddresses as Windows Firewall gives it back, into `into' (not
 * normalized).  Accepts what Windows writes for what we gave it: an
 * address, "a/n", an IPv4 "a/m.m.m.m" with a contiguous mask, and
 * "a-b", of either family, comma-separated.  FALSE (and `into' left
 * as it was) for anything else: "*", the keywords (LocalSubnet, DNS,
 * DHCP, WINS, DefaultGateway, Intranet, ...), an empty token. */
gboolean fs_intelwin_parse_remote (const gchar *text, FsRangeSet *into);

/* One rule as read from the firewall: every property that can narrow
 * or undo a block.  Strings may be NULL (not set). */
typedef struct
{
	gchar   *name;
	gchar   *description;
	gchar   *grouping;
	gint     direction;        /* NET_FW_RULE_DIRECTION              */
	gint     action;           /* NET_FW_ACTION: 0 block, 1 allow    */
	gboolean enabled;
	glong    profiles;         /* NET_FW_PROFILE_TYPE2 bits          */
	glong    protocol;         /* 256: any                           */
	gchar   *local_addresses;
	gchar   *remote_addresses;
	gchar   *local_ports;
	gchar   *remote_ports;
	gchar   *application;
	gchar   *service;
	gchar   *interface_types;
	gboolean interfaces;       /* limited to named interfaces        */
	gboolean conditions;       /* INetFwRule3: limited to an app
	                            * package, users, machines, or needs
	                            * IPsec                               */
} FsIntelWinSeen;

FsIntelWinSeen *fs_intelwin_seen_new  (void);
void            fs_intelwin_seen_free (gpointer seen);

/* The generation a rule name ends with ("SFW-TI ... g0123abcd"), or
 * NULL when the name is not one StockFW writes.  Borrowed from
 * `name'. */
const gchar *fs_intelwin_name_gen (const gchar *name);

/* Whether a rule's group is ours (exact). */
gboolean fs_intelwin_in_group (const gchar *grouping);

/* The key two rule names share when Windows may take them for the same
 * name: case folded, since the documentation does not say whether
 * INetFwRules::Remove matches names case-insensitively.  Counting
 * names by this key errs towards "shared", so a rule is renamed before
 * its removal whenever another rule's name differs only in case
 * (review W6).  NULL for NULL.  Caller frees. */
gchar *fs_intelwin_name_key (const gchar *name);

/* How many rules in `seen' (FsIntelWinSeen*) are in our group and
 * carry generation `gen', whatever else is there (a foreign rule in the
 * group does not hide them).  The backend reads this back after taking
 * a failed apply's rules out again, instead of trusting Remove, which
 * succeeds for a name it does not find (review W6). */
guint fs_intelwin_count_gen (const GPtrArray *seen, const gchar *gen);

typedef struct
{
	FsIntelLive live;     /* ABSENT, PRESENT or PARTIAL               */
	gchar      *digest;   /* PRESENT: the manifest's digest           */
	gchar      *gen;      /* PRESENT: the generation                  */
	gchar      *why;      /* PARTIAL: one sentence on what is wrong   */
	guint       ours;     /* rules in our group                       */
	GPtrArray  *gens;     /* gchar*: every generation seen, once      */
} FsIntelWinRead;

/* The verdict on every rule read back (FsIntelWinSeen*, any group;
 * other groups are ignored):
 *   ABSENT   no rule in our group;
 *   PRESENT  exactly one generation, its manifest, and its rules are
 *            all there and unaltered: the plan hash recomputed from
 *            what was read (names, directions, addresses) is the one
 *            the manifest records, and every rule blocks, is enabled,
 *            covers every profile, protocol, port, local address,
 *            program and interface, and carries no INetFwRule3
 *            condition;
 *   PARTIAL  anything else: a rule missing, added, edited, disabled,
 *            narrowed, a second generation (a removal that failed),
 *            a rule in the group StockFW did not write.
 * Fills `out' (clear it with fs_intelwin_read_clear()). */
void fs_intelwin_read       (const GPtrArray *seen, FsIntelWinRead *out);
void fs_intelwin_read_clear (FsIntelWinRead *read);

/* ---- in force? ------------------------------------------------------ */

/* NET_FW_PROFILE_TYPE2 bits. */
#define FS_INTELWIN_PROFILE_DOMAIN  1
#define FS_INTELWIN_PROFILE_PRIVATE 2
#define FS_INTELWIN_PROFILE_PUBLIC  4

/* What decides whether Windows Firewall enforces the rules now. */
typedef struct
{
	gboolean service_known;   /* the service state could be read      */
	gboolean service_running; /* MpsSvc is running                    */
	gboolean policy_read;     /* the settings below could be read     */
	glong    current;         /* CurrentProfileTypes: profiles in use */
	gint     enabled[3];      /* domain, private, public: 1 on, 0 off,
	                           * -1 could not be read                 */
	guint    excluded[3];     /* interfaces excluded from each profile */
	gboolean gp_read;         /* LocalPolicyModifyState could be read */
	gboolean gp_override;     /* LocalPolicyModifyState is
	                           * NET_FW_MODIFY_STATE_GP_OVERRIDE: rules
	                           * added on this computer do not apply  */
} FsIntelWinForce;

/* NULL when the rules are in force on every network in use; else one
 * sentence saying where they are not and why: the service is stopped;
 * the settings, Group Policy's state or a profile in use cannot be
 * read (never taken as "on"); Group Policy does not apply local rules;
 * the firewall is off for a profile in use; adapters are excluded from
 * a profile in use.  Caller frees. */
gchar *fs_intelwin_not_in_force (const FsIntelWinForce *force);

G_END_DECLS

#endif /* FS_INTELWIN_H */
