/*---[ fs-whatif.h ]-----------------------------------------------------
 * The What-If engine (1.0.7): "would this connection be allowed by my
 * firewall?", answered the way the real firewall on this platform
 * would answer it, with the reasons, and with fixes that have been
 * checked before they are offered.
 *
 * Three parts:
 *
 *   1. A query.  fs_whatif_parse() reads one line of plain text
 *      ("allow SSH from 192.168.1.50", "block DNS to 8.8.8.8 udp",
 *      "can [2001:db8::5]:443 reach me") into an FsWhatIfQuery: a
 *      direction (or both), a protocol, a port, a host, the user's verb
 *      (allow / block / just asking), and the pieces it recognised with
 *      a confidence.  Anything the line leaves open stays open -- no
 *      silent defaults.  A line with nothing recognisable in it is an
 *      error, not an "outbound TCP to anywhere" guess.
 *
 *   2. A context.  FsWhatIfContext carries everything that changes the
 *      answer besides the policy: which firewall model applies, the
 *      Firewall preferences (ICMP types, reject method, restrictive
 *      outbound, interfaces and NAT, the broadcast and reserved-source
 *      blocks), whether the firewall is running, the Windows network
 *      profiles in force with their default actions when known, whether
 *      the saved policy is actually the one loaded, and Sentinel's
 *      auto-blocks with their expiry times.  Unknowns stay unknown and
 *      the answer says what it assumed.
 *
 *   3. Two firewall models, one per platform:
 *
 *      LINUX_FIRST_MATCH   the INBOUND and OUTBOUND chains exactly as
 *                          fs-script.c writes them, in their order, and
 *                          the first rule that matches decides.  The
 *                          model renders itself as iptables lines
 *                          (fs_whatif_linux_chain_text) and the core
 *                          suite compares those with the generator's own
 *                          output, so the two cannot drift apart.
 *
 *      WINDOWS_BLOCK_WINS  the policy as fs_fwrule_from_policy() turns
 *                          it into Windows Firewall rules, plus the
 *                          settings plan (fs-settings-plan.c) with its
 *                          profile scoping.  Any matching block wins over
 *                          any allow; with neither, the profile's default
 *                          action decides (read from INetFwPolicy2 when
 *                          the backend can, otherwise Windows' own
 *                          default -- block inbound, allow outbound --
 *                          and the answer says it was assumed).
 *
 * Under-specified lines.  When the line left the host, port, protocol
 * or ICMP type open (or the profile, interface or a host name's address
 * is unknown), the engine evaluates a representative of every region a
 * rule draws on that field.  If they all agree, that is the answer; if
 * not, the answer is DEPENDS with the concrete split ("Allowed for most
 * hosts; blocked for 203.0.113.0/24 by rule 'X'").  A line with no
 * direction is answered for both directions.
 *
 * Every answer carries the evaluation trace (each rule checked, skipped
 * or matched, by display name and policy row) and the deciding step,
 * a short plain-English reason, and a list of actions.  An action that
 * would change the policy (CREATE_ALLOW / CREATE_BLOCK) is offered only
 * after the engine has re-run the question against the policy with the
 * row added and found exactly the verdict asked for, with no change to
 * a fixed set of unrelated probes beyond what the row itself names.  A
 * created allow always names one port and one protocol: never portless,
 * never every port for anyone.
 *
 * Pure core: no GTK, no OS calls.  The UI fills the context from the
 * backend; the tests fill it by hand.
 *--------------------------------------------------------------------*/
#ifndef FS_WHATIF_H
#define FS_WHATIF_H

#include <glib.h>
#include "core/fs-rules.h"
#include "core/fs-script.h"

G_BEGIN_DECLS

/* ---- the question ------------------------------------------------- */

typedef enum
{
	FS_WHATIF_DIR_BOTH = 0,        /* the line did not say: ask both   */
	FS_WHATIF_DIR_INBOUND,
	FS_WHATIF_DIR_OUTBOUND
} FsWhatIfDirection;

typedef enum
{
	FS_WHATIF_PROTO_ANY = 0,       /* the line did not say             */
	FS_WHATIF_PROTO_TCP,
	FS_WHATIF_PROTO_UDP,
	FS_WHATIF_PROTO_ICMP
} FsWhatIfProto;

/* What the user wants, as their verb said it.  "block X" asks for X to
 * be blocked: the answer says what it is NOW, and the fix offered is a
 * block. */
typedef enum
{
	FS_WHATIF_VERB_NONE = 0,       /* a question: "is ssh open?"       */
	FS_WHATIF_VERB_ALLOW,
	FS_WHATIF_VERB_BLOCK
} FsWhatIfVerb;

typedef enum
{
	FS_WHATIF_PIECE_VERB,
	FS_WHATIF_PIECE_DIRECTION,
	FS_WHATIF_PIECE_PROTOCOL,
	FS_WHATIF_PIECE_PORT,
	FS_WHATIF_PIECE_SERVICE,
	FS_WHATIF_PIECE_HOST,
	FS_WHATIF_PIECE_ICMP,
	FS_WHATIF_PIECE_IGNORED        /* seen, deliberately not used      */
} FsWhatIfPieceKind;

/* One thing the parser recognised: the words as typed and what it took
 * them to mean ("SSH" -> "service SSH: TCP port 22"). */
typedef struct
{
	FsWhatIfPieceKind kind;
	gchar *text;
	gchar *meaning;
} FsWhatIfPiece;

typedef struct
{
	gchar            *text;        /* the line as typed                */
	FsWhatIfVerb      verb;
	FsWhatIfDirection direction;
	FsWhatIfProto     protocol;
	guint             port;        /* 1-65535; 0 = open                */
	gchar            *host;        /* address or block, canonical; NULL = open */
	gchar            *icmp_type;   /* iptables type name ("echo-request"),
	                                * NULL = any ICMP type             */
	gchar            *service;     /* the service the line named, or NULL */
	gdouble           confidence;  /* 0..1                             */
	GPtrArray        *pieces;      /* FsWhatIfPiece*                   */

	/* A host the line named that could not be read as an address (a
	 * host name): the answer is for every host, and no rule is offered,
	 * since a row for "anyone" is not the row that was asked for. */
	gchar            *host_unread;
	/* The line itself said the other end is anyone ("from anyone",
	 * "from the internet", "to anywhere").  Only then is a row for
	 * every host offered. */
	gboolean          host_any_said;
} FsWhatIfQuery;

/* An empty query (direction BOTH, everything open), for callers that
 * build one by hand.  Free with fs_whatif_query_free. */
FsWhatIfQuery *fs_whatif_query_new  (void);
FsWhatIfQuery *fs_whatif_query_copy (const FsWhatIfQuery *query);
void           fs_whatif_query_free (FsWhatIfQuery *query);

GQuark fs_whatif_error_quark (void);
#define FS_WHATIF_PARSE_ERROR (fs_whatif_error_quark ())

enum
{
	FS_WHATIF_ERR_EMPTY = 1,       /* nothing typed                    */
	FS_WHATIF_ERR_UNREADABLE,      /* nothing recognisable             */
	FS_WHATIF_ERR_BAD_PORT,        /* port 0, or above 65535           */
	FS_WHATIF_ERR_BAD_HOST         /* an address that is not one       */
};

/* Reads one line.  NULL with error when the line is empty, names
 * nothing recognisable ("I could not find a port, service, host or
 * direction in ..."), or names an impossible port or address. */
FsWhatIfQuery *fs_whatif_parse (const gchar *text, GError **error);

/* ---- the context -------------------------------------------------- */

typedef enum
{
	FS_WHATIF_LINUX_FIRST_MATCH,
	FS_WHATIF_WINDOWS_BLOCK_WINS
} FsWhatIfPlatform;

/* The model of the platform this build runs on. */
FsWhatIfPlatform fs_whatif_native_platform (void);

typedef enum
{
	FS_WHATIF_FW_UNKNOWN = 0,
	FS_WHATIF_FW_RUNNING,
	FS_WHATIF_FW_STOPPED
} FsWhatIfFwState;

typedef enum
{
	FS_WHATIF_DEFAULT_UNKNOWN = 0, /* Windows' own default is assumed  */
	FS_WHATIF_DEFAULT_ALLOW,
	FS_WHATIF_DEFAULT_BLOCK
} FsWhatIfDefault;

/* Whether the saved policy is what the firewall has loaded. */
typedef enum
{
	FS_WHATIF_LIVE_UNKNOWN = 0,
	FS_WHATIF_LIVE_YES,            /* the last apply loaded exactly it */
	FS_WHATIF_LIVE_HELD,           /* applies are held (audit-only, Lock) */
	FS_WHATIF_LIVE_FAILED,         /* the last apply failed            */
	FS_WHATIF_LIVE_STALE           /* saved since the last apply       */
} FsWhatIfLive;

typedef struct
{
	gchar *target;                 /* the destination Sentinel blocked */
	gint64 expires_unix;           /* when it lifts; 0 = not known     */
} FsWhatIfAutoBlock;

typedef struct
{
	FsWhatIfPlatform platform;
	const FsPolicy  *policy;       /* borrowed; NULL = no policy loaded */
	const FsSettings *settings;    /* borrowed; NULL = fresh-install defaults */

	FsWhatIfFwState  firewall;

	/* Windows.  profiles_in_use: FS_PROFILE_BIT() of each profile in
	 * force (0 = not known: every profile is considered).
	 * profile_enabled: -1 not known, 0 off, 1 on. */
	guint            profiles_in_use;
	gint             profile_enabled[3];
	FsWhatIfDefault  default_inbound[3];
	FsWhatIfDefault  default_outbound[3];
	/* "Block all incoming connections, including those in the list of
	 * allowed apps" (netsh blockinboundalways) per profile: -1 not
	 * known, 0 off, 1 on.  On, Windows ignores every inbound allow. */
	gint             block_all_inbound[3];

	FsWhatIfLive     live;
	gchar           *live_detail;  /* owned; why, in words, or NULL    */

	/* Addresses of this computer, when known (gchar*, owned).  Linux
	 * outbound "from host" rows match the SOURCE address; with these
	 * the answer can say which one applies instead of "depends". */
	GPtrArray       *local_addresses;

	GPtrArray       *auto_blocks;  /* FsWhatIfAutoBlock*, owned        */
	gint64           now_unix;     /* for "expires in N minutes"; 0 = now */
} FsWhatIfContext;

/* A context with everything unknown: the firewall assumed running,
 * live state unknown, no auto-blocks. */
FsWhatIfContext *fs_whatif_context_new (FsWhatIfPlatform platform,
                                        const FsPolicy *policy,
                                        const FsSettings *settings);
void             fs_whatif_context_free (FsWhatIfContext *ctx);
void             fs_whatif_context_add_auto_block (FsWhatIfContext *ctx,
                                                   const gchar *target,
                                                   gint64 expires_unix);
void             fs_whatif_context_add_local_address (FsWhatIfContext *ctx,
                                                      const gchar *address);

/* TRUE when two policies hold the same rows, kind by kind, in the same
 * order -- "is the saved policy the applied one?". */
gboolean fs_whatif_policy_same (const FsPolicy *a, const FsPolicy *b);

/* ---- the answer --------------------------------------------------- */

typedef enum
{
	FS_WHATIF_ALLOWED,
	FS_WHATIF_BLOCKED,
	FS_WHATIF_DEPENDS,
	FS_WHATIF_ERROR
} FsWhatIfVerdict;

/* "ALLOWED", "BLOCKED", "DEPENDS", "ERROR". */
const gchar *fs_whatif_verdict_name (FsWhatIfVerdict verdict);

/* Where the deciding rule came from. */
typedef enum
{
	FS_WHATIF_ORIGIN_DEFAULT,      /* the chain's / profile's default  */
	FS_WHATIF_ORIGIN_POLICY,       /* a row of the user's policy       */
	FS_WHATIF_ORIGIN_SENTINEL,     /* a row Sentinel staged            */
	FS_WHATIF_ORIGIN_SETTINGS,     /* a Firewall preference (ICMP ...) */
	FS_WHATIF_ORIGIN_BUILTIN,      /* always there (loopback ...)      */
	FS_WHATIF_ORIGIN_STOPPED       /* the firewall is off              */
} FsWhatIfOrigin;

typedef enum
{
	FS_WHATIF_STEP_SKIPPED,        /* checked, did not match           */
	FS_WHATIF_STEP_MATCHED,        /* matched (decides, or is shadowed) */
	FS_WHATIF_STEP_NOTE            /* not a rule: a fact on the way    */
} FsWhatIfStepKind;

typedef struct
{
	FsWhatIfStepKind kind;
	FsWhatIfOrigin   origin;
	gchar           *rule;         /* display name                     */
	gint             policy_kind;  /* FsRuleKind, or -1                */
	gint             policy_index; /* row within that kind, or -1      */
	gboolean         allows;       /* the rule's action                */
	gchar           *detail;       /* what was checked, in words       */
} FsWhatIfStep;

/* One region of a DEPENDS answer. */
typedef struct
{
	FsWhatIfVerdict verdict;       /* ALLOWED or BLOCKED               */
	gchar          *condition;     /* "for 203.0.113.0/24", "for UDP"  */
	FsWhatIfOrigin  origin;
	gchar          *rule;          /* deciding rule's name             */
	gint            policy_kind;
	gint            policy_index;
} FsWhatIfCase;

typedef enum
{
	FS_WHATIF_ACT_CREATE_ALLOW,    /* add `row' (verified)              */
	FS_WHATIF_ACT_CREATE_BLOCK,    /* add `row' (verified)              */
	FS_WHATIF_ACT_OPEN_RULE,       /* a policy row decided: edit it    */
	FS_WHATIF_ACT_LIFT_SENTINEL,   /* a Sentinel auto-block decided    */
	FS_WHATIF_ACT_OPEN_ICMP_SETTINGS, /* ICMP is a Preferences page    */
	FS_WHATIF_ACT_OPEN_SETTINGS,   /* another Firewall preference      */
	FS_WHATIF_ACT_START_FIREWALL,  /* the firewall (or profile) is off */
	FS_WHATIF_ACT_APPLY_POLICY     /* the saved policy is not live     */
} FsWhatIfActionKind;

typedef struct
{
	FsWhatIfActionKind kind;
	gboolean    inbound;           /* the direction it answers         */
	gchar      *label;             /* button text                      */
	gchar      *explanation;       /* one or two sentences             */
	FsRule     *row;               /* CREATE_*: the exact row          */
	gint        policy_kind;       /* OPEN_RULE / LIFT_SENTINEL: the row */
	gint        policy_index;
	gchar      *target;            /* LIFT_SENTINEL: the destination   */
	gint64      expires_unix;      /* LIFT_SENTINEL: 0 = not known     */
	gchar      *page;              /* OPEN_*SETTINGS: the Preferences
	                                * page id, "icmp" or "protection" */
	gchar      *setting;           /* OPEN_*SETTINGS: the FsSettings field
	                                * to change ("icmp_echo_request")  */
	gboolean    setting_on;        /* ... and the value it should get  */
	FsWhatIfVerdict gives;         /* the verdict the question gets
	                                * with this change made            */
	gboolean    verified;          /* re-simulated with the change made:
	                                * the question gets `gives' for every
	                                * case (CREATE_*: and no unrelated
	                                * probe changes).  A CREATE_* action
	                                * is only ever offered verified.   */
} FsWhatIfAction;

/* One direction's answer. */
typedef struct
{
	gboolean        inbound;
	FsWhatIfVerdict verdict;       /* ALLOWED, BLOCKED or DEPENDS      */
	gchar          *probe;         /* "Inbound TCP port 22 from 1.2.3.4" */
	gchar          *reason;        /* short, plain English             */
	GPtrArray      *steps;         /* FsWhatIfStep*, the trace          */
	gint            decided_by;    /* index into steps, or -1          */
	FsWhatIfOrigin  origin;        /* of the deciding rule             */
	gchar          *rule;          /* the deciding rule's name         */
	gint            policy_kind;   /* -1 unless a policy row decided   */
	gint            policy_index;
	GPtrArray      *cases;         /* FsWhatIfCase*: DEPENDS only, the
	                                * first is the common case        */
	GPtrArray      *actions;       /* FsWhatIfAction*                   */
} FsWhatIfAnswer;

typedef struct
{
	FsWhatIfQuery   *query;        /* owned copy; NULL on a parse error */
	FsWhatIfVerdict  verdict;      /* both directions together          */
	GPtrArray       *answers;      /* FsWhatIfAnswer*: one, or inbound
	                                * then outbound                    */
	GPtrArray       *notes;        /* gchar*: what was assumed          */
	gchar           *summary;      /* one line: "You asked to block
	                                * this. It is currently ALLOWED." */
	gchar           *error;        /* ERROR only: why                   */

	/* The firewall (or, on Windows, a profile) being off decided part
	 * of the answer.  verdict_running is then the verdict the same
	 * question gets once it runs; otherwise it equals verdict. */
	gboolean         stopped_decides;
	FsWhatIfVerdict  verdict_running;
} FsWhatIfResult;

/* Answers a query.  Never NULL. */
FsWhatIfResult *fs_whatif_simulate (const FsWhatIfContext *ctx,
                                    const FsWhatIfQuery *query);

/* Parses and answers; a line that cannot be read gives an ERROR
 * result carrying the parser's message.  Never NULL. */
FsWhatIfResult *fs_whatif_simulate_text (const FsWhatIfContext *ctx,
                                         const gchar *text);

void fs_whatif_result_free (FsWhatIfResult *result);

/* The first verified CREATE_ALLOW / CREATE_BLOCK action of any answer,
 * or NULL: what "Create This Rule" is allowed to write. */
const FsWhatIfAction *fs_whatif_result_create_action (const FsWhatIfResult *r);

/* The first action of the kinds a window can run in place
 * (CREATE_*, LIFT_SENTINEL), or NULL. */
const FsWhatIfAction *fs_whatif_result_primary_action (const FsWhatIfResult *r);

/* ---- checking a fix ----------------------------------------------- */

/* TRUE when the row a CREATE_* action carries is one StockFW may write
 * on the user's behalf: it parses on both platforms, names exactly one
 * port (or, for a block of one host, no port at all), and an allow names
 * exactly one protocol ("TCP" or "UDP").  *why says what is wrong. */
gboolean fs_whatif_row_is_safe (const FsWhatIfAction *action, gchar **why);

/* Re-runs the check behind a CREATE_* action against ctx's policy as
 * it is now: the row gives exactly the verdict the action promises for
 * the question, and leaves every unrelated probe's verdict alone.
 * Used again just before a row is written, because the policy may have
 * changed since the question was asked. */
gboolean fs_whatif_action_verify (const FsWhatIfContext *ctx,
                                  const FsWhatIfQuery *query,
                                  const FsWhatIfAction *action,
                                  gchar **why);

/* ---- text --------------------------------------------------------- */

/* The Preferences switches a settings fix may name: the i-th one's key
 * (NULL past the last), its label as the dialog shows it, where it is
 * in words ("Preferences > ICMP") and the dialog's page id ("icmp"). */
const gchar *fs_whatif_setting_nth (guint i, const gchar **label,
                                    const gchar **where, const gchar **page);

/* The whole answer as a few lines of plain text (the panel and the
 * command line print this).  Caller frees. */
gchar *fs_whatif_result_describe (const FsWhatIfResult *result);

/* ---- the Linux model, as iptables text ---------------------------- */

/* The INBOUND or OUTBOUND chain of the Linux model for one family
 * (FS_FAMILY_IPV4 / FS_FAMILY_IPV6), one "-A CHAIN ..." line per rule
 * in evaluation order -- the same text fs_script_generate_*_family()
 * writes for those chains, which the core suite checks.  Caller frees. */
gchar *fs_whatif_linux_chain_text (const FsPolicy *policy,
                                   const FsSettings *settings,
                                   FsFamily family, gboolean inbound);

G_END_DECLS

#endif /* FS_WHATIF_H */
