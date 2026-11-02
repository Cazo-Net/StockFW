/*---[ fs-health.h ]-----------------------------------------------------
 * Policy health check (1.0.7 Copilot).
 *
 * Reads the saved policy row by row and reports what is wrong with it:
 * exact duplicates, rows another row already covers, allows that a
 * deny makes unreachable, outbound allows that do nothing while
 * outbound traffic is allowed by default, broad or risky inbound
 * allows, and denies that reach no address family on this platform.
 *
 * Coverage is computed exactly, not sampled: ports through the netsh
 * port-spec parser (fs_fwrule_port_spec), addresses through the range
 * parser (fs_range_parse).  "A covers B" means the same direction, the
 * same address side, every protocol and port of B inside A, and every
 * address of B inside A.  A row that names a host by name is never
 * called covered and never covers anything.
 *
 * Every fix is checked with the What-If engine before it is offered:
 * the engine answers a set of probes (the corners of the row, and for a
 * narrowing one probe outside the new scope) against the policy as it
 * is and against the policy with the fix made.  A removal is offered
 * only when no verdict changes; a narrowing only when every in-scope
 * verdict stays and every out-of-scope probe goes from ALLOWED to
 * BLOCKED.  Otherwise the finding carries no fix and says why.
 *
 * These are fixed, documented rules.  Nothing here learns or guesses,
 * and nothing here touches the network.  Pure core: no GTK.
 *--------------------------------------------------------------------*/
#ifndef FS_HEALTH_H
#define FS_HEALTH_H

#include <glib.h>
#include "core/fs-rules.h"
#include "core/fs-whatif.h"
#include "core/fs-copilot.h"

G_BEGIN_DECLS

typedef enum
{
	FS_HEALTH_DUPLICATE,      /* same row twice                        */
	FS_HEALTH_SHADOWED,       /* another row with the same action covers it */
	FS_HEALTH_UNREACHABLE,    /* an allow a deny covers                */
	FS_HEALTH_NO_EFFECT,      /* outbound allows while outbound is open */
	FS_HEALTH_BROAD,          /* a wide inbound allow from anyone      */
	FS_HEALTH_RISKY_OPEN,     /* a risky service open to the internet  */
	FS_HEALTH_NO_FAMILY,      /* a deny that reaches no address family */
	FS_HEALTH_FAMILY_GAP      /* reserved (not checked yet)            */
} FsHealthKind;

typedef enum
{
	FS_HEALTH_FIX_NONE,
	FS_HEALTH_FIX_REMOVE,     /* take the row out                      */
	FS_HEALTH_FIX_REPLACE     /* put fix_after where the row is        */
} FsHealthFixKind;

/* One What-If probe behind a fix. */
typedef struct
{
	gchar           *probe;     /* "Inbound TCP port 3389 from 203.0.113.10" */
	FsWhatIfVerdict  before;    /* against the policy as it is           */
	FsWhatIfVerdict  after;     /* against the policy with the fix made  */
	FsWhatIfVerdict  expected;  /* what the fix promises for `after'     */
	gboolean         in_scope;  /* FALSE: a probe the fix should block   */
} FsHealthCheck;

typedef struct
{
	FsHealthKind       kind;
	FsCopilotSeverity  severity;
	gint               policy_kind;   /* the row the finding is about   */
	gint               policy_index;
	gint               other_kind;    /* the covering row, or -1        */
	gint               other_index;
	gchar             *rule_csv;      /* the row as stored              */
	gchar             *other_csv;     /* the covering row, or NULL      */
	gchar             *title;
	gchar             *why;
	gchar             *evidence;
	gchar             *whatif_line;   /* a line to ask What-If, or NULL */

	FsHealthFixKind    fix;
	gchar             *fix_label;     /* "Remove the later copy"        */
	gchar             *fix_before;    /* literal CSV rows               */
	gchar             *fix_after;     /* NULL for a removal             */
	GPtrArray         *checks;        /* FsHealthCheck*                 */
	gboolean           verified;      /* every check came out as promised */
	gchar             *no_fix_reason; /* why no fix is offered, or NULL */
} FsHealthFinding;

/* The check.  ctx gives the platform model, the policy and the
 * settings; its firewall state and Sentinel blocks are ignored (the
 * check is about the saved policy).  lan_prefix is the local network
 * a narrowing fix narrows to ("192.168.1.0/24"); NULL derives a /24
 * from the first private IPv4 address in ctx->local_addresses, and
 * with none known no narrowing is offered.  Returns FsHealthFinding*
 * most severe first; never NULL. */
GPtrArray *fs_health_check (const FsWhatIfContext *ctx,
                            const gchar *lan_prefix);

void fs_health_finding_free (FsHealthFinding *finding);

/* "duplicate", "shadowed", ... (the JSON names). */
const gchar *fs_health_kind_name (FsHealthKind kind);

/* "inbound_allow_service", ... (the JSON names). */
const gchar *fs_health_rule_kind_name (FsRuleKind kind);

/* "critical", "warning", "info". */
const gchar *fs_health_severity_name (FsCopilotSeverity severity);

/* The network of ip/netmask as "a.b.c.d/n", or NULL when either is
 * not an IPv4 address or the address is not private.  Caller frees. */
gchar *fs_health_lan_prefix (const gchar *ip, const gchar *netmask);

/* TRUE when two findings describe the same problem with the same fix
 * and the same check results: what the apply path compares after
 * running the check again just before writing. */
gboolean fs_health_finding_same (const FsHealthFinding *a,
                                 const FsHealthFinding *b);

/* ---- applying a fix ------------------------------------------------ */

/* What it takes to put a fix back. */
typedef struct
{
	FsHealthFixKind kind;
	FsRuleKind      rule_kind;
	gint            index;        /* where the row was                 */
	gchar          *before_csv;   /* the row before the fix            */
	gchar          *after_csv;    /* the row after (REPLACE), or NULL  */
	gchar          *anchor_csv;   /* the row that preceded it, or NULL */
	gchar          *label;
} FsHealthUndo;

/* Makes a verified fix in `policy' and saves it, rolling the store
 * back when the write fails.  The row is found by its content (the
 * index is a hint): FALSE with *why set when it is no longer there,
 * when the finding is not verified, or when the save fails.  Writes
 * the audit line "copilot health fix".  *undo receives what it takes
 * to put it back (free with fs_health_undo_free). */
gboolean fs_health_fix_apply (FsPolicy *policy,
                              const FsHealthFinding *finding,
                              FsHealthUndo **undo, gchar **why);

/* Puts a fix back, found by content: a replaced row is located by its
 * after_csv; a removed row goes back after its anchor row (or at its
 * old index when the anchor is gone).  Saves with rollback; audits
 * "copilot health fix undone". */
gboolean fs_health_undo_apply (FsPolicy *policy, const FsHealthUndo *undo,
                               gchar **why);

void fs_health_undo_free (FsHealthUndo *undo);

G_END_DECLS

#endif /* FS_HEALTH_H */
