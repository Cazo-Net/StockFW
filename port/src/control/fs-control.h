/*---[ fs-control.h ]----------------------------------------------------
 * The one control layer every write goes through (master plan section
 * 2, PR 3).
 *
 *   fs_control_do (actor, op, params) -> FsControlResult
 *
 * PR 3 runs it in-process, from the terminal; PR 7 and PR 8 put the
 * daemon's socket in front of it, so no command body is written twice.
 * It lives outside src/core: it is Linux-only (flock, uids) and linked
 * into `stockfw' only.
 *
 * Every op that writes takes the policy lock (fs_policy_lock) for its
 * whole length, re-reads the policy and the preferences from disk under
 * it, and passes the actor's channel to the core gates as the audit
 * source.  Ops never prompt and never print: a question (the lockout
 * guard) comes back as FS_CONTROL_CONFIRM with what to ask, and the
 * caller asks again with "yes".
 *
 * Params are a GVariant dictionary (a{sv}), so the same op can arrive
 * as JSON over a socket later.  The result carries typed parts for an
 * in-process caller and fs_control_result_json for any other.
 *--------------------------------------------------------------------*/
#ifndef FS_CONTROL_H
#define FS_CONTROL_H

#include <glib.h>
#include "core/fs-apply.h"
#include "core/fs-backend.h"
#include "core/fs-intel.h"
#include "core/fs-lockout.h"
#include "core/fs-prefs.h"
#include "core/fs-rules.h"

G_BEGIN_DECLS

/* Who asks.  channel is the audit source ("cli"; later "daemon",
 * "dashboard", "boot"); uid the caller's (the socket's SO_PEERCRED
 * from PR 8, getuid () in-process). */
typedef struct
{
	const gchar *channel;
	gint         uid;
} FsControlActor;

typedef enum
{
	FS_CONTROL_OK = 0,
	FS_CONTROL_FAILED,      /* the op ran and did not succeed           */
	FS_CONTROL_USAGE,       /* refused: the request is wrong, nothing
	                         * was changed                              */
	FS_CONTROL_NEED_ROOT,   /* the op needs uid 0                       */
	FS_CONTROL_CONFIRM,     /* the lockout guard: this would cut an SSH
	                         * session; nothing was changed.  Ask, then
	                         * send the op again with "yes": true      */
	FS_CONTROL_CONFLICT     /* the row named is no longer the row the
	                         * caller read: nothing was changed         */
} FsControlStatus;

/* "ok" "failed" "usage" "need-root" "confirm" "conflict". */
const gchar *fs_control_status_name (FsControlStatus status);

/* The blocklists following a start or a stop (B7, design 6.5). */
typedef struct
{
	gboolean ran;           /* the follow-up was attempted             */
	gboolean ok;
	gboolean start;
	const gchar *result;    /* "applied" "held" "failed" "none"
	                         * "suspended"                              */
	gchar   *hold;
	gchar   *error;
	gchar   *notes;         /* lines, "\n"-ended                        */
	guint    sets;
	gboolean held;          /* the start was held: nothing re-applied  */
	gboolean outcome;       /* an apply outcome was read               */
} FsControlIntel;

/* The rule kinds by the names the terminal uses ("inbound-tcp" ...),
 * NULL-ended, in FsRuleKind order. */
const gchar * const *fs_control_kind_names (void);
gboolean fs_control_kind_parse (const gchar *name, FsRuleKind *kind);

typedef struct
{
	gchar           *op;
	FsControlStatus  status;
	gchar           *error;        /* one sentence, or NULL             */
	gchar           *hint;         /* what to do next, or NULL          */

	/* policy.add, policy.remove, policy.replace */
	FsRule          *rule;         /* as stored (add, replace) or as
	                                * removed (remove)                  */
	FsRule          *twin;         /* add --both                        */
	FsRule          *old;          /* replace: the row before           */
	guint            number;       /* 1-based, in its kind              */
	guint            twin_number;
	gboolean         already;      /* add: the rule was there already   */
	gboolean         invalid_rule; /* USAGE: the fields are not a rule;
	                                * problem says why (may be NULL)    */
	gchar           *problem;
	FsPolicy        *policy;       /* the policy after the op           */
	GPtrArray       *problems;     /* FsPolicyProblem*: lines of the
	                                * files that are not rules (refused) */
	gboolean         no_policy;    /* apply/start: no rule file at all  */
	gboolean         saved;        /* 3D: the edit (or init) was saved;
	                                * an "apply" after it may still have
	                                * failed (status, error say so)     */
	guint            dropped;      /* policy.init: rows it replaced     */

	/* apply, firewall.start, firewall.stop, settings.apply */
	FsApplyOutcome  *outcome;
	gboolean         changed;      /* start/stop did something          */
	FsFirewallState  was;          /* the state read first              */
	guint            live_rules;   /* start while running: rows live    */
	gboolean         journal;      /* start/settings.apply: a journal   */
	gboolean         settings_from_journal; /* start: the settings the
	                                * backend got are the journal's (3B) */
	FsPolicyImpact  *unapplied;    /* settings.apply: saved policy rows
	                                * left out (journal -> file)         */
	FsControlIntel   intel;

	/* the lockout guard (apply, start, settings.apply) */
	FsLockoutReport *lockout;      /* NULL when not run                 */
	FsPolicy        *lockout_policy; /* what it checked                 */
	gboolean         lockout_confirmed;

	/* settings.set */
	FsPrefsCheck    *check;
	gboolean         prefs_unreadable; /* kept as .bad, defaults written */

	/* PR 4: each package adds its fields between its markers (4B
	 * copilot and sentinel, 4C event and What-If actions, 4D trust and
	 * intel), so the packages merge without touching each other. */
	/* === PR4-B === */
	/* === end PR4-B === */
	/* === PR4-C === */
	/* === end PR4-C === */
	/* === PR4-D === */
	/* === end PR4-D === */
} FsControlResult;

/* [ fs_control_do ]
 * Runs `op' for `actor' with `params' (a{sv}; may be NULL for none; a
 * floating reference is sunk).  Never NULL; fs_control_result_free.
 *
 * Ops and their params:
 *   policy.add      kind s, fields as, comment s, both b
 *   policy.remove   kind s, number u, csv s (the row as read: refused
 *                   with CONFLICT when the row there is another now)
 *   policy.replace  kind s, number u, csv s, fields as, comment s
 *                   (no comment: the old row's is kept)
 *   policy.init     force b: the default rules (DHCP and DNS out),
 *                   refused (USAGE) when a policy with rules is saved
 *                   and force is not given
 * policy.add, policy.remove and policy.replace also take "apply" b and
 * "yes" b (3D): the saved policy is then applied under the same lock
 * (root).  The lockout guard runs on the policy the edit would give
 * before anything is saved, so CONFIRM still means nothing changed.
 *   apply           yes b                                    (root)
 *   firewall.start  yes b                                    (root)
 *   firewall.stop                                            (root)
 *   settings.set    keys as, values as, reset as (keys back to
 *                   the table's default)                     (root)
 *   settings.apply  yes b                                    (root)
 * An unknown op is USAGE. */
FsControlResult *fs_control_do (const FsControlActor *actor,
                                const gchar *op, GVariant *params);

/* The same, answered as one JSON object: {"op","status","ok","error",
 * "hint", and the op's own members}.  g_free. */
gchar *fs_control_do_json (const FsControlActor *actor, const gchar *op,
                           GVariant *params);
gchar *fs_control_result_json (const FsControlResult *result);

void fs_control_result_free (FsControlResult *result);

/* The actor of this process: channel `channel', uid geteuid (). */
FsControlActor fs_control_actor_self (const gchar *channel);

/* How the backend is handed a policy and its settings.  The platform's
 * fs_backend_set_context by default; a test may set its own. */
void fs_control_set_context_func (FsSettingsContextFunc func);

G_END_DECLS

#endif /* FS_CONTROL_H */
