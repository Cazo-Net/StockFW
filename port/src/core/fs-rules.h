/*---[ fs-rules.h ]-----------------------------------------------------
 * The traffic policy rule store.
 *
 * Ported from policyview.c.  Rules live in plain CSV files under the
 * rules directory, one file per rule kind, which keeps the format
 * identical to the original and human-editable.  The store itself is
 * pure data: no GTK, no OS calls, so the same rules feed an iptables
 * script on Linux and INetFwRule objects on Windows.
 *--------------------------------------------------------------------*/
#ifndef FS_RULES_H
#define FS_RULES_H

#include <glib.h>
#include "core/fs-types.h"
#include "core/fs-util.h"

G_BEGIN_DECLS

/* Target meaning "any host".  The original used the string "Anyone" in
 * its policy files; keep it so existing rules keep working. */
#define FS_TARGET_ANY "Anyone"

/* Rule kinds.  Names match the original RULETYPE_* and the CSV files. */
typedef enum
{
	FS_RULE_INBOUND_ALLOW_FROM,       /* host[,comment]              */
	FS_RULE_INBOUND_ALLOW_SERVICE,    /* service,port,target[,comment] */
	FS_RULE_INBOUND_FORWARD,          /* service,fwport,to,port[,comment] */
	FS_RULE_OUTBOUND_ALLOW_TO,        /* host[,comment]              */
	FS_RULE_OUTBOUND_ALLOW_FROM,      /* host[,comment]              */
	FS_RULE_OUTBOUND_ALLOW_SERVICE,   /* service,port,target[,comment] */
	FS_RULE_OUTBOUND_DENY_TO,         /* host[,comment]              */
	FS_RULE_OUTBOUND_DENY_FROM,       /* host[,comment]              */
	FS_RULE_OUTBOUND_DENY_SERVICE,    /* service,port,target[,comment] */
	FS_RULE_N_KINDS
} FsRuleKind;

/* One rule row.  Field meaning depends on kind; unused fields are NULL. */
typedef struct
{
	FsRuleKind kind;
	gchar      *service;    /* service name                     */
	gchar      *port;       /* port or range, as text           */
	gchar      *target;     /* source/destination host          */
	gchar      *to;         /* forward destination host         */
	gchar      *to_port;    /* forward destination port         */
	gchar      *comment;
} FsRule;

FsRule *fs_rule_new  (FsRuleKind kind);
FsRule *fs_rule_copy (const FsRule *rule);
void    fs_rule_free (FsRule *rule);

/* The kind that pairs with this one for a bi-directional rule (the
 * same host or service, the opposite direction), or FS_RULE_N_KINDS
 * when the kind has no counterpart.  Only the allow kinds pair: the
 * policy has no inbound-deny kind (inbound is default-deny already)
 * and forward rules only point one way. */
FsRuleKind fs_rule_counterpart_kind (FsRuleKind kind);

/* The counterpart of a rule: the same fields under the counterpart
 * kind, or NULL when the kind has none.  Caller frees. */
FsRule *fs_rule_counterpart (const FsRule *rule);

/* The Direction setting's own-direction entry for a kind ("Outbound
 * only" / "Inbound only"), or NULL when the kind has no counterpart
 * and the setting has nothing to choose.  The second entry of the
 * setting is always "Bi-directional". */
const gchar *fs_rule_direction_label (FsRuleKind kind);

/* [ fs_rule_coverage ]
 * Which address families a rule reaches when applied, and why, for the
 * Policy page's "Covers" column, its tooltip and the CLI.  The answer
 * follows what the generator does (fs-script.c), so the page cannot
 * claim a reach the firewall does not have:
 *   - an address or range: its own family only;
 *   - Anyone: both;
 *   - a host name: both, when names_resolved (Linux looks the name up
 *     at apply time and writes each family's addresses); otherwise
 *     FS_FAMILY_NONE, because Windows Firewall takes addresses only;
 *   - a forward: the family of its destination address; a name or a
 *     range there is left out by the generator, so NONE;
 *   - anything invalid: NONE.
 * *detail (optional) receives one sentence saying why; free it. */
FsFamily fs_rule_coverage (const FsRule *rule, gboolean names_resolved,
                           gchar **detail);

/* Column labels for a kind, in CSV order.  num_columns is an in/out:
 * on entry the capacity, on return the number written. */
const gchar * const *fs_rule_columns (FsRuleKind kind, gint *num_columns);

/* Why a rule is not one the policy may hold, in a few plain words
 * ("port \"99999\" is out of range (1-65535)"), or NULL when it is
 * fine: a host or port field that cannot name a real one (F-1), or a
 * service row with no port whose name is not a known service (the
 * generator writes nothing for such a row).  g_free. */
gchar   *fs_rule_problem (const FsRule *rule);

/* fs_rule_problem () == NULL.  Used by the policy loader and by
 * every place that writes a row. */
gboolean fs_rule_fields_sane (const FsRule *rule);

/* The host and port fields alone (F-1), without the service rule: the
 * apply gate's journal loader uses it, so a journal written by an
 * older release stays readable and a start at boot finds what was
 * live. */
gboolean fs_rule_addresses_sane (const FsRule *rule);

/* Serialise / parse.  Both return newly allocated strings. */
gchar   *fs_rule_to_csv   (const FsRule *rule);
FsRule  *fs_rule_from_csv (FsRuleKind kind, const gchar *csv);

/* The whole policy: one GPtrArray of FsRule* per kind. */
typedef struct
{
	GPtrArray *kinds[FS_RULE_N_KINDS];
} FsPolicy;

FsPolicy *fs_policy_new  (void);
void      fs_policy_free (FsPolicy *policy);
void      fs_policy_clear (FsPolicy *policy);

/* One line of a rule file that is not a rule.  file is the path
 * relative to the rules directory ("inbound/allow-service"), line
 * counts from 1, text is the line (stripped), reason says why in a few
 * words ("expected NAME, PORT, FOR (no commas)"). */
typedef struct
{
	gchar *file;
	guint  line;
	gchar *text;
	gchar *reason;
} FsPolicyProblem;

void      fs_policy_problem_free (FsPolicyProblem *problem);

/* Reads every rule file.  Missing files are not an error: an empty
 * policy is valid.  Lines that are not rules are left out, and when
 * problems is not NULL it receives a new array of FsPolicyProblem*,
 * in file then line order (empty when all is well; unref it).  Prints
 * nothing.  TRUE when at least one rule file exists. */
gboolean  fs_policy_load_report (FsPolicy *policy, GPtrArray **problems);

/* fs_policy_load_report, with each problem printed on stderr (the
 * desktop app's log) and counted in *malformed. */
gboolean  fs_policy_load  (FsPolicy *policy, gint *malformed);
gboolean  fs_policy_save  (FsPolicy *policy);

void      fs_policy_add    (FsPolicy *policy, FsRule *rule);
gboolean  fs_policy_remove (FsPolicy *policy, FsRule *rule);

/* Add / remove and persist in one step.  On a save failure the store
 * is put back the way it was and FALSE is returned, so callers never
 * have to hand-roll the rollback.  fs_policy_add_persist also refuses
 * duplicates (FALSE when the rule is already stored). */
gboolean  fs_policy_add_persist    (FsPolicy *policy, FsRule *rule);
gboolean  fs_policy_remove_persist (FsPolicy *policy, FsRule *rule);

/* Add a rule and its counterpart as one change: either both end up
 * stored and saved, or neither does.  counterpart == NULL makes this
 * fs_policy_add_persist.  A counterpart that is already stored counts
 * as success -- the intent, both directions present, then holds. */
gboolean  fs_policy_add_persist_pair (FsPolicy *policy, FsRule *rule,
                                      FsRule *counterpart);

/* TRUE when a rule identical to the one passed in is already stored.
 * Identity is the CSV form, the same way fs_policy_remove matches. */
gboolean  fs_policy_contains (const FsPolicy *policy, const FsRule *rule);

void      fs_policy_install_defaults (FsPolicy *policy);

/* Convenience: how many rules of a kind. */
guint fs_policy_count (const FsPolicy *policy, FsRuleKind kind);

/* The rules directory a file for this kind lives in, relative to the
 * rules dir.  Free with g_free. */
gchar *fs_rule_kind_path (FsRuleKind kind);

/* ---- PR 3: one writer, and no row that changes shape on disk ------- */

GQuark fs_rules_error_quark (void);
#define FS_RULES_ERROR (fs_rules_error_quark ())
typedef enum
{
	FS_RULES_ERR_INVALID,     /* the row cannot be written as it is   */
	FS_RULES_ERR_NOT_FOUND,   /* the row to change is not there       */
	FS_RULES_ERR_DUPLICATE,   /* the change would store a row twice   */
	FS_RULES_ERR_SAVE,        /* the files could not be written       */
	FS_RULES_ERR_LOCK         /* the policy lock could not be taken   */
} FsRulesError;

/* [ fs_rule_validate ]
 * FALSE (with FS_RULES_ERR_INVALID and the field in the message) when
 * a field holds a comma or a line break: the rule files are CSV with no
 * quoting, so the row would read back as other fields or other rows
 * (T15); also when the first field starts with '#', which would read
 * back as a comment line.  fs_policy_save refuses a policy holding such a row and writes
 * nothing; so does the apply journal.  Every writer of fs_rule_to_csv
 * output calls it. */
gboolean  fs_rule_validate (const FsRule *rule, GError **error);

/* [ fs_policy_lock ]
 * One writer of the policy at a time, across processes.  Linux: flock
 * on <run>/apply.lock, then <rules_dir>/.lock (always in that order;
 * <run> is /run/stockfw, created 0750 when absent, or
 * $STOCKFW_RUN_DIR).  Windows: within the process only.  Blocks until
 * both are held.  Re-entrant within one process; fs_policy_save and the
 * persist calls take it themselves, and a caller that reads, changes
 * and saves (fs_control) holds it across all three, so a write made by
 * another process in between is never lost.  An account that may not
 * create a lock file (not root) goes on without it: it cannot write the
 * files either.  NULL with *error when root cannot take it. */
typedef struct _FsPolicyLock FsPolicyLock;
FsPolicyLock *fs_policy_lock   (GError **error);
void          fs_policy_unlock (FsPolicyLock *lock);
/* "/run/stockfw", or $STOCKFW_RUN_DIR.  g_free. */
gchar        *fs_policy_run_dir (void);

/* [ fs_policy_replace_persist ]
 * Edit in place (E4): the row identical (CSV) to `old' becomes a copy
 * of `rule', at the same position and number, and the policy is saved
 * once.  Refused, nothing changed: a different kind, a row that fails
 * fs_rule_validate or fs_rule_problem (INVALID), `old' not there
 * (NOT_FOUND), `rule' already stored as another row (DUPLICATE).  On a
 * save failure the old row is put back (SAVE). */
gboolean  fs_policy_replace_persist (FsPolicy *policy, const FsRule *old,
                                     const FsRule *rule, GError **error);
/* The same for row `nth' (from 0) of old's kind, which must be
 * identical to `old': `policy edit KIND:N' changes row N even when an
 * identical row comes before it.  nth < 0: the first identical row. */
gboolean  fs_policy_replace_nth_persist (FsPolicy *policy, gint nth,
                                         const FsRule *old,
                                         const FsRule *rule, GError **error);

G_END_DECLS

#endif /* FS_RULES_H */