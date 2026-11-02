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

/* TRUE when a rule's host and port fields could name real ones (F-1).
 * Used by the policy loader and by the apply gate's journal loader. */
gboolean fs_rule_fields_sane (const FsRule *rule);

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

/* Reads every rule file.  Missing files are not an error: an empty
 * policy is valid.  Malformed lines are counted in *malformed. */
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

G_END_DECLS

#endif /* FS_RULES_H */