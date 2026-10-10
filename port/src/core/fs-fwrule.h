/*---[ fs-fwrule.h ]----------------------------------------------------
 * Backend-neutral firewall rule.
 *
 * The FsPolicy rows are written for humans (CSV with service names).
 * Neither Windows nor netfilter can consume those directly, so this is
 * the translation layer: policy rows in, concrete rules out.  A rule is
 * fully resolved here -- no service names, no "Anyone" placeholders --
 * so each backend only has to map fields onto its own API.
 *--------------------------------------------------------------------*/
#ifndef FS_FWRULE_H
#define FS_FWRULE_H

#include <glib.h>
#include "core/fs-types.h"
#include "core/fs-rules.h"

G_BEGIN_DECLS

typedef enum
{
	FS_DIR_INBOUND,
	FS_DIR_OUTBOUND
} FsRuleDirection;

typedef enum
{
	FS_ACTION_ALLOW,
	FS_ACTION_BLOCK
} FsRuleAction;

typedef enum
{
	FS_PROTO_ANY,
	FS_PROTO_TCP,
	FS_PROTO_UDP
} FsRuleProtocol;

/* A single concrete rule. */
typedef struct
{
	gchar          *name;          /* shown in the Windows firewall UI */
	FsRuleDirection direction;
	FsRuleAction   action;
	FsRuleProtocol protocol;

	/* Local side. */
	gint            local_port;    /* 0 = any */
	gchar          *local_address; /* NULL = any */

	/* Remote side. */
	gint            remote_port;   /* 0 = any */
	gchar          *remote_address;/* NULL = any */

	/* Port forwarding: remote_port on us -> local_port on
	 * local_address.  Unused when 0. */
	gboolean        forward;
	gchar          *forward_address;
} FsFwRule;

FsFwRule *fs_fwrule_new  (void);
void      fs_fwrule_free (FsFwRule *rule);
void      fs_fwrule_list_free (GList *rules);

/* Ports accepted for a policy row: "22", "1024:65535", or empty for
 * any port.  Returns FALSE when the text is not a valid port spec. */
gboolean fs_fwrule_parse_port (const gchar *text, gint *port);

/* Splits "1024:65535" into 1024 and 65535.  A single port yields
 * first == last. */
gboolean fs_fwrule_parse_range (const gchar *text, gint *first, gint *last);

/* The protocol implied by a service name.  Known services that are
 * TCP only (SSH, HTTP, ...) give FS_PROTO_TCP; unknown ones give
 * FS_PROTO_ANY so the port still opens. */
FsRuleProtocol fs_fwrule_protocol_for_service (const gchar *service);

/* Translates one policy row into concrete rules, appending them to out.
 * Returns the number appended.
 *
 * Inbound service rules whose source is a specific host become
 * address-scoped rules.  Port forwards become forward rules.  A single
 * row can produce several rules when its port field is a range. */
guint fs_fwrule_expand (const FsPolicy *policy, GList **out);

/* Convenience: the whole policy as a list of concrete rules.  Caller
 * frees with fs_fwrule_list_free(). */
/* Translate the whole policy into concrete rules (a list of
 * FsFwRule*, caller frees with fs_fwrule_list_free). */
GList *fs_fwrule_from_policy (const FsPolicy *policy);

/* TRUE when two concrete rules match on every resolved field.  Used by
 * the narrow apply to tell "unchanged" from "same name, different
 * port". */
gboolean fs_fwrule_equal (const FsFwRule *a, const FsFwRule *b);

/* A name for a rule, e.g. "StockFW: allow SSH".  Caller frees. */
gchar *fs_fwrule_default_name (FsRuleDirection direction,
                               FsRuleAction action,
                               const gchar *service,
                               const gchar *address);

G_END_DECLS

#endif /* FS_FWRULE_H */