/*---[ fs-fwrule.h ]----------------------------------------------------
 * Backend-neutral firewall rule.
 *
 * The FsPolicy rows are written for humans (CSV with service names).
 * Neither Windows nor netfilter can consume those directly, so this is
 * the translation layer: policy rows in, concrete rules out.  A rule is
 * fully resolved here -- no service names, no "Anyone" placeholders --
 * so each backend only has to map fields onto its own API.
 *
 * The Windows backend is the consumer (netsh); the Linux backend
 * writes iptables scripts from the policy rows itself (fs-script.c).
 * The What-If Simulator and the Policy page read these rules too.
 *--------------------------------------------------------------------*/
#ifndef FS_FWRULE_H
#define FS_FWRULE_H

#include <glib.h>
#include "core/fs-types.h"
#include "core/fs-rules.h"

G_BEGIN_DECLS

/* The translation's version.  It goes up whenever the same policy row
 * starts compiling to different firewall rules, and the applied-policy
 * journal records the version that wrote the live rules.  A journal
 * from an older translation describes rules this code would not
 * write, so the apply gate replaces the whole set instead of trusting
 * a narrow delta computed from it (fs-apply.c).
 *   1: 1.0.6 and earlier -- single int ports, protocol "any" for most
 *      services, outbound service ports on the local side.
 *   2: port specs, a protocol for every ported rule, outbound
 *      service ports on the remote side. */
#define FS_FWRULE_TRANSLATION 2

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

/* A single concrete rule.
 *
 * Ports are SPECS in netsh syntax -- "22", "67-68", "137-139,445" --
 * already validated and normalised by fs_fwrule_port_spec(); NULL
 * means any port.  A rule that names a port is TCP or UDP, never
 * FS_PROTO_ANY: netsh refuses ports with protocol=any, and dropping
 * the port instead is how 1.0.6 turned "allow DNS" into "allow
 * everything".  fs_fwrule_is_sound() checks it. */
typedef struct
{
	gchar          *name;          /* shown in the Windows firewall UI */
	FsRuleDirection direction;
	FsRuleAction   action;
	FsRuleProtocol protocol;

	/* Local side: this computer.  Inbound service rows and port
	 * forwards name their ports here. */
	gchar          *local_ports;   /* NULL = any */
	gchar          *local_address; /* NULL = any */

	/* Remote side: the other end.  Outbound service rows name their
	 * ports here -- an outbound connection's service port is the
	 * port it connects TO. */
	gchar          *remote_ports;  /* NULL = any */
	gchar          *remote_address;/* NULL = any */

	/* Port forwarding: local_ports on us -> forward_address. */
	gboolean        forward;
	gchar          *forward_address;

	/* The program this rule is bound to (Windows: the full executable
	 * path, e.g. C:\Program Files\App\app.exe).  NULL means the rule
	 * applies to every program; set means this firewall rule matches
	 * only this program. */
	gchar          *program;
} FsFwRule;

FsFwRule *fs_fwrule_new  (void);
void      fs_fwrule_free (FsFwRule *rule);
void      fs_fwrule_list_free (GList *rules);

/* Port text from a policy row as a netsh port spec, or NULL when it
 * is not one.  Accepted: ports 1-65535, ranges written "a-b" or "a:b"
 * (a <= b), and lists of those separated by commas and/or spaces
 * ("137-139 445", "1234,1243").  The result joins the elements with
 * ',' and writes ranges with '-' ("137-139,445"); "a-a" becomes "a"
 * and a repeated element is kept once.  Empty or NULL text is not a
 * spec either: callers decide what a missing port means.  Caller
 * frees. */
gchar *fs_fwrule_port_spec (const gchar *text);

/* TRUE when port lies in one of the spec's ports or ranges.  A NULL
 * spec covers every port. */
gboolean fs_fwrule_port_spec_covers (const gchar *spec, guint port);

/* TRUE when a rule can be handed to a firewall as it stands: a rule
 * naming a port is TCP or UDP, and every port spec is in the
 * normalised form fs_fwrule_port_spec() produces. */
gboolean fs_fwrule_is_sound (const FsFwRule *rule);

/* Translates one policy row kind by kind into concrete rules,
 * appending them to out.  Returns the number appended.
 *
 * Service rows (and forwards) become one rule per protocol the
 * service uses, from the service table (fs-service.h): "SSH" is TCP,
 * "DHCP" UDP, "DNS" both; any other name gets a TCP and a UDP rule,
 * except the pseudo-services "TCP" and "UDP", which mean exactly that
 * protocol.  When a row yields both, the names end in " (TCP)" and
 * " (UDP)" so each rule can be deleted on its own.  A row whose port
 * text is empty takes the service's own ports; a row whose port text
 * does not parse, or an unknown service or a bare "TCP"/"UDP" with no
 * port, is REFUSED, never widened to "any port": no rule is appended,
 * and when refused is not NULL one sentence saying why is added to it
 * (gchar*, owned by the array, which must free its elements with
 * g_free). */
guint fs_fwrule_expand_checked (const FsPolicy *policy, GList **out,
                                GPtrArray *refused);

/* The refusals of the policy's BLOCK rows alone, joined by newlines,
 * or NULL when every block row compiles.  A refused allow only leaves
 * a hole closed; a refused block is a block missing, so a backend
 * that replaces its whole rule set must not start when this is not
 * NULL -- the Linux generator refuses the whole script for a deny
 * with a bad port in the same way (fs-script.c).  Caller frees. */
gchar *fs_fwrule_block_refusals (const FsPolicy *policy);

/* fs_fwrule_expand_checked() without the refusals. */
guint fs_fwrule_expand (const FsPolicy *policy, GList **out);

/* Translate the whole policy into concrete rules (a list of
 * FsFwRule*, caller frees with fs_fwrule_list_free).  Refused rows are
 * left out; use fs_fwrule_from_policy_checked() wherever a refusal has
 * to reach the user. */
GList *fs_fwrule_from_policy (const FsPolicy *policy);

/* The same, with *refused (when not NULL) set to a new array of the
 * refusal sentences -- empty when every row compiled.  Free it with
 * g_ptr_array_unref. */
GList *fs_fwrule_from_policy_checked (const FsPolicy *policy,
                                      GPtrArray **refused);

/* TRUE when two concrete rules match on every resolved field.  Used by
 * the narrow apply to tell "unchanged" from "same name, different
 * port". */
gboolean fs_fwrule_equal (const FsFwRule *a, const FsFwRule *b);

/* A name for a rule, e.g. "StockFW: allow SSH".  Caller frees. */
gchar *fs_fwrule_default_name (FsRuleDirection direction,
                               FsRuleAction action,
                               const gchar *service,
                               const gchar *address);

/* A rule name as netsh is given it: netsh rejects ':', parentheses,
 * '/' and ',' in names, so each becomes '-' ("StockFW: Allow SSH
 * (inbound)" -> "StockFW- Allow SSH -inbound-"), and a double quote,
 * which would end the name on netsh's command line, becomes '\''.
 * The backend creates, lists and deletes rules under this spelling.
 * Caller frees. */
gchar *fs_fwrule_netsh_name (const gchar *name);

/* The argv that creates one rule with "netsh advfirewall firewall add
 * rule", NULL-terminated, for a process spawned with no shell: no
 * argument carries quote characters, "name=..." is one element.
 *   netsh.exe advfirewall firewall add rule name=<netsh name>
 *   profile=any dir=in|out action=allow|block protocol=TCP|UDP|any
 *   enable=yes [localport=<spec>] [remoteport=<spec>] [remoteip=<addr>]
 * NULL when the rule is not sound (fs_fwrule_is_sound): a ported rule
 * must never reach netsh as protocol=any.  Free with g_strfreev. */
GStrv fs_fwrule_netsh_args (const FsFwRule *rule);

G_END_DECLS

#endif /* FS_FWRULE_H */
