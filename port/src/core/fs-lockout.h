/*---[ fs-lockout.h ]----------------------------------------------------
 * The lockout guard: would this policy cut the SSH session the admin
 * is using?
 *
 * An apply over SSH can block the very connection it came in on, and
 * the admin finds out when the next keystroke hangs.  Before a policy
 * goes live, every SSH peer of this computer is asked about, as a NEW
 * connection (what a reconnect would be), against the policy and the
 * firewall settings about to be applied: "inbound tcp PORT from PEER".
 * The established session itself may well survive the apply (the
 * ESTABLISHED rule), but the next login would not.
 *
 * Peers come from fs_hostnet_read()->sessions: $SSH_CONNECTION when it
 * is set, and the established connections to the SSH port in the
 * kernel's tables, so it works under sudo, which drops the variable.
 * Ports are sshd's listening ports plus the server port that
 * $SSH_CONNECTION names.
 *
 * Pure core: the front ends (the CLI today, the daemon later) decide
 * what to do with the answer -- a prompt, --yes, or a refusal.
 *--------------------------------------------------------------------*/
#ifndef FS_LOCKOUT_H
#define FS_LOCKOUT_H

#include <glib.h>
#include "core/fs-iprange.h"
#include "core/fs-rules.h"
#include "core/fs-script.h"
#include "core/fs-whatif.h"

G_BEGIN_DECLS

/* One peer asked about on one port. */
typedef struct
{
	gchar          *peer;          /* the address, as text             */
	guint           port;          /* the local port it connects to    */
	FsWhatIfVerdict verdict;       /* ALLOWED, BLOCKED or DEPENDS      */
	gchar          *reason;        /* the What-If's reason, short      */
	gchar          *rule;          /* the deciding rule's name, or NULL */
	gint            policy_kind;   /* FsRuleKind of the deciding row,
	                                * or -1 when no policy row decided */
	gint            policy_index;  /* 0-based row, or -1               */
} FsLockoutPair;

typedef struct
{
	gboolean         checked;      /* at least one peer and one port   */
	const gchar     *why_not;      /* when not checked: "not an SSH
	                                * session" (static)               */
	GPtrArray       *pairs;        /* FsLockoutPair*, every pair asked */
	FsWhatIfVerdict  verdict;      /* the worst: BLOCKED, then DEPENDS,
	                                * then ALLOWED                     */
	const FsLockoutPair *worst;    /* the first pair with that verdict,
	                                * or NULL when nothing was checked */
} FsLockoutReport;

/* At most this many peers are asked about (a busy jump host). */
#define FS_LOCKOUT_MAX_PEERS 64

/* Ask about every peer in `peers' on every port in `ports' (guint16),
 * against `policy' and `settings' (NULL: fresh-install defaults) as if
 * the firewall ran them.  Either set may be NULL or empty: the report
 * then says it was not checked.  Never NULL. */
FsLockoutReport *fs_lockout_check (const FsPolicy *policy,
                                   const FsSettings *settings,
                                   const FsRangeSet *peers,
                                   const GArray *ports);

/* TRUE when the report found a pair the policy would cut (BLOCKED) or
 * might cut (DEPENDS). */
gboolean fs_lockout_report_cuts (const FsLockoutReport *report);

void fs_lockout_report_free (FsLockoutReport *report);

/* This computer's SSH peers and ports, as fs_lockout_check takes them:
 * peers from fs_hostnet_read()->sessions; ports from
 * fs_hostnet_ssh_listen_ports() (sshd's listening ports; 22 when that
 * cannot be read) plus the server port of $SSH_CONNECTION.  Free with
 * fs_range_set_free and g_array_unref. */
void fs_lockout_sessions (FsRangeSet **peers, GArray **ports);

/* The server port of an $SSH_CONNECTION value ("client cport server
 * sport"), or 0 when there is none or it is not a port. */
guint fs_lockout_env_port (const gchar *ssh_connection);

G_END_DECLS

#endif /* FS_LOCKOUT_H */
