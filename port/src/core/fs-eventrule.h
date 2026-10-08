/*---[ fs-eventrule.h ]--------------------------------------------------
 * One-click rules from an event row (the "Event -> Rule" path).
 *
 * A firewall hit already names the remote host, the service and the
 * direction; this module turns those fields into a concrete policy row
 * so the Events page can offer Block/Allow/Trust without inventing
 * policy syntax in UI code.  Pure data -- no GTK, no OS calls -- so the
 * builders are covered by the core test suite directly.
 *--------------------------------------------------------------------*/
#ifndef FS_EVENTRULE_H
#define FS_EVENTRULE_H

#include <glib.h>
#include "core/fs-types.h"
#include "core/fs-rules.h"

G_BEGIN_DECLS

typedef enum
{
	/* Outbound event: deny further traffic to the event's destination. */
	FS_EVENTRULE_BLOCK_DEST,
	/* Outbound event: allow traffic to the event's destination. */
	FS_EVENTRULE_ALLOW_DEST,
	/* Outbound event: deny this service/port to the destination. */
	FS_EVENTRULE_BLOCK_SERVICE,
	/* Inbound event: add an inbound allow for the event's source. */
	FS_EVENTRULE_TRUST_SOURCE
} FsEventRuleAction;

/* Build the policy row for an action, or NULL when the action does not
 * fit the hit (wrong direction, missing fields).  The caller owns the
 * returned rule (fs_rule_free).  The "[BLOCKED]" marker the Windows
 * parser appends to the service field is stripped before use. */
FsRule *fs_eventrule_build (const FsHit *hit, FsEventRuleAction action);

/* The stored inbound-allow rule an UNTRUST action would remove: the
 * first FS_RULE_INBOUND_ALLOW_FROM whose target matches the hit's
 * source (case-insensitive), or NULL when the source is not trusted.
 * The pointer is borrowed from the policy. */
FsRule *fs_eventrule_find_trust (const FsPolicy *policy,
                                 const FsHit *hit);

/* Remove the trust rule for this hit and persist the change; on a save
 * failure the rule is put back and FALSE is returned.  FALSE also when
 * no matching rule exists. */
gboolean fs_eventrule_untrust (FsPolicy *policy, const FsHit *hit);

G_END_DECLS

#endif /* FS_EVENTRULE_H */
