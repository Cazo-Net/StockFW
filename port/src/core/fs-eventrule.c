/*---[ fs-eventrule.c ]--------------------------------------------------
 * Builders described in fs-eventrule.h.
 *--------------------------------------------------------------------*/
#include "core/fs-eventrule.h"

#include <string.h>

/* [ hit_direction ] */
static gboolean
hit_is_inbound (const FsHit *hit)
{
	if (hit == NULL || hit->direction == NULL)
		return FALSE;

	return g_ascii_strcasecmp (hit->direction, "In") == 0 ||
	       g_ascii_strcasecmp (hit->direction, "Inbound") == 0;
}

static gboolean
hit_is_outbound (const FsHit *hit)
{
	if (hit == NULL || hit->direction == NULL)
		return FALSE;

	return g_ascii_strcasecmp (hit->direction, "Out") == 0 ||
	       g_ascii_strcasecmp (hit->direction, "Outbound") == 0;
}

/* [ service_without_marker ]
 * The Windows backend appends " [BLOCKED]" to the service field of
 * dropped events.  A policy row must never carry that marker into
 * netsh, so it is cut off before the field is used. */
static gchar *
service_without_marker (const gchar *service)
{
	const gchar *end;

	if (service == NULL)
		return NULL;

	end = strstr (service, " [BLOCKED]");
	if (end == NULL)
		return g_strdup (service);

	return g_strndup (service, (gsize) (end - service));
}

/* [ fs_eventrule_build ] */
FsRule *
fs_eventrule_build (const FsHit *hit, FsEventRuleAction action)
{
	FsRule *rule = NULL;

	if (hit == NULL)
		return NULL;

	switch (action) {
	case FS_EVENTRULE_BLOCK_DEST:
		if (!hit_is_outbound (hit) || hit->destination == NULL ||
		    *hit->destination == '\0')
			return NULL;
		rule = fs_rule_new (FS_RULE_OUTBOUND_DENY_TO);
		rule->target  = g_strdup (hit->destination);
		rule->comment = g_strdup ("Blocked from event view");
		break;

	case FS_EVENTRULE_ALLOW_DEST:
		if (!hit_is_outbound (hit) || hit->destination == NULL ||
		    *hit->destination == '\0')
			return NULL;
		rule = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_TO);
		rule->target  = g_strdup (hit->destination);
		rule->comment = g_strdup ("Allowed from event view");
		break;

	case FS_EVENTRULE_BLOCK_SERVICE:
		if (!hit_is_outbound (hit) || hit->destination == NULL ||
		    *hit->destination == '\0' || hit->port == NULL ||
		    *hit->port == '\0')
			return NULL;
		rule = fs_rule_new (FS_RULE_OUTBOUND_DENY_SERVICE);
		rule->service = service_without_marker (hit->service);
		rule->port    = g_strdup (hit->port);
		rule->target  = g_strdup (hit->destination);
		rule->comment = g_strdup ("Blocked from event view");
		break;

	case FS_EVENTRULE_TRUST_SOURCE:
		if (!hit_is_inbound (hit) || hit->source == NULL ||
		    *hit->source == '\0')
			return NULL;
		rule = fs_rule_new (FS_RULE_INBOUND_ALLOW_FROM);
		rule->target  = g_strdup (hit->source);
		rule->comment = g_strdup ("Trusted from event view");
		break;
	}

	return rule;
}

/* [ fs_eventrule_find_trust ]
 * Removal matches on the target only, not on the whole CSV: the user's
 * existing rule may carry any comment, and an identity match against
 * our own comment would silently find nothing. */
FsRule *
fs_eventrule_find_trust (const FsPolicy *policy, const FsHit *hit)
{
	GPtrArray *rules;
	guint i;

	if (policy == NULL || hit == NULL || hit->source == NULL ||
	    *hit->source == '\0' || !hit_is_inbound (hit))
		return NULL;

	rules = policy->kinds[FS_RULE_INBOUND_ALLOW_FROM];
	if (rules == NULL)
		return NULL;

	for (i = 0; i < rules->len; i++) {
		FsRule *rule = g_ptr_array_index (rules, i);

		if (rule->target != NULL &&
		    g_ascii_strcasecmp (rule->target, hit->source) == 0)
			return rule;
	}

	return NULL;
}

/* [ fs_eventrule_untrust ] */
gboolean
fs_eventrule_untrust (FsPolicy *policy, const FsHit *hit)
{
	FsRule *existing = fs_eventrule_find_trust (policy, hit);

	if (existing == NULL)
		return FALSE;

	return fs_policy_remove_persist (policy, existing);
}
