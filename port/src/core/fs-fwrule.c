/*---[ fs-fwrule.c ]----------------------------------------------------
 * Backend-neutral firewall rule translation.
 *--------------------------------------------------------------------*/

#include "core/fs-fwrule.h"
#include "core/fs-util.h"
#include "core/fs-service.h"
#include "core/fs-i18n.h"

#include <stdlib.h>
#include <string.h>

/* Services that are TCP-only.  Everything not listed here falls back to
 * FS_PROTO_ANY, which on Windows means both TCP and UDP and on Linux
 * means no -p match. */
static const gchar * const tcp_only_services[] = {
	"BitTorrent", "FTP", "HTTP", "HTTPS", "IMAP", "NNTP", "POP3",
	"SMTP", "SSH", "Telnet", "Xwindows", "NTP", NULL
};

FsFwRule *
fs_fwrule_new (void)
{
	return g_new0 (FsFwRule, 1);
}

void
fs_fwrule_free (FsFwRule *rule)
{
	if (rule == NULL)
		return;

	g_free (rule->name);
	g_free (rule->local_address);
	g_free (rule->remote_address);
	g_free (rule->forward_address);

	g_free (rule);
}

void
fs_fwrule_list_free (GList *rules)
{
	g_list_free_full (rules, (GDestroyNotify) fs_fwrule_free);
}

/* [ field_is_number ]
 * strtol() is too forgiving on its own: it accepts "80abc" as 80 and
 * "0x50" as 0.  Require the whole field to be digits. */
static gboolean
field_is_number (const gchar *field)
{
	if (field == NULL || *field == '\0')
		return FALSE;

	for (const gchar *p = field; *p != '\0'; p++) {
		if (!g_ascii_isdigit (*p))
			return FALSE;
	}

	return TRUE;
}

gboolean
fs_fwrule_parse_range (const gchar *text, gint *first, gint *last)
{
	const gchar *colon;
	gint a = 0;
	gint b = 0;

	if (first != NULL)
		*first = 0;
	if (last != NULL)
		*last = 0;

	if (text == NULL || *text == '\0')
		return FALSE;

	colon = strchr (text, ':');

	if (colon == NULL) {
		if (!field_is_number (text))
			return FALSE;

		a = (gint) strtol (text, NULL, 10);

		if (a < 0 || a > 65535)
			return FALSE;

		if (first != NULL) *first = a;
		if (last != NULL)  *last = a;

		return TRUE;
	}

	if (colon == text || *(colon + 1) == '\0')
		return FALSE;

	/* Each half must be digits on its own; "1024:65535x" is not a
	 * range, and neither is "abc:80". */
	{
		gchar *lower = g_strndup (text, (gsize) (colon - text));
		gboolean lower_ok = field_is_number (lower);
		gboolean upper_ok = field_is_number (colon + 1);

		g_free (lower);

		if (!lower_ok || !upper_ok)
			return FALSE;
	}

	a = (gint) strtol (text, NULL, 10);
	b = (gint) strtol (colon + 1, NULL, 10);

	if (a < 0 || b > 65535 || a > b)
		return FALSE;

	if (first != NULL) *first = a;
	if (last != NULL)  *last = b;

	return TRUE;
}

gboolean
fs_fwrule_parse_port (const gchar *text, gint *port)
{
	gint first = 0, last = 0;

	if (port != NULL)
		*port = 0;

	/* Empty means "any port". */
	if (text == NULL || *text == '\0')
		return TRUE;

	if (!fs_fwrule_parse_range (text, &first, &last))
		return FALSE;

	if (first != last)
		return FALSE;

	if (port != NULL)
		*port = first;

	return TRUE;
}

FsRuleProtocol
fs_fwrule_protocol_for_service (const gchar *service)
{
	if (service == NULL)
		return FS_PROTO_ANY;

	for (guint i = 0; tcp_only_services[i] != NULL; i++) {
		if (g_ascii_strcasecmp (service, tcp_only_services[i]) == 0)
			return FS_PROTO_TCP;
	}

	return FS_PROTO_ANY;
}

gchar *
fs_fwrule_default_name (FsRuleDirection direction, FsRuleAction action,
                        const gchar *service, const gchar *address)
{
	const gchar *verb = (action == FS_ACTION_ALLOW) ? _("Allow")
	                                                : _("Block");
	const gchar *dir = (direction == FS_DIR_INBOUND) ? _("inbound")
	                                                  : _("outbound");

	/* F-3: control characters must not reach the rule name, which is
	 * textual output both in netsh and in every listing of it. */
	gchar *clean_service = fs_util_strip_controls (service);
	gchar *clean_address = fs_util_strip_controls (address);
	gchar *name;

	service = clean_service;
	address = clean_address;

	if (service != NULL && *service != '\0') {
		if (address != NULL && *address != '\0' &&
		    !fs_util_target_is_anyone (address))
			name = g_strdup_printf ("StockFW: %s %s (%s, %s)",
			                        verb, service, dir, address);
		else
			name = g_strdup_printf ("StockFW: %s %s (%s)",
			                        verb, service, dir);
	} else if (address != NULL && *address != '\0' &&
	           !fs_util_target_is_anyone (address)) {
		name = g_strdup_printf ("StockFW: %s %s (%s)", verb, dir,
		                        address);
	} else {
		name = g_strdup_printf ("StockFW: %s %s", verb, dir);
	}

	g_free (clean_service);
	g_free (clean_address);

	return name;
}

/* [ address_or_null ]
 * Normalises a policy target into a concrete address, or NULL for any. */
static gchar *
address_or_null (const gchar *target)
{
	if (fs_util_target_is_anyone (target))
		return NULL;

	if (target == NULL || *target == '\0')
		return NULL;

	return g_strdup (target);
}

/* [ append_service_rows ]
 * Expands every service row of one kind. */
static guint
append_service_rows (GList **out, GPtrArray *rows,
                     FsRuleDirection direction, FsRuleAction action)
{
	guint count = 0;

	for (guint i = 0; i < rows->len; i++) {
		FsRule *row = g_ptr_array_index (rows, i);
		gint first = 0, last = 0;
		gboolean have_range;

		have_range = fs_fwrule_parse_range (row->port, &first, &last);

		/* An unparseable port means "any" rather than dropping the
		 * rule silently; the user probably meant a wildcard. */
		if (!have_range)
			first = last = 0;

		/* A range is not representable as a single port on Windows,
		 * so the rule is opened across the range instead: two rules,
		 * or one any-port rule when the range is unusable. */
		if (have_range && first != last && last - first > 1024) {
			FsFwRule *rule = fs_fwrule_new ();

			rule->direction = direction;
			rule->action = action;
			rule->protocol = fs_fwrule_protocol_for_service (row->service);
			rule->local_port = 0;
			rule->remote_address = address_or_null (row->target);
			rule->name = fs_fwrule_default_name (direction, action,
			                                     row->service, row->target);

			*out = g_list_append (*out, rule);
			count++;
			continue;
		}

		for (gint port = first; port <= last; port++) {
			FsFwRule *rule = fs_fwrule_new ();

			rule->direction = direction;
			rule->action = action;
			rule->protocol = fs_fwrule_protocol_for_service (row->service);
			rule->local_port = port;
			rule->remote_address = address_or_null (row->target);
			rule->name = fs_fwrule_default_name (direction, action,
			                                     row->service, row->target);

			*out = g_list_append (*out, rule);
			count++;
		}
	}

	return count;
}

/* [ append_host_rows ]
 * Expands every host row of one kind. */
static guint
append_host_rows (GList **out, GPtrArray *rows,
                  FsRuleDirection direction, FsRuleAction action)
{
	guint count = 0;

	for (guint i = 0; i < rows->len; i++) {
		FsRule *row = g_ptr_array_index (rows, i);
		gchar *address = address_or_null (row->target);
		FsFwRule *rule;

		/* A host rule with no host constrains nothing. */
		if (address == NULL)
			continue;

		rule = fs_fwrule_new ();
		rule->direction = direction;
		rule->action = action;
		rule->protocol = FS_PROTO_ANY;
		rule->remote_address = address;
		rule->name = fs_fwrule_default_name (direction, action,
		                                     NULL, row->target);

		*out = g_list_append (*out, rule);
		count++;
	}

	return count;
}

/* [ append_forward_rows ]
 * Port forwards: expose remote_port, deliver to forward_address:to_port. */
static guint
append_forward_rows (GList **out, GPtrArray *rows)
{
	guint count = 0;

	for (guint i = 0; i < rows->len; i++) {
		FsRule *row = g_ptr_array_index (rows, i);
		FsFwRule *rule;
		gint first = 0, last = 0;

		if (row->to == NULL || *row->to == '\0' ||
		    row->to_port == NULL || *row->to_port == '\0')
			continue;

		if (!fs_fwrule_parse_range (row->port, &first, &last))
			first = last = 0;

		for (gint port = first; port <= last; port++) {
			rule = fs_fwrule_new ();
			rule->direction = FS_DIR_INBOUND;
			rule->action = FS_ACTION_ALLOW;
			rule->protocol = fs_fwrule_protocol_for_service (row->service);
			rule->local_port = port;
			rule->forward = TRUE;
			rule->forward_address = g_strdup (row->to);
			rule->remote_address = NULL;
			rule->name = fs_fwrule_default_name (FS_DIR_INBOUND,
			                                     FS_ACTION_ALLOW,
			                                     row->service, NULL);

			*out = g_list_append (*out, rule);
			count++;
		}
	}

	return count;
}

guint
fs_fwrule_expand (const FsPolicy *policy, GList **out)
{
	guint count = 0;

	if (policy == NULL || out == NULL)
		return 0;

	/* Inbound allows. */
	count += append_host_rows (out,
		policy->kinds[FS_RULE_INBOUND_ALLOW_FROM],
		FS_DIR_INBOUND, FS_ACTION_ALLOW);
	count += append_service_rows (out,
		policy->kinds[FS_RULE_INBOUND_ALLOW_SERVICE],
		FS_DIR_INBOUND, FS_ACTION_ALLOW);
	count += append_forward_rows (out,
		policy->kinds[FS_RULE_INBOUND_FORWARD]);

	/* Outbound denies first: a block has to be seen before the allows. */
	count += append_host_rows (out,
		policy->kinds[FS_RULE_OUTBOUND_DENY_TO],
		FS_DIR_OUTBOUND, FS_ACTION_BLOCK);
	count += append_host_rows (out,
		policy->kinds[FS_RULE_OUTBOUND_DENY_FROM],
		FS_DIR_OUTBOUND, FS_ACTION_BLOCK);
	count += append_service_rows (out,
		policy->kinds[FS_RULE_OUTBOUND_DENY_SERVICE],
		FS_DIR_OUTBOUND, FS_ACTION_BLOCK);

	/* Outbound allows. */
	count += append_host_rows (out,
		policy->kinds[FS_RULE_OUTBOUND_ALLOW_TO],
		FS_DIR_OUTBOUND, FS_ACTION_ALLOW);
	count += append_host_rows (out,
		policy->kinds[FS_RULE_OUTBOUND_ALLOW_FROM],
		FS_DIR_OUTBOUND, FS_ACTION_ALLOW);
	count += append_service_rows (out,
		policy->kinds[FS_RULE_OUTBOUND_ALLOW_SERVICE],
		FS_DIR_OUTBOUND, FS_ACTION_ALLOW);

	return count;
}

GList *
fs_fwrule_from_policy (const FsPolicy *policy)
{
	GList *out = NULL;

	fs_fwrule_expand (policy, &out);

	return out;
}

/* [ fs_fwrule_equal ]
 * Full-field identity of two concrete rules.  The name alone is not
 * identity: "service ssh, port 22" and "service ssh, port 2222" both
 * translate to "StockFW: Allow ssh (outbound)" yet differ where it
 * counts, and the narrow apply has to tell them apart. */
gboolean
fs_fwrule_equal (const FsFwRule *a, const FsFwRule *b)
{
	if (a == b)
		return TRUE;

	if (a == NULL || b == NULL)
		return FALSE;

	if (a->direction != b->direction ||
	    a->action != b->action ||
	    a->protocol != b->protocol ||
	    a->local_port != b->local_port ||
	    a->remote_port != b->remote_port ||
	    a->forward != b->forward)
		return FALSE;

	return (g_strcmp0 (a->name, b->name) == 0 &&
	        g_strcmp0 (a->local_address, b->local_address) == 0 &&
	        g_strcmp0 (a->remote_address, b->remote_address) == 0 &&
	        g_strcmp0 (a->forward_address, b->forward_address) == 0);
}