/*---[ fs-fwrule.c ]----------------------------------------------------
 * Backend-neutral firewall rule translation.
 *
 * Before 1.0.7 this file is where Windows lost the policy: every
 * service outside a short TCP list compiled to protocol "any", the
 * netsh call then had to drop the port (netsh refuses ports with
 * protocol=any), and "Allow DNS (inbound)" opened every inbound port;
 * port lists and '-' ranges ("67-68", the default DHCP row) did not
 * parse and became "any port"; and outbound service ports sat on the
 * local side, where an outbound connection's service port never is.
 * The Linux generator (fs-script.c) always wrote a tcp and a udp rule
 * on the destination port of each service row; this translation now
 * says the same thing in netsh's terms, with the protocols taken from
 * the service table instead of assumed.
 *--------------------------------------------------------------------*/

#include "core/fs-fwrule.h"
#include "core/fs-util.h"
#include "core/fs-service.h"
#include "core/fs-i18n.h"

#include <stdlib.h>
#include <string.h>

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
	g_free (rule->local_ports);
	g_free (rule->local_address);
	g_free (rule->remote_ports);
	g_free (rule->remote_address);
	g_free (rule->forward_address);

	g_free (rule);
}

void
fs_fwrule_list_free (GList *rules)
{
	g_list_free_full (rules, (GDestroyNotify) fs_fwrule_free);
}

/* [ parse_port_number ]
 * strtol() is too forgiving on its own: it accepts "80abc" as 80,
 * " 80" and "+80" as 80, and "0x50" as 0.  Require the whole field to
 * be at most five digits, then the value to be a real port: port 0
 * is not one a firewall rule can name. */
static gboolean
parse_port_number (const gchar *field, gsize len, guint *port)
{
	guint value = 0;

	if (field == NULL || len == 0 || len > 5)
		return FALSE;

	for (gsize i = 0; i < len; i++) {
		if (!g_ascii_isdigit (field[i]))
			return FALSE;
		value = value * 10 + (guint) (field[i] - '0');
	}

	if (value < 1 || value > 65535)
		return FALSE;

	*port = value;
	return TRUE;
}

/* [ parse_port_element ]
 * One element of a port list: "80", "67-68" or "67:68".  One
 * separator at most, so "1-2-3" and "1:2-3" are refused. */
static gboolean
parse_port_element (const gchar *element, guint *first, guint *last)
{
	const gchar *sep = strpbrk (element, "-:");
	gsize len = strlen (element);

	if (sep == NULL) {
		if (!parse_port_number (element, len, first))
			return FALSE;
		*last = *first;
		return TRUE;
	}

	if (!parse_port_number (element, (gsize) (sep - element), first) ||
	    !parse_port_number (sep + 1, strlen (sep + 1), last))
		return FALSE;

	return *first <= *last;
}

/* [ fs_fwrule_port_spec ] -- see fs-fwrule.h. */
gchar *
fs_fwrule_port_spec (const gchar *text)
{
	gchar **tokens;
	GString *out;
	GHashTable *seen;
	gboolean ok = TRUE;

	if (text == NULL || *text == '\0')
		return NULL;

	/* Commas and spaces both separate, in any mix: the service table
	 * writes "137-139 445" and "1234,1243", and people write
	 * "80, 443". */
	tokens = g_strsplit_set (text, " ,", -1);
	out = g_string_new (NULL);
	/* A set, not a list scanned per element: port text may list
	 * thousands of ports, and a scan per element made that seconds of
	 * quadratic work in every compile (apply, simulator, Policy
	 * page).  The set owns the element strings it holds. */
	seen = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

	for (guint i = 0; tokens[i] != NULL && ok; i++) {
		guint first = 0, last = 0;
		gchar *element;

		if (*tokens[i] == '\0')
			continue;

		if (!parse_port_element (tokens[i], &first, &last)) {
			ok = FALSE;
			break;
		}

		element = (first == last)
			? g_strdup_printf ("%u", first)
			: g_strdup_printf ("%u-%u", first, last);

		if (g_hash_table_contains (seen, element)) {
			g_free (element);
			continue;
		}

		if (out->len > 0)
			g_string_append_c (out, ',');
		g_string_append (out, element);
		g_hash_table_add (seen, element);
	}

	g_strfreev (tokens);
	g_hash_table_unref (seen);

	/* Separators alone (",", "  ") name no port at all. */
	if (!ok || out->len == 0) {
		g_string_free (out, TRUE);
		return NULL;
	}

	return g_string_free (out, FALSE);
}

/* [ port_range_compare ] -- ascending by first port, then last. */
static gint
port_range_compare (gconstpointer a, gconstpointer b)
{
	const guint *x = a, *y = b;

	if (x[0] != y[0])
		return x[0] < y[0] ? -1 : 1;
	if (x[1] != y[1])
		return x[1] < y[1] ? -1 : 1;
	return 0;
}

/* [ spec_port_set ]
 * The set of ports a normalised spec names, written one way only:
 * ranges sorted, overlapping and touching ones merged.  "445,137-139"
 * and "137-139,445" are the same set, and so are "137-138,139,445"
 * and "137-139 445".  Used only to compare specs; rules keep the spec
 * the row was written with.  NULL when spec is NULL. */
static gchar *
spec_port_set (const gchar *spec)
{
	gchar **elements;
	GArray *ranges;
	GString *out;

	if (spec == NULL)
		return NULL;

	elements = g_strsplit (spec, ",", -1);
	ranges = g_array_new (FALSE, FALSE, sizeof (guint) * 2);

	for (guint i = 0; elements[i] != NULL; i++) {
		guint pair[2];

		if (parse_port_element (elements[i], &pair[0], &pair[1]))
			g_array_append_val (ranges, pair);
	}

	g_strfreev (elements);
	g_array_sort (ranges, port_range_compare);
	out = g_string_new (NULL);

	for (guint i = 0; i < ranges->len; ) {
		const guint *r = &g_array_index (ranges, guint, i * 2);
		guint first = r[0], last = r[1];

		for (i++; i < ranges->len; i++) {
			const guint *n = &g_array_index (ranges, guint, i * 2);

			if (n[0] > last + 1)
				break;
			last = MAX (last, n[1]);
		}

		g_string_append_printf (out, "%s%u-%u", out->len > 0 ? "," : "",
		                        first, last);
	}

	g_array_unref (ranges);
	return g_string_free (out, FALSE);
}

/* [ fs_fwrule_port_spec_covers ] -- see fs-fwrule.h. */
gboolean
fs_fwrule_port_spec_covers (const gchar *spec, guint port)
{
	gchar **elements;
	gboolean covered = FALSE;

	if (spec == NULL)
		return TRUE;

	elements = g_strsplit (spec, ",", -1);

	for (guint i = 0; elements[i] != NULL && !covered; i++) {
		guint first = 0, last = 0;

		if (parse_port_element (elements[i], &first, &last) &&
		    port >= first && port <= last)
			covered = TRUE;
	}

	g_strfreev (elements);
	return covered;
}

/* [ spec_is_normal ]
 * A spec is usable only in the exact form the parser writes, so no
 * hand-built rule can smuggle a space, a ':' range or a bad element
 * past the checks into a netsh argument. */
static gboolean
spec_is_normal (const gchar *spec)
{
	gchar *again;
	gboolean same;

	if (spec == NULL)
		return TRUE;

	again = fs_fwrule_port_spec (spec);
	same = (again != NULL && strcmp (again, spec) == 0);
	g_free (again);

	return same;
}

/* [ fs_fwrule_is_sound ] -- see fs-fwrule.h. */
gboolean
fs_fwrule_is_sound (const FsFwRule *rule)
{
	if (rule == NULL)
		return FALSE;

	if (rule->protocol == FS_PROTO_ANY &&
	    (rule->local_ports != NULL || rule->remote_ports != NULL))
		return FALSE;

	return spec_is_normal (rule->local_ports) &&
	       spec_is_normal (rule->remote_ports);
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

/* What one service row asks for: a spec per protocol, set when the
 * protocol is used.  A used protocol always has a spec: a planned
 * service row never means "any port". */
typedef struct
{
	gboolean tcp;
	gboolean udp;
	gchar   *tcp_ports;
	gchar   *udp_ports;
} PortPlan;

static void
port_plan_clear (PortPlan *plan)
{
	g_free (plan->tcp_ports);
	g_free (plan->udp_ports);
	memset (plan, 0, sizeof *plan);
}

/* [ plan_service_ports ]
 * Decides the protocols and ports of one service row.  FALSE (with
 * *why set, caller frees) when the row has to be refused.
 *
 *   - "TCP" / "UDP" (what the What-If Simulator's "Create This Rule"
 *     writes for a port with no service name): exactly that
 *     protocol, on the row's ports.  With no port they are refused
 *     like any name with nothing to fall back on: "every TCP port"
 *     is not a service, the What-If writes such a row for a probe
 *     that named no port at all ("allow from 10.0.0.5"), and Linux
 *     writes no rule for a portless service row (fs-script.c skips
 *     it) -- Windows opening every TCP port for it would make the
 *     same policy far wider on one platform.
 *   - A well-known service: its own protocols.  With no port text,
 *     or port text naming the same ports as its default in any order
 *     ("445 137-139"), each protocol gets its own default ports
 *     (Samba: UDP 137-138 and TCP 139,445).  With other
 *     port text (SSH moved to 2222) the row's ports apply to every
 *     protocol the service uses.
 *   - Any other name, user-defined or a back door: a TCP and a UDP
 *     rule on the row's ports, the pair fs-script.c writes on Linux.
 *     With no port text a back door uses its table ports; a name we
 *     do not know has nothing to fall back on and is refused, since
 *     "no port" there would mean every port.
 *   - Port text that does not parse is refused, whatever the name. */
static gboolean
plan_service_ports (const gchar *service, const gchar *port_text,
                    const gchar *label, PortPlan *plan, gchar **why)
{
	const FsService *known;
	gchar *text = g_strstrip (g_strdup (port_text != NULL ? port_text : ""));
	gchar *spec = NULL;
	gboolean has_text = (*text != '\0');

	memset (plan, 0, sizeof *plan);
	*why = NULL;

	if (has_text) {
		spec = fs_fwrule_port_spec (text);

		if (spec == NULL) {
			*why = g_strdup_printf (
				_("%s was not applied: \"%s\" is not a valid "
				  "port list (ports 1-65535, ranges written "
				  "67-68 or 67:68, separated by commas or "
				  "spaces)."), label, port_text);
			g_free (text);
			return FALSE;
		}
	}

	g_free (text);

	if (service != NULL && (g_ascii_strcasecmp (service, "TCP") == 0 ||
	                        g_ascii_strcasecmp (service, "UDP") == 0)) {
		if (spec == NULL) {
			*why = g_strdup_printf (
				_("%s was not applied: it names no port, and "
				  "\"%s\" alone would mean every %s port.  Name "
				  "the ports, or use a host rule for every port "
				  "of one host."), label, service, service);
			return FALSE;
		}

		if (g_ascii_strcasecmp (service, "TCP") == 0) {
			plan->tcp = TRUE;
			plan->tcp_ports = spec;
		} else {
			plan->udp = TRUE;
			plan->udp_ports = spec;
		}
		return TRUE;
	}

	known = fs_service_find (service);

	if (known != NULL &&
	    (known->tcp_ports != NULL || known->udp_ports != NULL)) {
		/* The same ports in another order or spelling ("445
		 * 137-139" for Samba) are still the defaults, so each
		 * protocol keeps its own: comparing the text would put
		 * TCP on Samba's UDP ports and UDP on its TCP ones. */
		gchar *defaults = fs_fwrule_port_spec (known->ports);
		gchar *want_set = spec_port_set (spec);
		gchar *default_set = spec_port_set (defaults);
		gboolean use_defaults =
			(spec == NULL || g_strcmp0 (want_set, default_set) == 0);

		g_free (want_set);
		g_free (default_set);
		g_free (defaults);

		if (known->tcp_ports != NULL) {
			plan->tcp = TRUE;
			plan->tcp_ports = use_defaults
				? fs_fwrule_port_spec (known->tcp_ports)
				: g_strdup (spec);
		}

		if (known->udp_ports != NULL) {
			plan->udp = TRUE;
			plan->udp_ports = use_defaults
				? fs_fwrule_port_spec (known->udp_ports)
				: g_strdup (spec);
		}

		g_free (spec);

		/* A table entry that does not parse is a bug in the table;
		 * refuse rather than let it become "any port". */
		if ((plan->tcp && plan->tcp_ports == NULL) ||
		    (plan->udp && plan->udp_ports == NULL)) {
			port_plan_clear (plan);
			*why = g_strdup_printf (
				_("%s was not applied: the ports of \"%s\" "
				  "could not be read."), label, service);
			return FALSE;
		}

		return TRUE;
	}

	if (spec == NULL && known != NULL)
		spec = fs_fwrule_port_spec (known->ports);

	if (spec == NULL) {
		*why = g_strdup_printf (
			_("%s was not applied: it names no port, and \"%s\" "
			  "is not a known service whose ports could be "
			  "used."), label,
			(service != NULL && *service != '\0')
				? service : _("(no service)"));
		return FALSE;
	}

	plan->tcp = TRUE;
	plan->udp = TRUE;
	plan->tcp_ports = spec;
	plan->udp_ports = g_strdup (spec);

	return TRUE;
}

/* [ append_planned ]
 * The rules of one planned row.  Each used protocol gets its own rule
 * with its ports on the side the direction names; a row that yields
 * both is told apart by a " (TCP)" / " (UDP)" suffix, so delete-by-
 * name removes exactly one of them and the Windows UI shows which is
 * which. */
static guint
append_planned (GList **out, const PortPlan *plan, const gchar *base_name,
                FsRuleDirection direction, FsRuleAction action,
                gboolean ports_local, const gchar *remote_address,
                const gchar *forward_address)
{
	struct { gboolean used; FsRuleProtocol proto; const gchar *ports;
	         const gchar *suffix; } sides[2] = {
		{ plan->tcp, FS_PROTO_TCP, plan->tcp_ports, " (TCP)" },
		{ plan->udp, FS_PROTO_UDP, plan->udp_ports, " (UDP)" }
	};
	gboolean pair = (plan->tcp && plan->udp);
	guint count = 0;

	for (guint i = 0; i < G_N_ELEMENTS (sides); i++) {
		FsFwRule *rule;

		if (!sides[i].used)
			continue;

		rule = fs_fwrule_new ();
		rule->direction = direction;
		rule->action = action;
		rule->protocol = sides[i].proto;

		if (ports_local)
			rule->local_ports = g_strdup (sides[i].ports);
		else
			rule->remote_ports = g_strdup (sides[i].ports);

		rule->remote_address = g_strdup (remote_address);
		rule->name = pair ? g_strconcat (base_name, sides[i].suffix,
		                                 NULL)
		                  : g_strdup (base_name);

		if (forward_address != NULL) {
			rule->forward = TRUE;
			rule->forward_address = g_strdup (forward_address);
		}

		*out = g_list_append (*out, rule);
		count++;
	}

	return count;
}

/* [ append_service_rows ]
 * Expands every service row of one kind.  Inbound rows put the
 * service port on the local side (connections come TO it); outbound
 * rows on the remote side (connections go TO it) -- the --dport of
 * each chain in fs-script.c. */
static guint
append_service_rows (GList **out, GPtrArray *refused, GPtrArray *rows,
                     FsRuleDirection direction, FsRuleAction action)
{
	guint count = 0;

	for (guint i = 0; i < rows->len; i++) {
		FsRule *row = g_ptr_array_index (rows, i);
		gchar *name = fs_fwrule_default_name (direction, action,
		                                      row->service, row->target);
		gchar *address = address_or_null (row->target);
		gchar *why = NULL;
		PortPlan plan;

		if (plan_service_ports (row->service, row->port, name, &plan,
		                        &why))
			count += append_planned (out, &plan, name, direction,
			                         action,
			                         direction == FS_DIR_INBOUND,
			                         address, NULL);
		else if (refused != NULL)
			g_ptr_array_add (refused, g_steal_pointer (&why));

		g_free (why);
		port_plan_clear (&plan);
		g_free (address);
		g_free (name);
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
 * Port forwards: open the exposed port (the row's port) inbound on
 * this computer, deliver to forward_address.  Same protocol rules as
 * a service row. */
static guint
append_forward_rows (GList **out, GPtrArray *refused, GPtrArray *rows)
{
	guint count = 0;

	for (guint i = 0; i < rows->len; i++) {
		FsRule *row = g_ptr_array_index (rows, i);
		gchar *name;
		gchar *why = NULL;
		PortPlan plan;

		/* A forward with nowhere to go is not a rule at all. */
		if (row->to == NULL || *row->to == '\0' ||
		    row->to_port == NULL || *row->to_port == '\0')
			continue;

		name = fs_fwrule_default_name (FS_DIR_INBOUND, FS_ACTION_ALLOW,
		                               row->service, NULL);

		if (plan_service_ports (row->service, row->port, name, &plan,
		                        &why))
			count += append_planned (out, &plan, name,
			                         FS_DIR_INBOUND, FS_ACTION_ALLOW,
			                         TRUE, NULL, row->to);
		else if (refused != NULL)
			g_ptr_array_add (refused, g_steal_pointer (&why));

		g_free (why);
		port_plan_clear (&plan);
		g_free (name);
	}

	return count;
}

guint
fs_fwrule_expand_checked (const FsPolicy *policy, GList **out,
                          GPtrArray *refused)
{
	guint count = 0;

	if (policy == NULL || out == NULL)
		return 0;

	/* Inbound allows. */
	count += append_host_rows (out,
		policy->kinds[FS_RULE_INBOUND_ALLOW_FROM],
		FS_DIR_INBOUND, FS_ACTION_ALLOW);
	count += append_service_rows (out, refused,
		policy->kinds[FS_RULE_INBOUND_ALLOW_SERVICE],
		FS_DIR_INBOUND, FS_ACTION_ALLOW);
	count += append_forward_rows (out, refused,
		policy->kinds[FS_RULE_INBOUND_FORWARD]);

	/* Outbound denies first: a block has to be seen before the allows. */
	count += append_host_rows (out,
		policy->kinds[FS_RULE_OUTBOUND_DENY_TO],
		FS_DIR_OUTBOUND, FS_ACTION_BLOCK);
	count += append_host_rows (out,
		policy->kinds[FS_RULE_OUTBOUND_DENY_FROM],
		FS_DIR_OUTBOUND, FS_ACTION_BLOCK);
	count += append_service_rows (out, refused,
		policy->kinds[FS_RULE_OUTBOUND_DENY_SERVICE],
		FS_DIR_OUTBOUND, FS_ACTION_BLOCK);

	/* Outbound allows. */
	count += append_host_rows (out,
		policy->kinds[FS_RULE_OUTBOUND_ALLOW_TO],
		FS_DIR_OUTBOUND, FS_ACTION_ALLOW);
	count += append_host_rows (out,
		policy->kinds[FS_RULE_OUTBOUND_ALLOW_FROM],
		FS_DIR_OUTBOUND, FS_ACTION_ALLOW);
	count += append_service_rows (out, refused,
		policy->kinds[FS_RULE_OUTBOUND_ALLOW_SERVICE],
		FS_DIR_OUTBOUND, FS_ACTION_ALLOW);

	return count;
}

/* [ fs_fwrule_block_refusals ] -- see fs-fwrule.h.  Only service
 * rows can be refused (host rows have no port), so the outbound deny
 * service kind is the only block kind to look at. */
gchar *
fs_fwrule_block_refusals (const FsPolicy *policy)
{
	GList *rules = NULL;
	GPtrArray *refused;
	gchar *out = NULL;

	if (policy == NULL)
		return NULL;

	refused = g_ptr_array_new_with_free_func (g_free);
	append_service_rows (&rules, refused,
	                     policy->kinds[FS_RULE_OUTBOUND_DENY_SERVICE],
	                     FS_DIR_OUTBOUND, FS_ACTION_BLOCK);
	fs_fwrule_list_free (rules);

	if (refused->len > 0) {
		g_ptr_array_add (refused, NULL);
		out = g_strjoinv ("\n", (gchar **) refused->pdata);
	}

	g_ptr_array_unref (refused);
	return out;
}

guint
fs_fwrule_expand (const FsPolicy *policy, GList **out)
{
	return fs_fwrule_expand_checked (policy, out, NULL);
}

GList *
fs_fwrule_from_policy (const FsPolicy *policy)
{
	return fs_fwrule_from_policy_checked (policy, NULL);
}

GList *
fs_fwrule_from_policy_checked (const FsPolicy *policy, GPtrArray **refused)
{
	GList *out = NULL;
	GPtrArray *why = g_ptr_array_new_with_free_func (g_free);

	fs_fwrule_expand_checked (policy, &out, why);

	if (refused != NULL)
		*refused = why;
	else
		g_ptr_array_unref (why);

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
	    a->forward != b->forward)
		return FALSE;

	return (g_strcmp0 (a->name, b->name) == 0 &&
	        g_strcmp0 (a->local_ports, b->local_ports) == 0 &&
	        g_strcmp0 (a->remote_ports, b->remote_ports) == 0 &&
	        g_strcmp0 (a->local_address, b->local_address) == 0 &&
	        g_strcmp0 (a->remote_address, b->remote_address) == 0 &&
	        g_strcmp0 (a->forward_address, b->forward_address) == 0);
}

/* [ fs_fwrule_netsh_name ] -- see fs-fwrule.h. */
gchar *
fs_fwrule_netsh_name (const gchar *name)
{
	GString *out = g_string_new (NULL);

	for (const gchar *p = (name != NULL) ? name : "StockFW rule";
	     *p != '\0'; p++) {
		switch (*p) {
		case ':':
		case '(':
		case ')':
		case '/':
		case ',':
			g_string_append_c (out, '-');
			break;
		case '"':
			/* The argv crosses to netsh with no shell, but
			 * CreateProcess still hands netsh one command line
			 * that it splits on quotes: a quote in a service
			 * name ("a\" dir=in \"b") could end the name there
			 * and let the rest read as netsh arguments. */
			g_string_append_c (out, '\'');
			break;
		default:
			g_string_append_c (out, *p);
			break;
		}
	}

	return g_string_free (out, FALSE);
}

/* [ fs_fwrule_netsh_args ] -- see fs-fwrule.h.  Built here, in core,
 * so the exact argv netsh receives is checked by the tests on any
 * platform; the backend only runs it. */
GStrv
fs_fwrule_netsh_args (const FsFwRule *rule)
{
	GPtrArray *args;
	gchar *name;

	/* The 1.0.6 failure: a ported rule with protocol "any", whose
	 * port had to be dropped to get past netsh. */
	if (!fs_fwrule_is_sound (rule))
		return NULL;

	args = g_ptr_array_new ();
	g_ptr_array_add (args, g_strdup ("netsh.exe"));
	g_ptr_array_add (args, g_strdup ("advfirewall"));
	g_ptr_array_add (args, g_strdup ("firewall"));
	g_ptr_array_add (args, g_strdup ("add"));
	g_ptr_array_add (args, g_strdup ("rule"));

	/* The process is spawned with no shell, so the arguments must not
	 * carry quote characters: the whole "name=..." pair goes across
	 * as one element.  Quotes here make netsh mis-parse the value and
	 * then complain about the profiles argument. */
	name = fs_fwrule_netsh_name (rule->name);
	g_ptr_array_add (args, g_strdup_printf ("name=%s", name));
	g_free (name);

	/* Every profile, so the rule applies wherever the firewall is on. */
	g_ptr_array_add (args, g_strdup ("profile=any"));

	g_ptr_array_add (args, g_strdup_printf ("dir=%s",
		rule->direction == FS_DIR_INBOUND ? "in" : "out"));
	g_ptr_array_add (args, g_strdup_printf ("action=%s",
		rule->action == FS_ACTION_ALLOW ? "allow" : "block"));
	g_ptr_array_add (args, g_strdup_printf ("protocol=%s",
		rule->protocol == FS_PROTO_TCP ? "TCP"
		: rule->protocol == FS_PROTO_UDP ? "UDP" : "any"));
	g_ptr_array_add (args, g_strdup ("enable=yes"));

	/* No port named is netsh's own default, any; the soundness check
	 * above already holds a ported rule to TCP or UDP. */
	if (rule->local_ports != NULL)
		g_ptr_array_add (args, g_strdup_printf ("localport=%s",
		                                        rule->local_ports));

	if (rule->remote_ports != NULL)
		g_ptr_array_add (args, g_strdup_printf ("remoteport=%s",
		                                        rule->remote_ports));

	if (rule->remote_address != NULL && *rule->remote_address != '\0')
		g_ptr_array_add (args, g_strdup_printf ("remoteip=%s",
		                                        rule->remote_address));

	g_ptr_array_add (args, NULL);

	return (GStrv) g_ptr_array_free (args, FALSE);
}
