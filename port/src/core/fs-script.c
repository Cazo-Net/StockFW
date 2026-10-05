/*---[ fs-script.c ]----------------------------------------------------
 * iptables rule script generation.
 *
 * Ported from netfilter-script.c.  Same rule semantics, modernised where
 * the original shell was broken or relied on bash-isms.
 *--------------------------------------------------------------------*/

#include "core/fs-script.h"
#include "core/fs-util.h"
#include "core/fs-i18n.h"

#include <string.h>

FsSettings *
fs_settings_new (void)
{
	FsSettings *settings = g_new0 (FsSettings, 1);

	settings->filter_icmp  = TRUE;
	settings->filter_tos   = TRUE;
	settings->deny_packets = TRUE;

	return settings;
}

void
fs_settings_free (FsSettings *settings)
{
	if (settings == NULL)
		return;

	g_free (settings->ext_device);
	g_free (settings->int_device);

	g_free (settings);
}

/* [ emit_source ]
 * Appends "-s <target>" unless the target means everyone. */
static void
emit_source (GString *out, const gchar *target, int indent)
{
	gchar *pad = g_strnfill ((gsize) indent, ' ');

	if (!fs_util_target_is_anyone (target))
		g_string_append_printf (out, "%s-s %s ", pad, target);

	g_free (pad);
}

/* [ emit_service_rules ]
 * Emits the tcp/udp pair for one service rule. */
static void
emit_service_rules (GString *out, const gchar *target, const gchar *port,
                    const gchar *jump, int indent)
{
	if (port == NULL || *port == '\0')
		return;

	emit_source (out, target, indent);
	g_string_append_printf (out, "-p tcp --dport %s -j %s\n", port, jump);
	emit_source (out, target, indent);
	g_string_append_printf (out, "-p udp --dport %s -j %s\n", port, jump);
}

/* [ append_host_rules ]
 * Emits one "-H <host> -j <jump>" per line for host-based rules. */
static void
append_host_rules (GString *out, GPtrArray *rules, const gchar *jump)
{
	for (guint i = 0; i < rules->len; i++) {
		FsRule *rule = g_ptr_array_index (rules, i);

		if (rule->target != NULL && *rule->target != '\0')
			g_string_append_printf (out, "$IPT -H %s -j %s\n",
			                        rule->target, jump);
	}
}

/* [ append_service_rules ]
 * Emits rules of a service kind into a chain. */
static void
append_service_rules (GString *out, GPtrArray *rules, const gchar *chain,
                      const gchar *jump)
{
	for (guint i = 0; i < rules->len; i++) {
		FsRule *rule = g_ptr_array_index (rules, i);
		GString *pair = g_string_new (NULL);

		emit_service_rules (pair, rule->target, rule->port, jump, 0);

		/* emit_service_rules produced one line per protocol; prefix
		 * each with the chain append. */
		for (gchar *line = pair->str; line != NULL; ) {
			gchar *nl = strchr (line, '\n');

			if (nl != NULL)
				*nl = '\0';

			if (*line != '\0')
				g_string_append_printf (out, "$IPT -A %s %s\n",
				                        chain, line);

			line = (nl != NULL) ? nl + 1 : NULL;
		}

		g_string_free (pair, TRUE);
	}
}

/* [ script_preamble ]
 * Common chain setup shared by both directions. */
static GString *
script_preamble (const gchar *chain)
{
	GString *out = g_string_new (NULL);

	g_string_append_printf (out, "# Initialize %s chain\n", chain);

	/* No "2> /dev/null": the original needed it to hide the error from
	 * a -N on an existing chain, but nothing here runs through a shell,
	 * so a redirection would just be an invalid iptables argument.
	 * Backends tolerate -N failing when the chain already exists. */
	g_string_append_printf (out,
		"$IPT -N %1$s\n"
		"$IPT -F %1$s\n\n", chain);

	return out;
}

gchar *
fs_script_generate_inbound (const FsPolicy *policy,
                            const FsSettings *settings)
{
	GString *out;

	if (policy == NULL || settings == NULL)
		return g_strdup ("");

	out = script_preamble ("INBOUND");

	/* ICMP handling, from the original feature set. */
	if (settings->filter_icmp) {
		g_string_append (out,
			"# Allow essential ICMP types for path MTU discovery\n"
			"$IPT -A INBOUND -p icmp --icmp-type destination-unreachable -j ACCEPT\n"
			"$IPT -A INBOUND -p icmp --icmp-type time-exceeded -j ACCEPT\n"
			"$IPT -A INBOUND -p icmp --icmp-type parameter-problem -j ACCEPT\n");
	}

	/* Connection state.  The original opened with -m state which lets
	 * inbound traffic spoof a RELATED state; NEW is the safe default. */
	g_string_append (out,
		"# Accept return traffic for connections we started\n"
		"$IPT -A INBOUND -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n\n");

	/* Loopback is always trusted. */
	g_string_append (out,
		"# Trust loopback\n"
		"$IPT -A INBOUND -i lo -j ACCEPT\n\n");

	if (settings->nat && settings->int_device != NULL) {
		g_string_append (out,
			"# Accept traffic arriving on the internal interface\n");
		g_string_append_printf (out,
			"$IPT -A INBOUND -i %s -j ACCEPT\n\n", settings->int_device);
	}

	if (settings->deny_packets)
		g_string_append (out,
			"# Drop malformed packets before anything else sees them\n"
			"$IPT -A INBOUND -m conntrack --ctstate INVALID -j DROP\n\n");

	/* User policy. */
	g_string_append (out, "# Inbound policy\n");

	for (guint i = 0; i < policy->kinds[FS_RULE_INBOUND_ALLOW_FROM]->len; i++) {
		FsRule *rule = g_ptr_array_index (
			policy->kinds[FS_RULE_INBOUND_ALLOW_FROM], i);

		if (rule->target != NULL && *rule->target != '\0')
			g_string_append_printf (out,
				"$IPT -A INBOUND -s %s -j ACCEPT\n", rule->target);
	}

	append_service_rules (out,
		policy->kinds[FS_RULE_INBOUND_ALLOW_SERVICE], "INBOUND", "ACCEPT");

	/* Port forwarding needs NAT PREROUTING. */
	for (guint i = 0; i < policy->kinds[FS_RULE_INBOUND_FORWARD]->len; i++) {
		FsRule *rule = g_ptr_array_index (
			policy->kinds[FS_RULE_INBOUND_FORWARD], i);

		if (rule->port == NULL || rule->to == NULL || rule->to_port == NULL)
			continue;

		g_string_append_printf (out,
			"\n# Forward %s to %s:%s\n"
			"$IPT -t nat -A PREROUTING -i %s -p tcp --dport %s "
			"-j DNAT --to-destination %s:%s\n",
			rule->service ? rule->service : "service",
			rule->to, rule->to_port,
			settings->ext_device ? settings->ext_device : "eth0",
			rule->port, rule->to, rule->to_port);
	}

	/* Default. */
	g_string_append (out,
		"\n# Everything else is refused\n"
		"$IPT -A INBOUND -j LOG --log-prefix \"FIRESTARTER-DROP \" "
		"--log-level 6\n"
		"$IPT -A INBOUND -j DROP\n");

	return g_string_free (out, FALSE);
}

gchar *
fs_script_generate_outbound (const FsPolicy *policy,
                             const FsSettings *settings)
{
	GString *out;

	if (policy == NULL || settings == NULL)
		return g_strdup ("");

	out = script_preamble ("OUTBOUND");

	g_string_append (out,
		"# Accept return traffic\n"
		"$IPT -A OUTBOUND -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
		"$IPT -A OUTBOUND -i lo -j ACCEPT\n");

	if (settings->filter_icmp)
		g_string_append (out, "$IPT -A OUTBOUND -p icmp -j ACCEPT\n");

	if (settings->nat && settings->ext_device != NULL)
		g_string_append_printf (out,
			"$IPT -A OUTBOUND -o %s -j ACCEPT\n", settings->ext_device);

	g_string_append (out, "\n# Outbound policy\n");

	if (settings->restrictive_outbound) {
		g_string_append (out, "# Deny rules are applied first\n");

		append_host_rules (out,
			policy->kinds[FS_RULE_OUTBOUND_DENY_TO], "DROP");
		append_host_rules (out,
			policy->kinds[FS_RULE_OUTBOUND_DENY_FROM], "DROP");

		append_service_rules (out,
			policy->kinds[FS_RULE_OUTBOUND_DENY_SERVICE], "OUTBOUND", "DROP");
	}

	/* Allow rules. */
	append_host_rules (out, policy->kinds[FS_RULE_OUTBOUND_ALLOW_TO], "ACCEPT");
	append_host_rules (out, policy->kinds[FS_RULE_OUTBOUND_ALLOW_FROM],
	                   "ACCEPT");

	append_service_rules (out,
		policy->kinds[FS_RULE_OUTBOUND_ALLOW_SERVICE], "OUTBOUND", "ACCEPT");

	g_string_append (out,
		settings->restrictive_outbound
		? "\n# Restrictive mode: default deny\n$IPT -A OUTBOUND -j DROP\n"
		: "\n# Permissive mode: default accept\n$IPT -A OUTBOUND -j ACCEPT\n");

	return g_string_free (out, FALSE);
}

gchar *
fs_script_generate_control (const FsSettings *settings)
{
	GString *out = g_string_new (NULL);

	g_string_append (out,
		"#!/bin/sh\n"
		"# Firestarter control script (generated - do not edit)\n\n"
		"IPT=\"${IPT:-iptables}\"\n"
		"export IPT\n\n"
		"if [ \"$1\" = \"stop\" ]; then\n"
		"\t$IPT -F\n"
		"\t$IPT -X\n"
		"\t$IPT -t nat -F\n"
		"\t$IPT -t nat -X\n"
		"\texit 0\n"
		"fi\n\n");

	if (settings != NULL && settings->deny_packets) {
		g_string_append (out,
			"# Drop packets that are not really connections\n"
			"$IPT -A INPUT -m conntrack --ctstate INVALID -j DROP\n"
			"$IPT -A FORWARD -m conntrack --ctstate INVALID -j DROP\n"
			"$IPT -A OUTPUT -m conntrack --ctstate INVALID -j DROP\n\n");
	}

	if (settings != NULL && settings->nat) {
		g_string_append (out,
			"# Enable forwarding and masquerading\n"
			"sysctl -w net.ipv4.ip_forward=1 > /dev/null\n");

		if (settings->ext_device != NULL) {
			g_string_append_printf (out,
				"$IPT -t nat -A POSTROUTING -o %s -j MASQUERADE\n",
				settings->ext_device);
			g_string_append_printf (out,
				"$IPT -A FORWARD -i %s -o %s -j ACCEPT\n",
				settings->int_device ? settings->int_device : "eth0",
				settings->ext_device);
		}

		g_string_append_c (out, '\n');
	}

	g_string_append (out,
		"# Chains are defined by the per-direction setup scripts\n"
		". /etc/firestarter/inbound/setup\n"
		". /etc/firestarter/outbound/setup\n\n"
		"# Hook the chains into the built-in ones\n"
		"$IPT -A INPUT -j INBOUND\n"
		"$IPT -A OUTPUT -j OUTBOUND\n"
		"$IPT -A FORWARD -j INBOUND\n");

	return g_string_free (out, FALSE);
}

gchar *
fs_script_generate_full (const FsPolicy *policy,
                         const FsSettings *settings)
{
	gchar *control, *inbound, *outbound, *full;

	control  = fs_script_generate_control (settings);
	inbound  = fs_script_generate_inbound (policy, settings);
	outbound = fs_script_generate_outbound (policy, settings);

	full = g_strconcat (control, "\n# ---- INBOUND ----\n", inbound,
	                    "\n# ---- OUTBOUND ----\n", outbound, NULL);

	g_free (control);
	g_free (inbound);
	g_free (outbound);

	return full;
}