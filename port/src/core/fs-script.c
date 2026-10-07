/*---[ fs-script.c ]----------------------------------------------------
 * iptables rule script generation.
 *
 * Ported from netfilter-script.c.  Same rule semantics, modernised where
 * the original shell was broken or relied on bash-isms.
 *--------------------------------------------------------------------*/

#include "core/fs-script.h"
#include "core/fs-util.h"
#include "core/fs-prefs.h"
#include "core/fs-i18n.h"

#include <string.h>

FsSettings *
fs_settings_new (void)
{
	FsSettings *settings = g_new0 (FsSettings, 1);

	settings->filter_icmp  = TRUE;
	settings->filter_tos   = TRUE;
	settings->deny_packets = TRUE;

	/* The original shipped no schema default for the per-type keys,
	 * so these are the ones that keep a normal machine working on
	 * first run: ping, traceroute and the unreachable reports.  The
	 * privacy-questionable ones start off. */
	settings->icmp_echo_request    = TRUE;
	settings->icmp_echo_reply      = TRUE;
	settings->icmp_traceroute      = TRUE;
	settings->icmp_mstraceroute    = TRUE;
	settings->icmp_unreachable     = TRUE;
	settings->icmp_timestamping    = FALSE;
	settings->icmp_masking         = FALSE;
	settings->icmp_redirection     = FALSE;
	settings->icmp_source_quenches = FALSE;

	/* Must agree with the fallbacks in fs_settings_load_prefs(), so a
	 * freshly constructed settings object behaves like a fresh install
	 * whether or not prefs have been read yet. */
	settings->block_non_routables = TRUE;

	return settings;
}

/* [ fs_settings_load_prefs ]
 * The Firewall pages of the Preferences dialog set these keys; reading
 * them here is what makes those pages mean something. */
void
fs_settings_load_prefs (FsSettings *settings)
{
	gchar *text;

	if (settings == NULL)
		return;

	g_free (settings->ext_device);
	g_free (settings->int_device);

	text = fs_prefs_get_string (FS_PREFS_FW_EXT_IF, NULL);
	settings->ext_device = text;

	text = fs_prefs_get_string (FS_PREFS_FW_INT_IF, NULL);
	settings->int_device = text;

	settings->nat                   = fs_prefs_get_bool (FS_PREFS_FW_NAT, FALSE);
	settings->filter_icmp           = fs_prefs_get_bool (FS_PREFS_FW_FILTER_ICMP, TRUE);
	settings->filter_tos            = fs_prefs_get_bool (FS_PREFS_FW_FILTER_TOS, TRUE);
	settings->deny_packets          = fs_prefs_get_bool (FS_PREFS_FW_DENY_PACKETS, TRUE);
	settings->block_external_broadcast =
		fs_prefs_get_bool (FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST, FALSE);
	settings->block_internal_broadcast =
		fs_prefs_get_bool (FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST, FALSE);
	settings->block_non_routables   =
		fs_prefs_get_bool (FS_PREFS_FW_BLOCK_NON_ROUTABLES, TRUE);
	settings->restrictive_outbound  =
		fs_prefs_get_bool (FS_PREFS_FW_RESTRICTIVE_OUTBOUND, FALSE);

	/* ICMP types.  The fallbacks match fs_settings_new() so an unset
	 * key behaves like a fresh install. */
	settings->icmp_echo_request =
		fs_prefs_get_bool (FS_PREFS_FW_ICMP_ECHO_REQUEST, TRUE);
	settings->icmp_echo_reply =
		fs_prefs_get_bool (FS_PREFS_FW_ICMP_ECHO_REPLY, TRUE);
	settings->icmp_traceroute =
		fs_prefs_get_bool (FS_PREFS_FW_ICMP_TRACEROUTE, TRUE);
	settings->icmp_mstraceroute =
		fs_prefs_get_bool (FS_PREFS_FW_ICMP_MSTRACEROUTE, TRUE);
	settings->icmp_unreachable =
		fs_prefs_get_bool (FS_PREFS_FW_ICMP_UNREACHABLE, TRUE);
	settings->icmp_timestamping =
		fs_prefs_get_bool (FS_PREFS_FW_ICMP_TIMESTAMPING, FALSE);
	settings->icmp_masking =
		fs_prefs_get_bool (FS_PREFS_FW_ICMP_MASKING, FALSE);
	settings->icmp_redirection =
		fs_prefs_get_bool (FS_PREFS_FW_ICMP_REDIRECTION, FALSE);
	settings->icmp_source_quenches =
		fs_prefs_get_bool (FS_PREFS_FW_ICMP_SOURCE_QUENCHES, FALSE);
}

void
fs_settings_save_prefs (const FsSettings *settings)
{
	if (settings == NULL)
		return;

	fs_prefs_set_string (FS_PREFS_FW_EXT_IF,
	                     settings->ext_device ? settings->ext_device : "");
	fs_prefs_set_string (FS_PREFS_FW_INT_IF,
	                     settings->int_device ? settings->int_device : "");
	fs_prefs_set_bool (FS_PREFS_FW_NAT, settings->nat);
	fs_prefs_set_bool (FS_PREFS_FW_FILTER_ICMP, settings->filter_icmp);
	fs_prefs_set_bool (FS_PREFS_FW_FILTER_TOS, settings->filter_tos);
	fs_prefs_set_bool (FS_PREFS_FW_DENY_PACKETS, settings->deny_packets);
	fs_prefs_set_bool (FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST,
	                   settings->block_external_broadcast);
	fs_prefs_set_bool (FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST,
	                   settings->block_internal_broadcast);
	fs_prefs_set_bool (FS_PREFS_FW_BLOCK_NON_ROUTABLES,
	                   settings->block_non_routables);
	fs_prefs_set_bool (FS_PREFS_FW_RESTRICTIVE_OUTBOUND,
	                   settings->restrictive_outbound);

	fs_prefs_set_bool (FS_PREFS_FW_ICMP_ECHO_REQUEST,
	                   settings->icmp_echo_request);
	fs_prefs_set_bool (FS_PREFS_FW_ICMP_ECHO_REPLY,
	                   settings->icmp_echo_reply);
	fs_prefs_set_bool (FS_PREFS_FW_ICMP_TRACEROUTE,
	                   settings->icmp_traceroute);
	fs_prefs_set_bool (FS_PREFS_FW_ICMP_MSTRACEROUTE,
	                   settings->icmp_mstraceroute);
	fs_prefs_set_bool (FS_PREFS_FW_ICMP_UNREACHABLE,
	                   settings->icmp_unreachable);
	fs_prefs_set_bool (FS_PREFS_FW_ICMP_TIMESTAMPING,
	                   settings->icmp_timestamping);
	fs_prefs_set_bool (FS_PREFS_FW_ICMP_MASKING,
	                   settings->icmp_masking);
	fs_prefs_set_bool (FS_PREFS_FW_ICMP_REDIRECTION,
	                   settings->icmp_redirection);
	fs_prefs_set_bool (FS_PREFS_FW_ICMP_SOURCE_QUENCHES,
	                   settings->icmp_source_quenches);
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
 * Emits one address match per line for host-based rules.  iptables has
 * no -H: outbound "to host" rules match the destination (-d) and
 * "from host" rules the source (-s). */
static void
append_host_rules (GString *out, GPtrArray *rules, const gchar *jump,
                   const gchar *match)
{
	for (guint i = 0; i < rules->len; i++) {
		FsRule *rule = g_ptr_array_index (rules, i);

		if (rule->target != NULL && *rule->target != '\0')
			g_string_append_printf (out, "$IPT %s %s -j %s\n",
			                        match, rule->target, jump);
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

/* [ append_icmp_rules ]
 * Ported from the original's "Rules Configuration - ICMP" section in
 * netfilter-script.c.  Each checkbox on the ICMP Filtering page gates
 * its own rule, and turning the master switch off allows everything.
 *
 * The original wrote INPUT and FORWARD rules side by side; our FORWARD
 * chain already jumps to INBOUND, so one chain covers both.
 *
 * Two types stay unconditional while filtering is on: time-exceeded and
 * parameter-problem are not on the Preferences page at all but are what
 * makes path-MTU discovery and traceroute loop reports work. */
static void
append_icmp_rules (GString *out, const FsSettings *settings)
{
	if (!settings->filter_icmp) {
		g_string_append (out,
			"# ICMP filtering is off: allow all ICMP\n"
			"$IPT -A INBOUND -p icmp -m limit --limit 10/s -j ACCEPT\n\n");
		return;
	}

	g_string_append (out,
		"# Only the ICMP types ticked in Preferences are allowed\n"
		"$IPT -A INBOUND -p icmp --icmp-type time-exceeded -j ACCEPT\n"
		"$IPT -A INBOUND -p icmp --icmp-type parameter-problem -j ACCEPT\n");

	if (settings->icmp_echo_request)
		g_string_append (out,
			"# ICMP: Ping requests\n"
			"$IPT -A INBOUND -p icmp --icmp-type echo-request "
			"-m limit --limit 1/s -j ACCEPT\n");

	if (settings->icmp_echo_reply)
		g_string_append (out,
			"# ICMP: Ping replies\n"
			"$IPT -A INBOUND -p icmp --icmp-type echo-reply "
			"-m limit --limit 1/s -j ACCEPT\n");

	/* Not ICMP: the original opened UDP 33434 for traceroute. */
	if (settings->icmp_traceroute)
		g_string_append (out,
			"# ICMP: Traceroute requests (UDP 33434, as in the original)\n"
			"$IPT -A INBOUND -p udp --dport 33434 -j ACCEPT\n");

	if (settings->icmp_mstraceroute)
		g_string_append (out,
			"# ICMP: MS Traceroute\n"
			"$IPT -A INBOUND -p icmp --icmp-type destination-unreachable "
			"-j ACCEPT\n");

	if (settings->icmp_unreachable)
		g_string_append (out,
			"# ICMP: Unreachable\n"
			"$IPT -A INBOUND -p icmp --icmp-type host-unreachable -j ACCEPT\n");

	if (settings->icmp_timestamping)
		g_string_append (out,
			"# ICMP: Timestamping\n"
			"$IPT -A INBOUND -p icmp --icmp-type timestamp-request -j ACCEPT\n"
			"$IPT -A INBOUND -p icmp --icmp-type timestamp-reply -j ACCEPT\n");

	if (settings->icmp_masking)
		g_string_append (out,
			"# ICMP: Address masking\n"
			"$IPT -A INBOUND -p icmp --icmp-type address-mask-request -j ACCEPT\n"
			"$IPT -A INBOUND -p icmp --icmp-type address-mask-reply -j ACCEPT\n");

	if (settings->icmp_redirection)
		g_string_append (out,
			"# ICMP: Redirection\n"
			"$IPT -A INBOUND -p icmp --icmp-type redirect "
			"-m limit --limit 2/s -j ACCEPT\n");

	if (settings->icmp_source_quenches)
		g_string_append (out,
			"# ICMP: Source quench\n"
			"$IPT -A INBOUND -p icmp --icmp-type source-quench "
			"-m limit --limit 2/s -j ACCEPT\n");

	g_string_append (out,
		"# Anything else falls through to the default action\n\n");
}

gchar *
fs_script_generate_inbound (const FsPolicy *policy,
                            const FsSettings *settings)
{
	GString *out;

	if (policy == NULL || settings == NULL)
		return g_strdup ("");

	out = script_preamble ("INBOUND");

	append_icmp_rules (out, settings);

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

	/* Malformed packets are dropped whatever the rejection method is:
	 * answering them would just tell a scanner we are here. */
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

	/* Advanced Options: broadcast traffic.  Each is scoped to the
	 * interface it belongs to, as the original's rules were. */
	if (settings->block_external_broadcast && settings->ext_device != NULL)
		g_string_append_printf (out,
			"# Block broadcasts arriving from outside\n"
			"$IPT -A INBOUND -i %s -d 255.255.255.255 -j DROP\n",
			settings->ext_device);

	if (settings->block_internal_broadcast && settings->nat &&
	    settings->int_device != NULL)
		g_string_append_printf (out,
			"# Block broadcasts arriving on the local network\n"
			"$IPT -A INBOUND -i %s -d 255.255.255.255 -j DROP\n",
			settings->int_device);

	/* Advanced Options: reserved addresses.  Private source addresses
	 * arriving on the external interface cannot be genuine, so they
	 * are spoofed and refused. */
	if (settings->block_non_routables && settings->ext_device != NULL)
		g_string_append_printf (out,
			"# Refuse reserved addresses arriving from outside\n"
			"$IPT -A INBOUND -i %s -s 10.0.0.0/8 -j DROP\n"
			"$IPT -A INBOUND -i %s -s 172.16.0.0/12 -j DROP\n"
			"$IPT -A INBOUND -i %s -s 192.168.0.0/16 -j DROP\n"
			"$IPT -A INBOUND -i %s -s 127.0.0.0/8 -j DROP\n",
			settings->ext_device, settings->ext_device,
			settings->ext_device, settings->ext_device);

	/* Default.  Advanced Options chooses the method: drop the packet
	 * silently, or answer with an ICMP error -- the original called
	 * these STOP_TARGET=DROP and STOP_TARGET=REJECT. */
	if (settings->deny_packets)
		g_string_append (out,
			"\n# Everything else is dropped silently\n"
			"$IPT -A INBOUND -j LOG --log-prefix \"STOCKFW-DROP \" "
			"--log-level 6\n"
			"$IPT -A INBOUND -j DROP\n");
	else
		g_string_append (out,
			"\n# Everything else is answered with an error packet\n"
			"$IPT -A INBOUND -j LOG --log-prefix \"STOCKFW-REJECT \" "
			"--log-level 6\n"
			"$IPT -A INBOUND -j REJECT --reject-with "
			"icmp-host-unreachable\n");

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
			policy->kinds[FS_RULE_OUTBOUND_DENY_TO], "DROP", "-d");
		append_host_rules (out,
			policy->kinds[FS_RULE_OUTBOUND_DENY_FROM], "DROP", "-s");

		append_service_rules (out,
			policy->kinds[FS_RULE_OUTBOUND_DENY_SERVICE], "OUTBOUND", "DROP");
	}

	/* Allow rules. */
	append_host_rules (out, policy->kinds[FS_RULE_OUTBOUND_ALLOW_TO],
	                   "ACCEPT", "-d");
	append_host_rules (out, policy->kinds[FS_RULE_OUTBOUND_ALLOW_FROM],
	                   "ACCEPT", "-s");

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
		"# StockFW control script (generated - do not edit)\n\n"
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
		". /etc/stockfw/inbound/setup\n"
		". /etc/stockfw/outbound/setup\n\n"
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