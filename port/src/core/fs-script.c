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

#include <gio/gio.h>
#include <stdarg.h>
#include <string.h>

/* [ settings_fill ]
 * Every field from one reader: the table default (defaults_only) or the
 * stored value with the table default behind it.  One function for
 * both, so a fresh FsSettings and an unset key can never mean two
 * different things -- the defaults themselves live in fs-prefs.c. */
static gboolean
settings_bool (const gchar *key, gboolean defaults_only)
{
	if (defaults_only) {
		const FsPrefSpec *spec = fs_prefs_spec (key);

		g_return_val_if_fail (spec != NULL, FALSE);
		return spec->bool_default;
	}

	return fs_prefs_bool (key);
}

static gchar *
settings_device (const gchar *key, gboolean defaults_only)
{
	gchar *text;

	if (defaults_only) {
		const FsPrefSpec *spec = fs_prefs_spec (key);

		text = g_strdup (spec != NULL ? spec->string_default : NULL);
	} else {
		text = fs_prefs_string (key);
	}

	/* "" is "no device chosen", the same as unset. */
	if (text != NULL && *text == '\0') {
		g_free (text);
		text = NULL;
	}

	return text;
}

static void
settings_fill (FsSettings *settings, gboolean defaults_only)
{
	g_free (settings->ext_device);
	g_free (settings->int_device);
	settings->ext_device = settings_device (FS_PREFS_FW_EXT_IF, defaults_only);
	settings->int_device = settings_device (FS_PREFS_FW_INT_IF, defaults_only);

	settings->nat          = settings_bool (FS_PREFS_FW_NAT, defaults_only);
	settings->filter_icmp  = settings_bool (FS_PREFS_FW_FILTER_ICMP, defaults_only);
	settings->deny_packets = settings_bool (FS_PREFS_FW_DENY_PACKETS, defaults_only);
	settings->block_external_broadcast =
		settings_bool (FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST, defaults_only);
	settings->block_internal_broadcast =
		settings_bool (FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST, defaults_only);
	settings->block_non_routables =
		settings_bool (FS_PREFS_FW_BLOCK_NON_ROUTABLES, defaults_only);
	settings->restrictive_outbound =
		settings_bool (FS_PREFS_FW_RESTRICTIVE_OUTBOUND, defaults_only);
	settings->log_allowed =
		settings_bool (FS_PREFS_FW_LOG_ALLOWED, defaults_only);

	settings->icmp_echo_request =
		settings_bool (FS_PREFS_FW_ICMP_ECHO_REQUEST, defaults_only);
	settings->icmp_echo_reply =
		settings_bool (FS_PREFS_FW_ICMP_ECHO_REPLY, defaults_only);
	settings->icmp_traceroute =
		settings_bool (FS_PREFS_FW_ICMP_TRACEROUTE, defaults_only);
	settings->icmp_mstraceroute =
		settings_bool (FS_PREFS_FW_ICMP_MSTRACEROUTE, defaults_only);
	settings->icmp_unreachable =
		settings_bool (FS_PREFS_FW_ICMP_UNREACHABLE, defaults_only);
	settings->icmp_timestamping =
		settings_bool (FS_PREFS_FW_ICMP_TIMESTAMPING, defaults_only);
	settings->icmp_masking =
		settings_bool (FS_PREFS_FW_ICMP_MASKING, defaults_only);
	settings->icmp_redirection =
		settings_bool (FS_PREFS_FW_ICMP_REDIRECTION, defaults_only);
	settings->icmp_source_quenches =
		settings_bool (FS_PREFS_FW_ICMP_SOURCE_QUENCHES, defaults_only);
}

/* [ fs_settings_new ]
 * The defaults of a fresh install, from the settings table, whether or
 * not the preferences have been read yet. */
FsSettings *
fs_settings_new (void)
{
	FsSettings *settings = g_new0 (FsSettings, 1);

	settings_fill (settings, TRUE);

	return settings;
}

/* [ fs_settings_load_prefs ]
 * The Firewall pages of the Preferences window set these keys; reading
 * them here is what makes those pages mean something. */
void
fs_settings_load_prefs (FsSettings *settings)
{
	if (settings == NULL)
		return;

	settings_fill (settings, FALSE);
}

FsSettings *
fs_settings_copy (const FsSettings *settings)
{
	FsSettings *copy;

	if (settings == NULL)
		return NULL;

	copy = g_new (FsSettings, 1);
	*copy = *settings;
	copy->ext_device = g_strdup (settings->ext_device);
	copy->int_device = g_strdup (settings->int_device);

	return copy;
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

/* ================================================================
 * Generation, per address family (1.0.7)
 *
 * The same policy is rendered once for IPv4 (iptables) and once for
 * IPv6 (ip6tables).  The two differ in their ICMP rules, the reject
 * message, the reserved source ranges and which literal targets they
 * carry; everything else is shared.
 *
 * Two output forms:
 *   text      "$IPT ..." lines, one iptables invocation each (the
 *             inspectable script, and what the core suite reads);
 *   restore   iptables-restore input, which the Linux backend loads in
 *             one transaction per family.  In this form host names are
 *             resolved here, once, and written as addresses, so neither
 *             tool ever looks a name up itself and nothing a user typed
 *             reaches the restore parser except validated literals.
 * ================================================================ */

typedef struct
{
	GPtrArray *v4;           /* gchar* address text */
	GPtrArray *v6;
	GError    *error;        /* set when the lookup failed */
} Resolved;

static void
resolved_free (gpointer data)
{
	Resolved *r = data;

	g_ptr_array_unref (r->v4);
	g_ptr_array_unref (r->v6);
	g_clear_error (&r->error);
	g_free (r);
}

typedef struct
{
	const FsSettings *settings;
	FsFamily    family;      /* FS_FAMILY_IPV4 or FS_FAMILY_IPV6     */
	gboolean    resolve;     /* restore form: names become addresses */
	gboolean    lenient;     /* unresolvable blocks are skipped, not
	                          * fatal (FS_PLAN_LENIENT_BLOCKS)       */
	GHashTable *cache;       /* host -> Resolved*, shared by passes  */
	GPtrArray  *notes;       /* informational sentences (nullable)   */
	GPtrArray  *skipped;     /* rules not enforced (nullable)        */
	GError     *error;       /* first hard failure                   */
} Gen;

#define GEN_V6(g) ((g)->family == FS_FAMILY_IPV6)

static gboolean
default_resolve (const gchar *host, GPtrArray *v4, GPtrArray *v6,
                 GError **error)
{
	GResolver *resolver = g_resolver_get_default ();
	GList *addrs = g_resolver_lookup_by_name (resolver, host, NULL, error);

	g_object_unref (resolver);

	if (addrs == NULL)
		return FALSE;

	for (GList *l = addrs; l != NULL; l = l->next) {
		GInetAddress *addr = l->data;
		GPtrArray *dst = g_inet_address_get_family (addr) ==
		                 G_SOCKET_FAMILY_IPV6 ? v6 : v4;

		g_ptr_array_add (dst, g_inet_address_to_string (addr));
	}

	g_resolver_free_addresses (addrs);
	return TRUE;
}

static FsScriptResolveFunc script_resolver = NULL;

void
fs_script_set_resolver (FsScriptResolveFunc func)
{
	script_resolver = func;
}

GQuark
fs_script_error_quark (void)
{
	return g_quark_from_static_string ("fs-script-error");
}

static void
add_unique (GPtrArray *list, gchar *text)
{
	if (list == NULL) {
		g_free (text);
		return;
	}

	for (guint i = 0; i < list->len; i++)
		if (strcmp (g_ptr_array_index (list, i), text) == 0) {
			g_free (text);
			return;
		}

	g_ptr_array_add (list, text);
}

static void
gen_fail (Gen *g, gint code, const gchar *format, ...) G_GNUC_PRINTF (3, 4);

static void
gen_fail (Gen *g, gint code, const gchar *format, ...)
{
	va_list ap;
	gchar *text;

	if (g->error != NULL)
		return;          /* the first failure is the one reported */

	va_start (ap, format);
	text = g_strdup_vprintf (format, ap);
	va_end (ap);

	g->error = g_error_new_literal (FS_SCRIPT_ERROR, code, text);
	g_free (text);
}

/* Only an address matches only one family, and only the canonical
 * text of a literal is ever written in restore form. */
static Resolved *
lookup_host (Gen *g, const gchar *host)
{
	Resolved *r = g_hash_table_lookup (g->cache, host);
	FsScriptResolveFunc func = script_resolver != NULL ? script_resolver
	                                                   : default_resolve;

	if (r != NULL)
		return r;

	r = g_new0 (Resolved, 1);
	r->v4 = g_ptr_array_new_with_free_func (g_free);
	r->v6 = g_ptr_array_new_with_free_func (g_free);

	if (!func (host, r->v4, r->v6, &r->error)) {
		if (r->error == NULL)
			r->error = g_error_new_literal (FS_SCRIPT_ERROR,
			                                FS_SCRIPT_ERR_RESOLVE,
			                                "lookup failed");
		g_ptr_array_set_size (r->v4, 0);
		g_ptr_array_set_size (r->v6, 0);
	} else {
		/* Keep only what parses as an address of its family, in
		 * canonical form: a resolver is an input like any other. */
		GPtrArray *lists[2] = { r->v4, r->v6 };

		for (gint k = 0; k < 2; k++) {
			GPtrArray *clean = g_ptr_array_new_with_free_func (g_free);

			for (guint i = 0; i < lists[k]->len; i++) {
				GInetAddress *a = g_inet_address_new_from_string (
					g_ptr_array_index (lists[k], i));

				if (a != NULL &&
				    g_inet_address_get_family (a) ==
				    (k == 0 ? G_SOCKET_FAMILY_IPV4
				            : G_SOCKET_FAMILY_IPV6))
					add_unique (clean,
					            g_inet_address_to_string (a));
				if (a != NULL)
					g_object_unref (a);
			}

			g_ptr_array_set_size (lists[k], 0);
			for (guint i = 0; i < clean->len; i++)
				g_ptr_array_add (lists[k],
				                 g_strdup (g_ptr_array_index (clean, i)));
			g_ptr_array_unref (clean);
		}
	}

	g_hash_table_insert (g->cache, g_strdup (host), r);
	return r;
}

/* [ gen_addresses ]
 * What to write for `target' in this pass: a list of address texts, or
 * a single NULL entry for "everyone" (no address match at all).  An
 * empty list means the rule has nothing to say about this family.
 *
 * deny says what a failed lookup costs.  An allow rule that cannot be
 * resolved is left out (the firewall fails closed) and reported as
 * skipped; a block that cannot be resolved fails the whole apply,
 * because leaving it out would let through what the user blocked. */
static GPtrArray *
gen_addresses (Gen *g, const gchar *target, gboolean deny)
{
	GPtrArray *out = g_ptr_array_new_with_free_func (g_free);
	FsFamily fam;
	Resolved *r;
	GPtrArray *mine;

	if (fs_util_target_is_anyone (target)) {
		g_ptr_array_add (out, NULL);
		return out;
	}

	fam = fs_util_target_families (target);

	if (fam == FS_FAMILY_NONE) {
		if (deny)
			gen_fail (g, FS_SCRIPT_ERR_INVALID,
			          _("\"%s\" is not an address or host name, so "
			            "it cannot be blocked."), target);
		else if (g->family == FS_FAMILY_IPV4)
			add_unique (g->skipped, g_strdup_printf (
				_("\"%s\" is not an address or host name; its "
				  "rule was left out."), target));
		return out;
	}

	if (fam != FS_FAMILY_BOTH) {
		/* A literal: its own family only. */
		if ((fam & g->family) != 0)
			g_ptr_array_add (out, g_strdup (target));
		return out;
	}

	/* A host name. */
	if (!g->resolve) {
		/* The text form keeps the name; iptables resolves it. */
		if (g->family == FS_FAMILY_IPV4)
			g_ptr_array_add (out, g_strdup (target));
		return out;
	}

	r = lookup_host (g, target);

	if (r->error != NULL) {
		if (deny && !g->lenient)
			gen_fail (g, FS_SCRIPT_ERR_RESOLVE,
			          _("Cannot block %s: its address could not be "
			            "looked up (%s). Nothing was changed."),
			          target, r->error->message);
		else if (deny && g->family == FS_FAMILY_IPV4)
			add_unique (g->skipped, g_strdup_printf (
				_("NOT BLOCKED: %s could not be looked up (%s). "
				  "Apply the policy again once name lookups work."),
				target, r->error->message));
		else if (g->family == FS_FAMILY_IPV4)
			add_unique (g->skipped, g_strdup_printf (
				_("%s could not be looked up (%s); its rules "
				  "were left out."), target, r->error->message));
		return out;
	}

	mine = GEN_V6 (g) ? r->v6 : r->v4;

	if (mine->len == 0) {
		GPtrArray *other = GEN_V6 (g) ? r->v4 : r->v6;

		if (other->len > 0)
			add_unique (g->notes, g_strdup_printf (
				GEN_V6 (g)
				? _("%s has no IPv6 address; its rules cover IPv4 only.")
				: _("%s has no IPv4 address; its rules cover IPv6 only."),
				target));
		else if (g->family == FS_FAMILY_IPV4) {
			if (deny && !g->lenient)
				gen_fail (g, FS_SCRIPT_ERR_RESOLVE,
				          _("Cannot block %s: it has no address."),
				          target);
			else if (deny)
				add_unique (g->skipped, g_strdup_printf (
					_("NOT BLOCKED: %s has no address."),
					target));
			else
				add_unique (g->skipped, g_strdup_printf (
					_("%s has no address; its rules were "
					  "left out."), target));
		}
		return out;
	}

	for (guint i = 0; i < mine->len; i++)
		g_ptr_array_add (out, g_strdup (g_ptr_array_index (mine, i)));

	return out;
}

/* [ ipt_port ]
 * iptables writes a port range with ':'; the policy files also use
 * '-' ("67-68"), which iptables refuses.  NULL when the port is not
 * valid at all. */
static gchar *
ipt_port (const gchar *port)
{
	gchar *out;

	if (!fs_util_is_valid_port (port))
		return NULL;

	out = g_strdup (port);
	g_strdelimit (out, "-", ':');
	return out;
}

/* [ gen_ifname ]
 * An interface name as it may be written, or NULL (and, in restore
 * form, a failed generation) when it is not a valid name. */
static const gchar *
gen_ifname (Gen *g, const gchar *name, const gchar *what)
{
	if (name == NULL || *name == '\0')
		return NULL;

	if (fs_util_is_valid_ifname (name))
		return name;

	if (g->resolve)
		gen_fail (g, FS_SCRIPT_ERR_INVALID,
		          _("The %s interface name \"%s\" is not valid."),
		          what, name);
	return NULL;
}

/* [ accept_target ]
 * Where a policy ACCEPT jumps: the logging chain, or plain ACCEPT. */
static const gchar *
accept_target (const FsSettings *settings)
{
	return (settings != NULL && settings->log_allowed)
	       ? FS_SCRIPT_ACCEPT_CHAIN : "ACCEPT";
}

/* [ append_accept_chain ]
 * The logging accept chain.  Both directions' scripts declare it (each
 * may be applied alone); -N on an existing chain fails harmlessly and
 * -F makes the second declaration a no-op. */
static void
append_accept_chain (GString *out, const FsSettings *settings)
{
	if (settings == NULL || !settings->log_allowed)
		return;

	g_string_append_printf (out,
		"# Log the first packet of each accepted new connection "
		"(sampled), then accept\n"
		"$IPT -N %1$s\n"
		"$IPT -F %1$s\n"
		"$IPT -A %1$s -m conntrack --ctstate NEW -m limit --limit %2$s "
		"--limit-burst %3$s -j LOG --log-prefix \"STOCKFW-ALLOW \" "
		"--log-level 6\n"
		"$IPT -A %1$s -j ACCEPT\n\n",
		FS_SCRIPT_ACCEPT_CHAIN, FS_SCRIPT_ALLOW_LOG_RATE,
		FS_SCRIPT_ALLOW_LOG_BURST);
}

/* [ append_host_rules ]
 * One address match per line for host-based rules.  iptables has no
 * -H: outbound "to host" rules match the destination (-d) and "from
 * host" rules the source (-s).  (Before 1.0.7 these lines had no
 * "-A OUTBOUND" at all, which iptables refuses, so any outbound host
 * rule failed the whole apply.) */
static void
append_host_rules (Gen *g, GString *out, GPtrArray *rules,
                   const gchar *jump, const gchar *match, gboolean deny)
{
	for (guint i = 0; i < rules->len; i++) {
		FsRule *rule = g_ptr_array_index (rules, i);
		GPtrArray *addrs;

		if (rule->target == NULL || *rule->target == '\0' ||
		    fs_util_target_is_anyone (rule->target))
			continue;

		addrs = gen_addresses (g, rule->target, deny);
		for (guint a = 0; a < addrs->len; a++)
			g_string_append_printf (out,
				"$IPT -A OUTBOUND %s %s -j %s\n", match,
				(const gchar *) g_ptr_array_index (addrs, a), jump);
		g_ptr_array_unref (addrs);
	}
}

/* [ append_service_rules ]
 * The tcp/udp pair for each service rule, per address of its target. */
static void
append_service_rules (Gen *g, GString *out, GPtrArray *rules,
                      const gchar *chain, const gchar *jump, gboolean deny)
{
	for (guint i = 0; i < rules->len; i++) {
		FsRule *rule = g_ptr_array_index (rules, i);
		gchar *port;
		GPtrArray *addrs;

		if (rule->port == NULL || *rule->port == '\0')
			continue;

		port = ipt_port (rule->port);
		if (port == NULL) {
			if (deny && g->resolve)
				gen_fail (g, FS_SCRIPT_ERR_INVALID,
				          _("\"%s\" is not a valid port, so it "
				            "cannot be blocked."), rule->port);
			else if (g->family == FS_FAMILY_IPV4)
				add_unique (g->skipped, g_strdup_printf (
					_("\"%s\" is not a valid port; its rule "
					  "was left out."), rule->port));
			continue;
		}

		addrs = gen_addresses (g, rule->target, deny);

		for (guint a = 0; a < addrs->len; a++) {
			const gchar *addr = g_ptr_array_index (addrs, a);
			gchar *src = addr != NULL ? g_strdup_printf ("-s %s ", addr)
			                          : g_strdup ("");

			g_string_append_printf (out,
				"$IPT -A %s %s-p tcp --dport %s -j %s\n"
				"$IPT -A %s %s-p udp --dport %s -j %s\n",
				chain, src, port, jump, chain, src, port, jump);
			g_free (src);
		}

		g_ptr_array_unref (addrs);
		g_free (port);
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

/* [ append_icmp6_essentials ]
 * What IPv6 itself needs (RFC 4890): path-MTU discovery, the error
 * reports, neighbour discovery and multicast listener discovery.
 * Unlike ARP, which never passes through iptables, neighbour discovery
 * is ICMPv6, so without these an IPv6 host cannot even find its router.
 * Always on, never rate-limited (a ping flood must not be able to
 * starve neighbour discovery), and the link-local ones demand hop
 * limit 255 -- proof the packet was not routed here from elsewhere. */
static void
append_icmp6_essentials (GString *out)
{
	g_string_append (out,
		"# IPv6 needs these to work at all (RFC 4890)\n"
		"$IPT -A INBOUND -p ipv6-icmp --icmpv6-type packet-too-big -j ACCEPT\n"
		"$IPT -A INBOUND -p ipv6-icmp --icmpv6-type time-exceeded -j ACCEPT\n"
		"$IPT -A INBOUND -p ipv6-icmp --icmpv6-type parameter-problem -j ACCEPT\n"
		"$IPT -A INBOUND -s fe80::/10 -p ipv6-icmp --icmpv6-type "
		"router-advertisement -m hl --hl-eq 255 -j ACCEPT\n"
		"$IPT -A INBOUND -p ipv6-icmp --icmpv6-type neighbour-solicitation "
		"-m hl --hl-eq 255 -j ACCEPT\n"
		"$IPT -A INBOUND -p ipv6-icmp --icmpv6-type neighbour-advertisement "
		"-m hl --hl-eq 255 -j ACCEPT\n"
		"# Multicast listener discovery (130-132, and 143 = MLDv2 report)\n"
		"$IPT -A INBOUND -p ipv6-icmp --icmpv6-type 130 -m hl --hl-eq 1 -j ACCEPT\n"
		"$IPT -A INBOUND -p ipv6-icmp --icmpv6-type 131 -m hl --hl-eq 1 -j ACCEPT\n"
		"$IPT -A INBOUND -p ipv6-icmp --icmpv6-type 132 -m hl --hl-eq 1 -j ACCEPT\n"
		"$IPT -A INBOUND -p ipv6-icmp --icmpv6-type 143 -m hl --hl-eq 1 -j ACCEPT\n"
		"# DHCPv6 answers come from the server's link-local address\n"
		"$IPT -A INBOUND -s fe80::/10 -p udp --sport 547 --dport 546 -j ACCEPT\n");
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
 * makes path-MTU discovery and traceroute loop reports work.
 *
 * IPv6 (1.0.7): the essentials above come first, then the same
 * checkboxes mapped to their ICMPv6 types.  Timestamps, address masks
 * and source quench have no ICMPv6 counterpart and stay IPv4-only. */
static void
append_icmp_rules (Gen *g, GString *out)
{
	const FsSettings *settings = g->settings;
	const gchar *proto = GEN_V6 (g) ? "ipv6-icmp" : "icmp";
	const gchar *opt = GEN_V6 (g) ? "--icmpv6-type" : "--icmp-type";

	if (GEN_V6 (g))
		append_icmp6_essentials (out);

	if (!settings->filter_icmp) {
		g_string_append_printf (out,
			"# ICMP filtering is off: allow all ICMP\n"
			"$IPT -A INBOUND -p %s -m limit --limit 10/s -j ACCEPT\n\n",
			proto);
		return;
	}

	g_string_append (out,
		"# Only the ICMP types ticked in Preferences are allowed\n");
	if (!GEN_V6 (g))
		g_string_append (out,
			"$IPT -A INBOUND -p icmp --icmp-type time-exceeded -j ACCEPT\n"
			"$IPT -A INBOUND -p icmp --icmp-type parameter-problem -j ACCEPT\n");

	if (settings->icmp_echo_request)
		g_string_append_printf (out,
			"# ICMP: Ping requests\n"
			"$IPT -A INBOUND -p %s %s echo-request "
			"-m limit --limit 1/s -j ACCEPT\n", proto, opt);

	if (settings->icmp_echo_reply)
		g_string_append_printf (out,
			"# ICMP: Ping replies\n"
			"$IPT -A INBOUND -p %s %s echo-reply "
			"-m limit --limit 1/s -j ACCEPT\n", proto, opt);

	/* Not ICMP: the original opened UDP 33434 for traceroute. */
	if (settings->icmp_traceroute)
		g_string_append (out,
			"# ICMP: Traceroute requests (UDP 33434, as in the original)\n"
			"$IPT -A INBOUND -p udp --dport 33434 -j ACCEPT\n");

	if (settings->icmp_mstraceroute)
		g_string_append_printf (out,
			"# ICMP: MS Traceroute\n"
			"$IPT -A INBOUND -p %s %s destination-unreachable "
			"-j ACCEPT\n", proto, opt);

	if (settings->icmp_unreachable)
		g_string_append_printf (out,
			"# ICMP: Unreachable\n"
			"$IPT -A INBOUND -p %s %s %s -j ACCEPT\n", proto, opt,
			GEN_V6 (g) ? "address-unreachable" : "host-unreachable");

	if (settings->icmp_timestamping && !GEN_V6 (g))
		g_string_append (out,
			"# ICMP: Timestamping\n"
			"$IPT -A INBOUND -p icmp --icmp-type timestamp-request -j ACCEPT\n"
			"$IPT -A INBOUND -p icmp --icmp-type timestamp-reply -j ACCEPT\n");

	if (settings->icmp_masking && !GEN_V6 (g))
		g_string_append (out,
			"# ICMP: Address masking\n"
			"$IPT -A INBOUND -p icmp --icmp-type address-mask-request -j ACCEPT\n"
			"$IPT -A INBOUND -p icmp --icmp-type address-mask-reply -j ACCEPT\n");

	if (settings->icmp_redirection) {
		if (GEN_V6 (g))
			/* An IPv6 redirect is only valid from a link-local
			 * router on this link (RFC 4861 8.1). */
			g_string_append (out,
				"# ICMP: Redirection\n"
				"$IPT -A INBOUND -s fe80::/10 -p ipv6-icmp --icmpv6-type "
				"redirect -m hl --hl-eq 255 -m limit --limit 2/s "
				"-j ACCEPT\n");
		else
			g_string_append (out,
				"# ICMP: Redirection\n"
				"$IPT -A INBOUND -p icmp --icmp-type redirect "
				"-m limit --limit 2/s -j ACCEPT\n");
	}

	if (settings->icmp_source_quenches && !GEN_V6 (g))
		g_string_append (out,
			"# ICMP: Source quench\n"
			"$IPT -A INBOUND -p icmp --icmp-type source-quench "
			"-m limit --limit 2/s -j ACCEPT\n");

	g_string_append (out,
		"# Anything else falls through to the default action\n\n");
}

/* [ gen_forward_to ]
 * A port forward's destination as DNAT writes it ("192.0.2.5:80",
 * "[2001:db8::5]:80" -- without the brackets ip6tables reads the port
 * as part of the address), or NULL when the forward is not this
 * family's.  The destination must be an address: a forward that
 * silently went wherever a name resolved to at apply time would be a
 * surprise. */
static gchar *
gen_forward_to (Gen *g, const FsRule *rule, gchar **port_out)
{
	FsFamily fam;
	gchar *to_port;

	*port_out = NULL;

	if (rule->port == NULL || rule->to == NULL || rule->to_port == NULL)
		return NULL;

	fam = fs_util_target_families (rule->to);

	if (fam == FS_FAMILY_NONE || fam == FS_FAMILY_BOTH ||
	    strchr (rule->to, '/') != NULL) {
		if (g->family == FS_FAMILY_IPV4)
			add_unique (g->skipped, g_strdup_printf (
				_("The forward to \"%s\" was left out: a forward "
				  "needs an IP address, not a name or a range."),
				rule->to));
		return NULL;
	}

	if ((fam & g->family) == 0)
		return NULL;

	*port_out = ipt_port (rule->port);
	to_port = ipt_port (rule->to_port);

	if (*port_out == NULL || to_port == NULL || strchr (to_port, ':')) {
		if (g->family == FS_FAMILY_IPV4 || fam == FS_FAMILY_IPV6)
			add_unique (g->skipped, g_strdup_printf (
				_("The forward to %s was left out: its ports are "
				  "not valid."), rule->to));
		g_clear_pointer (port_out, g_free);
		g_free (to_port);
		return NULL;
	}

	{
		gchar *out = GEN_V6 (g)
			? g_strdup_printf ("[%s]:%s", rule->to, to_port)
			: g_strdup_printf ("%s:%s", rule->to, to_port);

		g_free (to_port);
		return out;
	}
}

static gchar *
generate_inbound (Gen *g, const FsPolicy *policy)
{
	const FsSettings *settings = g->settings;
	const gchar *ext = gen_ifname (g, settings->ext_device, _("external"));
	const gchar *intf = gen_ifname (g, settings->int_device, _("internal"));
	GString *out;

	out = script_preamble ("INBOUND");

	append_accept_chain (out, settings);
	append_icmp_rules (g, out);

	/* Connection state.  The original opened with -m state which lets
	 * inbound traffic spoof a RELATED state; NEW is the safe default. */
	g_string_append (out,
		"# Accept return traffic for connections we started\n"
		"$IPT -A INBOUND -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n\n");

	/* Loopback is always trusted. */
	g_string_append (out,
		"# Trust loopback\n"
		"$IPT -A INBOUND -i lo -j ACCEPT\n\n");

	if (settings->nat && intf != NULL) {
		g_string_append (out,
			"# Accept traffic arriving on the internal interface\n");
		g_string_append_printf (out,
			"$IPT -A INBOUND -i %s -j ACCEPT\n\n", intf);
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
		GPtrArray *addrs;

		if (rule->target == NULL || *rule->target == '\0')
			continue;

		addrs = gen_addresses (g, rule->target, FALSE);
		for (guint a = 0; a < addrs->len; a++) {
			const gchar *addr = g_ptr_array_index (addrs, a);

			if (addr != NULL)
				g_string_append_printf (out,
					"$IPT -A INBOUND -s %s -j %s\n", addr,
					accept_target (settings));
			else
				g_string_append_printf (out,
					"$IPT -A INBOUND -j %s\n",
					accept_target (settings));
		}
		g_ptr_array_unref (addrs);
	}

	append_service_rules (g, out,
		policy->kinds[FS_RULE_INBOUND_ALLOW_SERVICE], "INBOUND",
		accept_target (settings), FALSE);

	/* Port forwards: the DNAT itself is in the nat table
	 * (fs_script_generate_nat); what arrives after it is let through
	 * here.  Before 1.0.7 nothing was, so a forward to another machine
	 * was rewritten and then dropped by FORWARD -> INBOUND. */
	for (guint i = 0; i < policy->kinds[FS_RULE_INBOUND_FORWARD]->len; i++) {
		FsRule *rule = g_ptr_array_index (
			policy->kinds[FS_RULE_INBOUND_FORWARD], i);
		gchar *port = NULL;
		gchar *to = gen_forward_to (g, rule, &port);
		gchar *to_port;

		if (to == NULL)
			continue;

		to_port = ipt_port (rule->to_port);
		g_string_append_printf (out,
			"$IPT -A INBOUND -d %s -p tcp --dport %s -m conntrack "
			"--ctstate DNAT -j %s\n", rule->to, to_port,
			accept_target (settings));
		g_free (to_port);
		g_free (port);
		g_free (to);
	}

	/* Advanced Options: broadcast traffic.  Each is scoped to the
	 * interface it belongs to, as the original's rules were.  IPv6 has
	 * no broadcast. */
	if (settings->block_external_broadcast && ext != NULL && !GEN_V6 (g))
		g_string_append_printf (out,
			"# Block broadcasts arriving from outside\n"
			"$IPT -A INBOUND -i %s -d 255.255.255.255 -j DROP\n", ext);

	if (settings->block_internal_broadcast && settings->nat &&
	    intf != NULL && !GEN_V6 (g))
		g_string_append_printf (out,
			"# Block broadcasts arriving on the local network\n"
			"$IPT -A INBOUND -i %s -d 255.255.255.255 -j DROP\n", intf);

	/* Advanced Options: reserved addresses.  Source addresses that
	 * cannot be genuine on the external interface are spoofed and
	 * refused.  For IPv6 these are loopback, IPv4-mapped and the
	 * documentation prefix; unique local addresses (fc00::/7) are
	 * left alone because home networks use them. */
	if (settings->block_non_routables && ext != NULL) {
		if (GEN_V6 (g))
			g_string_append_printf (out,
				"# Refuse reserved addresses arriving from outside\n"
				"$IPT -A INBOUND -i %1$s -s ::1/128 -j DROP\n"
				"$IPT -A INBOUND -i %1$s -s ::ffff:0:0/96 -j DROP\n"
				"$IPT -A INBOUND -i %1$s -s 2001:db8::/32 -j DROP\n",
				ext);
		else
			g_string_append_printf (out,
				"# Refuse reserved addresses arriving from outside\n"
				"$IPT -A INBOUND -i %1$s -s 10.0.0.0/8 -j DROP\n"
				"$IPT -A INBOUND -i %1$s -s 172.16.0.0/12 -j DROP\n"
				"$IPT -A INBOUND -i %1$s -s 192.168.0.0/16 -j DROP\n"
				"$IPT -A INBOUND -i %1$s -s 127.0.0.0/8 -j DROP\n",
				ext);
	}

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
		g_string_append_printf (out,
			"\n# Everything else is answered with an error packet\n"
			"$IPT -A INBOUND -j LOG --log-prefix \"STOCKFW-REJECT \" "
			"--log-level 6\n"
			"$IPT -A INBOUND -j REJECT --reject-with %s\n",
			GEN_V6 (g) ? "icmp6-addr-unreachable"
			           : "icmp-host-unreachable");

	return g_string_free (out, FALSE);
}

static gchar *
generate_outbound (Gen *g, const FsPolicy *policy)
{
	const FsSettings *settings = g->settings;
	const gchar *ext = gen_ifname (g, settings->ext_device, _("external"));
	GString *out;

	out = script_preamble ("OUTBOUND");

	append_accept_chain (out, settings);

	/* Loopback goes OUT on lo: an "-i lo" match can never be true in
	 * OUTPUT, which before 1.0.7 left restrictive mode dropping every
	 * new loopback connection (127.0.0.53, the systemd-resolved stub,
	 * included). */
	g_string_append (out,
		"# Accept return traffic\n"
		"$IPT -A OUTBOUND -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
		"$IPT -A OUTBOUND -o lo -j ACCEPT\n");

	if (settings->filter_icmp)
		g_string_append_printf (out, "$IPT -A OUTBOUND -p %s -j ACCEPT\n",
		                        GEN_V6 (g) ? "ipv6-icmp" : "icmp");

	if (GEN_V6 (g))
		/* Neighbour discovery, router solicitation, listener reports
		 * and DHCPv6 leave without a connection to be part of, so no
		 * ESTABLISHED rule covers them; restrictive mode would
		 * otherwise drop them and IPv6 would stop working. */
		g_string_append (out,
			"# IPv6 needs these to work at all\n"
			"$IPT -A OUTBOUND -p ipv6-icmp --icmpv6-type neighbour-solicitation "
			"-m hl --hl-eq 255 -j ACCEPT\n"
			"$IPT -A OUTBOUND -p ipv6-icmp --icmpv6-type neighbour-advertisement "
			"-m hl --hl-eq 255 -j ACCEPT\n"
			"$IPT -A OUTBOUND -p ipv6-icmp --icmpv6-type router-solicitation "
			"-m hl --hl-eq 255 -j ACCEPT\n"
			"$IPT -A OUTBOUND -p ipv6-icmp --icmpv6-type 131 -m hl --hl-eq 1 -j ACCEPT\n"
			"$IPT -A OUTBOUND -p ipv6-icmp --icmpv6-type 132 -m hl --hl-eq 1 -j ACCEPT\n"
			"$IPT -A OUTBOUND -p ipv6-icmp --icmpv6-type 143 -m hl --hl-eq 1 -j ACCEPT\n"
			"$IPT -A OUTBOUND -p ipv6-icmp --icmpv6-type packet-too-big -j ACCEPT\n"
			"$IPT -A OUTBOUND -p udp --sport 546 --dport 547 -j ACCEPT\n");

	g_string_append (out, "\n# Outbound policy\n");

	/* Deny rules come first, in BOTH modes.  They used to be emitted
	 * in restrictive mode only -- where the default already drops --
	 * so in the default permissive mode the Policy page's "Deny
	 * connections to host" rows were shown, saved, and never reached
	 * the kernel. */
	g_string_append (out, "# Deny rules are applied first\n");

	append_host_rules (g, out,
		policy->kinds[FS_RULE_OUTBOUND_DENY_TO], "DROP", "-d", TRUE);
	append_host_rules (g, out,
		policy->kinds[FS_RULE_OUTBOUND_DENY_FROM], "DROP", "-s", TRUE);

	append_service_rules (g, out,
		policy->kinds[FS_RULE_OUTBOUND_DENY_SERVICE], "OUTBOUND", "DROP",
		TRUE);

	/* Router mode lets what leaves on the external interface go --
	 * after the blocks, which it used to come before, so in router
	 * mode no "deny" row reached the traffic it named. */
	if (settings->nat && ext != NULL)
		g_string_append_printf (out,
			"$IPT -A OUTBOUND -o %s -j ACCEPT\n", ext);

	/* Allow rules. */
	append_host_rules (g, out, policy->kinds[FS_RULE_OUTBOUND_ALLOW_TO],
	                   accept_target (settings), "-d", FALSE);
	append_host_rules (g, out, policy->kinds[FS_RULE_OUTBOUND_ALLOW_FROM],
	                   accept_target (settings), "-s", FALSE);

	append_service_rules (g, out,
		policy->kinds[FS_RULE_OUTBOUND_ALLOW_SERVICE], "OUTBOUND",
		accept_target (settings), FALSE);

	if (settings->restrictive_outbound)
		g_string_append (out,
			"\n# Restrictive mode: default deny\n"
			"$IPT -A OUTBOUND -m limit --limit 20/s --limit-burst 40 "
			"-j LOG --log-prefix \"STOCKFW-DROP \" --log-level 6\n"
			"$IPT -A OUTBOUND -j DROP\n");
	else
		g_string_append_printf (out,
			"\n# Permissive mode: default accept\n"
			"$IPT -A OUTBOUND -j %s\n", accept_target (settings));

	return g_string_free (out, FALSE);
}

/* [ generate_nat ]
 * The nat table's part: port forwards (DNAT) in STOCKFW-DNAT, and
 * masquerading for router mode (IPv4 only) in STOCKFW-SNAT.  Lines are
 * "$IPT -t nat -A ...".  Empty when there is nothing to do. */
static gchar *
generate_nat (Gen *g, const FsPolicy *policy)
{
	const FsSettings *settings = g->settings;
	const gchar *ext = gen_ifname (g, settings->ext_device, _("external"));
	GString *out = g_string_new (NULL);

	for (guint i = 0; i < policy->kinds[FS_RULE_INBOUND_FORWARD]->len; i++) {
		FsRule *rule = g_ptr_array_index (
			policy->kinds[FS_RULE_INBOUND_FORWARD], i);
		gchar *port = NULL;
		gchar *to = gen_forward_to (g, rule, &port);

		if (to == NULL)
			continue;

		if (ext == NULL) {
			if (g->family == FS_FAMILY_IPV4 ||
			    fs_util_target_families (rule->to) == FS_FAMILY_IPV6)
				add_unique (g->skipped, g_strdup_printf (
					_("The forward to %s was left out: no "
					  "external interface is set."), rule->to));
		} else {
			g_string_append_printf (out,
				"# Forward %s to %s\n"
				"$IPT -t nat -A " FS_SCRIPT_DNAT_CHAIN " -i %s -p tcp "
				"--dport %s -j DNAT --to-destination %s\n",
				rule->service != NULL &&
				fs_util_is_valid_ifname (rule->service)
					? rule->service : "service",
				to, ext, port, to);
		}

		g_free (port);
		g_free (to);
	}

	if (settings->nat && ext != NULL && !GEN_V6 (g))
		g_string_append_printf (out,
			"# Router mode: masquerade what leaves on %s\n"
			"$IPT -t nat -A " FS_SCRIPT_SNAT_CHAIN " -o %s -j MASQUERADE\n",
			ext, ext);

	return g_string_free (out, FALSE);
}

static Gen *
gen_new (const FsSettings *settings, FsFamily family, gboolean resolve,
         GHashTable *cache)
{
	Gen *g = g_new0 (Gen, 1);

	g->settings = settings;
	g->family = family;
	g->resolve = resolve;
	g->cache = cache != NULL
		? g_hash_table_ref (cache)
		: g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
		                         resolved_free);
	return g;
}

static void
gen_free (Gen *g)
{
	g_hash_table_unref (g->cache);
	g_clear_error (&g->error);
	g_free (g);
}

gchar *
fs_script_generate_inbound_family (const FsPolicy *policy,
                                   const FsSettings *settings,
                                   FsFamily family)
{
	Gen *g;
	gchar *out;

	if (policy == NULL || settings == NULL ||
	    (family != FS_FAMILY_IPV4 && family != FS_FAMILY_IPV6))
		return g_strdup ("");

	g = gen_new (settings, family, FALSE, NULL);
	out = generate_inbound (g, policy);
	gen_free (g);
	return out;
}

gchar *
fs_script_generate_outbound_family (const FsPolicy *policy,
                                    const FsSettings *settings,
                                    FsFamily family)
{
	Gen *g;
	gchar *out;

	if (policy == NULL || settings == NULL ||
	    (family != FS_FAMILY_IPV4 && family != FS_FAMILY_IPV6))
		return g_strdup ("");

	g = gen_new (settings, family, FALSE, NULL);
	out = generate_outbound (g, policy);
	gen_free (g);
	return out;
}

gchar *
fs_script_generate_inbound (const FsPolicy *policy,
                            const FsSettings *settings)
{
	return fs_script_generate_inbound_family (policy, settings,
	                                          FS_FAMILY_IPV4);
}

gchar *
fs_script_generate_outbound (const FsPolicy *policy,
                             const FsSettings *settings)
{
	return fs_script_generate_outbound_family (policy, settings,
	                                           FS_FAMILY_IPV4);
}

/* ---- restore form ------------------------------------------------- */

/* [ line_is_safe ]
 * Defence in depth for iptables-restore input: a rule line holds only
 * the characters rules are made of, and a double quote only in the
 * one place the generator puts one (--log-prefix "STOCKFW-..."). */
static gboolean
line_is_safe (const gchar *line)
{
	const gchar *quote = strchr (line, '"');

	for (const gchar *p = line; *p != '\0'; p++)
		if (!g_ascii_isalnum (*p) && strchr (" -_.:/[]!,@\"", *p) == NULL)
			return FALSE;

	if (quote != NULL) {
		const gchar *close;

		if (quote < line + 13 ||
		    strncmp (quote - 13, "--log-prefix ", 13) != 0 ||
		    strncmp (quote + 1, "STOCKFW-", 8) != 0)
			return FALSE;
		close = strchr (quote + 1, '"');
		if (close == NULL || strchr (close + 1, '"') != NULL)
			return FALSE;
	}

	return TRUE;
}

typedef struct
{
	GPtrArray *chains;      /* declared, in order */
	GPtrArray *lines;       /* "-A ..." */
} Table;

static void
table_init (Table *t)
{
	t->chains = g_ptr_array_new_with_free_func (g_free);
	t->lines = g_ptr_array_new_with_free_func (g_free);
}

static void
table_clear (Table *t)
{
	g_ptr_array_unref (t->chains);
	g_ptr_array_unref (t->lines);
}

static void
table_declare (Table *t, const gchar *chain)
{
	for (guint i = 0; i < t->chains->len; i++)
		if (strcmp (g_ptr_array_index (t->chains, i), chain) == 0)
			return;
	g_ptr_array_add (t->chains, g_strdup (chain));
}

/* -F after an earlier declaration starts the chain over, exactly as it
 * would when the text lines run one by one. */
static void
table_flush (Table *t, const gchar *chain)
{
	gchar *prefix = g_strdup_printf ("-A %s ", chain);

	for (guint i = t->lines->len; i > 0; i--)
		if (g_str_has_prefix (g_ptr_array_index (t->lines, i - 1), prefix))
			g_ptr_array_remove_index (t->lines, i - 1);
	g_free (prefix);
}

/* [ absorb ]
 * Moves the "$IPT ..." lines of a text script into the two tables. */
static gboolean
absorb (Gen *g, Table *filter, Table *nat, const gchar *script)
{
	gchar **lines = g_strsplit (script, "\n", -1);
	gboolean ok = TRUE;

	for (gint i = 0; lines[i] != NULL && ok; i++) {
		const gchar *l = lines[i];
		Table *t = filter;

		if (*l == '\0' || *l == '#')
			continue;
		if (!g_str_has_prefix (l, "$IPT ")) {
			ok = FALSE;
			break;
		}
		l += 5;
		if (g_str_has_prefix (l, "-t nat ")) {
			t = nat;
			l += 7;
		}

		if (g_str_has_prefix (l, "-N "))
			table_declare (t, l + 3);
		else if (g_str_has_prefix (l, "-F "))
			table_flush (t, l + 3);
		else if (g_str_has_prefix (l, "-A ") && line_is_safe (l))
			g_ptr_array_add (t->lines, g_strdup (l));
		else
			ok = FALSE;
	}

	if (!ok)
		gen_fail (g, FS_SCRIPT_ERR_INVALID,
		          _("A generated rule failed the safety check; nothing "
		            "was applied."));

	g_strfreev (lines);
	return ok;
}

static gchar *
table_render (const gchar *name, Table *t, const gchar *const *extra_chains,
              const gchar *const *drop_chains)
{
	GString *out = g_string_new (NULL);

	g_string_append_printf (out, "*%s\n", name);

	for (guint i = 0; i < t->chains->len; i++)
		g_string_append_printf (out, ":%s - [0:0]\n",
		                        (const gchar *) g_ptr_array_index (t->chains, i));
	for (gint i = 0; extra_chains != NULL && extra_chains[i] != NULL; i++) {
		gboolean seen = FALSE;

		for (guint k = 0; k < t->chains->len; k++)
			if (strcmp (g_ptr_array_index (t->chains, k),
			            extra_chains[i]) == 0)
				seen = TRUE;
		if (!seen)
			g_string_append_printf (out, ":%s - [0:0]\n", extra_chains[i]);
	}

	for (guint i = 0; i < t->lines->len; i++)
		g_string_append_printf (out, "%s\n",
		                        (const gchar *) g_ptr_array_index (t->lines, i));

	for (gint i = 0; drop_chains != NULL && drop_chains[i] != NULL; i++)
		g_string_append_printf (out, "-X %s\n", drop_chains[i]);

	g_string_append (out, "COMMIT\n");
	return g_string_free (out, FALSE);
}

static void
build_part (Gen *g, const FsPolicy *policy, FsRestorePart *part)
{
	Table filter, nat;
	gchar *in, *out, *natsrc;

	table_init (&filter);
	table_init (&nat);

	in = generate_inbound (g, policy);
	out = generate_outbound (g, policy);
	natsrc = generate_nat (g, policy);

	if (g->error == NULL &&
	    absorb (g, &filter, &nat, in) && absorb (g, &filter, &nat, out) &&
	    absorb (g, &filter, &nat, natsrc)) {
		/* A chain the settings no longer use is created-and-deleted in
		 * the same transaction, so an apply also removes a leftover
		 * from the previous one without failing when there is none. */
		const gchar *log_chain[] = { FS_SCRIPT_ACCEPT_CHAIN, NULL };
		gboolean use_log = g->settings->log_allowed;

		part->filter = table_render ("filter", &filter,
		                             use_log ? NULL : log_chain,
		                             use_log ? NULL : log_chain);

		if (nat.lines->len > 0) {
			const gchar *nat_chains[] = { FS_SCRIPT_DNAT_CHAIN,
			                              FS_SCRIPT_SNAT_CHAIN, NULL };

			part->nat = table_render ("nat", &nat, nat_chains, NULL);
		}
	}

	g_free (in);
	g_free (out);
	g_free (natsrc);
	table_clear (&filter);
	table_clear (&nat);
}

FsRestorePlan *
fs_script_restore_plan (const FsPolicy *policy, const FsSettings *settings,
                        GError **error)
{
	return fs_script_restore_plan_ex (policy, settings,
	                                  FS_PLAN_STRICT_BLOCKS, error);
}

FsRestorePlan *
fs_script_restore_plan_ex (const FsPolicy *policy,
                           const FsSettings *settings, FsPlanBlocks blocks,
                           GError **error)
{
	FsRestorePlan *plan;
	GHashTable *cache;
	Gen *g4, *g6;

	g_return_val_if_fail (policy != NULL && settings != NULL, NULL);

	plan = g_new0 (FsRestorePlan, 1);
	plan->notes = g_ptr_array_new_with_free_func (g_free);
	plan->skipped = g_ptr_array_new_with_free_func (g_free);

	cache = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
	                               resolved_free);
	g4 = gen_new (settings, FS_FAMILY_IPV4, TRUE, cache);
	g6 = gen_new (settings, FS_FAMILY_IPV6, TRUE, cache);
	g_hash_table_unref (cache);

	g4->notes = g6->notes = plan->notes;
	g4->skipped = g6->skipped = plan->skipped;
	g4->lenient = g6->lenient = (blocks == FS_PLAN_LENIENT_BLOCKS);

	build_part (g4, policy, &plan->v4);
	if (g4->error == NULL)
		build_part (g6, policy, &plan->v6);

	if (g4->error != NULL || g6->error != NULL) {
		g_propagate_error (error, g4->error != NULL ? g4->error : g6->error);
		if (g4->error != NULL)
			g4->error = NULL;
		else
			g6->error = NULL;
		gen_free (g4);
		gen_free (g6);
		fs_restore_plan_free (plan);
		return NULL;
	}

	gen_free (g4);
	gen_free (g6);
	return plan;
}

void
fs_restore_plan_free (FsRestorePlan *plan)
{
	if (plan == NULL)
		return;

	g_free (plan->v4.filter);
	g_free (plan->v4.nat);
	g_free (plan->v6.filter);
	g_free (plan->v6.nat);
	g_ptr_array_unref (plan->notes);
	g_ptr_array_unref (plan->skipped);
	g_free (plan);
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