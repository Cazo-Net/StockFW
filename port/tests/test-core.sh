#!/bin/bash
# Core logic tests: rule CSV round-trip, port validation, service lookup
# and iptables script generation.  Pure GLib, so it runs on either
# platform without a display.
#
#   ./tests/test-core.sh

set -e

# Locate the toolchain: MSYS2's UCRT64 prefix on Windows, plain gcc
# elsewhere.
if [ -d /ucrt64/bin ]; then
  export PATH="/ucrt64/bin:$PATH"
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"

cd "$PORT"

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

cat > "$BUILD_DIR/test-core.c" <<'EOF'
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include "core/fs-rules.h"
#include "core/fs-util.h"
#include "core/fs-service.h"
#include "core/fs-script.h"
#include "core/fs-fwrule.h"
#include "core/fs-prefs.h"
#include "core/fs-copilot.h"
#include "core/fs-eventrule.h"
#include "core/fs-audit.h"
#include "core/fs-trust.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	if (!(cond)) {                                             \
		printf ("FAIL: ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
		failures++;                                         \
	} else {                                                  \
		printf ("ok:   ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
	}                                                         \
} while (0)

static void test_ports (void)
{
	CHECK (fs_util_is_valid_port ("80"), "port 80");
	CHECK (fs_util_is_valid_port ("1024:65535"), "port range");
	CHECK (fs_util_is_valid_port ("65535"), "port 65535");
	CHECK (!fs_util_is_valid_port ("0x50"), "port 0x50 rejected");
	CHECK (!fs_util_is_valid_port ("70000"), "port 70000 rejected");
	CHECK (!fs_util_is_valid_port ("200:100"), "inverted range rejected");
	CHECK (fs_util_is_valid_port ("67-68"),
	       "hyphen range from the default ruleset accepted");
	CHECK (!fs_util_is_valid_port ("68-67"),
	       "inverted hyphen range rejected");
	CHECK (!fs_util_is_valid_port ("67-"), "half a hyphen range rejected");
	CHECK (!fs_util_is_valid_port (""), "empty port rejected");
	CHECK (!fs_util_is_valid_port (NULL), "NULL port rejected");
}

static void test_hosts (void)
{
	CHECK (fs_util_is_valid_host ("192.168.1.1"), "ipv4");
	CHECK (fs_util_is_valid_host ("10.0.0.255"), "ipv4 broadcast");
	CHECK (fs_util_is_valid_host ("example.com"), "hostname");
	CHECK (fs_util_is_valid_host ("*"), "wildcard");
	CHECK (!fs_util_is_valid_host ("999.1.1.1"), "octet > 255 rejected");
	CHECK (!fs_util_is_valid_host ("1.2.3"), "three octets rejected");
	CHECK (!fs_util_is_valid_host ("192.168..1"), "empty label rejected");
	CHECK (!fs_util_is_valid_host (NULL), "NULL host rejected");
	CHECK (fs_util_is_valid_host ("192.168.1.0/24"), "cidr v4");
	CHECK (fs_util_is_valid_host ("2001:db8::1/64"), "cidr v6");
	CHECK (fs_util_is_valid_host ("2001:db8::1"), "ipv6");
	CHECK (!fs_util_is_valid_host ("192.168.1.0/33"),
	       "v4 prefix over /32 rejected");
	CHECK (!fs_util_is_valid_host ("2001:db8::1/129"),
	       "v6 prefix over /128 rejected");
	CHECK (!fs_util_is_valid_host ("example.com/24"),
	       "hostnames do not take a prefix");
	CHECK (!fs_util_is_valid_host ("192.168.1.0/"), "empty prefix rejected");
	CHECK (!fs_util_is_valid_host ("nonsense:stuff"), "junk ipv6 rejected");
}

static void test_rule_csv (void)
{
	FsRule *rule = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);
	gchar *csv;
	FsRule *back;

	rule->service = g_strdup ("SSH");
	rule->port    = g_strdup ("22");
	rule->target  = g_strdup ("192.168.1.0/24");
	rule->comment = g_strdup ("from LAN");

	csv = fs_rule_to_csv (rule);
	CHECK (g_strcmp0 (csv, "SSH, 22, 192.168.1.0/24, from LAN") == 0,
	       "service rule serialises as \"%s\"", csv);

	back = fs_rule_from_csv (FS_RULE_INBOUND_ALLOW_SERVICE, csv);
	CHECK (back != NULL, "service rule parses back");
	CHECK (back != NULL && g_strcmp0 (back->service, "SSH") == 0 &&
	       g_strcmp0 (back->port, "22") == 0 &&
	       g_strcmp0 (back->target, "192.168.1.0/24") == 0 &&
	       g_strcmp0 (back->comment, "from LAN") == 0,
	       "service round-trip preserves all fields");

	g_free (csv);
	fs_rule_free (rule);
	fs_rule_free (back);

	/* Host rules have only two fields. */
	rule = fs_rule_new (FS_RULE_INBOUND_ALLOW_FROM);
	rule->target  = g_strdup ("10.0.0.5");
	rule->comment = g_strdup ("friend");
	csv = fs_rule_to_csv (rule);
	CHECK (g_strcmp0 (csv, "10.0.0.5, friend") == 0,
	       "host rule serialises as \"%s\"", csv);
	back = fs_rule_from_csv (FS_RULE_INBOUND_ALLOW_FROM, csv);
	CHECK (back != NULL && g_strcmp0 (back->target, "10.0.0.5") == 0,
	       "host round-trip preserves target");
	g_free (csv);
	fs_rule_free (rule);
	fs_rule_free (back);

	/* Forward rules have five. */
	rule = fs_rule_new (FS_RULE_INBOUND_FORWARD);
	rule->service = g_strdup ("HTTP");
	rule->port    = g_strdup ("80");
	rule->to      = g_strdup ("192.168.1.10");
	rule->to_port = g_strdup ("8080");
	csv = fs_rule_to_csv (rule);
	back = fs_rule_from_csv (FS_RULE_INBOUND_FORWARD, csv);
	CHECK (back != NULL && g_strcmp0 (back->to_port, "8080") == 0,
	       "forward round-trip preserves destination port");
	g_free (csv);
	fs_rule_free (rule);
	fs_rule_free (back);

	/* Too many fields is malformed. */
	CHECK (fs_rule_from_csv (FS_RULE_INBOUND_ALLOW_FROM,
	                         "a, b, c, d, e, f") == NULL,
	       "over-long row rejected");
}

static void test_policy_persist (void)
{
	FsPolicy *policy = fs_policy_new ();
	FsRule *rule;
	gint malformed = 0;

	fs_policy_install_defaults (policy);
	CHECK (fs_policy_count (policy, FS_RULE_OUTBOUND_ALLOW_SERVICE) == 2,
	       "defaults install 2 outbound services");

	CHECK (fs_policy_save (policy), "policy saves to disk");

	fs_policy_clear (policy);
	CHECK (fs_policy_load (policy, &malformed), "policy loads from disk");
	CHECK (malformed == 0, "no malformed rows (got %d)", malformed);
	CHECK (fs_policy_count (policy, FS_RULE_OUTBOUND_ALLOW_SERVICE) == 2,
	       "outbound services survive the round trip");

	rule = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);
	rule->service = g_strdup ("HTTPS");
	rule->port = g_strdup ("443");
	rule->target = g_strdup (FS_TARGET_ANY);
	fs_policy_add (policy, rule);

	CHECK (fs_policy_count (policy, FS_RULE_INBOUND_ALLOW_SERVICE) == 1,
	       "inbound service added");
	CHECK (fs_policy_remove (policy, rule),
	       "rule removable by matching CSV");
	CHECK (fs_policy_count (policy, FS_RULE_INBOUND_ALLOW_SERVICE) == 0,
	       "removed rule is gone from the store");
	CHECK (!fs_policy_remove (policy, rule),
	       "removing the same rule twice fails");
	fs_rule_free (rule);

	fs_policy_free (policy);
}

static void test_fwrule_ports (void)
{
	gint port = 0;
	gint first = 0, last = 0;

	CHECK (fs_fwrule_parse_port ("80", &port) && port == 80, "parse port 80");
	CHECK (fs_fwrule_parse_port (NULL, &port) && port == 0, "NULL port = any");
	CHECK (fs_fwrule_parse_port ("", &port) && port == 0, "empty port = any");
	CHECK (!fs_fwrule_parse_port ("1024:2000", &port),
	       "a range is not a single port");
	CHECK (!fs_fwrule_parse_port ("abc", &port), "garbage port rejected");

	CHECK (fs_fwrule_parse_range ("1024:65535", &first, &last) &&
	       first == 1024 && last == 65535, "range parsed");
	CHECK (fs_fwrule_parse_range ("80", &first, &last) &&
	       first == 80 && last == 80, "single port as a 1:1 range");
	CHECK (!fs_fwrule_parse_range ("200:100", &first, &last),
	       "inverted range rejected");
	CHECK (!fs_fwrule_parse_range ("99999", &first, &last),
	       "out of range port rejected");

	CHECK (fs_fwrule_protocol_for_service ("SSH") == FS_PROTO_TCP,
	       "SSH is TCP");
	CHECK (fs_fwrule_protocol_for_service ("Samba (SMB)") == FS_PROTO_ANY,
	       "Samba is left as any-protocol");
	CHECK (fs_fwrule_protocol_for_service (NULL) == FS_PROTO_ANY,
	       "unknown service is any-protocol");
}

static void test_fwrule_expand (void)
{
	FsPolicy *policy = fs_policy_new ();
	FsRule *row;
	GList *rules, *iter;
	guint inbound_allows = 0;
	guint outbound_blocks = 0;

	/* An inbound service open to a specific network. */
	row = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);
	row->service = g_strdup ("SSH");
	row->port = g_strdup ("22");
	row->target = g_strdup ("192.168.1.0/24");
	fs_policy_add (policy, row);
	fs_rule_free (row);

	/* The same port open to anyone: no address constraint. */
	row = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);
	row->service = g_strdup ("HTTPS");
	row->port = g_strdup ("443");
	row->target = g_strdup (FS_TARGET_ANY);
	fs_policy_add (policy, row);
	fs_rule_free (row);

	/* A port range should expand to individual rules. */
	row = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);
	row->service = g_strdup ("SMB");
	row->port = g_strdup ("137:139");
	row->target = g_strdup (FS_TARGET_ANY);
	fs_policy_add (policy, row);
	fs_rule_free (row);

	/* A blocked host outbound. */
	row = fs_rule_new (FS_RULE_OUTBOUND_DENY_TO);
	row->target = g_strdup ("10.0.0.7");
	fs_policy_add (policy, row);
	fs_rule_free (row);

	rules = fs_fwrule_from_policy (policy);

	CHECK (g_list_length (rules) == 6,
	       "policy expands to 6 concrete rules (got %u)",
	       g_list_length (rules));

	/* The address-scoped rule keeps its address. */
	{
		gboolean found = FALSE;

		for (iter = rules; iter != NULL; iter = iter->next) {
			FsFwRule *r = iter->data;

			if (r->direction == FS_DIR_INBOUND && r->local_port == 22) {
				found = TRUE;
				CHECK (g_strcmp0 (r->remote_address,
				                  "192.168.1.0/24") == 0,
				       "SSH rule keeps its source network");
				CHECK (r->protocol == FS_PROTO_TCP,
				       "SSH rule is TCP only");
				CHECK (g_strcmp0 (r->name,
				                  "StockFW: Allow SSH "
				                  "(inbound, 192.168.1.0/24)") == 0,
				       "rule name reads \"%s\"", r->name);
			}
		}

		CHECK (found, "SSH rule present");
	}

	/* The "Anyone" rule has no remote address. */
	{
		gboolean found = FALSE;

		for (iter = rules; iter != NULL; iter = iter->next) {
			FsFwRule *r = iter->data;

			if (r->local_port == 443) {
				found = TRUE;
				CHECK (r->remote_address == NULL,
				       "\"Anyone\" becomes no address constraint");
			}
		}

		CHECK (found, "HTTPS rule present");
	}

	/* The range expanded to 137, 138 and 139. */
	{
		gboolean have137 = FALSE, have138 = FALSE, have139 = FALSE;
		gboolean have140 = FALSE;

		for (iter = rules; iter != NULL; iter = iter->next) {
			FsFwRule *r = iter->data;

			if (r->local_port == 137) have137 = TRUE;
			if (r->local_port == 138) have138 = TRUE;
			if (r->local_port == 139) have139 = TRUE;
			if (r->local_port == 140) have140 = TRUE;
		}

		CHECK (have137 && have138 && have139,
		       "range 137:139 expands to three rules");
		CHECK (!have140, "range does not overshoot");
	}

	/* The blocked host became a block rule. */
	for (iter = rules; iter != NULL; iter = iter->next) {
		FsFwRule *r = iter->data;

		if (r->direction == FS_DIR_OUTBOUND) {
			outbound_blocks++;
			CHECK (r->action == FS_ACTION_BLOCK,
			       "outbound deny is a block");
		}

		if (r->direction == FS_DIR_INBOUND &&
		    r->action == FS_ACTION_ALLOW)
			inbound_allows++;
	}

	CHECK (outbound_blocks == 1, "one outbound rule (got %u)",
	       outbound_blocks);
	CHECK (inbound_allows == 5, "five inbound allows (got %u)",
	       inbound_allows);

	/* A host row with no host constrains nothing and must be dropped. */
	fs_policy_clear (policy);
	row = fs_rule_new (FS_RULE_INBOUND_ALLOW_FROM);
	row->target = g_strdup (FS_TARGET_ANY);
	fs_policy_add (policy, row);
	fs_rule_free (row);

	fs_fwrule_list_free (rules);
	rules = fs_fwrule_from_policy (policy);
	CHECK (g_list_length (rules) == 0,
	       "an empty host rule produces no rule (got %u)",
	       g_list_length (rules));

	fs_fwrule_list_free (rules);
	fs_policy_free (policy);
}

static void test_fwrule_forward (void)
{
	FsPolicy *policy = fs_policy_new ();
	FsRule *row = fs_rule_new (FS_RULE_INBOUND_FORWARD);
	GList *rules;

	row->service = g_strdup ("HTTP");
	row->port = g_strdup ("80");
	row->to = g_strdup ("192.168.1.50");
	row->to_port = g_strdup ("8080");
	fs_policy_add (policy, row);
	fs_rule_free (row);

	rules = fs_fwrule_from_policy (policy);

	CHECK (g_list_length (rules) == 1, "forward row yields one rule");

	if (rules != NULL) {
		FsFwRule *r = rules->data;

		CHECK (r->forward, "rule is marked as a forward");
		CHECK (r->local_port == 80, "forward listens on the firewall port");
		CHECK (g_strcmp0 (r->forward_address, "192.168.1.50") == 0,
		       "forward targets the internal host");
	}

	fs_fwrule_list_free (rules);
	fs_policy_free (policy);
}

static void test_service_lookup (void)
{
	gchar *name;

	name = fs_service_lookup_port (22);
	CHECK (g_strcmp0 (name, "SSH") == 0, "port 22 -> SSH (got %s)", name);
	g_free (name);

	name = fs_service_lookup_port (443);
	CHECK (g_strcmp0 (name, "HTTPS") == 0, "port 443 -> HTTPS");
	g_free (name);

	name = fs_service_lookup_port (31337);
	CHECK (g_strcmp0 (name, "Back orifice") == 0,
	       "port 31337 -> Back orifice (got %s)", name);
	g_free (name);

	name = fs_service_lookup_port (44444);
	CHECK (name == NULL, "unknown port returns NULL");
	g_free (name);

	name = fs_service_icmp_name (8);
	CHECK (g_strcmp0 (name, "Echo") == 0, "icmp 8 -> Echo");
	g_free (name);

	/* Range expansion: Samba covers 137-139 and 445. */
	{
		GPtrArray *ports = g_ptr_array_new ();
		gsize i;
		gboolean saw137 = FALSE, saw445 = FALSE;

		fs_service_expand_ports ("137-139 445", NULL, ports);
		for (i = 0; i < ports->len; i++) {
			if (GPOINTER_TO_INT (ports->pdata[i]) == 137) saw137 = TRUE;
			if (GPOINTER_TO_INT (ports->pdata[i]) == 445) saw445 = TRUE;
		}
		CHECK (ports->len == 4, "137-139 445 expands to 4 ports (got %u)",
		       ports->len);
		CHECK (saw137 && saw445, "expansion includes 137 and 445");
		g_ptr_array_unref (ports);
	}
}

static void test_script_generation (void)
{
	FsPolicy *policy = fs_policy_new ();
	FsSettings *settings = fs_settings_new ();
	FsRule *rule;
	gchar *script;

	settings->ext_device = g_strdup ("eth0");
	settings->int_device = g_strdup ("eth1");
	settings->nat = TRUE;

	rule = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);
	rule->service = g_strdup ("SSH");
	rule->port = g_strdup ("22");
	rule->target = g_strdup ("192.168.1.0/24");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	script = fs_script_generate_inbound (policy, settings);
	CHECK (strstr (script, "-A INBOUND -s 192.168.1.0/24 "
	                    "-p tcp --dport 22 -j ACCEPT") != NULL,
	       "inbound service rule emitted with source match");
	CHECK (strstr (script, "-p udp --dport 22 -j ACCEPT") != NULL,
	       "inbound service rule also covers udp");
	CHECK (strstr (script, "-A INBOUND -i lo -j ACCEPT") != NULL,
	       "loopback trusted");
	CHECK (strstr (script, "-A INBOUND -i eth1 -j ACCEPT") != NULL,
	       "internal interface accepted when NAT is on");
	CHECK (strstr (script, "-j DROP") != NULL,
	       "default inbound action is DROP");
	g_free (script);

	script = fs_script_generate_outbound (policy, settings);
	CHECK (strstr (script, "-A OUTBOUND -j ACCEPT") != NULL,
	       "permissive outbound defaults to ACCEPT");
	g_free (script);

	settings->restrictive_outbound = TRUE;
	script = fs_script_generate_outbound (policy, settings);
	CHECK (strstr (script, "-A OUTBOUND -j DROP") != NULL,
	       "restrictive outbound defaults to DROP");
	CHECK (strstr (script, "-A OUTBOUND -j ACCEPT") == NULL,
	       "restrictive mode emits no default ACCEPT");
	g_free (script);

	settings->restrictive_outbound = FALSE;
	script = fs_script_generate_control (settings);
	CHECK (strstr (script, "net.ipv4.ip_forward=1") != NULL,
	       "control script enables forwarding for NAT");
	CHECK (strstr (script, "-j MASQUERADE") != NULL,
	       "control script masquerades on the external interface");
	g_free (script);

	/* ICMP filtering: every tick on the Preferences page has to change
	 * the rules that come out, or the page is decoration. */
	{
		script = fs_script_generate_inbound (policy, settings);
		CHECK (strstr (script, "--icmp-type echo-request") != NULL,
		       "default settings allow ping");
		CHECK (strstr (script, "--icmp-type redirect") == NULL,
		       "redirect is off by default");
		CHECK (strstr (script, "--icmp-type timestamp-request") == NULL,
		       "timestamping is off by default");
		CHECK (strstr (script, "-p udp --dport 33434") != NULL,
		       "traceroute tick opens UDP 33434 as the original did");
		CHECK (strstr (script, "--icmp-type destination-unreachable") != NULL,
		       "MS traceroute tick allows destination-unreachable");
		g_free (script);

		settings->icmp_echo_request = FALSE;
		settings->icmp_redirection = TRUE;
		script = fs_script_generate_inbound (policy, settings);
		CHECK (strstr (script, "--icmp-type echo-request") == NULL,
		       "unticking echo request removes the rule");
		CHECK (strstr (script, "--icmp-type redirect") != NULL,
		       "ticking redirection adds the rule");
		g_free (script);

		settings->icmp_echo_request = TRUE;
		settings->icmp_redirection = FALSE;

		/* Master switch off: everything ICMP is allowed. */
		settings->filter_icmp = FALSE;
		script = fs_script_generate_inbound (policy, settings);
		CHECK (strstr (script, "-p icmp -m limit --limit 10/s "
		                           "-j ACCEPT") != NULL,
		       "filtering off allows all ICMP");
		CHECK (strstr (script, "--icmp-type echo-request") == NULL,
		       "filtering off emits no per-type rules");
		g_free (script);
		settings->filter_icmp = TRUE;
	}

	/* Advanced Options: the rejection method and the two broadcast /
	 * reserved-address switches each have to reach the script. */
	{
		settings->deny_packets = TRUE;
		script = fs_script_generate_inbound (policy, settings);
		CHECK (strstr (script, "-j DROP\n") != NULL,
		       "drop-silently is the default rejection method");
		CHECK (strstr (script, "-j REJECT") == NULL,
		       "drop mode emits no REJECT");
		g_free (script);

		settings->deny_packets = FALSE;
		script = fs_script_generate_inbound (policy, settings);
		CHECK (strstr (script, "-j REJECT --reject-with "
		                       "icmp-host-unreachable") != NULL,
		       "reject mode answers with an error packet");
		g_free (script);
		settings->deny_packets = TRUE;

		settings->block_external_broadcast = TRUE;
		script = fs_script_generate_inbound (policy, settings);
		CHECK (strstr (script, "-i eth0 -d 255.255.255.255 -j DROP") != NULL,
		       "external broadcast blocking is emitted");
		g_free (script);
		settings->block_external_broadcast = FALSE;

		settings->block_internal_broadcast = TRUE;
		script = fs_script_generate_inbound (policy, settings);
		CHECK (strstr (script, "-i eth1 -d 255.255.255.255 -j DROP") != NULL,
		       "internal broadcast blocking is emitted when NAT is on");
		g_free (script);
		settings->block_internal_broadcast = FALSE;

		CHECK (settings->block_non_routables == TRUE,
		       "reserved addresses are refused by default");
		script = fs_script_generate_inbound (policy, settings);
		CHECK (strstr (script, "-i eth0 -s 10.0.0.0/8 -j DROP") != NULL,
		       "reserved-address blocking is emitted");
		g_free (script);
	}

	/* Host rules must use a real address match: iptables has no -H.
	 * "to host" is a destination, "from host" a source. */
	{
		FsRule *to_host   = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_TO);
		FsRule *from_host = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_FROM);
		FsRule *deny_host = fs_rule_new (FS_RULE_OUTBOUND_DENY_TO);

		to_host->target   = g_strdup ("203.0.113.7");
		from_host->target = g_strdup ("198.51.100.9");
		deny_host->target = g_strdup ("192.0.2.66");

		settings->restrictive_outbound = TRUE;
		fs_policy_add (policy, to_host);
		fs_policy_add (policy, from_host);
		fs_policy_add (policy, deny_host);

		script = fs_script_generate_outbound (policy, settings);

		CHECK (strstr (script, "-H ") == NULL,
		       "host rules never emit the invalid -H option");
		CHECK (strstr (script, "-d 203.0.113.7 -j ACCEPT") != NULL,
		       "allow-to host rule matches the destination");
		CHECK (strstr (script, "-s 198.51.100.9 -j ACCEPT") != NULL,
		       "allow-from host rule matches the source");
		CHECK (strstr (script, "-d 192.0.2.66 -j DROP") != NULL,
		       "deny-to host rule matches the destination");

		g_free (script);
		fs_rule_free (to_host);
		fs_rule_free (from_host);
		fs_rule_free (deny_host);
		settings->restrictive_outbound = FALSE;
	}

	/* "Anyone" must not become a bogus -s match. */
	rule = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_SERVICE);
	rule->service = g_strdup ("DNS");
	rule->port = g_strdup ("53");
	rule->target = g_strdup (FS_TARGET_ANY);
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	script = fs_script_generate_outbound (policy, settings);
	CHECK (strstr (script, "--dport 53 -j ACCEPT") != NULL,
	       "outbound service rule emitted");
	CHECK (strstr (script, "-s Anyone") == NULL,
	       "\"Anyone\" does not become a source match");
	g_free (script);

	fs_policy_free (policy);
	fs_settings_free (settings);
}

/* The Copilot's "Apply Selected Rule" button turns a suggestion's CSV
 * text into a real policy row.  These checks cover that path: the exact
 * field layout the copilot emits, the de-duplication that stops a
 * second click stacking a copy, and the save/load round-trip that
 * proves the rule survives to disk rather than only being printed. */
static void test_copilot_suggestion_apply (void)
{
	FsPolicy *policy = fs_policy_new ();
	FsRule *rule;
	guint before, after;
	gint malformed = -1;

	/* This is the shape core/fs-copilot.c writes into
	 * FsInsight->rule_csv: service, port, target, comment. */
	const gchar *csv = "brave.exe, 443, 203.0.113.7, Auto-generated by Copilot";

	rule = fs_rule_from_csv (FS_RULE_OUTBOUND_ALLOW_SERVICE, csv);
	CHECK (rule != NULL, "copilot suggestion parses into a rule");
	if (rule == NULL) {
		fs_policy_free (policy);
		return;
	}

	CHECK (g_strcmp0 (rule->service, "brave.exe") == 0,
	       "suggestion keeps the application name");
	CHECK (g_strcmp0 (rule->port, "443") == 0,
	       "suggestion keeps the port");
	CHECK (g_strcmp0 (rule->target, "203.0.113.7") == 0,
	       "suggestion keeps the target host");
	CHECK (g_strcmp0 (rule->comment, "Auto-generated by Copilot") == 0,
	       "suggestion keeps the comment");

	/* Not there yet. */
	CHECK (!fs_policy_contains (policy, rule),
	       "fresh suggestion is not already in the policy");

	before = fs_policy_count (policy, FS_RULE_OUTBOUND_ALLOW_SERVICE);
	fs_policy_add (policy, rule);
	after = fs_policy_count (policy, FS_RULE_OUTBOUND_ALLOW_SERVICE);
	CHECK (after == before + 1, "applying adds exactly one rule");

	/* The second click must not stack a duplicate. */
	CHECK (fs_policy_contains (policy, rule),
	       "applied rule is found afterwards");
	CHECK (fs_policy_count (policy, FS_RULE_OUTBOUND_ALLOW_SERVICE) == after,
	       "duplicate apply is detected before it adds a second row");

	/* A genuinely different suggestion must still be allowed. */
	{
		FsRule *other = fs_rule_from_csv (
			FS_RULE_OUTBOUND_ALLOW_SERVICE,
			"steam.exe, 27015, 198.51.100.9, Auto-generated by Copilot");

		CHECK (other != NULL, "second suggestion parses");
		if (other != NULL) {
			CHECK (!fs_policy_contains (policy, other),
			       "a different rule is not mistaken for a duplicate");
			fs_rule_free (other);
		}
	}

	/* What the Policy page reads back must match what was written. */
	CHECK (fs_policy_save (policy), "applied rule is saved to disk");
	fs_policy_clear (policy);
	CHECK (fs_policy_load (policy, &malformed), "policy reloads from disk");
	CHECK (malformed == 0, "no malformed rows were read back");
	CHECK (fs_policy_count (policy, FS_RULE_OUTBOUND_ALLOW_SERVICE) == after,
	       "applied rule survives the save/load round-trip");

	{
		FsRule *reloaded = fs_rule_from_csv (
			FS_RULE_OUTBOUND_ALLOW_SERVICE, csv);

		CHECK (reloaded != NULL, "original suggestion still parses");
		if (reloaded != NULL) {
			CHECK (fs_policy_contains (policy, reloaded),
			       "reloaded policy contains the applied rule");
			fs_rule_free (reloaded);
		}
	}

	fs_rule_free (rule);
	fs_policy_free (policy);
}

/* Regression: fs_prefs_get_bool()/get_int() used to pass NULL for the
 * GError, so g_key_file returned FALSE for a missing key and the
 * fallback argument was dead code.  Every default in the application
 * -- ICMP filtering on, policy auto-apply on, reserved addresses
 * refused -- was silently coming out FALSE on a fresh install. */
static void test_prefs_fallbacks (void)
{
	gchar *s;

	CHECK (fs_prefs_get_bool ("/apps/stockfw/client/never/set",
	                          TRUE) == TRUE,
	       "missing bool key falls back to TRUE");
	CHECK (fs_prefs_get_bool ("/apps/stockfw/client/never/set",
	                          FALSE) == FALSE,
	       "missing bool key falls back to FALSE");
	CHECK (fs_prefs_get_int ("/apps/stockfw/client/never/set",
	                         42) == 42,
	       "missing int key falls back to 42");

	s = fs_prefs_get_string ("/apps/stockfw/client/never/set", "dflt");
	CHECK (g_strcmp0 (s, "dflt") == 0, "missing string key falls back");
	g_free (s);

	/* A stored value still wins over the fallback, in both directions. */
	fs_prefs_set_bool ("/apps/stockfw/client/sample", TRUE);
	CHECK (fs_prefs_get_bool ("/apps/stockfw/client/sample",
	                          FALSE) == TRUE,
	       "stored TRUE beats a FALSE fallback");

	fs_prefs_set_bool ("/apps/stockfw/client/sample", FALSE);
	CHECK (fs_prefs_get_bool ("/apps/stockfw/client/sample",
	                          TRUE) == FALSE,
	       "stored FALSE beats a TRUE fallback");

	fs_prefs_set_int ("/apps/stockfw/client/int_sample", 7);
	CHECK (fs_prefs_get_int ("/apps/stockfw/client/int_sample",
	                         99) == 7,
	       "stored int beats the fallback");
}

/* Regression: fs_copilot_feed_event() re-inserted the profile on EVERY
 * event, including the ones whose profile came from the lookup.  On a
 * key that already exists, g_hash_table_insert() frees the OLD value
 * through the table's destroy notify -- and old and new value were the
 * same object.  So the profile was freed and immediately stored again
 * as a dangling pointer: the next feed wrote into freed memory, the one
 * after that freed it a second time.  That was the crash behind
 * "enabling monitoring closes the app" -- g_hash_table_lookup() on the
 * freed profile->common_ports inside is_anomalous_port (integer
 * divide-by-zero / access violation in libglib) plus the heap
 * fail-fasts from the double free, once a log carried a second event
 * from the same service (which every real batch does).
 *
 * The junk blocks below are the teeth: they are the profile's size, so
 * when the buggy code frees the profile, the next allocation reuses and
 * zeroes it, and the dangling pointer becomes visibly poisoned instead
 * of accidentally still looking healthy. */
static void test_copilot_profile_lifetime (void)
{
	FsCopilot *copilot = fs_copilot_new ();
	FsHit hit;
	const FsAppProfile *profile;
	gpointer junk[80];
	gint i, j, n_junk = 0;

	memset (&hit, 0, sizeof hit);
	hit.service     = "SSH";
	hit.source      = "192.168.1.50";
	hit.destination = "192.168.1.10";
	hit.port        = "22";
	hit.protocol    = "TCP";
	hit.direction   = "In";

	fs_copilot_feed_event (copilot, &hit);   /* feed 1: creates it */
	fs_copilot_feed_event (copilot, &hit);   /* feed 2: frees it under the bug */

	/* Reuse the profile's block right after the buggy free, so the
	 * dangling pointer is poisoned instead of accidentally healthy. */
	for (j = 0; j < 4; j++)
		junk[n_junk++] = g_malloc0 (sizeof (FsAppProfile));

	profile = fs_copilot_get_profile (copilot, "SSH");
	CHECK (profile != NULL, "SSH profile exists after feed 2");
	CHECK (profile != NULL && profile->common_ports != NULL &&
	       profile->common_destinations != NULL &&
	       profile->hourly_activity != NULL,
	       "profile's counting tables are live after feed 2");
	CHECK (profile != NULL && profile->total_connections == 2,
	       "2 feeds counted after feed 2 (got %" G_GUINT64_FORMAT ")",
	       profile ? profile->total_connections : 0);

	/* Flush before anything crash-prone: if the bug is present the
	 * process may die later, and the evidence must already be on disk. */
	fflush (stdout);

	for (i = 2; i < 20; i++) {
		fs_copilot_feed_event (copilot, &hit);

		/* Reuse the profile's block right after each feed. */
		for (j = 0; j < 4; j++)
			junk[n_junk++] = g_malloc0 (sizeof (FsAppProfile));
	}

	profile = fs_copilot_get_profile (copilot, "SSH");
	CHECK (profile != NULL, "SSH profile survives 20 feeds");
	if (profile != NULL) {
		CHECK (profile->common_ports != NULL &&
		       profile->common_destinations != NULL &&
		       profile->hourly_activity != NULL,
		       "profile's counting tables are still live");
		CHECK (profile->total_connections == 20,
		       "all 20 feeds counted (got %" G_GUINT64_FORMAT ")",
		       profile->total_connections);
	}

	/* A second application must get its own profile without touching
	 * the first one. */
	hit.service = "DNS";
	hit.port    = "53";
	for (i = 0; i < 5; i++)
		fs_copilot_feed_event (copilot, &hit);

	profile = fs_copilot_get_profile (copilot, "DNS");
	CHECK (profile != NULL && profile->total_connections == 5,
	       "DNS profile counts its own 5 feeds");

	profile = fs_copilot_get_profile (copilot, "SSH");
	CHECK (profile != NULL && profile->total_connections == 20,
	       "SSH profile still intact after the DNS feeds");

	fflush (stdout);

	for (i = 0; i < n_junk; i++)
		g_free (junk[i]);

	fs_copilot_free (copilot);
}

/* =====================================================================
 * 1.0.4: Event -> Rule builders (right-click on an event row).
 * Pure data: no GTK, no OS calls, so the core suite covers them.
 * ===================================================================== */

static void test_eventrule_builders (void)
{
	FsHit out_hit, in_hit;
	FsRule *rule;
	FsPolicy *policy;
	const FsRule *found;

	memset (&out_hit, 0, sizeof out_hit);
	out_hit.direction   = "Out";
	out_hit.source      = "192.168.1.7";
	out_hit.destination = "203.0.113.9";
	out_hit.port        = "443";
	out_hit.protocol    = "TCP";
	out_hit.service     = "HTTPS [BLOCKED]";

	memset (&in_hit, 0, sizeof in_hit);
	in_hit.direction   = "In";
	in_hit.source      = "2001:DB8::1";
	in_hit.port        = "22";
	in_hit.protocol    = "TCP";
	in_hit.service     = "SSH";

	rule = fs_eventrule_build (&out_hit, FS_EVENTRULE_BLOCK_DEST);
	CHECK (rule != NULL, "outbound BLOCK_DEST builds");
	if (rule != NULL) {
		CHECK (rule->kind == FS_RULE_OUTBOUND_DENY_TO,
		       "BLOCK_DEST is an outbound deny");
		CHECK (g_strcmp0 (rule->target, "203.0.113.9") == 0,
		       "BLOCK_DEST targets the event's destination");
		fs_rule_free (rule);
	}

	rule = fs_eventrule_build (&out_hit, FS_EVENTRULE_ALLOW_DEST);
	CHECK (rule != NULL && rule->kind == FS_RULE_OUTBOUND_ALLOW_TO,
	       "ALLOW_DEST is an outbound allow");
	fs_rule_free (rule);

	rule = fs_eventrule_build (&out_hit, FS_EVENTRULE_BLOCK_SERVICE);
	CHECK (rule != NULL, "BLOCK_SERVICE builds");
	if (rule != NULL) {
		CHECK (rule->kind == FS_RULE_OUTBOUND_DENY_SERVICE,
		       "BLOCK_SERVICE is a service deny");
		CHECK (g_strcmp0 (rule->service, "HTTPS") == 0,
		       "[BLOCKED] marker never reaches the rule");
		CHECK (g_strcmp0 (rule->port, "443") == 0 &&
		       g_strcmp0 (rule->target, "203.0.113.9") == 0,
		       "service deny carries port and destination");
		fs_rule_free (rule);
	}

	rule = fs_eventrule_build (&in_hit, FS_EVENTRULE_TRUST_SOURCE);
	CHECK (rule != NULL, "inbound TRUST_SOURCE builds");
	if (rule != NULL) {
		CHECK (rule->kind == FS_RULE_INBOUND_ALLOW_FROM,
		       "TRUST_SOURCE is an inbound allow");
		CHECK (g_strcmp0 (rule->target, "2001:DB8::1") == 0,
		       "TRUST_SOURCE targets the event's source");
		fs_rule_free (rule);
	}

	/* Direction mismatches must return NULL rather than invent a
	 * rule the model cannot express (there is no inbound deny). */
	CHECK (fs_eventrule_build (&in_hit, FS_EVENTRULE_BLOCK_DEST) == NULL,
	       "BLOCK_DEST on an inbound event is refused");
	CHECK (fs_eventrule_build (&out_hit, FS_EVENTRULE_TRUST_SOURCE) == NULL,
	       "TRUST_SOURCE on an outbound event is refused");
	CHECK (fs_eventrule_build (NULL, FS_EVENTRULE_BLOCK_DEST) == NULL,
	       "a NULL hit builds nothing");

	/* UNTRUST: find the stored allow by target alone -- the user's
	 * comment can be anything, so CSV identity must not be used. */
	policy = fs_policy_new ();
	CHECK (fs_eventrule_find_trust (policy, &in_hit) == NULL,
	       "no trust rule exists yet");

	rule = fs_eventrule_build (&in_hit, FS_EVENTRULE_TRUST_SOURCE);
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	found = fs_eventrule_find_trust (policy, &in_hit);
	CHECK (found != NULL, "trust rule is found again");
	CHECK (found != NULL &&
	       g_ascii_strcasecmp (found->target, "2001:db8::1") == 0,
	       "the match is case-insensitive (literal IPv6 letters)");

	CHECK (fs_eventrule_untrust (policy, &in_hit),
	       "untrust removes and persists the allow");
	CHECK (fs_eventrule_find_trust (policy, &in_hit) == NULL,
	       "the allow is gone afterwards");
	CHECK (!fs_eventrule_untrust (policy, &in_hit),
	       "untrust with nothing to remove reports failure");

	fs_policy_free (policy);
}

/* Rollback teeth: when the disk refuses the write, add/remove must
 * put the store back exactly as it was.  The rules directory is
 * pointed at a regular FILE so every write beneath it fails. */
static void test_policy_persist_rollback (void)
{
	FsPolicy *policy = fs_policy_new ();
	FsRule *rule = fs_rule_new (FS_RULE_OUTBOUND_DENY_TO);
	FsRule *r2 = fs_rule_new (FS_RULE_OUTBOUND_DENY_TO);
	gchar *good_dir;
	gchar *bad_path;
	guint before, after;

	rule->target  = g_strdup ("198.51.100.201");
	rule->comment = g_strdup ("rollback teeth");

	CHECK (fs_policy_add_persist (policy, rule),
	       "add_persist succeeds while writes work");
	before = fs_policy_count (policy, FS_RULE_OUTBOUND_DENY_TO);
	CHECK (before == 1, "one deny is stored");
	CHECK (!fs_policy_add_persist (policy, rule),
	       "duplicate add_persist is refused");

	good_dir = g_strdup (fs_util_rules_dir ());
	bad_path = g_build_filename (g_get_tmp_dir (),
	                            "stockfw-rules-as-file", NULL);
	g_file_set_contents (bad_path, "not a directory", -1, NULL);
	g_setenv ("STOCKFW_RULES_DIR", bad_path, TRUE);

	r2->target  = g_strdup ("198.51.100.202");
	r2->comment = g_strdup ("must roll back");

	CHECK (!fs_policy_add_persist (policy, r2),
	       "add_persist reports the save failure");
	after = fs_policy_count (policy, FS_RULE_OUTBOUND_DENY_TO);
	CHECK (after == before,
	       "failed save rolled the store back (got %u, want %u)",
	       after, before);

	CHECK (!fs_policy_remove_persist (policy, rule),
	       "remove_persist reports the save failure too");
	CHECK (fs_policy_contains (policy, rule),
	       "failed removal was rolled back into the store");

	/* Repair the disk: the same removal must now take. */
	g_setenv ("STOCKFW_RULES_DIR", good_dir, TRUE);
	CHECK (fs_policy_remove_persist (policy, rule),
	       "removal succeeds once writes work again");
	CHECK (!fs_policy_contains (policy, rule),
	       "the rule is gone after the successful removal");

	remove (bad_path);
	g_free (good_dir);
	g_free (bad_path);
	fs_rule_free (rule);
	fs_rule_free (r2);
	fs_policy_free (policy);
}

/* =====================================================================
 * 1.0.4 Sentinel: beacon (covert channel) and fan-out (scan) --
 * driven through fs_copilot_feed_event_at() so the arrival times are
 * exact instead of whatever the wall clock happens to do.
 * ===================================================================== */

static guint count_insights (FsCopilot *copilot, FsInsightType type)
{
	GList *insights = fs_copilot_get_insights (copilot);
	GList *l;
	guint n = 0;

	for (l = insights; l != NULL; l = l->next) {
		FsInsight *ins = l->data;

		if (ins->type == type)
			n++;
	}

	g_list_free (insights);
	return n;
}

static const FsInsight *find_insight (FsCopilot *copilot, FsInsightType type)
{
	GList *insights = fs_copilot_get_insights (copilot);
	GList *l;
	const FsInsight *hit_insight = NULL;

	for (l = insights; l != NULL; l = l->next) {
		FsInsight *ins = l->data;

		if (ins->type == type) {
			hit_insight = ins;
			break;
		}
	}

	g_list_free (insights);
	return hit_insight;
}

static void test_sentinel_beacon (void)
{
	FsCopilot *copilot = fs_copilot_new ();
	FsHit hit;
	const FsInsight *beacon;
	gint i;
	const gint64 t0 = (gint64) 500000 * G_USEC_PER_SEC;
	const gint64 gaps[] = { 60, 60, 60, 60, 150 };

	memset (&hit, 0, sizeof hit);
	hit.direction   = "Out";
	hit.source      = "192.168.1.7";
	hit.destination = "203.0.113.9";
	hit.port        = "8443";
	hit.protocol    = "TCP";
	hit.service     = "unknown";

	/* Six contacts at exact 60 s intervals: a control channel. */
	for (i = 0; i < 6; i++)
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * 60 * G_USEC_PER_SEC);

	CHECK (count_insights (copilot, FS_INSIGHT_BEACON) == 1,
	       "six metronomic contacts raise exactly one beacon");

	beacon = find_insight (copilot, FS_INSIGHT_BEACON);
	if (beacon != NULL) {
		FsPolicy *policy = fs_policy_new ();
		FsRule *probe;

		CHECK (beacon->severity == FS_COPILOT_CRITICAL,
		       "the beacon is CRITICAL");
		CHECK (beacon->auto_applicable && beacon->rule_csv != NULL,
		       "the beacon carries an auto-applicable rule");
		CHECK (beacon->rule_kind == FS_RULE_OUTBOUND_DENY_TO,
		       "the rule parses as an outbound deny, not a service allow");

		/* The point of the whole feature: the suggestion stages a
		 * real deny into the policy. */
		CHECK (fs_insight_apply (beacon, policy),
		       "the beacon rule stages into the policy");
		probe = fs_insight_to_rule (beacon);
		CHECK (probe != NULL && fs_policy_contains (policy, probe),
		       "the staged rule is in the policy");
		fs_rule_free (probe);
		fs_policy_free (policy);
	}

	/* More of the same must not stack reports. */
	for (i = 6; i < 9; i++)
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * 60 * G_USEC_PER_SEC);
	CHECK (count_insights (copilot, FS_INSIGHT_BEACON) == 1,
	       "a beacon is reported once, not once per contact");

	fs_copilot_free (copilot);

	/* Jitter is what humans and page loads look like: intervals
	 * 60/60/60/60/150 give cv = 0.46, well over the 0.30 limit. */
	copilot = fs_copilot_new ();
	{
		gint64 t = t0;

		for (i = 0; i < 6; i++) {
			fs_copilot_feed_event_at (copilot, &hit, t);
			if (i < 5)
				t += gaps[i] * G_USEC_PER_SEC;
		}
	}
	CHECK (count_insights (copilot, FS_INSIGHT_BEACON) == 0,
	       "jittered intervals are not a beacon");
	fs_copilot_free (copilot);

	/* A polled batch: ten records delivered in the same second are
	 * one moment, not ten contacts. */
	copilot = fs_copilot_new ();
	for (i = 0; i < 10; i++)
		fs_copilot_feed_event_at (copilot, &hit, t0);
	CHECK (count_insights (copilot, FS_INSIGHT_BEACON) == 0,
	       "a same-second batch does not fire the detector");
	fs_copilot_free (copilot);

	/* 5-second chatter is below the beacon floor (mean >= 10 s). */
	copilot = fs_copilot_new ();
	for (i = 0; i < 8; i++)
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * 5 * G_USEC_PER_SEC);
	CHECK (count_insights (copilot, FS_INSIGHT_BEACON) == 0,
	       "5-second chatter is not a beacon");
	fs_copilot_free (copilot);

	/* Sentinel watches egress; inbound regularity is out of scope. */
	copilot = fs_copilot_new ();
	hit.direction = "In";
	for (i = 0; i < 6; i++)
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * 60 * G_USEC_PER_SEC);
	CHECK (count_insights (copilot, FS_INSIGHT_BEACON) == 0,
	       "inbound traffic is not scored as an egress beacon");
	fs_copilot_free (copilot);
}

static void test_sentinel_fanout (void)
{
	FsCopilot *copilot = fs_copilot_new ();
	FsHit hit;
	gchar dest[32];
	gint i;
	const gint64 t0 = (gint64) 700000 * G_USEC_PER_SEC;

	memset (&hit, 0, sizeof hit);
	hit.direction = "Out";
	hit.source    = "192.168.1.7";
	hit.port      = "443";
	hit.protocol  = "TCP";
	hit.service   = "HTTPS";

	/* 60 distinct hosts inside 60 seconds: a scan. */
	for (i = 0; i < 60; i++) {
		g_snprintf (dest, sizeof dest, "203.0.113.%d", i);
		hit.destination = dest;
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * G_USEC_PER_SEC);
	}

	CHECK (count_insights (copilot, FS_INSIGHT_FANOUT) == 1,
	       "60 distinct hosts in the window raise one fan-out");
	{
		const FsInsight *fo = find_insight (copilot, FS_INSIGHT_FANOUT);

		if (fo != NULL) {
			CHECK (fo->severity == FS_COPILOT_CRITICAL,
			       "the fan-out is CRITICAL");
			CHECK (fo->rule_csv == NULL && !fo->auto_applicable,
			       "fan-out carries no guessed rule to auto-apply");
		}
	}

	/* One report per window, however the traffic continues. */
	hit.destination = "203.0.113.250";
	fs_copilot_feed_event_at (copilot, &hit,
	                          t0 + 60 * G_USEC_PER_SEC);
	CHECK (count_insights (copilot, FS_INSIGHT_FANOUT) == 1,
	       "the same window reports only once");

	/* After a quiet minute the episode ends and a new burst is
	 * reported again. */
	for (i = 0; i < 60; i++) {
		g_snprintf (dest, sizeof dest, "198.18.0.%d", i);
		hit.destination = dest;
		fs_copilot_feed_event_at (
			copilot, &hit,
			t0 + 600 * G_USEC_PER_SEC + (gint64) i * G_USEC_PER_SEC);
	}
	CHECK (count_insights (copilot, FS_INSIGHT_FANOUT) == 2,
	       "a second burst after a quiet window reports again");

	fs_copilot_free (copilot);

	/* 60 hosts spread over two minutes never reach 60-in-60s. */
	copilot = fs_copilot_new ();
	for (i = 0; i < 60; i++) {
		g_snprintf (dest, sizeof dest, "203.0.113.%d", i);
		hit.destination = dest;
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * 2 * G_USEC_PER_SEC);
	}
	CHECK (count_insights (copilot, FS_INSIGHT_FANOUT) == 0,
	       "60 hosts over 120 seconds is not a burst");
	fs_copilot_free (copilot);

	/* Refused contacts are the strongest scan signal: ten distinct
	 * blocked hosts are enough on their own. */
	copilot = fs_copilot_new ();
	hit.service = "TROJAN [BLOCKED]";
	for (i = 0; i < 10; i++) {
		g_snprintf (dest, sizeof dest, "198.51.100.%d", i);
		hit.destination = dest;
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * G_USEC_PER_SEC);
	}
	CHECK (count_insights (copilot, FS_INSIGHT_FANOUT) == 1,
	       "10 distinct blocked hosts raise a fan-out");
	fs_copilot_free (copilot);
}

/* The append-only audit trail: one line per action, never rewritten. */
static void test_audit_log (void)
{
	gchar *dir = g_build_filename (g_get_tmp_dir (),
	                               "stockfw-audit-test", NULL);
	gchar *file = g_build_filename (dir, "audit.log", NULL);
	gchar *contents = NULL;

	g_mkdir_with_parents (dir, 0700);
	remove (file);
	g_setenv ("STOCKFW_AUDIT_FILE", file, TRUE);

	CHECK (fs_audit_log ("sentinel auto-block",
	                     "203.0.113.9, Sentinel: periodic beacon"),
	       "first audit line is written");
	CHECK (fs_audit_log ("event rule added", "198.51.100.4, block"),
	       "second audit line is written");

	CHECK (g_file_get_contents (file, &contents, NULL, NULL),
	       "the audit file exists on disk");
	if (contents != NULL) {
		CHECK (strstr (contents,
		               "| sentinel auto-block | 203.0.113.9") != NULL,
		       "action and detail reach the line");
		CHECK (strstr (contents, "| event rule added |") != NULL,
		       "the second line was appended, not written over");
		CHECK (strstr (contents, "T") != NULL &&
		       strstr (contents, "Z |") != NULL,
		       "the line carries an ISO-8601 UTC stamp");
	}
	g_free (contents);

	g_unsetenv ("STOCKFW_AUDIT_FILE");
	remove (file);
	g_free (file);
	g_free (dir);
}

/* The Events filter bar's matcher, kept in core for exactly this. */
static void test_filter_match (void)
{
	const gchar *fields[] = { "192.168.1.5", "HTTPS", NULL, "443" };

	CHECK (fs_util_filter_match (NULL, fields, 4),
	       "NULL needle matches everything");
	CHECK (fs_util_filter_match ("", fields, 4),
	       "empty needle matches everything");
	CHECK (fs_util_filter_match ("https", fields, 4),
	       "match is case-insensitive");
	CHECK (fs_util_filter_match ("2.168", fields, 4),
	       "a substring of an address matches");
	CHECK (fs_util_filter_match ("443", fields, 4),
	       "a later field matches even with a NULL field in between");
	CHECK (!fs_util_filter_match ("2001", fields, 4),
	       "absent needle does not match");
	CHECK (!fs_util_filter_match ("DNS", NULL, 0),
	       "no fields, no match");
}

/* fs_insight_to_rule/apply: the staging path Sentinel auto-block and
 * the Copilot's Apply button share. */
static void test_insight_apply (void)
{
	FsPolicy *policy = fs_policy_new ();
	FsInsight *insight = g_new0 (FsInsight, 1);
	FsRule *probe;

	insight->rule_kind = FS_RULE_OUTBOUND_DENY_TO;
	insight->rule_csv = g_strdup (
		"198.51.100.77, Sentinel: periodic beacon");

	probe = fs_insight_to_rule (insight);
	CHECK (probe != NULL && probe->kind == FS_RULE_OUTBOUND_DENY_TO,
	       "the insight parses as its own rule kind");
	fs_rule_free (probe);

	CHECK (fs_insight_apply (insight, policy),
	       "apply stages and saves the rule");
	probe = fs_insight_to_rule (insight);
	CHECK (probe != NULL && fs_policy_contains (policy, probe),
	       "the staged rule is in the policy afterwards");
	fs_rule_free (probe);

	CHECK (!fs_insight_apply (insight, policy),
	       "a second apply is refused instead of stacking a duplicate");

	/* A suggestion with nothing in it must not stage anything. */
	g_free (insight->rule_csv);
	insight->rule_csv = g_strdup ("");
	CHECK (fs_insight_to_rule (insight) == NULL,
	       "an empty suggestion parses to nothing");
	CHECK (!fs_insight_apply (insight, policy),
	       "an empty suggestion applies to nothing");

	/* The auto-block invariant: only a rule that can TIGHTEN the
	 * policy may be staged without a human.  Legacy insights flag
	 * service allows auto-applicable for the confirmed Apply
	 * button -- the auto gate must refuse them regardless. */
	insight->rule_kind = FS_RULE_OUTBOUND_ALLOW_SERVICE;
	g_free (insight->rule_csv);
	insight->rule_csv = g_strdup (
		"evil.exe, 80, 198.51.100.9, Auto-generated by Copilot");
	CHECK (!fs_insight_is_auto_safe (insight),
	       "a service allow is never auto-safe, whatever its flag says");

	insight->rule_kind = FS_RULE_OUTBOUND_DENY_TO;
	CHECK (fs_insight_is_auto_safe (insight),
	       "an outbound deny is auto-safe");

	insight->rule_kind = FS_RULE_OUTBOUND_DENY_SERVICE;
	CHECK (fs_insight_is_auto_safe (insight),
	       "a service deny is auto-safe");

	g_free (insight->rule_csv);
	insight->rule_csv = NULL;
	CHECK (!fs_insight_is_auto_safe (insight),
	       "a missing suggestion is not auto-safe");
	CHECK (!fs_insight_is_auto_safe (NULL),
	       "a NULL insight is not auto-safe");

	g_free (insight->rule_csv);
	g_free (insight);
	fs_policy_free (policy);
}

/* =====================================================================
 * 1.0.4 F-1/F-3 hygiene: validation at load, control-character
 * stripping before a rule name reaches textual output.
 * ===================================================================== */

static void test_policy_load_validation_f1 (void)
{
	FsPolicy *policy = fs_policy_new ();
	gchar *good_dir = g_strdup (fs_util_rules_dir ());
	gchar *test_dir = g_build_filename (g_get_tmp_dir (),
	                                    "stockfw-f1-rules", NULL);
	gchar *deny_path;
	gchar *svc_path;
	gchar *trust_path;
	gchar *body;
	gint malformed = -1;

	/* A clean directory so earlier tests' rows cannot pollute the
	 * counts. */
	g_setenv ("STOCKFW_RULES_DIR", test_dir, TRUE);

	deny_path = fs_util_rules_path ("outbound/deny-to");
	svc_path  = fs_util_rules_path ("outbound/allow-service");
	CHECK (deny_path != NULL && svc_path != NULL,
	       "rule paths are built under the test directory");
	CHECK (fs_util_ensure_parent_dir (deny_path) &&
	       fs_util_ensure_parent_dir (svc_path),
	       "the rule directories are created");

	body = g_strdup (
		"198.51.100.1, good v4\n"
		"999.1.2.3, octet over 255\n");
	g_file_set_contents (deny_path, body, -1, NULL);
	g_free (body);

	body = g_strdup (
		"HTTPS, 99999, 198.51.100.2, port over the range\n"
		"DNS, 53, 198.18.0.0/15, good cidr row\n"
		"SSH, 22, , empty target means any\n");
	g_file_set_contents (svc_path, body, -1, NULL);
	g_free (body);

	trust_path = fs_util_rules_path ("inbound/allow-from");
	CHECK (trust_path != NULL &&
	       fs_util_ensure_parent_dir (trust_path),
	       "the inbound rule directory is created");
	body = g_strdup ("2001:db8::1, ipv6 trust\n");
	g_file_set_contents (trust_path, body, -1, NULL);
	g_free (body);

	CHECK (fs_policy_load (policy, &malformed), "the files load");
	CHECK (malformed == 2,
	       "exactly the bad host and the bad port are rejected "
	       "(got %d)", malformed);
	CHECK (fs_policy_count (policy, FS_RULE_OUTBOUND_DENY_TO) == 1,
	       "the valid deny row survives the load");
	CHECK (fs_policy_count (policy, FS_RULE_OUTBOUND_ALLOW_SERVICE) == 2,
	       "the cidr and empty-field service rows survive");
	CHECK (fs_policy_count (policy, FS_RULE_INBOUND_ALLOW_FROM) == 1,
	       "the inbound trust row loads");

	/* The IPv6 row specifically: it must round-trip, because the
	 * trust-source rules the Events page builds can be IPv6. */
	{
		FsHit in_hit;
		const FsRule *found;

		memset (&in_hit, 0, sizeof in_hit);
		in_hit.direction = "In";
		in_hit.source    = "2001:DB8::1";

		found = fs_eventrule_find_trust (policy, &in_hit);
		CHECK (found != NULL,
		       "an IPv6 trust rule loads instead of being dropped");
	}

	g_setenv ("STOCKFW_RULES_DIR", good_dir, TRUE);

	g_free (good_dir);
	g_free (test_dir);
	g_free (deny_path);
	g_free (svc_path);
	g_free (trust_path);
	fs_policy_free (policy);
}

static void test_name_hygiene_f3 (void)
{
	gchar *clean;
	gchar *name;

	clean = fs_util_strip_controls ("ab" "\001" "cd" "\033" "ef");
	CHECK (g_strcmp0 (clean, "abcdef") == 0,
	       "C0 characters are stripped from a name");
	g_free (clean);

	clean = fs_util_strip_controls ("tab\there");
	CHECK (g_strcmp0 (clean, "tabhere") == 0,
	       "the tab character is stripped too");
	g_free (clean);

	CHECK (fs_util_strip_controls (NULL) == NULL,
	       "NULL passes through untouched");

	name = fs_fwrule_default_name (FS_DIR_OUTBOUND, FS_ACTION_BLOCK,
	                               "EV\x1bIL", "198.51.100.9");
	CHECK (name != NULL, "a rule name is built");
	if (name != NULL) {
		CHECK (strchr (name, '\x1b') == NULL,
		       "no ESC byte reaches the rule name");
		CHECK (strstr (name, "EVIL") != NULL,
		       "the printable text of the name survives");
		g_free (name);
	}

	name = fs_fwrule_default_name (FS_DIR_INBOUND, FS_ACTION_ALLOW,
	                               NULL, "10.0.0." "\007" "5");
	if (name != NULL) {
		CHECK (strchr (name, '\x07') == NULL,
		       "addresses are stripped as well");
		CHECK (strstr (name, "10.0.0.5") != NULL,
		       "the address text survives");
		g_free (name);
	}
}

/* The What-If simulator: the closed grammar in core/fs-copilot.c and
 * the verdict it produces against a real policy.  The teeth here are
 * for the lies a simulator can tell -- a verdict based on a wrong
 * reading of the line; a verdict that ignores block precedence or
 * pretends a subnet block does not cover its hosts; and a verdict
 * reached through the wrong rule: the portless line that misses the
 * rule opening a port, ICMP joined to a ported rule, an any-port
 * rule named where the exact-port rule decided, a forward hiding
 * where the traffic goes, or a deciding port/host left out of the
 * reason the panel's notes point at. */
static void test_whatif_simulate (void)
{
	FsScenario *sc;
	FsSimulationResult *r;
	FsCopilot *copilot;
	FsPolicy *policy;
	FsRule *rule;

	sc = fs_copilot_parse_scenario ("allow SSH from 192.168.1.50 on port 22");
	CHECK (sc != NULL, "a full scenario line parses");
	if (sc != NULL) {
		CHECK (sc->inbound, "'from' reads as inbound");
		CHECK (sc->had_port && sc->port == 22, "port 22 is read");
		CHECK (sc->had_addr &&
		       g_strcmp0 (sc->remote_ip, "192.168.1.50") == 0,
		       "the host is read");
		CHECK (g_strcmp0 (sc->protocol, "TCP") == 0,
		       "TCP is the default protocol");
		CHECK (g_strcmp0 (sc->app, "SSH") == 0,
		       "the token after 'allow' is the application");
		fs_scenario_free (sc);
	}

	sc = fs_copilot_parse_scenario ("block DNS to 8.8.8.8 on port 53 udp");
	CHECK (sc != NULL, "a deny-style line parses");
	if (sc != NULL) {
		CHECK (!sc->inbound, "'to' reads as outbound");
		CHECK (sc->had_port && sc->port == 53, "port 53 is read");
		CHECK (g_strcmp0 (sc->remote_ip, "8.8.8.8") == 0,
		       "the host is read");
		CHECK (g_strcmp0 (sc->protocol, "UDP") == 0,
		       "the udp keyword is read");
		CHECK (g_strcmp0 (sc->app, "DNS") == 0,
		       "a service name supplies the application");
		fs_scenario_free (sc);
	}

	/* No port clause: a known service name supplies the port, and
	 * with no direction words the documented default is outbound. */
	sc = fs_copilot_parse_scenario ("allow HTTPS to 10.0.0.1");
	CHECK (sc != NULL, "a service-only line parses");
	if (sc != NULL) {
		CHECK (!sc->inbound, "the default direction is outbound");
		CHECK (sc->had_port && sc->port == 443,
		       "HTTPS supplies port 443");
		CHECK (g_strcmp0 (sc->remote_ip, "10.0.0.1") == 0,
		       "the host is read");
		fs_scenario_free (sc);
	}

	/* The host:port shorthand. */
	sc = fs_copilot_parse_scenario ("outbound to 203.0.113.9:8443");
	CHECK (sc != NULL, "a host:port line parses");
	if (sc != NULL) {
		CHECK (!sc->inbound, "the outbound keyword is read");
		CHECK (sc->had_addr &&
		       g_strcmp0 (sc->remote_ip, "203.0.113.9") == 0,
		       "the host survives the colon shorthand");
		CHECK (sc->had_port && sc->port == 8443,
		       "the port is read from the colon shorthand");
		fs_scenario_free (sc);
	}

	/* No port, no host: the line still parses, with the flags clear
	 * so the panel can say what was left out. */
	sc = fs_copilot_parse_scenario ("allow anything outbound");
	CHECK (sc != NULL, "a line with no port and no host parses");
	if (sc != NULL) {
		CHECK (!sc->had_port, "a missing port leaves had_port clear");
		CHECK (!sc->had_addr, "a missing host leaves had_addr clear");
		fs_scenario_free (sc);
	}

	CHECK (fs_copilot_parse_scenario ("") == NULL,
	       "an empty line parses to nothing");
	CHECK (fs_copilot_parse_scenario (NULL) == NULL,
	       "a NULL line parses to nothing");

	/* --- Verdicts against a real policy --- */
	policy = fs_policy_new ();
	copilot = fs_copilot_new ();
	fs_copilot_set_policy (copilot, policy);

	/* The same host allowed and blocked: Windows Firewall gives the
	 * block precedence, and so must the answer. */
	rule = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_TO);
	rule->target = g_strdup ("203.0.113.5");
	fs_policy_add (policy, rule);

	rule = fs_rule_new (FS_RULE_OUTBOUND_DENY_TO);
	rule->target = g_strdup ("203.0.113.5");
	fs_policy_add (policy, rule);

	r = fs_copilot_simulate_text (copilot,
	                              "allow SSH to 203.0.113.5 on port 22",
	                              NULL);
	CHECK (r != NULL, "simulate_text answers");
	if (r != NULL) {
		CHECK (r->would_block,
		       "a block rule beats an allow rule on the same host");
		CHECK (r->matching_rule != NULL,
		       "the verdict names the rule that decided it");
		CHECK (strstr (r->explanation, "shadowed") != NULL,
		       "the dead allow is reported as shadowed");
		fs_simulation_result_free (r);
	}

	/* A block written as a subnet still covers a host inside it. */
	fs_policy_clear (policy);
	rule = fs_rule_new (FS_RULE_OUTBOUND_DENY_TO);
	rule->target = g_strdup ("203.0.113.0/24");
	fs_policy_add (policy, rule);

	r = fs_copilot_simulate_text (copilot,
	                              "outbound ping to 203.0.113.77", NULL);
	CHECK (r != NULL, "simulate_text answers for the subnet probe");
	if (r != NULL) {
		CHECK (r->would_block,
		       "a /24 block covers a host inside the block");
		fs_simulation_result_free (r);
	}

	/* An allow with no block: the probe is allowed, and says by what. */
	fs_policy_clear (policy);
	rule = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_TO);
	rule->target = g_strdup ("198.51.100.10");
	fs_policy_add (policy, rule);

	r = fs_copilot_simulate_text (copilot,
	                              "allow HTTPS to 198.51.100.10", NULL);
	CHECK (r != NULL, "simulate_text answers for the allow probe");
	if (r != NULL) {
		CHECK (!r->would_block,
		       "a covering allow lets the traffic through");
		CHECK (r->matching_rule != NULL,
		       "the allow verdict names its rule too");
		fs_simulation_result_free (r);
	}

	/* --- Precision: symmetric ports, ICMP, best match, forwards ---
	 *
	 * A port constrains the same way a host does: a port either side
	 * left unnamed is unconstrained.  So a line with no port must
	 * still find the rule that opens one (and say which port), ICMP
	 * must never meet a ported rule, the rule the verdict names must
	 * be the exact-port one rather than an earlier any-port rule, and
	 * a forward must say where the traffic goes after it is let in. */
	fs_policy_clear (policy);
	rule = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);
	rule->service = g_strdup ("mystery");
	rule->port = g_strdup ("22");
	rule->target = g_strdup ("192.168.1.50");
	fs_policy_add (policy, rule);

	r = fs_copilot_simulate_text (copilot, "allow from 192.168.1.50",
	                              NULL);
	CHECK (r != NULL, "the portless probe answers");
	if (r != NULL) {
		CHECK (!r->would_block,
		       "a line with no port finds the rule that opens one");
		CHECK (strstr (r->explanation, "on port 22") != NULL,
		       "and the verdict names the port that decided it");
		fs_simulation_result_free (r);
	}

	r = fs_copilot_simulate_text (copilot,
	                              "allow ping from 192.168.1.50", NULL);
	CHECK (r != NULL, "the ICMP probe answers");
	if (r != NULL) {
		CHECK (r->would_block,
		       "ICMP meets no ported rule, portless line or not");
		fs_simulation_result_free (r);
	}

	r = fs_copilot_simulate_text (
		copilot, "allow ping from 192.168.1.50 port 22", NULL);
	if (r != NULL) {
		CHECK (r->would_block,
		       "not even a typed port joins ICMP to a ported rule");
		fs_simulation_result_free (r);
	}

	r = fs_copilot_simulate_text (copilot,
	                              "allow from 192.168.1.50 port 80", NULL);
	if (r != NULL) {
		CHECK (r->would_block,
		       "a port the rule does not open stays blocked");
		fs_simulation_result_free (r);
	}

	/* The exact-port rule decides port-443 traffic even when an
	 * any-port rule is listed before it (host rows expand first). */
	fs_policy_clear (policy);
	rule = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_TO);
	rule->target = g_strdup ("203.0.113.9");
	fs_policy_add (policy, rule);

	rule = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_SERVICE);
	rule->service = g_strdup ("HTTPS");
	rule->port = g_strdup ("443");
	rule->target = g_strdup ("203.0.113.9");
	fs_policy_add (policy, rule);

	r = fs_copilot_simulate_text (copilot,
	                              "allow HTTPS to 203.0.113.9", NULL);
	CHECK (r != NULL, "the exact-port probe answers");
	if (r != NULL) {
		CHECK (!r->would_block,
		       "the host allow covers it as well");
		CHECK (r->matching_rule != NULL &&
		       strstr (r->matching_rule, "HTTPS") != NULL,
		       "the exact-port rule, not the earlier any-port "
		       "rule, is the one named");
		CHECK (strstr (r->explanation, "on port 443") != NULL,
		       "the deciding port is in the reason");
		fs_simulation_result_free (r);
	}

	/* A forward is a real allow; the verdict says where the traffic
	 * is sent after it is let in. */
	fs_policy_clear (policy);
	rule = fs_rule_new (FS_RULE_INBOUND_FORWARD);
	rule->service = g_strdup ("HTTP");
	rule->port = g_strdup ("8080");
	rule->to = g_strdup ("10.0.0.5");
	rule->to_port = g_strdup ("80");
	fs_policy_add (policy, rule);

	r = fs_copilot_simulate_text (copilot, "inbound port 8080", NULL);
	CHECK (r != NULL, "the forward probe answers");
	if (r != NULL) {
		CHECK (!r->would_block, "a forward opens its port");
		CHECK (strstr (r->explanation, "on port 8080") != NULL,
		       "the forward's port is in the reason");
		CHECK (strstr (r->explanation, "10.0.0.5") != NULL,
		       "the verdict says where the traffic is forwarded");
		fs_simulation_result_free (r);
	}

	/* A line that named no host meets the host-scoped block, and the
	 * block's own host is in the reason the panel's note points at. */
	fs_policy_clear (policy);
	rule = fs_rule_new (FS_RULE_OUTBOUND_DENY_TO);
	rule->target = g_strdup ("203.0.113.5");
	fs_policy_add (policy, rule);

	r = fs_copilot_simulate_text (copilot, "block outbound", NULL);
	CHECK (r != NULL, "the no-host probe answers");
	if (r != NULL) {
		CHECK (r->would_block,
		       "a line with no host meets the host-scoped block");
		CHECK (strstr (r->explanation, "203.0.113.5") != NULL,
		       "the block's host is named in the reason");
		fs_simulation_result_free (r);
	}

	fs_copilot_free (copilot);
	fs_policy_free (policy);

	/* No policy attached: the fallback says so instead of pretending
	 * to have read rules it does not have. */
	{
		FsCopilot *bare = fs_copilot_new ();

		r = fs_copilot_simulate_text (
			bare, "allow SSH from 10.0.0.2 on port 22", NULL);
		CHECK (r != NULL, "simulate_text answers without a policy");
		if (r != NULL) {
			CHECK (r->would_block,
			       "inbound falls back to the deny default");
			CHECK (strstr (r->explanation,
			              "No firewall policy") != NULL,
			       "the fallback is labelled honestly");
			fs_simulation_result_free (r);
		}
		fs_copilot_free (bare);
	}
}

/* The reading itself: the shapes people actually type.  Each one
 * here once read as port 0 -- "local:0" in the verdict -- or as
 * the wrong port entirely, which is how a simulation can be
 * honest about the wrong question. */
static void test_whatif_reading (void)
{
	FsScenario *sc;
	FsSimulationResult *r;
	FsCopilot *bare;
	FsRule *rule;
	gchar *s;

	sc = fs_copilot_parse_scenario ("ssh is open at 22 port");
	CHECK (sc != NULL, "the 'N port' shape parses");
	if (sc != NULL) {
		CHECK (sc->had_port && sc->port == 22,
		       "the number before 'port' is the port");
		CHECK (g_strcmp0 (sc->protocol, "TCP") == 0,
		       "ssh reads as TCP");
		CHECK (!sc->inbound,
		       "with no direction word the default is outbound");
		CHECK (g_strcmp0 (sc->app, "ssh") == 0,
		       "the service name is the application");
		fs_scenario_free (sc);
	}

	sc = fs_copilot_parse_scenario ("scan at 8080 port");
	CHECK (sc != NULL, "an unknown service with 'N port' parses");
	if (sc != NULL) {
		CHECK (sc->had_port && sc->port == 8080,
		       "8080 is read without any service name to help");
		fs_scenario_free (sc);
	}

	sc = fs_copilot_parse_scenario ("allow anything to :22");
	CHECK (sc != NULL, "a bare ':N' port parses");
	if (sc != NULL) {
		CHECK (sc->had_port && sc->port == 22,
		       "the bare colon port is read");
		CHECK (!sc->had_addr,
		       "':22' is a local port, not a host");
		CHECK (!sc->inbound, "'to' still reads as outbound");
		fs_scenario_free (sc);
	}

	sc = fs_copilot_parse_scenario ("block local:22 inbound");
	CHECK (sc != NULL, "the 'local:N' shorthand parses");
	if (sc != NULL) {
		CHECK (sc->had_port && sc->port == 22,
		       "the local shorthand port is read");
		CHECK (sc->inbound, "the inbound keyword is read");
		CHECK (!sc->had_addr, "and it names no remote host");
		fs_scenario_free (sc);
	}

	sc = fs_copilot_parse_scenario ("allow RDP to 10.0.0.9");
	CHECK (sc != NULL, "an RDP line parses");
	if (sc != NULL) {
		CHECK (sc->had_port && sc->port == 3389,
		       "RDP supplies port 3389");
		CHECK (g_strcmp0 (sc->remote_ip, "10.0.0.9") == 0,
		       "the host is still read");
		fs_scenario_free (sc);
	}

	sc = fs_copilot_parse_scenario ("block ftp to 1.2.3.4");
	CHECK (sc != NULL, "an FTP line parses");
	if (sc != NULL) {
		CHECK (sc->had_port && sc->port == 21,
		       "FTP is the control port 21, not the table's 20");
		fs_scenario_free (sc);
	}

	sc = fs_copilot_parse_scenario ("block port 80 outbound");
	CHECK (sc != NULL, "the plain 'port N' shape parses");
	if (sc != NULL) {
		CHECK (sc->had_port && sc->port == 80, "port 80 is read");
		CHECK (!sc->inbound, "the outbound keyword is read");
		fs_scenario_free (sc);
	}

	sc = fs_copilot_parse_scenario ("allow ping from 192.168.1.5");
	CHECK (sc != NULL, "a ping line parses");
	if (sc != NULL) {
		CHECK (g_strcmp0 (sc->protocol, "ICMP") == 0,
		       "ping reads as ICMP");
		CHECK (sc->inbound && sc->had_addr,
		       "the source host and direction are read");
		CHECK (!sc->had_port,
		       "ICMP asks for no port, so had_port stays clear");
		fs_scenario_free (sc);
	}

	/* The honesty boundary: a hostname-shaped token is not a host,
	 * and "example.com:22" must not smuggle a port past that rule
	 * either. */
	sc = fs_copilot_parse_scenario ("block example.com:22");
	CHECK (sc != NULL, "a hostname-shaped line still parses");
	if (sc != NULL) {
		CHECK (!sc->had_addr, "a hostname is not read as a host");
		CHECK (!sc->had_port,
		       "and its ':22' is not read as a port");
		fs_scenario_free (sc);
	}

	/* The suggestion sentence and the rule behind it. */
	sc = fs_copilot_parse_scenario ("allow ssh from 192.168.1.50 on port 22");
	if (sc != NULL) {
		s = fs_copilot_allow_suggestion (sc);
		CHECK (s != NULL, "a blocked scenario gets a suggestion");
		if (s != NULL) {
			CHECK (strstr (s,
			              "Allow inbound TCP port 22 from 192.168.1.50.")
			       != NULL,
			       "the suggestion names direction, protocol, "
			       "port and host (got \"%s\")", s);
			g_free (s);
		}

		rule = fs_copilot_allow_rule_for (sc);
		CHECK (rule != NULL, "a blocked scenario gets a rule");
		if (rule != NULL) {
			CHECK (rule->kind == FS_RULE_INBOUND_ALLOW_SERVICE,
			       "inbound maps to the inbound service-allow kind");
			CHECK (g_strcmp0 (rule->service, "SSH") == 0,
			       "port 22 carries its well-known name");
			CHECK (g_strcmp0 (rule->port, "22") == 0,
			       "the rule carries the port as text");
			CHECK (g_strcmp0 (rule->target, "192.168.1.50") == 0,
			       "the rule carries the host");
			CHECK (rule->comment != NULL,
			       "the rule says where it came from");
			fs_rule_free (rule);
		}
		fs_scenario_free (sc);
	} else {
		CHECK (FALSE, "the suggestion scenario parses");
	}

	sc = fs_copilot_parse_scenario ("allow anything outbound");
	if (sc != NULL) {
		s = fs_copilot_allow_suggestion (sc);
		CHECK (s != NULL && strstr (s, "Allow outbound TCP traffic.")
		       != NULL,
		       "a line that named no port suggests 'traffic' "
		       "(got \"%s\")", s ? s : "(null)");
		g_free (s);
		fs_scenario_free (sc);
	} else {
		CHECK (FALSE, "the no-port scenario parses");
	}

	sc = fs_copilot_parse_scenario ("allow ping from 192.168.1.5");
	if (sc != NULL) {
		s = fs_copilot_allow_suggestion (sc);
		CHECK (s != NULL, "the ICMP scenario gets a suggestion");
		if (s != NULL) {
			CHECK (strstr (s, "port") == NULL,
			       "ICMP is not offered a port (got \"%s\")", s);
			g_free (s);
		}

		rule = fs_copilot_allow_rule_for (sc);
		CHECK (rule != NULL, "the ICMP scenario gets a rule");
		if (rule != NULL) {
			CHECK (g_strcmp0 (rule->service, "ICMP") == 0 &&
			       g_strcmp0 (rule->port, "") == 0,
			       "the ICMP rule names ICMP and no port");
			fs_rule_free (rule);
		}
		fs_scenario_free (sc);
	} else {
		CHECK (FALSE, "the ICMP scenario parses");
	}

	sc = fs_copilot_parse_scenario ("outbound to 203.0.113.9:8443");
	if (sc != NULL) {
		rule = fs_copilot_allow_rule_for (sc);
		CHECK (rule != NULL, "the odd-port scenario gets a rule");
		if (rule != NULL) {
			CHECK (g_strcmp0 (rule->port, "8443") == 0 &&
			       g_strcmp0 (rule->target, "203.0.113.9") == 0,
			       "the rule carries the odd port and the host");
			CHECK (g_strcmp0 (rule->service, "TCP") == 0,
			       "a port with no well-known name falls back "
			       "to the protocol word");
			fs_rule_free (rule);
		}
		fs_scenario_free (sc);
	} else {
		CHECK (FALSE, "the odd-port scenario parses");
	}

	CHECK (fs_copilot_allow_suggestion (NULL) == NULL &&
	       fs_copilot_allow_rule_for (NULL) == NULL,
	       "NULL scenarios suggest nothing");

	/* The result now carries the reason twice: as the log sentence
	 * and on its own for the visualizer's Explanation section. */
	bare = fs_copilot_new ();
	r = fs_copilot_simulate_text (bare, "allow ssh from 10.0.0.2 on port 22",
	                              NULL);
	CHECK (r != NULL, "the reason probe answers");
	if (r != NULL) {
		CHECK (r->reason != NULL && *r->reason != '\0',
		       "the result carries a bare reason");
		CHECK (strstr (r->explanation, "Simulation:") != NULL,
		       "the log sentence keeps its wrapper");
		CHECK (r->reason != NULL &&
		       strstr (r->reason, "Simulation:") == NULL,
		       "the bare reason drops the wrapper");
		fs_simulation_result_free (r);
	}
	fs_copilot_free (bare);
}

/* The bi-directional Direction setting: the pairing map, the labels,
 * the twin rule and the all-or-nothing persist.  The teeth are for the
 * three ways this feature could lie -- pairing a kind that has no
 * counterpart (there is no inbound-deny kind), silently staging one
 * direction while the dialog said two, and leaving half a pair behind
 * when the write fails. */
static void test_direction_pairing (void)
{
	FsPolicy *policy;
	FsPolicy *fresh;
	FsRule *rule;
	FsRule *twin;
	FsRule *cp;
	gchar *good_dir;
	gchar *bad_path;
	guint out_before, in_before;
	gint malformed = -1;

	/* --- the pairing map --- */
	CHECK (fs_rule_counterpart_kind (FS_RULE_OUTBOUND_ALLOW_TO)
	       == FS_RULE_INBOUND_ALLOW_FROM,
	       "an outbound allow-to pairs with an inbound allow-from");
	CHECK (fs_rule_counterpart_kind (FS_RULE_INBOUND_ALLOW_FROM)
	       == FS_RULE_OUTBOUND_ALLOW_TO,
	       "the host pairing is symmetric");
	CHECK (fs_rule_counterpart_kind (FS_RULE_OUTBOUND_ALLOW_SERVICE)
	       == FS_RULE_INBOUND_ALLOW_SERVICE,
	       "an outbound service allow pairs with the inbound one");
	CHECK (fs_rule_counterpart_kind (FS_RULE_INBOUND_ALLOW_SERVICE)
	       == FS_RULE_OUTBOUND_ALLOW_SERVICE,
	       "the service pairing is symmetric");
	CHECK (fs_rule_counterpart_kind (FS_RULE_OUTBOUND_DENY_TO)
	       == FS_RULE_N_KINDS,
	       "a deny has no counterpart (inbound is default-deny)");
	CHECK (fs_rule_counterpart_kind (FS_RULE_OUTBOUND_DENY_SERVICE)
	       == FS_RULE_N_KINDS,
	       "a service deny has no counterpart either");
	CHECK (fs_rule_counterpart_kind (FS_RULE_INBOUND_FORWARD)
	       == FS_RULE_N_KINDS,
	       "a forward only points one way");
	CHECK (fs_rule_counterpart_kind (FS_RULE_OUTBOUND_ALLOW_FROM)
	       == FS_RULE_N_KINDS,
	       "outbound-from would need an inbound-to kind, which the "
	       "policy does not have");

	/* --- the Direction setting's first entry --- */
	CHECK (g_strcmp0 (fs_rule_direction_label (FS_RULE_OUTBOUND_ALLOW_TO),
	                  "Outbound only") == 0,
	       "a pairable outbound kind defaults to Outbound only");
	CHECK (g_strcmp0 (fs_rule_direction_label (FS_RULE_INBOUND_ALLOW_FROM),
	                  "Inbound only") == 0,
	       "a pairable inbound kind defaults to Inbound only");
	CHECK (fs_rule_direction_label (FS_RULE_OUTBOUND_DENY_TO) == NULL,
	       "no Direction setting where the kind has no pair");

	/* --- the twin rule --- */
	rule = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_TO);
	rule->target  = g_strdup ("198.51.100.7");
	rule->comment = g_strdup ("pair teeth");
	cp = fs_rule_counterpart (rule);
	CHECK (cp != NULL, "a host allow has a twin");
	if (cp != NULL) {
		CHECK (cp->kind == FS_RULE_INBOUND_ALLOW_FROM,
		       "the twin carries the counterpart kind");
		CHECK (g_strcmp0 (cp->target, "198.51.100.7") == 0,
		       "the twin keeps the host");
		CHECK (g_strcmp0 (cp->comment, "pair teeth") == 0,
		       "the twin keeps the comment");
		fs_rule_free (cp);
	}
	fs_rule_free (rule);

	rule = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_SERVICE);
	rule->service = g_strdup ("brave.exe");
	rule->port    = g_strdup ("443");
	rule->target  = g_strdup ("203.0.113.8");
	cp = fs_rule_counterpart (rule);
	CHECK (cp != NULL, "a service allow has a twin");
	if (cp != NULL) {
		CHECK (cp->kind == FS_RULE_INBOUND_ALLOW_SERVICE,
		       "the service twin carries the counterpart kind");
		CHECK (g_strcmp0 (cp->service, "brave.exe") == 0 &&
		       g_strcmp0 (cp->port, "443") == 0 &&
		       g_strcmp0 (cp->target, "203.0.113.8") == 0,
		       "service, port and host all survive the pairing");
		fs_rule_free (cp);
	}
	fs_rule_free (rule);

	rule = fs_rule_new (FS_RULE_OUTBOUND_DENY_TO);
	CHECK (fs_rule_counterpart (rule) == NULL,
	       "a deny has no twin to stage");
	fs_rule_free (rule);

	/* --- the pair persists as one change --- */
	policy = fs_policy_new ();

	rule = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_TO);
	rule->target  = g_strdup ("198.51.100.221");
	rule->comment = g_strdup ("pair persist teeth");
	twin = fs_rule_counterpart (rule);

	out_before = fs_policy_count (policy, FS_RULE_OUTBOUND_ALLOW_TO);
	in_before  = fs_policy_count (policy, FS_RULE_INBOUND_ALLOW_FROM);

	CHECK (fs_policy_add_persist_pair (policy, rule, twin),
	       "the pair persists while writes work");
	CHECK (fs_policy_count (policy, FS_RULE_OUTBOUND_ALLOW_TO)
	       == out_before + 1,
	       "the first half is stored");
	CHECK (fs_policy_count (policy, FS_RULE_INBOUND_ALLOW_FROM)
	       == in_before + 1,
	       "the second half is stored too");

	/* The disk agrees: a fresh load sees both halves. */
	fresh = fs_policy_new ();
	CHECK (fs_policy_load (fresh, &malformed), "the files reload");
	CHECK (fs_policy_contains (fresh, rule),
	       "the first half reached disk");
	CHECK (fs_policy_contains (fresh, twin),
	       "the second half reached disk too");
	fs_policy_free (fresh);

	/* A stored primary is refused, like add_persist. */
	CHECK (!fs_policy_add_persist_pair (policy, rule, twin),
	       "a duplicate primary is refused");
	CHECK (fs_policy_count (policy, FS_RULE_OUTBOUND_ALLOW_TO)
	       == out_before + 1,
	       "the refusal changed nothing");

	/* --- rollback: the write fails, neither half stays --- */
	good_dir = g_strdup (fs_util_rules_dir ());
	bad_path = g_build_filename (g_get_tmp_dir (),
	                            "stockfw-rules-as-file", NULL);
	g_file_set_contents (bad_path, "not a directory", -1, NULL);
	g_setenv ("STOCKFW_RULES_DIR", bad_path, TRUE);

	{
		FsRule *r2 = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_TO);
		FsRule *t2;

		r2->target  = g_strdup ("198.51.100.222");
		r2->comment = g_strdup ("pair rollback teeth");
		t2 = fs_rule_counterpart (r2);

		CHECK (!fs_policy_add_persist_pair (policy, r2, t2),
		       "the pair save failure is reported");
		CHECK (fs_policy_count (policy, FS_RULE_OUTBOUND_ALLOW_TO)
		       == out_before + 1,
		       "neither half of the failed pair stayed behind (out)");
		CHECK (fs_policy_count (policy, FS_RULE_INBOUND_ALLOW_FROM)
		       == in_before + 1,
		       "neither half of the failed pair stayed behind (in)");

		fs_rule_free (r2);
		fs_rule_free (t2);
	}

	g_setenv ("STOCKFW_RULES_DIR", good_dir, TRUE);
	remove (bad_path);

	/* --- an already-stored twin completes the pair --- */
	{
		FsPolicy *half = fs_policy_new ();
		FsRule *r2 = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_TO);
		FsRule *t2;

		r2->target = g_strdup ("198.51.100.223");
		t2 = fs_rule_counterpart (r2);

		CHECK (fs_policy_add_persist (half, t2),
		       "the twin alone persists first");
		CHECK (fs_policy_add_persist_pair (half, r2, t2),
		       "an existing twin counts as the pair completing");
		CHECK (fs_policy_count (half, FS_RULE_OUTBOUND_ALLOW_TO) == 1,
		       "the missing half was added");
		CHECK (fs_policy_count (half, FS_RULE_INBOUND_ALLOW_FROM) == 1,
		       "the existing twin stayed");

		fs_rule_free (r2);
		fs_rule_free (t2);
		fs_policy_free (half);
	}

	g_free (good_dir);
	g_free (bad_path);
	fs_rule_free (rule);
	fs_rule_free (twin);
	fs_policy_free (policy);
}

/* The application trust engine: a file's hash and facts, signature
 * states through an injected provider, and the baseline that
 * notices when attested bytes change underneath us. */

static gboolean fake_sign_provider (const gchar *path,
                                    FsTrustSignature *out_sig,
                                    gchar **out_publisher,
                                    gpointer user)
{
	(void) path;
	(void) user;
	*out_sig = FS_TRUST_SIG_VALID;
	*out_publisher = g_strdup ("Example, \"Signer\", Inc.");
	return TRUE;
}

static gboolean fake_unsigned_provider (const gchar *path,
                                        FsTrustSignature *out_sig,
                                        gchar **out_publisher,
                                        gpointer user)
{
	(void) path;
	(void) user;
	*out_sig = FS_TRUST_SIG_UNSIGNED;
	*out_publisher = NULL;
	return TRUE;
}

static gboolean fake_silent_provider (const gchar *path,
                                      FsTrustSignature *out_sig,
                                      gchar **out_publisher,
                                      gpointer user)
{
	(void) path;
	(void) out_sig;
	(void) out_publisher;
	(void) user;
	return FALSE;
}

static void test_trust_engine (void)
{
	const gchar *payload_text = "StockFW trust engine test payload\n";
	const gchar *payload_sha =
		"7de4fddf8f5fdd52ac594d71ace412adf55291e66b38c18e42c046fd27240d4c";
	gchar *dir = g_build_filename (g_get_tmp_dir (),
	                               "stockfw-trust-test", NULL);
	gchar *payload = g_build_filename (dir, "payload.txt", NULL);
	gchar *missing = g_build_filename (dir, "gone.exe", NULL);
	gchar *fakeexe = g_build_filename (dir, "maybe.exe", NULL);
	gchar *store_file = g_build_filename (dir, "trust.csv", NULL);
	gchar *weird_file = g_build_filename (dir, "weird.csv", NULL);
	gchar *audit_file = g_build_filename (dir, "audit.log", NULL);
	FsTrustStore *store;
	FsTrustReport *report;
	FsTrustAssessment *assessment;
	GError *error = NULL;

	g_mkdir_with_parents (dir, 0700);
	remove (payload);
	remove (missing);
	remove (fakeexe);
	remove (store_file);
	remove (weird_file);
	remove (audit_file);
	g_setenv ("STOCKFW_AUDIT_FILE", audit_file, TRUE);
	g_file_set_contents (payload, payload_text, 34, NULL);

	/* Facts a digest can prove: the constant below was computed from
	 * the bytes above by `sha256sum', not by this code. */
	report = fs_trust_inspect (payload, &error);
	CHECK (report != NULL && error == NULL,
	       "a readable file yields a report");
	if (report != NULL) {
		CHECK (g_strcmp0 (report->sha256, payload_sha) == 0,
		       "the SHA-256 is the file's own (got %s)",
		       report->sha256);
		CHECK (report->size == 34,
		       "the byte count is the file's (got %"
		       G_GUINT64_FORMAT ")", report->size);
		CHECK (report->executable == FALSE,
		       "a text payload is not an executable");
		CHECK (report->sig == FS_TRUST_SIG_NOT_APPLICABLE,
		       "signature work is skipped for non-executables");
		fs_trust_report_free (report);
	}

	/* Nothing readable is an error, never a half-report. */
	report = fs_trust_inspect (missing, &error);
	CHECK (report == NULL && error != NULL,
	       "a missing file is an error, not a report");
	g_clear_error (&error);

	/* The signature half arrives as a provider, so its states are
	 * decided by the test -- not by this machine's certificate
	 * stores or clock. */
	g_file_set_contents (fakeexe, "MZ this is a fake executable", -1,
	                     NULL);

	report = fs_trust_inspect (fakeexe, NULL);
	CHECK (report != NULL && report->executable == TRUE,
	       "an MZ header marks an executable");
	CHECK (report != NULL && report->sig == FS_TRUST_SIG_UNKNOWN,
	       "an executable with nobody to ask reads as not checked");
	fs_trust_report_free (report);

	fs_trust_set_signature_provider (fake_sign_provider, NULL);
	report = fs_trust_inspect (fakeexe, NULL);
	CHECK (report != NULL && report->sig == FS_TRUST_SIG_VALID,
	       "a verifying platform verdict reaches the report");
	CHECK (report != NULL && g_strcmp0 (report->publisher,
	                                    "Example, \"Signer\", Inc.") == 0,
	       "the signer's name survives quoting intact");
	fs_trust_report_free (report);

	fs_trust_set_signature_provider (fake_unsigned_provider, NULL);
	report = fs_trust_inspect (fakeexe, NULL);
	CHECK (report != NULL && report->sig == FS_TRUST_SIG_UNSIGNED &&
	       report->publisher == NULL,
	       "an unsigned executable reports no signer");
	fs_trust_report_free (report);

	fs_trust_set_signature_provider (fake_silent_provider, NULL);
	report = fs_trust_inspect (fakeexe, NULL);
	CHECK (report != NULL && report->sig == FS_TRUST_SIG_UNKNOWN,
	       "a provider that cannot answer leaves the state unknown");
	fs_trust_report_free (report);
	fs_trust_set_signature_provider (NULL, NULL);

	/* The store path honours the same override style as the audit
	 * file, so tests never touch the user's baseline. */
	g_setenv ("STOCKFW_TRUST_FILE", store_file, TRUE);
	{
		gchar *home = fs_trust_store_path ();

		CHECK (g_strcmp0 (home, store_file) == 0,
		       "STOCKFW_TRUST_FILE decides the baseline's home");
		g_free (home);
	}
	g_unsetenv ("STOCKFW_TRUST_FILE");

	store = fs_trust_store_load (store_file);
	CHECK (store != NULL && fs_trust_store_count (store) == 0,
	       "no baseline yet: an empty store");

	assessment = fs_trust_assess (store, payload);
	CHECK (assessment != NULL &&
	       assessment->change == FS_TRUST_CHANGE_NEW,
	       "a never-attested file reads as new");
	fs_trust_assessment_free (assessment);

	report = fs_trust_inspect (payload, NULL);
	CHECK (fs_trust_attest (store, report),
	       "the report is attested into the baseline");
	CHECK (g_strcmp0 (fs_trust_store_path_at (store, 0),
	                  payload) == 0,
	       "the store hands out row paths for the page's list");
	CHECK (fs_trust_store_path_at (store, 1) == NULL &&
	       fs_trust_store_path_at (store, (guint) -1) == NULL,
	       "reading past the rows is refused");
	fs_trust_report_free (report);

	assessment = fs_trust_assess (store, payload);
	CHECK (assessment != NULL &&
	       assessment->change == FS_TRUST_CHANGE_UNCHANGED,
	       "an untouched file stays unchanged");
	CHECK (assessment != NULL &&
	       g_strcmp0 (assessment->baseline_sha256, payload_sha) == 0,
	       "the baseline remembers the attested hash");
	fs_trust_assessment_free (assessment);

	CHECK (fs_trust_store_save (store, &error) && error == NULL,
	       "the baseline saves to disk");
	fs_trust_store_free (store);
	g_clear_error (&error);

	store = fs_trust_store_load (store_file);
	CHECK (fs_trust_store_count (store) == 1,
	       "the attested row comes back from disk");

	/* Change the bytes under the attested name: the change the whole
	 * engine exists to notice. */
	g_file_set_contents (payload,
	                     "StockFW trust engine test payload, edited\n",
	                     -1, NULL);
	assessment = fs_trust_assess (store, payload);
	CHECK (assessment != NULL &&
	       assessment->change == FS_TRUST_CHANGE_CHANGED,
	       "an edited file is a change, loudly");
	CHECK (assessment != NULL && assessment->report != NULL &&
	       g_strcmp0 (assessment->report->sha256,
	                  assessment->baseline_sha256) != 0,
	       "the change is proven by two different hashes");
	fs_trust_assessment_free (assessment);

	/* Vanish it: the baseline is the only witness left. */
	remove (payload);
	assessment = fs_trust_assess (store, payload);
	CHECK (assessment != NULL &&
	       assessment->change == FS_TRUST_CHANGE_GONE,
	       "an attested file that disappears reads as gone");
	CHECK (assessment != NULL &&
	       g_strcmp0 (assessment->baseline_sha256, payload_sha) == 0,
	       "gone still carries what was attested");
	fs_trust_assessment_free (assessment);

	/* Forgetting is a write with a witness too. */
	CHECK (fs_trust_remove (store, payload),
	       "the baseline forgets a row");
	CHECK (!fs_trust_remove (store, payload),
	       "forgetting twice is refused, not invented");
	CHECK (fs_trust_store_count (store) == 0,
	       "the forgotten row is gone");

	/* Paths and publishers may hold commas and quotes; the CSV
	 * quotes them and the round trip must not lose either. */
	{
		FsTrustStore *weird = fs_trust_store_new (weird_file);
		FsTrustReport hand;

		memset (&hand, 0, sizeof (hand));
		hand.path = (gchar *) "C:\\Apps\\weird, dir\\app \"two\".exe";
		hand.sha256 = (gchar *)
			"aa11bb22cc33dd44ee55ff6677889900"
			"112233445566778899aabbccddee00ff";
		hand.size = 7;
		hand.mtime = 8;
		hand.sig = FS_TRUST_SIG_INVALID;
		hand.publisher = (gchar *)
			"Example, \"The Signer\", Inc.";

		CHECK (fs_trust_attest (weird, &hand),
		       "a comma-laden path attests");
		CHECK (fs_trust_store_save (weird, &error) && error == NULL,
		       "and saves");
		fs_trust_store_free (weird);
		g_clear_error (&error);

		weird = fs_trust_store_load (weird_file);
		CHECK (fs_trust_store_count (weird) == 1,
		       "the quoted row reloads whole");
		assessment = fs_trust_assess (weird, hand.path);
		CHECK (assessment != NULL &&
		       assessment->change == FS_TRUST_CHANGE_GONE &&
		       g_strcmp0 (assessment->baseline_sha256,
		                  hand.sha256) == 0 &&
		       g_strcmp0 (assessment->baseline_publisher,
		                  "Example, \"The Signer\", Inc.") == 0,
		       "commas and quotes survive the round trip");
		fs_trust_assessment_free (assessment);

		CHECK (fs_trust_store_save (weird, &error) && error == NULL,
		       "the reloaded baseline saves again");
		fs_trust_store_free (weird);
		g_clear_error (&error);
	}

	{
		gchar *contents = NULL;

		CHECK (g_file_get_contents (weird_file, &contents, NULL,
		                            NULL) &&
		       strstr (contents, ",invalid,") != NULL,
		       "the signature state has a spelling on disk");
		g_free (contents);
	}

	/* Every attestation and every forgetting was appended to the
	 * audit log: the baseline can be questioned afterwards. */
	{
		gchar *contents = NULL;

		CHECK (g_file_get_contents (audit_file, &contents, NULL,
		                            NULL),
		       "the audit file exists on disk");
		if (contents != NULL) {
			CHECK (strstr (contents, "trust-attest") != NULL,
			       "attestations reach the audit log");
			CHECK (strstr (contents, "trust-forget") != NULL,
			       "so does a forgetting");
			CHECK (strstr (contents, payload_sha) != NULL,
			       "with the hash that was attested");
		}
		g_free (contents);
	}

	g_unsetenv ("STOCKFW_AUDIT_FILE");
	remove (payload);
	remove (fakeexe);
	remove (store_file);
	remove (weird_file);
	remove (audit_file);
	g_free (payload);
	g_free (missing);
	g_free (fakeexe);
	g_free (store_file);
	g_free (weird_file);
	g_free (audit_file);
	g_free (dir);
}

int main (void)
{
	/* Point the preference file somewhere disposable before anything
	 * reads it: the path is computed once, on first use. */
#ifdef G_OS_WIN32
	g_setenv ("APPDATA", g_get_tmp_dir (), TRUE);
#else
	g_setenv ("XDG_CONFIG_HOME", g_get_tmp_dir (), TRUE);
#endif

	test_ports ();
	test_hosts ();
	test_rule_csv ();
	test_policy_persist ();
	test_fwrule_ports ();
	test_fwrule_expand ();
	test_fwrule_forward ();
	test_service_lookup ();
	test_script_generation ();
	test_copilot_suggestion_apply ();
	test_prefs_fallbacks ();
	test_copilot_profile_lifetime ();
	test_eventrule_builders ();
	test_policy_persist_rollback ();
	test_sentinel_beacon ();
	test_sentinel_fanout ();
	test_audit_log ();
	test_filter_match ();
	test_insight_apply ();
	test_policy_load_validation_f1 ();
	test_name_hygiene_f3 ();
	test_whatif_simulate ();
	test_whatif_reading ();
	test_direction_pairing ();
	test_trust_engine ();

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);

	return failures ? 1 : 0;
}
EOF

EXTRA_LIBS=""
if [ "${OS:-}" = "Windows_NT" ] || [ -d /ucrt64 ]; then
  EXTRA_LIBS="-lws2_32"
fi

cc "$BUILD_DIR/test-core.c" \
   -I src \
   $(pkg-config --cflags glib-2.0) \
   -o "$BUILD_DIR/test-core" \
   src/core/*.c \
   $(pkg-config --libs glib-2.0 gio-2.0) $EXTRA_LIBS

# Keep rule files out of the real rules directory.
export STOCKFW_RULES_DIR="$BUILD_DIR/rules"
rm -rf "$STOCKFW_RULES_DIR"

"$BUILD_DIR/test-core"