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

	CHECK (fs_prefs_get_bool ("/apps/firestarter/client/never/set",
	                          TRUE) == TRUE,
	       "missing bool key falls back to TRUE");
	CHECK (fs_prefs_get_bool ("/apps/firestarter/client/never/set",
	                          FALSE) == FALSE,
	       "missing bool key falls back to FALSE");
	CHECK (fs_prefs_get_int ("/apps/firestarter/client/never/set",
	                         42) == 42,
	       "missing int key falls back to 42");

	s = fs_prefs_get_string ("/apps/firestarter/client/never/set", "dflt");
	CHECK (g_strcmp0 (s, "dflt") == 0, "missing string key falls back");
	g_free (s);

	/* A stored value still wins over the fallback, in both directions. */
	fs_prefs_set_bool ("/apps/firestarter/client/sample", TRUE);
	CHECK (fs_prefs_get_bool ("/apps/firestarter/client/sample",
	                          FALSE) == TRUE,
	       "stored TRUE beats a FALSE fallback");

	fs_prefs_set_bool ("/apps/firestarter/client/sample", FALSE);
	CHECK (fs_prefs_get_bool ("/apps/firestarter/client/sample",
	                          TRUE) == FALSE,
	       "stored FALSE beats a TRUE fallback");

	fs_prefs_set_int ("/apps/firestarter/client/int_sample", 7);
	CHECK (fs_prefs_get_int ("/apps/firestarter/client/int_sample",
	                         99) == 7,
	       "stored int beats the fallback");
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
export FIRESTARTER_RULES_DIR="$BUILD_DIR/rules"
rm -rf "$FIRESTARTER_RULES_DIR"

"$BUILD_DIR/test-core"