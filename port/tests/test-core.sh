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
#include <gio/gio.h>
#include <stdio.h>
#include <string.h>
#include "core/fs-rules.h"
#include "core/fs-util.h"
#include "core/fs-service.h"
#include "core/fs-script.h"
#include "core/fs-settings-plan.h"
#include "core/fs-fwrule.h"
#include "core/fs-prefs.h"
#include "core/fs-copilot.h"
#include "core/fs-eventrule.h"
#include "core/fs-audit.h"
#include "core/fs-trust.h"
#include "core/fs-apply.h"
#include "core/fs-netparse.h"
#include "core/fs-activity.h"
#include "core/fs-json.h"
#include "core/fs-autoblock.h"
#include "core/fs-autostart.h"
#include "core/fs-blocktally.h"
#include <glib/gstdio.h>
#include <stdlib.h>
#ifndef G_OS_WIN32
#include <unistd.h>
#endif
#include "core/fs-i18n.h"
#include "core/fs-intelset.h"
#include "core/fs-intelwin.h"
#include "core/fs-winstore.h"
#include "core/fs-intel.h"
#include "core/fs-hostnet.h"
#include "core/fs-toolpath.h"
#include "core/fs-lockout.h"
#include <stdlib.h>

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

/* --- Windows rule translation (1.0.7) ---------------------------------
 *
 * Golden tests for fs_fwrule_*: what each policy row compiles to
 * (protocol, side, port spec, name) and the exact netsh argv.  Before
 * 1.0.7 most services compiled to protocol "any" with the port
 * dropped (allow-everything), '-' ranges and lists became "any port",
 * outbound service ports sat on the local side, and NTP was TCP. */

static void test_fwrule_ports (void)
{
	/* Each case: the port text, and the netsh spec (NULL: refused). */
	static const struct { const gchar *text; const gchar *spec; } cases[] = {
		{ "22", "22" },
		{ "67-68", "67-68" },
		{ "67:68", "67-68" },
		{ "1024:65535", "1024-65535" },
		{ "137-139 445", "137-139,445" },
		{ "137:139,445", "137-139,445" },
		{ "1234,1243,2772,2773", "1234,1243,2772,2773" },
		{ "80, 443", "80,443" },
		{ " 22 ", "22" },
		{ "22-22", "22" },
		{ "80,80", "80" },
		{ "1", "1" },
		{ "65535", "65535" },
		{ "0", NULL },
		{ "0-10", NULL },
		{ "65536", NULL },
		{ "99999", NULL },
		{ "200:100", NULL },
		{ "68-67", NULL },
		{ "67-", NULL },
		{ "-67", NULL },
		{ "1-2-3", NULL },
		{ "1:2-3", NULL },
		{ "abc", NULL },
		{ "0x50", NULL },
		{ "+80", NULL },
		{ "80abc", NULL },
		{ "22;23", NULL },
		{ "22\t23", NULL },
		{ "000022", NULL },
		{ "22,abc", NULL },
		{ ",", NULL },
		{ "", NULL },
	};

	for (guint i = 0; i < G_N_ELEMENTS (cases); i++) {
		gchar *spec = fs_fwrule_port_spec (cases[i].text);

		CHECK (g_strcmp0 (spec, cases[i].spec) == 0,
		       "port text \"%s\" -> %s (got %s)", cases[i].text,
		       cases[i].spec != NULL ? cases[i].spec : "refused",
		       spec != NULL ? spec : "refused");
		g_free (spec);
	}

	CHECK (fs_fwrule_port_spec (NULL) == NULL, "NULL port text is no spec");

	CHECK (fs_fwrule_port_spec_covers ("137-139,445", 138) &&
	       fs_fwrule_port_spec_covers ("137-139,445", 445) &&
	       fs_fwrule_port_spec_covers ("137-139,445", 137) &&
	       fs_fwrule_port_spec_covers ("137-139,445", 139),
	       "a spec covers every port in its ranges and list");
	CHECK (!fs_fwrule_port_spec_covers ("137-139,445", 140) &&
	       !fs_fwrule_port_spec_covers ("137-139,445", 136) &&
	       !fs_fwrule_port_spec_covers ("137-139,445", 444),
	       "and no port outside them");
	CHECK (fs_fwrule_port_spec_covers (NULL, 1) &&
	       fs_fwrule_port_spec_covers (NULL, 65535),
	       "no spec covers every port");
}

/* One expected rule of a golden case. */
typedef struct
{
	FsRuleProtocol proto;
	const gchar   *local;     /* expected local_ports  (NULL: any) */
	const gchar   *remote;    /* expected remote_ports (NULL: any) */
	const gchar   *suffix;    /* expected name ending, or NULL     */
} FwExpect;

static const gchar *
fw_proto_name (FsRuleProtocol p)
{
	return p == FS_PROTO_TCP ? "TCP" : p == FS_PROTO_UDP ? "UDP" : "ANY";
}

/* [ fw_golden ]
 * Compiles one row alone and compares every rule with the expected
 * list, in order.  n == 0 means the row must be refused, with a
 * reason. */
static void
fw_golden (FsRuleKind kind, const gchar *service, const gchar *port,
           const FwExpect *want, guint n)
{
	FsPolicy *policy = fs_policy_new ();
	FsRule *row = fs_rule_new (kind);
	GPtrArray *refused = NULL;
	GList *rules;
	gboolean inbound = (kind == FS_RULE_INBOUND_ALLOW_SERVICE ||
	                    kind == FS_RULE_INBOUND_FORWARD);
	guint i = 0;

	row->service = g_strdup (service);
	row->port = g_strdup (port);
	if (kind == FS_RULE_INBOUND_FORWARD) {
		row->to = g_strdup ("192.168.1.50");
		row->to_port = g_strdup ("8080");
	} else {
		row->target = g_strdup (FS_TARGET_ANY);
	}
	fs_policy_add (policy, row);
	fs_rule_free (row);

	rules = fs_fwrule_from_policy_checked (policy, &refused);

	if (n == 0) {
		CHECK (rules == NULL && refused->len == 1,
		       "%s %s port \"%s\" is refused, not widened "
		       "(%u rules, %u refusals)",
		       inbound ? "inbound" : "outbound",
		       service != NULL ? service : "(none)",
		       port != NULL ? port : "",
		       g_list_length (rules), refused->len);
		if (refused->len == 1)
			CHECK (strstr (g_ptr_array_index (refused, 0),
			               "was not applied") != NULL,
			       "the refusal says the rule was not applied: %s",
			       (gchar *) g_ptr_array_index (refused, 0));
	} else {
		CHECK (g_list_length (rules) == n && refused->len == 0,
		       "%s %s port \"%s\" compiles to %u rule(s) (got %u, "
		       "%u refused)", inbound ? "inbound" : "outbound",
		       service, port != NULL ? port : "", n,
		       g_list_length (rules), refused->len);
	}

	for (GList *l = rules; l != NULL && i < n; l = l->next, i++) {
		FsFwRule *r = l->data;

		CHECK (r->protocol == want[i].proto &&
		       g_strcmp0 (r->local_ports, want[i].local) == 0 &&
		       g_strcmp0 (r->remote_ports, want[i].remote) == 0,
		       "  %s \"%s\" rule %u: %s local=%s remote=%s "
		       "(got %s local=%s remote=%s)",
		       service, port != NULL ? port : "", i,
		       fw_proto_name (want[i].proto),
		       want[i].local ? want[i].local : "any",
		       want[i].remote ? want[i].remote : "any",
		       fw_proto_name (r->protocol),
		       r->local_ports ? r->local_ports : "any",
		       r->remote_ports ? r->remote_ports : "any");
		CHECK (r->direction == (inbound ? FS_DIR_INBOUND
		                                : FS_DIR_OUTBOUND),
		       "  %s \"%s\" rule %u keeps its direction", service,
		       port != NULL ? port : "", i);
		CHECK (fs_fwrule_is_sound (r),
		       "  %s \"%s\" rule %u is sound (a port means TCP or UDP)",
		       service, port != NULL ? port : "", i);
		if (want[i].suffix != NULL)
			CHECK (g_str_has_suffix (r->name, want[i].suffix),
			       "  name \"%s\" ends in \"%s\"", r->name,
			       want[i].suffix);
		else
			CHECK (!g_str_has_suffix (r->name, "(TCP)") &&
			       !g_str_has_suffix (r->name, "(UDP)"),
			       "  name \"%s\" carries no protocol suffix",
			       r->name);
	}

	g_ptr_array_unref (refused);
	fs_fwrule_list_free (rules);
	fs_policy_free (policy);
}

static void test_fwrule_services_golden (void)
{
	const FsRuleKind IN = FS_RULE_INBOUND_ALLOW_SERVICE;
	const FsRuleKind OUT = FS_RULE_OUTBOUND_ALLOW_SERVICE;
	const FsRuleKind DENY = FS_RULE_OUTBOUND_DENY_SERVICE;
	const gchar *T = " (TCP)";
	const gchar *U = " (UDP)";

	/* Every service in the user table, inbound on its default ports:
	 * the protocols it really uses, ports on the local side. */
	{
		FwExpect e[] = { { FS_PROTO_TCP, "6881-6889", NULL, T },
		                 { FS_PROTO_UDP, "6881-6889", NULL, U } };
		fw_golden (IN, "BitTorrent", "6881-6889", e, 2);
	}
	{
		FwExpect e[] = { { FS_PROTO_UDP, "67-68", NULL, NULL } };
		fw_golden (IN, "DHCP", "67-68", e, 1);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, "53", NULL, T },
		                 { FS_PROTO_UDP, "53", NULL, U } };
		fw_golden (IN, "DNS", "53", e, 2);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, "20-21", NULL, NULL } };
		fw_golden (IN, "FTP", "20-21", e, 1);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, "80", NULL, NULL } };
		fw_golden (IN, "HTTP", "80", e, 1);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, "443", NULL, T },
		                 { FS_PROTO_UDP, "443", NULL, U } };
		fw_golden (IN, "HTTPS", "443", e, 2);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, "143", NULL, NULL } };
		fw_golden (IN, "IMAP", "143", e, 1);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, "111,2049", NULL, T },
		                 { FS_PROTO_UDP, "111,2049", NULL, U } };
		fw_golden (IN, "NFS", "111 2049", e, 2);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, "119", NULL, NULL } };
		fw_golden (IN, "NNTP", "119", e, 1);
	}
	{
		FwExpect e[] = { { FS_PROTO_UDP, "123", NULL, NULL } };
		fw_golden (IN, "NTP", "123", e, 1);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, "110", NULL, NULL } };
		fw_golden (IN, "POP3", "110", e, 1);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, "139,445", NULL, T },
		                 { FS_PROTO_UDP, "137-138", NULL, U } };
		fw_golden (IN, "Samba (SMB)", "137-139 445", e, 2);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, "25", NULL, NULL } };
		fw_golden (IN, "SMTP", "25", e, 1);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, "22", NULL, NULL } };
		fw_golden (IN, "SSH", "22", e, 1);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, "23", NULL, NULL } };
		fw_golden (IN, "Telnet", "23", e, 1);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, "6000-6015", NULL, NULL } };
		fw_golden (IN, "Xwindows", "6000-6015", e, 1);
	}

	/* SSDP, from the back-door table, is UDP 1900; the other entries
	 * there have no protocol data and block both. */
	{
		FwExpect e[] = { { FS_PROTO_UDP, NULL, "1900", NULL } };
		fw_golden (DENY, "SSDP", "1900", e, 1);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, NULL, "12345,12346", T },
		                 { FS_PROTO_UDP, NULL, "12345,12346", U } };
		fw_golden (DENY, "Netbus", "12345,12346", e, 2);
	}

	/* Outbound: the service port is the REMOTE port. */
	{
		FwExpect e[] = { { FS_PROTO_UDP, NULL, "67-68", NULL } };
		fw_golden (OUT, "DHCP", "67-68", e, 1);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, NULL, "53", T },
		                 { FS_PROTO_UDP, NULL, "53", U } };
		fw_golden (OUT, "DNS", "53", e, 2);
	}
	{
		FwExpect e[] = { { FS_PROTO_UDP, NULL, "123", NULL } };
		fw_golden (OUT, "NTP", "123", e, 1);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, NULL, "25", NULL } };
		fw_golden (DENY, "SMTP", "25", e, 1);
	}

	/* Names as policies store them: hand-edited case, and the
	 * default policy's _("DHCP"). */
	{
		FwExpect e[] = { { FS_PROTO_TCP, "22", NULL, NULL } };
		fw_golden (IN, "ssh", "22", e, 1);
	}
	{
		FwExpect e[] = { { FS_PROTO_UDP, NULL, "67-68", NULL } };
		fw_golden (OUT, _("DHCP"), "67-68", e, 1);
	}

	/* A moved service: the row's ports, the service's protocols. */
	{
		FwExpect e[] = { { FS_PROTO_TCP, "2222", NULL, NULL } };
		fw_golden (IN, "SSH", "2222", e, 1);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, "445", NULL, T },
		                 { FS_PROTO_UDP, "445", NULL, U } };
		fw_golden (IN, "Samba (SMB)", "445", e, 2);
	}
	{
		FwExpect e[] = { { FS_PROTO_UDP, NULL, "5353", NULL } };
		fw_golden (OUT, "NTP", "5353", e, 1);
	}

	/* No port text: a known service uses its own ports. */
	{
		FwExpect e[] = { { FS_PROTO_TCP, "139,445", NULL, T },
		                 { FS_PROTO_UDP, "137-138", NULL, U } };
		fw_golden (IN, "Samba (SMB)", "", e, 2);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, "1234,1243,2772,2773", NULL, T },
		                 { FS_PROTO_UDP, "1234,1243,2772,2773", NULL, U } };
		fw_golden (IN, "Subseven", NULL, e, 2);
	}

	/* A custom name: both protocols on the row's ports, ranges and
	 * lists in both notations. */
	{
		FwExpect e[] = { { FS_PROTO_TCP, "8080", NULL, T },
		                 { FS_PROTO_UDP, "8080", NULL, U } };
		fw_golden (IN, "My game server", "8080", e, 2);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, NULL, "5000-5010,6000", T },
		                 { FS_PROTO_UDP, NULL, "5000-5010,6000", U } };
		fw_golden (OUT, "Custom", "5000:5010 6000", e, 2);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, "10000-20000", NULL, T },
		                 { FS_PROTO_UDP, "10000-20000", NULL, U } };
		fw_golden (IN, "Wide", "10000-20000", e, 2);
	}

	/* The pseudo-services the simulator writes: exactly that
	 * protocol.  With no port they are refused (test_fwrule_review). */
	{
		FwExpect e[] = { { FS_PROTO_TCP, "8443", NULL, NULL } };
		fw_golden (IN, "TCP", "8443", e, 1);
	}
	{
		FwExpect e[] = { { FS_PROTO_UDP, NULL, "5000-5010", NULL } };
		fw_golden (OUT, "UDP", "5000-5010", e, 1);
	}

	/* Port forwards: inbound, on the exposed local port. */
	{
		FwExpect e[] = { { FS_PROTO_TCP, "8080", NULL, NULL } };
		fw_golden (FS_RULE_INBOUND_FORWARD, "HTTP", "8080", e, 1);
	}
	{
		FwExpect e[] = { { FS_PROTO_TCP, "27015", NULL, T },
		                 { FS_PROTO_UDP, "27015", NULL, U } };
		fw_golden (FS_RULE_INBOUND_FORWARD, "Game", "27015", e, 2);
	}

	/* Refused, never "any port". */
	fw_golden (IN, "SSH", "0", NULL, 0);
	fw_golden (IN, "DNS", "70000", NULL, 0);
	fw_golden (OUT, "Custom", "200:100", NULL, 0);
	fw_golden (DENY, "SMTP", "25x", NULL, 0);
	fw_golden (IN, "Custom", "22;23", NULL, 0);
	fw_golden (IN, "TCP", "1-2-3", NULL, 0);
	fw_golden (IN, "My service", "", NULL, 0);
	fw_golden (IN, "ICMP", "", NULL, 0);
	fw_golden (FS_RULE_INBOUND_FORWARD, "HTTP", "eighty", NULL, 0);
}

/* Every concrete rule of the default policy and the old defects in
 * one place: no rule of any policy may be ANY with a port. */
static void test_fwrule_default_policy (void)
{
	FsPolicy *policy = fs_policy_new ();
	GPtrArray *refused = NULL;
	GList *rules;
	guint unsound = 0;

	fs_policy_install_defaults (policy);
	rules = fs_fwrule_from_policy_checked (policy, &refused);

	CHECK (g_list_length (rules) == 3 && refused->len == 0,
	       "the default policy compiles to 3 rules (DHCP UDP, DNS TCP "
	       "and UDP; got %u, %u refused)", g_list_length (rules),
	       refused->len);

	for (GList *l = rules; l != NULL; l = l->next) {
		FsFwRule *r = l->data;

		if (!fs_fwrule_is_sound (r))
			unsound++;
		CHECK (r->protocol != FS_PROTO_ANY && r->remote_ports != NULL &&
		       r->local_ports == NULL,
		       "default rule \"%s\" is %s to remote port %s",
		       r->name, fw_proto_name (r->protocol),
		       r->remote_ports != NULL ? r->remote_ports : "ANY");
	}

	CHECK (unsound == 0, "every default rule is sound");

	/* The soundness rule itself. */
	{
		FsFwRule *bad = fs_fwrule_new ();

		bad->name = g_strdup ("StockFW: Allow DNS (inbound)");
		bad->protocol = FS_PROTO_ANY;
		bad->local_ports = g_strdup ("53");
		CHECK (!fs_fwrule_is_sound (bad),
		       "protocol ANY with a port is not sound");
		CHECK (fs_fwrule_netsh_args (bad) == NULL,
		       "and netsh is never given it");

		bad->protocol = FS_PROTO_TCP;
		CHECK (fs_fwrule_is_sound (bad), "the same rule as TCP is");

		g_free (bad->local_ports);
		bad->local_ports = g_strdup ("53 54");
		CHECK (!fs_fwrule_is_sound (bad),
		       "a spec not in netsh form is not sound");

		g_free (bad->local_ports);
		bad->local_ports = NULL;
		bad->remote_ports = g_strdup ("0");
		CHECK (!fs_fwrule_is_sound (bad), "port 0 is not sound");

		g_free (bad->remote_ports);
		bad->remote_ports = NULL;
		bad->protocol = FS_PROTO_ANY;
		CHECK (fs_fwrule_is_sound (bad),
		       "protocol ANY with no port (a host rule) is sound");
		fs_fwrule_free (bad);
	}

	g_ptr_array_unref (refused);
	fs_fwrule_list_free (rules);
	fs_policy_free (policy);
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

	/* A range stays ONE spec per protocol: 1.0.6 wrote one rule per
	 * port (and any-port past 1024 ports). */
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

	/* SSH TCP, HTTPS TCP+UDP, "SMB" (a custom name) TCP+UDP, host. */
	CHECK (g_list_length (rules) == 6,
	       "policy expands to 6 concrete rules (got %u)",
	       g_list_length (rules));

	/* The address-scoped rule keeps its address. */
	{
		gboolean found = FALSE;

		for (iter = rules; iter != NULL; iter = iter->next) {
			FsFwRule *r = iter->data;

			if (r->direction == FS_DIR_INBOUND &&
			    g_strcmp0 (r->local_ports, "22") == 0) {
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
		guint found = 0;

		for (iter = rules; iter != NULL; iter = iter->next) {
			FsFwRule *r = iter->data;

			if (g_strcmp0 (r->local_ports, "443") == 0) {
				found++;
				CHECK (r->remote_address == NULL,
				       "\"Anyone\" becomes no address constraint");
			}
		}

		CHECK (found == 2, "HTTPS rules present, TCP and UDP");
	}

	/* The range is one spec on each protocol. */
	{
		guint ranged = 0;

		for (iter = rules; iter != NULL; iter = iter->next) {
			FsFwRule *r = iter->data;

			if (g_strcmp0 (r->local_ports, "137-139") == 0)
				ranged++;
		}

		CHECK (ranged == 2, "range 137:139 is one 137-139 rule per "
		       "protocol (got %u)", ranged);
	}

	/* The blocked host became a block rule. */
	for (iter = rules; iter != NULL; iter = iter->next) {
		FsFwRule *r = iter->data;

		if (r->direction == FS_DIR_OUTBOUND) {
			outbound_blocks++;
			CHECK (r->action == FS_ACTION_BLOCK,
			       "outbound deny is a block");
			CHECK (r->protocol == FS_PROTO_ANY &&
			       r->local_ports == NULL && r->remote_ports == NULL,
			       "a host rule stays protocol ANY with no port");
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
		CHECK (r->direction == FS_DIR_INBOUND &&
		       g_strcmp0 (r->local_ports, "80") == 0 &&
		       r->remote_ports == NULL,
		       "forward listens on the firewall's local port");
		CHECK (g_strcmp0 (r->forward_address, "192.168.1.50") == 0,
		       "forward targets the internal host");
	}

	fs_fwrule_list_free (rules);
	fs_policy_free (policy);
}

/* [ netsh_golden ]
 * The argv of the first rule a one-row policy compiles to (index
 * `which'), joined with '|' for one comparison. */
static gchar *
netsh_golden (FsRuleKind kind, const gchar *service, const gchar *port,
              const gchar *target, guint which)
{
	FsPolicy *policy = fs_policy_new ();
	FsRule *row = fs_rule_new (kind);
	GList *rules;
	gchar *joined = NULL;
	FsFwRule *rule;

	row->service = g_strdup (service);
	row->port = g_strdup (port);
	if (kind == FS_RULE_INBOUND_FORWARD) {
		row->to = g_strdup ("192.168.1.50");
		row->to_port = g_strdup ("80");
	} else {
		row->target = g_strdup (target);
	}
	fs_policy_add (policy, row);
	fs_rule_free (row);

	rules = fs_fwrule_from_policy (policy);
	rule = g_list_nth_data (rules, which);

	if (rule != NULL) {
		GStrv args = fs_fwrule_netsh_args (rule);

		if (args != NULL)
			joined = g_strjoinv ("|", args);
		g_strfreev (args);
	}

	fs_fwrule_list_free (rules);
	fs_policy_free (policy);

	return joined;
}

static void test_fwrule_netsh_golden (void)
{
	static const gchar *head =
		"netsh.exe|advfirewall|firewall|add|rule|";
	struct {
		FsRuleKind kind;
		const gchar *service, *port, *target;
		guint which;
		const gchar *argv;      /* after head */
		const gchar *what;
	} cases[] = {
		{ FS_RULE_INBOUND_ALLOW_SERVICE, "SSH", "22", FS_TARGET_ANY, 0,
		  "name=StockFW- Allow SSH -inbound-|profile=any|dir=in|"
		  "action=allow|protocol=TCP|enable=yes|localport=22",
		  "inbound service" },
		{ FS_RULE_INBOUND_ALLOW_SERVICE, "SSH", "22", "192.168.1.0/24", 0,
		  "name=StockFW- Allow SSH -inbound- 192.168.1.0-24-|"
		  "profile=any|dir=in|action=allow|protocol=TCP|enable=yes|"
		  "localport=22|remoteip=192.168.1.0/24",
		  "inbound service from a network" },
		{ FS_RULE_OUTBOUND_DENY_SERVICE, "SMTP", "25", FS_TARGET_ANY, 0,
		  "name=StockFW- Block SMTP -outbound-|profile=any|dir=out|"
		  "action=block|protocol=TCP|enable=yes|remoteport=25",
		  "outbound service block on the remote port" },
		{ FS_RULE_OUTBOUND_ALLOW_SERVICE, "DHCP", "67-68", FS_TARGET_ANY, 0,
		  "name=StockFW- Allow DHCP -outbound-|profile=any|dir=out|"
		  "action=allow|protocol=UDP|enable=yes|remoteport=67-68",
		  "outbound DHCP, UDP on a '-' range" },
		{ FS_RULE_INBOUND_ALLOW_SERVICE, "DNS", "53", FS_TARGET_ANY, 0,
		  "name=StockFW- Allow DNS -inbound- -TCP-|profile=any|dir=in|"
		  "action=allow|protocol=TCP|enable=yes|localport=53",
		  "both-protocol service, the TCP half" },
		{ FS_RULE_INBOUND_ALLOW_SERVICE, "DNS", "53", FS_TARGET_ANY, 1,
		  "name=StockFW- Allow DNS -inbound- -UDP-|profile=any|dir=in|"
		  "action=allow|protocol=UDP|enable=yes|localport=53",
		  "both-protocol service, the UDP half" },
		{ FS_RULE_INBOUND_ALLOW_SERVICE, "Samba (SMB)", "137-139 445",
		  FS_TARGET_ANY, 0,
		  "name=StockFW- Allow Samba -SMB- -inbound- -TCP-|profile=any|"
		  "dir=in|action=allow|protocol=TCP|enable=yes|"
		  "localport=139,445",
		  "a port list in netsh form" },
		{ FS_RULE_OUTBOUND_DENY_TO, NULL, NULL, "10.0.0.7", 0,
		  "name=StockFW- Block outbound -10.0.0.7-|profile=any|dir=out|"
		  "action=block|protocol=any|enable=yes|remoteip=10.0.0.7",
		  "host rule: protocol any, no port" },
		{ FS_RULE_INBOUND_FORWARD, "HTTP", "8080", NULL, 0,
		  "name=StockFW- Allow HTTP -inbound-|profile=any|dir=in|"
		  "action=allow|protocol=TCP|enable=yes|localport=8080",
		  "port forward on the exposed port" },
		{ FS_RULE_INBOUND_ALLOW_SERVICE, "TCP", "8443", FS_TARGET_ANY, 0,
		  "name=StockFW- Allow TCP -inbound-|profile=any|dir=in|"
		  "action=allow|protocol=TCP|enable=yes|localport=8443",
		  "TCP pseudo-service: TCP only, on its port" },
	};

	for (guint i = 0; i < G_N_ELEMENTS (cases); i++) {
		gchar *got = netsh_golden (cases[i].kind, cases[i].service,
		                           cases[i].port, cases[i].target,
		                           cases[i].which);
		gchar *want = g_strconcat (head, cases[i].argv, NULL);

		CHECK (g_strcmp0 (got, want) == 0,
		       "netsh argv, %s:\n        want %s\n        got  %s",
		       cases[i].what, want, got != NULL ? got : "(none)");

		CHECK (got == NULL || strchr (got, '"') == NULL,
		       "netsh argv, %s: no quote characters", cases[i].what);

		g_free (want);
		g_free (got);
	}

	{
		gchar *name = fs_fwrule_netsh_name (
			"StockFW: Allow DNS (inbound, 2001:db8::/32) (UDP)");

		CHECK (g_strcmp0 (name, "StockFW- Allow DNS -inbound- "
		                        "2001-db8---32- -UDP-") == 0,
		       "netsh names keep the StockFW prefix the clear relies "
		       "on (got %s)", name);
		g_free (name);
	}
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

	/* iptables reads a tcp/udp port with base 0: "022" written as typed
	 * would be port 18.  The generator writes plain decimal. */
	{
		FsPolicy *padded = fs_policy_new ();
		FsRule *row = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);
		gchar *text, *a, *b;

		row->service = g_strdup ("SSH");
		row->port = g_strdup ("022");
		row->target = g_strdup ("192.168.1.0/24");
		fs_policy_add (padded, row);
		fs_rule_free (row);
		text = fs_script_generate_inbound (padded, settings);
		CHECK (text != NULL &&
		       strstr (text, "-p tcp --dport 22 -j ACCEPT") != NULL &&
		       strstr (text, "--dport 022") == NULL,
		       "a zero-padded port is written in plain decimal");
		g_free (text);
		fs_policy_free (padded);

		a = fs_script_port_text ("0067-068");
		b = fs_script_port_text ("+22");
		CHECK (g_strcmp0 (a, "67:68") == 0,
		       "a padded range is written as 67:68 (%s)", a ? a : "NULL");
		CHECK (b == NULL || strcmp (b, "22") == 0,
		       "a signed port is refused or written plain (%s)",
		       b ? b : "NULL");
		g_free (a);
		g_free (b);
	}
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

	/* 1.0.7 session safety: the running program's periodic save
	 * writes the settings only when this says they changed. */
	{
		const gchar *path = fs_prefs_path ();
		gboolean existed = g_file_test (path, G_FILE_TEST_EXISTS);

		CHECK (fs_prefs_dirty (), "a setter marks the settings dirty");
		CHECK (fs_prefs_save () && !fs_prefs_dirty (),
		       "a save leaves them clean");
		fs_prefs_set_string ("/apps/stockfw/client/str_sample", "x");
		CHECK (fs_prefs_dirty (), "the next setter marks them again");
		CHECK (fs_prefs_load () && !fs_prefs_dirty (),
		       "a load leaves them clean");
		if (!existed)
			g_unlink (path);
	}
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
	CHECK (beacon != NULL && beacon->severity == FS_COPILOT_WARNING,
	       "the beacon is a Warning, not Critical: timing alone is not proof");
	CHECK (beacon != NULL && !beacon->auto_applicable &&
	       beacon->withheld != NULL &&
	       strstr (beacon->withheld, "waits for 8 contacts") != NULL,
	       "at six contacts it is report-only, and says it waits for 8");
	CHECK (beacon != NULL && beacon->evidence != NULL &&
	       beacon->evidence->len == 6 &&
	       ((FsEvidence *) g_ptr_array_index (beacon->evidence, 5))->when -
	       ((FsEvidence *) g_ptr_array_index (beacon->evidence, 4))->when == 60,
	       "the evidence holds the six contacts, 60 s apart");
	CHECK (beacon != NULL && beacon->why != NULL &&
	       strstr (beacon->why, "0.30") != NULL &&
	       strstr (beacon->why, "6 contacts") != NULL,
	       "why: the numbers next to the limits (\"%s\")",
	       beacon != NULL && beacon->why != NULL ? beacon->why : "");
	CHECK (beacon != NULL && beacon->benign != NULL &&
	       strstr (beacon->benign, "Update checks") != NULL &&
	       strstr (beacon->description, "so do update checks") != NULL,
	       "the text says what else looks like this");
	CHECK (beacon != NULL &&
	       g_strcmp0 (beacon->whatif_line,
	                  "outbound tcp port 8443 to 203.0.113.9") == 0,
	       "Ask What-If gets the matching line");

	/* Contacts 7 and 8: the same finding, now eligible for the block. */
	for (i = 6; i < 8; i++)
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * 60 * G_USEC_PER_SEC);
	CHECK (count_insights (copilot, FS_INSIGHT_BEACON) == 1,
	       "contacts 7 and 8 update the finding, they add no second one");
	beacon = find_insight (copilot, FS_INSIGHT_BEACON);
	CHECK (beacon != NULL && beacon->count >= 2 &&
	       beacon->evidence->len == 8,
	       "the updated finding holds all eight contacts");
	if (beacon != NULL) {
		FsPolicy *policy = fs_policy_new ();
		FsRule *probe;

		CHECK (beacon->auto_applicable && beacon->rule_csv != NULL &&
		       beacon->withheld == NULL,
		       "at eight contacts the beacon carries an auto-applicable rule");
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
	for (i = 8; i < 11; i++)
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
	hit.direction = "Out";

	/* Two programs polling one server are two series: interleaved,
	 * each is every 60 s; mixed together they would be every 30 s. */
	copilot = fs_copilot_new ();
	for (i = 0; i < 6; i++) {
		hit.service = "agent-a.exe";
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * 60 * G_USEC_PER_SEC);
		hit.service = "agent-b.exe";
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) (i * 60 + 30) * G_USEC_PER_SEC);
	}
	CHECK (count_insights (copilot, FS_INSIGHT_BEACON) == 2,
	       "two apps polling one destination are two series (got %u)",
	       count_insights (copilot, FS_INSIGHT_BEACON));
	fs_copilot_free (copilot);
	hit.service = "unknown";

	/* Time sync is periodic by nature: port 123 is never timed. */
	copilot = fs_copilot_new ();
	hit.port = "123";
	hit.protocol = "UDP";
	for (i = 0; i < 10; i++)
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * 64 * G_USEC_PER_SEC);
	CHECK (count_insights (copilot, FS_INSIGHT_BEACON) == 0,
	       "NTP (port 123) is never reported as a beacon");
	fs_copilot_free (copilot);

	/* DNS to this computer's resolvers is never timed; DNS to another
	 * server is. */
	copilot = fs_copilot_new ();
	fs_copilot_set_resolvers (copilot, "# test\nnameserver 203.0.113.9\n");
	hit.port = "53";
	for (i = 0; i < 8; i++)
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * 60 * G_USEC_PER_SEC);
	CHECK (count_insights (copilot, FS_INSIGHT_BEACON) == 0,
	       "DNS to a configured resolver is not a beacon");
	hit.destination = "198.51.100.53";
	for (i = 0; i < 8; i++)
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * 60 * G_USEC_PER_SEC);
	CHECK (count_insights (copilot, FS_INSIGHT_BEACON) == 1,
	       "DNS to some other server is timed like anything else");
	fs_copilot_free (copilot);

	/* A beacon to an address a block list names is Critical. */
	copilot = fs_copilot_new ();
	hit.port = "8443";
	hit.protocol = "TCP";
	hit.destination = "203.0.113.66";
	hit.rule = "Threat intel: Spamhaus DROP";
	for (i = 0; i < 6; i++)
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * 60 * G_USEC_PER_SEC);
	beacon = find_insight (copilot, FS_INSIGHT_BEACON);
	CHECK (beacon != NULL && beacon->severity == FS_COPILOT_CRITICAL &&
	       strstr (beacon->why, "block list") != NULL,
	       "a beacon to a listed address is Critical and says why");
	/* CORRECTNESS-2 (1.0.7 release review): What-If does not consult
	 * the lists or the country and network rules, so it would answer
	 * "Allowed" and a block rule would look like a change. */
	CHECK (beacon != NULL && beacon->whatif_line == NULL &&
	       beacon->rule_csv == NULL && beacon->suggested_rule == NULL &&
	       !beacon->auto_applicable && beacon->withheld != NULL &&
	       strstr (beacon->withheld, "already blocks it") != NULL,
	       "a beacon a list blocks offers no What-If line and no block "
	       "(%s)", beacon != NULL ? beacon->withheld : "none");
	fs_copilot_free (copilot);

	/* Reported first while allowed, then blocked by a country rule:
	 * the block and the What-If line of the first report go. */
	copilot = fs_copilot_new ();
	hit.destination = "203.0.113.67";
	hit.rule = NULL;
	for (i = 0; i < 6; i++)
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * 60 * G_USEC_PER_SEC);
	beacon = find_insight (copilot, FS_INSIGHT_BEACON);
	CHECK (beacon != NULL && beacon->whatif_line != NULL &&
	       beacon->rule_csv != NULL,
	       "an allowed beacon offers What-If and a block");
	hit.rule = "Threat intel: Country CN";
	for (i = 6; i < 10; i++)
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * 60 * G_USEC_PER_SEC);
	beacon = find_insight (copilot, FS_INSIGHT_BEACON);
	CHECK (count_insights (copilot, FS_INSIGHT_BEACON) == 1 &&
	       beacon != NULL && beacon->severity == FS_COPILOT_CRITICAL &&
	       beacon->whatif_line == NULL && beacon->rule_csv == NULL &&
	       beacon->suggested_rule == NULL && !beacon->auto_applicable,
	       "once a country rule blocks it, the same finding drops the "
	       "block and the What-If line (%s)",
	       beacon != NULL && beacon->rule_csv != NULL ? beacon->rule_csv
	                                                  : "none");
	fs_copilot_free (copilot);
	hit.rule = NULL;
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
	/* A program's name, as a Windows log carries it: a port's service
	 * name ("HTTPS") stands for every program on the port, and only
	 * refused hosts count for it (test_copilot_review_fixes, F10). */
	hit.service   = "scanner.exe";

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
			CHECK (fo->severity == FS_COPILOT_WARNING,
			       "the fan-out is a Warning");
			CHECK (fo->why != NULL && strstr (fo->why, "60 distinct") &&
			       fo->application != NULL &&
			       strstr (fo->title, "scanner.exe") != NULL,
			       "it names the program and the numbers");
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

	/* Per program: two apps reaching 40 hosts each are not one app
	 * reaching 80. */
	copilot = fs_copilot_new ();
	for (i = 0; i < 40; i++) {
		g_snprintf (dest, sizeof dest, "203.0.113.%d", i);
		hit.destination = dest;
		hit.service = "browser.exe";
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * G_USEC_PER_SEC);
		g_snprintf (dest, sizeof dest, "198.51.100.%d", i);
		hit.service = "mail.exe";
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * G_USEC_PER_SEC);
	}
	CHECK (count_insights (copilot, FS_INSIGHT_FANOUT) == 0,
	       "two apps reaching 40 hosts each do not trip the 60-host limit");
	fs_copilot_free (copilot);
}

/* ==== P6: false-outage hardening (2026-10-10 incident) ============
 * StockFW blocked this machine's own internet, and the demand was
 * "not just DeepSeek, any platform".  These checks pin the three
 * gates that make that true: the destination classes that may never
 * be auto-blocked (protocol infrastructure and the user's own
 * address space), the established-baseline veto (metronomic traffic
 * to a destination the application already talks to is reported, not
 * blocked), and the netsh name parser whose CSV-only shape let every
 * clear delete nothing while full applies stacked 479 rules with 28
 * copies of a single name. */

static void test_sentinel_auto_gates (void)
{
	static const gchar *never[] = {
		/* the incident's own hits, plus the rest of the classes */
		"224.0.0.252",          /* LLMNR, Windows' own multicast     */
		"239.255.255.250",      /* SSDP discovery                    */
		"192.168.1.21",         /* the user's own machine            */
		"192.168.50.2",         /* the user's own gateway            */
		"127.0.0.1",            /* loopback                          */
		"0.0.0.0", "10.0.0.1", "100.64.0.1", "100.127.255.255",
		"169.254.10.10", "172.16.0.1", "172.31.255.254",
		"224.0.0.1", "239.1.2.3", "240.0.0.1", "255.255.255.255",
		"::1", "::", "fe80::1", "ff02::1", "fd00::1", "fec0::1",
		"::ffff:192.168.1.1",   /* mapped: laundering buys nothing  */
		"::ffff:127.0.0.1",
		"",                     /* unparseable is withheld           */
		"not-an-ip",
		"evil.example.com"
	};
	static const gchar *ok[] = {
		"3.173.21.63",          /* the incident's CDN: genuinely public */
		"8.8.8.8", "1.1.1.1", "9.9.9.9",
		"203.0.113.9", "198.51.100.77", "104.20.32.17",
		"2606:4700::1111", "::ffff:8.8.8.8"
	};
	guint i;

	for (i = 0; i < G_N_ELEMENTS (never); i++)
		CHECK (fs_sentinel_dest_never_auto_block (never[i]),
		       "never auto-blocked: \"%s\"", never[i]);

	CHECK (fs_sentinel_dest_never_auto_block (NULL),
	       "a NULL destination is withheld");

	for (i = 0; i < G_N_ELEMENTS (ok); i++)
		CHECK (!fs_sentinel_dest_never_auto_block (ok[i]),
		       "still blockable (public): \"%s\"", ok[i]);

	/* The choke point refuses a deny at a withheld destination even
	 * when the insight itself claims auto. */
	{
		FsInsight ins;

		memset (&ins, 0, sizeof ins);
		ins.type = FS_INSIGHT_BEACON;
		ins.severity = FS_COPILOT_CRITICAL;
		ins.auto_applicable = TRUE;

		ins.rule_kind = FS_RULE_OUTBOUND_DENY_TO;
		ins.rule_csv = (gchar *) "224.0.0.252, Sentinel: periodic beacon";
		CHECK (!fs_insight_is_auto_safe (&ins),
		       "a multicast deny is never auto-safe");

		ins.rule_csv = (gchar *) "192.168.1.21, Sentinel: periodic beacon";
		CHECK (!fs_insight_is_auto_safe (&ins),
		       "a LAN deny is never auto-safe");

		ins.rule_csv = (gchar *) "203.0.113.9, Sentinel: periodic beacon";
		CHECK (fs_insight_is_auto_safe (&ins),
		       "a public deny stays auto-safe");

		ins.rule_kind = FS_RULE_OUTBOUND_ALLOW_SERVICE;
		ins.rule_csv = (gchar *) "HTTP, 80, 203.0.113.9, hi";
		CHECK (!fs_insight_is_auto_safe (&ins),
		       "an allow suggestion is never auto-safe");

		ins.rule_kind = FS_RULE_OUTBOUND_DENY_TO;
		ins.rule_csv = NULL;
		CHECK (!fs_insight_is_auto_safe (&ins),
		       "no rule is never auto-safe");
	}

	/* The established-baseline veto: three recorded connections and
	 * the destination is part of the application's normal life. */
	{
		FsCopilot *c = fs_copilot_new ();
		FsHit hit;
		gint n;

		CHECK (!fs_copilot_baseline_dest_established (c, "app.exe",
		                                              "9.9.9.9"),
		       "no profile at all: nothing is established");

		memset (&hit, 0, sizeof hit);
		hit.direction   = "Out";
		hit.source      = "192.168.1.7";
		hit.destination = "9.9.9.9";
		hit.port        = "80";
		hit.protocol    = "TCP";
		hit.service     = "app.exe";

		for (n = 0; n < 2; n++)
			fs_copilot_feed_event_at (c, &hit,
			                          (gint64) 400000 * G_USEC_PER_SEC +
			                          (gint64) n * 600 * G_USEC_PER_SEC);

		CHECK (!fs_copilot_baseline_dest_established (c, "app.exe",
		                                              "9.9.9.9"),
		       "two connections: the destination is still new");

		fs_copilot_feed_event_at (c, &hit,
		                          (gint64) 400000 * G_USEC_PER_SEC +
		                          2 * 600 * G_USEC_PER_SEC);

		CHECK (fs_copilot_baseline_dest_established (c, "app.exe",
		                                             "9.9.9.9"),
		       "three connections: the destination is established");
		CHECK (!fs_copilot_baseline_dest_established (c, "other.exe",
		                                              "9.9.9.9"),
		       "another application does not inherit the baseline");
		CHECK (!fs_copilot_baseline_dest_established (c, "app.exe",
		                                              "8.8.8.8"),
		       "the baseline is per destination");
		fs_copilot_free (c);
	}

	/* Same metronomic traffic, three verdicts: a public stranger is
	 * auto-blockable; the LAN, the multicast infrastructure and an
	 * established CDN are report-only.  These are the incident's
	 * exact shapes. */
	{
		FsCopilot *c;
		FsHit hit;
		const FsInsight *b;
		gint i;
		const gint64 t0 = (gint64) 910000 * G_USEC_PER_SEC;

		memset (&hit, 0, sizeof hit);
		hit.direction = "Out";
		hit.source    = "192.168.1.7";
		hit.port      = "443";
		hit.protocol  = "TCP";

		/* a public destination the baseline has never seen */
		c = fs_copilot_new ();
		hit.service     = "stranger.exe";
		hit.destination = "203.0.113.50";
		for (i = 0; i < 8; i++)
			fs_copilot_feed_event_at (c, &hit,
			                          t0 + (gint64) i * 60 * G_USEC_PER_SEC);
		b = find_insight (c, FS_INSIGHT_BEACON);
		CHECK (b != NULL && b->auto_applicable,
		       "a metronomic stranger is reported and auto-blockable");
		fs_copilot_free (c);

		/* the user's own LAN host */
		c = fs_copilot_new ();
		hit.service     = "lan.exe";
		hit.destination = "192.168.77.50";
		for (i = 0; i < 8; i++)
			fs_copilot_feed_event_at (c, &hit,
			                          t0 + (gint64) i * 60 * G_USEC_PER_SEC);
		b = find_insight (c, FS_INSIGHT_BEACON);
		CHECK (b != NULL, "the LAN beacon is still reported");
		CHECK (b == NULL || !b->auto_applicable,
		       "the LAN beacon is never auto-blockable");
		fs_copilot_free (c);

		/* Windows' own LLMNR multicast */
		c = fs_copilot_new ();
		hit.service     = "svchost.exe";
		hit.destination = "224.0.0.252";
		for (i = 0; i < 8; i++)
			fs_copilot_feed_event_at (c, &hit,
			                          t0 + (gint64) i * 60 * G_USEC_PER_SEC);
		b = find_insight (c, FS_INSIGHT_BEACON);
		CHECK (b != NULL, "the multicast beacon is still reported");
		CHECK (b == NULL || !b->auto_applicable,
		       "the multicast beacon is never auto-blockable");
		fs_copilot_free (c);

		/* the browser's own established CDN: history first (port 80),
		 * then the metronomic tail (port 443).  The beacon key is
		 * dst:port, the baseline key is app+dest -- so the history
		 * vetoes the auto-block without hiding the report. */
		c = fs_copilot_new ();
		hit.service     = "browser.exe";
		hit.destination = "104.20.32.17";
		hit.port        = "80";
		for (i = 0; i < 3; i++)
			fs_copilot_feed_event_at (c, &hit,
			                          t0 + (gint64) i * 3600 * G_USEC_PER_SEC);
		hit.port = "443";
		for (i = 0; i < 8; i++)
			fs_copilot_feed_event_at (
				c, &hit,
				t0 + (gint64) 3 * 3600 * G_USEC_PER_SEC +
				(gint64) i * 60 * G_USEC_PER_SEC);
		b = find_insight (c, FS_INSIGHT_BEACON);
		CHECK (b != NULL,
		       "the established CDN beacon is still reported");
		CHECK (b == NULL || !b->auto_applicable,
		       "an established baseline destination is not auto-blockable");
		CHECK (b != NULL && b->withheld != NULL &&
		       strstr (b->withheld, "already talked") != NULL,
		       "and the row says why the block was withheld");
		fs_copilot_free (c);
	}

	/* No finding that could open something is ever auto-applicable:
	 * every check, on a mixed corpus, offers auto only on deny rows. */
	{
		FsCopilot *c = fs_copilot_new ();
		FsHit hit;
		GList *all, *l;
		guint autos = 0, bad = 0;
		gchar port[16], src[32];
		gint i;
		const gint64 t0 = (gint64) 930000 * G_USEC_PER_SEC;

		memset (&hit, 0, sizeof hit);
		hit.direction = "Out";
		hit.source = "192.168.1.7";
		hit.protocol = "TCP";
		hit.service = "mixed.exe";
		hit.destination = "203.0.113.70";
		for (i = 0; i < 40; i++) {           /* baseline, then new ports */
			g_snprintf (port, sizeof port, "%d", i < 12 ? 443 : 2000 + i);
			hit.port = port;
			fs_copilot_feed_event_full (c, &hit,
				t0 + (gint64) i * 7 * G_USEC_PER_SEC, 1700000000 + i);
		}
		hit.port = "8443";
		hit.destination = "203.0.113.71";
		for (i = 0; i < 9; i++)              /* a beacon */
			fs_copilot_feed_event_full (c, &hit,
				t0 + (gint64) (1000 + i * 60) * G_USEC_PER_SEC,
				1700001000 + i * 60);
		hit.direction = "In";
		hit.destination = "192.168.1.7";
		hit.service = "SSH [BLOCKED]";
		hit.port = "22";
		for (i = 0; i < 12; i++) {           /* login attempts + a scan */
			g_snprintf (src, sizeof src, "198.51.100.%d", 1 + (i % 2));
			hit.source = src;
			fs_copilot_feed_event_full (c, &hit,
				t0 + (gint64) (2000 + i) * G_USEC_PER_SEC,
				1700002000 + i);
		}
		all = fs_copilot_get_insights (c);
		for (l = all; l != NULL; l = l->next) {
			FsInsight *ins = l->data;

			if (!ins->auto_applicable)
				continue;
			autos++;
			if (ins->rule_kind != FS_RULE_OUTBOUND_DENY_TO &&
			    ins->rule_kind != FS_RULE_OUTBOUND_DENY_SERVICE)
				bad++;
		}
		CHECK (g_list_length (all) >= 2 && autos == 1 && bad == 0,
		       "a mixed corpus: only the beacon's deny is auto-applicable "
		       "(%u auto, %u not a deny, of %u findings)", autos, bad,
		       g_list_length (all));
		for (l = all; l != NULL; l = l->next) {
			FsInsight *ins = l->data;

			if (ins->type != FS_INSIGHT_BEACON)
				CHECK (ins->rule_csv == NULL &&
				       ins->suggested_rule == NULL,
				       "\"%s\" offers no rule (an anomaly is not answered "
				       "with an allow)", ins->title);
		}
		g_list_free (all);
		fs_copilot_free (c);
	}

	/* The netsh name parser: text records, our prefix only.  This is
	 * the piece whose CSV-only shape let every clear delete nothing
	 * and every full apply stack copies (479 rules, 28 of one name). */
	{
		static const gchar fixture[] =
			"Rule Name:                            "
			    "StockFW- Block outbound -3.173.21.63-\r\n"
			"Enabled:                              Yes\r\n"
			"Rule Name:                            "
			    "StockFW- Allow outbound -203.0.113.9-\r\n"
			"Rule Name:                            "
			    "Core Networking - DNS (UDP-Out)\r\n"
			"Rule Name:                            "
			    "@FirewallAPI.dll,-28752\r\n"
			"Rule Name:                            "
			    "StockFW Allow service -HTTP-\r\n"
			"Rule Name:                            NotStockFW- not ours\r\n"
			"\r\n"
			"StockFW- bare name line\r\n"
			"StockFW- csv shaped,Outbound,Yes\r\n";
		GHashTable *names = fs_netsh_rule_names_extract (fixture);

		CHECK (g_hash_table_size (names) == 5,
		       "the parser finds exactly our 5 names (got %u)",
		       g_hash_table_size (names));
		CHECK (g_hash_table_contains (names,
		       "StockFW- Block outbound -3.173.21.63-"),
		       "text-form block name collected");
		CHECK (g_hash_table_contains (names,
		       "StockFW- Allow outbound -203.0.113.9-"),
		       "text-form allow name collected");
		CHECK (g_hash_table_contains (names,
		       "StockFW Allow service -HTTP-"),
		       "the space prefix still matches (legacy rules)");
		CHECK (g_hash_table_contains (names, "StockFW- bare name line"),
		       "a bare name line is collected");
		CHECK (g_hash_table_contains (names, "StockFW- csv shaped"),
		       "the CSV first field is collected without its tail");
		CHECK (!g_hash_table_contains (names,
		       "Core Networking - DNS (UDP-Out)"),
		       "a foreign rule name is not ours");
		CHECK (!g_hash_table_contains (names, "NotStockFW- not ours"),
		       "a near-miss prefix is not ours");
		g_hash_table_destroy (names);

		names = fs_netsh_rule_names_extract (NULL);
		CHECK (g_hash_table_size (names) == 0,
		       "empty output yields no names");
		g_hash_table_destroy (names);
	}
}

/* ==== P2: explainable behavior analysis ============================
 * Historical baselines (persisted) and correlated findings.  Every
 * check pins one honest input or one explainability promise: the
 * right end of the conversation is learned, one profile per program,
 * every signal in one finding, timing and rate driven by an
 * injectable clock, and a baseline that survives the restart. */

static void
behavior_hit (FsHit *hit, const gchar *service, const gchar *src,
              const gchar *dst, const gchar *port, const gchar *dir)
{
	memset (hit, 0, sizeof *hit);
	hit->service = (gchar *) service;
	hit->source = (gchar *) src;
	hit->destination = (gchar *) dst;
	hit->port = (gchar *) port;
	hit->direction = (gchar *) dir;
	hit->protocol = (gchar *) "TCP";
}

/* Same-second arrival on purpose: a batch is one moment, so Sentinel
 * never sees a beacon between two behavior-test events. */
static void
behavior_feed (FsCopilot *copilot, FsHit *hit, gint64 now_unix)
{
	fs_copilot_feed_event_full (copilot, hit,
	                            (gint64) 420000 * G_USEC_PER_SEC,
	                            now_unix);
}

static guint
total_insights (FsCopilot *copilot)
{
	GList *insights = fs_copilot_get_insights (copilot);
	guint n = g_list_length (insights);

	g_list_free (insights);
	return n;
}

static void test_behavior_derivation (void)
{
	FsCopilot *copilot = fs_copilot_new ();
	FsHit hit;
	const FsAppProfile *p;
	GList *all;

	/* Outbound: the remote host is the DESTINATION; the source is
	 * our own address. */
	behavior_hit (&hit, "chrome.exe", "192.168.1.7", "203.0.113.9",
	              "443", "out");
	behavior_feed (copilot, &hit, 1700000000);
	p = fs_copilot_get_profile (copilot, "chrome.exe");
	CHECK (p != NULL, "the profile is keyed by the executable name");
	CHECK (p != NULL &&
	       g_hash_table_contains (p->common_destinations, "203.0.113.9"),
	       "an outbound event records the remote destination");
	CHECK (p != NULL &&
	       !g_hash_table_contains (p->common_destinations, "192.168.1.7"),
	       "an outbound event never mistakes our own address for a destination");

	/* Inbound, lowercase as the Windows backend writes it: the
	 * remote host is the SOURCE. */
	behavior_hit (&hit, "chrome.exe", "198.51.100.20", "192.168.1.7",
	              "443", "in");
	behavior_feed (copilot, &hit, 1700000000);
	p = fs_copilot_get_profile (copilot, "chrome.exe");
	CHECK (p != NULL &&
	       g_hash_table_contains (p->common_destinations, "198.51.100.20"),
	       "an inbound event records the source as the remote host");

	/* The blocked marker must not split the profile in two. */
	behavior_hit (&hit, "svchost.exe [BLOCKED]", "192.168.1.7",
	              "203.0.113.9", "443", "out");
	behavior_feed (copilot, &hit, 1700000000);
	CHECK (fs_copilot_get_profile (copilot, "svchost.exe") != NULL,
	       "a blocked event is filed under the program, not the marker");
	all = fs_copilot_get_all_profiles (copilot);
	CHECK (g_list_length (all) == 2,
	       "the [BLOCKED] marker does not start a second profile");
	g_list_free (all);

	behavior_hit (&hit, "svchost.exe", "192.168.1.7", "203.0.113.9",
	              "443", "out");
	behavior_feed (copilot, &hit, 1700000000);
	p = fs_copilot_get_profile (copilot, "svchost.exe");
	CHECK (p != NULL && p->total_connections == 2,
	       "blocked and allowed events share one history");

	/* No service at all: one honest "Unknown" profile. */
	behavior_hit (&hit, NULL, "192.168.1.7", "203.0.113.9", "53", "out");
	behavior_feed (copilot, &hit, 1700000000);
	CHECK (fs_copilot_get_profile (copilot, "Unknown") != NULL,
	       "an event without a service lands in one Unknown profile");

	fs_copilot_free (copilot);
}

/* A profile that is 8 days old with 50 connections over three hours:
 * old and large enough for the new-destination check. */
static void
behavior_mature (FsCopilot *copilot, FsHit *hit, const gchar *app,
                 gint64 start)
{
	const gint64 step = 5 * 3600;

	behavior_hit (hit, app, "192.168.1.7", "198.51.100.10", "443", "out");
	for (gint k = 0; k < 3; k++)
		for (gint i = 0; i < (k < 2 ? 17 : 16); i++)
			behavior_feed (copilot, hit, start + k * step);
}

static void test_behavior_signals (void)
{
	FsCopilot *copilot = fs_copilot_new ();
	FsHit hit;
	const FsInsight *ins;
	GDateTime *dt;
	gchar *expected;
	gchar dest[32];
	gint i;
	const gint64 w0 = 1700000400;
	const gint64 start = w0 - 8 * 86400;   /* same local hour as w0 */

	behavior_mature (copilot, &hit, "sync.exe", start);
	CHECK (total_insights (copilot) == 0,
	       "the baseline phase raises nothing at all");

	/* The correlation moment: ONE event, a new port AND a new
	 * destination together. */
	behavior_hit (&hit, "sync.exe", "192.168.1.7", "203.0.113.66",
	              "8443", "out");
	behavior_feed (copilot, &hit, w0);

	CHECK (total_insights (copilot) == 1,
	       "two signals on one event raise exactly one finding");
	ins = find_insight (copilot, FS_INSIGHT_UNUSUAL_PORT);
	CHECK (ins != NULL, "the finding is typed by its strongest signal");
	CHECK (ins != NULL && ins->severity == FS_COPILOT_WARNING,
	       "two signals together are a Warning (Critical needs a Critical "
	       "check or two different checks)");
	if (ins != NULL) {
		CHECK (strstr (ins->description, "8443") != NULL,
		       "the description names the new port");
		CHECK (strstr (ins->description, "203.0.113.66") != NULL,
		       "and the new destination");
		CHECK (strstr (ins->description, "\n- ") != NULL,
		       "as two listed signals, not one");
		CHECK (ins->rule_csv == NULL && ins->suggested_rule == NULL &&
		       !ins->auto_applicable,
		       "a behavior finding suggests no rule");
		CHECK (ins->why != NULL && strstr (ins->why, "8 days") != NULL &&
		       strstr (ins->why, "50 connections") != NULL,
		       "why: the profile's age and size next to the limits (%s)",
		       ins->why != NULL ? ins->why : "");
		CHECK (ins->evidence != NULL && ins->evidence->len == 1 &&
		       ((FsEvidence *) g_ptr_array_index (ins->evidence, 0))->port
		       == 8443,
		       "the event behind it is the evidence");
	}

	/* A single new destination: Info, no allow offered. */
	behavior_hit (&hit, "sync.exe", "192.168.1.7", "203.0.113.77",
	              "443", "out");
	behavior_feed (copilot, &hit, w0 + 60);
	CHECK (count_insights (copilot, FS_INSIGHT_UNUSUAL_DESTINATION) == 1,
	       "a first contact raises one destination finding");
	ins = find_insight (copilot, FS_INSIGHT_UNUSUAL_DESTINATION);
	CHECK (ins != NULL && ins->severity == FS_COPILOT_INFO,
	       "a single signal is Info");
	if (ins != NULL) {
		CHECK (strstr (ins->description, "203.0.113.77") != NULL,
		       "the description names the host");
		CHECK (strstr (ins->description, "The baseline knew 2") != NULL,
		       "and how many destinations the baseline knew");
		CHECK (ins->rule_csv == NULL && ins->suggested_rule == NULL,
		       "no allow is offered for an anomaly");
		CHECK (g_strcmp0 (ins->whatif_line,
		                  "outbound tcp port 443 to 203.0.113.77") == 0,
		       "Ask What-If gets the line instead");
	}

	/* A second new destination in the same hour joins that finding. */
	behavior_hit (&hit, "sync.exe", "192.168.1.7", "203.0.113.78",
	              "443", "out");
	behavior_feed (copilot, &hit, w0 + 120);
	ins = find_insight (copilot, FS_INSIGHT_UNUSUAL_DESTINATION);
	CHECK (count_insights (copilot, FS_INSIGHT_UNUSUAL_DESTINATION) == 1 &&
	       ins != NULL && ins->count == 2 && ins->evidence->len == 2,
	       "one finding per app per hour: the second contact updates it");

	/* Our own network and infrastructure are never "new destinations". */
	behavior_hit (&hit, "sync.exe", "192.168.1.7", "192.168.5.5",
	              "443", "out");
	behavior_feed (copilot, &hit, w0 + 5 * 3600);
	behavior_hit (&hit, "sync.exe", "192.168.1.7", "224.0.0.251",
	              "443", "out");
	behavior_feed (copilot, &hit, w0 + 5 * 3600);
	CHECK (count_insights (copilot, FS_INSIGHT_UNUSUAL_DESTINATION) == 1,
	       "a LAN or multicast first contact is not reported");

	/* First activity in a new hour, once the app HAS hours. */
	dt = g_date_time_new_from_unix_local (w0 + 2 * 3600);
	expected = g_strdup_printf ("first activity at %02d:00",
	                            g_date_time_get_hour (dt));
	g_date_time_unref (dt);

	behavior_hit (&hit, "sync.exe", "192.168.1.7", "198.51.100.10",
	              "443", "out");
	behavior_feed (copilot, &hit, w0 + 2 * 3600);
	CHECK (count_insights (copilot, FS_INSIGHT_UNUSUAL_TIME) == 1,
	       "the first activity in a new hour is a timing finding");
	ins = find_insight (copilot, FS_INSIGHT_UNUSUAL_TIME);
	CHECK (ins != NULL && ins->severity == FS_COPILOT_INFO,
	       "a lone timing finding stays informational");
	if (ins != NULL) {
		CHECK (strstr (ins->description, expected) != NULL,
		       "the description names the unexpected hour");
		CHECK (strstr (ins->description, "Established hours") != NULL,
		       "and points at the established ones");
	}
	g_free (expected);

	behavior_feed (copilot, &hit, w0 + 2 * 3600);
	CHECK (count_insights (copilot, FS_INSIGHT_UNUSUAL_TIME) == 1,
	       "a second event in that hour says nothing new");
	fs_copilot_free (copilot);

	/* Too young or too small: no new-destination finding at all. */
	copilot = fs_copilot_new ();
	behavior_hit (&hit, "young.exe", "192.168.1.7", "198.51.100.10",
	              "443", "out");
	for (i = 0; i < 60; i++)
		behavior_feed (copilot, &hit, w0 - 86400);
	behavior_hit (&hit, "young.exe", "192.168.1.7", "203.0.113.90",
	              "443", "out");
	behavior_feed (copilot, &hit, w0);
	CHECK (count_insights (copilot, FS_INSIGHT_UNUSUAL_DESTINATION) == 0,
	       "a one-day-old profile (60 connections) raises no destination "
	       "finding: the check needs 7 days");
	fs_copilot_free (copilot);

	copilot = fs_copilot_new ();
	behavior_hit (&hit, "small.exe", "192.168.1.7", "198.51.100.10",
	              "443", "out");
	for (i = 0; i < 40; i++)
		behavior_feed (copilot, &hit, start);
	behavior_hit (&hit, "small.exe", "192.168.1.7", "203.0.113.90",
	              "443", "out");
	behavior_feed (copilot, &hit, w0);
	CHECK (count_insights (copilot, FS_INSIGHT_UNUSUAL_DESTINATION) == 0,
	       "an 8-day-old profile with 40 connections raises none: the check "
	       "needs 50");
	fs_copilot_free (copilot);

	/* The churn guard: an app that meets 20 new hosts in a week is
	 * browser-like, and the 21st is not news. */
	for (gint churn = 0; churn < 2; churn++) {
		guint before, after;

		copilot = fs_copilot_new ();
		behavior_mature (copilot, &hit, "browser.exe", start);
		for (i = 0; i < (churn ? 20 : 1); i++) {
			g_snprintf (dest, sizeof dest, "203.0.113.%d", 100 + i);
			behavior_hit (&hit, "browser.exe", "192.168.1.7", dest,
			              "443", "out");
			behavior_feed (copilot, &hit, w0);
		}
		before = count_insights (copilot, FS_INSIGHT_UNUSUAL_DESTINATION);
		behavior_hit (&hit, "browser.exe", "192.168.1.7", "198.51.100.200",
		              "443", "out");
		behavior_feed (copilot, &hit, w0 + 10 * 3600);
		after = count_insights (copilot, FS_INSIGHT_UNUSUAL_DESTINATION);
		if (churn)
			CHECK (before == 1 && after == 1,
			       "after 20 new hosts in a week the app is browser-like: "
			       "the next new host raises nothing");
		else
			CHECK (before == 1 && after == 2,
			       "with one earlier new host, a new host in another hour "
			       "is a second finding");
		fs_copilot_free (copilot);
	}
}

static void test_behavior_hour_guard (void)
{
	FsCopilot *copilot = fs_copilot_new ();
	FsHit hit;
	gint i;
	const gint64 w0 = 1700000400;

	/* Ten connections in one hour: the profile has no "usual hours"
	 * yet, so a new hour must not be judged unusual. */
	behavior_hit (&hit, "young.exe", "192.168.1.7", "198.51.100.10",
	              "443", "out");
	for (i = 0; i < 10; i++)
		behavior_feed (copilot, &hit, w0);
	behavior_feed (copilot, &hit, w0 + 5 * 3600);

	CHECK (total_insights (copilot) == 0,
	       "without established hours, a new hour claims nothing");

	fs_copilot_free (copilot);
}

static void test_behavior_rate (void)
{
	FsCopilot *copilot = fs_copilot_new ();
	FsHit hit;
	const FsInsight *ins;
	gint i, b;
	const gint64 r0 = 1700000400;   /* aligned to the 10-min window */

	behavior_hit (&hit, "burst.exe", "192.168.1.7", "198.51.100.30",
	              "443", "out");

	/* Ten quiet buckets of three: the rate this app established. */
	for (b = 0; b < 10; b++)
		for (i = 0; i < 3; i++)
			behavior_feed (copilot, &hit,
			               r0 + (gint64) b * 600);

	CHECK (total_insights (copilot) == 0,
	       "a steady rate raises nothing");

	/* Ten times that rate, inside one bucket. */
	for (i = 0; i < 30; i++)
		behavior_feed (copilot, &hit, r0 + 9 * 600);

	CHECK (count_insights (copilot, FS_INSIGHT_UNUSUAL_VOLUME) == 1,
	       "the burst raises exactly one rate finding");
	ins = find_insight (copilot, FS_INSIGHT_UNUSUAL_VOLUME);
	if (ins != NULL) {
		CHECK (strstr (ins->description,
		               "connections in the last 10 minutes") != NULL,
		       "the finding counts the burst");
		CHECK (strstr (ins->description,
		               "usual rate is about 3") != NULL,
		       "and names the rate the app established");
	}
	CHECK (count_insights (copilot, FS_INSIGHT_UNUSUAL_VOLUME) == 1,
	       "a burst is reported once per window, not per event");

	/* The next quiet bucket stays quiet. */
	for (i = 0; i < 3; i++)
		behavior_feed (copilot, &hit, r0 + 10 * 600);
	CHECK (count_insights (copilot, FS_INSIGHT_UNUSUAL_VOLUME) == 1,
	       "the next quiet bucket says nothing");

	fs_copilot_free (copilot);
}

static void test_behavior_insight_cap (void)
{
	FsCopilot *copilot = fs_copilot_new ();
	FsHit hit;
	gchar dest[64];
	gint i;

	/* A flood of findings: 205 sources each scanning 12 ports.  The
	 * insight list is bounded, and the flood cannot grow it without
	 * end. */
	for (i = 1; i <= 205; i++) {
		g_snprintf (dest, sizeof dest, "203.0.%d.%d", 100 + i / 200,
		            i % 200 + 1);
		for (gint p = 0; p < 12; p++) {
			gchar port[8];

			g_snprintf (port, sizeof port, "%d", 1000 + p);
			behavior_hit (&hit, "Unknown [BLOCKED]", dest, "192.168.1.7",
			              port, "In");
			behavior_feed (copilot, &hit, 1700000400);
		}
	}

	CHECK (total_insights (copilot) == 200,
	       "the insight list stops at its cap, however loud the flood");

	fs_copilot_free (copilot);
}

/* ==== 1.0.7 Copilot: inbound checks, block lists, dedup ==========
 * Driven with exact clocks (monotonic for the windows, unix for the
 * evidence and the once-per-hour memory). */

static void
inbound_feed (FsCopilot *c, const gchar *src, guint port,
              gboolean blocked, gint64 sec)
{
	FsHit hit;
	gchar p[8];

	g_snprintf (p, sizeof p, "%u", port);
	memset (&hit, 0, sizeof hit);
	hit.direction = (gchar *) "In";
	hit.source = (gchar *) src;
	hit.destination = (gchar *) "192.168.1.7";
	hit.port = p;
	hit.protocol = (gchar *) "TCP";
	hit.service = (gchar *) (blocked ? "Unknown [BLOCKED]" : "Unknown");
	fs_copilot_feed_event_full (c, &hit,
	                            (gint64) (950000 + sec) * G_USEC_PER_SEC,
	                            1700100000 + sec);
}

static void test_inbound_scan (void)
{
	FsCopilot *c;
	const FsInsight *ins;
	gint i;

	/* 12 distinct ports in a minute, all refused: one Info finding. */
	c = fs_copilot_new ();
	for (i = 0; i < 12; i++)
		inbound_feed (c, "203.0.113.5", 1000 + i, TRUE, i * 4);
	CHECK (count_insights (c, FS_INSIGHT_INBOUND_SCAN) == 1,
	       "scan: 12 local ports in 60 s from one source report once");
	ins = find_insight (c, FS_INSIGHT_INBOUND_SCAN);
	CHECK (ins != NULL && ins->severity == FS_COPILOT_INFO &&
	       strstr (ins->description, "was refused") != NULL,
	       "scan: all refused is Info, and says so");
	CHECK (ins != NULL && ins->rule_csv == NULL && !ins->auto_applicable &&
	       ins->withheld != NULL,
	       "scan: never a rule, never auto");
	CHECK (ins != NULL && ins->evidence->len == 12 &&
	       strstr (ins->description, "1000, 1001") != NULL &&
	       strstr (ins->why, "12 distinct ports in the last 60 seconds") != NULL,
	       "scan: the evidence and the counts next to the limits");

	/* More ports from the same source within the hour: still one. */
	for (i = 12; i < 30; i++)
		inbound_feed (c, "203.0.113.5", 1000 + i, TRUE, 50 + i);
	CHECK (count_insights (c, FS_INSIGHT_INBOUND_SCAN) == 1,
	       "scan: one report per source per hour");
	fs_copilot_free (c);

	/* 11 ports, each tried twice: 22 events, not a scan. */
	c = fs_copilot_new ();
	for (i = 0; i < 22; i++)
		inbound_feed (c, "203.0.113.6", 2000 + i % 11, TRUE, i * 2);
	CHECK (count_insights (c, FS_INSIGHT_INBOUND_SCAN) == 0,
	       "scan: 11 distinct ports do not (22 events: ports, not events, "
	       "count)");
	fs_copilot_free (c);

	/* 25 ports over 10 minutes, slowly. */
	c = fs_copilot_new ();
	for (i = 0; i < 25; i++)
		inbound_feed (c, "203.0.113.7", 3000 + i, TRUE, i * 20);
	CHECK (count_insights (c, FS_INSIGHT_INBOUND_SCAN) == 1,
	       "scan: 25 ports in 10 minutes report, however slow");
	fs_copilot_free (c);

	/* Some got through to allowed ports: a Warning naming them. */
	c = fs_copilot_new ();
	for (i = 0; i < 12; i++)
		inbound_feed (c, "198.51.100.40", i == 3 ? 22 : 4000 + i, i != 3,
		              i);
	ins = find_insight (c, FS_INSIGHT_INBOUND_SCAN);
	CHECK (ins != NULL && ins->severity == FS_COPILOT_WARNING &&
	       strstr (ins->description, "ports your policy allows: 22") != NULL,
	       "scan: reaching an allowed port is a Warning that names it");
	fs_copilot_free (c);

	/* From the LAN: Info, whatever got through. */
	c = fs_copilot_new ();
	for (i = 0; i < 12; i++)
		inbound_feed (c, "192.168.1.50", 5000 + i, FALSE, i);
	ins = find_insight (c, FS_INSIGHT_INBOUND_SCAN);
	CHECK (ins != NULL && ins->severity == FS_COPILOT_INFO &&
	       strstr (ins->why, "local network") != NULL,
	       "scan: a LAN scanner is reported as Info");
	fs_copilot_free (c);

	/* Loopback is not a scanner. */
	c = fs_copilot_new ();
	for (i = 0; i < 20; i++)
		inbound_feed (c, "127.0.0.1", 6000 + i, FALSE, i);
	CHECK (count_insights (c, FS_INSIGHT_INBOUND_SCAN) == 0,
	       "scan: loopback is ignored");
	fs_copilot_free (c);
}

static void test_brute_force (void)
{
	FsCopilot *c;
	FsPolicy *policy;
	const FsInsight *ins;
	gint i;

	/* 10 refused SSH attempts in 5 minutes, no policy attached. */
	c = fs_copilot_new ();
	for (i = 0; i < 10; i++)
		inbound_feed (c, "198.51.100.23", 22, TRUE, i * 25);
	CHECK (count_insights (c, FS_INSIGHT_BRUTE_FORCE) == 1,
	       "brute: 10 attempts in 5 minutes report");
	ins = find_insight (c, FS_INSIGHT_BRUTE_FORCE);
	CHECK (ins != NULL && ins->severity == FS_COPILOT_INFO &&
	       ins->rule_csv == NULL && !ins->auto_applicable,
	       "brute: all refused is Info, never a rule, never auto");
	CHECK (ins != NULL && strstr (ins->description, "SSH") != NULL &&
	       strstr (ins->description, "allowed-event logging") != NULL &&
	       ins->evidence->len == 10,
	       "brute: names the service, the logging caveat, the attempts");
	fs_copilot_free (c);

	/* 9 do not. */
	c = fs_copilot_new ();
	for (i = 0; i < 9; i++)
		inbound_feed (c, "198.51.100.23", 22, TRUE, i * 25);
	CHECK (count_insights (c, FS_INSIGHT_BRUTE_FORCE) == 0,
	       "brute: 9 attempts do not");
	fs_copilot_free (c);

	/* 10 spread over 6 minutes: never 10 inside any 5 minutes. */
	c = fs_copilot_new ();
	for (i = 0; i < 10; i++)
		inbound_feed (c, "198.51.100.23", 22, TRUE, i * 40);
	CHECK (count_insights (c, FS_INSIGHT_BRUTE_FORCE) == 0,
	       "brute: 10 attempts over 6 minutes do not (the window expires)");
	fs_copilot_free (c);

	/* Not a login port. */
	c = fs_copilot_new ();
	for (i = 0; i < 15; i++)
		inbound_feed (c, "198.51.100.23", 8080, TRUE, i * 5);
	CHECK (count_insights (c, FS_INSIGHT_BRUTE_FORCE) == 0,
	       "brute: port 8080 is not a login port");
	fs_copilot_free (c);

	/* The policy lets the source in: Critical. */
	c = fs_copilot_new ();
	policy = fs_policy_new ();
	{
		FsRule *r = fs_rule_from_csv (FS_RULE_INBOUND_ALLOW_SERVICE,
		                              "RDP, 3389, Anyone");

		fs_policy_add (policy, r);
		fs_rule_free (r);
	}
	fs_copilot_set_policy (c, policy);
	for (i = 0; i < 10; i++)
		inbound_feed (c, "198.51.100.24", 3389, TRUE, i * 25);
	ins = find_insight (c, FS_INSIGHT_BRUTE_FORCE);
	CHECK (ins != NULL && ins->severity == FS_COPILOT_CRITICAL &&
	       strstr (ins->title, "the policy lets it in") != NULL &&
	       strstr (ins->why, "ALLOWED") != NULL,
	       "brute: Critical when What-If says the policy allows the source");
	CHECK (ins != NULL && ins->rule_csv == NULL && !ins->auto_applicable,
	       "brute: even then, never auto-applicable");

	/* From the LAN, allowed, one of them refused: a Warning.  (With
	 * none refused it is Info: test_copilot_review_fixes, F5.) */
	for (i = 0; i < 10; i++)
		inbound_feed (c, "192.168.1.60", 3389, i == 0, 400 + i * 2);
	{
		GList *all = fs_copilot_get_insights (c);
		gboolean lan_warn = FALSE;

		for (GList *l = all; l != NULL; l = l->next) {
			FsInsight *x = l->data;

			if (x->type == FS_INSIGHT_BRUTE_FORCE &&
			    g_strcmp0 (x->subject, "192.168.1.60") == 0)
				lan_warn = x->severity == FS_COPILOT_WARNING;
		}
		g_list_free (all);
		CHECK (lan_warn, "brute: an allowed LAN source is a Warning");
	}
	fs_copilot_free (c);
	fs_policy_free (policy);

	/* What-If says DEPENDS, and the log shows connections let in: the
	 * log answers it for the network this computer was on.  The case
	 * on each platform model: on Linux a row for a host name; on
	 * Windows a private source, which StockFW's reserved-source block
	 * stops on Public networks only (the Copilot asks without the
	 * network in use).  All refused stays Info. */
	policy = fs_policy_new ();
	{
		FsRule *r = fs_rule_from_csv (FS_RULE_INBOUND_ALLOW_SERVICE,
#ifdef G_OS_WIN32
		                              "RDP, 3389, Anyone"
#else
		                              "RDP, 3389, lan.example"
#endif
		                              );
		FsWhatIfContext *ctx;
		FsWhatIfResult *res;

		fs_policy_add (policy, r);
		fs_rule_free (r);
		ctx = fs_whatif_context_new (fs_whatif_native_platform (), policy,
		                             NULL);
		ctx->firewall = FS_WHATIF_FW_RUNNING;
		res = fs_whatif_simulate_text (ctx,
		                               "inbound tcp port 3389 from 192.168.1.61");
		CHECK (res->verdict == FS_WHATIF_DEPENDS,
		       "brute: the probe for this case depends (got %s)",
		       fs_whatif_verdict_name (res->verdict));
		fs_whatif_result_free (res);
		fs_whatif_context_free (ctx);
	}
	c = fs_copilot_new ();
	fs_copilot_set_policy (c, policy);
	for (i = 0; i < 10; i++)
		inbound_feed (c, "192.168.1.61", 3389, i == 0, i * 2);
	for (i = 0; i < 10; i++)
		inbound_feed (c, "192.168.1.62", 3389, TRUE, 100 + i * 2);
	{
		const FsInsight *let = NULL, *refused = NULL;
		GList *all = fs_copilot_get_insights (c);

		for (GList *l = all; l != NULL; l = l->next) {
			const FsInsight *x = l->data;

			if (x->type != FS_INSIGHT_BRUTE_FORCE)
				continue;
			if (g_strcmp0 (x->subject, "192.168.1.61") == 0)
				let = x;
			if (g_strcmp0 (x->subject, "192.168.1.62") == 0)
				refused = x;
		}
		CHECK (let != NULL && let->severity == FS_COPILOT_WARNING &&
		       strstr (let->title, "lets it in") != NULL &&
		       strstr (let->description, "answer depends") != NULL &&
		       strstr (let->why, "DEPENDS") != NULL,
		       "brute: DEPENDS with connections let in is a LAN Warning "
		       "(\"%s\")", let != NULL ? let->title : "none");
		CHECK (refused != NULL && refused->severity == FS_COPILOT_INFO &&
		       strstr (refused->title, "lets") == NULL,
		       "brute: DEPENDS with every attempt refused stays Info");
		g_list_free (all);
	}
	fs_copilot_free (c);
	fs_policy_free (policy);
}

static void
intel_feed (FsCopilot *c, const gchar *dir, const gchar *src,
            const gchar *dst, const gchar *rule, gint64 unix_sec)
{
	FsHit hit;

	memset (&hit, 0, sizeof hit);
	hit.direction = (gchar *) dir;
	hit.source = (gchar *) src;
	hit.destination = (gchar *) dst;
	hit.port = (gchar *) "443";
	hit.protocol = (gchar *) "TCP";
	hit.service = (gchar *) "browser.exe [BLOCKED]";
	hit.rule = (gchar *) rule;
	fs_copilot_feed_event_full (c, &hit, (gint64) 960000 * G_USEC_PER_SEC,
	                            unix_sec);
}

static void test_threat_intel (void)
{
	FsCopilot *c = fs_copilot_new ();
	const FsInsight *ins;
	const gint64 h0 = 1700200800;   /* on the hour */

	intel_feed (c, "Out", "192.168.1.7", "203.0.113.200",
	            "Threat intel: Spamhaus DROP", h0);
	ins = find_insight (c, FS_INSIGHT_THREAT_INTEL);
	CHECK (ins != NULL && ins->severity == FS_COPILOT_WARNING &&
	       strstr (ins->title, "Spamhaus DROP") != NULL &&
	       strstr (ins->title, "browser.exe") != NULL,
	       "intel: outbound is a Warning naming the list and the app");
	CHECK (ins != NULL && ins->rule_csv == NULL && !ins->auto_applicable,
	       "intel: nothing to stage, the list already blocks it");
	CHECK (ins != NULL && ins->whatif_line == NULL,
	       "intel: no Ask What-If: What-If does not consult the lists "
	       "or the country and network rules (CORRECTNESS-2)");

	intel_feed (c, "In", "198.51.100.1", "192.168.1.7",
	            "Threat intel: FireHOL level 1", h0 + 10);
	intel_feed (c, "In", "198.51.100.2", "192.168.1.7",
	            "Threat intel: FireHOL level 1", h0 + 20);
	intel_feed (c, "In", "198.51.100.3", "192.168.1.7",
	            "Threat intel: FireHOL level 1", h0 + 30);
	CHECK (count_insights (c, FS_INSIGHT_THREAT_INTEL) == 2,
	       "intel: three inbound drops in an hour roll up into one finding");
	ins = find_insight (c, FS_INSIGHT_THREAT_INTEL);
	CHECK (ins != NULL && ins->count == 3 && ins->evidence->len == 3 &&
	       ins->severity == FS_COPILOT_INFO,
	       "intel: the roll-up is Info and counts all three");

	intel_feed (c, "In", "198.51.100.4", "192.168.1.7",
	            "Threat intel: FireHOL level 1", h0 + 3700);
	CHECK (count_insights (c, FS_INSIGHT_THREAT_INTEL) == 3,
	       "intel: the next hour starts a new roll-up");

	/* A country or network rule's block, as fs_intel_rule_text
	 * names it (the same marker and id space as a list). */
	intel_feed (c, "In", "198.51.100.5", "192.168.1.7",
	            "Threat intel: High risk countries", h0 + 3710);
	CHECK (count_insights (c, FS_INSIGHT_THREAT_INTEL) == 4,
	       "intel: a country block is its own roll-up");

	intel_feed (c, "In", "198.51.100.6", "192.168.1.7", NULL, h0 + 3720);
	CHECK (count_insights (c, FS_INSIGHT_THREAT_INTEL) == 4,
	       "intel: an event with no rule is no intel finding");
	fs_copilot_free (c);
}

static void test_insight_dedup (void)
{
	FsCopilot *c = fs_copilot_new ();
	FsHit hit;
	const FsInsight *b, *t;
	gint i;

	/* A beacon and a block-list hit on the same host within the hour:
	 * two different checks, so both become Critical and say why. */
	memset (&hit, 0, sizeof hit);
	hit.direction = "Out";
	hit.source = "192.168.1.7";
	hit.destination = "203.0.113.150";
	hit.port = "8443";
	hit.protocol = "TCP";
	hit.service = "agent.exe";
	for (i = 0; i < 6; i++)
		fs_copilot_feed_event_full (c, &hit,
			(gint64) (970000 + i * 60) * G_USEC_PER_SEC,
			1700300000 + i * 60);
	b = find_insight (c, FS_INSIGHT_BEACON);
	CHECK (b != NULL && b->severity == FS_COPILOT_WARNING,
	       "dedup: the beacon alone is a Warning");
	intel_feed (c, "Out", "192.168.1.7", "203.0.113.150",
	            "Threat intel: Spamhaus DROP", 1700300400);
	b = find_insight (c, FS_INSIGHT_BEACON);
	t = find_insight (c, FS_INSIGHT_THREAT_INTEL);
	CHECK (b != NULL && t != NULL && b->severity == FS_COPILOT_CRITICAL &&
	       t->severity == FS_COPILOT_CRITICAL &&
	       strstr (b->why, "Also flagged") != NULL,
	       "dedup: two different checks on one host within the hour are "
	       "Critical, and say so");
	fs_copilot_free (c);
}

/* ==== 1.0.7 Copilot review fixes ===================================
 * Each block pins one reviewed failure: the scenario that broke and
 * what it must give now. */

static void
out_feed (FsCopilot *c, const gchar *app, const gchar *dst,
          const gchar *port, const gchar *proto, const gchar *rule,
          gint64 sec)
{
	FsHit hit;

	memset (&hit, 0, sizeof hit);
	hit.direction = (gchar *) "Out";
	hit.source = (gchar *) "192.168.1.7";
	hit.destination = (gchar *) dst;
	hit.port = (gchar *) port;
	hit.protocol = (gchar *) proto;
	hit.service = (gchar *) app;
	hit.rule = (gchar *) rule;
	fs_copilot_feed_event_full (c, &hit,
	                            (gint64) (980000 + sec) * G_USEC_PER_SEC,
	                            1700400000 + sec);
}

static const FsInsight *
find_by_subject (FsCopilot *c, FsInsightType type, const gchar *subject)
{
	GList *all = fs_copilot_get_insights (c);
	const FsInsight *found = NULL;

	for (GList *l = all; l != NULL && found == NULL; l = l->next) {
		FsInsight *x = l->data;

		if (x->type == type && g_strcmp0 (x->subject, subject) == 0)
			found = x;
	}
	g_list_free (all);
	return found;
}

static gchar *
write_tmp (const gchar *dir, const gchar *name, const gchar *text)
{
	gchar *path = g_build_filename (dir, name, NULL);

	g_file_set_contents (path, text, -1, NULL);
	return path;
}

static void test_copilot_review_fixes (void)
{
	FsCopilot *c;
	const FsInsight *ins;
	gint i;

	/* F1: the machine's own DNS servers and gateway.
	 * A systemd-resolved system: resolv.conf names only the stub,
	 * the upstream list names 1.1.1.1, the default route goes via a
	 * public gateway 203.0.113.1. */
	{
		gchar *dir = g_dir_make_tmp ("fs-cp-net-XXXXXX", NULL);
		gchar *rc = write_tmp (dir, "resolv.conf",
		                       "nameserver 127.0.0.53\noptions edns0\n");
		gchar *rd = write_tmp (dir, "resolved.conf",
		                       "nameserver 1.1.1.1\n");
		gchar *rt = write_tmp (dir, "route",
			"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\t"
			"Mask\t\tMTU\tWindow\tIRTT\n"
			"eth0\t00000000\t017100CB\t0003\t0\t0\t0\t00000000\t0\t0\t0\n");
		gchar *old = g_strdup (g_getenv ("STOCKFW_RESOLV_CONF"));
		FsInsight probe;

		g_setenv ("STOCKFW_RESOLV_CONF", rc, TRUE);
		g_setenv ("STOCKFW_RESOLVED_CONF", rd, TRUE);
		g_setenv ("STOCKFW_ROUTE_FILE", rt, TRUE);
		c = fs_copilot_new ();
		for (i = 0; i < 8; i++)
			out_feed (c, "systemd-resolved", "1.1.1.1", "53", "UDP", NULL,
			          i * 30);
		for (i = 0; i < 8; i++)
			out_feed (c, "systemd-resolved", "1.1.1.1", "853", "TCP", NULL,
			          i * 60);
		CHECK (count_insights (c, FS_INSIGHT_BEACON) == 0,
		       "F1: DNS (53) and DNS over TLS (853) to the upstream behind "
		       "a 127.0.0.53 stub are never timed");

		for (i = 0; i < 8; i++)
			out_feed (c, "agent.exe", "1.1.1.1", "443", "TCP", NULL,
			          1000 + i * 60);
		ins = find_insight (c, FS_INSIGHT_BEACON);
		CHECK (ins != NULL && !ins->auto_applicable &&
		       ins->withheld != NULL &&
		       strstr (ins->withheld, "DNS servers or its default "
		                              "gateway") != NULL &&
		       !fs_insight_is_auto_safe (ins),
		       "F1: a resolver on any other port is reported, never "
		       "auto-blocked, and the choke point refuses it too");
		fs_copilot_clear_insights (c);

		for (i = 0; i < 8; i++)
			out_feed (c, "agent.exe", "203.0.113.1", "8443", "TCP", NULL,
			          2000 + i * 60);
		ins = find_insight (c, FS_INSIGHT_BEACON);
		CHECK (ins != NULL && !ins->auto_applicable &&
		       !fs_insight_is_auto_safe (ins),
		       "F1: the default gateway, though public, is never "
		       "auto-blocked");

		memset (&probe, 0, sizeof probe);
		probe.rule_kind = FS_RULE_OUTBOUND_DENY_TO;
		probe.rule_csv = (gchar *) "1.1.1.1, Sentinel: periodic beacon";
		CHECK (!fs_insight_is_auto_safe (&probe),
		       "F1: fs_insight_is_auto_safe refuses a deny to a resolver");
		fs_copilot_free (c);
		CHECK (fs_insight_is_auto_safe (&probe),
		       "F1: and forgets them with the copilot that read them");

		if (old != NULL)
			g_setenv ("STOCKFW_RESOLV_CONF", old, TRUE);
		else
			g_unsetenv ("STOCKFW_RESOLV_CONF");
		g_unsetenv ("STOCKFW_RESOLVED_CONF");
		g_unsetenv ("STOCKFW_ROUTE_FILE");
		g_remove (rc);
		g_remove (rd);
		g_remove (rt);
		g_rmdir (dir);
		g_free (rc);
		g_free (rd);
		g_free (rt);
		g_free (dir);
		g_free (old);
	}

	/* The stub alone, its upstream unreadable: DNS is still timed (a
	 * DNS tunnel is a real thing) but never blocked automatically. */
	c = fs_copilot_new ();
	fs_copilot_set_resolvers (c, "nameserver 127.0.0.53\n");
	for (i = 0; i < 8; i++)
		out_feed (c, "domain", "1.1.1.1", "53", "UDP", NULL, i * 30);
	ins = find_insight (c, FS_INSIGHT_BEACON);
	CHECK (ins != NULL && !ins->auto_applicable &&
	       strstr (ins->withheld, "upstream servers could not be read")
	       != NULL,
	       "F1: behind a stub with an unknown upstream, DNS is reported, "
	       "never auto-blocked");
	fs_copilot_free (c);

	/* A configured resolver on 853. */
	c = fs_copilot_new ();
	fs_copilot_set_resolvers (c, "nameserver 8.8.8.8\n");
	for (i = 0; i < 8; i++)
		out_feed (c, "domain-s", "8.8.8.8", "853", "TCP", NULL, i * 60);
	CHECK (count_insights (c, FS_INSIGHT_BEACON) == 0,
	       "F1: DNS over TLS to a configured resolver is never timed");
	fs_copilot_free (c);

	/* F2: a host another program uses all the time. */
	c = fs_copilot_new ();
	for (i = 0; i < 100; i++)
		out_feed (c, "browser.exe", "93.184.216.34", "443", "TCP", NULL,
		          i * 7);
	for (i = 0; i < 8; i++)
		out_feed (c, "updater.exe", "93.184.216.34", "443", "TCP", NULL,
		          5000 + i * 60);
	ins = find_insight (c, FS_INSIGHT_BEACON);
	CHECK (ins != NULL && !ins->auto_applicable && ins->withheld != NULL &&
	       strstr (ins->withheld, "browser.exe has 100 recorded") != NULL,
	       "F2: a destination another program has a history with is never "
	       "auto-blocked (the block would hit every program)");
	fs_copilot_free (c);
	c = fs_copilot_new ();
	for (i = 0; i < 8; i++)
		out_feed (c, "updater.exe", "93.184.216.34", "443", "TCP", NULL,
		          5000 + i * 60);
	ins = find_insight (c, FS_INSIGHT_BEACON);
	CHECK (ins != NULL && ins->auto_applicable,
	       "F2 control: the same run to a stranger is still auto-blocked");

	/* R1: the staging pass judges the gates again.  The finding was
	 * made auto-blockable; another program then makes 5 connections
	 * to the host.  The re-check withholds and says why. */
	CHECK (ins != NULL &&
	       fs_copilot_beacon_recheck (c, (FsInsight *) ins),
	       "R1 control: the re-check passes while nothing changed");
	for (i = 0; i < 5; i++)
		out_feed (c, "brave.exe", "93.184.216.34", "443", "TCP", NULL,
		          9000 + i * i * 7 + 1);
	ins = find_insight (c, FS_INSIGHT_BEACON);
	CHECK (ins != NULL &&
	       !fs_copilot_beacon_recheck (c, (FsInsight *) ins) &&
	       !ins->auto_applicable && ins->withheld != NULL &&
	       strstr (ins->withheld, "brave.exe has 5 recorded") != NULL,
	       "R1: another program's later use of the host withholds the "
	       "block at stage time, and the finding says so");
	fs_copilot_free (c);

	/* R2: the user's own outbound allow for the host (or a network
	 * around it) withholds the block, when the finding is made and
	 * when it is staged.  An "Anyone" allow does not count. */
	{
		FsPolicy *p = fs_policy_new ();
		FsRule *allow = fs_rule_from_csv (FS_RULE_OUTBOUND_ALLOW_TO,
		                                  "Anyone, open outbound");

		c = fs_copilot_new ();
		fs_policy_add (p, allow);
		fs_rule_free (allow);
		fs_copilot_set_policy (c, p);
		for (i = 0; i < 8; i++)
			out_feed (c, "updater.exe", "9.8.7.6", "443", "TCP", NULL,
			          5000 + i * 60);
		ins = find_insight (c, FS_INSIGHT_BEACON);
		CHECK (ins != NULL && ins->auto_applicable,
		       "R2 control: an allow-to-Anyone row does not withhold");
		allow = fs_rule_from_csv (FS_RULE_OUTBOUND_ALLOW_TO,
		                          "9.8.7.0/24, my allow");
		fs_policy_add (p, allow);
		fs_rule_free (allow);
		CHECK (ins != NULL &&
		       !fs_copilot_beacon_recheck (c, (FsInsight *) ins) &&
		       !ins->auto_applicable && ins->withheld != NULL &&
		       strstr (ins->withheld, "you allowed this destination") != NULL,
		       "R2: an allow row added later for a network around the "
		       "host withholds the block at stage time");
		fs_copilot_free (c);

		c = fs_copilot_new ();
		fs_copilot_set_policy (c, p);
		for (i = 0; i < 8; i++)
			out_feed (c, "updater.exe", "9.8.7.6", "443", "TCP", NULL,
			          5000 + i * 60);
		ins = find_insight (c, FS_INSIGHT_BEACON);
		CHECK (ins != NULL && !ins->auto_applicable &&
		       ins->withheld != NULL &&
		       strstr (ins->withheld, "you allowed this destination") != NULL,
		       "R2: a beacon to a host the policy allows is reported, "
		       "never made auto-blockable");
		fs_copilot_free (c);
		fs_policy_free (p);
	}

	/* R3: on Linux the profile key is the port's service name, and
	 * the withheld text must not call it a program. */
	{
		gchar *s443 = fs_service_lookup_port (443);
		gchar *s80  = fs_service_lookup_port (80);
		gchar *want;

		CHECK (s443 != NULL && s80 != NULL &&
		       g_strcmp0 (s443, s80) != 0,
		       "R3 setup: ports 443 and 80 have service names");
		c = fs_copilot_new ();
		for (i = 0; i < 5; i++)
			out_feed (c, s443, "4.3.2.1", "443", "TCP", NULL,
			          i * i * 7 + 1);
		for (i = 0; i < 8; i++)
			out_feed (c, s80, "4.3.2.1", "80", "TCP", NULL,
			          1000 + i * 60);
		ins = find_insight (c, FS_INSIGHT_BEACON);
		want = g_strdup_printf ("traffic on the %s port (any program) "
		                        "has 5 recorded", s443);
		CHECK (ins != NULL && !ins->auto_applicable &&
		       ins->withheld != NULL &&
		       strstr (ins->withheld, want) != NULL,
		       "R3: another service key is named as a port's traffic, "
		       "not as a program");
		g_free (want);
		fs_copilot_free (c);

		/* the key's own history, before the run, on another port */
		c = fs_copilot_new ();
		for (i = 0; i < 4; i++)
			out_feed (c, "Unknown", "4.3.2.2", "40001", "TCP", NULL,
			          i * i * 7 + 1);
		for (i = 0; i < 8; i++)
			out_feed (c, "Unknown", "4.3.2.2", "40000", "TCP", NULL,
			          1000 + i * 60);
		ins = find_insight (c, FS_INSIGHT_BEACON);
		CHECK (ins != NULL && !ins->auto_applicable &&
		       ins->withheld != NULL &&
		       strstr (ins->withheld, "traffic on this port already "
		                              "reached") != NULL &&
		       strstr (ins->withheld, "program") == NULL,
		       "R3: a service key's own history is not called a "
		       "program's");
		fs_copilot_free (c);
		g_free (s443);
		g_free (s80);
	}
	c = NULL;

	/* F3: a 300-port scan is one finding, and small findings never
	 * push it out of the list. */
	c = fs_copilot_new ();
	for (i = 0; i < 300; i++)
		inbound_feed (c, "45.33.32.156", 30000 + i, TRUE, i);
	CHECK (count_insights (c, FS_INSIGHT_INBOUND_SCAN) == 1 &&
	       count_insights (c, FS_INSIGHT_UNUSUAL_PORT) == 0 &&
	       total_insights (c) == 1,
	       "F3: 300 refused probes leave exactly one scan finding and no "
	       "\"used port N\" rows (got %u)", total_insights (c));
	{
		/* Probes the policy let through are the stranger's ports
		 * too. */
		FsCopilot *c2 = fs_copilot_new ();

		for (i = 0; i < 40; i++)
			inbound_feed (c2, "45.33.32.158", 40000 + i, FALSE, i);
		CHECK (count_insights (c2, FS_INSIGHT_UNUSUAL_PORT) == 0 &&
		       count_insights (c2, FS_INSIGHT_INBOUND_SCAN) == 1,
		       "F3: allowed inbound probes are no \"used port N\" rows "
		       "either");
		fs_copilot_free (c2);
	}
	for (i = 0; i < 10; i++)
		out_feed (c, "tool.exe", "203.0.113.80", "443", "TCP", NULL,
		          400 + i);
	for (i = 0; i < 260; i++) {
		gchar p[8];

		g_snprintf (p, sizeof p, "%d", 10000 + i);
		out_feed (c, "tool.exe", "203.0.113.80", p, "TCP", NULL, 420 + i);
	}
	CHECK (total_insights (c) == 200 &&
	       count_insights (c, FS_INSIGHT_INBOUND_SCAN) == 1,
	       "F3: 260 new-port findings fill the list, and the scan finding "
	       "is still on it");
	fs_copilot_free (c);

	/* F4: a full source table, then a real scan. */
	c = fs_copilot_new ();
	for (i = 0; i < 1024; i++) {
		gchar src[32];

		g_snprintf (src, sizeof src, "198.51.%d.%d", i / 250, i % 250 + 1);
		inbound_feed (c, src, 23, TRUE, i / 4);
	}
	for (i = 0; i < 40; i++)
		inbound_feed (c, "45.33.32.156", 2000 + i, TRUE, 260 + i);
	ins = find_by_subject (c, FS_INSIGHT_INBOUND_SCAN, "45.33.32.156");
	CHECK (ins != NULL,
	       "F4: with 1024 sources in the window, a new scanner is still "
	       "seen");
	{
		const FsAppProfile *p = fs_copilot_get_profile (c, "Unknown");

		CHECK (p != NULL && !p->baseline_partial &&
		       g_hash_table_size (p->common_destinations) == 0,
		       "F4: refused probes teach the profile no destinations, so "
		       "they cannot fill it and silence it");
	}
	/* ... and the login table. */
	for (i = 0; i < 1024; i++) {
		gchar src[32];

		g_snprintf (src, sizeof src, "198.18.%d.%d", i / 250, i % 250 + 1);
		inbound_feed (c, src, 22, TRUE, 300 + i / 8);
	}
	for (i = 0; i < 10; i++)
		inbound_feed (c, "45.33.32.157", 22, TRUE, 440 + i);
	CHECK (find_by_subject (c, FS_INSIGHT_BRUTE_FORCE, "45.33.32.157")
	       != NULL,
	       "F4: with the login table full, a new source is still counted");
	fs_copilot_free (c);

	/* A scanner rotating its address inside one IPv6 /64. */
	c = fs_copilot_new ();
	for (i = 0; i < 40; i++) {
		gchar src[64];

		g_snprintf (src, sizeof src, "2001:db8:1:2::%x", 0x100 + i);
		inbound_feed (c, src, 1000 + i, TRUE, i);
	}
	ins = find_insight (c, FS_INSIGHT_INBOUND_SCAN);
	CHECK (count_insights (c, FS_INSIGHT_INBOUND_SCAN) == 1 && ins != NULL &&
	       g_strcmp0 (ins->subject, "2001:db8:1:2::/64") == 0 &&
	       strstr (ins->title, "40 addresses") != NULL &&
	       strstr (ins->title, "probed 40 ports") != NULL,
	       "F4: 40 addresses of one /64 are one scanner (\"%s\")",
	       ins != NULL ? ins->title : "");
	CHECK (ins != NULL && ins->evidence->len == 12 &&
	       g_strcmp0 (((FsEvidence *) g_ptr_array_index (
	                   ins->evidence, 11))->remote,
	                  "2001:db8:1:2::127") == 0,
	       "F4: its evidence names each address the log showed");
	fs_copilot_free (c);

	/* F5: an admin's own deploy over an allowed SSH port. */
	{
		FsPolicy *policy = fs_policy_new ();
		FsRule *r = fs_rule_from_csv (FS_RULE_INBOUND_ALLOW_SERVICE,
		                              "SSH, 22, Anyone");

		fs_policy_add (policy, r);
		fs_rule_free (r);
		c = fs_copilot_new ();
		fs_copilot_set_policy (c, policy);
		for (i = 0; i < 12; i++)
			inbound_feed (c, "203.0.113.77", 22, FALSE, i * 10);
		ins = find_insight (c, FS_INSIGHT_BRUTE_FORCE);
		CHECK (ins != NULL && ins->severity == FS_COPILOT_WARNING &&
		       strstr (ins->title, "connections") != NULL &&
		       strstr (ins->title, "attempts") == NULL &&
		       strstr (ins->description, "cannot tell a failed login")
		       != NULL,
		       "F5: allowed connections only are a Warning about "
		       "\"connections\", not Critical \"attempts\"");
		/* F8: the open finding follows the run. */
		CHECK (ins != NULL && ins->count == 12 &&
		       strstr (ins->description, "made 12 connections") != NULL,
		       "F8: the 11th and 12th connection update the finding");
		fs_copilot_free (c);

		/* F6: SSH on a port the policy gives it. */
		r = fs_rule_from_csv (FS_RULE_INBOUND_ALLOW_SERVICE,
		                      "SSH, 2222, Anyone");
		fs_policy_add (policy, r);
		fs_rule_free (r);
		c = fs_copilot_new ();
		fs_copilot_set_policy (c, policy);
		for (i = 0; i < 30; i++)
			inbound_feed (c, "45.33.32.157", 2222, TRUE, i * 5);
		ins = find_insight (c, FS_INSIGHT_BRUTE_FORCE);
		CHECK (ins != NULL && strstr (ins->title, "SSH") != NULL,
		       "F6: SSH on 2222, as the policy names it, is a login port");
		fs_copilot_free (c);
		fs_policy_free (policy);
	}
	c = fs_copilot_new ();
	for (i = 0; i < 30; i++)
		inbound_feed (c, "45.33.32.157", 2222, TRUE, i * 5);
	CHECK (count_insights (c, FS_INSIGHT_BRUTE_FORCE) == 0,
	       "F6 control: without that policy row 2222 is no login port");
	fs_copilot_free (c);

	/* F6: split across services. */
	c = fs_copilot_new ();
	for (i = 0; i < 9; i++) {
		inbound_feed (c, "45.33.32.156", 22, TRUE, i * 10);
		inbound_feed (c, "45.33.32.156", 3389, TRUE, i * 10 + 1);
	}
	ins = find_insight (c, FS_INSIGHT_BRUTE_FORCE);
	CHECK (count_insights (c, FS_INSIGHT_BRUTE_FORCE) == 1 && ins != NULL &&
	       strstr (ins->title, "SSH and RDP") != NULL && ins->count == 18,
	       "F6: 9 on SSH and 9 on RDP from one host are 18 attempts");
	fs_copilot_free (c);

	/* F8: a 40-port scan reads 40, not the 12 it was first seen at. */
	c = fs_copilot_new ();
	for (i = 0; i < 40; i++)
		inbound_feed (c, "45.33.32.156", 2000 + i, TRUE, i);
	ins = find_insight (c, FS_INSIGHT_INBOUND_SCAN);
	CHECK (ins != NULL && strstr (ins->title, "probed 40 ports") != NULL &&
	       ins->count == 40 && ins->evidence->len == 12 &&
	       ((FsEvidence *) g_ptr_array_index (ins->evidence, 11))->port ==
	       2039,
	       "F8: the open scan finding follows the scan (\"%s\")",
	       ins != NULL ? ins->title : "");
	fs_copilot_free (c);

	/* F7: the browser memory survives a restart. */
	{
		gchar *dir = g_dir_make_tmp ("fs-cp-nd-XXXXXX", NULL);
		gchar *path = g_build_filename (dir, "behavior.csv", NULL);
		gchar *text = NULL;
		gint64 t1 = 8 * 86400;
		gchar d[32];

		c = fs_copilot_new ();
		for (i = 0; i < 60; i++)
			out_feed (c, "chrome.exe", "142.250.1.1", "443", "TCP", NULL, i);
		for (i = 0; i < 30; i++) {
			g_snprintf (d, sizeof d, "104.16.%d.1", i);
			out_feed (c, "chrome.exe", d, "443", "TCP", NULL,
			          t1 + i * 3600);
		}
		fs_copilot_clear_insights (c);
		CHECK (fs_copilot_baseline_save (c, path, NULL),
		       "F7: the baseline saves");
		fs_copilot_free (c);
		g_file_get_contents (path, &text, NULL, NULL);
		CHECK (text != NULL && strstr (text, "chrome.exe,newdest,") != NULL,
		       "F7: behavior.csv keeps the first contacts");
		g_free (text);

		c = fs_copilot_new ();
		fs_copilot_baseline_load (c, path, NULL);
		out_feed (c, "chrome.exe", "104.17.0.2", "443", "TCP", NULL,
		          t1 + 32 * 3600);
		CHECK (count_insights (c, FS_INSIGHT_UNUSUAL_DESTINATION) == 0,
		       "F7: after a restart the browser is still browser-like");
		fs_copilot_free (c);
		g_remove (path);
		g_rmdir (dir);
		g_free (path);
		g_free (dir);
	}

	/* F9: every evidence row is its own contact. */
	c = fs_copilot_new ();
	for (i = 0; i < 8; i++)
		out_feed (c, i < 7 ? "agent.exe" : "agent.exe [BLOCKED]",
		          "203.0.113.70", "8443", "TCP",
		          i < 7 ? NULL : "Threat intel: Spamhaus DROP", i * 60);
	ins = find_insight (c, FS_INSIGHT_BEACON);
	{
		gboolean rows_ok = ins != NULL && ins->evidence->len == 8;

		for (i = 0; rows_ok && i < 8; i++) {
			const FsEvidence *e = g_ptr_array_index (ins->evidence, i);

			rows_ok = (i < 7) ? (!e->blocked && e->rule == NULL)
			                  : (e->blocked &&
			                     g_strcmp0 (e->rule, "Threat intel: "
			                                "Spamhaus DROP") == 0);
		}
		CHECK (rows_ok,
		       "F9: seven allowed contacts stay allowed in the evidence; "
		       "only the eighth shows the block list");
	}
	fs_copilot_free (c);
	c = fs_copilot_new ();
	for (i = 0; i < 6; i++) {
		out_feed (c, "agent.exe", "203.0.113.71", "4500", "TCP", NULL,
		          i * 60);
		out_feed (c, "agent.exe", "203.0.113.71", "4500", "UDP", NULL,
		          i * 60 + 30);
	}
	CHECK (count_insights (c, FS_INSIGHT_BEACON) == 2,
	       "F9: TCP and UDP to one port are two series, not one at 30 s");
	ins = find_insight (c, FS_INSIGHT_BEACON);
	CHECK (ins != NULL &&
	       g_strcmp0 (((FsEvidence *) g_ptr_array_index (ins->evidence, 0))
	                  ->protocol,
	                  ((FsEvidence *) g_ptr_array_index (ins->evidence, 5))
	                  ->protocol) == 0,
	       "F9: a series' rows share one protocol");
	fs_copilot_free (c);

	/* F10: a port's service name is every program on that port. */
	c = fs_copilot_new ();
	for (i = 0; i < 70; i++) {
		gchar d[32];

		g_snprintf (d, sizeof d, "151.101.%d.%d", i / 50, i % 50 + 1);
		out_feed (c, "https", d, "443", "TCP", NULL, i / 2);
	}
	CHECK (count_insights (c, FS_INSIGHT_FANOUT) == 0,
	       "F10: one busy page on \"https\" (70 hosts, none refused) is "
	       "no fan-out");
	for (i = 0; i < 10; i++) {
		gchar d[32];

		g_snprintf (d, sizeof d, "198.51.100.%d", i + 1);
		out_feed (c, "https [BLOCKED]", d, "443", "TCP", NULL, 40 + i);
	}
	ins = find_insight (c, FS_INSIGHT_FANOUT);
	CHECK (ins != NULL && strstr (ins->why, "only refused hosts count")
	       != NULL,
	       "F10: ten refused hosts on \"https\" still are, and say why");
	fs_copilot_free (c);
}

static void test_behavior_persistence (void)
{
	gchar *dir = g_build_filename (g_get_tmp_dir (),
	                               "stockfw-behavior-test", NULL);
	gchar *file = g_build_filename (dir, "behavior.csv", NULL);
	gchar *file2 = g_build_filename (dir, "broken.csv", NULL);
	FsCopilot *a = fs_copilot_new ();
	FsCopilot *b = fs_copilot_new ();
	GError *err = NULL;
	FsHit hit;
	const FsAppProfile *pa, *pb;
	GList *all;
	gchar *path;
	guint hours_a;
	gint bidx;

	g_mkdir_with_parents (dir, 0700);
	remove (file);

	/* A file that is not there is a fresh start, not an error. */
	CHECK (!fs_copilot_baseline_load (a, file, &err) && err == NULL,
	       "a missing baseline is a quiet fresh start");

	/* The documented path honors the environment override. */
	g_setenv ("STOCKFW_BEHAVIOR_FILE", file, TRUE);
	path = fs_copilot_baseline_path ();
	CHECK (path != NULL && g_strcmp0 (path, file) == 0,
	       "STOCKFW_BEHAVIOR_FILE overrides the store path");
	g_free (path);
	g_unsetenv ("STOCKFW_BEHAVIOR_FILE");

	/* Ten windows of one connection each: totals, a destination, a
	 * port, hours, settled rate state. */
	behavior_hit (&hit, "sync.exe", "192.168.1.7", "198.51.100.10",
	              "443", "out");
	for (bidx = 0; bidx < 10; bidx++)
		behavior_feed (a, &hit, 1700000400 + (gint64) bidx * 600);

	/* And a comma-laden name, to pin the CSV quoting. */
	behavior_hit (&hit, "odd,name.exe", "192.168.1.7", "198.51.100.11",
	              "8080", "out");
	behavior_feed (a, &hit, 1700000400);

	pa = fs_copilot_get_profile (a, "sync.exe");
	hours_a = pa != NULL ? g_hash_table_size (pa->hourly_activity) : 0;

	CHECK (fs_copilot_baseline_save (a, file, &err),
	       "the baseline saves to disk");
	CHECK (err == NULL, "and saves without an error");
	CHECK (fs_copilot_baseline_save (a, file, NULL),
	       "a save with no error slot still works");

	/* The fresh copilot resumes the history. */
	CHECK (fs_copilot_baseline_load (b, file, &err),
	       "a fresh copilot loads the baseline back");
	CHECK (err == NULL, "and loads without an error");

	pb = fs_copilot_get_profile (b, "sync.exe");
	CHECK (pb != NULL, "the application comes back");
	CHECK (pb != NULL && pb->total_connections == 10,
	       "the connection total survives the restart");
	CHECK (pb != NULL &&
	       g_hash_table_contains (pb->common_destinations,
	                              "198.51.100.10"),
	       "the destination set survives");
	if (pb != NULL && pa != NULL) {
		guint *port_count = g_hash_table_lookup (pb->common_ports,
		                                         GUINT_TO_POINTER (443));

		CHECK (port_count != NULL && *port_count == 10,
		       "port counts survive");
		CHECK (g_hash_table_size (pb->hourly_activity) == hours_a,
		       "the hour buckets survive");
		CHECK (pb->rate_ema_milli == 1000 && pb->rate_buckets == 9,
		       "the established rate survives");
		CHECK (pb->first_seen == pa->first_seen &&
		       pb->last_seen == pa->last_seen,
		       "first and last seen survive");
	}
	CHECK (fs_copilot_get_profile (b, "odd,name.exe") != NULL,
	       "a comma in a name round-trips through the quoted CSV");

	/* The resumed history silences what it knows ... */
	behavior_hit (&hit, "sync.exe", "192.168.1.7", "198.51.100.10",
	              "443", "out");
	behavior_feed (b, &hit, 1700000400);
	CHECK (total_insights (b) == 0,
	       "a known port and host say nothing after the restart");

	/* ... and a genuinely new port still speaks up. */
	behavior_hit (&hit, "sync.exe", "192.168.1.7", "198.51.100.10",
	              "9999", "out");
	behavior_feed (b, &hit, 1700000400);
	CHECK (count_insights (b, FS_INSIGHT_UNUSUAL_PORT) == 1,
	       "a new port still fires against the loaded baseline");

	/* Garbage lines are skipped, not fatal. */
	{
		GError *err2 = NULL;
		FsCopilot *c;

		g_file_set_contents (file2,
		                     "# broken\nnot,a,valid,row\ngarbage\n",
		                     -1, NULL);
		c = fs_copilot_new ();
		CHECK (fs_copilot_baseline_load (c, file2, &err2),
		       "a file with garbage lines still loads");
		CHECK (err2 == NULL, "and the garbage sets no error");
		all = fs_copilot_get_all_profiles (c);
		CHECK (g_list_length (all) == 0,
		       "the garbage rows invent no profiles");
		g_list_free (all);
		g_clear_error (&err2);
		fs_copilot_free (c);
	}

	fs_copilot_free (a);
	fs_copilot_free (b);
	remove (file);
	remove (file2);
	g_free (file);
	g_free (file2);
	g_free (dir);
}

static void test_behavior_partial (void)
{
	FsCopilot *copilot = fs_copilot_new ();
	FsHit hit;
	const FsAppProfile *p;
	gchar dest[64];
	gint i;

	/* Port cap: a profile that exceeds it stops claiming novelty. */
	behavior_hit (&hit, "scanner.exe", "192.168.1.7", "203.0.113.5",
	              "443", "out");
	for (i = 0; i < 10; i++)
		behavior_feed (copilot, &hit, 1700000400);
	for (i = 1024; i < 1400; i++) {
		gchar port[16];

		g_snprintf (port, sizeof port, "%d", i);
		hit.port = port;
		behavior_feed (copilot, &hit, 1700000400);
	}
	p = fs_copilot_get_profile (copilot, "scanner.exe");
	CHECK (p != NULL && p->baseline_partial,
	       "hitting the port cap marks the baseline partial");

	fs_copilot_clear_insights (copilot);
	hit.port = "5000";
	behavior_feed (copilot, &hit, 1700000400);
	CHECK (count_insights (copilot, FS_INSIGHT_UNUSUAL_PORT) == 0,
	       "a partial baseline does not claim a new port is novel");

	/* The cap that filled here was the PORT set, so port 5000 above
	 * was never even recorded -- that check passes by construction.
	 * Destinations still have room, so this first contact WOULD be
	 * recordable and novel; only the partial guard keeps it quiet,
	 * and that guard is what this line pins. */
	hit.port = "443";
	hit.destination = "203.0.113.77";
	behavior_feed (copilot, &hit, 1700000400);
	CHECK (count_insights (copilot, FS_INSIGHT_UNUSUAL_DESTINATION) == 0 &&
	       count_insights (copilot, FS_INSIGHT_UNUSUAL_PORT) == 0,
	       "and a recordable first contact stays quiet too");

	/* Destination cap: same discipline, same flag. */
	behavior_hit (&hit, "flood.exe", "192.168.1.7", "198.51.100.40",
	              "443", "out");
	for (i = 0; i < 10; i++)
		behavior_feed (copilot, &hit, 1700000400);
	for (i = 1; i <= 1024; i++) {
		g_snprintf (dest, sizeof dest, "203.0.113.%d", i);
		hit.destination = dest;
		behavior_feed (copilot, &hit, 1700000400);
	}
	p = fs_copilot_get_profile (copilot, "flood.exe");
	CHECK (p != NULL && p->baseline_partial,
	       "hitting the destination cap marks the baseline partial");

	fs_copilot_clear_insights (copilot);
	hit.destination = "198.51.100.99";
	behavior_feed (copilot, &hit, 1700000400);
	CHECK (count_insights (copilot, FS_INSIGHT_UNUSUAL_DESTINATION) == 0,
	       "and it does not claim a new destination is novel either");

	/* Mirror image: the DESTINATION set filled here, so 198.51.100.99
	 * above was never recorded.  Ports still have room -- port 8443
	 * would be recorded and novel, so the partial guard is again
	 * the only thing keeping the finding quiet. */
	hit.port = "8443";
	behavior_feed (copilot, &hit, 1700000400);
	CHECK (count_insights (copilot, FS_INSIGHT_UNUSUAL_PORT) == 0 &&
	       count_insights (copilot, FS_INSIGHT_UNUSUAL_DESTINATION) == 0,
	       "and a recordable new port stays quiet too");

	fs_copilot_free (copilot);
}

static void test_behavior_app_cap (void)
{
	FsCopilot *copilot = fs_copilot_new ();
	FsHit hit;
	GList *all;
	gchar service[32];
	gint i;

	/* 260 one-event applications: the profile table stays bounded,
	 * the least recently seen makes room. */
	for (i = 0; i < 260; i++) {
		g_snprintf (service, sizeof service, "app%d.exe", i);
		behavior_hit (&hit, service, "192.168.1.7", "198.51.100.10",
		              "443", "out");
		behavior_feed (copilot, &hit, 1700000400);
	}

	all = fs_copilot_get_all_profiles (copilot);
	CHECK (g_list_length (all) == 256,
	       "the profile table stops at its cap");
	g_list_free (all);

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

/* The Overview hides loopback-to-loopback connections; this decides
 * which ones those are.  A wrong TRUE would hide a real connection. */
static void test_loopback_address (void)
{
	CHECK (fs_util_is_loopback_address ("127.0.0.1"), "127.0.0.1 is loopback");
	CHECK (fs_util_is_loopback_address ("127.8.9.10"), "all of 127/8 is loopback");
	CHECK (fs_util_is_loopback_address ("::1"), "::1 is loopback");
	CHECK (fs_util_is_loopback_address ("[::1]"), "[::1] (bracketed) is loopback");
	CHECK (fs_util_is_loopback_address ("::ffff:127.0.0.1"),
	       "IPv4-mapped 127.0.0.1 is loopback");
	CHECK (fs_util_is_loopback_address ("localhost"), "localhost is loopback");
	CHECK (!fs_util_is_loopback_address ("128.0.0.1"), "128.0.0.1 is not");
	CHECK (!fs_util_is_loopback_address ("::ffff:10.0.0.1"),
	       "IPv4-mapped 10.0.0.1 is not");
	CHECK (!fs_util_is_loopback_address ("::2"), "::2 is not");
	CHECK (!fs_util_is_loopback_address ("0.0.0.0"), "0.0.0.0 is not");
	CHECK (!fs_util_is_loopback_address ("localhost.example"),
	       "a name that starts with localhost is not");
	CHECK (!fs_util_is_loopback_address ("[::1"), "an unclosed bracket is not");
	CHECK (!fs_util_is_loopback_address (""), "empty is not");
	CHECK (!fs_util_is_loopback_address (NULL), "NULL is not");
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

	/* P6: the destination gate holds at the choke point too, so a
	 * deny gets the csv it will actually carry (host + comment). */
	insight->rule_kind = FS_RULE_OUTBOUND_DENY_TO;
	g_free (insight->rule_csv);
	insight->rule_csv = g_strdup (
		"198.51.100.9, Auto-generated by Copilot");
	CHECK (fs_insight_is_auto_safe (insight),
	       "an outbound deny is auto-safe");

	/* An unclassifiable destination (here a leftover app name) is
	 * never auto-blocked, whatever the kind says: not an address
	 * means not classifiable means withheld. */
	g_free (insight->rule_csv);
	insight->rule_csv = g_strdup (
		"evil.exe, Auto-generated by Copilot");
	CHECK (!fs_insight_is_auto_safe (insight),
	       "an unclassifiable destination is never auto-safe");

	g_free (insight->rule_csv);
	insight->rule_csv = g_strdup (
		"evil.exe, 80, 198.51.100.9, Auto-generated by Copilot");
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

/* The What-If simulator through the copilot's wrappers: what the older
 * callers (the Copilot page's log, the CLI) read from the engine in
 * core/fs-whatif.c.  The engine's own golden table is
 * tests/test-whatif.c, run after this program; what is pinned here is
 * that the wrappers carry the engine's reading and verdicts through
 * unchanged on whichever platform this runs, and refuse rather than
 * guess. */

/* [ whatif_ask ] -- one line against a policy, on a named platform,
 * with the firewall running and the policy in force. */
static FsWhatIfResult *
whatif_ask (FsWhatIfPlatform platform, const FsPolicy *policy,
            const gchar *line)
{
	FsSettings *settings = fs_settings_new ();
	FsWhatIfContext *ctx = fs_whatif_context_new (platform, policy, settings);
	FsWhatIfResult *r;

	ctx->firewall = FS_WHATIF_FW_RUNNING;
	ctx->live = FS_WHATIF_LIVE_YES;
	r = fs_whatif_simulate_text (ctx, line);
	fs_whatif_context_free (ctx);
	fs_settings_free (settings);
	return r;
}

static const FsWhatIfAnswer *
whatif_answer (const FsWhatIfResult *r)
{
	return (r != NULL && r->answers->len > 0)
	       ? g_ptr_array_index (r->answers, 0) : NULL;
}

static void test_whatif_simulate (void)
{
	FsSimulationResult *r;
	FsWhatIfQuery *q = NULL;
	FsCopilot *copilot;
	FsPolicy *policy;
	FsRule *rule;

	/* The reading comes back with the answer. */
	copilot = fs_copilot_new ();
	r = fs_copilot_simulate_text (copilot,
	                              "allow SSH from 192.168.1.50 on port 22", &q);
	CHECK (r != NULL && q != NULL, "a full line is read and answered");
	if (q != NULL) {
		CHECK (q->direction == FS_WHATIF_DIR_INBOUND,
		       "'from' reads as inbound");
		CHECK (q->port == 22 && q->protocol == FS_WHATIF_PROTO_TCP,
		       "port 22, TCP");
		CHECK (g_strcmp0 (q->host, "192.168.1.50") == 0, "the host is read");
		CHECK (q->verb == FS_WHATIF_VERB_ALLOW, "the verb is read");
		CHECK (q->confidence >= 0.8 && q->pieces->len >= 3,
		       "and the reading says what it recognised (%.0f%%)",
		       q->confidence * 100);
		fs_whatif_query_free (q);
		q = NULL;
	}
	if (r != NULL) {
		CHECK (r->verdict == FS_WHATIF_BLOCKED && r->would_block,
		       "no rule: the default blocks it");
		CHECK (r->whatif != NULL && r->whatif->answers->len == 1,
		       "the whole answer rides along");
		CHECK (strstr (r->explanation, "Simulation:") != NULL &&
		       r->reason != NULL && *r->reason != '\0' &&
		       strstr (r->reason, "Simulation:") == NULL,
		       "the log sentence keeps its wrapper; the reason does not");
		fs_simulation_result_free (r);
	}

	/* A line with no direction is asked both ways. */
	r = fs_copilot_simulate_text (copilot, "ssh is open at 22 port", &q);
	CHECK (r != NULL && q != NULL && q->direction == FS_WHATIF_DIR_BOTH &&
	       q->port == 22 && r->whatif->answers->len == 2,
	       "a line that names no direction is answered both ways");
	fs_whatif_query_free (q);
	q = NULL;
	fs_simulation_result_free (r);

	/* Refusals, never guesses. */
	CHECK (fs_copilot_simulate_text (copilot, "", NULL) == NULL &&
	       fs_copilot_simulate_text (copilot, "   ", NULL) == NULL &&
	       fs_copilot_simulate_text (copilot, NULL, NULL) == NULL,
	       "an empty line is no question");
	{
		static const gchar *bad[] = {
			"hello there", "allow port 0 from 10.0.0.1",
			"inbound tcp port 65536", "outbound to 203.0.113.9:70000",
			"inbound from 999.1.1.1 port 22",
		};

		for (guint i = 0; i < G_N_ELEMENTS (bad); i++) {
			r = fs_copilot_simulate_text (copilot, bad[i], &q);
			CHECK (r != NULL && r->verdict == FS_WHATIF_ERROR &&
			       !r->would_block && q == NULL &&
			       r->reason != NULL && *r->reason != '\0',
			       "\"%s\" is refused with a reason (%s)", bad[i],
			       r != NULL && r->reason ? r->reason : "-");
			fs_simulation_result_free (r);
		}
	}
	r = fs_copilot_simulate (copilot, NULL, "example.com", 22, "TCP", TRUE);
	CHECK (r != NULL && r->verdict == FS_WHATIF_ERROR,
	       "the field-by-field call refuses a host that is not an address");
	fs_simulation_result_free (r);
	fs_copilot_free (copilot);

	/* --- Verdicts against a real policy, on this platform --- */
	policy = fs_policy_new ();
	copilot = fs_copilot_new ();
	fs_copilot_set_policy (copilot, policy);

	/* The same host allowed and blocked: blocked on both platforms
	 * (Windows: the block wins; Linux: deny rows come first). */
	rule = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_TO);
	rule->target = g_strdup ("203.0.113.5");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);
	rule = fs_rule_new (FS_RULE_OUTBOUND_DENY_TO);
	rule->target = g_strdup ("203.0.113.5");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	r = fs_copilot_simulate_text (copilot, "outbound tcp to 203.0.113.5 port 22",
	                              NULL);
	CHECK (r != NULL && r->would_block && r->matching_rule != NULL &&
	       strstr (r->matching_rule, "Block outbound") != NULL,
	       "a block rule beats an allow rule on the same host, and is named "
	       "(%s)", r != NULL && r->matching_rule ? r->matching_rule : "-");
	fs_simulation_result_free (r);

	/* A block written as a subnet covers a host inside it. */
	fs_policy_clear (policy);
	rule = fs_rule_new (FS_RULE_OUTBOUND_DENY_TO);
	rule->target = g_strdup ("203.0.113.0/24");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);
	r = fs_copilot_simulate (copilot, NULL, "203.0.113.77", 80, "TCP", FALSE);
	CHECK (r != NULL && r->would_block, "a /24 block covers a host inside it");
	fs_simulation_result_free (r);
	r = fs_copilot_simulate (copilot, NULL, "203.0.112.0/23", 80, "TCP", FALSE);
	CHECK (r != NULL && r->verdict == FS_WHATIF_DEPENDS &&
	       strstr (r->reason, "203.0.113.0/24") != NULL,
	       "a wider block of hosts is only partly blocked, and says where "
	       "(%s)", r != NULL ? r->reason : "-");
	fs_simulation_result_free (r);

	/* b1, inverted: a line with no port used to be answered "allowed"
	 * because one rule opened one port.  It is DEPENDS now, with the
	 * port that is open and the rest that is not. */
	fs_policy_clear (policy);
	rule = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);
	rule->service = g_strdup ("mystery");
	rule->port = g_strdup ("22");
	rule->target = g_strdup ("192.168.1.50");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	r = fs_copilot_simulate_text (copilot, "inbound from 192.168.1.50", NULL);
	CHECK (r != NULL && r->verdict == FS_WHATIF_DEPENDS && !r->would_block,
	       "b1: a portless line meets a one-port rule: DEPENDS, not ALLOWED "
	       "(%s)", r != NULL ? r->reason : "-");
	if (r != NULL && r->verdict == FS_WHATIF_DEPENDS) {
		const FsWhatIfAnswer *a = whatif_answer (r->whatif);
		gboolean open22 = FALSE, closed = FALSE;

		for (guint i = 0; a != NULL && i < a->cases->len; i++) {
			const FsWhatIfCase *c = g_ptr_array_index (a->cases, i);

			if (c->verdict == FS_WHATIF_ALLOWED &&
			    strstr (c->condition, "port 22") != NULL &&
			    c->rule != NULL && strstr (c->rule, "mystery") != NULL)
				open22 = TRUE;
			if (c->verdict == FS_WHATIF_BLOCKED)
				closed = TRUE;
		}
		CHECK (open22 && closed,
		       "b1: the split names port 22 and its rule, and the blocked "
		       "rest");
	}
	fs_simulation_result_free (r);

	r = fs_copilot_simulate_text (copilot,
	                              "inbound tcp port 80 from 192.168.1.50", NULL);
	CHECK (r != NULL && r->would_block,
	       "a port the rule does not open stays blocked");
	fs_simulation_result_free (r);
	r = fs_copilot_simulate_text (copilot, "inbound ping from 192.168.1.50",
	                              NULL);
	CHECK (r != NULL && (r->whatif->answers->len == 1) &&
	       (r->matching_rule == NULL ||
	        strstr (r->matching_rule, "mystery") == NULL),
	       "ICMP never meets a ported rule (%s)",
	       r != NULL && r->matching_rule ? r->matching_rule : "-");
	fs_simulation_result_free (r);

	fs_copilot_free (copilot);
	fs_policy_free (policy);

	/* No policy attached: an empty policy, said plainly. */
	{
		FsCopilot *bare = fs_copilot_new ();

		r = fs_copilot_simulate_text (bare,
		                              "inbound ssh from 10.0.0.2", NULL);
		CHECK (r != NULL && r->would_block,
		       "inbound with no rules falls to the deny default");
		fs_simulation_result_free (r);
		fs_copilot_free (bare);
	}
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
	gchar *pair_file = g_build_filename (dir, "pair.csv", NULL);
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
	remove (pair_file);
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
	fs_trust_store_free (store);

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

	/* Two rows must survive a save/reload together.  The writer used
	 * to prefix every row after the first with a comma, giving them
	 * nine fields against the parser's exact eight -- so the second
	 * attestation vanished on the next load. */
	{
		FsTrustStore *pair = fs_trust_store_new (pair_file);
		FsTrustReport ra, rb;

		memset (&ra, 0, sizeof ra);
		ra.path = (gchar *) "C:/Apps/one.exe";
		ra.sha256 = (gchar *)
			"aa11bb22cc33dd44ee55ff6677889900"
			"112233445566778899aabbccddee00ff";
		ra.size = 1;
		ra.mtime = 2;
		ra.sig = FS_TRUST_SIG_INVALID;

		memset (&rb, 0, sizeof rb);
		rb.path = (gchar *) "C:/Apps/two.exe";
		rb.sha256 = (gchar *)
			"112233445566778899aabbccddee00ff"
			"aa11bb22cc33dd44ee55ff6677889900";
		rb.size = 3;
		rb.mtime = 4;
		rb.sig = FS_TRUST_SIG_INVALID;

		CHECK (fs_trust_attest (pair, &ra) && fs_trust_attest (pair, &rb),
		       "two programs attest");
		CHECK (fs_trust_store_count (pair) == 2,
		       "both rows are in the store");
		CHECK (fs_trust_store_save (pair, &error) && error == NULL,
		       "the pair saves");
		fs_trust_store_free (pair);
		g_clear_error (&error);

		pair = fs_trust_store_load (pair_file);
		CHECK (fs_trust_store_count (pair) == 2,
		       "both rows reload, not just the first");
		fs_trust_store_free (pair);
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
	remove (pair_file);
	remove (audit_file);
	g_free (payload);
	g_free (missing);
	g_free (fakeexe);
	g_free (store_file);
	g_free (weird_file);
	g_free (pair_file);
	g_free (audit_file);
	g_free (dir);
}

/* =====================================================================
 * P3: safe policy enforcement -- the apply gate.
 *
 * A scripted fake backend drives every branch: hold, first apply,
 * narrow delta, the no-change fast path, failure with a verified
 * rollback, failure with a failed rollback, failure with nothing to
 * restore, a missing backend, and a backend with no delta slot.  The
 * backend is a parameter of the gate precisely so none of this needs
 * a firewall.
 * ===================================================================== */

/* --- small helpers -------------------------------------------------- */

/* fs_policy_add stores a copy: add `rule' and free it. */
static void
policy_add_take (FsPolicy *policy, FsRule *rule)
{
	fs_policy_add (policy, rule);
	fs_rule_free (rule);
}

static FsRule *
gate_rule (FsRuleKind kind, const gchar *service, const gchar *port,
           const gchar *target)
{
	FsRule *rule = fs_rule_new (kind);

	rule->service = g_strdup (service);
	rule->port = g_strdup (port);
	rule->target = g_strdup (target);

	return rule;
}

/* One allow-service (DNS) plus one deny-host: an allow and a block,
 * so the impact's allow/block split has something to count. */
static FsPolicy *
gate_policy_two (void)
{
	FsPolicy *policy = fs_policy_new ();
	FsRule *rule;

	rule = gate_rule (FS_RULE_OUTBOUND_ALLOW_SERVICE, "DNS", "53",
	                  FS_TARGET_ANY);
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	rule = gate_rule (FS_RULE_OUTBOUND_DENY_TO, NULL, NULL,
	                  "198.51.100.9");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	return policy;
}

static FsPolicy *
gate_policy_copy (const FsPolicy *src)
{
	FsPolicy *dst = fs_policy_new ();

	for (gint kind = 0; kind < FS_RULE_N_KINDS; kind++) {
		for (guint i = 0; i < src->kinds[kind]->len; i++)
			fs_policy_add (dst,
			               g_ptr_array_index (src->kinds[kind], i));
	}

	return dst;
}

static guint
gate_policy_total (const FsPolicy *policy)
{
	guint total = 0;

	for (gint kind = 0; kind < FS_RULE_N_KINDS; kind++)
		total += policy->kinds[kind]->len;

	return total;
}

static gchar *
gate_audit_read (void)
{
	gchar *contents = NULL;
	const gchar *path = g_getenv ("STOCKFW_AUDIT_FILE");

	if (path != NULL)
		g_file_get_contents (path, &contents, NULL, NULL);

	return contents;
}

/* --- the scripted fake backend -------------------------------------- */

#define FAKE_MAX_QUEUE 8

static FsApplyResult fake_queue[FAKE_MAX_QUEUE];
static gint fake_queue_len, fake_queue_pos;
static gint fake_full_calls, fake_delta_calls;
static gboolean fake_available_flag = TRUE;
static FsPolicy *fake_seen[FAKE_MAX_QUEUE];
static gint fake_seen_len;
static gint fake_last_remove_n, fake_last_add_n, fake_last_repair_n;

static void
fake_reset (void)
{
	for (gint i = 0; i < fake_seen_len; i++)
		fs_policy_free (fake_seen[i]);

	fake_seen_len = 0;
	fake_queue_len = fake_queue_pos = 0;
	fake_full_calls = fake_delta_calls = 0;
	fake_last_remove_n = fake_last_add_n = fake_last_repair_n = 0;
	fake_available_flag = TRUE;
}

static void
fake_enqueue (FsApplyResult result)
{
	fake_queue[fake_queue_len++] = result;
}

static FsApplyResult
fake_next (GError **error)
{
	FsApplyResult result = FS_APPLY_OK;

	if (fake_queue_pos < fake_queue_len)
		result = fake_queue[fake_queue_pos++];

	if (result != FS_APPLY_OK)
		g_set_error_literal (error,
		                     g_quark_from_static_string ("fake-backend"),
		                     (int) result,
		                     "scripted backend failure");

	return result;
}

static gboolean
fake_available (void)
{
	return fake_available_flag;
}

static FsApplyResult
fake_apply_rules (const FsPolicy *policy, GError **error)
{
	fake_full_calls++;

	if (fake_seen_len < FAKE_MAX_QUEUE)
		fake_seen[fake_seen_len++] = gate_policy_copy (policy);

	return fake_next (error);
}

/* Lengths only: the delta's lists belong to the gate and are freed
 * when it returns, so recording the pointers would dangle. */
static FsApplyResult
fake_apply_delta (const GList *remove, const GList *add,
                  const GList *repair, GError **error)
{
	fake_delta_calls++;
	fake_last_remove_n = g_list_length ((GList *) remove);
	fake_last_add_n = g_list_length ((GList *) add);
	fake_last_repair_n = g_list_length ((GList *) repair);

	return fake_next (error);
}

static const FsBackend fake_backend = {
	.name = "fake",
	.display_name = "scripted fake backend",
	.available = fake_available,
	.apply_rules = fake_apply_rules,
	.apply_delta = fake_apply_delta,
};

/* A backend that applies and leaves notes (Linux without ip6tables, a
 * skipped allow): the notes ride on a success. */
static gchar *
fake_notes (void)
{
	return g_strdup ("IPv6 is not filtered: ip6tables is not installed.\n"
	                 "2026-11-02 | forged audit entry");
}

static const FsBackend fake_backend_notes = {
	.name = "fake-notes",
	.display_name = "scripted fake backend with apply notes",
	.available = fake_available,
	.apply_rules = fake_apply_rules,
	.apply_notes = fake_notes,
};

/* The same fake without the narrow slot: whole-set apply only. */
static const FsBackend fake_backend_no_delta = {
	.name = "fake-full",
	.display_name = "scripted fake backend, no delta",
	.available = fake_available,
	.apply_rules = fake_apply_rules,
};

/* --- fs_fwrule_equal: full-field identity, not name identity -------- */

static void test_fwrule_equal (void)
{
	FsPolicy *a = fs_policy_new ();
	FsPolicy *b = fs_policy_new ();
	FsPolicy *c = fs_policy_new ();
	FsRule *r;
	GList *la, *lb, *lc;
	FsFwRule *a0, *b0, *c0;
	gchar *saved;

	r = gate_rule (FS_RULE_OUTBOUND_ALLOW_SERVICE, "SSH", "22",
	               FS_TARGET_ANY);
	fs_policy_add (a, r);
	fs_rule_free (r);
	r = gate_rule (FS_RULE_OUTBOUND_ALLOW_SERVICE, "SSH", "2222",
	               FS_TARGET_ANY);
	fs_policy_add (b, r);
	fs_rule_free (r);
	r = gate_rule (FS_RULE_OUTBOUND_ALLOW_SERVICE, "SSH", "22",
	               FS_TARGET_ANY);
	fs_policy_add (c, r);
	fs_rule_free (r);

	la = fs_fwrule_from_policy (a);
	lb = fs_fwrule_from_policy (b);
	lc = fs_fwrule_from_policy (c);
	a0 = la->data;
	b0 = lb->data;
	c0 = lc->data;

	CHECK (fs_fwrule_equal (a0, a0), "a rule equals itself");
	CHECK (fs_fwrule_equal (NULL, NULL), "two NULLs are equal");
	CHECK (!fs_fwrule_equal (a0, NULL), "a rule and NULL differ");
	CHECK (g_strcmp0 (a0->name, b0->name) == 0,
	       "SSH on 22 and SSH on 2222 share one default name");
	CHECK (!fs_fwrule_equal (a0, b0),
	       "...but they are not equal: the port differs");
	CHECK (fs_fwrule_equal (a0, c0),
	       "the same row expands to equal concrete rules");

	/* Every field, one at a time: change it, expect inequality,
	 * restore it. */
	/* Outbound SSH carries its port on the remote side; the local
	 * side is NULL (any). */
	saved = c0->remote_ports;
	c0->remote_ports = g_strdup ("65535");
	CHECK (!fs_fwrule_equal (a0, c0), "a different remote port is not equal");
	g_free (c0->remote_ports);
	c0->remote_ports = saved;

	c0->local_ports = g_strdup ("8080");
	CHECK (!fs_fwrule_equal (a0, c0), "a different local port is not equal");
	g_free (c0->local_ports);
	c0->local_ports = NULL;

	saved = c0->name;
	c0->name = g_strdup ("StockFW: something else");
	CHECK (!fs_fwrule_equal (a0, c0), "a different name is not equal");
	g_free (c0->name);
	c0->name = saved;

	/* "Anyone" resolves to no address, so the originals are NULL:
	 * restore NULL rather than aliasing a0's pointers into c0. */
	c0->remote_address = g_strdup ("10.0.0.1");
	CHECK (!fs_fwrule_equal (a0, c0), "a different remote address is not equal");
	g_free (c0->remote_address);
	c0->remote_address = NULL;

	c0->local_address = g_strdup ("10.0.0.2");
	CHECK (!fs_fwrule_equal (a0, c0), "a different local address is not equal");
	g_free (c0->local_address);
	c0->local_address = NULL;

	c0->forward_address = g_strdup ("10.0.0.3");
	CHECK (!fs_fwrule_equal (a0, c0), "a different forward address is not equal");
	g_free (c0->forward_address);
	c0->forward_address = NULL;

	c0->forward = !a0->forward;
	CHECK (!fs_fwrule_equal (a0, c0), "a different forward flag is not equal");
	c0->forward = a0->forward;

	c0->direction = a0->direction == FS_DIR_INBOUND ? FS_DIR_OUTBOUND
	                                                : FS_DIR_INBOUND;
	CHECK (!fs_fwrule_equal (a0, c0), "a different direction is not equal");
	c0->direction = a0->direction;

	c0->action = a0->action == FS_ACTION_ALLOW ? FS_ACTION_BLOCK
	                                           : FS_ACTION_ALLOW;
	CHECK (!fs_fwrule_equal (a0, c0), "a different action is not equal");
	c0->action = a0->action;

	c0->protocol = a0->protocol == FS_PROTO_ANY ? FS_PROTO_TCP
	                                            : FS_PROTO_ANY;
	CHECK (!fs_fwrule_equal (a0, c0), "a different protocol is not equal");
	c0->protocol = a0->protocol;

	CHECK (fs_fwrule_equal (a0, c0),
	       "every field restored: equality comes back");

	fs_fwrule_list_free (la);
	fs_fwrule_list_free (lb);
	fs_fwrule_list_free (lc);
	fs_policy_free (a);
	fs_policy_free (b);
	fs_policy_free (c);
}

/* --- the journal ----------------------------------------------------- */

static void test_apply_journal (void)
{
	gchar *dir = g_build_filename (g_get_tmp_dir (),
	                               "stockfw-apply-test", NULL);
	gchar *file = g_build_filename (dir, "applied.csv", NULL);
	FsPolicy *policy = fs_policy_new ();
	FsPolicy *loaded = fs_policy_new ();
	GError *error = NULL;
	FsRule *rule;
	gchar *tampered;

	g_mkdir_with_parents (dir, 0700);
	remove (file);
	g_setenv ("STOCKFW_APPLIED_FILE", file, TRUE);

	CHECK (!fs_apply_journal_load (loaded, &error) && error != NULL &&
	       g_error_matches (error, FS_APPLY_ERROR,
	                        FS_APPLY_ERR_NO_JOURNAL),
	       "a missing journal reports NO_JOURNAL");
	g_clear_error (&error);

	/* Two rows, one carrying a comment: it has to survive the shared
	 * CSV dialect unquoted and read back identically. */
	rule = gate_rule (FS_RULE_OUTBOUND_ALLOW_SERVICE, "DNS", "53",
	                  FS_TARGET_ANY);
	rule->comment = g_strdup ("primary resolver");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	rule = gate_rule (FS_RULE_INBOUND_ALLOW_FROM, NULL, NULL, "10.0.0.7");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	CHECK (fs_apply_journal_save (policy, &error),
	       "saving the journal succeeds");
	g_clear_error (&error);

	CHECK (fs_apply_journal_load (loaded, &error),
	       "the journal loads back");
	g_clear_error (&error);

	CHECK (gate_policy_total (loaded) == 2,
	       "both rows survive the round trip");
	{
		/* Row identity is the CSV form, comment included -- the
		 * needle has to carry the same comment to match. */
		FsRule *needle = gate_rule (FS_RULE_OUTBOUND_ALLOW_SERVICE,
		                            "DNS", "53", FS_TARGET_ANY);

		needle->comment = g_strdup ("primary resolver");
		CHECK (fs_policy_contains (loaded, needle),
		       "the service row is found by content");
		fs_rule_free (needle);
	}
	CHECK (loaded->kinds[FS_RULE_OUTBOUND_ALLOW_SERVICE]->len == 1 &&
	       g_strcmp0 (((FsRule *) loaded->kinds[
	                    FS_RULE_OUTBOUND_ALLOW_SERVICE]->pdata[0])->comment,
	                  "primary resolver") == 0,
	       "the comment survives the round trip");

	/* The dialect cannot represent a comma inside a comment: the row
	 * would not parse back.  The journal refuses such a journal
	 * outright instead of loading half of it -- the same strictness
	 * as any other malformed row. */
	{
		FsPolicy *comma = fs_policy_new ();
		FsRule *crow = gate_rule (FS_RULE_OUTBOUND_ALLOW_SERVICE,
		                          "DNS", "53", FS_TARGET_ANY);

		crow->comment = g_strdup ("resolver, primary");
		fs_policy_add (comma, crow);
		fs_rule_free (crow);
		CHECK (fs_apply_journal_save (comma, NULL),
		       "the comma-carrying journal writes");
		CHECK (!fs_apply_journal_load (loaded, &error) && error != NULL &&
		       g_error_matches (error, FS_APPLY_ERROR,
		                        FS_APPLY_ERR_MALFORMED),
		       "but the dialect refuses to read it back -- no half-load");
		g_clear_error (&error);
		fs_policy_free (comma);
	}

	/* F-1 applies to the rollback target too: a tampered journal is
	 * refused, never half-loaded. */
	tampered = g_strdup_printf (
		"# StockFW applied policy journal v1\n"
		"%d,10.0.0.7\n"
		"%d,999.1.1.1\n",
		(int) FS_RULE_INBOUND_ALLOW_FROM,
		(int) FS_RULE_OUTBOUND_DENY_TO);
	g_file_set_contents (file, tampered, -1, NULL);
	g_free (tampered);

	CHECK (!fs_apply_journal_load (loaded, &error) && error != NULL &&
	       g_error_matches (error, FS_APPLY_ERROR,
	                        FS_APPLY_ERR_MALFORMED),
	       "an invalid host in the journal is malformed");
	g_clear_error (&error);
	CHECK (gate_policy_total (loaded) == 0,
	       "a refused journal leaves nothing half-loaded");

	/* An out-of-range kind is malformed too. */
	g_file_set_contents (file, "99,whatever\n", -1, NULL);
	CHECK (!fs_apply_journal_load (loaded, &error) && error != NULL &&
	       g_error_matches (error, FS_APPLY_ERROR,
	                        FS_APPLY_ERR_MALFORMED),
	       "an unknown kind in the journal is malformed");
	g_clear_error (&error);
	CHECK (gate_policy_total (loaded) == 0,
	       "and it too leaves nothing behind");

	/* A save failure is normalised onto the FS_APPLY_ERROR quark so
	 * callers match one domain.  Pointing the journal at a directory
	 * makes the write fail after the parent dir check passed. */
	g_setenv ("STOCKFW_APPLIED_FILE", dir, TRUE);
	error = NULL;
	CHECK (!fs_apply_journal_save (policy, &error) && error != NULL &&
	       g_error_matches (error, FS_APPLY_ERROR,
	                        FS_APPLY_ERR_UNREADABLE),
	       "a failed save is normalised onto the apply error domain");
	g_clear_error (&error);
	g_setenv ("STOCKFW_APPLIED_FILE", file, TRUE);

	g_unsetenv ("STOCKFW_APPLIED_FILE");
	remove (file);
	fs_policy_free (policy);
	fs_policy_free (loaded);
	g_free (file);
	g_free (dir);
}

/* --- impact measurement --------------------------------------------- */

static void test_apply_impact (void)
{
	gchar *dir = g_build_filename (g_get_tmp_dir(),
	                               "stockfw-impact-test", NULL);
	gchar *file = g_build_filename (dir, "applied.csv", NULL);
	FsPolicy *before = gate_policy_two ();
	FsPolicy *after = gate_policy_two ();
	FsPolicyImpact *impact;
	gchar *desc;
	FsRule *needle;

	g_mkdir_with_parents (dir, 0700);
	remove (file);

	impact = fs_policy_impact (before, after);
	CHECK (impact->added == 0 && impact->removed == 0 &&
	       impact->unchanged == 2,
	       "identical policies: nothing added or removed");
	desc = fs_policy_impact_describe (impact);
	CHECK (strstr (desc, "+0 added") != NULL &&
	       strstr (desc, "=2 unchanged") != NULL,
	       "describe counts the unchanged rows");
	g_free (desc);
	fs_policy_impact_free (impact);

	/* Change: the deny becomes an allow, a new row joins. */
	needle = gate_rule (FS_RULE_OUTBOUND_DENY_TO, NULL, NULL,
	                    "198.51.100.9");
	fs_policy_remove (after, needle);
	fs_rule_free (needle);

	needle = gate_rule (FS_RULE_OUTBOUND_ALLOW_TO, NULL, NULL,
	                    "203.0.113.80");
	fs_policy_add (after, needle);
	fs_rule_free (needle);

	impact = fs_policy_impact (before, after);
	CHECK (impact->added == 1 && impact->added_allows == 1 &&
	       impact->added_blocks == 0,
	       "the new allow counts on the added side");
	CHECK (impact->removed == 1 && impact->removed_allows == 0 &&
	       impact->removed_blocks == 1,
	       "the removed deny counts on the removed side");
	CHECK (impact->unchanged == 1, "the DNS row is untouched");
	desc = fs_policy_impact_describe (impact);
	CHECK (strstr (desc, "+1 added (1 allow, 0 block)") != NULL,
	       "describe names the added side");
	CHECK (strstr (desc, "-1 removed (0 allow, 1 block)") != NULL,
	       "describe names the removed side");
	g_free (desc);
	fs_policy_impact_free (impact);

	/* No record of what is live: everything counts as added --
	 * nothing is claimed live that is not known to be. */
	impact = fs_policy_impact (NULL, before);
	CHECK (impact->added == 2 && impact->removed == 0 &&
	       impact->unchanged == 0,
	       "NULL before means every row is added");
	fs_policy_impact_free (impact);

	/* The preview reads the journal for what is live. */
	g_mkdir_with_parents (dir, 0700);
	g_setenv ("STOCKFW_APPLIED_FILE", file, TRUE);
	CHECK (fs_apply_journal_save (before, NULL), "the preview journal saves");
	impact = fs_policy_impact_preview (after);
	CHECK (impact->added == 1 && impact->removed == 1 &&
	       impact->unchanged == 1,
	       "the preview measures against the journal, not a guess");
	fs_policy_impact_free (impact);
	g_unsetenv ("STOCKFW_APPLIED_FILE");
	remove (file);

	fs_policy_free (before);
	fs_policy_free (after);
	g_free (file);
	g_free (dir);
}

/* --- the delta work lists ------------------------------------------- */

static void test_apply_delta (void)
{
	FsPolicy *base = gate_policy_two ();
	FsPolicy *copy = gate_policy_copy (base);
	FsPolicy *more = gate_policy_copy (base);
	FsPolicy *ssh_before = fs_policy_new ();
	FsPolicy *ssh_after = fs_policy_new ();
	FsPolicyDelta *delta;
	FsRule *rule;

	/* DNS is a TCP and a UDP rule, plus the host block: three. */
	delta = fs_policy_delta (NULL, base);
	CHECK (g_list_length (delta->add) == 3 &&
	       g_list_length (delta->remove) == 0 && !delta->empty,
	       "no previous state: the whole set is an add");
	fs_policy_delta_free (delta);

	delta = fs_policy_delta (base, copy);
	CHECK (delta->empty, "identical policies: nothing to do at all");
	CHECK (g_list_length (delta->add) == 0 &&
	       g_list_length (delta->remove) == 0 &&
	       g_list_length (delta->repair) == 0,
	       "and every work list stays empty");
	fs_policy_delta_free (delta);

	rule = gate_rule (FS_RULE_OUTBOUND_ALLOW_TO, NULL, NULL,
	                  "203.0.113.44");
	fs_policy_add (more, rule);
	fs_rule_free (rule);

	delta = fs_policy_delta (base, more);
	CHECK (!delta->empty && g_list_length (delta->add) == 1 &&
	       g_list_length (delta->remove) == 0 &&
	       g_list_length (delta->repair) == 0,
	       "one row added is one concrete add");
	fs_policy_delta_free (delta);

	/* The name-collision repair: SSH on 22 and SSH on 2222 share one
	 * firewall name.  Dropping the first would take the second down
	 * with it by name -- unless the survivor is re-created. */
	rule = gate_rule (FS_RULE_OUTBOUND_ALLOW_SERVICE, "SSH", "22",
	                  FS_TARGET_ANY);
	fs_policy_add (ssh_before, rule);
	fs_rule_free (rule);
	rule = gate_rule (FS_RULE_OUTBOUND_ALLOW_SERVICE, "SSH", "2222",
	                  FS_TARGET_ANY);
	fs_policy_add (ssh_before, rule);
	fs_policy_add (ssh_after, rule);
	fs_rule_free (rule);

	delta = fs_policy_delta (ssh_before, ssh_after);
	CHECK (g_list_length (delta->remove) == 1,
	       "the dropped SSH row is one removal");
	CHECK (g_list_length (delta->repair) == 1,
	       "the kept SSH row is repaired -- its name is going away "
	       "with its twin");
	CHECK (g_list_length (delta->add) == 0,
	       "the kept row is not re-added as something new");
	CHECK (delta->repair != NULL && delta->remove != NULL &&
	       g_strcmp0 (delta->remove->data,
	                 ((FsFwRule *) delta->repair->data)->name) == 0,
	       "the collision is exactly the shared name");
	fs_policy_delta_free (delta);

	fs_policy_free (base);
	fs_policy_free (copy);
	fs_policy_free (more);
	fs_policy_free (ssh_before);
	fs_policy_free (ssh_after);
}

/* --- the gate --------------------------------------------------------- */

static void test_apply_gate (void)
{
	gchar *dir = g_build_filename (g_get_tmp_dir(),
	                               "stockfw-gate-test", NULL);
	gchar *file = g_build_filename (dir, "applied.csv", NULL);
	gchar *audit_file = g_build_filename (dir, "audit.log", NULL);
	FsPolicy *policy;
	FsPolicy *loaded;
	FsApplyOutcome *outcome;
	GError *error = NULL;
	gchar *contents;
	guint rows;
	FsRule *rule;
	const gchar *hold;

	g_mkdir_with_parents (dir, 0700);
	remove (file);
	remove (audit_file);
	g_setenv ("STOCKFW_APPLIED_FILE", file, TRUE);
	g_setenv ("STOCKFW_AUDIT_FILE", audit_file, TRUE);

	fake_reset ();
	policy = gate_policy_two ();
	rows = gate_policy_total (policy);
	loaded = fs_policy_new ();

	/* --- hold: nothing reaches the backend -------------------------- */
	outcome = fs_policy_apply_safe (&fake_backend, policy, "gate test",
	                                "audit-only testing mode", &error);
	CHECK (outcome->result == FS_APPLY_DRY_RUN && outcome->held &&
	       !outcome->applied,
	       "a hold is reported as a dry run, not as success or failure");
	CHECK (fake_full_calls == 0 && fake_delta_calls == 0,
	       "a held apply never calls the backend");
	CHECK (error == NULL, "a hold is not an error");
	CHECK (!g_file_test (file, G_FILE_TEST_EXISTS),
	       "a held apply writes no journal: nothing is live");
	CHECK (outcome->impact != NULL && outcome->impact->added == rows,
	       "the hold still measures the change honestly");
	contents = gate_audit_read ();
	CHECK (contents != NULL &&
	       strstr (contents,
	               "| policy held, firewall untouched |") != NULL &&
	       strstr (contents, "audit-only testing mode") != NULL,
	       "the hold is an audit line in those words");
	g_free (contents);
	fs_apply_outcome_free (outcome);

	/* --- first apply: no journal, whole-set path -------------------- */
	outcome = fs_policy_apply_safe (&fake_backend, policy, "gate test",
	                                NULL, &error);
	CHECK (outcome->result == FS_APPLY_OK && outcome->applied &&
	       !outcome->narrow,
	       "the first apply runs whole-set: nothing is known to be live");
	CHECK (fake_full_calls == 1 && fake_delta_calls == 0,
	       "exactly one whole-set call");
	CHECK (fs_apply_journal_load (loaded, &error) &&
	       gate_policy_total (loaded) == rows,
	       "a successful apply journals what is live");
	g_clear_error (&error);
	contents = gate_audit_read ();
	CHECK (contents != NULL &&
	       strstr (contents, "| policy applied |") != NULL &&
	       strstr (contents, "gate test | full |") != NULL,
	       "the applied audit line carries source, mode and impact");
	g_free (contents);
	fs_apply_outcome_free (outcome);

	/* --- no change: zero backend work -------------------------------- */
	fake_reset ();
	outcome = fs_policy_apply_safe (&fake_backend, policy, "gate test",
	                                NULL, &error);
	CHECK (outcome->applied && outcome->narrow &&
	       fake_full_calls == 0 && fake_delta_calls == 0,
	       "an unchanged policy touches nothing at all");
	contents = gate_audit_read ();
	CHECK (contents != NULL &&
	       strstr (contents, "| policy apply: no change |") != NULL,
	       "the no-change apply is still an audit line");
	g_free (contents);
	fs_apply_outcome_free (outcome);

	/* --- narrow: one row added ----------------------------------------- */
	rule = gate_rule (FS_RULE_OUTBOUND_ALLOW_TO, NULL, NULL,
	                  "203.0.113.9");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	outcome = fs_policy_apply_safe (&fake_backend, policy, "gate test",
	                                NULL, &error);
	CHECK (outcome->applied && outcome->narrow,
	       "one row added applies narrowly");
	CHECK (fake_delta_calls == 1 && fake_full_calls == 0,
	       "the narrow path never falls back to a whole-set apply");
	CHECK (fake_last_add_n == 1 && fake_last_remove_n == 0 &&
	       fake_last_repair_n == 0,
	       "one rule to create, none to delete, none to repair");
	CHECK (fs_apply_journal_load (loaded, &error) &&
	       gate_policy_total (loaded) == rows + 1,
	       "the journal follows the change");
	g_clear_error (&error);
	fs_apply_outcome_free (outcome);

	/* --- failure, rollback verified ------------------------------------ */
	rule = gate_rule (FS_RULE_OUTBOUND_ALLOW_TO, NULL, NULL,
	                  "203.0.113.10");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	fake_reset ();
	fake_enqueue (FS_APPLY_PARTIAL);   /* the narrow apply */
	fake_enqueue (FS_APPLY_OK);        /* the rollback     */
	outcome = fs_policy_apply_safe (&fake_backend, policy, "gate test",
	                                NULL, &error);
	CHECK (outcome->result == FS_APPLY_PARTIAL && !outcome->applied,
	       "a partial apply is never reported as applied");
	CHECK (outcome->rollback_attempted && outcome->rollback_verified,
	       "the rollback runs and its verdict is verified");
	CHECK (fake_delta_calls == 1 && fake_full_calls == 1,
	       "failure from the narrow path, rollback restored whole-set");
	CHECK (fake_seen_len == 1 &&
	       gate_policy_total (fake_seen[0]) == rows + 1,
	       "the rollback restores the last applied policy, not the new one");
	CHECK (fs_apply_journal_load (loaded, &error) &&
	       gate_policy_total (loaded) == rows + 1,
	       "a failed apply does not journal the new state");
	g_clear_error (&error);
	contents = gate_audit_read ();
	CHECK (contents != NULL &&
	       strstr (contents, "| policy apply failed |") != NULL &&
	       strstr (contents, "rollback verified:") != NULL,
	       "the failure and the verified rollback are one audit line");
	g_free (contents);
	fs_apply_outcome_free (outcome);

	/* --- failure, rollback failed --------------------------------------- */
	fake_reset ();
	fake_enqueue (FS_APPLY_FAILED);
	fake_enqueue (FS_APPLY_FAILED);
	outcome = fs_policy_apply_safe (&fake_backend, policy, "gate test",
	                                NULL, &error);
	CHECK (!outcome->applied && outcome->rollback_attempted &&
	       !outcome->rollback_verified,
	       "a failed rollback is reported as failed, never assumed");
	CHECK (outcome->rollback_detail != NULL &&
	       strstr (outcome->rollback_detail, "rollback FAILED") != NULL,
	       "the detail names the failed rollback");
	contents = gate_audit_read ();
	CHECK (contents != NULL &&
	       strstr (contents, "rollback FAILED:") != NULL,
	       "the failed rollback is in the audit log too");
	g_free (contents);
	g_clear_error (&error);
	fs_apply_outcome_free (outcome);

	/* --- failure with nothing to restore --------------------------------- */
	remove (file);
	fake_reset ();
	fake_enqueue (FS_APPLY_FAILED);
	outcome = fs_policy_apply_safe (&fake_backend, policy, "gate test",
	                                NULL, &error);
	CHECK (!outcome->applied && !outcome->rollback_attempted &&
	       outcome->rollback_detail != NULL &&
	       strstr (outcome->rollback_detail,
	               "no applied-policy journal") != NULL,
	       "with no journal there is nothing to restore, and it says so");
	CHECK (fake_full_calls == 1 && fake_delta_calls == 0,
	       "without a journal the apply is whole-set");
	contents = gate_audit_read ();
	CHECK (contents != NULL &&
	       strstr (contents, "rollback skipped") != NULL,
	       "the skipped rollback is in the audit log too");
	g_free (contents);
	g_clear_error (&error);
	fs_apply_outcome_free (outcome);

	/* --- no backend -------------------------------------------------------- */
	fake_reset ();
	fake_available_flag = FALSE;
	outcome = fs_policy_apply_safe (&fake_backend, policy, "gate test",
	                                NULL, &error);
	CHECK (outcome->result == FS_APPLY_NO_IPTABLES && error != NULL &&
	       g_error_matches (error, FS_APPLY_ERROR,
	                        FS_APPLY_ERR_NO_BACKEND),
	       "a missing backend is refused before anything runs");
	CHECK (fake_full_calls == 0 && fake_delta_calls == 0,
	       "no backend means no calls");
	contents = gate_audit_read ();
	CHECK (contents != NULL &&
	       strstr (contents, "| policy apply refused |") != NULL,
	       "the refusal is an audit line");
	g_free (contents);
	g_clear_error (&error);
	fs_apply_outcome_free (outcome);

	/* --- backend without the delta slot ----------------------------------- */
	fake_reset ();
	CHECK (fs_apply_journal_save (policy, NULL),
	       "journal restored for the fallback test");
	rule = gate_rule (FS_RULE_OUTBOUND_ALLOW_TO, NULL, NULL,
	                  "203.0.113.11");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	outcome = fs_policy_apply_safe (&fake_backend_no_delta, policy,
	                                "gate test", NULL, &error);
	CHECK (outcome->applied && !outcome->narrow,
	       "a backend without a delta slot falls back to whole-set");
	CHECK (fake_full_calls == 1 && fake_delta_calls == 0,
	       "the fallback is exactly one whole-set call");
	g_clear_error (&error);
	fs_apply_outcome_free (outcome);

	/* --- notes on a success: applied, journalled, no rollback ------------ */
	rule = gate_rule (FS_RULE_OUTBOUND_ALLOW_TO, NULL, NULL,
	                  "203.0.113.12");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);
	fake_reset ();
	outcome = fs_policy_apply_safe (&fake_backend_notes, policy,
	                                "gate test", NULL, &error);
	CHECK (outcome->result == FS_APPLY_OK && outcome->applied &&
	       !outcome->rollback_attempted && fake_full_calls == 1,
	       "an apply with notes is a success: no rollback (a host "
	       "without ip6tables must not have every apply undone)");
	CHECK (outcome->notes != NULL &&
	       strstr (outcome->notes, "ip6tables is not installed") != NULL,
	       "and the notes reach the caller");
	contents = gate_audit_read ();
	CHECK (contents != NULL &&
	       strstr (contents, "| policy applied, with notes |") != NULL &&
	       strstr (contents, "not installed. 2026-11-02 | forged") != NULL &&
	       strstr (contents, "\n2026-11-02 | forged") == NULL,
	       "the audit line carries the notes on one line: a line break "
	       "in a detail cannot forge a second entry");
	g_free (contents);
	g_clear_error (&error);
	fs_apply_outcome_free (outcome);

	/* --- the preference-driven hold --------------------------------------- */
	fake_reset ();
	fs_apply_set_audit_only (TRUE);
	hold = fs_apply_hold_reason ();
	CHECK (hold != NULL && strstr (hold, "audit-only") != NULL,
	       "the preference produces a hold reason");
	outcome = fs_policy_apply_safe (&fake_backend, policy, "gate test",
	                                hold, &error);
	CHECK (outcome->held && fake_full_calls == 0 &&
	       fake_delta_calls == 0,
	       "the preference-driven hold keeps the backend untouched");
	fs_apply_outcome_free (outcome);
	fs_apply_set_audit_only (FALSE);
	CHECK (fs_apply_hold_reason () == NULL,
	       "turning the mode off releases the hold");

	fake_reset ();
	fs_policy_free (policy);
	fs_policy_free (loaded);
	g_unsetenv ("STOCKFW_APPLIED_FILE");
	g_unsetenv ("STOCKFW_AUDIT_FILE");
	remove (file);
	remove (audit_file);
	g_free (file);
	g_free (audit_file);
	g_free (dir);
}

/* --- the start gate (1.0.7) -------------------------------------------
 * Every start -- at launch, Start/Resume, `stockfw start' at boot --
 * goes through fs_firewall_start_safe.  A backend whose start installs
 * the policy (Linux) must never start the policy FILE while changes
 * are held; it starts the journal instead, or nothing at all. */

static gint fake_starts, fake_stops;
static gboolean fake_start_ok = TRUE;

static gboolean
fake_start (GError **error)
{
	fake_starts++;
	if (!fake_start_ok)
		g_set_error_literal (error,
		                     g_quark_from_static_string ("fake-backend"),
		                     1, "scripted start failure");
	return fake_start_ok;
}

static gboolean
fake_stop (GError **error)
{
	(void) error;
	fake_stops++;
	return TRUE;
}

static const FsBackend fake_backend_linux_start = {
	.name = "fake-linux",
	.display_name = "scripted fake, start installs the policy",
	.start_applies_policy = TRUE,
	.available = fake_available,
	.start = fake_start,
	.stop = fake_stop,
	.apply_rules = fake_apply_rules,
	.apply_notes = fake_notes,
};

static const FsBackend fake_backend_windows_start = {
	.name = "fake-windows",
	.display_name = "scripted fake, start switches profiles on",
	.available = fake_available,
	.start = fake_start,
	.stop = fake_stop,
	.apply_rules = fake_apply_rules,
};

static void test_start_gate (void)
{
	gchar *dir = g_build_filename (g_get_tmp_dir (),
	                               "stockfw-start-gate-test", NULL);
	gchar *file = g_build_filename (dir, "applied.csv", NULL);
	gchar *audit_file = g_build_filename (dir, "audit.log", NULL);
	FsPolicy *policy, *live, *loaded;
	FsApplyOutcome *outcome;
	GError *error = NULL;
	gchar *audit;

	g_mkdir_with_parents (dir, 0700);
	remove (file);
	remove (audit_file);
	g_setenv ("STOCKFW_APPLIED_FILE", file, TRUE);
	g_setenv ("STOCKFW_AUDIT_FILE", audit_file, TRUE);

	policy = gate_policy_two ();

	/* 1. Linux-shaped, no hold, no journal: start() runs, the journal
	 * now records the policy as live, notes ride along. */
	fake_reset ();
	fake_starts = fake_stops = 0;
	fake_start_ok = TRUE;
	outcome = fs_firewall_start_safe (&fake_backend_linux_start, policy,
	                                  "test", NULL, &error);
	CHECK (outcome->result == FS_APPLY_OK && outcome->applied &&
	       !outcome->held && fake_starts == 1 && fake_full_calls == 0,
	       "start gate: no hold -> backend start, policy live");
	CHECK (outcome->notes != NULL,
	       "start gate: the backend's notes are kept on a start");
	loaded = fs_policy_new ();
	CHECK (fs_apply_journal_load (loaded, NULL) &&
	       fs_policy_count (loaded, FS_RULE_OUTBOUND_ALLOW_SERVICE) ==
	       fs_policy_count (policy, FS_RULE_OUTBOUND_ALLOW_SERVICE),
	       "start gate: a start that installs the policy updates the "
	       "journal");
	fs_policy_free (loaded);
	fs_apply_outcome_free (outcome);
	g_clear_error (&error);

	/* 2. Held, journal present: start() is NOT called (it would
	 * install the file); the journal policy is applied instead. */
	live = fs_policy_new ();
	policy_add_take (live, gate_rule (FS_RULE_OUTBOUND_ALLOW_SERVICE,
	                                "SSH", "22", FS_TARGET_ANY));
	fs_apply_journal_save (live, NULL);
	fake_reset ();
	fake_starts = 0;
	outcome = fs_firewall_start_safe (&fake_backend_linux_start, policy,
	                                  "test", "audit-only testing mode",
	                                  &error);
	CHECK (outcome->result == FS_APPLY_OK && outcome->held &&
	       outcome->applied && fake_starts == 0 && fake_full_calls == 1,
	       "start gate: held -> the journal is started, never the file "
	       "(%d starts, %d applies)", fake_starts, fake_full_calls);
	CHECK (fake_seen_len == 1 &&
	       fs_policy_count (fake_seen[0], FS_RULE_OUTBOUND_ALLOW_SERVICE)
	       == 1,
	       "start gate: what was applied is exactly the journal");
	loaded = fs_policy_new ();
	fs_apply_journal_load (loaded, NULL);
	CHECK (fs_policy_count (loaded, FS_RULE_OUTBOUND_ALLOW_SERVICE) == 1,
	       "start gate: a held start leaves the journal alone");
	fs_policy_free (loaded);
	fs_apply_outcome_free (outcome);
	g_clear_error (&error);
	fs_policy_free (live);

	/* 3. Held, no journal: nothing safe to start with. */
	remove (file);
	fake_reset ();
	fake_starts = 0;
	outcome = fs_firewall_start_safe (&fake_backend_linux_start, policy,
	                                  "test", "policy locked", &error);
	CHECK (outcome->result == FS_APPLY_DRY_RUN && outcome->held &&
	       !outcome->applied && fake_starts == 0 && fake_full_calls == 0,
	       "start gate: held with no journal -> firewall untouched");
	fs_apply_outcome_free (outcome);
	g_clear_error (&error);

	/* 4. Windows-shaped: start only switches profiles on, so a hold
	 * has nothing to hold back, and the journal is not touched. */
	fake_reset ();
	fake_starts = 0;
	outcome = fs_firewall_start_safe (&fake_backend_windows_start,
	                                  policy, "test",
	                                  "audit-only testing mode", &error);
	CHECK (outcome->result == FS_APPLY_OK && fake_starts == 1 &&
	       !outcome->applied && fake_full_calls == 0,
	       "start gate: a profiles-only start runs even when held, and "
	       "never claims the policy went live");
	CHECK (!g_file_test (file, G_FILE_TEST_EXISTS),
	       "start gate: a profiles-only start writes no journal");
	fs_apply_outcome_free (outcome);
	g_clear_error (&error);

	/* 5. A failing start reports it; an absent backend is refused. */
	fake_reset ();
	fake_start_ok = FALSE;
	outcome = fs_firewall_start_safe (&fake_backend_linux_start, policy,
	                                  "test", NULL, &error);
	CHECK (outcome->result == FS_APPLY_FAILED && !outcome->applied &&
	       error != NULL,
	       "start gate: a failed start is a failure, with the reason");
	fs_apply_outcome_free (outcome);
	g_clear_error (&error);
	fake_start_ok = TRUE;

	fake_reset ();
	fake_available_flag = FALSE;
	fake_starts = 0;
	outcome = fs_firewall_start_safe (&fake_backend_linux_start, policy,
	                                  "test", NULL, &error);
	CHECK (outcome->result == FS_APPLY_NO_IPTABLES && fake_starts == 0 &&
	       error != NULL,
	       "start gate: no backend available -> refused, not started");
	fs_apply_outcome_free (outcome);
	g_clear_error (&error);
	CHECK (!fs_firewall_stop_logged (&fake_backend_linux_start, "test",
	                                 &error) && fake_stops == 0,
	       "stop: no backend available -> refused");
	g_clear_error (&error);
	fake_available_flag = TRUE;

	/* 6. Stop is never held, and is on the record. */
	fake_stops = 0;
	CHECK (fs_firewall_stop_logged (&fake_backend_linux_start, "test",
	                                &error) && fake_stops == 1,
	       "stop: the backend stops");
	g_clear_error (&error);

	audit = NULL;
	g_file_get_contents (audit_file, &audit, NULL, NULL);
	CHECK (audit != NULL && strstr (audit, "firewall started") &&
	       strstr (audit, "firewall start held") &&
	       strstr (audit, "firewall start failed") &&
	       strstr (audit, "firewall start refused") &&
	       strstr (audit, "firewall stopped"),
	       "start gate: every start and stop outcome is audited");
	g_free (audit);

	fake_reset ();
	fs_policy_free (policy);
	g_unsetenv ("STOCKFW_APPLIED_FILE");
	g_unsetenv ("STOCKFW_AUDIT_FILE");
	remove (file);
	remove (audit_file);
	g_free (file);
	g_free (audit_file);
	g_free (dir);
}

/* --- a start installs what was APPLIED, never the file (1.0.7) ----------
 * The boot unit runs `stockfw start' unattended at every boot.  A
 * start that installed the policy FILE put live whatever had been
 * saved but never applied (an allow nobody pushed), and with the rule
 * files gone it started an empty policy over a working one.  A start
 * on a backend whose start installs a policy now installs the journal,
 * less the expired Sentinel rows it is handed, held or not; a journal
 * that cannot be read refuses the start.  fs_firewall_lift_live takes
 * expired rows off without applying anything else. */

static void test_start_from_journal (void)
{
	gchar *dir = g_build_filename (g_get_tmp_dir (),
	                               "stockfw-start-journal-test", NULL);
	gchar *file = g_build_filename (dir, "applied.csv", NULL);
	gchar *audit_file = g_build_filename (dir, "audit.log", NULL);
	FsPolicy *file_policy, *live, *lift, *loaded;
	FsRule *allow, *block, *sentinel;
	FsApplyOutcome *outcome;
	GError *error = NULL;
	gchar *audit;

	g_mkdir_with_parents (dir, 0700);
	remove (file);
	remove (audit_file);
	g_setenv ("STOCKFW_APPLIED_FILE", file, TRUE);
	g_setenv ("STOCKFW_AUDIT_FILE", audit_file, TRUE);

	allow = gate_rule (FS_RULE_INBOUND_ALLOW_SERVICE, "SSH", "22",
	                   FS_TARGET_ANY);
	block = gate_rule (FS_RULE_OUTBOUND_DENY_TO, NULL, NULL,
	                   "203.0.113.9");
	sentinel = gate_rule (FS_RULE_OUTBOUND_DENY_TO, NULL, NULL,
	                      "198.51.100.77");

	/* Applied: the block and a Sentinel block.  Saved since, never
	 * applied: an SSH allow. */
	live = fs_policy_new ();
	fs_policy_add (live, block);
	fs_policy_add (live, sentinel);
	fs_apply_journal_save (live, NULL);
	file_policy = fs_policy_new ();
	fs_policy_add (file_policy, block);
	fs_policy_add (file_policy, sentinel);
	fs_policy_add (file_policy, allow);

	/* 1. Unheld, journal present: the journal goes in, start() (which
	 * would install the file) is never called. */
	fake_reset ();
	fake_starts = 0;
	outcome = fs_firewall_start_safe (&fake_backend_linux_start,
	                                  file_policy, "test", NULL, &error);
	CHECK (outcome->result == FS_APPLY_OK && outcome->applied &&
	       fake_starts == 0 && fake_full_calls == 1,
	       "start: with a journal, the journal is installed, not the "
	       "file (%d starts, %d applies)", fake_starts, fake_full_calls);
	CHECK (fake_seen_len == 1 && gate_policy_total (fake_seen[0]) == 2 &&
	       !fs_policy_contains (fake_seen[0], allow),
	       "start: the allow that was saved but never applied stays "
	       "OFF the firewall");
	fs_apply_outcome_free (outcome);
	g_clear_error (&error);

	/* 2. ...less what it is told to lift (expired Sentinel rows), and
	 * the journal then records that as live. */
	lift = fs_policy_new ();
	fs_policy_add (lift, sentinel);
	fake_reset ();
	fake_starts = 0;
	outcome = fs_firewall_start_lifting (&fake_backend_linux_start,
	                                     file_policy, lift, "test", NULL,
	                                     &error);
	CHECK (outcome->result == FS_APPLY_OK && fake_starts == 0 &&
	       fake_seen_len == 1 && gate_policy_total (fake_seen[0]) == 1 &&
	       fs_policy_contains (fake_seen[0], block) &&
	       !fs_policy_contains (fake_seen[0], sentinel),
	       "start: the expired Sentinel block is left out, the user's "
	       "block goes in");
	loaded = fs_policy_new ();
	CHECK (fs_apply_journal_load (loaded, NULL) &&
	       gate_policy_total (loaded) == 1 &&
	       !fs_policy_contains (loaded, sentinel),
	       "start: the journal records what this start installed");
	fs_policy_free (loaded);
	fs_apply_outcome_free (outcome);
	g_clear_error (&error);
	audit = gate_audit_read ();
	CHECK (audit != NULL &&
	       strstr (audit, "started with the last applied policy") &&
	       strstr (audit, "expired Sentinel block") &&
	       strstr (audit, "not applied:"),
	       "start: the audit line says the journal started, what was "
	       "left out and what stays unapplied");
	g_free (audit);

	/* 3. The rule files are gone (empty policy) but the journal is
	 * there: the start still installs what was applied. */
	fs_apply_journal_save (live, NULL);
	{
		FsPolicy *empty = fs_policy_new ();

		fake_reset ();
		fake_starts = 0;
		outcome = fs_firewall_start_safe (&fake_backend_linux_start,
		                                  empty, "test", NULL, &error);
		CHECK (outcome->result == FS_APPLY_OK && fake_starts == 0 &&
		       fake_seen_len == 1 &&
		       gate_policy_total (fake_seen[0]) == 2,
		       "start: an empty policy file never replaces what was "
		       "live (%d rules installed, want 2)",
		       fake_seen_len == 1 ? (gint) gate_policy_total (
		       fake_seen[0]) : -1);
		fs_apply_outcome_free (outcome);
		g_clear_error (&error);
		fs_policy_free (empty);
	}

	/* 4. A journal that is there but cannot be read: refused, neither
	 * it nor the file goes in. */
	g_file_set_contents (file, "this is not a journal row\n", -1, NULL);
	fake_reset ();
	fake_starts = 0;
	outcome = fs_firewall_start_safe (&fake_backend_linux_start,
	                                  file_policy, "test", NULL, &error);
	CHECK (outcome->result == FS_APPLY_FAILED && !outcome->applied &&
	       fake_starts == 0 && fake_full_calls == 0 && error != NULL,
	       "start: an unreadable journal refuses the start, firewall "
	       "untouched");
	fs_apply_outcome_free (outcome);
	g_clear_error (&error);
	audit = gate_audit_read ();
	CHECK (audit != NULL &&
	       strstr (audit, "journal could not be read") != NULL,
	       "start: the refusal is audited");
	g_free (audit);

	/* 5. Lifting expired rows off a running firewall: only their
	 * removal, never the file. */
	fs_apply_journal_save (live, NULL);
	fake_reset ();
	outcome = fs_firewall_lift_live (&fake_backend_linux_start, lift,
	                                 "test", NULL, &error);
	CHECK (outcome != NULL && outcome->applied && fake_seen_len == 1 &&
	       gate_policy_total (fake_seen[0]) == 1 &&
	       fs_policy_contains (fake_seen[0], block) &&
	       !fs_policy_contains (fake_seen[0], allow),
	       "lift: the journal less the expired block is applied -- the "
	       "unapplied allow does not ride along");
	if (outcome != NULL)
		fs_apply_outcome_free (outcome);
	g_clear_error (&error);

	fake_reset ();
	outcome = fs_firewall_lift_live (&fake_backend_linux_start, lift,
	                                 "test", NULL, &error);
	CHECK (outcome == NULL && fake_full_calls == 0,
	       "lift: a row that is not live any more changes nothing");
	if (outcome != NULL)
		fs_apply_outcome_free (outcome);

	remove (file);
	fake_reset ();
	outcome = fs_firewall_lift_live (&fake_backend_linux_start, lift,
	                                 "test", NULL, &error);
	CHECK (outcome == NULL && fake_full_calls == 0,
	       "lift: no journal, nothing known to be live, nothing done");
	if (outcome != NULL)
		fs_apply_outcome_free (outcome);

	fake_reset ();
	fs_rule_free (allow);
	fs_rule_free (block);
	fs_rule_free (sentinel);
	fs_policy_free (lift);
	fs_policy_free (live);
	fs_policy_free (file_policy);
	g_unsetenv ("STOCKFW_APPLIED_FILE");
	g_unsetenv ("STOCKFW_AUDIT_FILE");
	remove (file);
	remove (audit_file);
	g_rmdir (dir);
	g_free (file);
	g_free (audit_file);
	g_free (dir);
}

/* --- Sentinel's persisted blocks at a start without the app ------------
 * `stockfw start' at boot has no Sentinel running to lift a block whose
 * ten minutes ran out while the machine was off; fs_autoblock_expire
 * takes such rows out of the policy BEFORE the start can install them. */

static void test_autoblock_expire (void)
{
	gchar *dir = g_build_filename (g_get_tmp_dir (),
	                               "stockfw-autoblock-test", NULL);
	gchar *state = g_build_filename (dir, "autoblocks", NULL);
	gchar *audit_file = g_build_filename (dir, "audit.log", NULL);
	const gchar *old_csv = "203.0.113.9, Sentinel: old beacon";
	const gchar *new_csv = "203.0.113.10, Sentinel: fresh beacon";
	const gchar *user_csv = "198.51.100.7, mine";
	gint64 now = 1800000000;
	FsPolicy *policy, *lifted;
	FsRule *probe;
	gchar *rows, *after = NULL;
	guint dropped;

	g_mkdir_with_parents (dir, 0700);
	g_setenv ("STOCKFW_AUTOBLOCK_FILE", state, TRUE);
	g_setenv ("STOCKFW_AUDIT_FILE", audit_file, TRUE);

	policy = fs_policy_new ();
	policy_add_take (policy, fs_rule_from_csv (FS_RULE_OUTBOUND_DENY_TO,
	                                         old_csv));
	policy_add_take (policy, fs_rule_from_csv (FS_RULE_OUTBOUND_DENY_TO,
	                                         new_csv));
	policy_add_take (policy, fs_rule_from_csv (FS_RULE_OUTBOUND_DENY_TO,
	                                         user_csv));
	fs_policy_save (policy);

	rows = g_strdup_printf ("S,%" G_GINT64_FORMAT ",%d,%s\n"
	                        "S,%" G_GINT64_FORMAT ",%d,%s\n"
	                        "garbage row\n",
	                        now - 3600, (int) FS_RULE_OUTBOUND_DENY_TO,
	                        old_csv,
	                        now - 60, (int) FS_RULE_OUTBOUND_DENY_TO,
	                        new_csv);
	g_file_set_contents (state, rows, -1, NULL);
	g_free (rows);

	{
		/* A second stale row whose rule the user already deleted
		 * from the file: the journal may still hold it. */
		gchar *more = NULL, *both;

		g_file_get_contents (state, &more, NULL, NULL);
		both = g_strdup_printf ("%sS,%" G_GINT64_FORMAT ",%d,%s\n",
		                        more, now - 7200,
		                        (int) FS_RULE_OUTBOUND_DENY_TO,
		                        "192.0.2.200, Sentinel: deleted");
		g_file_set_contents (state, both, -1, NULL);
		g_free (both);
		g_free (more);
	}
	lifted = fs_policy_new ();
	dropped = fs_autoblock_expire (policy, now, FALSE, lifted);
	CHECK (dropped == 1, "autoblock expire: one stale block came out "
	       "(got %u)", dropped);
	probe = fs_rule_from_csv (FS_RULE_OUTBOUND_DENY_TO, old_csv);
	CHECK (fs_policy_contains (lifted, probe) &&
	       fs_policy_count (lifted, FS_RULE_OUTBOUND_DENY_TO) == 2,
	       "autoblock expire: every due row is handed back for the "
	       "start to leave out, the one already gone from the file "
	       "too (%u)", fs_policy_count (lifted, FS_RULE_OUTBOUND_DENY_TO));
	fs_rule_free (probe);
	fs_policy_free (lifted);
	probe = fs_rule_from_csv (FS_RULE_OUTBOUND_DENY_TO, old_csv);
	CHECK (!fs_policy_contains (policy, probe),
	       "autoblock expire: the stale block left the policy");
	fs_rule_free (probe);
	{
		FsPolicy *disk = fs_policy_new ();

		fs_policy_load (disk, NULL);
		probe = fs_rule_from_csv (FS_RULE_OUTBOUND_DENY_TO, old_csv);
		CHECK (!fs_policy_contains (disk, probe),
		       "autoblock expire: ...and the policy file");
		fs_rule_free (probe);
		probe = fs_rule_from_csv (FS_RULE_OUTBOUND_DENY_TO, new_csv);
		CHECK (fs_policy_contains (disk, probe),
		       "autoblock expire: a block inside its ten minutes "
		       "stays for the app to re-arm");
		fs_rule_free (probe);
		probe = fs_rule_from_csv (FS_RULE_OUTBOUND_DENY_TO, user_csv);
		CHECK (fs_policy_contains (disk, probe),
		       "autoblock expire: the user's own rule is never touched");
		fs_rule_free (probe);
		fs_policy_free (disk);
	}
	g_file_get_contents (state, &after, NULL, NULL);
	CHECK (after != NULL && strstr (after, new_csv) != NULL &&
	       strstr (after, old_csv) == NULL &&
	       strstr (after, "garbage") == NULL,
	       "autoblock expire: the state file keeps only the live row");
	g_free (after);

	dropped = fs_autoblock_expire (policy, now, TRUE, NULL);
	CHECK (dropped == 1, "autoblock expire: Sentinel out of auto mode "
	       "lifts the rest (got %u)", dropped);
	CHECK (fs_autoblock_expire (policy, now, FALSE, NULL) == 0,
	       "autoblock expire: nothing left, nothing removed");

	fs_policy_clear (policy);
	fs_policy_save (policy);
	fs_policy_free (policy);
	g_unsetenv ("STOCKFW_AUTOBLOCK_FILE");
	g_unsetenv ("STOCKFW_AUDIT_FILE");
	remove (state);
	remove (audit_file);
	g_rmdir (dir);
	g_free (state);
	g_free (audit_file);
	g_free (dir);
}

/* Start at sign-in (core/fs-autostart.c).  The Windows half is the
 * task XML -- what the Task Scheduler is handed decides whose sign-in
 * starts it, whether it runs elevated and what it runs -- so it is
 * pinned here, portably.  The Linux half is the XDG entry, written to
 * a scratch directory through $STOCKFW_AUTOSTART_DIR. */
static gboolean
xml_has (const gchar *xml, const gchar *needle)
{
	return strstr (xml, needle) != NULL;
}

static void test_autostart (void)
{
	gchar *xml = fs_autostart_task_xml (
		"PC\\Ann & Bob",
		"C:\\Program Files\\StockFW\\StockFW.exe");
	gchar *name, *exec;
#ifndef G_OS_WIN32
	gchar *dir, *entry, *contents = NULL;
	GKeyFile *kf;
#endif

	CHECK (xml_has (xml, "<LogonTrigger>") &&
	       xml_has (xml, "<UserId>PC\\Ann &amp; Bob</UserId>\n"
	                     "      <Delay>"),
	       "autostart task: a logon trigger for this user only");
	CHECK (xml_has (xml, "<LogonType>InteractiveToken</LogonType>") &&
	       xml_has (xml, "<RunLevel>LeastPrivilege</RunLevel>") &&
	       !xml_has (xml, "HighestAvailable"),
	       "autostart task: runs in the user's session, NOT elevated "
	       "(an elevated task with no prompt is a silent UAC bypass)");
	CHECK (xml_has (xml, "<AllowStartOnDemand>false</AllowStartOnDemand>") &&
	       !xml_has (xml, "<AllowStartOnDemand>true"),
	       "autostart task: cannot be started on demand, only at sign-in");
	CHECK (xml_has (xml, "<Command>C:\\Program Files\\StockFW\\StockFW.exe</Command>") &&
	       xml_has (xml, "<Arguments>--background</Arguments>") &&
	       xml_has (xml, "<WorkingDirectory>C:\\Program Files\\StockFW</WorkingDirectory>"),
	       "autostart task: runs <exe dir>\\StockFW.exe --background");
	CHECK (xml_has (xml, "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>") &&
	       xml_has (xml, "<DisallowStartIfOnBatteries>false") &&
	       xml_has (xml, "<StopIfGoingOnBatteries>false") &&
	       xml_has (xml, "<MultipleInstancesPolicy>IgnoreNew"),
	       "autostart task: no time limit, runs on battery, one copy");
	CHECK (!xml_has (xml, "Ann & Bob<"),
	       "autostart task: the user name is XML-escaped");
	g_free (xml);

	name = fs_autostart_task_name ("PC\\Ann");
	CHECK (strcmp (name, "Start at sign-in (PC_Ann)") == 0,
	       "autostart task name: no backslash (got \"%s\")", name);
	g_free (name);

	exec = fs_autostart_desktop_exec ("/usr/local/bin/StockFW", TRUE);
	CHECK (strcmp (exec, "StockFW --background") == 0,
	       "autostart Exec: bare name when PATH finds this binary");
	g_free (exec);
	exec = fs_autostart_desktop_exec ("/opt/StockFW/StockFW", FALSE);
	CHECK (strcmp (exec, "/opt/StockFW/StockFW --background") == 0,
	       "autostart Exec: absolute path otherwise (got \"%s\")", exec);
	g_free (exec);
	exec = fs_autostart_desktop_exec ("/home/a b/100%\"$x/StockFW", FALSE);
	CHECK (strcmp (exec, "\"/home/a b/100%%\\\"\\$x/StockFW\" --background") == 0,
	       "autostart Exec: reserved characters quoted per the Desktop "
	       "Entry spec (got %s)", exec);
	g_free (exec);

#ifndef G_OS_WIN32
	/* The Linux entry itself.  (On Windows the same calls would
	 * register a real Task Scheduler task.) */
	dir = g_build_filename (g_get_tmp_dir (), "stockfw-autostart-test", NULL);
	entry = g_build_filename (dir, "stockfw.desktop", NULL);
	g_setenv ("STOCKFW_AUTOSTART_DIR", dir, TRUE);
	remove (entry);
	g_rmdir (dir);

	CHECK (fs_autostart_supported (), "autostart: supported on Linux");
	CHECK (!fs_autostart_enabled (), "autostart: off with no entry");
	CHECK (fs_autostart_set (TRUE, NULL), "autostart: turned on");
	CHECK (fs_autostart_enabled (), "autostart: on after turning on");
	kf = g_key_file_new ();
	CHECK (g_key_file_load_from_file (kf, entry, G_KEY_FILE_NONE, NULL),
	       "autostart: the entry is a valid key file");
	exec = g_key_file_get_string (kf, "Desktop Entry", "Exec", NULL);
	CHECK (exec != NULL && g_str_has_suffix (exec, " --background"),
	       "autostart: Exec ends in --background (got %s)",
	       exec != NULL ? exec : "(none)");
	g_free (exec);
	g_key_file_free (kf);

	/* A desktop's "startup applications" switch turns it off by key. */
	g_file_set_contents (entry,
		"[Desktop Entry]\nType=Application\nName=StockFW\n"
		"Exec=StockFW --background\nX-GNOME-Autostart-enabled=false\n",
		-1, NULL);
	CHECK (!fs_autostart_enabled (),
	       "autostart: X-GNOME-Autostart-enabled=false reads as off");
	g_file_set_contents (entry,
		"[Desktop Entry]\nType=Application\nName=StockFW\n"
		"Exec=StockFW --background\nHidden=true\n", -1, NULL);
	CHECK (!fs_autostart_enabled (), "autostart: Hidden=true reads as off");
	CHECK (fs_autostart_set (TRUE, NULL) && fs_autostart_enabled (),
	       "autostart: turning on again rewrites a switched-off entry");
	g_file_get_contents (entry, &contents, NULL, NULL);
	CHECK (contents != NULL && strstr (contents, "Hidden") == NULL,
	       "autostart: the rewrite drops Hidden=true");
	g_free (contents);

	CHECK (fs_autostart_set (FALSE, NULL) && !fs_autostart_enabled () &&
	       !g_file_test (entry, G_FILE_TEST_EXISTS),
	       "autostart: turned off, the entry is gone");
	CHECK (fs_autostart_set (FALSE, NULL),
	       "autostart: turning off what is off succeeds");

	g_unsetenv ("STOCKFW_AUTOSTART_DIR");
	g_rmdir (dir);
	g_free (entry);
	g_free (dir);

	/* The boot unit Preferences reports beside it: read from where
	 * install.sh puts it and where enabling it links it. */
	{
		gchar *sd = g_build_filename (g_get_tmp_dir (),
		                              "stockfw-systemd-test", NULL);
		gchar *wants = g_build_filename (sd, "multi-user.target.wants",
		                                 NULL);
		gchar *unit = g_build_filename (sd, "stockfw.service", NULL);
		gchar *link = g_build_filename (wants, "stockfw.service", NULL);
		gchar *gone = g_build_filename (sd, "gone.service", NULL);

		remove (link);
		remove (unit);
		g_rmdir (wants);
		g_rmdir (sd);
		g_setenv ("STOCKFW_SYSTEMD_DIR", sd, TRUE);

		CHECK (fs_autostart_boot_unit () == FS_BOOT_UNIT_ABSENT,
		       "boot unit: none installed reads as absent");
		g_mkdir_with_parents (wants, 0700);
		g_file_set_contents (unit, "[Unit]\n", -1, NULL);
		CHECK (fs_autostart_boot_unit () == FS_BOOT_UNIT_DISABLED,
		       "boot unit: installed, not linked, reads as not enabled");
		CHECK (symlink (unit, link) == 0 &&
		       fs_autostart_boot_unit () == FS_BOOT_UNIT_ENABLED,
		       "boot unit: linked into multi-user.target.wants reads "
		       "as enabled");
		remove (link);
		CHECK (symlink (gone, link) == 0 &&
		       fs_autostart_boot_unit () == FS_BOOT_UNIT_DISABLED,
		       "boot unit: a link to nothing is not enabled");
		remove (link);
		remove (unit);
		CHECK (symlink (unit, link) == 0 &&
		       fs_autostart_boot_unit () == FS_BOOT_UNIT_ABSENT,
		       "boot unit: a link left behind with the unit removed "
		       "reads as absent");

		remove (link);
		g_rmdir (wants);
		g_rmdir (sd);
		g_unsetenv ("STOCKFW_SYSTEMD_DIR");
		g_free (sd);
		g_free (wants);
		g_free (unit);
		g_free (link);
		g_free (gone);
	}
#endif
}

/* The tray's "Blocked today" and Recent blocks (core/fs-blocktally.c). */
static void test_block_tally (void)
{
	GTimeZone *tz = g_time_zone_new_utc ();
	GDateTime *morning = g_date_time_new (tz, 2026, 11, 2, 9, 5, 0);
	GDateTime *night = g_date_time_new (tz, 2026, 11, 2, 23, 59, 0);
	GDateTime *next = g_date_time_new (tz, 2026, 11, 3, 0, 1, 0);
	GDateTime *year_on = g_date_time_new (tz, 2027, 11, 2, 9, 0, 0);
	FsHit *in = fs_hit_new (), *out = fs_hit_new (), *bare = fs_hit_new ();
	gchar *s, **rows;

	in->direction = g_strdup ("In");
	in->protocol = g_strdup ("tcp");
	in->port = g_strdup ("445");
	in->source = g_strdup ("203.0.113.5");
	in->destination = g_strdup ("192.0.2.1");
	out->direction = g_strdup ("Outbound");
	out->protocol = g_strdup ("UDP");
	out->port = g_strdup ("53");
	out->source = g_strdup ("192.0.2.1");
	out->destination = g_strdup ("198.51.100.53");

	s = fs_block_tally_describe (in, "10:42");
	CHECK (strcmp (s, "TCP 445 from 203.0.113.5 (10:42)") == 0,
	       "block tally: inbound reads \"proto port from host (time)\" "
	       "(got \"%s\")", s);
	g_free (s);
	s = fs_block_tally_describe (out, "10:43");
	CHECK (strcmp (s, "UDP 53 to 198.51.100.53 (10:43)") == 0,
	       "block tally: outbound names where it was going (got \"%s\")",
	       s);
	g_free (s);
	s = fs_block_tally_describe (bare, NULL);
	CHECK (strcmp (s, "Traffic to unknown") == 0,
	       "block tally: an event with nothing in it still reads as a "
	       "sentence (got \"%s\")", s);
	g_free (s);

	fs_block_tally_reset ();
	CHECK (fs_block_tally_today (morning) == 0,
	       "block tally: nothing counted yet");
	for (gint i = 0; i < 7; i++)
		fs_block_tally_note (i % 2 ? out : in, i < 6 ? morning : night);
	CHECK (fs_block_tally_today (night) == 7,
	       "block tally: seven blocks on one day count seven");
	rows = fs_block_tally_recent ();
	CHECK (g_strv_length (rows) == FS_BLOCK_TALLY_RECENT &&
	       strcmp (rows[0], "TCP 445 from 203.0.113.5 (23:59)") == 0,
	       "block tally: the last five are kept, newest first");
	g_strfreev (rows);
	CHECK (fs_block_tally_today (next) == 0,
	       "block tally: the count is zero after midnight");
	CHECK (fs_block_tally_today (year_on) == 0,
	       "block tally: the same date a year on is another day");
	fs_block_tally_note (out, next);
	CHECK (fs_block_tally_today (next) == 1,
	       "block tally: a new day starts again from one");
	fs_block_tally_reset ();

	fs_hit_free (in);
	fs_hit_free (out);
	fs_hit_free (bare);
	g_date_time_unref (morning);
	g_date_time_unref (night);
	g_date_time_unref (next);
	g_date_time_unref (year_on);
	g_time_zone_unref (tz);
}

/* --- firewall settings through the apply gate (Preferences, D5) ------
 * A settings change must reach the firewall even when the policy rows
 * did not change -- which the policy gate's narrow path would call "no
 * change" -- and a failed apply must be rolled back under the settings
 * that were live. */

static gboolean swap_previous_active = FALSE;
static GString *swap_trace = NULL;
static GString *apply_trace = NULL;

static void
settings_swap_probe (gboolean previous, gpointer data)
{
	(void) data;
	swap_previous_active = previous;
	g_string_append_c (swap_trace, previous ? 'P' : 'N');
}

/* Records under which settings each whole-set apply ran. */
static FsApplyResult
fake_apply_rules_traced (const FsPolicy *policy, GError **error)
{
	g_string_append_c (apply_trace, swap_previous_active ? 'p' : 'n');
	return fake_apply_rules (policy, error);
}

static const FsBackend fake_backend_traced = {
	.name = "fake-traced",
	.display_name = "scripted fake backend, settings traced",
	.available = fake_available,
	.apply_rules = fake_apply_rules_traced,
	.apply_delta = fake_apply_delta,
};

static void test_settings_apply_gate (void)
{
	gchar *dir = g_build_filename (g_get_tmp_dir (),
	                               "stockfw-settings-gate-test", NULL);
	gchar *file = g_build_filename (dir, "applied.csv", NULL);
	gchar *audit_file = g_build_filename (dir, "audit.log", NULL);
	FsPolicy *policy;
	FsApplyOutcome *outcome;
	GError *error = NULL;
	gchar *contents;
	gint before_full;

	g_mkdir_with_parents (dir, 0700);
	remove (file);
	remove (audit_file);
	g_setenv ("STOCKFW_APPLIED_FILE", file, TRUE);
	g_setenv ("STOCKFW_AUDIT_FILE", audit_file, TRUE);
	swap_trace = g_string_new (NULL);
	apply_trace = g_string_new (NULL);

	fake_reset ();
	policy = gate_policy_two ();

	/* Make the policy live, so the journal matches it exactly. */
	outcome = fs_policy_apply_safe (&fake_backend_traced, policy,
	                                "settings test", NULL, &error);
	CHECK (outcome->applied && fake_full_calls == 1,
	       "settings gate: the policy is live first");
	fs_apply_outcome_free (outcome);

	/* The policy gate sees nothing to do... */
	before_full = fake_full_calls;
	outcome = fs_policy_apply_safe (&fake_backend_traced, policy,
	                                "settings test", NULL, &error);
	CHECK (outcome->narrow && fake_full_calls == before_full &&
	       fake_delta_calls == 0,
	       "settings gate: the policy gate calls an unchanged policy "
	       "\"no change\" and leaves the firewall alone");
	fs_apply_outcome_free (outcome);

	/* ...so a settings change goes the whole way. */
	outcome = fs_settings_apply_safe (&fake_backend_traced, policy,
	                                  "settings test", NULL,
	                                  settings_swap_probe, NULL, &error);
	CHECK (outcome->result == FS_APPLY_OK && outcome->applied &&
	       !outcome->narrow && fake_full_calls == before_full + 1 &&
	       fake_delta_calls == 0,
	       "settings gate: an unchanged policy is applied whole when the "
	       "settings changed");
	CHECK (swap_trace->len == 0,
	       "settings gate: a successful apply never swaps settings");
	contents = gate_audit_read ();
	CHECK (contents != NULL &&
	       strstr (contents, "| firewall settings applied |") != NULL,
	       "settings gate: the audit line says \"firewall settings "
	       "applied\"");
	g_free (contents);
	fs_apply_outcome_free (outcome);

	/* A hold reaches nothing and swaps nothing. */
	before_full = fake_full_calls;
	outcome = fs_settings_apply_safe (&fake_backend_traced, policy,
	                                  "settings test",
	                                  "audit-only testing mode",
	                                  settings_swap_probe, NULL, &error);
	CHECK (outcome->held && outcome->result == FS_APPLY_DRY_RUN &&
	       fake_full_calls == before_full && swap_trace->len == 0,
	       "settings gate: a hold leaves the firewall and the settings "
	       "context untouched");
	contents = gate_audit_read ();
	CHECK (contents != NULL &&
	       strstr (contents,
	               "| firewall settings held, firewall untouched |") != NULL,
	       "settings gate: the hold is audited as a settings hold");
	g_free (contents);
	fs_apply_outcome_free (outcome);

	/* A failure is rolled back under the previous settings, and the
	 * new ones go back into the context afterwards. */
	g_string_truncate (apply_trace, 0);
	fake_enqueue (FS_APPLY_FAILED);
	fake_enqueue (FS_APPLY_OK);
	outcome = fs_settings_apply_safe (&fake_backend_traced, policy,
	                                  "settings test", NULL,
	                                  settings_swap_probe, NULL, &error);
	CHECK (outcome->result == FS_APPLY_FAILED && !outcome->applied &&
	       outcome->rollback_attempted && outcome->rollback_verified,
	       "settings gate: a failed apply is rolled back and verified");
	CHECK (g_strcmp0 (apply_trace->str, "np") == 0 &&
	       g_strcmp0 (swap_trace->str, "PN") == 0 &&
	       !swap_previous_active,
	       "settings gate: new settings first, the rollback under the "
	       "previous ones, the new ones back after (applies %s, swaps %s)",
	       apply_trace->str, swap_trace->str);
	g_clear_error (&error);
	contents = gate_audit_read ();
	CHECK (contents != NULL &&
	       strstr (contents, "| firewall settings apply failed |") != NULL &&
	       strstr (contents, "rollback verified") != NULL,
	       "settings gate: the failure and the verified rollback are "
	       "audited");
	g_free (contents);
	fs_apply_outcome_free (outcome);

	/* No journal: nothing to restore, nothing swapped. */
	remove (file);
	g_string_truncate (swap_trace, 0);
	fake_enqueue (FS_APPLY_FAILED);
	outcome = fs_settings_apply_safe (&fake_backend_traced, policy,
	                                  "settings test", NULL,
	                                  settings_swap_probe, NULL, &error);
	CHECK (!outcome->rollback_attempted && swap_trace->len == 0 &&
	       outcome->rollback_detail != NULL &&
	       strstr (outcome->rollback_detail, "no applied-policy journal")
	       != NULL,
	       "settings gate: with no journal there is honestly nothing "
	       "to restore");
	g_clear_error (&error);
	fs_apply_outcome_free (outcome);

	fake_reset ();
	fs_policy_free (policy);
	g_string_free (swap_trace, TRUE);
	g_string_free (apply_trace, TRUE);
	g_unsetenv ("STOCKFW_APPLIED_FILE");
	g_unsetenv ("STOCKFW_AUDIT_FILE");
	remove (file);
	remove (audit_file);
	g_free (file);
	g_free (audit_file);
	g_free (dir);
}

/* --- the settings table (Preferences, D3 D6 D8) ----------------------
 * One key/type/default table in fs-prefs.c.  Pinned here: a fresh
 * FsSettings, an unset key and the first-run defaults all agree with
 * it; every reader in src/ that still passes a literal fallback for a
 * table key passes the table's (the source is scanned, so a consumer
 * that drifts fails here, not on a user's machine); an unreadable
 * settings file is kept before defaults overwrite it; and the edit
 * copy writes only what changed and may be written. */

typedef struct
{
	const gchar *key;
	gsize        offset;
} SettingsField;

#define SF(key, field) { key, G_STRUCT_OFFSET (FsSettings, field) }

static const SettingsField settings_fields[] = {
	SF (FS_PREFS_FW_NAT, nat),
	SF (FS_PREFS_FW_FILTER_ICMP, filter_icmp),
	SF (FS_PREFS_FW_DENY_PACKETS, deny_packets),
	SF (FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST, block_external_broadcast),
	SF (FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST, block_internal_broadcast),
	SF (FS_PREFS_FW_BLOCK_NON_ROUTABLES, block_non_routables),
	SF (FS_PREFS_FW_RESTRICTIVE_OUTBOUND, restrictive_outbound),
	SF (FS_PREFS_FW_LOG_ALLOWED, log_allowed),
	SF (FS_PREFS_FW_ICMP_ECHO_REQUEST, icmp_echo_request),
	SF (FS_PREFS_FW_ICMP_ECHO_REPLY, icmp_echo_reply),
	SF (FS_PREFS_FW_ICMP_TRACEROUTE, icmp_traceroute),
	SF (FS_PREFS_FW_ICMP_MSTRACEROUTE, icmp_mstraceroute),
	SF (FS_PREFS_FW_ICMP_UNREACHABLE, icmp_unreachable),
	SF (FS_PREFS_FW_ICMP_TIMESTAMPING, icmp_timestamping),
	SF (FS_PREFS_FW_ICMP_MASKING, icmp_masking),
	SF (FS_PREFS_FW_ICMP_REDIRECTION, icmp_redirection),
	SF (FS_PREFS_FW_ICMP_SOURCE_QUENCHES, icmp_source_quenches),
};

static gboolean
settings_field (const FsSettings *s, gsize offset)
{
	return G_STRUCT_MEMBER (gboolean, s, offset);
}

/* Every .c under dir, recursively. */
static void
collect_sources (const gchar *dir, GPtrArray *out)
{
	GDir *d = g_dir_open (dir, 0, NULL);
	const gchar *name;

	if (d == NULL)
		return;
	while ((name = g_dir_read_name (d)) != NULL) {
		gchar *path = g_build_filename (dir, name, NULL);

		if (g_file_test (path, G_FILE_TEST_IS_DIR))
			collect_sources (path, out);
		else if (g_str_has_suffix (name, ".c"))
			g_ptr_array_add (out, g_strdup (path));
		g_free (path);
	}
	g_dir_close (d);
}

static void
reset_prefs_file (const gchar *contents)
{
	g_file_set_contents (fs_prefs_path (), contents, -1, NULL);
	fs_prefs_load ();
}

static void test_prefs_table (void)
{
	guint n = 0;
	const FsPrefSpec *specs = fs_prefs_specs (&n);
	FsSettings *fresh, *loaded;
	guint mismatches = 0, literal_uses = 0, scanned = 0, unread = 0;
	GPtrArray *files;
	GRegex *literal;
	gchar *backup, *text = NULL;

	CHECK (n >= 25, "the settings table has every setting (%u rows)", n);

	/* Dead keys are not settings any more. */
	CHECK (fs_prefs_spec ("/apps/stockfw/firewall/tos/enable") == NULL &&
	       fs_prefs_spec ("/apps/stockfw/firewall/dhcp/enable_server") == NULL &&
	       fs_prefs_spec ("/apps/stockfw/client/start_firewall_on_dhcp") == NULL &&
	       fs_prefs_spec ("/apps/stockfw/client/first_run") == NULL,
	       "the table carries no ToS, DHCP, dial-out or first-run key");

	/* fs_settings_new() and an unset store agree with the table. */
	{
		gchar *prefs_dir = g_path_get_dirname (fs_prefs_path ());

		g_mkdir_with_parents (prefs_dir, 0700);
		g_free (prefs_dir);
	}
	reset_prefs_file ("");
	fresh = fs_settings_new ();
	loaded = fs_settings_new ();
	fs_settings_load_prefs (loaded);
	for (guint i = 0; i < G_N_ELEMENTS (settings_fields); i++) {
		const FsPrefSpec *spec = fs_prefs_spec (settings_fields[i].key);

		if (spec == NULL ||
		    settings_field (fresh, settings_fields[i].offset) !=
		    spec->bool_default ||
		    settings_field (loaded, settings_fields[i].offset) !=
		    spec->bool_default) {
			printf ("       mismatch: %s\n", settings_fields[i].key);
			mismatches++;
		}
	}
	CHECK (mismatches == 0 && fresh->ext_device == NULL &&
	       loaded->int_device == NULL,
	       "fs_settings_new() and unset keys give the table's defaults "
	       "(%u mismatches)", mismatches);
	fs_settings_free (fresh);
	fs_settings_free (loaded);

	/* D3: the one that drifted -- off unless set. */
	CHECK (!fs_prefs_bool (FS_PREFS_APPLY_POLICY_INSTANTLY) &&
	       !fs_prefs_spec (FS_PREFS_APPLY_POLICY_INSTANTLY)->bool_default,
	       "D3: \"apply policy changes immediately\" is off unless set");

	/* Every literal fallback for a table key in src/ matches. */
	files = g_ptr_array_new_with_free_func (g_free);
	collect_sources ("src", files);
	literal = g_regex_new ("fs_prefs_get_(bool|string)\\s*\\(\\s*"
	                       "(FS_PREFS_[A-Z0-9_]+)\\s*,\\s*([^)]*?)\\s*\\)",
	                       G_REGEX_MULTILINE, 0, NULL);
	for (guint f = 0; f < files->len; f++) {
		gchar *src = NULL;
		GMatchInfo *m = NULL;

		if (!g_file_get_contents (files->pdata[f], &src, NULL, NULL))
			continue;
		scanned++;
		g_regex_match (literal, src, 0, &m);
		while (g_match_info_matches (m)) {
			gchar *kind = g_match_info_fetch (m, 1);
			gchar *macro = g_match_info_fetch (m, 2);
			gchar *fallback = g_match_info_fetch (m, 3);

			for (guint i = 0; i < n; i++) {
				gboolean ok;

				if (g_strcmp0 (specs[i].name, macro) != 0)
					continue;
				literal_uses++;
				if (g_strcmp0 (kind, "bool") == 0)
					ok = g_strcmp0 (fallback,
					                specs[i].bool_default
					                ? "TRUE" : "FALSE") == 0;
				else
					ok = FALSE;   /* use fs_prefs_string() */
				if (!ok) {
					printf ("       %s: %s falls back to %s, "
					        "the table says %s\n",
					        (gchar *) files->pdata[f], macro,
					        fallback,
					        specs[i].type == FS_PREF_BOOL
					        ? (specs[i].bool_default
					           ? "TRUE" : "FALSE")
					        : specs[i].string_default);
					mismatches++;
				}
			}
			g_free (kind);
			g_free (macro);
			g_free (fallback);
			g_match_info_next (m, NULL);
		}
		g_match_info_free (m);

		g_free (src);
	}
	CHECK (scanned > 20 && mismatches == 0,
	       "every consumer in src/ falls back to the table's default "
	       "(%u files, %u literal reads of table keys, %u mismatches)",
	       scanned, literal_uses, mismatches);
	for (guint i = 0; i < n; i++) {
		gboolean read = FALSE;

		for (guint f = 0; f < files->len && !read; f++) {
			gchar *src = NULL;

			/* The table itself and the window that edits it
			 * are not readers. */
			if (g_str_has_suffix (files->pdata[f], "fs-prefs.c") ||
			    g_str_has_suffix (files->pdata[f],
			                      "fs-prefsdialog.c") ||
			    !g_file_get_contents (files->pdata[f], &src, NULL,
			                          NULL))
				continue;
			read = strstr (src, specs[i].name) != NULL;
			g_free (src);
		}
		if (!read) {
			printf ("       nothing reads %s\n", specs[i].name);
			unread++;
		}
	}
	CHECK (unread == 0, "every table setting is read by something "
	       "outside the settings code and the Preferences window");
	g_regex_unref (literal);
	g_ptr_array_unref (files);

	/* First-run defaults: every bool written, nothing dead. */
	reset_prefs_file ("");
	fs_prefs_set_defaults ();
	fs_prefs_load ();
	mismatches = 0;
	for (guint i = 0; i < n; i++)
		if (specs[i].type == FS_PREF_BOOL &&
		    (!fs_prefs_has_key (specs[i].key) ||
		     fs_prefs_get_bool (specs[i].key, !specs[i].bool_default) !=
		     specs[i].bool_default))
			mismatches++;
	CHECK (mismatches == 0 &&
	       !fs_prefs_has_key ("/apps/stockfw/firewall/tos/enable") &&
	       !fs_prefs_has_key ("/apps/stockfw/client/first_run"),
	       "first-run defaults are the table's, and no dead key is "
	       "written");

	/* ...and never overwrite what is there. */
	reset_prefs_file ("[firewall]\ndeny_packets=false\n");
	fs_prefs_set_defaults ();
	CHECK (!fs_prefs_bool (FS_PREFS_FW_DENY_PACKETS),
	       "defaults leave a stored value alone");

	/* D6: an unreadable file is kept before anything replaces it. */
	backup = fs_prefs_backup_path ();
	remove (backup);
	g_file_set_contents (fs_prefs_path (),
	                     "[client\nenable_tray_icon=maybe\n", -1, NULL);
	CHECK (!fs_prefs_load (), "D6: an unparsable settings file fails "
	       "to load");
	CHECK (g_file_get_contents (backup, &text, NULL, NULL) &&
	       g_strcmp0 (text, "[client\nenable_tray_icon=maybe\n") == 0,
	       "D6: and is kept, byte for byte, as %s", backup);
	g_free (text);
	text = NULL;
	fs_prefs_set_defaults ();
	CHECK (fs_prefs_load () &&
	       g_file_get_contents (backup, &text, NULL, NULL) &&
	       strstr (text, "maybe") != NULL,
	       "D6: the defaults written after it leave the kept copy alone");
	g_free (text);
	remove (backup);
	g_free (backup);

	/* D8: the edit copy writes only changed, writable values. */
	reset_prefs_file ("[firewall]\next_if=eth1\n");
	{
		FsPrefsEdit *edit = fs_prefs_edit_new ();
		gboolean firewall = TRUE;
		guint written;

		CHECK (g_strcmp0 (fs_prefs_edit_get_string (edit,
		                  FS_PREFS_FW_EXT_IF), "eth1") == 0 &&
		       !fs_prefs_edit_get_bool (edit,
		                                FS_PREFS_APPLY_POLICY_INSTANTLY),
		       "edit: the copy starts from the stored values and the "
		       "table's defaults");

		fs_prefs_edit_set_bool (edit, FS_PREFS_SKIP_REDUNDANT, TRUE);
		fs_prefs_edit_set_bool (edit, FS_PREFS_FW_DENY_PACKETS, FALSE);
		fs_prefs_edit_set_bool (edit, FS_PREFS_FW_NAT, FALSE); /* same */
		fs_prefs_edit_set_writable (edit, FS_PREFS_SKIP_REDUNDANT, TRUE);
		fs_prefs_edit_set_writable (edit, FS_PREFS_FW_NAT, TRUE);
		fs_prefs_edit_set_writable (edit, FS_PREFS_FW_EXT_IF, TRUE);
		/* deny_packets changed but stays unwritable: its control is
		 * not offered (Windows). */
		CHECK (fs_prefs_edit_n_changed (edit) == 2,
		       "edit: two values differ from the snapshot");
		CHECK (fs_prefs_edit_n_pending (edit) == 1,
		       "edit: one of them would be written (the footer's "
		       "count is what Save writes)");

		written = fs_prefs_edit_commit (edit, &firewall);
		CHECK (written == 1 && !firewall &&
		       fs_prefs_bool (FS_PREFS_SKIP_REDUNDANT) &&
		       !fs_prefs_has_key (FS_PREFS_FW_DENY_PACKETS) &&
		       !fs_prefs_has_key (FS_PREFS_FW_NAT) &&
		       !fs_prefs_has_key (FS_PREFS_APPLY_POLICY_INSTANTLY),
		       "D8: only the changed, writable value is written; an "
		       "unchanged one and one with no control are not");
		CHECK (fs_prefs_edit_commit (edit, NULL) == 0,
		       "edit: committing again writes nothing");

		fs_prefs_edit_set_writable (edit, FS_PREFS_FW_DENY_PACKETS, TRUE);
		written = fs_prefs_edit_commit (edit, &firewall);
		CHECK (written == 1 && firewall &&
		       !fs_prefs_bool (FS_PREFS_FW_DENY_PACKETS),
		       "edit: a firewall setting reports itself as one");
		fs_prefs_edit_free (edit);
	}

	reset_prefs_file ("");
}

/* --- settings saved but not applied ("Later") -------------------------
 * The journal records the firewall settings each successful apply went
 * out with.  While the saved ones differ, the policy gate applies the
 * whole set -- even for an unchanged policy, which it would otherwise
 * call "no change", and never through the narrow delta, which carries
 * no settings -- so "Later" really means "with the next policy
 * apply", on every backend. */
static void test_settings_pending (void)
{
	gchar *dir = g_build_filename (g_get_tmp_dir (),
	                               "stockfw-settings-pending-test", NULL);
	gchar *file = g_build_filename (dir, "applied.csv", NULL);
	gchar *audit_file = g_build_filename (dir, "audit.log", NULL);
	FsPolicy *policy;
	FsApplyOutcome *outcome;
	GError *error = NULL;
	GHashTable *recorded;
	gchar *contents = NULL;
	gint before_full;
	guint n = 0, firewall_rows = 0;
	const FsPrefSpec *specs = fs_prefs_specs (&n);

	for (guint i = 0; i < n; i++)
		if (specs[i].firewall)
			firewall_rows++;

	g_mkdir_with_parents (dir, 0700);
	remove (file);
	remove (audit_file);
	g_setenv ("STOCKFW_APPLIED_FILE", file, TRUE);
	g_setenv ("STOCKFW_AUDIT_FILE", audit_file, TRUE);
	{
		gchar *prefs_dir = g_path_get_dirname (fs_prefs_path ());

		g_mkdir_with_parents (prefs_dir, 0700);
		g_free (prefs_dir);
	}
	reset_prefs_file ("");

	fake_reset ();
	policy = gate_policy_two ();

	CHECK (!fs_apply_settings_pending () &&
	       fs_apply_journal_settings () == NULL,
	       "pending: with no journal nothing is pending (every apply is "
	       "whole then)");

	outcome = fs_policy_apply_safe (&fake_backend, policy, "pending test",
	                                NULL, &error);
	recorded = fs_apply_journal_settings ();
	CHECK (outcome->applied && fake_full_calls == 1 &&
	       !fs_apply_settings_pending () && recorded != NULL &&
	       g_hash_table_size (recorded) == firewall_rows &&
	       g_strcmp0 (g_hash_table_lookup (recorded,
	                  FS_PREFS_FW_ICMP_ECHO_REQUEST), "true") == 0 &&
	       g_strcmp0 (g_hash_table_lookup (recorded,
	                  FS_PREFS_FW_EXT_IF), "") == 0,
	       "pending: an apply records every firewall setting it went "
	       "out with (%u of %u)",
	       recorded != NULL ? g_hash_table_size (recorded) : 0,
	       firewall_rows);
	if (recorded != NULL)
		g_hash_table_unref (recorded);
	fs_apply_outcome_free (outcome);

	/* Saved in Preferences, answered "Later". */
	fs_prefs_set_bool (FS_PREFS_FW_ICMP_TIMESTAMPING, TRUE);
	fs_prefs_set_string (FS_PREFS_FW_EXT_IF, "eth0");
	CHECK (fs_apply_settings_pending (),
	       "pending: settings saved after the apply are pending");

	before_full = fake_full_calls;
	outcome = fs_policy_apply_safe (&fake_backend, policy, "pending test",
	                                NULL, &error);
	CHECK (outcome->applied && outcome->settings && !outcome->narrow &&
	       fake_full_calls == before_full + 1 && fake_delta_calls == 0 &&
	       !fs_apply_settings_pending (),
	       "pending: the next apply of an UNCHANGED policy is whole and "
	       "brings them in");
	contents = gate_audit_read ();
	CHECK (contents != NULL &&
	       strstr (contents, "| full, settings pending |") != NULL,
	       "pending: the audit line says the settings went with it");
	g_free (contents);
	fs_apply_outcome_free (outcome);

	before_full = fake_full_calls;
	outcome = fs_policy_apply_safe (&fake_backend, policy, "pending test",
	                                NULL, &error);
	CHECK (outcome->narrow && !outcome->settings &&
	       fake_full_calls == before_full && fake_delta_calls == 0,
	       "pending: once applied, an unchanged policy is \"no change\" "
	       "again");
	fs_apply_outcome_free (outcome);

	/* A changed policy while settings are pending: whole, never the
	 * delta (which carries no settings). */
	fs_prefs_set_bool (FS_PREFS_FW_ICMP_TIMESTAMPING, FALSE);
	{
		FsRule *rule = gate_rule (FS_RULE_OUTBOUND_DENY_TO, NULL, NULL,
		                          "198.51.100.10");

		fs_policy_add (policy, rule);
		fs_rule_free (rule);
	}
	before_full = fake_full_calls;
	outcome = fs_policy_apply_safe (&fake_backend, policy, "pending test",
	                                NULL, &error);
	CHECK (outcome->applied && outcome->settings &&
	       fake_full_calls == before_full + 1 && fake_delta_calls == 0,
	       "pending: a changed policy goes whole too, not as a delta");
	fs_apply_outcome_free (outcome);

	/* Without pending settings the same kind of edit is a delta. */
	{
		FsRule *rule = gate_rule (FS_RULE_OUTBOUND_DENY_TO, NULL, NULL,
		                          "198.51.100.11");

		fs_policy_add (policy, rule);
		fs_rule_free (rule);
	}
	before_full = fake_full_calls;
	outcome = fs_policy_apply_safe (&fake_backend, policy, "pending test",
	                                NULL, &error);
	CHECK (outcome->applied && !outcome->settings && outcome->narrow &&
	       fake_full_calls == before_full && fake_delta_calls == 1,
	       "pending: with nothing pending an edit still goes narrow");
	fs_apply_outcome_free (outcome);

	/* A value that needs escaping survives the record. */
	fs_prefs_set_string (FS_PREFS_FW_INT_IF, "odd=name\\with\nlines");
	outcome = fs_policy_apply_safe (&fake_backend, policy, "pending test",
	                                NULL, &error);
	recorded = fs_apply_journal_settings ();
	CHECK (outcome->applied && !fs_apply_settings_pending () &&
	       recorded != NULL &&
	       g_strcmp0 (g_hash_table_lookup (recorded, FS_PREFS_FW_INT_IF),
	                  "odd=name\\with\nlines") == 0,
	       "pending: a value with '=', '\\' and a newline is recorded "
	       "exactly");
	fs_apply_outcome_free (outcome);

	/* The record rebuilds the settings that were on the firewall. */
	{
		FsSettings *was = fs_settings_new ();

		fs_settings_load_values (was, recorded);
		CHECK (g_strcmp0 (was->ext_device, "eth0") == 0 &&
		       !was->icmp_timestamping && was->icmp_echo_request,
		       "pending: the record rebuilds the settings that went out");
		fs_settings_free (was);
	}
	g_hash_table_unref (recorded);

	/* A journal written before settings were recorded: unknown, so
	 * the next apply gives the firewall the lot. */
	{
		GString *legacy = g_string_new (NULL);
		gchar **lines;

		g_file_get_contents (file, &contents, NULL, NULL);
		lines = g_strsplit (contents, "\n", -1);
		for (guint i = 0; lines[i] != NULL; i++)
			if (!g_str_has_prefix (lines[i], "# setting "))
				g_string_append_printf (legacy, "%s\n", lines[i]);
		g_file_set_contents (file, legacy->str, -1, NULL);
		g_strfreev (lines);
		g_string_free (legacy, TRUE);
		g_free (contents);
		contents = NULL;
	}
	CHECK (fs_apply_journal_settings () == NULL &&
	       fs_apply_settings_pending (),
	       "pending: a journal with no settings record counts as pending");

	g_clear_error (&error);
	fake_reset ();
	fs_policy_free (policy);
	reset_prefs_file ("");
	g_unsetenv ("STOCKFW_APPLIED_FILE");
	g_unsetenv ("STOCKFW_AUDIT_FILE");
	remove (file);
	remove (audit_file);
	g_free (file);
	g_free (audit_file);
	g_free (dir);
}

/* --- the settings plan ------------------------------------------------
 * fs-settings-plan.c maps the Firewall preferences onto portable rules
 * that the Windows backend executes.  Each mapping is pinned here: the
 * checkboxes, the original's quirks (traceroute is UDP 33434; the two
 * unconditional ICMP types; MS Traceroute subsuming host-unreachable),
 * the profile scoping that stands in for iptables' interface scoping,
 * and the naming contract the rule lifecycle depends on. */

static const FsSettingRule *
plan_find (FsSettingsPlan *plan, const gchar *name)
{
	for (guint i = 0; i < plan->rules->len; i++) {
		const FsSettingRule *r = g_ptr_array_index (plan->rules, i);

		if (g_strcmp0 (r->name, name) == 0)
			return r;
	}

	return NULL;
}

static FsSettings *
plan_settings_with (gboolean all_types_off)
{
	FsSettings *s = fs_settings_new ();

	/* Start every checkbox from a known state instead of trusting
	 * the constructor, so each check isolates one mapping. */
	s->block_external_broadcast = FALSE;
	s->block_internal_broadcast = FALSE;
	s->block_non_routables      = FALSE;

	if (all_types_off) {
		s->icmp_echo_request    = FALSE;
		s->icmp_echo_reply      = FALSE;
		s->icmp_traceroute      = FALSE;
		s->icmp_mstraceroute    = FALSE;
		s->icmp_unreachable     = FALSE;
		s->icmp_timestamping    = FALSE;
		s->icmp_masking         = FALSE;
		s->icmp_redirection     = FALSE;
		s->icmp_source_quenches = FALSE;
	}

	return s;
}

/* --- 1.0.7: the first apply after the rule translation changed --------
 *
 * A machine upgraded from 1.0.6 carries the old translation's rules
 * (allow DNS = allow everything) and a journal whose rows equal the
 * policy.  A delta computed from those rows finds nothing to change,
 * so the gate must take the full apply, which clears every StockFW
 * rule and writes the new set.  And a row the translation refuses must
 * never let an apply report success. */

static void test_apply_translation_upgrade (void)
{
	gchar *dir = g_build_filename (g_get_tmp_dir (),
	                               "stockfw-upgrade-test", NULL);
	gchar *file = g_build_filename (dir, "applied.csv", NULL);
	gchar *audit_file = g_build_filename (dir, "audit.log", NULL);
	FsPolicy *policy = gate_policy_two ();
	FsApplyOutcome *outcome;
	GError *error = NULL;
	GString *old_journal;
	gchar *contents = NULL;
	FsRule *rule;
	FsPolicyDelta *delta;

	g_mkdir_with_parents (dir, 0700);
	remove (file);
	remove (audit_file);
	g_setenv ("STOCKFW_APPLIED_FILE", file, TRUE);
	g_setenv ("STOCKFW_AUDIT_FILE", audit_file, TRUE);
	fake_reset ();

	/* The journal exactly as 1.0.6 wrote it: the same header and
	 * rows, without the translation line. */
	CHECK (fs_apply_journal_save (policy, NULL), "journal written");
	g_file_get_contents (file, &contents, NULL, NULL);
	old_journal = g_string_new (NULL);
	{
		gchar **lines = g_strsplit (contents != NULL ? contents : "",
		                            "\n", -1);

		for (guint i = 0; lines[i] != NULL; i++) {
			if (g_str_has_prefix (lines[i], "# rules translation"))
				continue;
			if (*lines[i] != '\0')
				g_string_append_printf (old_journal, "%s\n",
				                        lines[i]);
		}
		g_strfreev (lines);
	}
	g_free (contents);
	contents = NULL;
	CHECK (g_str_has_prefix (old_journal->str,
	                         "# StockFW applied policy journal v1\n") &&
	       strstr (old_journal->str, "translation") == NULL,
	       "the stand-in 1.0.6 journal has no translation line");
	g_file_set_contents (file, old_journal->str, -1, NULL);
	g_string_free (old_journal, TRUE);

	{
		FsPolicy *loaded = fs_policy_new ();

		CHECK (fs_apply_journal_load (loaded, NULL) &&
		       gate_policy_total (loaded) == gate_policy_total (policy),
		       "a 1.0.6 journal still loads (it is the rollback "
		       "target)");
		fs_policy_free (loaded);
	}

	outcome = fs_policy_apply_safe (&fake_backend, policy, "upgrade test",
	                                NULL, &error);
	CHECK (outcome->result == FS_APPLY_OK && outcome->applied &&
	       !outcome->narrow,
	       "upgrade: an unchanged policy over a 1.0.6 journal is NOT "
	       "\"no change\"");
	CHECK (fake_full_calls == 1 && fake_delta_calls == 0,
	       "upgrade: the whole set is replaced (full %d, narrow %d)",
	       fake_full_calls, fake_delta_calls);
	g_clear_error (&error);
	fs_apply_outcome_free (outcome);

	g_file_get_contents (file, &contents, NULL, NULL);
	CHECK (contents != NULL &&
	       strstr (contents, "# rules translation 2\n") != NULL,
	       "the journal now records the translation that wrote the "
	       "rules");
	g_free (contents);
	contents = gate_audit_read ();
	CHECK (contents != NULL &&
	       strstr (contents, "full (rule translation upgrade)") != NULL,
	       "the audit line says why the apply was a full one");
	g_free (contents);

	/* Once upgraded, the narrow path is back: no change is no work. */
	fake_reset ();
	outcome = fs_policy_apply_safe (&fake_backend, policy, "upgrade test",
	                                NULL, &error);
	CHECK (outcome->applied && outcome->narrow &&
	       fake_full_calls == 0 && fake_delta_calls == 0,
	       "after the upgrade apply, an unchanged policy touches "
	       "nothing");
	g_clear_error (&error);
	fs_apply_outcome_free (outcome);

	/* A journal naming another translation (a newer one, or a
	 * garbled number) is treated the same way. */
	g_file_get_contents (file, &contents, NULL, NULL);
	{
		gchar **parts = g_strsplit (contents, "# rules translation 2\n",
		                            2);
		gchar *odd = g_strjoinv ("# rules translation x\n", parts);

		g_file_set_contents (file, odd, -1, NULL);
		g_free (odd);
		g_strfreev (parts);
	}
	g_free (contents);
	fake_reset ();
	outcome = fs_policy_apply_safe (&fake_backend, policy, "upgrade test",
	                                NULL, &error);
	CHECK (outcome->applied && fake_full_calls == 1 &&
	       fake_delta_calls == 0,
	       "an unreadable translation line also means a full apply");
	g_clear_error (&error);
	fs_apply_outcome_free (outcome);

	/* --- a refused row ---------------------------------------------- */
	rule = gate_rule (FS_RULE_INBOUND_ALLOW_SERVICE, "Custom", "0",
	                  FS_TARGET_ANY);
	{
		FsPolicy *with_bad = gate_policy_copy (policy);

		fs_policy_add (with_bad, rule);

		delta = fs_policy_delta (policy, with_bad);
		CHECK (delta->refused == 1 && !delta->empty &&
		       delta->add == NULL && delta->remove == NULL,
		       "a refused row makes the delta non-empty, with nothing "
		       "to add for it");
		fs_policy_delta_free (delta);

		delta = fs_policy_delta (NULL, with_bad);
		CHECK (delta->refused == 1 && !delta->empty,
		       "the same with no previous state");
		fs_policy_delta_free (delta);

		/* The gate must not call that "no change", nor hand it to the
		 * narrow path (which has no rule to carry it): the full apply
		 * is the one that reports refusals. */
		fake_reset ();
		outcome = fs_policy_apply_safe (&fake_backend, with_bad,
		                                "refusal test", NULL, &error);
		CHECK (fake_full_calls == 1 && fake_delta_calls == 0,
		       "a policy with a refused row goes the full way "
		       "(full %d, narrow %d)", fake_full_calls,
		       fake_delta_calls);
		g_clear_error (&error);
		fs_apply_outcome_free (outcome);
		fs_policy_free (with_bad);
	}
	fs_rule_free (rule);

	fake_reset ();
	g_unsetenv ("STOCKFW_APPLIED_FILE");
	g_unsetenv ("STOCKFW_AUDIT_FILE");
	remove (file);
	remove (audit_file);
	fs_policy_free (policy);
	g_free (file);
	g_free (audit_file);
	g_free (dir);
}

/* --- 1.0.7: the simulator reads the new rules --------------------------
 *
 * The What-If engine's Windows model answers from the same compiled
 * rules netsh gets, so the translation fixes show here too: DHCP is UDP
 * to remote ports 67-68, not "any outbound traffic", and an outbound
 * block sits on the remote port the traffic goes to.  The platform is
 * named, so this runs the same on either build. */

static void test_whatif_winrules (void)
{
	const FsWhatIfPlatform W = FS_WHATIF_WINDOWS_BLOCK_WINS;
	FsPolicy *policy = fs_policy_new ();
	FsWhatIfResult *r;
	const FsWhatIfAnswer *a;
	FsRule *rule;

	rule = gate_rule (FS_RULE_OUTBOUND_ALLOW_SERVICE, "DHCP", "67-68",
	                  FS_TARGET_ANY);
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	r = whatif_ask (W, policy, "outbound tcp to 203.0.113.5 port 22");
	a = whatif_answer (r);
	CHECK (a != NULL && (a->rule == NULL || strstr (a->rule, "DHCP") == NULL),
	       "\"Allow DHCP (outbound)\" does not decide outbound TCP 22 "
	       "(decided by: %s)", a != NULL && a->rule ? a->rule : "(default)");
	fs_whatif_result_free (r);

	r = whatif_ask (W, policy, "outbound tcp to 203.0.113.5 port 67");
	a = whatif_answer (r);
	CHECK (a != NULL && (a->rule == NULL || strstr (a->rule, "DHCP") == NULL),
	       "nor outbound TCP 67: DHCP is UDP (decided by: %s)",
	       a != NULL && a->rule ? a->rule : "(default)");
	fs_whatif_result_free (r);

	r = whatif_ask (W, policy, "outbound udp to 203.0.113.5 port 68");
	a = whatif_answer (r);
	CHECK (r->verdict == FS_WHATIF_ALLOWED && a != NULL && a->rule != NULL &&
	       strstr (a->rule, "DHCP") != NULL &&
	       a->origin == FS_WHATIF_ORIGIN_POLICY &&
	       a->policy_kind == FS_RULE_OUTBOUND_ALLOW_SERVICE &&
	       a->policy_index == 0,
	       "but outbound UDP 68 is the DHCP rule, row 0 (%s)",
	       a != NULL ? a->reason : "(none)");
	fs_whatif_result_free (r);

	/* An outbound block on SMTP: the traffic goes TO port 25. */
	rule = gate_rule (FS_RULE_OUTBOUND_DENY_SERVICE, "SMTP", "25",
	                  FS_TARGET_ANY);
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	r = whatif_ask (W, policy, "outbound tcp to 198.51.100.25 port 25");
	a = whatif_answer (r);
	CHECK (r->verdict == FS_WHATIF_BLOCKED && a != NULL && a->rule != NULL &&
	       strstr (a->rule, "SMTP") != NULL,
	       "an outbound SMTP block matches remote port 25 (%s)",
	       a != NULL ? a->reason : "(none)");
	fs_whatif_result_free (r);

	r = whatif_ask (W, policy, "outbound tcp to 198.51.100.25 port 587");
	CHECK (r->verdict == FS_WHATIF_ALLOWED,
	       "and it does not block another port");
	fs_whatif_result_free (r);

	/* "Allow DNS (inbound)" opens DNS, not every inbound port. */
	fs_policy_clear (policy);
	rule = gate_rule (FS_RULE_INBOUND_ALLOW_SERVICE, "DNS", "53",
	                  FS_TARGET_ANY);
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	r = whatif_ask (W, policy, "inbound tcp port 3389 from 203.0.113.5");
	CHECK (r->verdict == FS_WHATIF_BLOCKED,
	       "\"Allow DNS (inbound)\" does not allow inbound TCP 3389");
	fs_whatif_result_free (r);

	r = whatif_ask (W, policy, "inbound udp port 53 from 203.0.113.5");
	a = whatif_answer (r);
	CHECK (r->verdict == FS_WHATIF_ALLOWED && a != NULL && a->rule != NULL &&
	       strstr (a->rule, "(UDP)") != NULL,
	       "but it allows inbound UDP 53, by its UDP rule (%s)",
	       a != NULL && a->rule ? a->rule : "(none)");
	fs_whatif_result_free (r);

	fs_policy_free (policy);
}

/* --- 1.0.7 review: hostile input to the Windows translation ------------
 *
 * What a second pair of eyes found by attacking the translation: port
 * texts a fuzzer would try, a bare "TCP" with no port (the What-If's
 * "Create This Rule" for a portless probe), Samba's own ports written
 * in another order, a quote in a service name, and a block row that
 * cannot be compiled -- which must stop a whole-set apply before it
 * removes the block that is in force. */

/* [ review_policy ] -- one row, the way the Policy page stores it. */
static FsPolicy *
review_policy (FsRuleKind kind, const gchar *service, const gchar *port)
{
	FsPolicy *policy = fs_policy_new ();
	FsRule *rule = gate_rule (kind, service, port, FS_TARGET_ANY);

	fs_policy_add (policy, rule);
	fs_rule_free (rule);
	return policy;
}

static void test_fwrule_review (void)
{
	const FsRuleKind IN = FS_RULE_INBOUND_ALLOW_SERVICE;
	const FsRuleKind OUT = FS_RULE_OUTBOUND_ALLOW_SERVICE;
	const FsRuleKind DENY = FS_RULE_OUTBOUND_DENY_SERVICE;
	static const struct { const gchar *text; const gchar *spec; } cases[] = {
		{ " ", NULL },
		{ "   ,  , ", NULL },
		{ "80-", NULL },
		{ "-80", NULL },
		{ "80--90", NULL },
		{ "80::90", NULL },
		{ "80:70", NULL },
		{ "1:2:3", NULL },
		{ "65536", NULL },
		{ "0", NULL },
		{ "00000", NULL },
		{ "4294967376", NULL },          /* 2^32 + 80: no wrap to 80 */
		{ "8\xd9\xa0", NULL },           /* Arabic-Indic zero        */
		{ "\xef\xbc\x98\xef\xbc\x90", NULL }, /* fullwidth "80"       */
		{ "\xc2\xa0" "80", NULL },       /* no-break space is no sep */
		{ "80\n443", NULL },
		{ "1,,2", "1,2" },
		{ "80 , 443", "80,443" },
		{ "00080", "80" },
		{ "1-65535", "1-65535" },
		{ "65535:65535", "65535" },
	};
	FwExpect e_smb[] = { { FS_PROTO_TCP, "139,445", NULL, " (TCP)" },
	                     { FS_PROTO_UDP, "137-138", NULL, " (UDP)" } };

	for (guint i = 0; i < G_N_ELEMENTS (cases); i++) {
		gchar *spec = fs_fwrule_port_spec (cases[i].text);

		CHECK (g_strcmp0 (spec, cases[i].spec) == 0,
		       "review: hostile port text #%u -> %s (got %s)", i,
		       cases[i].spec != NULL ? cases[i].spec : "refused",
		       spec != NULL ? spec : "refused");
		g_free (spec);
	}

	/* Every port, listed one by one and then again: one spec, each
	 * port once, in the order written. */
	{
		GString *text = g_string_new (NULL);
		gchar *spec;

		for (guint pass = 0; pass < 2; pass++)
			for (guint p = 1; p <= 65535; p++)
				g_string_append_printf (text, "%u ", p);

		spec = fs_fwrule_port_spec (text->str);
		CHECK (spec != NULL && g_str_has_prefix (spec, "1,2,3,") &&
		       g_str_has_suffix (spec, ",65534,65535") &&
		       strstr (spec, ",1,") == NULL,
		       "review: a list of all 65535 ports twice compiles once "
		       "each (%" G_GSIZE_FORMAT " bytes)",
		       spec != NULL ? strlen (spec) : 0);
		CHECK (fs_fwrule_port_spec_covers (spec, 40000) &&
		       !fs_fwrule_port_spec_covers (spec, 0),
		       "review: and the simulator reads it whole");
		g_free (spec);
		g_string_free (text, TRUE);
	}

	/* A bare protocol is no service: with no port it is refused, as
	 * Linux writes no rule for it, never "every TCP port". */
	fw_golden (IN, "TCP", "", NULL, 0);
	fw_golden (OUT, "UDP", "", NULL, 0);
	fw_golden (IN, "tcp", "  ", NULL, 0);
	fw_golden (DENY, "TCP", "", NULL, 0);
	fw_golden (FS_RULE_INBOUND_FORWARD, "UDP", "", NULL, 0);

	/* What-If "Create This Rule" for a probe with no port: the engine
	 * offers no row at all, on either platform, and the safety check
	 * the Create button runs refuses the portless row the old
	 * simulator used to write -- which Windows would refuse too, rather
	 * than open every inbound TCP port. */
	{
		FsPolicy *empty = fs_policy_new ();
		FsWhatIfAction act;
		FsRule *rule;
		FsPolicy *policy = fs_policy_new ();
		GPtrArray *refused = NULL;
		GList *rules;
		gchar *why = NULL;

		for (gint plat = 0; plat < 2; plat++) {
			FsWhatIfResult *r = whatif_ask (
				plat ? FS_WHATIF_WINDOWS_BLOCK_WINS
				     : FS_WHATIF_LINUX_FIRST_MATCH,
				empty, "allow inbound tcp");
			gboolean any_create = FALSE;

			for (guint i = 0; i < r->answers->len; i++) {
				const FsWhatIfAnswer *a = g_ptr_array_index (r->answers, i);

				for (guint k = 0; k < a->actions->len; k++) {
					const FsWhatIfAction *x =
						g_ptr_array_index (a->actions, k);

					if (x->kind == FS_WHATIF_ACT_CREATE_ALLOW)
						any_create = TRUE;
				}
			}
			CHECK (r->verdict == FS_WHATIF_BLOCKED && !any_create,
			       "review: the What-If offers no row for a portless "
			       "probe (%s)", plat ? "Windows" : "Linux");
			fs_whatif_result_free (r);
		}

		rule = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);
		rule->service = g_strdup ("TCP");
		rule->port = g_strdup ("");
		rule->target = g_strdup (FS_TARGET_ANY);
		memset (&act, 0, sizeof act);
		act.kind = FS_WHATIF_ACT_CREATE_ALLOW;
		act.row = rule;
		CHECK (!fs_whatif_row_is_safe (&act, &why) && why != NULL,
		       "review: the Create check refuses a portless TCP row (%s)",
		       why != NULL ? why : "accepted");
		g_free (why);

		fs_policy_add (policy, rule);
		fs_rule_free (rule);
		rules = fs_fwrule_from_policy_checked (policy, &refused);
		CHECK (rules == NULL && refused->len == 1,
		       "review: and that row opens nothing on Windows -- not "
		       "every inbound TCP port (%u rules)",
		       g_list_length (rules));
		fs_fwrule_list_free (rules);
		g_ptr_array_unref (refused);
		fs_policy_free (policy);
		fs_policy_free (empty);
	}

	/* Samba's own ports in any order or spelling keep the split. */
	fw_golden (IN, "Samba (SMB)", "445 137-139", e_smb, 2);
	fw_golden (IN, "Samba (SMB)", "137:138,139 445", e_smb, 2);
	fw_golden (IN, "Samba (SMB)", "445,139,138,137", e_smb, 2);
	{
		/* A real change of ports still applies to both protocols. */
		FwExpect e[] = { { FS_PROTO_TCP, "137-139", NULL, " (TCP)" },
		                 { FS_PROTO_UDP, "137-139", NULL, " (UDP)" } };
		fw_golden (IN, "Samba (SMB)", "137-139", e, 2);
	}

	/* A quote in a service name must not reach netsh's command line,
	 * where it would end the name and start new arguments. */
	{
		FsPolicy *policy = review_policy (IN,
			"x\" dir=in action=allow protocol=any \"y", "80");
		GList *rules = fs_fwrule_from_policy (policy);
		gboolean clean = (rules != NULL);

		for (GList *l = rules; l != NULL; l = l->next) {
			gchar **argv = fs_fwrule_netsh_args (l->data);

			for (guint i = 0; argv != NULL && argv[i] != NULL; i++)
				if (strchr (argv[i], '"') != NULL)
					clean = FALSE;
			if (argv == NULL || g_strv_length (argv) != 12)
				clean = FALSE;
			g_strfreev (argv);
		}
		CHECK (clean,
		       "review: a quote in a service name never reaches netsh");
		fs_fwrule_list_free (rules);
		fs_policy_free (policy);
	}
	{
		gchar *name = fs_fwrule_netsh_name ("StockFW: Allow a\"b (inbound)");

		CHECK (g_strcmp0 (name, "StockFW- Allow a'b -inbound-") == 0,
		       "review: the netsh spelling of a quote is ' (got %s)",
		       name);
		g_free (name);
	}

	/* Block rows the translation refuses stop a whole-set apply;
	 * refused allows do not. */
	{
		FsPolicy *policy = review_policy (DENY, "SMTP", "25x");
		gchar *why = fs_fwrule_block_refusals (policy);

		CHECK (why != NULL && strstr (why, "SMTP") != NULL &&
		       strstr (why, "25x") != NULL,
		       "review: a block with a bad port is a block refusal "
		       "(%s)", why != NULL ? why : "none");
		g_free (why);
		fs_policy_free (policy);

		policy = review_policy (DENY, "Mystery", "");
		why = fs_fwrule_block_refusals (policy);
		CHECK (why != NULL,
		       "review: so is a block that names nothing to block");
		g_free (why);
		fs_policy_free (policy);

		policy = review_policy (IN, "SSH", "0");
		why = fs_fwrule_block_refusals (policy);
		CHECK (why == NULL,
		       "review: a refused allow is not a block refusal");
		g_free (why);
		fs_policy_free (policy);

		policy = review_policy (DENY, "SMTP", "25");
		why = fs_fwrule_block_refusals (policy);
		CHECK (why == NULL,
		       "review: a block that compiles is no refusal");
		g_free (why);
		fs_policy_free (policy);

		CHECK (fs_fwrule_block_refusals (NULL) == NULL,
		       "review: no policy, no refusal");
	}

	/* The narrow apply deletes by name, and netsh decides which names
	 * are the same: its spelling folds "a/b" and "a-b" together and
	 * ignores case.  A rule that shares a netsh name with a removed
	 * one has to be re-created, and the shared name deleted once. */
	{
		FsPolicy *before = fs_policy_new ();
		FsPolicy *after = fs_policy_new ();
		FsPolicyDelta *delta;
		FsRule *rule;

		rule = gate_rule (DENY, "a/b", "25", FS_TARGET_ANY);
		fs_policy_add (before, rule);
		fs_rule_free (rule);
		rule = gate_rule (DENY, "a-b", "26", FS_TARGET_ANY);
		fs_policy_add (before, rule);
		fs_policy_add (after, rule);
		fs_rule_free (rule);

		delta = fs_policy_delta (before, after);
		CHECK (g_list_length (delta->remove) == 2 &&
		       g_list_length (delta->repair) == 2 &&
		       delta->add == NULL,
		       "review: removing \"a/b\" re-creates \"a-b\", which netsh "
		       "deletes with it (remove %u, repair %u, add %u)",
		       g_list_length (delta->remove),
		       g_list_length (delta->repair),
		       g_list_length (delta->add));
		fs_policy_delta_free (delta);

		fs_policy_clear (after);
		delta = fs_policy_delta (before, after);
		CHECK (g_list_length (delta->remove) == 2,
		       "review: and removing both deletes each netsh name once "
		       "(%u deletes for 4 rules under 2 netsh names)",
		       g_list_length (delta->remove));
		fs_policy_delta_free (delta);

		/* Case: "SSH" and "ssh" are one name to netsh. */
		fs_policy_clear (before);
		fs_policy_clear (after);
		rule = gate_rule (IN, "SSH", "22", FS_TARGET_ANY);
		fs_policy_add (before, rule);
		fs_policy_add (after, rule);
		fs_rule_free (rule);
		rule = gate_rule (IN, "ssh", "2222", FS_TARGET_ANY);
		fs_policy_add (before, rule);
		fs_rule_free (rule);

		delta = fs_policy_delta (before, after);
		CHECK (g_list_length (delta->remove) == 1 &&
		       g_list_length (delta->repair) == 1,
		       "review: removing \"ssh\" re-creates \"SSH\" (remove %u, "
		       "repair %u)", g_list_length (delta->remove),
		       g_list_length (delta->repair));
		fs_policy_delta_free (delta);

		/* A both-protocol row that moves: both halves go, both come
		 * back, nothing else is touched. */
		fs_policy_clear (before);
		fs_policy_clear (after);
		rule = gate_rule (IN, "DNS", "53", FS_TARGET_ANY);
		fs_policy_add (before, rule);
		fs_rule_free (rule);
		rule = gate_rule (IN, "DNS", "5353", FS_TARGET_ANY);
		fs_policy_add (after, rule);
		fs_rule_free (rule);

		delta = fs_policy_delta (before, after);
		CHECK (g_list_length (delta->remove) == 2 &&
		       g_list_length (delta->add) == 2 &&
		       delta->repair == NULL,
		       "review: DNS moved to 5353 is two deletes and two adds");
		fs_policy_delta_free (delta);

		fs_policy_free (before);
		fs_policy_free (after);
	}

	/* The simulator's Windows model on lists and ranges: inside any
	 * element is covered, the gaps between them are not. */
	{
		FsPolicy *policy = review_policy (IN, "Game",
		                                  "7000-7010 7100,7200");
		static const struct { guint port; gboolean open; } probe[] = {
			{ 7000, TRUE }, { 7005, TRUE }, { 7010, TRUE },
			{ 7011, FALSE }, { 7099, FALSE }, { 7100, TRUE },
			{ 7150, FALSE }, { 7200, TRUE }, { 7201, FALSE },
		};

		for (guint i = 0; i < G_N_ELEMENTS (probe); i++) {
			gchar *line = g_strdup_printf ("inbound udp port %u from "
			                               "203.0.113.5", probe[i].port);
			FsWhatIfResult *r = whatif_ask (FS_WHATIF_WINDOWS_BLOCK_WINS,
			                                policy, line);

			CHECK (r->verdict == (probe[i].open ? FS_WHATIF_ALLOWED
			                                    : FS_WHATIF_BLOCKED),
			       "review: inbound UDP %u on \"7000-7010 7100,7200\" "
			       "is %s", probe[i].port,
			       probe[i].open ? "allowed" : "blocked");
			fs_whatif_result_free (r);
			g_free (line);
		}
		fs_policy_free (policy);
	}
}

static void test_settings_plan (void)
{
	FsSettings *s;
	FsSettingsPlan *plan;
	const FsSettingRule *r;

	/* --- filtering off collapses to one allow-all rule ------- */
	s = plan_settings_with (TRUE);
	s->filter_icmp = FALSE;
	plan = fs_settings_plan_new (s);
	CHECK (plan->rules->len == 1,
	       "filtering off: exactly one rule (%u)", plan->rules->len);
	r = plan_find (plan, "StockFW ICMP allow (filtering disabled)");
	CHECK (r != NULL && r->allow && r->proto == FS_SETPLAN_PROTO_ICMP &&
	       r->icmp == NULL,
	       "filtering off: one untyped ICMP allow");
	fs_settings_plan_free (plan);

	/* --- filtering on, nothing ticked: the two unconditional --- */
	s->filter_icmp = TRUE;
	plan = fs_settings_plan_new (s);
	CHECK (plan->rules->len == 2,
	       "filtering on, nothing ticked: the two unconditional rules "
	       "alone (%u)", plan->rules->len);
	r = plan_find (plan, "StockFW ICMP allow time exceeded");
	CHECK (r != NULL && g_strcmp0 (r->icmp, "11,any") == 0,
	       "time-exceeded is 11,any");
	r = plan_find (plan, "StockFW ICMP allow parameter problem");
	CHECK (r != NULL && g_strcmp0 (r->icmp, "12,any") == 0,
	       "parameter-problem is 12,any");
	fs_settings_plan_free (plan);

	/* --- the per-checkbox mappings --------------------------- */
	s->icmp_echo_request = TRUE;
	plan = fs_settings_plan_new (s);
	r = plan_find (plan, "StockFW ICMP allow echo request");
	CHECK (r != NULL && r->allow && g_strcmp0 (r->icmp, "8,any") == 0,
	       "echo request is 8,any");
	fs_settings_plan_free (plan);
	s->icmp_echo_request = FALSE;

	s->icmp_echo_reply = TRUE;
	plan = fs_settings_plan_new (s);
	r = plan_find (plan, "StockFW ICMP allow echo reply");
	CHECK (r != NULL && g_strcmp0 (r->icmp, "0,any") == 0,
	       "echo reply is 0,any");
	fs_settings_plan_free (plan);
	s->icmp_echo_reply = FALSE;

	/* The original's quirk: this checkbox never was ICMP. */
	s->icmp_traceroute = TRUE;
	plan = fs_settings_plan_new (s);
	r = plan_find (plan, "StockFW allow traceroute (UDP 33434)");
	CHECK (r != NULL && r->proto == FS_SETPLAN_PROTO_UDP &&
	       r->port == 33434 && r->icmp == NULL,
	       "traceroute is UDP 33434, not ICMP");
	CHECK (plan_find (plan, "StockFW ICMP allow traceroute") == NULL,
	       "no ICMP rule pretends to be traceroute");
	fs_settings_plan_free (plan);
	s->icmp_traceroute = FALSE;

	s->icmp_mstraceroute = TRUE;
	plan = fs_settings_plan_new (s);
	r = plan_find (plan, "StockFW ICMP allow destination unreachable");
	CHECK (r != NULL && g_strcmp0 (r->icmp, "3,any") == 0,
	       "MS Traceroute is destination-unreachable 3,any");
	fs_settings_plan_free (plan);
	s->icmp_mstraceroute = FALSE;

	s->icmp_unreachable = TRUE;
	plan = fs_settings_plan_new (s);
	r = plan_find (plan, "StockFW ICMP allow host unreachable");
	CHECK (r != NULL && g_strcmp0 (r->icmp, "3,1") == 0,
	       "Unreachable alone is the narrower 3,1");
	fs_settings_plan_free (plan);

	s->icmp_mstraceroute = TRUE;
	plan = fs_settings_plan_new (s);
	CHECK (plan_find (plan, "StockFW ICMP allow host unreachable") == NULL,
	       "3,1 is dropped when 3,any already covers it");
	fs_settings_plan_free (plan);
	s->icmp_mstraceroute = FALSE;
	s->icmp_unreachable = FALSE;

	s->icmp_timestamping = TRUE;
	plan = fs_settings_plan_new (s);
	r = plan_find (plan, "StockFW ICMP allow timestamp request");
	CHECK (r != NULL && g_strcmp0 (r->icmp, "13,any") == 0,
	       "timestamping: request is 13,any");
	r = plan_find (plan, "StockFW ICMP allow timestamp reply");
	CHECK (r != NULL && g_strcmp0 (r->icmp, "14,any") == 0,
	       "timestamping: reply is 14,any");
	fs_settings_plan_free (plan);
	s->icmp_timestamping = FALSE;

	s->icmp_masking = TRUE;
	plan = fs_settings_plan_new (s);
	r = plan_find (plan, "StockFW ICMP allow address mask request");
	CHECK (r != NULL && g_strcmp0 (r->icmp, "17,any") == 0,
	       "masking: request is 17,any");
	r = plan_find (plan, "StockFW ICMP allow address mask reply");
	CHECK (r != NULL && g_strcmp0 (r->icmp, "18,any") == 0,
	       "masking: reply is 18,any");
	fs_settings_plan_free (plan);
	s->icmp_masking = FALSE;

	s->icmp_redirection = TRUE;
	plan = fs_settings_plan_new (s);
	r = plan_find (plan, "StockFW ICMP allow redirect");
	CHECK (r != NULL && g_strcmp0 (r->icmp, "5,any") == 0,
	       "redirection is 5,any");
	fs_settings_plan_free (plan);
	s->icmp_redirection = FALSE;

	s->icmp_source_quenches = TRUE;
	plan = fs_settings_plan_new (s);
	r = plan_find (plan, "StockFW ICMP allow source quench");
	CHECK (r != NULL && g_strcmp0 (r->icmp, "4,any") == 0,
	       "source quench is 4,any");
	fs_settings_plan_free (plan);
	s->icmp_source_quenches = FALSE;

	/* --- the Advanced Options blocks ------------------------- */
	/* ACC-2: a Windows rule's remote address is the sender of an
	 * inbound packet, and nothing is sent from 255.255.255.255, so a
	 * broadcast "block" there blocked nothing.  Neither switch plans
	 * a rule, and no planned rule names the broadcast address. */
	s->block_external_broadcast = TRUE;
	s->block_internal_broadcast = TRUE;
	plan = fs_settings_plan_new (s);
	{
		gboolean bcast = FALSE;

		for (guint i = 0; i < plan->rules->len; i++) {
			const FsSettingRule *sr =
				g_ptr_array_index (plan->rules, i);

			if (sr->remote != NULL
			    && strstr (sr->remote, "255.255.255.255") != NULL)
				bcast = TRUE;
		}
		CHECK (!bcast,
		       "broadcast switches plan no rule: a remote of "
		       "255.255.255.255 matches no sender (ACC-2)");
	}
	fs_settings_plan_free (plan);
	s->block_external_broadcast = FALSE;
	s->block_internal_broadcast = FALSE;

	s->block_non_routables = TRUE;
	plan = fs_settings_plan_new (s);
	r = plan_find (plan,
	               "StockFW block reserved source addresses on "
	               "public networks");
	CHECK (r != NULL && !r->allow &&
	       r->profiles == FS_FWP_PROFILE_PUBLIC &&
	       g_strcmp0 (r->remote,
	                  "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,"
	                  "127.0.0.0/8") == 0,
	       "reserved sources: the same four ranges, public profile");
	fs_settings_plan_free (plan);
	fs_settings_free (s);

	/* --- the everything-on snapshot -------------------------- */
	s = plan_settings_with (TRUE);
	s->icmp_echo_request    = TRUE;
	s->icmp_echo_reply      = TRUE;
	s->icmp_traceroute      = TRUE;
	s->icmp_mstraceroute    = TRUE;
	s->icmp_unreachable     = TRUE;
	s->icmp_timestamping    = TRUE;
	s->icmp_masking         = TRUE;
	s->icmp_redirection     = TRUE;
	s->icmp_source_quenches = TRUE;
	s->block_external_broadcast = TRUE;
	s->block_internal_broadcast = TRUE;
	s->block_non_routables      = TRUE;
	plan = fs_settings_plan_new (s);
	/* 2 unconditional + echo req + echo reply + traceroute +
	 * mstraceroute (3,1 skipped as a subset) + 2 timestamping +
	 * 2 masking + redirect + quench = 12 ICMP/UDP, plus the
	 * reserved-source block (the broadcast switches plan nothing). */
	CHECK (plan->rules->len == 13,
	       "everything ticked plans 13 rules (%u)", plan->rules->len);

	/* Naming contract: the rule lifecycle owns everything starting
	 * with "StockFW", and policy rules always arrive as "StockFW-"
	 * after netsh_safe_name -- so the settings spelling must be the
	 * space form, and no name may carry a character netsh would have
	 * to rewrite (or the lifecycle could never delete it again). */
	{
		gboolean names_ok = TRUE;

		for (guint i = 0; i < plan->rules->len; i++) {
			const FsSettingRule *sr =
				g_ptr_array_index (plan->rules, i);

			if (!g_str_has_prefix (sr->name, "StockFW ") ||
			    strchr (sr->name, ':') != NULL ||
			    strchr (sr->name, ',') != NULL ||
			    strchr (sr->name, '"') != NULL) {
				names_ok = FALSE;
				break;
			}
		}

		CHECK (names_ok,
		       "every planned name is the netsh-safe StockFW space "
		       "spelling");
	}
	fs_settings_plan_free (plan);
	fs_settings_free (s);

	/* --- edges ---------------------------------------------- */
	plan = fs_settings_plan_new (NULL);
	CHECK (plan->rules->len == 0, "no settings: an empty plan");
	fs_settings_plan_free (plan);
	fs_settings_plan_free (NULL);
	s = fs_settings_new ();
	s->block_non_routables = FALSE;
	plan = fs_settings_plan_new (s);
	CHECK (plan_find (plan,
	                  "StockFW block reserved source addresses on "
	                  "public networks") == NULL,
	       "the reserved-source block follows its checkbox off");
	/* Defaults: every offered-page mapping that ships ticked. */
	r = plan_find (plan, "StockFW ICMP allow echo request");
	CHECK (r != NULL, "fresh settings keep ping working (echo request)");
	CHECK (plan_find (plan, "StockFW ICMP allow echo reply") != NULL,
	       "fresh settings keep pong working (echo reply)");
	fs_settings_plan_free (plan);
	fs_settings_free (s);

	CHECK (g_strcmp0 (fs_settings_plan_profile_name (
	                  FS_FWP_PROFILE_PRIVATE), "private") == 0 &&
	       g_strcmp0 (fs_settings_plan_profile_name (
	                  FS_FWP_PROFILE_PUBLIC), "public") == 0 &&
	       g_strcmp0 (fs_settings_plan_profile_name (
	                  FS_FWP_PROFILE_DOMAIN), "domain") == 0 &&
	       fs_settings_plan_profile_name (0) == NULL,
	       "profile bits render as their netsh names");
}

/* ---- 1.0.6: Linux text parsers (fs-netparse) ---------------------- */

/* Encode an address the way the kernel prints it into /proc/net/tcp:
 * each 32-bit word of the network-order bytes as a native %08X.  Built
 * here rather than pasted so the fixtures hold on either byte order. */
static gchar *
proc_hex_address (const guint8 *bytes, gsize len, guint port)
{
	GString *out = g_string_new (NULL);

	for (gsize w = 0; w < len / 4; w++) {
		guint32 word;

		memcpy (&word, bytes + w * 4, 4);
		g_string_append_printf (out, "%08X", word);
	}

	g_string_append_printf (out, ":%04X", port);
	return g_string_free (out, FALSE);
}

static void
clear_hit_fields (FsHit *h)
{
	g_free (h->time); g_free (h->direction); g_free (h->in);
	g_free (h->out); g_free (h->port); g_free (h->source);
	g_free (h->destination); g_free (h->length); g_free (h->tos);
	g_free (h->protocol); g_free (h->service);
	memset (h, 0, sizeof (*h));
}

static void test_netparse_log (void)
{
	FsHit hit = { 0 };
	GTimeZone *utc = g_time_zone_new_utc ();
	GDateTime *now = g_date_time_new (utc, 2026, 10, 11, 15, 0, 0);
	gboolean ok;

	/* The line the end-to-end test also uses: an inbound drop. */
	ok = fs_netparse_log_line (
		"Oct 11 14:30:00 kali kernel: [ 1234.567890] STOCKFW-DROP "
		"IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.0.2.10 "
		"DST=198.51.100.20 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF "
		"PROTO=TCP SPT=54321 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0",
		&hit, now);
	CHECK (ok, "netparse: a STOCKFW-DROP line is ours");
	CHECK (g_strcmp0 (hit.port, "443") == 0,
	       "netparse: port is the DESTINATION port (DPT=443), not the "
	       "ephemeral source port -- got %s", hit.port);
	CHECK (g_strcmp0 (hit.out, "") == 0 && g_strcmp0 (hit.in, "eth0") == 0,
	       "netparse: OUT stays the (empty) interface; DPT no longer "
	       "overwrites it -- in=[%s] out=[%s]", hit.in, hit.out);
	CHECK (g_strcmp0 (hit.source, "192.0.2.10") == 0 &&
	       g_strcmp0 (hit.destination, "198.51.100.20") == 0 &&
	       g_strcmp0 (hit.protocol, "TCP") == 0,
	       "netparse: src, dst, proto");
	CHECK (g_strcmp0 (hit.length, "60") == 0 &&
	       g_strcmp0 (hit.tos, "0x00") == 0,
	       "netparse: LEN and TOS fill the Length/ToS columns");
	CHECK (g_strcmp0 (hit.direction, "in") == 0,
	       "netparse: IN= set means inbound");
	CHECK (g_strcmp0 (hit.time, "2026-10-11T14:30:00Z") == 0,
	       "netparse: syslog stamp becomes the ISO UTC stamp the Events "
	       "page localises -- got %s", hit.time);
	CHECK (hit.service == NULL,
	       "netparse: service is left for the backend to name and mark");
	clear_hit_fields (&hit);

	/* REJECT prefix, RFC 3339 stamp with an offset, outbound, UDP
	 * with its second LEN= in the UDP header. */
	ok = fs_netparse_log_line (
		"2026-10-11T16:30:05.123456+02:00 kali kernel: STOCKFW-REJECT "
		"IN= OUT=wlan0 SRC=192.0.2.5 DST=203.0.113.9 LEN=76 TOS=0x10 "
		"PROTO=UDP SPT=40000 DPT=123 LEN=56",
		&hit, now);
	CHECK (ok, "netparse: a STOCKFW-REJECT line is ours too");
	CHECK (g_strcmp0 (hit.direction, "out") == 0 &&
	       g_strcmp0 (hit.out, "wlan0") == 0,
	       "netparse: only OUT= set means outbound");
	CHECK (g_strcmp0 (hit.time, "2026-10-11T14:30:05Z") == 0,
	       "netparse: an RFC 3339 offset is honoured (16:30+02:00 is "
	       "14:30 UTC) -- got %s", hit.time);
	CHECK (g_strcmp0 (hit.length, "76") == 0,
	       "netparse: the IP header's LEN wins over the UDP header's");
	clear_hit_fields (&hit);

	/* A December line read in early January belongs to last year. */
	{
		GDateTime *jan = g_date_time_new (utc, 2027, 1, 2, 9, 0, 0);

		ok = fs_netparse_log_line (
			"Dec 31 23:59:00 kali kernel: STOCKFW-DROP IN=eth0 OUT= "
			"SRC=192.0.2.1 DST=192.0.2.2 PROTO=ICMP TYPE=8 CODE=0",
			&hit, jan);
		CHECK (ok && g_strcmp0 (hit.time, "2026-12-31T23:59:00Z") == 0,
		       "netparse: syslog year rolls back across New Year -- "
		       "got %s", hit.time);
		CHECK (hit.port == NULL && g_strcmp0 (hit.protocol, "ICMP") == 0,
		       "netparse: ICMP has no port");
		clear_hit_fields (&hit);
		g_date_time_unref (jan);
	}

	/* A single-digit day is space-padded. */
	ok = fs_netparse_log_line (
		"Oct  1 08:00:00 kali kernel: STOCKFW-DROP IN=eth0 OUT= "
		"SRC=192.0.2.1 DST=192.0.2.2 PROTO=TCP SPT=1 DPT=22", &hit, now);
	CHECK (ok && g_strcmp0 (hit.time, "2026-10-01T08:00:00Z") == 0,
	       "netparse: \"Oct  1\" parses -- got %s", hit.time);
	clear_hit_fields (&hit);

	/* No stamp at all: the arrival time, never the raw line. */
	ok = fs_netparse_log_line (
		"[ 99.1]STOCKFW-DROP IN=eth0 OUT= SRC=192.0.2.1 DST=192.0.2.2 "
		"PROTO=TCP SPT=1 DPT=80", &hit, now);
	CHECK (ok && g_strcmp0 (hit.time, "2026-10-11T15:00:00Z") == 0,
	       "netparse: marker glued to the uptime still counts; no stamp "
	       "means the arrival time -- got %s", hit.time);
	clear_hit_fields (&hit);

	/* Foreign kernel noise. */
	memset (&hit, 0, sizeof (hit));
	ok = fs_netparse_log_line (
		"Oct 11 14:30:01 kali kernel: [UFW BLOCK] IN=eth0 OUT= "
		"SRC=192.0.2.99 DST=198.51.100.99 PROTO=UDP SPT=1 DPT=2",
		&hit, now);
	CHECK (!ok && hit.source == NULL && hit.port == NULL,
	       "netparse: a line without our marker is not an event and "
	       "leaves the hit untouched");

	/* A key repeated must not leak or keep the first value. */
	ok = fs_netparse_log_line (
		"Oct 11 14:30:00 h kernel: STOCKFW-DROP IN=eth0 OUT= "
		"SRC=192.0.2.1 SRC=192.0.2.7 DST=192.0.2.2 PROTO=TCP DPT=25",
		&hit, now);
	CHECK (ok && g_strcmp0 (hit.source, "192.0.2.7") == 0,
	       "netparse: a repeated key keeps its last value");
	clear_hit_fields (&hit);

	/* Naming: the destination port's service plus the marker. */
	ok = fs_netparse_log_line (
		"Oct 11 14:30:00 h kernel: STOCKFW-DROP IN=eth0 OUT= "
		"SRC=192.0.2.1 DST=192.0.2.2 PROTO=TCP SPT=40000 DPT=22",
		&hit, now);
	fs_netparse_name_blocked (&hit);
	CHECK (ok && g_strcmp0 (hit.service, "SSH [BLOCKED]") == 0 &&
	       fs_hit_is_blocked (&hit),
	       "netparse: a drop to port 22 is named \"SSH [BLOCKED]\" -- "
	       "got %s", hit.service);
	fs_netparse_clear_hit (&hit);
	CHECK (hit.service == NULL && hit.port == NULL,
	       "netparse: clear_hit frees and zeroes the fields");

	ok = fs_netparse_log_line (
		"Oct 11 14:30:00 h kernel: STOCKFW-DROP IN=eth0 OUT= "
		"SRC=192.0.2.1 DST=192.0.2.2 PROTO=ICMP TYPE=8", &hit, now);
	fs_netparse_name_blocked (&hit);
	CHECK (g_strcmp0 (hit.service, "ICMP [BLOCKED]") == 0,
	       "netparse: ICMP is named ICMP");
	fs_netparse_clear_hit (&hit);

	/* Any line's stamp, ours or not. */
	{
		gchar *t1 = fs_netparse_line_time (
			"Oct 11 14:29:00 kali kernel: usb 1-1: new device", now);
		gchar *t2 = fs_netparse_line_time ("no stamp here", now);

		CHECK (g_strcmp0 (t1, "2026-10-11T14:29:00Z") == 0 && t2 == NULL,
		       "netparse: line_time reads a foreign line's stamp, NULL "
		       "for none -- got %s", t1);
		g_free (t1);
		g_free (t2);
	}

	/* The shared marker test. */
	{
		FsHit a = { 0 }, b = { 0 };

		a.service = (gchar *) "HTTPS [BLOCKED]";
		b.service = (gchar *) "HTTPS";
		{
			gchar *na = fs_hit_service_name (&a);
			gchar *nb = fs_hit_service_name (&b);
			gchar *nn = fs_hit_service_name (NULL);

			CHECK (fs_hit_is_blocked (&a) && !fs_hit_is_blocked (&b) &&
			       g_strcmp0 (nb, b.service) == 0 &&
			       g_strcmp0 (nn, "") == 0 &&
			       strstr (na, "BLOCKED") == NULL &&
			       g_str_has_prefix (a.service, na) && na[0] != '\0',
			       "hit service name: the marker is cut, an allowed "
			       "hit's name is kept -- got \"%s\"", na);
			g_free (na); g_free (nb); g_free (nn);
		}
		CHECK (fs_hit_is_blocked (&a) && !fs_hit_is_blocked (&b) &&
		       !fs_hit_is_blocked (NULL),
		       "netparse: fs_hit_is_blocked keys on the shared marker");
	}

	g_date_time_unref (now);
	g_time_zone_unref (utc);
}

static void test_netparse_proc (void)
{
	const gchar *dev =
		"Inter-|   Receive                                                |  Transmit\n"
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
		"    lo:  269777     285    0    0    0     0          0         0   269777     285    0    0    0     0       0          0\n"
		"  eth0: 298846211   26340    0    6    0     0          0         0  8649880   16780    0    0    0     0       0          0\n"
		"wlan0:12 1 0 0 0 0 0 0 34 1 0 0 0 0 0 0\n"
		"  bad0: 1 2 3\n";
	GList *stats = fs_netparse_proc_dev (dev);
	FsIfaceStat *eth0, *wlan0;

	CHECK (g_list_length (stats) == 2,
	       "proc dev: two adapters (loopback left out, short row "
	       "rejected) -- got %u", g_list_length (stats));

	eth0  = stats ? stats->data : NULL;
	wlan0 = stats && stats->next ? stats->next->data : NULL;

	CHECK (eth0 != NULL && g_strcmp0 (eth0->device, "eth0") == 0 &&
	       eth0->received == G_GUINT64_CONSTANT (298846211) &&
	       eth0->sent == G_GUINT64_CONSTANT (8649880),
	       "proc dev: eth0 rx = column 1, tx = column 9");
	CHECK (wlan0 != NULL && g_strcmp0 (wlan0->device, "wlan0") == 0 &&
	       wlan0->received == 12 && wlan0->sent == 34,
	       "proc dev: an old-style row with no space after ':' parses");
	g_list_free_full (stats, (GDestroyNotify) fs_iface_stat_free);

	CHECK (fs_netparse_proc_dev (NULL) == NULL &&
	       fs_netparse_proc_dev ("") == NULL,
	       "proc dev: no text, no adapters");

	/* /proc/net/tcp: a LISTEN row, a real ESTABLISHED row taken from
	 * a live machine, a TIME_WAIT, and a garbage row. */
	{
		const guint8 lo[4]     = { 127, 0, 0, 1 };
		const guint8 any[4]    = { 0, 0, 0, 0 };
		const guint8 me[4]     = { 192, 0, 2, 2 };
		const guint8 peer[4]   = { 34, 149, 66, 165 };
		const guint8 client[4] = { 198, 51, 100, 7 };
		gchar *l_lo  = proc_hex_address (lo, 4, 631);
		gchar *r_any = proc_hex_address (any, 4, 0);
		gchar *l_me  = proc_hex_address (me, 4, 37054);
		gchar *r_pe  = proc_hex_address (peer, 4, 443);
		gchar *l_ssh = proc_hex_address (me, 4, 22);
		gchar *r_cl  = proc_hex_address (client, 4, 51000);
		gchar *text = g_strdup_printf (
			"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
			"   0: %s %s 0A 00000000:00000000 00:00000000 00000000     0        0 1079 1 0 100 0 0 10 0\n"
			"   1: %s %s 01 00000000:00000000 00:00000000 00000000  1000        0 10715 1 0 20 4 30 27 -1\n"
			"   2: %s %s 06 00000000:00000000 03:00000000 00000000     0        0 0 3 0\n"
			"   3: %s %s 01 00000000:00000000 00:00000000 00000000     0        0 22222 1 0\n"
			"   4: zz:zz yy:yy 01 0 0 0 0 0 0 0\n",
			l_lo, r_any, l_me, r_pe, l_me, r_pe, l_ssh, r_cl);
		GList *socks = fs_netparse_proc_tcp (text, FALSE);
		GList *conns;
		GHashTable *owners = g_hash_table_new_full (g_int64_hash,
		                                            g_int64_equal,
		                                            g_free, g_free);
		gint64 *key = g_new (gint64, 1);
		FsNetSocket *s1;
		FsConnection *c;

		*key = 10715;
		g_hash_table_insert (owners, key, g_strdup ("firefox"));

		CHECK (g_list_length (socks) == 4,
		       "proc tcp: four rows (header and garbage skipped) -- "
		       "got %u", g_list_length (socks));

		s1 = socks && socks->next ? socks->next->data : NULL;
		CHECK (s1 != NULL &&
		       g_strcmp0 (s1->local_addr, "192.0.2.2") == 0 &&
		       s1->local_port == 37054 &&
		       g_strcmp0 (s1->remote_addr, "34.149.66.165") == 0 &&
		       s1->remote_port == 443 && s1->state == 1 &&
		       s1->inode == 10715,
		       "proc tcp: addresses decoded from the kernel's native "
		       "words, ports from hex, state and inode");

		conns = fs_netparse_connections (socks, owners);
		CHECK (g_list_length (conns) == 2,
		       "connections: LISTEN and TIME_WAIT rows are not "
		       "connections -- got %u", g_list_length (conns));

		c = conns ? conns->data : NULL;
		CHECK (c != NULL && g_strcmp0 (c->destination, "34.149.66.165") == 0 &&
		       g_strcmp0 (c->port, "443") == 0 &&
		       g_strcmp0 (c->service, "HTTPS") == 0 &&
		       g_strcmp0 (c->program, "firefox") == 0 &&
		       g_strcmp0 (c->direction, "Outbound") == 0 &&
		       g_strcmp0 (c->protocol, "TCP") == 0,
		       "connections: remote port named, owner from the inode "
		       "map, a high local port to 443 is outbound");

		c = conns && conns->next ? conns->next->data : NULL;
		CHECK (c != NULL && g_strcmp0 (c->program, "?") == 0 &&
		       g_strcmp0 (c->direction, "Inbound") == 0 &&
		       g_strcmp0 (c->port, "22") == 0 &&
		       g_strcmp0 (c->service, "SSH") == 0,
		       "connections: an unreadable owner is \"?\", a client on "
		       "our port 22 is inbound and named by our port (SSH), "
		       "not its own -- got %s %s", c ? c->port : "-",
		       c ? c->service : "-");

		g_list_free_full (conns, (GDestroyNotify) fs_connection_free);
		g_list_free_full (socks, (GDestroyNotify) fs_net_socket_free);
		g_hash_table_unref (owners);
		g_free (text);
		g_free (l_lo); g_free (r_any); g_free (l_me); g_free (r_pe);
		g_free (l_ssh); g_free (r_cl);
	}

	/* /proc/net/tcp6: a plain IPv6 peer and an IPv4-mapped one. */
	{
		const guint8 v6_me[16]   = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		                             0, 0, 0, 0, 0, 0, 0, 0x02 };
		const guint8 v6_peer[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		                             0, 0, 0, 0, 0, 0, 0, 0x01 };
		const guint8 mapped[16]  = { 0, 0, 0, 0, 0, 0, 0, 0,
		                             0, 0, 0xff, 0xff, 192, 0, 2, 5 };
		gchar *a = proc_hex_address (v6_me, 16, 50000);
		gchar *b = proc_hex_address (v6_peer, 16, 993);
		gchar *m = proc_hex_address (mapped, 16, 8080);
		gchar *text = g_strdup_printf (
			"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
			"   0: %s %s 01 00000000:00000000 00:00000000 00000000  1000        0 555 1 0\n"
			"   1: %s %s 01 00000000:00000000 00:00000000 00000000  1000        0 556 1 0\n",
			a, b, a, m);
		GList *socks = fs_netparse_proc_tcp (text, TRUE);
		FsNetSocket *s0 = socks ? socks->data : NULL;
		FsNetSocket *s1 = socks && socks->next ? socks->next->data : NULL;

		CHECK (s0 != NULL && g_strcmp0 (s0->remote_addr, "2001:db8::1") == 0 &&
		       s0->remote_port == 993,
		       "proc tcp6: IPv6 peer rendered in its short form -- got %s",
		       s0 ? s0->remote_addr : "(none)");
		CHECK (s1 != NULL && g_strcmp0 (s1->remote_addr, "192.0.2.5") == 0,
		       "proc tcp6: an IPv4-mapped peer reads as IPv4 -- got %s",
		       s1 ? s1->remote_addr : "(none)");
		CHECK (fs_netparse_proc_tcp (text, FALSE) == NULL,
		       "proc tcp: tcp6 rows are refused by the IPv4 parser, not "
		       "misread");

		g_list_free_full (socks, (GDestroyNotify) fs_net_socket_free);
		g_free (text); g_free (a); g_free (b); g_free (m);
	}

	/* Two high ports either way: only the LISTEN row can tell which
	 * end accepted.  A local server on 8765 (the dashboard) and a
	 * client of it on the same machine. */
	{
		const guint8 lo[4] = { 127, 0, 0, 1 };
		gchar *srv  = proc_hex_address (lo, 4, 8765);
		gchar *cli  = proc_hex_address (lo, 4, 33262);
		gchar *any  = g_strdup ("00000000:0000");
		gchar *text = g_strdup_printf (
			"  sl  local_address rem_address   st\n"
			"   0: %s %s 0A 00000000:00000000 00:00000000 00000000 0 0 900 1 0\n"
			"   1: %s %s 01 00000000:00000000 00:00000000 00000000 0 0 901 1 0\n"
			"   2: %s %s 01 00000000:00000000 00:00000000 00000000 0 0 902 1 0\n",
			srv, any, srv, cli, cli, srv);
		GList *socks = fs_netparse_proc_tcp (text, FALSE);
		GList *conns = fs_netparse_connections (socks, NULL);
		FsConnection *accepted = conns ? conns->data : NULL;
		FsConnection *client = conns && conns->next ? conns->next->data : NULL;

		CHECK (g_list_length (conns) == 2 && accepted != NULL &&
		       g_strcmp0 (accepted->direction, "Inbound") == 0 &&
		       g_strcmp0 (accepted->port, "8765") == 0,
		       "connections: the accepted end of a listening port is "
		       "inbound on that port, though both ports are high -- "
		       "got %s %s", accepted ? accepted->direction : "-",
		       accepted ? accepted->port : "-");
		CHECK (client != NULL &&
		       g_strcmp0 (client->direction, "Outbound") == 0 &&
		       g_strcmp0 (client->port, "8765") == 0,
		       "connections: the client end of the same connection is "
		       "outbound to 8765");

		g_list_free_full (conns, (GDestroyNotify) fs_connection_free);
		g_list_free_full (socks, (GDestroyNotify) fs_net_socket_free);
		g_free (srv); g_free (cli); g_free (any); g_free (text);
	}

	CHECK (g_strcmp0 (fs_netparse_guess_direction (51000, 443), "Outbound") == 0 &&
	       g_strcmp0 (fs_netparse_guess_direction (22, 51000), "Inbound") == 0,
	       "connections: direction guess matches the Windows backend's");
}

/* ---- 1.0.6: activity time series (fs-activity) -------------------- */

static gint64 activity_test_now;

static gint64
activity_test_clock (gpointer data)
{
	(void) data;
	return activity_test_now;
}

/* --- connection sharing needs both devices ---------------------------
 * The Preferences window says sharing needs the Internet AND the local
 * device.  With either missing the generator must emit nothing of
 * router mode: no masquerade, no forwarding, no accept for the
 * internal device, no accept for everything leaving the Internet
 * device (which would let this computer's own traffic past restrictive
 * outbound), and no local-broadcast block that the window shows as
 * having no effect. */
static void test_sharing_needs_both_devices (void)
{
	static const struct
	{
		const gchar *ext, *intf;
		gboolean     acts;
	} cases[] = {
		{ "eth0", "eth1", TRUE  },
		{ "eth0", NULL,   FALSE },
		{ NULL,   "eth1", FALSE },
		{ NULL,   NULL,   FALSE },
	};
	FsPolicy *p = fs_policy_new ();

	for (guint i = 0; i < G_N_ELEMENTS (cases); i++) {
		FsSettings *s = fs_settings_new ();
		FsRestorePlan *plan;
		gchar *in, *out, *ctl;
		gboolean masq, out_accept, in_accept, bcast, fwd;
		GError *error = NULL;

		s->ext_device = g_strdup (cases[i].ext);
		s->int_device = g_strdup (cases[i].intf);
		s->nat = TRUE;
		s->restrictive_outbound = TRUE;
		s->block_internal_broadcast = TRUE;

		in = fs_script_generate_inbound (p, s);
		out = fs_script_generate_outbound (p, s);
		ctl = fs_script_generate_control (s);
		plan = fs_script_restore_plan (p, s, &error);

		masq = plan != NULL && plan->v4.nat != NULL &&
		       strstr (plan->v4.nat, "MASQUERADE") != NULL;
		out_accept = cases[i].ext != NULL &&
		       strstr (out, "-A OUTBOUND -o eth0 -j ACCEPT") != NULL;
		in_accept = cases[i].intf != NULL &&
		       strstr (in, "-A INBOUND -i eth1 -j ACCEPT") != NULL;
		bcast = strstr (in, "-d 255.255.255.255") != NULL;
		fwd = strstr (ctl, "ip_forward") != NULL ||
		      strstr (ctl, "MASQUERADE") != NULL;

		CHECK (plan != NULL &&
		       fs_settings_sharing (s) == cases[i].acts &&
		       masq == cases[i].acts && out_accept == cases[i].acts &&
		       in_accept == cases[i].acts && bcast == cases[i].acts &&
		       fwd == cases[i].acts,
		       "sharing with ext=%s int=%s %s (masquerade %d, outbound "
		       "accept %d, internal accept %d, local broadcast block "
		       "%d, control script %d)",
		       cases[i].ext ? cases[i].ext : "-",
		       cases[i].intf ? cases[i].intf : "-",
		       cases[i].acts ? "acts" : "emits nothing of router mode",
		       masq, out_accept, in_accept, bcast, fwd);

		g_clear_error (&error);
		fs_restore_plan_free (plan);
		g_free (in);
		g_free (out);
		g_free (ctl);
		fs_settings_free (s);
	}
	fs_policy_free (p);
}

/* Review T5: the CLI's blocklist text names the platform's firewall
 * and its way to get rights (fs-cli.h's FS_CLI_LIVE, FS_CLI_SUDO,
 * FS_CLI_RIGHTS) in fs-cli-cmds.c too, not only in fs-cli-intel.c.  The
 * CLI is built on Linux only, so the Windows words are read from the
 * source: no Linux-only literal where the macros belong. */
static gchar *
read_lf (const gchar *path)
{
	gchar *src = NULL;

	if (!g_file_get_contents (path, &src, NULL, NULL))
		return NULL;
	{
		gchar *w = src;
		for (const gchar *r = src; *r != '\0'; r++)
			if (*r != '\r')
				*w++ = *r;
		*w = '\0';
	}
	return src;
}

static void test_cli_platform_words (void)
{
	/* The commands are split over several files since the command
	 * registry (cli-plan.md WP-A): Stop and Start in fs-cli-policy.c,
	 * the root hint in fs-cli-cmds.c, the sudo prefix in fs-cli-out.c. */
	gchar *cmds = read_lf ("src/cli/fs-cli-cmds.c");
	gchar *policy = read_lf ("src/cli/fs-cli-policy.c");
	gchar *out_c = read_lf ("src/cli/fs-cli-out.c");
	gchar *intel = read_lf ("src/cli/fs-cli-intel.c");
	gchar *hdr = read_lf ("src/cli/fs-cli.h");
	const gchar *win;

	CHECK (cmds != NULL && policy != NULL && out_c != NULL &&
	       intel != NULL && hdr != NULL,
	       "cli words: the CLI sources are readable");
	if (cmds == NULL || policy == NULL || out_c == NULL || intel == NULL ||
	    hdr == NULL)
		goto out;
	win = strstr (hdr, "#elif defined G_OS_WIN32");
	CHECK (win != NULL &&
	       strstr (win, "#define FS_CLI_LIVE      \"Windows Firewall\"")
	       != NULL &&
	       strstr (win, "#define FS_CLI_SUDO      \"\"") != NULL &&
	       strstr (win, "opened as administrator") != NULL,
	       "cli words: fs-cli.h names Windows Firewall and an "
	       "administrator prompt for Windows");
	CHECK (strstr (policy, "\"the kernel does not hold them\"") == NULL &&
	       strstr (policy, "FS_CLI_LIVE \" does not hold \"") != NULL,
	       "cli words: Stop and Start's blocklist error in fs-cli-policy.c "
	       "names the platform's firewall (FS_CLI_LIVE)");
	CHECK (strstr (cmds, "\"run it with sudo, e.g.") == NULL &&
	       strstr (cmds, "FS_CLI_RIGHTS \", e.g. `%s'\"") != NULL &&
	       strstr (out_c, "const gchar *sudo = FS_CLI_SUDO;") != NULL,
	       "cli words: the root hint in fs-cli-cmds.c is the platform's "
	       "(FS_CLI_RIGHTS, and FS_CLI_SUDO in fs_cli_sudo_hint)");
	CHECK (strstr (intel, "#define FS_CLI_LIVE") == NULL,
	       "cli words: one definition, in fs-cli.h");
out:
	g_free (cmds);
	g_free (policy);
	g_free (out_c);
	g_free (intel);
	g_free (hdr);
}

/* --- "Start the firewall when StockFW opens" -------------------------
 * On Linux, start applies a policy.  At launch the shared policy is
 * created empty and only filled when the Policy page is built, and
 * Sentinel's expired blocks come out of it after that; starting any
 * earlier would take every block and forward down.  The window cannot
 * be built here, so the order in fs_app_activate is read from the
 * source: no direct backend start anywhere in fs-app.c, one start
 * through the start gate, in start_at_launch, called once, after both.
 * (tests/ui-startup-smoke.c drives the same start at runtime.) */
static void test_start_on_open_order (void)
{
	gchar *src = NULL;
	const gchar *body, *end, *page, *restore, *start, *gate, *call;
	guint direct = 0, gates = 0, calls = 0;

	CHECK (g_file_get_contents ("src/ui/fs-app.c", &src, NULL, NULL),
	       "start on open: fs-app.c is readable");
	if (src == NULL)
		return;
	/* A Windows checkout (core.autocrlf) has CRLF line ends; the
	 * patterns below match LF, so read the source as LF. */
	{
		gchar *w = src;
		for (const gchar *r = src; *r != '\0'; r++)
			if (*r != '\r')
				*w++ = *r;
		*w = '\0';
	}

	for (const gchar *p = src; (p = strstr (p, "->start (")) != NULL; p++)
		direct++;
	for (const gchar *p = src;
	     (p = strstr (p, "fs_firewall_start_")) != NULL; p++)
		gates++;
	for (const gchar *p = src;
	     (p = strstr (p, "start_at_launch (due);")) != NULL; p++)
		calls++;

	body = strstr (src, "\nfs_app_activate (GtkApplication *app)\n{");
	end = body != NULL ? strstr (body, "\n}\n") : NULL;
	start = strstr (src, "\nstart_at_launch (const FsPolicy *due)\n{");
	gate = start != NULL ? strstr (start, "fs_firewall_start_lifting (")
	                     : NULL;
	page = body != NULL ? strstr (body, "fs_policyview_page (policy)") : NULL;
	restore = body != NULL
		? strstr (body, "fs_copilot_autoblocks_restore (policy, due);")
		: NULL;
	call = body != NULL ? strstr (body, "start_at_launch (due);") : NULL;

	CHECK (direct == 0 && gates == 1 && calls == 1 && start != NULL &&
	       gate != NULL && gate < strstr (start + 1, "\n}\n"),
	       "start on open: the app's only start goes through the start "
	       "gate in start_at_launch, called once (%u direct start, "
	       "%u gate, %u call)", direct, gates, calls);
	CHECK (body != NULL && end != NULL && page != NULL &&
	       restore != NULL && call != NULL && call < end &&
	       page < call && restore < call,
	       "start on open: it runs after the Policy page loads the policy "
	       "and after Sentinel's expired blocks are restored out of it");
	g_free (src);
}

static void test_activity_series (void)
{
	FsActivity *a;
	/* Room for the widest window asked below (26 points). */
	guint64 values[32];
	guint covered[32];
	gint64 start;
	guint step;

	/* Start mid-slot: 10:00:05 on an arbitrary day. */
	activity_test_now = 1760000405;
	a = fs_activity_new (activity_test_clock, NULL);

	CHECK (fs_activity_started (a) == 1760000405,
	       "activity: starts at the clock's now");

	/* Nothing counted yet: the window has coverage only from the
	 * start, and points before it are no-data (covered 0), never a
	 * zero that reads as an idle firewall. */
	step = fs_activity_window (a, FS_ACTIVITY_ALLOWED, 60, 4, values,
	                           covered, &start);
	CHECK (step == 60 && start == 1760000220,
	       "activity: points align to the step (start %" G_GINT64_FORMAT
	       ", step %u)", start, step);
	CHECK (covered[0] == 0 && covered[1] == 0 && covered[2] == 0 &&
	       covered[3] == 1 && values[3] == 0,
	       "activity: before the start is no data; the current point "
	       "covers only the elapsed second (got %u %u %u %u)",
	       covered[0], covered[1], covered[2], covered[3]);

	/* Count across two minutes. */
	fs_activity_add (a, FS_ACTIVITY_ALLOWED, 3);
	fs_activity_add (a, FS_ACTIVITY_BLOCKED, 1);
	activity_test_now += 30;                      /* 10:00:35 */
	fs_activity_add (a, FS_ACTIVITY_ALLOWED, 2);
	activity_test_now += 60;                      /* 10:01:35 */
	fs_activity_add (a, FS_ACTIVITY_ALLOWED, 7);

	fs_activity_window (a, FS_ACTIVITY_ALLOWED, 60, 3, values, covered,
	                    &start);
	CHECK (values[1] == 5 && values[2] == 7,
	       "activity: counts land in their minute (got %" G_GUINT64_FORMAT
	       " %" G_GUINT64_FORMAT ")", values[1], values[2]);
	CHECK (covered[1] == 55 && covered[2] == 36,
	       "activity: the first minute is covered from the start (55 s), "
	       "the current one up to now (36 s) -- got %u %u",
	       covered[1], covered[2]);
	CHECK (fs_activity_total (a, FS_ACTIVITY_ALLOWED, 3600) == 12 &&
	       fs_activity_total (a, FS_ACTIVITY_BLOCKED, 3600) == 1,
	       "activity: totals over the last hour");

	/* Future times clamp to now; times before the start are dropped. */
	CHECK (fs_activity_add_at (a, FS_ACTIVITY_BLOCKED,
	                           activity_test_now + 500, 1) &&
	       fs_activity_total (a, FS_ACTIVITY_BLOCKED, 10) == 1,
	       "activity: a future stamp is counted now");
	CHECK (!fs_activity_add_at (a, FS_ACTIVITY_BLOCKED,
	                            fs_activity_started (a) - 1, 1),
	       "activity: a stamp before the start is refused");

	/* An unknown series reads as measured zeros, not as no data. */
	fs_activity_window (a, "never.counted", 60, 3, values, covered, NULL);
	CHECK (values[2] == 0 && covered[2] == 36,
	       "activity: an unknown series is zeros with real coverage");

	/* A day and a half later: the ring has wrapped.  Old counts are
	 * gone, the slots passed over read zero, and coverage stops at
	 * the ring's 24-hour floor. */
	activity_test_now += 36 * 3600;
	fs_activity_add (a, FS_ACTIVITY_ALLOWED, 4);
	CHECK (fs_activity_total (a, FS_ACTIVITY_ALLOWED, FS_ACTIVITY_SPAN_S)
	       == 4,
	       "activity: after 36 h only what is inside the 24 h ring "
	       "remains (got %" G_GUINT64_FORMAT ")",
	       fs_activity_total (a, FS_ACTIVITY_ALLOWED, FS_ACTIVITY_SPAN_S));
	fs_activity_window (a, FS_ACTIVITY_ALLOWED, 3600, 26, NULL, covered,
	                    NULL);
	CHECK (covered[0] == 0 && covered[1] < 3600 && covered[25] > 0,
	       "activity: a point older than the ring is no data, the one "
	       "the ring's floor cuts through is partial (got %u %u %u)",
	       covered[0], covered[1], covered[25]);
	CHECK (!fs_activity_add_at (a, FS_ACTIVITY_ALLOWED,
	                            activity_test_now - FS_ACTIVITY_SPAN_S - 20,
	                            1),
	       "activity: a stamp older than the ring is refused");

	/* The series cap: new names past it are refused, old ones count. */
	{
		guint accepted = 0;
		GList *names;

		for (guint i = 0; i < FS_ACTIVITY_MAX_SERIES + 5; i++) {
			gchar *name = g_strdup_printf ("test.%u", i);

			if (fs_activity_add (a, name, 1))
				accepted++;
			g_free (name);
		}

		names = fs_activity_series_names (a);

		CHECK (g_list_length (names) == FS_ACTIVITY_MAX_SERIES,
		       "activity: never more than %d series",
		       FS_ACTIVITY_MAX_SERIES);
		g_list_free (names);
		CHECK (fs_activity_add (a, FS_ACTIVITY_ALLOWED, 1),
		       "activity: an existing series still counts at the cap "
		       "(%u new names accepted)", accepted);
	}

	/* A backfilled structure covers from the archive's start, but
	 * never further back than the ring reaches. */
	{
		FsActivity *b = fs_activity_new_at (activity_test_clock, NULL,
		                                    activity_test_now - 3600);
		FsActivity *c = fs_activity_new_at (activity_test_clock, NULL,
		                                    activity_test_now - 90000);

		CHECK (fs_activity_started (b) == activity_test_now - 3600 &&
		       fs_activity_add_at (b, FS_ACTIVITY_BLOCKED,
		                           activity_test_now - 1800, 1) &&
		       fs_activity_total (b, FS_ACTIVITY_BLOCKED, 3600) == 1,
		       "activity: new_at backfills from an hour ago");
		CHECK (fs_activity_started (c) > activity_test_now - 90000 &&
		       fs_activity_started (c) >= activity_test_now -
		                                  FS_ACTIVITY_SPAN_S,
		       "activity: new_at is clamped to the ring's reach");
		fs_activity_free (b);
		fs_activity_free (c);
	}

	/* Steps for the four ranges the graphs offer. */
	CHECK (fs_activity_step_for (15 * 60, 120) == 10 &&
	       fs_activity_step_for (3600, 120) == 30 &&
	       fs_activity_step_for (6 * 3600, 120) == 300 &&
	       fs_activity_step_for (24 * 3600, 120) == 900,
	       "activity: step choice 15 min/1 h/6 h/24 h -> 10 s/30 s/5 min/15 min");
	CHECK (fs_activity_window (a, NULL, 25, 1, NULL, NULL, NULL) == 30,
	       "activity: a step is rounded up to whole slots");

	fs_activity_free (a);
}

static void test_activity_sampler (void)
{
	FsActivity *a;
	FsActivitySampler *s;
	FsIfaceStat eth = { 0 }, wlan = { 0 };
	GList *stats = NULL;
	gchar *eth_rx;

	activity_test_now = 1760100000;
	a = fs_activity_new (activity_test_clock, NULL);
	s = fs_activity_sampler_new (a);

	eth.device = (gchar *) "eth0";   eth.received = 1000; eth.sent = 500;
	wlan.device = (gchar *) "wlan0"; wlan.received = 10;  wlan.sent = 10;
	stats = g_list_append (stats, &eth);
	stats = g_list_append (stats, &wlan);

	CHECK (fs_activity_sampler_feed (s, stats) == 0 &&
	       fs_activity_total (a, FS_ACTIVITY_NET_RX, 60) == 0,
	       "sampler: the first sample is a baseline, not traffic");

	activity_test_now += 2;
	eth.received = 4000;  eth.sent = 700;
	wlan.received = 110;  wlan.sent = 15;
	CHECK (fs_activity_sampler_feed (s, stats) == 2,
	       "sampler: the second sample yields a delta per device");
	CHECK (fs_activity_total (a, FS_ACTIVITY_NET_RX, 60) == 3100 &&
	       fs_activity_total (a, FS_ACTIVITY_NET_TX, 60) == 205,
	       "sampler: totals are the sum of the device deltas");

	eth_rx = fs_activity_device_series ("eth0", FALSE);
	CHECK (g_strcmp0 (eth_rx, "net.eth0.rx") == 0 &&
	       fs_activity_total (a, eth_rx, 60) == 3000,
	       "sampler: per-device series");

	/* Counter reset: eth0 went backwards.  That is a new baseline,
	 * never 2^64 bytes of traffic. */
	activity_test_now += 2;
	eth.received = 50;  eth.sent = 20;
	wlan.received = 110; wlan.sent = 15;
	fs_activity_sampler_feed (s, stats);
	CHECK (fs_activity_total (a, eth_rx, 60) == 3000,
	       "sampler: a counter that went backwards adds nothing");

	activity_test_now += 2;
	eth.received = 150;
	fs_activity_sampler_feed (s, stats);
	CHECK (fs_activity_total (a, eth_rx, 60) == 3100,
	       "sampler: counting resumes from the reset baseline");

	/* A device that disappears and returns starts from a baseline. */
	stats = g_list_remove (stats, &wlan);
	activity_test_now += 2;
	fs_activity_sampler_feed (s, stats);
	stats = g_list_append (stats, &wlan);
	wlan.received = 99999;
	activity_test_now += 2;
	fs_activity_sampler_feed (s, stats);
	{
		gchar *wl = fs_activity_device_series ("wlan0", FALSE);

		CHECK (fs_activity_total (a, wl, 60) == 100,
		       "sampler: a returning device is re-baselined (got %"
		       G_GUINT64_FORMAT ")", fs_activity_total (a, wl, 60));
		g_free (wl);
	}

	g_free (eth_rx);
	g_list_free (stats);
	fs_activity_sampler_free (s);
	fs_activity_free (a);
}

static void test_json_writer (void)
{
	GString *out = g_string_new (NULL);

	fs_json_string (out, "a\"b\\c\n\t\x01</script>&");
	CHECK (strcmp (out->str,
	               "\"a\\\"b\\\\c\\n\\t\\u0001\\u003c/script\\u003e\\u0026\"") == 0,
	       "json: quotes, backslashes, control characters and <>& are "
	       "escaped -- got %s", out->str);

	g_string_truncate (out, 0);
	fs_json_string (out, "caf\xc3\xa9 \xff");
	CHECK (g_utf8_validate (out->str, -1, NULL) &&
	       strstr (out->str, "caf\xc3\xa9") != NULL,
	       "json: valid UTF-8 kept, an invalid byte repaired -- got %s",
	       out->str);

	g_string_truncate (out, 0);
	g_string_append_c (out, '{');
	fs_json_kv_str (out, "s", NULL);
	g_string_append_c (out, ',');
	fs_json_kv_int (out, "i", -5);
	g_string_append_c (out, ',');
	fs_json_kv_uint (out, "u", G_GUINT64_CONSTANT (18446744073709551615));
	g_string_append_c (out, ',');
	fs_json_kv_bool (out, "b", TRUE);
	g_string_append_c (out, '}');
	CHECK (strcmp (out->str,
	               "{\"s\":null,\"i\":-5,\"u\":18446744073709551615,\"b\":true}")
	       == 0, "json: key/value helpers -- got %s", out->str);

	g_string_free (out, TRUE);
}

/* 1.0.7 event capture: the /dev/kmsg record converter.  The ring buffer
 * is the only kernel log on hosts without rsyslog or journald (WSL,
 * containers), so this is the line every Linux event there goes
 * through. */
static void test_netparse_kmsg (void)
{
	/* Clocks: real 2026-11-02T10:00:00Z, monotonic 1000 s since boot. */
	const gint64 real = (gint64) 1793613600 * G_USEC_PER_SEC;
	const gint64 mono = (gint64) 1000 * G_USEC_PER_SEC;
	const gchar *rec;
	gchar *line;
	FsHit hit = { 0 };

	/* A kernel record stamped 400 s after boot: 600 s before "now". */
	rec = "4,1234,400000000,-;STOCKFW-DROP IN=eth0 OUT= SRC=192.0.2.5 "
	      "DST=198.51.100.7 LEN=60 PROTO=TCP SPT=40000 DPT=22\n"
	      " SUBSYSTEM=net\n DEVICE=n2\n";
	line = fs_netparse_kmsg_line (rec, strlen (rec), real, mono);
	CHECK (line != NULL &&
	       g_str_has_prefix (line, "2026-11-02T09:50:00Z STOCKFW-DROP "),
	       "kmsg record becomes \"<its own UTC time> <message>\" "
	       "(boot offset 400 s, now 1000 s -> 10 minutes ago) -- got [%s]",
	       line ? line : "(null)");
	CHECK (line != NULL && strstr (line, "SUBSYSTEM") == NULL &&
	       strchr (line, '\n') == NULL,
	       "continuation lines are not part of the message");
	CHECK (line != NULL && fs_netparse_log_line (line, &hit, NULL) &&
	       g_strcmp0 (hit.time, "2026-11-02T09:50:00Z") == 0 &&
	       g_strcmp0 (hit.source, "192.0.2.5") == 0 &&
	       g_strcmp0 (hit.port, "22") == 0,
	       "and the event parser reads it with the record's time");
	fs_netparse_clear_hit (&hit);
	g_free (line);

	/* Teeth: user space can write to /dev/kmsg.  The kernel gives such
	 * records the user facility (prio >> 3 == 1), whatever "<N>" the
	 * writer asked for, so the facility is what proves a line came
	 * from the kernel's LOG target. */
	rec = "12,1235,400000001,-;STOCKFW-DROP IN=eth0 OUT= SRC=203.0.113.9 "
	      "DST=198.51.100.7 PROTO=TCP SPT=1 DPT=22\n";
	line = fs_netparse_kmsg_line (rec, strlen (rec), real, mono);
	CHECK (line == NULL,
	       "a user-facility record (prio 12 = user.warning) is refused: "
	       "a local program cannot forge a firewall event");
	g_free (line);

	rec = "30,1236,400000002,-;STOCKFW-ALLOW something\n";
	line = fs_netparse_kmsg_line (rec, strlen (rec), real, mono);
	CHECK (line == NULL, "so is a daemon-facility record (prio 30)");
	g_free (line);

	/* Malformed records: never read past the buffer, never guess. */
	{
		const gchar *bad[] = {
			"",                                  /* empty            */
			"4,1,2",                             /* no ';'           */
			"x,1,2,-;STOCKFW-DROP SRC=1.2.3.4",  /* prio not digits  */
			"4,,2,-;STOCKFW-DROP SRC=1.2.3.4",   /* empty seq        */
			"4,1,2x,-;STOCKFW-DROP SRC=1.2.3.4", /* junk in usec     */
			"4,1,2,-;",                          /* empty message    */
			"4,1,2,-;\n SUBSYSTEM=net",          /* empty, then more */
			"-4,1,2,-;STOCKFW-DROP SRC=1.2.3.4", /* negative prio    */
		};
		guint refused = 0;

		for (guint i = 0; i < G_N_ELEMENTS (bad); i++) {
			line = fs_netparse_kmsg_line (bad[i], strlen (bad[i]),
			                              real, mono);
			if (line == NULL)
				refused++;
			g_free (line);
		}
		CHECK (refused == G_N_ELEMENTS (bad),
		       "every malformed record is refused (%u of %u)",
		       refused, (guint) G_N_ELEMENTS (bad));
	}

	/* Length is honoured: a record handed with a shorter length than
	 * its text ends where the length says. */
	rec = "6,9,1000000000,-;STOCKFW-DROP IN=eth0 OUT= SRC=192.0.2.8 "
	      "DST=198.51.100.7 PROTO=UDP SPT=1 DPT=53 TRAILING-JUNK";
	line = fs_netparse_kmsg_line (rec, strlen (rec) - strlen (" TRAILING-JUNK"),
	                              real, mono);
	CHECK (line != NULL && strstr (line, "TRAILING") == NULL &&
	       g_str_has_prefix (line, "2026-11-02T10:00:00Z "),
	       "the record length is honoured (no read past it), and a "
	       "record stamped now is stamped now");
	g_free (line);

	/* A record from "the future" (clocks raced) is stamped now, not
	 * after now. */
	rec = "6,10,1000500000,-;STOCKFW-DROP SRC=192.0.2.8 DST=1.1.1.1 "
	      "PROTO=UDP SPT=1 DPT=53";
	line = fs_netparse_kmsg_line (rec, strlen (rec), real, mono);
	CHECK (line != NULL && g_str_has_prefix (line, "2026-11-02T10:00:00Z "),
	       "a record newer than the monotonic clock is stamped now");
	g_free (line);
}

/* 1.0.7: which marker a line carries decides the verdict the Events
 * page shows.  Before, every Linux event was named blocked, so an
 * allowed connection would have been reported as a block. */
static void test_netparse_verdicts (void)
{
	const gchar *drop =
		"2026-11-02T10:00:00Z STOCKFW-DROP IN=eth0 OUT= "
		"SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP SPT=1 DPT=443";
	const gchar *rej =
		"Nov  2 10:00:00 host kernel: [12.3] STOCKFW-REJECT IN=eth0 "
		"OUT= SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP SPT=1 DPT=22";
	const gchar *allow =
		"2026-11-02T10:00:00Z STOCKFW-ALLOW IN= OUT=eth0 "
		"SRC=10.0.0.2 DST=198.51.100.1 PROTO=TCP SPT=40000 DPT=443";
	const gchar *foreign =
		"2026-11-02T10:00:00Z IN=eth0 OUT= SRC=192.0.2.1 "
		"DST=198.51.100.1 PROTO=TCP SPT=1 DPT=443";
	/* Two markers: the first one decides, the same one
	 * fs_netparse_log_line starts the packet fields from, so the
	 * verdict and the fields always describe the same log entry. */
	const gchar *twice =
		"2026-11-02T10:00:00Z STOCKFW-DROP IN=eth0 OUT= SRC=192.0.2.1 "
		"STOCKFW-ALLOW DST=198.51.100.1 PROTO=TCP SPT=1 DPT=443";
	FsHit hit = { 0 };

	CHECK (fs_netparse_log_verdict (drop) == FS_LOG_VERDICT_DROP,
	       "STOCKFW-DROP -> drop");
	CHECK (fs_netparse_log_verdict (rej) == FS_LOG_VERDICT_REJECT,
	       "STOCKFW-REJECT -> reject");
	CHECK (fs_netparse_log_verdict (allow) == FS_LOG_VERDICT_ALLOW,
	       "STOCKFW-ALLOW -> allow");
	CHECK (fs_netparse_log_verdict (foreign) == FS_LOG_VERDICT_NONE,
	       "no marker -> none");
	CHECK (fs_netparse_log_verdict (twice) == FS_LOG_VERDICT_DROP,
	       "with two markers the first one decides");
	CHECK (fs_netparse_log_verdict ("2026-11-02T10:00:00Z "
	                                "XSTOCKFW-ALLOWX SRC=1.2.3.4") ==
	       FS_LOG_VERDICT_NONE,
	       "a marker must end its word (no match inside other text)");

	CHECK (fs_netparse_log_line (allow, &hit, NULL),
	       "an STOCKFW-ALLOW line is an event");
	fs_netparse_name_by_verdict (&hit, fs_netparse_log_verdict (allow));
	CHECK (g_strcmp0 (hit.service, "HTTPS") == 0 && !fs_hit_is_blocked (&hit),
	       "an allowed line is named without the blocked marker (got %s)",
	       hit.service ? hit.service : "(null)");
	CHECK (g_strcmp0 (hit.direction, "out") == 0,
	       "and keeps its direction");
	fs_netparse_clear_hit (&hit);

	CHECK (fs_netparse_log_line (drop, &hit, NULL), "a drop line parses");
	fs_netparse_name_by_verdict (&hit, fs_netparse_log_verdict (drop));
	CHECK (g_strcmp0 (hit.service, "HTTPS" FS_HIT_BLOCKED_MARKER) == 0 &&
	       fs_hit_is_blocked (&hit),
	       "a drop line is named blocked (got %s)",
	       hit.service ? hit.service : "(null)");
	fs_netparse_clear_hit (&hit);

	CHECK (fs_netparse_log_line (rej, &hit, NULL), "a reject line parses");
	fs_netparse_name_by_verdict (&hit, fs_netparse_log_verdict (rej));
	CHECK (fs_hit_is_blocked (&hit) &&
	       g_strcmp0 (hit.service, "SSH" FS_HIT_BLOCKED_MARKER) == 0,
	       "a reject line is named blocked too");
	fs_netparse_clear_hit (&hit);

	/* NONE (a caller that could not tell) errs to blocked: a block
	 * shown as a block is never a lie about the firewall letting
	 * something through. */
	CHECK (fs_netparse_log_line (drop, &hit, NULL), "parse again");
	fs_netparse_name_by_verdict (&hit, FS_LOG_VERDICT_NONE);
	CHECK (fs_hit_is_blocked (&hit), "an unknown verdict is named blocked");
	fs_netparse_clear_hit (&hit);
}

/* 1.0.7 threat intel: the table logs "STOCKFW-TI <id> " (design 7).
 * Only fs_netparse_intel_line takes those lines, and only with an id
 * the engine could have written; the policy's parser never does, so a
 * reader that knows nothing of the lists (the CLI's event list) cannot
 * show one as a policy block. */
static void test_netparse_intel_line (void)
{
	const gchar *ti =
		"2026-11-02T10:00:00Z STOCKFW-TI spamhaus-drop IN=eth0 OUT= "
		"SRC=203.0.113.7 DST=198.51.100.1 LEN=60 PROTO=TCP SPT=4444 "
		"DPT=22";
	const gchar *ti_out =
		"Nov  2 10:00:00 host kernel: [99.1] STOCKFW-TI local-office IN= "
		"OUT=eth0 SRC=10.0.0.2 DST=203.0.113.9 PROTO=TCP SPT=40000 "
		"DPT=443";
	const gchar *bad_id =
		"2026-11-02T10:00:00Z STOCKFW-TI Bad;id IN=eth0 OUT= "
		"SRC=203.0.113.7 DST=198.51.100.1 PROTO=TCP DPT=22";
	const gchar *no_id =
		"2026-11-02T10:00:00Z STOCKFW-TI";
	const gchar *drop =
		"2026-11-02T10:00:00Z STOCKFW-DROP IN=eth0 OUT= "
		"SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP SPT=1 DPT=443";
	FsHit hit = { 0 };
	gchar *id = NULL;

	CHECK (fs_netparse_intel_line (ti, &hit, NULL, &id) &&
	       g_strcmp0 (id, "spamhaus-drop") == 0 &&
	       g_strcmp0 (hit.source, "203.0.113.7") == 0 &&
	       g_strcmp0 (hit.port, "22") == 0 &&
	       g_strcmp0 (hit.direction, "in") == 0 &&
	       g_strcmp0 (hit.time, "2026-11-02T10:00:00Z") == 0,
	       "intel line: the list's id and the packet's fields (id %s, "
	       "src %s)", id ? id : "(null)",
	       hit.source ? hit.source : "(null)");
	fs_netparse_clear_hit (&hit);
	g_clear_pointer (&id, g_free);

	CHECK (fs_netparse_intel_line (ti_out, &hit, NULL, &id) &&
	       g_strcmp0 (id, "local-office") == 0 &&
	       g_strcmp0 (hit.direction, "out") == 0 &&
	       g_strcmp0 (hit.destination, "203.0.113.9") == 0,
	       "intel line: an outbound block in a classic syslog line");
	fs_netparse_clear_hit (&hit);
	g_clear_pointer (&id, g_free);

	CHECK (!fs_netparse_intel_line (bad_id, &hit, NULL, &id) &&
	       id == NULL && hit.source == NULL,
	       "intel line: an id the engine could not have written is "
	       "not an event");
	CHECK (!fs_netparse_intel_line (no_id, &hit, NULL, &id) && id == NULL,
	       "intel line: a marker with nothing after it is not an event");
	CHECK (!fs_netparse_intel_line (drop, &hit, NULL, &id) && id == NULL,
	       "intel line: a policy line is not an intel line");
	CHECK (!fs_netparse_log_line (ti, &hit, NULL) && hit.source == NULL,
	       "the policy parser never takes an intel line");
	CHECK (fs_netparse_intel_line (ti, &hit, NULL, NULL),
	       "intel line: the id is optional for the caller");
	fs_netparse_clear_hit (&hit);
}

/* 1.0.7: allowed connections are logged (sampled) through ACCEPT_LOG,
 * and the Policy page's deny rows reach the kernel in permissive mode. */
static void test_script_accept_log (void)
{
	FsPolicy *policy = fs_policy_new ();
	FsSettings *settings = fs_settings_new ();
	FsRule *rule;
	gchar *in, *out;

	CHECK (settings->log_allowed,
	       "a fresh install logs allowed connections");

	rule = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);
	rule->service = g_strdup ("SSH");
	rule->port = g_strdup ("22");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	rule = fs_rule_new (FS_RULE_OUTBOUND_DENY_TO);
	rule->target = g_strdup ("203.0.113.50");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	in = fs_script_generate_inbound (policy, settings);
	out = fs_script_generate_outbound (policy, settings);

	CHECK (strstr (in, "$IPT -N ACCEPT_LOG\n") != NULL &&
	       strstr (out, "$IPT -N ACCEPT_LOG\n") != NULL,
	       "both directions declare the logging chain (each can be "
	       "applied alone)");
	CHECK (strstr (in, "-A ACCEPT_LOG -m conntrack --ctstate NEW -m limit "
	                   "--limit 10/s --limit-burst 20 -j LOG --log-prefix "
	                   "\"STOCKFW-ALLOW \"") != NULL,
	       "it logs only NEW connections, rate-limited, with the "
	       "STOCKFW-ALLOW prefix");
	CHECK (strstr (in, "-A ACCEPT_LOG -j ACCEPT\n") != NULL,
	       "and then accepts");
	CHECK (strstr (in, "-p tcp --dport 22 -j ACCEPT_LOG\n") != NULL,
	       "a policy allow jumps to the logging chain");
	CHECK (strstr (in, "--ctstate ESTABLISHED,RELATED -j ACCEPT\n") != NULL,
	       "return traffic is accepted directly, never logged");
	CHECK (strstr (in, "-A INBOUND -i lo -j ACCEPT\n") != NULL,
	       "loopback is accepted directly, never logged");
	CHECK (strstr (out, "\n$IPT -A OUTBOUND -j ACCEPT_LOG\n") != NULL,
	       "the permissive outbound default is logged too");

	/* Teeth: the deny row must come out in permissive mode, and before
	 * the default accept, or it is decoration. */
	{
		const gchar *deny = strstr (out, "-d 203.0.113.50 -j DROP");
		const gchar *dflt = strstr (out, "\n$IPT -A OUTBOUND -j ACCEPT_LOG\n");

		CHECK (!settings->restrictive_outbound && deny != NULL,
		       "permissive mode emits the \"deny connections to host\" "
		       "rule");
		CHECK (deny != NULL && dflt != NULL && deny < dflt,
		       "before the default accept");
	}
	g_free (in);
	g_free (out);

	/* Restrictive mode logs what its default drops (rate-limited). */
	settings->restrictive_outbound = TRUE;
	out = fs_script_generate_outbound (policy, settings);
	CHECK (strstr (out, "-A OUTBOUND -m limit --limit 20/s --limit-burst 40 "
	                    "-j LOG --log-prefix \"STOCKFW-DROP \"") != NULL &&
	       strstr (out, "-A OUTBOUND -j DROP\n") != NULL,
	       "restrictive outbound logs its default drop, then drops");
	g_free (out);
	settings->restrictive_outbound = FALSE;

	/* Off switch: no chain, plain ACCEPT everywhere. */
	settings->log_allowed = FALSE;
	in = fs_script_generate_inbound (policy, settings);
	out = fs_script_generate_outbound (policy, settings);
	CHECK (strstr (in, "ACCEPT_LOG") == NULL &&
	       strstr (out, "ACCEPT_LOG") == NULL &&
	       strstr (in, "STOCKFW-ALLOW") == NULL,
	       "with logging of allowed connections off, no chain and no "
	       "allow log line");
	CHECK (strstr (in, "-p tcp --dport 22 -j ACCEPT\n") != NULL &&
	       strstr (out, "\n$IPT -A OUTBOUND -j ACCEPT\n") != NULL,
	       "and allows go straight to ACCEPT");
	g_free (in);
	g_free (out);

	fs_settings_free (settings);
	fs_policy_free (policy);
}

/* ---- 1.0.7: dual-stack restore plans -------------------------------- */

static gint fake_lookups = 0;

/* Stands in for DNS: example.test has both families, v4only.test only
 * IPv4, and anything else fails the way an outage does. */
static gboolean
fake_resolve (const gchar *host, GPtrArray *v4, GPtrArray *v6, GError **error)
{
	fake_lookups++;
	if (strcmp (host, "example.test") == 0) {
		g_ptr_array_add (v4, g_strdup ("192.0.2.66"));
		g_ptr_array_add (v6, g_strdup ("2001:db8::66"));
		return TRUE;
	}
	if (strcmp (host, "v4only.test") == 0) {
		g_ptr_array_add (v4, g_strdup ("192.0.2.9"));
		return TRUE;
	}
	if (strcmp (host, "liar.test") == 0) {
		/* A resolver that answers with something that is not an
		 * address must not get it into a rule. */
		g_ptr_array_add (v4, g_strdup ("1.2.3.4 -j ACCEPT"));
		return TRUE;
	}
	g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
	                     "Temporary failure in name resolution");
	return FALSE;
}

static void
plan_add (FsPolicy *p, FsRuleKind kind, const gchar *port,
          const gchar *target, const gchar *to, const gchar *to_port)
{
	FsRule *r = fs_rule_new (kind);

	r->service = g_strdup ("Test");
	r->port = g_strdup (port);
	r->target = g_strdup (target);
	r->to = g_strdup (to);
	r->to_port = g_strdup (to_port);
	fs_policy_add (p, r);
	fs_rule_free (r);
}

/* Every line of a restore payload is a table header, a chain
 * declaration, a rule in one of StockFW's chains, a chain removal, or
 * COMMIT -- nothing else may reach iptables-restore. */
static gboolean
plan_lines_are_ours (const gchar *payload)
{
	gchar **lines = g_strsplit (payload, "\n", -1);
	gboolean ok = TRUE;

	for (gint i = 0; lines[i] != NULL; i++) {
		const gchar *l = lines[i];

		if (*l == '\0' || g_str_has_prefix (l, "*") ||
		    g_str_has_prefix (l, ":") || strcmp (l, "COMMIT") == 0 ||
		    g_str_has_prefix (l, "-X "))
			continue;
		if (g_str_has_prefix (l, "-A INBOUND ") ||
		    g_str_has_prefix (l, "-A OUTBOUND ") ||
		    g_str_has_prefix (l, "-A ACCEPT_LOG ") ||
		    g_str_has_prefix (l, "-A STOCKFW-DNAT ") ||
		    g_str_has_prefix (l, "-A STOCKFW-SNAT "))
			continue;
		ok = FALSE;
	}
	g_strfreev (lines);
	return ok;
}

/* Position of needle in hay, or G_MAXSIZE when absent (so "absent"
 * never passes an ordering check). */
static gsize
pos_of (const gchar *hay, const gchar *needle)
{
	const gchar *p = hay != NULL ? strstr (hay, needle) : NULL;

	return p != NULL ? (gsize) (p - hay) : G_MAXSIZE;
}

static void test_target_families (void)
{
	struct { const gchar *t; FsFamily want; } cases[] = {
		{ "Anyone",          FS_FAMILY_BOTH },
		{ "10.0.0.1",        FS_FAMILY_IPV4 },
		{ "10.0.0.0/8",      FS_FAMILY_IPV4 },
		{ "2001:db8::1",     FS_FAMILY_IPV6 },
		{ "2001:db8::/32",   FS_FAMILY_IPV6 },
		{ "::ffff:1.2.3.4",  FS_FAMILY_IPV6 },
		{ "example.org",     FS_FAMILY_BOTH },
		{ "example.org/24",  FS_FAMILY_NONE },
		{ "10.0.0.0/33",     FS_FAMILY_NONE },
		{ "2001:db8::/129",  FS_FAMILY_NONE },
		{ "-evil.example",   FS_FAMILY_NONE },
		{ "a.-b.example",    FS_FAMILY_NONE },
		{ "1.2.3.4\n-A INPUT -j ACCEPT", FS_FAMILY_NONE },
		{ "1.2.3.4 -j ACCEPT", FS_FAMILY_NONE },
		{ "",                FS_FAMILY_BOTH },  /* empty = anyone */
	};

	for (gsize i = 0; i < G_N_ELEMENTS (cases); i++) {
		FsFamily got = fs_util_target_families (cases[i].t);
		gchar *shown = g_strescape (cases[i].t, NULL);

		CHECK (got == cases[i].want,
		       "target \"%s\" covers %s (got %s)", shown,
		       cases[i].want == FS_FAMILY_NONE ? "nothing"
		         : fs_util_families_label (cases[i].want),
		       got == FS_FAMILY_NONE ? "nothing"
		         : fs_util_families_label (got));
		g_free (shown);
	}

	CHECK (fs_util_target_families (NULL) == FS_FAMILY_BOTH,
	       "no target means anyone: both families");
	CHECK (strcmp (fs_util_families_label (FS_FAMILY_BOTH), "IPv4 + IPv6") == 0 &&
	       strcmp (fs_util_families_label (FS_FAMILY_IPV4), "IPv4 only") == 0 &&
	       strcmp (fs_util_families_label (FS_FAMILY_IPV6), "IPv6 only") == 0 &&
	       strcmp (fs_util_families_label (FS_FAMILY_NONE), "") == 0,
	       "family labels read as the Policy page shows them");

	CHECK (fs_util_is_valid_ifname ("eth0") &&
	       fs_util_is_valid_ifname ("wlp2s0") &&
	       fs_util_is_valid_ifname ("br-1a2b3c4d5e6f") &&
	       fs_util_is_valid_ifname ("veth1@if3") &&
	       fs_util_is_valid_ifname ("enp0s31f6.100"),
	       "real interface names are valid");
	CHECK (!fs_util_is_valid_ifname ("") &&
	       !fs_util_is_valid_ifname (NULL) &&
	       !fs_util_is_valid_ifname ("-j") &&
	       !fs_util_is_valid_ifname ("abcdefghijklmnop") &&
	       !fs_util_is_valid_ifname ("eth0\n-A INPUT -j ACCEPT") &&
	       !fs_util_is_valid_ifname ("eth 0") &&
	       !fs_util_is_valid_ifname ("eth0\""),
	       "empty, option-like, too long (16), newline, space and quote "
	       "are not interface names");
	/* What a rule covers, as the Policy page and the CLI show it. */
	{
		struct { FsRuleKind kind; const gchar *target, *to;
		         gboolean names; FsFamily want; const gchar *why; } c[] = {
			{ FS_RULE_INBOUND_ALLOW_SERVICE, "Anyone", NULL, TRUE,
			  FS_FAMILY_BOTH, "IPv4 and IPv6" },
			{ FS_RULE_INBOUND_ALLOW_SERVICE, "192.168.1.0/24", NULL, TRUE,
			  FS_FAMILY_IPV4, "IPv4 range" },
			{ FS_RULE_INBOUND_ALLOW_FROM, "10.0.0.5", NULL, TRUE,
			  FS_FAMILY_IPV4, "second rule" },
			{ FS_RULE_OUTBOUND_DENY_TO, "2001:db8::bad", NULL, TRUE,
			  FS_FAMILY_IPV6, "IPv6 only" },
			{ FS_RULE_OUTBOUND_DENY_TO, "example.org", NULL, TRUE,
			  FS_FAMILY_BOTH, "looked up" },
			{ FS_RULE_OUTBOUND_DENY_TO, "example.org", NULL, FALSE,
			  FS_FAMILY_NONE, "addresses only" },
			{ FS_RULE_OUTBOUND_DENY_TO, "not a host", NULL, TRUE,
			  FS_FAMILY_NONE, "left out" },
			{ FS_RULE_INBOUND_FORWARD, NULL, "2001:db8::5", TRUE,
			  FS_FAMILY_IPV6, "IPv6 address" },
			{ FS_RULE_INBOUND_FORWARD, NULL, "192.168.1.5", TRUE,
			  FS_FAMILY_IPV4, "IPv4 address" },
			{ FS_RULE_INBOUND_FORWARD, NULL, "nas.lan", TRUE,
			  FS_FAMILY_NONE, "needs an IP address" },
			{ FS_RULE_INBOUND_FORWARD, NULL, "192.168.1.0/24", TRUE,
			  FS_FAMILY_NONE, "not a range" },
			{ FS_RULE_INBOUND_FORWARD, NULL, "", TRUE,
			  FS_FAMILY_NONE, "destination address" },
		};

		for (gsize i = 0; i < G_N_ELEMENTS (c); i++) {
			FsRule *r = fs_rule_new (c[i].kind);
			gchar *why = NULL;
			FsFamily got;

			r->target = g_strdup (c[i].target);
			r->to = g_strdup (c[i].to);
			got = fs_rule_coverage (r, c[i].names, &why);
			CHECK (got == c[i].want && why != NULL &&
			       strstr (why, c[i].why) != NULL,
			       "coverage of %s%s%s: %s -- \"%s\"",
			       c[i].kind == FS_RULE_INBOUND_FORWARD ? "a forward to " : "",
			       c[i].target != NULL ? c[i].target : c[i].to,
			       c[i].names ? "" : " (names not looked up)",
			       c[i].want == FS_FAMILY_NONE ? "nothing"
			         : fs_util_families_label (c[i].want),
			       why != NULL ? why : "(none)");
			g_free (why);
			fs_rule_free (r);
		}
	}

	CHECK (!fs_util_is_valid_host ("-evil.example") &&
	       !fs_util_is_valid_host ("ok.-evil.example") &&
	       fs_util_is_valid_host ("ok-fine.example"),
	       "a host label may not start with '-' (it would read as an "
	       "option)");
}

static void test_restore_plan (void)
{
	FsPolicy *p = fs_policy_new ();
	FsSettings *s = fs_settings_new ();
	FsRestorePlan *plan;
	GError *error = NULL;
	gchar *text;

	s->ext_device = g_strdup ("eth0");
	s->int_device = g_strdup ("eth1");
	s->filter_icmp = FALSE;     /* essentials must not depend on it */

	plan_add (p, FS_RULE_INBOUND_ALLOW_SERVICE, "22", "192.168.1.0/24",
	          NULL, NULL);
	plan_add (p, FS_RULE_INBOUND_ALLOW_SERVICE, "67-68", "Anyone",
	          NULL, NULL);
	plan_add (p, FS_RULE_INBOUND_ALLOW_FROM, NULL, "2001:db8:1::/48",
	          NULL, NULL);
	plan_add (p, FS_RULE_INBOUND_ALLOW_FROM, NULL, "v4only.test",
	          NULL, NULL);
	plan_add (p, FS_RULE_INBOUND_ALLOW_FROM, NULL, "down.test",
	          NULL, NULL);
	plan_add (p, FS_RULE_OUTBOUND_DENY_TO, NULL, "example.test",
	          NULL, NULL);
	plan_add (p, FS_RULE_OUTBOUND_DENY_FROM, NULL, "example.test",
	          NULL, NULL);

	fs_script_set_resolver (fake_resolve);
	fake_lookups = 0;
	plan = fs_script_restore_plan (p, s, &error);
	CHECK (plan != NULL, "a mixed IPv4/IPv6/name policy plans (%s)",
	       error != NULL ? error->message : "ok");
	g_clear_error (&error);
	if (plan == NULL)
		goto out;

	/* Family separation. */
	CHECK (strstr (plan->v4.filter, "-s 192.168.1.0/24 -p tcp --dport 22 ") &&
	       !strstr (plan->v6.filter, "192.168.1.0"),
	       "an IPv4 range goes to IPv4 only");
	CHECK (strstr (plan->v6.filter, "-A INBOUND -s 2001:db8:1::/48 -j ") &&
	       !strstr (plan->v4.filter, "2001:db8:1::"),
	       "an IPv6 range goes to IPv6 only");
	CHECK (strstr (plan->v4.filter, "-p tcp --dport 67:68 ") &&
	       strstr (plan->v6.filter, "-p udp --dport 67:68 "),
	       "\"Anyone\" covers both families, and a 67-68 range is "
	       "written 67:68 (iptables refuses the hyphen)");
	CHECK (!strstr (plan->v4.filter, "67-68") && !strstr (plan->v6.filter, "67-68"),
	       "no hyphen range is left anywhere");

	/* Names: resolved once, each family gets its own addresses. */
	CHECK (strstr (plan->v4.filter, "-A OUTBOUND -d 192.0.2.66 -j DROP") &&
	       strstr (plan->v6.filter, "-A OUTBOUND -d 2001:db8::66 -j DROP"),
	       "a blocked name becomes each family's own address");
	CHECK (strstr (plan->v4.filter, "-A OUTBOUND -s 192.0.2.66 -j DROP") &&
	       strstr (plan->v6.filter, "-A OUTBOUND -s 2001:db8::66 -j DROP"),
	       "and so does a blocked source");
	CHECK (!strstr (plan->v4.filter, "example.test") &&
	       !strstr (plan->v6.filter, "example.test"),
	       "no name is left for iptables to resolve at load time");
	CHECK (fake_lookups == 3,
	       "each name is looked up once for both families and every "
	       "rule using it (%d lookups for 3 names)", fake_lookups);
	CHECK (strstr (plan->v4.filter, "-s 192.0.2.9 ") &&
	       !strstr (plan->v6.filter, "192.0.2.9"),
	       "a name with only an IPv4 address is an IPv4-only rule");
	{
		gboolean noted = FALSE;

		for (guint i = 0; i < plan->notes->len; i++)
			noted |= strstr (g_ptr_array_index (plan->notes, i),
			                 "v4only.test has no IPv6 address") != NULL;
		CHECK (noted, "and the plan says so");
	}
	{
		gboolean skipped = FALSE;

		for (guint i = 0; i < plan->skipped->len; i++)
			skipped |= strstr (g_ptr_array_index (plan->skipped, i),
			                   "down.test") != NULL;
		CHECK (skipped && !strstr (plan->v4.filter, "down.test"),
		       "an allow whose name cannot be looked up is left out and "
		       "reported (fails closed)");
	}

	/* What IPv6 needs to work, whatever the ICMP preferences say. */
	CHECK (strstr (plan->v6.filter, "-A INBOUND -p ipv6-icmp --icmpv6-type "
	                                "neighbour-solicitation -m hl --hl-eq 255 -j ACCEPT\n") &&
	       strstr (plan->v6.filter, "-A INBOUND -p ipv6-icmp --icmpv6-type "
	                                "neighbour-advertisement -m hl --hl-eq 255 -j ACCEPT\n") &&
	       strstr (plan->v6.filter, "-A INBOUND -s fe80::/10 -p ipv6-icmp "
	                                "--icmpv6-type router-advertisement -m hl --hl-eq 255 -j ACCEPT\n") &&
	       strstr (plan->v6.filter, "-A INBOUND -p ipv6-icmp --icmpv6-type "
	                                "packet-too-big -j ACCEPT\n"),
	       "IPv6 inbound always accepts neighbour discovery, router "
	       "adverts and packet-too-big, unlimited");
	CHECK (strstr (plan->v6.filter, "-A OUTBOUND -p ipv6-icmp --icmpv6-type "
	                                "neighbour-solicitation -m hl --hl-eq 255 -j ACCEPT\n") &&
	       strstr (plan->v6.filter, "-A OUTBOUND -p ipv6-icmp --icmpv6-type "
	                                "router-solicitation -m hl --hl-eq 255 -j ACCEPT\n"),
	       "and lets its own solicitations out");
	CHECK (!strstr (plan->v6.filter, "-p icmp "),
	       "no IPv4 ICMP rule in IPv6 (ip6tables takes it as protocol 1 "
	       "and it never matches)");
	CHECK (!strstr (plan->v4.filter, "ipv6-icmp"),
	       "and no ICMPv6 in IPv4");
	CHECK (pos_of (plan->v6.filter, "neighbour-solicitation") <
	       pos_of (plan->v6.filter, "-A INBOUND -m limit"),
	       "neighbour discovery comes before any rate-limited ICMP rule");

	/* Loopback and ordering. */
	CHECK (strstr (plan->v4.filter, "-A OUTBOUND -o lo -j ACCEPT\n") &&
	       strstr (plan->v6.filter, "-A OUTBOUND -o lo -j ACCEPT\n") &&
	       !strstr (plan->v4.filter, "-A OUTBOUND -i lo"),
	       "OUTBOUND accepts loopback with -o lo (-i lo never matches "
	       "in OUTPUT)");
	CHECK (pos_of (plan->v4.filter, "-A OUTBOUND -m conntrack --ctstate "
	                                "ESTABLISHED,RELATED -j ACCEPT") <
	       pos_of (plan->v4.filter, "-A OUTBOUND -d 192.0.2.66 -j DROP"),
	       "a block on connections out comes after the reply accept, so "
	       "it never cuts replies to connections that host opened to us");
	CHECK (strstr (plan->v6.filter, "-A INBOUND -i eth0 -s ::1/128 -j DROP") &&
	       strstr (plan->v6.filter, "-A INBOUND -i eth0 -s ::ffff:0:0/96 -j DROP"),
	       "IPv6 drops spoofed loopback and IPv4-mapped sources on the "
	       "outside interface");
	CHECK (plan->v4.nat == NULL && plan->v6.nat == NULL,
	       "without router mode there is no nat table in the plan");
	CHECK (plan_lines_are_ours (plan->v4.filter) &&
	       plan_lines_are_ours (plan->v6.filter),
	       "every line written is a rule in StockFW's own chains");
	fs_restore_plan_free (plan);

	/* Restrictive outbound must not cut IPv6 off its own network. */
	s->restrictive_outbound = TRUE;
	plan = fs_script_restore_plan (p, s, NULL);
	CHECK (plan != NULL &&
	       pos_of (plan->v6.filter, "-A OUTBOUND -p ipv6-icmp --icmpv6-type "
	                                "neighbour-solicitation") <
	       pos_of (plan->v6.filter, "-A OUTBOUND -j DROP") &&
	       pos_of (plan->v6.filter, "-A OUTBOUND -p udp --sport 546 --dport 547 -j ACCEPT") <
	       pos_of (plan->v6.filter, "-A OUTBOUND -j DROP"),
	       "restrictive outbound still lets neighbour discovery and "
	       "DHCPv6 out, ahead of its default drop");
	fs_restore_plan_free (plan);
	s->restrictive_outbound = FALSE;

	/* Router mode. */
	s->nat = TRUE;
	plan_add (p, FS_RULE_INBOUND_FORWARD, "8080", NULL, "2001:db8::5", "80");
	plan_add (p, FS_RULE_INBOUND_FORWARD, "8081", NULL, "192.168.1.5", "80");
	plan_add (p, FS_RULE_INBOUND_FORWARD, "8082", NULL, "example.test", "80");
	plan = fs_script_restore_plan (p, s, NULL);
	CHECK (plan != NULL && plan->v4.nat != NULL && plan->v6.nat != NULL,
	       "router mode adds a nat table to both families");
	if (plan != NULL && plan->v4.nat != NULL && plan->v6.nat != NULL) {
		CHECK (strstr (plan->v6.nat, "-A STOCKFW-DNAT -i eth0 -p tcp --dport 8080 "
		                             "-j DNAT --to-destination [2001:db8::5]:80\n") != NULL,
		       "an IPv6 forward is written [address]:port");
		CHECK (strstr (plan->v4.nat, "--to-destination 192.168.1.5:80\n") &&
		       !strstr (plan->v4.nat, "2001:db8::5") &&
		       !strstr (plan->v6.nat, "192.168.1.5"),
		       "each forward is in its own family's nat table");
		CHECK (strstr (plan->v4.nat, "-A STOCKFW-SNAT -o eth0 -j MASQUERADE") &&
		       !strstr (plan->v6.nat, "MASQUERADE"),
		       "masquerading is IPv4 only, in STOCKFW-SNAT");
		CHECK (!strstr (plan->v4.nat, "example.test") &&
		       !strstr (plan->v4.nat, "192.0.2.66"),
		       "a forward to a name is left out, not resolved");
		CHECK (strstr (plan->v6.filter, "-A INBOUND -d 2001:db8::5 -p tcp --dport 80 "
		                                "-m conntrack --ctstate DNAT -j ") != NULL,
		       "what a forward lets in is accepted after the DNAT");
		CHECK (pos_of (plan->v4.filter, "-A OUTBOUND -d 192.0.2.66 -j DROP") <
		       pos_of (plan->v4.filter, "-A OUTBOUND -o eth0 -j ACCEPT"),
		       "in router mode a block comes before the accept for "
		       "everything leaving the outside interface");
		CHECK (plan_lines_are_ours (plan->v4.nat) &&
		       plan_lines_are_ours (plan->v6.nat),
		       "nat lines are in StockFW's own chains only");
	}
	fs_restore_plan_free (plan);
	s->nat = FALSE;

	/* A block that cannot be looked up fails the whole plan. */
	plan_add (p, FS_RULE_OUTBOUND_DENY_TO, NULL, "down.test", NULL, NULL);
	plan = fs_script_restore_plan (p, s, &error);
	CHECK (plan == NULL && g_error_matches (error, FS_SCRIPT_ERROR,
	                                        FS_SCRIPT_ERR_RESOLVE),
	       "a block whose name cannot be looked up fails the plan (it "
	       "must not fail open)");
	g_clear_error (&error);
	fs_restore_plan_free (plan);

	/* ...unless nothing is loaded yet: then refusing protects nobody. */
	plan = fs_script_restore_plan_ex (p, s, FS_PLAN_LENIENT_BLOCKS, &error);
	CHECK (plan != NULL && error == NULL,
	       "with nothing loaded (lenient), the same policy plans");
	if (plan != NULL) {
		gboolean said = FALSE;

		for (guint i = 0; i < plan->skipped->len; i++)
			said |= g_str_has_prefix (g_ptr_array_index (plan->skipped, i),
			                          "NOT BLOCKED: down.test could not "
			                          "be looked up");
		CHECK (said && strstr (plan->v4.filter, "-d 192.0.2.66 -j DROP"),
		       "the unresolvable block is listed as NOT BLOCKED, and every "
		       "other block is in");
	}
	g_clear_error (&error);
	fs_restore_plan_free (plan);

out:
	fs_policy_free (p);
	fs_settings_free (s);

	/* Hostile input never reaches a rule. */
	p = fs_policy_new ();
	s = fs_settings_new ();
	s->ext_device = g_strdup ("eth0\n-A INPUT -j ACCEPT");
	plan = fs_script_restore_plan (p, s, &error);
	CHECK (plan == NULL && g_error_matches (error, FS_SCRIPT_ERROR,
	                                        FS_SCRIPT_ERR_INVALID),
	       "an interface name carrying a second rule is refused");
	g_clear_error (&error);
	fs_restore_plan_free (plan);

	g_free (s->ext_device);
	s->ext_device = g_strdup ("eth0");
	plan_add (p, FS_RULE_INBOUND_ALLOW_SERVICE, "22\n-A INPUT -j ACCEPT",
	          "Anyone", NULL, NULL);
	plan_add (p, FS_RULE_INBOUND_ALLOW_FROM, NULL,
	          "1.2.3.4\n-A INPUT -j ACCEPT", NULL, NULL);
	plan_add (p, FS_RULE_INBOUND_ALLOW_FROM, NULL, "liar.test", NULL, NULL);
	plan = fs_script_restore_plan (p, s, &error);
	CHECK (plan == NULL ||
	       (plan_lines_are_ours (plan->v4.filter) &&
	        plan_lines_are_ours (plan->v6.filter) &&
	        !strstr (plan->v4.filter, "INPUT") &&
	        !strstr (plan->v4.filter, "1.2.3.4")),
	       "a port, a target or a resolver answer carrying a rule never "
	       "becomes one");
	g_clear_error (&error);
	fs_restore_plan_free (plan);

	plan_add (p, FS_RULE_OUTBOUND_DENY_TO, NULL, "1.2.3.4\" -j ACCEPT", NULL,
	          NULL);
	plan = fs_script_restore_plan (p, s, &error);
	CHECK (plan == NULL && error != NULL,
	       "a block on something that is not an address fails the plan "
	       "rather than being dropped silently");
	g_clear_error (&error);
	fs_restore_plan_free (plan);

	fs_policy_free (p);
	fs_settings_free (s);

	/* "Covers" says what the generator does: for each target, a
	 * family is covered exactly when that family's payload names it. */
	{
		struct { const gchar *target, *v4, *v6; } c[] = {
			{ "10.0.0.5",        "-d 10.0.0.5 ",        NULL },
			{ "192.168.1.0/24",  "-d 192.168.1.0/24 ",  NULL },
			{ "2001:db8::bad",   NULL,                  "-d 2001:db8::bad " },
			{ "2001:db8:9::/48", NULL,                  "-d 2001:db8:9::/48 " },
			{ "example.test",    "-d 192.0.2.66 ",      "-d 2001:db8::66 " },
		};

		for (gsize i = 0; i < G_N_ELEMENTS (c); i++) {
			FsPolicy *cp = fs_policy_new ();
			FsSettings *cs = fs_settings_new ();
			FsRestorePlan *pl;
			FsFamily said;
			FsRule *r;

			plan_add (cp, FS_RULE_OUTBOUND_DENY_TO, NULL, c[i].target,
			          NULL, NULL);
			r = g_ptr_array_index (cp->kinds[FS_RULE_OUTBOUND_DENY_TO], 0);
			said = fs_rule_coverage (r, TRUE, NULL);
			pl = fs_script_restore_plan (cp, cs, NULL);
			CHECK (pl != NULL &&
			       ((said & FS_FAMILY_IPV4) != 0) ==
			         (c[i].v4 != NULL && strstr (pl->v4.filter, c[i].v4) != NULL) &&
			       ((said & FS_FAMILY_IPV6) != 0) ==
			         (c[i].v6 != NULL && strstr (pl->v6.filter, c[i].v6) != NULL) &&
			       (c[i].v4 != NULL || !strstr (pl->v4.filter, "-A OUTBOUND -d ")) &&
			       (c[i].v6 != NULL || !strstr (pl->v6.filter, "-A OUTBOUND -d ")),
			       "\"Covers %s\" for %s matches what each family's rules "
			       "contain", fs_util_families_label (said), c[i].target);
			fs_restore_plan_free (pl);
			fs_settings_free (cs);
			fs_policy_free (cp);
		}
	}

	/* The text form (scripts, What-If) keeps a name for iptables. */
	p = fs_policy_new ();
	s = fs_settings_new ();
	plan_add (p, FS_RULE_OUTBOUND_DENY_TO, NULL, "203.0.113.50", NULL, NULL);
	text = fs_script_generate_outbound (p, s);
	CHECK (strstr (text, "$IPT -A OUTBOUND -d 203.0.113.50 -j DROP\n") != NULL,
	       "the text form writes host blocks into OUTBOUND (\"-A OUTBOUND\" "
	       "was missing, so the line was not a rule at all)");
	g_free (text);
	fs_policy_free (p);
	fs_settings_free (s);

	fs_script_set_resolver (NULL);
}

/* ---- threat intel on Windows (fs-intelwin, design 11) ---------------- */

#define IW_GEN  "g0123abcd"
#define IW_GEN2 "g89abcdef"

static FsRangeSet *
iw_set (const gchar *const *tokens)
{
	FsRangeSet *s = fs_range_set_new ();

	for (guint i = 0; tokens[i] != NULL; i++)
		fs_range_set_add_text (s, tokens[i]);
	fs_range_set_normalize (s);
	return s;
}

/* A rule set of two lists: "alpha" both ways (5 IPv4, 2 IPv6), "beta"
 * outbound only (1 IPv4). */
static FsIntelRuleset *
iw_ruleset (void)
{
	static const gchar *const alpha[] = {
		"10.0.0.0/8", "192.0.2.7", "198.51.100.0/24",
		"203.0.113.10-203.0.113.20", "45.0.0.1",
		"2001:db8::/32", "2001:db8:ffff::1", NULL };
	static const gchar *const beta[] = { "100.64.0.0/10", NULL };
	FsIntelRuleset *rs = fs_intel_ruleset_new ();

	fs_intel_ruleset_add (rs, "alpha", "Alpha | list\nsecond line",
	                      FS_INTEL_DIR_BOTH, iw_set (alpha));
	fs_intel_ruleset_add (rs, "beta", "Beta", FS_INTEL_DIR_OUT,
	                      iw_set (beta));
	return rs;
}

/* What Windows Firewall would hand back for a plan's rules: every
 * property as written, RemoteAddresses optionally the way Windows
 * stores it (IPv4 with dotted masks, tokens in another order). */
static gchar *
iw_windows_form (const gchar *remote)
{
	gchar **t = g_strsplit (remote, ",", -1);
	guint n = g_strv_length (t);
	GString *out = g_string_new (NULL);

	for (guint k = n; k-- > 0;) {
		gchar *tok = t[k];
		gchar *slash = strchr (tok, '/');

		if (out->len > 0)
			g_string_append_c (out, ',');
		if (strchr (tok, ':') == NULL && strchr (tok, '-') == NULL) {
			guint bits = slash ? (guint) atoi (slash + 1) : 32;
			guint32 m = bits == 0 ? 0 : 0xffffffffu << (32 - bits);

			if (slash)
				*slash = '\0';
			g_string_append_printf (out, "%s/%u.%u.%u.%u", tok,
			                        m >> 24, (m >> 16) & 255,
			                        (m >> 8) & 255, m & 255);
		} else {
			g_string_append (out, tok);
		}
	}
	g_strfreev (t);
	return g_string_free (out, FALSE);
}

static GPtrArray *
iw_seen_from_plan (const FsIntelWinPlan *plan, gboolean windows_form)
{
	GPtrArray *seen = g_ptr_array_new_with_free_func (fs_intelwin_seen_free);

	for (guint i = 0; i < plan->rules->len; i++) {
		const FsIntelWinRule *r = g_ptr_array_index (plan->rules, i);
		FsIntelWinSeen *s = fs_intelwin_seen_new ();

		s->name = g_strdup (r->name);
		s->description = g_strdup (r->description);
		s->grouping = g_strdup (FS_INTELWIN_GROUP);
		s->direction = (gint) r->dir;
		s->action = 0;
		s->enabled = r->enabled;
		s->profiles = 0x7fffffff;   /* NET_FW_PROFILE2_ALL */
		s->protocol = 256;
		s->local_addresses = g_strdup ("*");
		s->remote_addresses = windows_form && r->family != FS_AF_NONE
		                      ? iw_windows_form (r->remote)
		                      : g_strdup (r->remote);
		s->local_ports = NULL;
		s->remote_ports = NULL;
		s->interface_types = g_strdup ("All");
		g_ptr_array_add (seen, s);
	}
	return seen;
}

static FsIntelWinSeen *
iw_find (GPtrArray *seen, const gchar *name)
{
	for (guint i = 0; i < seen->len; i++) {
		FsIntelWinSeen *s = g_ptr_array_index (seen, i);

		if (g_strcmp0 (s->name, name) == 0)
			return s;
	}
	return NULL;
}

static FsIntelWinRule *
iw_rule (const FsIntelWinPlan *plan, const gchar *name)
{
	for (guint i = 0; i < plan->rules->len; i++) {
		FsIntelWinRule *r = g_ptr_array_index (plan->rules, i);

		if (strcmp (r->name, name) == 0)
			return r;
	}
	return NULL;
}

/* ---- the Windows store's security descriptors (fs-winstore, 11.5) --- */

/* A reader for the SDDL subset the store uses and Windows shows for a
 * folder (owner "O:", "D:" with "P", "(type;flags;rights;;;sid)"), as
 * the judge's input.  `trusted' names the SIDs taken as trusted, as
 * fs-winstore.c does: SY, BA, and the user when it is trusted. */
typedef struct
{
	gchar         *owner;
	gboolean       has_dacl;
	gboolean       protected_dacl;
	FsWinstoreAce  aces[16];
	gchar         *sids[16];
	guint          n;
} SddlRead;

static guint32
sddl_rights (const gchar *r)
{
	if (g_str_has_prefix (r, "0x"))
		return (guint32) g_ascii_strtoull (r + 2, NULL, 16);
	if (strcmp (r, "FA") == 0)
		return 0x1f01ffu;   /* FILE_ALL_ACCESS */
	if (strcmp (r, "GA") == 0)
		return 0x10000000u;
	if (strcmp (r, "GR") == 0)
		return 0x80000000u;
	if (strcmp (r, "GW") == 0)
		return 0x40000000u;
	return 0xffffffffu;   /* unknown: make it fail loudly */
}

static guint8
sddl_flags (const gchar *f)
{
	guint8 out = 0;

	for (; f[0] != '\0' && f[1] != '\0'; f += 2) {
		if (strncmp (f, "OI", 2) == 0)
			out |= 0x01;
		else if (strncmp (f, "CI", 2) == 0)
			out |= 0x02;
		else if (strncmp (f, "IO", 2) == 0)
			out |= 0x08;
		else if (strncmp (f, "ID", 2) == 0)
			out |= 0x10;
	}
	return out;
}

static gboolean
sddl_read (const gchar *sddl, SddlRead *out)
{
	const gchar *p = sddl;

	memset (out, 0, sizeof *out);
	if (g_str_has_prefix (p, "O:")) {
		const gchar *d = strstr (p, "D:");

		if (d == NULL)
			d = p + strlen (p);   /* an owner and no access list */
		out->owner = g_strndup (p + 2, (gsize) (d - p - 2));
		p = d;
	}
	if (!g_str_has_prefix (p, "D:"))
		return TRUE;
	out->has_dacl = TRUE;
	p += 2;
	while (*p != '\0' && *p != '(') {
		if (*p == 'P')
			out->protected_dacl = TRUE;
		p++;
	}
	while (*p == '(' && out->n < G_N_ELEMENTS (out->aces)) {
		const gchar *end = strchr (p, ')');
		gchar *body, **f;

		if (end == NULL)
			return FALSE;
		body = g_strndup (p + 1, (gsize) (end - p - 1));
		f = g_strsplit (body, ";", -1);
		if (g_strv_length (f) != 6) {
			g_strfreev (f);
			g_free (body);
			return FALSE;
		}
		out->aces[out->n].type =
			strcmp (f[0], "A") == 0 ? FS_WINSTORE_ACE_ALLOWED :
			strcmp (f[0], "D") == 0 ? FS_WINSTORE_ACE_DENIED :
			strcmp (f[0], "AU") == 0 ? FS_WINSTORE_ACE_AUDIT :
			strcmp (f[0], "OA") == 0 ? 0x05 : 0xff;
		out->aces[out->n].flags = sddl_flags (f[1]);
		out->aces[out->n].mask = sddl_rights (f[2]);
		out->sids[out->n] = g_strdup (f[5]);
		out->n++;
		g_strfreev (f);
		g_free (body);
		p = end + 1;
	}
	return *p == '\0';
}

static void
sddl_trust (SddlRead *r, const gchar *user)
{
	for (guint i = 0; i < r->n; i++)
		r->aces[i].trusted = strcmp (r->sids[i], "SY") == 0 ||
		                     strcmp (r->sids[i], "BA") == 0 ||
		                     (user != NULL &&
		                      strcmp (r->sids[i], user) == 0);
}

static gboolean
sddl_owner_trusted (const SddlRead *r, const gchar *creator,
                    const gchar *user)
{
	/* No "O:": Windows makes the creating account the owner. */
	const gchar *o = r->owner != NULL ? r->owner : creator;

	return strcmp (o, "SY") == 0 || strcmp (o, "BA") == 0 ||
	       (user != NULL && strcmp (o, user) == 0);
}

static void
sddl_clear (SddlRead *r)
{
	g_free (r->owner);
	for (guint i = 0; i < r->n; i++)
		g_free (r->sids[i]);
}

/* Judges `sddl' as a folder created by `creator', with `user' trusted
 * (NULL: the default store, where only SY and BA are). */
static FsWinstoreFault
judge_sddl (const gchar *sddl, const gchar *creator, const gchar *user,
            gboolean *readable)
{
	SddlRead r;
	FsWinstoreFault f;

	if (!sddl_read (sddl, &r)) {
		sddl_clear (&r);
		return (FsWinstoreFault) -1;
	}
	sddl_trust (&r, user);
	f = fs_winstore_judge (sddl_owner_trusted (&r, creator, user),
	                       r.has_dacl, r.aces, r.n, readable);
	sddl_clear (&r);
	return f;
}

#define WS_ADMIN_USER "S-1-5-21-111-222-333-500"   /* runneradmin, say */

static void
test_winstore_sddl (void)
{
	gchar *parent = fs_winstore_sddl (FS_WINSTORE_DIR_PARENT, TRUE, NULL);
	gchar *store = fs_winstore_sddl (FS_WINSTORE_DIR_STORE, TRUE, NULL);
	gchar *over = fs_winstore_sddl (FS_WINSTORE_DIR_STORE, TRUE,
	                                WS_ADMIN_USER);
	gchar *over_plain = fs_winstore_sddl (FS_WINSTORE_DIR_STORE, FALSE,
	                                      WS_ADMIN_USER);
	gchar *old_parent = g_strdup ("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	                              "(A;OICI;0x1200a9;;;BU)");
	gboolean readable = TRUE;
	SddlRead r;

	/* What StockFW creates, exactly. */
	CHECK (strcmp (parent, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	                       "(A;OICI;0x1200a9;;;BU)") == 0,
	       "winstore: %%ProgramData%%\\StockFW is created owned by "
	       "Administrators, protected, SYSTEM and Administrators full, "
	       "Users read (%s)", parent);
	CHECK (strcmp (store, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)") == 0,
	       "winstore: intel is created owned by Administrators, "
	       "protected, SYSTEM and Administrators only (%s)", store);
	CHECK (strcmp (over, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	                     "(A;OICI;FA;;;" WS_ADMIN_USER ")") == 0 &&
	       strcmp (over_plain, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	                           "(A;OICI;FA;;;" WS_ADMIN_USER ")") == 0,
	       "winstore: an override adds the current user; it names "
	       "Administrators as owner only when elevated (%s | %s)", over,
	       over_plain);
	CHECK (sddl_read (parent, &r) && r.protected_dacl && r.owner != NULL &&
	       strcmp (r.owner, "BA") == 0,
	       "winstore: the reader sees the owner and the protection");
	sddl_clear (&r);

	/* Each passes the check it will meet, created by an elevated
	 * administrator account that is neither SYSTEM nor
	 * Administrators: the CI's runneradmin (round 3 on Windows). */
	CHECK (judge_sddl (parent, WS_ADMIN_USER, NULL, &readable) ==
	       FS_WINSTORE_SAFE && readable,
	       "winstore: StockFW's own %%ProgramData%%\\StockFW passes the "
	       "default store's check (Users may read it)");
	CHECK (judge_sddl (store, WS_ADMIN_USER, NULL, &readable) ==
	       FS_WINSTORE_SAFE && !readable,
	       "winstore: StockFW's own intel passes, and nobody else may "
	       "read it (so it is never tightened again)");
	CHECK (judge_sddl (over, WS_ADMIN_USER, WS_ADMIN_USER, &readable) ==
	       FS_WINSTORE_SAFE &&
	       judge_sddl (over_plain, WS_ADMIN_USER, WS_ADMIN_USER,
	                   &readable) == FS_WINSTORE_SAFE,
	       "winstore: an override passes the override's check, elevated "
	       "or not");

	/* The fault the CI found: without "O:BA" the creating account owns
	 * the folder, and the default store trusts no user. */
	CHECK (judge_sddl (old_parent, WS_ADMIN_USER, NULL, &readable) ==
	       FS_WINSTORE_FAULT_OWNER,
	       "winstore: a folder created without an owner belongs to the "
	       "account that made it, and the default store refuses it "
	       "(the CI failure: owned by runneradmin)");
	CHECK (judge_sddl (old_parent, "SY", NULL, &readable) ==
	       FS_WINSTORE_SAFE,
	       "winstore: ... which only a creator that is SYSTEM avoided");

	/* A folder another account made first is refused as foreign, even
	 * with StockFW's access list on it. */
	CHECK (judge_sddl ("O:BUD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
	                   WS_ADMIN_USER, NULL, &readable) ==
	       FS_WINSTORE_FAULT_OWNER &&
	       judge_sddl ("O:S-1-5-21-111-222-333-1001D:P(A;OICI;FA;;;SY)",
	                   WS_ADMIN_USER, WS_ADMIN_USER, &readable) ==
	       FS_WINSTORE_FAULT_OWNER,
	       "winstore: a folder owned by Users, or by another user under "
	       "an override, is refused as foreign");

	/* A folder that inherits a drive root's default access list (the
	 * runner's D:\a\_temp\...): Users may add folders (CI;AD) and,
	 * through the inherit-only entry for files, add files below;
	 * CREATOR OWNER applies to what is created inside only. */
	CHECK (judge_sddl ("O:" WS_ADMIN_USER "D:AI(A;OICIID;FA;;;SY)"
	                   "(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)"
	                   "(A;CIID;0x4;;;BU)(A;CIIOID;0x2;;;BU)"
	                   "(A;OICIIOID;GA;;;CO)",
	                   WS_ADMIN_USER, WS_ADMIN_USER, &readable) ==
	       FS_WINSTORE_FAULT_CHANGE,
	       "winstore: a temporary folder under a drive root (Users may "
	       "add folders to it) is refused as an override's parent (the "
	       "CI failure for the override and the engine checks)");
	CHECK (judge_sddl ("O:" WS_ADMIN_USER "D:AI(A;OICIID;FA;;;SY)"
	                   "(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)"
	                   "(A;CIIOID;0x2;;;BU)(A;OICIIOID;GA;;;CO)",
	                   WS_ADMIN_USER, WS_ADMIN_USER, &readable) ==
	       FS_WINSTORE_SAFE && readable,
	       "winstore: inherit-only entries (CREATOR OWNER, Users' "
	       "add-file for what is inside) do not count against the "
	       "folder itself; Users' read makes it readable");

	/* The rest of the judge. */
	CHECK (judge_sddl ("O:BAD:P(A;;FA;;;BA)(D;;FA;;;WD)(AU;SA;FA;;;WD)",
	                   WS_ADMIN_USER, NULL, &readable) == FS_WINSTORE_SAFE &&
	       !readable,
	       "winstore: deny and audit entries are not grants");
	CHECK (judge_sddl ("O:BAD:P(A;;FA;;;BA)(A;;0x40000;;;WD)",
	                   WS_ADMIN_USER, NULL, &readable) ==
	       FS_WINSTORE_FAULT_CHANGE &&
	       judge_sddl ("O:BAD:P(A;;FA;;;BA)(A;;0x40;;;AU)",
	                   WS_ADMIN_USER, NULL, &readable) ==
	       FS_WINSTORE_FAULT_CHANGE &&
	       judge_sddl ("O:BAD:P(A;;FA;;;BA)(A;;GW;;;BU)",
	                   WS_ADMIN_USER, NULL, &readable) ==
	       FS_WINSTORE_FAULT_CHANGE,
	       "winstore: write-DAC for Everyone, delete-child for "
	       "Authenticated Users, generic write for Users: each refused");
	CHECK (judge_sddl ("O:BAD:P(A;;FA;;;BA)(A;;FA;;;" WS_ADMIN_USER ")",
	                   WS_ADMIN_USER, NULL, &readable) ==
	       FS_WINSTORE_FAULT_CHANGE,
	       "winstore: the current user is trusted only under an "
	       "override, never in the default store");
	CHECK (judge_sddl ("O:BA", WS_ADMIN_USER, NULL, &readable) ==
	       FS_WINSTORE_FAULT_NO_DACL,
	       "winstore: no access list is refused");
	CHECK (judge_sddl ("O:BAD:P(A;;FA;;;BA)(OA;;FA;;;WD)", WS_ADMIN_USER,
	                   NULL, &readable) == FS_WINSTORE_FAULT_UNKNOWN_ACE,
	       "winstore: an entry the judge cannot read (an object ACE) is "
	       "refused");
	CHECK (fs_winstore_fault_text (FS_WINSTORE_SAFE) == NULL &&
	       fs_winstore_fault_text (FS_WINSTORE_FAULT_OWNER) != NULL &&
	       strstr (fs_winstore_fault_text (FS_WINSTORE_FAULT_CHANGE),
	               "may change it") != NULL,
	       "winstore: every fault has its sentence");

	g_free (parent);
	g_free (store);
	g_free (over);
	g_free (over_plain);
	g_free (old_parent);
}

static void
test_intelwin_gen (void)
{
	const gchar *taken[] = { "g00000005", NULL };
	gchar *g;

	CHECK (fs_intelwin_gen_is_valid (IW_GEN), "intelwin: %s is a generation",
	       IW_GEN);
	CHECK (!fs_intelwin_gen_is_valid ("G0123abcd") &&
	       !fs_intelwin_gen_is_valid ("g0123ABCD") &&
	       !fs_intelwin_gen_is_valid ("g0123abc") &&
	       !fs_intelwin_gen_is_valid ("g0123abcde") &&
	       !fs_intelwin_gen_is_valid ("g0123abc ") &&
	       !fs_intelwin_gen_is_valid (NULL),
	       "intelwin: upper case, short, long, trailing space and NULL "
	       "are not generations");
	g = fs_intelwin_gen_new (5, NULL);
	CHECK (g_strcmp0 (g, "g00000005") == 0,
	       "intelwin: a new generation comes from its seed (%s)", g);
	g_free (g);
	g = fs_intelwin_gen_new (5, taken);
	CHECK (fs_intelwin_gen_is_valid (g) && strcmp (g, "g00000005") != 0,
	       "intelwin: a new generation is never one already on the "
	       "firewall (%s)", g);
	g_free (g);
}

static void
test_intelwin_plan (void)
{
	FsIntelRuleset *rs = iw_ruleset ();
	FsIntelWinPlan *plan = fs_intelwin_plan (rs, IW_GEN, 2, 1000);
	static const gchar *const names[] = {
		"SFW-TI alpha in IPv4 1/3 " IW_GEN,
		"SFW-TI alpha in IPv4 2/3 " IW_GEN,
		"SFW-TI alpha in IPv4 3/3 " IW_GEN,
		"SFW-TI alpha in IPv6 1/1 " IW_GEN,
		"SFW-TI alpha out IPv4 1/3 " IW_GEN,
		"SFW-TI alpha out IPv4 2/3 " IW_GEN,
		"SFW-TI alpha out IPv4 3/3 " IW_GEN,
		"SFW-TI alpha out IPv6 1/1 " IW_GEN,
		"SFW-TI beta out IPv4 1/1 " IW_GEN,
		"SFW-TI manifest " IW_GEN,
	};
	gboolean names_ok, shape_ok = TRUE, lossless = TRUE;
	gchar *digest = fs_intel_ruleset_digest (rs);
	const FsIntelWinRule *m;
	gchar *want;

	CHECK (plan != NULL && plan->rules->len == G_N_ELEMENTS (names),
	       "intelwin plan: 2 lists, one both ways, 2 tokens a rule -> %u "
	       "rules (got %u)", (guint) G_N_ELEMENTS (names),
	       plan ? plan->rules->len : 0);
	if (plan == NULL || plan->rules->len != G_N_ELEMENTS (names))
		goto out;
	names_ok = TRUE;
	for (guint i = 0; i < G_N_ELEMENTS (names); i++) {
		const FsIntelWinRule *r = g_ptr_array_index (plan->rules, i);

		if (strcmp (r->name, names[i]) != 0) {
			printf ("      rule %u is \"%s\", wanted \"%s\"\n", i,
			        r->name, names[i]);
			names_ok = FALSE;
		}
	}
	CHECK (names_ok, "intelwin plan: names encode list, direction, "
	       "family, chunk i/n and generation, inbound before outbound, "
	       "IPv4 before IPv6, the manifest last");
	CHECK (g_strcmp0 (plan->digest, digest) == 0 && plan->plan != NULL &&
	       strlen (plan->plan) == 32 && g_strcmp0 (plan->gen, IW_GEN) == 0,
	       "intelwin plan: carries the rule set's digest, its generation "
	       "and a 32-digit plan hash");

	for (guint i = 0; i + 1 < plan->rules->len; i++) {
		const FsIntelWinRule *r = g_ptr_array_index (plan->rules, i);

		if (!r->enabled || r->tokens == 0 || r->tokens > 2 ||
		    r->family == FS_AF_NONE ||
		    g_str_has_prefix (r->name, "StockFW-") ||
		    !g_str_has_prefix (r->name, FS_INTELWIN_PREFIX) ||
		    strchr (r->description, '|') != NULL ||
		    strchr (r->description, '\n') != NULL ||
		    (strstr (r->name, " in ") ? r->dir != FS_INTELWIN_IN
		                              : r->dir != FS_INTELWIN_OUT))
			shape_ok = FALSE;
	}
	CHECK (shape_ok, "intelwin plan: every address rule is enabled, has "
	       "1-2 tokens, the direction its name says, never the policy's "
	       "\"StockFW-\" prefix, and a description without '|' or line "
	       "breaks");

	/* No address lost or added: per list and direction, the rules'
	 * RemoteAddresses read back are the list. */
	for (guint s = 0; s < rs->sets->len; s++) {
		const FsIntelSet *set = g_ptr_array_index (rs->sets, s);

		for (guint d = 1; d <= 2; d++) {
			FsRangeSet *got = fs_range_set_new ();
			gchar *a, *b;
			gchar *prefix;

			if ((set->dir & d) == 0)
				continue;
			prefix = g_strdup_printf ("SFW-TI %s %s ", set->id,
			                          d == 1 ? "in" : "out");
			for (guint i = 0; i < plan->rules->len; i++) {
				const FsIntelWinRule *r =
					g_ptr_array_index (plan->rules, i);

				if (g_str_has_prefix (r->name, prefix))
					fs_intelwin_parse_remote (r->remote, got);
			}
			fs_range_set_normalize (got);
			a = fs_range_set_to_text (got);
			b = fs_range_set_to_text (set->ranges);
			if (strcmp (a, b) != 0)
				lossless = FALSE;
			g_free (a);
			g_free (b);
			g_free (prefix);
			fs_range_set_free (got);
		}
	}
	CHECK (lossless, "intelwin plan: per list and direction, the chunks "
	       "together hold exactly the list's addresses");

	m = g_ptr_array_index (plan->rules, plan->rules->len - 1);
	want = g_strdup_printf ("sfw:%s plan:%s rules:9", digest, plan->plan);
	CHECK (!m->enabled && m->family == FS_AF_NONE &&
	       g_strcmp0 (m->remote, FS_INTELWIN_MANIFEST_REMOTE) == 0 &&
	       g_str_has_suffix (m->description, want),
	       "intelwin plan: the manifest is disabled, names only "
	       "192.0.2.1 and ends \"%s\"", want);
	g_free (want);
	CHECK (strstr (((FsIntelWinRule *) g_ptr_array_index (plan->rules, 0))
	               ->description, "Alpha") != NULL,
	       "intelwin plan: a rule's description names its list");
out:
	fs_intelwin_plan_free (plan);
	g_free (digest);

	/* The same rule set planned again: the same rules. */
	{
		FsIntelWinPlan *a = fs_intelwin_plan (rs, IW_GEN, 2, 1000);
		FsIntelWinPlan *b = fs_intelwin_plan (rs, IW_GEN2, 2, 1000);

		CHECK (a && b && g_strcmp0 (a->digest, b->digest) == 0 &&
		       g_strcmp0 (a->plan, b->plan) != 0,
		       "intelwin plan: another generation names other rules, "
		       "so its plan hash differs; the digest does not");
		fs_intelwin_plan_free (a);
		fs_intelwin_plan_free (b);
	}

	/* Refusals. */
	CHECK (fs_intelwin_plan (rs, "g0123ABCD", 2, 1000) == NULL &&
	       fs_intelwin_plan (rs, "x; rm", 2, 1000) == NULL &&
	       fs_intelwin_plan (rs, IW_GEN, 0, 1000) == NULL &&
	       fs_intelwin_plan (rs, IW_GEN, 2, 0) == NULL,
	       "intelwin plan: an invalid generation or a zero limit plans "
	       "nothing");
	{
		FsIntelSet *first = g_ptr_array_index (rs->sets, 0);
		gchar *saved = first->id;

		first->id = (gchar *) "../evil name";
		CHECK (fs_intelwin_plan (rs, IW_GEN, 2, 1000) == NULL,
		       "intelwin plan: a hand-filled set whose id is not valid "
		       "never becomes a rule name");
		first->id = (gchar *) "beta";
		CHECK (fs_intelwin_plan (rs, IW_GEN, 2, 1000) == NULL,
		       "intelwin plan: two sets with one id are refused");
		first->id = saved;
	}
	fs_intel_ruleset_free (rs);

	/* The empty rule set leaves no rule; a list emptied by
	 * subtraction leaves the manifest alone. */
	rs = fs_intel_ruleset_new ();
	plan = fs_intelwin_plan (rs, IW_GEN, FS_INTELWIN_MAX_TOKENS,
	                         FS_INTELWIN_MAX_CHARS);
	CHECK (plan != NULL && plan->rules->len == 0 && plan->digest != NULL,
	       "intelwin plan: the empty rule set has no rule at all");
	fs_intelwin_plan_free (plan);
	fs_intel_ruleset_add (rs, "emptied", "Emptied", FS_INTEL_DIR_BOTH,
	                      fs_range_set_new ());
	plan = fs_intelwin_plan (rs, IW_GEN, FS_INTELWIN_MAX_TOKENS,
	                         FS_INTELWIN_MAX_CHARS);
	CHECK (plan != NULL && plan->rules->len == 1 &&
	       strcmp (((FsIntelWinRule *) plan->rules->pdata[0])->name,
	               "SFW-TI manifest " IW_GEN) == 0,
	       "intelwin plan: a list with every address subtracted leaves "
	       "only the manifest, so it still reads as loaded");
	if (plan != NULL) {
		GPtrArray *seen = iw_seen_from_plan (plan, FALSE);
		FsIntelWinRead rd;

		fs_intelwin_read (seen, &rd);
		CHECK (rd.live == FS_INTEL_LIVE_PRESENT &&
		       g_strcmp0 (rd.digest, plan->digest) == 0,
		       "intelwin read: ... and reads back PRESENT with its digest");
		fs_intelwin_read_clear (&rd);
		g_ptr_array_unref (seen);
	}
	fs_intelwin_plan_free (plan);
	fs_intel_ruleset_free (rs);
}

/* The real limits, on lists the size of real feeds. */
static void
test_intelwin_limits (void)
{
	FsIntelRuleset *rs = fs_intel_ruleset_new ();
	FsRangeSet *v4 = fs_range_set_new ();
	FsRangeSet *v6 = fs_range_set_new ();
	FsIntelWinPlan *plan;
	guint rules4 = 0, rules6 = 0, max_tok = 0;
	gsize max_len = 0;
	guint64 tokens = 0;

	/* 2500 separate IPv4 addresses. */
	for (guint i = 0; i < 2500; i++)
		fs_range_set_add4 (v4, 0x0a000000u + i * 4, 0x0a000000u + i * 4);
	fs_range_set_normalize (v4);
	/* 1500 IPv6 ranges that print as long "a-b" tokens. */
	for (guint i = 0; i < 1500; i++) {
		FsU128 a = { G_GUINT64_CONSTANT (0x2001db8abcdef012) + i * 2,
		             G_GUINT64_CONSTANT (0x123456789abcdef1) };
		FsU128 b = { a.hi, G_GUINT64_CONSTANT (0xfedcba9876543210) };

		fs_range_set_add6 (v6, a, b);
	}
	fs_range_set_normalize (v6);
	fs_intel_ruleset_add (rs, "big4", "Big v4", FS_INTEL_DIR_IN, v4);
	fs_intel_ruleset_add (rs, "big6", "Big v6", FS_INTEL_DIR_IN, v6);

	plan = fs_intelwin_plan (rs, IW_GEN, FS_INTELWIN_MAX_TOKENS,
	                         FS_INTELWIN_MAX_CHARS);
	for (guint i = 0; plan != NULL && i < plan->rules->len; i++) {
		const FsIntelWinRule *r = g_ptr_array_index (plan->rules, i);

		if (r->family == FS_AF_NONE)
			continue;
		if (r->family == FS_AF_V4)
			rules4++;
		else
			rules6++;
		tokens += r->tokens;
		max_tok = MAX (max_tok, r->tokens);
		max_len = MAX (max_len, strlen (r->remote));
	}
	CHECK (plan != NULL && rules4 == 3 && tokens == 4000 &&
	       max_tok <= FS_INTELWIN_MAX_TOKENS &&
	       max_len <= FS_INTELWIN_MAX_CHARS,
	       "intelwin limits: 2500 IPv4 addresses take 3 rules, every "
	       "rule holds at most %u addresses and %u characters (most: %u, "
	       "%" G_GSIZE_FORMAT ")", FS_INTELWIN_MAX_TOKENS,
	       FS_INTELWIN_MAX_CHARS, max_tok, max_len);
	CHECK (rules6 >= 3,
	       "intelwin limits: 1500 long IPv6 ranges are split by "
	       "characters before they reach 1000 a rule (%u rules)", rules6);
	CHECK (plan != NULL && iw_rule (plan, "SFW-TI big4 in IPv4 3/3 " IW_GEN)
	       != NULL && iw_rule (plan, "SFW-TI big4 in IPv4 3/3 " IW_GEN)
	       ->tokens == 500,
	       "intelwin limits: the last chunk holds the remainder (500)");
	fs_intelwin_plan_free (plan);

	/* A cap smaller than one token: the token stands alone, never
	 * split. */
	plan = fs_intelwin_plan (rs, IW_GEN, 1000, 5);
	CHECK (plan != NULL && plan->rules->len == 4000 + 1,
	       "intelwin limits: a token longer than the character cap gets "
	       "a rule of its own, never cut");
	fs_intelwin_plan_free (plan);
	fs_intel_ruleset_free (rs);
}

static void
test_intelwin_parse_remote (void)
{
	FsRangeSet *s = fs_range_set_new ();
	gchar *text;

	CHECK (fs_intelwin_parse_remote ("10.0.0.0/255.0.0.0,"
	                                 "192.0.2.7/255.255.255.255,"
	                                 "203.0.113.10-203.0.113.20,"
	                                 "2001:db8::/32, 2001:db8:ffff::1", s),
	       "intelwin remote: dotted masks, a range, IPv6 and spaces "
	       "after commas are read");
	fs_range_set_normalize (s);
	text = fs_range_set_to_text (s);
	CHECK (g_strcmp0 (text, "10.0.0.0/8\n192.0.2.7\n"
	                        "203.0.113.10-203.0.113.20\n2001:db8::/32\n") == 0,
	       "intelwin remote: ... as the same addresses (%s)", text);
	g_free (text);
	fs_range_set_free (s);

	{
		static const gchar *const bad[] = {
			"*", "LocalSubnet", "DNS", "DefaultGateway", "Intranet",
			"", "1.2.3.4,,5.6.7.8", "1.2.3.4,", "1.2.3.4/255.0.255.0",
			"1.2.3.4/33", "example.com", "1.2.3.4,*",
		};
		gboolean all = TRUE;

		for (guint i = 0; i < G_N_ELEMENTS (bad); i++) {
			FsRangeSet *t = fs_range_set_new ();

			fs_range_set_add_text (t, "198.51.100.1");
			if (fs_intelwin_parse_remote (bad[i], t) ||
			    fs_range_set_count4 (t) != 1 ||
			    fs_range_set_count6 (t) != 0) {
				printf ("      accepted or touched: \"%s\"\n", bad[i]);
				all = FALSE;
			}
			fs_range_set_free (t);
		}
		CHECK (all && !fs_intelwin_parse_remote (NULL, NULL),
		       "intelwin remote: \"*\", keywords, empty tokens, a mask "
		       "with holes and names are refused, and the set is left "
		       "as it was");
	}
}

typedef void (*IwTamper) (GPtrArray *seen);

static void iw_t_drop_chunk (GPtrArray *s)
{ g_ptr_array_remove (s, iw_find (s, "SFW-TI alpha in IPv4 2/3 " IW_GEN)); }
static void iw_t_disable (GPtrArray *s)
{ iw_find (s, "SFW-TI alpha in IPv4 1/3 " IW_GEN)->enabled = FALSE; }
static void iw_t_allow (GPtrArray *s)
{ iw_find (s, "SFW-TI beta out IPv4 1/1 " IW_GEN)->action = 1; }
static void iw_t_direction (GPtrArray *s)
{ iw_find (s, "SFW-TI beta out IPv4 1/1 " IW_GEN)->direction = 1; }
static void iw_t_profile (GPtrArray *s)
{ iw_find (s, "SFW-TI alpha out IPv6 1/1 " IW_GEN)->profiles = 4; }
static void iw_t_protocol (GPtrArray *s)
{ iw_find (s, "SFW-TI alpha out IPv6 1/1 " IW_GEN)->protocol = 6; }
static void iw_t_local_port (GPtrArray *s)
{
	FsIntelWinSeen *x = iw_find (s, "SFW-TI alpha in IPv6 1/1 " IW_GEN);
	g_free (x->local_ports);
	x->local_ports = g_strdup ("443");
}
static void iw_t_local_addr (GPtrArray *s)
{
	FsIntelWinSeen *x = iw_find (s, "SFW-TI alpha in IPv6 1/1 " IW_GEN);
	g_free (x->local_addresses);
	x->local_addresses = g_strdup ("10.9.9.9");
}
static void iw_t_program (GPtrArray *s)
{
	FsIntelWinSeen *x = iw_find (s, "SFW-TI alpha in IPv4 3/3 " IW_GEN);
	x->application = g_strdup ("C:\\nothing.exe");
}
static void iw_t_remote_port (GPtrArray *s)
{
	FsIntelWinSeen *x = iw_find (s, "SFW-TI beta out IPv4 1/1 " IW_GEN);
	g_free (x->remote_ports);
	x->remote_ports = g_strdup ("443");
}
static void iw_t_service (GPtrArray *s)
{
	FsIntelWinSeen *x = iw_find (s, "SFW-TI beta out IPv4 1/1 " IW_GEN);
	g_free (x->service);
	x->service = g_strdup ("Dnscache");
}
static void iw_t_iftype (GPtrArray *s)
{
	FsIntelWinSeen *x = iw_find (s, "SFW-TI alpha in IPv4 3/3 " IW_GEN);
	g_free (x->interface_types);
	x->interface_types = g_strdup ("Wireless");
}
static void iw_t_ifaces (GPtrArray *s)
{ iw_find (s, "SFW-TI alpha in IPv4 3/3 " IW_GEN)->interfaces = TRUE; }
static void iw_t_conditions (GPtrArray *s)
{ iw_find (s, "SFW-TI alpha in IPv4 3/3 " IW_GEN)->conditions = TRUE; }
static void iw_t_remote_less (GPtrArray *s)
{
	FsIntelWinSeen *x = iw_find (s, "SFW-TI alpha in IPv4 1/3 " IW_GEN);
	gchar *comma = strchr (x->remote_addresses, ',');
	if (comma != NULL)
		*comma = '\0';   /* one address fewer */
}
static void iw_t_remote_any (GPtrArray *s)
{
	FsIntelWinSeen *x = iw_find (s, "SFW-TI alpha in IPv4 1/3 " IW_GEN);
	g_free (x->remote_addresses);
	x->remote_addresses = g_strdup ("*");
}
static void iw_t_remote_mixed (GPtrArray *s)
{
	FsIntelWinSeen *x = iw_find (s, "SFW-TI beta out IPv4 1/1 " IW_GEN);
	gchar *more = g_strconcat (x->remote_addresses, ",2001:db8::1", NULL);
	g_free (x->remote_addresses);
	x->remote_addresses = more;
}
static void iw_t_swap (GPtrArray *s)
{
	/* Same addresses overall, moved between two rules. */
	FsIntelWinSeen *a = iw_find (s, "SFW-TI alpha in IPv4 1/3 " IW_GEN);
	FsIntelWinSeen *b = iw_find (s, "SFW-TI alpha in IPv4 2/3 " IW_GEN);
	gchar *t = a->remote_addresses;
	a->remote_addresses = b->remote_addresses;
	b->remote_addresses = t;
}
static void iw_t_extra (GPtrArray *s)
{
	FsIntelWinSeen *x = fs_intelwin_seen_new ();
	FsIntelWinSeen *like = iw_find (s, "SFW-TI beta out IPv4 1/1 " IW_GEN);

	*x = *like;
	x->name = g_strdup ("SFW-TI gamma out IPv4 1/1 " IW_GEN);
	x->description = g_strdup (like->description);
	x->grouping = g_strdup (like->grouping);
	x->local_addresses = g_strdup (like->local_addresses);
	x->remote_addresses = g_strdup ("8.8.8.8");
	x->interface_types = g_strdup (like->interface_types);
	g_ptr_array_add (s, x);
}
static void iw_t_foreign (GPtrArray *s)
{
	FsIntelWinSeen *x = fs_intelwin_seen_new ();

	x->name = g_strdup ("Someone's rule");
	x->grouping = g_strdup (FS_INTELWIN_GROUP);
	x->action = 1;
	x->enabled = TRUE;
	g_ptr_array_add (s, x);
}
static void iw_t_old_gen (GPtrArray *s)
{
	FsIntelWinSeen *x = fs_intelwin_seen_new ();

	x->name = g_strdup ("SFW-TI alpha in IPv4 1/1 " IW_GEN2);
	x->grouping = g_strdup (FS_INTELWIN_GROUP);
	x->direction = 1;
	x->enabled = TRUE;
	x->profiles = 7;
	x->protocol = 256;
	x->remote_addresses = g_strdup ("192.0.2.7");
	g_ptr_array_add (s, x);
}
static void iw_t_no_manifest (GPtrArray *s)
{ g_ptr_array_remove (s, iw_find (s, "SFW-TI manifest " IW_GEN)); }
static void iw_t_manifest_count (GPtrArray *s)
{
	FsIntelWinSeen *m = iw_find (s, "SFW-TI manifest " IW_GEN);
	gchar *at = g_strrstr (m->description, "rules:");
	gchar *edited = g_strndup (m->description,
	                           (gsize) (at - m->description));
	g_free (m->description);
	m->description = g_strconcat (edited, "rules:8", NULL);
	g_free (edited);
	/* And one rule gone, so the count would match. */
	g_ptr_array_remove (s, iw_find (s, "SFW-TI beta out IPv4 1/1 " IW_GEN));
}
static void iw_t_rename (GPtrArray *s)
{
	FsIntelWinSeen *x = iw_find (s, "SFW-TI beta out IPv4 1/1 " IW_GEN);
	g_free (x->name);
	x->name = g_strdup ("SFW-TI betb out IPv4 1/1 " IW_GEN);
}
static void iw_t_regroup (GPtrArray *s)
{
	FsIntelWinSeen *x = iw_find (s, "SFW-TI beta out IPv4 1/1 " IW_GEN);
	g_free (x->grouping);
	x->grouping = g_strdup ("Other");
}

static void
test_intelwin_read (void)
{
	FsIntelRuleset *rs = iw_ruleset ();
	FsIntelWinPlan *plan = fs_intelwin_plan (rs, IW_GEN, 2, 1000);
	GPtrArray *seen;
	FsIntelWinRead rd;
	static const struct { IwTamper fn; const gchar *what; } t[] = {
		{ iw_t_drop_chunk,     "a chunk deleted" },
		{ iw_t_disable,        "a rule disabled" },
		{ iw_t_allow,          "a rule turned into allow" },
		{ iw_t_direction,      "a rule's direction flipped" },
		{ iw_t_profile,        "a rule narrowed to the Public profile" },
		{ iw_t_protocol,       "a rule narrowed to TCP" },
		{ iw_t_local_port,     "a rule narrowed to local port 443" },
		{ iw_t_local_addr,     "a rule narrowed to one local address" },
		{ iw_t_program,        "a rule narrowed to one program" },
		{ iw_t_remote_port,    "a rule narrowed to remote port 443" },
		{ iw_t_service,        "a rule narrowed to one service" },
		{ iw_t_iftype,         "a rule narrowed to wireless adapters" },
		{ iw_t_ifaces,         "a rule narrowed to named adapters" },
		{ iw_t_conditions,     "a rule given a user/app/IPsec condition" },
		{ iw_t_remote_less,    "an address taken out of a rule" },
		{ iw_t_remote_any,     "a rule's addresses set to *" },
		{ iw_t_remote_mixed,   "an IPv6 address added to an IPv4 rule" },
		{ iw_t_swap,           "addresses moved between two chunks" },
		{ iw_t_extra,          "a rule added with a name like ours" },
		{ iw_t_foreign,        "someone else's rule put in our group" },
		{ iw_t_old_gen,        "a rule left from an earlier apply" },
		{ iw_t_no_manifest,    "the manifest deleted" },
		{ iw_t_manifest_count, "the manifest's count edited to match a "
		                       "deleted rule" },
		{ iw_t_rename,         "a rule renamed" },
		{ iw_t_regroup,        "a rule moved out of our group" },
	};

	g_return_if_fail (plan != NULL);

	fs_intelwin_read (NULL, &rd);
	CHECK (rd.live == FS_INTEL_LIVE_ABSENT && rd.ours == 0,
	       "intelwin read: no rule at all is ABSENT");
	fs_intelwin_read_clear (&rd);

	/* Someone else's rules, even with our prefix, are not ours. */
	seen = g_ptr_array_new_with_free_func (fs_intelwin_seen_free);
	{
		FsIntelWinSeen *x = fs_intelwin_seen_new ();

		x->name = g_strdup ("SFW-TI alpha in IPv4 1/1 " IW_GEN);
		x->grouping = g_strdup ("Somebody else");
		g_ptr_array_add (seen, x);
		x = fs_intelwin_seen_new ();
		x->name = g_strdup ("StockFW-in-ssh");
		g_ptr_array_add (seen, x);
	}
	fs_intelwin_read (seen, &rd);
	CHECK (rd.live == FS_INTEL_LIVE_ABSENT,
	       "intelwin read: rules outside our group are never counted, "
	       "whatever their names");
	fs_intelwin_read_clear (&rd);
	g_ptr_array_unref (seen);

	seen = iw_seen_from_plan (plan, FALSE);
	fs_intelwin_read (seen, &rd);
	CHECK (rd.live == FS_INTEL_LIVE_PRESENT &&
	       g_strcmp0 (rd.digest, plan->digest) == 0 &&
	       g_strcmp0 (rd.gen, IW_GEN) == 0 && rd.ours == plan->rules->len,
	       "intelwin read: the rules as written read back PRESENT with "
	       "the plan's digest and generation");
	fs_intelwin_read_clear (&rd);
	g_ptr_array_unref (seen);

	seen = iw_seen_from_plan (plan, TRUE);
	/* Windows also hands rules back in its own order. */
	for (guint i = 0; i < seen->len / 2; i++) {
		gpointer a = seen->pdata[i];

		seen->pdata[i] = seen->pdata[seen->len - 1 - i];
		seen->pdata[seen->len - 1 - i] = a;
	}
	{
		FsIntelWinSeen *x = fs_intelwin_seen_new ();

		x->name = g_strdup ("Core Networking - DNS (UDP-Out)");
		x->grouping = g_strdup ("@FirewallAPI.dll,-25000");
		x->action = 1;
		g_ptr_array_add (seen, x);
	}
	fs_intelwin_read (seen, &rd);
	CHECK (rd.live == FS_INTEL_LIVE_PRESENT &&
	       g_strcmp0 (rd.digest, plan->digest) == 0,
	       "intelwin read: still PRESENT when Windows writes IPv4 with "
	       "dotted masks, reorders tokens and rules, and other rules "
	       "exist (e.g. \"%s\")",
	       ((FsIntelWinSeen *) iw_find (seen, "SFW-TI beta out IPv4 1/1 "
	                                    IW_GEN))->remote_addresses);
	fs_intelwin_read_clear (&rd);
	g_ptr_array_unref (seen);

	for (guint i = 0; i < G_N_ELEMENTS (t); i++) {
		seen = iw_seen_from_plan (plan, FALSE);
		t[i].fn (seen);
		fs_intelwin_read (seen, &rd);
		CHECK (rd.live == FS_INTEL_LIVE_PARTIAL && rd.digest == NULL &&
		       rd.why != NULL && rd.why[0] != '\0',
		       "intelwin read: %s is PARTIAL, never the digest (%s)",
		       t[i].what, rd.why ? rd.why : "no reason");
		fs_intelwin_read_clear (&rd);
		g_ptr_array_unref (seen);
	}

	/* Two applies' rules: both generations are reported, so the backend
	 * can remove the one it is not keeping. */
	seen = iw_seen_from_plan (plan, FALSE);
	iw_t_old_gen (seen);
	fs_intelwin_read (seen, &rd);
	CHECK (rd.gens != NULL && rd.gens->len == 2,
	       "intelwin read: every generation on the firewall is listed");
	fs_intelwin_read_clear (&rd);
	g_ptr_array_unref (seen);

	CHECK (g_strcmp0 (fs_intelwin_name_gen ("SFW-TI x in IPv4 1/1 "
	                                        IW_GEN), IW_GEN) == 0 &&
	       fs_intelwin_name_gen ("StockFW-in " IW_GEN) == NULL &&
	       fs_intelwin_name_gen ("SFW-TI x in IPv4 1/1 g0123ABCD") == NULL &&
	       fs_intelwin_name_gen (NULL) == NULL,
	       "intelwin: a name's generation is read only from names "
	       "StockFW writes");
	fs_intelwin_plan_free (plan);
	fs_intel_ruleset_free (rs);
}

static void
test_intelwin_force (void)
{
	FsIntelWinForce f;
	gchar *s;

#define IW_FORCE_OK() do { \
	memset (&f, 0, sizeof f); \
	f.service_known = TRUE; f.service_running = TRUE; \
	f.policy_read = TRUE; f.gp_read = TRUE; \
	f.current = FS_INTELWIN_PROFILE_PUBLIC; \
	f.enabled[0] = f.enabled[1] = f.enabled[2] = 1; \
} while (0)

	IW_FORCE_OK ();
	s = fs_intelwin_not_in_force (&f);
	CHECK (s == NULL, "intelwin force: firewall on for the profile in use "
	       "is in force");
	g_free (s);

	IW_FORCE_OK ();
	f.service_running = FALSE;
	s = fs_intelwin_not_in_force (&f);
	CHECK (s && strstr (s, "MpsSvc") && strstr (s, "not running"),
	       "intelwin force: the service stopped says so (%s)", s);
	g_free (s);

	IW_FORCE_OK ();
	f.gp_override = TRUE;
	s = fs_intelwin_not_in_force (&f);
	CHECK (s && strstr (s, "Group Policy"),
	       "intelwin force: Group Policy that ignores local rules says so "
	       "(%s)", s);
	g_free (s);

	IW_FORCE_OK ();
	f.enabled[2] = 0;
	s = fs_intelwin_not_in_force (&f);
	CHECK (s && strstr (s, "off for the Public profile") &&
	       strstr (s, "block nothing"),
	       "intelwin force: firewall off for the only profile in use "
	       "(%s)", s);
	g_free (s);

	IW_FORCE_OK ();
	f.current = FS_INTELWIN_PROFILE_DOMAIN | FS_INTELWIN_PROFILE_PUBLIC;
	f.enabled[2] = 0;
	s = fs_intelwin_not_in_force (&f);
	CHECK (s && strstr (s, "Public") && strstr (s, "on that network"),
	       "intelwin force: off for one of two profiles in use names it "
	       "(%s)", s);
	g_free (s);

	IW_FORCE_OK ();
	f.current = FS_INTELWIN_PROFILE_PRIVATE | FS_INTELWIN_PROFILE_PUBLIC;
	f.enabled[1] = f.enabled[2] = 0;
	s = fs_intelwin_not_in_force (&f);
	CHECK (s && strstr (s, "Private and Public profiles"),
	       "intelwin force: two profiles off are both named (%s)", s);
	g_free (s);

	IW_FORCE_OK ();
	f.enabled[1] = 0;   /* Private off, but only Public in use */
	s = fs_intelwin_not_in_force (&f);
	CHECK (s == NULL, "intelwin force: a profile no network has does not "
	       "matter");
	g_free (s);

	IW_FORCE_OK ();
	f.excluded[2] = 1;
	s = fs_intelwin_not_in_force (&f);
	CHECK (s && strstr (s, "excluded"),
	       "intelwin force: adapters excluded from the profile in use "
	       "(%s)", s);
	g_free (s);

	/* Review W5: what cannot be read is never "in force". */
	IW_FORCE_OK ();
	f.policy_read = FALSE;
	s = fs_intelwin_not_in_force (&f);
	CHECK (s && strstr (s, "cannot read") &&
	       strstr (s, "does not report the blocklists as in force"),
	       "intelwin force: profiles in use that could not be read are "
	       "never in force (%s)", s);
	g_free (s);

	IW_FORCE_OK ();
	f.enabled[2] = -1;
	s = fs_intelwin_not_in_force (&f);
	CHECK (s && strstr (s, "cannot read") && strstr (s, "Public profile"),
	       "intelwin force: a profile in use whose firewall switch could "
	       "not be read is never in force (%s)", s);
	g_free (s);

	IW_FORCE_OK ();
	f.enabled[0] = -1;   /* Domain unreadable, but only Public in use */
	s = fs_intelwin_not_in_force (&f);
	CHECK (s == NULL, "intelwin force: an unreadable profile no network "
	       "has does not matter");
	g_free (s);

	IW_FORCE_OK ();
	f.current = FS_INTELWIN_PROFILE_PRIVATE | FS_INTELWIN_PROFILE_PUBLIC;
	f.enabled[1] = -1;
	f.enabled[2] = 0;
	s = fs_intelwin_not_in_force (&f);
	CHECK (s && strstr (s, "off for the Public profile"),
	       "intelwin force: a profile known to be off is named before one "
	       "that could not be read (%s)", s);
	g_free (s);

	IW_FORCE_OK ();
	f.gp_read = FALSE;
	s = fs_intelwin_not_in_force (&f);
	CHECK (s && strstr (s, "cannot read"),
	       "intelwin force: a Group Policy state that could not be read is "
	       "never in force (%s)", s);
	g_free (s);
#undef IW_FORCE_OK
}

/* Review of Round 3 on Windows (W3, W6): the pure pieces the backend's
 * fixes rest on. */
static void
test_intelwin_review (void)
{
	FsIntelRuleset *rs = iw_ruleset ();
	FsIntelWinPlan *plan = fs_intelwin_plan (rs, IW_GEN, 2, 1000);
	GPtrArray *seen;
	gchar *a, *b;

	g_return_if_fail (plan != NULL);

	/* W6: after taking a failed apply's rules out again, the backend
	 * counts what of that generation is still there. */
	seen = iw_seen_from_plan (plan, FALSE);
	CHECK (fs_intelwin_count_gen (seen, IW_GEN) == plan->rules->len &&
	       fs_intelwin_count_gen (seen, IW_GEN2) == 0,
	       "intelwin review: every rule of a generation is counted, none "
	       "of another");
	/* A foreign rule first in the group, and an earlier apply's rule:
	 * neither hides the new generation, nor counts as it. */
	{
		FsIntelWinSeen *x = fs_intelwin_seen_new ();

		x->name = g_strdup ("Someone's rule");
		x->grouping = g_strdup (FS_INTELWIN_GROUP);
		g_ptr_array_insert (seen, 0, x);
	}
	iw_t_old_gen (seen);
	CHECK (fs_intelwin_count_gen (seen, IW_GEN) == plan->rules->len &&
	       fs_intelwin_count_gen (seen, IW_GEN2) == 1,
	       "intelwin review: rules of a generation are counted past a "
	       "foreign rule in the group and an earlier apply's rule");
	g_ptr_array_unref (seen);
	seen = iw_seen_from_plan (plan, FALSE);
	for (guint i = 0; i < seen->len; i++) {
		FsIntelWinSeen *x = g_ptr_array_index (seen, i);

		g_free (x->grouping);
		x->grouping = g_strdup ("Other");
	}
	CHECK (fs_intelwin_count_gen (seen, IW_GEN) == 0 &&
	       fs_intelwin_count_gen (NULL, IW_GEN) == 0 &&
	       fs_intelwin_count_gen (seen, NULL) == 0,
	       "intelwin review: rules outside the group are never counted");
	g_ptr_array_unref (seen);

	/* W6: names that differ only in case share a key, so a removal
	 * renames the rule first instead of trusting Remove's matching. */
	a = fs_intelwin_name_key ("SFW-TI alpha in IPv4 1/1 " IW_GEN);
	b = fs_intelwin_name_key ("sfw-ti ALPHA in ipv4 1/1 G0123ABCD");
	CHECK (a != NULL && g_strcmp0 (a, b) == 0,
	       "intelwin review: rule names that differ only in case share "
	       "one key");
	g_free (b);
	b = fs_intelwin_name_key ("SFW-TI alpha in IPv4 2/2 " IW_GEN);
	CHECK (g_strcmp0 (a, b) != 0 && fs_intelwin_name_key (NULL) == NULL,
	       "intelwin review: different names keep different keys");
	g_free (a);
	g_free (b);

	/* W3: the policy lists its own rules by name; a blocklist rule is
	 * never one of them. */
	CHECK (fs_netsh_rule_name_is_ours ("StockFW- Allow SSH -inbound-") &&
	       fs_netsh_rule_name_is_ours ("StockFW Allow SSH") &&
	       !fs_netsh_rule_name_is_ours ("SFW-TI alpha in IPv4 1/1 "
	                                     IW_GEN) &&
	       !fs_netsh_rule_name_is_ours ("SFW-TI manifest " IW_GEN) &&
	       !fs_netsh_rule_name_is_ours ("Core Networking - DNS") &&
	       !fs_netsh_rule_name_is_ours (NULL),
	       "intelwin review: the policy's rule names are told apart from "
	       "the blocklist rules'");

	/* W3: why the policy no longer lists through netsh's printout.  A
	 * rule set at the interval limit written as Windows rules: netsh
	 * `show rule name=all' prints every RemoteIP, and this much text
	 * alone is past the 16 MiB the backend reads of a child's output. */
	{
		FsIntelRuleset *big = fs_intel_ruleset_new ();
		FsRangeSet *v6 = fs_range_set_new ();
		FsIntelWinPlan *bp;
		guint64 chars = 0;
		guint n = FS_INTEL_MAX_INTERVALS / 2;

		for (guint i = 0; i < n; i++) {
			FsU128 lo = { G_GUINT64_CONSTANT (0x2001db8abcdef012) + i * 2,
			              G_GUINT64_CONSTANT (0x123456789abcdef1) };
			FsU128 hi = { lo.hi, G_GUINT64_CONSTANT (0xfedcba9876543210) };

			fs_range_set_add6 (v6, lo, hi);
		}
		fs_range_set_normalize (v6);
		fs_intel_ruleset_add (big, "huge", "Huge", FS_INTEL_DIR_BOTH, v6);
		bp = fs_intelwin_plan (big, IW_GEN, FS_INTELWIN_MAX_TOKENS,
		                       FS_INTELWIN_MAX_CHARS);
		for (guint i = 0; bp != NULL && i < bp->rules->len; i++)
			chars += strlen (((FsIntelWinRule *)
			                  g_ptr_array_index (bp->rules, i))->remote);
		CHECK (bp != NULL && chars > 16u * 1024 * 1024,
		       "intelwin review: %u long IPv6 ranges both ways print %"
		       G_GUINT64_FORMAT " characters of addresses in %u rules, "
		       "more than the 16 MiB a netsh listing may hold", n, chars,
		       bp ? bp->rules->len : 0);
		fs_intelwin_plan_free (bp);
		fs_intel_ruleset_free (big);
	}

	fs_intelwin_plan_free (plan);
	fs_intel_ruleset_free (rs);
}

static void
test_hostnet_onlink (void)
{
	const guint8 a4[4] = { 192, 168, 1, 37 };
	const guint8 a6[16] = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0,
	                        0x12, 0x34, 0, 0, 0, 0, 0, 1 };
	FsRangeSet *s;
	gchar *text;

	s = fs_range_set_new ();
	fs_hostnet_add_onlink (s, a4, 4, 24);
	fs_hostnet_add_onlink (s, a6, 16, 64);
	fs_range_set_normalize (s);
	text = fs_range_set_to_text (s);
	CHECK (g_strcmp0 (text, "192.168.1.0/24\nfe80::/64\n") == 0,
	       "hostnet onlink: an address and its OnLinkPrefixLength give "
	       "the block it lies in (%s)", text);
	g_free (text);
	fs_range_set_free (s);

	s = fs_range_set_new ();
	fs_hostnet_add_onlink (s, a4, 4, 0);
	fs_hostnet_add_onlink (s, a4, 4, 33);
	fs_hostnet_add_onlink (s, a6, 16, 200);
	fs_hostnet_add_onlink (s, a4, 3, 8);
	fs_range_set_normalize (s);
	text = fs_range_set_to_text (s);
	CHECK (g_strcmp0 (text, "192.168.1.37\nfe80::1234:0:0:1\n") == 0,
	       "hostnet onlink: a zero or too-wide prefix keeps the address "
	       "alone, never everything; a bad length adds nothing (%s)",
	       text);
	g_free (text);
	fs_range_set_free (s);

	s = fs_range_set_new ();
	fs_hostnet_add_onlink (s, a4, 4, 30);
	text = fs_range_set_to_text (s);
	CHECK (g_strcmp0 (text, "192.168.1.36/30\n") == 0,
	       "hostnet onlink: a prefix inside a byte (%s)", text);
	g_free (text);
	fs_range_set_free (s);
}

/* [ rm_tree ] -- remove the run's private directory and everything
 * under it.  Symbolic links are removed, never followed. */
static void
rm_tree (const gchar *path)
{
	GDir *dir;
	const gchar *name;

	if (!g_file_test (path, G_FILE_TEST_IS_SYMLINK) &&
	    g_file_test (path, G_FILE_TEST_IS_DIR) &&
	    (dir = g_dir_open (path, 0, NULL)) != NULL) {
		while ((name = g_dir_read_name (dir)) != NULL) {
			gchar *child = g_build_filename (path, name, NULL);

			rm_tree (child);
			g_free (child);
		}
		g_dir_close (dir);
		g_rmdir (path);
		return;
	}
	g_remove (path);
}

/* [ make_run_dir ]
 * Every scratch path this program uses (the settings and audit files
 * under the config dir, and the fixed-name test directories such as
 * stockfw-behavior-test) lives under g_get_tmp_dir ().  A shared /tmp
 * that a root run, or another session, filled with root-owned copies
 * made a later normal-user run fail by the dozen and then crash.  So
 * the temp dir is pointed at a fresh directory only this run owns,
 * BEFORE GLib first reads and caches it, and removed at the end. */
static gchar *
make_run_dir (void)
{
#ifdef G_OS_WIN32
	const gchar *base = g_getenv ("TEMP");

	if (base == NULL || *base == '\0')
		base = g_getenv ("TMP");
	if (base == NULL || *base == '\0')
		base = ".";
#else
	const gchar *base = g_getenv ("TMPDIR");

	if (base == NULL || *base == '\0')
		base = "/tmp";
#endif
	gchar *tmpl = g_build_filename (base, "stockfw-core-XXXXXX", NULL);

	if (g_mkdtemp_full (tmpl, 0700) == NULL) {
		fprintf (stderr, "cannot make a private test directory under "
		         "%s\n", base);
		exit (2);
	}
#ifdef G_OS_WIN32
	g_setenv ("TEMP", tmpl, TRUE);
	g_setenv ("TMP", tmpl, TRUE);
#else
	g_setenv ("TMPDIR", tmpl, TRUE);
#endif
	return tmpl;
}

/* SECURITY-1 and SECURITY-2 (1.0.7 release review): where the system
 * tools come from.  Root never searches the PATH it was given; Windows
 * runs a bare tool name from System32, never through CreateProcess's
 * search of the program's and the current folder. */
static void test_toolpath (void)
{
	gchar *t;

	/* Windows: the pure mapping. */
	t = fs_toolpath_windows ("C:\\Windows\\system32", "netsh.exe");
	CHECK (g_strcmp0 (t, "C:\\Windows\\system32\\netsh.exe") == 0,
	       "toolpath: netsh.exe runs from System32 (%s)", t);
	g_free (t);
	t = fs_toolpath_windows ("C:\\Windows\\system32\\", "wevtutil.exe");
	CHECK (g_strcmp0 (t, "C:\\Windows\\system32\\wevtutil.exe") == 0,
	       "toolpath: a trailing backslash is not doubled (%s)", t);
	g_free (t);
	t = fs_toolpath_windows ("C:\\Windows\\system32", "auditpol.exe");
	CHECK (g_strcmp0 (t, "C:\\Windows\\system32\\auditpol.exe") == 0,
	       "toolpath: auditpol.exe runs from System32 (%s)", t);
	g_free (t);
	t = fs_toolpath_windows ("C:\\Windows\\system32",
	                         "C:\\Windows\\system32\\curl.exe");
	CHECK (g_strcmp0 (t, "C:\\Windows\\system32\\curl.exe") == 0,
	       "toolpath: a full path is kept (%s)", t);
	g_free (t);
	t = fs_toolpath_windows ("C:\\Windows\\system32", "\\\\srv\\s\\x.exe");
	CHECK (g_strcmp0 (t, "\\\\srv\\s\\x.exe") == 0,
	       "toolpath: a UNC path is kept (%s)", t);
	g_free (t);
	{
		static const gchar *const refused[] = {
			"bin\\netsh.exe", ".\\netsh.exe", "C:netsh.exe",
			"tools/netsh.exe", "", ".", "..", NULL
		};

		for (guint i = 0; refused[i] != NULL; i++) {
			t = fs_toolpath_windows ("C:\\Windows\\system32",
			                         refused[i]);
			CHECK (t == NULL, "toolpath: [%s] is refused, never "
			       "searched for (%s)", refused[i], t);
			g_free (t);
		}
	}
	t = fs_toolpath_windows (NULL, "netsh.exe");
	CHECK (t == NULL, "toolpath: no System32 known, nothing runs");
	g_free (t);
	t = fs_toolpath_windows ("", "netsh.exe");
	CHECK (t == NULL, "toolpath: an empty System32 runs nothing");
	g_free (t);

#ifndef G_OS_WIN32
	{
		gchar *dir = g_dir_make_tmp ("toolpath-XXXXXX", NULL);
		gchar *bin = g_build_filename (dir, "bin", NULL);
		gchar *tool = g_build_filename (bin, "iptables-restore", NULL);
		gchar *plain = g_build_filename (bin, "nft", NULL);
		gchar *dirs = g_strdup_printf ("relative:.::%s:/usr/bin", bin);
		const gchar *old = g_getenv ("PATH");
		gchar *saved = g_strdup (old);
		gchar *p;

		g_mkdir_with_parents (bin, 0700);
		g_file_set_contents (tool, "#!/bin/sh\nexit 0\n", -1, NULL);
		g_chmod (tool, 0755);
		g_file_set_contents (plain, "not a program\n", -1, NULL);
		g_chmod (plain, 0644);

		p = fs_toolpath_search ("iptables-restore", dirs);
		CHECK (g_strcmp0 (p, tool) == 0,
		       "toolpath: search takes the first absolute directory "
		       "holding the tool (%s)", p);
		g_free (p);
		p = fs_toolpath_search ("nft", bin);
		CHECK (p == NULL, "toolpath: a file that is not executable "
		       "is not a tool (%s)", p);
		g_free (p);
		p = fs_toolpath_search ("../bin/iptables-restore", bin);
		CHECK (p == NULL, "toolpath: a name with a folder is refused");
		g_free (p);
		p = fs_toolpath_search ("iptables-restore", "bin:.:");
		CHECK (p == NULL, "toolpath: relative and empty entries "
		       "(the current directory) are never searched (%s)", p);
		g_free (p);

		/* The fake tool first on PATH, as `sudo -E' would pass it. */
		g_setenv ("PATH", bin, TRUE);
		p = fs_toolpath_find ("iptables-restore");
		if (geteuid () == 0) {
			CHECK (p == NULL || (!g_str_has_prefix (p, dir) &&
			       (g_str_has_prefix (p, "/usr/sbin/") ||
			        g_str_has_prefix (p, "/usr/bin/") ||
			        g_str_has_prefix (p, "/sbin/") ||
			        g_str_has_prefix (p, "/bin/"))),
			       "toolpath: as root the PATH is not searched; "
			       "the tool comes from the system directories (%s)",
			       p);
			CHECK (strcmp (fs_toolpath_where (),
			               "in /usr/sbin, /usr/bin, /sbin or /bin") == 0,
			       "toolpath: the messages name those directories");
		} else {
			CHECK (g_strcmp0 (p, tool) == 0,
			       "toolpath: not root, the PATH is used (%s)", p);
			CHECK (strcmp (fs_toolpath_where (), "on PATH") == 0,
			       "toolpath: the messages say PATH");
		}
		g_free (p);
		p = fs_toolpath_find ("/tmp/iptables-restore");
		CHECK (p == NULL, "toolpath: find takes a bare name only");
		g_free (p);
		g_setenv ("PATH", saved != NULL ? saved : "/usr/bin:/bin", TRUE);

		g_unlink (tool);
		g_unlink (plain);
		g_rmdir (bin);
		g_rmdir (dir);
		g_free (saved);
		g_free (dirs);
		g_free (plain);
		g_free (tool);
		g_free (bin);
		g_free (dir);
	}
#endif
}

/* === WP-B === */
/* Policy truth and safe changes (cli-plan.md WP-B): the problem report
 * of the policy loader, the apply gate with the firewall stopped, and
 * the lockout guard. */

/* [ test_policy_load_report ]
 * Each line that is not a rule comes back with its file, its line
 * number and a reason in words; the rules around it still load. */
static void test_policy_load_report (void)
{
	gchar *dir = g_build_filename (g_get_tmp_dir (), "stockfw-wpb-report",
	                               NULL);
	gchar *old = g_strdup (g_getenv ("STOCKFW_RULES_DIR"));
	gchar *path;
	FsPolicy *policy = fs_policy_new ();
	GPtrArray *problems = NULL;
	const FsPolicyProblem *p;
	gint malformed = -1;

	g_setenv ("STOCKFW_RULES_DIR", dir, TRUE);
	path = fs_util_rules_path ("inbound/allow-service");
	fs_util_ensure_parent_dir (path);
	g_file_set_contents (path,
		"SSH, 22, Anyone, fine\n"
		"garbage line without commas\n"
		"FTP, 99999, Anyone,\n"
		"SSH,,Anyone\n"
		"Frobnicator,,Anyone\n", -1, NULL);

	CHECK (fs_policy_load_report (policy, &problems),
	       "report: the file loads");
	CHECK (problems != NULL && problems->len == 3,
	       "report: three lines are not rules (got %u)",
	       problems != NULL ? problems->len : 0);
	CHECK (fs_policy_count (policy, FS_RULE_INBOUND_ALLOW_SERVICE) == 2,
	       "report: the good row and the portless known service load "
	       "(got %u)", fs_policy_count (policy,
	                                    FS_RULE_INBOUND_ALLOW_SERVICE));
	if (problems != NULL && problems->len == 3) {
		p = g_ptr_array_index (problems, 0);
		CHECK (p->line == 2 &&
		       g_strcmp0 (p->file, "inbound/allow-service") == 0 &&
		       g_strcmp0 (p->reason,
		                  "expected NAME, PORT, FOR (no commas)") == 0 &&
		       g_strcmp0 (p->text, "garbage line without commas") == 0,
		       "report: line 2 has no commas (%u, %s)", p->line,
		       p->reason);
		p = g_ptr_array_index (problems, 1);
		CHECK (p->line == 3 &&
		       g_strcmp0 (p->reason,
		                  "port \"99999\" is out of range (1-65535)") == 0,
		       "report: line 3's port is out of range (%u, %s)",
		       p->line, p->reason);
		p = g_ptr_array_index (problems, 2);
		CHECK (p->line == 5 &&
		       g_strcmp0 (p->reason, "no port, and \"Frobnicator\" is "
		                  "not a known service") == 0,
		       "report: line 5 names no port and no known service "
		       "(%u, %s)", p->line, p->reason);
	}
	g_ptr_array_unref (problems);

	/* The old entry point counts the same lines. */
	CHECK (fs_policy_load (policy, &malformed) && malformed == 3,
	       "report: fs_policy_load counts the same three (got %d)",
	       malformed);

	/* The journal keeps the F-1 check only: a portless row a 1.0.7
	 * apply recorded must not make the boot start refuse (Q6). */
	{
		FsRule *r = fs_rule_from_csv (FS_RULE_INBOUND_ALLOW_SERVICE,
		                              "Frobnicator,,Anyone");

		CHECK (!fs_rule_fields_sane (r) && fs_rule_addresses_sane (r),
		       "report: a portless unknown service is not a policy row, "
		       "but its addresses are sane for the journal");
		fs_rule_free (r);
	}

	fs_policy_free (policy);
	g_free (path);
	if (old != NULL)
		g_setenv ("STOCKFW_RULES_DIR", old, TRUE);
	else
		g_unsetenv ("STOCKFW_RULES_DIR");
	g_free (old);
	g_free (dir);
}

static FsFirewallState wpb_state = FS_FW_RUNNING;
static FsFirewallState wpb_get_state (void) { return wpb_state; }

static const FsBackend fake_backend_stateful = {
	.name = "fake-state",
	.display_name = "scripted fake backend that reads its state",
	.start_applies_policy = TRUE,
	.available = fake_available,
	.get_state = wpb_get_state,
	.apply_rules = fake_apply_rules,
	.apply_delta = fake_apply_delta,
};

/* [ test_apply_while_stopped ]
 * The journal says what the last apply put live, not what is live now.
 * With the firewall stopped the gate must load the whole policy (which
 * starts it) instead of finding "no change" against the journal. */
static void test_apply_while_stopped (void)
{
	gchar *dir = g_build_filename (g_get_tmp_dir (), "stockfw-wpb-a1",
	                               NULL);
	gchar *file = g_build_filename (dir, "applied.csv", NULL);
	gchar *audit_file = g_build_filename (dir, "audit.log", NULL);
	FsPolicy *policy;
	FsApplyOutcome *o;
	gchar *log;

	g_mkdir_with_parents (dir, 0700);
	remove (file);
	remove (audit_file);
	g_setenv ("STOCKFW_APPLIED_FILE", file, TRUE);
	g_setenv ("STOCKFW_AUDIT_FILE", audit_file, TRUE);
	fake_reset ();
	policy = gate_policy_two ();

	/* Running: the first apply is whole, the second finds no change. */
	wpb_state = FS_FW_RUNNING;
	o = fs_policy_apply_safe (&fake_backend_stateful, policy, "wpb", NULL,
	                          NULL);
	CHECK (o->applied && fake_full_calls == 1,
	       "A1: the first apply goes out whole");
	fs_apply_outcome_free (o);
	o = fs_policy_apply_safe (&fake_backend_stateful, policy, "wpb", NULL,
	                          NULL);
	CHECK (o->applied && o->narrow && fake_full_calls == 1 &&
	       fake_delta_calls == 0 && o->firewall_was == FS_FW_RUNNING,
	       "A1: running and unchanged: the narrow no-change path, the "
	       "backend untouched");
	fs_apply_outcome_free (o);

	/* Stopped: the same unchanged policy goes out whole. */
	wpb_state = FS_FW_STOPPED;
	o = fs_policy_apply_safe (&fake_backend_stateful, policy, "wpb", NULL,
	                          NULL);
	CHECK (o->applied && !o->narrow && fake_full_calls == 2 &&
	       o->firewall_was == FS_FW_STOPPED,
	       "A1: stopped: the whole policy is applied (full calls %d, "
	       "narrow %d)", fake_full_calls, o->narrow);
	fs_apply_outcome_free (o);
	log = gate_audit_read ();
	CHECK (log != NULL && strstr (log, "| full (firewall was stopped) |")
	                      != NULL,
	       "A1: the audit line says the firewall was stopped");
	g_free (log);

	/* Unknown (no root to read it): whole too, never "no change". */
	wpb_state = FS_FW_NONE;
	o = fs_policy_apply_safe (&fake_backend_stateful, policy, "wpb", NULL,
	                          NULL);
	CHECK (o->applied && !o->narrow && fake_full_calls == 3,
	       "A1: a state that cannot be read takes the whole apply");
	fs_apply_outcome_free (o);

	/* A backend that cannot read its state keeps the narrow path. */
	o = fs_policy_apply_safe (&fake_backend, policy, "wpb", NULL, NULL);
	CHECK (o->applied && o->narrow && fake_full_calls == 3 &&
	       o->firewall_was == FS_FW_NONE,
	       "A1: no get_state: the narrow path as before");
	fs_apply_outcome_free (o);

	fake_reset ();
	fs_policy_free (policy);
	g_unsetenv ("STOCKFW_APPLIED_FILE");
	g_unsetenv ("STOCKFW_AUDIT_FILE");
	remove (file);
	remove (audit_file);
	g_rmdir (dir);
	g_free (audit_file);
	g_free (file);
	g_free (dir);
}

/* [ test_lockout_check ]
 * Each SSH peer is asked about as a new connection on each port.
 * The addresses are public documentation ranges: the Windows model
 * blocks reserved sources such as 192.168/16 on Public networks, so a
 * LAN peer is DEPENDS there, not ALLOWED. */
static void test_lockout_check (void)
{
	FsPolicy *policy = fs_policy_new ();
	FsRule *ssh = fs_rule_from_csv (FS_RULE_INBOUND_ALLOW_SERVICE,
	                                "SSH, 22, 203.0.113.0/24, admin");
	FsRangeSet *peers = fs_range_set_new ();
	FsRangeSet *lan = fs_range_set_new ();
	FsRangeSet *none = fs_range_set_new ();
	GArray *ports = g_array_new (FALSE, FALSE, sizeof (guint16));
	GArray *other = g_array_new (FALSE, FALSE, sizeof (guint16));
	guint16 p22 = 22, p2222 = 2222;
	FsLockoutReport *r;

	fs_policy_add (policy, ssh);
	fs_range_set_add_text (peers, "10.0.0.5");
	fs_range_set_add_text (lan, "203.0.113.20");
	g_array_append_val (ports, p22);
	g_array_append_val (other, p2222);

	r = fs_lockout_check (policy, NULL, peers, ports);
	CHECK (r->checked && fs_lockout_report_cuts (r) &&
	       r->verdict == FS_WHATIF_BLOCKED && r->worst != NULL &&
	       g_strcmp0 (r->worst->peer, "10.0.0.5") == 0 &&
	       r->worst->port == 22,
	       "lockout: a peer outside the SSH row's network is cut");
	fs_lockout_report_free (r);

	r = fs_lockout_check (policy, NULL, lan, ports);
	CHECK (r->checked && !fs_lockout_report_cuts (r) &&
	       r->worst != NULL && r->worst->policy_kind ==
	       FS_RULE_INBOUND_ALLOW_SERVICE && r->worst->policy_index == 0,
	       "lockout: a peer inside it is allowed, by that row");
	fs_lockout_report_free (r);

	r = fs_lockout_check (policy, NULL, lan, other);
	CHECK (fs_lockout_report_cuts (r),
	       "lockout: sshd on another port is cut by a port-22 row");
	fs_lockout_report_free (r);

	r = fs_lockout_check (policy, NULL, none, ports);
	CHECK (!r->checked && !fs_lockout_report_cuts (r) &&
	       g_strcmp0 (r->why_not, "not an SSH session") == 0,
	       "lockout: no peer, no check");
	fs_lockout_report_free (r);

	/* Peers next to each other are one range once normalized (as
	 * fs_hostnet_read leaves them): each address is still asked
	 * about, not only the first. */
	{
		FsRule *ssh6 = fs_rule_from_csv (FS_RULE_INBOUND_ALLOW_SERVICE,
		                                 "SSH, 22, 2001:db8::/127,");
		FsRangeSet *pair4 = fs_range_set_new ();
		FsRangeSet *pair6 = fs_range_set_new ();

		fs_policy_add (policy, ssh6);
		fs_range_set_add_text (pair4, "203.0.113.255");
		fs_range_set_add_text (pair4, "203.0.114.0");
		fs_range_set_normalize (pair4);
		fs_range_set_add_text (pair6, "2001:db8::1");
		fs_range_set_add_text (pair6, "2001:db8::2");
		fs_range_set_normalize (pair6);

		r = fs_lockout_check (policy, NULL, pair4, ports);
		CHECK (pair4->v4->len == 1 && r->pairs->len == 2 &&
		       fs_lockout_report_cuts (r) && r->worst != NULL &&
		       g_strcmp0 (r->worst->peer, "203.0.114.0") == 0,
		       "lockout: of two adjacent IPv4 peers (one range), the "
		       "second, outside the LAN, is cut");
		fs_lockout_report_free (r);

		r = fs_lockout_check (policy, NULL, pair6, ports);
		CHECK (pair6->v6->len == 1 && r->pairs->len == 2 &&
		       fs_lockout_report_cuts (r) && r->worst != NULL &&
		       g_strcmp0 (r->worst->peer, "2001:db8::2") == 0,
		       "lockout: the same for two adjacent IPv6 peers");
		fs_lockout_report_free (r);

		fs_range_set_free (pair6);
		fs_range_set_free (pair4);
		fs_rule_free (ssh6);
	}

	/* A busy jump host (docs 15.2, review notes): 70 sessions from the
	 * SSH row's network sort before the admin's own peer, 203.0.114.5, which the SSH
	 * row does not let in.  Capped at 64, the plain check never asks
	 * about it and says ALLOWED; the session's own peer is asked about
	 * first, outside the cap, and the report counts what it left out. */
	{
		FsRangeSet *busy = fs_range_set_new ();
		FsRangeSet *own = fs_range_set_new ();

		for (guint i = 1; i <= 70; i++) {
			gchar *a = g_strdup_printf ("203.0.113.%u", i);

			fs_range_set_add_text (busy, a);
			g_free (a);
		}
		fs_range_set_add_text (busy, "203.0.114.5");
		fs_range_set_normalize (busy);
		fs_range_set_add_text (own, "203.0.114.5");

		r = fs_lockout_check (policy, NULL, busy, ports);
		CHECK (r->checked && !fs_lockout_report_cuts (r) &&
		       r->pairs->len == FS_LOCKOUT_MAX_PEERS && r->skipped == 7,
		       "lockout: past the cap, the plain check stops at %u peers "
		       "and counts 7 not asked (%u, skipped %u)",
		       FS_LOCKOUT_MAX_PEERS, r->pairs->len, r->skipped);
		fs_lockout_report_free (r);

		r = fs_lockout_check_own (policy, NULL, own, busy, ports);
		CHECK (r->checked && fs_lockout_report_cuts (r) &&
		       r->verdict == FS_WHATIF_BLOCKED && r->worst != NULL &&
		       g_strcmp0 (r->worst->peer, "203.0.114.5") == 0 &&
		       r->worst->own &&
		       r->pairs->len == FS_LOCKOUT_MAX_PEERS + 1 &&
		       r->skipped == 6,
		       "lockout: the session's own peer is asked about first, "
		       "past a busy host's 70 others, and is cut (%s, %u pairs, "
		       "skipped %u)", r->worst != NULL ? r->worst->peer : "-",
		       r->pairs->len, r->skipped);
		fs_lockout_report_free (r);

		fs_range_set_free (own);
		fs_range_set_free (busy);
	}

	CHECK (fs_lockout_env_port ("10.0.0.5 50000 10.0.0.1 2222") == 2222 &&
	       fs_lockout_env_port ("10.0.0.5 50000 10.0.0.1") == 0 &&
	       fs_lockout_env_port ("a b c 99999") == 0 &&
	       fs_lockout_env_port (NULL) == 0,
	       "lockout: the server port of $SSH_CONNECTION");

	g_array_unref (other);
	g_array_unref (ports);
	fs_range_set_free (none);
	fs_range_set_free (lan);
	fs_range_set_free (peers);
	fs_rule_free (ssh);
	fs_policy_free (policy);
}
/* === end WP-B === */

int main (void)
{
	gchar *run_dir = make_run_dir ();

	/* Point the preference file somewhere disposable before anything
	 * reads it: the path is computed once, on first use.  The temp
	 * dir is this run's own (make_run_dir), never a shared /tmp. */
#ifdef G_OS_WIN32
	g_setenv ("APPDATA", g_get_tmp_dir (), TRUE);
#else
	g_setenv ("XDG_CONFIG_HOME", g_get_tmp_dir (), TRUE);
#endif
	{
#ifdef G_OS_WIN32
		const gchar *cfg = g_getenv ("APPDATA");
#else
		const gchar *cfg = g_getenv ("XDG_CONFIG_HOME");
#endif
		GStatBuf st;
		gboolean own = cfg != NULL && g_strcmp0 (cfg, run_dir) == 0 &&
		               g_stat (cfg, &st) == 0;

#ifndef G_OS_WIN32
		own = own && st.st_uid == getuid () && (st.st_mode & 0077) == 0;
#endif
		CHECK (own, "the settings, baseline and audit files go to a "
		       "directory only this run owns, not a shared /tmp");
	}
	/* The Copilot reads this computer's DNS servers and gateways; the
	 * tests use none (the review-fix test sets its own). */
	g_setenv ("STOCKFW_RESOLV_CONF", "/dev/null", TRUE);

	test_ports ();
	test_cli_platform_words ();
	test_hosts ();
	test_rule_csv ();
	test_policy_persist ();
	test_fwrule_ports ();
	test_fwrule_services_golden ();
	test_fwrule_default_policy ();
	test_fwrule_expand ();
	test_fwrule_forward ();
	test_fwrule_netsh_golden ();
	test_service_lookup ();
	test_script_generation ();
	test_copilot_suggestion_apply ();
	test_prefs_fallbacks ();
	test_copilot_profile_lifetime ();
	test_eventrule_builders ();
	test_policy_persist_rollback ();
	test_sentinel_beacon ();
	test_sentinel_fanout ();
	test_sentinel_auto_gates ();
	test_behavior_derivation ();
	test_behavior_signals ();
	test_behavior_hour_guard ();
	test_behavior_rate ();
	test_behavior_insight_cap ();
	test_inbound_scan ();
	test_brute_force ();
	test_threat_intel ();
	test_insight_dedup ();
	test_copilot_review_fixes ();
	test_behavior_persistence ();
	test_behavior_partial ();
	test_behavior_app_cap ();
	test_audit_log ();
	test_filter_match ();
	test_loopback_address ();
	test_insight_apply ();
	test_policy_load_validation_f1 ();
	test_name_hygiene_f3 ();
	test_whatif_simulate ();
	test_direction_pairing ();
	test_trust_engine ();
	test_fwrule_equal ();
	test_apply_journal ();
	test_apply_impact ();
	test_apply_delta ();
	test_apply_gate ();
	test_start_gate ();
	test_start_from_journal ();
	test_autoblock_expire ();
	test_autostart ();
	test_block_tally ();
	test_settings_apply_gate ();
	test_prefs_table ();
	test_settings_pending ();
	test_apply_translation_upgrade ();
	test_whatif_winrules ();
	test_fwrule_review ();
	test_settings_plan ();
	test_netparse_log ();
	test_netparse_proc ();
	test_netparse_kmsg ();
	test_netparse_verdicts ();
	test_netparse_intel_line ();
	test_script_accept_log ();
	test_target_families ();
	test_restore_plan ();
	test_sharing_needs_both_devices ();
	test_start_on_open_order ();
	test_activity_series ();
	test_activity_sampler ();
	test_json_writer ();
	test_intelwin_gen ();
	test_intelwin_plan ();
	test_intelwin_limits ();
	test_intelwin_parse_remote ();
	test_intelwin_read ();
	test_intelwin_force ();
	test_intelwin_review ();
	test_hostnet_onlink ();
	test_winstore_sddl ();
	test_toolpath ();
	/* === WP-B === */
	test_policy_load_report ();
	test_apply_while_stopped ();
	test_lockout_check ();
	/* === end WP-B === */

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);

	rm_tree (run_dir);
	g_free (run_dir);
	return failures ? 1 : 0;
}
EOF

EXTRA_LIBS=""
if [ "${OS:-}" = "Windows_NT" ] || [ -d /ucrt64 ]; then
  EXTRA_LIBS="-lws2_32 -liphlpapi -ladvapi32 -lshell32 -lole32 -loleaut32"
fi

# STOCKFW_TEST_CFLAGS adds compiler flags, for the sanitizer run the
# README describes (-fsanitize=address,undefined ...).
# shellcheck disable=SC2086
cc ${STOCKFW_TEST_CFLAGS:-} "$BUILD_DIR/test-core.c" \
   -I src \
   $(pkg-config --cflags glib-2.0 gio-2.0 liblzma libcrypto) \
   -o "$BUILD_DIR/test-core" \
   src/core/*.c \
   $(pkg-config --libs glib-2.0 gio-2.0 liblzma libcrypto) $EXTRA_LIBS

# Keep rule files out of the real rules directory.
export STOCKFW_RULES_DIR="$BUILD_DIR/rules"
rm -rf "$STOCKFW_RULES_DIR"

core_rc=0
"$BUILD_DIR/test-core" || core_rc=$?

# The location database reader (tests/test-geodb.c), a test build of
# src/core: FS_GEODB_TESTING lets it verify with the fixtures' test key.
# shellcheck disable=SC2086
cc ${STOCKFW_TEST_CFLAGS:-} -DFS_GEODB_TESTING=1 tests/test-geodb.c \
   -I src \
   $(pkg-config --cflags glib-2.0 gio-2.0 liblzma libcrypto) \
   -o "$BUILD_DIR/test-geodb" \
   src/core/*.c \
   $(pkg-config --libs glib-2.0 gio-2.0 liblzma libcrypto) $EXTRA_LIBS
geodb_rc=0
"$BUILD_DIR/test-geodb" tests/geodb > "$BUILD_DIR/geodb.log" 2>&1 || geodb_rc=$?
grep -E '^(FAIL|SKIP)|checks,|test-geodb:' "$BUILD_DIR/geodb.log" || true

# Country and network-owner rules in the engine (tests/test-intel-geo.c,
# design section 13), the same test build of src/core: its databases
# are signed with a key the test makes.
# shellcheck disable=SC2086
cc ${STOCKFW_TEST_CFLAGS:-} -DFS_GEODB_TESTING=1 tests/test-intel-geo.c \
   -I src -I tests \
   $(pkg-config --cflags glib-2.0 gio-2.0 liblzma libcrypto) \
   -o "$BUILD_DIR/test-intel-geo" \
   src/core/*.c \
   $(pkg-config --libs glib-2.0 gio-2.0 liblzma libcrypto) $EXTRA_LIBS
intelgeo_rc=0
"$BUILD_DIR/test-intel-geo" > "$BUILD_DIR/intel-geo.log" 2>&1 || intelgeo_rc=$?
grep -E '^(FAIL|SKIP)|checks,|test-intel-geo:' "$BUILD_DIR/intel-geo.log" || true

# The What-If engine's golden table (tests/test-whatif.c): the reading of
# a line, both firewall models, the Linux model pinned to the generator,
# and the fixes it offers.  Same compiler flags as above.
# shellcheck disable=SC2086
cc ${STOCKFW_TEST_CFLAGS:-} tests/test-whatif.c \
   -I src \
   $(pkg-config --cflags glib-2.0 gio-2.0 liblzma libcrypto) \
   -o "$BUILD_DIR/test-whatif" \
   src/core/*.c \
   $(pkg-config --libs glib-2.0 gio-2.0 liblzma libcrypto) $EXTRA_LIBS
whatif_rc=0
"$BUILD_DIR/test-whatif" || whatif_rc=$?

# The Copilot's policy health check (tests/test-health.c): exact coverage,
# the golden table on both platform models, every fix verified by the
# What-If engine, apply and undo proved on the rules file.
# shellcheck disable=SC2086
cc ${STOCKFW_TEST_CFLAGS:-} tests/test-health.c \
   -I src \
   $(pkg-config --cflags glib-2.0 gio-2.0 liblzma libcrypto) \
   -o "$BUILD_DIR/test-health" \
   src/core/*.c \
   $(pkg-config --libs glib-2.0 gio-2.0 liblzma libcrypto) $EXTRA_LIBS
health_rc=0
"$BUILD_DIR/test-health" || health_rc=$?

# Wording guard: the Copilot is a set of fixed rules, and nothing in the
# program or the docs may call it AI.  The one sentence that says there
# is no AI model is allowed.
# The installers, their documents and the release notes ship to users
# too (the Windows installer once carried a changelog promising
# "AI-powered" detection), so they are read as well.  site/ is the
# website's own tree and has its own checks.
WORDING_HITS="$(grep -rnE '\bAI\b|AI-' src docs installer contrib ../docs ../README.md \
  ../CHANGELOG.md ../RELEASING.md ../AUTHORS ../CREDITS 2>/dev/null \
  | grep -v 'There is no AI model' || true)"
if [ -n "$WORDING_HITS" ]; then
  echo "FAIL: \"AI\" wording in the program, the installers or the docs:"
  echo "$WORDING_HITS"
  exit 1
fi
# The manual page and the completion words are printed by `stockfw'
# from its tables in src/cli (read above), and contrib/ holds the
# completion scripts.  When a build is at hand, what it prints is read
# too.
SFW="${STOCKFW_BUILD:-build-linux}/stockfw"
if [ -x "$SFW" ]; then
  GEN_HITS="$( { "$SFW" __man; "$SFW" __complete ''
                 for c in $("$SFW" __complete ''); do
                   "$SFW" __complete "$c" -; "$SFW" __complete "$c" ''
                 done; } 2>/dev/null | grep -nE '\bAI\b|AI-' || true)"
  if [ -n "$GEN_HITS" ]; then
    echo "FAIL: \"AI\" wording in what stockfw __man or __complete prints:"
    echo "$GEN_HITS"
    exit 1
  fi
fi
echo "ok:   wording guard: no \"AI\" claims in src, installers, docs, README or CHANGELOG"

# Credits: "Stockfw Team - Creator & Original Developer", never the
# creator's full name or e-mail address, anywhere in the repository
# (the legacy tree included).
if git -C .. rev-parse --git-dir > /dev/null 2>&1; then
  NAME_HITS="$(git -C .. grep -nIi -e 'fethalrahma[n]' -e 'qusaifo[x]' || true)"
else
  NAME_HITS="$(grep -rnIi -e 'fethalrahma[n]' -e 'qusaifo[x]' .. \
    --exclude-dir=.git --exclude-dir='build*' 2>/dev/null || true)"
fi
if [ -n "$NAME_HITS" ]; then
  echo "FAIL: a credit carries the creator's full name or e-mail address:"
  echo "$NAME_HITS"
  exit 1
fi
for f in ../AUTHORS ../CREDITS ../README.md src/ui/fs-aboutdialog.c; do
  if ! grep -q 'Stockfw Team' "$f"; then
    echo "FAIL: $f does not credit \"Stockfw Team\""
    exit 1
  fi
done
# The port's own credit reads "Stock Team" too: About and Help said
# "StockFW Project - GTK3 Port, ..." (release review, problem 1).
for f in src/ui/fs-aboutdialog.c src/ui/fs-helpcontent.c; do
  if ! tr -d '\r\n\t' < "$f" | sed 's/"  *"//g' | grep -q 'Stock Team - GTK3 Port, Windows Backend, Copilot' ||
     grep -q 'StockFW Project' "$f"; then
    echo "FAIL: $f does not credit \"Stock Team - GTK3 Port, Windows Backend, Copilot\""
    exit 1
  fi
done
echo "ok:   credits guard: Stockfw Team, no full name, no e-mail address"

# Privacy (DOCS-HELP-07): the location database downloads as a
# blocklist does, so "Your data" and the threat-intel topic must name it
# wherever they say what StockFW downloads.
PRIV="$(tr -d '\r\n\t' < src/ui/fs-helpcontent.c | sed 's/"  *"//g')"
case "$PRIV" in
  *'nothing unless you turn on a <a href=\"help:threat-intel\">threat-intel blocklist</a> or the location database'*) ;;
  *) echo "FAIL: Help > Your data says only a blocklist downloads anything"; exit 1 ;;
esac
case "$PRIV" in
  *'While no list and not the location database is on, StockFW makes no network request'*) ;;
  *) echo "FAIL: Help > Threat intel says no list means no network request"; exit 1 ;;
esac
echo "ok:   privacy guard: Help names the location database as a download"

# SECURITY-1 and SECURITY-2: the spawns that run system tools go through
# fs-toolpath, never a PATH search (root) or CreateProcess's search of
# the program's own and the current folder (Windows).
SPAWN_HITS="$(grep -nE 'G_SPAWN_SEARCH_PATH|g_find_program_in_path' \
  src/platform/linux/fs-backend-linux.c src/core/fs-nftset.c \
  src/cli/*.c || true)"
if [ -n "$SPAWN_HITS" ]; then
  echo "FAIL: a system tool is found through PATH:"
  echo "$SPAWN_HITS"
  exit 1
fi
if ! tr -d '\r' < src/platform/windows/fs-backend-windows.c \
     | grep -q 'fs_toolpath_windows (system_dir, argv\[0\])'; then
  echo "FAIL: spawn_capture no longer maps argv[0] to System32"
  exit 1
fi
echo "ok:   spawn guard: system tools by absolute path (Linux root, Windows)"

# The command line (cli-plan.md, WP-A).  A hint that says a bare
# `sudo stockfw' may find another copy, or none, on root's PATH: hints
# come from fs_cli_sudo_hint, with the full path.
SUDO_HITS="$(grep -n '`sudo stockfw' src/cli/*.c src/cli/*.h || true)"
if [ -n "$SUDO_HITS" ]; then
  echo "FAIL: a bare \`sudo stockfw' hint in src/cli (use fs_cli_sudo_hint):"
  echo "$SUDO_HITS"
  exit 1
fi
echo "ok:   cli guard: no bare \`sudo stockfw' hint in src/cli"
# "--" is the parser's (fs-cli-main.c drops it); a command that looks
# for it again would read a dash word after it as an option.
DASH_HITS="$(grep -nE 'strcmp \(argv\[[a-z0-9_ +]*\], "--"\)' src/cli/*.c \
  | grep -v '^src/cli/fs-cli-main\.c:' || true)"
if [ -n "$DASH_HITS" ]; then
  echo "FAIL: a command looks for \"--\" itself (fs_cli_is_positional is the way):"
  echo "$DASH_HITS"
  exit 1
fi
echo "ok:   cli guard: only fs-cli-main.c handles \"--\""
# The option tables are what completion and the man page are made of:
# every option a command reads with fs_cli_take_opt is a value option
# of the table in the same file, and every value option of a table is
# read there.
if ! python3 -I - src/cli/*.c <<'PYEOF'
import re, sys
bad = []
for path in sys.argv[1:]:
    src = open(path, encoding='utf-8').read()
    taken = set(re.findall(r'fs_cli_take_opt\s*\([^;"]*?"(-[^"]*)"', src))
    table = set(re.findall(r'\{\s*"(-[^"]*)",\s*TRUE\s*,', src))
    for o in sorted(taken - table):
        bad.append('%s: %s is read by fs_cli_take_opt but is not a value option of its table' % (path, o))
    for o in sorted(table - taken):
        bad.append('%s: %s is a value option of the table but no fs_cli_take_opt reads it' % (path, o))
for b in bad:
    print('FAIL: ' + b)
sys.exit(1 if bad else 0)
PYEOF
then
  exit 1
fi
echo "ok:   cli guard: fs_cli_take_opt options and the option tables agree"

# === WP-D ===
# The socket tables (cli-plan.md WP-D): the UDP parser, the listening
# test, port names, the connection rows' new fields, and the SSH
# sessions an apply keeps on every port sshd listens on
# (tests/test-sockets.c, a test build of src/core).
# shellcheck disable=SC2086
cc ${STOCKFW_TEST_CFLAGS:-} tests/test-sockets.c \
   -I src \
   $(pkg-config --cflags glib-2.0 gio-2.0 liblzma libcrypto) \
   -o "$BUILD_DIR/test-sockets" \
   src/core/*.c \
   $(pkg-config --libs glib-2.0 gio-2.0 liblzma libcrypto) $EXTRA_LIBS
if ! "$BUILD_DIR/test-sockets"; then
  exit 1
fi
# Live (Linux): a listener named sshd on a free port, with a session
# from 127.0.0.3.  The port is found from the socket's owner, and the
# session on it is kept, as one on 22 always was.
if [ "$(uname -s)" = Linux ] && command -v python3 > /dev/null; then
  rm -f "$BUILD_DIR/sshd-in"
  mkfifo "$BUILD_DIR/sshd-in"
  python3 -I tests/fake-sshd.py < "$BUILD_DIR/sshd-in" > "$BUILD_DIR/sshd-port" &
  SSHD_PID=$!
  exec 7> "$BUILD_DIR/sshd-in"
  for _ in $(seq 50); do [ -s "$BUILD_DIR/sshd-port" ] && break; sleep 0.1; done
  SSHD_PORT="$(cat "$BUILD_DIR/sshd-port")"
  SSHD_PORTS="$("$BUILD_DIR/test-sockets" --ssh-ports)"
  SSHD_SESSION="$("$BUILD_DIR/test-sockets" --session 127.0.0.3)"
  exec 7>&-
  wait "$SSHD_PID" 2> /dev/null || true
  case ",$SSHD_PORTS," in
    *",$SSHD_PORT,"*) ;;
    *) echo "FAIL: sshd's port $SSHD_PORT is not among the ssh ports ($SSHD_PORTS)"; exit 1 ;;
  esac
  if [ "$SSHD_SESSION" != yes ]; then
    echo "FAIL: the session to sshd on port $SSHD_PORT is not kept"
    exit 1
  fi
  echo "ok:   hostnet: sshd found on port $SSHD_PORT by its owner, and its session kept"

  # Socket activation (ssh.socket; docs 15.2, review notes): a lower
  # pid that is not sshd (systemd, pid 1) holds the listener too.  Any
  # holder that is sshd makes it sshd's port, not only the first.
  rm -f "$BUILD_DIR/sshd-in" "$BUILD_DIR/sshd-port"
  mkfifo "$BUILD_DIR/sshd-in"
  python3 -I tests/fake-sshd.py --activated < "$BUILD_DIR/sshd-in" > "$BUILD_DIR/sshd-port" &
  SSHD_PID=$!
  exec 7> "$BUILD_DIR/sshd-in"
  for _ in $(seq 50); do [ -s "$BUILD_DIR/sshd-port" ] && break; sleep 0.1; done
  SSHD_PORT="$(cat "$BUILD_DIR/sshd-port")"
  SSHD_PORTS="$("$BUILD_DIR/test-sockets" --ssh-ports)"
  SSHD_SESSION="$("$BUILD_DIR/test-sockets" --session 127.0.0.3)"
  exec 7>&-
  wait "$SSHD_PID" 2> /dev/null || true
  case ",$SSHD_PORTS," in
    *",$SSHD_PORT,"*) ;;
    *) echo "FAIL: socket-activated sshd's port $SSHD_PORT is not among the ssh ports ($SSHD_PORTS)"; exit 1 ;;
  esac
  if [ "$SSHD_SESSION" != yes ]; then
    echo "FAIL: the session to socket-activated sshd on port $SSHD_PORT is not kept"
    exit 1
  fi
  echo "ok:   hostnet: socket-activated sshd on port $SSHD_PORT (an earlier non-sshd holder) is found, its session kept"

  # The session this process runs in, with no $SSH_CONNECTION (sudo
  # drops it): the connection its sshd ancestor holds on sshd's port.
  # The lockout guard asks about it before any other peer.
  rm -f "$BUILD_DIR/sshd-in" "$BUILD_DIR/sshd-port"
  mkfifo "$BUILD_DIR/sshd-in"
  env -u SSH_CONNECTION -u SSH_CLIENT python3 -I tests/fake-sshd.py --exec "$BUILD_DIR/test-sockets" --own \
    < "$BUILD_DIR/sshd-in" > "$BUILD_DIR/sshd-port" &
  SSHD_PID=$!
  exec 7> "$BUILD_DIR/sshd-in"
  for _ in $(seq 50); do [ -s "$BUILD_DIR/sshd-port" ] && break; sleep 0.1; done
  SSHD_OWN="$(cat "$BUILD_DIR/sshd-port")"
  exec 7>&-
  wait "$SSHD_PID" 2> /dev/null || true
  if [ "$SSHD_OWN" != "own=127.0.0.3" ]; then
    echo "FAIL: the session's own peer from its sshd ancestor is not 127.0.0.3 ($SSHD_OWN)"
    exit 1
  fi
  echo "ok:   hostnet: the session's own peer (127.0.0.3) is read from its sshd ancestor, no \$SSH_CONNECTION"
  rm -f "$BUILD_DIR/sshd-in" "$BUILD_DIR/sshd-port"
fi
# `stockfw interfaces': a rate is the bytes over the real time between
# the two samples.  1.0.7 divided the first --watch frame, measured over
# one second, by 2.0, and showed half the rate.
IFACE_BODY="$(awk '/^fs_cli_cmd_interfaces /,/^}/' src/cli/fs-cli-events.c)"
if printf '%s\n' "$IFACE_BODY" | grep -nE 'print_interfaces \([^;]*[0-9]\.[0-9]' ||
   [ "$(printf '%s\n' "$IFACE_BODY" | grep -c 't_now - t_before')" -lt 2 ] ||
   [ "$(printf '%s\n' "$IFACE_BODY" | grep -c 'g_get_monotonic_time')" -lt 2 ]; then
  echo "FAIL: interfaces divides by a fixed interval, not the time measured"
  exit 1
fi
echo "ok:   cli guard: interfaces rates use the time measured between samples"
# === end WP-D ===

# The dashboard (PR 2, 2B and 2C; docs 15.3.2-15.3.3).  No `--token'
# option, ever: a credential in an argument list is readable by every
# account from /proc/<pid>/cmdline (T10).  The session key is the only
# credential the API takes, in a header.
TOKEN_HITS="$(grep -nE '"--token|--token=|X-StockFW-Token' src/cli/*.c src/cli/*.h \
  src/cli/dashboard.html || true)"
if [ -n "$TOKEN_HITS" ]; then
  echo "FAIL: a --token option or the old token header is back in src/cli:"
  echo "$TOKEN_HITS"
  exit 1
fi
echo "ok:   dashboard guard: no --token option and no token header (T10)"
# The page builds every node with textContent (T14).  Banned: the HTML
# parsers and script runners, WebSocket and EventSource, inline on*
# handlers, and href, src, style, srcdoc or action set from script.
DOM_HITS="$(grep -nE 'innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval[[:space:]]*\(|new[[:space:]]+Function|setTimeout[[:space:]]*\([[:space:]]*["'"'"'`]|setInterval[[:space:]]*\([[:space:]]*["'"'"'`]|WebSocket|EventSource|createContextualFragment|DOMParser|srcdoc' \
  src/cli/dashboard.html || true)"
DOM_HITS="$DOM_HITS$(grep -nE '<[a-zA-Z][^>]*[[:space:]]on[a-zA-Z]+[[:space:]]*=' src/cli/dashboard.html || true)"
DOM_HITS="$DOM_HITS$(grep -nE '\.on[a-z]+[[:space:]]*=[^=]|setAttribute[[:space:]]*\([[:space:]]*["'"'"'](href|src|style|on[a-z]*|action|formaction|xlink:href)["'"'"']|\.(href|src|action|formAction)[[:space:]]*=[^=]|\.style\.cssText|\.setAttributeNS[[:space:]]*\(' \
  src/cli/dashboard.html || true)"
if [ -n "$DOM_HITS" ]; then
  echo "FAIL: dashboard.html uses a banned DOM API or attribute (textContent only, T14):"
  echo "$DOM_HITS"
  exit 1
fi
echo "ok:   dashboard guard: no innerHTML, document.write, eval, WebSocket, EventSource or on* handlers in dashboard.html (T14)"

[ "$core_rc" -eq 0 ] && [ "$geodb_rc" -eq 0 ] && [ "$intelgeo_rc" -eq 0 ] \
  && [ "$whatif_rc" -eq 0 ] && [ "$health_rc" -eq 0 ]
