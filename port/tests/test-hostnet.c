/*---[ test-hostnet.c ]--------------------------------------------------
 * What a blocklist must never cut on this computer (fs-hostnet, design
 * section 6.4).
 *
 * The parsers against fixtures modelled on the real files: both route
 * tables, the three resolver files, the SSH variables and both TCP
 * tables, IPv6 included.  Then fs_hostnet_new/free/all, a read of the
 * machine the test runs on, and a live read in private namespaces: as
 * root, the test re-executes itself under "unshare -n -m", makes
 * interfaces, routes, resolver and hosts files and SSH sessions there,
 * and checks what fs_hostnet_read() finds.  Everything it makes
 * vanishes with the namespaces; the host's network and files are never
 * touched.  Without root, unshare or ip, the live part prints SKIP.
 *
 * IPv6 live checks run only on a kernel that has IPv6; elsewhere the
 * fixtures cover IPv6, and the output says so.
 *--------------------------------------------------------------------*/
#ifdef __linux__
#define _GNU_SOURCE   /* symlink, mkfifo, mount under a strict -std */
#endif

#include <glib.h>
#include <gio/gio.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-hostnet.h"
#include "core/fs-iprange.h"

#ifdef __linux__
#include "core/fs-netparse.h"
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

static guint failures = 0;

#define CHECK(cond, ...) do {                                   \
	if (cond) {                                             \
		g_print ("ok:   " __VA_ARGS__);                 \
	} else {                                                \
		g_print ("FAIL: " __VA_ARGS__);                 \
		failures++;                                     \
	}                                                       \
	g_print ("\n");                                         \
} while (0)

/* ============================================================ helpers */

/* A set on one line, "a b c", or "(empty)". */
static gchar *
flat (const FsRangeSet *set)
{
	gchar *text = fs_range_set_to_text (set);

	g_strchomp (text);
	g_strdelimit (text, "\n", ' ');
	if (*text == '\0') {
		g_free (text);
		return g_strdup ("(empty)");
	}
	return text;
}

/* `set' is exactly `want' (as flat() writes it).  Frees the set. */
static void
expect (FsRangeSet *set, const gchar *want, const gchar *what)
{
	gchar *got = flat (set);
	gboolean same = g_strcmp0 (got, want) == 0;

	CHECK (same, "%s: %s", what, want);
	if (!same)
		g_print ("      (got %s)\n", got);
	g_free (got);
	fs_range_set_free (set);
}

/* The IPv4 half of a set, as flat() writes it. */
static gchar *
flat4 (const FsRangeSet *set)
{
	FsRangeSet *v4 = fs_range_set_copy (set);
	gchar *text;

	g_array_set_size (v4->v6, 0);
	text = flat (v4);
	fs_range_set_free (v4);
	return text;
}

static gint
u128_cmp (FsU128 a, FsU128 b)
{
	if (a.hi != b.hi)
		return a.hi < b.hi ? -1 : 1;
	if (a.lo != b.lo)
		return a.lo < b.lo ? -1 : 1;
	return 0;
}

/* Sorted, no interval inverted, none overlapping or touching the
 * next: what fs-iprange calls normalized. */
static gboolean
is_normalized (const FsRangeSet *set)
{
	if (set == NULL)
		return FALSE;
	for (guint i = 0; i < set->v4->len; i++) {
		const FsRange4 *r = &g_array_index (set->v4, FsRange4, i);

		if (r->start > r->end)
			return FALSE;
		if (i > 0) {
			const FsRange4 *p = &g_array_index (set->v4, FsRange4,
			                                    i - 1);

			if (p->end == G_MAXUINT32 || r->start <= p->end + 1)
				return FALSE;
		}
	}
	for (guint i = 0; i < set->v6->len; i++) {
		const FsRange6 *r = &g_array_index (set->v6, FsRange6, i);

		if (u128_cmp (r->start, r->end) > 0)
			return FALSE;
		if (i > 0) {
			const FsRange6 *p = &g_array_index (set->v6, FsRange6,
			                                    i - 1);
			FsU128 next = p->end;

			if (next.hi == G_MAXUINT64 && next.lo == G_MAXUINT64)
				return FALSE;
			if (++next.lo == 0)
				next.hi++;
			if (u128_cmp (r->start, next) <= 0)
				return FALSE;
		}
	}
	return TRUE;
}

static gboolean
all_normalized (const FsHostNet *h)
{
	return is_normalized (h->own) && is_normalized (h->onlink) &&
	       is_normalized (h->gateways) && is_normalized (h->resolvers) &&
	       is_normalized (h->sessions) && is_normalized (h->update_hosts);
}

/* ======================================================= route tables */

/* /proc/net/route as the kernel prints it: tab-separated, padded with
 * blanks, each address one little-endian word ("016433C6" is
 * 198.51.100.1, "FE0200C0" is 192.0.2.254). */
static const gchar ROUTE[] =
	"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT                                                       \n"
	/* default via 198.51.100.1, flags UG: in */
	"eth0\t00000000\t016433C6\t0003\t0\t0\t100\t00000000\t0\t0\t0                                                                               \n"
	/* the connected /24, no gateway: out */
	"eth0\t006433C6\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0                                                                               \n"
	/* 203.0.113.0/24 via 198.51.100.254: a gateway, not a default */
	"eth0\t007100CB\tFE6433C6\t0003\t0\t0\t100\t00FFFFFF\t0\t0\t0                                                                               \n"
	/* a second default, via 192.0.2.254 on the Wi-Fi: in */
	"wlan0\t00000000\tFE0200C0\t0003\t0\t0\t600\t00000000\t0\t0\t0                                                                              \n"
	/* default straight onto a PPP link: no gateway flag, no gateway */
	"ppp0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0                                                                               \n"
	/* a gateway column without the gateway flag (203.0.113.13): out */
	"tun0\t00000000\t0D7100CB\t0001\t0\t0\t50\t00000000\t0\t0\t0                                                                               \n"
	/* a default via 203.0.113.9 that is down (no RTF_UP): out */
	"eth1\t00000000\t097100CB\t0002\t0\t0\t200\t00000000\t0\t0\t0                                                                               \n"
	/* "unreachable default" (RTF_REJECT|RTF_UP): out */
	"*\t00000000\t00000000\t0201\t0\t0\t0\t00000000\t0\t0\t0                                                                               \n"
	/* damaged rows */
	"eth0\t00000000\tZZ6433C6\t0003\n"
	"eth0\t00000000\n"
	"eth0\t00000000\t16433C6\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";

/* /proc/net/ipv6_route: destination, its prefix length, source, its
 * length, next hop, metric, refcnt, use, flags, device.  These
 * addresses are printed byte by byte, in order. */
static const gchar IPV6_ROUTE[] =
	"20010db8000000010000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n"
	"20010db8000000020000000000000000 30 00000000000000000000000000000000 00 fe800000000000000000000000000002 00000400 00000001 00000000 00000003     eth0\n"
	"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n"
	/* default via the router's link-local address: in */
	"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000021122fffe334455 00000400 00000001 00000000 00000003     eth0\n"
	/* default via a global next hop: in */
	"00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db800000000000000000000ffff 00000400 00000001 00000000 00000003     eth1\n"
	/* default straight onto a link, no next hop: out */
	"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000001     ppp0\n"
	/* ::/3 from a VPN's redirect: zero destination, not a default */
	"00000000000000000000000000000000 03 00000000000000000000000000000000 00 fe800000000000000000000000000009 00000400 00000001 00000000 00000003     tun0\n"
	"00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000002 00000000 80200001       lo\n"
	"ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000004 00000000 00000001     eth0\n"
	/* the kernel's own unreachable default: out */
	"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n"
	/* damaged: a next hop one digit short */
	"00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db800000000000000000000fff 00000400 00000001 00000000 00000003     eth2\n";

static void
test_routes (void)
{
	expect (fs_hostnet_parse_route (ROUTE), "192.0.2.254 198.51.100.1",
	        "/proc/net/route: the up defaults with a gateway, read "
	        "little-endian");
	expect (fs_hostnet_parse_route (
	        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
	        "eth0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"),
	        "(empty)", "/proc/net/route: no default route, no gateway");
	/* The header is skipped because it is not a route, not because it
	 * comes first: the live reader hands the table over in blocks. */
	expect (fs_hostnet_parse_route (
	        "eth0\t00000000\t016433C6\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"),
	        "198.51.100.1", "/proc/net/route: a block without the header");
	expect (fs_hostnet_parse_route (NULL), "(empty)",
	        "/proc/net/route: no text");

	expect (fs_hostnet_parse_ipv6_route (IPV6_ROUTE),
	        "2001:db8::ffff fe80::211:22ff:fe33:4455",
	        "/proc/net/ipv6_route: ::/0 rows with a next hop");
	expect (fs_hostnet_parse_ipv6_route (NULL), "(empty)",
	        "/proc/net/ipv6_route: no text");
}

/* ===================================================== resolver files */

/* systemd-resolved: /etc/resolv.conf is its stub, the real servers
 * are in /run/systemd/resolve/resolv.conf. */
static const gchar STUB[] =
	"# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8).\n"
	"# Do not edit.\n"
	"#\n"
	"# Run \"resolvectl status\" to see details about the uplink DNS servers\n"
	"# currently in use.\n"
	"\n"
	"nameserver 127.0.0.53\n"
	"options edns0 trust-ad\n"
	"search .\n";

static const gchar RESOLVED[] =
	"# This is /run/systemd/resolve/resolv.conf managed by man:systemd-resolved(8).\n"
	"# Do not edit.\n"
	"#\n"
	"# This is a dynamic resolv.conf file for connecting local clients directly to\n"
	"# all known uplink DNS servers. This file lists all configured search domains.\n"
	"\n"
	"nameserver 1.1.1.1\n"
	"nameserver 2606:4700:4700::1111\n"
	"search .\n";

/* NetworkManager with its dnsmasq: /etc/resolv.conf names 127.0.1.1,
 * the real servers are in /run/NetworkManager/no-stub-resolv.conf. */
static const gchar NM_DNSMASQ[] =
	"# Generated by NetworkManager\n"
	"search lan\n"
	"nameserver 127.0.1.1\n";

static const gchar NM_NO_STUB[] =
	"# Generated by NetworkManager\n"
	"search lan\n"
	"nameserver 192.168.1.1\n"
	"nameserver fd00::1\n"
	"nameserver 2001:db8::53\n";

static void
test_resolvers (void)
{
	expect (fs_hostnet_parse_resolvers (STUB, RESOLVED, NULL),
	        "1.1.1.1 127.0.0.53 2606:4700:4700::1111",
	        "resolvers: only 127.0.0.53 -> resolved's upstreams, both "
	        "families");
	expect (fs_hostnet_parse_resolvers ("nameserver 192.0.2.53\n",
	                                    RESOLVED, NM_NO_STUB),
	        "192.0.2.53",
	        "resolvers: a real server in resolv.conf -> the upstream "
	        "files are not used");
	expect (fs_hostnet_parse_resolvers (NM_DNSMASQ, NULL, NM_NO_STUB),
	        "127.0.1.1 192.168.1.1 2001:db8::53 fd00::1",
	        "resolvers: NetworkManager's dnsmasq -> its no-stub file");
	expect (fs_hostnet_parse_resolvers (STUB, RESOLVED, NM_NO_STUB),
	        "1.1.1.1 127.0.0.53 192.168.1.1 2001:db8::53 "
	        "2606:4700:4700::1111 fd00::1",
	        "resolvers: behind a stub, both upstream files");
	expect (fs_hostnet_parse_resolvers (
	        "# nameserver 203.0.113.1\n"
	        "; nameserver 203.0.113.2\n"
	        "#nameserver 203.0.113.3\n"
	        "nameserver 127.0.0.53 # the stub\n", RESOLVED, NULL),
	        "1.1.1.1 127.0.0.53 2606:4700:4700::1111",
	        "resolvers: commented-out servers are neither listed nor "
	        "taken for real ones");
	expect (fs_hostnet_parse_resolvers ("nameserver ::1\n",
	        "nameserver fe80::1%eth0\nnameserver fe80::53%3\n", NULL),
	        "::1 fe80::1 fe80::53",
	        "resolvers: ::1 is a stub; zone suffixes are dropped");
	expect (fs_hostnet_parse_resolvers ("nameserver fe80::53%wlan0\n",
	                                    RESOLVED, NULL),
	        "fe80::53",
	        "resolvers: a link-local server with a zone is a real one");
	expect (fs_hostnet_parse_resolvers ("nameserver 127.0.0.53\n"
	                                    "nameserver 192.0.2.53\n",
	                                    RESOLVED, NULL),
	        "127.0.0.53 192.0.2.53",
	        "resolvers: not every server loopback -> no upstream files");
	expect (fs_hostnet_parse_resolvers ("search example.com\n"
	                                    "options ndots:2\n",
	                                    RESOLVED, NULL),
	        "1.1.1.1 2606:4700:4700::1111",
	        "resolvers: no nameserver at all -> the upstream files");
	expect (fs_hostnet_parse_resolvers (NULL, NULL, NM_NO_STUB),
	        "192.168.1.1 2001:db8::53 fd00::1",
	        "resolvers: no resolv.conf -> the upstream files");
	expect (fs_hostnet_parse_resolvers (NULL, NULL, NULL), "(empty)",
	        "resolvers: nothing readable");
}

/* ======================================================== SSH variables */

static void
test_ssh_env (void)
{
	expect (fs_hostnet_parse_ssh_env ("198.51.100.23 50122 192.0.2.10 22",
	                                  NULL),
	        "198.51.100.23", "SSH_CONNECTION, IPv4");
	expect (fs_hostnet_parse_ssh_env ("2001:db8::23 50122 2001:db8::10 22",
	                                  NULL),
	        "2001:db8::23", "SSH_CONNECTION, IPv6");
	expect (fs_hostnet_parse_ssh_env ("fe80::23%eth0 50122 fe80::10%eth0 22",
	                                  NULL),
	        "fe80::23", "SSH_CONNECTION, a zone suffix is dropped");
	expect (fs_hostnet_parse_ssh_env (
	        "::ffff:198.51.100.23 50122 ::ffff:192.0.2.10 22", NULL),
	        "198.51.100.23", "SSH_CONNECTION, IPv4-mapped comes out IPv4");
	expect (fs_hostnet_parse_ssh_env ("garbage", NULL), "(empty)",
	        "SSH_CONNECTION, garbage");
	expect (fs_hostnet_parse_ssh_env ("999.1.2.3 50122 192.0.2.10 22",
	                                  NULL),
	        "(empty)", "SSH_CONNECTION, not an address");
	expect (fs_hostnet_parse_ssh_env ("bastion.example 50122 192.0.2.10 22",
	                                  NULL),
	        "(empty)", "SSH_CONNECTION, a name is never looked up");
	expect (fs_hostnet_parse_ssh_env ("", ""), "(empty)",
	        "SSH variables empty");
	expect (fs_hostnet_parse_ssh_env (NULL, NULL), "(empty)",
	        "SSH variables unset");
	expect (fs_hostnet_parse_ssh_env (NULL, "203.0.113.8 50122 22"),
	        "203.0.113.8", "only SSH_CLIENT");
	expect (fs_hostnet_parse_ssh_env ("garbage", "203.0.113.8 50122 22"),
	        "203.0.113.8", "SSH_CONNECTION garbage -> SSH_CLIENT");
	expect (fs_hostnet_parse_ssh_env ("198.51.100.23 50122 192.0.2.10 22",
	                                  "203.0.113.8 50122 22"),
	        "198.51.100.23", "both set -> SSH_CONNECTION's client");
}

/* ========================================================== TCP tables */

/* /proc/net/tcp of a machine at 10.0.2.15 ("0F02000A") running sshd.
 * Addresses are little-endian words, ports plain hex ("0016" is 22),
 * states hex: 01 ESTABLISHED, 06 TIME_WAIT, 0A LISTEN. */
static const gchar TCP4[] =
	"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     \n"
	/* sshd listening on 0.0.0.0:22: out */
	"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18123 1 0000000000000000 100 0 0 10 0                     \n"
	/* an SSH session from 198.51.100.23: in */
	"   1: 0F02000A:0016 176433C6:C35A 01 00000000:00000000 02:000A7D1F 00000000     0        0 27154 4 0000000000000000 20 4 31 10 -1                    \n"
	/* a session from 203.0.113.11 that has ended (TIME_WAIT): out */
	"   2: 0F02000A:0016 0B7100CB:D431 06 00000000:00000000 03:00001564 00000000     0        0 0 3 0000000000000000                                      \n"
	/* a web client of port 80, 203.0.113.12: another port */
	"   3: 0F02000A:0050 0C7100CB:E1A2 01 00000000:00000000 00:00000000 00000000    33        0 31337 1 0000000000000000 20 4 30 10 -1                    \n"
	/* local port 0x1600 (22 with its bytes swapped), to 203.0.113.13 */
	"   4: 0F02000A:1600 0D7100CB:0016 01 00000000:00000000 00:00000000 00000000  1000        0 40001 1 0000000000000000 20 4 30 10 -1                    \n"
	/* a second SSH session, from 203.0.113.14: in */
	"   5: 0F02000A:0016 0E7100CB:C001 01 00000000:00000000 02:00098E36 00000000     0        0 27999 2 0000000000000000 20 4 29 10 -1                    \n"
	/* our own SSH client to 203.0.113.15: 22 is the REMOTE port */
	"   6: 0F02000A:9C40 0F7100CB:0016 01 00000000:00000000 02:00098E36 00000000  1000        0 28000 2 0000000000000000 20 4 29 10 -1                    \n"
	/* damaged */
	"   7: 0F02000A:0016 0F7100C:C002 01 00000000:00000000\n"
	"   8: 0F02000A:0016\n";

/* /proc/net/tcp6: each address four little-endian words. */
static const gchar TCP6[] =
	"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	"   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18125 1 0000000000000000 100 0 0 10 0\n"
	/* an IPv6 session from 2001:db8::23 to 2001:db8::10: in */
	"   1: B80D0120000000000000000010000000:0016 B80D0120000000000000000023000000:D6F2 01 00000000:00000000 02:000A7D1F 00000000     0        0 27160 4 0000000000000000 20 4 31 10 -1\n"
	/* an IPv4 client of the dual-stack socket, ::ffff:203.0.113.40 */
	"   2: 0000000000000000FFFF00000F02000A:0016 0000000000000000FFFF0000287100CB:C35B 01 00000000:00000000 02:000A7D1F 00000000     0        0 27161 4 0000000000000000 20 4 31 10 -1\n"
	/* ended, from 2001:db8::24: out */
	"   3: B80D0120000000000000000010000000:0016 B80D0120000000000000000024000000:D6F3 06 00000000:00000000 03:00001564 00000000     0        0 0 3 0000000000000000\n"
	/* port 443, from 2001:db8::99: another port */
	"   4: B80D0120000000000000000010000000:01BB B80D0120000000000000000099000000:E000 01 00000000:00000000 00:00000000 00000000    33        0 31338 1 0000000000000000 20 4 30 10 -1\n";

static void
test_tcp (void)
{
	expect (fs_hostnet_parse_tcp_peers (TCP4, FALSE, 22),
	        "198.51.100.23 203.0.113.14",
	        "tcp: ESTABLISHED rows on local port 22 (not LISTEN, not "
	        "TIME_WAIT, not port 0x1600, not a remote port 22)");
	expect (fs_hostnet_parse_tcp_peers (TCP4, FALSE, 80), "203.0.113.12",
	        "tcp: the port asked for, not always 22");
	expect (fs_hostnet_parse_tcp_peers (TCP6, TRUE, 22),
	        "203.0.113.40 2001:db8::23",
	        "tcp6: ESTABLISHED on port 22; the IPv4-mapped peer comes "
	        "out as IPv4");
	expect (fs_hostnet_parse_tcp_peers (TCP6, TRUE, 443), "2001:db8::99",
	        "tcp6: port 443");
	expect (fs_hostnet_parse_tcp_peers (TCP6, FALSE, 22), "(empty)",
	        "tcp6 text read as tcp: no row fits");
	expect (fs_hostnet_parse_tcp_peers (TCP4, TRUE, 22), "(empty)",
	        "tcp text read as tcp6: no row fits");
	expect (fs_hostnet_parse_tcp_peers (NULL, FALSE, 22), "(empty)",
	        "tcp: no text");
}

/* ====================================================== hostile input */

/* Damaged and boundary input for every parser: what is not exactly the
 * kernel's (or resolv.conf's) form adds nothing, never a different
 * address, and nothing is read past a field's end. */
static void
test_hostile (void)
{
	GString *big;

	/* Every field one digit off, a sign or a prefix; then one good
	 * row, last and without its newline, which still counts. */
	expect (fs_hostnet_parse_route (
	        "eth0\t00000000\t0016433C6\t0003\n"     /* 9 digits     */
	        "eth0\t00000000\t0x6433C6\t0003\n"      /* 0x prefix    */
	        "eth0\t00000000\t+16433C6\t0003\n"      /* sign         */
	        "eth0\t000000000\t016433C6\t0003\n"     /* dest 9       */
	        "eth0\t0000000\t016433C6\t0003\n"       /* dest 7       */
	        "eth0\t00000000\t016433C6\t-003\n"      /* flags sign   */
	        "eth0\t00000000\t016433C6\t000000003\n" /* flags 9      */
	        "eth0\t00000000\t016433C6\n"            /* no flags     */
	        "\n\n\t\n"
	        "eth0 00000000 FE0200C0 0003"),
	        "192.0.2.254",
	        "hostile /proc/net/route: damaged fields add nothing; a last "
	        "row without its newline counts");
	expect (fs_hostnet_parse_route (""), "(empty)",
	        "hostile /proc/net/route: empty text");

	expect (fs_hostnet_parse_ipv6_route (
	        /* destination 31 and 33 digits */
	        "0000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n"
	        "000000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000002 00000400 00000001 00000000 00000003 eth0\n"
	        /* next hop 33 digits, and one with a non-digit */
	        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe8000000000000000000000000000033 00000400 00000001 00000000 00000003 eth0\n"
	        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000000000000000000g 00000400 00000001 00000000 00000003 eth0\n"
	        /* prefix length not hex, and 0x100 */
	        "00000000000000000000000000000000 zz 00000000000000000000000000000000 00 fe800000000000000000000000000005 00000400 00000001 00000000 00000003 eth0\n"
	        "00000000000000000000000000000000 100 00000000000000000000000000000000 00 fe800000000000000000000000000006 00000400 00000001 00000000 00000003 eth0\n"
	        /* only five fields: still a default with a next hop */
	        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 FE800000000000000000000000000007"),
	        "fe80::7",
	        "hostile /proc/net/ipv6_route: wrong widths and non-digits "
	        "add nothing");

	/* A port over 0xffff never stands for 22, and a slot that is not
	 * "<digits>:" is not a row. */
	expect (fs_hostnet_parse_tcp_peers (
	        "   0: 0F02000A:10016 176433C6:C35A 01 0\n"   /* port 5 digits */
	        "   1: 0F02000A:0016 176433C6 01 0\n"         /* no port       */
	        "   2: 0F02000A:0016 176433C6:C35A:1 01 0\n"  /* two colons    */
	        "   x: 0F02000A:0016 186433C6:C35A 01 0\n"    /* slot          */
	        "    : 0F02000A:0016 196433C6:C35A 01 0\n"    /* slot          */
	        "   3 0F02000A:0016 1A6433C6:C35A 01 0\n"     /* no colon      */
	        "   4: 0F02000A:0016 1B6433C6:C35A 001 0\n"   /* 001 is 01     */
	        "   5: 0F02000A:0016 1C6433C6:C35A 11 0\n"    /* 0x11, not 01  */
	        "   6: 0F02000A:0016 1D6433C6:C35A",          /* no state      */
	        FALSE, 22),
	        "198.51.100.27",
	        "hostile tcp: damaged rows add nothing, a different state "
	        "is not ESTABLISHED");
	expect (fs_hostnet_parse_tcp_peers (
	        "   0: 0F02000A:0016 176433C6:C35A 01 0\n", FALSE, 0x10016),
	        "(empty)",
	        "hostile tcp: a local port over 65535 matches no row");

	expect (fs_hostnet_parse_ssh_env (" \t198.51.100.23\t50122 x 22",
	                                  NULL),
	        "198.51.100.23", "hostile SSH: leading blanks and tabs");
	expect (fs_hostnet_parse_ssh_env ("198.51.100.23/24 50122 x 22",
	                                  "203.0.113.8 50122 22"),
	        "203.0.113.8",
	        "hostile SSH: a prefix is not an address -> SSH_CLIENT");
	expect (fs_hostnet_parse_ssh_env ("%eth0 50122 x 22",
	                                  "203.0.113.8%eth1 50122 22"),
	        "203.0.113.8",
	        "hostile SSH: a bare zone is not an address; an IPv4 zone "
	        "is dropped");
	expect (fs_hostnet_parse_ssh_env ("198.51.100.23,203.0.113.1 1 x 22",
	                                  NULL),
	        "(empty)", "hostile SSH: two addresses in one word");
	big = g_string_new (NULL);
	while (big->len < 256 * 1024)
		g_string_append (big, "1.2.3.4.");
	expect (fs_hostnet_parse_ssh_env (big->str, big->str), "(empty)",
	        "hostile SSH: a 256 KiB word");
	g_string_free (big, TRUE);

	/* "nameserver" as a prefix of another word, upper case, and
	 * blanks around: only the real keyword counts. */
	expect (fs_hostnet_parse_resolvers (
	        "nameserver127.0.0.1\n"
	        "NAMESERVER 203.0.113.1\n"
	        "nameservers 203.0.113.2\n"
	        "  nameserver\t127.0.0.53  \r\n"
	        "nameserver\n"
	        "nameserver not-an-address\n",
	        "nameserver 1.1.1.1\n", NULL),
	        "1.1.1.1 127.0.0.53",
	        "hostile resolvers: lookalike lines are not servers, so "
	        "127.0.0.53 alone still means the upstream file");
	expect (fs_hostnet_parse_resolvers ("nameserver 127.255.255.255\n"
	                                    "nameserver 128.0.0.0\n",
	                                    "nameserver 1.1.1.1\n", NULL),
	        "127.255.255.255-128.0.0.0",
	        "hostile resolvers: 128.0.0.0 next to 127/8 is a real "
	        "server (merged intervals are not taken for loopback)");
	expect (fs_hostnet_parse_resolvers ("nameserver ::1\nnameserver ::2\n",
	                                    "nameserver 1.1.1.1\n", NULL),
	        "::1-::2",
	        "hostile resolvers: ::2 next to ::1 is a real server");
}

/* ===================================================== new, free, all */

static void
test_new_all (void)
{
	FsHostNet *h = fs_hostnet_new ();
	FsRangeSet *all;

	CHECK (h != NULL && h->own != NULL && h->onlink != NULL &&
	       h->gateways != NULL && h->resolvers != NULL &&
	       h->sessions != NULL && h->update_hosts != NULL &&
	       fs_range_set_is_empty (h->own) &&
	       fs_range_set_is_empty (h->onlink) &&
	       fs_range_set_is_empty (h->gateways) &&
	       fs_range_set_is_empty (h->resolvers) &&
	       fs_range_set_is_empty (h->sessions) &&
	       fs_range_set_is_empty (h->update_hosts) && all_normalized (h),
	       "fs_hostnet_new: six empty, normalized sets");
	expect (fs_hostnet_all (h), "(empty)", "fs_hostnet_all of nothing");

	/* One entry in each set, so a set left out shows; overlapping and
	 * adjacent ones, so the result must be merged. */
	fs_range_set_add_text (h->own, "198.51.100.7");
	fs_range_set_add_text (h->onlink, "198.51.100.0/24");
	fs_range_set_add_text (h->gateways, "192.0.2.1");
	fs_range_set_add_text (h->resolvers, "2001:db8::53");
	fs_range_set_add_text (h->sessions, "203.0.113.9");
	fs_range_set_add_text (h->update_hosts, "203.0.113.10");
	fs_range_set_add_text (h->update_hosts, "2001:db8::54");
	all = fs_hostnet_all (h);
	CHECK (is_normalized (all), "fs_hostnet_all: normalized");
	expect (all, "192.0.2.1 198.51.100.0/24 203.0.113.9-203.0.113.10 "
	        "2001:db8::53-2001:db8::54",
	        "fs_hostnet_all: every set, merged");

	expect (fs_hostnet_all (NULL), "(empty)", "fs_hostnet_all (NULL)");
	fs_hostnet_free (h);
	fs_hostnet_free (NULL);
	CHECK (TRUE, "fs_hostnet_free (NULL) is harmless");
}

/* ===================================================== this machine */

static void
test_read_here (void)
{
	FsHostNet *h;

	/* Only this process's environment: the live part sets its own. */
	g_setenv ("SSH_CONNECTION", "192.0.2.201 50022 192.0.2.1 22", TRUE);
	g_unsetenv ("SSH_CLIENT");
	h = fs_hostnet_read (NULL);

	CHECK (h != NULL && all_normalized (h),
	       "read here: six sets, all normalized");
#if defined __linux__ || defined G_OS_WIN32
	CHECK (!fs_range_set_contains_text (h->own, "127.0.0.1") &&
	       !fs_range_set_contains_text (h->own, "::1") &&
	       !fs_range_set_contains_text (h->onlink, "127.0.0.1"),
	       "read here: loopback is in neither own nor onlink");
	CHECK (fs_range_set_contains_text (h->sessions, "192.0.2.201"),
	       "read here: the client in $SSH_CONNECTION is kept");
	CHECK (fs_range_set_is_empty (h->update_hosts),
	       "read here: no hosts asked for, none resolved");
#else
	CHECK (fs_range_set_is_empty (h->own) &&
	       fs_range_set_is_empty (h->sessions),
	       "read here: empty sets outside Linux and Windows");
#endif
	fs_hostnet_free (h);
}

/* ================================================== the live namespace */

#ifdef __linux__

/* The child's exit status: 0, or this plus its failure count. */
#define LIVE_FAILED   100
#define LIVE_MAX_FAIL 50

/* Runs argv (argv[0] searched in PATH); TRUE when it exits 0.  On
 * failure *why (nullable) gets its error output, first line. */
static gboolean
run (const gchar *const *argv, gchar **why)
{
	GError *error = NULL;
	GSubprocess *proc;
	gchar *err = NULL;
	gboolean ok;

	proc = g_subprocess_newv (argv, G_SUBPROCESS_FLAGS_STDOUT_SILENCE |
	                          G_SUBPROCESS_FLAGS_STDERR_PIPE, &error);
	if (proc == NULL) {
		if (why != NULL)
			*why = g_strdup (error->message);
		g_error_free (error);
		return FALSE;
	}
	ok = g_subprocess_communicate_utf8 (proc, NULL, NULL, NULL, &err,
	                                    &error) &&
	     g_subprocess_get_successful (proc);
	if (!ok && why != NULL) {
		const gchar *msg = error != NULL ? error->message :
		                   (err != NULL ? err : "");

		*why = g_strndup (msg, strcspn (msg, "\n"));
	}
	g_clear_error (&error);
	g_free (err);
	g_object_unref (proc);
	return ok;
}

/* A setup step that must work; a FAIL line when it does not. */
static gboolean
setup (const gchar *const *argv)
{
	gchar *why = NULL;
	gboolean ok = run (argv, &why);

	if (!ok) {
		GString *cmd = g_string_new (argv[0]);

		for (guint i = 1; argv[i] != NULL; i++)
			g_string_append_printf (cmd, " %s", argv[i]);
		CHECK (FALSE, "live setup: %s (%s)", cmd->str, why);
		g_string_free (cmd, TRUE);
	}
	g_free (why);
	return ok;
}

#define ARGV(...) ((const gchar *const[]) { __VA_ARGS__, NULL })

/* "net:[4026531840]": which namespace of `kind' the process at `proc'
 * ("/proc/self", "/proc/1") is in; NULL when that cannot be read. */
static gchar *
namespace_of (const gchar *proc, const gchar *kind)
{
	gchar *path = g_strdup_printf ("%s/ns/%s", proc, kind);
	gchar *id = g_file_read_link (path, NULL);

	g_free (path);
	return id;
}

/* A new network namespace has every interface down, lo included (and
 * the fallback tunnels some kernel modules add to each one); the
 * host's has at least lo up. */
static gboolean
fresh_netns (void)
{
	struct ifaddrs *list = NULL;
	gboolean fresh = getifaddrs (&list) == 0;

	for (const struct ifaddrs *ifa = list; fresh && ifa != NULL;
	     ifa = ifa->ifa_next)
		if ((ifa->ifa_flags & IFF_UP) != 0)
			fresh = FALSE;
	if (list != NULL)
		freeifaddrs (list);
	return fresh;
}

/* TRUE only in network and mount namespaces of this process's own:
 * other than its parent's (the test that ran "unshare", which execs
 * this program in place), other than init's where those can be read,
 * and a network namespace nobody has set up yet.  All read from /proc,
 * nothing taken from the environment; the parent check alone keeps
 * the live part off the host, the other two back it up. */
static gboolean
isolated (void)
{
	gchar *parent = g_strdup_printf ("/proc/%d", (gint) getppid ());
	gchar *net = namespace_of ("/proc/self", "net");
	gchar *mnt = namespace_of ("/proc/self", "mnt");
	gchar *parent_net = namespace_of (parent, "net");
	gchar *parent_mnt = namespace_of (parent, "mnt");
	gchar *init_net = namespace_of ("/proc/1", "net");
	gchar *init_mnt = namespace_of ("/proc/1", "mnt");
	gboolean ok = net != NULL && mnt != NULL &&
	              parent_net != NULL && parent_mnt != NULL &&
	              strcmp (net, parent_net) != 0 &&
	              strcmp (mnt, parent_mnt) != 0 &&
	              g_strcmp0 (net, init_net) != 0 &&
	              g_strcmp0 (mnt, init_mnt) != 0 &&
	              fresh_netns ();

	g_free (parent);
	g_free (net);
	g_free (mnt);
	g_free (parent_net);
	g_free (parent_mnt);
	g_free (init_net);
	g_free (init_mnt);
	return ok;
}

/* Writes in place (never a new file renamed over it: a bind mount
 * holds on to the file it was made from). */
static gboolean
write_in_place (const gchar *path, const gchar *text)
{
	FILE *f = fopen (path, "w");
	gboolean ok;

	if (f == NULL)
		return FALSE;
	ok = fputs (text, f) >= 0;
	return fclose (f) == 0 && ok;
}

static gboolean
same_text (const gchar *path, const gchar *want)
{
	gchar *text = NULL;
	gboolean same = g_file_get_contents (path, &text, NULL, NULL) &&
	                g_strcmp0 (text, want) == 0;

	g_free (text);
	return same;
}

/* fs-hostnet.c's cap on a resolver file. */
#define RESOLVER_CAP_HERE (1024 * 1024)

#define RUN_DIR   "/run/sfw-hostnet"
#define LIVE_STUB "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n"
#define LIVE_HOSTS \
	"127.0.0.1 localhost\n" \
	"198.51.100.211 feeds.stockfw.test\n" \
	"2001:db8::79 feeds.stockfw.test\n"

/* A tmpfs over /run (this mount namespace's only) holding the resolver
 * files, and fixtures bound over /etc/resolv.conf and /etc/hosts.
 * Nothing is written outside that tmpfs: /etc is only ever read, and
 * every bind is read back before the test relies on it. */
static gboolean
mount_fixtures (void)
{
	GDir *dir;
	gboolean empty;

	if (mount ("sfw-hostnet", "/run", "tmpfs", MS_NOSUID | MS_NODEV,
	           "mode=0755,size=64m") != 0) {
		g_print ("SKIP: live resolver and hosts files: cannot mount "
		         "a tmpfs on /run here (%s)\n", g_strerror (errno));
		return FALSE;
	}
	dir = g_dir_open ("/run", 0, NULL);
	empty = dir != NULL && g_dir_read_name (dir) == NULL;
	if (dir != NULL)
		g_dir_close (dir);
	if (!empty) {
		CHECK (FALSE, "live setup: /run is a fresh tmpfs");
		return FALSE;
	}

	if (g_mkdir_with_parents (RUN_DIR, 0755) != 0 ||
	    g_mkdir_with_parents ("/run/systemd/resolve", 0755) != 0 ||
	    g_mkdir_with_parents ("/run/NetworkManager", 0755) != 0 ||
	    !write_in_place (RUN_DIR "/resolv.conf", LIVE_STUB) ||
	    !write_in_place (RUN_DIR "/hosts", LIVE_HOSTS) ||
	    !write_in_place (RUN_DIR "/upstream.conf",
	                     "nameserver 1.1.1.1\n"
	                     "nameserver 2606:4700:4700::1111\n") ||
	    /* resolved's file as a symlink, as /etc/resolv.conf often
	     * is: the reader follows them */
	    symlink (RUN_DIR "/upstream.conf",
	             "/run/systemd/resolve/resolv.conf") != 0 ||
	    !write_in_place ("/run/NetworkManager/no-stub-resolv.conf",
	                     "# Generated by NetworkManager\n"
	                     "nameserver 192.0.2.53\n")) {
		CHECK (FALSE, "live setup: resolver files in the tmpfs (%s)",
		       g_strerror (errno));
		return FALSE;
	}

	if (mount (RUN_DIR "/resolv.conf", "/etc/resolv.conf", NULL,
	           MS_BIND, NULL) != 0 ||
	    mount (RUN_DIR "/hosts", "/etc/hosts", NULL, MS_BIND, NULL) != 0 ||
	    !same_text ("/etc/resolv.conf", LIVE_STUB) ||
	    !same_text ("/etc/hosts", LIVE_HOSTS)) {
		g_print ("SKIP: live resolver and hosts files: cannot bind "
		         "fixtures over /etc here\n");
		return FALSE;
	}
	return TRUE;
}

/* A TCP connection from `from' to `to':22; the client end. */
static gint
connect_from (const gchar *from, const gchar *to)
{
	struct sockaddr_in src = { 0 }, dst = { 0 };
	gint fd = socket (AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

	src.sin_family = dst.sin_family = AF_INET;
	dst.sin_port = htons (22);
	if (fd < 0 || inet_pton (AF_INET, from, &src.sin_addr) != 1 ||
	    inet_pton (AF_INET, to, &dst.sin_addr) != 1 ||
	    bind (fd, (struct sockaddr *) &src, sizeof src) != 0 ||
	    connect (fd, (struct sockaddr *) &dst, sizeof dst) != 0) {
		if (fd >= 0)
			close (fd);
		return -1;
	}
	return fd;
}

/* Whether /proc/net/tcp (read with fs-netparse, not with the code under
 * test) has a row from `peer' to local port 22 in `state'. */
static gboolean
kernel_shows (const gchar *peer, guint state)
{
	gchar *text = NULL;
	GList *rows;
	gboolean found = FALSE;

	if (!g_file_get_contents ("/proc/net/tcp", &text, NULL, NULL))
		return FALSE;
	rows = fs_netparse_proc_tcp (text, FALSE);
	for (GList *l = rows; l != NULL && !found; l = l->next) {
		const FsNetSocket *s = l->data;

		found = s->local_port == 22 && s->state == state &&
		        g_strcmp0 (s->remote_addr, peer) == 0;
	}
	g_list_free_full (rows, (GDestroyNotify) fs_net_socket_free);
	g_free (text);
	return found;
}

static void
on_alarm (int sig)
{
	static const char msg[] =
		"FAIL: live: a FIFO at a resolver path is skipped, not waited "
		"on (fs_hostnet_read hung on it)\n";
	ssize_t n;

	(void) sig;
	/* write(2), not stdio: this runs in a signal handler */
	n = write (STDOUT_FILENO, msg, sizeof msg - 1);
	(void) n;
	_exit (LIVE_FAILED + 1);
}

static void
check_v4 (const FsRangeSet *set, const gchar *want, const gchar *what)
{
	gchar *got = flat4 (set);

	CHECK (g_strcmp0 (got, want) == 0, "%s: %s", what, want);
	if (g_strcmp0 (got, want) != 0)
		g_print ("      (got %s)\n", got);
	g_free (got);
}

/* Many SSH sessions at once, so /proc/net/tcp (150 bytes a row) is
 * more than two of the reader's 64 KiB blocks and takes dozens of reads
 * (the kernel hands out a page of whole rows per read): every session
 * must still be found, the last ones included.  The peers are 127.1.x.y
 * on lo; the server ends wait in `srv''s accept queue, ESTABLISHED all
 * the same. */
#define MANY_SESSIONS 500

static void
check_many_sessions (gint srv)
{
	gint clients[MANY_SESSIONS];
	guint made = 0, found = 0;
	gchar *text = NULL;
	gsize len = 0;
	FsHostNet *h;

	if (listen (srv, 2 * MANY_SESSIONS) != 0) {
		CHECK (FALSE, "live setup: a longer accept queue (%s)",
		       g_strerror (errno));
		return;
	}
	for (guint i = 0; i < MANY_SESSIONS; i++) {
		gchar *from = g_strdup_printf ("127.1.%u.%u", i / 200,
		                               i % 200 + 1);

		clients[i] = connect_from (from, "127.0.0.1");
		g_free (from);
		if (clients[i] >= 0)
			made++;
	}
	CHECK (made == MANY_SESSIONS &&
	       g_file_get_contents ("/proc/net/tcp", &text, &len, NULL) &&
	       len > 2 * 64 * 1024,
	       "live setup: %u sessions on port 22, /proc/net/tcp over "
	       "two 64 KiB blocks (%" G_GSIZE_FORMAT " bytes)", made, len);
	g_free (text);

	h = fs_hostnet_read (NULL);
	for (guint i = 0; i < MANY_SESSIONS; i++) {
		guint32 peer = (127u << 24) | (1u << 16) | ((i / 200) << 8) |
		               (i % 200 + 1);

		if (fs_range_set_contains4 (h->sessions, peer))
			found++;
	}
	CHECK (found == MANY_SESSIONS,
	       "live: sessions: all %u peers of a /proc/net/tcp of many "
	       "reads, to its end (found %u)",
	       MANY_SESSIONS, found);
	fs_hostnet_free (h);

	for (guint i = 0; i < MANY_SESSIONS; i++)
		if (clients[i] >= 0)
			close (clients[i]);
}

static gint
live_main (void)
{
	const gchar *const hosts[] = {
		"198.51.100.200", "2001:db8::77", "[2001:db8::78]",
		"feeds.stockfw.test", "stockfw-hostnet-test.invalid", "",
		NULL
	};
	gboolean files, tun, v6 = FALSE;
	gint srv = -1, live1 = -1, peer1 = -1, live2 = -1, peer2 = -1;
	gint fds[5];
	FsHostNet *h;
	FsRangeSet *all, *six;
	gchar *text, *why = NULL;
	gint one = 1;
	struct sockaddr_in any = { 0 };

	/* Never on the host: refuse unless both namespaces are new. */
	if (!isolated ()) {
		g_print ("FAIL: live: not in private network and mount "
		         "namespaces; refusing to touch anything\n");
		return LIVE_FAILED + 1;
	}
	g_print ("      (live: in private network and mount namespaces)\n");

	files = mount_fixtures ();

	/* lo with a service address on it; sfw0 up with three addresses
	 * and a fourth with a peer (ifupdown's "pointopoint" on Ethernet,
	 * as some hosting providers configure it); sfw2 down with one; a
	 * point-to-point tun with a peer. */
	if (!setup (ARGV ("ip", "link", "set", "lo", "up")) ||
	    !setup (ARGV ("ip", "addr", "add", "203.0.113.200/32", "dev", "lo")) ||
	    !setup (ARGV ("ip", "link", "add", "sfw0", "type", "veth",
	                  "peer", "name", "sfw1")) ||
	    !setup (ARGV ("ip", "addr", "add", "198.51.100.7/24", "dev", "sfw0")) ||
	    !setup (ARGV ("ip", "addr", "add", "203.0.113.5/26", "dev", "sfw0")) ||
	    !setup (ARGV ("ip", "addr", "add", "203.0.113.6/26", "dev", "sfw0")) ||
	    !setup (ARGV ("ip", "addr", "add", "198.51.100.9", "peer",
	                  "203.0.113.150/32", "dev", "sfw0")) ||
	    !setup (ARGV ("ip", "link", "set", "sfw0", "up")) ||
	    !setup (ARGV ("ip", "link", "set", "sfw1", "up")) ||
	    !setup (ARGV ("ip", "link", "add", "sfw2", "type", "veth",
	                  "peer", "name", "sfw3")) ||
	    !setup (ARGV ("ip", "addr", "add", "192.0.2.77/24", "dev", "sfw2")))
		return LIVE_FAILED + MIN (failures, LIVE_MAX_FAIL);

	tun = run (ARGV ("ip", "tuntap", "add", "dev", "sfwtun", "mode", "tun"),
	           &why) &&
	      setup (ARGV ("ip", "addr", "add", "10.9.0.1", "peer",
	                   "203.0.113.133/32", "dev", "sfwtun")) &&
	      setup (ARGV ("ip", "link", "set", "sfwtun", "up"));
	if (!tun)
		g_print ("SKIP: live point-to-point link: no tun device here "
		         "(%s)\n", why != NULL ? why : "");
	g_clear_pointer (&why, g_free);

	/* --- read 1: the feed hosts, while this computer has IPv4 and no
	 * IPv6 address and no route out (a lookup fails at once) */
	h = fs_hostnet_read (hosts);
	CHECK (all_normalized (h), "live read 1: all six sets normalized");
	CHECK (fs_range_set_contains_text (h->update_hosts, "198.51.100.200") &&
	       fs_range_set_contains_text (h->update_hosts, "2001:db8::78"),
	       "live: update hosts: IPv4 literal and a bracketed IPv6 one");
	CHECK (fs_range_set_contains_text (h->update_hosts, "2001:db8::77"),
	       "live: update hosts: an IPv6 address is kept although this "
	       "computer has no IPv6 address (no AI_ADDRCONFIG)");
	if (files) {
		CHECK (fs_range_set_contains_text (h->update_hosts,
		                                   "198.51.100.211") &&
		       fs_range_set_contains_text (h->update_hosts,
		                                   "2001:db8::79"),
		       "live: update hosts: a name's addresses, both families");
		check_v4 (h->update_hosts, "198.51.100.200 198.51.100.211",
		          "live: update hosts: nothing for a name that does not "
		          "resolve");
	}
	fs_hostnet_free (h);

	/* IPv6 where the kernel has it, added after read 1 so that read
	 * proved the lookup does not depend on having IPv6. */
	if (g_file_test ("/proc/net/if_inet6", G_FILE_TEST_EXISTS)) {
		v6 = run (ARGV ("ip", "-6", "addr", "add", "2001:db8:7::7/64",
		                "dev", "sfw0", "nodad"), &why) &&
		     run (ARGV ("ip", "-6", "route", "add", "default", "via",
		                "2001:db8:7::1", "dev", "sfw0"), &why);
		if (!v6)
			g_print ("SKIP: live IPv6: the kernel refused an address "
			         "or route (%s); the fixtures cover IPv6\n",
			         why != NULL ? why : "");
		g_clear_pointer (&why, g_free);
	} else {
		g_print ("SKIP: live IPv6: this kernel has no IPv6; the "
		         "fixtures cover it\n");
	}

	if (!setup (ARGV ("ip", "route", "add", "default", "via",
	                  "198.51.100.1", "dev", "sfw0")))
		return LIVE_FAILED + MIN (failures, LIVE_MAX_FAIL);

	/* sshd's port: one session that stays up (from 203.0.113.5) and
	 * one that this end closes first, so ours sits in TIME_WAIT (from
	 * 203.0.113.6). */
	srv = socket (AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	any.sin_family = AF_INET;
	any.sin_port = htons (22);
	if (srv < 0 ||
	    setsockopt (srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0 ||
	    bind (srv, (struct sockaddr *) &any, sizeof any) != 0 ||
	    listen (srv, 8) != 0 ||
	    (peer1 = connect_from ("203.0.113.5", "198.51.100.7")) < 0 ||
	    (live1 = accept (srv, NULL, NULL)) < 0 ||
	    (peer2 = connect_from ("203.0.113.6", "198.51.100.7")) < 0 ||
	    (live2 = accept (srv, NULL, NULL)) < 0) {
		CHECK (FALSE, "live setup: SSH sessions on port 22 (%s)",
		       g_strerror (errno));
	} else {
		close (live2);
		live2 = -1;
		g_usleep (50 * 1000);
		close (peer2);
		peer2 = -1;
	}
	for (guint i = 0; i < 50 && !(kernel_shows ("203.0.113.5", 0x01) &&
	                              kernel_shows ("203.0.113.6", 0x06)); i++)
		g_usleep (100 * 1000);
	CHECK (kernel_shows ("203.0.113.5", 0x01) &&
	       kernel_shows ("203.0.113.6", 0x06),
	       "live setup: the kernel shows one SSH session up and one in "
	       "TIME_WAIT");

	g_setenv ("SSH_CONNECTION", "192.0.2.200 50022 198.51.100.7 22", TRUE);
	g_unsetenv ("SSH_CLIENT");

	/* --- read 2: everything */
	h = fs_hostnet_read (NULL);
	CHECK (all_normalized (h), "live read 2: all six sets normalized");
	check_v4 (h->own, tun ?
	          "10.9.0.1 198.51.100.7 198.51.100.9 203.0.113.5-203.0.113.6 "
	          "203.0.113.200" :
	          "198.51.100.7 198.51.100.9 203.0.113.5-203.0.113.6 "
	          "203.0.113.200",
	          "live: own, IPv4: every address of the interfaces that are "
	          "up, lo's service address too");
	CHECK (!fs_range_set_contains_text (h->own, "127.0.0.1") &&
	       !fs_range_set_contains_text (h->own, "::1") &&
	       !fs_range_set_contains_text (h->onlink, "127.0.0.1") &&
	       !fs_range_set_contains_text (h->onlink, "::1"),
	       "live: loopback is not in own (nor in onlink)");
	CHECK (!fs_range_set_contains_text (h->own, "192.0.2.77") &&
	       !fs_range_set_contains_text (h->onlink, "192.0.2.1"),
	       "live: an interface that is down adds nothing");
	check_v4 (h->onlink, tun ?
	          "198.51.100.0/24 203.0.113.0/26 203.0.113.133 203.0.113.150 "
	          "203.0.113.200" :
	          "198.51.100.0/24 203.0.113.0/26 203.0.113.150 203.0.113.200",
	          "live: onlink, IPv4: each address's prefix");
	CHECK (fs_range_set_contains_text (h->onlink, "203.0.113.150"),
	       "live: an address with a peer on an Ethernet link: the peer "
	       "is on-link (the kernel routes it there)");
	if (tun)
		CHECK (fs_range_set_contains_text (h->onlink, "203.0.113.133") &&
		       !fs_range_set_contains_text (h->onlink, "10.9.0.1"),
		       "live: a point-to-point link: the peer is on-link, not "
		       "the local address's /32 block");
	check_v4 (h->gateways, "198.51.100.1",
	          "live: gateways, IPv4: the default route's");
	check_v4 (h->sessions, "192.0.2.200 203.0.113.5",
	          "live: sessions: $SSH_CONNECTION's client and the SSH "
	          "session that is up (not the ended one, not the listener)");
	if (files)
		expect (fs_range_set_copy (h->resolvers),
		        "1.1.1.1 127.0.0.53 192.0.2.53 2606:4700:4700::1111",
		        "live: resolvers: behind the stub, resolved's file "
		        "(a symlink) and NetworkManager's");
	if (v6) {
		CHECK (fs_range_set_contains_text (h->own, "2001:db8:7::7") &&
		       fs_range_set_contains_text (h->onlink, "2001:db8:7::abcd") &&
		       fs_range_set_contains_text (h->gateways, "2001:db8:7::1"),
		       "live IPv6: own, onlink and the default gateway");
	}

	all = fs_hostnet_all (h);
	six = fs_range_set_new ();
	fs_range_set_union (six, h->own);
	fs_range_set_union (six, h->onlink);
	fs_range_set_union (six, h->gateways);
	fs_range_set_union (six, h->resolvers);
	fs_range_set_union (six, h->sessions);
	fs_range_set_union (six, h->update_hosts);
	text = flat (six);
	expect (all, text, "live: fs_hostnet_all is the six sets together");
	g_free (text);
	fs_range_set_free (six);
	fs_hostnet_free (h);

	if (srv >= 0)
		check_many_sessions (srv);

	if (files) {
		gchar *big;
		GString *pad = g_string_new ("# Generated by NetworkManager\n"
		                             "nameserver 192.0.2.53\n");

		/* --- read 3: a real server in resolv.conf */
		write_in_place (RUN_DIR "/resolv.conf", "nameserver 192.0.2.10\n");
		h = fs_hostnet_read (NULL);
		expect (fs_range_set_copy (h->resolvers), "192.0.2.10",
		        "live: resolvers: a real server in resolv.conf, the "
		        "upstream files are not read");
		fs_hostnet_free (h);
		write_in_place (RUN_DIR "/resolv.conf", LIVE_STUB);

		/* --- read 4: a resolver file far over its cap (1 MiB) */
		while (pad->len < 3 * 1024 * 1024)
			g_string_append (pad, "# padding padding padding padding "
			                 "padding padding padding padding\n");
		g_string_append (pad, "nameserver 192.0.2.54\n");
		big = g_string_free (pad, FALSE);
		write_in_place ("/run/NetworkManager/no-stub-resolv.conf", big);
		g_free (big);
		h = fs_hostnet_read (NULL);
		CHECK (fs_range_set_contains_text (h->resolvers, "192.0.2.53") &&
		       !fs_range_set_contains_text (h->resolvers, "192.0.2.54"),
		       "live: a resolver file is read up to its cap, no further");
		fs_hostnet_free (h);

		/* --- read 4b: the cap falls inside a line.  The bytes up to
		 * the cap end in "nameserver 192.0.2.5", the start of a line
		 * that names 192.0.2.54: that piece must be dropped, never
		 * read as a server that nobody named. */
		pad = g_string_new ("# Generated by NetworkManager\n"
		                    "nameserver 192.0.2.53\n");
		while (pad->len + 64 + 2 <= RESOLVER_CAP_HERE - 20)
			g_string_append (pad, "# padding padding padding padding "
			                 "padding padding padding p\n");
		g_string_append_c (pad, '#');
		while (pad->len < RESOLVER_CAP_HERE - 20 - 1)
			g_string_append_c (pad, 'p');
		g_string_append (pad, "\nnameserver 192.0.2.54\n");
		CHECK (strncmp (pad->str + RESOLVER_CAP_HERE - 20,
		                "nameserver 192.0.2.5", 20) == 0 &&
		       pad->str[RESOLVER_CAP_HERE] == '4',
		       "live setup: the cap falls between \"192.0.2.5\" and "
		       "\"4\"");
		big = g_string_free (pad, FALSE);
		write_in_place ("/run/NetworkManager/no-stub-resolv.conf", big);
		g_free (big);
		h = fs_hostnet_read (NULL);
		expect (fs_range_set_copy (h->resolvers),
		        "1.1.1.1 127.0.0.53 192.0.2.53 2606:4700:4700::1111",
		        "live: a line cut by the cap is dropped, not read as "
		        "192.0.2.5");
		fs_hostnet_free (h);

		/* --- read 5: a FIFO where a resolver file belongs: skipped,
		 * not waited on (the alarm turns a hang into a FAIL) */
		if (unlink ("/run/NetworkManager/no-stub-resolv.conf") == 0 &&
		    mkfifo ("/run/NetworkManager/no-stub-resolv.conf", 0644) == 0) {
			fflush (stdout);
			signal (SIGALRM, on_alarm);
			alarm (10);
			h = fs_hostnet_read (NULL);
			alarm (0);
			expect (fs_range_set_copy (h->resolvers),
			        "1.1.1.1 127.0.0.53 2606:4700:4700::1111",
			        "live: a FIFO at a resolver path is skipped, "
			        "not waited on");
			fs_hostnet_free (h);
		} else {
			CHECK (FALSE, "live setup: a FIFO in the tmpfs (%s)",
			       g_strerror (errno));
		}
	}

	fds[0] = live1;
	fds[1] = peer1;
	fds[2] = live2;
	fds[3] = peer2;
	fds[4] = srv;
	for (guint i = 0; i < G_N_ELEMENTS (fds); i++)
		if (fds[i] >= 0)
			close (fds[i]);

	return failures == 0 ? 0 : LIVE_FAILED + MIN (failures, LIVE_MAX_FAIL);
}

/* As root: this program again, under "unshare -n -m" (live_main), its
 * output inline and its failures counted here. */
static void
test_live (void)
{
	GSubprocess *proc;
	GError *error = NULL;
	gchar *self, *unshare, *ip;
	gchar *why = NULL;

	unshare = g_find_program_in_path ("unshare");
	ip = g_find_program_in_path ("ip");
	if (getuid () != 0 || unshare == NULL || ip == NULL) {
		g_print ("SKIP: live read in private namespaces: needs root, "
		         "unshare and ip\n");
		g_free (unshare);
		g_free (ip);
		return;
	}
	g_free (unshare);
	g_free (ip);
	if (!run (ARGV ("unshare", "-n", "-m", "--propagation", "private",
	                "true"), &why)) {
		g_print ("SKIP: live read: cannot make private network and "
		         "mount namespaces here (%s)\n", why != NULL ? why : "");
		g_free (why);
		return;
	}

	self = g_file_read_link ("/proc/self/exe", &error);
	if (self == NULL) {
		CHECK (FALSE, "live: find this program (%s)", error->message);
		g_error_free (error);
		return;
	}
	/* The child's output goes straight to ours: flush what is ours
	 * first so the lines stay in order. */
	fflush (stdout);
	proc = g_subprocess_new (G_SUBPROCESS_FLAGS_NONE, &error, "unshare",
	                         "-n", "-m", "--propagation", "private", self,
	                         "--live", NULL);
	if (proc == NULL) {
		CHECK (FALSE, "live: start the namespace child (%s)",
		       error->message);
		g_error_free (error);
	} else if (!g_subprocess_wait (proc, NULL, &error)) {
		CHECK (FALSE, "live: wait for the namespace child (%s)",
		       error->message);
		g_error_free (error);
	} else if (!g_subprocess_get_if_exited (proc)) {
		CHECK (FALSE, "live: the namespace child ran to its end (killed "
		       "by signal %d)", g_subprocess_get_term_sig (proc));
	} else {
		gint status = g_subprocess_get_exit_status (proc);

		if (status >= LIVE_FAILED &&
		    status <= LIVE_FAILED + LIVE_MAX_FAIL)
			failures += (guint) (status - LIVE_FAILED);
		else if (status != 0)
			CHECK (FALSE, "live: the namespace child ran to its end "
			       "(exit status %d)", status);
	}
	g_clear_object (&proc);
	g_free (self);
}

#endif /* __linux__ */

int
main (int argc, char **argv)
{
#ifdef __linux__
	if (argc > 1 && strcmp (argv[1], "--live") == 0)
		return live_main ();
#endif

	test_routes ();
	test_resolvers ();
	test_ssh_env ();
	test_tcp ();
	test_hostile ();
	test_new_all ();
	test_read_here ();
#ifdef __linux__
	test_live ();
#else
	g_print ("SKIP: live read: Linux only\n");
#endif

	g_print ("\n");
	if (failures == 0)
		g_print ("PASSED: 0 failure(s)\n");
	else
		g_print ("FAILED: %u failure(s)\n", failures);
	return failures == 0 ? 0 : 1;
}
