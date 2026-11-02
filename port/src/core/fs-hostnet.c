/*---[ fs-hostnet.c ]----------------------------------------------------
 * What a blocklist must never cut on this computer.  See fs-hostnet.h
 * and docs/1.0.7-threat-intel-design.md, section 6.4.
 *
 * Two halves.  The parsers are pure (text in, set out) and build on
 * every platform, so the tests pin them against fixtures modelled on
 * the real files.  fs_hostnet_read() is the only part that touches the
 * system, and only on Linux: getifaddrs(), /proc/net, the resolver
 * files, the SSH variables and getaddrinfo().  Windows has none of
 * these sources wired in yet: its blocklists are Round 3 (design
 * section 2), and until then fs_hostnet_read() answers with six empty
 * sets there.
 *--------------------------------------------------------------------*/

/* getifaddrs(), getaddrinfo(), IFF_UP and O_CLOEXEC are POSIX and BSD
 * additions a strict -std=c11 hides; the build's gnu11 shows them, and
 * this keeps the file right either way, as in fs-backend-linux.c. */
#ifdef __linux__
#define _GNU_SOURCE
#endif

/* Windows: GetAdaptersAddresses() names each adapter's gateways and DNS
 * servers.  The structures come from the headers; the function itself
 * is looked up in iphlpapi.dll at run time, so nothing that links the
 * core needs another import library. */
#if defined(_WIN32)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#endif

#include "core/fs-hostnet.h"

#include <string.h>

#ifdef __linux__
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

/* Route flags (<linux/route.h>) and a TCP state number
 * (<net/tcp_states.h>), spelled out so the parsers build anywhere. */
#define ROUTE_FLAG_UP          0x0001u
#define ROUTE_FLAG_GATEWAY     0x0002u
#define TCP_STATE_ESTABLISHED  0x01u

/* The local port whose established connections are kept: sshd's. */
#define SSH_PORT 22

/* ============================================================ helpers */

/* Splits `line' in place at runs of blanks and keeps at most `max'
 * fields; the rest of the line is not looked at.  Returns the count. */
static guint
split_fields (gchar *line, gchar **fields, guint max)
{
	guint n = 0;
	gchar *p = line;

	while (n < max) {
		while (g_ascii_isspace (*p))
			p++;
		if (*p == '\0')
			break;
		fields[n++] = p;
		while (*p != '\0' && !g_ascii_isspace (*p))
			p++;
		if (*p == '\0')
			break;
		*p++ = '\0';
	}
	return n;
}

/* The next line of a mutable text, cut off in place; NULL at the end.
 * `*cursor' moves past it. */
static gchar *
next_line (gchar **cursor)
{
	gchar *line = *cursor;
	gchar *nl;

	if (line == NULL)
		return NULL;
	nl = strchr (line, '\n');
	if (nl != NULL) {
		*nl = '\0';
		*cursor = nl + 1;
	} else {
		*cursor = NULL;
	}
	return line;
}

/* `text' as an unsigned hex number of 1 to 8 digits and nothing else
 * (no sign, no "0x", no blanks): the kernel's %X and %08X fields. */
static gboolean
parse_hex32 (const gchar *text, guint32 *out)
{
	gsize len = strlen (text);
	guint32 value = 0;

	if (len == 0 || len > 8)
		return FALSE;
	for (gsize i = 0; i < len; i++) {
		gint d = g_ascii_xdigit_value (text[i]);

		if (d < 0)
			return FALSE;
		value = (value << 4) | (guint32) d;
	}
	*out = value;
	return TRUE;
}

/* `ndigits' hex digits at `text' into ndigits / 2 bytes, two digits a
 * byte, in the order written.  Stops (FALSE) at the first non-digit,
 * so a short string is never read past its end. */
static gboolean
parse_hex_bytes (const gchar *text, gsize ndigits, guint8 *out)
{
	for (gsize i = 0; i < ndigits; i++) {
		gint d = g_ascii_xdigit_value (text[i]);

		if (d < 0)
			return FALSE;
		if (i % 2 == 0)
			out[i / 2] = (guint8) (d << 4);
		else
			out[i / 2] |= (guint8) d;
	}
	return TRUE;
}

/* An address as /proc/net/route and /proc/net/tcp{,6} print it: each
 * 32-bit word of the network-order address printed as one native
 * integer (%08X).  Read little-endian, as the contract says: on x86-64,
 * the only Linux build StockFW ships, 127.0.0.1 is "0100007F".  (A
 * big-endian kernel prints the bytes in order; a port to one would
 * have to read these words the other way round.) */
static gboolean
parse_le_words (const gchar *text, gsize words, guint8 *out)
{
	for (gsize w = 0; w < words; w++) {
		guint8 b[4];

		if (!parse_hex_bytes (text + w * 8, 8, b))
			return FALSE;
		/* "0100007F" -> 01 00 00 7F -> 7F 00 00 01 */
		out[w * 4 + 0] = b[3];
		out[w * 4 + 1] = b[2];
		out[w * 4 + 2] = b[1];
		out[w * 4 + 3] = b[0];
	}
	return TRUE;
}

/* A field that is exactly `words' little-endian words. */
static gboolean
parse_le_field (const gchar *text, gsize words, guint8 *out)
{
	return strlen (text) == words * 8 && parse_le_words (text, words, out);
}

static gboolean
all_zero (const guint8 *b, gsize len)
{
	for (gsize i = 0; i < len; i++)
		if (b[i] != 0)
			return FALSE;
	return TRUE;
}

static guint32
be32 (const guint8 *b)
{
	return ((guint32) b[0] << 24) | ((guint32) b[1] << 16) |
	       ((guint32) b[2] << 8) | (guint32) b[3];
}

static FsU128
u128_from_bytes (const guint8 *b)
{
	FsU128 v = { 0, 0 };

	for (guint i = 0; i < 8; i++)
		v.hi = (v.hi << 8) | b[i];
	for (guint i = 8; i < 16; i++)
		v.lo = (v.lo << 8) | b[i];
	return v;
}

/* ::ffff:a.b.c.d */
static gboolean
is_v4_mapped (const guint8 *b)
{
	static const guint8 prefix[12] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
	};

	return memcmp (b, prefix, sizeof prefix) == 0;
}

/* One address given as its network-order bytes (4 or 16).  An
 * IPv4-mapped IPv6 address goes in as IPv4, as fs-iprange does with
 * text: the IPv4 peer of a dual-stack socket is an IPv4 peer, and the
 * IPv4 sets are the ones that would block it. */
static void
add_address (FsRangeSet *set, const guint8 *b, gsize len)
{
	if (len == 4 || is_v4_mapped (b)) {
		guint32 v = be32 (len == 4 ? b : b + 12);

		fs_range_set_add4 (set, v, v);
	} else {
		FsU128 v = u128_from_bytes (b);

		fs_range_set_add6 (set, v, v);
	}
}

/* Everything that ends up in a set ends up merged. */
static void
merge (FsRangeSet *into, FsRangeSet *part)
{
	fs_range_set_union (into, part);
	fs_range_set_free (part);
}

/* ============================================================ parsers */

FsRangeSet *
fs_hostnet_parse_route (const gchar *text)
{
	FsRangeSet *set = fs_range_set_new ();
	gchar *copy, *cursor, *line;

	if (text == NULL)
		return set;

	copy = cursor = g_strdup (text);
	while ((line = next_line (&cursor)) != NULL) {
		gchar *f[4] = { NULL };
		guint8 dest[4], gw[4];
		guint32 flags = 0;

		/* Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		 * The header row fails the hex tests like any other line
		 * that is not a route, wherever it comes, so the table can
		 * also be parsed a block of lines at a time. */
		if (split_fields (line, f, 4) < 4 ||
		    !parse_le_field (f[1], 1, dest) ||
		    !parse_le_field (f[2], 1, gw) ||
		    !parse_hex32 (f[3], &flags))
			continue;

		/* A default route through a router that is up.  A default
		 * straight onto a link (a PPP or VPN interface) has no
		 * gateway: that link's peer is in `onlink'. */
		if (!all_zero (dest, 4) ||
		    (flags & (ROUTE_FLAG_UP | ROUTE_FLAG_GATEWAY)) !=
		    (ROUTE_FLAG_UP | ROUTE_FLAG_GATEWAY))
			continue;
		add_address (set, gw, 4);
	}
	g_free (copy);
	fs_range_set_normalize (set);
	return set;
}

FsRangeSet *
fs_hostnet_parse_ipv6_route (const gchar *text)
{
	FsRangeSet *set = fs_range_set_new ();
	gchar *copy, *cursor, *line;

	if (text == NULL)
		return set;

	copy = cursor = g_strdup (text);
	while ((line = next_line (&cursor)) != NULL) {
		gchar *f[5] = { NULL };
		guint8 dest[16], hop[16];
		guint32 plen = 0;

		/* destination, its prefix length, source, its length, next
		 * hop, metric, refcnt, use, flags, device.  Unlike the IPv4
		 * table, the addresses here are printed byte by byte (%pi6),
		 * so they are read in order, not as words. */
		if (split_fields (line, f, 5) < 5 ||
		    strlen (f[0]) != 32 || !parse_hex_bytes (f[0], 32, dest) ||
		    !parse_hex32 (f[1], &plen) ||
		    strlen (f[4]) != 32 || !parse_hex_bytes (f[4], 32, hop))
			continue;

		/* ::/0 with a next hop.  The kernel's own "unreachable"
		 * default and a default straight onto a link have none. */
		if (plen != 0 || !all_zero (dest, 16) || all_zero (hop, 16))
			continue;
		add_address (set, hop, 16);
	}
	g_free (copy);
	fs_range_set_normalize (set);
	return set;
}

/* TRUE when every server in `servers' is on this computer (127.0.0.0/8
 * or ::1), and for no server at all: a local stub, such as
 * systemd-resolved at 127.0.0.53 or NetworkManager's dnsmasq at
 * 127.0.1.1, forwards to the real servers, which are listed elsewhere;
 * with no server, the resolver library asks this computer too. */
static gboolean
only_loopback (const FsRangeSet *servers)
{
	for (guint i = 0; i < servers->v4->len; i++) {
		const FsRange4 *r = &g_array_index (servers->v4, FsRange4, i);

		if ((r->start >> 24) != 127 || (r->end >> 24) != 127)
			return FALSE;
	}
	for (guint i = 0; i < servers->v6->len; i++) {
		const FsRange6 *r = &g_array_index (servers->v6, FsRange6, i);

		if (r->start.hi != 0 || r->start.lo != 1 ||
		    r->end.hi != 0 || r->end.lo != 1)
			return FALSE;
	}
	return TRUE;
}

FsRangeSet *
fs_hostnet_parse_resolvers (const gchar *resolv_conf, const gchar *resolved,
                            const gchar *nm)
{
	FsRangeSet *servers = fs_range_set_from_resolv_conf (resolv_conf);

	/* A real server in /etc/resolv.conf is the one in use, and the
	 * upstream files are then not looked at: what a service that is
	 * not the resolver left in /run says nothing about where queries
	 * go.  Behind a stub, those files are the only place the real
	 * servers are named [N5, S7.1]. */
	if (only_loopback (servers)) {
		merge (servers, fs_range_set_from_resolv_conf (resolved));
		merge (servers, fs_range_set_from_resolv_conf (nm));
	}
	return servers;
}

/* The first word of `value' as one address, its zone suffix (%eth0)
 * dropped.  FALSE when there is no such word or it is not an address;
 * a name is never looked up. */
static gboolean
add_first_word (FsRangeSet *set, const gchar *value)
{
	gchar *copy, *f[1] = { NULL };
	gboolean added = FALSE;
	guint32 v4;
	FsU128 v6;

	if (value == NULL)
		return FALSE;

	copy = g_strdup (value);
	if (split_fields (copy, f, 1) == 1) {
		gchar *pct = strchr (f[0], '%');

		if (pct != NULL)
			*pct = '\0';
		switch (fs_addr_parse (f[0], &v4, &v6)) {
		case FS_AF_V4:
			fs_range_set_add4 (set, v4, v4);
			added = TRUE;
			break;
		case FS_AF_V6:
			fs_range_set_add6 (set, v6, v6);
			added = TRUE;
			break;
		default:
			break;
		}
	}
	g_free (copy);
	return added;
}

FsRangeSet *
fs_hostnet_parse_ssh_env (const gchar *ssh_connection,
                          const gchar *ssh_client)
{
	FsRangeSet *set = fs_range_set_new ();

	/* sshd sets both to the same client.  SSH_CLIENT is the older
	 * name, and the only one some environments pass on; it is also
	 * the fallback when SSH_CONNECTION does not start with an
	 * address. */
	if (!add_first_word (set, ssh_connection))
		add_first_word (set, ssh_client);
	fs_range_set_normalize (set);
	return set;
}

/* The row number column, "12:".  The header ("sl") is not one. */
static gboolean
is_slot (const gchar *field)
{
	gsize len = strlen (field);

	if (len < 2 || field[len - 1] != ':')
		return FALSE;
	for (gsize i = 0; i + 1 < len; i++)
		if (!g_ascii_isdigit (field[i]))
			return FALSE;
	return TRUE;
}

/* "0F02000A:0016": the address as `words' little-endian words, a
 * colon, and the port.  The port was converted to host order before
 * it was printed, so its digits read as a plain number: "0016" is 22,
 * never 0x1600. */
static gboolean
parse_endpoint (gchar *text, gsize words, guint8 *addr, guint32 *port)
{
	gchar *colon = strchr (text, ':');

	if (colon == NULL)
		return FALSE;
	*colon = '\0';
	return parse_le_field (text, words, addr) &&
	       parse_hex32 (colon + 1, port) && *port <= 0xffff;
}

FsRangeSet *
fs_hostnet_parse_tcp_peers (const gchar *text, gboolean v6, guint local_port)
{
	FsRangeSet *set = fs_range_set_new ();
	gsize words = v6 ? 4 : 1;
	gchar *copy, *cursor, *line;

	if (text == NULL)
		return set;

	copy = cursor = g_strdup (text);
	while ((line = next_line (&cursor)) != NULL) {
		gchar *f[4] = { NULL };
		guint8 local[16], remote[16];
		guint32 lport = 0, rport = 0, state = 0;

		/* sl local_address rem_address st tx_queue:rx_queue ... */
		if (split_fields (line, f, 4) < 4 || !is_slot (f[0]) ||
		    !parse_endpoint (f[1], words, local, &lport) ||
		    !parse_endpoint (f[2], words, remote, &rport) ||
		    !parse_hex32 (f[3], &state))
			continue;

		/* A connection to our port that is up.  A LISTEN row's peer
		 * is 0.0.0.0; a TIME_WAIT or closing row is a session that
		 * has already ended; our own client to someone else's port
		 * 22 has 22 as the REMOTE port. */
		if (state != TCP_STATE_ESTABLISHED || lport != local_port)
			continue;
		add_address (set, remote, words * 4);
	}
	g_free (copy);
	fs_range_set_normalize (set);
	return set;
}

/* ============================================================ the set */

FsHostNet *
fs_hostnet_new (void)
{
	FsHostNet *host = g_new0 (FsHostNet, 1);

	host->own = fs_range_set_new ();
	host->onlink = fs_range_set_new ();
	host->gateways = fs_range_set_new ();
	host->resolvers = fs_range_set_new ();
	host->sessions = fs_range_set_new ();
	host->update_hosts = fs_range_set_new ();
	return host;
}

void
fs_hostnet_free (FsHostNet *host)
{
	if (host == NULL)
		return;
	fs_range_set_free (host->own);
	fs_range_set_free (host->onlink);
	fs_range_set_free (host->gateways);
	fs_range_set_free (host->resolvers);
	fs_range_set_free (host->sessions);
	fs_range_set_free (host->update_hosts);
	g_free (host);
}

FsRangeSet *
fs_hostnet_all (const FsHostNet *host)
{
	FsRangeSet *all = fs_range_set_new ();

	if (host != NULL) {
		fs_range_set_union (all, host->own);
		fs_range_set_union (all, host->onlink);
		fs_range_set_union (all, host->gateways);
		fs_range_set_union (all, host->resolvers);
		fs_range_set_union (all, host->sessions);
		fs_range_set_union (all, host->update_hosts);
	}
	fs_range_set_normalize (all);
	return all;
}

/* ======================================================= the system */

#ifdef __linux__

/* What is read of each file at most.  A resolver file is a few hundred
 * bytes, and a megabyte is far beyond any real one.  The /proc tables
 * grow with the routes and sockets of the machine (150 bytes a socket)
 * and are parsed a block at a time, so their cap only stops a runaway
 * read: 256 MiB is well over a million sockets. */
#define RESOLVER_CAP  (1024 * 1024)
#define PROC_CAP      (256 * 1024 * 1024)
#define READ_BLOCK    (64 * 1024)

typedef void (*LinesFunc) (const gchar *lines, gpointer data);

/* `path' opened for reading when it is a regular file, else -1.  A
 * FIFO or a device at one of these paths could otherwise block the
 * read (O_NONBLOCK makes open() itself return at once) or feed it
 * forever.  Symlinks are followed: /etc/resolv.conf usually is one. */
static gint
open_regular (const gchar *path)
{
	struct stat st;
	gint fd = open (path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);

	if (fd < 0)
		return -1;
	if (fstat (fd, &st) != 0 || !S_ISREG (st.st_mode)) {
		close (fd);
		return -1;
	}
	return fd;
}

/* Hands `fn' the text of `path' a block of whole lines at a time, so
 * a table of any size is parsed in little memory, and reads at most
 * `cap' bytes.  A last line without its newline is handed over at the
 * end of the file, but not after the cap or a read error, where it may
 * be a piece of a line.  FALSE when the file cannot be opened (what
 * was handed over before an error stays: those were whole lines). */
static gboolean
read_lines (const gchar *path, gsize cap, LinesFunc fn, gpointer data)
{
	GString *pending;
	gchar *block;
	gsize total = 0;
	gboolean to_the_end = FALSE;
	gint fd = open_regular (path);

	if (fd < 0)
		return FALSE;

	pending = g_string_sized_new (READ_BLOCK);
	block = g_malloc (READ_BLOCK);
	while (total < cap) {
		gssize n = read (fd, block, MIN ((gsize) READ_BLOCK, cap - total));
		gsize end;

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			to_the_end = n == 0;
			break;
		}
		total += (gsize) n;
		g_string_append_len (pending, block, n);

		/* Everything up to the last newline is whole lines. */
		for (end = pending->len; end > 0; end--)
			if (pending->str[end - 1] == '\n')
				break;
		if (end > 0) {
			gchar keep = pending->str[end];

			pending->str[end] = '\0';
			fn (pending->str, data);
			pending->str[end] = keep;
			g_string_erase (pending, 0, (gssize) end);
		}
	}
	if (to_the_end && pending->len > 0)
		fn (pending->str, data);

	close (fd);
	g_free (block);
	g_string_free (pending, TRUE);
	return TRUE;
}

static void
collect_lines (const gchar *lines, gpointer text)
{
	g_string_append (text, lines);
}

/* A small text file, up to `cap'; NULL when it cannot be read. */
static gchar *
read_text (const gchar *path, gsize cap)
{
	GString *text = g_string_new (NULL);

	if (!read_lines (path, cap, collect_lines, text)) {
		g_string_free (text, TRUE);
		return NULL;
	}
	return g_string_free (text, FALSE);
}

static void
route_lines (const gchar *lines, gpointer into)
{
	merge (into, fs_hostnet_parse_route (lines));
}

static void
route6_lines (const gchar *lines, gpointer into)
{
	merge (into, fs_hostnet_parse_ipv6_route (lines));
}

typedef struct
{
	FsRangeSet *into;
	gboolean    v6;
} TcpTable;

static void
tcp_lines (const gchar *lines, gpointer data)
{
	TcpTable *table = data;

	merge (table->into,
	       fs_hostnet_parse_tcp_peers (lines, table->v6, SSH_PORT));
}

/* The network-order bytes of an AF_INET or AF_INET6 socket address (4
 * or 16 of them); 0 for any other family, or no address. */
static gsize
sockaddr_bytes (const struct sockaddr *sa, guint8 *out)
{
	if (sa == NULL)
		return 0;
	if (sa->sa_family == AF_INET) {
		memcpy (out, &((const struct sockaddr_in *) sa)->sin_addr, 4);
		return 4;
	}
	if (sa->sa_family == AF_INET6) {
		memcpy (out, &((const struct sockaddr_in6 *) sa)->sin6_addr, 16);
		return 16;
	}
	return 0;
}

/* 127.0.0.0/8 or ::1 */
static gboolean
is_loopback (const guint8 *b, gsize len)
{
	static const guint8 v6_loopback[16] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
	};

	if (len == 4)
		return b[0] == 127;
	return memcmp (b, v6_loopback, sizeof v6_loopback) == 0;
}

/* The block under a netmask: (a & m) to (a | ~m).  The kernel's
 * netmasks are contiguous; were one not, the interval would only grow
 * to cover it, which errs towards keeping more reachable. */
static void
add_prefix (FsRangeSet *set, const guint8 *addr, const guint8 *mask,
            gsize len)
{
	guint8 first[16], last[16];

	for (gsize i = 0; i < len; i++) {
		first[i] = addr[i] & mask[i];
		last[i] = addr[i] | (guint8) ~mask[i];
	}
	if (len == 4)
		fs_range_set_add4 (set, be32 (first), be32 (last));
	else
		fs_range_set_add6 (set, u128_from_bytes (first),
		                   u128_from_bytes (last));
}

/* Whether `a' and `b' lie in the same block under `mask'. */
static gboolean
same_prefix (const guint8 *a, const guint8 *b, const guint8 *mask,
             gsize len)
{
	for (gsize i = 0; i < len; i++)
		if ((a[i] & mask[i]) != (b[i] & mask[i]))
			return FALSE;
	return TRUE;
}

/* own and onlink from every address of every interface that is up.
 * Loopback addresses are left out (they are protected anyway); any
 * other address counts wherever it is, a service address put on lo
 * included, since this computer answers to it. */
static void
read_interfaces (FsRangeSet *own, FsRangeSet *onlink)
{
	struct ifaddrs *list = NULL;

	if (getifaddrs (&list) != 0)
		return;

	for (const struct ifaddrs *ifa = list; ifa != NULL;
	     ifa = ifa->ifa_next) {
		guint8 addr[16], mask[16], peer[16];
		const guint8 *base = addr;
		gsize len;

		if ((ifa->ifa_flags & IFF_UP) == 0)
			continue;
		len = sockaddr_bytes (ifa->ifa_addr, addr);
		if (len == 0 || is_loopback (addr, len))
			continue;
		add_address (own, addr, len);

		if (sockaddr_bytes (ifa->ifa_netmask, mask) != len)
			memset (mask, 0xff, len);
		/* An address with a peer connects the peer's prefix, not the
		 * local address's ("ip addr add A peer P/n" routes P/n to
		 * the link).  That is not only for point-to-point links:
		 * ifupdown's "pointopoint" puts a /32 with a peer on an
		 * Ethernet card, as some hosting providers configure it.
		 * glibc puts the peer in ifa_dstaddr, which on any other
		 * link is the same field as ifa_broadaddr: there it holds
		 * the broadcast address, inside the local prefix, or the
		 * local address itself when there is neither.  So whatever
		 * it holds outside the local prefix is the peer (a broadcast
		 * address set outside it, a misconfiguration, would only
		 * keep more reachable, never less). */
		if (sockaddr_bytes (ifa->ifa_dstaddr, peer) == len &&
		    !same_prefix (addr, peer, mask, len))
			base = peer;
		add_prefix (onlink, base, mask, len);
	}
	freeifaddrs (list);
}

/* Every address of every host, both families. */
static void
resolve_hosts (const gchar *const *hosts, FsRangeSet *into)
{
	for (guint i = 0; hosts != NULL && hosts[i] != NULL; i++) {
		struct addrinfo hints, *found = NULL;
		gchar *name = g_strdup (hosts[i]);
		gsize len = strlen (name);

		/* A URL writes an IPv6 literal in brackets. */
		if (len > 2 && name[0] == '[' && name[len - 1] == ']') {
			memmove (name, name + 1, len - 2);
			name[len - 2] = '\0';
		}

		memset (&hints, 0, sizeof hints);
		/* No AI_ADDRCONFIG: a feed host's IPv6 addresses are kept
		 * out of the lists even while this computer has no IPv6
		 * address of its own, since the lists are not rebuilt the
		 * moment it gets one. */
		hints.ai_family = AF_UNSPEC;
		/* One answer per address, not one per socket type. */
		hints.ai_socktype = SOCK_STREAM;

		if (*name != '\0' &&
		    getaddrinfo (name, NULL, &hints, &found) == 0) {
			for (const struct addrinfo *ai = found; ai != NULL;
			     ai = ai->ai_next) {
				guint8 b[16];
				gsize n = sockaddr_bytes (ai->ai_addr, b);

				if (n != 0)
					add_address (into, b, n);
			}
			freeaddrinfo (found);
		}
		g_free (name);
	}
}

#endif /* __linux__ */

#if defined(_WIN32)
typedef ULONG (WINAPI *GaaFunc) (ULONG, ULONG, PVOID,
                                 PIP_ADAPTER_ADDRESSES, PULONG);

/* One socket address into a set (IPv4 or IPv6, nothing else). */
static void
add_sockaddr_win32 (FsRangeSet *set, const SOCKET_ADDRESS *sa)
{
	if (sa->lpSockaddr == NULL)
		return;
	if (sa->lpSockaddr->sa_family == AF_INET) {
		const struct sockaddr_in *in =
			(const struct sockaddr_in *) sa->lpSockaddr;

		add_address (set, (const guint8 *) &in->sin_addr, 4);
	} else if (sa->lpSockaddr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 =
			(const struct sockaddr_in6 *) sa->lpSockaddr;

		add_address (set, (const guint8 *) &in6->sin6_addr, 16);
	}
}

/* [ read_adapters_win32 ] -- the gateways and DNS servers of every
 * adapter that is up.  A failure at any step adds nothing. */
static void
read_adapters_win32 (FsRangeSet *gateways, FsRangeSet *resolvers)
{
	HMODULE dll = LoadLibraryW (L"iphlpapi.dll");
	GaaFunc gaa;
	IP_ADAPTER_ADDRESSES *list = NULL, *a;
	ULONG size = 16384, status = ERROR_BUFFER_OVERFLOW;
	const ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS |
	                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;

	if (dll == NULL)
		return;
	gaa = (GaaFunc) (void (*) (void)) GetProcAddress (
		dll, "GetAdaptersAddresses");
	for (gint tries = 0; gaa != NULL && tries < 3 &&
	     status == ERROR_BUFFER_OVERFLOW; tries++) {
		g_free (list);
		list = g_malloc0 (size);
		status = gaa (AF_UNSPEC, flags, NULL, list, &size);
	}
	if (gaa != NULL && status == NO_ERROR) {
		for (a = list; a != NULL; a = a->Next) {
			IP_ADAPTER_GATEWAY_ADDRESS_LH *g;
			IP_ADAPTER_DNS_SERVER_ADDRESS *d;

			if (a->OperStatus != IfOperStatusUp)
				continue;
			for (g = a->FirstGatewayAddress; g != NULL; g = g->Next)
				add_sockaddr_win32 (gateways, &g->Address);
			for (d = a->FirstDnsServerAddress; d != NULL; d = d->Next)
				add_sockaddr_win32 (resolvers, &d->Address);
		}
	}
	g_free (list);
	FreeLibrary (dll);
}
#endif /* _WIN32 */

FsHostNet *
fs_hostnet_read (const gchar *const *hosts)
{
	FsHostNet *host = fs_hostnet_new ();
#ifdef __linux__
	gchar *resolv_conf, *resolved, *nm;
	TcpTable table;

	read_interfaces (host->own, host->onlink);

	read_lines ("/proc/net/route", PROC_CAP, route_lines, host->gateways);
	read_lines ("/proc/net/ipv6_route", PROC_CAP, route6_lines,
	            host->gateways);

	resolv_conf = read_text ("/etc/resolv.conf", RESOLVER_CAP);
	resolved = read_text ("/run/systemd/resolve/resolv.conf",
	                      RESOLVER_CAP);
	nm = read_text ("/run/NetworkManager/no-stub-resolv.conf",
	                RESOLVER_CAP);
	merge (host->resolvers,
	       fs_hostnet_parse_resolvers (resolv_conf, resolved, nm));
	g_free (resolv_conf);
	g_free (resolved);
	g_free (nm);

	/* The session running this command, then every SSH session that
	 * is up: under sudo or pkexec the variables are usually gone, but
	 * the connection is still in the tables. */
	merge (host->sessions,
	       fs_hostnet_parse_ssh_env (g_getenv ("SSH_CONNECTION"),
	                                 g_getenv ("SSH_CLIENT")));
	table.into = host->sessions;
	table.v6 = FALSE;
	read_lines ("/proc/net/tcp", PROC_CAP, tcp_lines, &table);
	table.v6 = TRUE;
	read_lines ("/proc/net/tcp6", PROC_CAP, tcp_lines, &table);

	resolve_hosts (hosts, host->update_hosts);

	fs_range_set_normalize (host->own);
	fs_range_set_normalize (host->onlink);
	fs_range_set_normalize (host->gateways);
	fs_range_set_normalize (host->resolvers);
	fs_range_set_normalize (host->sessions);
	fs_range_set_normalize (host->update_hosts);
#elif defined(_WIN32)
	/* Windows: the gateways and DNS servers of every adapter that is
	 * up (GetAdaptersAddresses), which the Copilot never blocks
	 * automatically.  Its own addresses, prefixes and sessions come
	 * with its blocklists in Round 3 (design section 2). */
	(void) hosts;
	read_adapters_win32 (host->gateways, host->resolvers);
	fs_range_set_normalize (host->gateways);
	fs_range_set_normalize (host->resolvers);
#else
	(void) hosts;
#endif
	return host;
}
