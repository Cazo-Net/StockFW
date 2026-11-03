/*---[ fs-hostnet.c ]----------------------------------------------------
 * What a blocklist must never cut on this computer.  See fs-hostnet.h
 * and docs/design/1.0.7-threat-intel-design.md, section 6.4.
 *
 * Two halves.  The parsers are pure (text in, set out) and build on
 * every platform, so the tests pin them against fixtures modelled on
 * the real files.  fs_hostnet_read() is the only part that touches the
 * system.  On Linux: getifaddrs(), /proc/net, the resolver files, the
 * SSH variables and getaddrinfo().  On Windows (Round 3, design 11.4):
 * GetAdaptersAddresses() for the addresses, prefixes, gateways and DNS
 * servers of every adapter that is up, the SSH variables and
 * GetExtendedTcpTable() for the SSH and Remote Desktop sessions, and
 * getaddrinfo().
 *--------------------------------------------------------------------*/

/* getifaddrs(), getaddrinfo(), IFF_UP and O_CLOEXEC are POSIX and BSD
 * additions a strict -std=c11 hides; the build's gnu11 shows them, and
 * this keeps the file right either way, as in fs-backend-linux.c. */
#ifdef __linux__
#define _GNU_SOURCE
#endif

/* Windows: OnLinkPrefixLength and the gateway list of
 * IP_ADAPTER_ADDRESSES need Vista or later; the feature test must come
 * before any header.  winsock2 before windows.h, as everywhere. */
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#endif

#include "core/fs-hostnet.h"
#include "core/fs-netparse.h"

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
/* On Windows also Remote Desktop's: an administrator applying a list
 * over RDP must not lose the session (design 11.4). */
#define RDP_PORT 3389

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
	GArray *ports = g_array_new (FALSE, FALSE, sizeof (guint16));
	guint16 port = (guint16) local_port;
	FsRangeSet *set;

	if (local_port <= 0xffff)
		g_array_append_val (ports, port);
	set = fs_hostnet_parse_tcp_peers_on (text, v6, ports);
	g_array_unref (ports);
	return set;
}

/* [ has_port ] -- is `port' one of `ports' (guint16)? */
static gboolean
has_port (const GArray *ports, guint32 port)
{
	for (guint i = 0; ports != NULL && i < ports->len; i++)
		if (g_array_index (ports, guint16, i) == port)
			return TRUE;
	return FALSE;
}

FsRangeSet *
fs_hostnet_parse_tcp_peers_on (const gchar *text, gboolean v6,
                               const GArray *ports)
{
	FsRangeSet *set = fs_range_set_new ();
	gsize words = v6 ? 4 : 1;
	gchar *copy, *cursor, *line;

	if (text == NULL || ports == NULL || ports->len == 0)
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
		if (state != TCP_STATE_ESTABLISHED || !has_port (ports, lport))
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

void
fs_hostnet_add_onlink (FsRangeSet *set, const guint8 *addr, gsize len,
                       guint prefix)
{
	guint8 first[16], last[16];
	guint bits = (guint) len * 8;

	if (len != 4 && len != 16)
		return;
	/* No prefix, or one wider than the family: the address alone. A
	 * zero length would otherwise keep every address reachable and
	 * empty every list without a word. */
	if (prefix == 0 || prefix > bits)
		prefix = bits;
	for (gsize i = 0; i < len; i++) {
		guint at = (guint) i * 8;
		guint8 mask = prefix >= at + 8 ? 0xff
		            : prefix <= at     ? 0x00
		            : (guint8) (0xff << (8 - (prefix - at)));

		first[i] = addr[i] & mask;
		last[i] = addr[i] | (guint8) ~mask;
	}
	if (len == 4)
		fs_range_set_add4 (set, be32 (first), be32 (last));
	else
		fs_range_set_add6 (set, u128_from_bytes (first),
		                   u128_from_bytes (last));
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
	FsRangeSet   *into;
	gboolean      v6;
	const GArray *ports;
} TcpTable;

static void
tcp_lines (const gchar *lines, gpointer data)
{
	TcpTable *table = data;

	merge (table->into,
	       fs_hostnet_parse_tcp_peers_on (lines, table->v6, table->ports));
}

/* [ inode_pids ]
 * socket inode (gint64*) -> pid (string) for every process whose fd
 * table this account may list.  `wanted' (inodes as gint64*) limits
 * the walk, and ends it once each is placed; NULL takes every socket. */
static GHashTable *
inode_pids (GHashTable *wanted)
{
	GHashTable *pids = g_hash_table_new_full (g_int64_hash, g_int64_equal,
	                                          g_free, g_free);
	GDir *proc;
	const gchar *pid;

	if (wanted != NULL && g_hash_table_size (wanted) == 0)
		return pids;

	proc = g_dir_open ("/proc", 0, NULL);
	while (proc != NULL && (pid = g_dir_read_name (proc)) != NULL) {
		gchar *fd_path;
		GDir *fds;
		const gchar *fd;

		if (!g_ascii_isdigit (*pid))
			continue;

		fd_path = g_build_filename ("/proc", pid, "fd", NULL);
		fds = g_dir_open (fd_path, 0, NULL);
		while (fds != NULL && (fd = g_dir_read_name (fds)) != NULL) {
			gchar *link = g_build_filename (fd_path, fd, NULL);
			gchar *target = g_file_read_link (link, NULL);
			guint64 inode = 0;

			g_free (link);
			if (target != NULL && g_str_has_prefix (target, "socket:[")) {
				gchar *end = NULL;

				inode = g_ascii_strtoull (target + 8, &end, 10);
				if (end == NULL || *end != ']')
					inode = 0;
			}
			if (inode != 0 &&
			    (wanted == NULL || g_hash_table_contains (wanted, &inode)) &&
			    !g_hash_table_contains (pids, &inode)) {
				gint64 *key = g_new (gint64, 1);

				*key = (gint64) inode;
				g_hash_table_insert (pids, key, g_strdup (pid));
			}
			g_free (target);
		}
		if (fds != NULL)
			g_dir_close (fds);
		g_free (fd_path);

		/* Every socket placed: the rest of /proc cannot add one. */
		if (wanted != NULL &&
		    g_hash_table_size (pids) == g_hash_table_size (wanted))
			break;
	}
	if (proc != NULL)
		g_dir_close (proc);
	return pids;
}

/* [ pid_comm ] -- /proc/PID/comm, stripped; NULL when unreadable. */
static gchar *
pid_comm (const gchar *pid)
{
	gchar *path = g_build_filename ("/proc", pid, "comm", NULL);
	gchar *name = NULL;

	if (g_file_get_contents (path, &name, NULL, NULL))
		g_strstrip (name);
	g_free (path);
	return name;
}

/* [ pid_program ]
 * The executable's basename, as the Windows backend shows it; the
 * kernel's 15-character comm name when the exe link cannot be read
 * (another user's process, a kernel thread). */
static gchar *
pid_program (const gchar *pid)
{
	gchar *link = g_build_filename ("/proc", pid, "exe", NULL);
	gchar *target = g_file_read_link (link, NULL);
	gchar *name;

	g_free (link);
	if (target == NULL)
		return pid_comm (pid);

	/* A replaced binary reads "/usr/bin/foo (deleted)". */
	if (g_str_has_suffix (target, " (deleted)"))
		target[strlen (target) - strlen (" (deleted)")] = '\0';
	name = g_path_get_basename (target);
	g_free (target);
	return name;
}

/* [ is_sshd ] -- the program or the comm name is sshd's. */
static gboolean
is_sshd (const gchar *pid)
{
	gchar *program = pid_program (pid);
	gchar *comm = pid_comm (pid);
	gboolean yes = g_strcmp0 (program, "sshd") == 0 ||
	               g_strcmp0 (comm, "sshd") == 0;

	g_free (program);
	g_free (comm);
	return yes;
}

static void
socket_lines (const gchar *lines, gpointer data)
{
	GList **into = data;

	*into = g_list_concat (*into, fs_netparse_proc_tcp (lines, FALSE));
}

static void
socket6_lines (const gchar *lines, gpointer data)
{
	GList **into = data;

	*into = g_list_concat (*into, fs_netparse_proc_tcp (lines, TRUE));
}

static gint
port_order (gconstpointer a, gconstpointer b)
{
	return (gint) *(const guint16 *) a - (gint) *(const guint16 *) b;
}

#endif /* __linux__ */

GHashTable *
fs_hostnet_socket_owners (const GList *sockets)
{
	GHashTable *owners = g_hash_table_new_full (g_int64_hash, g_int64_equal,
	                                            g_free, g_free);
#ifdef __linux__
	GHashTable *wanted = NULL, *pids, *programs;
	GHashTableIter iter;
	gpointer key, value;

	if (sockets != NULL) {
		wanted = g_hash_table_new (g_int64_hash, g_int64_equal);
		for (const GList *l = sockets; l != NULL; l = l->next) {
			FsNetSocket *s = l->data;

			if (s->inode != 0)
				g_hash_table_add (wanted, &s->inode);
		}
		/* Nothing to look up: do not walk /proc for nothing. */
		if (g_hash_table_size (wanted) == 0) {
			g_hash_table_unref (wanted);
			return owners;
		}
	}

	pids = inode_pids (wanted);
	programs = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);
	g_hash_table_iter_init (&iter, pids);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		gchar *program = g_hash_table_lookup (programs, value);
		gint64 *copy = g_new (gint64, 1);

		if (program == NULL) {
			program = pid_program (value);
			if (program == NULL)
				program = g_strdup ("?");
			g_hash_table_insert (programs, value, program);
		}
		*copy = *(gint64 *) key;
		g_hash_table_insert (owners, copy, g_strdup (program));
	}
	g_hash_table_unref (programs);
	g_hash_table_unref (pids);
	if (wanted != NULL)
		g_hash_table_unref (wanted);
#else
	(void) sockets;
#endif
	return owners;
}

GArray *
fs_hostnet_ssh_listen_ports (void)
{
	GArray *ports = g_array_new (FALSE, FALSE, sizeof (guint16));
#ifdef __linux__
	GList *sockets = NULL, *listen = NULL;
	GHashTable *wanted, *pids;

	read_lines ("/proc/net/tcp", PROC_CAP, socket_lines, &sockets);
	read_lines ("/proc/net/tcp6", PROC_CAP, socket6_lines, &sockets);

	wanted = g_hash_table_new (g_int64_hash, g_int64_equal);
	for (GList *l = sockets; l != NULL; l = l->next) {
		FsNetSocket *s = l->data;

		if (fs_netparse_socket_is_listening (s) && s->inode != 0) {
			g_hash_table_add (wanted, &s->inode);
			listen = g_list_prepend (listen, s);
		}
	}

	pids = inode_pids (wanted);
	for (GList *l = listen; l != NULL; l = l->next) {
		FsNetSocket *s = l->data;
		const gchar *pid = g_hash_table_lookup (pids, &s->inode);
		guint16 port = (guint16) s->local_port;

		if (pid != NULL && !has_port (ports, port) && is_sshd (pid))
			g_array_append_val (ports, port);
	}
	g_array_sort (ports, port_order);

	g_hash_table_unref (pids);
	g_hash_table_unref (wanted);
	g_list_free (listen);
	g_list_free_full (sockets, (GDestroyNotify) fs_net_socket_free);
#endif
	return ports;
}

#if defined __linux__ || defined G_OS_WIN32

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

#endif /* __linux__ || G_OS_WIN32 */

#ifdef __linux__

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

#endif /* __linux__ */

#if defined __linux__ || defined G_OS_WIN32

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

#endif /* __linux__ || G_OS_WIN32 */

#ifdef G_OS_WIN32

/* [Unverified on Windows here: compiled and linked with mingw, run by
 * fs-intel-windows-test on the CI's Windows runner.] */

/* own, onlink, gateways and resolvers from every adapter that is up:
 * its unicast addresses (loopback left out, as on Linux) with their
 * on-link prefixes, its gateways and its DNS servers. */
static void
read_adapters (FsHostNet *host)
{
	const ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST |
	                    GAA_FLAG_SKIP_MULTICAST |
	                    GAA_FLAG_SKIP_FRIENDLY_NAME;
	ULONG size = 32 * 1024, rc = ERROR_BUFFER_OVERFLOW;
	IP_ADAPTER_ADDRESSES *list = NULL;

	/* The table can grow between the size query and the read. */
	for (guint tries = 0; tries < 4 && rc == ERROR_BUFFER_OVERFLOW;
	     tries++) {
		g_free (list);
		list = g_malloc (size);
		rc = GetAdaptersAddresses (AF_UNSPEC, flags, NULL, list, &size);
	}
	if (rc != NO_ERROR) {
		g_free (list);
		return;
	}
	for (const IP_ADAPTER_ADDRESSES *a = list; a != NULL; a = a->Next) {
		if (a->OperStatus != IfOperStatusUp)
			continue;
		for (const IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress;
		     u != NULL; u = u->Next) {
			guint8 addr[16];
			gsize len = sockaddr_bytes (u->Address.lpSockaddr, addr);

			if (len == 0 || is_loopback (addr, len))
				continue;
			add_address (host->own, addr, len);
			fs_hostnet_add_onlink (host->onlink, addr, len,
			                       u->OnLinkPrefixLength);
		}
		for (const IP_ADAPTER_GATEWAY_ADDRESS_LH *g =
		             a->FirstGatewayAddress;
		     g != NULL; g = g->Next) {
			guint8 addr[16];
			gsize len = sockaddr_bytes (g->Address.lpSockaddr, addr);

			if (len != 0 && !all_zero (addr, len))
				add_address (host->gateways, addr, len);
		}
		for (const IP_ADAPTER_DNS_SERVER_ADDRESS *d =
		             a->FirstDnsServerAddress;
		     d != NULL; d = d->Next) {
			guint8 addr[16];
			gsize len = sockaddr_bytes (d->Address.lpSockaddr, addr);

			if (len != 0)
				add_address (host->resolvers, addr, len);
		}
	}
	g_free (list);
}

static gboolean
kept_port (guint port)
{
	return port == SSH_PORT || port == RDP_PORT;
}

/* The peers of every established connection to this computer's SSH
 * or Remote Desktop port, both families.  The tables are re-read when
 * they grew between the size query and the read. */
static void
read_sessions (FsRangeSet *into)
{
	for (guint fam = 0; fam < 2; fam++) {
		ULONG af = fam == 0 ? AF_INET : AF_INET6;
		DWORD size = 0, rc = ERROR_INSUFFICIENT_BUFFER;
		gpointer table = NULL;

		for (guint tries = 0;
		     tries < 4 && rc == ERROR_INSUFFICIENT_BUFFER; tries++) {
			g_free (table);
			table = size > 0 ? g_malloc (size) : NULL;
			rc = GetExtendedTcpTable (table, &size, FALSE, af,
			                          TCP_TABLE_OWNER_PID_ALL, 0);
		}
		if (rc != NO_ERROR || table == NULL) {
			g_free (table);
			continue;
		}
		if (af == AF_INET) {
			const MIB_TCPTABLE_OWNER_PID *t = table;

			for (DWORD i = 0; i < t->dwNumEntries; i++) {
				const MIB_TCPROW_OWNER_PID *r = &t->table[i];

				if (r->dwState == MIB_TCP_STATE_ESTAB &&
				    kept_port (ntohs ((u_short) r->dwLocalPort)))
					add_address (into,
					             (const guint8 *) &r->dwRemoteAddr,
					             4);
			}
		} else {
			const MIB_TCP6TABLE_OWNER_PID *t = table;

			for (DWORD i = 0; i < t->dwNumEntries; i++) {
				const MIB_TCP6ROW_OWNER_PID *r = &t->table[i];

				if (r->dwState == MIB_TCP_STATE_ESTAB &&
				    kept_port (ntohs ((u_short) r->dwLocalPort)))
					add_address (into, r->ucRemoteAddr, 16);
			}
		}
		g_free (table);
	}
}

#endif /* G_OS_WIN32 */

FsHostNet *
fs_hostnet_read (const gchar *const *hosts)
{
	FsHostNet *host = fs_hostnet_new ();
#ifdef __linux__
	gchar *resolv_conf, *resolved, *nm;
	TcpTable table;
	GArray *ssh_ports;

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
	/* On 22, and wherever sshd listens (a server moved to 2222 is
	 * still the session an apply must not cut). */
	ssh_ports = fs_hostnet_ssh_listen_ports ();
	if (!has_port (ssh_ports, SSH_PORT)) {
		guint16 port = SSH_PORT;

		g_array_append_val (ssh_ports, port);
	}
	table.into = host->sessions;
	table.ports = ssh_ports;
	table.v6 = FALSE;
	read_lines ("/proc/net/tcp", PROC_CAP, tcp_lines, &table);
	table.v6 = TRUE;
	read_lines ("/proc/net/tcp6", PROC_CAP, tcp_lines, &table);
	g_array_unref (ssh_ports);

	resolve_hosts (hosts, host->update_hosts);

	fs_range_set_normalize (host->own);
	fs_range_set_normalize (host->onlink);
	fs_range_set_normalize (host->gateways);
	fs_range_set_normalize (host->resolvers);
	fs_range_set_normalize (host->sessions);
	fs_range_set_normalize (host->update_hosts);
#elif defined G_OS_WIN32
	WSADATA wsa;
	gboolean wsa_ok = WSAStartup (MAKEWORD (2, 2), &wsa) == 0;

	read_adapters (host);
	merge (host->sessions,
	       fs_hostnet_parse_ssh_env (g_getenv ("SSH_CONNECTION"),
	                                 g_getenv ("SSH_CLIENT")));
	read_sessions (host->sessions);
	if (wsa_ok) {
		resolve_hosts (hosts, host->update_hosts);
		WSACleanup ();
	}

	fs_range_set_normalize (host->own);
	fs_range_set_normalize (host->onlink);
	fs_range_set_normalize (host->gateways);
	fs_range_set_normalize (host->resolvers);
	fs_range_set_normalize (host->sessions);
	fs_range_set_normalize (host->update_hosts);
#else
	/* Other platforms: six empty sets; nothing applies a list there. */
	(void) hosts;
#endif
	return host;
}
