/*---[ fs-hostnet.h ]----------------------------------------------------
 * What a blocklist must never cut on this computer (1.0.7 threat
 * intel; design section 6.4): its own addresses, the networks it is
 * directly connected to, its default gateways, the DNS servers it uses,
 * the sessions it must keep (the SSH client running the command, and
 * every established inbound SSH connection), and the hosts the enabled
 * feeds are downloaded from.
 *
 * fs_hostnet_read() gathers it all from the running system (Linux:
 * getifaddrs, /proc/net, resolver files; Windows: GetAdaptersAddresses,
 * GetExtendedTcpTable; elsewhere: empty).  The
 * parsers it uses are pure and public, so the tests feed them fixtures.
 *--------------------------------------------------------------------*/
#ifndef FS_HOSTNET_H
#define FS_HOSTNET_H

#include <glib.h>
#include "core/fs-iprange.h"

G_BEGIN_DECLS

typedef struct
{
	FsRangeSet *own;          /* this computer's addresses, one each    */
	FsRangeSet *onlink;       /* connected prefixes (address & mask),
	                           * both families; loopback left out       */
	FsRangeSet *gateways;     /* default gateways, both families        */
	FsRangeSet *resolvers;    /* DNS servers in use                     */
	FsRangeSet *sessions;     /* peers to keep reachable                */
	FsRangeSet *update_hosts; /* addresses of the feeds' hosts          */
} FsHostNet;

/* An FsHostNet with six empty, normalized sets (tests fill it). */
FsHostNet  *fs_hostnet_new  (void);
void        fs_hostnet_free (FsHostNet *host);

/* The running system (all sets normalized):
 *   own, onlink  getifaddrs(); addresses of every interface that is up,
 *                except loopback ones; prefixes from their netmasks,
 *                link-local IPv6 included;
 *   gateways     /proc/net/route and /proc/net/ipv6_route;
 *   resolvers    fs_hostnet_parse_resolvers() over /etc/resolv.conf,
 *                /run/systemd/resolve/resolv.conf and
 *                /run/NetworkManager/no-stub-resolv.conf;
 *   sessions     fs_hostnet_parse_ssh_env() over $SSH_CONNECTION and
 *                $SSH_CLIENT, plus fs_hostnet_parse_tcp_peers_on() over
 *                /proc/net/tcp and /proc/net/tcp6 for local port 22 and
 *                every port fs_hostnet_ssh_listen_ports() finds;
 *   update_hosts every host in `hosts' (NULL-terminated, may be NULL)
 *                looked up with getaddrinfo (AF_UNSPEC); a host that
 *                does not resolve adds nothing.
 * Windows (Round 3): own, onlink, gateways and resolvers from
 * GetAdaptersAddresses() over every adapter that is up (on-link
 * prefixes through fs_hostnet_add_onlink()); sessions from the SSH
 * variables and GetExtendedTcpTable() for local ports 22 and 3389
 * (Remote Desktop); update_hosts as above.
 * Never NULL.  A source that cannot be read adds nothing. */
FsHostNet  *fs_hostnet_read (const gchar *const *hosts);

/* Everything above as one normalized set.  Caller frees. */
FsRangeSet *fs_hostnet_all (const FsHostNet *host);

/* ---- pure parsers -------------------------------------------------- */

/* Adds the block `addr' (4 or 16 network-order bytes) lies in under a
 * prefix length -- Windows' OnLinkPrefixLength -- to `set': (addr & m)
 * to (addr | ~m).  A prefix of 0 or wider than the family adds the
 * address alone: a zero length would keep every address reachable and
 * empty every list without a word.  Other lengths of `addr' add
 * nothing. */
void fs_hostnet_add_onlink (FsRangeSet *set, const guint8 *addr, gsize len,
                            guint prefix);

/* Default IPv4 gateways from /proc/net/route text: rows whose
 * Destination is 00000000, whose Flags have RTF_GATEWAY (0x2) and
 * RTF_UP (0x1), with the Gateway column read as a little-endian hex
 * address.  The header row is skipped. */
FsRangeSet *fs_hostnet_parse_route (const gchar *text);

/* Default IPv6 gateways from /proc/net/ipv6_route text: rows whose
 * destination is 32 zero digits with prefix length 00 and whose next
 * hop is not all zeros. */
FsRangeSet *fs_hostnet_parse_ipv6_route (const gchar *text);

/* The DNS servers in use.  `resolv_conf' is /etc/resolv.conf; when every
 * nameserver in it is loopback (systemd-resolved's 127.0.0.53,
 * NetworkManager's dnsmasq at 127.0.1.1, ::1) or it has none, the
 * upstream files are read too: `resolved' (systemd-resolved's
 * /run/systemd/resolve/resolv.conf) and `nm' (NetworkManager's
 * /run/NetworkManager/no-stub-resolv.conf).  Any argument may be NULL.
 * Loopback servers are kept in the result (they are protected anyway). */
FsRangeSet *fs_hostnet_parse_resolvers (const gchar *resolv_conf,
                                        const gchar *resolved,
                                        const gchar *nm);

/* The client address of an SSH session: the first word of
 * $SSH_CONNECTION ("client port server port"), else of $SSH_CLIENT
 * ("client port lport").  Either may be NULL.  Zone suffixes (%eth0)
 * are dropped. */
FsRangeSet *fs_hostnet_parse_ssh_env (const gchar *ssh_connection,
                                      const gchar *ssh_client);

/* Remote addresses of ESTABLISHED (st 01) rows whose local port is
 * `local_port', from /proc/net/tcp (v6 FALSE) or /proc/net/tcp6 (v6
 * TRUE) text.  Addresses are in the kernel's hex form: IPv4 as one
 * little-endian 32-bit word, IPv6 as four such words; an IPv4-mapped
 * IPv6 address comes out as IPv4. */
FsRangeSet *fs_hostnet_parse_tcp_peers (const gchar *text, gboolean v6,
                                        guint local_port);

/* The same for any of several local ports (a GArray of guint16): the
 * peers of every established connection to sshd, wherever it listens.
 * NULL or empty ports: an empty set. */
FsRangeSet *fs_hostnet_parse_tcp_peers_on (const gchar *text, gboolean v6,
                                           const GArray *ports);

/* ---- sockets and their owners (Linux; elsewhere empty) ------------- */

/* socket inode -> program name, for every process whose fd table this
 * account may list: the executable's basename, or the kernel's comm
 * name when the exe link cannot be read (another user's process).
 * `sockets' (a GList of FsNetSocket*, fs-netparse.h) names the inodes
 * wanted; NULL asks for every socket.  Keys are gint64*, values
 * strings (g_int64_hash); g_hash_table_unref.  The Linux backend's
 * connection list and `stockfw listening' read owners through this. */
GHashTable *fs_hostnet_socket_owners (const GList *sockets);

/* The TCP ports sshd listens on, from /proc/net/tcp and tcp6 and the
 * owner of each LISTEN socket (a process whose executable or comm name
 * is "sshd").  A GArray of guint16, sorted, no repeats; empty when no
 * sshd listener can be seen (not root and sshd is another user's, or
 * no sshd).  fs_hostnet_read() keeps the sessions on these ports as
 * well as on 22, so moving sshd to 2222 does not lose the session
 * running an apply (master plan, PR 1 adjustment 4). */
GArray     *fs_hostnet_ssh_listen_ports (void);

G_END_DECLS

#endif /* FS_HOSTNET_H */
