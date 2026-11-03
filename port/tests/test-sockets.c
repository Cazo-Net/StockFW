/* The socket tables and their owners (cli-plan.md WP-D): the UDP parser,
 * the listening test, the port names the Events page shows, the
 * connection rows' new fields, and the SSH sessions an apply keeps on
 * every port sshd listens on (master plan PR 1, adjustment 4).
 *
 *   test-sockets                 the pure checks
 *   test-sockets --ssh-ports     prints fs_hostnet_ssh_listen_ports()
 *   test-sockets --session ADDR  "yes" when fs_hostnet_read() keeps ADDR
 *                                as a session, else "no"
 *
 * Built and run by tests/test-core.sh against src/core. */
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include "core/fs-hostnet.h"
#include "core/fs-netparse.h"

static guint checks, failures;

#define CHECK(cond, ...)                                              \
	do {                                                              \
		checks++;                                                     \
		if (!(cond)) {                                                \
			failures++;                                               \
			printf ("FAIL: ");                                        \
			printf (__VA_ARGS__);                                     \
			printf ("\n");                                            \
		}                                                             \
	} while (0)

static const gchar udp4[] =
	"   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
	"  411: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   108        0 21001 2 0000000000000000 0\n"
	"  700: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 21002 2 0000000000000000 0\n"
	"  812: 0500000A:A000 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 21003 2 0000000000000000 0\n"
	"  bad row\n";

static const gchar udp6[] =
	"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
	"   10: 00000000000000000000000000000000:14E9 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   108        0 22001 2 0000000000000000 0\n"
	"   11: 00000000000000000000000001000000:0222 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 22002 2 0000000000000000 0\n"
	"   12: 0000000000000000FFFF00000500000A:A001 0000000000000000FFFF000008080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 22003 2 0000000000000000 0\n"
	"   13: B80D0120000000000000000001000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 22004 2 0000000000000000 0\n";

static void
test_udp (void)
{
	GList *v4 = fs_netparse_proc_udp (udp4, FALSE);
	GList *v6 = fs_netparse_proc_udp (udp6, TRUE);
	FsNetSocket *s;

	CHECK (g_list_length (v4) == 3, "udp: 3 rows, header and bad row skipped (%u)",
	       g_list_length (v4));
	s = g_list_nth_data (v4, 0);
	CHECK (s != NULL && strcmp (s->local_addr, "0.0.0.0") == 0 &&
	       s->local_port == 5353 && s->udp && !s->ipv6 && s->inode == 21001,
	       "udp: 0.0.0.0:5353, udp set, inode read");
	CHECK (s != NULL && fs_netparse_socket_is_listening (s),
	       "udp: a socket with no peer is listening");
	s = g_list_nth_data (v4, 1);
	CHECK (s != NULL && strcmp (s->local_addr, "127.0.0.1") == 0 &&
	       s->local_port == 53, "udp: 127.0.0.1:53");
	s = g_list_nth_data (v4, 2);
	CHECK (s != NULL && strcmp (s->remote_addr, "8.8.8.8") == 0 &&
	       s->remote_port == 53 && !fs_netparse_socket_is_listening (s),
	       "udp: a connected socket has its peer and is not listening");

	CHECK (g_list_length (v6) == 4, "udp6: 4 rows (%u)", g_list_length (v6));
	s = g_list_nth_data (v6, 0);
	CHECK (s != NULL && strcmp (s->local_addr, "::") == 0 &&
	       s->local_port == 5353 && s->ipv6 && s->udp &&
	       fs_netparse_socket_is_listening (s), "udp6: :::5353 listening");
	s = g_list_nth_data (v6, 1);
	CHECK (s != NULL && strcmp (s->local_addr, "::1") == 0 &&
	       s->local_port == 546, "udp6: ::1 read from its hex words (%s)",
	       s != NULL ? s->local_addr : "-");
	s = g_list_nth_data (v6, 2);
	CHECK (s != NULL && strcmp (s->local_addr, "10.0.0.5") == 0 &&
	       strcmp (s->remote_addr, "8.8.8.8") == 0,
	       "udp6: a v4-mapped address reads as IPv4 (%s)",
	       s != NULL ? s->local_addr : "-");
	s = g_list_nth_data (v6, 3);
	CHECK (s != NULL && strcmp (s->local_addr, "2001:db8::1") == 0,
	       "udp6: 2001:db8::1 from its hex words (%s)",
	       s != NULL ? s->local_addr : "-");

	g_list_free_full (v4, (GDestroyNotify) fs_net_socket_free);
	g_list_free_full (v6, (GDestroyNotify) fs_net_socket_free);
}

static const gchar tcp4[] =
	"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 31001 1 0000000000000000 100 0 0 10 0\n"
	"   1: 0500000A:0016 0964330A:9C40 01 00000000:00000000 00:00000000 00000000     0        0 31002 1 0000000000000000 20 4 0 10 -1\n"
	"   2: 0500000A:D431 0A0B0C0D:01BB 08 00000000:00000000 00:00000000 00000000  1000        0 31003 1 0000000000000000 20 4 0 10 -1\n"
	"   3: 0500000A:D432 0964330A:0D3D 01 00000000:00000000 00:00000000 00000000     0        0 31004 1 0000000000000000 20 4 0 10 -1\n";

static void
test_connections (void)
{
	GList *tcp = fs_netparse_proc_tcp (tcp4, FALSE);
	GList *udp = fs_netparse_proc_udp (udp4, FALSE);
	GList *all = g_list_concat (tcp, udp);
	GList *conns = fs_netparse_connections (all, NULL);
	FsConnection *c;
	gchar *name;

	CHECK (fs_netparse_socket_is_listening (g_list_nth_data (all, 0)),
	       "tcp: LISTEN is listening");
	CHECK (g_list_length (conns) == 4,
	       "connections: 3 TCP and the one connected UDP socket (%u)",
	       g_list_length (conns));
	c = g_list_nth_data (conns, 0);
	CHECK (c != NULL && c->local_port == 22 && c->remote_port == 40000 &&
	       g_strcmp0 (c->state, "ESTABLISHED") == 0 &&
	       g_strcmp0 (c->direction, "Inbound") == 0,
	       "connections: ports and the state are filled in");
	c = g_list_nth_data (conns, 1);
	CHECK (c != NULL && g_strcmp0 (c->state, "CLOSE_WAIT") == 0 &&
	       c->remote_port == 443, "connections: CLOSE_WAIT named");
	c = g_list_nth_data (conns, 2);
	CHECK (c != NULL && g_strcmp0 (c->service, "Remote Desktop") == 0,
	       "connections: 3389 is Remote Desktop, not Unknown (%s)",
	       c != NULL ? c->service : "-");
	c = g_list_nth_data (conns, 3);
	CHECK (c != NULL && g_strcmp0 (c->protocol, "UDP") == 0 &&
	       c->state == NULL && g_strcmp0 (c->destination, "8.8.8.8") == 0 &&
	       g_strcmp0 (c->service, "DNS") == 0,
	       "connections: connected UDP, no TCP state");

	CHECK (strcmp (fs_netparse_tcp_state_name (0x0A), "LISTEN") == 0 &&
	       strcmp (fs_netparse_tcp_state_name (99), "UNKNOWN") == 0,
	       "tcp state names");

	name = fs_netparse_port_name (22);
	CHECK (g_strcmp0 (name, "SSH") == 0, "port name: the service table first");
	g_free (name);
	name = fs_netparse_port_name (161);
	CHECK (g_strcmp0 (name, "SNMP") == 0, "port name: 161 is SNMP");
	g_free (name);
	name = fs_netparse_port_name (40000);
	CHECK (name == NULL, "port name: an unknown port has none");
	g_free (name);

	g_list_free_full (conns, (GDestroyNotify) fs_connection_free);
	g_list_free_full (all, (GDestroyNotify) fs_net_socket_free);
}

static void
test_log_names (void)
{
	FsHit hit = { 0 };
	gboolean ok = fs_netparse_log_line (
		"2026-11-03T10:00:00+00:00 host kernel: [1.0] STOCKFW-REJECT "
		"IN=eth0 OUT= SRC=192.0.2.44 DST=10.0.0.5 LEN=60 PROTO=TCP "
		"SPT=40002 DPT=3389 SYN", &hit, NULL);

	fs_netparse_name_blocked (&hit);
	CHECK (ok && g_strcmp0 (hit.service, "Remote Desktop" FS_HIT_BLOCKED_MARKER) == 0,
	       "a live 3389 event is named Remote Desktop (%s)", hit.service);
	fs_netparse_clear_hit (&hit);
}

/* Established sessions on sshd's ports, not only on 22. */
static const gchar peers[] =
	"  sl  local_address rem_address   st\n"
	"   0: 0500000A:0016 0964330A:9C40 01 00000000:00000000 00:00000000 00000000 0 0 1\n"
	"   1: 0500000A:08AE 0A64330A:9C41 01 00000000:00000000 00:00000000 00000000 0 0 2\n"
	"   2: 0500000A:08AE 0B64330A:9C42 06 00000000:00000000 00:00000000 00000000 0 0 3\n";

static void
test_ssh_ports (void)
{
	GArray *ports = g_array_new (FALSE, FALSE, sizeof (guint16));
	guint16 p22 = 22, p2222 = 2222;
	FsRangeSet *set;

	set = fs_hostnet_parse_tcp_peers (peers, FALSE, 22);
	CHECK (fs_range_set_contains_text (set, "10.51.100.9") &&
	       !fs_range_set_contains_text (set, "10.51.100.10"),
	       "peers: port 22 alone keeps only the session on 22");
	fs_range_set_free (set);

	g_array_append_val (ports, p22);
	g_array_append_val (ports, p2222);
	set = fs_hostnet_parse_tcp_peers_on (peers, FALSE, ports);
	CHECK (fs_range_set_contains_text (set, "10.51.100.9") &&
	       fs_range_set_contains_text (set, "10.51.100.10") &&
	       !fs_range_set_contains_text (set, "10.51.100.11"),
	       "peers: sshd on 2222 too keeps that session, not a closed one");
	fs_range_set_free (set);

	set = fs_hostnet_parse_tcp_peers_on (peers, FALSE, NULL);
	CHECK (fs_range_set_is_empty (set), "peers: no ports, no peers");
	fs_range_set_free (set);
	g_array_unref (ports);
}

int
main (int argc, char **argv)
{
	if (argc == 2 && strcmp (argv[1], "--ssh-ports") == 0) {
		GArray *ports = fs_hostnet_ssh_listen_ports ();

		for (guint i = 0; i < ports->len; i++)
			printf ("%s%u", i > 0 ? "," : "",
			        g_array_index (ports, guint16, i));
		printf ("\n");
		g_array_unref (ports);
		return 0;
	}
	if (argc == 3 && strcmp (argv[1], "--session") == 0) {
		FsHostNet *host = fs_hostnet_read (NULL);

		printf ("%s\n", fs_range_set_contains_text (host->sessions, argv[2])
		        ? "yes" : "no");
		fs_hostnet_free (host);
		return 0;
	}

	test_udp ();
	test_connections ();
	test_log_names ();
	test_ssh_ports ();

	printf ("test-sockets: %u checks, %u failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
