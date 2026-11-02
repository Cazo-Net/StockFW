# StockFW core tests

Checks the platform-independent logic in `src/core/`: rule CSV
round-tripping, host/port validation, the service table, and iptables
script generation.  Pure GLib, so it runs headless on either platform.

```sh
cd port
./tests/test-core.sh
```

The script compiles the suite against the core sources directly rather
than through CMake, so a failing test points at the logic rather than a
link problem. Set `MSYS2_PATH` if your toolchain is not on `/ucrt64/bin`.

Rules are written under a temporary `STOCKFW_RULES_DIR`, so running
the tests never touches a real `/etc/stockfw`.

## Coverage

| Suite | What it pins down |
|---|---|
| ports | single ports, ranges, hex, out-of-range, inverted ranges, empty |
| hosts | dotted quads, hostnames, wildcards, bad octets, short forms |
| rule CSV | every rule kind survives serialise/parse; over-long rows rejected |
| policy | save/load round trip, defaults, add and remove by content |
| services | port to name lookup, back-door ports, ICMP types, range expansion |
| scripts | inbound/outbound rules, NAT, permissive vs restrictive defaults |

## Event source (`tests/test-logstart.sh`)

```sh
cd port
./tests/test-logstart.sh
```

Builds the platform backend on its own -- `fs-backend-windows.c` or
`fs-backend-linux.c` -- and asks it to start monitoring traffic. Either
it starts and `log_active()` agrees, or it refuses **and says why**.

The case it exists for: `log_start()` used to return TRUE whether or not
the Security log could be read, so a non-elevated Windows session and an
unprivileged Linux session both showed an empty event list that read as a
working firewall with nothing to report. Monitoring now has to be either
honestly running or honestly explained.

## Command line and dashboard (`tests/test-cli.sh`)

```sh
cd port
bash tests/test-cli.sh
```

Linux only, no root needed.  Builds the `stockfw` target through CMake
and drives the real binary against scratch rules and config directories
and a fixture kernel log, so it never touches `/etc/stockfw` or the live
firewall (`apply` only runs with `--dry-run`).

It pins down the documented exit codes, policy editing (the service
shorthand, refused commas, mistyped options and bad hosts), the
simulator's verdicts, the kernel-log history, every `--json` document
parsed back, and the dashboard's security model: loopback only, the
per-run token (header only, never the query string or the page), the
Host check against DNS rebinding, GET/HEAD only, the 16 KB request-head
cap, the CSP nonce, and the dashboard leaving its own sockets out of the
connection list.


## Where the computer is connected (`fs-netplace-test`, `fs-overview-place-smoke`)

```sh
cd port
ninja -C build-linux fs-netplace-test fs-overview-place-smoke
./build-linux/fs-netplace-test
DISPLAY=:99 ./build-linux/fs-overview-place-smoke   # needs a display
```

Windows applies one of three firewall profiles to each network, by the
network's category.  The Overview names the network and its kind in the
subtitle, marks the profiles in force "In use", and turns the verdict
red when the profile in use is switched off: the firewall service still
reports running, but nothing on that network is filtered.

`fs-netplace-test` pins down the wording and that judgement in
`src/core/fs-netplace.c`.  `fs-overview-place-smoke` builds the real
Overview page against a fake backend that answers the way
`fs-backend-windows.c` does, so the Windows half of the page runs on any
platform.  The COM reads themselves (`INetFwPolicy2::CurrentProfileTypes`,
`INetworkListManager`) need a Windows machine.

Teeth, each seen failing when re-injected: `fs_network_place_unguarded`
ignoring which profile states were readable; networks not sorted
internet-first; the verdict ignoring the profile in use; the "In use"
marks never shown; switching a profile on from the card not re-judging
until the next poll.

## What a blocklist must never cut (`fs-hostnet-test`)

```sh
cd port
ninja -C build-linux fs-hostnet-test
./build-linux/fs-hostnet-test        # as root for the live part
```

`src/core/fs-hostnet.c` gathers what the threat-intel engine subtracts
from every list (design 6.4): this computer's addresses, its connected
prefixes, its default gateways, the DNS servers in use, the SSH sessions
to keep and the feed hosts.

- **Parsers, on fixtures modelled on the real files** (any platform, no
  root).  `/proc/net/route` with its header: only defaults with
  RTF_GATEWAY and RTF_UP, the gateway read little-endian; not the
  connected route, a route via a gateway that is not a default, a
  default without the gateway flag (with and without a gateway column),
  one that is down, the "unreachable" default, damaged rows; a block of
  rows without the header (the reader hands tables over in blocks).
  `/proc/net/ipv6_route`: ::/0 with a next hop, not without one, not
  ::/3, not other prefixes.  Resolvers: only 127.0.0.53 means
  systemd-resolved's upstreams (1.1.1.1 and 2606:4700:4700::1111 both
  kept), a real server in resolv.conf means the upstream files are not
  used, NetworkManager's dnsmasq and its no-stub file, commented-out
  servers, zone suffixes, ::1, no nameserver, no resolv.conf.  SSH
  variables: IPv4, IPv6, zone, IPv4-mapped, garbage, a name (never
  looked up), empty, only SSH_CLIENT, garbage falling back to
  SSH_CLIENT.  `/proc/net/tcp` and `tcp6`: ESTABLISHED rows on the local
  port only (not LISTEN, TIME_WAIT, port 0x1600, or our own client to a
  remote port 22), the port as plain hex, an IPv4-mapped peer as IPv4.
- **Hostile input to every parser**: fields one digit long or short, a
  sign or "0x", non-digits, missing fields, a last row without its
  newline, a port over 0xffff, slots that are not "<digits>:", a state
  that is not 01; SSH variables with blanks, a prefix, a bare zone, two
  addresses in one word, a 256 KiB word; resolver lines that only look
  like "nameserver" lines; a server next to 127/8 or ::1 that merges
  with the loopback one into one interval (still a real server, so the
  upstream files stay unread).  Damage adds nothing, never a different
  address.
- **fs_hostnet_new/free/all**: six empty normalized sets; all six merged.
- **This machine** (no root): normalized sets, no loopback in own or
  onlink, `$SSH_CONNECTION`'s client kept.
- **Live, as root**: the test re-executes itself under
  `unshare -n -m --propagation private`.  The child refuses to touch
  anything unless /proc shows network and mount namespaces other than
  its parent's (and init's, where readable) and a network namespace
  with every interface still down.  There it makes lo with a service
  address, a veth with three addresses and a fourth with a peer
  (ifupdown's "pointopoint" on Ethernet), a veth left down, a tun with a
  peer, a default route, sshd's port with one session up and one in
  TIME_WAIT, a tmpfs over /run with systemd-resolved's file (a symlink)
  and NetworkManager's, and fixtures bound over /etc/resolv.conf and
  /etc/hosts; then checks own, onlink, gateways, sessions, resolvers and
  update hosts exactly, loopback absent, the down interface absent, the
  tun's peer and the Ethernet peer on-link, an IPv6 feed address kept
  without IPv6 configured, 500 sessions on port 22 (a /proc/net/tcp of
  more than two 64 KiB blocks and dozens of reads) all found, a resolver
  file read only up to its 1 MiB cap, a line cut by that cap dropped
  rather than read as a shorter address ("nameserver 192.0.2.54" cut to
  192.0.2.5), and a FIFO at a resolver path skipped (an alarm turns a
  hang into a FAIL).  Everything
  vanishes with the namespaces.  IPv6 is checked live only on a kernel
  that has it; elsewhere the test says so and the fixtures cover it.

Without root, unshare or ip the live part prints SKIP.  Teeth, each
re-injected into `src/core/fs-hostnet.c` and seen failing, then
restored (cmp) and green again:

| bug | check that caught it |
|---|---|
| route gateway read big-endian | "/proc/net/route: the up defaults ..." (got 1.100.51.198 254.2.0.192); live "gateways" from the kernel's own table |
| upstream resolver files always read | "resolvers: a real server in resolv.conf -> the upstream files are not used", and live |
| upstream resolver files never read | "resolvers: only 127.0.0.53 -> resolved's upstreams", nine more |
| ESTABLISHED filter dropped | "tcp: ESTABLISHED rows on local port 22" (got LISTEN's 0.0.0.0 and the TIME_WAIT peer); live "sessions" |
| hex port read with its bytes swapped | "tcp: ESTABLISHED rows on local port 22" (got only the 0x1600 row); live "sessions" |
| loopback addresses in own | live "loopback is not in own (nor in onlink)"; "read here: loopback ..." |
| interfaces that are down counted | live "an interface that is down adds nothing" |
| point-to-point link given its local prefix | live "a point-to-point link: the peer is on-link" |
| AI_ADDRCONFIG in the host lookup | live "update hosts: an IPv6 address is kept although ..." |
| no cap on resolver files | live "a resolver file is read up to its cap, no further" |
| resolver files opened without O_NONBLOCK | live "a FIFO at a resolver path is skipped, not waited on" |
| IPv4-mapped peer left IPv6 | "tcp6: ... the IPv4-mapped peer comes out as IPv4" |
| RTF_UP ignored | "/proc/net/route: the up defaults ..." (the down route came in) |
| RTF_GATEWAY ignored | the same check (0.0.0.0 and the flagless gateway came in) |
| IPv6 default without the prefix-length test | "/proc/net/ipv6_route: ::/0 rows with a next hop" (::/3 came in) |
| SSH zone suffix kept | "SSH_CONNECTION, a zone suffix is dropped" |
| fs_hostnet_all forgets update_hosts | "fs_hostnet_all: every set, merged" |
| the remote port taken for the local one | "tcp: ESTABLISHED rows on local port 22"; live "sessions" |

Added by the review (each re-injected, seen failing, restored with cmp,
green again):

| bug | check that caught it |
|---|---|
| a peer address on a link that is not point-to-point given the local /32 (the bug the review fixed) | live "an address with a peer on an Ethernet link: the peer is on-link" and the exact onlink check |
| /proc tables capped at 64 KiB | live "sessions: all 500 peers of a /proc/net/tcp of many reads" (found 212) |
| the piece of a line cut by the cap handed over | live "a line cut by the cap is dropped, not read as 192.0.2.5" (got 192.0.2.5) |
| no partial line kept between blocks (every block handed over whole) | the same check |
| a field longer than the kernel's width read by its first digits | "hostile /proc/net/route ..." (got 60.67.22.0 and 198.51.100.1); "tcp6 text read as tcp" |
| a merged interval taken for loopback by its start alone | "hostile resolvers: 128.0.0.0 next to 127/8 is a real server" |

Re-verified from the table above: route gateway read big-endian,
ESTABLISHED filter dropped, loopback addresses in own.
