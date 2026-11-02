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


## Threat-intel rule set in nftables (`fs-intelset-test`, `tests/test-intelset.sh`)

```sh
cd port
ninja -C build-linux fs-intelset-test fs-intelset-driver
./build-linux/fs-intelset-test
sudo bash tests/test-intelset.sh    # needs root and nft; SKIPs otherwise
```

`fs-intelset-test` is the pure half of `src/core/fs-intelset.c`: no
root, no network, no nft.  It compares whole scripts byte for byte with
literal goldens (an IN set over IPv4, an OUT set over IPv6, a BOTH set
over both families, several sets in their order, the empty rule set),
and pins the id rule `^[a-z0-9][a-z0-9-]{0,39}$`, the set names, what
`fs_intel_ruleset_add()` refuses, and the digest.  The golden digests
were computed from the canonical text by another SHA-256 tool, so they
pin the canonical form itself, not just the code agreeing with itself.
The parsers are fed captured `nft list chain` and `nft -j list tables`
output plus hand-made cases: a counter with no comment, a comment that
is not an id, broken and overflowing numbers; a table `stockfw_intel2`,
family `ip`, members in any order, escapes, deep nesting, trailing
garbage.

`tests/test-intelset.sh` puts the same scripts into a real kernel.  It
re-executes itself under `unshare -n` and makes its own namespaces (a
peer on a veth pair; for forwarding, a client and a server routed
through the test's namespace), so the host's firewall is never touched.
Through `fs-intelset-driver` (`script|check|apply SPEC`, `clear`,
`live`, `counters`) it proves:

- `nft -c` accepts every fixture: one family only, a set with no
  addresses, the empty rule set, a 40-character id, 2500 IPv4 and 300
  IPv6 elements in statements of 1000;
- an apply is live with its digest; a second apply replaces the first
  (its sets and rules are gone); a transaction the kernel rejects
  part-way -- a wrapper `nft` on `PATH` appends a bad command -- leaves
  the previous table and its digest in force;
- the six direction cells, each a real TCP connection over the veth
  pair, (a) started by the listed peer, (b) started here: in (a)
  dropped, (b) works because the replies pass; out (a) works, (b)
  rejected at once (EHOSTUNREACH, not a timeout); both (a) dropped, (b)
  rejected;
- this computer still reaches its own listed addresses over loopback,
  for every direction;
- the counters of an id move with blocked attempts, sum every rule of
  the id, and match what `nft list chain` prints;
- clear removes our table and only it, clearing twice is fine, and the
  table then reads back as absent;
- forwarding, with three namespaces: an in set drops a routed
  connection the listed client starts, an out set rejects one to a
  listed server, and the other direction works in both cases;
- the nft runner in `fs-nftset.c`: an nft that hangs is killed at the
  timeout and the apply, or the listing, says it timed out; an nft that
  quits without reading a large script is an error, not a SIGPIPE that
  kills the caller.

IPv6 is checked as rule text and with `nft -c` only: the test sends no
IPv6 packet, and says so in its output, with the reason it found.

Teeth, each re-injected into the source, seen failing, then restored
from a copy and seen green again:

| Bug re-injected | Check that failed |
|---|---|
| IN rules without `ct direction original` | `in (b): this side still connects to it: the replies pass`; `forward, in set: a routed connection to the listed client still works` |
| no `iif "lo" accept` in input | `loopback, in set` and `loopback, both set` time out |
| no `oif "lo" accept` in output | `loopback, out set` fails with EHOSTUNREACH |
| a family with no addresses still gets a set and an empty element statement | `nft -c accepts the script of ...` (nft syntax error); `a set with no addresses has no nft set and no rules` |
| the old table deleted in a separate nft call before the apply | `the previous table and its digest are still in force` (absent); `with its set and elements` |
| the script re-declares the table without deleting it | `the first rule set's sets are gone: replaced, not merged`; `and so are its rules` |
| `parse_counters` reads the listing as one text, not each counter's own line | `beta: 2 packets, 120 bytes -- the comment-less counter on the line before is not added` (got 6) |
| `parse_counters` takes any comment as an id | `a comment that is not an id is ignored` (got 3 ids) |
| the label hashed into the digest | the golden scripts and digests; `a label change leaves the digest alone` |
| OUT rules drop instead of rejecting | `out (b): connecting to it fails at once` (timed out); `both (b)`; `forward, out set: ... rejected at once` |
| OUT rules without `ct direction original` | `out (a): the listed peer still connects here: our replies pass`; `forward, out set: the listed server still connects to the client` |
| IN sets left out of the forward chain | `forward, in set: a routed connection the listed client starts is dropped`; `the forward rule counted it` |
| `parse_live` compares names as prefixes | `only "stockfw_intel2" -> absent` |
| `parse_live` ignores the family | `only family "ip" -> absent` |
| the nft timer armed a thousand times late | `an nft that hangs is killed: the apply says it timed out` (it said "applied", after 30 s); `a listing that hangs times out too` |
| SIGPIPE not held while writing to nft | `an nft that quits without reading a large script is an error, not a SIGPIPE death` (exit 141) |
| a refused add keeps the ranges it was given | LeakSanitizer, in an AddressSanitizer build of `fs-intelset-test` (the checks themselves pass) |

The split-delete tooth needs a caller: the backend's `intel_apply` is
not written yet, so `fs-intelset-driver apply` stands in for it, and the
tooth makes the driver clear first, as a backend would if the delete
were split off.  The sanitizer build is its own CMake directory,
configured with `-fsanitize=address,undefined`.

### Review additions (`fs-intelset-test`, `tests/test-intelset.sh`)

An independent review added hostile checks for what the first round
left unproven, and one contract fix:

- **Unknown is not absent.**  `fs_intelset_nft_parse_live()` answered
  FALSE both for a listing without the table and for text that is not a
  listing at all, so a backend built on it could only report a garbled
  `nft -j list tables` as a missing table -- the state "not loaded", a
  claim about the kernel nobody checked [S10].
  `fs_intelset_nft_parse_live_state()` keeps the three answers apart
  (`FsIntelLive`: present, absent, unknown); `parse_live()` is unchanged
  and is now TRUE exactly when that answer is present.  Every live check
  runs both readers; truncated or trailing text, `{}`, an `nftables`
  member that is not a list and a warning line before the listing are
  unknown, and the driver's `live` prints `unknown` (exit 1).  Live: an
  `nft` on `PATH` that prints one line of its own before the real
  listing reads as `unknown`, not `absent`.
- **Element statements at their edges**: 1, 999, 1000, 1001 and 2000
  elements give statements of exactly 1000 and the rest, never an empty
  one (an empty `{  }` is a syntax error that fails the whole apply);
  live, `nft -c` accepts exactly 1000 and 1001 elements.  The 2500 check
  could not see a count that is one too high only at exact multiples.
- **Labels never reach nft**: a set whose label is
  `Evil" counter accept comment "x"` plus `flush ruleset` renders byte
  for byte the script of the same set without a label.
- **Hand-made sets with NULL ranges** render and hash as an empty set.
- **Parsers at their edges**: `nft -a` handles after the comment, the
  40-character id, leading zeros and CRLF still count; a comment of
  `sfw:` and 31 or 33 hex digits is no digest.
- **Sets that are all empty** (not the empty rule set): `nft -c`
  accepts them, and the table loads with its digest, three chains and no
  set.
- **UDP direction cells**, the same six as TCP with a query and its
  answer -- only conntrack tells the answer from a request [N0]: in (a)
  dropped, (b) answered; out (a) answered, (b) refused at once; both (a)
  dropped, (b) refused at once.  A datagram this computer sends to an
  OUT-listed address is refused by `send()` itself (EPERM, the output
  hook kept it in), where TCP sees EHOSTUNREACH from the reject.
- **A child that keeps nft's pipes open**: an `nft` that leaves a
  process holding its stdout and stderr still stops at the timeout, for
  an apply and for a listing; killing nft alone would leave the runner
  reading until that child exits.

Teeth of the review additions, each injected by a script that asserts
the exact old text, seen failing, restored with `cp`, checked with
`cmp`, and seen green again:

| Bug re-injected | Check that failed |
|---|---|
| `parse_live_state()` answers absent for text that is not a listing | the eight `-> unknown` live checks; `a listing that cannot be read is unknown, not absent` (absent) |
| the number of element statements computed as n / 1000 + 1 | `1000 elements go in statements of 1000` (got 1000+0); `2000 ...` (1000+1000+0); `nft -c accepts the script of k1000.spec` (syntax error); `1000 elements are one add-element statement` -- the 2500 check and every golden still passed |
| the label printed as the rule comment | `a hostile label never reaches the script`, and the goldens |
| the timer kills nft but keeps reading its pipes (no cancel) | `live: ...` and `apply: an nft whose child holds its pipes open still stops at the timeout` (8010 ms) -- the existing hung-nft checks still passed |
| the digest taken from any comment at least `sfw:` + 32 long | `sfw: and 33 hex digits` |
| a counter whose comment does not end the line is skipped | `handles after the comment, a 40-character id, leading zeros and CRLF still count` |

The review also re-injected three teeth of the first round and saw them
fail: IN rules without `ct direction original` (`in (b)`, now also `in,
UDP (b)`, and `forward, in set: a routed connection to the listed
client still works`); no `iif "lo" accept` (`loopback, in set`,
`loopback, both set`); the label hashed into the digest (the goldens,
`golden digest`, `a label change leaves the digest alone`).
