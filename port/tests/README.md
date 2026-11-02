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

## Threat-intel feeds (`fs-feed-test`)

```sh
cd port
ninja -C build-linux fs-feed-test
./build-linux/fs-feed-test
```

Pins down `src/core/fs-feed.c`: the built-in catalog, the three feed
formats, the parse guards of design 4.3, the URL rule, and the judge
that decides whether a new copy of a list may replace the one in use
(design 4.5).  Nothing in it touches the network or the disk: every
feed body is a string in the test, IPv6 is checked as parsed values,
and no kernel is involved.  It also runs clean under AddressSanitizer,
LeakSanitizer and UndefinedBehaviorSanitizer:

```sh
cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined"
ninja -C build-asan fs-feed-test && ./build-asan/fs-feed-test
```

What it proves:

- **Catalog.** The design's nine feeds in order, each with its format,
  default direction and "recommended" flag; ids valid and unique; every
  URL passes the URL rule and names its host; an info page and a terms
  page for each; a licence only where the publisher states one (Feodo
  CC0, DShield CC BY-NC-SA 2.5); DShield and FireHOL level 1 flagged
  non-commercial; `includes` names only ids that exist.
- **Formats.** Samples copied from FireHOL, Feodo Tracker, Spamhaus
  DROP (IPv4 and IPv6) and DShield, headers verbatim, parse to the
  right entries, comments and content dates ("This File Date", "Last
  updated", the metadata `timestamp`, DShield's `updated`).  A date in
  another zone, before 2000 or in milliseconds is no date.  The NDJSON
  reader takes all of JSON (escapes, surrogate pairs, nesting 15 deep)
  and refuses, line by line, text after the object, duplicate keys, a
  `\u0000` escape, lone surrogates, raw control characters, leading
  zeros, nesting 16 deep, comments and trailing commas.
- **Size guards.** 32 MiB exactly is read, one byte more is refused
  unread; a NUL byte anywhere refuses the body, in every format and as
  CSV; a BOM and CRLF are accepted; a line of 4,096 bytes is read and
  one of 4,097 is invalid, not truncated; 200,000 entries are accepted
  and 200,001 refused.
- **Span floor.** Eleven spellings of a too-broad entry (a /0, a /7,
  IPv4-mapped CIDRs and ranges, plain ranges, IPv6 /16 and wider) are
  dropped from a good list and counted.  The floor is a size: a /10 is
  allowed and one address more is not, as a CIDR, a range or a mapped
  CIDR, and likewise an IPv6 /29.  It is measured after the protected
  ranges come out, so FireHOL's 224.0.0.0/3 loses nothing and is not
  too broad.
- **Poisoned lists.** Refused as not a list when as many entries were
  too broad as were kept: 221 /8s, 221 /8s with 221 good entries, 1,000
  /9s and 82 IPv6 /16s are refused; 221 /8s with 222 good entries are
  kept without the /8s.
- **Coverage caps.** Eight /10s (2^25 addresses) are accepted and nine
  refused; 128 IPv6 /29s (2^42 /64s) are accepted and 129 refused.
- **Not a list.** An HTML error page is refused in every format and as
  CSV, with one sentence that says why; a few bad lines in a real list
  are counted and the first one named.
- **CSV import.** Reads like `fs_blocklist_parse_csv` (same set and
  counts on a clean file), with the same guards; a header only on the
  first data line; never a content date.
- **Judge.** Every verdict with its one-sentence reason, and NULL when
  the verdict is OK; each override and the one it does not cover; the
  thresholds at their edges (403 and 404 of 1,614 entries, 8 -> 1 and
  8 -> 2, 7 -> 1, 2^16 addresses, exactly doubled, exactly 2^22 more);
  the walk 1,614 -> 404 -> 101 caught against the largest of the last
  seven copies, which is forgotten after seven more; the order EMPTY,
  ROLLBACK, SHRANK, GREW.  The history keeps the newest seven and the
  newest date, and clamps a damaged count.
- **URL rule and redaction.** Seven good URLs and thirty bad ones
  (other schemes, user@host, spaces and control bytes, non-ASCII, a
  leading '-', empty hosts, bad ports, backslashes, broken IPv6
  literals); 2,048 bytes accepted and 2,049 refused.  The query string
  and a user:password part never reach a displayed URL.

Teeth, each re-injected into a copy of `fs-feed.c` by a script that
checks the exact old text, rebuilt, and seen failing (the restored file
passed again):

- the span floor by prefix length instead of size (a range's prefix
  length 0 read as "none"): `too broad: ::ffff:0.0.0.0/96 is dropped`,
  every range spelling, `floor: 44.0.0.0-44.64.0.0 is too broad` (30
  checks failed);
- the floor measured before the protected ranges come out: `FireHOL's
  224.0.0.0/3 counts nothing` and the FireHOL sample's counts (4);
- no poisoned-list rule: `poisoned: 221 /8s are refused`, `1,000 /9s`,
  `82 IPv6 /16s`, the CSV case and each `... alone is a poisoned list`
  (16);
- `>=` for `>` at the /10 boundary: `floor: 44.0.0.0/10 is allowed` in
  all three spellings, `a /10 exactly is allowed`, `eight /10s ... are
  accepted` (7);
- no NUL check: `a NUL byte refuses the body`, `a NUL at the very end
  (the C terminator counted) refuses it`, `a NUL byte refuses every
  format and CSV` (3);
- the shrink threshold by integer division (`now < max / 4`, so 403 of
  1,614 passes): `SHRANK: 403 is under a quarter of 1,614` and its
  sentence (2);
- no rollback check: `ROLLBACK: content one second older than ours`,
  its sentence, `ROLLBACK comes before SHRANK` (4);
- the IPv4 or IPv6 coverage cap off by one: `eight /10s (2^25
  addresses, at the cap) are accepted`, `128 IPv6 /29s (2^42 /64s, at
  the cap) are accepted`;
- the entry cap off by one: `200,001 entries are refused (TOO_MANY)`
  and its CSV twin;
- the size cap off by one: `a body of exactly 32 MiB is read`;
- the line cap off by one: `a line of exactly 4096 bytes is read`;
- no not-a-list rule: the HTML page checks, `nothing parsed while a
  line was invalid is not a list`, `an error document is not an empty
  list`;
- no GREW check: the five GREW checks;
- no EMPTY check: `EMPTY guards a list too small for SHRANK: 1 -> 0`
  and the other EMPTY checks;
- the IPv6 floor off by one: `floor: 2001:db8::/29 is allowed` in both
  spellings and `128 IPv6 /29s ... are accepted`;
- the shrink rule from 9 entries instead of 8: `SHRANK applies from 8
  entries: 8 -> 1`;
- judging against the newest copy only: `the walk 1,614 -> 404 -> 101
  is caught at 101` and `the 1,614 copy still counts six copies later`;
- no query-string redaction: the five redaction checks with a query;
- a JSON `\u0000` escape accepted: `a cidr with \u0000 inside is an
  invalid line`.

### Review of the feed judge (`test_judge_after_override` and others)

An adversarial review of `fs-feed.c` found two defects in `fs_feed_judge`,
both fixed and pinned down by `test_judge_after_override`:

- **An accepted shrink was asked again on each of the next six
  updates.**  SHRANK compared with the largest of the last seven copies,
  and the history keeps the larger copies after `--accept-shrink`, so
  the next copy of the accepted size (1,614 -> 100, then 100 again) was
  refused as SHRANK until the old copies aged out; the same after an
  accepted empty copy or an accepted coverage shrink.  The judge now
  reads the history oldest first and restarts the shrink baseline at a
  copy that was itself below a quarter of the baseline before it (only
  an accepted shrink lets such a copy in).  A walk down a quarter at a
  time still never resets it, and GREW still compares with every recent
  copy, so a list coming back to its size of before an accepted shrink
  is not "sudden growth".
- **An unchanged list of protected space only was EMPTY on every
  update.**  EMPTY fired whenever the new copy blocked nothing and the
  copy in use had entries, even when that copy blocked nothing either.
  It now needs the copy in use to have covered IPv4 addresses or to have
  had more entries than the new copy.

The review also added hostile checks: two JSON objects on one line, a
null `cidr`, a Spamhaus copy with only its metadata (an empty, dated
list), and the floor on what is left of an entry (a /9 half CGNAT keeps
its /10; `::ffff:0.0.0.0/95` stays IPv6).

Teeth of the fixes (injected into a copy of `fs-feed.c` by a script that
checks the exact old text; each restored with `cp`, checked with `cmp`
and run green again):

- EMPTY back to "the copy in use had entries": `an unchanged list of
  protected space only is not EMPTY on its next update`;
- EMPTY without the IPv4 coverage of the copy in use: `one blocked
  address replaced by one protected entry: EMPTY`;
- no baseline restart after an accepted shrink: `after an accepted
  shrink to 100, the next copy of 100 is not SHRANK again`, `after an
  accepted empty copy, the next empty copy is not SHRANK`, `after an
  accepted coverage shrink to 2^16, the next copy of 2^16 is accepted`.

Three of the implementer's teeth were re-proven the same way: the floor
measured before the protected ranges come out (4 checks failed,
FireHOL's 224.0.0.0/3 among them), no rollback check (4 failed), no
poisoned-list rule (16 failed).

## Downloads (`tests/test-fetch.sh`, `fs-fetch-test`)

```sh
cd port
ninja -C build-linux fs-fetch-test
./build-linux/fs-fetch-test golden    # the pure pieces, no root needed
sudo bash tests/test-fetch.sh         # everything
```

`src/core/fs-fetch.c` is how StockFW downloads (1.0.7 design, section
5): one https:// URL, through `curl` started with an argv and an
environment of its own, the body read from a pipe and counted here, not
by curl alone.  `fs-fetch-test` is built from the same file with
`FS_FETCH_TESTING`, the only build that honours `STOCKFW_TEST_CURL` (a
stand-in for curl) and `STOCKFW_TEST_CACERT` (the throwaway CA, passed
as `--cacert`); built without it, fs-fetch reads no environment at all.

The shell test needs root (curl has to be made `nobody`), curl,
openssl, python3, unshare, mount and ip, and SKIPs without them
(`setpriv`, when present, adds the not-root case and a control).  It re-runs
itself under `unshare -n`: an HTTPS server with a throwaway CA, a plain
HTTP server, a server that accepts and never answers and a proxy that
records connections all listen on the namespace's own 127.0.0.1, so no
case reaches the host or the internet.  Cases that change `/etc/passwd`
or hide `/usr/bin/curl` bind-mount over them in a nested `unshare -m`.
Stand-ins for curl (shell scripts in the test's temporary directory)
report what they were given, exit 60, hang past their own `--max-time`,
drop `--max-filesize` before running the real curl, flood stderr (200
KB, and 64 MiB), print an escape sequence, or only leave a flag saying
they ran.
`FS_FETCH_TEST=build-asan/fs-fetch-test` runs the whole test with
another build of the driver, an ASan one for instance; with UBSan in
it too, set `UBSAN_OPTIONS=halt_on_error=1` so that a report fails the
case instead of only being printed.

| Area | What it pins down |
|---|---|
| pure pieces | the argv golden with `-q` first; exactly `PATH` and `LC_ALL`; the URL and proxy rules; curl's exit table; bad requests refused before anything starts |
| trust | with the test CA a download works, on a main context of its own, and four at once from four threads; without it no curlrc saying `insecure` (under `HOME`, `CURL_HOME`, `XDG_CONFIG_HOME`, or in nobody's passwd home), no `CURL_CA_BUNDLE`, `SSL_CERT_FILE`/`SSL_CERT_DIR`, `SSLKEYLOGFILE` or `*_proxy` gets through: a TLS error, no proxy connection, no key log, while controls show plain curl obeying each of them |
| size | exactly the cap passes, one byte over is TOO_LARGE; an endless or stalled chunked body is cut at the cap within 3 s, also when curl ignores `--max-filesize` (as curl before 8.4 did for a chunked body), and no curl is left running; the edges hold at a cap of 1 byte and of exactly one 64 KiB read |
| time | a server that never answers is TIMEOUT within budget; a curl that hangs past its own `--max-time` is killed by fs_fetch's timer |
| where | a redirect to http:// and a chain of 5 redirects are URL errors, and the http server behind the redirect never sees a request; 3 redirects pass; `{..}` and `[..]` in a URL make one request, not a curl glob; a 404 is HTTP; a proxy the caller passes is used |
| who | as root, curl runs as nobody (every uid and gid, no groups, no capabilities, no_new_privs) with the golden argv, stdin `/dev/null`, cwd `/` and none of the caller's descriptors, while the caller stays root with its own groups; no `nobody`, a `nobody` with uid 0 or group 0, or one the child cannot become: PRIVILEGE, and nothing runs; a caller that is not root downloads as itself |
| words | a curl exiting 60 is TLS with curl's own text, without its `curl: (60)` prefix; a missing curl is NO_CURL (also the real lookup, with `/usr/bin/curl` hidden); a curl flooding stderr still gives one short line, and 64 MiB of it raises the caller's peak memory by less than 32 MiB (keeping it all costs over 64); every message is printable ASCII: an escape sequence, a tab or DEL in curl's text becomes `?` |
| leftovers | 2 to 4 fetches in a row of each outcome (a body, the cap, TLS, HTTP, the timer's kill, no curl, PRIVILEGE) leave the caller with no more descriptors than after the first, and no curl running |
| release | the release objects of `fs-fetch.c` (fs-core, fs-core-nogui) name neither `STOCKFW_TEST_CURL` nor `STOCKFW_TEST_CACERT`; the test object does (the control) |

Teeth, each re-injected into `fs-fetch.c` and seen failing, then
restored (checked with `cmp`) and green again.  After the dash, the
checks that caught it:

- `-q` dropped -- "nobody's own curlrc says insecure: TLS", both argv
  goldens, "-q is the first argument", the report's "-q is curl's first
  argument";
- the caller's environment inherited (no `set_environ`) -- "the hostile
  environment, no test CA: TLS", "no TLS key log was written", the
  report's "curl's environment is exactly ...";
- no privilege drop (no child setup) -- the report's uid, gid and
  no_new_privs checks, "root, a nobody the child cannot become:
  PRIVILEGE", "and the stand-in never ran";
- only curl's `--max-filesize` for the cap (fs_fetch's count disabled)
  -- "one byte over, chunked, curl without --max-filesize: TOO_LARGE",
  and the endless and stalled bodies "returned within 3 s";
- the whole-transfer timer no longer kills -- "a curl that hangs past
  its own --max-time: fs_fetch did not return within 25 s";
- http allowed (`--proto` and `--proto-redir` `=http,https`) -- "a
  redirect to http://: URL", "the http:// server behind the redirect saw
  no request", both argv goldens;
- `--globoff` dropped -- "a URL with {1,2} in it: the body has 47 bytes"
  (it had 94), "the server saw one request", "a query with [..] in it:
  ok", both argv goldens;
- the caller's descriptors inherited (`INHERIT_FDS`) -- the report's "no
  descriptor of the caller reached curl (the held marker file
  included)";
- the cap off by one (`>=`) -- "exactly the cap (Content-Length): ok"
  and "exactly the cap, chunked, ...: ok";
- at the cap, reading stops but curl is not killed -- the endless and
  stalled bodies "returned within 3 s";
- no `PR_SET_NO_NEW_PRIVS` in the child -- the report's "no_new_privs
  set";
- curl given the caller's stdin -- the report's "curl's stdin is
  /dev/null";
- failing open without a `nobody` (downloading as root) -- "root, no
  account nobody: PRIVILEGE", "and nothing was started";
- the caller's default main context iterated -- "a small file with the
  test CA: fs_fetch ran on its own main context";
- curl's `curl: (60) ` prefix kept in the message -- "curl exits 60: the
  message is "Could not download: SSL certificate problem: ..."".

Review.  Four of the teeth above were re-injected again and seen
failing as listed (`-q` dropped: 7 FAIL; only curl's `--max-filesize`
for the cap: the 6 listed, and 10 more of the checks below; failing
open without a `nobody`: 3 FAIL; the timer no longer kills: the hang
case and "the timer's kill, twice").  The review added the checks
marked in the table (capabilities, the caller staying root, group 0,
not root, control bytes, the 64 MiB flood, leftovers, the cap edges,
release objects, and in `golden` the user-agent bound of 256 bytes,
DEL in a user agent, a CR LF user agent refused by fs_fetch, and
max_bytes G_MAXUINT refused while G_MAXUINT - 1 reaches the spawn).
Their teeth; "(gap)" marks a bug the suite before the review let
through, run against the same re-injected source:

- control bytes kept in curl's text (no `?` for them) -- "curl prints
  an escape sequence, a tab and DEL: the message is printable ASCII
  only" and its exact message (gap);
- the subprocess never released (both pipes leak) -- "4 fetches in a
  row leave no descriptor open (8 after the first, 14 after the last)"
  for each outcome, 6 FAIL (gap);
- the account change made in this process before the spawn, failures
  handled, curl still nobody -- "the caller is still root with its own
  groups (uid 65534 ...)", twice; before the review only the four-thread
  case noticed, by a race (other threads' setgroups failing);
- the test hooks compiled into every build (`#ifdef FS_FETCH_TESTING`
  made `#if 1`) -- "the release fs-fetch.c.o (fs-core-nogui) names
  neither hook" and the same for fs-core (gap);
- all of curl's stderr kept -- "curl prints 64 MiB on stderr: peak
  memory grew by at most 32768 KiB (66972 KiB)" (gap);
- a `nobody` with group 0 accepted -- "root, nobody's group is 0:
  PRIVILEGE (got ok)", its message, "and nothing was started" (gap);
- the child setup installed whatever the caller's account -- "started
  by nobody, not root: ok (got FAILED)" and its body checks (gap);
- the user-agent bound off by one (`>`) -- "argv refuses a user agent
  of 257 bytes" (gap);
- no guard for a cap a GByteArray cannot count to -- "max_bytes
  G_MAXUINT is refused before spawning -> FAILED (got NO_CURL)" (gap).

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
