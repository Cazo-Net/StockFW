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
