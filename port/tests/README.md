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
| settings table | one key, type and default per setting; every reader falls back to the table; a broken file kept as `.bad`; Preferences writes only what changed |
| settings gate | a settings change is applied whole, through the gate, and rolled back under the previous settings |
| settings pending | each apply records the settings it went out with; settings saved later ("Later") make the next policy apply whole, even for an unchanged policy, never a delta |
| sharing | router mode (forwarding, masquerade, the accepts for both devices, the local-broadcast block) only with both devices chosen |
| start on open | the app's one start goes through the start gate (`fs_firewall_start_lifting` in `start_at_launch`), only after the policy is loaded and Sentinel's expired blocks are out of it; no direct backend start (read from `fs-app.c`) |
| Windows rules | policy rows to netsh rules and argv, refusals, the upgrade apply (see below) |
| Copilot | detections with evidence, the policy health check and its verified fixes, the wording guard (see below) |

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


## Preferences (`fs-ui-smoke`, `fs-prefs-fake-smoke`)

```sh
cd port
ninja -C build-linux fs-ui-smoke fs-prefs-fake-smoke
xvfb-run -a ./build-linux/fs-ui-smoke
xvfb-run -a ./build-linux/fs-prefs-fake-smoke
STOCKFW_PREFS_SHOTS=/some/dir xvfb-run -a ./build-linux/fs-prefs-fake-smoke
```

Both build `tests/ui-prefs-smoke.c` and keep the settings file in a
scratch directory.  `fs-ui-smoke` opens the window against the real
backend and checks that saving with nothing changed writes nothing.
`fs-prefs-fake-smoke` supplies its own backend, which answers once as
the Linux backend and once as the Windows one, so both platforms' page
sets run on any machine: a page or row is shown only where the backend
says it acts, and a row that cannot act right now says why.  It also
answers the "Apply the new firewall settings now?" question both ways.
With `STOCKFW_PREFS_SHOTS` it saves a PNG of every page.

What it pins down, each seen failing when the old bug is put back:

- D1: the device choosers select the stored device by name, never by
  position (re-injected: `gtk_combo_box_set_active (combo, 1)` showed
  `eth0` for a stored `eth1`).
- D2: the local-network chooser lists every device once, plus a stored
  device that is not attached as "name (not present)", kept selected.
- D3: "Apply policy changes immediately" is off unless set, in the
  table, in the window and in every reader.  `test-core.sh` scans
  `src/` for any `fs_prefs_get_bool/_string` of a table key with its
  own literal fallback, so a reader cannot drift from the table again.
- D8: Save writes only values that changed, and only for rows the
  window offers; a setting the platform does not offer keeps its stored
  value.  A row disabled right now still saves a change made to it:
  connection sharing turned off with a device missing is saved, so is
  a block switched on before its device was cleared, and the footer
  counts exactly what Save writes.
- Every Protection and sharing row is live exactly when the rule
  generator emits its rule, for every device and sharing combination.
- "Apply now" reaches the apply gate with the policy that is live (the
  journal's): Policy-page edits that were never applied stay out, and
  the question says so.  With nothing on record the question names the
  policy that goes out with the settings.  On Windows it is asked with
  the firewall off too (Start does not re-apply rules there), and the
  report then says the firewall is still off; on Linux it is not asked
  (Start applies the whole policy).
- After "Later", the next apply of an unchanged policy is a whole one
  and brings the settings in.
- Screen readers get each row's line, and the reason first while a row
  cannot act.
- A switch with keyboard focus is ringed solid, at least 2px, at 3:1 or
  more against its slider, as the theme computes it.
- Start at sign-in (General, Background card; scenarios `signin-*`,
  with `STOCKFW_AUTOSTART_DIR` and `STOCKFW_SYSTEMD_DIR` in the
  scratch directory; Linux only, since on Windows they would register
  a real Task Scheduler task on the machine): the switch shows what the system has; moving it
  is one unsaved change and writes nothing; Cancel writes nothing; Save
  writes or removes the entry and nothing else, and applies nothing.
  When the entry cannot be written, Save saves nothing at all and the
  window stays open on General with the reason under the switch, the
  switch back to what is really set and the other change still
  pending.  A copy that may not change it (unelevated Windows) shows it
  greyed with the reason and never counts it as a change.  Changed
  from outside while the window is open, an unmoved switch follows and
  a moved one stays.  The note under it says whether the Linux boot
  unit is enabled, installed but not enabled (with the command), or
  missing.

Teeth for the sign-in row: let Save go on after the entry failed and
"the window stays open after Save" and "nothing was saved" fail; count
a switch the copy cannot act on and the "never a change to save" check
fails; leave it out of the footer's count and the three count checks
fail.  `test-core.sh` reads the boot unit from a scratch
`STOCKFW_SYSTEMD_DIR` (absent, installed, linked, a link to nothing, a
link left behind); trust a link without following it and "a link to
nothing is not enabled" fails.

The settings apply itself (`fs_settings_apply_safe`) is covered in
`test-core.sh`: an unchanged policy is applied whole under the new
settings, a failure is rolled back under the previous ones and
verified, and the audit log names it.
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

## The Windows build directory on its own (`tests/test-staged-runtime.sh`)

```sh
cd port
bash tests/test-staged-runtime.sh    # Windows (MSYS2); SKIP elsewhere
```

After every build, `tools/stage-runtime-dlls.sh` copies the GTK DLLs
next to `build/StockFW.exe`, so it starts from Explorer as well as from
the MSYS2 shell.  Windows then loads those copies first, even inside
the shell, and GTK and gdk-pixbuf take `build/` as their prefix: they
look for their module trees under `build/lib` and their data under
`build/share`, the layout the installer gives `$INSTDIR`.

The script used to copy the trees to `build/<name>` instead.  gdk-pixbuf
then found no loader cache, every SVG image failed, and GTK warned about
Adwaita's own radio-button bullet; the first Windows CI runs caught it
through `fs-activity-smoke`, which counts GTK warnings as failures.

The test checks that the loader cache and the SVG loader are under
`build/lib`, that nothing is left at the old place, that every DLL the
SVG loader imports from the toolchain is staged beside the exe (the
script follows the loaders' imports with `objdump -p`), and then runs
`fs-activity-smoke` from `build/` with nothing but Windows' own
directories on PATH, as if started from Explorer: it must pass, with no
GTK warning.  It is also part of `tests/full-suite.sh`.


## What the firewall is handed at launch (`fs-startup-smoke`)

```sh
cd port
ninja -C build-linux fs-startup-smoke
xvfb-run -a ./build-linux/fs-startup-smoke    # needs a display
```

Runs the real `fs_app_activate()` against a fake, Linux-shaped backend
(one where starting the firewall installs the whole policy) that
records what it is handed.  One process per scenario:

| Scenario | What must happen |
|---|---|
| start | "Start the firewall on program startup" starts once, with every rule from the policy files and without the Sentinel block whose ten minutes ran out while StockFW was closed; the start is audited and the journal records it |
| held | audit-only mode: `start()` is never called (it would install the file with its held changes); the last applied policy goes in instead |
| heldnone | audit-only mode and nothing ever applied: the firewall is not touched |
| startjournal | something was applied before: the start installs the last APPLIED policy (the journal) less the expired Sentinel block, and an allow saved since but never applied stays off |
| push | no start at launch, firewall running: only the expired Sentinel block's removal goes out (the journal less that block, through the apply gate, audited "sentinel auto-block expired"); the allow saved but never applied does not ride along |
| pushnone | the expired block was never live: nothing is pushed at all |
| stopped | no start at launch, firewall stopped: nothing is applied, so a stopped firewall is never started behind the user's back |

Up to 1.0.7 the start ran before the Policy page loaded the policy, so
on Linux it installed an empty one, and Sentinel's restore took expired
blocks out of the file without ever pushing that change.

Teeth: put the start back above the Policy page in `fs-app.c` and
"start" fails with 0 rules at start; drop the push in
`start_at_launch()` and "push" fails; push the whole policy file
instead of `fs_firewall_lift_live()` and "push" and "pushnone" fail.  `tests/test-core.sh` pins the
start gate itself (`fs_firewall_start_safe`) and the boot-time expiry
of Sentinel rows (`fs_autoblock_expire`).


## One StockFW per user (`tests/test-instance.sh`)

```sh
cd port
ninja -C build-linux StockFW
xvfb-run -a bash tests/test-instance.sh   # needs xdotool; stalonetray optional
```

Drives the real `StockFW` binary.  As root the whole test re-runs
itself in a private network namespace, every file the app writes goes
to a scratch directory, the firewall is never started, and the instance
name is private to the run (`STOCKFW_INSTANCE_NAME`), so a StockFW you
are using is not disturbed.

It checks that a second launch exits at once and the first copy brings
its window back; that there is still one window and one instance;
that another user's `--quit` is refused (root only, through `setpriv`)
and says why; that `--quit` returns only once the copy is gone, which
must exit 0 with its settings saved; and that `--quit` with nothing
running succeeds and says so.

`--background` is checked the same way: with stalonetray standing in
for the notification area the window stays hidden past the five-second
embed timeout (the docked 24-pixel tray icon carries the same window
name, so the test only counts windows wider than 100 pixels), a second
`--minimized` launch leaves it hidden, a normal launch brings it up;
with no notification area the window is shown and the reason goes to
stderr, so a hidden start never leaves a copy nobody can reach.

Last, SIGTERM, SIGINT and SIGHUP each make a running copy exit 0 with
its settings and Copilot baseline written.  Teeth: without the signal
handlers SIGTERM and SIGHUP kill it (exit 143 and 129, nothing
written) and SIGINT is ignored altogether, as it is for any background
job of a script.

Under `nohup` SIGHUP stays ignored and the copy keeps running.  As
root (with `setpriv` and `python3`): 48 connections that never speak,
half from uid 65534 and half from root, do not hold up a show or a
`--quit` right behind them; and with a uid-65534 copy running, a root
launch with `SUDO_UID=65534` makes it quit cleanly and takes its place,
after which the user launching again only raises root's window.

Teeth: read from a connection before checking who it is (as 1.0.7
did) and five "silent" checks fail; skip the takeover in `main()`
and five "takeover" checks fail; install the SIGHUP handler over
nohup's SIG_IGN and the nohup check fails.

Teeth: let `main()` ignore the "another copy runs" answer and the
second launch stays up (killed by the test's timeout, rc 124); let the
socket accept `quit` from anyone and the other user's `--quit` closes
the app; drop the fallback show and the no-tray check fails; ignore
`--background` and the hidden checks fail.


## Start at sign-in (`tests/test-autostart.sh`, `test_autostart` in `test-core.sh`)

```sh
cd port
ninja -C build-linux StockFW
bash tests/test-autostart.sh          # the sudo half needs root
```

`StockFW --enable-autostart` must write
`$XDG_CONFIG_HOME/autostart/stockfw.desktop` running this very binary
with `--background` (by name when PATH finds it, by a quoted absolute
path when not; `desktop-file-validate` must accept it), and
`--disable-autostart` must remove it.  As root on behalf of a user
(`SUDO_UID`), the entry is written with that user's file permissions:
it ends up owned by the user, and a directory only root may write is
refused rather than written by root.

`test-core.sh` pins what Windows is handed (portably, as text): the
Task Scheduler XML runs `<exe dir>\StockFW.exe --background` at THIS
user's logon, in their session (`InteractiveToken`), NOT elevated
(`LeastPrivilege`, never `HighestAvailable`: a prompt-free elevated GTK
program would be a silent UAC bypass), not startable on demand, with no
time limit and on battery.  It also pins
the Desktop Entry quoting and which keys switch an entry off
(`Hidden=true`, `X-GNOME-Autostart-enabled=false`).  Registering the
task through COM needs a Windows machine.

Teeth: skip the per-user file permissions and the root checks fail
(the entry is root's, the read-only directory is written); skip the
quoting and both the core check and the "path with a space" check fail.


## The boot service (`tests/test-boot-start.sh`, `tests/test-linux-install.sh`)

```sh
cd port
ninja -C build-linux stockfw StockFW
sudo bash tests/test-boot-start.sh
sudo bash tests/test-linux-install.sh
```

Linux keeps iptables rules in the kernel only; `stockfw.service` puts
them back at boot.  `test-boot-start.sh` checks the unit (oneshot,
`RemainAfterExit`, before `network-pre.target`, no `ExecStop`, a no-op
until a policy was applied, `systemd-analyze verify` clean) and then,
in a private network namespace, runs `stockfw start` as the unit does:
the user's block is in the kernel, a Sentinel block whose ten minutes
ran out is neither installed nor left in the files, a block by a host
name that cannot be looked up is named in the output without stopping
the start, and in audit-only mode the last applied policy goes in, not
the held change.  It also checks that a start puts back what was
APPLIED, never what was only saved: an SSH allow saved but never
applied stays out of the kernel; with the rule files gone the journal
still goes in, never an empty policy; with nothing ever applied, a
missing policy or one with a malformed line is refused; an expired
Sentinel row already gone from the file is left out of the journal.

`test-linux-install.sh` runs `install.sh` and the `stockfw-uninstall`
it writes for real, in a private mount namespace with a scratch PREFIX
and a tmpfs over `/etc/systemd/system`: the unit is installed pointing
at the installed `stockfw` and enabled, and the uninstaller disables
and removes it.

Teeth: drop the Sentinel expiry from `stockfw start` and three checks
fail; install the policy file instead of the journal and the
"unapplied", "no rule files" and audit-only checks fail; start without the hold and the audit-only checks fail; leave the
`systemctl disable` out of the uninstaller and "disabled" fails (a
dangling enable link counts as still enabled).


## The tray menu (`fs-traymenu-smoke`, `fs-tray-smoke`)

```sh
cd port
ninja -C build-linux fs-traymenu-smoke
xvfb-run -a ./build-linux/fs-traymenu-smoke     # needs a display
```

Runs the real `fs_app_activate()` against a fake backend that records
starts and stops, reports a Private network and hands the app's own
event callback back to the test, then works every row of the tray menu
the way a click does and answers the dialogs that come up:
"Firewall: On - Private network" and "Blocked today: N" are greyed
information rows; a blocked event fed through the monitor callback
shows up as "Blocked today: 1", as "TCP 445 to 203.0.113.5 (hh:mm)"
under Recent blocks (a click opens the window on Events) and in the
tooltip; Go to opens all six pages; Pause protection asks first with
Cancel as the default, stops only on "Pause protection", is audited,
and turns into Resume protection, which starts the firewall again;
without the rights to change the firewall it is greyed with a reason;
Pause Sentinel auto-block pauses and resumes (both audited) and is
greyed in detect mode (scenario "detect") and in a copy that cannot
change the firewall; a firewall stopped or started outside StockFW
shows as such the moment the menu opens, and on the slow timer
(`STOCKFW_TRAY_REFRESH_S=1`) with no menu open; Start at sign-in writes and
removes the entry, and a failure is reported with the tick left
showing the truth; Preferences and About open; Quit (firewall stays
on) leaves the firewall running.  Preferences... from a hidden window
brings the window up and opens over it, and asked for again while it
is open it gives no second window.  The tray's Start at sign-in and
the Preferences switch agree: ticked in the tray, the open switch
follows with nothing to save; moved in Preferences, nothing changes
until Save, and then the tick follows at once (read without opening
the menu again, which would re-read it anyway).  `test-core.sh` pins
the block tally itself (wording, five kept, midnight).

`STOCKFW_TRAYMENU_SHOT=menu.png ./build-linux/fs-traymenu-smoke main`
pops the menu up with Recent blocks open and saves a screenshot
instead of running the checks.

`fs-tray-smoke` keeps pinning the icon, the hide gate and the menu's
layout (information rows first, Quit last behind a separator) against
whatever notification area there is (the real Windows shell on CI).

Teeth: have the tray stop the firewall without the confirmation and
"it asks first" and "Cancel leaves the firewall running" fail; stop
counting blocks and the count, Recent blocks and tooltip checks fail;
refresh the tick from the request instead of from the system and the
failed Start at sign-in check fails (this one was a real bug the smoke
caught while it was written); stop asking the backend again when the
menu opens, or on the timer, and the "outside StockFW" checks fail.
Drop the one-window guard and "still one window" fails (a second
window opened inside the first); leave the open Preferences out when
the tray changes the setting and "the open Preferences switch follows"
fails; leave the tray out when Preferences saves it and "the tray's
tick follows at once" fails.


## Session safety (`fs-session-smoke`)

```sh
cd port
ninja -C build-linux fs-session-smoke
xvfb-run -a ./build-linux/fs-session-smoke      # needs a display
```

Runs the real `fs_app_activate()` against a fake backend, one scenario
per process:

- `autosave` (`STOCKFW_AUTOSAVE_S=1` in place of five minutes): with
  nothing changed nothing is written; a changed setting, and what the
  Copilot learned from an event fed through the app's monitor
  callback, are written while the app keeps running; a Sentinel
  staged-list write that fails is audited once, retries do not repeat
  the line, and once the file can be written the periodic save brings
  it up to date and audits that.
- `queryend`: emitting GtkApplication's `query-end` writes the settings
  and the baseline at once, inhibits nothing and quits nothing; a
  session manager's Stop (`g_application_quit` without
  `fs_app_quit()`) still writes what changed after it.
- `dialog`: `fs_app_quit()` dispatched inside a running
  `gtk_dialog_run()` writes everything and takes the icon down at once,
  frees nothing while the dialog's caller still runs, closes the dialog
  as its close button would, and finishes the quit once it has
  returned.
- `prefs`: the same with the Preferences window open and a setting
  moved in it.  That window is no GtkDialog but runs a loop of its
  own; the quit closes it as Cancel would (the moved setting is not
  saved) instead of waiting for it, and the Copilot's state is still
  intact.
- `background` (`STOCKFW_AUTOSAVE_S=1`; the DNS server and gateway
  fixed through `STOCKFW_RESOLV_CONF` and `STOCKFW_ROUTE_FILE`): the
  window is hidden as "Minimize to the tray" hides it (directly, since
  xvfb has no notification area for the icon to embed in), and then
  the Copilot must keep working.  A Sentinel block restored with three
  seconds left is lifted from the policy and the staged list on time,
  and audited; seven timed contacts fed into the app's Copilot and the
  eighth delivered through the Events page's own callback stage a
  Sentinel block (policy, staged list, apply gate); the periodic save
  writes what was learned; the tray's "Pause Sentinel auto-block for 1
  hour" is offered, pauses, the menu then offers Resume, and a second
  timed series stages nothing while paused; no window or dialog came
  up meanwhile (the tray icon's own window aside).

No scenario stops the firewall.  `test-core.sh` pins
`fs_prefs_dirty()`.

Teeth: a periodic save that does nothing fails the three "written
within the period" checks; a `query-end` handler that does nothing
fails both "at once" checks; a quit that frees everything at once
under the dialog fails "nothing is freed" and then crashes the
scenario (the use-after-free this prevents); no retry of the staged
list fails the three recovery checks; a dirty flag that is always set
fails "nothing changed: nothing written" and two core checks; no save
on the Stop path fails its check; freeing the state in the quit
instead of in shutdown fails "sametick" (a timer due in the same loop
pass as the quit found freed memory); leave the Preferences window out
of the quit and "the quit closes the Preferences window" and
"promptly" fail.

Teeth for `background`, each re-injected in the real file, seen
failing with `fs-session-smoke background`, restored with `cp` and
proved with `cmp`:

| Bug re-injected | Checks that caught it |
|---|---|
| the Copilot fed only while the Events page is on screen (`fs-hitview.c`) | "an event delivered while hidden reaches the Copilot (7 seen)", "the contact that completes a timed series is staged ...", "what the Copilot learned while hidden is written ..." |
| the expiry timer waits while the Copilot page is not on screen (`fs-copilot.c`) | "a Sentinel block whose ten minutes ran out while the window was hidden is lifted ...", "...and audited (0)" |
| the periodic save skipped while the window is hidden (`fs-app.c`) | "what the Copilot learned while hidden is written by the periodic save" |
| Sentinel's automatic pass run only while the Events page is on screen (`fs-hitview.c`) | "the contact that completes a timed series is staged as a Sentinel block while the window is hidden" |
## Windows rule translation (`tests/test-core.sh`)

```sh
cd port
bash tests/test-core.sh
```

Part of the core suite, so it runs on Linux with no Windows anywhere.
On Windows every policy row is compiled by `src/core/fs-fwrule.c` into
concrete rules, and each rule becomes one `netsh advfirewall firewall
add rule` call.  Up to 1.0.6 most services compiled to protocol "any"
with the port dropped (a rule matching every connection in its
direction), `-` ranges and port lists became "any port", outbound
service ports sat on the local side, and NTP was TCP.  The tests pin
the translation down as golden data:

- `test_fwrule_ports`: port text to netsh spec (`67:68` -> `67-68`,
  `137-139 445` -> `137-139,445`), and every malformed text refused
  (0, 65536, inverted, half ranges, `1-2-3`, hex, signs, `;`, tabs,
  separators alone, empty); `fs_fwrule_port_spec_covers`.
- `test_fwrule_services_golden`: one row per known service, inbound
  and outbound, to its exact rules: protocol, side (local inbound,
  remote outbound, local for a forward), port spec and name suffix.
  Also SSDP and a back door, hand-edited case, a moved service (SSH on
  2222, Samba on 445), a row with no port, custom names, the "TCP"
  and "UDP" pseudo-services, ranges and lists in both notations, and
  invalid port texts refused with a reason instead of widened.
- `test_fwrule_default_policy`: the default policy (DHCP, DNS) compiles
  to UDP and TCP+UDP rules on remote ports, and the soundness rule: a
  ported rule with protocol ANY, a spec not in netsh form, or port 0
  is not sound and gets no netsh argv.
- `test_fwrule_netsh_golden`: the exact argv for an inbound service,
  one from a network, an outbound block, outbound DHCP, both halves of
  a TCP+UDP service, a port list, a host rule, a port forward and the
  TCP pseudo-service on its port; no argument carries a quote; netsh names
  keep the `StockFW-` prefix the clear relies on.
- `test_apply_translation_upgrade`: a journal as 1.0.6 wrote it (no
  `# rules translation` line) makes the next apply a full one even
  though the rows have not changed, the journal then records the
  translation, and the apply after that is "no change" again; an
  unreadable translation line also means a full apply.  A refused row
  makes the delta non-empty and sends the apply the full way, whose
  verdict reports it.
- `test_whatif_winrules`: the What-If engine's Windows model reads the
  new rules: "Allow DHCP (outbound)" does not decide outbound TCP 22 or
  67 but decides UDP 68 (row 0 named); an outbound SMTP block matches
  remote port 25 and not 587; "Allow DNS (inbound)" does not allow
  inbound TCP 3389 but allows UDP 53 by its UDP rule.

What Linux cannot check: that netsh accepts these argvs and that the
backend's error reaches the dialog.  `fs-backend-windows.c` only runs
the argv `fs_fwrule_netsh_args` returns; the Windows CI build compiles
it.

Teeth, each re-injected into a copy of the source, seen failing, and
restored (`cmp`) to green:

| Bug re-injected | Checks that caught it |
|---|---|
| `fs_fwrule_is_sound` accepts protocol ANY with a port | "protocol ANY with a port is not sound", "and netsh is never given it" |
| a TCP+UDP service compiles to protocol ANY (the 1.0.6 shape) | 64 checks: every both-protocol golden, "is sound", both DNS netsh argvs, the default policy's DNS rules, the simulator's inbound UDP 53 |
| `-` ranges unparsed (only `a:b` known) | 20 checks: port texts `67-68`, `137-139 445`, DHCP/FTP/Samba/Xwindows goldens, the default policy, two netsh argvs, the simulator's DHCP UDP 68 |
| outbound service ports back on the local side | 23 checks: every outbound golden, the default policy, the SMTP and DHCP netsh argvs, "an outbound SMTP block matches remote port 25" |
| NTP back to TCP | the three NTP goldens (inbound, outbound, NTP on 5353) |
| invalid port text widened to every port | the seven "is refused, not widened" checks and the three refused-row gate checks |
| the gate trusts a 1.0.6 journal (no upgrade apply) | "an unchanged policy over a 1.0.6 journal is NOT \"no change\"", "the whole set is replaced", the audit line, "an unreadable translation line also means a full apply" |
| refused rows dropped from the delta | "a refused row makes the delta non-empty", "the same with no previous state", "goes the full way" |
| Samba on its default ports loses its UDP 137-138 / TCP 139,445 split | both Samba golden rules and the port-list netsh argv |

## Windows rule translation, second review (`test_fwrule_review`)

```sh
cd port
bash tests/test-core.sh
# The same suite under AddressSanitizer and UBSan:
STOCKFW_TEST_CFLAGS="-g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined" \
  bash tests/test-core.sh
```

An adversarial pass over the translation above, as part of the core
suite.  What it proves:

- Hostile port text is refused, never widened or wrapped: blanks and
  separators alone, `80-`, `-80`, `80--90`, `80::90`, `80:70`, `1:2:3`,
  `65536`, `0`, `00000`, `4294967376` (2^32 + 80), Arabic-Indic and
  fullwidth digits, a no-break space, a newline.  `1,,2`, `80 , 443`
  and `00080` normalise.  A list of all 65535 ports written twice
  compiles to each port once, and the simulator reads it.
- A bare "TCP" or "UDP" with no port is refused in every kind (inbound,
  outbound, block, forward), and so is the row the What-If "Create This
  Rule" writes for a probe that named no port: Linux writes no rule for
  a portless service row, and Windows used to open every TCP port.
- Samba's default ports in another order or spelling (`445 137-139`,
  `137:138,139 445`, `445,139,138,137`) keep the TCP 139,445 / UDP
  137-138 split; a real change (`137-139`) still applies to both.
- A double quote in a service name never reaches netsh's command line
  (it is spelled `'`): every argument is quote-free and the argv keeps
  its 12 elements.
- `fs_fwrule_block_refusals` reports a block row that cannot be
  compiled (a bad port, or nothing named to block) and nothing for a
  refused allow or a block that compiles.  The Windows whole-set apply
  stops on it before clearing anything, so a typo cannot remove a
  block that is in force (that call itself is compiled, not run, here).
- The narrow apply's delta keys removals and repairs on what netsh
  deletes (its spelling, case-insensitive): removing "a/b" re-creates
  "a-b", removing "ssh" re-creates "SSH", one delete per netsh name,
  and DNS moved to 5353 is exactly two deletes and two adds.
- The What-If engine's Windows model on a list with ranges
  (`7000-7010 7100,7200`): every port inside an element is allowed,
  every gap blocked.  The portless "Create This Rule" row is gone: the
  engine offers no row for a portless probe on either platform, and
  `fs_whatif_row_is_safe` refuses the row it used to write.

The sanitizer run is clean.  It used to report a stack overflow in
`test_activity_series` (an 8-slot buffer for a 26-point window),
leaked template rules, settings, a trust store and a name list in
older tests, and a real leak in `fs-copilot.c`: the per-application
port, destination and hour counters were never freed with their
profile, so every profile the LRU cap evicted leaked them.

Teeth, each re-injected into a copy of the source, seen failing, and
restored (`cmp`) to green:

| Bug re-injected | Checks that caught it |
|---|---|
| a bare "TCP"/"UDP" with no port opens every port of it again | the five "is refused, not widened" pseudo-service goldens and "that row opens nothing on Windows" |
| the default-port test compares text, not port sets | the six reordered Samba golden rules |
| a quote in a name goes to netsh as it is | "a quote in a service name never reaches netsh", "the netsh spelling of a quote is '" |
| `fs_fwrule_block_refusals` never reports | "a block with a bad port is a block refusal", "so is a block that names nothing to block" |
| port lists keep duplicates | `80,80` -> `80` and the all-ports-twice check |
| the delta compares display names, not netsh names | "removing \"a/b\" re-creates \"a-b\"", "deletes each netsh name once", "removing \"ssh\" re-creates \"SSH\"" |
| profile counters not freed with their profile | the sanitizer run: LeakSanitizer reports the counters from `app_profile_record_connection` |
| `test_activity_series` buffers back to 8 slots | the sanitizer run: stack-buffer-overflow in `fs_activity_window` |

## The What-If engine (`tests/test-whatif.c`, `tests/test-whatif-live.sh`)

```sh
cd port
bash tests/test-core.sh                 # builds and runs test-whatif.c last
ninja -C build-linux fs-whatif-test     # the same program through CMake
sudo bash tests/test-whatif-live.sh     # the engine against the kernel
```

`core/fs-whatif.c` answers "would this traffic be allowed?" with a
model of each firewall (Linux first match, Windows block-wins per
profile).  It answers every case a line leaves open (DEPENDS when they
differ) and offers only fixes it re-simulated.  The design is
`docs/ARCHITECTURE-AND-SECURITY.md` section 14.3.  `test-whatif.c`
(pure GLib) pins:

- the reading: 54 lines with what was recognised, and refusals
  instead of guesses (nothing recognisable, port 0 or above 65535, a
  bad address, a port range or list, a second host, a pattern, a zone,
  a negated request); host names read as the far end but not looked
  up; durations and counts that are not ports;
- a 112-row golden table over both models: CIDR blocks both ways,
  IPv6, ICMP types and the settings behind them, host names ("depends
  on DNS"), DEPENDS with the split in words, both directions for a line
  without one, the user's verb, Sentinel's blocks with their expiry, a
  stopped firewall, Windows profiles and their defaults, restrictive
  outbound, and whether the saved policy is in force.  Each row checks
  the verdict, its words, the actions that must and must not be
  offered, and that every answer's trace marks its deciding step;
- the trace (rule names, policy kind and row, the shadowed allow);
- the Linux model against the generator: `fs_whatif_linux_chain_text`
  equals the INBOUND/OUTBOUND chains `fs-script.c` writes, as `$IPT`
  text and as the `iptables-restore` form, for 5 policies x 13
  settings, both families: 520 comparisons;
- the fixes: each kind offered where it should be and verified; a
  created row gives the promised verdict and changes nothing it does
  not name; the check refuses the row again once the policy has
  changed; `fs_whatif_row_is_safe` refuses portless, ranged, listed,
  named-service, every-host and host-name rows;
- a brute-force sweep: every allow offered for 35 lines x 6 policies x
  3 settings x 2 platforms is one TCP or UDP port, both in the rules
  Windows compiles for it and in every line it adds to the Linux script;
- the second review (`test_review`): no allow for a line naming no host
  or an unread one, the allow for anyone labelled and warned, the
  stopped firewall's two verdicts, forwards outside router mode,
  "Block all incoming", interfaces in router mode, ICMP replies, and
  the notes each of these adds.

The card and the window are driven by two UI smokes (run under
`xvfb-run -a`; set `FS_SHOT_DIR` to a directory to save screenshots):

- `fs-simviz-smoke` builds the What-If window from real engine results:
  ALLOWED by a policy row, BLOCKED by the default (Create allow rule
  with its exact row), a user's block rule on both platforms (Open rule,
  never Create), a Sentinel block (Lift), DEPENDS, a line answered both
  ways (one tab per direction), the error state, a stopped firewall and
  held applies.  It checks the badge, the facts, the highlighted step,
  that an unverified row gets no Create, that the window is not modal,
  that Close is the sensitive default with a dark face (light in a dark
  theme), Esc and Enter, a still final frame without animations, and a
  dark-theme run in a child process.
- `fs-copilot-smoke` section 7 drives the real card: the entry keeps
  its line, the chips, the answer row, Recent (five, newest first),
  the example chips, Details opening a transient non-modal window that
  a new question updates in place, and Create: No writes nothing, Yes
  writes exactly the row shown, audited and held.  It runs with applies
  on hold and, as root, in a network namespace of its own.

`test-whatif-live.sh` runs in a private network namespace with a veth
peer that plays every remote host, and a third namespace behind v2
that plays a machine on the computer's own network.  It loads six
policy/settings rounds through the real Linux backend, then sends 46
real TCP, UDP and ICMP probes (Python sockets, raw ICMP echo) in both
directions: zero-padded ports (round 4), an echo reply nobody asked
for (caught by a raw socket after INPUT), a forward in router mode
(round 5) and outside it with IP forwarding off and on (round 6).  The
engine's verdict must equal what the kernel did for each one.  IPv4
only, since the test kernel has no IPv6.  It SKIPs without root,
iptables, ip, unshare, nsenter or python3.

Teeth, each re-injected into `fs-whatif.c`, seen failing, and restored
(`cmp`) to green:

| Bug re-injected | Checks that caught it |
|---|---|
| Windows lets a matching allow win over a block | 14 golden and detail checks |
| a portless line meeting a one-port rule answers ALLOWED (b1) | 11 golden checks, and test-core's b1 check |
| the safety check removed and a portless allow widened to 1-65535 | the sweep (108 offered rows named), "a portless question gets no allow row", the safe-row table |
| the Create path's re-check skipped | "re-checked after a block for the host was added, it is refused", the Linux ICMP block |
| created rows not re-simulated | the re-check, the Linux ICMP block, the Windows partial fix promising DEPENDS |
| the Linux model reads an outbound service row's host as the destination (b6) | 53 pin checks; live: round 2's DNS probe |
| the matcher ignores an outbound row's source address (the pin cannot see it) | live: round 2's DNS probe; the golden local-address row |
| "from the internet" not read as a direction | "read: \"block RDP from the internet\"", "read: \"allow https to anywhere\"" |
| a hostless allow offered for every host | golden "allow inbound ssh" offers no Create |
| an unread host name allowed as "anyone" | "review: an unread name is never widened to anyone" |
| IP forwarding not modelled | the forward goldens; live round 6 |
| the ESTABLISHED rule matching unsolicited replies | live round 4's unasked echo reply |
| "Block all incoming" ignored | the shields goldens and their note |
| an ICMP answer to an open connection counted against a block row | "fix: on Windows a whole host is blocked with a deny-to row" |
| ports written as typed (`fs-script.c`) | test-core "a zero-padded port is written in plain decimal"; live round 4 |

And in the UI (`fs-simviz.c`, `fs-copilot.c`):

| Bug re-injected | Checks that caught it |
|---|---|
| a Create button for a row the engine did not verify | "an unverified row gets no Create button, only the reason" |
| the window modal | "what-if: the window is not modal and holds no grab" |
| Close without the primary style | "Close is the dialog's sensitive default action, primary style" (and the dark run's face check) |
| the animation played with animations off | "reduced motion: the final frame at once, nothing to replay" |
| the card's line without the saved-policy caveat | "what-if: with applies on hold the one line says it describes the saved policy" |
| folded rows left in the focus chain | "review: a run of non-matching rules is folded, its rows hidden" |
| the allow-for-everyone button primary | "review: an allow for everyone is offered, not as the primary button" |
| the stopped header saying it describes the saved policy | "a stopped firewall and a held policy are said up front" |
| Create written without asking | "Create asks first", "answering No writes nothing" |

## The Copilot (`tests/test-health.c`, `test-core.sh`, `fs-copilot-smoke`)

```sh
cd port
bash tests/test-core.sh                     # detections, then test-health.c, then the wording guard
ninja -C build-linux fs-health-test         # test-health.c through CMake
ninja -C build-linux fs-copilot-smoke fs-hitview-smoke
xvfb-run -a ./build-linux/fs-copilot-smoke  # section 8: the page; a dark run in a child
xvfb-run -a ./build-linux/fs-hitview-smoke  # feed order (as root)
bash tests/test-cli.sh                      # stockfw copilot health
```

The Copilot is a set of fixed rules; the design is
`docs/ARCHITECTURE-AND-SECURITY.md` chapter 4 (every detection, its
limits, Sentinel's gates, what each platform's log shows) and section
14.4 (the 1.0.7 rework, the health check and the page).  That the
Copilot keeps working with the window hidden is `fs-session-smoke`'s
`background` scenario (Session safety, above).

`test-health.c` (pure GLib) pins the policy health check
(`core/fs-health.c`):

- exact coverage: a port range covers a port inside it, a network an
  address inside it, TCP never covers UDP, a host name never covers or
  is covered;
- a golden table, one small policy per check, on both platform models:
  duplicate, shadowed, unreachable, no effect, broad (101 ports is,
  100 is not), risky open (RDP Critical, SSH Info), a forward to a risky
  port, a deny by host name on Windows;
- every fix verified by the What-If engine, with its probes and their
  verdicts before and after, and the refusals: a narrowing that would
  also block a LAN host, a narrowing another row undoes, no known LAN,
  a removal that would change a verdict;
- apply and undo, by content, proved with the rules file's bytes,
  including an undo after the user removed another row in between.

`test-core.sh` adds the detections: the inbound scan (12 distinct ports
in 60 s reports; 11 ports tried twice do not), repeated login attempts
(10 in 5 minutes report; 10 over 6 minutes do not; Critical when the
policy admits the source; never auto-applicable), block-list hits
(outbound Warning naming the list; inbound rolled up per list per
hour), dedup by key, beacons per app (two apps polling one host are two
series; port 123 is never reported; auto-block needs 8 contacts),
fan-out per app, and that on a mixed corpus only the beacon's deny is
auto-applicable and no anomaly offers an allow.
`test_copilot_review_fixes` (F1 to F10) adds: DNS on 53 and 853 to a
configured resolver is not timed, and a resolver on another port, the
default gateway and a stub resolver with an unknown upstream are never
auto-blocked, also at `fs_insight_is_auto_safe` (the resolver, route
and stub files come from `STOCKFW_RESOLV_CONF`, `STOCKFW_RESOLVED_CONF`
and `STOCKFW_ROUTE_FILE`; main sets `STOCKFW_RESOLV_CONF=/dev/null` so
the host's own network never decides a result); a destination another
program has recorded connections to is withheld; allowed inbound probes
and refused probes teach the profile nothing; 260 new-port findings
evict behavior findings first; with 1024 sources tracked a new scanner
and a new login source are still seen; 40 addresses of one /64 make one
aggregate finding naming them; allowed-only login attempts from a
public source the policy admits are a Warning; SSH on a port the policy
names, and 9 attempts on SSH plus 9 on RDP from one source, report;
the new-destination times survive a restart; later probes update the
open scan and login findings; each beacon evidence row has its own
verdict, and TCP and UDP to one port are two series; a busy service
name ("https") does not trip fan-out without refused hosts.  The
mixed-corpus and fan-out tests feed program names (`scanner.exe`).
Its last step is the
wording guard: `\bAI\b` or `AI-` anywhere in `src`, `docs` or the
README fails the suite, except the one sentence that says there is no
AI model.

`fs-copilot-smoke` section 8 drives the page with applies on hold
(as root, in a network namespace of its own; on Windows against the
section 7 stand-in, a known firewall on a Private network, for every
section that calls `whatif_isolate`; `STOCKFW_LAN_PREFIX` fixes the
LAN and `STOCKFW_LOCAL_ADDRESSES` this computer's addresses, so a
runner's own 10.1.0.x or Public profile cannot decide the checks): the tiles follow the data (no constant), each finding
row has a pill with a word and an ATK name "Severity: title", the
drawer opens by click and by a real Enter key event and shows evidence
rows, an unverified fix has no button and says why, Fix asks first (No
writes nothing; Yes writes exactly the after row, audited), Undo puts
the rules files back byte for byte, the block offered from a finding is
checked by What-If first, and the empty states (no events, all clear
with "This is not a guarantee", monitoring off with its reason).  It
also checks: the Policy health tile counts the rows but not the "no
effect in this mode" notes (found by their own words, not a flag the
page sets) and says the notes are below; Needs attention counts the
Critical and Warning health rows; Show rule's ATK name names its row;
an undone change stays in Changes marked "Undone at" with no Undo; the
evidence cells are selectable and out of the Tab order; a click
delivered inside the open drawer (through `gtk_propagate_event`, so
the list box's own click gesture sees it) leaves it open, and the same
click on the head closes it; a refresh with nothing new keeps every
row widget and the focused button; a row that shows a new event is
rebuilt, stays open, and gets the focus back on the same button.  A
child process repeats the page under `GTK_THEME=Adwaita:dark` and
checks that it stays light (no dark class, dark title text, light
card).  Set `FS_SHOT_DIR` to save screenshots.

`fs-hitview-smoke` checks the feed order as root: with "skip repeats"
on, 10 identical log lines give the Copilot 10 events while the list
shows 1 row.

`test-cli.sh` checks `stockfw copilot health`: usage errors exit 2, a
clean policy exits 0, RDP open to anyone exits 7 with a verified
narrowing in `--json`, and the rules directory (files and times) is
unchanged afterwards.  The local network (`STOCKFW_LAN_PREFIX`) and
this computer's addresses (`STOCKFW_LOCAL_ADDRESSES`) are fixed: with
the real adapters, a CI runner's 10.1.0.x is a second private network
the narrowing would cut off, so no fix was offered and the check read
`fix: null` (seen on GitHub's Ubuntu runner, and reproduced as a
normal user in a network namespace with 10.1.0.42/16 and 172.17.0.1/16).
That case is now a check of its own: with 192.168.1.5 and 10.1.0.42
no narrowing is offered, `tried` holds the failed 10.1.0.20 check, and
the text prints it under the reason.  A failed check prints the JSON
it read.

Teeth, each re-injected, seen failing, and restored with `cp` (proved
with `cmp`):

| Bug re-injected | Checks that caught it |
|---|---|
| coverage ignores the protocol (`fs-health.c`) | "TCP 8080 and UDP 8080 are not the same rule", both models |
| fix verification skipped: `verified` forced TRUE | "a narrowing that also blocks a LAN host gets no fix", "no narrowing while another row still opens the port", both models |
| the narrowing writes `0.0.0.0/0` | 18 checks, among them "the fix narrows the row to the LAN, verified" and "checked: 203.0.113.10:3389 ALLOWED -> BLOCKED" |
| a host-name deny not flagged on Windows (the design's "Windows model treated as first match" row is replaced by this one: the unreachable golden rows already run on both models) | "windows: a deny by host name blocks nothing on Windows" |
| Undo finds the row by index, not by content | "undo: by content, the right row is restored (not row 2)" |
| the scan counts events, not distinct ports | "scan: 11 distinct ports do not (22 events ...)" |
| the brute-force window never expires | "brute: 10 attempts over 6 minutes do not (the window expires)" |
| the beacon keyed without the app | "two apps polling one destination are two series" |
| the NTP guard removed | "NTP (port 123) is never reported as a beacon" |
| inbound block-list hits not rolled up | 5 intel checks, among them "three inbound drops in an hour roll up into one finding" |
| anomaly findings carry an auto-applicable allow row | "a mixed corpus: only the beacon's deny is auto-applicable", and 31 "offers no rule" checks |
| "AI-powered" put back in the About dialog | the wording guard |
| the Copilot fed after the skip-repeats filter (`fs-hitview.c`) | "feed order: ... 10 identical events still reach the Copilot as 10 (got 1)" |
| a constant in the Policy health tile (`fs-copilot.c`) | "page: the Policy health tile counts the findings but not the ... notes", "page: the tile follows the check" |
| DNS over TLS (853) timed like any port | "F1: DNS (53) and DNS over TLS ...", "F1: DNS over TLS to a configured ..." |
| resolvers and the gateway not withheld | "F1: a resolver on any other port ...", "F1: the default gateway ..." |
| `fs_insight_is_auto_safe` ignores the resolvers and gateway | "F1: fs_insight_is_auto_safe refuses ..." |
| systemd-resolved's upstream list not read | "F1: DNS (53) and DNS over TLS ..." |
| a stub with an unknown upstream auto-blocked | "F1: behind a stub with an unknown upstream ..." |
| only the program's own history checked | "F2: a destination another program ..." |
| new-port signal on inbound events | "F3: allowed inbound probes ..." |
| refused probes recorded in the profile | "F4: refused probes teach the profile no destinations" |
| the 200 cap evicts the oldest finding of any kind | "F3: 260 new-port findings ..." |
| the scan table refuses new sources when full | "F4: with 1024 sources ..." |
| no IPv6 /64 aggregate | "F4: 40 addresses of one /64 ...", "F4: its evidence names ..." |
| the login table refuses new sources when full | "F4: with the login table full ..." |
| allowed-only attempts always Info | "F5: allowed connections only ..." |
| login ports from the policy ignored | "F6: SSH on 2222 ..." |
| login attempts counted per port | "F6: 9 on SSH and 9 on RDP ..." |
| new-destination times not saved | "F7: behavior.csv keeps ...", "F7: after a restart ..." |
| an open finding not updated within the hour | "F8: the 11th and 12th ...", "F8: the open scan finding ..." |
| every beacon evidence row copies the latest verdict | "F9: seven allowed contacts ..." |
| the protocol left out of the beacon key | "F9: TCP and UDP to one port ..." |
| a service-name key counts any host for fan-out | "F10: one busy page ..." |
| the findings list rebuilt on every refresh (`fs-copilot.c`) | "page: a refresh with nothing new keeps the row and its focused button", "page: the row that did not change is the same widget" |
| the focus not put back after a row is rebuilt | "page: when the focused row changes, the focus goes to the same button in its new row" |
| the page given the dark class again | "dark: the page stays light like the rest of the app" |
| the evidence cells' colour rule removed (`fs-theme.css`) | "dark: the evidence cells are dark text on the light card (48 of 54 light)" |
| Undo removes the change from the list | "page: the undone change stays in Changes ..." |
| Needs attention skips the health rows | "page: Needs attention counts the policy's Critical rows", "page: Needs attention counts the Warning finding ..." |
| the health tile counts the "no effect" notes | "page: the Policy health tile counts the findings but not the ... notes" and 3 more |
| the drawer guard lets the click through | "page: a click inside the open drawer leaves it open" |
| drawer text not selectable | "page: the evidence cells are selectable text ...", "page: what Sentinel did can be selected and copied" |
| Show rule without its ATK name | "page: Show rule's accessible name names the row" |
| the tile note does not say the notes are below | "page: the tile's note says the notes are below" |
| the auto pass does not judge the gates again (`fs-copilot.c`, UI) | "R1: resume does not block a host brave.exe now uses", "R1: the switch to auto-block does not block ...", "R2: resume does not stage a deny over the user's allow" and 3 more |
| `fs_copilot_beacon_recheck` passes every beacon unjudged | "R1: another program's later use of the host withholds ...", "R2: an allow row added later ...", and the same 6 smoke checks |
| the user's allow row not a gate | "R2: a beacon to a host the policy allows ...", "R2: an allow row added later ...", "R2: a new beacon to an allowed host stages nothing" and 4 more |
| a Linux service key called a program in the withheld text | "R3: another service key is named as a port's traffic ...", "R3: a service key's own history ..." |
| `test-core` writes its settings under the shared temp dir | "the settings, baseline and audit files go to a directory only this run owns ..."; run as a normal user next to a root-owned `/tmp/stockfw`, 86 checks fail and the program crashes |

Since the review of 1.0.7, the staging pass asks `fs_copilot_beacon_recheck`
before it writes, so a pass that runs late (a tray pause ending, a switch
from Detect only, a retry) judges the beacon's gates with that moment's
baseline, network and policy. `test-core.sh` makes its own temp dir for
each run and removes it at the end.

## Threat-intel backend slots on Linux (`tests/test-intel-backend.sh`)

```sh
cd port
ninja -C build-linux fs-intel-backend-driver fs-nftset-load
sudo bash tests/test-intel-backend.sh   # needs root, nft, iptables; SKIPs otherwise
```

`src/platform/linux/fs-backend-linux.c` fills the four threat-intel
slots of the backend (design section 7): `intel_apply` loads
`fs_intelset_nft_script()` with the nft runner of `fs-nftset.c` (60 s),
`intel_clear` loads `fs_intelset_nft_clear_script()`, `intel_counters`
parses `nft list chain` of the three base chains with
`fs_intelset_nft_parse_counters()`, and `intel_live` reads `nft -j list
tables` with `fs_intelset_nft_parse_live_state()` (listings get 10 s).
An apply is the module's one transaction -- create if missing, delete,
re-create, in a single `nft -f -` -- never a delete of its own first.
After every apply and clear, whatever nft said, the backend reads the
live table back and trusts it: an nft that timed out or was killed
after it committed is a success; after an nft success the table must
carry the digest asked for (the empty rule set: no table at all), or
the apply fails saying so.  A failure says which lists are in force
now.  Errors are `G_IO_ERROR`: `PERMISSION_DENIED` (not root),
`NOT_FOUND` (no nft), `TIMED_OUT`, `INVALID_ARGUMENT`, `FAILED`.  The
Windows backend leaves the four slots NULL until Round 3: that is how
the engine knows to say "unsupported" rather than "cannot tell".

`fs-intel-backend-driver` calls the slots through `fs_backend()` the way
the engine does, plus the policy's `apply_rules`, `stop` and
`clear_rules`.  It is built with its own copy of the backend compiled
with `FS_BACKEND_TESTING`, the only build in which
`$STOCKFW_TEST_NFT_TIMEOUT_MS` shortens the nft timeouts.  The test runs
under `unshare -n` with a peer namespace on a veth pair, and every nft
the slots run goes through a wrapper that logs its arguments and the
scripts it loads.  It proves:

- the four slots are set; with nothing loaded live is absent and the
  counters are NULL;
- an apply is live with its digest, in exactly one nft load; the IPv6
  rules are loaded (as rule text: no IPv6 packet is sent here);
- counters move by exactly what hit a listed address -- 5 datagrams
  from the listed peer, 3 sent to an out-listed address (refused by the
  send itself) -- and equal nft's own listing;
- re-applying the same digest is an idempotent replace: same live
  digest, one load, counters back at zero (the engine carries them just
  before an apply, so a skipped re-apply would count them twice);
- a change replaces the old sets and rules, not merges;
- applying the policy twice, stopping it, clearing it and applying it
  again leaves the table and its counters untouched [N6];
- a transaction the kernel rejects is an error naming the lists still
  in force, and they are;
- nft killed before it loads: an error, the old lists in force; killed
  after it committed: a success, the new lists live;
- nft hanging before it loads: a timeout at 800 ms (not the hung nft's
  30 s), the old lists in force and named; a timeout after the commit:
  a success, for an apply, a clear, and the empty rule set; nft hanging
  on everything: live unknown, counters NULL, the apply times out and
  says the lists in force could not be read;
- an unreadable listing is unknown, never absent; nft accepting a load
  whose table then cannot be read back, or that someone replaced at
  once, is not reported as applied;
- the empty rule set leaves no table and that is a success (live
  absent), also when no table was there;
- clear removes the table; twice is fine;
- no nft: apply and clear are `not-found` errors naming the nftables
  package, live unknown, counters NULL; not root: `permission` errors,
  live unknown, counters NULL; neither changes the kernel;
- the slots list only `-j list tables` and our three chains, never a
  table, a set or the ruleset [S8.3];
- every script the slots loaded names no table but `inet
  stockfw_intel`, and the policy's iptables rules, Docker-style chains
  (`DOCKER-USER`, nat `DOCKER`), a libvirt-style `ip libvirt_network`, a
  firewalld-style `inet firewalld` (holding an address our lists hold
  too) and the standalone helper's `inet stockfw_blocklist` are byte for
  byte the same after all of it (`iptables-save` without counters,
  `nft -s list table`).

The sanitizer build (`build-asan`, `-fsanitize=address,undefined`,
Debug) of `fs-intel-backend-driver` and `fs-nftset-load` runs the whole
test clean (`STOCKFW_INTEL_BACKEND_DRIVER`, `STOCKFW_NFTSET_LOAD` point
the test at it).

Teeth, each injected into the backend by a script that asserts the
exact old text once, seen failing, restored with `cp`, checked with
`cmp`, and seen green again:

| Bug re-injected | Checks that failed |
|---|---|
| after an nft error, the error is trusted and the live table not read | `nft killed after it committed`, `a timeout that fires after nft committed`, `a clear whose nft times out after committing`, `the empty rule set with a timeout after the commit`, and the four checks whose error must name the lists in force (8 in all) |
| after an nft success, "applied" without reading the table back | `nft accepted the load but the table cannot be read back`, `... but another table is there now` |
| the boolean `parse_live()`, so an unreadable listing reads as absent | `a listing that cannot be read is unknown, not absent`; `... cannot be read back: not reported as applied` (it said "something removed it") |
| the empty rule set expected as a table with its digest | `the empty rule set is applied by removing the table`, `applying it again`, `the empty rule set with a timeout after the commit` |
| a re-apply of the digest already live skipped as a no-op | `re-applying the same digest ... in one load`; `and the counters start again from zero` (got 5 and 3) |
| the old table deleted in an nft call of its own before the load | `the apply was one nft load`, `a rejected transaction ... names the lists still in force` ("No blocklists are loaded now"), `the previous table ... still in force`, `nft killed before it loaded anything`, and the hang checks (30 s, not 800 ms: the separate delete hung) -- 8 in all |
| counters read from `nft list table` | `the slots list only the tables and our three chains` (the counts themselves stayed right) |
| the policy's stop also removes the intel table | `the lists and their counters are untouched by all of it`, and the three checks that need the previous lists in force |
| no root check before running nft | `not root: the apply says it needs root` (nft's own complaint instead), `not root: clear is an error` |

The upfront `nft` lookup has no tooth: without it the runner's own
"Could not run nft (is the nftables package installed?)" is also a
`not-found` error and reads the same in every check.

The split-delete tooth of the rule-set section above stood in for this
backend with `fs-intelset-driver apply`; here it is injected into the
real `intel_apply` and caught by the same kind of rejected transaction.
