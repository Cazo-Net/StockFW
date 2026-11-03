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
| threat intel on Windows | blocklist rules: plan, chunking, read-back verdicts, in force, on-link prefixes (see below) |
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

Linux only.  Builds the whole tree in the build directory through CMake
(the man page and `cmake --install` need more than the `stockfw`
target) and drives the real binary against scratch rules and config
directories and a fixture kernel log, so it never touches
`/etc/stockfw` or the host's firewall.  Without root, `apply` only runs
with `--dry-run`.  As root, more parts run: the live event line and
`events -f` (under `script`), the lockout guard under `sudo`, and real
`apply`, `start` and `stop`, these only in a private network namespace
(`unshare -n`).  A root-only part that cannot run prints `skip:`; CI
runs the script as root and fails on such a line.  The midnight check
of the live event line builds `tests/fake-clock.c`, an `LD_PRELOAD`
shim that moves the wall clock (not the timers) of `stockfw`.

It pins down the documented exit codes, policy editing (the service
shorthand, refused commas, mistyped options and bad hosts), the
simulator's verdicts, the kernel-log history, every `--json` document
parsed back, and the dashboard's security model: loopback only, the
session key (header only, never the query string or the page; the
launch code read from the launch file, since the link is never printed
to a pipe), the Host check against DNS rebinding, GET/HEAD only, the 16 KB request-head
cap, the CSP nonce, and the dashboard leaving its own sockets out of the
connection list.  `stockfw events` is checked with its filters
against the kernel log, and `--history` against a history folder the
test writes by hand (so the file format is pinned too): oldest first
across days, `-n` keeping the newest, `--since`/`--until` by day and
by stamp, every filter, a damaged and a cut-short line skipped and
counted, unreadable filters refused with exit 2, and a missing folder
named with where it would be.

As root, the dashboard runs here as `sudo` runs it, with
`SUDO_UID=65533`, and a `curl` first on `PATH` makes every request as
uid 65533: the dashboard reads no other account's connections.  Its
`$XDG_RUNTIME_DIR` is a directory of that uid, where the launch file
and the link socket go.

## Dashboard server and credentials (`tests/test-dashboard.sh`)

```sh
cd port
sudo STOCKFW_BUILD=build-linux bash tests/test-dashboard.sh
```

Linux only.  It also builds `stockfw-dash-test` (the
same sources with `FS_DASH_TESTING`: a test clock, a WSL switch and an
"ownerless" uid) and `fs-dash-auth-test` (`tests/dash-auth-test.c`, the
session rules on a clock of its own).  Starts the dashboard from a copy of
`stockfw` in a directory every account can read, with `SUDO_UID=65533`
when run as root, and checks `src/cli/fs-dash-http.c` (docs 15.3.1):
with 32 slow senders holding connections a valid request answers
within 1 s; a head or a body trickled in is cut off after 5 s;
`Host: localhost:PORT`, two `Host` headers, `Upgrade`,
`Transfer-Encoding` and a body over 64 KB are refused.  As root it
also checks that connections from root, from `nobody` and from
127.0.0.2 get no byte back even with a session, and that the dashboard
refuses to start as root without `SUDO_UID`.  Without root those
checks print `skip:`.

For `src/cli/fs-dash-auth.c` and the page (docs 15.3.2, 15.3.3): piped
or with `--json`, no hex string of 32 characters or more is printed,
and on a terminal (a pty) the link is; the launch file is 0600 in a
0700 directory and is gone once its code is used, or at 121 s on the
test clock; a code used twice gets 410 and ends every session; an
unknown code 401; POST without or with a foreign `Origin`, with
`Sec-Fetch-Site` `same-site`, `cross-site` or missing gets 403,
`text/plain` 415, no `Content-Length` 411, `OPTIONS` 405 with no CORS
header; a GET with a foreign `Origin` or a cross-site or same-site
`Sec-Fetch-Site` gets 403; `--origin-port N` lets in `Host` and
`Origin` 127.0.0.1:N (via `ssh`) and nothing else; a key from the last
run gets 401; reads stop at 12 h on the test clock; `dashboard link`
prints a path on a pipe and a link on a terminal; the new headers are
sent; the release `stockfw` has no test hook in it.  As root: the
link socket answers no other uid, and on a pretend WSL a peer with no
socket owner is closed unless `--allow-windows` is given.

From the review of PR 2 (docs 15.3.4): with `--allow-windows`, a
request from another account that closes at once is not read (the
dashboard is held with `SIGSTOP` meanwhile; once normally, once in a
network namespace that keeps no `TIME_WAIT` entries); with 40,000
`TIME_WAIT` entries (in a namespace of its own) 20 requests answer
within 2 s; empty lines before the request line are skipped, under
`G_DEBUG=fatal-criticals`; SIGHUP removes the socket and launch files;
`dashboard link` skips the socket of a killed dashboard and prints the
`--origin-port` link.  The root-only parts need `unshare`, `nsenter`,
`ip` and `sysctl`; the whole script now takes about 3 minutes.


## Event store and history (`tests/test-eventstore.sh`)

```sh
cd port
bash tests/test-eventstore.sh               # the checks
bash tests/test-eventstore.sh bench 100000  # timings and memory
bash tests/test-eventstore.sh bench 1000000
```

Compiles `src/core/*.c` by hand, like `test-core.sh`; GLib only.  It
pins down `core/fs-eventstore.c` (the ring buffer behind the Events
list) and `core/fs-eventlog.c` (the history on disk):

- times: both backend stamps read and written back exactly, anything
  else kept as text; every `--since`/From form.
- the ring: the oldest goes first, the evict callback sees it still
  readable, growing and shrinking keep the newest, 1,000,000 is the cap.
- interning: one copy of each string, freed with its last event, ids
  reused; a query's cached answer is not reused for a new string that
  got an old id.
- duplicates: the same row twice is one event, as before.
- filters: text (the columns the list shows, the time as shown
  included, the rule not; `--grep` the same), direction, verdict,
  protocol, port (single, range, colon), address (v4 and v6 CIDR,
  ranges; names and /33 refused), time window, and every combination
  agreeing with the store-free check the command line uses.
- CSV: the header, quoting, formula-looking fields defused (a leading
  minus too, unless the whole field is a plain number: `-1+1` and the
  DDE payload `-2+3+cmd|' /C calc'!A0` are defused, `-5` and `-1.25`
  are not), mode 0600.
- history: round trip with escapes and a text stamp; a cut-short last
  line and a damaged middle line skipped and counted, the next write
  starting on a fresh line; folder 0700 and files 0600 (a loosened file
  put back); age and size limits (a file that is not ours left alone);
  the bounded load at start reads only the newest files it needs.
- history at volume: 460,000 events in a day under the 1 MB cap go past
  part 999, and usage, the cap, the load and Delete history all see
  part 1000 and after; a restart after the cap took the day's first
  parts goes on after the highest part, so the start shows the newest
  and the cap deletes the oldest; no part grows past its size; an event
  stamped a year ahead is filed under today, and a file named for a
  later day (from before) is capped and aged by when it was written;
  under the 10,000 MB cap a part stops at 32 MB and the start reads
  only the bytes of the 1,000 events it loads.
- a full disk (Linux; `RLIMIT_FSIZE` makes write() fail as ENOSPC
  would): the problem is said and the lost events counted, the next try
  waits out the back-off, then history goes on; new limits (Preferences
  > Save) try again at once; every event is either in the history or
  counted as lost.
- one writer per folder: a second log on the same folder is refused
  (`FS_EVENTLOG_ERROR_IN_USE`, "another copy of StockFW is saving the
  history") while the first is open, from this process and from a
  forked child; once the child is killed without closing (a crash) the
  system has dropped its lock and the folder opens again.  The lock file
  is 0600, not counted as history and not deleted by Delete history.

Teeth: open the lock without `flock()` and "a second log on the same
folder is refused while it is open" fails.

## The Windows event log reader (`tests/test-winevt.sh`)

```sh
cd port
bash tests/test-winevt.sh
```

Runs `core/fs-winevt.c`, the logic of the Windows backend's
Security-log reader, on any platform, against a fake log
(`tests/winevt-fixture.h`: records first..last in wevtutil's raw
`/f:xml` shape, 5156 and 5157 alternating, a 4624 logon every
thousandth).  Until 1.0.7 the backend read the newest ten events every
five seconds (`/c:10`), so a burst of 4,000 reached the Events list as
ten.  It checks:

- parsing: a 5156 and a 5157 give the rows the text reader gave (port
  is the destination port, In and Out the local and remote side by
  direction, `%%14592`/`%%14593` and the rendered words, protocol
  names, the program's file name as the service, `[BLOCKED]` on 5157,
  `&amp;` and `&#233;` unescaped, the time from `TimeCreated`); another
  event id or no `DestAddress` gives no row; double quotes, a BOM and
  an `EventID` with attributes are read; a cut-short last element is
  left out and said.
- the command: the poll's exact argv (`/q:` with `EventRecordID>N`,
  `/c:10000`, `/rd:true`, `/f:xml`), no metacharacter in the query, and
  the probe's argv (the newest record of any kind).
- polls against the fake log: the start skips what was there; a burst
  of 4,000 arrives whole, oldest first, once, and all 4,000 land in an
  event store; the same log again delivers nothing; a burst of 30,000
  delivers the newest 10,000 and counts the gap below them as skipped
  (an upper bound: the gap holds the logons too); a cut-short read
  counts what it lost; a cleared log (newest record below the cursor)
  sends the cursor back to 0 and the records since the clear arrive,
  once; rollover needs nothing; overlapping batches in both orders give
  each record once; a timed-out read halves the next request down to
  500 and good reads double it back; when the event log refuses the
  record condition, the newest records read without it deliver only
  what is new and a full batch that reaches back past the cursor (also
  over a logon record) counts nothing as skipped.  Parsing 10,000 events must take
  well under a poll (about 75 ms here).

Teeth (each restored with `cp` and checked with `cmp`): `/c:10` fails
"poll argv"; taking records at the cursor (`>=`) fails "once each";
no sort fails "oldest first"; no skip count fails "skipped: the record
gap"; no clear check fails "cleared"; no halving fails "timeout: half";
the time looked for outside `<System>` fails "the time is
TimeCreated's SystemTime"; no `&amp;` fails "&amp; unescaped"; a
full batch counting a skip though it reached the cursor fails "no
record condition (fallback)".

On Windows `tests/test-winlog.sh` runs the same fake log through the
real spawn: `fake-wevtutil.exe` (built beside the test; the test build
runs a tool from `STOCKFW_TEST_TOOL_DIR`, which the test points there,
while the release build runs System32's only) answers for `STOCKFW_FAKE_WEVTUTIL_LOG` ("first last"),
honours the query's `EventRecordID>`, `/c:` and `/rd:`, pads with NULs
and records its arguments; with `STOCKFW_FAKE_WEVTUTIL_NO_RECORDID=1`
it refuses a query with the record condition (exit 15001).  The test starts monitoring, checks a burst
of 4,000 arrives whole and in order, nothing twice, 10,000 of a
30,000 burst with the skip shown through `log_skipped`, the records
after a clear, that a refused record condition still brings the new
records once with nothing counted as skipped, and that the query
reached wevtutil as one argument.

## Events list at scale (`fs-hitview-smoke`)

```sh
cd port
ninja -C build-linux fs-hitview-smoke
xvfb-run -a -s "-screen 0 1280x900x24" ./build-linux/fs-hitview-smoke
STOCKFW_EVENTS_SHOTS=/some/dir xvfb-run -a ./build-linux/fs-hitview-smoke
```

Builds the real Events page with its history in a scratch folder
(`STOCKFW_EVENTS_DIR`).  Besides the page's older checks, it reads 500
saved events back at start, then appends 100,000 events into the shown
list and checks: the list's model is the virtual one (no GtkListStore,
no filter copy) in fixed-height mode; appending reads only the visible
cells; a scroll frame at 100,000 rows costs what it costs at 1,000
(measured up to three times, so one stall on a busy CI machine does
not decide it; every attempt is printed);
the port, CIDR, protocol and combined filters give the store's own
count, label included, and every shown row matches; live events at the
cap land or are left out as the filter says; a bad port is refused and
the list kept; CSV export writes the filtered rows; sorting by port is
numeric both ways and a live event lands in sorted place; the history
files are written.  Timings are printed as `measure:` lines.

The list checks count and order only the rows the smoke puts in, so
after the reason-strip check the smoke turns the page's Monitor switch
(`events-monitor`) off.  On Windows the live source is the real
Security log, where any connection the runner makes is an event; one
(local port 32526) once landed in the port sort check on Windows CI.
On Linux the source is the scratch kernel log the smoke tails as root,
and only the feed-order check turns Monitor on again, for its own
lines.  The switch, not `fs_hitview_stop()`: a stop behind the
switch's back is what the page's watchdog reports as "Event monitoring
stopped.", as it should for a source that dies on its own.

History is off until switched on (checked), so the smoke switches it on
in a scratch settings folder.  On Linux it also fills the disk in the
middle of the session (`RLIMIT_FSIZE`): the strip says history is not
being saved within seconds, and with room again the history goes on
and the strip goes back to what it said.

At the list's largest, 1,000,000 events in a real view, a burst of
5,000 live events under the port sort and under the source sort must
cost about what it costs under the time sort (within 6 times, plus 20
us).  Before the row list was kept in chunks each such event moved up
to the whole row array twice, about 200 us at this size.  After those
bursts, and after 360,000 adds and drops at 20,000 rows (chunks split
and joined many times), the rows must be exactly those a sort from
scratch gives.

The Preferences smoke (below) covers Preferences > Events: the list
size, the history switch (off at first) with its days and size rows
live only while it is on and going up to the limits the app keeps to
(3,650 days, 10,000 MB), values clamped to the row's range, and Delete
history asking first, then deleting only history files.

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

## The verdict in both front ends (`fs-verdict-smoke`)

```sh
cd port
ninja -C build-linux fs-verdict-smoke
DISPLAY=:99 ./build-linux/fs-verdict-smoke   # needs a display
```

`stockfw status` prints the Overview's verdict on its first line from
`fs_verdict_compute` (core); the window still has its own copy in
`update_overview` (`src/ui/fs-statusview.c`).  `tests/verdict-golden.h`
is one table for both: `test-pr3-core.c` (run by `test-core.sh`) checks
the core against every row, and this smoke builds the real Overview
page against a fake Linux-shaped backend (and one with no IPv6 slot),
sets each row's state and IPv6 answer that the window can be given, and
checks the card's title, body, sidebar word and level against the row
and against `fs_verdict_compute`, byte for byte.

Teeth, each seen failing when re-injected: a sentence changed in the
core's copy (row and parity checks), the same in the window's copy, and
the core ignoring the IPv6 answer.


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

### How curl is started (`fs-fetch-spawn-test`, Windows and Linux)

```sh
ninja -C build-linux fs-fetch-spawn-test   # also builds fs-fake-curl
./build-linux/fs-fetch-spawn-test          # not as root
```

`tests/test-fetch-spawn.c` runs `fs_fetch()` against
`tests/fake-curl.c` in curl's place (`fs-fake-curl` next to the test,
or the path given as the first argument).  The fake is plain C without
GLib, because on Windows `fs_fetch()` gives curl no `PATH`; it reads
only `--url` and acts on its path (`/ok`, `/bytes/N`, `/exit6`, `/hang`,
`/stderr-flood`, `/argv`, `/env`, `/cwd`).  On Windows the test calls
`FreeConsole()` first, as the window app has no console, and checks
that the fake started by `fs_fetch()` has no console window on the
screen, then starts the same fake through `GSubprocess` (how curl was
started before the fix) and checks that it does get one: the control
that proves the first check can fail.  On both platforms: the body at
and under the cap, TOO_LARGE one byte over, exit 6 and 22, a hanging
curl killed at the deadline, 4 MiB on stderr, user agents with spaces,
quotes and backslashes reaching curl unchanged, the environment exactly
`fs_fetch_envp()`, the working folder (`/`, or the Windows system
folder), a missing curl as NO_CURL, and no handle or descriptor left
after twenty downloads.  As root on Linux it prints SKIP: curl would run
as `nobody`, which `test-fetch.sh` covers.  `full-suite.sh` runs it on
both; CI runs it as the runner's user on Linux and in `full-suite.sh` on
Windows.

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

The footer's Help button is checked to be there on both platforms'
page sets; what it opens is checked in `fs-help-smoke` below.  The
About credits are checked here too: the creator line reads exactly
"Stockfw Team - Creator & Original Developer", and no credit
carries an e-mail address.

## Help and About (`fs-help-smoke`)

```sh
cd port
ninja -C build-linux fs-help-smoke
xvfb-run -a ./build-linux/fs-help-smoke                     # Adwaita:dark
GTK_THEME=Adwaita xvfb-run -a ./build-linux/fs-help-smoke   # light
STOCKFW_HELP_SHOTS=/some/dir xvfb-run -a ./build-linux/fs-help-smoke
```

Builds the real main window (`fs_app_activate` in a `GtkApplication`),
with every file it reads or writes (settings, rules, journal, audit
log, behaviour baseline, trust store) moved to a scratch directory.
It runs under `GTK_THEME=Adwaita:dark` unless `GTK_THEME` is set, and
fails on any GTK warning or critical.  With `STOCKFW_HELP_SHOTS` it
saves three Help topics, Help opened from Preferences and About, named
after the theme.

What it pins down, each seen failing when its bug is put back (the
check that failed is in brackets):

- H1: `app.help` and F1 on the main window open Help at the topic for
  the page shown; so does the sidebar's Help item.  Every page of the
  main window maps to its own topic (`fs_help_topic_for_page`), and F1
  on the Threat Intel page opens `threat-intel`.  Ctrl+W closes it.
  (Re-injected: the action not registered; the accelerator on F2; the
  page table without Threat Intel, as it was after the merge of PR
  #18, which opened Copilot's topic on Threat Intel, Trust's on Copilot
  and Getting started on Trust.)
- H2: every topic in `fs-helpcontent.c` renders, with its title and
  every block on screen; every string parses as GtkLabel markup, every
  `help:` link and related topic names a real topic, and there is no em
  dash.  (Re-injected: callouts not rendered; an unclosed `<b>`; a
  link to `help:troubleshoot`.)
- H3: search filters the topic list ("SSH locked" lists Troubleshooting
  and leaves Activity out), finds subtopics, says when nothing
  matches, opens the first match on Enter ("feodo" opens Threat intel)
  and is cleared by Escape.
  (Re-injected: every topic matching.)
- H4: links, related-topic chips, Next (after Policy comes Threat
  intel, in the main window's sidebar order), the breadcrumb, the sidebar,
  Back, Forward, Alt+Left and Alt+Right all navigate.  (Re-injected:
  `help:` links not followed; the topic left not put on the Back
  list.)
- H5: Preferences' Help button opens `prefs-<page>` for every page it
  shows, and F1 there does too.  Help lives in its own window group, so
  a key on it acts while Preferences holds its modal grab, and closing
  Preferences leaves Help open.  (Re-injected: Help always opening
  "preferences"; F1 not handled; Help left in the default window group,
  where the key went to Preferences instead.)
- H6: one Help window; asking again moves and raises it.  (Re-injected:
  a new window each time.)
- A1: About is a dialog transient for the main window and not modal,
  one at a time; the first credit reads exactly "Stockfw Team -
  Creator & Original Developer", the three credits on this base are
  shown, nothing in it has an `@`; the licence summary names both
  texts the source carries (GPL v2 in `COPYING`, Apache 2.0 in
  `LICENSE`) and claims no GPL 3; "View licence texts" shows both
  files, compiled in at configure time, form feeds dropped.
  (Re-injected: the credit reworded; an address in a credit; "version
  3" in the summary; About opening twice.)
- A2: "Copy system info" copies the StockFW, GTK and GLib versions, the
  operating system and the firewall backend, and nothing with the user
  name, host name, home directory, an `@` or a `/` in it; the clipboard
  then holds exactly that.  (Re-injected: the user name added; the
  clipboard given something else.)
- T1: every label drawn in Help (six topics, and the sidebar's "nothing
  found" line), About and the licence window is at 4.5:1 or more
  against the colour painted behind it, measured from the style GTK
  computes under the theme.  (Re-injected: the article text's colour
  rules removed, which leaves Adwaita:dark's light text on the light
  page.)

- H7: claims the code does not back are gone from the help, and the
  true statement is there instead: on Linux only the inbound default
  and "Block outgoing unless allowed" log their drops (deny rules,
  Sentinel and the Protection blocks do not); the Windows broadcast
  blocks are not offered, since a rule can only match 255.255.255.255
  as the sender; on a Public network the Windows reserved-address
  block outranks your own allow rules; What-If (1.0.7, as merged from
  main) takes the broadcast and reserved-address blocks into account;
  a Sentinel block whose ten minutes ran out while StockFW was closed
  is taken off when StockFW starts again with the rights to (as
  `start_at_launch` in `fs-app.c` does); StockFW's Windows rules start
  with `StockFW`; threat intel works on Windows too, as rules in their
  own group; StockFW
  also turns profiles on and off; the ported code is GPL 2 or later.
  (Re-injected: the old `fs-helpcontent.c`, which fails all ten.)
- H8: the help matches 1.0.7 as merged.  What-If answers DEPENDS, asks
  both ways when the line names no direction, takes the firewall's
  state into account and names its fixes as the window does ("Create
  allow rule"); the background topic describes the tray menu as it is,
  with its Help item, one StockFW per user and `--background`; Sentinel
  describes the tray's pause; Preferences > General describes the
  sign-in switch; the Linux notes describe `stockfw.service`; the CLI
  topic gives exit status 6 for DEPENDS.  Threat intel (PR #18) is
  described as present: the terms dialog's "Accept and turn on", a
  lookup that says "would be blocked once in force" unless it is, the
  Linux table `inet stockfw_intel` and the Windows rule group "StockFW
  Threat Intel", no per-rule counts on Windows, the update judge's
  "Accept smaller list", and `/api/intel`; Events offers "Add
  exception"; What-If says it does not consult the lists; the Linux,
  Windows, CLI and background topics name the table, the group,
  `stockfw intel lookup` and the hourly update check.  Blocking by
  country or network owner is described as present too: the switch
  "Use the location database" and its dialog, "is registered, not where
  the computer using it is", the "Anycast" mark, the licence as
  IPFire confirmed it (CC BY-SA 4.0), "downloaded at most once a day",
  Windows "not supported on Windows in this version of StockFW", and
  the CLI topic's `stockfw intel geo`.  No FS_HELP_SOON callout is
  left in any topic (the last one, on country and ASN blocking, went
  with the page and the command); the threat-intel summary names
  countries and does not say "available" or "build"; no block or
  summary mentions 1.0.7 or says "in this build", "planned" or
  "coming", in any case; and the shown threat-intel topic has
  "Countries and networks" with the licence line and no "Not in this
  build" heading.  (Re-injected: the pre-PR #18
  `fs-helpcontent.c`, which fails the fifteen threat-intel H8 checks,
  the changed H7 one and H4's Next; before that, the branch's pre-merge
  `fs-helpcontent.c` and the old heading, which failed the fourteen
  older H8 checks.)
- H9: What-If's settings fixes.  `fs_dialogs_preferences_at` opens
  Preferences at `icmp` and at `protection`, and each is the page
  shown; every switch label and page title `fs_whatif_setting_nth`
  lists (the ones a fix's text names) is in the dialog as written; the
  What-If topic says a fix opens the ICMP or Protection page.
  (Re-injected: the old engine labels and pages "Enable ICMP
  filtering" on "Preferences > Firewall > ICMP Filtering"; the dialog
  always opening on General.)  `fs-copilot-smoke` presses Open ICMP
  settings in the What-If window and checks that Preferences opens at
  ICMP (re-injected: `fs-copilot.c` calling `fs_dialogs_preferences`).
- K1: keyboard.  Tab and Shift+Tab in About walk View licence texts,
  the website, Copy system info and Close; About asks for the keyboard
  when it opens (`gtk_window_present`), since a dialog that never gets
  it keeps every Tab on Close.  Help opens with focus on the topic
  shown, not in the search field (GTK hides a focused entry's
  placeholder).  The topic list is one Tab stop: 30 Tabs land on a
  topic at most once and open nothing; Down moves along the list
  without opening, Enter opens.  Every button, row and entry in Help
  and About has a name for a screen reader (Back and Forward are
  icon-only).  (Re-injected: About not presented; the list's focus
  handler removed; selection following focus; the history buttons
  and the rows left unnamed; focus put in the search field.)
- L1: layout.  Key caps are one height beside text that wraps, and
  the shortcut descriptions start in one column; no topic makes Help
  wider than 640 pixels (the caps wrap between keys); on a wide window
  the page is a centred column of at most 700 pixels; related-topic
  chips sit 6 pixels apart (a GtkFlowBox spread them, so they are laid
  out by a small wrapping container); the sidebar is `FS_SIDE_WIDTH`,
  as in Preferences.  At Help's own size (980 by 680) no topic title
  in the sidebar is ellipsized: a long one wraps.  (Re-injected: caps
  filling the row; caps that never wrap; the descriptions' width left
  free; no column limit; chips 60 apart; a 250-pixel sidebar; the
  topic labels ellipsized at the end, which cuts "Running in the
  background" and "Command line and dashboard".)

The prefs smoke's Help-button check was seen failing with the button
left out of the footer.

The Preferences redesign is checked in the prefs smokes, on both
platforms' page sets: the sidebar is `FS_SIDE_WIDTH` wide, as Help's,
and groups its pages under "StockFW" and "Firewall"; every page opens
with its icon tile; every sidebar item is named for a screen reader;
on a wide window the settings column stops at 720 pixels and is
centred; a change marks its row, its page's dot in the sidebar (no
other page's) and the footer, and changing it back clears all three.
On Windows the broadcast blocks are not offered, and the
reserved-address row says it outranks your own allow rules on public
networks.  (Re-injected: no group headings; no page icon; no column
limit; changes not marked; a 200-pixel sidebar; the broadcast rows
offered on Windows; the old Windows reserved-address line.)

After the merge with main's Preferences (PR #17), start at sign-in is
marked the same way although it is not a `stockfw.conf` row: moving
its switch marks its row and General's dot, and moving it back clears
both and the footer ("sign-in: the moved switch marks its row and
General in the sidebar", in the `signin-cancel` scenario of
`fs-prefs-fake-smoke`).  (Re-injected: the sign-in row never marked;
the check failed, restored with cp, cmp clean.)

## Installer licence texts (`tests/test-licence-texts.sh`)

```sh
cd port
bash tests/test-licence-texts.sh
```

Runs the licence step of each installer build (`build_installer.sh`
for NSIS, `linux/build_installer_linux.sh`) into a scratch directory
and checks the `LICENSE.txt` it stages: no claim of GPL 3, the About
window's licence summary sentence for sentence (read from
`fs-aboutdialog.c`), then `COPYING` and `LICENSE` in full.  The NSIS
licence page shows that file.  (Re-injected: the GPL 3 paragraph put
back; the Linux step without the licence texts.)

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


## No tray, and words the app does not take (`tests/test-notray.sh`)

```sh
cd port
ninja -C build-linux StockFW fs-prefs-fake-smoke
bash tests/test-notray.sh   # broadwayd (libgtk-3-bin) for the desktop part
```

Drives the real `StockFW` binary, with the same scratch directories,
private instance name and (as root) private network namespace as
`test-instance.sh`.

First, `StockFW dashboard` -- a command meant for the command-line tool
`stockfw` -- must exit 2 at once with a message naming
`sudo /usr/local/bin/stockfw dashboard` and `sudo ./cli/stockfw
dashboard`, and never reach GApplication, whose only answer was "This
application can not open files".  It is checked with no display and
again with one.  While a stand-in listener (python3) holds the instance
name, nothing may connect to it: a binary that went for the name before
refusing the word would (looking for the name after the process exits
proves nothing, an abstract socket being gone by then).  A word after
an option is refused the same way, and `--version` alone still works.

Then, on a Broadway display (a GDK backend that is not X11, the same
case as Wayland, GNOME, KDE Plasma and WSL's WSLg), a `--background`
start with "Show a tray icon" on must make no tray icon, show its window
instead of hiding it, still run the slow re-read of the firewall's state
(`STOCKFW_TRAY_REFRESH_S=1`; it used to start with the icon), print no
Gtk-CRITICAL or warning (`G_DEBUG=fatal-criticals` makes a critical a
crash), refuse `StockFW dashboard` with exit 2 while it runs rather than
hand it over, and quit cleanly with `--quit`.  Last, `fs-prefs-fake-smoke`
runs on Broadway, where its tray check wants both tray switches greyed
with the reason shown.

The Broadway display binds HTTP to 127.0.0.1 and counts as up only once
broadwayd's own (abstract) socket is listening and broadwayd still runs:
it prints "Listening on" before binding its HTTP port and exits when the
port is taken, so the next display number is tried.

The desktop part SKIPs without broadwayd; `STOCKFW_NOTRAY_REQUIRE=1`
(set in CI) makes that a failure.  Teeth: against the 1.0.7 binary the
test fails 16 checks (the stray word reaches GApplication or a
running copy; the tray icon's Gtk-CRITICAL kills the background start;
Preferences offers the switches).


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

With Keep event history on, the test also reads which processes hold
the history folder's writer lock (`/proc/*/fd`): the first copy does;
after a second launch hands over, still only the first copy (the
handoff never opens the history); a hidden `--background` copy has it
open and a second `--minimized` launch does not; after `--quit` no
process holds it.

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
showing the truth; Preferences, Help and About open; Quit (firewall stays
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

Help (1.0.7, with the Help window): the menu has Help between
Preferences and About; with the main window hidden it opens the Help
window at "Running in the background" and leaves the main window
hidden.  About is no longer modal, so the About check waits (up to two
seconds) for the dialog answerer to see "[About StockFW]" instead of
expecting it before the click returns.  `fs-tray-smoke` counts sixteen
rows.  (Re-injected: Help opening Getting started, which fails "Help
opens the Help window at Running in the background"; the Help row left
out, which fails both Help checks.  Each restored with cp, cmp
clean.)


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
- `history`: started as `--background` starts it (window hidden) with
  Keep event history on.  A burst of 4,000 events fed through the
  app's monitor callback is all in the Events list and, within a
  second, all in the history file, the window still hidden; a second
  writer on the folder is refused while the app runs; a skip count from
  the backend (`log_skipped`) shows beside the count as "(up to 1,234
  skipped)" with a tooltip; ten events fed right before `fs_app_quit()`
  are in the file after the run, and the folder's lock is free again.
- `background` (`STOCKFW_AUTOSAVE_S=1`; the DNS server and gateway
  fixed through `STOCKFW_RESOLV_CONF` and `STOCKFW_ROUTE_FILE`): the
  window is hidden as "Minimize to the tray" hides it (directly, since
  xvfb has no notification area for the icon to embed in), and then
  the Copilot must keep working.  A Sentinel block restored with 12
  seconds of its ten minutes left is in the policy once the window is
  hidden (a precondition: 12 s covers the start-up, which took over
  3 s on the Windows runner; with too little left the boot restore
  already takes it out as "expired while StockFW was not running" and
  the timer under test never runs), is lifted from the policy and the
  staged list by the expiry timer (waited for up to 4 s past its due
  time, and not before it), and audited "expired after 10 minutes";
  seven timed contacts fed into the app's Copilot and the
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
"promptly" fail.  For `history`: no `fs_hitview_shutdown()` in
`on_shutdown` fails "the quit let the folder go"; without it and
without the flush in `save_state(TRUE)` "written on the way out"
fails (4,000 lines, not 4,010); no `flock()` fails "no second
writer"; no skip text fails "skipped show beside the count".

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

## Threat-intel engine (`fs-intel-test`)

```sh
cd port
ninja -C build-linux fs-intel-test && ./build-linux/fs-intel-test
# Sanitizers: a separate Debug build with -fsanitize=address,undefined.
# ASan's strstr interceptor makes g_strsplit quadratic on the 160,000-
# line lists, so turn that one interceptor off:
ASAN_OPTIONS=detect_leaks=1:intercept_strstr=0 ./build-asan/fs-intel-test
```

`src/core/fs-intel.c` (design section 6) driven through a fake backend
and a fake downloader (`fs_intel_set_fetcher`).  The fake backend plays
the kernel: it records the rule set `intel_apply` received (digest and
every set's text) and can commit and return TRUE, fail and change
nothing, commit and then "time out" (return FALSE), claim success and
change nothing, or make `intel_live` read UNKNOWN.  No network, no nft;
root is not needed (two store checks that chown a directory run only as
root and say SKIP otherwise).  Each test gets a fresh store under a
base directory whose every parent passes the store's own ownership
check: `$STOCKFW_TEST_SAFE_DIR`, else `$HOME`, else the directory of
the test binary; when none passes, the engine tests print SKIP.
`$STOCKFW_AUDIT_FILE` points the audit at that base, and the checks
read it back.

What it proves:

- **Store directory** [S2]: a safe override is created 0700; refused
  (FS_INTEL_ERR_UNSAFE_DIR): a relative path, a directory under `/tmp`
  (and nothing is created there), a directory writable by others or by
  its group, a 0700 store inside a 0777 parent, the store itself a
  symlink, and as root a directory owned by another user or a root store
  inside a user's directory (`sudo -E`).  A symlinked parent is followed
  and its target chain is what is checked.  Not root and no override:
  NEEDS_ROOT.
- **intel.conf**: a missing file is the defaults (every catalog feed in
  catalog order, off, its default direction, terms not accepted); the
  golden layout (`[feed <id>]`, `[list <id>]`, `[exceptions]`), 0600,
  and a full round trip including a custom feed, a list name with `;`,
  quotes and brackets, exceptions of both families and a proxy.  Unknown
  keys, groups and feeds are ignored; each invalid value fails naming
  `[group] key`: a bad direction, `enabled=yes`, a negative time, a time
  with junk, a custom feed over http://, an unknown format, no name, an
  id nft must never see (`Bad;Id`), a list name with a line break, a
  list id without `local-`, a proxy with a password (it would be in
  curl's argv), a socks proxy, an exception that is a host name, a
  broken group line, bytes that are not UTF-8.  Hostile files: over
  1 MiB, a symlink, a FIFO (refused without waiting), a stray temporary
  from a crashed save (never read; saving next to it works).
- **Consent** [S14]: enabling without accepting the terms changes
  nothing (CONSENT), and `set_enabled` is no way around it; accepting
  records when.  Custom feeds: http:// and `user@` refused, the slug id,
  typed URL = consent, the same slug twice refused; catalog feeds cannot
  be removed.  The consent text names the host, how often ("every 6
  hours", "once a day"), what the host learns ("StockFW/<version>", the
  public address), the licence or "see the provider's terms" with the
  terms URL, the non-commercial warning (FireHOL level 1, DShield) and
  how to make an exception.
- **No network unless consented**: the default configuration makes no
  request; every feed enabled without accepted terms gives
  NEEDS_CONSENT and no request; the master switch off fetches nothing;
  a URL the design's rule refuses (`fs_feed_url_is_acceptable`, stricter
  than fs-fetch's own check) is never fetched; a custom feed goes
  through the configured proxy; local lists and feeds that are off are
  never fetched.
- **Updates, guards and scheduling** (injected clock): first download
  stored (0600, state recorded); 5 h later not due; due exactly one
  interval after the last attempt; a clock that went back makes it due
  at once; same bytes are UNCHANGED; `--now`; stale after 7 intervals
  from the download, or from the content date when the list has one.
  A shrink (10 to 1), an empty list, an HTML page and a failed download
  are refused/failed and keep the previous list byte for byte (with
  `refused` / `last_error` recorded, the tool's first line only);
  `--accept-shrink` lets the shrink in.  A content date a year ahead is
  refused even with `--accept-shrink` (it would make every honest copy
  after it a ROLLBACK); an hour of skew is not "the future"; an older
  content date is ROLLBACK; a stored content date in 2033 (clock put
  back, or an edited state) is forgotten rather than refusing every
  copy forever.  One audit line per attempted download, `|` escaped,
  a forged second line never written.
- **Per-feed isolation and crashes**: three feeds, three results in
  config order; one failing, one garbage and one good side by side, the
  first two keeping their lists.  A crash between writing the list and
  its state (the old state put back over the new list): fetching the
  old bytes again stores them again instead of reporting "unchanged"
  over a list that is not theirs.  A damaged state is rebuilt with a
  fresh history; a state with an out-of-range number is not trusted; a
  stray temporary list is never loaded.  An id that is a path (a
  hand-filled struct) neither writes nor deletes anything outside the
  store.
- **Stored lists** [S2.7, S4.4]: missing is STORE; tampered is TAMPERED:
  a line that is not an entry, junk after an entry, 0.0.0.0/0, ::/0,
  2000::/3, a /6, a NUL byte, 200,300 intervals; a symlink is refused.
  What the parser let in loads again (eight adjacent /10s stored as one
  /7, at the coverage cap exactly), and protected space in a stored
  list is taken out, never blocked.  The parser's per-entry span floor
  is not re-applied on load: a stored list is normalized, so adjacent
  accepted entries merge into wider intervals; the coverage caps bound
  what a tampered list can block.  Import: a CSV becomes
  `local-<slug>`, enabled, in its direction, protected space left out;
  the same name again replaces it; a file with no address, too-broad
  entries, a FIFO and a directory are refused; removing a list deletes
  its files.
- **Build (golden)**: one exact rule set with the own address, on-link
  network, gateway, resolver, SSH session, a feed's server and two
  exceptions subtracted, IPv4 of out/both sets mapped into
  64:ff9b::/96 (and an exception written in its NAT64 form honoured), a
  list never downloaded left out with a note; a note per kind of address
  kept, naming the list that had it; host NULL subtracts only
  exceptions; master off is the empty rule set; FireHOL level 1 with
  Feodo on gets the "already contains" note; a tampered list fails the
  build.  Limits: 2 x 160,000 intervals is TOO_BIG naming both sets;
  160,000 outbound intervals plus their NAT64 copies is TOO_BIG; 2^26
  IPv4 addresses build, one /10 more is TOO_BIG naming the largest.
- **Gate, lifecycle, state** [S10, N8, P4]: a hold is DRY_RUN with
  nothing reaching the backend; a backend without intel slots is FAILED
  "not available" and its state "unsupported"; the backend gets exactly
  the built rule set; applied.state records digest, sets, not
  suspended; `fs_intel_applied_has` answers for applied sets only.
  A failed apply keeps applied.state and does not carry the counters
  (the old table still counts them: 5, not 10); nft timing out after it
  committed is OK because the live digest is the new one, and the
  counters are carried once (5 + 2 live = 7); a backend that claims
  success while the kernel holds the old table is FAILED and carries
  nothing; an error with an unreadable kernel is FAILED, a success with
  an unreadable kernel stands.  State: not-loaded before the first
  apply and after a flush, enforced (naming the lists), differs for
  another digest or none, unknown (needs-root when not root) for an
  unreadable listing, never not-loaded; suspend removes the table,
  carries the counters and reads "suspended" (and "differs" when a
  table comes back); resume under a hold applies nothing, resume applies
  again; a suspend whose tool fails is FALSE while the table is there
  and fine when it is gone; lists off with the table still loaded is
  "differs", not "off"; the empty rule set is expected ABSENT (also
  after a timeout).  One audit line per attempt (13), tool output
  escaped and cut to its first line.
- **Hostile gate**: a tampered list never reaches the backend and the
  old table stays enforced; a corrupt intel.conf makes the state
  "unknown" naming the key and resume applies nothing; a damaged or
  empty applied.state is never "enforced" on its word and attributes no
  log line, and a re-apply heals it; an unsafe store applies nothing.
- **Lookup** (26 addresses, each also compared with the built rule
  set): CIDR edges (first, last, one before, one after) for IPv4 and an
  IPv6 /48, upper-case IPv6, IPv4-mapped IPv6, the union of directions,
  NAT64 addresses for an out list (and not for an in list), protected
  space including the NAT64 form of an RFC 1918 address, exceptions,
  kept host addresses; refused as not single addresses: a CIDR, a
  range, a zone, a leading blank, a name, empty, `/128`.  The sentence
  names the lists; NULL for an excepted address; host NULL keeps
  nothing; master off lists nothing.

Not checked here: the real kernel (`intel_apply` and the other slots
are the Linux backend's, tested by `tests/test-intelset.sh`), real
downloads (`tests/test-fetch.sh`), and `fs_hostnet_read` on a live
system (`fs-hostnet-test`).  A custom feed URL may carry a key in its
query string; while curl runs that key is visible in
`/proc/<pid>/cmdline` to local users (intel.conf refuses proxy
passwords for the same reason).

Teeth, each re-injected into a copy of `src/core/fs-intel.c` (the old
text asserted to occur once), seen failing, restored with `cp` and
checked with `cmp`:

| bug re-injected | checks that caught it |
|---|---|
| update fetches without accepted terms | "enabled without accepted terms: NEEDS_CONSENT, no request" (9 calls), "master switch off: not fetched" |
| no URL rule before the download | "a URL the design's rule refuses is never fetched" |
| `set_enabled` turns a feed on without consent | "set_enabled is no way around the consent" |
| the master switch ignored by updates | "master switch off: not fetched" |
| the master switch ignored by the build | "master switch off: empty rule set", "master switch off: nothing is listed" |
| a future content date accepted | "a content date a year ahead: REFUSED" |
| a stored future date never forgotten | "a stored content date in 2033 does not refuse an honest copy forever" (ROLLBACK) |
| the shrink guard overridden | "10 -> 1 entries", "an empty list after 10 entries", "an older content date than ours", the list-kept checks |
| a refused copy written over the list anyway | "a refused copy keeps the previous list", "after all of them the 10-entry list is still the one stored" |
| "unchanged" without checking the list matches its state | "crash between list and state ...", "and the list on disk is the copy the state describes" |
| a clock that went back waits for itself | "the clock went back: due again" |
| tool output kept whole | "a failed download: ... the tool's first line only", the audit checks |
| audit details not escaped | "audit: '\|' escaped ...", "one intel-apply line per attempt" |
| a proxy with a password accepted | "intel.conf: a proxy with a password ... fails" |
| store files followed through symlinks | "intel.conf as a symlink is refused" (it read /etc/passwd), "a list that is a symlink is refused" |
| store files opened blocking | the run hangs at "intel.conf as a FIFO" (killed by a 60 s timeout) |
| a store name may be a path | "an id that is a path: remove deletes nothing outside the store" (then a crash) |
| a group-writable store accepted | "a directory writable by its group (0720) is refused" |
| the store itself may be a symlink (stat for lstat) | "a symbolic link as the store itself is refused" |
| parents of the store not checked | "/tmp", "and nothing was created there", "0700 store inside a 0777 parent", "a root-owned store inside a user's directory" |
| no coverage caps on a stored list | the 0.0.0.0/0, ::/0, 2000::/3 and /6 tampered checks, "a tampered stored list: the build fails", "the backend is never called" |
| what the host needs not subtracted | the build golden, and 10 gate checks downstream |
| exceptions not subtracted | the build golden, and 8 gate checks downstream |
| no NAT64 mapping for outbound sets | the build golden, "160,000 outbound intervals + their NAT64 copies", "lookup 64:ff9b::2d00:1 agrees with the built rule set" |
| no interval limit | "320,000 intervals: TOO_BIG", "160,000 outbound ... TOO_BIG" |
| no IPv4 union limit | "one /10 more: over 2^26 IPv4 addresses" |
| the hold ignored | "hold: DRY_RUN, nothing reaches the backend", "resume under a hold", the audit count |
| the error trusted over the live digest (nft timed out after committing) | "a timeout after nft committed: OK", "... and the state is enforced", the counter checks, "empty rule set, a timeout, the table absent: OK" |
| the backend's success trusted over the live digest | "the backend reports success but the kernel holds the old table: FAILED", "... and nothing is carried" |
| counters carried before the apply is known to have happened | "a failed apply: ... counters not carried", "counters after the failed apply: still 5, not 10", four more |
| counters never carried on apply | "a timeout after nft committed ... counters carried once", "carried 5 + live 2 = 7" |
| the empty rule set expected as a present table | "apply with nothing on: ... expected ABSENT, OK", "empty rule set, a timeout ..." |
| suspended ignored by the state | "state: suspended", "resume under a hold: ... still suspended", "the tool complains but the table is gone: suspended" |
| an unreadable listing read as absent | "state: an unreadable listing is unknown, never not-loaded" |
| `fs_intel_applied_has` ignores suspended | "applied_has: nothing while suspended" |
| lookup ignores the NAT64 form | "lookup 64:ff9b::2d00:1", "... agrees with the built rule set" |

The run is also clean under AddressSanitizer and UBSan (LeakSanitizer
on), and passes as root and as an ordinary user.
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
14.5 (the 1.0.7 rework, the health check and the page).  That the
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
rebuilt, stays open, and gets the focus back on the same button.  "The
same row" and "a new row" are told by a tag set on the old row and its
`destroy` signal, never by comparing pointers: the row built in place
of a destroyed one can get its memory, and so its address.  The
Windows heap does this now and then, which made a real rebuild read as
"not rebuilt" on Windows CI; on Linux, preloading an allocator that
hands back the block just freed (any `LD_PRELOAD` shim that reuses
same-size frees first) shows the old pointer check failing and the tag
check passing.  A
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
`NOT_FOUND` (no nft), `TIMED_OUT`, `INVALID_ARGUMENT`, `FAILED`.  A
backend that leaves the slots NULL is how the engine knows to say
"unsupported" rather than "cannot tell".  Since Round 3 the Windows
backend fills intel_apply, intel_clear, intel_live and
intel_not_in_force; it leaves intel_counters NULL, because Windows
Firewall keeps no count per rule (see "Threat intel on Windows"
below).

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

## Threat intel end to end on Linux (`tests/test-intel-e2e.sh`)

```sh
cd port
ninja -C build-linux fs-intel-e2e-driver
sudo bash tests/test-intel-e2e.sh   # needs root, nft, curl, openssl, python3; SKIPs otherwise
```

The engine (`fs-intel.c`) and the Linux slots (`fs-backend-linux.c`)
were each tested against stand-ins: the engine through a fake backend
and a fake downloader, the slots through a driver that builds rule sets
by hand.  This test runs them together with nothing replaced.
`fs-intel-e2e-driver` calls the engine the way a `stockfw intel` command
would: `fs_intel_config_load`/`save`, `fs_intel_import_list`,
`fs_intel_update` with the default downloader (`fs_fetch`, curl as
nobody, 120 s), `fs_intel_apply_safe` with host NULL (so the engine
reads this computer with `fs_hostnet_read()`), `fs_intel_suspend`,
`fs_intel_resume`, `fs_intel_state`, `fs_intel_counters`,
`fs_intel_lookup` and `fs_intel_applied_has`, all with `fs_backend()`.
Its copy of `fs-fetch.c` is compiled with `FS_FETCH_TESTING` only so
`$STOCKFW_TEST_CACERT` can name the test server's CA (the
`fs-fetch-test` arrangement); its copy of the backend has no test hook.

The test re-executes itself under `unshare -n -m`.  In there, a tmpfs
over `/var/lib` holds the default store (`/var/lib/stockfw/intel`,
created by the engine), a `resolv.conf` bound over `/etc/resolv.conf`
names the DNS server, and a veth pair joins this computer
(192.0.2.1/24, default gateway 192.0.2.2) to a peer namespace that
plays the internet: the HTTPS feed server at 203.0.113.80 (a throwaway
CA), the DNS server 203.0.113.53, the SSH client in `$SSH_CONNECTION`
(198.51.100.22), an established connection to this computer's port 22
from 198.51.100.33, and the listed and unlisted addresses.  The feed
(custom, both directions) lists all of those plus this computer's own
/24; a local CSV list (outbound only) holds 198.51.100.128/26 and
203.0.113.128/25.  Packets are UDP datagrams with receivers on both
sides; a send the kernel refuses (the outbound reject) is counted by the
sender.  It proves:

- with nothing turned on: state off, no table, and an update makes no
  request at all; the store is created 0700 under a 0755 parent, and
  `intel.conf` and every list are 0600;
- the feed is downloaded by the default downloader as
  `StockFW/<version>`, with its entries and content date recorded;
- one apply builds both sets and loads them in one nft transaction,
  the table carries the digest, the state is enforced, and a note names
  each kind of address kept: this computer's own, its network, the
  gateway, the DNS server, both SSH peers, the feed's server; the
  kernel's set holds the listed address and none of the kept ones, and
  the outbound entries are also in 64:ff9b::/96 (rule text only);
- real packets: in from a listed address, dropped; in from an address
  only the outbound list holds, delivered; in from every kept address,
  delivered; out to a listed address, refused at once; out to unlisted
  and kept addresses, delivered; the counters are exactly the packets
  the lists stopped (12 and 4), and `fs_intel_lookup` agrees with every
  packet, the NAT64 form included;
- the next update reaches the feed's server although the enforced list
  names it in both directions;
- an update with a changed list: the address it dropped passes, the one
  it added is dropped, and the counters carry across the replace;
- bad copies change nothing in the store or the kernel: an HTML page,
  an HTTP 503, the older copy replayed (rollback), a copy that shrank
  from 16 entries to 2, and one dated a year ahead; an apply afterwards
  enforces the last good copy with the same digest;
- a transaction the kernel rejects fails naming the lists in force; the
  previous table and its digest stay, the state still reads enforced,
  the counters are not carried, and the change (an exception) is not in
  force; with the real nft the exception lets its address through and
  is noted, and the counters come out counted once; removing it gives
  the previous digest again;
- a stored list tampered with on disk (`0.0.0.0/0`) is refused before
  any nft load, the kernel keeps the last good list, and the next update
  stores the good copy again although the download is byte for byte the
  one already recorded;
- a hold reaches no nft (dry-run);
- a table someone removed reads not-loaded (and the address really
  passes), one someone else loaded reads differs, and an apply repairs
  both;
- user Stop and Start: suspend removes the table, the state reads
  suspended, the log parser would accept no list line, the count
  survives and the addresses pass; resume brings back the same digest
  and the count goes on;
- the master switch off: the apply removes the table, the state reads
  off, nothing is blocked (and the lookup says so), an update makes no
  request, and the carried counts stay;
- one audit line per apply attempt (held and failed ones included), per
  suspend, per feed update attempt and per import.

The sanitizer build (`build-asan`, `-fsanitize=address,undefined`,
Debug, LeakSanitizer on) of `fs-intel-e2e-driver` runs the whole test
clean (`STOCKFW_INTEL_E2E_DRIVER` points the test at it).

Not covered here: IPv6 packets (none are sent; the IPv6 sets are
checked as rule text), `STOCKFW-TI` kernel log lines (nft's log
statement is silent in a network namespace by default), catalog feeds
and their real hosts (no internet; a custom feed stands in, and its
host is an address, so no DNS lookup is made for it), and Windows.

Teeth, each injected into the real source by a script that asserts the
exact old text once; the driver was rebuilt, the named checks seen
failing, the file restored with `cp` and checked with `cmp`, and the
test seen green again:

| Bug re-injected | Checks that failed |
|---|---|
| a custom feed's host not kept reachable | `the next update reaches the feed's server although the enforced list names it`, `in from the feed's server`, its note, the kernel-set and NAT64 checks (31 in all) |
| established connections to port 22 not read | `in from the peer of the established SSH connection`, its note, the kernel-set check, the lookup, the counters |
| the DNS servers not read | `in from the DNS server`, `out to the DNS server`, its note, the kernel-set check, the lookup, the counters |
| exceptions not subtracted | `with the real nft the exception is applied and noted`, `the exception lets 198.51.100.10 through` |
| no NAT64 mapping for outbound lists | `IPv6 (rule text): outbound entries are also blocked in 64:ff9b::/96`, the interval count (v6=0) |
| an outbound list also matched inbound | `in from an address only the outbound list holds`, and the counters |
| counters carried when the apply failed | `the counters are not carried by a failed apply`, `... counted once` (21, not 20) |
| the backend skips a re-apply of the digest already live | `... counted once` (24, not 20: the engine carried counts the kernel kept) |
| suspend leaves the table | `Stop: suspend removes the table`, `state: suspended`, `while suspended the listed addresses really pass` |
| suspend does not carry the counters | `the count survives the suspend`, `the count goes on from where it was` (23 -> 22) |
| "unchanged" without checking the stored list against its state | `the next update stores the good copy again`, and every apply after it (the tampered list stays) |
| no rollback guard | `the older copy replayed (a rollback)`, and the checks that need the newer copy |
| the hold ignored | `a hold reaches no nft`, the audit count of held attempts |

## Threat intel, second review (`fs-intel-test`, `tests/test-intel-backend.sh`, `tests/test-intel-e2e.sh`)

What the second review of the engine found, and the checks that now
hold each answer.

`fs-intel-test` (fake backend, fake downloader):

- **coverage counted as the parser counts it**: `test_cover6_at_cap`
  builds a feed of 128 IPv6 ranges that are not /64-aligned and cover
  exactly the cap (2^42 /64 networks). The parser accepts it, the update
  stores it, the stored copy loads again (not TAMPERED) and builds;
  one more /64 is refused by the parser, and a stored copy holding it is
  TAMPERED. Both now use `fs_feed_cover6_64`.
- **the proxy kept reachable** (`test_update_hosts`):
  `fs_intel_update_hosts` lists each enabled feed's host (an upper-case
  `HTTPS://` custom feed too), then the proxy's host while any feed is
  on (IPv4, bracketed IPv6 with a port, a name already listed in
  another case listed once); an apply with host NULL keeps a proxy and
  a feed server that a list names, their NAT64 forms too, and says so
  in a note ("a feed's download server or proxy"); with no feed on, the
  proxy is not kept.
- **a re-apply of the same digest that the tool fails**
  (`test_gate_same_digest`): FAILED with the tool's error and the note
  "The same rules were already in force, and still are.", nothing
  carried (the counters read 5, not 10), still enforced, audited as
  failed; committed then timed out: OK, carried once; the backend says
  yes and changes nothing: OK, nothing carried (6, not 7); a real
  replace: carried; nothing counted and refused: FAILED; another rule
  set refused: FAILED without the same-rules note.
- **Stop and Start** (`test_gate_start_stop`): a Start whose apply
  fails, or whose build is refused (TAMPERED), reads not-loaded, never
  suspended; a Stop with no table clears nothing; Start without intel
  slots is a no-op; without nft (fake `G_IO_ERROR_NOT_FOUND`) a Stop
  where nothing was ever applied is not an error and the state reads
  off, while after a load the Stop fails NOT_FOUND and the state is
  unknown or needs-root, never off, even with the list turned off; with
  no store directory at all, Stop and Start create nothing, and a table
  found anyway is still removed.
- **flushed chains** (`test_state_rules`): `applied.state` records in
  `ruled` the lists whose sets have addresses (not one an exception
  emptied); one list's counter rules gone reads differs naming that
  list only; all gone (`nft flush table`) reads differs naming both;
  chains that cannot be listed, or a record from before `ruled`, leave
  the digest to decide (enforced); an apply restores them.
- **a list name that collides with another list's id** (in
  `test_stored_lists`): "office-blocks", "Office: blocks!" and
  "OFFICE_BLOCKS" are refused (INVALID, naming the list that has the
  id) while "office  BLOCKS" stays untouched; the same name in another
  case or spacing replaces it.
- **values GKeyFile cannot decode** (in `test_config`): a bad escape in
  the proxy, the exceptions, a custom feed's name or a list's name
  fails the load naming the group and key; the same file without it
  loads.
- **a store others can read** (in `test_store_dir`): an existing store
  of mode 0755, 0750, 0711 or 0705 is set to 0700, by `fs_intel_dir`
  and by every store operation.

`tests/test-intel-backend.sh` (real nft, private namespace):

- the same rule set loaded under the wrapper that makes the kernel
  refuse every load with elements: the slot fails, naming nft's error
  and "The same blocklists (fingerprint ...) were already loaded and
  are still in force"; the table was not replaced (its counters still
  run);
- `policy-reload` (the driver's new command: the backend's `reload`)
  joins apply, stop and clear: the table and its counters are untouched.

`tests/test-intel-e2e.sh` (everything real):

- the same rule set refused by the kernel: `result failed`, the
  same-rules note, the backend's error, the table, the state, the
  counters and the carried totals as they were;
- `nft flush table inet stockfw_intel`: differs, naming both lists, and
  the address really passes; an apply restores the rules;
- `stockfw stop` and `stockfw start` (the CLI, with iptables in the
  namespace and its own `XDG_CONFIG_HOME`): stop removes the table and
  the state reads suspended; start enforces the same digest again and
  prints "Blocklists applied (2 lists)."; `--json` adds an `intel`
  object (`result` suspended / applied); the audit records them as
  `source=cli`. Skipped when the CLI is not built or iptables is
  missing;
- without nft (an empty `PATH`): after a load, a Stop fails saying nft
  is missing and the state reads unknown; in a store where nothing was
  ever loaded a Stop is not an error and the state reads off; with no
  store at all a Stop creates none;
- the driver's lookup now keeps the hosts `fs_intel_update_hosts`
  gives, not a copy of that logic.

Not covered: the Status page's Stop and Start and start-on-open call
the same engine functions in a worker thread; they are built, not run
here (no GUI test drives them). The `stockfw intel` commands, the
Threat Intel page and Events attribution do not exist yet (design
section 9).

Teeth, each injected into the real source by
`teeth.py` in a scratch directory, which asserts the exact old text
occurs once, rebuilds, runs the test, looks for the named checks among
the failures, then restores the file with `cp` and checks it with
`cmp`:

| Bug re-injected | Checks that failed |
|---|---|
| the stored-list check counts IPv6 coverage as `end.hi - start.hi + 1` (the old count) | `cover6 cap: the stored copy loads again, not TAMPERED`, `cover6 cap: the build holds it and the healthy list` |
| the proxy left out of `fs_intel_update_hosts` | `update hosts: each enabled feed's host ... then the proxy's`, `update hosts: an IPv6 proxy ...`, `apply: a list naming the proxy and a feed's server keeps both reachable ...`, `... and a note says so` |
| resume leaves `suspended` in applied.state | `resume under a hold: ... never suspended`, `start, the apply fails: FAILED, then not-loaded, never suspended`, `start, the build refused: TAMPERED, then not-loaded` |
| the state never checks the counter rules | `rules: one list's rules gone: differs, naming it`, `rules: the chains flushed: differs, never enforced` |
| a same-digest re-apply the tool failed reported OK | `same digest, nft refuses: FAILED ...`, `... and the audit records the failure`, `same digest, nothing counted, nft refuses: FAILED` |
| counters carried without proof the table was replaced | `same digest, the table untouched: OK, nothing carried (6, not 7)`, `same digest, replaced: carried once` |
| the Linux backend calls an identical table after a refusal a success | `the same rule set refused: a failure that says the same lists are still in force` (test-intel-backend.sh) |
| without nft, a Stop with nothing to remove is an error | `no nft, nothing ever applied: stop is not an error` |
| without nft, the state reads unknown with nothing on | `no nft, nothing on: off, not unknown` |
| a colliding import name replaces the other list | the three `import: "..." (the same slug, another name) is refused ...`, `import: two long names cut to the same id ...` |
| undecodable intel.conf values read as absent | `intel.conf: a proxy with an invalid escape (\q) fails, naming [intel] proxy` |
| an existing 0755 store accepted as it is | the four `store: an existing 0NNN store is set to 0700`, `store: saving the configuration into a 0755 store leaves it 0700` |
| Stop creates a store where none was | `no store: stop and start do nothing, create nothing`, `no store, a table left behind: ...` |
| the policy reload clears the intel table | `the lists and their counters are untouched by all of it`, and every later check that needs the table (test-intel-backend.sh) |
| `stockfw stop` does not suspend the lists | `stockfw stop: the firewall stops, the lists are removed and suspended`, `stockfw --json stop: ...`, `the command line's stops and starts are audited as source=cli` (test-intel-e2e.sh) |
| the old note wording ("a feed's download server") | `notes: every kind of address kept, and the list that named it`, `... and a note says so` |

The sanitizer build (`build-asan`, Debug, `-fsanitize=address,undefined`)
runs `fs-intel-test` clean.

## The location database reader (`fs-geodb-test`, `tests/test-geodb.sh`)

```sh
cd port
ninja -C build-linux fs-geodb-test
./build-linux/fs-geodb-test tests/geodb      # the suite (also run by tests/test-core.sh)
bash tests/test-geodb.sh                     # libloc, IPFire's file, xz, curl, libFuzzer
STOCKFW_GEODB_REQUIRE=1 FUZZ_SECONDS=300 bash tests/test-geodb.sh   # CI: no SKIP allowed
bash tests/test-geodb.sh --regen             # rewrite tests/geodb with new test keys
```

`src/core/fs-geodb.c` reads IPFire's location database (1.0.7 design,
section 12).  `fs-geodb-test` is built from it with `FS_GEODB_TESTING`,
the only build that can verify with a test key
(`fs_geodb_testing_set_key`) or check a buffer without its signature
(`fs_geodb_testing_open_unverified`, for the mutation loop and the
fuzzer).  `tests/test-geodb.sh` proves that the release objects
(fs-core, fs-core-nogui) define neither.

The fixtures in `tests/geodb` are written by libloc's own writer
(`tests/geodb-fixtures.py`, python3-location, with
`tests/geodb-faketime.c` to fix the creation time), signed with two
P-521 test keys whose private halves were thrown away (`k1.pub`,
`k2.pub`).  Next to each `.db` are the answers libloc's reader gives
(`.lookup.tsv`, `.enum.txt`, `.meta.txt`).  The malformed files are
made by the suite from those fixtures and re-signed with a key made at
run time, so that each one gets past the signature and reaches the
structural check it is aimed at.  The shell test regenerates every
fixture with fresh keys and checks that the committed ones are what
the generator writes.

Needs: liblzma and libcrypto (both linked); for the shell test
python3-location and `location`, libloc-database (IPFire's file of
2022-10-29), xz, openssl, and clang with libFuzzer (libclang-rt-dev).
Each part SKIPs without its tool, unless `STOCKFW_GEODB_REQUIRE=1`.
No case uses the network: the download goes to a stand-in for curl
(`STOCKFW_TEST_CURL`, honoured only by the `FS_FETCH_TESTING` build).

| Area | What it pins down |
|---|---|
| golden | every lookup and every enumeration of the generated databases (IPv4 and IPv6, nested networks, adjacent halves, a /32 and a /128, the last address of each family, flags, unnamed ASes, AS 2^31-1, an IPv6 `::/8` and `::/0` covering the IPv4 subtree, an empty database, 300 random networks) is libloc's answer; enumeration agrees with lookup address by address |
| IPFire's file | the 2022-10-29 copy verifies with the pinned key (slot 2 only) and agrees with libloc on 8,000 lookups and 12 flattened searches; `location lookup` agrees on 8.8.8.8, 1.1.1.1, 2a00:1450::1 and 2606:4700::1 |
| signature | either slot; a wrong key, a key made now, a P-256 key; a bit flipped in the magic, every header field, each signature field and the body; appended and cut bytes; the zeroing rule (lengths and full slots zeroed, the 32 reserved bytes signed); no usable slot is "not signed"; libloc's `location verify` accepts what the test signer signs and refuses it with another key or one byte changed |
| malformed | truncation at 484 places; every section offset and length pushed outside the file, onto the header or onto another section; offsets and lengths near 2^32; trie loops and shared subtrees; children and networks out of range; chains 128 deep (fine), 129 and 4,000 deep (refused); strings at the 4,096-byte limit, one past it, and unterminated; unsorted and duplicate tables; bad codes; creation time 0 and 2^63; all FORMAT, never a crash |
| enumeration edge | `::/8` in a database with no IPv4 subtree: the IPv6 set is `::/8` without `::ffff:0:0/96`, and the IPv4 set is empty |
| mutation and fuzzing | a deterministic mutation loop (seed 1077, 4,000 cases by default, `STOCKFW_GEODB_MUTATIONS` to change it; 1,000 in the shell test on fresh fixtures) where whatever opens must give sane answers, and libFuzzer (`tests/fuzz-geodb.c`) with ASan and UBSan from every fixture; the suite itself runs clean under ASan and UBSan (4,000 mutations) |
| xz | round trip; `xz -9e`; a 64 MiB dictionary (fine) and a 128 MiB one (over the 96 MiB decoder limit); a 39 KB bomb that unpacks to 256 MiB + 1 (TOO_LARGE, never more than the cap written); exactly 256 MiB (fine); corrupt, cut, padded, concatenated and empty streams |
| freshness | `fs_geodb_judge`: newer, the same second, one second older, from 1970, a day and a second ahead (checked first), the end of time; staleness at 30 days |
| install | first copy, the same copy, a rollback by one second, a copy from the future, a non-database, a bomb, a download over 64 MB, a relative store, a store or copy in use that is a symbolic link, a damaged copy in use; after each, `location.db` is byte for byte as expected and nothing else is in the store |
| floor (review GEO-ROLLBACK-1) | with `min_created` at the newest copy accepted: the copy in use damaged or deleted, an older good copy is still a rollback; the copy accepted last repairs a missing or damaged copy and is then "unchanged"; a floor one second past the copy in use refuses it; with no floor (0) a damaged copy counts as none |
| stale temporary files (review GEO-TMP-LEAK-2) | `.location.db.<x>.tmp` files left by a killed install are removed by the next install; a symbolic link of that name, its target, another name and `.location.db..tmp` are not; a second install waits for the store's `flock`, then runs |
| download | `fs_geodb_update` with a fake downloader, and with the real `fs_fetch` and a curl stand-in: one request for `FS_GEODB_URL`, `--max-filesize 67108864`, no proxy unless given |

Teeth, each injected into the real `fs-geodb.c` by a scratch script
that checks the old text occurs once, rebuilds `fs-geodb-test`, runs
the suite, then restores the file with `cp` and proves it with `cmp`.
Every one made the suite fail:

| Bug re-injected | Checks that failed |
|---|---|
| open skips the signature step | 52, among them `small.db (libloc's writer, key 1) verifies with key 1, slot 1`, `the 2022-10-29 copy is signed in slot 2 only, and that is enough` |
| the 32 reserved bytes zeroed too | `zeroing: a bit flipped in reserved byte 0: SIGNATURE`, `... byte 31: SIGNATURE` |
| only the signature's own bytes zeroed, not the whole slot | `zeroing: bytes after the signature inside its slot are not signed`, `zeroing: garbage in slot 2 with a length of 137 does not stop slot 1` |
| the signature lengths not zeroed | 143, among them `IPFire's own database verifies with the pinned key and passes every check`, and every fixture fails to open |
| no usable slot accepted as unsigned | `both slots empty: SIGNATURE, "not signed"`, `both lengths past the slot: SIGNATURE` |
| only slot 1 tried | `small-two.db verifies with key 2 in slot 2`, `zeroing: slot 1 removed, slot 2 alone verifies`, IPFire's own file |
| any EC curve accepted as the key | `a file signed with a P-256 key, checked with that key: SIGNATURE, the key is not P-521` |
| sections may overlap | `the pool starting inside the countries: FORMAT` |
| sections may overlap the header | `the network section starts on the header's last byte`, `the pool section starts at 0 (the magic)`, `the pool section starts in the header` |
| a section's end computed in 32 bits (it wraps) | the suite dies with SIGSEGV right after `the AS section length 0xffffffff: FORMAT` |
| depth limit 129 | `a chain 129 nodes deep: FORMAT` |
| no visited set in the tree check | `a node whose two children are the same node (a shared branch): FORMAT`, the mutation loop |
| strings need no NUL | `the pool's last string without its NUL ...: FORMAT`, `a vendor of 4,097 bytes: FORMAT` |
| string limit off by one | `a vendor of 4,096 bytes: opens` |
| AS order unchecked | `two ASes swapped (not ascending): FORMAT`, `an AS number twice: FORMAT` |
| country order unchecked | `two countries swapped: FORMAT`, `a country code twice: FORMAT` |
| creation time unchecked | `created_at 0: FORMAT`, `created_at 2^63: FORMAT` |
| the same second judged older | `judge: the same second`, `install: the same copy again` |
| no rollback check | `judge: one second older`, `judge: from 1970`, `install: a copy one second older (rollback)` and 9 more |
| no future check | `judge: a day and a second ahead ...`, `judge: the end of time` and 2 more |
| the xz cap checked after the write | `xz: 39184 bytes that unpack to 256 MiB + 1: TOO_LARGE, ... never more than the cap`, `xz: a 1 MiB cap and 1 MiB + 1 of data` |
| no xz memory limit | `xz: a 128 MiB dictionary is over the decoder's memory limit (96 MiB): XZ` and one more |
| data after the xz stream accepted | `xz: data after the stream: XZ`, `xz: stream padding after the stream`, `xz: two streams back to back` |
| install does not judge | `install: the same copy again`, `install: a copy one second older (rollback)`, `install: a newer copy more than a day ahead of the clock` and 8 more |
| install renames before it verifies | 15, among them `install: a first copy`, `install: a copy one second older (rollback)` |
| install leaves the temporary file | 13 `install: ...` checks (`nothing else is left in the store`) |
| install ignores the floor (judges against the copy in use only) | `install: floor: the copy in use damaged, an older good copy is still a rollback` and 2 more; fs-intel-geo-test `rollback floor: ...` (4) |
| the copy accepted last cannot repair a damaged or missing copy | `install: floor: the copy accepted last (created at the floor) repairs a missing copy` and 4 more |
| no sweep of stale temporary files | `install: the temporary files of an install that was killed are removed` and 2 more |
| the sweep removes any file type | `install: the sweep removes nothing else (a symbolic link, another name, the target of the link)` |
| the sweep ignores the name prefix | the same check (found no check with a 9-byte name, so the other name is now longer than the pattern's minimum) |
| no lock around an install | `install: a second install waits for the store's lock, then runs` |
| no download size cap | `install: a download over 64 MB: REFUSED` |
| lookup keeps the least specific network | `8.8.8.8 is in 8.8.8.0/24, registered in US, AS15169 ...` and every golden lookup set |
| IPv4 looked up from the root of the trie | `edge6: ::/0 is an IPv6 network and never answers for an IPv4 address` and 3 more |
| enumeration not flattened (a nested network of another country counted) | `small.db: 22 enumerations ... are exactly libloc's flattened search, merged` and 6 more |
| IPv4-mapped space left in the IPv6 set | `::/8 and no IPv4 subtree: enumerate gives ::/8 without ::ffff:0:0/96, and no IPv4` (added after this tooth found no check) |
| control and format characters kept in names | `small: 192.0.2.77 -> ... (a BEL in the AS name is shown as ?)`, `... (a bidi override in the name is shown as ?)` and 5 more |
| symbolic links followed | `a symbolic link to a good database: IO, not followed` |
| the size cap exclusive | `exactly 256 MiB is read (and is no database: FORMAT)` |

## Country and network-owner rules (`fs-intel-geo-test`, `tests/test-intel-e2e.sh` section 12)

```sh
cd port
ninja -C build-linux fs-intel-geo-test
./build-linux/fs-intel-geo-test              # also run by tests/test-core.sh
ninja -C build-linux fs-intel-e2e-driver fs-intel-backend-driver fs-intelset-test
sudo bash tests/test-intel-e2e.sh            # section 12 is the location rules
sudo bash tests/test-intel-backend.sh
./build-linux/fs-intelset-test
STOCKFW_E2E_GEO_LARGE=100000 sudo bash tests/test-intel-e2e.sh   # a smaller "large country"
```

The engine half of round 2 (1.0.7 design, section 13): location rules
in `intel.conf`, the database's consent, download and state, the sets
built from it, their enforcement through the Linux slots, and the
lookup.  The tests write their own location databases with
`tests/geodb-writer.h` (a header-only writer of IPFire's format v1,
signed with a P-521 key made at run time, and xz-packed), so they need
no fixture and no network.  Both `fs-intel-geo-test` and
`fs-intel-e2e-driver` are built with their own copy of `fs-geodb.c`
compiled with `FS_GEODB_TESTING`, the only build that can be told to
trust a test key.

`fs-intel-geo-test` (GLib, liblzma, libcrypto; no root, no network;
the downloads and the backend are fakes) checks:

| Area | What it pins down |
|---|---|
| wording | the attribution names IPFire and the licence and says IPFire confirmed it; the consent text names the host, how often, what the server learns, "registered", anycast and exceptions; the defaults are off and never consented; source kinds and set names by id; on Windows, "not supported on Windows in this version" |
| config | `[geo]` and `[location <id>]` round trip; refusals for a key of the wrong kind, bad or missing values, a bad id or name, more than 1,000 values; codes and AS numbers are normalised, deduplicated and sorted |
| consent | no rule and no enabling without the terms accepted; a config that says enabled but never accepted downloads nothing |
| no network | the default configuration, the database off, no consent, the master switch off: no request at all; the database's host (and the proxy) is in `fs_intel_update_hosts` only while it is on |
| updates | updated, unchanged, not due within a day, refused (rollback, another key, not xz, from the future), failed (first line only); after each refusal or failure the same copy is in use; the status keeps the last error and success; every attempt is an audit line; with the copy in use damaged or deleted, a signed copy 400 days old and one a day older than the floor are refused, `geodb.state` keeps the newest creation time accepted, and the copy accepted last repairs it (review GEO-ROLLBACK-1, GEO-2) |
| build | each set is the enumeration minus the protected ranges, the exceptions and this computer's addresses (exceptions win; the notes say which rule named them); outbound sets also in 64:ff9b::/96 and inbound ones not; lists and rules in one rule set, lists first; rules that match nothing are enforced empty with a note; anycast is kept and counted after the subtractions, with its note; a missing database leaves every rule unenforced with a note; a copy that no longer verifies fails the build; a stale copy is still used, with a note |
| limits | 300,001 intervals and 2^27 addresses of a country build (the lists' caps do not apply); above 500,000 entries in all, NAT64 copies included, the build fails and names the largest rules |
| lookup | country, AS, network, anycast flag and the rules holding an address; NAT64 addresses only for outbound rules, located by the IPv4 address inside them (`via=nat64`, review GEO-3); exceptions, protected space and this computer's addresses located but not blocked; `fs_intel_geo_lookup`; the cache follows a new copy; nothing while the database is off; the picker's preview counts; with the copy in use damaged or deleted after an apply, "may be blocked" for the rules in the kernel, never "not blocked", except for an exception or protected space, and nothing after Stop (review GEO-1) |
| gate | the apply loads lists and rules in one table; the state names both; a hold keeps the rules out; counters carry across a replace; Stop and Start take the rule sets out and back; rules on with the database off read "off", and say why; a platform without slots says blocklists and location blocking are not available |

`tests/test-intel-e2e.sh` section 12 (root, `unshare -n -m`, real nft,
real packets) adds what only the kernel can show.  Rules are refused
without consent, and nothing is downloaded while the database is off.
The copy is stored 0600.  A country rule (in), an AS rule (out) and a
country rule (both) drop and refuse exactly their packets, while this
computer, its gateway, the DNS server and the SSH peers inside those
countries stay reachable.  An exception inside a country wins, the
counters are per rule, and the lookup agrees (a NAT64 address is
located by the IPv4 address inside it).  With one byte of the copy in
use changed, the apply is refused, the kernel keeps the sets, and the
lookup of an address the kernel drops says "may be blocked"; with the
copy damaged or deleted, an older copy signed with the same key
(`older.db.xz` from `geo-make`) is refused, and the copy accepted last
repairs it.  A country of 400,000
networks applies (about 3.6 s here) and its state is read in under
3 s (about 30 ms here).  IPv6 is checked in the sets, and with packets
when the kernel has IPv6 on the veth pair.  The machine these were
written on has none, so the IPv6 packet checks did not run there; the
test prints a note when it leaves them out.

`fs-intelset-test` adds the chain listing parser: our table present
with the digest on its input chain, the digest taken from input and
not from output, no input chain or no comment (present without a
digest), other families and tables, a chain object without its table,
a table object, an escaped name (absent), and unreadable text
(unknown).  `tests/test-intel-backend.sh` checks that the slots list
chains, and that a table carrying the applied digest but no chains is
not taken for the applied one.

Teeth, each injected into the real file by a scratch script that checks
the old text occurs once, rebuilds the target, runs the test, then
restores the file with `cp` and proves it with `cmp`.  Every one made
the named test fail:

| Bug re-injected | Test | First check that failed |
|---|---|---|
| location sets skip the exceptions and kept addresses (`add_set`) | fs-intel-geo-test | `the country set is the enumeration minus the protected ranges, the exceptions and this computer's addresses` |
| protected ranges not taken out of location sets | fs-intel-geo-test | the same check (10/8 is in the set) |
| a rule added without consent | fs-intel-geo-test | `a location rule before the database's terms were accepted: CONSENT, nothing added` |
| a download without consent | fs-intel-geo-test | `on without consent: needs consent, no request` |
| `fs_intel_update (only "location")` while the database is off | fs-intel-geo-test | `asking for the database while it is off: failed, no request` |
| a full update downloads the database while it is off | fs-intel-geo-test | `the default configuration: no result, no request at all` |
| anycast not counted | fs-intel-geo-test | `anycast is kept and counted after the exception ...: the note says so` |
| inbound rules mapped into 64:ff9b::/96 too | fs-intel-geo-test | the country set check (inbound Atlantis gains NAT64 entries) |
| the location limit four times higher | fs-intel-geo-test | `outbound, with its NAT64 copy, it passes 500,000: refused, naming the rule` |
| lookup holds a NAT64 address for inbound rules | fs-intel-geo-test | `lookup 64:ff9b::c633:6409: a NAT64 address in XA: no inbound rule holds it` (now `... located by its IPv4 address, yet no inbound rule holds it`) |
| the database's host not kept reachable | fs-intel-geo-test | `the database's host and the proxy are kept reachable while it is on` |
| rules built while the database is off | fs-intel-geo-test | `the database turned off: only the list is built` |
| a copy that no longer verifies treated as missing (fail open) | fs-intel-geo-test | `a copy in use that no longer verifies fails the build` |
| no rollback check (`fs-geodb.c`) | fs-intel-geo-test | `an older copy is refused, even with accept-shrink` |
| the engine passes no floor (GEO-ROLLBACK-1) | fs-intel-geo-test | `rollback floor: one byte of the copy in use damaged, a signed copy 400 days old is still refused` and 3 more |
| the same | test-intel-e2e.sh | `the copy in use damaged: an older signed copy is refused, the damaged copy is left as it was` and 2 more |
| a refusal lowers the floor in `geodb.state` (GEO-2) | fs-intel-geo-test | `rollback floor: the copy in use deleted, the old copy is still refused and nothing is installed`, `rollback floor: geodb.state still records the newest copy accepted` and 1 more |
| install ignores the floor (`fs-geodb.c`) | fs-intel-geo-test | `rollback floor: one byte of the copy in use damaged ...` and 3 more (and 3 in fs-geodb-test) |
| the copy accepted last cannot repair (`fs-geodb.c`) | fs-intel-geo-test | `rollback floor: the copy last accepted (the same second) repairs it`, `and the lookup is certain again` |
| lookup says nothing when the copy in use cannot be read (GEO-1) | fs-intel-geo-test | `lookup with the copy in use damaged while Atlantis is in the kernel: never "not blocked"`, `... deleted ...` |
| the same | test-intel-e2e.sh | `lookup 198.51.100.10 with the copy damaged: may be blocked, and the kernel does drop it`, `... deleted ...` |
| the sentence leaves out unreadable rules | fs-intel-geo-test | the same two checks |
| unreadable rules named for an exception or protected space | fs-intel-geo-test | `lookup of 198.51.100.7 with the copy damaged: no sentence` and 3 more |
| unreadable rules named after Stop | fs-intel-geo-test | `after Stop, a missing copy claims nothing` |
| a NAT64 address not located by its IPv4 address (GEO-3) | fs-intel-geo-test | `lookup 64:ff9b::c633:6482: its NAT64 form: the outbound rule holds it, and it is located by its IPv4 address`, `lookup 64:ff9b::c633:6409: ...` |
| the same | test-intel-e2e.sh | `lookup 64:ff9b::c633:6482: located by its IPv4 address, blocked outbound, as its set holds it` |
| no digest comment on the chains | fs-intelset-test | `golden: an IN set, IPv4 only` and every golden |
| the chain parser ignores the family | fs-intelset-test | `chains: only family ip -> absent` |
| the digest taken from any chain | fs-intelset-test | `chains: the digest comes from input, not output` |
| a table without chains read with its table digest | test-intel-backend.sh | `a table with the applied digest but no chains: not applied, and live reads it without a digest` |
| the live check reads `list tables` again | test-intel-e2e.sh | `the state of a table with 400000 elements is read in 6409 ms, without listing them` |
## `stockfw intel`: the threat-intel command line and dashboard panel (`tests/test-intel-cli.sh`, `tests/test-cli.sh`)

```
ninja -C build-linux stockfw stockfw-intel-test
sudo bash tests/test-intel-cli.sh   # root, nft, curl, openssl, unshare, setpriv; SKIPs otherwise
bash tests/test-cli.sh              # no kernel; the intel part needs a store base that passes
                                    # the ownership check ($HOME or the build directory)
```

`stockfw intel` (design section 8) is `src/cli/fs-cli-intel.c`, a front end
over the engine: status, feeds, terms, enable, disable, on, off, add-feed,
update, apply, clear, import, lists, `list show|add|remove`, remove,
except, unexcept, exceptions and lookup, each with `--json`.
`stockfw status` gains an `intel` object and a "Threat intel" line; the
dashboard gains `GET /api/intel` and a read-only "Threat-intel
blocklists" card.  Exit codes follow the CLI: 0 done, 1 failed, 2 usage
(unknown id, bad value, terms not accepted), 3 needs root, 5 `lookup`:
a list blocks the address.  The engine gained `fs_intel_store_exists`
and `fs_intel_clear`; `fs_intel_state` and `fs_intel_counters` no longer
create the store; the catalog gained a `credit` line per feed.

`tests/test-intel-cli.sh` re-executes itself under `unshare -n -m`: the
store is the default `/var/lib/stockfw/intel` on a tmpfs over
`/var/lib`, the feed server is a local HTTPS server on 127.0.0.1 with a
throwaway CA, and the binary is `stockfw-intel-test` -- the real CLI
sources and Linux backend with a copy of `fs-fetch.c` compiled with
`FS_FETCH_TESTING` (the only build that reads `STOCKFW_TEST_CACERT`; the
`stockfw` that ships has no hook).  A failing check prints the last
command's exit status, stdout and stderr.  It checks:

- nothing turned on: status, `--json status`, feeds (every catalog feed
  with its licence or none, the non-commercial flag, credit, terms page,
  interval), lookup, update and `stockfw --json status` exit 0, create
  no store and make no request; `terms` names the host, how often and
  the terms page;
- consent: `enable` without `--accept-terms` exits 2, prints the terms,
  names the flag and leaves the feed off (plain, and `--json` with
  `needs_consent`); with it the feed is on, accepted now, in the
  direction asked; turned off and on again it needs no flag; unknown
  ids, directions, options and actions exit 2; an `http://` custom feed
  is refused;
- a custom feed whose URL has `?key=SECRETKEY`: the key never appears in
  the output (JSON or table); the first change makes the store 0700 with
  0600 files; update downloads it as `StockFW/<version>` (updated, 16
  entries, not applied: the firewall is not running), then not due (no
  request), `--now` unchanged; a copy that shrank to 2 entries is
  refused (exit 1) and the 16-entry copy kept, status "refused";
  `--accept-shrink --feed` takes it; an HTTP 404 fails (exit 1); `--feed`
  of an unknown or turned-off feed exits 2;
- local lists: import (4 entries, out; the unparsable line and the
  private part named), `lists --json`, `list show ID` with its ranges
  (10.1.2.3 left out), `list add` (a new list blocks both ways), the
  same name in another case replaces, `list remove` deletes the files;
  a missing `--name`, a missing file, removing a built-in feed and
  showing an unknown list are errors;
- exceptions: one bad value saves nothing (exit 2); two addresses
  merge; `unexcept` takes one out;
- apply: the dry run names three sets and loads nothing; apply loads
  the digest the dry run named, the state is enforced, one
  `intel-apply` audit line with `source=cli`, the kernel's sets hold the
  lists minus the exception; `intel status` and `stockfw status` say
  enforced; lookup exits 5 for listed addresses (naming the list and the
  direction), 0 for the exception and an unlisted address, 2 for a
  network;
- audit-only mode (`[client] policy_audit_only=true`): apply is held,
  exit 0, the kernel's table unchanged although the config changed;
- clear: the table is gone, the state not-loaded, the three lists still
  on, one `intel-clear` audit line; a second clear is not an error;
  apply restores the same digest;
- as nobody: apply and clear exit 3 and touch nothing; status with
  root's store exits 3 and says needs-root;
- with iptables: after `stockfw stop`, an update stores the new copy and
  does not apply it; `stockfw start` applies it; with the firewall
  running but the lists cleared, an update applies nothing;
  `--no-apply` applies nothing; running and enforced, an update applies
  the new copy at once;
- the master switch off: the kernel untouched until apply, apply removes
  the table (state off), update makes no request; removing the custom
  feed deletes its files.

`tests/test-cli.sh` (no kernel; the store in a directory under `$HOME`
or the build directory, which passes the ownership check that `/tmp`
never does): help lists `intel`; feeds without a store (and creating
none) with LICENCE and CREDIT columns; consent refused and accepted;
import, except, lookup exit 5 / 0 / 2; `status --json` carries `intel`;
as nobody (or as the user, when not root) apply and clear exit 3;
`apply --dry-run`; the dashboard's `/api/intel` needs the token, lists
the two sources with licence and credit, refuses POST (405), and the
page has the panel and asks for `/api/intel`; every JSON endpoint parses
(intel included).  `fs-feed-test` checks that every catalog feed has a
credit line and that Spamhaus's names Spamhaus.

Not covered: the desktop Threat Intel page, the consent dialog and
Events attribution (not built); IPv6 lookups against a live kernel
(no IPv6 here); catalog feeds' real hosts (no internet: only a custom
feed on 127.0.0.1 is downloaded).

Teeth (`teeth.py` in a scratch directory: asserts the old text occurs
once, rebuilds, runs the test, looks for the named checks among the
failures, restores with `cp`, checks with `cmp`):

| Bug re-injected | Checks that failed |
|---|---|
| `enable` passes `TRUE` for the terms instead of `--accept-terms` | `enable without --accept-terms: exit 2, the terms shown, the flag named`, `... and the feed is still off`, `... as JSON: needs_consent ...`, `enable --accept-terms --direction in: on, accepted now` |
| the CLI loads the config through the store even for read-only commands | `intel (status): off, exit 0, and no store is created`, `intel --json feeds: ... no store`, `intel lookup: ... no store`, `intel update with nothing on: ... no store`, `status --json: intel.state off, no store` |
| `fs_intel_counters` opens the store without checking it exists | `intel --json feeds: ... no store`, `intel lookup: ... no store`, `intel update with nothing on: ...`, `status --json: ...` |
| `fs_intel_state` without its no-store branch | `intel (status): off, exit 0, and no store is created` and the four other no-store checks |
| `lookup` always exits 0 | `lookup of a listed address: blocked, exit 5, names the list`, `lookup of a local-list address: blocked out, exit 5` |
| `update` exits 0 for a refused copy | `a copy that shrank to 2 entries: refused, exit 1` |
| `update` re-applies without checking the firewall runs | `... and not applied: the firewall is not running` |
| `update` re-applies without checking the lists are enforced | `update while running but the lists cleared: stored, not applied` |
| `clear` records the lists as suspended | `clear: removed from the kernel, state not-loaded`, `... the three lists are still turned on`, `update while running but the lists cleared: ...` |
| `intel apply` passes no hold | `audit-only mode: the apply is held, exit 0, the kernel untouched`, `... and says so` |
| the feeds table prints a custom feed's URL unredacted | `... feeds shows it with the query string hidden` |
| the dashboard without its `/api/intel` route | `intel: the state and the lists turned on, with licence and credit` (test-cli.sh) |
| `intel apply`/`clear` without their root check | `intel apply and clear need root (exit 3)` (test-cli.sh) |
| Spamhaus DROP's credit without "Spamhaus" | `every feed has a credit line; Spamhaus's names Spamhaus` (fs-feed-test) |
| `stockfw status --json` without its `intel` object | `status --json carries an intel object` (test-cli.sh) |
| `update --feed` of a feed that is turned off goes ahead | `update --feed of a feed that is off: exit 2` |

The sanitizer build (`build-asan`) runs `test-cli.sh` and
`test-intel-cli.sh` (with `STOCKFW_BUILD` / `STOCKFW_INTEL_CLI` naming
it) with no AddressSanitizer or UndefinedBehaviorSanitizer report.

## The Threat Intel page and Events attribution (1.0.7, design 8)

`fs-intelview-smoke` (`ninja -C port/build-linux fs-intelview-smoke`,
then `xvfb-run -a port/build-linux/fs-intelview-smoke`, as root or with
`STOCKFW_TEST_SAFE_DIR` set to a directory the engine accepts as a store
parent) builds the real page in an offscreen window against a fake
intel backend (`fs_intelview_set_backend`: an in-memory table with a
digest, counters and a firewall state) and a fake downloader
(`fs_intel_set_fetcher`), with its own store, audit file and `HOME`.
An auto-responder stands in for the user at every dialog
(`fs_intelview_set_responder`). It flips the switches, clicks the
buttons, types into the editors and reads back what the user reads:

- no store: "Off", every feed "Off.", the page creates no store, and
  FireHOL level 1 shows "Non-commercial use only" and a credit link to
  its publisher;
- turning a feed on asks first (the consent text names the host); Cancel
  downloads and applies nothing; Accept downloads once and applies once,
  "Protected", "Up to date and in force.", entries, last and next update;
- the work runs in the worker: a 10 ms timer keeps firing on the main
  loop during a 0.4 s download, the progress line names the download,
  and while an update runs the controls are insensitive;
- the blocked counter per feed and the card's tiles;
- a list that shrank is refused, "Accept smaller list" is offered and
  lets it in (and is applied); a failed download says so and keeps the
  copy;
- "Not loaded" with Apply, which puts it back; "Changed outside
  StockFW"; "Paused" after the engine's suspend; "Unknown"; "Not
  supported on this platform" with nothing usable (the Windows build
  says "Not supported on Windows yet");
- with the firewall stopped a change is saved, nothing applied, and the
  page says when it will be; under a hold (the Overview's Lock) a change
  is saved, not applied, and the reason is shown; Apply afterwards puts
  it in;
- lookup: a listed address (blocked, naming the list), an address on no
  list, text that is not an address; the allow list (saved, then the
  lookup says it is never blocked; a bad line is refused as an error);
  your blocklist (saved as "My blocklist", applied, blocks); importing a
  file ("Office VPN.txt" becomes `local-office-vpn`, applied) and
  removing it (asked first);
- Events: a line from `fs_netparse_intel_line` with its rule shows
  "SSH [BLOCKED] · Threat intel: Spamhaus DROP (IPv4)" in the Service
  column while a policy block shows as before; the selection carries the
  rule and an untouched service; the filter finds the row by the list's
  name; Add exception asks first naming the list, Cancel changes
  nothing, Accept puts the address on the allow list.

`INTEL_SMOKE_SHOTS=<dir>` writes a PNG of each state (off, protected,
updating, refused, not loaded, differs, paused, your lists, events,
unknown, unsupported).

`test-core.sh` gains `test_netparse_intel_line`: the id and the fields of
a `STOCKFW-TI <id>` line (RFC 3339 and classic syslog), an id the engine
could not have written, a bare marker and a policy line are not intel
events, and the policy parser never takes an intel line (so the CLI's
event list cannot show one as a policy block). `fs-intel-test` gains the
refusal's override: a shrink records `--accept-shrink`, sudden growth
`--accept-coverage` (and only that flag lets it in), a body that is not
a list records none, and an accepted copy clears it.

Not covered: the Linux backend's check that a `STOCKFW-TI` line names a
set of the applied rule set (`fs_intel_applied_has`) is in a static
function of the log reader and is built, not run; the Events page's
right-click menu itself (the smoke calls `fs_intelview_add_exception`,
which the menu item calls); the page as a non-root user (needs root).

Teeth (`teeth.py` in a scratch directory, the same procedure as above):

| Bug re-injected | Check that failed |
|---|---|
| no consent dialog before a feed is turned on | `turning a feed on asks first, naming the host contacted` |
| the job run on the main thread | `the window kept running during a 0.4 s download (1 timer ticks ...)` |
| the refusal's override not recorded | `and "Accept smaller list" is offered`; `a shrink refusal records that --accept-shrink lets it in` (fs-intel-test) |
| Events ignores the rule | `events: the list's block names the list in the Service column` |
| the page creates the store when it opens | `opening the page creates no store (Stop and Start stay no-ops)` |
| the Overview's Lock does not hold the apply | `under a hold: saved, not applied, and why` |
| applied while the firewall is stopped | `firewall stopped: turning a feed on saves it, applies nothing, ...` |
| controls usable while a job runs | `mid-update: the progress line shows (...), and the controls wait for it` |
| the intel parser takes any id | `intel line: an id the engine could not have written is not an event` |
| the policy parser takes intel lines | `the policy parser never takes an intel line` |
| "Not loaded" shown as "Protected" | `table gone behind StockFW's back: "Not loaded", with Apply` |
| the Events filter ignores the rule | `events: the filter finds the list's block by the list's name` |

## Threat intel after the CLI and the page were merged (`intel-r3/integrated`)

The CLI (`intel-r3/cli`) and the Threat Intel page (`intel-r3/ui`) were
built side by side on the round 2 engine.  Once merged, the places
where they disagreed were fixed, each with a check:

| check | where | what it proves |
|---|---|---|
| `Spamhaus DROP: the credit names The Spamhaus Project` | `fs-intelview-smoke` | the page's credit link is the catalog's credit line (`FsFeedInfo.credit`), the words `stockfw intel feeds` and the dashboard print, not the download host |
| `the consent text sends mistakes to this page's allow list` | `fs-intelview-smoke` | the consent text names the page's allow list (it said "Exceptions on the Threat Intel page", a heading the page does not have); `fs-intel-test`'s consent check still finds "exception" |
| `... and it names the flag that takes it (the page's Accept smaller list)` | `test-intel-cli.sh` | a refused shrink prints `sudo stockfw intel update --feed ID --now --accept-shrink`, from the engine's `refused_override` |
| `... the status says refused, accept_with --accept-shrink` | `test-intel-cli.sh` | `feeds --json` carries the same flag as `accept_with` |
| `... update --json: refused, accept_with --accept-shrink` | `test-intel-cli.sh` | so does `update --json` |
| `no store: a list's log line is not attributed, and asking creates nothing` | `fs-intel-test` | `fs_intel_applied_has`, which the Linux log reader (UI branch) asks for every `STOCKFW-TI` line, no longer creates the store, like the other read-only questions the CLI branch fixed |

Teeth (each injected, rebuilt, run, restored with `cp`, checked with
`cmp`):

| injected bug | check that fails |
|---|---|
| the page's credit link shows `fi->host` again | `Spamhaus DROP: the credit names The Spamhaus Project` |
| the consent text says "Exceptions on the Threat Intel page" again | `the consent text sends mistakes to this page's allow list` |
| the CLI never reports an override (`accept_flag` returns NULL) | the three `test-intel-cli.sh` checks above |
| the CLI maps a shrink to `--accept-coverage` | the same three checks |
| `fs_intel_applied_has` without its `store_exists` check | `no store: a list's log line is not attributed, ...` (and then `no store, a table left behind: stop removes it, creates nothing`) |

Every suite, module test and smoke was run on the merged tree (the
smokes under `xvfb-run -a`; `fs-tray-smoke` fails headless as before).
The sanitizer build (`build-asan`) runs `fs-feed-test`, `fs-intel-test`,
`test-cli.sh` and `test-intel-cli.sh` with leak checking on, and
`fs-intelview-smoke` and `fs-hitview-smoke` with it off (GTK keeps its
caches until exit), with no AddressSanitizer, LeakSanitizer or
UndefinedBehaviorSanitizer report.  With leak checking on, `test-cli.sh`
first found that `stockfw policy add` never freed the rule it parsed
(the policy stores copies), five reports, one per add; that is fixed.

## Threat intel, round 3 review fixes (`intel-r3/integrated`)

What the kernel does, not just the configuration; one engine operation
at a time; and the CLI, the dashboard and the page saying the same.

| check | where | what it proves |
|---|---|---|
| `a Stop during an apply waits for it ..., then the lists are down and suspended` | `fs-intel-test` | the engine lock (`flock` on `<store>/engine.lock`): a Stop from another thread blocks until the apply ends, then wins; the audit has intel-apply before intel-suspend |
| `an apply that waited for a Stop is held ...` | `fs-intel-test` | an apply that had to wait, and finds the firewall stopped by the operation it waited for, is held, the kernel left empty |
| `an apply that did not wait is not held by an old Stop` | `fs-intel-test` | a deliberate `intel apply` with the firewall stopped behaves as before |
| `a Stop during an apply waits for it, then the lists are down and suspended` | `test-intel-cli.sh` | the same across processes: `intel apply` slowed by an nft wrapper, `stockfw stop` a moment later |
| `an update during which a Stop carried the counters keeps them` | `fs-intel-test` | an update re-reads the carried totals under the lock before it writes its state |
| `lookup_live: ...` (10 checks) | `fs-intel-test` | `fs_intel_lookup_live`: not loaded, enforced, an exception saved but not applied (still in force, pending), applied, removed, a direction change, Stop, Start, clear, a new copy not applied (uncertain), another table (differs) |
| `lookup of an exception not applied: the kernel still blocks it, exit 5, pending`, `lookup after clear ...`, `lookup with the firewall stopped ...` | `test-intel-cli.sh` | `stockfw intel lookup` exits 5 only when the kernel blocks the address (checked with `nft get element`) |
| `lookup: a listed address names the list, but nothing is in force: exit 0, in_force false` | `test-cli.sh` | without a kernel table the answer is never "blocked" |
| `paused: lookup says the list holds it but nothing blocks it now` | `fs-intelview-smoke` | the page's lookup box under Paused (no red "is blocked") |
| `the paused lookup's answer is gone once the state changed` | `fs-intelview-smoke` | a stale answer is hidden when a snapshot changes the state |
| `held under the Lock: after a refresh the feodo row says it is not in force, and why` | `fs-intelview-smoke` | a feed turned on under the Lock reads "On, but not in force: the policy is locked ..." after the 30 s refresh took the message away |
| `paused: the failed update's copy is kept, not said to be used` | `fs-intelview-smoke` | "is kept", and "and in force" only when it is |
| `"No list file imported." is padded like the rows` | `fs-intelview-smoke` | the placeholder has `intel-pad` |
| `import: the bad line and the private entry are named, as a warning` | `fs-intelview-smoke` | the page's Import reports `invalid`, `too_broad` and `protected_hits` as the CLI does |
| `fs_intelview_hold_reason: the Lock's sentence ...` | `fs-intelview-smoke` | the one hold that the page's applies and the Status page's Start both use |
| `re-import with dir 0 keeps the list's direction (in)` | `fs-intel-test` | `fs_intel_import_list` with dir 0 keeps the replaced list's direction (the name in any case or spacing) |
| `re-import, the name in another case and spacing, no --direction: still out` | `test-intel-cli.sh` | the CLI passes 0 when `--direction` is absent |
| `events: a list's block is in the history, with its rule; a set not applied is not`, `events (table): a RULE column names the list` | `test-cli.sh` | `stockfw events` (and the dashboard's history, the same function) reads `STOCKFW-TI` lines as the live feed does, with `fs_intel_rule_text` |
| `chains: ...` (11 checks) | `fs-intelset-test` | `fs_intelset_nft_parse_live_chains`: one digest on every chain, an older table without chain comments (fallback), mixed digests, decoys, broken listings |
| the goldens | `fs-intelset-test` | every chain carries `comment "sfw:<digest>"` |
| `every chain carries the digest too: ...` | `test-intelset.sh` | real nft 1.0.9 loads the chain comments, and `nft -j list chains inet` reads the digest |
| `the live state is read from the chain listing (-j list chains inet)` | `test-intel-backend.sh` | the backend's live read is the fast listing |
| `unknown: the reason is in the sentence` | `fs-intel-test` | `intel_live_error` (no nft) reaches the state's sentence |
| `proxy ...` (5 checks), `intel proxy ...` (3 checks) | `fs-intel-test`, `test-cli.sh` | `fs_intel_config_set_proxy` and `stockfw intel proxy URL\|none`; one with a password is refused; `status` shows it |
| `rule text of ...` | `fs-intel-test` | `fs_intel_rule_text`, shared by the backend, `stockfw events` and the dashboard |

Teeth (each injected into the source by a script that asserts the old
text once, rebuilt, run, seen failing on the named check, restored with
`cp`, checked with `cmp`):

| injected bug | check that fails |
|---|---|
| `engine_lock` never locks | `a Stop during an apply waits for it ...` |
| a waited apply is not held | `an apply that waited for a Stop is held` |
| the CLI's exit 5 from `blocked` (the configuration) | `lookup: a listed address names the list, but nothing is in force ...` |
| the applied exceptions ignored | `lookup_live: exception not applied: ...` |
| the page says "is blocked" from the configuration | `paused: lookup says the list holds it ...` |
| `stockfw events` without `STOCKFW-TI` lines | `events: a list's block is in the history ...` |
| a re-import widens to both | `re-import with dir 0 keeps the list's direction (in)` |
| the page's Import drops lines silently | `import: the bad line and the private entry are named ...` |
| no digest on the chains | `golden: an IN set, IPv4 only` |
| the chain parser takes mixed digests | `chains: one chain replaced by hand, ...` |
| the unknown state without the backend's reason | `unknown: the reason is in the sentence` |
| a proxy with a password accepted | `proxy with a password: refused, nothing set` |
| a held feed reads "Up to date." | `held under the Lock: after a refresh ...` |
| "is still used" under Paused | `paused: the failed update's copy is kept, ...` |
| the placeholder without `intel-pad` | `"No list file imported." is padded like the rows` |
| the stale lookup answer stays | `the paused lookup's answer is gone once the state changed` |
| the update does not re-read the carried counters | `an update during which a Stop carried the counters keeps them` |

Not covered by a test: the Status page's Start calling
`fs_intelview_hold_reason` (its worker runs on the real backend); the
smoke checks the function it calls.

The sanitizer build runs `fs-intel-test`, `fs-intelset-test`,
`test-intel-cli.sh`, `test-intel-backend.sh`, `test-cli.sh` and
`test-intelset.sh` with leak checking on, and `fs-intelview-smoke` with
it off, with no report.

## Threat intel on Windows (`tests/test-core.sh`, `fs-intel-test`, `fs-intel-windows-test`)

Round 3 (design section 11) enforces blocklists with Windows Firewall
rules in the group `StockFW Threat Intel`. What the rules are and what
a read-back means is pure code (`core/fs-intelwin.c`), so most of it is
checked on Linux.

`tests/test-core.sh` (pure):

- **generations** (`test_intelwin_gen`): `g` and 8 lower-case hex
  digits only; a new one is never one already on the firewall.
- **the plan** (`test_intelwin_plan`): two lists, one both ways, at 2
  tokens a rule: the exact names in order (inbound before outbound,
  IPv4 before IPv6, chunk i/n, the generation, the manifest last); every
  address rule enabled, with its direction, never named `StockFW-`, no
  `|` or line break in a description; per list and direction the
  chunks hold exactly the list's addresses; the manifest is disabled,
  names only 192.0.2.1 and ends `sfw:<digest> plan:<hash> rules:9`;
  another generation changes the plan hash, not the digest; invalid
  generations, zero limits, an invalid or repeated id plan nothing; the
  empty rule set has no rule; a list emptied by subtraction leaves the
  manifest, which reads back PRESENT.
- **the real limits** (`test_intelwin_limits`): 2500 IPv4 addresses
  take 3 rules (1000, 1000, 500); 1500 long IPv6 ranges split by the
  32,000-character cap; a token longer than the cap gets a rule of its
  own, never cut.
- **`RemoteAddresses` read back** (`test_intelwin_parse_remote`): dotted
  masks, ranges, IPv6, spaces after commas; `*`, keywords, empty
  tokens, masks with holes, prefixes over 32 and names are refused and
  leave the set as it was.
- **the verdict** (`test_intelwin_read`): no rule is ABSENT; rules
  outside the group (even named like ours) are not counted; the rules
  as written, and as Windows writes them back (dotted masks, tokens and
  rules reordered, other rules around) read PRESENT with the digest;
  25 tamperings each read PARTIAL with a reason and no digest (a chunk
  deleted, disabled, allow, direction, profile, protocol, local port,
  local address, program, remote port 443, one service (`Dnscache`),
  interface type, named interfaces, an
  `INetFwRule3` condition, an address taken out, `*`, an IPv6 address
  in an IPv4 rule, addresses moved between chunks, a rule added with a
  name like ours, a foreign rule in the group, a rule of an earlier
  apply, the manifest deleted, the manifest's count edited to hide a
  deleted rule, a rule renamed, a rule moved out of the group).
- **in force** (`test_intelwin_force`): service stopped, Group Policy
  override, off for the only profile in use, for one of two, for two,
  excluded adapters each give their sentence; a profile no network has
  gives none. Settings, Group Policy's state or a profile in use that
  could not be read give "StockFW cannot read whether ...", never
  nothing (review W5); a profile known to be off is named first, and an
  unreadable profile no network has does not matter.
- **review** (`test_intelwin_review`): `fs_intelwin_count_gen` counts
  every rule of a generation, past a foreign rule in the group and an
  earlier apply's rule, and never one outside the group (W6);
  `fs_intelwin_name_key` gives names that differ only in case one key
  (W6); `fs_netsh_rule_name_is_ours` tells the policy's names from the
  blocklist rules' (W3); a rule set of 150,000 long IPv6 ranges both
  ways holds about 24 million characters of addresses, past the 16 MiB
  a netsh listing may hold (W3, the reason the policy lists through
  COM).
- **on-link prefixes** (`test_hostnet_onlink`): an address and
  `OnLinkPrefixLength` give its block (a /24, a /64, a /30 inside a
  byte); a prefix of 0 or wider than the family keeps the address
  alone; a bad address length adds nothing.

`fs-intel-test` (fake backend, `test_state_windows` and `test_build`):
PARTIAL reads differs and an apply rewrites it; INACTIVE reads
not-in-force with the backend's sentence (also when the rules are not
the ones last applied, and with no sentence at all); unreadable rules
with the service stopped read not-in-force, and with nothing known
never read not-in-force or enforced; an apply that leaves the rules
not enforced is OK with the note "in place, but not in force"; Stop
removes PARTIAL and INACTIVE rules; a backend with no counters slot
gets `fs_intel_counts_unavailable` and no count of 0; the build's
exceptions and kept addresses reach no rule the Windows plan writes.

`fs-intel-windows-test` (`tests/test-intel-windows.c`, Windows only,
elevated only, run by `tests/full-suite.sh`): applies a two-list rule
set through the real backend (one list at 2500 addresses, so three
rules at the 1000 limit), reads every rule back through `INetFwRules`
itself and compares names, group, direction, action, profiles,
protocol, description and addresses with the plan; `intel_live` reads
the digest; the same rule set again keeps the generation; a changed one
replaces every old rule; a rule disabled by hand reads PARTIAL and an
apply repairs it; a foreign rule in the group reads PARTIAL; every
profile off reads INACTIVE with a reason (the profiles are put back);
clear leaves nothing in the group and every rule outside it exactly as
before, including a decoy that has one of our rule names in another
group (checked for the decoy alone, the clear alone and the whole run,
as multisets of whole rule lines sorted by text; a failure prints each
line whose count differs, and `full-suite.sh` prints the whole output
of this test when it fails); the store directory gets a
protected DACL naming only SYSTEM, Administrators and the current user,
and Administrators as owner; an override whose parent Users may change
is refused and not created (its temporary parents are made with a
protected DACL, as an override's parent must be). It prints SKIP when the shell is
not elevated, the firewall service is stopped, or the computer already
holds StockFW blocklist rules (they are the user's).

Review additions: rules that cannot be read (`intel_live` UNKNOWN)
fail, never skip (W1); with `STOCKFW_REQUIRE_WINDOWS_INTEL=1`, which
the CI's Windows job sets, every skip fails, the whole-run ones and the
parts below alike (W1). The apply over a foreign rule in the group is
checked, the group then reads PRESENT with the digest and the foreign
rule is gone, and the profile-off checks run whatever it returned (W2).
"Policy beside big lists" applies 140,000 long IPv6 ranges both ways
(more than 16 MiB of addresses), adds a rule with a policy name after
them, runs the policy's clear and checks that the rule is gone and
every blocklist rule is still there, whole (W3; it runs only when the
computer holds no StockFW policy rules). "Store squatted" makes
`%ProgramData%\StockFW` first, once as a folder owned by
BUILTIN\Users and once as a link to another folder, and checks that
`fs_intel_dir` moves it aside (the link as a link: the folder it points
to keeps its file and gets no `intel`) and makes its own protected
folder (W7; it runs only when the computer has no StockFW store). It
was compiled and linked with mingw against the Windows headers in the
development container, not run there.

Teeth, each injected into the real source by `teeth.py` in a scratch
directory, which asserts the exact old text occurs once, runs the
test, looks for the named check among the failures, then restores the
file with `cp` and checks it with `cmp`:

| Bug re-injected | Checks that failed |
|---|---|
| the read-back ignores a rule narrowed to fewer profiles | `intelwin read: a rule narrowed to the Public profile is PARTIAL` |
| the plan hash covers names and directions, not addresses | `intelwin read: addresses moved between two chunks is PARTIAL` |
| chunks are cut by token count only, no character cap | `intelwin limits: 1500 long IPv6 ranges are split by characters ...` |
| a dotted mask with holes is accepted | `intelwin remote: "*", keywords, empty tokens, a mask with holes ...` |
| a profile no network has counts as "off" | `intelwin force: a profile no network has does not matter` |
| an on-link prefix of 0 keeps everything | `hostnet onlink: a zero or too-wide prefix keeps the address alone ...` |
| PARTIAL rules read enforced | `windows states: rules missing or edited outside StockFW read "differs" ...` |
| an apply into rules that are not enforced says nothing | `windows states: an apply whose rules are not enforced is OK and says ...` |
| unreadable rules ignore the backend's "service stopped" | `windows states: rules that cannot be read with the service stopped ...` |
| the read-back ignores a rule's direction | `intelwin read: a rule's direction flipped is PARTIAL` |
| (W4) the read-back ignores remote ports | `intelwin read: a rule narrowed to remote port 443 is PARTIAL ...` |
| (W4) the read-back ignores the service | `intelwin read: a rule narrowed to one service is PARTIAL ...` |
| (W5) unreadable settings claim nothing (the old `return NULL`) | `intelwin force: profiles in use that could not be read are never in force` |
| (W5) a profile in use that cannot be read counts as on | `intelwin force: a profile in use whose firewall switch could not be read ...` |
| (W5) Group Policy's state is not required to be read | `intelwin force: a Group Policy state that could not be read ...` |
| (W6) the name key is not case-folded | `intelwin review: rule names that differ only in case share one key` |
| (W6) the generation count ignores the group | `intelwin review: rules outside the group are never counted` |
| (W3) blocklist names pass as the policy's | `intelwin review: the policy's rule names are told apart ...` |

The Windows backend's COM code itself has no tooth here: the container
cannot run it (that covers W1, W2, W7 and the COM halves of W3 and W6:
the policy's name listing through `INetFwRules`, the cut-off netsh
output as an error, the rollback's read-back). `fs-intel-windows-test` is its check on the CI's Windows
runner.

## Threat intel, one feature on Linux and Windows (`intel-r3/integrated` with the Windows enforcement and main)

The Windows enforcement (`claude/stockfw-1.0.7-wintel`) and main (the
start gate, Preferences, background mode, the tray) were merged into
`intel-r3/integrated`. The places where the Linux surfaces did not yet
know the Windows states were fixed, each with a check (design 11.12):

| check | where | what it proves |
|---|---|---|
| `windows: PRESENT with the digest is in force (no counters ...)` | `fs-intel-test` | `fs_intel_lookup_live` answers from the firewall's rules on Windows, with no counters slot |
| `windows: INACTIVE with the same digest is never in force` | `fs-intel-test` | rules there but not enforced are not "in force"; the detail is the backend's sentence |
| `windows: PARTIAL rules are never in force`, `windows: PRESENT with another digest is not in force` | `fs-intel-test` | rules not whole, or of an older list, are never in force |
| `windows: no store, PARTIAL rules there: differs`, `... INACTIVE ...`, `... and asking created no store` | `fs-intel-test` | with no store, any rules of ours read differs, as PRESENT ones did, and nothing is created |
| `windows: a backend without counters says counts are ...` | `fs-intel-test` | `fs_intel_counts_unavailable()` gives a sentence on Windows and none where there are counters |
| `windows: rules the firewall does not enforce: "Not in force" ...` | `fs-intelview-smoke` | the page's card for the not-in-force state, with the backend's sentence |
| `windows: the Overview and tray summary says not in force` | `fs-intelview-smoke` | `fs_intelview_summary`, which the Overview's verdict and the tray's tooltip show |
| `windows: no count per feed, the reason instead` | `fs-intelview-smoke` | no "Blocked N packets" or "Nothing blocked yet" where there are no counts |
| `windows: the Blocked tile says n/a, never 0` | `fs-intelview-smoke` | the tile never shows a zero it cannot know |
| `windows: rules not whole read "Changed outside StockFW"`, `windows: whole and enforced again: "Protected"` | `fs-intelview-smoke` | PARTIAL reads differs on the page, and the page comes back |
| `engine lock: taken at once ...`, `engine lock: a second holder ... waits`, `engine lock: a symbolic link in its place is refused` | `fs-intel-windows-test` | `LockFileEx` on `engine.lock` (Windows only) |
| `winstore: %ProgramData%\StockFW is created owned by Administrators ...`, `winstore: intel is created ...`, `winstore: an override adds the current user ...` | `test-core.sh` | W8: the exact SDDL each folder is created with (`fs_winstore_sddl`); removing `O:BA` fails these and the two "passes" checks below |
| `winstore: StockFW's own ... passes ...`, `winstore: a folder created without an owner ... refuses it`, `winstore: a temporary folder under a drive root ... is refused`, the other `winstore: ...` checks | `test-core.sh` | `fs_winstore_judge`, the pure owner and access-list check the Windows store runs, against SDDL as Windows shows it |
| `store: an elevated StockFW makes Administrators the directory's owner ...`, `store: an override whose parent Users may change is refused ...`, `clear: the decoy named like ours is exactly as it was ...`, `clear: the clear itself changed no rule outside the group` | `fs-intel-windows-test` | W8, on the CI's Windows runner only |

The start gate from main refuses `stockfw start` when no policy is
saved and none was applied. `test-intel-cli.sh` (section 8) and
`test-intel-e2e.sh` stop and start the firewall, so each now saves one
policy rule first (`policy add inbound-allow-service SSH 22 Anyone`);
`test-intel-e2e.sh` keeps that rule in its scratch directory through
`STOCKFW_RULES_DIR`. Without it, 3 and 4 of their checks failed on
the merged tree.

Teeth (each injected into the real source by a script that asserts the
exact old text occurs once, rebuilds, runs the test, looks for the
named check among the failures, then restores the file with `cp` and
checks it with `cmp`; all seven bit and all seven files were identical
after):

| injected bug | check that fails |
|---|---|
| no store: only PRESENT rules read differs (not `live_holds`) | `windows: no store, PARTIAL rules there: differs` |
| `fs_intel_lookup_live` also answers in the not-in-force state | `windows: INACTIVE with the same digest is never in force` |
| the per-feed facts ignore `counts_unavailable` | `windows: no count per feed, the reason instead` |
| the Blocked tile shows the count whatever | `windows: the Blocked tile says n/a, never 0` |
| the page's card has no not-in-force case | `windows: rules the firewall does not enforce: "Not in force"` |
| the summary has no not-in-force case | `windows: the Overview and tray summary says not in force` |
| the page never updates the summary (`summary_update` removed) | `windows: the Overview and tray summary says not in force` |

Not covered:

- `stockfw intel status` printing "n/a" and `counts_unavailable` in
  its JSON: the CLI is built on Linux only, where there are always
  counts, so that branch cannot be reached by a test here.
- `fs-intel-windows-test` (the engine lock checks above included) is
  compiled and linked with mingw against the Windows headers in the
  development container and not run there; it runs on the CI's
  Windows runner.
- The Overview's verdict and the tray's tooltip are not read back by a
  smoke; the smoke checks `fs_intelview_summary`, which both show.
  (The tray's tooltip is read back since the review below.)

Every suite, module test and smoke was run on the merged tree (the
smokes under `xvfb-run -a`; `fs-tray-smoke` fails headless as before).
The Windows sources compile (`wincheck.sh`) and `StockFW.exe` links
(`winlink.sh`) with mingw.

## Threat intel, review of the merge (design 11.13)

| check | where | what it proves |
|---|---|---|
| `engine: after an apply the list is applied`, `engine: after a Stop the list is not applied`, `engine: a Start after a Stop returns and the list is applied again`, `engine: a Stop during an apply waits for it`, `engine: an apply that waited for a Stop is held`, `engine: after a clear the list is not applied` | `fs-intel-test` and `fs-intel-windows-test` (`tests/intel-engine-checks.h`) | M1: the engine's lock and `fs_intel_applied_has` through a fake backend, each call on a worker thread with a 30 s deadline (a self-deadlock prints `engine: ... returns within 30 s` as a FAIL and ends the run). On Linux the Linux branches run; on the Windows runner the G_OS_WIN32 ones (`engine_held`, `fs_winstore_lock` in every operation, `applied.state` read each time) |
| `windows states: ... and the outcome carries why` | `fs-intel-test` | T2: an apply whose rules read INACTIVE is OK and carries `not_in_force` |
| `windows: Apply with the firewall off for the profile says the rules are in place but not in force` | `fs-intelview-smoke` | T2: the page never says "The lists are in force." then |
| `tray: after Stop, before the next read, the tooltip claims no blocklist in force`, `after Stop, once read: no summary` | `fs-intelview-smoke` | T1: the tray's tooltip, read back through `gtk_status_icon_get_tooltip_text` |
| `held under the Lock: the summary names the list that is on but not in force` | `fs-intelview-smoke` | T3 |
| `master switch off under the Lock: "Off, but rules still in place" ...` | `fs-intelview-smoke` | T4: the user's own switch is never "changed outside StockFW", and the summary says the rules still block |
| `cli words: Stop and Start's blocklist error in fs-cli-cmds.c names the platform's firewall`, `cli words: the root hint in fs-cli-cmds.c is the platform's`, `cli words: fs-cli.h names Windows Firewall ...` | `tests/test-core.sh` | T5: read from the source (CR stripped), since the CLI is built on Linux only |

`fs-intel-test` runs the engine checks first among its engine tests:
an older check that calls Start directly would otherwise hang, not
fail, on the same bug.

Teeth (each injected into the real file, the named check seen failing,
the file restored with `cp` and proved with `cmp`):

| injected bug | check that fails |
|---|---|
| `engine_held` answers FALSE (the Linux branch; the reviewer's Windows bug made the Windows branch do the same) | `engine: a Start (fs_intel_resume) returns within 30 s`, and the run stops with exit 1 in about 30 s |
| `fs_intel_applied_has` never finds the id (the Linux branch) | `engine: after an apply the list is applied`, `engine: a Start after a Stop returns and the list is applied again` |
| the apply does not set `not_in_force` | `windows states: ... and the outcome carries why` |
| the page's Apply ignores `not_in_force` | `windows: Apply with the firewall off for the profile ...` |
| the tray adds the summary whatever the firewall's state | `tray: after Stop, before the next read, ...` |
| the summary ignores lists not applied | `held under the Lock: the summary names the list ...` |
| differs back to "changed outside StockFW" in the summary and the title | `master switch off under the Lock: ...` |
| `fs-cli-cmds.c` says "the kernel does not hold them" again | `cli words: Stop and Start's blocklist error ...` |

Not covered:

- The engine checks run the G_OS_WIN32 branches only on the CI's
  Windows runner; here they are compiled and linked with mingw and not
  run, so their teeth against the Windows branches themselves (the
  reviewer's two injections) were not seen failing.
- `fs_intel_update` under the engine lock on Windows (it needs the
  downloader on Windows); the Linux run covers the lock's use there.
- The Status page's Stop and Start worker (`intel_job_done` reading the
  state again, the not-in-force dialog after Start) runs on the real
  backend and is built, not run; the smoke checks what it calls.

## Country and network-owner rules merged with threat intel on Windows (design 13.15)

```sh
ninja -C build-linux fs-intel-geo-test fs-intelset-test fs-intel-backend-driver
./build-linux/fs-intel-geo-test
./build-linux/fs-intelset-test
sudo bash tests/test-intel-backend.sh   # the driver must be readable by nobody for the "not root" part
```

The merge kept Round 3's chain reader (one digest on every chain, `nft -j list chains inet`) and
Round 2's rule that a table with no chain of ours reads present without a digest, and taught
`fs_intel_lookup_live` to ask a location set through the database copy it was built from. Each
check below was seen failing with its bug put back in a copy of the source, then the copy was
restored with `cp` and checked with `cmp`.

| bug put back | test | check that fails |
|---|---|---|
| `fs_intel_lookup_live` reads a location set as a stored list | fs-intel-geo-test | `live: an address in the country set is blocked now, by it, and nothing is pending`, `live: an address of another country is not blocked, and that is certain`, `live: a rule turned off but not applied still blocks, and the change is pending` |
| the location set's input digest leaves out the rule's values | fs-intel-geo-test | `live: the rule's countries changed since the apply: pending and uncertain, never a plain no` |
| enabled location rules missing from the live lookup's "changed since" | fs-intel-geo-test | `live: an address in the country set is blocked now, ...`, `live: an address of another country is not blocked, ...` |
| a table with no chain of ours keeps its table comment's digest | test-intel-backend.sh | `a table with the applied digest but no chains: not applied, and live reads it without a digest` |

fs-intelset-test runs both branches' chain-listing cases (`test_live_chains`, `test_chains_live_more`)
under Round 3's rule: two chains with different digests, or one without, give no digest.

## Countries and networks on the page, the command line and in Help (design 13.16)

```sh
ninja -C build-linux fs-intelview-smoke fs-help-smoke stockfw stockfw-intel-test
xvfb-run -a ./build-linux/fs-intelview-smoke
xvfb-run -a ./build-linux/fs-help-smoke
bash tests/test-cli.sh
sudo bash tests/test-intel-cli.sh   # STOCKFW_INTEL_CLI must name a copy nobody can run
```

Everything here uses the signed test databases in `tests/geodb`
(`small.db`, `small-older.db`), signed with `k1`'s key.  The release
build pins IPFire's key and has no way to change it; the test builds
compile `fs-geodb.c` with `FS_GEODB_TESTING`, so `fs-intelview-smoke`
sets `k1.pub` with `fs_geodb_set_key` and replaces the downloader with
`fs_geodb_set_fetcher` (it xz's `small.db` in memory and counts the
requests), and `stockfw-intel-test` reads the key from
`$STOCKFW_TEST_GEODB_KEY` (an absolute path).  `test-intel-cli.sh`
section 10 serves the xz'd databases through a stand-in curl
(`STOCKFW_TEST_CURL`) that logs each request and prints the file;
curl runs as nobody, so the files are world-readable.

- `fs-intelview-smoke` (`check_geo`): the card's controls on Linux; no
  picker before consent; the licence line; the consent dialog's text
  (host, how often, what it learns, the licence as IPFire
  confirmed it, "registered in", anycast), Cancel (nothing downloaded),
  Accept (one download from the IPFire URL); the date and state; the
  picker's 7 countries and the "Example" AS search; Netherlands picked
  with "in": in force, its networks, and the "Anycast" chip whose
  tooltip reads "Includes 1 anycast network (IPv6) ..."; "de" typed in
  full (Germany, no chip); AS64500 picked from the search; three rules;
  text that names nothing; the lookup of `2c0f:f000::1` (the rule,
  "Registered in", anycast, the licence line); Remove (page, config and
  kernel); Update database (a second request); off (rules kept, sets
  gone); on again without a second dialog; a platform without it
  (the sentence `fs_intel_geo_unsupported_text()` and no control that
  acts).  GTK prints a Gdk-CRITICAL for an entry with a completion in
  an offscreen window at every allocation; the smoke drops only that
  message and fails on any other critical.
- `test-intel-cli.sh` section 1: `intel geo`, `geo status --json`,
  `geo terms`, `geo search` (exit 1), `geo on` without
  `--accept-terms` (exit 2, plain and JSON), `geo add` before consent
  (exit 2), `geo off` and an unknown action, none of which creates the
  store.  Section 10: `geo update` with the database off (exit 2, no
  request); `geo on --accept-terms` (no download by the switch);
  `geo update` (one request to the IPFire URL, `location.db` is the
  signed file, 0600), again (unchanged), `intel update` without
  `--now` (no request: at most daily); an older copy refused (exit 1,
  the copy in use byte for byte); `geo status` (date, stale, licence,
  counts, the refusal, the attribution; plain and JSON); `geo search`;
  `geo add` (named from the database, two ASes in one rule, a code the
  database lacks with its note, bad values exit 2); `geo list`;
  `geo remove` (and of a feed id: exit 2); `intel apply` (the
  country's networks in `s_country_netherlands_4`/`_6`, nothing of
  another country, the anycast note); lookups (exit 5 and "registered
  in" in JSON; "Registered in", the anycast network, the meaning and the
  attribution in text; NAT64; an address the database lacks; private
  space listed but never blocked; an AS rule); a damaged copy (unknown;
  restored with `cp` and `cmp`); `intel disable`/`enable` by a rule's
  id; `intel status --json`'s `location`; `geo on`/`add` as nobody
  (exit 3); `geo off` then `apply` (the sets leave the kernel, the
  lookup's `location` is null); on again; remove.
- `test-cli.sh` (no root, no download): `intel geo` with its sentence;
  `geo on` without consent (exit 2, nothing accepted); `geo add` before
  consent; `geo search` with no database (exit 1); consent then a rule
  (`no-database`); `intel status --json`'s `location`; a lookup with no
  copy (`found` false with the reason); `/api/intel`'s read-only
  `location` object.
- `fs-help-smoke` H8, above.

Each check below was seen failing with its bug put back in the source
(the original kept in a copy); the file was then restored from the
copy with `cp` and checked with `cmp`.  The table was re-run in full
after the work-in-progress commit, on the tree as committed.  `geo_pick`
in the smoke no longer emits "match-selected" for a row it did not
find: with the countries bug put back, the smoke used to crash on an
unset iterator instead of reporting the failures.  The eleven rows from "a location
rule's status" to "the card says an old copy" were added with the
review fixes and each was seen failing the same way.  The smoke reads
the completion's own filtered model (the tree view in its popup, after
`gtk_entry_completion_complete`), so the rows it counts are the ones
GTK offers, with the key GTK normalizes and casefolds.

| bug put back | test | check that fails |
|---|---|---|
| `geo on` without `--accept-terms` creates the store (`load_config (on, ...)`) | test-intel-cli.sh | `geo on without --accept-terms: exit 2, the terms shown, the flag named, no store` |
| `geo on` passes TRUE for the consent | test-intel-cli.sh | the same, and the JSON one |
| `geo add` creates the store before the consent check | test-intel-cli.sh | `geo add before consent: exit 2, no store` |
| the lookup's attribution line left out | test-intel-cli.sh | `lookup (plain) of the anycast network: Registered in, anycast, the meaning, the attribution` |
| the lookup's JSON `unknown` always false | test-intel-cli.sh | `the database damaged: lookup says unknown` |
| the lookup's JSON `via_nat64` always false | test-intel-cli.sh | `lookup of a NAT64 address: the IPv4 address's country and network, via_nat64` |
| the apply's anycast note never written | test-intel-cli.sh | `... and the apply says the Netherlands includes anycast networks` |
| `/api/intel` without its `location` object | test-cli.sh | `intel: the location fields, read-only (rules, database, attribution)` (and `intel status --json carries the location object`) |
| the page turns the database on without the consent dialog | fs-intelview-smoke | `geo: turning it on asks first: ...`, `geo: Accept turns it on and downloads it once` |
| the page never shows the anycast chip | fs-intelview-smoke | `geo: a rule whose set holds an anycast network carries the warning, with the count on hover` |
| the card's licence line empty | fs-intelview-smoke | `geo: the card carries the licence line` |
| the card's controls shown where the platform has none | fs-intelview-smoke | `geo: a platform without it shows its sentence (...) and no control` |
| the picker's countries never filled from the copy in use (`geo_fill_countries` returns at once) | fs-intelview-smoke | `geo: the picker lists the database's 7 countries, code and name`, `geo: "Netherlands (NL)" is in the picker's list`, and the add that follows |
| Block ignores the direction chosen (always both) | fs-intelview-smoke | `geo: its row says where the country's ranges are registered and the direction (...)` |
| a location rule's status "in-force" from StockFW's record alone (`location_status` ignores the overall state) | test-intel-cli.sh | `the table deleted by hand: geo list --json says not-in-force, never in-force` |
| `geo status` says an old copy is "still used by the rules" with the database off | test-intel-cli.sh | `geo status with the database off: out of date, never "still used"` |
| the picker's row keys lowered as ASCII (`g_ascii_strdown`, not `geo_fold`) | fs-intelview-smoke | `geo: an accented name completes typed in either case` |
| the completion's match function never matches | fs-intelview-smoke | `geo: the completion offers the Netherlands for "nl" ... and "Nether" ..., AS64500 for "64500"` |
| a name typed in full compared as ASCII (`geo_find_row` with `g_ascii_strcasecmp`) | fs-intelview-smoke | `geo: a name typed in full in another case finds its row and blocks AS64502` |
| Enter in the entry adds a rule while Block is greyed out | fs-intelview-smoke | `geo: Enter while Block is greyed out adds nothing` |
| the entry, direction and Block back on one line (entry 34 characters) | fs-intelview-smoke | `geo: the picker needs 623 px, within a 640 px window's card` |
| a rule's Remove button without its accessible name | fs-intelview-smoke | `geo: its Remove button's accessible name names the rule` |
| the anycast count only in the chip's tooltip | fs-intelview-smoke | `geo: the row says how many anycast networks in words, for the keyboard and screen readers` |
| a country rule's row without "Registered in" | fs-intelview-smoke | `geo: its row says where the country's ranges are registered and the direction` |
| the card says an old copy "is still used" with the database off | fs-intelview-smoke | `geo: turned off, the rules are kept, say they block nothing, ...` |
| the "Not in this build" callout put back on the threat-intel topic | fs-help-smoke | `[H8] no "Not in this build" callout in any topic ...`, `[H8] the threat-intel topic shows "Countries and networks" ...` |
| the anycast mark's name left out of the help | fs-help-smoke | `[H8] countries: the anycast warning and its mark` |
| the help says "not available on Windows yet" | fs-help-smoke | `[H8] countries: Windows does not support it, said as a limit` |

Not verified: a download from the real `location.ipfire.org` (every
test uses the test databases and a stand-in downloader); the page on
a desktop with a screen reader (it runs offscreen under Xvfb); the
time the per-rule statistics take for a large country of IPFire's full
database in the page; the card on Windows (checked through a
Windows-like backend on Linux).

## Release review: tool paths, the dashboard token, the Events page start (1.0.7)

- `test_toolpath` (`test-core.sh`): the Windows mapping of a bare tool
  name to System32 and the names it refuses; the fixed-directory search;
  as root, a fake `iptables-restore` first on `PATH` is not the one
  found.  Teeth: `fixed_dirs_only` returning FALSE fails the root check;
  `fs_toolpath_windows` returning the bare name fails the mapping.
- Spawn guard (`test-core.sh`): no `G_SPAWN_SEARCH_PATH` or
  `g_find_program_in_path` in the Linux backend, `fs-nftset.c`,
  `fs-cli-cmds.c` or `fs-dashboard.c`, and `spawn_capture` maps
  `argv[0]`.  Teeth: `G_SPAWN_SEARCH_PATH` put back in
  `run_command_quiet` fails it; `spawn_capture` running `argv[0]` as
  given fails it.
- Planted tools (`test-apply-linux.sh`, live, as root): fakes of every
  firewall tool first on `PATH`; none runs and the real
  `iptables-restore` loads the rules.  Teeth: `fixed_dirs_only`
  returning FALSE makes the fakes run and the rules stay unloaded.
  The drivers that need a fake tool first on `PATH` are test builds
  (`FS_TOOLPATH_TESTING`, see `CMakeLists.txt` and `test-apply-dual.sh`).
- Dashboard launch page (`test-cli.sh`, as `nobody` when run as root,
  with a fake `xdg-open`): the token is in none of xdg-open's
  arguments, the page is 0600 in a 0700 directory under
  `$XDG_RUNTIME_DIR` and redirects to the printed URL, and it is gone
  once the token is used.  Teeth: handing xdg-open the URL again fails
  five checks.
- Block-list findings (`test_threat_intel`, `test_sentinel_beacon` in
  `test-core.sh`): no What-If line and no block for traffic a list or a
  country or network rule dropped, also when an open beacon finding is
  updated.  Teeth: putting the What-If line back, or not clearing the
  earlier report's block, fails them.
- The Events page start (`fs-hitview-smoke`): the page is back before
  the history is read; the saved events and one that arrived meanwhile
  are listed, that one saved once.  Teeth: loading synchronously in
  `build_store` fails "built without waiting".  The retry after another
  copy let go (`check_history_retry`) lists the 50 older saved events
  and not the one newer than the list.  Teeth: a retry that installs the
  writer only lists 0 of 50; dropping the cutoff lists 51.

## Release packaging (`tests/test-release.sh`, 1.0.7)

```sh
cd port
bash tests/test-release.sh                     # source checks; the tarball too when build-linux/ is built
STOCKFW_BUILD_DIR=build-release STOCKFW_REQUIRE_PACKAGE=1 bash tests/test-release.sh   # as CI runs it
```

What it checks (architecture document 14.9):

- Version: every `#define FS_VERSION` fallback and `-DFS_VERSION`
  literal in `src/`, `tests/` and `tools/` equals `project(VERSION)`;
  `stockfw.rc.in` takes all four fields from `@PROJECT_VERSION*@`, is
  configured as CMake does it and compiled with windres (when
  installed); `StockFW.nsi` has no APP_VERSION of its own and stops
  without one; `build_installer.sh` passes `-DAPP_VERSION` and names no
  version; the Linux `LICENSE.txt` is a `@VERSION@` template; the Linux
  README names only this version and the tarball's real name.
- Docs: a `## [<version>]` section in `CHANGELOG.md`, which does not call
  the Copilot AI; the three asset names in `RELEASING.md`; every in-page
  link in `README.md` lands on a heading (GitHub's anchor rules).
- Modes: the shell entry points are executable on disk and 100755 in git.
- Windows installer, run on its own: the documentation step stages the
  root README and CHANGELOG byte for byte; the licence step writes the
  version and lists liblzma and OpenSSL libcrypto; with makensis,
  `StockFW.nsi` compiles with `-DAPP_VERSION` against stand-in stage
  files into `StockFW-<version>-Setup.exe` (file properties
  `<version>.0`), and fails without APP_VERSION or without
  `CHANGELOG.md`.
- Linux tarball, with a Linux build: the real packager into a scratch
  directory; `install.sh`, `StockFW` and `cli/stockfw` are
  `-rwxr-xr-x` in the archive and the documents `-rw-r--r--`; neither
  binary has `.symtab` or `.debug_info`; both report the version; the
  README, project README, changelog and licence are the real ones;
  `./install.sh` runs directly (as a non-root user, where it stops at
  its root check); the `.sha256` matches. The archive listing is printed.

`tests/test-linux-install.sh` (root, private mount namespace) also
checks that the install summary reports `nft` and `curl`, and, with a
stand-in `ldconfig` that hides `libcrypto.so.3`, that `install.sh` fails,
names the library and installs nothing. `tests/test-licence-texts.sh`
checks the version line of both licence files.

Teeth (each in a copy of the tree, restored with `cp` and checked with
`cmp`):

| Bug put back | Fails |
|---|---|
| `#define FS_VERSION "1.0.6"` in `main.c` | the `main.c` fallback, every FS_VERSION literal |
| `!define APP_VERSION "1.0.6"` in `StockFW.nsi` | no APP_VERSION of its own; makensis compile, output name, file properties |
| `FILEVERSION 1,0,5,0` in `stockfw.rc.in` | no literal version, all four fields, the configured `.rc` |
| the old documentation step (stub README) | stages the project README, stages CHANGELOG.md |
| makensis without `-DAPP_VERSION` | passes `-DAPP_VERSION` |
| OpenSSL missing from the Windows licence list | lists liblzma and OpenSSL libcrypto |
| liblzma missing from the Linux `LICENSE.txt` | the archive's licence lists them |
| `cp` of a 0644 `install.sh` in the packager | executable on disk, packages, `install.sh` is `-rwxr-xr-x` |
| the packager's `strip` line removed | no symbol table (both binaries) |
| the old `#threat-intel-blocklists-linux-107` anchor | every in-page link lands |
| no `## [1.0.7]` changelog section | the changelog section, packages, the archive's name |
| `libcrypto.so.3` dropped from `install.sh`'s list | (`test-linux-install.sh`) fails, names it, installs nothing |

## Release review: what StockFW contacts, credits, one test runner (1.0.7)

`tests/full-suite.sh` is the one runner on both platforms:

```sh
cd port
sudo xvfb-run -a bash tests/full-suite.sh   # Linux (build-linux/, or $STOCKFW_BUILD)
bash tests/full-suite.sh                    # Windows, MSYS2 UCRT64 (build/, or $STOCKFW_BUILD)
```

It configures the build directory if it is missing, builds every target
the suites run (the unit binaries, the Linux drivers, the UI smokes,
`fs-backend-probe`), exports `STOCKFW_BUILD` so every suite reads that
one build, and ends with PASS, FAIL or SKIP for each suite. Suites of
the other platform print SKIP; `fs-tray-smoke` runs on Windows (or with
`STOCKFW_TRAY_SMOKE=1`); `test-geodb.sh`'s fuzzer runs `FUZZ_SECONDS`
(30 by default here). Run as root on Linux, the live suites each make
their own private namespaces. Two checks depend on the host rather
than the code: `test-logstart-kmsg.sh` needs kernel log lines, which a
network namespace only produces with `net.netfilter.nf_log_all_netns=1`,
and `test-cli.sh`'s "interfaces lists at least one adapter" needs a
physical adapter, which a fresh network namespace does not have.

New checks in `test-core.sh` (end of the script):

- **wording guard**, widened: `src`, `docs`, `installer`, `../docs`, the
  README, `CHANGELOG.md`, `RELEASING.md`, `AUTHORS` and `CREDITS`;
- **credits guard**: no file in the repository (`git grep`) carries the
  creator's full name or e-mail address, and `AUTHORS`, `CREDITS`, the
  README and `fs-aboutdialog.c` name "Stockfw Team";
- **privacy guard**: Help > Your data names the location database next
  to the blocklists as a download, and the Threat Intel topic says no
  list *and not the location database* means no network request.

`test-state-windows.sh` prints SKIP off Windows; `test-linux-install.sh`
stages `install.sh` with the tested build's binaries, as the tarball
lays them out.

Teeth (each in a copy of one file, restored with `cp` and checked with
`cmp`):

| Bug put back | Fails |
|---|---|
| "AI-powered" line in `installer/build_installer.sh` | wording guard |
| the creator's surname in `AUTHORS` | credits guard (full name) |
| the old personal e-mail address in the README credits | credits guard (e-mail) |
| "Stockfw Team" removed from `CREDITS` | credits guard (credit line) |
| the old Help text (both sentences) | privacy guard, Your data |
| the old Threat Intel sentence only | privacy guard, Threat Intel |
| `test-state-windows.sh` without its platform guard | it fails on Linux (`windows.h`) |
| `fs-backend-probe` as an executable again | `ninja fs-backend-probe` fails to link |
| `sum` passed bare to `%s` in `ui-intelview-smoke.c` | `-Wformat-overflow` "argument is null" |
| the staged `StockFW` left out in `test-linux-install.sh` | `install.sh succeeds` fails |
