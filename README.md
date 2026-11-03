<p align="center"><img src="logo.png" alt="StockFW logo" width="140"></p>

# StockFW

**Smart firewall configuration tool with a local, rule-based Copilot.**
GTK3 · Windows and Linux · status, live events, policy editing, and a
Copilot page that checks the event log and the policy with fixed rules,
shows the evidence, and simulates rules, entirely offline.

StockFW makes a stock OS firewall *legible*: policy as a readable, diffable
CSV; events as a classified, searchable stream; advanced knobs in one
dialog; and a Copilot layer that can answer "why is this blocked?"
(analysis), "what would happen if?" (what-if simulation) and propose
rules — without a shell prompt.

## Features

- **Status** — real profile state at a glance: on Windows the three
  firewall profiles (Domain, Private, Public) with enable/disable, on
  Linux the filter-table posture. The app's logo is embedded in the
  executable, so an installed copy and a development build render
  identically. Icons are real GTK stock/themed icons — no emoji, ever.
- **Events** — a live, deduplicated event stream. On Windows: Security
  log 5156/5157 (connection allowed/blocked) parsed from
  `wevtutil /f:text`, polled every 5 seconds with a batch cap. On Linux:
  kernel drop logging. Rows are classified, and a **filter bar** narrows
  the list as you type (case-insensitive, any field — the count label
  shows *"3 of 1200 events"* so an empty result is never mistaken for an
  idle firewall). **Right-click any row for one-click Event → Rule**:
  block/allow that destination, block this service to it, or trust an
  inbound source — where the kind has an opposite-direction twin the
  confirm dialog carries the **Direction** setting (one direction by
  default, **Bi-directional** stages the twin as the same change),
  every action confirms, saves with rollback if the write fails, and
  reports honestly whether it is live or only staged.
  The list is a window over the OS log — the OS log remains the archive.
- **Sentinel** — detect *and* auto-block rogue-agent behavior in the
  event feed: **periodic beacons** (metronomic egress to one host:port —
  a covert-channel signature; jitter, polled batches and inbound traffic
  don't trip it) and **fan-out scans** (60+ distinct destinations in 60
  seconds, or 10 distinct blocked ones). In auto mode a beacon's
  ready-made deny is staged into the policy and pushed with a
  **10-minute time-box** plus one-click Undo — auto-block can only ever
  tighten policy, never open it, and user-authored rules are never
  touched. Detect-only mode reports without staging. Every stage, push,
  undo and expiry is written to an append-only `audit.log`.
- **Policy** — add / edit / duplicate / delete rules with **round-trip
  CSV save/load**: what you save is what loads back, typed and validated
  (ports, addresses, protocols checked fail-closed — IPv4/IPv6/CIDR and
  port ranges included). The pairable allow kinds carry a **Direction**
  setting: the default is one direction (*Outbound only*, or *Inbound
  only* on the inbound groups), and **Bi-directional** stages the
  opposite-direction twin as one all-or-nothing save — if the write
  fails, neither half stays.
- **Copilot** — a **local, rule-based** page: fixed checks, no model,
  no network. **Findings** from the event log (inbound port scans,
  repeated attempts on a login port, new destinations for a known app,
  contacts at a near-fixed interval, block-list hits, fan-out, rate
  spikes), each with a severity word, an evidence drawer (the events,
  why it was flagged with the numbers and limits, why it could be
  harmless, what Sentinel did) and actions (a block offered only when
  What-If confirms it, Ask What-If, Show in Events, Dismiss).
  **Policy health** reports duplicate, shadowed, unreachable and
  no-effect rules, broad allows, risky services open to the internet
  and denies that reach no address family; a fix is offered only when
  the What-If engine has checked it, and it asks first. **Changes made
  by the Copilot** lists every auto-block and fix with Undo. Sentinel
  is a two-way switch: Detect only, or Detect + auto-block (outbound
  blocks to unknown public addresses, for 10 minutes). No finding is
  not a guarantee that nothing is wrong, and the page says so. On
  Linux the kernel log names no program, so the Copilot learns per
  service there, and it sees allowed traffic only when allowed-event
  logging is on. `stockfw copilot health [--json]` runs the policy
  check from the command line (exit 7 with findings) and writes
  nothing. The
  **What-If Simulator** takes a line like *"allow SSH from
  192.168.1.50 on port 22"* and answers **BLOCKED/ALLOWED** against
  the real policy: block rules take precedence the way Windows
  Firewall resolves them, a shadowed allow is called out as shadowed,
  a `/24` block covers the hosts inside it, and the line itself writes
  nothing — it is a question, not a change. It reads the shapes people
  type: *ssh is open at 22 port*, *port 80*, *:22*, *local:22*,
  *rdp* → 3389, *ping* → ICMP. The card keeps the line, shows how it
  was read as chips (direction, protocol, port or service, host and
  whether it is on the LAN or the Internet), answers in one row
  (badge, one line, **Details**) and keeps the last five questions.
  **Details** opens the **What-If window** beside the page (not
  modal): the verdict and the question in plain words, an animated
  diagram (this computer, the StockFW wall, the LAN or Internet host;
  a still final frame when animations are off), the facts, *Why* (the
  rules in the order the firewall checks them, the deciding one
  highlighted and linked to its row on the Policy page) and *What you
  can do*: one button per fix the engine verified, such as **Create
  allow rule** with the exact row shown, which asks before anything
  is written.
  **No network, no telemetry.**
- **Activity** *(1.0.6)* — two graphs over 15 minutes to 24 hours:
  **Policy activity** (events per minute, allowed and blocked; blocked
  only on Linux, whose kernel log never carries accepts) and **Network
  I/O** (throughput for all adapters or one). Events count at their own
  time, the stretch before the app started is shaded *no data* rather
  than drawn as a quiet zero, a crosshair reads any interval (mouse or
  arrow keys), and every graph has a table view.
- **Command line and local dashboard** *(Linux, 1.0.6)* — `stockfw`
  drives the same policy files, what-if simulator and apply gate as the
  desktop app: `status`, `policy list|add|remove`, `apply [--dry-run]`,
  `simulate`, `events [-f]`, `connections`, `interfaces`, every one with
  `--json` and stable exit codes (`simulate` exits 5 when the traffic
  would be blocked). `stockfw dashboard` serves a read-only web
  dashboard on **127.0.0.1 only**, behind a token that changes every
  run, with the same graphs, live events, connections, the simulator
  and the policy — see [below](#command-line-and-dashboard-linux).
- **Threat-intel blocklists** *(Linux, 1.0.7, opt-in)* — block
  addresses that well-known public lists name as hijacked networks,
  botnet servers or attackers, plus your own lists, in the kernel
  before the policy sees a packet. Every feed is off until you turn it
  on and accept its terms; with nothing on, StockFW makes no network
  request. A **Threat Intel** page, `stockfw intel` and a read-only
  dashboard card — see [below](#threat-intel-blocklists-linux-107).
- **Preferences** — what you see is what you save: pages that do not
  apply to the current backend are not shown, so there are no dead
  settings that silently do nothing.

## Backends

| | Windows | Linux |
|---|---|---|
| Rule application | `netsh advfirewall` | `iptables` (argv, no shell) |
| Event source | Security log 5156/5157 | kernel log |
| Profiles | Domain / Private / Public per-profile state | filter table |
| Build | MSYS2 (UCRT64) | CMake + Ninja (Debian/Kali/WSL2) |
| IPv6 | Filtered (Windows Firewall covers both families) | Filtered (1.0.7): the same policy is loaded into `iptables` and `ip6tables` |

**IPv6 on Linux (1.0.7).** One apply loads the policy into both families
with `iptables-restore` and `ip6tables-restore`, each replacing only
StockFW's own chains in one atomic step. If the IPv6 half is refused, the
IPv4 half is put back, so the kernel never runs half of a new policy.
Each address goes only to its own family; a host name is looked up once
when you apply and written as its IPv4 and IPv6 addresses. Neighbour
discovery, router adverts, path-MTU and DHCPv6 are always allowed, even
in restrictive mode, because IPv6 does not work without them. Without
`ip6tables` installed, the apply reports that IPv6 is not filtered.

## Threat-intel blocklists (Linux and Windows, 1.0.7)

StockFW can block the addresses on public threat-intel lists ("feeds")
and on lists you make yourself, on Linux and on Windows. The Windows
side is built and compiled but has not yet been run on a real Windows
computer (see *On Windows* below).

**How it works.** Each list you turn on is downloaded from its own
publisher over HTTPS, checked, stored under `/var/lib/stockfw/intel`
(root only) and loaded into one nftables table of StockFW's own,
`inet stockfw_intel`. That table is checked before the iptables policy,
and a policy apply never touches it. Blocked packets are logged with the
list's name, so on the Events page a block reads *Threat intel: <list>*.

**On Windows.** The same page, the same feeds and the same checks.
The lists are stored under `%ProgramData%\StockFW\intel` (Administrators
and SYSTEM only) and enforced as block rules of StockFW's own in Windows
Firewall. Changing anything needs StockFW to run elevated. Windows
Firewall keeps no per-rule counts, so where Linux says *Blocked N
packets* the page says why there is no number, and the Blocked tile
reads *n/a*. When the rules are there but Windows Firewall is not
enforcing them (the service stopped, a profile off, or Group Policy in
charge) the page says *Not in force* and why; rules changed by someone
else read *Changed outside StockFW*. The `stockfw` command is built on
Linux only.

### Turning it on

You need root, `nft` (the `nftables` package) and `curl`.

In the desktop app, open **Threat Intel** in the sidebar and switch a
feed on. A dialog first tells you which host it is downloaded from, how
often, what that host learns (this computer's public address and
"StockFW/<version>"), its licence and terms. Nothing is downloaded until
you accept. While the app is open it checks every hour for feeds that
are due. Changing a list needs the app to run as root; otherwise the
page says *Needs administrator rights*.

From the command line:

```sh
stockfw intel feeds                                   # every feed, its licence and credit
stockfw intel terms spamhaus-drop                     # what turning it on means
sudo stockfw intel enable spamhaus-drop --accept-terms
sudo stockfw intel update                             # download the feeds that are due
sudo stockfw intel apply                              # load the lists into the kernel
sudo stockfw intel status                             # protected? which lists, how many blocks
sudo stockfw intel lookup 203.0.113.7                 # which lists hold it; exit 5 if the kernel blocks it now
sudo stockfw intel except 203.0.113.7                 # a mistake: never block this address
sudo stockfw intel import mylist.txt --name "My list" # your own list, no network
```

`stockfw help intel` lists every action. Each one takes `--json`.
Downloads connect to each feed's host directly. Behind a proxy, set it
with `sudo stockfw intel proxy http://proxy.example:3128` (`none` removes
it); it is kept as `[intel] proxy=` in `/var/lib/stockfw/intel/intel.conf`
and `stockfw intel status` shows it.
`feeds` and `terms` work without root until something is turned on.
After that the store is root-only, so every `stockfw intel` command
needs sudo.

`stockfw intel update` can run from cron or a systemd timer. It loads
the new copies only while the firewall runs, the lists are already
loaded and audit-only mode is off. Otherwise it stores them and says
why it did not load them.

**Direction.** *in* stops listed addresses connecting to you, *out*
stops you connecting to them, *both* does both. Outbound blocks are
rejected so programs fail at once instead of hanging.

**After a reboot** nothing is loaded, policy or lists, until the
firewall is started again (Status page, `stockfw start`, or
start-on-open). Start loads the lists with the policy, and Stop removes
both.

### The feeds

| Feed (`id`) | What it lists | Licence / terms | Commercial use | Credit |
|---|---|---|---|---|
| Spamhaus DROP, IPv4 (`spamhaus-drop`) *recommended* | Networks hijacked or run by spammers and cyber-criminals. Daily, both directions | free; [Spamhaus DROP terms](https://www.spamhaus.org/drop/terms/) (no licence named) | not restricted; credit Spamhaus | The Spamhaus Project, spamhaus.org (DROP) |
| Spamhaus DROP, IPv6 (`spamhaus-dropv6`) *recommended* | The IPv6 part of DROP. Daily, both directions | as above | not restricted; credit Spamhaus | The Spamhaus Project, spamhaus.org (DROPv6) |
| abuse.ch Feodo Tracker (`feodo`) *recommended* | Botnet command-and-control servers seen active recently. Every 6 h, both directions | CC0 ([abuse.ch terms](https://abuse.ch/terms-of-use/)) | allowed | abuse.ch Feodo Tracker, feodotracker.abuse.ch |
| DShield top attackers (`dshield`) | The 20 /24 networks that attacked DShield sensors most over three days. Daily, inbound | CC BY-NC-SA 2.5 | **non-commercial only** | DShield.org, SANS Internet Storm Center |
| FireHOL level 1 (`firehol-level1`) | An aggregate of Spamhaus DROP, DShield, Feodo Tracker and unroutable space. Daily, inbound; fetched from raw.githubusercontent.com | no licence of its own; [see the repository](https://github.com/firehol/blocklist-ipsets) | **non-commercial only** (it contains DShield's list) | FireHOL IP lists, iplists.firehol.org |
| blocklist.de (`blocklist-de`) | Addresses that attacked servers reporting to blocklist.de (fail2ban and similar) in the last 48 hours. Daily, inbound | [blocklist.de terms](https://www.blocklist.de/en/terms.html) (no licence named) | see terms | blocklist.de |
| Emerging Threats compromised hosts (`et-compromised`) | Hosts seen compromised and attacking others. Daily, inbound | no licence published ([community thread](https://community.emergingthreats.net/t/licensing-is-the-compromised-ips-list-also-open/676)) | see terms | Emerging Threats, emergingthreats.net |
| CINS Army (`cins-army`) | Up to 15,000 addresses with the poorest reputation in the CINS network. Daily, inbound | no licence named ([cinsscore.com](https://cinsscore.com/)) | see terms | CINS Army list, cinsscore.com |
| Tor exit relays (`tor-exits`) | The relays Tor traffic leaves from. This is a choice about Tor users, not protection from a threat. Every 6 h, inbound | no licence named ([bulk exit list](https://check.torproject.org/api/bulk)) | see terms | The Tor Project, check.torproject.org |

The direction shown is the default; `stockfw intel enable ID
--direction in|out|both` chooses another (the page uses the default).
The update interval is fixed per feed (24 hours for a feed you add
yourself).

The lists and their data belong to their publishers. StockFW only
downloads them for you, from each publisher and from no mirror. The
page, `stockfw intel feeds` and the dashboard show each list's licence
(or "see terms"), whether it is non-commercial, and its credit line.
Before turning on a non-commercial list on a business computer, get the
publisher's permission. A licence is named only where the publisher
names one. You can also add your own feed by URL (`stockfw intel
add-feed`, HTTPS only).

### What it does and does not do

It does:

- block every address on the lists you turn on, IPv4 and IPv6, in the
  directions you choose, and count the blocks ("blocked N since
  <date>");
- never block what this computer needs: its own addresses and network,
  gateways, DNS servers, your SSH session, the feed servers themselves,
  special-purpose ranges and your allow list. `apply` says when a list
  named any of these;
- refuse an update that looks wrong, keeping the copy you had: a list
  that suddenly shrinks or empties, one older than the copy you have,
  one whose coverage jumps, entries wider than a /10 (IPv4) or /29
  (IPv6), or a body that is not a list. The page offers *Accept smaller
  list* or *Accept larger list*, and `stockfw intel update` prints the
  flag to use;
- show what the kernel is really doing: *Protected*, *Not loaded*
  (after a reboot or a `flush ruleset`), *Paused* (the firewall was
  stopped), or *Changed outside StockFW*, never only what is
  configured.

It does not:

- filter domains or URLs, inspect traffic, or detect intrusions. It
  blocks IP addresses that the lists name, and nothing else;
- make the lists right. Lists contain mistakes and go stale, and a
  blocked address may be a shared host you need. Use the allow list or
  `stockfw intel except`;
- verify signatures, because no feed publishes them. Integrity rests on
  HTTPS to the publisher and the update checks above;
- keep a key secret. curl gets the feed URL on its command line, which
  other local users can read while a download runs. Do not put a
  secret in a custom feed's URL. A proxy with a user name and password
  in it is refused;
- answer from What-If, Copilot or `stockfw simulate` yet: these still
  judge the policy alone. Ask `stockfw intel lookup` or the page's
  lookup box;
- block by country or network owner, on either platform. That is a
  later round.

## Running in the background, and after a reboot (1.0.7)

One StockFW runs per user (on Windows, per sign-in session): starting
it again brings the running copy's window forward, wherever it is (on
Linux a launch on a second display of the same user shows the first
copy rather than opening another), and `StockFW --quit` asks it to quit
cleanly (the firewall stays on). A launch with more rights than the
running copy (`sudo StockFW`, or StockFW (Elevated) on Windows, while
the sign-in copy runs) asks that copy to quit and takes its place, so
the copy you started with rights is the one that runs. `StockFW --background` (or
`--minimized`) starts it in the notification area with the window
hidden; if no notification area takes the icon within five seconds the
window is shown instead, so it is never running out of reach.

**Start at sign-in** (tray menu, the Background card on Preferences >
General, or `--enable-autostart` / `--disable-autostart`; the tray's
tick and the Preferences switch always show the same thing):

- Windows: a Task Scheduler task for the signed-in account, in the
  `\StockFW` folder, runs `StockFW.exe --background` at sign-in WITHOUT
  administrator rights, so it shows the firewall's state but cannot
  change it or watch blocked traffic; start StockFW (Elevated) for that,
  and it takes over from the sign-in copy. It never runs elevated
  without a prompt: that would let anything running as you get
  administrator rights at your next sign-in. Changing it needs StockFW
  running as administrator. The installer offers it as a component
  (ticked by default) and the uninstaller removes it. Windows Firewall
  keeps its rules across reboots by itself.
- Linux: `~/.config/autostart/stockfw.desktop`. The desktop starts it
  without root, so it can neither read nor change the rules nor watch
  blocked traffic: it shows the firewall's state as unknown (never as
  Off), and greys what it cannot do. `sudo StockFW` takes over from it.

**Linux rules vanish at reboot** unless something loads them again: the
kernel keeps iptables rules in memory only. The Linux installer installs
and enables `stockfw.service`, which runs `stockfw start` before the
network comes up, using root's policy in `/etc/stockfw` (the one
`sudo StockFW` edits; a policy in `~/.stockfw` is not used). It puts
back the last policy that was applied, never changes saved since but
not applied. It does nothing until a policy has been applied as root
once, has no stop action, and leaves out blocks by host name until the next apply because
names cannot be looked up before the network is up. Details:
[`port/installer/linux/README.md`](port/installer/linux/README.md).

**Signing out does not lose anything.** While it runs, StockFW writes
its settings and what the Copilot has learned every five minutes when
they have changed, and writes everything when the session is about to
end (Windows sign-out or shutdown, a GNOME or Xfce logout) without
holding the logout up. `kill`, Ctrl+C and closing its terminal quit it
the same way as the tray's Quit. None of this turns the firewall off.

## Privilege model (summary)

StockFW runs **asInvoker** — it never silently self-elevates. All
elevation is explicit and fail-loud: operations that need admin surface a
clear error instead of half-applying; the elevated helper shares no
injected environment module; temp files are share-locked; strings passed
back to the shell are quoted with a strict inverse-quoting check. The
full property-by-property verification (ten properties, file:line
evidence) is in
[`docs/ARCHITECTURE-AND-SECURITY.md`](docs/ARCHITECTURE-AND-SECURITY.md)
Chapter 5.

## Build

### Windows (MSYS2, UCRT64)

```sh
pacman -S --needed base-devel \
    mingw-w64-ucrt-x86_64-{toolchain,gtk3,pkg-config,ninja,cmake}

cd port
cmake -S . -B build -G Ninja
cmake --build build
./build/StockFW.exe
```

Run the toolchain from the UCRT64 shell.

### Linux (Debian / Kali / WSL2)

```sh
sudo apt install build-essential cmake ninja-build libgtk-3-dev

cd port
cmake -S . -B build-linux -G Ninja
cmake --build build-linux
./build-linux/StockFW
```

### Command line and dashboard (Linux)

The Linux build also produces `build-linux/stockfw`:

```sh
./build-linux/stockfw status
./build-linux/stockfw policy add inbound-allow-service ssh   # SSH, port 22, anyone
./build-linux/stockfw simulate "inbound ssh from 203.0.113.5" # exit 5 if blocked
sudo ./build-linux/stockfw apply --dry-run                    # impact preview only
sudo ./build-linux/stockfw events -f --json                   # NDJSON, live
./build-linux/stockfw dashboard                               # opens the browser
```

The dashboard's security model: it binds 127.0.0.1 and nothing else;
each run makes a 128-bit token, passed in the URL fragment (never sent
to the server or logged) and then as a request header compared in
constant time; the `Host` header must name 127.0.0.1 or localhost on
its port, so a DNS-rebinding page cannot reach it; GET and HEAD only,
a 16 KB cap on request heads, a 10 s timeout and 32 connections at
most; a per-run CSP nonce with `default-src 'none'`; and it never opens
a browser as root. It is read-only: changes go through `stockfw policy`
and `stockfw apply`, which use the same gate as the desktop app.

### Installer (Windows, NSIS)

```sh
cd port/installer
./build_installer.sh
```

The installer bundles the full GTK3 runtime and the spawn helpers into
`$INSTDIR` and fails the build if any staged launcher still carries the
old branding.

## Tests

Every claim in the documentation is graded `[Verified]` / `[Measured]` /
`[Roadmap]` and maps to something you can run:

```sh
cd port
bash tests/full-suite.sh             # every suite below, one pass, one verdict
bash tests/test-core.sh              # rule engine, CSV, copilot detections + policy health, sentinel, event-rule, what-if, direction pairing
bash tests/test-winlog.sh            # Security-log parsing + dedup
bash tests/test-logstart.sh          # event stream start-up
bash tests/test-installer-spawn.sh   # staged spawn helpers
bash tests/test-state-windows.sh     # per-profile backend compile
bash tests/test-uaf-analyze.sh       # analyzer proves the UAF fix
bash tests/test-cli.sh               # Linux: stockfw CLI + dashboard security model
bash tests/test-intel-cli.sh         # Linux, root: stockfw intel end to end (private namespaces)

ninja -C build fs-ui-smoke fs-hitview-smoke fs-activity-smoke
./build/fs-ui-smoke                  # UI wiring smoke
./build/fs-hitview-smoke             # hit-view rendering + filter smoke
./build/fs-activity-smoke            # Activity page: counting, no-data, drawing
```

The suites include *teeth* tests: known bugs are re-injected to prove the
test fails, then removed to prove it passes again — a green suite that
cannot fail is not a green suite.

## Documentation

- [`docs/ARCHITECTURE-AND-SECURITY.md`](docs/ARCHITECTURE-AND-SECURITY.md)
  — full architecture and security document: data flow, backends,
  privilege model with file:line evidence, findings register,
  measurements (150 s memory soak), roadmap.
- [`docs/PORTING.md`](docs/PORTING.md) — porting notes and prerequisites.
- [`port/docs/ELEVATED.md`](port/docs/ELEVATED.md) — the elevated helper
  protocol.

## License

The repository currently carries two license texts: root `LICENSE`
(Apache-2.0) and root `COPYING` (GPLv2, inherited). Which license
governs which portions is an open provenance-review item, tracked in
Chapter 10 of the architecture document. Contributions are accepted under
the license ultimately declared for their portion.

## Credits

- **Qusai** Qusaifox2@gmail.com — Creator & Original
  Developer
- **H3xCore** — Developer
- **StockFW Project** — GTK3 port, Windows backend, Copilot
- **Threat-intel data** — the blocklists belong to their publishers:
  The Spamhaus Project, abuse.ch, DShield.org (SANS Internet Storm
  Center), FireHOL IP lists, blocklist.de, Emerging Threats, CINS Army
  and The Tor Project. StockFW does not ship their data; it downloads
  a list only after you turn it on (see
  [Threat-intel blocklists](#threat-intel-blocklists-linux-107)).
