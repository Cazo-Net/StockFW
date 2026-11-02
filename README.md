<p align="center"><img src="logo.png" alt="StockFW logo" width="140"></p>

# StockFW

**Smart firewall configuration tool with a local AI copilot.**
GTK3 · Windows and Linux · status, live events, policy editing, and a
Copilot page that analyzes, explains and simulates rules — entirely
offline.

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
- **Copilot** — a **local, deterministic** analysis page, no LLM. Policy
  Analysis reads the event feed and your rules and proposes the exact
  firewall rule it would install, shows it in a Yes/No dialog before
  anything is written, is **allow-only** (it can never silently open
  more than you approve), and rolls back if the save fails. The
  **What-If Simulator** takes a line like *"allow SSH from
  192.168.1.50 on port 22"* and answers **BLOCKED/ALLOWED** against
  the real policy: block rules take precedence the way Windows
  Firewall resolves them, a shadowed allow is called out as shadowed,
  a `/24` block covers the hosts inside it, and the line itself writes
  nothing — it is a question, not a change. It reads the shapes people
  type: *ssh is open at 22 port*, *port 80*, *:22*, *local:22*,
  *rdp* → 3389, *ping* → ICMP. The verdict then plays in the
  **Simulation Visualizer** — a small modal window that animates
  source → firewall → destination (the packet travels; the wall
  answers with a green check or a red shake; a blocked packet bounces
  back and the far line grays out), shows the parsed packet details
  and the reason in plain English, and offers **Create This Rule**,
  which prints the literal rule, asks, and only then stages it.
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

**Start at sign-in** (tray menu, or `--enable-autostart` /
`--disable-autostart`):

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
bash tests/test-core.sh              # rule engine, CSV, copilot, sentinel, event-rule, what-if, direction pairing
bash tests/test-winlog.sh            # Security-log parsing + dedup
bash tests/test-logstart.sh          # event stream start-up
bash tests/test-installer-spawn.sh   # staged spawn helpers
bash tests/test-state-windows.sh     # per-profile backend compile
bash tests/test-uaf-analyze.sh       # analyzer proves the UAF fix
bash tests/test-cli.sh               # Linux: stockfw CLI + dashboard security model

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
