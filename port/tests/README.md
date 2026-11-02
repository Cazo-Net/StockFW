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
| push | no start at launch, firewall running: the expired Sentinel block is pushed off the firewall through the apply gate |
| stopped | no start at launch, firewall stopped: nothing is applied, so a stopped firewall is never started behind the user's back |

Up to 1.0.7 the start ran before the Policy page loaded the policy, so
on Linux it installed an empty one, and Sentinel's restore took expired
blocks out of the file without ever pushing that change.

Teeth: put the start back above the Policy page in `fs-app.c` and
"start" fails with 0 rules at start; drop the push in
`start_at_launch()` and "push" fails.  `tests/test-core.sh` pins the
start gate itself (`fs_firewall_start_safe`) and the boot-time expiry
of Sentinel rows (`fs_autoblock_expire`).


## One StockFW per session (`tests/test-instance.sh`)

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
user's logon, in their session (`InteractiveToken`), elevated
(`HighestAvailable`), with no time limit and on battery.  It also pins
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
the held change.

`test-linux-install.sh` runs `install.sh` and the `stockfw-uninstall`
it writes for real, in a private mount namespace with a scratch PREFIX
and a tmpfs over `/etc/systemd/system`: the unit is installed pointing
at the installed `stockfw` and enabled, and the uninstaller disables
and removes it.

Teeth: drop the Sentinel expiry from `stockfw start` and three checks
fail; start without the hold and the audit-only checks fail; leave the
`systemctl disable` out of the uninstaller and "disabled" fails (a
dangling enable link counts as still enabled).
