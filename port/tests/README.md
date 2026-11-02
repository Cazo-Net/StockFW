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
- D8: Save writes only values that changed, and only for rows that can
  act; a setting the platform does not offer keeps its stored value.

The settings apply itself (`fs_settings_apply_safe`) is covered in
`test-core.sh`: an unchanged policy is applied whole under the new
settings, a failure is rolled back under the previous ones and
verified, and the audit log names it.

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
