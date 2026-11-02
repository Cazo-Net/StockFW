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
| start on open | the app starts the firewall only after the policy is loaded and Sentinel's expired blocks are out of it (read from `fs-app.c`) |

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

The settings apply itself (`fs_settings_apply_safe`) is covered in
`test-core.sh`: an unchanged policy is applied whole under the new
settings, a failure is rolled back under the previous ones and
verified, and the audit log names it.

The footer's Help button is checked to be there on both platforms'
page sets; what it opens is checked in `fs-help-smoke` below.  The
About credits are checked here too: the creator line reads exactly
"Stock Team & Qusai - Creator & Original Developer", and no credit
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
  the page shown; so does the sidebar's Help item.  Ctrl+W closes it.
  (Re-injected: the action not registered; the accelerator on F2.)
- H2: every topic in `fs-helpcontent.c` renders, with its title and
  every block on screen; every string parses as GtkLabel markup, every
  `help:` link and related topic names a real topic, and there is no em
  dash.  (Re-injected: callouts not rendered; an unclosed `<b>`; a
  link to `help:troubleshoot`.)
- H3: search filters the topic list ("SSH locked" lists Troubleshooting
  and leaves Activity out), finds subtopics, says when nothing
  matches, opens the first match on Enter and is cleared by Escape.
  (Re-injected: every topic matching.)
- H4: links, related-topic chips, Next, the breadcrumb, the sidebar,
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
  one at a time; the first credit reads exactly "Stock Team & Qusai -
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

The prefs smoke's Help-button check was seen failing with the button
left out of the footer.

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
