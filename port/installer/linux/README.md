# StockFW for Linux

Firewall configuration tool for Linux, driving `iptables`.

    StockFW 1.0.6 (Linux (iptables) backend)

## Install

    tar xzf StockFW-1.0.6-linux-x86_64.tar.gz
    cd StockFW-1.0.6-linux-x86_64
    sudo ./install.sh

This installs:

    /usr/local/bin/StockFW                              the application
    /usr/local/bin/stockfw                              command line + dashboard
    /usr/local/share/applications/stockfw.desktop       menu entry
    /usr/local/share/icons/hicolor/{48x48,128x128,256x256}/apps/stockfw.png
    /usr/local/share/doc/stockfw/LICENSE.txt
    /usr/local/bin/stockfw-uninstall                    removal script
    /etc/systemd/system/stockfw.service                 puts the rules back at boot (enabled)

The installer checks that every runtime library the binary links against
is present, by soname. It reports sonames rather than package names
because those differ between distributions: Debian and Ubuntu renamed
`libgtk-3-0` to `libgtk-3-0t64` in their time64 transition, so a
package-name check would wrongly report a working system as missing.

If a library is absent, install it with your package manager:

    Debian / Kali / Ubuntu:  sudo apt install libgtk-3-0 libgdk-pixbuf-2.0-0
    Fedora:                  sudo dnf install gtk3
    Arch:                    sudo pacman -S gtk3

`iptables` is checked separately and only warns if missing: the
application still runs and can read, simulate, and display policy; only
applying rules needs it.

## Run

    StockFW          read-only: status, events, policy, simulation
    sudo /usr/local/bin/StockFW     the full tool, including applying rules

Use the full path with `sudo`. `sudo` runs commands with its own search
path (`Defaults secure_path` in `/etc/sudoers`), which on Debian and Kali
is typically `/usr/sbin:/usr/bin:/sbin:/bin` and does **not** include
`/usr/local/bin`. On such a system the shorter `sudo StockFW` reports
"command not found" even though plain `StockFW` works — because your
login shell's PATH includes `/usr/local/bin` while sudo's does not.

If `sudo StockFW` works on your system, keep using it; the full path is
always correct either way. This installer does not edit `/etc/sudoers`:
widening `secure_path` so that one tool can be found would widen it for
every command on the system, which is a worse trade than typing the
path.

The Linux backend invokes `iptables` directly and expects to already be
running as root. It does not re-exec itself through `sudo`, and the
installer deliberately ships no polkit policy or setuid wrapper: a GUI
able to silently rewrite the entire firewall is a worse security posture
than one that asks for root openly. Grant privilege by launching with
`sudo`, or through your desktop environment's own mechanism.

## After a reboot: the boot service

Linux keeps firewall rules in the kernel only. **A reboot empties
them**: without something to load them again, the machine runs
unfiltered until someone starts StockFW with `sudo` again.

`install.sh` therefore installs and enables `stockfw.service`, which runs
`stockfw start` once at boot, before any network interface comes up
(`Before=network-pre.target`). What it does:

- It uses root's StockFW files, the ones `sudo /usr/local/bin/StockFW`
  uses: the policy in `/etc/stockfw` and the preferences in
  `/root/.config/stockfw`. A policy edited by StockFW running **without**
  sudo lives in `~/.stockfw`; the service does not see it.
- It does nothing until a policy has been applied as root at least once
  (`/etc/stockfw/applied.csv` exists), so installing StockFW never
  firewalls a machine nobody has set up yet.
- It starts the last policy that was **applied**, never changes saved
  but not applied (held by audit-only mode or the Policy Lock, or simply
  never applied): those wait for the next apply. Sentinel blocks whose
  ten minutes ran out while the machine was off are not put back.
- It has no stop action. `systemctl stop stockfw` and shutting down
  never take the rules away; `sudo stockfw stop` does.
- A block by host name cannot be looked up before the network is up, so
  it is left out at boot (`journalctl -u stockfw` names it) and goes in
  with the next apply (`sudo /usr/local/bin/stockfw apply`, or applying
  from StockFW).

Without systemd the installer says so, and the rules do not come back
after a reboot on their own: run `sudo /usr/local/bin/stockfw start`
from your init system's boot scripts.

    systemctl status stockfw          did it run at boot, and what it said
    sudo systemctl disable stockfw    stop loading the rules at boot

## Start at sign-in

"Start at sign-in" in StockFW's tray menu, or "Start StockFW in the
background when I sign in" on Preferences > General (or `StockFW
--enable-autostart`), adds `~/.config/autostart/stockfw.desktop`, which
starts `StockFW --background` in the notification area when you sign in
to the desktop. The desktop starts it as you, **without root**: it shows
the firewall's state as unknown, because iptables cannot be read
without root, and cannot change rules or watch blocked traffic.
`sudo StockFW` takes over from it (the copy without root quits).
The rules themselves come from the boot service above, not from this;
the note under the Preferences switch says whether that service is
enabled, installed but not enabled, or missing.
When StockFW runs with `sudo`, the entry is still written into your own
home, as you. `StockFW --disable-autostart` removes it.

## Command line and dashboard

`stockfw` drives the same policy files, simulator and apply gate as the
desktop app, from a terminal or a script:

    stockfw status                         state, policy, monitoring
    stockfw policy add inbound-allow-service ssh
    stockfw simulate "inbound ssh from 203.0.113.5"      # exit 5 if blocked
    sudo /usr/local/bin/stockfw apply --dry-run          # impact preview
    sudo /usr/local/bin/stockfw events -f                # follow live
    stockfw dashboard                      local web dashboard

Every command takes `--json`.  `stockfw help <command>` has the details.

`stockfw dashboard` serves a read-only page on 127.0.0.1 only, behind a
token that changes every run, and opens it in your browser (never as
root: under `sudo` it prints the address instead).  The same `sudo`
search-path note as above applies: use `sudo /usr/local/bin/stockfw`.

## Uninstall

    sudo stockfw-uninstall

Removes exactly what `install.sh` created, disables the boot service,
asks a running StockFW to quit and removes your own sign-in entry. It
does not stop the firewall: run `sudo /usr/local/bin/stockfw stop`
first if you want the rules gone too.

## Building from source

    cd port
    bash tools/build-linux.sh              # produces build-linux/StockFW
    cd installer/linux
    bash build_installer_linux.sh          # produces dist/*.tar.gz

`build-linux.sh` compiles the real `iptables` backend when a C toolchain
is available and falls back to a null backend otherwise, so the build
does not silently produce a binary that pretends to work.

The packaging script refuses to package anything that is not a Linux ELF
executable. This matters on a dual-platform tree: an MSYS2 build produces
a Windows PE binary that installs without complaint and then fails at
exec time with a bare "Exec format error".

## Requirements

- GTK 3 (from your distribution's packages, not bundled)
- glib 2.0 (from your distribution's packages, not bundled)
- iptables, to apply rules
- root, to apply rules

## Licence

The source carries two licence texts: the GNU GPL version 2 (`COPYING`)
and the Apache License 2.0 (`LICENSE`). The code StockFW was ported from
was released under the GNU GPL, version 2 or any later version. Which
licence covers which part is still being reviewed. `LICENSE.txt` holds
this summary and both texts in full. GTK3, GLib, Cairo, Pango, HarfBuzz
and gdk-pixbuf are linked dynamically and provided by your distribution;
they are not bundled.
