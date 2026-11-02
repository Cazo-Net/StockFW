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
    /usr/local/share/icons/hicolor/128x128/apps/stockfw.png
    /usr/local/share/doc/stockfw/LICENSE.txt
    /usr/local/bin/stockfw-uninstall                    removal script

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

Removes exactly what `install.sh` created.

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

GPL-3.0-or-later. See `LICENSE.txt`. GTK3, GLib, Cairo, Pango, HarfBuzz
and gdk-pixbuf are linked dynamically and provided by your distribution;
they are not bundled.
