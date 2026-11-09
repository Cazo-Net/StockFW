# StockFW for Linux

Firewall configuration tool for Linux, driving `iptables`.

    StockFW 1.0.8 (Linux (iptables) backend)

## Install

    sha256sum -c SHA256SUMS.txt --ignore-missing   # from the release page
    tar xzf StockFW-1.0.8-linux-x86_64.tar.gz
    cd StockFW-1.0.8-linux-x86_64
    sudo ./install.sh

This installs:

    /usr/local/bin/StockFW                              the application
    /usr/local/bin/stockfw                              command line + dashboard
    /usr/local/share/applications/stockfw.desktop       menu entry
    /usr/local/share/icons/hicolor/{48x48,128x128,256x256}/apps/stockfw.png
    /usr/local/share/doc/stockfw/LICENSE.txt
    /usr/local/share/doc/stockfw/CHANGELOG.md           what changed in this release
    /usr/local/bin/stockfw-uninstall                    removal script
    /etc/systemd/system/stockfw.service                 puts the rules back at boot (enabled)

The installer checks that every runtime library the binary links against
is present, by soname. It reports sonames rather than package names
because those differ between distributions: Debian and Ubuntu renamed
`libgtk-3-0` to `libgtk-3-0t64` in their time64 transition, so a
package-name check would wrongly report a working system as missing.

If a library is absent, install it with your package manager:

    Debian / Kali / Ubuntu:  sudo apt install libgtk-3-0 libgdk-pixbuf-2.0-0 liblzma5 libssl3
    Fedora:                  sudo dnf install gtk3 xz-libs openssl-libs
    Arch:                    sudo pacman -S gtk3 xz openssl

`libcrypto.so.3` is OpenSSL 3. A distribution that ships only OpenSSL
1.1 (Debian 11, Ubuntu 20.04) cannot run this build; the installer stops
there rather than install a program that cannot start.

Three tools are checked separately and only warn if missing, looked for
where StockFW running as root looks for them (`/usr/sbin`, `/usr/bin`,
`/sbin`, `/bin`; curl only in `/usr/bin` and `/bin`):

- `iptables`: applying rules needs it. Without it the application still
  runs and can read, simulate, and display policy.
- `nft` (nftables): threat-intel blocklists and country and network
  blocking load an nftables table.
- `curl`: downloads the blocklists and the location database.

## Run

    StockFW          read-only: status, events, policy, simulation
    sudo /usr/local/bin/StockFW     the full tool, including applying rules

Use the full path with `sudo`. `sudo` runs commands with its own search
path (`Defaults secure_path` in `/etc/sudoers`), which on some systems
(Fedora, RHEL, and the Kali StockFW was first tested on) does **not**
include `/usr/local/bin`. On such a system the shorter `sudo StockFW`
reports "command not found" even though plain `StockFW` works — because
your login shell's PATH includes `/usr/local/bin` while sudo's does not.
`install.sh` checks yours and warns when it is one of them.

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

`StockFW` (capitals) is the window app and takes options only
(`StockFW --help`). Commands such as `status` and `dashboard` belong to
the command-line tool `stockfw`, in lowercase: `StockFW dashboard` stops
with a message saying so.

### Before installing, from the unpacked folder

`sudo` never looks in the current folder, so name the program with
`./`:

    ./StockFW                       the window app, read-only
    sudo ./StockFW                  the full tool
    sudo ./cli/stockfw dashboard    the local dashboard, with live events

### Wayland desktops and WSL

Started without `sudo` on Wayland (GNOME and KDE Plasma by default, and
WSL's WSLg), StockFW runs on GTK's Wayland side, which has no tray area:
it shows no tray icon, closing the window quits it, and Preferences
greys the two tray switches with the reason.

Started with `sudo`, it runs on the desktop's X11 side (XWayland)
instead, because `sudo` drops the Wayland settings. There the tray
switches stay on offer, but an icon appears only where the desktop shows
X11 tray icons (WSLg and a plain GNOME desktop do not); without one,
closing still quits. On an X11 session the icon shows where the desktop
has a system tray (Xfce, MATE, Cinnamon, KDE Plasma); GNOME has none
unless an extension adds one.

Under WSL a `dconf-WARNING ... unable to open file '/etc/dconf/db/local'`
line at start comes from WSL's own settings setup and is harmless.

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
  never take the rules away; `sudo /usr/local/bin/stockfw stop` does.
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

Before you apply, and after:

    stockfw check                          lines of the policy files that are not rules
    stockfw policy diff                    what apply would add and remove
    sudo /usr/local/bin/stockfw apply      make the saved policy live
    stockfw audit -n 10                    the last applies, starts and stops
    stockfw listening                      open ports, and who can reach them
    stockfw events --summary --since 24h   who was blocked, on which ports

`apply` refuses while `check` finds a problem.  Over SSH, `apply` and
`start` check that the new policy still lets your session in; without
a terminal they refuse unless you add `--yes`.  Hints that need root
print the full path, as above, because `sudo` may not search
`/usr/local/bin`.

Exit codes: 0 done, 1 failed (or `check` found problems), 2 usage
error, 3 needs root, 5 `simulate`: blocked, 6 `simulate`: depends,
7 `copilot health`: findings.

`man stockfw` lists every command and option.  The installer puts the
manual page in `/usr/local/share/man/man1/stockfw.1`, and completion
for bash in `/usr/local/share/bash-completion/completions/stockfw` and
for zsh in `/usr/local/share/zsh/site-functions/_stockfw`.  Completion
asks `stockfw` itself, so it offers your own rule references
(`policy remove inbound-allow-service:2`).  If your shell does not
load them (a distro without the `bash-completion` package, or a zsh
`fpath` without `/usr/local/share/zsh/site-functions`), add one line
to your shell's start-up file:

    source /usr/local/share/bash-completion/completions/stockfw      # ~/.bashrc
    fpath+=(/usr/local/share/zsh/site-functions); autoload -Uz compinit; compinit   # ~/.zshrc

`stockfw dashboard` serves a read-only page on 127.0.0.1 only and
opens it in your browser (never as root: under `sudo` it prints the
link instead).  The link holds a code that works once, for 2 minutes;
the page swaps it for a session that lasts the day.  The link is
printed only when the output goes to a terminal: piped or with
`--json`, you get the path of a launch file (0600) to open instead.
If the link has expired or a tab was closed, run `stockfw dashboard
link` as yourself, without `sudo`, in another terminal for a new one.
A link used twice ends every session.  Check that the fingerprint at
the top of the page is the one the terminal shows.  It answers only
your own account: under `sudo`, the account that ran `sudo`.  Run it
with `sudo` from your own account, not from a root shell, where it
refuses to start.  Open the address exactly as printed, with
`127.0.0.1`: `localhost` is refused.  The same `sudo` search-path note
as above applies: `sudo /usr/local/bin/stockfw` always works.  Under
WSL, a browser on the Windows side is refused by default, since its
connection does not come from your Linux account; a browser inside WSL
works, and `stockfw dashboard --allow-windows` lets the Windows side
in.  Over SSH, run `ssh -L 8443:127.0.0.1:PORT host` and start the
dashboard with `--origin-port 8443`; never forward with `-g` or
`0.0.0.0`.  Leave the terminal running while you use it.

## Uninstall

    sudo /usr/local/bin/stockfw-uninstall

Removes exactly what `install.sh` created, disables the boot service,
asks a running StockFW to quit and removes your own sign-in entry. It
does not stop the firewall: run `sudo /usr/local/bin/stockfw stop`
first if you want the rules gone too.

## Building from source

    sudo apt install build-essential cmake ninja-build pkg-config \
        libgtk-3-dev liblzma-dev libssl-dev
    cd port
    bash tools/build-linux.sh                       # Release build: build-linux/StockFW, build-linux/stockfw
    bash installer/linux/build_installer_linux.sh   # dist/StockFW-<version>-linux-<machine>.tar.gz

`tools/build-linux.sh` runs CMake (`cmake -S . -B build-linux
-DCMAKE_BUILD_TYPE=Release`, then builds `StockFW` and `stockfw`);
`CMakeLists.txt` is the one place that lists the sources, the libraries
and the version. `cmake --install` puts the two binaries, the manual
page and the completion files in place; `install.sh` is the supported
install.

A server with no display can build the command-line tool alone, with
no GTK installed: `cmake -S . -B build-cli -G Ninja -DFS_BUILD_GUI=OFF`
then `ninja -C build-cli` builds `stockfw` and its manual page, and no
desktop app.  The default (`FS_BUILD_GUI=ON`) builds both and needs
`libgtk-3-dev`.

The packaging script:

- refuses anything that is not a Linux ELF executable. This matters on
  a dual-platform tree: an MSYS2 build produces a Windows PE binary that
  installs without complaint and then fails at exec time with a bare
  "Exec format error";
- refuses a build whose `--version` is not the version in
  `CMakeLists.txt`, so a stale build directory is not shipped under an
  old number;
- strips the binaries as it stages them;
- requires a `CHANGELOG.md` section for the version;
- checks that `install.sh`, `StockFW` and `cli/stockfw` are executable
  inside the finished archive;
- stages the manual page (`cli/stockfw.1`, written by `stockfw __man`)
  and the bash and zsh completion (`cli/stockfw.bash`, `cli/_stockfw`)
  beside `cli/stockfw`.

## Requirements

- GTK 3 (from your distribution's packages, not bundled)
- glib 2.0 (from your distribution's packages, not bundled)
- liblzma 5 and OpenSSL 3 libcrypto (from your distribution's packages,
  not bundled)
- iptables, to apply rules
- nftables (`nft`) and curl, for threat-intel blocklists and country and
  network blocking
- root, to apply rules

## Licence

The source carries two licence texts: the GNU GPL version 2 (`COPYING`)
and the Apache License 2.0 (`LICENSE`). The code StockFW was ported from
was released under the GNU GPL, version 2 or any later version. Which
licence covers which part is still being reviewed. `LICENSE.txt` holds
this summary and both texts in full. GTK3, GLib, Cairo, Pango, HarfBuzz,
gdk-pixbuf, liblzma (0BSD) and OpenSSL libcrypto (Apache License 2.0)
are linked dynamically and provided by your distribution; they are not
bundled.
