#!/bin/bash
# StockFW Linux installer
#
#   sudo ./install.sh          install
#   sudo /usr/local/bin/stockfw-uninstall   remove (installed by this script)
#
# What it does:
#   - checks the runtime libraries the binary actually links against,
#     by soname via ldconfig (NOT by package name: Debian/Ubuntu's
#     t64 transition renamed libgtk-3-0 -> libgtk-3-0t64, so a package
#     check would wrongly report a working system as missing)
#   - installs the binary to /usr/local/bin (FHS: locally-installed
#     software, not the distro's own /usr/bin)
#   - installs the desktop entry and icon so the app appears in the
#     desktop menu
#   - installs an uninstall script alongside, so removal is symmetric
#
# What it deliberately does NOT do:
#   - no polkit policy and no setuid.  The Linux backend invokes
#     iptables directly and expects to already be root, so privilege is
#     obtained by launching with sudo, exactly as docs/ELEVATED.md
#     states.  Shipping a polkit rule that silently elevated a GUI tool
#     able to rewrite the whole firewall would be a worse security
#     posture than the honest one, not a better one.
#
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
DATADIR="$PREFIX/share"
APPID="stockfw"

# --- locate this script's own directory (the payload) --------------------
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- colours only when on a tty ------------------------------------------
if [ -t 1 ]; then
    G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; B=$'\033[1m'; N=$'\033[0m'
else
    G=""; R=""; Y=""; B=""; N=""
fi

ok()   { printf '  %sok:%s   %s\n' "$G" "$N" "$*"; }
warn() { printf '  %sWARN:%s %s\n' "$Y" "$N" "$*"; }
fail() { printf '  %sFAIL:%s %s\n' "$R" "$N" "$*"; }

# --- root check ----------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    printf '%sStockFW must be installed as root.%s\n' "$R" "$N"
    printf 'Run:  sudo %s/install.sh\n' "$HERE"
    exit 1
fi

printf '%s\n' "${B}StockFW Linux installer${N}"
printf '\n'

# --- locate the binary: staged beside this script, else the build dir ----
SRC="$HERE/StockFW"
if [ ! -f "$SRC" ]; then
    # allow running straight from the repo before staging
    if [ -f "$HERE/../../build-linux/StockFW" ]; then
        SRC="$(cd "$HERE/../../build-linux" && pwd)/StockFW"
    else
        printf '%sNo StockFW binary found next to this script.%s\n' "$R" "$N"
        printf 'Build it first:  cd port && bash tools/build-linux.sh\n'
        exit 1
    fi
fi

# --- must be a real Linux ELF, not a Windows PE --------------------------
# A PE binary (from an MSYS2 build) installs and then fails at exec time
# with a bare "Exec format error"; catching it here explains why.
MAGIC="$(od -An -tx1 -N4 "$SRC" | tr -d ' \n')"
if [ "$MAGIC" != "7f454c46" ]; then
    printf '%s%s is not a Linux ELF executable (magic: %s)%s\n' "$R" "$SRC" "$MAGIC" "$N"
    printf 'Rebuild on Linux:  cd port && bash tools/build-linux.sh\n'
    exit 1
fi
ok "binary is a Linux ELF executable"

# --- dependency check: sonames via ldconfig ------------------------------
# The binaries' own NEEDED entries (StockFW and cli/stockfw), the C
# library aside, in any build type (a build linked without --as-needed
# also names cairo-gobject, harfbuzz and zlib, which GTK3 brings);
# tests/test-release.sh compares this list with readelf.  libgtk-3.so.0 and
# libgdk-3.so.0 both come from the GTK3 package; listed separately
# because a stripped install can carry one without the other.
# liblzma and libcrypto (1.0.7) read the location database; a system
# with only OpenSSL 1.1 (Debian 11, Ubuntu 20.04) has no libcrypto.so.3,
# and StockFW and the boot service would then fail to start at all.
NEEDED="libgtk-3.so.0 libgdk-3.so.0 libgdk_pixbuf-2.0.so.0
        libpango-1.0.so.0 libpangocairo-1.0.so.0 libcairo.so.2
        libatk-1.0.so.0 libcairo-gobject.so.2 libharfbuzz.so.0 libz.so.1
        libglib-2.0.so.0 libgobject-2.0.so.0 libgio-2.0.so.0
        liblzma.so.5 libcrypto.so.3"

MISSING=""
for so in $NEEDED; do
    if ldconfig -p 2>/dev/null | awk -v s="$so" '$1==s{f=1} END{exit !f}'; then
        :
    else
        MISSING="$MISSING $so"
    fi
done

if [ -n "$MISSING" ]; then
    fail "missing runtime libraries:$MISSING"
    printf '\n'
    printf 'Install them with your package manager.  Package names vary by\n'
    printf 'distro (Debian/Ubuntu use libgtk-3-0t64, Fedora uses gtk3), so\n'
    printf 'this installer reports sonames, not package names:\n\n'
    printf '  Debian/Kali/Ubuntu:  sudo apt install libgtk-3-0 libgdk-pixbuf-2.0-0 liblzma5 libssl3\n'
    printf '  Fedora:              sudo dnf install gtk3 xz-libs openssl-libs\n'
    printf '  Arch:                sudo pacman -S gtk3 xz openssl\n'
    case "$MISSING" in
    *libcrypto.so.3*)
        printf '\nlibcrypto.so.3 is OpenSSL 3.  A distribution that ships only\n'
        printf 'OpenSSL 1.1 (Debian 11, Ubuntu 20.04) cannot run this build.\n' ;;
    esac
    exit 1
fi
ok "all runtime libraries present"

# --- external tools: present, but only warnings ---------------------------
# Not fatal: the GUI reads and simulates fine without them, and the app
# reports a missing backend itself.  Installing a firewall tool that then
# hard-fails because one optional tool is absent would be the wrong call.
#
# Looked for where StockFW running as root looks, not on this shell's
# PATH: as root it runs these only from fixed system folders.
find_tool () {   # <name> <dir>...: print the first executable match
    local name="$1" d
    shift
    for d in "$@"; do
        if [ -x "$d/$name" ] && [ -f "$d/$name" ]; then
            printf '%s\n' "$d/$name"
            return 0
        fi
    done
    return 1
}
SYSDIRS="/usr/sbin /usr/bin /sbin /bin"

# shellcheck disable=SC2086
if t="$(find_tool iptables $SYSDIRS)"; then
    ok "iptables found ($t)"
else
    warn "iptables not found in $SYSDIRS -- the app will run but cannot apply rules"
    warn "install it:  sudo apt install iptables   (Fedora: dnf, Arch: pacman -S iptables)"
fi
# Threat-intel blocklists and country and network blocking load an
# nftables table; without nft they cannot be turned on.
# shellcheck disable=SC2086
if t="$(find_tool nft $SYSDIRS)"; then
    ok "nft found ($t)"
else
    warn "nft not found in $SYSDIRS -- threat-intel blocklists and country"
    warn "and network blocking will not work; the firewall policy still does"
    warn "install it:  sudo apt install nftables   (Fedora/Arch: nftables)"
fi
# The blocklists and the location database are downloaded with curl,
# which StockFW runs only as /usr/bin/curl or /bin/curl.
if t="$(find_tool curl /usr/bin /bin)"; then
    ok "curl found ($t)"
else
    warn "curl not found in /usr/bin or /bin -- threat-intel lists and the"
    warn "location database cannot be downloaded"
    warn "install it:  sudo apt install curl"
fi

# --- install -------------------------------------------------------------
printf '\n'
ok "installing to $PREFIX"

install -Dm755 "$SRC" "$BINDIR/StockFW"
ok "$BINDIR/StockFW"

# The command-line tool (1.0.6), staged as cli/stockfw; from a repo
# checkout, the build directory's.  Optional: an older payload without
# it still installs the desktop app.
CLI="$HERE/cli/stockfw"
if [ ! -f "$CLI" ] && [ -f "$HERE/../../build-linux/stockfw" ]; then
    CLI="$(cd "$HERE/../../build-linux" && pwd)/stockfw"
fi
if [ -f "$CLI" ]; then
    install -Dm755 "$CLI" "$BINDIR/stockfw"
    ok "$BINDIR/stockfw (command line and local dashboard)"
fi

# Its manual page and shell completion, staged beside it as
# cli/stockfw.1, cli/stockfw.bash and cli/_stockfw; from a repo
# checkout, the build's page and contrib/completion.  Optional, like
# the tool: an older payload has none of them.
MAN_SRC="$HERE/cli/stockfw.1"
BASH_SRC="$HERE/cli/stockfw.bash"
ZSH_SRC="$HERE/cli/_stockfw"
if [ ! -f "$MAN_SRC" ] && [ -f "$(dirname "$CLI")/stockfw.1" ]; then
    MAN_SRC="$(dirname "$CLI")/stockfw.1"
fi
if [ ! -f "$BASH_SRC" ] && [ -f "$HERE/../../contrib/completion/stockfw.bash" ]; then
    BASH_SRC="$HERE/../../contrib/completion/stockfw.bash"
    ZSH_SRC="$HERE/../../contrib/completion/_stockfw"
fi
if [ -x "$BINDIR/stockfw" ] && [ -f "$MAN_SRC" ]; then
    install -Dm644 "$MAN_SRC" "$DATADIR/man/man1/stockfw.1"
    ok "$DATADIR/man/man1/stockfw.1 (man stockfw)"
fi
if [ -x "$BINDIR/stockfw" ] && [ -f "$BASH_SRC" ]; then
    install -Dm644 "$BASH_SRC" "$DATADIR/bash-completion/completions/stockfw"
    ok "$DATADIR/bash-completion/completions/stockfw (bash completion)"
fi
if [ -x "$BINDIR/stockfw" ] && [ -f "$ZSH_SRC" ]; then
    install -Dm644 "$ZSH_SRC" "$DATADIR/zsh/site-functions/_stockfw"
    ok "$DATADIR/zsh/site-functions/_stockfw (zsh completion)"
fi

# The boot service: iptables rules live in the kernel only, so without
# it every rule is gone after a reboot until someone starts StockFW
# with sudo again.  It runs `stockfw start' before the network comes up
# and does nothing until a policy has been applied as root once
# (see the unit file).  Enabled, not started: installing never changes
# the running firewall.
UNIT_DIR="/etc/systemd/system"
UNIT="$UNIT_DIR/stockfw.service"
SERVICE_STATE="not installed"
if [ -x "$BINDIR/stockfw" ] && [ -f "$HERE/stockfw.service" ] &&
   command -v systemctl >/dev/null 2>&1 && [ -d "$UNIT_DIR" ]; then
    sed "s|/usr/local/bin/stockfw|$BINDIR/stockfw|" "$HERE/stockfw.service" \
        > "$UNIT.tmp"
    install -m644 "$UNIT.tmp" "$UNIT"
    rm -f "$UNIT.tmp"
    ok "$UNIT (puts the rules back at boot)"
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload
        if systemctl enable stockfw.service >/dev/null 2>&1; then
            ok "stockfw.service enabled"
            SERVICE_STATE="enabled"
        else
            warn "could not enable stockfw.service -- run: systemctl enable stockfw.service"
            SERVICE_STATE="installed, not enabled"
        fi
    else
        # Installing into an image or chroot: systemctl enable works
        # offline (it only makes the symlink).
        if systemctl enable stockfw.service >/dev/null 2>&1; then
            ok "stockfw.service enabled (systemd not running here)"
            SERVICE_STATE="enabled"
        else
            SERVICE_STATE="installed, not enabled"
        fi
    fi
else
    warn "no systemd: firewall rules will NOT come back after a reboot"
    warn "until StockFW is started with sudo (or 'sudo $BINDIR/stockfw start' runs)"
fi

install -Dm644 "$HERE/stockfw.desktop" "$DATADIR/applications/$APPID.desktop"
ok "$DATADIR/applications/$APPID.desktop"

# The icon in three theme sizes (menus, docks, app grids each pick the
# nearest).  The 48 and 256 files are optional: an older payload with
# only the 128 one still installs.
install -Dm644 "$HERE/stockfw-icon.png" "$DATADIR/icons/hicolor/128x128/apps/$APPID.png"
ok "$DATADIR/icons/hicolor/128x128/apps/$APPID.png"
for size in 48 256; do
    if [ -f "$HERE/stockfw-icon-$size.png" ]; then
        install -Dm644 "$HERE/stockfw-icon-$size.png" \
            "$DATADIR/icons/hicolor/${size}x${size}/apps/$APPID.png"
        ok "$DATADIR/icons/hicolor/${size}x${size}/apps/$APPID.png"
    fi
done

install -Dm644 "$HERE/LICENSE.txt" "$DATADIR/doc/stockfw/LICENSE.txt"
ok "$DATADIR/doc/stockfw/LICENSE.txt"
# What changed in this release; optional, an older payload has none.
if [ -f "$HERE/CHANGELOG.md" ]; then
    install -Dm644 "$HERE/CHANGELOG.md" "$DATADIR/doc/stockfw/CHANGELOG.md"
    ok "$DATADIR/doc/stockfw/CHANGELOG.md"
fi

# refresh the desktop/icon caches if the tools exist; absence is fine
command -v update-desktop-database >/dev/null 2>&1 \
    && update-desktop-database "$DATADIR/applications" >/dev/null 2>&1 || true
command -v gtk-update-icon-cache   >/dev/null 2>&1 \
    && gtk-update-icon-cache -q -t "$DATADIR/icons/hicolor" >/dev/null 2>&1 || true

# --- uninstall script ----------------------------------------------------
# Installed beside the app so removal is symmetric with install and does
# not require keeping this tree around.
cat > "$BINDIR/stockfw-uninstall" <<UNINSTALL
#!/bin/bash
# StockFW uninstaller.  Removes exactly what install.sh created.
set -euo pipefail
PREFIX="\${PREFIX:-$PREFIX}"
if [ "\$(id -u)" -ne 0 ]; then
    echo "Run as root:  sudo \$0" >&2
    exit 1
fi
# The boot service: disabled and removed.  Not stopped first -- it has
# no ExecStop, and removing StockFW does not take the running rules
# down ('sudo stockfw stop' before uninstalling does).
if command -v systemctl >/dev/null 2>&1; then
    systemctl disable stockfw.service >/dev/null 2>&1 || true
fi
rm -f /etc/systemd/system/stockfw.service
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
# A running StockFW is asked to quit cleanly, so it saves its settings.
# The sign-in entry of the user running this through sudo goes too
# (written as that user; other users' entries are theirs to remove).
if [ -x "\$PREFIX/bin/StockFW" ]; then
    timeout 20 "\$PREFIX/bin/StockFW" --quit >/dev/null 2>&1 || true
    timeout 20 "\$PREFIX/bin/StockFW" --disable-autostart >/dev/null 2>&1 || true
fi
rm -f "\$PREFIX/bin/StockFW"
rm -f "\$PREFIX/bin/stockfw"
rm -f "\$PREFIX/share/man/man1/stockfw.1"
rm -f "\$PREFIX/share/bash-completion/completions/stockfw"
rm -f "\$PREFIX/share/zsh/site-functions/_stockfw"
rmdir "\$PREFIX/share/bash-completion/completions" 2>/dev/null || true
rmdir "\$PREFIX/share/bash-completion" 2>/dev/null || true
rmdir "\$PREFIX/share/zsh/site-functions" 2>/dev/null || true
rmdir "\$PREFIX/share/zsh" 2>/dev/null || true
rm -f "\$PREFIX/share/applications/stockfw.desktop"
rm -f "\$PREFIX/share/icons/hicolor/48x48/apps/stockfw.png"
rm -f "\$PREFIX/share/icons/hicolor/128x128/apps/stockfw.png"
rm -f "\$PREFIX/share/icons/hicolor/256x256/apps/stockfw.png"
rm -f "\$PREFIX/share/doc/stockfw/LICENSE.txt"
rm -f "\$PREFIX/share/doc/stockfw/CHANGELOG.md"
rmdir "\$PREFIX/share/doc/stockfw" 2>/dev/null || true
rm -f "\$PREFIX/bin/stockfw-uninstall"
command -v update-desktop-database >/dev/null 2>&1 \\
    && update-desktop-database "\$PREFIX/share/applications" >/dev/null 2>&1 || true
echo "StockFW removed."
UNINSTALL
chmod 755 "$BINDIR/stockfw-uninstall"
ok "$BINDIR/stockfw-uninstall"

# --- summary -------------------------------------------------------------
# The launch command is given as an absolute path on purpose.  sudo runs
# with its own search path (Defaults secure_path in sudoers), which on
# some systems (Fedora and RHEL, and the Kali StockFW was first tested
# on) does NOT include /usr/local/bin -- so the bare "sudo StockFW" that
# a user will naturally type fails with "command not found" even though
# "StockFW" works perfectly as an ordinary user.  The absolute path is
# correct on every system regardless of how sudoers is configured.
SUDO_CMD="$BINDIR/StockFW"

# Detect that exact trap and say so, rather than letting the user
# rediscover it.  Reading sudoers is only possible as root, which is
# where we already are.  Both spellings count: Debian and Ubuntu write
# secure_path="..." and RHEL and Fedora secure_path = ... (spaces, no
# quotes); tests/test-release.sh feeds this function each one.
sudo_path_has_bindir () {
    local sp
    sp=$( { grep -hE '^[[:space:]]*Defaults[[:space:]]+secure_path[[:space:]]*=' \
                 /etc/sudoers /etc/sudoers.d/* 2>/dev/null \
           || true; } \
         | sed -nE 's/.*secure_path[[:space:]]*=[[:space:]]*"?([^"[:space:]]*)"?.*/\1/p' \
         | tr ':' '\n' )
    [ -z "$sp" ] && return 0   # no secure_path set: sudo inherits PATH
    printf '%s\n' "$sp" | grep -qxF "$BINDIR"
}

printf '\n'
printf '%sInstalled.%s\n\n' "$G" "$N"
printf 'Launch from your desktop menu, or:\n'
printf '    %-20s %s\n' "StockFW" \
        "(read-only: status, events, policy, simulate)"
printf '    sudo %s\n' "$SUDO_CMD"
printf '    %-20s %s\n' "" "(apply rules: the backend needs root)"
if [ -x "$BINDIR/stockfw" ]; then
    printf '\nFrom a terminal:\n'
    printf '    %-20s %s\n' "stockfw help" "(status, policy, simulate, events, ...)"
    printf '    %-20s %s\n' "stockfw dashboard" "(local web dashboard, 127.0.0.1 only)"
    printf '    %-20s %s\n' "man stockfw" "(every command and option)"
fi

printf '\nAt boot:\n'
if [ "$SERVICE_STATE" = "enabled" ]; then
    printf '    stockfw.service puts the rules back before the network comes up,\n'
    printf '    once a policy has been applied with sudo.\n'
else
    printf '    %sstockfw.service is %s: the firewall rules will be gone after%s\n' "$Y" "$SERVICE_STATE" "$N"
    printf '    %sa reboot until StockFW is started with sudo again.%s\n' "$Y" "$N"
fi

if ! sudo_path_has_bindir; then
    printf '\n'
    warn "sudo's secure_path does not include $BINDIR,"
    warn "so the shorter 'sudo StockFW' will report 'command not found'."
    warn "Use the full path shown above.  (This installer deliberately"
    warn "does not edit sudoers: widening secure_path for one tool would"
    warn "widen it for every command on the system.)"
fi

printf '\nRemove with:\n'
printf '    sudo %s\n\n' "$BINDIR/stockfw-uninstall"
