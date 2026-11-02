#!/bin/bash
# StockFW Linux installer
#
#   sudo ./install.sh          install
#   sudo ./uninstall.sh        remove (installed by this script)
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
# The binary's own NEEDED entries, in link order.  libgtk-3.so.0 and
# libgdk-3.so.0 both come from the GTK3 package; listed separately
# because a stripped install can carry one without the other.
NEEDED="libgtk-3.so.0 libgdk-3.so.0 libgdk_pixbuf-2.0.so.0
        libpango-1.0.so.0 libpangocairo-1.0.so.0 libcairo.so.2
        libglib-2.0.so.0 libgobject-2.0.so.0 libgio-2.0.so.0"

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
    printf '  Debian/Kali/Ubuntu:  sudo apt install libgtk-3-0 libgdk-pixbuf-2.0-0\n'
    printf '  Fedora:              sudo dnf install gtk3\n'
    printf '  Arch:                sudo pacman -S gtk3\n'
    exit 1
fi
ok "all runtime libraries present"

# --- iptables: present, but only a warning -------------------------------
# Not fatal: the GUI reads and simulates fine without it, and the app
# reports the missing backend itself in the Status page.  Installing a
# firewall tool that then hard-fails because the distro ships nftables
# would be the wrong call.
if command -v iptables >/dev/null 2>&1; then
    ok "iptables found ($(command -v iptables))"
else
    warn "iptables not on PATH -- the app will run but cannot apply rules"
    warn "install it:  sudo apt install iptables"
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

install -Dm644 "$HERE/stockfw.desktop" "$DATADIR/applications/$APPID.desktop"
ok "$DATADIR/applications/$APPID.desktop"

install -Dm644 "$HERE/stockfw-icon.png" "$DATADIR/icons/hicolor/128x128/apps/$APPID.png"
ok "$DATADIR/icons/hicolor/128x128/apps/$APPID.png"

install -Dm644 "$HERE/LICENSE.txt" "$DATADIR/doc/stockfw/LICENSE.txt"
ok "$DATADIR/doc/stockfw/LICENSE.txt"

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
rm -f "\$PREFIX/bin/StockFW"
rm -f "\$PREFIX/bin/stockfw"
rm -f "\$PREFIX/share/applications/stockfw.desktop"
rm -f "\$PREFIX/share/icons/hicolor/128x128/apps/stockfw.png"
rm -f "\$PREFIX/share/doc/stockfw/LICENSE.txt"
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
# Debian/Kali is typically "/usr/sbin:/usr/bin:/sbin:/bin" and does NOT
# include /usr/local/bin -- so the bare "sudo StockFW" that a user will
# naturally type fails with "command not found" even though "StockFW"
# works perfectly as an ordinary user.  The absolute path is correct on
# every system regardless of how sudoers is configured.
SUDO_CMD="$BINDIR/StockFW"

# Detect that exact trap and say so, rather than letting the user
# rediscover it.  Reading sudoers is only possible as root, which is
# where we already are.
sudo_path_has_bindir () {
    local sp
    sp=$( { grep -hE '^[[:space:]]*Defaults[[:space:]]+secure_path=' \
                 /etc/sudoers /etc/sudoers.d/* 2>/dev/null \
           || true; } \
         | sed -n 's/.*secure_path="\([^"]*\)".*/\1/p' \
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
