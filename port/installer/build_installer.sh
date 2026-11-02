#!/bin/bash
# Build script for StockFW NSIS Installer
# Prepares staging directory and builds the installer

set -e

# Work out where port/ lives from this script's own location, instead of
# hard-coding it: the tree has already been renamed once, and a stale
# absolute path here meant the installer build quietly pointed at a
# directory that no longer existed.
PORT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$PORT_DIR/build"
INSTALLER_DIR="$PORT_DIR/installer/nsis"
STAGE_DIR="$INSTALLER_DIR/stage"
RESOURCES_DIR="$INSTALLER_DIR/resources"

echo "=========================================="
echo "StockFW Installer Build Script"
echo "=========================================="

# Clean and create staging directory
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/gtk-runtime/bin"
mkdir -p "$STAGE_DIR/gtk-runtime/lib"
mkdir -p "$STAGE_DIR/gtk-runtime/share"
mkdir -p "$STAGE_DIR/gtk-runtime/etc"

# 1. Copy main executable (rename to StockFW.exe)
echo "[1/7] Copying main executable..."
cp "$BUILD_DIR/StockFW.exe" "$STAGE_DIR/StockFW.exe"

# 2. Copy GTK3 runtime dependencies - copy ALL DLLs (no whitelist)
echo "[2/7] Copying GTK3 runtime (ALL DLLs)..."

# Find and copy required DLLs from MSYS2.  Inside an MSYS2 shell
# /ucrt64 is the UCRT64 tree wherever MSYS2 was installed; C:\msys64 is
# only the installer's default, and a second drive or a CI runner puts
# it somewhere else.  The fixed path stays as the fallback for a shell
# that has no /ucrt64 mount (Git Bash).
if [ -d /ucrt64/bin ]; then
    MSYS_ROOT="/ucrt64"
else
    MSYS_ROOT="/c/msys64/ucrt64"
fi

# Copy ALL DLLs from MSYS2 ucrt64/bin
# This ensures nothing is missing - Windows only needs DLLs that are
# actually imported, extra DLLs are harmless
cp "$MSYS_ROOT"/bin/*.dll "$STAGE_DIR/gtk-runtime/bin/" 2>/dev/null
echo "  Copied $(ls "$STAGE_DIR/gtk-runtime/bin/"*.dll | wc -l) DLLs"

# GLib does not call CreateProcess itself: it starts child processes
# through gspawn-win64-helper.exe, resolved like any other program --
# $INSTDIR first, then PATH.  Nothing above pulls it in, because it is
# exec'd rather than linked and so never shows up in a dependency scan.
#
# Without it the app still starts and looks healthy, but every external
# command fails with "Failed to execute helper program (No such file or
# directory)": wevtutil.exe for traffic events, netsh.exe for applying
# firewall rules.  Both variants are shipped because GLib picks the
# console one when the child needs a console.
helpers=0
for helper in gspawn-win64-helper.exe gspawn-win64-helper-console.exe; do
    if [ -f "$MSYS_ROOT/bin/$helper" ]; then
        cp "$MSYS_ROOT/bin/$helper" "$STAGE_DIR/gtk-runtime/bin/"
        helpers=$((helpers + 1))
    fi
done

if [ "$helpers" -eq 0 ]; then
    echo "ERROR: GLib spawn helper not found in $MSYS_ROOT/bin" >&2
    echo "       Refusing to build an installer whose StockFW.exe" >&2
    echo "       cannot run wevtutil.exe or netsh.exe at all." >&2
    exit 1
fi
echo "  Copied $helpers spawn helper(s)"

# Copy GTK3 modules (immodules, printbackends, etc.)
echo "[3/7] Copying GTK3 modules..."
if [ -d "$MSYS_ROOT/lib/gtk-3.0" ]; then
    cp -r "$MSYS_ROOT/lib/gtk-3.0" "$STAGE_DIR/gtk-runtime/lib/"
fi

# Copy gdk-pixbuf loaders
if [ -d "$MSYS_ROOT/lib/gdk-pixbuf-2.0" ]; then
    cp -r "$MSYS_ROOT/lib/gdk-pixbuf-2.0" "$STAGE_DIR/gtk-runtime/lib/"
fi

# Copy pango modules
if [ -d "$MSYS_ROOT/lib/pango" ]; then
    cp -r "$MSYS_ROOT/lib/pango" "$STAGE_DIR/gtk-runtime/lib/"
fi

# Copy share files (themes, icons, locales)
echo "[4/7] Copying GTK3 share files..."
if [ -d "$MSYS_ROOT/share/themes" ]; then
    mkdir -p "$STAGE_DIR/gtk-runtime/share/themes"
    cp -r "$MSYS_ROOT/share/themes/"* "$STAGE_DIR/gtk-runtime/share/themes/" 2>/dev/null || true
fi

if [ -d "$MSYS_ROOT/share/icons" ]; then
    mkdir -p "$STAGE_DIR/gtk-runtime/share/icons"
    cp -r "$MSYS_ROOT/share/icons/"* "$STAGE_DIR/gtk-runtime/share/icons/" 2>/dev/null || true
fi

# Copy locale files (keep only English to save space)
mkdir -p "$STAGE_DIR/gtk-runtime/share/locale/en/LC_MESSAGES"
for mo in "$MSYS_ROOT/share/locale/en/LC_MESSAGES"/*.mo; do
    if [ -f "$mo" ]; then
        cp "$mo" "$STAGE_DIR/gtk-runtime/share/locale/en/LC_MESSAGES/"
    fi
done

# 5. Copy elevated launchers
echo "[5/7] Copying elevated launchers..."
# The files are named StockFW-elevated.* in the tree already, so they are
# copied unchanged -- the old version rewrote "stockfw" out of them
# with sed on every build.  The guard fails the build if any old branding
# survives inside one, rather than shipping it to users.
for launcher in StockFW-elevated.vbs StockFW-elevated.cmd StockFW-elevated.ps1; do
    cp "$PORT_DIR/$launcher" "$STAGE_DIR/$launcher"
    if grep -qi 'fire''starter' "$STAGE_DIR/$launcher"; then
        echo "ERROR: $launcher still mentions the old brand:" >&2
        grep -ni 'fire''starter' "$STAGE_DIR/$launcher" >&2
        exit 1
    fi
done

# 6. Create LICENSE.txt
echo "[6/7] Creating license file..."
cat > "$STAGE_DIR/LICENSE.txt" << 'EOF'
StockFW Firewall Configuration Tool
Version 1.0.6

Copyright (C) 2024-2026 StockFW Project

StockFW is free software and comes with no warranty. Its source
carries two licence texts: the GNU General Public License version 2
(COPYING) and the Apache License 2.0 (LICENSE). The code it was ported
from was released under the GNU GPL, version 2 or any later version.
Which licence covers which part is still being reviewed.

This is the same summary the About window shows. Both licence texts
follow in full at the end of this file.

---

Third-party Components:

GTK3 (GNU LGPL v2.1)
GLib (GNU LGPL v2.1)
Cairo (LGPL v2.1 / MPL v1.1)
Pango (LGPL v2.1)
HarfBuzz (MIT)
FreeType (FTL / GPL)
Fontconfig (MIT)
Pixman (MIT)
libpng (zlib license)
zlib (zlib license)
fribidi (LGPL v2.1)
libwebp (BSD)
libjpeg-turbo (BSD)
libtiff (BSD)
brotli (MIT)
freetype (FTL)
fontconfig (MIT)
pcre2 (BSD)

Windows Firewall API (Microsoft - system component)
NSIS (zlib license)

---

Icons and branding derived from original project assets.
EOF
# The licence texts the source carries, in full, after the summary:
# the installer's licence page is the first licence a user reads, and
# it must say what the About window says (tests/test-licence-texts.sh).
for text in COPYING LICENSE; do
    if [ ! -s "$PORT_DIR/../$text" ]; then
        echo "ERROR: $text is missing from the source tree" >&2
        exit 1
    fi
    printf '\n---\n\n%s\n\n' "$text" >> "$STAGE_DIR/LICENSE.txt"
    cat "$PORT_DIR/../$text" >> "$STAGE_DIR/LICENSE.txt"
done

# 7. Copy documentation
echo "[7/7] Copying documentation..."
cp "$PORT_DIR/README.md" "$STAGE_DIR/" 2>/dev/null || echo "# StockFW Firewall Tool" > "$STAGE_DIR/README.md"
# Create minimal CHANGELOG.md if not exists
if [ ! -f "$PORT_DIR/CHANGELOG.md" ]; then
    cat > "$STAGE_DIR/CHANGELOG.md" << 'EOF'
# StockFW Changelog

## Version 1.0.6 (2026)
- Activity page: Policy activity (events per minute, allowed and
  blocked) and Network I/O (throughput per adapter) graphs over
  15 minutes to 24 hours, with a crosshair, a table view, and an
  honest "no data" stretch before the app started
- Linux: dropped packets are named and marked blocked like on
  Windows, events carry their own time, port and direction, and
  the Network and Connections panels show real data
- Linux command-line tool `stockfw` and its local, read-only web
  dashboard (Linux build only)
- Desktop UI fixes: Policy buttons no longer print "_Add", frame
  titles readable, an empty Events list says why, larger window

## Version 1.0.5 (2026)
- Sentinel false-outage hardening: auto-block refuses whole
  destination classes (your own network, loopback, multicast,
  protocol infrastructure, anything unclassifiable), never
  re-stages a rule it just took down, persists its staged blocks
  across restarts with their *remaining* time, and an Allow in the
  event view lifts Sentinel's block for that destination - it can
  no longer lock you out of legitimate sites
- Application trust engine: signed/unsigned identification,
  SHA-256, publisher identity, attested baselines that notice
  unexpected changes
- Explainable behavior analysis: per-application baselines and
  correlated, sentence-level findings on the Copilot page
- Safe policy enforcement: apply gate with impact preview, an
  applied-policy journal, narrow delta application and verified
  rollback
- System tray and background operation (close/minimize to tray,
  firewall-state tooltip, Open/Quit menu)
- Preferences made real on Windows: ICMP, broadcast, profile,
  port-range and notification settings apply for real; pages
  Windows cannot honor stay hidden rather than greyed
- What-If Simulator: type a line like "allow SSH from 192.168.1.50
  on port 22" and get a BLOCKED/ALLOWED verdict against the real
  policy (block precedence, shadowed-allow reporting, CIDR
  coverage) without writing anything
- Bi-directional Direction setting on the pairable rule kinds: one
  option, one all-or-nothing save for both directions
- AI Assistant pane removed from the Copilot page; status messages
  live in the Policy Analysis log
- Canonical test runner tests/full-suite.sh (653 core checks)

## Version 1.0.4 (2026)
- Event -> Rule one-click staging, Events filter bar
- Sentinel detect/auto-block with time-boxed undo
- Initial release of StockFW
- GTK3-based firewall configuration tool
- Smart Firewall Copilot with AI-powered anomaly detection
- Windows Defender Firewall backend (netsh)
- Linux iptables backend
- Per-profile firewall control (Domain/Private/Public)
- Policy rule management with CSV import/export
- Elevated launcher for admin operations
EOF
else
    cp "$PORT_DIR/CHANGELOG.md" "$STAGE_DIR/"
fi

# Generate gdk-pixbuf.loaders.cache
echo "Generating gdk-pixbuf loader cache..."
"$MSYS_ROOT/bin/gdk-pixbuf-query-loaders.exe" > "$STAGE_DIR/gtk-runtime/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache" 2>/dev/null || true

# Generate gtk.immodules.cache
echo "Generating GTK immodules cache..."
"$MSYS_ROOT/bin/gtk-query-immodules-3.0.exe" > "$STAGE_DIR/gtk-runtime/lib/gtk-3.0/3.0.0/immodules.cache" 2>/dev/null || true

# Generate pango.modules.cache.  Pango >= 1.38 no longer ships any
# modules, so the query tool prints nothing and the file legitimately
# stays absent -- but the directory has to exist first, or the shell's
# own redirection fails loudly on every build.
echo "Generating Pango modules cache..."
mkdir -p "$STAGE_DIR/gtk-runtime/lib/pango"
"$MSYS_ROOT/bin/pango-querymodules.exe" > "$STAGE_DIR/gtk-runtime/lib/pango/pango.modules" 2>/dev/null || true

echo ""
echo "=========================================="
echo "Staging complete. Building installer..."
echo "=========================================="

# Build installer with NSIS
cd "$INSTALLER_DIR"
NSIS_SCRIPT="StockFW.nsi"
# Check if NSIS is available
if command -v makensis &> /dev/null; then
    NSIS_CMD="makensis"
elif [ -f "/c/Program Files (x86)/NSIS/makensis.exe" ]; then
    NSIS_CMD="/c/Program Files (x86)/NSIS/makensis.exe"
elif [ -f "/c/Program Files/NSIS/makensis.exe" ]; then
    NSIS_CMD="/c/Program Files/NSIS/makensis.exe"
else
    echo "ERROR: NSIS not found. Please install NSIS 3.x"
    echo "Download from: https://nsis.sourceforge.io/Download"
    exit 1
fi

echo "Using NSIS: $NSIS_CMD"
# PROJECT_DIR reaches the script as the relative "..\.." define; it is
# not passed with /D here.  Running makensis is done from $INSTALLER_DIR
# above, so the relative path lands on port/, and an MSYS2 shell would
# mangle a leading-slash /D argument into a file name anyway
# ("Can't open script C:/msys64/DPROJECT_DIR=...").
"$NSIS_CMD" "$NSIS_SCRIPT"

echo ""
echo "=========================================="
echo "Installer built successfully!"
echo "Output: $INSTALLER_DIR/StockFW-1.0.6-Setup.exe"
echo "=========================================="