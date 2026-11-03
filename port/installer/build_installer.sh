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
ROOT_DIR="$(cd "$PORT_DIR/.." && pwd)"

# The version: CMakeLists.txt's project VERSION is the one source of
# truth.  It names the installer, its file properties, the Add/Remove
# Programs entry (passed to makensis as APP_VERSION), the licence page
# and the changelog check below.  A build directory configured from an
# older checkout would package an exe of another version, so the two
# must agree.
VERSION="$(sed -n 's/^[[:space:]]*VERSION[[:space:]]\{1,\}\([0-9][0-9.]*\).*/\1/p' \
           "$PORT_DIR/CMakeLists.txt" | head -n 1)"
if [ -z "$VERSION" ]; then
    echo "ERROR: no project VERSION in $PORT_DIR/CMakeLists.txt" >&2
    exit 1
fi
if [ -f "$BUILD_DIR/CMakeCache.txt" ]; then
    BUILT="$(sed -n 's/^CMAKE_PROJECT_VERSION:STATIC=//p' "$BUILD_DIR/CMakeCache.txt")"
    if [ -n "$BUILT" ] && [ "$BUILT" != "$VERSION" ]; then
        echo "ERROR: $BUILD_DIR was configured for $BUILT, the source is $VERSION" >&2
        echo "       cmake -S . -B build -G Ninja && cmake --build build" >&2
        exit 1
    fi
fi

echo "=========================================="
echo "StockFW Installer Build Script ($VERSION)"
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
# The release carries no debug information: a RelWithDebInfo exe is
# mostly DWARF.  Only the staged copy is stripped; build/ keeps its
# symbols for debugging.  No strip stops the build, as the Linux
# packager does: it used to warn and ship the unstripped exe.
if ! command -v strip >/dev/null 2>&1; then
    echo "ERROR: strip not found; StockFW.exe would ship with debug information" >&2
    echo "       Install binutils (pacman -S mingw-w64-ucrt-x86_64-binutils)" >&2
    exit 1
fi
strip --strip-unneeded "$STAGE_DIR/StockFW.exe"
echo "  Stripped StockFW.exe"

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

# The location database reader needs liblzma (xz) and OpenSSL's
# libcrypto; an installer without them would install a program that
# cannot read the database, so their absence stops the build.
for pattern in 'liblzma-*.dll' 'libcrypto-*-x64.dll'; do
    if ! ls "$STAGE_DIR/gtk-runtime/bin/"$pattern >/dev/null 2>&1; then
        echo "ERROR: $pattern is not in $MSYS_ROOT/bin" >&2
        echo "  pacman -S mingw-w64-ucrt-x86_64-xz mingw-w64-ucrt-x86_64-openssl" >&2
        exit 1
    fi
done

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
cat > "$STAGE_DIR/LICENSE.txt" << EOF
StockFW Firewall Configuration Tool
Version $VERSION

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
liblzma from XZ Utils (BSD Zero Clause License, 0BSD; releases before
  5.6 are in the public domain) -- unpacks the location database
OpenSSL libcrypto 3 (Apache License 2.0; the full text is the Apache
  License 2.0 at the end of this file; copyright The OpenSSL Project
  Authors) -- verifies the location database signature

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
# The project README (the Documentation shortcut opens it) and the
# changelog, from the repository root.  Both are required: until 1.0.7
# this step looked for port/README.md, which does not exist, and
# silently shipped a one-line stub plus a changelog kept in a heredoc
# here that had fallen a release behind.
for doc in README.md CHANGELOG.md; do
    if [ ! -s "$ROOT_DIR/$doc" ]; then
        echo "ERROR: $doc is missing from the repository root" >&2
        exit 1
    fi
    cp "$ROOT_DIR/$doc" "$STAGE_DIR/$doc"
done
# Installed without docs/ and port/ beside it: the README's relative
# links point at the repository at this release's tag instead.
sh "$PORT_DIR/tools/readme-for-package.sh" "$VERSION" \
    "$ROOT_DIR/README.md" "$STAGE_DIR/README.md"
if ! grep -q "^## \[$VERSION\]" "$STAGE_DIR/CHANGELOG.md"; then
    echo "ERROR: CHANGELOG.md has no section for $VERSION" >&2
    exit 1
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
#
# APP_VERSION is passed with "-D", not "/D": makensis takes either, and
# an MSYS2 shell leaves an argument without a leading slash alone.
"$NSIS_CMD" "-DAPP_VERSION=$VERSION" "$NSIS_SCRIPT"

echo ""
echo "=========================================="
echo "Installer built successfully!"
echo "Output: $INSTALLER_DIR/StockFW-$VERSION-Setup.exe"
echo "=========================================="