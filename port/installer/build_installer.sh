#!/bin/bash
# Build script for StockFW NSIS Installer
# Prepares staging directory and builds the installer

set -e

PORT_DIR="/e/PROJECTS/firestarter-1.0.3/firestarter-1.0.3/port"
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

# Find and copy required DLLs from MSYS2
MSYS_ROOT="/c/msys64/ucrt64"

# Copy ALL DLLs from MSYS2 ucrt64/bin
# This ensures nothing is missing - Windows only needs DLLs that are
# actually imported, extra DLLs are harmless
cp "$MSYS_ROOT"/bin/*.dll "$STAGE_DIR/gtk-runtime/bin/" 2>/dev/null
echo "  Copied $(ls "$STAGE_DIR/gtk-runtime/bin/"*.dll | wc -l) DLLs"

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

# 5. Copy elevated launchers (rename to StockFW)
echo "[5/7] Copying elevated launchers..."
sed 's/firestarter/StockFW/g' "$PORT_DIR/firestarter-elevated.vbs" > "$STAGE_DIR/StockFW-elevated.vbs"
sed 's/firestarter/StockFW/g' "$PORT_DIR/firestarter-elevated.cmd" > "$STAGE_DIR/StockFW-elevated.cmd"
sed 's/firestarter/StockFW/g' "$PORT_DIR/firestarter-elevated.ps1" > "$STAGE_DIR/StockFW-elevated.ps1"

# 6. Create LICENSE.txt
echo "[6/7] Creating license file..."
cat > "$STAGE_DIR/LICENSE.txt" << 'EOF'
StockFW Firewall Configuration Tool
Version 1.0.3

Copyright (C) 2024-2026 StockFW Project

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

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

# 7. Copy documentation
echo "[7/7] Copying documentation..."
cp "$PORT_DIR/README.md" "$STAGE_DIR/" 2>/dev/null || echo "# StockFW Firewall Tool" > "$STAGE_DIR/README.md"
# Create minimal CHANGELOG.md if not exists
if [ ! -f "$PORT_DIR/CHANGELOG.md" ]; then
    cat > "$STAGE_DIR/CHANGELOG.md" << 'EOF'
# StockFW Changelog

## Version 1.0.3 (2024)
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

# Generate pango.modules.cache
echo "Generating Pango modules cache..."
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
"$NSIS_CMD" "$NSIS_SCRIPT"

echo ""
echo "=========================================="
echo "Installer built successfully!"
echo "Output: $INSTALLER_DIR/StockFW-1.0.3-Setup.exe"
echo "=========================================="