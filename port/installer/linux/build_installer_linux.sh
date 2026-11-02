#!/bin/bash
# Build the Linux installer package.
#
# Mirrors installer/build_installer.sh (the Windows/NSIS one): stages a
# self-contained payload directory, then tars it so the result is a
# single file a user can download and run.
#
#   ./build_installer_linux.sh          -> installer/linux/dist/StockFW-<version>-linux-<machine>.tar.gz
#
# Unlike the Windows build, there is no GTK runtime to bundle: on Linux
# GTK3 comes from the distribution's own packages and the dynamic linker
# resolves it.  Bundling it would be both unnecessary and wrong (it would
# bypass the distro's security updates).  The payload is therefore small:
# binary, desktop entry, icon, license, install script.
set -euo pipefail

PORT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT_DIR_ROOT="$(cd "$PORT_DIR/.." && pwd)"
LINUX_DIR="$PORT_DIR/installer/linux"
BUILD_DIR="$PORT_DIR/build-linux"
DIST_DIR="$LINUX_DIR/dist"

# Version comes from the binary itself, not a literal here: the CMake
# project version is the single source of truth and the binary reports it.
VERSION="$(timeout 10 "$BUILD_DIR/StockFW" --version 2>/dev/null \
           | sed -n 's/^StockFW \([0-9.]*\).*/\1/p')"
if [ -z "$VERSION" ]; then
    echo "ERROR: could not read the version from $BUILD_DIR/StockFW" >&2
    echo "       Run:  cd port && bash tools/build-linux.sh" >&2
    exit 1
fi

MACHINE="$(uname -m)"
NAME="StockFW-$VERSION-linux-$MACHINE"
STAGE="$DIST_DIR/$NAME"

echo "=========================================="
echo "StockFW Linux Installer Build"
echo "  version:  $VERSION"
echo "  machine:  $MACHINE"
echo "=========================================="

rm -rf "$STAGE"
mkdir -p "$STAGE"

# 1. the binary -- and it must be a real ELF.  An MSYS2 build produces a
#    PE executable that installs fine and then dies at exec with a bare
#    "Exec format error"; refuse to package it rather than ship a dud.
echo "[1/5] Copying binary..."
MAGIC="$(od -An -tx1 -N4 "$BUILD_DIR/StockFW" | tr -d ' \n')"
if [ "$MAGIC" != "7f454c46" ]; then
    echo "ERROR: $BUILD_DIR/StockFW is not a Linux ELF (magic: $MAGIC)" >&2
    echo "       Build it on Linux:  cd port && bash tools/build-linux.sh" >&2
    exit 1
fi
cp "$BUILD_DIR/StockFW" "$STAGE/StockFW"
echo "  ok: ELF confirmed"

# The command-line tool and dashboard (1.0.6).  Staged in its own
# directory: "stockfw" beside "StockFW" would be one file on a
# case-insensitive filesystem, and a tarball can be unpacked anywhere.
if [ -f "$BUILD_DIR/stockfw" ]; then
    MAGIC="$(od -An -tx1 -N4 "$BUILD_DIR/stockfw" | tr -d ' \n')"
    if [ "$MAGIC" != "7f454c46" ]; then
        echo "ERROR: $BUILD_DIR/stockfw is not a Linux ELF (magic: $MAGIC)" >&2
        exit 1
    fi
    mkdir -p "$STAGE/cli"
    cp "$BUILD_DIR/stockfw" "$STAGE/cli/stockfw"
    echo "  ok: command-line tool staged (cli/stockfw)"
else
    echo "ERROR: $BUILD_DIR/stockfw is missing -- build it first:" >&2
    echo "       cmake -S . -B build-linux -G Ninja && ninja -C build-linux" >&2
    exit 1
fi

# 2. desktop entry + icon + license + installer scripts
echo "[2/5] Copying desktop integration..."
cp "$LINUX_DIR/stockfw.desktop"  "$STAGE/"
cp "$LINUX_DIR/stockfw-icon.png" "$STAGE/"
cp "$LINUX_DIR/LICENSE.txt"      "$STAGE/"

# 3. docs
# The Linux-specific README is the one the user reads after extracting;
# the project README rides along as background.  Both are checked, not
# silently skipped: the first version of this loop iterated over
# "$PORT_DIR/README.md", which does not exist, and shipped a tarball
# with no documentation at all and a zero exit status.
echo "[3/5] Copying documentation..."
cp "$LINUX_DIR/README.md" "$STAGE/README.md"
if [ -f "$PORT_DIR_ROOT/README.md" ]; then
    cp "$PORT_DIR_ROOT/README.md" "$STAGE/README-project.md"
fi
for f in README.md LICENSE.txt; do
    if [ ! -s "$STAGE/$f" ]; then
        echo "ERROR: $f missing or empty in the staged payload" >&2
        exit 1
    fi
done
echo "  ok: README.md, LICENSE.txt"

# 4. installer scripts
echo "[4/5] Copying installer scripts..."
cp "$LINUX_DIR/install.sh" "$STAGE/"

# 5. tar it up
echo "[5/5] Creating archive..."
mkdir -p "$DIST_DIR"
TARBALL="$DIST_DIR/$NAME.tar.gz"
# deterministic-ish: stable file order, no owner names, so two builds of
# the same tree produce comparable archives
tar --sort=name --owner=0 --group=0 --numeric-owner \
    -czf "$TARBALL" -C "$DIST_DIR" "$NAME"

SUM="$(sha256sum "$TARBALL" | cut -d' ' -f1)"
printf '%s  %s\n' "$SUM" "$(basename "$TARBALL")" > "$TARBALL.sha256"

echo ""
echo "=========================================="
echo "Installer built."
echo "  $TARBALL"
echo "  sha256: $SUM"
echo ""
echo "To install on the target machine:"
echo "  tar xzf $(basename "$TARBALL")"
echo "  cd $NAME"
echo "  sudo ./install.sh"
echo "=========================================="
