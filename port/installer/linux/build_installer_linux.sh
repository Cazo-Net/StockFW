#!/bin/bash
# Build the Linux installer package.
#
# Mirrors installer/build_installer.sh (the Windows/NSIS one): stages a
# self-contained payload directory, then tars it so the result is a
# single file a user can download and run.
#
#   ./build_installer_linux.sh          -> installer/linux/dist/StockFW-<version>-linux-<machine>.tar.gz
#
# Build the binaries first, as a Release build:
#
#   cd port && bash tools/build-linux.sh
#
# STOCKFW_BUILD_DIR names another build directory (CI packages a
# separate Release build that way).  The staged binaries are stripped:
# the release carries no debug information.
#
# Unlike the Windows build, there is no GTK runtime to bundle: on Linux
# GTK3 comes from the distribution's own packages and the dynamic linker
# resolves it.  Bundling it would be both unnecessary and wrong (it would
# bypass the distro's security updates).  The payload is therefore small:
# binary, desktop entry, icon, license, install script, boot unit.
set -euo pipefail

PORT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT_DIR_ROOT="$(cd "$PORT_DIR/.." && pwd)"
LINUX_DIR="$PORT_DIR/installer/linux"
BUILD_DIR="${STOCKFW_BUILD_DIR:-$PORT_DIR/build-linux}"
DIST_DIR="${STOCKFW_DIST_DIR:-$LINUX_DIR/dist}"

# Version comes from the binary itself, not a literal here: the CMake
# project version is the single source of truth and the binary reports it.
VERSION="$(timeout 10 "$BUILD_DIR/StockFW" --version 2>/dev/null \
           | sed -n 's/^StockFW \([0-9.]*\).*/\1/p')"
if [ -z "$VERSION" ]; then
    echo "ERROR: could not read the version from $BUILD_DIR/StockFW" >&2
    echo "       Run:  cd port && bash tools/build-linux.sh" >&2
    exit 1
fi

# ...and it must be the version the source names.  A build directory
# left over from an older checkout would otherwise be packaged under
# its own, older number.
SRC_VERSION="$(sed -n 's/^[[:space:]]*VERSION[[:space:]]\{1,\}\([0-9][0-9.]*\).*/\1/p' \
               "$PORT_DIR/CMakeLists.txt" | head -n 1)"
if [ "$VERSION" != "$SRC_VERSION" ]; then
    echo "ERROR: $BUILD_DIR/StockFW is version $VERSION, the source is $SRC_VERSION" >&2
    echo "       Rebuild:  cd port && bash tools/build-linux.sh" >&2
    exit 1
fi

# The binaries are stripped as they are staged: a RelWithDebInfo build
# is about 15 MB of DWARF per binary.  Missing strip stops the build
# rather than shipping the debug build.
if ! command -v strip >/dev/null 2>&1; then
    echo "ERROR: strip (binutils) is not installed" >&2
    exit 1
fi
stage_bin () {   # <built binary> <staged path>
    install -D -m755 "$1" "$2"
    strip --strip-unneeded "$2"
}

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
stage_bin "$BUILD_DIR/StockFW" "$STAGE/StockFW"
echo "  ok: ELF confirmed, stripped"

# The command-line tool and dashboard (1.0.6).  Staged in its own
# directory: "stockfw" beside "StockFW" would be one file on a
# case-insensitive filesystem, and a tarball can be unpacked anywhere.
if [ -f "$BUILD_DIR/stockfw" ]; then
    MAGIC="$(od -An -tx1 -N4 "$BUILD_DIR/stockfw" | tr -d ' \n')"
    if [ "$MAGIC" != "7f454c46" ]; then
        echo "ERROR: $BUILD_DIR/stockfw is not a Linux ELF (magic: $MAGIC)" >&2
        exit 1
    fi
    stage_bin "$BUILD_DIR/stockfw" "$STAGE/cli/stockfw"
    echo "  ok: command-line tool staged (cli/stockfw), stripped"
else
    echo "ERROR: $BUILD_DIR/stockfw is missing -- build it first:" >&2
    echo "       cd port && bash tools/build-linux.sh" >&2
    exit 1
fi

# 2. desktop entry + icon + license + installer scripts
echo "[2/5] Copying desktop integration..."
install -m644 "$LINUX_DIR/stockfw.desktop"      "$STAGE/"
install -m644 "$LINUX_DIR/stockfw-icon.png"     "$STAGE/"
install -m644 "$LINUX_DIR/stockfw-icon-48.png"  "$STAGE/"
install -m644 "$LINUX_DIR/stockfw-icon-256.png" "$STAGE/"
# The summary carries the release's own version (the file has none).
sed "s/@VERSION@/$VERSION/" "$LINUX_DIR/LICENSE.txt" > "$STAGE/LICENSE.txt"
# The summary, then both licence texts the source carries, in full
# (tests/test-licence-texts.sh).
for text in COPYING LICENSE; do
    if [ ! -s "$PORT_DIR_ROOT/$text" ]; then
        echo "ERROR: $text is missing from the source tree" >&2
        exit 1
    fi
    printf '\n---\n\n%s\n\n' "$text" >> "$STAGE/LICENSE.txt"
    cat "$PORT_DIR_ROOT/$text" >> "$STAGE/LICENSE.txt"
done

# 3. docs
# The Linux-specific README is the one the user reads after extracting;
# the project README rides along as background.  Both are checked, not
# silently skipped: the first version of this loop iterated over
# "$PORT_DIR/README.md", which does not exist, and shipped a tarball
# with no documentation at all and a zero exit status.
echo "[3/5] Copying documentation..."
install -m644 "$LINUX_DIR/README.md" "$STAGE/README.md"
# Alone in the archive, its relative links would lead nowhere: they
# point at the repository at this release's tag instead.
sh "$PORT_DIR/tools/readme-for-package.sh" "$VERSION" \
    "$PORT_DIR_ROOT/README.md" "$STAGE/README-project.md"
chmod 644 "$STAGE/README-project.md"
install -m644 "$PORT_DIR_ROOT/CHANGELOG.md" "$STAGE/CHANGELOG.md"
# The changelog must describe this release.
if ! grep -q "^## \[$VERSION\]" "$STAGE/CHANGELOG.md"; then
    echo "ERROR: CHANGELOG.md has no section for $VERSION" >&2
    exit 1
fi
for f in README.md README-project.md CHANGELOG.md LICENSE.txt; do
    if [ ! -s "$STAGE/$f" ]; then
        echo "ERROR: $f missing or empty in the staged payload" >&2
        exit 1
    fi
done
echo "  ok: README.md, README-project.md, CHANGELOG.md, LICENSE.txt"

# 4. installer scripts
echo "[4/5] Copying installer scripts..."
# install, not cp: the documented command is `sudo ./install.sh', so the
# script must reach the user executable whatever mode the checkout gave
# it (a tarball once shipped it 0644, and that command failed).
install -m755 "$LINUX_DIR/install.sh" "$STAGE/"
# The boot unit (1.0.7): without it the rules are gone after a reboot.
install -m644 "$LINUX_DIR/stockfw.service" "$STAGE/"

# 5. tar it up
echo "[5/5] Creating archive..."
mkdir -p "$DIST_DIR"
TARBALL="$DIST_DIR/$NAME.tar.gz"
# deterministic-ish: stable file order, no owner names, so two builds of
# the same tree produce comparable archives
tar --sort=name --owner=0 --group=0 --numeric-owner \
    -czf "$TARBALL" -C "$DIST_DIR" "$NAME"

# What the user unpacks: the entry points are executable in the archive
# itself, not only in the staging directory.
for exe in install.sh StockFW cli/stockfw; do
    mode="$(tar -tvzf "$TARBALL" "$NAME/$exe" | cut -c1-10)"
    if [ "$mode" != "-rwxr-xr-x" ]; then
        echo "ERROR: $exe is $mode in the archive, not -rwxr-xr-x" >&2
        exit 1
    fi
done
echo "  ok: install.sh, StockFW and cli/stockfw are executable in the archive"

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
