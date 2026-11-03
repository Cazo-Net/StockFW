#!/bin/bash
# Build StockFW for Linux: the desktop app (build-linux/StockFW) and the
# command-line tool (build-linux/stockfw), the two binaries the Linux
# packager (installer/linux/build_installer_linux.sh) stages.
#
#   cd port && bash tools/build-linux.sh            # Release build
#   BUILD_TYPE=RelWithDebInfo bash tools/build-linux.sh
#   STOCKFW_BUILD_DIR=/tmp/b bash tools/build-linux.sh
#
# It is CMake, not a second build system.  Until 1.0.7 this script
# compiled a hand-written list of sources with gcc; the list fell
# behind CMakeLists.txt (no fs-whatif, fs-intel, fs-geodb, ...; no
# liblzma or libcrypto) and the link failed, while the Linux README and
# every packager hint still pointed here.  CMakeLists.txt is now the one
# place that names the sources, the libraries and the version; this
# script only runs it with the settings a release package wants.
#
# Linux only: on MSYS2 build the Windows program with
#   cmake -S . -B build -G Ninja && cmake --build build
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="$(dirname "$HERE")"
OUT="${STOCKFW_BUILD_DIR:-$PORT/build-linux}"
TYPE="${BUILD_TYPE:-Release}"

if [ "$(uname -s)" != "Linux" ]; then
	echo "ERROR: tools/build-linux.sh builds the Linux program on Linux." >&2
	echo "       On Windows (MSYS2 UCRT64):" >&2
	echo "         cd port && cmake -S . -B build -G Ninja && cmake --build build" >&2
	exit 1
fi

for tool in cmake pkg-config; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "ERROR: $tool is not installed." >&2
		echo "       Debian/Ubuntu: sudo apt install build-essential cmake ninja-build \\" >&2
		echo "                        pkg-config libgtk-3-dev liblzma-dev libssl-dev" >&2
		exit 1
	fi
done

# Ninja when it is there (what CI and the README use), else CMake's
# default generator -- unless the directory was already configured,
# when CMake must keep the generator it has.
GEN=()
if [ ! -f "$OUT/CMakeCache.txt" ] && command -v ninja >/dev/null 2>&1; then
	GEN=(-G Ninja)
fi

cmake -S "$PORT" -B "$OUT" "${GEN[@]}" -DCMAKE_BUILD_TYPE="$TYPE"
cmake --build "$OUT" --target StockFW stockfw -j "$(nproc 2>/dev/null || echo 2)"

for bin in StockFW stockfw; do
	if [ ! -x "$OUT/$bin" ]; then
		echo "ERROR: $OUT/$bin was not built" >&2
		exit 1
	fi
done

echo
echo "ok:   $OUT/StockFW  ($(timeout 10 "$OUT/StockFW" --version 2>/dev/null || echo '?'))"
echo "ok:   $OUT/stockfw"
echo "Package it:  bash installer/linux/build_installer_linux.sh"
