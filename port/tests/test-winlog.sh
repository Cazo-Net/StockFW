#!/bin/bash
# Regression test for the Windows event pipeline: de-duplication across
# polls and the field mapping of parsed firewall records.
#
# Windows-only (it compiles the Windows backend); on Linux it reports
# a skip and exits 0.
#
#   ./tests/test-winlog.sh

set -e

# Locate the toolchain: MSYS2's UCRT64 prefix on Windows, plain gcc
# elsewhere.
if [ -d /ucrt64/bin ]; then
  export PATH="/ucrt64/bin:$PATH"
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"

cd "$PORT"

if [ ! "${OS:-}" = "Windows_NT" ] && [ ! -d /ucrt64 ]; then
  echo "ok:   test-winlog skipped (Windows-only)"
  exit 0
fi

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

cc "$HERE/test-winlog.c" \
   -I src \
   $(pkg-config --cflags glib-2.0 gio-2.0 liblzma libcrypto) \
   -o "$BUILD_DIR/test-winlog" \
   src/core/*.c \
   src/platform/windows/fs-trust-win.c \
   $(pkg-config --libs glib-2.0 gio-2.0 liblzma libcrypto) -lws2_32 -lole32 -loleaut32 -liphlpapi -lwintrust -lcrypt32

# The end-to-end test needs a fake wevtutil.exe beside the test
# binary: CreateProcess searches the process's own directory before
# System32, so the backend's probe and poll run against canned
# (byte-honest) records without Administrator rights to read the real
# Security log.
cc "$HERE/fake-wevtutil.c" -o "$BUILD_DIR/wevtutil.exe"

"$BUILD_DIR/test-winlog"

# The window-flash probe: runs as a console-less parent (FreeConsole),
# which is the shape StockFW.exe has.  Its stdout must be a file, not
# the console -- FreeConsole() invalidates console handles while file
# handles keep working -- so capture first, then replay.
probe_rc=0
"$BUILD_DIR/test-winlog" --spawn-probe > "$BUILD_DIR/spawn-probe.out" || probe_rc=$?
cat "$BUILD_DIR/spawn-probe.out"
if [ "$probe_rc" -ne 0 ]; then
  echo "spawn-probe exited $probe_rc"
  exit "$probe_rc"
fi
