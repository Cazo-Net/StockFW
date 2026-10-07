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
   $(pkg-config --cflags glib-2.0 gio-2.0) \
   -o "$BUILD_DIR/test-winlog" \
   src/core/*.c \
   $(pkg-config --libs glib-2.0 gio-2.0) -lws2_32 -lole32 -loleaut32 -liphlpapi

"$BUILD_DIR/test-winlog"
