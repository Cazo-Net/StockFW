#!/bin/bash
# The Windows Security-log reader's logic (core/fs-winevt.c) against a
# fake log, on any platform: wevtutil XML parsing, the poll query and
# argv, bursts of 4,000 and past the 10,000 cap, cut-short reads, a
# cleared log, rollover and slow reads.  GLib only, no display, no
# root, no Windows.  test-winlog.sh runs the same fake log through the
# real spawn on Windows.
#
#   cd port && bash tests/test-winevt.sh
set -e

if [ -d /ucrt64/bin ]; then
  export PATH="/ucrt64/bin:$PATH"
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
cd "$PORT"

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

EXTRA_LIBS=""
if [ "${OS:-}" = "Windows_NT" ] || [ -d /ucrt64 ]; then
  EXTRA_LIBS="-lws2_32"
fi

cc -O2 -Wall -Wextra -Wno-unused-parameter tests/test-winevt.c \
   -I src -I tests \
   $(pkg-config --cflags glib-2.0 gio-2.0) \
   -o "$BUILD_DIR/test-winevt" \
   src/core/*.c \
   $(pkg-config --libs glib-2.0 gio-2.0) $EXTRA_LIBS

export STOCKFW_RULES_DIR="$BUILD_DIR/rules"
"$BUILD_DIR/test-winevt" "$@"
