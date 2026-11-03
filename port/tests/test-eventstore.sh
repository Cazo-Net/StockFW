#!/bin/bash
# The event store and the on-disk event history: core/fs-eventstore.c
# and core/fs-eventlog.c, against the core sources directly (no CMake),
# like test-core.sh.  GLib only, no display, no root.
#
#   cd port && bash tests/test-eventstore.sh
#   bash tests/test-eventstore.sh bench 100000     # timings and RSS
set -e

if [ -d /ucrt64/bin ]; then
  export PATH="/ucrt64/bin:$PATH"
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
cd "$PORT"

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

# src/core/*.c is every core source, so the link needs every Windows
# library any of them calls (fs-autostart: COM; fs-hostnet: IP Helper;
# fs-eventlog: the security API for the history's owner-only DACL),
# not only the ones this test reaches.
EXTRA_LIBS=""
if [ "${OS:-}" = "Windows_NT" ] || [ -d /ucrt64 ]; then
  EXTRA_LIBS="-lws2_32 -lole32 -loleaut32 -liphlpapi -ladvapi32 -lshell32"
fi

cc -O2 -Wall -Wextra -Wno-unused-parameter tests/test-eventstore.c \
   -I src \
   $(pkg-config --cflags glib-2.0 gio-2.0 liblzma libcrypto) \
   -o "$BUILD_DIR/test-eventstore" \
   src/core/*.c \
   $(pkg-config --libs glib-2.0 gio-2.0 liblzma libcrypto) $EXTRA_LIBS

export STOCKFW_RULES_DIR="$BUILD_DIR/rules"
"$BUILD_DIR/test-eventstore" "$@"
