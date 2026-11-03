#!/bin/bash
# End-to-end Linux event-monitor test: a real STOCKFW-DROP kernel line
# must travel fork -> tail -F -> pipe -> poll -> parse -> callback and
# arrive as a populated FsHit; a foreign line must not.
#
# Complements test-logstart.sh, which only proves the monitor is either
# honestly running or honestly refused.  This one proves that when it
# runs, traffic actually shows up -- the silent-empty-list failure.
#
# Uses the backend's own STOCKFW_LOG_FILE override seam, so the real
# tail/parser code runs against a scratch file.  Needs root.
#
#   sudo ./tests/test-logstart-events.sh

set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"

if [ -d /ucrt64/bin ]; then
  export PATH="/ucrt64/bin:$PATH"
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "SKIP: this test needs root (the Linux log reader refuses without it)"
  exit 0
fi

# The Linux backend is the unit under test; it needs ifaddrs.h, which is
# POSIX-only.  On MSYS2 (even elevated to root) it cannot compile, so say
# so rather than reporting a false failure for a file that was never
# meant to build on this host.
if ! echo '#include <ifaddrs.h>' | cc -E -xc - >/dev/null 2>&1; then
  echo "SKIP: no POSIX ifaddrs.h on this host -- the Linux event monitor"
  echo "      only builds on a real Linux toolchain"
  exit 0
fi

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

cd "$PORT"

cc "$HERE/test-logstart-events.c" \
   -I src \
   $(pkg-config --cflags glib-2.0 gio-2.0 liblzma libcrypto) \
   -o "$BUILD_DIR/test-logstart-events" \
   src/platform/linux/fs-backend-linux.c \
   src/core/*.c \
   $(pkg-config --libs glib-2.0 gio-2.0 liblzma libcrypto)

"$BUILD_DIR/test-logstart-events"
