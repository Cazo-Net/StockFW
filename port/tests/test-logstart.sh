#!/bin/bash
# Builds the platform event source on its own and checks that it
# either actually monitors or explains why it cannot.
#
#   ./tests/test-logstart.sh

set -e

# Locate the toolchain: MSYS2's UCRT64 prefix on Windows, plain gcc
# elsewhere.
if [ -d /ucrt64/bin ]; then
  export PATH="/ucrt64/bin:$PATH"
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"

cd "$PORT"

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

if [ "${OS:-}" = "Windows_NT" ] || [ -d /ucrt64 ]; then
  BACKEND="src/platform/windows/fs-backend-windows.c src/platform/windows/fs-trust-win.c"
  PLATFORM_LIBS="-lws2_32 -lole32 -loleaut32 -liphlpapi -lwintrust -lcrypt32"
else
  BACKEND=src/platform/linux/fs-backend-linux.c
  PLATFORM_LIBS=""
fi

cc "$HERE/test-logstart.c" \
   -I src \
   $(pkg-config --cflags glib-2.0) \
   -o "$BUILD_DIR/test-logstart" \
   $BACKEND \
   src/core/*.c \
   $(pkg-config --libs glib-2.0 gio-2.0 liblzma libcrypto) $PLATFORM_LIBS

"$BUILD_DIR/test-logstart"
