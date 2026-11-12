#!/bin/bash
# The Linux event monitor reading the kernel ring buffer (/dev/kmsg):
# real LOG lines arrive with the right verdict, forged user-space lines
# do not.  See test-logstart-kmsg.c.  Needs root, iptables, and a host
# (/dev/kmsg is tried before /var/log/kern.log, so a kern.log does not matter).
#
#   sudo ./tests/test-logstart-kmsg.sh

set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"

if [ "$(id -u)" -ne 0 ]; then
  echo "SKIP: this test needs root"
  exit 0
fi
if ! command -v iptables >/dev/null 2>&1; then
  echo "SKIP: no iptables"
  exit 0
fi
if ! echo '#include <ifaddrs.h>' | cc -E -xc - >/dev/null 2>&1; then
  echo "SKIP: no POSIX toolchain"
  exit 0
fi

BUILD_DIR="$(mktemp -d)"
cleanup () {
  # Whatever happened, take the temporary LOG rules out again.
  while iptables -w -S OUTPUT 2>/dev/null | grep -q stockfw-kmsg-test; do
    rule="$(iptables -w -S OUTPUT | grep stockfw-kmsg-test | head -n 1)"
    eval "iptables -w ${rule/-A/-D}" || break
  done
  rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

cd "$PORT"

cc "$HERE/test-logstart-kmsg.c" \
   -I src \
   $(pkg-config --cflags glib-2.0 gio-2.0 liblzma libcrypto json-glib-1.0) \
   -o "$BUILD_DIR/test-logstart-kmsg" \
   src/platform/linux/fs-backend-linux.c \
   src/core/*.c \
   $(pkg-config --libs glib-2.0 gio-2.0 liblzma libcrypto json-glib-1.0)

"$BUILD_DIR/test-logstart-kmsg"

