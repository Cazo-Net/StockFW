#!/bin/bash
# installer/linux/install.sh and the stockfw-uninstall it writes, run for
# real -- in a private mount namespace, with a scratch PREFIX and an
# empty tmpfs over /etc/systemd/system, so the host is not touched.
#
# What it proves: the boot unit is installed with ExecStart pointing at
# the installed `stockfw', and enabled (the multi-user.target.wants
# link); the uninstaller disables and removes it, and removes the
# binaries.  Needs root and unshare; SKIP otherwise.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"

if [ "$(id -u)" -ne 0 ] || ! command -v unshare >/dev/null 2>&1; then
	echo "SKIP: needs root and unshare"
	exit 0
fi
if ! command -v systemctl >/dev/null 2>&1; then
	echo "SKIP: systemctl not installed"
	exit 0
fi
if [ ! -x "$PORT/build-linux/StockFW" ] || [ ! -x "$PORT/build-linux/stockfw" ]; then
	echo "SKIP: build StockFW and stockfw first (ninja -C build-linux)"
	exit 0
fi

if [ "${STOCKFW_INSTALL_IN_MNTNS:-}" != "1" ]; then
	exec env STOCKFW_INSTALL_IN_MNTNS=1 unshare -m --propagation private bash "$0" "$@"
fi

failures=0
ok ()   { echo "ok:   $*"; }
fail () { echo "FAIL: $*"; failures=$((failures + 1)); }
check () { local what="$1"; shift; if "$@"; then ok "$what"; else fail "$what"; fi; }

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
mkdir -p /etc/systemd/system
mount -t tmpfs none /etc/systemd/system || { echo "SKIP: cannot mount a tmpfs"; exit 0; }
# Hide a running systemd from the installer as well: it would reload
# the host's manager, which cannot see this namespace's unit directory.
# With /run/systemd empty, systemctl works offline (it only makes the
# links), exactly as when installing into an image.
if [ -d /run/systemd ]; then
	mount -t tmpfs none /run/systemd || { echo "SKIP: cannot hide /run/systemd"; exit 0; }
fi

PREFIX="$SCRATCH/prefix"
UNIT=/etc/systemd/system/stockfw.service
WANTS=/etc/systemd/system/multi-user.target.wants/stockfw.service

PREFIX="$PREFIX" bash "$PORT/installer/linux/install.sh" > "$SCRATCH/install.log" 2>&1
rc=$?
check "install.sh succeeds (rc=$rc)" [ "$rc" -eq 0 ]
check "the boot unit is installed" [ -f "$UNIT" ]
check "...running the installed stockfw" grep -qx "ExecStart=$PREFIX/bin/stockfw start" "$UNIT"
check "...with no ExecStop" bash -c "! grep -q '^ExecStop' '$UNIT'"
check "...and enabled for boot" [ -L "$WANTS" ]
grep -q "puts the rules back before the network comes up" "$SCRATCH/install.log" &&
	ok "the summary says what the service does" ||
	fail "the summary says what the service does"

timeout 60 bash "$PREFIX/bin/stockfw-uninstall" > "$SCRATCH/uninstall.log" 2>&1
rc=$?
check "stockfw-uninstall succeeds (rc=$rc: $(tail -1 "$SCRATCH/uninstall.log"))" [ "$rc" -eq 0 ]
# -L as well: a link left dangling would still be "enabled" to systemd.
check "the boot unit is disabled" [ ! -e "$WANTS" -a ! -L "$WANTS" ]
check "...and removed" [ ! -e "$UNIT" ]
check "the binaries are gone" [ ! -e "$PREFIX/bin/StockFW" -a ! -e "$PREFIX/bin/stockfw" ]

umount /etc/systemd/system
echo
if [ "$failures" -eq 0 ]; then
	echo "PASSED: 0 failure(s)"
else
	echo "FAILED: $failures failure(s)"
fi
exit $(( failures > 0 ))
