#!/bin/bash
# Start at sign-in on Linux, through the real binary
# (src/core/fs-autostart.c, src/main.c --enable/--disable-autostart).
#
# What it proves:
#   - --enable-autostart writes $XDG_CONFIG_HOME/autostart/stockfw.desktop
#     that runs this very binary with --background, by name when PATH
#     finds it and by a correctly quoted absolute path when not;
#   - the entry is a valid desktop entry (desktop-file-validate, when
#     installed);
#   - --disable-autostart removes it, and succeeds when it is already
#     gone;
#   - as root on behalf of a user (sudo/pkexec), the entry is written
#     with THAT user's file permissions: it ends up owned by the user,
#     and a directory the user cannot write is refused instead of
#     being written by root.  (Root only; SKIP otherwise.)
#
# No display needed: the switches run before GTK.  Nothing outside a
# scratch directory is touched.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
BUILD="${STOCKFW_BUILD:-$PORT/build-linux}"
BIN="$BUILD/StockFW"

if [ ! -x "$BIN" ]; then
	echo "SKIP: $BIN not built (ninja -C build-linux StockFW)"
	exit 0
fi

failures=0
ok ()   { echo "ok:   $*"; }
fail () { echo "FAIL: $*"; failures=$((failures + 1)); }
check () { local what="$1"; shift; if "$@"; then ok "$what"; else fail "$what"; fi; }

SCRATCH="$(mktemp -d)"
chmod 755 "$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT

export HOME="$SCRATCH/home"
export XDG_CONFIG_HOME="$SCRATCH/config"
unset STOCKFW_AUTOSTART_DIR SUDO_UID PKEXEC_UID
mkdir -p "$HOME"
ENTRY="$XDG_CONFIG_HOME/autostart/stockfw.desktop"
exec_line () { sed -n 's/^Exec=//p' "$1"; }

# ---------------------------------------------------------------- 1. on, by path
PATH_NO_BUILD="/usr/bin:/bin"
env PATH="$PATH_NO_BUILD" "$BIN" --enable-autostart > "$SCRATCH/on.log" 2>&1
rc=$?
check "--enable-autostart succeeds (rc=$rc)" [ "$rc" -eq 0 ]
check "it writes \$XDG_CONFIG_HOME/autostart/stockfw.desktop" [ -f "$ENTRY" ]
REAL_BIN="$(readlink -f "$BIN")"
got="$(exec_line "$ENTRY")"
check "not on PATH: Exec runs this binary by absolute path with --background (got: $got)" \
	[ "$got" = "$REAL_BIN --background" ]
check "the entry is an application, switched on" \
	grep -qx "Type=Application" "$ENTRY"
check "...with X-GNOME-Autostart-enabled=true" \
	grep -qx "X-GNOME-Autostart-enabled=true" "$ENTRY"
check "the entry is readable by the desktop (mode 644)" \
	[ "$(stat -c %a "$ENTRY")" = "644" ]
grep -q "cannot change rules" "$SCRATCH/on.log" &&
	ok "it says plainly that the sign-in copy runs without root" ||
	fail "it says plainly that the sign-in copy runs without root ($(cat "$SCRATCH/on.log"))"
if command -v desktop-file-validate >/dev/null 2>&1; then
	out="$(desktop-file-validate "$ENTRY" 2>&1)"
	check "desktop-file-validate accepts it ($out)" [ -z "$out" ]
else
	echo "SKIP: desktop-file-validate not installed"
fi

# ---------------------------------------------------------------- 2. on, by name
env PATH="$BUILD:$PATH_NO_BUILD" "$BIN" --enable-autostart > /dev/null 2>&1
got="$(exec_line "$ENTRY")"
check "on PATH: Exec=StockFW --background (got: $got)" \
	[ "$got" = "StockFW --background" ]

# ---------------------------------------------------------------- 3. a path that needs quoting
ODD="$SCRATCH/dir with space"
mkdir -p "$ODD"
cp "$BIN" "$ODD/StockFW"
env PATH="$PATH_NO_BUILD" "$ODD/StockFW" --enable-autostart > /dev/null 2>&1
got="$(exec_line "$ENTRY")"
check "a path with a space is quoted (got: $got)" \
	[ "$got" = "\"$ODD/StockFW\" --background" ]
if command -v desktop-file-validate >/dev/null 2>&1; then
	out="$(desktop-file-validate "$ENTRY" 2>&1)"
	check "...and still validates ($out)" [ -z "$out" ]
fi

# ---------------------------------------------------------------- 4. off
"$BIN" --disable-autostart > "$SCRATCH/off.log" 2>&1
rc=$?
check "--disable-autostart succeeds (rc=$rc)" [ "$rc" -eq 0 ]
check "...and the entry is gone" [ ! -e "$ENTRY" ]
"$BIN" --disable-autostart > /dev/null 2>&1
rc=$?
check "--disable-autostart with nothing set up succeeds (rc=$rc)" [ "$rc" -eq 0 ]
"$BIN" --enable-autostart --disable-autostart > /dev/null 2>&1
rc=$?
check "two contradictory switches are refused (rc=$rc)" [ "$rc" -ne 0 ]

# ---------------------------------------------------------------- 5. root on behalf of a user
if [ "$(id -u)" -eq 0 ]; then
	NOBODY_UID="$(id -u nobody 2>/dev/null || echo 65534)"
	USERDIR="$SCRATCH/userhome/autostart"
	mkdir -p "$USERDIR"
	chown "$NOBODY_UID" "$USERDIR"
	env SUDO_UID="$NOBODY_UID" STOCKFW_AUTOSTART_DIR="$USERDIR" \
		"$BIN" --enable-autostart > "$SCRATCH/sudo.log" 2>&1
	rc=$?
	check "under sudo: --enable-autostart succeeds (rc=$rc)" [ "$rc" -eq 0 ]
	check "...and the entry belongs to the user, not root" \
		[ "$(stat -c %u "$USERDIR/stockfw.desktop" 2>/dev/null)" = "$NOBODY_UID" ]

	ROOTDIR="$SCRATCH/rootonly/autostart"
	mkdir -p "$ROOTDIR"
	chmod 755 "$ROOTDIR"
	env SUDO_UID="$NOBODY_UID" STOCKFW_AUTOSTART_DIR="$ROOTDIR" \
		"$BIN" --enable-autostart > "$SCRATCH/sudo2.log" 2>&1
	rc=$?
	check "under sudo: a directory the user cannot write is refused (rc=$rc)" [ "$rc" -ne 0 ]
	check "...and root wrote nothing there" [ ! -e "$ROOTDIR/stockfw.desktop" ]

	env SUDO_UID="$NOBODY_UID" STOCKFW_AUTOSTART_DIR="$USERDIR" \
		"$BIN" --disable-autostart > /dev/null 2>&1
	check "under sudo: --disable-autostart removes the user's entry" \
		[ ! -e "$USERDIR/stockfw.desktop" ]
else
	echo "SKIP: the sudo checks need root"
fi

echo
if [ "$failures" -eq 0 ]; then
	echo "PASSED: 0 failure(s)"
else
	echo "FAILED: $failures failure(s)"
fi
exit $(( failures > 0 ))
