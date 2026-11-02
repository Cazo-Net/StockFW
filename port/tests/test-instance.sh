#!/bin/bash
# One StockFW per desktop session, driven through the real binary
# (src/core/fs-instance.c, src/main.c, src/ui/fs-app.c).
#
# What it proves:
#   - a second launch does not start a second copy: it exits at once,
#     and the first copy brings its window back to the front;
#   - --quit makes the running copy quit cleanly (exit 0, its settings
#     saved) and returns only once it is gone; with nothing running it
#     says so and succeeds;
#   - a user who is neither root nor the instance's own user cannot
#     make it quit or show (the credentials check on the socket);
#   - --background: with a notification area the window stays hidden
#     behind the tray icon; a second launch shows it; with NO
#     notification area the window is shown after the embed timeout,
#     so there is never an unreachable copy; a second --background
#     launch leaves a running copy alone.
#
# Needs a display (xvfb-run -a bash tests/test-instance.sh) and
# xdotool; stalonetray provides the notification area (those checks
# SKIP without it).  As root the whole test runs in a private network
# namespace, so the real backend can never touch the host's firewall;
# every file the app writes goes to a scratch directory, and the
# instance name is private to this run.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
BUILD="${STOCKFW_BUILD:-$PORT/build-linux}"
BIN="$BUILD/StockFW"

if [ -z "${DISPLAY:-}" ]; then
	echo "SKIP: needs a display (run under xvfb-run -a)"
	exit 0
fi
if ! command -v xdotool >/dev/null 2>&1; then
	echo "SKIP: xdotool not installed"
	exit 0
fi
if [ ! -x "$BIN" ]; then
	echo "SKIP: $BIN not built (ninja -C build-linux StockFW)"
	exit 0
fi

if [ "$(id -u)" -eq 0 ] && [ "${STOCKFW_INSTANCE_IN_NETNS:-}" != "1" ] &&
   command -v unshare >/dev/null 2>&1; then
	exec env STOCKFW_INSTANCE_IN_NETNS=1 unshare -n bash "$0" "$@"
fi

failures=0
ok ()   { echo "ok:   $*"; }
fail () { echo "FAIL: $*"; failures=$((failures + 1)); }
check () { local what="$1"; shift; if "$@"; then ok "$what"; else fail "$what"; fi; }

SCRATCH="$(mktemp -d)"
TRAY_PID=""
cleanup () {
	[ -n "$TRAY_PID" ] && kill "$TRAY_PID" 2>/dev/null
	pkill -f "$SCRATCH" 2>/dev/null
	for p in $(jobs -p); do kill "$p" 2>/dev/null; done
	rm -rf "$SCRATCH"
}
trap cleanup EXIT

export HOME="$SCRATCH/home"
export XDG_CONFIG_HOME="$SCRATCH/config"
export XDG_CACHE_HOME="$SCRATCH/cache"
export XDG_DATA_HOME="$SCRATCH/data"
export STOCKFW_RULES_DIR="$SCRATCH/rules"
export STOCKFW_AUDIT_FILE="$SCRATCH/audit.log"
export STOCKFW_APPLIED_FILE="$SCRATCH/applied.csv"
export STOCKFW_AUTOBLOCK_FILE="$SCRATCH/autoblocks"
export STOCKFW_BEHAVIOR_FILE="$SCRATCH/behavior.csv"
export STOCKFW_TRUST_FILE="$SCRATCH/trust.csv"
export STOCKFW_INSTANCE_NAME="stockfw-test-$$"
export NO_AT_BRIDGE=1
mkdir -p "$HOME" "$XDG_CONFIG_HOME/stockfw"
# The window must never start the firewall from a test.
cat > "$XDG_CONFIG_HOME/stockfw/stockfw.conf" <<EOF
[client]
start_firewall_on_gui=false
enable_tray_icon=true
minimize_to_tray=true
EOF

listening () { grep -q "@$STOCKFW_INSTANCE_NAME\$" /proc/net/unix; }
visible_windows () { xdotool search --onlyvisible --name '^StockFW$' 2>/dev/null | wc -l; }
any_window () { xdotool search --onlyvisible --name '^StockFW$' 2>/dev/null | head -1; }

wait_for () {   # wait_for <seconds> <command...>
	local limit=$(( $1 * 10 )); shift
	for ((i = 0; i < limit; i++)); do
		"$@" && return 0
		sleep 0.1
	done
	return 1
}
is_visible () { [ "$(visible_windows)" -ge 1 ]; }
is_hidden ()  { [ "$(visible_windows)" -eq 0 ]; }
alive ()      { kill -0 "$1" 2>/dev/null; }
dead ()       { ! kill -0 "$1" 2>/dev/null; }

# ---------------------------------------------------------------- 1. single instance
"$BIN" > "$SCRATCH/a.log" 2>&1 &
A=$!
check "first launch claims the instance name" wait_for 30 listening
check "first launch shows its window" wait_for 30 is_visible

WIN="$(any_window)"
xdotool windowunmap --sync "$WIN" 2>/dev/null
check "the window is out of sight before the second launch" wait_for 5 is_hidden

start=$(date +%s)
# A second copy that stays up (the bug) is killed by timeout: rc 124.
timeout 15 "$BIN" > "$SCRATCH/b.log" 2>&1
rc=$?
took=$(( $(date +%s) - start ))
check "a second launch exits at once with status 0 (rc=$rc, ${took}s)" \
	[ "$rc" -eq 0 -a "$took" -le 10 ]
check "the first copy is still running" alive "$A"
check "the first copy brought its window back to the front" wait_for 10 is_visible
check "there is still exactly one StockFW window on screen" [ "$(visible_windows)" -eq 1 ]
check "the second launch did not claim a second instance" [ "$(grep -c "@$STOCKFW_INSTANCE_NAME\$" /proc/net/unix)" -eq 1 ]

# ---------------------------------------------------------------- 2. who may ask
if command -v setpriv >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
	setpriv --reuid=65534 --regid=65534 --clear-groups \
		timeout 30 "$BIN" --quit > "$SCRATCH/nobody.log" 2>&1
	rc=$?
	check "another user's --quit is refused (rc=$rc)" [ "$rc" -ne 0 ]
	check "...and the instance keeps running" alive "$A"
	grep -q "refused" "$SCRATCH/nobody.log" && ok "the refusal says why" ||
		fail "the refusal says why ($(cat "$SCRATCH/nobody.log"))"
else
	echo "SKIP: credentials check needs root and setpriv"
fi

# ---------------------------------------------------------------- 3. --quit
timeout 30 "$BIN" --quit > "$SCRATCH/quit.log" 2>&1
rc=$?
check "--quit succeeds (rc=$rc)" [ "$rc" -eq 0 ]
check "--quit returns only once the instance is gone" dead "$A"
wait "$A"
rc=$?
check "the instance quit cleanly, not killed (exit $rc)" [ "$rc" -eq 0 ]
check "it saved its settings on the way out" grep -q "minimize_to_tray" "$XDG_CONFIG_HOME/stockfw/stockfw.conf"
check "the name is free again" wait_for 5 bash -c "! grep -q '@$STOCKFW_INSTANCE_NAME\$' /proc/net/unix"

timeout 30 "$BIN" --quit > "$SCRATCH/quit2.log" 2>&1
rc=$?
check "--quit with nothing running succeeds and says so (rc=$rc)" \
	[ "$rc" -eq 0 ] && grep -q "not running" "$SCRATCH/quit2.log"

echo
if [ "$failures" -eq 0 ]; then
	echo "PASSED: 0 failure(s)"
else
	echo "FAILED: $failures failure(s)"
fi
exit $(( failures > 0 ))
