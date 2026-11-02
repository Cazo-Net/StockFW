#!/bin/bash
# One StockFW per user, driven through the real binary
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
#     launch leaves a running copy alone;
#   - SIGTERM, SIGINT and SIGHUP quit cleanly: exit 0, settings and
#     the Copilot baseline written; under nohup SIGHUP stays ignored;
#   - connections that never speak, from another account or from root,
#     do not hold up a show or a --quit behind them;
#   - root's copy (sudo StockFW) takes over from the user's copy without
#     root: that one quits cleanly, and a later launch by the user only
#     shows root's.
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
# The main window: a visible "StockFW" window wider than the 24-pixel
# tray icon, which carries the same name once it docks.
main_windows () {
	local w WIDTH
	for w in $(xdotool search --onlyvisible --name '^StockFW$' 2>/dev/null); do
		eval "$(xdotool getwindowgeometry --shell "$w" 2>/dev/null | grep '^WIDTH=')"
		[ "${WIDTH:-0}" -gt 100 ] && echo "$w"
	done
}
visible_windows () { main_windows | wc -l; }
any_window () { main_windows | head -1; }

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

# ---------------------------------------------------------------- 4. --background, with a tray
if command -v stalonetray >/dev/null 2>&1; then
	stalonetray --geometry 4x1+0+0 > "$SCRATCH/tray.log" 2>&1 &
	TRAY_PID=$!
	sleep 1

	"$BIN" --background > "$SCRATCH/bg.log" 2>&1 &
	A=$!
	check "--background claims the instance" wait_for 30 listening
	# Past the embed timeout (5 s): still hidden, because the icon
	# really docked in the notification area.
	sleep 7
	check "--background with a notification area: the window stays hidden" is_hidden
	check "...and the copy runs behind the icon" alive "$A"

	timeout 15 "$BIN" --minimized > "$SCRATCH/bg2.log" 2>&1
	rc=$?
	check "a second background launch (--minimized) exits at once (rc=$rc)" [ "$rc" -eq 0 ]
	sleep 1
	check "...and leaves the running copy hidden" is_hidden

	timeout 15 "$BIN" > "$SCRATCH/bg3.log" 2>&1
	check "a normal second launch brings the hidden window up" wait_for 10 is_visible

	timeout 30 "$BIN" --quit > /dev/null 2>&1
	check "--quit ends the background copy" wait_for 5 dead "$A"
	wait "$A" 2>/dev/null

	kill "$TRAY_PID" 2>/dev/null
	wait "$TRAY_PID" 2>/dev/null
	TRAY_PID=""
	sleep 1
else
	echo "SKIP: stalonetray not installed -- no notification area to hide behind"
fi

# ---------------------------------------------------------------- 5. --background, no tray
"$BIN" --background > "$SCRATCH/notray.log" 2>&1 &
A=$!
check "--background with no notification area: the copy starts" wait_for 30 listening
check "...and shows its window rather than hide with no way back" wait_for 15 is_visible
grep -q "no notification area took the icon" "$SCRATCH/notray.log" &&
	ok "...and says why on stderr" || fail "...and says why on stderr"
timeout 30 "$BIN" --quit > /dev/null 2>&1
wait "$A" 2>/dev/null

# ---------------------------------------------------------------- 6. signals
# SIGTERM (systemd ending the session, kill), SIGINT (Ctrl+C) and
# SIGHUP (its terminal closed) quit the way the tray's Quit does: exit
# 0, settings and Copilot baseline written, firewall left alone.  They
# used to end the process where it stood (SIGINT was even ignored, as
# for any background job of a script).
CONF="$XDG_CONFIG_HOME/stockfw/stockfw.conf"
for sig in TERM INT HUP; do
	rm -f "$STOCKFW_BEHAVIOR_FILE"
	before="$(stat -c %i "$CONF")"
	"$BIN" > "$SCRATCH/sig-$sig.log" 2>&1 &
	A=$!
	# The window is up once activate is done, long after the
	# handlers were installed.
	check "SIG$sig: the copy starts" wait_for 30 is_visible
	kill -s "$sig" "$A"
	check "SIG$sig: the copy goes" wait_for 10 dead "$A"
	if dead "$A"; then
		wait "$A"
		rc=$?
	else
		kill -9 "$A" 2>/dev/null
		wait "$A" 2>/dev/null
		rc=137
	fi
	check "SIG$sig: it quit cleanly, not killed (exit $rc)" [ "$rc" -eq 0 ]
	check "SIG$sig: it wrote its settings on the way out" \
		[ "$(stat -c %i "$CONF")" != "$before" ]
	check "SIG$sig: ...and what the Copilot learned" [ -s "$STOCKFW_BEHAVIOR_FILE" ]
	check "SIG$sig: the name is free again" \
		wait_for 5 bash -c "! grep -q '@$STOCKFW_INSTANCE_NAME\$' /proc/net/unix"
done

ms () { echo $(( $(date +%s%N) / 1000000 )); }
# reap <pid>: collect a copy that should be gone; one that is not (the
# check above has already failed) is killed, so a failure never hangs
# the test.  Its exit status, 137 when it had to be killed.
reap () {
	if dead "$1"; then
		wait "$1" 2>/dev/null
		return $?
	fi
	kill -9 "$1" 2>/dev/null
	wait "$1" 2>/dev/null
	return 137
}

# ---------------------------------------------------------------- 7. nohup
# `nohup StockFW &' asks for SIGHUP to be ignored; StockFW must keep
# that rather than quit when the terminal closes.
nohup "$BIN" > "$SCRATCH/nohup.log" 2>&1 &
A=$!
check "nohup: the copy starts" wait_for 30 is_visible
kill -s HUP "$A"
sleep 2
check "nohup: SIGHUP, which nohup asked to ignore, leaves it running" alive "$A"
timeout 30 "$BIN" --quit > /dev/null 2>&1
check "nohup: --quit still ends it" wait_for 10 dead "$A"
reap "$A"

if [ "$(id -u)" -eq 0 ] && command -v setpriv >/dev/null 2>&1 &&
   command -v python3 >/dev/null 2>&1; then
	# A directory another account can read: the silent client, the
	# user copy's files, and a readable copy of the X cookie.
	PUB="$(mktemp -d)"
	chmod 755 "$PUB"
	trap 'cleanup; rm -rf "$PUB"' EXIT
	cat > "$PUB/silent.py" <<'EOF'
# Open N connections to the instance socket and never say a word.
import socket, sys, time
name, n, secs = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
held = []
for _ in range(n):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect("\0" + name)
        held.append(s)
    except OSError:
        s.close()
print(len(held), flush=True)
time.sleep(secs)
EOF
	chmod 644 "$PUB/silent.py"
	XA=""
	if [ -n "${XAUTHORITY:-}" ] && [ -r "$XAUTHORITY" ]; then
		cp "$XAUTHORITY" "$PUB/xauth"
		chmod 644 "$PUB/xauth"
		XA="$PUB/xauth"
	fi
	U="$PUB/user"
	mkdir -p "$U/home" "$U/config/stockfw" "$U/cache" "$U/data" "$U/rules"
	cp "$XDG_CONFIG_HOME/stockfw/stockfw.conf" "$U/config/stockfw/"
	chown -R 65534:65534 "$U"
	as_nobody () {
		setpriv --reuid=65534 --regid=65534 --clear-groups \
			env HOME="$U/home" XDG_CONFIG_HOME="$U/config" \
			XDG_CACHE_HOME="$U/cache" XDG_DATA_HOME="$U/data" \
			STOCKFW_RULES_DIR="$U/rules" \
			STOCKFW_AUDIT_FILE="$U/audit.log" \
			STOCKFW_APPLIED_FILE="$U/applied.csv" \
			STOCKFW_AUTOBLOCK_FILE="$U/autoblocks" \
			STOCKFW_BEHAVIOR_FILE="$U/behavior.csv" \
			STOCKFW_TRUST_FILE="$U/trust.csv" \
			${XA:+XAUTHORITY="$XA"} "$@"
	}

	# ------------------------------------------------------------ 8. silent connections
	# Connections that connect and never speak -- from another account,
	# and from root -- must not freeze the copy: a show and a --quit
	# right behind them still get through at once.  (The credentials
	# used to be checked only after a blocking one-second read, so a
	# handful of mute connections locked the main loop and --quit out.)
	"$BIN" > "$SCRATCH/dos.log" 2>&1 &
	A=$!
	check "silent: the copy starts" wait_for 30 is_visible
	as_nobody python3 -I "$PUB/silent.py" "$STOCKFW_INSTANCE_NAME" 24 20 \
		> "$PUB/silent-nobody.log" 2>&1 &
	P1=$!
	python3 -I "$PUB/silent.py" "$STOCKFW_INSTANCE_NAME" 24 20 \
		> "$PUB/silent-root.log" 2>&1 &
	P2=$!
	sleep 2
	check "silent: another account's mute connections were made" \
		[ "$(head -1 "$PUB/silent-nobody.log")" -ge 1 ]
	WIN="$(any_window)"
	xdotool windowunmap --sync "$WIN" 2>/dev/null
	t0=$(ms)
	timeout 15 "$BIN" > "$SCRATCH/dos-show.log" 2>&1
	rc=$?
	took=$(( $(ms) - t0 ))
	check "silent: a show behind 48 mute connections answers at once (rc=$rc, ${took} ms)" \
		[ "$rc" -eq 0 -a "$took" -le 2500 ]
	check "silent: ...and the window comes up" wait_for 5 is_visible
	t0=$(ms)
	timeout 30 "$BIN" --quit > "$SCRATCH/dos-quit.log" 2>&1
	rc=$?
	took=$(( $(ms) - t0 ))
	check "silent: --quit gets through at once (rc=$rc, ${took} ms)" \
		[ "$rc" -eq 0 -a "$took" -le 5000 ]
	check "silent: ...and the copy is gone" wait_for 5 dead "$A"
	reap "$A"
	kill "$P1" "$P2" 2>/dev/null
	wait "$P1" "$P2" 2>/dev/null

	# ------------------------------------------------------------ 9. root takes over
	# The user's sign-in copy runs without root; `sudo StockFW' must
	# not just raise that powerless window and exit (as it did), but
	# replace it: the user copy quits cleanly and root's runs.
	as_nobody "$BIN" --background > "$PUB/user.log" 2>&1 &
	UP=$!
	check "takeover: the user's copy (uid 65534) starts" wait_for 30 listening
	sleep 2
	SUDO_UID=65534 SUDO_GID=65534 "$BIN" > "$SCRATCH/root.log" 2>&1 &
	R=$!
	check "takeover: sudo StockFW makes the user's copy quit" wait_for 25 dead "$UP"
	reap "$UP"
	rc=$?
	check "takeover: ...cleanly (exit $rc)" [ "$rc" -eq 0 ]
	check "takeover: root's copy is the one running" alive "$R"
	check "takeover: ...and holds the name" wait_for 10 listening
	check "takeover: ...with its window up" wait_for 15 is_visible
	grep -q "quit to make way" "$SCRATCH/root.log" &&
		ok "takeover: it says what it did" ||
		fail "takeover: it says what it did ($(cat "$SCRATCH/root.log"))"
	WIN="$(any_window)"
	xdotool windowunmap --sync "$WIN" 2>/dev/null
	as_nobody timeout 15 "$BIN" > "$PUB/user2.log" 2>&1
	rc=$?
	check "takeover: the user launching again only shows root's copy (rc=$rc)" \
		[ "$rc" -eq 0 ]
	check "takeover: ...whose window comes up" wait_for 10 is_visible
	check "takeover: ...and root's copy is still the one running" alive "$R"
	timeout 30 "$BIN" --quit > /dev/null 2>&1
	check "takeover: --quit ends root's copy" wait_for 10 dead "$R"
	reap "$R"
else
	echo "SKIP: silent connections and takeover need root, setpriv and python3"
fi

echo
if [ "$failures" -eq 0 ]; then
	echo "PASSED: 0 failure(s)"
else
	echo "FAILED: $failures failure(s)"
fi
exit $(( failures > 0 ))
