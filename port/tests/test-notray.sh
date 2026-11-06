#!/bin/bash
# StockFW on a desktop with no tray, and words the window app does not
# take -- driven through the real binary (src/main.c, src/ui/fs-tray.c,
# src/ui/fs-app.c, src/ui/fs-prefsdialog.c).
#
# What it proves:
#   - `StockFW dashboard' (a command meant for the command-line tool)
#     exits 2 at once with a message naming `stockfw dashboard', starts
#     nothing (no instance name claimed) and never reaches GApplication,
#     whose answer was only "This application can not open files";
#   - on a GDK backend that is not X11 -- Broadway here, the same case
#     as Wayland, GNOME, KDE Plasma and WSL's WSLg -- StockFW starts
#     with no Gtk-CRITICAL (G_DEBUG=fatal-criticals turns one into a
#     crash), makes no tray icon, and a background start shows its
#     window instead of hiding it behind an icon that cannot exist;
#   - --quit still ends that copy cleanly (exit 0);
#   - Preferences greys both tray switches there, with the reason
#     (ui-prefs-smoke run on Broadway: its tray check).
#
# Needs broadwayd (Debian/Ubuntu: libgtk-3-bin) for the desktop part;
# it SKIPs without it unless STOCKFW_NOTRAY_REQUIRE=1.  As root it runs
# in a private network namespace, so the backend never touches the
# host's firewall; every file goes to a scratch directory.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
BUILD="${STOCKFW_BUILD:-$PORT/build-linux}"
BIN="$BUILD/StockFW"
PREFS_SMOKE="$BUILD/fs-prefs-fake-smoke"

if [ ! -x "$BIN" ]; then
	echo "SKIP: $BIN not built (ninja -C build-linux StockFW)"
	exit 0
fi

if [ "$(id -u)" -eq 0 ] && [ "${STOCKFW_NOTRAY_IN_NETNS:-}" != "1" ] &&
   command -v unshare >/dev/null 2>&1; then
	exec env STOCKFW_NOTRAY_IN_NETNS=1 unshare -n bash "$0" "$@"
fi

failures=0
ok ()   { echo "ok:   $*"; }
fail () { echo "FAIL: $*"; failures=$((failures + 1)); }
check () { local what="$1"; shift; if "$@"; then ok "$what"; else fail "$what"; fi; }

SCRATCH="$(mktemp -d)"
BW_PID=""
cleanup () {
	pkill -f "$SCRATCH" 2>/dev/null
	for p in $(jobs -p); do kill "$p" 2>/dev/null; done
	[ -n "$BW_PID" ] && kill "$BW_PID" 2>/dev/null
	rm -rf "$SCRATCH"
}
trap cleanup EXIT

export HOME="$SCRATCH/home"
export XDG_CONFIG_HOME="$SCRATCH/config"
export XDG_CACHE_HOME="$SCRATCH/cache"
export XDG_DATA_HOME="$SCRATCH/data"
export XDG_RUNTIME_DIR="$SCRATCH/run"
export STOCKFW_RULES_DIR="$SCRATCH/rules"
export STOCKFW_AUDIT_FILE="$SCRATCH/audit.log"
export STOCKFW_APPLIED_FILE="$SCRATCH/applied.csv"
export STOCKFW_AUTOBLOCK_FILE="$SCRATCH/autoblocks"
export STOCKFW_BEHAVIOR_FILE="$SCRATCH/behavior.csv"
export STOCKFW_TRUST_FILE="$SCRATCH/trust.csv"
export STOCKFW_INSTANCE_NAME="stockfw-notray-$$"
export NO_AT_BRIDGE=1
mkdir -p "$HOME" "$XDG_CONFIG_HOME/stockfw" "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"
# The tray asked for, as a user who turned it on elsewhere would have
# it; the window must never start the firewall from a test.
cat > "$XDG_CONFIG_HOME/stockfw/stockfw.conf" <<EOF
[client]
start_firewall_on_gui=false
enable_tray_icon=true
minimize_to_tray=true
EOF

listening () { grep -q "@$STOCKFW_INSTANCE_NAME\$" /proc/net/unix; }
alive ()     { kill -0 "$1" 2>/dev/null; }
dead ()      { ! kill -0 "$1" 2>/dev/null; }
wait_for () {   # wait_for <seconds> <command...>
	local limit=$(( $1 * 10 )); shift
	for ((i = 0; i < limit; i++)); do
		"$@" && return 0
		sleep 0.1
	done
	return 1
}

# ---------------------------------------------------------------- 1. a word, not an option
# No display at all: the check comes before anything opens one.
out="$(env -u DISPLAY -u WAYLAND_DISPLAY "$BIN" dashboard 2>&1)"; rc=$?
check "\`StockFW dashboard' exits with status 2 (rc=$rc)" [ "$rc" -eq 2 ]
check "...saying \"dashboard\" is not an option of the window app" \
	grep -q '"dashboard" is not an option of the StockFW window app' <<<"$out"
check "...and naming the installed command-line tool: sudo /usr/local/bin/stockfw dashboard" \
	grep -q 'sudo /usr/local/bin/stockfw dashboard' <<<"$out"
check "...and the unpacked folder's copy: sudo ./cli/stockfw dashboard" \
	grep -q 'sudo ./cli/stockfw dashboard' <<<"$out"
check "...not GApplication's \"can not open files\"" \
	bash -c '! grep -q "can not open files" <<<"$1"' _ "$out"
# The instance name is an abstract socket, gone when its owner exits, so
# looking for it afterwards proves nothing.  Hold it instead: a binary
# that went for it before refusing the word would find it taken and
# connect to the holder (1.0.7 did, and exited 0).
if command -v python3 >/dev/null 2>&1; then
	python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind("\0" + sys.argv[1]); s.listen(4); s.settimeout(5)
print("listening", flush=True)
try:
    s.accept(); print("CONNECTED", flush=True)
except socket.timeout:
    pass
' "$STOCKFW_INSTANCE_NAME" > "$SCRATCH/holder.log" 2>&1 &
	H=$!
	wait_for 5 grep -q listening "$SCRATCH/holder.log"
	env -u DISPLAY -u WAYLAND_DISPLAY "$BIN" dashboard >/dev/null 2>&1; hrc=$?
	sleep 0.3; kill "$H" 2>/dev/null; wait "$H" 2>/dev/null
	check "...and it never went for the instance name (rc=$hrc; nothing connected to a copy holding it)" \
		bash -c '[ "$1" -eq 2 ] && ! grep -q CONNECTED "$2"' _ "$hrc" "$SCRATCH/holder.log"
else
	echo "SKIP: python3 not installed: the instance-name check"
fi
out="$("$BIN" --background stray 2>&1)"; rc=$?
check "a word after an option is refused the same way (rc=$rc)" \
	bash -c '[ "$1" -eq 2 ] && grep -q "\"stray\" is not an option" <<<"$2"' _ "$rc" "$out"
out="$("$BIN" --version 2>&1)"; rc=$?
check "--version alone still works (rc=$rc: $out)" \
	bash -c '[ "$1" -eq 0 ] && grep -q "^StockFW " <<<"$2"' _ "$rc" "$out"

# ---------------------------------------------------------------- 2. no tray: Broadway
if ! command -v broadwayd >/dev/null 2>&1; then
	if [ "${STOCKFW_NOTRAY_REQUIRE:-}" = "1" ]; then
		fail "broadwayd is not installed (libgtk-3-bin) and STOCKFW_NOTRAY_REQUIRE=1"
	else
		echo "SKIP: broadwayd not installed (libgtk-3-bin): the no-tray desktop checks"
	fi
else
	# A display of its own.  broadwayd binds its HTTP port (8080 + the
	# display; on 127.0.0.1 here, so the test's windows are not served to
	# the network) and then its socket, an abstract one named after this
	# run's runtime folder; with the port taken it exits instead.  So a
	# display counts as up only once that socket is listening and
	# broadwayd still runs; otherwise the next number is tried.
	BW=""
	bw_up ()      { grep -q "@$XDG_RUNTIME_DIR/broadway$(( $1 + 1 )).socket\$" /proc/net/unix; }
	bw_settled () { bw_up "$1" || dead "$BW_PID"; }
	for n in $(seq 40 79); do
		broadwayd --address 127.0.0.1 ":$n" > "$SCRATCH/broadwayd.log" 2>&1 &
		BW_PID=$!
		if wait_for 5 bw_settled "$n" && alive "$BW_PID" && bw_up "$n"; then
			BW="$n"
			break
		fi
		kill "$BW_PID" 2>/dev/null; wait "$BW_PID" 2>/dev/null; BW_PID=""
	done
	check "a Broadway display is up (:${BW:-none})" [ -n "$BW" ]
	[ -n "$BW" ] || tail -3 "$SCRATCH/broadwayd.log" | sed 's/^/       /'

	if [ -n "$BW" ]; then
		export GDK_BACKEND=broadway BROADWAY_DISPLAY=":$BW"
		unset DISPLAY WAYLAND_DISPLAY

		# With a display the old binary got as far as GApplication.
		out="$("$BIN" dashboard 2>&1)"; rc=$?
		check "with a display too, \`StockFW dashboard' exits 2 with the message (rc=$rc)" \
			bash -c '[ "$1" -eq 2 ] && grep -q "sudo ./cli/stockfw dashboard" <<<"$2"' _ "$rc" "$out"
		check "...not GApplication's \"can not open files\"" \
			bash -c '! grep -q "can not open files" <<<"$1"' _ "$out"

		# The slow refresh every second (instead of every minute): it
		# must run with no icon, being how the window learns of a
		# firewall stopped from a terminal.
		G_DEBUG=fatal-criticals G_MESSAGES_DEBUG=all STOCKFW_TRAY_REFRESH_S=1 \
			"$BIN" --background > "$SCRATCH/bg.log" 2>&1 &
		A=$!
		check "--background on a desktop with no tray: the copy starts" wait_for 30 listening
		check "...it made no tray icon (none can exist there)" \
			wait_for 10 grep -q "no tray icon: this desktop" "$SCRATCH/bg.log"
		check "...and showed its window rather than hide with no way back" \
			wait_for 10 grep -q "background start: no tray icon, the window is shown" "$SCRATCH/bg.log"
		check "...and still re-reads the firewall's state on the slow timer, icon or not" \
			wait_for 10 grep -q "slow refresh: the firewall's state read again (no tray icon)" "$SCRATCH/bg.log"
		sleep 2
		check "...and it is still running (a Gtk-CRITICAL is fatal here)" alive "$A"

		# With the copy up, a stray word must still be refused, not
		# handed to it (1.0.7 sent it "show" and exited 0).
		out="$("$BIN" dashboard 2>&1)"; rc=$?
		check "with StockFW running, \`StockFW dashboard' still exits 2 with the message (rc=$rc)" \
			bash -c '[ "$1" -eq 2 ] && grep -q "\"dashboard\" is not an option" <<<"$2"' _ "$rc" "$out"
		check "no Gtk-CRITICAL and no warning at start" \
			bash -c '! grep -E "CRITICAL|WARNING" "$1"' _ "$SCRATCH/bg.log"
		"$BIN" --quit > "$SCRATCH/quit.log" 2>&1; rc=$?
		check "--quit succeeds (rc=$rc)" [ "$rc" -eq 0 ]
		check "--quit ends the copy" wait_for 10 dead "$A"
		wait "$A" 2>/dev/null; rc=$?
		check "it quit cleanly, not killed (exit $rc)" [ "$rc" -eq 0 ]
		if grep -E "CRITICAL|WARNING" "$SCRATCH/bg.log" >/dev/null; then
			grep -E "CRITICAL|WARNING" "$SCRATCH/bg.log" | head -5 | sed 's/^/       /'
		fi

		if [ -x "$PREFS_SMOKE" ]; then
			"$PREFS_SMOKE" > "$SCRATCH/prefs.log" 2>&1; rc=$?
			check "Preferences on Broadway: the smoke passes (rc=$rc)" [ "$rc" -eq 0 ]
			check "...both tray switches greyed with the reason" \
				grep -q "^ok:.*the tray switches follow the desktop (no tray: both greyed, the reason shown)" "$SCRATCH/prefs.log"
			[ "$rc" -eq 0 ] || grep '^FAIL' "$SCRATCH/prefs.log" | head -10 | sed 's/^/       /'
		else
			echo "SKIP: $PREFS_SMOKE not built (ninja -C build-linux fs-prefs-fake-smoke)"
		fi
	fi
fi

echo
if [ "$failures" -eq 0 ]; then
	echo "test-notray: PASSED"
	exit 0
fi
echo "test-notray: $failures FAILURE(S)"
exit 1
