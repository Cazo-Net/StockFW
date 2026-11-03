#!/bin/bash
# The dashboard's HTTP server (src/cli/fs-dash-http.c), end to end:
# the checks made at accept time (peer address and peer uid), the slots
# and deadlines that keep slow senders from locking the user out, and
# the request checks (Host, Upgrade, Transfer-Encoding, Content-Length).
# docs/ARCHITECTURE-AND-SECURITY.md 15.3.1.
#
# The dashboard serves one account: its own, or SUDO_UID under sudo,
# never uid 0.  As root this script runs it the way sudo does, with
# SUDO_UID=65533, makes the user's requests as uid 65533, and tries
# root and nobody (65534) as the other accounts.  Without root only
# the checks that need no second account run.
#
#   cd port && bash tests/test-dashboard.sh
#
# Linux only.  STOCKFW_BUILD names the build directory.

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
cd "$PORT" || exit 1

if [ "$(uname -s)" != "Linux" ]; then
  echo "SKIP: the dashboard is part of the Linux command-line tool"
  exit 0
fi

BUILD="${STOCKFW_BUILD:-$PORT/build-linux}"
if ! { cmake -S . -B "$BUILD" -G Ninja > /dev/null &&
       cmake --build "$BUILD" --target stockfw > /dev/null; }; then
  echo "FAIL: could not build stockfw in $BUILD"
  echo "FAILED: 1 failure(s)"
  exit 1
fi
S="$BUILD/stockfw"

# A copy the other accounts can run, in a directory they can read.
W="$(mktemp -d /tmp/stockfw-dashtest-XXXXXX)"; chmod 755 "$W"
cp "$S" "$W/stockfw"; chmod 755 "$W/stockfw"
DASH_PID=""
cleanup () {
  [ -n "$DASH_PID" ] && kill "$DASH_PID" 2>/dev/null
  rm -rf "$W"
}
trap cleanup EXIT

fails=0
check () {   # check <description> <command...>
  local what="$1"; shift
  if "$@"; then
    echo "ok:   $what"
  else
    echo "FAIL: $what"
    fails=$((fails+1))
  fi
}

ROOT=0
[ "$(id -u)" = 0 ] && command -v setpriv > /dev/null && ROOT=1
if [ "$ROOT" = 1 ]; then
  USER_UID=65533
  as_user () { setpriv --reuid=$USER_UID --regid=$USER_UID --clear-groups "$@"; }
  as_nobody () { setpriv --reuid=65534 --regid=65534 --clear-groups "$@"; }
  START=(env SUDO_UID=$USER_UID)
else
  USER_UID="$(id -u)"
  as_user () { "$@"; }
  START=(env)
fi

export STOCKFW_RULES_DIR="$W/rules"
export XDG_CONFIG_HOME="$W/cfg"
export STOCKFW_LOG_FILE="$W/kern.log"
: > "$W/kern.log"

DPORT=$(python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
"${START[@]}" "$W/stockfw" dashboard --no-open --port "$DPORT" > "$W/dash.txt" 2>&1 &
DASH_PID=$!
for _ in $(seq 1 50); do
  grep -q '#token=' "$W/dash.txt" 2>/dev/null && break
  sleep 0.1
done
URL=$(grep -o 'http://[^ ]*' "$W/dash.txt")
TOKEN=${URL##*#token=}
B="http://127.0.0.1:$DPORT"
check "the dashboard started (port $DPORT)" bash -c "[[ '$TOKEN' =~ ^[0-9a-f]{32}$ ]]"

# code <curl args...>: the status code of a request made as the user.
code () { as_user curl -sS -o /dev/null -w '%{http_code}' "$@" 2>/dev/null; }
upy () { as_user python3 -I -c "$1"; }

check "the user's own request is answered (200, as uid $USER_UID)" \
  [ "$(code -H "X-StockFW-Token: $TOKEN" "$B/api/summary")" = 200 ]

# ------------------------------------------------------- request checks
check "Host: localhost:PORT is refused (403): only 127.0.0.1:PORT is ours (G4, T5)" \
  [ "$(code -H "Host: localhost:$DPORT" -H "X-StockFW-Token: $TOKEN" "$B/api/summary")" = 403 ]
check "  ...and so is the right address on another port (403)" \
  [ "$(code -H "Host: 127.0.0.1:1" -H "X-StockFW-Token: $TOKEN" "$B/api/summary")" = 403 ]
check "Upgrade: websocket is refused (400), even with the token (T7)" \
  [ "$(code -H "Upgrade: websocket" -H "Connection: Upgrade" -H "X-StockFW-Token: $TOKEN" "$B/api/summary")" = 400 ]
check "  ...and from a foreign Origin too (400)" \
  [ "$(code -H "Upgrade: websocket" -H "Origin: http://attacker.example" "$B/")" = 400 ]
check "Transfer-Encoding is refused (400)" \
  [ "$(code -H "Transfer-Encoding: chunked" -H "X-StockFW-Token: $TOKEN" --data-binary x "$B/api/summary")" = 400 ]
check "a Content-Length over 64 KB is refused (413)" \
  [ "$(code -H "Content-Length: 70000" -H "X-StockFW-Token: $TOKEN" "$B/api/summary")" = 413 ]
check "two Host headers are refused (403)" upy "
import socket
s = socket.create_connection(('127.0.0.1', $DPORT))
s.sendall(b'GET / HTTP/1.1\r\nHost: 127.0.0.1:$DPORT\r\nHost: 127.0.0.1:$DPORT\r\n\r\n')
assert s.recv(64).startswith(b'HTTP/1.1 403'), 'not 403'"

# ------------------------------------------------------------ deadlines
# The old server only had a 10 s inactivity timeout: one byte every few
# seconds held a connection for ever.
check "a request head trickled a byte at a time is cut off after 5 s" upy "
import socket, time
s = socket.create_connection(('127.0.0.1', $DPORT))
s.sendall(b'GET / HTTP/1.1\r\n')
s.settimeout(0.4)
t0 = time.monotonic(); closed = None
while time.monotonic() - t0 < 9:
    try:
        s.send(b'X')
    except OSError:
        closed = time.monotonic() - t0; break
    try:
        if s.recv(64) == b'':
            closed = time.monotonic() - t0; break
    except socket.timeout:
        pass
    except OSError:
        closed = time.monotonic() - t0; break
assert closed is not None and 4.5 <= closed <= 7, closed"
check "a body promised by Content-Length and not sent is cut off after 5 s, unanswered" upy "
import socket, time
s = socket.create_connection(('127.0.0.1', $DPORT))
s.sendall(b'GET /api/summary HTTP/1.1\r\nHost: 127.0.0.1:$DPORT\r\nX-StockFW-Token: $TOKEN\r\nContent-Length: 10\r\n\r\nabc')
s.settimeout(9)
t0 = time.monotonic()
try:
    got = s.recv(64)
except OSError:
    got = b''
t = time.monotonic() - t0
assert got == b'' and 4.5 <= t <= 7, (got, t)"
check "  ...and the same request with its body is answered (200)" upy "
import socket
s = socket.create_connection(('127.0.0.1', $DPORT))
s.sendall(b'GET /api/summary HTTP/1.1\r\nHost: 127.0.0.1:$DPORT\r\nX-StockFW-Token: $TOKEN\r\nContent-Length: 10\r\n\r\n0123456789')
assert s.recv(64).startswith(b'HTTP/1.1 200'), 'not 200'"

# ---------------------------------------------------------------- slots
# T2: 32 connections held open by trickling bytes, from the user's own
# account (the worst case: other accounts are closed at accept).  The
# 1.0.7 server, capped at 32 connections, then reset the 33rd: curl
# printed 000.  Now a new connection takes the slot of the oldest
# sender, so the user's request is answered within 1 s.
check "with 32 slow senders holding connections, a valid request answers within 1 s (T2)" upy "
import socket, threading, time
stop = False
socks = []
for i in range(32):
    s = socket.create_connection(('127.0.0.1', $DPORT))
    s.sendall(b'GET / HTTP/1.1\r\n')
    socks.append(s)
def trickle():
    while not stop:
        for s in socks:
            try: s.send(b'X')
            except OSError: pass
        time.sleep(0.3)
t = threading.Thread(target=trickle, daemon=True); t.start()
time.sleep(1.0)
t0 = time.monotonic()
c = socket.create_connection(('127.0.0.1', $DPORT)); c.settimeout(3)
c.sendall(b'GET /api/summary HTTP/1.1\r\nHost: 127.0.0.1:$DPORT\r\nX-StockFW-Token: $TOKEN\r\n\r\n')
data = b''
try:
    while True:
        d = c.recv(65536)
        if not d: break
        data += d
except OSError:
    pass
took = time.monotonic() - t0
stop = True
for s in socks: s.close()
assert data.startswith(b'HTTP/1.1 200') and took < 1.0, (data[:40], took)"

# ---------------------------------------------------- accept-time checks
check "a peer at 127.0.0.2 (not 127.0.0.1) is closed at accept, unanswered" upy "
import socket
s = socket.socket(); s.bind(('127.0.0.2', 0)); s.settimeout(5)
s.connect(('127.0.0.1', $DPORT))
try:
    s.sendall(b'GET / HTTP/1.1\r\nHost: 127.0.0.1:$DPORT\r\n\r\n')
    got = s.recv(64)
except OSError:
    got = b''
assert got == b'', got"

if [ "$ROOT" = 1 ]; then
  # The token is valid in every one of these: only the peer's uid
  # differs.  curl prints 000 when the connection closes unanswered.
  check "a connection from uid 0 (root) is closed at accept, unanswered (000)" \
    [ "$(curl -sS -o /dev/null -w '%{http_code}' -H "X-StockFW-Token: $TOKEN" "$B/api/summary" 2>/dev/null)" = 000 ]
  check "a connection from uid nobody is closed at accept, unanswered (000)" \
    [ "$(as_nobody curl -sS -o /dev/null -w '%{http_code}' -H "X-StockFW-Token: $TOKEN" "$B/api/summary" 2>/dev/null)" = 000 ]
  check "  ...not one byte comes back, whatever is sent" python3 -I -c "
import socket
s = socket.create_connection(('127.0.0.1', $DPORT)); s.settimeout(5)
try:
    s.sendall(b'GET / HTTP/1.1\r\nHost: 127.0.0.1:$DPORT\r\n\r\n')
    got = s.recv(64)
except OSError:
    got = b''
assert got == b'', got"
  check "  ...while the user's own request still gets 200" \
    [ "$(code -H "X-StockFW-Token: $TOKEN" "$B/api/summary")" = 200 ]
  check "the terminal names the account served" \
    grep -q "uid $USER_UID only (SUDO_UID)" "$W/dash.txt"
fi

kill "$DASH_PID" 2>/dev/null; wait "$DASH_PID" 2>/dev/null; DASH_PID=""

if [ "$ROOT" = 1 ]; then
  check "as root without SUDO_UID it refuses to start (exit 1), naming why" bash -c "
    timeout 10 env -u SUDO_UID '$W/stockfw' dashboard --no-open > '$W/out' 2>&1; rc=\$?
    [ \$rc = 1 ] && grep -q 'does not serve uid 0' '$W/out' && ! grep -q 'token=' '$W/out'"
  check "  ...and with SUDO_UID=0 too" bash -c "
    timeout 10 env SUDO_UID=0 '$W/stockfw' dashboard --no-open > '$W/out' 2>&1; rc=\$?
    [ \$rc = 1 ] && grep -q 'does not serve uid 0' '$W/out'"
else
  echo "skip: peer uid checks need root (a second account)"
fi

echo ""
if [ "$fails" -eq 0 ]; then
  echo "PASSED: 0 failure(s)"
else
  echo "FAILED: $fails failure(s)"
fi
exit "$fails"
