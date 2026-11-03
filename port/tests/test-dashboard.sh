#!/bin/bash
# The dashboard's server and credentials, end to end (PR 2; docs
# ARCHITECTURE-AND-SECURITY.md 15.3):
#   - the HTTP server (src/cli/fs-dash-http.c, 15.3.1): the checks made
#     at accept time (peer address and peer uid), the slots and
#     deadlines that keep slow senders from locking the user out, and
#     the request checks (Host, Upgrade, Transfer-Encoding,
#     Content-Length);
#   - the credentials (src/cli/fs-dash-auth.c, 15.3.2): launch codes,
#     sessions, the link printed only to a terminal, `dashboard link',
#     the Origin and Sec-Fetch checks, --origin-port, WSL and
#     --allow-windows, the new headers; the session rules on a test
#     clock (the stockfw-dash-test build and fs-dash-auth-test);
#   - the page (15.3.3): it sends the session header.
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
       cmake --build "$BUILD" --target stockfw stockfw-dash-test \
             fs-dash-auth-test > /dev/null; }; then
  echo "FAIL: could not build stockfw, stockfw-dash-test and fs-dash-auth-test in $BUILD"
  echo "FAILED: 1 failure(s)"
  exit 1
fi

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

# ----------------------------------------------------- the session rules
# fs-dash-auth.c on a clock the test moves (codes, 12 h reads, the
# 15 minute write rule, reuse, the caps).
"$BUILD/fs-dash-auth-test" > "$BUILD/dash-auth-test.log" 2>&1
auth_rc=$?
sed 's/^/  unit: /' "$BUILD/dash-auth-test.log"
check "fs-dash-auth-test: the session rules on a test clock" [ "$auth_rc" = 0 ]

# A copy the other accounts can run, in a directory they can read.
W="$(mktemp -d /tmp/stockfw-dashtest-XXXXXX)"; chmod 755 "$W"
cp "$BUILD/stockfw" "$W/stockfw"; chmod 755 "$W/stockfw"
cp "$BUILD/stockfw-dash-test" "$W/stockfw-test"; chmod 755 "$W/stockfw-test"
DASH_PID=""
stop_dash () {
  [ -n "$DASH_PID" ] && { kill "$DASH_PID" 2>/dev/null; wait "$DASH_PID" 2>/dev/null; }
  DASH_PID=""
}
cleanup () {
  stop_dash
  end_netns
  rm -rf "$W"
}
trap cleanup EXIT

ROOT=0
[ "$(id -u)" = 0 ] && command -v setpriv > /dev/null && ROOT=1
if [ "$ROOT" = 1 ]; then
  USER_UID=65533
  as_user () { setpriv --reuid=$USER_UID --regid=$USER_UID --clear-groups "$@"; }
  as_nobody () { setpriv --reuid=65534 --regid=65534 --clear-groups "$@"; }
  START=(env SUDO_UID=$USER_UID)
  AS="setpriv --reuid=$USER_UID --regid=$USER_UID --clear-groups"
else
  USER_UID="$(id -u)"
  as_user () { "$@"; }
  START=(env)
  AS=""
fi

# The user's runtime directory: launch files and the link socket.
RUN="$W/run"
mkdir -m 700 "$RUN"
[ "$ROOT" = 1 ] && chown "$USER_UID:$USER_UID" "$RUN"
export XDG_RUNTIME_DIR="$RUN"
export STOCKFW_RULES_DIR="$W/rules"
export XDG_CONFIG_HOME="$W/cfg"
export STOCKFW_LOG_FILE="$W/kern.log"
: > "$W/kern.log"

check "the release build has no test hooks (no STOCKFW_TEST_ variable in stockfw)" \
  bash -c "! grep -qa 'STOCKFW_TEST_' '$W/stockfw' && grep -qa 'STOCKFW_TEST_CLOCK_FILE' '$W/stockfw-test'"

# mk_netns <tw buckets>: a network namespace of its own (root only),
# held by a sleeping process $NSHOLD, with lo up and at most that many
# TIME_WAIT entries.  end_netns ends it.
SAVED_START=("${START[@]}")
NSHOLD=""
mk_netns () {
  unshare -n sleep 600 2>/dev/null &
  NSHOLD=$!
  sleep 0.2
  nsenter -t "$NSHOLD" -n ip link set lo up 2>/dev/null &&
    nsenter -t "$NSHOLD" -n sysctl -qw "net.ipv4.tcp_max_tw_buckets=$1" 2>/dev/null
}
end_netns () {
  [ -n "$NSHOLD" ] && { kill "$NSHOLD" 2>/dev/null; wait "$NSHOLD" 2>/dev/null; }
  NSHOLD=""
}

free_port () { python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

# start_dash <binary> <port> [args...]: stdout to $W/dash.txt (a pipe,
# not a terminal); LINK_FILE is the launch file it names.
start_dash () {
  local bin="$1" port="$2"; shift 2
  "${START[@]}" "$bin" dashboard --no-open --port "$port" "$@" > "$W/dash.txt" 2>&1 &
  DASH_PID=$!
  for _ in $(seq 1 50); do
    grep -q 'Ctrl-C' "$W/dash.txt" 2>/dev/null && break
    sleep 0.1
  done
  LINK_FILE=$(sed -n 's/^  Link file   //p' "$W/dash.txt")
}
code_in () { grep -oE '#code=[0-9a-f]{32}' "$1" 2>/dev/null | head -1 | cut -d= -f2; }
# new_code: a code from `stockfw dashboard link', run as the user with
# stdout piped (it prints the launch file's path).
new_code () { code_in "$(as_user "$W/stockfw" dashboard link "$@" 2>/dev/null)"; }

# post <port> <body> [curl args...]: a POST to /api/session as the
# user; prints the status, the body goes to $W/body.
post () {
  local port="$1" body="$2"; shift 2
  as_user curl -sS -o - -w '\n%{http_code}' -X POST --data-binary "$body" "$@" \
    "http://127.0.0.1:$port/api/session" > "$W/resp" 2>/dev/null
  tail -n1 "$W/resp"; sed '$d' "$W/resp" > "$W/body"
}
# The headers a browser's fetch from the page itself sends.
page_hdrs () {  # page_hdrs <origin port>
  PAGE=(-H "Origin: http://127.0.0.1:$1" -H 'Sec-Fetch-Site: same-origin'
        -H 'Sec-Fetch-Mode: cors' -H 'Sec-Fetch-Dest: empty'
        -H 'Content-Type: application/json')
}
# session <port> <code> [curl args]: the key, or nothing.
session () {
  local port="$1" code="$2"; shift 2
  page_hdrs "$port"
  [ "$(post "$port" "{\"code\":\"$code\"}" "${PAGE[@]}" "$@")" = 200 ] &&
    python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["session"])' "$W/body"
}
# code <curl args...>: the status code of a request made as the user.
code () { as_user curl -sS -o /dev/null -w '%{http_code}' "$@" 2>/dev/null; }
upy () { as_user python3 -I -c "$1"; }
no_long_hex () { ! grep -qE '[0-9a-f]{32,}' "$1"; }

DPORT=$(free_port)
B="http://127.0.0.1:$DPORT"
start_dash "$W/stockfw" "$DPORT"
FP=$(sed -n 's/^  Fingerprint \([0-9A-F-]*\) .*/\1/p' "$W/dash.txt")
check "the dashboard started (port $DPORT) and names a launch file" \
  bash -c "[ -n '$LINK_FILE' ] && [ -f '$LINK_FILE' ]"

# ------------------------------------------------------ the link (T11)
check "with stdout piped, no hex string of 32 characters or more is printed (T11)" \
  no_long_hex "$W/dash.txt"
check "  ...the launch file holds the code, 0600 in a 0700 directory of the user" \
  bash -c "[ -n \"\$(grep -oE '#code=[0-9a-f]{32}' '$LINK_FILE')\" ] &&
           [ \"\$(stat -c '%a %u' '$LINK_FILE')\" = '600 $USER_UID' ] &&
           [ \"\$(stat -c '%a %u' \"\$(dirname '$LINK_FILE')\")\" = '700 $USER_UID' ]"
check "  ...and the terminal shows a fingerprint (T13)" \
  bash -c "[[ '$FP' =~ ^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$ ]]"
check "on a terminal, the link with the code is printed" python3 -I -c "
import os, pty, select, signal, subprocess, time, re
m, s = pty.openpty()
env = dict(os.environ)
env.update(dict(x.split('=', 1) for x in '${START[*]}'.split()[1:]))
p = subprocess.Popen(['$W/stockfw', 'dashboard', '--no-open'], stdin=s, stdout=s, stderr=s, env=env)
os.close(s)
out = b''; t0 = time.time()
while time.time() - t0 < 5 and b'Ctrl-C' not in out:
    if select.select([m], [], [], 0.2)[0]:
        try: out += os.read(m, 4096)
        except OSError: break
p.send_signal(signal.SIGINT); p.wait(timeout=5)
assert re.search(rb'http://127\.0\.0\.1:\d+/#code=[0-9a-f]{32}\b', out), out"
"${START[@]}" "$W/stockfw" --json dashboard --no-open > "$W/json.txt" 2>&1 &
JPID=$!
for _ in $(seq 1 50); do grep -q link_file "$W/json.txt" && break; sleep 0.1; done
kill "$JPID" 2>/dev/null; wait "$JPID" 2>/dev/null
check "with --json, no 32-hex string either: the launch file's path instead" \
  bash -c "no_long_hex () { ! grep -qE '[0-9a-f]{32,}' \"\$1\"; }; no_long_hex '$W/json.txt' &&
           python3 -I -c 'import json,sys; d=json.loads(open(sys.argv[1]).read().splitlines()[0]); assert d[\"link_file\"].endswith(\"/open.html\") and d[\"fingerprint\"]' '$W/json.txt'"

# ----------------------------------------------------- the launch code
CODE1=$(code_in "$LINK_FILE")
check "the page loads without a session (it holds no data)" \
  [ "$(code "$B/")" = 200 ]
check "the API refuses a request without a session (401)" \
  [ "$(code "$B/api/summary")" = 401 ]
page_hdrs "$DPORT"
check "a code that was never issued gets 401" \
  [ "$(post "$DPORT" '{"code":"0123456789abcdef0123456789abcdef"}' "${PAGE[@]}")" = 401 ]

# The POST checks (D3 step 3), each on a valid code that must survive
# the refusals.
P_SITE=(-H 'Sec-Fetch-Mode: cors' -H 'Sec-Fetch-Dest: empty' -H 'Content-Type: application/json')
J="{\"code\":\"$CODE1\"}"
check "POST without Origin gets 403" \
  [ "$(post "$DPORT" "$J" -H 'Sec-Fetch-Site: same-origin' "${P_SITE[@]}")" = 403 ]
check "POST with a foreign Origin gets 403" \
  [ "$(post "$DPORT" "$J" -H 'Origin: http://attacker.example' -H 'Sec-Fetch-Site: same-origin' "${P_SITE[@]}")" = 403 ]
check "POST with Origin http://127.0.0.1:OTHERPORT gets 403" \
  [ "$(post "$DPORT" "$J" -H "Origin: http://127.0.0.1:$((DPORT+1))" -H 'Sec-Fetch-Site: same-origin' "${P_SITE[@]}")" = 403 ]
check "POST with Sec-Fetch-Site: same-site gets 403" \
  [ "$(post "$DPORT" "$J" -H "Origin: http://127.0.0.1:$DPORT" -H 'Sec-Fetch-Site: same-site' "${P_SITE[@]}")" = 403 ]
check "POST with Sec-Fetch-Site: cross-site gets 403" \
  [ "$(post "$DPORT" "$J" -H "Origin: http://127.0.0.1:$DPORT" -H 'Sec-Fetch-Site: cross-site' "${P_SITE[@]}")" = 403 ]
check "POST without Sec-Fetch-Site gets 403" \
  [ "$(post "$DPORT" "$J" -H "Origin: http://127.0.0.1:$DPORT" "${P_SITE[@]}")" = 403 ]
check "POST as text/plain (what a form can send) gets 415" \
  [ "$(post "$DPORT" "$J" -H "Origin: http://127.0.0.1:$DPORT" -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-Mode: cors' -H 'Sec-Fetch-Dest: empty' -H 'Content-Type: text/plain')" = 415 ]
check "POST without Content-Length gets 411" upy "
import socket
s = socket.create_connection(('127.0.0.1', $DPORT))
s.sendall(b'POST /api/session HTTP/1.1\r\nHost: 127.0.0.1:$DPORT\r\nOrigin: http://127.0.0.1:$DPORT\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\nContent-Type: application/json\r\n\r\n')
assert s.recv(64).startswith(b'HTTP/1.1 411'), 'not 411'"
check "OPTIONS gets 405 and no CORS answer" bash -c "
  h=\$($AS curl -sS -D - -o /dev/null -X OPTIONS -H 'Origin: http://attacker.example' -H 'Access-Control-Request-Method: POST' '$B/api/session')
  echo \"\$h\" | grep -q '^HTTP/1.1 405' && ! echo \"\$h\" | grep -qi '^Access-Control'"

KEY1=$(session "$DPORT" "$CODE1")
check "the page's own POST swaps the code for a 64-hex session key (200)" \
  bash -c "[[ '$KEY1' =~ ^[0-9a-f]{64}$ ]]"
check "  ...the answer carries the terminal's fingerprint" \
  python3 -I -c "import json; d=json.load(open('$W/body')); assert d['fingerprint'] == '$FP' and d['via'] == 'local', d"
check "  ...and the launch file is gone, with its directory" \
  bash -c "[ -n '$LINK_FILE' ] && [ ! -e '$LINK_FILE' ] && [ ! -e \"\$(dirname '$LINK_FILE')\" ]"
check "the session key unlocks the API (200)" \
  [ "$(code -H "X-StockFW-Session: $KEY1" "$B/api/summary")" = 200 ]
check "  ...a wrong key gets 401" \
  [ "$(code -H "X-StockFW-Session: $(printf 'ab%.0s' $(seq 1 32))" "$B/api/summary")" = 401 ]
check "  ...the key in the query string gets 401 (headers only)" \
  [ "$(code "$B/api/summary?session=$KEY1")" = 401 ]
check "  ...the old token header gets 401" \
  [ "$(code -H "X-StockFW-Token: $KEY1" "$B/api/summary")" = 401 ]
check "summary shows the fingerprint the terminal printed" \
  bash -c "$AS curl -sS -H 'X-StockFW-Session: $KEY1' '$B/api/summary' | python3 -I -c 'import json,sys; assert json.load(sys.stdin)[\"fingerprint\"] == \"$FP\"'"

# GET checks (D3 step 4), with a valid session.
S1=(-H "X-StockFW-Session: $KEY1")
check "GET with a foreign Origin gets 403, even with a session" \
  [ "$(code "${S1[@]}" -H 'Origin: http://attacker.example' "$B/api/summary")" = 403 ]
check "GET with Sec-Fetch-Site: cross-site gets 403" \
  [ "$(code "${S1[@]}" -H 'Sec-Fetch-Site: cross-site' "$B/api/summary")" = 403 ]
check "GET with Sec-Fetch-Site: same-site gets 403" \
  [ "$(code "${S1[@]}" -H 'Sec-Fetch-Site: same-site' "$B/api/summary")" = 403 ]
check "GET from the page itself (own Origin, same-origin) gets 200" \
  [ "$(code "${S1[@]}" -H "Origin: http://127.0.0.1:$DPORT" -H 'Sec-Fetch-Site: same-origin' "$B/api/summary")" = 200 ]

# Reuse (T9): a second session from `dashboard link', then the first
# code again.
LINK_OUT="$(as_user "$W/stockfw" dashboard link 2>&1)"
check "dashboard link, piped, prints only a launch file's path (no 32-hex string)" \
  bash -c "printf '%s\n' '$LINK_OUT' | grep -qE '^/.*/open.html$' && ! printf '%s' '$LINK_OUT' | grep -qE '[0-9a-f]{32,}'"
KEY2=$(session "$DPORT" "$(code_in "$LINK_OUT")")
check "  ...and its code gives a second session" \
  [ "$(code -H "X-StockFW-Session: $KEY2" "$B/api/summary")" = 200 ]
page_hdrs "$DPORT"
check "a code used a second time gets 410 (T9)" \
  [ "$(post "$DPORT" "{\"code\":\"$CODE1\"}" "${PAGE[@]}")" = 410 ]
check "  ...and every session ends, not only the one it opened" \
  bash -c "[ \"\$($AS curl -sS -o /dev/null -w '%{http_code}' -H 'X-StockFW-Session: $KEY1' '$B/api/summary')\" = 401 ] &&
           [ \"\$($AS curl -sS -o /dev/null -w '%{http_code}' -H 'X-StockFW-Session: $KEY2' '$B/api/summary')\" = 401 ]"
check "  ...and the terminal says so" grep -q 'used dashboard link was presented again' "$W/dash.txt"
check "dashboard link on a terminal prints the link with a code" python3 -I -c "
import os, pty, subprocess, re
pre = '$AS'.split()
m, s = pty.openpty()
r = subprocess.run(pre + ['$W/stockfw', 'dashboard', 'link'], stdin=s, stdout=s, stderr=s, timeout=10)
os.close(s)
out = os.read(m, 4096)
assert r.returncode == 0 and re.search(rb'http://127\.0\.0\.1:$DPORT/#code=[0-9a-f]{32}', out), out"

# ------------------------------------------------- new response headers
check "every answer carries Trusted Types, Permissions-Policy and COEP" bash -c "
  h=\$($AS curl -sS -D - -o /dev/null '$B/')
  echo \"\$h\" | grep -q \"require-trusted-types-for 'script'; trusted-types 'none'\" &&
  echo \"\$h\" | grep -q '^Permissions-Policy: camera=(), microphone=(), geolocation=(), clipboard-read=()' &&
  echo \"\$h\" | grep -q '^Cross-Origin-Embedder-Policy: require-corp'"
check "the page sends X-StockFW-Session and swaps the code at /api/session (2C)" bash -c "
  p=\$($AS curl -sS '$B/')
  echo \"\$p\" | grep -q 'X-StockFW-Session' && echo \"\$p\" | grep -q '\"/api/session\"' &&
  ! echo \"\$p\" | grep -q 'X-StockFW-Token' && ! echo \"\$p\" | grep -q 'innerHTML'"

# ------------------------------------------------------- request checks
KEY=$(session "$DPORT" "$(new_code)")
S=(-H "X-StockFW-Session: $KEY")
check "Host: localhost:PORT is refused (403): only 127.0.0.1:PORT is ours (G4, T5)" \
  [ "$(code -H "Host: localhost:$DPORT" "${S[@]}" "$B/api/summary")" = 403 ]
check "  ...and so is the right address on another port (403)" \
  [ "$(code -H "Host: 127.0.0.1:1" "${S[@]}" "$B/api/summary")" = 403 ]
check "Upgrade: websocket is refused (400), even with a session (T7)" \
  [ "$(code -H "Upgrade: websocket" -H "Connection: Upgrade" "${S[@]}" "$B/api/summary")" = 400 ]
check "  ...and from a foreign Origin too (400)" \
  [ "$(code -H "Upgrade: websocket" -H "Origin: http://attacker.example" "$B/")" = 400 ]
check "Transfer-Encoding is refused (400)" \
  [ "$(code -H "Transfer-Encoding: chunked" "${S[@]}" --data-binary x "$B/api/summary")" = 400 ]
check "a Content-Length over 64 KB is refused (413)" \
  [ "$(code -H "Content-Length: 70000" "${S[@]}" "$B/api/summary")" = 413 ]
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
s.sendall(b'GET /api/summary HTTP/1.1\r\nHost: 127.0.0.1:$DPORT\r\nX-StockFW-Session: $KEY\r\nContent-Length: 10\r\n\r\nabc')
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
s.sendall(b'GET /api/summary HTTP/1.1\r\nHost: 127.0.0.1:$DPORT\r\nX-StockFW-Session: $KEY\r\nContent-Length: 10\r\n\r\n0123456789')
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
c.sendall(b'GET /api/summary HTTP/1.1\r\nHost: 127.0.0.1:$DPORT\r\nX-StockFW-Session: $KEY\r\n\r\n')
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
  # The session is valid in every one of these: only the peer's uid
  # differs.  curl prints 000 when the connection closes unanswered.
  check "a connection from uid 0 (root) is closed at accept, unanswered (000)" \
    [ "$(curl -sS -o /dev/null -w '%{http_code}' "${S[@]}" "$B/api/summary" 2>/dev/null)" = 000 ]
  check "a connection from uid nobody is closed at accept, unanswered (000)" \
    [ "$(as_nobody curl -sS -o /dev/null -w '%{http_code}' "${S[@]}" "$B/api/summary" 2>/dev/null)" = 000 ]
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
    [ "$(code "${S[@]}" "$B/api/summary")" = 200 ]
  check "the terminal names the account served" \
    grep -q "uid $USER_UID only (SUDO_UID)" "$W/dash.txt"
  # The link socket: SO_PEERCRED before anything is sent.  Root can get
  # past the 0700 directory, and still gets nothing.
  check "the link socket is 0700 in a 0700 directory of the user" \
    bash -c "[ \"\$(stat -c '%a %u' '$RUN/stockfw')\" = '700 $USER_UID' ] &&
             [ \"\$(stat -c '%u' '$RUN/stockfw/dash-$DPORT.sock')\" = '$USER_UID' ]"
  check "  ...and a connection from another uid (root) gets no code" python3 -I -c "
import socket
s = socket.socket(socket.AF_UNIX); s.settimeout(5)
s.connect('$RUN/stockfw/dash-$DPORT.sock')
got = b''
try:
    while True:
        d = s.recv(4096)
        if not d: break
        got += d
except OSError:
    pass
assert b'code=' not in got, got"
  check "dashboard link as root is refused (exit 1)" bash -c "
    '$W/stockfw' dashboard link > /dev/null 2>&1; [ \$? = 1 ]"
fi

KEY_OLD="$KEY"
stop_dash

# A restart: every key dies with the process.
start_dash "$W/stockfw" "$DPORT"
# A session of the new run is open, so a key that outlived the run (or
# keys that repeat) would be found.
NEW_KEY=$(session "$DPORT" "$(code_in "$LINK_FILE")")
check "after a restart, a key from the last run gets 401 (a new session is open)" \
  bash -c "[[ '$NEW_KEY' =~ ^[0-9a-f]{64}$ ]] && [ '$NEW_KEY' != '$KEY_OLD' ] &&
           [ \"\$($AS curl -sS -o /dev/null -w '%{http_code}' -H 'X-StockFW-Session: $KEY_OLD' '$B/api/summary')\" = 401 ]"
check "  ...and the link socket is there again for the new run" \
  bash -c "[ -S '$RUN/stockfw/dash-$DPORT.sock' ]"
stop_dash
check "when the dashboard stops, its socket and launch files are gone" \
  bash -c "[ ! -e '$RUN/stockfw/dash-$DPORT.sock' ] && [ -z \"\$(ls '$RUN' | grep stockfw-dashboard)\" ]"

# Review of PR 2: closing the terminal (SIGHUP) left the socket and the
# launch files behind, and `dashboard link' then counted every socket
# left behind as a running dashboard.
start_dash "$W/stockfw" "$DPORT"
kill -HUP "$DASH_PID"; wait "$DASH_PID" 2>/dev/null; DASH_PID=""
check "on SIGHUP (the terminal closed) the socket and launch files are gone too" \
  bash -c "[ ! -e '$RUN/stockfw/dash-$DPORT.sock' ] && [ -z \"\$(ls '$RUN' | grep stockfw-dashboard)\" ]"
start_dash "$W/stockfw" "$DPORT"
kill -KILL "$DASH_PID"; wait "$DASH_PID" 2>/dev/null; DASH_PID=""
check "a dashboard killed with SIGKILL leaves its socket (nothing can remove it)" \
  [ -S "$RUN/stockfw/dash-$DPORT.sock" ]
rm -rf "$RUN"/stockfw-dashboard-*
DPORT2=$(free_port)
start_dash "$W/stockfw" "$DPORT2"
LINK_OUT2="$(as_user "$W/stockfw" dashboard link 2>&1)"; LINK_RC=$?
check "after a dashboard was killed, dashboard link finds the one still running" \
  bash -c "[ '$LINK_RC' = 0 ] && printf '%s\n' '$LINK_OUT2' | grep -qE '^/.*/open.html$'"
check "  ...and the socket the killed one left is removed" \
  bash -c "[ ! -e '$RUN/stockfw/dash-$DPORT.sock' ] && [ -S '$RUN/stockfw/dash-$DPORT2.sock' ]"
stop_dash

# ------------------------------------------------------- --origin-port
# ssh -L N:127.0.0.1:PORT host (T22): the browser's end is 127.0.0.1:N.
OPORT=$(free_port)
start_dash "$W/stockfw" "$DPORT" --origin-port "$OPORT"
OC=$(code_in "$LINK_FILE")
page_hdrs "$OPORT"
check "--origin-port N: a POST with Host and Origin 127.0.0.1:N opens a session (200)" \
  [ "$(post "$DPORT" "{\"code\":\"$OC\"}" "${PAGE[@]}" -H "Host: 127.0.0.1:$OPORT")" = 200 ]
check "  ...and the session is marked via=ssh" \
  python3 -I -c "import json; d=json.load(open('$W/body')); assert d['via'] == 'ssh', d"
OKEY=$(python3 -I -c "import json; print(json.load(open('$W/body'))['session'])")
check "  ...a GET with Host 127.0.0.1:N gets 200" \
  [ "$(code -H "Host: 127.0.0.1:$OPORT" -H "X-StockFW-Session: $OKEY" "$B/api/summary")" = 200 ]
check "  ...Host 127.0.0.1:N+1 gets 403" \
  [ "$(code -H "Host: 127.0.0.1:$((OPORT+1))" -H "X-StockFW-Session: $OKEY" "$B/api/summary")" = 403 ]
check "  ...dashboard link on a terminal prints the link on port N too" python3 -I -c "
import os, pty, subprocess, re
pre = '$AS'.split()
m, s = pty.openpty()
r = subprocess.run(pre + ['$W/stockfw', 'dashboard', 'link'], stdin=s, stdout=s, stderr=s, timeout=10)
os.close(s)
out = os.read(m, 4096)
assert r.returncode == 0 and re.search(rb'http://127\.0\.0\.1:$OPORT/#code=[0-9a-f]{32}', out), out"
check "  ...and its --json names origin_port" bash -c "
  $AS '$W/stockfw' --json dashboard link | python3 -I -c 'import json,sys; assert json.load(sys.stdin)[\"origin_port\"] == $OPORT'"
OC2=$(new_code)
check "  ...an Origin of :N with Host :PORT (mismatched) gets 403" \
  [ "$(post "$DPORT" "{\"code\":\"$OC2\"}" "${PAGE[@]}")" = 403 ]
stop_dash
start_dash "$W/stockfw" "$DPORT"
check "without --origin-port, Host 127.0.0.1:N gets 403" \
  [ "$(code -H "Host: 127.0.0.1:$OPORT" "$B/")" = 403 ]
stop_dash

# ---------------------------------------------- empty lines (RFC 9112)
# Review of PR 2: a request that began with "\r\n\r\n" was a head of
# length 0 with no request line, and NULL went to g_strsplit.  GLib
# only logged it; with G_DEBUG=fatal-criticals the dashboard died.
G_DEBUG=fatal-criticals start_dash "$W/stockfw" "$DPORT"
check "empty lines before the request line are ignored: the request is answered (200)" upy "
import socket
s = socket.create_connection(('127.0.0.1', $DPORT)); s.settimeout(5)
s.sendall(b'\r\n\r\nGET /logo.png HTTP/1.1\r\nHost: 127.0.0.1:$DPORT\r\n\r\n')
assert s.recv(64).startswith(b'HTTP/1.1 200'), 'not 200'"
check "  ...and \"\\r\\n\\r\\n\" alone, then a close, leaves the dashboard running" upy "
import socket, time
s = socket.create_connection(('127.0.0.1', $DPORT)); s.sendall(b'\r\n\r\n'); time.sleep(0.3); s.close()
time.sleep(0.3)
s = socket.create_connection(('127.0.0.1', $DPORT)); s.settimeout(5)
s.sendall(b'GET /logo.png HTTP/1.1\r\nHost: 127.0.0.1:$DPORT\r\n\r\n')
assert s.recv(64).startswith(b'HTTP/1.1 200'), 'not 200'"
check "  ...with no GLib warning" bash -c "! grep -q CRITICAL '$W/dash.txt'"
stop_dash

# ------------------------------------------- the test clock (E7, T12)
# stockfw-dash-test reads seconds to add to its clock from a file.
CLK="$W/clock"; echo 0 > "$CLK"; chmod 644 "$CLK"
export STOCKFW_TEST_CLOCK_FILE="$CLK"
start_dash "$W/stockfw-test" "$DPORT"
TKEY=$(session "$DPORT" "$(code_in "$LINK_FILE")")
LF2="$(as_user "$W/stockfw-test" dashboard link 2>/dev/null)"
TCODE=$(code_in "$LF2")
# The clock counts whole seconds and real time passes too: 117 + the
# 1.5 s waited stays under 120.
echo 117 > "$CLK"; sleep 1.5
check "test clock: a code's launch file is still there before 120 s" \
  bash -c "[ -n '$TCODE' ] && [ -f '$LF2' ]"
echo 121 > "$CLK"; sleep 1.5
check "  ...and gone at 121 s, with no request (T12)" \
  bash -c "[ -n '$LF2' ] && [ ! -e '$LF2' ] && [ ! -e \"\$(dirname '$LF2')\" ]"
page_hdrs "$DPORT"
check "  ...and the code gets 410 at 121 s (T9)" \
  [ "$(post "$DPORT" "{\"code\":\"$TCODE\"}" "${PAGE[@]}")" = 410 ]
check "  ...an expired code ends no session" \
  [ "$(code -H "X-StockFW-Session: $TKEY" "$B/api/summary")" = 200 ]
echo $((12 * 3600 - 30)) > "$CLK"
check "test clock: a session still reads 12 h after its code, less 30 s (E7)" \
  [ "$(code -H "X-StockFW-Session: $TKEY" "$B/api/summary")" = 200 ]
echo $((12 * 3600 + 5)) > "$CLK"
check "  ...and gets 401 once the 12 h are over" \
  [ "$(code -H "X-StockFW-Session: $TKEY" "$B/api/summary")" = 401 ]
stop_dash
unset STOCKFW_TEST_CLOCK_FILE

# ---------------------------------------------------------- WSL (T21)
check "--allow-windows off WSL refuses to start (exit 2)" bash -c "
  STOCKFW_TEST_WSL=0 timeout 10 ${START[*]} '$W/stockfw-test' dashboard --no-open --allow-windows > '$W/out' 2>&1; rc=\$?
  [ \$rc = 2 ] && grep -q 'WSL only' '$W/out'"
if [ "$ROOT" = 1 ]; then
  # In the test build, sockets of uid 65534 look as if they had no
  # owner, as Windows' relay is expected to.
  export STOCKFW_TEST_WSL=1 STOCKFW_TEST_OWNERLESS_UID=65534
  start_dash "$W/stockfw-test" "$DPORT"
  wsl_refused_page () {
    local out
    out=$(as_nobody curl -sS -w '\n%{http_code}' "$B/?code=0123" 2>/dev/null)
    [ "$(printf '%s' "$out" | tail -n 1)" = 403 ] &&
      printf '%s' "$out" | grep -q -- '--allow-windows' &&
      ! printf '%s' "$out" | grep -q -e 0123 -e fingerprint
  }
  check "WSL, fail-closed: a peer with no socket owner gets 403 and a page naming --allow-windows, nothing else" \
    wsl_refused_page
  sleep 0.3
  check "  ...and the terminal says how to let it in" \
    grep -q -- '--allow-windows' "$W/dash.txt"
  stop_dash
  start_dash "$W/stockfw-test" "$DPORT" --allow-windows
  check "WSL with --allow-windows: that peer is answered (the page, 200)" \
    [ "$(as_nobody curl -sS -o /dev/null -w '%{http_code}' "$B/" 2>/dev/null)" = 200 ]
  check "  ...but still needs a session (401)" \
    [ "$(as_nobody curl -sS -o /dev/null -w '%{http_code}' "$B/api/summary" 2>/dev/null)" = 401 ]
  WC=$(code_in "$LINK_FILE")
  check "  ...its session is marked via=wsl, and the terminal says Windows is let in" bash -c "
    r=\$(setpriv --reuid=65534 --regid=65534 --clear-groups curl -sS -X POST -H 'Origin: http://127.0.0.1:$DPORT' -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-Mode: cors' -H 'Sec-Fetch-Dest: empty' -H 'Content-Type: application/json' --data '{\"code\":\"$WC\"}' '$B/api/session')
    echo \"\$r\" | grep -q '\"via\":\"wsl\"' && grep -q 'allow-windows' '$W/dash.txt'"
  check "  ...while root is still closed at accept (000)" \
    [ "$(curl -sS -o /dev/null -w '%{http_code}' "$B/" 2>/dev/null)" = 000 ]
  # Review of PR 2: under --allow-windows, a connection whose socket
  # has no owner on this machine is let in.  A socket its process has
  # closed (an orphan: inode 0, or no row at all once the TIME_WAIT
  # table is full) used to count as that too, so another account got a
  # request read by closing at once.  closed_at_once [prefix...]: with
  # the dashboard stopped, uid 65532 sends a POST with a fresh code and
  # closes; true when that code still works afterwards (the POST was
  # not read).
  closed_at_once () {
    local c; c=$(new_code)
    [ -n "$c" ] || return 1
    kill -STOP "$DASH_PID"
    "$@" setpriv --reuid=65532 --regid=65532 --clear-groups python3 -I -c "
import socket
b = b'{\"code\":\"$c\"}'
s = socket.create_connection(('127.0.0.1', $DPORT))
s.sendall(b'POST /api/session HTTP/1.1\r\nHost: 127.0.0.1:$DPORT\r\nOrigin: http://127.0.0.1:$DPORT\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n' % len(b) + b)
s.close()"
    sleep 0.3
    kill -CONT "$DASH_PID"
    sleep 0.5
    [ "$("$@" setpriv --reuid=65534 --regid=65534 --clear-groups curl -sS -o /dev/null -w '%{http_code}' -X POST -H "Origin: http://127.0.0.1:$DPORT" -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-Mode: cors' -H 'Sec-Fetch-Dest: empty' -H 'Content-Type: application/json' --data "{\"code\":\"$c\"}" "$B/api/session" 2>/dev/null)" = 200 ]
  }
  check "  ...a request from another account that closed at once is not read (orphan, inode 0)" \
    closed_at_once
  stop_dash
  # The same in a network namespace of its own that keeps no TIME_WAIT
  # entries, as a full table does: the closed socket is then gone.
  if mk_netns 0; then
    START=(nsenter -t "$NSHOLD" -n "${SAVED_START[@]}")
    start_dash "$W/stockfw-test" "$DPORT" --allow-windows
    START=("${SAVED_START[@]}")
    check "  ...nor when its closed socket is gone (no TIME_WAIT entry)" \
      closed_at_once nsenter -t "$NSHOLD" -n
    check "  ...while a Windows peer still open is answered there (200)" \
      [ "$(nsenter -t "$NSHOLD" -n setpriv --reuid=65534 --regid=65534 --clear-groups curl -sS -o /dev/null -w '%{http_code}' "$B/" 2>/dev/null)" = 200 ]
    stop_dash
  else
    check "a network namespace for the TIME_WAIT check (unshare -n, ip, sysctl)" false
  fi
  end_netns
  unset STOCKFW_TEST_WSL STOCKFW_TEST_OWNERLESS_UID
fi

if [ "$ROOT" = 1 ]; then
  check "as root without SUDO_UID it refuses to start (exit 1), naming why" bash -c "
    timeout 10 env -u SUDO_UID '$W/stockfw' dashboard --no-open > '$W/out' 2>&1; rc=\$?
    [ \$rc = 1 ] && grep -q 'does not serve uid 0' '$W/out' && ! grep -qE 'code=|Link file' '$W/out'"
  check "  ...and with SUDO_UID=0 too" bash -c "
    timeout 10 env SUDO_UID=0 '$W/stockfw' dashboard --no-open > '$W/out' 2>&1; rc=\$?
    [ \$rc = 1 ] && grep -q 'does not serve uid 0' '$W/out'"
  check "under sudo with no runtime directory of the user and stdout piped, it does not start (exit 1)" bash -c "
    timeout 10 env SUDO_UID=$USER_UID XDG_RUNTIME_DIR=/nonexistent '$W/stockfw' dashboard --no-open > '$W/out' 2>&1; rc=\$?
    [ \$rc = 1 ] && grep -q 'nowhere to go' '$W/out'"
else
  echo "skip: peer uid, link socket, WSL peer and full socket table checks need root (a second account)"
fi

# ------------------------------------------- a full socket table (T2)
# Review of PR 2: the accept check used to read and split all of
# /proc/net/tcp for every connection, so an account that filled the
# table with TIME_WAIT entries (no file descriptors held) slowed every
# request down: about 150 ms each at 60,000 entries.  The one-socket
# netlink lookup does not grow with the table.  It runs in a network
# namespace of its own, so the entries (they stay 60 s) slow nothing
# else on the machine.  Nobody makes the entries; the user's requests
# fetch /logo.png (the API reads the connection table itself).
if [ "$ROOT" = 1 ]; then
  if mk_netns 262144; then
    START=(nsenter -t "$NSHOLD" -n "${SAVED_START[@]}")
    start_dash "$W/stockfw" "$DPORT"
    START=("${SAVED_START[@]}")
    nsenter -t "$NSHOLD" -n setpriv --reuid=65534 --regid=65534 --clear-groups python3 -I -c "
import socket
l = socket.socket(); l.bind(('127.0.0.1', 0)); l.listen(128)
lp = l.getsockname()[1]; made = 0
for a in range(1, 255):
    for b in range(1, 255):
        if made >= 40000: break
        c = socket.socket(); c.bind(('127.0.%d.%d' % (a, b), 0))
        c.connect(('127.0.0.1', lp)); s, _ = l.accept()
        c.close(); s.close(); made += 1"
    check "with 40,000 TIME_WAIT entries in the table, 20 requests answer within 2 s (T2)" \
      nsenter -t "$NSHOLD" -n setpriv --reuid=$USER_UID --regid=$USER_UID --clear-groups python3 -I -c "
import socket, time
assert sum(1 for _ in open('/proc/net/tcp')) > 40000
t0 = time.monotonic()
for i in range(20):
    c = socket.create_connection(('127.0.0.1', $DPORT)); c.settimeout(5)
    c.sendall(b'GET /logo.png HTTP/1.1\r\nHost: 127.0.0.1:$DPORT\r\n\r\n')
    assert c.recv(64).startswith(b'HTTP/1.1 200')
    c.close()
took = time.monotonic() - t0
assert took < 2.0, took"
    stop_dash
  else
    check "a network namespace for the T2 check (unshare -n, ip, sysctl)" false
  fi
  end_netns
fi

echo ""
if [ "$fails" -eq 0 ]; then
  echo "PASSED: 0 failure(s)"
else
  echo "FAILED: $fails failure(s)"
fi
exit "$fails"
