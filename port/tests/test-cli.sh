#!/bin/bash
# The `stockfw' command-line tool and its local dashboard, end to end.
#
# Builds the real binary through CMake, then drives it the way a user
# (or a script) would: the exit codes `stockfw help' documents, the
# policy files the desktop app shares, the simulator's verdicts, the
# kernel-log history, every --json document parsed back, and the
# dashboard's security model -- 127.0.0.1 only, a per-run token,
# DNS-rebinding defence, GET/HEAD only, a capped request head and a
# nonce-locked CSP.
#
# Everything runs against scratch directories (STOCKFW_RULES_DIR,
# XDG_CONFIG_HOME) and a fixture log (STOCKFW_LOG_FILE): the test never
# touches /etc/stockfw or the live firewall, and `apply' only ever runs
# with --dry-run.  Linux only; no root needed.
#
#   cd port && bash tests/test-cli.sh

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
cd "$PORT" || exit 1

if [ "$(uname -s)" != "Linux" ]; then
  echo "SKIP: the stockfw CLI is the Linux front end"
  exit 0
fi

BUILD="${STOCKFW_BUILD:-$PORT/build-linux}"
if ! { cmake -S . -B "$BUILD" -G Ninja > /dev/null &&
       cmake --build "$BUILD" --target stockfw > /dev/null; }; then
  echo "FAIL: could not build the stockfw target"
  echo "FAILED: 1 failure(s)"
  exit 1
fi
S="$BUILD/stockfw"

TMP="$(mktemp -d)"
DASH_PID=""
cleanup () {
  [ -n "$DASH_PID" ] && kill "$DASH_PID" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

export STOCKFW_RULES_DIR="$TMP/rules"
export XDG_CONFIG_HOME="$TMP/config"
export STOCKFW_LOG_FILE="$TMP/kern.log"
unset NO_COLOR

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
rc_is () {   # rc_is <expected> <command...>  (output discarded)
  local want="$1"; shift
  "$@" > "$TMP/out" 2> "$TMP/err"
  [ "$?" -eq "$want" ]
}
json_ok () { python3 -I -c 'import json,sys; json.load(sys.stdin)' < "$1"; }
py () { python3 -I -c "$1"; }

# ------------------------------------------------------------- fixture
# Kernel-log lines the way rsyslog writes them, a minute apart and
# ending now: three drops and a reject, plus noise that must be ignored.
py '
import datetime
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
def at(m): return (now - datetime.timedelta(minutes=m)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
lines = [
 at(4) + " host kernel: [1.0] STOCKFW-DROP IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=40000 DPT=22 SYN",
 at(3) + " host kernel: [2.0] some other driver says hello",
 at(3) + " host kernel: [3.0] STOCKFW-DROP IN=eth0 OUT= SRC=198.51.100.7 DST=10.0.0.5 LEN=40 PROTO=TCP SPT=40001 DPT=445 SYN",
 at(2) + " host kernel: [4.0] STOCKFW-REJECT IN=eth0 OUT= SRC=192.0.2.44 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=40002 DPT=3389 SYN",
 at(1) + " host kernel: [5.0] STOCKFW-DROP IN= OUT=eth0 SRC=10.0.0.5 DST=203.0.113.9 LEN=60 PROTO=TCP SPT=50000 DPT=443 SYN",
]
open("'"$TMP"'/kern.log", "w").write("\n".join(lines) + "\n")
'

# --------------------------------------------------------- basics
check "--version prints the version and exits 0" \
  bash -c "'$S' --version | grep -q '^stockfw [0-9]'"
check "an unknown command is a usage error (exit 2)" rc_is 2 "$S" frobnicate
check "help lists every command" \
  bash -c "'$S' help | grep -q dashboard && '$S' help | grep -q simulate"
check "per-command help exists for policy" \
  bash -c "'$S' help policy | grep -q 'inbound-allow-service'"
check "output to a pipe has no colour codes" \
  bash -c "! '$S' simulate inbound ssh | grep -q \$'\\e\\['"

# --------------------------------------------------------- policy
check "an empty policy lists as JSON" \
  bash -c "'$S' --json policy list > '$TMP/p.json'"
check "  ...and it parses" json_ok "$TMP/p.json"
check "a known service needs no port: 'add inbound-allow-service ssh'" \
  rc_is 0 "$S" policy add inbound-allow-service ssh
check "  ...and is saved as SSH, port 22, for Anyone" \
  grep -q '^SSH, *22, *Anyone' "$STOCKFW_RULES_DIR/inbound/allow-service"
check "a multi-port service still needs its port (exit 2)" \
  rc_is 2 "$S" policy add inbound-allow-service samba
check "a mistyped option is refused, not saved as a field (exit 2)" \
  rc_is 2 "$S" policy add outbound-deny-to 203.0.113.9 --commnet x
check "a comma inside a field is refused (it would split the CSV)" \
  rc_is 2 "$S" policy add outbound-deny-to 203.0.113.9 --comment "a,b"
check "an invalid host is refused" \
  rc_is 2 "$S" policy add outbound-deny-to 999.1.1.1
check "a valid deny rule with a comment is saved" \
  rc_is 0 "$S" policy add outbound-deny-to 203.0.113.9 --comment "known bad"
check "adding the same rule twice is a no-op, not a duplicate" \
  bash -c "'$S' policy add outbound-deny-to 203.0.113.9 --comment 'known bad' | grep -q Already &&
           [ \$(grep -c 203.0.113.9 '$STOCKFW_RULES_DIR/outbound/deny-to') -eq 1 ]"
check "policy list --json shows both rules" \
  bash -c "'$S' --json policy list > '$TMP/p.json'"
check "  ...parsed: one inbound SSH rule and one deny rule" py "
import json; d = json.load(open('$TMP/p.json'))
rules = d['rules'] if isinstance(d, dict) else d
kinds = sorted(r['kind'] for r in rules)
assert kinds == ['inbound-allow-service', 'outbound-deny-to'], kinds"

# --------------------------------------------------------- simulate
check "simulate: SSH from anywhere is ALLOWED (exit 0)" \
  rc_is 0 "$S" simulate inbound ssh from 198.51.100.4
check "simulate: the denied host is BLOCKED (exit 5)" \
  rc_is 5 "$S" simulate outbound tcp to 203.0.113.9 port 443
check "simulate --json names the verdict and the matching rule" py "
import json, subprocess
out = subprocess.run(['$S', '--json', 'simulate', 'outbound tcp to 203.0.113.9 port 443'],
                     capture_output=True, text=True).stdout
d = json.loads(out)
assert d['verdict'] == 'BLOCKED' and '203.0.113.9' in d['rule'], d"
check "simulate with no description is a usage error" rc_is 2 "$S" simulate

# --------------------------------------------------------- apply (dry run only)
check "apply --dry-run previews and changes nothing" \
  bash -c "'$S' apply --dry-run | grep -q 'Nothing was changed'"

# --------------------------------------------------------- events
check "events reads the fixture log: four events, noise ignored" \
  bash -c "'$S' --json events -n 50 > '$TMP/e.json'"
check "  ...parsed as JSON" json_ok "$TMP/e.json"
check "  ...four events, all blocked, oldest first, named without the marker" py "
import json; ev = json.load(open('$TMP/e.json'))
assert len(ev) == 4, len(ev)
assert all(e['blocked'] for e in ev)
assert [e['port'] for e in ev] == ['22', '445', '3389', '443'], [e['port'] for e in ev]
assert ev[0]['service'] == 'SSH' and ev[1]['service'] == 'Samba (SMB)', ev[:2]
assert not any('BLOCKED' in e['service'] for e in ev)
assert ev[3]['direction'] == 'out' and ev[3]['destination'] == '203.0.113.9'"
check "events -n 1 keeps only the newest" py "
import json, subprocess
ev = json.loads(subprocess.run(['$S', '--json', 'events', '-n', '1'], capture_output=True, text=True).stdout)
assert len(ev) == 1 and ev[0]['port'] == '443', ev"
check "events as a table has a header and a BLOCKED row per event" \
  bash -c "[ \$('$S' events -n 50 | grep -c BLOCKED) -eq 4 ]"

check "events with a filter looks further back and keeps what matches" py "
import json, subprocess
ev = json.loads(subprocess.run(['$S', '--json', 'events', '-n', '1', '--port', '445'], capture_output=True, text=True).stdout)
assert [e['port'] for e in ev] == ['445'], ev
ev = json.loads(subprocess.run(['$S', '--json', 'events', '-n', '50', '--dir', 'out'], capture_output=True, text=True).stdout)
assert [e['port'] for e in ev] == ['443'], ev
ev = json.loads(subprocess.run(['$S', '--json', 'events', '-n', '50', '--allowed'], capture_output=True, text=True).stdout)
assert ev == [], ev"

# --------------------------------------------------------- events --history
# The history the desktop app saves (core/fs-eventlog.c): one file per
# UTC day, a tab-separated line per event with an FNV-1a checksum.
# Written here by hand, so the test also pins the file format.
H="$TMP/history"
py "
import os
H = '$H'
os.makedirs(H, mode=0o700)
def fnv(b):
    h = 2166136261
    for c in b:
        h = ((h ^ c) * 16777619) & 0xffffffff
    return h
def line(stamp, ticks, d, port, src, dst, proto, service):
    f = [str(ticks), stamp, d, 'eth0' if d == 'in' else '', 'eth0' if d == 'out' else '',
         port, src, dst, '60', '0x00', proto, service, 'STOCKFW-DROP']
    body = '\t'.join(f)
    return body + '\t%08x\n' % fnv(body.encode())
def t(day, hh, mm):
    import datetime
    dt = datetime.datetime(2026, 10, day, hh, mm, tzinfo=datetime.timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ'), int(dt.timestamp()) * 10000000
ev30 = [
  line(*t(30, 9, 0), 'in', '22', '203.0.113.5', '10.0.0.5', 'TCP', 'SSH [BLOCKED]'),
  line(*t(30, 9, 5), 'in', '3389', '198.51.100.7', '10.0.0.5', 'TCP', 'Remote Desktop [BLOCKED]'),
]
ev31 = [
  line(*t(31, 8, 0), 'out', '443', '10.0.0.5', '203.0.113.9', 'TCP', 'HTTPS'),
  line(*t(31, 8, 1), 'in', '22', '10.1.2.3', '10.0.0.5', 'TCP', 'SSH [BLOCKED]'),
]
with open(os.path.join(H, 'events-2026-10-30-000.log'), 'w') as f:
    f.write('# StockFW event history 1\n' + ''.join(ev30))
bad = ev31[0][:-9] + 'deadbeef\n'           # checksum does not match
cut = ev31[1][:40]                           # a crash mid-write
with open(os.path.join(H, 'events-2026-10-31-000.log'), 'w') as f:
    f.write('# StockFW event history 1\n' + ev31[1] + bad + ev31[0] + cut)
"
check "events --history reads the saved days oldest first, a damaged and a cut-short line skipped" py "
import json, subprocess
r = subprocess.run(['$S', 'events', '--history-dir', '$H', '-n', '100'], capture_output=True, text=True)
assert r.returncode == 0 and r.stdout.count('BLOCKED') == 3 and 'ALLOWED' in r.stdout, r
assert '2 damaged or cut-short line(s)' in r.stderr, r.stderr
ev = json.loads(subprocess.run(['$S', '--json', 'events', '--history-dir', '$H', '-n', '100'], capture_output=True, text=True).stdout)
assert [e['port'] for e in ev] == ['22', '3389', '22', '443'], ev
assert ev[0]['service'] == 'SSH' and ev[0]['blocked'] and not ev[3]['blocked'], ev"
check "  ...-n keeps the newest" py "
import json, subprocess
ev = json.loads(subprocess.run(['$S', '--json', 'events', '--history-dir', '$H', '-n', '2'], capture_output=True, text=True).stdout)
assert [e['port'] for e in ev] == ['22', '443'], ev"
check "  ...--since and --until by day, the --until day taken whole" py "
import json, subprocess
def q(*a): return [e['port'] for e in json.loads(subprocess.run(['$S', '--json', 'events', '--history-dir', '$H', *a], capture_output=True, text=True).stdout)]
assert q('--since', '2026-10-31') == ['22', '443'], q('--since', '2026-10-31')
assert q('--until', '2026-10-30') == ['22', '3389']
assert q('--since', '2026-10-30T09:05:00Z', '--until', '2026-10-31T08:01:00Z') == ['3389', '443']"
check "  ...--port, --dir, --addr (CIDR), --proto, --grep, --blocked and --allowed" py "
import json, subprocess
def q(*a): return [e['port'] for e in json.loads(subprocess.run(['$S', '--json', 'events', '--history-dir', '$H', '-n', '100', *a], capture_output=True, text=True).stdout)]
assert q('--port', '22') == ['22', '22']
assert q('--port', '400-4000') == ['3389', '443']
assert q('--dir', 'out') == ['443']
assert q('--addr', '10.1.0.0/16') == ['22']
assert q('--addr', '203.0.113.0/24') == ['22', '443']
assert q('--proto', 'udp') == []
assert q('--grep', 'remote desk') == ['3389']
assert q('--blocked', '--dir', 'in', '--port', '22') == ['22', '22']
assert q('--allowed') == ['443']"
check "a filter that cannot be read is a usage error, not an empty answer" bash -c "
  '$S' events --history-dir '$H' --port 70000 2> '$TMP/err'; [ \$? -eq 2 ] && grep -q 'port' '$TMP/err' &&
  '$S' events --history-dir '$H' --since yesterday-ish 2> /dev/null; [ \$? -eq 2 ] &&
  '$S' events --history-dir '$H' --addr example.com 2> /dev/null; [ \$? -eq 2 ] &&
  '$S' events --history-dir '$H' --dir sideways 2> /dev/null; [ \$? -eq 2 ] &&
  '$S' events --history-dir '$H' --port 2> /dev/null; [ \$? -eq 2 ]"
check "no saved history is said plainly, with where it would be" bash -c "
  STOCKFW_EVENTS_DIR='$TMP/none' '$S' events --history 2> '$TMP/err'; [ \$? -eq 1 ] &&
  grep -q 'no saved event history in $TMP/none' '$TMP/err' && grep -q 'Keep event history' '$TMP/err'"
check "--history follows STOCKFW_EVENTS_DIR and needs no root" bash -c "
  [ \$(STOCKFW_EVENTS_DIR='$H' '$S' --json events --history | python3 -I -c 'import json,sys; print(len(json.load(sys.stdin)))') -eq 4 ]"

# --------------------------------------------------------- read-only views
check "connections --json parses" \
  bash -c "'$S' --json connections > '$TMP/c.json' && python3 -I -c 'import json,sys; json.load(open(sys.argv[1]))' '$TMP/c.json'"
check "interfaces --json parses and lists at least one adapter" py "
import json, subprocess
d = json.loads(subprocess.run(['$S', '--json', 'interfaces'], capture_output=True, text=True).stdout)
assert isinstance(d, list) and len(d) >= 1 and 'device' in d[0], d"
check "status --json parses and counts the saved rules" py "
import json, subprocess
d = json.loads(subprocess.run(['$S', '--json', 'status'], capture_output=True, text=True).stdout)
assert d['policy_saved'] is True and d['rules']['outbound-deny-to'] == 1, d"
check "status --json says whether IPv6 is filtered, and why" py "
import json, subprocess
d = json.loads(subprocess.run(['$S', '--json', 'status'], capture_output=True, text=True).stdout)
assert d['ipv6']['state'] in ('filtered', 'not-filtered', 'absent', 'unknown'), d['ipv6']
assert d['ipv6']['detail'], d['ipv6']"
check "status has an IPv6 line" \
  bash -c "'$S' status | grep -qE '^  IPv6 +(filtered|not filtered|none on this system|unknown)'"

# Which families each rule covers (1.0.7): the answer follows the
# generator, and the JSON carries the reason.
"$S" policy add inbound-allow-from 2001:db8:1::/48 > /dev/null
"$S" policy add inbound-allow-service HTTP 80 192.168.7.0/24 > /dev/null
"$S" policy add inbound-forward Web 8080 2001:db8::5 80 > /dev/null
check "policy list marks each rule with what it covers" \
  bash -c "'$S' policy list > '$TMP/pl.txt' && grep -q '2001:db8:1::/48  \[IPv6 only\]' '$TMP/pl.txt' && grep -q 'for 192.168.7.0/24  \[IPv4 only\]' '$TMP/pl.txt' && grep -q 'SSH  port 22  for Anyone  \[IPv4 + IPv6\]' '$TMP/pl.txt'"
check "  ...and writes an IPv6 forward [address]:port" \
  grep -qF -- '-> [2001:db8::5]:80  [IPv6 only]' "$TMP/pl.txt"
check "policy list --json gives covers and the reason" py "
import json, subprocess
d = json.loads(subprocess.run(['$S', '--json', 'policy', 'list'], capture_output=True, text=True).stdout)
by = {(r['kind'], r['target'] or r['to']): r for r in d['rules']}
r = by[('inbound-allow-service', '192.168.7.0/24')]
assert r['covers'] == ['ipv4'] and 'IPv4 range' in r['covers_why'], r
assert by[('inbound-allow-from', '2001:db8:1::/48')]['covers'] == ['ipv6']
assert by[('inbound-forward', '2001:db8::5')]['covers'] == ['ipv6']
assert by[('inbound-allow-service', 'Anyone')]['covers'] == ['ipv4', 'ipv6']"
"$S" policy remove inbound-forward 1 > /dev/null
"$S" policy remove inbound-allow-service 2 > /dev/null
"$S" policy remove inbound-allow-from 1 > /dev/null

# --------------------------------------------------------- dashboard
DPORT=$(py 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
"$S" dashboard --no-open --port "$DPORT" > "$TMP/dash.txt" 2>&1 &
DASH_PID=$!
for _ in $(seq 1 50); do
  grep -q '#token=' "$TMP/dash.txt" 2>/dev/null && break
  sleep 0.1
done
URL=$(grep -o 'http://[^ ]*' "$TMP/dash.txt")
TOKEN=${URL##*#token=}
B="http://127.0.0.1:$DPORT"

check "dashboard prints a 127.0.0.1 URL with a 128-bit token" \
  bash -c "[[ '$URL' == http://127.0.0.1:$DPORT/#token=* ]] && [[ '$TOKEN' =~ ^[0-9a-f]{32}$ ]]"
check "it listens on loopback only" \
  bash -c "ss -ltnH 2>/dev/null | grep ':$DPORT ' | grep -qv '127.0.0.1:$DPORT' && exit 1; exit 0"

code () { curl -sS -o /dev/null -w '%{http_code}' "$@"; }

check "the page loads without the token (it holds no data)" \
  bash -c "[ \$(curl -sS -o '$TMP/page.html' -w '%{http_code}' '$B/') = 200 ]"
check "  ...and the token is not in it" bash -c "! grep -q '$TOKEN' '$TMP/page.html'"
check "  ...and its scripts carry this run's CSP nonce" py "
import re, subprocess
h = subprocess.run(['curl', '-sS', '-D', '-', '-o', '/dev/null', '$B/'], capture_output=True, text=True).stdout
csp = re.search(r'Content-Security-Policy: (.*)', h).group(1)
nonce = re.search(r\"'nonce-([0-9a-f]{32})'\", csp).group(1)
page = open('$TMP/page.html').read()
assert \"default-src 'none'\" in csp and \"frame-ancestors 'none'\" in csp, csp
assert page.count('nonce=\"' + nonce + '\"') >= 2 and '{{NONCE}}' not in page"
check "the API refuses a request without the token (401)" \
  bash -c "[ \$(curl -sS -o /dev/null -w '%{http_code}' '$B/api/summary') = 401 ]"
check "  ...and a wrong token (401)" \
  bash -c "[ \$(curl -sS -o /dev/null -w '%{http_code}' -H 'X-StockFW-Token: 0123456789abcdef0123456789abcdef' '$B/api/summary') = 401 ]"
check "  ...and the token in the query string (401: headers only)" \
  bash -c "[ \$(curl -sS -o /dev/null -w '%{http_code}' '$B/api/summary?token=$TOKEN') = 401 ]"
check "the token unlocks the API (200)" \
  bash -c "[ \$(curl -sS -o '$TMP/s.json' -w '%{http_code}' -H 'X-StockFW-Token: $TOKEN' '$B/api/summary') = 200 ]"
check "a foreign Host header is refused even with the token (DNS rebinding, 403)" \
  bash -c "[ \$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: attacker.example:$DPORT' -H 'X-StockFW-Token: $TOKEN' '$B/api/summary') = 403 ]"
check "localhost:PORT is accepted as a Host" \
  bash -c "[ \$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: localhost:$DPORT' -H 'X-StockFW-Token: $TOKEN' '$B/api/summary') = 200 ]"
check "POST is refused (405): the dashboard is read-only" \
  bash -c "[ \$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'X-StockFW-Token: $TOKEN' '$B/api/summary') = 405 ]"
check "a request head over 16 KB is refused (431), however it is split" py "
import socket
s = socket.create_connection(('127.0.0.1', $DPORT))
s.sendall(b'GET / HTTP/1.1\r\nHost: 127.0.0.1:$DPORT\r\nX: ' + b'a' * 20000 + b'\r\n\r\n')
assert s.recv(64).startswith(b'HTTP/1.1 431'), 'not 431'"
check "a path outside the API is 404, not a file read" \
  bash -c "[ \$(curl -sS --path-as-is -o /dev/null -w '%{http_code}' -H 'X-StockFW-Token: $TOKEN' '$B/../../etc/passwd') = 404 ]"

api () { curl -sS -H "X-StockFW-Token: $TOKEN" "$B/api/$1"; }
check "summary says whether IPv6 is filtered, and logs allowed traffic by default" py "
import json; d = json.load(open('$TMP/s.json'))
assert d['ipv6']['state'] in ('filtered', 'not-filtered', 'absent', 'unknown') and d['ipv6']['detail'], d
assert d['logs_allowed'] is True, d"
check "summary counts the fixture's blocked events and the saved policy" py "
import json; d = json.load(open('$TMP/s.json'))
assert d['blocked_24h'] == 4 and d['blocked_1h'] == 4, d
assert d['policy_saved'] is True and d['rules'] == 2, d"
check "activity: blocked events land in the graph, honest no-data before the log starts" py "
import json, subprocess
d = json.loads(subprocess.run(['curl', '-sS', '-H', 'X-StockFW-Token: $TOKEN', '$B/api/activity?range=3600'],
                              capture_output=True, text=True).stdout)
b, cov = d['events']['blocked'], d['events']['covered']
assert sum(b) == 4, sum(b)
assert cov[0] == 0 and cov[-1] > 0, (cov[:3], cov[-3:])"
check "events: newest first, marker cut, verdict in its own field" py "
import json, subprocess
ev = json.loads(subprocess.run(['curl', '-sS', '-H', 'X-StockFW-Token: $TOKEN', '$B/api/events?limit=10'],
                               capture_output=True, text=True).stdout)
assert [e['port'] for e in ev] == ['443', '3389', '445', '22'], ev
assert ev[3]['service'] == 'SSH' and all(e['blocked'] for e in ev)"
check "simulate over the API answers BLOCKED for the denied host" py "
import json, subprocess, urllib.parse
q = urllib.parse.quote('outbound tcp to 203.0.113.9 port 443')
d = json.loads(subprocess.run(['curl', '-sS', '-H', 'X-StockFW-Token: $TOKEN', '$B/api/simulate?q=' + q],
                              capture_output=True, text=True).stdout)
assert d['verdict'] == 'BLOCKED', d"
check "simulate refuses an over-long question (400)" \
  bash -c "[ \$(curl -sS -o /dev/null -w '%{http_code}' -H 'X-StockFW-Token: $TOKEN' '$B/api/simulate?q=$(printf 'a%.0s' $(seq 1 400))') = 400 ]"
check "the dashboard's own sockets are not listed as connections" py "
import json, subprocess
c = json.loads(subprocess.run(['curl', '-sS', '-H', 'X-StockFW-Token: $TOKEN', '$B/api/connections'],
                              capture_output=True, text=True).stdout)
assert not [x for x in c if x['port'] == '$DPORT' and x['remote'].startswith('127.')], c"
check "every JSON endpoint parses" py "
import json, subprocess
for p in ('summary', 'activity?range=900', 'activity?range=86400', 'events', 'connections', 'interfaces', 'policy'):
    out = subprocess.run(['curl', '-sS', '-H', 'X-StockFW-Token: $TOKEN', '$B/api/' + p], capture_output=True, text=True).stdout
    json.loads(out)"

kill "$DASH_PID" 2>/dev/null; wait "$DASH_PID" 2>/dev/null; DASH_PID=""
check "a second dashboard on a busy port fails cleanly (exit 1)" py "
import socket, subprocess
s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(1)
p = s.getsockname()[1]
r = subprocess.run(['$S', 'dashboard', '--no-open', '--port', str(p)], capture_output=True, text=True, timeout=10)
assert r.returncode == 1 and 'error' in r.stderr, (r.returncode, r.stderr)"

echo ""
if [ "$fails" -eq 0 ]; then
  echo "PASSED: 0 failure(s)"
else
  echo "FAILED: $fails failure(s)"
fi
exit "$fails"
