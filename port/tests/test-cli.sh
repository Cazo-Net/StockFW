#!/bin/bash
# The `stockfw' command-line tool and its local dashboard, end to end.
#
# Builds the real binary through CMake, then drives it the way a user
# (or a script) would: the exit codes `stockfw help' documents, the
# policy files the desktop app shares, the simulator's verdicts, the
# kernel-log history, every --json document parsed back, and the
# dashboard's security model -- 127.0.0.1 only, a per-run token,
# DNS-rebinding defence, GET/HEAD only, a capped request head and a
# nonce-locked CSP.  `stockfw intel' too, as far as it goes without the
# kernel: feeds with licence and credit, consent, local lists,
# exceptions, lookups and their exit codes, the `intel' object of
# `status', and the dashboard's read-only blocklist panel
# (tests/test-intel-cli.sh does apply, clear and update in a private
# namespace).
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
INTEL_BASE=""
cleanup () {
  [ -n "$DASH_PID" ] && kill "$DASH_PID" 2>/dev/null
  rm -rf "$TMP"
  [ -n "$INTEL_BASE" ] && rm -rf "$INTEL_BASE"
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
# --assume-running: these ask about the policy, whatever state the
# firewall of the machine running the suite is in.
check "simulate: SSH from anywhere is ALLOWED (exit 0)" \
  rc_is 0 "$S" simulate --assume-running inbound ssh from 198.51.100.4
check "simulate: the denied host is BLOCKED (exit 5)" \
  rc_is 5 "$S" simulate --assume-running outbound tcp to 203.0.113.9 port 443
check "simulate: a question the policy splits is DEPENDS (exit 6), never 0" \
  rc_is 6 "$S" simulate --assume-running outbound tcp port 443
check "simulate --json names the verdict and the matching rule" py "
import json, subprocess
out = subprocess.run(['$S', '--json', 'simulate', '--assume-running',
                      'outbound tcp to 203.0.113.9 port 443'],
                     capture_output=True, text=True).stdout
d = json.loads(out)
assert d['verdict'] == 'BLOCKED' and '203.0.113.9' in d['rule'], d
a = d['answers'][0]
assert a['origin'] == 'policy' and a['policy_kind'] is not None, a
assert [t for t in a['trace'] if t['decides']][0]['rule'] == d['rule'], a"
check "simulate --json spells out the split of a DEPENDS answer" py "
import json, subprocess
d = json.loads(subprocess.run(['$S', '--json', 'simulate', '--assume-running',
                               'outbound tcp port 443'],
                              capture_output=True, text=True).stdout)
c = d['answers'][0]['cases']
assert d['verdict'] == 'DEPENDS' and len(c) == 2, d
assert c[0]['verdict'] == 'ALLOWED' and c[1]['verdict'] == 'BLOCKED', c
assert '203.0.113.9' in c[1]['condition'], c"
check "simulate: a line with nothing recognisable is a usage error, not a guess" \
  bash -c "! '$S' simulate hello there 2> '$TMP/err' && grep -q 'could not find' '$TMP/err'"
check "simulate: port 0 is refused" rc_is 2 "$S" simulate inbound tcp port 0
check "simulate with no description is a usage error" rc_is 2 "$S" simulate
if [ "$(id -u)" = 0 ] && command -v iptables > /dev/null 2>&1 &&
   unshare -n true 2> /dev/null; then
  # A network namespace of its own: no StockFW chains, so the firewall
  # reads as stopped -- and the answer must say what that means.
  check "simulate with the firewall stopped: ALLOWED, and what it is once running" py "
import json, subprocess
d = json.loads(subprocess.run(['unshare', '-n', '$S', '--json', 'simulate',
                               'outbound tcp to 203.0.113.9 port 443'],
                              capture_output=True, text=True).stdout)
assert d['verdict'] == 'ALLOWED' and d['answers'][0]['origin'] == 'stopped', d
assert d['notes'][0].startswith('Once the firewall runs: BLOCKED'), d['notes']"
fi

# --------------------------------------------------------- copilot health
# A policy of its own, so the findings are exactly the ones planted.
# The machine is fixed too: the local network a narrowing uses
# (STOCKFW_LAN_PREFIX) and this computer's own addresses
# (STOCKFW_LOCAL_ADDRESSES, one on that network).  Every private
# address of the computer is a LAN the fix must keep reachable, so with
# the real adapters a CI runner's 10.1.0.x would decide the answer.
# It must write nothing.
CP_RULES="$TMP/rules-cp"
mkdir -p "$CP_RULES"
CP_ENV="STOCKFW_RULES_DIR='$CP_RULES' STOCKFW_LAN_PREFIX=192.168.1.0/24 STOCKFW_LOCAL_ADDRESSES=192.168.1.5"
cp_run () { STOCKFW_RULES_DIR="$CP_RULES" STOCKFW_LAN_PREFIX=192.168.1.0/24 \
            STOCKFW_LOCAL_ADDRESSES=192.168.1.5 "$@"; }
cp_snap () { (cd "$CP_RULES" && find . -type f -exec md5sum {} + | sort; stat -c '%n %y' .; ls -lA --time-style=full-iso -R .) > "$1"; }
# cp_json_at <local addresses> <python>: runs `stockfw --json copilot
# health' in the fixed environment with those addresses as this
# computer's, then the python on r (the process) and d (the document);
# a failed check prints the document it read.  cp_json: on the LAN only.
cp_json_at () { py "
import json, os, subprocess, sys
env = dict(os.environ, STOCKFW_RULES_DIR='$CP_RULES',
           STOCKFW_LAN_PREFIX='192.168.1.0/24',
           STOCKFW_LOCAL_ADDRESSES='$1')
r = subprocess.run(['$S', '--json', 'copilot', 'health'], env=env,
                   capture_output=True, text=True)
try:
    d = json.loads(r.stdout)
$(printf '%s\n' "$2" | sed 's/^/    /')
except Exception:
    print('--- stockfw --json copilot health (exit %d) printed:' % r.returncode, file=sys.stderr)
    print(r.stdout + r.stderr, file=sys.stderr)
    raise"; }
cp_json () { cp_json_at 192.168.1.5 "$1"; }

check "help lists copilot" bash -c "'$S' help | grep -q 'copilot health'"
check "copilot with no subcommand is a usage error (exit 2)" rc_is 2 "$S" copilot
check "copilot health with a stray argument is a usage error (exit 2)" \
  rc_is 2 "$S" copilot health now
check "copilot health on an empty policy: no findings (exit 0)" \
  rc_is 0 cp_run "$S" copilot health
check "  ...and --json says so" cp_json "
assert d['version'] == 1 and d['findings'] == [] and d['policy_rules'] == 0, d"
cp_run "$S" policy add inbound-allow-service RDP 3389 Anyone > /dev/null
cp_snap "$TMP/cp-before"
check "copilot health with RDP open to anyone: findings (exit 7)" \
  rc_is 7 cp_run "$S" copilot health
check "  ...--json parses: risky_open, critical, a verified narrowing" cp_json "
assert r.returncode == 7, r.returncode
f = [x for x in d['findings'] if x['kind'] == 'risky_open']
assert len(f) == 1, d
f = f[0]
assert f['severity'] == 'critical' and f['rule']['csv'] == 'RDP, 3389, Anyone', f
assert f['rule']['kind'] == 'inbound_allow_service' and f['rule']['index'] == 0, f
fx = f['fix']
assert fx is not None, f
assert fx['verified'] and fx['after'] == 'RDP, 3389, 192.168.1.0/24', fx
outside = [c for c in fx['checks'] if '203.0.113.10' in c['probe']]
assert outside and outside[0]['before'] == 'ALLOWED' and outside[0]['after'] == 'BLOCKED', fx
lan = [c for c in fx['checks'] if '192.168.1.20' in c['probe']]
assert lan and all(c['before'] == c['after'] for c in lan), fx"
check "  ...the text output names the fix and says nothing was written" \
  bash -c "$CP_ENV '$S' copilot health > '$TMP/cp-text';
           grep -q 'fix:   Narrow to 192.168.1.0/24' '$TMP/cp-text' &&
           grep -q 'nothing was written' '$TMP/cp-text' ||
           { cat '$TMP/cp-text' >&2; false; }"
# A computer on two private networks (a CI runner's 10.1.0.x beside the
# LAN): narrowing to one would cut the other off, so no fix is offered,
# and the checks the reason points to are printed.
check "  ...on a second private network no narrowing is offered, and the failed check is shown" \
  cp_json_at 192.168.1.5,10.1.0.42 "
f = [x for x in d['findings'] if x['kind'] == 'risky_open'][0]
assert f['fix'] is None and 'did not give the promised' in f['no_fix_reason'], f
t = f['tried']
assert t['after'] == 'RDP, 3389, 192.168.1.0/24', t
other = [c for c in t['checks'] if '10.1.0.20' in c['probe']]
assert other and other[0]['before'] == 'ALLOWED' and other[0]['after'] == 'BLOCKED', t"
check "  ...and the text output lists that check under the reason" \
  bash -c "STOCKFW_RULES_DIR='$CP_RULES' STOCKFW_LAN_PREFIX=192.168.1.0/24 STOCKFW_LOCAL_ADDRESSES=192.168.1.5,10.1.0.42 '$S' copilot health > '$TMP/cp-text2';
           grep -q 'no fix offered' '$TMP/cp-text2' &&
           grep -q 'checked: Inbound TCP port 3389 from 10.1.0.20: ALLOWED -> BLOCKED' '$TMP/cp-text2' ||
           { cat '$TMP/cp-text2' >&2; false; }"
cp_snap "$TMP/cp-after"
check "copilot health writes nothing (rules files and their times unchanged)" \
  cmp -s "$TMP/cp-before" "$TMP/cp-after"
check "copilot health in text mode shows the word for the severity" \
  bash -c "$CP_ENV '$S' copilot health | grep -q '^\[critical\] RDP (3389) is open to the internet'"

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

# --------------------------------------------------------- threat intel
# The store must pass the engine's ownership check (no parent writable
# by others), which /tmp never does: try the home directory, then the
# build directory.
export STOCKFW_AUDIT_FILE="$TMP/audit.log"
for base in "$HOME" "$BUILD"; do
  [ -d "$base" ] || continue
  cand="$(mktemp -d "$base/sfw-cli-intel-XXXXXX" 2>/dev/null)" || continue
  chmod 700 "$cand"
  if STOCKFW_INTEL_DIR="$cand/probe" "$S" -q intel on > /dev/null 2>&1; then
    INTEL_BASE="$cand"
    break
  fi
  rm -rf "$cand"
done

check "help lists intel, and intel has its own help" \
  bash -c "'$S' help | grep -q '^  intel ' && '$S' help intel | grep -q 'accept-terms'"
if [ -n "$INTEL_BASE" ]; then
  export STOCKFW_INTEL_DIR="$INTEL_BASE/intel"
  icode () { "$S" "$@" > "$TMP/iout" 2> "$TMP/ierr"; echo $?; }
  export S TMP; export -f icode

  check "intel feeds lists the catalog without creating the store" py "
import json, os, subprocess
r = subprocess.run(['$S', '--json', 'intel', 'feeds'], capture_output=True, text=True)
d = json.loads(r.stdout)
f = {x['id']: x for x in d['feeds']}
assert r.returncode == 0 and len(f) == 9, (r.returncode, list(f))
assert all(x['credit'] and x['terms_url'] for x in f.values())
assert f['dshield']['noncommercial'] and f['dshield']['licence'] == 'CC BY-NC-SA 2.5'
assert f['spamhaus-drop']['licence'] is None and 'Spamhaus' in f['spamhaus-drop']['credit']
assert not os.path.exists('$STOCKFW_INTEL_DIR'), 'store created'"
  check "  ...and as a table, with LICENCE and CREDIT columns" \
    bash -c "'$S' intel feeds | head -1 | grep -q 'LICENCE *CREDIT\$'"
  check "intel status --json without a store: off" py "
import json, subprocess
d = json.loads(subprocess.run(['$S', '--json', 'intel', 'status'], capture_output=True, text=True).stdout)
assert d['state'] == 'off' and d['lists'] == [], d"
  check "enable without --accept-terms is refused (exit 2) and shows the terms" \
    bash -c "[ \$(icode intel enable feodo) = 2 ] && grep -q 'feodotracker.abuse.ch' '$TMP/iout' && grep -q -- '--accept-terms' '$TMP/ierr'"
  check "  ...and leaves the feed off" py "
import json, subprocess
d = json.loads(subprocess.run(['$S', '--json', 'intel', 'feeds'], capture_output=True, text=True).stdout)
assert not [x for x in d['feeds'] if x['id'] == 'feodo'][0]['enabled']"
  check "enable with --accept-terms turns it on (exit 0)" \
    bash -c "[ \$(icode intel enable feodo --accept-terms) = 0 ] && grep -q 'Feodo Tracker turned on (both' '$TMP/iout'"
  check "an unknown feed is a usage error (exit 2)" \
    bash -c "[ \$(icode intel enable no-such-feed --accept-terms) = 2 ]"
  printf '203.0.113.50\n198.51.100.0/28\n' > "$TMP/mine.txt"
  check "import a local list" \
    bash -c "[ \$(icode intel import '$TMP/mine.txt' --name 'CLI list') = 0 ] && grep -q 'CLI list (local-cli-list): 2 entries, both' '$TMP/iout'"
  check "except: an address the list holds" \
    bash -c "[ \$(icode intel except 198.51.100.5) = 0 ]"
  # Nothing was applied here: the list would block it, the kernel does
  # not, so the answer is "not blocked now" (exit 0), never exit 5.
  check "lookup: a listed address names the list, but nothing is in force: exit 0, in_force false" py "
import json, subprocess
r = subprocess.run(['$S', '--json', 'intel', 'lookup', '203.0.113.50'], capture_output=True, text=True)
d = json.loads(r.stdout)
assert r.returncode == 0 and d['blocked'] and not d['in_force'] and d['state'] != 'enforced' and d['in_force_lists'] == [] and d['lists'] == [{'id': 'local-cli-list', 'name': 'CLI list'}], (r.returncode, d)"
  check "lookup (text): LISTED, NOT BLOCKED NOW, with why" \
    bash -c "'$S' intel lookup 203.0.113.50 | grep -q 'LISTED, NOT BLOCKED NOW.*CLI list'"
  check "lookup: the exception is listed but not blocked (exit 0)" py "
import json, subprocess
r = subprocess.run(['$S', '--json', 'intel', 'lookup', '198.51.100.5'], capture_output=True, text=True)
d = json.loads(r.stdout)
assert r.returncode == 0 and not d['blocked'] and d['exception'] and len(d['lists']) == 1, (r.returncode, d)"
  check "lookup: not an address is a usage error (exit 2)" \
    bash -c "[ \$(icode intel lookup nonsense) = 2 ]"
  # A list's blocks in the event history, as the backend's live feed
  # shows them: only for an id of the applied rule set (here a record
  # written by hand), named after the list, in a RULE column / "rule".
  py "
import datetime, os
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
def at(m): return (now - datetime.timedelta(minutes=m)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
open('$TMP/ti.log', 'w').write('\\n'.join([
 at(3) + ' host kernel: [1.0] STOCKFW-DROP IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=40000 DPT=22 SYN',
 at(2) + ' host kernel: [2.0] STOCKFW-TI local-cli-list IN=eth0 OUT= SRC=203.0.113.50 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=40001 DPT=22 SYN',
 at(1) + ' host kernel: [3.0] STOCKFW-TI feodo IN=eth0 OUT= SRC=203.0.113.51 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=40002 DPT=22 SYN',
]) + '\\n')
fd = os.open('$STOCKFW_INTEL_DIR/applied.state', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, b'[applied]\\ndigest=0123456789abcdef0123456789abcdef\\napplied-at=1\\nsuspended=false\\ncount4=1\\ncount6=0\\nsets=local-cli-list;\\nruled=local-cli-list;\\n')
os.close(fd)
"
  check "events: a list's block is in the history, with its rule; a set not applied is not" py "
import json, os, subprocess
env = dict(os.environ, STOCKFW_LOG_FILE='$TMP/ti.log')
ev = json.loads(subprocess.run(['$S', '--json', 'events', '-n', '50'], capture_output=True, text=True, env=env).stdout)
assert [(e['source'], e['blocked'], e['rule']) for e in ev] == [('203.0.113.5', True, None), ('203.0.113.50', True, 'Threat intel: CLI list')], ev"
  check "events (table): a RULE column names the list" \
    bash -c "STOCKFW_LOG_FILE='$TMP/ti.log' '$S' events -n 50 | head -1 | grep -q 'PROTO *RULE' && STOCKFW_LOG_FILE='$TMP/ti.log' '$S' events -n 50 | grep -q '203.0.113.50.*Threat intel: CLI list'"
  rm -f "$STOCKFW_INTEL_DIR/applied.state"
  check "intel proxy: one with a password is refused (exit 2), none is saved" \
    bash -c "[ \$(icode intel proxy http://u:p@proxy.example:3128) = 2 ] && ! grep -q proxy= '$STOCKFW_INTEL_DIR/intel.conf'"
  check "intel proxy URL: saved, and status shows it" py "
import json, subprocess
r = subprocess.run(['$S', '--json', 'intel', 'proxy', 'http://proxy.example:3128'], capture_output=True, text=True)
assert r.returncode == 0 and json.loads(r.stdout)['proxy'] == 'http://proxy.example:3128', r
d = json.loads(subprocess.run(['$S', '--json', 'intel', 'status'], capture_output=True, text=True).stdout)
assert d['proxy'] == 'http://proxy.example:3128', d
t = subprocess.run(['$S', 'intel', 'status'], capture_output=True, text=True).stdout
assert 'Proxy        http://proxy.example:3128' in t, t"
  check "intel proxy none: removed" py "
import json, subprocess
r = subprocess.run(['$S', '--json', 'intel', 'proxy', 'none'], capture_output=True, text=True)
assert r.returncode == 0 and json.loads(r.stdout)['proxy'] is None, r
assert 'proxy=' not in open('$STOCKFW_INTEL_DIR/intel.conf').read()"
  check "status --json carries an intel object" py "
import json, subprocess
d = json.loads(subprocess.run(['$S', '--json', 'status'], capture_output=True, text=True).stdout)
i = d['intel']
assert i['state'] in ('not-loaded', 'needs-root', 'unknown', 'differs') and i['detail'], i"
  check "status has a Threat intel line" \
    bash -c "'$S' status | grep -qE '^  Threat intel +[a-z-]+'"
  # Changing the kernel needs root; as root, ask as nobody.
  if [ "$(id -u)" = 0 ]; then
    as_user () { setpriv --reuid=65534 --regid=65534 --clear-groups "$@"; }
  else
    as_user () { "$@"; }
  fi
  if [ "$(id -u)" != 0 ] || command -v setpriv > /dev/null; then
    needs_root () {
      as_user "$S" intel apply > /dev/null 2>&1; local a=$?
      as_user "$S" intel clear > /dev/null 2>&1; local c=$?
      [ "$a" = 3 ] && [ "$c" = 3 ]
    }
    check "intel apply and clear need root (exit 3)" needs_root
  fi
  # Countries and networks: without the database's consent nothing is
  # saved; with it a rule is kept, and the status reads it back.  No
  # download here (test-intel-cli.sh downloads the test databases).
  check "intel geo: the status, with the \"registered in\" sentence" \
    bash -c "[ \$(icode intel geo) = 0 ] && grep -q '^  Location ' '$TMP/iout' && grep -q 'registered, not where a computer is' '$TMP/iout'"
  check "intel geo on without --accept-terms: exit 2, the terms name location.ipfire.org" \
    bash -c "[ \$(icode intel geo on) = 2 ] && grep -q 'location.ipfire.org' '$TMP/iout' && grep -q -- '--accept-terms' '$TMP/ierr' && '$S' --json intel geo status | grep -q '\"terms_accepted_at\":null'"
  check "intel geo add before consent: exit 2, nothing saved" \
    bash -c "[ \$(icode intel geo add country DE) = 2 ] && ! grep -qi 'country-' '$STOCKFW_INTEL_DIR/intel.conf'"
  check "intel geo search with no database: exit 1" \
    bash -c "[ \$(icode intel geo search Example) = 1 ] && grep -q 'not been downloaded' '$TMP/ierr'"
  check "intel geo on --accept-terms, then add country DE --dir in: a rule, no database yet" py "
import json, subprocess
r = subprocess.run(['$S', '--json', 'intel', 'geo', 'on', '--accept-terms'], capture_output=True, text=True)
assert r.returncode == 0 and json.loads(r.stdout)['terms_accepted_now'], r
r = subprocess.run(['$S', '--json', 'intel', 'geo', 'add', 'country', 'de', '--dir', 'in'], capture_output=True, text=True)
d = json.loads(r.stdout)
assert r.returncode == 0 and d['id'] == 'country-de' and d['values'] == ['DE'] and d['direction'] == 'in', (r, d)
d = json.loads(subprocess.run(['$S', '--json', 'intel', 'geo', 'list'], capture_output=True, text=True).stdout)
assert [(x['id'], x['status']) for x in d['rules']] == [('country-de', 'no-database')], d"
  check "intel status --json carries the location object" py "
import json, subprocess
d = json.loads(subprocess.run(['$S', '--json', 'intel', 'status'], capture_output=True, text=True).stdout)
g = d['location']
assert g['supported'] and g['enabled'] and not g['database']['present'] and g['url'].startswith('https://location.ipfire.org/'), g
assert 'IPFire' in g['attribution'] and [x['id'] for x in g['rules']] == ['country-de'], g"
  check "intel lookup with the database on and no copy: \"registered in\" unknown, exit 0" py "
import json, subprocess
r = subprocess.run(['$S', '--json', 'intel', 'lookup', '192.0.2.1'], capture_output=True, text=True)
d = json.loads(r.stdout)
assert r.returncode == 0 and d['location']['found'] is False and d['location']['why_none'], (r.returncode, d)"
  check "intel apply --dry-run names the sets and changes nothing" \
    bash -c "'$S' intel apply --dry-run > '$TMP/dry.txt' && grep -q '^  local-cli-list  *both' '$TMP/dry.txt' && grep -q 'Nothing was changed' '$TMP/dry.txt'"
else
  echo "skip: threat intel (no directory here passes the store's ownership check)"
fi

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
d = json.loads(subprocess.run(['curl', '-sS', '-H', 'X-StockFW-Token: $TOKEN',
                               '$B/api/simulate?assume_running=1&q=' + q],
                              capture_output=True, text=True).stdout)
assert d['verdict'] == 'BLOCKED', d"
check "simulate over the API answers DEPENDS for a split question" py "
import json, subprocess, urllib.parse
q = urllib.parse.quote('outbound tcp port 443')
d = json.loads(subprocess.run(['curl', '-sS', '-H', 'X-StockFW-Token: $TOKEN',
                               '$B/api/simulate?assume_running=1&q=' + q],
                              capture_output=True, text=True).stdout)
assert d['verdict'] == 'DEPENDS', d"
check "simulate over the API refuses an unreadable line (400)" \
  bash -c "[ \$(curl -sS -o /dev/null -w '%{http_code}' -H 'X-StockFW-Token: $TOKEN' '$B/api/simulate?q=hello') = 400 ]"
check "simulate refuses an over-long question (400)" \
  bash -c "[ \$(curl -sS -o /dev/null -w '%{http_code}' -H 'X-StockFW-Token: $TOKEN' '$B/api/simulate?q=$(printf 'a%.0s' $(seq 1 400))') = 400 ]"
if [ -n "$INTEL_BASE" ]; then
  check "intel: the API needs the token (401)" \
    bash -c "[ \$(curl -sS -o /dev/null -w '%{http_code}' '$B/api/intel') = 401 ]"
  check "intel: the state and the lists turned on, with licence and credit" py "
import json, subprocess
d = json.loads(subprocess.run(['curl', '-sS', '-H', 'X-StockFW-Token: $TOKEN', '$B/api/intel'],
                              capture_output=True, text=True).stdout)
assert d['state'] in ('not-loaded', 'needs-root', 'unknown', 'differs') and d['detail'], d
by = {l['id']: l for l in d['lists']}
assert set(by) == {'feodo', 'local-cli-list'}, by.keys()
assert by['feodo']['licence'] == 'CC0' and 'abuse.ch' in by['feodo']['credit']
assert by['local-cli-list']['name'] == 'CLI list' and by['local-cli-list']['entries'] == 2"
  check "intel: the location fields, read-only (rules, database, attribution)" py "
import json, subprocess
d = json.loads(subprocess.run(['curl', '-sS', '-H', 'X-StockFW-Token: $TOKEN', '$B/api/intel'],
                              capture_output=True, text=True).stdout)
g = d['location']
assert g['enabled'] and g['database']['present'] is False and 'IPFire' in g['attribution'], g
assert [(x['id'], x['direction'], x['status']) for x in g['rules']] == [('country-de', 'in', 'no-database')], g"
  check "intel: POST is refused (405): the panel is read-only" \
    bash -c "[ \$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'X-StockFW-Token: $TOKEN' '$B/api/intel') = 405 ]"
  check "the page has the blocklist panel and asks for /api/intel" \
    bash -c "grep -q 'id=\"h-intel\"' '$TMP/page.html' && grep -q '/api/intel' '$TMP/page.html'"
fi
check "the dashboard's own sockets are not listed as connections" py "
import json, subprocess
c = json.loads(subprocess.run(['curl', '-sS', '-H', 'X-StockFW-Token: $TOKEN', '$B/api/connections'],
                              capture_output=True, text=True).stdout)
assert not [x for x in c if x['port'] == '$DPORT' and x['remote'].startswith('127.')], c"
check "every JSON endpoint parses" py "
import json, subprocess
for p in ('summary', 'activity?range=900', 'activity?range=86400', 'events', 'connections', 'interfaces', 'policy', 'intel'):
    out = subprocess.run(['curl', '-sS', '-H', 'X-StockFW-Token: $TOKEN', '$B/api/' + p], capture_output=True, text=True).stdout
    json.loads(out)"

kill "$DASH_PID" 2>/dev/null; wait "$DASH_PID" 2>/dev/null; DASH_PID=""

# The browser is opened on a 0600 page that redirects to the URL, never
# with the token in an argument list, where any local account could read
# it from /proc/<pid>/cmdline (1.0.7 release review, SECURITY-3).  The
# dashboard never starts a browser as root, so as root this part runs
# as nobody, from a copy of the binary nobody can reach.
OD="$(mktemp -d /tmp/stockfw-open-XXXXXX)"; chmod 755 "$OD"
mkdir -p "$OD/bin" "$OD/run" "$OD/seen"
cp "$S" "$OD/stockfw"
cat > "$OD/bin/xdg-open" <<'XEOF'
#!/bin/sh
d="$(dirname "$0")/../seen"
tr '\0' '\n' < /proc/$$/cmdline > "$d/cmdline"
stat -c '%a' "$1" > "$d/mode"
stat -c '%a' "$(dirname "$1")" > "$d/dirmode"
cp "$1" "$d/page.html"
printf '%s\n' "$1" > "$d/argv"
XEOF
chmod 755 "$OD/bin/xdg-open"
chmod 700 "$OD/run"
AS=""
if [ "$(id -u)" = 0 ]; then
  chown 65534:65534 "$OD/run" "$OD/seen"
  AS="setpriv --reuid=65534 --regid=65534 --clear-groups"
fi
OPORT=$(py 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
$AS env -i PATH="$OD/bin:/usr/bin:/bin" DISPLAY=:99 XDG_RUNTIME_DIR="$OD/run" \
  HOME="$OD/run" XDG_CONFIG_HOME="$OD/run/cfg" STOCKFW_RULES_DIR="$OD/run/rules" \
  "$OD/stockfw" dashboard --port "$OPORT" > "$OD/out" 2>&1 &
DASH_PID=$!
for _ in $(seq 1 50); do [ -s "$OD/seen/argv" ] && break; sleep 0.1; done
OURL=$(grep -o 'http://[^ ]*' "$OD/out" | head -1)
OTOKEN=${OURL##*#token=}
OPAGE=$(cat "$OD/seen/argv" 2>/dev/null)
check "dashboard: the terminal still prints the whole URL with the token" \
  bash -c "[[ '$OTOKEN' =~ ^[0-9a-f]{32}$ ]]"
check "  ...xdg-open was started on a page under \$XDG_RUNTIME_DIR ($OPAGE)" \
  bash -c "[[ '$OPAGE' == '$OD/run/stockfw-dashboard-'*/open.html ]]"
check "  ...and the token is in no argument xdg-open got" \
  bash -c "[ -s '$OD/seen/cmdline' ] && ! grep -q '$OTOKEN' '$OD/seen/cmdline'"
check "  ...the page is 0600 in a 0700 directory" \
  bash -c "[ \"\$(cat '$OD/seen/mode')\" = 600 ] && [ \"\$(cat '$OD/seen/dirmode')\" = 700 ]"
check "  ...and sends the browser on to the URL with the token" \
  bash -c "grep -qF 'location.replace(\"$OURL\")' '$OD/seen/page.html' && grep -qF 'url=$OURL\"' '$OD/seen/page.html'"
check "  ...and the terminal says to open the URL if the browser cannot read the page" \
  bash -c "grep -q 'A browser was started' '$OD/out' && grep -q 'open the URL' '$OD/out'"
check "  ...it stays until the token is used" bash -c "[ -f '$OPAGE' ]"
curl -sS -o /dev/null -H "X-StockFW-Token: $OTOKEN" "http://127.0.0.1:$OPORT/api/summary"
check "  ...and is removed, with its directory, once it is" \
  bash -c "[ ! -e '$OPAGE' ] && [ ! -e \"\$(dirname '$OPAGE')\" ]"
kill "$DASH_PID" 2>/dev/null; wait "$DASH_PID" 2>/dev/null; DASH_PID=""
check "  ...and nothing is left in the runtime directory when it stops" \
  bash -c "[ -z \"\$(ls -A '$OD/run' | grep stockfw-dashboard)\" ]"
rm -rf "$OD"

check "a second dashboard on a busy port fails cleanly (exit 1)" py "
import socket, subprocess
s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(1)
p = s.getsockname()[1]
r = subprocess.run(['$S', 'dashboard', '--no-open', '--port', str(p)], capture_output=True, text=True, timeout=10)
assert r.returncode == 1 and 'error' in r.stderr, (r.returncode, r.stderr)"

# Each work package of the next release keeps its tests between its
# own markers (cli-plan.md section 4), so the packages never touch one
# another's lines.

# === WP-A ===
# The parser and the output helpers (cli-plan.md section 4, WP-A).
# A rules directory of its own, readable by nobody (the hints below
# are checked as uid 65534 when the suite runs as root).
A="$(mktemp -d /tmp/stockfw-wpa-XXXXXX)"; chmod 755 "$A"
A_ENV=(env STOCKFW_RULES_DIR="$A/rules" STOCKFW_LOG_FILE="$A/kern.log")
a_run () { "${A_ENV[@]}" "$@"; }
a_rc () { local want="$1"; shift; a_run "$@" > "$TMP/out" 2> "$TMP/err"; [ "$?" -eq "$want" ]; }
if [ "$(id -u)" = 0 ] && command -v setpriv > /dev/null; then
  a_nobody () { setpriv --reuid=65534 --regid=65534 --clear-groups "${A_ENV[@]}" "$@"; }
else
  a_nobody () { a_run "$@"; }
fi
# Kernel-log lines with IPv6 addresses written out in full, as some
# loggers print them: the table must show them short and still fit.
py "
import datetime
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
def at(m): return (now - datetime.timedelta(minutes=m)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
open('$A/kern.log', 'w').write('\n'.join([
 at(3) + ' host kernel: [1.0] STOCKFW-DROP IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=40000 DPT=22 SYN',
 at(2) + ' host kernel: [2.0] STOCKFW-DROP IN=eth0 OUT= SRC=2001:0db8:0000:0000:0000:0000:0000:0042 DST=2001:0db8:0000:0000:0000:0000:0000:0001 LEN=60 TC=0 HOPLIMIT=64 FLOWLBL=0 PROTO=TCP SPT=40001 DPT=3389 SYN',
 at(1) + ' host kernel: [3.0] STOCKFW-DROP IN=eth0 OUT= SRC=198.51.100.70 DST=10.0.0.5 LEN=40 PROTO=TCP SPT=40002 DPT=445 SYN',
]) + '\n')
"
a_run "$S" policy add inbound-allow-service SSH 22 Anyone > /dev/null
chmod -R a+rX "$A"

a_comment_h () { a_rc 0 "$S" policy add outbound-deny-to 198.51.100.6 --comment -h &&
                 ! grep -q '^Usage' "$TMP/out"; }
check "parser: --comment -h saves the comment \"-h\" (exit 0), it is not a request for help" a_comment_h
check "  ...and policy list --json shows comment \"-h\"" py "
import json, os, subprocess
env = dict(os.environ, STOCKFW_RULES_DIR='$A/rules')
d = json.loads(subprocess.run(['$S', '--json', 'policy', 'list'], capture_output=True, text=True, env=env).stdout)
assert [r['comment'] for r in d['rules'] if r['target'] == '198.51.100.6'] == ['-h'], d"
check "parser: --comment --json and --comment=-x are both saved as comments" py "
import json, os, subprocess
env = dict(os.environ, STOCKFW_RULES_DIR='$A/rules')
for args in (['198.51.100.7', '--comment', '--json'], ['198.51.100.8', '--comment=-x']):
    r = subprocess.run(['$S', 'policy', 'add', 'outbound-deny-to', *args], capture_output=True, text=True, env=env)
    assert r.returncode == 0 and r.stdout.startswith('+ '), (args, r)
d = json.loads(subprocess.run(['$S', '--json', 'policy', 'list'], capture_output=True, text=True, env=env).stdout)
c = {r['target']: r['comment'] for r in d['rules']}
assert c.get('198.51.100.7') == '--json' and c.get('198.51.100.8') == '-x', c"
a_dashdash () { a_rc 2 "$S" policy add outbound-deny-to -- -x &&
                grep -q 'not a valid address' "$TMP/err" && ! grep -q 'unknown option' "$TMP/err"; }
check "parser: after --, \"-x\" is a field: \"not a valid address\" (exit 2), not \"unknown option\"" a_dashdash
a_needs_value () { a_rc 2 "$S" policy list --kind && grep -q -- '--kind needs a value' "$TMP/err" &&
                   a_rc 2 "$S" dashboard --port && grep -q -- '--port needs a value' "$TMP/err"; }
check "parser: an option with no value says it needs one (policy list --kind, dashboard --port: exit 2)" a_needs_value
a_typo_opt () { a_rc 2 "$S" simulate --assume-runing inbound ssh &&
                grep -q 'did you mean --assume-running' "$TMP/err"; }
check "parser: simulate --assume-runing is refused with \"did you mean\" (exit 2), not folded into the question" a_typo_opt
check "  ...and simulate --assume-running -- \"inbound ssh\" answers (ALLOWED, exit 0)" \
  a_rc 0 "$S" simulate --assume-running -- "inbound ssh from 198.51.100.4"
check "parser: -q simulate prints the verdict word alone" \
  bash -c "[ \"\$(STOCKFW_RULES_DIR='$A/rules' '$S' -q simulate --assume-running inbound ssh from 198.51.100.4)\" = ALLOWED ]"
check "parser: \`stauts' gives \"did you mean \`stockfw status'\" (exit 2) and runs nothing" \
  bash -c "STOCKFW_RULES_DIR='$A/rules' STOCKFW_LOG_FILE='$A/missing.log' '$S' stauts > '$TMP/out' 2> '$TMP/err'; [ \$? -eq 2 ] &&
           grep -q \"did you mean \\\`stockfw status'\" '$TMP/err' && [ ! -s '$TMP/out' ] && ! grep -q 'Firewall' '$TMP/err'"
a_frob () { a_rc 2 "$S" --frob status && grep -q 'unknown option --frob' "$TMP/err" &&
            ! grep -q 'unknown command' "$TMP/err"; }
check "parser: --frob before a command is an unknown option, not an unknown command" a_frob
check "help: \`help help', \`help version' and \`help intel geo' exit 0" \
  bash -c "'$S' help help > /dev/null && '$S' help version > /dev/null && '$S' help intel geo | grep -q 'intel geo search'"
check "version: one line, \"stockfw N <sep> backend\", no nested brackets" \
  bash -c "'$S' version | grep -Eq '^stockfw [0-9.]+ (·|-) [^(]+\\(' && ! '$S' version | grep -q '(.*(.*))'"
check "output: the comment's ESC and U+202E are printed escaped, never raw" \
  bash -c "STOCKFW_RULES_DIR='$A/rules' '$S' policy add outbound-deny-to 198.51.100.9 --comment \"\$(printf 'a\\033[31mred\\342\\200\\256X')\" > /dev/null &&
           STOCKFW_RULES_DIR='$A/rules' '$S' policy list > '$TMP/esc.txt' &&
           grep -qF 'a\\x1b[31mred\\u202eX' '$TMP/esc.txt' &&
           ! grep -q \$'\\033' '$TMP/esc.txt' && ! grep -q \$'\\342\\200\\256' '$TMP/esc.txt'"
a_root_hint () { a_nobody "$S" apply > /dev/null 2> "$TMP/err"; [ "$?" -eq 3 ] &&
                 grep -qF "sudo $S apply'" "$TMP/err" && ! grep -q '`sudo stockfw' "$TMP/err"; }
check "output: a root hint names this program by its full path and repeats the arguments" a_root_hint
check "output: an event table piped gets every character, whatever COLUMNS says" \
  bash -c "COLUMNS=40 STOCKFW_LOG_FILE='$A/kern.log' '$S' events | cat > '$TMP/ev.txt' &&
           grep -q '2001:db8::42' '$TMP/ev.txt' && ! grep -qE '…|\\.\\.\\.' '$TMP/ev.txt'"
check "output: IPv6 addresses are shown short (2001:db8::42, not 2001:0db8:0000:...)" \
  bash -c "STOCKFW_LOG_FILE='$A/kern.log' '$S' events | grep -q '2001:db8::42  *2001:db8::1 '"
check "output: --plain events: no ESC, exactly 8 tabs per row, no header" py "
import os, subprocess
env = dict(os.environ, STOCKFW_LOG_FILE='$A/kern.log', COLUMNS='40')
out = subprocess.run(['script', '-qec', '$S --plain events', '/dev/null'], capture_output=True, env=env).stdout if os.path.exists('/usr/bin/script') else subprocess.run(['$S', '--plain', 'events'], capture_output=True, env=env).stdout
rows = [l for l in out.decode().replace('\r', '').split('\n') if l]
assert b'\x1b' not in out and len(rows) == 3, out
assert all(r.count('\t') == 8 for r in rows) and not rows[0].startswith('TIME'), rows"
check "output: --color=always colours a pipe" \
  bash -c "STOCKFW_LOG_FILE='$A/kern.log' '$S' --color=always events | grep -q \$'\\033\\['"
if [ "$(id -u)" = 0 ] && command -v setpriv > /dev/null || [ "$(id -u)" != 0 ]; then
  check "output: LC_ALL=C status (uid 65534 as root) is ASCII only" py "
import os, subprocess
cmd = ['$S', 'status']
if os.getuid() == 0:
    cmd = ['setpriv', '--reuid=65534', '--regid=65534', '--clear-groups'] + cmd
env = dict(os.environ, LC_ALL='C', STOCKFW_RULES_DIR='$A/rules', STOCKFW_LOG_FILE='$A/kern.log')
r = subprocess.run(cmd, capture_output=True, env=env)
assert r.returncode == 0 and b'Firewall' in r.stdout, r
bad = [l for l in (r.stdout + r.stderr).split(b'\n') if any(c > 127 for c in l)]
assert not bad, bad"
fi
if command -v script > /dev/null; then
  # A terminal of 80 columns (stty inside script: the harness may have
  # none), and the widest line of each output, colour codes taken out.
  a_width () { py "
import os, re, subprocess, sys
env = dict(os.environ, STOCKFW_RULES_DIR='$A/rules', STOCKFW_LOG_FILE='$A/kern.log', COLUMNS='80')
out = subprocess.run(['script', '-qec', 'stty cols 80 rows 24 2>/dev/null; $S $1', '/dev/null'],
                     capture_output=True, env=env).stdout.decode('utf-8', 'replace')
lines = [re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', l.rstrip('\r')) for l in out.split('\n')]
long = [l for l in lines if len(l) > 80]
assert lines and not long, long"; }
  check "output: on an 80-column terminal \`help' fits" a_width "help"
  check "  ...and \`help intel'" a_width "help intel"
  check "  ...and \`events' with IPv6 rows" a_width "events"
  check "  ...and \`intel feeds', the legend included" a_width "intel feeds"
  check "output: colour follows stdout alone: events 2>/dev/null on a terminal is coloured" py "
import os, subprocess
env = dict(os.environ, STOCKFW_LOG_FILE='$A/kern.log')
env.pop('NO_COLOR', None)
out = subprocess.run(['script', '-qec', '$S events 2>/dev/null', '/dev/null'], capture_output=True, env=env).stdout
assert b'\x1b[' in out, out"
else
  echo "skip: 80-column and terminal colour checks (no script(1))"
fi
rm -rf "$A"
# === end WP-A ===

# === WP-B ===
# === end WP-B ===

# === WP-C ===
# status truth, audit and sentinel list (cli-plan.md section 4, WP-C).
# Everything has its own scratch directory, readable by nobody, so the
# checks that matter without root run as uid 65534 when the suite runs
# as root.
C="$(mktemp -d /tmp/stockfw-wpc-XXXXXX)"; chmod 755 "$C"
mkdir -p "$C/rules" "$C/cfg/stockfw"
if [ "$(id -u)" = 0 ] && command -v setpriv > /dev/null; then
  C_AS="['setpriv', '--reuid=65534', '--regid=65534', '--clear-groups']"
else
  C_AS="[]"
fi
# The environment every WP-C check runs in (python: CENV).
C_PRE="
import datetime, hashlib, json, os, subprocess, time
CENV = dict(os.environ, STOCKFW_RULES_DIR='$C/rules', XDG_CONFIG_HOME='$C/cfg',
            STOCKFW_AUDIT_FILE='$C/audit.log', STOCKFW_LOG_FILE='$C/kern.log',
            STOCKFW_EVENTS_DIR='$C/no-history', STOCKFW_AUTOBLOCK_FILE='$C/autoblocks',
            STOCKFW_APPLIED_FILE='$C/applied.csv', STOCKFW_SYSTEMD_DIR='$C/systemd')
def run(*args, nobody=False, env=None):
    pre = $C_AS if nobody else []
    return subprocess.run(pre + ['$S'] + list(args), capture_output=True, text=True, env=env or CENV, timeout=20)
def js(*args, **kw):
    r = run('--json', *args, **kw)
    assert r.returncode == 0, r
    return json.loads(r.stdout)
"
c_py () { py "$C_PRE
$1"; }

# An audit log across midnight UTC with one damaged line, as
# fs_audit_log writes it (the gate's layout was pinned from a real
# apply, start and stop in a private namespace).
cat > "$C/audit.log" <<'AEOF'
2026-11-02T22:00:00Z | policy applied | cli | full | +1 added (1 allow, 0 block), -0 removed (0 allow, 0 block), =0 unchanged
2026-11-02T23:10:00Z | firewall stopped | policy page | stop | stopped
this line is damaged
2026-11-02T23:45:00Z | intel-apply | source=cli result=ok digest=x sets=0 v4=0 v6=0
2026-11-03T00:05:00Z | firewall started | cli | start | started with the last applied policy
2026-11-03T00:20:00Z | sentinel auto-block | 203.0.113.77, Sentinel: periodic beacon
AEOF
# Three drops seconds ago, one from two days ago, and noise.
py "
import datetime
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
def at(s): return (now - datetime.timedelta(seconds=s)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
open('$C/kern.log', 'w').write('\n'.join([
 at(2 * 86400) + ' host kernel: [0.5] STOCKFW-DROP IN=eth0 OUT= SRC=192.0.2.200 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=40000 DPT=23 SYN',
 at(3) + ' host kernel: [1.0] STOCKFW-DROP IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=40000 DPT=22 SYN',
 at(3) + ' host kernel: [1.5] some other driver says hello',
 at(2) + ' host kernel: [2.0] STOCKFW-DROP IN=eth0 OUT= SRC=198.51.100.7 DST=10.0.0.5 LEN=40 PROTO=TCP SPT=40001 DPT=445 SYN',
 at(1) + ' host kernel: [3.0] STOCKFW-DROP IN= OUT=eth0 SRC=10.0.0.5 DST=203.0.113.9 LEN=60 PROTO=TCP SPT=50000 DPT=443 SYN',
]) + '\n')
"
chmod -R a+rX "$C"

check "audit: -n 2 gives the last 2 entries, and the damaged line is counted (bad_lines 1, stderr note)" c_py "
r = run('--json', 'audit', '-n', '2')
d = json.loads(r.stdout)
assert r.returncode == 0 and len(d['entries']) == 2, r
assert d['bad_lines'] == 1 and d['lines_total'] == 6, d
assert '1 damaged line skipped' in r.stderr, r.stderr
assert [e['action'] for e in d['entries']] == ['firewall started', 'sentinel auto-block'], d"
check "audit: --action start gives the one start line, from cli" c_py "
d = js('audit', '--action', 'start')
assert [(e['action'], e['origin']) for e in d['entries']] == [('firewall started', 'cli')], d"
check "audit: --since/--until in ISO UTC pick the entries across midnight" c_py "
d = js('audit', '--since', '2026-11-02T23:30Z', '--until', '2026-11-03T00:10Z')
assert [e['action'] for e in d['entries']] == ['intel-apply', 'firewall started'], d"
check "audit: origin is cli, gui or null as the line says, never guessed" c_py "
d = js('audit', '-n', '0')
assert [e['origin'] for e in d['entries']] == ['cli', 'gui', 'cli', 'cli', None], d
assert d['entries'][1]['detail'] == 'stop | stopped', d"
check "audit: every epoch is the stamp's own UTC second, in any time zone" c_py "
env = dict(CENV, TZ='Asia/Kolkata')
r = run('--json', 'audit', '-n', '0', env=env)
d = json.loads(r.stdout)
for e in d['entries']:
    want = datetime.datetime.fromisoformat(e['raw'].split(' | ')[0].replace('Z', '+00:00')).timestamp()
    assert e['epoch'] == want and e['time'] == e['raw'].split(' | ')[0], e
r = run('audit', '--utc', '-n', '1', env=env)
assert '2026-11-03T00:20:00Z' in r.stdout, r.stdout"
check "audit: --since garbage is a usage error (exit 2)" c_py "
r = run('audit', '--since', 'garbage')
assert r.returncode == 2 and 'not a time' in r.stderr, r"
check "audit: --action strat says \"did you mean --action start\" (exit 2)" c_py "
r = run('audit', '--action', 'strat')
assert r.returncode == 2 and 'did you mean --action start' in r.stderr, r"
check "audit: no log is exit 1, \"nothing recorded yet\", with the path" c_py "
r = run('audit', env=dict(CENV, STOCKFW_AUDIT_FILE='$C/none.log'))
assert r.returncode == 1 and 'nothing recorded yet' in r.stderr and '$C/none.log' in r.stderr, r"
check "audit: --file refuses a link and a directory (exit 1)" c_py "
os.path.lexists('$C/link.log') or os.symlink('$C/audit.log', '$C/link.log')
for p in ('$C/link.log', '$C'):
    r = run('audit', '--file', p)
    assert r.returncode == 1 and 'not a regular file' in r.stderr, (p, r)
assert run('audit', '--file', '$C/audit.log').returncode == 0"
check "audit: the table has TIME ACTION FROM DETAIL and a header with the line count" c_py "
r = run('audit', '-n', '0')
lines = r.stdout.splitlines()
assert lines[0].startswith('Audit log $C/audit.log  (6 lines'), lines
assert lines[1].split() == ['TIME', 'ACTION', 'FROM', 'DETAIL'], lines
assert any('firewall stopped' in l and ' gui ' in l for l in lines), lines"
check "audit -f --json: a new line arrives as one NDJSON object" c_py "
import shutil
shutil.copy('$C/audit.log', '$C/follow.log')
env = dict(CENV, STOCKFW_AUDIT_FILE='$C/follow.log')
p = subprocess.Popen(['$S', '--json', 'audit', '-f', '-n', '1'], stdout=subprocess.PIPE, text=True, env=env)
first = json.loads(p.stdout.readline())
with open('$C/follow.log', 'a') as f:
    f.write('2026-11-03T10:00:00Z | firewall stopped | cli | stop | stopped\n')
line = p.stdout.readline()
p.terminate(); p.wait(timeout=5)
e = json.loads(line)
assert first['action'] == 'sentinel auto-block', first
assert e['action'] == 'firewall stopped' and e['origin'] == 'cli' and e['epoch'] == datetime.datetime(2026, 11, 3, 10, tzinfo=datetime.timezone.utc).timestamp(), e"
if [ "$(id -u)" = 0 ] && command -v unshare > /dev/null; then
  # A real apply, in a private network namespace: the newest entry is
  # that apply, from cli.
  check "audit: after a real apply (netns), the last entry is an apply from cli" c_py "
env = {k: v for k, v in CENV.items() if k != 'STOCKFW_APPLIED_FILE'}
env.update(STOCKFW_AUDIT_FILE='$C/netns-audit.log', STOCKFW_RULES_DIR='$C/netns-rules')
r = subprocess.run(['unshare', '-n', 'sh', '-c', '\"\$0\" policy add inbound-allow-service SSH 22 Anyone >/dev/null && \"\$0\" apply >/dev/null 2>&1 && \"\$0\" --json audit -n 1', '$S'], capture_output=True, text=True, env=env, timeout=60)
d = json.loads(r.stdout)
e = d['entries'][-1]
assert e['action'] == 'policy applied' and e['origin'] == 'cli' and e['detail'].startswith('full | +1 added'), d"
fi

# status: the journal fixture holds the saved rules -> live.
c_py "
r = run('policy', 'add', 'inbound-allow-service', 'SSH', '22', 'Anyone')
assert r.returncode == 0, r
# The settings it went out with: the defaults, as a real apply writes them.
sets = ['ext_if=', 'int_if=', 'nat=false', 'icmp/enable=true', 'icmp/echo_request=true', 'icmp/echo_reply=true',
        'icmp/traceroute=true', 'icmp/mstraceroute=true', 'icmp/unreachable=true', 'icmp/timestamping=false',
        'icmp/masking=false', 'icmp/redirection=false', 'icmp/source_quenches=false', 'deny_packets=true',
        'restrictive_outbound=false', 'log_allowed=true', 'block_external_broadcast=false',
        'block_internal_broadcast=false', 'block_non_routables=true']
open('$C/applied.csv', 'w').write('# StockFW applied policy journal v1\n# rules translation 2\n1,\"SSH, 22, Anyone, \"\n'
                                  + ''.join('# setting /apps/stockfw/firewall/%s\n' % x for x in sets))
" > /dev/null
chmod -R a+rX "$C"
check "status: a journal equal to the rules is live == \"same\", pending 0" c_py "
d = js('status', nobody=True)
assert d['live'] == 'same' and d['pending'] == {'added': 0, 'removed': 0, 'settings': False}, d"
check "  ...one more rule: live == \"pending\", pending.added == 1, and the text says so" c_py "
assert run('policy', 'add', 'outbound-deny-to', '203.0.113.77', '--comment', 'Sentinel: periodic beacon').returncode == 0
os.system('chmod -R a+rX $C')
d = js('status', nobody=True)
assert d['live'] == 'pending' and d['pending']['added'] == 1 and d['pending']['removed'] == 0, d
t = run('status', nobody=True).stdout
assert '2 rules, 1 change not applied (stockfw policy diff)' in t, t
q = run('-q', 'status', nobody=True).stdout
assert q == 'unknown, 1 change pending\n', q"
check "status: last_apply is the newest gate line of the audit log, to the second" c_py "
d = js('status')
la = d['last_apply']
assert la['action'] == 'firewall started' and la['origin'] == 'cli', la
assert la['epoch'] == datetime.datetime(2026, 11, 3, 0, 5, tzinfo=datetime.timezone.utc).timestamp(), la"
check "status: as uid 65534 with a readable log, monitoring is readable (1.0.7 said no)" c_py "
d = js('status', nobody=True)
assert d['monitoring'] == {'readable': True, 'source': '$C/kern.log', 'problem': None}, d['monitoring']
assert d['monitoring_available'] is True, d
assert 'reading $C/kern.log' in run('status', nobody=True).stdout"
check "  ...and an unreadable one is not, with the reason" c_py "
d = js('status', nobody=True, env=dict(CENV, STOCKFW_LOG_FILE='$C/missing.log'))
m = d['monitoring']
assert m['readable'] is False and d['monitoring_available'] is False and 'cannot read' in m['problem'], d"
check "status: blocked today counts the 3 drops since local midnight, and names the last" c_py "
now = datetime.datetime.now()
midnight = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
want = 3 if time.time() - 3 >= midnight else None
d = js('status')
if want is not None:
    assert d['blocked_today'] == 3 and d['blocked_source'] == 'kernel_log', d
    assert d['last_block']['destination'] == '203.0.113.9' and d['last_block']['blocked'] is True, d
    assert 'today 3' in run('status').stdout"
check "status -v --json: the firewall settings, restrictive outbound from stockfw.conf" c_py "
open('$C/cfg/stockfw/stockfw.conf', 'w').write('[firewall]\nrestrictive_outbound=true\n')
d = js('status', '-v')
assert d['settings']['/apps/stockfw/firewall/restrictive_outbound'] == 'true', d['settings']
assert d['sentinel']['mode'] == 'auto' and d['history']['enabled'] is False, d
t = run('status', '-v').stdout
assert 'blocked unless a rule allows it (restrictive)' in t and 'Policy Lock is not enforced by the CLI' in t, t
os.remove('$C/cfg/stockfw/stockfw.conf')"
check "status: the boot unit is read (absent, then enabled)" c_py "
assert js('status')['boot_unit'] == 'absent'
os.makedirs('$C/systemd/multi-user.target.wants', exist_ok=True)
open('$C/systemd/stockfw.service', 'w').write('[Unit]\n')
os.path.lexists('$C/systemd/multi-user.target.wants/stockfw.service') or os.symlink('$C/systemd/stockfw.service', '$C/systemd/multi-user.target.wants/stockfw.service')
d = js('status')
assert d['boot_unit'] == 'enabled' and d['host'], d
assert 'stockfw.service enabled' in run('status').stdout"
check "status --json: every 1.0.7 key is still there" c_py "
old = ['version', 'backend', 'state', 'ipv6', 'root', 'rules_dir', 'policy_saved', 'malformed_rules',
       'rules', 'apply_hold', 'monitoring_available', 'connections', 'intel', 'interfaces']
d = js('status')
assert all(k in d for k in old), [k for k in old if k not in d]
assert set(d['ipv6']) == {'state', 'detail'}"
check "status: an unknown option is refused (exit 2)" c_py "
r = run('status', '--verbos')
assert r.returncode == 2 and 'did you mean --verbose' in r.stderr, r"

# sentinel list: one fresh row, one expired, one damaged.
py "
import time
t = int(time.time())
open('$C/autoblocks', 'w').write('S,%d,6,203.0.113.77, Sentinel: periodic beacon\nS,%d,6,203.0.113.78, Sentinel: fan-out\nnot a row\n' % (t - 60, t - 700))
"
chmod -R a+rX "$C"
check "sentinel list --json: fresh and expired rows, and the file is not changed" c_py "
before = hashlib.sha256(open('$C/autoblocks', 'rb').read()).hexdigest()
r = run('--json', 'sentinel', 'list')
d = json.loads(r.stdout)
after = hashlib.sha256(open('$C/autoblocks', 'rb').read()).hexdigest()
assert before == after, 'sentinel list changed the file'
b = {x['target']: x for x in d['blocks']}
assert b['203.0.113.77']['expired'] is False and b['203.0.113.78']['expired'] is True, d
assert b['203.0.113.77']['rule_ref'] == 'outbound-deny-to:1' and b['203.0.113.78']['rule_ref'] is None, d
assert b['203.0.113.77']['why'] == 'periodic beacon' and d['mode'] == 'auto', d
assert b['203.0.113.77']['expires_epoch'] - b['203.0.113.77']['epoch'] == 600, d
assert '1 damaged row' in r.stderr, r.stderr"
check "sentinel: the table, and \`sentinel lift' is refused (exit 2)" c_py "
t = run('sentinel').stdout
assert 'TARGET' in t and 'due since' in t and 'outbound-deny-to:1' in t, t
r = run('sentinel', 'lift')
assert r.returncode == 2, r"
check "status -v: Sentinel's staged count comes from the same file" c_py "
d = js('status', '-v')
assert d['sentinel']['staged'] == 2 and d['sentinel']['next_lift_epoch'] > time.time(), d['sentinel']"
check "simulate: a staged Sentinel block says when it lifts" c_py "
r = run('simulate', '--assume-running', 'outbound', 'to', '203.0.113.77', 'port', '443')
assert r.returncode == 5 and 'lifts by itself' in r.stdout, r"

# dashboard: monitoring by readability, and live rows from the file.
if [ "$(id -u)" = 0 ] && command -v setpriv > /dev/null || [ "$(id -u)" != 0 ]; then
  check "dashboard: as uid 65534 with a readable log, monitoring is on and new lines arrive" c_py "
import socket, urllib.request
s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
pre = $C_AS
p = subprocess.Popen(pre + ['$S', 'dashboard', '--no-open', '--port', str(port)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=CENV)
try:
    url = ''
    for _ in range(50):
        line = p.stdout.readline()
        if '#token=' in line:
            url = line; break
    token = url.split('#token=')[1].split()[0]
    def get(path):
        req = urllib.request.Request('http://127.0.0.1:%d%s' % (port, path), headers={'X-StockFW-Token': token})
        return json.loads(urllib.request.urlopen(req, timeout=5).read())
    d = get('/api/summary')
    assert d['monitoring'] is True and d['root'] is False and 'readable without root' in d['monitor_note'], d
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S+00:00')
    with open('$C/kern.log', 'a') as f:
        f.write(stamp + ' host kernel: [9.0] STOCKFW-DROP IN=eth0 OUT= SRC=192.0.2.123 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=40000 DPT=8443 SYN\n')
    for _ in range(30):
        if any(e['source'] == '192.0.2.123' for e in get('/api/events')):
            break
        time.sleep(0.2)
    else:
        raise AssertionError('the appended line never reached /api/events')
finally:
    p.terminate(); p.wait(timeout=5)"
fi
rm -rf "$C"
# === end WP-C ===

# === WP-D ===
# === end WP-D ===

# === WP-F ===
# === end WP-F ===

# === WP-E ===
# === end WP-E ===

echo ""
if [ "$fails" -eq 0 ]; then
  echo "PASSED: 0 failure(s)"
else
  echo "FAILED: $fails failure(s)"
fi
exit "$fails"
