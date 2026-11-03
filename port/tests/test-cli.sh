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
