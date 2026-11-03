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
# touches /etc/stockfw or the host's firewall.  Without root, `apply'
# only ever runs with --dry-run.  As root, more checks run (the live
# event line, events -f, the lockout guard, real apply, start and
# stop); the ones that change a firewall do so only inside a private
# network namespace (unshare -n).  Linux only.
#
#   cd port && bash tests/test-cli.sh
#
# It builds the whole tree in the build directory first: the manual
# page and `cmake --install' need more than the stockfw target.

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
cd "$PORT" || exit 1

if [ "$(uname -s)" != "Linux" ]; then
  echo "SKIP: the stockfw CLI is the Linux front end"
  exit 0
fi

BUILD="${STOCKFW_BUILD:-$PORT/build-linux}"
if ! { cmake -S . -B "$BUILD" -G Ninja > /dev/null &&
       cmake --build "$BUILD" > /dev/null; }; then
  echo "FAIL: could not build the tree in $BUILD"
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
else
  echo "skip: simulate with the firewall stopped (needs root, iptables and unshare)"
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

# The text of `copilot health' shows a rule's name and comment as the
# rule file holds them: an ESC or a BEL there reaches the terminal only
# escaped (\x1b), like every other command that shows a rule.
check "copilot health: a rule name and comment with ESC and BEL are printed escaped" py "
import os, subprocess
d = '$TMP/rules-cp-esc'
env = dict(os.environ, STOCKFW_RULES_DIR=d, STOCKFW_LAN_PREFIX='192.168.1.0/24', STOCKFW_LOCAL_ADDRESSES='192.168.1.5')
a = subprocess.run(['$S', 'policy', 'add', 'inbound-allow-service', 'EV\x1b]0;PWNED\x07IL', '3389', 'Anyone',
                    '--comment', 'c\x1b[2J'], env=env, capture_output=True)
assert a.returncode == 0, a
r = subprocess.run(['$S', 'copilot', 'health'], env=env, capture_output=True)
assert r.returncode == 7 and b'rule:' in r.stdout, r
assert b'\x1b' not in r.stdout and b'\x07' not in r.stdout, r.stdout
assert b'EV\\\\x1b]0;PWNED\\\\x07IL' in r.stdout and b'c\\\\x1b[2J' in r.stdout, r.stdout"

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
    assert r.returncode == 0 and r.stdout.startswith('Added '), (args, r)
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
# Review notes (docs 15.2): simulate's description names rules after
# the policy's rows; a service name with U+202E showed reversed.
check "output: simulate prints a rule label's U+202E escaped, never raw" \
  bash -c "STOCKFW_RULES_DIR='$TMP/simrules' '$S' -q policy add inbound-allow-service \"\$(printf 'web\\342\\200\\256nimda')\" 8080 Anyone &&
           STOCKFW_RULES_DIR='$TMP/simrules' '$S' --color=never simulate --assume-running inbound tcp port 8080 from 8.8.8.8 > '$TMP/sim.txt';
           grep -qF \"Allow web\\\\u202enimda\" '$TMP/sim.txt' && ! grep -q \$'\\342\\200\\256' '$TMP/sim.txt'"
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
# Policy truth and safe changes (cli-plan.md section 4, WP-B): lines
# that are not rules, KIND:N references, `policy diff', the A1 apply
# with the firewall stopped, the lockout guard and start/stop that know
# the state.  Scratch rules of its own, readable by nobody; the root
# parts run in a private network namespace.
B="$(mktemp -d /tmp/stockfw-wpb-XXXXXX)"; chmod 755 "$B"
b_env () { env STOCKFW_RULES_DIR="$B/$1" STOCKFW_APPLIED_FILE="$B/$1.applied" \
               STOCKFW_LOG_FILE="$B/kern.log" STOCKFW_LAN_PREFIX=192.168.1.0/24 \
               STOCKFW_LOCAL_ADDRESSES=192.168.1.5 "${@:2}"; }
b_rc () { local want="$1"; shift; b_env "$@" > "$TMP/out" 2> "$TMP/err"; [ "$?" -eq "$want" ]; }
: > "$B/kern.log"
# A journal (STOCKFW_APPLIED_FILE) written from rule-file rows:
# b_journal <dir> "<kind index>|<row>" ...  (the kind index is the
# FsRuleKind: 1 inbound-allow-service, 2 forward, 6 outbound-deny-to).
b_journal () { local d="$1"; shift; python3 -I -c "
import csv, sys
rows = sys.argv[1:]
with open('$B/$d.applied', 'w', newline='') as f:
    f.write('# StockFW applied policy journal v1\n')
    w = csv.writer(f, lineterminator='\n')
    for r in rows:
        k, row = r.split('|', 1)
        w.writerow([k, row])
" "$@"; }

# --- check: a line that is not a rule (survey A2, A3)
mkdir -p "$B/chk/inbound"
printf '%s\n' 'SSH, 22, Anyone,' 'HTTP, 80, Anyone,' 'HTTPS, 443, Anyone,' \
  'DNS, 53, Anyone,' 'NTP, 123, Anyone,' 'IMAP, 143, Anyone,' \
  'garbage line without commas' > "$B/chk/inbound/allow-service"
check "check: a line without commas is a problem (rc 1, FILE:7:)" \
  bash -c "$(declare -f b_env b_rc); B='$B'; TMP='$TMP'; S='$S'; b_rc 1 chk '$S' check && grep -q 'allow-service:7: expected NAME, PORT, FOR' '$TMP/out'"
check "  ...apply --dry-run refuses it (rc 2)" b_rc 2 chk "$S" apply --dry-run
check "  ...status --json counts it once" py "
import json, os, subprocess
env = dict(os.environ, STOCKFW_RULES_DIR='$B/chk', STOCKFW_APPLIED_FILE='$B/chk.applied')
d = json.loads(subprocess.run(['$S', '--json', 'status'], capture_output=True, text=True, env=env).stdout)
assert d['malformed_rules'] == 1, d['malformed_rules']"
check "  ...and policy list --json does not list it" py "
import json, os, subprocess
env = dict(os.environ, STOCKFW_RULES_DIR='$B/chk')
d = json.loads(subprocess.run(['$S', '--json', 'policy', 'list'], capture_output=True, text=True, env=env).stdout)
assert len(d['rules']) == 6 and not any('garbage' in (r['service'] or '') for r in d['rules']), d
assert d['rules'][0]['rule_ref'] == 'inbound-allow-service:1', d['rules'][0]"
check "  ...check --json gives file, path, line and reason" py "
import json, os, subprocess
env = dict(os.environ, STOCKFW_RULES_DIR='$B/chk')
r = subprocess.run(['$S', '--json', 'check'], capture_output=True, text=True, env=env)
d = json.loads(r.stdout)
assert r.returncode == 1 and d['ok'] is False and len(d['problems']) == 1, d
p = d['problems'][0]
assert p['file'] == 'inbound/allow-service' and p['line'] == 7, p
assert p['path'] == '$B/chk/inbound/allow-service' and 'no commas' in p['reason'], p"
mkdir -p "$B/port/inbound"
printf '%s\n' 'SSH, 22, Anyone,' 'FTP, 99999, Anyone,' > "$B/port/inbound/allow-service"
check "check: port 99999 is \"out of range\" once on stderr, as an error" \
  bash -c "$(declare -f b_env b_rc); B='$B'; TMP='$TMP'; b_rc 2 port '$S' apply --dry-run &&
           [ \$(grep -c 'out of range' '$TMP/err') -eq 1 ] &&
           grep 'out of range' '$TMP/err' | grep -q '^stockfw: error: '"
mkdir -p "$B/ok/inbound"
printf '%s\n' 'SSH,,Anyone' > "$B/ok/inbound/allow-service"
check "check: SSH,,Anyone still loads (a known service needs no port)" \
  bash -c "$(declare -f b_env b_rc); B='$B'; TMP='$TMP'; b_rc 0 ok '$S' check"
check "check: one bad line reads \"this line is not a rule\" and \"1 line ... is not a rule\"" \
  bash -c "$(declare -f b_env b_rc); B='$B'; TMP='$TMP'; b_rc 2 port '$S' apply --dry-run &&
           grep -q 'hint: this line is not a rule and is left out' '$TMP/err' &&
           grep -q 'not applied: 1 line of the policy is not a rule\$' '$TMP/err'"
# policy add and remove rewrite every rule file from memory, where a
# line that is not a rule is missing: they refuse instead of deleting it.
mkdir -p "$B/lossy/inbound" "$B/lossy/outbound"
printf '%s\n' 'SSH, 22, 192.168.1.0/24,' 'PostgreSQL 5432 10.0.0.0/8' 'HTTP,80,Anyone,' \
  > "$B/lossy/inbound/allow-service"
printf '%s\n' '198.51.100.7,' > "$B/lossy/outbound/deny-to"
cp -r "$B/lossy" "$B/lossy.orig"
check "policy remove: refuses (rc 2) when a line is not a rule, and names it" \
  bash -c "$(declare -f b_env b_rc); B='$B'; TMP='$TMP'; b_rc 2 lossy '$S' policy remove inbound-allow-service:2 &&
           grep -q 'allow-service:2: expected NAME, PORT, FOR' '$TMP/err' &&
           grep -q 'not saved: 1 line of the policy is not a rule' '$TMP/err' && [ ! -s '$TMP/out' ]"
check "policy add: refuses (rc 2) for a rule of another kind too" \
  b_rc 2 lossy "$S" policy add outbound-deny-to 203.0.113.9
check "  ...and the rule files are left byte for byte" diff -r "$B/lossy" "$B/lossy.orig"

# --- diff: saved against applied
# As root the firewall's real state would decide "live"; uid 65534
# cannot read it, so the diff is against the journal alone.
BU=""
if [ "$(id -u)" = 0 ] && command -v setpriv > /dev/null; then
  BU="setpriv --reuid=65534 --regid=65534 --clear-groups"
fi
mkdir -p "$B/d/inbound" "$B/d/outbound"
printf '%s\n' 'SSH, 22, 192.168.1.0/24,' 'HTTP, 80, Anyone,' 'HTTPS, 443, Anyone,' \
  'PostgreSQL, 5432, 192.168.1.0/24,' > "$B/d/inbound/allow-service"
printf '%s\n' 'Web, 8080, 192.168.1.10, 80' > "$B/d/inbound/forward"
b_journal d '1|SSH, 22, 192.168.1.0/24,' '1|HTTP, 80, Anyone,' '1|HTTPS, 443, Anyone,' \
  '2|Web, 8080, 192.168.1.10, 80' '6|198.51.100.3,'
check "diff: one row added (inbound-allow-service:4), one removed, pending" py "
import json, os, subprocess
BU = '$BU'.split()
env = dict(os.environ, STOCKFW_RULES_DIR='$B/d', STOCKFW_APPLIED_FILE='$B/d.applied')
d = json.loads(subprocess.run(BU + ['$S', '--json', 'policy', 'diff'], capture_output=True, text=True, env=env).stdout)
assert d['live'] == 'pending' and d['added'][0]['ref'] == 'inbound-allow-service:4', d
assert len(d['added']) == 1 and len(d['removed']) == 1 and d['unchanged'] == 4, d
assert d['removed'][0]['ref'] == 'outbound-deny-to:1' and d['epoch'] > 0, d"
check "  ...the forward with no external interface is one note, not an added row" py "
import json, os, subprocess
BU = '$BU'.split()
env = dict(os.environ, STOCKFW_RULES_DIR='$B/d', STOCKFW_APPLIED_FILE='$B/d.applied')
d = json.loads(subprocess.run(BU + ['$S', '--json', 'policy', 'diff'], capture_output=True, text=True, env=env).stdout)
assert len(d['notes']) == 1 and 'inbound-forward:1' in d['notes'][0] and 'left out' in d['notes'][0], d['notes']
assert not any(a['kind'] == 'inbound-forward' for a in d['added']), d['added']"
check "  ...apply --dry-run --json lists as many added_rules as it counts" py "
import json, os, subprocess
BU = '$BU'.split()
env = dict(os.environ, STOCKFW_RULES_DIR='$B/d', STOCKFW_APPLIED_FILE='$B/d.applied')
d = json.loads(subprocess.run(BU + ['$S', '--json', 'apply', '--dry-run'], capture_output=True, text=True, env=env).stdout)
assert len(d['added_rules']) == d['added'] == 1 and len(d['removed_rules']) == d['removed'] == 1, d
assert d['added_rules'][0]['ref'] == 'inbound-allow-service:4' and len(d['notes']) == 1, d"
check "  ...and the text names the rows with their references" \
  bash -c "$(declare -f b_env b_rc); B='$B'; TMP='$TMP'; b_rc 0 d $BU '$S' policy diff &&
           grep -q '^+ inbound-allow-service:4  PostgreSQL' '$TMP/out' &&
           grep -q '^- outbound-deny-to:1  198.51.100.3.*(as applied)' '$TMP/out'"
b_journal d '1|SSH, 22, 192.168.1.0/24,' '1|HTTP, 80, Anyone,' '1|HTTPS, 443, Anyone,' \
  '1|PostgreSQL, 5432, 192.168.1.0/24,' '2|Web, 8080, 192.168.1.10, 80'
check "diff: a journal that holds the saved rows is live == same" py "
import json, os, subprocess
BU = '$BU'.split()
env = dict(os.environ, STOCKFW_RULES_DIR='$B/d', STOCKFW_APPLIED_FILE='$B/d.applied')
d = json.loads(subprocess.run(BU + ['$S', '--json', 'policy', 'diff'], capture_output=True, text=True, env=env).stdout)
assert d['live'] == 'same' and d['added'] == [] and d['removed'] == [], d"

# --- references: KIND:N everywhere
mkdir -p "$B/r1/inbound" "$B/r1/outbound"
printf '%s\n' 'SSH, 22, Anyone,' 'HTTP, 80, Anyone,' > "$B/r1/inbound/allow-service"
printf '%s\n' '198.51.100.1, first' '203.0.113.9, second' > "$B/r1/outbound/deny-to"
cp -r "$B/r1" "$B/r2"; cp -r "$B/r1" "$B/r3"
check "refs: remove KIND:N, KIND N and KIND#N remove the same row" \
  bash -c "$(declare -f b_env b_rc); B='$B'; TMP='$TMP'; b_rc 0 r1 '$S' policy remove inbound-allow-service:1 &&
           b_rc 0 r2 '$S' policy remove inbound-allow-service 1 &&
           b_rc 0 r3 '$S' policy remove 'inbound-allow-service#1' &&
           cmp -s '$B/r1/inbound/allow-service' '$B/r2/inbound/allow-service' &&
           cmp -s '$B/r1/inbound/allow-service' '$B/r3/inbound/allow-service' &&
           ! grep -q SSH '$B/r1/inbound/allow-service' && grep -q HTTP '$B/r1/inbound/allow-service'"
check "refs: a number past the end is refused (rc 2), nothing removed" \
  bash -c "$(declare -f b_env b_rc); B='$B'; TMP='$TMP'; b_rc 2 r1 '$S' policy remove outbound-deny-to:3 &&
           [ \$(wc -l < '$B/r1/outbound/deny-to') -eq 2 ]"
check "refs: simulate --json's rule_ref goes straight into policy remove" py "
import json, os, subprocess
env = dict(os.environ, STOCKFW_RULES_DIR='$B/r2')
d = json.loads(subprocess.run(['$S', '--json', 'simulate', '--assume-running', 'outbound tcp to 203.0.113.9 port 443'],
                              capture_output=True, text=True, env=env).stdout)
ref = d['rule_ref']
assert ref == 'outbound-deny-to:2' and d['answers'][0]['rule_ref'] == ref, d
assert [t for t in d['answers'][0]['trace'] if t['decides']][0]['rule_ref'] == ref, d
r = subprocess.run(['$S', 'policy', 'remove', ref], capture_output=True, text=True, env=env)
assert r.returncode == 0 and 'Removed outbound-deny-to:2' in r.stdout, r
rows = open('$B/r2/outbound/deny-to').read()
assert '203.0.113.9' not in rows and '198.51.100.1' in rows, rows"
check "refs: policy show REF prints one rule; --json is the rule object" py "
import json, os, subprocess
env = dict(os.environ, STOCKFW_RULES_DIR='$B/r3')
d = json.loads(subprocess.run(['$S', '--json', 'policy', 'show', 'outbound-deny-to:2'], capture_output=True, text=True, env=env).stdout)
assert d['ref'] == 'outbound-deny-to:2' and d['fields']['target'] == '203.0.113.9' and d['comment'] == 'second', d
assert d['status'] == 'pending', d"
check "refs: policy add echoes the reference and a check of its own traffic" \
  bash -c "$(declare -f b_env b_rc); B='$B'; TMP='$TMP'; b_rc 0 r3 '$S' policy add inbound-allow-service SSH 22 192.168.1.0/24 &&
           grep -q '^Added inbound-allow-service:2  SSH  port 22  for 192.168.1.0/24' '$TMP/out' &&
           grep -q '^Check: inbound tcp port 22 from 192.168.1.1 .* ALLOWED (saved policy)' '$TMP/out' &&
           grep -q 'preview: stockfw policy diff' '$TMP/out'"
check "refs: policy add --json carries the rule and the rules directory" py "
import json, os, subprocess
env = dict(os.environ, STOCKFW_RULES_DIR='$B/r3')
d = json.loads(subprocess.run(['$S', '--json', 'policy', 'add', 'inbound-allow-service', 'HTTPS', '--both'],
                              capture_output=True, text=True, env=env).stdout)
assert d['rule']['ref'] == 'inbound-allow-service:3' and d['twin']['ref'] == 'outbound-allow-service:1', d
assert d['rules_dir'] == '$B/r3' and d['check']['verdict'] == 'ALLOWED', d"
if [ "$(id -u)" != 0 ]; then
  check "refs: a policy edited without sudo says sudo applies /etc/stockfw" \
    bash -c "$(declare -f b_env b_rc); B='$B'; TMP='$TMP'; b_rc 0 r3 '$S' policy add outbound-deny-to 203.0.113.44 && grep -q '/etc/stockfw' '$TMP/out'"
elif command -v setpriv > /dev/null; then
  cp -r "$B/r1" "$B/r4"; chown -R 65534:65534 "$B/r4"
  check "refs: a policy edited without sudo says sudo applies /etc/stockfw" \
    bash -c "$(declare -f b_env b_rc); B='$B'; TMP='$TMP'; b_rc 0 r4 setpriv --reuid=65534 --regid=65534 --clear-groups '$S' policy add outbound-deny-to 203.0.113.44 && grep -q 'with sudo, stockfw reads and applies /etc/stockfw' '$TMP/out'"
fi
mkdir -p "$B/cp/inbound"
printf '%s\n' 'RDP, 3389, Anyone,' > "$B/cp/inbound/allow-service"
check "refs: copilot health --json keeps index 0 and adds rule_ref" py "
import json, os, subprocess
env = dict(os.environ, STOCKFW_RULES_DIR='$B/cp', STOCKFW_LAN_PREFIX='192.168.1.0/24', STOCKFW_LOCAL_ADDRESSES='192.168.1.5')
r = subprocess.run(['$S', '--json', 'copilot', 'health'], capture_output=True, text=True, env=env)
f = json.loads(r.stdout)['findings'][0]
assert r.returncode == 7 and f['rule']['index'] == 0 and f['rule']['rule_ref'] == 'inbound-allow-service:1', f
assert f['rule']['kind'] == 'inbound_allow_service', f"
mkdir -p "$B/info/outbound"
printf '%s\n' '198.51.100.9, nothing to allow' > "$B/info/outbound/allow-to"
check "copilot health --severity: info findings exit 7 by default, 0 at warning" \
  bash -c "$(declare -f b_env b_rc); B='$B'; TMP='$TMP'; b_rc 7 info '$S' copilot health && b_rc 0 info '$S' copilot health --severity warning &&
           b_rc 2 info '$S' copilot health --severity loud"

# --- simulate --applied: the journal, not the saved file
mkdir -p "$B/sa/inbound"
printf '%s\n' 'SSH, 22, Anyone,' > "$B/sa/inbound/allow-service"
b_journal sa '1|SSH, 22, Anyone,' '6|203.0.113.50,'
check "simulate --applied asks the journal: BLOCKED (5) where the saved policy says 0" \
  bash -c "$(declare -f b_env b_rc); B='$B'; TMP='$TMP'; b_rc 0 sa '$S' simulate --assume-running outbound tcp to 203.0.113.50 port 443 &&
           b_rc 5 sa '$S' simulate --applied --assume-running outbound tcp to 203.0.113.50 port 443 &&
           grep -q '(applied policy, ' '$TMP/out' && grep -q 'Decided by outbound-deny-to:1' '$TMP/out'"

# --- lockout as any user: a dry run warns and changes nothing
b_user=()
if [ "$(id -u)" = 0 ] && command -v setpriv > /dev/null; then
  b_user=(setpriv --reuid=65534 --regid=65534 --clear-groups)
fi
mkdir -p "$B/lk/inbound"
printf '%s\n' 'SSH, 22, 192.168.1.0/24,' > "$B/lk/inbound/allow-service"
b_lockout_dry () {
  b_rc 0 lk "${b_user[@]}" env SSH_CONNECTION='10.0.0.5 50000 10.0.0.1 22' "$S" apply --dry-run &&
  grep -q 'warning: this policy would block your SSH session' "$TMP/err" &&
  grep -q 'from 10.0.0.5 to port 22: BLOCKED' "$TMP/err"
}
check "lockout: apply --dry-run as uid 65534 warns about the SSH session, rc 0" b_lockout_dry

# --- live, as root, in a private network namespace
if [ "$(id -u)" = 0 ] && command -v iptables > /dev/null 2>&1 &&
   command -v ip > /dev/null 2>&1 && unshare -n true 2> /dev/null; then
  cat > "$B/live.sh" <<'LIVE'
S="$1"; B="$2"
f=0
ok () { echo "ok:   $1"; }
no () { echo "FAIL: $1"; f=$((f+1)); }
t () { local what="$1"; shift; if "$@"; then ok "$what"; else no "$what"; fi; }
export STOCKFW_RULES_DIR="$B/live" STOCKFW_APPLIED_FILE="$B/live.applied"
export STOCKFW_AUDIT_FILE="$B/live.audit" STOCKFW_AUTOBLOCK_FILE="$B/live.autoblocks"
export HOME="$B/home" XDG_CONFIG_HOME="$B/home/.config"
unset SSH_CONNECTION SSH_CLIENT STOCKFW_INTEL_DIR
mkdir -p "$HOME"
ip link set lo up
"$S" -q policy add inbound-allow-service SSH 22 Anyone
"$S" -q policy add outbound-deny-to 198.51.100.3
# A1: apply, stop, apply: the second apply must start the firewall.
"$S" apply > "$B/a1.out" 2>&1; "$S" stop > /dev/null 2>&1
"$S" apply > "$B/a2.out" 2>&1; rc=$?
t "A1: apply after stop does not say \"Nothing to change\" (rc $rc)" bash -c "[ $rc -eq 0 ] && ! grep -q 'Nothing to change' '$B/a2.out' && grep -q 'firewall was stopped and is now running' '$B/a2.out'"
t "A1: ...the chains are back" bash -c "iptables -S INBOUND > /dev/null"
t "A1: ...status says running" bash -c "'$S' --json status | python3 -I -c 'import json,sys; assert json.load(sys.stdin)[\"state\"] == \"running\"'"
t "A1: ...the audit line says why it was whole" bash -c "grep '| policy applied |' '$STOCKFW_AUDIT_FILE' | tail -1 | grep -q '| full (firewall was stopped) |'"
# Running: an unchanged apply still takes the narrow path.
"$S" apply > /dev/null 2>&1
t "A1: apply; apply while running stays narrow" bash -c "tail -1 '$STOCKFW_AUDIT_FILE' | grep -q '| narrow |'"
t "A1: --json says what the firewall was" bash -c "'$S' --json apply | python3 -I -c 'import json,sys; assert json.load(sys.stdin)[\"firewall_was\"] == \"running\"'"
# B6: start and stop know the state.
n0=$(wc -l < "$STOCKFW_AUDIT_FILE")
"$S" start > "$B/st.out" 2>&1
t "start while running: \"Already running\", no audit line" bash -c "grep -q '^Already running' '$B/st.out' && [ \$(wc -l < '$STOCKFW_AUDIT_FILE') -eq $n0 ]"
"$S" stop > /dev/null 2>&1; "$S" stop > "$B/sp.out" 2>&1
t "stop; stop: one audit line, then \"Already stopped\"" bash -c "[ \$(wc -l < '$STOCKFW_AUDIT_FILE') -eq $((n0 + 1)) ] && grep -q '^Already stopped' '$B/sp.out'"
"$S" start > /dev/null 2>&1
# Lockout: the SSH row narrowed to the LAN, a session from elsewhere.
"$S" -q policy remove inbound-allow-service:1
"$S" -q policy add inbound-allow-service SSH 22 192.168.1.0/24
snap () { iptables-save | grep -v '^#' | sha256sum; }
before=$(snap)
SSH_CONNECTION='10.0.0.5 50000 10.0.0.1 22' "$S" apply < /dev/null > "$B/lk.out" 2>&1; rc=$?
t "lockout: no terminal, no --yes: refused (rc $rc), the firewall untouched" bash -c "[ $rc -eq 1 ] && [ '$(snap)' = '$before' ] && grep -q 'pass --yes' '$B/lk.out'"
SSH_CONNECTION='10.0.0.5 50000 10.0.0.1 22' "$S" --json apply --yes < /dev/null > "$B/lky.out" 2> /dev/null; rc=$?
t "lockout: --yes applies, and the JSON says it was confirmed" bash -c "[ $rc -eq 0 ] && [ '$(snap)' != '$before' ] && python3 -I -c 'import json; d = json.load(open(\"$B/lky.out\")); l = d[\"lockout\"]; assert l[\"checked\"] and l[\"verdict\"] == \"BLOCKED\" and l[\"client\"] == \"10.0.0.5\" and l[\"confirmed\"], d'"
"$S" -q policy add outbound-deny-to 198.51.100.4
SSH_CONNECTION='192.168.1.20 50000 10.0.0.1 22' "$S" apply < /dev/null > "$B/lan.out" 2>&1; rc=$?
t "lockout: a session from the LAN is no warning (rc $rc)" bash -c "[ $rc -eq 0 ] && ! grep -q warning '$B/lan.out'"
"$S" -q policy add outbound-deny-to 198.51.100.5
t "lockout: no SSH session, no check" bash -c "'$S' --json apply < /dev/null | python3 -I -c 'import json,sys; l = json.load(sys.stdin)[\"lockout\"]; assert l == {\"checked\": False, \"reason\": \"not an SSH session\"}, l'"
# Under sudo the variable is gone: the session is in the kernel's
# table.  An established connection to port 22 from 10.0.0.5.
ip addr add 10.0.0.1/32 dev lo; ip addr add 10.0.0.5/32 dev lo
python3 -I -c '
import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.0.0.1", 22)); s.listen()
c = socket.socket(); c.bind(("10.0.0.5", 0)); c.connect(("10.0.0.1", 22)); a, _ = s.accept()
print("up", flush=True); time.sleep(30)' > "$B/peer.out" &
peer=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do grep -q up "$B/peer.out" 2>/dev/null && break; sleep 0.2; done
"$S" -q policy add outbound-deny-to 198.51.100.6 2> /dev/null
before=$(snap)
"$S" apply < /dev/null > "$B/sudo.out" 2>&1; rc=$?
t "lockout under sudo: a peer in the TCP table, no SSH_CONNECTION: refused (rc $rc)" bash -c "[ $rc -eq 1 ] && [ '$(snap)' = '$before' ] && grep -q 'from 10.0.0.5 to port 22' '$B/sudo.out'"
kill "$peer" 2> /dev/null; wait "$peer" 2> /dev/null
# sshd on port 2222 under sudo (master plan, PR 1): the port comes from
# the listener's owner (fs_hostnet_ssh_listen_ports, 15.2.4), the peer
# from the TCP table.  The SSH row allows port 22 only, from the LAN.
python3 -I -c '
import ctypes, socket, time
ctypes.CDLL(None).prctl(15, b"sshd", 0, 0, 0)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.0.0.1", 2222)); s.listen()
c = socket.socket(); c.bind(("10.0.0.5", 0)); c.connect(("10.0.0.1", 2222)); a, _ = s.accept()
print("up", flush=True); time.sleep(30)' > "$B/sshd2222.out" &
peer=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do grep -q up "$B/sshd2222.out" 2>/dev/null && break; sleep 0.2; done
"$S" -q policy add outbound-deny-to 198.51.100.7 2> /dev/null
before=$(snap)
"$S" apply < /dev/null > "$B/sudo2222.out" 2>&1; rc=$?
t "lockout under sudo, sshd on 2222: refused (rc $rc), the firewall untouched" bash -c "[ $rc -eq 1 ] && [ '$(snap)' = '$before' ] && grep -q 'from 10.0.0.5 to port 2222' '$B/sudo2222.out'"
kill "$peer" 2> /dev/null; wait "$peer" 2> /dev/null
# Held (audit-only), a start with a journal still installs it
# (fs_firewall_start_lifting), so the guard runs on it as on an unheld
# start (docs 15.2, review notes).  The journal lets SSH in from the
# LAN only; the session is from 10.0.0.5.
"$S" stop > /dev/null 2>&1
mkdir -p "$XDG_CONFIG_HOME/stockfw"
printf '[client]\npolicy_audit_only=true\n' > "$XDG_CONFIG_HOME/stockfw/stockfw.conf"
before=$(snap)
SSH_CONNECTION='10.0.0.5 50000 10.0.0.1 22' "$S" start < /dev/null > "$B/heldstart.out" 2>&1; rc=$?
t "lockout: a held start that installs the journal: refused without --yes (rc $rc), the firewall untouched" bash -c "[ $rc -eq 1 ] && [ '$(snap)' = '$before' ] && grep -q 'pass --yes to start' '$B/heldstart.out'"
SSH_CONNECTION='10.0.0.5 50000 10.0.0.1 22' "$S" start --yes < /dev/null > "$B/heldstarty.out" 2>&1; rc=$?
t "  ...--yes starts it, and says it was held (rc $rc)" bash -c "[ $rc -eq 0 ] && [ '$(snap)' != '$before' ] && grep -q 'Held' '$B/heldstarty.out'"
rm -f "$XDG_CONFIG_HOME/stockfw/stockfw.conf"
exit "$f"
LIVE
  unshare -n bash "$B/live.sh" "$S" "$B" > "$B/live.log" 2>&1
  live_rc=$?
  cat "$B/live.log"
  fails=$((fails + live_rc))
else
  echo "skip: the live A1, lockout and start/stop checks need root, iptables, ip and unshare"
fi
rm -rf "$B"
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
  # A real apply, in a private network namespace: the newest apply entry
  # is that apply, from cli.  The firewall was stopped there, so the gate
  # applies the whole policy and says why (15.2.2, A1); the blocklists may
  # follow it with an intel-apply line of their own, hence --action policy.
  check "audit: after a real apply (netns), the newest apply entry is from cli" c_py "
env = {k: v for k, v in CENV.items() if k != 'STOCKFW_APPLIED_FILE'}
env.update(STOCKFW_AUDIT_FILE='$C/netns-audit.log', STOCKFW_RULES_DIR='$C/netns-rules')
r = subprocess.run(['unshare', '-n', 'sh', '-c', '\"\$0\" policy add inbound-allow-service SSH 22 Anyone >/dev/null && \"\$0\" apply >/dev/null 2>&1 && \"\$0\" --json audit --action policy -n 1', '$S'], capture_output=True, text=True, env=env, timeout=60)
d = json.loads(r.stdout)
e = d['entries'][-1]
assert e['action'] == 'policy applied' and e['origin'] == 'cli' and e['detail'].startswith('full (firewall was stopped) | +1 added'), d"
else
  echo "skip: the audit check after a real apply (needs root and unshare)"
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
# events, connections, listening and interfaces (cli-plan.md WP-D).
# A directory of its own, readable by uid 65534 (the legend check runs
# as nobody when the suite runs as root).
D="$(mktemp -d /tmp/stockfw-wpd-XXXXXX)"; chmod 755 "$D"
export STOCKFW_LOG_FILE="$D/kern.log"
d_run () { env STOCKFW_RULES_DIR="$D/rules" "$@"; }
d_rc () { local want="$1"; shift; d_run "$@" > "$TMP/out" 2> "$TMP/err"; [ "$?" -eq "$want" ]; }
if [ "$(id -u)" = 0 ] && command -v setpriv > /dev/null; then
  d_nobody () { setpriv --reuid=65534 --regid=65534 --clear-groups "$@"; }
else
  d_nobody () { "$@"; }
fi
# Seven events a minute apart: three from 203.0.113.5, two from
# 198.51.100.7 (one with an IN field a spreadsheet would run as a
# formula), one from 192.0.2.44, and one allowed outbound connection.
py "
import datetime
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
def at(m): return (now - datetime.timedelta(minutes=m)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
k = ' host kernel: [1.0] '
open('$D/kern.log', 'w').write('\n'.join([
 at(7) + k + 'STOCKFW-DROP IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=60 TOS=0x10 PROTO=TCP SPT=40000 DPT=22 SYN',
 at(6) + k + 'STOCKFW-DROP IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=40001 DPT=22 SYN',
 at(5) + k + 'STOCKFW-REJECT IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=40002 DPT=3389 SYN',
 at(4) + k + 'STOCKFW-DROP IN=eth0 OUT= SRC=198.51.100.7 DST=10.0.0.5 LEN=40 PROTO=TCP SPT=40003 DPT=445 SYN',
 at(3) + k + 'STOCKFW-DROP IN==SUM(1+1) OUT= SRC=198.51.100.7 DST=10.0.0.5 LEN=76 PROTO=UDP SPT=40004 DPT=161',
 at(2) + k + 'STOCKFW-DROP IN=eth0 OUT= SRC=192.0.2.44 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=40005 DPT=22 SYN',
 at(1) + k + 'STOCKFW-ALLOW IN= OUT=eth0 SRC=10.0.0.5 DST=203.0.113.9 LEN=60 PROTO=TCP SPT=50000 DPT=443 SYN',
]) + '\n')
"
d_json () { "$S" --json events "$@" | python3 -I -c 'import json,sys; print(json.dumps(json.load(sys.stdin)))'; }

check "events: --blocked with --allowed is a usage error (exit 2), not the last one winning" \
  d_rc 2 "$S" events --blocked --allowed
check "events: --proto foo is refused (exit 2) and names the four protocols" \
  bash -c "'$S' events --proto foo 2> '$TMP/err'; [ \$? -eq 2 ] && grep -q 'tcp, udp, icmp or icmpv6' '$TMP/err'"
check "  ...and --proto tpc suggests tcp" \
  bash -c "'$S' events --proto tpc 2> '$TMP/err'; [ \$? -eq 2 ] && grep -q 'did you mean tcp' '$TMP/err'"
check "events: --dir both is every event; inbound and --direction are aliases" py "
import json, subprocess
def q(*a): return json.loads(subprocess.run(['$S', '--json', 'events', *a], capture_output=True, text=True).stdout)
assert len(q('--dir', 'both')) == 7
assert q('--direction', 'inbound') == q('--dir', 'in') and len(q('--dir', 'in')) == 6
assert [e['port'] for e in q('--dir', 'outbound')] == ['443']"
check "events: --port 22,3389 is the union of both ports" py "
import json, subprocess
ev = json.loads(subprocess.run(['$S', '--json', 'events', '--port', '22,3389'], capture_output=True, text=True).stdout)
assert [e['port'] for e in ev] == ['22', '22', '3389', '22'], ev
ev = json.loads(subprocess.run(['$S', '--json', 'events', '--port', '400-500,161'], capture_output=True, text=True).stdout)
assert [e['port'] for e in ev] == ['445', '161', '443'], ev"
check "  ...and a list that cannot be read is a usage error" \
  bash -c "'$S' events --port 22,,80 2> /dev/null; [ \$? -eq 2 ] && '$S' events --port 22,70000 2> /dev/null; [ \$? -eq 2 ]"
check "events --utc: every row starts with an ISO-8601 UTC time" py "
import re, subprocess
out = subprocess.run(['$S', 'events', '--utc'], capture_output=True, text=True).stdout.splitlines()
assert out[0].startswith('TIME') and len(out) == 8, out
assert all(re.match(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ ', l) for l in out[1:]), out"
check "events --wide: IN, OUT, LEN and TOS columns; JSON has length, tos, epoch and rule_name" py "
import json, subprocess
out = subprocess.run(['$S', 'events', '--wide', '-n', '1'], capture_output=True, text=True).stdout.splitlines()
assert out[0].split()[:5] == ['TIME', 'VERDICT', 'DIR', 'IN', 'OUT'] and 'LEN' in out[0] and 'TOS' in out[0], out
ev = json.loads(subprocess.run(['$S', '--json', 'events'], capture_output=True, text=True).stdout)
assert ev[0]['length'] == 60 and ev[0]['tos'] == '0x10' and ev[1]['tos'] is None, ev[:2]
assert isinstance(ev[0]['epoch'], int) and ev[0]['rule_name'] is None, ev[0]"
check "events --csv: a header and one row per event; a formula in a field is made harmless" py "
import csv, io, subprocess
rows = list(csv.reader(io.StringIO(subprocess.run(['$S', 'events', '--csv'], capture_output=True, text=True).stdout)))
assert rows[0] == ['time', 'direction', 'in', 'out', 'port', 'source', 'destination', 'length', 'tos', 'protocol', 'service', 'action', 'rule'], rows[0]
assert len(rows) == 8 and rows[5][4] == '161' and rows[5][2] == \"'=SUM(1+1)\", rows[5]
assert rows[1][10] == 'SSH' and rows[1][11] == 'blocked' and rows[7][11] == 'allowed', rows"
check "events -r: newest first" py "
import json, subprocess
def q(*a): return json.loads(subprocess.run(['$S', '--json', 'events', *a], capture_output=True, text=True).stdout)
assert q('-r') == list(reversed(q())) and q('-r', '-n', '2')[0]['port'] == '443'"
check "events: port 3389 is Remote Desktop and 161 SNMP in the kernel log, not Unknown" \
  bash -c "'$S' events | grep -q '3389 *Remote Desktop' && '$S' events | grep -q '161 *SNMP'"
check "events --history: the RULE column never shows the log marker (STOCKFW-DROP)" \
  bash -c "'$S' events --history-dir '$H' -n 100 > '$TMP/out' && ! grep -q 'STOCKFW-' '$TMP/out' &&
           '$S' --json events --history-dir '$H' | python3 -I -c 'import json,sys; assert all(e[\"rule_name\"] is None for e in json.load(sys.stdin))'"
d_summary () { py "
import collections, json, subprocess
def run(*a): return json.loads(subprocess.run(['$S', '--json', 'events', *a], capture_output=True, text=True).stdout)
d = run('--summary')
src = collections.Counter(['203.0.113.5'] * 3 + ['198.51.100.7'] * 2 + ['192.0.2.44', '10.0.0.5'])
want = sorted(src.items(), key=lambda kv: (-kv[1], kv[0]))
got = [(g['key'], g['blocked'] + g['allowed']) for g in d['by']['src']]
assert got == want, (got, want)
assert d['blocked'] == 6 and d['allowed'] == 1 and d['total'] == 7, d
assert d['by']['port'][0]['key'] == '22/tcp' and d['by']['port'][0]['blocked'] == 3, d['by']['port']
assert d['by']['src'][0]['top_port'] == 22 and d['by']['src'][0]['distinct_ports'] == 2, d['by']['src'][0]
assert sum(b['blocked'] + b['allowed'] for b in d['buckets']) == 7, d['buckets']
blocked = run('--blocked', '-n', '100000', '--since', '24h')
assert sum(g['blocked'] for g in d['by']['src']) == len(blocked) == 6
p = run('--summary', '--port', '22,445', '--by', 'src')
assert p['total'] == len(run('--port', '22,445', '-n', '100000')) == 4, p
assert list(p['by']) == ['src'], p['by']"; }
check "events --summary: counts per source and port equal a Counter over the fixture, filters included" d_summary
check "  ...--top, --by hour and the table" py "
import json, subprocess
d = json.loads(subprocess.run(['$S', '--json', 'events', '--summary', '--by', 'src,hour', '--top', '1'], capture_output=True, text=True).stdout)
assert len(d['by']['src']) == 1 and d['by']['src'][0]['key'] == '203.0.113.5' and 'hour' in d['by'], d['by']
out = subprocess.run(['$S', 'events', '--summary'], capture_output=True, text=True).stdout
assert '6 blocked' in out and 'SOURCE' in out and '22/tcp' in out and 'Remote Desktop' in out, out"
check "events: --by with a typo is refused with a suggestion; --by without --summary is refused" \
  bash -c "'$S' events --summary --by sorce 2> '$TMP/err'; [ \$? -eq 2 ] && grep -q 'did you mean src' '$TMP/err' &&
           '$S' events --by src 2> /dev/null; [ \$? -eq 2 ]"
# Review notes (docs 15.2): the CSV rows go through fs_cli_out_safe
# like every other event row.  An interface name may hold ESC (the
# kernel refuses only '/', ':' and blanks); raw, `events --csv' on a
# terminal rewrote the window title and cleared the screen.
py "
import datetime
t = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).strftime('%Y-%m-%dT%H:%M:%S+00:00')
open('$D/esc-kern.log', 'w').write(t + ' host kernel: [1.0] STOCKFW-DROP IN=e\x1b]0;PWNED\x07th0 OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TC\x1b[2JP SPT=40000 DPT=22 SYN\n')
"
d_csv_esc () { py "
import csv, io, os, subprocess
env = dict(os.environ, STOCKFW_LOG_FILE='$D/esc-kern.log')
piped = subprocess.run(['$S', 'events', '--csv'], capture_output=True, env=env).stdout
tty = subprocess.run(['script', '-qec', '$S events --csv', '/dev/null'], capture_output=True, env=env).stdout
for out in (piped, tty):
    assert b'\x1b' not in out and b'\x07' not in out, out
    assert b'e\\\\x1b]0;PWNED\\\\x07th0' in out and b'TC\\\\x1b[2JP' in out, out
rows = list(csv.reader(io.StringIO(piped.decode())))
assert len(rows) == 2 and rows[1][2] == 'e\\\\x1b]0;PWNED\\\\x07th0', rows"; }
check "events --csv: ESC and BEL from the log are escaped (\\x1b), piped and on a terminal, never raw" d_csv_esc
# `events --summary' over thousands of years: the bar step is worked
# out in 64 bits.  It wrapped a guint round to 0 and died of SIGFPE.
d_far_until () { py "
import json, subprocess
for a in (['--until', '9999-12-30'], ['--since', '0001-01-01 00:00', '--until', '9999-12-31 00:00']):
    r = subprocess.run(['$S', '--json', 'events', '--summary', *a], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, (a, r.returncode, r.stderr)
    d = json.loads(r.stdout)
    assert 0 < d['step'] <= 4294967295 and d['step'] % 86400 == 0 and len(d['buckets']) <= 75, (a, d['step'], len(d['buckets']))
r = subprocess.run(['$S', 'events', '--summary', '--until', '9999-12-30'], capture_output=True, text=True, timeout=30)
assert r.returncode == 0 and 'blocked' in r.stdout, (r.returncode, r.stderr)"; }
check "events --summary --until 9999-12-30: answers (exit 0), the step fits, no SIGFPE" d_far_until

# Python helpers for the events -f checks.  wait_reader: block until
# the reader (tail -n 0 -F FILE) has the followed file open, so a line
# appended after it is a live event, however slow the machine.
# interrupt: Ctrl-C to the stockfw process running ARGV0.
# away_from_midnight: wait while local midnight is less than a minute
# away, so "blocked today" cannot roll over in the middle of a check.
FOLLOW_PY=$(cat <<'PYEOF'
import datetime, os, signal, time
def _procs():
    for pid in os.listdir('/proc'):
        if pid.isdigit():
            try:
                yield pid, open('/proc/%s/cmdline' % pid, 'rb').read().split(b'\0')
            except OSError:
                pass
def wait_reader(live, limit=20):
    end = time.time() + limit
    while time.time() < end:
        for pid, argv in _procs():
            if argv[:4] == [b'tail', b'-n', b'0', b'-F'] and len(argv) > 4 and argv[4] == os.fsencode(live):
                try:
                    if any(os.readlink('/proc/%s/fd/%s' % (pid, fd)) == live for fd in os.listdir('/proc/%s/fd' % pid)):
                        return
                except OSError:
                    pass
        time.sleep(0.05)
    raise AssertionError('the event reader never opened %r' % live)
def interrupt(argv0):
    for pid, argv in _procs():
        if argv[0] == os.fsencode(argv0) and b'events' in argv:
            try:
                os.kill(int(pid), signal.SIGINT)
            except OSError:
                pass
def away_from_midnight():
    while True:
        t = datetime.datetime.now()
        secs = t.hour * 3600 + t.minute * 60 + t.second
        if 60 <= secs <= 86400 - 60:
            return
        time.sleep(1)
PYEOF
)
if [ "$(id -u)" = 0 ] && command -v script > /dev/null; then
  # -f on a terminal: the live row sits under the header's columns
  # (1.0.7 printed it with its own widths and merged the service and
  # the protocol), and Ctrl-C ends it with a count on stderr, exit 0.
  d_follow () { py "$FOLLOW_PY
import os, re, subprocess, time, datetime
live = '$D/live.log'
open(live, 'w').write(open('$D/kern.log').read())
env = dict(os.environ, STOCKFW_LOG_FILE=live)
p = subprocess.Popen(['script', '-qec', 'COLUMNS=200 timeout -s INT 30 $S events -n 5 -f; echo rc=\$?', '/dev/null'],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
wait_reader(live)
stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S+00:00')
open(live, 'a').write(stamp + ' host kernel: [9.0] STOCKFW-DROP IN=eth0 OUT= SRC=2001:db8:aaaa:bbbb:cccc:dddd:eeee:1 DST=2001:db8::5 LEN=80 PROTO=TCP SPT=1 DPT=3389 SYN\n')
time.sleep(1)
interrupt('$S')
out = p.communicate(timeout=40)[0].decode('utf-8', 'replace')
# What is left after the last carriage return: the status line of
# 15.2.5 is drawn and cleared with \r before each row.
lines = [re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', l.rstrip('\r')).split('\r')[-1] for l in out.split('\n')]
head = [l for l in lines if l.startswith('TIME')]
row = [l for l in lines if '2001:db8' in l]
assert len(head) == 1 and len(row) == 1, lines
def starts(l): return [m.start() for m in re.finditer(r'(?:^|(?<=  ))\S', l)]
assert starts(row[0]) == starts(head[0]), (head[0], row[0])
assert 'Remote Desktop' in row[0] and 'TCP' in row[0], row[0]
assert any(re.match(r'^1 event \(1 blocked\) in ', l) for l in lines), lines
assert 'rc=0' in lines or 'rc=124' in lines, lines"; }
  check "events -f: a live IPv6 row lines up with the header; Ctrl-C prints a count" d_follow
  # The reader dying ends -f with a reason and exit 1: the followed
  # file deleted (tail -F would wait for it forever), or the reader
  # process gone.
  d_death () { py "
import os, subprocess, time
live = '$D/live-$1.log'
open(live, 'w').write('')
env = dict(os.environ, STOCKFW_LOG_FILE=live)
p = subprocess.Popen(['$S', 'events', '-n', '0', '-f'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
time.sleep(1.5)
t0 = time.time()
if '$1' == 'gone':
    os.unlink(live)
else:
    subprocess.run(['pkill', '-f', 'tail -n 0 -F ' + live])
out, err = p.communicate(timeout=10)
took = time.time() - t0
assert p.returncode == 1 and b'the event reader stopped' in err, (p.returncode, err)
assert took <= 5, took"; }
  check "events -f: the followed file deleted ends it within 5 s, exit 1, with the reason" d_death gone
  check "events -f: the reader process killed ends it within 5 s, exit 1" d_death killed
else
  echo "skip: events -f checks (need root and script(1))"
fi

# listening: the sockets of a fixture /proc/net, the verdicts from the
# What-If engine.  SSH is allowed from the LAN only.
py "
import os
d = '$D/proc'
os.makedirs(d)
hdr = '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n'
def row(i, local, remote, st, inode):
    return '%4d: %s %s %s 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0\n' % (i, local, remote, st, inode)
open(d + '/tcp', 'w').write(hdr + row(0, '00000000:0016', '00000000:0000', '0A', 91001)
  + row(1, '00000000:1538', '00000000:0000', '0A', 91002) + row(2, '0100007F:0277', '00000000:0000', '0A', 91003)
  + ''.join(row(3 + k, '0500000A:0016', '0764336C:%04X' % (40000 + k), '01', 92000 + k) for k in range(16)))
open(d + '/tcp6', 'w').write(hdr)
open(d + '/udp', 'w').write(hdr + row(0, '00000000:14E9', '00000000:0000', '07', 91005))
open(d + '/udp6', 'w').write(hdr)
"
L_ENV=(env STOCKFW_RULES_DIR="$D/rules" STOCKFW_PROC_NET_DIR="$D/proc" STOCKFW_LAN_PREFIX=192.168.1.0/24)
"${L_ENV[@]}" "$S" policy add inbound-allow-service SSH 22 192.168.1.0/24 > /dev/null
d_listen () { py "
import json, subprocess, sys
env = dict(STOCKFW_RULES_DIR='$D/rules', STOCKFW_PROC_NET_DIR='$D/proc', STOCKFW_LAN_PREFIX='192.168.1.0/24')
import os; env = dict(os.environ, **env)
d = json.loads(subprocess.run(['$S', '--json', 'listening'], capture_output=True, text=True, env=env).stdout)
by = {(x['proto'], x['port']): x for x in d}
assert set(by) == {('tcp', 22), ('tcp', 5432), ('tcp', 631), ('udp', 5353)}, by
ssh = by[('tcp', 22)]
want = sys.argv[1] if len(sys.argv) > 1 else '$1'
if want == 'lan':
    assert ssh['lan'] == {'verdict': 'ALLOWED', 'rule_ref': 'inbound-allow-service:1'}, ssh
else:
    assert ssh['lan']['verdict'] == 'BLOCKED', ssh
assert ssh['internet']['verdict'] == 'BLOCKED' and ssh['scope'] == 'all' and ssh['bind'] == '0.0.0.0', ssh
assert by[('tcp', 5432)]['lan']['verdict'] == 'BLOCKED' and by[('tcp', 5432)]['internet']['verdict'] == 'BLOCKED'
assert by[('tcp', 631)]['scope'] == 'local' and by[('tcp', 631)]['lan'] is None
assert by[('udp', 5353)]['scope'] == 'all' and ssh['policy'] == 'saved'"; }
check "listening: SSH limited to the LAN is ALLOWED from it by inbound-allow-service:1, BLOCKED from the internet" d_listen lan
check "  ...the table: the rule that decides, local sockets counted, not shown" \
  bash -c "STOCKFW_RULES_DIR='$D/rules' STOCKFW_PROC_NET_DIR='$D/proc' STOCKFW_LAN_PREFIX=192.168.1.0/24 '$S' listening > '$TMP/out' 2> /dev/null &&
           grep -q '22/tcp .*ALLOWED *BLOCKED *inbound-allow-service:1' '$TMP/out' &&
           grep -q '5432/tcp .*BLOCKED *BLOCKED *default inbound block' '$TMP/out' &&
           ! grep -q '631/tcp' '$TMP/out' && grep -q '+ 1 socket for this computer only' '$TMP/out' &&
           grep -q '0 ports reachable from the internet' '$TMP/out'"
check "  ...-q prints only what the internet reaches: nothing here" \
  bash -c "[ -z \"\$(STOCKFW_RULES_DIR='$D/rules' STOCKFW_PROC_NET_DIR='$D/proc' '$S' -q listening)\" ]"
"${L_ENV[@]}" "$S" policy remove inbound-allow-service 1 > /dev/null
check "listening: with the SSH row removed, 22 is BLOCKED from the LAN too (the What-If join is real)" d_listen none
"${L_ENV[@]}" "$S" policy add inbound-allow-service SSH 22 Anyone > /dev/null
check "  ...and SSH for Anyone is the one line -q prints" \
  bash -c "STOCKFW_RULES_DIR='$D/rules' STOCKFW_PROC_NET_DIR='$D/proc' '$S' -q listening > '$TMP/out' &&
           [ \$(grep -c . '$TMP/out') -eq 2 ] && grep -q '^22/tcp .*ALLOWED *ALLOWED' '$TMP/out'"
check "listening (live): a TCP listener on 127.0.0.1 is local, with its program; a UDP socket is listed" py "
import json, os, socket, subprocess
t = socket.socket(); t.bind(('127.0.0.1', 0)); t.listen(1)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(('0.0.0.0', 0))
env = dict(os.environ, STOCKFW_RULES_DIR='$D/rules')
env.pop('STOCKFW_PROC_NET_DIR', None)
d = json.loads(subprocess.run(['$S', '--json', 'listening'], capture_output=True, text=True, env=env).stdout)
mine = [x for x in d if x['proto'] == 'tcp' and x['port'] == t.getsockname()[1]]
assert len(mine) == 1 and mine[0]['scope'] == 'local' and mine[0]['lan'] is None, mine
assert (mine[0]['program'] or '').startswith('python'), mine
assert any(x['proto'] == 'udp' and x['port'] == u.getsockname()[1] and x['scope'] == 'all' for x in d), d"

# connections: 16 sessions from one address collapse into one row.
check "connections --by remote: 16 fixture sessions are one row, count 16" py "
import json, os, subprocess
env = dict(os.environ, STOCKFW_PROC_NET_DIR='$D/proc')
d = json.loads(subprocess.run(['$S', '--json', 'connections', '--by', 'remote'], capture_output=True, text=True, env=env).stdout)
assert d == [{'key': '108.51.100.7', 'count': 16}], d
c = json.loads(subprocess.run(['$S', '--json', 'connections', '--port', '40003'], capture_output=True, text=True, env=env).stdout)
assert len(c) == 1 and c[0]['remote_port'] == 40003 and c[0]['local_port'] == 22 and c[0]['state'] == 'ESTABLISHED', c
assert json.loads(subprocess.run(['$S', '--json', 'connections', '--state', 'SYN_SENT'], capture_output=True, text=True, env=env).stdout) == []"
check "connections: --state with a typo, --by with a typo and --dir sideways are usage errors" \
  bash -c "'$S' connections --state ESTABLISHD 2> '$TMP/err'; [ \$? -eq 2 ] && grep -q 'did you mean ESTABLISHED' '$TMP/err' &&
           '$S' connections --by remot 2> /dev/null; [ \$? -eq 2 ] && '$S' connections --dir sideways 2> /dev/null; [ \$? -eq 2 ]"
d_legend () { STOCKFW_PROC_NET_DIR="$D/proc" d_nobody "$S" connections > "$TMP/out" 2> "$TMP/err" &&
              grep -q '108.51.100.7' "$TMP/out" && ! grep -q 'another user' "$TMP/out" &&
              { [ "$(id -u)" = 0 ] && ! command -v setpriv > /dev/null || grep -q 'another user' "$TMP/err"; }; }
check "connections: the \"?\" legend goes to stderr (as uid 65534), never into the table on stdout" d_legend

# interfaces --watch: NDJSON per frame, the banner on stderr only.
check "interfaces --watch=1 -c 2 --json: two lines, each a JSON array" py "
import json, subprocess
r = subprocess.run(['$S', '--json', 'interfaces', '--watch=1', '-c', '2'], capture_output=True, text=True, timeout=30)
lines = r.stdout.splitlines()
assert r.returncode == 0 and len(lines) == 2 and all(isinstance(json.loads(l), list) for l in lines), r"
check "interfaces --watch in a pipe: no ESC, and the banner once, on stderr, never on stdout" py "
import subprocess
r = subprocess.run(['$S', 'interfaces', '--watch=1', '-c', '2'], capture_output=True, timeout=30)
assert b'\x1b' not in r.stdout and b'Refreshing' not in r.stdout, r.stdout
assert r.stderr.count(b'Refreshing every 1 s') == 1 and r.stdout.count(b'ADAPTER') == 2, r"

export STOCKFW_LOG_FILE="$TMP/kern.log"
rm -rf "$D"
# === end WP-D ===

# === WP-F ===
# The live event line of events -f (master plan PR 1, adjustment 2):
# a status line on stderr under the rows, only when stdout and stderr
# are both terminals.  The checks run events -f under script(1), set
# the size with stty inside it, append fixture lines while it follows,
# and read the raw bytes of the terminal.  events -f needs root.
if [ "$(id -u)" = 0 ] && command -v script > /dev/null && command -v stty > /dev/null; then
  F="$(mktemp -d /tmp/stockfw-wpf-XXXXXX)"; chmod 755 "$F"
  # f_run NAME MODE SHELL-COMMAND: follow a fresh copy of the fixture
  # under script, append three lines (two blocked, one allowed) once
  # the reader has the file open, then Ctrl-C, and save the raw
  # terminal bytes in $F/NAME.out.  In the command, $S is stockfw and
  # the followed file's name holds an ESC and a U+202E.  MODE "held"
  # turns audit-only on first.  Not within a minute of midnight, so
  # the history line is today's and the count does not roll over.
  f_run () { py "$FOLLOW_PY
away_from_midnight()
import datetime, os, subprocess, time
F, name, mode, cmd = '$F', '$1', '$2', '''$3'''
live = F + '/' + name + '-\x1b[2J\u202e.log'
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
def at(s): return (now - datetime.timedelta(seconds=s)).strftime('%Y-%m-%dT%H:%M:%S+00:00')
k = ' host kernel: [1.0] '
bad_in = 'e\x1b]0;pwn\x07th\u202e0'
open(live, 'w').write(at(30) + k + 'STOCKFW-DROP IN=' + bad_in + ' OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=40000 DPT=22 SYN\n'
                      + at(20) + k + 'STOCKFW-ALLOW IN= OUT=eth0 SRC=10.0.0.5 DST=203.0.113.9 LEN=60 PROTO=TCP SPT=50000 DPT=443 SYN\n')
cfg = F + '/cfg-' + name
os.makedirs(cfg + '/stockfw', exist_ok=True)
open(cfg + '/stockfw/stockfw.conf', 'w').write('[client]\npolicy_audit_only=true\n' if mode == 'held' else '')
env = dict(os.environ, STOCKFW_LOG_FILE=live, STOCKFW_RULES_DIR=F + '/rules', XDG_CONFIG_HOME=cfg,
           XDG_DATA_HOME=F + '/data', TERM='xterm', S='$S', OUT=F + '/' + name + '.pipe')
env.pop('COLUMNS', None)
p = subprocess.Popen(['script', '-qec', cmd, '/dev/null'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
wait_reader(live)
with open(live, 'a') as f:
    f.write(at(0) + k + 'STOCKFW-DROP IN=' + bad_in + ' OUT= SRC=198.51.100.1 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=1 DPT=23 SYN\n')
    f.flush(); time.sleep(0.5)
    f.write(at(0) + k + 'STOCKFW-ALLOW IN= OUT=eth0 SRC=10.0.0.5 DST=198.51.100.2 LEN=60 PROTO=TCP SPT=2 DPT=443 SYN\n')
    f.flush(); time.sleep(0.5)
    f.write(at(0) + k + 'STOCKFW-REJECT IN=' + bad_in + ' OUT= SRC=198.51.100.3 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=3 DPT=3389 SYN\n')
time.sleep(1)
interrupt('$S')
open(F + '/' + name + '.out', 'wb').write(p.communicate(timeout=40)[0])"; }
  # f_check NAME PYTHON: assertions on the bytes ($F/NAME.out is `out').
  f_check () { py "
import re, json
out = open('$F/$1.out', 'rb').read()
STATUS = re.compile(rb'\r\x1b\[K(?:\x1b\[[0-9;]*m)*((?:running|stopped|locked|state unknown)\b[^\r\n\x1b]*)')
lines = [m.group(1).decode('utf-8') for m in STATUS.finditer(out)]
$2"; }
  # No status line -- and the run did work: the appended rows are there
  # and nothing was refused.
  f_none () { f_check "$1" "
assert b'\x1b[K' not in out and b'blocked today' not in out, out
assert out.count(b'198.51.') >= 3, out
assert b'error:' not in out and b'unknown option' not in out, out"; }

  f_run tty plain 'stty rows 20 cols 100; timeout -s INT 30 "$S" --full events -n 5 -f --wide'
  check "events -f: on a terminal the stderr status line is redrawn after every event row" f_check tty "
rows = re.findall(rb'198\.51\.100\.[0-9] [^\r\n]*\r\n\r\x1b\[K(?:\x1b\[[0-9;]*m)*(?:running|stopped|locked|state unknown) ', out)
assert len(rows) == 3, out
assert lines and all('blocked today' in l and 'Sentinel auto' in l for l in lines), lines
assert 'HELD' not in out.decode('utf-8', 'replace')"
  check "  ...blocked today rises by exactly the two blocked lines appended (not the allowed one)" f_check tty "
n = [int(re.search(r'blocked today ([0-9]+)', l).group(1)) for l in lines]
assert n[0] >= 1 and n[-1] == n[0] + 2 and sorted(n) == n, n"
  check "  ...the line fits 100 columns (stty cols 100) and is cleared before the count at Ctrl-C" f_check tty "
assert all(len(l) <= 99 for l in lines), [len(l) for l in lines]
assert re.search(rb'\r\x1b\[K\r\n3 events \(2 blocked\) in', out), out[-200:]"
  check "  ...ESC and U+202E from the log are escaped in the rows and on the status line" f_check tty "
assert b'\x1b]' not in out and b'\x07' not in out and b'\x1b[2J' not in out and '\u202e'.encode() not in out, out
low = out.lower()
assert len(re.findall(rb'e\\\\x1b\]0;pwn\\\\x07th\\\\u202e0', low)) == 3, out
assert all('\\\\x1b[2J\\\\u202e.log' in l for l in lines), lines"

  f_run held held 'stty rows 20 cols 100; timeout -s INT 30 "$S" events -n 1 -f'
  check "events -f: with audit-only on, the line says HELD (audit-only)" f_check held "
assert lines and all('HELD (audit-only)' in l for l in lines), lines"

  f_run narrow plain 'stty rows 20 cols 0; COLUMNS=60 timeout -s INT 30 "$S" events -n 1 -f'
  check "events -f: a terminal with no width (ws_col 0) falls back to COLUMNS=60" f_check narrow "
assert lines and all(len(l) <= 59 and l.endswith(('\u2026', '...')) for l in lines), lines"

  f_run ndjson plain 'stty rows 20 cols 100; timeout -s INT 30 "$S" --json events -n 2 -f | head -n 4 > "$OUT"'
  check "events -f --json | head: only event objects, one per line, and no status line" f_check ndjson "
objs = [json.loads(l) for l in open('$F/ndjson.pipe').read().splitlines()]
assert len(objs) == 4 and all(isinstance(o, dict) and 'blocked' in o and 'source' in o for o in objs), objs
assert b'\x1b[K' not in out and b'blocked today' not in out, out"

  f_run json plain 'stty rows 20 cols 100; timeout -s INT 30 "$S" --json events -n 1 -f'
  check "events -f --json on a terminal: no status line" f_none json
  f_run nostat plain 'stty rows 20 cols 100; timeout -s INT 30 "$S" events -n 1 -f --no-status-line'
  check "events -f --no-status-line: no status line" f_none nostat
  f_run quiet plain 'stty rows 20 cols 100; timeout -s INT 30 "$S" -q events -n 1 -f'
  check "events -q -f: no status line" f_none quiet
  f_run dumb plain 'stty rows 20 cols 100; TERM=dumb timeout -s INT 30 "$S" events -n 1 -f'
  check "events -f with TERM=dumb: no status line" f_none dumb
  f_run pipe plain 'stty rows 20 cols 100; timeout -s INT 30 "$S" events -n 1 -f | cat'
  check "events -f into a pipe: no status line" f_none pipe

  # Midnight: the first blocked event of a new day is counted in it.
  # fake-clock.so moves the wall clock of stockfw (not its timers) to
  # 23:59:55 UTC; once midnight has passed and before the next 2 s
  # redraw, one DROP is appended.  1.0.7's line counted it, then the
  # redraw saw the new day and wiped it: "blocked today 0" all day.
  # A run whose redraw falls too close after midnight proves nothing
  # and is run again one second later.
  if cc -shared -fPIC -o "$F/fake-clock.so" tests/fake-clock.c -ldl 2> /dev/null; then
    f_midnight () { py "$FOLLOW_PY
import datetime, os, re, select, subprocess, time
F, start = '$F', int('$1')
live = F + '/midnight-%d.log' % start
open(live, 'w').write('')
os.makedirs(F + '/cfg-midnight/stockfw', exist_ok=True)
open(F + '/cfg-midnight/stockfw/stockfw.conf', 'w').write('')
day = datetime.datetime.now(datetime.timezone.utc).replace(hour=23, minute=59, second=start, microsecond=0)
off = day.timestamp() - time.time()
midnight = day.timestamp() + (60 - start) - off          # in real time
env = dict(os.environ, STOCKFW_LOG_FILE=live, STOCKFW_RULES_DIR=F + '/rules', XDG_CONFIG_HOME=F + '/cfg-midnight',
           XDG_DATA_HOME=F + '/data', TERM='xterm', TZ='UTC', S='$S', SO=F + '/fake-clock.so',
           FAKE_OFFSET_US=str(int(off * 1e6)))
env.pop('COLUMNS', None)
cmd = 'stty rows 20 cols 100; timeout -s INT 30 env LD_PRELOAD=\"\$SO\" \"\$S\" events -n 0 -f'
p = subprocess.Popen(['script', '-qec', cmd, '/dev/null'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
out, draws = b'', []
def pump(until):
    global out
    while time.time() < until:
        r, _, _ = select.select([p.stdout], [], [], 0.02)
        if r:
            chunk = os.read(p.stdout.fileno(), 65536)
            if not chunk:
                return
            out += chunk
            if b'blocked today' in chunk:
                draws.append(time.time())
wait_reader(live)
pump(midnight + 0.15)
before = [t for t in draws if t < midnight]
assert before, out
nxt = before[-1] + 2.0
if nxt - time.time() < 0.6:
    interrupt('$S'); p.communicate(timeout=40)
    print('retry'); raise SystemExit(3)
open(live, 'a').write(datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S+00:00')
                      + ' host kernel: [1.0] STOCKFW-DROP IN=eth0 OUT= SRC=198.51.100.9 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=1 DPT=23 SYN\n')
pump(time.time() + 0.4)
interrupt('$S')
out += p.communicate(timeout=40)[0]
rows = re.findall(rb'198\.51\.100\.9 [^\r\n]*\r\n\r\x1b\[K(?:\x1b\[[0-9;]*m)*[^\r\n\x1b]*blocked today ([0-9]+)', out)
assert rows == [b'1'], (rows, out[-600:])"; }
    f_midnight 55; rc=$?
    [ "$rc" -eq 3 ] && { f_midnight 54; rc=$?; }
    check "events -f: a blocked event just after midnight counts in the new day (blocked today 1)" [ "$rc" -eq 0 ]
  else
    echo "skip: the midnight check (no C compiler for tests/fake-clock.c)"
  fi
  rm -rf "$F"
else
  echo "skip: the live event line checks (need root, script(1) and stty)"
fi
# === end WP-F ===

# === WP-E ===
# Completion and the manual page (cli-plan.md WP-E): both come from the
# command tables, so they are checked against the tables in the source
# (read here with python, not through the binary), and the completion
# scripts are run the way bash runs them.
E="$TMP/wpe"
mkdir -p "$E"
# Every command and its options, from the tables in src/cli/*.c.
py '
import glob, re
cmds = {}
for path in sorted(glob.glob("src/cli/*.c")):
    src = open(path, encoding="utf-8").read()
    tables = {}
    for m in re.finditer(r"static const FsCliOption (\w+)\[\] = \{(.*?)\n\};", src, re.S):
        tables[m.group(1)] = re.findall(r"\{\s*\"(-[^\"]*)\",", m.group(2))
    for m in re.finditer(r"\n\t\{ \"([a-z][a-z-]*)\", fs_cli_cmd_\w+,", src):
        rest = src[m.end():]
        o = re.search(r"\n\t  (\w+), (?:NULL|\"\w+\") \},", rest)
        cmds[m.group(1)] = tables.get(o.group(1), []) if o else None
with open("'"$E"'/tables", "w") as f:
    for c, opts in cmds.items():
        f.write(c + " " + " ".join(opts if opts is not None else ["?"]) + "\n")
'
check "the command tables were read from the source (at least 15 commands)" \
  test "$(wc -l < "$E/tables")" -ge 15
check "  ...and every command has its option table" \
  bash -c "! grep -q ' ?\$' '$E/tables'"
"$S" __complete '' > "$E/cmds" 2> "$E/err"
missing=""
while read -r c _; do
  grep -qx -- "$c" "$E/cmds" || missing="$missing $c"
done < "$E/tables"
check "__complete '' lists every command of the tables (missing:$missing)" \
  test -z "$missing"
check "  ...and help and version, and nothing on stderr" \
  bash -c "grep -qx help '$E/cmds' && grep -qx version '$E/cmds' && [ ! -s '$E/err' ]"
check "  ...but not the hidden __complete and __man" \
  bash -c "! grep -q '^__' '$E/cmds' && ! '$S' help | grep -q '__'"
missing=""
while read -r c opts; do
  "$S" __complete "$c" - > "$E/opts" 2>/dev/null
  for o in $opts; do
    grep -qx -- "$o" "$E/opts" || missing="$missing $c:$o"
  done
done < "$E/tables"
check "__complete CMD - offers every option of CMD's table (missing:$missing)" \
  test -z "$missing"
check "  ...and the global flags" \
  bash -c "'$S' __complete events - | grep -qx -- --json"
check "__complete policy list - offers --grep but not add's --comment" \
  bash -c "'$S' __complete policy list - > '$E/o' && grep -qx -- --grep '$E/o' && ! grep -qx -- --comment '$E/o'"
check "__complete events --by '' gives the summary keys" \
  bash -c "[ \"\$('$S' __complete events --by '' | tr '\n' ' ')\" = 'src dst port service dir rule hour ' ]"
check "__complete connections --by=p gives --by=program and --by=port" \
  bash -c "[ \"\$('$S' __complete connections --by=p | tr '\n' ' ')\" = '--by=program --by=port ' ]"
check "__complete events --proto '' gives the four protocols" \
  bash -c "[ \"\$('$S' __complete events --proto '' | tr '\n' ' ')\" = 'tcp udp icmp icmpv6 ' ]"
check "a word after -- is a plain word, not an option to complete" \
  bash -c "[ -z \"\$('$S' __complete policy -- -)\" ]"
check "--json anywhere is ignored by __complete" \
  bash -c "[ \"\$('$S' __complete --json copilot '')\" = health ]"
# References from the saved policy.
ER="$E/rules"
check "two rules saved in a scratch policy" \
  bash -c "STOCKFW_RULES_DIR='$ER' '$S' policy add inbound-allow-service SSH 22 192.168.1.0/24 > /dev/null 2>&1 &&
           STOCKFW_RULES_DIR='$ER' '$S' policy add outbound-deny-to 198.51.100.6 > /dev/null 2>&1"
check "__complete policy remove '' prints exactly their 2 references" \
  bash -c "[ \"\$(STOCKFW_RULES_DIR='$ER' '$S' __complete policy remove '' | tr '\n' ' ')\" = 'inbound-allow-service:1 outbound-deny-to:1 ' ]"
STOCKFW_RULES_DIR="$ER" "$S" policy add outbound-deny-to 198.51.100.7 > /dev/null 2>&1
check "  ...and 3 once a third rule is saved" \
  bash -c "[ \"\$(STOCKFW_RULES_DIR='$ER' '$S' __complete policy show '' | wc -l)\" -eq 3 ]"
check "__complete intel '' offers geo, and intel geo add '' country and asn" \
  bash -c "'$S' __complete intel '' | grep -qx geo &&
           [ \"\$('$S' __complete intel geo add '' | tr '\n' ' ')\" = 'country asn ' ]"
# The bash script, run the way bash runs it: COMP_LINE and COMP_POINT
# set, the function called, COMPREPLY read.
BC="contrib/completion/stockfw.bash"
check "bash -n accepts the bash completion" bash -n "$BC"
cat > "$E/comp.sh" <<'EOS'
# comp.sh SCRIPT LINE: what bash offers for LINE, one per line
source "$1"
COMP_LINE="$2"
COMP_POINT=${#COMP_LINE}
COMP_WORDBREAKS=$' \t\n"\'><=;|&(:'
_stockfw
printf '%s\n' "${COMPREPLY[@]}"
EOS
comp () { STOCKFW_RULES_DIR="$ER" bash "$E/comp.sh" "$BC" "$1"; }
out="$(comp "$S sta")"
check "bash: 'stockfw sta' completes to status and start ($(echo $out))" \
  test "$(echo $out)" = "status start"
out="$(comp "$S policy remove outbound-deny-to:")"
check "bash: a reference after its colon completes to the number alone ($(echo $out))" \
  test "$(echo $out)" = "1 2"
out="$(comp "$S events --by=s")"
check "bash: --by=s completes to the value alone ($(echo $out))" \
  test "$(echo $out)" = "src service"
if command -v zsh > /dev/null; then
  check "zsh -n accepts the zsh completion" zsh -n contrib/completion/_stockfw
else
  echo "skip: zsh is not installed; zsh -n is not run"
fi
# The manual page.
"$S" __man > "$E/stockfw.1" 2> "$E/err"
missing=""
while read -r c _; do
  up="$(printf '%s' "$c" | tr a-z A-Z)"
  grep -qx ".SH \"STOCKFW $up\"" "$E/stockfw.1" || missing="$missing $c"
done < "$E/tables"
check "__man has a .SH section for every command (missing:$missing)" \
  test -z "$missing"
check "  ...and NAME, SYNOPSIS, EXIT STATUS, ENVIRONMENT, FILES and EXAMPLES" \
  bash -c "for s in NAME SYNOPSIS '\"EXIT STATUS\"' ENVIRONMENT FILES EXAMPLES; do grep -qx \".SH \$s\" '$E/stockfw.1' || exit 1; done"
check "  ...with the exit codes 0 1 2 3 5 6 7 and no 4" \
  bash -c "[ \"\$(sed -n '/^\\.SH \"EXIT STATUS\"/,/^\\.SH ENV/p' '$E/stockfw.1' | grep -A1 '^\\.TP' | grep '^\\.B' | tr -d '.B \n')\" = 0123567 ]"
check "  ...names every STOCKFW_ variable src/cli reads" \
  bash -c "for v in \$(grep -oh 'getenv (\"STOCKFW_[A-Z_]*' src/cli/*.c | sed 's/.*\"//' | sort -u); do grep -q \"^\\.B \$v\\\$\" '$E/stockfw.1' || { echo \"missing \$v\"; exit 1; }; done"
check "  ...is the page the build wrote" cmp -s "$E/stockfw.1" "$BUILD/stockfw.1"
check "  ...SEE ALSO names no StockFW(1) page (there is none)" \
  bash -c "! grep -q '^\\.BR StockFW' '$E/stockfw.1' && grep -q '^\\.BR nft (8),' '$E/stockfw.1'"
# apply -n is an accepted alias of --dry-run that stays undocumented.
check "apply -n: still a dry run, but not on the page or in completion" \
  bash -c "a=\$('$S' apply -n 2>&1); ra=\$?; b=\$('$S' apply --dry-run 2>&1); rb=\$?;
           [ \$ra -ne 2 ] && [ \$ra -eq \$rb ] && [ \"\$a\" = \"\$b\" ] &&
           ! '$S' __complete apply - | grep -qx -- -n &&
           '$S' __complete apply - | grep -qx -- --dry-run &&
           ! sed -n '/^\\.SH \"STOCKFW APPLY\"/,/^\\.SH \"STOCKFW START\"/p' '$E/stockfw.1' | grep -qF '\\fB\\-n\\fR'"
if command -v groff > /dev/null; then
  groff -man -Tutf8 -ww "$E/stockfw.1" > /dev/null 2> "$E/groff.err"
  check "groff -man -Tutf8 -ww reads it without a warning" \
    bash -c "[ ! -s '$E/groff.err' ] || { cat '$E/groff.err'; false; }"
  # A dash must come out as the ASCII minus, or an option copied from
  # the page (--dry-run) is not the option the parser knows.
  groff -man -Tutf8 "$E/stockfw.1" 2> /dev/null | sed 's/\x1b\[[0-9;]*m//g' > "$E/page.txt"
  check "  ...and options print with ASCII dashes, ready to copy" \
    bash -c "grep -q -- 'stockfw apply \\[--dry-run' '$E/page.txt' && ! grep -q \$'\\u2010' '$E/page.txt'"
else
  echo "skip: groff is not installed; the page is not formatted"
fi
# CMake's install rules put the page and the completion where man, bash
# and zsh look.
if cmake --install "$BUILD" --prefix "$E/inst" > "$E/install.log" 2>&1; then
  check "cmake --install puts in share/man/man1/stockfw.1, bash and zsh completion" \
    bash -c "cmp -s '$E/inst/share/man/man1/stockfw.1' '$BUILD/stockfw.1' &&
             cmp -s '$E/inst/share/bash-completion/completions/stockfw' contrib/completion/stockfw.bash &&
             cmp -s '$E/inst/share/zsh/site-functions/_stockfw' contrib/completion/_stockfw"
else
  check "cmake --install into a scratch prefix ($(tail -1 "$E/install.log"))" false
fi
# The wording guard of test-core.sh, over what these commands print.
{ cat "$E/stockfw.1" "$E/cmds"
  while read -r c _; do "$S" __complete "$c" - ; "$S" __complete "$c" ''; done < "$E/tables"
} > "$E/all-generated" 2>/dev/null
check "no \"AI\" wording in the generated page or completions" \
  bash -c "! grep -nE '\\bAI\\b|AI-' '$E/all-generated'"
# No GTK in the command-line tool (master plan PR 1, adjustment 5);
# tests/test-nogui-build.sh builds it with FS_BUILD_GUI=OFF and GTK
# hidden from pkg-config.
if command -v readelf > /dev/null; then
  check "stockfw needs no GTK, GDK, Pango or cairo library" \
    bash -c "! readelf -d '$S' | grep -Ei 'gtk|gdk|pango|cairo'"
fi
# === end WP-E ===

echo ""
if [ "$fails" -eq 0 ]; then
  echo "PASSED: 0 failure(s)"
else
  echo "FAILED: $fails failure(s)"
fi
exit "$fails"
