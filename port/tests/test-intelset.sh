#!/bin/bash
# Threat-intel rule set -> nftables, against a real nft (1.0.7, design
# section 7).
#
# Runs in private network namespaces: it re-executes itself under
# `unshare -n', makes a peer namespace joined to it by a veth pair, and
# for forwarding a client and a server routed through this one.  Nothing
# here reaches the host, and it all vanishes with the namespaces.  Needs
# root, nft, unshare, nsenter, ip and python3; SKIPs without them.
#
# What it proves, beyond test-intelset.c's byte-for-byte checks:
#   - nft -c accepts the script of every fixture: one family only, an
#     empty set, sets that are all empty, the empty rule set, a
#     40-character id, 2500 elements, exactly 1000 and 1001 elements;
#   - an apply is live with the digest it was applied with; a second
#     apply replaces the first (its sets and rules are gone); a
#     transaction the kernel rejects part-way leaves the previous table
#     and its digest in force (teeth: deleting in a separate nft call);
#   - the six direction cells, each a real TCP connection over the
#     veth pair, (a) started by the listed peer, (b) started here:
#        in    (a) dropped, times out    (b) works: replies pass
#        out   (a) works                 (b) rejected: fails at once
#        both  (a) dropped, times out    (b) rejected: fails at once
#     and the same six over UDP, a query and its answer;
#   - this computer always reaches its own addresses over loopback,
#     even listed ones, in every direction;
#   - the counters of an id move with blocked attempts, sum every rule
#     of the id, and match what `nft list chain' prints;
#   - clear removes our table and only it, and clearing twice is fine;
#   - forwarding: an in set drops a routed connection the listed client
#     starts, an out set rejects one to a listed server, and the other
#     direction works in both cases;
#   - nft that hangs is killed after the timeout and the apply or the
#     listing says it timed out, also when a child of it keeps its
#     pipes open; nft that quits without reading the script is an
#     error, not a SIGPIPE that kills the caller; a listing that cannot
#     be read is "unknown", never "absent".
# IPv6 is checked as rule text and with nft -c only: no IPv6 packet is
# sent here (the output says why).
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
DRV="${STOCKFW_INTELSET_DRIVER:-$PORT/build-linux/fs-intelset-driver}"

if [ "${STOCKFW_IN_NETNS:-}" != 1 ]; then
  if [ "$(id -u)" != 0 ]; then
    echo "SKIP: needs root"
    exit 0
  fi
  for tool in nft unshare nsenter ip python3; do
    if ! command -v "$tool" >/dev/null; then
      echo "SKIP: needs $tool"
      exit 0
    fi
  done
  if [ ! -x "$DRV" ]; then
    echo "SKIP: $DRV not built -- ninja -C build-linux fs-intelset-driver"
    exit 0
  fi
  if ! unshare -n true 2>/dev/null; then
    echo "SKIP: cannot make a network namespace here (unshare -n)"
    exit 0
  fi
  export STOCKFW_INTELSET_DRIVER="$DRV"
  STOCKFW_IN_NETNS=1 exec unshare -n "$0" "$@"
fi

REAL_NFT="$(command -v nft)"
W="$(mktemp -d)"
PIDS=""
cleanup() {
  # Quiet: the shell reports background jobs it reaps as "Killed", and
  # the summary must stay the last line.
  exec 2>/dev/null
  for p in $PIDS; do kill -KILL "$p"; done
  wait
  rm -rf "$W"
}
trap cleanup EXIT

fails=0
ok()   { echo "ok:   $*"; }
bad()  { echo "FAIL: $*"; fails=$((fails + 1)); }
check() { if eval "$1"; then ok "$2"; else bad "$2"; fi; }

# spec NAME LINE... -> writes $W/NAME.spec, prints its path
spec() {
  local f="$W/$1.spec"
  shift
  printf '%s\n' "$@" > "$f"
  echo "$f"
}

# --------------------------------------------------------------- helpers
cat > "$W/listen.py" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(16)
print("listening", flush=True)
while True:
    c, _ = s.accept()
    try:
        c.sendall(b"hi\n")
    except OSError:
        pass
    c.close()
EOF

# A UDP echo: every datagram comes back with "re:" in front.
cat > "$W/udpecho.py" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], int(sys.argv[2])))
print("listening", flush=True)
while True:
    data, peer = s.recvfrom(512)
    s.sendto(b"re:" + data, peer)
EOF

# One UDP query: "<result> <seconds>": answered, timeout, or the errno
# name (an ICMP error arrives on a connected UDP socket).
cat > "$W/udpask.py" <<'EOF'
import errno, socket, sys, time
addr, port, limit = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(limit)
t = time.monotonic()
try:
    s.connect((addr, port))
    s.send(b"query")
    result = "answered" if s.recv(512) == b"re:query" else "garbled"
except socket.timeout:
    result = "timeout"
except OSError as e:
    result = errno.errorcode.get(e.errno, "errno%d" % e.errno)
print("%s %.3f" % (result, time.monotonic() - t))
EOF

# Prints "<result> <seconds>": connected, timeout, or the errno name.
cat > "$W/connect.py" <<'EOF'
import errno, socket, sys, time
addr, port, limit = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(limit)
t = time.monotonic()
try:
    s.connect((addr, port))
    data = s.recv(16)
    result = "connected" if data.startswith(b"hi") else "connected-without-greeting"
except socket.timeout:
    result = "timeout"
except OSError as e:
    result = errno.errorcode.get(e.errno, "errno%d" % e.errno)
print("%s %.3f" % (result, time.monotonic() - t))
EOF

# A namespace to stand in for another machine: a sleeping process
# holds it.  Waits until the process really is in a new namespace, so
# a veth end moved "into" it cannot land in ours.
new_ns() {
  unshare -n sleep 600 &
  local pid=$!
  PIDS="$PIDS $pid"
  for _ in $(seq 100); do
    if [ "$(readlink "/proc/$pid/ns/net")" != "$(readlink /proc/self/ns/net)" ]; then
      NS=$pid
      return 0
    fi
    sleep 0.05
  done
  return 1
}

in_ns() {   # in_ns PID-or-empty CMD...
  local pid="$1"
  shift
  if [ -n "$pid" ]; then nsenter -t "$pid" -n "$@"; else "$@"; fi
}

start_listener() {   # start_listener PID-or-empty ADDR PORT [SERVER.py]
  local server="${4:-listen.py}"
  local log="$W/$server-$2-$3.log"
  # Started directly, not through a function, so $! is the listener
  # itself and cleanup's kill reaches it.
  if [ -n "$1" ]; then
    nsenter -t "$1" -n python3 -I "$W/$server" "$2" "$3" > "$log" 2>&1 &
  else
    python3 -I "$W/$server" "$2" "$3" > "$log" 2>&1 &
  fi
  PIDS="$PIDS $!"
  for _ in $(seq 100); do
    grep -q listening "$log" 2>/dev/null && return 0
    sleep 0.05
  done
  echo "      (listener on $2:$3 did not start: $(cat "$log"))"
  return 1
}

conn() {   # conn PID-or-empty ADDR PORT -> "<result> <seconds>"
  in_ns "$1" python3 -I "$W/connect.py" "$2" "$3" 3
}

uask() {   # uask PID-or-empty ADDR PORT -> "<result> <seconds>"
  in_ns "$1" python3 -I "$W/udpask.py" "$2" "$3" 1.5
}

works()     { [ "${1%% *}" = connected ]; }
answered()  { [ "${1%% *}" = answered ]; }
times_out() { [ "${1%% *}" = timeout ]; }
# Rejected: refused by an ICMP admin-prohibited error, well inside the
# 3 s a dropped connection takes to time out.
fails_fast() {
  [ "${1%% *}" = EHOSTUNREACH ] &&
    awk -v t="${1##* }" 'BEGIN { exit !(t < 1.0) }'
}
# A datagram this computer sends is refused by the send itself (EPERM:
# the output hook did not let it out), or by the ICMP error after it.
udp_refused() {
  case "${1%% *}" in EPERM|EHOSTUNREACH) ;; *) return 1 ;; esac &&
    awk -v t="${1##* }" 'BEGIN { exit !(t < 1.0) }'
}

# The packets and bytes nft itself prints for one id, over all chains.
listed_counter() {
  { nft list chain inet stockfw_intel input
    nft list chain inet stockfw_intel output
    nft list chain inet stockfw_intel forward; } 2>/dev/null |
  awk -v id="$1" -v want="comment \"$1\"" '
    index($0, want) && /counter packets/ {
      for (i = 1; i < NF; i++) {
        if ($i == "packets") p += $(i + 1)
        if ($i == "bytes") b += $(i + 1)
      }
    }
    END { printf "%s %d %d\n", id, p, b }'
}

chain_packets() {   # chain_packets CHAIN ID -> packets of that id in it
  nft list chain inet stockfw_intel "$1" 2>/dev/null |
  awk -v want="comment \"$2\"" '
    index($0, want) && /counter packets/ {
      for (i = 1; i < NF; i++) if ($i == "packets") p += $(i + 1)
    }
    END { print p + 0 }'
}

# -------------------------------------------------------------- fixtures
LONG_ID="a123456789-123456789-123456789-123456789"   # 40, the longest id
F_IN4="$(spec in4 'feed-in in 192.0.2.0/24 198.51.100.7')"
F_OUT6="$(spec out6 'feed-out out 2001:db8:bad::/48 2001:db8:beef::1-2001:db8:beef::9')"
F_BOTH="$(spec both46 'feed-both both 203.0.113.0/25 2001:db8:c0de::/64')"
F_SEVERAL="$(spec several \
  'feed-in in 192.0.2.0/24 198.51.100.7' \
  'feed-out out 2001:db8:bad::/48' \
  'feed-both both 203.0.113.0/25 2001:db8:c0de::/64' \
  "$LONG_ID both 198.51.100.64/26")"
F_EMPTYSET="$(spec emptyset 'not-fetched-yet both' 'feed-in in 192.0.2.0/24')"
F_EMPTY="$(spec empty '# no sets at all: the table is removed')"
# Sets, but every one of them empty: a table with only its chains.
F_ALLEMPTY="$(spec allempty 'quiet-a both' 'quiet-b in' 'quiet-c out')"
python3 -I - "$W/big.spec" "$W/huge.spec" "$W/k1000.spec" "$W/k1001.spec" <<'EOF'
import sys
def singles(base, n):
    return " ".join("198.18.%d.%d" % divmod(base + 2 * i, 256) for i in range(n))
with open(sys.argv[1], "w") as f:
    # 2500 separate IPv4 intervals (three add-element statements) and
    # 300 IPv6 ones, in one set; a second set beside it.
    v6 = " ".join("2001:db8:%x::1" % i for i in range(300))
    f.write("big both %s %s\n" % (singles(0, 2500), v6))
    f.write("small in 192.0.2.77\n")
with open(sys.argv[2], "w") as f:
    # Big enough that its script overflows a pipe buffer (64 KiB).
    f.write("huge in %s\n" % " ".join("10.%d.%d.1" % (i // 256, i % 256) for i in range(9000)))
# Exactly one statement's worth of elements, and one more.
with open(sys.argv[3], "w") as f:
    f.write("edge both %s\n" % singles(0, 1000))
with open(sys.argv[4], "w") as f:
    f.write("edge both %s\n" % singles(0, 1001))
EOF
F_BIG="$W/big.spec"
F_HUGE="$W/huge.spec"
F_K1000="$W/k1000.spec"
F_K1001="$W/k1001.spec"

# ------------------------------------------------------ 1. nft -c accepts
for f in "$F_IN4" "$F_OUT6" "$F_BOTH" "$F_SEVERAL" "$F_EMPTYSET" "$F_EMPTY" \
         "$F_ALLEMPTY" "$F_BIG" "$F_K1000" "$F_K1001"; do
  out="$("$DRV" check "$f" 2>&1)"; rc=$?
  check '[ $rc -eq 0 ] && [ "$out" = ok ]' "nft -c accepts the script of $(basename "$f") (${out:0:80})"
done
n1000="$("$DRV" script "$F_K1000" | grep -c "^add element ")"
n1001="$("$DRV" script "$F_K1001" | grep -c "^add element ")"
check '[ "$n1000" -eq 1 ] && [ "$n1001" -eq 2 ]' \
      "1000 elements are one add-element statement and 1001 are two, none empty (got $n1000, $n1001)"
s="$("$DRV" script "$F_EMPTYSET")"
check '! grep -q "not_fetched_yet" <<<"$s" && grep -q "s_feed_in_4" <<<"$s"' \
      "a set with no addresses has no nft set and no rules, and nft -c still accepts the script"
s="$("$DRV" script "$F_IN4")"
check '! grep -q "ip6\|_6 " <<<"$s"' "an IPv4-only set has no IPv6 set and no IPv6 rules"
n="$("$DRV" script "$F_BIG" | grep -c "^add element inet stockfw_intel s_big_4 ")"
check '[ "$n" -eq 3 ]' "2500 IPv4 elements go in 3 add-element statements, and nft accepts them (got $n)"

# ------------------------------------------ 2. apply, digest, replace
ip link set lo up
out="$("$DRV" apply "$F_SEVERAL")"; rc=$?
d_several="$("$DRV" digest "$F_SEVERAL")"
check '[ $rc -eq 0 ] && [ "$out" = "applied $d_several" ]' "the rule set applies (${out:0:60})"
live="$("$DRV" live)"
check '[ "$live" = "present $d_several" ]' "the live digest read back is the applied one ($live)"
check 'nft list set inet stockfw_intel s_feed_in_4 | grep -q "192.0.2.0/24"' "its sets are in the kernel"
check 'nft list chain inet stockfw_intel input | grep -q "ip saddr @s_a123456789_123456789_123456789_123456789_4 counter"' \
      "a 40-character id makes a working set name, rule and comment"

# IPv6: as rule text only.
if [ -d /proc/sys/net/ipv6 ]; then
  why="this test sends no IPv6 traffic"
else
  why="this kernel has no IPv6 (/proc/sys/net/ipv6 is missing), so no IPv6 packet can be sent"
fi
echo "note: IPv6 is checked as rule text and with nft -c only: $why"
out_chain="$(nft list chain inet stockfw_intel output)"
fwd_chain="$(nft list chain inet stockfw_intel forward)"
in_chain="$(nft list chain inet stockfw_intel input)"
check 'grep -q "ip6 daddr @s_feed_out_6 ct direction original counter packets 0 bytes 0 reject with icmpx admin-prohibited comment \"feed-out\"" <<<"$out_chain"' \
      "IPv6 (text): an out set rejects in output, only connections this side starts"
check 'grep -q "ip6 daddr @s_feed_out_6 ct direction original counter" <<<"$fwd_chain"' \
      "IPv6 (text): ... and in forward"
check 'grep -q "ip6 saddr @s_feed_both_6 counter packets 0 bytes 0 drop comment \"feed-both\"" <<<"$in_chain" && ! grep -q "s_feed_out_6" <<<"$in_chain"' \
      "IPv6 (text): a both set drops every packet in input; an out set has no input rule"

F_B="$(spec second 'feed-b in 198.51.100.0/24')"
d_b="$("$DRV" digest "$F_B")"
out="$("$DRV" apply "$F_B")"; rc=$?
live="$("$DRV" live)"
check '[ $rc -eq 0 ] && [ "$live" = "present $d_b" ]' "a second apply is live with its own digest ($live)"
check '! nft list set inet stockfw_intel s_feed_in_4 >/dev/null 2>&1' \
      "the first rule set's sets are gone: replaced, not merged"
check '! nft list chain inet stockfw_intel input | grep -q "feed-in\|feed-both"' "and so are its rules"
check 'nft list set inet stockfw_intel s_feed_b_4 | grep -q "198.51.100.0/24"' "the second rule set's set is there"

# --------------------------- 3. a transaction the kernel rejects part-way
mkdir -p "$W/bin"
cat > "$W/bin/nft" <<EOF
#!/bin/bash
# The real nft.  A script that loads elements gets one more statement
# that parses but that the kernel refuses (the table does not exist),
# so the whole transaction is aborted.  Anything else -- a bare delete
# sent on its own -- passes untouched, so an apply that deleted the old
# table in a separate nft call would lose it.
case " \$* " in
  *" -f "*) ;;
  *) exec "$REAL_NFT" "\$@" ;;
esac
script="\$(cat)"
if grep -q "add element" <<<"\$script"; then
  script="\$script
delete table inet stockfw_no_such_table"
fi
printf '%s\n' "\$script" | "$REAL_NFT" "\$@"
EOF
chmod +x "$W/bin/nft"
out="$(PATH="$W/bin:$PATH" "$DRV" apply "$F_SEVERAL")"; rc=$?
live="$("$DRV" live)"
check '[ $rc -eq 1 ] && grep -q "nft refused the change" <<<"$out"' \
      "a transaction the kernel rejects is a failure (${out:0:90})"
check '[ "$live" = "present $d_b" ]' "the previous table and its digest are still in force ($live)"
check 'nft list set inet stockfw_intel s_feed_b_4 | grep -q "198.51.100.0/24"' "with its set and elements"
check '! nft list set inet stockfw_intel s_feed_in_4 >/dev/null 2>&1' "and nothing of the rejected rule set"

# --------------------------------------------- 4. the six direction cells
new_ns || bad "could not make the peer namespace"
PEER=$NS
ip link add v0 type veth peer name v1 netns "$PEER"
ip addr add 192.0.2.1/24 dev v0
ip link set v0 up
in_ns "$PEER" ip link set lo up
in_ns "$PEER" ip addr add 192.0.2.2/24 dev v1
in_ns "$PEER" ip link set v1 up
start_listener "" 192.0.2.1 8001 || bad "listener here"
start_listener "$PEER" 192.0.2.2 8002 || bad "listener on the peer"
start_listener "" 192.0.2.1 9001 udpecho.py || bad "UDP echo here"
start_listener "$PEER" 192.0.2.2 9002 udpecho.py || bad "UDP echo on the peer"

"$DRV" clear >/dev/null
ra="$(conn "$PEER" 192.0.2.1 8001)"
rb="$(conn "" 192.0.2.2 8002)"
check 'works "$ra" && works "$rb"' "without the table both directions connect ($ra / $rb)"
ua="$(uask "$PEER" 192.0.2.1 9001)"
ub="$(uask "" 192.0.2.2 9002)"
check 'answered "$ua" && answered "$ub"' "without the table UDP queries are answered both ways ($ua / $ub)"

for d in in out both; do
  f="$(spec "cell-$d" "cell-$d $d 192.0.2.2")"
  out="$("$DRV" apply "$f")" || bad "apply cell-$d ($out)"
  ra="$(conn "$PEER" 192.0.2.1 8001)"   # (a) the listed peer connects here
  rb="$(conn "" 192.0.2.2 8002)"        # (b) this side connects to the peer
  # The same over UDP, where only conntrack tells a reply from a
  # request: a DNS answer is the case [N0] names.
  ua="$(uask "$PEER" 192.0.2.1 9001)"   # (a) the listed peer asks here
  ub="$(uask "" 192.0.2.2 9002)"        # (b) this side asks the peer
  case $d in
    in)
      check 'times_out "$ra"' "in (a): the listed peer cannot connect here: dropped, times out ($ra)"
      check 'works "$rb"' "in (b): this side still connects to it: the replies pass ($rb)"
      check 'times_out "$ua"' "in, UDP (a): the listed peer's query is dropped ($ua)"
      check 'answered "$ub"' "in, UDP (b): this side's query to it is answered: the reply passes ($ub)"
      ;;
    out)
      check 'works "$ra"' "out (a): the listed peer still connects here: our replies pass ($ra)"
      check 'fails_fast "$rb"' "out (b): connecting to it fails at once: rejected, not a timeout ($rb)"
      check 'answered "$ua"' "out, UDP (a): the listed peer's query here is answered: our reply passes ($ua)"
      check 'udp_refused "$ub"' "out, UDP (b): a query to it fails at once, it is never sent ($ub)"
      ;;
    both)
      check 'times_out "$ra"' "both (a): the listed peer cannot connect here ($ra)"
      check 'fails_fast "$rb"' "both (b): connecting to it fails at once ($rb)"
      check 'times_out "$ua"' "both, UDP (a): the listed peer's query is dropped ($ua)"
      check 'udp_refused "$ub"' "both, UDP (b): a query to it fails at once ($ub)"
      ;;
  esac

  # Counters: what the driver reads (fs_intelset_nft_parse_counters on
  # `nft list chain' output) against nft's own listing.
  mine="$("$DRV" counters | grep "^cell-$d ")"
  theirs="$(listed_counter "cell-$d")"
  check '[ -n "$mine" ] && [ "$mine" = "$theirs" ]' "counters of cell-$d match the nft listing ($mine)"
  check '[ "$(echo "$mine" | cut -d" " -f2)" -gt 0 ]' "counters of cell-$d moved with the blocked attempts"
done
pin="$(chain_packets input cell-both)"
pout="$(chain_packets output cell-both)"
total="$("$DRV" counters | grep "^cell-both " | cut -d" " -f2)"
check '[ "$pin" -gt 0 ] && [ "$pout" -gt 0 ] && [ "$total" -eq $((pin + pout)) ]' \
      "a both set counts in input and output, and its id sums both rules ($pin + $pout = $total)"

# ----------------------------------------------------------- 5. loopback
# A listed address this computer holds (on lo), and its own veth
# address listed too: local traffic goes over lo and must pass [S5].
ip addr add 203.0.113.5/32 dev lo
start_listener "" 203.0.113.5 8003 || bad "listener on lo"
for d in in out both; do
  f="$(spec "loop-$d" "loop-$d $d 203.0.113.5 192.0.2.1")"
  "$DRV" apply "$f" >/dev/null || bad "apply loop-$d"
  r1="$(conn "" 203.0.113.5 8003)"
  r2="$(conn "" 192.0.2.1 8001)"
  check 'works "$r1" && works "$r2"' "loopback, $d set: this computer still reaches its own listed addresses ($r1 / $r2)"
done

# -------------------------------------------------------------- 6. clear
"$DRV" apply "$F_B" >/dev/null
nft add table inet other
nft add set inet other keep '{ type ipv4_addr; }'
nft add element inet other keep '{ 192.0.2.99 }'
nft add chain inet other c '{ type filter hook input priority 0; policy accept; }'
out="$("$DRV" clear)"; rc=$?
check '[ $rc -eq 0 ] && ! nft list table inet stockfw_intel >/dev/null 2>&1' "clear removes our table ($out)"
check 'nft list set inet other keep | grep -q 192.0.2.99 && nft list chain inet other c >/dev/null' \
      "an unrelated table inet other survives it, set, element and chain"
out="$("$DRV" clear)"; rc=$?
check '[ $rc -eq 0 ] && [ "$out" = cleared ]' "clearing twice is fine ($out)"
live="$("$DRV" live)"
check '[ "$live" = absent ]' "and the table reads back as absent ($live)"
out="$("$DRV" apply "$F_EMPTY")"; rc=$?
check '[ $rc -eq 0 ] && [ "$("$DRV" live)" = absent ]' "applying the empty rule set leaves no table"
# Sets that are all empty are not the empty rule set: the table is
# loaded, with its digest, its three chains and no set.
d_allempty="$("$DRV" digest "$F_ALLEMPTY")"
out="$("$DRV" apply "$F_ALLEMPTY")"; rc=$?
live="$("$DRV" live)"
tbl="$(nft list table inet stockfw_intel 2>&1)"
check '[ $rc -eq 0 ] && [ "$live" = "present $d_allempty" ] && ! grep -q "set " <<<"$tbl" && [ "$(grep -c "chain " <<<"$tbl")" -eq 3 ]' \
      "a rule set whose sets are all empty loads a table with its digest, three chains and no set ($live)"
"$DRV" clear >/dev/null
nft delete table inet other

# --------------------------------------------------------- 7. forwarding
# client -- c0 [this one, forwarding] s0 -- server
fwd_ok=1
new_ns || fwd_ok=0
CLIENT=${NS:-}
new_ns || fwd_ok=0
SERVER=${NS:-}
if [ $fwd_ok -eq 1 ]; then
  ip link add c0 type veth peer name c1 netns "$CLIENT"
  ip link add s0 type veth peer name s1 netns "$SERVER"
  ip addr add 198.51.100.1/24 dev c0
  ip link set c0 up
  ip addr add 203.0.113.129/25 dev s0
  ip link set s0 up
  in_ns "$CLIENT" ip link set lo up
  in_ns "$CLIENT" ip addr add 198.51.100.2/24 dev c1
  in_ns "$CLIENT" ip link set c1 up
  in_ns "$CLIENT" ip route add default via 198.51.100.1
  in_ns "$SERVER" ip link set lo up
  in_ns "$SERVER" ip addr add 203.0.113.130/25 dev s1
  in_ns "$SERVER" ip link set s1 up
  in_ns "$SERVER" ip route add default via 203.0.113.129
  echo 1 > /proc/sys/net/ipv4/ip_forward
  start_listener "$CLIENT" 198.51.100.2 8101 || fwd_ok=0
  start_listener "$SERVER" 203.0.113.130 8102 || fwd_ok=0
fi
r1="$(conn "${CLIENT:-}" 203.0.113.130 8102)"
r2="$(conn "${SERVER:-}" 198.51.100.2 8101)"
check '[ $fwd_ok -eq 1 ] && works "$r1" && works "$r2"' \
      "forwarding without the table: client and server reach each other through this one ($r1 / $r2)"

f="$(spec fwd-in 'fwd-in in 198.51.100.2')"
"$DRV" apply "$f" >/dev/null || bad "apply fwd-in"
r1="$(conn "$CLIENT" 203.0.113.130 8102)"
r2="$(conn "$SERVER" 198.51.100.2 8101)"
check 'times_out "$r1"' "forward, in set: a routed connection the listed client starts is dropped ($r1)"
check 'works "$r2"' "forward, in set: a routed connection to the listed client still works ($r2)"
check '[ "$(chain_packets forward fwd-in)" -gt 0 ]' "forward, in set: the forward rule counted it"

f="$(spec fwd-out 'fwd-out out 203.0.113.130')"
"$DRV" apply "$f" >/dev/null || bad "apply fwd-out"
r1="$(conn "$CLIENT" 203.0.113.130 8102)"
r2="$(conn "$SERVER" 198.51.100.2 8101)"
check 'fails_fast "$r1"' "forward, out set: a routed connection to the listed server is rejected at once ($r1)"
check 'works "$r2"' "forward, out set: the listed server still connects to the client ($r2)"
check '[ "$(chain_packets forward fwd-out)" -gt 0 ]' "forward, out set: the forward rule counted it"

# ----------------------------------------------------------- 8. timeouts
"$DRV" apply "$F_B" >/dev/null
mkdir -p "$W/slow" "$W/deaf"
printf '#!/bin/bash\n# An nft that hangs and never reads its input.\nexec sleep 30\n' > "$W/slow/nft"
printf '#!/bin/bash\n# An nft that quits at once, without reading its input.\necho "Error: not today" >&2\nexit 1\n' > "$W/deaf/nft"
chmod +x "$W/slow/nft" "$W/deaf/nft"

t0=$(date +%s%N)
out="$(PATH="$W/slow:$PATH" "$DRV" --timeout-ms 800 apply "$F_SEVERAL")"; rc=$?
t1=$(date +%s%N)
ms=$(( (t1 - t0) / 1000000 ))
check '[ $rc -eq 1 ] && grep -q "timed out" <<<"$out"' "an nft that hangs is killed: the apply says it timed out (${out:0:80})"
check '[ $ms -lt 5000 ]' "... after the timeout, not after the hung nft's 30 s (${ms} ms)"
check '[ "$("$DRV" live)" = "present $d_b" ]' "... and the table in force is unchanged"
out="$(PATH="$W/slow:$PATH" "$DRV" --timeout-ms 800 live)"; rc=$?
check '[ $rc -eq 1 ] && grep -q "timed out" <<<"$out"' "a listing that hangs times out too (${out:0:80})"

# An nft whose child keeps nft's stdout and stderr open: killing nft
# does not close the pipes, so the runner has to stop reading as well
# or it waits for the child, not the timeout.
mkdir -p "$W/orphan"
cat > "$W/orphan/nft" <<EOF
#!/bin/bash
sleep 8 &
echo \$! >> "$W/orphan.pids"
exec sleep 30
EOF
chmod +x "$W/orphan/nft"
for cmd in live apply; do
  t0=$(date +%s%N)
  if [ $cmd = live ]; then
    out="$(PATH="$W/orphan:$PATH" "$DRV" --timeout-ms 800 live)"; rc=$?
  else
    out="$(PATH="$W/orphan:$PATH" "$DRV" --timeout-ms 800 apply "$F_SEVERAL")"; rc=$?
  fi
  t1=$(date +%s%N)
  ms=$(( (t1 - t0) / 1000000 ))
  check '[ $rc -eq 1 ] && grep -q "timed out" <<<"$out" && [ $ms -lt 5000 ]' \
        "$cmd: an nft whose child holds its pipes open still stops at the timeout (${ms} ms: ${out:0:60})"
  for p in $(cat "$W/orphan.pids" 2>/dev/null); do kill -KILL "$p" 2>/dev/null; done
  rm -f "$W/orphan.pids"
done
check '[ "$("$DRV" live)" = "present $d_b" ]' "... and the table in force is unchanged"

# An nft whose listing cannot be read says nothing about the kernel:
# "unknown", never "absent" -- absent would be shown as a table that is
# missing, a claim about the kernel nobody checked [S10].
mkdir -p "$W/chatty"
cat > "$W/chatty/nft" <<EOF
#!/bin/bash
echo "Warning: a line that is not part of the listing"
exec "$REAL_NFT" "\$@"
EOF
chmod +x "$W/chatty/nft"
out="$(PATH="$W/chatty:$PATH" "$DRV" live)"; rc=$?
check '[ $rc -eq 1 ] && [ "$out" = unknown ]' "a listing that cannot be read is unknown, not absent ($out)"

out="$(PATH="$W/deaf:$PATH" "$DRV" apply "$F_HUGE" 2>&1)"; rc=$?
check '[ $rc -eq 1 ] && grep -q "^error: " <<<"$out"' \
      "an nft that quits without reading a large script is an error, not a SIGPIPE death (rc $rc: ${out:0:70})"

echo
if [ $fails -eq 0 ]; then echo "PASSED: 0 failure(s)"; else echo "FAILED: $fails failure(s)"; fi
[ $fails -eq 0 ]
