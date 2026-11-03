#!/bin/bash
# Threat intel end to end on Linux (1.0.7, design sections 4-7): a feed
# served over HTTPS, the engine's default downloader (curl as nobody),
# its store, update, judge and build, this computer read live, the
# Linux backend's real slots, the nft table in the kernel, and real
# packets.  Nothing is replaced: fs-intel-e2e-driver calls the engine
# the way a `stockfw intel' command would, with fs_backend().
#
# Runs in private namespaces: it re-executes itself under `unshare -n
# -m', so the host's network, firewall, /var/lib and /etc/resolv.conf
# are never touched.  In there:
#   - this computer: 192.0.2.1/24 on a veth pair, default gateway
#     192.0.2.2, DNS server 203.0.113.53 (a resolv.conf bound over
#     /etc/resolv.conf), an SSH client in $SSH_CONNECTION
#     (198.51.100.22) and an established connection to its port 22 from
#     198.51.100.33;
#   - the peer namespace ("the internet"): the gateway, the HTTPS feed
#     server at 203.0.113.80 (a throwaway CA), and the addresses the
#     packets come from and go to;
#   - the store is the default one, /var/lib/stockfw/intel, on a tmpfs
#     mounted over /var/lib in the private mount namespace;
#   - the audit file is $STOCKFW_AUDIT_FILE in the scratch directory.
# Needs root, nft, curl, openssl, python3, unshare, nsenter, ip and
# mount; SKIPs without them.
#
# What it proves:
#   - with nothing turned on, no request is made, the state is off and
#     no table is loaded; the store is created where the design says,
#     0755 above 0700, every file 0600;
#   - a custom feed (both directions) is downloaded with the default
#     downloader, as StockFW/<version>; a local list (out) is imported;
#   - the apply keeps every kind of address this computer must reach
#     (its own, its network, the gateway, the DNS server, both SSH
#     peers, the feed's server) out of the sets, and says so in notes;
#     the outbound list is also mapped into 64:ff9b::/96 (rule text);
#   - real packets: from a listed address in -> dropped; to a listed
#     address out -> refused at once; an out-only list lets its
#     addresses connect in; unlisted and kept addresses pass both ways;
#     the counters are exactly the packets the lists stopped, and the
#     lookup agrees with every packet;
#   - the next update still reaches the feed server although the list
#     names it;
#   - an update with a changed list: the removed address passes, the
#     added one is dropped, the counters carry across the replace;
#   - bad lists change nothing, in the store or in the kernel: an HTML
#     page, an HTTP error, a replayed older copy (rollback), a list that
#     shrank to almost nothing, one dated a year ahead; a transaction
#     the kernel rejects leaves the previous table, its digest and its
#     counters (never counted twice), and so does one that would have
#     loaded the very same table -- a failure, never "applied", nothing
#     carried; a stored list tampered with on
#     disk is refused before nft runs, and the next update repairs it;
#   - an exception lets an address through; removing it gives the same
#     digest as before;
#   - a hold reaches no nft; a table removed or replaced by someone else,
#     or whose chains were flushed (its digest still on it), reads
#     not-loaded / differs, and an apply repairs it;
#   - user Stop and Start: suspend removes the table and keeps the
#     count, resume restores the same digest; `stockfw stop' and
#     `stockfw start' do the same (plain and --json), with iptables;
#   - without nft: a Stop where StockFW never loaded a table is not an
#     error and the state reads off; where its record says it left one,
#     the Stop fails and the state is unknown, never off; with no store
#     at all, a Stop creates none;
#   - the master switch off clears the table, no request is made, the
#     carried counts stay; one audit line per attempt.
# IPv6 is checked as rule text only: no IPv6 packet is sent here.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
DRV="${STOCKFW_INTEL_E2E_DRIVER:-$PORT/build-linux/fs-intel-e2e-driver}"

if [ "${STOCKFW_IN_NETNS:-}" != 1 ]; then
  if [ "$(id -u)" != 0 ]; then
    echo "SKIP: needs root"
    exit 0
  fi
  for tool in nft unshare nsenter ip mount openssl python3 date; do
    if ! command -v "$tool" >/dev/null; then
      echo "SKIP: needs $tool"
      exit 0
    fi
  done
  if [ ! -x /usr/bin/curl ] && [ ! -x /bin/curl ]; then
    echo "SKIP: needs curl in /usr/bin or /bin"
    exit 0
  fi
  if [ ! -x "$DRV" ]; then
    echo "SKIP: $DRV not built -- ninja -C build-linux fs-intel-e2e-driver"
    exit 0
  fi
  if ! unshare -n -m true 2>/dev/null; then
    echo "SKIP: cannot make network and mount namespaces here (unshare -n -m)"
    exit 0
  fi
  export STOCKFW_INTEL_E2E_DRIVER="$DRV"
  STOCKFW_IN_NETNS=1 exec unshare -n -m --propagation private "$0" "$@"
fi

REAL_NFT="$(command -v nft)"
# World-readable: curl runs as nobody and reads the CA from here.
W="$(cd "$(mktemp -d)" && pwd -P)"
chmod 755 "$W"
PIDS=""
cleanup() {
  exec 2>/dev/null
  for p in $PIDS; do kill -KILL "$p"; done
  wait
  rm -rf "$W"
}
trap cleanup EXIT

fails=0
ok()    { echo "ok:   $*"; }
bad()   { echo "FAIL: $*"; fails=$((fails + 1)); }
check() { if eval "$1"; then ok "$2"; else bad "$2"; fi; }
die()   { bad "$*"; echo; echo "FAILED: $fails failure(s)"; exit 1; }

# ------------------------------------------------- private mounts, env
# The default store, on a tmpfs that exists only in this namespace.
mount -t tmpfs -o mode=0755 stockfw-e2e /var/lib || die "could not mount a tmpfs over /var/lib"
printf '# StockFW end-to-end test\nnameserver 203.0.113.53\n' > "$W/resolv.conf"
mount --bind "$W/resolv.conf" /etc/resolv.conf || die "could not bind a resolv.conf over /etc/resolv.conf"
unset STOCKFW_INTEL_DIR STOCKFW_TEST_CURL SSH_CLIENT
export STOCKFW_AUDIT_FILE="$W/audit.log"
export SSH_CONNECTION="198.51.100.22 50022 192.0.2.1 22"
export STOCKFW_TEST_CACERT="$W/ca.pem"
STORE=/var/lib/stockfw/intel
FEED=custom-e2e-feed
LOCAL=local-e2e-local

# Every nft the backend runs goes through this wrapper: it logs the
# arguments, and the script of every load, then runs the real nft.
mkdir -p "$W/log" "$W/scripts" "$W/reject"
cat > "$W/log/nft" <<EOF
#!/bin/bash
echo "\$*" >> "$W/nft.log"
case " \$* " in
  *" -f "*)
    n=\$(ls "$W/scripts" | wc -l)
    cat > "$W/scripts/\$n.nft"
    exec "$REAL_NFT" "\$@" < "$W/scripts/\$n.nft"
    ;;
esac
exec "$REAL_NFT" "\$@"
EOF
# A load that adds elements gets one more statement the kernel refuses,
# so the whole transaction aborts.
cat > "$W/reject/nft" <<EOF
#!/bin/bash
case " \$* " in *" -f "*) ;; *) exec "$REAL_NFT" "\$@" ;; esac
script="\$(cat)"
if grep -q "add element" <<<"\$script"; then
  script="\$script
delete table inet stockfw_no_such_table"
fi
printf '%s\n' "\$script" | "$REAL_NFT" "\$@"
EOF
chmod +x "$W/log/nft" "$W/reject/nft"

drv() { PATH="$W/log:$PATH" "$DRV" "$@"; }
drv_with() { local dir="$1"; shift; PATH="$W/$dir:$W/log:$PATH" "$DRV" "$@"; }
loads() { ls "$W/scripts" | wc -l; }
live() {   # "<digest>" of the table, or "absent"
  "$REAL_NFT" -j list tables 2>/dev/null | python3 -I -c '
import json, sys
for t in json.load(sys.stdin)["nftables"]:
    t = t.get("table")
    if t and t["family"] == "inet" and t["name"] == "stockfw_intel":
        print(t.get("comment", "").removeprefix("sfw:")); break
else:
    print("absent")'
}
field() { sed -n "s/^result .*$1=\([^ ]*\).*/\1/p"; }   # from apply output
has_element() { "$REAL_NFT" get element inet stockfw_intel "$1" "{ $2 }" >/dev/null 2>&1; }

# ------------------------------------------------------------ network
ip link set lo up
PEER=""
unshare -n sleep 3600 &
PIDS="$PIDS $!"
for _ in $(seq 100); do
  if [ "$(readlink "/proc/$!/ns/net")" != "$(readlink /proc/self/ns/net)" ]; then
    PEER=$!
    break
  fi
  sleep 0.05
done
[ -n "$PEER" ] || die "could not make the peer namespace"
peer() { nsenter -t "$PEER" -n "$@"; }
ip link add v0 type veth peer name v1 netns "$PEER"
ip addr add 192.0.2.1/24 dev v0
ip link set v0 up
ip route add default via 192.0.2.2 dev v0
peer ip link set lo up
peer ip addr add 192.0.2.2/24 dev v1
peer ip link set v1 up
# Listed, unlisted and kept addresses, all on the peer.
PEER_ADDRS="198.51.100.10 198.51.100.22 198.51.100.33 198.51.100.70 198.51.100.100
  198.51.100.130 198.51.100.200 203.0.113.9 203.0.113.53 203.0.113.80 203.0.113.140"
for a in $PEER_ADDRS; do peer ip addr add "$a/32" dev lo; done

# ------------------------------------------------------- the helpers
cat > "$W/net.py" <<'EOF'
import os, select, socket, ssl, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

def log(path, line):
    with open(path, "a") as f:
        f.write(line + "\n")

def ready(path):
    open(path, "w").close()

mode = sys.argv[1]
if mode == "send":         # send SRC|- DST PORT COUNT: prints the refused
    src, dst, port, count = sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if src != "-":
        s.bind((src, 0))
    refused = 0
    for _ in range(count):
        try:
            s.sendto(b"0123456789", (dst, port))   # 38 bytes on the wire
        except OSError:
            refused += 1
    print(refused)
elif mode == "recv":       # recv LOG PORT ADDR...: "<dst> <src>" a datagram
    path, port = sys.argv[2], int(sys.argv[3])
    socks = {}
    for a in sys.argv[4:]:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((a, port))
        socks[s] = a
    ready(path + ".ready")
    while True:
        r, _, _ = select.select(list(socks), [], [])
        for s in r:
            _, (src, _) = s.recvfrom(2048)
            log(path, "%s %s" % (socks[s], src))
elif mode == "tcp-listen":  # tcp-listen ADDR PORT READY: accept, hold
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((sys.argv[2], int(sys.argv[3])))
    s.listen(4)
    ready(sys.argv[4])
    held = []
    while True:
        held.append(s.accept()[0])
elif mode == "tcp-hold":    # tcp-hold SRC DST PORT READY: connect, hold
    c = socket.create_connection((sys.argv[3], int(sys.argv[4])),
                                 source_address=(sys.argv[2], 0))
    ready(sys.argv[5])
    while True:
        time.sleep(3600)
elif mode == "https":       # https DIR ADDR: serves DIR/body with DIR/status
    d, addr = sys.argv[2], sys.argv[3]

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *args):
            pass
        def do_GET(self):
            log(os.path.join(d, "https.log"), "%s %s" % (
                self.path, self.headers.get("User-Agent", "-")))
            with open(os.path.join(d, "status")) as f:
                code = int(f.read().strip())
            with open(os.path.join(d, "body"), "rb") as f:
                data = f.read()
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        def handle_error(self, request, client_address):
            pass

    srv = Server((addr, 443), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(d, "srv.pem"), os.path.join(d, "srv.key"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True,
                                 do_handshake_on_connect=False)
    ready(os.path.join(d, "ready"))
    srv.serve_forever()
EOF

wait_for() { for _ in $(seq 100); do [ -e "$1" ] && return 0; sleep 0.1; done; return 1; }

# The feed server's CA and certificate (for 203.0.113.80).
S="$W/serve"
mkdir -p "$S"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj "/CN=StockFW e2e test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$W/ca.key" -out "$W/ca.pem" >/dev/null 2>&1 &&
openssl req -newkey rsa:2048 -nodes -subj "/CN=203.0.113.80" \
  -keyout "$S/srv.key" -out "$W/srv.csr" >/dev/null 2>&1 &&
printf 'subjectAltName=IP:203.0.113.80\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' \
  > "$W/srv.ext" &&
openssl x509 -req -days 2 -in "$W/srv.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" \
  -CAcreateserial -extfile "$W/srv.ext" -out "$S/srv.pem" >/dev/null 2>&1 ||
  die "could not make the test CA with openssl"
chmod 644 "$W/ca.pem"

# serve FILE [STATUS]: what the feed server answers from now on.
serve() { cp "$1" "$S/body.new" && mv "$S/body.new" "$S/body"; echo "${2:-200}" > "$S/status"; }
requests() { if [ -f "$S/https.log" ]; then wc -l < "$S/https.log"; else echo 0; fi; }

# The feed's copies.  Dates are relative to now, so they are always in
# the past (and the future one always ahead).
NOW="$(date -u +%s)"
stamp() { date -u -d "@$1" '+%Y-%m-%d %H:%M:%S'; }
D1=$((NOW - 2 * 86400)); D2=$((NOW - 86400))
PAD="198.51.100.231 198.51.100.233 198.51.100.235 198.51.100.237 198.51.100.239 198.51.100.241
     198.51.100.243 198.51.100.245 198.51.100.247 198.51.100.249 198.51.100.251 198.51.100.253"
feed_copy() {   # feed_copy DATE ENTRY...: a plain feed with 12 padding singles
  local date="$1"; shift
  printf '# StockFW e2e feed\n# Last updated: %s UTC\n' "$(stamp "$date")"
  printf '%s\n' "$@"
  # shellcheck disable=SC2086
  printf '%s\n' $PAD
}
# v1: 198.51.100.0/26 (.10 listed; .22 and .23 are the SSH peers),
#     198.51.100.64/27 (.70), 203.0.113.0/25 (.9 listed; .53 the DNS
#     server, .80 the feed's server), and this computer's own /24.
feed_copy "$D1" 198.51.100.0/26 198.51.100.64/27 203.0.113.0/25 192.0.2.0/24 > "$W/v1.txt"
# v2: .64/27 is gone (.70 passes again), .100 is new.
feed_copy "$D2" 198.51.100.0/26 198.51.100.100 203.0.113.0/25 192.0.2.0/24 > "$W/v2.txt"
feed_copy $((NOW + 365 * 86400)) 198.51.100.0/26 198.51.100.100 203.0.113.0/25 192.0.2.0/24 > "$W/future.txt"
printf '# StockFW e2e feed\n# Last updated: %s UTC\n198.51.100.10\n198.51.100.100\n' \
  "$(stamp $((NOW - 3600)))" > "$W/shrunk.txt"
printf '<!DOCTYPE html>\n<html>\n<head><title>503</title></head>\n<body>\n<h1>Service Unavailable</h1>\n<p>Try again later.</p>\n</body>\n</html>\n' > "$W/html.txt"
printf 'address,comment\n198.51.100.128/26,lab range\n203.0.113.128/25,lab range\n' > "$W/local.csv"
chmod 644 "$W"/*.txt "$W/local.csv"
serve "$W/v1.txt"

nsenter -t "$PEER" -n python3 -I "$W/net.py" https "$S" 203.0.113.80 &
PIDS="$PIDS $!"
# This computer receives on 9999; the peer on port 9 of each address
# this computer sends to.
python3 -I "$W/net.py" recv "$W/a.log" 9999 192.0.2.1 &
PIDS="$PIDS $!"
nsenter -t "$PEER" -n python3 -I "$W/net.py" recv "$W/b.log" 9 \
  198.51.100.10 198.51.100.130 198.51.100.200 203.0.113.53 203.0.113.140 192.0.2.2 &
PIDS="$PIDS $!"
# An established connection to this computer's SSH port.
python3 -I "$W/net.py" tcp-listen 192.0.2.1 22 "$W/sshd.ready" &
PIDS="$PIDS $!"
wait_for "$W/sshd.ready" || die "the port 22 listener did not start"
nsenter -t "$PEER" -n python3 -I "$W/net.py" tcp-hold 198.51.100.33 192.0.2.1 22 "$W/ssh.ready" &
PIDS="$PIDS $!"
for f in "$S/ready" "$W/a.log.ready" "$W/b.log.ready" "$W/ssh.ready"; do
  wait_for "$f" || die "a helper did not start ($f)"
done

seen() { if [ -f "$1" ]; then grep -c -x -F "$2" "$1"; else echo 0; fi; }
# in_from SRC COUNT: COUNT datagrams from SRC (on the peer) to this
# computer; prints how many arrived.
in_from() {
  local before after
  before=$(seen "$W/a.log" "192.0.2.1 $1")
  peer python3 -I "$W/net.py" send "$1" 192.0.2.1 9999 "$2" >/dev/null
  sleep 0.3
  after=$(seen "$W/a.log" "192.0.2.1 $1")
  echo $((after - before))
}
# out_to DST COUNT: COUNT datagrams from this computer to DST; prints
# "<refused by the kernel> <arrived>".
out_to() {
  local before after refused
  before=$(seen "$W/b.log" "$1 192.0.2.1")
  refused=$(python3 -I "$W/net.py" send - "$1" 9 "$2")
  sleep 0.3
  after=$(seen "$W/b.log" "$1 192.0.2.1")
  echo "$refused $((after - before))"
}
total() { drv counters | awk -v id="$1" '$1 == id { print $2 " " $3; f = 1 } END { if (!f) print "0 0" }'; }
# Every fs_intel_apply_safe call is counted here, for the audit check.
counted() { echo x >> "$W/applies"; "$@"; }
apply() { counted drv apply "$@"; }

check '[ "$(in_from 198.51.100.10 1)" = 1 ] && [ "$(out_to 198.51.100.10 1)" = "0 1" ]' \
      "the network works before any list (a datagram each way)"

# ------------------------------------------------- 1. nothing turned on
out="$(drv state)"
check '[ "$out" = "off: No blocklist is turned on." ] && [ "$(live)" = absent ]' \
      "nothing turned on: the state is off and no table is loaded ($out)"
out="$(drv update)"
check '[ "$out" = nothing ] && [ "$(requests)" = 0 ]' \
      "nothing turned on: an update makes no request at all ($out)"
out="$(drv dir)"
check '[ "$out" = "$STORE" ] && [ "$(stat -c "%a %U" /var/lib/stockfw)" = "755 root" ] && [ "$(stat -c "%a %U" "$STORE")" = "700 root" ]' \
      "the store is the default $STORE, created 0700 under a 0755 parent ($out)"

# --------------------------------------------- 2. a feed and a local list
out="$(drv add-feed "E2E feed" https://203.0.113.80/feed.txt plain both)"
check 'grep -q "^added $FEED$" <<<"$out"' "a custom feed is added, both directions ($(head -1 <<<"$out"))"
out="$(drv import "$W/local.csv" "E2E local" out)"
check 'grep -q "^imported $LOCAL 2$" <<<"$out"' "a local CSV list is imported, outbound only ($(head -1 <<<"$out"))"
out="$(drv state)"
check 'grep -q "^not-loaded: " <<<"$out" && [ "$(live)" = absent ]' \
      "turned on but never applied: not-loaded, not enforced ($out)"

out="$(drv update)"
check '[ "$out" = "$FEED updated 16 Updated: 16 entries." ]' "the feed is downloaded and stored ($out)"
ua="$(tail -1 "$S/https.log")"
check '[ "$(requests)" = 1 ] && grep -q "^/feed.txt StockFW/[0-9]" <<<"$ua"' \
      "one request, from the default downloader as StockFW/<version> ($ua)"
check '[ "$(stat -c %a "$STORE/intel.conf") $(stat -c %a "$STORE/$FEED.list") $(stat -c %a "$STORE/$LOCAL.list")" = "600 600 600" ]' \
      "the configuration and both stored lists are 0600"
out="$(drv source $FEED)"
# 16 entries; 15 intervals stored (198.51.100.0/26 and .64/27 merge).
check 'grep -q "^entries=16 v4=15 v6=0 content_date=$D1 carried=0/0 refused=- error=-$" <<<"$out"' \
      "the feed's state records its entries and its content date ($out)"

# ----------------------------------------------------------- 3. apply
before=$(loads)
out="$(apply)"
D1G="$(field digest <<<"$out")"
# The feed: 198.51.100.0-95 split around .22 and .33 (3), 203.0.113.0/25
# split around .53 and .80 (3), the 12 singles, the /24 gone (18); the
# local list 2.  IPv6: the same 20 in 64:ff9b::/96 (both are outbound).
check 'grep -q "^result ok digest=[0-9a-f]\{32\} sets=2 v4=20 v6=20$" <<<"$out" && [ $(( $(loads) - before )) -eq 1 ]' \
      "the apply builds two sets and loads them in one nft transaction ($(head -1 <<<"$out"))"
check '[ "$(live)" = "$D1G" ]' "the kernel's table carries the applied digest"
out_state="$(drv state)"
check '[ "$out_state" = "enforced: 2 lists are enforced: E2E feed, E2E local." ]' "state: enforced ($out_state)"
for want in \
  "Kept reachable: 192.0.2.1 (this computer's own address), although E2E feed lists it." \
  "Kept reachable: 192.0.2.0/24 (a network this computer is connected to), although E2E feed lists it." \
  "Kept reachable: 192.0.2.2 (a default gateway), although E2E feed lists it." \
  "Kept reachable: 203.0.113.53 (a DNS server in use), although E2E feed lists it." \
  "Kept reachable: 198.51.100.22, 198.51.100.33 (an SSH session to this computer), although E2E feed lists it." \
  "Kept reachable: 203.0.113.80 (a feed's download server or proxy), although E2E feed lists it."; do
  check 'grep -q -x -F "note: $want" <<<"$out"' "note: $want"
done
check 'has_element s_custom_e2e_feed_4 198.51.100.10 && ! has_element s_custom_e2e_feed_4 198.51.100.22 && ! has_element s_custom_e2e_feed_4 198.51.100.33 && ! has_element s_custom_e2e_feed_4 203.0.113.53 && ! has_element s_custom_e2e_feed_4 203.0.113.80 && ! has_element s_custom_e2e_feed_4 192.0.2.2' \
      "the kernel's feed set holds 198.51.100.10 but none of the kept addresses"
check 'has_element s_local_e2e_local_6 64:ff9b::c633:6482 && has_element s_custom_e2e_feed_6 64:ff9b::c633:640a && ! has_element s_custom_e2e_feed_6 64:ff9b::cb00:7150' \
      "IPv6 (rule text): outbound entries are also blocked in 64:ff9b::/96, kept ones are not"
check '[ "$(drv applied-has $FEED) $(drv applied-has $LOCAL) $(drv applied-has feodo)" = "yes yes no" ]' \
      "the log parser would accept STOCKFW-TI lines of the applied sets only"

# ---------------------------------------------------------- 4. packets
check '[ "$(in_from 198.51.100.10 5)" = 0 ]' "in from a listed address (198.51.100.10): 0 of 5 arrive"
check '[ "$(in_from 198.51.100.70 2)" = 0 ]' "in from a listed address (198.51.100.70): 0 of 2 arrive"
check '[ "$(in_from 203.0.113.9 1)" = 0 ]' "in from a listed address (203.0.113.9): 0 of 1 arrive"
check '[ "$(in_from 198.51.100.200 3)" = 3 ]' "in from an unlisted address (198.51.100.200): 3 of 3 arrive"
check '[ "$(in_from 198.51.100.130 3)" = 3 ]' \
      "in from an address only the outbound list holds (198.51.100.130): 3 of 3 arrive"
check '[ "$(in_from 198.51.100.22 2)" = 2 ]' "in from the SSH client in \$SSH_CONNECTION (listed): 2 of 2 arrive"
check '[ "$(in_from 198.51.100.33 2)" = 2 ]' "in from the peer of the established SSH connection (listed): 2 of 2 arrive"
check '[ "$(in_from 203.0.113.53 2)" = 2 ]' "in from the DNS server (listed): 2 of 2 arrive"
check '[ "$(in_from 203.0.113.80 2)" = 2 ]' "in from the feed's server (listed): 2 of 2 arrive"
check '[ "$(in_from 192.0.2.2 2)" = 2 ]' "in from the gateway (its network is listed): 2 of 2 arrive"
check '[ "$(out_to 198.51.100.10 4)" = "4 0" ]' "out to a listed address (both): 4 of 4 refused at once, none arrive"
check '[ "$(out_to 198.51.100.130 3)" = "3 0" ]' "out to an address on the outbound list: 3 of 3 refused, none arrive"
check '[ "$(out_to 203.0.113.140 1)" = "1 0" ]' "out to another address on the outbound list: refused"
check '[ "$(out_to 198.51.100.200 3)" = "0 3" ]' "out to an unlisted address: 3 of 3 arrive"
check '[ "$(out_to 203.0.113.53 2)" = "0 2" ]' "out to the DNS server (listed): 2 of 2 arrive"
check '[ "$(out_to 192.0.2.2 2)" = "0 2" ]' "out to the gateway: 2 of 2 arrive"
c="$(drv counters | tr '\n' ' ')"
check '[ "$c" = "$FEED 12 456 $LOCAL 4 152 " ]' \
      "the counters are exactly the packets the lists stopped: 8 in + 4 out, and 4 out ($c)"

lk() { drv lookup "$1" | tr '\n' ' '; }
check '[ "$(lk 198.51.100.10)" = "listed=$FEED dir=both protected=0 exception=0 host=0 blocked=1 Blocked by threat intel: E2E feed " ]' \
      "lookup 198.51.100.10 agrees: blocked by E2E feed, both ways"
check '[ "$(lk 198.51.100.130)" = "listed=$LOCAL dir=out protected=0 exception=0 host=0 blocked=1 Blocked by threat intel: E2E local " ]' \
      "lookup 198.51.100.130 agrees: blocked outbound by E2E local"
check '[ "$(lk 64:ff9b::c633:6482)" = "listed=$LOCAL dir=out protected=0 exception=0 host=0 blocked=1 Blocked by threat intel: E2E local " ]' \
      "lookup of its NAT64 form agrees"
for a in 198.51.100.22 198.51.100.33 203.0.113.53 203.0.113.80 192.0.2.2; do
  check '[ "$(lk $a)" = "listed=$FEED dir=both protected=0 exception=0 host=1 blocked=0 " ]' \
        "lookup $a agrees: listed, kept reachable, not blocked"
done
check '[ "$(lk 198.51.100.200)" = "listed=- dir=- protected=0 exception=0 host=0 blocked=0 " ]' \
      "lookup 198.51.100.200 agrees: on no list"

# The list names the feed's own server, in both directions: the next
# update must still get through.
out="$(drv update)"
check '[ "$out" = "$FEED unchanged 16 Unchanged since the last download." ] && [ "$(requests)" = 2 ]' \
      "the next update reaches the feed's server although the enforced list names it ($out)"

# ------------------------------------------ 5. an update with a change
serve "$W/v2.txt"
out="$(drv update)"
check '[ "$out" = "$FEED updated 16 Updated: 16 entries." ]' "a changed copy is downloaded and stored ($out)"
out="$(apply)"
D2G="$(field digest <<<"$out")"
check 'grep -q "^result ok " <<<"$out" && [ -n "$D2G" ] && [ "$D2G" != "$D1G" ] && [ "$(live)" = "$D2G" ]' \
      "the changed list is applied with a new digest ($(head -1 <<<"$out"))"
check '[ "$(in_from 198.51.100.70 2)" = 2 ]' "the address the new copy dropped (198.51.100.70) passes again: 2 of 2"
check '[ "$(in_from 198.51.100.100 3)" = 0 ]' "the address it added (198.51.100.100) is dropped: 0 of 3"
check '[ "$(in_from 198.51.100.10 1)" = 0 ]' "an address both copies list is still dropped"
c="$(drv counters | tr '\n' ' ')"
check '[ "$c" = "$FEED 16 608 $LOCAL 4 152 " ]' \
      "the counters carried across the replace: 12 before + 4 since, and 4 ($c)"
check 'grep -q " carried=12/456 " <<<"$(drv source $FEED)" && grep -q " carried=4/152 " <<<"$(drv source $LOCAL)"' \
      "the counts of the replaced table were carried into the store"

# ----------------------------------------------- 6. bad copies of the list
# Each is turned away; the stored copy (v2) and the kernel stay.
bad_copy() {   # bad_copy FILE STATUS WANT-OUTCOME WANT-TEXT LABEL
  local out want="$3" text="$4"
  serve "$1" "$2"
  out="$(drv update)"
  check 'grep -q "^$FEED $want 16 " <<<"$out" && grep -q -- "$text" <<<"$out" && grep -q "^entries=16 v4=16 v6=0 content_date=$D2 " <<<"$(drv source $FEED)" && [ "$(live)" = "$D2G" ]' \
        "$5: $want, the stored copy and the table stay ($out)"
}
bad_copy "$W/html.txt" 200 refused "Refused: " "an HTML page instead of the list"
bad_copy "$W/v2.txt" 503 failed "Download failed: .*503" "an HTTP 503"
bad_copy "$W/v1.txt" 200 refused "older" "the older copy replayed (a rollback)"
bad_copy "$W/shrunk.txt" 200 refused "Refused: " "a copy that shrank from 16 entries to 2"
bad_copy "$W/future.txt" 200 refused "in the future" "a copy dated a year ahead"
out="$(apply)"
check '[ "$(field digest <<<"$out")" = "$D2G" ] && [ "$(live)" = "$D2G" ] && [ "$(in_from 198.51.100.100 1)" = 0 ] && [ "$(in_from 198.51.100.70 1)" = 1 ]' \
      "an apply after all of them enforces the last good copy, the same digest"
serve "$W/v2.txt"

# A transaction the kernel rejects: the previous table, digest and
# counters stay, and nothing is counted twice.
out="$(drv except 198.51.100.10)"
c_before="$(drv counters | tr '\n' ' ')"
out="$(counted drv_with reject apply)"; rc=$?
check '[ $rc -eq 1 ] && grep -q "^result failed " <<<"$out" && grep -q "^error other: nft refused the change" <<<"$out" && grep -q "(fingerprint $D2G) are still in force" <<<"$out"' \
      "a transaction the kernel rejects fails and names the lists still in force ($(grep ^error <<<"$out" | cut -c1-140))"
check '[ "$(live)" = "$D2G" ] && grep -q "^enforced: " <<<"$(drv state)"' \
      "the previous table and digest are still in force, and the state still reads enforced"
check '[ "$(drv counters | tr "\n" " ")" = "$c_before" ]' \
      "the counters are not carried by a failed apply: still $c_before"
check '[ "$(in_from 198.51.100.10 2)" = 0 ]' "the exception in the rejected rule set is not in force: 0 of 2 arrive"
out="$(apply)"
D3G="$(field digest <<<"$out")"
check '[ "$(live)" = "$D3G" ] && [ "$D3G" != "$D2G" ] && grep -q -x -F "note: Not blocked, by exception: 198.51.100.10 (listed by E2E feed)." <<<"$out"' \
      "with the real nft the exception is applied and noted"
check '[ "$(in_from 198.51.100.10 2)" = 2 ] && [ "$(in_from 198.51.100.100 1)" = 0 ]' \
      "the exception lets 198.51.100.10 through; the rest of the list still holds"
c="$(drv counters | tr '\n' ' ')"
check '[ "$c" = "$FEED 20 760 $LOCAL 4 152 " ]' \
      "the counters: the 2 the failed apply's old table stopped and the 1 since, counted once ($c)"
drv unexcept 198.51.100.10 >/dev/null
out="$(apply)"
check '[ "$(field digest <<<"$out")" = "$D2G" ] && [ "$(live)" = "$D2G" ]' \
      "removing the exception gives the same digest as before it"

# The same rule set refused (the hourly re-apply of an unchanged one):
# the kernel then holds the digest asked for, but only because it held
# it before.  The table still counts, so nothing may be carried, and the
# attempt is a failure, not "applied".
in_from 198.51.100.100 1 >/dev/null
c_before="$(drv counters | tr '\n' ' ')"
carried="$(drv source $FEED | sed -n 's/.* \(carried=[^ ]*\) .*/\1/p')"
out="$(counted drv_with reject apply)"; rc=$?
check '[ $rc -eq 1 ] && grep -q "^result failed digest=$D2G " <<<"$out" && grep -q -x -F "note: The same rules were already in force, and still are." <<<"$out" && grep -q "The same blocklists (fingerprint $D2G) were already loaded and are still in force" <<<"$out"' \
      "the same rule set refused: a failure that says the same lists are still in force ($(grep ^error <<<"$out" | cut -c1-200))"
check '[ "$(live)" = "$D2G" ] && grep -q "^enforced: " <<<"$(drv state)" && [ "$(drv counters | tr "\n" " ")" = "$c_before" ] && grep -q " $carried " <<<"$(drv source $FEED)"' \
      "... the table, the state and the counters as they were, nothing carried ($c_before, $carried)"

# A stored list tampered with on disk: refused before nft runs; the next
# update stores the good copy again.
printf '0.0.0.0/0\n' > "$STORE/$FEED.list"
before=$(loads)
out="$(apply)"; rc=$?
check '[ $rc -eq 1 ] && grep -q "^error tampered: " <<<"$out" && [ "$(loads)" = "$before" ] && [ "$(live)" = "$D2G" ]' \
      "a stored list tampered with (0.0.0.0/0) is refused before any nft load ($out)"
check '[ "$(in_from 198.51.100.200 1)" = 1 ] && [ "$(in_from 198.51.100.100 1)" = 0 ]' \
      "and the kernel still enforces the last good list, nothing more"
out="$(drv update)"
check '[ "$out" = "$FEED updated 16 Updated: 16 entries." ]' \
      "the next update stores the good copy again, though the body is unchanged ($out)"
out="$(apply)"
check '[ "$(field digest <<<"$out")" = "$D2G" ] && [ "$(live)" = "$D2G" ]' "and the apply after it is the same digest"

# ------------------------------------------------------------- 7. hold
before=$(loads)
out="$(apply "audit-only mode")"
check 'grep -q "^result dry-run digest=$D2G sets=2 " <<<"$out" && [ "$(loads)" = "$before" ]' \
      "a hold reaches no nft: dry-run ($(head -1 <<<"$out"))"

# ------------------------------------------------ 8. others in the kernel
"$REAL_NFT" delete table inet stockfw_intel
out="$(drv state)"
check 'grep -q "^not-loaded: " <<<"$out" && [ "$(in_from 198.51.100.100 1)" = 1 ]' \
      "a table someone removed: not-loaded, and the address really passes ($out)"
apply >/dev/null
check 'grep -q "^enforced: " <<<"$(drv state)" && [ "$(live)" = "$D2G" ] && [ "$(in_from 198.51.100.100 1)" = 0 ]' \
      "an apply puts it back"
"$REAL_NFT" -f - <<'EOF'
table inet stockfw_intel {}
delete table inet stockfw_intel
table inet stockfw_intel {
	comment "sfw:00000000000000000000000000000000"
}
EOF
out="$(drv state)"
check 'grep -q "^differs: " <<<"$out"' "a table someone else loaded: differs ($out)"
apply >/dev/null
check 'grep -q "^enforced: " <<<"$(drv state)" && [ "$(live)" = "$D2G" ]' "an apply replaces it"
# The chains flushed: the table and its comment (the digest) stay, the
# rules are gone, nothing is blocked.
"$REAL_NFT" flush table inet stockfw_intel
out="$(drv state)"
check 'grep -q -x -F "differs: The blocklist table is loaded, but the rules of E2E feed, E2E local are gone (removed by another program); apply to restore them." <<<"$out" && [ "$(live)" = "$D2G" ] && [ "$(in_from 198.51.100.100 1)" = 1 ]' \
      "a table whose chains someone flushed (its digest still on it): differs, and the address really passes ($out)"
apply >/dev/null
check 'grep -q "^enforced: " <<<"$(drv state)" && [ "$(live)" = "$D2G" ] && [ "$(in_from 198.51.100.100 1)" = 0 ]' \
      "an apply restores the rules"

# -------------------------------------------------- 9. user Stop, Start
in_from 198.51.100.100 2 >/dev/null
c_before="$(drv counters | tr '\n' ' ')"
out="$(drv suspend)"
check '[ "$out" = suspended ] && [ "$(live)" = absent ]' "Stop: suspend removes the table ($out)"
check 'grep -q "^suspended: " <<<"$(drv state)" && [ "$(drv applied-has $FEED)" = no ]' \
      "state: suspended; the log parser accepts no list line now"
check '[ "$(drv counters | tr "\n" " ")" = "$c_before" ]' "the count survives the suspend ($c_before)"
check '[ "$(in_from 198.51.100.100 1)" = 1 ] && [ "$(out_to 198.51.100.130 1)" = "0 1" ]' \
      "while suspended the listed addresses really pass"
out="$(counted drv resume)"
check 'grep -q "^result ok digest=$D2G " <<<"$out" && [ "$(live)" = "$D2G" ] && grep -q "^enforced: " <<<"$(drv state)"' \
      "Start: resume restores the same digest ($(head -1 <<<"$out"))"
check '[ "$(in_from 198.51.100.100 1)" = 0 ] && [ "$(out_to 198.51.100.130 1)" = "1 0" ]' "and the lists block again"
read -r p b <<<"$(total $FEED)"
read -r p0 b0 <<<"$(awk -v id=$FEED '{ for (i = 1; i < NF; i += 3) if ($i == id) print $(i + 1), $(i + 2) }' <<<"$c_before")"
check '[ "$p" = $((p0 + 1)) ] && [ "$b" = $((b0 + 38)) ]' "the count goes on from where it was ($p0 -> $p)"

# The same through the command line, which stops and starts the
# firewall itself (iptables, in this namespace) and the lists with it.
CLI="${STOCKFW_CLI:-$PORT/build-linux/stockfw}"
CLI_RAN=0
if [ -x "$CLI" ] && command -v iptables >/dev/null; then
  CLI_RAN=1
  mkdir -p "$W/config" "$W/clirules"
  cli() { PATH="$W/log:$PATH" XDG_CONFIG_HOME="$W/config" STOCKFW_RULES_DIR="$W/clirules" "$CLI" "$@"; }
  # `stockfw start' refuses to start with no policy saved and none
  # applied before (the start gate): give it one rule of its own, in
  # the scratch directory, never /etc/stockfw.
  cli -q policy add inbound-allow-service SSH 22 Anyone > /dev/null
  out="$(cli stop)"; rc=$?
  check '[ $rc -eq 0 ] && grep -q -x "Firewall stopped." <<<"$out" && [ "$(live)" = absent ] && grep -q "^suspended: " <<<"$(drv state)"' \
        "stockfw stop: the firewall stops, the lists are removed and suspended ($out)"
  out="$(counted cli start)"; rc=$?
  check '[ $rc -eq 0 ] && grep -q -x "Blocklists applied (2 lists)." <<<"$out" && [ "$(live)" = "$D2G" ] && grep -q "^enforced: " <<<"$(drv state)"' \
        "stockfw start: the firewall starts and the same digest is enforced again ($(tr '\n' ' ' <<<"$out"))"
  out="$(cli --json stop)"; rc=$?
  check '[ $rc -eq 0 ] && grep -q "\"intel\":{\"ok\":true,\"result\":\"suspended\"" <<<"$out" && [ "$(live)" = absent ]' \
        "stockfw --json stop: the JSON says the lists were suspended ($out)"
  out="$(counted cli --json start)"; rc=$?
  check '[ $rc -eq 0 ] && grep -q "\"intel\":{\"ok\":true,\"result\":\"applied\"" <<<"$out" && [ "$(live)" = "$D2G" ]' \
        "stockfw --json start: the JSON says the lists were applied ($(cut -c1-160 <<<"$out"))"
  cli -q stop >/dev/null
  out="$(counted drv resume)"
  check 'grep -q "^result ok digest=$D2G " <<<"$out" && ! iptables -S | grep -qi stockfw' \
        "(the firewall stopped again, the lists back for what follows)"
else
  echo "skip: stockfw stop and start (no $CLI, or no iptables)"
fi

# Without nft.  A record that says a table was left (this one): the
# Stop cannot remove it, cannot tell it is gone, and says so; the state
# is unknown, never off.
mkdir -p "$W/empty"
nonft() { env PATH="$W/empty" "$DRV" "$@"; }
out="$(nonft suspend)"; rc=$?
check '[ $rc -eq 1 ] && grep -q "nft was not found on PATH" <<<"$out" && [ "$(live)" = "$D2G" ] && grep -q "^unknown: " <<<"$(nonft state)"' \
      "without nft, after a load: Stop fails, saying why; the state is unknown ($out)"
# A store where nothing was ever loaded: not an error, and off.
mkdir -m 700 /var/lib/nonft
out="$(STOCKFW_INTEL_DIR=/var/lib/nonft nonft suspend)"; rc=$?
check '[ $rc -eq 0 ] && [ "$out" = suspended ]' "without nft, nothing ever loaded: Stop is not an error ($out)"
out="$(STOCKFW_INTEL_DIR=/var/lib/nonft nonft state)"
check '[ "$out" = "off: No blocklist is turned on." ]' "... and the state is off, not unknown ($out)"
# No store at all: nothing to do, and none is made.
out="$(STOCKFW_INTEL_DIR=/var/lib/never nonft suspend)"; rc=$?
check '[ $rc -eq 0 ] && [ ! -e /var/lib/never ]' "no store at all: Stop does nothing and creates none ($out)"

# --------------------------------------------- 10. the master switch off
c_before="$(drv counters | tr '\n' ' ')"
drv master off >/dev/null
out="$(apply)"
check 'grep -q "^result ok digest=[0-9a-f]* sets=0 v4=0 v6=0$" <<<"$out" && [ "$(live)" = absent ]' \
      "master switch off: the apply removes the table ($(head -1 <<<"$out"))"
check '[ "$(drv state)" = "off: Threat intel is switched off." ]' "state: off"
check '[ "$(in_from 198.51.100.10 1)" = 1 ] && [ "$(out_to 198.51.100.130 1)" = "0 1" ] && [ "$(lk 198.51.100.10)" = "listed=- dir=- protected=0 exception=0 host=0 blocked=0 " ]' \
      "nothing is blocked any more, and the lookup says so"
before=$(requests)
out="$(drv update)"
check '[ "$out" = "$FEED not-due 0 Threat intel is switched off." ] && [ "$(requests)" = "$before" ]' \
      "an update makes no request while switched off ($out)"
check '[ "$(drv counters | tr "\n" " ")" = "$c_before" ]' "the carried counts stay ($c_before)"

# ------------------------------------------------------------ 11. audit
n_apply=$(grep -c " | intel-apply | " "$W/audit.log")
n_held=$(grep -c " | intel-apply | source=e2e-test result=held " "$W/audit.log")
n_failed=$(grep -c " | intel-apply | source=e2e-test result=failed " "$W/audit.log")
APPLIES=$(wc -l < "$W/applies")
check '[ "$n_apply" = "$APPLIES" ] && [ "$n_held" = 1 ] && [ "$n_failed" = 3 ]' \
      "one audit line per apply attempt ($n_apply of $APPLIES; held $n_held, failed $n_failed)"
check '[ "$(grep -c " | intel-suspend | source=e2e-test result=ok" "$W/audit.log")" = 2 ] && [ "$(grep -c " | intel-suspend | source=e2e-test result=failed" "$W/audit.log")" = 1 ] && [ "$(grep -c " | intel-update | " "$W/audit.log")" = 9 ] && [ "$(grep -c " | intel-import | " "$W/audit.log")" = 1 ]' \
      "and one per suspend, feed update attempt and import"
check '[ $CLI_RAN = 0 ] || { [ "$(grep -c " | intel-suspend | source=cli result=ok" "$W/audit.log")" = 3 ] && [ "$(grep -c " | intel-apply | source=cli result=ok" "$W/audit.log")" = 2 ]; }' \
      "the command line's stops and starts are audited as source=cli"

echo
if [ $fails -eq 0 ]; then echo "PASSED: 0 failure(s)"; else echo "FAILED: $fails failure(s)"; fi
[ $fails -eq 0 ]
