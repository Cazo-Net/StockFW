#!/bin/bash
# `stockfw intel' end to end (1.0.7, design section 8): the commands a
# user types, their output, their --json documents and their exit
# codes, against the real engine, store, downloader and nft.
#
# Runs in private namespaces: it re-executes itself under `unshare -n
# -m', so the host's network, firewall and /var/lib are never touched.
# In there the store is the default one, /var/lib/stockfw/intel, on a
# tmpfs mounted over /var/lib; the feed server is a local HTTPS server
# on 127.0.0.1 with a throwaway CA; the policy files, the preferences
# and the audit log live in a scratch directory.
#
# The binary is stockfw-intel-test (ninja -C build-linux
# stockfw-intel-test): the real CLI sources and Linux backend, whose
# copy of fs-fetch.c is compiled with FS_FETCH_TESTING so
# $STOCKFW_TEST_CACERT names the test CA.  Needs root, nft, curl,
# openssl, python3, unshare, mount and setpriv; SKIPs without them.
# `stockfw start'/`stop' checks also need iptables.
#
# What it proves:
#   - read-only commands (status, feeds, lists, exceptions, lookup,
#     terms, update with nothing on) never create the store and make no
#     request; `feeds' shows every catalog feed with its licence (or
#     "see terms"), the non-commercial flag, its credit and terms page;
#   - turning a feed on without --accept-terms changes nothing, shows
#     the terms and exits 2 (also as JSON); with it the feed is on and
#     the acceptance is recorded; unknown ids and bad values exit 2;
#   - a custom feed is added (its URL's query string never printed),
#     updated from the server as StockFW/<version>: updated, not due,
#     unchanged with --now; a copy that shrank is refused (exit 1, the
#     old copy kept) until --accept-shrink; an HTTP error fails (exit 1);
#   - local lists: import (a bad line skipped, private space left out),
#     lists, list show with its ranges, the `list add' alias, remove;
#     exceptions: add, a bad one refused with nothing saved, remove;
#   - apply loads the table (the digest the CLI reports is the kernel's),
#     the state is enforced; lookup exits 5 for a listed address and 0
#     for an exception, and agrees with the kernel's sets; dry run
#     changes nothing; audit-only mode holds the apply (exit 0, the
#     kernel untouched); clear removes the table and keeps the lists
#     configured (state not-loaded, one intel-clear audit line), apply
#     restores it; the master switch off empties the kernel;
#   - `intel update' re-applies the new copies only while the firewall
#     runs and the lists are enforced: with the firewall stopped, or the
#     lists cleared, it says so and loads nothing; --no-apply never
#     applies;
#   - not root: apply and clear exit 3 and touch nothing; status with a
#     root-only store exits 3 and says needs-root;
#   - `stockfw status' carries the same state (plain and --json);
#   - countries and networks (`intel geo', section 10, the signed test
#     databases of tests/geodb through a stand-in curl): consent first,
#     never a store for a refusal; update, unchanged, an older copy
#     refused; status, search, add, list, remove; apply into the
#     country's sets with the anycast note; lookups with "registered
#     in", NAT64 and a damaged copy; nobody exits 3; off empties them.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
CLI="${STOCKFW_INTEL_CLI:-${STOCKFW_BUILD:-$PORT/build-linux}/stockfw-intel-test}"

if [ "${STOCKFW_IN_NETNS:-}" != 1 ]; then
  if [ "$(id -u)" != 0 ]; then
    echo "SKIP: needs root"
    exit 0
  fi
  for tool in nft unshare mount openssl python3 setpriv; do
    if ! command -v "$tool" >/dev/null; then
      echo "SKIP: needs $tool"
      exit 0
    fi
  done
  if [ ! -x /usr/bin/curl ] && [ ! -x /bin/curl ]; then
    echo "SKIP: needs curl in /usr/bin or /bin"
    exit 0
  fi
  if [ ! -x "$CLI" ]; then
    echo "SKIP: $CLI not built -- ninja -C build-linux stockfw-intel-test"
    exit 0
  fi
  if ! unshare -n -m true 2>/dev/null; then
    echo "SKIP: cannot make network and mount namespaces here (unshare -n -m)"
    exit 0
  fi
  export STOCKFW_INTEL_CLI="$CLI"
  STOCKFW_IN_NETNS=1 exec unshare -n -m --propagation private "$0" "$@"
fi

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
check() {   # on a failure, the last command's exit status and output too
  if eval "$1"; then ok "$2"; else
    bad "$2"
    printf '      rc=%s\n      out: %s\n      err: %s\n' "${rc:-}" \
      "$(head -c 600 <<<"${out:-}" | tr '\n' ' ')" "$(head -c 300 <<<"${err:-}" | tr '\n' ' ')"
  fi
}
die()   { bad "$*"; echo; echo "FAILED: $fails failure(s)"; exit 1; }
py()    { python3 -I -c "$@"; }

mount -t tmpfs -o mode=0755 stockfw-cli /var/lib || die "could not mount a tmpfs over /var/lib"
unset STOCKFW_INTEL_DIR STOCKFW_TEST_CURL SSH_CLIENT SSH_CONNECTION NO_COLOR
export STOCKFW_AUDIT_FILE="$W/audit.log"
export STOCKFW_TEST_CACERT="$W/ca.pem"
export STOCKFW_RULES_DIR="$W/rules"
export XDG_CONFIG_HOME="$W/config"
export STOCKFW_LOG_FILE="$W/kern.log"
: > "$W/kern.log"
STORE=/var/lib/stockfw/intel
FEED=custom-cli-feed
ip link set lo up

S() { "$CLI" "$@"; }
# run CMD...: $out (stdout), $err (stderr), $rc
run() { out="$("$CLI" "$@" 2>"$W/err")"; rc=$?; err="$(cat "$W/err")"; }
jget() {   # jget EXPR: EXPR over the JSON in $out (d); a tuple prints space-separated
  py "import json,sys
d = json.loads(sys.argv[1]); r = eval(sys.argv[2])
print(' '.join(map(str, r)) if isinstance(r, tuple) else r)" "$out" "$1"
}
live() {   # "<digest>" of the table, or "absent"
  nft -j list tables 2>/dev/null | python3 -I -c '
import json, sys
for t in json.load(sys.stdin)["nftables"]:
    t = t.get("table")
    if t and t["family"] == "inet" and t["name"] == "stockfw_intel":
        print(t.get("comment", "").removeprefix("sfw:")); break
else:
    print("absent")'
}
has_element() { nft get element inet stockfw_intel "$1" "{ $2 }" >/dev/null 2>&1; }
audit_lines() { grep -c " | $1 | " "$W/audit.log" 2>/dev/null || true; }

# --------------------------------------------------------- the server
cat > "$W/https.py" <<'EOF'
import os, ssl, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
d = sys.argv[1]
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *args):
        pass
    def do_GET(self):
        with open(os.path.join(d, "https.log"), "a") as f:
            f.write("%s %s\n" % (self.path, self.headers.get("User-Agent", "-")))
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
srv = Server(("127.0.0.1", 443), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.path.join(d, "srv.pem"), os.path.join(d, "srv.key"))
srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
open(os.path.join(d, "ready"), "w").close()
srv.serve_forever()
EOF
SRV="$W/serve"
mkdir -p "$SRV"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=StockFW CLI test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$W/ca.key" -out "$W/ca.pem" >/dev/null 2>&1 &&
openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" \
  -keyout "$SRV/srv.key" -out "$W/srv.csr" >/dev/null 2>&1 &&
printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > "$W/srv.ext" &&
openssl x509 -req -days 2 -in "$W/srv.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" \
  -CAcreateserial -extfile "$W/srv.ext" -out "$SRV/srv.pem" >/dev/null 2>&1 ||
  die "could not make the test CA with openssl"
chmod 644 "$W/ca.pem"
serve() { cp "$1" "$SRV/body.new" && mv "$SRV/body.new" "$SRV/body"; echo "${2:-200}" > "$SRV/status"; }
requests() { if [ -f "$SRV/https.log" ]; then wc -l < "$SRV/https.log"; else echo 0; fi; }

NOW="$(date -u +%s)"
stamp() { date -u -d "@$1" '+%Y-%m-%d %H:%M:%S'; }
feed_copy() {   # feed_copy AGE_DAYS ENTRY...
  printf '# StockFW CLI test feed\n# Last updated: %s UTC\n' "$(stamp $((NOW - $1 * 86400)))"
  shift
  printf '%s\n' "$@"
}
# v1: 16 entries (enough history for the shrink guard), 203.0.113.0/26
# among them.
V1_ADDRS="203.0.113.0/26 198.51.100.10 198.51.100.11 198.51.100.12 198.51.100.13
  198.51.100.14 198.51.100.15 198.51.100.16 198.51.100.17 198.51.100.18 198.51.100.19
  198.51.100.20 198.51.100.21 198.51.100.22 198.51.100.23 198.51.100.24"
# shellcheck disable=SC2086
feed_copy 2 $V1_ADDRS > "$W/v1.txt"
feed_copy 1 198.51.100.10 198.51.100.11 > "$W/small.txt"
# shellcheck disable=SC2086
feed_copy 0 $V1_ADDRS > "$W/v1-now.txt"
# shellcheck disable=SC2086
feed_copy 0 $V1_ADDRS 198.51.100.99 > "$W/v3.txt"
serve "$W/v1.txt"
python3 -I "$W/https.py" "$SRV" &
PIDS="$PIDS $!"
for _ in $(seq 100); do [ -e "$SRV/ready" ] && break; sleep 0.1; done
[ -e "$SRV/ready" ] || die "the test HTTPS server did not start"

# ------------------------------------------------ 1. nothing turned on
run intel
check '[ $rc -eq 0 ] && grep -q "Threat intel off" <<<"$out" && [ ! -e /var/lib/stockfw ]' \
      "intel (status): off, exit 0, and no store is created"
run --json intel status
check '[ $rc -eq 0 ] && [ "$(jget "d[\"state\"], d[\"lists\"]")" = "off []" ]' \
      "intel --json status: {state: off, lists: []}"
run --json intel feeds
check '[ $rc -eq 0 ] && [ ! -e /var/lib/stockfw ] && py "
import json, sys
d = json.loads(sys.argv[1])
f = {x[\"id\"]: x for x in d[\"feeds\"]}
assert len(f) == 9 and all(x[\"kind\"] == \"catalog\" and not x[\"enabled\"] for x in f.values()), f.keys()
assert all(x[\"credit\"] and x[\"terms_url\"].startswith(\"https://\") for x in f.values())
assert f[\"spamhaus-drop\"][\"credit\"].startswith(\"The Spamhaus Project\") and f[\"spamhaus-drop\"][\"licence\"] is None
assert f[\"spamhaus-drop\"][\"interval_hours\"] == 24
assert f[\"feodo\"][\"licence\"] == \"CC0\" and not f[\"feodo\"][\"noncommercial\"]
assert f[\"dshield\"][\"licence\"] == \"CC BY-NC-SA 2.5\" and f[\"dshield\"][\"noncommercial\"]
assert f[\"firehol-level1\"][\"noncommercial\"] and f[\"firehol-level1\"][\"host\"] == \"raw.githubusercontent.com\"
assert all(x[\"status\"] == \"off\" and x[\"updated_at\"] is None for x in f.values())
" "$out"' "intel --json feeds: every catalog feed, off, with licence, non-commercial flag, credit and terms; no store"
run intel feeds
check '[ $rc -eq 0 ] && grep -q "^dshield .*CC BY-NC-SA 2.5, non-commercial  DShield.org" <<<"$out" && grep -q "^spamhaus-drop .*see terms  *The Spamhaus Project" <<<"$out"' \
      "intel feeds: a table with the licence (or \"see terms\") and the credit"
run intel lookup 203.0.113.9
check '[ $rc -eq 0 ] && grep -q "^NOT LISTED" <<<"$out" && [ ! -e /var/lib/stockfw ]' "intel lookup: not listed, exit 0, no store"
run intel update
check '[ $rc -eq 0 ] && grep -q "No feed is turned on" <<<"$out" && [ "$(requests)" = 0 ] && [ ! -e /var/lib/stockfw ]' \
      "intel update with nothing on: no request at all, no store"
run --json status
check '[ $rc -eq 0 ] && [ "$(jget "d[\"intel\"][\"state\"]")" = off ] && [ ! -e /var/lib/stockfw ]' \
      "status --json: intel.state off, no store"
run intel terms spamhaus-drop
check '[ $rc -eq 0 ] && grep -q "from www.spamhaus.org once a day" <<<"$out" && grep -q "terms of use: https://www.spamhaus.org/drop/terms/" <<<"$out"' \
      "intel terms: the host, how often, and the terms page"
run intel terms nosuch
check '[ $rc -eq 2 ]' "intel terms of an unknown feed: exit 2"
# The location database: read-only commands, refusals and consent
# never create the store either.
run intel geo
check '[ $rc -eq 0 ] && grep -q "^  Location  *off" <<<"$out" && grep -q "registered, not where a computer is" <<<"$out" && [ ! -e /var/lib/stockfw ]' \
      "intel geo (status): off, exit 0, the \"registered\" sentence, no store"
run --json intel geo status
check '[ $rc -eq 0 ] && [ "$(jget "d[\"supported\"], d[\"enabled\"], d[\"database\"][\"present\"], d[\"rules\"], d[\"url\"]")" = "True False False [] https://location.ipfire.org/databases/1/location.db.xz" ] && [ ! -e /var/lib/stockfw ]' \
      "intel geo status --json: supported, off, no database, no rules; no store"
run intel geo terms
check '[ $rc -eq 0 ] && grep -q "location.ipfire.org" <<<"$out" && [ ! -e /var/lib/stockfw ]' "intel geo terms: names location.ipfire.org; no store"
run intel geo search Example
check '[ $rc -eq 1 ] && grep -q "not been downloaded" <<<"$err" && [ ! -e /var/lib/stockfw ]' "geo search with no database: exit 1, says why; no store"
run intel geo on
check '[ $rc -eq 2 ] && grep -q "location.ipfire.org" <<<"$out" && grep -q "accept-terms" <<<"$err" && [ ! -e /var/lib/stockfw ]' \
      "geo on without --accept-terms: exit 2, the terms shown, the flag named, no store"
run --json intel geo on
check '[ $rc -eq 2 ] && [ "$(jget "d[\"needs_consent\"], d[\"enabled\"], \"location.ipfire.org\" in d[\"terms\"]")" = "True False True" ] && [ ! -e /var/lib/stockfw ]' \
      "  ... as JSON: needs_consent, the terms, exit 2"
run intel geo add country DE
check '[ $rc -eq 2 ] && grep -q "accept-terms" <<<"$err" && [ ! -e /var/lib/stockfw ]' "geo add before consent: exit 2, no store"
run intel geo off
check '[ $rc -eq 0 ] && [ ! -e /var/lib/stockfw ]' "geo off with nothing on: exit 0, no store"
run intel geo frobnicate
check '[ $rc -eq 2 ]' "an unknown geo action: exit 2"

# ----------------------------------------------- 2. consent, ids, values
run intel enable spamhaus-drop
check '[ $rc -eq 2 ] && grep -q "www.spamhaus.org" <<<"$out" && grep -q "accept-terms" <<<"$err"' \
      "enable without --accept-terms: exit 2, the terms shown, the flag named"
run --json intel feeds
check '[ "$(jget "[x[\"enabled\"] for x in d[\"feeds\"] if x[\"id\"] == \"spamhaus-drop\"][0]")" = False ]' \
      "  ... and the feed is still off"
run --json intel enable spamhaus-drop
check '[ $rc -eq 2 ] && [ "$(jget "d[\"needs_consent\"], d[\"enabled\"], \"spamhaus\" in d[\"terms\"]")" = "True False True" ]' \
      "  ... as JSON: needs_consent, the terms, exit 2"
run --json intel enable spamhaus-drop --accept-terms --direction in
check '[ $rc -eq 0 ] && [ "$(jget "d[\"enabled\"], d[\"terms_accepted_now\"], d[\"direction\"]")" = "True True in" ]' \
      "enable --accept-terms --direction in: on, accepted now"
run --json intel feeds
check '[ "$(jget "[(x[\"enabled\"], x[\"direction\"], x[\"terms_accepted_at\"] > 0, x[\"status\"]) for x in d[\"feeds\"] if x[\"id\"] == \"spamhaus-drop\"][0]")" = "True in True not-downloaded" ]' \
      "  ... feeds says on, in, accepted, not downloaded yet"
run intel disable spamhaus-drop
check '[ $rc -eq 0 ] && grep -q "turned off" <<<"$out"' "disable: exit 0"
run intel enable spamhaus-drop
check '[ $rc -eq 0 ]' "  ... and on again without the flag: the terms stay accepted"
S -q intel disable spamhaus-drop
run intel enable nosuch-feed --accept-terms
check '[ $rc -eq 2 ] && grep -q "no feed or list" <<<"$err"' "enable an unknown id: exit 2"
run intel enable feodo --direction sideways
check '[ $rc -eq 2 ]' "enable --direction sideways: exit 2"
run intel enable feodo --accept-terms --bogus
check '[ $rc -eq 2 ]' "an unknown option: exit 2"
run intel frobnicate
check '[ $rc -eq 2 ]' "an unknown intel action: exit 2"
run intel add-feed "Plain http" http://127.0.0.1/feed.txt
check '[ $rc -eq 2 ]' "add-feed with an http:// URL: refused, exit 2"

# ------------------------------------------------------- 3. a custom feed
run --json intel add-feed "CLI feed" "https://127.0.0.1/feed.txt?key=SECRETKEY" --direction both
check '[ $rc -eq 0 ] && [ "$(jget "d[\"id\"], d[\"enabled\"]")" = "$FEED True" ] && ! grep -q SECRETKEY <<<"$out"' \
      "add-feed: custom-cli-feed, on, its key not printed"
run intel feeds
check '! grep -q SECRETKEY <<<"$out" && grep -q "^$FEED .*CLI feed (https://127.0.0.1/feed.txt?…)" <<<"$out"' \
      "  ... feeds shows it with the query string hidden"
check '[ "$(stat -c %a "$STORE")" = 700 ] && [ "$(stat -c %a "$STORE/intel.conf")" = 600 ]' \
      "the store is made by the first change: 0700, files 0600"

run --json intel update
check '[ $rc -eq 0 ] && [ "$(jget "[(r[\"id\"], r[\"outcome\"], r[\"entries\"]) for r in d[\"results\"]]")" = "[('"'$FEED'"', '"'updated'"', 16)]" ] && [ "$(requests)" = 1 ] && grep -q "^/feed.txt?key=SECRETKEY StockFW/" "$SRV/https.log"' \
      "update: downloaded as StockFW/<version>, 16 entries ($(jget 'd["results"]'))"
check '[ "$(jget "d[\"reapply\"][\"result\"], d[\"reapply\"][\"reason\"]")" = "skipped the firewall is not running" ]' \
      "  ... and not applied: the firewall is not running"
run intel update
check '[ $rc -eq 0 ] && grep -q "^  $FEED  *not-due " <<<"$out" && [ "$(requests)" = 1 ]' "update again: not due, no request"
run intel update --now
check '[ $rc -eq 0 ] && grep -q "^  $FEED  *unchanged " <<<"$out" && [ "$(requests)" = 2 ]' "update --now: fetched, unchanged"
serve "$W/small.txt"
run intel update --now
check '[ $rc -eq 1 ] && grep -q "^  $FEED  *refused " <<<"$out"' "a copy that shrank to 2 entries: refused, exit 1"
check 'grep -q "To take this copy anyway: sudo stockfw intel update --feed $FEED --now --accept-shrink" <<<"$out"' \
      "  ... and it names the flag that takes it (the page's Accept smaller list)"
run --json intel feeds
check '[ "$(jget "[(x[\"entries\"], x[\"status\"], bool(x[\"refused\"]), x[\"accept_with\"]) for x in d[\"feeds\"] if x[\"id\"] == \"$FEED\"][0]")" = "16 refused True --accept-shrink" ]' \
      "  ... the old copy (16 entries) is kept, the status says refused, accept_with --accept-shrink"
run --json intel update --now --feed "$FEED"
check '[ $rc -eq 1 ] && [ "$(jget "d[\"results\"][0][\"outcome\"], d[\"results\"][0][\"accept_with\"]")" = "refused --accept-shrink" ]' \
      "  ... update --json: refused, accept_with --accept-shrink"
run --json intel update --now --accept-shrink --feed "$FEED"
check '[ $rc -eq 0 ] && [ "$(jget "d[\"results\"][0][\"outcome\"], d[\"results\"][0][\"entries\"]")" = "updated 2" ]' \
      "update --accept-shrink --feed: accepted, 2 entries"
serve "$W/v1.txt" 404
run intel update --now
check '[ $rc -eq 1 ] && grep -q "^  $FEED  *failed " <<<"$out"' "an HTTP 404: failed, exit 1"
serve "$W/v1-now.txt"
run intel update --now
check '[ $rc -eq 0 ] && grep -q "^  $FEED  *updated  *16 entries" <<<"$out"' "the next update brings 16 entries back"
run intel update --feed nosuch
check '[ $rc -eq 2 ]' "update --feed with an unknown id: exit 2"
run intel update --feed feodo
check '[ $rc -eq 2 ] && grep -q "turned off" <<<"$err"' "update --feed of a feed that is off: exit 2"

# ------------------------------------------------------- 4. local lists
printf '# mine\n192.0.2.200\n192.0.2.128/28\n10.1.2.3\nnot an address\n2001:db8:77::/48\n' > "$W/mine.txt"
run intel import "$W/mine.txt" --name "My list" --direction out
check '[ $rc -eq 0 ] && grep -q "My list (local-my-list): 4 entries, out" <<<"$out" && grep -q "1 line did not parse (the first is line 5)" <<<"$out" && grep -q "never blocked" <<<"$out"' \
      "import: 4 entries, out; the bad line and the private part are named"
run --json intel lists
check '[ "$(jget "[(l[\"id\"], l[\"name\"], l[\"direction\"], l[\"entries\"], l[\"kind\"]) for l in d[\"lists\"]]")" = "[('"'local-my-list'"', '"'My list'"', '"'out'"', 4, '"'local'"')]" ]' \
      "lists --json: the list, its name, direction, entries"
run --json intel list show local-my-list
check '[ "$(jget "d[\"ranges\"]")" = "['"'192.0.2.128/28'"', '"'192.0.2.200'"', '"'2001:db8:77::/48'"']" ]' \
      "list show ID: its stored ranges, 10.1.2.3 left out ($(jget 'd["ranges"]'))"
# Imported again under the same name in another case and spacing, with
# no --direction: it keeps "out" (the engine matches the name as it does
# to replace the list), never widens to both.
run intel import "$W/mine.txt" --name "my  LIST"
check '[ $rc -eq 0 ] && grep -q "(local-my-list): 4 entries, out" <<<"$out"' \
      "re-import, the name in another case and spacing, no --direction: still out"
S -q intel import "$W/mine.txt" --name "My list"
run --json intel lists
check '[ "$(jget "[(l[\"name\"], l[\"direction\"]) for l in d[\"lists\"]]")" = "[('"'My list'"', '"'out'"')]" ]' \
      "  ... and the list still reads out ($(jget 'd["lists"]'))"
printf '203.0.113.200\n' > "$W/second.txt"
run intel list add "$W/second.txt" --name "Second"
check '[ $rc -eq 0 ] && grep -q "both: blocks both directions" <<<"$out"' "list add (the import alias): a new list blocks both ways"
run intel import "$W/second.txt" --name "second"
check '[ $rc -eq 0 ] && grep -q "Second\|second" <<<"$out"' "  ... the same name in another case replaces it"
run intel import "$W/second.txt" --name "Sec ond"
check '[ $rc -eq 0 ]' "  ... (another name, another id)"
run intel list remove local-sec-ond
check '[ $rc -eq 0 ] && [ ! -e "$STORE/local-sec-ond.list" ]' "list remove: gone, with its stored copy"
run intel import "$W/second.txt"
check '[ $rc -eq 2 ]' "import without --name: exit 2"
run intel import /nonexistent --name x
check '[ $rc -ne 0 ] && [ $rc -ne 3 ]' "import of a missing file: an error ($rc)"
run intel remove spamhaus-drop
check '[ $rc -eq 2 ] && grep -q "cannot be removed" <<<"$err"' "remove a built-in feed: exit 2, turn it off instead"
run intel list show local-nosuch
check '[ $rc -eq 2 ]' "list show of an unknown list: exit 2"

# ------------------------------------------------------- 5. exceptions
run intel except 203.0.113.7 not-an-address
check '[ $rc -eq 2 ] && ! grep -q "203.0.113.7" "$STORE/intel.conf"' "except with one bad value: exit 2, nothing saved"
run --json intel except 203.0.113.7 203.0.113.8
check '[ $rc -eq 0 ] && [ "$(jget "d[\"exceptions\"]")" = "['"'203.0.113.7-203.0.113.8'"']" ]' "except two addresses: merged"
run --json intel unexcept 203.0.113.8
check '[ $rc -eq 0 ] && [ "$(jget "d[\"exceptions\"]")" = "['"'203.0.113.7'"']" ]' "unexcept: taken out again"
run intel exceptions
check '[ $rc -eq 0 ] && grep -q "^203.0.113.7$" <<<"$out"' "exceptions: listed"

# ------------------------------------------------------- 6. apply
run --json intel apply --dry-run
DRY="$(jget 'd["digest"]')"
check '[ $rc -eq 0 ] && [ "$(live)" = absent ] && [ "$(jget "[s[\"id\"] for s in d[\"sets\"]]")" = "['"'$FEED'"', '"'local-my-list'"', '"'local-second'"']" ]' \
      "apply --dry-run: three sets, nothing loaded"
n_applies=$(audit_lines intel-apply)
run --json intel apply
DIG="$(jget 'd["digest"]')"
check '[ $rc -eq 0 ] && [ "$(jget "d[\"applied\"], d[\"state\"], d[\"sets\"]")" = "True enforced 3" ] && [ "$(live)" = "$DIG" ] && [ "$DIG" = "$DRY" ]' \
      "apply: applied, enforced, the kernel holds the reported digest (= the dry run's)"
check '[ "$(audit_lines intel-apply)" = $((n_applies + 1)) ] && grep -q " | intel-apply | source=cli result=ok digest=$DIG " "$W/audit.log"' \
      "  ... one audit line, source=cli"
check 'has_element s_custom_cli_feed_4 203.0.113.9 && has_element s_local_my_list_4 192.0.2.200 && ! has_element s_custom_cli_feed_4 203.0.113.7' \
      "  ... the sets hold the lists, minus the exception"
run intel status
check '[ $rc -eq 0 ] && grep -q "Threat intel enforced" <<<"$out" && grep -q "^$FEED  *CLI feed  *both  *16 " <<<"$out"' "status: enforced, the lists with their entries"
run status
check 'grep -qE "^  Threat intel +enforced" <<<"$out"' "stockfw status: a Threat intel line, enforced"

# ------------------------------------------- a list name on a terminal
# A list name may hold a bidi control (the engine refuses only Cc
# characters, and the desktop app names an import after its file).
# Every line that names the list escapes it, as the table always did:
# the import line, the apply's Now line, `intel status' and `stockfw
# status' (docs 15.2, review notes).  Without the fix the raw U+202E
# reached the terminal and showed "abcexe.txt".
RLO="$(printf '\342\200\256')"
printf '203.0.113.201\n' > "$W/rlo.txt"
run intel import "$W/rlo.txt" --name "abc${RLO}txt.exe"
check '[ $rc -eq 0 ] && ! grep -qF "$RLO" <<<"$out" && grep -qF "abc\\u202etxt.exe" <<<"$out"' \
      "import of a list named with U+202E: the line escapes it"
RLO_ID="$(S --json intel lists | py 'import json,sys; print([l["id"] for l in json.load(sys.stdin)["lists"] if l["name"].startswith("abc")][0])')"
run intel apply
check '[ $rc -eq 0 ] && ! grep -qF "$RLO" <<<"$out" && grep -q "^  Now .*abc\\\\u202etxt.exe" <<<"$out"' \
      "  ... apply: the Now line escapes it"
run intel status
check '[ $rc -eq 0 ] && ! grep -qF "$RLO" <<<"$out" && grep -qF "abc\\u202etxt.exe" <<<"$out"' \
      "  ... intel status: the detail line escapes it"
run status
check '! grep -qF "$RLO" <<<"$out" && grep -qE "^  Threat intel .*abc\\\\u202etxt.exe" <<<"$out"' \
      "  ... stockfw status: the Threat intel line escapes it"
run intel list remove "$RLO_ID"
check '[ $rc -eq 0 ] && ! grep -qF "$RLO" <<<"$out" && grep -qF "abc\\u202etxt.exe" <<<"$out"' \
      "  ... list remove: the line escapes it"
# Back to the three sets; the checks below compare with this digest.
run --json intel apply
DIG="$(jget 'd["digest"]')"

run --json intel lookup 203.0.113.9
check '[ $rc -eq 5 ] && [ "$(jget "d[\"blocked\"], d[\"in_force\"], d[\"state\"], d[\"direction\"], [l[\"id\"] for l in d[\"lists\"]]")" = "True True enforced both ['"'$FEED'"']" ]' \
      "lookup of a listed address: blocked and in force, exit 5, names the list"
run intel lookup 203.0.113.7
check '[ $rc -eq 0 ] && grep -q "^LISTED, NOT BLOCKED.*exception" <<<"$out"' "lookup of the exception: listed, not blocked, exit 0"
run intel lookup 192.0.2.200
check '[ $rc -eq 5 ] && grep -q "out: stops you connecting" <<<"$out"' "lookup of a local-list address: blocked out, exit 5"
run intel lookup 198.51.100.200
check '[ $rc -eq 0 ] && grep -q "^NOT LISTED" <<<"$out"' "lookup of an unlisted address: exit 0"
run intel lookup 203.0.113.0/24
check '[ $rc -eq 2 ]' "lookup of a network: exit 2 (one address)"

# audit-only mode holds the apply: the kernel keeps the old table.
mkdir -p "$XDG_CONFIG_HOME/stockfw"
printf '[client]\npolicy_audit_only=true\n' > "$XDG_CONFIG_HOME/stockfw/stockfw.conf"
S -q intel except 203.0.113.9
run --json intel apply
check '[ $rc -eq 0 ] && [ "$(jget "d[\"held\"], d[\"applied\"]")" = "True False" ] && [ "$(live)" = "$DIG" ] && has_element s_custom_cli_feed_4 203.0.113.9' \
      "audit-only mode: the apply is held, exit 0, the kernel untouched"
run intel apply
check '[ $rc -eq 0 ] && grep -q "^Held: audit-only testing mode" <<<"$out"' "  ... and says so"
# The exception is saved, not applied: the kernel still blocks it, and
# the lookup says what the kernel does.
run --json intel lookup 203.0.113.9
check '[ $rc -eq 5 ] && [ "$(jget "d[\"blocked\"], d[\"in_force\"], d[\"pending\"], d[\"in_force_lists\"]")" = "False True True ['"'$FEED'"']" ] && has_element s_custom_cli_feed_4 203.0.113.9' \
      "lookup of an exception not applied: the kernel still blocks it, exit 5, pending"
run intel lookup 203.0.113.9
check '[ $rc -eq 5 ] && grep -q "^BLOCKED  the kernel still blocks 203.0.113.9" <<<"$out"' "  ... and says so in words"
rm "$XDG_CONFIG_HOME/stockfw/stockfw.conf"
S -q intel unexcept 203.0.113.9

# clear: the table goes, the lists stay configured.
n_clear=$(audit_lines intel-clear)
run --json intel clear
check '[ $rc -eq 0 ] && [ "$(jget "d[\"cleared\"], d[\"state\"]")" = "True not-loaded" ] && [ "$(live)" = absent ]' \
      "clear: removed from the kernel, state not-loaded"
check '[ "$(audit_lines intel-clear)" = $((n_clear + 1)) ] && grep -q " | intel-clear | source=cli result=ok" "$W/audit.log"' \
      "  ... one intel-clear audit line"
run --json intel status
check '[ "$(jget "d[\"state\"], len(d[\"lists\"])")" = "not-loaded 3" ]' "  ... the three lists are still turned on"
run --json intel lookup 203.0.113.9
check '[ $rc -eq 0 ] && [ "$(jget "d[\"blocked\"], d[\"in_force\"], d[\"state\"]")" = "True False not-loaded" ]' \
      "lookup after clear: listed, not in force, exit 0 (nothing is in the kernel)"
run intel lookup 203.0.113.9
check '[ $rc -eq 0 ] && grep -q "^LISTED, NOT BLOCKED NOW" <<<"$out"' "  ... LISTED, NOT BLOCKED NOW"
run intel clear
check '[ $rc -eq 0 ] && [ "$(live)" = absent ]' "clear again (nothing loaded): not an error"
run intel apply
check '[ $rc -eq 0 ] && [ "$(live)" = "$DIG" ] && grep -q "^Applied 3 lists" <<<"$out"' "apply: the same digest is back"

# ----------------------------------------------- 7. not root
nobody() { setpriv --reuid=65534 --regid=65534 --clear-groups "$CLI" "$@"; }
out="$(nobody intel apply 2>&1)"; rc=$?
check '[ $rc -eq 3 ] && grep -q "needs root" <<<"$out" && [ "$(live)" = "$DIG" ]' "apply as nobody: exit 3, nothing touched"
out="$(nobody intel clear 2>&1)"; rc=$?
check '[ $rc -eq 3 ] && [ "$(live)" = "$DIG" ]' "clear as nobody: exit 3, nothing touched"
out="$(nobody intel status 2>&1)"; rc=$?
check '[ $rc -eq 3 ] && grep -q "needs-root" <<<"$out"' "status as nobody, with root's store: needs-root, exit 3"

# ------------------------------------- 8. update and the running firewall
if command -v iptables >/dev/null; then
  # `stockfw start' refuses to start with no policy saved and none
  # applied before (the start gate): give it one rule to start with.
  S -q policy add inbound-allow-service SSH 22 Anyone > /dev/null
  run stop
  check '[ $rc -eq 0 ] && [ "$(live)" = absent ]' "(stockfw stop: the lists are suspended)"
  run --json intel lookup 203.0.113.9
  check '[ $rc -eq 0 ] && [ "$(jget "d[\"blocked\"], d[\"in_force\"], d[\"state\"]")" = "True False suspended" ]' \
        "lookup with the firewall stopped: listed, not in force, exit 0"
  serve "$W/v3.txt"
  run --json intel update --now
  check '[ $rc -eq 0 ] && [ "$(jget "d[\"results\"][0][\"outcome\"], d[\"reapply\"][\"result\"]")" = "updated skipped" ] && [ "$(live)" = absent ]' \
        "update while the firewall is stopped: stored, not applied ($(jget 'd["reapply"]["reason"]'))"
  run start
  check '[ $rc -eq 0 ] && [ "$(live)" != absent ] && [ "$(live)" != "$DIG" ] && has_element s_custom_cli_feed_4 198.51.100.99' \
        "(stockfw start: the stored copies are applied)"
  run intel clear
  serve "$W/v1-now.txt"
  run --json intel update --now
  check '[ $rc -eq 0 ] && [ "$(jget "d[\"results\"][0][\"outcome\"], d[\"reapply\"][\"result\"], d[\"reapply\"][\"reason\"]")" = "updated skipped the blocklists are not-loaded, not enforced" ] && [ "$(live)" = absent ]' \
        "update while running but the lists cleared: stored, not applied"
  S intel apply > /dev/null
  D3="$(live)"
  serve "$W/v1.txt"
  run --json intel update --now --accept-shrink --no-apply
  check '[ $rc -eq 0 ] && [ "$(jget "d[\"reapply\"][\"result\"]")" = skipped ] && [ "$(live)" = "$D3" ]' \
        "update --no-apply: the firewall running, still nothing applied"
  serve "$W/v3.txt"
  run --json intel update --now
  D4="$(jget 'd["reapply"]["digest"]')"
  check '[ $rc -eq 0 ] && [ "$(jget "d[\"reapply\"][\"result\"]")" = applied ] && [ "$(live)" = "$D4" ] && has_element s_custom_cli_feed_4 198.51.100.99' \
        "update while running and enforced: the new copy is applied at once"
  run stop

  # A Stop during an apply (another process: cron's update, the app):
  # the engine lock makes the Stop wait for the apply and then take the
  # lists down -- the apply never brings them back behind its back.
  # nft is slowed by a wrapper so the apply is still running.
  mkdir -p "$W/slow"
  printf '#!/bin/sh\ncase " $* " in *" -f "*) sleep 2;; esac\nexec %s "$@"\n' \
    "$(command -v nft)" > "$W/slow/nft"
  chmod 755 "$W/slow/nft"
  S -q start
  S -q intel except 198.51.100.77   # a change, so the apply loads a new table
  ( PATH="$W/slow:$PATH" "$CLI" intel apply > "$W/race.out" 2>&1 ) &
  race=$!
  sleep 0.7
  run stop
  wait "$race"
  run --json intel status
  check '[ "$(live)" = absent ] && [ "$(jget "d[\"state\"]")" = suspended ] && [ "$(grep -n " | intel-suspend | source=cli" "$W/audit.log" | tail -1 | cut -d: -f1)" -gt "$(grep -n " | intel-apply | source=cli" "$W/audit.log" | tail -1 | cut -d: -f1)" ]' \
        "a Stop during an apply waits for it, then the lists are down and suspended ($(jget 'd["state"]'))"
  S -q intel unexcept 198.51.100.77
else
  echo "skip: update with the firewall running (no iptables)"
fi
S intel apply > /dev/null

# ------------------------------------------------ 9. the master switch
run intel off
check '[ $rc -eq 0 ] && [ "$(live)" != absent ]' "intel off: saved, the kernel untouched until apply"
run --json intel apply
check '[ $rc -eq 0 ] && [ "$(jget "d[\"state\"], d[\"sets\"]")" = "off 0" ] && [ "$(live)" = absent ]' "apply with the switch off: the table is removed, state off"
before=$(requests)
run intel update --now
check '[ $rc -eq 0 ] && [ "$(requests)" = "$before" ]' "update with the switch off: no request"
S -q intel on
run intel remove "$FEED"
check '[ $rc -eq 0 ] && [ ! -e "$STORE/$FEED.list" ] && [ ! -e "$STORE/$FEED.state" ]' "remove the custom feed: its files are gone"

# ------------------------------------- 10. countries and networks
# The database comes from a stand-in curl (STOCKFW_TEST_CURL) that logs
# its arguments and prints the file in $GEO/serve: the test databases
# of tests/geodb, xz'd, signed with k1's key (STOCKFW_TEST_GEODB_KEY).
# curl runs as nobody: everything it touches is world-readable.
GEO="$W/geo"
mkdir -p "$GEO"
chmod 755 "$GEO"
: > "$GEO/curl.log"
chmod 666 "$GEO/curl.log"
printf '#!/bin/sh\necho "$*" >> %s/curl.log\nexec cat %s/serve\n' "$GEO" "$GEO" > "$GEO/curl"
chmod 755 "$GEO/curl"
for db in small small-older small-newer; do
  py "import lzma, sys
open(sys.argv[2], 'wb').write(lzma.compress(open(sys.argv[1], 'rb').read(), format=lzma.FORMAT_XZ))" \
     "$PORT/tests/geodb/$db.db" "$GEO/$db.db.xz" || die "could not xz $db.db"
done
chmod 644 "$GEO"/*.xz
geo_serve() { cp "$GEO/$1.db.xz" "$GEO/serve.new" && chmod 644 "$GEO/serve.new" && mv "$GEO/serve.new" "$GEO/serve"; }
geo_requests() { wc -l < "$GEO/curl.log"; }
export STOCKFW_TEST_GEODB_KEY="$PORT/tests/geodb/k1.pub"
export STOCKFW_TEST_CURL="$GEO/curl"
geo_serve small
S -q intel on

run intel geo update
check '[ $rc -eq 2 ] && grep -q "geo on --accept-terms" <<<"$err" && [ "$(geo_requests)" = 0 ]' \
      "geo update with the database off: exit 2, the way to turn it on, no request"
run --json intel geo on --accept-terms
check '[ $rc -eq 0 ] && [ "$(jget "d[\"enabled\"], d[\"terms_accepted_now\"], d[\"database_present\"]")" = "True True False" ] && [ "$(geo_requests)" = 0 ]' \
      "geo on --accept-terms: on, accepted now, nothing downloaded by the switch"
run --json intel geo update --no-apply
check '[ $rc -eq 0 ] && [ "$(jget "[(r[\"id\"], r[\"outcome\"]) for r in d[\"results\"]]")" = "[('"'location'"', '"'updated'"')]" ] && [ "$(geo_requests)" = 1 ] && grep -q "location.ipfire.org/databases/1/location.db.xz" "$GEO/curl.log"' \
      "geo update: downloaded from location.ipfire.org, updated"
check 'cmp -s "$PORT/tests/geodb/small.db" "$STORE/location.db" && [ "$(stat -c %a "$STORE/location.db")" = 600 ]' \
      "  ... the stored copy is the signed database, 0600"
run intel geo update --no-apply
check '[ $rc -eq 0 ] && grep -q "^  location  *unchanged" <<<"$out" && [ "$(geo_requests)" = 2 ]' "geo update again: fetched (--now), unchanged"
run intel update
check '[ $rc -eq 0 ] && [ "$(geo_requests)" = 2 ]' "intel update without --now: the database is not due (at most daily), no request"
geo_serve small-older
run --json intel geo update --no-apply
check '[ $rc -eq 1 ] && [ "$(jget "d[\"results\"][0][\"outcome\"]")" = refused ] && cmp -s "$PORT/tests/geodb/small.db" "$STORE/location.db"' \
      "an older database: refused, exit 1, the copy in use kept"
geo_serve small
run --json intel geo status
check '[ $rc -eq 0 ] && [ "$(jget "d[\"enabled\"], d[\"database\"][\"present\"], d[\"database\"][\"created_at\"], d[\"database\"][\"stale\"], d[\"database\"][\"licence\"], d[\"database\"][\"networks\"], d[\"database\"][\"countries\"], bool(d[\"database\"][\"refused\"])")" = "True True 1700000000 True CC0-1.0 17 7 True" ]' \
      "geo status --json: the copy's date, stale, licence, 17 networks, 7 countries, the refusal"
check '[ -n "$(jget "d[\"attribution\"]")" ] && grep -q "IPFire" <<<"$(jget "d[\"attribution\"]")"' "  ... and the attribution"
run intel geo status
check '[ $rc -eq 0 ] && grep -q "copy of 2023-11-14: 17 networks, 7 countries" <<<"$out" && grep -q "out of date (older than 30 days), still used by the rules" <<<"$out" && grep -q "refused" <<<"$out" && grep -q "IPFire" <<<"$out"' \
      "geo status: the copy's day, out of date and still used (it is on), the refusal, the attribution"

run --json intel geo search ex
check '[ $rc -eq 0 ] && [ "$(jget "[a[\"asn\"] for a in d[\"ases\"]], [c[\"code\"] for c in d[\"countries\"]]")" = "[64500, 64501] []" ]' \
      "geo search ex: the ASes whose name has it ($(jget 'd["ases"]'))"
run --json intel geo search nether
check '[ $rc -eq 0 ] && [ "$(jget "[c[\"code\"] for c in d[\"countries\"]]")" = "['"'NL'"']" ]' "geo search nether: the Netherlands"
run intel geo search
check '[ $rc -eq 2 ]' "geo search with no text: exit 2"

run --json intel geo add country NL --dir in
check '[ $rc -eq 0 ] && [ "$(jget "d[\"id\"], d[\"name\"], d[\"values\"], d[\"direction\"], d[\"enabled\"]")" = "country-netherlands Netherlands ['"'NL'"'] in True" ]' \
      "geo add country NL --dir in: country-netherlands, named from the database"
run intel geo add asn 64500,AS64501
check '[ $rc -eq 0 ] && grep -q "(asn-" <<<"$out" && grep -q "AS64500, AS64501" <<<"$out"' "geo add asn with two values: one rule, both named"
ASN_ID="$(grep -o '(asn-[a-z0-9-]*)' <<<"$out" | tr -d '()')"
run intel geo add country XQ
check '[ $rc -eq 0 ] && grep -q "names no country XQ" <<<"$out"' "geo add of a code the database lacks: saved, and says so"
XQ_ID="$(grep -o '(country-[a-z0-9-]*)' <<<"$out" | tr -d '()')"
run intel geo add country NLD
check '[ $rc -eq 2 ]' "geo add country NLD (not two letters): exit 2"
run intel geo add asn ASX
check '[ $rc -eq 2 ]' "geo add asn ASX: exit 2"
run intel geo add country NL --dir sideways
check '[ $rc -eq 2 ]' "geo add --dir sideways: exit 2"
run intel geo add region NL
check '[ $rc -eq 2 ]' "geo add region: exit 2"
run --json intel geo list
check '[ $rc -eq 0 ] && [ "$(jget "sorted((r[\"id\"], r[\"status\"]) for r in d[\"rules\"])")" = "[('"'$ASN_ID'"', '"'not-applied'"'), ('"'country-netherlands'"', '"'not-applied'"'), ('"'$XQ_ID'"', '"'not-applied'"')]" ]' \
      "geo list --json: three rules, not applied yet"
run intel geo remove "$XQ_ID"
check '[ $rc -eq 0 ] && grep -q "removed" <<<"$out"' "geo remove: the rule is gone"
run intel geo remove spamhaus-drop
check '[ $rc -eq 2 ]' "geo remove of a feed id: exit 2"

run intel apply
check '[ $rc -eq 0 ] && has_element s_country_netherlands_6 2c0f:f000::1 && has_element s_country_netherlands_4 192.0.2.10' \
      "apply: the country's networks are in its sets"
check 'grep -q "anycast" <<<"$out"' "  ... and the apply says the Netherlands includes anycast networks"
check '! has_element s_country_netherlands_4 198.51.100.7' "  ... and nothing of another country"
run --json intel geo list
check '[ $rc -eq 0 ] && [ "$(jget "[r[\"status\"] for r in d[\"rules\"] if r[\"id\"] == \"country-netherlands\"]")" = "['"'in-force'"']" ]' \
      "geo list --json after apply: the country rule is in-force"
# The live rules gone behind StockFW's back: the record of the last
# apply still lists the rule, but no surface may call it in force.
nft delete table inet stockfw_intel
run --json intel geo list
check '[ $rc -eq 0 ] && [ "$(jget "[r[\"status\"] for r in d[\"rules\"] if r[\"id\"] == \"country-netherlands\"]")" = "['"'not-in-force'"']" ]' \
      "the table deleted by hand: geo list --json says not-in-force, never in-force ($(jget 'd["rules"]'))"
run intel geo list
check '[ $rc -eq 0 ] && grep -q "not-in-force" <<<"$out" && ! grep -qw "in-force" <<<"$(sed "s/not-in-force//g" <<<"$out")"' \
      "  ... and so does the plain list"
run --json intel status
check '[ "$(jget "[r[\"status\"] for r in d[\"location\"][\"rules\"] if r[\"id\"] == \"country-netherlands\"]")" = "['"'not-in-force'"']" ]' \
      "  ... and the location object of intel status --json (/api/intel)"
run intel apply
check '[ $rc -eq 0 ] && has_element s_country_netherlands_4 192.0.2.10' "apply again: the country's sets are back"
run --json intel lookup 192.0.2.10
check '[ $rc -eq 5 ] && [ "$(jget "d[\"blocked\"], [l[\"id\"] for l in d[\"locations\"]], d[\"location\"][\"country\"], d[\"location\"][\"asn\"], d[\"location\"][\"anycast\"], d[\"location\"][\"meaning\"]")" = "True ['"'country-netherlands'"'] NL 64504 False registered in" ]' \
      "lookup in a blocked country: exit 5, the rule, NL, AS64504, not anycast, \"registered in\" ($(jget 'd["location"]'))"
run intel lookup 2c0f:f000::1
check '[ $rc -eq 5 ] && grep -q "^  Registered in  *Netherlands (NL)" <<<"$out" && grep -q "^  Network  *2c0f:f000::/20, anycast" <<<"$out" && grep -q "IPFire" <<<"$out" && grep -q "not where the computer is" <<<"$out"' \
      "lookup (plain) of the anycast network: Registered in, anycast, the meaning, the attribution"
run --json intel lookup 64:ff9b::c000:20a
check '[ "$(jget "d[\"location\"][\"country\"], d[\"location\"][\"asn\"], d[\"location\"][\"via_nat64\"]")" = "NL 64504 True" ]' \
      "lookup of a NAT64 address: the IPv4 address's country and network, via_nat64"
run --json intel lookup 198.51.100.6
check '[ $rc -eq 0 ] && [ "$(jget "d[\"location\"][\"found\"], d[\"locations\"]")" = "False []" ]' "lookup of an address the database lacks: found false, exit 0"
run intel lookup 10.0.0.1
check '[ $rc -eq 0 ] && grep -q "^  Registered in  *Germany (DE)" <<<"$out"' "lookup of 10.0.0.1: registered in Germany (the test database says so)"
run intel lookup 10.1.0.1
check '[ $rc -eq 0 ] && grep -q "^LISTED, NOT BLOCKED.*never blocked" <<<"$out" && grep -q "^  Registered in  *United States (US)" <<<"$out"' \
      "lookup of 10.1.0.1 (AS64501, private space): listed, never blocked, registered in the US"
run intel lookup 2001:db8:2::1
check '[ $rc -eq 5 ] && grep -q "AS64501 Example Two GmbH" <<<"$out" && grep -q "AS64500, AS64501" <<<"$out"' \
      "lookup in a blocked network (AS64501): exit 5, the network and the rule"

# The copy in use damaged: lookups say unknown, never "not listed".
cp "$STORE/location.db" "$W/location.db.good"
py "import sys
p = sys.argv[1]; b = bytearray(open(p, 'rb').read()); b[len(b) // 2] ^= 0xff; open(p, 'wb').write(b)" "$STORE/location.db"
run --json intel lookup 192.0.2.10
check '[ "$(jget "d[\"location\"][\"unknown\"], d[\"locations_unknown\"] != []")" = "True True" ]' \
      "the database damaged: lookup says unknown ($(jget 'd["location"]'))"
cp "$W/location.db.good" "$STORE/location.db"
cmp -s "$W/location.db.good" "$STORE/location.db" || die "could not restore location.db"

run --json intel disable country-netherlands
check '[ $rc -eq 0 ] && [ "$(jget "d[\"enabled\"]")" = False ]' "intel disable country-netherlands: off"
run --json intel enable country-netherlands --direction out
check '[ $rc -eq 0 ] && [ "$(jget "d[\"enabled\"], d[\"direction\"]")" = "True out" ]' "intel enable country-netherlands --direction out: on, out"
run --json intel status
check '[ "$(jget "d[\"location\"][\"enabled\"], len(d[\"location\"][\"rules\"])")" = "True 2" ]' "intel status --json: the location object, two rules"

out="$(nobody intel geo on --accept-terms 2>&1)"; rc=$?
check '[ $rc -eq 3 ]' "geo on as nobody: exit 3"
out="$(nobody intel geo add country DE 2>&1)"; rc=$?
check '[ $rc -eq 3 ]' "geo add as nobody: exit 3"
out="$(nobody intel geo search nether 2>&1)"; rc=$?
check '[ $rc -eq 3 ]' "geo search as nobody: exit 3 (the store is root's; the README says sudo)"
out="$(nobody intel lookup 192.0.2.10 2>&1)"; rc=$?
check '[ $rc -eq 3 ]' "lookup as nobody: exit 3"

run intel geo off
check '[ $rc -eq 0 ] && has_element s_country_netherlands_6 2c0f:f000::1' "geo off: saved, the kernel untouched until apply"
run intel geo status
check '[ $rc -eq 0 ] && grep -q "out of date (older than 30 days)" <<<"$out" && ! grep -q "still used\|still enforced" <<<"$out"' \
      "geo status with the database off: out of date, never \"still used\""
run intel apply
check '[ $rc -eq 0 ] && ! has_element s_country_netherlands_6 2c0f:f000::1 && ! has_element s_country_netherlands_4 192.0.2.10' \
      "apply with the database off: the country sets are gone"
run --json intel lookup 192.0.2.10
check '[ $rc -eq 0 ] && [ "$(jget "d[\"location\"]")" = None ]' "lookup with the database off: no location, exit 0"
run intel geo on
check '[ $rc -eq 0 ]' "geo on again: the terms stay accepted"
run intel geo remove country-netherlands
check '[ $rc -eq 0 ]' "geo remove country-netherlands"
unset STOCKFW_TEST_CURL STOCKFW_TEST_GEODB_KEY

echo ""
if [ "$fails" -eq 0 ]; then
  echo "PASSED: 0 failure(s)"
else
  echo "FAILED: $fails failure(s)"
fi
exit "$fails"
