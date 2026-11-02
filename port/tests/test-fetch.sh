#!/bin/bash
# Downloads through curl (fs-fetch, 1.0.7 design section 5), against a
# local HTTPS server with a throwaway CA.
#
# Runs in a private network namespace (unshare -n): the servers listen
# on the namespace's own 127.0.0.1, nothing reaches the host or the
# internet, and no case depends on an external host.  The cases that
# change the account database or hide curl do it in a nested private
# mount namespace (unshare -m), never on the host.  Needs root (curl
# has to be made `nobody'), curl, openssl, python3, unshare and mount;
# SKIPs without them.  IPv4 loopback only: nothing here is about IPv6.
#
# Driver: fs-fetch-test (ninja -C build-linux fs-fetch-test), the only
# build that honours STOCKFW_TEST_CURL / STOCKFW_TEST_CACERT.  Another
# build of it can be named with FS_FETCH_TEST=/path/to/fs-fetch-test.
#
# What it proves:
#   - the pure pieces: argv golden with -q first, the environment, the
#     URL and proxy rules, curl's exit table (fs-fetch-test golden);
#   - a download works when the test CA is passed (STOCKFW_TEST_CACERT),
#     on a main context of its own (nothing of the caller's runs during
#     the call), and four at once from four threads;
#   - without it, nothing in the caller's environment makes curl trust
#     the server or use a proxy: a curlrc with "insecure" under HOME,
#     CURL_HOME and XDG_CONFIG_HOME, CURL_CA_BUNDLE, SSL_CERT_FILE/DIR,
#     SSLKEYLOGFILE and every *_proxy are set, and the fetch still fails
#     with a TLS error, the proxy sees no connection, no key log is
#     written (a control shows plain curl obeying the same environment);
#   - a curlrc in the home directory of the account curl runs as (its
#     passwd entry, which curl reads with no HOME) is ignored too: that
#     is -q's job (a control shows curl reading it without -q);
#   - the size cap is ours: exactly the cap passes, one byte over is
#     TOO_LARGE, and an endless or stalled chunked body is cut at the
#     cap at once, also by a curl with no --max-filesize (what curl did
#     before 8.4 for a chunked body), and curl is gone afterwards;
#   - time: a server that accepts and never answers is TIMEOUT within
#     budget, and a curl that hangs past its own --max-time is killed;
#   - a redirect to http:// and a chain of 5 redirects are refused
#     (URL), the http server behind the redirect never sees a request;
#     3 redirects are fine; a URL with {..} or [..] is one request, not a
#     curl glob; a 404 is HTTP; a proxy the caller passes is used (the
#     recorder's positive control);
#   - curl runs as nobody (uid, gid, saved ids, no groups, no_new_privs)
#     with exactly PATH and LC_ALL, the golden argv, stdin /dev/null,
#     cwd /, and none of the caller's descriptors;
#   - root without an account `nobody', or with one that is uid 0,
#     starts nothing (PRIVILEGE); a `nobody' the child cannot become
#     stops in the child before exec (PRIVILEGE);
#   - a curl exiting 60 is TLS with its text; a missing curl is NO_CURL
#     (the test path, and the real lookup with /usr/bin/curl hidden); a
#     curl flooding stderr still gives a short one-line message.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
DRV="${FS_FETCH_TEST:-$PORT/build-linux/fs-fetch-test}"

if [ "${STOCKFW_IN_NETNS:-}" != 1 ]; then
  if [ "$(id -u)" != 0 ]; then
    echo "SKIP: needs root (curl is run as nobody, in private namespaces)"
    exit 0
  fi
  for tool in unshare mount openssl python3 timeout awk sha256sum; do
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
    echo "SKIP: $DRV not built -- ninja -C build-linux fs-fetch-test"
    exit 0
  fi
  STOCKFW_IN_NETNS=1 exec unshare -n "$0" "$@"
fi

REAL_CURL=/usr/bin/curl
[ -x "$REAL_CURL" ] || REAL_CURL=/bin/curl

ip link set lo up
# World-readable: curl runs as nobody and must read the CA and run the
# stand-ins from here.  pwd -P: the stand-ins compare real paths.
W="$(cd "$(mktemp -d)" && pwd -P)"
chmod 755 "$W"
SERVER_PID=
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  pkill -KILL -f "$W/" 2>/dev/null   # anything a failing case left behind
  rm -rf "$W"
}
trap cleanup EXIT

fails=0
ok()    { echo "ok:   $*"; }
bad()   { echo "FAIL: $*"; fails=$((fails + 1)); }
check() { if eval "$1"; then ok "$2"; else bad "$2"; fi; }
lines() { if [ -f "$1" ]; then wc -l < "$1"; else echo 0; fi; }
token() { echo "tok$RANDOM$RANDOM$RANDOM"; }

# The driver under a guard (GUARD seconds, default 60): its lines are
# shown and its FAILs counted; a driver that hangs or dies is a FAIL.
drive() {
  local out rc n a prev="" what="the driver"
  for a in "$@"; do [ "$prev" = --what ] && what="$a"; prev="$a"; done
  out="$(timeout "${GUARD:-60}" "$@" 2>&1)"; rc=$?
  grep -v -e '^PASSED: ' -e '^FAILED: ' -e '^$' <<<"$out"
  n="$(grep -c '^FAIL:' <<<"$out")"
  fails=$((fails + n))
  if [ $rc -eq 124 ]; then
    bad "$what: fs_fetch did not return within ${GUARD:-60} s"
  elif [ $rc -ne 0 ] && [ "$n" -eq 0 ]; then
    bad "$what: the driver failed with status $rc"
  fi
}

# bash -c "$MNT" _ FILE TARGET [FILE TARGET ...] -- CMD...: bind-mount
# each FILE over its TARGET, then run CMD.  Used under unshare -m, so
# the mounts exist only for CMD.
MNT='while [ "$1" != -- ]; do mount --bind "$1" "$2" || exit 97; shift 2; done; shift; exec "$@"'

# ------------------------------------------------------------ the CA
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj "/CN=StockFW fetch test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$W/ca.key" -out "$W/ca.pem" >/dev/null 2>&1 &&
openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" \
  -keyout "$W/srv.key" -out "$W/srv.csr" >/dev/null 2>&1 &&
printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' \
  > "$W/srv.ext" &&
openssl x509 -req -days 2 -in "$W/srv.csr" -CA "$W/ca.pem" \
  -CAkey "$W/ca.key" -CAcreateserial -extfile "$W/srv.ext" \
  -out "$W/srv.pem" >/dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "FAIL: could not make the test CA with openssl"
  echo; echo "FAILED: 1 failure(s)"
  exit 1
fi
chmod 644 "$W/ca.pem"
CA="$W/ca.pem"

printf '# StockFW fetch test\n192.0.2.1\n198.51.100.0/24\n' > "$W/small.txt"
SMALL_LEN="$(wc -c < "$W/small.txt")"
SMALL_SHA="$(sha256sum "$W/small.txt" | cut -d' ' -f1)"

# -------------------------------------------------------- the servers
# 8443 HTTPS (the test CA), 8080 plain HTTP (the redirect target), 8444
# accepts and never answers, 8445 records connections and closes them
# (the proxy).  Each logs to $W/<name>.log; $W/ready when all listen.
cat > "$W/server.py" <<'EOF'
import os, socket, ssl, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

W = sys.argv[1]
SMALL = open(os.path.join(W, "small.txt"), "rb").read()

def log(name, line):
    with open(os.path.join(W, name), "a") as f:
        f.write(line + "\n")

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, code, data, headers=()):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def chunk(self, data):
        self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))

    def do_GET(self):
        log(self.server.logname, self.path)
        path = self.path.split("?", 1)[0]
        part = path.strip("/").split("/")
        if path == "/small":
            self.reply(200, SMALL)
        elif part[0] == "bytes":                  # /bytes/N, Content-Length
            self.reply(200, b"x" * int(part[1]))
        elif part[0] in ("chunked", "stall", "endless"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                if part[0] == "endless":          # about 8 MB/s, forever
                    block = b"y" * 16384
                    while True:
                        self.chunk(block)
                        time.sleep(0.002)
                n, sent = int(part[1]), 0         # N bytes, no length
                while sent < n:
                    k = min(16384, n - sent)
                    self.chunk(b"z" * k)
                    sent += k
                self.wfile.flush()
                if part[0] == "stall":            # then nothing, ever
                    time.sleep(3600)
                self.wfile.write(b"0\r\n\r\n")
            except OSError:
                log(self.server.logname, "closed " + self.path)
        elif path == "/redirect-http":
            self.reply(302, b"", [("Location", "http://127.0.0.1:8080/small")])
        elif part[0] == "chain":                  # /chain/K: K redirects
            k = int(part[1])
            if k == 0:
                self.reply(200, SMALL)
            else:
                self.reply(302, b"", [("Location", "/chain/%d" % (k - 1))])
        else:
            self.reply(404, b"not here\n")

class Server(ThreadingHTTPServer):
    daemon_threads = True
    def handle_error(self, request, client_address):
        pass

def listener(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(16)
    return s

def accept_loop(s, logname, hold):
    held = []
    while True:
        c, _ = s.accept()
        log(logname, "connection")
        if hold:
            held.append(c)
        else:
            c.close()

https = Server(("127.0.0.1", 8443), Handler)
https.logname = "https.log"
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.path.join(W, "srv.pem"), os.path.join(W, "srv.key"))
https.socket = ctx.wrap_socket(https.socket, server_side=True,
                               do_handshake_on_connect=False)
http = Server(("127.0.0.1", 8080), Handler)
http.logname = "http.log"
silent, proxy = listener(8444), listener(8445)

threading.Thread(target=https.serve_forever, daemon=True).start()
threading.Thread(target=http.serve_forever, daemon=True).start()
threading.Thread(target=accept_loop, args=(silent, "silent.log", True),
                 daemon=True).start()
threading.Thread(target=accept_loop, args=(proxy, "proxy.log", False),
                 daemon=True).start()
open(os.path.join(W, "ready"), "w").close()
while True:
    time.sleep(3600)
EOF

python3 -I "$W/server.py" "$W" &
SERVER_PID=$!
for _ in $(seq 100); do [ -e "$W/ready" ] && break; sleep 0.1; done
if [ ! -e "$W/ready" ]; then
  echo "FAIL: the test server did not start"
  echo; echo "FAILED: 1 failure(s)"
  exit 1
fi

# -------------------------------------------------------- stand-ins
# Each is run by fs_fetch() in place of curl (STOCKFW_TEST_CURL), as
# nobody, with fs_fetch's environment.
mkdir -p "$W/bin" "$W/flags" "$W/home/.config" "$W/certs"
chmod 755 "$W/bin" "$W/home" "$W/home/.config" "$W/certs"
chmod 1777 "$W/flags"   # writable by nobody: a leak must be able to show

# What it was given, as the body: account, argv, environment, stdin,
# working directory, descriptors.  The descriptors are listed by a child
# (find), so the listing itself opens nothing in the shell it lists.
cat > "$W/bin/report" <<'EOF'
#!/bin/sh
grep -E '^(Uid|Gid|Groups|NoNewPrivs):' /proc/$$/status | tr '\t' ' '
printf 'argv0 %s\n' "$0"
for a in "$@"; do printf 'arg %s\n' "$a"; done
tr '\0' '\n' < /proc/$$/environ | sed 's/^/env /'
printf 'stdin %s\n' "$(readlink /proc/$$/fd/0)"
printf 'cwd %s\n' "$(readlink /proc/$$/cwd)"
find /proc/$$/fd -mindepth 1 -maxdepth 1 -printf 'fd %f %l\n'
EOF

cat > "$W/bin/tls60" <<'EOF'
#!/bin/sh
echo 'curl: (60) SSL certificate problem: unable to get local issuer certificate' >&2
echo 'More details here: https://curl.se/docs/sslcerts.html' >&2
exit 60
EOF

# Ignores its own --max-time: only fs_fetch's timer can stop it.  The
# exec keeps one process, named after the stand-in and its arguments
# (so --gone can find it by the URL's token).
cat > "$W/bin/hang" <<'EOF'
#!/bin/bash
exec -a "$0 $*" sleep 3600
EOF

# The real curl without --max-filesize: what curl before 8.4 did with a
# body of unknown length.  Only fs_fetch's own count can stop it.
cat > "$W/bin/nocap" <<EOF
#!/bin/sh
skip=0
for a in "\$@"; do
  shift
  if [ "\$skip" = 1 ]; then skip=0; continue; fi
  if [ "\$a" = --max-filesize ]; then skip=1; continue; fi
  set -- "\$@" "\$a"
done
exec $REAL_CURL "\$@"
EOF

cat > "$W/bin/noisy" <<'EOF'
#!/bin/sh
head -c 200000 /dev/zero | tr '\0' e >&2
echo >&2
exit 3
EOF

# Proves it was started at all.
cat > "$W/bin/spawned" <<EOF
#!/bin/sh
: > "$W/flags/spawned"
exit 0
EOF
chmod 755 "$W/bin/"*

# -------------------------------------------------------------- cases
echo "== the pure pieces"
drive "$DRV" golden

echo "== a download with the test CA"
drive env STOCKFW_TEST_CACERT="$CA" "$DRV" fetch \
  --what "a small file with the test CA" --expect ok --isolated \
  --len "$SMALL_LEN" --sha256 "$SMALL_SHA" https://127.0.0.1:8443/small
drive env STOCKFW_TEST_CACERT="$CA" "$DRV" fetch \
  --what "four downloads at once, one per thread" --threads 4 --expect ok \
  --len "$SMALL_LEN" --sha256 "$SMALL_SHA" https://127.0.0.1:8443/small

echo "== a hostile environment: curlrc, CA bundle, key log, proxies"
printf 'insecure\n' > "$W/home/.curlrc"
cp "$W/home/.curlrc" "$W/home/.config/curlrc"
chmod 644 "$W/home/.curlrc" "$W/home/.config/curlrc"
cp "$CA" "$W/certs/test-ca.pem" && openssl rehash "$W/certs" >/dev/null 2>&1
P=http://127.0.0.1:8445
HOSTILE=(HOME="$W/home" CURL_HOME="$W/home" XDG_CONFIG_HOME="$W/home/.config"
         CURL_CA_BUNDLE="$CA" SSL_CERT_FILE="$CA" SSL_CERT_DIR="$W/certs"
         SSLKEYLOGFILE="$W/flags/keylog"
         https_proxy=$P HTTPS_PROXY=$P http_proxy=$P ALL_PROXY=$P all_proxy=$P)
env "${HOSTILE[@]}" "$REAL_CURL" -s -o /dev/null --max-time 10 \
  --noproxy '*' https://127.0.0.1:8443/small
rc=$?
check '[ $rc -eq 0 ]' \
  "control: plain curl in that environment does trust the server"
check '[ -s "$W/flags/keylog" ]' \
  "control: and writes the TLS key log SSLKEYLOGFILE names"
rm -f "$W/flags/keylog"
proxy_before="$(lines "$W/proxy.log")"
drive env "${HOSTILE[@]}" "$DRV" fetch \
  --what "the hostile environment, no test CA" --expect TLS \
  --msg "SSL certificate problem" https://127.0.0.1:8443/small
check '[ "$(lines "$W/proxy.log")" -eq "$proxy_before" ]' \
  "the proxies in the environment saw no connection"
check '[ ! -e "$W/flags/keylog" ]' \
  "no TLS key log was written (SSLKEYLOGFILE never reached curl)"

echo "== a curlrc in the home directory of the account curl runs as"
awk -F: -v OFS=: -v home="$W/home" '$1 == "nobody" { $6 = home } 1' \
  /etc/passwd > "$W/passwd-home"
if command -v setpriv >/dev/null; then
  unshare -m bash -c "$MNT" _ "$W/passwd-home" /etc/passwd -- \
    setpriv --reuid=nobody --regid="$(id -g nobody)" --clear-groups \
    env -i "$REAL_CURL" -s -o /dev/null --max-time 10 \
    https://127.0.0.1:8443/small
  rc=$?
  check '[ $rc -eq 0 ]' \
    "control: curl as nobody without -q reads that curlrc and trusts the server"
fi
drive unshare -m bash -c "$MNT" _ "$W/passwd-home" /etc/passwd -- \
  "$DRV" fetch --what "nobody's own curlrc says insecure" --expect TLS \
  --msg "SSL certificate problem" https://127.0.0.1:8443/small

echo "== the size cap"
CACERT=(env STOCKFW_TEST_CACERT="$CA")
NOCAP=(env STOCKFW_TEST_CACERT="$CA" STOCKFW_TEST_CURL="$W/bin/nocap")
drive "${CACERT[@]}" "$DRV" fetch --what "exactly the cap (Content-Length)" \
  --max 1000 --expect ok --len 1000 https://127.0.0.1:8443/bytes/1000
drive "${CACERT[@]}" "$DRV" fetch --what "one byte over the cap (Content-Length)" \
  --max 1000 --expect TOO_LARGE https://127.0.0.1:8443/bytes/1001
drive "${NOCAP[@]}" "$DRV" fetch \
  --what "exactly the cap, chunked, curl without --max-filesize" \
  --max 1000 --expect ok --len 1000 https://127.0.0.1:8443/chunked/1000
drive "${NOCAP[@]}" "$DRV" fetch \
  --what "one byte over, chunked, curl without --max-filesize" \
  --max 1000 --expect TOO_LARGE --msg "larger than the limit of 1000 bytes" \
  https://127.0.0.1:8443/chunked/1001
t="$(token)"
drive "${CACERT[@]}" "$DRV" fetch --what "an endless chunked body" \
  --max 262144 --timeout 20 --expect TOO_LARGE --within 3 --gone "$t" \
  "https://127.0.0.1:8443/endless?$t"
t="$(token)"
drive "${NOCAP[@]}" "$DRV" fetch \
  --what "an endless chunked body, curl without --max-filesize" \
  --max 262144 --timeout 8 --expect TOO_LARGE --within 3 --gone "$t" \
  "https://127.0.0.1:8443/endless?$t"
t="$(token)"
drive "${NOCAP[@]}" "$DRV" fetch \
  --what "a body that stalls past the cap, curl without --max-filesize" \
  --max 262144 --timeout 20 --expect TOO_LARGE --within 3 --gone "$t" \
  "https://127.0.0.1:8443/stall/400000?$t"

echo "== time"
silent_before="$(lines "$W/silent.log")"
drive "${CACERT[@]}" "$DRV" fetch \
  --what "a server that accepts and never answers" --timeout 3 \
  --expect TIMEOUT --within 6 https://127.0.0.1:8444/silent
check '[ "$(lines "$W/silent.log")" -gt "$silent_before" ]' \
  "  (that server did accept the connection)"
t="$(token)"
GUARD=25 drive env STOCKFW_TEST_CURL="$W/bin/hang" "$DRV" fetch \
  --what "a curl that hangs past its own --max-time" --timeout 2 \
  --expect TIMEOUT --within 9 --gone "$t" "https://127.0.0.1:8443/small?$t"

echo "== redirects, HTTP errors, proxies"
exec 3<>/dev/tcp/127.0.0.1/8080 &&
  printf 'GET /control HTTP/1.0\r\n\r\n' >&3 && cat <&3 >/dev/null
exec 3<&-
check 'grep -q "^/control$" "$W/http.log"' \
  "control: the plain http:// server logs what it is asked"
http_before="$(lines "$W/http.log")"
drive "${CACERT[@]}" "$DRV" fetch --what "a redirect to http://" \
  --expect URL https://127.0.0.1:8443/redirect-http
check '[ "$(lines "$W/http.log")" -eq "$http_before" ]' \
  "the http:// server behind the redirect saw no request"
drive "${CACERT[@]}" "$DRV" fetch --what "a chain of 5 redirects" \
  --expect URL --msg "redirects" https://127.0.0.1:8443/chain/5
drive "${CACERT[@]}" "$DRV" fetch --what "a chain of 3 redirects (the most allowed)" \
  --expect ok --len "$SMALL_LEN" https://127.0.0.1:8443/chain/3
ids_before="$(grep -c '^/small?ids=' "$W/https.log")"
drive "${CACERT[@]}" "$DRV" fetch --what "a URL with {1,2} in it" \
  --expect ok --len "$SMALL_LEN" 'https://127.0.0.1:8443/small?ids={1,2}'
check '[ "$(grep -c "^/small?ids=" "$W/https.log")" -eq $((ids_before + 1)) ]' \
  "  the server saw one request, not one per {..} alternative (--globoff)"
drive "${CACERT[@]}" "$DRV" fetch --what "a query with [..] in it" \
  --expect ok --len "$SMALL_LEN" 'https://127.0.0.1:8443/small?filter[type]=ip'
drive "${CACERT[@]}" "$DRV" fetch --what "a 404" --expect HTTP --msg "404" \
  https://127.0.0.1:8443/404
proxy_before="$(lines "$W/proxy.log")"
drive "${CACERT[@]}" "$DRV" fetch --what "a proxy the caller passes" \
  --proxy "$P" --expect NETWORK https://127.0.0.1:8443/small
check '[ "$(lines "$W/proxy.log")" -gt "$proxy_before" ]' \
  "  and that proxy saw the connection (the recorder works)"

echo "== what curl is given"
printf 'held by the caller\n' > "$W/held-marker"
printf 'the caller stdin\n' > "$W/caller-stdin"
drive env "${HOSTILE[@]}" FOO=bar STOCKFW_TEST_CURL="$W/bin/report" \
  "$DRV" report --what "started by root" --marker "$W/held-marker" \
  https://127.0.0.1:8443/small < "$W/caller-stdin"
drive env STOCKFW_TEST_CURL="$W/bin/report" STOCKFW_TEST_CACERT="$CA" \
  "$DRV" report --what "with the test CA" https://127.0.0.1:8443/small

echo "== curl's own word"
drive env STOCKFW_TEST_CURL="$W/bin/tls60" "$DRV" fetch \
  --what "curl exits 60" --expect TLS \
  --msg-is "Could not download: SSL certificate problem: unable to get local issuer certificate" \
  https://127.0.0.1:8443/small
drive env STOCKFW_TEST_CURL="$W/bin/noisy" "$DRV" fetch \
  --what "curl floods stderr" --expect FAILED --msg-max 400 --within 10 \
  https://127.0.0.1:8443/small
drive env STOCKFW_TEST_CURL="$W/no-such-curl" "$DRV" fetch \
  --what "the test curl path does not exist" --expect NO_CURL \
  https://127.0.0.1:8443/small
: > "$W/not-curl"
chmod 644 "$W/not-curl"
HIDE=("$W/not-curl" /usr/bin/curl)
if [ -e /bin/curl ] && ! [ /bin/curl -ef /usr/bin/curl ]; then
  HIDE+=("$W/not-curl" /bin/curl)
fi
drive unshare -m bash -c "$MNT" _ "${HIDE[@]}" -- \
  "$DRV" fetch --what "no curl in /usr/bin or /bin (the release lookup)" \
  --expect NO_CURL --msg "/usr/bin/curl" https://127.0.0.1:8443/small

echo "== root without a usable nobody downloads nothing"
awk -F: '$1 != "nobody"' /etc/passwd > "$W/passwd-none"
awk -F: -v OFS=: '$1 == "nobody" { $3 = 0 } 1' /etc/passwd > "$W/passwd-root"
awk -F: -v OFS=: '$1 == "nobody" { $3 = 4294967295 } 1' /etc/passwd > "$W/passwd-bad"
unshare -m bash -c "$MNT" _ "$W/passwd-none" /etc/passwd -- \
  getent passwd nobody >/dev/null
rc=$?
check '[ $rc -ne 0 ]' "control: with that passwd there is no account nobody"
rm -f "$W/flags/spawned"
drive env STOCKFW_TEST_CURL="$W/bin/spawned" "$DRV" fetch \
  --what "control: the flag stand-in, with the real nobody" --expect ok --len 0 \
  https://127.0.0.1:8443/small
check '[ -e "$W/flags/spawned" ]' \
  "  and it left its flag: \"nothing was started\" below means something"
rm -f "$W/flags/spawned"
drive unshare -m bash -c "$MNT" _ "$W/passwd-none" /etc/passwd -- \
  env STOCKFW_TEST_CURL="$W/bin/spawned" "$DRV" fetch \
  --what "root, no account nobody" --expect PRIVILEGE --msg "no account" \
  https://127.0.0.1:8443/small
check '[ ! -e "$W/flags/spawned" ]' "  and nothing was started"
rm -f "$W/flags/spawned"   # each case its own flag: a failure names its case
drive unshare -m bash -c "$MNT" _ "$W/passwd-root" /etc/passwd -- \
  env STOCKFW_TEST_CURL="$W/bin/spawned" "$DRV" fetch \
  --what "root, nobody has uid 0" --expect PRIVILEGE \
  https://127.0.0.1:8443/small
check '[ ! -e "$W/flags/spawned" ]' "  and nothing was started"
rm -f "$W/flags/spawned"
drive unshare -m bash -c "$MNT" _ "$W/passwd-bad" /etc/passwd -- \
  env STOCKFW_TEST_CURL="$W/bin/spawned" "$DRV" fetch \
  --what "root, a nobody the child cannot become" --expect PRIVILEGE \
  --msg "could not be started as" https://127.0.0.1:8443/small
check '[ ! -e "$W/flags/spawned" ]' \
  "  and the stand-in never ran: the child stopped before exec"

echo
if [ $fails -eq 0 ]; then echo "PASSED: 0 failure(s)"; else echo "FAILED: $fails failure(s)"; fi
[ $fails -eq 0 ]
