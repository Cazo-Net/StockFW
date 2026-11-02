#!/bin/bash
# Blocklist -> nftables set, against a real nft (1.0.7).
#
# Runs in a private network namespace (unshare -n), so the tables it
# makes are invisible to the host and vanish with the namespace.  Needs
# root, nft and unshare; SKIPs without them.
#
# What it proves, beyond test-intel.c's script checks:
#   - nft accepts the script and the sets end up holding the list;
#   - a second load REPLACES the first (nothing lingers);
#   - a load that nft rejects part-way changes nothing: flush and adds
#     are one transaction (teeth: a separate flush call fails this);
#   - garbage, empty and absurdly wide lists are refused before nft runs;
#   - protected ranges (the LAN, loopback) never reach the set;
#   - a rule using the set really drops traffic to a listed address.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
LOAD="$PORT/build-linux/fs-nftset-load"

if [ "${STOCKFW_IN_NETNS:-}" != 1 ]; then
  if [ "$(id -u)" != 0 ] || ! command -v nft >/dev/null ||
     ! command -v unshare >/dev/null; then
    echo "SKIP: needs root, nft and unshare"
    exit 0
  fi
  if [ ! -x "$LOAD" ]; then
    echo "SKIP: $LOAD not built -- ninja -C build-linux fs-nftset-load"
    exit 0
  fi
  STOCKFW_IN_NETNS=1 exec unshare -n "$0" "$@"
fi

REAL_NFT="$(command -v nft)"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
fails=0
ok()   { echo "ok:   $*"; }
bad()  { echo "FAIL: $*"; fails=$((fails + 1)); }
check() { if eval "$1"; then ok "$2"; else bad "$2"; fi; }

set4() { nft list set inet stockfw_intel blocklist 2>/dev/null; }
set6() { nft list set inet stockfw_intel blocklist6 2>/dev/null; }

cat > "$W/a.csv" <<'EOF'
ip,comment
# a Spamhaus-style line, a quoted CSV field, a range, IPv6
192.0.2.0/24 ; SBL000001
"198.51.100.7",scanner
203.0.113.10-203.0.113.20,range
2001:db8:bad::/48
10.0.0.0/8
192.168.1.5
EOF

cat > "$W/b.csv" <<'EOF'
198.51.100.99
2001:db8:beef::1
EOF

# --- 1. first load
out="$("$LOAD" "$W/a.csv")"; rc=$?
check '[ $rc -eq 0 ]' "list A loads (${out})"
s4="$(set4)"; s6="$(set6)"
check 'grep -q "192.0.2.0/24" <<<"$s4"'                "A: the /24 is in blocklist"
check 'grep -q "198.51.100.7" <<<"$s4"'                "A: the quoted address is in blocklist"
check 'grep -q "203.0.113.10-203.0.113.20" <<<"$s4"'   "A: the range is in blocklist"
check 'grep -q "2001:db8:bad::/48" <<<"$s6"'           "A: the IPv6 /48 is in blocklist6"
check '! grep -q "10.0.0.0" <<<"$s4"'                  "A: 10.0.0.0/8 (the LAN) never reached the set"
check '! grep -q "192.168." <<<"$s4"'                  "A: 192.168.1.5 (the LAN) never reached the set"
check 'grep -q "2 overlapped protected" <<<"$out"'     "A: the two protected entries are reported"

# --- 2. second load replaces
"$LOAD" "$W/b.csv" >/dev/null; rc=$?
s4="$(set4)"; s6="$(set6)"
check '[ $rc -eq 0 ]'                                  "list B loads"
check 'grep -q "198.51.100.99" <<<"$s4"'               "B: its address is in blocklist"
check '! grep -q "192.0.2.0/24" <<<"$s4"'              "B: A's entries are gone (replace, not merge)"
check '! grep -q "2001:db8:bad::" <<<"$s6"'            "B: A's IPv6 entry is gone too"
check 'grep -q "2001:db8:beef::1" <<<"$s6"'            "B: its IPv6 address is in blocklist6"

# --- 3. a transaction nft rejects part-way changes nothing
mkdir -p "$W/bin"
cat > "$W/bin/nft" <<EOF
#!/bin/bash
# The real nft.  A script that adds elements gets one invalid statement
# appended; anything else (a flush sent on its own) passes untouched, so
# an implementation that flushed in a separate call would empty the set.
script="\$(cat)"
if grep -q "add element" <<<"\$script"; then
  script="\$script
add element inet stockfw_intel blocklist { 999.1.1.1 }"
fi
printf '%s\n' "\$script" | "$REAL_NFT" "\$@"
EOF
chmod +x "$W/bin/nft"
out="$(PATH="$W/bin:$PATH" "$LOAD" "$W/a.csv")"; rc=$?
s4="$(set4)"
check '[ $rc -ne 0 ]'                                  "a rejected script is reported as a failure"
check 'grep -q "nft refused" <<<"$out"'                "and says nft refused it (${out:0:90})"
check 'grep -q "198.51.100.99" <<<"$s4" && ! grep -q "192.0.2.0/24" <<<"$s4"' \
      "the set still holds list B: the flush did not happen on its own"

# --- 4. refused before nft ever runs
printf '<html><body>502 Bad Gateway</body></html>\n<p>try later</p>\n' > "$W/html.csv"
out="$("$LOAD" "$W/html.csv")"; rc=$?
check '[ $rc -ne 0 ] && grep -q "198.51.100.99" <<<"$(set4)"' \
      "an HTML error page is refused; the set is unchanged (${out:0:70})"

: > "$W/empty.csv"
out="$("$LOAD" "$W/empty.csv")"; rc=$?
check '[ $rc -ne 0 ] && grep -q "198.51.100.99" <<<"$(set4)"' \
      "an empty file is refused, never an empty set (${out:0:70})"

printf '2.0.0.0/7\n' > "$W/wide.csv"
out="$("$LOAD" "$W/wide.csv")"; rc=$?
check '[ $rc -ne 0 ] && grep -q "198.51.100.99" <<<"$(set4)"' \
      "a /7 is refused as too wide (${out:0:70})"

out="$("$LOAD" "$W/a.csv" stockfw_intel 'x;flush')"; rc=$?
check '[ $rc -ne 0 ]'                                  "a hostile set name is refused (${out:0:60})"

# --- 5. a rule using the set drops traffic to a listed address
ip link set lo up
ip addr add 198.51.100.99/32 dev lo
ip addr add 198.51.100.50/32 dev lo
nft add chain inet stockfw_intel output \
  '{ type filter hook output priority filter - 10; policy accept; }'
nft add rule inet stockfw_intel output ip daddr @blocklist counter drop
( exec 3<>/dev/tcp/198.51.100.50/9 ) 2>/dev/null; plain=$?
timeout 3 bash -c '( exec 3<>/dev/tcp/198.51.100.99/9 )' 2>/dev/null; listed=$?
# Port 9 has no listener: an unlisted address answers at once with a
# reset ("refused", status 1); a listed one is dropped, so the connect
# hangs until the timeout (status 124).
check '[ $plain -eq 1 ]'                               "an unlisted address answers (refused at once)"
echo "      (connect: unlisted=$plain listed=$listed)"
check '[ $listed -eq 124 ]'                            "a listed address is dropped (no answer, timed out)"
check 'nft list chain inet stockfw_intel output | grep -q "packets [1-9]"' \
      "the rule's counter saw the dropped packets"

# --- 6. reloading keeps the chain that uses the set
"$LOAD" "$W/a.csv" >/dev/null; rc=$?
check '[ $rc -eq 0 ] && nft list chain inet stockfw_intel output | grep -q "@blocklist"' \
      "a reload leaves the table's chains in place"

echo
if [ $fails -eq 0 ]; then echo "PASSED: 0 failure(s)"; else echo "FAILED: $fails failure(s)"; fi
[ $fails -eq 0 ]
