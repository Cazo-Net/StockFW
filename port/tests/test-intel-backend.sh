#!/bin/bash
# The Linux backend's threat-intel slots against a real nft (1.0.7,
# design section 7): intel_apply, intel_clear, intel_counters and
# intel_live, called through fs_backend() by fs-intel-backend-driver,
# exactly as the engine calls them.
#
# Runs in a private network namespace: it re-executes itself under
# `unshare -n' and makes a peer namespace on a veth pair to send real
# traffic, so the host's firewall is never touched.  Needs root, nft,
# iptables, unshare, nsenter, ip, setpriv and python3; SKIPs without
# them.
#
# What it proves (test-intelset.sh covers the rule text and the six
# direction cells; this is the backend that drives it):
#   - the slots are set; nothing loaded reads as absent, counters NULL;
#   - an apply is live with its digest, as one nft call that names no
#     table but inet stockfw_intel; re-applying the same digest is an
#     idempotent replace (live digest the same, counters back to zero:
#     the engine carries them just before); a change replaces the old
#     sets; clear removes the table, twice is fine;
#   - counters move when traffic hits a listed address, exactly by the
#     packets sent, and match nft's own listing; reading them, or the
#     live state, never lists a table or a set [S8.3];
#   - the empty rule set leaves no table, and that is a success: the
#     expected live state is absent, not "present with an empty digest";
#   - after any nft failure the kernel is read back and trusted: an nft
#     killed, or timed out, after it committed is a success; one killed
#     or hung before is a failure that says which lists are in force;
#     a rejected transaction leaves the previous table, and one that
#     would have loaded the very same table is still a failure (the
#     counters were never reset, so nothing may be carried); after an nft
#     success the table must carry the digest asked for (not one put
#     there by someone else, and not an unreadable listing);
#   - a hanging nft is stopped at the timeout (shortened by the test
#     build's $STOCKFW_TEST_NFT_TIMEOUT_MS), for loads and listings;
#   - an unreadable listing is unknown, never absent;
#   - nft missing, not root: clear errors, live unknown, counters NULL;
#   - coexistence: the policy's apply, stop, reload and clear leave the
#     table and its counters alone [N6]; the policy's iptables rules, Docker- and
#     libvirt-style iptables chains, firewalld- and libvirt-style nft
#     tables and the standalone helper's inet stockfw_blocklist are
#     byte for byte the same after everything above.
# IPv6 is checked as rule text only: no IPv6 packet is sent here.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
DRV="${STOCKFW_INTEL_BACKEND_DRIVER:-$PORT/build-linux/fs-intel-backend-driver}"
LOADER="${STOCKFW_NFTSET_LOAD:-$PORT/build-linux/fs-nftset-load}"

if [ "${STOCKFW_IN_NETNS:-}" != 1 ]; then
  if [ "$(id -u)" != 0 ]; then
    echo "SKIP: needs root"
    exit 0
  fi
  for tool in nft iptables iptables-save unshare nsenter ip setpriv python3; do
    if ! command -v "$tool" >/dev/null; then
      echo "SKIP: needs $tool"
      exit 0
    fi
  done
  if [ ! -x "$DRV" ]; then
    echo "SKIP: $DRV not built -- ninja -C build-linux fs-intel-backend-driver"
    exit 0
  fi
  if ! unshare -n true 2>/dev/null; then
    echo "SKIP: cannot make a network namespace here (unshare -n)"
    exit 0
  fi
  export STOCKFW_INTEL_BACKEND_DRIVER="$DRV" STOCKFW_NFTSET_LOAD="$LOADER"
  STOCKFW_IN_NETNS=1 exec unshare -n "$0" "$@"
fi

REAL_NFT="$(command -v nft)"
W="$(mktemp -d)"
# Readable by nobody: the not-root checks read their spec from here.
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
ok()   { echo "ok:   $*"; }
bad()  { echo "FAIL: $*"; fails=$((fails + 1)); }
check() { if eval "$1"; then ok "$2"; else bad "$2"; fi; }

spec() {   # spec NAME LINE... -> writes $W/NAME.spec, prints its path
  local f="$W/$1.spec"
  shift
  printf '%s\n' "$@" > "$f"
  chmod 644 "$f"
  echo "$f"
}

# Every nft the backend runs goes through this wrapper: it logs the
# arguments, and the script of every load, then runs the real nft.
mkdir -p "$W/log" "$W/scripts"
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
chmod +x "$W/log/nft"

drv() { PATH="$W/log:$PATH" "$DRV" "$@"; }
# The driver with another nft first on PATH (a directory under $W).
drv_with() { local dir="$1"; shift; PATH="$W/$dir:$W/log:$PATH" "$DRV" "$@"; }
loads() { ls "$W/scripts" | wc -l; }
ms_since() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }

# Only the counters with an id, in the order the driver prints them.
counters() { drv counters; }
# nft's own sum for one id, over the three chains.
listed_counter() {
  { "$REAL_NFT" list chain inet stockfw_intel input
    "$REAL_NFT" list chain inet stockfw_intel output
    "$REAL_NFT" list chain inet stockfw_intel forward; } 2>/dev/null |
  awk -v id="$1" -v want="comment \"$1\"" '
    index($0, want) && /counter packets/ {
      for (i = 1; i < NF; i++) {
        if ($i == "packets") p += $(i + 1)
        if ($i == "bytes") b += $(i + 1)
      }
    }
    END { printf "%s %d %d\n", id, p, b }'
}

# --------------------------------------------------------------- network
ip link set lo up
PEER=""
unshare -n sleep 600 &
PIDS="$PIDS $!"
for _ in $(seq 100); do
  if [ "$(readlink "/proc/$!/ns/net")" != "$(readlink /proc/self/ns/net)" ]; then
    PEER=$!
    break
  fi
  sleep 0.05
done
[ -n "$PEER" ] || bad "could not make the peer namespace"
ip link add v0 type veth peer name v1 netns "$PEER"
ip addr add 192.0.2.1/24 dev v0
ip link set v0 up
nsenter -t "$PEER" -n ip link set lo up
nsenter -t "$PEER" -n ip addr add 192.0.2.2/24 dev v1
nsenter -t "$PEER" -n ip link set v1 up

# send_from PID-or-empty ADDR COUNT: COUNT UDP datagrams of 10 bytes to
# ADDR port 9 (38 bytes each on the wire, IPv4); prints how many sends
# the kernel refused.
cat > "$W/send.py" <<'EOF'
import socket, sys
addr, count = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
refused = 0
for _ in range(count):
    try:
        s.sendto(b"0123456789", (addr, 9))
    except OSError:
        refused += 1
print(refused)
EOF
send_from() {
  if [ -n "$1" ]; then nsenter -t "$1" -n python3 -I "$W/send.py" "$2" "$3"
  else python3 -I "$W/send.py" "$2" "$3"; fi
  sleep 0.2   # let the datagrams cross the veth pair
}

# ------------------------------------------------- foreign rules, before
# The policy itself (iptables, which is nftables underneath here), and
# stand-ins for what shares a real machine: Docker's chains, libvirt's
# and firewalld's nft tables -- one of them holding an address our
# lists will hold too -- and the standalone helper's own table.
out="$(drv policy-apply)"
check '[ "$out" = "policy applied" ]' "the policy applies through the backend ($out)"
iptables -N DOCKER-USER && iptables -A DOCKER-USER -j RETURN && iptables -I FORWARD -j DOCKER-USER
iptables -t nat -N DOCKER && iptables -t nat -A DOCKER -i docker0 -j RETURN
"$REAL_NFT" -f - <<'EOF'
table ip libvirt_network {
	chain guest_output {
		type filter hook forward priority filter; policy accept;
		ip saddr 192.168.122.0/24 counter accept
	}
}
table inet firewalld {
	set trusted { type ipv4_addr; flags interval; elements = { 192.0.2.0/24 } }
	chain filter_INPUT {
		type filter hook input priority filter + 10; policy accept;
		ip saddr @trusted counter accept
	}
}
EOF
printf '198.51.100.0/24\n192.0.2.2\n' > "$W/blocklist.txt"
if [ -x "$LOADER" ]; then
  out="$("$LOADER" "$W/blocklist.txt")"
  check 'grep -q "^loaded" <<<"$out"' "the standalone helper loads inet stockfw_blocklist ($out)"
else
  echo "note: $LOADER not built; inet stockfw_blocklist is made with nft"
  "$REAL_NFT" -f - <<'EOF'
table inet stockfw_blocklist {
	set blocklist { type ipv4_addr; flags interval; elements = { 198.51.100.0/24, 192.0.2.2 } }
}
EOF
fi
foreign() {
  # Rules without their counters: traffic may move those.
  iptables-save | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//'
  for t in "ip libvirt_network" "inet firewalld" "inet stockfw_blocklist"; do
    echo "== $t"
    # shellcheck disable=SC2086
    "$REAL_NFT" -s list table $t
  done
}
foreign > "$W/foreign.before"
check 'grep -q "^:INBOUND" "$W/foreign.before" && grep -q "^:DOCKER-USER" "$W/foreign.before" && grep -q "192.0.2.2" "$W/foreign.before"' \
      "the foreign rules and tables are in place"

# ----------------------------------------------------- 1. slots, nothing
out="$("$DRV" slots | tr '\n' ' ')"
check '[ "$out" = "intel_apply set intel_clear set intel_counters set intel_live set " ]' \
      "the Linux backend sets all four intel slots ($out)"
check '[ "$(drv live)" = absent ]' "nothing loaded: live reads absent, with no digest"
check '[ "$(counters)" = none ]' "nothing loaded: counters are NULL, not zeros"

# ------------------------------------------------- 2. apply, re-apply
F_A="$(spec a 'feed-a in 192.0.2.2 2001:db8:bad::/48' 'feed-b out 192.0.2.3 2001:db8:beef::1')"
D_A="$(drv digest "$F_A")"
before=$(loads)
out="$(drv apply "$F_A")"; rc=$?
check '[ $rc -eq 0 ] && [ "$out" = applied ]' "apply loads the rule set ($out)"
check '[ "$(drv live)" = "present $D_A" ]' "live reads back the digest it was applied with"
check '[ $(( $(loads) - before )) -eq 1 ]' "the apply was one nft load: one transaction, never a delete of its own first"
check '"$REAL_NFT" list chain inet stockfw_intel input | grep -q "ip6 saddr @s_feed_a_6 ct direction original"' \
      "IPv6 (rule text): the in set's IPv6 rule is loaded"

# ------------------------------------------------------- 3. counters move
r="$(send_from "$PEER" 192.0.2.1 5)"
r2="$(send_from "" 192.0.2.3 3)"
c="$(counters | tr '\n' ' ')"
check '[ "$c" = "feed-a 5 190 feed-b 3 114 " ]' \
      "counters move by exactly what hit the listed addresses: 5 in from the peer, 3 out to a listed address ($c)"
check '[ "$r2" = 3 ]' "and this side's datagrams to the out-listed address were refused ($r2 of 3)"
check '[ "$(counters | grep "^feed-a ")" = "$(listed_counter feed-a)" ] && [ "$(counters | grep "^feed-b ")" = "$(listed_counter feed-b)" ]' \
      "the counters equal nft's own listing"

# Re-applying the same digest is a whole replace: the same table,
# counters back at zero (the engine has carried them by then).
before=$(loads)
out="$(drv apply "$F_A")"; rc=$?
c="$(counters | tr '\n' ' ')"
check '[ $rc -eq 0 ] && [ "$(drv live)" = "present $D_A" ] && [ $(( $(loads) - before )) -eq 1 ]' \
      "re-applying the same digest succeeds and replaces the table in one load ($out)"
check '[ "$c" = "feed-a 0 0 feed-b 0 0 " ]' "and the counters start again from zero ($c)"

# --------------------------------------------------------- 4. a change
F_B="$(spec b 'feed-c both 192.0.2.2')"
D_B="$(drv digest "$F_B")"
out="$(drv apply "$F_B")"; rc=$?
check '[ $rc -eq 0 ] && [ "$(drv live)" = "present $D_B" ]' "a changed rule set is live with its own digest ($out)"
check '! "$REAL_NFT" list set inet stockfw_intel s_feed_a_4 >/dev/null 2>&1 && [ "$(counters | cut -d" " -f1 | tr "\n" " ")" = "feed-c " ]' \
      "the old sets and rules are gone: replaced, not merged"

# ------------------------------------------- 5. the policy leaves it alone
send_from "$PEER" 192.0.2.1 4 >/dev/null
c_before="$(counters)"
o1="$(drv policy-apply)"; o2="$(drv policy-apply)"; o3="$(drv policy-stop)"
o4="$(drv policy-clear)"; o5="$(drv policy-apply)"; o6="$(drv policy-reload)"
check '[ "$o1$o2$o3$o4$o5$o6" = "policy appliedpolicy appliedpolicy stoppedpolicy clearedpolicy appliedpolicy reloaded" ]' \
      "the policy applies twice, stops, clears, applies again and reloads ($o6)"
check '[ "$(drv live)" = "present $D_B" ] && [ "$(counters)" = "$c_before" ] && [ "${c_before#feed-c 4 }" != "$c_before" ]' \
      "the lists and their counters are untouched by all of it ($c_before)"

# ------------------------------------ 6. a transaction the kernel rejects
mkdir -p "$W/reject"
cat > "$W/reject/nft" <<EOF
#!/bin/bash
# A load that adds elements gets one more statement the kernel refuses,
# so the whole transaction aborts; a load without elements passes.
case " \$* " in *" -f "*) ;; *) exec "$REAL_NFT" "\$@" ;; esac
script="\$(cat)"
if grep -q "add element" <<<"\$script"; then
  script="\$script
delete table inet stockfw_no_such_table"
fi
printf '%s\n' "\$script" | "$REAL_NFT" "\$@"
EOF
chmod +x "$W/reject/nft"
out="$(drv_with reject apply "$F_A")"; rc=$?
check '[ $rc -eq 1 ] && grep -q "^error failed: nft refused the change" <<<"$out" && grep -q "(fingerprint $D_B) are still in force" <<<"$out"' \
      "a rejected transaction is a failure that names the lists still in force (${out:0:150})"
check '[ "$(drv live)" = "present $D_B" ] && "$REAL_NFT" list set inet stockfw_intel s_feed_c_4 | grep -q 192.0.2.2' \
      "the previous table, its digest and its set are still in force"

# The same rule set refused (the hourly re-apply of an unchanged one):
# the kernel then holds the digest asked for, but only because it held
# it before.  Never a success: nothing shows the table was replaced,
# and its counters (still counting) must not be carried and counted
# again.
c_before="$(counters)"
out="$(drv_with reject apply "$F_B")"; rc=$?
check '[ $rc -eq 1 ] && grep -q "nft refused the change" <<<"$out" && grep -q "The same blocklists (fingerprint $D_B) were already loaded and are still in force" <<<"$out"' \
      "the same rule set refused: a failure that says the same lists are still in force (${out:0:220})"
check '[ "$(drv live)" = "present $D_B" ] && [ "$(counters)" = "$c_before" ] && [ "${c_before#feed-c 4 }" != "$c_before" ]' \
      "... the table was not replaced: its counters still run ($c_before)"

# ------------------------------------------------- 7. nft killed mid-apply
mkdir -p "$W/killed-before" "$W/killed-after"
cat > "$W/killed-before/nft" <<EOF
#!/bin/bash
case " \$* " in *" -f "*) ;; *) exec "$REAL_NFT" "\$@" ;; esac
cat > /dev/null
kill -KILL \$\$
EOF
cat > "$W/killed-after/nft" <<EOF
#!/bin/bash
case " \$* " in *" -f "*) ;; *) exec "$REAL_NFT" "\$@" ;; esac
"$REAL_NFT" "\$@"
kill -KILL \$\$
EOF
chmod +x "$W/killed-before/nft" "$W/killed-after/nft"
out="$(drv_with killed-before apply "$F_A")"; rc=$?
check '[ $rc -eq 1 ] && grep -q "killed by a signal" <<<"$out" && grep -q "(fingerprint $D_B) are still in force" <<<"$out" && [ "$(drv live)" = "present $D_B" ]' \
      "nft killed before it loaded anything: a failure, and the previous lists are in force (${out:0:120})"
out="$(drv_with killed-after apply "$F_A")"; rc=$?
check '[ $rc -eq 0 ] && [ "$out" = applied ] && [ "$(drv live)" = "present $D_A" ]' \
      "nft killed after it committed: the kernel holds the new lists, so the apply succeeded ($out)"

# ---------------------------------------------------- 8. a hanging nft
export STOCKFW_TEST_NFT_TIMEOUT_MS=800
mkdir -p "$W/hang-before" "$W/hang-after" "$W/hang-all"
cat > "$W/hang-before/nft" <<EOF
#!/bin/bash
# Hangs on a load, before reading it; listings work.
case " \$* " in *" -f "*) exec sleep 30 ;; esac
exec "$REAL_NFT" "\$@"
EOF
cat > "$W/hang-after/nft" <<EOF
#!/bin/bash
# Commits a load, then hangs: the timeout fires after the commit.
case " \$* " in *" -f "*) "$REAL_NFT" "\$@"; exec sleep 30 ;; esac
exec "$REAL_NFT" "\$@"
EOF
printf '#!/bin/bash\n# Hangs on everything, listings too.\nexec sleep 30\n' > "$W/hang-all/nft"
chmod +x "$W/hang-before/nft" "$W/hang-after/nft" "$W/hang-all/nft"

t0=$(date +%s%N)
out="$(drv_with hang-before apply "$F_B")"; rc=$?
ms=$(ms_since "$t0")
check '[ $rc -eq 1 ] && grep -q "^error timed-out: nft timed out" <<<"$out" && grep -q "(fingerprint $D_A) are still in force" <<<"$out"' \
      "an nft that hangs before loading times out, and the error names the lists in force (${out:0:140})"
check '[ $ms -lt 5000 ] && [ "$(drv live)" = "present $D_A" ]' \
      "... stopped at the timeout, not after the hung nft's 30 s (${ms} ms), the old lists still in force"

t0=$(date +%s%N)
out="$(drv_with hang-after apply "$F_B")"; rc=$?
ms=$(ms_since "$t0")
check '[ $rc -eq 0 ] && [ "$out" = applied ] && [ "$(drv live)" = "present $D_B" ] && [ $ms -lt 5000 ]' \
      "a timeout that fires after nft committed: the live digest is the new one, so the apply succeeded (${ms} ms: $out)"

t0=$(date +%s%N)
out="$(drv_with hang-after clear)"; rc=$?
ms=$(ms_since "$t0")
check '[ $rc -eq 0 ] && [ "$out" = cleared ] && [ "$(drv live)" = absent ] && [ $ms -lt 5000 ]' \
      "a clear whose nft times out after committing: the table is gone, so the clear succeeded ($out)"
drv apply "$F_B" >/dev/null

t0=$(date +%s%N)
l="$(drv_with hang-all live)"
c="$(drv_with hang-all counters)"
out="$(drv_with hang-all apply "$F_A")"; rc=$?
ms=$(ms_since "$t0")
check '[ "$l" = unknown ] && [ "$c" = none ]' \
      "a listing that hangs: live is unknown, never absent, and counters are NULL ($l, $c)"
check '[ $rc -eq 1 ] && grep -q "^error timed-out: " <<<"$out" && grep -q "could not be read" <<<"$out" && [ $ms -lt 15000 ]' \
      "an apply whose nft hangs everywhere times out and says the lists in force could not be read (${ms} ms: ${out:0:160})"
check '[ "$(drv live)" = "present $D_B" ]' "... and nothing changed"
unset STOCKFW_TEST_NFT_TIMEOUT_MS

# ------------------------------------------- 9. what nft says vs the kernel
mkdir -p "$W/chatty" "$W/usurp"
cat > "$W/chatty/nft" <<EOF
#!/bin/bash
# A line of its own before every listing; loads pass untouched.
case " \$* " in *" -f "*) exec "$REAL_NFT" "\$@" ;; esac
echo "Warning: a line that is not part of the listing"
exec "$REAL_NFT" "\$@"
EOF
cat > "$W/usurp/nft" <<EOF
#!/bin/bash
# Loads, then something else replaces the table at once, with a
# digest on the table and on its input chain, where the live check
# reads it (design 12.7).
case " \$* " in *" -f "*) ;; *) exec "$REAL_NFT" "\$@" ;; esac
"$REAL_NFT" "\$@" || exit
printf 'table inet stockfw_intel {}\ndelete table inet stockfw_intel\ntable inet stockfw_intel {\n\tcomment "sfw:00000000000000000000000000000000"\n\tchain input {\n\t\ttype filter hook input priority filter - 10; policy accept;\n\t\tcomment "sfw:00000000000000000000000000000000"\n\t}\n}\n' | "$REAL_NFT" -f -
EOF
mkdir -p "$W/bare"
cat > "$W/bare/nft" <<EOF
#!/bin/bash
# Loads, then something else replaces the table with one that has our
# digest on the table but no chain at all: it blocks nothing.
case " \$* " in *" -f "*) ;; *) exec "$REAL_NFT" "\$@" ;; esac
"$REAL_NFT" "\$@" || exit
printf 'table inet stockfw_intel {}\ndelete table inet stockfw_intel\ntable inet stockfw_intel {\n\tcomment "sfw:%s"\n}\n' "\$STOCKFW_BARE_DIGEST" | "$REAL_NFT" -f -
EOF
chmod +x "$W/chatty/nft" "$W/usurp/nft" "$W/bare/nft"
check '[ "$(drv_with chatty live)" = unknown ]' "a listing that cannot be read is unknown, not absent"
out="$(drv_with chatty apply "$F_A")"; rc=$?
check '[ $rc -eq 1 ] && grep -q "could not be read back to confirm it" <<<"$out"' \
      "nft accepted the load but the table cannot be read back: not reported as applied (${out:0:110})"
check '[ "$(drv live)" = "present $D_A" ]' "(it did load: the honest answer was \"not confirmed\")"
out="$(drv_with usurp apply "$F_B")"; rc=$?
check '[ $rc -eq 1 ] && grep -q "not the one applied (fingerprint 00000000000000000000000000000000, not $D_B)" <<<"$out"' \
      "nft accepted the load but another table is there now: not reported as applied (${out:0:120})"
export STOCKFW_BARE_DIGEST="$D_A"
out="$(drv_with bare apply "$F_A")"; rc=$?
check '[ $rc -eq 1 ] && grep -q "not the one applied (fingerprint none, not $D_A)" <<<"$out" && [ "$(drv live)" = "present without digest" ]' \
      "a table with the applied digest but no chains: not applied, and live reads it without a digest (${out:0:120})"

# --------------------------------------------------- 10. the empty rule set
drv apply "$F_B" >/dev/null
F_EMPTY="$(spec empty '# nothing enabled')"
out="$(drv apply "$F_EMPTY")"; rc=$?
check '[ $rc -eq 0 ] && [ "$out" = applied ] && [ "$(drv live)" = absent ]' \
      "the empty rule set is applied by removing the table: live absent is the success ($out)"
check '[ "$(counters)" = none ]' "and there are no counters"
out="$(drv apply "$F_EMPTY")"; rc=$?
check '[ $rc -eq 0 ] && [ "$(drv live)" = absent ]' "applying it again, with no table there, is fine too ($out)"
drv apply "$F_B" >/dev/null
export STOCKFW_TEST_NFT_TIMEOUT_MS=800
out="$(drv_with hang-after apply "$F_EMPTY")"; rc=$?
unset STOCKFW_TEST_NFT_TIMEOUT_MS
check '[ $rc -eq 0 ] && [ "$(drv live)" = absent ]' \
      "the empty rule set with a timeout after the commit: absent, so a success ($out)"

# ------------------------------------------------------------- 11. clear
drv apply "$F_B" >/dev/null
out="$(drv clear)"; rc=$?
check '[ $rc -eq 0 ] && [ "$out" = cleared ] && [ "$(drv live)" = absent ]' "clear removes the table ($out)"
out="$(drv clear)"; rc=$?
check '[ $rc -eq 0 ] && [ "$out" = cleared ]' "clearing twice is fine ($out)"

# ------------------------------------------------ 12. no nft, not root
drv apply "$F_B" >/dev/null
out="$(PATH=/nonexistent "$DRV" apply "$F_A")"; rc=$?
check '[ $rc -eq 1 ] && grep -q "^error not-found: .*nftables package" <<<"$out"' "no nft: the apply says to install nftables (${out:0:90})"
out="$(PATH=/nonexistent "$DRV" clear)"; rc=$?
check '[ $rc -eq 1 ] && grep -q "^error not-found: " <<<"$out"' "no nft: clear is an error, not a claim that nothing is loaded"
check '[ "$(PATH=/nonexistent "$DRV" live)" = unknown ] && [ "$(PATH=/nonexistent "$DRV" counters)" = none ]' \
      "no nft: live is unknown, counters NULL"
nobody() { setpriv --reuid=65534 --regid=65534 --clear-groups env PATH="$W/log:$PATH" "$DRV" "$@"; }
out="$(nobody apply "$F_A")"; rc=$?
check '[ $rc -eq 1 ] && grep -q "^error permission: .*requires root" <<<"$out"' "not root: the apply says it needs root (${out:0:90})"
out="$(nobody clear)"; rc=$?
check '[ $rc -eq 1 ] && grep -q "^error permission: " <<<"$out"' "not root: clear is an error"
check '[ "$(nobody live)" = unknown ] && [ "$(nobody counters)" = none ]' "not root: live is unknown, counters NULL"
check '[ "$(drv live)" = "present $D_B" ]' "and none of them changed the kernel"
drv clear >/dev/null

# --------------------------------------------- 13. reading stays cheap
# Every listing the slots ran: the chains (names and comments only), the
# tables (names and comments only, when no chain of ours is listed) and
# our chains (rules only).  Never a table, a set or the ruleset, which
# would print every element [S8.3].  `list tables' itself fetches every
# element in nft 1.0.9 (design 12.7), so a table that is there must be
# read from `list chains' alone.
lists="$(grep -v -- "-f -" "$W/nft.log" | sort -u)"
odd="$(grep -v -x -e "-j list chains" -e "-j list tables" -e "list chain inet stockfw_intel input" \
  -e "list chain inet stockfw_intel output" -e "list chain inet stockfw_intel forward" <<<"$lists")"
check '[ -z "$odd" ] && grep -q "^list chain" <<<"$lists"' \
      "the slots list only the chains, the tables and our three chains, never a table or set (${odd:-none other})"

# ---------------------------------------------- 14. foreign rules, after
others="$(cat "$W"/scripts/*.nft | grep -E '^(table|delete|add|flush|destroy|insert|replace)' | grep -v -E '^(table|delete table|add element) inet stockfw_intel( |$)')"
check '[ -z "$others" ] && [ "$(loads)" -gt 10 ]' \
      "every script the slots loaded ($(loads)) names no table but inet stockfw_intel (${others:0:80})"
foreign > "$W/foreign.after"
check 'cmp -s "$W/foreign.before" "$W/foreign.after"' \
      "the policy's iptables rules, Docker's chains, libvirt's, firewalld's and the stockfw_blocklist tables are unchanged"
cmp -s "$W/foreign.before" "$W/foreign.after" || diff "$W/foreign.before" "$W/foreign.after" | head -20

echo
if [ $fails -eq 0 ]; then echo "PASSED: 0 failure(s)"; else echo "FAILED: $fails failure(s)"; fi
[ $fails -eq 0 ]
