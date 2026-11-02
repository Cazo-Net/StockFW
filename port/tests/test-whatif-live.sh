#!/bin/bash
# The What-If engine's Linux model against the kernel (1.0.7).
#
# A differential test: the same policy is loaded through the real Linux
# backend and asked about through the What-If engine, then real packets
# are sent and the engine's verdict must be what the kernel did.  No
# text is compared -- the golden table in test-whatif.c already pins
# the model to the generator's chains; this pins the chains' meaning,
# as iptables runs them, to the engine's answer.
#
# Runs itself in a private network namespace (unshare -n): this side is
# "the computer" (198.51.100.1 on v0); a peer namespace on the other end
# of a veth pair plays every remote host (198.51.100.2, 10.1.2.3,
# 192.0.2.7, 203.0.113.9 on v1).  TCP and UDP listeners and probes and
# raw ICMP echo are Python; no ping binary is needed.  IPv4 only: the
# kernel here may have no IPv6 stack.
#
# Needs root, iptables, ip, unshare, nsenter and python3; SKIPs without
# them.
#
#   sudo ./tests/test-whatif-live.sh

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"

if [ "$(id -u)" -ne 0 ]; then
	echo "SKIP: this test needs root"
	exit 0
fi
for tool in iptables iptables-restore ip unshare nsenter python3; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "SKIP: $tool not installed"
		exit 0
	fi
done

if [ "${STOCKFW_WHATIF_IN_NETNS:-}" != "1" ]; then
	exec env STOCKFW_WHATIF_IN_NETNS=1 unshare -n bash "$0" "$@"
fi
ip link set lo up

BUILD_DIR="$(mktemp -d)"
PEER_PID=""
SERVE_PIDS=""
cleanup() {
	for p in $SERVE_PIDS $PEER_PID; do
		kill "$p" 2>/dev/null
	done
	rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

failures=0
checked=0
CHECK() {
	local cond="$1"; shift
	if [ "$cond" = "0" ]; then
		printf 'ok:   %s\n' "$*"
	else
		printf 'FAIL: %s\n' "$*"
		failures=$((failures + 1))
	fi
}

# ------------------------------------------------------------ the driver
# Applies a round's policy through the real backend, and answers lines
# for it through the What-If engine (Linux model, firewall running,
# policy in force, this computer's address known).
cat > "$BUILD_DIR/whatif-live.c" <<'CEOF'
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "core/fs-backend.h"
#include "core/fs-rules.h"
#include "core/fs-script.h"
#include "core/fs-whatif.h"

static void
row (FsPolicy *p, FsRuleKind kind, const gchar *csv)
{
	FsRule *r = fs_rule_from_csv (kind, csv);

	if (r == NULL) {
		fprintf (stderr, "bad row %d %s\n", kind, csv);
		exit (2);
	}
	fs_policy_add (p, r);
	fs_rule_free (r);
}

static void
round_of (gint n, FsPolicy *p, FsSettings *s)
{
	switch (n) {
	case 1:
		row (p, FS_RULE_INBOUND_ALLOW_SERVICE, "SSH,22,10.0.0.0/8,lan");
		row (p, FS_RULE_INBOUND_ALLOW_FROM, "192.0.2.7,friend");
		row (p, FS_RULE_INBOUND_ALLOW_SERVICE, "TCP,8443,Anyone,x");
		row (p, FS_RULE_INBOUND_ALLOW_SERVICE, "UDP,5000,198.51.100.2,x");
		row (p, FS_RULE_INBOUND_ALLOW_SERVICE,
		     "Game,7000-7010 7100,Anyone,lists");
		row (p, FS_RULE_OUTBOUND_DENY_TO, "203.0.113.9,bad");
		row (p, FS_RULE_OUTBOUND_DENY_SERVICE, "SMTP,25,Anyone,no mail");
		break;
	case 2:
		s->restrictive_outbound = TRUE;
		s->icmp_echo_request = FALSE;
		s->deny_packets = FALSE;
		row (p, FS_RULE_OUTBOUND_ALLOW_SERVICE, "HTTPS,443,Anyone,web");
		row (p, FS_RULE_OUTBOUND_ALLOW_SERVICE, "DNS,53,198.51.100.2,dns");
		row (p, FS_RULE_OUTBOUND_ALLOW_TO, "192.0.2.7,friend");
		row (p, FS_RULE_OUTBOUND_DENY_TO, "192.0.2.7,but not");
		row (p, FS_RULE_INBOUND_ALLOW_SERVICE, "HTTP,80,198.51.100.2,web");
		break;
	case 3:
		g_free (s->ext_device);
		s->ext_device = g_strdup ("v0");
		s->log_allowed = FALSE;
		row (p, FS_RULE_INBOUND_ALLOW_SERVICE, "SSH,22,10.0.0.0/8,lan");
		row (p, FS_RULE_INBOUND_ALLOW_SERVICE, "SSH,22,198.51.100.2,peer");
		row (p, FS_RULE_INBOUND_ALLOW_FROM, "192.0.2.7,friend");
		break;
	default:
		fprintf (stderr, "no round %d\n", n);
		exit (2);
	}
}

/* A DEPENDS answer that splits only on the interface the packet uses:
 * the probes here all use v0, so the case that names it applies, or
 * the common case when none does. */
static FsWhatIfVerdict
on_v0 (const FsWhatIfAnswer *a)
{
	const FsWhatIfCase *base;

	if (a->verdict != FS_WHATIF_DEPENDS || a->cases->len == 0)
		return a->verdict;
	base = g_ptr_array_index (a->cases, 0);
	for (guint i = 1; i < a->cases->len; i++) {
		const FsWhatIfCase *c = g_ptr_array_index (a->cases, i);

		if (strstr (c->condition, "arrives on v0") != NULL ||
		    strstr (c->condition, "leaves by v0") != NULL)
			return c->verdict;
		if (strstr (c->condition, " on ") == NULL &&
		    strstr (c->condition, " by ") == NULL)
			return FS_WHATIF_DEPENDS;
	}
	return base->verdict;
}

int
main (int argc, char **argv)
{
	FsPolicy *p = fs_policy_new ();
	FsSettings *s = fs_settings_new ();
	gint n;

	if (argc < 3) {
		fprintf (stderr, "usage: whatif-live apply|ask ROUND [line...]\n");
		return 2;
	}
	n = atoi (argv[2]);
	round_of (n, p, s);

	if (strcmp (argv[1], "apply") == 0) {
		GError *error = NULL;
		FsApplyResult r;

		fs_backend_set_context (p, s);
		r = fs_backend ()->apply_rules (p, &error);
		printf ("RESULT %s | %s\n", fs_util_apply_result_to_string (r),
		        error != NULL ? error->message : "");
		g_clear_error (&error);
		return (r == FS_APPLY_OK) ? 0 : 1;
	}

	for (gint i = 3; i < argc; i++) {
		FsWhatIfContext *ctx = fs_whatif_context_new (
			FS_WHATIF_LINUX_FIRST_MATCH, p, s);
		FsWhatIfResult *r;

		ctx->firewall = FS_WHATIF_FW_RUNNING;
		ctx->live = FS_WHATIF_LIVE_YES;
		fs_whatif_context_add_local_address (ctx, "198.51.100.1");
		r = fs_whatif_simulate_text (ctx, argv[i]);
		if (r->verdict == FS_WHATIF_ERROR || r->answers->len != 1) {
			printf ("ERROR\t%s\n", r->error != NULL ? r->error
			                                        : "not one answer");
		} else {
			const FsWhatIfAnswer *a = g_ptr_array_index (r->answers, 0);

			printf ("%s\t%s\n", fs_whatif_verdict_name (on_v0 (a)),
			        r->summary);
		}
		fs_whatif_result_free (r);
		fs_whatif_context_free (ctx);
	}
	fs_settings_free (s);
	fs_policy_free (p);
	return 0;
}
CEOF

CF="$(pkg-config --cflags glib-2.0 gobject-2.0 gio-2.0)"
LF="$(pkg-config --libs glib-2.0 gobject-2.0 gio-2.0)"
# shellcheck disable=SC2086
cc ${STOCKFW_TEST_CFLAGS:-} -o "$BUILD_DIR/whatif-live" -I "$PORT/src" $CF \
	"$BUILD_DIR/whatif-live.c" "$PORT/src/platform/linux/fs-backend-linux.c" \
	"$PORT"/src/core/*.c $LF 2> "$BUILD_DIR/cc.log"
CHECK $? "the driver compiles against the real Linux backend and the engine"
[ -x "$BUILD_DIR/whatif-live" ] || { cat "$BUILD_DIR/cc.log"; exit 1; }
DRIVER="$BUILD_DIR/whatif-live"

# ------------------------------------------------------------ the probes
cat > "$BUILD_DIR/probe.py" <<'PYEOF'
"""Listeners and probes for the What-If live test.

serve PORT...             TCP accept-and-close and UDP echo on each port
probe tcp|udp SRC DST PORT  OPEN if a connection or an echo came back
probe icmp SRC DST        OPEN if an echo reply came back
"""
import os
import select
import socket
import struct
import sys
import time

TIMEOUT = 1.0
IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8)


def serve(ports):
    socks = []
    for port in ports:
        t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        t.bind(("0.0.0.0", port))
        t.listen(16)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
        u.bind(("0.0.0.0", port))
        socks += [t, u]
    print("READY", flush=True)
    while True:
        ready, _, _ = select.select(socks, [], [])
        for s in ready:
            if s.type == socket.SOCK_STREAM:
                c, _ = s.accept()
                c.close()
            else:
                # Answer from the address the probe was sent to: the
                # kernel's own choice would be the interface's first
                # address, which conntrack would not see as the reply.
                data, anc, _, peer = s.recvmsg(2048, socket.CMSG_SPACE(12))
                local = None
                for level, kind, cdata in anc:
                    if level == socket.IPPROTO_IP and kind == IP_PKTINFO:
                        local = struct.unpack("I4s4s", cdata[:12])[2]
                if local is None:
                    s.sendto(data, peer)
                else:
                    info = struct.pack("I4s4s", 0, local, b"\0" * 4)
                    s.sendmsg([data], [(socket.IPPROTO_IP, IP_PKTINFO, info)],
                               0, peer)


def checksum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def probe(proto, src, dst, port):
    if proto == "tcp":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.bind((src, 0))
        try:
            s.connect((dst, port))
            return True
        except OSError:
            return False
        finally:
            s.close()
    if proto == "udp":
        # Connected: only an answer from dst:port counts.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(TIMEOUT)
        s.bind((src, 0))
        try:
            s.connect((dst, port))
            s.send(b"whatif")
            return s.recv(2048) == b"whatif"
        except OSError:
            return False
        finally:
            s.close()
    # ICMP echo
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.bind((src, 0))
    ident = os.getpid() & 0xFFFF
    head = struct.pack("!BBHHH", 8, 0, 0, ident, 1)
    body = b"whatif-live"
    pkt = struct.pack("!BBHHH", 8, 0, checksum(head + body), ident, 1) + body
    try:
        s.sendto(pkt, (dst, 0))
    except OSError:
        return False
    end = time.time() + TIMEOUT
    while time.time() < end:
        r, _, _ = select.select([s], [], [], max(0, end - time.time()))
        if not r:
            break
        data, addr = s.recvfrom(2048)
        ihl = (data[0] & 0x0F) * 4
        typ, _, _, rid, _ = struct.unpack("!BBHHH", data[ihl:ihl + 8])
        if typ == 0 and rid == ident and addr[0] == dst:
            return True
    return False


if sys.argv[1] == "serve":
    serve([int(p) for p in sys.argv[2:]])
else:
    proto, src, dst = sys.argv[2], sys.argv[3], sys.argv[4]
    port = int(sys.argv[5]) if len(sys.argv) > 5 else 0
    print("OPEN" if probe(proto, src, dst, port) else "SHUT")
PYEOF
PROBE="python3 -I $BUILD_DIR/probe.py"

# ------------------------------------------------------------ the network
unshare -n sleep 600 &
PEER_PID=$!
sleep 0.3
PEER="nsenter -t $PEER_PID -n"

ip link add v0 type veth peer name v1 netns "$PEER_PID"
ip addr add 198.51.100.1/24 dev v0
ip link set v0 up
$PEER ip link set lo up
$PEER ip addr add 198.51.100.2/24 dev v1
for a in 10.1.2.3 192.0.2.7 203.0.113.9; do
	$PEER ip addr add "$a/32" dev v1
	ip route add "$a/32" dev v0
done
$PEER ip link set v1 up
sleep 1

PORTS="22 25 53 80 443 587 3389 5000 7005 8080 8443 33434"
$PROBE serve $PORTS > "$BUILD_DIR/serve-here.txt" 2>&1 &
SERVE_PIDS="$!"
$PEER $PROBE serve $PORTS > "$BUILD_DIR/serve-peer.txt" 2>&1 &
SERVE_PIDS="$SERVE_PIDS $!"
sleep 1
T_READY=0
grep -q READY "$BUILD_DIR/serve-here.txt" && grep -q READY "$BUILD_DIR/serve-peer.txt" || T_READY=1
CHECK $T_READY "listeners are up on both sides"

# Before any firewall: every probe gets through, so a SHUT later is the
# firewall's doing and not the network's.
nofw=0
for spec in "tcp 198.51.100.1 198.51.100.2 443" "udp 198.51.100.1 203.0.113.9 53" \
            "icmp 198.51.100.1 203.0.113.9"; do
	[ "$($PROBE probe $spec)" = "OPEN" ] || nofw=1
done
for spec in "tcp 10.1.2.3 198.51.100.1 22" "udp 192.0.2.7 198.51.100.1 5000" \
            "icmp 198.51.100.2 198.51.100.1"; do
	[ "$($PEER $PROBE probe $spec)" = "OPEN" ] || nofw=1
done
CHECK $nofw "with no firewall loaded every probe gets through (the network works)"

# ------------------------------------------------------------ one probe
# probe ROUND "line" PROTO DIR REMOTE PORT
#   DIR in: the peer sends from REMOTE to 198.51.100.1:PORT
#   DIR out: this side sends from 198.51.100.1 to REMOTE:PORT
probe() {
	local round="$1" line="$2" proto="$3" dir="$4" remote="$5" port="${6:-}"
	local model kernel got
	model="$("$DRIVER" ask "$round" "$line")"
	if [ "$dir" = in ]; then
		kernel="$($PEER $PROBE probe "$proto" "$remote" 198.51.100.1 $port)"
	else
		kernel="$($PROBE probe "$proto" 198.51.100.1 "$remote" $port)"
	fi
	case "$kernel" in
		OPEN) got=ALLOWED ;;
		SHUT) got=BLOCKED ;;
		*) got="probe failed: $kernel" ;;
	esac
	checked=$((checked + 1))
	[ "${model%%	*}" = "$got" ]
	CHECK $? "round $round: \"$line\": the engine says ${model%%	*}, the kernel $got -- ${model#*	}"
}

apply_round() {
	local out
	out="$("$DRIVER" apply "$1")"
	CHECK $? "round $1 applies through the real backend -- $out"
	iptables -C INPUT -j INBOUND 2>/dev/null && iptables -C OUTPUT -j OUTBOUND 2>/dev/null
	CHECK $? "round $1: INPUT and OUTPUT go through StockFW's chains"
}

# --------------------------------------------- round 1: defaults, rows
apply_round 1
probe 1 "inbound tcp port 22 from 10.1.2.3"        tcp in 10.1.2.3 22
probe 1 "inbound tcp port 22 from 198.51.100.2"    tcp in 198.51.100.2 22
probe 1 "inbound udp port 22 from 10.1.2.3"        udp in 10.1.2.3 22
probe 1 "inbound tcp port 8443 from 198.51.100.2"  tcp in 198.51.100.2 8443
probe 1 "inbound udp port 8443 from 198.51.100.2"  udp in 198.51.100.2 8443
probe 1 "inbound udp port 5000 from 198.51.100.2"  udp in 198.51.100.2 5000
probe 1 "inbound udp port 5000 from 10.1.2.3"      udp in 10.1.2.3 5000
probe 1 "inbound tcp port 3389 from 192.0.2.7"     tcp in 192.0.2.7 3389
probe 1 "inbound tcp port 3389 from 198.51.100.2"  tcp in 198.51.100.2 3389
probe 1 "inbound udp port 7005 from 198.51.100.2"  udp in 198.51.100.2 7005
probe 1 "inbound udp port 33434 from 198.51.100.2" udp in 198.51.100.2 33434
probe 1 "inbound ping from 198.51.100.2"           icmp in 198.51.100.2
probe 1 "outbound tcp to 203.0.113.9 port 443"     tcp out 203.0.113.9 443
probe 1 "outbound udp to 203.0.113.9 port 53"      udp out 203.0.113.9 53
probe 1 "outbound tcp to 198.51.100.2 port 443"    tcp out 198.51.100.2 443
probe 1 "outbound tcp to 198.51.100.2 port 25"     tcp out 198.51.100.2 25
probe 1 "outbound udp to 198.51.100.2 port 25"     udp out 198.51.100.2 25
probe 1 "outbound tcp to 198.51.100.2 port 587"    tcp out 198.51.100.2 587
probe 1 "outbound ping to 203.0.113.9"             icmp out 203.0.113.9

# ----------------- round 2: restrictive outbound, no ping, reject, b6
apply_round 2
probe 2 "outbound tcp to 198.51.100.2 port 443"    tcp out 198.51.100.2 443
probe 2 "outbound tcp to 198.51.100.2 port 8080"   tcp out 198.51.100.2 8080
probe 2 "outbound udp to 198.51.100.2 port 53"     udp out 198.51.100.2 53
probe 2 "outbound tcp to 192.0.2.7 port 22"        tcp out 192.0.2.7 22
probe 2 "outbound udp to 203.0.113.9 port 443"     udp out 203.0.113.9 443
probe 2 "outbound ping to 198.51.100.2"            icmp out 198.51.100.2
probe 2 "inbound ping from 198.51.100.2"           icmp in 198.51.100.2
probe 2 "inbound tcp port 80 from 198.51.100.2"    tcp in 198.51.100.2 80
probe 2 "inbound tcp port 80 from 10.1.2.3"        tcp in 10.1.2.3 80
probe 2 "inbound udp port 33434 from 10.1.2.3"     udp in 10.1.2.3 33434

# -------------- round 3: an external device, its reserved-source block
apply_round 3
probe 3 "inbound tcp port 22 from 10.1.2.3"        tcp in 10.1.2.3 22
probe 3 "inbound tcp port 22 from 198.51.100.2"    tcp in 198.51.100.2 22
probe 3 "inbound tcp port 80 from 192.0.2.7"       tcp in 192.0.2.7 80
probe 3 "inbound tcp port 80 from 203.0.113.9"     tcp in 203.0.113.9 80
probe 3 "inbound ping from 10.1.2.3"               icmp in 10.1.2.3
probe 3 "outbound tcp to 10.1.2.3 port 443"        tcp out 10.1.2.3 443
probe 3 "outbound tcp to 203.0.113.9 port 443"     tcp out 203.0.113.9 443

CHECK $([ "$checked" -ge 30 ]; echo $?) \
	"$checked probes compared: the engine's verdict is the kernel's for every one"

printf '\n%s: %d failure(s)\n' "$([ "$failures" -eq 0 ] && echo PASSED || echo FAILED)" \
	"$failures"
[ "$failures" -eq 0 ]
