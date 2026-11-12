#!/bin/bash
# The Linux backend with both address families (1.0.7), executed for
# real.  Runs itself inside a private network namespace (unshare -n),
# so the host's own firewall is never touched.
#
# What it proves, by inspecting the kernel afterwards:
#   - one apply loads IPv4 and IPv6, each hooked into INPUT/OUTPUT, and
#     IPv6 keeps what IPv6 needs to work (neighbour discovery);
#   - addresses land only in their own family; a name is looked up once
#     and written as each family's addresses;
#   - re-applying replaces the rules in place: the INPUT hook is never
#     removed and re-added (no unfiltered moment), nothing duplicates;
#   - an IPv6 failure rolls IPv4 back, so the kernel keeps the old
#     policy rather than half of the new one (teeth: the test fails if
#     the rollback is removed);
#   - a block whose host cannot be looked up fails the apply and
#     changes nothing;
#   - router mode: IPv6 port forward with [addr]:port, masquerading
#     IPv4 only, FORWARD hooked for IPv6 only then;
#   - stop removes every StockFW chain in both families and nothing else;
#   - ipv6_state tells filtered, not filtered and absent apart.
#
# The kernel here may have no IPv6 stack at all; ip6tables still loads
# rules, and STOCKFW_ASSUME_IPV6=1 tells the backend to try.
#
#   sudo ./tests/test-apply-dual.sh

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"

if [ "$(id -u)" -ne 0 ]; then
	echo "SKIP: this test needs root"
	exit 0
fi
for tool in iptables ip6tables iptables-restore ip6tables-restore unshare; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "SKIP: $tool not installed"
		exit 0
	fi
done

if [ "${STOCKFW_DUAL_IN_NETNS:-}" != "1" ]; then
	exec env STOCKFW_DUAL_IN_NETNS=1 unshare -n bash "$0" "$@"
fi
ip link set lo up 2>/dev/null

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT
failures=0

CHECK() {
	local cond="$1"; shift
	if [ "$cond" = "0" ]; then
		printf 'ok:   %s\n' "$*"
	else
		printf 'FAIL: %s\n' "$*"
		failures=$((failures + 1))
	fi
}
# T 'shell expression' description -- the expression is evaluated as
# written, so negation, pipes and && all mean what they say.
T() {
	local code="$1"; shift
	if eval "$code"; then CHECK 0 "$*"; else CHECK 1 "$*"; fi
}
APPLIED="RESULT Rules applied"

cat > "$BUILD_DIR/dual.c" <<'CEOF'
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <gio/gio.h>
#include "core/fs-backend.h"
#include "core/fs-rules.h"
#include "core/fs-script.h"

static gboolean
fake_resolve (const gchar *host, GPtrArray *v4, GPtrArray *v6, GError **error)
{
	if (strcmp (host, "example.test") == 0) {
		g_ptr_array_add (v4, g_strdup ("192.0.2.66"));
		g_ptr_array_add (v6, g_strdup ("2001:db8::66"));
		return TRUE;
	}
	g_set_error (error, G_RESOLVER_ERROR, G_RESOLVER_ERROR_TEMPORARY_FAILURE,
	             "Temporary failure in name resolution");
	return FALSE;
}

static void
add (FsPolicy *p, FsRuleKind kind, const gchar *service, const gchar *port,
     const gchar *target, const gchar *to, const gchar *to_port)
{
	FsRule *r = fs_rule_new (kind);

	r->service = g_strdup (service);
	r->port = g_strdup (port);
	r->target = g_strdup (target);
	r->to = g_strdup (to);
	r->to_port = g_strdup (to_port);
	fs_policy_add (p, r);
	fs_rule_free (r);
}

int
main (int argc, char **argv)
{
	FsPolicy *p = fs_policy_new ();
	FsSettings *s = fs_settings_new ();
	const FsBackend *b = fs_backend ();
	GError *error = NULL;
	const gchar *mode = argc > 1 ? argv[1] : "apply";

	s->ext_device = g_strdup ("eth9");
	s->int_device = g_strdup ("eth8");

	add (p, FS_RULE_INBOUND_ALLOW_SERVICE, "SSH", "22", "192.168.1.0/24",
	     NULL, NULL);
	add (p, FS_RULE_INBOUND_ALLOW_FROM, NULL, NULL, "2001:db8:1::/48",
	     NULL, NULL);
	add (p, FS_RULE_OUTBOUND_DENY_TO, NULL, NULL, "2001:db8::bad", NULL, NULL);
	add (p, FS_RULE_OUTBOUND_DENY_TO, NULL, NULL, "example.test", NULL, NULL);

	for (gint i = 2; i < argc; i++) {
		if (strcmp (argv[i], "nat") == 0) {
			s->nat = TRUE;
			add (p, FS_RULE_INBOUND_FORWARD, "Web", "8080", NULL,
			     "2001:db8::5", "80");
			add (p, FS_RULE_INBOUND_FORWARD, "Web", "8081", NULL,
			     "192.168.1.5", "80");
		} else if (strcmp (argv[i], "extra") == 0)
			add (p, FS_RULE_INBOUND_ALLOW_SERVICE, "HTTP", "80", "Anyone",
			     NULL, NULL);
		else if (strcmp (argv[i], "downallow") == 0)
			add (p, FS_RULE_INBOUND_ALLOW_FROM, NULL, NULL, "down.test",
			     NULL, NULL);
		else if (strcmp (argv[i], "badhost") == 0)
			add (p, FS_RULE_OUTBOUND_DENY_TO, NULL, NULL, "broken.test",
			     NULL, NULL);
		else if (strcmp (argv[i], "nolog") == 0)
			s->log_allowed = FALSE;
		else if (strcmp (argv[i], "restrictive") == 0)
			s->restrictive_outbound = TRUE;
	}

	fs_script_set_resolver (fake_resolve);
	fs_backend_set_context (p, s);

	if (strcmp (mode, "apply") == 0) {
		FsApplyResult r = b->apply_rules (p, &error);

		gchar *notes = (r == FS_APPLY_OK && b->apply_notes != NULL)
		               ? b->apply_notes () : NULL;

		if (notes != NULL)
			g_strdelimit (notes, "\n", '/');
		printf ("RESULT %s | %s | NOTES %s\n",
		        fs_util_apply_result_to_string (r),
		        error != NULL ? error->message : "",
		        notes != NULL ? notes : "");
		g_free (notes);
	} else if (strcmp (mode, "stop") == 0) {
		printf ("STOP %s\n", b->stop (&error) ? "ok" : error->message);
	} else if (strcmp (mode, "state") == 0) {
		gchar *detail = NULL;
		FsIpv6State st = b->ipv6_state (&detail);

		printf ("IPV6 %s | %s\n", fs_ipv6_state_to_string (st), detail);
		g_free (detail);
	}

	g_clear_error (&error);
	return 0;
}
CEOF

CF="$(pkg-config --cflags glib-2.0 gobject-2.0 gio-2.0)"
LF="$(pkg-config --libs glib-2.0 gobject-2.0 gio-2.0 liblzma libcrypto json-glib-1.0)"
# fs-toolpath.c with FS_TOOLPATH_TESTING: root then takes its tools from
# PATH, so the fake ip6tables-restore below is the one that runs.  The
# release build takes them from the system directories only.
gcc -o "$BUILD_DIR/dual" -I "$PORT/src" $CF -DFS_TOOLPATH_TESTING=1 \
	"$BUILD_DIR/dual.c" "$PORT/src/core/fs-toolpath.c" \
	"$PORT/src/platform/linux/fs-backend-linux.c" \
	"${STOCKFW_BUILD:-$PORT/build-linux}/libfs-core.a" $LF 2> "$BUILD_DIR/cc.log"
CHECK $? "harness compiles against the real Linux backend"
[ -x "$BUILD_DIR/dual" ] || { cat "$BUILD_DIR/cc.log"; exit 1; }

DUAL="$BUILD_DIR/dual"
export STOCKFW_ASSUME_IPV6=1

# Someone else's rules, in both families: never touched.
iptables -N TEST_FOREIGN; iptables -A TEST_FOREIGN -j RETURN
iptables -A INPUT -j TEST_FOREIGN
ip6tables -N TEST_FOREIGN; ip6tables -A TEST_FOREIGN -j RETURN
ip6tables -A INPUT -j TEST_FOREIGN

# ------------------------------------------------------------ first apply
out="$("$DUAL" apply)"
T '[ "${out%% |*}" = "$APPLIED" ]' "dual apply succeeds -- got [$out]"

for t in iptables ip6tables; do
	T '$t -C INPUT -j INBOUND' "$t: INPUT jumps to INBOUND"
	T '$t -C OUTPUT -j OUTBOUND' "$t: OUTPUT jumps to OUTBOUND"
done
T 'iptables -C FORWARD -j INBOUND' "IPv4 FORWARD goes through INBOUND, as before"
T '! ip6tables -C FORWARD -j INBOUND 2>/dev/null' \
	"IPv6 FORWARD is left alone outside router mode (containers, VMs)"

v4in="$(iptables -S INBOUND)"; v6in="$(ip6tables -S INBOUND)"
v4out="$(iptables -S OUTBOUND)"; v6out="$(ip6tables -S OUTBOUND)"

T 'grep -q -- "-s 192.168.1.0/24 -p tcp -m tcp --dport 22" <<<"$v4in"' \
	"IPv4 gets the IPv4 rule"
T '! grep -q "192.168.1.0" <<<"$v6in"' "IPv6 does not"
T 'grep -q -- "-s 2001:db8:1::/48 -j ACCEPT_LOG" <<<"$v6in"' \
	"IPv6 gets the IPv6 rule"
T '! grep -q "2001:db8" <<<"$v4in$v4out"' "IPv4 does not"
T 'grep -q -- "-d 192.0.2.66/32 -j DROP" <<<"$v4out"' \
	"a blocked name becomes its IPv4 address in IPv4"
T 'grep -q -- "-d 2001:db8::66/128 -j DROP" <<<"$v6out"' \
	"and its IPv6 address in IPv6"
T 'grep -q -- "--icmpv6-type 135 -m hl --hl-eq 255 -j ACCEPT" <<<"$v6in"' \
	"IPv6 inbound accepts neighbour solicitations (hop limit 255)"
T 'grep -q -- "--icmpv6-type 134 -m hl --hl-eq 255 -j ACCEPT" <<<"$v6in"' \
	"and router advertisements"
T 'grep -q -- "--icmpv6-type 135 -m hl --hl-eq 255 -j ACCEPT" <<<"$v6out"' \
	"IPv6 outbound lets neighbour solicitations out"
T '! grep -q -- "-p icmp " <<<"$v6in$v6out"' \
	"no IPv4 ICMP rule leaked into IPv6 (it would silently match nothing)"
T 'grep -q -- "-o lo -j ACCEPT" <<<"$v4out" && grep -q -- "-o lo -j ACCEPT" <<<"$v6out"' \
	"loopback is accepted on its way OUT in both (-i lo never matched in OUTPUT)"
T '[ "$(tail -n 1 <<<"$v6in" | sed "s/^-A INBOUND //")" = "$(tail -n 1 <<<"$v4in" | sed "s/^-A INBOUND //")" ]' \
	"IPv6 ends with the same default action as IPv4 -- [$(tail -n 1 <<<"$v6in")]"

# ---------------------------------------------- re-apply: in place, no gap
hook() { nft -a list chain "$1" filter INPUT 2>/dev/null | grep 'jump INBOUND' | grep -o 'handle [0-9]*'; }
h4="$(hook ip)"; h6="$(hook ip6)"
out="$("$DUAL" apply extra)"
T '[ "${out%% |*}" = "$APPLIED" ]' "re-apply with one more rule -- got [$out]"
T 'iptables -C INBOUND -p tcp --dport 80 -j ACCEPT_LOG && ip6tables -C INBOUND -p tcp --dport 80 -j ACCEPT_LOG' \
	"the new rule is there, in both families"
if command -v nft >/dev/null 2>&1 && [ -n "$h4" ] && [ -n "$h6" ]; then
	T '[ "$h4" = "$(hook ip)" ] && [ "$h6" = "$(hook ip6)" ]' \
		"the INPUT hooks were never removed and re-added ($h4 / $h6): no unfiltered moment"
fi
T '[ "$(iptables -S INPUT | grep -c -- "-j INBOUND")" = 1 ] && [ "$(ip6tables -S INPUT | grep -c -- "-j INBOUND")" = 1 ]' \
	"exactly one hook per family after re-applying"
T '[ "$(iptables -S INBOUND | grep -c -- "--dport 22 ")" = 2 ]' \
	"no rule duplicated (tcp + udp for SSH, once)"

# ------------------------------------------------ rollback on IPv6 failure
before4="$(iptables -S; iptables -t nat -S)"; before6="$(ip6tables -S; ip6tables -t nat -S)"
mkdir -p "$BUILD_DIR/failbin" "$BUILD_DIR/fakebin"
printf '#!/bin/sh\ncat >/dev/null\necho "ip6tables-restore: injected failure" >&2\nexit 1\n' \
	> "$BUILD_DIR/failbin/ip6tables-restore"
chmod +x "$BUILD_DIR/failbin/ip6tables-restore"
out="$(PATH="$BUILD_DIR/failbin:$PATH" "$DUAL" apply)"   # the policy WITHOUT "extra"
T 'grep -q "^RESULT Failed.*IPv6 rules were refused (ip6tables-restore: injected failure)" <<<"$out"' \
	"an IPv6 failure fails the apply and says why -- got [$out]"
T 'grep -q "IPv4 was put back as it was" <<<"$out"' "and says IPv4 was put back"
T '[ "$(iptables -S; iptables -t nat -S)" = "$before4" ]' \
	"IPv4 is exactly as it was: the half-applied new policy was rolled back"
T '[ "$(ip6tables -S; ip6tables -t nat -S)" = "$before6" ]' "IPv6 is untouched"

# ------------------------------- an allow that cannot resolve: a note
out="$("$DUAL" apply downallow)"
T '[ "${out%% |*}" = "$APPLIED" ]' \
	"an allow whose name cannot be looked up does not fail the apply -- got [$out]"
T 'grep -q "| NOTES .*down.test" <<<"$out"' \
	"the apply says the rule was left out"
T '! iptables -S | grep -q down.test' "and nothing names it in the kernel"
out="$("$DUAL" apply)"
T 'grep -q "| NOTES $" <<<"$out"' "a clean apply has no notes -- got [$out]"
before4="$(iptables -S; iptables -t nat -S)"; before6="$(ip6tables -S; ip6tables -t nat -S)"

# ------------------------------------------- a block that cannot resolve
out="$("$DUAL" apply badhost)"
T 'grep -q "^RESULT Failed.*Cannot block broken.test" <<<"$out"' \
	"a block whose name cannot be looked up fails the apply -- got [$out]"
T '[ "$(iptables -S; iptables -t nat -S)" = "$before4" ] && [ "$(ip6tables -S; ip6tables -t nat -S)" = "$before6" ]' \
	"and nothing changed in either family"

# -------------------------------------------------------------- router mode
out="$("$DUAL" apply nat)"
T '[ "${out%% |*}" = "$APPLIED" ]' "router mode applies -- got [$out]"
T 'ip6tables -C FORWARD -j INBOUND' "IPv6 FORWARD is filtered in router mode"
T 'ip6tables -t nat -S STOCKFW-DNAT | grep -qF -- "--to-destination [2001:db8::5]:80"' \
	"the IPv6 forward is written [address]:port (without brackets the port joins the address)"
T 'iptables -t nat -S STOCKFW-DNAT | grep -qF -- "--to-destination 192.168.1.5:80"' \
	"the IPv4 forward is in IPv4's nat table"
T '! ip6tables -t nat -S STOCKFW-DNAT | grep -qF "192.168.1.5"' \
	"and not in IPv6's"
T '! iptables -t nat -C POSTROUTING -o eth9 -j MASQUERADE 2>/dev/null' \
	"masquerading is no longer written straight into POSTROUTING"
T 'iptables -t nat -S STOCKFW-SNAT | grep -q -- "-o eth9 -j MASQUERADE"' \
	"but in StockFW's own STOCKFW-SNAT"
T '! ip6tables -t nat -S 2>/dev/null | grep -q MASQUERADE' \
	"and for IPv4 only"
T 'iptables -t nat -C PREROUTING -j STOCKFW-DNAT && ip6tables -t nat -C PREROUTING -j STOCKFW-DNAT' \
	"both nat tables hook STOCKFW-DNAT"
T 'iptables -S INBOUND | grep -q -- "-d 192.168.1.5/32 -p tcp -m tcp --dport 80 -m conntrack --ctstate DNAT"' \
	"what an IPv4 forward lets in is accepted after the DNAT"
T 'ip6tables -S INBOUND | grep -q -- "-d 2001:db8::5/128 -p tcp -m tcp --dport 80 -m conntrack --ctstate DNAT"' \
	"and the same for the IPv6 forward"
out="$("$DUAL" apply nat)"
T '[ "$(iptables -t nat -S STOCKFW-DNAT | grep -c -- "-j DNAT")" = 1 ] && [ "$(iptables -t nat -S PREROUTING | grep -c STOCKFW-DNAT)" = 1 ]' \
	"re-applying router mode duplicates nothing in nat"

# ------------- leaving router mode, IPv6 refused: IPv4 nat comes back hooked
before4="$(iptables -S; iptables -t nat -S)"; before6="$(ip6tables -S; ip6tables -t nat -S)"
out="$(PATH="$BUILD_DIR/failbin:$PATH" "$DUAL" apply)"
T 'grep -q "^RESULT Failed.*IPv4 was put back" <<<"$out"' \
	"leaving router mode with IPv6 refused fails -- got [$out]"
T 'iptables -t nat -C PREROUTING -j STOCKFW-DNAT && iptables -t nat -C POSTROUTING -j STOCKFW-SNAT' \
	"IPv4's nat chains are hooked in again, not just refilled"
T '[ "$(iptables -S; iptables -t nat -S)" = "$before4" ] && [ "$(ip6tables -S; ip6tables -t nat -S)" = "$before6" ]' \
	"both families are exactly as they were"

# ------------------------------- rollback restores router mode, hooks too
before4="$(iptables -S; iptables -t nat -S)"; before6="$(ip6tables -S; ip6tables -t nat -S)"
real6="$(command -v ip6tables-restore)"
cat > "$BUILD_DIR/fakebin/ip6tables-restore" <<FAKE
#!/bin/bash
# Accepts filter payloads, refuses everything else (the nat step).
input="\$(cat)"
if grep -q '^\*filter' <<<"\$input"; then
	exec "$real6" "\$@" <<<"\$input"
fi
echo "ip6tables-restore: injected nat failure" >&2
exit 1
FAKE
chmod +x "$BUILD_DIR/fakebin/ip6tables-restore"
out="$(PATH="$BUILD_DIR/fakebin:$PATH" "$DUAL" apply nat extra)"
T 'grep -q "^RESULT Failed.*injected nat failure" <<<"$out"' \
	"an IPv6 failure after its filter table changed fails the apply -- got [$out]"
T '[ "$(iptables -S; iptables -t nat -S)" = "$before4" ]' \
	"IPv4 is exactly as it was (router mode, nat chains and hooks)"
T '[ "$(ip6tables -S; ip6tables -t nat -S)" = "$before6" ]' \
	"IPv6's filter table, already replaced, was put back too"

# ------------- IPv6 cannot even be put back: IPv4 is still rolled back
# The first payload (the new IPv6 filter table) is accepted; every later
# one is refused, the nat step and the rollback alike.  IPv6 is left
# half-changed and the error says so; IPv4 must still be put back.
# Teeth: `back6 && back4' written as one && expression skips IPv4 here.
before4="$(iptables -S; iptables -t nat -S)"
mkdir -p "$BUILD_DIR/once6bin"
cat > "$BUILD_DIR/once6bin/ip6tables-restore" <<FAKE
#!/bin/bash
input="\$(cat)"
n=\$(( \$(cat "$BUILD_DIR/once6.count" 2>/dev/null || echo 0) + 1 ))
echo "\$n" > "$BUILD_DIR/once6.count"
if [ "\$n" = 1 ]; then
	exec "$real6" "\$@" <<<"\$input"
fi
echo "ip6tables-restore: injected failure \$n" >&2
exit 1
FAKE
chmod +x "$BUILD_DIR/once6bin/ip6tables-restore"
rm -f "$BUILD_DIR/once6.count"
out="$(PATH="$BUILD_DIR/once6bin:$PATH" "$DUAL" apply nat extra)"
T 'grep -q "^RESULT Failed.*IPv6 rules were refused.*Putting the previous rules back also failed" <<<"$out"' \
	"when IPv6 cannot be put back, the error says so instead of \"nothing changed\" -- got [$out]"
T '[ "$(iptables -S; iptables -t nat -S)" = "$before4" ]' \
	"IPv4 is still put back exactly as it was"
out="$("$DUAL" apply nat)"
T '[ "${out%% |*}" = "$APPLIED" ]' \
	"and the next apply brings IPv6 back in line -- got [$out]"

# -------------------------------------------------- back out of router mode
out="$("$DUAL" apply nolog)"
T '[ "${out%% |*}" = "$APPLIED" ]' "leaving router mode, logging off -- got [$out]"
T '! iptables -t nat -n -L STOCKFW-DNAT >/dev/null 2>&1 && ! ip6tables -t nat -n -L STOCKFW-DNAT >/dev/null 2>&1' \
	"the nat chains go when nothing uses them"
T '! iptables -t nat -S PREROUTING | grep -q STOCKFW && ! iptables -t nat -S POSTROUTING | grep -q STOCKFW' \
	"and so do their hooks"
T '! ip6tables -C FORWARD -j INBOUND 2>/dev/null' "the IPv6 FORWARD hook goes too"
T '! iptables -n -L ACCEPT_LOG >/dev/null 2>&1 && ! ip6tables -n -L ACCEPT_LOG >/dev/null 2>&1' \
	"with logging of allowed connections off, ACCEPT_LOG is removed in both families"

# ------------------- rollback when entering router mode removes the hook
before4="$(iptables -S; iptables -t nat -S)"; before6="$(ip6tables -S; ip6tables -t nat -S)"
out="$(PATH="$BUILD_DIR/fakebin:$PATH" "$DUAL" apply nat)"
T 'grep -q "^RESULT Failed.*injected nat failure" <<<"$out"' \
	"entering router mode with a refused IPv6 nat table fails -- got [$out]"
T '! ip6tables -C FORWARD -j INBOUND 2>/dev/null' \
	"the IPv6 FORWARD hook the failed apply added is taken out again"
T '[ "$(iptables -S; iptables -t nat -S)" = "$before4" ] && [ "$(ip6tables -S; ip6tables -t nat -S)" = "$before6" ]' \
	"both families are exactly as they were"

# ------------------------------------------- a host without ip6tables
mkdir -p "$BUILD_DIR/v4bin"
for tool in iptables iptables-restore iptables-save; do
	ln -s "$(command -v $tool)" "$BUILD_DIR/v4bin/$tool"
done
out="$(PATH="$BUILD_DIR/v4bin:/usr/bin:/bin" "$DUAL" apply)"
T '[ "${out%% |*}" = "$APPLIED" ]' \
	"without ip6tables the apply still succeeds for IPv4 -- got [$out]"
T 'grep -q "| NOTES IPv6 is not filtered: ip6tables is not installed" <<<"$out"' \
	"and says IPv6 is not filtered"
out="$(PATH="$BUILD_DIR/v4bin:/usr/bin:/bin" "$DUAL" state)"
T 'grep -q "^IPV6 not-filtered.*ip6tables is not installed" <<<"$out"' \
	"ipv6_state says the same -- got [$out]"
out="$("$DUAL" apply nolog)"

# ------------------------------------------------------------------ state
out="$("$DUAL" state)"
T 'grep -q "^IPV6 filtered" <<<"$out"' "ipv6_state: filtered -- got [$out]"
out="$(env -u STOCKFW_ASSUME_IPV6 "$DUAL" state)"
if [ -e /proc/net/if_inet6 ]; then
	T 'grep -q "^IPV6 filtered" <<<"$out"' "ipv6_state without the hook: filtered -- got [$out]"
else
	T 'grep -q "^IPV6 absent" <<<"$out"' \
		"ipv6_state on a kernel without IPv6: absent -- got [$out]"
fi
ip6tables -D INPUT -j INBOUND
out="$("$DUAL" state)"
T 'grep -q "^IPV6 not-filtered.*not in use" <<<"$out"' \
	"rules loaded but unhooked: not filtered, and says so -- got [$out]"

# -------------------------------------------------------------------- stop
out="$("$DUAL" stop)"
T '[ "$out" = "STOP ok" ]' "stop succeeds -- got [$out]"
for t in iptables ip6tables; do
	T '! $t -n -L INBOUND >/dev/null 2>&1 && ! $t -n -L OUTBOUND >/dev/null 2>&1' \
		"$t: INBOUND and OUTBOUND removed"
	T '! $t -S | grep -q -- "-j INBOUND\|-j OUTBOUND"' "$t: no hook left"
	T '$t -C INPUT -j TEST_FOREIGN && [ "$($t -S TEST_FOREIGN | wc -l)" = 2 ]' \
		"$t: someone else's chain and hook survive"
done
out="$("$DUAL" state)"
T 'grep -q "^IPV6 not-filtered.*stopped" <<<"$out"' \
	"after stop: not filtered, firewall stopped -- got [$out]"

# ------------- starting from stopped: one unresolvable block is not fatal
out="$("$DUAL" apply badhost)"
T '[ "${out%% |*}" = "$APPLIED" ]' \
	"from stopped, a block whose name cannot be looked up does not keep the whole firewall down -- got [$out]"
T 'grep -q "| NOTES .*NOT BLOCKED: broken.test could not be looked up" <<<"$out"' \
	"and the notes say it is NOT BLOCKED"
T 'iptables -C INPUT -j INBOUND && ip6tables -C INPUT -j INBOUND && iptables -C OUTBOUND -d 192.0.2.66/32 -j DROP' \
	"everything else is in force, in both families"
out="$("$DUAL" stop)"
T '[ "$out" = "STOP ok" ] && ! iptables -n -L INBOUND >/dev/null 2>&1' "and stops cleanly"

echo ""
if [ "$failures" -eq 0 ]; then echo "PASSED: 0 failure(s)"; else echo "FAILED: $failures failure(s)"; fi
exit $((failures > 0))

