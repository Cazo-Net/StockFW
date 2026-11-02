#!/bin/bash
# What the boot service does, live: installer/linux/stockfw.service runs
# `stockfw start' before the network is up.  This runs that same command
# against a scratch policy in a private network namespace and reads
# back what the kernel was given.
#
# What it proves:
#   - the unit file is what the boot needs: oneshot, stays "active",
#     ordered before network-pre.target, no ExecStop (stopping the unit
#     or shutting down never takes the rules away), and a no-op until a
#     policy has been applied once (systemd-analyze verify, when there);
#   - `stockfw start' installs the saved policy: the user's block is in
#     the kernel;
#   - a Sentinel block whose ten minutes ran out while the machine was
#     off is NOT installed again, and leaves the policy file;
#   - in audit-only mode the last APPLIED policy is started, not the
#     file with its held changes;
#   - a block by host name that cannot be looked up (no network yet)
#     does not stop the start: the rest goes in, and the output says
#     which block was left out.
#
# Needs root, iptables and unshare (SKIP otherwise).

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
BUILD="${STOCKFW_BUILD:-$PORT/build-linux}"
CLI="$BUILD/stockfw"
UNIT="$PORT/installer/linux/stockfw.service"

failures=0
ok ()   { echo "ok:   $*"; }
fail () { echo "FAIL: $*"; failures=$((failures + 1)); }
check () { local what="$1"; shift; if "$@"; then ok "$what"; else fail "$what"; fi; }

# ---------------------------------------------------------------- 1. the unit
if [ "${STOCKFW_BOOT_IN_NETNS:-}" != "1" ]; then
	unit_has () { grep -qx "$1" "$UNIT"; }
	check "unit: runs stockfw start once" unit_has "ExecStart=/usr/local/bin/stockfw start"
	check "unit: Type=oneshot" unit_has "Type=oneshot"
	check "unit: stays active after it ran (RemainAfterExit=yes)" unit_has "RemainAfterExit=yes"
	check "unit: before the network is brought up" unit_has "Before=network-pre.target shutdown.target"
	check "unit: pulls network-pre.target in" unit_has "Wants=network-pre.target"
	check "unit: no default dependencies (runs early)" unit_has "DefaultDependencies=no"
	check "unit: nothing to do until a policy was applied" \
		unit_has "ConditionPathExists=/etc/stockfw/applied.csv"
	check "unit: no ExecStop -- stopping it never takes the rules away" \
		bash -c "! grep -q '^ExecStop' '$UNIT'"
	if command -v systemd-analyze >/dev/null 2>&1 && [ -x "$CLI" ]; then
		VDIR="$(mktemp -d)"
		sed "s|/usr/local/bin/stockfw|$CLI|" "$UNIT" > "$VDIR/stockfw.service"
		out="$(systemd-analyze verify "$VDIR/stockfw.service" 2>&1)"
		check "unit: systemd-analyze verify is clean ($out)" [ -z "$out" ]
		rm -rf "$VDIR"
	else
		echo "SKIP: systemd-analyze not installed"
	fi
fi

# ---------------------------------------------------------------- live part
if [ "$(id -u)" -ne 0 ] || ! command -v iptables >/dev/null 2>&1 ||
   ! command -v unshare >/dev/null 2>&1 || [ ! -x "$CLI" ]; then
	echo "SKIP: the live start needs root, iptables, unshare and $CLI"
	echo
	[ "$failures" -eq 0 ] && echo "PASSED: 0 failure(s)" || echo "FAILED: $failures failure(s)"
	exit $(( failures > 0 ))
fi

if [ "${STOCKFW_BOOT_IN_NETNS:-}" != "1" ]; then
	# A private network namespace: the rules never reach the host.
	env STOCKFW_BOOT_IN_NETNS=1 unshare -n bash "$0" "$@"
	rc=$?
	[ "$failures" -eq 0 ] && exit $rc
	echo "FAILED: $failures failure(s) in the unit checks"
	exit 1
fi

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
export HOME="$SCRATCH/home"
export XDG_CONFIG_HOME="$SCRATCH/config"
export STOCKFW_RULES_DIR="$SCRATCH/rules"
export STOCKFW_AUDIT_FILE="$SCRATCH/audit.log"
export STOCKFW_APPLIED_FILE="$SCRATCH/applied.csv"
export STOCKFW_AUTOBLOCK_FILE="$SCRATCH/autoblocks"
mkdir -p "$HOME" "$XDG_CONFIG_HOME/stockfw" "$STOCKFW_RULES_DIR"

ipt () { iptables -S 2>/dev/null; }
in_kernel () { ipt | grep -q -- "$1"; }

# A user's block, and a Sentinel block staged two hours ago.
"$CLI" policy add outbound-deny-to 203.0.113.9 --comment "user block" > /dev/null
"$CLI" policy add outbound-deny-to 203.0.113.10 --comment "Sentinel: old beacon" > /dev/null
OLD=$(( $(date +%s) - 7200 ))
# 6 = FS_RULE_OUTBOUND_DENY_TO; the row is the rule's CSV, comment last.
printf 'S,%s,6,203.0.113.10, Sentinel: old beacon\n' "$OLD" > "$STOCKFW_AUTOBLOCK_FILE"
# A host name nobody can look up in here (no network at all).
"$CLI" policy add outbound-deny-to blocked.invalid --comment "by name" > /dev/null 2>&1

# ---------------------------------------------------------------- 2. boot start
"$CLI" start > "$SCRATCH/start.log" 2>&1
rc=$?
check "stockfw start at boot succeeds (rc=$rc: $(tr '\n' ' ' < "$SCRATCH/start.log"))" [ "$rc" -eq 0 ]
check "the user's block is in the kernel" in_kernel "203.0.113.9"
check "the expired Sentinel block is NOT installed again" bash -c "! iptables -S | grep -q 203.0.113.10"
check "...and has left the policy file" bash -c "! grep -rq 203.0.113.10 '$STOCKFW_RULES_DIR'"
check "...and the state file" bash -c "! grep -q 203.0.113.10 '$STOCKFW_AUTOBLOCK_FILE'"
grep -qi "blocked.invalid" "$SCRATCH/start.log" &&
	ok "a block by a name that cannot be looked up is named in the output" ||
	fail "a block by a name that cannot be looked up is named in the output"
check "the start is journalled (the next boot's restore point)" [ -s "$STOCKFW_APPLIED_FILE" ]
grep -q "firewall started" "$STOCKFW_AUDIT_FILE" 2>/dev/null &&
	ok "the start is on the audit record" || fail "the start is on the audit record"

# ---------------------------------------------------------------- 3. audit-only
# Flush, as a reboot would; add a change while audit-only is on.
"$CLI" stop > /dev/null 2>&1
check "(setup) the firewall is stopped" bash -c "! iptables -S | grep -q 203.0.113.9"
printf '[client]\npolicy_audit_only=true\n' > "$XDG_CONFIG_HOME/stockfw/stockfw.conf"
"$CLI" policy add outbound-deny-to 198.51.100.77 --comment "held change" > /dev/null 2>&1
"$CLI" start > "$SCRATCH/held.log" 2>&1
rc=$?
check "audit-only: stockfw start succeeds (rc=$rc)" [ "$rc" -eq 0 ]
check "audit-only: the last applied policy is back" in_kernel "203.0.113.9"
check "audit-only: the held change is NOT in the kernel" bash -c "! iptables -S | grep -q 198.51.100.77"
grep -qi "held" "$SCRATCH/held.log" &&
	ok "audit-only: the output says the changes stay held" ||
	fail "audit-only: the output says the changes stay held ($(cat "$SCRATCH/held.log"))"

"$CLI" stop > /dev/null 2>&1

echo
if [ "$failures" -eq 0 ]; then
	echo "PASSED: 0 failure(s)"
else
	echo "FAILED: $failures failure(s)"
fi
exit $(( failures > 0 ))
