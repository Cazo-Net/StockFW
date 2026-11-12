#!/bin/bash
# Linux backend integration test: applies a policy through the real
# backend and then inspects the live iptables state.
#
# This is deliberately an *execution* test, not a text-comparison test:
# the earlier script tests only proved the generated text looked right,
# which is exactly how a firewall that never filtered anything stayed
# green.  Requires root (CAP_NET_ADMIN) and iptables.
#
#   sudo ./tests/test-apply-linux.sh

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
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

if [ "$(id -u)" -ne 0 ]; then
	echo "SKIP: this test needs root (iptables rules cannot be managed otherwise)"
	exit 0
fi

if ! command -v iptables >/dev/null 2>&1; then
	echo "SKIP: iptables not installed"
	exit 0
fi

# ---------------------------------------------------------------- harness
cat > "$BUILD_DIR/test-apply.c" <<'EOF'
#include <glib.h>
#include <stdio.h>
#include "core/fs-backend.h"
#include "core/fs-rules.h"
#include "core/fs-script.h"

/* Applies a small policy through the real backend so the test can then
 * inspect whatever the kernel actually received. */
int main (void)
{
	FsPolicy *policy = fs_policy_new ();
	FsSettings *settings = fs_settings_new ();
	GError *error = NULL;
	FsApplyResult result;
	FsRule *rule;

	settings->ext_device = g_strdup ("lo");
	settings->nat = FALSE;

	rule = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);
	rule->service = g_strdup ("SSH");
	rule->port = g_strdup ("22");
	rule->target = g_strdup ("192.168.1.0/24");
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	fs_backend_set_context (policy, settings);

	result = fs_backend ()->apply_rules (policy, &error);
	if (result != FS_APPLY_OK && result != FS_APPLY_PARTIAL) {
		fprintf (stderr, "apply_rules failed: %s\n",
		         error ? error->message : "(no error)");
		return 2;
	}
	g_clear_error (&error);

	/* Hand over to the shell half of the test. */
	printf ("APPLIED\n");
	fflush (stdout);

	/* Keep the process alive is not needed: rules live in the kernel. */
	fs_policy_free (policy);
	fs_settings_free (settings);
	return 0;
}
EOF

# Compile against the real backend.  Flags are split so that the
# libraries come last: the linker resolves left to right, and an
# archive listed before its dependants pulls nothing.
if [ -d /ucrt64/bin ]; then export PATH="/ucrt64/bin:$PATH"; fi

CF="$(pkg-config --cflags glib-2.0 gobject-2.0 gio-2.0)"
LF="$(pkg-config --libs glib-2.0 gobject-2.0 gio-2.0 liblzma libcrypto json-glib-1.0)"

gcc -o "$BUILD_DIR/test-apply" \
	-I "$PORT/src" $CF \
	"$BUILD_DIR/test-apply.c" \
	"$PORT/src/platform/linux/fs-backend-linux.c" \
	"${STOCKFW_BUILD:-$PORT/build-linux}/libfs-core.a" \
	$LF 2> "$BUILD_DIR/cc.log"

CHECK $? "test program compiles against the real Linux backend"
if [ ! -x "$BUILD_DIR/test-apply" ]; then
	cat "$BUILD_DIR/cc.log"
	echo "FAIL: cannot continue without a test binary"
	exit 1
fi

# ------------------------------------------------------- foreign rules
# Stand in for Docker/libvirt/ufw: something else's rules that our
# apply and stop must never touch.
iptables -N TEST_FOREIGN 2>/dev/null
iptables -F TEST_FOREIGN
iptables -A TEST_FOREIGN -j RETURN
iptables -A INPUT -j TEST_FOREIGN 2>/dev/null
foreign_before="$(iptables -S TEST_FOREIGN | sort)"

# ---------------------------------------------------------------- apply
output="$("$BUILD_DIR/test-apply" 2>"$BUILD_DIR/apply.err")"
CHECK $([ "$output" = "APPLIED" ]; echo $?) "apply_rules returns OK"
[ "$output" = "APPLIED" ] || { echo "--- stdout ---"; echo "$output"; \
	echo "--- stderr ---"; cat "$BUILD_DIR/apply.err"; }

# -------------------------------------------------- chains are created
iptables -n -L INBOUND >/dev/null 2>&1
CHECK $? "INBOUND chain exists after apply"

iptables -n -L OUTBOUND >/dev/null 2>&1
CHECK $? "OUTBOUND chain exists after apply"

# ------------------------------------------- THE regression under test
# The chains must be jumped to from the built-ins, otherwise the kernel
# never consults them and nothing is filtered at all.
iptables -C INPUT -j INBOUND >/dev/null 2>&1
CHECK $? "INPUT is hooked to INBOUND (traffic actually filtered)"

iptables -C OUTPUT -j OUTBOUND >/dev/null 2>&1
CHECK $? "OUTPUT is hooked to OUTBOUND (traffic actually filtered)"

iptables -C FORWARD -j INBOUND >/dev/null 2>&1
CHECK $? "FORWARD is hooked to INBOUND (forwarded traffic filtered)"

# ------------------------------------------------ the policy is present
# Allowed connections are logged (1.0.7, on by default): a policy allow
# jumps to ACCEPT_LOG, which logs the first packet of a new connection
# (rate-limited) and accepts.
iptables -C INBOUND -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT_LOG >/dev/null 2>&1
CHECK $? "allow-SSH rule for 192.168.1.0/24 is installed (via ACCEPT_LOG)"

iptables -S ACCEPT_LOG 2>/dev/null | grep -q -- '--log-prefix "STOCKFW-ALLOW "'
CHECK $? "ACCEPT_LOG logs with the STOCKFW-ALLOW prefix"

iptables -S ACCEPT_LOG 2>/dev/null | tail -n 1 | grep -q -- '-A ACCEPT_LOG -j ACCEPT$'
CHECK $? "ACCEPT_LOG ends by accepting"

# Default action must still drop everything else.
iptables -S INBOUND | grep -q '\-j DROP'
CHECK $? "INBOUND ends with a default DROP"

# ------------------------------------------------ foreign rules intact
foreign_now="$(iptables -S TEST_FOREIGN | sort)"
CHECK $([ "$foreign_before" = "$foreign_now" ]; echo $?) \
	"unrelated rules (TEST_FOREIGN) survive apply"

iptables -C INPUT -j TEST_FOREIGN >/dev/null 2>&1
CHECK $? "unrelated jump from INPUT survives apply"

# ------------------------------------------- re-apply is not duplicating
for _ in 1 2; do "$BUILD_DIR/test-apply" >/dev/null 2>&1; done
dupes="$(iptables -S INPUT | grep -c -- '-j INBOUND')"
CHECK $([ "$dupes" = "1" ]; echo $?) \
	"re-applying does not stack duplicate jumps (got $dupes)"

# ------------------------------ root never runs a tool from its PATH
# `sudo -E' or a sudoers without secure_path hands root the user's PATH.
# Tools planted first on it must not run: as root the release backend
# takes iptables, ip6tables, their -save/-restore and nft from
# /usr/sbin, /usr/bin, /sbin or /bin only (1.0.7 release review,
# SECURITY-2).  Each fake records that it ran and claims success.
mkdir -p "$BUILD_DIR/planted"
for tool in iptables iptables-save iptables-restore ip6tables \
            ip6tables-save ip6tables-restore nft journalctl; do
	printf '#!/bin/sh\necho "%s $*" >> "%s/planted.log"\nexit 0\n' \
		"$tool" "$BUILD_DIR" > "$BUILD_DIR/planted/$tool"
	chmod 755 "$BUILD_DIR/planted/$tool"
done
iptables -F INBOUND
output="$(PATH="$BUILD_DIR/planted:$PATH" "$BUILD_DIR/test-apply" 2>/dev/null)"
CHECK $([ "$output" = "APPLIED" ]; echo $?) \
	"with tools planted first on PATH, the apply still succeeds ($output)"
CHECK $([ ! -e "$BUILD_DIR/planted.log" ]; echo $?) \
	"  ...and not one planted tool ran ($(head -c 120 "$BUILD_DIR/planted.log" 2>/dev/null))"
iptables -S INBOUND | grep -q '\-j DROP'
CHECK $? "  ...the real iptables-restore loaded the rules again"

# ----------------------------------------------------------------- stop
cat > "$BUILD_DIR/stop.c" <<'EOF'
#include <glib.h>
#include <stdio.h>
#include "core/fs-backend.h"
int main (void)
{
	GError *error = NULL;
	if (!fs_backend ()->stop (&error)) {
		fprintf (stderr, "stop failed: %s\n",
		         error ? error->message : "(no error)");
		return 1;
	}
	return 0;
}
EOF

gcc -o "$BUILD_DIR/stop" \
	-I "$PORT/src" $CF \
	"$BUILD_DIR/stop.c" \
	"$PORT/src/platform/linux/fs-backend-linux.c" \
	"${STOCKFW_BUILD:-$PORT/build-linux}/libfs-core.a" \
	$LF 2> "$BUILD_DIR/stop.log"

"$BUILD_DIR/stop" >/dev/null 2>"$BUILD_DIR/stop.err"
CHECK $? "backend stop() succeeds"
[ -s "$BUILD_DIR/stop.err" ] && { echo "--- stop stderr ---"; cat "$BUILD_DIR/stop.err"; }

iptables -n -L INBOUND >/dev/null 2>&1
CHECK $([ $? -ne 0 ]; echo $?) "INBOUND chain removed on stop"

iptables -n -L OUTBOUND >/dev/null 2>&1
CHECK $([ $? -ne 0 ]; echo $?) "OUTBOUND chain removed on stop"

iptables -n -L ACCEPT_LOG >/dev/null 2>&1
CHECK $([ $? -ne 0 ]; echo $?) "ACCEPT_LOG chain removed on stop"

iptables -C INPUT -j INBOUND >/dev/null 2>&1
CHECK $([ $? -ne 0 ]; echo $?) "INPUT jump removed on stop"

# ------------------------------------------------ foreign rules survive
iptables -C INPUT -j TEST_FOREIGN >/dev/null 2>&1
CHECK $? "unrelated rules survive stop (not flushed)"

# ----------------------------------------------------------------- clean
iptables -D INPUT -j TEST_FOREIGN 2>/dev/null
iptables -F TEST_FOREIGN 2>/dev/null
iptables -X TEST_FOREIGN 2>/dev/null

if [ "$failures" -eq 0 ]; then
	echo
	echo "PASSED: 0 failure(s)"
	exit 0
else
	echo
	echo "FAILED: $failures failure(s)"
	exit 1
fi

