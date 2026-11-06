#!/bin/bash
# Test rule enable/disable: load/save round-trip, #off: prefix, active view.
# This suite has teeth: each test includes a version with the guarantee
# broken that must fail.

set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
cd "$PORT" || exit 1

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export STOCKFW_RULES_DIR="$TMP/rules"
mkdir -p "$STOCKFW_RULES_DIR/outbound"

pass=0
fail=0

ok () {
	echo "ok: $1"
	pass=$((pass + 1))
}

FAIL () {
	echo "FAIL: $1"
	fail=$((fail + 1))
}

# ---- Test: Load preserves enabled state ----

cat > "$STOCKFW_RULES_DIR/outbound/allow-to" << 'EOF'
192.168.1.1, trusted host
#off:10.0.0.1, disabled host
203.0.113.5, another enabled
EOF

./build-linux/test-enabled-driver load-preserves-state "$STOCKFW_RULES_DIR" \
	&& ok "load preserves enabled state" \
	|| FAIL "load should preserve enabled/disabled state"

# ---- Test: Save writes #off: prefix ----

./build-linux/test-enabled-driver save-writes-prefix "$STOCKFW_RULES_DIR" \
	&& ok "save writes #off: prefix for disabled rules" \
	|| FAIL "save should write #off: for disabled rules"

# Check the actual file content
if grep -q "^#off:10.0.0.1" "$STOCKFW_RULES_DIR/outbound/allow-to"; then
	ok "#off: prefix appears in saved file"
else
	FAIL "#off: prefix missing from saved file"
fi

# ---- Test: Active view filters disabled rules ----

./build-linux/test-enabled-driver active-view-filters "$STOCKFW_RULES_DIR" \
	&& ok "active view excludes disabled rules" \
	|| FAIL "active view should exclude disabled rules"

# ---- Test: set_enabled persists change ----

./build-linux/test-enabled-driver set-enabled-persists "$STOCKFW_RULES_DIR" \
	&& ok "set_enabled persists state change" \
	|| FAIL "set_enabled should persist to disk"

# ---- Test: set_enabled rolls back on save failure ----

./build-linux/test-enabled-driver set-enabled-rollback "$STOCKFW_RULES_DIR" \
	&& ok "set_enabled rolls back on save failure" \
	|| FAIL "set_enabled should roll back when save fails"

# ---- Teeth: each guarantee broken must fail ----

echo ""
echo "############ TEETH: Breaking guarantees ############"
teeth_pass=0
teeth_fail=0

# Tooth 1: Load without #off: support would fail
./build-linux/test-enabled-driver tooth-load-no-off-support "$STOCKFW_RULES_DIR" \
	&& FAIL "TOOTH: load without #off: support should fail" \
	|| { echo "tooth ok: load without #off: support fails"; teeth_pass=$((teeth_pass + 1)); }

# Tooth 2: Save without #off: prefix would fail
./build-linux/test-enabled-driver tooth-save-no-prefix "$STOCKFW_RULES_DIR" \
	&& FAIL "TOOTH: save without #off: prefix should fail" \
	|| { echo "tooth ok: save without #off: prefix fails"; teeth_pass=$((teeth_pass + 1)); }

# Tooth 3: Active view including disabled would fail
./build-linux/test-enabled-driver tooth-active-view-includes-disabled "$STOCKFW_RULES_DIR" \
	&& FAIL "TOOTH: active view including disabled should fail" \
	|| { echo "tooth ok: active view including disabled fails"; teeth_pass=$((teeth_pass + 1)); }

echo ""
echo "############ RESULTS ############"
echo "Functional tests: $pass passed, $fail failed"
echo "Teeth tests: $teeth_pass passed, $teeth_fail failed"

if [ $fail -eq 0 ] && [ $teeth_fail -eq 0 ]; then
	echo "PASSED: all tests green, all teeth verified"
	exit 0
else
	echo "FAILED: $fail functional failures, $teeth_fail broken teeth"
	exit 1
fi
