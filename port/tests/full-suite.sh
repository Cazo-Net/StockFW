#!/bin/bash
# Canonical test runner: every suite in one pass, one binary verdict.
# Every section reports its own exit code; the script exits non-zero
# if anything failed.
#
#   cd port && bash tests/full-suite.sh
#
# Windows (MSYS2/UCRT64): every suite including the UI smokes.
# The build directory must already exist
# (cmake -S . -B build -G Ninja).

export PATH="/ucrt64/bin:$PATH"

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
cd "$PORT" || exit 1

TMP="$(mktemp -d)"
# A test child can still hold one of the scratch files for a moment;
# failing to remove the scratch dir must not turn a green run red.
trap 'rm -rf "$TMP" 2>/dev/null || true' EXIT
fails=0

section () {
  echo ""
  echo "############ $1 ############"
}

run_sh () {   # run_sh <label> <script> [pattern]
  local label="$1" script="$2" pattern="${3:-PASSED|FAILED|PASSED:|tests run|failure}"
  local rc=0
  section "$label"
  bash "$script" > "$TMP/last-suite.txt" 2>&1 || rc=$?
  grep -E "$pattern" "$TMP/last-suite.txt" | tail -6
  echo "exit=$rc  (ok checks: $(grep -c '^ok:' "$TMP/last-suite.txt"))"
  grep "^FAIL" "$TMP/last-suite.txt" | head -10
  [ "$rc" -eq 0 ] || fails=$((fails+1))
}

run_sh "CORE"        tests/test-core.sh
run_sh "LOG START"   tests/test-logstart.sh
run_sh "WINLOG + SPAWN PROBE" tests/test-winlog.sh
run_sh "INSTALLER SPAWN" tests/test-installer-spawn.sh
run_sh "BACKEND COMPILE (state-windows)" tests/test-state-windows.sh "compiled|PASSED|FAILED|ok:"
run_sh "UAF ANALYZE" tests/test-uaf-analyze.sh

section "UI SMOKE TARGETS"
rc=0
ninja -C build fs-ui-smoke fs-hitview-smoke fs-simviz-smoke fs-theme-smoke > "$TMP/last-ninja.txt" 2>&1 || rc=$?
echo "ninja exit=$rc"
grep "error:" "$TMP/last-ninja.txt" | head -5
[ "$rc" -eq 0 ] || fails=$((fails+1))

for exe in fs-ui-smoke fs-hitview-smoke fs-simviz-smoke fs-theme-smoke; do
  rc=0
  "./build/$exe" > "$TMP/last-suite.txt" 2>&1 || rc=$?
  echo "--- $exe exit=$rc"
  grep -E "PASSED|FAILED|^[0-9]+ ?failure|^FAIL" "$TMP/last-suite.txt" | tail -8
  [ "$rc" -eq 0 ] || fails=$((fails+1))
done

section "SUMMARY"
if [ "$fails" -eq 0 ]; then
  echo "ALL SUITES PASSED"
else
  echo "$fails suite(s) FAILED"
fi
exit "$fails"
