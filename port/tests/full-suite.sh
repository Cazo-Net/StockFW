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
run_sh "P4 ADVERSARIAL" tests/test-adversarial.sh
run_sh "LOG START"   tests/test-logstart.sh
run_sh "LOG EVENTS (file)" tests/test-logstart-events.sh
run_sh "LOG EVENTS (/dev/kmsg)" tests/test-logstart-kmsg.sh
run_sh "WINLOG + SPAWN PROBE" tests/test-winlog.sh
run_sh "INSTALLER SPAWN" tests/test-installer-spawn.sh
run_sh "STAGED RUNTIME (build/ on its own)" tests/test-staged-runtime.sh "PASSED|FAILED|SKIP"
run_sh "BACKEND COMPILE (state-windows)" tests/test-state-windows.sh "compiled|PASSED|FAILED|ok:"
run_sh "UAF ANALYZE" tests/test-uaf-analyze.sh
run_sh "CLI + DASHBOARD (Linux)" tests/test-cli.sh
# Linux with a display (xvfb-run); prints SKIP elsewhere.
run_sh "SINGLE INSTANCE + BACKGROUND (Linux, real binary)" tests/test-instance.sh "PASSED|FAILED|SKIP"
# Linux only, and only as root; both print SKIP elsewhere.
run_sh "APPLY (Linux, live iptables)" tests/test-apply-linux.sh "PASSED|FAILED|SKIP"
run_sh "APPLY DUAL-STACK (Linux, IPv4 + IPv6, private netns)" tests/test-apply-dual.sh "PASSED|FAILED|SKIP"
run_sh "WHAT-IF vs KERNEL (Linux, private netns)" tests/test-whatif-live.sh "PASSED|FAILED|SKIP"
# Start at sign-in (XDG entry; the sudo half as root), the boot unit and
# `stockfw start' live in a private netns (root), the Linux installer in
# a private mount namespace (root).
run_sh "START AT SIGN-IN (Linux, real binary)" tests/test-autostart.sh "PASSED|FAILED|SKIP"
run_sh "BOOT START (unit + stockfw start, private netns)" tests/test-boot-start.sh "PASSED|FAILED|SKIP"
run_sh "LINUX INSTALLER (boot unit, private mount ns)" tests/test-linux-install.sh "PASSED|FAILED|SKIP"

section "UI SMOKE TARGETS"
rc=0
ninja -C build fs-ui-smoke fs-prefs-fake-smoke fs-hitview-smoke fs-simviz-smoke fs-theme-smoke fs-trustview-smoke fs-tray-smoke fs-copilot-smoke fs-statusview-smoke fs-activity-smoke fs-startup-smoke fs-traymenu-smoke fs-session-smoke > "$TMP/last-ninja.txt" 2>&1 || rc=$?
echo "ninja exit=$rc"
grep "error:" "$TMP/last-ninja.txt" | head -5
[ "$rc" -eq 0 ] || fails=$((fails+1))

for exe in fs-ui-smoke fs-prefs-fake-smoke fs-hitview-smoke fs-simviz-smoke fs-theme-smoke fs-trustview-smoke fs-tray-smoke fs-copilot-smoke fs-statusview-smoke fs-activity-smoke fs-startup-smoke fs-traymenu-smoke fs-session-smoke; do
  rc=0
  "./build/$exe" > "$TMP/last-suite.txt" 2>&1 || rc=$?
  echo "--- $exe exit=$rc"
  grep -E "PASSED|FAILED|^[0-9]+ ?failure|^FAIL" "$TMP/last-suite.txt" | tail -8
  # A smoke that fails on a GLib or GTK warning only reports how many it
  # saw; the warnings themselves are in its output, so show them.
  [ "$rc" -eq 0 ] || grep -E -A1 "(WARNING|CRITICAL) \*\*" "$TMP/last-suite.txt" | head -12
  [ "$rc" -eq 0 ] || fails=$((fails+1))
done

section "SUMMARY"
if [ "$fails" -eq 0 ]; then
  echo "ALL SUITES PASSED"
else
  echo "$fails suite(s) FAILED"
fi
exit "$fails"
