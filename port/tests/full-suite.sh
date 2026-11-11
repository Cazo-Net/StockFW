#!/bin/bash
# Canonical test runner: every suite in one pass, one binary verdict.
# Every section reports its own exit code; the script exits non-zero
# if anything failed.
#
#   cd port && bash tests/full-suite.sh                 # Windows (MSYS2)
#   cd port && sudo xvfb-run -a bash tests/full-suite.sh  # Linux
#
# One build directory for every suite: build/ on Windows (MSYS2/UCRT64),
# build-linux/ on Linux, or $STOCKFW_BUILD on either.  It is configured
# (cmake -G Ninja) if it does not exist yet, and every target the suites
# run is built into it first.  STOCKFW_BUILD is exported, so each suite
# below that reads a build (the CLI, the apply and intel drivers, the
# installer test, the UI smokes) reads this one.
#
# Platform: a suite that belongs to the other platform prints SKIP and
# passes.  On Linux the live suites (apply, nft, threat intel, fetch,
# the installer, boot start) need root, and each runs in a private
# network or mount namespace; as another user they print SKIP.  The UI
# smokes and test-instance.sh need a display: run under xvfb-run -a.
# fs-tray-smoke needs a notification area, which a bare X server does
# not have, so it runs on Windows only (as in CI); STOCKFW_TRAY_SMOKE=1
# runs it on Linux too, for a desktop session that has one.
# FUZZ_SECONDS (default 30 here) is how long test-geodb.sh's fuzzer runs.

export PATH="/ucrt64/bin:$PATH"

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
cd "$PORT" || exit 1

if [ "${OS:-}" = "Windows_NT" ] || [ -d /ucrt64 ]; then
  WINDOWS=1
  BUILD="${STOCKFW_BUILD:-$PORT/build}"
  EXE=.exe
else
  WINDOWS=0
  BUILD="${STOCKFW_BUILD:-$PORT/build-linux}"
  EXE=
fi
case "$BUILD" in /*) ;; *) BUILD="$PORT/$BUILD" ;; esac
export STOCKFW_BUILD="$BUILD"
export FUZZ_SECONDS="${FUZZ_SECONDS:-30}"

TMP="$(mktemp -d)"
# A test child can still hold one of the scratch files for a moment;
# failing to remove the scratch dir must not turn a green run red.
trap 'rm -rf "$TMP" 2>/dev/null || true' EXIT
fails=0
verdicts=""

section () {
  echo ""
  echo "############ $1 ############"
}

verdict () {   # verdict <label> <PASS|FAIL|SKIP>
  verdicts="$verdicts$2  $1
"
}

# The tail a section prints is too short to diagnose a failure on a
# runner no one can log in to: a failing suite also prints its whole
# output (every FAIL line, compiler and linker errors, the command that
# died), in a foldable group on GitHub Actions.
full_output () {   # full_output <label> <what> <exit code> <file>
  echo "----- full output of $2 (exit $3) -----"
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::group::$1: full output"; fi
  cat "$4"
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::endgroup::"; fi
  echo "----- end of $2 -----"
}

# A suite that printed SKIP and exited 0 passed without running; the
# summary says SKIP for it, so a green verdict never hides one.
judge () {   # judge <label> <exit code> <output file> <what>
  if [ "$2" -ne 0 ]; then
    fails=$((fails+1))
    verdict "$1" FAIL
    full_output "$1" "$4" "$2" "$3"
  elif grep -q '^SKIP' "$3" && ! grep -q '^ok:' "$3"; then
    verdict "$1" SKIP
  else
    verdict "$1" PASS
  fi
}

run_sh () {   # run_sh <label> <script> [pattern]
  local label="$1" script="$2" pattern="${3:-PASSED|FAILED|PASSED:|tests run|failure|SKIP}"
  local rc=0
  section "$label"
  bash "$script" > "$TMP/last-suite.txt" 2>&1 || rc=$?
  grep -E "$pattern" "$TMP/last-suite.txt" | tail -6
  echo "exit=$rc  (ok checks: $(grep -c '^ok:' "$TMP/last-suite.txt"))"
  grep "^FAIL" "$TMP/last-suite.txt" | head -10
  judge "$label" "$rc" "$TMP/last-suite.txt" "$script"
}

run_bin () {   # run_bin <label> <target> [args...]
  local label="$1" target="$2" rc=0
  shift 2
  section "$label"
  if [ ! -x "$BUILD/$target$EXE" ]; then
    echo "FAIL: $BUILD/$target$EXE was not built"
    echo "not built" > "$TMP/last-suite.txt"
    judge "$label" 1 "$TMP/last-suite.txt" "$target"
    return
  fi
  "$BUILD/$target$EXE" "$@" > "$TMP/last-suite.txt" 2>&1 || rc=$?
  grep -E "PASSED|FAILED|checks|passed|failed|SKIP" "$TMP/last-suite.txt" | tail -4
  echo "exit=$rc  (ok checks: $(grep -c '^ok' "$TMP/last-suite.txt"))"
  grep "^FAIL" "$TMP/last-suite.txt" | head -10
  judge "$label" "$rc" "$TMP/last-suite.txt" "$target"
}

linux_only () {   # linux_only <label> <command...>
  if [ "$WINDOWS" -eq 1 ]; then
    section "$1"; echo "SKIP: Linux only"; verdict "$1" SKIP
  else
    "$2" "$1" "${@:3}"
  fi
}

windows_only () {
  if [ "$WINDOWS" -eq 0 ]; then
    section "$1"; echo "SKIP: Windows only"; verdict "$1" SKIP
  else
    "$2" "$1" "${@:3}"
  fi
}

# Threat intel on the real Windows Firewall (Round 3): the backend's
# blocklist rules applied, read back through INetFwRules, cleared.
# Prints SKIP in a shell that is not elevated, which fails instead when
# STOCKFW_REQUIRE_WINDOWS_INTEL=1 (the CI sets it).  Rules that cannot
# be read always fail.  This runs only on the CI's Windows runner, so
# on a failure its whole output is printed, unfiltered (the details --
# the rules that differ, an unexpected ACE -- go to stdout with the
# FAIL lines, indented under them).
run_intel_windows () {
  run_bin "$1" fs-intel-windows-test
}

# ------------------------------------------------------------- the build
# Unit binaries, Linux drivers for the live suites, the UI smokes,
# fs-intel-windows-test on Windows, and fs-backend-probe (the backend
# compiled on its own).
# fs-intel-test (POSIX modes on the store) and fs-fetch-test (the Linux
# curl argv, environment and account) are written for Linux; the
# location database reader runs on both inside test-core.sh.
UNITS="fs-txapply-test fs-netplace-test fs-feed-test fs-intelset-test fs-hostnet-test
       fs-fetch-spawn-test fs-fake-curl"
SMOKES="fs-ui-smoke fs-prefs-fake-smoke fs-hitview-smoke fs-simviz-smoke
        fs-theme-smoke fs-trustview-smoke fs-copilot-smoke
        fs-statusview-smoke fs-activity-smoke fs-overview-place-smoke
        fs-verdict-smoke fs-startup-smoke fs-traymenu-smoke fs-session-smoke fs-help-smoke
        fs-intelview-smoke fs-whatif-start-smoke fs-sentinel-test fs-topology-smoke"
if [ "$WINDOWS" -eq 1 ] || [ "${STOCKFW_TRAY_SMOKE:-}" = 1 ]; then
  SMOKES="$SMOKES fs-tray-smoke"
fi
if [ "$WINDOWS" -eq 1 ]; then
  EXTRA="fs-intel-windows-test"
else
  UNITS="$UNITS fs-intel-test fs-fetch-test fs-geodb-test"
  EXTRA="fs-nftset-load fs-intelset-driver fs-intel-backend-driver
         fs-intel-e2e-driver stockfw-intel-test"
fi

section "BUILD ($BUILD)"
rc=0
{
  if [ ! -f "$BUILD/build.ninja" ]; then
    cmake -S "$PORT" -B "$BUILD" -G Ninja || exit 1
  fi
  ninja -C "$BUILD" || exit 1
  # -k 0: one target that does not build must not hide the others;
  # each suite that needs it then fails on its own.
  # shellcheck disable=SC2086
  ninja -k 0 -C "$BUILD" $UNITS $SMOKES $EXTRA fs-backend-probe
} > "$TMP/last-ninja.txt" 2>&1 || rc=$?
echo "build exit=$rc"
grep -E "error:|FAILED:" "$TMP/last-ninja.txt" | head -10
judge "BUILD" "$rc" "$TMP/last-ninja.txt" "the build"

run_sh "CORE"        tests/test-core.sh
run_sh "POLICY IO"   tests/test-policyio.sh
run_sh "EVENT STORE + HISTORY" tests/test-eventstore.sh
run_sh "WINDOWS EVENT LOG READER (fake log, any platform)" tests/test-winevt.sh
run_sh "P4 ADVERSARIAL" tests/test-adversarial.sh
run_sh "LOG START"   tests/test-logstart.sh
# Linux, root: the log reader against a file and against /dev/kmsg.
run_sh "LOG EVENTS (file)" tests/test-logstart-events.sh
run_sh "LOG EVENTS (/dev/kmsg)" tests/test-logstart-kmsg.sh
run_sh "WINLOG + SPAWN PROBE" tests/test-winlog.sh
run_sh "INSTALLER SPAWN" tests/test-installer-spawn.sh
run_sh "LICENCE TEXTS (installers match About)" tests/test-licence-texts.sh
# The release checks and the analyser sweep have run on Linux only so
# far (CI's Linux job runs test-release.sh on the real tarball).
linux_only "RELEASE (versions, documents, modes, packages)" run_sh tests/test-release.sh
run_sh "STAGED RUNTIME (build/ on its own)" tests/test-staged-runtime.sh
run_sh "BACKEND COMPILE (state-windows)" tests/test-state-windows.sh "compiled|PASSED|FAILED|ok:|SKIP"
windows_only "TRANSACTIONAL WINDOWS APPLY (snapshot/rollback)" run_sh tests/test-apply-windows.sh
run_sh "UAF ANALYZE" tests/test-uaf-analyze.sh
linux_only "UAF SWEEP (every source file)" run_sh tests/test-uaf-all.sh

# Unit binaries of 1.0.7 threat intel (fs-hostnet-test reads the IP
# Helper tables on Windows and the kernel's on Linux).
run_bin "ADDRESS PLACES (fs-netplace-test)" fs-netplace-test
run_bin "FEED PARSERS (fs-feed-test)" fs-feed-test
run_bin "INTEL SET SCRIPT (fs-intelset-test)" fs-intelset-test
run_bin "WHAT A LIST MUST NEVER CUT (fs-hostnet-test)" fs-hostnet-test
linux_only "THREAT INTEL ENGINE (fs-intel-test)" run_bin fs-intel-test
linux_only "DOWNLOADER, PURE PARTS (fs-fetch-test golden)" run_bin fs-fetch-test golden
windows_only "THREAT INTEL (Windows Firewall rules)" run_intel_windows
# How the downloader starts curl, against a fake curl: on Windows, no
# console window (CREATE_NO_WINDOW).  SKIP as root on Linux, where curl
# runs as nobody (test-fetch.sh covers that).
run_bin "DOWNLOADER START (fs-fetch-spawn-test, fake curl)" fs-fetch-spawn-test

run_sh "CLI + DASHBOARD (Linux)" tests/test-cli.sh
run_sh "DASHBOARD HTTP SERVER (Linux)" tests/test-dashboard.sh
# The command-line tool built with FS_BUILD_GUI=OFF and GTK hidden from
# pkg-config: no GTK library in it.  A second configure and build.
linux_only "CLI WITHOUT GTK (FS_BUILD_GUI=OFF)" run_sh tests/test-nogui-build.sh
# Linux with a display (xvfb-run); prints SKIP elsewhere.
run_sh "SINGLE INSTANCE + BACKGROUND (Linux, real binary)" tests/test-instance.sh
# A desktop with no tray (Broadway standing in for Wayland and WSLg),
# and words the window app does not take; needs broadwayd for the first.
linux_only "NO TRAY DESKTOP + STRAY WORDS (Linux, real binary)" run_sh tests/test-notray.sh
# Linux only, and only as root; each prints SKIP elsewhere.
run_sh "APPLY (Linux, live iptables)" tests/test-apply-linux.sh
run_sh "APPLY DUAL-STACK (Linux, IPv4 + IPv6, private netns)" tests/test-apply-dual.sh
run_sh "WHAT-IF vs KERNEL (Linux, private netns)" tests/test-whatif-live.sh
run_sh "NFT SETS (Linux, private netns)" tests/test-nftset.sh
run_sh "INTEL SETS (Linux, nft, private netns)" tests/test-intelset.sh
run_sh "INTEL BACKEND (Linux, nft + iptables, private netns)" tests/test-intel-backend.sh
run_sh "INTEL END TO END (Linux, private namespaces)" tests/test-intel-e2e.sh
run_sh "STOCKFW INTEL CLI (Linux, private namespaces)" tests/test-intel-cli.sh
run_sh "DOWNLOADER (Linux, curl as nobody, private namespaces)" tests/test-fetch.sh
linux_only "LOCATION DATABASE vs LIBLOC + FUZZER (Linux)" run_sh tests/test-geodb.sh
# Start at sign-in (XDG entry; the sudo half as root), the boot unit and
# `stockfw start' live in a private netns (root), the Linux installer in
# a private mount namespace (root).
linux_only "START AT SIGN-IN (Linux, real binary)" run_sh tests/test-autostart.sh
run_sh "BOOT START (unit + stockfw start, private netns)" tests/test-boot-start.sh
run_sh "LINUX INSTALLER (boot unit, private mount ns)" tests/test-linux-install.sh

for exe in $SMOKES; do
  run_bin "UI SMOKE $exe" "$exe"
  # A smoke that fails on a GLib or GTK warning only reports how many it
  # saw; the warnings themselves are in its output, so show them.
  grep -E -A1 "(WARNING|CRITICAL) \*\*" "$TMP/last-suite.txt" | head -12
done
if [ "$WINDOWS" -eq 0 ] && [ "${STOCKFW_TRAY_SMOKE:-}" != 1 ]; then
  section "UI SMOKE fs-tray-smoke"
  echo "SKIP: needs a notification area; Windows runs it (STOCKFW_TRAY_SMOKE=1 to run it here)"
  verdict "UI SMOKE fs-tray-smoke" SKIP
fi

section "SUMMARY"
printf '%s' "$verdicts"
echo ""
if [ "$fails" -eq 0 ]; then
  echo "ALL SUITES PASSED ($(printf '%s' "$verdicts" | grep -c '^SKIP') skipped on this platform or account)"
else
  echo "$fails suite(s) FAILED"
fi
exit "$fails"
