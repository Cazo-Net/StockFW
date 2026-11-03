#!/bin/bash
# The installed copy must ship GLib's spawn helpers.  They are exec'd
# rather than linked, so no dependency scan sees them, and the *.dll
# glob in StockFW.nsi once silently skipped them: the app then failed
# every g_spawn with "Failed to execute helper program (No such file or
# directory)" -- empty Events page, no netsh -- while looking healthy.
#
# Checks the two places the helpers can go missing:
#   1. the staging directory (build_installer.sh copies them),
#   2. the .nsi wiring: an install File line for each, not marked
#      /nonfatal (a fatal line makes makensis fail instead of shipping
#      a broken installer), plus an uninstall Delete for each.
#
#   ./tests/test-installer-spawn.sh

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
NSI="$PORT/installer/nsis/StockFW.nsi"
STAGE="$PORT/installer/nsis/stage/gtk-runtime/bin"

failures=0
ok_case () {
  if [ "$1" -eq 0 ]; then
    echo "ok:   $2"
  else
    echo "FAIL: $2"
    failures=$((failures + 1))
  fi
}

[ -f "$NSI" ] || { echo "FAIL: StockFW.nsi exists"; exit 1; }
echo "ok:   StockFW.nsi exists"

for helper in gspawn-win64-helper.exe gspawn-win64-helper-console.exe; do
  # 1. Staged (only meaningful after a build; skip without failing).
  if [ -d "$STAGE" ]; then
    if [ -f "$STAGE/$helper" ]; then ok=0; else ok=1; fi
    ok_case "$ok" "$helper is staged for install"
  fi

  # 2a. Installed to $INSTDIR by a File line that is NOT /nonfatal.
  line=$(grep -F "File " "$NSI" | grep -F "$helper" || true)
  if [ -n "$line" ]; then ok=0; else ok=1; fi
  ok_case "$ok" ".nsi installs $helper"

  case "$line" in
    */nonfatal*) ok=1 ;;
    *) ok=0 ;;
  esac
  ok_case "$ok" ".nsi install of $helper is fatal (makensis fails if missing)"

  # 2b. Removed on uninstall, or the uninstaller leaves it behind.
  if grep -Fq "Delete \"\$INSTDIR\\$helper\"" "$NSI"; then ok=0; else ok=1; fi
  ok_case "$ok" ".nsi uninstaller deletes $helper"
done

echo ""
if [ "$failures" -gt 0 ]; then
  echo "FAILED: $failures failure(s)"
  exit 1
fi
echo "PASSED: 0 failure(s)"
