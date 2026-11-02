#!/bin/bash
# build/StockFW.exe must work as a GTK program on its own.  The
# post-build step (tools/stage-runtime-dlls.sh) puts the GTK DLLs beside
# it; GTK and gdk-pixbuf then take build/ as their prefix and look for
# their module trees under build/lib.  While the script copied those
# trees to build/<name> instead, gdk-pixbuf found no loader cache and
# every SVG image failed, Adwaita's own radio-button bullet first:
#
#   Gtk-WARNING: Could not load a pixbuf from
#   /org/gtk/libgtk/theme/Adwaita/assets/bullet-symbolic.svg.
#
# Checks the staged layout, then runs a UI smoke from build/ with PATH
# cut down to Windows' own directories, as if it were started from
# Explorer, so that only what was staged can be found.
#
#   cd port && bash tests/test-staged-runtime.sh
#
# Windows (MSYS2) only; prints SKIP elsewhere.  Needs the build
# directory: cmake -S . -B build -G Ninja && cmake --build build

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
cd "$PORT" || exit 1

case "$(uname -s)" in
  MINGW*|MSYS*) ;;
  *) echo "SKIP: the staged runtime belongs to the Windows build"; exit 0 ;;
esac
if [ ! -f build/StockFW.exe ]; then
  echo "SKIP: build/StockFW.exe is not built (cmake --build build)"
  exit 0
fi

TOOL_BIN=""
for cand in /ucrt64/bin /c/msys64/ucrt64/bin /mingw64/bin /clang64/bin; do
  if [ -f "$cand/libgtk-3-0.dll" ]; then
    TOOL_BIN="$cand"
    break
  fi
done

failures=0
ok_case () {
  if [ "$1" -eq 0 ]; then
    echo "ok:   $2"
  else
    echo "FAIL: $2"
    failures=$((failures + 1))
  fi
}

loaders=build/lib/gdk-pixbuf-2.0/2.10.0
[ -f "$loaders/loaders.cache" ]
ok_case $? "gdk-pixbuf's loader cache is staged where GTK looks for it ($loaders)"
grep -q 'pixbufloader[-_]svg' "$loaders/loaders.cache" 2>/dev/null
ok_case $? "the cache lists the SVG loader"
svg="$(ls "$loaders"/loaders/*svg*.dll 2>/dev/null | head -1)"
[ -n "$svg" ]
ok_case $? "the SVG loader itself is staged"
[ ! -e build/gdk-pixbuf-2.0 ]
ok_case $? "no copy is left at the old, wrong place (build/gdk-pixbuf-2.0)"

# Every DLL the SVG loader imports from the toolchain sits beside the
# exe; Windows' own DLLs are not the toolchain's and are not checked.
missing=""
if [ -n "$svg" ] && [ -n "$TOOL_BIN" ]; then
  for name in $(objdump -p "$svg" 2>/dev/null \
                | sed -n 's/^[[:space:]]*DLL Name: //p' | tr -d '\r'); do
    if [ -f "$TOOL_BIN/$name" ] && [ ! -f "build/$name" ]; then
      missing="$missing $name"
    fi
  done
fi
[ -z "$missing" ]
ok_case $? "the SVG loader's own DLLs are staged too${missing:+ (missing:$missing)}"

# A UI smoke from build/, with nothing on PATH but Windows.
ninja -C build fs-activity-smoke > /dev/null 2>&1
sysroot="$(cygpath -u "${SYSTEMROOT:-C:\\Windows}")"
rc=0
out="$(PATH="$sysroot/System32:$sysroot" ./build/fs-activity-smoke.exe 2>&1)" || rc=$?
[ "$rc" -eq 0 ]
ok_case $? "a UI smoke runs from build/ with only Windows on PATH (exit $rc)"
if printf '%s\n' "$out" | grep -q -E '(WARNING|CRITICAL) \*\*'; then
  warned=1
else
  warned=0
fi
[ "$warned" -eq 0 ]
ok_case $? "and GTK has nothing to warn about: every image, SVG included, loads"
printf '%s\n' "$out" | grep -E -A1 '(WARNING|CRITICAL) \*\*' | head -6

if [ "$failures" -eq 0 ]; then
  echo "PASSED: 0 failure(s)"
  exit 0
fi
echo "FAILED: $failures failure(s)"
exit 1
