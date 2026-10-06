#!/bin/bash
#---[ tools/stage-runtime-dlls.sh ]--------------------------------------
#
# Stage the MSYS2 runtime DLLs next to StockFW.exe.
#
# Windows resolves a program's dependencies from the directory holding
# the .exe.  An MSYS2 shell hides the problem because /ucrt64/bin is
# already on PATH, so the app starts there and nowhere else -- double
# clicking build/StockFW.exe, launching it from PowerShell, or the
# installed copy all die with a "StockFW.exe - System Error" dialog.
# The NSIS installer already stages DLLs into $INSTDIR for the same
# reason; this does the equivalent for the build directory.
#
# Only the DLLs StockFW actually imports are copied, taken from ldd's
# closure rather than all 270 MB of the toolchain.  Windows system DLLs
# are skipped: they come with the OS.
#
# Usage:
#   bash tools/stage-runtime-dlls.sh [builddir]     # default: build
#
#----------------------------------------------------------------------

set -e

if [ -d /ucrt64/bin ]; then
  export PATH="/ucrt64/bin:$PATH"
fi

PORT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${1:-$PORT/build}"

# Where the toolchain actually lives.  ldd reports it as /ucrt64/bin
# from inside MSYS2 and as /c/msys64/ucrt64/bin otherwise, so the
# directory is located rather than guessed.
TOOL_BIN=""
for cand in /ucrt64/bin /c/msys64/ucrt64/bin /mingw64/bin /clang64/bin; do
  if [ -f "$cand/libgtk-3-0.dll" ]; then
    TOOL_BIN="$cand"
    break
  fi
done

if [ -z "$TOOL_BIN" ]; then
  echo "stage-runtime-dlls: no GTK toolchain found" >&2
  exit 1
fi

TOOL_ROOT="$(dirname "$TOOL_BIN")"

# The build system may invoke this from a cmd.exe process whose PATH
# has no MSYS2 directories on it at all, in which case ldd cannot be
# found and the script would silently copy nothing.
export PATH="$TOOL_BIN:/usr/bin:$PATH"

if ! command -v ldd >/dev/null 2>&1; then
  echo "stage-runtime-dlls: ldd not found on PATH" >&2
  exit 1
fi

EXE="$BUILD/StockFW.exe"

if [ ! -f "$EXE" ]; then
  echo "stage-runtime-dlls: no $EXE -- build first" >&2
  exit 1
fi

# ldd's "name => path" layout is stable, the path spelling is not: it
# shows up as /ucrt64/bin, /c/msys64/ucrt64/bin or C:\msys64\...  depending
# on how the process was started.  Take the name and ask the toolchain
# whether it owns it -- a Windows system DLL simply will not be there.
deps=$(ldd "$EXE" 2>/dev/null \
  | sed -n 's/^[[:space:]]*\([^ ][^=]*\)[[:space:]]*=>.*/\1/p' \
  | sed 's/[[:space:]]*$//' \
  | sort -u)

copied=0
copied_list=""
for dll in $deps; do
  if [ -f "$TOOL_BIN/$dll" ]; then
    cp -f "$TOOL_BIN/$dll" "$BUILD/"
    copied=$((copied + 1))
    copied_list="$copied_list $dll"
  fi
done

# A zero here would leave the app unlaunchable while claiming success,
# so the libraries that make it a GTK program are checked by name.
if [ "$copied" -eq 0 ] || ! printf '%s' "$copied_list" | grep -q 'libgtk-3-0\.dll'; then
  echo "stage-runtime-dlls: did not find the GTK runtime" >&2
  echo "  ldd says: $(command -v ldd)" >&2
  echo "  copied:   $copied ($copied_list)" >&2
  ldd "$EXE" 2>&1 | head -6 >&2 || true
  exit 1
fi

echo "stage-runtime-dlls: $copied DLL(s) -> $BUILD"

# gdk-pixbuf/Pango/GTK read their module caches at run time, and the
# icon theme is looked up relative to the DLLs.  Without these the app
# starts but paints blank toolbar buttons.  The installer stages the
# same set for $INSTDIR.
#
# These directories are several MB, so they are copied only when the
# destination is missing -- this script runs after every build.
for mod in gdk-pixbuf-2.0 pango gtk-3.0; do
  src="$TOOL_ROOT/lib/$mod"
  if [ -d "$src" ] && [ ! -d "$BUILD/$mod" ]; then
    cp -r "$src" "$BUILD/"
  fi
done

if [ -d "$TOOL_ROOT/share" ]; then
  mkdir -p "$BUILD/share"
  for res in icons themes locales; do
    src="$TOOL_ROOT/share/$res"
    if [ -d "$src" ] && [ ! -d "$BUILD/share/$res" ]; then
      cp -r "$src" "$BUILD/share/$res"
    fi
  done
fi

exit 0
