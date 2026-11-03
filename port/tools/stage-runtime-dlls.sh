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

# The location database reader (src/core/fs-geodb.c) needs liblzma and
# OpenSSL's libcrypto.  They are staged by name, not only when ldd sees
# them: the linker drops an unused object of a static library, so the
# closure above lists them only once the app calls the reader, and a
# build that started calling it must not ship without them.
geodb=0
for pattern in 'liblzma-*.dll' 'libcrypto-*-x64.dll'; do
  # shellcheck disable=SC2086
  found="$(cd "$TOOL_BIN" && ls $pattern 2>/dev/null | head -1)"
  if [ -z "$found" ]; then
    echo "stage-runtime-dlls: $pattern missing from $TOOL_BIN" >&2
    echo "  (pacman -S mingw-w64-ucrt-x86_64-xz mingw-w64-ucrt-x86_64-openssl)" >&2
    exit 1
  fi
  cp -f "$TOOL_BIN/$found" "$BUILD/"
  geodb=$((geodb + 1))
  # and what it imports from the toolchain (libcrypto: zlib, for one)
  for dep in $(objdump -p "$TOOL_BIN/$found" 2>/dev/null |
               sed -n 's/^[[:space:]]*DLL Name: //p' | tr -d '\r'); do
    if [ -f "$TOOL_BIN/$dep" ] && [ ! -f "$BUILD/$dep" ]; then
      cp -f "$TOOL_BIN/$dep" "$BUILD/"
    fi
  done
done
echo "stage-runtime-dlls: $geodb location database DLL(s) (xz, OpenSSL)"

# GLib does not call CreateProcess itself: it starts children through
# gspawn-win64-helper.exe, resolved like any other program -- the
# executable's own directory first, then PATH.  ldd can never report
# this file, because StockFW does not import it (it is exec'd, not
# linked), so the closure above deliberately does not cover it.
#
# Leaving it out does not stop the app from starting; it stops every
# g_spawn from working, with "Failed to execute helper program (No such
# file or directory)".  That is how an installed copy could show an
# empty Events page and refuse to run netsh while looking perfectly
# healthy, so a missing helper is an error here rather than a warning.
helpers=0
for helper in gspawn-win64-helper.exe gspawn-win64-helper-console.exe; do
  if [ -f "$TOOL_BIN/$helper" ]; then
    cp -f "$TOOL_BIN/$helper" "$BUILD/"
    helpers=$((helpers + 1))
  fi
done

if [ "$helpers" -eq 0 ]; then
  echo "stage-runtime-dlls: GLib spawn helper missing from $TOOL_BIN" >&2
  echo "  without it the app cannot run wevtutil.exe or netsh.exe at all" >&2
  exit 1
fi

echo "stage-runtime-dlls: $helpers spawn helper(s) staged"

# gdk-pixbuf/Pango/GTK read their module caches at run time, and the
# icon theme is looked up relative to the DLLs.  Without these the app
# starts but paints blank toolbar buttons.  The installer stages the
# same set for $INSTDIR.
#
# Where "relative to the DLLs" lands: each library takes the directory
# it was loaded from, minus a trailing bin/ or lib/, as its prefix.  The
# DLLs above sit directly in $BUILD, so the prefix is $BUILD itself and
# the module trees belong in $BUILD/lib -- the layout the installer
# gives $INSTDIR (DLLs beside the exe, then lib\ and share\).  This
# script used to copy them to $BUILD/<name>, where nothing looks:
# gdk-pixbuf then found no loader cache, every SVG image failed to load
# (Adwaita's radio-button bullet among them) and GTK said so on stderr.
#
# These directories are several MB, so they are copied only when the
# destination is missing -- this script runs after every build.
mkdir -p "$BUILD/lib"
for mod in gdk-pixbuf-2.0 pango gtk-3.0; do
  src="$TOOL_ROOT/lib/$mod"
  # The copy an older version of this script left at the wrong place.
  if [ -d "$BUILD/$mod" ]; then
    rm -rf "$BUILD/$mod"
  fi
  if [ -d "$src" ] && [ ! -d "$BUILD/lib/$mod" ]; then
    cp -r "$src" "$BUILD/lib/"
  fi
done

# The image loaders are DLLs as well, loaded on demand, and the SVG one
# needs librsvg and its own dependencies, which StockFW.exe does not
# import, so ldd's closure above misses them.  Inside an MSYS2 shell
# PATH finds them anyway; started from Explorer it does not, and SVG
# images fail again.  Follow the loaders' imports (objdump -p lists a
# PE file's "DLL Name:" entries) and stage every one the toolchain owns;
# the rest are Windows system DLLs.
imports_of () {
  objdump -p "$1" 2>/dev/null | sed -n 's/^[[:space:]]*DLL Name: //p' | tr -d '\r'
}
queue=""
for loader in "$BUILD"/lib/gdk-pixbuf-2.0/2.10.0/loaders/*.dll; do
  if [ -f "$loader" ]; then
    queue="$queue $(imports_of "$loader")"
  fi
done
seen=" "
loader_deps=0
while :; do
  set -- $queue
  [ "$#" -gt 0 ] || break
  name=$1
  shift
  queue="$*"
  case "$seen" in *" $name "*) continue ;; esac
  seen="$seen$name "
  [ -f "$TOOL_BIN/$name" ] || continue
  if [ ! -f "$BUILD/$name" ]; then
    cp -f "$TOOL_BIN/$name" "$BUILD/"
    loader_deps=$((loader_deps + 1))
  fi
  queue="$queue $(imports_of "$TOOL_BIN/$name")"
done
if [ "$loader_deps" -gt 0 ]; then
  echo "stage-runtime-dlls: $loader_deps more DLL(s) for the image loaders"
fi

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
