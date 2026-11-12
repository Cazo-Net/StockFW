#!/bin/bash
# The build without the desktop app (master plan PR 1, adjustment 5).
#
# FS_BUILD_GUI=OFF must configure and build fs-core and the command-line
# tool `stockfw' on a system with no GTK at all, and `stockfw' must not
# need a GTK, GDK, Pango or cairo library.  "No GTK" is made here by
# giving pkg-config a directory with every .pc file of this system
# except GTK's and GDK's (PKG_CONFIG_LIBDIR), so nothing is uninstalled.
# It also checks that FS_BUILD_GUI=ON (the default) still asks for GTK,
# and fails without it.
#
# Linux only.  Needs cmake, ninja, pkg-config and readelf; SKIP without.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"

if [ "$(uname -s)" != Linux ]; then
	echo "SKIP: the command-line tool is built on Linux only"
	exit 0
fi
for tool in cmake ninja pkg-config readelf; do
	if ! command -v "$tool" > /dev/null; then
		echo "SKIP: $tool is not installed"
		exit 0
	fi
done

fails=0
check () {   # check <description> <command...>
	local what="$1"; shift
	if "$@"; then echo "ok:   $what"; else echo "FAIL: $what"; fails=$((fails + 1)); fi
}

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
chmod 755 "$W"

# pkg-config without GTK: every .pc file it can see, but gtk*, gdk-3*
# and gail*.
PC="$W/pkgconfig"
mkdir -p "$PC"
for d in $(pkg-config --variable pc_path pkg-config | tr : ' '); do
	[ -d "$d" ] || continue
	for f in "$d"/*.pc; do
		[ -e "$f" ] || continue
		case "$(basename "$f")" in gtk*|gdk-3*|gail*) continue ;; esac
		[ -e "$PC/$(basename "$f")" ] || cp "$f" "$PC/"
	done
done
check "pkg-config finds GLib but not GTK in the stand-in" \
	bash -c "PKG_CONFIG_LIBDIR='$PC' pkg-config --exists glib-2.0 gio-2.0 &&
	         ! PKG_CONFIG_LIBDIR='$PC' pkg-config --exists gtk+-3.0"

B="$W/build"
PKG_CONFIG_LIBDIR="$PC" cmake -S "$PORT" -B "$B" -G Ninja -DFS_BUILD_GUI=OFF \
	> "$W/configure.log" 2>&1
rc=$?
check "FS_BUILD_GUI=OFF configures without GTK (rc=$rc)" [ "$rc" -eq 0 ]
[ "$rc" -eq 0 ] || tail -15 "$W/configure.log"
check "  ...and never looks for it" \
	bash -c "! grep -qi 'gtk' '$W/configure.log' && ! grep -q '^GTK3_' '$B/CMakeCache.txt'"

PKG_CONFIG_LIBDIR="$PC" ninja -C "$B" > "$W/build.log" 2>&1
rc=$?
check "ninja builds fs-core and stockfw (rc=$rc)" [ "$rc" -eq 0 ]
[ "$rc" -eq 0 ] || tail -15 "$W/build.log"
check "  ...and the manual page" test -s "$B/stockfw.1"
check "  ...but not the desktop app" test ! -e "$B/StockFW"
check "  ...with no warning" bash -c "! grep -q 'warning:' '$W/build.log'"

check "stockfw runs (--version)" \
	bash -c "'$B/stockfw' --version | grep -q '^stockfw '"
readelf -d "$B/stockfw" > "$W/needed" 2>&1
check "readelf -d stockfw lists its libraries" grep -q NEEDED "$W/needed"
check "  ...and none is GTK, GDK, Pango or cairo" \
	bash -c "! grep -Ei 'gtk|gdk|pango|cairo' '$W/needed'"

# The default still builds the desktop app, so it must ask for GTK.
PKG_CONFIG_LIBDIR="$PC" cmake -S "$PORT" -B "$W/build-on" -G Ninja \
	> "$W/configure-on.log" 2>&1
rc=$?
check "the default (FS_BUILD_GUI=ON) refuses to configure without GTK (rc=$rc)" \
	[ "$rc" -ne 0 ]
check "  ...and names gtk+-3.0" grep -q 'gtk+-3.0' "$W/configure-on.log"

echo
if [ "$fails" -eq 0 ]; then
	echo "PASSED: 0 failure(s)"
else
	echo "FAILED: $fails failure(s)"
fi
exit $(( fails > 0 ))

