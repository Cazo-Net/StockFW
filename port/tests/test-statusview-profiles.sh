#!/bin/bash
# Status-page profile-frame test: a backend with no profiles must not
# offer per-profile switches that are reachable on screen.
#
# The regression was a visibility one -- the frame was hidden at build
# time with gtk_widget_hide(), then a page-wide gtk_widget_show_all()
# (fs-app.c does exactly this when the window is shown) walked back
# over it and re-showed it.  Linux then presented Domain / Private /
# Public switches that could only answer "Linux has a single firewall
# state, not per-profile settings."
#
# This needs a display for gtk_init.  WSLg provides one; on a headless
# host it self-SKIPs rather than reporting a false failure.
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
OUT="$PORT/build-linux"

if [ -d /ucrt64/bin ]; then
  export PATH="/ucrt64/bin:$PATH"
fi

# gtk_init needs a display.  Skip rather than fail where there is none.
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
  echo "SKIP: no display (DISPLAY/WAYLAND_DISPLAY unset) -- gtk_init would abort"
  exit 0
fi

# $OUT/ui/*.o is the object tree the hand-written tools/build-linux.sh
# made before 1.0.7.  That script now runs CMake, which keeps its
# objects elsewhere; the same smoke is the CMake target
# fs-statusview-smoke (CI runs it under xvfb-run).
if [ ! -d "$OUT/ui" ]; then
  echo "SKIP: no hand-built object tree in $OUT/ui -- run the CMake target instead:"
  echo "      ninja -C build-linux fs-statusview-smoke && xvfb-run -a ./build-linux/fs-statusview-smoke"
  exit 0
fi

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

cd "$PORT"

# fs-app.c is part of the UI set, but src/main.c is NOT: it owns a
# main() that would collide with the test's.  CMake's FS_UI_SOURCES
# makes the same exclusion, so filter main.o out of the prebuilt glob.
UI_OBJS=""
for o in "$OUT"/ui/*.o; do
    case "$(basename "$o")" in
        main.o) ;;
        *)      UI_OBJS="$UI_OBJS $o" ;;
    esac
done

gcc "$HERE/ui-statusview-smoke.c" \
    -I src \
    -I "$OUT" \
    $(pkg-config --cflags glib-2.0 gobject-2.0 gio-2.0 gtk+-3.0) \
    -DFS_VERSION='"1.0.7"' -DFS_PLATFORM_NAME='"linux"' \
    -o "$BUILD_DIR/ui-statusview-smoke" \
    $UI_OBJS \
    "$OUT/libfs-core.a" \
    "$OUT/fs-backend-linux.o" \
    $(pkg-config --libs glib-2.0 gobject-2.0 gio-2.0 gtk+-3.0 liblzma libcrypto)

"$BUILD_DIR/ui-statusview-smoke"
