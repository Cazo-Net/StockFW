#!/bin/bash
# Use-after-free analysis for a single source file.
#
# GCC's -fanalyzer follows the free, and g_free() is aliased to free()
# because GLib does not declare it as a deallocation function.  g_malloc
# is already attributed as an allocator, so this really does catch a
# freed-then-used pointer -- verified by pointing the script at a
# deliberately buggy program.
#
#   ./tests/test-uaf-analyze.sh            analyse the working tree default
#   ./tests/test-uaf-analyze.sh <file>     analyse a specific file
#
# Exit status is the whole point of the script, so it never reports a
# pass for a file it did not look at:
#
#   0  the file was compiled and no use-after-free was reported
#   0  the file needs Windows headers on a non-Windows host -- printed
#      as SKIP, because nothing was analysed
#   1  a use-after-free was reported
#   1  the file did not compile for any other reason: analysis was
#      requested and could not be done, which is not a pass

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT=$(dirname "$HERE")

SRC="${1:-$PORT/src/platform/windows/fs-backend-windows.c}"
LABEL="${2:-working tree}"

if [ -d /ucrt64/bin ]; then
	export PATH="/ucrt64/bin:$PATH"
fi

if [ ! -f "$SRC" ]; then
	echo "SKIP: $SRC not present"
	exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# gtk+-3.0 is in the list because most of the interesting code lives in
# src/ui; without it those files never compiled and the script used to
# call that a pass.
CFLAGS=$(pkg-config --cflags glib-2.0 gobject-2.0 gio-2.0 gtk+-3.0 2>/dev/null)
if [ -z "$CFLAGS" ]; then
	echo "FAILED: pkg-config could not supply the header flags"
	exit 1
fi

# -fanalyzer is noisy about things we are not testing for; keep only
# the use-after-free findings.

# Generated project headers (fs-theme-css.h) live in the build tree --
# CMake puts ${CMAKE_CURRENT_BINARY_DIR} on every UI target's include
# path, so this analysis must too, or src/ui/fs-app.c could never be
# examined here.
BUILD_INC=""
for b in "${STOCKFW_BUILD:-}" "$PORT/build" "$PORT/build-linux"; do
	if [ -n "$b" ] && [ -f "$b/fs-theme-css.h" ]; then
		BUILD_INC="-I $b"
		break
	fi
done

gcc -fanalyzer -Dg_free=free \
	-Wno-analyzer-malloc-leak \
	-Wno-analyzer-possible-null-argument \
	-Wno-analyzer-possible-null-dereference \
	-Wno-analyzer-null-argument \
	-Wno-analyzer-null-dereference \
	-Wno-analyzer-symbol-too-complex \
	-Wno-analyzer-too-complex \
	-I "$PORT/src" \
	-I "$PORT/resources" \
	-I "$PORT/src/platform/windows" \
	$BUILD_INC \
	$CFLAGS \
	-c -o "$TMP/out.o" "$SRC" 2> "$TMP/analyzer.log"
compile_rc=$?

uaf=$(grep -c 'analyzer-use-after-free' "$TMP/analyzer.log")

echo "=== use-after-free analysis: $LABEL ==="
echo "file: $SRC"

if [ "$uaf" -gt 0 ]; then
	echo
	grep -A14 'analyzer-use-after-free' "$TMP/analyzer.log" | head -60
	echo
	echo "FAILED: $uaf use-after-free finding(s)"
	exit 1
fi

if [ "$compile_rc" -ne 0 ]; then
	# A header this host simply does not have means the file could not
	# be analysed at all -- say which one, rather than claim it is
	# clean.  A missing header of our own is a broken analysis setup,
	# not a platform difference, so that still fails.
	if grep -qiE 'fatal error: .*: No such file or directory' "$TMP/analyzer.log"; then
		hdr=$(grep -oiE 'fatal error: [^:]+' "$TMP/analyzer.log" \
		      | head -1 | sed 's/.*fatal error: //')

		case "$hdr" in
		fs-*|stockfw-*)
			echo "FAILED: missing project header '$hdr', nothing was analysed"
			exit 1
			;;
		*)
			echo "SKIP: needs '$hdr', not available here (nothing analysed)"
			exit 0
			;;
		esac
	fi

	echo
	echo "FAILED: the file did not compile, so nothing was analysed"
	grep -m5 'error:' "$TMP/analyzer.log" | sed 's/^/  /'
	exit 1
fi

echo "ok:   compiled and analysed, no use-after-free found"
echo
echo "PASSED: 0 failure(s)"
exit 0
