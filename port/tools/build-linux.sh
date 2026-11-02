#!/bin/bash
# Build the Linux backend + core the way tests/test-apply-linux.sh expects:
# libfs-core.a in build-linux/, then compile fs-backend-linux.c against it.
#
# This is a *compile/link* proof on an MSYS2 host.  It produces PE/COFF,
# not ELF: the point is to prove the Linux port still builds and the
# portable core suite still passes against it.  Running the live-iptables
# half needs a real Linux box with root + iptables (that test self-SKIPs).
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
OUT="$PORT/build-linux"

if [ -d /ucrt64/bin ]; then export PATH="/ucrt64/bin:/usr/bin:/bin"; fi

CF="$(pkg-config --cflags glib-2.0 gobject-2.0 gio-2.0 gtk+-3.0)"
LF="$(pkg-config --libs glib-2.0 gobject-2.0 gio-2.0 gtk+-3.0)"

# ws2_32 is the Windows toolchain's home for inet_pton/getnameinfo (the
# G_OS_WIN32 branch of fs-util.c).  On Linux those live in libc and the
# library does not exist, so gate it on the toolchain: MSYS2/MinGW gets
# it, Linux gets nothing.
case "$(uname -s)" in
Linux) EXTRA_LIBS="" ;;
*)     EXTRA_LIBS="-lws2_32" ;;
esac

mkdir -p "$OUT/obj"
fail=0

# ---- core: every portable unit, compiled to an object -----------------
CORE_SRCS="
fs-types fs-prefs fs-util fs-rules fs-script fs-settings-plan
fs-service fs-fwrule fs-copilot fs-eventrule fs-audit fs-trust fs-apply
fs-netparse fs-activity fs-json
"
for s in $CORE_SRCS; do
	if ! gcc -c -o "$OUT/obj/$s.o" -I "$PORT/src" $CF \
	        "$PORT/src/core/$s.c" 2>"$OUT/obj/$s.log"; then
		echo "FAIL: core/$s.c does not compile"
		sed 's/^/    /' "$OUT/obj/$s.log"
		fail=$((fail + 1))
	fi
done

if [ "$fail" -ne 0 ]; then
	echo "ABORT: $fail core unit(s) failed; no archive built"
	exit 1
fi

ar rcs "$OUT/libfs-core.a" "$OUT"/obj/*.o || exit 1
echo "ok:   build-linux/libfs-core.a ($(ls "$OUT"/obj/*.o | wc -l) objects)"

# ---- the Linux backend, compiled against core -------------------------
# On a real Linux toolchain this compiles (ifaddrs.h is POSIX) and the
# object is linked into the full binary below.  On MSYS2 it cannot:
# <ifaddrs.h> has no Windows equivalent, so the null backend stands in
# for the link -- noted honestly, never silently.
BACKEND_OBJ=""
if gcc -c -o "$OUT/fs-backend-linux.o" -I "$PORT/src" $CF \
       "$PORT/src/platform/linux/fs-backend-linux.c" 2>"$OUT/backend.log"; then
	echo "ok:   platform/linux/fs-backend-linux.c compiles (real Linux toolchain)"
	BACKEND_OBJ="$OUT/fs-backend-linux.o"
else
	echo "SKIP: platform/linux/fs-backend-linux.c needs a Linux toolchain"
	echo "      (<ifaddrs.h> is POSIX-only; getifaddrs() has no Windows"
	echo "      equivalent).  The null backend links in its place."
fi

# ---- the UI, compiled against the Linux-oriented core -----------------
# The UI is platform-neutral GTK3; prove no Windows header has crept in.
# The null backend stands in as the platform piece: the real Linux unit
# needs ifaddrs.h, which MSYS2 does not have.
UI_SRCS="
main ui/fs-app ui/fs-dialogs ui/fs-statusview ui/fs-policyview
ui/fs-hitview ui/fs-activityview ui/fs-copilot ui/fs-simviz
ui/fs-trustview ui/fs-tray
"
mkdir -p "$OUT/ui"

# ---- generate fs-theme-css.h the way CMake configure does -------------
# CMake escapes: backslash, then quote, strips CR, then turns each
# newline into the two-char sequence \n, and substitutes into the .h.in
# template.  Replicated here so the UI builds without running CMake.
perl -0777 -e '
	my $css = do { local $/; open my $f, "<", $ARGV[0] or die $!; <$f> };
	$css =~ s/\\/\\\\/g; $css =~ s/"/\\"/g; $css =~ s/\r//g;
	$css =~ s/\n/\\n/g;
	my $tpl = do { local $/; open my $f, "<", $ARGV[1] or die $!; <$f> };
	$tpl =~ s/\@FS_THEME_CSS\@/$css/;
	print $tpl;
' "$PORT/src/ui/fs-theme.css" "$PORT/src/ui/fs-theme-css.h.in" \
	> "$OUT/fs-theme-css.h" || { echo "FAIL: theme header generation"; exit 1; }
echo "ok:   generated build-linux/fs-theme-css.h from fs-theme.css"

for u in $UI_SRCS; do
	base="$(basename "$u")"
	if gcc -c -o "$OUT/ui/$base.o" -I "$PORT/src" -I "$PORT/resources" \
	        -I "$OUT" $CF \
	        -DFS_VERSION='"1.0.6"' -DFS_PLATFORM_NAME='"linux"' \
	        "$PORT/src/$u.c" 2>"$OUT/ui/$base.log"; then
		echo "ok:   src/$u.c"
	else
		echo "FAIL: src/$u.c does not compile"
		sed 's/^/    /' "$OUT/ui/$base.log"
		fail=$((fail + 1))
	fi
done

if [ "$fail" -ne 0 ]; then
	echo "ABORT: $fail UI unit(s) failed"
	exit 1
fi

echo "ok:   full UI compiles against the Linux-oriented core"

# ---- full link: the StockFW binary ------------------------------------
# The real Linux backend when it compiled (a real Linux box); otherwise
# the null backend, which is exactly its purpose -- the GUI links and
# starts, honestly reporting "no firewall backend" instead of pretending.
# Proves the whole program LINKS, not just compiles.
#
# EXTRA_LIBS carries -lws2_32 on the MSYS2/MinGW host only (the
# G_OS_WIN32 branch of fs-util.c); on Linux libc provides inet_pton
# and getnameinfo, and the library does not exist.
# ui/main.o is already in the glob, so src/main.c is NOT passed again.
PLATFORM_SRC="$PORT/src/platform/fs-backend-null.c"
PLATFORM_LABEL="null backend"
if [ -n "$BACKEND_OBJ" ]; then
	PLATFORM_SRC="$BACKEND_OBJ"
	PLATFORM_LABEL="real Linux (iptables) backend"
fi

if gcc -o "$OUT/StockFW" -I "$PORT/src" -I "$PORT/resources" -I "$OUT" $CF \
       "$OUT"/ui/*.o \
       "$PLATFORM_SRC" \
       "$OUT/libfs-core.a" $LF $EXTRA_LIBS 2>"$OUT/link.log"; then
	echo "ok:   full StockFW binary links ($PLATFORM_LABEL)"
else
	echo "FAIL: StockFW does not link"
	sed 's/^/    /' "$OUT/link.log"
	exit 1
fi

echo
echo "LINUX BUILD: core + UI + full link all good."
if [ -n "$BACKEND_OBJ" ]; then
	echo "Backend: the real Linux (iptables) backend is linked in."
	echo "Next: sudo tests/test-apply-linux.sh (root + iptables) proves"
	echo "traffic is actually filtered."
else
	echo "Backend: null (this host has no Linux toolchain for ifaddrs.h)."
	echo "fs-backend-linux.c compiles and links on the Linux side."
fi
exit 0
