#!/bin/bash
# test-release.sh: what a release ships says the version it is, and the
# packages are usable as documented.
#
#   cd port && bash tests/test-release.sh
#
# 1. Version: every place that carries the version as text agrees with
#    project(VERSION) in CMakeLists.txt; the resource script and NSIS
#    take it from the build, not a literal (1.0.7 shipped its first
#    builds as "1.0.6", file properties 1.0.5.0).
# 2. Docs: CHANGELOG.md has the version's section, RELEASING.md names
#    the three assets, every in-page link in README.md lands on a heading.
# 3. Modes: the shell entry points are executable in git and on disk.
# 4. Windows installer steps, run on their own into a scratch directory:
#    the documentation step stages the real README and CHANGELOG (it
#    once staged a one-line stub), the licence page names the version,
#    liblzma and OpenSSL; with makensis installed, StockFW.nsi compiles
#    with -DAPP_VERSION into StockFW-<version>-Setup.exe and refuses to
#    compile without it; with windres, the configured stockfw.rc builds.
# 5. Linux tarball, when build-linux/ (or STOCKFW_BUILD_DIR) holds both
#    binaries: the real packager, into a scratch directory, then the
#    archive itself -- install.sh, StockFW and cli/stockfw executable,
#    binaries stripped, the unpacked StockFW reports the version, the
#    changelog, README and licence are the real ones.
#    STOCKFW_REQUIRE_PACKAGE=1 turns a missing build into a failure (CI).
set -u
PORT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$PORT_DIR/.." && pwd)"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
fails=0

check () {
	if [ "$1" = 0 ]; then echo "ok:   $2"; else echo "FAIL: $2"; fails=$((fails + 1)); fi
}
yes_if () { if "$@"; then echo 0; else echo 1; fi; }

V="$(sed -n 's/^[[:space:]]*VERSION[[:space:]]\{1,\}\([0-9][0-9.]*\).*/\1/p' \
	"$PORT_DIR/CMakeLists.txt" | head -n 1)"
case "$V" in
[0-9]*.[0-9]*.[0-9]*) r=0 ;;
*) r=1 ;;
esac
check $r "CMakeLists.txt names a three-part project version ($V)"
VMAJ="${V%%.*}"; rest="${V#*.}"; VMIN="${rest%%.*}"; VPAT="${rest#*.}"

# ---------------------------------------------------------------- 1. version
for f in src/main.c src/ui/fs-aboutdialog.c src/ui/fs-helpwindow.c \
         src/cli/fs-cli.h tests/ui-help-smoke.c; do
	got="$(sed -n 's/^#define FS_VERSION "\(.*\)"$/\1/p' "$PORT_DIR/$f")"
	check "$(yes_if [ "$got" = "$V" ])" "$f: the FS_VERSION fallback is $V (it is '$got')"
done
# Every other hard-coded FS_VERSION in the sources, wherever it is.
others="$(grep -rhoE --include='*.c' --include='*.h' --include='*.sh' --include='*.in' \
	'#define FS_VERSION "[^"]*"|-DFS_VERSION=.?"[^"]*"' \
	"$PORT_DIR/src" "$PORT_DIR/tests" "$PORT_DIR/tools" 2>/dev/null \
	| grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sort -u)"
check "$(yes_if [ "$others" = "$V" ])" "every FS_VERSION literal in src/, tests/ and tools/ is $V (found: $(echo $others))"

rc="$PORT_DIR/stockfw.rc.in"
! grep -Eq '[0-9]+,[0-9]+,[0-9]+,[0-9]+|"[0-9]+\.[0-9]+\.[0-9]+"' "$rc"
check $? "stockfw.rc.in carries no literal version"
grep -q 'FILEVERSION @PROJECT_VERSION_MAJOR@,@PROJECT_VERSION_MINOR@,@PROJECT_VERSION_PATCH@,0' "$rc" &&
grep -q 'PRODUCTVERSION @PROJECT_VERSION_MAJOR@,@PROJECT_VERSION_MINOR@,@PROJECT_VERSION_PATCH@,0' "$rc" &&
grep -q '"FileVersion", "@PROJECT_VERSION@"' "$rc" &&
grep -q '"ProductVersion", "@PROJECT_VERSION@"' "$rc"
check $? "stockfw.rc.in takes all four version fields from @PROJECT_VERSION*@"

# The resource script exactly as CMake configures it.
if command -v cmake >/dev/null 2>&1; then
	cat > "$SCRATCH/rc.cmake" <<'EOF'
set(PROJECT_VERSION "${V}")
string(REPLACE "." ";" parts "${V}")
list(GET parts 0 PROJECT_VERSION_MAJOR)
list(GET parts 1 PROJECT_VERSION_MINOR)
list(GET parts 2 PROJECT_VERSION_PATCH)
set(STOCKFW_ICON_ICO "${ICON}")
configure_file("${IN}" "${OUT}" @ONLY)
EOF
	cmake -DV="$V" -DIN="$rc" -DOUT="$SCRATCH/stockfw.rc" \
	      -DICON="$PORT_DIR/installer/nsis/resources/stockfw_icon.ico" \
	      -P "$SCRATCH/rc.cmake" >/dev/null 2>&1
	grep -q "FILEVERSION $VMAJ,$VMIN,$VPAT,0" "$SCRATCH/stockfw.rc" &&
	grep -q "\"ProductVersion\", \"$V\"" "$SCRATCH/stockfw.rc"
	check $? "the configured stockfw.rc says $VMAJ,$VMIN,$VPAT,0 and \"$V\""
	if command -v x86_64-w64-mingw32-windres >/dev/null 2>&1; then
		x86_64-w64-mingw32-windres "$SCRATCH/stockfw.rc" -O coff \
			-o "$SCRATCH/stockfw.res.o" 2>"$SCRATCH/windres.log"
		check $? "windres compiles the configured stockfw.rc"
	else
		echo "SKIP: windres not installed; the configured .rc is not compiled"
	fi
else
	echo "SKIP: cmake not installed; stockfw.rc.in is not configured"
fi

nsi="$PORT_DIR/installer/nsis/StockFW.nsi"
! grep -Eq '^[[:space:]]*!define[[:space:]]+APP_VERSION[[:space:]]' "$nsi"
check $? "StockFW.nsi defines no APP_VERSION of its own"
grep -q '!ifndef APP_VERSION' "$nsi" && grep -q '!error' "$nsi"
check $? "StockFW.nsi stops when APP_VERSION is not passed"
grep -q '"-DAPP_VERSION=\$VERSION"' "$PORT_DIR/installer/build_installer.sh"
check $? "build_installer.sh passes -DAPP_VERSION to makensis"
# (The GTK module paths 2.10.0 and 3.0.0 are not StockFW versions.)
! grep -v '^[[:space:]]*#' "$PORT_DIR/installer/build_installer.sh" |
	grep -Eq '(StockFW-|Version |APP_VERSION=)[0-9]+\.[0-9]+\.[0-9]+'
check $? "build_installer.sh names no StockFW version literally"

lic="$PORT_DIR/installer/linux/LICENSE.txt"
grep -qx 'Version @VERSION@' "$lic"
check $? "installer/linux/LICENSE.txt takes its version from the packager"

lreadme="$PORT_DIR/installer/linux/README.md"
bad="$(grep -oE 'StockFW[ -][0-9]+\.[0-9]+\.[0-9]+' "$lreadme" | grep -v "StockFW[ -]$V\$" || true)"
check "$(yes_if [ -z "$bad" ])" "installer/linux/README.md names only $V (others: $(echo $bad))"
grep -q "StockFW-$V-linux-x86_64.tar.gz" "$lreadme"
check $? "installer/linux/README.md names StockFW-$V-linux-x86_64.tar.gz"

grep -q 'cmake -S "\$PORT" -B "\$OUT"' "$PORT_DIR/tools/build-linux.sh"
check $? "tools/build-linux.sh builds through CMakeLists.txt"

# One copyright line on everything the release carries: the Windows
# file properties (stockfw.rc.in), the installer's own (StockFW.nsi) and
# both licence files said three different things (release review).
COPY_LINE='Copyright (C) 2024-2026 StockFW Project'
copy_bad=""
grep -q "\"LegalCopyright\", \"$COPY_LINE\"" "$PORT_DIR/stockfw.rc.in" || copy_bad="$copy_bad stockfw.rc.in"
grep -q "\"LegalCopyright\" \"$COPY_LINE\"" "$PORT_DIR/installer/nsis/StockFW.nsi" || copy_bad="$copy_bad StockFW.nsi"
grep -qx "$COPY_LINE" "$PORT_DIR/installer/linux/LICENSE.txt" || copy_bad="$copy_bad installer/linux/LICENSE.txt"
grep -qx "$COPY_LINE" "$PORT_DIR/installer/build_installer.sh" || copy_bad="$copy_bad build_installer.sh"
others="$(grep -hoE '(\(C\)|Copyright \(C\)) [0-9-]+ StockFW Project' \
	"$PORT_DIR/stockfw.rc.in" "$PORT_DIR/installer/nsis/StockFW.nsi" \
	"$PORT_DIR/installer/linux/LICENSE.txt" "$PORT_DIR/installer/build_installer.sh" |
	grep -vx "$COPY_LINE" || true)"
[ -z "$others" ] || copy_bad="$copy_bad (also: $others)"
check "$(yes_if [ -z "$copy_bad" ])" "one copyright line, '$COPY_LINE', in the resource script, the NSIS script and both licence files (differs:$copy_bad)"

# ---------------------------------------------------------------- 2. docs
grep -q "^## \[$V\]" "$ROOT/CHANGELOG.md"
check $? "CHANGELOG.md has a ## [$V] section"
! grep -Eqi '\bAI\b|AI-powered|artificial intelligence' "$ROOT/CHANGELOG.md"
check $? "CHANGELOG.md does not call the Copilot AI"
for asset in "StockFW-$V-Setup.exe" "StockFW-$V-linux-x86_64.tar.gz" "SHA256SUMS.txt"; do
	grep -qF "$asset" "$ROOT/RELEASING.md"
	check $? "RELEASING.md names $asset"
done

# GitHub's anchor for a heading: lower case, punctuation other than
# '-' and '_' dropped, spaces to '-'.
python3 -I - "$ROOT/README.md" > "$SCRATCH/anchors.txt" <<'EOF'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
text = re.sub(r"```.*?```", "", text, flags=re.S)
anchors = set()
for line in text.splitlines():
    m = re.match(r"#{1,6}\s+(.*)", line)
    if m:
        h = m.group(1).strip().lower()
        h = re.sub(r"[^\w\- ]", "", h)
        anchors.add(h.replace(" ", "-"))
bad = sorted(set(re.findall(r"\]\(#([^)]+)\)", text)) - anchors)
for b in bad:
    print(b)
EOF
check "$(yes_if [ ! -s "$SCRATCH/anchors.txt" ])" "every in-page link in README.md lands on a heading (broken: $(echo $(cat "$SCRATCH/anchors.txt")))"

# ---------------------------------------------------------------- 3. modes
ENTRY="installer/linux/install.sh installer/linux/build_installer_linux.sh
       installer/build_installer.sh tools/build-linux.sh tools/stage-runtime-dlls.sh"
for f in $ENTRY; do
	check "$(yes_if [ -x "$PORT_DIR/$f" ])" "$f is executable on disk"
done
if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
	for f in $ENTRY; do
		mode="$(git -C "$ROOT" ls-files -s "port/$f" | cut -d' ' -f1)"
		check "$(yes_if [ "$mode" = 100755 ])" "port/$f is 100755 in git (it is $mode)"
	done
else
	echo "SKIP: not a git checkout; modes in git not checked"
fi

# ---------------------------------------------------------------- 4. Windows installer steps
NS="$SCRATCH/nsis"
mkdir -p "$NS"
sed -n '/^# 7\. Copy documentation/,/^fi$/p' "$PORT_DIR/installer/build_installer.sh" \
	> "$SCRATCH/nsis-docs.sh"
grep -q 'CHANGELOG.md' "$SCRATCH/nsis-docs.sh"
check $? "the NSIS documentation step was found in build_installer.sh"
( ROOT_DIR="$ROOT" PORT_DIR="$PORT_DIR" STAGE_DIR="$NS" VERSION="$V"; \
  . "$SCRATCH/nsis-docs.sh" ) > /dev/null 2>&1
sh "$PORT_DIR/tools/readme-for-package.sh" "$V" "$ROOT/README.md" "$SCRATCH/readme-pkg.md"
cmp -s "$NS/README.md" "$SCRATCH/readme-pkg.md"
check $? "the Windows installer stages the project README (not a stub)"
# Alone in a package, a relative link leads nowhere (release review,
# problem 5): every link has a scheme or is an in-page anchor, and
# with the tag's address taken out again the text is the README's.
rel="$(grep -oE '\]\([^)]*\)' "$NS/README.md" | grep -vE '^\]\((https?:|mailto:|#)' || true)"
check "$(yes_if [ -z "$rel" ])" "the packaged README has no relative link left (found: $(echo $rel | head -c 200))"
sed "s#https://github.com/Cazo-Net/StockFW/blob/v$V/##g" "$NS/README.md" > "$SCRATCH/readme-back.md"
sed -E 's#\]\(\./#](#g' "$ROOT/README.md" > "$SCRATCH/readme-root.md"
cmp -s "$SCRATCH/readme-back.md" "$SCRATCH/readme-root.md"
check $? "  ...and otherwise it is the project README, links to v$V pointing at the same files"
cmp -s "$NS/CHANGELOG.md" "$ROOT/CHANGELOG.md"
check $? "the Windows installer stages CHANGELOG.md"

# The strip step stops the build without strip, as the Linux
# packager does (it once warned and shipped the exe unstripped).
sed -n '/^# 1\. Copy main executable/,/^echo "  Stripped StockFW.exe"$/p' \
	"$PORT_DIR/installer/build_installer.sh" > "$SCRATCH/nsis-strip.sh"
mkdir -p "$SCRATCH/wstrip/build" "$SCRATCH/wstrip/stage" "$SCRATCH/wstrip/bin"
printf 'MZ' > "$SCRATCH/wstrip/build/StockFW.exe"
for t in cp mkdir echo; do ln -sf "$(command -v $t)" "$SCRATCH/wstrip/bin/$t" 2>/dev/null; done
( PATH="$SCRATCH/wstrip/bin"; BUILD_DIR="$SCRATCH/wstrip/build"; STAGE_DIR="$SCRATCH/wstrip/stage"; \
  . "$SCRATCH/nsis-strip.sh" ) > /dev/null 2>&1
r=$?
check "$(yes_if [ $r -ne 0 ] && [ -s "$SCRATCH/nsis-strip.sh" ])" "the Windows packager stops when strip is missing"

sed -n '/^# 6\. Create LICENSE.txt/,/^done$/p' "$PORT_DIR/installer/build_installer.sh" \
	> "$SCRATCH/nsis-lic.sh"
( PORT_DIR="$PORT_DIR" STAGE_DIR="$NS" VERSION="$V"; . "$SCRATCH/nsis-lic.sh" ) > /dev/null 2>&1
grep -qx "Version $V" "$NS/LICENSE.txt"
check $? "the Windows licence page says Version $V"
grep -q '^liblzma from XZ Utils (BSD Zero Clause License' "$NS/LICENSE.txt" &&
grep -q '^OpenSSL libcrypto 3 (Apache License 2.0' "$NS/LICENSE.txt"
check $? "the Windows licence page lists the bundled liblzma and OpenSSL libcrypto"
grep -q 'File "${PROJECT_DIR}\\installer\\nsis\\stage\\LICENSE.txt"' "$nsi" &&
grep -q 'Delete "$INSTDIR\\LICENSE.txt"' "$nsi"
check $? "the Windows installer installs LICENSE.txt and the uninstaller removes it"

if command -v makensis >/dev/null 2>&1; then
	MN="$SCRATCH/mkn/installer/nsis"
	mkdir -p "$MN/stage/gtk-runtime/bin" "$MN/stage/gtk-runtime/lib" \
	         "$MN/stage/gtk-runtime/share" "$MN/stage/gtk-runtime/etc"
	ln -s "$PORT_DIR/installer/nsis/resources" "$MN/resources"
	cp "$nsi" "$MN/StockFW.nsi"
	for f in StockFW.exe gtk-runtime/bin/gspawn-win64-helper.exe \
	         gtk-runtime/bin/gspawn-win64-helper-console.exe gtk-runtime/bin/x.dll \
	         StockFW-elevated.vbs StockFW-elevated.cmd StockFW-elevated.ps1; do
		echo stand-in > "$MN/stage/$f"
	done
	cp "$NS/README.md" "$NS/CHANGELOG.md" "$NS/LICENSE.txt" "$MN/stage/"
	( cd "$MN" && makensis -V1 "-DAPP_VERSION=$V" StockFW.nsi ) > "$SCRATCH/makensis.log" 2>&1
	check $? "makensis compiles StockFW.nsi with -DAPP_VERSION=$V"
	check "$(yes_if [ -s "$MN/StockFW-$V-Setup.exe" ])" "...into StockFW-$V-Setup.exe"
	strings -el "$MN/StockFW-$V-Setup.exe" 2>/dev/null | grep -qx "$V.0"
	check $? "...whose file properties say $V.0"
	rm -f "$MN"/StockFW-*-Setup.exe
	( cd "$MN" && makensis -V1 StockFW.nsi ) > "$SCRATCH/makensis-nov.log" 2>&1
	r=$?
	check "$(yes_if [ $r -ne 0 ] && grep -q 'APP_VERSION is not defined' "$SCRATCH/makensis-nov.log")" \
		"makensis refuses StockFW.nsi without APP_VERSION"
	rm -f "$MN/stage/CHANGELOG.md"
	( cd "$MN" && makensis -V1 "-DAPP_VERSION=$V" StockFW.nsi ) > /dev/null 2>&1
	check "$(yes_if [ $? -ne 0 ])" "makensis refuses a stage without CHANGELOG.md"
else
	echo "SKIP: makensis not installed; StockFW.nsi is not compiled"
fi

# ---------------------------------------------------------------- 5. Linux tarball
BUILD="${STOCKFW_BUILD_DIR:-${STOCKFW_BUILD:-$PORT_DIR/build-linux}}"
if [ -x "$BUILD/StockFW" ] && [ -x "$BUILD/stockfw" ] &&
   [ "$(od -An -tx1 -N4 "$BUILD/StockFW" | tr -d ' \n')" = 7f454c46 ]; then
	DIST="$SCRATCH/dist"
	STOCKFW_BUILD_DIR="$BUILD" STOCKFW_DIST_DIR="$DIST" \
		bash "$PORT_DIR/installer/linux/build_installer_linux.sh" > "$SCRATCH/pack.log" 2>&1
	r=$?
	check $r "build_installer_linux.sh packages $BUILD"
	[ $r -eq 0 ] || sed 's/^/    /' "$SCRATCH/pack.log" | tail -20
	NAME="StockFW-$V-linux-$(uname -m)"
	TB="$DIST/$NAME.tar.gz"
	check "$(yes_if [ -s "$TB" ])" "the archive is named $NAME.tar.gz"
	if [ -s "$TB" ]; then
		tar -tvzf "$TB" > "$SCRATCH/list.txt"
		mode_of () { awk -v p="$NAME/$1" '$6==p{print $1}' "$SCRATCH/list.txt"; }
		for exe in install.sh StockFW cli/stockfw; do
			m="$(mode_of "$exe")"
			check "$(yes_if [ "$m" = "-rwxr-xr-x" ])" "the archive has $exe as -rwxr-xr-x (it is '$m')"
		done
		for doc in README.md README-project.md CHANGELOG.md LICENSE.txt \
		           stockfw.service stockfw.desktop stockfw-icon.png; do
			m="$(mode_of "$doc")"
			check "$(yes_if [ "$m" = "-rw-r--r--" ])" "the archive has $doc as -rw-r--r-- (it is '$m')"
		done
		X="$SCRATCH/x"
		mkdir -p "$X"
		tar -xzf "$TB" -C "$X"
		U="$X/$NAME"
		# As a user would: run the script the documented way.  Only
		# when not root, where it stops at its root check; as root it
		# would install for real.
		if [ "$(id -u)" -ne 0 ]; then
			out="$(cd "$U" && ./install.sh 2>&1)"
			case "$out" in
			*"must be installed as root"*) r=0 ;;
			*) r=1 ;;
			esac
			check $r "./install.sh runs directly from the unpacked archive"
		else
			echo "SKIP: running as root; ./install.sh is not run (it would install)"
		fi
		for b in StockFW cli/stockfw; do
			! readelf -S "$U/$b" 2>/dev/null | grep -q '\.debug_info'
			check $? "$b carries no debug information"
			! readelf -S "$U/$b" 2>/dev/null | grep -q ' \.symtab'
			check $? "$b carries no symbol table"
		done
		# install.sh checks every library the binaries name (the C
		# library aside): it once left out libatk-1.0.so.0.
		listed="$(sed -n '/^NEEDED="/,/"$/p' "$U/install.sh" | tr -d '"' | sed 's/^NEEDED=//' | tr -s ' \n' '\n')"
		unlisted=""
		for so in $(readelf -d "$U/StockFW" "$U/cli/stockfw" 2>/dev/null |
		            sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | sort -u); do
			case "$so" in libc.so.*|libm.so.*|ld-linux*|libpthread.so.*|libdl.so.*|librt.so.*|libasan.so.*|libubsan.so.*) continue ;; esac  # (the C library; sanitizer builds)
			echo "$listed" | grep -qx "$so" || unlisted="$unlisted $so"
		done
		check "$(yes_if [ -z "$unlisted" ])" "install.sh checks for every library the binaries need (missing:$unlisted)"
		got="$(timeout 10 "$U/StockFW" --version 2>/dev/null)"
		case "$got" in "StockFW $V "*) r=0 ;; *) r=1 ;; esac
		check $r "the unpacked StockFW --version says $V ('$got')"
		got="$(timeout 10 "$U/cli/stockfw" --version 2>/dev/null)"
		case "$got" in "stockfw $V "*) r=0 ;; *) r=1 ;; esac
		check $r "the unpacked stockfw --version says $V ('$got')"
		cmp -s "$U/CHANGELOG.md" "$ROOT/CHANGELOG.md"
		check $? "the archive carries CHANGELOG.md"
		cmp -s "$U/README-project.md" "$SCRATCH/readme-pkg.md"
		check $? "the archive carries the project README, its links pointing at v$V"
		cmp -s "$U/README.md" "$PORT_DIR/installer/linux/README.md"
		check $? "the archive's README.md is the Linux installer README"
		grep -qx "Version $V" "$U/LICENSE.txt"
		check $? "the archive's LICENSE.txt says Version $V"
		grep -q '^liblzma from XZ Utils' "$U/LICENSE.txt" &&
		grep -q '^OpenSSL libcrypto 3 (Apache License 2.0' "$U/LICENSE.txt"
		check $? "the archive's LICENSE.txt lists liblzma and OpenSSL libcrypto"
		(cd "$DIST" && sha256sum -c --quiet "$NAME.tar.gz.sha256")
		check $? "the archive's .sha256 matches it"
		# For the CI log and the release notes.
		sed 's/^/    /' "$SCRATCH/list.txt"
	fi
elif [ "${STOCKFW_REQUIRE_PACKAGE:-}" = 1 ]; then
	check 1 "a Linux build to package in $BUILD (STOCKFW_REQUIRE_PACKAGE=1)"
else
	echo "SKIP: no Linux build in $BUILD; the tarball is not built (bash tools/build-linux.sh)"
fi

echo
if [ $fails -eq 0 ]; then echo "PASSED: 0 failure(s)"; exit 0; fi
echo "FAILED: $fails failure(s)"; exit 1
