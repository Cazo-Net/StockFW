#!/bin/bash
# test-licence-texts.sh: the installers say what the About window says.
#
# The About window (src/ui/fs-aboutdialog.c) summarises the licence
# state the source really has: COPYING is the GNU GPL version 2,
# LICENSE is the Apache License 2.0, the ported code was released under
# GPL version 2 or later, and which covers which is still under review.
# The installers once shipped a LICENSE.txt that said "GPL version 3 or
# any later version", which no file in the source says.  This runs the
# two installers' own licence steps into a scratch directory and checks
# the file each one stages:
#
#   - it claims no GPL 3,
#   - it carries the About window's summary, sentence for sentence,
#   - it ends with COPYING and LICENSE in full, byte for byte.
#
#   cd port && bash tests/test-licence-texts.sh
set -u
PORT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$PORT_DIR/.." && pwd)"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
fails=0

check () {
	if [ "$1" = 0 ]; then echo "ok:   $2"; else echo "FAIL: $2"; fails=$((fails + 1)); fi
}

# One line of text with single spaces, for comparing prose wrapped
# differently in C strings and in a text file.  Carriage returns go too:
# a Windows checkout (core.autocrlf) ends the text file's lines in CRLF.
flat () { tr -d '\r' | tr '\n' ' ' | tr -s ' \t' ' '; }

# The About summary, from the C source: the string pieces of the
# label that starts "StockFW is free software", joined.
about="$(sed -n '/_("StockFW is free software and comes/,/"being reviewed.")/p' \
	"$PORT_DIR/src/ui/fs-aboutdialog.c" \
	| grep -o '"[^"]*"' | tr -d '"' | tr -d '\n' | tr -s ' ')"
[ -n "$about" ]; check $? "the About summary was found in fs-aboutdialog.c"

check_staged () {   # <file> <what>
	local file="$1" what="$2" body
	[ -s "$file" ]; check $? "$what: LICENSE.txt is staged"
	body="$(flat < "$file")"
	! grep -Eqi 'version 3 of the License|GPL-?3|GPLv3|GPL 3' "$file"
	check $? "$what: no claim of GPL version 3"
	case "$body" in *"$about"*) r=0 ;; *) r=1 ;; esac
	check $r "$what: carries the About window's licence summary"
	# Each text must appear whole, after the summary: COPYING inside
	# the file, LICENSE as its very end.
	python3 -I -c 'import sys; f=open(sys.argv[1],"rb").read(); c=open(sys.argv[2],"rb").read(); sys.exit(0 if c in f else 1)' \
		"$file" "$ROOT/COPYING"
	check $? "$what: carries COPYING in full"
	tail -c "$(wc -c < "$ROOT/LICENSE")" "$file" | cmp -s - "$ROOT/LICENSE"
	check $? "$what: ends with LICENSE in full"
}

# --- Windows (NSIS): step 6 of build_installer.sh, run on its own.
STAGE_DIR="$SCRATCH/nsis"
mkdir -p "$STAGE_DIR"
sed -n '/^# 6\. Create LICENSE.txt/,/^done$/p' "$PORT_DIR/installer/build_installer.sh" \
	> "$SCRATCH/nsis-step.sh"
grep -q 'cat > "$STAGE_DIR/LICENSE.txt"' "$SCRATCH/nsis-step.sh"
check $? "the NSIS licence step was found in build_installer.sh"
( PORT_DIR="$PORT_DIR" STAGE_DIR="$STAGE_DIR"; . "$SCRATCH/nsis-step.sh" ) > /dev/null
check_staged "$STAGE_DIR/LICENSE.txt" "Windows installer"
grep -q 'MUI_PAGE_LICENSE.*stage\\LICENSE.txt' "$PORT_DIR/installer/nsis/StockFW.nsi"
check $? "the NSIS licence page shows that staged file"

# --- Linux: the licence lines of build_installer_linux.sh.
STAGE="$SCRATCH/linux"
mkdir -p "$STAGE"
sed -n '/^cp "\$LINUX_DIR\/LICENSE.txt"/,/^done$/p' \
	"$PORT_DIR/installer/linux/build_installer_linux.sh" > "$SCRATCH/linux-step.sh"
grep -q 'LICENSE.txt' "$SCRATCH/linux-step.sh"
check $? "the Linux licence step was found in build_installer_linux.sh"
( LINUX_DIR="$PORT_DIR/installer/linux" PORT_DIR_ROOT="$ROOT" STAGE="$STAGE"; \
  . "$SCRATCH/linux-step.sh" ) > /dev/null
check_staged "$STAGE/LICENSE.txt" "Linux installer"

! grep -Eqi 'GPL-?3|GPLv3|version 3 of the License' "$PORT_DIR/installer/linux/README.md"
check $? "the Linux installer README claims no GPL 3"

echo
if [ $fails -eq 0 ]; then echo "PASSED: 0 failure(s)"; exit 0; fi
echo "FAILED: $fails failure(s)"; exit 1
