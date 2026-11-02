#!/bin/bash
# Regenerate every logo asset from the one master image:
#
#   port/resources/stockfw-logo.png   square, transparent, >= 512 px
#
# Writes (and overwrites):
#   port/resources/stockfw-logo-{32,64,96,128}.png and their .h twins
#       -- embedded in the app (window and tray icon, Status page, About)
#          and in the command-line dashboard (header and favicon)
#   port/installer/nsis/resources/stockfw_icon.ico (16..256) and .png
#       -- StockFW.exe's icon (stockfw.rc) and the Windows installer's
#   port/installer/nsis/resources/stockfw_header.bmp, stockfw_welcome.bmp
#       -- the installer's page banner and Welcome/Finish side panel
#   port/installer/linux/stockfw-icon{-48,,-256}.png
#       -- the Linux menu entry's icon (hicolor 48, 128, 256)
#   pixmaps/stockfw.png (48) -- the original tree's icon
#
# Small sizes (<= 32 px) drop the master's margin so the mark fills the
# square; larger ones keep it.  Needs ImageMagick (`magick' or
# `convert'); od and awk for the headers.  Output is stripped of
# timestamps, so an unchanged master regenerates byte-identical files.
#
#   bash port/tools/make-logo-assets.sh

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
ROOT="$(dirname "$PORT")"
MASTER="$PORT/resources/stockfw-logo.png"

if command -v magick >/dev/null 2>&1; then
  IM=(magick)
elif command -v convert >/dev/null 2>&1; then
  IM=(convert)
else
  echo "error: ImageMagick (magick or convert) is required" >&2
  exit 1
fi

[ -f "$MASTER" ] || { echo "error: no master image at $MASTER" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# render <size> <out.png>
render () {
  local size="$1" out="$2" fit
  if [ "$size" -le 32 ]; then
    fit="$size"                          # no margin at icon sizes
  else
    fit=$(( size * 92 / 100 ))           # the master's own margin
  fi
  "${IM[@]}" "$MASTER" -background none -trim +repage \
    -filter Lanczos -resize "${fit}x${fit}" \
    -gravity center -extent "${size}x${size}" \
    -strip -define png:exclude-chunks=date,time,tIME \
    "PNG32:$out"
}

# header <png> <symbol> <out.h> -- the PNG as a C byte array.
header () {
  local png="$1" sym="$2" out="$3" guard len
  guard="$(echo "$sym" | tr '[:lower:]' '[:upper:]')"
  guard="${guard%_PNG}_H"
  len="$(wc -c < "$png" | tr -d ' ')"
  {
    echo "#ifndef $guard"
    echo "#define $guard"
    echo ""
    echo "/* Auto-generated from $(basename "$png") by tools/make-logo-assets.sh */"
    echo "/* Do not edit manually */"
    echo ""
    echo "static const unsigned char ${sym}[] = {"
    od -An -v -tx1 "$png" | awk '
      { for (i = 1; i <= NF; i++) { b[n++] = $i } }
      END {
        for (i = 0; i < n; i++) {
          if (i % 16 == 0) printf "    "
          printf "0x%s%s", b[i], (i == n - 1) ? "" : ", "
          if (i % 16 == 15 || i == n - 1) printf "\n"
        }
      }'
    echo "};"
    echo "static const unsigned int ${sym}_len = ${len};"
    echo ""
    echo "#endif /* $guard */"
  } > "$out"
}

# Embedded app and dashboard sizes.
for s in 32 64 96 128; do
  render "$s" "$PORT/resources/stockfw-logo-$s.png"
  header "$PORT/resources/stockfw-logo-$s.png" "stockfw_logo_${s}_png" \
         "$PORT/resources/stockfw-logo-$s.h"
  echo "  resources/stockfw-logo-$s.png (+ .h)"
done

# Windows: the .exe and installer icon.
ICO_PARTS=()
for s in 16 20 24 32 40 48 64 128 256; do
  render "$s" "$TMP/ico-$s.png"
  ICO_PARTS+=("$TMP/ico-$s.png")
done
"${IM[@]}" "${ICO_PARTS[@]}" "$PORT/installer/nsis/resources/stockfw_icon.ico"
cp "$TMP/ico-256.png" "$PORT/installer/nsis/resources/stockfw_icon.png"
echo "  installer/nsis/resources/stockfw_icon.ico (16-256) and .png"

# Windows installer artwork (NSIS Modern UI).  NSIS only takes 24-bit
# BMP3 files with no alpha, so the logo is flattened onto a solid
# background.  Colours are the app's own (fs-theme.css): sidebar
# #16181d / #2a2f39, accent #c62828, muted text #5b6472 / #8b93a1.
#   stockfw_header.bmp   150x57   top banner of every inner page (white,
#                                 like the banner it sits in)
#   stockfw_welcome.bmp  164x314  left panel of the Welcome and Finish pages
FONT_BOLD="DejaVu-Sans-Bold"
FONT="DejaVu-Sans"
render 44 "$TMP/hdr-logo.png"
"${IM[@]}" -size 150x57 xc:'#ffffff' \
  "$TMP/hdr-logo.png" -geometry +4+6 -composite \
  -font "$FONT_BOLD" -pointsize 19 -fill '#16181d' \
  -annotate +52+31 'StockFW' \
  -font "$FONT" -pointsize 10 -fill '#5b6472' \
  -annotate +53+45 'Firewall' \
  -fill '#c62828' -draw 'rectangle 0,55 149,56' \
  -alpha remove -alpha off -type TrueColor -strip \
  "BMP3:$PORT/installer/nsis/resources/stockfw_header.bmp"
echo "  installer/nsis/resources/stockfw_header.bmp (150x57)"

render 120 "$TMP/side-logo.png"
"${IM[@]}" -size 164x314 gradient:'#2a2f39-#16181d' \
  "$TMP/side-logo.png" -geometry +22+46 -composite \
  -gravity north \
  -font "$FONT_BOLD" -pointsize 22 -fill '#ffffff' \
  -annotate +0+180 'StockFW' \
  -fill '#c62828' -draw 'rectangle 62,214 101,216' \
  -font "$FONT" -pointsize 10 -fill '#cdd2da' \
  -annotate +0+226 'Firewall for' \
  -annotate +0+240 'Windows and Linux' \
  -alpha remove -alpha off -type TrueColor -strip \
  "BMP3:$PORT/installer/nsis/resources/stockfw_welcome.bmp"
echo "  installer/nsis/resources/stockfw_welcome.bmp (164x314)"

# Linux: hicolor theme sizes for the menu entry.
render 48  "$PORT/installer/linux/stockfw-icon-48.png"
render 128 "$PORT/installer/linux/stockfw-icon.png"
render 256 "$PORT/installer/linux/stockfw-icon-256.png"
echo "  installer/linux/stockfw-icon{-48,,-256}.png"

# The original tree's icon.
if [ -d "$ROOT/pixmaps" ]; then
  render 48 "$ROOT/pixmaps/stockfw.png"
  echo "  pixmaps/stockfw.png"
fi
