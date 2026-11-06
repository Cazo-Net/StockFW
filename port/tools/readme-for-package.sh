#!/bin/sh
# readme-for-package.sh VERSION IN OUT
#
# The project README as a package carries it: alone, without docs/,
# port/ and the rest of the repository beside it.  Every relative link
# (docs/..., port/..., CHANGELOG.md) is rewritten to the same file on
# GitHub at the release's tag (vVERSION, see RELEASING.md); links that
# already have a scheme and in-page anchors (#...) are left as they are.
# Used by both packagers; tests/test-release.sh checks the result.
set -eu
[ $# -eq 3 ] || { echo "usage: $0 VERSION IN OUT" >&2; exit 2; }
BASE="https://github.com/Cazo-Net/StockFW/blob/v$1"
sed -E "s#\]\((\./)?([^)#:][^):]*)\)#](${BASE}/\2)#g" "$2" > "$3"
