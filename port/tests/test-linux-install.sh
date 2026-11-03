#!/bin/bash
# installer/linux/install.sh and the stockfw-uninstall it writes, run for
# real -- in a private mount namespace, with a scratch PREFIX and an
# empty tmpfs over /etc/systemd/system, so the host is not touched.
#
# What it proves: the boot unit is installed with ExecStart pointing at
# the installed `stockfw', and enabled (the multi-user.target.wants
# link); the manual page and the bash and zsh completion are installed;
# the uninstaller disables and removes the unit, and removes the
# binaries, the page and the completion.  Needs root and unshare; SKIP otherwise.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"

if [ "$(id -u)" -ne 0 ] || ! command -v unshare >/dev/null 2>&1; then
	echo "SKIP: needs root and unshare"
	exit 0
fi
if ! command -v systemctl >/dev/null 2>&1; then
	echo "SKIP: systemctl not installed"
	exit 0
fi
if [ ! -x "${STOCKFW_BUILD:-$PORT/build-linux}/StockFW" ] || [ ! -x "${STOCKFW_BUILD:-$PORT/build-linux}/stockfw" ]; then
	echo "SKIP: build StockFW and stockfw first (ninja -C build-linux)"
	exit 0
fi

if [ "${STOCKFW_INSTALL_IN_MNTNS:-}" != "1" ]; then
	exec env STOCKFW_INSTALL_IN_MNTNS=1 unshare -m --propagation private bash "$0" "$@"
fi

failures=0
ok ()   { echo "ok:   $*"; }
fail () { echo "FAIL: $*"; failures=$((failures + 1)); }
check () { local what="$1"; shift; if "$@"; then ok "$what"; else fail "$what"; fi; }

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
mkdir -p /etc/systemd/system
mount -t tmpfs none /etc/systemd/system || { echo "SKIP: cannot mount a tmpfs"; exit 0; }
# Hide a running systemd from the installer as well: it would reload
# the host's manager, which cannot see this namespace's unit directory.
# With /run/systemd empty, systemctl works offline (it only makes the
# links), exactly as when installing into an image.
if [ -d /run/systemd ]; then
	mount -t tmpfs none /run/systemd || { echo "SKIP: cannot hide /run/systemd"; exit 0; }
fi

# install.sh as the tarball lays it out: the binaries next to it
# (StockFW, cli/stockfw), taken from the build being tested
# ($STOCKFW_BUILD, default build-linux), so the test never falls back to
# whatever ../../build-linux holds.
BUILD="${STOCKFW_BUILD:-$PORT/build-linux}"
STAGE="$SCRATCH/stage"
mkdir -p "$STAGE/cli"
cp -a "$PORT/installer/linux/." "$STAGE/"
install -m755 "$BUILD/StockFW" "$STAGE/StockFW"
install -m755 "$BUILD/stockfw" "$STAGE/cli/stockfw"
# The manual page and completion, as build_installer_linux.sh stages them.
"$BUILD/stockfw" __man > "$STAGE/cli/stockfw.1"
install -m644 "$PORT/contrib/completion/stockfw.bash" "$STAGE/cli/stockfw.bash"
install -m644 "$PORT/contrib/completion/_stockfw" "$STAGE/cli/_stockfw"

PREFIX="$SCRATCH/prefix"
UNIT=/etc/systemd/system/stockfw.service
WANTS=/etc/systemd/system/multi-user.target.wants/stockfw.service

PREFIX="$PREFIX" bash "$STAGE/install.sh" > "$SCRATCH/install.log" 2>&1
rc=$?
check "install.sh succeeds (rc=$rc)" [ "$rc" -eq 0 ]
check "the boot unit is installed" [ -f "$UNIT" ]
check "...running the installed stockfw" grep -qx "ExecStart=$PREFIX/bin/stockfw start" "$UNIT"
check "...with no ExecStop" bash -c "! grep -q '^ExecStop' '$UNIT'"
check "...and enabled for boot" [ -L "$WANTS" ]
EXTRAS="$PREFIX/share/man/man1/stockfw.1 $PREFIX/share/bash-completion/completions/stockfw $PREFIX/share/zsh/site-functions/_stockfw"
for f in $EXTRAS; do
	check "installed: ${f#"$PREFIX/"}" [ -s "$f" ]
done
check "...the manual page is the tool's own" cmp -s "$STAGE/cli/stockfw.1" "$PREFIX/share/man/man1/stockfw.1"
grep -q "puts the rules back before the network comes up" "$SCRATCH/install.log" &&
	ok "the summary says what the service does" ||
	fail "the summary says what the service does"

timeout 60 bash "$PREFIX/bin/stockfw-uninstall" > "$SCRATCH/uninstall.log" 2>&1
rc=$?
check "stockfw-uninstall succeeds (rc=$rc: $(tail -1 "$SCRATCH/uninstall.log"))" [ "$rc" -eq 0 ]
# -L as well: a link left dangling would still be "enabled" to systemd.
check "the boot unit is disabled" [ ! -e "$WANTS" -a ! -L "$WANTS" ]
check "...and removed" [ ! -e "$UNIT" ]
check "the binaries are gone" [ ! -e "$PREFIX/bin/StockFW" -a ! -e "$PREFIX/bin/stockfw" ]
for f in $EXTRAS; do
	check "removed: ${f#"$PREFIX/"}" [ ! -e "$f" ]
done
check "...and the completion folders it made" \
	[ ! -e "$PREFIX/share/bash-completion" -a ! -e "$PREFIX/share/zsh" ]

# The tools the install summary must account for (1.0.7): nft and curl
# are only warnings, but the user is told either way.
grep -Eq 'nft (found|not found)' "$SCRATCH/install.log" &&
grep -Eq 'curl (found|not found)' "$SCRATCH/install.log"
check "the install reports nft and curl" [ $? -eq 0 ]

# A system without OpenSSL 3 (Debian 11, Ubuntu 20.04): the binaries
# need libcrypto.so.3, so install.sh stops before installing anything
# and names the library.  ldconfig is the installer's only source for
# the check, so a stand-in that hides libcrypto.so.3 is that system.
REAL_LDCONFIG="$(command -v ldconfig || true)"
if [ -n "$REAL_LDCONFIG" ]; then
	mkdir -p "$SCRATCH/fakebin"
	printf '#!/bin/sh\n"%s" "$@" | grep -v %s\n' "$REAL_LDCONFIG" \
		"'libcrypto\.so\.3 '" > "$SCRATCH/fakebin/ldconfig"
	chmod 755 "$SCRATCH/fakebin/ldconfig"
	PREFIX2="$SCRATCH/prefix-no-ssl3"
	PATH="$SCRATCH/fakebin:$PATH" PREFIX="$PREFIX2" \
		bash "$STAGE/install.sh" > "$SCRATCH/install-nossl.log" 2>&1
	rc=$?
	check "without libcrypto.so.3, install.sh fails (rc=$rc)" [ "$rc" -ne 0 ]
	check "...naming libcrypto.so.3" grep -q 'missing runtime libraries:.*libcrypto\.so\.3' "$SCRATCH/install-nossl.log"
	check "...and installs nothing" [ ! -e "$PREFIX2/bin/StockFW" ]
else
	echo "SKIP: no ldconfig; the missing-libcrypto case is not run"
fi

umount /etc/systemd/system
echo
if [ "$failures" -eq 0 ]; then
	echo "PASSED: 0 failure(s)"
else
	echo "FAILED: $failures failure(s)"
fi
exit $(( failures > 0 ))
