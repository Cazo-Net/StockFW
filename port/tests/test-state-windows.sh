#!/bin/bash
# Windows firewall state integration test: drives the real backend
# against the real Windows Firewall service and checks that the state
# it reports matches what was just applied.
#
# This exists because the state logic was a single boolean expression
# that read RUNNING no matter what had been configured -- something no
# amount of generated-text testing could ever catch.
#
# The test briefly changes the firewall state, which is the point of
# it, so the original per-profile settings are read first and restored
# on every exit path.  Needs an elevated shell; a plain one cannot
# change the firewall state at all, which the test reports as SKIP
# rather than failure.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
BUILD_DIR="$(mktemp -d)"

failures=0

CHECK() {
	local cond="$1"; shift
	if [ "$cond" = "0" ]; then
		printf 'ok:   %s\n' "$*"
	else
		printf 'FAIL: %s\n' "$*"
		failures=$((failures + 1))
	fi
}

export PATH="/ucrt64/bin:$PATH"

# The Windows backend needs <windows.h>: MSYS2 only, as test-winlog.sh.
if [ "${OS:-}" != "Windows_NT" ] && [ ! -d /ucrt64 ]; then
	echo "SKIP: Windows only (the backend compiled here is fs-backend-windows.c)"
	exit 0
fi

B="${STOCKFW_BUILD:-$PORT/build}"
if [ ! -f "$B/libfs-core.a" ]; then
	echo "SKIP: $B/libfs-core.a not present (build the project first)"
	exit 0
fi

# ---------------------------------------------------------------- source
cat > "$BUILD_DIR/test-state.c" <<'EOF'
#include <glib.h>
#include <stdio.h>
#include "core/fs-backend.h"
#include "core/fs-rules.h"
#include "core/fs-script.h"

static const gchar *
state_name (FsFirewallState s)
{
	switch (s) {
	case FS_FW_STOPPED: return "STOPPED";
	case FS_FW_RUNNING: return "RUNNING";
	case FS_FW_LOCKED:  return "LOCKED";
	case FS_FW_HIT:     return "HIT";
	case FS_FW_NONE:
	default:            return "NONE";
	}
}

static gboolean
set_all (gboolean on, GError **error)
{
	const FsBackend *b = fs_backend ();
	gint i;

	for (i = 0; i < FS_PROFILE_COUNT; i++)
		if (!b->set_profile_enabled (i, on, error))
			return FALSE;

	return TRUE;
}

/* argv[1]:
 *   get      - print current state
 *   getall    - print state, then one line per profile (0/1)
 *   alloff    - switch every profile off, print the resulting state
 *   allon     - switch every profile on,  print the resulting state
 *   oneoff    - everything on except the last profile (a mix)
 *   restore   - argv[2..] are the profile states to put back
 *   probe     - verify we can change the firewall at all (exit 2 if
 *               not elevated)                                     */
int main (int argc, char **argv)
{
	const FsBackend *b = fs_backend ();
	GError *error = NULL;
	const gchar *cmd = (argc > 1) ? argv[1] : "get";

	g_print ("%s\n", state_name (b->get_state ()));

	if (g_strcmp0 (cmd, "get") == 0)
		return 0;

	if (g_strcmp0 (cmd, "getall") == 0) {
		gint i;
		for (i = 0; i < FS_PROFILE_COUNT; i++) {
			gboolean on = FALSE;
			b->get_profile_enabled (i, &on);
			g_print ("%d\n", on ? 1 : 0);
		}
		return 0;
	}

	if (g_strcmp0 (cmd, "probe") == 0) {
		gboolean on = FALSE;

		if (!b->get_profile_enabled (0, &on)) {
			fprintf (stderr, "cannot read profile 0\n");
			return 2;
		}
		/* Writing back the value it already has is a real test of
		 * permission without changing anything meaningful. */
		if (!b->set_profile_enabled (0, on, &error)) {
			fprintf (stderr, "not elevated: %s\n",
			         error ? error->message : "?");
			return 2;
		}
		return 0;
	}

	if (g_strcmp0 (cmd, "alloff") == 0) {
		if (!set_all (FALSE, &error)) {
			fprintf (stderr, "off: %s\n", error->message);
			return 1;
		}
	} else if (g_strcmp0 (cmd, "allon") == 0) {
		if (!set_all (TRUE, &error)) {
			fprintf (stderr, "on: %s\n", error->message);
			return 1;
		}
	} else if (g_strcmp0 (cmd, "oneoff") == 0) {
		gint i;
		for (i = 0; i < FS_PROFILE_COUNT; i++)
			if (!b->set_profile_enabled (i, i != FS_PROFILE_COUNT - 1,
			                             &error)) {
				fprintf (stderr, "mix: %s\n", error->message);
				return 1;
			}
	} else if (g_strcmp0 (cmd, "restore") == 0) {
		gint i;
		for (i = 0; i < FS_PROFILE_COUNT && i + 2 < argc; i++)
			if (!b->set_profile_enabled (i,
			                             g_strcmp0 (argv[i + 2],
			                                        "1") == 0, NULL))
				return 1;
	} else {
		fprintf (stderr, "unknown command: %s\n", cmd);
		return 64;
	}

	g_print ("%s\n", state_name (b->get_state ()));
	return 0;
}
EOF

CF="$(pkg-config --cflags gtk+-3.0 glib-2.0 gobject-2.0 gio-2.0)"
LF="$(pkg-config --libs gtk+-3.0 glib-2.0 gobject-2.0 gio-2.0 liblzma libcrypto json-glib-1.0)"

gcc -o "$BUILD_DIR/test-state" \
	-I "$PORT/src" $CF \
	"$BUILD_DIR/test-state.c" \
	"$PORT/src/platform/windows/fs-backend-windows.c" \
	"$PORT/src/platform/windows/fs-trust-win.c" \
	"$B/libfs-core.a" \
	$LF -lole32 -loleaut32 -liphlpapi -lws2_32 -lwintrust -lcrypt32 \
	2> "$BUILD_DIR/cc.log"

CHECK $? "test program compiles against the real Windows backend"

if [ ! -x "$BUILD_DIR/test-state" ]; then
	cat "$BUILD_DIR/cc.log"
	echo "FAIL: cannot continue without a test binary"
	exit 1
fi

T="$BUILD_DIR/test-state"

# GLib writes \r\n on Windows, so every value read back from the test
# binary has to be scrubbed before comparing or word-splitting.  Missing
# this once already left the firewall disabled after a test run.
strip_cr() { tr -d '\r'; }

# Helper: last line of a command's stdout is always the state.
state_of() { "$T" "$@" 2>/dev/null | tail -1 | strip_cr; }

# Helper: the profile states, as a whitespace-separated list.
profile_states() {
	"$T" getall 2>/dev/null | tail -n +2 | strip_cr | tr '\n' ' '
}

# ----------------------------------------------------------- elevation
if ! "$T" probe >/dev/null 2>&1; then
	echo "SKIP: shell is not elevated, so the firewall state cannot be"
	echo "      changed.  Re-run from an elevated MSYS2 shell."
	exit 0
fi
printf 'ok:   shell is elevated (firewall state can be changed)\n'

# ------------------------------------------------ save current settings
saved_state="$(state_of get)"
saved_profiles="$(profile_states)"
saved_profiles="$(printf '%s' "$saved_profiles" | xargs)"   # normalise
printf '     saved state: %s | profiles: [%s]\n' "$saved_state" "$saved_profiles"

# [ restore ]
# Puts the original per-profile settings back and then *verifies* they
# took.  A silent failure here would leave the machine with the firewall
# off, so it retries and, if that still fails, says so loudly enough to
# act on rather than quietly exiting 0.
restore() {
	local now try

	for try in 1 2; do
		# shellcheck disable=SC2086
		"$T" restore $saved_profiles >/dev/null 2>&1
		now="$(profile_states | xargs)"
		[ "$now" = "$saved_profiles" ] && return 0
	done

	printf '\n'
	printf '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n'
	printf '!! WARNING: could not restore the original firewall state.\n'
	printf '!! Saved:   [%s]\n' "$saved_profiles"
	printf '!! Current: [%s]\n' "$now"
	printf '!! Re-enable manually with an elevated shell:\n'
	printf '!!     netsh advfirewall set allprofiles state on\n'
	printf '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n'
	failures=$((failures + 1))
}
trap 'restore; rm -rf "$BUILD_DIR"' EXIT

# ------------------------------------------------------ all profiles off
if "$T" alloff >/dev/null 2>&1; then
	printf 'ok:   disabling every profile succeeds when elevated\n'
else
	printf 'FAIL: disabling every profile failed\n'
	failures=$((failures + 1))
fi
off_state="$(state_of get)"
CHECK $([ "$off_state" = "STOPPED" ]; echo $?) \
	"state reads STOPPED with every profile off (got $off_state)"

# ------------------------------------------------------ all profiles on
if "$T" allon >/dev/null 2>&1; then
	printf 'ok:   enabling every profile succeeds when elevated\n'
else
	printf 'FAIL: enabling every profile failed\n'
	failures=$((failures + 1))
fi
on_state="$(state_of get)"
CHECK $([ "$on_state" = "RUNNING" ]; echo $?) \
	"state reads RUNNING with every profile on (got $on_state)"

# ------------------------------------------------------------ a mix
if "$T" oneoff >/dev/null 2>&1; then
	printf 'ok:   setting a mix of profiles succeeds\n'
else
	printf 'FAIL: setting a mix of profiles failed\n'
	failures=$((failures + 1))
fi
mix_state="$(state_of get)"
CHECK $([ "$mix_state" = "RUNNING" ]; echo $?) \
	"state reads RUNNING while at least one profile filters (got $mix_state)"

# --------------------------------------- repeated stop does not drift
"$T" alloff >/dev/null 2>&1
off2_state="$(state_of get)"
CHECK $([ "$off2_state" = "STOPPED" ]; echo $?) \
	"repeating stop() still reports STOPPED, no drift (got $off2_state)"

# ------------------------------------------------- restore and re-check
restore
final_state="$(state_of get)"
CHECK $([ "$final_state" = "$saved_state" ]; echo $?) \
	"original firewall state restored (was $saved_state, now $final_state)"

echo
if [ "$failures" -eq 0 ]; then
	echo "PASSED: 0 failure(s)"
	exit 0
else
	echo "FAILED: $failures failure(s)"
	exit 1
fi

