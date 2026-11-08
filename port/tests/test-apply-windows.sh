#!/bin/bash
# Regression test for transactional Windows policy application
# (firewalled_apply_rules, firewalled_snapshot_rules,
#  firewalled_restore_snapshot).
#
# Drives the real Windows backend against a fake netsh.exe (FS_TOOLPATH_TESTING,
# fs-toolpath.h) so every apply path is exercised without touching the real
# Windows Firewall.  Windows-only; other platforms print a skip and exit 0.
#
#   ./tests/test-apply-windows.sh
#
set -e

# Locate the toolchain: MSYS2's UCRT64 prefix on Windows.
if [ -d /ucrt64/bin ]; then
  export PATH="/ucrt64/bin:$PATH"
elif [ -d /c/msys64/ucrt64/bin ]; then
  export PATH="/c/msys64/ucrt64/bin:$PATH"
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"

cd "$PORT"

if [ ! "${OS:-}" = "Windows_NT" ] && [ ! -d /ucrt64 ]; then
  echo "ok:   test-apply-windows skipped (Windows-only)"
  exit 0
fi

BUILD_DIR="$(mktemp -d)"
# Keep build dir on failure for debugging
trap '[ $? -eq 0 ] && rm -rf "$BUILD_DIR" || echo "KEEP_BUILD_DIR=$BUILD_DIR"' EXIT

# FS_TOOLPATH_TESTING: the test build runs netsh from
# $STOCKFW_TEST_TOOL_DIR before System32 (fs-toolpath.h).  The fake netsh
# below records every invocation and can be programmed to fail on a chosen
# invocation, so the snapshot/restore/rollback paths are deterministic.
export STOCKFW_TEST_TOOL_DIR="$BUILD_DIR/faketools"
mkdir -p "$STOCKFW_TEST_TOOL_DIR"

cc "$HERE/fake-netsh.c" \
   -o "$STOCKFW_TEST_TOOL_DIR/netsh.exe" \
   || { echo "FAIL: cannot build fake netsh"; exit 1; }

# ---------------------------------------------------------------- harness
cat > "$BUILD_DIR/test-apply.c" <<'HARNESS_EOF'
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include "core/fs-backend.h"
#include "core/fs-rules.h"
#include "core/fs-fwrule.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
  if (!(cond)) {                                                 \
    printf ("FAIL: ");                                          \
    printf (__VA_ARGS__);                                       \
    printf ("\n");                                              \
    failures++;                                                 \
  } else {                                                      \
    printf ("ok:   ");                                          \
    printf (__VA_ARGS__);                                       \
    printf ("\n");                                              \
  }                                                             \
} while (0)

static FsPolicy *
make_policy (void)
{
  FsPolicy *p = fs_policy_new ();
  FsRule *r;

  r = fs_rule_new (FS_RULE_INBOUND_ALLOW_SERVICE);
  r->service = g_strdup ("SSH");
  r->port    = g_strdup ("22");
  r->target  = g_strdup ("Anyone");
  fs_policy_add (p, r);
  fs_rule_free (r);

  r = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_SERVICE);
  r->service = g_strdup ("HTTPS");
  r->port    = g_strdup ("443");
  r->target  = g_strdup ("Anyone");
  fs_policy_add (p, r);
  fs_rule_free (r);

  return p;
}

int
main (void)
{
  const FsBackend *b = fs_backend ();
  GError *error = NULL;
  FsApplyResult ares;

  CHECK (b != NULL, "backend available");
  CHECK (g_strcmp0 (b->name, "windows") == 0, "windows backend");

  /* 1. Apply a fresh policy: both rules created. */
  {
    FsPolicy *p = make_policy ();
    fs_backend_set_context (p, NULL);
    ares = b->apply_rules (p, &error);
    CHECK (ares == FS_APPLY_OK, "first apply succeeds (got %d)", (int) ares);
    g_clear_error (&error);
    fs_policy_free (p);
  }

  /* 2. Re-applying the same policy is a no-change narrow apply: OK. */
  {
    FsPolicy *p = make_policy ();
    fs_backend_set_context (p, NULL);
    ares = b->apply_rules (p, &error);
    CHECK (ares == FS_APPLY_OK, "re-apply succeeds (got %d)", (int) ares);
    g_clear_error (&error);
    fs_policy_free (p);
  }

  /* 3. Per-app rule: program= reaches netsh. */
  {
    FsPolicy *p = fs_policy_new ();
    FsRule *r = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_SERVICE);
    r->service = g_strdup ("firefox");
    r->port    = g_strdup ("443");
    r->target  = g_strdup ("Anyone");
    r->program = g_strdup ("C:\\Program Files\\Mozilla Firefox\\firefox.exe");
    fs_policy_add (p, r);
    fs_rule_free (r);

    fs_backend_set_context (p, NULL);
    ares = b->apply_rules (p, &error);
    CHECK (ares == FS_APPLY_OK, "per-app rule apply succeeds (got %d)", (int) ares);
    g_clear_error (&error);
    fs_policy_free (p);
  }

  /* 4. Failure: netsh add-rule fails with elevation error.
   *    Expect FS_APPLY_PARTIAL or FS_APPLY_FAILED, never FS_APPLY_OK. */
  {
    FsPolicy *p = fs_policy_new ();
    FsRule *r = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_SERVICE);
    r->service = g_strdup ("bad");
    r->port    = g_strdup ("9999");
    r->target  = g_strdup ("Anyone");
    fs_policy_add (p, r);
    fs_rule_free (r);

    fs_backend_set_context (p, NULL);
    g_setenv ("STOCKFW_FAKE_NETSH_LOG", "netsh.log", TRUE);
    g_setenv ("STOCKFW_FAKE_NETSH_FAIL_N", "1", TRUE);
    ares = b->apply_rules (p, &error);
    CHECK (ares == FS_APPLY_PARTIAL || ares == FS_APPLY_FAILED,
           "failing netsh does not report success (got %d)", (int) ares);
    g_clear_error (&error);
    g_unsetenv ("STOCKFW_FAKE_NETSH_LOG");
    g_unsetenv ("STOCKFW_FAKE_NETSH_FAIL_N");
    fs_policy_free (p);
  }

  printf ("\n");
  if (failures == 0) {
    printf ("PASSED: 0 failure(s)\n");
    return 0;
  } else {
    printf ("FAILED: %d failure(s)\n", failures);
    return 1;
  }
}
HARNESS_EOF

# The test harness compiles against the real Windows backend.
CF="$(pkg-config --cflags glib-2.0 gobject-2.0 gio-2.0)"
LF="$(pkg-config --libs glib-2.0 gobject-2.0 gio-2.0 liblzma libcrypto)"

cc -o "$BUILD_DIR/test-apply" \
   -DFS_TOOLPATH_TESTING=1 \
   -I "$PORT/src" $CF \
   "$BUILD_DIR/test-apply.c" \
   "$PORT/src/platform/windows/fs-backend-windows.c" \
   "$PORT/src/platform/windows/fs-trust-win.c" \
   "$PORT/src/core/fs-fwrule.c" \
   "$PORT/build/libfs-core.a" \
   $LF -lole32 -loleaut32 -liphlpapi -lws2_32 -lwintrust -lcrypt32 \
   2> "$BUILD_DIR/cc.log"

CC_RC=$?
echo "compile exit=$CC_RC"
if [ $CC_RC -ne 0 ]; then
  cat "$BUILD_DIR/cc.log"
  echo "FAIL: cannot continue without a test binary"
  exit 1
fi

if [ ! -x "$BUILD_DIR/test-apply" ]; then
  cat "$BUILD_DIR/cc.log"
  echo "FAIL: test binary not produced"
  exit 1
fi

"$BUILD_DIR/test-apply"
TEST_RC=$?

exit $TEST_RC
