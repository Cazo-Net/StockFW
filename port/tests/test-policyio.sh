#!/bin/bash
# Portable policy import/export tests.  The exchange must preserve kind,
# fields and enabled state; malformed input must be reported without a partial
# policy, and merge/replace must be deterministic and duplicate-safe.
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
cd "$PORT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/test-policyio.c" <<'EOF'
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include "core/fs-rules.h"

static int failures;
#define CHECK(c, ...) do { \
	if (c) printf("ok: " __VA_ARGS__); \
	else { printf("FAIL: " __VA_ARGS__); failures++; } \
	printf("\n"); \
} while (0)

static guint total(const FsPolicy *p) {
	guint n = 0;
	for (gint k = 0; k < FS_RULE_N_KINDS; k++) n += p->kinds[k]->len;
	return n;
}

static FsRule *host(FsRuleKind kind, const gchar *target, gboolean enabled) {
	FsRule *r = fs_rule_new(kind);
	r->target = g_strdup(target);
	r->comment = g_strdup("policy io test");
	r->enabled = enabled;
	return r;
}

int main(void) {
	FsPolicy *source = fs_policy_new(), *parsed, *base, *bad;
	FsRule *r;
	GError *error = NULL;
	GPtrArray *problems = NULL;
	gchar *text;
	guint added = 0, duplicates = 0;

	r = host(FS_RULE_OUTBOUND_ALLOW_TO, "192.0.2.10", TRUE);
	fs_policy_add(source, r); fs_rule_free(r);
	r = host(FS_RULE_OUTBOUND_DENY_TO, "2001:db8::10", FALSE);
	fs_policy_add(source, r); fs_rule_free(r);
	r = fs_rule_new(FS_RULE_INBOUND_ALLOW_SERVICE);
	r->service = g_strdup("HTTPS"); r->port = g_strdup("443");
	r->target = g_strdup(FS_TARGET_ANY); r->comment = g_strdup("web");
	fs_policy_add(source, r); fs_rule_free(r);

	text = fs_policy_export_text(source, &error);
	CHECK(text != NULL && error == NULL, "export valid policy");
	CHECK(text != NULL && strchr(text, '\t') != NULL && strchr(text, '\n') != NULL,
	      "export uses real tab-delimited lines");
	CHECK(text != NULL && strstr(text, "outbound-deny-to\toff\t") != NULL,
	      "export preserves disabled state");
	parsed = fs_policy_import_parse(text, &problems, &error);
	CHECK(parsed != NULL && error == NULL && problems != NULL && problems->len == 0,
	      "parse exported policy without problems");
	CHECK(parsed != NULL && total(parsed) == total(source), "round trip preserves rule count");
	CHECK(parsed != NULL && parsed->kinds[FS_RULE_OUTBOUND_DENY_TO]->len == 1 &&
	      !((FsRule *)g_ptr_array_index(parsed->kinds[FS_RULE_OUTBOUND_DENY_TO], 0))->enabled,
	      "round trip preserves disabled rule");
	if (problems) g_ptr_array_unref(problems); problems = NULL;
	g_clear_error(&error);

	bad = fs_policy_import_parse("outbound-allow-to\ton\t192.0.2.1, good\n"
	                             "bogus\ton\t192.0.2.2\n"
	                             "outbound-deny-to\tmaybe\t192.0.2.3\n",
	                             &problems, &error);
	CHECK(bad != NULL && problems != NULL && problems->len == 2,
	      "parse reports every malformed exchange line");
	CHECK(bad != NULL && total(bad) == 1, "parser exposes only valid rows for diagnostics");
	fs_policy_free(bad);
	if (problems) g_ptr_array_unref(problems); problems = NULL;
	g_clear_error(&error);

	bad = fs_policy_import_parse("outbound-allow-to\ton\t999.0.0.1, bad host\n", NULL, &error);
	CHECK(bad == NULL && error != NULL, "strict parse rejects invalid host without problem array");
	fs_policy_free(bad); g_clear_error(&error);

	base = fs_policy_new();
	r = host(FS_RULE_OUTBOUND_ALLOW_TO, "192.0.2.10", TRUE);
	fs_policy_add(base, r); fs_rule_free(r);
	CHECK(fs_policy_merge(base, parsed, FALSE, &added, &duplicates, &error), "merge succeeds");
	CHECK(added == 2 && duplicates == 1 && total(base) == 3,
	      "merge adds unique rows and ignores existing duplicate");
	CHECK(fs_policy_merge(base, parsed, TRUE, &added, &duplicates, &error), "replace merge succeeds");
	CHECK(added == 3 && duplicates == 0 && total(base) == 3,
	      "replace merge replaces destination exactly");

	g_free(text);
	fs_policy_free(base);
	fs_policy_free(parsed);
	fs_policy_free(source);
	printf("%s: %d failure(s)\n", failures ? "FAILED" : "PASSED", failures);
	return failures ? 1 : 0;
}
EOF

EXTRA_LIBS=""
if [ "${OS:-}" = "Windows_NT" ] || [ -d /ucrt64 ]; then
  EXTRA_LIBS="-lws2_32 -liphlpapi -ladvapi32 -lshell32 -lole32 -loleaut32"
fi
# shellcheck disable=SC2086
cc "$TMP/test-policyio.c" -I src \
  $(pkg-config --cflags glib-2.0 gio-2.0 liblzma libcrypto json-glib-1.0) \
  -o "$TMP/test-policyio" src/core/*.c \
  $(pkg-config --libs glib-2.0 gio-2.0 liblzma libcrypto json-glib-1.0) $EXTRA_LIBS
"$TMP/test-policyio"
