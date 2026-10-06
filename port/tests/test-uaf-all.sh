#!/bin/bash
# Run the use-after-free analysis over every source file.
#
# This exists because fs-backend-null.c compiled for the first time
# only after this sweep was written: it had two copies of the same two
# functions and was never part of any build, so nothing had ever read
# it.  Files that are compiled are checked by the compiler; files that
# are not need something that looks at all of them.
#
#   ./tests/test-uaf-all.sh
#
# Each file is compiled and analysed in isolation.  A file that needs
# the other platform's headers is reported as SKIP and does not fail
# the run -- on Windows that is src/platform/linux/*, on Linux
# src/platform/windows/*.  Everything else must compile and be clean.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT=$(dirname "$HERE")

if [ -d /ucrt64/bin ]; then
	export PATH="/ucrt64/bin:$PATH"
fi

analysed=0
skipped=0
failed=0

for f in $(find "$PORT/src" -name '*.c' | sort); do
	name=${f#"$PORT/"}
	out=$(bash "$HERE/test-uaf-analyze.sh" "$f" "$name" 2>&1)
	rc=$?

	if [ "$rc" -ne 0 ]; then
		failed=$((failed + 1))
		echo "$out"
		echo
	elif printf '%s' "$out" | grep -q '^SKIP'; then
		skipped=$((skipped + 1))
		echo "skip: $name  ($(printf '%s' "$out" | grep -o "needs '[^']*'" | head -1))"
	else
		analysed=$((analysed + 1))
		echo "ok:   $name"
	fi
done

echo
echo "=== use-after-free sweep: $analysed analysed, $skipped skipped, $failed failed ==="

if [ "$failed" -gt 0 ]; then
	echo "FAILED: $failed file(s)"
	exit 1
fi

if [ "$analysed" -eq 0 ]; then
	# Passing without having looked at anything would be worthless.
	echo "FAILED: nothing was analysed"
	exit 1
fi

echo "PASSED: 0 failure(s)"
exit 0
