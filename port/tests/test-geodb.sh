#!/bin/bash
# The location database reader (src/core/fs-geodb.c, 1.0.7 design
# section 12) against libloc itself, IPFire's own database, the xz tool,
# the downloader and a coverage-guided fuzzer.
#
#   tests/test-geodb.sh            everything below
#   tests/test-geodb.sh --regen    rewrite tests/geodb (new test keys)
#
# Driver: fs-geodb-test (ninja -C build-linux fs-geodb-test); another
# build of it can be named with FS_GEODB_TEST=/path/to/fs-geodb-test.
# Needs python3-location (libloc's Python binding) and `location' for
# the libloc parts, libloc-database for IPFire's file, xz, openssl, and
# clang with libFuzzer (libclang-rt-dev) for the fuzzer; each part
# SKIPs without its tool, unless STOCKFW_GEODB_REQUIRE=1 (CI), which
# makes a missing tool a FAIL.  FUZZ_SECONDS (default 180) is how long
# the fuzzer runs.  No network: the download is a stand-in for curl.
#
# What it proves:
#   - the suite (fs-geodb-test) passes on fixtures made just now by
#     libloc's writer with keys made just now, not only on the committed
#     ones; and the committed fixtures are what the generator writes
#     (byte for byte past the signatures, answers identical);
#   - libloc's `location verify' accepts what the test signer signs, in
#     either slot, and refuses it with another key or one byte changed:
#     the signature rule the reader checks is the format's;
#   - IPFire's own database (2022-10-29, libloc-database) agrees with
#     libloc address by address (8,000 lookups: network boundaries and
#     random addresses) and filter by filter (12 flattened searches),
#     verified with the pinned key; `location lookup' says the same for
#     a few well-known addresses;
#   - xz -9e of a database installs through fs_geodb_update with the
#     real downloader (fs_fetch, curl replaced by a stand-in that serves
#     the file): one request, for FS_GEODB_URL, no proxy unless given;
#   - libFuzzer, with AddressSanitizer and UBSan, finds nothing in
#     FUZZ_SECONDS, starting from every fixture;
#   - release builds carry no test hook: the release object of
#     fs-geodb.c names no fs_geodb_testing_* function.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="$(dirname "$HERE")"
DRV="${FS_GEODB_TEST:-${STOCKFW_BUILD:-$PORT/build-linux}/fs-geodb-test}"
REQUIRE="${STOCKFW_GEODB_REQUIRE:-0}"
REAL_DB="${STOCKFW_GEODB_REAL:-/usr/share/libloc-location/location.db}"

W="$(mktemp -d)"
cleanup() { rm -rf "$W"; }
trap cleanup EXIT

fails=0
ok()    { echo "ok:   $*"; }
bad()   { echo "FAIL: $*"; fails=$((fails + 1)); }
check() { if eval "$1"; then ok "$2"; else bad "$2"; fi; }
skip()  {
  if [ "$REQUIRE" = 1 ]; then bad "$* (STOCKFW_GEODB_REQUIRE=1)"
  else echo "SKIP: $*"; fi
}

# python3-location is built for one Python; find the one that has it.
PY=""
for p in python3 python3.13 python3.12 python3.11 /usr/bin/python3.12; do
  if command -v "$p" >/dev/null 2>&1 &&
     "$p" -W ignore -c 'import location' >/dev/null 2>&1; then
    PY="$(command -v "$p")"
    break
  fi
done
loc() { "$PY" -W ignore /usr/bin/location "$@"; }

# libloc's writer stamps time(NULL); the shim makes it $FAKE_TIME.
build_shim() {
  cc -shared -fPIC -o "$W/faketime.so" "$HERE/geodb-faketime.c"
}

newkey() {   # newkey NAME: $W/NAME.pem (private) and $W/NAME.pub
  openssl ecparam -name secp521r1 -genkey -noout -out "$W/$1.pem" 2>/dev/null &&
  openssl ec -in "$W/$1.pem" -pubout -out "$W/$1.pub" 2>/dev/null
}

fixtures() {  # fixtures OUTDIR: the generator, with new keys k1 and k2
  newkey k1 && newkey k2 && build_shim &&
  LD_PRELOAD="$W/faketime.so" "$PY" -W ignore "$HERE/geodb-fixtures.py" \
    "$1" "$W/k1.pem" "$W/k2.pem" &&
  cp "$W/k1.pub" "$W/k2.pub" "$1/"
}

if [ "${1:-}" = --regen ]; then
  [ -n "$PY" ] || { echo "needs python3-location"; exit 1; }
  fixtures "$W/fx" || exit 1
  rm -f "$HERE"/geodb/*
  cp "$W"/fx/* "$HERE/geodb/"
  echo "tests/geodb rewritten (private keys discarded)"
  exit 0
fi

if [ ! -x "$DRV" ]; then
  ninja -C "${STOCKFW_BUILD:-$PORT/build-linux}" fs-geodb-test >/dev/null || {
    echo "FAIL: cannot build fs-geodb-test"; exit 1; }
fi

# ------------------------------------------------------------------ suite
echo "== the suite on the committed fixtures"
if "$DRV" "$HERE/geodb" > "$W/suite.log" 2>&1; then
  ok "fs-geodb-test tests/geodb: $(tail -2 "$W/suite.log" | head -1)"
else
  grep -E '^FAIL' "$W/suite.log"
  bad "fs-geodb-test tests/geodb"
fi

echo "== fixtures made now, by libloc's writer, with keys made now"
if [ -z "$PY" ]; then
  skip "python3-location is not installed (apt install python3-location)"
elif ! fixtures "$W/fx" > "$W/gen.log" 2>&1; then
  cat "$W/gen.log"
  bad "the fixture generator runs"
else
  ok "the fixture generator runs"
  if STOCKFW_GEODB_MUTATIONS=1000 "$DRV" "$W/fx" > "$W/fresh.log" 2>&1; then
    ok "fs-geodb-test on them: $(tail -2 "$W/fresh.log" | head -1)"
  else
    grep -E '^FAIL' "$W/fresh.log"
    bad "fs-geodb-test on fresh fixtures"
  fi
  same=1
  for f in "$HERE"/geodb/*.tsv "$HERE"/geodb/*.txt; do
    b="$(basename "$f")"
    if ! cmp -s "$f" "$W/fx/$b"; then echo "      differs: $b"; same=0; fi
  done
  check '[ $same -eq 1 ]' \
    "the committed answers (.lookup.tsv, .enum.txt, .meta.txt) are what the generator writes"
  same=1
  for f in "$HERE"/geodb/*.db; do
    b="$(basename "$f")"
    if ! cmp -s <(head -c 68 "$f") <(head -c 68 "$W/fx/$b") ||
       ! cmp -s <(tail -c +4201 "$f") <(tail -c +4201 "$W/fx/$b"); then
      echo "      differs: $b"; same=0
    fi
  done
  check '[ $same -eq 1 ]' \
    "the committed databases are the generator's, byte for byte but for the signatures"
fi

# --------------------------------------------------------- libloc verify
echo "== libloc's verify and the test signer"
if [ -z "$PY" ] || [ ! -x /usr/bin/location ]; then
  skip "location (libloc's tool) is not installed (apt install location)"
else
  newkey s1 && newkey s2
  "$DRV" resign "$HERE/geodb/small.db" "$W/s1.db" "$W/s1.pem" 1
  "$DRV" resign "$HERE/geodb/small.db" "$W/s2.db" "$W/s1.pem" 2
  check 'loc -d "$HERE/geodb/small.db" -k "$HERE/geodb/k1.pub" verify >/dev/null 2>&1' \
    "control: location verify accepts small.db, as libloc's writer signed it, with key 1"
  check 'loc -d "$W/s1.db" -k "$W/s1.pub" verify >/dev/null 2>&1' \
    "location verify accepts small.db re-signed by the test signer (slot 1)"
  check 'loc -d "$W/s2.db" -k "$W/s1.pub" verify >/dev/null 2>&1' \
    "location verify accepts it signed in slot 2 only"
  check '! loc -d "$W/s1.db" -k "$W/s2.pub" verify >/dev/null 2>&1' \
    "location verify refuses it with another key"
  cp "$W/s1.db" "$W/s1-bad.db"
  printf '\001' | dd of="$W/s1-bad.db" bs=1 seek=5000 conv=notrunc 2>/dev/null
  check '! loc -d "$W/s1-bad.db" -k "$W/s1.pub" verify >/dev/null 2>&1' \
    "location verify refuses it with one byte changed past the header"
  check '"$DRV" info "$W/s1.db" "$W/s1.pub" >/dev/null 2>&1 &&
         ! "$DRV" info "$W/s1-bad.db" "$W/s1.pub" >/dev/null 2>&1' \
    "fs-geodb agrees on both"
fi

# ------------------------------------------------------ IPFire's database
echo "== IPFire's own database against libloc"
if [ ! -f "$REAL_DB" ]; then
  skip "no IPFire database at $REAL_DB (apt install libloc-database)"
elif [ -z "$PY" ]; then
  skip "python3-location is not installed"
else
  mkdir -p "$W/real"
  cp "$REAL_DB" "$W/real/real.db"
  if "$PY" -W ignore "$HERE/geodb-fixtures.py" --reference "$REAL_DB" \
       "$W/real" real 1077 4000 > "$W/ref.log" 2>&1; then
    if "$DRV" golden "$W/real" real pinned > "$W/real.log" 2>&1; then
      grep '^ok' "$W/real.log"
      ok "IPFire's database: every lookup and enumeration agrees with libloc"
    else
      grep -E '^(FAIL|      )' "$W/real.log" | head -20
      bad "IPFire's database agrees with libloc"
    fi
  else
    cat "$W/ref.log"
    bad "libloc's answers for IPFire's database"
  fi
  printf '8.8.8.8\n1.1.1.1\n2a00:1450::1\n2606:4700::1\n' > "$W/addrs"
  "$DRV" lookup-tsv "$REAL_DB" pinned "$W/addrs" > "$W/ours.tsv"
  same=1
  while IFS=$'\t' read -r addr status net cc asn _flags _name; do
    out="$(loc -d "$REAL_DB" lookup "$addr" 2>/dev/null)"
    if [ "$status" != found ] ||
       ! grep -q "Network *: $net\$" <<<"$out" ||
       ! grep -q "Autonomous System *: AS$asn " <<<"$out"; then
      echo "      $addr: ours $status $net $cc AS$asn"; echo "$out"; same=0
    fi
  done < "$W/ours.tsv"
  check '[ $same -eq 1 ] && [ "$(wc -l < "$W/ours.tsv")" -eq 4 ]' \
    "\`location lookup' gives the same network and AS for 8.8.8.8, 1.1.1.1, 2a00:1450::1 and 2606:4700::1"
fi

# --------------------------------------------------- xz and the download
echo "== xz -9e through fs_geodb_update and the real downloader"
if ! command -v xz >/dev/null; then
  skip "xz is not installed"
else
  # curl runs as nobody when we are root: everything it reads is
  # world-readable, its log directory world-writable.
  D="$W/dl"
  mkdir -p "$D/store" "$D/log"
  chmod 755 "$W" "$D"
  chmod 777 "$D/log"
  xz -9e -c "$HERE/geodb/small.db" > "$D/small.db.xz"
  chmod 644 "$D/small.db.xz"
  cat > "$D/curl" <<EOF
#!/bin/sh
for a in "\$@"; do printf '%s\n' "\$a"; done > "$D/log/argv.\$\$"
exec cat "$D/small.db.xz"
EOF
  chmod 755 "$D/curl"
  out="$(STOCKFW_TEST_CURL="$D/curl" "$DRV" update "$D/store" "$HERE/geodb/k1.pub" 2>&1)"
  echo "      $out"
  check '[ "${out%%	*}" = UPDATED ] && cmp -s "$D/store/location.db" "$HERE/geodb/small.db"' \
    "the download installs, byte for byte small.db"
  check '[ "$(ls "$D/log" | wc -l)" -eq 1 ] &&
         grep -qx -- "--url" "$D"/log/argv.* &&
         grep -qxF "https://location.ipfire.org/databases/1/location.db.xz" "$D"/log/argv.* &&
         grep -qx -- "--noproxy" "$D"/log/argv.*' \
    "one request, for https://location.ipfire.org/databases/1/location.db.xz, no proxy"
  check 'grep -qx -- "--max-filesize" "$D"/log/argv.* && grep -qx 67108864 "$D"/log/argv.*' \
    "curl is told the 64 MiB cap"
  out="$(STOCKFW_TEST_CURL="$D/curl" "$DRV" update "$D/store" "$HERE/geodb/k1.pub" http://proxy.test:3128 2>&1)"
  check '[ "${out%%	*}" = UNCHANGED ] && grep -qx "http://proxy.test:3128" $(ls -t "$D"/log/argv.* | head -1)' \
    "the same file again: UNCHANGED; a proxy given is passed to curl"
  ls -A "$D/store" > "$D/left"
  check '[ "$(cat "$D/left")" = location.db ]' "nothing else is left in the store"
fi

# ------------------------------------------------------------- the fuzzer
echo "== libFuzzer, AddressSanitizer and UBSan, ${FUZZ_SECONDS:-180} s"
if ! command -v clang >/dev/null; then
  skip "clang is not installed"
elif ! clang -g -O1 -fsanitize=fuzzer,address,undefined \
         -fno-sanitize-recover=undefined -DFS_GEODB_TESTING=1 \
         -I "$PORT/src" $(pkg-config --cflags glib-2.0 gio-2.0 liblzma libcrypto) \
         -o "$W/fuzz-geodb" "$HERE/fuzz-geodb.c" "$PORT"/src/core/*.c \
         $(pkg-config --libs glib-2.0 gio-2.0 liblzma libcrypto) \
         > "$W/fuzz-cc.log" 2>&1; then
  if grep -q -e 'libclang_rt.fuzzer' -e 'fuzzer.*not found' "$W/fuzz-cc.log"; then
    skip "clang has no libFuzzer runtime (apt install libclang-rt-dev)"
  else
    head -20 "$W/fuzz-cc.log"; bad "the fuzzer builds"
  fi
else
  mkdir -p "$W/corpus"
  ASAN_OPTIONS=detect_leaks=1:intercept_strstr=0 \
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
    "$W/fuzz-geodb" -max_total_time="${FUZZ_SECONDS:-180}" -max_len=131072 \
    -rss_limit_mb=4096 -timeout=10 -artifact_prefix="$W/" -print_final_stats=1 \
    "$W/corpus" "$HERE/geodb" > "$W/fuzz.log" 2>&1
  rc=$?
  grep -E '^stat::number_of_executed_runs|^stat::peak_rss_mb|cov:' "$W/fuzz.log" | tail -3 | sed 's/^/      /'
  if [ $rc -ne 0 ]; then
    grep -E 'ERROR|SUMMARY|runtime error|==' "$W/fuzz.log" | head -20
    ls "$W"/crash-* "$W"/leak-* "$W"/timeout-* 2>/dev/null
    mkdir -p "${STOCKFW_BUILD:-$PORT/build-linux}/geodb-fuzz-findings" 2>/dev/null &&
      cp "$W"/crash-* "$W"/leak-* "$W"/timeout-* "$W"/oom-* \
         "${STOCKFW_BUILD:-$PORT/build-linux}/geodb-fuzz-findings/" 2>/dev/null
  fi
  check '[ $rc -eq 0 ]' \
    "the fuzzer ran ${FUZZ_SECONDS:-180} s and found nothing (findings would be kept in build-linux/geodb-fuzz-findings)"
fi

# ------------------------------------------------- no test hook in release
echo "== release builds have no test hook"
B="$(dirname "$DRV")/CMakeFiles"
hook() { nm "$1" 2>/dev/null | grep -q fs_geodb_testing_; }
if [ -f "$B/fs-geodb-test.dir/src/core/fs-geodb.c.o" ]; then
  check 'hook "$B/fs-geodb-test.dir/src/core/fs-geodb.c.o"' \
    "control: the test build's fs-geodb.c.o does define fs_geodb_testing_*"
  check '[ -f "$B/fs-core-nogui.dir/src/core/fs-geodb.c.o" ] && ! hook "$B/fs-core-nogui.dir/src/core/fs-geodb.c.o"' \
    "the release fs-geodb.c.o (fs-core-nogui) has no fs_geodb_testing_*"
  if [ -f "$B/fs-core.dir/src/core/fs-geodb.c.o" ]; then
    check '! hook "$B/fs-core.dir/src/core/fs-geodb.c.o"' \
      "the release fs-geodb.c.o (fs-core, the app's) has no fs_geodb_testing_*"
  fi
else
  echo "      ($DRV is not in a CMake build tree: the objects were not checked)"
fi

echo
if [ $fails -eq 0 ]; then echo "PASSED: 0 failure(s)"; else echo "FAILED: $fails failure(s)"; fi
[ $fails -eq 0 ]
