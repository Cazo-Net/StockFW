# Experimental modules (not shipped)

These files came in with the 1.0.9 work. Nothing in the desktop app
(`StockFW`) or the command-line tool (`stockfw`) calls any of them, so
they are not compiled into either program and are not part of a release.
They are kept here so the work is not lost and can be finished one module
at a time.

Build and test them on request:

```sh
sudo apt install libjson-glib-dev      # the KEV reader needs json-glib
cmake -S port -B port/build-exp -G Ninja -DFS_EXPERIMENTAL=ON
ninja -C port/build-exp fs-experimental-tests
```

CI does this on Linux so they keep compiling, and runs their tests except
two: `test-psi-fuzz` (fails two checks) and `test-feed-sync` (starts a real
download from www.cisa.gov, which a test must not do).

## Status

"Placeholder" means the function exists but does not do what its name
says. Read this table before building anything on a module.

| Module | What it is today |
|---|---|
| `fs-quantum` | **Placeholder, no cryptography.** The key and signature functions refuse every call. (As written for 1.0.9 they returned random bytes as keys and accepted every signature.) The cipher-suite "audit" classifies a suite by words in its name; it inspects no connection. |
| `fs-quarantine` | **Do not use on real files.** `restore` writes the encrypted bytes back to the original path without decrypting them, and trusts a length field read from the vault file. |
| `fs-mesh` | Placeholder. Packets carry the literal signature `UNSIGNED_STUB`; verification is a string-prefix check. No transport. |
| `fs-l7` | Placeholder. The DNS and TLS SNI "inspection" is a simplified byte scan, not a protocol parser. |
| `fs-ml`, `fs-ml-model.h`, `fs-ml-engine` | Does not work as described. The generated tree thresholds are on a different scale from the quantised inputs (and the inputs are `gint8`), so many branches are always true; the "confidence" is a fixed 0.95 / 0.985. The model was trained on synthetic data only. |
| `fs-ml-monitor` | Drift (PSI) arithmetic. `tests/test-psi-fuzz.c` currently fails 2 checks, so it is left out of the CI run. |
| `fs-ebpf` | Generates a Tetragon `TracingPolicy` text and keeps an in-memory table. It loads nothing into the kernel. `src/ebpf/` (Rust) is not built by CMake or CI. |
| `fs-wfp` | Formats `netsh` / PowerShell command text. It runs nothing. Not compiled even with `FS_EXPERIMENTAL=ON` (Windows only, never built there). |
| `fs-kev`, `fs-feed-sync` | Reads the CISA KEV JSON and schedules a refresh. Not reviewed against hostile input; not connected to the Threat Intel page. |
| `fs-playbook` | Playbook and incident records. "Executing" a playbook records what it would do; it changes no firewall rule. |
| `fs-audit-ledger`, `fs-zero-trust` | Hash-chained log and token helpers with unit tests. Not connected to the program's audit log. |

## Moving a module into the program

1. Finish it, with tests that fail when it is wrong (not only when it crashes).
2. Move the files to `src/core/` and add them to `fs-core` in `CMakeLists.txt`.
3. Call it from the program, and only then describe it in the changelog and the docs.
