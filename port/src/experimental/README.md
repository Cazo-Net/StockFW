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

CI does this on Linux so they keep compiling (all but `fs-wfp.c` and
`fs-ml-engine.c`, which are in no build), and runs their tests except
two: `test-psi-fuzz` (fails two checks) and `test-feed-sync` (starts a real
download from www.cisa.gov, which a test must not do).

## Status

"Placeholder" means the function exists but does not do what its name
says. Read this table before building anything on a module.

| Module | What it is today |
|---|---|
| `fs-quantum` | **Placeholder, no cryptography.** The key and signature functions refuse every call. (As written for 1.0.9 they returned random bytes as keys, and verify accepted any signature of the right length without looking at the key or the message.) The cipher-suite "audit" classifies a suite by words in its name; it inspects no connection. |
| `fs-quarantine` | **Do not use on real files.** `restore` writes the encrypted bytes back to the original path without decrypting them, and trusts a length field read from the vault file. |
| `fs-mesh` | Placeholder. Packets carry the literal signature `UNSIGNED_STUB`; verification is a string-prefix check. No transport. |
| `fs-l7` | Placeholder. Neither function reads the packet: each returns a fixed sample name (`query.example.com`, `api.openai.com`). The DNS verdict depends only on the packet length (over 512 bytes), and the SNI check can never block. |
| `fs-ml`, `fs-ml-model.h`, `fs-ml-engine` | Does not work as described. The generated tree thresholds are on a different scale from the quantised inputs (and the inputs are `gint8`), so many branches are always true; the "confidence" is a fixed 0.95 / 0.985. The model was trained on synthetic data only. **Do not call `fs_ml_predict`:** the generated header adds to `logits[0..15]` of a 4-element array, so every call writes past the end of it. No test calls the scorer. `fs-ml-engine.c` is not compiled even with `FS_EXPERIMENTAL=ON`, and its self-test aborts for that reason. |
| `fs-ml-monitor` | Drift (PSI) arithmetic. `tests/test-psi-fuzz.c` currently fails 2 checks, so it is left out of the CI run. |
| `fs-ebpf` | Generates a Tetragon `TracingPolicy` text and keeps an in-memory table. It loads nothing into the kernel. `src/ebpf/` (Rust) is not built by CMake or CI. |
| `fs-wfp` | Formats `netsh` / PowerShell command text. It runs nothing. Not compiled even with `FS_EXPERIMENTAL=ON` (Windows only, never built there). |
| `fs-kev`, `fs-feed-sync` | Reads the CISA KEV JSON and schedules a refresh. Not reviewed against hostile input; not connected to the Threat Intel page. |
| `fs-playbook` | Playbook and incident records. "Executing" a playbook changes no firewall rule, but it writes lines to the program's audit log saying the actions were executed. |
| `fs-audit-ledger` | Hash-chained log with unit tests. The program's audit log does not feed it. |
| `fs-zero-trust` | Token and manifest helpers with unit tests. Two real side effects: `fs_zero_trust_contain_agent` kills the process ID it is given, and the module writes lines to the program's audit log. |

## Moving a module into the program

1. Finish it, with tests that fail when it is wrong (not only when it crashes).
2. Move the files to `src/core/` and add them to `fs-core` in `CMakeLists.txt`.
3. Call it from the program, and only then describe it in the changelog and the docs.
