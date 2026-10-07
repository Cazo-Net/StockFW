# StockFW

**Smart firewall configuration tool with a local AI copilot.**
GTK3 · Windows and Linux · status, live events, policy editing, and an
assistant that explains and proposes rules — entirely offline.

StockFW makes a stock OS firewall *legible*: policy as a readable, diffable
CSV; events as a classified, searchable stream; advanced knobs in one
dialog; and an assistant layer that can answer "why is this blocked?" and
"what would this rule do?" without a shell prompt.

## Features

- **Status** — real profile state at a glance: on Windows the three
  firewall profiles (Domain, Private, Public) with enable/disable, on
  Linux the filter-table posture. The app's logo is embedded in the
  executable, so an installed copy and a development build render
  identically. Icons are real GTK stock/themed icons — no emoji, ever.
- **Events** — a live, deduplicated event stream. On Windows: Security
  log 5156/5157 (connection allowed/blocked) parsed from
  `wevtutil /f:text`, polled every 5 seconds with a batch cap. On Linux:
  kernel drop logging. Rows are classified, searchable, and the list is a
  window over the OS log — the OS log remains the archive.
- **Policy** — add / edit / duplicate / delete rules with **round-trip
  CSV save/load**: what you save is what loads back, typed and validated
  (ports, addresses, protocols checked fail-closed).
- **Copilot** — a **local, deterministic** rule parser. It reads what you
  typed, proposes the exact firewall rule it would install, shows it in a
  Yes/No dialog before anything is written, is **allow-only** (it can
  never silently open more than you approve), and rolls back if the save
  fails. **No LLM, no network, no telemetry.**
- **Preferences** — what you see is what you save: pages that do not
  apply to the current backend are not shown, so there are no dead
  settings that silently do nothing.

## Backends

| | Windows | Linux |
|---|---|---|
| Rule application | `netsh advfirewall` | `iptables` (argv, no shell) |
| Event source | Security log 5156/5157 | kernel log |
| Profiles | Domain / Private / Public per-profile state | filter table |
| Build | MSYS2 (UCRT64) | CMake + Ninja (Debian/Kali/WSL2) |

## Privilege model (summary)

StockFW runs **asInvoker** — it never silently self-elevates. All
elevation is explicit and fail-loud: operations that need admin surface a
clear error instead of half-applying; the elevated helper shares no
injected environment module; temp files are share-locked; strings passed
back to the shell are quoted with a strict inverse-quoting check. The
full property-by-property verification (ten properties, file:line
evidence) is in
[`docs/ARCHITECTURE-AND-SECURITY.md`](docs/ARCHITECTURE-AND-SECURITY.md)
Chapter 5.

## Build

### Windows (MSYS2, UCRT64)

```sh
pacman -S --needed base-devel \
    mingw-w64-ucrt-x86_64-{toolchain,gtk3,pkg-config,ninja,cmake}

cd port
cmake -S . -B build -G Ninja
cmake --build build
./build/StockFW.exe
```

Run the toolchain from the UCRT64 shell.

### Linux (Debian / Kali / WSL2)

```sh
sudo apt install build-essential cmake ninja-build libgtk-3-dev

cd port
cmake -S . -B build-linux -G Ninja
cmake --build build-linux
./build-linux/StockFW
```

### Installer (Windows, NSIS)

```sh
cd port/installer
./build_installer.sh
```

The installer bundles the full GTK3 runtime and the spawn helpers into
`$INSTDIR` and fails the build if any staged launcher still carries the
old branding.

## Tests

Every claim in the documentation is graded `[Verified]` / `[Measured]` /
`[Roadmap]` and maps to something you can run:

```sh
cd port
bash tests/test-core.sh              # rule engine, CSV round-trip, copilot
bash tests/test-winlog.sh            # Security-log parsing + dedup
bash tests/test-logstart.sh          # event stream start-up
bash tests/test-installer-spawn.sh   # staged spawn helpers
bash tests/test-state-windows.sh     # per-profile backend compile
bash tests/test-uaf-analyze.sh       # analyzer proves the UAF fix

ninja -C build fs-ui-smoke fs-hitview-smoke
./build/fs-ui-smoke                  # UI wiring smoke
./build/fs-hitview-smoke             # hit-view rendering smoke
```

The suites include *teeth* tests: known bugs are re-injected to prove the
test fails, then removed to prove it passes again — a green suite that
cannot fail is not a green suite.

## Documentation

- [`docs/ARCHITECTURE-AND-SECURITY.md`](docs/ARCHITECTURE-AND-SECURITY.md)
  — full architecture and security document: data flow, backends,
  privilege model with file:line evidence, findings register,
  measurements (150 s memory soak), roadmap.
- [`docs/PORTING.md`](docs/PORTING.md) — porting notes and prerequisites.
- [`port/docs/ELEVATED.md`](port/docs/ELEVATED.md) — the elevated helper
  protocol.

## License

The repository currently carries two license texts: root `LICENSE`
(Apache-2.0) and root `COPYING` (GPLv2, inherited). Which license
governs which portions is an open provenance-review item, tracked in
Chapter 10 of the architecture document. Contributions are accepted under
the license ultimately declared for their portion.

## Credits

- **Qusai Fethalrahman** \<Qusaifox2@gmail.com\> — Creator & Original
  Developer
- **H3xCore** — Developer
- **StockFW Project** — GTK3 port, Windows backend, Copilot
