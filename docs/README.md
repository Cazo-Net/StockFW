# StockFW documentation

Every document in the repository, by what you want to do. The
maintained code is in [`port/`](../port/); the top-level autotools files,
`src/`, `po/` and the rest are the legacy GPL tree, kept and not built
(see the root [README](../README.md#start-here)).

## Use StockFW

| Document | What it covers |
|---|---|
| [`README.md`](../README.md) | Features, the backends, threat intel, countries and networks, background mode, building. |
| [`port/installer/linux/README.md`](../port/installer/linux/README.md) | The Linux tarball: install, the boot service, the command line, uninstall, building the package. |
| [`port/docs/ELEVATED.md`](../port/docs/ELEVATED.md) | Starting StockFW with administrator rights on Windows. |
| [`CHANGELOG.md`](../CHANGELOG.md) | What changed in each release. |
| The website, `site/` | The same material for users, built by `site/build.py`. |

The app has its own Help window (F1), compiled in from
`port/src/core/fs-helpcontent.c`. The command-line tool prints the
same topics (`stockfw help topics`, and the page `stockfw-topics(7)`).

## Understand and change it

| Document | What it covers |
|---|---|
| [`ARCHITECTURE-AND-SECURITY.md`](ARCHITECTURE-AND-SECURITY.md) | The architecture and security document: data flow, both backends, the privilege model with file:line evidence, the findings register, measurements. One addendum chapter per release (Chapter 14 is 1.0.7). |
| [`PORTING.md`](PORTING.md) | Porting notes and the build prerequisites on Windows and Linux. |
| [`port/tests/README.md`](../port/tests/README.md) | Every test suite, what it checks, and the teeth that prove each check can fail. |

## Release it

| Document | What it covers |
|---|---|
| [`RELEASING.md`](../RELEASING.md) | Version bump, CI, the tag, the assets and their checksums, the release notes. |
| [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | What CI builds and tests on Linux and Windows, and the artifacts it keeps. |

## Design notes (historical)

Written before the work they describe and kept as the record of what was
planned. Where they differ from the code, the architecture document is
right.

| Document | What it covers |
|---|---|
| [`design/1.0.6-graph-research.md`](design/1.0.6-graph-research.md) | Research for the 1.0.6 Activity graphs. |
| [`design/1.0.7-threat-intel-design.md`](design/1.0.7-threat-intel-design.md) | The threat-intel and location-database design, with its review findings. |
