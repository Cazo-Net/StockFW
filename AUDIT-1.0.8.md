# StockFW 1.0.8 Engineering Audit Report

**Branch:** `develop/1.0.8` (from `main` @ `001cc01`)
**Working tree:** clean before branch (`.claude/` untracked only)
**Tags:** v1.0.3–v1.0.7 exist; v1.0.7 is the latest GitHub release (05 Nov 2026)
**Version in `port/CMakeLists.txt`:** 1.0.7

## 1. Version / release state

- `main` is at `001cc01` "Add Policy CSV import and export (Patch 0003)" — one commit ahead of the v1.0.7 tag.
- `git diff --stat main v1.0.7` shows the delta is almost entirely `site/` (website docs) — **no source diff** between main and v1.0.7 in `port/`.
- So the **1.0.7 release tag already contains what `main` has in `port/`** (What-If, Copilot, Sentinel, threat-intel, geo, tray/background, prefs, CLI, dashboard, event history). The competitive memo's claim that 1.0.7 is "still on branches" is outdated for the source tree.

## 2. Two source trees (confirmed)

- Top-level `src/`, `configure.in`, `Makefile.am`, etc. = **legacy GPL/autotools tree**, not built.
- `port/` = active CMake/Ninja tree (GTK3 app + `stockfw` CLI + both backends + installers + tests).

## 3. Rule model audit (the per-app rules gap)

`port/src/core/fs-rules.h` `FsRule`:
```
kind, service, port, target, to, to_port, comment, enabled
```
**No `program` field.**

`port/src/core/fs-fwrule.h` `FsFwRule`:
```
name, direction, action, protocol, local_ports, local_address,
remote_ports, remote_address, forward, forward_address
```
**No program/application field.**

`port/src/core/fs-types.h` `FsHit`:
```
time, direction, in, out, port, source, destination, length, tos,
protocol, service, rule
```
**No full executable path.** `fs-winevt.c` `make_hit()` extracts the `Application` XML field, keeps only the basename in `hit->service`, and **drops the full path** (lines 274–282).

CSV contract (`fs-rules.c` `columns_for`/`fs_rule_to_csv`/`fs_rule_from_csv`): one file per rule kind, unquoted CSV. Adding a column changes the on-disk contract — needs a backward-compatible strategy (new column appended last, old rows without it load fine).

## 4. Windows apply path audit (transactional gap)

`firewalled_apply_rules()` (`fs-backend-windows.c:1238`):
1. Refuses block rows that can't compile (fail-open, good).
2. `fs_fwrule_from_policy_checked()` → concrete rules.
3. `firewalled_clear_rules()` — **drops ALL StockFW-owned rules first.**
4. Loops `netsh_add_rule()` per rule; failures counted but **loop continues**.
5. Applies settings-plan rules similarly.
6. Verdict: if `failed > 0 && applied == 0` → FAILED; if partial → PARTIAL; else OK.

**Defect:** A partial apply leaves the firewall with the old rules cleared and only some new rules created — a hole. Violates non-negotiable principles #2 and #3. No snapshot/rollback to the previous known-good policy within this function (the rollback lives in the apply gate `fs_policy_apply_safe` via the journal, but `firewalled_clear_rules` has already destroyed the live state before the gate can react).

## 5. Windows event parsing (5156/5157)

`fs-winevt.c` parses XML from `wevtutil /f:xml`. Extracts `Application`, `SourceAddress`, `DestAddress`, `DestPort`, `Direction`, `Protocol`. The full executable path from `Application` is **not preserved** — only basename → `hit->service`. Needed for "Event → Create Per-App Rule".

## 6. netsh `program=` support (to verify)

`fs_fwrule_netsh_args()` builds:
```
netsh.exe advfirewall firewall add rule name=... profile=any dir=... action=... protocol=... enable=yes [localport=] [remoteport=] [remoteip=]
```
No `program=` element. netsh `advfirewall firewall add rule` does support `program="C:\Path\app.exe"` on modern Windows. To confirm exact syntax/behavior before shipping, validate on a real Windows box or via MSYS2.

## 7. Tests

- `port/tests/test-core.sh`: pure GLib core suite (CSV round-trip, ports, services, copilot, health, what-if, apply gate). Runs on both platforms, no display.
- `port/tests/full-suite.sh`: one build, every suite.
- Teeth methodology: known bugs re-injected to prove tests fail.
- UI smoke tests exist but `fs-hitview-smoke` p95 timing flagged as intermittent.

## 8. Known incomplete / risky areas for 1.0.8

| Area | Status |
|------|--------|
| Per-app rules | Absent (no program field anywhere) |
| Transactional Windows apply | Partial apply possible; clear-then-add |
| Event → per-app rule | Application path dropped in winevt |
| Linux app rules | Not investigated (cgroup/nftables/owner) — schedule 1.0.9 |
| VPN coexistence matrix | None |
| Code signing | Unsigned Windows binary |
| Licence | Apache-2.0 (root LICENSE) vs GPLv2 (COPYING) — open provenance item |

## 9. Implementation plan (develop/1.0.8)

P0: fix `firewalled_apply_rules` partial-apply defect + regression test.
P0: per-app rules on Windows (FsRule.program, FsFwRule program, netsh `program=`, CSV round-trip, UI "Event → per-app rule").
P1: transactional apply with snapshot/rollback, VPN test matrix, code signing, import/export UX.
P1: Linux app rules architecture decision (cgroup/nftables/owner) — likely 1.0.9.
