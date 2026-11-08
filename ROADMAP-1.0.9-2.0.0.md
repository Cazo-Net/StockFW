# StockFW Roadmap — 1.0.9 & 2.0.0 Architecture & Engineering Blueprint

Prepared by StockFW Engineering (Autonomous Night-Shift Session, 2026-11-08).
Branch: `develop/1.0.8` (Targeting subsequent releases).

---

## 1. StockFW 1.0.9 — Linux Per-Application Rules & DNS Filtering

Having established Windows per-application rules and transactional apply in 1.0.8, 1.0.9 brings full parity to Linux and introduces secure DNS filtering.

### 1.1 Linux Per-Application Rule Architecture
Unlike Windows (where `netsh` takes `program=<path>` directly via WFP), Linux netfilter (`iptables`/`nftables`) does not natively bind application executable paths in kernel packet filters without extensions.
- **Approach:**
  1. **Cgroup v2 matching (`nftables`):** Group target systemd services or application container slices under specific cgroups, then match packets via `socket cgroupv2 level 2 "app.slice"`.
  2. **Socket-Owner matching (`nftables`):** For locally generated outbound connections, match socket UID/GID or process owner via `meta skuid <user>` or socket-owner matching where supported by the kernel (Linux 4.16+ / nftables).
  3. **Process attribution mapping:** `fs-hostnet.c` already maps socket inodes to PIDs and executable paths; 1.0.9 binds this to policy authoring.

### 1.2 DNS & Domain Filtering (Opt-in, Fail-Open)
Unlike Portmaster (whose DNS takeover has a history of breaking VPNs and connectivity), StockFW's DNS filtering will be strictly designed around reliability:
- **Architecture:** Coexists with `systemd-resolved`, split-tunnel VPN DNS, and NextDNS.
- **Mechanism:** Opt-in local forwarding stub / CNAME inspection that never breaks raw IP connectivity or overrides system resolvers when offline.
- **Fail-Open guarantee:** If the DNS inspection filter encounters an error, queries pass through unhindered.

---

## 2. StockFW 2.0.0 — Enterprise, Fleet Management & Commercial Edition

StockFW 2.0.0 establishes the commercial and enterprise tier that Portmaster lacks, while maintaining strict local privacy guarantees.

### 2.1 Centralized Fleet Management & Policy Push
- **Architecture:** Signed policy bundles pushed from an enterprise controller or local daemon via secure authenticated mTLS endpoints.
- **Audit & Compliance:** Cryptographically signed audit logs exporting compliance reports (CIS benchmarks, firewall enforcement verification).
- **Headless Fleet Operations:** Enhanced `stockfw` daemon mode with robust JSON-RPC / REST APIs bound to localhost or authenticated unix sockets.

### 2.2 Settle Licensing & Commercial Readiness
- **Provenance Review:** Clean-room verification of all core modules to ensure clean Apache-2.0 / dual-licensing compliance without GPL contamination on proprietary enterprise modules.
- **Threat-Feed Attribution & Compliance:** Formal written agreements with feed publishers (Spamhaus, abuse.ch, IPFire location DB) for commercial distribution.

### 2.3 Packaging & Distribution
- Official signed Windows NSIS installer with SmartScreen reputation build-up.
- Official `.deb` and `.rpm` repository packages for Debian, Ubuntu, RHEL, Fedora, and Kali Linux.
- First-class ARM64 builds for Linux and Windows on ARM.
