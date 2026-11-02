# StockFW core tests

Checks the platform-independent logic in `src/core/`: rule CSV
round-tripping, host/port validation, the service table, and iptables
script generation.  Pure GLib, so it runs headless on either platform.

```sh
cd port
./tests/test-core.sh
```

The script compiles the suite against the core sources directly rather
than through CMake, so a failing test points at the logic rather than a
link problem. Set `MSYS2_PATH` if your toolchain is not on `/ucrt64/bin`.

Rules are written under a temporary `STOCKFW_RULES_DIR`, so running
the tests never touches a real `/etc/stockfw`.

## Coverage

| Suite | What it pins down |
|---|---|
| ports | single ports, ranges, hex, out-of-range, inverted ranges, empty |
| hosts | dotted quads, hostnames, wildcards, bad octets, short forms |
| rule CSV | every rule kind survives serialise/parse; over-long rows rejected |
| policy | save/load round trip, defaults, add and remove by content |
| services | port to name lookup, back-door ports, ICMP types, range expansion |
| scripts | inbound/outbound rules, NAT, permissive vs restrictive defaults |

## Event source (`tests/test-logstart.sh`)

```sh
cd port
./tests/test-logstart.sh
```

Builds the platform backend on its own -- `fs-backend-windows.c` or
`fs-backend-linux.c` -- and asks it to start monitoring traffic. Either
it starts and `log_active()` agrees, or it refuses **and says why**.

The case it exists for: `log_start()` used to return TRUE whether or not
the Security log could be read, so a non-elevated Windows session and an
unprivileged Linux session both showed an empty event list that read as a
working firewall with nothing to report. Monitoring now has to be either
honestly running or honestly explained.

## Command line and dashboard (`tests/test-cli.sh`)

```sh
cd port
bash tests/test-cli.sh
```

Linux only, no root needed.  Builds the `stockfw` target through CMake
and drives the real binary against scratch rules and config directories
and a fixture kernel log, so it never touches `/etc/stockfw` or the live
firewall (`apply` only runs with `--dry-run`).

It pins down the documented exit codes, policy editing (the service
shorthand, refused commas, mistyped options and bad hosts), the
simulator's verdicts, the kernel-log history, every `--json` document
parsed back, and the dashboard's security model: loopback only, the
per-run token (header only, never the query string or the page), the
Host check against DNS rebinding, GET/HEAD only, the 16 KB request-head
cap, the CSP nonce, and the dashboard leaving its own sockets out of the
connection list.

