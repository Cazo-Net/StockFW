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
| Windows rules | policy rows to netsh rules and argv, refusals, the upgrade apply (see below) |

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


## Where the computer is connected (`fs-netplace-test`, `fs-overview-place-smoke`)

```sh
cd port
ninja -C build-linux fs-netplace-test fs-overview-place-smoke
./build-linux/fs-netplace-test
DISPLAY=:99 ./build-linux/fs-overview-place-smoke   # needs a display
```

Windows applies one of three firewall profiles to each network, by the
network's category.  The Overview names the network and its kind in the
subtitle, marks the profiles in force "In use", and turns the verdict
red when the profile in use is switched off: the firewall service still
reports running, but nothing on that network is filtered.

`fs-netplace-test` pins down the wording and that judgement in
`src/core/fs-netplace.c`.  `fs-overview-place-smoke` builds the real
Overview page against a fake backend that answers the way
`fs-backend-windows.c` does, so the Windows half of the page runs on any
platform.  The COM reads themselves (`INetFwPolicy2::CurrentProfileTypes`,
`INetworkListManager`) need a Windows machine.

Teeth, each seen failing when re-injected: `fs_network_place_unguarded`
ignoring which profile states were readable; networks not sorted
internet-first; the verdict ignoring the profile in use; the "In use"
marks never shown; switching a profile on from the card not re-judging
until the next poll.


## The Windows build directory on its own (`tests/test-staged-runtime.sh`)

```sh
cd port
bash tests/test-staged-runtime.sh    # Windows (MSYS2); SKIP elsewhere
```

After every build, `tools/stage-runtime-dlls.sh` copies the GTK DLLs
next to `build/StockFW.exe`, so it starts from Explorer as well as from
the MSYS2 shell.  Windows then loads those copies first, even inside
the shell, and GTK and gdk-pixbuf take `build/` as their prefix: they
look for their module trees under `build/lib` and their data under
`build/share`, the layout the installer gives `$INSTDIR`.

The script used to copy the trees to `build/<name>` instead.  gdk-pixbuf
then found no loader cache, every SVG image failed, and GTK warned about
Adwaita's own radio-button bullet; the first Windows CI runs caught it
through `fs-activity-smoke`, which counts GTK warnings as failures.

The test checks that the loader cache and the SVG loader are under
`build/lib`, that nothing is left at the old place, that every DLL the
SVG loader imports from the toolchain is staged beside the exe (the
script follows the loaders' imports with `objdump -p`), and then runs
`fs-activity-smoke` from `build/` with nothing but Windows' own
directories on PATH, as if started from Explorer: it must pass, with no
GTK warning.  It is also part of `tests/full-suite.sh`.


## Windows rule translation (`tests/test-core.sh`)

```sh
cd port
bash tests/test-core.sh
```

Part of the core suite, so it runs on Linux with no Windows anywhere.
On Windows every policy row is compiled by `src/core/fs-fwrule.c` into
concrete rules, and each rule becomes one `netsh advfirewall firewall
add rule` call.  Up to 1.0.6 most services compiled to protocol "any"
with the port dropped (a rule matching every connection in its
direction), `-` ranges and port lists became "any port", outbound
service ports sat on the local side, and NTP was TCP.  The tests pin
the translation down as golden data:

- `test_fwrule_ports`: port text to netsh spec (`67:68` -> `67-68`,
  `137-139 445` -> `137-139,445`), and every malformed text refused
  (0, 65536, inverted, half ranges, `1-2-3`, hex, signs, `;`, tabs,
  separators alone, empty); `fs_fwrule_port_spec_covers`.
- `test_fwrule_services_golden`: one row per known service, inbound
  and outbound, to its exact rules: protocol, side (local inbound,
  remote outbound, local for a forward), port spec and name suffix.
  Also SSDP and a back door, hand-edited case, a moved service (SSH on
  2222, Samba on 445), a row with no port, custom names, the "TCP"
  and "UDP" pseudo-services, ranges and lists in both notations, and
  invalid port texts refused with a reason instead of widened.
- `test_fwrule_default_policy`: the default policy (DHCP, DNS) compiles
  to UDP and TCP+UDP rules on remote ports, and the soundness rule: a
  ported rule with protocol ANY, a spec not in netsh form, or port 0
  is not sound and gets no netsh argv.
- `test_fwrule_netsh_golden`: the exact argv for an inbound service,
  one from a network, an outbound block, outbound DHCP, both halves of
  a TCP+UDP service, a port list, a host rule, a port forward and the
  TCP pseudo-service on its port; no argument carries a quote; netsh names
  keep the `StockFW-` prefix the clear relies on.
- `test_apply_translation_upgrade`: a journal as 1.0.6 wrote it (no
  `# rules translation` line) makes the next apply a full one even
  though the rows have not changed, the journal then records the
  translation, and the apply after that is "no change" again; an
  unreadable translation line also means a full apply.  A refused row
  makes the delta non-empty and sends the apply the full way, whose
  verdict reports it.
- `test_whatif_winrules`: the simulator reads the new rules: "Allow
  DHCP (outbound)" does not match outbound TCP 22 or 67 but matches UDP
  68 "on ports 67-68"; an outbound SMTP block matches remote port 25
  and not 587; "Allow DNS (inbound)" does not allow inbound TCP 3389.

What Linux cannot check: that netsh accepts these argvs and that the
backend's error reaches the dialog.  `fs-backend-windows.c` only runs
the argv `fs_fwrule_netsh_args` returns; the Windows CI build compiles
it.

Teeth, each re-injected into a copy of the source, seen failing, and
restored (`cmp`) to green:

| Bug re-injected | Checks that caught it |
|---|---|
| `fs_fwrule_is_sound` accepts protocol ANY with a port | "protocol ANY with a port is not sound", "and netsh is never given it" |
| a TCP+UDP service compiles to protocol ANY (the 1.0.6 shape) | 64 checks: every both-protocol golden, "is sound", both DNS netsh argvs, the default policy's DNS rules, the simulator's inbound UDP 53 |
| `-` ranges unparsed (only `a:b` known) | 20 checks: port texts `67-68`, `137-139 445`, DHCP/FTP/Samba/Xwindows goldens, the default policy, two netsh argvs, the simulator's DHCP UDP 68 |
| outbound service ports back on the local side | 23 checks: every outbound golden, the default policy, the SMTP and DHCP netsh argvs, "an outbound SMTP block matches remote port 25" |
| NTP back to TCP | the three NTP goldens (inbound, outbound, NTP on 5353) |
| invalid port text widened to every port | the seven "is refused, not widened" checks and the three refused-row gate checks |
| the gate trusts a 1.0.6 journal (no upgrade apply) | "an unchanged policy over a 1.0.6 journal is NOT \"no change\"", "the whole set is replaced", the audit line, "an unreadable translation line also means a full apply" |
| refused rows dropped from the delta | "a refused row makes the delta non-empty", "the same with no previous state", "goes the full way" |
| Samba on its default ports loses its UDP 137-138 / TCP 139,445 split | both Samba golden rules and the port-list netsh argv |

## Windows rule translation, second review (`test_fwrule_review`)

```sh
cd port
bash tests/test-core.sh
# The same suite under AddressSanitizer and UBSan:
STOCKFW_TEST_CFLAGS="-g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined" \
  bash tests/test-core.sh
```

An adversarial pass over the translation above, as part of the core
suite.  What it proves:

- Hostile port text is refused, never widened or wrapped: blanks and
  separators alone, `80-`, `-80`, `80--90`, `80::90`, `80:70`, `1:2:3`,
  `65536`, `0`, `00000`, `4294967376` (2^32 + 80), Arabic-Indic and
  fullwidth digits, a no-break space, a newline.  `1,,2`, `80 , 443`
  and `00080` normalise.  A list of all 65535 ports written twice
  compiles to each port once, and the simulator reads it.
- A bare "TCP" or "UDP" with no port is refused in every kind (inbound,
  outbound, block, forward), and so is the row the What-If "Create This
  Rule" writes for a probe that named no port: Linux writes no rule for
  a portless service row, and Windows used to open every TCP port.
- Samba's default ports in another order or spelling (`445 137-139`,
  `137:138,139 445`, `445,139,138,137`) keep the TCP 139,445 / UDP
  137-138 split; a real change (`137-139`) still applies to both.
- A double quote in a service name never reaches netsh's command line
  (it is spelled `'`): every argument is quote-free and the argv keeps
  its 12 elements.
- `fs_fwrule_block_refusals` reports a block row that cannot be
  compiled (a bad port, or nothing named to block) and nothing for a
  refused allow or a block that compiles.  The Windows whole-set apply
  stops on it before clearing anything, so a typo cannot remove a
  block that is in force (that call itself is compiled, not run, here).
- The narrow apply's delta keys removals and repairs on what netsh
  deletes (its spelling, case-insensitive): removing "a/b" re-creates
  "a-b", removing "ssh" re-creates "SSH", one delete per netsh name,
  and DNS moved to 5353 is exactly two deletes and two adds.
- The simulator on a list with ranges (`7000-7010 7100,7200`): every
  port inside an element is allowed, every gap blocked.

The sanitizer run is clean.  It used to report a stack overflow in
`test_activity_series` (an 8-slot buffer for a 26-point window),
leaked template rules, settings, a trust store and a name list in
older tests, and a real leak in `fs-copilot.c`: the per-application
port, destination and hour counters were never freed with their
profile, so every profile the LRU cap evicted leaked them.

Teeth, each re-injected into a copy of the source, seen failing, and
restored (`cmp`) to green:

| Bug re-injected | Checks that caught it |
|---|---|
| a bare "TCP"/"UDP" with no port opens every port of it again | the five "is refused, not widened" pseudo-service goldens and "that row opens nothing on Windows" |
| the default-port test compares text, not port sets | the six reordered Samba golden rules |
| a quote in a name goes to netsh as it is | "a quote in a service name never reaches netsh", "the netsh spelling of a quote is '" |
| `fs_fwrule_block_refusals` never reports | "a block with a bad port is a block refusal", "so is a block that names nothing to block" |
| port lists keep duplicates | `80,80` -> `80` and the all-ports-twice check |
| the delta compares display names, not netsh names | "removing \"a/b\" re-creates \"a-b\"", "deletes each netsh name once", "removing \"ssh\" re-creates \"SSH\"" |
| profile counters not freed with their profile | the sanitizer run: LeakSanitizer reports the counters from `app_profile_record_connection` |
| `test_activity_series` buffers back to 8 slots | the sanitizer run: stack-buffer-overflow in `fs_activity_window` |
