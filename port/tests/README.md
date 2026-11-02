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

## Downloads (`tests/test-fetch.sh`, `fs-fetch-test`)

```sh
cd port
ninja -C build-linux fs-fetch-test
./build-linux/fs-fetch-test golden    # the pure pieces, no root needed
sudo bash tests/test-fetch.sh         # everything
```

`src/core/fs-fetch.c` is how StockFW downloads (1.0.7 design, section
5): one https:// URL, through `curl` started with an argv and an
environment of its own, the body read from a pipe and counted here, not
by curl alone.  `fs-fetch-test` is built from the same file with
`FS_FETCH_TESTING`, the only build that honours `STOCKFW_TEST_CURL` (a
stand-in for curl) and `STOCKFW_TEST_CACERT` (the throwaway CA, passed
as `--cacert`); built without it, fs-fetch reads no environment at all.

The shell test needs root (curl has to be made `nobody`), curl,
openssl, python3, unshare and mount, and SKIPs without them.  It re-runs
itself under `unshare -n`: an HTTPS server with a throwaway CA, a plain
HTTP server, a server that accepts and never answers and a proxy that
records connections all listen on the namespace's own 127.0.0.1, so no
case reaches the host or the internet.  Cases that change `/etc/passwd`
or hide `/usr/bin/curl` bind-mount over them in a nested `unshare -m`.
Stand-ins for curl (shell scripts in the test's temporary directory)
report what they were given, exit 60, hang past their own `--max-time`,
drop `--max-filesize` before running the real curl, flood stderr, or
only leave a flag saying they ran.
`FS_FETCH_TEST=build-asan/fs-fetch-test` runs the whole test with
another build of the driver, an ASan one for instance.

| Area | What it pins down |
|---|---|
| pure pieces | the argv golden with `-q` first; exactly `PATH` and `LC_ALL`; the URL and proxy rules; curl's exit table; bad requests refused before anything starts |
| trust | with the test CA a download works, on a main context of its own, and four at once from four threads; without it no curlrc saying `insecure` (under `HOME`, `CURL_HOME`, `XDG_CONFIG_HOME`, or in nobody's passwd home), no `CURL_CA_BUNDLE`, `SSL_CERT_FILE`/`SSL_CERT_DIR`, `SSLKEYLOGFILE` or `*_proxy` gets through: a TLS error, no proxy connection, no key log, while controls show plain curl obeying each of them |
| size | exactly the cap passes, one byte over is TOO_LARGE; an endless or stalled chunked body is cut at the cap within 3 s, also when curl ignores `--max-filesize` (as curl before 8.4 did for a chunked body), and no curl is left running |
| time | a server that never answers is TIMEOUT within budget; a curl that hangs past its own `--max-time` is killed by fs_fetch's timer |
| where | a redirect to http:// and a chain of 5 redirects are URL errors, and the http server behind the redirect never sees a request; 3 redirects pass; `{..}` and `[..]` in a URL make one request, not a curl glob; a 404 is HTTP; a proxy the caller passes is used |
| who | as root, curl runs as nobody (every uid and gid, no groups, no_new_privs) with the golden argv, stdin `/dev/null`, cwd `/` and none of the caller's descriptors; no `nobody`, a `nobody` with uid 0, or one the child cannot become: PRIVILEGE, and nothing runs |
| words | a curl exiting 60 is TLS with curl's own text, without its `curl: (60)` prefix; a missing curl is NO_CURL (also the real lookup, with `/usr/bin/curl` hidden); a curl flooding stderr still gives one short line |

Teeth, each re-injected into `fs-fetch.c` and seen failing, then
restored (checked with `cmp`) and green again.  After the dash, the
checks that caught it:

- `-q` dropped -- "nobody's own curlrc says insecure: TLS", both argv
  goldens, "-q is the first argument", the report's "-q is curl's first
  argument";
- the caller's environment inherited (no `set_environ`) -- "the hostile
  environment, no test CA: TLS", "no TLS key log was written", the
  report's "curl's environment is exactly ...";
- no privilege drop (no child setup) -- the report's uid, gid and
  no_new_privs checks, "root, a nobody the child cannot become:
  PRIVILEGE", "and the stand-in never ran";
- only curl's `--max-filesize` for the cap (fs_fetch's count disabled)
  -- "one byte over, chunked, curl without --max-filesize: TOO_LARGE",
  and the endless and stalled bodies "returned within 3 s";
- the whole-transfer timer no longer kills -- "a curl that hangs past
  its own --max-time: fs_fetch did not return within 25 s";
- http allowed (`--proto` and `--proto-redir` `=http,https`) -- "a
  redirect to http://: URL", "the http:// server behind the redirect saw
  no request", both argv goldens;
- `--globoff` dropped -- "a URL with {1,2} in it: the body has 47 bytes"
  (it had 94), "the server saw one request", "a query with [..] in it:
  ok", both argv goldens;
- the caller's descriptors inherited (`INHERIT_FDS`) -- the report's "no
  descriptor of the caller reached curl (the held marker file
  included)";
- the cap off by one (`>=`) -- "exactly the cap (Content-Length): ok"
  and "exactly the cap, chunked, ...: ok";
- at the cap, reading stops but curl is not killed -- the endless and
  stalled bodies "returned within 3 s";
- no `PR_SET_NO_NEW_PRIVS` in the child -- the report's "no_new_privs
  set";
- curl given the caller's stdin -- the report's "curl's stdin is
  /dev/null";
- failing open without a `nobody` (downloading as root) -- "root, no
  account nobody: PRIVILEGE", "and nothing was started";
- the caller's default main context iterated -- "a small file with the
  test CA: fs_fetch ran on its own main context";
- curl's `curl: (60) ` prefix kept in the message -- "curl exits 60: the
  message is "Could not download: SSL certificate problem: ..."".
