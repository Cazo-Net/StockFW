# StockFW — Modern Port Plan (Windows + Linux)

## What this is

`stockfw-1.0.3` is the original GNOME 2 / GTK+ 2 firewall GUI (C, 2000-2005).
It targets Linux only, iptables only, and depends on libraries that no longer exist
on modern systems:

| Old dependency | Status today | Replacement |
|---|---|---|
| `libgnome` / `libgnomeui` (`gnome.h`) | removed | GTK3 + `GtkApplication` |
| `libgnomeui` `GnomeApp` / `GnomeAboutDialog` | removed | `GtkApplicationWindow` / `GtkAboutDialog` |
| `gnome_program_init`, session mgmt | removed | `g_application_run` |
| `libgnomevfs` (async file IO) | removed | GIO (`GFile`/`GFileInputStream`) |
| `libglade` (runtime UI from XML) | removed | GtkBuilder (`gtk_builder_new_from_file`) |
| GConf 2 (settings) | removed | GKeyFile (ini) — or GSettings on Linux |
| `eggtrayicon` | obsolete | `GtkStatusIcon` |
| `popt` (CLI parsing) | rarely installed | GLib `GOptionContext` |
| `gethostname`, `gettext`-style `_()` | ok | keep / `glib/gi18n` |
| autotools (`configure`, `aclocal.m4`) | works but stale | CMake |

The firewall engine is pure text generation (`scriptwriter.c`, `netfilter-script.c`
emit shell scripts that call `iptables`). That logic is **portable** and is the
part worth keeping.

## Target architecture

```
port/
  CMakeLists.txt
  src/
    main.c                 entry point, GOptionContext, GApplication
    core/                  platform-independent, no OS calls
      fs-model.{c,h}       Hit struct, view/view-column defs, enums
      fs-prefs.{c,h}       GKeyFile-backed settings (replaces GConf)
      fs-policy.{c,h}      CSV policy read/write helpers
      fs-rules.{c,h}       rule model shared by wizard + policy editor
      fs-script.{c,h}      iptables script generation (was scriptwriter.c)
      fs-service.{c,h}     service/protocol tables
      fs-util.{c,h}        validation, string helpers, hit logging
    platform/
      linux/
        fs-backend-linux.c    iptables exec, interface enumeration
        fs-log-linux.c        syslog/journald tailing
        fs-dhcp-linux.c       dhcpd control
        fs-script-linux.c     shell script emission
      windows/
        fs-backend-windows.c  WFP / HNetCfg.FwPolicy2 via COM
        fs-log-windows.c      event log tailing
        fs-dhcp-windows.c     DHCP server control
        fs-script-windows.c   netsh/powershell rule emission
    ui/
      fs-app.c            GtkApplication, main window, notebook
      fs-menu.c           menu bar + toolbar
      fs-statusview.c     Status tab (was statusview.c)
      fs-hitview.c        Events tab (was hitview.c)
      fs-policyview.c     Policy tab (was policyview.c)
      fs-wizard.c         wizard dialog (was wizard.c)
      fs-prefs-dialog.c   preferences (was preferences.c + preferences.glade)
      fs-tray.c           tray icon
      fs-dialogs.c        about/error helpers
  data/
    stockfw.1.ui      GtkBuilder XML
    stockfw.desktop
```

Key rule: **`core/` never includes a platform header.** All OS access goes through
the `fs-backend` vtable in `core/fs-backend.h`, so the same GUI drives both
iptables on Linux and the Windows Firewall API on Windows.

## Milestones

- **M1 — Buildable modern shell.** DONE.
  - CMake + GTK3/GLib, portable core (`core/`) compiles warning-free.
  - `GtkApplication` main window with Status / Events / Policy tabs.
  - Settings store round-trips the original GConf key paths through GKeyFile.
  - Windows backend talks to `HNetCfg.FwPolicy2`: reports live firewall state
    across the three profiles and enables/disables them.
  - Builds and runs under MSYS2 (Windows).
- **M2 — GUI feature parity.** Wizard, policy editor, preferences, hit monitor,
  tray icon all working with the GtkBuilder UI.
  - DONE: rule store (`core/fs-rules.c`) — CSV per rule kind, same file
    format as the original.
  - DONE: service table (`core/fs-service.c`) — port/service lookup,
    ICMP names, range expansion.
  - DONE: script generation (`core/fs-script.c`) — iptables text for the
    Linux backend.
  - DONE: core test suite (`port/tests/test-core.sh`), 40 assertions.
  - DONE: tray icon (`src/ui/fs-tray.c`) — notification-area icon with an
    Open/Quit menu and close/minimize-to-tray, shipped in 1.0.5.
  - TODO: wire these into the Policy/Events pages, plus preferences.
- **M3 — Linux firewall backend.** DONE, except DHCP.
  - Builds and runs under WSL2/Kali via WSLg.
  - `iptables` rules applied and verified with `iptables -L`: inbound
    chain with ICMP allowances, conntrack, loopback, policy rules and a
    default DROP.
  - NAT verified: `MASQUERADE` in `nat/POSTROUTING`, `ACCEPT` in
    `filter/FORWARD`, `ip_forward=1`.
  - State is reported by probing for the `INBOUND` chain.
  - TODO: DHCP server, and the syslog tailer is untested because WSL has
    no `/var/log/kern.log`.
- **M4 — Windows firewall backend (rules).** Profile state and interface
  enumeration are done; still needs `INetFwRule` creation from the wizard and
  an event-log/ETW hit monitor.
- **M5 — Packaging.** Windows installer / MSIX, Linux .deb + AppStream.

## Build environments

- **Windows**: MSYS2 — `winget install MSYS2.MSYS2`, then
  `pacman -S --needed base-devel mingw-w64-ucrt-x86_64-{toolchain,gtk3,pkg-config,ninja,cmake,xz,openssl}`.
  Produces a native Windows GTK3 binary in `port/build/`.
- **Linux**: WSL2 Ubuntu + `build-essential cmake ninja-build pkg-config
  libgtk-3-dev liblzma-dev libssl-dev`. Produces a native Linux GTK3
  binary.

liblzma (`xz`) and libcrypto (`openssl`) are required (1.0.7): they read
and verify the location database. CMake stops at configure time when
pkg-config cannot find them.

Both use the same `CMakeLists.txt`.

```sh
cmake -S . -B build -G Ninja
cmake --build build
./build/stockfw
```

Note for MSYS2: run the toolchain from the UCRT64 shell, not `sh -c` with a
hand-built PATH, or the MinGW DLLs will not be found.

### MinGW-w64's netfw.h is unusable for rule management

The Windows rule path was first written against `INetFwRules` /
`INetFwRule` directly over COM. That does not work under MinGW:

- `INetFwRules` is declared with `INetFwAuthorizedApplications`'
  method signatures — `Add(INetFwRule *)`, `Remove(BSTR)`,
  `Item(BSTR, INetFwRule **)` — none of which match the real API, so
  the calling conventions are wrong.
- `INetFwPolicy2`'s vtable does not match the real COM server, so calls
  past a point in it crash the process.
- `NET_FW_RULE_PROTOCOL_*` is missing entirely.
- The `CLSID_NetFwPolicy2` / `IID_INetFwPolicy2` symbols segfault when
  their addresses are taken.

**Decision:** read the firewall profile state over COM (that part works
and is verified), but manage rules through `netsh advfirewall`, the
documented command line interface. It is stable across SDK versions and
needs no header shims. `platform/windows/netfw-compat.h` remains only for
the GUIDs and profile constants.

netsh specifics found while testing:

- `g_spawn_sync` does no shell parsing, so arguments must not contain
  quote characters; `name=StockFW - Allow SSH` must be a single argv
  element with no surrounding quotes.
- netsh rejects rule names containing `:`, `(`, `)`, `/` or `,`, which
  the generated display names do contain. They are sanitised before use.
- Any port specification combined with `protocol=any` is rejected:
  "Ports can only be specified if the protocol is TCP or UDP."
- Deleting our own rules must **not** use `name=all`, which would remove
  every rule on the machine. The backend lists rules, keeps the names
  matching its own prefix, and deletes exactly those.
- Creating or deleting rules needs an elevated shell. Unprivileged runs
  get "The requested operation requires elevation", which is mapped to
  `FS_APPLY_NO_PRIVILEGE` so the UI can say so plainly.

## Gotchas hit while building

- `g_get_user_config_dir()` returns *local* AppData on Windows, which is the
  wrong place for settings. `core/fs-prefs.c` reads `%APPDATA%` directly.
- `g_key_file_save_to_file()` writes via a temp file in the target directory,
  so that directory must exist first or saving fails silently.
- MinGW has no `netfw.lib`; `netfw.h` GUIDs need `#define INITGUID` before the
  include to get real storage.
- `INetFwPolicy2::get_FirewallEnabled` takes a `VARIANT_BOOL` (-1/0), not a
  `VARIANT`. Passing a `VARIANT*` compiles with a warning and fails to link.
- `gtk_application_set_menubar()` takes a `GMenuModel`, not a `GtkMenuBar`.
- `gtk_about_dialog_set_wrap_mode()` does not exist; the real call is
  `gtk_about_dialog_set_wrap_license()`.

## Known hazards

- `gui.c` reaches into `dialog->window` (private GTK struct) — breaks on GTK3.
- `eggtrayicon.c` pokes X11 internals; replaced wholesale by `GtkStatusIcon`.
- `policyview.c` uses `gdk_pixbuf` inline XPM data built at build time by
  `src/xpm/Makefile.am` — needs a CMake equivalent or conversion to PNG.
- Preferences keys are GConf paths (`/apps/stockfw/...`); GKeyFile needs a
  flat key mapping — keep the same macro names so call sites don't change.
- The iptables script uses `$IPT` and bash-isms (`==`, `while read`); on Windows
  there is no bash, which is why the Windows backend must not shell out.