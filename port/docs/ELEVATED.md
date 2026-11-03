# Elevated launch (Windows)

Creating or deleting firewall rules needs administrator privileges, so the
normal build stops at "requires elevation". These wrappers ask for
elevation once and then run the same binary, which is what makes the
**Apply policy** button on the Policy page actually reach the firewall.

## Which one to use

| File | How | Console window |
|---|---|---|
| `StockFW-elevated.vbs` | double-click | none |
| `StockFW-elevated.cmd` | double-click | flashes briefly |
| `StockFW-elevated.ps1` | `powershell -File ...` | yes, shows errors |

The `.vbs` is the one to hand people. It runs the PowerShell wrapper
hidden, so the only thing they see is the UAC prompt and then the app.

### AutoHotkey (not shipped, untested)

For anyone who already runs AutoHotkey v2, the same launch is one line.
It is not shipped and nothing tests it (there is no AutoHotkey on the
build machines); the three files above are the supported paths. Until
1.0.7 this lived as a comment-only `port/StockFW-elevated.ahk`, whose
`Run` line had unbalanced quotes.

```autohotkey
#Requires AutoHotkey v2.0
; Save next to StockFW.exe.  "*RunAs" asks UAC for elevation.
Run '*RunAs "' A_ScriptDir '\StockFW.exe"'
```

## What it does

`Start-Process -Verb RunAs` is the only way to trigger a UAC prompt from
a script. The wrapper resolves `StockFW.exe` relative to itself, so
it can sit next to the binary or in the build directory.

## Verifying it works

Launch elevated, open the **Policy** tab, press **Apply policy**.

Expected: a dialog saying the rules were applied, and five rules named
`StockFW- ...` visible in
*Windows Security → Firewall & network protection → Advanced settings →
Inbound Rules*.

If it still reports elevation, the UAC prompt was declined or the binary
is not the one next to the wrapper.

## Note on the Linux side

No equivalent is needed: `sudo` already covers it, and the backend
checks `geteuid()` and says so plainly when it is not root.