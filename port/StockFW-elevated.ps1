#---[ StockFW-elevated.ps1 ]-------------------------------------------
# Launch StockFW with administrator privileges.
#
# Creating or deleting firewall rules needs elevation on Windows, so the
# normal (unprivileged) build reports "requires elevation" and stops
# there.  This wrapper asks for elevation once and then runs the same
# binary, so the Apply button actually reaches the firewall.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File StockFW-elevated.ps1
#
# Or right-click -> Run with PowerShell, which prompts for UAC.
#--------------------------------------------------------------------

$ErrorActionPreference = 'Stop'

# Resolve the binary relative to this script so the wrapper can live
# anywhere.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$binary   = Join-Path $scriptDir 'StockFW.exe'

if (-not (Test-Path $binary)) {
    # Fall back to the build directory next to the source tree.
    $binary = Join-Path $scriptDir 'build\StockFW.exe'
}

if (-not (Test-Path $binary)) {
    Write-Host "Could not find StockFW.exe" -ForegroundColor Red
    Write-Host "Looked in:" -ForegroundColor Yellow
    Write-Host "  $scriptDir"
    Write-Host "  $(Join-Path $scriptDir 'build')"
    exit 1
}

# The binary is a MinGW build and needs its runtime DLLs, which the
# loader finds in the application directory -- the folder holding
# StockFW.exe.  That is where we require them, whether that folder is
# this script's own directory (installed copy) or build\ (dev tree).
$binDir    = Split-Path -Parent $binary
$hasRuntime = Test-Path (Join-Path $binDir 'libglib-2.0-0.dll')

# SECURITY: a missing runtime is a broken install, so stop and say so.
# The launcher must NOT fall back to a development toolchain directory.
# Widening the elevated process's PATH to one means a DLL planted there
# by a non-administrator would load into an administrator process -- a
# privilege-escalation primitive, not a convenience.  A directory a
# non-admin can write to must never reach an elevated search path.
if (-not $hasRuntime) {
    Write-Host "StockFW runtime DLLs are missing next to StockFW.exe." `
              -ForegroundColor Red
    Write-Host "Expected to find: $(Join-Path $binDir 'libglib-2.0-0.dll')" `
              -ForegroundColor Yellow
    Write-Host "Reinstall StockFW (the runtime belongs beside StockFW.exe)." `
              -ForegroundColor Yellow
    Write-Host "Not falling back to a toolchain directory: widening an" `
              -ForegroundColor DarkGray
    Write-Host "elevated DLL search path is a privilege-escalation risk." `
              -ForegroundColor DarkGray
    exit 1
}

Write-Host "Launching elevated: $binary" -ForegroundColor Cyan

# -Verb RunAs triggers the UAC prompt.  -Wait keeps this window open
# until the app exits, so any error output is visible.
Start-Process -FilePath $binary -Verb RunAs -Wait

Write-Host "StockFW has exited." -ForegroundColor Cyan
