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

# The binary is a MinGW build and needs its runtime DLLs.  The normal
# build has them staged beside StockFW.exe, but a binary copied around
# on its own does not, and an elevated process does not inherit a PATH
# set in an interactive MSYS2 shell -- so keep the toolchain on PATH as
# a fallback.
#
# Start-Process inherits the current process environment, so setting
# $env:PATH here is enough.
$msysBin = 'C:\msys64\ucrt64\bin'

if (Test-Path (Join-Path $msysBin 'libgio-2.0-0.dll')) {
    if (($env:PATH -split ';') -notcontains $msysBin) {
        $env:PATH = "$msysBin;$env:PATH"
        Write-Host "Added $msysBin to PATH" -ForegroundColor DarkGray
    }
} else {
    Write-Host "Warning: $msysBin not found; the app may fail to start." `
              -ForegroundColor Yellow
}

Write-Host "Launching elevated: $binary" -ForegroundColor Cyan

# -Verb RunAs triggers the UAC prompt.  -Wait keeps this window open
# until the app exits, so any error output is visible.
Start-Process -FilePath $binary -Verb RunAs -Wait

Write-Host "StockFW has exited." -ForegroundColor Cyan
