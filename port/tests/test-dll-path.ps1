#---[ test-dll-path.ps1 ]---------------------------------------------
# Confirms the binary starts from its own directory WITHOUT the MSYS2
# runtime on PATH.  That is the whole point of staging the runtime next
# to StockFW.exe: an MSYS2 shell hides the problem because /ucrt64/bin
# is on PATH there, while double clicking, an installed copy or a plain
# Start Menu launch is not.
#
# StockFW.exe is built as a GUI-subsystem binary, so invoking it with
# PowerShell's & neither waits for it nor captures its output -- the
# test would "fail" with an empty exit code every time.  Start-Process
# -Wait with redirected output is required here.
#--------------------------------------------------------------------

$ErrorActionPreference = 'Stop'

$port   = Split-Path -Parent $PSScriptRoot
$binary = Join-Path $port 'build\StockFW.exe'

if (-not (Test-Path $binary)) {
    Write-Host "SKIP: $binary not built (ninja -C build StockFW)"
    exit 0
}

$failures = 0
function Check ($cond, $msg) {
    if ($cond) { Write-Host "ok:   $msg" }
    else       { Write-Host "FAIL: $msg"; $script:failures++ }
}

Write-Host "=== without any MSYS2 directory on PATH ==="
$env:PATH = (($env:PATH -split ';' | Where-Object { $_ -notmatch 'msys64|ucrt64' }) -join ';')
Check (-not ($env:PATH -match 'msys64|ucrt64')) "no MSYS2 directory left on PATH"

$out = Join-Path $env:TEMP 'dll-path-version.out'
Remove-Item $out -ErrorAction SilentlyContinue

# -PassThru is required: Start-Process does not set $LASTEXITCODE, so
# reading that afterwards would report whatever ran before this test.
$proc = Start-Process -FilePath $binary -WorkingDirectory (Split-Path $binary) `
                      -Wait -PassThru -RedirectStandardOutput $out `
                      -RedirectStandardError "$out.err" `
                      -ArgumentList '--version'
$code = $proc.ExitCode
$text = if (Test-Path $out) { (Get-Content $out) -join ' ' } else { '' }

Write-Host "exit:   $code"
Write-Host "output: $text"

Check ($code -eq 0)               "exit code is 0"
Check ($text -match 'StockFW')    "it reports its own version from a bare PATH"

Write-Host ""
if ($failures -eq 0) {
    Write-Host "PASSED: 0 failure(s)"
    exit 0
} else {
    Write-Host "FAILED: $failures failure(s)"
    exit 1
}
