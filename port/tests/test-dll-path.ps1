#---[ test-dll-path.ps1 ]---------------------------------------------
# Confirms the binary starts once the MSYS2 runtime is on PATH, which
# is what the elevated wrapper now does.  Runs --version so no window
# is needed.
#--------------------------------------------------------------------

$binary = 'E:\PROJECTS\firestarter-1.0.3\firestarter-1.0.3\port\build\firestarter.exe'
$msysBin = 'C:\msys64\ucrt64\bin'

Write-Host "=== without the MSYS2 runtime on PATH ==="
$env:PATH = ($env:PATH -split ';' | Where-Object { $_ -notmatch 'ucrt64' }) -join ';'
$out = & $binary --version 2>&1
$code = $LASTEXITCODE
Write-Host "exit: $code"
Write-Host "output: $out"

Write-Host ""
Write-Host "=== with the MSYS2 runtime on PATH ==="
$env:PATH = "$msysBin;$env:PATH"
$out = & $binary --version 2>&1
$code = $LASTEXITCODE
Write-Host "exit: $code"
Write-Host "output: $out"

Write-Host ""
if ($code -eq 0 -and "$out" -match 'Firestarter') {
    Write-Host "PASSED: binary starts with the runtime on PATH"
    exit 0
} else {
    Write-Host "FAILED"
    exit 1
}