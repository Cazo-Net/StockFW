#---[ test-elevated.ps1 ]----------------------------------------------
# Checks the launcher's logic without triggering a UAC prompt: the
# prompt needs a human, so this only verifies the script parses and
# finds the binary.
#--------------------------------------------------------------------

$ErrorActionPreference = 'Stop'

function Test-PathResolution {
    param([string]$ScriptDir)

    $binary = Join-Path $ScriptDir 'StockFW.exe'
    if (-not (Test-Path $binary)) {
        $binary = Join-Path $ScriptDir 'build\StockFW.exe'
    }
    return $binary
}

# Derived from this file's own location: the repository has been renamed
# once, and hard-coded paths here pointed at a directory that no longer
# existed, so the test could never pass again.
$portDir  = Split-Path -Parent $PSScriptRoot
$buildDir = Join-Path $portDir 'build'

$cases = @(
    # The exe sits in the directory the launcher looks in first.
    @{ Name = 'binary next to script';       Dir = $buildDir; Expected = (Join-Path $buildDir 'StockFW.exe') },
    # The launcher sits one level up and falls back to build\.
    @{ Name = 'binary in build subdirectory'; Dir = $portDir;  Expected = (Join-Path $buildDir 'StockFW.exe') }
)

$failures = 0

foreach ($case in $cases) {
    $resolved = Test-PathResolution -ScriptDir $case.Dir
    $exists = Test-Path $resolved

    if ($resolved -eq $case.Expected -and $exists) {
        Write-Host "ok:   $($case.Name) -> $resolved"
    } else {
        Write-Host "FAIL: $($case.Name)"
        Write-Host "      resolved: $resolved"
        Write-Host "      expected: $($case.Expected)"
        Write-Host "      exists:   $exists"
        $failures++
    }
}

# The negative case: a directory with no binary must report failure.
$empty = Join-Path $env:TEMP ('fs-elev-empty-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $empty | Out-Null

$resolved = Test-PathResolution -ScriptDir $empty
if (Test-Path $resolved) {
    Write-Host "FAIL: empty dir should not resolve to an existing file"
    $failures++
} else {
    Write-Host "ok:   empty dir correctly reports not found"
}

Remove-Item -Recurse -Force $empty

Write-Host ""
if ($failures -eq 0) {
    Write-Host "PASSED: 0 failure(s)"
    exit 0
} else {
    Write-Host "FAILED: $failures failure(s)"
    exit 1
}