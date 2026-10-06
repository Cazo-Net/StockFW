#---[ check-elevated-syntax.ps1 ]--------------------------------------
# Parses the launcher scripts to catch syntax errors without running
# them (running would raise a UAC prompt, which needs a human).
#--------------------------------------------------------------------

# Derived from this file's own location -- a hard-coded path here broke
# when the repository was renamed.
$portDir = Split-Path -Parent $PSScriptRoot

$files = @(
    (Join-Path $portDir 'StockFW-elevated.ps1')
)

$failures = 0

foreach ($file in $files) {
    if (-not (Test-Path $file)) {
        Write-Host "FAIL: missing $file"
        $failures++
        continue
    }

    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $file, [ref]$null, [ref]$errors)

    if ($errors.Count -eq 0) {
        Write-Host "ok:   $(Split-Path $file -Leaf) parses cleanly"
    } else {
        Write-Host "FAIL: $(Split-Path $file -Leaf)"
        foreach ($e in $errors) {
            Write-Host "      line $($e.Extent.StartLineNumber): $($e.Message)"
        }
        $failures++
    }
}

# The .vbs and .cmd are not parseable by PowerShell, so check them by
# eye: confirm they reference the files that actually exist.
$vbs = Join-Path $portDir 'StockFW-elevated.vbs'
$cmd = Join-Path $portDir 'StockFW-elevated.cmd'

foreach ($f in @($vbs, $cmd)) {
    if (Test-Path $f) {
        Write-Host "ok:   $(Split-Path $f -Leaf) present"
    } else {
        Write-Host "FAIL: missing $f"
        $failures++
    }
}

Write-Host ""
if ($failures -eq 0) {
    Write-Host "PASSED: 0 failure(s)"
    exit 0
} else {
    Write-Host "FAILED: $failures failure(s)"
    exit 1
}