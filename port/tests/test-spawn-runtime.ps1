# Verifies the installed-shaped app can actually spawn external
# programs, using a PATH like the one a Start Menu launch gets.
#
# Why this test exists: GLib starts child processes through
# gspawn-win64-helper.exe rather than CreateProcess, and nothing in a
# dependency scan sees that file because it is exec'd, not linked.  Both
# staging scripts used to copy DLLs only.  The app still started and
# looked perfectly healthy -- it just could not run wevtutil.exe or
# netsh.exe, so the Events page stayed empty forever.
#
# fs-hitview-smoke builds the real Events page, which asks the backend
# to start monitoring.  With the helper present that reaches wevtutil
# and reports the privilege problem; without it, g_spawn fails first and
# the message names the helper instead.  Asserting on which message
# appears is what makes this catch a regression.
#
#   powershell -ExecutionPolicy Bypass -File tests/test-spawn-runtime.ps1

$ErrorActionPreference = 'Stop'

$here  = Split-Path -Parent $MyInvocation.MyCommand.Path
$port  = Split-Path -Parent $here
$build = Join-Path $port 'build'
$exe   = Join-Path $build 'fs-hitview-smoke.exe'

if (-not (Test-Path $exe)) {
  Write-Output "SKIP: $exe not built (run: ninja -C build fs-hitview-smoke)"
  exit 0
}

$failures = 0
function Check ($cond, $msg) {
  if ($cond) { Write-Output "ok:   $msg" }
  else       { Write-Output "FAIL: $msg"; $script:failures++ }
}

# 1. Both helpers must ship next to the binary.  GLib picks between
#    them: the plain one when the parent is a GUI process, the console
#    one when it has a console.  StockFW.exe is a GUI app but a test
#    harness is not, so shipping only one of them looks fine in one
#    context and breaks in the other.
$failHelpers = @()
foreach ($name in 'gspawn-win64-helper.exe', 'gspawn-win64-helper-console.exe') {
  $present = Test-Path (Join-Path $build $name)
  Check $present "$name sits beside the exe"
  if (-not $present) { $failHelpers += $name }
}

# 2. Run it with the environment a Start Menu launch gets: machine + user
#    PATH only, with no MSYS2 directory anywhere on it.
$m = [Environment]::GetEnvironmentVariable("Path", "Machine")
$u = [Environment]::GetEnvironmentVariable("Path", "User")
$env:PATH = "$m;$u"
Check ($env:PATH -notlike '*ucrt64*') "PATH has no MSYS2 directory on it"

$out = Join-Path $env:TEMP 'spawn-runtime.out'
Remove-Item $out -ErrorAction SilentlyContinue
Start-Process -FilePath $exe -WorkingDirectory $build -Wait `
              -RedirectStandardOutput $out -RedirectStandardError "$out.err"

$text = if (Test-Path $out) { (Get-Content $out) -join "`n" } else { "" }

# 3. The spawn must have got through to wevtutil.  On an unprivileged
#    session that means the privilege message; running as Administrator
#    monitoring simply starts and neither message appears.
$spawnBroke = $text -like '*helper program*'
$explained  = $text -like '*Administrator*' -or $text -like '*root*'
$running    = $text -like '*monitoring -> running*'

Check (-not $spawnBroke) "g_spawn did not fail with 'helper program'"
Check ($explained -or $running) "monitoring is either running or explained"

Write-Output ""
Write-Output "observed: monitoring=$(if ($running) {'running'} else {'not running'}), "`
             "reason explained=$explained"
Write-Output "$failures failure(s)"
if ($failures -gt 0) {
  Write-Output "--- output was: ---"
  Write-Output $text
}
exit $failures
