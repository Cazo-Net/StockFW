#---[ StockFW-elevated.cmd ]-------------------------------------------
# Double-click launcher for the elevated build.
#
# PowerShell's -Verb RunAs is the only way to trigger a UAC prompt from
# a script, so this just forwards to the PowerShell wrapper.
@echo off
setlocal

set "HERE=%~dp0"
set "PS=%HERE%StockFW-elevated.ps1"

if not exist "%PS%" (
    echo StockFW-elevated.ps1 not found next to this launcher.
    echo Expected: %PS%
    pause
    exit /b 1
)

rem -ExecutionPolicy Bypass is needed because the default policy blocks
rem scripts.  -NoProfile keeps it from loading the user profile.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS%"

if errorlevel 1 (
    echo.
    echo Launch failed.  See the message above.
    pause
)

endlocal
