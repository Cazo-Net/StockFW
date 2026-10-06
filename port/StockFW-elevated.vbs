'---[ StockFW-elevated.vbs ]-------------------------------------------
' Silent double-click launcher.
'
' The .cmd wrapper flashes a console window, which is wrong for a GUI
' app.  This runs the same PowerShell wrapper with no console at all.
'
' The UAC prompt still appears, because that comes from the OS, not from
' the console.
'--------------------------------------------------------------------

Option Explicit

Dim shell, here, ps1, cmd

Set shell = CreateObject("WScript.Shell")
here = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\") - 1)
ps1 = here & "\StockFW-elevated.ps1"

If Not CreateObject("Scripting.FileSystemObject").FileExists(ps1) Then
    MsgBox "StockFW-elevated.ps1 not found next to this launcher." & vbCrLf & _
           "Expected: " & ps1, vbCritical, "StockFW"
    WScript.Quit 1
End If

cmd = "powershell.exe -NoProfile -WindowStyle Hidden " & _
      "-ExecutionPolicy Bypass -File """ & ps1 & """"

' 0 = hidden window, True = wait for it to finish.
shell.Run cmd, 0, True
