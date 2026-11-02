; Where port/ lives, so every ${PROJECT_DIR}\... reference below works.
; This used to be a hard-coded absolute path, which survived a rename of
; the repository and broke every installer build with "can't open file"
; on the icon lookup.  It is relative now: build_installer.sh runs
; makensis from this directory, so "..\.." is port/ wherever the tree
; sits.
!ifndef PROJECT_DIR
  !define PROJECT_DIR "..\.."
!endif

!define APP_NAME "StockFW"
!define APP_VERSION "1.0.6"
!define APP_PUBLISHER "StockFW Project"
!define APP_WEBSITE "https://github.com/stockfw/stockfw"
!define APP_EXE "StockFW.exe"
!define INSTALLER_NAME "StockFW-${APP_VERSION}-Setup.exe"
; Windows file-properties version resource.  VIProductVersion wants a
; strict four-part X.X.X.X number, so the display version carries a
; ".0" build part; the human-readable strings below carry it as-is.
!define APP_VERSION_FULL "${APP_VERSION}.0"
VIProductVersion "${APP_VERSION_FULL}"
VIFileVersion "${APP_VERSION_FULL}"
VIAddVersionKey /LANG=0 "ProductName" "${APP_NAME}"
VIAddVersionKey /LANG=0 "ProductVersion" "${APP_VERSION}"
VIAddVersionKey /LANG=0 "FileVersion" "${APP_VERSION_FULL}"
VIAddVersionKey /LANG=0 "FileDescription" "${APP_NAME} Setup"
VIAddVersionKey /LANG=0 "CompanyName" "${APP_PUBLISHER}"
VIAddVersionKey /LANG=0 "LegalCopyright" "(C) 04-10-2026 StockFW Project"

;------------------------------------------------------------------------------
; Modern UI 2 Configuration
;------------------------------------------------------------------------------
!include MUI2.nsh
!include LogicLib.nsh

; String search behind the uninstaller's running-process check.  StrFunc ships
; a separate ${UnStrStr} for uninstaller code -- the installer-side ${StrStr}
; is not visible to Section Uninstall -- so it is declared here, ahead of the
; uninstaller section that calls it.
!include StrFunc.nsh
${UnStrStr}

;------------------------------------------------------------------------------
; Custom Branding Resources
;------------------------------------------------------------------------------
!define MUI_ICON "${PROJECT_DIR}\installer\nsis\resources\stockfw_icon.ico"
!define MUI_UNICON "${PROJECT_DIR}\installer\nsis\resources\stockfw_icon.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "${PROJECT_DIR}\installer\nsis\resources\stockfw_header.bmp"
!define MUI_HEADERIMAGE_UNBITMAP "${PROJECT_DIR}\installer\nsis\resources\stockfw_header.bmp"
; Left-hand panel of the Welcome and Finish pages (164x314).  Without
; these MUI falls back to its stock orange "wizard" picture.  Both
; bitmaps come from tools/make-logo-assets.sh -- regenerate, don't edit.
!define MUI_WELCOMEFINISHPAGE_BITMAP "${PROJECT_DIR}\installer\nsis\resources\stockfw_welcome.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "${PROJECT_DIR}\installer\nsis\resources\stockfw_welcome.bmp"

;------------------------------------------------------------------------------
; Modern UI Pages
;------------------------------------------------------------------------------
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${PROJECT_DIR}\installer\nsis\stage\LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
; Finish-page settings belong to the page macro that follows them: MUI
; reads and then clears them inside MUI_PAGE_FINISH.  They used to sit
; at the end of this file, after the page was already built, so the
; "Launch StockFW" box never appeared.
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APP_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "Launch ${APP_NAME}"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

;------------------------------------------------------------------------------
; Language
;------------------------------------------------------------------------------
!insertmacro MUI_LANGUAGE "English"

;------------------------------------------------------------------------------
; General Settings
;------------------------------------------------------------------------------
Name "${APP_NAME} ${APP_VERSION}"
OutFile "${INSTALLER_NAME}"
InstallDir "$PROGRAMFILES64\${APP_NAME}"
InstallDirRegKey HKLM "Software\${APP_NAME}" "InstallDir"
RequestExecutionLevel admin
ShowInstDetails show

;------------------------------------------------------------------------------
; Variables
;------------------------------------------------------------------------------
Var PreviousUninstall
Var StartMenuFolder
Var CreateDesktopShortcut
Var RunAfterInstall

;------------------------------------------------------------------------------
; Sections
;------------------------------------------------------------------------------
Section "Main Application" SecMain
    SectionIn RO

    ; Create install directory
    SetOutPath "$INSTDIR"

    ; Main executable
    File "${PROJECT_DIR}\installer\nsis\stage\StockFW.exe"

    ; GTK3 DLLs MUST be in the SAME folder as StockFW.exe
    ; Windows loads DLLs from the exe's own directory first
    SetOutPath "$INSTDIR"
    File /nonfatal /r "${PROJECT_DIR}\installer\nsis\stage\gtk-runtime\bin\*.dll"

    ; GLib runs children through gspawn-win64-helper*.exe (exec'd, never
    ; linked, so no dependency scan sees them).  The *.dll line above
    ; silently skipped them -- they are .exe -- and the installed copy
    ; then failed every g_spawn with "Failed to execute helper program
    ; (No such file or directory)": wevtutil never ran, Events stayed
    ; empty with that error, netsh could not apply rules.  Not /nonfatal:
    ; an installer missing these is broken, so makensis must fail.
    File "${PROJECT_DIR}\installer\nsis\stage\gtk-runtime\bin\gspawn-win64-helper.exe"
    File "${PROJECT_DIR}\installer\nsis\stage\gtk-runtime\bin\gspawn-win64-helper-console.exe"

    ; GTK3 support directories (modules, themes, icons, locales)
    SetOutPath "$INSTDIR\lib"
    File /nonfatal /r "${PROJECT_DIR}\installer\nsis\stage\gtk-runtime\lib\*"

    SetOutPath "$INSTDIR\share"
    File /nonfatal /r "${PROJECT_DIR}\installer\nsis\stage\gtk-runtime\share\*"

    SetOutPath "$INSTDIR\etc"
    File /nonfatal /r "${PROJECT_DIR}\installer\nsis\stage\gtk-runtime\etc\*"

    ; Back to install root for remaining files
    SetOutPath "$INSTDIR"

    ; Elevated launchers
    File "${PROJECT_DIR}\installer\nsis\stage\StockFW-elevated.vbs"
    File "${PROJECT_DIR}\installer\nsis\stage\StockFW-elevated.cmd"
    File "${PROJECT_DIR}\installer\nsis\stage\StockFW-elevated.ps1"

    ; Documentation
    File "${PROJECT_DIR}\installer\nsis\stage\README.md"
    File /nonfatal "${PROJECT_DIR}\installer\nsis\stage\CHANGELOG.md"

    ; Write uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"

    ; Store install path in registry
    WriteRegStr HKLM "Software\${APP_NAME}" "InstallDir" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "DisplayName" "${APP_NAME} ${APP_VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "UninstallString" "$INSTDIR\uninstall.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "DisplayVersion" "${APP_VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "Publisher" "${APP_PUBLISHER}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "URLInfoAbout" "${APP_WEBSITE}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "InstallLocation" "$INSTDIR"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "NoRepair" 1

    ; Create Start Menu shortcuts
    CreateDirectory "$SMPROGRAMS\${APP_NAME}"
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}" 0
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\${APP_NAME} (Elevated).lnk" "$INSTDIR\StockFW-elevated.vbs" "" "$INSTDIR\StockFW-elevated.vbs" 0
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\Documentation.lnk" "$INSTDIR\README.md" "" "$INSTDIR\README.md" 0

SectionEnd

Section "Desktop Shortcut" SecDesktop
    CreateShortcut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}" 0
SectionEnd

; Ticked by default.  StockFW.exe registers a Task Scheduler task for the
; account running this installer (src/core/fs-autostart.c): at that
; account's sign-in it starts "StockFW.exe --background" with the highest
; privileges, so it comes up in the notification area without a UAC
; prompt.  The installer already runs elevated, which registering an
; elevated task needs.  A failure is reported and does not fail the
; install: the option is also in StockFW's tray menu.
Section "Start StockFW in the background when I sign in" SecAutostart
    DetailPrint "Setting ${APP_NAME} to start in the background at sign-in..."
    ClearErrors
    ExecWait '"$INSTDIR\${APP_EXE}" --enable-autostart' $0
    ${If} ${Errors}
    ${OrIf} $0 != 0
        DetailPrint "Could not set up start at sign-in (exit code $0).  Turn it on later from the ${APP_NAME} tray menu."
    ${EndIf}
SectionEnd

;------------------------------------------------------------------------------
; Section Descriptions (disabled to avoid MUI2 warnings)
;------------------------------------------------------------------------------
; !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
;     !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "Installs the StockFW firewall configuration tool with GTK3 runtime."
;     !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "Creates a shortcut on your desktop for quick access."
; !insertmacro MUI_FUNCTION_DESCRIPTION_END

;------------------------------------------------------------------------------
; Custom Functions
;------------------------------------------------------------------------------
Function .onInit
    ; Check for previous installation
    ReadRegStr $PreviousUninstall HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "UninstallString"
    StrCmp $PreviousUninstall "" 0 PreviousInstallFound
    Goto NoPreviousInstall

    PreviousInstallFound:
    MessageBox MB_YESNO|MB_ICONQUESTION \
        "A previous version of ${APP_NAME} was detected. Do you want to uninstall it first?" \
        IDYES UninstallPrevious IDNO NoPreviousInstall

    UninstallPrevious:
    ClearErrors
    ExecWait '"$PreviousUninstall" /S'
    IfErrors NoPreviousInstall
    Goto NoPreviousInstall

    NoPreviousInstall:
FunctionEnd

Function .onInstSuccess
    ; Hide "Run after install" checkbox if not needed
    ; We'll handle this in the finish page
FunctionEnd

; Custom Welcome Page with branding
Function customWelcome
    !insertmacro MUI_HEADER_TEXT "Welcome to ${APP_NAME} Setup" "This wizard will guide you through the installation of ${APP_NAME} ${APP_VERSION}."
FunctionEnd

; Custom Finish Page
Function customFinish
    !insertmacro MUI_HEADER_TEXT "Installation Complete" "${APP_NAME} ${APP_VERSION} has been successfully installed."
FunctionEnd

;------------------------------------------------------------------------------
; Uninstaller
;------------------------------------------------------------------------------
; Is the app running?  In: $R7 = image name.  Out: $R7 = 1 running, 0 not.
;
; tasklist's exit code is 0 whether or not a row matched, so it cannot serve as
; the signal.  The verdict comes from its output text instead: a matched row
; always contains the image name, and the localised "no tasks" notice never
; does, so containment is locale-proof.  StrStr rather than a prefix compare,
; because a matched row arrives with a leading CRLF that the no-match line does
; not have -- a fixed-offset compare falls into that every time.  (Both facts
; were teeth-tested against the real tasklist before this was written.)
Function un.IsRunning
    Push $R8
    Push $R9
    nsExec::ExecToStack '"$SYSDIR\tasklist.exe" /FI "IMAGENAME eq $R7" /NH'
    Pop $R8                      ; exit code -- discarded, proved useless
    Pop $R8                      ; output text
    ${UnStrStr} $R9 $R8 "$R7"
    StrCmp $R9 "" not_running
        StrCpy $R7 1
        Goto done
    not_running:
        StrCpy $R7 0
    done:
    Pop $R9
    Pop $R8
FunctionEnd

; Wait for the app to stop, up to about five seconds.  Out: $R7 = 1 still
; running, 0 gone.
Function un.WaitForExit
    StrCpy $R9 0
    ${Do}
        StrCpy $R7 "${APP_EXE}"
        Call un.IsRunning
        ${If} $R7 = 0
            Return
        ${EndIf}
        IntOp $R9 $R9 + 1
        ${If} $R9 >= 20
            Return
        ${EndIf}
        Sleep 250
    ${Loop}
FunctionEnd

Section Uninstall
    ; Refuse to half-uninstall.  A running ${APP_EXE} has its image and the
    ; DLLs beside it locked by Windows, so the Delete lines below would fail
    ; silently and the non-recursive RMDir at the end would leave the whole
    ; binary tree behind -- roughly 47 MB of husk -- while the uninstaller
    ; still reported success.  A reinstall over the top cannot repair that.
    ; So find out first, and leave the machine untouched if the app cannot be
    ; closed.
    StrCpy $R7 "${APP_EXE}"
    Call un.IsRunning
    StrCmp $R7 0 NotRunning

    IfSilent CloseApp AskFirst

AskFirst:
    MessageBox MB_YESNO|MB_ICONEXCLAMATION \
        "${APP_EXE} is still running.$\r$\n$\r$\nUninstalling now would remove everything except the files Windows has locked, leaving a partial installation that a reinstall cannot repair.$\r$\n$\r$\nClose ${APP_NAME} and continue?" \
        /SD IDNO IDYES CloseApp

    MessageBox MB_ICONINFORMATION \
        "${APP_NAME} was not uninstalled.  Nothing was removed." \
        /SD IDOK
    Quit

CloseApp:
    ; Cleanest first: "StockFW.exe --quit" asks the running copy to quit
    ; through its own instance channel (src/core/fs-instance.c), so it
    ; saves its settings and Sentinel's state and leaves the firewall on;
    ; it returns once that copy is gone, or after 15 seconds.  A copy it
    ; cannot reach -- another user's -- falls through to taskkill.
    DetailPrint "${APP_EXE} is running; asking it to quit before removing files."
    ExecWait '"$INSTDIR\${APP_EXE}" --quit' $R8
    Call un.WaitForExit
    StrCmp $R7 0 NotRunning

    ; Then graceful -- taskkill without /F posts WM_CLOSE, so the app gets to
    ; exit on its own terms and may refuse.  Only force it if it ignores that.
    DetailPrint "${APP_EXE} is still running; closing it before removing files."
    nsExec::ExecToStack '"$SYSDIR\taskkill.exe" /IM ${APP_EXE}'
    Pop $R7
    Pop $R8
    Call un.WaitForExit
    StrCmp $R7 0 NotRunning

    DetailPrint "A graceful close was ignored; forcing ${APP_EXE} to stop."
    nsExec::ExecToStack '"$SYSDIR\taskkill.exe" /F /IM ${APP_EXE}'
    Pop $R7
    Pop $R8
    Call un.WaitForExit
    StrCmp $R7 0 NotRunning

    MessageBox MB_ICONEXCLAMATION \
        "${APP_EXE} would not stop, so nothing was uninstalled.$\r$\n$\r$\nYour installation is untouched.  Close ${APP_NAME} yourself, then run Uninstall again." \
        /SD IDOK
    Quit

NotRunning:
    ; Start at sign-in: every user's task in the \StockFW Task Scheduler
    ; folder, and the folder.  Before the files go -- it is StockFW.exe
    ; that removes them -- and whatever the outcome, since a task left
    ; behind would only fail to start a program that is gone.
    DetailPrint "Removing ${APP_NAME}'s sign-in tasks..."
    ExecWait '"$INSTDIR\${APP_EXE}" --remove-all-autostart' $R8

    ; Remove files
    Delete "$INSTDIR\${APP_EXE}"
    Delete "$INSTDIR\uninstall.exe"
    Delete "$INSTDIR\StockFW-elevated.vbs"
    Delete "$INSTDIR\StockFW-elevated.cmd"
    Delete "$INSTDIR\StockFW-elevated.ps1"
    Delete "$INSTDIR\README.md"
    Delete "$INSTDIR\CHANGELOG.md"

    ; Remove ALL DLLs in install root
    Delete "$INSTDIR\*.dll"
    ; The spawn helpers are .exe, so *.dll never covered them.
    Delete "$INSTDIR\gspawn-win64-helper.exe"
    Delete "$INSTDIR\gspawn-win64-helper-console.exe"

    ; Remove GTK support directories
    RMDir /r "$INSTDIR\lib"
    RMDir /r "$INSTDIR\share"
    RMDir /r "$INSTDIR\etc"
    RMDir /r "$INSTDIR\gtk-runtime"
    RMDir /r "$INSTDIR\gtk-3.0"
    RMDir /r "$INSTDIR\gdk-pixbuf-2.0"
    RMDir /r "$INSTDIR\pango"
    RMDir /r "$INSTDIR\themes"
    RMDir /r "$INSTDIR\icons"
    RMDir /r "$INSTDIR\locale"

    ; Remove shortcuts
    Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"
    Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME} (Elevated).lnk"
    Delete "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk"
    Delete "$SMPROGRAMS\${APP_NAME}\Documentation.lnk"
    Delete "$DESKTOP\${APP_NAME}.lnk"

    ; Remove Start Menu folder
    RMDir "$SMPROGRAMS\${APP_NAME}"

    ; Remove registry keys
    DeleteRegKey HKLM "Software\${APP_NAME}"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"

    ; Remove install directory
    RMDir "$INSTDIR"

    ; RMDir only succeeds on an empty directory, and it fails silently.  If
    ; anything survived -- most often a file another process still holds --
    ; say so, rather than letting the user believe the uninstall was clean.
    IfFileExists "$INSTDIR\*.*" 0 UninstallComplete
        MessageBox MB_ICONEXCLAMATION \
            "Some files in:$\r$\n$INSTDIR$\r$\ncould not be removed because they are still in use.$\r$\n$\r$\nThey have been left behind and must be removed by hand." \
            /SD IDOK
    UninstallComplete:
SectionEnd

;------------------------------------------------------------------------------
; Custom UI Functions (Optional - for advanced branding)
;------------------------------------------------------------------------------
Function guiInit
    ; Enable visual styles (Windows XP+)
    System::Call 'comctl32::InitCommonControlsEx(i)i'
FunctionEnd

;------------------------------------------------------------------------------
; End
;------------------------------------------------------------------------------