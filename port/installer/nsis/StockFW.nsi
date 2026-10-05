!define PROJECT_DIR "E:\PROJECTS\firestarter-1.0.3\firestarter-1.0.3\port"

!define APP_NAME "StockFW"
!define APP_VERSION "1.0.3"
!define APP_PUBLISHER "StockFW Project"
!define APP_WEBSITE "https://github.com/stockfw/stockfw"
!define APP_EXE "StockFW.exe"
!define INSTALLER_NAME "StockFW-${APP_VERSION}-Setup.exe"

;------------------------------------------------------------------------------
; Modern UI 2 Configuration
;------------------------------------------------------------------------------
!include MUI2.nsh

;------------------------------------------------------------------------------
; Custom Branding Resources
;------------------------------------------------------------------------------
!define MUI_ICON "${PROJECT_DIR}\installer\nsis\resources\stockfw_icon.ico"
!define MUI_UNICON "${PROJECT_DIR}\installer\nsis\resources\stockfw_icon.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "${PROJECT_DIR}\installer\nsis\resources\stockfw_header.bmp"
!define MUI_HEADERIMAGE_UNBITMAP "${PROJECT_DIR}\installer\nsis\resources\stockfw_header.bmp"

;------------------------------------------------------------------------------
; Modern UI Pages
;------------------------------------------------------------------------------
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${PROJECT_DIR}\installer\nsis\stage\LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
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

    ; GTK3 Runtime Dependencies - copy DLLs directly to install dir (same as .exe)
    File /nonfatal /r "${PROJECT_DIR}\installer\nsis\stage\gtk-runtime\bin\*"
    File /nonfatal /r "${PROJECT_DIR}\installer\nsis\stage\gtk-runtime\lib\*"
    File /nonfatal /r "${PROJECT_DIR}\installer\nsis\stage\gtk-runtime\share\*"
    File /nonfatal /r "${PROJECT_DIR}\installer\nsis\stage\gtk-runtime\etc\*"

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
Section Uninstall
    ; Remove files
    Delete "$INSTDIR\${APP_EXE}"
    Delete "$INSTDIR\uninstall.exe"
    Delete "$INSTDIR\StockFW-elevated.vbs"
    Delete "$INSTDIR\StockFW-elevated.cmd"
    Delete "$INSTDIR\StockFW-elevated.ps1"
    Delete "$INSTDIR\README.md"
    Delete "$INSTDIR\CHANGELOG.md"

    ; Remove GTK runtime
    RMDir /r "$INSTDIR\gtk-runtime"

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
SectionEnd

;------------------------------------------------------------------------------
; Custom UI Functions (Optional - for advanced branding)
;------------------------------------------------------------------------------
Function guiInit
    ; Enable visual styles (Windows XP+)
    System::Call 'comctl32::InitCommonControlsEx(i)i'
FunctionEnd

;------------------------------------------------------------------------------
; Modern UI Customizations
;------------------------------------------------------------------------------
; Custom bitmap for welcome page (optional)
; !define MUI_WELCOMEFINISHPAGE_BITMAP "${NSISDIR}\resources\stockfw_welcome.bmp"

; Custom finish page text
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APP_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "Launch ${APP_NAME}"
!define MUI_FINISHPAGE_SHOWREADME ""
!define MUI_FINISHPAGE_LINK "Visit ${APP_NAME} website"
!define MUI_FINISHPAGE_LINK_LOCATION "${APP_WEBSITE}"

;------------------------------------------------------------------------------
; End
;------------------------------------------------------------------------------