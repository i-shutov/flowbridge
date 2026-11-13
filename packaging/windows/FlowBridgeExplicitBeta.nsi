; Limited engineering beta only. NO WFP/NDISRD/helper, no system traffic interception.
; Distinct HKCU registration, install directory and profile from stable FlowBridge.
; This is unsigned until the publisher provides an approved release signature.
Unicode true
; Use the standard x86 Unicode NSIS bootstrapper for the x64 payload.
; Official Windows NSIS packages do not ship amd64 stubs.
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "WinVer.nsh"

; Host paths passed to File must use the makensis host separator.
!ifdef NSIS_WIN32_MAKENSIS
  !define HOST_SEP "\"
!else
  !define HOST_SEP "/"
!endif

!ifndef PAYLOAD_DIR
  !error "Specify -DPAYLOAD_DIR=/absolute/path/to/staged/payload"
!endif
!ifndef OUTPUT_FILE
  !error "Specify OUTPUT_FILE from packaging/explicit-beta.json"
!endif
!ifndef VERSION
  !error "Specify VERSION from packaging/explicit-beta.json"
!endif
!ifndef FILE_VERSION
  !error "Specify FILE_VERSION from packaging/explicit-beta.json"
!endif
!define PRODUCT "FlowBridge Explicit SOCKS Beta"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridgeExplicitBeta"
Var ExistingInstallDir
Name "${PRODUCT} ${VERSION}"
OutFile "${OUTPUT_FILE}"
InstallDir "$LOCALAPPDATA\Programs\FlowBridge Explicit Beta"
InstallDirRegKey HKCU "Software\FlowBridgeExplicitBeta" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma
SetCompressorDictSize 32
BrandingText "FlowBridge Explicit SOCKS Beta — no driver / no interception"
VIProductVersion "${FILE_VERSION}"
VIAddVersionKey /LANG=1033 "ProductName" "FlowBridge"
VIAddVersionKey /LANG=1033 "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=1033 "FileDescription" "FlowBridge explicit SOCKS-only beta; no driver"
VIAddVersionKey /LANG=1033 "FileVersion" "${FILE_VERSION}"
VIAddVersionKey /LANG=1033 "LegalCopyright" "FlowBridge contributors"
!define MUI_ABORTWARNING
!define MUI_LANGDLL_REGISTRY_ROOT HKCU
!define MUI_LANGDLL_REGISTRY_KEY "Software\FlowBridgeExplicitBeta"
!define MUI_LANGDLL_REGISTRY_VALUENAME "InstallerLanguage"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${PAYLOAD_DIR}${HOST_SEP}LICENSE"
!define MUI_PAGE_CUSTOMFUNCTION_PRE DirectoryPre
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Russian"
!insertmacro MUI_RESERVEFILE_LANGDLL

LangString Running ${LANG_ENGLISH} "Close FlowBridge before installing or uninstalling. Existing traffic will stop when you close it. Then run this installer again."
LangString Running ${LANG_RUSSIAN} "Закройте FlowBridge перед установкой или удалением. При закрытии текущие соединения будут остановлены. Затем запустите установщик снова."
LangString Need64 ${LANG_ENGLISH} "FlowBridge requires 64-bit Windows 10 or later."
LangString Need64 ${LANG_RUSSIAN} "Для FlowBridge требуется 64-разрядная Windows 10 или более поздняя версия."

!macro CheckRunning
  System::Call 'kernel32::OpenMutexW(i 0x100000, i 0, w "Local\FlowBridge.NativeUI.v02") p .r0'
  ${If} $0 P<> 0
    System::Call 'kernel32::CloseHandle(p r0)'
    MessageBox MB_OK|MB_ICONEXCLAMATION "$(Running)"
    Abort
  ${EndIf}
!macroend
Function DirectoryPre
  ${If} $ExistingInstallDir != ""
    StrCpy $INSTDIR "$ExistingInstallDir"
    Abort
  ${EndIf}
FunctionEnd
Function .onInit
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_OK|MB_ICONSTOP "$(Need64)"
    Abort
  ${EndIf}
  ${IfNot} ${RunningX64}
    MessageBox MB_OK|MB_ICONSTOP "$(Need64)"
    Abort
  ${EndIf}
  SetShellVarContext current
  SetRegView 64
  ReadRegStr $ExistingInstallDir HKCU "Software\FlowBridgeExplicitBeta" "InstallDir"
  ${If} $ExistingInstallDir != ""
    StrCpy $INSTDIR "$ExistingInstallDir"
  ${EndIf}
  !insertmacro MUI_LANGDLL_DISPLAY
  !insertmacro CheckRunning
FunctionEnd
Function un.onInit
  SetShellVarContext current
  SetRegView 64
  !insertmacro MUI_UNGETLANGUAGE
  !insertmacro CheckRunning
FunctionEnd

Section "FlowBridge" SEC_MAIN
  SectionIn RO
  !insertmacro CheckRunning
  ; An upgrade replaces the registered installation, including silent /D runs.
  ${If} $ExistingInstallDir != ""
    StrCpy $INSTDIR "$ExistingInstallDir"
  ${EndIf}
  SetOutPath "$INSTDIR"
  File "${PAYLOAD_DIR}${HOST_SEP}FlowBridge.exe"
  File "${PAYLOAD_DIR}${HOST_SEP}flowbridge_ffi.dll"
  File "${PAYLOAD_DIR}${HOST_SEP}flowbridge-cli.exe"
  File "${PAYLOAD_DIR}${HOST_SEP}LICENSE"
  File "${PAYLOAD_DIR}${HOST_SEP}README.txt"
  File "${PAYLOAD_DIR}${HOST_SEP}SBOM.cdx.json"
  File "${PAYLOAD_DIR}${HOST_SEP}BUILD-METADATA.json"
  SetOutPath "$INSTDIR\examples"
  File "${PAYLOAD_DIR}${HOST_SEP}examples${HOST_SEP}*.json"
  SetOutPath "$INSTDIR\licenses"
  File "${PAYLOAD_DIR}${HOST_SEP}licenses${HOST_SEP}nlohmann-json-LICENSE.MIT"
  File "${PAYLOAD_DIR}${HOST_SEP}licenses${HOST_SEP}THIRD_PARTY_NOTICES.txt"
  SetOutPath "$INSTDIR\resources"
  File "${PAYLOAD_DIR}${HOST_SEP}resources${HOST_SEP}presets.json"
  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\FlowBridge Explicit Beta"
  CreateShortcut "$SMPROGRAMS\FlowBridge Explicit Beta\FlowBridge.lnk" "$INSTDIR\FlowBridge.exe"
  CreateShortcut "$SMPROGRAMS\FlowBridge Explicit Beta\Help.lnk" "$INSTDIR\README.txt"
  CreateShortcut "$SMPROGRAMS\FlowBridge Explicit Beta\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "Software\FlowBridgeExplicitBeta" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayName" "FlowBridge"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "Publisher" "FlowBridge contributors"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\FlowBridge.exe"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegStr HKCU "${UNINSTALL_KEY}" "QuietUninstallString" '$\"$INSTDIR\Uninstall.exe$\" /S'
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  !insertmacro CheckRunning
  ; Explicit known files only. Never recursively delete user-selected directories,
  ; profile data, or files the user added to the installation directory.
  Delete "$INSTDIR\FlowBridge.exe"
  Delete "$INSTDIR\flowbridge_ffi.dll"
  Delete "$INSTDIR\flowbridge-cli.exe"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\README.txt"
  Delete "$INSTDIR\SBOM.cdx.json"
  Delete "$INSTDIR\BUILD-METADATA.json"
  Delete "$INSTDIR\examples\ssh-socks.json"
  Delete "$INSTDIR\examples\chain.json"
  Delete "$INSTDIR\examples\direct.json"
  Delete "$INSTDIR\licenses\nlohmann-json-LICENSE.MIT"
  Delete "$INSTDIR\licenses\THIRD_PARTY_NOTICES.txt"
  Delete "$INSTDIR\resources\presets.json"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR\examples"
  RMDir "$INSTDIR\licenses"
  RMDir "$INSTDIR\resources"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\FlowBridge Explicit Beta\FlowBridge.lnk"
  Delete "$SMPROGRAMS\FlowBridge Explicit Beta\Help.lnk"
  Delete "$SMPROGRAMS\FlowBridge Explicit Beta\Uninstall.lnk"
  RMDir "$SMPROGRAMS\FlowBridge Explicit Beta"
  DeleteRegKey HKCU "${UNINSTALL_KEY}"
  DeleteRegValue HKCU "Software\FlowBridgeExplicitBeta" "InstallDir"
  ; Keep profile at $LOCALAPPDATA\FlowBridgeExplicitBeta and language preference.
SectionEnd
