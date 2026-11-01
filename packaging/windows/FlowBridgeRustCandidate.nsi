; Independent user-owned Rust SSH/SOCKS engineering candidate. Never the
; legacy C++/WFP installer, no vendor driver, no SCM or protected-mode changes.
; The installed CLI is NOT a finished Windows application or a public release.
Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!ifndef PAYLOAD_DIR
  !error "PAYLOAD_DIR must be set to independently verified Rust artifacts"
!endif
!ifndef OUTPUT_FILE
  !error "OUTPUT_FILE must be set"
!endif

Name "FlowBridge Rust Candidate (SSH/SOCKS ONLY)"
OutFile "${OUTPUT_FILE}"
RequestExecutionLevel user
InstallDir "$LOCALAPPDATA\FlowBridge Rust Candidate"
ShowInstDetails show
ShowUninstDetails show
SetCompressor /SOLID lzma
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridgeRustCandidate"
!define SETTINGS_KEY "Software\FlowBridgeRustCandidate"

!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

; Do not install or uninstall binaries while a same-name Rust service might
; own them. Error 1060 means SCM confirms it does not exist; any other error
; is unsafe, including access denied, service running or an unknown state.
!macro RequireAbsentRustService
  nsExec::ExecToStack '"$SYSDIR\sc.exe" query FlowBridgeRustCandidateCI'
  Pop $0
  Pop $1
  ${If} $0 != "1060"
    DetailPrint "Rust SCM service is present or cannot be queried; no changes"
    SetErrorLevel 41
    Abort
  ${EndIf}
!macroend

Function .onInit
  SetShellVarContext current
  SetRegView 64
  ReadRegStr $0 HKCU "${SETTINGS_KEY}" "InstallDir"
  ${If} $0 != ""
    ; No in-place partial upgrades: uninstall the old candidate only after
    ; stopping all foreground processes; do not touch existing user profiles.
    SetErrorLevel 42
    Abort
  ${EndIf}
  !insertmacro RequireAbsentRustService
FunctionEnd

Function un.onInit
  SetShellVarContext current
  SetRegView 64
  !insertmacro RequireAbsentRustService
FunctionEnd

Section "Rust SSH/SOCKS candidate" SEC_MAIN
  SectionIn RO
  ; An arbitrary /D target may be user-selected. Fail BEFORE SetOutPath
  ; and File if the target already contains unrelated files or profiles.
  ; Never silently replace a same-name EXE in an unregistered directory.
  IfFileExists "$INSTDIR\*.*" 0 clean_candidate_target
    DetailPrint "Candidate target is occupied; refusing to overwrite any user file"
    SetErrorLevel 45
    Abort
  clean_candidate_target:
  SetOutPath "$INSTDIR"
  File "${PAYLOAD_DIR}\flowbridge.exe"
  File "${PAYLOAD_DIR}\flowbridge-agent.exe"
  File "${PAYLOAD_DIR}\manifest.json"
  File "${PAYLOAD_DIR}\README.md"
  File "${PAYLOAD_DIR}\LICENSE"
  IfErrors 0 +3
    SetErrorLevel 43
    Abort
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  IfErrors 0 +3
    SetErrorLevel 43
    Abort
  WriteRegStr HKCU "${SETTINGS_KEY}" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayName" "FlowBridge Rust Candidate (NOT RELEASE)"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayVersion" "0.2.0-candidate"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  ; Known candidate files only. Preserve every user-created profile/SSH key.
  ; Never recursively delete directories and never remove NDISRD or services.
  Delete "$INSTDIR\flowbridge-agent.exe"
  IfErrors 0 +3
    SetErrorLevel 44
    Abort
  Delete "$INSTDIR\flowbridge.exe"
  IfErrors 0 +3
    SetErrorLevel 44
    Abort
  Delete "$INSTDIR\manifest.json"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "${UNINSTALL_KEY}"
  DeleteRegKey HKCU "${SETTINGS_KEY}"
SectionEnd
