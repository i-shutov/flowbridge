Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "WinVer.nsh"
!ifndef PAYLOAD_DIR
!error "PAYLOAD_DIR is required"
!endif
!ifndef OUTPUT_FILE
!error "OUTPUT_FILE is required"
!endif
Name "FlowBridge internal native beta candidate"
OutFile "${OUTPUT_FILE}"
InstallDir "$PROGRAMFILES64\FlowBridgeBeta"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
BrandingText "Internal test candidate — signed WFP driver required separately"
!define KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridgeNativeBeta"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${PAYLOAD_DIR}\LICENSE"
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Russian"
!macro CheckStopped
  System::Call 'kernel32::OpenMutexW(i 0x100000, i 0, w "Global\FlowBridge.NativeCapture.Beta") p .r0'
  ${If} $0 P<> 0
    System::Call 'kernel32::CloseHandle(p r0)'
    MessageBox MB_OK|MB_ICONEXCLAMATION "Stop FlowBridge native capture before changing this installation."
    Abort
  ${EndIf}
  System::Call 'kernel32::OpenMutexW(i 0x100000, i 0, w "Local\FlowBridge.NativeUI.v02") p .r0'
  ${If} $0 P<> 0
    System::Call 'kernel32::CloseHandle(p r0)'
    MessageBox MB_OK|MB_ICONEXCLAMATION "Close FlowBridge before changing this installation."
    Abort
  ${EndIf}
!macroend
Function .onInit
  ${IfNot} ${RunningX64}
    Abort
  ${EndIf}
  ${IfNot} ${AtLeastWin10}
    Abort
  ${EndIf}
  SetRegView 64
  SetShellVarContext all
  StrCpy $INSTDIR "$PROGRAMFILES64\FlowBridgeBeta"
  !insertmacro CheckStopped
FunctionEnd
Function un.onInit
  SetRegView 64
  SetShellVarContext all
  !insertmacro CheckStopped
FunctionEnd
Section "Native beta candidate"
  !insertmacro CheckStopped
  ; No driver installation, boot changes, certificate trust or DNS changes.
  StrCpy $INSTDIR "$PROGRAMFILES64\FlowBridgeBeta"
  SetOutPath "$INSTDIR"
  File "${PAYLOAD_DIR}\FlowBridge.exe"
  File "${PAYLOAD_DIR}\FlowBridgeCapture.exe"
  File "${PAYLOAD_DIR}\flowbridge_ffi.dll"
  File "${PAYLOAD_DIR}\flowbridge-cli.exe"
  File "${PAYLOAD_DIR}\dns_policy.ps1"
  File "${PAYLOAD_DIR}\LICENSE"
  File "${PAYLOAD_DIR}\README.txt"
  SetOutPath "$INSTDIR\resources"
  File "${PAYLOAD_DIR}\resources\presets.json"
  SetOutPath "$INSTDIR\licenses"
  File "${PAYLOAD_DIR}\licenses\nlohmann-json-LICENSE.MIT"
  File "${PAYLOAD_DIR}\licenses\THIRD_PARTY_NOTICES.txt"
  SetOutPath "$INSTDIR"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\FlowBridge Native Beta"
  CreateShortcut "$SMPROGRAMS\FlowBridge Native Beta\FlowBridge.lnk" "$INSTDIR\FlowBridge.exe"
  WriteRegStr HKLM "${KEY}" "DisplayName" "FlowBridge internal native beta candidate"
  WriteRegStr HKLM "${KEY}" "DisplayVersion" "0.2.0-native-candidate"
  WriteRegStr HKLM "${KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${KEY}" "UninstallString" '$"$INSTDIR\Uninstall.exe$"'
  WriteRegDWORD HKLM "${KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${KEY}" "NoRepair" 1
SectionEnd
Section "Uninstall"
  !insertmacro CheckStopped
  ; The helper must already have restored DNS. Preserve all user profiles.
  Delete "$INSTDIR\FlowBridge.exe"
  Delete "$INSTDIR\FlowBridgeCapture.exe"
  Delete "$INSTDIR\flowbridge_ffi.dll"
  Delete "$INSTDIR\flowbridge-cli.exe"
  Delete "$INSTDIR\dns_policy.ps1"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\README.txt"
  Delete "$INSTDIR\resources\presets.json"
  Delete "$INSTDIR\licenses\nlohmann-json-LICENSE.MIT"
  Delete "$INSTDIR\licenses\THIRD_PARTY_NOTICES.txt"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR\resources"
  RMDir "$INSTDIR\licenses"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\FlowBridge Native Beta\FlowBridge.lnk"
  RMDir "$SMPROGRAMS\FlowBridge Native Beta"
  DeleteRegKey HKLM "${KEY}"
SectionEnd
