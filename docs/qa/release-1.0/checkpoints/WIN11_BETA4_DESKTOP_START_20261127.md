# Start the original beta.4 desktop QA on Win11

The Win11 runner was observed in Session 0 with no active desktop sessions.
Use the existing VM console or approved RDP access to sign in as
`VM-326272\Admin` on `VM-326272`. Keep that desktop connected and unlocked and
open Windows PowerShell there. The retained test state was recovered in run46043723863 and the complete
headless lifecycle passed in run46043764383. Recheck the beta namespace with
the pinned preflight before starting a new desktop run. The runner's own terminal remains
in Session 0 even while Admin is signed in.

The instructions below are commands to paste into a local PowerShell terminal.
The existing Restricted policy permits this and Python execution. For the
native compact geometry check, the actual desktop work area must contain the
980 × 680 test window. A 1366 × 768 client display is usually sufficient.
Use the monitor and DPI the desktop actually reports.

## Pinned preflight and automated Win32 smoke

These are the original private bytes from build 46040903481, attempt 1. All
outputs are local to a new private work directory outside the candidate.

```powershell
$ErrorActionPreference = 'Stop'
$who = [Security.Principal.WindowsIdentity]::GetCurrent()
$os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if ($env:COMPUTERNAME -ine 'VM-326272' -or $who.Name -ine 'VM-326272\Admin' -or
    (Get-Process -Id $PID).SessionId -eq 0 -or $os.CurrentBuildNumber -ne '22631' -or
    $os.EditionID -ne 'Professional' -or -not [Environment]::Is64BitOperatingSystem) {
    throw 'Open PowerShell on the unlocked VM-326272 Win11 Admin desktop'
}
$base = 'C:\FlowBridge\private-candidates'
$root = Join-Path $base 'run-beta4-46040903481-1\candidate'
$python = Join-Path $base 'toolchain-45986630920-1\python\tools\python.exe'
$run = Join-Path $base ('desktop-beta4-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $run)
& "$env:SystemRoot\System32\icacls.exe" $run /inheritance:r /grant:r `
    ('*' + $who.User.Value + ':(OI)(CI)F') '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' |
    Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Private evidence ACL setup failed' }

$source = 'c8881dada43e3183a0340dc823105bdcdac71171'
$tree = 'ce336e83bb724a65bf512e79e286c97fb0cb3190'
$packageSha = 'e0e4491cd97b30aa52b52ce89a7a8396a2fc11902bec3e70bed8ebfd722450b0'
$manifestSha = '3542633d089aff80e379f30db8be6f301edae462f38f70ea07c5b8ba76011703'
$harnessSha = '46cd8970cf669e0be3493998aeec6ba30ecb464dd399d0c3cdd972444e193a32'
$toolSha = 'faf62aabeea95ef316f5c0935177a65820ea4679ac94afe8b5461138dd17a33c'
$probeSha = '89fcff121b1cd12c6b8a0e315bfdf73599157dd1d11e79cc713a90a73230e858'
$package = Join-Path $root 'artifacts\FlowBridge-0.3.0-beta.4-windows-x64-setup.exe'
$manifest = Join-Path $root 'build\verification\explicit-beta-package.json'
$harness = Join-Path $root 'build\windows-explicit-beta\Release\FlowBridgeNativeSmoke.exe'
$tool = Join-Path $root 'tools\explicit_beta_acceptance.py'
$probe = Join-Path $run 'win11_explicit_beta_preflight.py'
$url = 'https://raw.githubusercontent.com/i-shutov/flowbridge/562ac8fb5087d820a4b213b08dffb24c4ed1680e/tools/win11_explicit_beta_preflight.py'
Invoke-WebRequest -Uri $url -OutFile $probe -UseBasicParsing -TimeoutSec 20
if ((Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash -ine $probeSha) {
    throw 'Wrong Win11 preflight bytes'
}
$readOnly = @($probe, '--candidate-root', $root, '--expected-source', $source,
    '--expected-tree', $tree, '--expected-installer-sha256', $packageSha,
    '--expected-manifest-sha256', $manifestSha, '--expected-harness-sha256', $harnessSha,
    '--expected-tool-sha256', $toolSha)
$checks = & $python -I -X utf8 -B @readOnly
$code = $LASTEXITCODE
$reportPath = Join-Path $run 'desktop-preflight.json'
$checks | Set-Content -LiteralPath $reportPath -Encoding UTF8
if ($code -ne 0) { throw 'Pin or Win11 preflight blocked. Read desktop-preflight.json locally' }
$report = ($checks -join "`n") | ConvertFrom-Json
if ($report.desktop.status -ne 'INTERACTIVE_DESKTOP_OBSERVED' -or
    $report.isolation -ne 'ISOLATION_BASELINE_AVAILABLE' -or
    $report.candidate.status -ne 'VERIFIED_BYTES') {
    throw 'Desktop, isolation, or candidate checks blocked. Read desktop-preflight.json locally'
}
if ((Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash -ine $toolSha) {
    throw 'Wrong acceptance tool bytes'
}

$common = @($tool, '--package', $package, '--manifest', $manifest, '--harness', $harness,
    '--expected-source', $source, '--expected-package-sha256', $packageSha,
    '--expected-manifest-sha256', $manifestSha, '--expected-tool-sha256', $toolSha,
    '--expected-computer', 'VM-326272')
# Keep even intermediate installer and DLL files within this private directory.
$temp = Join-Path $run 'tmp'
[void](New-Item -ItemType Directory -Path $temp)
$oldTemp, $oldTmp = $env:TEMP, $env:TMP
try {
    $env:TEMP = $temp
    $env:TMP = $temp
    & $python -I -X utf8 -B @common --execute --output (Join-Path $run 'native') |
        Set-Content -LiteralPath (Join-Path $run 'native-tool-output.json') -Encoding UTF8
    $exit = $LASTEXITCODE
    if ($exit -ne 0) { throw 'Win32 smoke failed. Read native-acceptance.json and cleanup status locally' }
} finally {
    $env:TEMP = $oldTemp
    $env:TMP = $oldTmp
}
```

The expected automated result is `OWNER_NATIVE_AUTOMATED_CHECKS_PASS`. The
source-pinned harness launches the exact installed GUI, matches its window
class and PID, checks its beta.4 title, tests real local TCP, checks controls
and captures five different compact-page BMPs. It also exercises the modal
rules editor. The harness's transport uses its own local echo, and its SSH
checks cover editing, validation and ingress/worker port collision. Only the
manual desktop cases below provide visual acceptance and authenticated GUI
OpenSSH evidence.

The tool can leave its test profile, work files or a partial installation.
Use `native-acceptance.json` to locate this run's owned paths and confirm
cleanup before a second harness run. Record any failure and leave unproven
objects for inspection. Keep evidence private, including the native BMPs.

## Remaining interactive checks

Use the same installer and matching installed GUI/FFI hashes for a fresh owned
GUI install after cleanup. To install into a unique path with no spaces, use
`Start-Process -FilePath $package -ArgumentList '/S', "/D=$guiInstall" -Wait -PassThru`.
Set `$guiInstall = Join-Path $run 'gui-install'` and verify it is absent with a
clean beta registration first. Require exit code 0, the expected registered
path and actual payload hashes. `Start-Process -FilePath (Join-Path $guiInstall
'FlowBridge.exe') -PassThru` launches the verified product from the same
desktop. Record the app PID, real foreground HWND, DPI and window geometry.

1. Visit Dashboard, Connection in managed SSH and external proxy modes,
   Apps, Advanced and the modal rule editor. Inspect rendered controls and
   keyboard focus at normal and compact geometry. Use Tab and Enter, verify
   the modal rule editor's Cancel preserves its parent draft, and test
   Apply, Save and Start/Stop. Record the observations separately from BMP
   evidence. Keep protected capture and system network settings untouched.
2. Follow the private [Win11 SSH case and restore protocol](WIN11_BETA4_NATIVE_ACCEPTANCE_20261127.md#4-exercise-the-installed-gui-and-real-ssh).
   Run a Microsoft-signed, loopback-only test sshd and a separate echo listener
   with a connection counter. Use one worker initially. Verify the GUI's
   managed readiness, test-owned OpenSSH process image, binary SOCKS5h echo
   and both EOFs. Then run wrong-host-key, missing-key, unsigned-backend
   rejection and journal redaction, all-down/recovery and Stop cases. Use
   separate ports for ingress, each worker, sshd and echo. With one worker,
   allow its recorded reconnect grace before asserting the all-down outcome.
3. Close only the test GUI, stop its fixture and remove the owner-verified
   test install with its own uninstaller. Verify registry, payload and
   listener cleanup and restore the original beta baseline. Retain sanitized
   outcomes and any private images or logs under the run directory.

## Which existing tools apply

| Tool | Applicability |
| --- | --- |
| Original `explicit_beta_acceptance.py` | Uses `sys.platform == win32` and the exact operator-supplied hostname. The pinned preflight supplies the Win11 edition/build and active-desktop guards. |
| Original `FlowBridgeNativeSmoke.exe` | Uses Win32 GUI APIs with no Win10 build guard. Requires actual monitor work area and checks the on-screen compact geometry. |
| Historical `FlowBridge-Win10-W2B0/W2B1/W2B2` scripts | Bind the target to Win10 build 19045 and have older CLI or GUI assumptions. |
| Historical `FlowBridge-ExplicitBeta-A3-Frozen.ps1` | Allows Windows Pro builds from 19045 but defaults to the old hostname and hard-pins beta.1 bytes. |
| `tests/windows_installed_real_ssh.py` | Guards for opt-in disposable hosted Windows. Its signed fixture recipe can guide the Win11 desktop exercise. |
