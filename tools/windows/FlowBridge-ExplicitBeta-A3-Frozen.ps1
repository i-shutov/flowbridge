#requires -Version 5.1
<#
.SYNOPSIS
    FlowBridge explicit-beta A3 exact-source Windows 10/11 owner acceptance.
.DESCRIPTION
    Defaults to ZIP provenance checks and Python pinned-byte preflight.
    -Execute is an explicit operator action: beta install/GUI/TCP/upgrade/uninstall.
    NEVER installs a driver, alters Defender/firewall/BFE/Secure Boot, or
    accepts transparent routing, DNS no-leak, A3 manual GUI or release 1.0.
    Outputs go to a newly created evidence directory; no user data removed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$KitZip,
    [string]$ExpectedComputerName = 'VM-910136',
    [string]$OutputRoot = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'FlowBridge-A3'),
    [switch]$Execute
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ExpectedSource = 'f5ecd48d8f81c594f755a55e7969b57d20903020'
$ExpectedKit = '4b51d4136878476b48946361ce1635cb6d630e62b50ca82c73df28a5902ed8b8'
$ExpectedInstaller = '74ff309d2e8ae115083bed9c5d4f233fd02dc841a8084a22912f3430c1e4b504'
$ExpectedManifest = '4a16dd710e468dd6e13e387fa4640c00102771758b4a5eb8c5f7bf9ec62bbf9a'
$ExpectedTool = 'faf62aabeea95ef316f5c0935177a65820ea4679ac94afe8b5461138dd17a33c'
$ExpectedKitName = 'FlowBridge-0.3.0-beta.1-candidate-f5ecd48d8f81.zip'

function Assert-True([bool]$Value, [string]$Code) {
    if (-not $Value) { throw $Code }
}
function Assert-Hash([string]$FilePath, [string]$Expected) {
    Assert-True (Test-Path -LiteralPath $FilePath -PathType Leaf) 'PINNED_FILE_MISSING'
    $item = Get-Item -LiteralPath $FilePath
    Assert-True (-not [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'PINNED_FILE_IS_LINK'
    $actual = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True ($actual -eq $Expected) 'PINNED_SHA256_MISMATCH'
}
function Assert-TargetOS {
    Assert-True ([Environment]::Is64BitOperatingSystem) 'TARGET_NOT_X64'
    $os = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    Assert-True ($os.InstallationType -eq 'Client') 'WINDOWS_SERVER_NOT_TARGET'
    $build = [int]$os.CurrentBuildNumber
    Assert-True ($build -ge 19045) 'UNSUPPORTED_WINDOWS_BUILD'
    $edition = [string]$os.EditionID
    Assert-True ($edition -match '^Professional') 'UNSUPPORTED_WINDOWS_EDITION'
    Assert-True (-not [string]::IsNullOrWhiteSpace($ExpectedComputerName)) 'EXPECTED_HOST_REQUIRED'
    Assert-True ([Environment]::MachineName.Equals($ExpectedComputerName,[StringComparison]::OrdinalIgnoreCase)) 'WRONG_TARGET_HOST'
}

Assert-True (Test-Path -LiteralPath $KitZip -PathType Leaf) 'KIT_ZIP_MISSING'
Assert-True ([IO.Path]::GetFileName($KitZip) -eq $ExpectedKitName) 'KIT_NAME_MISMATCH'
Assert-Hash $KitZip $ExpectedKit
Assert-TargetOS
if ($Execute) {
    Assert-True (-not ($env:GITHUB_ACTIONS -or $env:CI)) 'REFUSE_MUTATING_QA_IN_CI'
}
$launcher = Get-Command py.exe -ErrorAction SilentlyContinue
Assert-True ($null -ne $launcher) 'PYTHON_LAUNCHER_NOT_FOUND'
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$unique = [Guid]::NewGuid().ToString('N').Substring(0,8)
$run = Join-Path $OutputRoot ('a3-' + $stamp + '-' + $unique)
Assert-True (-not (Test-Path -LiteralPath $run)) 'EVIDENCE_PATH_EXISTS'
[void](New-Item -ItemType Directory -Path $run -Force:$false)
$extracted = Join-Path $run 'kit'
[void](New-Item -ItemType Directory -Path $extracted -Force:$false)
# The exact ZIP digest is verified BEFORE extraction; an attacker cannot replace
# the source index or insert a path alias without invalidating the owner pin.
Expand-Archive -LiteralPath $KitZip -DestinationPath $extracted -ErrorAction Stop
$manifest = Join-Path $extracted 'windows\explicit-beta-package.json'
$package = Join-Path $extracted 'windows\FlowBridge-0.3.0-beta.1-windows-x64-setup.exe'
$harness = Join-Path $extracted 'windows\FlowBridgeNativeSmoke.exe'
$tool = Join-Path $extracted 'tools\explicit_beta_acceptance.py'
Assert-Hash $manifest $ExpectedManifest
Assert-Hash $package $ExpectedInstaller
Assert-Hash $tool $ExpectedTool
Assert-True (Test-Path -LiteralPath $harness -PathType Leaf) 'HARNESS_MISSING'
$arguments = @(
    '-3', $tool, '--manifest', $manifest, '--package', $package, '--harness', $harness,
    '--expected-source', $ExpectedSource,
    '--expected-package-sha256', $ExpectedInstaller,
    '--expected-manifest-sha256', $ExpectedManifest,
    '--expected-tool-sha256', $ExpectedTool,
    '--expected-computer', $ExpectedComputerName
)
$preflight = Join-Path $run 'native-preflight'
& $launcher.Source @arguments '--output' $preflight
Assert-True ($LASTEXITCODE -eq 0) 'A3_PREFLIGHT_FAILED'
Write-Host ('A3_BYTES_PASS; evidence=' + $preflight) -ForegroundColor Green
if (-not $Execute) {
    Write-Host 'A3_NATIVE_NOT_RUN; run with -Execute only in an interactive owner Windows desktop.' -ForegroundColor Yellow
    exit 0
}
$native = Join-Path $run 'native-automated'
& $launcher.Source @arguments '--execute' '--output' $native
Assert-True ($LASTEXITCODE -eq 0) 'A3_NATIVE_AUTOMATED_FAILED'
$reportPath = Join-Path $native 'native-acceptance.json'
Assert-True (Test-Path -LiteralPath $reportPath -PathType Leaf) 'A3_NATIVE_REPORT_MISSING'
$report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
Assert-True ($report.status -eq 'OWNER_NATIVE_AUTOMATED_CHECKS_PASS') 'A3_OWNER_AUTOMATED_STATUS_INVALID'
Assert-True (-not $report.release_accepted -and -not $report.a3_a4_full_acceptance) 'A3_MISLEADING_RELEASE_VERDICT'
Write-Host ('A3_AUTOMATED_PASS_MANUAL_GUI_SSH_OPEN; evidence=' + $native) -ForegroundColor Green
