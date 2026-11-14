# FlowBridge Win10 R39/Release read-only inventory, 2026-11-10.
# The specific host name is supplied by the caller and is not stored in this file.
# No installer, elevation attempt, driver load, registry write, WFP, BCD,
# Defender, firewall, service, runner, network, credential or RDP change.
# Only the caller-selected JSON report is written.
[CmdletBinding()]
param(
  [string]$ExpectedHost = '',
  [string]$OutputPath = (Join-Path ([IO.Path]::GetTempPath()) 'FlowBridge-Win10-ReadOnly-Inventory.json')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function FindExecutable([string]$name) {
  $cmd = Get-Command $name -ErrorAction SilentlyContinue
  if ($null -eq $cmd) { return $false }
  if ($cmd.Source -match '\\WindowsApps\\(?:python|python3)\.exe$') { return $false }
  return $true
}
function IsAvailable([string]$path) {
  return [bool](Test-Path -LiteralPath $path -PathType Leaf -ErrorAction SilentlyContinue)
}
$problems = [System.Collections.Generic.List[string]]::new()
$report = [ordered]@{
  schema = 'flowbridge-windows10-lab-inventory-v1'
  timestamp_utc = [DateTime]::UtcNow.ToString('o')
  intended_host = $ExpectedHost
  observed_host = $env:COMPUTERNAME
  expected_host_matched = ([bool]$ExpectedHost -and $ExpectedHost -ieq $env:COMPUTERNAME)
  os = [ordered]@{ name = 'unknown'; version=''; build=''; ubr=$null; x64=[Environment]::Is64BitOperatingSystem }
  identity = [ordered]@{ whoami = ''; elevated_admin = $false; integrity = 'unknown' }
  system = [ordered]@{ memory_gb=$null; free_memory_gb=$null; system_drive_free_gb=$null }
  tools = [ordered]@{}
  toolchain = [ordered]@{ msvc_files_found=$false; sdk_signtool_found=$false; wdk_inf2cat_found=$false }
  protections = [ordered]@{ secure_boot='unknown'; device_guard='unknown' }
  flowbridge_service_names = @()
  wfp_runtime_eligibility = 'NOT_ADMITTED'
  vnc_rescue_independently_verified = $false
  system_rescue_independently_verified = $false
  rollback_independently_verified = $false
  physical_egress_observer_verified = $false
  any_driver_installed_by_this_script = $false
  any_driver_loaded_by_this_script = $false
  wfp_or_bfe_changed_by_this_script = $false
  host_security_modified_by_this_script = $false
  remote_connection_test_performed = $false
  g2_pass = $false
  release_accepted = $false
  problems = @()
}
try {
  $registry = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
  $report.os.name=[string]$registry.ProductName
  $report.os.version=[string]$registry.DisplayVersion
  $report.os.build=[string]$registry.CurrentBuild
  $report.os.ubr=[int]$registry.UBR
} catch { $problems.Add('os_registry_read_failed') }
try {
  $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
  $report.os.name=[string]$os.Caption
  $report.os.build=[string]$os.BuildNumber
  $report.system.free_memory_gb=[Math]::Round([double]$os.FreePhysicalMemory / 1MB,2)
} catch {
  # Non-elevated Admin has previously received Access Denied from WMI on this
  # host. OS registry evidence is retained; no UAC bypass is attempted.
  $problems.Add('cim_operating_system_unavailable')
}
try {
  $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
  $report.system.memory_gb=[Math]::Round([double]$computer.TotalPhysicalMemory / 1GB,2)
} catch { $problems.Add('cim_computer_system_unavailable') }
try {
  $drive=Get-PSDrive -Name $env:SystemDrive.TrimEnd(':') -ErrorAction Stop
  $report.system.system_drive_free_gb=[Math]::Round([double]$drive.Free / 1GB,2)
} catch { $problems.Add('system_drive_space_unavailable') }
try {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $principal=[Security.Principal.WindowsPrincipal]::new($identity)
  $report.identity.whoami=[string]$identity.Name
  $report.identity.elevated_admin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  $groups=& whoami.exe /groups 2>$null | Out-String
  if ($groups -match 'S-1-16-12288') { $report.identity.integrity='high' }
  elseif ($groups -match 'S-1-16-8192') { $report.identity.integrity='medium' }
  elseif ($groups -match 'S-1-16-4096') { $report.identity.integrity='low' }
} catch { $problems.Add('process_identity_unavailable') }
foreach($command in @('git.exe','rustc.exe','cargo.exe','rustup.exe','python.exe','pwsh.exe','cmake.exe','node.exe','cl.exe','link.exe','signtool.exe','inf2cat.exe')) {
  $report.tools[$command]=FindExecutable $command
}
try {
  $pf86=[Environment]::GetFolderPath('ProgramFilesX86')
  $msvcRoot=Join-Path $pf86 'Microsoft Visual Studio\2022'
  if(Test-Path -LiteralPath $msvcRoot){
    $report.toolchain.msvc_files_found=(@(Get-ChildItem -Path $msvcRoot -Filter 'cl.exe' -Recurse -File -ErrorAction SilentlyContinue).Count -gt 0)
  }
  $kitRoot=Join-Path $pf86 'Windows Kits\10\bin'
  if(Test-Path -LiteralPath $kitRoot){
    $report.toolchain.sdk_signtool_found=(@(Get-ChildItem -Path $kitRoot -Filter 'signtool.exe' -Recurse -File -ErrorAction SilentlyContinue).Count -gt 0)
    $report.toolchain.wdk_inf2cat_found=(@(Get-ChildItem -Path $kitRoot -Filter 'inf2cat.exe' -Recurse -File -ErrorAction SilentlyContinue).Count -gt 0)
  }
} catch { $problems.Add('toolchain_files_unavailable') }
try {
  $boot=Confirm-SecureBootUEFI -ErrorAction Stop
  $report.protections.secure_boot= $(if($boot){'on'}else{'off'})
} catch { $report.protections.secure_boot='unavailable_or_unsupported' }
try {
  $dg=Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
  $report.protections.device_guard=(@($dg.SecurityServicesRunning) -join ',')
} catch { $report.protections.device_guard='unavailable_or_denied' }
try {
  $serviceRoot='HKLM:\SYSTEM\CurrentControlSet\Services'
  $names=@(Get-ChildItem -LiteralPath $serviceRoot -ErrorAction Stop |
    Where-Object { $_.PSChildName -like 'FlowBridge*' } |
    ForEach-Object { [string]$_.PSChildName })
  $report.flowbridge_service_names=$names
} catch { $problems.Add('service_registry_read_unavailable') }
if(-not $ExpectedHost){$problems.Add('expected_hostname_not_supplied')}
elseif(-not $report.expected_host_matched){$problems.Add('unexpected_hostname')}
if(-not $report.os.x64){$problems.Add('non_x64_os')}
if($report.os.build -ne '19045'){$problems.Add('expected_windows10_22h2_build_not_observed')}
if(-not $report.identity.elevated_admin){$problems.Add('not_elevated_for_future_kernel_operations')}
$report.problems=@($problems.ToArray())
$json=$report | ConvertTo-Json -Depth 8
try {
  $target=[IO.Path]::GetFullPath($OutputPath)
  $dir=Split-Path -Parent $target
  if(-not (Test-Path -LiteralPath $dir -PathType Container)){
    $null=New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop
  }
  [IO.File]::WriteAllText($target,$json+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
  Write-Output $json
} catch {
  Write-Output $json
  Write-Error ('Unable to write audit report: '+$_.Exception.Message)
  exit 2
}
