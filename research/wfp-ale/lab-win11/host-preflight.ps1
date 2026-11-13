# Read-only Hyper-V host capacity/capability report for FlowBridge R39-DEV.
# NO Hyper-V installation, VM creation, networking, BCD or driver operations.
[CmdletBinding()]
param(
  [string]$VMRoot = (Join-Path $env:ProgramData 'FlowBridgeLab'),
  [string]$IsoPath = '',
  [ValidateRange(4,64)][int]$GuestMemoryGB = 6,
  [ValidateRange(2,64)][int]$GuestVcpu = 2,
  [ValidateRange(64,1024)][int]$GuestDiskGB = 96,
  [string]$OutputPath = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$reported=[ordered]@{
  schema='flowbridge-r39-win11-host-audit-v1'
  at_utc=[DateTime]::UtcNow.ToString('o')
  admission='NOT_ADMITTED'
  any_host_changed=$false
  vm_created=$false
  driver_installed=$false
  guest_test_mode_enabled=$false
  vm_host=$env:COMPUTERNAME
  host_os=''
  host_total_memory_gb=0
  host_free_memory_gb=0
  host_logical_processors=0
  host_storage_free_gb=0
  guest_memory_gb=$GuestMemoryGB
  guest_vcpus=$GuestVcpu
  guest_vhdx_gb=$GuestDiskGB
  iso_path=$IsoPath
  iso_exists=$false
  is_administrator=$false
  hyperv_cmdlets_present=$false
  hyperv_host_operational=$false
  nested_virtualization_verified=$false
  host_resources_sufficient=$false
  ready_to_create=$false
  blockers=@()
}
$issues=[System.Collections.Generic.List[string]]::new()
try {
  if (-not $IsWindows) { throw 'Windows host required' }
  if ($env:GITHUB_ACTIONS -eq 'true') { $issues.Add('github_actions_runner_not_authorized_lab_host') }
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $reported.is_administrator=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $reported.is_administrator) { $issues.Add('elevated_powershell_required') }
  $os=Get-CimInstance Win32_OperatingSystem
  $cs=Get-CimInstance Win32_ComputerSystem
  $cpus=@(Get-CimInstance Win32_Processor)
  $reported.host_os=[string]$os.Caption
  $reported.host_total_memory_gb=[Math]::Round([double]$cs.TotalPhysicalMemory/1GB,2)
  $reported.host_free_memory_gb=[Math]::Round([double]$os.FreePhysicalMemory*1KB/1GB,2)
  $reported.host_logical_processors=(@($cpus|Measure-Object -Property NumberOfLogicalProcessors -Sum))[0].Sum
  if ($reported.host_total_memory_gb -lt ($GuestMemoryGB+8)) {
    $issues.Add('insufficient_total_ram_for_guest_plus_host_margin')
  }
  if ($reported.host_free_memory_gb -lt ($GuestMemoryGB+2)) {
    $issues.Add('insufficient_current_free_ram')
  }
  if ($reported.host_logical_processors -lt [Math]::Max(4,$GuestVcpu)) {
    $issues.Add('insufficient_cpu_threads')
  }
  $fullRoot=[IO.Path]::GetFullPath($VMRoot)
  if ($fullRoot.StartsWith('\\')) { throw 'UNC VM storage path not supported' }
  $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($fullRoot))
  $reported.host_storage_free_gb=[Math]::Round([double]$drive.AvailableFreeSpace/1GB,2)
  if ($reported.host_storage_free_gb -lt ($GuestDiskGB+24)) {
    $issues.Add('insufficient_free_disk_for_guest_and_checkpoints')
  }
  if ($IsoPath) {
    if (([IO.Path]::GetExtension($IsoPath)).ToLowerInvariant() -ne '.iso') {
      $issues.Add('iso_extension_required')
    } elseif (Test-Path -LiteralPath $IsoPath -PathType Leaf) {
      $reported.iso_exists=$true
    } else {
      $issues.Add('official_windows11_iso_not_present')
    }
  } else {
    $issues.Add('official_windows11_iso_not_supplied')
  }
  $reported.hyperv_cmdlets_present=($null -ne (Get-Command New-VM -ErrorAction SilentlyContinue))
  if (-not $reported.hyperv_cmdlets_present) {
    $issues.Add('hyperv_role_or_management_cmdlets_missing')
  } else {
    try {
      $null=Get-VMHost -ErrorAction Stop
      $reported.hyperv_host_operational=$true
    } catch {
      $issues.Add('hyperv_host_not_operational_or_nested_virtualization_absent')
    }
  }
  if (-not $reported.is_administrator -or -not $reported.hyperv_host_operational) {
    $reported.nested_virtualization_verified=$false
  }
  # Read-only cmdlets cannot independently prove outer-VPS VT-x/EPT pass-through.
  # A working Hyper-V host with real VM execution is still necessary.
  $reported.host_resources_sufficient=(
    $reported.host_total_memory_gb -ge ($GuestMemoryGB+8) -and
    $reported.host_free_memory_gb -ge ($GuestMemoryGB+2) -and
    $reported.host_logical_processors -ge [Math]::Max(4,$GuestVcpu) -and
    $reported.host_storage_free_gb -ge ($GuestDiskGB+24))
  $reported.ready_to_create=(
    $reported.is_administrator -and $reported.host_resources_sufficient -and
    $reported.hyperv_host_operational -and $reported.iso_exists -and $env:GITHUB_ACTIONS -ne 'true')
} catch {
  $issues.Add('preflight_error: '+[string]$_.Exception.Message)
}
$reported.blockers=@($issues)
if ($reported.ready_to_create) { $reported.admission='HOST_PRECHECK_ONLY' }
$result=$reported|ConvertTo-Json -Depth 6
if ($OutputPath) {
  $dest=[IO.Path]::GetFullPath($OutputPath)
  $dir=Split-Path -Parent $dest
  if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force|Out-Null }
  [IO.File]::WriteAllText($dest,$result+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
}
Write-Output $result
