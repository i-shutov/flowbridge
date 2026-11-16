# Provision a NEW disconnected Windows 11 Generation-2 Hyper-V VM only.
# Default audit-only. No Hyper-V installation, HOST restart/BCD, networking,
# service or WFP driver modification. Partial failures are NOT auto-deleted.
[CmdletBinding()]
param(
  [ValidatePattern('^FlowBridge-R39-DEV-W11(-[A-Za-z0-9]{1,20})?$')]
  [string]$VMName='FlowBridge-R39-DEV-W11',
  [string]$VMRoot=(Join-Path $env:ProgramData 'FlowBridgeLab'),
  [string]$IsoPath='',
  [ValidateRange(4,64)][int]$GuestMemoryGB=6,
  [ValidateRange(2,64)][int]$GuestVcpu=2,
  [ValidateRange(64,1024)][int]$GuestDiskGB=96,
  [ValidatePattern('^([a-fA-F0-9]{64})?$')][string]$ExpectedIsoSha256='',
  [switch]$Apply,
  [string]$OutputPath=''
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$auditText= & (Join-Path $PSScriptRoot 'host-preflight.ps1') -VMRoot $VMRoot -IsoPath $IsoPath -GuestMemoryGB $GuestMemoryGB -GuestVcpu $GuestVcpu -GuestDiskGB $GuestDiskGB
$preflight=$auditText|ConvertFrom-Json -AsHashtable
$report=[ordered]@{
  schema='flowbridge-r39-win11-vm-creation-v1'
  vm_name=$VMName
  mode=$(if($Apply){'APPLY'}else{'AUDIT_ONLY'})
  status='NOT_CREATED'
  host_preflight=$preflight
  iso_sha256=''
  vm_created=$false
  secure_boot='NOT_CONFIGURED'
  vtpm_enabled=$false
  network='NONE'
  guest_os_installed=$false
  host_bcd_modified=$false
  driver_signed=$false
  driver_loaded=$false
  g2_pass=$false
  error=''
}
try {
  if (-not $Apply) {
    $report.status='AUDIT_ONLY_NO_HOST_CHANGE'
  } else {
    if (-not $preflight.ready_to_create) {
      throw 'Host blocked: insufficient memory/cpu/disk, ISO, admin or Hyper-V. Examine preflight JSON.'
    }
    if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
      throw 'Refusing to modify an existing VM, even if stopped.'
    }
    # Operator must supply an official ISO. No automatic download or bypass.
    $isoSha=(Get-FileHash -LiteralPath $IsoPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ExpectedIsoSha256 -and $ExpectedIsoSha256.ToLowerInvariant() -ne $isoSha) {
      throw 'ISO SHA-256 differs from operator-pinned expected value.'
    }
    $report.iso_sha256=$isoSha
    $folder=[IO.Path]::GetFullPath($VMRoot)
    if (-not (Test-Path -LiteralPath $folder)) {
      $null=New-Item -ItemType Directory -Path $folder -Force
    }
    $diskDir=Join-Path $folder 'Virtual Hard Disks'
    if (-not (Test-Path -LiteralPath $diskDir)) {
      $null=New-Item -ItemType Directory -Path $diskDir -Force
    }
    $vhdx=Join-Path $diskDir ($VMName+'.vhdx')
    if (Test-Path -LiteralPath $vhdx) { throw 'Refusing to overwrite existing VHDX.' }
    # No virtual switch, physical adapter, port forwarding or NAT is modified.
    $null=New-VM -Name $VMName -Generation 2 -MemoryStartupBytes ([long]$GuestMemoryGB*1GB) -NoVHD -Path $folder -ErrorAction Stop
    $report.vm_created=$true
    $null=New-VHD -Path $vhdx -SizeBytes ([long]$GuestDiskGB*1GB) -Dynamic -ErrorAction Stop
    Add-VMHardDiskDrive -VMName $VMName -Path $vhdx -ErrorAction Stop
    Add-VMDvdDrive -VMName $VMName -Path ([IO.Path]::GetFullPath($IsoPath)) -ErrorAction Stop
    Set-VMProcessor -VMName $VMName -Count $GuestVcpu -ErrorAction Stop
    Set-VM -Name $VMName -CheckpointType Standard -AutomaticCheckpointsEnabled $false -AutomaticStartAction Nothing -ErrorAction Stop
    Set-VMKeyProtector -VMName $VMName -NewLocalKeyProtector -ErrorAction Stop
    Enable-VMTPM -VMName $VMName -ErrorAction Stop
    $report.vtpm_enabled=$true
    $dvd=Get-VMDvdDrive -VMName $VMName -ErrorAction Stop|Select-Object -First 1
    Set-VMFirmware -VMName $VMName -EnableSecureBoot On -FirstBootDevice $dvd -ErrorAction Stop
    $report.secure_boot='ON_FOR_WINDOWS_INSTALL'
    Get-VMNetworkAdapter -VMName $VMName -ErrorAction Stop | Disconnect-VMNetworkAdapter -ErrorAction Stop
    $report.network='DISCONNECTED'
    $vm=Get-VM -Name $VMName -ErrorAction Stop
    if ([int]$vm.Generation -ne 2 -or [string]$vm.State -ne 'Off') {
      throw 'VM unexpectedly changed generation or started.'
    }
    $report.status='CREATED_OFF_AWAITING_WINDOWS_INSTALL'
  }
} catch {
  $report.error=[string]$_.Exception.Message
  $report.status='STOPPED_REQUIRES_REVIEW_NO_AUTO_CLEANUP'
}
$json=$report|ConvertTo-Json -Depth 8
if ($OutputPath) {
  $dest=[IO.Path]::GetFullPath($OutputPath)
  $parent=Split-Path -Parent $dest
  if (-not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force|Out-Null
  }
  [IO.File]::WriteAllText($dest,$json+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
}
Write-Output $json
if ($report.error) { exit 2 }
