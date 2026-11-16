# HOST side, only for the dedicated OFF Windows 11 lab VM.
# Takes a Standard checkpoint before changing Secure Boot on THAT VM ONLY.
# Never changes host BCD, host firmware, host security or any other VM.
[CmdletBinding()]
param(
 [ValidatePattern('^FlowBridge-R39-DEV-W11(-[A-Za-z0-9]{1,20})?$')]
 [string]$VMName='FlowBridge-R39-DEV-W11',
 [switch]$Apply,
 [switch]$ConfirmWindowsInstalled,
 [switch]$ConfirmGuestBitLockerRecoverySafe,
 [string]$OutputPath=''
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$report=[ordered]@{
 schema='flowbridge-r39-win11-testmode-host-v1'
 vm_name=$VMName
 status='AUDIT_ONLY'
 vm_state=''
 checkpoint=''
 guest_secure_boot_previous=''
 guest_secure_boot_now=''
 host_secure_boot_changed=$false
 host_bcd_modified=$false
 guest_bcd_modified=$false
 driver_loaded=$false
 g2_pass=$false
 error=''
}
try{
 $vm=Get-VM -Name $VMName -ErrorAction Stop
 if ([int]$vm.Generation -ne 2) {throw 'Only Gen2 lab VM accepted'}
 $report.vm_state=[string]$vm.State
 $firmware=Get-VMFirmware -VMName $VMName -ErrorAction Stop
 $report.guest_secure_boot_previous=[string]$firmware.SecureBoot
 $report.guest_secure_boot_now=[string]$firmware.SecureBoot
 if($Apply){
   if(-not $ConfirmWindowsInstalled -or -not $ConfirmGuestBitLockerRecoverySafe){
     throw 'Explicit guest installation and BitLocker/recovery acknowledgement required'
   }
   if([string]$vm.State -ne 'Off'){throw 'Guest must be OFF; not changing a running VM'}
   if([string]$firmware.SecureBoot -ne 'On'){throw 'Expected Secure Boot ON before first guest-only transition'}
   $snap='R39-CLEAN-W11-PRE-TESTMODE-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
   $null=Checkpoint-VM -Name $VMName -SnapshotName $snap -ErrorAction Stop
   $report.checkpoint=$snap
   # ONLY the selected VM firmware, NEVER the host.
   Set-VMFirmware -VMName $VMName -EnableSecureBoot Off -ErrorAction Stop
   $after=Get-VMFirmware -VMName $VMName -ErrorAction Stop
   if([string]$after.SecureBoot -ne 'Off'){throw 'Guest Secure Boot state did not change'}
   $report.guest_secure_boot_now='Off'
   $report.status='CHECKPOINT_CREATED_GUEST_SECUREBOOT_OFF_GUEST_BCD_UNCHANGED'
 }
}catch{
 $report.status='BLOCKED'
 $report.error=[string]$_.Exception.Message
}
$json=$report|ConvertTo-Json -Depth 6
if($OutputPath){
 $dest=[IO.Path]::GetFullPath($OutputPath)
 $dir=Split-Path -Parent $dest
 if(-not (Test-Path -LiteralPath $dir)){New-Item -ItemType Directory -Path $dir -Force|Out-Null}
 [IO.File]::WriteAllText($dest,$json+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
}
Write-Output $json
if($report.error){exit 2}
