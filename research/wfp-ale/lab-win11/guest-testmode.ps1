# GUEST ONLY. Enables test-signing in the disposable R39 Windows 11 VM.
# Never executes on the Hyper-V host, Windows Server, physical Windows, or CI.
# Audit is default; -Apply is guarded, changes guest BCD, requires guest reboot.
[CmdletBinding()]
param(
 [switch]$Apply,
 [string]$ExpectedComputerName='',
 [string]$OutputPath=''
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$report=[ordered]@{
 schema='flowbridge-r39-win11-testmode-guest-v1'
 status='NOT_ADMITTED'
 machine=$env:COMPUTERNAME
 os=''
 computer_model=''
 guest_virtual_machine_confirmed=$false
 admin_confirmed=$false
 secure_boot_state='UNKNOWN'
 bitlocker_state='UNKNOWN'
 bcd_test_mode_requested=$false
 guest_reboot_performed=$false
 host_modified=$false
 driver_installed=$false
 g2_pass=$false
 error=''
}
try{
 if(-not $IsWindows){throw 'Windows required'}
 $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
 $machine=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
 $report.os=[string]$os.Caption
 $report.computer_model=[string]$machine.Model
 $report.guest_virtual_machine_confirmed=(
   [int]$os.ProductType -eq 1 -and [string]$os.Caption -match 'Windows 11' -and
   [string]$machine.Manufacturer -match 'Microsoft' -and
   [string]$machine.Model -match 'Virtual Machine'
 )
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $report.admin_confirmed=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole(
   [Security.Principal.WindowsBuiltInRole]::Administrator)
 try {
   $secure=Confirm-SecureBootUEFI -ErrorAction Stop
   $report.secure_boot_state= $(if($secure){'ON'}else{'OFF'})
 } catch {
   $report.secure_boot_state='UNAVAILABLE'
 }
 try {
   $bitlocker=Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
   $report.bitlocker_state=[string]$bitlocker.ProtectionStatus
 } catch {
   $report.bitlocker_state='UNKNOWN'
 }
 if(-not $Apply){
   $report.status='AUDIT_ONLY_NO_CHANGE'
 } else {
   if(-not $report.guest_virtual_machine_confirmed){throw 'Only installed Windows 11 on Microsoft Hyper-V guest is allowed'}
   if(-not $report.admin_confirmed){throw 'Guest Administrator required'}
   if(-not $ExpectedComputerName -or $ExpectedComputerName -ne $env:COMPUTERNAME){
     throw 'Exact lab guest computer name confirmation required'
   }
   if($env:COMPUTERNAME -notmatch '^FB-R39-'){
     throw 'Rename dedicated lab guest to FB-R39-* before BCD changes'
   }
   if($report.secure_boot_state -ne 'OFF'){
     throw 'Guest Secure Boot must be OFF after host-side snapshot; never change host firmware'
   }
   if($report.bitlocker_state -ne 'Off'){
     throw 'BitLocker must be safely suspended/decrypted in guest before test mode; abort'
   }
   & bcdedit.exe /set '{current}' TESTSIGNING ON | Out-Null
   if($LASTEXITCODE -ne 0){throw 'BCDEdit rejected guest test-signing change'}
   $report.bcd_test_mode_requested=$true
   $report.status='GUEST_REBOOT_REQUIRED_TEST_MODE_NOT_YET_PROVEN'
 }
}catch{
 $report.status='BLOCKED'
 $report.error=[string]$_.Exception.Message
}
$json=$report|ConvertTo-Json -Depth 6
if($OutputPath){
 $dest=[IO.Path]::GetFullPath($OutputPath)
 $dir=Split-Path -Parent $dest
 if(-not(Test-Path -LiteralPath $dir)){New-Item -ItemType Directory -Path $dir -Force|Out-Null}
 [IO.File]::WriteAllText($dest,$json+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
}
Write-Output $json
if($report.error){exit 2}
