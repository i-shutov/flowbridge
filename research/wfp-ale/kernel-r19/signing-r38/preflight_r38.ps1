# R38 read-only cryptographic target preflight. No install/start or filter action.
# Requires an exact Microsoft-signed catalog/driver returned by Partner Center.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$SignedDriver,
  [Parameter(Mandatory=$true)][string]$UnsignedDriver,
  [Parameter(Mandatory=$true)][string]$SignedCatalog,
  [Parameter(Mandatory=$true)][string]$Broker,
  [Parameter(Mandatory=$true)][string]$ExpectedSignedSha256,
  [Parameter(Mandatory=$true)][string]$ExpectedUnsignedSha256,
  [Parameter(Mandatory=$true)][string]$ExpectedBrokerSha256,
  [Parameter(Mandatory=$true)][string]$ResultJson
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$state = [ordered]@{
  ok = $false
  status = 'NOT_ADMITTED'
  target_os = ''
  target_machine = $env:COMPUTERNAME
  signed_driver_sha256 = ''
  unsigned_driver_sha256 = ''
  broker_sha256 = ''
  signature_kernel_policy_verified = $false
  executable_sections_match_unsigned_source = $false
  platform_protection_observation_complete = $false
  vnc_independently_verified = $false
  system_rescue_independently_verified = $false
  rollback_independently_verified = $false
  physical_egress_observer_verified = $false
  driver_installed = $false
  driver_loaded = $false
  wfp_filters_changed = $false
  host_admitted_for_R39 = $false
  g2_pass = $false
  release_accepted = $false
  error_code = 'prerequisites_unchecked'
}
function Sha([string]$path) {
  return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
try {
  foreach ($p in @($SignedDriver,$UnsignedDriver,$SignedCatalog,$Broker)) {
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
      throw 'missing_package_member'
    }
  }
  foreach ($v in @($ExpectedSignedSha256,$ExpectedUnsignedSha256,$ExpectedBrokerSha256)) {
    if ($v -notmatch '^[a-fA-F0-9]{64}$') { throw 'invalid_expected_sha256' }
  }
  $signedSha=Sha $SignedDriver
  $unsignedSha=Sha $UnsignedDriver
  $brokerSha=Sha $Broker
  $state.signed_driver_sha256=$signedSha
  $state.unsigned_driver_sha256=$unsignedSha
  $state.broker_sha256=$brokerSha
  if ($signedSha -ne $ExpectedSignedSha256.ToLowerInvariant() -or
      $unsignedSha -ne $ExpectedUnsignedSha256.ToLowerInvariant() -or
      $brokerSha -ne $ExpectedBrokerSha256.ToLowerInvariant()) {
    throw 'artifact_sha256_mismatch'
  }
  $signtool=Get-Command signtool.exe -ErrorAction Stop
  # Kernel-policy verification of the exact .SYS with its catalog, not merely
  # an embedded Authenticode /pa check. Never sign or trust a test certificate.
  $signedLog = & $signtool.Source verify /kp /v /c $SignedCatalog $SignedDriver 2>&1
  if ($LASTEXITCODE -ne 0) { throw 'kernel_signature_policy_failed' }
  $state.signature_kernel_policy_verified=$true

  $py=Get-Command python.exe -ErrorAction SilentlyContinue
  if (-not $py) {throw 'python3_unavailable_for_section_comparison'}
  & $py.Source (Join-Path $PSScriptRoot 'compare_pe_sections_r38.py') $UnsignedDriver $SignedDriver | Out-Null
  if ($LASTEXITCODE -ne 0) {throw 'loadable_pe_sections_not_identical'}
  $state.executable_sections_match_unsigned_source=$true

  $svc=Get-CimInstance Win32_SystemDriver -Filter "Name='FlowBridgeG2WitnessR38'" -ErrorAction Stop
  if ($null -ne $svc) {throw 'research_driver_already_installed'}
  $info=Get-CimInstance Win32_OperatingSystem
  $state.target_os=$info.Caption
  if ($info.ProductType -ne 1) {throw 'windows_desktop_target_required'}
  $boot=Confirm-SecureBootUEFI -ErrorAction Stop
  $deviceGuard=Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
  if ($null -eq $deviceGuard) {throw 'deviceguard_state_unknown'}
  # These observations are not a request to change SecureBoot, HVCI or
  # driver policy. Changing protections invalidates any external admission.
  $state.platform_protection_observation_complete=$true
  $state.secure_boot_enabled=[bool]$boot
  $state.device_guard_running= @($deviceGuard.SecurityServicesRunning)
  $state.error_code='cryptographic_and_host_readonly_checks_complete_external_rescue_pending'
  $state.status='CRYPTO_VERIFIED_HOST_NOT_ADMITTED'
}
catch {
  if ($state.error_code -eq 'prerequisites_unchecked') {
    $state.error_code = [string]$_.Exception.Message
  }
  $state.status='NOT_ADMITTED'
}
finally {
  $output=[IO.Path]::GetFullPath($ResultJson)
  $parent=Split-Path -Parent $output
  if (-not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
  }
  $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $output -Encoding utf8
  Write-Output ($state | ConvertTo-Json -Compress -Depth 5)
}
# This read-only tool CANNOT admit a target: recent independent VNC,
# SYSTEM rescue, rollback and physical capture must each be witnessed.
# Never treat a green signature as permission to load a driver.
exit 2
