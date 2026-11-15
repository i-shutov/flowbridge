#requires -Version 5.1
# Native hosted Windows with no driver changes. No G2 PacketBound claims.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Probe,
    [Parameter(Mandatory=$true)][string]$OutputRoot
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[void](New-Item -ItemType Directory -Path $OutputRoot -Force)
$token=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path -LiteralPath $Probe).Path,[ref]$token,[ref]$errors)
if($errors.Count -ne 0){throw 'PS51_PROVENANCE_SYNTAX_FAILED'}
$functionNode = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Resolve-DriverPath'
},$true)
if($null -eq $functionNode){throw 'PURE_PATH_VALIDATOR_MISSING'}
# Extract ONLY the file's pure resolver definition, not the probe body.
. ([ScriptBlock]::Create($functionNode.Extent.Text))
function ExpectReject([string]$path) {
    $rejected=$false
    try { [void](Resolve-DriverPath $path) } catch { $rejected=$true }
    if(-not $rejected){throw ('UNSAFE_DRIVER_IMAGE_PATH_ACCEPTED: '+$path)}
}
ExpectReject '..\evil.sys'
ExpectReject '\\attacker\share\ndisrd.sys'
ExpectReject 'C:\Windows\System32\drivers\..\fake.sys'
ExpectReject 'C:\Windows\System32\drivers\evil.exe'
ExpectReject '\Device\HarddiskVolume1\Windows\System32\drivers\ndisrd.sys'
ExpectReject ''
$canonical=Resolve-DriverPath '\SystemRoot\System32\drivers\tcpip.sys'
if(-not $canonical.StartsWith($env:SystemRoot,[StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFileName($canonical) -ine 'tcpip.sys'){throw 'SYSTEMROOT_EXPANSION_FAILED'}
Write-Host 'PASS six hostile service paths refused and native systemroot expanded'
$default=Join-Path $OutputRoot 'ndisrd-original-readonly.json'
$positive=Join-Path $OutputRoot 'windows-system-driver-positive.json'
$mismatch=Join-Path $OutputRoot 'wrong-host-negative.json'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Probe -OutputPath $default |
    Out-Null
if($LASTEXITCODE -ne 0){throw 'DEFAULT_NDISRD_PROBE_MUST_REPORT_NOT_ASSERT_GO'}
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Probe -OutputPath $positive -HostedSystemDriverControl |
    Out-Null
if($LASTEXITCODE -ne 0){throw 'TCPIP_SYSTEM_DRIVER_CONTROL_FAILED'}
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Probe -OutputPath $mismatch -ExpectedComputerName 'WRONG-HOST-REJECT-CI' |
    Out-Null
if($LASTEXITCODE -ne 2){throw 'HOSTNAME_SCOPE_GUARD_BROKEN'}
$a=Get-Content -LiteralPath $default -Raw | ConvertFrom-Json
$b=Get-Content -LiteralPath $positive -Raw | ConvertFrom-Json
$c=Get-Content -LiteralPath $mismatch -Raw | ConvertFrom-Json
$pinOk=Join-Path $OutputRoot 'explicit-reference-match.json'
$pinBad=Join-Path $OutputRoot 'explicit-reference-mismatch.json'
$pinMalformed=Join-Path $OutputRoot 'explicit-reference-invalid.json'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Probe -OutputPath $pinOk -HostedSystemDriverControl -ExpectedVendorSha256 $b.driver_file_sha256 | Out-Null
if($LASTEXITCODE -ne 0){throw 'REFERENCE_PIN_VALID_PRECHECK_FAILED'}
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Probe -OutputPath $pinBad -HostedSystemDriverControl -ExpectedVendorSha256 ('0'*64) | Out-Null
if($LASTEXITCODE -ne 2){throw 'WRONG_VENDOR_REFERENCE_NOT_REFUSED'}
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Probe -OutputPath $pinMalformed -HostedSystemDriverControl -ExpectedVendorSha256 'invalid-pin' | Out-Null
if($LASTEXITCODE -ne 2){throw 'MALFORMED_VENDOR_REFERENCE_NOT_REFUSED'}
$d=Get-Content $pinOk -Raw | ConvertFrom-Json
$e=Get-Content $pinBad -Raw | ConvertFrom-Json
$g=Get-Content $pinMalformed -Raw | ConvertFrom-Json
if($d.supplied_vendor_reference_sha256_matches -ne $true -or $d.supplied_vendor_reference_authority_verified -ne $false -or
   $e.supplied_vendor_reference_sha256_matches -ne $false -or $e.error_code -ne 'VENDOR_PIN_MISMATCH' -or
   $g.error_code -ne 'INVALID_VENDOR_PIN_FORMAT'){throw 'EXPLICIT_REFERENCE_HASH_GATE_UNSOUND'}
Write-Host 'PASS explicit hash reference matched, mismatched and malformed refs denied without vendor trust assertion'
if($a.target -ne 'NDISRD' -or $a.target_is_product_ndisrd -ne $true){throw 'TARGET_NDISRD_CHANGED'}
if($b.target -ne 'Tcpip' -or $b.target_is_product_ndisrd -ne $false -or
   $b.service_registration -ne 'REGISTERED' -or $b.service_type -ne 'KERNEL_DRIVER' -or
   $b.image_path_status -ne 'EXISTS_HASHED' -or
   $b.driver_file_sha256 -notmatch '^[0-9a-f]{64}$' -or $b.authenticode_status -ne 'Valid'){throw 'REAL_WINDOWS_SYSTEM_DRIVER_PATH_HASH_NOT_PROVED'}
if($c.status -ne 'BLOCKED' -or $c.error_code -ne 'UNEXPECTED_HOST' -or
    $c.expected_host_matches -ne $false){throw 'HOSTNAME_MISMATCH_NOT_BLOCKED'}
foreach($item in @($a,$b,$c,$d,$e,$g)){
    foreach($key in @('driver_device_opened','filter_or_adapter_mode_modified',
        'service_installed_or_started_by_probe','network_or_security_settings_modified',
        'owner_process_per_packet_proven','kernel_connection_id_available',
        'selected_application_protected','native_g2_accepted','release_1_0_accepted',
        'microsoft_kernel_code_integrity_policy_verified','file_hash_independently_vendor_pinned',
        'on_disk_file_proves_currently_loaded_image')) {
        if($item.$key -ne $false){throw ('UNSUPPORTED_SECURITY_GO: '+$key)}
    }
}
Write-Host 'PASS real Windows TCPIP driver image hashed and Authenticode observed; NDISRD still native NO_GO'
