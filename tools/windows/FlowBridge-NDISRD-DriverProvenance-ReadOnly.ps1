#requires -Version 5.1
<#
.SYNOPSIS
  Exact read-only SCM/driver-file provenance preflight for the owner-approved NDISRD backend.
.DESCRIPTION
  Default: inspect local NDISRD service registration, binary hash and
  Authenticode/cached catalog signature without opening the NDISRD device.
  NEVER installs/starts/stops/configures services, loads a driver, changes
  adapters/WFP/BFE/security policy, or authorizes packet ownership.
  -HostedSystemDriverControl uses the Windows TCPIP driver only on a
  disposable GitHub-hosted runner for positive fixture coverage.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$OutputPath,
    [string]$ExpectedComputerName = '',
    [string]$ExpectedVendorSha256 = '',
    [switch]$HostedSystemDriverControl
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ServiceName = if ($HostedSystemDriverControl) { 'Tcpip' } else { 'NDISRD' }
$IsHosted = ($env:GITHUB_ACTIONS -eq 'true' -and
             $env:RUNNER_ENVIRONMENT -eq 'github-hosted' -and
             $env:RUNNER_OS -eq 'Windows')
$Report = [ordered]@{
    schema = 'flowbridge-ndisrd-driver-provenance-readonly-v1'
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    target = $ServiceName
    target_is_product_ndisrd = (-not $HostedSystemDriverControl)
    host_name = [Environment]::MachineName
    expected_host_matches = $null
    os_caption = ''
    os_build = ''
    service_registration = 'UNKNOWN'
    service_type = 'UNKNOWN'
    service_state = 'UNKNOWN'
    image_path_status = 'NOT_CHECKED'
    image_basename = $null
    driver_file_sha256 = $null
    driver_file_size_bytes = $null
    supplied_vendor_reference_sha256_matches = $null
    supplied_vendor_reference_authority_verified = $false
    authenticode_status = 'NOT_CHECKED'
    signer_subject = $null
    file_hash_independently_vendor_pinned = $false
    microsoft_kernel_code_integrity_policy_verified = $false
    on_disk_file_proves_currently_loaded_image = $false
    driver_device_opened = $false
    filter_or_adapter_mode_modified = $false
    service_installed_or_started_by_probe = $false
    network_or_security_settings_modified = $false
    owner_process_per_packet_proven = $false
    kernel_connection_id_available = $false
    selected_application_protected = $false
    native_g2_accepted = $false
    release_1_0_accepted = $false
    status = 'BLOCKED'
    error_code = $null
}
function Resolve-DriverPath([string]$Raw) {
    if ([string]::IsNullOrWhiteSpace($Raw) -or $Raw.Length -gt 2048 -or
        $Raw.Contains([char]0) -or $Raw.Contains([char]10) -or $Raw.Contains([char]13)) {
        throw 'SERVICE_IMAGE_PATH_INVALID'
    }
    $path = $Raw.Trim().Trim('"')
    if ($path.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {
        $path = Join-Path $env:SystemRoot $path.Substring('\SystemRoot\'.Length)
    } elseif ($path.StartsWith('System32\', [StringComparison]::OrdinalIgnoreCase)) {
        $path = Join-Path $env:SystemRoot $path
    } elseif ($path.StartsWith('%SystemRoot%\', [StringComparison]::OrdinalIgnoreCase)) {
        $path = Join-Path $env:SystemRoot $path.Substring('%SystemRoot%\'.Length)
    } else {
        $path = [Environment]::ExpandEnvironmentVariables($path)
    }
    # SCM configuration does not authenticate the binary. Refuse UNC,
    # device paths, relative paths, traversal and non-SYS executables.
    if ($path -notmatch '^[a-zA-Z]:\\' -or $path -match '(^|\\)\.\.(\\|$)' -or
        $path -notmatch '(?i)\.sys$') {
        throw 'SERVICE_IMAGE_PATH_NOT_CANONICAL'
    }
    return [IO.Path]::GetFullPath($path)
}
try {
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitOperatingSystem) {
        throw 'WINDOWS_X64_REQUIRED'
    }
    if ($HostedSystemDriverControl -and -not $IsHosted) {
        throw 'HOSTED_POSITIVE_CONTROL_NOT_AUTHORIZED'
    }
    if ($ExpectedVendorSha256 -and $ExpectedVendorSha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'INVALID_VENDOR_PIN_FORMAT'
    }
    if ($ExpectedComputerName) {
        $matchHost = $ExpectedComputerName.Equals([Environment]::MachineName,
                                                 [StringComparison]::OrdinalIgnoreCase)
        $Report.expected_host_matches = $matchHost
        if (-not $matchHost) { throw 'UNEXPECTED_HOST' }
    }
    $nt = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $Report.os_caption = [string]$nt.ProductName
    $Report.os_build = [string]$nt.CurrentBuildNumber
    $serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $ServiceName
    if (-not (Test-Path -LiteralPath $serviceKey -PathType Container)) {
        $Report.service_registration = 'NOT_INSTALLED'
        $Report.status = 'NO_LOCAL_DRIVER_READONLY'
    } else {
        $reg = Get-ItemProperty -LiteralPath $serviceKey -ErrorAction Stop
        $Report.service_registration = 'REGISTERED'
        $driverType = [int]$reg.Type
        $Report.service_type = if (($driverType -band 1) -ne 0) { 'KERNEL_DRIVER' } else { 'NOT_KERNEL_DRIVER' }
        try {
            $svc = Get-Service -Name $ServiceName -ErrorAction Stop
            $Report.service_state = [string]$svc.Status
        } catch { $Report.service_state = 'UNKNOWN' }
        if ($Report.service_type -ne 'KERNEL_DRIVER') {
            $Report.status = 'NOT_KERNEL_DRIVER'
        } elseif ($null -eq $reg.ImagePath) {
            $Report.image_path_status = 'MISSING'
            $Report.status = 'MISSING_DRIVER_IMAGE_PATH'
        } else {
            try {
                $image = Resolve-DriverPath ([string]$reg.ImagePath)
                $Report.image_basename = [IO.Path]::GetFileName($image)
                if (-not (Test-Path -LiteralPath $image -PathType Leaf)) {
                    $Report.image_path_status = 'FILE_NOT_FOUND'
                    $Report.status = 'DRIVER_FILE_MISSING'
                } else {
                    $file = Get-Item -LiteralPath $image -ErrorAction Stop
                    if ([bool]($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                        throw 'DRIVER_IMAGE_REPARSE_POINT'
                    }
                    if ($file.Length -lt 4096 -or $file.Length -gt 67108864) {
                        throw 'DRIVER_FILE_SIZE_OUT_OF_BOUNDS'
                    }
                    $Report.driver_file_size_bytes = [long]$file.Length
                    $Report.driver_file_sha256 = (Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant()
                    $Report.image_path_status = 'EXISTS_HASHED'
                    if ($ExpectedVendorSha256) {
                        $matchesPin = $Report.driver_file_sha256.Equals($ExpectedVendorSha256,
                            [StringComparison]::OrdinalIgnoreCase)
                        $Report.supplied_vendor_reference_sha256_matches = $matchesPin
                        if (-not $matchesPin) { throw 'VENDOR_PIN_MISMATCH' }
                    }
                    try {
                        $sig = Get-AuthenticodeSignature -LiteralPath $image -ErrorAction Stop
                        $Report.authenticode_status = [string]$sig.Status
                        if ($null -ne $sig.SignerCertificate) {
                            $Report.signer_subject = [string]$sig.SignerCertificate.Subject
                        }
                    } catch { $Report.authenticode_status = 'UNAVAILABLE' }
                    $Report.status = 'FILE_PROVENANCE_OBSERVED_NOT_NATIVE_G2'
                }
            } catch {
                $Report.image_path_status = 'PATH_REFUSED'
                $Report.status = 'DRIVER_IMAGE_UNVERIFIED'
                $Report.error_code = if ([string]$_.Exception.Message -match '^[A-Z][A-Z_]+$') {
                    [string]$_.Exception.Message
                } else { 'IMAGE_INSPECTION_FAILED' }
            }
        }
    }
} catch {
    $Report.status = 'BLOCKED'
    $Report.error_code = if ([string]$_.Exception.Message -match '^[A-Z][A-Z_]+$') {
        [string]$_.Exception.Message
    } else { 'READONLY_OBSERVATION_FAILED' }
} finally {
    # Only a caller-selected JSON is written; never modify the system.
    $json = $Report | ConvertTo-Json -Depth 8
    $full = [IO.Path]::GetFullPath($OutputPath)
    $parent = Split-Path -Parent $full
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [void](New-Item -Path $parent -ItemType Directory -Force)
    }
    [IO.File]::WriteAllText($full,
        $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    Write-Output $json
}
if ($Report.status -eq 'BLOCKED' -or $Report.error_code -eq 'VENDOR_PIN_MISMATCH') { exit 2 }
