# Read-only Win10 x64 exact-beta.2 installer preflight.
# Does not execute installer, modify system settings, open network or grant release GO.
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$InstallerPath)
$ErrorActionPreference = 'Stop'
$expected = '0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4'
$result = [ordered]@{
    schema = 'flowbridge-win10-beta2-internal-installer-preflight-v1'
    source_sha = '86583a1a0487b9d383c0122b24558e620bde5b9c'
    product = 'FlowBridge 0.3.0-beta.2 explicit SOCKS only'
    expected_installer_sha256 = $expected
    installer_sha256_matches = $false
    windows_10_pro_22h2_x64 = $false
    win11_supported = $false
    public_distribution_approved = $false
    release_approved = $false
    internal_pilot_deployment_approved = $false
    os_security_updates_verified = $false
    signing_status = 'NOT_CHECKED'
    status = 'NOT_ACCEPTED'
    error_code = $null
}
try {
    if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
        throw 'INSTALLER_NOT_FOUND'
    }
    $hash = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $result.installer_sha256_matches = ($hash -ceq $expected)
    if (-not $result.installer_sha256_matches) {
        throw 'INSTALLER_SHA256_MISMATCH'
    }
    $registry = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = [string]$registry.CurrentBuildNumber
    $edition = [string]$registry.EditionID
    $version = [string]$registry.DisplayVersion
    $result.windows_10_pro_22h2_x64 = (
        [Environment]::Is64BitOperatingSystem -and
        $build -ceq '19045' -and
        $version -ceq '22H2' -and
        ($edition -ceq 'Professional' -or $edition -ceq 'ProfessionalN')
    )
    # This is an UNSIGNED engineering installer; never disable SmartScreen.
    $sig = Get-AuthenticodeSignature -LiteralPath $InstallerPath
    $result.signing_status = [string]$sig.Status
    if (-not $result.windows_10_pro_22h2_x64) {
        throw 'WRONG_HOST_OS_EDITION_OR_BUILD'
    }
    $result.status = 'EXACT_INSTALLER_AND_WIN10_HOST_PREFLIGHT_PASS_NOT_DEPLOYMENT_GO'
} catch {
    $message = [string]$_.Exception.Message
    $result.error_code = if ($message -in @(
        'INSTALLER_NOT_FOUND', 'INSTALLER_SHA256_MISMATCH',
        'WRONG_HOST_OS_EDITION_OR_BUILD')) { $message } else { 'LOCAL_READ_ONLY_CHECK_FAILED' }
}
# Never print local paths, user names or profile contents.
$result | ConvertTo-Json -Compress -Depth 4
if ($result.status -ceq 'EXACT_INSTALLER_AND_WIN10_HOST_PREFLIGHT_PASS_NOT_DEPLOYMENT_GO') {
    exit 0
}
exit 1
