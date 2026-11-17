# Read-only Windows 10 Pro ESU/servicing inventory for internal FlowBridge QA.
# No activation, license key display, installs, updates, policy or registry edits.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$result = [ordered]@{
    schema = 'flowbridge-win10-2026-security-servicing-readonly-v1'
    os_supported_for_current_flowbridge_scope = $false
    os_build_19045_22h2_pro_x64 = $false
    ubr = $null
    october_2026_esu_build_floor_7811_met = $false
    esu_year2_license_status = 'UNKNOWN'
    esu_year2_license_activation_id_checked = $true
    esu_year2_license_activated = $false
    prerequisite_kb5066791_detected = $false
    preparation_kb5072653_detected = $false
    patches_current_as_of_today_proven = $false
    full_esu_entitlement_and_securing_proven = $false
    a6_internal_security_go = $false
    a7_internal_deployment_go = $false
    status = 'NOT_VERIFIED'
    error_code = $null
}
try {
    $registry = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = [string]$registry.CurrentBuildNumber
    $edition = [string]$registry.EditionID
    $display = [string]$registry.DisplayVersion
    $result.os_build_19045_22h2_pro_x64 = (
        [Environment]::Is64BitOperatingSystem -and
        $build -ceq '19045' -and
        $display -ceq '22H2' -and
        ($edition -ceq 'Professional' -or $edition -ceq 'ProfessionalN')
    )
    $result.os_supported_for_current_flowbridge_scope = $result.os_build_19045_22h2_pro_x64
    if (-not $result.os_build_19045_22h2_pro_x64) {
        throw 'WRONG_OS_NOT_WIN10_PRO_22H2_X64'
    }
    $result.ubr = [int]$registry.UBR
    # Microsoft release-health table published 19045.7811 (2026-10-26)
    # as an October 2026 ESU build. This is a historical FLOOR only:
    # it is NOT proof of current monthly patch status.
    $result.october_2026_esu_build_floor_7811_met = ($result.ubr -ge 7811)
    $kbs = @()
    try { $kbs = @(Get-HotFix -ErrorAction Stop | ForEach-Object { $_.HotFixID }) }
    catch { $kbs = @() }
    $result.prerequisite_kb5066791_detected = ($kbs -contains 'KB5066791')
    $result.preparation_kb5072653_detected = ($kbs -contains 'KB5072653')
    # ESU year 2 activation ID is public Microsoft documentation; never
    # read or emit MAK/product key, installation ID or user identity.
    $activationId = '1043add5-23b1-4afb-9a0f-64343c8f3f8d'
    try {
        $products = @(Get-CimInstance -ClassName SoftwareLicensingProduct -Filter ("ID='" + $activationId + "'") -ErrorAction Stop)
        if ($products.Count -eq 1 -and [int]$products[0].LicenseStatus -eq 1) {
            $result.esu_year2_license_status = 'LICENSED'
            $result.esu_year2_license_activated = $true
        } elseif ($products.Count -gt 0) {
            $result.esu_year2_license_status = 'NOT_LICENSED'
        } else {
            $result.esu_year2_license_status = 'NOT_FOUND'
        }
    } catch {
        $result.esu_year2_license_status = 'UNKNOWN_NO_WMI_ACCESS'
    }
    if ($result.esu_year2_license_activated -and
        $result.october_2026_esu_build_floor_7811_met) {
        $result.status = 'ESU_YEAR2_AND_2026_OCT_FLOOR_OBSERVED_SECURITY_GO_STILL_OPEN'
    } else {
        $result.status = 'ESU_SECURITY_SERVICING_NOT_SUFFICIENTLY_VERIFIED'
    }
} catch {
    $code = [string]$_.Exception.Message
    $result.error_code = if ($code -eq 'WRONG_OS_NOT_WIN10_PRO_22H2_X64') {
        $code
    } else { 'READ_ONLY_OS_INVENTORY_FAILED' }
}
# Preserve only OS servicing facts: no usernames/hostnames/product keys.
$result | ConvertTo-Json -Compress -Depth 4
if ($result.status -ceq 'ESU_YEAR2_AND_2026_OCT_FLOOR_OBSERVED_SECURITY_GO_STILL_OPEN') { exit 0 }
exit 1
