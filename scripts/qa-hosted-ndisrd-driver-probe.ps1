# One-shot, disposable GitHub-hosted Windows probe. Never use a self-hosted runner.
# No capture, forwarding, WFP mutation, reboot, defender/firewall change, or service configuration.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = Join-Path $env:GITHUB_WORKSPACE 'build/verification/github-hosted-ndisrd'
$null = New-Item -ItemType Directory -Force -Path $root
$msi = Join-Path $env:RUNNER_TEMP 'Windows.Packet.Filter.3.6.2.1.x64.msi'
$extract = Join-Path $env:RUNNER_TEMP 'flowbridge-ndisrd-admin-extraction'
$agent = Join-Path $env:GITHUB_WORKSPACE 'target/release/flowbridge-agent.exe'
$reportPath = Join-Path $root 'probe.json'
$report = [ordered]@{
    schema_version = 1
    kind = 'github_hosted_windows_2025_signed_ndisrd_driver_readonly_compatibility'
    source_commit = $env:GITHUB_SHA
    runner_environment = $env:RUNNER_ENVIRONMENT
    tested_on_disposable_github_hosted = $false
    vendor_release = 'wiresock/ndisapi v3.6.2'
    vendor_msi_sha256 = $null
    preflight_msi_signature = $null
    preflight_catalog_status = 'not_checked'
    install_attempted = $false
    install_exit_code = $null
    baseline = $null
    installed = $null
    loopback_tcp_healthy = $false
    driver_device_opened = $false
    driver_api_compatible = $false
    read_only_adapter_inventory = $false
    driver_runtime_proved = $false
    native_packet_interception_tested = $false
    flowbridge_g1_accepted = $false
    rollback_attempted = $false
    rollback_exit_code = $null
    phase = 'preflight'
    error = $null
}
function Save-Report {
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportPath -Encoding utf8
    Write-Host ('PROBE_PHASE=' + $report.phase)
    Write-Host ('DRIVER_RUNTIME_PROVED=' + $report.driver_runtime_proved)
    Write-Host ('REPORT=' + $reportPath)
}
function Invoke-Msi([string] $verb, [string] $path, [string] $extra) {
    $log = Join-Path $env:RUNNER_TEMP ("flowbridge-msi-$verb.log")
    $args = "/$verb " + ('"' + $path + '"') + ' /qn /norestart /l*v "' + $log + '"'
    if ($extra) { $args += ' ' + $extra }
    $process = Start-Process -FilePath "$env:WINDIR\System32\msiexec.exe" -ArgumentList $args -PassThru -Wait
    return [int] $process.ExitCode
}
function Get-DriverStatus {
    $output = & $agent status 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'flowbridge_agent_status_nonzero' }
    $s = ($output -join [Environment]::NewLine) | ConvertFrom-Json -AsHashtable
    if (-not $s.ContainsKey('driver')) { throw 'missing_original_rust_driver_report' }
    $d = $s.driver
    return [ordered]@{
        service_registered = $d.service.service_registered
        service_state = $d.service.service_state
        kernel_driver_type = $d.service.kernel_driver_type
        device_opened = $d.device_opened
        api_compatible = $d.api_compatible
        driver_api_version = $d.driver_api_version
        adapter_inventory_status = $d.adapter_inventory_status
        adapter_count = $d.adapter_count
        error_class = $d.error
        win32_error = $d.win32_error
    }
}
function Test-LocalTcp {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $client.Connect('127.0.0.1', $port)
            $accepted = $listener.AcceptTcpClient()
            try { return $client.Connected -and $accepted.Connected }
            finally { $accepted.Dispose() }
        } finally { $client.Dispose() }
    } finally { $listener.Stop() }
}
$installStarted = $false
try {
    if ($env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows') {
        throw 'refuse_non_github_hosted_windows_runner'
    }
    $report.tested_on_disposable_github_hosted = $true

    $report.phase = 'build_original_rust_agent'
    & cargo build --locked --release -p flowbridge-capture --bin flowbridge-agent
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $agent -PathType Leaf)) {
        throw 'rust_agent_build_failed'
    }
    $report.phase = 'baseline_readonly'
    $report.baseline = Get-DriverStatus
    if ($report.baseline.service_registered -eq $true) {
        throw 'driver_already_present_refuse_to_replace'
    }

    $report.phase = 'download_official_msi'
    $uri = 'https://github.com/wiresock/ndisapi/releases/download/v3.6.2/Windows.Packet.Filter.3.6.2.1.x64.msi'
    Invoke-WebRequest -Uri $uri -OutFile $msi -MaximumRedirection 5
    if ((Get-Item -LiteralPath $msi).Length -lt 10000) { throw 'download_too_small' }
    $report.vendor_msi_sha256 = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant()
    $msiSig = Get-AuthenticodeSignature -LiteralPath $msi
    $report.preflight_msi_signature = [string] $msiSig.Status

    # Administrative extraction runs no installed network filter; validate the
    # signed driver catalog before attempting to modify the disposable VM.
    $report.phase = 'verify_vendor_driver_catalog'
    $null = New-Item -ItemType Directory -Force -Path $extract
    $extractExit = Invoke-Msi -verb 'a' -path $msi -extra ('TARGETDIR="' + $extract + '"')
    if ($extractExit -ne 0) {
        throw ('msi_administrative_extraction_exit_' + $extractExit)
    }
    $cats = @(Get-ChildItem -LiteralPath $extract -Filter '*.cat' -Recurse -File -ErrorAction Stop)
    $drivers = @(Get-ChildItem -LiteralPath $extract -Filter 'ndisrd.sys' -Recurse -File -ErrorAction Stop)
    if ($cats.Count -lt 1 -or $drivers.Count -lt 1) { throw 'driver_catalog_or_sys_missing' }
    $microsoftCats = @($cats | Where-Object {
        $sign = Get-AuthenticodeSignature -LiteralPath $_.FullName
        ($sign.Status -eq 'Valid') -and ($sign.SignerCertificate.Subject -match 'Microsoft')
    })
    if ($microsoftCats.Count -eq 0) { throw 'no_valid_microsoft_signed_driver_catalog' }
    $report.preflight_catalog_status = 'valid_microsoft_signed_catalog'

    $report.phase = 'install_vendor_signed_driver'
    $report.install_attempted = $true
    $installStarted = $true
    $report.install_exit_code = Invoke-Msi -verb 'i' -path $msi -extra ''
    if ($report.install_exit_code -ne 0) {
        if ($report.install_exit_code -eq 3010) { throw 'installation_requires_reboot_not_supported_on_hosted' }
        throw ('driver_msi_install_exit_' + $report.install_exit_code)
    }

    $report.phase = 'original_rust_readonly_driver_api'
    $report.installed = Get-DriverStatus
    $report.driver_device_opened = ($report.installed.device_opened -eq $true)
    $report.driver_api_compatible = ($report.installed.api_compatible -eq $true)
    $report.read_only_adapter_inventory = ($report.installed.adapter_inventory_status -eq 'read_only_ok')
    $report.loopback_tcp_healthy = [bool] (Test-LocalTcp)
    $report.driver_runtime_proved = (
        $report.installed.service_registered -eq $true -and
        $report.installed.service_state -eq 'running' -and
        $report.installed.kernel_driver_type -eq $true -and
        $report.driver_device_opened -and $report.driver_api_compatible -and
        $report.read_only_adapter_inventory -and $report.loopback_tcp_healthy
    )
    if (-not $report.driver_runtime_proved) { throw 'original_rust_ndisrd_readonly_runtime_not_proved' }
    $report.phase = 'driver_runtime_proved_cleanup_pending'
} catch {
    $report.error = [string] $_.Exception.Message
    $report.phase = 'failed_' + $report.phase
} finally {
    # This is an ephemeral VM. Attempt reversible MSI removal even after failure.
    if ($installStarted) {
        try {
            $report.rollback_attempted = $true
            $report.rollback_exit_code = Invoke-Msi -verb 'x' -path $msi -extra ''
        } catch {
            $report.rollback_exit_code = -1
        }
    }
    Save-Report
}
if (-not $report.driver_runtime_proved -or ($report.rollback_attempted -and $report.rollback_exit_code -notin @(0,3010,1605))) { exit 1 }
