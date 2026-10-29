# Transactional DNS routing for the internal beta. Run elevated.
# Changes only an exactly identified NRPT rule; never rewrites adapter/DHCP DNS.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Enter','Exit','Guard','Recover')][string]$Action,
    [string]$Token = '', [int]$OwnerProcessId = 0,
    [string]$OwnerStartTicks = '', [string]$Namespace = '.', [string]$ReadyEvent = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$prefix = 'FlowBridge beta DNS '
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Native DNS requires elevation. No DNS settings changed.'
}
if ($Action -ne 'Recover') {
    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParseExact($Token,'D',[ref]$parsed)) { throw 'Invalid DNS session token' }
}
if ($Namespace -ne '.' -and $Namespace -notmatch '^[a-z0-9][a-z0-9.-]{0,252}[a-z0-9]$') { throw 'Invalid namespace' }
function Read-OwnedRule($Rule) {
    try {
        if (-not ([string]$Rule.DisplayName).StartsWith($prefix)) { return $null }
        $r = $Rule.Comment | ConvertFrom-Json
        if ($r.product -ne 'FlowBridge' -or $r.schema -ne 1 -or $Rule.DisplayName -ne ($prefix + $r.token)) { return $null }
        $guid = [Guid]::Empty
        if (-not [Guid]::TryParseExact([string]$r.token,'D',[ref]$guid)) { return $null }
        if (@($Rule.Namespace).Count -ne 1 -or [string]$Rule.Namespace[0] -ne [string]$r.namespace) { return $null }
        if (@($Rule.NameServers).Count -ne 1 -or [string]$Rule.NameServers[0] -ne '127.0.0.1') { return $null }
        if ($r.namespace -ne '.' -and $r.namespace -notmatch '^[a-z0-9][a-z0-9.-]{0,252}[a-z0-9]$') { return $null }
        if ([int]$r.owner_pid -le 0 -or [string]$r.owner_start_ticks -notmatch '^\d+$') { return $null }
        return $r
    } catch { return $null }
}
function Owner-Alive($Record) {
    $p = Get-Process -Id ([int]$Record.owner_pid) -ErrorAction SilentlyContinue
    if ($null -eq $p) { return $false }
    try { return $p.StartTime.ToUniversalTime().Ticks.ToString() -eq [string]$Record.owner_start_ticks }
    catch { return $true }
}
function Remove-Session([string]$Session) {
    $rules = @(Get-DnsClientNrptRule | Where-Object { $_.DisplayName -eq ($prefix + $Session) })
    foreach ($rule in $rules) {
        $r = Read-OwnedRule $rule
        if ($null -eq $r -or $r.token -ne $Session) { throw 'Owned rule was modified; refusing to delete unknown DNS settings' }
        try { Remove-DnsClientNrptRule -Name $rule.Name -Force }
        catch {
            if (@(Get-DnsClientNrptRule | Where-Object { $_.Name -eq $rule.Name }).Count -gt 0) { throw }
        }
    }
    if ($rules.Count -gt 0) { Clear-DnsClientCache }
}
if ($Action -eq 'Guard') {
    if ($ReadyEvent -ne ('Global\FlowBridge.DNSGuard.'+$Token) -or $OwnerStartTicks -notmatch '^\d+$') { throw 'Invalid guard lease' }
    $lease = @{owner_pid=$OwnerProcessId;owner_start_ticks=$OwnerStartTicks}
    $ready = [Threading.EventWaitHandle]::OpenExisting($ReadyEvent)
    try { $null=$ready.Set() } finally { $ready.Dispose() }
    $seen = $false
    for ($iteration=0; ; $iteration++) {
        $rules = @(Get-DnsClientNrptRule | Where-Object { $_.DisplayName -eq ($prefix + $Token) })
        if ($rules.Count -gt 0) { $seen = $true }
        if (-not (Owner-Alive $lease)) { Remove-Session $Token; exit 0 }
        if (($seen -and $rules.Count -eq 0) -or (-not $seen -and $iteration -ge 30)) { exit 0 }
        Start-Sleep -Seconds 1
    }
}
$mutex = New-Object Threading.Mutex($false,'Global\FlowBridgeNativeDnsTransaction')
$held = $false
try {
    try { $held=$mutex.WaitOne(15000) } catch [Threading.AbandonedMutexException] { $held=$true }
    if (-not $held) { throw 'Another DNS transaction is in progress' }
    if ($Action -eq 'Exit') {
        Remove-Session $Token
        @{ok=$true;action='restored';token=$Token} | ConvertTo-Json -Compress
        exit 0
    }
    if ($Action -eq 'Recover') {
        $removed=0
        foreach ($rule in @(Get-DnsClientNrptRule)) {
            $r=Read-OwnedRule $rule
            if ($null -ne $r -and -not (Owner-Alive $r)) { Remove-Session ([string]$r.token); $removed++ }
        }
        @{ok=$true;removed=$removed;adapter_settings_modified=$false} | ConvertTo-Json -Compress
        exit 0
    }
    $owner=Get-Process -Id $OwnerProcessId
    if ($owner.ProcessName -ne 'FlowBridgeCapture' -and $env:FLOWBRIDGE_ISOLATED_DNS_QA -ne '1') { throw 'Invalid DNS owner' }
    if (@(Get-DnsClientNrptRule).Count -gt 0 -or @(Get-DnsClientNrptPolicy -Effective).Count -gt 0) {
        throw 'Existing corporate/third-party NRPT policy detected; it will not be overwritten.'
    }
    $udp=@(Get-NetUDPEndpoint -LocalAddress '127.0.0.1' -LocalPort 53 -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $OwnerProcessId })
    $tcp=@(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 53 -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $OwnerProcessId })
    if ($udp.Count -ne 1 -or $tcp.Count -ne 1) { throw 'Owned UDP/TCP stub is not ready on 127.0.0.1:53' }
    $ticks=$owner.StartTime.ToUniversalTime().Ticks.ToString()
    $record=@{product='FlowBridge';schema=1;token=$Token;namespace=$Namespace;owner_pid=$OwnerProcessId;owner_start_ticks=$ticks}
    $readyName='Global\FlowBridge.DNSGuard.'+$Token
    $ready=New-Object Threading.EventWaitHandle($false,[Threading.EventResetMode]::ManualReset,$readyName)
    $guardian=$null
    try {
        $guardArgs=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'),
            '-Action','Guard','-Token',$Token,'-OwnerProcessId',$OwnerProcessId,'-OwnerStartTicks',$ticks,'-ReadyEvent',$readyName)
        $guardian=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $guardArgs -WindowStyle Hidden -PassThru
        if (-not $ready.WaitOne(10000)) { throw 'Rollback guardian did not acknowledge startup' }
        Add-DnsClientNrptRule -Namespace $Namespace -NameServers '127.0.0.1' -DisplayName ($prefix+$Token) -Comment ($record|ConvertTo-Json -Compress) -PassThru | Out-Null
        Clear-DnsClientCache
        $effective=@(Get-DnsClientNrptPolicy -Effective | Where-Object { @($_.Namespace) -contains $Namespace -and @($_.NameServers) -contains '127.0.0.1' })
        if ($effective.Count -ne 1) { throw 'Windows did not confirm the effective DNS policy' }
        $guardian.Refresh()
        if ($guardian.HasExited -or -not (Owner-Alive $record)) { throw 'DNS owner or guardian exited during activation' }
        @{ok=$true;action='enabled';token=$Token;scope=$Namespace;adapter_settings_modified=$false} | ConvertTo-Json -Compress
    } catch {
        Remove-Session $Token
        if ($null -ne $guardian -and -not $guardian.HasExited) { Stop-Process -Id $guardian.Id -ErrorAction SilentlyContinue }
        throw
    } finally { $ready.Dispose() }
} finally {
    if ($held) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
