#requires -Version 5.1
<#
R139, read-only evidence of the already committed WFP receipt and policy contract.
No driver/filter/WFP calls, no sockets, no process or security-setting changes.
Downloads 4 pinned exact source blobs from the same research repo; optional SDK header read.
Result exit 3 means CONTRACT NO-GO, never protection PASS. 2 means failure/unknown.
#>
[CmdletBinding()]
param([switch]$SkipSdkHeader)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$pin = [ordered]@{
    'broker_windows.rs' = '16ec8853d322b40f0e00e14d49ae3410741b9395'
    'kernel_lib.rs' = '0af6d4539673d2894cbaa91af0ea8f3524862a26'
    'redirect.rs' = '9a07e026134d46ef646d39862bd982cc48bbc5f6'
    'policy_windows.rs' = 'acf60334320d970f58af3349ee75fbaa59826602'
}
$work = Join-Path ([IO.Path]::GetTempPath()) ('FlowBridge-R139-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work
$report = [ordered]@{
    schema = 1; stage = 'R139 read-only pinned source contract'; status = 'NOT_RUN'; reason = $null
    started_utc = [DateTime]::UtcNow.ToString('o'); finished_utc = $null; evidence = $work
    sources = @(); checks = [ordered]@{}; windows_sdk = [ordered]@{status='NOT_CHECKED'; path=$null; symbols=@{}}
    source_receipt_pipeline_pass = $false; action_rights_blocker = $false
    dynamic_policy_lifetime_gap = $false; no_kernel_proof = $true; no_direct_proof = $true
    bfe_queried = $false; driver_executed = $false; socket_created = $false; policy_mutated = $false
    exit_code = 2
}
function Hash-Data([byte[]]$Data, [string]$Algorithm) {
    $h = [Security.Cryptography.HashAlgorithm]::Create($Algorithm)
    try { return -join ($h.ComputeHash($Data) | ForEach-Object { $_.ToString('x2') }) }
    finally { $h.Dispose() }
}
function Git-Blob([byte[]]$Data) {
    $prefix=[Text.Encoding]::ASCII.GetBytes(('blob {0}' -f $Data.Length) + [char]0)
    $bytes = New-Object byte[] ($prefix.Length + $Data.Length)
    [Array]::Copy($prefix,0,$bytes,0,$prefix.Length)
    [Array]::Copy($Data,0,$bytes,$prefix.Length,$Data.Length)
    return Hash-Data $bytes 'SHA1'
}
function Contains-InOrder([string]$Source,[string[]]$Needles) {
    $position=0
    foreach($needle in $Needles){
        $at=$Source.IndexOf($needle,$position,[StringComparison]::Ordinal)
        if($at -lt 0){return $false}
        $position=$at+$needle.Length
    }
    return $true
}
function Status([string]$Key,[bool]$Ok) { $report.checks[$Key]=$Ok; return $Ok }
$exitCode=2
try {
    if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'R139 Windows source gate needs Windows, no OS mutation attempted' }
    $contents=@{}
    foreach($entry in $pin.GetEnumerator()) {
        $url='https://api.github.com/repos/i-shutov/flowbridge/git/blobs/'+$entry.Value
        $response=Invoke-WebRequest -UseBasicParsing -Uri $url -Headers @{'User-Agent'='FlowBridge-R139-SourceGate'}
        $blob=$response.Content|ConvertFrom-Json
        if($blob.sha -cne $entry.Value -or $blob.encoding -cne 'base64'){throw 'Unexpected immutable source blob response'}
        [byte[]]$bytes=[Convert]::FromBase64String($blob.content)
        $git=Git-Blob $bytes
        if($git -cne $entry.Value){throw ('Source Git blob mismatch: '+$entry.Key)}
        $sha=Hash-Data $bytes 'SHA256'
        [IO.File]::WriteAllBytes((Join-Path $work $entry.Key),$bytes)
        $contents[$entry.Key]=[Text.Encoding]::UTF8.GetString($bytes)
        $report.sources+=([ordered]@{file=$entry.Key; git_blob=$git; sha256=$sha; bytes=$bytes.Length})
        Write-Host ('Verified exact source: '+$entry.Key+' / '+$git)
    }
    $broker=$contents['broker_windows.rs']; $kernel=$contents['kernel_lib.rs']
    $redirect=$contents['redirect.rs']; $policy=$contents['policy_windows.rs']
    $parts=$broker.Split(@('pub fn receive(accepted:TcpStream)'),[StringSplitOptions]::None)
    if($parts.Count -ne 2){throw 'Missing/duplicated exact receive function'}
    $receive=$parts[1].Split(@('struct Raw(usize)'),[StringSplitOptions]::None)[0]
    $claims=$broker.Split(@('pub fn claim_and_connect(self','pub fn claim_and_connect_trusted_ssh('),[StringSplitOptions]::None)
    if($claims.Count -ne 3){throw 'Missing or duplicated two claimed relay functions'}
    $socks=$claims[1]; $trusted=$claims[2].Split(@('impl TrustedSshRelay'),[StringSplitOptions]::None)[0]
    $r1=Status 'receipt_uses_one_owned_accepted_socket' (Contains-InOrder $receive @('accepted.peer_addr()?','query(&accepted,QUERY_RECORDS,CAP)?','query(&accepted,QUERY_CONTEXT,h::LEN)?','Context::parse(&bytes)','Received{accepted,context,records}'))
    $r2=Status 'receipt_fields_are_private' ($broker.Contains('pub struct Received{accepted:TcpStream,context:Context,records:Vec<u8>}'))
    $r3=Status 'physical_ssh_sets_original_records_before_connect' (Contains-InOrder $trusted @('device.command(h::CLAIM','socket(2,1,6)','WSAIoctl(s.0,SET_RECORDS','if status!=0{return Err(fail());}','connect(s.0'))
    $r4=Status 'other_upstream_sets_original_records_before_connect' (Contains-InOrder $socks @('device.command(h::CLAIM','socket(2,1,6)','WSAIoctl(s.0,SET_RECORDS','if status!=0{return Err(fail());}','connect(s.0'))
    $r5=Status 'exact_winsock_redirect_constants' ($broker.Contains('const QUERY_RECORDS:u32=0x980000dc;const QUERY_CONTEXT:u32=0x980000dd;const SET_RECORDS:u32=0x980000de;'))
    $r6=Status 'no_unproven_ingress_fallback' ($broker.Contains('if status!=0||n==0||n as usize>capacity{return Err(fail());}') -and $broker.Contains('if receive(a).is_ok()||receive(b).is_ok(){return Err(fail());}'))
    $r7=Status 'kernel_redirect_context_is_tagged' (Contains-InOrder $redirect @('request.localRedirectTargetPID=broker','request.localRedirectHandle=HANDLE','request.localRedirectContext=memory'))
    $receipt=$r1 -and $r2 -and $r3 -and $r4 -and $r5 -and $r6 -and $r7
    $report.source_receipt_pipeline_pass=$receipt
    $rights=($redirect.Contains('unsafe fn block(out:*mut k::FWPS_CLASSIFY_OUT0){(*out).actionType=k::FWP_ACTION_BLOCK;') -and
        $redirect.Contains('(*out).rights&=!k::FWPS_RIGHT_ACTION_WRITE;') -and
        $kernel.Contains('let Some(_active)=Active::enter() else{if !out.is_null(){(*out).actionType=k::FWP_ACTION_BLOCK;') -and
        $kernel.Contains('if STOP.load(Ordering::Acquire){if !out.is_null(){(*out).actionType=k::FWP_ACTION_BLOCK;'))
    $report.action_rights_blocker=Status 'conditional_action_write_veto_contract_blocker' $rights
    $dynamic=($policy.Contains('session.flags=FWPM_SESSION_FLAG_DYNAMIC;') -and $policy.Contains('FwpmEngineOpen0('))
    $report.dynamic_policy_lifetime_gap=Status 'dynamic_session_disappears_at_close' $dynamic
    if(-not $SkipSdkHeader){
        $root=Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Windows Kits\10\Include'
        if(Test-Path -LiteralPath $root -PathType Container){
            $headers=@(Get-ChildItem -Path $root -Filter 'mstcpip.h' -Recurse -File -ErrorAction SilentlyContinue|Sort-Object FullName -Descending)
            if($headers.Count -gt 0){
                $header=$headers[0].FullName; $report.windows_sdk.path=$header
                $text=[IO.File]::ReadAllText($header)
                foreach($item in @(@('RECORDS','SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS',220),@('CONTEXT','SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT',221),@('SET','SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS',222))){
                    $pattern='(?m)^\s*#\s*define\s+'+$item[1]+'\s+_WSAIOW\s*\(\s*IOC_VENDOR\s*,\s*'+$item[2]+'\s*\)'
                    $report.windows_sdk.symbols[$item[0]]=($text -match $pattern)
                }
                $report.windows_sdk.status=if(@($report.windows_sdk.symbols.Values|Where-Object { -not $_ }).Count -eq 0){'SDK_SYMBOLS_MATCH'}else{'SDK_SYMBOLS_MISMATCH'}
            }else{$report.windows_sdk.status='HEADER_UNAVAILABLE'}
        }else{$report.windows_sdk.status='HEADER_UNAVAILABLE'}
    }
    if(-not $receipt){throw 'Exact source no longer matches receipt safety contract'}
    if(-not $rights -or -not $dynamic){throw 'Release-blocker source signatures changed; independent re-review required'}
    if($report.windows_sdk.status -eq 'SDK_SYMBOLS_MISMATCH'){throw 'Installed SDK header does not match pinned IOCTL macro signature'}
    $report.status='R139_SOURCE_RECEIPT_VALIDATED_RELEASE_NO_GO'
    $report.reason='Two release blockers: conditional action-write veto plus dynamic-policy lifetime'
    $exitCode=3
} catch {
    $report.status='R139_UNAVAILABLE_OR_SOURCE_MISMATCH'; $report.reason=$_.Exception.Message; $exitCode=2
} finally {
    $report.exit_code=$exitCode; $report.finished_utc=[DateTime]::UtcNow.ToString('o')
    $out=Join-Path $work 'R139_EVIDENCE.json'
    [IO.File]::WriteAllText($out,($report|ConvertTo-Json -Depth 9),[Text.UTF8Encoding]::new($false))
    Write-Host ('R139 status: '+$report.status)
    Write-Host ('R139 reason: '+$report.reason)
    Write-Host ('R139 evidence: '+$out)
    Write-Host ('R139 exit code: '+$exitCode)
    Write-Host 'Exit 3 is deliberate RELEASE NO-GO, NOT a Windows compile or network failure.'
}
exit $exitCode
