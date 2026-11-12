#requires -Version 5.1
<#
FlowBridge R132: event-order tests of exact-source R19 modules. No BFE or Windows FFI.
Six events, 720 permutations, two families, five applied hazards, five payloads.
A TEST-ONLY composition, not the full kernel adapter or physical event scheduler.
Downloads five immutable Git blobs; writes only a fresh temporary directory.
No clone/checkout/install/driver/filter/service/network-setting/CI changes.
Synthetic integer identities are NOT live EPROCESS/socket references.
#>
[CmdletBinding()]
param(
    [string]$RustBinDirectory = (Join-Path $env:USERPROFILE '.cargo\bin'),
    [string]$OfflineBundleRoot = '',
    [switch]$CompileOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$files = @'
[
  {
    "path": "research/wfp-ale/kernel-r19/kernel/src/auth_appid.rs",
    "git_blob": "f16ab6ad0f618c74ed4e79ce606583169084970d",
    "sha256": "c3da7a7107cf4b72b8ed372a18f7b0fa226c2d2c4f6fa044e98606bc5b2d95a1"
  },
  {
    "path": "research/wfp-ale/kernel-r19/kernel/src/handoff.rs",
    "git_blob": "e1d17217db50362ba9c4efc83af820b6beb094cf",
    "sha256": "8d64d156ecce6cd17ad0a55802a7e0150aa5fee39b8067e67d944a31d25731f9"
  },
  {
    "path": "research/wfp-ale/kernel-r19/kernel/src/ledger.rs",
    "git_blob": "b88c4c9237c4c118517978fc454f5048f522aa7f",
    "sha256": "bb07015b6bb97191e9e3d9321c6b9b60d0b770a0358864a70706bc72ebf852b1"
  },
  {
    "path": "research/wfp-ale/kernel-r19/policy_plan.rs",
    "git_blob": "c8ab344551f1adfc20fd0019c4606cf3ca3c81c4",
    "sha256": "1683f9b2300868ba399632308c1db0c2e6deb7fe09969fef4b1bacc17eba6851"
  },
  {
    "path": "research/wfp-ale/r132/r132_event_orders.rs",
    "git_blob": "82b97b3952cb8006ed389c68030bf136af9bdf47",
    "sha256": "a0509d3c36e7279a508c2691e6adf059839725f3df0a6c3c8385a07f30d8e452"
  }
]
'@ | ConvertFrom-Json

$expectedTests = 64
$expectedTraces = 36000
$expectedCampaignHash = 'c2af3f996ec4c52620c973f0fb34dc4ead470e94f6805edeb9a8d49fcf278e37'
$evidence = Join-Path ([IO.Path]::GetTempPath()) ('FlowBridge-R132-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $evidence
$utf8 = [Text.UTF8Encoding]::new($false)
$oldPath = $env:PATH
$oldStack = $env:RUST_MIN_STACK
$exitCode = 2
$report = [ordered]@{
    schema=1; tool='FlowBridge R132 exact-source event orders'
    started_utc=[DateTime]::UtcNow.ToString('o'); finished_utc=$null
    status='NOT_RUN'; reason=$null; evidence_directory=$evidence
    windows_build=$null; rustc_version=$null; target='x86_64-pc-windows-msvc'
    sources=@(); metadata_exit=$null; test_link_exit=$null; tests_exit=$null
    expected_tests=$expectedTests; listed_tests=$null; passed_tests=$null
    test_exe_sha256=$null; proof_scope='EXACT_SOURCE_SYNTHETIC_EVENT_ORDERS'
    campaign_exe_sha256=$null; campaign_exit=$null; campaign_traces=$null
    campaign_sha256=$null; expected_campaign_sha256=$expectedCampaignHash
    bfe_queried=$false; kernel_origin_proof=$false; packet_bound_g2_pass=$false
    kernel_adapter_executed=$false; real_process_liveness_proof=$false
    no_direct_proof=$false; native_r129_status_not_retested=$true
    archive=$null; archive_error=$null
}
function Save-Text([string]$Name,[string]$Text) {
    [IO.File]::WriteAllText((Join-Path $evidence $Name),$Text,$utf8)
}
function Hash-Bytes([byte[]]$Bytes,[string]$Algorithm) {
    $h=[Security.Cryptography.HashAlgorithm]::Create($Algorithm)
    try { return -join ($h.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) }
    finally { $h.Dispose() }
}
function Blob-Hash([byte[]]$Bytes) {
    $header=[Text.Encoding]::ASCII.GetBytes(('blob {0}' -f $Bytes.Length)+[char]0)
    $payload=New-Object byte[] ($header.Length+$Bytes.Length)
    [Array]::Copy($header,0,$payload,0,$header.Length)
    [Array]::Copy($Bytes,0,$payload,$header.Length,$Bytes.Length)
    return Hash-Bytes $payload 'SHA1'
}
function Run-Local([string]$Exe,[string[]]$Arguments,[string]$Log) {
    $quoted=@($Arguments | ForEach-Object {
        if ($_ -match '["\r\n]' -or $_.EndsWith('\')) { throw 'Unsafe native argument shape' }
        '"'+$_+'"'
    })
    $si=[Diagnostics.ProcessStartInfo]::new()
    $si.FileName=$Exe; $si.Arguments=$quoted -join ' '; $si.WorkingDirectory=$evidence
    $si.UseShellExecute=$false; $si.CreateNoWindow=$true
    $si.RedirectStandardOutput=$true; $si.RedirectStandardError=$true
    $p=[Diagnostics.Process]::new(); $p.StartInfo=$si
    try {
        if (-not $p.Start()) { throw ('Cannot start '+$Exe) }
        $stdout=$p.StandardOutput.ReadToEndAsync(); $stderr=$p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit(180000)) {
            # Kill only the child process this harness created; never another process.
            if (-not $p.HasExited) { $p.Kill() }
            $p.WaitForExit()
            Save-Text ($Log+'.stdout.txt') ($stdout.GetAwaiter().GetResult())
            Save-Text ($Log+'.stderr.txt') ($stderr.GetAwaiter().GetResult())
            throw ('Own test/compiler child exceeded timeout: '+$Log)
        }
        $text=$stdout.GetAwaiter().GetResult(); $err=$stderr.GetAwaiter().GetResult()
        Save-Text ($Log+'.stdout.txt') $text; Save-Text ($Log+'.stderr.txt') $err
        return [pscustomobject]@{ExitCode=$p.ExitCode; Output=$text; ErrorOutput=$err}
    } finally { $p.Dispose() }
}
try {
    if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or
        -not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
        throw 'Requires native Windows x86_64 PowerShell'
    }
    $os=Get-CimInstance Win32_OperatingSystem
    $report.windows_build=('{0} / {1} / {2}' -f $os.Caption,$os.Version,$os.BuildNumber)
    if (Test-Path -LiteralPath $RustBinDirectory -PathType Container) {
        $env:PATH=$RustBinDirectory+';'+$env:PATH
    }
    # Child test threads only; restores the prior process environment in finally.
    $env:RUST_MIN_STACK='8388608'
    $rust=Get-Command rustc.exe -CommandType Application -ErrorAction Stop
    $info=Run-Local $rust.Source @('-vV') 'rustc-version'
    if ($info.ExitCode -ne 0 -or $info.Output -notmatch '(?m)^host:\s*x86_64-pc-windows-msvc\s*$') {
        throw 'Existing rustc must be native x86_64-pc-windows-msvc; nothing installed'
    }
    $report.rustc_version=$info.Output.Trim()
    foreach ($item in $files) {
        [byte[]]$bytes=@()
        if (-not [string]::IsNullOrWhiteSpace($OfflineBundleRoot)) {
            $local=Join-Path $OfflineBundleRoot $item.path
            $bytes=[IO.File]::ReadAllBytes($local)
        } else {
            $uri='https://api.github.com/repos/i-shutov/flowbridge/git/blobs/'+$item.git_blob
            $response=Invoke-WebRequest -UseBasicParsing -Uri $uri -Headers @{'User-Agent'='FlowBridge-R132-SourceFetch'}
            $blob=$response.Content | ConvertFrom-Json
            if ($blob.sha -cne $item.git_blob -or $blob.encoding -cne 'base64') { throw 'Unexpected GitHub blob response' }
            $bytes=[Convert]::FromBase64String($blob.content)
        }
        $sha=Hash-Bytes $bytes 'SHA256'; $git=Blob-Hash $bytes
        if ($git -cne $item.git_blob -or $sha -cne $item.sha256) {
            throw ('Exact-source attestation failed: '+$item.path+'; no normalization or hash bypass permitted')
        }
        $dest=Join-Path $evidence $item.path
        $null=New-Item -ItemType Directory -Path (Split-Path -Parent $dest) -Force
        [IO.File]::WriteAllBytes($dest,$bytes)
        $report.sources+=([ordered]@{path=$item.path; git_blob=$git; sha256=$sha; bytes=$bytes.Length})
        Write-Host ('Verified source: '+$item.path+' / '+$git)
    }
    $source=Join-Path $evidence 'research\wfp-ale\r132\r132_event_orders.rs'
    $meta=Join-Path $evidence 'r132-tests.rmeta'
    $r=Run-Local $rust.Source @('--edition=2021','--target',$report.target,'--test',
        '--forbid','unsafe_code','--emit=metadata',$source,'-o',$meta) 'metadata'
    $report.metadata_exit=$r.ExitCode
    if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $meta)) {
        throw 'Rust metadata typecheck failed; see metadata.stderr.txt'
    }
    $report.status='EXACT_SOURCE_METADATA_ONLY'; $exitCode=0
    if (-not $CompileOnly) {
        $exe=Join-Path $evidence 'r132-exact-logic-tests.exe'
        $r=Run-Local $rust.Source @('--edition=2021','--target',$report.target,'--test',
            '--forbid','unsafe_code',$source,'-o',$exe) 'test-build'
        $report.test_link_exit=$r.ExitCode
        if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $exe)) { throw 'Rust test link failed; see test-build.stderr.txt' }
        $report.test_exe_sha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
        $list=Run-Local $exe @('--list','--format=terse') 'test-list'
        $names=@($list.Output -split '\r?\n' | Where-Object { $_ -match ': test$' })
        $report.listed_tests=$names.Count
        if ($list.ExitCode -ne 0 -or $names.Count -ne $expectedTests -or
            @($names | Select-Object -Unique).Count -ne $expectedTests) { throw 'Unexpected/duplicate/missing Rust test list' }
        foreach ($expect in @(@('ledger',11),@('handoff',19),@('auth_appid',7),@('policy_plan',9),@('schedule_tests',18))) {
            $prefix='^'+[regex]::Escape([string]$expect[0])+'::'
            if (@($names | Where-Object { $_ -match $prefix }).Count -ne [int]$expect[1]) { throw ('Wrong test group: '+$expect[0]) }
        }
        $r=Run-Local $exe @('--test-threads=1','--nocapture') 'unit-tests'
        $report.tests_exit=$r.ExitCode
        Write-Host $r.Output
        if ($r.ExitCode -ne 0 -or $r.Output -notmatch 'test result: ok\. 64 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;') {
            throw 'Exact-source tests failed or result cardinality changed; see unit-tests logs'
        }
        $report.passed_tests=$expectedTests
        # Compare an executed Rust trace campaign to an independently computed oracle.
        $campaignExe=Join-Path $evidence 'r132-event-orders.exe'
        $r=Run-Local $rust.Source @('--edition=2021','--target',$report.target,
            '--forbid','unsafe_code',$source,'-o',$campaignExe) 'campaign-build'
        if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $campaignExe)) {
            throw 'Rust campaign linking failed; see campaign-build.stderr.txt'
        }
        $report.campaign_exe_sha256=(Get-FileHash -LiteralPath $campaignExe -Algorithm SHA256).Hash.ToLowerInvariant()
        $r=Run-Local $campaignExe @('--campaign') 'campaign'
        $report.campaign_exit=$r.ExitCode
        # Normalize only CRLF from captured stdout, never any source bytes.
        $text=$r.Output.Replace("`r`n","`n")
        $lines=@($text -split "`n" | Where-Object { $_.Length -gt 0 })
        $report.campaign_traces=$lines.Count
        $report.campaign_sha256=Hash-Bytes ([Text.Encoding]::UTF8.GetBytes($text)) 'SHA256'
        if ($r.ExitCode -ne 0 -or $r.ErrorOutput.Trim().Length -ne 0 -or
            $lines.Count -ne $expectedTraces -or $report.campaign_sha256 -cne $expectedCampaignHash) {
            throw 'Rust event sequence differs from the independent oracle; keep campaign logs'
        }
        Write-Host ('Event orders verified: '+$lines.Count+' traces / 216000 event steps')
        Write-Host ('Campaign SHA256: '+$report.campaign_sha256)
        $report.status='EXACT_SOURCE_EVENT_ORDERS_PASS_NOT_KERNEL_PROOF' 
        $exitCode=0
    }
} catch {
    $report.status='UNAVAILABLE_OR_FAILED'; $report.reason=$_.Exception.Message; $exitCode=2
} finally {
    $env:PATH=$oldPath; $env:RUST_MIN_STACK=$oldStack
    $report.finished_utc=[DateTime]::UtcNow.ToString('o')
    $archive=Join-Path $evidence 'evidence-only.zip'
    $report.archive=$archive
    Save-Text 'R132_EVIDENCE.json' ($report | ConvertTo-Json -Depth 8)
    try {
        $logs=@(Get-ChildItem -LiteralPath $evidence -File | Where-Object { $_.Extension -eq '.txt' -or $_.Extension -eq '.json' })
        Compress-Archive -LiteralPath $logs.FullName -DestinationPath $archive -Force
    } catch {
        $report.archive=$null; $report.archive_error=$_.Exception.Message
        Save-Text 'R132_EVIDENCE.json' ($report | ConvertTo-Json -Depth 8)
    }
    Write-Host ('R132 status: '+$report.status)
    if ($report.reason) { Write-Host ('R132 reason: '+$report.reason) }
    Write-Host ('R132 evidence: '+$evidence)
    if ($report.archive) { Write-Host ('R132 evidence ZIP: '+$archive) }
    Write-Host ('R132 exit code: '+$exitCode)
    Write-Host 'No BFE, sockets, drivers or filters. Applied synthetic events are not Windows callback proof.'
}
exit $exitCode
