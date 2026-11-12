#requires -Version 5.1
<#
R138: exactly two concurrent OWN helpers, same EXE/AppId, distinct process identity.
No BFE policy/filter/driver/socket operations. No caller-selected child PID or EXE.
Default builds/tests only; -RunOwnSiblingProbe explicitly enables native helpers.
Only one immutable source blob is downloaded. Original checkout and system untouched.
#>
[CmdletBinding()]
param(
    [string]$RustBinDirectory = (Join-Path $env:USERPROFILE '.cargo\bin'),
    [string]$OfflineSource = '',
    [switch]$RunOwnSiblingProbe,
    [switch]$CompileOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$sourceBlob='eb4671a08ce2d7fd8a928e504886f74a9e00b508'
$sourceHash='549991c3974359444ce1ddfec1e0b181ce307126df574799b5a2d60966e0e53b'
$matrixHash='8185ca0c6b8a1dbd968ab3be9a3b0fa105bbc16f9ca0b4b8271f8a1de3d16695'
$evidence=Join-Path ([IO.Path]::GetTempPath()) ('FlowBridge-R138-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $evidence
$utf8=[Text.UTF8Encoding]::new($false)
$oldPath=$env:PATH
$exitCode=2
$report=[ordered]@{
    schema=1; tool='FlowBridge R138 same-image process-instance binding'; status='NOT_RUN'; reason=$null
    started_utc=[DateTime]::UtcNow.ToString('o'); finished_utc=$null; evidence_directory=$evidence
    source_blob_expected=$sourceBlob; source_sha256_expected=$sourceHash; source_sha256_observed=$null
    target='x86_64-pc-windows-msvc'; windows_build=$null; rustc_version=$null
    metadata_exit=$null; listed_tests=$null; unit_tests_exit=$null; test_exe_sha256=$null
    inspector_sha256=$null; contract_matrix_sha256=$null; native_probe_requested=[bool]$RunOwnSiblingProbe
    native_probe_exit=$null; binding_mask=$null; appid_only_mask=$null; archive=$null; archive_error=$null
    kernel_origin_proof=$false; socket_binding_proof=$false; no_direct_proof=$false
    pid_reuse_test_performed=$false; atomic_snapshot=$false; policy_modified=$false
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
        if (-not $p.WaitForExit(120000)) {
            # Only this harness's direct compiler/probe child; never a process by PID lookup.
            if (-not $p.HasExited) { $p.Kill() }
            $p.WaitForExit()
            Save-Text ($Log+'.stdout.txt') ($stdout.GetAwaiter().GetResult())
            Save-Text ($Log+'.stderr.txt') ($stderr.GetAwaiter().GetResult())
            throw ('Own child timeout: '+$Log)
        }
        $text=$stdout.GetAwaiter().GetResult(); $err=$stderr.GetAwaiter().GetResult()
        Save-Text ($Log+'.stdout.txt') $text; Save-Text ($Log+'.stderr.txt') $err
        return [pscustomobject]@{ExitCode=$p.ExitCode;Output=$text;ErrorOutput=$err}
    } finally { $p.Dispose() }
}

function Is-U32($v) {return (($v -is [int] -or $v -is [long] -or $v -is [uint32] -or $v -is [uint64]) -and [decimal]$v -ge 0 -and [decimal]$v -le 4294967295)}
function Is-Time($v) {return ($v -is [string] -and $v -cmatch '^[0-9A-F]{16}$' -and $v -cne ('0'*16))}
function Is-Wide($v) {
    if ($v -isnot [string] -or $v.Length -gt 131068 -or $v -cnotmatch '^(?:[0-9A-F]{4})+$') {return $false}
    for ($i=0;$i -lt $v.Length;$i+=4) {if ($v.Substring($i,4) -ceq '0000') {return $false}}
    return $true
}
function Is-Opaque($v) {return ($v -is [string] -and $v.Length -le 131072 -and $v -cmatch '^(?:[0-9A-F]{2})+$')}
try {
    if ($CompileOnly -and $RunOwnSiblingProbe) {throw 'CompileOnly cannot execute the native probe'}
    if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or -not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {throw 'Native Windows x86_64 PowerShell required'}
    $os=Get-CimInstance Win32_OperatingSystem
    $report.windows_build=('{0} / {1} / {2}' -f $os.Caption,$os.Version,$os.BuildNumber)
    if (Test-Path -LiteralPath $RustBinDirectory -PathType Container) {$env:PATH=$RustBinDirectory+';'+$env:PATH}
    $rust=Get-Command rustc.exe -CommandType Application -ErrorAction Stop
    $r=Run-Local $rust.Source @('-vV') 'rustc-version'
    if ($r.ExitCode -ne 0 -or $r.Output -notmatch '(?m)^host:\s*x86_64-pc-windows-msvc\s*$') {throw 'Existing MSVC x64 Rust required; no installation attempted'}
    $report.rustc_version=$r.Output.Trim()
    if (-not [string]::IsNullOrWhiteSpace($OfflineSource)) {
        [byte[]]$bytes=[IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $OfflineSource).Path)
    } else {
        $uri='https://api.github.com/repos/i-shutov/flowbridge/git/blobs/'+$sourceBlob
        $response=Invoke-WebRequest -UseBasicParsing -Uri $uri -Headers @{'User-Agent'='FlowBridge-R138-SourceFetch'}
        $blob=$response.Content|ConvertFrom-Json
        if ($blob.sha -cne $sourceBlob -or $blob.encoding -cne 'base64') {throw 'Unexpected GitHub blob response'}
        [byte[]]$bytes=[Convert]::FromBase64String($blob.content)
    }
    $report.source_sha256_observed=Hash-Bytes $bytes 'SHA256'
    if ((Blob-Hash $bytes) -cne $sourceBlob -or $report.source_sha256_observed -cne $sourceHash) {throw 'Exact source byte verification failed'}
    $source=Join-Path $evidence 'r138_same_image_siblings.rs'
    [IO.File]::WriteAllBytes($source,$bytes)
    Write-Host ('Exact R138 source: '+$sourceBlob)
    $meta=Join-Path $evidence 'r138.rmeta'
    $r=Run-Local $rust.Source @('--edition=2021','--target',$report.target,'--emit=metadata',$source,'-o',$meta) 'metadata'
    $report.metadata_exit=$r.ExitCode
    if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $meta)) {throw 'Windows-gated source typecheck failed; see metadata.stderr.txt'}
    $report.status='WINDOWS_METADATA_ONLY';$exitCode=0
    if (-not $CompileOnly) {
        $test=Join-Path $evidence 'r138-tests.exe'
        $r=Run-Local $rust.Source @('--edition=2021','--target',$report.target,'--test',$source,'-o',$test) 'test-build'
        if ($r.ExitCode -ne 0) {throw 'Synthetic-test link failed'}
        $report.test_exe_sha256=(Get-FileHash -LiteralPath $test -Algorithm SHA256).Hash.ToLowerInvariant()
        $list=Run-Local $test @('--list','--format=terse') 'test-list'
        $names=@($list.Output -split '\r?\n'|Where-Object {$_ -match '^tests::.+: test$'})
        $report.listed_tests=$names.Count
        if ($list.ExitCode -ne 0 -or $names.Count -ne 20 -or @($names|Select-Object -Unique).Count -ne 20) {throw 'Expected exactly 20 unique tests'}
        $r=Run-Local $test @('--test-threads=1') 'unit-tests'
        $report.unit_tests_exit=$r.ExitCode;Write-Host $r.Output
        if ($r.ExitCode -ne 0 -or $r.Output -notmatch 'test result: ok\. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;') {throw 'Synthetic tests failed or incomplete'}
        $exe=Join-Path $evidence 'r138-siblings.exe'
        $r=Run-Local $rust.Source @('--edition=2021','--target',$report.target,$source,'-o',$exe) 'probe-build'
        if ($r.ExitCode -ne 0) {throw 'Native probe link failed'}
        $report.inspector_sha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
        $r=Run-Local $exe @('--contract-matrix') 'contract-matrix'
        $text=$r.Output.Replace("`r`n","`n")
        $report.contract_matrix_sha256=Hash-Bytes ([Text.Encoding]::ASCII.GetBytes($text)) 'SHA256'
        if ($r.ExitCode -ne 0 -or $r.ErrorOutput.Trim().Length -ne 0 -or $report.contract_matrix_sha256 -cne $matrixHash) {throw 'Rust contract matrix differs from independent oracle'}
        $report.status='NATIVE_SYNTHETIC_PASS_ONLY'
        if ($RunOwnSiblingProbe) {
            $r=Run-Local $exe @('--own-siblings') 'siblings'
            $report.native_probe_exit=$r.ExitCode;$exitCode=2
            Save-Text 'siblings.jsonl' $r.Output;Write-Host $r.Output
            if ($r.ExitCode -ne 0) {throw 'Native probe failed; preserve domain/stage/code in siblings.jsonl'}
            $lines=@($r.Output -split '\r?\n'|Where-Object {$_.Trim().Length -gt 0})
            if ($lines.Count -ne 7 -or $r.ErrorOutput.Trim().Length -ne 0) {throw 'Expected seven JSON records without stderr'}
            $rows=@($lines|ForEach-Object {$_|ConvertFrom-Json -ErrorAction Stop})
            foreach ($item in $rows) {
                if ($item.schema -isnot [int] -or $item.schema -ne 1) {throw 'Invalid schema'}
                foreach ($flag in @('kernel_origin_proof','socket_binding_proof','no_direct_proof')) {
                    if ($item.$flag -isnot [bool] -or $item.$flag) {throw ('Unsupported proof boundary: '+$flag)}
                }
            }
            $subjects=@('A','B','A','B','B');$phases=@('both_alive','both_alive','A_exited','B_survives','both_exited')
            $expectedWait=@(258,258,0,258,0);$expectedExit=@(259,259,23,259,29)
            for ($i=0;$i -lt 5;$i++) {
                $p=$rows[$i]
                if ($p.kind -cne 'process' -or $p.subject -cne $subjects[$i] -or $p.phase -cne $phases[$i] -or
                    -not (Is-U32 $p.pid) -or $p.pid -eq 0 -or -not (Is-Time $p.creation_hex) -or
                    -not (Is-U32 $p.wait_before) -or $p.wait_before -ne $expectedWait[$i] -or
                    -not (Is-U32 $p.wait_after) -or $p.wait_after -ne $expectedWait[$i] -or
                    -not (Is-U32 $p.exit_code) -or $p.exit_code -ne $expectedExit[$i] -or
                    $p.secondary_matches -isnot [bool] -or -not $p.secondary_matches) {throw 'Malformed or raced process observation'}
            }
            if ($rows[0].pid -eq $rows[1].pid) {throw 'Concurrent helper PIDs must differ'}
            foreach ($pair in @(@(0,2),@(1,3),@(1,4))) {
                $x=$rows[$pair[0]];$y=$rows[$pair[1]]
                if ($x.pid -ne $y.pid -or $x.creation_hex -cne $y.creation_hex) {throw 'Retained process identity changed'}
            }
            $a=$rows[5];$s=$rows[6]
            if ($a.kind -cne 'appid' -or $a.queries -isnot [int] -or $a.queries -ne 4 -or $a.opaque_bytes -isnot [bool] -or -not $a.opaque_bytes) {throw 'Malformed AppId record'}
            foreach ($key in @('a_path_hex','b_path_hex','b_path_after_hex')) {if (-not (Is-Wide $a.$key)) {throw 'Invalid image name encoding'}}
            if ($a.a_path_hex -cne $a.b_path_hex -or $a.b_path_hex -cne $a.b_path_after_hex) {throw 'Same image path not observed'}
            $apps=@($a.a_before,$a.b_before,$a.a_name_after_exit,$a.b_after)
            foreach ($app in $apps) {if (-not (Is-Opaque $app) -or $app -cne $apps[0]) {throw 'Same opaque AppId not observed'}}
            # Independent recomputation; do not trust a summary's binding decision.
            $binding=0;$weak=0
            for ($i=0;$i -lt 4;$i++) {
                $p=$rows[$i];$equal=$apps[$i] -ceq $apps[0]
                if ($equal) {$weak=$weak -bor (1 -shl $i)}
                if ($equal -and $p.pid -eq $rows[0].pid -and $p.creation_hex -ceq $rows[0].creation_hex -and
                    $p.wait_before -eq 258 -and $p.wait_after -eq 258 -and $p.exit_code -eq 259) {$binding=$binding -bor (1 -shl $i)}
            }
            if ($binding -ne 1 -or $weak -ne 15 -or $s.kind -cne 'summary' -or $s.status -cne 'SAME_APPID_DISTINCT_PROCESSES_NOT_ALE_PROOF' -or
                $s.processes -isnot [int] -or $s.processes -ne 2 -or $s.binding_mask -isnot [int] -or $s.binding_mask -ne $binding -or
                $s.appid_only_mask -isnot [int] -or $s.appid_only_mask -ne $weak -or
                $s.query_handle_rights -isnot [int] -or $s.query_handle_rights -ne 1052672 -or
                $s.atomic_snapshot -isnot [bool] -or $s.atomic_snapshot -or
                $s.pid_reuse_test_performed -isnot [bool] -or $s.pid_reuse_test_performed) {throw 'Summary/decision/proof mismatch'}
            $report.binding_mask=$binding;$report.appid_only_mask=$weak;$report.status=$s.status;$exitCode=0
            Write-Host 'Binding decisions: A alive=accept; B alive=reject; A exited=reject; surviving B=reject.'
        }
    }
} catch {$report.status='UNAVAILABLE_OR_FAILED';$report.reason=$_.Exception.Message;$exitCode=2}
finally {
    $env:PATH=$oldPath;$report.finished_utc=[DateTime]::UtcNow.ToString('o')
    $report.archive=Join-Path $evidence 'evidence-only.zip'
    Save-Text 'R138_EVIDENCE.json' ($report|ConvertTo-Json -Depth 8)
    try {
        $logs=@(Get-ChildItem -LiteralPath $evidence -File|Where-Object {$_.Extension -in @('.txt','.json','.jsonl')})
        Compress-Archive -LiteralPath $logs.FullName -DestinationPath $report.archive -Force
    } catch {$report.archive=$null;$report.archive_error=$_.Exception.Message;Save-Text 'R138_EVIDENCE.json' ($report|ConvertTo-Json -Depth 8)}
    Write-Host ('R138 status: '+$report.status)
    if ($report.reason) {Write-Host ('R138 reason: '+$report.reason)}
    Write-Host ('R138 evidence: '+$evidence)
    if ($report.archive) {Write-Host ('R138 evidence ZIP: '+$report.archive)}
    Write-Host ('R138 exit code: '+$exitCode)
    Write-Host 'Two own helpers only; no actual connection, socket attribution or WFP enforcement proof.'
}
exit $exitCode
