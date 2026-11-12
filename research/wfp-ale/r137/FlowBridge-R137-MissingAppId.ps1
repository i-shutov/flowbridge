#requires -Version 5.1
<#
R137: exact-source Rust; no-file-write test of WFP AppId for an absent filename.
Default synthetic-only. -RunReadOnlyMissingName checks GetFileAttributesW
before and after a filename-only WFP AppId request. Never creates that file.
No policy/driver/filter writes, arbitrary PID/path, sockets or installations.
Downloads one pinned source Git blob unless -OfflineSource is provided.
#>
[CmdletBinding()]
param(
    [string]$RustBinDirectory = (Join-Path $env:USERPROFILE '.cargo\bin'),
    [string]$OfflineSource = '',
    [switch]$RunReadOnlyMissingName,
    [switch]$CompileOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$sourceBlob='1b7ba8f0097811a3f636100cd843a26764b4238a'
$sourceHash='766f0495b4489958cdde0fbdfc3d9085fc55c780eaf58c91de524f10376be77d'
$matrixHash='a42dbe4fe12b36fd15b525dc0d659058c49aad3c77e3066305ad8529c5a65367'
$evidence=Join-Path ([IO.Path]::GetTempPath()) ('FlowBridge-R137-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $evidence
$utf8=[Text.UTF8Encoding]::new($false)
$oldPath=$env:PATH
$exitCode=2
$report=[ordered]@{
    schema=1; tool='FlowBridge R137 nonexistent own-folder filename WFP AppId diagnostic'; status='NOT_RUN'; reason=$null
    started_utc=[DateTime]::UtcNow.ToString('o'); finished_utc=$null; evidence_directory=$evidence
    source_blob_expected=$sourceBlob; source_sha256_expected=$sourceHash; source_sha256_observed=$null
    target='x86_64-pc-windows-msvc'; windows_build=$null; rustc_version=$null
    metadata_exit=$null; listed_tests=$null; unit_tests_exit=$null; test_exe_sha256=$null
    inspector_sha256=$null; contract_matrix_sha256=$null; native_probe_requested=[bool]$RunReadOnlyMissingName
    native_probe_exit=$null; observations_mask=$null; archive=$null; archive_error=$null
    kernel_origin_proof=$false; image_section_identity_proof=$false; no_direct_proof=$false
    policy_enumeration_performed=$false; wfp_policy_modified=$false; atomic_snapshot=$false; test_creates_file=$false
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

function Is-U32($v) {
    return (($v -is [int] -or $v -is [long] -or $v -is [uint32] -or $v -is [uint64]) -and
        [decimal]$v -ge 0 -and [decimal]$v -le 4294967295)
}
function Is-Hex($v,[int]$Length) { return ($v -is [string] -and $v.Length -eq $Length -and $v -cmatch '^[0-9A-F]+$') }
function Is-Wide($v) {
    if ($v -isnot [string] -or $v.Length -gt 131068 -or $v -cnotmatch '^(?:[0-9A-F]{4})+$') {return $false}
    for ($i=0;$i -lt $v.Length;$i+=4) {if ($v.Substring($i,4) -ceq '0000') {return $false}}
    return $true
}
function Is-Opaque($v) {return ($v -is [string] -and $v.Length -le 131072 -and $v -cmatch '^(?:[0-9A-F]{2})+$')}
try {
    if ($CompileOnly -and $RunReadOnlyMissingName) {throw 'CompileOnly cannot execute the native probe'}
    if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or -not [Environment]::Is64BitProcess -or
        $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {throw 'Native Windows x86_64 PowerShell required'}
    $os=Get-CimInstance Win32_OperatingSystem
    $report.windows_build=('{0} / {1} / {2}' -f $os.Caption,$os.Version,$os.BuildNumber)
    if (Test-Path -LiteralPath $RustBinDirectory -PathType Container) {$env:PATH=$RustBinDirectory+';'+$env:PATH}
    $rust=Get-Command rustc.exe -CommandType Application -ErrorAction Stop
    $r=Run-Local $rust.Source @('-vV') 'rustc-version'
    if ($r.ExitCode -ne 0 -or $r.Output -notmatch '(?m)^host:\s*x86_64-pc-windows-msvc\s*$') {throw 'Existing native MSVC x64 Rust required; no installation attempted'}
    $report.rustc_version=$r.Output.Trim()
    if (-not [string]::IsNullOrWhiteSpace($OfflineSource)) {
        [byte[]]$bytes=[IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $OfflineSource).Path)
    } else {
        $uri='https://api.github.com/repos/i-shutov/flowbridge/git/blobs/'+$sourceBlob
        $response=Invoke-WebRequest -UseBasicParsing -Uri $uri -Headers @{'User-Agent'='FlowBridge-R137-SourceFetch'}
        $blob=$response.Content|ConvertFrom-Json
        if ($blob.sha -cne $sourceBlob -or $blob.encoding -cne 'base64') {throw 'Unexpected GitHub blob response'}
        [byte[]]$bytes=[Convert]::FromBase64String($blob.content)
    }
    $report.source_sha256_observed=Hash-Bytes $bytes 'SHA256'
    if ((Blob-Hash $bytes) -cne $sourceBlob -or $report.source_sha256_observed -cne $sourceHash) {throw 'Exact source byte verification failed'}
    $source=Join-Path $evidence 'r137_missing_path_appid.rs'
    [IO.File]::WriteAllBytes($source,$bytes)
    Write-Host ('Exact R137 source: '+$sourceBlob)
    $meta=Join-Path $evidence 'r137.rmeta'
    $r=Run-Local $rust.Source @('--edition=2021','--target',$report.target,'--emit=metadata',$source,'-o',$meta) 'metadata'
    $report.metadata_exit=$r.ExitCode
    if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $meta)) {throw 'Windows-gated source typecheck failed; see metadata.stderr.txt'}
    $report.status='WINDOWS_METADATA_ONLY';$exitCode=0
    if (-not $CompileOnly) {
        $test=Join-Path $evidence 'r137-tests.exe'
        $r=Run-Local $rust.Source @('--edition=2021','--target',$report.target,'--test',$source,'-o',$test) 'test-build'
        if ($r.ExitCode -ne 0) {throw 'Synthetic-test link failed'}
        $report.test_exe_sha256=(Get-FileHash -LiteralPath $test -Algorithm SHA256).Hash.ToLowerInvariant()
        $list=Run-Local $test @('--list','--format=terse') 'test-list'
        $names=@($list.Output -split '\r?\n'|Where-Object {$_ -match '^tests::.+: test$'})
        $report.listed_tests=$names.Count
        if ($list.ExitCode -ne 0 -or $names.Count -ne 18 -or @($names|Select-Object -Unique).Count -ne 18) {throw 'Expected exactly 18 unique tests'}
        $r=Run-Local $test @('--test-threads=1') 'unit-tests'
        $report.unit_tests_exit=$r.ExitCode;Write-Host $r.Output
        if ($r.ExitCode -ne 0 -or $r.Output -notmatch 'test result: ok\. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;') {throw 'Synthetic tests failed or incomplete'}
        $exe=Join-Path $evidence 'r137-missing-name.exe'
        $r=Run-Local $rust.Source @('--edition=2021','--target',$report.target,$source,'-o',$exe) 'probe-build'
        if ($r.ExitCode -ne 0) {throw 'Native probe linking failed'}
        $report.inspector_sha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
        $r=Run-Local $exe @('--contract-matrix') 'contract-matrix'
        $text=$r.Output.Replace("`r`n","`n")
        $report.contract_matrix_sha256=Hash-Bytes ([Text.Encoding]::ASCII.GetBytes($text)) 'SHA256'
        if ($r.ExitCode -ne 0 -or $r.ErrorOutput.Trim().Length -ne 0 -or $report.contract_matrix_sha256 -cne $matrixHash) {throw 'Rust contract matrix differs from independent oracle'}
        $report.status='NATIVE_SYNTHETIC_PASS_ONLY'
        if ($RunReadOnlyMissingName) {
            $r=Run-Local $exe @('--read-only-missing-name') 'missing-name'
            $report.native_probe_exit=$r.ExitCode;$exitCode=2
            Save-Text 'missing-name.jsonl' $r.Output
            Write-Host $r.Output
            if ($r.ExitCode -notin @(0,3,4)) {throw 'Native query failed; preserve raw stage/code in missing-name.jsonl'}
            $lines=@($r.Output -split '\r?\n'|Where-Object {$_.Trim().Length -gt 0})
            if ($lines.Count -ne 2 -or $r.ErrorOutput.Trim().Length -ne 0) {
                throw 'Expected exactly one negative-name record and one summary, without stderr'
            }
            $rows=@($lines|ForEach-Object {$_|ConvertFrom-Json -ErrorAction Stop})
            foreach ($item in $rows) {
                if ($item.schema -isnot [int] -or $item.schema -ne 1) {throw 'Invalid schema'}
                foreach ($flag in @('kernel_origin_proof','image_section_identity_proof','no_direct_proof')) {
                    if ($item.$flag -isnot [bool] -or $item.$flag) {throw ('Invalid proof boundary: '+$flag)}
                }
            }
            $n=$rows[0];$summary=$rows[1]
            if ($n.kind -cne 'negative_name' -or $n.no_file_created -isnot [bool] -or -not $n.no_file_created) {
                throw 'Malformed negative-name record'
            }
            foreach ($flag in @('missing_before','missing_after','own_appid_stable',
                    'negative_results_stable','missing_name_appid_success','appid_distinct_from_own')) {
                if ($n.$flag -isnot [bool]) {throw ('Missing/invalid flag: '+$flag)}
            }
            foreach ($key in @('lookup_code_first','lookup_code_second','own_appid_bytes','missing_name_appid_bytes')) {
                if (-not (Is-U32 $n.$key)) {throw ('Invalid DWORD/length: '+$key)}
            }
            if ($n.own_appid_bytes -lt 1 -or $n.own_appid_bytes -gt 65536 -or
                $n.missing_name_appid_bytes -gt 65536) {throw 'Invalid byte lengths'}
            if ($n.missing_name_appid_success) {
                if ($n.lookup_code_first -ne 0 -or $n.missing_name_appid_bytes -eq 0) {
                    throw 'Inconsistent successful AppId response'
                }
            } elseif ($n.lookup_code_first -eq 0 -or $n.missing_name_appid_bytes -ne 0 -or
                $n.appid_distinct_from_own) {throw 'Inconsistent rejected AppId response'}
            if ($n.negative_results_stable -and $n.lookup_code_first -ne $n.lookup_code_second) {
                throw 'Stable negative result with differing API codes'
            }
            $flags=@($n.missing_before,$n.missing_after,$n.own_appid_stable,
                $n.negative_results_stable,$n.missing_name_appid_success,$n.appid_distinct_from_own)
            $mask=0;for ($i=0;$i -lt 6;$i++) {if ($flags[$i]) {$mask=$mask -bor (1 -shl $i)}}
            $expectedExit=3;$expectedStatus='NOT_STABLE_OR_NOT_CONFIRMED_ABSENT'
            if (($mask -band 15) -eq 15) {
                if (($mask -band 16) -eq 0) {
                    $expectedExit=4;$expectedStatus='ABSENT_PATH_APPID_REJECTED_NOT_ORIGIN_PROOF'
                } elseif (($mask -band 32) -ne 0) {
                    $expectedExit=0;$expectedStatus='ABSENT_PATH_APPID_ACCEPTED_NOT_ORIGIN_PROOF'
                } else {
                    $expectedStatus='AMBIGUOUS_APPID_EQUAL_TO_OWN_IMAGE'
                }
            }
            if ($summary.kind -cne 'summary' -or $summary.status -cne $expectedStatus -or
                $summary.diagnostic_exit -isnot [int] -or $summary.diagnostic_exit -ne $expectedExit -or
                $summary.observations_mask -isnot [int] -or $summary.observations_mask -ne $mask -or
                $summary.filename_only -isnot [bool] -or -not $summary.filename_only -or
                $summary.no_wfp_policy_mutation -isnot [bool] -or -not $summary.no_wfp_policy_mutation -or
                $summary.atomic_snapshot -isnot [bool] -or $summary.atomic_snapshot -or
                $summary.absence_confirmed_before_after -isnot [bool] -or
                $summary.absence_confirmed_before_after -ne ($n.missing_before -and $n.missing_after) -or
                $r.ExitCode -ne $expectedExit) {throw 'Native summary/status/exit inconsistency'}
            $report.observations_mask=$mask
            $report.status=$expectedStatus
            $exitCode=$expectedExit
        }

    }
} catch {$report.status='UNAVAILABLE_OR_FAILED';$report.reason=$_.Exception.Message;$exitCode=2}
finally {
    $env:PATH=$oldPath;$report.finished_utc=[DateTime]::UtcNow.ToString('o')
    $report.archive=Join-Path $evidence 'evidence-only.zip'
    Save-Text 'R137_EVIDENCE.json' ($report|ConvertTo-Json -Depth 8)
    try {
        $logs=@(Get-ChildItem -LiteralPath $evidence -File|Where-Object {$_.Extension -in @('.txt','.json','.jsonl')})
        Compress-Archive -LiteralPath $logs.FullName -DestinationPath $report.archive -Force
    } catch {$report.archive=$null;$report.archive_error=$_.Exception.Message;Save-Text 'R137_EVIDENCE.json' ($report|ConvertTo-Json -Depth 8)}
    Write-Host ('R137 status: '+$report.status)
    if ($report.reason) {Write-Host ('R137 reason: '+$report.reason)}
    Write-Host ('R137 evidence: '+$evidence)
    if ($report.archive) {Write-Host ('R137 evidence ZIP: '+$report.archive)}
    Write-Host ('R137 exit code: '+$exitCode)
    Write-Host 'No file was created for the negative path. AppId-from-filename is NOT kernel-origin proof.'
}
exit $exitCode
