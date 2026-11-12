#requires -Version 5.1
<#
R133: existing Rust compiler; read-only process queries for TWO own helper children.
Default: compile and synthetic tests only. -RunOwnChildProbe explicitly spawns
this freshly compiled executable twice and queries its retained process handles.
No BFE, sockets, drivers, filters, service/security/configuration changes.
The only download is an immutable Rust source blob from i-shutov/flowbridge.
#>
[CmdletBinding()]
param(
    [string]$RustBinDirectory = (Join-Path $env:USERPROFILE '.cargo\bin'),
    [string]$OfflineSource = '',
    [switch]$RunOwnChildProbe,
    [switch]$CompileOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$sourceBlob = '32736365059885ed9137bd124edeecbc27c49446'
$sourceHash = '2324c17e85826b72c9d2a93ec39cc5ba46b60187302da3d2bcf1ad691c5cad83'
$matrixHash = '9c7a1ee3052a06be99b03e0475b2cc00a08da565aa221bee4d5166649f0126dd'
$evidence = Join-Path ([IO.Path]::GetTempPath()) ('FlowBridge-R133-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $evidence
$utf8 = [Text.UTF8Encoding]::new($false)
$oldPath = $env:PATH
$exitCode = 2
$report = [ordered]@{
    schema=1; tool='FlowBridge R133 own-child handle lifetime'; status='NOT_RUN'; reason=$null
    started_utc=[DateTime]::UtcNow.ToString('o'); finished_utc=$null; evidence_directory=$evidence
    source_blob_expected=$sourceBlob; source_sha256_expected=$sourceHash; source_sha256_observed=$null
    target='x86_64-pc-windows-msvc'; windows_build=$null; rustc_version=$null
    metadata_exit=$null; unit_tests_exit=$null; listed_tests=$null; test_exe_sha256=$null
    inspector_sha256=$null; gate_matrix_sha256=$null; native_probe_requested=[bool]$RunOwnChildProbe
    native_probe_exit=$null; cases=$null; archive=$null; archive_error=$null
    bfe_queried=$false; kernel_origin_proof=$false; network_owner_proof=$false
    canonical_file_identity_proof=$false; pid_reuse_test_performed=$false; no_direct_proof=$false
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
function Is-U32($Value) {
    return (($Value -is [int] -or $Value -is [long] -or $Value -is [uint32] -or $Value -is [uint64]) -and
        [decimal]$Value -ge 0 -and [decimal]$Value -le 4294967295)
}
function Is-TimeHex($Value) {
    return ($Value -is [string] -and $Value -cmatch '^[0-9A-F]{16}$' -and $Value -cne '0000000000000000')
}
function Is-NameHex($Value) {
    if ($Value -isnot [string] -or $Value.Length -gt 131068 -or $Value -cnotmatch '^(?:[0-9A-F]{4})+$') {return $false}
    for ($j=0;$j -lt $Value.Length;$j+=4) {if ($Value.Substring($j,4) -ceq '0000') {return $false}}
    return $true
}
try {
    if ($CompileOnly -and $RunOwnChildProbe) {throw 'CompileOnly cannot run the native probe'}
    if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or -not [Environment]::Is64BitProcess -or
        $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {throw 'Requires native Windows x86_64 PowerShell'}
    $os=Get-CimInstance Win32_OperatingSystem
    $report.windows_build=('{0} / {1} / {2}' -f $os.Caption,$os.Version,$os.BuildNumber)
    if (Test-Path -LiteralPath $RustBinDirectory -PathType Container) {$env:PATH=$RustBinDirectory+';'+$env:PATH}
    $rust=Get-Command rustc.exe -CommandType Application -ErrorAction Stop
    $r=Run-Local $rust.Source @('-vV') 'rustc-version'
    if ($r.ExitCode -ne 0 -or $r.Output -notmatch '(?m)^host:\s*x86_64-pc-windows-msvc\s*$') {throw 'Existing native x86_64 MSVC Rust required; no installation attempted'}
    $report.rustc_version=$r.Output.Trim()
    if (-not [string]::IsNullOrWhiteSpace($OfflineSource)) {
        [byte[]]$bytes=[IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $OfflineSource).Path)
    } else {
        $uri='https://api.github.com/repos/i-shutov/flowbridge/git/blobs/'+$sourceBlob
        $response=Invoke-WebRequest -UseBasicParsing -Uri $uri -Headers @{'User-Agent'='FlowBridge-R133-SourceFetch'}
        $blob=$response.Content | ConvertFrom-Json
        if ($blob.sha -cne $sourceBlob -or $blob.encoding -cne 'base64') {throw 'Unexpected GitHub blob response'}
        [byte[]]$bytes=[Convert]::FromBase64String($blob.content)
    }
    $report.source_sha256_observed=Hash-Bytes $bytes 'SHA256'
    if ((Blob-Hash $bytes) -cne $sourceBlob -or $report.source_sha256_observed -cne $sourceHash) {throw 'Exact-source attestation failed; no normalization or bypass'}
    $source=Join-Path $evidence 'r133_owned_process_lifetime.rs'
    [IO.File]::WriteAllBytes($source,$bytes)
    Write-Host ('Exact R133 source: '+$sourceBlob)
    $meta=Join-Path $evidence 'r133.rmeta'
    $r=Run-Local $rust.Source @('--edition=2021','--target',$report.target,'--emit=metadata',$source,'-o',$meta) 'metadata'
    $report.metadata_exit=$r.ExitCode
    if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $meta)) {throw 'Windows-gated source typecheck failed; see metadata.stderr.txt'}
    $report.status='WINDOWS_METADATA_ONLY';$exitCode=0
    if (-not $CompileOnly) {
        $test=Join-Path $evidence 'r133-tests.exe'
        $r=Run-Local $rust.Source @('--edition=2021','--target',$report.target,'--test',$source,'-o',$test) 'test-build'
        if ($r.ExitCode -ne 0) {throw 'Synthetic-test link failed; see test-build.stderr.txt'}
        $report.test_exe_sha256=(Get-FileHash -LiteralPath $test -Algorithm SHA256).Hash.ToLowerInvariant()
        $list=Run-Local $test @('--list','--format=terse') 'test-list'
        $names=@($list.Output -split '\r?\n' | Where-Object {$_ -match '^tests::.+: test$'})
        $report.listed_tests=$names.Count
        if ($list.ExitCode -ne 0 -or $names.Count -ne 16 -or @($names|Select-Object -Unique).Count -ne 16) {throw 'Unexpected synthetic test list'}
        $r=Run-Local $test @('--test-threads=1') 'unit-tests'
        $report.unit_tests_exit=$r.ExitCode;Write-Host $r.Output
        if ($r.ExitCode -ne 0 -or $r.Output -notmatch 'test result: ok\. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;') {throw 'Synthetic tests did not pass exactly 16/16'}
        $exe=Join-Path $evidence 'r133-process-lifetime.exe'
        $r=Run-Local $rust.Source @('--edition=2021','--target',$report.target,$source,'-o',$exe) 'probe-build'
        if ($r.ExitCode -ne 0) {throw 'Native probe link failed; see probe-build.stderr.txt'}
        $report.inspector_sha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
        $r=Run-Local $exe @('--gate-matrix') 'gate-matrix'
        $text=$r.Output.Replace("`r`n","`n")
        $report.gate_matrix_sha256=Hash-Bytes ([Text.Encoding]::ASCII.GetBytes($text)) 'SHA256'
        if ($r.ExitCode -ne 0 -or $r.ErrorOutput.Trim().Length -ne 0 -or $report.gate_matrix_sha256 -cne $matrixHash) {throw 'Rust wait/exit contract differs from independent oracle'}
        $report.status='NATIVE_SYNTHETIC_PASS_ONLY'
        if ($RunOwnChildProbe) {
            $r=Run-Local $exe @('--own-child-probe') 'process-lifetime'
            $report.native_probe_exit=$r.ExitCode
            Save-Text 'process-lifetime.jsonl' $r.Output
            Write-Host $r.Output
            if ($r.ExitCode -ne 0 -or $r.ErrorOutput.Trim().Length -ne 0) {throw 'Native own-child probe failed; see process-lifetime.jsonl and stderr'}
            $lines=@($r.Output -split '\r?\n' | Where-Object {$_.Trim().Length -gt 0})
            if ($lines.Count -ne 5) {throw 'Expected four lifecycle rows and one summary'}
            $records=@($lines|ForEach-Object {$_|ConvertFrom-Json -ErrorAction Stop})
            foreach ($item in $records) {
                if ($item.schema -isnot [int] -or $item.schema -ne 1) {throw 'Invalid schema'}
                foreach ($flag in @('kernel_origin_proof','network_owner_proof','no_direct_proof')) {
                    if ($item.$flag -isnot [bool] -or $item.$flag) {throw ('Invalid proof boundary: '+$flag)}
                }
            }
            for ($i=0;$i -lt 2;$i++) {
                $a=$records[2*$i];$d=$records[2*$i+1];$wanted=@(23,259)[$i]
                foreach ($item in @($a,$d)) {
                    if ($item.case -isnot [int] -or $item.case -ne $i -or -not (Is-U32 $item.pid) -or $item.pid -eq 0 -or
                        -not (Is-U32 $item.planned_exit) -or $item.planned_exit -ne $wanted -or
                        -not (Is-U32 $item.get_exit_code) -or -not (Is-TimeHex $item.creation_filetime_hex) -or
                        $item.secondary_matches -isnot [bool] -or -not $item.secondary_matches) {throw 'Invalid case identity/result types'}
                }
                if ($a.kind -cne 'alive' -or $d.kind -cne 'exited' -or
                    -not (Is-U32 $a.wait_before) -or $a.wait_before -ne 258 -or
                    -not (Is-U32 $a.wait_after) -or $a.wait_after -ne 258 -or $a.get_exit_code -ne 259 -or
                    -not (Is-NameHex $a.win32_name_utf16_hex) -or -not (Is-NameHex $a.native_name_utf16_hex) -or
                    -not (Is-U32 $d.wait_result) -or $d.wait_result -ne 0 -or $d.get_exit_code -ne $wanted -or
                    $d.pid -ne $a.pid -or $d.creation_filetime_hex -cne $a.creation_filetime_hex -or
                    -not (Is-TimeHex $d.exit_filetime_hex) -or $d.same_held_handles -isnot [bool] -or -not $d.same_held_handles) {
                    throw 'Inconsistent live/exit observations or unstable retained identity'
                }
            }
            $s=$records[4]
            if ($s.kind -cne 'summary' -or $s.status -cne 'OWN_CHILD_HANDLE_LIFETIME_PASS_NOT_NETWORK_PROOF' -or
                $s.cases -isnot [int] -or $s.cases -ne 2 -or -not (Is-U32 $s.readonly_open_rights) -or
                $s.readonly_open_rights -ne 1052672 -or $s.exit259_is_signaled -isnot [bool] -or -not $s.exit259_is_signaled) {throw 'Invalid terminal observation'}
            foreach ($flag in @('pid_reuse_test_performed','canonical_file_identity_proof','atomic_snapshot')) {
                if ($s.$flag -isnot [bool] -or $s.$flag) {throw ('Unsupported terminal proof: '+$flag)}
            }
            $report.cases=2;$report.status=$s.status
        }
    }
} catch {
    $report.status='UNAVAILABLE_OR_FAILED';$report.reason=$_.Exception.Message;$exitCode=2
} finally {
    $env:PATH=$oldPath
    $report.finished_utc=[DateTime]::UtcNow.ToString('o')
    $report.archive=Join-Path $evidence 'evidence-only.zip'
    Save-Text 'R133_EVIDENCE.json' ($report|ConvertTo-Json -Depth 8)
    try {
        $logs=@(Get-ChildItem -LiteralPath $evidence -File|Where-Object {$_.Extension -in @('.txt','.json','.jsonl')})
        Compress-Archive -LiteralPath $logs.FullName -DestinationPath $report.archive -Force
    } catch {$report.archive=$null;$report.archive_error=$_.Exception.Message;Save-Text 'R133_EVIDENCE.json' ($report|ConvertTo-Json -Depth 8)}
    Write-Host ('R133 status: '+$report.status)
    if ($report.reason) {Write-Host ('R133 reason: '+$report.reason)}
    Write-Host ('R133 evidence: '+$evidence)
    if ($report.archive) {Write-Host ('R133 evidence ZIP: '+$report.archive)}
    Write-Host ('R133 exit code: '+$exitCode)
    Write-Host 'Own-child identity/lifetime only. No BFE/socket/driver/filter or network-origin proof.'
}
exit $exitCode
