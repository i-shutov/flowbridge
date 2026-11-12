#requires -Version 5.1
<#
R129: compile an exact Rust blob; query only four FlowBridge filter GUIDs on opt-in.
No clone, old checkout, dependency installation, driver, filter or service change.
The ONLY download is the pinned source blob from i-shutov/flowbridge on GitHub.
Live exit codes: 2=query/close error, 3=four GET successes (NOT proof),
4=NOT_FOUND observed, 5=ACCESS_DENIED observed. No live result exits zero.
#>
[CmdletBinding()]
param(
    [string]$RustBinDirectory = (Join-Path $env:USERPROFILE '.cargo\bin'),
    [switch]$RunReadOnlyBfe,
    [switch]$CompileOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$sourceBlob = '4003a17b4213072605994427080038becd11c092'
$sourceHash = '79c50bde682125883e04effdebf51b6620526e857a6d4bf4305c363c99f97c6b'
$matrixHash = '54335b8741c0b52c0dd5d71f6e511dcf1b2f64f9356773cf21c8c9cd904f28d4'
$evidence = Join-Path ([IO.Path]::GetTempPath()) ('FlowBridge-R129-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $evidence
$utf8 = [Text.UTF8Encoding]::new($false)
$oldPath = $env:PATH
$exitCode = 2
$report = [ordered]@{
    tool='FlowBridge R129 exact-key read-only BFE diagnostic'; schema=1
    started_utc=[DateTime]::UtcNow.ToString('o'); finished_utc=$null
    evidence_directory=$evidence; status='NOT_RUN'; reason=$null
    source_blob_expected=$sourceBlob; source_sha256_expected=$sourceHash
    source_sha256_observed=$null; windows_build=$null; rustc_version=$null
    target='x86_64-pc-windows-msvc'; metadata_exit=$null; unit_tests_exit=$null
    contract_matrix_sha256=$null; inspector_sha256=$null; bfe_requested=[bool]$RunReadOnlyBfe
    bfe_exit=$null; observation_status=$null; kernel_proof=$false; no_direct_proof=$false
}
function Save-Text([string]$Name, [string]$Text) {
    [IO.File]::WriteAllText((Join-Path $evidence $Name), $Text, $utf8)
}
function Hash-Bytes([byte[]]$Bytes, [string]$Algorithm) {
    $h = [Security.Cryptography.HashAlgorithm]::Create($Algorithm)
    try { return -join ($h.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) }
    finally { $h.Dispose() }
}
function Blob-Hash([byte[]]$Bytes) {
    $header = [Text.Encoding]::ASCII.GetBytes(('blob {0}' -f $Bytes.Length) + [char]0)
    $all = New-Object byte[] ($header.Length + $Bytes.Length)
    [Array]::Copy($header, 0, $all, 0, $header.Length)
    [Array]::Copy($Bytes, 0, $all, $header.Length, $Bytes.Length)
    return Hash-Bytes $all 'SHA1'
}
function Run-Local([string]$Exe, [string[]]$Arguments, [string]$Log) {
    $quoted = @($Arguments | ForEach-Object {
        if ($_ -match '["\r\n]' -or $_.EndsWith('\')) { throw 'Unsafe native argument shape' }
        '"' + $_ + '"'
    })
    $si = [Diagnostics.ProcessStartInfo]::new()
    $si.FileName=$Exe; $si.Arguments=($quoted -join ' '); $si.WorkingDirectory=$evidence
    $si.UseShellExecute=$false; $si.CreateNoWindow=$true
    $si.RedirectStandardOutput=$true; $si.RedirectStandardError=$true
    $p=[Diagnostics.Process]::new(); $p.StartInfo=$si
    try {
        if (-not $p.Start()) { throw ('Cannot start ' + $Exe) }
        $stdout=$p.StandardOutput.ReadToEndAsync(); $stderr=$p.StandardError.ReadToEndAsync()
        $p.WaitForExit()
        $text=$stdout.GetAwaiter().GetResult(); $err=$stderr.GetAwaiter().GetResult()
        Save-Text ($Log + '.stdout.txt') $text; Save-Text ($Log + '.stderr.txt') $err
        return [pscustomobject]@{ExitCode=$p.ExitCode; Output=$text; ErrorOutput=$err}
    } finally { $p.Dispose() }
}
function Is-U32($Value) {
    return (($Value -is [int] -or $Value -is [long] -or $Value -is [uint32] -or $Value -is [uint64]) -and
            [decimal]$Value -ge 0 -and [decimal]$Value -le 4294967295)
}
function Observation([uint32]$Code, [bool]$Pointer) {
    if ($Code -eq 0) { if ($Pointer) { return 'FOUND_BY_KEY' }; return 'INVALID_API_RESULT' }
    if ($Pointer) { return 'INVALID_API_RESULT' }
    if ($Code -eq [uint32]2150760451) { return 'NOT_FOUND_RETURNED' }
    if ($Code -eq 5) { return 'ACCESS_DENIED_RETURNED' }
    return 'OTHER_API_ERROR'
}
try {
    if ($CompileOnly -and $RunReadOnlyBfe) { throw '-CompileOnly cannot be combined with -RunReadOnlyBfe' }
    if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or
        -not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
        throw 'Requires native Windows x86_64 PowerShell; ARM64/emulation is not accepted'
    }
    $os=Get-CimInstance Win32_OperatingSystem
    $report.windows_build=('{0} / {1} / {2}' -f $os.Caption,$os.Version,$os.BuildNumber)
    if (Test-Path -LiteralPath $RustBinDirectory -PathType Container) {
        $env:PATH=$RustBinDirectory + ';' + $env:PATH
    }
    $rust=Get-Command rustc.exe -CommandType Application -ErrorAction Stop
    $info=Run-Local $rust.Source @('-vV') 'rustc-version'
    if ($info.ExitCode -ne 0 -or $info.Output -notmatch '(?m)^host:\s*x86_64-pc-windows-msvc\s*$') {
        throw 'Existing rustc must target native x86_64-pc-windows-msvc; nothing installed'
    }
    $report.rustc_version=$info.Output.Trim()
    $local=Join-Path $PSScriptRoot 'r129_filter_get_by_key.rs'
    $needDownload=$true
    if (Test-Path -LiteralPath $local -PathType Leaf) {
        [byte[]]$bytes=[IO.File]::ReadAllBytes($local)
        $needDownload=((Hash-Bytes $bytes 'SHA256') -cne $sourceHash -or (Blob-Hash $bytes) -cne $sourceBlob)
        if ($needDownload) { Write-Host 'Local source bytes differ (possibly CRLF); reading exact Git object instead.' }
    }
    if ($needDownload) {
        $uri='https://api.github.com/repos/i-shutov/flowbridge/git/blobs/' + $sourceBlob
        $response=Invoke-WebRequest -UseBasicParsing -Uri $uri -Headers @{'User-Agent'='FlowBridge-R129-SourceFetch'}
        $blob=$response.Content | ConvertFrom-Json
        if ($blob.sha -cne $sourceBlob -or $blob.encoding -cne 'base64') { throw 'Unexpected GitHub blob response' }
        [byte[]]$bytes=[Convert]::FromBase64String($blob.content)
    }
    $report.source_sha256_observed=Hash-Bytes $bytes 'SHA256'
    if ((Blob-Hash $bytes) -cne $sourceBlob -or $report.source_sha256_observed -cne $sourceHash) {
        throw 'Source byte attestation failed; no compile or BFE query attempted'
    }
    $source=Join-Path $evidence 'r129_filter_get_by_key.rs'
    [IO.File]::WriteAllBytes($source,$bytes)
    Write-Host ('Exact R129 source: ' + $sourceBlob)
    $meta=Join-Path $evidence 'r129.rmeta'
    $r=Run-Local $rust.Source @('--edition=2021','--target','x86_64-pc-windows-msvc','--emit=metadata',$source,'-o',$meta) 'metadata'
    $report.metadata_exit=$r.ExitCode
    if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $meta)) { throw 'Rust metadata compilation failed; see metadata.stderr.txt' }
    $report.status='METADATA_COMPILED_ONLY'; $exitCode=0
    if (-not $CompileOnly) {
        $tests=Join-Path $evidence 'r129-tests.exe'
        $r=Run-Local $rust.Source @('--edition=2021','--target','x86_64-pc-windows-msvc','--test',$source,'-o',$tests) 'test-build'
        if ($r.ExitCode -ne 0) { throw 'Rust test linking failed; see test-build.stderr.txt' }
        $r=Run-Local $tests @('--test-threads=1') 'unit-tests'
        $report.unit_tests_exit=$r.ExitCode
        if ($r.ExitCode -ne 0) { throw 'Rust unit tests failed; see unit-tests.stdout.txt' }
        $exe=Join-Path $evidence 'r129-by-key.exe'
        $r=Run-Local $rust.Source @('--edition=2021','--target','x86_64-pc-windows-msvc',$source,'-o',$exe) 'inspector-build'
        if ($r.ExitCode -ne 0) { throw 'Rust inspector linking failed; see inspector-build.stderr.txt' }
        $report.inspector_sha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
        $r=Run-Local $exe @('--contract-matrix') 'contract-matrix'
        $matrix=$r.Output.Replace("`r`n","`n")
        $report.contract_matrix_sha256=Hash-Bytes ([Text.Encoding]::UTF8.GetBytes($matrix)) 'SHA256'
        if ($r.ExitCode -ne 0 -or $report.contract_matrix_sha256 -cne $matrixHash) { throw 'Native Rust model differs from the independent offline oracle' }
        $report.status='NATIVE_SYNTHETIC_PASS_NOT_KERNEL_PROOF'
        if ($RunReadOnlyBfe) {
            $r=Run-Local $exe @('--read-only-bfe') 'bfe-by-key'
            $report.bfe_exit=$r.ExitCode; $exitCode=2
            Save-Text 'bfe-by-key.jsonl' $r.Output
            Write-Host $r.Output
            $lines=@($r.Output -split '\r?\n' | Where-Object { $_.Trim().Length -gt 0 })
            $records=@($lines | ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop })
            foreach ($item in $records) {
                if ($item.schema -isnot [int] -or $item.schema -ne 1 -or
                    $item.kernel_proof -isnot [bool] -or $item.kernel_proof -or
                    $item.no_direct_proof -isnot [bool] -or $item.no_direct_proof) { throw 'Invalid JSON proof boundary' }
            }
            if ($records.Count -eq 1 -and $records[0].status -ceq 'OPEN_ERROR' -and $r.ExitCode -eq 2) {
                throw ('BFE open returned ' + $records[0].api_code_hex + '; no filter queries made')
            }
            if ($r.ErrorOutput.Trim().Length -ne 0 -or $records.Count -ne 5) { throw 'Expected exactly four filter rows and one summary' }
            $labels=@('auth_connect_v4','auth_connect_v6','connect_redirect_v4','connect_redirect_v6')
            $observations=@()
            for ($i=0;$i -lt 4;$i++) {
                $item=$records[$i]; $wantKey='1649f03' + $i + '-25b3-4e01-9ca1-5ca803010019'
                if ($item.kind -cne 'filter' -or $item.rule -cne $labels[$i] -or $item.key -cne $wantKey -or
                    -not (Is-U32 $item.api_code) -or $item.pointer_present -isnot [bool]) { throw 'Invalid filter row / key / API code' }
                $obs=Observation ([uint32]$item.api_code) $item.pointer_present
                if ($item.observation -cne $obs -or $item.api_code_hex -cne ('0x{0:X8}' -f [uint32]$item.api_code)) { throw 'API result interpretation mismatch' }
                $observations += $obs
            }
            $last=$records[4]
            if (-not (Is-U32 $last.close_code)) { throw 'Invalid close code' }
            $expectedExit=3; $expectedStatus='ALL_FOUR_GETS_SUCCEEDED_NOT_PROOF'
            if ($last.close_code -ne 0 -or $observations -contains 'OTHER_API_ERROR' -or $observations -contains 'INVALID_API_RESULT') {
                $expectedExit=2; $expectedStatus='QUERY_OR_CLOSE_ERROR'
            } elseif ($observations -contains 'ACCESS_DENIED_RETURNED') {
                $expectedExit=5; $expectedStatus='ACCESS_DENIED_OBSERVED'
            } elseif ($observations -contains 'NOT_FOUND_RETURNED') {
                $expectedExit=4; $expectedStatus='NOT_FOUND_OBSERVED'
            }
            if ($last.kind -cne 'summary' -or $last.status -cne $expectedStatus -or
                $last.queries -isnot [int] -or $last.queries -ne 4 -or
                $last.diagnostic_exit -isnot [int] -or $last.diagnostic_exit -ne $expectedExit -or
                $last.close_code_hex -cne ('0x{0:X8}' -f [uint32]$last.close_code) -or
                $last.atomic_snapshot -isnot [bool] -or $last.atomic_snapshot -or $r.ExitCode -ne $expectedExit) {
                throw 'Terminal JSON/exit mismatch'
            }
            $report.observation_status=$expectedStatus
            $report.status='READONLY_DIAGNOSTIC_COMPLETED_NOT_PROOF'
            $exitCode=$expectedExit
        }
    }
} catch {
    $report.status='UNAVAILABLE_OR_FAILED'; $report.reason=$_.Exception.Message; $exitCode=2
} finally {
    $env:PATH=$oldPath
    $report.finished_utc=[DateTime]::UtcNow.ToString('o')
    Save-Text 'R129_EVIDENCE.json' ($report | ConvertTo-Json -Depth 6)
    Write-Host ('R129 status: ' + $report.status)
    if ($report.reason) { Write-Host ('R129 reason: ' + $report.reason) }
    Write-Host ('R129 evidence: ' + $evidence)
    Write-Host ('R129 exit code: ' + $exitCode)
}
exit $exitCode
