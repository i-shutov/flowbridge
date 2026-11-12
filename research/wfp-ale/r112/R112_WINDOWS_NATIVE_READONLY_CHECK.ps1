#requires -Version 5.1
<#
  R112: native Windows x64 Rust compile + synthetic ABI unit tests.
  Default behavior: metadata-only compilation. No network, no installation,
  no Windows settings, no BFE calls. -RunUnitTests links and executes Rust
  synthetic user-mode tests. -RunReadOnlyBfe additionally performs a BFE
  read-only enumeration; this is NOT a kernel/no-DIRECT proof.
  Never run on an unapproved machine; no system rescue/VNC/driver activity.
#>
[CmdletBinding()]
param(
    [string]$Source = (Join-Path $PSScriptRoot '..\r103\r103_readonly_arbitration_inventory.rs'),
    [switch]$RunUnitTests,
    [switch]$RunReadOnlyBfe
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedGitBlob = '49506ca07145c18947a0845f2a1a63b3de1f54ec'
$evidence = Join-Path ([IO.Path]::GetTempPath()) ('FlowBridge-R112-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $evidence -ErrorAction Stop
$report = [ordered]@{
    tool = 'FlowBridge WFP/ALE R112 compiler-only audit'
    evidence_directory = $evidence
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    research_source_git_blob_expected = $expectedGitBlob
    source_git_blob_observed = $null
    source_sha256 = $null
    source_compilation_sha256 = $null
    source_crlf_normalized = $false
    source_normalized_git_blob = $null
    windows_build = $null
    rustc_version = $null
    rustc_target = $null
    windows_sdk_header = $null
    metadata_compile_exit_code = $null
    unit_tests_exit_code = $null
    unit_test_exe_sha256 = $null
    inspector_sha256 = $null
    bfe_inventory_requested = [bool]$RunReadOnlyBfe
    bfe_inventory_exit_code = $null
    kernel_origin_proof = $false
    continuous_enforcement_proof = $false
    no_direct_proof = $false
    status = 'UNKNOWN'
    reason = $null
}
function Write-Evidence([string]$Name, [string]$Content) {
    $dest = Join-Path $evidence $Name
    [IO.File]::WriteAllText($dest, $Content, [Text.UTF8Encoding]::new($false))
}
function Git-BlobSha1([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $header = [Text.Encoding]::ASCII.GetBytes(('blob {0}' -f $bytes.Length) + [char]0)
    $payload = New-Object byte[] ($header.Length + $bytes.Length)
    [Array]::Copy($header, 0, $payload, 0, $header.Length)
    [Array]::Copy($bytes, 0, $payload, $header.Length, $bytes.Length)
    $hasher = [Security.Cryptography.SHA1]::Create()
    try { return -join ($hasher.ComputeHash($payload) | ForEach-Object { $_.ToString('x2') }) }
    finally { $hasher.Dispose() }
}
function Invoke-Local([string]$Exe, [string[]]$Parameters, [string]$LogName) {
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'   # PS 5.1 treats some native stderr as a non-terminating error
    try {
        $output = & $Exe @Parameters 2>&1 | Out-String
        $status = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $oldPreference }
    Write-Evidence $LogName $output
    return [pscustomobject]@{ ExitCode = [int]$status; Output = $output }
}
$exitStatus = 2
try {
    if ($RunReadOnlyBfe -and -not $RunUnitTests) {
        throw '-RunReadOnlyBfe requires -RunUnitTests (cannot skip ABI tests)'
    }
    if (-not [Environment]::Is64BitOperatingSystem -or [Environment]::OSVersion.Platform -ne 'Win32NT') {
        throw 'Requires an authorized Windows x64 host'
    }
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $report.windows_build = ('{0} / {1} / {2}' -f $os.Caption, $os.Version, $os.BuildNumber)
    $resolved = (Resolve-Path -LiteralPath $Source -ErrorAction Stop).Path
    $report.source_git_blob_observed = Git-BlobSha1 $resolved
    $report.source_sha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($report.source_git_blob_observed -ne $expectedGitBlob) {
        # The checkout can expand LF into CRLF (core.autocrlf). Never treat
        # git hash-object's clean-filter result as a hash of raw source bytes.
        # Accept only a byte-preserving CRLF -> LF transform that produces the
        # *exact* pinned Git blob; compile those verified canonical bytes.
        $originalBytes = [IO.File]::ReadAllBytes($resolved)
        $canonicalPath = Join-Path $evidence 'r115-canonical-source.rs'
        $stream = New-Object System.IO.MemoryStream
        try {
            for ($i = 0; $i -lt $originalBytes.Length; $i++) {
                if ($originalBytes[$i] -eq 13 -and ($i + 1) -lt $originalBytes.Length -and
                    $originalBytes[$i + 1] -eq 10) { continue }
                $stream.WriteByte($originalBytes[$i])
            }
            [IO.File]::WriteAllBytes($canonicalPath, $stream.ToArray())
        }
        finally { $stream.Dispose() }
        $normalizedBlob = Git-BlobSha1 $canonicalPath
        $report.source_normalized_git_blob = $normalizedBlob
        if ($normalizedBlob -ne $expectedGitBlob) {
            throw 'Source Git blob mismatch after exact CRLF normalization: refuse unverified source'
        }
        $resolved = $canonicalPath
        $report.source_crlf_normalized = $true
    }
    $report.source_compilation_sha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    $rust = Get-Command rustc.exe -ErrorAction SilentlyContinue
    if ($null -eq $rust) { throw 'rustc.exe not installed: no installation attempted' }
    $rustInfo = Invoke-Local $rust.Source @('-vV') 'rustc-version.txt'
    $report.rustc_version = $rustInfo.Output.Trim()
    if ($rustInfo.ExitCode -ne 0) { throw 'rustc -vV failed' }
    $match = [regex]::Match($rustInfo.Output, '(?m)^host:\s*(x86_64-pc-windows-(?:msvc|gnu))\s*$')
    if (-not $match.Success) { throw 'Native Rust host target is not Windows x86_64' }
    $report.rustc_target = $match.Groups[1].Value
    $sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Include'
    if (Test-Path -LiteralPath $sdkRoot -PathType Container) {
        $header = Get-ChildItem -LiteralPath $sdkRoot -Recurse -Filter 'fwpmtypes.h' -File -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($null -ne $header) { $report.windows_sdk_header = $header.FullName }
    }
    # No link, no DLL, no WFP APIs: compiler typechecks the real Windows-gated Rust source.
    $metadata = Join-Path $evidence 'r112.rmeta'
    $compile = Invoke-Local $rust.Source @('--edition=2021', '--crate-type=bin', '--emit=metadata',
        '--target', $report.rustc_target, $resolved, '-o', $metadata) 'rustc-metadata.log'
    $report.metadata_compile_exit_code = $compile.ExitCode
    if ($compile.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $metadata)) {
        throw 'Rust Windows metadata compilation failed; see rustc-metadata.log'
    }
    $report.status = 'WINDOWS_METADATA_COMPILED_ONLY'
    $exitStatus = 0
    if ($RunUnitTests) {
        # Linking unit tests requires an existing MSVC/MinGW + Windows SDK setup.
        # This script NEVER installs either toolchain.
        $unitBin = Join-Path $evidence 'r112-synthetic-tests.exe'
        $buildTests = Invoke-Local $rust.Source @('--edition=2021', '--test', '--target',
            $report.rustc_target, $resolved, '-o', $unitBin) 'rustc-test-link.log'
        if ($buildTests.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $unitBin)) {
            throw 'Rust Windows synthetic-test linking failed; no toolchain changes attempted'
        }
        $report.unit_test_exe_sha256 = (Get-FileHash -LiteralPath $unitBin -Algorithm SHA256).Hash.ToLowerInvariant()
        $test = Invoke-Local $unitBin @('--test-threads=1') 'rust-synthetic-tests.log'
        $report.unit_tests_exit_code = $test.ExitCode
        if ($test.ExitCode -ne 0) { throw 'Rust Windows synthetic-test runtime failure' }
        $report.status = 'WINDOWS_RUST_SYNTHETIC_TESTS_PASS_NOT_KERNEL_PROOF'
        if ($RunReadOnlyBfe) {
            # Explicit opt-in only. The source has only WFP read-only management calls.
            $inspector = Join-Path $evidence 'r112-readonly-inventory.exe'
            $build = Invoke-Local $rust.Source @('--edition=2021','--target',
                $report.rustc_target,$resolved,'-o',$inspector) 'rustc-inspector-link.log'
            if ($build.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $inspector)) {
                throw 'Read-only inspector link failed; no BFE access attempted'
            }
            $report.inspector_sha256 = (Get-FileHash -LiteralPath $inspector -Algorithm SHA256).Hash.ToLowerInvariant()
            $inventory = Invoke-Local $inspector @() 'bfe-readonly-inventory.jsonl'
            $report.bfe_inventory_exit_code = $inventory.ExitCode
            # Inspector contract: 2=UNKNOWN/management failure, 3=visible
            # arbitration candidate, 4=no visible candidate (still UNKNOWN).
            # Never report exit 0 after attempting live BFE enumeration.
            if ($inventory.ExitCode -eq 2) {
                throw 'BFE management query returned UNKNOWN/error; see bfe-readonly-inventory.jsonl'
            }
            if ($inventory.ExitCode -ne 3 -and $inventory.ExitCode -ne 4) {
                throw ('Unexpected BFE inspector exit code: ' + $inventory.ExitCode)
            }
            # Require exactly four per-rule JSON records plus one terminal JSON.
            # Do not classify an arbitrary command response as a valid snapshot.
            $lines = @($inventory.Output -split '\r?\n' | Where-Object { $_.Trim().Length -gt 0 })
            if ($lines.Count -ne 5) { throw 'Malformed BFE inventory: expected 5 JSONL records' }
            $labels = @('auth_connect_v4','auth_connect_v6',
                        'connect_redirect_v4','connect_redirect_v6')
            # R114: PowerShell's [ValueType] includes Boolean and floating point.
            # The Rust inspector serializes u64 integer counters only, <= 131072
            # visible snapshot entries; neither booleans nor fractions are evidence.
            $candidate = $false
            [long]$totalForeign = 0
            for ($i = 0; $i -lt 4; $i++) {
                $item = $lines[$i] | ConvertFrom-Json -ErrorAction Stop
                if ($item.rule -isnot [string] -or $item.rule -cne $labels[$i] -or
                    $item.match_and_runtime_action_unverified -isnot [bool] -or
                    $item.match_and_runtime_action_unverified -cne $true) {
                    throw 'Malformed BFE inventory: rule or proof boundary mismatch'
                }
                foreach ($key in @('visible_higher','visible_equal','visible_lower','visible_disabled')) {
                    $value = $item.$key
                    if (($value -isnot [int] -and $value -isnot [long]) -or
                        $value -lt 0 -or $value -gt 131072) {
                        throw ('Malformed BFE inventory integer counter: ' + $key)
                    }
                    $totalForeign += [long]$value
                }
                # R123: UNKNOWN redirect callouts can CONTINUE to lower same-sublayer filters.
                if ($item.visible_higher -gt 0 -or $item.visible_equal -gt 0 -or
                    ($i -ge 2 -and $item.visible_lower -gt 0)) {
                    $candidate = $true
                }
            }
            $terminal = $lines[4] | ConvertFrom-Json -ErrorAction Stop
            # Four owned baselines must be present and each foreign filter is
            # counted at most once: four disjoint ALE layers, one layer/filter.
            if (($terminal.visible_filters -isnot [int] -and
                 $terminal.visible_filters -isnot [long]) -or
                $terminal.visible_filters -lt 4 -or
                $terminal.visible_filters -gt 131072 -or
                $totalForeign -gt ([long]$terminal.visible_filters - 4)) {
                throw 'Inconsistent BFE snapshot counter cardinality'
            }
            foreach ($flag in @('single_enum_snapshot','acl_hidden_filters_possible',
                                'kernel_proof','no_direct_proof')) {
                if ($terminal.$flag -isnot [bool]) {
                    throw ('Malformed BFE terminal boolean: ' + $flag)
                }
            }
            $expectedStatus = if ($candidate) {'VISIBLE_ARBITRATION_CANDIDATE'}
                              else {'UNKNOWN_NO_VISIBLE_CANDIDATE'}
            $expectedExit = if ($candidate) {3} else {4}
            if ($terminal.status -isnot [string] -or
                $terminal.status -cne $expectedStatus -or
                $inventory.ExitCode -ne $expectedExit -or
                $terminal.single_enum_snapshot -cne $true -or
                $terminal.acl_hidden_filters_possible -cne $true -or
                $terminal.kernel_proof -cne $false -or
                $terminal.no_direct_proof -cne $false) {
                throw 'Inconsistent BFE terminal JSON / exit code / proof boundary'
            }
            $report.status = if ($candidate) {'BFE_VISIBLE_ARBITRATION_CANDIDATE_NO_KERNEL_PROOF'}
                             else {'BFE_UNKNOWN_NO_VISIBLE_CANDIDATE'}
            $exitStatus = $expectedExit   # Both results are NON-GO and NON-ZERO.
        }
    }
}
catch {
    $report.status = 'UNAVAILABLE_OR_FAILED'
    $report.reason = $_.Exception.Message
    $exitStatus = 2
}
finally {
    $report.timestamp_finished_utc = [DateTime]::UtcNow.ToString('o')
    Write-Evidence 'R112_WINDOWS_EVIDENCE.json' ($report | ConvertTo-Json -Depth 8)
    Write-Output ('R112 status: ' + $report.status)
    Write-Output ('R112 evidence: ' + $evidence)
    Write-Output ('R112 exit code: ' + $exitStatus)
}
exit $exitStatus
