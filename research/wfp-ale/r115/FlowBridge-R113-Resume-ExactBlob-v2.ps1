#requires -Version 5.1
<#
FlowBridge WFP/ALE R113: RESUME the already-pinned checkout, without cloning.
Fixes Windows core.autocrlf checkout bytes vs. raw Git blob SHA1 mismatch.
No Git ref changes, Windows settings, install, driver, callout/filter writes,
service/CI/runner/VNC operations. Rust/SDK must already be installed.
By default builds metadata, runs synthetic Rust tests and READ-ONLY BFE inventory.
-CompileOnly limits operation to Rust metadata compilation (no BFE calls).
-SkipReadOnlyBfe runs Rust synthetic tests but does not query BFE.
A BFE result is never proof of kernel origin or no-DIRECT.
#>
[CmdletBinding()]
param(
    [string]$CheckoutDirectory,
    [string]$RustBinDirectory,
    [switch]$CompileOnly,
    [switch]$SkipReadOnlyBfe
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$PinnedCommit = 'e24f3c2d866e9374e8873ecdab325dd7b06049ee'
$ExpectedSource = '49506ca07145c18947a0845f2a1a63b3de1f54ec'
$ExpectedHarness = '6cab4c1e8aee20506bb3ba9ae17cf348ec19b7df'
$SourceGitPath = 'research/wfp-ale/r103/r103_readonly_arbitration_inventory.rs'
$HarnessGitPath = 'research/wfp-ale/r112/R112_WINDOWS_NATIVE_READONLY_CHECK.ps1'
$exitCode = 2
$EvidenceDirectory = $null

function Invoke-VerifiedGit {
    param([string[]]$GitArguments)
    $before = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = (& $script:GitExe @GitArguments 2>&1 | Out-String).Trim()
        $rc = [int]$LASTEXITCODE
    }
    finally { $ErrorActionPreference = $before }
    if ($rc -ne 0) {
        throw ('git exit={0}: git {1} | {2}' -f $rc, ($GitArguments -join ' '), $output)
    }
    return $output
}

function Get-RawGitBlobSha1 {
    param([string]$FilePath)
    [byte[]]$body = [IO.File]::ReadAllBytes($FilePath)
    [byte[]]$header = [Text.Encoding]::ASCII.GetBytes(('blob ' + $body.Length) + [char]0)
    [byte[]]$data = New-Object byte[] ($header.Length + $body.Length)
    [Array]::Copy($header, 0, $data, 0, $header.Length)
    [Array]::Copy($body, 0, $data, $header.Length, $body.Length)
    $sha1 = [Security.Cryptography.SHA1]::Create()
    try {
        return -join ($sha1.ComputeHash($data) | ForEach-Object { $_.ToString('x2') })
    }
    finally { $sha1.Dispose() }
}

function Export-ExactGitBlob {
    param([string]$Checkout, [string]$BlobSha, [string]$Destination)
    # DO NOT use `git show ... > file` in Windows PowerShell 5.1:
    # the shell would re-encode redirected text. Copy the binary stdout stream.
    $processInfo = New-Object Diagnostics.ProcessStartInfo
    $processInfo.FileName = $script:GitExe
    $processInfo.Arguments = ('-C "{0}" cat-file blob {1}' -f $Checkout, $BlobSha)
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $processInfo
    $stream = $null
    $started = $false
    try {
        $started = $process.Start()
        if (-not $started) { throw 'Could not start git cat-file' }
        $stream = [IO.File]::Create($Destination)
        $process.StandardOutput.BaseStream.CopyTo($stream)
        $stream.Flush()
        $stream.Dispose()
        $stream = $null
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw ('git cat-file failed: ' + $stderr)
        }
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($started -and -not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
        $process.Dispose()
    }
    $observed = Get-RawGitBlobSha1 -FilePath $Destination
    if ($observed -cne $BlobSha) {
        throw ('Exact Git object byte verification failed: ' + $observed)
    }
}

try {
    if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or
        -not [Environment]::Is64BitOperatingSystem) {
        throw 'Requires an authorized Windows x64 machine'
    }
    $git = Get-Command git.exe -ErrorAction SilentlyContinue
    if ($null -eq $git) { throw 'git.exe not found; nothing will be installed' }
    $script:GitExe = $git.Source

    if ([string]::IsNullOrWhiteSpace($CheckoutDirectory)) {
        # Reuse an existing exact R113 checkout. NEVER change its Git ref.
        $candidates = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -Filter 'FlowBridge-R113-*' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending)
        foreach ($candidate in $candidates) {
            if (-not (Test-Path -LiteralPath (Join-Path $candidate.FullName '.git'))) { continue }
            try {
                $candidateHead = Invoke-VerifiedGit -GitArguments @('-C', $candidate.FullName, 'rev-parse', '--verify', 'HEAD')
                if ($candidateHead -ceq $PinnedCommit) {
                    $CheckoutDirectory = $candidate.FullName
                    break
                }
            }
            catch { continue }
        }
        if ([string]::IsNullOrWhiteSpace($CheckoutDirectory)) {
            throw 'No exact R113 checkout found. Supply -CheckoutDirectory from previous output.'
        }
    }
    $CheckoutDirectory = [IO.Path]::GetFullPath($CheckoutDirectory)
    if (-not (Test-Path -LiteralPath (Join-Path $CheckoutDirectory '.git'))) {
        throw 'Not a Git checkout (missing .git)'
    }
    $head = Invoke-VerifiedGit -GitArguments @('-C', $CheckoutDirectory, 'rev-parse', '--verify', 'HEAD')
    if ($head -cne $PinnedCommit) {
        throw ('Wrong HEAD; expected R113 ' + $PinnedCommit + ', got ' + $head)
    }
    foreach ($entry in @(
        @{ Name = $SourceGitPath; Sha = $ExpectedSource },
        @{ Name = $HarnessGitPath; Sha = $ExpectedHarness }
    )) {
        $treeBlob = Invoke-VerifiedGit -GitArguments @('-C', $CheckoutDirectory, 'rev-parse', ('HEAD:' + $entry.Name))
        if ($treeBlob -cne $entry.Sha) {
            throw ('R113 tree object mismatch for ' + $entry.Name)
        }
    }
    Write-Host ('R113 exact checkout: ' + $CheckoutDirectory)
    Write-Host ('Pinned commit: ' + $head)

    $EvidenceDirectory = Join-Path ([IO.Path]::GetTempPath()) (
        'FlowBridge-R113-ExactBlob-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $EvidenceDirectory -ErrorAction Stop
    $exactRust = Join-Path $EvidenceDirectory 'r113-exact-source.rs'
    $exactHarness = Join-Path $EvidenceDirectory 'r113-exact-harness.ps1'
    Export-ExactGitBlob -Checkout $CheckoutDirectory -BlobSha $ExpectedSource -Destination $exactRust
    Export-ExactGitBlob -Checkout $CheckoutDirectory -BlobSha $ExpectedHarness -Destination $exactHarness

    # Show line-ending conversion without calling it source corruption.
    $workingRust = Join-Path $CheckoutDirectory ($SourceGitPath.Replace('/', [IO.Path]::DirectorySeparatorChar))
    if (Test-Path -LiteralPath $workingRust -PathType Leaf) {
        $rawWorkingHash = Get-RawGitBlobSha1 -FilePath $workingRust
        if ($rawWorkingHash -cne $ExpectedSource) {
            Write-Host ('Working-tree bytes differ from Git blob: ' + $rawWorkingHash)
            Write-Host 'Likely checkout LF->CRLF translation. Using exact verified Git object bytes.'
        }
    }
    Write-Host ('Exact R113 Rust blob: ' + $ExpectedSource)
    Write-Host ('Exact R113 harness blob: ' + $ExpectedHarness)
    Write-Host ('Isolated evidence/source: ' + $EvidenceDirectory)

    if (-not [string]::IsNullOrWhiteSpace($RustBinDirectory)) {
        $bin = [IO.Path]::GetFullPath($RustBinDirectory)
        if (-not (Test-Path -LiteralPath (Join-Path $bin 'rustc.exe') -PathType Leaf)) {
            throw ('rustc.exe not found in ' + $bin)
        }
        # Per-process only. Do not modify machine/user PATH settings.
        $env:PATH = $bin + ';' + $env:PATH
    }
    if ($null -eq (Get-Command rustc.exe -ErrorAction SilentlyContinue)) {
        throw 'Rust compiler not available; no installations attempted'
    }

    $runnerArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
              $exactHarness, '-Source', $exactRust)
    if (-not $CompileOnly) {
        $runnerArguments += '-RunUnitTests'
        if (-not $SkipReadOnlyBfe) { $runnerArguments += '-RunReadOnlyBfe' }
    }
    Write-Host ('R113 mode: ' + $(if ($CompileOnly) { 'metadata compile only' }
        elseif ($SkipReadOnlyBfe) { 'metadata + synthetic Rust tests' }
        else { 'metadata + synthetic Rust tests + READ-ONLY BFE' }))
    $ps = (Get-Command powershell.exe -ErrorAction Stop).Source
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $ps @runnerArguments
        $exitCode = [int]$LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previous }
    Write-Host ('R113 result exit code: ' + $exitCode)
    if ($exitCode -eq 3) {
        Write-Host 'Visible BFE competitor; NOT a PASS or kernel proof.'
    }
    elseif ($exitCode -eq 4) {
        Write-Host 'No visible competitor; still UNKNOWN, NOT a PASS.'
    }
    elseif ($exitCode -eq 0) {
        Write-Host 'Only requested compilation/synthetic tests succeeded; NOT kernel proof.'
    }
    else {
        Write-Host 'Failure/unavailable. Examine R112 evidence directory printed by harness.'
    }
}
catch {
    Write-Host ('R113 BLOCKED: ' + $_.Exception.Message) -ForegroundColor Red
    Write-Host 'No Git refs, WFP filters, drivers, services or security settings were changed.'
    $exitCode = 2
}
finally {
    if ($null -ne $EvidenceDirectory) {
        Write-Host ('Preserved exact-source directory: ' + $EvidenceDirectory)
    }
    if (-not [string]::IsNullOrWhiteSpace($CheckoutDirectory)) {
        Write-Host ('Preserved original checkout: ' + $CheckoutDirectory)
    }
}
exit $exitCode
