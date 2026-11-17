# Read-only Windows OpenSSH backend trust check for internal FlowBridge QA.
# Does not execute SSH, install software, change PATH, load keys, or grant release GO.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SshExecutable,
    [string]$ExpectedSha256
)
$ErrorActionPreference = 'Stop'
$result = [ordered]@{
    schema = 'flowbridge-windows-ssh-backend-trust-v1'
    backend_origin = 'NOT_VERIFIED'
    signer_status = 'NOT_VERIFIED'
    microsoft_signer_verified = $false
    sha256_verified = $false
    artifact_hash_sha256 = $null
    status = 'BLOCKED_UNTRUSTED_BACKEND'
    error_code = $null
    runtime_file_pinned_at_launch = $false
    binary_executed = $false
    current_product_version = '0.3.0-beta.2'
    source_sha = '86583a1a0487b9d383c0122b24558e620bde5b9c'
    a5_native_security_go = $false
    a6_release_security_go = $false
    a7_internal_deployment_go = $false
}
try {
    if (-not [IO.Path]::IsPathRooted($SshExecutable) -or
        $SshExecutable.StartsWith('\\') -or
        $SshExecutable.StartsWith('//') -or
        $SshExecutable.Contains('%') -or
        $SshExecutable.Contains('..') -or
        [IO.Path]::GetFileName($SshExecutable) -ine 'ssh.exe') {
        throw 'NOT_LOCAL_ABSOLUTE_SSH_EXE'
    }
    if (-not (Test-Path -LiteralPath $SshExecutable -PathType Leaf)) {
        throw 'SSH_BINARY_MISSING'
    }
    $item = Get-Item -LiteralPath $SshExecutable -ErrorAction Stop
    $result.backend_origin = 'EXPLICIT_LOCAL_SSH_PATH'
    $current = $item
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'REPARSE_POINT_IN_BACKEND_PATH'
        }
        $current = if ($current -is [IO.FileInfo]) { $current.Directory } else { $current.Parent }
    }
    $result.artifact_hash_sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ExpectedSha256) {
        if ($ExpectedSha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
            $result.artifact_hash_sha256 -cne $ExpectedSha256.ToLowerInvariant()) {
            throw 'SSH_PINNED_SHA256_MISMATCH'
        }
        $result.sha256_verified = $true
    }
    $sig = Get-AuthenticodeSignature -LiteralPath $item.FullName -ErrorAction Stop
    $result.signer_status = [string]$sig.Status
    if ($sig.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $sig.SignerCertificate -or
        $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw 'SSH_AUTHENTICODE_MICROSOFT_SIGNER_NOT_VERIFIED'
    }
    $result.microsoft_signer_verified = $true
    # A signature+sha preflight cannot atomically bind the file to process
    # creation. The product's runtime trust boundary remains an open issue.
    $result.status = 'READ_ONLY_SIGNED_SSH_FILE_PASS_RUNTIME_TOCTOU_NOT_PROVED'
} catch {
    $code = [string]$_.Exception.Message
    $known = @(
        'NOT_LOCAL_ABSOLUTE_SSH_EXE', 'SSH_BINARY_MISSING',
        'REPARSE_POINT_IN_BACKEND_PATH', 'SSH_PINNED_SHA256_MISMATCH',
        'SSH_AUTHENTICODE_MICROSOFT_SIGNER_NOT_VERIFIED'
    )
    $result.error_code = if ($code -in $known) { $code } else { 'SSH_READ_ONLY_TRUST_CHECK_FAILED' }
}
# Deliberately no full path, subject details, CLI args, identity or SSH logs.
$result | ConvertTo-Json -Depth 4 -Compress
if ($result.status -ceq 'READ_ONLY_SIGNED_SSH_FILE_PASS_RUNTIME_TOCTOU_NOT_PROVED') { exit 0 }
exit 1
