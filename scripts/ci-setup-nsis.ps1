#requires -Version 7.0
<#
.SYNOPSIS
  Prepare official portable NSIS 3.13 only on disposable GitHub-hosted Windows CI.
.DESCRIPTION
  The separately distributed official SourceForge ZIP is SHA-256 pinned to the
  checksum published on its official download page. No Chocolatey feed, global
  installer, silent compatibility fallback, disabled protections or self-hosted
  server mutation. A missing or unexpected compiler FAILS required installer QA.
  The official NSIS build tool is not part of a FlowBridge candidate payload.
#>
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP) -or
    [string]::IsNullOrWhiteSpace($env:GITHUB_PATH)) {
  throw 'Official NSIS bootstrap allowed only on disposable GitHub-hosted Windows CI'
}
$expected = 'ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8'
# Official SourceForge CDN entry and named SourceForge project mirrors.
# No third-party repacks. Only the vendor-published ZIP SHA-256 can pass.
$urls = @(
  'https://downloads.sourceforge.net/project/nsis/NSIS%203/3.13/nsis-3.13.zip',
  'https://netcologne.dl.sourceforge.net/project/nsis/NSIS%203/3.13/nsis-3.13.zip',
  'https://phoenixnap.dl.sourceforge.net/project/nsis/NSIS%203/3.13/nsis-3.13.zip',
  'https://sourceforge.net/projects/nsis/files/NSIS%203/3.13/nsis-3.13.zip/download'
)
$root = Join-Path $env:RUNNER_TEMP 'flowbridge-pinned-nsis-3.13'
New-Item -Path $root -ItemType Directory -Force | Out-Null
$archive = Join-Path $root 'nsis-3.13.zip'
$verified = $false
for ($index = 0; $index -lt $urls.Count -and -not $verified; $index++) {
  $url = $urls[$index]
  for ($attempt = 1; $attempt -le 2; $attempt++) {
    if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
    try {
      if ($attempt -eq 1) {
        Invoke-WebRequest -Uri $url -OutFile $archive -MaximumRedirection 10 -TimeoutSec 40 -UserAgent 'Mozilla/5.0 (compatible; FlowBridge-CI/1.0)'
      } else {
        & curl.exe --proto '=https' --tlsv1.2 --location --fail --silent --show-error --max-time 40 --output $archive $url
        if ($LASTEXITCODE -ne 0) { throw 'Official mirror curl download failed' }
      }
    } catch {
      Write-Warning ('Official SourceForge mirror unavailable: index=' + $index + ', attempt=' + $attempt)
      continue
    }
    if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) { continue }
    $bytes = [IO.File]::ReadAllBytes($archive)
    # A SourceForge mirror can return an HTML download landing page with HTTP
    # 200. Never hash that page as the vendor ZIP or accept it as a toolchain.
    if ($bytes.Length -lt 1000000 -or $bytes.Length -gt 10000000 -or
        $bytes[0] -ne 0x50 -or $bytes[1] -ne 0x4b -or
        $bytes[2] -notin @(0x03,0x05,0x07) -or $bytes[3] -notin @(0x04,0x06,0x08)) {
      Write-Warning ('SourceForge returned non-archive content: mirror=' + $index +
        ', attempt=' + $attempt + ', byte_count=' + $bytes.Length)
      continue
    }
    # A genuine ZIP with a wrong hash is a security failure, not permission to
    # try mirrors until a convenient digest appears.
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
      throw 'Official NSIS 3.13 ZIP content SHA-256 mismatch (NO INSTALLER BYPASS)'
    }
    $verified = $true
    break
  }
}
if (-not $verified) { throw 'Official NSIS CDN/mirrors supplied no verified ZIP (NO INSTALLER BYPASS)' }
$dest = Join-Path $root 'verified-portable'
if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
Expand-Archive -LiteralPath $archive -DestinationPath $dest -Force
$compilers = @(Get-ChildItem -LiteralPath $dest -Recurse -File -Filter 'makensis.exe')
if ($compilers.Count -ne 1) {
  throw 'Official portable NSIS archive must contain exactly one makensis.exe'
}
$compiler = $compilers[0].FullName
$version = @(& $compiler /VERSION) -join ''
if ($LASTEXITCODE -ne 0 -or $version.Trim() -ne 'v3.13') {
  throw 'Official portable NSIS compiler version check failed (expected v3.13)'
}
$bin = $compilers[0].Directory.FullName
$env:PATH = $bin + [IO.Path]::PathSeparator + $env:PATH
Add-Content -LiteralPath $env:GITHUB_PATH -Value $bin -Encoding utf8
$evidence = @{
  kind = 'github_hosted_official_portable_nsis_toolchain'
  version = '3.13'
  official_zip_sha256 = $expected
  makensis_sha256 = (Get-FileHash -LiteralPath $compiler -Algorithm SHA256).Hash.ToLowerInvariant()
  source = 'https://sourceforge.net/projects/nsis/files/NSIS%203/3.13/'
  archive_digest_verified = $true
  compiler_version_verified = $true
  globally_installed = $false
  included_in_flowbridge_candidate = $false
  installer_security_tests_waived = $false
  driver_or_system_security_modified = $false
}
foreach ($sub in @('build/capture-candidate', 'build/verification/windows')) {
  New-Item -ItemType Directory -Path $sub -Force | Out-Null
  ($evidence | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath (Join-Path $sub 'nsis-toolchain-provenance.json') -Encoding utf8
}
Write-Output 'Verified official portable NSIS v3.13: SHA-256 pinned; installed-product tests remain mandatory'
