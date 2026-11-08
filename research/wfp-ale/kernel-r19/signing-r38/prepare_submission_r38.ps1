# R38: make an UNSIGNED attestation candidate, never install or sign a driver.
# All outputs confined to caller supplied build-artifact directory.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$BuildDirectory,
  [Parameter(Mandatory=$true)][string]$OutputDirectory
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$build = (Resolve-Path -LiteralPath $BuildDirectory).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
$source = Join-Path $build 'flowbridge_g2_witness.sys'
$broker = Join-Path $build 'flowbridge-redirect-broker.exe'
$record = Join-Path $build 'build-result.json'
$scopeFile = Join-Path $build 'r24-build-scope.json'
$infOriginal = Join-Path $PSScriptRoot 'flowbridge_g2_r38.inf'
foreach ($file in @($source,$broker,$record,$scopeFile,$infOriginal)) {
  if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing source file: $file" }
}
$report = Get-Content -LiteralPath $record -Raw | ConvertFrom-Json -AsHashtable
$scope = Get-Content -LiteralPath $scopeFile -Raw | ConvertFrom-Json -AsHashtable
if ([string]::IsNullOrWhiteSpace($env:GITHUB_SHA) -or
    $report.source_sha -ne $env:GITHUB_SHA -or
    $scope.source_sha -ne $env:GITHUB_SHA) { throw 'Provenance SHA did not match checkout' }
foreach ($flag in @('kernel_driver_loaded','wfp_filters_installed','g2_pass','release_accepted')) {
  if ($report[$flag] -ne $false) { throw "Unaccepted build proof promoted: $flag" }
}
foreach ($flag in @('actual_policy_installed','kernel_driver_loaded','g2_pass','release_accepted')) {
  if ($scope[$flag] -ne $false) { throw "Unaccepted broker proof promoted: $flag" }
}
$shaDriver = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
$shaBroker = (Get-FileHash -LiteralPath $broker -Algorithm SHA256).Hash.ToLowerInvariant()
if ($report.driver_sha256 -ne $shaDriver) { throw 'Driver hash does not match independent build report' }
$sig = Get-AuthenticodeSignature -LiteralPath $source
if ($sig.Status -ne [System.Management.Automation.SignatureStatus]::NotSigned) {
  throw 'Expected *unsigned* source candidate; stop and review changed signer state'
}
$package = Join-Path $output 'FlowBridgeG2R38'
New-Item -ItemType Directory -Path $package -Force | Out-Null
$driverCopy = Join-Path $package 'flowbridge_g2_witness.sys'
$infCopy = Join-Path $package 'flowbridge_g2_r38.inf'
Copy-Item -LiteralPath $source -Destination $driverCopy
Copy-Item -LiteralPath $infOriginal -Destination $infCopy
$ddf = Join-Path $output 'submission-r38.ddf'
$cab = Join-Path $output 'FlowBridgeG2R38.cab'
$ddfLines = @(
  '.OPTION EXPLICIT',
  '.Set Cabinet=on',
  '.Set Compress=on',
  '.Set CompressionType=MSZIP',
  '.Set CabinetNameTemplate=FlowBridgeG2R38.cab',
  ('.Set DiskDirectory1="' + $output + '"'),
  '.Set DestinationDir=FlowBridgeG2R38',
  ('"' + $driverCopy + '"'),
  ('"' + $infCopy + '"')
)
Set-Content -LiteralPath $ddf -Value $ddfLines -Encoding ASCII
& makecab.exe /F $ddf | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $cab -PathType Leaf)) {
  throw 'Windows MakeCab did not produce an attestation candidate'
}
$expanded = Join-Path $output 'r38-reextracted'
New-Item -ItemType Directory -Path $expanded -Force | Out-Null
& expand.exe '-F:*' $cab $expanded | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Windows Expand failed' }
foreach ($item in @(
    @{Name='flowbridge_g2_witness.sys';Expected=$shaDriver},
    @{Name='flowbridge_g2_r38.inf';Expected=(Get-FileHash -LiteralPath $infCopy -Algorithm SHA256).Hash.ToLowerInvariant()}
  )) {
  $candidates = @(Get-ChildItem -LiteralPath $expanded -File -Recurse | Where-Object Name -eq $item.Name)
  if ($candidates.Count -ne 1) { throw "Missing/ambiguous CAB member: $($item.Name)" }
  $actual = (Get-FileHash -LiteralPath $candidates[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $item.Expected) { throw "CAB member digest mismatch: $($item.Name)" }
}
$cabSha = (Get-FileHash -LiteralPath $cab -Algorithm SHA256).Hash.ToLowerInvariant()
$infSha = (Get-FileHash -LiteralPath $infCopy -Algorithm SHA256).Hash.ToLowerInvariant()
$manifest = [ordered]@{
  ok = $true
  evidence = 'unsigned_inf_and_cab_staged_and_reextracted'
  source_sha = $env:GITHUB_SHA
  unsigned_driver_sha256 = $shaDriver
  broker_sha256 = $shaBroker
  inf_sha256 = $infSha
  unsigned_cab_sha256 = $cabSha
  unsigned_driver_bytes = (Get-Item -LiteralPath $source).Length
  included_files = @('FlowBridgeG2R38/flowbridge_g2_witness.sys','FlowBridgeG2R38/flowbridge_g2_r38.inf')
  infverif_complete = $false
  partner_center_submission_complete = $false
  microsoft_kernel_signature_verified = $false
  exact_target_host_preflight_passed = $false
  kernel_driver_loaded = $false
  bfe_filters_installed = $false
  real_ale_connect_redirect_observed = $false
  full_redirect_chain_executed = $false
  physical_no_direct_proved = $false
  g2_pass = $false
  release_accepted = $false
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $output 'R38_UNSIGNED_SUBMISSION.json') -Encoding utf8
Write-Output "R38 unsigned cabinet checked: $cabSha (NOT SIGNED OR INSTALLED)"
