# Exact-source R39 TEST-SIGNING REHEARSAL, ephemeral CI only.
# Never install/start a kernel driver, add a trusted root, change BCD,
# change Secure Boot/HVCI/Defender, write BFE, or export a private key.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$CandidateDir,
 [Parameter(Mandatory=$true)][string]$OutputDir,
 [string]$TargetOs='10_25H2_X64'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$Error.Clear()
$originalSysSha='c613fd1d98a9a4e22d6551f07143c7821263df2732c3e25bae2543b1ca7d4c00'
$originalInfSha='29b62d0272436d62098d2514a6586db171261faaa58c9ac31a271518f3c5fbdd'
$originalBrokerSha='295bc4b74c42e95f3f94d7576bfba7a4e1aeee4e2ba52dc2c84f007d703ac2bb'
function Hash([string]$file){return (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()}
function FindSdkTool([string]$name){
  if($name -eq 'inf2cat' -and $env:FB_INF2CAT_EXE -and
    (Test-Path -LiteralPath $env:FB_INF2CAT_EXE -PathType Leaf)){
    return [IO.Path]::GetFullPath($env:FB_INF2CAT_EXE)
  }
  $kits=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
  $candidates=@()
  if(Test-Path -LiteralPath $kits){
    $candidates=@(Get-ChildItem -LiteralPath $kits -Recurse -File -Filter ($name+'.exe') -ErrorAction SilentlyContinue|
      Where-Object {$_.FullName -match '[\\/](?:x64|amd64)[\\/]'}|
      Sort-Object FullName -Descending)
  }
  if($candidates.Count -gt 0){return $candidates[0].FullName}
  $cmd=Get-Command ($name+'.exe') -ErrorAction SilentlyContinue
  if($cmd){return $cmd.Source}
  throw ("Missing official WDK/SDK tool "+$name)
}
$root=[IO.Path]::GetFullPath($OutputDir)
$null=New-Item -ItemType Directory -Path $root -Force
$report=[ordered]@{
 schema='flowbridge-r39-ephemeral-test-signing-rehearsal-v1'
 source_build_run=42465140005
 source_build_sha='c2829e87da59e16f06b631af683aee4101ff6621'
 status='NOT_STARTED'
 original_driver_sha256=''
 original_inf_sha256=''
 original_broker_sha256=''
 ephemeral_signer_thumbprint=''
 signed_driver_sha256=''
 signed_catalog_sha256=''
 signed_sys_test_signature_present=$false
 signed_cat_test_signature_present=$false
 signed_pe_sections_identical=$false
 inf2cat_generated_catalog=$false
 private_key_exported=$false
 system_trusted_roots_changed=$false
 test_signing_bcd_changed=$false
 kernel_driver_loaded=$false
 wfp_filters_installed=$false
 native_redirect_executed=$false
 host_admitted=false
 g2_pass=$false
 release_accepted=$false
 error=''
}
$cert=$null
$thumb=''
try{
  if($env:GITHUB_ACTIONS -ne 'true'){throw 'Only disposable GitHub Actions Windows runner admitted'}
  if(-not $IsWindows){throw 'Windows required'}
  $candidate=[IO.Path]::GetFullPath($CandidateDir)
  $sys=Join-Path $candidate 'flowbridge_g2_witness.sys'
  $inf=Join-Path $candidate 'signing-r38/FlowBridgeG2R38/flowbridge_g2_r38.inf'
  $broker=Join-Path $candidate 'flowbridge-redirect-broker.exe'
  foreach($file in @($sys,$inf,$broker)){
    if(-not (Test-Path -LiteralPath $file -PathType Leaf)){throw 'Missing pinned R39 source artifact'}
  }
  $report.original_driver_sha256=Hash $sys
  $report.original_inf_sha256=Hash $inf
  $report.original_broker_sha256=Hash $broker
  if($report.original_driver_sha256 -ne $originalSysSha -or
    $report.original_inf_sha256 -ne $originalInfSha -or
    $report.original_broker_sha256 -ne $originalBrokerSha){throw 'R39 original source SHA drift'}
  if((Get-AuthenticodeSignature -LiteralPath $sys).Status -ne [System.Management.Automation.SignatureStatus]::NotSigned){
    throw 'R39 source SYS must be unsigned'
  }
  $signTool=FindSdkTool 'signtool'
  $infTool=FindSdkTool 'inf2cat'
  $stage=Join-Path $root 'staging'
  $null=New-Item -ItemType Directory -Path $stage -Force
  $signedSys=Join-Path $stage 'flowbridge_g2_witness.sys'
  $stagedInf=Join-Path $stage 'flowbridge_g2_r38.inf'
  Copy-Item -LiteralPath $sys -Destination $signedSys -ErrorAction Stop
  Copy-Item -LiteralPath $inf -Destination $stagedInf -ErrorAction Stop
  # Ephemeral CurrentUser private key. No LocalMachine or Trusted Root writes.
  $cert=New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=FlowBridge R39 CI Ephemeral TEST ONLY' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -NotAfter ([DateTime]::UtcNow.AddDays(2)) -ErrorAction Stop
  $thumb=$cert.Thumbprint
  if($thumb -notmatch '^[A-Fa-f0-9]{40}$'){throw 'Unexpected test signer thumbprint'}
  $report.ephemeral_signer_thumbprint=$thumb
  & $signTool sign /v /fd SHA256 /s My /sha1 $thumb $signedSys | Out-Null
  if($LASTEXITCODE -ne 0){throw 'SignTool SYS signing rejected'}
  $sig=Get-AuthenticodeSignature -LiteralPath $signedSys
  if($null -eq $sig.SignerCertificate -or $sig.SignerCertificate.Thumbprint -ne $thumb){
    throw 'SYS signer does not match ephemeral test certificate'
  }
  $report.signed_sys_test_signature_present=$true
  $py=Get-Command python.exe -ErrorAction Stop
  $compare=(Join-Path $env:GITHUB_WORKSPACE 'research/wfp-ale/kernel-r19/signing-r38/compare_pe_sections_r38.py')
  $compared=@(& $py.Source $compare $sys $signedSys 2>&1)
  if($LASTEXITCODE -ne 0){throw 'Signed SYS changed original PE loadable section bytes'}
  $cmp=($compared -join [Environment]::NewLine)|ConvertFrom-Json -AsHashtable
  if($cmp.all_loadable_section_bytes_equal -ne $true){throw 'Signed SYS source section mismatch'}
  $report.signed_pe_sections_identical=$true
  & $infTool ("/driver:"+$stage) ("/os:"+$TargetOs) /verbose /uselocaltime | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Official WDK Inf2Cat refused R39 INF+SYS'}
  $cat=Join-Path $stage 'FlowBridgeG2R38.cat'
  if(-not (Test-Path -LiteralPath $cat -PathType Leaf)){throw 'Inf2Cat did not produce exact expected CAT'}
  $report.inf2cat_generated_catalog=$true
  & $signTool sign /v /fd SHA256 /s My /sha1 $thumb $cat | Out-Null
  if($LASTEXITCODE -ne 0){throw 'SignTool CAT signing rejected'}
  $catSig=Get-AuthenticodeSignature -LiteralPath $cat
  if($null -eq $catSig.SignerCertificate -or $catSig.SignerCertificate.Thumbprint -ne $thumb){
    throw 'CAT signer does not match ephemeral certificate'
  }
  $report.signed_cat_test_signature_present=$true
  $report.signed_driver_sha256=Hash $signedSys
  $report.signed_catalog_sha256=Hash $cat
  if($report.signed_driver_sha256 -eq $originalSysSha){throw 'SYS unchanged after signing'}
  $report.status='SIGNING_REHEARSAL_PASS_NOT_TRUSTED_NOT_LOADABLE_EVIDENCE'
}catch{
  $report.status='SIGNING_REHEARSAL_FAILED'
  $report.error=[string]$_.Exception.Message
}finally{
  if($thumb){
    try{
      $p='Cert:\CurrentUser\My\'+$thumb
      if(Test-Path -LiteralPath $p){Remove-Item -LiteralPath $p -Force -ErrorAction Stop}
    }catch{
      $report.status='EPHEMERAL_CERT_CLEANUP_FAILED'
      $report.error+='; ephemeral_test_certificate_cleanup_failed'
    }
  }
  # No SYS/CAT/certificate/private key is exported as an Actions artifact:
  # the offline report contains hashes and the NON-SECRET public thumbprint.
  $json=$report|ConvertTo-Json -Depth 8
  [IO.File]::WriteAllText((Join-Path $root 'signing-rehearsal-report.json'),$json+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
  Write-Output $json
}
if($report.status -ne 'SIGNING_REHEARSAL_PASS_NOT_TRUSTED_NOT_LOADABLE_EVIDENCE'){exit 2}
