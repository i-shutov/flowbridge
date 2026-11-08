# Guest-only test signing of ONE hash-pinned R39 unsigned candidate.
# Does NOT install/load/start the kernel driver or any WFP/BFE filters.
# Private key remains non-exportable in the disposable Windows 11 VM.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$UnsignedSys,
 [Parameter(Mandatory=$true)][string]$UnsignedInf,
 [string]$ExpectedUnsignedSysSha256='c613fd1d98a9a4e22d6551f07143c7821263df2732c3e25bae2543b1ca7d4c00',
 [string]$ExpectedUnsignedInfSha256='29b62d0272436d62098d2514a6586db171261faaa58c9ac31a271518f3c5fbdd',
 [ValidateSet('10_GE_X64','10_25H2_X64')][string]$Inf2CatOS='10_25H2_X64',
 [string]$OutputDirectory=(Join-Path $env:ProgramData 'FlowBridgeLab\R39-TESTSIGNED'),
 [string]$ExpectedComputerName='',
 [switch]$Apply,
 [string]$OutputPath=''
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Sha256([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
function FindKitTool([string]$tool){
 $cmd=Get-Command ($tool+'.exe') -ErrorAction SilentlyContinue
 if($cmd){return $cmd.Source}
 $kitRoot=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
 if(-not (Test-Path -LiteralPath $kitRoot)){throw "SDK/WDK not installed: $tool"}
 $found=@(Get-ChildItem -Path $kitRoot -Filter ($tool+'.exe') -Recurse -File -ErrorAction SilentlyContinue|
   Where-Object { $_.FullName -match '[\\/]x64[\\/]' }|
   Sort-Object FullName -Descending)
 if($found.Count -ne 1 -and $found.Count -eq 0){throw "SDK/WDK tool unavailable: $tool"}
 return $found[0].FullName
}
$report=[ordered]@{
 schema='flowbridge-r39-win11-test-signing-v1'
 status='AUDIT_ONLY'
 target=$env:COMPUTERNAME
 kernel_driver_source_sha256=''
 original_inf_sha256=''
 signed_driver_sha256=''
 test_signed_catalog_sha256=''
 test_certificate_thumbprint=''
 inf2cat_os=$Inf2CatOS
 code_signing_test_only=$true
 isolated_guest_verified=$false
 original_source_hashes_verified=$false
 root_certificate_imported=$false
 driver_signed=$false
 driver_installed=$false
 driver_loaded=$false
 wfp_filters_modified=$false
 g2_pass=$false
 release_accepted=$false
 error=''
}
try{
 if(-not (Test-Path -LiteralPath $UnsignedSys -PathType Leaf) -or
     -not (Test-Path -LiteralPath $UnsignedInf -PathType Leaf)){throw 'Missing candidate .sys or .inf'}
 if((Split-Path $UnsignedSys -Leaf) -ne 'flowbridge_g2_witness.sys' -or
    (Split-Path $UnsignedInf -Leaf) -ne 'flowbridge_g2_r38.inf'){throw 'Unexpected driver/INF filename'}
 if($ExpectedUnsignedSysSha256 -notmatch '^[0-9a-f]{64}$' -or
    $ExpectedUnsignedInfSha256 -notmatch '^[0-9a-f]{64}$'){throw 'Invalid pinned SHA256'}
 $report.kernel_driver_source_sha256=Sha256 $UnsignedSys
 $report.original_inf_sha256=Sha256 $UnsignedInf
 if($report.kernel_driver_source_sha256 -ne $ExpectedUnsignedSysSha256 -or
    $report.original_inf_sha256 -ne $ExpectedUnsignedInfSha256){
   throw 'Candidate differs from verified R39 Windows no-load CI (STOP)'
 }
 $report.original_source_hashes_verified=$true
 if($Apply){
   $os=Get-CimInstance Win32_OperatingSystem
   $cs=Get-CimInstance Win32_ComputerSystem
   if([int]$os.ProductType -ne 1 -or [string]$os.Caption -notmatch 'Windows 11' -or
      [string]$cs.Manufacturer -notmatch 'Microsoft' -or
      [string]$cs.Model -notmatch 'Virtual Machine'){
     throw 'Signing permitted ONLY inside Windows 11 Hyper-V guest'
   }
   if(-not $ExpectedComputerName -or $ExpectedComputerName -ne $env:COMPUTERNAME -or
      $env:COMPUTERNAME -notmatch '^FB-R39-'){throw 'Expected explicit FB-R39-* VM computer name'}
   $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
   if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated guest shell required'}
   if(Confirm-SecureBootUEFI -ErrorAction Stop){throw 'Guest Secure Boot remains enabled; do not modify host'}
   # Enabling test-signing does not itself prove the driver will load.
   $bcdText=(& bcdedit.exe /enum '{current}' | Out-String)
   if($LASTEXITCODE -ne 0 -or $bcdText -notmatch '(?im)^\s*testsigning\s+(Yes|On|True|Да)\s*$'){
     throw 'TESTSIGNING is not confirmed after GUEST reboot'
   }
   $report.isolated_guest_verified=$true
   if((Get-AuthenticodeSignature -LiteralPath $UnsignedSys).Status -ne 'NotSigned'){
     throw 'Input .sys must be pristine unsigned source candidate'
   }
   if(Test-Path -LiteralPath $OutputDirectory){throw 'Refusing to overwrite prior signed lab directory'}
   $signtool=FindKitTool 'signtool'
   $inf2cat=FindKitTool 'inf2cat'
   $null=New-Item -ItemType Directory -Path $OutputDirectory -Force
   $sys=Join-Path $OutputDirectory 'flowbridge_g2_witness.sys'
   $inf=Join-Path $OutputDirectory 'flowbridge_g2_r38.inf'
   Copy-Item -LiteralPath $UnsignedSys -Destination $sys -ErrorAction Stop
   Copy-Item -LiteralPath $UnsignedInf -Destination $inf -ErrorAction Stop
   $subject='CN=FlowBridge R39 DEV TEST ONLY'
   $existing=@(Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq $subject)
   if($existing.Count -ne 0){throw 'Existing lab signing cert: require manual review, do not reissue silently'}
   $cert=New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject -CertStoreLocation 'Cert:\LocalMachine\My' -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -NotAfter ([DateTime]::UtcNow.AddMonths(6))
   $report.test_certificate_thumbprint=$cert.Thumbprint
   $public=Join-Path $OutputDirectory 'FlowBridgeR39-TEST-PUBLIC.cer'
   $null=Export-Certificate -Cert $cert -FilePath $public -ErrorAction Stop
   $null=Import-Certificate -FilePath $public -CertStoreLocation 'Cert:\LocalMachine\Root' -ErrorAction Stop
   $null=Import-Certificate -FilePath $public -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' -ErrorAction Stop
   $report.root_certificate_imported=$true
   & $signtool sign /v /fd SHA256 /sm /s My /sha1 $cert.Thumbprint $sys | Out-Null
   if($LASTEXITCODE -ne 0){throw 'Test SYS signing failed'}
   & $inf2cat ("/driver:"+$OutputDirectory) ("/os:"+$Inf2CatOS) /verbose | Out-Null
   if($LASTEXITCODE -ne 0){throw 'Inf2Cat rejected driver package'}
   $cat=Join-Path $OutputDirectory 'FlowBridgeG2R38.cat'
   if(-not (Test-Path -LiteralPath $cat -PathType Leaf)){throw 'Expected catalog missing'}
   & $signtool sign /v /fd SHA256 /sm /s My /sha1 $cert.Thumbprint $cat | Out-Null
   if($LASTEXITCODE -ne 0){throw 'Test CAT signing failed'}
   & $signtool verify /pa /v $sys | Out-Null
   if($LASTEXITCODE -ne 0){throw 'Authenticode validation of test SYS failed'}
   & $signtool verify /pa /v $cat | Out-Null
   if($LASTEXITCODE -ne 0){throw 'Authenticode validation of test CAT failed'}
   $report.driver_signed=$true
   $report.signed_driver_sha256=Sha256 $sys
   $report.test_signed_catalog_sha256=Sha256 $cat
   $report.status='TEST_SIGNED_UNINSTALLED_NOT_NATIVE_ACCEPTED'
 }
}catch{
 $report.status='BLOCKED'
 $report.error=[string]$_.Exception.Message
}
$json=$report|ConvertTo-Json -Depth 8
if($OutputPath){
 $dest=[IO.Path]::GetFullPath($OutputPath)
 $dir=Split-Path -Parent $dest
 if(-not(Test-Path -LiteralPath $dir)){New-Item -ItemType Directory -Path $dir -Force | Out-Null}
 [IO.File]::WriteAllText($dest,$json+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
}
Write-Output $json
if($report.error){exit 2}
