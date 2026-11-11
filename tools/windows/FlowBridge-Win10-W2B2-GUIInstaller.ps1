#requires -version 5.1
<#
Native Windows 10 W2b2 exact-beta GUI/installer acceptance.
Use only on a dedicated QA machine, with an interactive RDP desktop.
Consumes the SHA-pinned hosted bundle of the exact FlowBridge beta source.
Does NOT install any driver, service or network filter or alter firewall/DNS.
A disposable per-user NSIS installation creates HKCU keys and a Start-menu
shortcut, all checked and removed by its own uninstaller. Never upgrades an
existing user installation or touches a pre-existing FlowBridge profile.
The NSIS engineering candidate is UNSIGNED, NOT an approved release.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
 [string]$BundleZip='',
 [string]$BundleDirectory='',
 [string]$ReportRoot="$env:ProgramData\FlowBridge\W2B2-Evidence",
 [switch]$AllowHostedCI
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$exactSource='c339df2e4d20edf1d11d45786581a68451a71929'
# Updated only after native exact-source package CI and independent SHA audit.
$requiredArtifactZipSha='NOT_PINNED_YET'
function FileHash([string]$path){(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
function DoProcess([string]$binary,[string]$arguments,[string]$label,[int]$maxSeconds=180){
 $p=New-Object Diagnostics.Process
 $psi=New-Object Diagnostics.ProcessStartInfo
 $psi.FileName=$binary;$psi.Arguments=$arguments
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
 $p.StartInfo=$psi
 try {
  if(-not $p.Start()){throw ('Failed to start '+$label)}
  $output=$p.StandardOutput.ReadToEndAsync()
  $errors=$p.StandardError.ReadToEndAsync()
  $completed=$p.WaitForExit($maxSeconds*1000)
  if(-not $completed){try{$p.Kill();$p.WaitForExit(4000)|Out-Null}catch{}}
  $out=[string]$output.GetAwaiter().GetResult()
  $err=[string]$errors.GetAwaiter().GetResult()
  [IO.File]::WriteAllText((Join-Path $run ($label+'.stdout.log')),$out,[Text.UTF8Encoding]::new($false))
  [IO.File]::WriteAllText((Join-Path $run ($label+'.stderr.log')),$err,[Text.UTF8Encoding]::new($false))
  return [ordered]@{ok=($completed -and $p.ExitCode -eq 0);exit_code=$p.ExitCode;timeout=(-not $completed);stdout=$out;stderr=$err}
 }finally{$p.Dispose()}
}
function WaitUntil([scriptblock]$condition,[string]$message,[int]$maxSeconds=60){
 $until=[DateTime]::UtcNow.AddSeconds($maxSeconds)
 while([DateTime]::UtcNow -lt $until){
  if(& $condition){return}
  Start-Sleep -Milliseconds 250
 }
 throw $message
}
function FindBundle([string]$suffix) {
 $normalized=$suffix.Replace('/','\')
 $matches=@(Get-ChildItem -LiteralPath $stage -File -Recurse|
  Where-Object {$_.FullName.EndsWith(('\'+$normalized),[StringComparison]::OrdinalIgnoreCase)})
 if($matches.Count -ne 1){throw ('Bundle missing or ambiguous: '+$suffix)}
 return $matches[0].FullName
}
function RegText([string]$path,[string]$field){
 try{
  $data=Get-ItemProperty -Path $path -ErrorAction Stop
  return [string]$data.$field
 }catch{return ''}
}
$clock=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$run=Join-Path ([IO.Path]::GetFullPath($ReportRoot)) ('w2b2-'+$clock+'-'+$PID)
$null=New-Item -ItemType Directory -Path $run -Force
$stage=Join-Path $run 'bundle'
$problems=[System.Collections.Generic.List[string]]::new()
$report=[ordered]@{
 schema='flowbridge-exact-beta-win10-w2b2-v1'
 expected_host=$ExpectedComputerName;actual_host=$env:COMPUTERNAME
 os_name='';os_build='';target_win10=$false;hosted=$false
 source_sha_expected=$exactSource;source_sha_verified=$false
 artifact_zip_sha256='';installer_sha256='';files_checked=0
 unsigned_engineering_candidate=$true
 prior_flowbridge_install_refused=$false
 no_prior_profile_at_start=$false;no_prior_install_at_start=$false
 build_gui_harness_pass=$false;ui_full_screenshots=0
 real_installed_gui_tcp_pass=$false
 installer_hashes_match=$false;installed_user_scope=$false
 upgrade_kept_registered_dir=$false;uninstaller_removed_payload=$false
 profile_preserved_after_uninstall=$false;user_note_preserved=$false
 W2b2='NOT_STARTED';W3='NO_GO';G2='NO_GO';release_accepted=$false
 driver_loaded=$false;service_installed=$false
 firewall_or_dns_changed=$false;host_security_changed=$false
 problems=@()
}
try{
 if($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess){throw 'Requires 64-bit Windows PowerShell'}
 try{
  $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
  $report.os_name=[string]$os.Caption;$report.os_build=[string]$os.BuildNumber
 }catch{
  $r=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $report.os_name=[string]$r.ProductName;$report.os_build=[string]$r.CurrentBuild
 }
 $report.hosted=($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted')
 $report.target_win10=($ExpectedComputerName -ieq $env:COMPUTERNAME -and
  $report.os_build -eq '19045' -and $report.os_name -match 'Windows 10')
 if(-not $report.target_win10 -and -not ($AllowHostedCI -and $report.hosted)){
  throw 'Not the approved native Win10 target; no installation is attempted'
 }
 if($report.target_win10 -and (Get-Process -Id $PID).SessionId -eq 0){
  throw 'Interactive RDP/desktop Windows session required for GUI smoke'
 }
 if(-not $report.hosted -and $BundleDirectory){throw 'Unpinned bundle directory is allowed only in disposable hosted CI'}
 $userKey='HKCU:\Software\FlowBridge'
 $uninstallKey='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridge'
 $shortcuts=Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\FlowBridge'
 $profile=Join-Path $env:LOCALAPPDATA 'FlowBridge'
 $previous=@(Get-Process -Name FlowBridge,FlowBridgeCapture -ErrorAction SilentlyContinue)
 if($previous.Count -gt 0 -or (Test-Path $userKey) -or (Test-Path $uninstallKey) -or
   (Test-Path $shortcuts) -or (Test-Path $profile)){
  $report.prior_flowbridge_install_refused=$true
  throw 'Existing FlowBridge process, registration, Start-menu item or profile found; refusing to overwrite user data'
 }
 $report.no_prior_profile_at_start=$true;$report.no_prior_install_at_start=$true
 if($BundleDirectory){
   $stage=[IO.Path]::GetFullPath($BundleDirectory)
   if(-not(Test-Path $stage -PathType Container)){throw 'Hosted bundle source folder missing'}
 }else{
   if(-not $BundleZip){throw 'Provide the GitHub Actions artifact ZIP using -BundleZip'}
   if($requiredArtifactZipSha -eq 'NOT_PINNED_YET'){throw 'Expected artifact ZIP checksum has not been pinned'}
   $sum=FileHash $BundleZip
   $report.artifact_zip_sha256=$sum
   if($sum -cne $requiredArtifactZipSha){throw 'GitHub artifact ZIP SHA256 does not match pinned expected digest'}
   $null=New-Item -ItemType Directory -Force -Path $stage
   Expand-Archive -LiteralPath $BundleZip -DestinationPath $stage -Force
 }
 $manifestPath=FindBundle 'build/w2b2-qa/bundle-manifest.json'
 $manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
 if($manifest.schema -ne 'flowbridge-exact-beta-win10-gui-installer-v1' -or
    $manifest.source_sha -cne $exactSource -or $manifest.signed -ne $false -or
    $manifest.driver_installed -or $manifest.target_win10_physically_tested){
   throw 'Bundle manifest scope, source SHA or signed/driver claims invalid'
 }
 $report.source_sha_verified=$true
 $sourcePath=FindBundle 'build/w2b2-qa/source-commit.txt'
 if((Get-Content -LiteralPath $sourcePath -Raw).Trim() -cne $exactSource){throw 'Source commitment marker incorrect'}
 foreach($item in @($manifest.files)){
  $relative=[string]$item.path
  if($relative -match '(^[A-Za-z]:)|(^/)|(\.\.)'){throw 'Unsafe bundle file path'}
  $actual=FindBundle $relative
  if((FileHash $actual) -cne [string]$item.sha256 -or
     (Get-Item -LiteralPath $actual).Length -ne [long]$item.bytes){
   throw ('Bundle payload SHA256 or size mismatch: '+$relative)
  }
  $report.files_checked++
 }
 $installer=FindBundle 'artifacts/FlowBridge-0.2.0-windows-x64-setup.exe'
 $harness=FindBundle 'build/windows/Release/FlowBridgeNativeSmoke.exe'
 $projectManifest=FindBundle 'docs/verification/windows-package.json'
 $pkg=Get-Content -LiteralPath $projectManifest -Raw|ConvertFrom-Json
 $report.installer_sha256=FileHash $installer
 if($report.installer_sha256 -cne $manifest.installer_sha256 -or
    $report.installer_sha256 -cne $pkg.sha256 -or $pkg.signed -ne $false -or
    $pkg.wfp_kernel_driver_included -ne $false){throw 'Installer manifest/security boundary mismatch'}
 $install=Join-Path $run 'Install QA With Spaces'
 $alternate=Join-Path $run 'Do Not Relocate'
 $cmd='/S /D='+$install
 $result=DoProcess $installer $cmd 'nsis-install' 120
 if(-not $result.ok){throw 'NSIS install failed; see nsis-install logs'}
 WaitUntil {Test-Path -LiteralPath (Join-Path $install 'Uninstall.exe') -PathType Leaf} 'Installer did not deploy Uninstall.exe'
 $report.installed_user_scope=$true
 foreach($item in @($pkg.payload)){
  $rel=([string]$item.path).Replace('/','\')
  if($rel -match '\.\.'){throw 'Unsafe package payload path'}
  $file=Join-Path $install $rel
  if(-not(Test-Path -LiteralPath $file -PathType Leaf) -or (FileHash $file) -cne [string]$item.sha256){
   throw ('Installed package does not match manifest: '+$rel)
  }
 }
 $report.installer_hashes_match=$true
 if((RegText $userKey 'InstallDir') -ne $install -or
    (RegText $uninstallKey 'InstallLocation') -ne $install){
    throw 'Per-user NSIS registry InstallDir mismatch'
 }
 # All GUI screen/window exercises happen only after an actual user installation.
 $gui=Join-Path $install 'FlowBridge.exe'
 $mainScreenshot=Join-Path $run 'installed-ui.bmp'
 $cmd='"'+$gui+'" "'+$mainScreenshot+'"'
 $result=DoProcess $harness $cmd 'native-gui-harness' 180
 if(-not $result.ok -or $result.stdout -notmatch 'PASS Win32 GUI:' -or
    $result.stdout -notmatch 'PASS Windows DLL:' -or
    $result.stdout -notmatch 'PASS compact Windows GUI:'){
  throw 'Real installed native GUI/FFI smoke failed; see native-gui-harness logs'
 }
 $report.build_gui_harness_pass=$true
 $report.real_installed_gui_tcp_pass=$true
 $hashes=[System.Collections.Generic.HashSet[string]]::new()
 foreach($page in @('dashboard','ssh','proxy','apps','advanced')){
  $bmp=Join-Path $run ('installed-ui-compact-'+$page+'.bmp')
  if(-not(Test-Path -LiteralPath $bmp -PathType Leaf)){throw ('GUI screenshot missing: '+$page)}
  $stream=[IO.File]::ReadAllBytes($bmp)
  if($stream.Length -lt 54 -or $stream[0] -ne 66 -or $stream[1] -ne 77){
   throw ('Invalid screenshot bitmap: '+$page)
  }
  $width=[BitConverter]::ToInt32($stream,18)
  $height=[Math]::Abs([BitConverter]::ToInt32($stream,22))
  if($width -lt 920 -or $height -lt 600){throw ('GUI page too small: '+$page)}
  if(-not $hashes.Add((FileHash $bmp))){throw 'Duplicate GUI page screenshots detected'}
  $report.ui_full_screenshots++
 }
 $savedProfile=Join-Path $profile 'profile.json'
 if(-not(Test-Path -LiteralPath $savedProfile -PathType Leaf)){throw 'GUI failed to save its own per-user test profile'}
 $originalProfileHash=FileHash $savedProfile
 $note=Join-Path $install 'user-owned-notes.txt'
 [IO.File]::WriteAllText($note,'Owner QA text - the uninstaller must preserve this note.',[Text.UTF8Encoding]::new($false))
 $result=DoProcess $installer ('/S /D='+$alternate) 'nsis-upgrade' 120
 if(-not $result.ok){throw 'NSIS upgrade failed'}
 if((RegText $userKey 'InstallDir') -ne $install -or
    (Test-Path -LiteralPath $alternate) -or
    -not(Test-Path -LiteralPath $note) -or
    (FileHash $savedProfile) -cne $originalProfileHash){
   throw 'Upgrade relocated installation or modified owner user files/profile'
 }
 $report.upgrade_kept_registered_dir=$true
 $uninstaller=Join-Path $install 'Uninstall.exe'
 if(-not(Test-Path -LiteralPath $uninstaller -PathType Leaf)){throw 'NSIS Uninstall.exe missing'}
 $result=DoProcess $uninstaller '/S' 'nsis-uninstall' 120
 if(-not $result.ok){throw 'NSIS uninstaller failed'}
 WaitUntil {
  -not(Test-Path -LiteralPath (Join-Path $install 'FlowBridge.exe')) -and
  -not(Test-Path -LiteralPath (Join-Path $install 'Uninstall.exe')) -and
  -not(Test-Path $userKey) -and -not(Test-Path $uninstallKey) -and
  -not(Test-Path (Join-Path $shortcuts 'FlowBridge.lnk'))
 } 'NSIS uninstall did not converge: binaries/keys/shortcut remain' 90
 foreach($item in @($pkg.payload)){
   if(Test-Path -LiteralPath (Join-Path $install ([string]$item.path)) -PathType Leaf){
      throw ('Uninstaller retained owned file '+$item.path)
   }
 }
 $report.uninstaller_removed_payload=$true
 $report.user_note_preserved=(Test-Path -LiteralPath $note -PathType Leaf)
 $report.profile_preserved_after_uninstall=($report.user_note_preserved -and
   (FileHash $savedProfile) -ceq $originalProfileHash)
 if(-not $report.profile_preserved_after_uninstall){throw 'Uninstaller lost user profile or note'}
 if($report.target_win10){$report.W2b2='PASS_NATIVE_WIN10_GUI_INSTALL_UPGRADE_UNINSTALL'}
 else{$report.W2b2='PASS_HOSTED_NON_TARGET_GUI_INSTALL_UPGRADE_UNINSTALL'}
}catch{
 $problems.Add($_.Exception.Message)
 $report.W2b2='FAILED_OR_BLOCKED'
}finally{
 $report.problems=@($problems.ToArray())
 $json=Join-Path $run 'w2b2-report.json'
 [IO.File]::WriteAllText($json,($report|ConvertTo-Json -Depth 14),[Text.UTF8Encoding]::new($false))
 $manifest=Join-Path $run 'sha256.txt'
 $files=@(Get-ChildItem -LiteralPath $run -File|Where-Object {$_.Extension -in @('.log','.json','.bmp')})
 $rows=@($files|Sort-Object Name|ForEach-Object{(FileHash $_.FullName)+'  '+$_.Name})
 [IO.File]::WriteAllLines($manifest,$rows,[Text.UTF8Encoding]::new($false))
 $zip=Join-Path $run 'evidence-only.zip'
 try{
  $paths=@($files|ForEach-Object{$_.FullName});$paths+=@($manifest)
  Compress-Archive -LiteralPath $paths -DestinationPath $zip -Force -ErrorAction Stop
 }catch{Write-Warning ('Evidence ZIP failed: '+$_.Exception.Message)}
 Write-Host ('W2b2: '+$report.W2b2+'; W3/G2: NO_GO')
 Write-Host ('Report: '+$json)
 if(Test-Path $zip){Write-Host ('Evidence ZIP: '+$zip);Write-Host ('ZIP SHA256: '+(FileHash $zip))}
 if($report.problems.Count){Write-Host ('Notes: '+($report.problems -join '; '))}
 Write-Host 'Unsigned engineering installer only; no protected routing or final release signoff.'
}
