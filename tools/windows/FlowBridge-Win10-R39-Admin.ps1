#requires -version 5.1
<#
FlowBridge R39: Windows 10 Pro administrator inventory and NO-DRIVER tests.
Read-only system probes; writes evidence only to ProgramData.
Optional user-mode Rust tests from an already available local checkout.
Never installs/loads drivers, enables TESTSIGNING, changes Defender, BFE,
Secure Boot, firewall, DNS, proxy, routes, services, RDP or credential stores.
No downloads or external network operations.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
 [string]$ResearchRepository = '',
 [switch]$RunSourceTests,
 [string]$UnsignedDriverPath = '',
 [string]$UnsignedInfPath = '',
 [string]$BrokerPath = '',
 [string]$ReportRoot = "$env:ProgramData\FlowBridge\R39-Evidence",
 [switch]$SkipLoopback
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$folder=Join-Path ([IO.Path]::GetFullPath($ReportRoot)) ('win10-'+$stamp+'-pid'+$PID)
$null=New-Item -ItemType Directory -Path $folder -Force
$warnings=New-Object 'System.Collections.Generic.List[string]'
function Warn([string]$s){$warnings.Add($s);Write-Warning $s}
function Tool([string]$n) {
 $c=Get-Command $n -ErrorAction SilentlyContinue|Select-Object -First 1
 if($null -eq $c){return [ordered]@{found=$false;path=''}}
 return [ordered]@{found=$true;path=[string]$c.Source}
}
function Hash([string]$file){return (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()}
function Inspect([string]$file,[string]$expected) {
 if(-not(Test-Path -LiteralPath $file -PathType Leaf)){
    return [ordered]@{exists=$false;expected_sha256=$expected;match=$false}
 }
 $sha=Hash $file
 $sig=Get-AuthenticodeSignature -LiteralPath $file
 return [ordered]@{
   exists=$true;sha256=$sha;expected_sha256=$expected;match=($sha -eq $expected)
   signature_status=[string]$sig.Status
   signer=$(if($sig.SignerCertificate){[string]$sig.SignerCertificate.Subject}else{''})
 }
}
function Loopback([string]$ipString){
 $listen=$null;$client=$null;$other=$null
 try {
  $ip=[Net.IPAddress]::Parse($ipString)
  $listen=New-Object Net.Sockets.TcpListener -ArgumentList $ip,0
  $listen.Start(1)
  $port=([Net.IPEndPoint]$listen.LocalEndpoint).Port
  $client=New-Object Net.Sockets.TcpClient -ArgumentList $ip.AddressFamily
  $client.Connect($ip,$port)
  $other=$listen.AcceptTcpClient()
  $a=$client.GetStream();$b=$other.GetStream()
  $a.ReadTimeout=3000;$b.ReadTimeout=3000
  $data=[Text.Encoding]::ASCII.GetBytes('FB-R39-LOOPBACK')
  $a.Write($data,0,$data.Length)
  $read=New-Object byte[] $data.Length
  $n=0
  while($n -lt $data.Length){
   $k=$b.Read($read,$n,$read.Length-$n)
   if($k -le 0){throw 'socket closed before echo'}
   $n+=$k
  }
  $b.Write($read,0,$n)
  $echo=New-Object byte[] $data.Length
  $n=0
  while($n -lt $data.Length){
   $k=$a.Read($echo,$n,$echo.Length-$n)
   if($k -le 0){throw 'socket closed before echo return'}
   $n+=$k
  }
  if([Convert]::ToBase64String($data) -cne [Convert]::ToBase64String($echo)){throw 'echo bytes differ'}
  return [ordered]@{address=$ipString;pass=$true;bytes=$n;error=''}
 }catch{
  return [ordered]@{address=$ipString;pass=$false;bytes=0;error=$_.Exception.Message}
 }finally{
  if($other){$other.Close()}
  if($client){$client.Close()}
  if($listen){$listen.Stop()}
 }
}
$report=[ordered]@{
 schema='flowbridge-win10-r39-admin-evidence-v3'
 timestamp_utc=[DateTime]::UtcNow.ToString('o')
 expected_host=$ExpectedComputerName
 actual_host=$env:COMPUTERNAME
 hostname_match=($ExpectedComputerName -ieq $env:COMPUTERNAME)
 identity=[ordered]@{account='';elevated=$false;integrity='unknown'}
 windows=[ordered]@{product='';version='';build='';ubr=$null;x64=[Environment]::Is64BitOperatingSystem}
 hardware=[ordered]@{ram_gb=$null;free_ram_gb=$null;logical_processors=$null;free_disk_gb=$null}
 security=[ordered]@{secure_boot='unknown';testsigning='unknown';device_guard='unknown';bitlocker='unknown';defender='unknown'}
 services=[ordered]@{bfe='unknown';mpssvc='unknown';flowbridge_names=@()}
 executables=[ordered]@{}
 sdk=[ordered]@{msvc_cl_count=0;signtool_count=0;inf2cat_count=0}
 pinned_files=[ordered]@{}
 loopback=@()
 source=[ordered]@{local_checkout='';head='';clean=$null;research_branch=$false}
 rust_tests=@()
 gates=[ordered]@{W0='NOT_ACCEPTED';W1='NOT_RUN';W2='NOT_RUN';W3='NO_GO';W4='NO_GO';W5='NO_GO';G2='NO_GO';release='NO_GO'}
 guardrails=[ordered]@{
  driver_installed=$false;driver_loaded=$false;wfp_filters_modified=$false
  testsigning_modified=$false;secure_boot_modified=$false;defender_modified=$false
  firewall_modified=$false;dns_or_route_modified=$false;service_modified=$false
  remote_network_called=$false;vnc_rollback_verified=$false;egress_observer_verified=$false
 }
 warnings=@()
}
$testLogs=New-Object 'System.Collections.Generic.List[string]'
try {
 if($env:OS -ne 'Windows_NT'){throw 'Windows required'}
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 $principal=New-Object Security.Principal.WindowsPrincipal -ArgumentList $id
 $report.identity.account=[string]$id.Name
 $report.identity.elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 $groups=(& whoami.exe /groups 2>$null|Out-String)
 if($groups -match 'S-1-16-12288'){$report.identity.integrity='high'}
 elseif($groups -match 'S-1-16-8192'){$report.identity.integrity='medium'}
 elseif($groups -match 'S-1-16-4096'){$report.identity.integrity='low'}
 if(-not $report.hostname_match){Warn 'Unexpected computer name, W0 remains NOT_ACCEPTED'}
 if(-not $report.identity.elevated){Warn 'Shell is not elevated (UAC), W0 remains NOT_ACCEPTED'}
 try {
  $reg=Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $report.windows.product=[string]$reg.ProductName
  $report.windows.version=[string]$reg.DisplayVersion
  $report.windows.build=[string]$reg.CurrentBuild
  $report.windows.ubr=[int]$reg.UBR
 }catch{Warn 'OS registry access unavailable'}
 try{
  $os=Get-CimInstance Win32_OperatingSystem
  $report.windows.product=[string]$os.Caption
  $report.windows.build=[string]$os.BuildNumber
  $report.hardware.free_ram_gb=[Math]::Round(([double]$os.FreePhysicalMemory*1024)/1GB,2)
 }catch{Warn 'CIM OS query unavailable; retained registry fallback'}
 try{
  $cs=Get-CimInstance Win32_ComputerSystem
  $report.hardware.ram_gb=[Math]::Round([double]$cs.TotalPhysicalMemory/1GB,2)
  $report.hardware.logical_processors=[int]$cs.NumberOfLogicalProcessors
 }catch{Warn 'CIM computer system query unavailable'}
 try{
  $disk=Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':'))
  $report.hardware.free_disk_gb=[Math]::Round([double]$disk.Free/1GB,2)
 }catch{Warn 'System drive capacity unavailable'}
 try {
  $sb=Confirm-SecureBootUEFI -ErrorAction Stop
  $report.security.secure_boot=$(if($sb){'on'}else{'off'})
 }catch{$report.security.secure_boot='unknown_or_unsupported'}
 try {
  $bcd=(& "$env:SystemRoot\System32\bcdedit.exe" /enum '{current}' 2>$null|Out-String)
  if($LASTEXITCODE -eq 0){
    if($bcd -match '(?im)^\s*testsigning\s+(\S+)\s*
  }
 }catch{$report.security.testsigning='unavailable'}
 try{
  $dg=Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -Class Win32_DeviceGuard
  $report.security.device_guard=(@($dg.SecurityServicesRunning) -join ',')
 }catch{$report.security.device_guard='unavailable'}
 try{$bit=Get-BitLockerVolume -MountPoint $env:SystemDrive;$report.security.bitlocker=[string]$bit.ProtectionStatus}catch{$report.security.bitlocker='unavailable'}
 try{$mp=Get-MpComputerStatus;$report.security.defender=$(if($mp.RealTimeProtectionEnabled){'realtime_on'}else{'realtime_off'})}catch{$report.security.defender='unavailable'}
 foreach($n in @('BFE','MpsSvc')){
  try{$report.services[$n.ToLowerInvariant()]=[string](Get-Service -Name $n).Status}
  catch{$report.services[$n.ToLowerInvariant()]='unavailable'}
 }
 try{
  $report.services.flowbridge_names=@(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services'|
    Where-Object {$_.PSChildName -like 'FlowBridge*'}|
    ForEach-Object {$_.PSChildName})
 }catch{Warn 'FlowBridge service registry query unavailable'}
 foreach($tool in @('git.exe','rustc.exe','cargo.exe','rustup.exe','python.exe',
    'pwsh.exe','cmake.exe','node.exe','cl.exe','link.exe','signtool.exe',
    'inf2cat.exe','ssh.exe','sshd.exe','winget.exe')){
  $report.executables[$tool]=Tool $tool
 }
 try{
  $pf86=[Environment]::GetFolderPath('ProgramFilesX86')
  $sdk=Join-Path $pf86 'Windows Kits\10\bin'
  if(Test-Path $sdk){
   $report.sdk.signtool_count=@(Get-ChildItem $sdk -Filter signtool.exe -Recurse -File -ErrorAction SilentlyContinue).Count
   $report.sdk.inf2cat_count=@(Get-ChildItem $sdk -Filter inf2cat.exe -Recurse -File -ErrorAction SilentlyContinue).Count
  }
  $vs=Join-Path $pf86 'Microsoft Visual Studio\2022'
  if(Test-Path $vs){
   $report.sdk.msvc_cl_count=@(Get-ChildItem $vs -Filter cl.exe -Recurse -File -ErrorAction SilentlyContinue).Count
  }
 }catch{Warn 'SDK/WDK/MSVC discovery incomplete'}
 foreach($file in @(
   @{key='unsigned_sys';path=$UnsignedDriverPath;hash='c613fd1d98a9a4e22d6551f07143c7821263df2732c3e25bae2543b1ca7d4c00'},
   @{key='unsigned_inf';path=$UnsignedInfPath;hash='29b62d0272436d62098d2514a6586db171261faaa58c9ac31a271518f3c5fbdd'},
   @{key='broker_exe';path=$BrokerPath;hash='295bc4b74c42e95f3f94d7576bfba7a4e1aeee4e2ba52dc2c84f007d703ac2bb'}
 )){
   if($file.path){
    $report.pinned_files[$file.key]=Inspect $file.path $file.hash
    if(-not $report.pinned_files[$file.key].match){Warn ('Missing or invalid pinned R39 '+$file.key)}
   }
 }
 if(-not $SkipLoopback){
  foreach($ip in @('127.0.0.1','::1')){$report.loopback+=@(Loopback $ip)}
 }
 if($ResearchRepository){
  $root=[IO.Path]::GetFullPath($ResearchRepository)
  $report.source.local_checkout=$root
  if(Test-Path (Join-Path $root '.git') -PathType Container){
   if($report.executables['git.exe'].found){
    $report.source.head=(& git.exe -C $root rev-parse HEAD 2>$null|Select-Object -First 1)
    $branch=(& git.exe -C $root branch --show-current 2>$null|Select-Object -First 1)
    $changes=@(& git.exe -C $root status --porcelain --untracked-files=no 2>$null)
    $report.source.clean=($changes.Count -eq 0)
    $report.source.research_branch=($branch -eq 'research/windows-wfp-ale-attribution-20261107')
   }
  }else{Warn 'ResearchRepository is not a local git checkout'}
 }
 if($RunSourceTests){
  $report.gates.W1='INCOMPLETE'
  if(-not $ResearchRepository){Warn 'RunSourceTests requires -ResearchRepository'}
  elseif($report.source.clean -ne $true){Warn 'RunSourceTests requires clean reviewed repository'}
  elseif($report.source.research_branch -ne $true){Warn 'RunSourceTests requires approved research branch'}
  elseif(-not $report.executables['rustc.exe'].found){Warn 'rustc unavailable'}
  else{
   $all=$true
   foreach($t in @(
      @{name='handoff';relative='research/wfp-ale/kernel-r19/kernel/src/handoff.rs'},
      @{name='ledger';relative='research/wfp-ale/kernel-r19/kernel/src/ledger.rs'},
      @{name='auth_appid';relative='research/wfp-ale/kernel-r19/kernel/src/auth_appid.rs'},
      @{name='broker_lifecycle';relative='research/wfp-ale/kernel-r19/broker_lifecycle.rs'}
    )){
    $source=Join-Path $report.source.local_checkout $t.relative
    $binary=Join-Path $folder ($t.name+'-test.exe')
    $log=Join-Path $folder ($t.name+'-test.log')
    if(-not(Test-Path $source -PathType Leaf)){
      $report.rust_tests+=@([ordered]@{name=$t.name;status='SOURCE_MISSING'})
      $all=$false;continue
    }
    & rustc.exe --edition=2021 --test $source -o $binary *> $log
    $exit=$LASTEXITCODE
    if($exit -eq 0){& $binary --test-threads=1 *>> $log;$exit=$LASTEXITCODE}
    $ok=($exit -eq 0)
    if(-not $ok){$all=$false;Warn ('Source model test failed '+$t.name)}
    $report.rust_tests+=@([ordered]@{name=$t.name;status=$(if($ok){'PASS'}else{'FAIL'});exit=$exit;log=[IO.Path]::GetFileName($log)})
   }
   if($all){$report.gates.W1='USERMODE_UNIT_PASS_ONLY'}
  }
 }
 $isWin10Pro=($report.windows.product -match 'Windows 10' -and $report.windows.product -match 'Pro')
 if($report.hostname_match -and $report.identity.elevated -and
    $report.windows.x64 -and $report.windows.build -eq '19045' -and $isWin10Pro){
    $report.gates.W0='READONLY_HOST_CONFIRMED'
 }else{Warn 'Host/OS/UAC guard does not admit W0'}
}catch{
 Warn ('Audit error: '+$_.Exception.Message)
}finally{
 $report.warnings=@($warnings.ToArray())
 $report.timestamp_finished_utc=[DateTime]::UtcNow.ToString('o')
 $reportPath=Join-Path $folder 'inventory.json'
 [IO.File]::WriteAllText($reportPath,($report|ConvertTo-Json -Depth 15),[Text.UTF8Encoding]::new($false))
 $summary=Join-Path $folder 'summary.txt'
 $text=@('FlowBridge Win10 Pro elevated read-only audit',
  ('Actual host: '+$report.actual_host),
  ('Windows: '+$report.windows.product+' build '+$report.windows.build),
  ('Elevated: '+$report.identity.elevated),
  ('W0: '+$report.gates.W0),
  ('W1: '+$report.gates.W1),
  'W2: NOT_RUN','W3-W5: NO_GO','G2: NO_GO','Release: NO_GO',
  'No driver installed/loaded; no system networking/security settings changed.')
 [IO.File]::WriteAllLines($summary,$text,[Text.UTF8Encoding]::new($false))
 $sha=Join-Path $folder 'sha256.txt'
 $hashes=@(Get-ChildItem -LiteralPath $folder -File |
   Where-Object {$_.Name -ne 'sha256.txt'} |
   Sort-Object Name |
   ForEach-Object {(Hash $_.FullName)+'  '+$_.Name})
 [IO.File]::WriteAllLines($sha,$hashes,[Text.UTF8Encoding]::new($false))
 $zip=$folder+'.zip'
 try{Compress-Archive -Path (Join-Path $folder '*') -DestinationPath $zip -Force}
 catch{Write-Warning ('ZIP failed; JSON remains: '+$_.Exception.Message)}
 Write-Host ('W0: '+$report.gates.W0+', W1: '+$report.gates.W1+', W3: NO_GO')
 Write-Host ('JSON: '+$reportPath)
 if(Test-Path $zip){Write-Host ('ZIP: '+$zip);Write-Host ('ZIP SHA256: '+(Hash $zip))}
 Write-Host 'Review the report before sharing; it contains local host and toolchain metadata.'
}
){$report.security.testsigning=[string]$Matches[1]}
    else{$report.security.testsigning='not_listed'}
  }
 }catch{$report.security.testsigning='unavailable'}
 try{
  $dg=Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -Class Win32_DeviceGuard
  $report.security.device_guard=(@($dg.SecurityServicesRunning) -join ',')
 }catch{$report.security.device_guard='unavailable'}
 try{$bit=Get-BitLockerVolume -MountPoint $env:SystemDrive;$report.security.bitlocker=[string]$bit.ProtectionStatus}catch{$report.security.bitlocker='unavailable'}
 try{$mp=Get-MpComputerStatus;$report.security.defender=$(if($mp.RealTimeProtectionEnabled){'realtime_on'}else{'realtime_off'})}catch{$report.security.defender='unavailable'}
 foreach($n in @('BFE','MpsSvc')){
  try{$report.services[$n.ToLowerInvariant()]=[string](Get-Service -Name $n).Status}
  catch{$report.services[$n.ToLowerInvariant()]='unavailable'}
 }
 try{
  $report.services.flowbridge_names=@(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services'|
    Where-Object {$_.PSChildName -like 'FlowBridge*'}|
    ForEach-Object {$_.PSChildName})
 }catch{Warn 'FlowBridge service registry query unavailable'}
 foreach($tool in @('git.exe','rustc.exe','cargo.exe','rustup.exe','python.exe',
    'pwsh.exe','cmake.exe','node.exe','cl.exe','link.exe','signtool.exe',
    'inf2cat.exe','ssh.exe','sshd.exe','winget.exe')){
  $report.executables[$tool]=Tool $tool
 }
 try{
  $pf86=[Environment]::GetFolderPath('ProgramFilesX86')
  $sdk=Join-Path $pf86 'Windows Kits\10\bin'
  if(Test-Path $sdk){
   $report.sdk.signtool_count=@(Get-ChildItem $sdk -Filter signtool.exe -Recurse -File -ErrorAction SilentlyContinue).Count
   $report.sdk.inf2cat_count=@(Get-ChildItem $sdk -Filter inf2cat.exe -Recurse -File -ErrorAction SilentlyContinue).Count
  }
  $vs=Join-Path $pf86 'Microsoft Visual Studio\2022'
  if(Test-Path $vs){
   $report.sdk.msvc_cl_count=@(Get-ChildItem $vs -Filter cl.exe -Recurse -File -ErrorAction SilentlyContinue).Count
  }
 }catch{Warn 'SDK/WDK/MSVC discovery incomplete'}
 foreach($file in @(
   @{key='unsigned_sys';path=$UnsignedDriverPath;hash='c613fd1d98a9a4e22d6551f07143c7821263df2732c3e25bae2543b1ca7d4c00'},
   @{key='unsigned_inf';path=$UnsignedInfPath;hash='29b62d0272436d62098d2514a6586db171261faaa58c9ac31a271518f3c5fbdd'},
   @{key='broker_exe';path=$BrokerPath;hash='295bc4b74c42e95f3f94d7576bfba7a4e1aeee4e2ba52dc2c84f007d703ac2bb'}
 )){
   if($file.path){
    $report.pinned_files[$file.key]=Inspect $file.path $file.hash
    if(-not $report.pinned_files[$file.key].match){Warn ('Missing or invalid pinned R39 '+$file.key)}
   }
 }
 if(-not $SkipLoopback){
  foreach($ip in @('127.0.0.1','::1')){$report.loopback+=@(Loopback $ip)}
 }
 if($ResearchRepository){
  $root=[IO.Path]::GetFullPath($ResearchRepository)
  $report.source.local_checkout=$root
  if(Test-Path (Join-Path $root '.git') -PathType Container){
   if($report.executables['git.exe'].found){
    $report.source.head=(& git.exe -C $root rev-parse HEAD 2>$null|Select-Object -First 1)
    $branch=(& git.exe -C $root branch --show-current 2>$null|Select-Object -First 1)
    $changes=@(& git.exe -C $root status --porcelain --untracked-files=no 2>$null)
    $report.source.clean=($changes.Count -eq 0)
    $report.source.research_branch=($branch -eq 'research/windows-wfp-ale-attribution-20261107')
   }
  }else{Warn 'ResearchRepository is not a local git checkout'}
 }
 if($RunSourceTests){
  $report.gates.W1='INCOMPLETE'
  if(-not $ResearchRepository){Warn 'RunSourceTests requires -ResearchRepository'}
  elseif($report.source.clean -ne $true){Warn 'RunSourceTests requires clean reviewed repository'}
  elseif($report.source.research_branch -ne $true){Warn 'RunSourceTests requires approved research branch'}
  elseif(-not $report.executables['rustc.exe'].found){Warn 'rustc unavailable'}
  else{
   $all=$true
   foreach($t in @(
      @{name='handoff';relative='research/wfp-ale/kernel-r19/kernel/src/handoff.rs'},
      @{name='ledger';relative='research/wfp-ale/kernel-r19/kernel/src/ledger.rs'},
      @{name='auth_appid';relative='research/wfp-ale/kernel-r19/kernel/src/auth_appid.rs'},
      @{name='broker_lifecycle';relative='research/wfp-ale/kernel-r19/broker_lifecycle.rs'}
    )){
    $source=Join-Path $report.source.local_checkout $t.relative
    $binary=Join-Path $folder ($t.name+'-test.exe')
    $log=Join-Path $folder ($t.name+'-test.log')
    if(-not(Test-Path $source -PathType Leaf)){
      $report.rust_tests+=@([ordered]@{name=$t.name;status='SOURCE_MISSING'})
      $all=$false;continue
    }
    & rustc.exe --edition=2021 --test $source -o $binary *> $log
    $exit=$LASTEXITCODE
    if($exit -eq 0){& $binary --test-threads=1 *>> $log;$exit=$LASTEXITCODE}
    $ok=($exit -eq 0)
    if(-not $ok){$all=$false;Warn ('Source model test failed '+$t.name)}
    $report.rust_tests+=@([ordered]@{name=$t.name;status=$(if($ok){'PASS'}else{'FAIL'});exit=$exit;log=[IO.Path]::GetFileName($log)})
   }
   if($all){$report.gates.W1='USERMODE_UNIT_PASS_ONLY'}
  }
 }
 $isWin10Pro=($report.windows.product -match 'Windows 10' -and $report.windows.product -match 'Pro')
 if($report.hostname_match -and $report.identity.elevated -and
    $report.windows.x64 -and $report.windows.build -eq '19045' -and $isWin10Pro){
    $report.gates.W0='READONLY_HOST_CONFIRMED'
 }else{Warn 'Host/OS/UAC guard does not admit W0'}
}catch{
 Warn ('Audit error: '+$_.Exception.Message)
}finally{
 $report.warnings=@($warnings.ToArray())
 $report.timestamp_finished_utc=[DateTime]::UtcNow.ToString('o')
 $reportPath=Join-Path $folder 'inventory.json'
 [IO.File]::WriteAllText($reportPath,($report|ConvertTo-Json -Depth 15),[Text.UTF8Encoding]::new($false))
 $summary=Join-Path $folder 'summary.txt'
 $text=@('FlowBridge Win10 Pro elevated read-only audit',
  ('Actual host: '+$report.actual_host),
  ('Windows: '+$report.windows.product+' build '+$report.windows.build),
  ('Elevated: '+$report.identity.elevated),
  ('W0: '+$report.gates.W0),
  ('W1: '+$report.gates.W1),
  'W2: NOT_RUN','W3-W5: NO_GO','G2: NO_GO','Release: NO_GO',
  'No driver installed/loaded; no system networking/security settings changed.')
 [IO.File]::WriteAllLines($summary,$text,[Text.UTF8Encoding]::new($false))
 $sha=Join-Path $folder 'sha256.txt'
 $hashes=@(Get-ChildItem -LiteralPath $folder -File |
   Where-Object {$_.Name -ne 'sha256.txt'} |
   Sort-Object Name |
   ForEach-Object {(Hash $_.FullName)+'  '+$_.Name})
 [IO.File]::WriteAllLines($sha,$hashes,[Text.UTF8Encoding]::new($false))
 $zip=$folder+'.zip'
 try{Compress-Archive -Path (Join-Path $folder '*') -DestinationPath $zip -Force}
 catch{Write-Warning ('ZIP failed; JSON remains: '+$_.Exception.Message)}
 Write-Host ('W0: '+$report.gates.W0+', W1: '+$report.gates.W1+', W3: NO_GO')
 Write-Host ('JSON: '+$reportPath)
 if(Test-Path $zip){Write-Host ('ZIP: '+$zip);Write-Host ('ZIP SHA256: '+(Hash $zip))}
 Write-Host 'Review the report before sharing; it contains local host and toolchain metadata.'
}
