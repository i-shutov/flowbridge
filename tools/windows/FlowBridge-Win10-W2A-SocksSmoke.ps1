#requires -version 5.1
<#
FlowBridge W2a: source-pinned native Windows user-mode CLI + loopback SOCKS5 smoke.
No driver, WFP, BFE, registry/services/firewall/DNS/route changes, SSH credentials,
real user proxy, auto-start or installer. GitHub and crates.io downloads only.
Downloads/build files and logs are restricted to a fresh evidence subdirectory.
Default permits only an exact Windows 10 x64 build 19045 target + expected host.
Explicit AllowHostedCI permits an isolated Windows GitHub runner but reports
HOSTED_NON_TARGET, never acceptance of the user's actual Windows 10 machine.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
  [string]$EvidenceRoot = "$env:ProgramData\FlowBridge\W2A-Evidence",
  [switch]$AllowHostedCI,
  [switch]$ToolDiscoveryOnly,
  [switch]$ForcePowerShellSmoke,
  [string]$RustBinDirectory = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$sourceSha='c339df2e4d20edf1d11d45786581a68451a71929'
$branch='integration/windows-rust-capture-agent-20261031'
$origin='https://github.com/i-shutov/flowbridge.git'
function SHA256([string]$path){(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
function FindCmd([string]$name){
 # W1 already supports per-user rustc under %USERPROFILE%\.cargo\bin.
 # W2a must discover Cargo the same way: PATH alone misses rustup shims
 # installed without a new login session. Never alter global/user PATH.
 $x=Get-Command $name -CommandType Application -ErrorAction SilentlyContinue|Select-Object -First 1
 if($null -ne $x){
   $candidate=[string]$x.Source
   if($candidate -notmatch '[\\/]WindowsApps[\\/](python|python3)\.exe$'){
     return $candidate
   }
 }
 if($name -in @('cargo.exe','rustc.exe','rustup.exe')){
   $folders=New-Object 'System.Collections.Generic.List[string]'
   if($RustBinDirectory){$folders.Add($RustBinDirectory)}
   if($env:CARGO_HOME){$folders.Add((Join-Path $env:CARGO_HOME 'bin'))}
   if($env:USERPROFILE){$folders.Add((Join-Path $env:USERPROFILE '.cargo\bin'))}
   foreach($dir in $folders){
     $candidate=Join-Path $dir $name
     if(Test-Path -LiteralPath $candidate -PathType Leaf){
       return [IO.Path]::GetFullPath($candidate)
     }
   }
 }
 return ''
}

# Self-contained subset of tests/smoke.py. No Python/SSH/WFP or external sockets.
function Read-Exact([System.IO.Stream]$stream,[int]$size){
 $bytes=New-Object byte[] $size;$read=0
 while($read -lt $size){
  $got=$stream.Read($bytes,$read,$size-$read)
  if($got -le 0){throw "Socket closed before $size bytes"}
  $read+=$got
 }
 return ,$bytes
}
function Free-LoopbackPort {
 $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
 try{$listener.Start();return ([Net.IPEndPoint]$listener.LocalEndpoint).Port}
 finally{$listener.Stop()}
}
function Connect-Socks([int]$port,[int]$command,[string]$host,[int]$destPort){
 $client=New-Object Net.Sockets.TcpClient
 try{
  $client.ReceiveTimeout=5000;$client.SendTimeout=5000
  $client.Connect([Net.IPAddress]::Loopback,$port)
  $stream=$client.GetStream();$stream.ReadTimeout=5000;$stream.WriteTimeout=5000
  [byte[]]$hello=@(5,1,0);$stream.Write($hello,0,$hello.Length)
  [byte[]]$method=Read-Exact $stream 2
  if($method[0] -ne 5 -or $method[1] -ne 0){throw 'SOCKS5 no-auth negotiation failed'}
  $name=[Text.Encoding]::ASCII.GetBytes($host)
  if($name.Length -lt 1 -or $name.Length -gt 250){throw 'Invalid fixture hostname'}
  $data=[System.Collections.Generic.List[byte]]::new()
  $data.AddRange([byte[]]@(5,$command,0,3,$name.Length))
  $data.AddRange([byte[]]$name)
  $data.Add([byte]($destPort -shr 8));$data.Add([byte]($destPort -band 255))
  $request=$data.ToArray();$stream.Write($request,0,$request.Length)
  [byte[]]$reply=Read-Exact $stream 4
  if($reply[0] -ne 5){throw 'Non-SOCKS5 reply'}
  $addressBytes=0
  switch([int]$reply[3]){
    1 {$addressBytes=6}
    4 {$addressBytes=18}
    3 {[byte[]]$len=Read-Exact $stream 1;$addressBytes=[int]$len[0]+2}
    default {throw 'Invalid SOCKS5 reply address type'}
  }
  [void](Read-Exact $stream $addressBytes)
  return [pscustomobject]@{client=$client;stream=$stream;code=[int]$reply[1]}
 }catch{$client.Close();throw}
}
function Start-SocksCli([string]$exe,[int]$listenPort,[string]$label,[hashtable]$profile){
 $cfg=Join-Path $work ('ps-socks-'+$label+'.json')
 $profile.listen="127.0.0.1:$listenPort"
 $json=$profile|ConvertTo-Json -Depth 12
 [IO.File]::WriteAllText($cfg,$json,[Text.UTF8Encoding]::new($false))
 $stdout=Join-Path $work ('ps-socks-'+$label+'.stdout.log')
 $stderr=Join-Path $work ('ps-socks-'+$label+'.stderr.log')
 $proc=Start-Process -FilePath $exe -ArgumentList @('serve','--config',('"'+$cfg+'"')) -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
 $owned.Add($proc)
 $ready=$false;$deadline=[DateTime]::UtcNow.AddSeconds(12)
 while([DateTime]::UtcNow -lt $deadline){
  if($proc.HasExited){throw "CLI exited before listening ($label), inspect stderr log"}
  $probe=New-Object Net.Sockets.TcpClient
  try{$probe.Connect([Net.IPAddress]::Loopback,$listenPort);$ready=$true;break}
  catch{Start-Sleep -Milliseconds 100}
  finally{$probe.Close()}
 }
 if(-not $ready){throw "CLI listener readiness timeout ($label)"}
}
function Invoke-PSSocksSmoke([string]$exe){
 $owned=New-Object 'System.Collections.Generic.List[System.Diagnostics.Process]'
 $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
 $checks=New-Object 'System.Collections.Generic.List[string]'
 try{
  $listener.Start(4);$targetPort=([Net.IPEndPoint]$listener.LocalEndpoint).Port
  $base=@{
    version=1;listen='127.0.0.1:0';proxies=@();chains=@();rules=@()
    default_action=@{type='direct'};connect_timeout_ms=1500
    handshake_timeout_ms=1500;idle_timeout_ms=5000;max_connections=16
  }
  $directPort=Free-LoopbackPort
  Start-SocksCli $exe $directPort 'direct' $base
  $exchange=Connect-Socks $directPort 1 '127.0.0.1' $targetPort
  try{
    if($exchange.code -ne 0){throw "SOCKS CONNECT failed with code $($exchange.code)"}
    if(-not $listener.Server.Poll(8000000,[Net.Sockets.SelectMode]::SelectRead)){throw 'Local target was never contacted'}
    $accepted=$listener.AcceptTcpClient()
    try{
      $accepted.ReceiveTimeout=5000;$accepted.SendTimeout=5000
      $targetStream=$accepted.GetStream();$targetStream.ReadTimeout=5000;$targetStream.WriteTimeout=5000
      [byte[]]$payload=0..255
      $exchange.stream.Write($payload,0,$payload.Length)
      [byte[]]$arrived=Read-Exact $targetStream $payload.Length
      if([Convert]::ToBase64String($arrived) -cne [Convert]::ToBase64String($payload)){throw 'SOCKS relay corrupted target bytes'}
      $targetStream.Write($arrived,0,$arrived.Length)
      [byte[]]$echo=Read-Exact $exchange.stream $payload.Length
      if([Convert]::ToBase64String($echo) -cne [Convert]::ToBase64String($payload)){throw 'SOCKS relay corrupted echo bytes'}
      $checks.Add('real_socks5_connect_binary_roundtrip_256_bytes')
    }finally{$accepted.Close()}
  }finally{$exchange.client.Close()}
  $udp=Connect-Socks $directPort 3 '127.0.0.1' $targetPort
  try{
    if($udp.code -ne 7){throw "UDP ASSOCIATE not rejected with code 7 (got $($udp.code))"}
    $checks.Add('udp_associate_rejected')
  }finally{$udp.client.Close()}
  $blockCfg=$base.Clone();$blockCfg.default_action=@{type='block'}
  $blockPort=Free-LoopbackPort
  Start-SocksCli $exe $blockPort 'block' $blockCfg
  $blocked=Connect-Socks $blockPort 1 '127.0.0.1' $targetPort
  try{
    if($blocked.code -ne 2){throw "BLOCK policy not rejected with code 2 (got $($blocked.code))"}
    if($listener.Pending()){throw 'BLOCK unexpectedly contacted target'}
    $checks.Add('policy_block_does_not_dial_target')
  }finally{$blocked.client.Close()}
  $deadCfg=$base.Clone();$deadPort=Free-LoopbackPort
  $deadCfg.proxies=@(@{id='dead';kind='socks5';endpoint=@{host='127.0.0.1';port=$deadPort};username=$null;password_env=$null})
  $deadCfg.default_action=@{type='proxy';id='dead'}
  $viaPort=Free-LoopbackPort
  Start-SocksCli $exe $viaPort 'deadproxy' $deadCfg
  $noUpstream=Connect-Socks $viaPort 1 '127.0.0.1' $targetPort
  try{
    if($noUpstream.code -eq 0){throw 'Unavailable SOCKS upstream incorrectly returned success'}
    if($listener.Pending()){throw 'Failed upstream fell back to DIRECT target'}
    $checks.Add('failed_upstream_no_direct_fallback')
  }finally{$noUpstream.client.Close()}
  $log=Join-Path $work 'ps-socks-smoke.json'
  [IO.File]::WriteAllText($log,($checks.ToArray()|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
  return [ordered]@{ok=$true;count=$checks.Count;names=@($checks.ToArray());engine='powershell-native-dotnet'}
 }finally{
  $listener.Stop()
  foreach($process in $owned){
    try{if(-not $process.HasExited){$process.Kill();$process.WaitForExit(5000)|Out-Null}}catch{}
    try{$process.Dispose()}catch{}
  }
 }
}

function Native([string]$exe,[string[]]$argv,[string]$cwd,[string]$stem,[int]$timeout=900){
 $psi=New-Object Diagnostics.ProcessStartInfo
 $psi.FileName=$exe
 $psi.Arguments=(($argv|ForEach-Object{'"'+($_.Replace('"','\"'))+'"'}) -join ' ')
 $psi.WorkingDirectory=$cwd
 $psi.UseShellExecute=$false
 $psi.CreateNoWindow=$true
 $psi.RedirectStandardOutput=$true
 $psi.RedirectStandardError=$true
 $outFile=Join-Path $work ($stem+'.stdout.log')
 $errFile=Join-Path $work ($stem+'.stderr.log')
 $p=New-Object Diagnostics.Process
 $p.StartInfo=$psi
 try{
   if(-not $p.Start()){throw ('cannot launch '+$stem)}
   $o=$p.StandardOutput.ReadToEndAsync()
   $e=$p.StandardError.ReadToEndAsync()
   $ok=$p.WaitForExit($timeout*1000)
   if(-not $ok){try{$p.Kill()}catch{};$p.WaitForExit()}
   $stdout=[string]$o.GetAwaiter().GetResult()
   $stderr=[string]$e.GetAwaiter().GetResult()
   [IO.File]::WriteAllText($outFile,$stdout,[Text.UTF8Encoding]::new($false))
   [IO.File]::WriteAllText($errFile,$stderr,[Text.UTF8Encoding]::new($false))
   return [ordered]@{ok=($ok -and $p.ExitCode -eq 0);exit_code=$p.ExitCode;timeout=(-not $ok);stdout=$stdout;stderr=$stderr}
 }finally{$p.Dispose()}
}
$now=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$root=[IO.Path]::GetFullPath($EvidenceRoot)
$work=Join-Path $root ('w2a-'+$now+'-'+$PID)
$null=New-Item -ItemType Directory -Path $work -Force
$errors=New-Object 'System.Collections.Generic.List[string]'
$report=[ordered]@{
 schema='flowbridge-win10-w2a-socks-cli-v1'
 target_hostname_expected=$ExpectedComputerName
 target_hostname_observed=$env:COMPUTERNAME
 target_match=($env:COMPUTERNAME -ieq $ExpectedComputerName)
 os_caption='';os_build='';x64=[Environment]::Is64BitOperatingSystem
 hosted_ci=$false;target_admitted=$false
 source_sha_expected=$sourceSha;source_sha_actual='';source_exact=$false
 rustc_version='';cargo_version='';git_version='';python_version=''
 smoke_engine='NOT_RUN';smoke_coverage='NOT_RUN';smoke_checks=@()
 tools=[ordered]@{git='';cargo='';rustc='';python='';python_launcher=$false}
 steps=@();smoke_tests_run=0;capabilities_explicit=$false
 W2a='NOT_STARTED';W2b='NOT_RUN';W3='NO_GO';G2='NO_GO'
 driver_loaded=$false;wfp_filters_modified=$false
 system_network_changed=$false;release_accepted=$false
 errors=@()
}
try{
 if($env:OS -ne 'Windows_NT'){throw 'Windows is required'}
 try{
   $os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
   $report.os_caption=[string]$os.Caption;$report.os_build=[string]$os.BuildNumber
 }catch{
   $reg=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
   $report.os_caption=[string]$reg.ProductName
   $report.os_build=[string]$reg.CurrentBuild
 }
 $report.hosted_ci=($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted')
 $win10=($report.os_build -eq '19045' -and $report.os_caption -match 'Windows 10')
 $report.target_admitted=($report.target_match -and $report.x64 -and $win10)
 if(-not $report.target_admitted){
   if(-not ($AllowHostedCI -and $report.hosted_ci)){throw 'Unexpected machine or Windows version; refusing executable tests'}
 }
 $git=FindCmd 'git.exe';$cargo=FindCmd 'cargo.exe'
 $rustc=FindCmd 'rustc.exe';$python=FindCmd 'python.exe'
 $pyLauncher=$false
 if(-not $python){$python=FindCmd 'py.exe';$pyLauncher=([bool]$python)}
 $report.tools=[ordered]@{
   git=$git;cargo=$cargo;rustc=$rustc;python=$python;python_launcher=$pyLauncher
 }
 $missing=New-Object 'System.Collections.Generic.List[string]'
 foreach($pair in @(@('git',$git),@('cargo',$cargo),@('rustc',$rustc))){
   if(-not $pair[1]){$missing.Add([string]$pair[0])}
 }
 if($missing.Count -gt 0){
   throw ('Missing executable(s): '+($missing -join ', ')+
     '. Probed PATH, supplied RustBinDirectory, CARGO_HOME/bin and USERPROFILE/.cargo/bin; no installation performed')
 }
 if($ToolDiscoveryOnly){
   $report.W2a='TOOLS_FOUND_ONLY_NOT_ACCEPTED'
   return
 }
 $v=Native $git @('--version') $work 'git-version' 30
 if(-not $v.ok){throw 'git version check failed'};$report.git_version=$v.stdout.Trim()
 $v=Native $rustc @('--version') $work 'rustc-version' 30
 if(-not $v.ok){throw 'rustc version check failed'};$report.rustc_version=$v.stdout.Trim()
 $v=Native $cargo @('--version') $work 'cargo-version' 30
 if(-not $v.ok){throw 'cargo version check failed'};$report.cargo_version=$v.stdout.Trim()
 if($python){
   try{
     $pythonVersionArgs=if($pyLauncher){@('-3','--version')}else{@('--version')}
     $v=Native $python $pythonVersionArgs $work 'python-version' 30
     if($v.ok){$report.python_version=($v.stdout+$v.stderr).Trim()}
     else{$python='';$report.tools.python=''}
   }catch{$python='';$report.tools.python=''}
 }
 $src=Join-Path $work 'src'
 $env:GIT_TERMINAL_PROMPT='0'
 $clone=Native $git @('clone','--single-branch','--depth','1','--no-tags','--branch',$branch,$origin,$src) $work 'git-clone' 240
 if(-not $clone.ok){throw 'Pinned-branch clone failed; see git-clone.stderr.log'}
 $rev=Native $git @('-C',$src,'rev-parse','HEAD') $work 'git-HEAD' 30
 if(-not $rev.ok){throw 'git rev-parse failed'}
 $report.source_sha_actual=$rev.stdout.Trim()
 if($report.source_sha_actual -ne $sourceSha){
   throw ('Source HEAD changed; expected '+$sourceSha+', got '+$report.source_sha_actual)
 }
 $report.source_exact=$true
 $report.steps+=@('exact_branch_head_verified')
 # Avoid changing pre-existing Cargo caches, tools, SSH or OS paths.
 $env:CARGO_HOME=Join-Path $work 'cargo-home'
 $env:CARGO_TARGET_DIR=Join-Path $work 'build'
 $build=Native $cargo @('build','--locked','-j','2','-p','flowbridge-cli','--bin','flowbridge') $src 'cargo-build' 900
 if(-not $build.ok){throw 'cargo build failed; see cargo-build.stderr.log'}
 $report.steps+=@('cargo_build_locked_pass')
 $exe=Join-Path $env:CARGO_TARGET_DIR 'debug\flowbridge.exe'
 if(-not(Test-Path -LiteralPath $exe -PathType Leaf)){throw 'Built native CLI executable missing'}
 $report.steps+=@('exe_sha256_'+(SHA256 $exe))
 $cap=Native $exe @('capabilities') $src 'cli-capabilities' 30
 if(-not $cap.ok){throw 'flowbridge capabilities failed'}
 $caps=$cap.stdout|ConvertFrom-Json
 if($caps.mode -ne 'explicit_loopback_socks5' -or $caps.transparent_interception -ne $false -or
    $caps.udp -ne $false -or $caps.system_kill_switch -ne $false){
    throw 'CLI capabilities contradict explicit beta scope'
 }
 $report.capabilities_explicit=$true
 $report.steps+=@('capabilities_explicit_only_pass')
 $env:FLOWBRIDGE_BIN=$exe
 if($python -and -not $ForcePowerShellSmoke){
   $pythonSmokeArgs=if($pyLauncher){@('-3','tests/smoke.py')}else{@('tests/smoke.py')}
   $smoke=Native $python $pythonSmokeArgs $src 'python-socks-smoke' 180
   if(-not $smoke.ok){throw 'Native SOCKS black-box smoke failed; see python-socks-smoke.stderr.log'}
   $raw=$smoke.stdout+[Environment]::NewLine+$smoke.stderr
   $m=[regex]::Match($raw,'Ran\s+(\d+)\s+tests')
   if(-not $m.Success -or [int]$m.Groups[1].Value -lt 1 -or $raw -notmatch 'OK'){
     throw 'Expected Python unittest positive summary missing'
   }
   $report.smoke_tests_run=[int]$m.Groups[1].Value
   $report.smoke_engine='python'
   $report.smoke_coverage='original_tests_smoke_py'
   $report.steps+=@('actual_loopback_python_socks_smoke_pass')
 }else{
   $psSmoke=Invoke-PSSocksSmoke $exe
   if(-not $psSmoke.ok -or $psSmoke.count -lt 4){throw 'Native PowerShell SOCKS smoke incomplete'}
   $report.smoke_tests_run=[int]$psSmoke.count
   $report.smoke_checks=@($psSmoke.names)
   $report.smoke_engine=$psSmoke.engine
   $report.smoke_coverage='powershell_four_test_subset_not_python_nine_tests'
   $report.steps+=@('actual_loopback_powershell_socks_smoke_pass')
 }
 if($report.target_admitted){$report.W2a='PASS_NATIVE_WIN10_USERMODE_CLI_ONLY'}
 else{$report.W2a='PASS_HOSTED_NON_TARGET_ONLY'}
}catch{
 $errors.Add($_.Exception.Message)
 if($report.W2a -eq 'NOT_STARTED'){$report.W2a='FAILED_OR_BLOCKED'}
}finally{
 $report.errors=@($errors.ToArray())
 $json=Join-Path $work 'w2a-report.json'
 [IO.File]::WriteAllText($json,($report|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
 $sha=Join-Path $work 'sha256.txt'
 # Large build/tree files are not included: only reproducible source commit and
 # small evidence logs are kept in SHA manifest and ZIP.
 $files=@(Get-ChildItem -LiteralPath $work -File)
 $rows=@($files|Sort-Object Name|ForEach-Object{(SHA256 $_.FullName)+'  '+$_.Name})
 [IO.File]::WriteAllLines($sha,$rows,[Text.UTF8Encoding]::new($false))
 $zip=$work+'.zip'
 try{Compress-Archive -Path (Join-Path $work '*.json'),(Join-Path $work '*.log'),$sha -DestinationPath $zip -Force -ErrorAction Stop}
 catch{Write-Warning ('Evidence ZIP failed: '+$_.Exception.Message)}
 Write-Host ('W2a: '+$report.W2a+'; W2b: NOT_RUN; W3/G2: NO_GO')
 Write-Host ('Report: '+$json)
 if(Test-Path $zip){Write-Host ('Evidence ZIP: '+$zip);Write-Host ('ZIP SHA256: '+(SHA256 $zip))}
 if($report.errors.Count){Write-Host ('Notes: '+($report.errors -join '; '))}
}
