#requires -version 5.1
<#
FlowBridge W2b1: isolate real Microsoft OpenSSH localhost authentication and
test actual managed FlowBridge SOCKS5->SSH->TCP data. NOT WFP, GUI, or release.
No Windows service, firewall, routing, machine DNS, system key, driver, or
Windows security change. Secret test keys deleted; logs never include keys.
Only exact W2a source SHA and executable receipt are trusted.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
 [string]$W2aEvidenceRoot="$env:ProgramData\FlowBridge\W2A-Evidence",
 [string]$ReportRoot="$env:ProgramData\FlowBridge\W2B-Evidence",
 [string]$FixtureArchive='',
 [switch]$AllowHostedCI
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$betaSha='c339df2e4d20edf1d11d45786581a68451a71929'
$fixtureSha='b67ff8becd203502190ec42ac7787c24c2cd3325ed7700485fe7a1c83d2a7957'
$fixtureUrl='https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.4.0.0p1-Preview/OpenSSH-Win64.zip'
function Hash([string]$path){(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Port {
 $x=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
 try{$x.Start();return ([Net.IPEndPoint]$x.LocalEndpoint).Port}finally{$x.Stop()}
}
function RequireSigned([string]$path){
 if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw ('Required SSH tool missing: '+[IO.Path]::GetFileName($path))}
 $sig=Get-AuthenticodeSignature -LiteralPath $path
 if($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate -or $sig.SignerCertificate.Subject -notmatch 'Microsoft'){
  throw ('Unverified SSH binary: '+[IO.Path]::GetFileName($path))
 }
}
function SecureTestFile([string]$path,[string]$sid){
 & "$env:SystemRoot\System32\icacls.exe" $path /inheritance:r /grant:r ("*"+$sid+":F") '*S-1-5-18:F' '*S-1-5-32-544:F' |Out-Null
 if($LASTEXITCODE -ne 0){throw 'Failed to restrict ephemeral test-file ACL'}
 & "$env:SystemRoot\System32\icacls.exe" $path /remove '*S-1-3-4' |Out-Null
}
function WaitLocal([int]$port,[Diagnostics.Process]$process,[int]$secs=20){
 $until=[DateTime]::UtcNow.AddSeconds($secs)
 while([DateTime]::UtcNow -lt $until){
  if($process.HasExited){throw ('Owned process exited before local TCP listener '+$port)}
  $probe=[Net.Sockets.TcpClient]::new()
  try{$probe.Connect([Net.IPAddress]::Loopback,$port);return}
  catch{Start-Sleep -Milliseconds 120}
  finally{$probe.Dispose()}
 }
 throw ('Local TCP listener '+$port+' readiness timed out')
}
function ReadExact([IO.Stream]$stream,[int]$count){
 $buf=New-Object byte[] $count;$n=0
 while($n -lt $count){
  $got=$stream.Read($buf,$n,$count-$n)
  if($got -le 0){throw ('EOF '+$n+'/'+$count)}
  $n+=$got
 }
 return ,$buf
}
function SockOpen([int]$port,[int]$targetPort){
 $c=[Net.Sockets.TcpClient]::new()
 try{
  $c.ReceiveTimeout=3500;$c.SendTimeout=3500
  $c.Connect([Net.IPAddress]::Loopback,$port)
  $s=$c.GetStream();$s.ReadTimeout=3500;$s.WriteTimeout=3500
  [byte[]]$greet=@(5,1,0);$s.Write($greet,0,$greet.Length)
  [byte[]]$method=ReadExact $s 2
  if($method[0] -ne 5 -or $method[1] -ne 0){throw 'SOCKS5 method mismatch'}
  [byte[]]$hostname=[Text.Encoding]::ASCII.GetBytes('127.0.0.1')
  $m=[System.Collections.Generic.List[byte]]::new()
  $m.AddRange([byte[]]@(5,1,0,3,$hostname.Length));$m.AddRange($hostname)
  $m.Add([byte]($targetPort -shr 8));$m.Add([byte]($targetPort -band 255))
  $raw=$m.ToArray();$s.Write($raw,0,$raw.Length)
  [byte[]]$reply=ReadExact $s 4
  switch([int]$reply[3]){
   1 {$rest=6}
   4 {$rest=18}
   3 {[byte[]]$len=ReadExact $s 1;$rest=[int]$len[0]+2}
   default {throw 'SOCKS5 ATYP invalid'}
  }
  [void](ReadExact $s $rest)
  return [pscustomobject]@{client=$c;stream=$s;reply=[int]$reply[1]}
 }catch{$c.Dispose();throw}
}
function RealEcho([int]$port,[int]$target,[Net.Sockets.TcpListener]$listener){
 $s=SockOpen $port $target
 try{
  if($s.reply -ne 0){throw ('SSH SOCKS not ready: reply '+$s.reply)}
  if(-not $listener.Server.Poll(4500000,[Net.Sockets.SelectMode]::SelectRead)){throw 'Remote SSH did not reach target'}
  $peer=$listener.AcceptTcpClient()
  try{
   $peer.ReceiveTimeout=3500;$peer.SendTimeout=3500
   $ps=$peer.GetStream();$ps.ReadTimeout=3500;$ps.WriteTimeout=3500
   [byte[]]$bytes=[Text.Encoding]::ASCII.GetBytes('FB-W2B1-REAL-SSH')
   $s.stream.Write($bytes,0,$bytes.Length)
   [byte[]]$received=ReadExact $ps $bytes.Length
   if([Convert]::ToBase64String($received) -cne [Convert]::ToBase64String($bytes)){throw 'Upstream bytes mismatch'}
   $ps.Write($received,0,$received.Length)
   [byte[]]$echo=ReadExact $s.stream $bytes.Length
   if([Convert]::ToBase64String($echo) -cne [Convert]::ToBase64String($bytes)){throw 'Downstream bytes mismatch'}
   return $bytes.Length
  }finally{$peer.Close()}
 }finally{$s.client.Close()}
}
function Own([string]$name,[string]$exe,[string[]]$args){
 $out=Join-Path $work ($name+'.stdout.log');$err=Join-Path $work ($name+'.stderr.log')
 $p=Start-Process -FilePath $exe -ArgumentList $args -PassThru -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err
 $owned.Add($p)
 return $p
}
$stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$work=Join-Path ([IO.Path]::GetFullPath($ReportRoot)) ('w2b1-'+$stamp+'-'+$PID)
$null=New-Item -ItemType Directory -Path $work -Force
$secrets=Join-Path $work 'secret-test-keys'
$null=New-Item -ItemType Directory -Path $secrets -Force
$issues=[System.Collections.Generic.List[string]]::new()
$owned=[System.Collections.Generic.List[Diagnostics.Process]]::new()
$targetListener=$null
$report=[ordered]@{
 schema='flowbridge-native-w2b1-real-ssh-v1'
 timestamp_utc=[DateTime]::UtcNow.ToString('o')
 expected_host=$ExpectedComputerName;observed_host=$env:COMPUTERNAME
 os='';build='';target_admitted=$false;hosted_ci=$false
 beta_source_sha=$betaSha;w2a_receipt_verified=$false
 cli_sha256='';ssh_sha256='';sshd_sha256=''
 pinned_openssh_archive_sha256=''
 microsoft_signatures_checked=$false
 isolated_sshd_listening=$false;real_ssh_authenticated=$false
 bytes_returned=0;ssh_child_owned=$false
 managed_owner_shutdown_cleanup='UNTESTED'
 ephemeral_keys_deleted=$false
 W2b1='NOT_RUN';W2b2_GUI='NOT_RUN';W3='NO_GO';G2='NO_GO'
 release_accepted=$false;driver_loaded=$false
 system_service_modified=$false;host_firewall_changed=$false
 host_network_route_changed=$false;host_security_changed=$false
 problems=@()
}
try{
 if($env:OS -ne 'Windows_NT'){throw 'Windows only'}
 try{
  $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
  $report.os=[string]$os.Caption;$report.build=[string]$os.BuildNumber
 }catch{
  $reg=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $report.os=[string]$reg.ProductName;$report.build=[string]$reg.CurrentBuild
 }
 $report.hosted_ci=($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted')
 $report.target_admitted=($ExpectedComputerName -ieq $env:COMPUTERNAME -and
  [Environment]::Is64BitOperatingSystem -and $report.build -eq '19045' -and
  $report.os -match 'Windows 10')
 if(-not $report.target_admitted -and -not ($AllowHostedCI -and $report.hosted_ci)){
  throw 'Unexpected target or Windows OS'
 }
 $required=if($report.target_admitted){'PASS_NATIVE_WIN10_USERMODE_CLI_ONLY'}else{'PASS_HOSTED_NON_TARGET_ONLY'}
 $w2as=@(Get-ChildItem -LiteralPath $W2aEvidenceRoot -Filter w2a-report.json -Recurse -File -ErrorAction SilentlyContinue|Sort-Object LastWriteTimeUtc -Descending)
 $binary=''
 foreach($item in $w2as){
  $receipt=Get-Content -LiteralPath $item.FullName -Raw|ConvertFrom-Json
  if($receipt.W2a -ne $required -or $receipt.source_sha_actual -ne $betaSha -or
     -not $receipt.source_exact -or -not $receipt.capabilities_explicit -or
     $receipt.target_admitted -ne $report.target_admitted){continue}
  $exe=Join-Path (Split-Path -Parent $item.FullName) 'build\debug\flowbridge.exe'
  if(-not(Test-Path -LiteralPath $exe -PathType Leaf)){continue}
  $hash=Hash $exe
  if(@($receipt.steps) -notcontains ('exe_sha256_'+$hash)){continue}
  $binary=$exe;$report.cli_sha256=$hash;$report.w2a_receipt_verified=$true
  break
 }
 if(-not $binary){throw 'Exact W2a source/binary/hash receipt missing'}
 $ssh=Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
 $keygen=Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
 RequireSigned $ssh;RequireSigned $keygen
 $report.ssh_sha256=Hash $ssh
 $zip=Join-Path $work 'OpenSSH-Win64.zip'
 if($FixtureArchive){Copy-Item -LiteralPath $FixtureArchive -Destination $zip -ErrorAction Stop}
 else{Invoke-WebRequest -Uri $fixtureUrl -UseBasicParsing -OutFile $zip -ErrorAction Stop}
 $report.pinned_openssh_archive_sha256=Hash $zip
 if($report.pinned_openssh_archive_sha256 -ne $fixtureSha){throw 'Portable sshd archive hash mismatch'}
 $extract=Join-Path $work 'portable-openssh'
 Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
 $sshd=Join-Path $extract 'OpenSSH-Win64\sshd.exe'
 RequireSigned $sshd
 $report.sshd_sha256=Hash $sshd;$report.microsoft_signatures_checked=$true
 $sidLine=(& "$env:SystemRoot\System32\whoami.exe" /user /fo csv /nh|Out-String).Trim()
 $sidMatch=[regex]::Match($sidLine,'S-1-\d+(?:-\d+)+')
 if(-not $sidMatch.Success){throw 'Cannot identify current user SID'}
 $sid=$sidMatch.Value
 $user=[Environment]::UserName.ToLowerInvariant()
 if($user -notmatch '^[a-z0-9][a-z0-9._-]{0,126}$'){throw 'Test account name is unsupported by isolated sshd fixture'}
 $hostKey=Join-Path $secrets 'host_key'
 $clientKey=Join-Path $secrets 'client_key'
 foreach($path in @($hostKey,$clientKey)){
  & $keygen -q -t ed25519 -N '' -f $path
  if($LASTEXITCODE -ne 0){throw 'Ephemeral SSH key generation failed'}
  SecureTestFile $path $sid
 }
 $authorized=Join-Path $secrets 'authorized_keys'
 [IO.File]::WriteAllBytes($authorized,[IO.File]::ReadAllBytes($clientKey+'.pub'))
 SecureTestFile $authorized $sid
 $ports=[System.Collections.Generic.HashSet[int]]::new()
 while($ports.Count -lt 4){[void]$ports.Add((Port))}
 $p=@($ports)|Sort-Object
 $serverPort=[int]$p[0];$socksPort=[int]$p[1];$flowPort=[int]$p[2];$targetPort=[int]$p[3]
 $known=Join-Path $secrets 'known_hosts'
 $hostPublic=([IO.File]::ReadAllText($hostKey+'.pub',[Text.Encoding]::ASCII)).Trim()
 [IO.File]::WriteAllText($known,('[127.0.0.1]:'+$serverPort+' '+$hostPublic+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
 SecureTestFile $known $sid
 $config=Join-Path $work 'test_sshd_config'
 $h=$hostKey.Replace('\','/')
 $a=$authorized.Replace('\','/')
 $cfg=@(
  ('Port '+$serverPort),'ListenAddress 127.0.0.1','AddressFamily inet',
  ('HostKey "'+$h+'"'),('AuthorizedKeysFile "'+$a+'"'),('AllowUsers '+$user),
  'PasswordAuthentication no','KbdInteractiveAuthentication no',
  'PubkeyAuthentication yes','AuthenticationMethods publickey',
  'AllowTcpForwarding local','GatewayPorts no',
  'PermitOpen 127.0.0.1:* localhost:*','PermitTTY no',
  'MaxStartups 10:30:20','MaxSessions 10','LogLevel VERBOSE',''
 )
 [IO.File]::WriteAllLines($config,$cfg,[Text.UTF8Encoding]::new($false))
 SecureTestFile $config $sid
 & $sshd -t -f $config 2>&1|Out-File (Join-Path $work 'sshd-config-validation.log') -Encoding utf8
 if($LASTEXITCODE -ne 0){throw 'Isolated sshd configuration invalid'}
 $daemon=Own 'sshd-owned' $sshd @('-D','-e','-f',('"'+$config+'"'))
 WaitLocal $serverPort $daemon
 $report.isolated_sshd_listening=$true
 $targetListener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,$targetPort)
 $targetListener.Start(4)
 $profile=@{
  consent='RUST_MANAGED_SSH_SOCKS_CANDIDATE'
  engine=@{
   version=1;listen=('127.0.0.1:'+$flowPort)
   proxies=@(@{id='managed';kind='socks5';endpoint=@{host='127.0.0.1';port=$socksPort};username=$null;password_env=$null})
   rules=@();chains=@();default_action=@{type='proxy';id='managed'}
   max_connections=8;connect_timeout_ms=3000;handshake_timeout_ms=3000
   idle_timeout_ms=8000;remote_dns_via_ssh=$true
  }
  ssh=@{
   host='127.0.0.1';user=$user;port=$serverPort;local_port=$socksPort
   ssh_executable=$ssh;identity_file=$clientKey;known_hosts_file=$known
   startup_timeout_ms=15000;connect_timeout_secs=3
   health_check_interval_ms=250;health_check_timeout_ms=1000
   restart_initial_delay_ms=500;restart_max_delay_ms=1000
   max_restarts=3
  }
 }
 $managedConfig=Join-Path $work 'managed-test-profile.json'
 [IO.File]::WriteAllText($managedConfig,($profile|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
 $flow=Own 'flowbridge-owned' $binary @('serve-managed','--config',('"'+$managedConfig+'"'))
 WaitLocal $flowPort $flow 20
 $deadline=[DateTime]::UtcNow.AddSeconds(25)
 while([DateTime]::UtcNow -lt $deadline){
  if($flow.HasExited){throw 'Managed FlowBridge exited before SSH authentication'}
  try{
   $n=RealEcho $flowPort $targetPort $targetListener
   if($n -gt 0){$report.bytes_returned=$n;$report.real_ssh_authenticated=$true;break}
  }catch{Start-Sleep -Milliseconds 250}
 }
 if(-not $report.real_ssh_authenticated){throw 'No authenticated SOCKS5 -> SSH -> localhost TCP round trip'}
 try{
  $children=@(Get-CimInstance Win32_Process -Filter ('ParentProcessId='+$flow.Id) -ErrorAction Stop|
   Where-Object {$_.Name -ieq 'ssh.exe'})
  $report.ssh_child_owned=($children.Count -eq 1)
 }catch{$report.ssh_child_owned=$false}
 # Deliberately terminate ONLY this script's owned CLI to test Windows Job
 # cleanup; the user's unrelated ssh.exe processes are never touched.
 if(-not $flow.HasExited){$flow.Kill();$flow.WaitForExit(3000)|Out-Null}
 $cleared=$false;$until=[DateTime]::UtcNow.AddSeconds(7)
 while([DateTime]::UtcNow -lt $until){
  $listen=@(Get-NetTCPConnection -LocalPort $socksPort -State Listen -ErrorAction SilentlyContinue|
   Where-Object {$_.LocalAddress -eq '127.0.0.1'})
  if($listen.Count -eq 0){$cleared=$true;break}
  Start-Sleep -Milliseconds 200
 }
 $report.managed_owner_shutdown_cleanup=if($cleared){'SOCKS_LISTENER_CLOSED'}else{'NOT_PROVEN'}
 if(-not $cleared){throw 'Owned SSH SOCKS port still listening after managed owner termination'}
 $report.W2b1=if($report.target_admitted){'PASS_NATIVE_WIN10_REAL_SSH_LOOPBACK_ONLY'}else{'PASS_HOSTED_NON_TARGET_REAL_SSH_LOOPBACK_ONLY'}
}catch{
 $issues.Add($_.Exception.Message)
 $report.W2b1='FAILED_OR_BLOCKED'
}finally{
 if($targetListener){try{$targetListener.Stop()}catch{}}
 foreach($p in $owned){
  try{if(-not $p.HasExited){$p.Kill();$p.WaitForExit(5000)|Out-Null}}catch{}
  try{$p.Dispose()}catch{}
 }
 try{Remove-Item -LiteralPath $secrets -Force -Recurse -ErrorAction Stop;$report.ephemeral_keys_deleted=$true}
 catch{$issues.Add('Ephemeral test keys could not be destroyed; do NOT share the evidence directory')}
 if($report.W2b1 -like 'PASS*' -and -not $report.ephemeral_keys_deleted){$report.W2b1='FAILED_OR_BLOCKED'}
 $report.problems=@($issues.ToArray())
 $json=Join-Path $work 'w2b1-report.json'
 [IO.File]::WriteAllText($json,($report|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
 $manifest=Join-Path $work 'sha256.txt'
 $files=@(Get-ChildItem -LiteralPath $work -File|Where-Object {$_.Extension -in @('.log','.json')})
 $lines=@($files|Sort-Object Name|ForEach-Object{(Hash $_.FullName)+'  '+$_.Name})
 [IO.File]::WriteAllLines($manifest,$lines,[Text.UTF8Encoding]::new($false))
 $archive=Join-Path $work 'evidence-only.zip'
 try{Compress-Archive -LiteralPath @($files.FullName)+@($manifest) -DestinationPath $archive -Force -ErrorAction Stop}
 catch{Write-Warning ('Evidence-only ZIP unavailable: '+$_.Exception.Message)}
 Write-Host ('W2b1: '+$report.W2b1+'; W2b2 GUI: NOT_RUN; W3/G2: NO_GO')
 Write-Host ('Report: '+$json)
 if(Test-Path $archive){Write-Host ('Evidence ZIP: '+$archive);Write-Host ('ZIP SHA256: '+(Hash $archive))}
 if($report.problems.Count){Write-Host ('Notes: '+($report.problems -join '; '))}
 Write-Host 'Never share the test directory if ephemeral keys could not be deleted.'
}
