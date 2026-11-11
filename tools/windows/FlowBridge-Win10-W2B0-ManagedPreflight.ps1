#requires -version 5.1
<#
W2b-0: Win10 real managed-SSH CLI contract guards, signature + packaging preflight.
Uses the existing, successful W2a local build, no clone, network, SSH
connections, daemon/service, driver, BFE, security or registry mutations.
W2b-0 does not prove authenticated SSH, GUI, installation or kernel G2.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
 [string]$W2aEvidenceRoot="$env:ProgramData\FlowBridge\W2A-Evidence",
 [string]$ReportRoot="$env:ProgramData\FlowBridge\W2B-Evidence",
 [switch]$AllowHostedCI
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$sourceSha='c339df2e4d20edf1d11d45786581a68451a71929'
function Sha256([string]$path){return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
function ProbePort {
 $x=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
 try{$x.Start();return ([Net.IPEndPoint]$x.LocalEndpoint).Port}finally{$x.Stop()}
}
function RunCli([string]$exe,[string]$profile,[string]$label){
 $psi=New-Object Diagnostics.ProcessStartInfo
 $psi.FileName=$exe
 $psi.Arguments='serve-managed --config "'+$profile+'"'
 $psi.UseShellExecute=$false
 $psi.CreateNoWindow=$true
 $psi.RedirectStandardOutput=$true
 $psi.RedirectStandardError=$true
 $p=New-Object Diagnostics.Process
 $p.StartInfo=$psi
 try {
   if(-not $p.Start()){throw 'Could not launch managed CLI'}
   $stdoutTask=$p.StandardOutput.ReadToEndAsync()
   $stderrTask=$p.StandardError.ReadToEndAsync()
   $completed=$p.WaitForExit(10000)
   if(-not $completed){try{$p.Kill();$p.WaitForExit()}catch{}}
   $out=[string]$stdoutTask.GetAwaiter().GetResult()
   $err=[string]$stderrTask.GetAwaiter().GetResult()
   # The CLI does not print keys; never log private key or known_hosts contents.
   $log=Join-Path $work ($label+'.log')
   [IO.File]::WriteAllText($log,$out+[Environment]::NewLine+$err,[Text.UTF8Encoding]::new($false))
   return [ordered]@{
     accepted=$false
     denied=($completed -and $p.ExitCode -ne 0)
     exit_code=$p.ExitCode
     timed_out=(-not $completed)
     log=[IO.Path]::GetFileName($log)
     message=$err.Trim()
   }
 }finally {$p.Dispose()}
}
$ts=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$root=[IO.Path]::GetFullPath($ReportRoot)
$work=Join-Path $root ('w2b0-'+$ts+'-'+$PID)
$null=New-Item -ItemType Directory -Path $work -Force
$issues=[System.Collections.Generic.List[string]]::new()
$report=[ordered]@{
 schema='flowbridge-win10-w2b0-managed-ssh-readonly-v1'
 expected_host=$ExpectedComputerName;observed_host=$env:COMPUTERNAME
 os_name='';os_build='';x64=[Environment]::Is64BitOperatingSystem
 hosted_ci=$false;target_admitted=$false
 source_sha=$sourceSha;w2a_evidence_status='NONE'
 cli_exe='';cli_sha256='';cli_source_verified=$false
 system_ssh_path='';ssh_signature_status='unknown';ssh_microsoft_signed=$false
 ssh_keygen_path='';sshd_available=$false
 gui_build_prerequisites=[ordered]@{cmake=$false;msvc_cl=$false;nsis=$false}
 negative_managed_tests=@()
 completed_guard_cases=0
 W2b0='NOT_RUN';W2b1_real_ssh='NOT_RUN';W2b2_gui='NOT_RUN'
 W3='NO_GO';G2='NO_GO';release_accepted=$false
 driver_loaded=$false;bfe_or_wfp_modified=$false;service_installed=$false
 host_protections_changed=$false;ssh_network_connection_performed=$false
 errors=@()
}
try{
 if($env:OS -ne 'Windows_NT'){throw 'Windows required'}
 try{
  $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
  $report.os_name=[string]$os.Caption;$report.os_build=[string]$os.BuildNumber
 }catch{
  $r=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $report.os_name=[string]$r.ProductName;$report.os_build=[string]$r.CurrentBuild
 }
 $report.hosted_ci=($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted')
 $report.target_admitted=($ExpectedComputerName -ieq $env:COMPUTERNAME -and
   $report.x64 -and $report.os_build -eq '19045' -and
   $report.os_name -match 'Windows 10')
 if(-not $report.target_admitted -and -not ($AllowHostedCI -and $report.hosted_ci)){
   throw 'Unexpected target/OS, no managed CLI will be executed'
 }
 # Reuse a just-built SOURCE-PINNED CLI from W2a. Never download binaries.
 $candidates=@(Get-ChildItem -LiteralPath $W2aEvidenceRoot -Filter w2a-report.json -Recurse -File -ErrorAction SilentlyContinue|
    Sort-Object LastWriteTimeUtc -Descending)
 $picked=$false
 foreach($candidate in $candidates){
   $r=Get-Content -LiteralPath $candidate.FullName -Raw|ConvertFrom-Json
   $expectedStatus=if($report.target_admitted){'PASS_NATIVE_WIN10_USERMODE_CLI_ONLY'}else{'PASS_HOSTED_NON_TARGET_ONLY'}
   if($r.W2a -ne $expectedStatus -or $r.source_sha_actual -ne $sourceSha -or
      $r.source_exact -ne $true -or $r.capabilities_explicit -ne $true -or
      $r.target_admitted -ne $report.target_admitted){continue}
   $folder=Split-Path -Parent $candidate.FullName
   $exe=Join-Path $folder 'build\debug\flowbridge.exe'
   if(-not (Test-Path -LiteralPath $exe -PathType Leaf)){continue}
   $sha=Sha256 $exe
   if(@($r.steps) -notcontains ('exe_sha256_'+$sha)){continue}
   $report.cli_exe=$exe;$report.cli_sha256=$sha
   $report.cli_source_verified=$true
   $report.w2a_evidence_status=[string]$r.W2a
   $picked=$true
   break
 }
 if(-not $picked){throw 'No fully verified local W2a executable/manifest matching exact source SHA'}
 $ssh=Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
 $keygen=Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
 $sshd=Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
 $report.sshd_available=[bool](Test-Path -LiteralPath $sshd -PathType Leaf)
 if(Test-Path -LiteralPath $keygen -PathType Leaf){$report.ssh_keygen_path=$keygen}
 if(Test-Path -LiteralPath $ssh -PathType Leaf){
   $report.system_ssh_path=$ssh
   $sign=Get-AuthenticodeSignature -LiteralPath $ssh
   $report.ssh_signature_status=[string]$sign.Status
   $report.ssh_microsoft_signed=($sign.Status -eq 'Valid' -and
     $null -ne $sign.SignerCertificate -and
     $sign.SignerCertificate.Subject -match 'Microsoft')
 }
 foreach($item in @(@('cmake','cmake.exe'),@('msvc_cl','cl.exe'),@('nsis','makensis.exe'))){
   $cmd=Get-Command $item[1] -CommandType Application -ErrorAction SilentlyContinue|Select-Object -First 1
   $report.gui_build_prerequisites[$item[0]]=($null -ne $cmd)
 }
 # Syntactically valid managed profile, except for the SINGLE property
 # changed in each negative. Each must FAIL prior to any Engine/SSH start.
 $ports=New-Object 'System.Collections.Generic.HashSet[int]'
 while($ports.Count -lt 3){[void]$ports.Add((ProbePort))}
 $n=@($ports)|Sort-Object
 $sshPath=if($report.system_ssh_path){$report.system_ssh_path}else{'C:\Windows\System32\OpenSSH\ssh.exe'}
 $testProfile=[ordered]@{
  consent='RUST_MANAGED_SSH_SOCKS_CANDIDATE'
  engine=[ordered]@{
   version=1;listen=('127.0.0.1:'+$n[0])
   proxies=@([ordered]@{id='managed';kind='socks5';endpoint=[ordered]@{host='127.0.0.1';port=$n[1]};username=$null;password_env=$null})
   chains=@();rules=@()
   default_action=[ordered]@{type='proxy';id='managed'}
   connect_timeout_ms=1500;handshake_timeout_ms=1500
   idle_timeout_ms=5000;max_connections=8
   remote_dns_via_ssh=$true
  }
  ssh=[ordered]@{
   host='127.0.0.1';user='testuser';port=$n[2];local_port=$n[1]
   ssh_executable=$sshPath
   identity_file=(Join-Path $work 'unused-test-private-key')
   known_hosts_file=(Join-Path $work 'unused-test-known-hosts')
  }
 }
 foreach($scenario in @('invalid_consent','disallow_direct','missing_identity')){
   $p=ConvertFrom-Json ($testProfile|ConvertTo-Json -Depth 12)
   switch($scenario){
     invalid_consent {$p.consent='NO_CONSENT'}
     disallow_direct {$p.engine.default_action.type='direct';$p.engine.default_action.PSObject.Properties.Remove('id')}
     missing_identity {$p.ssh.PSObject.Properties.Remove('identity_file')}
   }
   $cfg=Join-Path $work ($scenario+'.json')
   [IO.File]::WriteAllText($cfg,($p|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
   $result=RunCli $exe $cfg $scenario
   if(-not $result.denied -or $result.timed_out){throw ($scenario+' accepted or timed out; see '+$result.log)}
   $report.negative_managed_tests+=@([ordered]@{name=$scenario;denied=$true;exit_code=$result.exit_code;log=$result.log})
   $report.completed_guard_cases++
 }
 if($report.target_admitted){$report.W2b0='PASS_NATIVE_WIN10_CONFIG_DENIAL_ONLY'}
 else{$report.W2b0='PASS_HOSTED_NON_TARGET_CONFIG_DENIAL_ONLY'}
 if(-not $report.ssh_microsoft_signed){
   $issues.Add('Microsoft-signed ssh.exe not available or not verified; real SSH W2b1 remains blocked')
 }
}catch{
 $report.W2b0='FAILED_OR_BLOCKED'
 $issues.Add($_.Exception.Message)
}finally{
 $report.errors=@($issues.ToArray())
 $json=Join-Path $work 'w2b0-report.json'
 [IO.File]::WriteAllText($json,($report|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
 $shaFile=Join-Path $work 'sha256.txt'
 $lines=@(Get-ChildItem -LiteralPath $work -File|Sort-Object Name|ForEach-Object{(Sha256 $_.FullName)+'  '+$_.Name})
 [IO.File]::WriteAllLines($shaFile,$lines,[Text.UTF8Encoding]::new($false))
 $zip=$work+'.zip'
 try{Compress-Archive -Path (Join-Path $work '*') -DestinationPath $zip -Force}
 catch{Write-Warning ('ZIP failed: '+$_.Exception.Message)}
 Write-Host ('W2b0: '+$report.W2b0+'; W2b1 SSH: NOT_RUN; W2b2 GUI: NOT_RUN')
 Write-Host ('W3/G2: NO_GO')
 Write-Host ('Report: '+$json)
 if(Test-Path -LiteralPath $zip){Write-Host ('ZIP: '+$zip);Write-Host ('ZIP SHA256: '+(Sha256 $zip))}
 if($report.errors.Count){Write-Host ('Notes: '+($report.errors -join '; '))}
}
