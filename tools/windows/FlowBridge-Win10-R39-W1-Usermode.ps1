#requires -version 5.1
<#
FlowBridge R39 W1. Exact-source user-mode Rust regressions on Windows.
Inputs fetched from one fixed GitHub commit (HTTPS), every Git blob verified
before compilation/execution. Only standalone Rust source unit tests are used.
No drivers, kernel service, BFE/WFP filters, TESTSIGNING, ports or system changes.
Only files under the explicitly selected EvidenceRoot are created.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
  [string]$EvidenceRoot = "$env:ProgramData\FlowBridge\R39-Evidence\W1",
  [switch]$OfflineOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$sourceCommit='992a84b87c328483e08744d98ac5051183914066'
$suites=@(
  [ordered]@{name='handoff';path='research/wfp-ale/kernel-r19/kernel/src/handoff.rs';blob='e1d17217db50362ba9c4efc83af820b6beb094cf'},
  [ordered]@{name='ledger';path='research/wfp-ale/kernel-r19/kernel/src/ledger.rs';blob='b88c4c9237c4c118517978fc454f5048f522aa7f'},
  [ordered]@{name='auth_appid';path='research/wfp-ale/kernel-r19/kernel/src/auth_appid.rs';blob='f16ab6ad0f618c74ed4e79ce606583169084970d'},
  [ordered]@{name='broker_lifecycle';path='research/wfp-ale/kernel-r19/broker_lifecycle.rs';blob='211b5e5cee03f4d8ea13fc23e1be0777cbfa09c1'}
)
function SHA256([string]$path) {
  return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function GitBlobSHA1([string]$path) {
  $bytes=[IO.File]::ReadAllBytes($path)
  $header=[Text.Encoding]::ASCII.GetBytes(('blob '+$bytes.Length)+[char]0)
  $payload=New-Object byte[] ($header.Length+$bytes.Length)
  [Array]::Copy($header,0,$payload,0,$header.Length)
  [Array]::Copy($bytes,0,$payload,$header.Length,$bytes.Length)
  $sha=[Security.Cryptography.SHA1]::Create()
  try {return ([BitConverter]::ToString($sha.ComputeHash($payload))).Replace('-','').ToLowerInvariant()}
  finally {$sha.Dispose()}
}
function InvokeChild([string]$exe,[string[]]$arguments,[string]$log,[int]$timeout=120){
  $psi=New-Object Diagnostics.ProcessStartInfo
  $psi.FileName=$exe
  $psi.Arguments=(($arguments|ForEach-Object {'"'+($_ -replace '"','\"')+'"'}) -join ' ')
  $psi.UseShellExecute=$false
  $psi.CreateNoWindow=$true
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  $process=New-Object Diagnostics.Process
  $process.StartInfo=$psi
  $started=$false
  try {
    $started=$process.Start()
    if(-not $started){throw 'Cannot start child process'}
    $stdout=$process.StandardOutput.ReadToEndAsync()
    $stderr=$process.StandardError.ReadToEndAsync()
    $done=$process.WaitForExit($timeout*1000)
    if(-not $done){
      try{$process.Kill()}catch{}
      $process.WaitForExit()
    }
    $out=[string]$stdout.GetAwaiter().GetResult()
    $err=[string]$stderr.GetAwaiter().GetResult()
    [IO.File]::WriteAllText($log,$out+[Environment]::NewLine+$err,[Text.UTF8Encoding]::new($false))
    return [ordered]@{success=($done -and $process.ExitCode -eq 0);exit_code=$process.ExitCode;timed_out=(-not $done);log=[IO.Path]::GetFileName($log)}
  } finally {$process.Dispose()}
}
$stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$root=[IO.Path]::GetFullPath($EvidenceRoot)
$work=Join-Path $root ('r39-w1-'+$stamp+'-'+$PID)
$null=New-Item -ItemType Directory -Path $work -Force
$report=[ordered]@{
  schema='flowbridge-r39-win10-usermode-w1-v1'
  time_utc=[DateTime]::UtcNow.ToString('o')
  expected_computer=$ExpectedComputerName
  actual_computer=$env:COMPUTERNAME
  target_hostname_matched=($ExpectedComputerName -ieq $env:COMPUTERNAME)
  operating_system=''
  build=''
  x64=[Environment]::Is64BitOperatingSystem
  elevated=$false
  target_win10_admitted=$false
  source_commit=$sourceCommit
  source_download='not_attempted'
  rustc_path=''
  rustc_version=''
  suites=@()
  W1='NOT_STARTED'
  W3='NO_GO'
  G2='NO_GO'
  release_accepted=$false
  sys_installed_or_loaded=$false
  wfp_filters_modified=$false
  bcd_modified=$false
  security_settings_modified=$false
  external_network_scope='Pinned HTTPS GitHub raw source only'
  errors=@()
}
$errorsList=New-Object 'System.Collections.Generic.List[string]'
try{
  if($env:OS -ne 'Windows_NT'){throw 'Only Windows can run this audit'}
  $admin=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
  $report.elevated=$admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  try{
    $os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $report.operating_system=[string]$os.Caption
    $report.build=[string]$os.BuildNumber
  }catch{
    $reg=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $report.operating_system=[string]$reg.ProductName
    $report.build=[string]$reg.CurrentBuild
  }
  $report.target_win10_admitted=($report.target_hostname_matched -and $report.x64 -and
    $report.build -eq '19045' -and $report.operating_system -match 'Windows 10')
  if(-not $report.target_win10_admitted){$errorsList.Add('This run is not native target Windows 10 acceptance')}
  $rust=Get-Command rustc.exe -ErrorAction SilentlyContinue|Select-Object -First 1
  if($null -eq $rust){
    $candidate=Join-Path $env:USERPROFILE '.cargo\bin\rustc.exe'
    if(Test-Path -LiteralPath $candidate -PathType Leaf){$rust=[pscustomobject]@{Source=$candidate}}
  }
  if($null -eq $rust){
    $report.W1='BLOCKED_RUSTC_NOT_INSTALLED'
    $errorsList.Add('rustc.exe not found; no tool installation attempted')
  }else{
    $report.rustc_path=[string]$rust.Source
    $verLog=Join-Path $work 'rustc-version.log'
    $ver=InvokeChild $report.rustc_path @('--version') $verLog 30
    if(-not $ver.success){throw 'rustc --version failed'}
    $report.rustc_version=(Get-Content -LiteralPath $verLog -Raw).Trim()
    $report.W1='IN_PROGRESS'
    $all=$true
    foreach($suite in $suites){
      $name=[string]$suite.name
      $source=Join-Path $work ($name+'.rs')
      $binary=Join-Path $work ($name+'-unit.exe')
      $entry=[ordered]@{name=$name;path=$suite.path;expected_blob=$suite.blob;actual_blob='';sha256='';source_verified=$false;compile_pass=$false;test_pass=$false;passed_count=0;notes=''}
      try {
        if($OfflineOnly){throw 'OfflineOnly requested and pinned file is not staged'}
        $url='https://raw.githubusercontent.com/i-shutov/flowbridge/'+$sourceCommit+'/'+$suite.path
        Invoke-WebRequest -Uri $url -OutFile $source -UseBasicParsing -ErrorAction Stop
        $entry.actual_blob=GitBlobSHA1 $source
        $entry.sha256=SHA256 $source
        if($entry.actual_blob -ne $suite.blob){throw 'Exact Git source blob SHA mismatch'}
        $entry.source_verified=$true
        $build=InvokeChild $report.rustc_path @('--edition=2021','--test',$source,'-o',$binary) (Join-Path $work ($name+'-compile.log')) 120
        if(-not $build.success){throw 'Rust compilation failed: '+$build.log}
        $entry.compile_pass=$true
        $test=InvokeChild $binary @('--test-threads=1') (Join-Path $work ($name+'-test.log')) 120
        if(-not $test.success){throw 'Rust unit regression failed: '+$test.log}
        $entry.test_pass=$true
        $text=Get-Content -LiteralPath (Join-Path $work ($name+'-test.log')) -Raw
        $m=[regex]::Match($text,'test result: ok\.\s+(\d+)\s+passed;\s+0\s+failed;')
        if(-not $m.Success){throw 'Rust test summary missing or non-zero failures'}
        $entry.passed_count=[int]$m.Groups[1].Value
      }catch{
        $all=$false
        $entry.notes=$_.Exception.Message
        $errorsList.Add(($name+': '+$entry.notes))
      }
      $report.suites+=@($entry)
    }
    if($all){
      if($report.target_win10_admitted){$report.W1='PASS_NATIVE_USERMODE_ONLY'}
      else{$report.W1='PASS_NON_TARGET_HOST_ONLY'}
    }else{$report.W1='FAILED_OR_BLOCKED'}
  }
}catch{
  $errorsList.Add(('Fatal: '+$_.Exception.Message))
  if($report.W1 -eq 'NOT_STARTED' -or $report.W1 -eq 'IN_PROGRESS'){$report.W1='FAILED_OR_BLOCKED'}
}finally{
  $report.errors=@($errorsList.ToArray())
  $json=Join-Path $work 'w1-report.json'
  [IO.File]::WriteAllText($json,($report|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
  $manifest=Join-Path $work 'sha256.txt'
  $rows=@(Get-ChildItem -LiteralPath $work -File|Where-Object {$_.Name -ne 'sha256.txt'}|Sort-Object Name|
    ForEach-Object {(SHA256 $_.FullName)+'  '+$_.Name})
  [IO.File]::WriteAllLines($manifest,$rows,[Text.UTF8Encoding]::new($false))
  $zip=$work+'.zip'
  try{Compress-Archive -LiteralPath (Join-Path $work '*') -DestinationPath $zip -Force -ErrorAction Stop}
  catch{
    # Compress-Archive -LiteralPath does not expand globs on Windows PowerShell 5.1.
    try{Compress-Archive -Path (Join-Path $work '*') -DestinationPath $zip -Force -ErrorAction Stop}
    catch{$errorsList.Add('ZIP packaging failed')}
  }
  Write-Host ('W1: '+$report.W1+'; W3/G2: NO_GO')
  Write-Host ('Report: '+$json)
  if(Test-Path $zip){Write-Host ('ZIP: '+$zip);Write-Host ('ZIP SHA256: '+(SHA256 $zip))}
  if($report.errors.Count){Write-Host ('Notes: '+($report.errors -join '; '))}
}
