#requires -Version 5.1
<#
R140: exact source + pure native Rust test of ACTION_WRITE / veto guard.
NO kernel driver build, BFE policy, sockets, filters, service, ACL, or system change.
Expected diagnostic exit 3 means STATIC CONTRACT TEST PASS, RELEASE NO-GO.
#>
[CmdletBinding()]
param([string]$RustBinDirectory=(Join-Path $env:USERPROFILE '.cargo\bin'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$manifest=@'
[
 {"path":"research/wfp-ale/kernel-r19/kernel/src/lib.rs","blob":"53f5ce6faa0f9f591974287f38ea890cafeb0dd2"},
 {"path":"research/wfp-ale/kernel-r19/kernel/src/redirect.rs","blob":"a093f049d162987981a957aac90db1014bc6ff09"},
 {"path":"research/wfp-ale/kernel-r19/kernel/src/action_rights.rs","blob":"c6a4a107255cc5ecca82266481935c93467a01ed","sha256":"fa17c5d2880dabc62567f618bf7f0c0919103310795877da8ca3ecc7249b3faf"},
 {"path":"research/wfp-ale/kernel-r19/policy_windows.rs","blob":"acf60334320d970f58af3349ee75fbaa59826602"},
 {"path":"research/wfp-ale/r140/r140_guard_harness.rs","blob":"6c04a26f30ab05d773c6d5cce4b8f97fde5fc634","sha256":"5a53c38876635e0426dfdab2f413aa0a373f1d025775b853c71819e3434ffcc6"}
]
'@ | ConvertFrom-Json
$expectedMatrixSha='4837dbb987fdd28bd006f553b688d0a0746575ce4533ef7366e01bbf0cabc654'
$evidence=Join-Path ([IO.Path]::GetTempPath()) ('FlowBridge-R140-'+[guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $evidence)
$oldPath=$env:PATH
$exitCode=2
$report=[ordered]@{
 schema=1;status='NOT_RUN';reason=$null;evidence_directory=$evidence
 started_utc=[DateTime]::UtcNow.ToString('o');finished_utc=$null
 source_pins=@();rustc_version=$null;windows_build=$null
 static_contracts=0;synthetic_tests=$null;unit_exit=$null;matrix_sha256=$null
 action_rights_legality_covered=$false;kernel_compiled=$false;kernel_executed=$false
 dynamic_policy_lifetime_gap=$true;kernel_origin_proof=$false;no_direct_proof=$false
 release_accepted=$false;bfe_queried=$false;driver_loaded=$false;sockets_created=$false
 archive=$null
}
$utf8=[Text.UTF8Encoding]::new($false)
function Save-Text([string]$Name,[string]$Text){[IO.File]::WriteAllText((Join-Path $evidence $Name),$Text,$utf8)}
function Hash-Bytes([byte[]]$b,[string]$alg){
 $h=[Security.Cryptography.HashAlgorithm]::Create($alg)
 try{return -join($h.ComputeHash($b)|ForEach-Object{$_.ToString('x2')})}
 finally{$h.Dispose()}
}
function Git-Blob([byte[]]$b){
 $header=[Text.Encoding]::ASCII.GetBytes(('blob {0}' -f $b.Length)+[char]0)
 $data=New-Object byte[] ($header.Length+$b.Length)
 [Array]::Copy($header,0,$data,0,$header.Length)
 [Array]::Copy($b,0,$data,$header.Length,$b.Length)
 return Hash-Bytes $data 'SHA1'
}
function Run-Local([string]$exe,[string[]]$Arguments,[string]$name){
 $quotes=@($Arguments|ForEach-Object{
   if($_ -match '["\r\n]' -or $_.EndsWith('\')){throw 'Unsafe native argument'}
   '"'+$_+'"'
 })
 $si=[Diagnostics.ProcessStartInfo]::new()
 $si.FileName=$exe;$si.Arguments=$quotes -join ' ';$si.WorkingDirectory=$evidence
 $si.RedirectStandardOutput=$true;$si.RedirectStandardError=$true
 $si.UseShellExecute=$false;$si.CreateNoWindow=$true
 $p=[Diagnostics.Process]::new();$p.StartInfo=$si
 try{
  if(-not $p.Start()){throw ('Cannot start '+$exe)}
  $stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync()
  if(-not $p.WaitForExit(120000)){
   if(-not $p.HasExited){$p.Kill()};$p.WaitForExit()
   throw ('Timed out own native child: '+$name)
  }
  $out=$stdout.GetAwaiter().GetResult();$err=$stderr.GetAwaiter().GetResult()
  Save-Text ($name+'.stdout.txt') $out;Save-Text ($name+'.stderr.txt') $err
  return [pscustomobject]@{Code=$p.ExitCode;Out=$out;Err=$err}
 }finally{$p.Dispose()}
}
try{
 if([Environment]::OSVersion.Platform -ne 'Win32NT' -or -not [Environment]::Is64BitProcess -or
  $env:PROCESSOR_ARCHITECTURE -ne 'AMD64'){throw 'Native Windows x86_64 PowerShell required'}
 $os=Get-CimInstance Win32_OperatingSystem
 $report.windows_build=('{0} / {1} / {2}' -f $os.Caption,$os.Version,$os.BuildNumber)
 if(Test-Path -LiteralPath $RustBinDirectory -PathType Container){$env:PATH=$RustBinDirectory+';'+$env:PATH}
 $rust=Get-Command rustc.exe -CommandType Application -ErrorAction Stop
 $info=Run-Local $rust.Source @('-vV') 'rustc-version'
 if($info.Code -ne 0 -or $info.Out -notmatch '(?m)^host:\s*x86_64-pc-windows-msvc\s*$'){
  throw 'Existing native MSVC x64 rustc required; no installation attempted'
 }
 $report.rustc_version=$info.Out.Trim()
 foreach($entry in $manifest){
  $url='https://api.github.com/repos/i-shutov/flowbridge/git/blobs/'+$entry.blob
  $response=Invoke-WebRequest -UseBasicParsing -Uri $url -Headers @{'User-Agent'='FlowBridge-R140-ExactSource'}
  $object=$response.Content|ConvertFrom-Json
  if($object.sha -cne $entry.blob -or $object.encoding -cne 'base64'){throw 'Unexpected GitHub blob result'}
  [byte[]]$bytes=[Convert]::FromBase64String($object.content)
  $sha=Hash-Bytes $bytes 'SHA256';$git=Git-Blob $bytes
  if($git -cne $entry.blob){throw ('Git object mismatch: '+$entry.path)}
  if($null -ne $entry.PSObject.Properties['sha256'] -and $sha -cne $entry.sha256){throw ('SHA256 mismatch: '+$entry.path)}
  $path=Join-Path $evidence $entry.path
  [void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path))
  [IO.File]::WriteAllBytes($path,$bytes)
  $report.source_pins+=([ordered]@{path=$entry.path;git_blob=$git;sha256=$sha;bytes=$bytes.Length})
  Write-Host ('Verified: '+$entry.path+' / '+$git)
 }
 $k=Join-Path $evidence 'research\wfp-ale\kernel-r19\kernel\src'
 $lib=[IO.File]::ReadAllText((Join-Path $k 'lib.rs'),$utf8)
 $redirect=[IO.File]::ReadAllText((Join-Path $k 'redirect.rs'),$utf8)
 $policy=[IO.File]::ReadAllText((Join-Path $evidence 'research\wfp-ale\kernel-r19\policy_windows.rs'),$utf8)
 $helper=[IO.File]::ReadAllText((Join-Path $k 'action_rights.rs'),$utf8)
 if(-not $lib.Contains('mod action_rights;')){throw 'Kernel guard module missing'}
 if(-not $lib.Contains('unsafe fn guarded_block(out:*mut k::FWPS_CLASSIFY_OUT0)->bool')){throw 'Kernel guard entry missing'}
 if(([regex]::Matches($lib,'let _=guarded_block\(out\);')).Count -ne 4){throw 'Kernel STOP/rundown guards incomplete'}
 if(([regex]::Matches($lib,[regex]::Escape('(*out).actionType=k::FWP_ACTION_BLOCK;'))).Count -ne 1){throw 'Uncontrolled direct BLOCK in lib.rs'}
 if(-not $redirect.Contains('let _=super::guarded_block(out);')){throw 'Redirect does not call shared guard'}
 if($redirect.Contains('unsafe fn block(out:*mut k::FWPS_CLASSIFY_OUT0){(*out).actionType=k::FWP_ACTION_BLOCK')){throw 'Old unconditional block remains'}
 if(-not $redirect.Contains('(*out).rights|=incoming_write;(*out).actionType=k::FWP_ACTION_PERMIT;')){throw 'No rights restoration before PERMIT'}
 if(-not $helper.Contains('BlockDecision::MustPreserve')){throw 'MustPreserve guard missing'}
 if(-not $policy.Contains('FWPM_SESSION_FLAG_DYNAMIC')){throw 'Dynamic session boundary changed unexpectedly'}
 $report.static_contracts=9
 $source=Join-Path $evidence 'research\wfp-ale\r140\r140_guard_harness.rs'
 $test=Join-Path $evidence 'r140-tests.exe'
 $build=Run-Local $rust.Source @('--edition=2021','--target','x86_64-pc-windows-msvc','--test',$source,'-o',$test) 'test-build'
 if($build.Code -ne 0){throw 'Rust test build failed; inspect test-build.stderr.txt'}
 $r=Run-Local $test @('--list','--format=terse') 'test-list'
 $names=@($r.Out -split '\r?\n'|Where-Object{$_ -match ': test$'})
 if($r.Code -ne 0 -or $names.Count -ne 13 -or @($names|Select-Object -Unique).Count -ne 13){throw 'Expected 13 uniquely named tests'}
 $r=Run-Local $test @('--test-threads=1') 'unit-tests'
 $report.unit_exit=$r.Code
 if($r.Code -ne 0 -or $r.Out -notmatch 'test result: ok\. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'){
  throw 'Rust test result mismatch; see unit-tests logs'
 }
 $report.synthetic_tests=13
 $exe=Join-Path $evidence 'r140-action-guard.exe'
 $compile=Run-Local $rust.Source @('--edition=2021','--target','x86_64-pc-windows-msvc',$source,'-o',$exe) 'matrix-build'
 if($compile.Code -ne 0){throw 'Rust matrix build failed; see matrix-build logs'}
 $r=Run-Local $exe @('--matrix') 'matrix'
 $matrix=$r.Out.Replace("`r`n","`n")
 $report.matrix_sha256=Hash-Bytes ([Text.Encoding]::ASCII.GetBytes($matrix)) 'SHA256'
 $lines=@($matrix -split "`n"|Where-Object{$_.Length -gt 0})
 if($r.Code -ne 0 -or $r.Err.Trim().Length -gt 0 -or
  $lines.Count -ne 42 -or
  $report.matrix_sha256 -cne $expectedMatrixSha){throw 'Rust decision matrix differs from independent oracle'}
 $report.action_rights_legality_covered=$true
 $report.status='R140_STATIC_ACTION_GUARD_PASS_RELEASE_NO_GO'
 $report.reason='Dynamic policy lifetime and native kernel interception remain unproven'
 $exitCode=3
}catch{
 $report.status='UNAVAILABLE_OR_FAILED';$report.reason=$_.Exception.Message;$exitCode=2
}finally{
 $env:PATH=$oldPath
 $report.finished_utc=[DateTime]::UtcNow.ToString('o')
 $report.archive=Join-Path $evidence 'evidence-only.zip'
 Save-Text 'R140_EVIDENCE.json' ($report|ConvertTo-Json -Depth 8)
 try{
  $logs=@(Get-ChildItem -LiteralPath $evidence -File|Where-Object{$_.Extension -in @('.txt','.json')})
  Compress-Archive -LiteralPath $logs.FullName -DestinationPath $report.archive -Force
 }catch{$report.archive=$null;Save-Text 'R140_EVIDENCE.json' ($report|ConvertTo-Json -Depth 8)}
 Write-Host ('R140 status: '+$report.status)
 if($report.reason){Write-Host ('R140 reason: '+$report.reason)}
 Write-Host ('R140 evidence: '+$evidence)
 if($report.archive){Write-Host ('R140 evidence ZIP: '+$report.archive)}
 Write-Host ('R140 exit code: '+$exitCode)
 Write-Host 'Only static contract and user-mode pure Rust tested; no WFP or driver run.'
}
exit $exitCode
