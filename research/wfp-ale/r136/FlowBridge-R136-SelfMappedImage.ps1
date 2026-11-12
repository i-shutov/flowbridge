#requires -Version 5.1
<#
 R136. Windows x64, existing rustc MSVC. Default synthetic-only.
 -RunSelfMappedImage explicitly permits read-only self EXE/memory image observations.
 No process enumeration, service/security/firewall/WFP-policy changes or driver use.
 Source blob is immutable and SHA1(Git)+SHA256-verified before compilation.
#>
[CmdletBinding()]
param(
 [string]$RustBinDirectory = (Join-Path $env:USERPROFILE '.cargo\bin'),
 [string]$OfflineSource = '',
 [switch]$RunSelfMappedImage,
 [switch]$CompileOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$sourceBlob='f45b3ae5274325081d2644f27173b2e667909bd3'
$sourceHash='165675ec74ba2a70daaa69c014b3473b48a9bf11267014cc1b487978384db6d9'
$matrixHash='bae850d1de8c78c1acbf4aee36fb1a1a67a54c6b72c7c6e09677c774442385ec'
$evidence=Join-Path ([IO.Path]::GetTempPath()) ('FlowBridge-R136-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -Path $evidence -ItemType Directory
$utf8=[Text.UTF8Encoding]::new($false)
$oldPath=$env:PATH
$exitCode=2
$report=[ordered]@{
 schema=1; tool='FlowBridge R136 mapped self image'; status='NOT_RUN'; reason=$null
 evidence_directory=$evidence; windows_build=$null; started_utc=[DateTime]::UtcNow.ToString('o')
 finished_utc=$null; source_blob_expected=$sourceBlob; source_sha256_expected=$sourceHash
 source_sha256_observed=$null; rustc_version=$null; target='x86_64-pc-windows-msvc'
 metadata_exit=$null; listed_tests=$null; tests_exit=$null; inspector_sha256=$null; test_sha256=$null
 matrix_sha256=$null; native_probe_requested=[bool]$RunSelfMappedImage; native_probe_exit=$null
 observation_mask=$null; archive=$null; archive_error=$null
 mapped_section_file_id_proof=$false; kernel_origin_proof=$false; network_owner_proof=$false
 no_direct_proof=$false; atomic_snapshot=$false; wfp_policy_modified=$false
}
function Save-Text([string]$Name,[string]$Value) { [IO.File]::WriteAllText((Join-Path $evidence $Name),$Value,$utf8) }
function Hash-Bytes([byte[]]$bytes,[string]$algorithm) {
 $h=[Security.Cryptography.HashAlgorithm]::Create($algorithm)
 try { return -join ($h.ComputeHash($bytes)|ForEach-Object {$_.ToString('x2')}) }
 finally {$h.Dispose()}
}
function Git-Blob([byte[]]$bytes) {
 $header=[Text.Encoding]::ASCII.GetBytes(('blob {0}' -f $bytes.Length)+[char]0)
 $all=New-Object byte[] ($header.Length+$bytes.Length)
 [Array]::Copy($header,0,$all,0,$header.Length)
 [Array]::Copy($bytes,0,$all,$header.Length,$bytes.Length)
 return Hash-Bytes $all 'SHA1'
}
function Run-Owned([string]$exe,[string[]]$arguments,[string]$name) {
 $quoted=@($arguments|ForEach-Object {
   if ($_ -match '["\r\n]' -or $_.EndsWith('\')) {throw 'Invalid compiler/child argument'}
   '"'+$_+'"'
 })
 $si=[Diagnostics.ProcessStartInfo]::new()
 $si.FileName=$exe;$si.Arguments=$quoted -join ' ';$si.WorkingDirectory=$evidence
 $si.UseShellExecute=$false;$si.CreateNoWindow=$true
 $si.RedirectStandardOutput=$true;$si.RedirectStandardError=$true
 $p=[Diagnostics.Process]::new();$p.StartInfo=$si
 try {
   if (-not $p.Start()) {throw 'Owned process start failure'}
   $stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync()
   if (-not $p.WaitForExit(120000)) {
     if (-not $p.HasExited) {$p.Kill()};$p.WaitForExit()
     Save-Text ($name+'.stdout.txt') ($stdout.GetAwaiter().GetResult())
     Save-Text ($name+'.stderr.txt') ($stderr.GetAwaiter().GetResult())
     throw ('Owned child timeout: '+$name)
   }
   $s=$stdout.GetAwaiter().GetResult();$e=$stderr.GetAwaiter().GetResult()
   Save-Text ($name+'.stdout.txt') $s;Save-Text ($name+'.stderr.txt') $e
   return [pscustomobject]@{ExitCode=$p.ExitCode;Output=$s;ErrorOutput=$e}
 } finally {$p.Dispose()}
}
function Is-Wide($v) {
 if ($v -isnot [string] -or $v.Length -gt 131068 -or $v -cnotmatch '^(?:[0-9A-F]{4})+$') {return $false}
 for ($i=0;$i -lt $v.Length;$i+=4) {if ($v.Substring($i,4) -ceq '0000') {return $false}}
 return $true
}
function Is-Hex($v,[int]$n) {return $v -is [string] -and $v.Length -eq $n -and $v -cmatch '^[0-9A-F]+$'}
function Is-App($v) {return $v -is [string] -and $v.Length -le 131072 -and $v -cmatch '^(?:[0-9A-F]{2})+$'}
try {
 if ($CompileOnly -and $RunSelfMappedImage) {throw 'CompileOnly cannot request native probe'}
 if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or -not [Environment]::Is64BitProcess -or
     $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {throw 'Windows x86_64 PowerShell required'}
 $os=Get-CimInstance Win32_OperatingSystem
 $report.windows_build=('{0} / {1} / {2}' -f $os.Caption,$os.Version,$os.BuildNumber)
 if (Test-Path -LiteralPath $RustBinDirectory -PathType Container) {$env:PATH=$RustBinDirectory+';'+$env:PATH}
 $rust=Get-Command rustc.exe -CommandType Application -ErrorAction Stop
 $r=Run-Owned $rust.Source @('-vV') 'rustc-version'
 if ($r.ExitCode -ne 0 -or $r.Output -notmatch '(?m)^host:\s*x86_64-pc-windows-msvc\s*$') {throw 'Installed x64 MSVC Rust required'}
 $report.rustc_version=$r.Output.Trim()
 if (-not [string]::IsNullOrWhiteSpace($OfflineSource)) {
   [byte[]]$bytes=[IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $OfflineSource).Path)
 } else {
   $url='https://api.github.com/repos/i-shutov/flowbridge/git/blobs/'+$sourceBlob
   $b=(Invoke-WebRequest -UseBasicParsing -Uri $url -Headers @{'User-Agent'='FlowBridge-R136-SourceFetch'}).Content|ConvertFrom-Json
   if ($b.sha -cne $sourceBlob -or $b.encoding -cne 'base64') {throw 'Unexpected GitHub blob response'}
   [byte[]]$bytes=[Convert]::FromBase64String($b.content)
 }
 $report.source_sha256_observed=Hash-Bytes $bytes 'SHA256'
 if ($report.source_sha256_observed -cne $sourceHash -or (Git-Blob $bytes) -cne $sourceBlob) {throw 'Source SHA mismatch; no compilation'}
 $source=Join-Path $evidence 'r136_mapped_self_image.rs'
 [IO.File]::WriteAllBytes($source,$bytes)
 Write-Host ('Verified exact Rust blob '+$sourceBlob)
 $r=Run-Owned $rust.Source @('--edition=2021','--target',$report.target,'--emit=metadata',$source,'-o',(Join-Path $evidence 'r136.rmeta')) 'metadata'
 $report.metadata_exit=$r.ExitCode
 if ($r.ExitCode -ne 0) {throw 'Windows-gated Rust metadata check failed'}
 $report.status='WINDOWS_METADATA_ONLY';$exitCode=0
 if (-not $CompileOnly) {
   $tests=Join-Path $evidence 'r136-tests.exe'
   $r=Run-Owned $rust.Source @('--edition=2021','--target',$report.target,'--test',$source,'-o',$tests) 'tests-build'
   if ($r.ExitCode -ne 0) {throw 'Rust test binary build failed'}
   $report.test_sha256=(Get-FileHash -LiteralPath $tests -Algorithm SHA256).Hash.ToLowerInvariant()
   $r=Run-Owned $tests @('--list','--format=terse') 'test-list'
   $names=@($r.Output -split '\r?\n'|Where-Object {$_ -match '^tests::.+: test$'})
   $report.listed_tests=$names.Count
   if ($r.ExitCode -ne 0 -or $names.Count -ne 21 -or @($names|Select-Object -Unique).Count -ne 21) {throw 'Expected exactly 21 unique synthetic tests'}
   $r=Run-Owned $tests @('--test-threads=1') 'unit-tests'
   $report.tests_exit=$r.ExitCode;Write-Host $r.Output
   if ($r.ExitCode -ne 0 -or $r.Output -notmatch 'test result: ok\. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;') {throw 'Synthetic test failure'}
   $exe=Join-Path $evidence 'r136-self-mapping.exe'
   $r=Run-Owned $rust.Source @('--edition=2021','--target',$report.target,$source,'-o',$exe) 'probe-build'
   if ($r.ExitCode -ne 0) {throw 'Probe build failed'}
   $report.inspector_sha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
   $r=Run-Owned $exe @('--contract-matrix') 'contract-matrix'
   $normalized=$r.Output.Replace("`r`n","`n")
   $report.matrix_sha256=Hash-Bytes ([Text.Encoding]::ASCII.GetBytes($normalized)) 'SHA256'
   if ($r.ExitCode -ne 0 -or $r.ErrorOutput.Trim() -or $report.matrix_sha256 -cne $matrixHash) {throw 'Contract oracle mismatch'}
   $report.status='NATIVE_SYNTHETIC_PASS_NOT_IMAGE_PROOF'
   if ($RunSelfMappedImage) {
     $r=Run-Owned $exe @('--self-mapped-image') 'self-mapped-image'
     Save-Text 'self-mapped-image.jsonl' $r.Output;Write-Host $r.Output
     $report.native_probe_exit=$r.ExitCode;$exitCode=2
     if ($r.ExitCode -notin @(0,3) -or $r.ErrorOutput.Trim()) {throw 'Native API error; see raw logs'}
     $lines=@($r.Output -split '\r?\n'|Where-Object {$_.Trim()})
     if ($lines.Count -ne 4) {throw 'Expected exactly four JSON records'}
     $rows=@($lines|ForEach-Object {$_|ConvertFrom-Json -ErrorAction Stop})
     foreach ($x in $rows) {
       if ($x.schema -isnot [int] -or $x.schema -ne 1) {throw 'Invalid JSON schema'}
       foreach ($k in @('kernel_origin_proof','mapped_section_file_id_proof','network_owner_proof','no_direct_proof')) {
         if ($x.$k -isnot [bool] -or $x.$k) {throw ('Proof overclaim: '+$k)}
       }
     }
     $p=$rows[0];$m=$rows[1];$f=$rows[2];$s=$rows[3]
     if ($p.kind -cne 'self' -or $p.pid -isnot [int] -or $p.pid -le 0) {throw 'Bad self process'}
     foreach ($k in @('win32_before','win32_after','native_before','native_after','module_name')) {if (-not (Is-Wide $p.$k)) {throw ('Bad process name '+$k)}}
     if ($m.kind -cne 'mapping' -or $m.state -isnot [int] -or $m.type -isnot [int] -or
       -not (Is-Wide $m.mapped_native_before) -or -not (Is-Wide $m.mapped_native_after) -or
       -not (Is-Hex $m.module_base_hex 16) -or -not (Is-Hex $m.allocation_base_hex 16)) {throw 'Bad module mapping observation'}
     if ($f.kind -cne 'file' -or -not (Is-Wide $f.final_native) -or -not (Is-Wide $f.final_dos)) {throw 'Bad opened file record'}
     foreach ($k in @('volume_before','volume_after')) {if (-not (Is-Hex $f.$k 16)) {throw ('Bad file volume '+$k)}}
     foreach ($k in @('id_before','id_after')) {if (-not (Is-Hex $f.$k 32)) {throw ('Bad file ID '+$k)}}
     foreach ($k in @('app0','app1','app2','app3')) {if (-not (Is-App $f.$k)) {throw ('Bad opaque AppId '+$k)}}
     $flags=New-Object bool[] 8
     $flags[0]=($m.state -eq 4096 -and $m.type -eq 16777216 -and $m.module_base_hex -ceq $m.allocation_base_hex)
     $flags[1]=($m.mapped_native_before -ceq $m.mapped_native_after)
     $flags[2]=($m.mapped_native_before -ceq $p.native_before -and $p.native_before -ceq $p.native_after)
     $flags[3]=($m.mapped_native_before -ceq $f.final_native)
     $flags[4]=($f.id_before -cne ('0'*32) -and $f.volume_before -cne ('0'*16) -and
       $f.id_before -ceq $f.id_after -and $f.volume_before -ceq $f.volume_after)
     $flags[5]=($f.app0 -ceq $f.app1 -and $f.app0 -ceq $f.app2 -and $f.app0 -ceq $f.app3)
     $flags[6]=($p.win32_before -ceq $p.win32_after)
     $flags[7]=($p.module_name -ceq $p.win32_before)
     $mask=0;for ($i=0;$i -lt 8;$i++) {if ($flags[$i]) {$mask=$mask -bor (1 -shl $i)}}
     $expectedExit=if (($mask -band 127) -eq 127) {0} else {3}
     $expectedStatus=if ($expectedExit -eq 0) {'MAPPED_IMAGE_NAME_CONCORDANT_NOT_SECTION_FILE_ID_PROOF'} else {'MAPPING_OBSERVATION_MISMATCH_NO_PROOF'}
     if ($s.kind -cne 'summary' -or $s.status -cne $expectedStatus -or
       $s.observation_mask -isnot [int] -or $s.observation_mask -ne $mask -or
       $s.diagnostic_exit -isnot [int] -or $s.diagnostic_exit -ne $expectedExit -or
       $r.ExitCode -ne $expectedExit -or $s.file_id_class -isnot [int] -or $s.file_id_class -ne 18 -or
       $s.mem_image_constant -isnot [int] -or $s.mem_image_constant -ne 16777216 -or
       $s.atomic_snapshot -isnot [bool] -or $s.atomic_snapshot) {throw 'Summary does not match raw observations'}
     $report.observation_mask=$mask;$report.status=$expectedStatus;$exitCode=$expectedExit
   }
 }
} catch {$report.status='UNAVAILABLE_OR_FAILED';$report.reason=$_.Exception.Message;$exitCode=2}
finally {
 $env:PATH=$oldPath
 $report.finished_utc=[DateTime]::UtcNow.ToString('o')
 $report.archive=Join-Path $evidence 'evidence-only.zip'
 Save-Text 'R136_EVIDENCE.json' ($report|ConvertTo-Json -Depth 6)
 try {
   $files=@(Get-ChildItem -LiteralPath $evidence -File|Where-Object {$_.Extension -in @('.txt','.json','.jsonl')})
   Compress-Archive -LiteralPath $files.FullName -DestinationPath $report.archive -Force
 } catch {$report.archive=$null;$report.archive_error=$_.Exception.Message;Save-Text 'R136_EVIDENCE.json' ($report|ConvertTo-Json -Depth 6)}
 Write-Host ('R136 status: '+$report.status)
 if ($report.reason) {Write-Host ('R136 reason: '+$report.reason)}
 Write-Host ('R136 evidence: '+$evidence)
 if ($report.archive) {Write-Host ('R136 evidence ZIP: '+$report.archive)}
 Write-Host ('R136 exit code: '+$exitCode)
 Write-Host 'Read-only mapped main image; no mapped-section file-ID or ALE origin proof.'
}
exit $exitCode
