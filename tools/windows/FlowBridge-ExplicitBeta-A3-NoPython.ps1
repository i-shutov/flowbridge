#requires -Version 5.1
<#
.SYNOPSIS
  Python-free exact-byte A3 acceptance for frozen FlowBridge explicit beta.
.DESCRIPTION
  Default is byte preflight only. -Execute runs the user-mode NSIS package,
  native Win32 GUI/FFI harness, upgrade and uninstall on a dedicated owner VM.
  -AllowHostedCI is only for an actual GitHub-hosted disposable Windows runner.
  NO driver, WFP, DNS, firewall, system service, UAC, certificate, SSH key
  or global proxy changes. Never treat A3 as transparent routing or 1.0 GO.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$KitZip,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [string]$OutputRoot = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'FlowBridge-A3'),
    [switch]$Execute,
    [switch]$AllowHostedCI
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Source = 'f5ecd48d8f81c594f755a55e7969b57d20903020'
$RunID = '43407093536'
$Version = '0.3.0-beta.1'
$ExpectedKitName = 'FlowBridge-0.3.0-beta.1-candidate-f5ecd48d8f81.zip'
$KitHash = '4b51d4136878476b48946361ce1635cb6d630e62b50ca82c73df28a5902ed8b8'
$InstallerHash = '74ff309d2e8ae115083bed9c5d4f233fd02dc841a8084a22912f3430c1e4b504'
$ManifestHash = '4a16dd710e468dd6e13e387fa4640c00102771758b4a5eb8c5f7bf9ec62bbf9a'
$ToolHash = 'faf62aabeea95ef316f5c0935177a65820ea4679ac94afe8b5461138dd17a33c'
$Name = 'FlowBridgeExplicitBeta'
$hosted = ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted')
function Require([bool]$condition,[string]$reason) {
    if(-not $condition){throw $reason}
}
function Digest([string]$path) {
    Require (Test-Path -LiteralPath $path -PathType Leaf) 'REQUIRED_FILE_MISSING'
    $item=Get-Item -LiteralPath $path
    Require (-not [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'FILE_LINK_REJECTED'
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Pinned([string]$path,[string]$expected,[long]$size=0) {
    Require ((Digest $path) -ceq $expected.ToLowerInvariant()) 'PINNED_SHA256_MISMATCH'
    if($size -gt 0){Require ((Get-Item -LiteralPath $path).Length -eq $size) 'PINNED_SIZE_MISMATCH'}
}
function RegVal([string]$path,[string]$field) {
    try {
        $property=Get-ItemProperty -LiteralPath $path -ErrorAction Stop
        return [string]$property.$field
    } catch {return ''}
}
function Fingerprint([string]$path) {
    if(-not (Test-Path -LiteralPath $path)){return 'ABSENT'}
    $item=Get-Item -LiteralPath $path
    Require (-not [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'STATE_LINK_REFUSED'
    if(-not $item.PSIsContainer){return 'FILE:'+ (Digest $path)}
    $children=@(Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction Stop)
    Require ($children.Count -le 1024) 'STATE_FINGERPRINT_LIMIT'
    $rows=New-Object 'System.Collections.Generic.List[string]'
    $root=$item.FullName.TrimEnd('\')+'\'
    [long]$total=0
    foreach($child in @($children | Sort-Object FullName)){
        Require (-not [bool]($child.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'STATE_LINK_REFUSED'
        $relative=$child.FullName.Substring($root.Length)
        if($child.PSIsContainer){$rows.Add('D/'+$relative)}
        else {
            $total += $child.Length
            Require ($total -le 104857600) 'STATE_FINGERPRINT_LIMIT'
            $rows.Add(('F/'+$relative+'/'+$child.Length+'/'+(Digest $child.FullName)))
        }
    }
    $bytes=[Text.Encoding]::UTF8.GetBytes([string]::Join([char]10,$rows.ToArray()))
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return 'DIR:'+([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}
    finally{$sha.Dispose()}
}
function RunBounded([string]$binary,[string]$args,[int]$seconds=120) {
    $proc=New-Object Diagnostics.Process
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$binary
    $start.Arguments=$args
    $start.UseShellExecute=$false
    $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true
    $start.RedirectStandardError=$true
    $proc.StartInfo=$start
    try{
        Require ($proc.Start()) 'PROCESS_LAUNCH_FAILED'
        $stdout=$proc.StandardOutput.ReadToEndAsync()
        $stderr=$proc.StandardError.ReadToEndAsync()
        $finished=$proc.WaitForExit($seconds*1000)
        if(-not $finished){
            try{$proc.Kill();[void]$proc.WaitForExit(4000)}catch{}
            throw 'PROCESS_TIMEOUT'
        }
        $output=[string]$stdout.GetAwaiter().GetResult()
        $errorText=[string]$stderr.GetAwaiter().GetResult()
        Require ($proc.ExitCode -eq 0) 'PROCESS_EXIT_NONZERO'
        return [pscustomobject]@{stdout=$output;stderr=$errorText}
    }finally{$proc.Dispose()}
}
function Until([scriptblock]$predicate,[string]$reason,[int]$seconds=90) {
    $deadline=[DateTime]::UtcNow.AddSeconds($seconds)
    while([DateTime]::UtcNow -lt $deadline) {
        if(& $predicate){return}
        Start-Sleep -Milliseconds 250
    }
    throw $reason
}
function CheckTarget {
    Require ($env:OS -eq 'Windows_NT') 'WINDOWS_REQUIRED'
    Require ([Environment]::Is64BitProcess) 'POWERSHELL_X64_REQUIRED'
    Require ([Environment]::MachineName.Equals($ExpectedComputerName,[StringComparison]::OrdinalIgnoreCase)) 'WRONG_TARGET_HOST'
    $os=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    if($AllowHostedCI) {
        Require $hosted 'HOSTED_ONLY_EXPLICIT_OVERRIDE_REJECTED'
        Require ($env:RUNNER_OS -eq 'Windows') 'WRONG_HOSTED_PLATFORM'
    } else {
        Require (-not $hosted) 'HOSTED_SCOPE_NOT_OWNER'
        Require ($os.InstallationType -eq 'Client') 'WINDOWS_SERVER_NOT_TARGET'
        Require ([int]$os.CurrentBuildNumber -ge 19045) 'UNSUPPORTED_WINDOWS_BUILD'
        Require ([string]$os.EditionID -match '^Professional') 'UNSUPPORTED_WINDOWS_EDITION'
        if($Execute) {
            Require ((Get-Process -Id $PID).SessionId -ne 0) 'INTERACTIVE_DESKTOP_REQUIRED'
        }
    }
}
function RefuseExistingBeta {
    $local=$env:LOCALAPPDATA
    $startMenu=Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\FlowBridge Explicit Beta'
    $profile=Join-Path $local $Name
    $settings='HKCU:\Software\FlowBridgeExplicitBeta'
    $uninstall='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridgeExplicitBeta'
    Require (-not (Test-Path -LiteralPath $profile) -and
             -not (Test-Path -LiteralPath $startMenu) -and
             (RegVal $settings 'InstallDir') -eq '' -and
             (RegVal $uninstall 'DisplayName') -eq '') 'EXISTING_BETA_REFUSED'
    Require (@(Get-Process -Name FlowBridgeExplicitBeta -ErrorAction SilentlyContinue).Count -eq 0) 'RUNNING_BETA_REFUSED'
    foreach($mutexName in @('Local\FlowBridge.NativeUI.v02','Local\FlowBridge.ExplicitBeta.NativeUI')){
        try {
            $mutex=[Threading.Mutex]::OpenExisting($mutexName)
            $mutex.Dispose()
            throw 'RUNNING_FLOWBRIDGE_REFUSED'
        }catch [Threading.WaitHandleCannotBeOpenedException] {}
    }
}
function StableSnapshot {
    $stablePaths=@(Join-Path $env:LOCALAPPDATA 'FlowBridge')
    $registered=RegVal 'HKCU:\Software\FlowBridge' 'InstallDir'
    if($registered) {
        foreach($file in @('FlowBridge.exe','flowbridge-cli.exe','flowbridge_ffi.dll','Uninstall.exe')){
            $stablePaths+=Join-Path $registered $file
        }
    }
    $keys=@(
        (RegVal 'HKCU:\Software\FlowBridge' 'InstallDir'),
        (RegVal 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridge' 'InstallLocation'),
        (RegVal 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridge' 'DisplayVersion'),
        (RegVal 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridge' 'UninstallString')
    )
    return [pscustomobject]@{paths=$stablePaths;hashes=@($stablePaths | ForEach-Object {Fingerprint $_});keys=$keys}
}
function VerifyStable([object]$before) {
    $after=StableSnapshot
    Require ((@($after.keys) -join [char]10) -ceq (@($before.keys) -join [char]10)) 'STABLE_REGISTRY_CHANGED'
    Require ((@($after.hashes) -join [char]10) -ceq (@($before.hashes) -join [char]10)) 'STABLE_FILES_CHANGED'
}
function InstalledPayload([string]$root,[object]$manifest) {
    foreach($file in @($manifest.payload)){
        $relative=[string]$file.path
        Require ($relative -match '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$' -and
                 $relative -notmatch '(^|/)\.\.?(/|$)') 'UNSAFE_MANIFEST_PATH'
        Pinned (Join-Path $root $relative.Replace('/','\')) ([string]$file.sha256) ([long]$file.bytes)
    }
}
$report=[ordered]@{
    schema='flowbridge-explicit-beta-native-powershell-a3-v1'
    source_sha=$Source;candidate_run_id=$RunID;candidate_version=$Version
    status='NOT_RUN';error_code=$null
    owner_native=$false;host_identity_basis='operator_supplied_not_attested'
    checks=[ordered]@{install='NOT_RUN';payload='NOT_RUN';launch='NOT_RUN';upgrade='NOT_RUN';uninstall='NOT_RUN';stable_preserved='NOT_RUN'}
    initial_preflight='NOT_RUN';screenshots=@();cleanup_required=$false
    python_required=$false;driver_loaded=$false;system_dns_changed=$false
    wfp_g2_accepted=$false;transparent_interception_accepted=$false
    release_accepted=$false;a3_full_acceptance=$false
}
$run=$null
try {
    CheckTarget
    Require ([IO.Path]::GetFileName($KitZip) -ceq $ExpectedKitName) 'KIT_NAME_MISMATCH'
    Pinned $KitZip $KitHash
    $report.owner_native=(-not $hosted)
    $run=Join-Path ([IO.Path]::GetFullPath($OutputRoot)) ('a3-nopython-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
    [void](New-Item -ItemType Directory -Path $run -ErrorAction Stop)
    $stage=Join-Path $run 'kit'
    Expand-Archive -LiteralPath $KitZip -DestinationPath $stage -ErrorAction Stop
    $manifestPath=Join-Path $stage 'windows\explicit-beta-package.json'
    $package=Join-Path $stage 'windows\FlowBridge-0.3.0-beta.1-windows-x64-setup.exe'
    $harness=Join-Path $stage 'windows\FlowBridgeNativeSmoke.exe'
    $tool=Join-Path $stage 'tools\explicit_beta_acceptance.py'
    Pinned $manifestPath $ManifestHash
    Pinned $package $InstallerHash
    Pinned $tool $ToolHash
    $manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    Require ($manifest.schema -ceq 'flowbridge-explicit-beta-windows-qa-package-v1' -and
             $manifest.source_sha -ceq $Source -and
             $manifest.explicit_socks_only -eq $true -and
             $manifest.signed -eq $false -and
             $manifest.publisher_release_approved -eq $false -and
             $manifest.driver_included -eq $false -and
             $manifest.system_service_included -eq $false -and
             $manifest.capture_helper_included -eq $false -and
             $manifest.gui_protected_ui_compiled_disabled -eq $true) 'BETA_SCOPE_NOT_PINNED'
    Require (@($manifest.payload).Count -eq 13) 'PAYLOAD_COUNT_MISMATCH'
    # The original build manifest can retain a CI-host absolute harness path.
    # The frozen ZIP and independent harness SHA/size are the trusted locators;
    # never use a build-host pathname to select an executable on this machine.
    Pinned $harness ([string]$manifest.qa_harness.sha256) ([long]$manifest.qa_harness.bytes)
    $indexPath=Join-Path $stage 'candidate-index.json'
    $index=Get-Content -LiteralPath $indexPath -Raw | ConvertFrom-Json
    Require ($index.schema -ceq 'flowbridge-explicit-beta-candidate-v1' -and
             $index.source_sha -ceq $Source -and
             $index.workflow_run_id -ceq $RunID -and
             $index.version -ceq $Version -and
             $index.hosted_candidate_valid -eq $true -and
             $index.release_accepted -eq $false) 'CANDIDATE_INDEX_SCOPE_MISMATCH'
    Require (@($index.files).Count -eq 21) 'CANDIDATE_INDEX_FILE_COUNT'
    foreach($file in @($index.files)) {
        $relative=[string]$file.path
        Require ($relative -match '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$' -and
                 $relative -notmatch '(^|/)\.\.?(/|$)') 'UNSAFE_CANDIDATE_PATH'
        Pinned (Join-Path $stage $relative.Replace('/','\')) ([string]$file.sha256) ([long]$file.bytes)
    }
    $report.initial_preflight='PINNED_BYTES_PASS'
    if(-not $Execute) {
        $report.status='VERIFIED_BYTES_NATIVE_NOT_RUN'
        Write-Host 'A3_PINNED_BYTES_PASS_NATIVE_NOT_RUN' -ForegroundColor Green
    } else {
        RefuseExistingBeta
        $stable=StableSnapshot
        $install=Join-Path $run 'Beta QA With Spaces'
        $other=Join-Path $run 'Must Not Relocate'
        $profile=Join-Path $env:LOCALAPPDATA $Name
        $shortcuts=Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\FlowBridge Explicit Beta'
        $settingKey='HKCU:\Software\FlowBridgeExplicitBeta'
        $uninstallKey='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridgeExplicitBeta'
        $report.cleanup_required=$true
        [void](RunBounded $package ('/S /D='+$install))
        Until {Test-Path -LiteralPath (Join-Path $install 'Uninstall.exe') -PathType Leaf} 'INSTALL_DID_NOT_CONVERGE'
        Require ((RegVal $settingKey 'InstallDir') -ceq $install -and
                 (RegVal $uninstallKey 'InstallLocation') -ceq $install) 'INSTALL_REGISTRATION_MISMATCH'
        $report.checks.install='PASS'
        InstalledPayload $install $manifest
        $cli=RunBounded (Join-Path $install 'flowbridge-cli.exe') 'capabilities' 25
        $caps=$cli.stdout|ConvertFrom-Json
        Require ($caps.mode -ceq 'explicit_loopback_socks5' -and
                 $caps.transparent_interception -eq $false -and
                 $caps.system_kill_switch -eq $false -and
                 $caps.udp -eq $false) 'FALSE_CAPABILITY_CLAIM'
        $report.checks.payload='PASS'
        $qa=Join-Path $run 'qa-harness'
        [void](New-Item -ItemType Directory -Path $qa -ErrorAction Stop)
        Copy-Item -LiteralPath $harness -Destination (Join-Path $qa 'FlowBridgeNativeSmoke.exe')
        Copy-Item -LiteralPath (Join-Path $install 'flowbridge_ffi.dll') -Destination (Join-Path $qa 'flowbridge_ffi.dll')
        Pinned (Join-Path $qa 'FlowBridgeNativeSmoke.exe') ([string]$manifest.qa_harness.sha256) ([long]$manifest.qa_harness.bytes)
        $ffi=@($manifest.payload | Where-Object { $_.path -ceq 'flowbridge_ffi.dll' })
        Require ($ffi.Count -eq 1) 'FFI_MANIFEST_AMBIGUOUS'
        Pinned (Join-Path $qa 'flowbridge_ffi.dll') ([string]$ffi[0].sha256) ([long]$ffi[0].bytes)
        $bmp=Join-Path $run 'installed-beta-ui.bmp'
        $gui=Join-Path $install 'FlowBridge.exe'
        $result=RunBounded (Join-Path $qa 'FlowBridgeNativeSmoke.exe') ('"'+$gui+'" "'+$bmp+'"') 180
        foreach($marker in @('PASS Windows DLL','PASS Win32 GUI','PASS compact Windows GUI')){
            Require ($result.stdout.Contains($marker)) 'GUI_SMOKE_INCOMPLETE'
        }
        $shotHashes=New-Object 'System.Collections.Generic.HashSet[string]'
        foreach($page in @('dashboard','ssh','proxy','apps','advanced')){
            $shot=Join-Path $run ('installed-beta-ui-compact-'+$page+'.bmp')
            Require (Test-Path -LiteralPath $shot -PathType Leaf) 'GUI_SCREEN_MISSING'
            Require ((Get-Item -LiteralPath $shot).Length -gt 1500) 'GUI_SCREEN_TOO_SMALL'
            $hash=Digest $shot
            Require ($shotHashes.Add($hash)) 'DUPLICATE_GUI_SCREEN'
            $report.screenshots+=@{name=[IO.Path]::GetFileName($shot);sha256=$hash}
        }
        Require (Test-Path -LiteralPath (Join-Path $profile 'profile.json') -PathType Leaf) 'BETA_PROFILE_MISSING'
        $report.checks.launch='PASS'
        $betaBefore=Fingerprint $profile
        $markerPath=Join-Path $install 'native-qa-preserve-user-file.txt'
        [IO.File]::WriteAllText($markerPath,'Preserve this user-owned test file.',[Text.UTF8Encoding]::new($false))
        $markerHash=Digest $markerPath
        [void](RunBounded $package ('/S /D='+$other))
        InstalledPayload $install $manifest
        Require (-not (Test-Path -LiteralPath $other) -and
                 (Fingerprint $profile) -ceq $betaBefore -and
                 (Digest $markerPath) -ceq $markerHash) 'UPGRADE_CHANGED_USER_STATE'
        $report.checks.upgrade='PASS'
        [void](RunBounded (Join-Path $install 'Uninstall.exe') '/S')
        Until {
            -not (Test-Path -LiteralPath (Join-Path $install 'Uninstall.exe')) -and
            (RegVal $settingKey 'InstallDir') -eq '' -and
            (RegVal $uninstallKey 'DisplayName') -eq ''
        } 'UNINSTALL_DID_NOT_CONVERGE'
        foreach($file in @($manifest.payload)){
            Require (-not (Test-Path -LiteralPath (Join-Path $install ([string]$file.path).Replace('/','\')))) 'OWNED_PAYLOAD_SURVIVED_UNINSTALL'
        }
        Require (-not @(Get-ChildItem -LiteralPath $shortcuts -Filter '*.lnk' -ErrorAction SilentlyContinue).Count -and
                 (Fingerprint $profile) -ceq $betaBefore -and
                 (Digest $markerPath) -ceq $markerHash) 'UNINSTALL_CHANGED_USER_STATE'
        $report.checks.uninstall='PASS'
        VerifyStable $stable
        $report.checks.stable_preserved='PASS'
        $report.cleanup_required=$false
        $report.status=if($hosted){'CI_AUTOMATED_CHECKS_PASS'}else{'OWNER_NATIVE_AUTOMATED_CHECKS_PASS'}
        Write-Host ('A3_AUTOMATED_PASS_MANUAL_GUI_SSH_OPEN; '+$report.status) -ForegroundColor Green
    }
} catch {
    $text=[string]$_.Exception.Message
    $report.error_code=if($text -match '^[A-Z][A-Z0-9_]+$'){$text}else{'UNCLASSIFIED_QA_ERROR'}
    $report.status='FAIL'
    Write-Host ('A3_QA_FAIL: '+$report.error_code) -ForegroundColor Red
} finally {
    if($null -ne $run -and (Test-Path -LiteralPath $run -PathType Container)){
        $destination=Join-Path $run 'native-acceptance.json'
        [IO.File]::WriteAllText($destination,($report|ConvertTo-Json -Depth 12)+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
        Write-Host ('A3_EVIDENCE_DIR: '+$run)
    }
}
if($report.status -eq 'FAIL'){exit 1}
