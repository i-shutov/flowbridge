# A disposable hosted experiment. It neither uses nor approves a FlowBridge runtime.
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ARCH -ne 'X64') {
    throw 'This experiment requires a GitHub-hosted Windows x64 runner'
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$scratch = Join-Path $env:RUNNER_TEMP ('flowbridge-raw512-' + $env:GITHUB_RUN_ID + '-' + $env:GITHUB_RUN_ATTEMPT)
$source = Join-Path $scratch 'openssh'
$vcpkg = Join-Path $scratch 'vcpkg'
$runtime = Join-Path $scratch 'runtime'
$reports = Join-Path $scratch 'reports'
$buildReceipt = Join-Path $scratch 'build.json'
$evidenceTool = Join-Path $PSScriptRoot 'win32_openssh_capacity_lab.py'
$log = Join-Path $scratch 'build.log'
$ownsScratch = $false
$phase = 'HOST_TOOLCHAIN'
$exitCode = 1

function Invoke-Logged {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments *>> $log
    if ($LASTEXITCODE -ne 0) { throw 'external test command failed' }
}

function Checkout-Pin {
    param([string]$Directory, [string]$Remote, [string]$Commit, [switch]$Shallow)
    New-Item -ItemType Directory -Path $Directory | Out-Null
    Invoke-Logged git @('-C', $Directory, 'init', '--quiet')
    Invoke-Logged git @('-C', $Directory, 'config', 'core.autocrlf', 'false')
    Invoke-Logged git @('-C', $Directory, 'remote', 'add', 'origin', $Remote)
    # Keep the vcpkg Git trees for its manifest's registry versions.
    $fetch = @('-C', $Directory, 'fetch', '--quiet', '--no-tags', '--filter=blob:none')
    if ($Shallow) { $fetch += '--depth=1' }
    Invoke-Logged git ($fetch + @('origin', $Commit))
    Invoke-Logged git @('-C', $Directory, 'checkout', '--quiet', '--detach', $Commit)
}

try {
    $vswhere = Join-Path ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) 'Microsoft Visual Studio/Installer/vswhere.exe'
    $vs = & $vswhere -latest -version '[17.0,18.0)' -products '*' `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre `
        -property installationPath
    if ($LASTEXITCODE -ne 0 -or -not $vs) { throw 'VS 2022 v143 and Spectre libraries are required' }
    $msbuild = Join-Path $vs 'MSBuild/Current/Bin/amd64/MSBuild.exe'
    $sdk = '10.0.22621.0'
    $sdkRoot = Join-Path ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) 'Windows Kits/10'
    if (-not (Test-Path -LiteralPath $msbuild -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $sdkRoot "Include/$sdk/um/Windows.h") -PathType Leaf)) {
        throw 'Pinned Windows SDK or MSBuild missing'
    }
    New-Item -ItemType Directory -Path $scratch | Out-Null
    $ownsScratch = $true

    $phase = 'PINNED_SOURCE'
    Checkout-Pin $source 'https://github.com/PowerShell/openssh-portable.git' '274893f8d1fe86c4d128b514c3af4bc10cdc0c99' -Shallow
    Checkout-Pin $vcpkg 'https://github.com/microsoft/vcpkg.git' '99541cc939bf01ae3c42f928266d648f5acb88fd'
    & python $evidenceTool prepare --source $source --vcpkg $vcpkg 2>> $log
    if ($LASTEXITCODE -ne 0) { throw 'Upstream source or single modification verification failed' }

    $phase = 'VCPKG_MANIFEST'
    $env:VCPKG_DISABLE_METRICS = '1'
    $env:VCPKG_BINARY_SOURCES = 'clear'
    $env:VCPKG_ROOT = $vcpkg
    $env:VCPKG_VISUAL_STUDIO_PATH = $vs
    $env:VCPKG_PLATFORM_TOOLSET = 'v143'
    $env:VCPKG_DOWNLOADS = Join-Path $scratch 'downloads'
    Invoke-Logged (Join-Path $vcpkg 'bootstrap-vcpkg.bat') @('-disableMetrics')
    $project = Join-Path $source 'contrib/win32/openssh'
    $installed = Join-Path $project 'vcpkg_installed/x64-custom'
    $triplets = Join-Path $project 'vcpkg_triplets'
    $ports = Join-Path $project 'vcpkg_overlay_ports'
    Push-Location $project
    try {
        Invoke-Logged (Join-Path $vcpkg 'vcpkg.exe') @('install', '--triplet=x64-custom', "--x-install-root=$installed",
            "--overlay-triplets=$triplets", "--overlay-ports=$ports")
    } finally {
        Pop-Location
    }

    $phase = 'EXPERIMENTAL_COMPILATION'
    $integration = Join-Path $vcpkg 'scripts/buildsystems/msbuild'
    $properties = Join-Path $integration 'vcpkg.props'
    $targets = Join-Path $integration 'vcpkg.targets'
    $solution = Join-Path $project 'Win32-OpenSSH.sln'
    # Use the upstream solution paths while importing vcpkg only for this invocation.
    Invoke-Logged $msbuild @($solution, '/t:core\ssh;core\sshd;core\sshd-auth;core\sshd-session;core\ssh-keygen',
        '/p:Configuration=Release', '/p:Platform=x64', "/p:WindowsSDKVersion=$sdk",
        "/p:ForceImportAfterCppProps=$properties", "/p:ForceImportAfterCppTargets=$targets",
        '/p:VcpkgEnabled=true', '/p:VcpkgEnableManifest=true', '/p:VcpkgManifestInstall=false',
        '/p:VcpkgApplocalDeps=false', '/p:VcpkgTriplet=x64-custom', "/p:VcpkgInstalledDir=$installed",
        "/p:VcpkgRoot=$vcpkg",
        '/nodeReuse:false', '/m:2', '/nologo')

    $phase = 'RUNTIME_PROVENANCE'
    New-Item -ItemType Directory -Path $runtime | Out-Null
    $products = Join-Path $source 'bin/x64/Release'
    # WIN32 defaults in step-pinned pathnames.h and servconf.c resolve both sshd
    # children next to sshd.exe. The loopback harness leaves those defaults in place.
    foreach ($name in @('ssh.exe', 'sshd.exe', 'sshd-auth.exe', 'sshd-session.exe', 'ssh-keygen.exe')) {
        $binary = Join-Path $products $name
        if ((Get-AuthenticodeSignature -LiteralPath $binary).Status -ne 'NotSigned') {
            throw 'Expected locally compiled unsigned experiment binary'
        }
        Copy-Item -LiteralPath $binary -Destination $runtime
    }
    $dependencies = Join-Path $installed 'x64-custom/bin'
    Get-ChildItem -LiteralPath $dependencies -File -Filter '*.dll' |
        Copy-Item -Destination $runtime
    & python $evidenceTool built --source $source --vcpkg $vcpkg --runtime $runtime --receipt $buildReceipt 2>> $log
    if ($LASTEXITCODE -ne 0) { throw 'Missing or unbound compiled runtime' }

    $phase = 'STRICT_RAW_512'
    $env:FLOWBRIDGE_HOSTED_WINDOWS_SSH = '1'
    & python (Join-Path $repo 'tests/windows_real_ssh_hosted.py') --scenario raw `
        --ssh (Join-Path $runtime 'ssh.exe') --sshd (Join-Path $runtime 'sshd.exe') `
        --keygen (Join-Path $runtime 'ssh-keygen.exe') --output $reports *>> $log
    $probeExit = $LASTEXITCODE
    & python $evidenceTool result --source $source --vcpkg $vcpkg --runtime $runtime --receipt $buildReceipt `
        --reports $reports --probe-exit $probeExit 2>> $log
    $exitCode = $LASTEXITCODE
} catch {
    # Avoid emitting build paths or complete compiler command lines.
    $codes = @()
    if ($ownsScratch -and (Test-Path -LiteralPath $log)) {
        $tail = Get-Content -LiteralPath $log -Tail 240
        $codes = @([regex]::Matches(($tail -join "`n"), '\b(?:MSB|LNK|C)[0-9]{4}\b').Value |
            Sort-Object -Unique | Select-Object -First 12)
    }
    Write-Host ('FLOWBRIDGE_RAW512_LAB_BLOCKED ' + (@{phase=$phase; compiler_codes=$codes} | ConvertTo-Json -Compress))
} finally {
    if ($ownsScratch) {
        try {
            Remove-Item -LiteralPath $scratch -Recurse -Force
            Write-Host 'FLOWBRIDGE_RAW512_LAB_OWNED_TEMP_CLEANUP=PASS'
        } catch {
            Write-Host 'FLOWBRIDGE_RAW512_LAB_OWNED_TEMP_CLEANUP=FAIL'
            $exitCode = 1
        }
    }
}
exit $exitCode
