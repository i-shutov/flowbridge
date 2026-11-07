$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$out = Join-Path $env:GITHUB_WORKSPACE 'build/g2-kernel-r19'
New-Item -ItemType Directory -Force $out | Out-Null
$nuget = (Get-Command nuget.exe -ErrorAction Stop).Source
& $nuget install Microsoft.Windows.WDK.x64 -Version 10.0.26100.6584 -OutputDirectory "$out/wdk" -NonInteractive -Source https://api.nuget.org/v3/index.json -DirectDownload
if ($LASTEXITCODE -ne 0) { throw 'Pinned official WDK acquisition failed' }
$package = Join-Path $out 'wdk/Microsoft.Windows.WDK.x64.10.0.26100.6584'
$km = @(Get-ChildItem -Path $package -Recurse -Filter fwpsk.h)
if ($km.Count -ne 1) { throw 'WDK kernel header selection ambiguous' }
$env:FB_WDK_KM = $km[0].Directory.FullName
$env:FB_WDK_CRT = Join-Path $env:FB_WDK_KM 'crt'
$lib = @(Get-ChildItem -Path $package -Recurse -Filter fwpkclnt.lib | Where-Object { $_.Directory.Name -eq 'x64' })
if ($lib.Count -ne 1) { throw 'WDK x64 library selection ambiguous' }
$env:FB_WDK_LIB = $lib[0].Directory.FullName
$sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/Include'
$sdkVersion = Get-ChildItem $sdk -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'shared/ntdef.h') } | Sort-Object Name -Descending | Select-Object -First 1
if (-not $sdkVersion) { throw 'SDK shared headers missing' }
$env:FB_SDK_SHARED = Join-Path $sdkVersion.FullName 'shared'
$env:FB_SDK_UCRT = Join-Path $sdkVersion.FullName 'ucrt'
$llvm = Join-Path $env:ProgramFiles 'LLVM/bin'
if (-not (Test-Path (Join-Path $llvm 'libclang.dll'))) { throw 'libclang.dll missing' }
$env:LIBCLANG_PATH = $llvm
$env:RUSTFLAGS = '-C target-feature=+crt-static'
Push-Location (Join-Path $root 'kernel')
try {
  & cargo generate-lockfile
  if ($LASTEXITCODE -ne 0) { throw 'Cargo dependency resolution failed' }
  & cargo build --locked --release
  if ($LASTEXITCODE -ne 0) { throw 'Kernel build failed; STOP, no load attempted' }
  Copy-Item target/release/flowbridge_g2_witness.dll "$out/flowbridge_g2_witness.sys"
  Copy-Item Cargo.lock "$out/Cargo.lock"
  $bindings = Get-ChildItem target/release/build -Recurse -Filter wdk.rs | Select-Object -First 1
  Copy-Item $bindings.FullName "$out/generated-wdk.rs"
} finally { Pop-Location }
& rustc --edition=2021 --test "$root/kernel/src/ledger.rs" -o "$out/ledger-tests.exe"
if ($LASTEXITCODE -ne 0) { throw 'Exact kernel ledger tests did not compile' }
& "$out/ledger-tests.exe"
if ($LASTEXITCODE -ne 0) { throw 'Exact kernel ledger regression failed' }
& python "$root/verify-build.py" "$out/flowbridge_g2_witness.sys" "$out/build-result.json"
if ($LASTEXITCODE -ne 0) { throw 'Kernel PE audit failed' }
# Intentionally no installation, test signing, certificate import, service, filter or driver load.
