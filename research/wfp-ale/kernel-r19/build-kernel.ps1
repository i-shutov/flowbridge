$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$out = Join-Path $env:GITHUB_WORKSPACE 'build/g2-kernel-r19'
New-Item -ItemType Directory -Force $out | Out-Null
& python "$root/package_r24.py" $out
if ($LASTEXITCODE -ne 0) { throw 'Exact source snapshot failed' }
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
$env:FB_PDB_OUTPUT = Join-Path $out 'flowbridge_g2_witness.pdb'
Push-Location (Join-Path $root 'kernel')
try {
  # The exact Cargo.lock ships IN the repository and is checked before
  # source snapshot; no network-driven lockfile regeneration is permitted.
  Copy-Item Cargo.lock "$out/Cargo.lock"
  & cargo build --locked --release
  if ($LASTEXITCODE -ne 0) { throw 'Kernel build failed; STOP, no load attempted' }
  Copy-Item target/release/flowbridge_g2_witness.dll "$out/flowbridge_g2_witness.sys"
  # The exact release link command receives /PDB:FB_PDB_OUTPUT.
  # Never accept a random PDB discovered elsewhere in Cargo output.
  $symbol = Join-Path $out 'flowbridge_g2_witness.pdb'
  if (-not (Test-Path -LiteralPath $symbol -PathType Leaf) -or
      (Get-Item -LiteralPath $symbol).Length -lt 1024) {
    throw 'Kernel release linker did not emit the exact pinned PDB'
  }
} finally {
  $bindings = Get-ChildItem target/release/build -Recurse -Filter wdk.rs -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($bindings) { Copy-Item $bindings.FullName "$out/generated-wdk.rs" }
  Pop-Location
}
& rustc --edition=2021 --test "$root/kernel/src/ledger.rs" -o "$out/ledger-tests.exe"
if ($LASTEXITCODE -ne 0) { throw 'Exact kernel ledger tests did not compile' }
& "$out/ledger-tests.exe"
if ($LASTEXITCODE -ne 0) { throw 'Exact kernel ledger regression failed' }
& rustc --edition=2021 --test "$root/kernel/src/auth_appid.rs" -o "$out/auth-appid-tests.exe"
if ($LASTEXITCODE -ne 0) { throw 'R36 actual AUTH AppId tests did not compile' }
& "$out/auth-appid-tests.exe"
if ($LASTEXITCODE -ne 0) { throw 'R36 actual AUTH AppId tests failed' }
& rustc --edition=2021 --test "$root/kernel/src/handoff.rs" -o "$out/handoff-tests.exe"
if ($LASTEXITCODE -ne 0) { throw 'Handoff tests compile failed' }
& "$out/handoff-tests.exe"
if ($LASTEXITCODE -ne 0) { throw 'Handoff tests failed' }
Push-Location (Join-Path $root 'broker-package')
try {
  # Pinned original 185-package broker graph; refuse a new resolution.
  Copy-Item Cargo.lock "$out/broker.Cargo.lock"
  & cargo build --locked --release
  if ($LASTEXITCODE -ne 0) { throw 'Broker and scoped policy compilation failed' }
  Copy-Item target/release/flowbridge-redirect-broker.exe "$out/flowbridge-redirect-broker.exe"
  $testOutput = & cargo test --locked --release -- --nocapture 2>&1
  $testExit = $LASTEXITCODE
  $testOutput | ForEach-Object { Write-Output $_ }
  if ($testExit -ne 0) { throw 'Actual broker/policy/native-negative tests failed' }
  $summary = [regex]::Match(($testOutput -join "`n"), 'test result: ok\. (\d+) passed; 0 failed')
  if (-not $summary.Success) { throw 'Missing exact broker test count' }
  $tests = [int]$summary.Groups[1].Value
} finally { Pop-Location }
& "$out/flowbridge-redirect-broker.exe" --reject-unredirected | Set-Content -Encoding utf8 "$out/broker-negative.json"
if ($LASTEXITCODE -ne 0) { throw 'Unredirected socket was not rejected' }
& "$out/flowbridge-redirect-broker.exe" --verify-policy-plan | Set-Content -Encoding utf8 "$out/policy-plan-native.json"
if ($LASTEXITCODE -ne 0) { throw 'Native policy structure construction failed' }
& python "$root/ownership_check_r24.py" | Set-Content -Encoding utf8 "$out/ownership-contract.json"
if ($LASTEXITCODE -ne 0) { throw 'Accepted-socket compile-time ownership check failed' }
[ordered]@{ ok=$true; source_sha=$env:GITHUB_SHA; actual_broker_tests_passed=$tests; scoped_policy_code_compiled=$true; accepted_socket_ownership_compile_tests=$true; actual_policy_installed=$false; kernel_driver_loaded=$false; full_redirect_chain_executed=$false; g2_pass=$false; release_accepted=$false } | ConvertTo-Json | Set-Content -Encoding utf8 "$out/r24-build-scope.json"
& python "$root/verify-build.py" "$out/flowbridge_g2_witness.sys" "$out/build-result.json"
if ($LASTEXITCODE -ne 0) { throw 'Kernel PE audit failed' }
# Stage an UNSIGNED kernel submission candidate with exact source/provenance
# hashes and re-extracted CAB member checks. No signing/loading or policy change.
& "$root/signing-r38/prepare_submission_r38.ps1" -BuildDirectory "$out" -OutputDirectory (Join-Path "$out" "signing-r38")
if ($LASTEXITCODE -ne 0) { throw 'R38 unsigned CAB pre-submission failed' }
& python -m unittest discover -s "$root/signing-r38" -p 'test_*.py' -v
if ($LASTEXITCODE -ne 0) { throw 'R38 signed-driver admission source tests failed' }
# NEVER invoke --serve-admitted-lab here: no signed-driver/VNC/rescue admission.
# No kernel load, filter installation, signature bypass, service or host-policy change.
