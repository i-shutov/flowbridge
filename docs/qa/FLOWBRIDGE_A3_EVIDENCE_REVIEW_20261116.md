# FlowBridge beta A3 — independent Win10 evidence review, 2026-11-16

## Why this blocker work is needed

The original pinned `0.3.0-beta.1` installer and Python-free PowerShell A3
runner passed 6/6 hosted checks in PR #64. Target owner Win10 Pro
`VM-910136` has **not** yet run these exact frozen bytes. The locally
produced report and five screenshot files must be independently reviewed,
without trusting a printed `PASS` or inventing native acceptance.

This stacked QA-only change adds
`tools/explicit_beta_win10_owner_verify.py` and adversarial tests.
There is **no change** to frozen beta binaries, installer, A3 PowerShell
runner or any OS configuration.

## Operator: collect A3 evidence after running the pinned A3 script

On `VM-910136`, only after the read-only preflight and explicit
`-Execute` session from
[PR #64](https://github.com/i-shutov/flowbridge/pull/64):

```powershell
$ErrorActionPreference = 'Stop'
$root = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'FlowBridge-A3'
$run = Get-ChildItem -LiteralPath $root -Directory -Filter 'a3-nopython-*' |
       Sort-Object LastWriteTime -Descending | Select-Object -First 1
if(-not $run) { throw 'A3 evidence directory not found' }
$report = Get-Content -LiteralPath (Join-Path $run.FullName 'native-acceptance.json') -Raw | ConvertFrom-Json
if($report.status -ne 'OWNER_NATIVE_AUTOMATED_CHECKS_PASS') {
    throw ('Preserve all evidence; A3 is not PASS: '+$report.status)
}
$names = @('dashboard','ssh','proxy','apps','advanced')
$files = @((Join-Path $run.FullName 'native-acceptance.json'))
foreach($name in $names) {
    $files += Join-Path $run.FullName ('installed-beta-ui-compact-'+$name+'.bmp')
}
foreach($p in $files) {
    if(-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw ('Missing: '+$p) }
}
$zip = Join-Path ([Environment]::GetFolderPath('Desktop')) 'FlowBridge-A3-Win10-evidence.zip'
Compress-Archive -LiteralPath $files -DestinationPath $zip -Force
Get-FileHash -LiteralPath $zip -Algorithm SHA256 | Format-List
Write-Host ('EVIDENCE: '+$zip)
```

Upload **only the six files** (JSON + five BMPs). The extracted
`kit/` content, installation location, private profiles and credentials
are not required. On a failed QA, retain original failure evidence and
do **not** use the positive-only packager to turn FAIL into PASS.

## Independent read-only reviewer (Python is needed only on reviewer host)

```sh
python3 tools/explicit_beta_win10_owner_verify.py FlowBridge-A3-Win10-evidence.zip \
  --output FlowBridge-A3-Win10-review.json
```

This accepts a ZIP or the original report directory without extracting
untrusted ZIP paths. It pins exact frozen source/run/version/schema,
owner-reported six phases, original preflight, false release/kernel claims,
five canonical unique BMP names with matching SHA256 and plausible bitmap
headers. Malformed, unsafe, ambiguous or oversized input fails closed;
tests include forged host/release status, partial lifecycle, bad image,
hash mismatch, duplicated content and ZIP traversal/resource exhaustion.

Positive structural output is deliberately
`EVIDENCE_STRUCTURE_PASS_MANUAL_REVIEW_OPEN`.
`owner_native_claimed=true` is an unverified statement supplied by
the operator-side script, **not** an independent host attestation.
A reviewer must still inspect the five actual screenshots, original
installation/uninstall behavior, GUI keyboard/UX, and separate real
managed SSH/host-key/stop/DNS boundary. Windows 11 owner run is separate.

`a3_full_acceptance=false`, `release_accepted=false`, and
`wfp_g2_accepted=false` are never promoted by this verifier.
The WFP signed-native 1.0 path and macOS NE are wholly outside scope.

**Acceptance gate remains A3 OWNER OPEN, 1.0 G2 NO-GO.**
