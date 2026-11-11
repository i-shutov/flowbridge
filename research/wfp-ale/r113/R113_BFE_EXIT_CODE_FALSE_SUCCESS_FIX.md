# FlowBridge R113 — BFE inventory exit-code evidence integrity

Scope: `i-shutov/flowbridge`, **only** `research/windows-wfp-ale-attribution-20261107`.
Not beta, PR #56, main or a PacketBound/G2 verdict. No Windows runner/CI,
VNC, kernel driver/callout/filter, service, firewall, system-security, network,
paid service or automation modification was performed.

## Functional bug in the exact committed R112 PowerShell 5.1 harness

R112 source Git blob `6c85b367ead60d3ca490e7fec2f70eb468cb608c`
(`research/wfp-ale/r112/R112_WINDOWS_NATIVE_READONLY_CHECK.ps1`, research
commit `5293b16a1dc8ac9d4de662a9608090fca5ea124c`) contains:

```powershell
$report.bfe_inventory_exit_code = $inventory.ExitCode
$report.status = 'BFE_READONLY_MANAGEMENT_SNAPSHOT_NO_KERNEL_PROOF'
$exitStatus = 0
```

This unconditional 0 occurs after `-RunReadOnlyBfe` even if the exact R112 Rust
inspector returned `2` (a BFE API error, malformed policy or inaccessible
object), `3` (visible same-sublayer weight candidate), or `4` (no visible
candidate; still UNKNOWN). A wrapper interpreting exit 0 as successful live
BFE verification would be misled. **This is a concrete evidence-integrity
bug, not an observed leak or Windows API execution failure.**

## Change

- Preserve source Git-blob SHA gate for the exact Rust code, unchanged:
  `49506ca07145c18947a0845f2a1a63b3de1f54ec`.
- Preserve default metadata-only build, optional `-RunUnitTests`, optional
  `-RunReadOnlyBfe` requiring the unit-test stage. No package installation.
- For live inventory, treat Rust return `2`, `0`, `1` or any unrecognized value
  as failed/unavailable (PowerShell exit `2`).
- Require five parseable JSONL rows: four ordered ALE rule records with
  nonnegative counters, then one terminal status. Verify actual decision
  from higher/equal-weight counters matches exit 3 or 4. Verify terminal
  `{single_enum_snapshot:true,acl_hidden_filters_possible:true,
  kernel_proof:false,no_direct_proof:false}` before accepting a diagnostic.
- Preserve the **nonzero** exit code for either valid diagnostic:
  `3` = `BFE_VISIBLE_ARBITRATION_CANDIDATE_NO_KERNEL_PROOF`;
  `4` = `BFE_UNKNOWN_NO_VISIBLE_CANDIDATE`. Neither is a GO/PASS.
- Failure status still includes `reason`, raw JSONL, Windows edition/build,
  Rust version, executable SHA-256 and BFE returned code when available.

## Reproduction / independent test

```bash
python3 research/wfp-ale/r113/r113_bfe_exit_negative.py
python3 research/wfp-ale/r113/r113_bfe_exit_negative.py --matrix
node research/wfp-ale/r113/r113_bfe_exit_independent.mjs
```

Seven Python unittest assertions and two independent Python/Node state
models reproduce 154 deterministic scenarios (6 exit-code classes x
2 higher x 2 equal x 3 terminal classes x 2 claimed proof booleans,
plus 10 malformed transcripts). Every live BFE outcome is nonzero;
old R112's false-success branch is captured in
`R112_FALSE_SUCCESS_EXCERPT.txt` with its original exact blob reference.
These are user-mode deterministic tests; the PowerShell script and Rust
are **NOT** executed here on Windows. The Linux executor has no `rustc`,
`cargo`, `rustup`, Windows runtime; `static.rust-lang.org` did not resolve.

## Approved-machine native read-only procedure

From an existing local checkout of the **exact research commit** on an
already authorized Windows x64 host with an existing Rust compiler:

```powershell
# No installation, BFE access, or driver/filter changes; metadata only
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\research\wfp-ale\r112\R112_WINDOWS_NATIVE_READONLY_CHECK.ps1

# Native Windows ABI unit tests; still no BFE access
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\research\wfp-ale\r112\R112_WINDOWS_NATIVE_READONLY_CHECK.ps1 -RunUnitTests

# Optional read-only BFE management inventory after native unit tests
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\research\wfp-ale\r112\R112_WINDOWS_NATIVE_READONLY_CHECK.ps1 -RunUnitTests -RunReadOnlyBfe
```

The script records evidence in an isolated `%TEMP%\FlowBridge-R112-*`
folder. Exit codes 2, 3 and 4 are non-PASS as documented. No Windows host
was accessed by this research cycle.

## Documentation / trust boundary

`FwpmFilterEnum0` works on a BFE management snapshot and requires freeing the
returned pointer array by `FwpmFreeMemory0`. `FwpmFilterCreateEnumHandle0`
has ACL-dependent visibility; enumerator creation without an explicit
transaction does **not** guarantee current policy. The diagnostic cannot
prove a live kernel classify callback, origin PID+creation epoch+canonical
image-section path/AppId, actual redirected socket, accepted peer, SSH
protection, sibling no-DIRECT, UDP/DNS/QUIC coverage, reuse/reauthorization,
or behavior during WFP/SSH loss.

Official Microsoft API references:
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltercreateenumhandle0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_action0

## GO/NO-GO and next decisive experiment

**GO only for off-host test model and harness source correction.** No native
Windows PASS, no PacketBound/G2 PASS or leak-free/no-DIRECT acceptance.
Next test: on authorized Windows x64, run exact metadata compile then ABI unit
tests and optionally read-only BFE inventory; export Windows build, SDK,
`rustc -vV`, exact binary/source SHA-256, raw JSONL, exit code, and
PowerShell evidence JSON. Independently inspect the outputs. Any genuine
kernel-origin or WFP enforcement validation needs separate future approval.
