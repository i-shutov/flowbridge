# A4 — Frozen explicit SOCKS beta native macOS Intel + Apple Silicon

Date: 2026-11-15. A single **unchanged binary** across two genuinely different hosted Mac architectures.
Scope: explicit SOCKS-only v0.3.0-beta.1, NOT the signed Network Extension or product 1.0.

## Original immutable inputs (NO new build)

The exact source SHA is `f5ecd48d8f81c594f755a55e7969b57d20903020`.
The original candidate was produced by [unified run #43407093536](https://github.com/i-shutov/flowbridge/actions/runs/43407093536),
[artifact #14028139291](https://github.com/i-shutov/flowbridge/actions/runs/43407093536/artifacts/14028139291).

| Input | Original SHA256 |
| --- | --- |
| Inner candidate ZIP | `4b51d4136878476b48946361ce1635cb6d630e62b50ca82c73df28a5902ed8b8` |
| Universal macOS pkg | `7eb645e227442ba5a2d12bc1b9c5853212baf8a3d28e7215640f0e3e2ec0453c` |
| macOS manifest | `ed00c3257a4b5f1db453169fc802c3ba85215265bb2dce783d79275cbb386a03` |
| Operator QA tool | `faf62aabeea95ef316f5c0935177a65820ea4679ac94afe8b5461138dd17a33c` |

The new verifier checks all 21 indexed candidate payloads (SHA256 and exact sizes)
and original SHA256SUMS, plus source, version, run identity and limitations.
It is independent of the original frozen candidate assembler and QA tool.

## Two actual CPU types

- `macos-15` runs on native Apple Silicon arm64.
- `macos-15-intel` runs on native Intel x86_64, not Rosetta.
- A strict host `uname -m` and QA JSON architecture equality gate prevents
  inadvertently passing two ARM64 jobs as Intel coverage.
- On each new disposable GitHub runner, the original SHA-pinned Python
  acceptance tool from the kit runs byte-only validation first, followed
  by its existing explicit `--execute` macOS package install and removal.

Real hosted 6-step lifecycle: package install, payload parity, actual
four-second app process launch, upgrade, uninstall, stable preservation.
Original pkg structure/scripts, ad-hoc app signing, arm64+x86_64 lipo
and expected bundle/receipt are examined by the unmodified QA tool.
Only the ephemeral hosted app+receipt are touched; no other user profiles
or system NE/network/driver configuration is changed.

The cross-arch verifier refuses a missing platform, multiple reports,
unequal source or package hashes, partial lifecycle, forged owner status,
wrong architecture, false publisher/NE/DNS claims and cleanup failures.
Nine synthetic negative-control tests cover those failure paths.

## Proof and remaining gates

The correct verdict on success is `HOSTED_MAC_INTEL_AND_ARM_6_6_OWNER_OPEN`.
`owner_native_accepted=false`, `native_ne_activated=false`,
`physical_dns_no_leak_proved=false`, `release_accepted=false`.

This verifies app binary execution on hosted native Intel and ARM64,
**not actual owner Mac acceptance**. Full A4 still requires target
Apple Silicon and Intel operator machines, manual GUI/keyboard, actual
managed SSH/host-key, independent original evidence and reviewer GO.
The four-second launch alone does not prove all GUI controls or traffic.

The beta has no Network Extension, driver, kernel kill switch or
transparent interception. A4 hosted CI cannot close macOS 1.0 R02,
physical no-DIRECT, DNS/DoH/QUIC/UDP, signing/notarization, or A5/A6.
No change to main, beta source/PR #59 or owner machines is authorized.

Primary official runner labels:
https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job
