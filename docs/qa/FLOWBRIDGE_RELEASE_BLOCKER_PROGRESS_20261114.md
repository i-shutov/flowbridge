# FlowBridge — blocker-oriented checkpoint, 14 November 2026

**1.0.0 = NO-GO; candidate beta remains NOT RELEASED.**
This report records actual changed source and CI since the previous B0
checkpoint, without transferring hosted PASS to owner physical acceptance.

## Source identity and release safety

| Area | Source and evidence | Correct scope verdict |
| --- | --- | --- |
| Product main | 5b5afc2feeda2195f302380e615ba003d4906e09 | Unchanged 0.x, not 1.0 integrated |
| Frozen 0.3.0-beta.1 | f5ecd48d8f81c594f755a55e7969b57d20903020; unified run 43407093536 | 11/11 hosted jobs PASS; A3/A4 owner still NOT_RUN |
| WFP R182 research | Draft [PR #61](https://github.com/i-shutov/flowbridge/pull/61), source a738a125450defb6e675b1ff5dcb5a321665255e | Rust retained-authorization MODEL only; no physical G2 |
| macOS R02 preflight | Draft [PR #60](https://github.com/i-shutov/flowbridge/pull/60), source 32f15c8131a90f34dee6a86527191c5242fc5576 | Signed-bundle preflight code/test PASS; actual Team/NE activation NOT_RUN |
| Independent A5 kit | Draft [PR #62](https://github.com/i-shutov/flowbridge/pull/62), source 78ebcb2bb14089ee96c2fa8c93f85acb7c1a4e25 | **Original kit technical audit PASS**, owner license/legal/native review OPEN |
| A3 owner operator tool | tools/windows/FlowBridge-ExplicitBeta-A3-Frozen.ps1 in Draft [PR #58](https://github.com/i-shutov/flowbridge/pull/58) | Hosted parser/negative guard PASS; VM-910136 execution NOT_RUN |

No merge to main, beta PR #59, kernel implementation or signed release
was made; no installation, driver, firewall, SecureBoot, DNS, system-extension
or user host changes occurred in this checkpoint.

## B1 R01: specific code was written, but physical trust remains missing

[R182 model](https://github.com/i-shutov/flowbridge/blob/research/wfp-reauth-retained-authority-20261114/research/wfp-ale/r182/R182_RETAINED_AUTHORITY_MODEL.md)
implements a separately retained, bounded Rust per-flow authority after
one-shot CLAIM. Reauthorization requires immutable originating process
identity/creation epoch, endpoint/compartment, selected AppId, policy and
BFE/SSH generations, and prior egress-record attachment. It recognizes
reverse-direction reauthorization but does not issue a new initial permit.

- [Model CI 43569988661](https://github.com/i-shutov/flowbridge/actions/runs/43569988661):
  **3/3 platform jobs SUCCESS**; 26 tests each on Windows/Linux/macOS.
- [General Rust/native CI 43569988653](https://github.com/i-shutov/flowbridge/actions/runs/43569988653):
  **5/5 jobs SUCCESS**.
- The actual WFP R19 kernel source still rejects reauthorization, and R181
  remains a native source-level NO-GO. New R182 is deliberately separate
  and not plugged into a live kernel callout. The original NDISRD per-packet
  PID/epoch G2 trust gap remains.
- Owner decision [Issue #41](https://github.com/i-shutov/flowbridge/issues/41)
  still authorizes NDISRD-only product; any WFP production switch requires
  separate explicit approval, licensed backend and safe native lab.

**R01 ACCEPTED = false**. Unmodified EXE transparent TCP, physical no-DIRECT,
original backend driver signing and production fail-closed cannot be claimed.

## B1 R02: signed NE prerequisite code is tested

- [PR #60](https://github.com/i-shutov/flowbridge/pull/60) has a safe
  signed installed-bundle preflight and operator protocol. It verifies
  actual Team ID and entitlements only when an operator supplies a real
  signed application on a Mac, with no extension activation.
- [Negative-control CI 43446330496](https://github.com/i-shutov/flowbridge/actions/runs/43446330496):
  2/2 jobs PASS, 12 tests per platform.
- [General CI 43446330542](https://github.com/i-shutov/flowbridge/actions/runs/43446330542):
  5/5 jobs SUCCESS.
- **R02 native = NOT_RUN**: missing signed/provisioned NE app, actual
  Apple Silicon and Intel activation and physical selected-app/SSH traces.

## B0 A5: independent proof of the frozen original beta bytes

A new independent auditor reuses **the original** unified-run artifact
without recompilation. It discovered and corrected a counting error in its
first run: the kit contains **21 indexed payload files plus index and
SHA256SUMS**, totaling 23 ZIP entries. The original failure is retained.

- [A5 CI 43570582600](https://github.com/i-shutov/flowbridge/actions/runs/43570582600):
  3/3 jobs SUCCESS, including two adversarial-test jobs and original
  immutable package audit.
- Original inner kit SHA256:
  4b51d4136878476b48946361ce1635cb6d630e62b50ca82c73df28a5902ed8b8.
- Both original installer SHA256s match their independent frozen pins.
  Verified original CycloneDX inventories: Windows 71 components; macOS
  37 components, with embedded third-party notices and source metadata.
- The result explicitly preserves project_license_selected=false,
  independent_license_review_passed=false, native_sdk_runtime_distribution_review_passed=false,
  a5_accepted=false, release_accepted=false. This is **not** legal approval.
- Actual requirements still open: license for FlowBridge-specific code,
  native Windows C++/NSIS and Apple SDK/framework obligations, signing,
  independent legal/security audit and publication decision.

## B0 A3: target Windows operator tool is ready

A new pinned PowerShell 5.1 script
[FlowBridge-ExplicitBeta-A3-Frozen.ps1](../../tools/windows/FlowBridge-ExplicitBeta-A3-Frozen.ps1)
refuses incorrect ZIP hash/filename, unapproved OS edition/build, Windows
Server or wrong hostname before installation. The default invocation is
byte preflight only. The **explicit** -Execute flag permits the installed
beta lifecycle test from the frozen QA kit. Stable user data are preserved.

- [A3 hosted guard CI 43570996811](https://github.com/i-shutov/flowbridge/actions/runs/43570996811):
  PowerShell 5.1 bad-package refusal and PowerShell 7 AST parse PASS.
- Full [operator runbook](FLOWBRIDGE_A3_PINNED_RUNBOOK_20261114.md).
- **VM-910136 A3 native test remains NOT_RUN.** Hosted runner guard cannot
  upgrade owner A3 or replace manual GUI, real SSH and Win11 tests.

## Decisive next blocks, not a calendar promise

1. **Windows G2 (P0):** accept or reject an actual documented kernel-origin
   identity backend. If WFP is approved, integrate retained-flow model
   with genuine ALE AUTH/redirect/accepted-socket records under a safe lab;
   then repeat Win10/Win11 physical G2.1–G2.6 tests. No implicit change
   from NDISRD-only, no protected mode until physical proof.
2. **macOS R02 (P0):** obtain a genuinely provisioned Team/entitlement
   development app; run existing read-only PR #60 preflight, then approved
   native NE activation and SSH/IPv4/IPv6/DNS/Stop tests on ARM64 and Intel.
3. **A3/A4 beta (P0):** on actual owner Windows/Mac, verify and exercise
   the exact f5ecd48d8f81 package with original JSON/BMP and real SSH.
   Prior W0–W2b2 are old source; no transfer.
4. **A5/A6:** independent license/security/native distribution review and
   owner version/publication decision. No tag until all required beta
   acceptance is complete.
5. Only after BETA-C native/contained transparent routing proceed to
   R07/R08 signing/UX, frozen R09 24-hour soak and independent R10 release.

Machine-readable current gate register:
[gate_status_20261113.json](release-1.0/gate_status_20261113.json).

**Invariant:** all 19 release gate accepted flags remain false until
original native/legal evidence is independently accepted on the exact
built source. Release 1.0, physical no-DIRECT and packet ownership = NO-GO.
