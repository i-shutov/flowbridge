# FlowBridge — Windows-first release rebaseline, 16 November 2026

**State:** `0.3.0-beta.1` Windows-only prerelease `NO_GO_A3_INTERACTIVE_A5_A6_A7_OPEN`; Windows `1.0.0` `NO_GO_G2_NATIVE_OPEN`. No tag, publisher approval or OS policy changes.

## Current product scope

Owner decision 2026-11-15: Windows 10 Pro 22H2 x64 and Windows 11 Pro x64 first. macOS NE, native Mac ARM/Intel release QA, notarization and Mac DNS are deferred to a subsequent platform release; portable Rust cross-platform CI remains required. This is NOT a narrower explicit-SOCKS-only `1.0`: Windows 1.0 must include authentic selected-process transparent TCP, fail-closed and safe DNS/UDP claims. Win10 ESU/security update coverage remains `NOT_VERIFIED`.


## 16 Nov update — Codex V3 exposes GUI defect; new beta candidate required

- Owner-provided Codex V3 states that real SSH/FFI SOCKS5h, byte-verified echo, EOF/half-close, Stop, wrong-key rejection and all-down denial after **30.012 seconds** were exercised. Original 41-file ZIP has **not** yet been uploaded for independent review; its reported SHA256 is `8cf08b80a6d3e4d595cd2b33cf43eb6628cecf61e1c1940295d7d13de16883c6`. These are **Codex-reported**, not audited original outcomes.
- Original frozen GUI source `native/windows/main.cpp::showSsh` contains multi-line diagnostics in status. Codex reports it fixed layout on local `codex/a3-ssh-status-layout` commit `7ac6ef0ef5d4fb61e275e8a6c9f222893b7dd341` and tested an earlier QA EXE with reported hash prefix `82c308…483d`. Its final rebuilt EXE `30f855…550b` was **not executed**. Connected GitHub returned **404 for the branch and 422 for commit**, so no remote code review/CI is possible yet.
- Decision: do **not** modify accepted historical frozen `0.3.0-beta.1` SHA/kit. Publish local fix as a Draft PR, prepare a **uniquely versioned new beta candidate** (prefer `0.3.0-beta.2` with coherent version metadata/workflow), test **the exact final installed EXE**, run 6/6 new-package lifecycle and real GUI+SSH against same source/installer SHA, then submit original artifacts for independent acceptance. [Codex V4 execution task](https://github.com/i-shutov/flowbridge/blob/4be43c6569fe222a2153488a5c5bdb046ba0e1e1/docs/qa/release-1.0/checkpoints/A3_CODEX_V4_FINAL_CANDIDATE_HANDOFF_20261116.md).
- Scope unchanged: Windows 1.0 WFP G2 and signed native packet/no-DIRECT, DNS, Win11 and release security gates remain **NO-GO**. Old frozen 6/6 automated PASS remains valid **only for old binaries**, not for the next candidate.

## A3 frozen Windows beta: what is now actually proven

**Codex first full Admin attempt:** GUI `BLOCKED_PROFILE_ISOLATION`, positive SSH `BLOCKED_SIGNED_SSHD_UNAVAILABLE` (owner-pasted summary, raw ZIP not independently reviewed). Exact product source proves fixed beta Known Folder and retained settings; verified W2b1 uses pinned portable Microsoft-signed SSHD. Corrected [Admin+SSHD V2 QA task](https://github.com/i-shutov/flowbridge/blob/8c23e10819e200e7bf38e596490fba2c1113cf37/docs/qa/release-1.0/checkpoints/A3_WIN10_CODEX_AUTONOMOUS_GUI_SSH_TASK_20261116.md) and [RCA](https://github.com/i-shutov/flowbridge/blob/ef1277d1bcc6ede436cc5800048d088d534c7b90/docs/qa/release-1.0/checkpoints/A3_CODEX_FIRST_PASS_BLOCKER_RCA_20261116.md). Codex execution of V2 still NOT_RUN; no GUI/SSH PASS credited.


- Source `f5ecd48d8f81c594f755a55e7969b57d20903020`; inner candidate ZIP SHA256 `4b51d4136878476b48946361ce1635cb6d630e62b50ca82c73df28a5902ed8b8`; immutable Windows installer SHA256 `74ff309d2e8ae115083bed9c5d4f233fd02dc841a8084a22912f3430c1e4b504`.
- Owner Win10 PowerShell exact-kit `OWNER_NATIVE_AUTOMATED_CHECKS_PASS`: install, payload, GUI/FFI harness, upgrade, uninstall, stable state **6/6**; the original user ZIP was independently checked including original JSON and five unique BMP SHA-256 and decoded screens. Full provenance: [Win10 A3 original evidence review](A3_OWNER_WIN10_ORIGINAL_EVIDENCE_REVIEW_20261116.md) and [PR #73](https://github.com/i-shutov/flowbridge/pull/73).
- Crucial bounds: owner host identity is operator asserted, not cryptographically attested. The five automated GUI smoke images do **not** prove interactive keyboard/menu/Save/Cancel; there was **no original exact-kit real SSH/SOCKS5h full interactive verification**. `A3_full_accepted=false`.
- Owner explicitly delegated remaining GUI/SSH Win10 tests to locally installed Codex; owner is **not** the manual mouse tester. [Full pinned Codex task, exact Git commit](https://github.com/i-shutov/flowbridge/blob/8c23e10819e200e7bf38e596490fba2c1113cf37/docs/qa/release-1.0/checkpoints/A3_WIN10_CODEX_AUTONOMOUS_GUI_SSH_TASK_20261116.md). Execution is `NOT_YET_PROVED`: do not mark PASS until actual Codex JSON/screenshot/SSH evidence and independent review.
- A3 installer was removed by the accepted scripted test; for interactive testing locate its original pinned kit in that run's `kit/windows` and verify SHA. Do not silently substitute a `main` binary or rebuild.
- Windows beta other remaining gates: separate owner-native Windows 11 exact-kit checks, A5 independent license/native runtime/legal/security decision (original SBOM technical inventory PASS only: [PR #62](https://github.com/i-shutov/flowbridge/pull/62)), A6 independent release QA, A7 explicit release authorization and publication. macOS A4 not a Windows-first release gate. FlowBridge-specific `LICENSE` remains unselected; both Windows installer and original beta app are unsigned.

## P0 1.0 work in dependency order

| Gate | Evidence/obstacle as at 2026-11-16 | Next objective |
| --- | --- | --- |
| WIN-00 | Windows-first scope agreed; machine gate contract exists. Execution still open | Ensure exact SHA ledger, OS target ESU, no conflicting 1.0/beta claims |
| WIN-01 / G2 | WFP/ALE product [#69](https://github.com/i-shutov/flowbridge/pull/69)→[#70](https://github.com/i-shutov/flowbridge/pull/70)→[#71](https://github.com/i-shutov/flowbridge/pull/71)→[#72](https://github.com/i-shutov/flowbridge/pull/72), latest source `91699dac13e925a0cc90d51c4ba06853c42561e7`, ABI4 terminal CLAIM, source hard-PERMIT veto. WDK and source tests passed; exact PR #72 Rust/native workflow FAILED because separate macOS mock SSH port race, fixed in [#74](https://github.com/i-shutov/flowbridge/pull/74), not yet integrated/retested together. Driver unsigned/unloaded; accepted-socket OS object binding, 512-entry non-reclaimable book and reauthorization open | Fix kernel accepted-socket authority/generation/reauth; integrate source-only fixes with clean CI; prepare signed rollback-capable isolated Win10+Win11 lab, independently observe native WFP and egress |
| WIN-02 | Actual selected/unselected IPv4/IPv6 EXE→WFP→accepted socket→Rust→owned SSH and independent pcap NOT ACCEPTED | Native E2E byte parity, process+endpoint witness on both target OS |
| WIN-03 | BFE/dynamic filter loss, service/SSH/driver crash, competing filter arbitration, fail-closed/direct leakage unproved | Independent no-DIRECT physical traces under faults and rollback |
| WIN-04 | Protected DNS remote-only/split LAN, dual stack, unsupported UDP/QUIC/DoH/DoT scope unproved | Exact resolver/pcap positive+negative native evidence |
| WIN-05 | Frozen beta managed 128 held/1152 overload/10k churn/4 SSH children hosted PASS. Separate raw Windows OpenSSH requested 512 held; #74 workflow #43823314443 FAILED after ~244 successful held, resource errors from hosted sshd; not universal cap | Measure safe cap, investigate resources, 251/252 and 24h target Win10+Win11 soak. Do not downgrade raw capacity failure or conflate direct OpenSSH and managed core |
| WIN-06 | Beta automated screen set is PASS, but 1.0 rules/app selector, native protected Apply/Stop, keyboard/DPI and end-to-end state still OPEN | First beta interactive Codex on Win10; later 1.0 rule editor and full DPI/native QA |
| WIN-07 | License project-specific code undecided; product/driver publisher signing, source/supply-chain legal review and ACL/secure-store/rollback open | Owner license decision; independent audit/signing; product+driver signed exact artifacts |
| WIN-08/09 | No frozen signed 1.0 RC accepted on both Win10 and Win11; no independent GO | Full P0 green at same SHA, original evidence and release authorization before tag |

## Execution priorities

1. **Parallel beta lane:** Codex runs Win10 A3 **real GUI + original beta SSH** and returns independently auditable ZIP; separately arrange Win11 exact-kit owner-native, A5 legal/security and A6 verdict; then owner A7 decision for an explicitly labelled *unsigned* Windows engineering prerelease only if distribution/security conditions permit. Never call it transparent 1.0.
2. **Primary 1.0 critical path:** fix WIN-01 accepted socket, reclaimable/generation-safe AUTH and reauthorization; obtain safe signed driver and isolated/native rollback lab. **Do not deploy WFP on the 4 GiB owner QA host** without an independent approved safe lab; A3 does not authorize driver installation.
3. WIN-01 positive native proof → WIN-02 E2E → WIN-03 fail-closed → WIN-04 DNS/UDP; parallel SSH capacity/soak, Windows native rule editor UX and signing/legal; then WIN-08 RC and WIN-09 independent GO. Cross-platform Rust source CI remains green on target integration SHA.

## Strict status vocabulary

`OWNER_REPORTED_6_OF_6_EVIDENCE_VERIFIED` is a valid **automated beta A3 sub-result**, not `A3_FULL_ACCEPTED`. `HOSTED_WDK_SOURCE_PASS` is not `NATIVE_SIGNED_WFP_G2_PASS`. Failed raw512 or CI jobs remain visible. All `WIN-00...WIN-09.accepted=false` until independently satisfied; `release_accepted=false`, `publisher_release_approved=false`, `release_tag_created=false`.
