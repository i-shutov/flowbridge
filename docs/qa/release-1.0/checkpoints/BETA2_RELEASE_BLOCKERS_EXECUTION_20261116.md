# FlowBridge Windows beta.2 → 1.0: blocker execution checkpoint — 16 Nov 2026

**Status:** `WINDOWS_BETA2_TECHNICAL_CANDIDATE_PASS_RELEASE_GO_OPEN`; `WINDOWS_1_0_NATIVE_WFP_G2_NO_GO`. No `v0.3.0-beta.2` tag or GitHub Release, no main merge, no signed WFP installation.

## Frozen beta.2 provenance

- PRs: [GUI source correction #75](https://github.com/i-shutov/flowbridge/pull/75), [Windows/Mac candidate #76](https://github.com/i-shutov/flowbridge/pull/76), exact source `86583a1a0487b9d383c0122b24558e620bde5b9c`.
- Unified package run [#43883696169](https://github.com/i-shutov/flowbridge/actions/runs/43883696169) attempt 2: **11/11 SUCCESS**, verified candidate artifact `14238314845`; inner exact kit SHA256 `9980c786ceea82d2609b0229eca87b7f3ba044dc742466fedfa5e3b08e7585ae`.
- Original owner Win10 V4 ZIP SHA256 `23844631907f96063f0b13db73a835b92c386a4be3ed13a174c484c3139606e2`: externally supplied and independently checked for **100/100 original files**, 17 GUI PNG, 13 Windows manifest product files, nested V3 41 files; exact final GUI and DLL/installer hashes match, original GUI/SSH/all-down and restoration reports are coherent. [Independent detailed review](BETA2_OWNER_WIN10_A3_V4_INDEPENDENT_REVIEW_20261116.md). This is independent **original evidence integrity/consistency**, not an independent physical rerun.
- **Only known missing A3 negative:** nonexistent SSH private-key file path on **final beta.2 GUI**. On beta.1 V3 it failed safely, but V3 PASS cannot promote final version. [Codex V5 single-case handoff](A3_BETA2_CODEX_V5_MISSING_IDENTITY_NEGATIVE_20261116.md): existing Admin user on Win10; verified exact source/installer, user-only profile escrow and rollback, signed portable localhost sshd, actual GUI + failure/no-DIRECT/healthy-control + sanitized original ZIP. **NOT_EXECUTED_YET**, no owner manual clicking required.
- Win11 owner native acceptance separate and OPEN; GitHub Windows Server 2025 hosted pass does not replace Win11 Pro x64.

## A5 original supply-chain block

- Independent [QA PR #77](https://github.com/i-shutov/flowbridge/pull/77) with [CI run #43933964021](https://github.com/i-shutov/flowbridge/actions/runs/43933964021) **3/3 SUCCESS**: original immutable kit `9980c786...` audited through pinned source, all declared SHA/size and SHA256SUMS, ZIP safety, Windows/Apple SBOMs and third-party notices, plus Linux and Windows adversarial negatives.
- Original sanitized GitHub evidence artifact `14259407987`, ZIP SHA256 `a1883d6b4630d9df3749108542c5a803e9a5f20788668360735acc0f6e2ac2fc`; report `TECHNICAL_A5_INVENTORY_PASS_LEGAL_AND_NATIVE_REVIEW_OPEN`, Windows **71** BOM components / **64** licence inventory entries, Mac **37** / **31**, missing license metadata **0**, copyleft keyword scan flags **0**. This is metadata validation only, not per-file legal sign-off or vulnerability scan.
- **Genuine P0 owner action** [license and distribution decision issue #78](https://github.com/i-shutov/flowbridge/issues/78): the frozen `LICENSE` explicitly states the FlowBridge-specific code license has **not been selected**, so independent license/legal, native runtime/SDK, and vulnerability review remain OPEN. Do not silently publish/source-relicense before the owner decision. Windows installer unsigned; commercial signing vs explicitly labelled unsigned engineering prerelease requires release approval.

## Release gates

| Beta gate | Current evidence / decision |
| --- | --- |
| A0 scope | Exact explicit-SOCKS only; no driver/system DNS; hosted PASS |
| A1 exact candidate | 11/11 CI final kit PASS; 21 declared files + index/sums |
| A2 managed SSH | 128 held, 1152 expected overload, 10k churn/4 workers; plus original Win10 SSH positive/negative V4 evidence consistent; raw 512 **not proved** |
| A3 Win10 | Owner exact GUI+SSH V4 evidence audited **PASS_WITH_ONE_FINAL_NEGATIVE_OPEN**, Codex V5 task ready |
| Win11 owner | NOT_RUN |
| A5 | Technical original-kit / BOM **PASS**; license/security/native runtime **OPEN** |
| A6 | Formal independent P0/privacy and release decision **OPEN** |
| A7 | Publisher/owner public distribution approval **NOT_GRANTED**, release tag absent |

## Parallel Windows 1.0 critical path

- [PR #72](https://github.com/i-shutov/flowbridge/pull/72), current exact WFP source HEAD `f1ac3b04369163ece245c4fea9520571cec112bf`, source hard-PERMIT veto and ABI4 kernel CLAIM on earlier stack #69–#71. Integrated deterministic **test-only** macOS mock port race fix from [#74](https://github.com/i-shutov/flowbridge/pull/74); new WDK driver compile, WFP source/ABI and BFE scope jobs confirmed SUCCESS, others PENDING at this checkpoint.
- Still **NO-GO**: kernel socket-object trust binding, generation-safe ticket recycle and reauthorization, signed approved driver and isolated rollback+VNC Win10/Win11 native lab, selected app→WFP→Rust→SSH bytes and independent no-DIRECT/dual-stack/DNS/UDP/DoH/QUIC packet evidence, 24h SSH soak, signed product RC, independent WIN-09 GO.
- Raw OpenSSH 512 characterization remains unproved (previous ~244 failed; ~246 met minimum baseline, not 512). Do not infer universal cap and do not weaken managed 128 guarantee.
- The user-authorized windows-first decision continues to defer Mac NE native release QA; portable Rust-core CI still matters.

## Release-control truth rules

- Positive hosted/source checks attach to **specific source SHA and workflow** only. Never inherit onto a modified binary, driver or WFP branch. User's Codex V5 case pending until original evidence arrives.
- Technical A5 PASS is not legal/publication approval; no release tag or main merge before A3/Win11/A5/A6/A7.
- WFP signed native packet authority not proved; unprotected explicit SOCKS beta must never be advertised as protected Windows 1.0.

## Late-16 Nov original-lockfile advisory and WFP CI evidence update

- [A5 independent original binary auditor PR #77](https://github.com/i-shutov/flowbridge/pull/77): prior 3/3 original-kit/SBOM controls PASS; additional exact-original-source [RustSec run #43935816560](https://github.com/i-shutov/flowbridge/actions/runs/43935816560) **4/4 SUCCESS**. Original `Cargo.lock` SHA256 `7873affb09ffbb45dcb811b30555ad3844c0e4ce4da995e4a7f22130483d4b29`, `cargo-audit 0.23.0`, RustSec DB updated `2026-11-15T10:59:21+01:00` at commit `02e2517f457a359fc6d3440ea4560c8ea188fee8`: **75 dependencies, database 1509 advisories, zero known vulnerabilities, zero warnings**. Independent artifact `14261670133` ZIP SHA256 `edfeb32ca02fb468e2ea0e222b987ae22fc8204498023b0ac6b3f51175021ca8`. A follow-up CI commit `282c404176751679b0f07402ba2ef8bf477e28f9` explicitly pins cargo-audit 0.23.0/--locked; new-head workflow status **PENDING at this checkpoint**. Neither one verifies unknown vulnerabilities, Windows C++/Win32 code, binary reachability, native runtime redistribution, or owner-selected LICENSE. [Owner blocking decision issue #78](https://github.com/i-shutov/flowbridge/issues/78).
- WFP [PR #72](https://github.com/i-shutov/flowbridge/pull/72) exact `f1ac3b04369163ece245c4fea9520571cec112bf`: WDK #43934208759, WFP source/ABI negatives #43934208928, BFE scope #43934208781 and DNS #43934208882 **SUCCESS**. Real Windows OpenSSH #43934209527 **FAIL**: actual managed 128/1152/10k/four-worker tests PASS, then experimental **raw 512-capacity** FAILED with `WinError 10054`, Windows sshd `Too many open files`/ppoll resource shortage. General rust/native #43934209139 was still queued. This failure is real and is not hidden to call overall CI green. It does not refute the already-proved managed 128 baseline, nor provide the missing physical Windows WFP/G2 proof.
- **G2 and 1.0 remain NO-GO**, `beta2_release_accepted=false`, and the single final beta.2 A3 nonexistent key-path test remains **NOT_RUN** pending Codex V5 original evidence.
