# FlowBridge Windows 0.3.0-beta.2 — A6 independent release-review packet (NOT GO)

**Scope amendment 17 November 2026:** owner explicitly selected **Windows 10 Pro 22H2 x64 only** for the current beta.2 and Windows 1.0 release plan. Windows 11 native QA, support announcement and publication are **DEFERRED to later releases; not PASS and NOT a current blocker**. [Decision and scope contract](WIN10_ONLY_SCOPE_DECISION_20261117.md). This is a technical pre-review, not a distribution authorization, release note publication, or merge/tag. Product remains an **unsigned Windows engineering prerelease, explicit SOCKS-only**. `release_accepted=false`, `publisher_release_approved=false`.

## 1. Exact immutable candidate identity and verified source chain

| Item | SHA/URL |
|---|---|
| Product code source | `86583a1a0487b9d383c0122b24558e620bde5b9c` |
| Source tree | `9f92e9e9e87725d127505c8ac415f37e42a8d148` |
| Candidate GitHub CI | [#43883696169, attempt 2, 11/11 SUCCESS](https://github.com/i-shutov/flowbridge/actions/runs/43883696169) |
| Original immutable verified artifact | [#14238314845](https://github.com/i-shutov/flowbridge/actions/runs/43883696169/artifacts/14238314845) |
| Inner candidate kit ZIP SHA256 | `9980c786ceea82d2609b0229eca87b7f3ba044dc742466fedfa5e3b08e7585ae` |
| Windows installer SHA256 | `0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4` |
| Windows GUI EXE SHA256 | `0cf1749e7531659b1f5a42433818ecf31fe517d6815d11faeca6e04f9821325e` |
| Windows FFI DLL SHA256 | `23b62d54a89feea53331f3ac68fe7c3d348ca99ed72d816f3dcfbc94ef3fd2b4` |

**Do not accept a rebuild bearing the same version but different bytes.** If source/payload changes, freeze a NEW candidate and restart exact-byte receipt verification, including A3 native tests.

## 2. A0–A7 release gating review

| Gate | Status, factual basis | Required before GO |
| --- | --- | --- |
| A0 explicit-only | **PASS**: no WFP/NDISRD driver/extension, no transparent application capture, no system DNS or kill-switch claim | Maintain in UI/docs |
| A1 frozen candidate | **PASS**: one original source, 11/11 CI, independently reviewed Windows manifest 13/13 and candidate ZIP | Pin these hashes in every release output |
| A2 managed SSH | **PASS within bounded 128-flow product scope**: known-host, SSH-owned 1–4 workers, 10k churn, negative no-implicit-DIRECT, all-down; no guarantee for independent raw OpenSSH 512 | Do not assert 512 capacity or universal host limitations |
| A3 Win10 | **REVIEWED OWNER-ORIGINAL V4+V5 EVIDENCE ACCEPTED:** V4 100/100, GUI 17 PNG, 6/6 native install/upgrade/uninstall, real SOCKS5h/Stop/all-down; V5 26/26, 6 PNG, 23 UI actions, final beta.2 missing-key denial, healthy 10-byte control, stop and escrow restoration. [V5 checkpoint](BETA2_WIN10_A3_V5_INDEPENDENT_REVIEW_20261117.md). Owner host identity is asserted, not cryptographically attested; reviewer did not physically rerun tests | No further Win10 testing needed unless exact candidate changes |
| A3 Win11 | **DEFERRED_NOT_REQUIRED_FOR_CURRENT_WIN10_RELEASE**; no native Win11 test executed or accepted | Future platform release backlog [#79](https://github.com/i-shutov/flowbridge/issues/79); **do not test or advertise Win11 in this release** |
| A4 macOS | Native acceptance **DEFERRED** under Windows-first owner decision; hosted universal package passed but does not grant Mac release | Do not publish a Mac SKU as accepted |
| A5 technical | **PASS only for provenance/dependency metadata**: original kit 21 files + index/sums, 71 Windows and 37 Mac BOM; [QA PR #77](https://github.com/i-shutov/flowbridge/pull/77), [pinned A5 CI #43936785163](https://github.com/i-shutov/flowbridge/actions/runs/43936785163) 4/4 SUCCESS. RustSec original Cargo.lock, 75 dependencies, 0 known vulnerabilities at scanned DB version; native C++/security not covered | Complete owner own-code `LICENSE`, legal/redistributable Windows/MSVC/NSIS/SSH and native runtime/code security review, [issue #78](https://github.com/i-shutov/flowbridge/issues/78) |
| A6 formal independence | **NOT_APPROVED**: Win10 current-scope A3 original owner V4+V5 evidence accepted; A5 legal/native runtime, P0 and publisher review still outstanding. Win11 is not in current scope | Independent Win10-only exact-source review with no P0 FAIL/SKIP/UNKNOWN and complete A5 |
| A7 owner/publication | **NOT_APPROVED**: no selected own-code license, no release authorization or publisher signing, no tag | Explicit owner decision on Windows-only unsigned engineering prerelease vs signed distribution; confirm all release claims and checksum |

**No part of this A6 memo confers legal, supply-chain security or publisher approval.**

## 3. Honest unsigned engineering prerelease notes — DRAFT, NOT PUBLISHED

**FlowBridge 0.3.0-beta.2 — Windows x64 (engineering prerelease)**

- Scope: native Windows UI, explicit local SOCKS5/SOCKS5h TCP to configured clients, external proxy support and supervised OpenSSH with strict host-key checking, 1–4 SSH workers and bounded capacity; the app must be configured to use the SOCKS proxy.
- GUI status display now uses one concise connection headline; diagnostic text remains visible in journal. Added exact-beta GUI and SSH-negative regressions.
- Install/upgrade/uninstall are per-user and preserve separate user settings from stable FlowBridge; native Win10 owner original V4+V5 records reviewed. Windows 11 is not included or advertised for this release.
- **Do not use as protected transparent traffic interception.** No selected-app transparent interception, WFP/NDISRD driver, system kill switch or system-wide DNS no-leak guarantee. No UDP/QUIC-over-SSH, no restoration of existing TCP sessions after SSH break; browsers using own DoH/DoT or applications not configured for local SOCKS may use other routes.
- Publisher signing not complete. Both binary provenance via original GitHub Actions hashes and separate Windows OS/SmartScreen trust decisions matter. Do not tell users to disable Defender/SmartScreen or security controls to install an unsigned test build.
- Cross-platform source/build CI includes macOS but Mac native product support is not part of the Windows-first release.
- Do not describe the experimental independent raw OpenSSH backend as supporting 512 held channels; verified managed product scope is 128 concurrent flows with admission limits, 10k churn and up to four workers in hosted tests.
- Windows 10 Pro 22H2 is past standard Microsoft support and should not be represented as a secure host without verified eligible ESU/security updates.
- **Distribution license pending:** these notes are an internal draft until approved FlowBridge-specific project license and legally reviewed third-party notices/runtime terms are provided.

## 4. Explicit release decision dependency

**A6 reviewer cannot issue GO until [#78 license/legal/runtime](https://github.com/i-shutov/flowbridge/issues/78) and the remaining Win10-only security/release gates are accepted.** [Win11 #79](https://github.com/i-shutov/flowbridge/issues/79) was explicitly deferred and **must not block the current Windows 10 release**. Perform final A6 Win10-only P0/security/privacy audit, require explicit A7 owner approval and only then consider publishing a Win10-only prerelease. Do not merge a WFP driver stack into beta to satisfy unrelated product needs. Windows 1.0 WFP/ALE physical G2 is an independent mandatory release track and remains `NO_GO`.

## 5. Distinct WFP/1.0 blocker (not a beta release gate)

[WFP product PR #72](https://github.com/i-shutov/flowbridge/pull/72), exact `f1ac3b04369163ece245c4fea9520571cec112bf`: source/WDK/Windows BFE-scope/DNS checks PASS, but independent raw OpenSSH 512-characterization workflow FAIL under Windows sshd resource exhaustion and general Rust/native workflow records a cancelled macOS Rust job. No signed, loaded native driver, kernel socket-object binding, generation-safe AUTH reauth or physical no-DIRECT IPv4/v6/DNS packet proof. WFP G2 and `1.0` NO-GO; no traffic-filter changes on the existing owner VM are approved by this packet.
