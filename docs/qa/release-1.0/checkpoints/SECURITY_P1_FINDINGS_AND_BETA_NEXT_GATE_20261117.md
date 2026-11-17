# FlowBridge — security gate 17 November 2026 (closed / internal Windows 10 only)

**Release status: `BETA2_A0_A3_FUNCTIONAL_ACCEPTED_SECURITY_GO_BLOCKED`; `WIN10_1_0_WFP_G2_NO_GO`.** No main merge, new product installer, public tag/Release or Win11 test.

## Immutable frozen product and what has actually passed

| Identity | Exact original |
| --- | --- |
| Version / scope | `0.3.0-beta.2`, Windows 10 Pro 22H2 x64 only, explicit SOCKS5/SOCKS5h |
| Product source SHA | `86583a1a0487b9d383c0122b24558e620bde5b9c` |
| Original verified candidate kit SHA256 | `9980c786ceea82d2609b0229eca87b7f3ba044dc742466fedfa5e3b08e7585ae` |
| Original installer SHA256 | `0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4` |
| Original GUI SHA256 | `0cf1749e7531659b1f5a42433818ecf31fe517d6815d11faeca6e04f9821325e` |
| Original FFI DLL SHA256 | `23b62d54a89feea53331f3ac68fe7c3d348ca99ed72d816f3dcfbc94ef3fd2b4` |
| [Frozen candidate CI](https://github.com/i-shutov/flowbridge/actions/runs/43883696169) | 11/11 SUCCESS |
| Native Win10 A3 owner V4+V5 | Independently reviewed `100/100` + `26/26` original evidence, positive/negative SSH/GUI lifecycle & restore internally coherent; no independent live physical host rerun |

Accepted `A0–A3` describe the **unchanged original beta.2 functionality**, not the newly proposed privacy patch or signed OpenSSH hardening.

## Confirmed source risks and controls

| P | Risk | Evidence / current action | Current GO |
| --- | --- | --- | --- |
| **P0** | Closed-source repo still **Public** | GitHub API confirms `private=false`; user plans to change later, no automatic visibility mutation; external clones/downloads cannot be revoked. [#83](https://github.com/i-shutov/flowbridge/issues/83) | **OPEN** |
| **P1** | OpenSSH stderr returned raw in **serialized `Snapshot.stderr` and `Snapshot.events`**, then displayed by GUI; GUI also appended local backend executable path/version into journal | Source-confirmed at frozen beta.2. [Privacy fix PR #84](https://github.com/i-shutov/flowbridge/pull/84) branch based on exact source: replaces retained stderr with fixed non-sensitive categories; maintains host-key/auth/resource failure semantics; GUI stops appending raw backend path/version. [Exact-head targeted CI #44061327017](https://github.com/i-shutov/flowbridge/actions/runs/44061327017) **3/3 SUCCESS**: Rust on Windows/Linux + native Win32 explicit GUI compilation. **Product beta.2 existing installer NOT patched.** [#85](https://github.com/i-shutov/flowbridge/issues/85) | **OPEN until new candidate re-QA** |
| **P1** | `resolve_ssh` trusts explicit local `*.exe` or first `ssh.exe` from `PATH`, and the `-V OpenSSH_` prefix is spoofable. No product-runtime Microsoft Authenticode/signer chain or atomic file identity binding | [#86](https://github.com/i-shutov/flowbridge/issues/86). [QA PR #82](https://github.com/i-shutov/flowbridge/pull/82) supplies read-only canonical-path/reparse, Authenticode Valid/Microsoft signer + optional SHA verification. Does **not** execute SSH or solve runtime TOCTOU. Host owner evidence **NOT RUN**. | **OPEN** |
| **P1** | Windows 10 Pro 22H2 after end of standard support | Official Microsoft `Windows 10` ESU commercial prerequisites [KB5066791 / KB5072653 / Year2 activation ID](https://learn.microsoft.com/windows/whats-new/enable-extended-security-updates); October 2026 historical build floor [19045.7811](https://learn.microsoft.com/windows/release-health/release-information). [Read-only Win10 ESU auditor in PR #82](https://github.com/i-shutov/flowbridge/blob/qa/win10-internal-security-inventory-20261117/tools/windows/FlowBridge-Win10-ESU-ReadOnly.ps1) **does not activate or display ESU keys**; current target's actual Year2 activation and patch level **NOT VERIFIED**. Passing a historical build floor does **not** prove current patches. | **OPEN** |
| **P1** | Unsigned original installer and raw on-screen diagnostic/journal paths | Exact SHA pinned, static PE imports and BOM/RustSec audited, but no publisher signature or complete native Win32 security review | **OPEN** |

### Scope and evidence privacy

- [Independent A5 original BOM/RustSec #43936785163](https://github.com/i-shutov/flowbridge/actions/runs/43936785163) **4/4 SUCCESS**, at its database snapshot 75 locked Rust packages, 0 known advisories; not native C++ proof or rights grant.
- [Original-byte A6/PE import QA #44041579615](https://github.com/i-shutov/flowbridge/actions/runs/44041579615) **4/4 SUCCESS**; this proves original binary identity and direct imports only.
- [Security inventory PR #82](https://github.com/i-shutov/flowbridge/pull/82), [Git/ZIP history scan CI #44061793218](https://github.com/i-shutov/flowbridge/actions/runs/44061793218) **6/6 SUCCESS** including signed/unsigned SSH backend and wrong-OS negative fixtures and ESU negative. Git history original sanitized artifact #14317389918 SHA256 `e5d174a6787327ed287dd4a76ddb8bae87c46f45006e7531bbca77e741861d3f`: **9,514 Git objects / 2,789 blobs / 0 large skipped / 0 high-confidence secret hits** after examining three **specific known synthetic privacy-test history blobs** (exact fixture suppressed, not generic token patterns). The three match object SHA values were validated as revisions of our own privacy test in [#84](https://github.com/i-shutov/flowbridge/pull/84). This limited high-confidence screening is not a complete credential exfiltration/secret review and cannot assess already copied external history.
- Original source ZIP, private V4/V5 user evidence and any local SSH/host paths **must not be uploaded to public GitHub**. Only sanitized source/checkpoint descriptions are written here.

## Release critical path

1. **No unreviewed product mutation:** old beta.2 SHA stays immutable; P1 privacy fix source/build PASS is not a fixed old installer. Once SSH backend trust mitigation is accepted and repo visibility is controlled, freeze a **new uniquely versioned private candidate** (e.g. `0.3.0-beta.3`) and run original 6/6 lifecycle, GUI Ready/Failed/Recovering, known_hosts, invalid key, binary SOCKS5h and Stop on owner Windows 10, plus independent original evidence ZIP/hash review.
2. **Immediate read-only owner host facts:** [Codex Win10 A5/A6 preflight](https://github.com/i-shutov/flowbridge/blob/qa/win10-internal-security-inventory-20261117/docs/qa/release-1.0/checkpoints/WIN10_A5_A6_READONLY_SECURITY_PREFLIGHT_CODEX_20261117.md): exact installer hash/Win10 scope, actual configured signed SSH backend, Year2 ESU and servicing floor. Scripts run locally only; no paths/keys into public GitHub. These read-only checks do **not** grant A7 internal deployment GO.
3. Final P0/P1 Win32/FFI/privacy/third-party security review, A5 internal native rights, then formal A6 independent internal-pilot GO; only after explicit owner A7 scoped deployment authorization may any new installation be recommended outside existing authorized QA.
4. **Closed-source policy** / internal only. User deferred making public repo private, [#83](https://github.com/i-shutov/flowbridge/issues/83). Windows 11/macOS deferred, not tested. Full protected Windows 10 `1.0` signed WFP/G2 physical selected TCP/no-DIRECT/DNS/UDP **NO-GO**.

**Machine security conditions:** `frozen_beta2_functional_a0_a3=true`, `privacy_fixed_in_frozen_beta2=false`, `product_ssh_backend_identity_runtime_proved=false`, `win10_esu_target_verified=false`, `repo_private=false`, `formal_a5_a6_a7_release_go=false`. No public release/tag and no driver/host changes.
