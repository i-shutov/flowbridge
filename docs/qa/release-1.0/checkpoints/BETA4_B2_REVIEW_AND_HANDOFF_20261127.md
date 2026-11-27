# Beta.4 — B2 source, composition and security desk review / internal handoff (draft)

2026-11-27 · NOT A RELEASE AUTHORIZATION · Exact candidate from [build 46040903481](https://github.com/i-shutov/flowbridge/actions/runs/46040903481).
Plan committed before this block: [a9d1e6f](https://github.com/i-shutov/flowbridge/commit/a9d1e6f14bd701363c7cd37b9ceab168aa24e31b).
All observations below were made by direct GitHub API reads and independent calculation in the current session, not by new child agents or by executing native Windows tests.

## 1. New findings

- Reconstructed the complete staged Git tree by applying all ten unified-diff file patches to their verified source blobs at `1261201d8561ee4e70faccc8699f60606a71c93b`. Computed each before/after Git blob SHA-1 and rebuilt every directory tree from the complete 359-entry Git API tree. All 10/10 before/after blob pairs match; reconstructed root `ce336e83bb724a65bf512e79e286c97fb0cb3190` exactly matches the original build receipt. The private local commit object is not served by the public repository; its identity remains receipt-bound.
- Cargo.lock has 75 records: seven workspace versions changed, all 68 external records identical. Product lock blob is identical to the audited baseline 44f1fc0; prior beta.3 scan reported 0 advisories and 0 warnings on RustSec snapshot `c5279d0b0c9e8b70df666eb6d1edbabcfd1176bd`. This is dependency equivalence, not a fresh beta.4 cargo-audit or proof of native dependency safety.
- All 15 cross-receipt checks succeeded (source/tree, installer/manifest/GUI/CLI/FFI/harness/tool/SBOM/metadata pins, pool, headless, inventory and negative authority flags). Live Actions jobs for build, pool, headless, inventory and old RustSec completed successfully; each has 0 artifacts. Original artifact incident run 45975037904 still has 0 artifacts.
- Six source assertions PASS: fixed stderr categories, identity-failure categories, GUI health redaction, diagnostic export via allowlisted FFI, bounded four-worker export, numeric/boolean-only counters. Source review confirms explicit local executable resolution, Microsoft Authenticode requirement, guarded executable across version probe and spawn, separate guarded DNS discovery, strict host-key checking, and no Windows PATH fallback. This is a source review, not fresh Windows execution.
- The last documentation-head PR CI was 12/13, zero artifacts. The failure is the separate stock bare backend at 244 with WinError 10054 after successful managed 128/10k churn/owned lifecycle; no change to historical raw512 or G2 results.

Machine-readable [reconciliation](../evidence/20261127/beta4-b2-source-and-gate-reconciliation.json).

## 2. A5 / composition review

| Item | Evidence | Disposition |
| --- | --- | --- |
| Payload 13 files; SBOM 76 components; 114 notice records | Original static inventory 46042486760; hash chain reconciled | Technical inventory PASS |
| Cargo / Rust standard library / nlohmann 3.11.3 | 61 external Cargo lock checksums in resolved metadata, recorded notices and Rust library hashes, header attributions | Recorded-byte coverage PASS; actual notice obligations review still OPEN |
| Native MSVC v143 / SDK 10.0.26100.0 | CMake-generated MultiThreaded runtime and project hashes; direct/delay imports show no separately imported MSVC runtime DLLs | Exact linked library members, redistribution rights and SDK terms OPEN |
| NSIS 3.13 | Pinned compiler, COPYING, x86 Unicode stub and three distribution plugins; compile log hash | Compiler input chain verified; actual embedded plugin bytes / member selection OPEN |
| Host dependency | Local Microsoft-signed OpenSSH client and Windows PowerShell Security cmdlet | Documented; final interactive verification OPEN |
| Installer/product signatures | Original inventory: PE certificate tables absent; candidate marked unsigned | Not a signed release; any internal pilot must be explicitly authorized, no trust bypass |

Do not infer an exhaustive transitive import or dynamic-load inventory, exact static-link members, or compliance from the receipts. A5 remains OPEN. Require reviewer to inspect original package metadata, actual NSIS members and relevant redistribution terms, record acceptance/rejection by component and identify whether any issue requires a new candidate.

## 3. A6 / security and privacy

The exact staged tree retains the source protections above. Prior CI and new source assertions do not substitute for authenticated negative GUI cases. One source robustness follow-up: in the signature verifier, the normal 12-second timeout explicitly kills/waits on its child, but an exceptional try_wait error returns through error propagation; verify owned child cleanup on that error path before declaring process lifetime exhaustive. No native reproduction or security bypass established; keep as targeted review/test item, not a claimed exploitable vulnerability. Also verify portable selected executables against ancestor/path replacement and dependency origin assumptions in a controlled native test, without weakening the signing requirement.

Fresh exact-tree RustSec scan, original GUI negative host-key/missing-key/unsigned-backend, end-to-end diagnostic redaction, and independent reviewer conclusion remain OPEN. A6 is not accepted.

## 4. Draft release notes — internal-only engineering candidate

**FlowBridge 0.3.0-beta.4 for Windows 11 x64.** Explicit local SOCKS5/SOCKS5h TCP, managed OpenSSH tunnel and watchdog, GUI/CLI and profiles, external upstream proxy; configure supported clients explicitly to use the listener selected in FlowBridge. Four-worker capacity: 512 simultaneous byte-verified managed streams, 128 per worker; 80 bounded excess admissions, 16 recovery connections and owned process/listener/permit cleanup proved with the original FFI. Installer lifecycle 9/9 passed headless; beta.4 remains unsigned and interactive acceptance is pending.

Not included: WFP/NDIS transparent interception or system kill switch, system-wide proxy/DNS mutation, UDP/QUIC proxying, global DNS leak prevention, automatic protection for unconfigured apps or preserving existing TCP flows after SSH disconnect. SOCKS5h only delegates name resolution for requests using it; application DNS/DoH outside the explicit proxy remains outside scope. No native Win10 work is authorized. macOS and transparent routing have their own acceptance tracks.

Installation/rollback: **do not distribute or install as a released product until A7 GO**. For authorized QA use the pinned [desktop start card](WIN11_BETA4_DESKTOP_START_20261127.md). Before any internal delivery rehash the original installer and manifest; confirm the per-user beta directory and separate profile, no driver/service, no system-policy changes, and expected registration. After A7 approval, use the original approved installer through the normal Windows interface; configure verified host key and key/agent; start, observe Ready, verify a client via SOCKS5h and Stop. Never bypass signature/host-key/policy checks. To roll back use the candidate's own uninstaller; retain the user's existing profile and files; verify owned processes/listeners and beta registration removed. Do not remove stable installation or unrelated files. If the normal platform policy rejects the unsigned candidate, stop and resolve authorization/signing rather than bypassing controls.

### Exact SHA-256 pins (original engineering bytes)

| Member | SHA-256 |
| --- | --- |
| Installer | `e0e4491cd97b30aa52b52ce89a7a8396a2fc11902bec3e70bed8ebfd722450b0` |
| Manifest | `3542633d089aff80e379f30db8be6f301edae462f38f70ea07c5b8ba76011703` |
| GUI | `8317e93ecda430848cfe4e565daa80c90297c0a6ef66a9b8b60263f1666a837a` |
| CLI | `12dfc4ec1f605cfb41a69f574c32f68eaf4ddbe7a4a5eebec02a662c98b6b824` |
| FFI | `a193b8c9e96ecbcd5c2a79722a09e7ca3a822ce406ec997c9ab475f022f2469a` |
| QA harness | `46cd8970cf669e0be3493998aeec6ba30ecb464dd399d0c3cdd972444e193a32` |
| Acceptance tool | `faf62aabeea95ef316f5c0935177a65820ea4679ac94afe8b5461138dd17a33c` |
| SBOM | `3ea9e447fb67467d922f4c9394d6f13dc85f56cd1fb1a6234c71bf0ed65260b1` |
| Build metadata | `31f01bf7f112c36e467d164e19cea59ef29d32e36114b0e2bb97da0556fb1cbd` |

No binary was attached or copied to a distribution endpoint. These are previously recorded pins, cross-reconciled rather than newly rehashed native files.

## 5. Final acceptance matrix

| Gate | Status | Next required observation |
| --- | --- | --- |
| P1 / exact staged source | PASS | No rebuild unless product bytes change |
| P2 / original build | PASS | Preserve original bytes |
| P3 / managed 512 | PASS | No repeat absent regression |
| P4 / headless lifecycle | PASS 9/9 | Preserve original evidence |
| P4 / desktop and GUI SSH | NOT_RUN / previous desktop prerequisite unsatisfied | Fresh native preflight in existing interactive Win11 Admin session; positive and negative authenticated SSH, keyboard, visual evidence, cleanup |
| P5 / A5 | PARTIAL | Component obligations and actual NSIS/MSVC provenance review |
| P5 / A6 | PARTIAL | Exact-tree fresh audit; native negative/privacy tests; focused lifetime review |
| P6 | DRAFT DOCUMENTS READY, binary delivery NOT_RUN | Independent A5/A6 review; exact original checksums; owner A7 decision |
| A7 | NO GO | No delivery, release or tag until remaining criteria close |

The existing Win11 service runner's prior observation was Session 0 and no active desktop; there has been no fresh native preflight here. GitHub connector supports reads and repository edits, not workflow dispatch or interactive desktop; no subagent launch/model selection tool is available in this session. Four GPT-6.2 Sol task definitions remain in the workpackage registry, but prior agent outputs could not be recovered and no new agent was falsely recorded as started. This is a direct partial execution with a reproducible source result. Win10 not touched; no candidate bytes, runner settings, workflow or security policies changed.

## 6. Reproduce source reconstruction locally (no native installation)

In a disposable clone with the pinned Git objects already available, use a temporary Git index (GIT_INDEX_FILE), not the working index. Read the tree at `1261201d8561ee4e70faccc8699f60606a71c93b`, extract `tools/internal_beta4_source.patch` from `16b385c90160956bd3c64e602953d75434e5bc8e`, apply using `git apply --cached --unidiff-zero` to the temporary index, and run `git write-tree`. Require `ce336e83bb724a65bf512e79e286c97fb0cb3190`. Verify `git diff --cached 1261201d8561ee4e70faccc8699f60606a71c93b -- Cargo.lock` contains only the seven workspace version substitutions. Delete only the temporary index/patch; do not publish or reset any branch. Alternatively recompute the Git blob and tree hashes directly from GitHub API objects as done here.
