# FlowBridge Win10 — signed OpenSSH runtime + privacy source CI checkpoint

## Latest security source checkpoint (supersedes previous build SHA)

[Draft PR #88](https://github.com/i-shutov/flowbridge/pull/88) current exact source `44e3ba988ac5a9f7cf2d25b16d46c432ff3d8c38`. [**Targeted CI #44076875289**](https://github.com/i-shutov/flowbridge/actions/runs/44076875289): **3/3 SUCCESS** (Windows signed Microsoft OpenSSH positive and fake unsigned negative; locked real `-V` execution without using `PATH`, mock port regression, Linux SSH regression and Windows CMake FFI/GUI explicit-only compile). The earlier `0a0addce...` source / `44075525234` CI record below is historical, also 3/3 PASS.

Extended [rust-and-native-applications #44076875466](https://github.com/i-shutov/flowbridge/actions/runs/44076875466) is **not declared fully green until each hosted OS job completes**. An earlier exact SHA `0a0...` run failed due to a `clippy::needless_return` on Windows and a **test-only pre-child localhost bind collision** in the Linux dead-child reconnect test. The current source removes that Clippy warning and bounds retries to verified pre-child `Address already in use` only — never retries real authentication, overload, or changed SSH failure behaviour. Do not infer signed kernel driver/WFP G2 from any user-mode test.

**Still not accepted:** no beta.3 frozen installer source/binary hashes, no original owner Win10 native QA for new bytes, no independent Windows 10 ESU/pinned selected SSH runtime result, repository still public despite owner closed-source requirement, A5/A6 formal security and A7 internal pilot GO remain false. No installer released, no tag, no main merge.


**As of 17 November 2026.** Owner decision: `PROPRIETARY / INTERNAL_ONLY / WIN10_PRO_22H2_X64_ONLY`. **Current `0.3.0-beta.2` original installer is unchanged/unfixed.** This document is a **source/build** checkpoint for proposed future `0.3.0-beta.3`, not a publisher GO, signed product or private installer.

## Exact unchanged original beta.2

- Original source `86583a1a0487b9d383c0122b24558e620bde5b9c`; original immutable kit ZIP SHA256 `9980c786ceea82d2609b0229eca87b7f3ba044dc742466fedfa5e3b08e7585ae`; original Win10 installer SHA256 `0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4`.
- Original [unified beta.2 Actions](https://github.com/i-shutov/flowbridge/actions/runs/43883696169) 11/11 SUCCESS and original owner Win10 A3 V4/V5 100/100+26/26 independent archive review remain valid **only for those original bytes**.
- Source risk [#85](https://github.com/i-shutov/flowbridge/issues/85): raw OpenSSH stderr retained verbatim in FFI SSH `Snapshot.stderr` and `Snapshot.events` and displayed in Win32 GUI journal. Source-only privacy remediation [PR #84](https://github.com/i-shutov/flowbridge/pull/84) previously had targeted Windows/Rust 3/3 CI PASS.
- Source risk [#86](https://github.com/i-shutov/flowbridge/issues/86): original `resolve_ssh` allowed arbitrary PATH `ssh.exe`; version text `OpenSSH_` was spoofable and not a Microsoft signature.

## New exact source + CI

[**Stacked Draft PR #88**](https://github.com/i-shutov/flowbridge/pull/88), exact source **`0a0addce6e0a28cf5e69376f04af2fdb84435b50`**. [**Targeted GitHub CI #44075525234**](https://github.com/i-shutov/flowbridge/actions/runs/44075525234) **SUCCESS 3/3**:
- `flowbridge-tunnel` Rust SSH supervisor regressions PASS on **Windows 2025** and **Ubuntu 24.04**. Includes unsigned current/test EXE refusal, signed built-in Microsoft OpenSSH positive test, no arbitrary PATH choice, verified `ssh -V` while file guard denies ordinary file writes/deletes, auth/host-key/resource/Stop and private stderr synthetic path/hostname tests.
- Native Windows FFI + Win32 GUI **explicit-only** CMake compilation and SSH GUI test PASS. No WFP driver, installer, tag or publisher signing produced.
- Original source feature `windows-sys Win32_System_SystemInformation` allows kernel-derived `GetSystemDirectoryW` system ssh path, never first `ssh.exe` in untrusted PATH.
- A user-selected portable ssh.exe is subject to `Get-AuthenticodeSignature Status Valid` plus Microsoft Corporation signer check, performed via a trusted System32 Windows PowerShell 5.1 process with `-EncodedCommand` and module loading restricted to `$PSHOME/Modules`. The SSH executable path is passed solely via environment variable `-LiteralPath`, not substituted into PowerShell source. Tests confirmed Windows imports correctly and that signed system OpenSSH succeeds; earlier failure with missing implicit module loading was diagnosed and fixed **without weakening signer validation**.
- The selected canonical executable path and ancestor components must be local and non-reparse; an `OpenOptions::share_mode(FILE_SHARE_READ)` guard is held across signature check, version probe and real SSH `CreateProcess`, mitigating ordinary replacement/delete in-between. Remote DNS's separate SSH child uses the same signed+lock guard. Child Windows Job lifecycle preserved.
- OS-root trust, PowerShell binary/module integrity, default Windows chain validation and local admin/kernel compromise are **outside this source-only proof**; signer/revocation/ACL and actual Win10 owner-native QA remain a separate independent security gate. Static signing verifier is not proof of protection from a fully privileged local attacker.

## Remaining release gates and next block

- **NO `0.3.0-beta.3` frozen installer exists.** The owner wishes the repository Private but has postponed the visibility change; it remains public [P0 #83](https://github.com/i-shutov/flowbridge/issues/83). **Do not create/download new proprietary binary artifacts to public GitHub** until access/privacy is resolved.
- Internal Win10 signed ssh/backend and ESU original owner-host preflight [Codex read-only task](https://github.com/i-shutov/flowbridge/blob/qa/win10-internal-security-inventory-20261117/docs/qa/release-1.0/checkpoints/WIN10_A5_A6_READONLY_SECURITY_PREFLIGHT_CODEX_20261117.md) remains NOT_RUN. A real Win10-native signature/launch test is needed before A6.
- After owner confirms private artifact permissions, freeze a **new uniquely versioned beta** combining #84 + #88, coherent workspace/NSIS/manifest source hashes, native Win10 GUI/SSH/negative/Stop/rollback original ZIP and independent review. **Never inherit old beta.2 SHA-gated A3 to a newly compiled product**.
- A5 third-party/native SDK rights and full C++/FFI security, A6 privacy/native P0, A7 explicit internal-pilot owner GO all **OPEN**. Public licensing (MIT/Apache) not selected; closed/internal only. Windows 11/macOS deferred. Protected Windows 10 `1.0` WFP/G2 physical signed kernel socket/no-DIRECT/DNS remains `NO_GO`.

**Safety invariant:** `beta2_original_unmodified=true`, `beta3_installer_built=false`, `new_source_signed_ssh_ci_pass=true`, `native_owner_win10_new_version_accepted=false`, `a5_a6_a7_release_go=false`, `public_distribution_authorized=false`, `wfp_g2_accepted=false`.
