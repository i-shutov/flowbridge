# FlowBridge 0.3.0-beta.2 — independent original GitHub Windows artifact audit

**Date 2026-11-16. Status `WINDOWS_ARTIFACT_PROVENANCE_PASS_OWNER_V4_EVIDENCE_NOT_REVIEWED`.** This is an **offline SHA/metadata/original ZIP verification of GitHub-hosted artifacts**; it is neither a Win10 owner interactive acceptance nor a release GO.

## Exact source and independently downloaded original

- [PR #75](https://github.com/i-shutov/flowbridge/pull/75) — clipped SSH status fix, Draft, based on frozen beta.1.
- [PR #76](https://github.com/i-shutov/flowbridge/pull/76) — 0.3.0-beta.2 candidate, Draft, exact head **`86583a1a0487b9d383c0122b24558e620bde5b9c`**; exact tree SHA `9f92e9e9e87725d127505c8ac415f37e42a8d148`.
- [GitHub Actions candidate run #43883696169](https://github.com/i-shutov/flowbridge/actions/runs/43883696169), immutable [original Windows artifact #14233377409](https://github.com/i-shutov/flowbridge/actions/runs/43883696169/artifacts/14233377409).
- Independent downloaded **GitHub artifact ZIP SHA256**: `1cb5ceef10609f5921ea376a496819ece5915b8fe55e281862f1fdc356362b90` (matching GitHub Actions artifact digest).
- ZIP CRC all entries PASS; exactly **25 entries**, **13 fully hashed product payloads**, each independently matched to `explicit-beta-package.json` paths, sizes and SHA256; no extra undeclared product payload. QA harness SHA matches manifest. Seven hosted QA BMPs decode with valid dimensions.
- **Installer `FlowBridge-0.3.0-beta.2-windows-x64-setup.exe`** SHA256 `0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4`; 1,798,405 bytes.
- **GUI `FlowBridge.exe`** SHA256 `0cf1749e7531659b1f5a42433818ecf31fe517d6815d11faeca6e04f9821325e`; 668,672 bytes.
- **FFI `flowbridge_ffi.dll`** SHA256 `23b62d54a89feea53331f3ac68fe7c3d348ca99ed72d816f3dcfbc94ef3fd2b4`; 2,158,592 bytes.
- Windows QA manifest SHA256 `3ed7c6b73bc1edf4e3418203be07fc054b1f451d69b0ac0d9f5b589ed2581629`; original installed-product report SHA256 `c2f1e86904a0dc96319890abeb113fff4fc5c0f9fa7afd449da3bd9a6308dfc4`.
- **Confirmed from the original embedded CI lifecycle report:** `passed=true`, `on_owner_win10=false`, `installed_gui_sha256=0cf174...`, source and source-tree hashes agree with PR #76. Thus the tested **hosted** installed GUI is the original final Windows payload GUI, not a different intermediate test executable.
- All explicit scope denials present and consistent: installer unsigned; `publisher_release_approved=false`; `driver_included=false`, `capture_helper_included=false`, `system_service_included=false`, `app_specific_interception=false`, `udp_or_quic_proxied=false`, `system_dns_or_proxy_mutated=false`, `wfp_native_gate=NO_GO`, `independent_reviewer_passed=false`. This does not cryptographically prove an unsigned application's authenticity beyond origin ZIP and hash pins.

## CI and separate capacity claims

- Candidate run **attempt 1 FAILURE**: contract, Windows package/lifecycle, all three portable-core jobs, Mac static-scope, managed SSH PASS; **macOS universal-package CANCELLED** while waiting, downstream native QA and final unified kit SKIPPED. That is not a macOS source build failure, but **full unified beta.2 candidate CI was not green**.
- A re-run of the canceled macOS universal-package job was **successfully requested**, run **attempt 2**, and at the observation it was **QUEUED**; original run ID remains `43883696169`. Do not pre-declare completion or success.
- [Real Windows OpenSSH acceptance #43883706200](https://github.com/i-shutov/flowbridge/actions/runs/43883706200): separate managed and raw jobs SUCCESS, **raw maximum 246 held**, only the approved 128/recovery lower threshold proved, **not raw512**. Previous [#43823314443](https://github.com/i-shutov/flowbridge/actions/runs/43823314443) failed at about 244 held with sshd resource errors. No universal OpenSSH backend capacity inferred.
- Separate [G2 kernel connection owner #43883706094](https://github.com/i-shutov/flowbridge/actions/runs/43883706094) FAIL; native WFP 1.0 NO-GO is intentionally preserved. A generic rust-and-native workflow on source also includes an unrelated cancelled Mac job and should not be labeled fully green.

## Acceptance boundary and next steps

1. **User's original Win10 Codex V4 ZIP is not attached here or in GitHub artifact**. User reported local file `A3-Codex-V4-ReleaseQA-20261116T061509Z-V4-evidence.zip` SHA256 `23844631907f96063f0b13db73a835b92c386a4be3ed13a174c484c3139606e2`, 100 manifest files, actual GUI at 980×680 / 1366×768, SSH/hostkey/credentials/all-down/Stop PASS. These are **reported, not independently audited**. Exact owner GUI/SSH A3 result must remain OPEN pending that file's independent review. `beta.1` GUI remains known defective and never retroactively accepted.
2. User-reported invalid-key-path test was on **beta.1 V3**, not the final beta.2; it must be repeated if in A3 required matrix, or explicitly `NOT_RUN` with justified release decision.
3. Windows-first decision makes Mac native release acceptance deferred. For a distinct **Windows-only engineering prerelease**, an independently verified exact Windows artifact could be evaluated without presenting the joint Mac candidate workflow as fully successful. The full cross-platform package as originally designed is still incomplete until Mac completes; any Windows-only release must have an explicit separate scope and true required checks, no silent gate waiver.
4. Remaining Windows beta blockers: independent original V4 owner evidence and Win11 acceptance, project-specific `LICENSE` choice and independent legal/security/runtime audit, A6 reviewer decision and explicit A7 publication approval. Unsigned Windows beta package is not a signed 1.0 deliverable.
5. Windows 1.0 additionally requires signed WFP kernel origin/socket object identity and native selected vs unselected proof, no-DIRECT failures, DNS/UDP, 24h soak and separate Win10+Win11 frozen RC. Do not merge beta into main, deploy WFP or publish tags on this audit.

**Private handoff:** independent auditor generated a stand-alone Python stdlib verifier and SHA-verdict JSON alongside original GitHub artifact, retained with the user rather than committing binaries to the public repository. Only public artifact hashes and sanitized factual status are recorded here.
