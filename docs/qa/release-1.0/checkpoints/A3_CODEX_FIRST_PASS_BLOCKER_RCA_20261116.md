# A3 Codex first attempt — Admin profile and portable SSHD blocker RCA

**Date 2026-11-16. Scope frozen Windows 0.3.0-beta.1.** First Codex report was pasted by owner; the original first-attempt ZIP remains on target Win10 and was **not transferred/independently reviewed** in this change. Do not claim tested PASS based on the summary alone.

## Reported outcomes

- Target Win10 x64 active RDP and UI Automation available; exact installer SHA + 13 manifest payloads and explicit SOCKS capabilities PASS by Codex report.
- GUI interactive steps BLOCKED_PROFILE_ISOLATION because a beta profile persisted under fixed Windows Known Folder; **actual GUI testing not executed**.
- Positive real SSH/SOCKS5h echo and Stop BLOCKED_SIGNED_SSHD_UNAVAILABLE because Codex only searched installed Windows Feature server, did not reuse known verified portable fixture.
- One expected negative for unavailable SSH: SOCKS5 domain `localhost` returned failure `01`; direct local listener was not accessed. This only supports one denial scenario, **not** successful SSH or system DNS egress safety.
- Codex reported restoration of four user file fingerprints and no lingering QA processes; no independent archive review yet. A3 full remains false.

## Verified source correction

1. Frozen GUI `native/windows/main.cpp` uses `SHGetKnownFolderPath(FOLDERID_LocalAppData)`; the beta prefix is `FlowBridgeExplicitBeta`, with `profile.json` and `desktop-settings.json`. Frozen NSIS `packaging/windows/FlowBridgeExplicitBeta.nsi` explicitly preserves beta profile at uninstall. The existing `Admin` beta profile is **expected**, not proof of an unsupported OS. The operator has already authorized test on the existing Admin account (no new Windows account). Use same-volume atomic escrow rename, independent backup/fingerprint, genuine UI actions under same Admin, and unconditional rollback with SHA/registry/ACL confirmation.
2. `tools/windows/FlowBridge-Win10-W2B1-RealSSH.ps1` already contains an independently pinned portable official Microsoft OpenSSH server ZIP, downloaded into a user TEMP fixture, checked against SHA256 and Authenticode, and launched as a **local user-owned process**, no Windows service. Official pinned archive: `https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.4.0.0p1-Preview/OpenSSH-Win64.zip`, SHA256 `b67ff8becd203502190ec42ac7787c24c2cd3325ed7700485fe7a1c83d2a7957`. Reuse fixture mechanics, but run frozen beta CLI/FFI/GUI instead of the historical W2b1 binary.

## New controlling operator task

[V2 autonomous Codex task (same file, new exact source revision)](https://github.com/i-shutov/flowbridge/blob/8c23e10819e200e7bf38e596490fba2c1113cf37/docs/qa/release-1.0/checkpoints/A3_WIN10_CODEX_AUTONOMOUS_GUI_SSH_TASK_20261116.md). It explicitly supersedes the blocking assumptions from the first prompt, uses previously authorized Full Access/Admin GUI QA, and retains the mandatory native-driver/WFP safety boundary.

**Verdict:** `FIRST_CODEX_REPORT_BLOCKED` (NOT A PRODUCT DEFECT); `REMEDIATION_TASK_READY`; `GUI_REAL_NATIVE_ACCEPTED=false`; `SSH_REAL_POSITIVE_ACCEPTED=false`; `A3_FULL_ACCEPTED=false`; `RELEASE_APPROVED=false`; `G2_NO_GO`.
