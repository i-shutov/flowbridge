# FlowBridge 0.3.0-beta.2 — exact owner Win10 A3 V5 independent original-evidence review

**Reviewed 2026-11-17. Verdict: `WIN10_A3_OWNER_EVIDENCE_ACCEPTED` with explicit no-physical-rerun / no cryptographic host attestation. Windows dual-OS A3, A5/A6/A7 and Windows 1.0 G2 remain OPEN.**

## Original V5 file and pinned code

- User directly supplied original ZIP `A3-Beta2-Codex-V5-Win32-20261116T224755Z.zip`, independently recomputed SHA256 **`809dee21f0884e0d31dfa89a98033276cefaad859de1de64a87a2b90f454cb4c`**.
- Source **`86583a1a0487b9d383c0122b24558e620bde5b9c`**, Git tree `9f92e9e9e87725d127505c8ac415f37e42a8d148`, original [candidate CI #43883696169 attempt 2](https://github.com/i-shutov/flowbridge/actions/runs/43883696169) **11/11 SUCCESS**.
- Original frozen beta.2 Windows installer SHA256 **`0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4`**; GUI `FlowBridge.exe` SHA256 **`0cf1749e7531659b1f5a42433818ecf31fe517d6815d11faeca6e04f9821325e`**; FFI DLL SHA256 **`23b62d54a89feea53331f3ac68fe7c3d348ca99ed72d816f3dcfbc94ef3fd2b4`**. These same pins occur in original V5 `preflight.json`.
- ZIP CRC PASS, exactly **27 entries: 26/26 manifest files with identical SHA/bytes plus `sha256-manifest.json`**, no extra, missing, duplicate, ZIP traversal or symlinks. Independently decoded **six** 1180×760 RGBA PNG and inspected their native GUI states. Original `actions.jsonl` contains **23 actual GUI actions** with PID, foreground/HWND, control IDs and timestamps (including KeyPath 234, Start 100, Stop 101, Save 240).
- Original `VM-910136` Win10 Pro 22H2 x64 build 19045 / account Admin / RDP session 2 / DPI 96 claims are internally consistent, but **operator supplied, not cryptographically attested or independently re-executed by the reviewer**.

## Missing identity path: exact negative + positive control

**Original negative:** `identity_path_exists_before=false`, test changes only the private-key-path GUI input; UIA actions and screenshot states corroborate failed SSH state. OpenSSH real child launched: original journal includes `No such file or directory`, `Permission denied (publickey)`, `SSH 0/1`, plus `<ABSENT_TEST_IDENTITY>` substitution. **12 attempted TCP connections to SOCKS ingress FAILED to connect**; no listener was opened; SOCKS `REP=null` in this V5 test, **not `REP=01`**; independently instrumented localhost target had **0 direct accepts**. This proves a denial within the tested explicit loopback scope, not total system DNS/no-DIRECT coverage.

**Original healthy control:** after changing ONLY the test identity-file path, managed SSH reached `SSH 1/1 Ready`. Original SOCKS5h `hello=0500`, `reply=05000001`, `ATYP=DOMAINNAME` for `localhost`; exact binary payload `0001027F80FEFF410042` (10 bytes) returned byte-for-byte; both EOF flags true. GUI Stop: empty owned SSH child and GUI listener lists.

**Restoration:** original `restore-checks.json` lists six original stable/beta objects; all hash, ACL, time, attributes, count comparisons true, registry before/after hash unchanged, test installer uninstalled, escrow restored, test process list empty. Reader cannot remotely inspect the live machine.

**Test-harness issue documented:** at first Save, the UI automation appended numerical port digits causing an out-of-range validation failure; the script corrected the field using Home/Shift+End, saved correctly and then conducted the negative/positive identity tests. This intermediate self-corrected input error is not credited as a FlowBridge SSH-product defect.

**Microsoft portable SSH fixture:** pinned ZIP SHA256 `b67ff8becd203502190ec42ac7787c24c2cd3325ed7700485fe7a1c83d2a7957`, original fixture report claims Microsoft Authenticode verified. This audit did not re-run signature verification on the owner OS.

## Independent reviewer acceptance decision

This V5 closes exactly the **one** missing final-beta.2 A3 negative listed in [V4 independent review](BETA2_OWNER_WIN10_A3_V4_INDEPENDENT_REVIEW_20261116.md). V4 original archive already passed independent 100/100 integrity, GUI 17 images, original 6/6 native lifecycle, real SSH/host-key/all-down and recovery evidence. Combined V4+V5 exact product/hashes and CI support:

| Gate | Independent decision |
| --- | --- |
| A3 Win10 original evidence integrity | **PASS** |
| A3 Win10 agreed exact beta.2 GUI+SSH test matrix | **PASS_ON_SUBMITTED_ORIGINAL_OWNER_EVIDENCE** |
| A3 Win10 owner-native subgate | **ACCEPTED_ON_REVIEWED_EVIDENCE** |
| Windows target matrix A3 (Win10 + Win11) | **OPEN_WIN11_NATIVE_NOT_RUN** |
| A5 project LICENSE, security/legal/runtime | **OPEN**, despite original-byte technical+RustSec green |
| A6 and A7 owner/public release approval | **OPEN**, no release/tag |
| Windows 1.0 real WFP/G2 signed kernel capture, physical no-DIRECT and DNS | **NO_GO** |

**Provenance of private audit deliverables (not committed to public GitHub):** offline read-only script `verify_v5.py` SHA256 `97f561eea1ee200267d829018bf6ad42ace15c7d093f458b479084a6a81c8b15`, independent verdict JSON SHA256 `2f99ba49e14f42fd5a8145dd7527a6a9b109248d4608c55cacd2b50e862cf5ad`, full reviewer Markdown SHA256 `46baf98c5811f48c5b28ecfbe06f27ca24f67afe773ed0614138ab63ef6affc7`; audit bundle SHA256 `b79f4c655698308d7fedc77acbb52f4df7e42a34bce281b1000c255e0ab48c6a`. Original user ZIP/raw private GUI screenshots/SSH paths not uploaded to this public repository.

**Next**: A3 on **separate native Win11 Pro x64**, A5 project-specific license decision [issue #78](https://github.com/i-shutov/flowbridge/issues/78), independent native-runtime/license/security judgement, A6 independent beta release review, A7 explicit owner GO. No reason to repeat V4 or V5 on Win10 unless the exact candidate bytes change.
