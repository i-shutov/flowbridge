# FlowBridge beta.2 — independent bounded internal security review (17 November 2026)

**Verdict:** `TECHNICAL_SECRET_HISTORY_SCREEN_PASS_WITH_SCOPE_LIMITS` and `ORIGINAL_INSTALLER_PINNED_PREFLIGHT_NEGATIVE_PASS`. **Not A5/A6 full security GO; A7 internal pilot deployment remains NOT_GRANTED.**

## Closed-source / exposure risk: P0 open

- Live GitHub repository metadata confirms [`i-shutov/flowbridge`](https://github.com/i-shutov/flowbridge) is still **Public**, `private=false`, `allow_forking=true`. The owner's proprietary/closed-source decision does **not** conceal already readable source or previously downloaded artifacts. It cannot revoke clones/forks/caches. The owner has stated they will privatize the repository later; **no visibility changes were performed**. Tracked at [P0 #83](https://github.com/i-shutov/flowbridge/issues/83).
- **Do not post raw secret matches, user V4/V5 screenshots, personal profiles, SSH logs or private key material** to public GitHub/Actions. If a real secret is found, investigate and rotate using authorized private channels, not public Issue content.

## Direct checks executed and original evidence

| Claim | Actual result | Boundary |
| --- | --- | --- |
| Exact original frozen beta.2 source archive `86583a1a0487b9d383c0122b24558e620bde5b9c` SHA256 `f37533b57453ecbc79efd014d9dbc405e6076b2c9b35f823ecae1e56684f3628` | **303/303 source files** inspected by high-confidence regex, 0 hits, 0 oversized | Snapshot only, not all secret formats, not clone history |
| Original owner V5 evidence ZIP SHA256 `809dee21f0884e0d31dfa89a98033276cefaad859de1de64a87a2b90f454cb4c` | **27 archived objects** screened, 0 hits, 0 oversized | Owner-supplied evidence, not remote forensic attestation |
| Original owner V4 evidence ZIP SHA256 `23844631907f96063f0b13db73a835b92c386a4be3ed13a174c484c3139606e2` | **100/100 first-layer files** scanned; 0 hits. One original nested Windows CI ZIP >3 MB could not be scanned inside the bounded first-layer scan | Nest audited separately: original Windows artifact ZIP (matching prior GitHub SHA) **25/25 items** checked for the same high-confidence signatures, including direct scan of the only 3.1 MB executable; 0 hits. This still excludes encoded/encrypted content and non-matching secret forms |
| Public fetched Git/PR history | [Dedicated exact-head security CI #44055935443](https://github.com/i-shutov/flowbridge/actions/runs/44055935443) **4/4 SUCCESS**; artifact [#14315793075](https://github.com/i-shutov/flowbridge/actions/runs/44055935443/artifacts/14315793075) exact ZIP SHA256 `d49087b8fb9691c5896b9a93446e642d9b8335d146154cc1bec1758ffad1128d`; **9,399 Git objects, 2,769 blobs**, no skipped oversized blobs, **zero high-confidence findings** | All refs **fetched** on Actions, not inaccessible deleted/garbage-collected objects or external clone copies; no universal no-secrets claim |
| Original beta.2 installer SHA256 `0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4` | Read-only PS5.1 script and CI hash verification PASS; hosted Windows Server 2025 **rejected** as not Win10 Pro 22H2 x64, as intended | Owner native Win10 preflight script has **not been executed on owner host**, and no installation was performed by this review |

**Source/CI controls:** [security QA PR #82](https://github.com/i-shutov/flowbridge/pull/82) exact `ab7d0d56dfa6af0843c183497d455a6b67578ea1`, [CI #44055935443](https://github.com/i-shutov/flowbridge/actions/runs/44055935443) 4/4 SUCCESS: Windows/Linux adversarial mutation tests, historic Git object redacted scan (including fetched PR refs), and original SHA-pinned offline installer preflight negative on hosted Windows Server. `tools/security/scan_public_history.py` reports only finding categories and truncated blob hashes; no matched token values or private filenames are written to logs.

## Reviewed source boundaries and remaining tests

- **SSH strong defaults** in `crates/flowbridge-tunnel/src/lib.rs::arguments`: `-F none`, `StrictHostKeyChecking=yes`, `BatchMode=yes`, `PasswordAuthentication=no`, bounded localhost `-D`. These were read in the exact source and have positive/negative owner Win10 evidence. That does not prove every OpenSSH/Windows edge case.
- **Diagnostic/privacy distinction:** `crates/flowbridge-ffi/src/diagnostics.rs` constructs an allowlist-only diagnostic JSON and includes tests for secret/path/error injection. But `native/windows/main.cpp` shows raw SSH and engine event text in the on-screen journal, including potential destination hostnames / file paths; screenshots and screen-sharing are **not redacted automatically**. Manual redaction is required for evidence leaving internal QA.
- **Profile writes:** `native/windows/main.cpp::writeFile` stages a file in the destination directory, then uses `MoveFileExW(..., REPLACE_EXISTING|WRITE_THROUGH)` to replace it; the owner V4/V5 evidence shows file/ACL/registry restored after QA. **Security implications of arbitrary caller-controlled export locations/reparse points and admin execution have not been independently fuzzed or authenticated**, so remain targeted review points.
- **Installer OS scope mismatch:** original frozen `packaging/windows/FlowBridgeExplicitBeta.nsi` uses `AtLeastWin10`, meaning it does **not technically forbid Windows 11** even though owner deferred all Win11 tests/support. This is a **support enforcement gap, not evidence of a Win11 product security failure**. The new read-only preflight strictly checks `build=19045`, `22H2`, `Professional/ProfessionalN`, x64; no installer execution or altered accepted binary. A future installer hard gate would require a **new frozen candidate and re-QA**, not silently rewriting `beta.2`.
- **Unsigned installer:** no publisher signature established; original immutable SHA plus trusted distribution path are critical. The read-only preflight records Authenticode status, rejects wrong hash, never disables SmartScreen or runs installer. This does not substitute for signed-distributor authenticity.
- **Win10 patch servicing:** actual ESU/OS security updates remain **NOT_VERIFIED**. Internal pilot must use a responsibly maintained, constrained Win10 environment; do not call unpatched OS a secure production target.
- **WFP/G2 Windows 1.0:** protected kernel-origin capture and physical no-DIRECT/DNS/UDP still **NO-GO**, even if explicit-only beta passes.

## Release status / next bounded block

- **A0–A3 Win10 explicit beta.2 PASS** on independently reviewed original V4 100/100 and V5 26/26 evidence and same original binary/source SHA.
- **A5 technical dependency/BOM/RustSec** 4/4 PASS, **A6 technical source/PE** 4/4 PASS, **new bounded secret-history/installer preflight CI** 4/4 PASS.
- **A5 internal-use license/third-party runtime rights + native security, A6 final security/privacy P0 and A7 internal deployment GO remain OPEN.** The current product is closed/internal-only, no MIT/Apache grant, no public release tag/installer distribution. Owner-controlled repo privacy action tracked at #83.
- **No source/binary changes** to frozen beta.2; audit scripts/CI are **review tools only**. No Win11/macOS native execution, no driver install or firewall/DNS/UAC changes.
