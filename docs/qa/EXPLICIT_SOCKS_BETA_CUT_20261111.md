# FlowBridge explicit SOCKS beta — release cut and acceptance contract

**Updated:** 2026-11-13. **Status:** Engineering candidate / NO-GO for public release.
**Candidate branch:** `release/explicit-socks-beta-20261111`, created from previously verified product source `c339df2e4d20edf1d11d45786581a68451a71929` (PR #56).
**Review:** [draft PR #59](https://github.com/i-shutov/flowbridge/pull/59), based on PR #56's branch.

## What the candidate can claim

One user-owned Windows explicit TCP SOCKS5/SOCKS5h local listener,
existing upstream SOCKS/HTTP, managed OpenSSH -D with private-key/host-key
requirements, GUI operational state and normal user-mode Start/Stop.
A **client application must independently configure the proxy**.
Hostname DNS forwarded through SOCKS5h only applies to clients that send
hostnames; applications resolving locally remain outside this contract.

- No OS process identification, transparent interception, WFP/NDISRD
  driver, automatic application-scoped routing or system-level kill switch.
- No UDP/QUIC transparent proxy, universal DNS leak-free guarantee or
  traffic protection for apps not configured to use explicit SOCKS.
- No publication of unsigned candidate as a production or signed release.
- Existing user data and stable FlowBridge 0.2.0 installation must not be
  replaced by an engineering preview.

## A0 packaging exclusion gates

- Win32 GUI compiled with `FLOWBRIDGE_EXPLICIT_BETA_ONLY=ON`.
  Guard at **handler and control** levels for WFP start/stop,
  native EXE policy export and BlockOthers.
- Explicit profile at `%LOCALAPPDATA%\FlowBridgeExplicitBeta\profile.json`;
  original stable `%LOCALAPPDATA%\FlowBridge` must remain unchanged.
- NSIS distinct HKCU `Software\FlowBridgeExplicitBeta` and uninstall key
  `...\Uninstall\FlowBridgeExplicitBeta`, Start Menu and installation folder.
- Exact package payload allowlist: `FlowBridge.exe` (Win32),
  `flowbridge-cli.exe`, `flowbridge_ffi.dll`, LICENSE, README,
  3 safe example profiles, presets, dependency/license notices.
- **Forbidden distribution files:** `FlowBridgeCapture.exe`,
  kernel `.sys`, `.inf`, WFP/NDISRD service installer or automatic
  network-hook component. Source-only research may remain in the repo
  but is neither linked as a driver nor shipped as an executable helper.
- All package file hashes and PE x64 headers must be checked.
- The new version cut uses `0.3.0-beta.1` consistently in Rust, GUI and
  package metadata. `packaging/explicit-beta.json` is the version contract.
  This does not authorize a tag, GitHub prerelease, publisher signing or 1.0.
- Payload also contains source-pinned CycloneDX `SBOM.cdx.json` and
  `BUILD-METADATA.json`, with real license texts in the notices. The inventory
  covers resolved production/build inputs; binary composition, native runtime
  distribution review and independent license review remain separate.

## Verified user-owned Windows 10 evidence — *previous* product SHA

Owner-provided actual target Win10 PowerShell results (not independent
raw ZIP review): W0, W1, W2a, W2b0, W2b1, W2b2 **PASS**.
W2b2 owner diagnostic ZIP SHA256:
`dd3988e39a188d100ac5ded6c52d5b64102b0934e783c522649985ef68db9e37`.
These user-mode results belong to **the old engineering package built
from SHA c339df2e**, not to the modified release branch's GUI/NSIS bytes.
They are proof of feasibility and a regression baseline, **not** acceptance
of this new distribution's target Win10 install.

The exact old package has separate GitHub Windows hosted acceptance
[#43012107722](https://github.com/i-shutov/flowbridge/actions/runs/43012107722)
and [#43013314496](https://github.com/i-shutov/flowbridge/actions/runs/43013314496);
the previous apparent uninstaller failure was a QA auditor bug:
the existing NSIS intentionally retains HKCU user preferences while
removing its `InstallDir` value. The corrected tests and original
uninstaller are independently green.

## New release candidate gates

| ID | Required evidence | Current |
|---|---|---|
| A0 | Strict GUI compile gate + separately namespaced NSIS, no driver/helper, local Windows runtime and install+uninstall | **IN TEST**, not accepted |
| A1 | All required Rust/Win/macOS CI on the exact final source SHA, stable `Cargo.lock` | **OPEN** |
| A2 | Real managed SSH 64/128 admission, 10k controlled churn, real shutdown/reconnect, no DIRECT for accepted client traffic | **OPEN** |
| A3 | Actual target Win10 install/GUI/OpenSSH/uninstall of the **new** source/payload | **OPEN** |
| A4 | macOS local SwiftUI universal package plus native install/launch/update/uninstall, no NE claim | **OPEN** |
| A5 | Exact-version notes, SHA256SUMS, third-party dependencies and SBOM/license audit | **OPEN** |
| A6 | Independent security/release reviewer, zero P0 for explicit SOCKS-only, original source/package hashes match | **OPEN** |
| A7 | Tag and GitHub prerelease **only after** A0–A6; verify fetched published bytes | **NOT RELEASED** |
| Native WFP G2/W3 | Signed/loaded driver and independent physical ALE/accepted socket evidence | **NO-GO** (separate 1.0 track) |

### 2026-11-13 unified candidate pipeline

The A0–A7 table remains a release acceptance table. New hosted results are
recorded per **candidate source SHA**, not inferred from this document.
`explicit-beta-candidate.yml` is the single push/manual entry point; it calls
the three platform/SSH workflows as reusable jobs.

1. Strict Rust format/Clippy/workspace tests and DNS loopback regression on
   Linux, Windows and macOS run on the exact checkout.
2. Windows explicit install/GUI/upgrade/uninstall and macOS universal
   package scope checks produce manifests with source, tree and run ID.
3. Managed OpenSSH uses the **release DLL and CLI from the Windows package**.
   It requires 128 held channels, 1152 expected overload rejections, 10000
   churn and four independent workers; a rebuilt debug DLL cannot pass.
4. Fresh hosted Windows/macOS jobs execute the operator QA runner's install
   lifecycle. Their result is explicitly CI, never owner acceptance.
5. `tools/explicit_beta_candidate.py` verifies hashes, exact payload allowlist,
   source/tree/run identity, metadata and QA reports before producing one
   portable bundle with `candidate-index.json` and checksums.

The previous [managed SSH run 43388914981](https://github.com/i-shutov/flowbridge/actions/runs/43388914981)
is accepted hosted evidence for source `6f6f69ad`; it used debug FFI and is
not a substitute for the packaged-release-byte run. Original ZIP digest:
`bcd6a3821c01b6402f554ebad54ce0abca0fe122dd93f89ee78cbfe2410d27b1`.

The separate capture G2 job remains strict. Its original failure
`kernel_connection_id_missing` is retained; no `continue-on-error` or
manufactured PacketBound approval is introduced. See the
[current 1.0 plan](../RELEASE_1_0_PLAN.md) for backend scope and B0–B4.
Owner instructions: [EXPLICIT_BETA_NATIVE_ACCEPTANCE.md](EXPLICIT_BETA_NATIVE_ACCEPTANCE.md).

## Working checks

1. [Explicit Windows candidate CI](https://github.com/i-shutov/flowbridge/actions/workflows/explicit-socks-beta-windows.yml):
   build exact branch source, Windows MSVC/FFI/CLI, real GUI smoke (including
   native-capture buttons disabled), signed-off-by-upstream NSIS 3.13,
   per-user Unicode/spaced path, package SHA and 5 GUI screenshots.
   The test installs/uninstalls *only its own test account payload*.
2. Explicit manual target Win10 QA is not authorized by a successful hosted
   build alone; it requires an exact source/payload SHA and the original
   owner's acceptance. No new shell commands are automatically executed
   on their Windows server.
3. GUI or installer changes invalidate previous package SHA acceptance.
4. WFP research must remain in its independent branches. No kernel load,
   driver service, TestSigning or network settings change under this beta PR.

**GO/NO-GO:** still NO-GO for `v0.3.0-beta.1`, regardless of previous
Win10 W2b2 PASS, until the scope-separated package and remaining A1–A6
are independently accepted.

## A4 macOS explicit-only candidate work

Dedicated Xcode scheme, separate bundle/profile identity and no-NE package path
are staged in this beta branch. See
[EXPLICIT_SOCKS_BETA_MACOS_A4.md](EXPLICIT_SOCKS_BETA_MACOS_A4.md).
Hosted build and original package checks do NOT replace native Mac acceptance.

## 2026-11-13 — macOS hosted candidate PASS, managed SSH retest

- [macOS Actions #43387219678](https://github.com/i-shutov/flowbridge/actions/runs/43387219678):
  static-scope and universal-package SUCCESS on source 922a32df.
  Verified universal x64/ARM bundle and independent unsigned explicit beta package;
  .pkg SHA256 af4149fa0b55db1cf167adbba163cca45f1c153dfbbe3ede60b9efc42d08efdd.
  Artifact 14018813907, ZIP SHA256 29a91db82011e9ccbdeb6d1d7ff6170179e76718194ccb5ef777560c1d53e3e5.
  This is HOSTED_BUILD_ONLY, not native owner Mac A4 GO.
- Historical [Windows OpenSSH run #42339966362](https://github.com/i-shutov/flowbridge/actions/runs/42339966362)
  had raw 512 held-channel WinError 10054; its managed scenario PASSED.
  The new explicit-beta-managed-ssh.yml tests actual authenticated managed
  SSH on the new exact beta SHA (10k bounded churn, source/report pinning).
  Raw 512 stability remains UNPROVEN; not treated as a managed fail or waived.
- A2/A3/A4/A5/A6 not closed by hosted-only smoke; requires independent
  original artifacts and fresh physical Windows 10/11 and macOS acceptance.
