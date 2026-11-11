# FlowBridge explicit SOCKS beta — release cut and acceptance contract

**Date:** 2026-11-11. **Status:** Engineering candidate / NO-GO for public release.
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
- Engineering package version `0.2.0-explicit-candidate` matches the
  retained Rust core's `0.2.0` lineage. A new source/lockfile/version cut
  is required before tagging `v0.3.0-beta.1`.

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
