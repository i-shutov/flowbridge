# FlowBridge — real WFP redirect acceptance on an authorized Windows VM

Version: 2026-10-29. **Prepared QA scripts, not a claim that the VM test has run.**

## What hosted CI can and cannot prove

On Windows/Linux/macOS, `tests/wfp_wire_fixture_smoke.py` exercises actual
IPv4/IPv6 SOCKS5 wire framing, binary data, half-close, mock refusal, and UDP
echo using only loopback sockets. It does not load a driver, change firewall
policy, validate an actual system redirect, or establish server-side DNS.

The regular Windows BFE scope job tests *ALE_AUTH_CONNECT* selection and
dynamic lifetime with a BLOCK filter; it does not exercise our
*ALE_CONNECT_REDIRECT* callout. WDK compilation is not driver loading.

Two further tests in the *manual*, dedicated self-hosted
`windows-wfp-runtime-vm.yml` workflow require an **already installed,
authorized, signed/test-signed FlowBridge WFP driver**.

## VM prerequisites and protections

1. Use an isolated, snapshot-restorable Windows 10/11 x64 test VM (or
   compatible Windows Server test machine), with operator authorization and
   an administrator account. Avoid testing against a daily-use workstation,
   production network, or personal SSH credentials.
2. Install and load only a driver signed and accepted under the VM's
   **existing code-integrity policy**. This repo's ordinary NSIS installer does
   not install, register, sign, or trust a driver. Do not disable Secure Boot,
   Windows integrity checks, or unrelated endpoint protection as a shortcut.
3. Register the Actions runner exclusively on the authorized VM with labels
   `self-hosted`, `windows`, `x64`, `flowbridge-wfp-vm`. Avoid granting
   untrusted PRs access to this privileged runner; execute an approved,
   reviewed commit. The operator must keep the VM isolated and restore its
   snapshot if anything unexpected occurs.
4. Install Python 3.13, Rust stable toolchain, Visual Studio C++ x64/CMake,
   and Windows SDK/WDK needed for source builds. The workflow builds the
   unprivileged Rust DLL, native capture helper, and one disposable probe EXE.
5. Run the read-only `FlowBridgeCapture.exe --preflight`; its
   `kernel_driver_accessible: true` proves only ABI/device availability,
   **not** redirection, correct signature, or IP traffic coverage.

The Actions workflow is intentionally `workflow_dispatch` only and cannot
run on general GitHub-hosted Windows runners. No source signing, driver
installation, firewall changes, system DNS settings, HTTP/TLS interception,
or external connection is performed by either test.

## VM acceptance stages

### A. Exact full-path capture and dual-stack behavior

`tests/windows_wfp_redirect_runtime.py`:

- generates two test binaries with the **same basename** in different
  directories and a validated profile pinned with SHA-256 across the UAC
  helper launch; a mismatched profile must be rejected before filters;
- confirms both selected and unselected direct TCP IPv4/IPv6 baselines;
- after actual kernel redirect, confirms SOCKS5 sees selected IPv4/IPv6
  destinations, without changing the address family;
- confirms the other same-name full-path binary is not captured;
- confirms selected UDP IPv4/IPv6 remains DIRECT and is not recorded by SOCKS
  (this is **not** QUIC leak protection);
- induces an explicit negative SOCKS CONNECT reply and requires selected
  connections to fail rather than fall back to DIRECT, in **both** families;
- verifies dynamic WFP filter removal after signaled Stop and after abrupt
  GUI-owner process death, with normal direct traffic restored afterward.

Evidence: `build/verification/wfp-runtime/result.json`. Both
`ipv4_redirect_verified` and `ipv6_redirect_verified`, both UDP-bypass
fields, owner-death cleanup, and `passed` must be true.

### B. Real kernel capture through the GUI-owner Rust engine

`tests/windows_wfp_userchain_runtime.py`:

- starts the actual Rust FFI user-level FlowBridge SOCKS listener and confirms
  its OS TCP owner PID; the test process holds the listener, while the
  separately launched helper uses a WFP driver and an isolated local-SOCKS
  profile without SSH keys;
- routes a selected test EXE through **actual ALE_CONNECT_REDIRECT → elevated
  helper → GUI-owner Rust engine → second SOCKS5 hop → echo** for IPv4/IPv6;
- proves an unrelated same-name executable does not enter that route;
- sets the GUI engine's managed-upstream readiness gate false; requires
  selected probes to fail without any upstream SOCKS connection or direct
  connection to the original echo target, then permits new connections
  after readiness returns;
- verifies Stop removes WFP filters; in a second capture session, stops the
  GUI-owned listener and requires helper/filter teardown by the PID/port
  ownership monitor.

Evidence: `build/verification/wfp-runtime/userchain.json`. It must report
actual WFP, real Rust engine, both IP families, gate fail-closed, listener-loss
cleanup, and `passed` true.

**Boundary:** The VM harness itself requires administrator permission, so its
GUI-owner stand-in runs under that test token. This validates the
*process-ownership and functional routing*, not the normal GUI's
medium-integrity security boundary. Its outer SOCKS mock is not an actual
remote OpenSSH server. It does not verify remote SSH authentication,
host-key policy, remote DNS, system DNS leakage, or Apple NE activation.

## Running and reporting

When the dedicated VM has been prepared, select the reviewed branch/commit
in GitHub Actions → **Windows WFP real redirect — authorized VM only** →
**Run workflow**. If using a local console, set `FLOWBRIDGE_WFP_VM=1` and
pass absolute paths to the compiled helper, probe EXE, release Rust DLL, and
distinct JSON output files. The workflow's final `if: always()` artifact step
preserves both reports even on a failed assertion. A missing driver is a
**failed acceptance test**, not a skip or simulated success.

Record the exact commit SHA, OS build and driver signature/version, the two
JSON reports, WFP filter state after normal/abrupt cleanup, and manual
operator observations. Do not close `#1` unless these reports are actually
produced **on the authorized VM**, reviewed, and residual leak/installer
acceptance gates are satisfied.

## Additional independent release gates

- Windows per-selected-application DNS interception/name-preservation and
  packet-level leak evidence, including IPv6, browser DoH/DoT and QUIC scope;
- real OpenSSH remote-server test across WFP with restart/host-key failures
  and quantitative exhaustion/soak coverage;
- real Windows 10/11 upgrade/uninstall, driver signing and uninstall
  approval, Windows DPI 100/125/150/200% visual acceptance;
- Apple Network Extension activation with authorized entitlements on actual
  Macs, including isolated DNS and app-selected native routing.

A green hosted build, an available device, or a checked DNS control must
never be represented as completing these separate system-level gates.
