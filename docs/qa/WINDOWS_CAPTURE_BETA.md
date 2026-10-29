# Internal beta vertical: native Windows capture

This checkpoint contains two distinct deliverables:

1. **WFP process selection and functional redirect fixture.** The kernel driver is built separately. Existing BFE QA confirms exact image selection, IPv4/IPv6 TCP policy scope and dynamic-filter cleanup without loading a driver. New `tests/windows_wfp_redirect_runtime.py` performs *real* ALE_CONNECT_REDIRECT testing when and only when a signed/test-signed WFP driver has already been installed and loaded on a dedicated, administrator-authorized Windows VM. It verifies selected native EXE -> WFP -> FlowBridgeCapture -> local test SOCKS5 -> local echo, same-basename unselected exclusion, denial without DIRECT fallback, and cleanup after Stop. It uses only loopback; it is **not a standalone SSH end-to-end or remote DNS test**. The dedicated VM workflow is manual and never runs on general shared GitHub runners.
2. **GUI/elevated helper integration.** FlowBridge now packages `FlowBridgeCapture.exe` beside its existing GUI/CLI, includes a read-only `--preflight`, and exposes native Start/Stop in the Applications page. The GUI writes a checked native rules profile, requests UAC explicitly and passes only full EXE paths. A unique session stop event and GUI owner PID prevent the elevated helper remaining behind after normal/abnormal GUI exit. A deliberately absent kernel driver is reported as an error; **the ordinary NSIS installer does not install or trust any driver**. Exported rules and engine Start/Stop remain separate from native system capture.

### Running on a dedicated Windows VM

* Use an isolated Windows 10/11 or Server test VM with a snapshot, an authorized admin account, and a driver build signed/allowed under that VM's existing code-integrity policy. No guidance here requests disabling Secure Boot or production code-integrity protections.
* Install/load only the FlowBridge WFP driver using the VM operator's usual signed-driver process. Verify `FlowBridgeCapture.exe --preflight` reports `kernel_driver_accessible: true` under the test token.
* Build Rust FFI + native helper and `FlowBridgeWfpScopeQA.exe`; place `flowbridge_ffi.dll` beside the helper. Then run `FLOWBRIDGE_WFP_VM=1 python tests/windows_wfp_redirect_runtime.py --helper <absolute-helper> --probe <absolute-test-exe> --output <report.json>` from an elevated terminal. The optional GitHub Actions job uses the self-hosted `flowbridge-wfp-vm` runner label.
* Save reports and reproduce both stop and forced GUI termination. Inspect WFP filters after exit. Revert the VM snapshot on failure rather than testing on a daily-use machine.

### Boundaries and follow-up gates

* A green ordinary GitHub CI run proves *build/install/GUI preflight/explicit SOCKS*; it **does not prove kernel driver loading, real TCP redirect, unselected QUIC restrictions, remote DNS interception, or macOS extension activation**. This boundary is present in the CLI preflight and package manifest.
* This elevated helper inherits its own SSH process for the internal beta. Privilege separation and trusted SSH backend selection require separate security review before wider distribution.
* Windows system DNS NRPT activation is a separate process-level issue; a DNS-over-SSH unit test cannot prove OS DNS leakage prevention.
* Existing TCP connections cannot survive a full SSH disconnect without a protocol-preserving server-side relay.
