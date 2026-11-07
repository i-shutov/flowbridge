# R6 — read-only native WFP AppId test contract (2026-11-07)

Research branch only: `research/windows-wfp-ale-attribution-20261107`; parent SHA `adc187c04765afbffe14effff906687d464dfec0`; main at `5b5afc2feeda2195f302380e615ba003d4906e09`. No change to beta, PR #56, main, driver, WFP filters, security policy or runner.

## Test objective

Determine on actual Windows whether WFP `FwpmGetAppIdFromFileName0` distinguishes *identical binary content* stored as `probe.exe` in distinct directories, and characterize hardlink, symlink-directory, and case-only aliases. A returned WFP AppId is **not** the signed identity of the executable, a reference to an EPROCESS, PID creation epoch, socket ownership, or a TCP packet identity.

Two independently implemented native user-mode readers must agree: (1) Rust `appid_readonly.rs` calling `FwpmGetAppIdFromFileName0` and `FwpmFreeMemory0` and (2) Python `ctypes` calling those exact supported Win32 functions with independently declared FWP_BYTE_BLOB ABI. Optionally use the documented `netsh wfp show appid file=<absolute path>` CLI as a third read-only device-path cross-check. No executable fixture is launched; only temp copies of the existing Windows `System32\where.exe` binary are created and cleaned.

## Files and commands

- `appid_native_matrix.py`: bounded fixture creation, Rust compilation, native Python Win32 WFP FFI, cross-implementation exact-byte comparison (boolean only), netsh read-only check, strict JSON, mandatory cleanup.
- `test_appid_native_matrix.py`: independent offline safety and harness-contract regressions.
- **Offline preflight:** `python research/wfp-ale/appid_native_matrix.py --selftest`
- **Offline tests:** `python -m unittest discover -s research/wfp-ale -p test_appid_native_matrix.py -v`
- **Windows-native experiment (requires installed Rust toolchain and Python):** `python research/wfp-ale/appid_native_matrix.py`

On Windows this does not install a driver, register a callout, start capture, modify firewall, modify BFE, open a network socket or execute copied EXE. It creates bounded temporary filesystem fixtures only, then removes them in a finally-protected TemporaryDirectory context. A symlink may require unavailable permission and then is skipped, not silently treated as PASS.

## Actual evidence and execution barrier

- In current Linux container: `python -m py_compile` PASS for both files; `test_appid_native_matrix.py` **9/9 PASS**; `--selftest` **4 matrix entries prepared**, with case-variant skipped on case-sensitive filesystem. Native execution without Windows explicitly returned `no_windows_native_executor` / exit 2.
- Source SHA256 from local exact files: native matrix `b117182d0223bf286d718f09165ef3198e67283928d149674aabecd2b1131794`; independent tests `7d8f841aee8eb7f8c4afde6ed61af1a08a2eb80b9db74c1f394a1c152a8d5a66`.
- No local `rustc`, `cargo`, `gh`, Windows runtime or GitHub Actions workflow-dispatch credentials. The available connected GitHub actions support source/ref writes and read-only workflow inspection but do not expose `workflow_dispatch`; bypass via push-/issue-trigger, failed-job rerun, external paid browser or new tokens is forbidden. **Thus Windows WFP API result is BLOCKED, NOT EXECUTED**, not a PASS.
- Once an authorized Windows executor is available, the standalone script will fail if Rust compilation fails, if any two implementations disagree or if same-file lookup is unstable. Case outcomes are observational; alias identity is not predeclared from file name or content alone. Output contains only booleans, counts and status flags, not raw AppIds, local absolute paths, PIDs, credentials or raw receipts.

## Architecture result

Native WFP AppId semantics are **not yet measured**. Even a successful AppId comparison does not prove `ALE_CONNECT_REDIRECT -> referenced EPROCESS -> creation epoch -> accepted-socket redirect records -> selected physical traffic`. G2, native PacketBound, system no-DIRECT, dual-stack leak-free and release remain NO-GO / OPEN. NDISRD packet mode and WFP/ALE connection mode remain parallel, independently scoped mechanisms. Historical G1 10/10 remains bound only to `dd1ab3c`.

Official sources: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0 ; https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfreememory0 ; https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wfp .

Next binary GO/NO-GO gate: run the above script on a real permitted Windows x64 instance using the exact research SHA; independently audit raw-result sanitization, fixture deletion, command exit codes, toolchain provenance, and keep the kernel-origin attribution gate distinct.
