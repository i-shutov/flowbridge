# FlowBridge — P1 SSH diagnostics disclosure, source-only patch

**Date 2026-11-17. Review verdict: `P1_SOURCE_PATCH_PROPOSED_CI_PENDING`.** This branch starts exactly from accepted frozen source `86583a1a0487b9d383c0122b24558e620bde5b9c`; it does **not** rebuild, overwrite, retag or publish the existing `0.3.0-beta.2` installer SHA256 `0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4`.

## Original source finding

- In `crates/flowbridge-tunnel/src/lib.rs::stderr_line`, OpenSSH stderr was converted to UTF-8 `text` and pushed **verbatim** into both `State.stderr` and `State.events`. Both are part of serialized `Snapshot` available to the FFI, and GUI `native/windows/main.cpp::showSsh` appends `events` to retained journal. Untrusted OpenSSH messages may contain a local username, identity-file/known_hosts path, internal endpoint and even arbitrary text from an alternate executable.
- Original `Status.backend_path` (intentionally needed for **internal** process authority in future native capture) and free-form `backend_version` were copied directly into the user-visible SSH health text. The GUI journal stores the same health text. **Do not remove `backend_path` from the internal FFI authority data path without a separate native security design**.
- **Distinct safe route exists:** `fb_diagnostic_report_json` uses strict allowlisted counters/enums, not these raw strings. However, this does not protect raw `fb_ssh_snapshot_json` and GUI screenshots/journal. This is a real source-level **P1 privacy exposure**; it is **not evidence that private data was actually disclosed to a third party**.

## Targeted changes

1. Classify raw OpenSSH diagnostic text for host-key/publickey errors, missing identity, DNS/connection timeout/refused and otherwise generic `OpenSSH diagnostic suppressed`. Classification still uses original input in memory, so `s.fatal` and resource-exhaustion logic retain their safety behaviour; **only fixed non-sensitive literal categories** go into serialized `Snapshot.stderr` and `Snapshot.events`. Resource-exhaustion counters/coalescing remain unchanged.
2. Replace several dynamic `{error}` OS failure messages with safe `ErrorKind` categories; preserve local port number for user action without leaking OS-formatted arbitrary data.
3. Stop appending raw `backend_path` and arbitrary `backend_version` to the GUI health and journal. Internal FFI `Status.backend_path` remains available to the internal privileged-helper launch logic, so private snapshots **must not be treated as sanitized export artifacts**.
4. Runtime Rust unit test injects synthetic secret-appearing strings and paths into `stderr_line`; requires the entire serialized snapshot to omit them while retaining actionable publickey/host-key and bounded-lifecycle semantics. Existing tests for host key, resource overload, Stop and child reaping are retained. Win32/Python source contract rejects direct GUI path/version addition and raw-stderr persistence.
5. CI runs Rust tests and source safety tests on Linux/Windows and compiles Windows `FLOWBRIDGE_EXPLICIT_BETA_ONLY=ON` native GUI/FFI, **without** creating any installer or WFP binary.

## Release integrity / security limits

**Never declare the existing frozen beta.2 package privacy-patched.** Its EXE/DLL hashes remain the original old version. After this patch passes independent review, **a new version and new exact binary/manifest SHA** (e.g. `0.3.0-beta.3`) with original Windows 10 GUI/SSH failure/positive-control/restore evidence must be produced before internal deployment claims can inherit this fix.

This change specifically prevents raw **OpenSSH stderr** from escaping the SSH snapshot and GUI's backend-path banner. It does **not** prove all possible FFI errors, GUI logs, saved user profiles or screen-sharing are safe. Test the remaining user-profile / ACL / untrusted JSON handling separately; full A5 native rights, A6 P0 privacy/security, A7 explicit internal pilot deployment remain OPEN. Closed-source owner choice remains unchanged; the repository is still PUBLIC and user has deferred changing it. Future protected Windows 1.0 signed WFP/G2 is NO-GO.

**No key/credential values, private Win10 V4/V5 archive or screenshots are committed to public GitHub.** Test strings are synthetic and nonfunctional.
