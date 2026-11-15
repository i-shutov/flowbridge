# R199 — clean-host BFE readback without R19 runtime objects

`main.rs` is a **new, user-mode Rust, read-only diagnostic** for Windows 10+. R190's strict structural readback necessarily fails when the R19 dynamic BFE session has not been activated. R199 instead reports the raw statuses of `FwpmEngineOpen0`, `FwpmSubLayerGetByKey0`, four `FwpmCalloutGetByKey0` and four `FwpmFilterGetByKey0` calls. Nonzero codes are **UNKNOWN**, not automatically proof of object absence. Success establishes a management-object readback only, not effective filters, callbacks, process ownership, packet attribution, no-DIRECT or leak freedom. A registered callout flag is a snapshot of registration only.

Unlike R190, this probe intentionally does not begin a transaction, so it does not require `FWPM_ACTRL_BEGIN_READ_TXN` and cannot accidentally claim an atomic snapshot. It cannot establish that two readbacks describe one consistent BFE configuration. All six APIs used are read/open/free/close. No driver, callout, WFP filter, socket, service or firewall install/update/delete; no network request from the probe. No R19 objects need exist for it to return a diagnostic JSON line.

On a separately admitted Windows 10 Pro x64 **read-only** host, from this directory with a locally cached verified toolchain and dependencies:

```powershell
cargo build --offline --locked --release
.\target\release\flowbridge-r199-clean-bfe-readonly.exe
```

Record exact research HEAD and `main` HEAD (read-only), OS build, `rustc -Vv`, `cargo -V`, SHA-256 of `main.rs`, `Cargo.lock`, binary, stdout/stderr/exit code and ACL-related API codes. `--offline` never fetches dependencies. A no-R19-dynamic-session result must not be confused with a malformed ABI or with absent WFP enforcement. Do not install or activate R19, an extra filter, callout or driver to make this probe positive. No GitHub runner, VNC/SYSTEM gate, network or security setting change is authorized.

Independent source/contract negatives: `python test_surface.py`, `node independent.mjs`. Their success is not native Rust compilation or Windows API execution. Cargo.lock intentionally duplicates the exact `windows-sys 0.61.2` + `windows-link 0.2.1` locked hashes from R190.

Next decisive experiment after the clean-host baseline is still **separately gated native classify provenance**, requiring the selected-origin process, referenced EPROCESS/FileObject, PID+creation epoch+canonical EXE and AppId, exact ALE_CONNECT_REDIRECT/AUTH_CONNECT v4/v6, authenticated accepted-socket context/records, one-time CLAIM and tagged outbound SSH. Test process death/reused PID/5-tuple, reauthorization, sibling DIRECT, compartments, DNS/UDP and loss of WFP/SSH independently. Neither R199 nor R190 proves this chain. The conditional R88/R194/R198 selected-original-AppId self-block remains unresolved.

Official Microsoft: [FwpmEngineOpen0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0), [FwpmFilterGetByKey0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltergetbykey0), [FwpmCalloutGetByKey0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmcalloutgetbykey0), [FwpmSubLayerGetByKey0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsublayergetbykey0); [Access Control](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control).

Research only: `research/windows-wfp-ale-attribution-20261107`; not beta, PR #56, G2/PacketBound PASS, no-DIRECT or leak-free proof. Nothing may touch main/release, services, filters, drivers, firewall, Defender, SecureBoot, MemoryIntegrity, runners, networks or automations.
