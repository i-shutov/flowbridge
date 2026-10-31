# Clean-room Rust backend: lessons from ProxiFyre / NDISAPI

**Research snapshot:** 2026-10-30.
**Upstream version inspected:** wiresock/proxifyre `5e3bc845d73a47a0931b1233c745580cb916f4ba` (v2.6.4; 2026-10-14).
**FlowBridge base:** main `5b5afc2feeda2195f302380e615ba003d4906e09`.

## Firm design decision

**Do not run, embed, translate, or depend on the ProxiFyre executable/AGPL-3.0 source in the FlowBridge release.** Its design is a functional reference. Implement original Rust user-mode routing for the official separately installed Windows Packet Filter (NDISRD) driver, using publicly specified device interfaces and independently written code. This does not solve driver runtime acceptance or grant third-party redistribution rights.

Existing **FlowBridge** Rust crates already provide validated profiles, TCP SOCKS5 and HTTP CONNECT, rules, SSH worker pool, diagnostics, and reconnect controls. Reuse these. Windows Win32 UI may remain a thin client of the Rust FFI temporarily; packet interception, owner resolution, state machine, TCP/UDP routing, and driver access must be Rust.

## Useful functional patterns, not source code to translate

| Functional requirement | Upstream reference path at exact SHA | FlowBridge Rust implementation/acceptance |
|---|---|---|
| TCP packet interception with original IP/port retained | `netlib/src/ndisapi/tcp_local_redirect.h` | Independent Rust flow table, checksum/sequence tests, IPv4 and IPv6, fragment policy, half-close/reset correctness |
| Application attribution | `netlib/src/iphelper/process_lookup.h` and `owner_module_resolver.h` | Rust Windows IP Helper API ownership snapshots; correlate 5-tuples and PID+creation time, deny unresolved identities in protected mode, test PID reuse |
| Process matching / protocol rules | `netlib/src/proxy/process_routing_policy.h` | Rust flowbridge-core capture_policy with exact-path selected EXEs; preserve existing Config::evaluate for networks/ports; never silently fall back to Direct |
| Network adapter and routing lifecycle | `netlib/src/ndisapi/queued_multi_interface_packet_filter.h` | Rust RAII worker, bounded packet queues, adapter-change events, cancellation and cleanup before SSH stop |
| ABI/device diagnostics | `ProxiFyreUI/Infrastructure/WindowsPacketFilterProbe.cs` | Rust read-only NDISRD version/status probe; report separate NOT CHECKED signing and NOT ACCEPTED interception fields |
| Configuration safety | `ProxiFyre.Configuration/ConfigurationFileStore.cs` | Rust versioned config, atomic replace, SHA-256 conflict detection, rollback and ACL-preserving install in protected location |
| Verified apply/restart | `ProxiFyreUI/Infrastructure/ConfigurationApplyCoordinator.cs` | Rust state machine: Preflight -> Prepared -> Running -> Stopping, independent observed SCM status, rollback on failure |
| Privileged component security | `ProxiFyre.Configuration/ServiceInstallLocationPolicy.cs` and `PayloadIntegrity.cs` | Rust Windows service with least privilege, protected installation directory, approved config and identity, no arbitrary user-writable executable for SYSTEM |
| Packaging | `ProxiFyre.Bundle/Bundle.wxs`, `docs/installer.md` | Consent-based installation of separate official signed driver with pinned URL + SHA-256, no driver redistribution and no hidden integrity-policy changes |
| Logs and GUI | `docs/gui.md` | Existing FlowBridge Rust event model, bounded log views, truthful state labels, compact Win32/SwiftUI UI |

## Independence and licensing

- ProxiFyre is **AGPL-3.0**. Read published source for research and behavioral specifications, but do **not** copy or line-by-line translate its C++/C# algorithms, structures, source text, iconography or UI.
- No ProxiFyre assemblies, binaries, packages or user-service runtime in the final product. The separately installed Windows Packet Filter driver is the only intended third-party native dependency, subject to its own personal-use terms.
- The new Rust code uses public Windows APIs and NDISRD driver ABI, independently expressed. Before any public distribution, complete a formal dependency/license review. FlowBridge source itself does not yet have a selected open-source license.

## Current code delivered by this branch

- `crates/flowbridge-core/src/capture_policy.rs`: independent exact-executable selection, explicit unknown-owner policy, TCP-ready gating, UDP/other fail-closed behavior with negative tests. It does not claim OS identity attestation or packet capture.
- `crates/flowbridge-ffi/src/windows_packet_filter.rs`: passive, read-only `\\.\NDISRD` version query on Windows. Checks API major 3/minor >= 0x0601 and reports truthful status to native GUI through `fb_windows_packet_filter_status_json`. Does not load/start/install a driver or examine signatures. Non-Windows returns supported=false.
- Existing original custom WFP driver stays excluded from the release path. Experimental WFP source is research-only.

## Mandatory Rust milestones

1. **Preflight:** bind the driver API to a pinned supported NDISRD version, OS service state, real signature/Win10+11 acceptance and vendor installer hash. Refuse installation without explicit owner consent; no Secure Boot/Memory Integrity/Defender changes.
2. **Ownership:** Windows IP Helper TCP/UDP ownership snapshots, PID+creation time, full-path resolution; rapid close, PID reuse, elevated/UWP and owner-unavailable negatives. No synthetic owner may authorize a protected flow.
3. **Traffic:** Rust WFP-independent NDISRD packet receive/inject lifecycle on the vendor driver, with strict bounded buffers and correct TCP v4/v6 local redirect/original-destination tracking, loopback exclusions, checksum and state consistency; route into the existing Rust FlowBridge proxy engine.
4. **Service/GUI:** user-owned SSH remains unelevated, elevated packet service has minimal authorized IPC, validated configuration hash, explicit start/stop, driver state, crash cleanup, and rollback on any uncertain state.
5. **DNS/UDP:** prove per-app DNS and own DoH/DoT boundaries; QUIC either explicitly protected or blocked in protected mode. Merely setting an upstream SOCKS hostname cannot undo prior local DNS.
6. **Installer:** personal Win10/11 NSIS front-end + official vendor-signed NDISRD driver acquisition with pinned checksum/independent Microsoft signature check after install; no auto elevation or bundling restricted vendor binaries.
7. **Native acceptance:** Windows 10 22H2 and Windows 11 with protections enabled, selected/unselected EXE, exact flow identity, IPv4/IPv6, TCP half-close/teardown, SSH death, real DNS/UDP packet traces, resource stress, restart/uninstall, actual DPI. Machine-readable SHA-bound evidence.

**Never infer** kernel activation, Microsoft signature, per-app redirection, DNS privacy, DPI acceptance, or release PASS from a Rust unit test or GitHub-hosted Windows Server 2025 build.

## Upstream evidence

- https://github.com/wiresock/proxifyre/tree/5e3bc845d73a47a0931b1233c745580cb916f4ba
- https://github.com/wiresock/proxifyre/blob/5e3bc845d73a47a0931b1233c745580cb916f4ba/docs/configuration.md
- https://github.com/wiresock/proxifyre/blob/5e3bc845d73a47a0931b1233c745580cb916f4ba/docs/installer.md
- https://github.com/wiresock/proxifyre/blob/5e3bc845d73a47a0931b1233c745580cb916f4ba/netlib/src/proxy/process_routing_policy.h

## Native ownership boundary after independently launched OS PowerShell verification (2026-10-31)

A real native NDISRD RX/rewrite/TCP-return -> Rust relay -> SOCKS/SSH
laboratory path is now measured for four controlled process categories,
including a **separately QA-launched fixed Microsoft-signed PowerShell
process** ([12/12 private native phases PASS](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41218337232),
public code `64118bbbf15d2c0fa2eb5d76c76c2eb36539ef37`).
A previous negative test caught the independent process being falsely
classified **both independent and self-owned**, despite real traffic success.
The original Rust `owner_evidence_flags` correction enforces one-hot or
all-false **lab-only** source-evidence categories, with conflicting/unknown
identities denied. The native test only establishes the precisely prearranged
source socket (read-only pinned process, PID/creation epoch, two IP Helper
snapshots, fixed signed EXE and explicit control GO). Never elevate such an
ownership candidate to general kernel-verified `PacketBound` or arbitrary
selected-app authorization; direct app-level selection still requires a
separately justified OS authority and negative race/PID reuse tests.
Driver mode 0 remains ordinary networking; a crash-safe persistent blocking
mechanism must be independently designed and proven before calling protected
fail-closed or DNS leak-free. The full source, binary, QA digests and remaining
acceptance boundaries are in
[`RUST_CAPTURE_INTEGRATION_CANDIDATE.md`](RUST_CAPTURE_INTEGRATION_CANDIDATE.md)
and [issue #41](https://github.com/i-shutov/flowbridge/issues/41#issuecomment-6545902118).
