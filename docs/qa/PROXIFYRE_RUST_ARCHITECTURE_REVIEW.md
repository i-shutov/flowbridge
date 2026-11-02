## 2026-11-02 — Native WFP AppId canonicalization root-cause evidence

Exact source `f0e119623899893ce0e46e8137aef5d38c9a1d86` / CI merge `17c0e0f4b178d15a919bf2d9002c0292dc2a4a4d`.
The real Windows Server 2025 temporary BFE filter ID produces exactly
three CLASSIFY_DROP events on each of two local TCP destinations.
Python executable AppId matches its process event **byte-for-byte**;
both copied Rust executable AppIds match kernel event executable
**basenames** but NOT full AppId BLOBs from path lookup. App-only and
App+port WFP block remain ineffective, port-only really blocks.
This makes full-path canonicalization and NT volume aliasing a concrete
research hypothesis, NOT a per-app protected policy or packet-PID proof.
Real installed Rust GUI/SSH and NSIS/SCM tests pass; managed OpenSSH
10000-churn failed this exact SHA with WinError 10048 after 1654
completed; raw 512 remains unproved. Byte-level 19-entry ZIP, nested
five-entry Rust archive, three PE x64 and unsigned NSIS SHA verified.
See `RUST_CAPTURE_INTEGRATION_CANDIDATE.md` and [issue #41](https://github.com/i-shutov/flowbridge/issues/41#issuecomment-6564380435).
No vendor driver/host-security change, no Win10/11 acceptance or
release authorization.

## 2026-11-02 — Research constraint: actual WFP identity must be cross-correlated

The transient original-Rust WFP AppId filter remains unable to deny a
selected copied executable on hosted Server 2025 even though BFE readback
matches its requested AppId and port-only ALE denial succeeds. A fresh
read-only exact-filter-id event provenance check now compares live OS BFE
event AppIds with selected, other, supervising Rust agent and Python client
as separate identities, including in-memory normalized path-shape metrics.
This is diagnostic only, never a packet-to-PID or protected routing authority.
See RUST_CAPTURE_INTEGRATION_CANDIDATE.md. Permanent WFP, custom WFP
drivers and premature release/protected/DNS assertions remain prohibited.

### 2026-11-01 — Exact-filter WFP event diagnostics, not a packet identity token

Port-only WFP classification on actual hosted Windows produced three BFE
events that lacked a matching per-EXE AppId derived from filenames, but the
initial diagnostic compared only the TCP port and might have counted another
rule's events. The stricter original Rust laboratory probe binds
\`FWPM_NET_EVENT_CLASSIFY_DROP0.filterId\` to a still-active, dynamic, scoped
guard, compares its live BFE registration against the expected QA
sublayer/layer and emits anonymized aggregate identity counters. The transient
filter ID is not logged. Collection absent => INCONCLUSIVE; even a positive
exact-filter event is **not** an NDISRD packet-to-process credential, protected
crash-persistent deny, DNS privacy or Win10/11 acceptance. Existing observed
AppId enforcement failures stay strictly failing until a real selected client
is blocked and the two controls are not.

### 2026-11-01 — Cold-start integrity of the signed OS-process QA canaries

A hosted Windows CI run failed before entering the strict AppId diagnostic
because the signed PowerShell canary did not report its reserved socket within
eight seconds. The fixture now has a shared bounded 20-second pre-GO readiness
reader, validates live-process and actual port readiness, retains negative
no-GO/REJECT TCP checks, and logs only a sanitized failure class. This is
**QA harness reliability**, not a WFP identity, NDISRD interception, protected
fail-closed or native personal Windows acceptance result; see the candidate
QA journal for the exact source/test-merge and pending CI evidence.

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

### SSH middlebox hypothesis: diagnostic only
The opt-in original Rust `flowbridge ssh-diagnose` uses two direct TCP identification-order probes and never enters production SSH supervision, DNS, packet/driver path or protected fail-closed. Until the user's affected route is A/B retested, server-first is not an accepted production workaround; no transparent DIRECT fallback may be introduced.


### IPv6 UDP original-Rust bounded driver lab (2026-11-01)

The independent `udp6_quarantine` unit has a fixed RFC 3849 IPv6 target
and a caller-validated non-link-local source. An exact IPv6 L2 match drops
all upper-layer forms (including fragment/extension-header forms) rather
than mistaking the first Next Header for UDP. This avoids an IPv6 fragment
bypass in the **self-owned** canary, at the cost of deliberate same-pair
overblocking. No real NDISRD IPv6 packets, arbitrary PID attribution,
crash-persistent containment, DNS privacy or personal Win10/11 acceptance
are inferred from offline tests; see the candidate QA log for native proof.

## Accepted read-only WFP/BFE visibility does not prove protected fail-closed (2026-11-01)

On PR #56 code `9fbb3c16398594df938ab36e95a84175715abbb6`, test merge `92c640d05bec036ea881414a6afb5727a272691a`, an original Rust bounded `FwpmFilterEnum0` enumeration succeeded in a hosted Windows Server 2025 real TCP test. All three BFE snapshots observed 648 accessible filters while a separate socket's bytes survived. This confirms **enumeration API availability and safe coexistence with ordinary TCP only**, not filter enforcement, packet/PID attestation, native WFP→NDISRD ordering, crash-persistent blocking, or Windows 10/11 acceptance. See `RUST_CAPTURE_INTEGRATION_CANDIDATE.md` and [issue #41](https://github.com/i-shutov/flowbridge/issues/41). Next safe P0 design experiment requires explicit VNC recovery, independent SYSTEM rollback and a testable allowlisted selected flow; no custom WFP callout or silent firewall changes.


### 2026-11-01: WFP AppId lookup consistency is NOT network classification proof

Real hosted WinServer 2025 dynamic WFP QA on exact PR #56 code `433ad39ffe2ddb6042c54cbcfefc13488709d8f3` shows path-derived AppIds are internally consistent across a selected byte-identical Rust executable and two separately located copies: the target reports equality; other locations report inequality. Yet the actual ALE_AUTH_CONNECT_V4 AppId-only and AppId+port filters still do not block that selected EXE while the same dynamic sublayer **does block all processes** using the one ephemeral port-only control. Launching the guard from the same executable path did not change the negative finding. This is evidence of **unproven runtime AppId classification**, not a successful per-EXE firewall, native packet ownership, WFP/NDISRD ordering or persistent fail-closed. See [complete SHA-bound negative checkpoint](RUST_CAPTURE_INTEGRATION_CANDIDATE.md) and [Windows run](https://github.com/i-shutov/flowbridge/actions/runs/41335859787). Do not promote either the port-only test or the current user-mode AppId comparison to protected-mode authority.


### 2026-11-01: WFP AppId classification — independent local-interface route diagnostic

After exact hosted-Windows real-TCP WFP AppId filters failed on 127.0.0.1 while a TCP-port-only control enforced, the next original-Rust QA experiment uses an independently bound **host-owned non-127 IPv4** address and disposable TCP server. The client refuses IPs it cannot itself bind locally, preventing an arbitrary external destination. This distinguishes pure 127/8 behavior from host-interface local delivery; it **does not** prove physical NIC traversal. Five original loopback assertions and the additional local-interface controls remain strict, dynamic, killed-guard recovery must hold, and filter registration without actual denied connect is never accepted. No WFP/NDISRD ordering, persistent crash protection, kernel PacketBound owner authority or leak-free DNS/UDP/IPv6 can be inferred. See the exact-source CI checkpoint in `RUST_CAPTURE_INTEGRATION_CANDIDATE.md`.

### 2026-11-01: BFE AppId diagnostic evidence boundary

A disposable original-Rust WFP laboratory now verifies a registered filter's
**actual BFE read-back**, including AppId BLOB, matched conditions and type,
then queries bounded read-only existing network events for OS event AppIds.
The event lookup never enables audit collection or stores sensitive event data.
Either successful BFE serialization or an observed event AppId is distinct
from a proven kernel ALE AppId match, packet-to-PID authority, persistent
fail-closed or Windows 10/11 acceptance. Existing live failures still block
release. See the precise QA acceptance/evidence in
`RUST_CAPTURE_INTEGRATION_CANDIDATE.md`.

### 2026-11-02: handle-canonicalized WFP AppId QA (not production enforcement)

The original Rust dynamic WFP lab now uses a file-handle-resolved DOS final
path for its disposable AppId condition and compares the BFE event's live
AppId to the native NT-volume final path. An independent
`QueryFullProcessImageNameW(PROCESS_NAME_NATIVE)` of each actually running
QA client is compared in memory with its opened file image. Only sanitized
boolean/count results leave the process. Windows Server 2025 CI must **prove**
a selected-only real TCP deny, independent application allow, and crash
cleanup before this experimental AppId path can be considered functional.
It cannot establish arbitrary packet ownership, persistent fail-closed or
Windows 10/11 native acceptance. See the exact code/CI/ZIP evidence in
`RUST_CAPTURE_INTEGRATION_CANDIDATE.md`.

### 2026-11-02 — Verified native transient WFP AppId DENY (Windows Server 2025 QA, not protected mode)

Functional source `a45cab065da98f6bd220584c246b815076b05d7f`
(merge `01faf2b6b573fb32f3049d7473c8c3e33f717379`) passes the real
selected-only, independent-other/Python-allowed WFP dynamic BFE filter
matrix on both 127.0.0.1 and host-owned non-127 local IPv4 in
[Windows capture #41359888484](https://github.com/i-shutov/flowbridge/actions/runs/41359888484).
The app-only and app+port guards now derive AppId from the actual
file-handle canonical final DOS path. Exact live BFE filter-ID drop events
match handle-canonical AppIds and native paths for both Rust EXE copies.
Original DOS spelling does not match; the independent running-process
native image-vs-handle comparison remains unequal and not authoritative.
Downloaded outer Windows artifact SHA256
`31b56299c6a1f964f16d2456b6f30d23b26e1c65a53655c6b406df56eae1fe0f`
matches GitHub; full nested PE/NSIS provenance is recorded in the
`RUST_CAPTURE_INTEGRATION_CANDIDATE.md` checkpoint. The dynamic QA
guard is NOT persistent crash fail-closed; general NDISRD packet→PID,
DNS/UDP/IPv6 privacy and Win10/11 acceptance remain unproved.


### 2026-11-02 — WFP selected-application UDP/IPv4 localhost experimental integration (AWAITING CI)

The original Rust dynamic BFE AppId guard now has a distinct **high-port
UDP/IPv4 only** laboratory consent, and a real Rust UDP canary. A Windows
Server 2025 acceptance gate creates two byte-identical, differently named
executables and an unrelated Python UDP client; it requires healthy unfiltered
controls, a BFE-read-back-verified **real selected-only UDP denial** without
delivery to the real UDP listener, simultaneous sibling/Python success,
then immediate restoration after forced guard death. All paths, process
identity, filter identifiers, addresses and packet contents are omitted from
the report. TCP and existing SCM/GUI/SSH tests remain mandatory.

This uses a *dynamic* ALE_AUTH_CONNECT_V4 AppId+UDP protocol+ephemeral port
filter. It is NOT a system DNS/53 policy, not leak-free DNS, not native NDISRD
UDP or packet-to-PID proof, and does NOT survive the guard process crash.
The test must stay red until live Windows kernel enforcement is observed.
No persistent WFP policy, system resolver, Defender, packet diversion,
external route or Win10/11 release flag changes. Exact-head CI and artifact
hashes are required before recording PASS.


### 2026-11-02 — Native Windows IPv6 dual-protocol WFP lab integration (CI PENDING)

New original Rust disposable `ALE_AUTH_CONNECT_V6` AppId+high-port guards and `::1` socket probes for **both TCP half-close and UDP echo**. Strict Windows CI must see selected EXE denied, identically copied different-name EXE and independent Python allowed, no selected packet/connection at real server, and full selected recovery after forced guard-process termination; no skips when IPv6 loopback unavailable. BFE filter readback validates exact V6 layer, AppId and protocol. No NDISRD, protected persistence, DNS resolver, general arbitrary packet PID ownership, real Win10/11 acceptance, or release claims. This checkpoint is **unverified until exact HEAD CI and artifacts finish**.


### 2026-11-02 — Original Rust crash-persistent WFP single-EXE high-port QA (CI EVIDENCE PENDING)

On disposable **GitHub-hosted Windows 2025 only**, a new exact-consent Rust
BFE experiment uses an independently prearmed elevated SYSTEM Scheduled Task
(three-minute rescue) before creating a persistent AppId+protocol+single high
port rule for one temporary copied Rust test EXE. It tests four real socket
paths (TCP/UDP × IPv4/IPv6): selected-only denial, byte-identical sibling
and independent Python allow, guard-process forced death, **continued
selected denial after guard exit**, explicit independent Rust cleanup and
full recovery. BFE readback must confirm the persistent rule/sub-layer.
The rules are never created if the host is self-hosted, the rescue is absent,
the selected EXE is outside RUNNER_TEMP, or the port is not high. On failed
cleanup the independently scheduled task must remain in place. No vendor
driver, keys, global firewall, SSH server or Defender setting is modified.

This is an experimentally persistent **one-EXE, one-port canary**, NOT
protected production fail-closed after SSH/service/NDISRD crash. It does
not bind arbitrary packets to PID, validate WFP/NDISRD order, prove DNS
leak-freedom or constitute native Win10/11 acceptance. Do not execute it
on paid VPS #3293462. This section is NOT a PASS until a full exact-SHA
Windows CI execution, native JSON report, test-merge SHA and independently
audited binary/artifact hashes confirm the strict functional matrix.
