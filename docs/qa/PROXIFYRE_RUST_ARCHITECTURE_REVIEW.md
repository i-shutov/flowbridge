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


### 2026-11-02 — Exact SHA-pinned official portable NSIS dependency for both Windows installed-product acceptance tracks (CI PENDING)

At source `aeea41636c4ee6a3e8b99917bd103ef4ccd8d162`, the required Windows capture and legacy/native installer jobs FAILED before entering the new persistent WFP lab: the Chocolatey community NuGet V2 endpoint returned HTTP 503 twice. The capture gate remains **FAIL (not tested)**, and no persistent-WFP PASS, installed candidate verification, or accepted artifact can be inferred from earlier Rust-native/DNS successes. The independent OpenSSH load gate is separate; raw 512 has not been established.

The next integrated PR #56 candidate replaces the single-point Chocolatey dependency **in both** `.github/workflows/capture-integration.yml` and `.github/workflows/ci.yml` with a checked-in original PowerShell helper `scripts/ci-setup-nsis.ps1` restricted to `RUNNER_ENVIRONMENT=github-hosted` Windows. It retrieves the **official standalone NSIS v3.13 portable ZIP** from SourceForge, enforces the exact vendor-published SHA-256 `ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8` and actual `makensis /VERSION=v3.13`, and emits compiler provenance into both Windows QA artifact trees. The build tool is **never packaged into the FlowBridge candidate**, never installed into the paid VPS and never enables driver mode or changes Windows security. Mismatched/unavailable ZIP, wrong compiler or unexpected host remains a **hard failure**, not a skipped installer test. Official downloadable ZIP metadata is at https://sourceforge.net/projects/nsis/files/NSIS%203/3.13/nsis-3.13.zip/download .

**Pending strict gates:** real installed-product/fault recovery; persistent one-EXE/high-port WFP rule after guard crash with independent SYSTEM rollback, TCP/UDP IPv4/IPv6; exact-head 3/3 capture, 5/5 Rust/native, 3/3 DNS, separately 128/1152/10000/4 real OpenSSH, test-merge SHA and independently downloaded artifact / PE SHA-256. None of these is equivalent to arbitrary NDISRD packet→PID attestation, protected native fail-closed, DNS leak-free, Windows 10/11 acceptance, or release. No `main` modification or signed/unsigned product publication authorized.


### 2026-11-02 — Exact code SHA VERIFIED: hosted original-Rust persistent AppId/high-port crash-survival, independent SYSTEM recovery

**Functional source** `5a2db4d66fde8a28e27fe394b67b7e18430a1edb`, GitHub PR test-merge `cc1569b688a1df01c858ce9bd046965d06b5e0b0`, base `5b5afc2feeda2195f302380e615ba003d4906e09` unchanged. The previous CI-PENDING sections above are historical and are superseded for **this exact code SHA** by [capture Actions #41379171590](https://github.com/i-shutov/flowbridge/actions/runs/41379171590) **3/3 PASS**, [Rust/native #41379171757](https://github.com/i-shutov/flowbridge/actions/runs/41379171757) **SUCCESS** and [DNS #41379171625](https://github.com/i-shutov/flowbridge/actions/runs/41379171625) **SUCCESS**. Separately [managed OpenSSH #41379171674](https://github.com/i-shutov/flowbridge/actions/runs/41379171674) remained *in progress* at this checkpoint; do not inherit historical 10k PASS. Raw 512 was separately negative (246 peak held).

**Actual Windows Server 2025 hosted WFP report:** Independently extracted `windows-wfp-persistent-hosted.json` has `passed=true` and **all 15/15 strict checks true for each** `tcp4`, `udp4`, `tcp6`, `udp6`: preselected/sibling/Python allowed; independently prearmed elevated SYSTEM rescue; persistent BFE filter+AppId high-port readback; selected copied Rust executable DENIED and absent from real loopback receiver; differently named byte-identical Rust executable and independent Python allowed; guarding process forcibly killed; filter still present, selected still denied and sibling still working; exact filter/sublayer removal; selected transport recovered; rescue disarmed only after cleanup. This is *crash survival of a narrowly scoped experimental persistent WFP filter*, **not** production protected mode or blanket network denial. Its active temporary rule is never created on VDSina self-hosted runner.

**Independently downloaded Windows artifact #13113090988:** outer 23-entry ZIP SHA-256 `b60b351a92e033c6829b329909bd899db37adb958d2810e6a8fb3a12ce6975f7` equals GitHub digest; inner exact five-file original-Rust candidate SHA-256 `cdb072b358aaf7522fa30eeae456fe28cf0224507e1b7bab47ebe22f490fc6e2` matches independent sidecar. Nested manifest binds source and test merge, all payload hashes independently checked. Three PE32+ AMD64 SHA-256: agent `a9ea52911693022ca3d64c6148a5a16be6a4a02aa11648602effe57743d2a3aa`, CLI `fac163b40b099707c091a2bd0b2c575d80edd629d0128500de1fe03d1dc7ab54`, panel `57ee097070bce2ac51db664c26b55b72974bf044f4cc10040395d3331d2d7edd`; unsigned NSIS setup `64f44db9c414cdb6c26e3955743f630c6861b4c65a0ad79d1835242e82b5ac99`. Actual installed GUI→IPC→authenticated OpenSSH/SOCKS, two fault-injected NSIS rollback scenarios, recovery and uninstall passed. The SHA-pinned official SourceForge NSIS 3.13 ZIP `ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8` contains a root wrapper and the real `Bin/makensis.exe`; CI now strictly verifies the latter, its include/stubs resources and version, without relaxing installer QA. Neither NSIS compiler, vendor NDISRD, ProxiFyre, private keys nor legacy C++ WFP helper enter Rust candidate. Full checkpoint [issue #41](https://github.com/i-shutov/flowbridge/issues/41#issuecomment-6567876243).

**NON-CLAIMS / REQUIRED NEXT GATES:** tests are GitHub-hosted **Windows Server 2025** not personal Win10/11 x64, and operate on ONE QA EXE and ONE HIGH LOOPBACK PORT. They do NOT prove general native NDISRD packet→PID+creation-epoch ownership, WFP↔NDISRD order or active driver bypass, SSH-failure/service crash systemwide protected fail-closed, arbitrary app DNS/DoH/UDP/QUIC/IPv6 leak-freedom, or release 1.0. The signed NDISRD native VPS trials in private issue #1 were on earlier pinned source SHAs; the VPS was not touched in this block and remains useful for an independently rescued driver/WFP ordering trial. The docs-only checkpoint itself makes no new native execution claim.


### 2026-11-02 — SIGNED VDSina NDISRD + original-Rust WFP coexistence and copied-packet owner sampling (exact \`d4ab8d7\`)

These are **two separate, real Windows Server 2025 native experiments on the exact audited public source HEAD \`d4ab8d7eb20ed1aee9161bcf6e5afd63207aff02\`**, test-merge \`d35dec9b85db1d83ea27c306860f596c24692e5e\`, agent PE SHA-256 \`0d712d1363320b410b6fcf4f71e0b7f8c1c0d604f3196bc79076fee64c272729\`. They are not new Windows 10/11 acceptance, nor proof of WFP/NDISRD packet ordering.

1. **Signed driver loaded + disposable selected-only WFP IPv4/TCP coexistence, actual local sockets — PASS.** Private restricted QA commit \`448dbfd773cbf1b82abee30033bed2d2a47d5e6c\`, [run #41392042494](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41392042494), [private evidence #1](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6569565712). Exact signed running NDISRD driver SHA-256 \`8623a9c34531cf73de4286ad518b84af03a331c78959769a1ca38723e3258984\`; Defender and firewall remained enabled. **13/13 actual strict assertions**: selected EXE denied by live BFE dynamic AppId filter; byte-identical differently named sibling and independent .NET socket client allowed; blocked packet absent at receiving loopback socket; forcibly killed WFP guard caused access to recover. No persistent WFP object, no driver mode change and no NDISRD packet interception. Independently downloaded **3-file** native artifact #13118017261, outer ZIP SHA-256 \`4dc56b6717cdee7bbaff042e780b8af6a00f763981064fc8d32213ab8c57d6c7\` matches GitHub digest; JSON reports \`passed=true\`, \`wfp_ndisrd_order_proven=false\`.
2. **Real signed NDISRD native RX in bounded LISTEN_BOTH copy-only + IP Helper candidate correlations — PASS for observation, explicitly NOT PacketBound.** Private QA fast-forward commit \`6d75416f82082a8977fae6cdcb9ab801f3f05baf\` in existing private QA integration branch, [run #41392989022](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41392989022), [private report #1](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6569663954). Pinned five-file hosted Rust candidate ZIP SHA-256 \`9a0d3a59b7df7d0d05873d396c3a3d5fba6e8e0181e6be10d70d7aeef069fee5\` plus all four manifest payload hashes verified on the native host BEFORE any driver mode change. Exact official signed kernel driver and Defender gate, active firewall, unique native adapter, signed-MSI hash gate, independent **SYSTEM rescue task armed before mode I/O**. A bounded **6.503 s** real NDISRD listen-only trial observed **26 Ethernet packets: 12 outgoing and 14 incoming**, and made **24** bounded IP Helper candidate queries (**18 consistent snapshots; 4 missing; 2 indeterminate**). **Zero reinjected packets**, zero persisted payload/identity/endpoints, process exit code 0. Native adapter mode rollback confirmed; independent rescue task disarmed only following verified network recovery and active Defender. Independently downloaded one-file artifact #13118595210, ZIP SHA-256 \`df82a634131217f1e29358d441395b518139d970cb9e60e3cdb1e3486ebad780\` (matches GitHub published digest), inner \`listen-only.json\` SHA-256 \`cf4b12b54c07019f67d03ab435cab1ac1946bebefb0852ffdab5f243197870bb\`.
3. **Release/security gates still OPEN:** IP Helper two-snapshot correlations are **NOT packet→PID+creation-epoch authorization**; LISTEN-only canary does not demonstrate production interception, selected-app TCP rewrite, protected fail-closed, DNS/DoH/UDP/QUIC/IPv6 leak containment, or WFP/NDISRD ordering under simultaneous packet diversion. Hosted/private Windows Server 2025 does not substitute for native Win10/11. The restricted live driver mode returned to 0, which again permits ordinary DIRECT traffic, not a protected-denial state. Raw OpenSSH 512 remains FAIL (last exact code peak ~244); managed 128/1152/10,000/four independent workers independently PASS on \`d4ab8d7\` only. No main merge, signed third-party redistribution, security-protection disabling or release authorization. VPS #3293462 was used for this bounded trial and remains useful for ordering research with independent rescue; it cannot be retired solely on this outcome.

*The parent code SHA and artifact checks above belong to the prior reviewed source; this documentation-only commit requires its own CI and does not silently inherit a new executable SHA.*

## 2026-11-02 — Experimental WFP↔NDISRD TEST-NET UDP observation harness (ORIGINAL CANDIDATE; VERIFIED TRIAL BELOW)

An original Rust copy-only NDISRD LISTEN_BOTH canary profile now accepts exactly two distinct ephemeral UDP ports and matches only outbound IPv4 frames addressed to fixed RFC 5737 TEST-NET `198.51.100.53`. It rejects fragmented or truncated transport headers and reports only aggregate first/second counts; independent Rust QA executable copies can emit exactly two bounded datagrams each. A VPS native orchestration must prove **positive baseline selected and sibling frames, WFP dynamic AppId-specific denial of selected while sibling frames remain visible, and restored selected frames after guard death**, under a previously armed independent SYSTEM rollback and signed-driver/Defender/firewall preflight. The ports are only controlled correlation hints: no packet→PID or WFP/NDISRD general ordering claim follows from read-only counts alone; absence without positive controls is INCONCLUSIVE. This change cannot activate divert, process-wide policy, DNS leak freedom or protected mode. All binaries/manifest/CI exact HEAD and real native trial evidence are pending; do not promote to Windows beta or release. Prior signed-driver native LISTEN-only evidence remains pinned to `d4ab8d7...`.

## 2026-11-02 — VERIFIED signed NDISRD LISTEN-only + real WFP dynamic AppId-deny TEST-NET ordering canary (NARROW native PASS)

**Reproducible exact provenance.** The original Rust experiment is source PR #56 HEAD `0039a528a20a211b1a720c7b482ad70b497ab364`, official GitHub PR test-merge `61fa455229601e8bd1e2d277c9dc015eb4d9f109` (parents main `5b5afc2f...` and that HEAD). [Hosted capture CI #41398902923](https://github.com/i-shutov/flowbridge/actions/runs/41398902923) 3/3 PASS, [Rust/native #41398903004](https://github.com/i-shutov/flowbridge/actions/runs/41398903004) 5/5 PASS, [DNS #41398902871](https://github.com/i-shutov/flowbridge/actions/runs/41398902871) 3/3 PASS. These CI runners are **Windows Server 2025 / macOS / Linux**, NOT personal Windows 10/11 evidence. Independent downloaded Windows capture artifact #13120398882 is exactly 24 files and SHA-256 `3ebb24951d547a0cfd749b17cd6b93d68e8fe8695821a5724715d6b317f355c5`, equal to GitHub digest; nested five-file Rust candidate SHA-256 `6a8924c3b2c1044c7f645c29e0b29ec71c985e38496750a9d0cc36609a6db25c`, original PE32+ x64 agent SHA-256 `3de9f24531a424ac237fbd853a1ea9bf3220e997a7d7deab54da9999e572314a`, CLI `3e6a2dcdb508c4bbf8236b6e5dc608a7293b2f2dbd078ad71f93ccf2b0798723`, panel `bb42b20af26ee0b176947130db091a8f53ffb8a0f319ad2f7aad666a7dcf859b`, unsigned NSIS `5dc7f40ab14fccfc29aaaffe3efc9c3c9f7898e483f770044b45e4bf3bcf7a1f`. Manifest, sidecar and payload hashes independently compared; no vendor driver, ProxiFyre, C++ WFP sidecar or secrets in candidate.

**Real independent native ordering experiment.** Private `i-shutov/flowbridge-vps-qa` workflow HEAD `e2eb165d1804df8ca21f6e2c7d9e0d656644bcee`, [real VDSina Windows Server 2025 run #41400224489](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41400224489), [private issue #1 evidence](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6570697616) **PASS**. The exact verified agent was run with separately installed Microsoft-signed official NDISRD driver SHA-256 `8623a9c34531cf73de4286ad518b84af03a331c78959769a1ca38723e3258984`, active Defender and all firewall profiles. Two byte-identical original Rust EXE copies with different filenames generated 2 UDP datagrams each to the fixed documentation-range IPv4 and two distinct high UDP destination ports while the actual signed NDISRD listened in copy-only `LISTEN_BOTH`. Counts were:

| Phase / actual NDISRD outbound observation | Selected QA EXE | Sibling QA EXE |
|---|---:|---:|
| WFP rule absent, positive baseline | 2 | 2 |
| Dynamic BFE AppId + UDP-port BLOCK for selected, verified BFE readback | **0** | **2** |
| Guard process forcibly killed (dynamic filter removed) | **2** | **2** |

Each of three bounded NDISRD sessions returned mode to ordinary network (explicit Rust IOCTL readback / rollback PASS); **zero original packets reinjected**. Independent locally scheduled SYSTEM MSI-uninstall rescue was armed before the first adapter mode change and disarmed only after all three successful rollbacks, confirmed signed driver, active Defender/firewall, native status and working network. No dynamic filter persisted. No IP, port, PID, binary path, payload or private identity entered evidence. Independently downloaded single-report private artifact #13120998070 outer SHA-256 `933debb651a445fa0887358459d5a3f2798026a362269e3a13e910607e08ad07` equals GitHub digest, inner `wfp-testnet-ordering.json` SHA-256 `694b4bbb0f67535ff2ed1eeeaadfadc0076f7fcb37780c9574ad394c5f5b6bc9`, JSON keys unique and strict values independently checked. Earlier private #41399993406 demonstrated same 2/2 → 0/2 → 2/2 but had a *report-field naming mismatch*; corrected evidence is pinned **only** to #41400224489.

**What was actually proved and NOT proved.** In this narrowly controlled outward TEST-NET IPv4 UDP experiment, a real selected-app WFP AppId/port block prevented the selected canary's frames from appearing in an NDISRD **copy-only** observation while sibling frames continued, and killing the dynamic guard restored selected frames. This is a strictly bounded empirical WFP-deny/NDISRD-observer interaction, **NOT** a general WFP/NDISRD ordering guarantee with driver DIVERT, arbitrary packet→PID+creation epoch, or selected-app SOCKS redirect. A tuple/port match is NOT identity authentication. The host was **Windows Server 2025**, not Win10/11. Returning driver adapter mode to 0 permits ordinary network/direct; it is NOT protected fail-closed. No DNS/UDP/QUIC/DoH/IPv6 leak-free acceptance, crash-persistent full product denial or release approval.

**Real OpenSSH on same exact source/test-merge:** independently downloaded [managed run #41398902890](https://github.com/i-shutov/flowbridge/actions/runs/41398902890) artifact #13120534787, SHA-256 `b7fbac9d53faac4703b78175da949405fad033c716318e26885c5de3c2663e6c` equals GitHub. Managed **128 held, 1152 rejected, 10000 verified successful/0 failed churn, 4 independent supervised OpenSSH processes PASS**. Separately, raw artifact #13120841872 SHA-256 `9683be67839c5f426899f2e4c857b46a4e3a8ef7ef469d3af21799e6b187324a` confirms **FAIL at 244 held**, `WinError 10054`; stable raw 512 is explicitly unproved. No weakening of the existing capacity/regression gates.

**Next native release gate:** independently attest process ownership/creation epoch, connect actual NDISRD redirect/TCP reverse traffic to selected Rust-owned process through local relay→SOCKS/SSH, provide persistent lifecycle fail-closed including driver/service/SSH crash/restart and DNS/UDP/IPv6 negative tests, then native Windows 10/11 x64 sign/installer/upgrade/uninstall acceptance. VPS #3293462 remains useful for these controlled signed-driver experiments; do not delete without owner's instruction. Public PR #56 only; main/release untouched.
