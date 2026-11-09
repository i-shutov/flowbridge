# R64 — Corrected R63's critical Winsock ALE endpoint query opcode

Date: 2026-11-09. Exclusive FlowBridge research branch `research/windows-wfp-ale-attribution-20261107`. NOT beta, PR #56, main, PacketBound/G2, release, or a kernel proof.

## Source and immutable baseline

Research HEAD before R64: `65d431d3447d69c253e52cb10708482a5cee9bcb`; main: `5b5afc2feeda2195f302380e615ba003d4906e09`. R63 original Rust source blob `0372c33ea7f658a465e669cb83b7c319d7dccba7`; root AGENTS.md absent. Restriction audit: no drivers, callouts/filters, sockets, network experiments, services, firewall, runner, Defender/SecureBoot/MemoryIntegrity, beta/release/main, automations or other repos modified.

## Concrete functional defect and narrow fix

R63's `SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE` hardcoded **0x48000003**, corresponding to `_WSAIOR(IOC_WS2,3)`, not the ALE query. The correct Windows SDK value is `_WSAIOR(IOC_VENDOR,205)` = **0x580000CD** = **1476395213**. Microsoft-published windows-rs v0.62.2 metadata independently confirms the exact decimal constant:

https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Networking/WinSock/constant.SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE.html

https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls

The Rust-only diagnostic is patched to use `pub const ALE_ENDPOINT_IOCTL_OPCODE: u32 = 0x4000_0000 | 0x1800_0000 | 205`, including a cross-platform regression unit. The default main does not run Winsock or BFE. No network socket or policy API executed. This corrects a *source-level functional defect*, not a measured Windows call failure or leak.

## Deterministic verification

Python offline suite: **14/14 PASS** (included in independent local checkpoint), checks source opcode, regression invariant, x64 struct layout, no-call default, failure branches and kernel-identity counterexamples. Independent Node oracle `r64/r64_independent.mjs` is published here. Both enumerate **4096** synthetic cases with identical ordered-decision SHA-256 `3f1587cc3810aaf9f6026c7109147d3d98b043749ba819b68641ac7f5ea8118f`: 2048 UNOBSERVED (never assumed BLOCK), 2044 invalid, 4 endpoint-only, 1 hypothetical original-owner+kernel-join case. The hypothetical join does NOT exist in this PoC. Rust unit tests remain UNEXECUTED: rustc/cargo and Windows SDK unavailable.

## Exact API and trust boundary

`WSAIoctl(SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE)` maps an **already owned queried SOCKET** to a transport endpoint ID. `FwpmEngineOpen0` and `FwpsAleEndpointGetById0` can query endpoint properties, including that endpoint's AppId, IPv4/IPv6 and protocol. There is NO documented PID+creation epoch+canonical EXE, original AUTH_CONNECT witness, redirect-record provenance, or kernel-attested accepted socket→CLAIM join in these properties. `WSADuplicateSocket`, re-used 5-tuples, process death/reuse and sibling DIRECT do not improve this evidence. DNS/UDP/QUIC and WFP/SSH loss remain separate unproven conditions. AppId/endpoint ID is not a cross-layer authentication credential.

Sources: https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/nf-fwpsu-fwpsaleendpointgetbyid0 ; https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_ale_endpoint_properties0

**Unresolved API-lifetime/allocator blocker:** R63 frees a `FwpsAleEndpointGetById0` result using `FwpmFreeMemory0`; Microsoft's documented `FwpmFreeMemory0` use covers `Fwpm*` allocations. A distinct `FwpsFreeMemory0` export exists, but no allocator pairing was independently confirmed in this cycle. Do NOT execute this optional probe on Windows before resolving allocation ownership and ABI using official Windows SDK documentation.

https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfreememory0

## Decision and next decisive experiment

**GO (scope only):** corrected static read-only SOCKET→endpoint diagnostic constant. **NO-GO:** executing or enabling this optional probe, claiming original-owner/kernel-origin attribution, PID liveness, no-DIRECT/leak-free, PacketBound/G2 or native Windows success.

**R65:** verify the SDK-defined allocation/free contract for `FwpsAleEndpointGetById0` and perform compiler-only Windows x64 FFI check if rustc/SDK is available, with no socket activity. If allocator ownership cannot be established, quarantine the diagnostic. Separately seek official kernel proof of original AUTH_CONNECT socket→accepted socket join; otherwise close endpointId-as-CLAIM.
