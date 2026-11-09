# R63 — Rust read-only ALE endpoint diagnostic, no original owner proof

Date: 2026-11-09. Only i-shutov/flowbridge branch research/windows-wfp-ale-attribution-20261107. No beta, PR #56, main mutation, driver/filter, networking experiment or release claims.

## Verified baseline and boundaries

Fresh research HEAD before R63: d3087011df913423bfd7c810fa1c6254ad5ec717; main: 5b5afc2feeda2195f302380e615ba003d4906e09. Read research/wfp-ale/README.md, R62 and actual kernel-r19 Rust files. Source blob identifiers: lib 0af6d4539673d2894cbaa91af0ea8f3524862a26, redirect 9a07e026134d46ef646d39862bd982cc48bbc5f6, handoff e1d17217db50362ba9c4efc83af820b6beb094cf, broker 16ec8853d322b40f0e00e14d49ae3410741b9395. Root AGENTS.md not present on research HEAD.

## Documented Windows APIs

1. Read-only WSAIoctl(SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE) of an ALREADY OWNED Winsock socket returns a UINT64 transport endpoint handle; verify exactly eight output bytes. This identifies the queried socket's ALE endpoint, not the historical original client. Microsoft: https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls
2. User-mode FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &handle) requires FWPM_ACTRL_OPEN and an available BFE; FwpmEngineClose0 closes this session. Both APIs can be used without creating filters. https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0
3. User-mode FwpsAleEndpointGetById0(engine, endpointId, &properties) returns DWORD, fwpsu.h/fwpuclnt.lib. Properties include endpointId, IPv4/IPv6 address/ports, protocol, appId, token-modified ID and IPsec fields. They do NOT include original PID, process creation epoch, canonical image proof, original AUTH_CONNECT classify handle, redirect-record provenance or a kernel-attested accepted socket. https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/nf-fwpsu-fwpsaleendpointgetbyid0 and https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_ale_endpoint_properties0
4. WFP-allocated property memory requires correct release; this clean-room prototype uses FwpmFreeMemory0 on the returned allocation and RAII for the BFE session. Windows build/native execution is NOT VERIFIED. https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfreememory0

## Delivered executable offline material

- r63/r63_endpoint_probe.rs: std-only clean-room Rust; raw Windows x64 FFI with no driver; diagnostic function borrows an existing TcpStream and creates no sockets. main() invokes no Winsock, BFE or networking function. Eight Rust unit tests are present but **NOT EXECUTED**, because this isolated executor lacks rustc/cargo, Windows and Windows SDK. Windows x64 ABI offsets were checked only via host ctypes; native validation is still pending.
- r63/r63_negative.py: 10/10 Python tests PASS. r63/r63_independent.mjs: independently implemented Node oracle PASS. Exact equality of all counters and ordered SHA-256 of all 65,536 synthetic state decisions d52dbcb30622ef8e55e5f83d8a155c1c32b5b0047e6f716d5b2f3326c1c4c154.
- Counts: 32,768 UNOBSERVED callback-absent (NOT BLOCK), 32,752 invalid diagnostics, 16 complete endpoint-only observations, one counterfactual fully attested state (not a real Windows capability). Among 16 weak observations, 8 lack original-owner match, 8 lack record join, 8 may be physically dead but not yet observed as dead.
- Counterexample: states 4095 and 65535 are indistinguishable by available socket-endpoint diagnostic but differ in four hidden truth variables (original owner, epoch, record join, physical life). A user-mode endpoint query cannot resolve that ambiguity by comparing AppId/PID/5-tuple.

## Architectural decision

Narrow conditional GO for a compile-only user-mode read-only diagnostic design. NO-GO for kernel-origin owner attestation, original AUTH_CONNECT join, kernel CLAIM socket binding, selected sibling DIRECT, process death/reuse, TCP IPv4/IPv6 physical egress, DNS/UDP/QUIC, WFP/SSH failure, PacketBound/G2 or leak-free. Book::take currently accepts a 128-byte broker-supplied context without a kernel-verified accepted SOCKET identity. EndpointId passed as a number cannot fix this.

Next R64: independently verify Windows x64 FFI signatures/struct layout in permitted compiler-only workflow; search official kernel-side accepted-socket→original classify witness. If none, explicitly close endpointId-as-CLAIM path. Any native socket/filter/driver experiment requires separate authorization and rescue/rollback gates.
