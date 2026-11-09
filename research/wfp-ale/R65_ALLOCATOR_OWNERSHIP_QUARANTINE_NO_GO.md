# R65 — Quarantine Windows ALE endpoint probe: allocation ownership unproven

Date: 2026-11-09. Scope: **i-shutov/flowbridge**, branch **research/windows-wfp-ale-attribution-20261107** only. Independent architecture research, not beta/PR #56/main/release/PacketBound/G2.

## Baseline and provenance

Research base HEAD `591cc1ae6ff8e592968120ee96acb025a211c1c6`; main HEAD `5b5afc2feeda2195f302380e615ba003d4906e09`. Original R64 Rust probe at `research/wfp-ale/r63/r63_endpoint_probe.rs`, initial blob SHA `9e95f976abaf0417668cb5593741aed1401db4b2`.

## Decisive finding: documentation does **not** prove an allocator pairing

- Official `FwpsAleEndpointGetById0` (user-mode `fwpsu.h`, `fwpuclnt.lib`) documents `DWORD FwpsAleEndpointGetById0(HANDLE,UINT64,FWPS_ALE_ENDPOINT_PROPERTIES0**)` and **does not specify who frees the `properties` buffer**. Source: https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/nf-fwpsu-fwpsaleendpointgetbyid0
- Official `FwpmFreeMemory0` says broadly it frees WFP-allocated memory, but its **Remarks specifically identify memory from `Fwpm*` functions**. Passing an invalid pointer yields **undefined behavior**. It does *not* provide an explicit `FwpsAleEndpointGetById0` pairing. Source: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfreememory0
- `FWPS_ALE_ENDPOINT_PROPERTIES0` describes endpoint properties including `appId` and a token modified ID; it has no PID+creation epoch+original AUTH_CONNECT authorization identity. Source: https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_ale_endpoint_properties0
- A symbol or library export with a similar name is **not** proof of ownership. Neither `FwpmFreeMemory0`, an undocumented `FwpsFreeMemory0`, `free`, nor `CoTaskMemFree` may be chosen by guesswork.
- The unverified R63/R64 code performed `FwpsAleEndpointGetById0` and then `FwpmFreeMemory0`; even a successful lookup would not establish that the deallocator is correct. This is a *potential invalid free*, not an observed Windows crash.

## Executable remediation

The dangerous **entire Windows FFI module** has been removed from the buildable R63 Rust PoC. Replaced with a Windows-only **safe stub** `inspect_existing_socket(&TcpStream) -> Err(AllocatorOwnershipUnverified)` which performs no network, WFP or memory calls. `ProbeReadiness` is unconditionally `DisabledAllocatorOwnershipUnverified`. The cross-platform test asserts this fail-closed state; the corrected `0x580000CD` opcode constant and its regression test are retained for any future fully vetted reconstruction. Original unsafe code remains available via the R64 Git commit, not in any buildable code path. This is a real safety fix, not claimed Windows API functionality.

## Independent evidence and limits

Static source invariants checked by separate Python and Node implementations: no `extern`, no `unsafe`, no `WSAIoctl`, no `FwpsAleEndpointGetById0`, no `FwpmFreeMemory0`, no `FwpmEngineOpen0` on the buildable source; stub's unconditional error, corrected opcode retained, `Unobserved` distinguished from OS block and endpoint-only diagnostic from origin proof. No Rust toolchain or Windows SDK in this isolated environment, so **no Rust compile/test run or Windows x64 ABI verification**. Python/Node static tests cannot prove Windows ABI or memory ownership.

## Trust boundary and separate unclosed gates

`SOCKET -> SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE -> endpointId -> FwpsAleEndpointGetById0 -> appId` remains a *hypothetical diagnostic* only. `accepted socket → CLAIM → original AUTH_CONNECT` has no documented kernel-attested link. PID+creation epoch+canonical EXE, process death/PID reuse, repeated 5-tuple, sibling DIRECT, IPv4/IPv6, DNS/UDP/QUIC, WFP/SSH loss and cross-layer reauthorization cannot be proved by these fields. Neither this PoC nor previous synthetic models imply PacketBound/G2 PASS or leak-free. No OS/WFP packet assertion is made from a lack of callback.

## Decision and next decisive experiment

**NO-GO: enable or execute endpoint query PoC.** **GO: fail-closed safety quarantine.** R66: seek an official Microsoft SDK `FwpsAleEndpointGetById0` allocation/free pairing (and ABI evidence) or close this diagnostic path permanently. Independently investigate whether **documented kernel-origin connection metadata** can be atomically tied to a socket without relying on user-supplied IDs, and negative-test PID reuse/redirect replay only offline. No kernel/VNC/driver/filters/OS/network actions authorised.
