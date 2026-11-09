# R62 — Documented socket-to-ALE endpoint mapping is NOT original owner proof

2026-11-09. ONLY `research/windows-wfp-ale-attribution-20261107`. Independent FlowBridge WFP/ALE architecture research, NOT beta/PR #56, G1 transfer, PacketBound/G2, leak-free, or no-DIRECT. No driver, filter, network, VNC, runner, service, security setting or automation operations.

## Verified source baseline

Research HEAD `9a5ad30858a84c68e159824882811b214f1a6d1e`; main `5b5afc2feeda2195f302380e615ba003d4906e09`. No root AGENTS.md. Read R61, `research/wfp-ale/README.md`, and actual `research/wfp-ale/kernel-r19/kernel/src/{handoff,redirect,lib}.rs` / `research/wfp-ale/kernel-r19/broker_windows.rs`. Source Git blob SHAs: handoff `e1d17217db50362ba9c4efc83af820b6beb094cf`; redirect `9a07e026134d46ef646d39862bd982cc48bbc5f6`; lib `0af6d4539673d2894cbaa91af0ea8f3524862a26`; broker `16ec8853d322b40f0e00e14d49ae3410741b9395`. No implementation changes.

## Substantive previously missed official API

- `WSAIoctl(SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE)` is a documented, read-only `SOCKET → UINT64 endpoint ID` mapping (Windows Vista+). Query the *actual owned accepted socket*, validate successful return and 8-byte output. This is the endpoint of **the queried socket**, NOT a native attestation that it is the original client's endpoint. [Microsoft Winsock IOCTLs](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls).
- `FwpsAleEndpointGetById0` has both **user-mode** `fwpsu.h / fwpuclnt.lib` and **kernel** `fwpsk.h / Fwpkclnt.lib` entry points. It requires an opened BFE engine handle; kernel entry requires PASSIVE_LEVEL. Do not infer permission, endpoint persistence or a retrospective connection join from its existence. [User API](https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/nf-fwpsu-fwpsaleendpointgetbyid0) · [kernel API](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsaleendpointgetbyid0).
- `FWPS_ALE_ENDPOINT_PROPERTIES0` supplies endpointId, IPv4/v6 addresses, ports, protocol, localTokenModifiedId, IPsec fields, flags and *appId of that endpoint*. **No PID, creation epoch, EPROCESS reference, classify handle, original AUTH_JOIN or redirect-record provenance.** [Structure](https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_ale_endpoint_properties0).
- `WSADuplicateSocket` yields another descriptor for the **same underlying socket and shared state**. An endpoint ID is not a one-use capability, unique descriptor ID, original-owner credential, or a kernel-authenticated claim value. [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaduplicatesocketa).
- WFP redirect records from actual accepted socket `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS` remain **proxy-chain tracking state**, not owner credentials. Do not assume equality of original-client, accepted-proxy and outbound-proxy endpoint IDs; an endpoint equality rule may reject legitimate proxy chains. [Microsoft](https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records).

## Actual Rust boundary

`redirect.rs::classify` uses WFP-supplied original process metadata + transportEndpointHandle when available to issue private ticket. `handoff.rs::Book::attest` and `Book::take` validate/consume that ticket. `broker_windows.rs::receive` queries redirect context and records **on the same owned accepted TcpStream** into private `Received` fields: meaningful *trusted Rust application* provenance, not shown exploitable by a sibling.

But `DeviceIoControl(CLAIM)` contains only 128-byte context; `redirect.rs::ioctl(CLAIM)` checks `IoGetRequestorProcess(irp)` **for the broker requestor**, not a kernel reference to the accepted Winsock socket. A user-supplied endpoint number appended to this request would not become a kernel-attested socket reference. Querying endpoint properties can help diagnostics, not prove original PID+epoch+canonical EXE or AUTH_CONNECT identity.

## Deterministic negative countermodel

Local Python oracle: **16/16 unit tests PASS**. Independently authored Node oracle published at `r62/r62_independent.mjs`; both exhaust **32,768 synthetic states**, and agree in every count and full ordered decision-stream SHA-256 `12eec4bba6ff9a5b73c5344974f388dc82784f7cf2e4479eb98756f1427cf8b8`.

- **16,384 UNOBSERVED** callback-not-dispatched states, *never* equated to Windows BLOCK.
- Weak receipt/CLAIM/query policy conditionally admits **512**; stronger **counterfactual** model requiring an unavailable kernel-attested accepted-socket/record join, epoch and original selected origin admits **32**. **480** weak-only cases, including 256 sibling-origin cases and 256 wrong-record cases (overlapping).
- Even the strict *hypothetical* policy admits 16 states after physical owner death but before observed callback; 16 permit a different original/accepted endpoint numeric ID. Duplicated socket descriptors add no new identity.
- These are **synthetic assumptions and negative proofs about fields**. Not observed Windows behavior, not an exploit claim, not proof of arbitrary redirect-record acceptance, and the strict model is NOT implemented or a release GO.

## Decision

**Narrow conditional GO** to investigate a *read-only, user-mode* `accepted SOCKET → endpointId → endpoint properties` diagnostic; this is a new relevant documented capability. **NO-GO** for original kernel-origin process attestation, per-socket `CLAIM` binding, reauthorization, sibling DIRECT suppression, process liveness, IPv4/IPv6 egress/no-DIRECT, DNS/UDP/QUIC, WFP/SSH loss, PacketBound/G2 and leak-free.

**R63 decisive:** offline Rust (user-mode, read-only, no-driver) FFI prototype for `SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE` and `FwpsAleEndpointGetById0`; verify correct output length, engine permission/errors, endpoint lifecycle and whether v4/v6 property appId ever suffices *without* assuming it authenticates original owner. Do not execute socket/network operations or Windows experiments without separate authorization. If no documented native socket→original AUTH_JOIN exists, retain NO-GO.
