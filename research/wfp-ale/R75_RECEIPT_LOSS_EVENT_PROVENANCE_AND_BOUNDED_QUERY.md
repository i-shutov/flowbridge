# R75 — WFP receipt-loss provenance; bounded records query

Date: 2026-11-09. Scope ONLY research/windows-wfp-ale-attribution-20261107; standalone research, not beta/PR #56. Pinned research baseline a5ddaaa1db89b0a1984156ca9b303a156bb5a023, main 5b5afc2feeda2195f302380e615ba003d4906e09. No driver, callout, filters, Windows tests, network or runner changes.

## Source-derived result

- kernel-r19/broker_windows.rs blob 16ec8853d322b40f0e00e14d49ae3410741b9395: query(accepted socket) uses a single WSAIoctl with 65,536 bytes for opaque redirect records, 128 for context. The query function discards error cause and returns the same PermissionDenied for WSA errors, zero bytes and oversize output. The native WFP receipt is not known when query fails.
- kernel-r19/broker.rs blob ce6c549a9ae488cc7c0ca9a7e7be68871b9d7f2c: pre-receipt query errors result in IngressRejected for that socket; validated post-receipt failures revoke the shared lease. 9/9 independent source-structure assertions matched the GitHub blobs.
- Microsoft specifies variable-length SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS, with returned required size after insufficient-buffer error. CONDITIONAL narrow GO: a read-only, bounded, same-accepted-socket required-length query/retry could avoid rejections caused only by the fixed 64KiB records buffer. Explicitly check WSAGetLastError and the required length, cap growth, reject unsupported errors, and never reinterpret successful resizing as proof of original owner. The documentation simultaneously describes a zero-output size query and WSAEINVAL for outputs shorter than ULONG; do not assume one universal response without a Windows probe. The 1MiB ceiling in these tests is a hypothetical budget, not a native guarantee. R19 FBR3 custom context must still be exactly 128 bytes.
- Main NO-GO unchanged: an unrelated local TCP ingress with WSAIoctl failure is observationally identical to a selected redirected client with a failed query if authenticated kernel error evidence was lost. An algorithm using only those inputs cannot simultaneously guarantee immediate global STOP for selected failures and no STOP for unrelated ingress. This is a two-world information cut, not an observed leak.

A future authenticated kernel event might justify a GLOBAL stop for an independently established selected-flow failure, but is not proof that the error occurred on this particular accepted socket. An event from another selected connection and an unrelated local ingress can coexist. The kernel event must carry proven origin/process epoch + endpoint generation, session, sequencing and a reliable loss/heartbeat barrier. A sequence gap is detectable only after a later delivered event; a silent event channel needs a separate bounded kernel-enforced fail-closed guard. The current R19 broker has no proven kernel-origin failure-event producer. FwpmNetEventSubscribe2 is a user-mode net event subscription API, not a documented lossless WFP receipt-failure certificate or an accepted-socket witness.

## Trust boundary and open gaps

FwpmGetAppIdFromFileName0 produces WFP ALE_APP_ID device-path bytes, NOT original-process identity. A sound proof also needs referenced original process + PID + creation epoch/start key, validated at ALE_CONNECT_REDIRECT_V4/V6 and ALE_AUTH_CONNECT_V4/V6, original destination and redirect state before issuance, IPv4/IPv6 scope, and endpoint generation. Old PID, retired endpoint and reused 5-tuple cannot be joined after the fact. Received owns accepted socket + WFP context inside a trusted broker; raw DeviceIoControl(CLAIM, bytes) / Book::take does NOT independently prove socket pairing. QUERY and SET redirect records, terminal CLAIM, host-key-pinned SSH authentication and channel-open are separate steps; user-mode failures do not certify egress blocking. Sibling DIRECT, DNS/UDP/QUIC, owner death after CLAIM, WFP/SSH-loss, PacketBound/G2 PASS, leak-free/no-DIRECT and historical G1 at dd1ab3c all remain NO-GO.

## Executable tests

Python stdlib r75/r75_negative.py: 15 unittest PASS. Independent Node stdlib r75/r75_independent.mjs: identical outcomes for 960 synthetic worlds, both IPv4/v6, selected/foreign (hidden truth), 5 event classes, 6 record sizes, supported/unsupported provider, reused PID and 5-tuple. Matched SHA256 of every ordered decision: c4ffe3d637d2a5be6005cf6b8589c40649d0e5a402087aa670f8c66964868bb6. Counters: 480 observationally equivalent selected/foreign pairs, 96 selected/absent-event worlds, 160 hypothetical size-only recovery cases (fixed-size fit 160, bounded-size fit 320). Counts are NOT native measurements or 160 working redirects. A separate clean-room, pure Rust, no-FFI reference model with 14 tests was prepared locally, but rustc is unavailable; no Rust PASS claimed.

## Next decisive work

R76: audit actual FWPM_NET_EVENT0/2/5/7 structures, FwpmNetEventSubscribe2/Enum2 versioned APIs and delivery semantics against origin/epoch, flow identity, socket correlation and event-loss guarantees. Close event-attestation GO if there is no documented evidence rather than confusing telemetry with proof. Native owned-socket read-only WSAIoctl sizing probe requires a supported Windows 11 execution channel; do not install/activate any driver or filter.

Microsoft API primary sources:
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmneteventsubscribe2

Protected boundaries untouched: main/release, beta integration/windows-rust-capture-agent-20261031, PR #56, other repositories, CI/runner, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, networks, automations, VNC, SYSTEM/driver rescue gates, paid operations. No ProxiFyre AGPL, PR40, vendor binaries or C++ WFP payload.
