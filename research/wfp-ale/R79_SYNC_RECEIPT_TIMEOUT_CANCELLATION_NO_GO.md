# R79 — timeout is NOT WFP receipt completion (architectural NO-GO)

Date 2026-11-09; research branch ONLY research/windows-wfp-ale-attribution-20261107. Before: 48c952fca840beaba5d6e43f740a3c49535cebfe; main read-only 5b5afc2feeda2195f302380e615ba003d4906e09. Not beta / PR #56 / PacketBound / G2 / historic G1.

## Concrete source-order counterexample

Pinned source Git blobs:
- kernel-r19/broker.rs ce6c549a9ae488cc7c0ca9a7e7be68871b9d7f2c: one 32-slot pool for IPv4/IPv6; spawn before accepted-socket receipt.
- kernel-r19/broker_windows.rs 16ec8853d322b40f0e00e14d49ae3410741b9395: sequential synchronous WSAIoctl QUERY_RECORDS and QUERY_CONTEXT, BOTH overlapped/completion pointers null, without timeout; failed receipt rejected before CLAIM.
- kernel-r19/broker_lifecycle.rs 211b5e5cee03f4d8ea13fc23e1be0777cbfa09c1: slot reclaimed on actual worker completion/reaping, not on an external deadline.

Microsoft WSAIoctl API expressly says any IOCTL *may block indefinitely*, depending on provider; this is a documented possibility, **NOT** a measured hang in either particular WFP query. A timer around a blocked worker does not guarantee its completion/cancellation or reclaim its slot. With 32 unresolved pre-receipt workers, a selected connection on either family can still be refused before validation. Deadline-only mitigation proposed for R78 is insufficient.

CancelSynchronousIo(hThread) marks requests for cancellation; it does not wait for acknowledged completion, and cancellation may fail/delay. CancelIoEx similarly does not guarantee immediate completion. Closing a socket cannot be used concurrently with another Winsock call on it, and descriptor integers may be reused. For overlapped IO, WSAOVERLAPPED and output buffers must remain valid until actual completion; an expired request completing normally late must NOT revive an old session/ticket.

## Executed negative proof (no Windows, sockets, FFI, drivers or service changes)

- r79_lifecycle.py: 10/10 tests PASS, including an actual bounded stdlib ThreadPoolExecutor demonstration: result(timeout) times out while the worker is still RUNNING; cancel() is false; explicit release allows cleanup.
- Independent Node oracle: 256/256 ordered decisions identical to Python. Matrix: IP family 4/6, state PENDING/COMPLETED/CANCELLED/FAILED, expired, cancellation requested, same socket, same generation, valid context.
- Counts: HOLD_PENDING=64, REJECT_TERMINAL=128, REJECT_LATE=32, REJECT_CONTEXT=28, CONDITIONAL_RECEIPT_NOT_PROOF=4. Naive early release while still pending would occur in 32 synthetic states. Ordered SHA256: 338264cbb541673ffccda0afe30a7302e5a1eeba9a79c13b7710a5a7649bdcda.
- The synthetic numbers are NOT empirical Windows frequency, exploitation, native attribution or physical leak measurements. No rustc/cargo or native Windows IOCTL tests were available; Rust compilation NOT RUN.

## Safe conditional approach / still NO-GO

An overlapped socket with a valid WSAOVERLAPPED, wait/deadline, cancellation *request*, completion *acknowledgement* and pinned output/accepted-socket ownership may be investigated. On timeout quarantine the in-flight operation and reject any late success; do not reclaim safety-accounted resources until terminal completion. A quarantine bound limits amplification but does NOT guarantee admission if all unresolved calls persist. No claim that SO_RCVTIMEO bounds arbitrary WSAIoctl. A receipt candidate does not prove kernel original-owner identity or CLAIM-to-socket causality.

The required trust chain still has NO-GO gaps: original exact opaque WFP AppId + PID + referenced process creation epoch captured at ALE_CONNECT_REDIRECT V4/V6 (with validated IRQL), FwpsQueryConnectionRedirectState0, scoped original destination; ALE_AUTH_CONNECT V4/V6 scope and original/current AppId; socket-owned QUERY_RECORDS/QUERY_CONTEXT; one-shot CLAIM; outbound SET_RECORDS; pinned-key SSH; **independent kernel-enforced** sibling DIRECT denial. Retrospective OpenProcess/GetProcessTimes/QueryFullProcessImageNameW or FwpmGetAppIdFromFileName0 cannot prove historical owner. PID reuse/process death/reused 5-tuple, IPv6 scope/compartment, DNS/UDP/QUIC, WFP/BFE/SSH loss, PacketBound/G2 and leak-free remain unverified/NO-GO.

## R80 decisive next experiment

On a separately authorized user-mode Windows research workstation: compile R77/R78 Rust tests; use *owned ordinary unredirected sockets only* to measure WSAIoctl records/context error, completion status and duration for v4/v6 under properly owned synchronous vs overlapped calls. Read-only results are NEGATIVE BASELINE ONLY; no driver/filter or positive native redirect without owner and driver/VNC/SYSTEM-rescue/rollback gates. In parallel audit a pure safe Rust completion/cancel/late-result state machine; never accept guessed PID/tuple/event correlations as kernel proof.

Official Microsoft sources, reviewed 2026-11-09:
- https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaioctl
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context
- https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelsynchronousio
- https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex
- https://learn.microsoft.com/en-us/windows/win32/fileio/canceling-pending-i-o-operations
- https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-closesocket

Isolation: NO beta/main/release/PR #56/runner/CI/services/Defender/UFW/firewall/SecureBoot/MemoryIntegrity/VNC/driver/filter/network mutation, no ProxiFyre AGPL/vendor binaries/closed PR40/C++ payload, no paid operations.