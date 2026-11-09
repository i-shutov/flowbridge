# R78 — pre-receipt worker capacity is unauthenticated (conditional NO-GO)

Date: 2026-11-09. Research branch ONLY `research/windows-wfp-ale-attribution-20261107`. Parent `8fa98191783857348ed94d3451a7585ec688a805`; observed main `5b5afc2feeda2195f302380e615ba003d4906e09`. Not beta, PR #56, G2, PacketBound, historical G1 or native proof.

## Exact code and new counterexample

Pinned Git blobs: `kernel-r19/broker.rs` `ce6c549a9ae488cc7c0ca9a7e7be68871b9d7f2c`; `kernel-r19/broker_lifecycle.rs` `211b5e5cee03f4d8ea13fc23e1be0777cbfa09c1`; `kernel-r19/broker_windows.rs` `16ec8853d322b40f0e00e14d49ae3410741b9395`.

In broker.rs, the SAME `WorkerPool::new(32)` serves IPv4 `127.0.0.1` and IPv6 `[::1]`. `workers.spawn` happens BEFORE `broker_windows::receive(client)` queries the accepted socket's WFP records/context. `WorkerPool::spawn` polls finished workers, then refuses an additional stream when `active.len() >= limit`, without global STOP. The unverified socket holds capacity until its worker completes.

Source-order counterexample: if 32 unverified IPv4 receipts are still pending, a selected IPv6 connection is dropped BEFORE its WFP receipt is checked; the symmetric IPv6-to-IPv4 case is identical. An authenticated relay plus 31 unverified pending receipts also fills capacity. Completion and reaping of one slot restores admission. This is a **conditional availability NO-GO**, not a demonstrated ability to force a Windows WSAIoctl to hang. Native timing, adversarial feasibility and actual loss probability are unmeasured. No DIRECT fallback is shown on this refusal path, and system-level containment is NOT proven.

R39 corrected lifetime accumulation of finished worker handles; R78 isolates simultaneous occupancy by *not-yet-verified* sockets. A separate finite unverified pool does not by itself mathematically guarantee admission for an authenticated selected connection.

## Executed, independently checked

Extended offline Python event model: **15/15 tests PASS**; independent Node arithmetic oracle: **4,868/4,868** outcomes agree, including 52 DROP and 4,816 SCHEDULE cases across artificial capacities 1/2/4/32 and IPv4/IPv6; SHA-256 `c65549679756ad0587803852020b383a35ce4470e42ff976f70706060cafcdbe`. Compact published Python: **4/4 PASS**, independent JS agrees on **4,868/4,868** cases, same 52/4,816 counts and ordered SHA-256 `cb12a074dee468caa6ba03f57d1b0b1cf7443b7f2586b5486cb34a58622c1b2b`. These are synthetic states, not empirical rates.

Separate pure safe Rust worker-slot model with 8 unit tests is in the local R78 checkpoint. **Rust tests NOT RUN**: no rustc/cargo available. No sockets, WFP IOCTLs, native Windows, drivers, filters, CI/runner, services, network or OS security settings were touched.

## Trust boundary and next experiment

The documented required chain remains: original process and epoch with exact WFP AppId at `ALE_CONNECT_REDIRECT_V4/V6` → `ALE_AUTH_CONNECT_V4/V6` original-destination policy → accepted-socket `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)` → one-shot CLAIM → outbound `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` → authenticated SSH. Resource admission currently happens **before** the socket receipt; neither a retrospective PID lookup nor a 5-tuple/time correlation authenticates it. PID reuse/death, reused tuple, sibling DIRECT, IPv6 scope, DNS/UDP/QUIC, WFP/SSH-loss, kernel CLAIM-to-socket identity and physical leak-free remain **NO-GO**.

R79 decisive experiment: compile R77/R78 pure Rust models on an authorized user-mode Windows workstation, then measure time-bounded read-only receipt-query behavior on owned ordinary unredirected sockets. Such observations are only a negative baseline and cannot certify selected flows or native redirect. No native traffic or driver/filter setup without appropriate prior approval.

Microsoft references:
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
