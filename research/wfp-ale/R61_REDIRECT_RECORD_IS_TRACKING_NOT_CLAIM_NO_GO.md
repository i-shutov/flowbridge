# R61 — Redirect records are tracking state, NOT kernel CLAIM identity

2026-11-09. **ONLY** research/windows-wfp-ale-attribution-20261107. Independent FlowBridge WFP/ALE R&D; not beta/PR #56, G1 transfer, PacketBound/G2, no-DIRECT or leak-free. No driver/callout/filter/VNC, runner, service, firewall, Defender, SecureBoot, network, OS protection or automation operations.

## Verified starting point

Research HEAD before `1338548d6cad5123378d86a0ff543afe41c379f0`, main `5b5afc2feeda2195f302380e615ba003d4906e09` (research ahead 98/behind 0). No root AGENTS.md. Read R60, research README and the unchanged Rust source: `kernel/src/handoff.rs` blob `e1d17217db50362ba9c4efc83af820b6beb094cf`, `kernel/src/redirect.rs` blob `9a07e026134d46ef646d39862bd982cc48bbc5f6`, `broker_windows.rs` blob `16ec8853d322b40f0e00e14d49ae3410741b9395` (all under `research/wfp-ale/kernel-r19/`). No implementation edits.

## Official API boundary

- `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS)` reads an **opaque WFP tracking record** from the actual redirected, accepted socket; `..._CONTEXT` retrieves **callout-supplied context**, not a Windows-certified process credential. `WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS)` forwards the record to the outbound socket before connect. The official contract is proxy-chain linkage/loop detection, **not** unforgeable owner, per-socket AUTH_JOIN, single-use record or delivered-packet certificate. Microsoft [QUERY](https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records), [CONTEXT](https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context), [SET](https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records), [tracking](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking).
- **Documented alternative to study:** `FwpsQueryConnectionSioFormatRedirectRecords0` can serialize a redirectRecords metadata handle inside the kernel during a *pended* `ALE_CONNECT_REDIRECT_V4/V6`, before the proxy accepts the original connection. This is a narrow early-record transfer facility, **not** an owner credential and not a substitute for the later accepted-socket receipt. [Microsoft API](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionsioformatredirectrecords0).
- No official guarantee was found that copied records authenticate PID+creation epoch+canonical EXE, bind a particular pending classify handle to the subsequent `ALE_AUTH_CONNECT` reauthorization, or are single-use. **Do not** conclude Windows accepts foreign/cross-socket record injection: the tests deliberately assume possible outcomes only and do not execute Windows IOCTLs. SET can fail, including access denied.

## Actual source inspection (important non-bug distinction)

`broker_windows.rs::receive(accepted)` queries both record and context on the **same owned TcpStream**, then makes a `Received` with **private** accepted/context/records fields. `Received::claim_and_connect(self)` consumes it, sends `DeviceIoControl(CLAIM, context)`, and only afterwards sets the WFP records on a new outbound socket. This already constrains swaps at the *trusted Rust application boundary*. It is NOT demonstrated vulnerable to arbitrary external record substitution.

But the kernel `Book::take` verifies the one-use private ticket ledger from the **context bytes**; the `CLAIM` request does not include an authenticated accepted `SOCKET`, redirectRecords handle, or outbound socket. Thus the one-shot kernel ticket is not by itself a kernel-attested `accepted socket ↔ record ↔ outbound socket` join. User-mode encapsulation and WFP provenance are different trust boundaries.

Required unproven chain: original WFP AppId + referenced process epoch/start-key + canonical EXE + endpoint + actual original destination + v4/v6 + redirect history → kernel AUTH receipt → one-use ticket → accepted socket's matching context and opaque records → SET on the correct outbound socket → healthy SSH/WFP/liveness. PID+tuple or record bytes never repair an absent join. The current redirect code is inline, not an R60 async implementation.

## Executed independent negative experiment

Local stdlib Python oracle (18 tests) and independently authored published Node oracle enumerate **24,576 synthetic** combinations: IPv4/IPv6, selected A/sibling B with PID/5-tuple reuse but different epoch/endpoint, accepted/context/record/outbound identity, hypothetical record source family, completed/aborted pending classify, authenticated ticket, query and SET outcome, observed SSH/WFP loss, owner-death callback delay.

Results (conditional decisions, **not** Windows packets):
- Simplified context/CLAIM+QUERY+SET gate: **128** candidates; additionally require consistent accepted/context/record/outbound pairing, family and completed pending: **4**; add a hypothetical immediate physical owner-liveness proof: **2**.
- Weak policy: **64** candidates each for wrong accepted socket, wrong record, wrong outbound source, wrong IP family and aborted pending (overlapping classes). Stronger pairing leaves **2** instances after physical owner death but before callback. Observed SSH/WFP loss and processed exit: **zero** admissions by design.
- One-use kernel ticket redemption is modeled separately: first claim succeeds, second fails; **WFP record single-use is not inferred**.
- Python and independent Node agree in every counter and full ordered decision-stream SHA-256 `632eec35c1083e7986885775552ada7791b2f3c1c10d9b145c727ab8c54a7ed0`. Synthetic origin labels are oracle facts, **not** fields available from opaque Windows records. Windows may reject the hypothetical foreign record; such a rejection does not prove general provenance. Local checkpoint contains Python source, run logs, both outputs, SHA256.

## Architectural outcome

**Narrow GO:** WFP records for proxy-chain tracking; private same-accepted-socket Rust ownership; investigate early record serialization API on CONNECT_REDIRECT in read-only/offline mode. **NO-GO:** record/context/SET equivalence to trusted original process, one-shot receipt, callback-to-callback AUTH identity, OS no-DIRECT, PacketBound/G2, leak-free. Native kernel, callback-lifetime, sibling DIRECT, DNS/UDP/QUIC, WFP/SSH-loss, physical IPv4/IPv6 egress and death/PID-reuse gates remain unproven.

**R62 decisive next:** look for *documented* kernel-side witness joining the specifically accepted socket to `Book::take` without contextual aliases: `FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE`, `FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE`, `FwpsAleEndpointGetById0`, socket duplication/handle rights and `DeviceIoControl` requestor-process guarantees; check IRQL and lifetimes. If absent, explicit NO-GO. No driver/filter or VNC experiment without the owner's separate gating decision.
