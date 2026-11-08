# R54 — endpoint-closure lifetime witness, not a native owner-reauthorization proof

2026-11-08. **Only** `i-shutov/flowbridge` branch `research/windows-wfp-ale-attribution-20261107`. Independent R&D, no beta/PR #56, driver/filter/runner/service/VNC/network/security/automation mutation, no G2/PacketBound PASS or leak-free claims.

## Exact pinned Git inputs

Research parent HEAD `73feebe1378ad00ea7fa55c280a1d9646464c51a`, tree `e2d46ebf5805a424ddde14cb1c99f0417c2ad14d`. Main `5b5afc2feeda2195f302380e615ba003d4906e09`. Source blobs:
- `research/wfp-ale/kernel-r19/policy_windows.rs`: `acf60334320d970f58af3349ee75fbaa59826602` — four scoped redirect/AUTH filters; **no ALE_ENDPOINT_CLOSURE V4/V6 filter**.
- `kernel/src/lib.rs`: `0af6d4539673d2894cbaa91af0ea8f3524862a26` — four callouts with classify/notify; **no flowDeleteFn**.
- `kernel/src/redirect.rs`: `9a07e026134d46ef646d39862bd982cc48bbc5f6` — initial AUTH/redirect use TRANSPORT_ENDPOINT_HANDLE, reauthorization BLOCK; no closure subscriber.
- `kernel/src/handoff.rs`: `e1d17217db50362ba9c4efc83af820b6beb094cf` — permanent bounded numeric endpoint tombstones; Book::take consumes slot. No persistent established-flow reauth ledger.

## New documented boundary

Microsoft **ALE Endpoint Lifetime Management** specifies `FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4/V6`; for TCP an endpoint closure is indicated for ALE authorize connect/receive accept indications, with `FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE`. **Conditional architectural GO**: a separately registered native closure observer could invalidate a *previously authenticated* endpoint receipt when closure is actually delivered. It is not a synchronous owner-death notification, authenticated process identity, or a substitute for first-classify evidence.

`FWPS_METADATA_FIELD_FLOW_HANDLE` denotes a distinct data-flow runtime ID and must have its presence bit. `FwpsFlowAssociateContext0` requires `flowDeleteFn`; adding this API alone to current registered callouts cannot succeed. `FwpsAleEndpointGetById0` requires PASSIVE_LEVEL, not an arbitrary classify IRQL; retrospective lookup does not attest original ticket or process epoch.

**Unresolved:** reauthorization (CLASSIFY_COMPLETION or POLICY_CHANGE) may have FWP_EMPTY fields; a guaranteed endpoint-handle value and BFE delivery to the selected AUTH callback were NOT established. No unique WFP completion-to-ticket ID in a new reauth callback was demonstrated. Endpoint handle alone, PID or reused 5-tuple is not provenance.

## Executed negative experiment (NO native proof)

Local dependency-free Python `unittest`: **23/23 PASS** including v4/v6, same PID/tuple different epoch/ticket/endpoint, closure and duplicate closure, handle reuse tombstone, late callback, exact session/identity, missing endpoint metadata, sibling, TCP versus UDP/DNS, SSH and WFP loss and missed BFE dispatch.

Two independent synthetic Boolean oracles (local Python + committed executable JavaScript, independently executed in a V8 isolate) agree on **32,768** states: strict *conditional* model permits 2 (one per family, all 14 independently **assumed** guards true); unsafe endpoint-only model permits 16,384, including **16,382** extra states. All 14 absent-guard mutations were detected. No modeled permit proves real packets or OS source attribution.

The model deliberately permits a physically dead owner before its exit callback arrives; this is the existing observation gap, **not** a success. A callback BFE never dispatches is not a global OS deny. No Rust compiler/driver/Windows test was run; deterministic negative tests were used as permitted.

## Required trust chain / decision

Same native `ALE_CONNECT_REDIRECT_V4/V6` origin AppId, original destination, kernel process ID + referenced process object epoch/start key/canonical EXE and endpoint → one-use ticket/session → initial `ALE_AUTH_CONNECT_V4/V6` witness → **new hypothetical endpoint/established-flow lifetime ledger with closure invalidation** → independently authenticated `REAUTHORIZE_REASON`, with exact endpoint metadata or fail closed → actual accepted-socket `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS`, outbound `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`, trusted SSH. Every boundary is a separate proof obligation.

**Source-level NO-GO:** current 4-filter driver has no endpoint closure observation and no post-CLAIM authorization ledger. Endpoint/flow handles cannot be promoted into verified ownership without kernel event and lifetime proof. Owner-death timing, restart/rearm, sibling DIRECT, UDP/DNS/QUIC, IPv4/IPv6 physical egress, SSH/WFP loss, system no-DIRECT, G2/PacketBound and leak-free remain NO-GO. No G1 `dd1ab3c` acceptance transfer.

**Next decisive safe experiment R55:** document layer-by-layer guaranteed/conditional/unavailable metadata at REDIRECT, first AUTH, completion-triggered and policy-change REAUTH, and ENDPOINT_CLOSURE. Model an absent endpoint handle at REAUTH even when closure was observed, with selected-vs-sibling policy impact. Do not load drivers or modify native WFP policy.

Official documentation:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_incoming_metadata_values0_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsflowassociatecontext0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsaleendpointgetbyid0
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
