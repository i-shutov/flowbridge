# R55 — AUTH reauthorization with absent endpoint handle: source-verified attribution NO-GO

2026-11-09. Only `i-shutov/flowbridge` branch `research/windows-wfp-ale-attribution-20261107`. Independent read-only/offline R&D, not beta/PR #56/G2/PacketBound acceptance.

## Fresh frozen source
Research base HEAD `cd0aebde69b7d253901e4e50f7b3a1d6504cc08c`, tree `7908cae5f5891f318d552285f16f25b3e75c8893`; main `5b5afc2feeda2195f302380e615ba003d4906e09`. Pinned Git blobs:
- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs`: `9a07e026134d46ef646d39862bd982cc48bbc5f6`. Native redirect and initial AUTH demand transport endpoint, PID/AppId witnesses; current `auth_check` explicitly denies every `IS_REAUTHORIZE`.
- `kernel/src/lib.rs`: `0af6d4539673d2894cbaa91af0ea8f3524862a26`. Four callouts only; no endpoint closure callback or post-CLAIM connection-state owner proof.
- `kernel/src/handoff.rs`: `e1d17217db50362ba9c4efc83af820b6beb094cf`. One-use `Book::take` removes ticket; numeric endpoint tombstones, no established reauthorization ledger.
- `research/wfp-ale/kernel-r19/policy_windows.rs`: `acf60334320d970f58af3349ee75fbaa59826602`. Scoped BFE AUTH filters match original-AppId and TCP; dispatch when classifiable fields are unknown is not proved.

## Microsoft contract and proof gap
`FWPS_INCOMING_METADATA_VALUES0` fields `processId`, `transportEndpointHandle`, `flowHandle`, `completionHandle` and `originalDestination` are valid ONLY when their corresponding presence bits are set; a member's mere existence does not guarantee delivery at each ALE layer. `FWP_EMPTY` is a distinct classifiable-field type during reauthorization, not a metadata bit.

`FwpsPendOperation0` may pend initial `ALE_AUTH_CONNECT_V4/V6`; `FwpsCompleteOperation0` causes a new `AUTH_CONNECT` reauthorization, not a receipt identifying the original private ticket. Microsoft requires unique pending-operation state. Reauthorization can be triggered by completion, policy change or interface changes; policy reauthorization may have `FWP_EMPTY` fields and packet direction different from the initial authorization.

`ALE_ENDPOINT_CLOSURE_V4/V6` provides a unique engine-assigned transport endpoint handle for a *delivered closure event*, enabling invalidation of an already proved endpoint ledger. Microsoft does NOT thereby guarantee that the same handle exists on every initial/policy/completion reauthorization. `FwpsAleEndpointGetById0` is a PASSIVE_LEVEL query by an *existing ID*, not a mechanism for discovering a missing prior owner or ticket. `flowHandle` is not the transport endpoint handle.

## Reproducible negative experiment
Four paired observations (IPv4/IPv6 × completion/policy reauthorization) were constructed with absent transport endpoint, FWP_EMPTY original-AppId and protocol, same reused five-tuple and identical closure history. Selected-owner and sibling-owner worlds produce **identical observed data** while requiring different scoped policy outcomes. Therefore any policy based solely on that observation cannot both enforce selected-flow restrictions and preserve sibling nonselection. This is a *conditional indistinguishability proof*, NOT an assertion that actual Windows emits the specified absent fields.

Two independently authored, published and locally **executed** Python/Node oracles exhaustively agree on **16,384** synthetic states (2 families × 2 reasons × 2^12), **4** full-assumption conditional permits, **4,096** endpoint-presence-only permits (**4,092** excess), **8,192** cases without callback dispatch, **4** identical selected/sibling pairs, and **12/12** single-guard regressions detected. No modeled permit authenticates WFP ingress, physical packets or owner liveness. In particular **UNOBSERVED != OS BLOCK**.

The local extended checkpoint additionally includes **20/20** passing Python unit tests for endpoint closure/reuse, epoch/PID/ticket/session/sibling/IPv4-v6/UDP/SSH/WFP loss and delayed process-exit notification. The dependency-free `#![forbid(unsafe_code)]` pure Rust ledger has **24 unit tests authored but NOT COMPILED/EXECUTED** (`rustc/cargo` unavailable), so do not report Rust PASS or native PASS. The Rust/Python extended suite is in the checkpoint; only the two byte-verified executable oracles and this report are committed.

## Decision / trust boundary
**Conditional GO** for closure-driven invalidation of an *already authenticated* endpoint ledger; **NO-GO** for treating closure, `REAUTHORIZE_REASON`, AppId equality, PID, `flowHandle` or reused 5-tuple as an authenticated joining key when the reauthorization has no proved endpoint ID. The present driver has no post-CLAIM reauth ledger and denies reauthorization by source construction.

The required native proof chain remains: exact selected canonical EXE AppId, kernel-origin referenced process PID + creation epoch/start key at permissible IRQL, destination+v4/v6 endpoint from same `CONNECT_REDIRECT`, issued session/ticket, same-origin initial `AUTH_CONNECT`, independently authenticated per-flow retained witness across subsequent reauth, closure/exit invalidation, actual accepted-socket WSAIoctl redirect CONTEXT/RECORDS, outbound SET redirect RECORDS, authenticated SSH, and independently measured physical selected/sibling DIRECT and DNS/UDP/QUIC during WFP/SSH loss. No kernel driver, WFP filter, VNC, system settings, CI, runner, main, beta, PR #56 or automation mutation; no historical G1 promotion.

**R56 next decisive safe experiment:** inspect official `FWPS_METADATA_FIELD_FLOW_HANDLE` and `FwpsFlowAssociateContext0` / `FwpsFlowRemoveContext0` / `flowDeleteFn` lifetime to determine whether a WFP-authenticated kernel flow witness can be retrieved at *both* initial and subsequent AUTH events when endpoint metadata is absent. If documentation cannot prove this binding, keep NO-GO, do not replace it with correlation.

Official Microsoft sources (checked 2026-11-09):
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_incoming_metadata_values0_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendoperation0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscompleteoperation0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsaleendpointgetbyid0
