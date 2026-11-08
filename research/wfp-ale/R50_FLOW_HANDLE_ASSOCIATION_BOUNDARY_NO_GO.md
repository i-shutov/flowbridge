# R50 — Flow handle and flow-context association do not prove initial AUTH completion

Date 2026-11-08. Scope strictly `research/windows-wfp-ale-attribution-20261107`. Not beta, PR #56, PacketBound/G2, system no-DIRECT, or leak-free certification. No kernel build/load, driver, filters, CI, runner, services, network, WFP policy, signing or VNC.

## Pinned source

Before R50 research HEAD: `22c3c5101579581c99ea329a72dfb30b73dc4d58`; main HEAD `5b5afc2feeda2195f302380e615ba003d4906e09`.

- `research/wfp-ale/kernel-r19/kernel/src/lib.rs`: blob `0af6d4539673d2894cbaa91af0ea8f3524862a26`; all four FWPS_CALLOUT1 records are `mem::zeroed()`, then only `classifyFn` and `notifyFn` are set. **No flowDeleteFn is registered**.
- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs`: blob `9a07e026134d46ef646d39862bd982cc48bbc5f6`; `auth_check` reads PROCESS_ID, TRANSPORT_ENDPOINT_HANDLE, LOCAL_REDIRECT_TARGET_PID, ORIGINAL_DESTINATION, but not `FWPS_METADATA_FIELD_FLOW_HANDLE`. It does not call `FwpsFlowAssociateContext0`. It blocks IS_REAUTHORIZE.
- `research/wfp-ale/kernel-r19/kernel/src/handoff.rs`: blob `e1d17217db50362ba9c4efc83af820b6beb094cf`; `Book::attest` and `Book::take` are single-use, not a per-flow reauthorization cache.

## New source/API NO-GO

Microsoft's `FwpsFlowAssociateContext0(flowId, layerId, calloutId, flowContext)` binds an *opaque callout-defined* context to one flow at one layer/callout, **only if** the `FWPS_METADATA_FIELD_FLOW_HANDLE` presence flag is set for the metadata's `flowHandle`. The API requires the layer's registered callout to have a `flowDeleteFn`; absent callback yields `STATUS_INVALID_PARAMETER`. Current four callouts have none. A naive attempt to add association alone is therefore a source/API mismatch.

Flow-handle metadata availability on the initial `AUTH_CONNECT` or during `PEND → COMPLETE → REAUTHORIZE` is NOT guaranteed by the consulted documentation. The `ALE_FLOW_ESTABLISHED_V4/V6` stage occurs after the TCP handshake and cannot retroactively certify initial pre-establishment pending classification. `flowContext` does not authenticate original process, endpoint, redirect-record origin or outbound SSH relay. Neither a flowHandle nor a transportEndpointHandle alone is an authorization credential, nor can they be joined by PID/5-tuple correlations. Policy-change reauthorization may supply `FWP_EMPTY` fields and a reversed packet direction.

## Deterministic tests

Local Python negative suite **14/14 PASS**, independent Node enumeration **131072/131072** synthesized V4/V6 Boolean states with matching counts: 2 *conditional best-case* post-establishment policy-reautorization permits (assuming 16 separately authenticated facts), 0 current-driver reauth permits, 65536 unsafe permits under intentionally weakened `flowHandle-present ⇒ allow` rule, 16/16 single-guard mutants rejected by full model. Node independent oracle is published in this commit; full Python suite, logs and a dependency-free Rust `#![forbid(unsafe_code)]` **23-test model** are in the checkpoint. Rust not compiled or executed (rustc/cargo unavailable).

Conditional model permits do not prove that any native kernel receipts can be produced. No Windows, network or physical egress tests were executed.

## Next safe experiment

Build a separate *initial* AUTH `PEND → COMPLETE → REAUTHORIZE` state machine keyed to uniquely generated callout-private pending state, not a guessed WFP token or an assumed already-established flow handle. Explore missing metadata, process exit, duplicated completion, delayed callback, FWP_EMPTY, PID/endpoint reuse, V4/V6, original AppId, re-used 5-tuple and SSH/WFP loss. Keep kernel-origin/flow-lifecycle evidence as an unproven premise; do not install drivers or filters without the separately gated owner decision.

Trust chain still unproven: source-pinned AppId + referenced process epoch + canonical EXE → native CONNECT_REDIRECT origin/ticket → AUTH_CONNECT → accepted socket redirect context/records (SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS) → one-use CLAIM → outbound SIO_SET records → authenticated SSH. Owner-liveness, sibling DIRECT, DNS/UDP/QUIC, process death/PID reuse, re-used 5-tuple, WFP/SSH loss, full V4/V6 and physical egress remain NO-GO. Historical G1 dd1ab3c cannot be promoted.

## Official references

- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsflowassociatecontext0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/ns-fwpsu-fwps_incoming_metadata_values0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_flow_delete_notify_fn0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers
