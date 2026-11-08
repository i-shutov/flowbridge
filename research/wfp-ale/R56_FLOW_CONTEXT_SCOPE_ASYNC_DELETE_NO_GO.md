# R56 — scoped WFP flow context and deferred delete: architectural NO-GO

2026-11-09. Independent research solely on `research/windows-wfp-ale-attribution-20261107`; not beta, PR #56, release, G2, PacketBound or leak-free acceptance. No driver/filter/callout, VNC, CI, runner, services, network, Windows security or automation mutation.

## Source freeze
Research parent `82e72312dafe889c9bb0ffc601fcaff630c5ed57` (tree `aeb4f9044d87ff3976b6a1c6508fbabd2d9797cc`); main `5b5afc2feeda2195f302380e615ba003d4906e09`.
- `research/wfp-ale/kernel-r19/kernel/src/lib.rs`, Git blob `0af6d4539673d2894cbaa91af0ea8f3524862a26`: all four `FWPS_CALLOUT1` registrations omit `flowDeleteFn`; both classify functions discard `_flow`. No flow-association call.
- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs`, blob `9a07e026134d46ef646d39862bd982cc48bbc5f6`: unconditional `IS_REAUTHORIZE` rejection.
- `research/wfp-ale/kernel-r19/kernel/src/handoff.rs`, blob `e1d17217db50362ba9c4efc83af820b6beb094cf`: one-use `Book::take` consumes ticket, with no established-flow AUTH ledger.

## Windows contract
`FwpsFlowAssociateContext0(flowId,layerId,calloutId,flowContext)` associates a nonzero context only for the specified layer and callout. Without registered `flowDeleteFn` it returns `STATUS_INVALID_PARAMETER`. A duplicate association returns `STATUS_OBJECT_NAME_EXISTS`. It does not document automatic context handoff among CONNECT_REDIRECT, AUTH_CONNECT and STREAM. A classify `flowContext` is zero without an existing association. `FWPS_METADATA_FIELD_FLOW_HANDLE` must be present before reading `flowHandle`; availability at initial AUTH and every reauthorization is not established.

`FwpsFlowRemoveContext0` returns `STATUS_PENDING` if an active classify is underway and calls `flowDeleteFn` asynchronously; `STATUS_SUCCESS` calls it synchronously. Cleaning up a flow context is distinct from synchronously canceling policy permits, original process egress, or buffered SSH bytes. The model requires a logical terminal tombstone **before** remove, and retains associated memory until its delete callback. Neither source nor docs establishes the exact session/ticket/epoch join through PEND/COMPLETE/policy reauthorization or proves BFE dispatch under `FWP_EMPTY`.

## Executed negative test and independent verification
A separate dependency-free Python reference simulator ran **26/26 PASS** unit tests; the standalone Node oracle published in `r56/r56_publish_oracle.mjs` and an additional independent Node oracle match Python's **262,144** synthetic states (IPv4/IPv6 × completion/policy × 2^16 assumed trust bits): **4** conditional permits, **131,072** flow-handle-only permits, **131,068** false additional permits, **16/16** weakened-guard witnesses. Cross-verifier checked 11 counts and trace sets.

Of 12 modeled orders satisfying REMOVE before DELETE, two weak-policy traces, RCTD and RCDT, leave a hypothetical classify able to consult the stale record before terminal tombstone and deferred delete. Requiring TOMBSTONE before REMOVE eliminates those two counterexamples in the model. This **does not demonstrate** actual Windows scheduling, kernel-origin evidence, owner-death synchronization, or physical packet transmission.

Other tests cover missing flow metadata, wrong layer/callout, absent flowDeleteFn, conflicting association, delayed/double delete, reused flow identifier/PID with different process epoch, session/ticket replay, IPv4/IPv6 mismatch and WFP/SSH-loss gates. The full code, logs, results and SHA256 manifest are in the R56 checkpoint. Rust compiler unavailable; no Rust or native Windows execution claimed. No callback != OS BLOCK.

## Decision / next experiment
**NO-GO:** flowHandle or flowDeleteFn alone cannot certify source EXE, PID+creation epoch+start key, exact opaque AppId, original destination, kernel-issued ticket or safe reauthorization continuity. A scoped flow-context plus prior software tombstone is only a conditional cleanup design. The full trust chain also needs actual accepted-socket `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS`, outgoing `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`, authenticated SSH and independent selected/sibling DIRECT, DNS/UDP/QUIC and IPv4/v6 physical loss tests, behind separate driver/VNC/SYSTEM rescue/rollback gates. Historical G1 `dd1ab3c` remains separate.

R57: independently inspect `FWP_CALLOUT_FLAG_ALLOW_RECLASSIFY` and documented flow-capable layers/metadata; test user-mode state machine with tombstone-before-remove and delayed callback ownership, without inventing cross-layer joins or running a driver.

Official Microsoft sources (2026-11-09):
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsflowassociatecontext0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsflowremovecontext0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/associating-context-with-a-data-flow
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_classify_fn1
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_flow_delete_notify_fn0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_callout1_
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
