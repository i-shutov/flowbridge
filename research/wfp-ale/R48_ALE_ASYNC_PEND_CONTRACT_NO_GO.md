# R48 — ALE async pending cannot be substituted for a redirect or owner-exit fence

2026-11-08. Independent source-only WFP/ALE R&D; branch `research/windows-wfp-ale-attribution-20261107` **only**. Not beta / PR #56 / PacketBound G2 / native acceptance. No WFP driver, filter, runner, network, Windows settings, services or automation changes.

## Pinned read-only source
- Parent research HEAD `f6dc2ce60572d15988ef867fd7be83e9088b01c1`; parent root tree `c9c382c35e0757b48725c14bda7ce2b253e2faae`.
- Main `5b5afc2feeda2195f302380e615ba003d4906e09`.
- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs` blob `9a07e026134d46ef646d39862bd982cc48bbc5f6`; `kernel/src/lib.rs` blob `0af6d4539673d2894cbaa91af0ea8f3524862a26`.
- Only the **inline** `ALE_CONNECT_REDIRECT` publish and the `ALE_AUTH_CONNECT` verification path were inspected. No kernel execution.

## Three distinct WFP API contracts
1. **`FwpsPendOperation0` + `FwpsCompleteOperation0`:** official docs list only `ALE_RESOURCE_ASSIGNMENT`, `ALE_AUTH_LISTEN` and `ALE_AUTH_CONNECT` as eligible source layers. `ALE_CONNECT_REDIRECT_V4/V6` is **not documented** as eligible. At `ALE_AUTH_CONNECT` only the initial authorization can pend; `FWP_CONDITION_FLAG_IS_REAUTHORIZE` yields `STATUS_FWP_CANNOT_PEND`. Completion triggers another `AUTH_CONNECT` classify (reauthorization), not a redirect publication or an SSH packet-drain witness. A unique pending-flow state must be preserved.
2. **`FwpsPendClassify0` + `FwpsCompleteClassify0`:** a different classify-handle mechanism. `FwpsPendClassify0` can return `STATUS_FWP_CANNOT_PEND` when the engine rejects async classification at the current layer. Neither general success for the exact CONNECT_REDIRECT path nor cancellation of already claimed SSH bytes is established. `FwpsCompleteClassify0` with NULL `classifyOut` triggers **reauthorization, not permit**; non-NULL is a final callout classification, not a physical-egress receipt.
3. **`FwpsAcquireWritableLayerDataPointer0` + `FwpsApplyModifiedLayerData0`:** modifies `FWPS_CONNECT_REQUEST0`; `Apply` returns `void`, must be called following a successful writable acquisition even when no changes are made, and inline calls must use flags=0. No atomic owner-death fence follows from it.

**New NO-GO:** replacing R46's inline redirect publish with `FwpsPendOperation0` at `CONNECT_REDIRECT` has no documented foundation. Pending initial AUTH and later reauthorizing cannot convert a delayed process-exit notification into a synchronous denial of all egress. Treating `FwpsPendClassify0` as universally available is equally unjustified. Fail-closed handling of CANNOT_PEND is required.

## Deterministic negative evidence
- Standalone Python negative suite: **14/14 PASS**; independent Node enumeration (published as `r48_independent_oracle.mjs`): **48 modeled states**; counts agree.
- Exactly **8 model authorizations**, including **4 after physical owner death before the kernel callback is observed** (2 IPv4, 2 IPv6). Zero authorizations when callback is observed, process epoch mismatches, or SSH health is lost. A model authorization is **not evidence of physical packets**.
- **5/5** deliberate mutations (ignore callback, epoch, SSH loss, incorrect reauthorize pending, NULL complete = PERMIT) detected by negative tests.
- Python suite, mutation harness, source hashes and execution logs are in the R48 checkpoint. Rust compilation **not executed**; rustc/cargo unavailable. Windows execution **not attempted**.
- The oracle intentionally models the missing callback-delivery interval, not claims about actual Windows execution ordering or documentation of native packet transmission.

## Trust boundary and next experiment
The original AppId, `FWPS_METADATA_FIELD_PROCESS_ID` and endpoint from the SAME native `ALE_CONNECT_REDIRECT_V4/V6` and `AUTH_CONNECT_V4/V6` classify must be bound to referenced process + creation epoch + canonical EXE at permissible IRQL. `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS / CONTEXT)` on the accepted socket, `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on outgoing socket, and one-use kernel claim each have separate proof obligations. Neither PID / 5-tuple correlation nor WFP redirect records alone are owner authentication. Sibling DIRECT, DNS/UDP/QUIC and IPv4/IPv6 policy completeness are not demonstrated.

**Next safe experiment:** inspect `auth_classify` source handling of legitimate AUTH reauthorization; model `PEND -> COMPLETE -> REAUTHORIZE` with exact session/ticket/epoch and late/duplicated receipt, then separately test already-claimed user-mode worker revocation. No driver or WFP activation.

**NO-GO remains:** kernel-origin issuance proof; owner-death callback bound; native async support at actual redirect path; packet-level termination on SSH/WFP loss; restart/re-arm; sibling DIRECT; DNS/UDP/QUIC; full IPv4/v6 egress; PacketBound/G2 and leak-free.

## Official sources
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendoperation0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendclassify0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscompleteclassify0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsapplymodifiedlayerdata0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
