# R58 — parallel pending AUTH_CONNECT: completion reason is not a private-ticket identity

2026-11-09. Independent FlowBridge WFP/ALE research only. Branch research/windows-wfp-ale-attribution-20261107. NOT beta, PR #56, G1, PacketBound/G2, no-DIRECT or leak-free acceptance. No driver/callout/filter, runner, services, network settings, VNC, protection or automations changed.

## Exact source baseline

Research HEAD affe7f02841053b9111933947de5b73094279ea6, tree 41d9537f87fdc657622180e449b0df827b6978a8. Main (read only) 5b5afc2feeda2195f302380e615ba003d4906e09.

Pinned source blobs:
- kernel-r19/kernel/src/redirect.rs: 9a07e026134d46ef646d39862bd982cc48bbc5f6 — current AUTH explicitly rejects all REAUTHORIZE; requires selected original AppId, processId, endpoint, destination, kernel book, health.
- kernel-r19/kernel/src/handoff.rs: e1d17217db50362ba9c4efc83af820b6beb094cf — one-use ticket and attestation, no pending completion join.
- kernel-r19/kernel/src/lib.rs: 0af6d4539673d2894cbaa91af0ea8f3524862a26 — four callouts, no pending state or flowDelete callback.
- kernel-r19/policy_windows.rs: acf60334320d970f58af3349ee75fbaa59826602 — two-condition original-AppId+TCP scoped AUTH filters; FWP_EMPTY dispatch not proven.

All paths are under research/wfp-ale/.

## Primary official WFP contract

- FwpsPendOperation0 takes FWPS_INCOMING_METADATA_VALUES0.completionHandle (valid iff FWPS_METADATA_FIELD_COMPLETION_HANDLE), and returns a completionContext for the eventual FwpsCompleteOperation0 call. The completion context is an opaque engine resource, NOT an authenticated FlowBridge private ticket.
- FwpsCompleteOperation0 triggers a second AUTH_CONNECT classify. IS_REAUTHORIZE and FWP_CONDITION_REAUTHORIZE_REASON_CLASSIFY_COMPLETION distinguish this from initial AUTH and from other reauthorization reasons. The official API does not promise that this new classify will return the original completionContext, private ticket or any other automatically joined per-operation identity.
- Microsoft explicitly instructs the driver to preserve unique per-pended-AUTH_CONNECT state so its own decision can be found on reauthorization. Documented metadata members processId, flowHandle, transportEndpointHandle and completionHandle can be used only if the corresponding presence bit is set; reauthorization may have FWP_EMPTY classifiable fields.
- FwpsPendClassify0/FwpsCompleteClassify0 is distinct: non-NULL classifyOut means final decision, NULL triggers reauthorization, and PendClassify may return STATUS_FWP_CANNOT_PEND when unsupported at the current layer. Microsoft's async ALE guide prescribes PendOperation/CompleteOperation, so PendingClassify applicability at AUTH_CONNECT is NOT asserted.

## New R58 conditional negative proof

Two initial pending connections A and B can have the same subsequently observable IP family, reused PID/5-tuple, CLASSIFY_COMPLETION reason and callback schedule if no trustworthy per-operation identity reaches that callback. A belongs to the selected image at epoch E; B can belong to a same-basename sibling at epoch E+1. Their required decisions differ. Permuting the two callback arrivals leaves the observable sequence identical; neither FIFO matching nor reason/PID/5-tuple can authenticate the correct ticket. This is a theorem for the *specified absent-witness observation*, NOT a claim that Windows always actually emits that observation.

Executed locally, NO Windows or WFP APIs: 23/23 pure Python unittest cases PASS including IPv4, IPv6, reordered COMPLETE, ticket swap, process epoch and start-key reuse, sibling AppId, session replay, wrong endpoint, revoked/SSH/WFP loss, no callback vs explicit BLOCK, and stale owner-death callback. Independent Node oracle verified 32,768 synthetic states; independent Python/Node crosscheck agreed on all 7 counts: 16,384 unobserved, 16,380 delivered rejected, 4 conditional permits requiring ALL assumed proof guards, 8,192 reason+dispatch-only permits, of which 8,188 are excess versus the strict model. Removing one of 12 required checks was detected in 12/12 one-guard mutation witnesses.

A synthetic conditional model permit REQUIRES an externally assumed authentic NativeWitness bound to exact session, issuance, origin PID+epoch+start key, AppId, endpoint, family and destination. This is NOT a real Microsoft-provided type/API, never obtained by a user-mode PID lookup, 5-tuple or redirect records alone, and certainly not proof of actual Windows egress. Pure offline tests do not prove callback dispatch or completeness on WFP/SSH loss. Rust compiler unavailable; Rust test execution NOT claimed.

## Trust chain and decision

Still required: native origin proof in ALE_CONNECT_REDIRECT_V4/V6 (exact opaque AppId and canonical EXE, referenced EPROCESS, creation epoch/start key and original destination); same-origin initial ALE_AUTH_CONNECT and nonambiguous pending/reauth join; actual accepted socket SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS; outbound SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS; authenticated SSH; selected/sibling DIRECT, UDP/DNS/QUIC, IPv4/V6 and owner exit, PID/endpoint/tuple reuse, endpoint closure, WFP/SSH loss physical observation. NO historical G1 acceptance transfer.

NO-GO for authorizing CLASSIFY_COMPLETION based on reason, queue order or private completionContext alone. A callback not delivered is UNOBSERVED, never proven OS BLOCK.

Next safe R59: independently audit the official FwpsPendClassify0/CompleteClassify0 per-layer applicability at ALE_AUTH_CONNECT, whether non-NULL final classify can avoid the pending-operation reauth join, and exact classification-handle lifetime. Any missing official guarantee -> NO-GO. No native execution authorized.

Official Microsoft documentation:
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendoperation0
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscompleteoperation0
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/ns-fwpsu-fwps_incoming_metadata_values0
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendclassify0
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscompleteclassify0
