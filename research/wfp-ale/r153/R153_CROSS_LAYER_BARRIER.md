# R153 — ALE endpoint closure pend is not a global AUTH/CLAIM drain proof

Date: 2026-11-13. Repository: i-shutov/flowbridge.
Branch: research/windows-wfp-ale-attribution-20261107 ONLY.
Research base HEAD: fb88fc727d1d3d7b6170ea79a9bc9c9ee5e5c156.
Main observed: 5b5afc2feeda2195f302380e615ba003d4906e09.
NOT beta, NOT PR #56, NOT native WFP acceptance.

## Documented architectural boundary

Microsoft explicitly permits a callout at FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4/V6 to postpone *that closure classification* through FwpsPendClassify0 and FwpsCompleteClassify0, e.g. to reinject its own queued packets before endpoint shutdown. Its published contract does not certify global quiescence of older ALE_AUTH_CONNECT classify callbacks or of external FlowBridge broker/CLAIM consumers, and does not establish never-reused numeric endpoint handles.

These distinct operations are **not interchangeable**:

- Closure: FwpsAcquireClassifyHandle0 / FwpsPendClassify0 / FwpsCompleteClassify0. Completion removes the indicated pended classification. FwpsCompleteClassify0 with NULL classifyOut may trigger reauthorization.
- Initial ALE_AUTH_CONNECT: FwpsPendOperation0 / FwpsCompleteOperation0. Completion triggers a reauthorization; callout must maintain unique per-pended-operation state.
- Reauthorized ALE_AUTH_CONNECT: FwpsPendOperation0 fails with STATUS_FWP_CANNOT_PEND when FWP_CONDITION_FLAG_IS_REAUTHORIZE is set. It cannot be used as a generic barrier.

Official docs consulted 2026-11-13:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendclassify0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscompleteclassify0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendoperation0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization

## Executable test, strictly non-native

The countermodel gives closure stronger-than-minimal assumptions: CLOSE_ENTER -> CLOSE_PEND -> CLOSE_OWN_WORK_DONE -> CLOSE_COMPLETE, and permits numeric handle reissue only AFTER completion. It deliberately does NOT invent a cross-layer "all old AUTH/CLAIM operations drained" ordering edge. It enumerates 28 topological schedules and 224 cases across IPv4/IPv6, same/different visible tuple and reuse/quarantine decisions. This is a logical counterexample to declaring tombstone reuse safe *merely because closure finished*, **not proof Windows delivers stale callbacks or recycles numeric handles**.

Both implementations executed independently on Linux CPython 3.13.5 / Node 22.16.0. Python normal, -O, -OO, and independent Node generated the same 224-row SHA256:

`246b2b18f14bdc78bf411643c7872cc033fa578e2e54fb7051fb3ecdffa6c927`

Categories: REUSE_QUARANTINED 112; OLD_AUTH_BEFORE_NEW_ISSUANCE 60; OBSERVABLE_DIFFERENCE 26; STALE_AUTH_ALIAS 26 (hypothetical). Six additional unit/negative tests PASS. A deliberate mutation of pinned R152 input is rejected in normal/-O/-OO. No kernel driver, WFP filter, Windows host, native Rust or actual packet test was executed.

Source pin on R152: r152_aba_negative.py git blob ab703d06ab07ac003b0ea3c4aded0ab02a0e2b68. Independent GitHub source verification: R19 kernel/src/handoff.rs blob e1d17217db50362ba9c4efc83af820b6beb094cf and kernel/src/redirect.rs blob a093f049d162987981a957aac90db1014bc6ff09. R19 local pin is optional and NOT run this cycle.

Reproduce from repository root:

```sh
python -B research/wfp-ale/r153/r153_cross_layer_barrier.py --r152-source research/wfp-ale/r152/r152_aba_negative.py
python -O -B research/wfp-ale/r153/r153_cross_layer_barrier.py --r152-source research/wfp-ale/r152/r152_aba_negative.py
python -OO -B research/wfp-ale/r153/r153_cross_layer_barrier.py --r152-source research/wfp-ale/r152/r152_aba_negative.py
node research/wfp-ale/r153/r153_independent.mjs
python -B research/wfp-ale/r153/test_r153.py
```

## Trust chain / next decisive experiment

Required end-to-end proof: PsSetCreateProcessNotifyRoutineEx/PS_CREATE_NOTIFY_INFO + referenced EPROCESS, PID + creation epoch/start key + canonical executable + opaque WFP AppId -> actual ALE_CONNECT_REDIRECT_V4/V6 and ALE_AUTH_CONNECT_V4/V6 with endpoint handle, compartment, reauth and action-rights proof -> FWPS_CONNECT_REQUEST0 and redirect context -> actual accepted-socket WSAIoctl SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS -> one-shot CLAIM -> physical SSH socket SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS before connect -> separately proven sibling DIRECT and DNS/UDP/QUIC denial through WFP/BFE/SSH loss.

PID/5-tuple retrospective correlations are never kernel ownership proof. Read-only WFP metadata inspection is allowed next but cannot show callback ordering. A decisive runtime experiment would require explicit new authorization plus driver/VNC/SYSTEM rescue/rollback gates, observing native endpoint issue, AUTH entry/reauth, closure and own pending completion, handle reuse, broker CLAIM lifetime, independent outgoing traffic.

Architecture NO-GO. No PacketBound/G2 PASS, no no-DIRECT/leak-free assertion, no historical G1 promotion. No WFP objects, services, firewall, networks, security settings, runners, other repositories, automation states, main, beta or PR #56 touched.
