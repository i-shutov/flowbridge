# R59 — AUTH_CONNECT cannot be replaced with FwpsPendClassify finalization (source-verified NO-GO)

Date: 2026-11-09. Scope: **only** `research/windows-wfp-ale-attribution-20261107`; no beta, PR #56, G1 transfer, G2/PacketBound, no-DIRECT or leak-free claims. No kernel driver, callout, filters, runner, service, firewall, VNC, network, OS protection, signing or automation changes.

## Exact read-only baseline

Research parent `6192d03868697a2780aa67e361c28eb79564d7e2`, tree `01e7999b79d4c0b02f036a01809330f2ffc7120c`. Main `5b5afc2feeda2195f302380e615ba003d4906e09`.

Pinned source blobs (all under `research/wfp-ale/kernel-r19/`):
- `kernel/src/lib.rs`: `0af6d4539673d2894cbaa91af0ea8f3524862a26`; `auth_callback` delegates to `redirect::auth_classify`; four `FWPS_CALLOUT1` registrations.
- `kernel/src/redirect.rs`: `9a07e026134d46ef646d39862bd982cc48bbc5f6`; AUTH_CHECK rejects reauthorize, redirect uses writable-layer-data APIs.
- `kernel/src/handoff.rs`: `e1d17217db50362ba9c4efc83af820b6beb094cf`; one-use issue/attest/take; no verified pending-operation identity join.
- `policy_windows.rs`: `acf60334320d970f58af3349ee75fbaa59826602`; AUTH BFE filter matches ORIGINAL_APP_ID and TCP; no proof of dispatch with FWP_EMPTY.

## Decisive official layer/API split

Microsoft **Types of Callouts** explicitly enumerates the following DOCUMENTED uses:

| Asynchronous primitive | Listed layers (each for V4 and V6) | Consequence |
| --- | --- | --- |
| `FwpsPendOperation0` | `ALE_RESOURCE_ASSIGNMENT`, `ALE_AUTH_LISTEN`, `ALE_AUTH_CONNECT` | At initial `ALE_AUTH_CONNECT`, `FwpsCompleteOperation0` triggers a new AUTH reauthorization; the driver must find its unique pending decision |
| `FwpsPendClassify0` | `ALE_ENDPOINT_CLOSURE`, `ALE_CONNECT_REDIRECT`, `ALE_BIND_REDIRECT` | `FwpsCompleteClassify0` with NON-NULL `classifyOut` is the callout's final classify decision, NULL triggers reauthorization |

**R59 NEW NO-GO:** `ALE_AUTH_CONNECT_V4/V6` is NOT in the official `FwpsPendClassify0` layer list. Therefore R58's hoped-for `FwpsPendClassify0 -> FwpsCompleteClassify0(NON-NULL)` substitution at AUTH_CONNECT is **not a documented solution** to its missing pending-to-reauth ticket join. The general PendClassify API reference is not a blanket guarantee of eligibility at arbitrary layers. It explicitly permits `STATUS_FWP_CANNOT_PEND` when the engine disallows async classify at the current layer.

**Narrow possible R60 exploration:** `ALE_CONNECT_REDIRECT_V4/V6` *is* in the listed PendClassify layers, so async redirect classify is a source-supported avenue to investigate. But presence on the list DOES NOT establish actual STATUS_SUCCESS, safe writable-layer mutation or Apply ordering, owner lifetime, AUTH_CONNECT continuity, denial of sibling DIRECT, or physical egress. No native calls were run.

Per `FwpsAcquireClassifyHandle0` and `FwpsPendClassify0`, a classify handle belongs to a particular classify request, is reference-counted, and requires correct release; it is not a kernel-origin process identity or redirect-context ticket. An authentic WFP AppId/canonical EXE + referenced process/creation epoch/start key + original destination, session/issuance, accepted-socket redirect context/records, and egress WSAIoctl records still require separate proof.

## Executed deterministic offline negative experiment

- **22/22** Python stdlib unit tests PASS (IPv4/IPv6, BOTH API domains, initial/re-auth, CANNOT_PEND, NULL/non-NULL completion, missing classify/completion handle, missing callback, missing native origin witness, SSH/WFP loss, UDP outside TCP, FLOW_ESTABLISHED/RECV_ACCEPT disallowed substitution).
- **18,432** modeled states enumerated independently by Python and Node, with exact agreement of all 12 outcome categories and entire decision-stream SHA-256 `2eeafe9c243da26890e0bd64b8c553198062151a90c6e1007f646548fd924f4a`.
- 3,072 states: undocumented API/layer pair, 9,216: callback not observed, 4,608: UDP outside this TCP contract, 128: OPERATION cannot pend AUTH reauthorization, 352: PEND_FAILED.
- 12 conditional NON-NULL final CLASSIFY results belong ONLY to the officially listed classify layer family *and assume* valid handle, successful pend, kernel-origin witness and healthy SSH/WFP. They are NOT Windows egress, owner attribution, redirect proof, or system PERMIT. There are **zero claimed physical permits**, zero native Windows tests, zero kernel operations.
- Rust compiler unavailable here; no Rust compilation claimed. Python/Node are clean-room, user-mode and no-driver, with no network or WFP operations.

## Scope and next decisive experiment

**GO (documented API applicability only):** evaluate PendClassify on `ALE_CONNECT_REDIRECT_V4/V6` as a distinct, narrowly scoped possibility.
**NO-GO:** using PendClassify to finalize `ALE_AUTH_CONNECT` and bypass the pending-operation identity join; assuming NULL completion permits; treating STATUS_SUCCESS on a synthetic unsupported layer as proof; treating any classify handle or 5-tuple/PID as kernel owner authority.

**Next R60:** compare documented `FwpsPendClassify0` on `ALE_CONNECT_REDIRECT` with `FwpsAcquireWritableLayerDataPointer0` / `FwpsApplyModifiedLayerData0` ownership and timing; exercise offline STOP/process-exit/broker/SSH loss between PEND and final non-NULL completion. If Microsoft does not guarantee the atomicity needed, keep NO-GO. No kernel runtime or filter changes.

The chain still NOT proven end-to-end: exact AppId/canonical EXE + PID/creation epoch/start key, originating process vs broker, v4/v6, endpoint and reused 5-tuples, sibling DIRECT, DNS/UDP/QUIC, policy reauth, closure, WFP/SSH loss, packet-level kill, no-DIRECT, PacketBound/G2 and leak-free.

Primary Microsoft sources (read 2026-11-09):
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/types-of-callouts
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendoperation0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendclassify0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscompleteclassify0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsacquireclassifyhandle0
