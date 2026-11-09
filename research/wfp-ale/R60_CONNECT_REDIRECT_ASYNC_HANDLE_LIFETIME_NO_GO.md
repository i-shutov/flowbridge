# R60 — Async CONNECT_REDIRECT classify handles: narrow GO, owner-lifetime NO-GO

Date: 2026-11-09. **Only** research/windows-wfp-ale-attribution-20261107 (independent architecture R&D; NOT beta, PR #56, G1 transfer, G2, PacketBound, no-DIRECT or leak-free). No kernel driver/callout/filter/VNC, service, network, firewall, runner, security-setting or automation changes.

## Fresh read-only baseline

- Research parent: 3f34bfba3322fdc10b6fc748519647faf13a5de8, tree 0748a25b8cf588683ff4e9d68eb6ea53039868cb.
- Main: 5b5afc2feeda2195f302380e615ba003d4906e09.
- Rust source blobs: kernel/src/redirect.rs 9a07e026134d46ef646d39862bd982cc48bbc5f6, kernel/src/lib.rs 0af6d4539673d2894cbaa91af0ea8f3524862a26, kernel/src/handoff.rs e1d17217db50362ba9c4efc83af820b6beb094cf; policy_windows.rs acf60334320d970f58af3349ee75fbaa59826602. All under research/wfp-ale/kernel-r19/. Current redirect implementation is **inline**; nothing here implements pended kernel redirection.
- Repository tree contains no AGENTS.md. Owner's strict scope/gates apply.

## Documented API contract and the new narrow GO

Microsoft [Using Bind or Connect Redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection) explicitly describes the asynchronous **ALE_CONNECT_REDIRECT_V4/V6** path:

1. FwpsRedirectHandleCreate0 / FwpsQueryConnectionRedirectState0, FwpsAcquireClassifyHandle0; ensure selected app, protocol, original endpoint and redirect state are trustworthy at the initial kernel classify.
2. FwpsPendClassify0 returns STATUS_SUCCESS; return BLOCK in the initial classify (clear ACTION_WRITE) and retain a deep copy of classifyOut for the worker. Handle STATUS_FWP_CANNOT_PEND or errors without pretending to have pended.
3. FwpsAcquireWritableLayerDataPointer0 -> FWPS_CONNECT_REQUEST0; use only documented mutable members, including localRedirectTargetPID + localRedirectHandle for Windows 8+ local redirection; FwpsApplyModifiedLayerData0 **even if unchanged**.
4. FwpsCompleteClassify0(non-NULL deep-copy): final callout classify, **not** a packet delivery/egress receipt. NULL triggers reauthorization. Apply/Complete both return void. Balance local/engine classify-handle references and do not reuse completed handles.

[PendClassify docs](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendclassify0) explicitly say it increments classify-handle refcount; [CompleteClassify docs](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscompleteclassify0) say it consumes a previously pending classify operation. A handle identifies **this redirect-classification request** (a narrow continuation key): the worker need not rediscover it by PID or reused 5-tuple. It is **not a kernel-origin owner certificate**, and no documented API returns this same handle to a subsequent ALE_AUTH_CONNECT callback. R58/R59 AUTH reauthorization join is unresolved.

## Executed clean-room negative experiment

Published executable: r60/independent_oracle.mjs; independent Python stdlib reference, 12 unit tests, results and SHA256 in the conversation checkpoint. No sockets or Windows API calls, no driver and no Rust compilation.

- 15,120 distinct labeled schedules: 7,560 per IPv4 and IPv6. Two pending classifications A/B reuse PID and 5-tuple but have different process epochs and classify handles. **Physical exit of A precedes B's new process connection**, and the processed exit callback may lag. Each A/B requires PEND<APPLY<COMPLETE; physical exit<callback; sticky observed SSH/WFP losses may interleave arbitrarily.
- Weak snapshot-only delayed complete: 30,240 synthetic PERMIT decisions, 27,360 **after observed** SSH/WFP loss, and 12,420 completions for which last-issued tuple entry points at the other request. These are model counts, NOT Windows packets or observed misroutes.
- Strong handle-bound completion + fresh **observed** health/callback checks: 2,292 conditional model PERMITs; zero after an *observed* terminal loss or processed A-exit callback, but **1,092 A completions after physical death and before notification**. Thus observed-health checks cannot establish a physical owner-death egress fence. 612 permitted completions would have misidentified the request using tuple-last-issuer instead of handle.
- Python and independently implemented Node agree in every counter and full decision-stream SHA-256: bcf13aa740678edb589b3f37f6cb0939160f219865576f2db3d6e519bde81b9c. Python tests 12/12 PASS; duplicate complete, failed pend, and handle reference-accounting boundaries covered. The schedule is hypothetical; callback latency, PID reuse and real WFP dispatch must be native-proven.

## Trust chain / NO-GO and next test

Initial identity requires kernel WFP AppId + referenced PEPROCESS/epoch/start-key (PsSetCreateProcessNotifyRoutineEx, PsGetProcessCreateTimeQuadPart, PsGetProcessStartKey), canonical executable, genuine original destination + endpoint, correct IPv4/v6 policy and dispatch. Pended redirect requests need one-shot classify-handle lifetime, checked WFP/SSH health, redirect-state/other-callout history, and documented FWPS_CONNECT_REQUEST0 ownership. AUTH_CONNECT requires independent redirected original-appId/endpoint metadata (checking FWPS_METADATA_FIELD presence). User-mode proxy needs WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT) on the accepted original endpoint and SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on its outbound proxy socket, plus a non-forgeable one-shot kernel CLAIM. No PID+tuple correlation, redirect-record bytes or local port is an owner certificate.

**Narrow GO:** eligible API and scope-specific per-classify continuation key at CONNECT_REDIRECT. **NO-GO:** cross-layer AUTH provenance, callback-delivery bound, post-CLAIM queued bytes, sibling DIRECT, DNS/UDP/QUIC, physical v4/v6 egress, WFP/SSH loss safety, no-DIRECT/leak-free, PacketBound/G2. No kernel-native proof. R61: examine redirect-record/context ownership across WSAIoctl accepted/outbound socket and kernel CLAIM; test replay, cross-socket swap and aborted pended classify without installing/running drivers or filters.

Other official references:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsacquirewritablelayerdatapointer0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsapplymodifiedlayerdata0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-_fwps_connect_request0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
