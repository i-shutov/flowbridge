# R46 — WFP redirect commit outside the revocation epoch (source-only NO-GO)

2026-11-08. Scope: ONLY `research/windows-wfp-ale-attribution-20261107`, independent R&D. Not beta, PR #56, driver execution, PacketBound/G2, G1 carry-over or leak-free claim.

## Pinned state and exact sources

Research parent `af916dbd528f30d08e48052b53b5debcff87dccb` (root tree `960e8909afce371d5251fccdc390a4a28b18a4ae`). Main `5b5afc2feeda2195f302380e615ba003d4906e09`, unchanged. Exact Git blobs read from this parent:

- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs`: `9a07e026134d46ef646d39862bd982cc48bbc5f6`
- `research/wfp-ale/kernel-r19/kernel/src/lib.rs`: `0af6d4539673d2894cbaa91af0ea8f3524862a26`
- `research/wfp-ale/kernel-r19/kernel/src/handoff.rs`: `e1d17217db50362ba9c4efc83af820b6beb094cf`
- `research/wfp-ale/kernel-r19/broker.rs`: `ce6c549a9ae488cc7c0ca9a7e7be68871b9d7f2c`
- `research/wfp-ale/kernel-r19/trusted-ssh-r37/src/lib.rs`: `c6d8c8746fac45073c11557de893164e49d830eb`

No source, driver, workflow, filters, services, runner or host protections are modified.

## New source-level race (both IPv4 / IPv6)

`redirect::classify` obtains `Guard` to check `ready(time)` and call `Book::issue`. After releasing that lock, success path allocates memory, changes `FWPS_CONNECT_REQUEST0`, sets `FWP_ACTION_PERMIT`, and drops `Writable`. Its `Drop` calls `FwpsApplyModifiedLayerData0` and `FwpsReleaseClassifyHandle0`. The success path does NOT recheck `ready()` and does NOT reacquire `Guard`; the lone later Guard is in an allocation-failure branch for `Book::retire`.

The process-exit callback in `kernel/src/lib.rs` uses that same `Guard`. For a BROKER exit, `redirect::process_exit` invokes `lose()`, disarming and terminally killing the Book. For selected OWNER exit, `Ledger::died` marks the owner dead without invalidating an already staged modified WFP request.

Consequently, these interleavings are not ruled out by the *source's lock contract*:

- `ISSUE(ticket) -> release Guard -> BROKER EXIT callback -> Book.kill -> FWP_ACTION_PERMIT -> FwpsApplyModifiedLayerData0`.
- `ISSUE(ticket) -> OWNER EXIT callback -> FWP_ACTION_PERMIT -> FwpsApplyModifiedLayerData0`.

**Qualified positive:** `ioctl(CLAIM)` also runs under the same Guard and requires `ready()`. A new CLAIM cannot succeed **after** the broker callback has terminally killed the Book. This does not retract a CLAIM that completed before that callback. AUTH_CONNECT also checks ready and originating owner. Thus the possible *late publication* does NOT demonstrate successful post-revocation CLAIM or packet transmission.

R41/R42 remain relevant: an already claimed user-mode SSH relay has no authoritative per-owner exit signal. An additional ready check before publication alone is NOT an atomic barrier: exit can still arrive between recheck and external WFP completion.

## Executed clean-room negative test and independent cross-check

Full local research archive (Rust user-mode model, Python tests, independent Node oracle, logs and SHA256SUMS) is delivered as `FlowBridge_WFP_R46_checkpoint.zip` through the conversation artifact; it was not placed in the repository. Its sources are read-only, create no sockets/driver/filter and use only Rust std, Python stdlib, and Node std.

- **Python:** 10/10 executable unit tests PASS.
- **Independent Node partial-order oracle:** exact agreement with Python's full state-transition enumeration.
- **Each family IPv4 and IPv6:** 8! = **40,320** abstract schedules; **5,040** with post-broker callback redirect publication, **5,040** with post-owner callback publication, **8** with modeled post-owner-exit copy, **0** successful CLAIM after broker callback. Across families: 80,640 labelled schedules.
- **Rust:** self-contained state machine with **12 tests written but not compiled or executed** (no local rustc/cargo). All schedule results are abstractions; none is a native Windows observation.
- **Source verification:** five exact Git blobs and 14/14 structural checks, including a control-flow-corrected successful-path lock check. A naive initial grep matched the allocation-error Guard; that false positive was investigated and excluded.

Representative minimal witnesses: `Issue -> BrokerExitCallback -> PublishWfp` and `Issue -> OriginExitCallback -> PublishWfp`. These are source-order possibilities, not verified operating-system event orders.

## Boundary of trust / API references

1. Identity: `PsSetCreateProcessNotifyRoutineEx`, `PsGetProcessCreateTimeQuadPart`, `PsGetProcessStartKey`, canonical executable and referenced process/image objects. PID + five-tuple are NOT identities.
2. ALE: `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6`, `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6`, `ALE_ORIGINAL_APP_ID`, redirected target PID, original destination, transport endpoint handle; no native proof of complete kernel-origin authorization.
3. WFP publish: `FwpsAcquireClassifyHandle0`, `FwpsAcquireWritableLayerDataPointer0`, `FwpsApplyModifiedLayerData0`, `FwpsReleaseClassifyHandle0`. Microsoft documents data modification, NOT a synchronous broker-loss or process-death egress fence.
4. Handoff: `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS / CONTEXT)`, `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on outbound proxy TCP socket, then one-shot kernel CLAIM. Native provenance is still unproven.
5. SSH: `PING/STOP`, `tokio::watch` and cancellation. Queued bytes, callback latency, WFP/SSH loss and OS packet delivery have no proven upper bound.

Official Microsoft:
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsacquirewritablelayerdatapointer0
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsapplymodifiedlayerdata0
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection

**NO-GO:** PacketBound/G2, owner-liveness, sibling DIRECT, DNS/UDP/QUIC, physical IPv4/IPv6 egress, leak-free, and restart recovery. The R45 one-shot broker gate is not circumvented.

## Next decisive safe experiment

Create a second clean-room Rust-only schedule oracle comparing (a) naive check, (b) generation fence, and (c) single serialized issue/publication/EXIT ordering, with explicit *external WFP completion* timing. Any future GO must identify a documented WFP completion barrier and kernel-owner event proof; an in-memory invariant by itself cannot establish one. No driver/filter/callout installation or native system changes.
