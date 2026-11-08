# R47 — WFP/ALE redirect publication: three contracts, one unresolved physical-exit gap

2026-11-08. Independent source-only R&D, **only** `research/windows-wfp-ale-attribution-20261107`. Not beta, PR #56, driver execution, PacketBound/G2, no-DIRECT, leak-free or historical G1 acceptance. No kernel/WFP filters, services, runner or security settings were touched.

## Pinned source
- Parent research HEAD: `2a73962ea03b029c628122bee04ec4582c864904`; parent root tree: `7f5225dd9b6c5dcf9cf6e1c1f728ace796ecdf47`.
- Main: `5b5afc2feeda2195f302380e615ba003d4906e09`.
- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs` blob: `9a07e026134d46ef646d39862bd982cc48bbc5f6`.
- `kernel/src/lib.rs` blob: `0af6d4539673d2894cbaa91af0ea8f3524862a26`.
- `kernel/src/handoff.rs` blob: `e1d17217db50362ba9c4efc83af820b6beb094cf`.
- `broker.rs` blob: `ce6c549a9ae488cc7c0ca9a7e7be68871b9d7f2c`.

Source check: `Book::issue` is serialized under `Guard`, but a later `FWP_ACTION_PERMIT` and `FwpsApplyModifiedLayerData0` happen *after* that guard is dropped. The process-exit callback uses `Guard`, as does the one-use kernel CLAIM with `ready()`. Thus an *attempt* to publish after a processed exit callback is source-order possible; a fresh CLAIM after a broker exit is not.

## Three competing proposals and their limits

The clean-room schedule model separates `X` (physical death) from `N` (processed exit callback); `X<N`, but no bounded delay is assumed. `U` reuses a PID and tuple with a different process epoch, `L` denotes terminal health loss, `A` AUTH attestation, `K` CLAIM, `B` attempted user-mode copy.

| Contract | Ordering | Post-callback attempted WFP publication? | Post-physical-exit attempted publication? |
|---|---|---|---|
| Recheck | `I -> V -> P` | YES: `I V X N P` | YES |
| Generation fence at AUTH/CLAIM | `I -> P`, later epoch check | YES: `I X N P` | YES |
| Ideal atomic ISSUE+APPLY relative to callback | `T` | NO, **only under ideal shared serialization** | YES: `X T N` |

A lock around kernel bookkeeping and WFP API calls is **not** an approved implementation: lock/IRQL/reentrancy safety is not established. Serialization with the callback does not serialize *physical process death* or actual packets. Nor does it retroactively revoke a worker already admitted by CLAIM. Crucially, `FwpsApplyModifiedLayerData0` returns **void**: there is no status-based commit success / packet-drain witness. `FwpsCompleteClassify0` is also void and only completes pended classification.

## Independently executable negative evidence

- Local clean-room Python partial-order model: **11/11 tests PASS**.
- Independent Node oracle agrees exactly on all counters and witness traces, across **6,496** synthetic schedules total (both families).
- `r47/independent_oracle.mjs` is a standalone independent runnable oracle published with this report.
- Local pure Rust std-only source has 14 tests written but **NOT COMPILED** (no rustc/cargo); it is in the R47 checkpoint archive, not this Git change.
- Mutation check: removing the callback guard from the ideal atomic model produces **2 expected test failures**. This checks that the property is actually tested.

Per **IP family**:

| Contract | Traces | Attempts after processed EXIT | Attempts after physical EXIT | Copies after physical EXIT | Copies after callback |
|---|---:|---:|---:|---:|---:|
| Recheck | 1680 | 180 | 900 | 72 | 24 |
| Generation | 1008 | 108 | 540 | 60 | 20 |
| Ideal serialized | 560 | **0** | 160 | 48 | 16 |

Numbers are MODEL COUNTS, NOT observed Windows events or packets. Newly attested/claimed flows after a processed callback and claims to a reused process epoch are denied in the model. Sticky health loss prevents subsequent copy admission. An already claimed copy can still be admitted after source exit until relay revocation is observed.

## Documentary proof boundary

- Process/EXE identity: `PsSetCreateProcessNotifyRoutineEx`, referenced `PEPROCESS`, `PsGetProcessCreateTimeQuadPart`, `PsGetProcessStartKey` and pinned canonical executable. PID/5-tuple alone are not identities; callback processing is not guaranteed synchronous with physical egress.
- WFP: `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6`, `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6`, selected and original AppId, endpoint and original destination metadata; all need native provenance proof. `FwpsAcquireClassifyHandle0`, `FwpsAcquireWritableLayerDataPointer0`, `FwpsApplyModifiedLayerData0`, `FwpsReleaseClassifyHandle0` support data editing but do not document global owner-death or egress fencing.
- Handoff: `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS / CONTEXT)`, `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`, one-shot kernel CLAIM. None replaces kernel-issued identity.
- `FwpsPendClassify0` may return `STATUS_FWP_CANNOT_PEND`; pended/inline variants require separate native API-safety analysis. The `REAUTHORIZE_IF_MODIFIED_BY_OTHERS` option must NOT be used in inline `FwpsApplyModifiedLayerData0`.

Official Microsoft references:
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsapplymodifiedlayerdata0
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsacquirewritablelayerdatapointer0
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendclassify0
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscompleteclassify0
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex

**Conditional model-level GO:** only callback-order atomicity, NOT Windows implementation or physical owner-liveness.

**NO-GO:** kernel-origin issuance, owner-exit latency bound, claimed-worker revocation, sibling DIRECT, DNS/UDP/QUIC, IPv4/IPv6 physical egress, WFP/SSH loss packet drain, restart/re-arm, PacketBound/G2 and leak-free.

**Next decisive permitted experiment:** compile the Rust std-only user-mode model (not a driver, no runner/network), then model inline vs pended classify completion and per-ticket exit-ACK barriers. If no documented physical-eject/egress bound exists, stop with NO-GO. Never propose holding a kernel spinlock across WFP calls without an independent API/IRQL safety proof.
