# R222 — pre-lock timestamp is not CLAIM-time freshness

Date: 2026-11-24 (local). Research branch only, parent 6edf3cd8f3aa6efefa0025a4e885e0b7eeb9382d, main read-only 5b5afc2feeda2195f302380e615ba003d4906e09. Not beta, PR #56, driver work, G2 or physical packet evidence.

## Narrow source-level NO-GO

R211 established that R201's timeless model cannot certify the time-sensitive R19 gate. R222 addresses a different boundary: the R19 adapter's own clock sample precedes the critical section.

Pinned R19 Git blobs:
- kernel/src/redirect.rs a093f049d162987981a957aac90db1014bc6ff09: line 28 samples now() before Guard::take(); line 15 ready(time) checks rollback and lease; lines 41-45 use that original sample for PING and CLAIM, including Book::take(c,time). lose() is terminal.
- kernel/src/handoff.rs e1d17217db50362ba9c4efc83af820b6beb094cf: LEASE=30,000,000 and TTL=100,000,000 in 100ns units; line 117 accepts age <= TTL.
- kernel/src/lib.rs 53f5ce6faa0f9f591974287f38ea890cafeb0dd2: Guard uses KeAcquireSpinLockRaiseToDpc.
- broker.rs 6163e84aea08ddde7e51a7fb94ccb6d68ae951fb and broker_windows.rs 329ef14b63e70226bfad7372b0014559213abd04: ordinary broker shares one Arc<Device>, opens without overlapped flag and calls synchronous DeviceIoControl.

Let S be the sample, C>=S the locked check, last the last heartbeat and issued the ticket time. Holding all other gates valid and no intervening terminal loss, the adapter checks S-last<=LEASE and S-issued<=TTL, NOT the corresponding inequalities with C. At an inclusive deadline the sample can be valid while a subsequent locked decision is past the deadline. No source proof bounds C-S to zero or gives a safety margin. This is a conditional source-order counterexample to a strict deadline at the locked admission instant, not a demonstration of an actual expired Windows flow, a leak, or an incorrect contract if the owner deliberately defines the deadline at request entry instead.

A second hypothetical case: a newer PING updates last after an earlier CLAIM sampled S but before it acquires the lock. ready(S) then sees S<last and kills the book although the physical clock did not reverse. **Ordinary same-file-object synchronous I/O is serialized by the I/O manager, so the overlapping-dispatch PING/CLAIM premise is NOT established for the normal shared Device path.** The conditional test is for the adapter's source-level contract without that serialization premise; it does not assert reachability or advise bypassing it. The first (deadline-crossing) result does not need overlapping PING and CLAIM dispatches. No earlier applied STOP, actual owner exit or other terminal loss is bypassed in this model.

Microsoft documents KeQueryInterruptTimePrecise at any IRQL, so a fresh post-lock sample is a candidate for a locked-admission contract. This is only a future design recommendation; no driver/callout was created or edited. It would not make final WFP arbitration, socket acceptance, SSH connect or packet transmission atomic with the deadline.

## Executed deterministic negatives

Python absolute-time oracle and independent Node age-domain oracle ran locally; Node syntax check PASS. 128 synthetic rows, 26 old admits with corrected locked-time rejection, 12 conditional false terminal losses (overlap premise above). IPv4/v6 labels; both oracles asserted ten explicit boundary/control witnesses. Exact same canonical CSV SHA-256: 4eab5057fe73f76bf38ec46cfcea3a7ad45c88d702692762d9e2b2a5b130af52. These are bounded symbolic cases, not probabilities. Ten source predicates independently verified against pinned GitHub source. Executed test blob SHAs: negative.py 77968cc7b1b5bfc29c5e787a9c81c75191e93191; independent.mjs f055da2dde21d30924601d04958b3de4a1a7a864.

    python3 negative.py
    node --check independent.mjs
    node independent.mjs

Rust compiler/cargo unavailable here; no Rust or Windows runtime test. No new Rust adapter code is proposed for execution.

## Remaining trust boundary and next decisive experiment

Referenced EPROCESS/FileObject from PsSetCreateProcessNotifyRoutineEx -> PID/creation epoch/start key/canonical EXE and FwpmGetAppIdFromFileName0 -> native ALE_CONNECT_REDIRECT / AUTH_CONNECT V4/V6, FwpsQueryConnectionRedirectState0, original AppId/endpoint/original destination and final arbitration -> actual accepted SOCKET with SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS -> one-use CLAIM -> SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS -> authenticated physical SSH. No kernel-origin or final egress proof. Process death/PID reuse, 5-tuple reuse, sibling DIRECT, dual-stack/compartment, DNS/UDP/QUIC and BFE/WFP/SSH loss remain NO-GO.

Next permitted experiment: pure Rust user-mode exact-source time-boundary composition with explicitly injected sample and locked times; compile and run R201/R202/R218-R221 and this contract in an admitted offline toolchain. Native timing/dispatch/classify requires separate owner authorization and all rescue/rollback gates. Do not infer a physical result from synthetic tests. PacketBound/G2, no-DIRECT, leak-free and historical G1 are not claimed.

Official references:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryinterrupttimeprecise
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keacquirespinlockraisetodpc
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatefile
- https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration

Only new research/wfp-ale/r222 files. No protected branch, PR, driver/callout, WFP policy, runner, services, security, network or automation changes. No paid operation or prohibited source.
