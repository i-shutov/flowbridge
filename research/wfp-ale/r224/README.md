# R224 — AUTH double-sample contract discrimination, not a new native bypass

2026-11-24. Research branch only: research/windows-wfp-ale-attribution-20261107, parent 69b498290a675f7eca9907b1481fafc8d2ee82ba; main read-only 5b5afc2feeda2195f302380e615ba003d4906e09. R222/R223 remain conditional on strict locked-time semantics.

## New executed result: distinguish the temporal specifications

Pinned R19 redirect.rs blob a093f049d162987981a957aac90db1014bc6ff09: auth_check takes Guard::take, calls ready(now()), checks owner/destination, then route.book.attest(identity, original_destination, now()). Unlike R222/R223, both AUTH samples occur inside the same critical section. handoff.rs blob e1d17217db50362ba9c4efc83af820b6beb094cf: LEASE=3s, TTL=10s, inclusive bounds; attest sets auth_seen=true; take requires auth_seen and a still-valid ticket. lib.rs blob 53f5ce6faa0f9f591974287f38ea890cafeb0dd2: Guard uses KeAcquireSpinLockRaiseToDpc.

Let H be the last heartbeat, I the issue time, S the first AUTH sample, A the second and Q the subsequent fresh CLAIM sample. Assume monotone H<=S<=A<=Q, I<=S, all non-temporal guards true, one previously un-attested ticket and no intervening renewal or loss. R19's predicate is S-H<=LEASE and A-I<=TTL. A coherent first-sample contract uses S for both; a strict second-sample contract uses A for both. The old split predicate is a subset of the first-sample predicate, but not of the second-sample predicate. Thus a strict attest-time lease can be exceeded (S=H+LEASE-1ms, A=H+LEASE+1ms), while an entry-time lease is not violated by this example. Conversely, crossing TTL between S and A can reject a ticket that was valid at S.

Crucial negative result: with a subsequent fresh CLAIM and no renewal, all three models agree on CLAIM. If split AUTH accepted when the lease had expired by A, Q>=A ensures the fresh gate latches loss. If the split AUTH rejected due to ticket TTL at A, Q>=A means the ticket is still expired. Even a fresh PING after A cannot repair an expired lease; stale pre-lock PING remains the separate R223 problem. The test matrix does not model intervening PING, concurrent state changes, clock rollback, actual callback execution or externally observed network permits. No new end-to-end admission defect is established. ARM's pre-lock timestamp can shorten the initial lease; not part of this matrix.

## Executed negative tests and independent check

Python absolute-time sticky state model (blob 50f32a6c2cf9c5d2bb251e6c9af35f0c3220f1d6) and Node.js independently written age-domain algebra (blob a4548187e51826e3679badef8e0926ef1405e2f7). Both actually executed, node --check PASS. 800 rows per oracle: 80 split AUTH accepts not accepted under strict second-sample semantics; 192 split AUTH rejects accepted under first-sample semantics; 0 later fresh CLAIM disagreements. Identical ordered CSV SHA-256 9c47e057b394f8370a1408226289fb020ad3836706e55a0495588ee6c06f7305. Explicit millisecond witnesses and inclusive boundaries; IPv4/IPv6 labels only. The counts are synthetic scenarios, not rates or Windows observations.

    python3 negative.py
    node --check independent.mjs
    node independent.mjs

Recommendation for a future value-only Rust contract: explicitly define a single locked-time linearization sample for each ARM/PING/ISSUE/AUTH/CLAIM state transition, sticky loss and inclusive expiry boundaries. Do not describe that as a bound on elapsed time through the remainder of a WFP callback, final arbitration, or SSH connect. Microsoft documents KeQueryInterruptTimePrecise in 100ns units, microsecond accuracy and any IRQL; the spinlock API requires IRQL <= DISPATCH_LEVEL. No native timing proof.
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryinterrupttimeprecise
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keacquirespinlockraisetodpc
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration

## Trust boundary and next gate

Referenced EPROCESS/FileObject from PsSetCreateProcessNotifyRoutineEx -> PID/creation epoch (PsGetProcessCreateTimeQuadPart)/start key (PsGetProcessStartKey)/canonical EXE and exact AppId (FwpmGetAppIdFromFileName0) -> CONNECT_REDIRECT/AUTH_CONNECT V4/V6 -> final WFP arbitration -> actual accepted socket SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS -> terminal CLAIM -> SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS -> physical authenticated SSH. R201/R202/R218/R220/R221 limitations stand: no native proof for death/PID reuse, reused 5-tuple, sibling DIRECT, mapped IPv6, DNS/UDP/QUIC or WFP/BFE/SSH loss. No PacketBound/G2, no-DIRECT/leak-free or historical G1 transfer.

Next decisive allowed action is executing the existing pure Rust tests R201/R202/R218–R221 and a coherent time-state model in an offline Rust toolchain. rustc/cargo absent in this executor; no Rust compilation or native Windows test. No kernel/driver/callout/filter operations, protected ref edits, infrastructure or automation mutations, network changes, paid operations or unauthorized rescue experiments.
