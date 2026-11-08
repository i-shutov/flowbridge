# R35 — fail-closed endpoint non-reissuance in the kernel ticket book

Research branch only: `research/windows-wfp-ale-attribution-20261107`. Base HEAD `97ee1417d37c3c6a3bddd22ad9ada0c0eebd491d`.
Development authorization covers source and scoped push-trigger CI. No driver installation, signing bypass, WFP filter modification, service change, or release-branch change.

## Functional source change
- In the **actual** `kernel-r19/kernel/src/handoff.rs`, kernel `Book::issue` now tracks *every* endpoint handle that has received a private ticket within the driver's one active session.
- A retired, expired, failed, or CLAIM-consumed ticket **never frees its endpoint for reissuance**. A reused endpoint latches `lost=true`, rejecting new issues and claims. A live ticket no longer needs to be the sole source of duplicate detection.
- A separate fixed `MAX_ENDPOINT_TOMBSTONES=4096` holds used endpoint IDs and is never evicted. The active queue remains `CAP=32`. Tombstone exhaustion latches fail-closed; an inactive queue slot alone does not erase a tombstone.
- Session initialization remains one-shot: attempted rollover latches loss. The policy retains its kernel spinlock around `issue/attest/take`.

This is a conservative mitigation of the conditional R27/R28 **within one driver lifetime**. It eliminates candidate B after same-session reissuance of endpoint E, so delayed AUTH(A) cannot attest B in that session. It cannot prove Windows callback ordering and **does not solve cross-driver-load or cross-boot endpoint reuse**. No infinite-liveness claim: a 4097th unique endpoint fails closed until deliberate package/driver lifecycle handling is designed. A driver restart is **not** an automatic recovery.

## Test additions
Five new exact-source Rust tests: retired endpoint never renews; a different endpoint can proceed; expired endpoint never renews; consumed endpoint never renews; failed session rollover; bounded tombstone capacity (4096) never evicts. Existing foreign-session/one-use/duplicate endpoint/replay tests retained.
Test count increased from 14 to 19, subject to actual Windows build/test confirmation.

## G2 admission and caveats
This does not load the driver or prove AUTH field semantics, accepted-socket binding, physical no-DIRECT, user-mode SSH peer identity, or WFP/BFE fail-closed under crash. `g2_pass=false`, `release_accepted=false`. Next R36 addresses current versus original AppId with separate kernel-origin checks. R37 addresses SOCKS listener authenticity while preserving WFP redirect-record handoff.

Primary contract: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management
