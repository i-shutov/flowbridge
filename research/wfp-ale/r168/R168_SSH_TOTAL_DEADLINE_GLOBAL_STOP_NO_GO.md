# R168 — a healthy, long-lived SSH relay reaches a global terminal STOP

Date: 2026-11-13. Research ONLY: `research/windows-wfp-ale-attribution-20261107`.
This is a **source-level availability NO-GO**, NOT a measured Windows flow, kernel authorization, DIRECT leak, or PacketBound/G2 PASS.

## Cross-module chain — conditional on a pending long-lived copy

1. `trusted-ssh-r37/src/lib.rs::copy_with_revocation` puts **the entire** `tokio::io::copy_bidirectional(left,right)` future inside `tokio::time::timeout(Duration::from_secs(60), ...)`. This is a **total elapsed lifetime bound**, not an idle/inactivity timeout. Continuous application traffic does not restart it. `copy_bidirectional` completes normally only when both directions have shut down; an otherwise healthy open stream still awaits. At elapsed time beyond the deadline, a pending copy returns `ssh_relay_timeout`. Tokio's exact deadline-edge polling order may vary, so deterministic cases use 61+ seconds, not an equality claim.
2. `broker_windows.rs::TrustedSshRelay::relay` propagates this error to `broker.rs`'s admitted worker. `broker.rs` treats **any** such post-receipt error as fatal: `if result.is_err(){revoke(&s,&notify);}`. This sets the shared `stop` flag and sends sticky revocation to **all** live SSH workers, regardless of their health.
3. The heartbeat loop leaves `while !stop`, sends `handoff::STOP`. The R19 kernel `redirect.rs::ioctl` handles `STOP` with `lose()`, which sets `armed=false` and `Book::kill()` (`lost=true`). As R161 already established, this cannot re-ARM in the same loaded driver.

Therefore, under a healthy authenticated SSH channel with both copy directions still open after >60 seconds, a single legitimate long-running relay can terminate other relays and the entire R19 session **without** SSH loss, process death, BFE loss, or PING failure. Actual scheduling, socket outcome, and Windows deployment are UNOBSERVED. This is an availability defect, not proof of a network leak.

**Novelty accounting:** R38/R38A already mention/retain the 60s bound; R39 already describes broker-wide revocation on post-receipt error; R161 already establishes terminal kernel STOP. This checkpoint verifies the cross-component combination and its healthy-active-traffic consequence; it does not relabel the individual old facts as new.

## Exact Git blob source gate (R166 research HEAD `f999ff461786ee5c553231a0c8bd593ca392a932`)

- `research/wfp-ale/kernel-r19/trusted-ssh-r37/src/lib.rs` — `c6d8c8746fac45073c11557de893164e49d830eb`
- `research/wfp-ale/kernel-r19/broker.rs` — `6163e84aea08ddde7e51a7fb94ccb6d68ae951fb`
- `research/wfp-ale/kernel-r19/broker_windows.rs` — `329ef14b63e70226bfad7372b0014559213abd04`
- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs` — `a093f049d162987981a957aac90db1014bc6ff09`
- `research/wfp-ale/kernel-r19/kernel/src/handoff.rs` — `e1d17217db50362ba9c4efc83af820b6beb094cf`

All five exact paths and blob SHAs were re-read through the GitHub source tree, and the source anchors were directly inspected. No full local checkout or Rust toolchain was present; `--source-gate` against a local checkout has NOT executed. The Python gate in this folder rejects any altered source blob before trusting local source-pattern checks.

## Executed, independent, driverless negative tests

- `python3 research/wfp-ale/r168/r168_negative.py`: **7/7 PASS**; explicit streaming/idle long-lived deadline, predeadline clean EOF, sibling cancellation, sticky STOP path, kernel-loss control, and an intentionally wrong *idle-reset* oracle rejected.
- `python3 research/wfp-ale/r168/r168_negative.py --matrix` and `node research/wfp-ale/r168/r168_oracle.mjs`: **360/360 byte-identical JSON rows**; independent Python/Node implementations; disagreement count **0**. SHA-256 of JSON including final newline: `65e7aefd3fc6a9d0d2e34246b72d72ab1ddab0903f8a06adca4c9cee7aadb1e7`.
- Matrix axes: horizon (5/30/59/61/75/120 s), both-direction completion time (none/2/10/40/90 s), activity (idle/streaming), PING (healthy/lost), concurrent workers (1/2/3). This is a deterministic contract model, not an execution of Tokio or an observation of WFP.
- Source and tests do not create/install/run kernel drivers, WFP filters, NDISRD, network connections, services or privileges. No Rust compile and no native Windows session occurred.

## Trust boundary, non-goals and next decisive experiment

`PsSetCreateProcessNotifyRoutineEx` referenced process + image `FileObject`, `PsGetProcessCreateTimeQuadPart`, `PsGetProcessStartKey` and canonical appId from `FwpmGetAppIdFromFileName0` → ALE `CONNECT_REDIRECT_V4/V6` / `AUTH_CONNECT_V4/V6` `FWPS_METADATA_FIELD_PROCESS_ID` and `TRANSPORT_ENDPOINT_HANDLE` → authenticated original/context/records on accepted socket with `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS` → kernel one-shot CLAIM → `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on actual SSH socket → host-key-pinned SSH → global revocation → kernel STOP. **No full native proof exists**. R165 missing `Ledger::observe` producer, R166 routing scope gaps, process/PID and endpoint/5-tuple ABA, compartments, sibling DIRECT, DNS/UDP/QUIC, reauth and WFP/SSH loss remain NO-GO.

**Next permitted decisive experiment:** run an actual **clean-room Rust user-mode** Tokio test with paused/advanced virtual time and local `tokio::io::duplex` streams (NO network/driver) to hold both sides open and continually transfer synthetic bytes beyond 60 virtual seconds. Verify the real `copy_with_revocation` future returns timeout and the broker-style observer broadcasts STOP to a sibling; test normal EOF before 60s and a deliberate stop independently. Then require an explicit product decision: remove the total lifetime cap or make it a separately specified per-connection maximum without global revocation of unrelated healthy connections; preserve fail-closed behavior on actual SSH/lease loss. This is NOT authorization to modify R19 production/beta or deploy WFP.

Primary contracts: https://docs.rs/tokio/latest/tokio/time/fn.timeout.html ; https://docs.rs/tokio/latest/tokio/io/fn.copy_bidirectional.html ; https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking .

`g2_pass=false`, `packet_bound=false`, `leak_free_unproven=true`; main/release/beta/PR56/runners/services/network/system security/automations untouched.
