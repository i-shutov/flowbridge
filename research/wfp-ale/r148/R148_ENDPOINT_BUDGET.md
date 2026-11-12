# FlowBridge R148 — bounded endpoint identity implies hard availability NO-GO

Research branch: `research/windows-wfp-ale-attribution-20261107`; base HEAD `4ff6e11bbaf8f4a110129492a2cdd30c9f249b0a`; `main` observed `5b5afc2feeda2195f302380e615ba003d4906e09` on 2026-11-12.

## Substantive source-level finding, not a kernel observation

The clean-room R19 Rust `Book` is deliberately fail-closed but **not a long-running product ticket registry**:

- `CAP=32` tracks only up to 32 simultaneously live issued contexts. An eligible 33rd connection is denied until an entry is retired or expires (`TTL=100_000_000` 100-ns ticks = 10 seconds). This is a bounded concurrency cap; it is **not** evidence of DIRECT traffic.
- `MAX_ENDPOINT_TOMBSTONES=4096` remembers every issued transport-endpoint handle for the entire `Book` lifetime; reclaiming slots does not reclaim tombstones. After 4,096 successfully issued distinct endpoints, another new endpoint latches `lost=true`. A repeated endpoint handle can latch `lost` **earlier**. This is a hard availability ceiling, not a statement about Windows handle reuse frequency.
- The kernel `ready()` refuses a lost book and calls `lose()`, which disarms the route. `ARM` refuses an already configured route; `STOP` calls `lose()` but does not reset `configured`. Therefore no authorized in-place reset path was identified in this R19 scoped lab source. **Do not reset the guard or rearm it in live systems; this is a source-level research finding only.**

Pinned source Git blobs at research HEAD: `kernel-r19/kernel/src/handoff.rs` = `e1d17217db50362ba9c4efc83af820b6beb094cf`; `kernel-r19/kernel/src/redirect.rs` = `a093f049d162987981a957aac90db1014bc6ff09`. Both source contents were read via GitHub. The offline Python source gate requires the exact `handoff.rs` Git blob and seven key markers; it is deliberately not a substitute for kernel evidence.

## Executed independent negative tests

Two independent Python 3.13.5 and Node 22.16.0 models reproduced **4,137** deterministic event outcomes, with identical SHA-256 over rows:

`54f135f3aa830086eee1aaf726132fe4cdf2eb4649f827d8a7585916ff0e49a5`

Outcome counts: `ISSUED=4131`, `BLOCK_LIVE_CAP=1`, `LATCH_REUSED_ENDPOINT=1`, `LATCH_TOMBSTONE_EXHAUSTED=1`, `DENY=3`.

Python normal and `python -O` are identical; assertions are not used for Python invariants. Test cases cover 33rd concurrent issue, reclamation of a live slot, sequential 4096-issued/retired endpoints plus the 4097th request, endpoint replay, TTL expiration, and kill/disarm persistence.

Run from the repository root, without any driver, network or privilege change:

```sh
python -B research/wfp-ale/r148/r148_endpoint_budget.py
python -O -B research/wfp-ale/r148/r148_endpoint_budget.py
node research/wfp-ale/r148/r148_independent.mjs
```

The local research executor did not contain the entire R19 source tree and therefore ran Python with `--model-only` (no source-pin pass). Source Git blob was separately verified via GitHub. **Exact-checkout source-pin run is pending**, as are native Rust tests and Windows kernel observation. Do not report them as PASS.

## Trust chain and explicit limitations

A production attempt must preserve: referenced kernel process (`PsSetCreateProcessNotifyRoutineEx`, `PEPROCESS`, `PsGetProcessCreateTimeQuadPart`, `PsGetProcessStartKey`) + exact opaque `FwpmGetAppIdFromFileName0`/ALE AppId -> one classify provenance at `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6` and `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6` -> `FWPS_CONNECT_REQUEST0` + scoped redirect context -> accepted socket `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS)` -> one-shot CLAIM -> outbound socket `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` **before** physical SSH `connect` -> independent no-DIRECT enforcement. A PID + timestamp + reused 5-tuple is not that chain.

Neither synthetic model observes Windows transport-endpoint identifiers, proves their uniqueness, shows actual callback reachability or validates action rights/filter arbitration. Source-level capacity limits are exact only for this pinned R19 `Book`, not for a deployed product. IPv4/IPv6 compartments and scope, DNS/UDP/QUIC, sibling DIRECT, reauthorization including `FWP_EMPTY`, broker/process loss, WFP/BFE/SSH loss remain architectural `NO-GO`. No PacketBound/G2 PASS, leak-free or transferred historical G1 acceptance.

Microsoft primary API documents:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records

## Decisive next permitted experiment

On the exact research checkout, run both models and compare matrices and source-pin status, then (if toolchain already present) compile the *existing* `kernel-r19/kernel/src/handoff.rs` unit tests through the existing isolated test harness without loading a driver. Compare 32/33, 4096/4097 and early endpoint reuse with observed unit-test assertions. Product architecture must redesign endpoint identity lifetime to avoid an irreversible denial of service while maintaining replay safety; do **not** relax tombstones by merely evicting them. Native flow proof remains separately gated and unauthorized. The source-level availability NO-GO does not change the already-open security NO-GO.

No main/release, beta, PR56, driver, WFP filter, service, firewall, system security, runner, network, automation or other-repository change was made.
