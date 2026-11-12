# FlowBridge R149 — global process ledger exhausted by unrelated process churn

Scope: ONLY `research/windows-wfp-ale-attribution-20261107`. Initial research HEAD `7ddc0e34503726cf5d46727eb6438ba9ffbe71c8`; main `5b5afc2feeda2195f302380e615ba003d4906e09`. Date: 2026-11-13.

## New source-level availability NO-GO

The R19 `process_event` callback calls `Ledger::born(owner)` for **every eligible OS process creation**, without filtering the process image against the selected FlowBridge application. An *eligible* event must supply a successful creation, FileObject, full ImageFileName, a downcaseable path <= 512 bytes, and nonzero PID/process epoch/start key. It is incorrect to say every Windows process necessarily passes these gates.

The ledger has `MAX_OWNERS=256` and never reclaims a slot. `died()` marks an owner nonlive but does not reduce `used`. On the 257th **distinct eligible birth** it sets global `lost=true`; on an already-seen PID (including an unrelated exited process) it sets `lost=true` even earlier. `lookup()` then returns None for a still-live selected process. `redirect::ready()` checks that lookup, calls `lose()`, disarms the route and kills the endpoint ticket book. Thus a still-live selected app can lose routing due to **unrelated process churn**. This is conditional source-level availability failure, not kernel-observed traffic escape.

Successful `process_event` entries take kernel references to the process and executable FileObject. Those references are not released in `died()`; they are released in `cleanup()` on unload. This is bounded pinned lifetime, not an assertion of unbounded memory leakage.

Source Git blobs, independently read and marker-checked through GitHub:
- `kernel-r19/kernel/src/lib.rs`: `53f5ce6faa0f9f591974287f38ea890cafeb0dd2` (`process_event`, `born`, `died`, process/file references).
- `kernel-r19/kernel/src/ledger.rs`: `b88c4c9237c4c118517978fc454f5048f522aa7f` (`MAX_OWNERS=256`, `born`, `died`, `lookup`).
- `kernel-r19/kernel/src/redirect.rs`: `a093f049d162987981a957aac90db1014bc6ff09` (`ready` -> `lose`).

Microsoft: [PsSetCreateProcessNotifyRoutineEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex) and [PS_CREATE_NOTIFY_INFO](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info). These APIs describe event delivery and metadata, not observed churn rates on any Windows host.

## Executed independent negative tests

Python 3.13 normal and `-O` and independent Node.js 22 models produced **783 identical rows** with SHA-256 `23e078cc3b297664b34ca1f87652ef3cda29a0f758572144892ae99f9d64393f`. Cases model one selected living process + 255 eligible unrelated births/exits, 257th unrelated birth, unrelated PID reuse, a colliding live PID, and ineligible process events skipped. Explicit Python exceptions are active under `-O`. A deliberately missing source tree rejects normal source-gated execution. Source blobs were verified remotely but local runs used `--model-only`; do NOT claim exact-checkout source-pin PASS.

Commands (source-pinned only at the exact branch checkout):
```sh
python -B research/wfp-ale/r149/r149_ledger_churn.py
python -O -B research/wfp-ale/r149/r149_ledger_churn.py
node research/wfp-ale/r149/r149_independent.mjs
```

No Rust compiler, Windows host, driver or native WFP classification ran. Cross-language model agreement is not kernel proof.

## Trust boundary and next decision

Do not fix by simply recycling process records: historical process epoch/start key, referenced EXE identity, PID reuse, death/reclassification ordering and socket handoff must remain trusted. Candidate architecture: separate global observation from selected-process admission and require validated generation-scoped cleanup; no implementation accepted without proving races and lifecycle.

Required but unproved chain: referenced kernel PEPROCESS/FileObject + PID/epoch/start key/canonical EXE -> WFP ALE original/current AppId at CONNECT_REDIRECT and AUTH_CONNECT -> FWPS_CONNECT_REQUEST0 and redirect context/records on the actual accepted socket -> one-shot CLAIM -> SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS before outbound SSH connect -> independent selected-app egress enforcement. IPv4/IPv6 compartments, process death/PID and 5-tuple reuse, sibling DIRECT, DNS/UDP/QUIC, reauthorization and WFP/BFE/SSH loss remain **NO-GO**. R148's separate 4096 endpoint tombstone limit also remains.

Next permitted experiment: execute source-pinned tests from exact checkout and compile/run existing Rust `ledger.rs` tests in a user-mode isolated harness if a Rust compiler is already available. Then add Rust regression for 256/257 distinct eligible process births, unrelated PID reuse and reference release lifecycle. Any kernel proof requires distinct authorization, VM rescue and rollback gates. Never install/load a driver, create WFP filters or change system services/firewall/network/security.

No main/release, beta, PR #56, other repositories, runner, controllers, automation or historical G1 admission changes. PacketBound/G2 PASS, no-DIRECT and leak-free are NOT claimed.
