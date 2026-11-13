# R165: R19 kernel Witness IOCTL has no executable event producer

Date 2026-11-13. ONLY branch research/windows-wfp-ale-attribution-20261107.
This is a source-level availability-of-evidence NO-GO, not a kernel test or an observed DIRECT leak.

## Verified reachability failure

The static driver Ledger is created with count=0. Ledger::observe is the only
writer of private queue/count. Its calls in ledger.rs occur in cfg(test) tests
only, which are not linked into the actual driver. In the entire current
runtime module closure (lib.rs, redirect.rs, handoff.rs, auth_appid.rs,
action_rights.rs, msvc_runtime.rs) there is NO invocation of observe.
lib.rs::dispatch calls Ledger::pop, but no producer can enqueue a Witness.

Therefore, in the pinned R19 source, every witness IOCTL read returns EMPTY
while Ledger remains healthy, or NOT_READY after Ledger.lost. No successful
candidate witness receipt is reachable. This conclusion is limited to the
seven pinned modules; no kernel callback was executed or OS behavior observed.
It does not assert whether the separate ticket Book/AUTH/redirect path works.

The historical R19_KERNEL_BUILD_EVIDENCE.md claims the observer could emit
receipts, but building and testing ledger.rs alone never proved the adapter
actually called observe(). R164 global ledger churn had already been documented
at R91 and R149; this report does not re-label that old finding as new.

## Exact Git blobs checked against current research HEAD

Research before commit: 587c48d78b2fd59262428de134c93943cba93df4
main (read-only): 5b5afc2feeda2195f302380e615ba003d4906e09

lib.rs: 53f5ce6faa0f9f591974287f38ea890cafeb0dd2
redirect.rs: a093f049d162987981a957aac90db1014bc6ff09
ledger.rs: b88c4c9237c4c118517978fc454f5048f522aa7f
handoff.rs: e1d17217db50362ba9c4efc83af820b6beb094cf
auth_appid.rs: f16ab6ad0f618c74ed4e79ce606583169084970d
action_rights.rs: c6a4a107255cc5ecca82266481935c93467a01ed
msvc_runtime.rs: c0cb2f171ec841e91fc14b290a3c1d08dde518a0

## Driverless tests actually executed

Python 3.13 model: 37,449 traces, 22,737 pop events, zero successful
witness receipts; 8/8 unit tests passed, including a rejected mutant.
Independent Node.js 22 oracle: 37,449/37,449 matched. SHA-256 matrix
09d1fc07747a152f9fe3ddf20a0992f56ff44c04083f768b46cc0e7a63157d7b.
Both show capacity loss changes EMPTY to NOT_READY, not SUCCESS.
The Python and Node finite-state models and their output were executed locally.
The exact seven source blobs were checked remotely via GitHub.
The full-checkout source gate below was NOT executed in this local environment.

Reproduce only on an exact research checkout (no driver, filter or service):
  python research/wfp-ale/r165/r165_checkout_gate.py
  python research/wfp-ale/r165/r165_matrix.py
  node research/wfp-ale/r165/r165_matrix.mjs

The source checker fails if its pinned Rust sources change or if observe
becomes wired. It is a small source proof, not a compiler-derived call graph.
No full checkout, rustc, Windows kernel execution, filter, traffic, SSH or
network operation was involved.

## Trust boundary / next decisive experiment

PsSetCreateProcessNotifyRoutineEx -> referenced process + file + creation
epoch/start key -> FWPS ALE redirect/auth (PROCESS_ID, endpoint, AppId) ->
[missing runtime Ledger::observe] -> kernel Witness IOCTL. An actual
kernel-origin evidence route must be wired into the same ALE event before
a read-only witness can be trusted. The next permitted step is to build an
exact-source pure Rust adapter harness and verify event-to-observe reachability
without a driver. Do NOT repair by synthesizing user-mode PID/5-tuple/time
correlations. Native WFP proof requires separately approved rescue/rollback gates.

Independent accepted-socket redirect context/records -> one-shot CLAIM ->
physical SSH with transferred redirect records, sibling DIRECT, DNS/UDP/QUIC,
IPv4/IPv6 compartments, process death/reuse, ALE reauthorization and BFE/SSH
loss remain NO-GO; no PacketBound/G2 PASS or leak-free claim.

Official docs:
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking

Only the research branch may receive these new model/test/report files.
No main/release/beta/PR56, kernel driver/filter, other repo, runner, services,
firewall/Defender/SecureBoot/MemoryIntegrity, network or automation change.
