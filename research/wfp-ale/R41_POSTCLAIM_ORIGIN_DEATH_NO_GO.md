# R41 — post-CLAIM process exit lacks a per-flow worker revocation

2026-11-08. Independent WFP/ALE R&D ONLY, in research/windows-wfp-ale-attribution-20261107. NOT beta, PR #56, native G2, PacketBound PASS or a leak-free claim.

## Fresh source control

Research HEAD initially 2086cbaa860671cb3fa13524751fddf3f301e926 (R39 code repair); a subsequent research-only receipt commit 289a484d208909ffd8903c7ec03f54b1a5a6760d changed documentation, not the relevant source. main 5b5afc2feeda2195f302380e615ba003d4906e09.

Read-only exact GitHub blob checks:
- kernel/src/lib.rs 0af6d4539673d2894cbaa91af0ea8f3524862a26
- kernel/src/redirect.rs 9a07e026134d46ef646d39862bd982cc48bbc5f6
- kernel/src/ledger.rs b88c4c9237c4c118517978fc454f5048f522aa7f
- broker.rs ce6c549a9ae488cc7c0ca9a7e7be68871b9d7f2c
- trusted-ssh-r37/src/lib.rs c6d8c8746fac45073c11557de893164e49d830eb
All paths are below research/wfp-ale/kernel-r19/. Six source-path predicates checked on fetched blobs, 6/6 PASS.

## Exact finding (source-level)

On origin-process exit, lib.rs::process_event calls Ledger::died(pid, process) and redirect::process_exit(pid). Ledger marks the selected process dead, preventing future fresh process lookup/claim. However redirect::process_exit triggers lose() **only when pid equals ROUTE.pid, the BROKER PID**. redirect::ready() also consults STATE.lookup(ROUTE.pid), not the selected owner of a previously claimed stream.

After a successful one-time CLAIM, broker.rs starts TrustedSshRelay with worker_revocation driven by global PING/STOP and worker/SSH faults. The Tokio transport copy_with_revocation listens to this watch channel; it receives no specific selected-process-exit event. Therefore a possible abstract sequence is: CLAIM selected X -> active SSH relay -> selected X exits -> broker remains healthy -> kernel PING remains good -> watch STOP remains false. Queued data are still **eligible for copying in the source model**. The stronger invariant “original owner exit immediately revokes an already CLAIMed relay” is NOT established.

This is **not evidence that any bytes actually leave Windows after process exit**: socket teardown, pending buffers, order/timing of callbacks and physical egress have not been measured. An application might have already closed its stream. A policy that deliberately allows draining of claimed channels would need explicit acceptance and controls; do not silently equate it with strict owner-liveness.

PID+epoch+canonical EXE is mandatory at initial kernel classification, but a retrospective OpenProcess/5-tuple join is not a substitute for a per-flow revocation capability. PID reuse may poison the kernel ledger; plain origin exit before reuse does not send a per-flow STOP.

## Negative tests

- r41_postclaim_exit_negative.py: 9/9 deterministic model tests PASS in a local Python environment, including both IP families, process death before/after claim, broker death, PID reuse, SSH/lease loss, no queued data, unchanged 5-tuple and excluded sibling/UDP cases.
- r41_exit_independent_oracle.py: 128 independent abstract worlds enumerated; 2/128 strict-liveness counterexamples (one per family); NOT observed event frequency.
- Source-anchored read-only GitHub check: 6/6 exact source predicates PASS. The earlier R39 Windows no-load build run 42463556304 was green but does NOT test this exit behavior. No Rust compiler or native Windows system was used for R41.

## Proof boundary / APIs

Origin process: PsSetCreateProcessNotifyRoutineEx, PCREATE_PROCESS_NOTIFY_ROUTINE_EX, referenced EPROCESS, process creation epoch and canonical image. Redirect: FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6, ALE_AUTH_CONNECT_V4/V6, FWPS_METADATA_FIELD_PROCESS_ID, TRANSPORT_ENDPOINT_HANDLE, FWPM_CONDITION_ALE_APP_ID and ALE_ORIGINAL_APP_ID. Socket: WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS / ..._CONTEXT) on accepted redirect socket; SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on the real outbound SSH socket. These are NOT a post-CLAIM owner-liveness signal. A Tokio watch STOP can only cancel events actually delivered to it.

Docs:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_process_notify_routine_ex
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records

## Next decisive *allowed* experiment

Pure Rust user-mode, no-network per-ticket/per-worker revocation state machine. Test process exit racing CLAIM, selected vs broker exit, PID reuse, identical 5-tuple, v4/v6, heartbeat/SSH loss, and buffered-copy cancellation with an independent ticket-identity oracle. Before any real Windows kernel acceptance, separate owner permission and ALL driver, VNC, SYSTEM rescue and rollback gates are mandatory and not satisfied here.

NO-GO persists for native post-CLAIM liveness, kernel-origin AUTH issuance, reauthorization, sibling DIRECT, DNS/UDP/QUIC, IPv4/IPv6 physical egress, WFP crash fail-closed, systemic no-DIRECT, PacketBound/G2 and leak-free. No production ref, runner, service, driver, filter, Defender/SecureBoot or other infrastructure mutated.
