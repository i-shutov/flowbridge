# R44 — volatile ACK/session restart replay boundary (conditional NO-GO)

Date: 2026-11-08. Architecture-only R&D on `research/windows-wfp-ale-attribution-20261107` **only**. Not beta, PR #56, PacketBound/G2, a signed-driver test, a Windows proof, or a leak-free assertion.

## Source pins and scope

Read-only pinned branch HEAD `457fddac7fcf4997bb3844005ea72b85c7c89025`; main `5b5afc2feeda2195f302380e615ba003d4906e09`. Relevant kernel blobs: `kernel/src/lib.rs` `0af6d4539673d2894cbaa91af0ea8f3524862a26`, `kernel/src/redirect.rs` `9a07e026134d46ef646d39862bd982cc48bbc5f6`, and `r42_per_ticket_revocation.rs` `719a3cccc1876582c92a221f6933b77912f3a989`; paths start at `research/wfp-ale/` (kernel files under `kernel-r19/`).

The **unpublished local R43 model**, not current kernel code, claims an ACK after updating in-memory `BTreeMap`, `BTreeSet` and `next_seq`. This state is volatile, not durably persisted; no authenticated kernel-event sender or restart handshake has been proven. Consequently the comment calling the result a "durably applied" watermark cannot be used as evidence of crash-durable owner-exit revocation.

## Executable negative counterexample

Assume historical messages may be replayed after a receiver restart with the **same session ID**, and a previously ACKed `Exit(owner)` is not replayed:

1. Original receiver accepts `Issue(S,seq1,t)`, `Claim(S,seq2,t)`, then `Exit(S,seq3,owner)`; ACK=3 and ticket revocation.
2. Receiver crashes, losing the volatile state.
3. New receiver reuses S and receives old `Issue(S,1,t)`, `Claim(S,2,t)`, but no Exit.
4. The historical *dead-owner* ticket is permitted in the model. A same-session sequence counter alone cannot distinguish old from new messages.

**Important limits:** this is conditional, not evidence that the current FlowBridge broker or native Windows can replay these messages, preserve a socket across restart, or leak a packet. Crash **without** replay fails closed; a fresh authenticated session blocks old frames. A re-used PID or TCP 5-tuple is not an identity/freshness source. Fresh session fencing must also exclude old SSH channels and old kernel tickets; it does not prove instantaneous owner-exit enforcement.

## Tests, independent verification, and status

- `r44_restart_replay_negative.py` — 9/9 Python stdlib negative tests PASS locally; IPv4/IPv6, exit/replay/restart, fresh session, replay without prior issue, duplicate seq, PID/creation epoch and 5-tuple reuse, sibling owner.
- `r44_independent_oracle.mjs` — separately authored Node stdlib **32 synthetic worlds**, **8 conditional replay counterexamples**, 16 fresh-session rejections and 32 no-replay rejections; executed locally with Node 22. No physical packets or Windows calls.
- R43 local SHA256 checkpoint rechecked: 15/15 Python checks, 768 model worlds, 2343 traces and 8 mutation checks. `rustc` and `cargo` unavailable locally; 18 R43 Rust unit tests **NOT RUN**.

## Trust chain and remaining NO-GO

`FwpmGetAppIdFromFileName0`, `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6`, `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6` and `ALE_ORIGINAL_APP_ID` are candidate classification/selection surfaces; they do **not** authenticate a user-mode event stream. `PsSetCreateProcessNotifyRoutineEx`, `PsGetProcessCreateTimeQuadPart` and `PsGetProcessStartKey` give potential exact-owner evidence, but a trustworthy serialized Issue/Claim/Exit feed with bounded delivery delay has not been demonstrated. `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)` and `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` track proxied sockets, not persistent exit ACKs. ALE reauthorization is separately necessary.

**NO-GO remains** for kernel-origin issuance, strict process-death revocation, full IPv4/IPv6, PID/tuple reuse native behavior, sibling DIRECT, DNS/UDP/QUIC, WFP/SSH failure, physical egress, system kill-switch, PacketBound/G2 and leak-free.

Next authorized experiment: pure Rust user-mode restart/session-fencing state machine with a fresh issuer-bound epoch and monotonic STOP, independently checked against this event-log oracle. No drivers, WFP filters, service/runner, VNC, firewall, beta, main, PR #56, or costly actions.

Official docs:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
