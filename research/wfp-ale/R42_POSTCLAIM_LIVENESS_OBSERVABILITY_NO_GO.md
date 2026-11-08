# R42 — strict post-CLAIM owner liveness: broker-only NO-GO

Date 2026-11-08. Independent architecture-only WFP/ALE research in i-shutov/flowbridge, branch research/windows-wfp-ale-attribution-20261107. Not beta/PR #56, PacketBound/G2 acceptance or a leak-free assertion.

## Source-pinned finding

Inspected research HEAD e20a81798bd797ab838dab0f0aa1fdc21ac4fba7 (tree 45ba734de89fa78011f171198ce790c93ac15798); main 5b5afc2feeda2195f302380e615ba003d4906e09. Relevant untouched GitHub blobs: kernel/src/lib.rs 0af6d4539673d2894cbaa91af0ea8f3524862a26; kernel/src/redirect.rs 9a07e026134d46ef646d39862bd982cc48bbc5f6; kernel/src/ledger.rs b88c4c9237c4c118517978fc454f5048f522aa7f; broker.rs ce6c549a9ae488cc7c0ca9a7e7be68871b9d7f2c; broker_windows.rs 16ec8853d322b40f0e00e14d49ae3410741b9395; trusted-ssh-r37/src/lib.rs c6d8c8746fac45073c11557de893164e49d830eb. Paths are under research/wfp-ale/kernel-r19.

lib.rs::process_event receives process death through PsSetCreateProcessNotifyRoutineEx and invokes Ledger::died(pid,process). But redirect::process_exit(pid) revokes the route only when the BROKER PID dies. After successful one-shot CLAIM/Book::take, broker.rs and the SSH worker have a global health/STOP channel, not a per-claimed-ticket original owner-exit channel. An original AppId or a cached context attests an earlier event, not the later process lifetime.

## Two-world impossibility argument

Assume a finite interval with pending bytes and no distinguishing accepted-socket EOF/close notification. World A: original owner still alive. World B: original owner has exited after CLAIM, while kernel PING and authenticated SSH remain healthy and no per-ticket exit signal reaches user mode. Both worlds can present the SAME broker-visible ticket, PID, original AppId, endpoint, 5-tuple, socket and SSH state; even a late PID lookup can observe a new process reusing the numeric PID.

A decision function of identical broker-only observations cannot both permit in A and deny in B. Thus neither extra PID polling nor equality of 5-tuple, AppId, heartbeat or redirect records establishes STRICT post-CLAIM owner-liveness. This is a logical counterexample conditioned on nondistinguishing observations, NOT proof that native Windows preserves queued application bytes or sends any packet after exit. If an actual EOF arrives, the worlds may be distinguishable; no such timing claim has been experimentally established.

## Executed independent checks

- r42_observability_negative.py: 9 of 9 deterministic Python unittest cases PASS; IPv4/IPv6, PID reuse, 5-tuple reuse, sibling, source AppId, health loss and possible EOF.
- r42_independent_oracle.py: 32 of 32 conditional observationally indistinguishable pairs (64 synthetic worlds). A broker that permits whenever global health is good would falsely permit all 32 dead-owner worlds. A blanket-block broker falsely denies all 32 live-owner worlds. Idealized authenticated owner-exit input distinguishes them by assumption (zero model errors).
- r42_per_ticket_revocation.rs: clean-room std-only Rust specification with 13 unit tests WRITTEN for exact owner identity, single-use ticket, claims vs exits, sibling, PID/5-tuple reuse, v4/v6, terminal global health loss. No rustc/cargo available locally: NOT compiled, and Rust unit tests NOT executed. No networking or driver code.

These results are models, not native WFP evidence, packet measurements or empirical failure rates.

## Trust boundary and concrete Windows APIs

Process identity: PCREATE_PROCESS_NOTIFY_ROUTINE_EX via PsSetCreateProcessNotifyRoutineEx, referenced EPROCESS/image, creation epoch PsGetProcessCreateTimeQuadPart, PsGetProcessStartKey and canonical image identity. Redirection: FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6, FwpsRedirectHandleCreate0, FwpsQueryConnectionRedirectState0 and TRANSPORT_ENDPOINT_HANDLE metadata. Authorization: FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6, FWPM_CONDITION_ALE_APP_ID / FWPM_CONDITION_ALE_ORIGINAL_APP_ID, issue-specific AUTH evidence and reauthorization. Handoff: accepted-socket WSAIoctl SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS / CONTEXT; outbound-SSH socket SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS. These IOCTLs document proxy-connection tracking, NOT original-owner exit subscription. FwpsFlowAssociateContext0 associates an opaque context with a WFP data flow given a FLOW_HANDLE and registered flowDeleteFn; flow deletion is not documented to be source-process termination.

A user-mode per-ticket cancellation model assumes a trustworthy and ordered original-owner exit event; it does not supply such an event. It cannot retrospectively recall OS-queued bytes. This missing bridge is architectural NO-GO. Native kernel-origin issuance/reauthorization, process-death/PID reuse, physical IPv4/IPv6 egress, sibling DIRECT, DNS/UDP/QUIC, WFP/SSH failure, systemwide kill-switch, PacketBound/G2 and leak-free remain unproven.

## Next authorized experiment

Compile and run the std-only Rust model locally (without CI/driver/filters/network) when a user-mode compiler is available. Cross-check all 13 transitions against the independent oracle and deliberately failing mutation tests. Specify an authenticated ticket+owner-object+epoch exit-notification and ACK contract, with monotonic event ordering, race handling for exit/CLAIM, notification loss/timeout and terminal revocation; do NOT implement kernel hooks without explicit owner rescue/rollback/driver gates. Alternatively define an explicit bounded post-exit drain policy without promising strict owner-liveness.

Official documentation:
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_process_notify_routine_ex
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsflowassociatecontext0
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records

No runner/CI changes, driver, signing, WFP filter, VNC, service, firewall, Defender, SecureBoot, MemoryIntegrity, external repo, beta, PR #56, main or automation changes are part of R42. Existing unrelated G2 work in the research branch is not an authorization to change or execute it.
