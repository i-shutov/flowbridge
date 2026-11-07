# R5 — cross-epoch replay in WFP endpoint-correlation model (2026-11-07)

## Scope and source checkpoint

Only the independent research branch research/windows-wfp-ale-attribution-20261107. Before these R5 commits: research HEAD 9ccf67f9090709f581282afb009241154bdde87a; main 5b5afc2feeda2195f302380e615ba003d4906e09; beta integration/windows-rust-capture-agent-20261031 c339df2e4d20edf1d11d45786581a68451a71929. Nothing in beta, main, release, PR #56, another repo, runner, services, filters, security policy or automation was changed. No driver, VNC experiment, network operation or payable work.

## Reproducible counterexample against exact R4 original

The original model blob is cffc352f7cf77d59705637ade075ad9fbb12b74f. It maintained an Owner(pid, generation, creation epoch, WFP AppId, exe_identity), but neither a Redirect nor Authorization observation carried the creation epoch. Also, when Owner exited, a prior Authorization indexed by endpoint number remained. A local test of this **exact** R4 blob returned:

- start Owner PID 501, generation 1, epoch 901; classify ticket 9/endpoint 700; observe AUTH_CONNECT endpoint 700 -> expected partial observation;
- stop old PID 501 -> REVOKED_MODEL;
- start a **different** process epoch 902 with **same PID and generation 1** -> REGISTERED_MODEL (bad);
- classify ticket 10, recycled endpoint 700 -> CAPTURED_MODEL (bad);
- accept ticket 10 with the old AUTH observation -> CONDITIONAL_MODEL_ONLY (false model acceptance).

This is a demonstrated offline **model defect**, not evidence of exploitable Windows behavior. The model-assigned generation is NOT an OS-supplied ALE field. An endpoint handle is neither an eternally unique process-instance ID nor a per-NDISRD-frame owner witness.

## Remediation / exact change

The modified endpoint_witness_model.py adds per-session seen_generations and seen_epochs histories, both keyed by PID. Registration reusing either is rejected and poisons the PID. New _revoke_pid_state drains every pending Redirect and Authorization linked to a terminating/ambiguous process; their endpoint numbers remain poisoned for the model session. Inconsistent exit events and overlapping generations cannot silently restore evidence; replay tickets still fail.

This is an intentionally conservative *research safety rule*, not a Windows production algorithm. Creation epochs need not be globally unique, process callback delivery and synchronization are not proven, and ever-growing history/endpoint poison sets require a lifecycle and resource cap in production.

## Independent negative verification

- Direct R4 pre-fix trace: returned incorrect CONDITIONAL_MODEL_ONLY.
- Corrected Python model on isolated Linux Python 3.13.5: 82/82 local assertions PASS.
- Separate epoch_replay_audit.py: 256 deterministic cases = 254 REJECT and 2 strictly CONDITIONAL_MODEL_ONLY; dimensions are generation, epoch, endpoint, ticket, independent AUTH observation, accepted-socket provenance, SSH loss and IPv4/IPv6. Additional five assertion groups test conflicts, stale process exit, distinct PID on recycled endpoint, pending-only exit, and auth-only exit.
- Independent mutation sensitivity: 4/4 unsafe mutants rejected (remove generation guard, epoch guard, pending-endpoint retirement or AUTH-only endpoint retirement).
- Python syntax compilation PASS. Reproduce offline with: python3 research/wfp-ale/endpoint_witness_model.py; python3 research/wfp-ale/epoch_replay_audit.py; python3 -m py_compile research/wfp-ale/endpoint_witness_model.py research/wfp-ale/epoch_replay_audit.py.
- Verified git blob hash of corrected model: 05369e98d964fe8f634fcb2b60be0d3439aa7295; independent audit: 799561b540ec5abe6c89047765b2cbbc90288cef. SHA256: model a472497f52416d27191c2173477c6039e3436210f5d3db311e70a2c863071db2, audit acb3f087c909a73c6d5f369df1b1d11f67e105c199660fea1d35f5a330259ca5.

No rustc is installed in this executor; Rust compile/tests and existing read-only AppId probe on Windows have not run. There was **no native Windows WFP experiment or system no-DIRECT test**.

## Windows documentation, specific APIs and evidence status (checked 2026-11-07)

1. FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6: FWPS_FIELD_ALE_CONNECT_REDIRECT_*_ALE_APP_ID is fixed classify data; FWPS_METADATA_FIELD_PROCESS_ID and FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE are listed *conditional metadata*. Must test incomingMetadataValues valid bit flags. PROCESS_PATH is **not** listed at CONNECT_REDIRECT. FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6 lists PROCESS_PATH, PROCESS_ID, TRANSPORT_ENDPOINT_HANDLE, but the docs do **not** promise an immutable endpoint handle spanning original redirect and proxy AUTH stages. PROCESS_PATH is not canonical on-disk executable object identity. https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer
2. Candidate native process-generation binding: PsSetCreateProcessNotifyRoutineEx with referenced EPROCESS; PsGetProcessCreateTimeQuadPart reads creation epoch once the correct object is already pinned. PsLookupProcessByProcessId is pageable/IRQL <= APC_LEVEL whereas classify may occur at DISPATCH_LEVEL: an asynchronous numeric PID lookup has PID-reuse races. Required atomic binding of **same** kernel classify to correct referenced EPROCESS, creation epoch and canonical EXE is not proven. https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-pslookupprocessbyprocessid ; https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocesscreatetimequadpart
3. Redirect-chain candidate: FwpsQueryConnectionRedirectState0 prevents self loops; FwpsAcquireWritableLayerDataPointer0 -> FWPS_CONNECT_REQUEST0.localRedirectContext (custom ticket+original destination), localRedirectTargetPID (**local proxy PID**, not original app PID), localRedirectHandle (FwpsRedirectHandleCreate0), FwpsApplyModifiedLayerData0. PREVIOUSLY_REDIRECTED_BY_SELF must not be redirected again. https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection ; https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
4. Proxy: WSAIoctl SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS and SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT must inspect the **actually accepted** TCP socket. WSAIoctl SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on each outgoing TCP socket must precede connect. The record is opaque, not an epoch attestation. UDP first flow-creating packet instead carries IP_CONNECTION_REDIRECT_RECORD in WSARecvMsg and passes it via WSASendMsg. https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records ; https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
5. FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6 is an independent *enforcement candidate* for TCP connect and initial UDP remote tuple, not a verified persistent kill switch. System resolver DNS, UDP/QUIC, same-basename siblings outside selected AppId, IPv6/compartments, SSH/WFP loss and filters removal require distinct tests and a separately authorized system-level policy. https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers

## Architecture verdict and next decision gate

- Offline R5 negative contract: **MODEL PASS**, not a native kernel owner proof.
- Same-classify AppId + correct EPROCESS + creation epoch + canonical EXE: **NO-GO**, missing real referenced-object provenance.
- Shared endpoint number between REDIRECT and AUTH: **NO-GO as an immutable connection identity**; only supplementary heuristic pending native observation.
- Actual accepted-socket redirect chain and subsequent packet owner: **NO-GO**, no authorized callout.
- NDISRD per-frame PacketBound: **NO-GO**, no shared kernel-origin per-frame owner token.
- Direct/leak-free selected-app enforcement across SSH/WFP loss, sibling DIRECT, UDP/DNS/QUIC: **NO-GO**. Proxy-side ingress refusal does not block independent direct sockets. Historical G1 dd1ab3c is not transferred; G2 remains unproven.

**Next decisive non-driver test:** Compile and run existing read-only Rust appid_readonly.rs on authorized Windows with same-basename EXEs in separate paths, exact duplicate path and hardlink/reparse aliases. This can falsify WFP AppId assumptions only. Native redirect, driver/callout, BFE filters, network/VNC tests or system kill switch remain prohibited until owner authorizes the exact experiment and all signed-driver, VNC/SYSTEM rescue and rollback gates are met.
