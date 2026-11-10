# R91 — Global process-create churn irreversibly poisons selected WFP flow ledger

2026-11-10. Research-only in research/windows-wfp-ale-attribution-20261107. NOT beta, PR #56, PacketBound/G2 PASS, or leak-free proof.

## Verified source-level chain

Pinned research parent: 7014d3956607c010da550c88826911c6f16851c9; main: 5b5afc2feeda2195f302380e615ba003d4906e09.
Git blob lib.rs: 0af6d4539673d2894cbaa91af0ea8f3524862a26; ledger.rs: b88c4c9237c4c118517978fc454f5048f522aa7f; redirect.rs: 9a07e026134d46ef646d39862bd982cc48bbc5f6.

1. DriverEntry registers PsSetCreateProcessNotifyRoutineEx(Some(process_event),0). process_event calls STATE.born(owner) for every eligible image-complete process creation, with no selected-image filter. A callback qualifies only with non-null FileObject/ImageFileName, FileOpenNameAvailable, valid epoch and start key, and sane name. Do not count every OS process unconditionally.
2. ledger.rs: MAX_OWNERS=256, used only increases for new PID; died() marks dead without reclaiming slots. On the 257th unique eligible birth, born() sets lost=true and returns Full. Reuse of *any* earlier PID, including unrelated departed processes, sets lost=true and returns ReusedPid even earlier. Existing Rust unit tests owner_cap_no_eviction and pid_reuse_latches_forever verify local guards.
3. lookup() returns None whenever lost=true. redirect.rs ready() then invokes lose(), disarming the redirect ticket book; selected broker/app may still be alive. This is global fail-closed availability loss caused by unrelated process churn, NOT a demonstrated packet bypass, DIRECT traffic, or leak.

Official process-callback contract: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex

## Offline negative tests and independent oracle

Python r91_ledger_churn_negative.py: 5/5 PASS. Independent Node r91_ledger_churn_independent.mjs: 12/12 ordered records match. SHA-256 ordered state records: 6b4d1056865c351a2e1355059357e19000b1bbfbf86de12c36ffebf7ae0e6907.

Scenarios: one live selected process with 255 unrelated created/exited processes and a 257th unique create; unrelated PID reuse; 256 unrelated births before selected starts; 256 exited owners still occupying capacity. Model has no sockets, native Rust compilation, Windows execution, WFP filter or driver. The test verifies source branch semantics, not physical notification frequency or kernel reachability.

## Trust boundary and NO-GO

A real claim must originate at ALE_CONNECT_REDIRECT_V4/V6 with FWPS_METADATA_FIELD_PROCESS_ID and FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE, process reference, PsGetProcessCreateTimeQuadPart and PsGetProcessStartKey, canonical selected EXE, address/source bind, and original destination; be attested at ALE_AUTH_CONNECT_V4/V6 with ORIGINAL_APP_ID, redirect metadata and proper classify action rights; be bound to a real accepted SOCKET via WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT), one-use CLAIM, and a physical SSH socket using SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS and verified SSH identity. PID/tuple/ETW correlations do not satisfy that proof. NO-GO persists for process death/PID reuse, reused 5-tuple, sibling DIRECT, R85-R90, IPv4/IPv6, local/remote destination namespace, DNS/UDP/QUIC, WFP/BFE/SSH loss, and PacketBound/G2.

## Next decisive experiment

Offline first: run an isolated zero-socket Rust user-mode test using the exact ledger source on an approved x86_64 toolchain. Architecture must decide how to bound *selected* process tracking without recycling numeric PIDs or evicting live process references, while maintaining fail-closed semantics and auditable reason codes. Native WFP experiments require separate owner approval and the driver/VNC/SYSTEM rescue/rollback gates; none were performed.

Only these three R91 research files are in scope. No main/release/beta/PR #56, runner, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, networks, other repos, automation/controller, ProxiFyre AGPL, PR40, vendor binary, C++ WFP payload, filter, driver, NDISRD, VNC, signed driver or paid operation.
