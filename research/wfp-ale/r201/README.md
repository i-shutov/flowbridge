# R201 — selective owner ledger, clean-room Rust value model

2026-11-15. **Research-only** in branch research/windows-wfp-ale-attribution-20261107. Not beta, PR #56, driver QA, no-DIRECT/leak-free evidence, PacketBound/G2 or native WFP acceptance.

## Distinct contribution versus R91/R200

R91, dated 2026-11-10, already identified the worldwide process-notify callback and 256-entry non-evicting owner table. R200 independently reconfirmed that source-level availability failure in later R19 sources; it is NOT a newly discovered WFP defect. R201 implements a **constructive, zero-FFI Rust user-mode proof model** for a narrower hypothesis: unrelated process creation must not consume qualified-owner capacity, and an exact process-object exit may reclaim a live slot while old incarnation and endpoint tickets remain nonreplayable.

Sources pinned at research parent 44f546b1eb3a2b074465800cb3ec0c0197230d03:

- R19 kernel/src/lib.rs Git blob 53f5ce6faa0f9f591974287f38ea890cafeb0dd2, process_event and DriverEntry;
- R19 kernel/src/ledger.rs Git blob b88c4c9237c4c118517978fc454f5048f522aa7f, MAX_OWNERS and global lost;
- R19 kernel/src/redirect.rs, the actual ALE/claim implementation;
- R91_GLOBAL_PROCESS_CHURN_LATCH_NO_GO.md and r200/README.md.

## Files and executable contracts

- selective_ledger.rs: pure Rust/std value state machine. Contains **14 Rust unit tests**, compiled by an optional standalone rustc invocation. No WFP, kernel, Windows FFI, OS handles, network or file I/O.
- independent_oracle.py: **9 independent Python state tests**, actually executed. Scenarios: 10,000 unrelated births, selected PID reuse with different creation epoch/start key and process ref, mismatched exit object, endpoint ABA and repeated 5-tuple, one-use claim, broker absent/dead, unrelated sibling, reauthorize and wrong original AppId, IPv4/IPv6 tags, DNS/UDP rejected, history capacity and health loss.
- source_contract.mjs: **12 Rust source predicates** plus forbidden-API and mutation-sensitivity checks, actually executed.

Run in this directory:

    python3 independent_oracle.py
    node source_contract.mjs
    rustc --edition=2021 --test selective_ledger.rs -o selective_ledger_test
    ./selective_ledger_test

In the research authoring environment Python 9/9 and JavaScript 12/12 source checks PASS, including deliberately inverted TCP/UDP predicate detection. **No rustc or cargo installed: 14 Rust tests are authored but NOT compiled or executed.** No native Windows/BFE/kernel runtime, packet, or SSH observations were made. JavaScript source checks are NOT Rust compiler checks.

## Exactly what the model establishes, and what it does not

All model inputs are **synthetic and potentially untrusted**. A numeric process_ref or file_ref in this source is not a referenced EPROCESS/FileObject or authenticated Windows identity. The string EXE identity assumes canonical path equality was already established by a trusted authority. The attestation call receives a claimed same-ALE-classify indication and cannot prove that provenance. A model claim cannot prove binding to an actual accepted Winsock socket or authenticated physical SSH egress.

Before storing a process, the model requires exact pre-pinned selected or broker EXE, nonzero PID/creation epoch/start key/process/file reference, and an independent generation. An unrelated creation does not consume owner or history budget. A duplicate live PID is terminal. Death only frees an active slot when the process object matches, and retires outstanding tickets. Old incarnation keys remain in a bounded history to deny ABA; old endpoint handles cannot be recycled, even with a repeated TCP 5-tuple. Broker absent means no issuance; broker death or external health loss is terminal. Only TCP, family 4 or 6, selected ORIGINAL_APP_ID and non-reauthorize semantic attestations can proceed. These are **model safety invariants**, not no-DIRECT/liveness proofs.

The model intentionally retains bounded history and endpoint tombstones. After enough selected process churn or endpoints the session still stops, fail-closed. Thus this does NOT deliver unlimited uptime or solve allocation, synchronization, release of kernel object references or kernel crash safety.

## Critical bootstrap/pre-pinning NO-GO

A credible selected-only birth tracker requires exact selected and broker identities **before** the process notifications that are to become authoritative. The real R19 DriverEntry registers PsSetCreateProcessNotifyRoutineEx first and obtains the selection only later through broker ARM. There is currently no trusted pre-birth provisioning path. A selected or broker process that already existed before its trusted birth observation cannot be retroactively certified by OpenProcess, PID lookup, EXE text equality, ETW or TCP tuple correlation. The model constructor assumes pre-pinned paths, but does not solve installation, trust bootstrap, or process-start ordering. This is an architectural dependency, not a new kernel execution result.

## Full WFP trust chain remains unproven

1. Kernel birth: PsSetCreateProcessNotifyRoutineEx; PS_CREATE_NOTIFY_INFO.FileObject, FileOpenNameAvailable, ImageFileName; ObfReferenceObject and exact exit; PsGetProcessId, PsGetProcessCreateTimeQuadPart, PsGetProcessStartKey; canonical EXE matched against trusted AppId from FwpmGetAppIdFromFileName0.
2. Per-flow: scoped ALE_CONNECT_REDIRECT_V4/V6 and ALE_AUTH_CONNECT_V4/V6, original and current AppId, FWPS_METADATA_FIELD_PROCESS_ID, TRANSPORT_ENDPOINT_HANDLE, LOCAL_REDIRECT_TARGET_PID, ORIGINAL_DESTINATION, redirect/reauthorize flags, action rights; FwpsQueryConnectionRedirectState0, FwpsAcquireWritableLayerDataPointer0 and FwpsApplyModifiedLayerData0.
3. Accepted socket: actual WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS), terminal kernel one-use CLAIM with requestor process and exact origin/endpoint/epoch, not merely a copied context blob.
4. Physical SSH: WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS), verified SSH peer and handoff, positive loss revocation and separately enforced sibling DIRECT. Documentation describes records for connections to the destination; semantics when transferred onto the physical SSH transport remain unresolved (R88/R89).

Unproven: process death after claim, reused 5-tuple/endpoint in native WFP, IPv4/IPv6 compartments and scope, unrelated filter precedence, reauthorization, sibling DIRECT, DNS/UDP/QUIC, filter/BFE/SSH loss. Overall FlowBridge WFP/ALE remains **NO-GO**. In-memory matching or event correlation does not make PacketBound/G2 PASS or leak-free.

Official Microsoft contracts:

- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocessstartkey
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-field-identifiers
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records

## Next permitted deciding experiment

Independently run and inspect all 14 standalone Rust tests on an authorized clean offline Rust toolchain, then build R199 via cargo build --offline --locked --release and take only a passive BFE readback on the approved Windows 10 Pro x64 machine. Preserve OS build, exact toolchain, SHA-256, ACL, each Win32 return code and an independent replayable verifier. This does NOT establish kernel-origin WFP/SSH admission. Any native driver, WFP filter/callout, VNC or SYSTEM experiment needs separate owner approval and all rescue/rollback gates, which were not used.

No mutation to main/release, beta branch, PR #56, runners, services, firewall, UFW, Defender, SecureBoot, MemoryIntegrity, network, other repositories or automations. No driver/callout/filter install, NDISRD, VNC, signed driver, vendor binaries, AGPL ProxiFyre, closed PR40, C++ WFP payload or paid operation.
