# FlowBridge WFP/ALE R2 — process epoch, async classify and read-only AppId

Date: 2026-11-07. Research branch only: research/windows-wfp-ale-attribution-20261107. Parent checkpoint 2ca14bce0c926316cf7bce28615355f7eb804a02. main was 5b5afc2feeda2195f302380e615ba003d4906e09. Not beta, not PR #56.

**Result: narrowed NO-GO.** Documented Windows APIs provide a plausible asynchronous ALE_CONNECT_REDIRECT classification path, but they do **not** establish the identity and lifetime of the original process for a specific live connection without native proof. The research does not authorize a driver, filter, callout, VM changes or network tests.

## Critical correction to the R1 hypothesis

* FWPS_CALLOUT_CLASSIFY_FN2 can be invoked at IRQL <= DISPATCH_LEVEL. PsLookupProcessByProcessId is pageable and allowed only at IRQL <= APC_LEVEL: direct lookup in a DISPATCH classify is illegal.
* **PsGetProcessCreateTimeQuadPart accepts any IRQL** once the caller already has a *valid referenced* EPROCESS. The gap is obtaining and pinning the *correct* process object at the classification boundary, not reading creation time itself.
* **FwpsPendClassify0 + FwpsCompleteClassify0** is the documented asynchronous path for ALE connect redirect. Use FwpsAcquireClassifyHandle0, respect action rights/STATUS_FWP_CANNOT_PEND, only access pageable APIs in a suitable worker context, then acquire writable layer data and complete/release classification. This pathway does not by itself solve PID reuse.
* **FwpsPendOperation0 is a different API.** Its documented applicable layers are ALE_RESOURCE_ASSIGNMENT, ALE_AUTH_LISTEN and ALE_AUTH_CONNECT, NOT ALE_CONNECT_REDIRECT. It must not be substituted for FwpsPendClassify0.
* PsSetCreateProcessNotifyRoutineEx / PCREATE_PROCESS_NOTIFY_ROUTINE_EX executes at PASSIVE_LEVEL and supplies Process (EPROCESS) and ProcessId for creation and exit. A generation registry is a candidate; pre-registration processes, missing callbacks, process exit, duplicate PID generations, reference-counting, locking at DISPATCH, and deferred-worker races are not proven safe.
* PS_CREATE_NOTIFY_INFO exposes FileOpenNameAvailable; when false, ImageFileName may be partial. File path bytes, filename, reparse/hardlink alias and process epoch are different identity questions. WFP fixed ALE_APP_ID must be compared as opaque application bytes.

## Required trust chain (all currently unverified)

1. An ALE_CONNECT_REDIRECT_V4/V6 classify supplies WFP-conditioned AppId, original destination and valid metadata bits FWPS_METADATA_FIELD_PROCESS_ID / PROCESS_PATH. No post-hoc tuple or ETW join is allowed.
2. A nonpaged, correctly synchronized, referenced EPROCESS registry snapshot for the precise PID generation must be established at the same classify boundary. A deferred PsLookup by numeric PID can resolve a **new process** after exit/reuse. A reference prevents object reclamation, not process termination or direct leakage.
3. A unique owned redirect ticket and original target are placed in FWPS_CONNECT_REQUEST0.localRedirectContext, localRedirectTargetPID and localRedirectHandle (from FwpsRedirectHandleCreate0). FwpsApplyModifiedLayerData0 pairs with each writable-layer acquisition.
4. The proxy accepts the genuine redirected socket; WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT) reads that socket's WFP context. Outgoing WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS) must precede connect; FwpsQueryConnectionRedirectState0 prevents loops/coexistence failures.
5. Selected-app sibling DIRECT, DNS from system resolver, UDP/QUIC, IPv6 scope/compartment, process death, SSH crash, WFP callout/filter disappearance remain separate system-level fail-closed gates. Local proxy denial is NOT OS-wide no-DIRECT.

## Actual artifacts and bounded validation

* epoch_lifecycle_negative.py + epoch_cases.json: 36 deterministic synthetic sequences, including missing/partial process callback data, stale PID, exit and new process between classify and PASSIVE worker, same PID+same epoch but new object, wrong process object, incomplete metadata, DISPATCH illegality, wrong pend API, failed pend, IPv4/IPv6, different AppId and race. Locally 36/36 PASS; four MODEL_CANDIDATE_ONLY are conditional assumptions, **not real WFP proof**. The source safety scan forbids BFE/filter/driver mutations in the Rust helper.
* appid_readonly.rs: dependency-free Windows user-mode Rust probe with only FwpmGetAppIdFromFileName0 / FwpmFreeMemory0 from Fwpuclnt.dll; compares two existing absolute file paths' opaque AppId bytes, prints only equality and lengths, never raw paths or AppId, creates no WFP engine session or filter.
* Offline command: python3 research/wfp-ale/epoch_lifecycle_negative.py
* Future Windows read-only compile: rustc --edition=2021 research/wfp-ale/appid_readonly.rs -o appid_readonly.exe; run with two explicit absolute EXE paths (same basename in different locations, then identical path). Exact result not established until executed.
* No Rust compiler in current container: Rust compile, 17 previous Rust R1 unit tests, Windows AppId invocation, real WFP classify, EPROCESS epoch source, driver and network operations were NOT RUN. No native acceptance, G2 remains OPEN/NO-GO. G1 10/10 remains historical only at dd1ab3c.

## Next decisive experiment

First establish compile/QA for the read-only AppId probe and independent two-path comparison without driver/filter deployment. Separately research a race-free nonpaged reference acquisition protocol for process notify/exit vs ALE classify, including pre-existing processes and STATUS_FWP_CANNOT_PEND; if no proof exists, preserve NO-GO. Any actual kernel callout/driver activation, protections, or native system fail-closed test needs the owner's signed-driver/isolated-VM/VNC/SYSTEM rescue and rollback gates.

## Official Microsoft sources (consulted 2026-11-07)

- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_classify_fn2
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendclassify0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscompleteclassify0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendoperation0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-pslookupprocessbyprocessid
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocesscreatetimequadpart
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_process_notify_routine_ex
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_incoming_metadata_values0_
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfreememory0
