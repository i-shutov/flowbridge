# R123 — Same-sublayer lower-weight filter after `CALLOUT_UNKNOWN` CONTINUE

2026-11-12. Scope: **only** `i-shutov/flowbridge` branch `research/windows-wfp-ale-attribution-20261107`, independent architecture R&D, not beta `integration/windows-rust-capture-agent-20261031`, PR #56 or any release branch. Parent research HEAD `d9318a127173abb65c56246d0854d18174a3b096`; read-only main `5b5afc2feeda2195f302380e615ba003d4906e09` (reverify immediately before ref mutation).

## Material source-derived false negative

The read-only BFE filter enumerator in R103 (`r103/r103_readonly_arbitration_inventory.rs`, prior Git blob `49506ca07145c18947a0845f2a1a63b3de1f54ec`) outputs per-rule foreign effective-weight counters `visible_higher/equal/lower`. Yet its terminal `VISIBLE_ARBITRATION_CANDIDATE` classification previously counted **only** `higher/equal`. R112's native PowerShell harness (`r112/R112_WINDOWS_NATIVE_READONLY_CHECK.ps1`, prior blob `84944754c9cfdf0526a8783d3e5d8a727c6e2bdd`) repeated the same threshold.

For the exact R19 policy source `kernel-r19/policy_windows.rs` (blob `acf60334320d970f58af3349ee75fbaa59826602`), `ALE_CONNECT_REDIRECT_V4/V6` uses `FWP_ACTION_CALLOUT_UNKNOWN`, which allows the callout to return `FWP_ACTION_CONTINUE`. The pinned kernel source `kernel-r19/kernel/src/redirect.rs` (blob `9a07e026134d46ef646d39862bd982cc48bbc5f6`) contains a self-redirect return path, while the wrapper `kernel-r19/kernel/src/lib.rs` (blob `0af6d4539673d2894cbaa91af0ea8f3524862a26`) initializes `FWP_ACTION_CONTINUE`. Microsoft WFP arbitration explicitly evaluates lower-weight matching filters within the **same sublayer** after CONTINUE. Therefore, if a foreign filter has lower effective weight and overlapping conditions, it **can still be evaluated** even if higher/equal counts are zero. Old inspector/harness labeled such a snapshot `UNKNOWN_NO_VISIBLE_CANDIDATE` — diagnostic candidate under-reporting. This is not packet evidence and does not show that any real lower filter matches.

By contrast `ALE_AUTH_CONNECT_V4/V6` uses `FWP_ACTION_CALLOUT_TERMINATING`, and Microsoft requires its classify callback to decide BLOCK or PERMIT (CONTINUE treated as BLOCK), so R123 leaves the lower-only case noncandidate for AUTH; it retains higher/equal candidate detection. The R118 issue involved **lower-priority sublayers**, a distinct arbitration dimension. R123 fixes only own-sublayer lower-weight filter diagnostic classification.

## Exact implementation and receipts

- R103: new pure `candidate_for_rule(rule_index,higher,equal,lower)` returns `higher>0 || equal>0 || (rule_index>=2 && lower>0)` for the established order `[auth_v4,auth_v6,redirect_v4,redirect_v6]`. One native Rust unit test covers all four rules, lower-only/zero/higher/equal. No changes to FFI calls, enum scope, BFE, filters, or runtime policy.
- R112: PowerShell transcript classification applies the same predicate to its four strictly validated JSONL rule records. Counter schema and exit codes remain unchanged; status `VISIBLE_ARBITRATION_CANDIDATE` / code `3` remains a **candidate, never a security PASS**; code `4` remains UNKNOWN.
- Python negative oracle in `r123/r123_lower_weight_continue_negative.py`: 6/6 tests PASS including static assertions for both patched sources. Independent Node oracle in `r123/r123_lower_weight_continue_independent.mjs`: 256/256 ordered cases match Python SHA-256 `0afca413b90d63f641c21164503c57bdbd427ba3804dee315393eb2681d9e82f` (4 rule indices x 4 values each for higher/equal/lower). There are six synthetic lower-only states newly recognized across both redirect families and 246 total candidate states. **Zero Windows WFP observations.**
- Native Rust x64 tests and Windows PowerShell 5.1 execution **NOT RUN**: no Windows execution channel or rustc in the local environment. No driver, kernel, live BFE or network experiment attempted.

## Exact trust chain — limits of this finding

1. Source process: `PsSetCreateProcessNotifyRoutineEx` and `PS_CREATE_NOTIFY_INFO` (creation-time observed `FileObject`, full file path availability); hold referenced `EPROCESS` and file object, `PsGetProcessCreateTimeQuadPart`, `PsGetProcessStartKey`, and compare canonical NT image path against `FwpmGetAppIdFromFileName0`/original `ALE_APP_ID`. PID-only correlation, ETW, EXE basename, or a 5-tuple **cannot** substitute a kernel same-classify certificate. Process exit, PID reuse, pre-driver process and aliases remain conditional NO-GO.
2. Layer/flow: `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6` with `FWPS_METADATA_FIELD_PROCESS_ID`, transport endpoint and redirect state via `FwpsQueryConnectionRedirectState0`; `FWPS_CONNECT_REQUEST0` and `FwpsApplyModifiedLayerData0`; `ALE_AUTH_CONNECT_V4/V6` with original AppId, original destination and trustable same-endpoint ticket through initial/reauthorization, including reused 5-tuple. R120 documented `AUTH_CONNECT` metadata specification divergence; no native resolution.
3. Socket/egress: kernel terminal one-use receipt, accepted SOCKET queried using `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)`, terminal `DeviceIoControl(CLAIM)`, `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on the actual outgoing SSH TCP socket, trusted host key/auth and SSH `direct-tcpip`. R121/R122 compartment, source/remote destination namespace and physical route remain independent NO-GO.
4. Global enforcement: sublayer priority and action rights, sibling DIRECT, surviving process death/PID and endpoint reuse, IPv4/IPv6, DNS/UDP/QUIC, BFE/SSH/WFP loss and dynamic policy teardown **not proven**. WFP/BFE enumeration is ACL-limited and time-scoped; cannot be promoted to classify execution, no-DIRECT/leak-free, PacketBound/G2, or historical G1 `dd1ab3c` PASS.

## Next decisive authorized experiment

Use the **already authorized** Windows 10 x64 user-mode research QA channel, if and only if accessible without runner, service, system, network or settings mutation: exact Git-blob checkout of R115–R118/R123 and run Windows PowerShell 5.1 read-only compiler/ABI checks, patched R123 synthetic Rust unit tests and PowerShell JSONL negative fixture. Preserve original source SHA, binary SHA-256, `rustc -vV`, PowerShell parser results, exit code and full JSONL receipts. Separately, with existing authorization, optionally read-only BFE enumeration; if only lower-weight matching **potential** peers appear under redirect, result is code 3 (diagnostic), never a native packet proof. No write or filter creation. Physical `classifyFn`/actual redirect tests require separate owner decision and all driver/VNC/SYSTEM rescue/rollback gates, **not** authorized here.

## Official documentation checked 2026-11-12

- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
- https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_action0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0

**Isolation:** main/release/beta/PR #56, other repos, runners/CI, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, networks, controllers, schedules and automation state untouched; no ProxiFyre AGPL, closed PR40, vendor binaries, C++ WFP payload, driver/callout/filter, NDISRD, VNC experiment, signed driver or paid operation. Mutate research ref only with exact observed expected SHA, `force=false`; on conflict STOP/re-read.
