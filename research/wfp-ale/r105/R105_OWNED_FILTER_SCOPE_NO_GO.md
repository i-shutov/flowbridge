# R105 — definitive *owned-filter* protocol and identity scope gap (negative proof)

Date: **2026-11-11**. Only `i-shutov/flowbridge`, `research/windows-wfp-ale-attribution-20261107`. This is independent research, **not beta, PR #56, PacketBound/G2, no-DIRECT, leak-free, or G1 acceptance**.

## Immutable source anchors

Baseline research HEAD: `c1163f2d183079619dab917df1343b7068c915c0`; `main`: `5b5afc2feeda2195f302380e615ba003d4906e09`.

- `research/wfp-ale/kernel-r19/policy_windows.rs` — Git blob `acf60334320d970f58af3349ee75fbaa59826602`. `conditions` builds exactly two `FWP_MATCH_EQUAL` conditions: `FWPM_CONDITION_IP_PROTOCOL == FWP_UINT8(6)` AND `FWPM_CONDITION_ALE_APP_ID == selected` for redirect, OR `FWPM_CONDITION_ALE_ORIGINAL_APP_ID == selected` for AUTH. `filter` sets `numFilterConditions=2`, and `RULES` has only four V4/V6 × AUTH/REDIRECT entries.
- `research/wfp-ale/kernel-r19/policy_plan.rs` — blob `c8ab344551f1adfc20fd0019c4606cf3ca3c81c4`: exactly four owned rules, no UDP/DNS/QUIC fallback policy in this module.
- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs` — blob `9a07e026134d46ef646d39862bd982cc48bbc5f6`: redirect and AUTH classify require protocol 6; a non-matching BFE filter does **not** invoke these callbacks merely because their kernel functions exist.
- `research/wfp-ale/kernel-r19/kernel/src/ledger.rs` — blob `b88c4c9237c4c118517978fc454f5048f522aa7f`: PID/epoch/EXE identity model is not a replacement for a policy covering omitted traffic.

## Source-level result and proof boundary

**For the four R19-owned filters only**, IP protocol 17 (UDP, including typical DNS/QUIC) cannot satisfy the exact equality condition `IP_PROTOCOL=6` in *either* family or *either* stage, even when AppId is exactly selected. ICMP (1 or 58) is also excluded. A different/sibling AppId, or a different canonical AppId byte string, is not covered by these exact filters even if the protocol is TCP.

Microsoft documents that all filter conditions must match before the filter's action is evaluated and that the ALE connect-redirection facility can in principle handle UDP as well as TCP. The omission here is a **deliberate R19 policy scope**, not a Windows inability to redirect UDP:

- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_condition0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection

**Consequences that ARE proved:** the four **owned** R19 filters do not call the FlowBridge callouts for matched-selected UDP flows and do not cover unrelated sibling AppIds. Merely proving all four objects exist, are enabled, and are transaction-consistent (R99/R103) cannot upgrade protocol or process coverage.

**Consequences that are NOT proved:** UDP packets actually left Windows, default WFP policy permitted them, any third-party/OS filter was absent, DNS was sent by the selected process rather than Windows DNS Client, a mismatched AppId occurred on a real host, or a DIRECT leak occurred. The absence of *owned-rule coverage* is a source/Boolean result, NOT a live packet observation or a global WFP-policy audit.

## Independent reproducibility

`r105_protocol_coverage.py` (predicate oracle) and `r105_independent.mjs` (separate explicit-rule oracle) each execute 256 synthetic combinations: family {4,6} × stage {AUTH,REDIRECT} × IP protocol {1,6,17,58} × current AppId {selected,sibling,alias,missing} × original AppId with the same four values.

Both executed independently on Python and Node.js and agree: **16 MATCH; 240 NO_MATCH**, matrix SHA-256 `5f311bc57889ffde3d3a9e644d29455fa78919ed27544ff8a03cbd0c0fd63fb9`.

Specific negative invariants: selected UDP never matches either stage in either family; sibling TCP does not match when both current and original identities are sibling; a byte-different canonical alias does not match; selected TCP can satisfy both; original-selected/current-proxy TCP matches the AUTH filter but not the redirect filter. These are model checks, not an ALE runtime transcript. The synthetic AppId values are labels, not a prediction of actual Windows canonicalization.

No Rust/Windows compilation, packet capture, firewall change, driver or WFP filter installation, service/runner/network change, VNC run, or privileged manipulation took place.

## Required trust chain and remaining NO-GO

1. `FwpmGetAppIdFromFileName0` / `GetFinalPathNameByHandleW` and `PS_CREATE_NOTIFY_INFO.FileObject` supply **candidates** for canonical selected EXE; numeric PID is not process identity.
2. `PsSetCreateProcessNotifyRoutineEx` plus referenced `EPROCESS`, `PsGetProcessCreateTimeQuadPart` and `PsGetProcessStartKey` must bind a *live* process generation. Pre-registration processes, process death and PID reuse remain NO-GO.
3. WFP filter coverage must hold at `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6` and `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` for every **claimed in-scope** protocol/application. R105 proves that TCP-only four-rule set cannot cover UDP.
4. `FWPS_INCOMING_METADATA_VALUES0` (`processId`, `transportEndpointHandle`, `localRedirectTargetPID`, `originalDestination`) and `FwpsQueryConnectionRedirectState0` must authenticate actual kernel classify events, their redirect records, a unique endpoint and unconsumed ticket. BFE management visibility cannot prove that event.
5. The *same* accepted socket must furnish `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`/`...RECORDS`, terminal kernel CLAIM and `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on the exact physical SSH socket. Reused endpoint/5-tuple, sibling DIRECT and SSH/WFP loss remain NO-GO.

## Next decisive **allowed** experiment

First, execute exact Git R99/R103 user-mode/read-only Windows x86_64 programs with compiler and SDK ABI checks plus transaction-consistent BFE inventory; preserve executable SHA-256, Windows build, JSON, exit code. In parallel, formalize a protocol-coverage acceptance matrix separating *selected TCP transparent capture* from *selected UDP/QUIC* and *system-service DNS*. Determine whether the owner requires intentional **TCP-only** scope, or a separately approved UDP/DNS fail-closed design. Do **not** infer no-DIRECT from positive BFE inventory, install a new filter/driver, or make a global-WFP claim.

No Git ref other than the explicitly allowed research branch may be moved. Any proposed ref mutation must use exact observed SHA, `force=false`; on conflict STOP and reread.
