# R98 — exact BFE condition and layer snapshot gate, Rust user-mode ONLY

2026-11-11. Scope: i-shutov/flowbridge, exclusively branch research/windows-wfp-ale-attribution-20261107; architectural R&D, not beta, PR #56, release, PacketBound/G2 PASS, leak-free or G1 acceptance.

## Reproducible source baseline
- Research parent: 3ee7786cdc977d3b816194fca76e150d9e110498 (R97). Read-only main: 5b5afc2feeda2195f302380e615ba003d4906e09.
- R93/R95 source: research/wfp-ale/r93/r93_readonly_policy_inventory.rs blob cd803fa6edc4e4dccdf914516fc85150b1e8c7d6.
- R19 producer: kernel-r19/policy_windows.rs blob acf60334320d970f58af3349ee75fbaa59826602; rule order policy_plan.rs blob c8ab344551f1adfc20fd0019c4606cf3ca3c81c4.
- R96 negative condition mismatch and R97 same-wrong-layer false positives remain source-level diagnostic findings.

## Functional change
A NEW research-only, standalone std-only Rust Windows x86_64 read-only inventory is in r98_readonly_bfe_inventory.rs; historical R93/R95 source is untouched. Allowed imports only:
FwpmGetAppIdFromFileName0, FwpmEngineOpen0, FwpmFilterGetByKey0, FwpmCalloutGetByKey0, FwpmFreeMemory0, FwpmEngineClose0.
It makes no BFE, driver, callout, network, service, or firewall mutation and forbids UNC/network-path executable arguments.

For each of 4 R19 rules (AUTH_CONNECT V4/V6, CONNECT_REDIRECT V4/V6), require existing R95 object-key/sublayer/action/callout registered/count gates PLUS:
- Both filter.layerKey and callout.applicableLayer equal the exact expected layer GUID, not just one another.
- Exactly two conditions in either order: AUTH uses ALE_ORIGINAL_APP_ID, REDIRECT uses ALE_APP_ID; exact FWP_MATCH_EQUAL, FWP_BYTE_BLOB_TYPE, opaque bytes obtained separately by FwpmGetAppIdFromFileName0 for the explicitly supplied local selected executable; IP_PROTOCOL equals TCP/6 with FWP_UINT8. Reject wrong path, app scope, bytes, type, field, match operation, protocol, duplicates, additional predicates, missing BFE object or registration flag.
- Fail closed for malformed/unavailable data, with JSON per-rule flags. Return 0 = four management **snapshot** matches ONLY, 2 = missing prerequisites/unavailable, 3 = incomplete snapshot. The snapshots are NONATOMIC.

### Independent model checks (offline, NOT native WFP)
A separate complete offline artifact includes std-only Python and independent Node.js oracles, 84 R96 source-specific fixture cases crossed with seven R97 layer variants: **588** synthetic snapshots; legacy R95 model accepted **320**, strict R98 model **8**, therefore **312** modeled false positives were removed. Both independent oracles agreed on canonical CSV SHA-256 **fd3320bf4b7b513192189ceb12d0beccd138e9f4b896f2a50ad30122088851f5**. Python static source inspection and independent ctypes x64-layout calculation passed for the separately packaged, functionally equivalent R98 prototype. Archive SHA-256 **6bf9a1fb4158d06078c40f0a00163f2bc6f3025a7ad55803ba68c6175aa3a56b**. The archive is a separate research work product delivered in the conversation, not a Git blob in this commit. Its Rust source is a separately authored implementation of the same predicates, not byte-identical to the Git file.

The Git file is a transparent extension of audited R93; review of exact newly created Git blob and readonly API-surface guard were done before ref publication. NO native Rust compiler or Windows x86_64 runtime was available in this isolated research environment. Therefore no claims of Rust compile PASS, ABI PASS, live BFE observation, classify execution or real packet behavior. Embedded Rust unit layout assertions are present but NOT RUN.

## Remaining causal proof / hard NO-GO
BFE object identity does NOT establish per-connection origin. Still require: same classify kernel selected PID+referenced EPROCESS+PsGetProcessCreateTimeQuadPart epoch+canonical EXE+AppId; ALE_CONNECT_REDIRECT V4/V6 FWPS_CONNECT_REQUEST0 state; AUTH_CONNECT rights, selected-source and redirected flow context; accepted socket queried with WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS and ..._CONTEXT); one-use CLAIM; outbound socket SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS before connect; authenticated SSH channel; and independent sibling DIRECT denial. No retrospective PID, 5-tuple or ETW correlation substitutes for kernel proof. Process death/PID reuse, tuple reuse, reauthorization, IPv4/IPv6 scope, DNS/UDP/QUIC, WFP/BFE/SSH loss, source-bind, local destination namespace and filter deletion remain NO-GO. No G1/G2/PacketBound or no-leak inference.

Next decisive permitted step: compile exact Git Rust file on a separately authorized existing Windows x86_64 environment using installed Microsoft SDK GUIDs/ABI and run its pure unit tests; only then issue BFE read-only queries with explicit local executable path and record OS build, rustc version, executable hash, principal/ACL, timestamps, output JSON and exit codes. No driver/filter/callout install and no network or VNC experiment. Any kernel proof needs separate owner decision and all driver/VNC/SYSTEM rescue/rollback gates.

Official Microsoft contracts:
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_condition0
- https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ns-fwptypes-fwp_condition_value0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltergetbykey0
- https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer

Nothing in main/release/beta, PR #56, infrastructure, WFP driver/filter/callout, Windows security, network/firewall, services, automations or other repository may be changed by this research commit.
