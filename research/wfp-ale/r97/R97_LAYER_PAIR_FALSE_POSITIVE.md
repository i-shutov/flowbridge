# R97 — wrong-layer BFE inventory false positive (research only)

Date: 2026-11-11. Only i-shutov/flowbridge, branch research/windows-wfp-ale-attribution-20261107. Not beta, PR #56, PacketBound/G2 or G1 acceptance.

## Reproducible source-level finding

Source inputs read from Git at research HEAD 8edb9af3c5b595b19cf401bf8efec91738d23f42, main HEAD 5b5afc2feeda2195f302380e615ba003d4906e09:
- research/wfp-ale/r93/r93_readonly_policy_inventory.rs (blob cd803fa6edc4e4dccdf914516fc85150b1e8c7d6).
- research/wfp-ale/kernel-r19/policy_windows.rs (blob acf60334320d970f58af3349ee75fbaa59826602).

R95 checks filter.layer_key == callout.applicable_layer, but neither field is checked against the EXPECTED ALE layer GUID for that particular rule. R19 chooses four different layer GUIDs: ALE_AUTH_CONNECT_V4/V6 and ALE_CONNECT_REDIRECT_V4/V6. Matching WRONG layer GUIDs can therefore satisfy the existing diagnostic shape criterion while the intended layer is missing. This is a source-level false positive of the management-plane gate, not native proof that such wrong-layer BFE objects can be installed or that traffic escapes.

## Deterministic negative tests

Files r97_layer_negative.py and r97_layer_independent.mjs use independent Python/Node enumerators and directly guard relevant source text. For each of four rule slots, test five candidate filter layers times five candidate callout layers. All other R95 gates are assumed true to isolate this criterion. 100 deterministic cases: old criterion accepts 20, strict expected-layer comparison accepts 4, and 16 are old-model false positives. Canonical CSV SHA-256: 179ee2ac2377a9a4361016eaba1dddb23971aefd46bc0e56c03a8e5d7ad610bb. Both implementations produced identical counts/hash. Local execution used focused fragments of the two connector-verified Git blobs, NOT a full checkout: full-file source guards must still be rerun on checkout. No Windows/Rust native execution.

Separate uncommitted R96 local tests exposed another gap: R95 checks count of two conditions but not exact fieldKey/matchType/dataType/value (ALE_APP_ID vs ALE_ORIGINAL_APP_ID, TCP/6, selected executable opaque AppId).

## Required changes / trust boundary

Read-only Rust inventory must additionally require filter.layerKey == expected[rule] and callout.applicableLayer == expected[rule] for the four exact Windows SDK layer GUIDs. Keep existing equality/subLayer/action/callout checks. It must inspect both filter-condition contents and selected AppId, with ABI-checked WFP structs and byte bounds. This research commit contains only model tests/report; it does NOT patch or compile the inventory implementation.

Microsoft primary contracts:
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_callout0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_condition0
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltergetbykey0

## NO-GO and next decisive permitted experiment

WFP management snapshot is NOT a kernel connection-origin receipt. PID+creation epoch+canonical EXE/AppId, ALE AUTH/REDIRECT execution, redirect records and accepted socket -> one-use CLAIM -> SSH cannot be proven from an inventory. Process death/PID reuse, reused 5-tuple, sibling DIRECT, IPv4/IPv6, DNS/UDP/QUIC, WFP/SSH loss and continuous no-DIRECT enforcement remain unproven. No PacketBound/G2 PASS or leak-free claim.

Next: build a research-only Rust x86_64 user-mode copy on an already authorized Windows host; ABI-test, validate exact layer GUIDs and actual filter conditions, then perform read-only FwpmFilterGetByKey0/FwpmCalloutGetByKey0 queries. Preserve OS build, privilege, binary SHA-256, raw JSON and exit codes. No driver, filter, callout, VNC, network, service, security, CI or automation mutations.
