# R185 — Unregistered callout vs dynamic filter deletion

R&D only, branch research/windows-wfp-ale-attribution-20261107. Baseline research HEAD 502230d02561656da80fa004f93956703f47400b; main read-only 5b5afc2feeda2195f302380e615ba003d4906e09. No beta or PR #56 changes.

## Materially different failure states

Exact R19 source research/wfp-ale/kernel-r19/policy_windows.rs, Git blob acf60334320d970f58af3349ee75fbaa59826602:
- Engine::open requests FWPM_SESSION_FLAG_DYNAMIC;
- four selected-application TCP filters cover ALE_CONNECT_REDIRECT and ALE_AUTH_CONNECT for v4/v6;
- each filter sets f.flags=0; REDIRECT action FWP_ACTION_CALLOUT_UNKNOWN, AUTH action FWP_ACTION_CALLOUT_TERMINATING;
- installer verifies FWPM_CALLOUT_FLAG_REGISTERED only at installation, not continuously.

Microsoft documents that, while the filter remains installed, UNKNOWN and TERMINATING filters are treated as BLOCK if the referenced kernel callout is unregistered. This is a narrowly applicable filter-level fallback, not a guarantee of effective traffic isolation or the behavior of all WFP filters. R19 does not set FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED. Adding that flag would instead treat the unregistered-callout filter as PERMIT at the filter level.

When the dynamic BFE session owner dies, the R19 filter objects are removed, so the absent-callout BLOCK fallback disappears regardless of whether the callout remains registered. During BFE loss this source/API fallback cannot be extrapolated. Registered callout means its classify outcome is unknown without native runtime evidence. Sibling apps, UDP/DNS/QUIC and unmatched flows are not covered by the four R19 filters. R184 policy lifetime NO-GO remains intact.

## Executable offline tests

The Python model and independent Node.js fact-table oracle enumerate 256 scenarios: v4/v6, selected/sibling, TCP/non-TCP, BFE available/unavailable, dynamic session alive/dead, callout registered/unregistered, REDIRECT/AUTH, flag off/on. Both produce byte-identical canonical JSONL (256/256); SHA-256 b17189a86f59132b9a8f1cee1954f2bf3d93634a025da5245612ae80d5f72190. Python unittest: 9/9 each in normal, -O and -OO. Counts are 240 no-R19-match-or-BFE-unavailable, 8 registered-callout-runtime-unknown, 4 filter-level BLOCK, 4 hypothetical mutated-flag filter-level PERMIT. Counts are model rows, NOT probabilities or packet results.

No driver or callout was installed or run; no WFP filter, service, firewall, network, host or runner was changed. Native Rust/Windows verification was not executed (rustc absent). This is a conditional source/API-contract finding with executable negative tests.

## Trust boundary and next decisive experiment

A read-only Windows Rust inventory should query FwpmFilterGetByKey0, FwpmCalloutGetByKey0, FwpmSubLayerGetByKey0, FwpmSessionEnum0, and free with FwpmFreeMemory0. It must compare four exact R19 keys, conditions, action and flags, and report UNKNOWN on absent/inconsistent objects. Inventory is not enforcement proof: a kernel-origin transaction across referenced process/image plus PID/creation epoch/canonical EXE, WFP ALE_REDIRECT/AUTH with original AppId, compartment and reauthorization, accepted socket query redirect records, Witness durable ACK, CLAIM and physical SSH record set remains unproven. PID and 5-tuple ABA, sibling DIRECT, IPv6 scope, UDP/DNS/QUIC, BFE/SSH loss need native evidence and appropriate owner safety gates.

Official documentation:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscalloutunregisterbyid0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0
- https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmcalloutgetbykey0

**Overall WFP/ALE remains NO-GO**; no PacketBound/G2 PASS, no no-DIRECT or leak-free claim. Protected refs and operational infrastructure are untouched.
