# R184 — Dynamic BFE session policy-lifetime NO-GO

Baseline research branch: d2726f16d19fa2dd016b3a404d4e7cddb0be8f8d. Read-only main: 5b5afc2feeda2195f302380e615ba003d4906e09. This is architecture R&D, not beta or PR #56.

## New source-level finding

R19 policy_windows.rs, exact blob acf60334320d970f58af3349ee75fbaa59826602, opens FwpmEngineOpen0 with FWPM_SESSION_FLAG_DYNAMIC, then adds one fixed sublayer key SUB, four fixed callout keys and four fixed filter keys in a transaction. Installed owns the Engine; close/Drop calls FwpmEngineClose0. policy_plan.rs exact blob 0c3d0e88eb9d06f4030131d9533da2d629dbdab0 has no independently owned standby policy.

Microsoft explicitly documents that objects created in a dynamic WFP session are automatically deleted when its owning session ends, including process termination. Therefore, if R19's policy-owning process exits while the selected process survives, R19's own AppId-specific redirect/AUTH filters disappear for new classifications. A loaded driver, cached process reference, FBR3 ticket or durable Witness journal does not by itself preserve these filters. **Documented source-contract NO-GO for using this dynamic policy as sole fail-closed continuity guarantee. NOT proof of DIRECT/packet leakage.** Other providers may still block traffic.

All R19 sublayer and filter GUIDs are fixed. A second, independent dynamic session cannot add another sublayer with the same globally unique GUID while the old exists. The current installer neither adopts existing dynamic objects nor uses distinct generation-specific GUIDs. Thus a naive old-close-then-new-install creates a period with none of its own filters, while naive overlapping install collides. A hypothetical distinct-key overlap would avoid only the abstract policy-object absence, not guarantee valid WFP classification, packet ordering or safe handoff.

## Negative tests, independent oracle

Pure user-mode offline Python and independent Node.js sources cover 64 deterministic scenarios: v4/v6 × TCP/UDP × selected/sibling × external-blocker yes/no × owner-exit/close-first/fixed-key-overlap/distinct-key-overlap. Each row marks effective physical enforcement UNKNOWN. Twelve of 16 selected-TCP rows have a modelled own-filter gap; four distinct-key cases are strictly hypothetical. Sixteen cases show a GUID-key collision. Sibling DIRECT and UDP/DNS/QUIC have no R19 selected-AppId/TCP filter coverage even before policy-owner exit.

Executed: Python unittest 9/9 each in normal, -O and -OO; Python/Node 64/64 identical canonical JSONL. Matrix SHA-256 1c862f9016d74e70572b607b2acc456f627bc8cc88dc5c1df02b3d0ae332cf0f. No native Windows session or network experiment, no driver, WFP filter or services changed; models do not prove physical leak.

## Trust boundary and decision

The missing kernel-owned identity joins remain: process/image via PsSetCreateProcessNotifyRoutineEx, PsGetProcessCreateTimeQuadPart and PsGetProcessStartKey; ALE_CONNECT_REDIRECT/AUTH_CONNECT V4/V6, AppId/original AppId/compartment, reauthorization and flow lifetime; accepted-socket WSAIoctl redirect records; Witness durable ACK; one-shot CLAIM; physical SSH record propagation. PID reuse, reused 5-tuple, sibling DIRECT, IPv6 and DNS/UDP/QUIC remain unresolved. R183 journal-order fix cannot restore a filter removed by dynamic session rundown.

Decisive next choice: establish whether fail-closed continuity during policy-owner death/BFE loss is a product requirement. If yes, current dynamic-session policy cannot be the sole enforcement anchor. Do not silently substitute persistent or boot-time WFP filters: persistence does not prove continuous enforcement during BFE failure and demands separate owner authorization and driver/VNC/SYSTEM rescue/rollback gates. A permitted first read-only Windows Rust inventory could call FwpmSessionEnum0, FwpmSubLayerGetByKey0 and FwpmFilterGetByKey0; management snapshots cannot prove effective classification/egress.

Microsoft:
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0
- https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineclose0

Overall WFP/ALE NO-GO; no PacketBound/G2 PASS, no no-DIRECT/leak-free assertion or inherited G1 dd1ab3c. No change to main, release, beta, PR #56, drivers, filters, machine settings, network, runners or automation.
