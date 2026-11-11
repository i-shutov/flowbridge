# R107 — kernel PING does not attest BFE/WFP enforcement

Date: 2026-11-11. Independent architectural R&D only for i-shutov/flowbridge, branch research/windows-wfp-ale-attribution-20261107. Baseline research 215e4b54485141a382cd350a58ddc305c1e23474, main 5b5afc2feeda2195f302380e615ba003d4906e09. NOT beta/PR #56/PacketBound/G2/no-DIRECT or historical G1 dd1ab3c.

## Exact source-level negative

R19 broker.rs Git blob ce6c549a9ae488cc7c0ca9a7e7be68871b9d7f2c starts one heartbeat consisting only of kernel Device::command(PING). The research-only --serve-research path calls serve(..., activate_policy=false) but still calls device.arm and the same PING heartbeat; policy=if activate_policy { ... } else {None}. Hence PING readiness and four installed R19-owned BFE filters are distinct state variables BY DESIGN. That research mode explicitly disclaims policy, and no real Windows process, kernel callout or packet result was observed.

The actual kernel redirect.rs blob 9a07e026134d46ef646d39862bd982cc48bbc5f6 checks only broker lease, owner ledger and Book::lost on PING, without querying BFE. policy_windows.rs blob acf60334320d970f58af3349ee75fbaa59826602 uses FWPM_SESSION_FLAG_DYNAMIC; policy_plan.rs blob c8ab344551f1adfc20fd0019c4606cf3ca3c81c4 verifies filters only ONCE after installation commit. No ongoing BFE filter check or FwpmFilterSubscribeChanges0 in those four files. Fresh GitHub reads verified ten separate source predicates: 10/10 PASS.

The separately admitted policy-on branch could lose management availability during BFE/session faults while its kernel lease remains independently healthy; this is a HYPOTHESIS only. Broker process termination itself normally terminates the heartbeat too: do not misrepresent it as native PING healthy during broker crash (R106). Deletion of dynamic objects from a DIFFERENT dynamic session fails FWP_E_WRONG_SESSION: no arbitrary foreign deletion claim.

## Independent deterministic test

r107_bfe_notification_negative.py: Python Cartesian oracle. r107_bfe_notification_independent.mjs: separately written Node bitwise oracle. Both executed locally: 128/128 identical ordered rows (IPv4/v6, sixteen masks of four filters, PING yes/no, hypothetical notification delivered/missed). Abstract candidate states with green PING + incomplete BFE filter inventory + no delivered event: 30. Each family contains the paired worlds 1111|PING=1|event=0 vs 0000|PING=1|event=0, with identical observable heartbeat/event fields and differing hidden inventory. These are model-only states, NOT a real BFE outage, packet, DIRECT leak or callback observation. Ordered matrix SHA-256 independently identical:
9da720fc2c30961094c004eb4d3da58219072c91b265307877cfc438f473ac41

No Windows, driver, filter, socket, runner, network or system mutation. Native Rust/Windows compilation was not performed. Missing notifications are hypothetical for R19 because it is not subscribed. Microsoft states change notifications are asynchronous and unreliable, require subscription and appropriate ACL. Periodic read-only FwpmTransactionBegin0 + FwpmFilterGetByKey0/Enum0 can improve visibility but are only temporal management snapshots, not per-flow kernel callback proof or an OS fail-closed barrier. Query/ACL/commit uncertainty => UNKNOWN, never SAFE.

## Trust chain and next decisive experiment

A full physical proof still needs referenced EPROCESS/FileObject via PS_CREATE_NOTIFY_INFO and PsGetProcessCreateTimeQuadPart/PsGetProcessStartKey; canonical EXE & FwpmGetAppIdFromFileName0; v4/v6 ALE CONNECT_REDIRECT/AUTH_CONNECT native metadata, FwpsQueryConnectionRedirectState0, original destination and one-use kernel ticket; accepted SOCKET SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS; CLAIM causality; physical pinned SSH SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS; process death/PID reuse, repeated 5-tuple, sibling DIRECT, DNS/UDP/QUIC and WFP/SSH loss.

R107 NO-GO: PING green is not BFE/WFP enforcement health; best-effort notifications cannot make it a fail-closed certificate. PacketBound/G2/leak-free remain NO-GO.

Next allowed experiment: compile pinned read-only R99/R103 Rust user-mode tools on an already authorized Windows x86_64 host; check SDK ABI, capture binary SHA-256, Windows build, JSON/exit codes, ACL limits and BFE snapshot only. No new driver/callout/filter, physical loss, network or VNC test absent separate owner decision and gates.

Official Microsoft docs:
https://learn.microsoft.com/en-us/windows/win32/fwp/change-notifications
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltersubscribechanges0
https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterdeletebykey0

All writes limited to new research/r107 files; no main, release, beta integration/windows-rust-capture-agent-20261031, PR #56, other repositories, infrastructure, OS protections or automations. No AGPL ProxiFyre, closed PR40, vendor binaries or C++ WFP payload.
