# R193 — AUTH_CONNECT redirected bit does not identify the redirecting provider

2026-11-15. Independent architecture research, exclusively i-shutov/flowbridge, branch research/windows-wfp-ale-attribution-20261107. Not beta, PR #56, a kernel acceptance test, PacketBound/G2 PASS, no-DIRECT or leak-free.

## Pinned code and trust boundary

Research input HEAD: 458741dd8a5f526a8788562043aa69cf51f9246e. Main input HEAD, read-only: 5b5afc2feeda2195f302380e615ba003d4906e09.

Verified pinned blob SHAs:
- R19 kernel/src/redirect.rs: a093f049d162987981a957aac90db1014bc6ff09
- R19 kernel/src/handoff.rs: e1d17217db50362ba9c4efc83af820b6beb094cf
- R19 kernel/src/lib.rs: 53f5ce6faa0f9f591974287f38ea890cafeb0dd2
- R19 policy_windows.rs: acf60334320d970f58af3349ee75fbaa59826602

R19 redirect::auth_check requires FWP_CONDITION_FLAG_IS_CONNECTION_REDIRECTED (0x00100000), rejects REAUTHORIZE and HONORING_POLICY_AUTHORIZE, checks process ID, transport endpoint, original destination, local redirect target PID, original selected AppId, TCP/loopback/port, route readiness, a pinned live owner and a matching one-time Book::attest ticket. These are meaningful origin/endpoint/epoch checks, not an arbitrary PID/tuple correlation.

However, the source AUTH predicate never queries provider-relative redirect state against FlowBridge's redirect HANDLE and has no explicit final redirect-provider generation check. The redirected flag establishes that *some* ALE redirection occurred, not that FlowBridge's redirect was the final redirection on this flow. In contrast, R19 redirect::classify uses FwpsQueryConnectionRedirectState0 at ALE_CONNECT_REDIRECT. The public API documents its redirect-record handle as being supplied at ALE_CONNECT_REDIRECT, not as an unqualified AUTH_CONNECT provenance oracle.

Conditional countermodel: if the same selected endpoint, original destination, live ticket and all required AUTH metadata are observable after (A) a FlowBridge-only redirect and (B) an additional foreign redirect ending at the same broker and port, current AUTH predicate yields identical candidate PERMIT results. **It is not shown that Windows can realize case B** while preserving these exact observations. No observed packet leak or actual unauthorized socket claim is asserted. The source-level limitation is strictly that provider-exclusive final-redirection provenance is not independently evidenced by the present AUTH fields.

## Independent deterministic negative tests

Run: python3 research/wfp-ale/r193/auth_provenance_negative.py (8/8 PASS), also with Python -O and -OO (8/8 each). Generate CSV with --matrix; compare to node research/wfp-ale/r193/independent_oracle.mjs: 1024 ordered rows identical, SHA-256 6483ba28d9686752a821ed9c505bf33d24dc55d07a8b2ac3f7033cf156c79c49.

The model explicitly *assumes* valid UTF-16 AppIds, mandatory metadata, loopback port, a unique matching live ticket and available action-write; alternate redirect-provider histories have identical metadata. Four synthetic positive candidates represent two families times two stipulated histories. Remaining 1020 states are negative in this deliberately simplified predicate. It neither simulates real Windows redirect scheduling nor proves that a foreign history is reachable. No driver, callout, WFP filter, BFE setting, network socket, runner or Windows host was operated.

Official Microsoft contracts:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-flags
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_incoming_metadata_values0_

## Unproved end-to-end obligation and decisive next experiment

The intended proof remains: referenced EPROCESS / process-create PID + PsGetProcessCreateTimeQuadPart + PsGetProcessStartKey + FileObject / canonical EXE -> exact ALE_CONNECT_REDIRECT v4/v6 selected AppId, endpoint, redirect handle and context -> ALE_AUTH_CONNECT ORIGINAL_APP_ID + WFP original destination + one-use kernel ticket -> actual accepted socket with WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT) -> same-requestor CLAIM -> outbound socket WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS) -> observed SSH forwarding. Each join needs independent evidence. Reused PID/5-tuple, sibling DIRECT, UDP/DNS/QUIC, IPv6/compartments, process death, BFE arbitration, reauthorization and WFP/SSH loss remain NO-GO.

Allowed first: compile and execute R190 **read-only user-mode Rust** BFE inventory on a separately admitted Windows 10 Pro x64 host; record OS/Rust/binary SHA/API status/ACL. This only verifies management configuration, never provider chronology or no-DIRECT.

Native proof of redirect-provider chronology and accepted-socket lineage would require explicit owner authorization and all driver/VNC/SYSTEM rescue/rollback gates. Until such evidence exists, no kernel-origin/continuous-enforcement or leak-free GO is permitted. No protected branch, beta, PR #56, service, driver, filter, firewall, OS security setting, network, runner, automation or cost mutation in this cycle.
