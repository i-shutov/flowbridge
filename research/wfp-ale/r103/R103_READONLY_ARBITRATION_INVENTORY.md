# R103 — ACL-conservative read-only BFE arbitration inventory

2026-11-11. Independent research exclusively on research/windows-wfp-ale-attribution-20261107. NOT beta, PR #56, PacketBound/G2 PASS, no-DIRECT, leak-free or historical G1 dd1ab3c.

## Exact baseline

Research parent: 7cb4239887fcdd96c3563fb899d77fab3156acbb
Main: 5b5afc2feeda2195f302380e615ba003d4906e09

R19 policy_windows.rs blob acf60334320d970f58af3349ee75fbaa59826602 installs four FWP_EMPTY rules in an owned sublayer across AUTH_CONNECT/CONNECT_REDIRECT v4/v6. R99 r99_readonly_bfe_transactional.rs blob 4e66ead8f802476125d343c8a039f9a9ea109a8a reads only four keyed filters and four callouts. R102 documented a conditional same-sublayer higher-weight PERMIT/BLOCK shadow; no actual WFP shadow or packet was observed.

## New functional code

r103_readonly_arbitration_inventory.rs is a standalone clean-room Rust x64, user-mode, read-only BFE inspector using only Microsoft-documented FwpmEngineOpen0, FwpmTransactionBegin0(FWPM_TXN_READ_ONLY), FwpmFilterGetByKey0, FwpmFilterCreateEnumHandle0, FwpmFilterEnum0, FwpmFilterDestroyEnumHandle0, FwpmFreeMemory0, FwpmTransactionCommit0/FwpmTransactionAbort0 and FwpmEngineClose0.

It anchors the four expected FlowBridge rules to exact layers/sublayer and reads the pointer-backed FWP_UINT64 effectiveWeight, not an inline 64-bit integer. It creates the enumerator within the read-only transaction, scans visible filters in pages of 128 with a cap of 131072 entries, releases the returned pointer array (not nested filter pointers), counts same-layer/sublayer foreign filters by lower/equal/higher effective weight, and commits the read-only snapshot.

ERROR -> UNKNOWN (exit 2); higher/equal visible competitor -> VISIBLE_ARBITRATION_CANDIDATE (exit 3); none visible -> UNKNOWN_NO_VISIBLE_CANDIDATE (exit 4). No PASS or SAFE status exists.

Crucially, Microsoft states FwpmFilterCreateEnumHandle0 returns only filters readable by the caller (FWPM_ACTRL_ENUM/READ). A complete enumerated snapshot can omit inaccessible policy. No visible competitor NEVER establishes its absence, and a visible higher/equal-weight filter does not prove condition overlap, PERMIT/BLOCK action or runtime callout suppression.

## Reproduced deterministic tests

Two independent Python and Node scripts each enumerate 256 synthetic states: 192 UNKNOWN_ERROR, 16 VISIBLE_CANDIDATE, 48 UNKNOWN_NO_VISIBLE; both PASS with identical matrix SHA-256 043bcfce45bb8c228b192f702de3751a44e423bfb1e663d404e3fdcd0eb1a5cb. An ACL-hidden higher-weight filter with no visible competitor yields UNKNOWN, not SAFE. Independent ctypes static x64 model checks nine structure sizes/offsets and source guards for no WFP writes/sockets/process spawn; PASS.

No local rustc, authorized Windows x86_64 build or native WFP proof in this run. Rust source NOT compiled or executed. Nothing installed, no filters, drivers, services or network operations.

## Architecture and next safe experiment

Still NO-GO: kernel PID+creation epoch/start key+canonical EXE -> authentic ALE AppId/CONNECT_REDIRECT v4/v6 -> AUTH_CONNECT -> lifetime-bound one-shot receipt through process death/PID reuse/repeated 5-tuple -> accepted SOCKET and redirect records -> CLAIM -> SOCKS/SSH. Sibling DIRECT, DNS/UDP/QUIC and WFP/BFE/SSH loss remain unproved. Management inventory is not kernel-origin or leak-free proof.

Next: compile exact Git R99/R103 source on an already-authorized Windows x86_64 user-mode host, verify native SDK ABI, capture Windows build, rustc version, binary SHA-256, read-only BFE JSON and exit code. ACL-hidden and errors remain UNKNOWN. No driver/callout/NDISRD/WFP filters, VNC, paid work or security/network changes without owner gates.

Official Microsoft sources:
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-weight-assignment
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltercreateenumhandle0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterdestroyenumhandle0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0

No changes permitted to main/release, beta integration/windows-rust-capture-agent-20261031, PR #56, runner, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, networks, other repos, automations; no ProxiFyre AGPL, closed PR40, vendor binary or C++ WFP payload.
