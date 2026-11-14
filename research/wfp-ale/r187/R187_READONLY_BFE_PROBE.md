# R187: Read-only BFE inventory prototype — not a Windows proof

Date: 2026-11-14. Independent FlowBridge WFP/ALE research ONLY. Branch: research/windows-wfp-ale-attribution-20261107. Expected initial HEAD: 734f87ca64d66a1451a6a74aa3c85f6c108b470a. Read-only main: 5b5afc2feeda2195f302380e615ba003d4906e09. Not beta or PR #56.

## Implementation and trust boundary

This checkpoint adds a Windows-only Rust user-mode BFE inventory candidate (windows-sys=0.61.2) without driver, WFP filter installation, network sockets, services or system changes. It opens a BFE management engine, uses FWPM_TXN_READ_ONLY, reads one R19 sublayer, four callout objects and four filters by exact source-derived GUIDs, checks layer/action/conditions (TCP = 6, originating AppId selection), enumerates visible sessions, frees BFE allocations and closes the engine. A complete management read returns STRUCTURE_OBSERVED_NOT_PROOF, never an authorization claim.

Pinned source: R19 policy_windows.rs blob acf60334320d970f58af3349ee75fbaa59826602 and policy_plan.rs blob 0c3d0e88eb9d06f4030131d9533da2d629dbdab0. The dynamic session and fixed filter GUID source are unchanged.

If any lookup fails, an ACL hides an object, or BFE/RPC fails, report UNKNOWN or NO_ATTESTATION. Even successful observations cannot attest actual callback execution, process origin, policy continuity, authorized first byte, absence of DIRECT, or relation to dynamic session generation. Session enumeration returns a snapshot, not a causally bound owner. No canonical executable or PID/creation-epoch attestation is attempted.

## Executed tests and limitations

Python unittest: 6/6 PASS, including mutation rejection of filter installation, driver registration, network socket API, writable transaction and forged GO. Independent Python and Node.js scanners: identical allowlists (12 local read-only BFE calls), six guards true, no violations. All five executable/source blobs are exact copies of the locally inspected and tested files.

No Rust toolchain in the executor and no Windows host. Therefore Rust was NOT compiled, and no actual BFE API was called. Static scans are not formal safety verification. This is a source prototype plus runnable negative guards, NOT a compiled PoC or native WFP test.

## Full proof chain still NO-GO

Selected canonical EXE and opaque AppId must be joined by an owned kernel process reference, PID/create epoch/start key and original ALE classify, not by user-mode correlation. Native ALE_CONNECT_REDIRECT_V4/V6, FwpsQueryConnectionRedirectState0, local redirect context, ALE_AUTH_CONNECT_V4/V6 including reauthorization, accepted-socket WSAIoctl redirect records/context, durable Witness ACK and CLAIM, and physical SSH must be one verifiable transaction. IPv4/IPv6 scope, sibling DIRECT, DNS/system resolver, UDP/QUIC, PID/5-tuple reuse, process death and BFE/SSH loss remain unproven.

Next decisive allowed test: compile the unmodified Rust source on an approved Windows 10 Pro user account, compare to an independent read-only BFE snapshot, and keep UNKNOWN on ACL/RPC errors. Do not alter firewall, services or access permissions. Any native driver/callout experiment requires separate owner decision and all rescue/rollback gates.

Microsoft official API documentation: 
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltergetbykey0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmcalloutgetbykey0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsublayergetbykey0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsessionenum0
https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization

No PacketBound/G2 PASS, leak-free, no-DIRECT or historical G1 acceptance asserted.
