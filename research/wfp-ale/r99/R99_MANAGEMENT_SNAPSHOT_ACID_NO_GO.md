# R99 — Non-atomic R98 read-only inventory may describe a policy that never coexisted

2026-11-11. Scope ONLY i-shutov/flowbridge branch research/windows-wfp-ale-attribution-20261107. Research parent c0052f075ce7e6282601997047301298246e44dc; read-only main 5b5afc2feeda2195f302380e615ba003d4906e09. Not beta, PR #56, release or G1/G2/PacketBound/no-leak acceptance.

## Source-level counterexample
R98 queries four filter and callout pairs in eight separate GETs outside an explicit BFE transaction. If exactly pair i exists at the time it is read, with different pairs present at subsequent times, R98 can aggregate all four successful observations into snapshot_gate_complete=true even if there has NEVER been an instant where all four management pairs coexisted. This is a temporal diagnostic false positive under a permitted abstract schedule, not a real Windows traffic leak or measured BFE schedule. Kernel callout registration dynamics are not represented by the masks.

## Independent deterministic negative evidence
Independent Python and Node.js enumerate 65,536 four-time four-pair management-presence schedules. Original sequential gate passes 4,096 cases. Of these, 2,401 have no instant of coexistence; 1,695 have coexistence at least once. Single read-only management transaction snapshot model accepts 4,096 cases where the initial state contains all four pairs. Minimal witness sequence: 0001,0010,0100,1000. Both oracles reproduce canonical SHA-256 0e675416d5dcd925a0725c1b6afc9c0612c19f9163bcaa10e4baacb3e4171610. This is a deterministic formal model, not a claim that a live BFE can realize every schedule.

## Functional clean-room Rust mitigation
New standalone Rust r99_readonly_bfe_transactional.rs is a narrowly changed copy of R98 from the exact parent Git blob. It places ALL eight BFE management GETs within one explicit READ-ONLY transaction using FwpmTransactionBegin0(engine, FWPM_TXN_READ_ONLY=1), commits only after all reads with FwpmTransactionCommit0 and has RAII FwpmTransactionAbort0 cleanup on unfinished transactions. Missing FWPM_ACTRL_BEGIN_READ_TXN access, begin failure or commit failure => exit 2 (no positive snapshot). Incomplete management shape => exit 3; all prerequisites => exit 0, meaning BFE management snapshot only. No flags=0 read/write transaction and no BFE object mutations. Historical R98 remains unchanged.

This does not guarantee atomicity of the kernel callout REGISTERED flag relative to management transactions; does not prove classifyFn execution, kernel origin, packet enforcement, WFP arbitration or continuous presence. It does not establish leak-free or no-DIRECT.

## Verification limits and next experiment
The Python and Node oracles ran offline and agreed; Rust x86_64 Windows compilation and WFP execution were NOT performed because neither an authorized Windows host nor rustc/Windows SDK exists in this research runtime. Exact Git Rust FFI, ACL, transaction runtime and dynamic callout registration require native validation. Next permitted decisive step: compile the exact Git R99 source on a separately authorized Windows x86_64 host, inspect SDK GUID/FFI, run harmless READ-ONLY BFE snapshot, collect OS build, caller ACL, rustc, binary SHA-256, JSON, time and exit code. Do not install/load driver/callout/filter, perform VNC/SYSTEM/network experiments, modify runner/services/firewall/security/automations, or incur costs.

Full kernel-origin chain remains NO-GO: referenced EPROCESS via PsLookupProcessByProcessId and PsGetProcessCreateTimeQuadPart epoch, exact canonical EXE/AppId at ALE_CONNECT_REDIRECT and AUTH_CONNECT v4/v6, original destination, endpoint/one-use ticket, redirected accepted SOCKET and WSAIoctl SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/_CONTEXT, SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on outbound socket before connect, authenticated SSH, sibling DIRECT denial. Process death/PID reuse, reused 5-tuple, IPv4/IPv6, DNS/UDP/QUIC, WFP/SSH loss remain open. No correlation substitutes for kernel proof.

Official Microsoft source contracts checked 2026-11-11:
https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionbegin0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactioncommit0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionabort0
https://learn.microsoft.com/en-us/windows/win32/fwp/access-right-identifiers
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection

Only four new research files. No main/release/beta/PR56/runner/services/firewall/security/networks/automations/other repos change.
