# R102 — Same-sublayer arbitration blind spot in a complete R99 BFE inventory

2026-11-11. Independent FlowBridge WFP/ALE R&D. ONLY research/windows-wfp-ale-attribution-20261107; NOT beta, PR #56, PacketBound/G2, leak-free/no-DIRECT, historical G1 dd1ab3c.

## Exact baseline and source pins

Research parent: `17957ccf1861967f97bfc03beea5158434b34ec8`; main: `5b5afc2feeda2195f302380e615ba003d4906e09`.
- R19 `kernel-r19/policy_windows.rs` blob `acf60334320d970f58af3349ee75fbaa59826602`: four exact AppId + TCP/6 WFP filters all in owned sublayer `1649f024-25b3-4e01-9ca1-5ca803010019`; `weight.type=FWP_EMPTY`.
- `kernel-r19/policy_plan.rs` blob `c8ab344551f1adfc20fd0019c4606cf3ca3c81c4`: AUTH_CONNECT v4/v6 and CONNECT_REDIRECT v4/v6.
- R99 `r99/r99_readonly_bfe_transactional.rs` blob `4e66ead8f802476125d343c8a039f9a9ea109a8a`: reads exactly four keyed filters and four callouts in one read-only transaction; no foreign filter enumeration, effective-weight or arbitration check.

## Conditional counterexample grounded in Microsoft contracts

Microsoft Filter Weight Assignment: BFE gives `FWP_EMPTY` filters effective weight in `[0, 2^60)`. A separate, hypothetical authorized filter in the SAME sublayer/layer with `FWP_UINT64=2^60`, conditions matching the selected TCP flow, and `FWP_ACTION_PERMIT` or `FWP_ACTION_BLOCK` is necessarily evaluated before FlowBridge's auto-weighted filter. Microsoft Filter Arbitration: a matching Permit or Block stops evaluation of remaining filters in that sublayer. R99's eight exact management objects can still ALL match, while the relevant FlowBridge classifyFn is NEVER called for that flow.

PERMIT at AUTH_CONNECT is a conditional sibling-DIRECT authorization candidate; other sublayers/layers may still block. PERMIT at CONNECT_REDIRECT conditionally avoids redirect-layer callback. BLOCK gives foreign-filter denial. No real BFE conflict, callback absence, Windows behavior, network path or leak was observed. The extra filter would require BFE permissions on the owned sublayer; whether it is installable/present with actual ACLs is UNKNOWN. R99 deliberately claims management inventory only: this is a newly enumerated proof gap, not evidence that its declared output contract is false.

## Independently reproduced negative model

Run:
```sh
python3 research/wfp-ale/r102/r102_arbitration_negative.py
node research/wfp-ale/r102/r102_arbitration_independent.mjs
```
Both tests independently enumerate 48 synthetic states: family v4/v6 × AUTH/REDIRECT × competitor presence × match × PERMIT/BLOCK/CONTINUE. Shadowed by high-weight PERMIT=4, by BLOCK=4, callout reached in simplified model=40. Ordered matrix SHA-256 `764c482ff624def8de1cafde9c55a792d0d110dce9d8ff282f05cefa0f7cdb8d`; witness `v4|AUTH_CONNECT|1|1|PERMIT|SHADOWED_BY_PERMIT`. Neither test calls Windows APIs or performs driver/WFP/network operations. No native Rust Windows build occurred.

## Next decisive safe experiment / limits

Compile exact Git R99 Rust user-mode source on an already-authorized Windows x86_64 host, record SDK ABI, build, binary SHA256 and JSON. Then (separately; no filters installed) design read-only Rust BFE inventory using `FwpmTransactionBegin0(FWPM_TXN_READ_ONLY)`, `FwpmFilterCreateEnumHandle0`, `FwpmFilterEnum0`, `FWPM_FILTER0.effectiveWeight` and conservative condition overlap checks against the four exact layers/sublayer. ACL-denied or incomplete enumeration must be UNKNOWN, not no-collision. Management enumeration can never prove runtime callout execution.

Kernel-origin chain is still NO-GO: `PsSetCreateProcessNotifyRoutineEx` -> referenced process/EXE + `PsGetProcessCreateTimeQuadPart`/`PsGetProcessStartKey` -> authentic ALE CONNECT_REDIRECT v4/v6 AppId, endpoint and destination -> AUTH_CONNECT original AppId/rights -> real accepted SOCKET WFP redirect records/context -> terminal kernel CLAIM -> outbound WFP records -> trusted SSH and independent sibling DIRECT controls. IPv4/IPv6, process death/PID reuse, repeated 5-tuple, DNS/UDP/QUIC and BFE/WFP/SSH loss remain unproved. R101 overlaps R88's conditional SSH self-block: no extra native proof.

Official sources:
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-weight-assignment
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionbegin0

No changes to main/release, beta integration/windows-rust-capture-agent-20261031, PR #56, runner, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, networks, other repos, automations. No driver/callout/NDISRD/WFP filter installation/run, VNC, paid work, ProxiFyre AGPL, closed PR40, vendor binary or C++ WFP payload. Driver/VNC/SYSTEM rescue/rollback gates still REQUIRED for any later native WFP experiment.
