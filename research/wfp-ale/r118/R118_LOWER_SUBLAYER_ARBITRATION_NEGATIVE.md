# R118: lower-weight WFP sublayer is not arbitration-irrelevant (NO-GO)

2026-11-11 | ONLY research/windows-wfp-ale-attribution-20261107.
Expected parent dd3f410221081ec2efee68491c049176cfd60bdc;
read-only main 5b5afc2feeda2195f302380e615ba003d4906e09.
Independent architecture R&D; NOT beta, PR #56, PacketBound/G2 or release.

## Material counterexample and fix

R117 recorded foreign LOWER-weight sublayers, but classified a lower-only
snapshot as exit 4 UNKNOWN_NO_VISIBLE_WEIGHT_PEER, while reporting candidate
exit 3 only for higher/equal weights. This obscured a documented possible
arbitration path. Microsoft's Filter Arbitration specifies evaluation of
all sublayers within a WFP layer: a lower-weight matching BLOCK can override
a higher-weight SOFT PERMIT; a callout VETO can override even HARD PERMIT.
A normal lower BLOCK cannot override a HARD PERMIT without such veto.

Therefore the inspector now classifies ANY visible foreign sublayer (higher,
equal OR lower) as an unqualified candidate, exit 3
VISIBLE_SUBLAYER_ARBITRATION_PEER_UNQUALIFIED. Exit 4
UNKNOWN_NO_VISIBLE_FOREIGN_SUBLAYER requires zero visible foreign sublayers.
Exit 2 still means unavailable/malformed/owner drift. ALL outputs remain
diagnostics, never GO. The inspector does NOT prove any actual filter overlap,
matching condition, action rights, veto, flow, callout execution or leak.
Do not compare FWPM_SUBLAYER0 UINT16 weight with filter effectiveWeight UINT64.

## Independent negative verification

- Python and independent Node synthetic peer models: 2880/2880 exact matches.
  exit2=2868, exit3=11, exit4=1. Ordered matrix SHA-256:
  8a04faa95ba07609a5e79e58e970f74e4cb3c7a84e111dbf7e0f994446de4793
- Python rule evaluator and independent Node table model: 16/16 combinations
  of high-sub-layer soft/hard permit/block and lower action.
  SHA-256: f14ae8871ffd5cf6b08559512113a4f0240ad92816d0a78ccc41e8bfee55a324.
- Explicit witnesses: soft PERMIT + lower BLOCK -> BLOCK;
  hard PERMIT + lower VETO -> BLOCK;
  hard PERMIT + ordinary lower BLOCK -> PERMIT (absent veto).
- Rust adds synthetic lower-only case, but native Rust/Windows NOT EXECUTED.
  No WFP calls, traffic, BFE modifications, driver or filter creation in tests.

Commands:
  python3 research/wfp-ale/r117/r117_sublayer_negative.py
  node research/wfp-ale/r117/r117_sublayer_independent.mjs
  python3 research/wfp-ale/r118/r118_lower_priority_veto_negative.py
  node research/wfp-ale/r118/r118_lower_priority_veto_independent.mjs

## Trust boundary, not an interception certificate

WFP policy uses FwpmGetAppIdFromFileName0, FWPM_CONDITION_ALE_APP_ID /
ALE_ORIGINAL_APP_ID; this is NOT a kernel-origin process/image-section proof.
That requires a causally bound referenced EPROCESS, PID, process creation epoch
(PsLookupProcessByProcessId and PsGetProcessCreateTimeQuadPart with IRQL/lifetime
proof), canonical executable, original destination, connection and classifier
at FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6 and ALE_AUTH_CONNECT_V4/V6.
Redirect-state/flow lifetimes use FwpsQueryConnectionRedirectState0,
FWPS_CONNECT_REQUEST0, FwpsAcquireWritableLayerDataPointer0,
FwpsApplyModifiedLayerData0. A real socket handoff requires WSAIoctl
SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT on the accepted socket
and SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on outbound sockets; tuples,
timestamps and later OpenProcess results cannot replace it.
IPv4/v6, process death/PID reuse, reused 5-tuples, reauthorization,
sibling DIRECT, DNS/UDP/QUIC, and WFP/BFE/SSH loss remain NO-GO.

Next decisive authorized-only check: pinned Windows x64 source Git blobs,
native Rust metadata compilation/ABI/tests, separately opt-in READ-ONLY BFE
snapshot with raw JSON, SHA-256 and exit codes; those snapshots still cannot
certify runtime classify or no-DIRECT. No kernel/driver/VNC/SYSTEM/rollback
authorization for physical interception experiments. No changes to main,
release, beta, PR #56, runner, security/network settings, automation or
other repositories.

Primary Microsoft documentation reviewed 2026-11-11:
https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsublayerenum0
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
