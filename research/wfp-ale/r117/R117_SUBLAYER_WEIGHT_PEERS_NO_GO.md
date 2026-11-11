# R117 — ACL-limited competing sublayer weight inventory (NO-GO)

2026-11-11. Repository i-shutov/flowbridge, ONLY branch research/windows-wfp-ale-attribution-20261107. Research parent: 2d73539dd1deaaec813594ec815aaf3db5a45bf7. Read-only main: 5b5afc2feeda2195f302380e615ba003d4906e09.

## Material diagnostic gap

R103 examines foreign filter effectiveWeight only inside the owned sublayer. R116 verifies only the owned sublayer (GUID 1649f024-25b3-4e01-9ca1-5ca803010019, UINT16 weight 0x7000). Neither inventories OTHER visible sublayers. R103 and R116 could both yield exit 4 UNKNOWN while a foreign sublayer has equal or higher priority. This does NOT establish a competing matching filter, the final arbitration result, a leak, or kernel-origin proof.

Microsoft documents both inter-sublayer and intra-sublayer arbitration with action-rights/veto semantics. A sublayer's UINT16 weight must never be compared with an individual filter's UINT64 effectiveWeight. Sublayer enumeration is ACL-filtered, and separate R103/R116 snapshots cannot be atomically joined with this one.

## New clean-room read-only Rust PoC

r117_readonly_sublayer_peers.rs calls only FwpmEngineOpen0, FwpmSubLayerCreateEnumHandle0(NULL template), FwpmSubLayerEnum0, FwpmSubLayerDestroyEnumHandle0, FwpmFreeMemory0, FwpmEngineClose0.

It requires the R19 owned descriptor to be visible exactly once and match GUID, weight, flags=0, providerKey=NULL, providerData empty. From that same enumerator it counts visible foreign sublayers of higher, equal and lower weight. Enumeration cap is 16384 with page size 64; malformed pages, API/ACL error, changed/missing/duplicate owned descriptor or budget exhaustion => exit 2 UNKNOWN.

A visible higher/equal peer => exit 3 VISIBLE_SUBLAYER_WEIGHT_PEER_UNQUALIFIED (unverified layer/filter/condition overlap). No visible peers => exit 4 UNKNOWN_NO_VISIBLE_WEIGHT_PEER (ACL hidden objects possible). All exits are NON-GO; nothing reports PASS. A missing R19 dynamic sublayer on an unarmed host is expected UNKNOWN and does not call for installation.

No driver, callout, WFP filter, transaction, system changes, sockets, remote hosts, or process spawning. No actual native Windows/Rust execution in this cycle.

## Independent deterministic tests

python3 research/wfp-ale/r117/r117_sublayer_negative.py
node research/wfp-ale/r117/r117_sublayer_independent.mjs

Both independently enumerate 2880 cases (API availability, owned count/descriptor, higher/equal/lower peers and total cardinality): exit2=2868, exit3=10, exit4=2. Ordered matrix SHA256 4c2174a1655c35d98b9ab91e957e597be0e73d9df5c2a4b26e1ddfea5e787c53. Python guards prohibit APIs that modify BFE. Independent ctypes x64 ABI: FWPM_SUBLAYER0 sizeof 72; flags offset 32; providerKey 40; providerData 48; weight 64. Rust synthetic and Windows ABI tests included but not executed; rustc absent on the local research host. This is a purely synthetic model proof, not WFP evidence.

## Kernel-origin chain of trust remains unproved

1. FWPM_CONDITION_ALE_APP_ID / ALE_ORIGINAL_APP_ID and FwpmGetAppIdFromFileName0: path-based policy selection only, not process/image-section identity. Must bind referenced EPROCESS, PID, PsGetProcessCreateTimeQuadPart, canonical EXE, lifetime, and kernel endpoint.
2. FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6 plus FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6: real classify and independent sibling DIRECT denial, including reauthorization, process death/PID reuse, reused 5-tuples, both IP families.
3. FwpsQueryConnectionRedirectState0, FwpsAcquireWritableLayerDataPointer0, FWPS_CONNECT_REQUEST0, FwpsApplyModifiedLayerData0: kernel redirect state and original destination. WSAIoctl SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT on actual accepted socket and SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on outgoing socket; timestamps/5-tuples cannot authenticate that handoff.
4. DNS/UDP/QUIC, WFP/BFE/SSH losses and life-cycle transitions remain outside the TCP-only R19 policy and must have independent fail-closed enforcement. No kernel classify or physical failure proof has been collected.

Next decisive ALLOWED experiment: pinned read-only/native x64 Rust compilation and tests of R115/R116/R117 on authorized Windows host, retaining Windows build, rustc version, source Git blobs, binary SHA256, JSON and exit codes; do not conflate separate BFE snapshots. Driver/VNC/SYSTEM rescue/rollback gates are absent and no driver/packet trial is authorized. PacketBound/G2, no-DIRECT, leak-free and historical G1 dd1ab3c remain NO-GO.

Never touch main/release, integration/windows-rust-capture-agent-20261031, PR #56, other repos, CI/runners, firewall, services, security settings, network or automation state. Never use ProxiFyre AGPL, PR40, vendor binaries or C++ WFP payload.

Primary Microsoft sources:
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsublayercreateenumhandle0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsublayerenum0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsublayerdestroyenumhandle0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
