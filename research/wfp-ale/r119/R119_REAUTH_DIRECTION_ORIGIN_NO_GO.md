# R119: ALE reauthorization follows ORIGINAL flow direction, not current packet direction

2026-11-11. ONLY research/windows-wfp-ale-attribution-20261107. Parent research HEAD 7b057c7b4336e524ae2021081c89eab3868bd6bd; read-only main 5b5afc2feeda2195f302380e615ba003d4906e09. Independent architecture R&D; NOT beta, PR #56, PacketBound/G2 or release.

## Material, Microsoft-documented negative witness

Microsoft's ALE Reauthorization documents: the direction of an ALE flow is assigned by the first packet which CREATED/AUTHORIZED the flow; an ALE flow contains packets in BOTH directions; reauthorization returns to the ORIGINAL ALE authorization layer even if the triggering packet travels in the reverse direction. Triggers include policy change, interface change and pending connection. Observe FWP_CONDITION_FLAG_IS_REAUTHORIZE and the real classify layer instead of reconstructing a layer from the current packet direction.

Two counterexamples tested:
- Outbound IPv4 flow first authorized at FWPS_LAYER_ALE_AUTH_CONNECT_V4; policy change, then inbound packet triggers reauthorization. The true layer remains AUTH_CONNECT_V4; direction-only reconstruction chooses AUTH_RECV_ACCEPT_V4 incorrectly.
- Inbound IPv6 flow first authorized at FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6; interface change, then outbound packet triggers reauthorization. The true layer remains AUTH_RECV_ACCEPT_V6; direction-only reconstruction chooses AUTH_CONNECT_V6 incorrectly.

This is a negative test of a tempting USER-MODE SHORTCUT, not a confirmed bug in existing FlowBridge runtime, or evidence that Windows misrouted a flow. A real WFP classify callback knows its actual layer; absence of an authenticated event at the original flow boundary cannot be repaired by looking up PID, tuple or packet direction later.

## Independent executable test evidence

r119_reauth_direction_negative.py (Python) and r119_reauth_direction_independent.mjs (Node.js) independently enumerate original flow direction, triggering packet direction, three reauthorization reasons, IPv4/IPv6, PID epoch reuse, reused five-tuple/ticket, WFP health, SSH health and TCP/UDP.

Each oracle: 768 cases, 384 wrong guesses when assuming packet direction determines authorization layer, 384 indistinguishable pairs of original flow layers under the represented user-mode observables. Ordered scenario matrix SHA-256: 654114b13fd98f09a045834753dee2ffffee6eba683c732c68453a85a0924f84. Both independently produced identical JSON, both passed offline. The small CORROBORATION_NOT_PROOF category never asserts an authentic kernel event.

Run from repository root:
  python3 research/wfp-ale/r119/r119_reauth_direction_negative.py
  node research/wfp-ale/r119/r119_reauth_direction_independent.mjs

No Rust compiler was used; these are deterministic negative tests, NOT a Windows native test. No WFP, socket, driver, callout, filter, remote host or system/security/network state touched.

## Trust boundary and API-level acceptance

Selection: FwpmGetAppIdFromFileName0, FWPM_CONDITION_ALE_APP_ID and the FWPS_FIELD_ALE_AUTH_CONNECT_*_ALE_ORIGINAL_APP_ID describe WFP file-derived AppId, not a referenced process/image-section identity. PID+process creation epoch requires causally bound kernel evidence: PsLookupProcessByProcessId -> referenced EPROCESS -> PsGetProcessCreateTimeQuadPart, subject to IRQL and lifetime gates; no such proof obtained.

Initial flow and reauthorization: FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6, FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6, FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6, FWPS_METADATA_FIELD_PROCESS_ID only when flagged valid, FWP_CONDITION_FLAG_IS_REAUTHORIZE, FWPS_FIELD_ALE_AUTH_CONNECT_*_REAUTHORIZE_REASON. Must bind initial layer, owner, process epoch, full AppId, original destination, family, flow identity, process death, PID reuse and re-used five-tuple before inferring any authorization transition.

Redirect: FwpsQueryConnectionRedirectState0, FwpsAcquireWritableLayerDataPointer0, FWPS_CONNECT_REQUEST0, FwpsApplyModifiedLayerData0. WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT) on actual accepted socket, WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS) on outbound socket BEFORE connect. Neither opaque records nor a synthetic ticket are signed ownership evidence.

Protection: independently prove selected-app sibling DIRECT denial, DNS/UDP/QUIC, both IP families, IPv6 scope/compartments, service crash, WFP/BFE/SSH loss and already established ALE flows; read-only FwpmFilterEnum0 or FwpmSubLayerEnum0 snapshots cannot prove callout execution, complete visibility or system no-DIRECT. All are NO-GO.

Next decisive authorized experiment: pinned Windows 10 x64 compile/ABI/negative tests of R115–R119 and separately opt-in READ-ONLY BFE inspection with exact source Git blob, Windows build, SDK, rustc, binary SHA, JSON and exit code. Real classify/redirect/kernel-flow proof requires owner-approved driver, VNC/SYSTEM rescue and rollback gates; NOT granted here.

Never modify main/release, beta integration/windows-rust-capture-agent-20261031, PR #56, runner, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, network, other repos, automation schedule/state or controller. Never use ProxiFyre AGPL, closed PR40, vendor binaries or C++ WFP payload. No paid operations.

Primary Microsoft sources (verified 2026-11-11):
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
