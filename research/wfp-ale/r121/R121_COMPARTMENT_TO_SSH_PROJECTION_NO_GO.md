# R121 — Network compartment lost in R19 SSH destination projection (source-level NO-GO)

2026-11-12. Only research/windows-wfp-ale-attribution-20261107. Parent research HEAD f51a6c6be5a0778bcf992eaf7b3129eb50db105a; read-only main 5b5afc2feeda2195f302380e615ba003d4906e09. Independent architecture R&D, not beta, PR #56, PacketBound/G2, no-DIRECT or G1 acceptance.

## Material, source-verified gap

Microsoft exposes FWPS_FIELD_ALE_CONNECT_REDIRECT_V4/V6_COMPARTMENT_ID and FWPS_FIELD_ALE_AUTH_CONNECT_V4/V6_COMPARTMENT_ID beginning with Windows 10 1703. These identify the network-interface compartment, not a process-ownership certificate. Two connections can share a remote address and port but have distinct local network compartment identities.

Exact unchanged R19 source blobs:
- kernel-r19/kernel/src/redirect.rs: 9a07e026134d46ef646d39862bd982cc48bbc5f6. destination() extracts family, port, IP; classify() never reads COMPARTMENT_ID, and rejects nonzero IPv6 scope.
- kernel-r19/kernel/src/handoff.rs: e1d17217db50362ba9c4efc83af820b6beb094cf. Destination and 128-byte Context omit compartment, while retaining owner PID, epoch, start key, endpoint generation and ticket data for LOCAL checks.
- kernel-r19/broker_windows.rs: 16ec8853d322b40f0e00e14d49ae3410741b9395. Converts Destination to IpAddr and port for the remote SSH relay.
- kernel-r19/trusted-ssh-r37/src/lib.rs: c6d8c8746fac45073c11557de893164e49d830eb. Calls channel_open_direct_tcpip(destination.to_string(), destination_port, "127.0.0.1", 0) with no originating Windows compartment qualifier.

Therefore a Windows IPv4 or IPv6 flow in compartment X and one in Y can have distinct kernel network contexts but the same SSH direct-tcpip target. The REMOTE SSH server routes inside its own routing environment. The retained local ticket/endpoint/epoch do not restore a compartment ID that was not transmitted as a remote-routing selector. This is an information-projection limitation, NOT proof of wrong delivery, kernel interception, ACL bypass or packet leak. Some deployments may intentionally map all selected addresses into one remote SSH namespace: that is a policy choice requiring explicit acceptance, not transparent Windows routing equivalence.

## Executed clean-room negative controls

- r121_compartment_negative.py: Python 3.13, 5/5 unit tests PASS.
- r121_compartment_independent.mjs: independent Node 22 algorithm, matches 512/512 ordered rows and SHA-256 179cc8c5cad7e4882a73e1a290c11b8099f819f33d7eabe5a1730938f94eaddf.
- Finite dimensions: two IPv4 and two IPv6 valid unicast addresses, two ports, four compartment IDs, same numeric PID with two epochs, two endpoint/ticket labels, TCP/UDP, SSH health up/down. 128 *synthetic* TCP+healthy SSH projection candidates; an explicit hypothetical compartment==7 guard leaves 32, rejecting 96. There are 768 cross-compartment pairs with the same remote selector, including 192 with same epoch and endpoint label. These counts are model combinatorics, not observed traffic.
- r121_compartment_guard.rs: dependency-free Rust user-mode model, #![forbid(unsafe_code)], four authored tests; NOT compiled or executed (rustc unavailable). No sockets, drivers, callouts, WFP/BFE queries or network.
- All 3 source blobs were created from exact locally executed or authored files and their Git blob SHA-1 compared byte-for-byte before tree creation.

## Trust boundary / decision

Selected file identity: FwpmGetAppIdFromFileName0 + original/current FWPM_CONDITION_ALE_APP_ID. Native causal origin: FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6 with valid metadata PID, referenced EPROCESS, creation epoch/start key/canonical EXE, endpoint and original destination; include per-layer COMPARTMENT_ID in the exact same classify for a documented scope contract. Redirect state: FwpsQueryConnectionRedirectState0, FWPS_CONNECT_REQUEST0, owned context. Accepted socket: WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/_CONTEXT), one-use claim. Outbound socket: WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS) before connect and authenticated SSH. Independent FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6, reauthorization and ACL/arbitration checks; reject sibling DIRECT, DNS/UDP/QUIC and WFP/BFE/SSH-loss scenarios without proof. No user-mode 5-tuple, AppId basename or retrospective PID join is kernel-origin evidence.

Narrow offline design option: explicitly restrict the selected R&D policy to a separately established compartment and fail-closed/UNKNOWN other compartments, OR define a genuinely authenticated remote namespace mapping. Neither option proves runtime WFP behavior or systemic no-DIRECT. IPv6 scope/link-local is already excluded by source; do not claim physical bypass. PID death/reuse, repeated 5-tuple, foreign proxy, actual WFP records, leak-free and PacketBound/G2 all remain NO-GO.

Next decisive permitted experiment: compile exact Rust user-mode test offline on trusted Windows x64 and cross-check these 512 cases; separately read-only inspect compartment observability without installing drivers/filters or conducting traffic tests. Actual causal classify/redirect/remote namespace and physical egress needs separately authorized driver/signing/VNC/SYSTEM rescue/rollback gates. NOT authorized here.

Microsoft primary docs (checked 2026-11-12):
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_connect_redirect_v4_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_connect_redirect_v6_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v6_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection

Forbidden and untouched: main/release, integration/windows-rust-capture-agent-20261031, PR #56, other repos, driver/filter/callout/NDISRD, runner, services, VNC, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, network/system state, automations/controller, paid operations. No ProxiFyre AGPL, closed PR40, vendor binary or C++ WFP payload. Git ref mutation only expected SHA, force=false.
