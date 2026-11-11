# R122 — Source compartment and physical SSH egress are different trust boundaries

2026-11-12. Research-only branch research/windows-wfp-ale-attribution-20261107. Baseline HEAD 1bc324bcca949e4587901adef454e750c334ca8a; main read-only 5b5afc2feeda2195f302380e615ba003d4906e09. Not beta, PR #56, PacketBound/G2, leak-free/no-DIRECT or historical G1.

## Material clarification of R121: two independent obligations

R121 demonstrated that R19 does not transmit the original Windows source COMPARTMENT_ID through the numeric SSH direct-tcpip destination. R122 adds an orthogonal missing proof: the physical broker SSH TCP socket has a **separate unobserved Windows routing/compartment decision**.

Unchanged R19 broker_windows.rs creates socket(2,1,6), applies SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on that new socket, then connects to an IPv4 SSH server. No per-original-flow compartment identifier is an explicit input to that socket/connect path. The OS-selected physical path is UNKNOWN; do not claim a particular real compartment or route, and do not assume socket route equality from source-code projection. Unchanged trusted-ssh-r37/src/lib.rs independently opens channel_open_direct_tcpip(original_IP,original_port,"127.0.0.1",0), with no authenticated remote namespace mapping. Thus adding a hypothetical compartment field to an SSH label would not itself prove physical SSH egress routing; fixing physical egress selection would not establish equivalent remote destination semantics.

Crucially, Microsoft's official SetCurrentThreadCompartmentId documentation now states **"Reserved for future use. Do not use this function."** This API is NOT a supported quick fix. GetDefaultCompartmentId describes a host default; IP_UNICAST_IF and IPV6_UNICAST_IF specify outbound interface choices, not a kernel-origin process identity/flow certificate.

Pinned exact Git blobs (all unchanged):
- kernel-r19/broker_windows.rs: 16ec8853d322b40f0e00e14d49ae3410741b9395
- kernel-r19/trusted-ssh-r37/src/lib.rs: c6d8c8746fac45073c11557de893164e49d830eb
- kernel-r19/kernel/src/redirect.rs: 9a07e026134d46ef646d39862bd982cc48bbc5f6
- kernel-r19/kernel/src/handoff.rs: e1d17217db50362ba9c4efc83af820b6beb094cf

## Independently executed offline negative controls

- r122_dual_namespace_negative.py — Python 3, 5/5 PASS.
- r122_dual_namespace_independent.mjs — Node 22, 96/96 ordered states match Python SHA-256 d341981650f01b2f6a81ba9c3152fd8175acdb5aa0da160a16121ea979de0bad.
- Dimensions: v4/v6 target, two ports, three synthetic source compartments, two synthetic PID creation epochs, SSH up/down, TCP/UDP. 24 source-level healthy TCP candidates; a hypothetical compartment==7 local guard leaves eight. 48 cross-compartment pairs share the same explicit local/remote projection, including 24 same-epoch pairs.
- The unobserved broker routing context is always labeled UNKNOWN; these tests do NOT claim that Windows chose the same route for two connections, that a real WFP classify happened, or that any packet leaked. This is a source-contract counterexample, not OS measurement.
- The two exact test file bytes were Git-blob-hashed before publication; cross-language oracle is independently implemented rather than imported.

## Exact trust and decision boundary

Origin: FwpmGetAppIdFromFileName0 + original/current FWPM_CONDITION_ALE_APP_ID; FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6, metadata PID and transport endpoint, referenced process creation EPROCESS/PsGetProcessCreateTimeQuadPart/start key/canonical EXE, original destination and COMPARTMENT_ID from the same classify, process death/PID reuse. Redirect: FwpsQueryConnectionRedirectState0 and FWPS_CONNECT_REQUEST0 with writable-layer apply. Socket handoff: accepted SOCKET WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT), terminal one-use CLAIM. Outbound: WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS) before connecting to a trusted SSH server. Independent AUTH_CONNECT v4/v6 enforcement and reauthorization, sibling DIRECT, reused 5-tuple, v4/v6, DNS/UDP/QUIC, WFP/BFE/SSH loss all remain NO-GO. 5-tuple, ETW and late PID correlation never prove kernel origin.

Next permitted decisive experiment: exact R115–R118 Windows x64 native user-mode read-only BFE/ABI/JSON validation and Rust model build, preserving SHA, exit codes and unmodified receipts. Any physical same-flow compartment/SSH/classify or egress proof requires separate driver/signing/VNC/SYSTEM rescue/rollback gates. No driver, callout, filter or live network experiment authorized here.

Official docs reviewed 2026-11-12:
- https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setcurrentthreadcompartmentid
- https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getdefaultcompartmentid
- https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_connect_redirect_v4_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_connect_redirect_v6_

No changes to main/release, integration/windows-rust-capture-agent-20261031, PR #56, runners, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, networks, other repositories, paid operations or automations/controller. No ProxiFyre AGPL, closed PR40, vendor binaries or C++ WFP payload. Research ref mutation only exact expected SHA, force=false; on conflict STOP.
