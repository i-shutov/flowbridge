# R221 — AUTH receipt is not final WFP arbitration

Date: 2026-11-22. Scope: ONLY i-shutov/flowbridge research/windows-wfp-ale-attribution-20261107. Parent research HEAD cf58f3fafe61093dedc40f0840327f832465f781; read-only main 5b5afc2feeda2195f302380e615ba003d4906e09. Not beta, PR #56, physical kernel proof, PacketBound/G2, historical G1, no-DIRECT or leak-free.

## Source-level composition (narrow, substantive counterexample)

R19 kernel/src/redirect.rs (Git blob a093f049d162987981a957aac90db1014bc6ff09): auth_classify calls auth_check, which calls route.book.attest before the callback writes FWP_ACTION_PERMIT and clears FWPS_RIGHT_ACTION_WRITE. R19 handoff.rs (blob e1d17217db50362ba9c4efc83af820b6beb094cf): Book::attest sets auth_seen=true; Book::take requires auth_seen and an exact one-use context but receives no final WFP arbitration result or actual accepted SOCKET. R19 lib.rs (blob 53f5ce6faa0f9f591974287f38ea890cafeb0dd2) forwards DeviceIoControl(CLAIM) with IoGetRequestorProcess(irp). Broker_windows.rs (blob 329ef14b63e70226bfad7372b0014559213abd04) has a public raw Device::command, but the ordinary typed Received path obtains the context from SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT on the actual accepted socket before CLAIM.

Microsoft's WFP Filter Arbitration documentation explicitly states that sublayers are evaluated and the final action is decided after arbitration, including possible veto of a hard PERMIT. It also warns that a hard permit at one layer need not permit traffic at another layer.

Thus a source-level AUTH callback can have set auth_seen even in a hypothetical world where another WFP filter subsequently blocks the connection. These worlds are indistinguishable to Book::take IF THE SAME VALID CONTEXT BYTES ARE PRESENTED. An AUTH candidate or kernel raw CLAIM is therefore not a certificate of final WFP permission or physical egress.

This is not evidence that an unmodified broker can obtain a valid context from a flow that WFP ultimately blocks. In that case there is no proven accepted socket and the typed broker's WSAIoctl path cannot naturally obtain the record. The model's context-known variable is explicitly counterfactual, not an exploit, packet leak, permission bypass or assertion that a particular veto ordering occurs at runtime. R73's raw-CLAIM/socket-handle separation and R85/R86's action-rights uncertainties are prerequisites, not overturned. An unsuccessful malformed CLAIM is not modelled because R19 can consume a matching sequence even with other context bytes wrong.

## Deterministic independent negative experiment

- r221_arbitration_claim_model.rs: std-only pure Rust, forbid(unsafe_code), 8 unit tests authored, NOT compiled or run (rustc/cargo unavailable); no Win32/kernel/driver/network/FWP calls.
- r221_independent.py: Python 3.13 stdlib, 6/6 unittest PASS, and exhaustive 256-world matrix run.
- r221_independent.mjs: Node v22.16.0, node --check PASS and 256-world oracle PASS, independent bitwise implementation and veto-mutation sensitivity.
- Both executed oracles agree: AUTH candidates 32; model final permits 16; hypothetical raw-CLAIM candidates 8; typed-broker candidates 2; raw candidates with final block 4. Ordered CSV SHA-256 018c4c378bcef3865a8e9f7cb0a20eada304dc7d4504cd839a4dbfd4625502c1. These are enumerated SYNTHETIC states, not network counts or observed WFP outcomes.

Run in a full checkout:

    python3 research/wfp-ale/r221/r221_independent.py
    python3 research/wfp-ale/r221/r221_independent.py --summary
    node --check research/wfp-ale/r221/r221_independent.mjs
    node research/wfp-ale/r221/r221_independent.mjs
    rustc --edition=2021 --test research/wfp-ale/r221/r221_arbitration_claim_model.rs -o /tmp/r221 && /tmp/r221

## Official trust boundary and deciding evidence

PsSetCreateProcessNotifyRoutineEx with referenced EPROCESS/FileObject -> PID + creation epoch (PsGetProcessCreateTimeQuadPart) + start key (PsGetProcessStartKey) + WFP opaque exact AppId (FwpmGetAppIdFromFileName0) -> genuine ALE_CONNECT_REDIRECT_V4/V6 via FwpsQueryConnectionRedirectState0, FwpsAcquireWritableLayerDataPointer0, FwpsApplyModifiedLayerData0 and FWPS_CONNECT_REQUEST0 -> ALE_AUTH_CONNECT_V4/V6 current/original AppId, flags, endpoint, original destination and valid rights -> FINAL WFP sublayer/layer arbitration (NOT in R19 ticket) -> accepted Winsock socket SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT -> one-use DeviceIoControl(CLAIM) -> new physical TCP socket SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS -> authenticated SSH peer and terminal relay.

Exact native chronology of third-party veto, final connection acceptance and received-socket WFP record must be proven in a future separately admitted driver/filter classify experiment. Not authorized now. A passive FwpmEngineOpen0/FwpmFilterGetByKey0 readback can show BFE policy, not final per-flow arbitration. Pure Rust compilation is the next permitted action; then authorized read-only R199 if individually admitted. Without physical evidence status remains NO-GO for owner/epoch provenance, v4/v6, process death/PID reuse, reused endpoint/5-tuple, sibling DIRECT, TCP-only DNS/UDP/QUIC, WFP/BFE/SSH loss.

Official Microsoft sources:
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
- https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_classify_out0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records

No edits to main/release/beta/PR #56, runner, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, network, other repositories or automation state. No kernel driver/callout installation or execution, WFP filter mutation, NDISRD, VNC, signing, vendor binary, ProxiFyre AGPL, closed PR40, C++ WFP payload or paid operation.
