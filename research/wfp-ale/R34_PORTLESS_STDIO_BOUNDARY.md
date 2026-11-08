# R34 — Portless SSH stdio alternative: local substitution removed, WFP continuity unresolved

Date: 2026-11-08. Research-only branch `research/windows-wfp-ale-attribution-20261107`. Base `ff7fdd7293cba2aa38dc4055728a658b662d1312`; `main` read `5b5afc2feeda2195f302380e615ba003d4906e09`. No beta, PR #56, driver, filter, service, runner or network experiments.

## Source-pinned finding
The current experimental broker receives only a caller-specified numeric `ssh_port`, not an authenticated SSH-session capability. The actual code sends SOCKS5 method `0x00` to TCP 127.0.0.1, accepting syntactically valid replies; it does not attest the local peer process. Even a PID + creation-time + EXE snapshot would not bind a peer to the accepted TCP socket.

Source Git blobs verified via GitHub:
- `kernel-r19/broker.rs`: `825cb0a053dca0259a81fe77cdad9227c71883ae` — `claim_and_connect(&d,ssh_port)`, only WFP PING heartbeat; `broker_ready` not SSH proof.
- `kernel-r19/broker_windows.rs`: `f315d2cfab16ed7474446a9bb819980c8c737163` — CLAIM, `WSAIoctl(SET_RECORDS)` on new TCP socket, TCP connect 127.0.0.1, SOCKS relay.
- `kernel-r19/transport.rs`: `414458795896f02ac7f6c92ec5f455b9268551e4` — method [05 01 00], accepts [05 00].
All 13 pinned source anchors checked; no production Windows test.

## New topology and blocking tradeoff
OpenSSH `ssh -W host:port` forwards stdin/stdout over SSH. A trusted supervisor could create one child per flow and pass narrowly inherited anonymous pipe handles using Windows `CreatePipe`, `CreateProcessW`, `STARTUPINFOEX`, `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. This **removes the impersonable local TCP SOCKS listener from that path**, conditional on a real owned process/handle proof. It does **not** prove remote host-key authentication or that the requested SSH direct-tcpip channel opened. A local pipe, PID, process epoch or child liveness is not an authenticated channel-open event; the model includes a clearly hypothetical external remote-proof input. One child per flow carries unmeasured scaling costs.

**WFP integration NO-GO:** WFP's `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` applies to an outbound TCP socket, not to stdio anonymous pipes. The existing proxy's redirect-record handoff cannot be substituted with `ssh -W` without an independent redesign and genuine native proof. It also cannot prove that a separate OpenSSH physical socket carries these records. A ControlMaster multiplexing alternative would need its own verified local peer/channel boundary; none implemented.

## Completed offline tests
- `r34_capability_negative.py`: 12 PASS; optional exact-local-checkout pin test 1 SKIP (repo not mounted). Both families, PID/child restart, pipe-generation ABA, reused ticket/5-tuple, WFP/SSH loss, UDP/QUIC, NOAUTH and owner snapshot denial.
- `r34_independent_oracle.py`: exhaustive 18,432 combinations: 18,400 REJECT, 16 LOCAL_PEER_ONLY, **16 CONDITIONAL_RELEASE only under explicitly assumed remote-proof**. A deliberately insecure SOCKS/PID mutant has 768 false accepts. One observationally identical real/substitute SOCKS pair.
- 13/13 independent source-anchor checks against pinned GitHub blobs PASS.
- `r34_stdio_capability_model.rs` is pure Rust `#![forbid(unsafe_code)]` with 8 unit tests defined; **no Rust compile/test** (rustc/cargo unavailable). No Windows, WFP, SSH, socket, driver or CI execution.

## Trust and NO-GO
Selection: `FwpmGetAppIdFromFileName0`, `FWPM_CONDITION_ALE_APP_ID`, kernel WFP AppId + `FWPS_METADATA_FIELD_PROCESS_ID`, referenced EPROCESS + creation epoch, canonical image binding — UNPROVED.
Redirect: `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6`, `FwpsAcquireWritableLayerDataPointer0`, `FWPS_CONNECT_REQUEST0`, `FwpsRedirectHandleCreate0`, `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6` — native proof, reauthorization and issuance ABA UNPROVED.
Accept/handoff: `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT`, single-use CLAIM, `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on outbound TCP — source sequence exists; native proof UNPROVED.
WFP/SSH loss, process death/PID reuse, reused 5-tuple, sibling DIRECT, IPv4/IPv6 coverage, DNS/UDP/QUIC and fail-closed OS policy — NO-GO.
PacketBound/G2 and no-DIRECT/leak-free are NOT asserted; G1 `dd1ab3c` is not inherited.

Next permitted decisive step: compile/run pure Rust tests on exact checkout without drivers/networks, then determine whether any documented user-mode Windows API gives a per-flow cryptographic/authenticated SSH `-W` channel-open witness. If not, no end-to-end stdio GO. Separate WFP record propagation and performance cost decisions remain gated.

Primary: https://man.openbsd.org/ssh ; https://learn.microsoft.com/en-us/windows/win32/procthread/inheritance ; https://learn.microsoft.com/en-us/windows/win32/procthread/creating-processes ; https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records ; https://www.rfc-editor.org/rfc/rfc1928 .
