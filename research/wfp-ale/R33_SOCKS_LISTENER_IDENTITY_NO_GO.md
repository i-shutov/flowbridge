# R33 — authenticated SSH upstream is not established by loopback SOCKS success

Date: 2026-11-08. Independent **read-only, no-network** research. Only `research/windows-wfp-ale-attribution-20261107`; not beta or PR #56. Source baseline `e2996181980e7a1e2921135e5fb8f220ee74457a`; `main` baseline `5b5afc2feeda2195f302380e615ba003d4906e09`.

## New conditional peer-substitution counterexample

R32 established that WFP redirect records on a *local* broker-to-SOCKS TCP socket do not prove provenance of the physical SSH socket. R33 identifies a separate, actionable **local listener identity** problem: the actual research broker does not authenticate the SOCKS server's process/instance. Its only upstream selector is a loopback IPv4 address and externally supplied `ssh_port`. Its SOCKS handshake selects method 0x00 (NO AUTHENTICATION REQUIRED), accepts server reply `[05, 00]`, and accepts a syntactically successful CONNECT response before forwarding the accepted application's payload.

If the real OpenSSH `-D` listener is absent/replaced while the broker's other gates remain alive, a different local listener that can bind the configured `127.0.0.1:port` and return valid SOCKS bytes is indistinguishable *at this broker protocol boundary*. The broker could relay application bytes to that listener. This is **conditional** on listener control, a still-admitted WFP ticket, and broker lifetime; no such race, Windows socket takeover, impersonation or data transfer was performed or observed. If no listener exists, `connect` fails; if the fake returns invalid SOCKS bytes, the broker rejects. The finding is therefore NOT a demonstrated Windows vulnerability or DIRECT leak.

This cannot be repaired by stronger `PID + creation epoch + canonical EXE` proof for the *incoming application*, WFP `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on the outbound socket, the private redirect ticket, or local IP/port alone: none authenticates the opposite process accepting the SOCKS socket or proves an SSH channel exists. WFP redirect records are connection-tracking data, **not** a listener/SSH server credential. `SO_EXCLUSIVEADDRUSE` can constrain competing binds while an owned listener exists; it is not an SSH peer-authentication or crash/rebind guarantee. Re-querying a listener PID using `GetExtendedTcpTable`/`QueryFullProcessImageNameW` would be a retrospective snapshot, not a connection-bound credential.

## Source-pinned causal path and independent check

At source HEAD above, GitHub `fetch_file` returned these exact blobs:

| File | Git blob SHA | Relevant code |
| --- | --- | --- |
| `research/wfp-ale/kernel-r19/broker.rs` | `825cb0a053dca0259a81fe77cdad9227c71883ae` | `ssh_port:u16`; passes it into `claim_and_connect` after `receive`; heartbeat only invokes kernel `PING`, not an SSH-identity attestation |
| `research/wfp-ale/kernel-r19/broker_windows.rs` | `f315d2cfab16ed7474446a9bb819980c8c737163` | kernel `CLAIM`; socket `AF_INET`; `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`; `connect(127.0.0.1:port)`; then `socks_connect` and `relay` |
| `research/wfp-ale/kernel-r19/transport.rs` | `414458795896f02ac7f6c92ec5f455b9268551e4` | sends `05 01 00`; accepts `05 00`; validates SOCKS CONNECT reply then pumps data |

`r33_loopback_peer_identity_negative.py`: **8/8** offline Python 3.13 tests PASS (both destination address families; valid substituted listener versus honest listener; missing listener; invalid response; absence of kernel CLAIM; exact peer-identity counterexample). `r33_independent_peer_oracle.py` independently checks **16/16** observation-equivalent pairs, including **2** model-admitted alternatives. It imports no primary model. No sockets, SSH processes, WFP, services, networks, CI/runner, driver or filter calls were made. A `check_optional_exact_checkout` helper checks raw Git blob IDs and precise code anchors if given a full exact checkout; it was **NOT executed** in the local container because the GitHub repository is not mounted. Live source blobs were independently fetched and checked through the GitHub connector. No native Rust or Windows execution occurred; rustc not installed in local executor.

## Architectural consequences and exact APIs

Trust edges requiring distinct evidence:

1. **Selected original process:** `FwpmGetAppIdFromFileName0`, actual `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6` kernel classifying AppId / `FWPS_METADATA_FIELD_PROCESS_ID`, process-creation `EPROCESS` reference and `PsGetProcessCreateTimeQuadPart` or `PsGetProcessStartKey`. AppId/PID/epoch and executable file identity must refer to the same classified instance (not user-mode retro-join).
2. **Individual redirected flow:** `FWPS_CONNECT_REQUEST0` / `FwpsRedirectHandleCreate0`; AUTH witness at `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6`; `ALE_ORIGINAL_APP_ID`, original destination, endpoint handle, redirect target PID, and issuance lifetime. Reauthorize/PID reuse/reused 5-tuple/endpoint ABA not proved.
3. **Accepted socket / outbound handoff:** `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)` from the actual accepted socket, one-use `CLAIM`, `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on a separate outbound TCP socket. Source implements this sequence but does not establish native proof.
4. **Local SOCKS peer identity (NEW GAP):** `connect(127.0.0.1:ssh_port)` and RFC1928 NO AUTH are *not* authenticated SSH process/session/channel identity. Requires its own connection-bound authentication or an OS-enforced exclusive/trusted transport with documented lifetime semantics. A `GetExtendedTcpTable` owner snapshot is not enough. No documented Windows API in the present code supplies this peer-identity witness.
5. **Actual physical SSH egress:** must separately prove local accepted SOCKS request belongs to an authenticated SSH channel and enforce OS-level no-DIRECT; the WFP records do not cross SSH as a kernel credential.

IPv4/IPv6 destinations are encoded as SOCKS ATYP=1/4, but both currently traverse **the same IPv4 loopback upstream peer**. Sibling DIRECT, DNS/UDP/QUIC and fail-closed after WFP/BFE/SSH loss remain unproved. A malicious listener can also relay directly, but R33 did not demonstrate such egress. PacketBound/G2, native redirect acceptance and leak-free remain **NO-GO**; G1 `dd1ab3c` does not carry over.

## Next decisive permissible experiment

Implement a **pure Rust user-mode/no-network** broker-upstream state machine that refuses payload release until an authenticated, session-bound upstream witness is established. Define where that witness comes from; reject a naive PID snapshot, port-owner lookup, SOCKS method 0x00 reply or refreshed liveness polling as substitutes. Cross-check against an independent oracle with (a) honest listener, (b) same-port substitute, (c) SSH death/restart and (d) IPv4/v6 destinations. The integration of any real SSH process/listener must first provide a verifiable lifecycle/connection binding. This test does not need and must not install or run any kernel driver, filters or networks. Production/admission proofs remain separately gated.

## Primary documentation

- IETF RFC1928, SOCKS5 METHOD 0x00: https://www.rfc-editor.org/rfc/rfc1928
- Microsoft, WFP redirect records: https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
- Microsoft, original app tracking: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- Microsoft, Windows port collision and exclusive address use: https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
- OpenSSH ssh(1) `-D`: https://manpages.debian.org/trixie/openssh-client/ssh.1.en.html
