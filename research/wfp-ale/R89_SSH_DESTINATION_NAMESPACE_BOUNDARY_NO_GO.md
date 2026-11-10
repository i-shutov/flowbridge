# R89 — SSH destination namespace substitution: source-level architectural NO-GO

Date: 2026-11-10. Only the independent research branch; no beta, PR #56, PacketBound/G2, no-DIRECT, leak-free, or historical G1 claims.

## Exact baseline / blobs
- Research parent HEAD: `491deedfbb832892cdbbf97cc53076ec924b8ab1` (tree `1b861b1031dfc108141bd0f2ca22013edcc02fe3`); read-only main `5b5afc2feeda2195f302380e615ba003d4906e09`.
- `kernel-r19/kernel/src/handoff.rs` blob `e1d17217db50362ba9c4efc83af820b6beb094cf`: `Destination::valid` (lines 17-28).
- `kernel-r19/kernel/src/redirect.rs` blob `9a07e026134d46ef646d39862bd982cc48bbc5f6`: `classify` (lines 106-125).
- `kernel-r19/broker_windows.rs` blob `16ec8853d322b40f0e00e14d49ae3410741b9395`: accepted socket → CLAIM → physical IPv4 SSH → relay (lines 116-175).
- `kernel-r19/trusted-ssh-r37/src/lib.rs` blob `c6d8c8746fac45073c11557de893164e49d830eb`: `channel_open_direct_tcpip(destination.to_string(), destination_port, "127.0.0.1", 0)` (lines 109-151).

All four immutable Git blob source contracts separately re-fetched and verified, 4/4.

## Concrete finding, not kernel proof
The production source accepts original destination addresses 127.0.0.1, 127.0.0.2, 169.254.4.5, RFC1918 10/8, 172.16/12, 192.168/16, IPv6 ::1 and IPv6 ULA fd12::2. IPv4 link-local 169.254/16 is permitted, whereas IPv6 link-local fe80::/10 is rejected. At CONNECT_REDIRECT the only local exception is the broker's exact 127.0.0.1/::1 and port; other valid selected-app destinations are eligible for issuing a redirect ticket.

On successful selected-flow receipt, AUTH and CLAIM, `TrustedSshRelay::relay` transmits the original IP/port as an SSH `direct-tcpip` destination. RFC 4254 section 7.2 explicitly assigns the onward TCP connection to the SSH **recipient**. Thus client 127.0.0.1:8080 becomes **SSH-server** 127.0.0.1:8080, not client localhost. Likewise, client 10.2.3.4 might denote a completely different private host from the SSH server. This is a **source-derived destination namespace substitution**, a potential endpoint misrouting/disclosure or availability failure, not demonstrated real packets or a WFP leak. It is independent of R88's possible SSH self-block.

The SSH channel also uses hard-coded originator `127.0.0.1:0`. Those fields are not kernel-origin evidence of the selected application's PID/epoch/EXE/endpoint; RFC 4254 defines them as the originating machine's IP and port. Whether the product intentionally wishes to tunnel client-local/private destinations needs an explicit owner-level policy decision; no transparent-local equivalence can be claimed now.

## Offline reproducible negative tests
Run from the full research checkout:
- `python3 research/wfp-ale/r89/r89_namespace_negative.py` — 5/5 PASS.
- `node research/wfp-ale/r89/r89_namespace_independent.mjs` — 40/40 same ordered decisions.

20 fixed IP address cases × ports 4040 and 8080 = 40 synthetic rows: 24 `SSH_REMOTE_NAMESPACE_CANDIDATE`; 2 `BROKER_PORT_EXCLUDED`; 14 `DEST_REJECTED`. Full ordered SHA-256 `c7a91927a70b00a0a308af0c748bbcbb48a9d7bd1b36a1e16508a051b32e4a7c`. The two independent Python/Node implementations use distinct IP parsing and assert golden cases. A candidate is only eligibility in the analyzed source branch; no native WFP/SSH reachability or actual delivery is proved. No Rust compiler, Windows execution, network, filters or drivers were used.

## Trust boundary and next decisive experiment
Kernel-origin proof still needs ALE_CONNECT_REDIRECT_V4/V6 process creation epoch/start-key, referenced image and AppId, transport endpoint/generation, original destination, ALE_AUTH_CONNECT metadata/action-right provenance, `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)` on the **real accepted SOCKET**, terminal one-use CLAIM and actual SSH transport. Retain NO-GO for PID reuse/death, 5-tuple reuse, sibling DIRECT, DNS/UDP/QUIC, IPv4/v6 coverage, WFP/BFE/SSH loss, PacketBound/G2 and leak-free. R69/R87 AUTH-metadata and R88 original-AppId self-block may prevent the candidate path completely; that would be a failure to function, not a semantics proof.

**NO-GO** for calling current client-local/private address forwarding transparent without an explicit policy. Do **not** exempt local traffic from WFP blindly: that alters the sibling-DIRECT threat model. Next authorized offline experiment: compile the exact pinned Rust `Destination::valid` + SSH channel construction in a read-only user-mode Windows x86_64 harness, run this matrix and verify an explicit owner-approved policy rejects/handles client-local and private destinations before emitting a remote `direct-tcpip`. Native WFP / driver tests remain forbidden until separate driver/VNC/SYSTEM rescue/rollback gates.

References:
- https://www.rfc-editor.org/rfc/rfc4254.html#section-7.2
- https://www.rfc-editor.org/rfc/rfc3927.html#section-2.7
- https://www.rfc-editor.org/rfc/rfc4291.html#section-2.5.3
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records

Isolation: main/release, beta `integration/windows-rust-capture-agent-20261031`, PR #56, runners, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, networks, other repositories, automations and controller unchanged. Never run/install kernel driver, callout, WFP filter, NDISRD, VNC experiments, signed-driver work or paid operations. No ProxiFyre AGPL, closed PR40, vendor binary or C++ WFP payload.
