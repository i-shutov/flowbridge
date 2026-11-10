# R90 — Explicit source-bind at ALE_CONNECT_REDIRECT: conditional functional NO-GO

Date: 2026-11-10. Exclusive branch `research/windows-wfp-ale-attribution-20261107`; not beta/PR #56 or PacketBound/G2 PASS.

## Pinned evidence and contract
- Research parent `228552a62d28e33c2c38b85c55a1178632e33956`; tree `9add618ef2fd7d7fc693579852a59e8ff114fe8b`. Main `5b5afc2feeda2195f302380e615ba003d4906e09`; research ahead 125, behind 0.
- Exact `research/wfp-ale/kernel-r19/kernel/src/redirect.rs` Git blob `9a07e026134d46ef646d39862bd982cc48bbc5f6`, six read-only source guards 6/6 PASS.
- `local_supported(raw,family)` admits only IPv4 `0.0.0.0` or `127.0.0.1`, and IPv6 `::` or `::1` with zero `sin6_scope_id`.
- `classify` applies this check to `FWPS_CONNECT_REQUEST0.localAddressAndPort` **before** `r.book.issue`. Any other local source leads to `block(out); return`, not to ticket issue.
- Microsoft says `FWPS_CONNECT_REQUEST0.localAddressAndPort` is the local transport address of the connect request (SOCKADDR_STORAGE). It is not in the set of members that a connect-redirection callout may modify: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-_fwps_connect_request0 ; https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection .

## Conditional source-level finding
Given an otherwise eligible selected TCP flow for which the kernel supplies a non-wildcard, non-exact-loopback source address, this specific implementation **BLOCKS before issuing a redirect ticket**. An app explicitly bound to a local interface (RFC1918/ULA, link-local, alternate loopback) is a concrete source-address candidate. This is a possible legitimate-connectivity failure and a source-level restriction, **not** a demonstrated Windows callback, WFP interception, packet leak, or actual physical direct path.
Whether a particular native bind(sourceIP) is represented by exactly that `localAddressAndPort` at ALE_CONNECT_REDIRECT must be measured in an independently authorized Windows experiment. An observed user-mode bind or TCP table is not a kernel-origin classify receipt. Silently permitting DIRECT or blindly removing the predicate would change the security contract and is not justified.

## Deterministic, independently checked negative tests
- `python3 research/wfp-ale/r90/r90_bound_source_negative.py`: 5/5 PASS.
- `node research/wfp-ale/r90/r90_bound_source_independent.mjs`: independently reproduces 28/28 ordered source-conditional decisions.
- 14 local addresses across IPv4/IPv6 × two remote destinations = 28 synthetic rows: 20 `BLOCK_BEFORE_TICKET`, 8 `LOCAL_SOURCE_ADMITTED_TO_LATER_GATES`.
- Matching ordered SHA-256: `ad4b676bcf4fc06db05a8a39dd6c57693c524f67812a597cd5d78801379a1bfc`. No `rustc`, Windows, socket, BFE, driver, filter or physical traffic execution.

## Trust boundary / remaining NO-GO
Required proof remains original `ALE_CONNECT_REDIRECT_V4/V6` classify AppId, PID, transport endpoint and safe referenced process `EPROCESS`/creation epoch (e.g. `PsGetProcessCreateTimeQuadPart`), canonical executable, original destination and source-bind context; `ALE_AUTH_CONNECT_V4/V6` original AppId and valid redirect/original-destination metadata/action rights; one-use issuance; actual accepted SOCKET `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)`; CLAIM on that exact receipt; real outbound SSH socket with `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`, pinned host key and physical outcome. No ETW/PID/5-tuple heuristic is a substitute.
NO-GO persists for kernel-origin attribution, PID death/reuse, reused 5-tuple, accepted-socket/CLAIM causality, sibling DIRECT, R87 metadata, R88 original-AppId SSH self-block, R89 destination-namespace substitution, v4/v6, DNS/UDP/QUIC, and WFP/BFE/SSH loss. No no-DIRECT/leak-free or historical `dd1ab3c` G1 promotion.

## Decisive next experiment
Allowed offline: use a no-socket, no-driver clean-room Rust user-mode harness for the exact source predicate and raw `SOCKADDR_STORAGE` v4/v6 cases on an authorized x86_64 toolchain. A real WFP experiment can observe bound-source vs unbound localAddressAndPort only **after** separate owner authorization and all driver/VNC/SYSTEM rescue/rollback gates. Until then, decide explicitly whether bound-source TCP is unsupported, denied, or must be proxied preserving semantics; do not change the redirect filter.

Isolation: only these three research files. main/release, beta `integration/windows-rust-capture-agent-20261031`, PR #56, runner, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, services, networks, other repos, automation state and controller untouched. No ProxiFyre AGPL, closed PR40, vendor binary, C++ WFP payload, NDISRD, callout, filter, VNC experiment, signed-driver work or paid operations.
