# R109 — explicit local bind vs inline ALE connect redirection (conditional availability NO-GO)

Date: 2026-11-11. Research ONLY in i-shutov/flowbridge, branch research/windows-wfp-ale-attribution-20261107. Not beta, PR #56, PacketBound/G2 PASS or release acceptance. No driver, filters, network, Windows host, runner, firewall or service touched.

## Decision and exact source

**Conditional source-level availability NO-GO:** if FWPS_CONNECT_REQUEST0.localAddressAndPort carries a selected client's explicit non-wildcard, non-127.0.0.1 IPv4 address or non-wildcard, non-::1 IPv6 address, R19's local_supported returns false and classify() calls block(out) before issuing the redirect ticket. It is not evidence of a real Windows callback, physical disruption, or DIRECT leak.

- Exact redirect.rs blob 9a07e026134d46ef646d39862bd982cc48bbc5f6: local_supported accepts IPv4 0.0.0.0/127.0.0.1 only, IPv6 ::/::1 only with zero scope; classify() executes if !local_supported(local,family){block(out);return;} and writes remoteAddressAndPort to loopback on success.
- Exact broker.rs blob ce6c549a9ae488cc7c0ca9a7e7be68871b9d7f2c: listeners bind only to 127.0.0.1:0 and [::1]:0, not arbitrary selected client's local address.
- Exact policy_windows.rs blob acf60334320d970f58af3349ee75fbaa59826602: selected-app AppId and TCP/6 v4/v6 filter conditions contain no local-address exclusion; classified traffic can reach this gate if callouts run.

Official Microsoft source (consulted 2026-11-11): https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection . Microsoft documents that CONNECT_REDIRECT cannot change local address/port; its remote redirection example chooses loopback only for wildcard local address, otherwise chooses that local address as remote proxy address to avoid zone crossing. This is a documented compatibility concern, not proof of behavior on every Windows socket. Simply substituting a nonloopback destination would not work with the existing loopback-only listeners.

## Offline independent negative tests

r109_local_bind_negative.py constructs 128-byte synthetic SOCKADDR_STORAGE v4/v6 values and applies the exact local_supported allowlist. r109_local_bind_independent.mjs independently applies an address-family allowlist with a separately written oracle. Neither tool opens sockets or uses WFP/OS mutation.

12 family/local variants x 2 destination ports x 2 abstract lease states = 48 ordered cases. Both Python 3 and Node 22 ACTUALLY executed; TRY_REDIRECT=8, BLOCK_LOCAL=16, BLOCK_LEASE=24. Canonical JSONL matrix SHA-256 matches independently: b62a93d973ab4c9b84638a70a840969552847fbdfa0a820f3695c94a0c8d6abf.

Positive conditional values are IPv4 0.0.0.0 / 127.0.0.1 and IPv6 :: / ::1. Rejected bound-local examples include 127.0.0.2, 192.0.2.7, ::2 and 2001:db8::5. TRY_REDIRECT does NOT establish real redirect or acceptance. Pinned source guards verified independently: redirect 7/7; broker 3/3; policy 2/2.

Offline commands: python3 r109_local_bind_negative.py ; node r109_local_bind_independent.mjs

## Trust boundary and decisive experiment

Unproven kernel-origin chain: PsSetCreateProcessNotifyRoutineEx and referenced EPROCESS + PsGetProcessCreateTimeQuadPart / PsGetProcessStartKey -> FwpmGetAppIdFromFileName0 / WFP ALE AppId -> FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6 with FWPS_CONNECT_REQUEST0 + FwpsAcquireWritableLayerDataPointer0 / FwpsApplyModifiedLayerData0 / FwpsQueryConnectionRedirectState0 -> AUTH_CONNECT v4/v6 kernel ticket attestation -> actual accepted socket + WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT) -> terminal CLAIM -> pinned SSH socket with SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS. PID/5-tuple/ETW correlations are not a kernel receipt.

Current NO-GO remains for sibling DIRECT, process death/PID reuse, repeated 5-tuple, DNS/UDP/QUIC, IPv4/IPv6 and WFP/SSH loss, plus R100-R108 findings. R99/R103 native read-only BFE/ABI checks remain the next permitted experiment and cannot prove this native redirect gate. Resolving R109 requires separately authorized and gated native WFP classify observation for explicit-bind vs implicit-bind IPv4/v6 clients and proxy accept behavior. Neither a driver nor any WFP filter was installed/tested here. Engineering options are explicit unsupported-case fail-closed or an address-aware proxy design, both unimplemented and unaccepted.
