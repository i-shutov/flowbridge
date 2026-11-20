# R216 — dual-stack IPv4-mapped V6 ALE destination: conditional NO-GO

Date: 2026-11-20. Scope ONLY i-shutov/flowbridge branch research/windows-wfp-ale-attribution-20261107. Starting HEAD 3d258f330cd5f07194fe979a65adee84e47169b0; read-only main 5b5afc2feeda2195f302380e615ba003d4906e09. Independent R&D, NOT beta / PR #56 / PacketBound or G2 PASS / no-DIRECT or leak-free / historical G1.

## Source-verifiable finding

Microsoft's [Application Layer Enforcement (ALE)](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-) explicitly states that true dual-IP sockets may NOT classify at IPv4 ALE; their IPv4 traffic can require an IPv6 ALE filter with an IPv4-mapped IPv6 destination. This is platform possibility, not an observed FlowBridge connection.

- Original R19 `kernel-r19/kernel/src/handoff.rs` blob `e1d17217db50362ba9c4efc83af820b6beb094cf`: `Destination::valid()` for family 6 rejects IPv4-mapped V6 (`ip[..10] == [0;10] && ip[10..12] == [0xff,0xff]`).
- Original R19 `kernel-r19/kernel/src/redirect.rs` blob `a093f049d162987981a957aac90db1014bc6ff09`: V6 `destination(remote,family)` calls `Destination::valid()`; `classify` blocks an invalid destination before ticket issuance.
- The existing unit test named `no_scope_multicast_unspecified_or_mapped` has no explicit `::ffff:IPv4` fixture; this is a narrowly confirmed test coverage omission, not a claim that a compiled Rust test is faulty.

Conditional counterexample: selected dual-stack TCP to IPv4 `198.51.100.7:443` could classify at `ALE_CONNECT_REDIRECT_V6` with destination `::ffff:198.51.100.7`; the present R19 V6 model blocks it, whereas plain V4 `198.51.100.7` passes the destination predicate. This creates a possible availability/coverage failure. It is NOT evidence of actual DIRECT, packet leak, final WFP arbitration, native classify, or service bypass. Existing R121/R122 network-compartment and remote-SSH routing NO-GOs remain.

## Independently executed negative tests

- `r216_dualstack_negative.py`: Python 3.13.5, 4/4 unittest PASS, 12 deterministic source-contract samples (three mapped V6), mutation test removes the mapped guard and detects changed verdict; `py_compile` PASS.
- `r216_dualstack_independent.mjs`: independently authored Node.js 22.16.0 algorithm, 12/12 assertions PASS and `node --check` PASS.
- Both produce identical ordered transcript digest SHA-256 `bcb20d46677ab067651521c4c066c8bed5701d9321ae578a30d813c332c213dc`.
- Five source verifications against original pinned GitHub blobs PASS: mapped guard; parser invokes predicate; classify blocks invalid; exact two blob identities; original nominal mapped test lacks a mapped fixture.
- Git blobs of new scripts: Python `7083aa2b70ff9ef5210bb175d2ed395c1d289832`; Node `1410a7da40c59b978d255635dd7977d22f14cd64`.

Commands from repo root: `python3 research/wfp-ale/r216/r216_dualstack_negative.py`, `python3 -m py_compile research/wfp-ale/r216/r216_dualstack_negative.py`, `node research/wfp-ale/r216/r216_dualstack_independent.mjs`, `node --check research/wfp-ale/r216/r216_dualstack_independent.mjs`. These tests do not compile Rust or exercise Windows, WFP, sockets or traffic.

## Trust chain and gates

Exact selected WFP application identity `FwpmGetAppIdFromFileName0`/`FWPM_CONDITION_ALE_APP_ID` -> native `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6` with WFP-supplied `FWPS_METADATA_FIELD_PROCESS_ID` and `TRANSPORT_ENDPOINT_HANDLE` -> referenced EPROCESS/FileObject, PID, creation epoch, start key and canonical EXE from process creation (never late PID or 5-tuple correlation) -> `FwpsAcquireWritableLayerDataPointer0`, `FWPS_CONNECT_REQUEST0.previousVersion`, `FwpsQueryConnectionRedirectState0` and modified-layer apply -> independent `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6` with original AppId/destination, reauthorization and *final* arbitration -> real accepted socket `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS)` -> one-use terminal CLAIM -> `WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS)` on outbound socket before authenticated physical SSH. No uninterrupted native proof exists.

**Architecture: NO-GO.** Do not claim dual-stack transparent coverage. Either explicitly exclude mapped-V6 traffic and fail closed, or design normalization while preserving original family, socket mode, compartment, namespace, original AppId, endpoint, epoch, ticket and AUTH proof. Blind V6 acceptance or V4 conversion is not approved by synthetic models.

Next permitted decisive experiment: run original pure-Rust R201/R202 and a dedicated mapped-V6 Rust parser unit test with a trusted Rust toolchain; match these 12 cases to both independent oracles. Read-only native R199 BFE inventory may document management policy but cannot prove classify. Actual V6 ALE arrival, process death/PID reuse, repeated 5-tuple, sibling DIRECT, DNS/UDP/QUIC, WFP/SSH failure and physical egress need separately approved driver/callout lab with owner, signing, snapshot, VNC/SYSTEM rescue and rollback gates, not authorized in this research cycle. No drivers, filters, services, networks, security settings, runner, other repositories/branches, PRs, paid operations or automations were touched.

Official references: https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale- ; https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers ; https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection .
