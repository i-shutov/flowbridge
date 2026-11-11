# R108 — ALE reauthorization vs. one-shot AUTH: source-level NO-GO

2026-11-11. Independent architectural research ONLY. Repository i-shutov/flowbridge; sole permitted ref research/windows-wfp-ale-attribution-20261107. Parent at start: 541097a38503bb3dc08928b2d8f088e73312cfb4; main at start: 5b5afc2feeda2195f302380e615ba003d4906e09. No beta/PR #56, no G1 transfer, no PacketBound/G2 PASS, no no-DIRECT or leak-free claim.

## Decision

**Source-level conditional availability NO-GO:** when an established, originally redirected selected TCP flow reaches R19's terminating AUTH_CONNECT callback with FWP_CONDITION_FLAG_IS_REAUTHORIZE, the callback returns BLOCK, even if the remaining provenance is valid. It is NOT a demonstrated Windows crash, DIRECT leak, or observation that a particular Windows flow was reauthorized.

Microsoft states that ALE flow reauthorization can result from a policy change, a newly arriving interface, or completion of a pended connection, and is indicated by FWP_CONDITION_FLAG_IS_REAUTHORIZE. Direction of the packet and original flow direction may differ. A native classify callback reaching this branch is the missing physical prerequisite.

Exact frozen source, read through GitHub at the parent SHA:

- research/wfp-ale/kernel-r19/kernel/src/redirect.rs blob 9a07e026134d46ef646d39862bd982cc48bbc5f6: auth_check() rejects `(bits & (0x0000_0004 | 0x0200_0000)) != 0`, and auth_classify() calls block(out) on failed auth_check. Both FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6 are supported in its branch selection.
- research/wfp-ale/kernel-r19/kernel/src/handoff.rs blob e1d17217db50362ba9c4efc83af820b6beb094cf: Book::attest() rejects `auth_seen` replay; Book::take() marks the ticket nonlive even on failure.
- research/wfp-ale/kernel-r19/policy_windows.rs blob acf60334320d970f58af3349ee75fbaa59826602: AUTH filters are FWP_ACTION_CALLOUT_TERMINATING and match FWPM_CONDITION_ALE_ORIGINAL_APP_ID.

Removing only the REAUTHORIZE guard does not solve continuity: the AUTH ticket has already been seen, and after CLAIM is retired. Granting a fresh ticket from a matched PID, 5-tuple or timestamp would be an unauthenticated correlation, not a repair. A future design needs a separate kernel-anchored, generation-aware established-flow identity and explicit revocation, with native proof of the same connection. Until then, blocking is a deliberate fail-closed outcome, but transparent operation over legitimate reauthorization remains NO-GO.

## Deterministic independent negative tests

Two independently implemented OFFLINE models were actually run using Python 3 and Node.js 22. Results: 320 ordered states each (IPv4/IPv6, initial + four abstract reauthorization labels, five independent binary gates); only 2 initial fully-qualified states permit; 8 fully-qualified reauthorization states block. Their identical ordered-matrix SHA-256 is `39b792796cab78a1b92d265de0fcaa20029a30c5809b58a8290ea61f1f049b71`.

Test blob SHA: Python `8def9b81f07cfde418b18ff53657999fe6ec0cf2`; Node.js `b48d2ab96fbf01535baa853a47695908038d0317`. Both blobs match their locally executed files byte-for-byte. Eleven independent exact pinned-source predicates passed. The labels CLASSIFY_COMPLETION and SOCKET_PROPERTY are abstract matrix variants; NOT assertions that a specific event always triggers Windows ALE reauthorization.

Run: `python3 r108_reauth_negative.py` and `node r108_reauth_independent.mjs`. No drivers, sockets, network, WFP management calls or Windows operations are performed. These tests model the decision; they do NOT execute R19 Rust or a native Windows classifyFn.

## API evidence and trust boundary

Required future kernel-origin proof: referenced EPROCESS / process creation event and epoch (`PsSetCreateProcessNotifyRoutineEx`, `PsGetProcessCreateTimeQuadPart`, optionally `PsGetProcessStartKey` at correct lifetime and IRQL), exact canonical EXE and opaque AppId (`FwpmGetAppIdFromFileName0`), native ALE CONNECT_REDIRECT and AUTH_CONNECT V4/V6 metadata and redirect state (`FwpsQueryConnectionRedirectState0`), one-shot kernel ticket, accepted socket record/context (`WSAIoctl` with SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS and SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT), terminal CLAIM, then records set on the pinned outbound SSH socket (`SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`). The specific per-flow reauthorization decision and flow lifetime must originate in kernel callbacks, not ETW/TCP-table/PID/5-tuple joins.

Microsoft's generic metadata-at-layer table and the connect-redirection guidance do not present the same apparent enumeration of LOCAL_REDIRECT_TARGET_PID and ORIGINAL_DESTINATION on AUTH_CONNECT. This is an UNRESOLVED documentation/runtime-verification gap, NOT evidence of an OS omission.

Still NO-GO without physical proof: process death/PID reuse, re-used 5-tuple, sibling DIRECT, IPv4/IPv6, DNS/UDP/QUIC, BFE/WFP/SSH loss, R100-R107 existing gaps, and no-DIRECT. R99/R103 read-only BFE inventory can show available management objects but never proves a native reauthorization callback or continuous enforcement.

Official Microsoft references:
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer

## Next decision and scope

Next ALLOWED experiment: compile exact pinned R99/R103 user-mode read-only Rust sources on an already approved Windows x86_64 environment; verify SDK ABI, Windows build, binary SHA-256, BFE JSON and exit code. This would prove read-only BFE visibility at most. To settle reauthorization classification itself would require a separately authorized driver/callout test plus all owner driver/VNC/SYSTEM rescue/rollback gates; it is NOT authorized in this track.

No modifications to main/release, integration/windows-rust-capture-agent-20261031, PR #56, runner, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, networks, other repositories, automation schedules, controller, ProxiFyre AGPL, closed PR40, vendor binaries or C++ WFP payload. No paid operations.
