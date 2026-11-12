# R126: selected ORIGINAL_APP_ID AUTH filter may self-block record-bearing SSH uplink — conditional NO-GO

Date 2026-11-12. Independent i-shutov/flowbridge R&D only, research/windows-wfp-ale-attribution-20261107. Initial branch HEAD 95dd54b6defe6bf6281c7864a6132cefef86c170; read-only main HEAD 5b5afc2feeda2195f302380e615ba003d4906e09.

## Exact R19 anchors (read-only)

- research/wfp-ale/kernel-r19/policy_windows.rs blob acf60334320d970f58af3349ee75fbaa59826602: Kind::AttestOriginal is a terminating callout at ALE_AUTH_CONNECT_V4/V6 matching FWPM_CONDITION_ALE_ORIGINAL_APP_ID == selected plus IP_PROTOCOL == TCP, NOT current broker AppId.
- research/wfp-ale/kernel-r19/broker_windows.rs blob 16ec8853d322b40f0e00e14d49ae3410741b9395: receive() queries WFP records/context on actual accepted TCP socket. claim_and_connect_trusted_ssh() consumes a one-use CLAIM, sets opaque WFP redirect records via WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS) on the NEW broker-owned physical socket, then connects to remote SSH IP.
- research/wfp-ale/kernel-r19/kernel/src/redirect.rs blob 9a07e026134d46ef646d39862bd982cc48bbc5f6: auth_check() requires remote loopback IPv4 127.0.0.1 or IPv6 ::1, redirected flag, selected original AppId, original destination, redirect target broker PID, selected process identity and matching endpoint-ticket. auth_classify() BLOCKs on failure.
- research/wfp-ale/kernel-r19/kernel/src/handoff.rs blob e1d17217db50362ba9c4efc83af820b6beb094cf: a consumed one-use ticket is not a repeatable proxy-leg exception.

## Hypothesis and precise limits

There are two socket legs: (1) selected client -> local broker redirect accept, and (2) broker -> physical SSH server. Microsoft documents ALE_ORIGINAL_APP_ID as the **original application's path on proxied connections**. IF setting redirect records on the broker's outbound physical socket causes this selected original AppId to appear at its ALE_AUTH_CONNECT classify, then the same original-AppId TCP filter matches **the broker's SSH socket**. On external SSH IP, auth_check() necessarily fails its loopback requirement and the terminating callback BLOCKs that socket, provided WFP delivered this filter with action-write rights.

This is a source-derived, **conditional SSH self-block/liveness NO-GO**, not an observed kernel behavior and NOT a DIRECT leak. Whether the original AppId propagates to that exact physical socket, callback delivery and the actual metadata are NOT proved. A text AppId or user-mode 5-tuple is NOT kernel-owner evidence.

## Independently executed deterministic negative tests

r126_proxy_leg_negative.py (6 Python unittest PASS) and r126_proxy_leg_independent.mjs (independent Node oracle PASS) enumerate 4096 synthetic combinations of 12 flags: selected original, TCP, loopback, redirected, target broker PID, original destination, process selected, endpoint ticket match, not reauth, current broker AppId, SSH ready, v4/v6. Results: NO_MATCH 3072; BLOCK_CANDIDATE 1020; PERMIT_CANDIDATE 4; selected-original TCP physical broker/nonloopback subset 128/128 BLOCK_CANDIDATE; non-selected original TCP 1024/1024 NO_MATCH. The ordered 4096-line matrix SHA-256 matches between languages: 2e709a60e2eca14e100214e24453860272bae0243303dbf86825a10d5835c022.

The model over-approximates admissibility by assuming all omitted metadata/type/ticket/time requirements valid. PERMIT_CANDIDATE is NEVER physical proof. An initially incorrect independent expected proxy subset count was corrected 64->128 before publication; reruns passed. No Rust compiler, Windows classify or ABI test is claimed.

## Correct trust split and decisive next experiment

Selected original kernel ALE_CONNECT_REDIRECT_V4/V6 with WFP AppId and metadata PID/endpoint -> referenced process PID+creation epoch+start key+canonical EXE -> owned FWPS_CONNECT_REQUEST0 target/handle/context -> ALE_AUTH_CONNECT with actual field/mask/rights -> socket-specific accepted-side SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS and ...CONTEXT -> one-use CLAIM -> SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on separately owned physical SSH socket -> authenticated SSH server/destination. Original client flow and broker physical SSH socket MUST have separately defensible policy/owner decisions.

Do not blindly exempt a broker PID/current AppId, special port or 5-tuple: the current AppId may differ even on the initial redirected AUTH (as the code acknowledges). Read-only BFE inspection and R124 Windows x64 compiler/synthetic testing are permissible preparatory experiments, not kernel identity evidence. Definitive tests on (A) selected original redirected socket, (B) record-bearing broker external SSH, (C) ordinary broker no-record socket and (D) selected sibling DIRECT require separately authorized Windows kernel callout/driver/VNC/SYSTEM rescue/rollback gates. Also retain independent NO-GO for process death/PID reuse, reused 5-tuple, reauthorization, IPv4/IPv6, compartments, DNS/UDP/QUIC, WFP/BFE/SSH loss.

Primary official sources rechecked 2026-11-12:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v6_
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization

Overall architectural NO-GO, NOT PacketBound/G2, no-DIRECT, leak-free or historical G1 acceptance. No change to main/release, integration/windows-rust-capture-agent-20261031 or PR #56, runners, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, network, other repos, automation/controller, drivers, callouts, NDISRD, VNC, paid operations, ProxiFyre AGPL, closed PR40, vendor binaries or C++ WFP payload.
